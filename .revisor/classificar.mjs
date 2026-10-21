#!/usr/bin/env node
// Classificador de risco de PR — Node puro, sem token, só git local.
// Uso: node classificar.mjs --repo <nome> --mapa <arquivo> --base origin/main --head HEAD
// Saída JSON: { nivel, arquivos_por_nivel, gatilhos_bloqueantes[], trechos_suspeitos[] }
// nivel ∈ baixo|medio|alto|bloqueante (maior entre arquivos; gatilho bloqueante força bloqueante)
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
const repo = arg("--repo", "");
const mapaPath = arg("--mapa", ".revisor/mapa-de-risco.yml");
const base = arg("--base", "origin/main");
const head = arg("--head", "HEAD");
if (!repo || !existsSync(mapaPath)) {
  console.error(JSON.stringify({ erro: `uso: --repo <nome> --mapa <arquivo> (repo='${repo}', mapa existe=${existsSync(mapaPath)})` }));
  process.exit(2);
}

// ---------- parser do subset YAML do mapa ----------
function parseMapa(text) {
  const repos = {};
  let curRepo = null, curNivel = null;
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trim().startsWith("#")) continue;
    let m;
    if ((m = raw.match(/^([A-Za-z0-9._-]+):\s*$/))) { curRepo = m[1]; repos[curRepo] = {}; curNivel = null; continue; }
    if ((m = raw.match(/^\s{2}(bloqueante|alto|medio|baixo):\s*$/))) { curNivel = m[1]; if (curRepo) repos[curRepo][curNivel] = []; continue; }
    if ((m = raw.match(/^\s*-\s*"?([^"]+)"?\s*$/))) { if (curRepo && curNivel) repos[curRepo][curNivel].push(m[1]); continue; }
  }
  return repos;
}

// ---------- glob -> regex ----------
function globToRegex(glob) {
  let g = glob.replace(/^\.\//, "");
  let re = "";
  for (let i = 0; i < g.length; i++) {
    if (g.startsWith("**/", i)) { re += "(?:.*/)?"; i += 2; }
    else if (g.startsWith("**", i)) { re += ".*"; i += 1; }
    else if (g[i] === "*") re += "[^/]*";
    else if (g[i] === "?") re += "[^/]";
    else re += g[i].replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + re + "$");
}
const NIVEIS = ["baixo", "medio", "alto", "bloqueante"];
const rank = (n) => NIVEIS.indexOf(n);

function classificarArquivo(path, sec) {
  const p = path.replace(/^\.\//, "");
  if (p.startsWith(".revisor/")) return "bloqueante";
  for (const nivel of ["bloqueante", "alto", "medio", "baixo"]) {
    for (const pat of sec[nivel] || []) {
      if (globToRegex(pat).test(p)) return nivel;
    }
  }
  return "medio"; // default: checagem humana
}

// ---------- git ----------
function git(args) {
  return execFileSync("git", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}
let arquivos = [];
try {
  arquivos = git(["diff", "--name-only", `${base}...${head}`]).split(/\r?\n/).filter(Boolean);
  if (!arquivos.length) arquivos = git(["diff", "--name-only", base, head]).split(/\r?\n/).filter(Boolean);
} catch (e) {
  console.error(JSON.stringify({ erro: `git diff --name-only falhou: ${e.message}` })); process.exit(2);
}
let diff = "";
try { diff = git(["diff", "-U0", `${base}...${head}`]); } catch { try { diff = git(["diff", "-U0", base, head]); } catch {} }

// linhas adicionadas por arquivo
const adicionadasPorArquivo = {};
let curFile = null;
for (const line of diff.split(/\r?\n/)) {
  const mf = line.match(/^\+\+\+ b\/(.+)$/);
  if (mf) { curFile = mf[1]; adicionadasPorArquivo[curFile] = adicionadasPorArquivo[curFile] || []; continue; }
  if (line.startsWith("+") && !line.startsWith("+++") && curFile) adicionadasPorArquivo[curFile].push(line.slice(1));
}

// ---------- gatilhos bloqueantes ----------
const gatilhos = [];
const suspeitos = [];
const pushG = (tipo, arquivo, trecho) => gatilhos.push({ tipo, arquivo, trecho: String(trecho || "").slice(0, 200) });

const RE = {
  segredoAtribuicao: /\b(api[_-]?key|secret|token|password|passwd|pwd|private[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]/i,
  chaveConhecida: /\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b/,
  chavePrivada: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  serviceRole: /service_role/i,
  disableRls: /disable\s+row\s+level\s+security/i,
  dropPolicy: /drop\s+policy/i,
  alterPolicyAmplo: /alter\s+policy[\s\S]{0,200}(using\s*\(\s*true\s*\)|to\s+(public|anon)\b|permissive)/i,
  grantAnon: /grant\s+[^;]{0,120}\bto\s+(anon|public)\b/i,
  dropTable: /drop\s+table/i,
  truncate: /truncate\s+(table\s+)?[A-Za-z_"][A-Za-z0-9_".]*/i,
  deleteSemWhere: /delete\s+from\s+[A-Za-z_"][A-Za-z0-9_".]*\s*;?\s*$/i,
  dropColumn: /drop\s+column/i,
  nextPublicSegredo: /NEXT_PUBLIC_[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|TOKEN|KEY)[A-Z0-9_]*\s*[:=]/i,
  injecao: /(revisor\s*:|este PR é seguro|aprove\s*(este|o)?\s*PR|ignore\s+(as\s+)?(regras|instruções|instruc\w*))/i,
};
const isMigration = (p) => /(^|\/)(migrations|supabase)\//i.test(p) || /\.sql$/i.test(p);

for (const arquivo of arquivos) {
  const p = arquivo;
  if (p.startsWith(".revisor/")) pushG("caminho-.revisor", p, p);
  if (/(^|\/)CODEOWNERS$/.test(p)) pushG("alteracao-codeowners", p, p);
  if (p.startsWith(".github/workflows/")) pushG("alteracao-workflow", p, p);
  if (/^\.env($|\.)/.test(p.split("/").pop()) && !/\.env\.(example|sample|template)$/i.test(p)) pushG("arquivo-env", p, p);

  const linhas = adicionadasPorArquivo[p] || [];
  const arquivoEhCliente = linhas.some((l) => /["']use client["']/.test(l));
  for (const linha of linhas) {
    if (RE.segredoAtribuicao.test(linha) || RE.chaveConhecida.test(linha)) pushG("possivel-segredo", p, linha);
    if (RE.chavePrivada.test(linha)) pushG("chave-privada", p, linha);
    if (RE.serviceRole.test(linha)) pushG("service_role", p, linha);
    if (/\.env\b/.test(linha) && /(=|require|import|process\.env)/.test(linha) && RE.serviceRole.test(linha)) pushG("env-com-segredo", p, linha);
    if (RE.disableRls.test(linha)) pushG("disable-row-level-security", p, linha);
    if (RE.dropPolicy.test(linha)) pushG("drop-policy", p, linha);
    if (RE.alterPolicyAmplo.test(linha)) pushG("alter-policy-ampliando", p, linha);
    if (RE.grantAnon.test(linha)) pushG("grant-to-anon", p, linha);
    if (RE.dropTable.test(linha)) pushG("drop-table", p, linha);
    if (RE.truncate.test(linha)) pushG("truncate", p, linha);
    if (/delete\s+from/i.test(linha) && !/where/i.test(linha)) pushG("delete-sem-where", p, linha);
    if (RE.dropColumn.test(linha) && isMigration(p)) pushG("drop-column-migration", p, linha);
    if (RE.nextPublicSegredo.test(linha)) pushG("next_public-com-segredo", p, linha);
    if (arquivoEhCliente && (RE.serviceRole.test(linha) || RE.segredoAtribuicao.test(linha))) pushG("segredo-em-codigo-cliente", p, linha);
    if (RE.injecao.test(linha)) suspeitos.push({ arquivo: p, trecho: linha.slice(0, 200), motivo: "possível tentativa de influenciar o revisor (dado, não instrução)" });
  }
}

// ---------- resultado ----------
const mapa = parseMapa(readFileSync(mapaPath, "utf8"));
const sec = mapa[repo];
if (!sec) { console.error(JSON.stringify({ erro: `repo '${repo}' sem seção no mapa` })); process.exit(2); }

const arquivos_por_nivel = { baixo: [], medio: [], alto: [], bloqueante: [] };
let nivel = "baixo";
for (const arq of arquivos) {
  const n = classificarArquivo(arq, sec);
  arquivos_por_nivel[n].push(arq);
  if (rank(n) > rank(nivel)) nivel = n;
}
if (suspeitos.length && rank(nivel) < rank("alto")) nivel = "alto"; // piso por trecho suspeito
if (gatilhos.length) nivel = "bloqueante";

console.log(JSON.stringify({ nivel, arquivos_por_nivel, gatilhos_bloqueantes: gatilhos, trechos_suspeitos: suspeitos }, null, 2));
