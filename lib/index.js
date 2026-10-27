// dsh-guard — allow / ask / deny gates for DeepSeek Harness tool calls.
//
// Surfaces (all optional, defaults below):
//   path                 cross-cutting file-path rules, both directions
//   pathRead/pathWrite   directional overrides
//   externalDirectory    cwd boundary
//   bash                 command globs (last matching rule wins)
//   tools.<name>         per-tool path rules (read, write, edit, grep, glob, mcp__*)
//
// Decision rules: within one surface the LAST matching rule wins; across
// surfaces the most restrictive wins (deny > ask > allow). Invalid
// configuration fails closed: every call is denied with the validation errors.

import { homedir } from 'node:os';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, watchFile, unwatchFile, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { realpath } from 'node:fs/promises';
import { decomposeShellCommand } from './shell.js';
import { test as testPattern, check as checkPattern, DEFAULT_MAX_STARS } from './match.js';
import { flattenArguments, entryKeys, agentCandidates, agentLabel } from './params.js';
import { auditPath as defaultAuditPath, statusPath as defaultStatusPath, policyPath, snapshotsDir, ensureConfigDir, migrateLegacy, seedPolicy } from './paths.js';
import { capture, listSnapshots, restore, snapshotTargets, describeSnapshot, DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES, DEFAULT_RETAIN } from './snapshots.js';
import { parseJsonc } from './jsonc.js';
import { previewFor, MAX_READ_BYTES } from './preview.js';
import { applyPatch, summarize } from './policy-edit.js';
import { getPreset, listPresets } from './presets.js';
import { readTail, describeDecision } from './audit-log.js';
import { remember as rememberDiff, lookup as lookupDiff, renderPage as renderDiffPage } from './diff-view.js';

export const name = 'guard';
function packageVersion() {
  try {
    return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
  } catch {
    return '0.0.0';
  }
}

export const VERSION = packageVersion();
export const inject = ['tools', 'workingDirectory', 'sessionProjections'];

/** How many decisions `guard_status` and `status.json` keep in memory. */
export const RECENT_LIMIT = 10;

const SEVERITY = { allow: 0, ask: 1, deny: 2 };
const STATES = new Set(['allow', 'ask', 'deny']);
const APPROVAL_MODES = new Set(['approval', 'question', 'dialog']);

const DEFAULT_PERMISSION = {
  '*': 'allow',
  path: {
    '*': 'allow',
    '*.env': 'deny',
    '*.env.*': 'deny',
    '*id_rsa': 'deny',
    '*id_ed25519': 'deny',
    '*id_ecdsa': 'deny',
    '*id_dsa': 'deny',
    '*/.ssh': 'deny',
    '*/.ssh/*': 'deny',
    '*/.aws/*': 'deny',
    '*/.gnupg/*': 'deny',
    '*/.netrc': 'deny',
    '*/.git-credentials': 'deny',
    '*/.npmrc': 'deny',
    '*/.pypirc': 'deny',
    '*/.docker/config.json': 'deny',
    '*/.kube/config': 'deny',
    '*/.config/gh/hosts.yml': 'deny',
    '*/.dsh/.credentials.yaml': 'deny',
    '*.env.example': 'allow',
  },
  pathRead: {},
  pathWrite: {},
  externalDirectory: { '*': 'allow' },
  bash: { '*': 'allow' },
  tools: {},
  params: {},
  toolParams: {},
  agents: {},
  argv: [],
  opaque: 'ask',
  sandboxAware: true,
  yolo: false,
  audit: true,
  auditMaxBytes: 5 * 1024 * 1024,
  projectPolicy: true,
  projectPolicyStrict: false,
  projectPolicySearchUp: true,
  caseInsensitivePaths: process.platform === 'win32',
  patternMode: 'glob',
  maxGlobStars: DEFAULT_MAX_STARS,
  network: [],
  wrappers: 'allow',
  redact: true,
  sessionApprovals: false,
  sessionApprovalTtlMs: 0,
  sessionApprovalMaxUses: 0,
  approvePersist: true,
  webBase: '',
  enforce: true,
  repeatLimit: 0,
  repeatWindowMs: 60000,
  repeatAction: 'ask',
  snapshots: true,
  snapshotMaxFiles: DEFAULT_MAX_FILES,
  snapshotMaxBytes: DEFAULT_MAX_BYTES,
  snapshotRetain: DEFAULT_RETAIN,
  approvalMode: 'approval',
  denyTools: [],
};

const SHELL_TOOLS = new Set(['bash', 'pwsh', 'powershell']);
const READ_TOOLS = new Set(['read', 'read_image', 'grep', 'glob']);
const WRITE_TOOLS = new Set(['write', 'edit']);
const PATH_ARG_TOOLS = new Set([...READ_TOOLS, ...WRITE_TOOLS]);
const DENY_BASENAMES = new Set(['.netrc', '.git-credentials', '.npmrc', '.pypirc', '.credentials.yaml', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa']);

const OPAQUE = /(^|[^\\])\$\(|`|<\s*\(|<<-?\s*['\"]?[A-Za-z_]/;
const WRAPPER = /(^|\s)(sudo|eval|xargs|env)(\s|$)|\b(bash|sh|zsh|fish|dash)\s+-[a-z]*c\b|\bfind\b[^|;]*-exec\b/;

const REDACTIONS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[redacted private key]'],
  [/\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}\b/g, '***'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '***'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, '***'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, '***'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '***'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, '***'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, '***'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/gi, 'Bearer ***'],
  [/([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*=\s*)(?:"[^"]{6,}"|'[^']{6,}'|[^\s"']{6,})/g, '$1***'],
  [/([?&](?:token|access_token|api_key|apikey|key|secret|password)=)[^&\s"']+/gi, '$1***'],
  [/"(token|access_token|api_key|apikey|secret|password|authorization)"\s*:\s*"[^"]{4,}"/gi, '"$1":"***"'],
  [/^\s*(set-)?cookie\s*:\s*.*$/gim, 'Cookie: ***'],
];

/** Windows-style separators are matched as `/`; drive letters stay as written. */
export function toPosix(path) {
  return typeof path === 'string' ? path.replace(/\\/g, '/') : path;
}

export function matches(pattern, value, caseInsensitive = process.platform === 'win32') {
  return testPattern(toPosix(pattern), toPosix(value), { caseInsensitive });
}

/** Pattern options shared by every path, command and argv surface (always glob). */
export function patternOptions(permission) {
  return {
    mode: 'glob',
    maxStars: permission?.maxGlobStars ?? DEFAULT_MAX_STARS,
    caseInsensitive: permission?.caseInsensitivePaths === true,
  };
}

/** `params` is the one surface whose dialect is selectable (`patternMode`). */
export function paramOptions(permission) {
  return {
    ...patternOptions(permission),
    mode: permission?.patternMode === 'regex' ? 'regex' : 'glob',
  };
}

/** One rule evaluation with the permission's dialect. */
function matchValue(pattern, value, permission) {
  return testPattern(toPosix(pattern), toPosix(value), patternOptions(permission));
}

function matchParam(pattern, value, permission) {
  return testPattern(pattern, value, paramOptions(permission));
}

export function expand(p, cwd) {
  if (typeof p !== 'string' || p === '') return undefined;
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return resolve(homedir(), p.slice(2));
  return isAbsolute(p) ? resolve(p) : resolve(cwd, p);
}

async function candidates(raw, cwd) {
  const abs = expand(raw, cwd);
  if (abs === undefined) return [];
  const set = new Set([raw, abs, relative(cwd, abs)]);
  try {
    set.add(await realpath(abs));
  } catch {
    // Missing path: the literal spelling is all we can match.
  }
  return [...set].filter((v) => typeof v === 'string' && v !== '');
}

function evalRules(rules, values, permission, surface) {
  let hit;
  for (const [pattern, state] of Object.entries(rules ?? {})) {
    if (!STATES.has(state)) continue;
    if (values.some((v) => matchValue(pattern, v, permission))) {
      hit = { state, pattern, surface, key: pattern };
    }
  }
  return hit;
}

function mostRestrictive(a, b) {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return SEVERITY[b.state] > SEVERITY[a.state] ? b : a;
}

// A bash token is treated as a path only when it looks like one. This keeps
// identifiers (process.env.FOO, some.identifier) from being mistaken for dotenv
// files, while bare secret.env / .env / ~/.ssh/id_rsa still match.
function isPathLike(raw) {
  if (typeof raw !== 'string' || raw === '') return false;
  if (raw.includes('/') || raw.includes('\\') || raw.startsWith('~') || raw.startsWith('.') || /^[A-Za-z]:[\\/]/u.test(raw)) return true;
  const base = raw.split(/[\\/]/u).at(-1) ?? '';
  return DENY_BASENAMES.has(base) || /\.(?:env|pfx|p12)$/u.test(base);
}

function deriveArgvRules(bash) {
  const rules = [];
  for (const [pattern, action] of Object.entries(bash ?? {})) {
    if (action !== 'ask' || !pattern.endsWith(' *')) continue;
    const parts = pattern.slice(0, -2).split(/\s+/).filter(Boolean);
    if (parts.length === 0 || parts.some((part) => /[*?]/.test(part))) continue;
    const match = { command: [parts[0]] };
    if (parts.length > 1) match.args = parts.slice(1);
    rules.push({ match, action: 'ask', derived: true });
  }
  return rules;
}

function asList(value) {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function tokenMatches(pattern, token, permission) {
  if (typeof pattern !== 'string') return false;
  if (pattern.startsWith('!')) return !matchValue(pattern.slice(1), token, permission);
  return matchValue(pattern, token, permission);
}

function argvMatches(match, decomposition, permission) {
  if (typeof match !== 'object' || match === null) return false;
  const commands = decomposition.commands;
  const tokens = commands.flatMap((cmd) => [...cmd.args, ...cmd.redirects]);
  let fields = 0;

  const patterns = (key) => asList(match[key]).filter((p) => typeof p === 'string');

  if (match.command !== undefined) {
    fields += 1;
    const pats = patterns('command');
    if (!commands.some((cmd) => pats.some((p) => matchValue(p, cmd.command, permission)))) return false;
  }
  if (match.args !== undefined) {
    fields += 1;
    if (!patterns('args').every((p) => tokens.some((t) => tokenMatches(p, t, permission)))) return false;
  }
  if (match.anyArg !== undefined) {
    fields += 1;
    const pats = patterns('anyArg');
    if (!tokens.some((t) => pats.some((p) => tokenMatches(p, t, permission)))) return false;
  }
  if (match.pipeline !== undefined) {
    fields += 1;
    const pipelines = commands.map((cmd) => cmd.command).filter((c) => c !== '').join('|');
    if (!patterns('pipeline').some((p) => matchValue(p, pipelines, permission))) return false;
  }
  return fields > 0;
}

function bashTokens(command) {
  const tokens = [];
  for (const m of command.match(/"[^"]*"|'[^']*'|[^\s|;&<>()`]+/g) ?? []) {
    tokens.push(m.replace(/^["']|["']$/g, ''));
  }
  return tokens;
}

function outside(cwd, abs) {
  return abs !== cwd && !abs.startsWith(cwd + sep);
}

const PERSISTABLE = new Set(['path', 'pathRead', 'pathWrite', 'externalDirectory', 'bash']);

/** Whether a decision names a surface this plugin can write back as a rule. */
function canPersistDecision(decision) {
  const surface = decision?.surface;
  return typeof surface === 'string' && (PERSISTABLE.has(surface) || surface.startsWith('tools.'));
}

/**
 * Append one `allow` rule to the project policy file so a one-off approval can
 * become a standing rule. Only surfaces that are flat `{ pattern: state }` maps
 * are written; argv/network/params shapes are not round-trippable from a single
 * decision and are refused rather than guessed at.
 */
function persistAllow(cwd, decision) {
  const surface = decision?.surface;
  const key = decision?.key;
  if (typeof surface !== 'string' || typeof key !== 'string' || key === '') return false;
  let target;
  let tool;
  if (PERSISTABLE.has(surface)) target = surface;
  else if (surface.startsWith('tools.')) {
    target = 'tools';
    tool = surface.slice('tools.'.length);
  } else return false;

  const file = resolve(cwd, PROJECT_POLICY);
  let doc = {};
  try {
    doc = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    // Missing or unparsable: start a fresh document rather than refuse the write.
  }
  const body = (doc.permission ?? doc ?? {});
  if (target === 'tools') {
    body.tools ??= {};
    body.tools[tool] ??= {};
    body.tools[tool][key] = 'allow';
  } else {
    body[target] ??= {};
    body[target][key] = 'allow';
  }
  const out = doc.permission === undefined ? { permission: body } : { ...doc, permission: body };
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(out, null, 2) + '\n');
  projectCache.delete(file);
  return true;
}

/** Keep the audit trail bounded: one rolling `.1` file, no unbounded growth. */
function rotateAudit(path, maxBytes) {
  if (typeof maxBytes !== 'number' || maxBytes <= 0) return;
  let size;
  try {
    size = statSync(path).size;
  } catch {
    return;
  }
  if (size < maxBytes) return;
  try {
    renameSync(path, `${path}.1`);
  } catch {
    // A failed rotation must not stop the append that follows.
  }
}

export function redactText(text) {
  if (typeof text !== 'string' || text === '') return text;
  let out = text;
  for (const [pattern, replacement] of REDACTIONS) out = out.replace(pattern, replacement);
  return out;
}

/**
 * `tools` keys are tool-name globs, so `mcp__chrome-devtools__*` can govern one
 * whole MCP server without naming its 32 tools. Every matching map is merged,
 * later keys winning a collision, and the result then evaluated as one surface.
 */
function toolRules(permission, toolName) {
  const rules = permission.tools;
  if (rules === undefined || rules === null) return undefined;
  if (rules[toolName] !== undefined) return rules[toolName];
  let merged;
  for (const [pattern, map] of Object.entries(rules)) {
    if (!matchValue(pattern, toolName, permission)) continue;
    merged = { ...(merged ?? {}), ...map };
  }
  return merged;
}

async function pathDecision(permission, pathArg, cwd, direction, toolName) {
  const values = await candidates(pathArg, cwd);
  if (values.length === 0) return undefined;
  let result = evalRules(permission.path, values, permission, 'path');
  if (direction === 'read' || direction === 'both') result = mostRestrictive(result, evalRules(permission.pathRead, values, permission, 'pathRead'));
  if (direction === 'write' || direction === 'both') result = mostRestrictive(result, evalRules(permission.pathWrite, values, permission, 'pathWrite'));
  result = mostRestrictive(result, evalRules(toolRules(permission, toolName), values, permission, `tools.${toolName}`));
  const abs = expand(pathArg, cwd);
  if (abs !== undefined && outside(cwd, abs)) {
    result = mostRestrictive(result, evalRules(permission.externalDirectory, values, permission, 'externalDirectory'));
  }
  return result;
}

/**
 * `params` — key/value rules over any tool's argument object.
 *
 * Shape: `{ "<keyGlob>": { "<valueGlob>": "deny" } }`. A key pattern matches
 * either the full dotted path (`arguments.command`) or its last segment
 * (`command`). Within one key's value map the LAST matching rule wins; across
 * keys the most restrictive result wins.
 */
function paramsDecision(permission, args) {
  const rules = permission.params;
  if (rules === undefined || rules === null || Object.keys(rules).length === 0) return undefined;
  const entries = flattenArguments(args);
  if (entries.length === 0) return undefined;
  let result;
  for (const [keyPattern, valueRules] of Object.entries(rules)) {
    if (typeof valueRules !== 'object' || valueRules === null || Array.isArray(valueRules)) continue;
    const matched = entries.filter((entry) => entryKeys(entry).some((key) => matchParam(keyPattern, key, permission)));
    if (matched.length === 0) continue;
    let hit;
    for (const [valuePattern, state] of Object.entries(valueRules)) {
      if (!STATES.has(state)) continue;
      if (matched.some((entry) => matchParam(valuePattern, entry.value, permission))) {
        hit = { state, pattern: `params ${keyPattern}=${valuePattern}`, surface: 'params', key: keyPattern, sub: valuePattern };
      }
    }
    result = mostRestrictive(result, hit);
  }
  return result;
}

/**
 * `toolParams` — key/value rules scoped to one tool, or to a tool-name glob.
 *
 * Shape: `{ "<toolGlob>": { "<keyGlob>": { "<valueGlob>": "deny" } } }`.
 * `params` applies to every tool; this one lets
 * `mcp__chrome-devtools__navigate_page` restrict its `url` without also
 * restricting an unrelated tool that happens to have a `url` argument.
 */
function toolParamsDecision(permission, exec, args) {
  const rules = permission.toolParams;
  if (rules === undefined || rules === null || Object.keys(rules).length === 0) return undefined;
  const entries = flattenArguments(args);
  if (entries.length === 0) return undefined;
  let result;
  for (const [toolPattern, keyMap] of Object.entries(rules)) {
    if (typeof keyMap !== 'object' || keyMap === null || Array.isArray(keyMap)) continue;
    if (!matchValue(toolPattern, exec.name, permission)) continue;
    for (const [keyPattern, valueRules] of Object.entries(keyMap)) {
      if (typeof valueRules !== 'object' || valueRules === null || Array.isArray(valueRules)) continue;
      const matched = entries.filter((entry) => entryKeys(entry).some((key) => matchParam(keyPattern, key, permission)));
      if (matched.length === 0) continue;
      for (const [valuePattern, state] of Object.entries(valueRules)) {
        if (!STATES.has(state)) continue;
        if (matched.some((entry) => matchParam(valuePattern, entry.value, permission))) {
          result = mostRestrictive(result, {
            state,
            pattern: `toolParams ${toolPattern}.${keyPattern}=${valuePattern}`,
            surface: 'toolParams',
            key: toolPattern,
            sub: keyPattern,
          });
        }
      }
    }
  }
  return result;
}

/** `agents` — one state per agent identity, most specific identity first. */
function agentsDecision(permission, agent) {
  if (agent === undefined) return undefined;
  const rules = permission.agents;
  if (rules === undefined || rules === null || Object.keys(rules).length === 0) return undefined;
  for (const candidate of agentCandidates(agent)) {
    for (const [pattern, state] of Object.entries(rules)) {
      if (!STATES.has(state)) continue;
      if (matchValue(pattern, candidate, permission)) {
        return { state, pattern, surface: 'agents', key: pattern };
      }
    }
  }
  return undefined;
}

const PROJECT_POLICY = '.dsh/guard-policy.json';
const projectCache = new Map();

function overlay(basePermission, source) {
  const map = (name) => ({ ...(basePermission[name] ?? {}), ...(source[name] ?? {}) });
  const pick = (...values) => values.find((value) => value !== undefined);
  return {
    ...basePermission,
    '*': pick(source['*'], basePermission['*']),
    path: map('path'),
    pathRead: map('pathRead'),
    pathWrite: map('pathWrite'),
    externalDirectory: map('externalDirectory'),
    bash: map('bash'),
    tools: map('tools'),
    params: map('params'),
    toolParams: map('toolParams'),
    agents: map('agents'),
    argv: source.argv ?? basePermission.argv,
    network: source.network ?? basePermission.network,
    wrappers: pick(source.wrappers, basePermission.wrappers),
    opaque: pick(source.opaque, basePermission.opaque),
    redact: pick(source.redact, basePermission.redact),
    sessionApprovals: pick(source.sessionApprovals, basePermission.sessionApprovals),
    sessionApprovalTtlMs: pick(source.sessionApprovalTtlMs, basePermission.sessionApprovalTtlMs),
    sessionApprovalMaxUses: pick(source.sessionApprovalMaxUses, basePermission.sessionApprovalMaxUses),
    approvePersist: pick(source.approvePersist, basePermission.approvePersist),
    webBase: pick(source.webBase, basePermission.webBase),
    enforce: pick(source.enforce, basePermission.enforce),
    repeatLimit: pick(source.repeatLimit, basePermission.repeatLimit),
    repeatWindowMs: pick(source.repeatWindowMs, basePermission.repeatWindowMs),
    repeatAction: pick(source.repeatAction, basePermission.repeatAction),
    snapshots: pick(source.snapshots, basePermission.snapshots),
    snapshotMaxFiles: pick(source.snapshotMaxFiles, basePermission.snapshotMaxFiles),
    snapshotMaxBytes: pick(source.snapshotMaxBytes, basePermission.snapshotMaxBytes),
    snapshotRetain: pick(source.snapshotRetain, basePermission.snapshotRetain),
    patternMode: pick(source.patternMode, basePermission.patternMode),
    maxGlobStars: pick(source.maxGlobStars, basePermission.maxGlobStars),
    approvalMode: pick(source.approvalMode, basePermission.approvalMode),
    yolo: pick(source.yolo, basePermission.yolo),
    sandboxAware: pick(source.sandboxAware, basePermission.sandboxAware),
    audit: pick(source.audit, basePermission.audit),
    auditPath: pick(source.auditPath, basePermission.auditPath),
    auditMaxBytes: pick(source.auditMaxBytes, basePermission.auditMaxBytes),
    projectPolicy: basePermission.projectPolicy,
    denyTools: pick(source.denyTools, basePermission.denyTools),
  };
}

/** Cache one project file's parsed body, keyed by mtime. */
function readProjectFile(file) {
  try {
    const stat = statSync(file);
    const cached = projectCache.get(file);
    if (cached !== undefined && cached.mtimeMs === stat.mtimeMs) return cached.source;
    const raw = parseJsonc(readFileSync(file, 'utf8'));
    const body = raw?.permission ?? raw;
    if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
    const { $schema, ...source } = body;
    const errors = validate(source);
    if (errors.length > 0) {
      const bad = { invalid: errors };
      projectCache.set(file, { mtimeMs: stat.mtimeMs, source: bad });
      return bad;
    }
    projectCache.set(file, { mtimeMs: stat.mtimeMs, source });
    return source;
  } catch {
    return undefined;
  }
}

/**
 * Project rules stack from the filesystem root down to the session cwd, so a
 * monorepo can put a baseline in `<repo>/.dsh/guard-policy.json` and override
 * one package in `<repo>/pkg/.dsh/guard-policy.json`. The nearest file wins for
 * a conflicting key (plain object spread), and the global policy stays the
 * floor underneath all of them.
 */
function projectPermission(basePermission, cwd) {
  if (basePermission.projectPolicy === false) return basePermission;
  const chain = [];
  let dir = resolve(cwd);
  for (;;) {
    chain.unshift(dir);
    const parent = dirname(dir);
    if (parent === dir) break;
    if (basePermission.projectPolicySearchUp === false) break;
    dir = parent;
  }

  let merged = basePermission;
  for (const base of chain) {
    const source = readProjectFile(join(base, PROJECT_POLICY));
    if (source === undefined) continue;
    if (source.invalid !== undefined) {
      if (basePermission.projectPolicyStrict) return { invalid: source.invalid.map((error) => `project: ${error}`) };
      continue;
    }
    merged = overlay(merged, source);
  }
  return merged;
}

function collectUrls(value, out = [], depth = 0) {
  if (depth > 3 || value === null || value === undefined) return out;
  if (typeof value === 'string') {
    for (const match of value.matchAll(/https?:\/\/[^\s"'`;|)]+/g)) out.push(match[0]);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectUrls(item, out, depth + 1);
    return out;
  }
  if (typeof value === 'object') {
    for (const item of Object.values(value)) collectUrls(item, out, depth + 1);
  }
  return out;
}

function networkLayer(permission, exec) {
  const rules = permission.network ?? [];
  if (rules.length === 0) return undefined;
  const urls = collectUrls(exec?.arguments ?? {});
  if (urls.length === 0) return undefined;
  let hit;
  for (const rule of rules) {
    const domains = asList(rule.match?.domains).filter((d) => typeof d === 'string');
    for (const url of urls) {
      try {
        const host = new URL(url).hostname;
        if (domains.some((pattern) => matchValue(pattern, host, permission))) {
          hit = { state: rule.action, pattern: `network ${host}`, surface: 'network', key: host };
        }
      } catch {
        // Not a parseable URL; ignore.
      }
    }
  }
  return hit;
}

export async function decide(exec, cwd, permission = DEFAULT_PERMISSION) {
  if (permission.invalid) {
    return { state: 'deny', pattern: `invalid config: ${permission.invalid.join('; ')}` };
  }
  if (permission.denyTools?.includes(exec.name)) {
    return { state: 'deny', pattern: `denyTools: ${exec.name}`, surface: 'denyTools', key: exec.name };
  }
  const args = (exec && typeof exec.arguments === 'object' && exec.arguments) || {};
  const layers = [];
  const direction = READ_TOOLS.has(exec.name) ? 'read' : WRITE_TOOLS.has(exec.name) ? 'write' : 'both';

  // Agent identity is a cross-cutting gate: a subagent or a read-only preset
  // can be held to a tighter baseline than the interactive main agent.
  layers.push(agentsDecision(permission, exec.agent));

  if (PATH_ARG_TOOLS.has(exec.name) || exec.name.startsWith('mcp__') || exec.name === 'mcp') {
    const nested = (args.arguments && typeof args.arguments === 'object') ? args.arguments : {};
    const pathArg = args.file_path ?? args.path ?? nested.file_path ?? nested.path;
    if (typeof pathArg === 'string') {
      layers.push(await pathDecision(permission, pathArg, cwd, direction, exec.name));
    } else {
      // A tool with no path argument still has `tools.<name>` rules; match them
      // against the tool name so `{ "*": "deny" }` can refuse an MCP tool that
      // takes only non-path arguments.
      layers.push(evalRules(toolRules(permission, exec.name), [exec.name], permission, `tools.${exec.name}`));
    }
  }

  // `params` covers every tool, including ones with no path argument
  // (web_search, skill, mcp non-path args).
  layers.push(paramsDecision(permission, args));
  // `toolParams` narrows the same matching to one tool or one MCP server.
  layers.push(toolParamsDecision(permission, exec, args));

  if (SHELL_TOOLS.has(exec.name) && typeof args.command === 'string') {
    layers.push(evalRules(permission.bash, [args.command], permission, 'bash'));
    if (WRAPPER.test(args.command) && permission.wrappers !== 'allow') {
      layers.push({ state: permission.wrappers, pattern: 'wrapper (bash -c/sudo/eval/xargs/find -exec)', surface: 'wrappers', key: 'wrappers' });
    }
    if (OPAQUE.test(args.command) && permission.opaque !== 'allow') {
      layers.push({ state: permission.opaque, pattern: 'opaque construct ($(...), backtick, heredoc, <())', surface: 'opaque', key: 'opaque' });
    }
    const decomposition = decomposeShellCommand(args.command);
    for (const rule of permission.argv ?? []) {
      if (argvMatches(rule.match, decomposition, permission)) {
        layers.push({ state: rule.action, pattern: `argv ${JSON.stringify(rule.match)}`, surface: 'argv' });
      }
    }
    for (const simple of decomposition.commands) {
      for (const target of simple.redirects) {
        layers.push(await pathDecision(permission, target, cwd, 'write', 'bash'));
      }
    }
    for (const token of bashTokens(args.command)) {
      const raw = token.includes('=') ? token.slice(token.indexOf('=') + 1) : token;
      if (raw === '') continue;
      if (/[*?]/.test(raw)) continue; // glob patterns are patterns, not paths
      if (!isPathLike(raw)) continue; // identifiers such as process.env.X are not paths
      if (DENY_BASENAMES.has(raw.split(/[\\/]/u).at(-1) ?? '')) {
        layers.push({ state: 'deny', pattern: `basename ${raw}`, surface: 'basename', key: raw });
        continue;
      }
      layers.push(await pathDecision(permission, raw, cwd, 'both', exec.name));
    }
  }

  layers.push(networkLayer(permission, exec));
  let result;
  for (const layer of layers) result = mostRestrictive(result, layer);
  result = mostRestrictive(result, { state: permission['*'], pattern: '*', surface: 'default', key: '*' });
  return result?.state === 'allow' ? undefined : result;
}

export function validate(source) {
  const errors = [];
  const checkMap = (name, value, nested = false) => {
    if (value === undefined) return;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      errors.push(`${name} must be an object`);
      return;
    }
    for (const [key, state] of Object.entries(value)) {
      if (nested) {
        if (typeof state !== 'object' || state === null || Array.isArray(state)) {
          errors.push(`${name}.${key} must be an object`);
          continue;
        }
        for (const [k, s] of Object.entries(state)) if (!STATES.has(s)) errors.push(`${name}.${key}.${k} must be allow, ask, or deny`);
      } else if (!STATES.has(state)) {
        errors.push(`${name}.${key} must be allow, ask, or deny`);
      }
    }
  };

  const globOpts = { mode: 'glob', maxStars: source.maxGlobStars ?? DEFAULT_MAX_STARS };
  const paramOpts = { ...globOpts, mode: source.patternMode === 'regex' ? 'regex' : 'glob' };
  const checkPatterns = (name, value, opts) => {
    if (value === undefined || typeof value !== 'object' || value === null || Array.isArray(value)) return;
    for (const key of Object.keys(value)) {
      const err = checkPattern(key, opts);
      if (err !== undefined) errors.push(`${name}: ${err}`);
    }
  };

  if (source['*'] !== undefined && !STATES.has(source['*'])) errors.push('"*" must be allow, ask, or deny');
  for (const name of ['path', 'pathRead', 'pathWrite', 'externalDirectory', 'bash']) {
    checkMap(name, source[name]);
    checkPatterns(name, source[name], globOpts);
  }
  checkMap('tools', source.tools, true);
  checkMap('params', source.params, true);
  // `toolParams` is one level deeper than `params`: tool -> key -> value -> state.
  if (source.toolParams !== undefined) {
    if (typeof source.toolParams !== 'object' || source.toolParams === null || Array.isArray(source.toolParams)) {
      errors.push('toolParams must be an object');
    } else {
      for (const [tool, keyMap] of Object.entries(source.toolParams)) {
        if (typeof keyMap !== 'object' || keyMap === null || Array.isArray(keyMap)) {
          errors.push(`toolParams.${tool} must be an object`);
          continue;
        }
        for (const [key, valueMap] of Object.entries(keyMap)) {
          if (typeof valueMap !== 'object' || valueMap === null || Array.isArray(valueMap)) {
            errors.push(`toolParams.${tool}.${key} must be an object`);
            continue;
          }
          for (const [valuePattern, state] of Object.entries(valueMap)) {
            if (!STATES.has(state)) errors.push(`toolParams.${tool}.${key}.${valuePattern} must be allow, ask, or deny`);
          }
        }
      }
    }
  }
  checkPatterns('params', source.params, paramOpts);
  for (const value of Object.values(source.params ?? {})) {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) checkPatterns('params.value', value, paramOpts);
  }
  checkMap('agents', source.agents);
  checkPatterns('agents', source.agents, globOpts);
  if (source.wrappers !== undefined && !STATES.has(source.wrappers)) errors.push('wrappers must be allow, ask, or deny');
  if (source.redact !== undefined && typeof source.redact !== 'boolean') errors.push('redact must be a boolean');
  if (source.sessionApprovals !== undefined && typeof source.sessionApprovals !== 'boolean') errors.push('sessionApprovals must be a boolean');
  if (source.approvalMode !== undefined && !APPROVAL_MODES.has(source.approvalMode)) errors.push('approvalMode must be "approval", "question" or "dialog"');
  if (source.denyTools !== undefined && !Array.isArray(source.denyTools)) errors.push('denyTools must be an array of tool names');
  if (source.opaque !== undefined && !STATES.has(source.opaque)) errors.push('opaque must be allow, ask, or deny');
  if (source.sandboxAware !== undefined && typeof source.sandboxAware !== 'boolean') errors.push('sandboxAware must be a boolean');
  if (source.yolo !== undefined && typeof source.yolo !== 'boolean') errors.push('yolo must be a boolean');
  if (source.audit !== undefined && typeof source.audit !== 'boolean') errors.push('audit must be a boolean');
  if (source.auditPath !== undefined && typeof source.auditPath !== 'string') errors.push('auditPath must be a string');
  if (source.auditMaxBytes !== undefined && (!Number.isInteger(source.auditMaxBytes) || source.auditMaxBytes < 0)) errors.push('auditMaxBytes must be a non-negative integer');
  if (source.enforce !== undefined && typeof source.enforce !== 'boolean') errors.push('enforce must be a boolean');
  if (source.repeatLimit !== undefined && (!Number.isInteger(source.repeatLimit) || source.repeatLimit < 0)) errors.push('repeatLimit must be a non-negative integer');
  if (source.repeatWindowMs !== undefined && (!Number.isInteger(source.repeatWindowMs) || source.repeatWindowMs < 1)) errors.push('repeatWindowMs must be a positive integer');
  if (source.repeatAction !== undefined && !STATES.has(source.repeatAction)) errors.push('repeatAction must be allow, ask, or deny');
  if (source.snapshots !== undefined && typeof source.snapshots !== 'boolean') errors.push('snapshots must be a boolean');
  if (source.snapshotMaxFiles !== undefined && (!Number.isInteger(source.snapshotMaxFiles) || source.snapshotMaxFiles < 0)) errors.push('snapshotMaxFiles must be a non-negative integer');
  if (source.snapshotMaxBytes !== undefined && (!Number.isInteger(source.snapshotMaxBytes) || source.snapshotMaxBytes < 0)) errors.push('snapshotMaxBytes must be a non-negative integer');
  if (source.snapshotRetain !== undefined && (!Number.isInteger(source.snapshotRetain) || source.snapshotRetain < 0)) errors.push('snapshotRetain must be a non-negative integer');
  if (source.approvePersist !== undefined && typeof source.approvePersist !== 'boolean') errors.push('approvePersist must be a boolean');
  if (source.webBase !== undefined && typeof source.webBase !== 'string') errors.push('webBase must be a string');
  if (source.patternMode !== undefined && source.patternMode !== 'glob' && source.patternMode !== 'regex') errors.push('patternMode must be "glob" or "regex"');
  if (source.maxGlobStars !== undefined && (!Number.isInteger(source.maxGlobStars) || source.maxGlobStars < 0)) errors.push('maxGlobStars must be a non-negative integer');
  if (source.sessionApprovalTtlMs !== undefined && (!Number.isInteger(source.sessionApprovalTtlMs) || source.sessionApprovalTtlMs < 0)) errors.push('sessionApprovalTtlMs must be a non-negative integer');
  if (source.sessionApprovalMaxUses !== undefined && (!Number.isInteger(source.sessionApprovalMaxUses) || source.sessionApprovalMaxUses < 0)) errors.push('sessionApprovalMaxUses must be a non-negative integer');
  if (source.projectPolicy !== undefined && typeof source.projectPolicy !== 'boolean') errors.push('projectPolicy must be a boolean');
  if (source.projectPolicyStrict !== undefined && typeof source.projectPolicyStrict !== 'boolean') errors.push('projectPolicyStrict must be a boolean');
  if (source.projectPolicySearchUp !== undefined && typeof source.projectPolicySearchUp !== 'boolean') errors.push('projectPolicySearchUp must be a boolean');
  if (source.caseInsensitivePaths !== undefined && typeof source.caseInsensitivePaths !== 'boolean') errors.push('caseInsensitivePaths must be a boolean');
  if (source.network !== undefined) {
    if (!Array.isArray(source.network)) errors.push('network must be an array of rules');
    else source.network.forEach((rule, index) => {
      if (typeof rule !== 'object' || rule === null) errors.push(`network[${index}] must be an object`);
      else if (!STATES.has(rule.action)) errors.push(`network[${index}].action must be allow, ask, or deny`);
      else if (typeof rule.match !== 'object' || rule.match === null) errors.push(`network[${index}].match must be an object`);
    });
  }
  if (source.argv !== undefined) {
    if (!Array.isArray(source.argv)) errors.push('argv must be an array of rules');
    else {
      source.argv.forEach((rule, index) => {
        if (typeof rule !== 'object' || rule === null) errors.push(`argv[${index}] must be an object`);
        else if (!STATES.has(rule.action)) errors.push(`argv[${index}].action must be allow, ask, or deny`);
        else if (typeof rule.match !== 'object' || rule.match === null) errors.push(`argv[${index}].match must be an object`);
      });
    }
  }
  return errors;
}

// The repository copy is the seed (first mount) and the fallback (data file
// missing or unreadable). The live policy is the user-owned file in the data
// directory, so an edit never dirties the checkout.
const BUILTIN_POLICY_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'policy.json');
const BUILTIN_SCHEMA_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'policy.schema.json');

/**
 * The raw policy body on disk, with nothing merged in. `/guard-policy` edits
 * this document, so it must not start from the defaults — otherwise the first
 * write would freeze every default into the user's file.
 */
function readLivePolicyBody(file) {
  try {
    const raw = parseJsonc(readFileSync(file, 'utf8'));
    const body = raw?.permission ?? raw;
    if (typeof body !== 'object' || body === null || Array.isArray(body)) return {};
    const { $schema, ...permission } = body;
    return permission;
  } catch {
    return {};
  }
}

function readPolicyFile(path) {
  try {
    const raw = parseJsonc(readFileSync(path, 'utf8'));
    const body = raw?.permission ?? raw;
    if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
    // `$schema` is editor metadata, not a rule surface.
    const { $schema, ...permission } = body;
    return permission;
  } catch {
    return undefined;
  }
}

function loadPolicy() {
  const user = readPolicyFile(policyPath());
  if (user !== undefined) return user;
  return readPolicyFile(BUILTIN_POLICY_PATH) ?? {};
}

export function mergePermission(config = {}) {
  const policy = loadPolicy();
  const source = config.permission ?? config;
  const errors = [...validate(policy), ...validate(source)];
  if (errors.length > 0) return { invalid: errors };
  const pick = (...values) => values.find((value) => value !== undefined);
  const map = (name) => ({ ...(DEFAULT_PERMISSION[name] ?? {}), ...(policy[name] ?? {}), ...(source[name] ?? {}) });
  return {
    '*': pick(source['*'], policy['*'], DEFAULT_PERMISSION['*']),
    path: map('path'),
    pathRead: map('pathRead'),
    pathWrite: map('pathWrite'),
    externalDirectory: map('externalDirectory'),
    bash: map('bash'),
    tools: map('tools'),
    params: map('params'),
    toolParams: map('toolParams'),
    agents: map('agents'),
    argv: [...deriveArgvRules(pick(source.bash, policy.bash, DEFAULT_PERMISSION.bash)), ...pick(source.argv, policy.argv, DEFAULT_PERMISSION.argv)],
    wrappers: STATES.has(pick(source.wrappers, policy.wrappers)) ? pick(source.wrappers, policy.wrappers) : 'allow',
    opaque: STATES.has(pick(source.opaque, policy.opaque)) ? pick(source.opaque, policy.opaque) : 'ask',
    sandboxAware: pick(source.sandboxAware, policy.sandboxAware) !== false,
    yolo: pick(source.yolo, policy.yolo) === true,
    audit: pick(source.audit, policy.audit) !== false,
    auditPath: pick(source.auditPath, policy.auditPath) ?? defaultAuditPath(),
    auditMaxBytes: pick(source.auditMaxBytes, policy.auditMaxBytes) ?? DEFAULT_PERMISSION.auditMaxBytes,
    enforce: pick(source.enforce, policy.enforce) !== false,
    repeatLimit: pick(source.repeatLimit, policy.repeatLimit) ?? 0,
    repeatWindowMs: pick(source.repeatWindowMs, policy.repeatWindowMs) ?? 60000,
    repeatAction: STATES.has(pick(source.repeatAction, policy.repeatAction)) ? pick(source.repeatAction, policy.repeatAction) : 'ask',
    snapshots: pick(source.snapshots, policy.snapshots) !== false,
    snapshotMaxFiles: pick(source.snapshotMaxFiles, policy.snapshotMaxFiles) ?? DEFAULT_MAX_FILES,
    snapshotMaxBytes: pick(source.snapshotMaxBytes, policy.snapshotMaxBytes) ?? DEFAULT_MAX_BYTES,
    snapshotRetain: pick(source.snapshotRetain, policy.snapshotRetain) ?? DEFAULT_RETAIN,
    approvePersist: pick(source.approvePersist, policy.approvePersist) !== false,
    webBase: pick(source.webBase, policy.webBase) ?? '',
    patternMode: pick(source.patternMode, policy.patternMode) === 'regex' ? 'regex' : 'glob',
    maxGlobStars: pick(source.maxGlobStars, policy.maxGlobStars) ?? DEFAULT_MAX_STARS,
    projectPolicy: pick(source.projectPolicy, policy.projectPolicy) !== false,
    projectPolicyStrict: pick(source.projectPolicyStrict, policy.projectPolicyStrict) === true,
    projectPolicySearchUp: pick(source.projectPolicySearchUp, policy.projectPolicySearchUp) !== false,
    caseInsensitivePaths: pick(source.caseInsensitivePaths, policy.caseInsensitivePaths) ?? (process.platform === 'win32'),
    network: pick(source.network, policy.network, DEFAULT_PERMISSION.network),
    redact: pick(source.redact, policy.redact) !== false,
    sessionApprovals: pick(source.sessionApprovals, policy.sessionApprovals) === true,
    sessionApprovalTtlMs: pick(source.sessionApprovalTtlMs, policy.sessionApprovalTtlMs) ?? 0,
    sessionApprovalMaxUses: pick(source.sessionApprovalMaxUses, policy.sessionApprovalMaxUses) ?? 0,
    approvalMode: APPROVAL_MODES.has(pick(source.approvalMode, policy.approvalMode)) ? pick(source.approvalMode, policy.approvalMode) : 'approval',
    denyTools: pick(source.denyTools, policy.denyTools) ?? [],
  };
}

// DSH already enforces sandbox modes. Asking on top of `danger-full-access`
// (yolo) or `read-only` is noise: writes cannot happen under read-only, and the
// user asked for full access under danger-full-access. Deny rules still apply.
function sandboxYolo(ctx, exec, permission) {
  if (permission.sandboxAware === false || exec?.agent === undefined) return false;
  const mode = ctx.sessionProjections?.stateOf?.(exec.agent.session, 'sandboxMode');
  return mode === 'danger-full-access' || mode === 'read-only';
}

function sessionOf(exec) {
  return exec?.agent?.session?.id ?? exec?.agent?.id;
}

export function apply(ctx, config = {}) {
  // Every file this plugin owns lives under $DSH_HOME/dsh-plugins/dsh-guard/.
  // Files earlier versions wrote into the home root move there, and the shipped
  // policy seeds the data directory on first mount so the live policy is the
  // user-owned copy from then on. This has to run before the first read.
  try {
    migrateLegacy((message) => ctx.logger?.info?.(message));
    ensureConfigDir();
    seedPolicy(BUILTIN_POLICY_PATH, (message) => ctx.logger?.info?.(message), BUILTIN_SCHEMA_PATH);
  } catch (error) {
    ctx.logger?.warn?.(`dsh-guard: data directory setup failed: ${String(error)}`);
  }

  let permission = mergePermission(config);
  let lastDecision;
  if (permission.invalid) {
    ctx.logger?.warn?.(`dsh-guard: invalid config, denying every call: ${permission.invalid.join('; ')}`);
  }

  const pending = new Map();
  // sid -> Map<pattern, { until, uses, maxUses }>; `until === 0` means no expiry
  // and `maxUses === 0` means unlimited, so the defaults match the old Set.
  const approved = new Map();
  // A bounded in-memory window of decisions, newest first. Declared before
  // `writeStatus` reads it — the first write happens during mount.
  const recent = [];
  const statusPath = defaultStatusPath();
  const livePolicy = policyPath();
  let commandRegistered = false;
  // Diagnostic: the command names the host actually lists for the last agent
  // that made a tool call. An empty list here means registration never reached
  // the command directory; a populated list without `guard-test` means it is
  // scoped elsewhere.
  let commandNames = null;
  // Why the custom question channel did or did not run. 
  // distinguishes "service missing" from "service rejected the call" from
  // "answered", which the DSH-native approval fallback cannot show.
  let questionStatus = 'not-tried';
  // Advertised Web origin, resolved once the web server is mounted. Used to
  // build an absolute link for the approval card's diff page.
  let advertisedBase = '';
  // Last time a Client asked for the queue. A dialog with no listener must not
  // park the call for the full timeout, so this gates the dialog channel.
  let lastPollAt = 0;
  const writeStatus = () => {
    try {
      writeFileSync(statusPath, JSON.stringify({
        version: VERSION,
        pid: process.pid,
        at: new Date().toISOString(),
        dataDir: dirname(statusPath),
        policyPath: livePolicy,
        commandNames,
        config: {
          invalid: permission.invalid ?? null,
          approvalMode: permission.approvalMode,
          wrappers: permission.wrappers,
          redact: permission.redact,
          sessionApprovals: permission.sessionApprovals,
          denyTools: permission.denyTools,
          bashRuleCount: Object.keys(permission.bash ?? {}).length,
          bashRulesSample: Object.keys(permission.bash ?? {}).slice(0, 12),
          toolRules: Object.keys(permission.tools ?? {}),
          paramRules: Object.keys(permission.params ?? {}),
          agentRules: Object.keys(permission.agents ?? {}),
          argvRules: (permission.argv ?? []).length,
          sandboxAware: permission.sandboxAware,
          projectPolicy: permission.projectPolicy,
          projectPolicyStrict: permission.projectPolicyStrict,
          caseInsensitivePaths: permission.caseInsensitivePaths,
          patternMode: permission.patternMode,
          maxGlobStars: permission.maxGlobStars,
          enforce: permission.enforce,
          repeatLimit: permission.repeatLimit,
          repeatWindowMs: permission.repeatWindowMs,
          repeatAction: permission.repeatAction,
          snapshots: permission.snapshots,
          snapshotRetain: permission.snapshotRetain,
          commandRegistered,
          questionStatus,
          webBase: advertisedBase,
          networkRules: (permission.network ?? []).length,
          audit: permission.audit,
          auditPath: permission.auditPath,
          yolo: permission.yolo,
        },
        approved: [...approved.entries()].map(([sid, grants]) => [sid, [...grants.keys()]]),
        lastDecision: lastDecision ?? null,
        recentDecisions: recent,
      }, null, 2));
    } catch {
      // Diagnostics must never break enforcement.
    }
  };
  writeStatus();

  // Hot reload follows the live data-directory policy. A deleted file falls
  // back to the shipped seed on the next read, so recovery never needs a
  // restart.
  let watchedSignature = '';
  const reloadPolicy = () => {
    try {
      const raw = readFileSync(livePolicy, 'utf8');
      if (raw === watchedSignature) return;
      watchedSignature = raw;
      const next = mergePermission(config);
      if (next.invalid) {
        ctx.logger?.warn?.(`dsh-guard: policy reload rejected: ${next.invalid.join('; ')}`);
        return;
      }
      permission = next;
      writeStatus();
    } catch (error) {
      ctx.logger?.warn?.(`dsh-guard: policy reload failed: ${String(error)}`);
    }
  };
  try {
    watchedSignature = readFileSync(livePolicy, 'utf8');
  } catch {
    // Missing policy file: the shipped seed + profile config remain in force.
  }

  const policyWatcher = watchFile(livePolicy, { interval: 1000 }, reloadPolicy);
  policyWatcher.unref?.();
  ctx.on('dispose', () => unwatchFile(livePolicy, reloadPolicy));

  // Browser-facing routes for the settings panel. Only switches and scalar
  // knobs travel over HTTP; rules themselves stay in policy.json. The fence is
  // the same one every plugin uses: loopback or same-origin only.
  ctx.inject?.(['webServer'], (scope) => {
    const webServer = scope.webServer;
    if (webServer?.register === undefined) return;
    try {
      const webApp = ctx.get?.('webApp');
      if (typeof webApp?.getAdvertisedUrl === 'function') {
        advertisedBase = String(webApp.getAdvertisedUrl()).replace(/\/+$/u, '');
        writeStatus();
      }
    } catch {
      advertisedBase = '';
    }
    const allowed = (req) => {
      const remote = req.socket?.remoteAddress ?? '';
      if (remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1') return true;
      const host = String(req.headers.host ?? '').split(':')[0];
      const origin = String(req.headers.origin ?? '');
      try {
        return origin !== '' && new URL(origin).hostname === host;
      } catch {
        return false;
      }
    };
    const json = (res, status, body) => {
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body));
    };
    const readBody = async (req, limit = 32 * 1024) => {
      let body = '';
      for await (const chunk of req) {
        body += String(chunk);
        if (body.length > limit) throw new Error('body too large');
      }
      return body === '' ? {} : JSON.parse(body);
    };

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: '/api/dsh-guard/state',
      handler: async (req, res) => {
        if (!allowed(req)) return json(res, 403, { error: 'forbidden' });
        return json(res, 200, {
          config: {
            enforce: permission.enforce,
            yolo: permission.yolo,
            snapshots: permission.snapshots,
            snapshotMaxFiles: permission.snapshotMaxFiles,
            snapshotMaxBytes: permission.snapshotMaxBytes,
            snapshotRetain: permission.snapshotRetain,
            audit: permission.audit,
            auditMaxBytes: permission.auditMaxBytes,
            repeatLimit: permission.repeatLimit,
            repeatWindowMs: permission.repeatWindowMs,
            repeatAction: permission.repeatAction,
            approvalMode: permission.approvalMode,
          },
          presets: listPresets(),
          recentDecisions: recent,
          snapshots: listSnapshots(snapshotsDir()).slice(0, 8).map((entry) => ({
            id: entry.id,
            at: entry.at,
            tool: entry.tool,
            paths: entry.paths,
          })),
          policyPath: livePolicy,
        });
      },
    }), 'dsh-guard: state route');

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: '/api/dsh-guard/config',
      handler: async (req, res) => {
        if (!allowed(req)) return json(res, 403, { error: 'forbidden' });
        if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
        try {
          const body = await readBody(req);
          const patch = typeof body.patch === 'object' && body.patch !== null ? body.patch : body;
          const merged = applyPatch(readLivePolicyBody(livePolicy), patch);
          const errors = validate(merged.next);
          if (errors.length > 0) return json(res, 400, { error: errors.join('; ') });
          if (merged.changed) {
            if (existsSync(livePolicy)) copyFileSync(livePolicy, `${livePolicy}.bak`);
            writeFileSync(livePolicy, `${JSON.stringify({ $schema: './policy.schema.json', permission: merged.next }, null, 2)}\n`, { mode: 0o600 });
          }
          return json(res, 200, { ok: true, changed: merged.changed });
        } catch (error) {
          return json(res, 400, { error: String(error?.message ?? error) });
        }
      },
    }), 'dsh-guard: config route');

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: '/api/dsh-guard/preset',
      handler: async (req, res) => {
        if (!allowed(req)) return json(res, 403, { error: 'forbidden' });
        if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
        try {
          const body = await readBody(req);
          const preset = getPreset(String(body.name ?? ''));
          if (preset === undefined) return json(res, 400, { error: `unknown preset: ${body.name}` });
          const merged = applyPatch(readLivePolicyBody(livePolicy), preset.permission);
          const errors = validate(merged.next);
          if (errors.length > 0) return json(res, 400, { error: errors.join('; ') });
          if (existsSync(livePolicy)) copyFileSync(livePolicy, `${livePolicy}.bak`);
          writeFileSync(livePolicy, `${JSON.stringify({ $schema: './policy.schema.json', permission: merged.next }, null, 2)}\n`, { mode: 0o600 });
          return json(res, 200, { ok: true });
        } catch (error) {
          return json(res, 400, { error: String(error?.message ?? error) });
        }
      },
    }), 'dsh-guard: preset route');

    // The approval card can only carry Markdown; this page is the two-column
    // view the card links to. It renders nothing that was not already shown in
    // the card, and entries expire.
    const pageAllowed = (req) => {
      const remote = req.socket?.remoteAddress ?? '';
      if (remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1') return true;
      // A browser navigation may omit Origin; the web layer has already
      // authenticated the request, so requiring a Host header is enough here.
      return typeof req.headers.host === 'string' && req.headers.host !== '';
    };
    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: '/api/dsh-guard/diff',
      handler: async (req, res) => {
        if (!pageAllowed(req)) {
          res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('forbidden');
          return;
        }
        const id = new URL(req.url ?? '/', 'http://local').searchParams.get('id') ?? '';
        const entry = lookupDiff(id);
        if (entry === undefined) {
          res.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
          res.end('<!doctype html><meta charset="utf-8"><p style="font:14px system-ui;padding:24px;color:#6b7280">预览已过期，请重新触发一次审批。</p>');
          return;
        }
        const embed = new URL(req.url ?? '/', 'http://local').searchParams.get('embed') === '1';
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(renderDiffPage(id, entry, { embed }));
      },
    }), 'dsh-guard: diff page route');

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: '/api/dsh-guard/pending',
      handler: async (req, res) => {
        if (!allowed(req)) return json(res, 403, { error: 'forbidden' });
        lastPollAt = Date.now();
        const pending = [...pendingApprovals.values()].map((entry) => ({
          id: entry.id,
          at: entry.at,
          tool: entry.tool,
          pattern: entry.pattern,
          surface: entry.surface,
          path: entry.path,
          before: entry.before,
          after: entry.after,
          canPersist: entry.canPersist,
        }));
        return json(res, 200, { pending, mode: permission.approvalMode });
      },
    }), 'dsh-guard: pending route');

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: '/api/dsh-guard/decide',
      handler: async (req, res) => {
        if (!allowed(req)) return json(res, 403, { error: 'forbidden' });
        if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
        try {
          const body = await readBody(req);
          const entry = pendingApprovals.get(String(body.id ?? ''));
          if (entry === undefined) return json(res, 404, { error: 'no such request' });
          const choice = String(body.choice ?? '');
          if (!['allow', 'session', 'persist', 'deny'].includes(choice)) return json(res, 400, { error: 'bad choice' });
          entry.finish({ choice, reason: typeof body.reason === 'string' ? body.reason : undefined });
          return json(res, 200, { ok: true });
        } catch (error) {
          return json(res, 400, { error: String(error?.message ?? error) });
        }
      },
    }), 'dsh-guard: decide route');
  });

  // The audit file is the durable record; this window is what `guard_status`
  // and `status.json` show without reading a multi-megabyte JSONL per call.
  const remember = (exec, decision, snapshotId) => {
    recent.unshift({
      at: new Date().toISOString(),
      tool: exec.name,
      state: decision?.state ?? 'allow',
      pattern: decision?.pattern ?? null,
      surface: decision?.surface ?? null,
      snapshot: typeof snapshotId === 'string' ? snapshotId : null,
    });
    if (recent.length > RECENT_LIMIT) recent.length = RECENT_LIMIT;
  };

  const audit = (exec, decision, snapshotId) => {
    remember(exec, decision, snapshotId);
    if (!permission.audit) return;
    try {
      rotateAudit(permission.auditPath, permission.auditMaxBytes);
      const rawArgs = typeof exec.arguments === 'object' ? JSON.stringify(exec.arguments) : '';
      appendFileSync(permission.auditPath, JSON.stringify({
        at: new Date().toISOString(),
        session: sessionOf(exec),
        agent: agentLabel(exec.agent),
        tool: exec.name,
        state: decision?.state ?? 'allow',
        pattern: decision?.pattern ?? null,
        surface: decision?.surface ?? null,
        dryRun: decision?.dryRun === true ? true : undefined,
        snapshot: typeof snapshotId === 'string' ? snapshotId : undefined,
        // Argument text is redacted before it reaches the disk: the trail must
        // never become the place a credential survives.
        args: rawArgs === '' ? undefined : redactText(rawArgs).slice(0, 300),
      }) + '\n', { mode: 0o600 });
    } catch {
      // Auditing must never break enforcement.
    }
  };

  // Hide denyTools from every newly created agent, using the agent-scoped
  // `this` of agent/created. The list is filtered against that agent's actual
  // schema, so a preset that already lacks a tool is not an error.
  if ((permission.denyTools ?? []).length > 0) {
    ctx.on('agent/created', function onAgentCreated() {
      try {
        const names = new Set((this.tools?.schemas?.() ?? []).map((schema) => schema.name));
        const present = (permission.denyTools ?? []).filter((name) => names.size === 0 || names.has(name));
        if (present.length > 0) this.tools.restrict({ deny: present });
      } catch (error) {
        ctx.logger?.warn?.(`dsh-guard: per-agent hide failed: ${String(error)}`);
      }
    });
  }

  // `/guard-test` dry-evaluates a hypothetical call so a rule can be checked
  // without running the tool; `/guard-undo` puts back a pre-write snapshot.
  // Neither touches the policy — rules live in policy.json.
  const commands = ctx.get?.('commands');
  if (commands?.register !== undefined) {
    (async () => {
      let testId = 'dsh-guard/test';
      let undoId = 'dsh-guard/undo';
      let policyId = 'dsh-guard/policy';
      let logId = 'dsh-guard/log';
      try {
        const brand = await import('@deepseek-ai/dsh-commands/brand');
        testId = brand.CommandDefinitionId('dsh-guard/test');
        undoId = brand.CommandDefinitionId('dsh-guard/undo');
        policyId = brand.CommandDefinitionId('dsh-guard/policy');
        logId = brand.CommandDefinitionId('dsh-guard/log');
      } catch {
        // Test/stub environments may not resolve the brand module; the strings still work there.
      }
      try {
        commands.register({
          definitionId: testId,
          name: 'guard-test',
          description: '试算一次工具调用的判定，不执行：/guard-test bash {"command":"rm -rf /"}',
          // A command without `input` only claims its bare token: the Client's
          // enter handler returns early for `/name args`, so the line reaches
          // the model as ordinary chat. This one takes arguments by design.
          input: { hint: '<tool> <json arguments>' },
          handler: async (invocation) => {
            const text = typeof invocation?.rawInput === 'string' ? invocation.rawInput.trim() : '';
            const space = text.search(/\s/u);
            const tool = space === -1 ? text : text.slice(0, space);
            const json = space === -1 ? '' : text.slice(space).trim();
            if (tool === '') return { kind: 'error', text: '用法：/guard-test <tool> <json arguments>' };
            let args = {};
            if (json !== '') {
              try {
                args = JSON.parse(json);
              } catch {
                return { kind: 'error', text: `参数不是合法 JSON：${json}` };
              }
            }
            let cwd = process.cwd();
            if (invocation?.agent !== undefined) {
              try {
                cwd = await ctx.workingDirectory.ensure(invocation.agent, invocation.signal);
              } catch {
                // Keep the process cwd when the session working directory is unavailable.
              }
            }
            const effective = projectPermission(permission, cwd);
            const decision = await decide({ name: tool, arguments: args, agent: invocation.agent }, cwd, effective);
            lastDecision = { at: Date.now(), tool, state: decision?.state ?? 'allow', pattern: decision?.pattern ?? null, dryRun: true };
            writeStatus();
            if (decision === undefined) return { kind: 'success', text: `${tool}: allow（未命中任何规则）` };
            return {
              kind: 'success',
              text: `${tool}: ${decision.state} by "${decision.pattern}"${decision.surface === undefined ? '' : ` [${decision.surface}]`}`,
            };
          },
        });
        commands.register({
          definitionId: undoId,
          name: 'guard-undo',
          description: '回滚 dsh-guard 拍下的最近一次写前快照',
          input: { hint: '（空=最近一次）| list | <id>' },
          handler: async (invocation) => {
            const text = typeof invocation?.rawInput === 'string' ? invocation.rawInput.trim() : '';
            const root = snapshotsDir();
            const entries = listSnapshots(root);
            if (text === 'list' || text === 'ls') {
              if (entries.length === 0) return { kind: 'success', text: 'dsh-guard: 没有可回滚的快照' };
              return { kind: 'success', text: entries.slice(0, 10).map(describeSnapshot).join('\n') };
            }
            const id = text === '' ? entries[0]?.id : text;
            if (id === undefined) return { kind: 'success', text: 'dsh-guard: 没有可回滚的快照' };
            if (!entries.some((entry) => entry.id === id)) return { kind: 'error', text: `dsh-guard: 找不到快照 ${id}` };
            try {
              const result = await restore(root, id);
              const parts = [];
              if (result.restored.length > 0) parts.push(`恢复 ${result.restored.length} 个文件`);
              if (result.removed.length > 0) parts.push(`删除 ${result.removed.length} 个当时不存在的文件`);
              if (result.skipped.length > 0) parts.push(`跳过 ${result.skipped.length} 个（超限/非普通文件）`);
              const suffix = parts.length === 0 ? '' : `（${parts.join('，')}）`;
              return { kind: 'success', text: `dsh-guard: 已回滚 ${id}${suffix}` };
            } catch (error) {
              return { kind: 'error', text: `dsh-guard: 回滚失败 ${String(error?.message ?? error)}` };
            }
          },
        });
        commands.register({
          definitionId: policyId,
          name: 'guard-policy',
          description: '查看或修改生效中的策略：/guard-policy list 或 /guard-policy {"bash":{"rm *":"ask"}}',
          input: { hint: 'list | {"<surface>":{"<pattern>":"<state>"}}' },
          handler: async (invocation) => {
            const text = typeof invocation?.rawInput === 'string' ? invocation.rawInput.trim() : '';
            const file = policyPath();
            if (text === '' || text === 'list') {
              const current = readLivePolicyBody(file);
              const json = JSON.stringify(current, null, 2);
              return { kind: 'success', text: json.length > 3000 ? `${json.slice(0, 3000)}\n…（已截断，完整内容见 ${file}）` : json };
            }
            let patch;
            try {
              if (text === 'preset' || text.startsWith('preset ')) {
                const name = text.slice(6).trim();
                if (name === '' || name === 'list') {
                  return { kind: 'success', text: ['可用模板：', ...listPresets()].join('\n') };
                }
                const preset = getPreset(name);
                if (preset === undefined) return { kind: 'error', text: `dsh-guard: 没有模板 ${name}` };
                patch = preset.permission;
              } else {
                patch = JSON.parse(text);
              }
            } catch {
              return { kind: 'error', text: '参数必须是 JSON 对象，例如 {"bash":{"rm *":"ask"}}' };
            }
            let merged;
            try {
              merged = applyPatch(readLivePolicyBody(file), patch);
            } catch (error) {
              return { kind: 'error', text: String(error?.message ?? error) };
            }
            if (!merged.changed) return { kind: 'success', text: 'dsh-guard: 策略没有变化' };
            const errors = validate(merged.next);
            if (errors.length > 0) return { kind: 'error', text: `dsh-guard: 拒绝写入，配置无效：${errors.join('; ')}` };
            try {
              // A rewrite normalizes the file and drops comments; keep the exact
              // previous text beside it so a hand-written policy is recoverable.
              if (existsSync(file)) copyFileSync(file, `${file}.bak`);
              writeFileSync(file, `${JSON.stringify({ $schema: './policy.schema.json', permission: merged.next }, null, 2)}\n`, { mode: 0o600 });
            } catch (error) {
              return { kind: 'error', text: `dsh-guard: 写入失败 ${String(error?.message ?? error)}` };
            }
            return { kind: 'success', text: `dsh-guard: 已写入 ${file}（备份 policy.json.bak，1 秒内热重载）\n${summarize(merged.next)}` };
          },
        });
        commands.register({
          definitionId: logId,
          name: 'guard-log',
          description: '查看最近的判定记录：/guard-log 或 /guard-log 50',
          input: { hint: '[条数，默认 20，最多 200]' },
          handler: async (invocation) => {
            if (!permission.audit) return { kind: 'error', text: 'dsh-guard: audit 已关闭，没有记录可看' };
            const text = typeof invocation?.rawInput === 'string' ? invocation.rawInput.trim() : '';
            const asked = text === '' ? 20 : Number(text);
            if (text !== '' && (!Number.isFinite(asked) || asked <= 0)) return { kind: 'error', text: '参数必须是正整数' };
            const rows = readTail(permission.auditPath, asked);
            if (rows.length === 0) return { kind: 'success', text: 'dsh-guard: 还没有判定记录' };
            return { kind: 'success', text: rows.map(describeDecision).join('\n') };
          },
        });
        commandRegistered = true;
        // CommandRuntime only notifies observers from its constructor, so a
        // command registered later never reaches an already-open page. Ask for
        // the change explicitly: the Client's `commands/change` listener then
        // repulls the directory instead of keeping a stale snapshot.
        commands.notifyChange?.();
        writeStatus();
      } catch (error) {
        ctx.logger?.warn?.(`dsh-guard: command registration failed: ${String(error)}`);
      }
    })();
  }

  // One grant is keyed by (session, rule pattern): a grant for `rm *` never
  // widens to another rule. TTL and use budget are opt-in; the defaults keep
  // the old "rest of the session" behaviour.
  const grantFor = (sid, pattern) => {
    const grants = approved.get(sid);
    const grant = grants?.get(pattern);
    if (grant === undefined) return false;
    if (grant.until > 0 && Date.now() > grant.until) {
      grants.delete(pattern);
      return false;
    }
    if (grant.maxUses > 0 && grant.uses >= grant.maxUses) return false;
    grant.uses += 1;
    return true;
  };

  const addGrant = (sid, pattern) => {
    const ttl = permission.sessionApprovalTtlMs ?? 0;
    const grants = approved.get(sid) ?? new Map();
    grants.set(pattern, {
      until: ttl > 0 ? Date.now() + ttl : 0,
      uses: 0,
      maxUses: permission.sessionApprovalMaxUses ?? 0,
    });
    approved.set(sid, grants);
  };

  // Snapshot every existing file a write-capable call is about to replace.
  // The copy lands before the tool runs, so a bad edit is always recoverable —
  // including one that succeeds and then turns out to be wrong.
  const maybeSnapshot = async (exec, effective, cwd) => {
    if (effective.snapshots === false) return undefined;
    if (!WRITE_TOOLS.has(exec.name)) return undefined;
    const targets = snapshotTargets(exec.arguments ?? {});
    if (targets.length === 0) return undefined;
    const absolute = targets.map((target) => expand(target, cwd)).filter((path) => typeof path === 'string');
    if (absolute.length === 0) return undefined;
    const meta = await capture(snapshotsDir(), {
      tool: exec.name,
      callId: exec.callId,
      paths: absolute,
      maxFiles: effective.snapshotMaxFiles,
      maxBytes: effective.snapshotMaxBytes,
      retain: effective.snapshotRetain,
    });
    return meta?.id;
  };

  // Loop detection: the same tool with byte-identical arguments more than
  // `repeatLimit` times inside `repeatWindowMs`. In-process and per-session-
  // agnostic on purpose — a loop is a loop whichever session runs it. The
  // fingerprint is the serialized arguments, truncated so a huge payload does
  // not become a memory sink.
  const repeats = new Map();
  const trackRepeat = (exec, effective) => {
    const limit = effective.repeatLimit ?? 0;
    if (limit <= 0) return undefined;
    const windowMs = effective.repeatWindowMs ?? 60000;
    let fingerprint = '';
    try {
      fingerprint = JSON.stringify(exec.arguments ?? {});
    } catch {
      fingerprint = '';
    }
    if (fingerprint.length > 400) fingerprint = fingerprint.slice(0, 400);
    const key = `${exec.name}\u0000${fingerprint}`;
    const now = Date.now();
    const entry = repeats.get(key);
    if (entry === undefined || now - entry.firstAt > windowMs) {
      repeats.set(key, { firstAt: now, count: 1 });
      if (repeats.size > 512) {
        for (const [candidate, seen] of repeats) {
          if (now - seen.firstAt > windowMs) repeats.delete(candidate);
        }
      }
      return undefined;
    }
    entry.count += 1;
    if (entry.count < limit) return undefined;
    return {
      state: effective.repeatAction ?? 'ask',
      pattern: `repeat ${exec.name} ×${entry.count}`,
      surface: 'repeat',
      key: exec.name,
    };
  };

  // Self-drawn approval dialog. `pre-execute` parks one Promise per request in
  // this map; the Client fetches the queue over HTTP and posts the decision,
  // which resolves it. Nothing else touches the map, and every exit is
  // idempotent so a double click cannot settle twice.
  const pendingApprovals = new Map();
  const awaitDialog = (exec, decision, payload, effective) => {
    const id = Math.random().toString(36).slice(2, 10);
    const timeoutMs = Number.isInteger(effective.dialogTimeoutMs) && effective.dialogTimeoutMs > 0
      ? effective.dialogTimeoutMs
      : 120000;
    return new Promise((resolve) => {
      const finish = (outcome) => {
        const entry = pendingApprovals.get(id);
        if (entry === undefined) return;
        pendingApprovals.delete(id);
        clearTimeout(entry.timer);
        resolve(outcome);
      };
      const timer = setTimeout(() => finish({ choice: 'deny', reason: '审批超时' }), timeoutMs);
      timer.unref?.();
      pendingApprovals.set(id, {
        id,
        at: Date.now(),
        tool: exec.name,
        pattern: decision.pattern,
        surface: decision.surface ?? null,
        path: payload?.path ?? null,
        before: payload?.before ?? null,
        after: payload?.after ?? null,
        canPersist: canPersistDecision(decision),
        finish,
        timer,
      });
      if (exec.signal?.addEventListener !== undefined) {
        exec.signal.addEventListener('abort', () => finish({ choice: 'deny', reason: '调用已取消' }), { once: true });
      }
    });
  };

  ctx.on('tools/pre-execute', async (exec, next) => {
    try {
      const listed = commands?.list?.(exec.agent);
      if (Array.isArray(listed)) commandNames = listed.map((command) => command.name);
    } catch {
      commandNames = ['<list failed>'];
    }
    let cwd = process.cwd();
    if (exec.agent !== undefined) {
      try {
        cwd = await ctx.workingDirectory.ensure(exec.agent, exec.signal);
      } catch {
        // Keep the process cwd when the session working directory is unavailable.
      }
    }
    const effective = projectPermission(permission, cwd);
    let decision = await decide(exec, cwd, effective);
    // Loop detection runs after the rule layers and before the snapshot: a
    // model stuck repeating one identical call deserves a question even when
    // each individual call would be allowed.
    const repeat = trackRepeat(exec, effective);
    if (repeat !== undefined) {
      decision = mostRestrictive(decision, repeat);
      if (decision?.state === 'allow') decision = undefined;
    }
    // A denied call never rewrites anything, so it needs no snapshot.
    const snapshotId = decision?.state === 'deny' ? undefined : await maybeSnapshot(exec, effective, cwd);
    if (decision === undefined) {
      lastDecision = { at: Date.now(), tool: exec.name, state: 'allow', pattern: null };
      audit(exec, undefined, snapshotId);
      writeStatus();
      return next();
    }

    // Dry run: record what the rules would have done and let the call through.
    if (effective.enforce === false) {
      lastDecision = { at: Date.now(), tool: exec.name, state: `dry-run:${decision.state}`, pattern: decision.pattern };
      audit(exec, { ...decision, dryRun: true }, snapshotId);
      writeStatus();
      return next();
    }

    const reason = `dsh-guard: ${decision.state} by "${decision.pattern}"`;
    if (decision.state === 'deny') {
      lastDecision = { at: Date.now(), tool: exec.name, state: 'deny', pattern: decision.pattern };
      audit(exec, decision, snapshotId);
      writeStatus();
      return { kind: 'deny', reason };
    }
    if (effective.yolo || sandboxYolo(ctx, exec, effective)) {
      lastDecision = { at: Date.now(), tool: exec.name, state: 'allow', pattern: `yolo ${decision.pattern}` };
      audit(exec, { ...decision, state: 'allow', pattern: `yolo ${decision.pattern}` }, snapshotId);
      writeStatus();
      return next();
    }
    lastDecision = { at: Date.now(), tool: exec.name, state: decision.state, pattern: decision.pattern };
    audit(exec, decision, snapshotId);
    writeStatus();

    const sid = sessionOf(exec);
    if (sid !== undefined && grantFor(sid, decision.pattern)) return next();

    // A Client polls the queue every ~1.5s. If nobody has polled for a while,
    // fall back to the DSH question channel instead of waiting out the timeout.
    const dialogLive = Date.now() - lastPollAt < 10000;
    if (effective.approvalMode === 'dialog' && dialogLive) {
      // Read the target once: the dialog shows it side by side, and the same
      // bytes go to the snapshot path below.
      let payload = null;
      try {
        const args = exec.arguments ?? {};
        const rawPath = typeof args.file_path === 'string' ? args.file_path : (typeof args.path === 'string' ? args.path : undefined);
        if (rawPath !== undefined) {
          const absolute = expand(rawPath, cwd);
          let before = '';
          if (absolute !== undefined) {
            try {
              const stat = statSync(absolute);
              if (stat.isFile() && stat.size <= MAX_READ_BYTES) before = readFileSync(absolute, 'utf8');
            } catch {
              before = '';
            }
          }
          const after = typeof args.content === 'string' ? args.content
            : typeof args.new_string === 'string' ? args.new_string : '';
          payload = { path: rawPath, before, after };
        }
      } catch {
        payload = null;
      }
      const outcome = await awaitDialog(exec, decision, payload, effective);
      if (outcome.choice === 'allow') return next();
      if (outcome.choice === 'session') {
        if (sid !== undefined) addGrant(sid, decision.pattern);
        return next();
      }
      if (outcome.choice === 'persist') {
        try {
          if (persistAllow(cwd, decision)) {
            if (sid !== undefined) addGrant(sid, decision.pattern);
            return next();
          }
        } catch (error) {
          ctx.logger?.warn?.('dsh-guard: project rule write failed: ' + String(error));
        }
      }
      return { kind: 'deny', reason: `dsh-guard: ${outcome.reason ?? '用户拒绝'}` };
    }

    if (effective.approvalMode === 'question' || (effective.approvalMode === 'dialog' && !dialogLive)) {
      const uq = ctx.get?.('userQuestions');
      questionStatus = uq === undefined ? 'no-service' : exec.agent === undefined ? 'no-agent' : 'asking';
      if (uq !== undefined && exec.agent !== undefined) {
        try {
          const options = [
            { label: '允许一次', description: '只放行这次调用' },
            { label: '本会话允许', description: '本次会话内命中同一规则时不再询问' },
          ];
          if (effective.approvePersist !== false && canPersistDecision(decision)) {
            options.push({ label: '写入项目规则', description: '把这条 allow 写进 .dsh/guard-policy.json' });
          }
          options.push({ label: '拒绝', description: '阻止这次调用' });
          // A three-button dialog cannot show what is about to change. The
          // preview turns the call into "current vs next" text so a write that
          // claims to fix a typo but deletes forty lines is visible before the
          // approval, not after.
          let previewText = '';
          try {
            previewText = previewFor(exec, (raw) => {
              const absolute = expand(raw, cwd);
              if (absolute === undefined) return undefined;
              const stat = statSync(absolute);
              if (!stat.isFile() || stat.size > MAX_READ_BYTES) return undefined;
              return readFileSync(absolute, 'utf8');
            });
          } catch {
            previewText = '';
          }
          // A link to a real side-by-side page: the card itself can only carry
          // Markdown, so the two-column view lives behind this URL.
          let diffLink = '';
          try {
            const args = exec.arguments ?? {};
            const rawPath = typeof args.file_path === 'string' ? args.file_path : (typeof args.path === 'string' ? args.path : undefined);
            const content = typeof args.content === 'string' ? args.content : undefined;
            if (exec.name === 'write' && rawPath !== undefined && content !== undefined) {
              const absolute = expand(rawPath, cwd);
              let before = '';
              if (absolute !== undefined) {
                try {
                  const stat = statSync(absolute);
                  if (stat.isFile() && stat.size <= MAX_READ_BYTES) before = readFileSync(absolute, 'utf8');
                } catch {
                  before = '';
                }
              }
              const diffId = rememberDiff(before, content, rawPath);
              // Markdown drops a relative href, so the link needs the absolute
              // origin the Web app advertises.
              let base = typeof effective.webBase === 'string' && effective.webBase !== ''
                ? effective.webBase.replace(/\/+$/u, '')
                : advertisedBase;
              try {
                const webApp = base === '' ? ctx.get?.('webApp') : undefined;
                if (typeof webApp?.getAdvertisedUrl === 'function') {
                  base = String(webApp.getAdvertisedUrl()).replace(/\/+$/u, '');
                }
              } catch {
                base = '';
              }
              if (base === '') {
                const fromEnv = process.env.DSH_WEB_URL;
                if (typeof fromEnv === 'string' && fromEnv !== '') base = fromEnv.replace(/\/+$/u, '');
              }
              if (base !== '') {
                // The approval renderer escapes raw HTML — an inline iframe shows
                // up as literal text — so a Markdown link is the only thing that
                // renders. The two-column view opens in its own tab.
                diffLink = `[打开双栏对比](${base}/api/dsh-guard/diff?id=${diffId})`;
              }
            }
          } catch {
            diffLink = '';
          }
          // The dialog renders `detail` as markdown, so a fenced block is what
          // keeps the diff's line breaks; plain newlines collapse into spaces.
          const body = previewText === ''
            ? `规则：\`${decision.pattern}\``
            : [`规则：\`${decision.pattern}\``, '', '```diff', previewText, '```'].join('\n');
          const detail = diffLink === '' ? body : `${body}\n\n${diffLink}`;
          const answer = await uq.ask({
            agent: exec.agent,
            signal: exec.signal,
            questions: [{
              id: 'guard',
              header: 'dsh-guard',
              question: `允许 ${exec.name} 执行吗？`,
              detail,
              options,
            }],
          });
          questionStatus = 'answered';
          const item = answer?.answers?.find((a) => a.id === 'guard');
          const choice = item?.selected?.[0];
          if (choice === '本会话允许') {
            if (sid !== undefined) addGrant(sid, decision.pattern);
            return next();
          }
          if (choice === '允许一次') return next();
          if (choice === '写入项目规则') {
            let written = false;
            try {
              written = persistAllow(cwd, decision);
            } catch (error) {
              ctx.logger?.warn?.('dsh-guard: project rule write failed: ' + String(error));
            }
            if (written) {
              if (sid !== undefined) addGrant(sid, decision.pattern);
              return next();
            }
            return { kind: 'deny', reason: `dsh-guard: 无法写入项目规则（${decision.surface ?? 'unknown'} 不支持持久化）` };
          }
          const custom = typeof item?.custom === 'string' ? item.custom.trim() : '';
          const suffix = custom === '' ? '' : `：${custom}`;
          return { kind: 'deny', reason: `dsh-guard: 用户拒绝 "${decision.pattern}"${suffix}` };
        } catch (error) {
          // No answerer, or the question was aborted: fall back to DSH approval.
          questionStatus = `failed: ${String(error?.message ?? error)}`;
          ctx.logger?.warn?.(`dsh-guard: user question failed: ${questionStatus}`);
        }
      }
    }

    if (effective.sessionApprovals && sid !== undefined) pending.set(exec.callId, { sid, pattern: decision.pattern });
    return { kind: 'ask', reason };
  });

  // `defineTool` lives in @deepseek-ai/dsh-tools, which a profile-root plugin
  // can only resolve at runtime. Earlier versions referenced it without
  // importing it, so this whole block threw a ReferenceError and the tool was
  // never registered.
  (async () => {
    try {
      const { defineTool } = await import('@deepseek-ai/dsh-tools');
      ctx.tools.register(defineTool({
        name: 'guard_status',
        description: 'Report the live dsh-guard version, effective configuration, session approvals, and the last decision. Read-only.',
        parameters: {},
        output: {
          schema: {
            version: { type: 'string', required: true },
            config: { type: 'json', required: true },
            approved: { type: 'json', required: true },
            lastDecision: { type: 'json' },
            recentDecisions: { type: 'json', required: true },
          },
          render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
        },
        execute() {
          return Promise.resolve({
            version: VERSION,
            config: {
              invalid: permission.invalid ?? null,
              approvalMode: permission.approvalMode,
              enforce: permission.enforce,
              snapshots: permission.snapshots,
              snapshotRetain: permission.snapshotRetain,
              wrappers: permission.wrappers,
              redact: permission.redact,
              sessionApprovals: permission.sessionApprovals,
              denyTools: permission.denyTools,
              bashRules: Object.keys(permission.bash ?? {}),
              toolRules: Object.keys(permission.tools ?? {}),
              paramRules: Object.keys(permission.params ?? {}),
              agentRules: Object.keys(permission.agents ?? {}),
              argvRules: (permission.argv ?? []).length,
              sandboxAware: permission.sandboxAware,
              patternMode: permission.patternMode,
              yolo: permission.yolo,
              dataDir: dirname(statusPath),
              auditPath: permission.auditPath,
              commandNames,
            },
            approved: [...approved.entries()].map(([sid, grants]) => [sid, [...grants.keys()]]),
            lastDecision: lastDecision ?? null,
            recentDecisions: recent,
          });
        },
      }));
    } catch (error) {
      ctx.logger?.warn?.(`dsh-guard: guard_status registration failed: ${String(error)}`);
    }
  })();

  ctx.on('tools/post-execute', async (exec, result, next) => {
    if (permission.sessionApprovals) {
      const entry = pending.get(exec.callId);
      if (entry !== undefined) {
        pending.delete(exec.callId);
        if (result?.isError !== true) {
          const ttl = permission.sessionApprovalTtlMs ?? 0;
          const grants = approved.get(entry.sid) ?? new Map();
          grants.set(entry.pattern, {
            until: ttl > 0 ? Date.now() + ttl : 0,
            uses: 0,
            maxUses: permission.sessionApprovalMaxUses ?? 0,
          });
          approved.set(entry.sid, grants);
        }
      }
    }

    if (!permission.redact) return next();
    const blocks = result?.content;
    if (!Array.isArray(blocks) || blocks.length === 0) return next();
    let changed = false;
    const content = blocks.map((block) => {
      if (block?.type !== 'text' || typeof block.text !== 'string') return block;
      const text = redactText(block.text);
      if (text === block.text) return block;
      changed = true;
      return { ...block, text };
    });
    if (!changed) return next();
    return { kind: 'accept', content };
  });
}
