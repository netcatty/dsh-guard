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
import { appendFileSync, readFileSync, statSync, watchFile, unwatchFile, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { realpath } from 'node:fs/promises';
import { decomposeShellCommand } from './shell.js';

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

const SEVERITY = { allow: 0, ask: 1, deny: 2 };
const STATES = new Set(['allow', 'ask', 'deny']);

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
  argv: [],
  opaque: 'ask',
  sandboxAware: true,
  yolo: false,
  audit: true,
  projectPolicy: true,
  projectPolicyStrict: false,
  caseInsensitivePaths: process.platform === 'win32',
  network: [],
  wrappers: 'allow',
  redact: true,
  sessionApprovals: false,
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

function globToRegExp(pattern, caseInsensitive = false) {
  let out = '^';
  for (const ch of pattern) {
    if (ch === '*') out += '.*';
    else if (ch === '?') out += '.';
    else out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(out + '$', caseInsensitive ? 'iu' : 'u');
}

export function matches(pattern, value, caseInsensitive = process.platform === 'win32') {
  return globToRegExp(toPosix(pattern), caseInsensitive).test(toPosix(value));
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

function evalRules(rules, values, caseInsensitive = process.platform === 'win32') {
  let hit;
  for (const [pattern, state] of Object.entries(rules ?? {})) {
    if (!STATES.has(state)) continue;
    if (values.some((v) => matches(pattern, v, caseInsensitive))) hit = { state, pattern };
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

function tokenMatches(pattern, token, caseInsensitive) {
  if (typeof pattern !== 'string') return false;
  if (pattern.startsWith('!')) return !matches(pattern.slice(1), token, caseInsensitive);
  return matches(pattern, token, caseInsensitive);
}

function argvMatches(match, decomposition, caseInsensitive) {
  if (typeof match !== 'object' || match === null) return false;
  const commands = decomposition.commands;
  const tokens = commands.flatMap((cmd) => [...cmd.args, ...cmd.redirects]);
  let fields = 0;

  const patterns = (key) => asList(match[key]).filter((p) => typeof p === 'string');

  if (match.command !== undefined) {
    fields += 1;
    const pats = patterns('command');
    if (!commands.some((cmd) => pats.some((p) => matches(p, cmd.command, caseInsensitive)))) return false;
  }
  if (match.args !== undefined) {
    fields += 1;
    if (!patterns('args').every((p) => tokens.some((t) => tokenMatches(p, t, caseInsensitive)))) return false;
  }
  if (match.anyArg !== undefined) {
    fields += 1;
    const pats = patterns('anyArg');
    if (!tokens.some((t) => pats.some((p) => tokenMatches(p, t, caseInsensitive)))) return false;
  }
  if (match.pipeline !== undefined) {
    fields += 1;
    const pipelines = commands.map((cmd) => cmd.command).filter((c) => c !== '').join('|');
    if (!patterns('pipeline').some((p) => matches(p, pipelines, caseInsensitive))) return false;
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

export function redactText(text) {
  if (typeof text !== 'string' || text === '') return text;
  let out = text;
  for (const [pattern, replacement] of REDACTIONS) out = out.replace(pattern, replacement);
  return out;
}

async function pathDecision(permission, pathArg, cwd, direction, toolName) {
  const values = await candidates(pathArg, cwd);
  if (values.length === 0) return undefined;
  let result = evalRules(permission.path, values, permission.caseInsensitivePaths);
  if (direction === 'read' || direction === 'both') result = mostRestrictive(result, evalRules(permission.pathRead, values, permission.caseInsensitivePaths));
  if (direction === 'write' || direction === 'both') result = mostRestrictive(result, evalRules(permission.pathWrite, values, permission.caseInsensitivePaths));
  result = mostRestrictive(result, evalRules(permission.tools?.[toolName], values, permission.caseInsensitivePaths));
  const abs = expand(pathArg, cwd);
  if (abs !== undefined && outside(cwd, abs)) {
    result = mostRestrictive(result, evalRules(permission.externalDirectory, values, permission.caseInsensitivePaths));
  }
  return result;
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
    argv: source.argv ?? basePermission.argv,
    network: source.network ?? basePermission.network,
    wrappers: pick(source.wrappers, basePermission.wrappers),
    opaque: pick(source.opaque, basePermission.opaque),
    redact: pick(source.redact, basePermission.redact),
    sessionApprovals: pick(source.sessionApprovals, basePermission.sessionApprovals),
    approvalMode: pick(source.approvalMode, basePermission.approvalMode),
    yolo: pick(source.yolo, basePermission.yolo),
    sandboxAware: pick(source.sandboxAware, basePermission.sandboxAware),
    audit: pick(source.audit, basePermission.audit),
    auditPath: pick(source.auditPath, basePermission.auditPath),
    projectPolicy: basePermission.projectPolicy,
    denyTools: pick(source.denyTools, basePermission.denyTools),
  };
}

function projectPermission(basePermission, cwd) {
  if (basePermission.projectPolicy === false) return basePermission;
  const file = resolve(cwd, PROJECT_POLICY);
  try {
    const stat = statSync(file);
    const cached = projectCache.get(file);
    if (cached !== undefined && cached.mtimeMs === stat.mtimeMs) return cached.permission;
    const raw = JSON.parse(readFileSync(file, 'utf8'));
    const source = raw.permission ?? raw;
    const errors = validate(source);
    if (errors.length > 0) {
      if (basePermission.projectPolicyStrict) return { invalid: errors.map((e) => `project: ${e}`) };
      return basePermission;
    }
    const merged = overlay(basePermission, source);
    projectCache.set(file, { mtimeMs: stat.mtimeMs, permission: merged });
    return merged;
  } catch {
    return basePermission;
  }
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
        if (domains.some((pattern) => matches(pattern, host))) hit = { state: rule.action, pattern: `network ${host}` };
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
    return { state: 'deny', pattern: `denyTools: ${exec.name}` };
  }
  const args = (exec && typeof exec.arguments === 'object' && exec.arguments) || {};
  const layers = [];
  const direction = READ_TOOLS.has(exec.name) ? 'read' : WRITE_TOOLS.has(exec.name) ? 'write' : 'both';

  if (PATH_ARG_TOOLS.has(exec.name) || exec.name.startsWith('mcp__') || exec.name === 'mcp') {
    const nested = (args.arguments && typeof args.arguments === 'object') ? args.arguments : {};
    const pathArg = args.file_path ?? args.path ?? nested.file_path ?? nested.path;
    if (typeof pathArg === 'string') {
      layers.push(await pathDecision(permission, pathArg, cwd, direction, exec.name));
    }
  }

  if (SHELL_TOOLS.has(exec.name) && typeof args.command === 'string') {
    layers.push(evalRules(permission.bash, [args.command], permission.caseInsensitivePaths));
    if (WRAPPER.test(args.command) && permission.wrappers !== 'allow') {
      layers.push({ state: permission.wrappers, pattern: 'wrapper (bash -c/sudo/eval/xargs/find -exec)' });
    }
    if (OPAQUE.test(args.command) && permission.opaque !== 'allow') {
      layers.push({ state: permission.opaque, pattern: 'opaque construct ($(...), backtick, heredoc, <())' });
    }
    const decomposition = decomposeShellCommand(args.command);
    for (const rule of permission.argv ?? []) {
      if (argvMatches(rule.match, decomposition, permission.caseInsensitivePaths)) {
        layers.push({ state: rule.action, pattern: `argv ${JSON.stringify(rule.match)}` });
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
        layers.push({ state: 'deny', pattern: `basename ${raw}` });
        continue;
      }
      layers.push(await pathDecision(permission, raw, cwd, 'both', exec.name));
    }
  }

  layers.push(networkLayer(permission, exec));
  let result;
  for (const layer of layers) result = mostRestrictive(result, layer);
  result = mostRestrictive(result, { state: permission['*'], pattern: '*' });
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

  if (source['*'] !== undefined && !STATES.has(source['*'])) errors.push('"*" must be allow, ask, or deny');
  for (const name of ['path', 'pathRead', 'pathWrite', 'externalDirectory', 'bash']) checkMap(name, source[name]);
  checkMap('tools', source.tools, true);
  if (source.wrappers !== undefined && !STATES.has(source.wrappers)) errors.push('wrappers must be allow, ask, or deny');
  if (source.redact !== undefined && typeof source.redact !== 'boolean') errors.push('redact must be a boolean');
  if (source.sessionApprovals !== undefined && typeof source.sessionApprovals !== 'boolean') errors.push('sessionApprovals must be a boolean');
  if (source.approvalMode !== undefined && source.approvalMode !== 'approval' && source.approvalMode !== 'question') errors.push('approvalMode must be "approval" or "question"');
  if (source.denyTools !== undefined && !Array.isArray(source.denyTools)) errors.push('denyTools must be an array of tool names');
  if (source.opaque !== undefined && !STATES.has(source.opaque)) errors.push('opaque must be allow, ask, or deny');
  if (source.sandboxAware !== undefined && typeof source.sandboxAware !== 'boolean') errors.push('sandboxAware must be a boolean');
  if (source.yolo !== undefined && typeof source.yolo !== 'boolean') errors.push('yolo must be a boolean');
  if (source.audit !== undefined && typeof source.audit !== 'boolean') errors.push('audit must be a boolean');
  if (source.auditPath !== undefined && typeof source.auditPath !== 'string') errors.push('auditPath must be a string');
  if (source.projectPolicy !== undefined && typeof source.projectPolicy !== 'boolean') errors.push('projectPolicy must be a boolean');
  if (source.projectPolicyStrict !== undefined && typeof source.projectPolicyStrict !== 'boolean') errors.push('projectPolicyStrict must be a boolean');
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

const POLICY_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'policy.json');

function loadPolicy() {
  try {
    const raw = JSON.parse(readFileSync(POLICY_PATH, 'utf8'));
    return raw.permission ?? raw;
  } catch {
    return {};
  }
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
    argv: [...deriveArgvRules(pick(source.bash, policy.bash, DEFAULT_PERMISSION.bash)), ...pick(source.argv, policy.argv, DEFAULT_PERMISSION.argv)],
    wrappers: STATES.has(pick(source.wrappers, policy.wrappers)) ? pick(source.wrappers, policy.wrappers) : 'allow',
    opaque: STATES.has(pick(source.opaque, policy.opaque)) ? pick(source.opaque, policy.opaque) : 'ask',
    sandboxAware: pick(source.sandboxAware, policy.sandboxAware) !== false,
    yolo: pick(source.yolo, policy.yolo) === true,
    audit: pick(source.audit, policy.audit) !== false,
    auditPath: pick(source.auditPath, policy.auditPath) ?? `${homedir()}/.dsh/guard-audit.jsonl`,
    projectPolicy: pick(source.projectPolicy, policy.projectPolicy) !== false,
    projectPolicyStrict: pick(source.projectPolicyStrict, policy.projectPolicyStrict) === true,
    caseInsensitivePaths: pick(source.caseInsensitivePaths, policy.caseInsensitivePaths) ?? (process.platform === 'win32'),
    network: pick(source.network, policy.network, DEFAULT_PERMISSION.network),
    redact: pick(source.redact, policy.redact) !== false,
    sessionApprovals: pick(source.sessionApprovals, policy.sessionApprovals) === true,
    approvalMode: pick(source.approvalMode, policy.approvalMode) === 'question' ? 'question' : 'approval',
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
  let permission = mergePermission(config);
  let lastDecision;
  if (permission.invalid) {
    ctx.logger?.warn?.(`dsh-guard: invalid config, denying every call: ${permission.invalid.join('; ')}`);
  }

  const pending = new Map();
  const approved = new Map();
  const statusPath = `${homedir()}/.dsh/guard-status.json`;
  const writeStatus = () => {
    try {
      writeFileSync(statusPath, JSON.stringify({
        version: VERSION,
        pid: process.pid,
        at: new Date().toISOString(),
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
          argvRules: (permission.argv ?? []).length,
          sandboxAware: permission.sandboxAware,
          projectPolicy: permission.projectPolicy,
          projectPolicyStrict: permission.projectPolicyStrict,
          caseInsensitivePaths: permission.caseInsensitivePaths,
          commandRegistered,
          networkRules: (permission.network ?? []).length,
          audit: permission.audit,
          yolo: permission.yolo,
        },
        approved: [...approved.entries()].map(([sid, set]) => [sid, [...set]]),
        lastDecision: lastDecision ?? null,
      }));
    } catch {
      // Diagnostics must never break enforcement.
    }
  };
  writeStatus();

  // policy.json hot reload: a valid new file replaces the live permission object.
  let watchedSignature = '';
  const reloadPolicy = () => {
    try {
      const raw = readFileSync(POLICY_PATH, 'utf8');
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
    watchedSignature = readFileSync(POLICY_PATH, 'utf8');
  } catch {
    // Missing policy file: defaults + profile config remain in force.
  }
  let commandRegistered = false;

  const policyWatcher = watchFile(POLICY_PATH, { interval: 1000 }, reloadPolicy);
  policyWatcher.unref?.();
  ctx.on('dispose', () => unwatchFile(POLICY_PATH, reloadPolicy));

  const audit = (exec, decision) => {
    if (!permission.audit) return;
    try {
      appendFileSync(permission.auditPath, JSON.stringify({
        at: new Date().toISOString(),
        session: sessionOf(exec),
        tool: exec.name,
        state: decision?.state ?? 'allow',
        pattern: decision?.pattern ?? null,
        args: typeof exec.arguments === 'object' ? JSON.stringify(exec.arguments).slice(0, 300) : undefined,
      }) + '\n');
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

  // `/guard-clear` — drop every session approval recorded by this plugin.
  const commands = ctx.get?.('commands');
  if (commands?.register !== undefined) {
    (async () => {
      let definitionId = 'dsh-guard/clear';
      try {
        const brand = await import('@deepseek-ai/dsh-commands/brand');
        definitionId = brand.CommandDefinitionId('dsh-guard/clear');
      } catch {
        // Test/stub environments may not resolve the brand module; the string still works there.
      }
      try {
        commands.register({
          definitionId,
          name: 'guard-clear',
          description: '清空 dsh-guard 记录的会话批准',
          handler: () => {
            const cleared = approved.size;
            approved.clear();
            pending.clear();
            writeStatus();
            return { kind: 'success', text: `dsh-guard: cleared ${cleared} session approval set(s)` };
          },
        });
        commandRegistered = true;
        writeStatus();
      } catch (error) {
        ctx.logger?.warn?.(`dsh-guard: guard-clear registration failed: ${String(error)}`);
      }
    })();
  }

  ctx.on('tools/pre-execute', async (exec, next) => {
    let cwd = process.cwd();
    if (exec.agent !== undefined) {
      try {
        cwd = await ctx.workingDirectory.ensure(exec.agent, exec.signal);
      } catch {
        // Keep the process cwd when the session working directory is unavailable.
      }
    }
    const effective = projectPermission(permission, cwd);
    const decision = await decide(exec, cwd, effective);
    if (decision === undefined) {
      lastDecision = { at: Date.now(), tool: exec.name, state: 'allow', pattern: null };
      writeStatus();
      audit(exec, undefined);
      return next();
    }
    const reason = `dsh-guard: ${decision.state} by "${decision.pattern}"`;
    if (decision.state === 'deny') {
      lastDecision = { at: Date.now(), tool: exec.name, state: 'deny', pattern: decision.pattern };
      writeStatus();
      audit(exec, decision);
      return { kind: 'deny', reason };
    }
    if (effective.yolo || sandboxYolo(ctx, exec, effective)) {
      lastDecision = { at: Date.now(), tool: exec.name, state: 'allow', pattern: `yolo ${decision.pattern}` };
      writeStatus();
      audit(exec, { state: 'allow', pattern: `yolo ${decision.pattern}` });
      return next();
    }
    lastDecision = { at: Date.now(), tool: exec.name, state: decision.state, pattern: decision.pattern };
    writeStatus();
    audit(exec, decision);

    const sid = sessionOf(exec);
    if (sid !== undefined && approved.get(sid)?.has(decision.pattern)) return next();

    if (effective.approvalMode === 'question') {
      const uq = ctx.get?.('userQuestions');
      if (uq !== undefined && exec.agent !== undefined) {
        try {
          const answer = await uq.ask({
            agent: exec.agent,
            signal: exec.signal,
            questions: [{
              id: 'guard',
              header: 'dsh-guard',
              question: `允许 ${exec.name} 执行吗？`,
              detail: `规则：${decision.pattern}`,
              options: [
                { label: '允许一次', description: '只放行这次调用' },
                { label: '本会话允许', description: '本次会话内命中同一规则时不再询问' },
                { label: '拒绝', description: '阻止这次调用' },
              ],
            }],
          });
          const choice = answer?.answers?.find((a) => a.id === 'guard')?.selected?.[0];
          if (choice === '本会话允许') {
            if (sid !== undefined) {
              const set = approved.get(sid) ?? new Set();
              set.add(decision.pattern);
              approved.set(sid, set);
            }
            return next();
          }
          if (choice === '允许一次') return next();
          return { kind: 'deny', reason: `dsh-guard: 用户拒绝 "${decision.pattern}"` };
        } catch {
          // No answerer, or the question was aborted: fall back to DSH approval.
        }
      }
    }

    if (effective.sessionApprovals && sid !== undefined) pending.set(exec.callId, { sid, pattern: decision.pattern });
    return { kind: 'ask', reason };
  });

  try {
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
        },
        render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
      },
      execute() {
        return Promise.resolve({
          version: VERSION,
          config: {
            invalid: permission.invalid ?? null,
            approvalMode: permission.approvalMode,
            wrappers: permission.wrappers,
            redact: permission.redact,
            sessionApprovals: permission.sessionApprovals,
            denyTools: permission.denyTools,
            bashRules: Object.keys(permission.bash ?? {}),
            toolRules: Object.keys(permission.tools ?? {}),
          argvRules: (permission.argv ?? []).length,
          sandboxAware: permission.sandboxAware,
          yolo: permission.yolo,
          },
          approved: [...approved.entries()].map(([sid, set]) => [sid, [...set]]),
          lastDecision: lastDecision ?? null,
        });
      },
    }));
  } catch (error) {
    ctx.logger?.warn?.(`dsh-guard: guard_status registration failed: ${String(error)}`);
  }

  ctx.on('tools/post-execute', async (exec, result, next) => {
    if (permission.sessionApprovals) {
      const entry = pending.get(exec.callId);
      if (entry !== undefined) {
        pending.delete(exec.callId);
        if (result?.isError !== true) {
          const set = approved.get(entry.sid) ?? new Set();
          set.add(entry.pattern);
          approved.set(entry.sid, set);
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
