// One directory for every file this plugin owns:
//   $DSH_HOME/dsh-plugins/dsh-guard/policy.json   the live permission policy
//   $DSH_HOME/dsh-plugins/dsh-guard/audit.jsonl   decision audit trail
//   $DSH_HOME/dsh-plugins/dsh-guard/status.json   live status projection
//
// `$DSH_HOME/storages/` belongs to the storage backend and the home root belongs
// to the platform, so every plugin of this author keeps its data under
// `$DSH_HOME/dsh-plugins/<plugin>/`. `migrateLegacy` moves the files earlier
// versions wrote into the home root.
//
// The repository ships a `policy.json` too, but only as the seed and fallback:
// user edits belong in the data directory so they neither dirty the checkout
// nor lose to a `git pull`.

import { appendFileSync, chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const PLUGINS_DIR = 'dsh-plugins';
export const APP_DIR = 'dsh-guard';
export const AUDIT_FILE = 'audit.jsonl';
export const STATUS_FILE = 'status.json';
export const POLICY_FILE = 'policy.json';

export function dshHome() {
  const fromEnv = process.env.DSH_HOME;
  return typeof fromEnv === 'string' && fromEnv !== '' ? fromEnv : join(homedir(), '.dsh');
}

export function configDir() {
  return join(dshHome(), PLUGINS_DIR, APP_DIR);
}

export function auditPath() {
  return join(configDir(), AUDIT_FILE);
}

export function statusPath() {
  return join(configDir(), STATUS_FILE);
}

/** The live policy: user-owned, inside the data directory. */
export function policyPath() {
  return join(configDir(), POLICY_FILE);
}

/** Pre-write file snapshots, one directory per captured call. */
export function snapshotsDir() {
  return join(configDir(), 'snapshots');
}

/** Where every file this plugin writes lives. Created on demand, owner-only. */
export function ensureConfigDir() {
  const dir = configDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/**
 * Copy the shipped policy and its schema into the data directory once, when the
 * user has not written a policy yet. The schema travels with it so the
 * `"$schema": "./policy.schema.json"` line an editor reads resolves next to the
 * file. Returns true when a seed was written.
 */
export function seedPolicy(builtinPath, log, schemaPath) {
  const target = policyPath();
  if (existsSync(target)) return false;
  try {
    const raw = readFileSync(builtinPath, 'utf8');
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, raw, { mode: 0o600 });
    if (typeof schemaPath === 'string' && schemaPath !== '') {
      const schemaTarget = join(configDir(), 'policy.schema.json');
      if (!existsSync(schemaTarget)) {
        try {
          writeFileSync(schemaTarget, readFileSync(schemaPath, 'utf8'), { mode: 0o600 });
        } catch {
          // A missing schema only costs editor completion.
        }
      }
    }
    log?.(`dsh-guard: seeded ${target}`);
    return true;
  } catch (error) {
    log?.(`dsh-guard: policy seed failed: ${String(error)}`);
    return false;
  }
}

/** Earlier locations, newest first. */
export function legacyPaths() {
  const home = dshHome();
  return {
    audit: [join(home, 'guard-audit.jsonl')],
    status: [join(home, 'guard-status.json')],
  };
}

function moveFirst(sources, to) {
  const from = sources.find((candidate) => existsSync(candidate));
  if (from === undefined) return null;
  mkdirSync(dirname(to), { recursive: true, mode: 0o700 });
  if (existsSync(to)) {
    // The new file already exists: the old audit trail was written before the
    // migration and its tail would otherwise be lost. Append, then drop it.
    try {
      appendFileSync(to, readFileSync(from));
      rmSync(from);
      return from;
    } catch {
      return null;
    }
  }
  copyFileSync(from, to);
  try {
    // Preserve the owner bits but never wider than 0600: the audit trail can
    // quote command lines and file paths.
    chmodSync(to, (statSync(from).mode & 0o700) | 0o600);
  } catch {
    // Mode tightening is best-effort; the write path sets 0600 anyway.
  }
  try {
    rmSync(from);
  } catch {
    // Leaving the old file behind is harmless: the new one wins.
  }
  return from;
}

/** Move earlier files into the app directory. Returns the sources that moved. */
export function migrateLegacy(log) {
  const legacy = legacyPaths();
  const moved = [];
  const audit = moveFirst(legacy.audit, auditPath());
  if (audit !== null) moved.push(audit);
  const status = moveFirst(legacy.status, statusPath());
  if (status !== null) moved.push(status);
  if (moved.length > 0) log?.(`dsh-guard: moved ${moved.length} file(s) to ${configDir()}`);
  return moved;
}
