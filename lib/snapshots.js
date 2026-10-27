// Pre-write file snapshots and restore.
//
// A `write`/`edit` call is irreversible once it lands: the previous bytes are
// gone. Before letting one through, dsh-guard copies every regular file the
// call names into
//
//   $DSH_HOME/dsh-plugins/dsh-guard/snapshots/<id>/meta.json
//   $DSH_HOME/dsh-plugins/dsh-guard/snapshots/<id>/0000.bin
//
// `meta.json` records, per file, whether it was `saved`, did not exist yet
// (`absent`), or was refused as too large / not a regular file (`skipped`).
// Restore rewrites the saved bytes, deletes the ones that were absent, and
// reports the skipped ones instead of pretending they came back.
//
// The store is bounded by two knobs: `snapshotMaxFiles` per call and
// `snapshotRetain` directories overall (oldest pruned first).

import { readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

export const DEFAULT_MAX_FILES = 20;
export const DEFAULT_MAX_BYTES = 256 * 1024;
export const DEFAULT_RETAIN = 100;

function mintId(tool, callId) {
  const stamp = new Date().toISOString().replace(/[:.]/gu, '-');
  const suffix = typeof callId === 'string' && callId !== '' ? callId.replace(/[^A-Za-z0-9_-]/gu, '').slice(0, 12) : '';
  const random = Math.random().toString(16).slice(2, 8);
  const label = typeof tool === 'string' ? tool.replace(/[^A-Za-z0-9_-]/gu, '').slice(0, 16) : 'tool';
  return `${stamp}-${label}${suffix === '' ? '' : `-${suffix}`}-${random}`;
}

/**
 * Capture the current bytes of every path.
 *
 * @param {string} root snapshots directory
 * @param {{tool?: string, callId?: string, paths: string[], maxFiles?: number, maxBytes?: number, retain?: number}} request
 * @returns {Promise<{id: string, at: string, tool: string|null, callId: string|null, files: Array<{path: string, status: string, size?: number, file?: string}>, dropped: number} | undefined>}
 */
export async function capture(root, request) {
  const paths = (request.paths ?? []).filter((value) => typeof value === 'string' && value !== '');
  if (paths.length === 0) return undefined;

  const maxFiles = request.maxFiles ?? DEFAULT_MAX_FILES;
  const maxBytes = request.maxBytes ?? DEFAULT_MAX_BYTES;
  const id = mintId(request.tool, request.callId);
  const dir = join(root, id);
  const files = [];
  let dropped = 0;

  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    for (const path of paths) {
      if (files.length >= maxFiles) {
        dropped += 1;
        continue;
      }
      let stat;
      try {
        stat = statSync(path);
      } catch {
        files.push({ path, status: 'absent' });
        continue;
      }
      if (!stat.isFile()) {
        files.push({ path, status: 'skipped' });
        continue;
      }
      if (stat.size > maxBytes) {
        files.push({ path, status: 'skipped', size: stat.size });
        continue;
      }
      const name = `${String(files.length).padStart(4, '0')}.bin`;
      try {
        const bytes = await readFile(path);
        await writeFile(join(dir, name), bytes, { mode: 0o600 });
        files.push({ path, status: 'saved', size: bytes.length, file: name });
      } catch {
        files.push({ path, status: 'skipped' });
      }
    }

    const meta = {
      id,
      at: new Date().toISOString(),
      tool: request.tool ?? null,
      callId: request.callId ?? null,
      files,
      dropped,
    };
    await writeFile(join(dir, 'meta.json'), JSON.stringify(meta, null, 2), { mode: 0o600 });
    prune(root, request.retain ?? DEFAULT_RETAIN);
    return meta;
  } catch {
    // A snapshot that cannot be completed is not worth failing the call over;
    // drop the half-written directory so it never looks restorable.
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best effort.
    }
    return undefined;
  }
}

/**
 * Newest-first snapshot index.
 * @param {string} root
 * @returns {Array<{id: string, at: string, tool: string|null, paths: string[], saved: number, absent: number, skipped: number}>}
 */
export function listSnapshots(root) {
  let names;
  try {
    names = readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  } catch {
    return [];
  }
  const out = [];
  for (const id of names) {
    try {
      const meta = JSON.parse(readFileSync(join(root, id, 'meta.json'), 'utf8'));
      const files = Array.isArray(meta.files) ? meta.files : [];
      out.push({
        id,
        at: typeof meta.at === 'string' ? meta.at : '',
        tool: typeof meta.tool === 'string' ? meta.tool : null,
        paths: files.map((file) => file.path),
        saved: files.filter((file) => file.status === 'saved').length,
        absent: files.filter((file) => file.status === 'absent').length,
        skipped: files.filter((file) => file.status === 'skipped').length,
      });
    } catch {
      // Unreadable entry: it is neither listed nor restorable.
    }
  }
  return out.sort((left, right) => (left.at < right.at ? 1 : -1));
}

/** Keep only the newest `retain` snapshot directories. */
export function prune(root, retain) {
  try {
    const entries = listSnapshots(root);
    for (const entry of entries.slice(retain)) {
      rmSync(join(root, entry.id), { recursive: true, force: true });
    }
  } catch {
    // Pruning is housekeeping; never let it break a capture.
  }
}

/**
 * Put one snapshot back.
 *
 * @param {string} root
 * @param {string} id
 * @returns {Promise<{restored: string[], removed: string[], skipped: string[]}>}
 */
export async function restore(root, id) {
  const dir = join(root, id);
  const meta = JSON.parse(await readFile(join(dir, 'meta.json'), 'utf8'));
  const result = { restored: [], removed: [], skipped: [] };
  for (const file of meta.files ?? []) {
    if (file.status === 'saved' && typeof file.file === 'string') {
      const bytes = await readFile(join(dir, file.file));
      await mkdir(dirname(file.path), { recursive: true });
      await writeFile(file.path, bytes);
      try {
        await chmod(file.path, 0o644);
      } catch {
        // Mode restoration is cosmetic.
      }
      result.restored.push(file.path);
    } else if (file.status === 'absent') {
      await rm(file.path, { force: true });
      result.removed.push(file.path);
    } else {
      result.skipped.push(file.path);
    }
  }
  return result;
}

/** Absolute paths a write-capable call names. */
export function snapshotTargets(args) {
  if (typeof args !== 'object' || args === null) return [];
  const raw = args.file_path ?? args.path;
  if (typeof raw !== 'string' || raw === '') return [];
  return [raw];
}

/** One line for `/guard-undo list`. */
export function describeSnapshot(entry) {
  const when = entry.at === '' ? entry.id : entry.at;
  const names = entry.paths.map((path) => basename(path)).join(', ');
  const extra = entry.skipped > 0 ? `  (${entry.skipped} skipped)` : '';
  return `${entry.id}  ${when}  ${entry.tool ?? 'tool'}  ${names}${extra}`;
}
