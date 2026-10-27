// Reading the tail of the audit trail.
//
// `audit.jsonl` grows to multiple megabytes and is append-only, so the useful
// view is "the last N decisions", not the whole file. This reads a bounded
// window from the end instead of parsing the file: at 5 MiB the full read would
// allocate 5 MiB on every command.

import { closeSync, openSync, readSync, statSync } from 'node:fs';

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 200;
const WINDOW_BYTES = 256 * 1024;

/**
 * @param {string} file
 * @param {number} limit how many trailing lines to return
 * @returns {Array<object>} parsed rows, newest last
 */
export function readTail(file, limit = DEFAULT_LIMIT) {
  const wanted = Math.max(1, Math.min(Number.isFinite(limit) ? Math.trunc(limit) : DEFAULT_LIMIT, MAX_LIMIT));
  let stat;
  try {
    stat = statSync(file);
  } catch {
    return [];
  }
  if (!stat.isFile() || stat.size === 0) return [];

  const size = Math.min(stat.size, WINDOW_BYTES);
  const start = stat.size - size;
  const buffer = Buffer.alloc(size);
  let fd;
  try {
    fd = openSync(file, 'r');
    readSync(fd, buffer, 0, size, start);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }

  const lines = buffer.toString('utf8').split('\n').filter((line) => line.trim() !== '');
  // A window that starts mid-file begins mid-line; drop that fragment rather
  // than handing a truncated JSON object to the parser.
  if (start > 0 && lines.length > 0) lines.shift();

  const rows = [];
  for (const line of lines.slice(-wanted)) {
    try {
      rows.push(JSON.parse(line));
    } catch {
      // A half-written trailing line (the append is not atomic) is skipped.
    }
  }
  return rows;
}

/** One line for the command reply. */
export function describeDecision(row) {
  const at = typeof row.at === 'string' ? row.at.slice(11, 19) : '--:--:--';
  const state = String(row.state ?? 'allow').padEnd(5);
  const tool = String(row.tool ?? '?');
  const pattern = row.pattern === null || row.pattern === undefined ? '' : `  ${row.pattern}`;
  const agent = typeof row.agent === 'string' && row.agent !== 'main' ? `  [${row.agent}]` : '';
  return `${at}  ${state}  ${tool}${pattern}${agent}`;
}
