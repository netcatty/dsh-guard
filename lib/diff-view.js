// A side-by-side diff page for one approval.
//
// The approval card itself cannot render a custom component: `detail` is
// Markdown, and the question item has no attachment slot. So the card carries a
// link to this page, which is ordinary HTML/CSS and can therefore show a real
// two-column comparison instead of a text approximation.
//
// Entries are ephemeral: a bounded in-memory map, expired on read. Nothing is
// written to disk, and the page never exposes a path that was not already
// shown in the approval card.

const MAX_ENTRIES = 24;
const TTL_MS = 10 * 60 * 1000;

/** @type {Map<string, {path: string, before: string, after: string, at: number, rows: Array<{left: string|null, right: string|null, kind: string}>}>} */
const entries = new Map();

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Line-level pairing: common prefix and suffix are aligned unchanged, and the
 * middle is paired positionally. It is not a full LCS, but for a file edit it
 * puts the old and new version of each changed line next to each other.
 */
export function pairLines(before, after) {
  const a = before.split('\n');
  const b = after.split('\n');
  let head = 0;
  while (head < a.length && head < b.length && a[head] === b[head]) head += 1;
  let tailA = a.length - 1;
  let tailB = b.length - 1;
  while (tailA >= head && tailB >= head && a[tailA] === b[tailB]) {
    tailA -= 1;
    tailB -= 1;
  }

  const rows = [];
  for (let index = 0; index < head; index += 1) rows.push({ left: a[index], right: b[index], kind: 'same' });
  const middleA = a.slice(head, tailA + 1);
  const middleB = b.slice(head, tailB + 1);
  const middle = Math.max(middleA.length, middleB.length);
  for (let index = 0; index < middle; index += 1) {
    const left = index < middleA.length ? middleA[index] : null;
    const right = index < middleB.length ? middleB[index] : null;
    const kind = left === right ? 'same' : left === null ? 'add' : right === null ? 'del' : 'change';
    rows.push({ left, right, kind });
  }
  for (let index = 0; index < a.length - 1 - tailA; index += 1) {
    const left = a[tailA + 1 + index];
    const right = b[tailB + 1 + index];
    rows.push({ left, right, kind: left === right ? 'same' : 'change' });
  }
  return rows;
}

/** Store one preview and return the id used in the approval link. */
export function remember(before, after, path) {
  const now = Date.now();
  for (const [key, value] of entries) {
    if (now - value.at > TTL_MS) entries.delete(key);
  }
  while (entries.size >= MAX_ENTRIES) {
    const oldest = entries.keys().next().value;
    entries.delete(oldest);
  }
  const id = Math.random().toString(36).slice(2, 10);
  entries.set(id, { path, before, after, at: now, rows: pairLines(before, after) });
  return id;
}

export function lookup(id) {
  const entry = entries.get(id);
  if (entry === undefined) return undefined;
  if (Date.now() - entry.at > TTL_MS) {
    entries.delete(id);
    return undefined;
  }
  return entry;
}

/** Full HTML page for one entry. */
export function renderPage(id, entry) {
  const rows = entry.rows.slice(0, 400);
  const changed = entry.rows.filter((row) => row.kind !== 'same').length;
  const body = rows.map((row) => {
    const cls = row.kind;
    const left = row.left === null ? '' : escapeHtml(row.left);
    const right = row.right === null ? '' : escapeHtml(row.right);
    return `<tr class="${cls}"><td class="num"></td><td class="left">${left}</td><td class="right">${right}</td></tr>`;
  }).join('\n');

  let number = 0;
  const numbered = body.replace(/<td class="num"><\/td>/g, () => {
    number += 1;
    return `<td class="num">${number}</td>`;
  });

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>改动对比 · ${escapeHtml(entry.path)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 20px 24px 40px; font: 13px/1.6 system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; color: #111827; background: #fff; }
  h1 { font-size: 15px; font-weight: 650; margin: 0 0 4px; }
  .meta { color: #6b7280; font-size: 12px; margin-bottom: 14px; }
  .meta code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  table { width: 100%; border-collapse: collapse; table-layout: fixed; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  th { text-align: left; font-weight: 600; font-size: 11px; color: #6b7280; padding: 6px 10px; border-bottom: 1px solid #e5e7eb; background: #f9fafb; }
  td { padding: 1px 10px; vertical-align: top; white-space: pre-wrap; word-break: break-word; border-bottom: 1px solid #f3f4f6; }
  td.num { width: 44px; text-align: right; color: #9ca3af; background: #fafafa; user-select: none; }
  td.left, td.right { width: calc(50% - 22px); }
  tr.same td.left, tr.same td.right { color: #6b7280; }
  tr.del td.left { background: #fdecea; color: #8a1f1a; }
  tr.del td.right { background: #fafafa; }
  tr.add td.right { background: #e7f6ee; color: #0f5c37; }
  tr.add td.left { background: #fafafa; }
  tr.change td.left { background: #fdecea; color: #8a1f1a; }
  tr.change td.right { background: #e7f6ee; color: #0f5c37; }
  .empty { color: #9ca3af; padding: 40px 0; text-align: center; }
</style>
</head>
<body>
<h1>改动对比</h1>
<div class="meta"><code>${escapeHtml(entry.path)}</code> · 共 ${entry.rows.length} 行 · ${changed} 处变化</div>
<table>
<thead><tr><th></th><th>原</th><th>新</th></tr></thead>
<tbody>
${numbered}
</tbody>
</table>
</body>
</html>`;
}

/** Reset for tests. */
export function clearAll() {
  entries.clear();
}
