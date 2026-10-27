import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clearAll, lookup, pairLines, remember, renderPage } from '../lib/diff-view.js';

test('pairLines marks unchanged, changed, added and removed lines', () => {
  const rows = pairLines('a\nb\nc', 'a\nB\nc\nd');
  assert.deepEqual(rows.map((row) => row.kind), ['same', 'change', 'same', 'add']);
  assert.equal(rows[1].left, 'b');
  assert.equal(rows[1].right, 'B');

  const removed = pairLines('a\nb\nc', 'a');
  assert.equal(removed.some((row) => row.kind === 'del'), true);
});

test('an identical document produces only unchanged rows', () => {
  const rows = pairLines('x\ny', 'x\ny');
  assert.equal(rows.every((row) => row.kind === 'same'), true);
});

test('renderPage escapes markup in file content', () => {
  clearAll();
  const id = remember('<script>alert(1)</script>', '<b>bold</b>', 'evil.html');
  const entry = lookup(id);
  const html = renderPage(id, entry);
  assert.equal(html.includes('<script>alert(1)</script>'), false);
  assert.equal(html.includes('&lt;script&gt;'), true);
  assert.equal(html.includes('evil.html'), true);
});

test('lookup returns undefined for an unknown id', () => {
  clearAll();
  assert.equal(lookup('nope'), undefined);
});
