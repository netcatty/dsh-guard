import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describeDecision, readTail } from '../lib/audit-log.js';

test('readTail skips a half-written trailing line', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'guard-log-'));
  const file = join(dir, 'audit.jsonl');
  const lines = [JSON.stringify({ a: 1 }), JSON.stringify({ a: 2 }), '{"a":'];
  await writeFile(file, lines.join('\n'));
  const rows = readTail(file, 10);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((row) => row.a), [1, 2]);
  await rm(dir, { recursive: true, force: true });
});

test('describeDecision renders time, state, tool and pattern', () => {
  const line = describeDecision({ at: '2026-10-28T00:11:22.000Z', state: 'deny', tool: 'bash', pattern: 'rm -rf ~*' });
  assert.match(line, /^00:11:22 {2}deny {3}bash {2}rm -rf ~\*$/);
  assert.equal(describeDecision({ tool: 'read' }).includes('read'), true);
});
