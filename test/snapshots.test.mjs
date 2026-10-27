import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { capture, describeSnapshot, listSnapshots, prune, restore } from '../lib/snapshots.js';
import { apply } from '../lib/index.js';

const cwd = join(tmpdir(), 'guard-snapshot-project');

function ctxStub(overrides = {}) {
  const listeners = new Map();
  const ctx = {
    on: (event, fn) => listeners.set(event, fn),
    get: () => undefined,
    tools: { register: () => {} },
    workingDirectory: { ensure: async () => cwd },
    sessionProjections: { stateOf: () => 'workspace-write' },
    logger: { warn: () => {}, info: () => {} },
    ...overrides,
  };
  return { ctx, listeners };
}

async function withHome(fn) {
  const home = await mkdtemp(join(tmpdir(), 'guard-snap-home-'));
  const previous = process.env.DSH_HOME;
  process.env.DSH_HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME;
    else process.env.DSH_HOME = previous;
    await rm(home, { recursive: true, force: true });
  }
}

test('capture saves existing files and marks absent ones', async () => {
  const root = await mkdtemp(join(tmpdir(), 'guard-snap-'));
  const existing = join(root, 'a.txt');
  const missing = join(root, 'b.txt');
  await writeFile(existing, 'before');

  const meta = await capture(root, { tool: 'write', callId: 'c1', paths: [existing, missing] });
  assert.ok(meta);
  const byPath = new Map(meta.files.map((file) => [file.path, file.status]));
  assert.equal(byPath.get(existing), 'saved');
  assert.equal(byPath.get(missing), 'absent');

  const entries = listSnapshots(root);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].saved, 1);
  assert.equal(entries[0].absent, 1);
  assert.match(describeSnapshot(entries[0]), /a\.txt/);
  await rm(root, { recursive: true, force: true });
});

test('restore puts bytes back and removes files that did not exist', async () => {
  const root = await mkdtemp(join(tmpdir(), 'guard-snap-'));
  const existing = join(root, 'a.txt');
  const created = join(root, 'new.txt');
  await writeFile(existing, 'before');

  const meta = await capture(root, { tool: 'write', callId: 'c1', paths: [existing, created] });
  await writeFile(existing, 'after');
  await writeFile(created, 'brand new');

  const result = await restore(root, meta.id);
  assert.deepEqual(result.restored, [existing]);
  assert.deepEqual(result.removed, [created]);
  assert.equal(await readFile(existing, 'utf8'), 'before');
  assert.equal(existsSync(created), false);
  await rm(root, { recursive: true, force: true });
});

test('oversized and non-regular files are skipped, not silently restored', async () => {
  const root = await mkdtemp(join(tmpdir(), 'guard-snap-'));
  const big = join(root, 'big.bin');
  const dir = join(root, 'folder');
  await writeFile(big, 'x'.repeat(2048));
  await mkdir(dir);

  const meta = await capture(root, { tool: 'write', paths: [big, dir], maxBytes: 1024 });
  const status = new Map(meta.files.map((file) => [file.path, file.status]));
  assert.equal(status.get(big), 'skipped');
  assert.equal(status.get(dir), 'skipped');
  const result = await restore(root, meta.id);
  assert.equal(result.restored.length, 0);
  assert.equal(result.skipped.length, 2);
  await rm(root, { recursive: true, force: true });
});

test('prune keeps only the newest N snapshots', async () => {
  const root = await mkdtemp(join(tmpdir(), 'guard-snap-'));
  const file = join(root, 'a.txt');
  await writeFile(file, 'x');
  for (let index = 0; index < 5; index += 1) {
    await capture(root, { tool: 'write', callId: `c${index}`, paths: [file], retain: 3 });
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  assert.equal(listSnapshots(root).length, 3);
  prune(root, 1);
  assert.equal(listSnapshots(root).length, 1);
  await rm(root, { recursive: true, force: true });
});

test('a write call is snapshotted before it lands and the audit row names it', async () => {
  await withHome(async (home) => {
    const project = await mkdtemp(join(tmpdir(), 'guard-snap-proj-'));
    const target = join(project, 'notes.txt');
    await writeFile(target, 'original');

    const { ctx, listeners } = ctxStub({ workingDirectory: { ensure: async () => project } });
    apply(ctx, { audit: true, snapshots: true });
    const pre = listeners.get('tools/pre-execute');
    await pre({ name: 'write', arguments: { file_path: target }, agent: { session: { id: 's1' } }, callId: 'c1' }, () => 'NEXT');

    await writeFile(target, 'changed');

    const root = join(home, 'dsh-plugins', 'dsh-guard', 'snapshots');
    const entries = listSnapshots(root);
    assert.equal(entries.length, 1, 'one snapshot per write');
    const audit = (await readFile(join(home, 'dsh-plugins', 'dsh-guard', 'audit.jsonl'), 'utf8')).trim().split('\n');
    const row = JSON.parse(audit.at(-1));
    assert.equal(row.snapshot, entries[0].id);

    const result = await restore(root, entries[0].id);
    assert.equal(await readFile(target, 'utf8'), 'original');
    assert.equal(result.restored.length, 1);
    await rm(project, { recursive: true, force: true });
  });
});

test('a denied write is not snapshotted', async () => {
  await withHome(async (home) => {
    const project = await mkdtemp(join(tmpdir(), 'guard-snap-deny-'));
    const target = join(project, 'secret.env');
    await writeFile(target, 'TOKEN=1');

    const { ctx, listeners } = ctxStub({ workingDirectory: { ensure: async () => project } });
    apply(ctx, { audit: false, snapshots: true, path: { '*': 'allow', '*.env': 'deny' } });
    const pre = listeners.get('tools/pre-execute');
    const denied = await pre({ name: 'write', arguments: { file_path: target }, agent: { session: { id: 's1' } }, callId: 'c1' }, () => 'NEXT');
    assert.equal(denied.kind, 'deny');
    assert.equal(listSnapshots(join(home, 'dsh-plugins', 'dsh-guard', 'snapshots')).length, 0);
    await rm(project, { recursive: true, force: true });
  });
});

test('snapshots: false disables capture entirely', async () => {
  await withHome(async (home) => {
    const project = await mkdtemp(join(tmpdir(), 'guard-snap-off-'));
    const target = join(project, 'notes.txt');
    await writeFile(target, 'original');

    const { ctx, listeners } = ctxStub({ workingDirectory: { ensure: async () => project } });
    apply(ctx, { audit: false, snapshots: false });
    const pre = listeners.get('tools/pre-execute');
    await pre({ name: 'write', arguments: { file_path: target }, agent: { session: { id: 's1' } }, callId: 'c1' }, () => 'NEXT');
    assert.equal(listSnapshots(join(home, 'dsh-plugins', 'dsh-guard', 'snapshots')).length, 0);
    await rm(project, { recursive: true, force: true });
  });
});

test('/guard-undo restores the latest snapshot', async () => {
  await withHome(async (home) => {
    const project = await mkdtemp(join(tmpdir(), 'guard-snap-undo-'));
    const target = join(project, 'notes.txt');
    await writeFile(target, 'v1');

    const registered = new Map();
    const { ctx, listeners } = ctxStub({
      workingDirectory: { ensure: async () => project },
      get: (name) => name === 'commands' ? { register: (def) => registered.set(def.name, def), notifyChange: () => {} } : undefined,
    });
    apply(ctx, { audit: false, snapshots: true });
    await new Promise((resolve) => setTimeout(resolve, 20));

    const pre = listeners.get('tools/pre-execute');
    await pre({ name: 'edit', arguments: { file_path: target }, agent: { session: { id: 's1' } }, callId: 'c1' }, () => 'NEXT');
    await writeFile(target, 'v2');

    const undo = registered.get('guard-undo');
    assert.ok(undo, 'guard-undo is registered');
    const listed = await undo.handler({ rawInput: 'list', agent: { session: { id: 's1' } } });
    assert.equal(listed.kind, 'success');
    assert.match(listed.text, /notes\.txt/);

    const result = await undo.handler({ rawInput: '', agent: { session: { id: 's1' } } });
    assert.equal(result.kind, 'success');
    assert.match(result.text, /已回滚/);
    assert.equal(await readFile(target, 'utf8'), 'v1');
    await rm(project, { recursive: true, force: true });
  });
});
