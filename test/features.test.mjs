import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide, apply, validate, redactText } from '../lib/index.js';
import { flattenArguments, entryKeys, agentCandidates } from '../lib/params.js';
import { countStarRuns, compile } from '../lib/match.js';
import { configDir, statusPath, auditPath } from '../lib/paths.js';
import { parseJsonc, stripJsonc } from '../lib/jsonc.js';

const base = {
  '*': 'allow',
  path: { '*': 'allow' },
  pathRead: {},
  pathWrite: {},
  externalDirectory: { '*': 'allow' },
  bash: { '*': 'allow' },
};

const cwd = join(tmpdir(), 'guard-features-project');

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

// Every test that mounts the plugin points DSH_HOME at a throwaway directory so
// the real ~/.dsh is never touched.
async function withHome(fn) {
  const home = await mkdtemp(join(tmpdir(), 'guard-home-'));
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

// ---------------------------------------------------------------- params

test('params rules match any tool argument, not only path arguments', async () => {
  const permission = { ...base, params: { queries: { '*password*': 'deny' } } };
  const hit = await decide({ name: 'web_search', arguments: { queries: ['root password'] } }, cwd, permission);
  assert.equal(hit.state, 'deny');
  assert.match(hit.pattern, /params queries/);
  const miss = await decide({ name: 'web_search', arguments: { queries: ['weather'] } }, cwd, permission);
  assert.equal(miss, undefined);
});

test('params reach nested MCP router arguments by path or leaf name', async () => {
  const permission = { ...base, params: { command: { 'rm *': 'deny' } } };
  const exec = { name: 'mcp', arguments: { action: 'call', server: 'fs', arguments: { command: 'rm -rf /' } } };
  const hit = await decide(exec, cwd, permission);
  assert.equal(hit.state, 'deny');

  const exact = { ...base, params: { 'arguments.command': { 'rm *': 'deny' } } };
  assert.equal((await decide(exec, cwd, exact)).state, 'deny');
});

test('params values can use regex when patternMode is regex', async () => {
  const permission = { ...base, patternMode: 'regex', params: { command: { '^git\\s+push': 'ask' } } };
  const hit = await decide({ name: 'bash', arguments: { command: 'git  push origin main' } }, cwd, permission);
  assert.equal(hit.state, 'ask');
  const miss = await decide({ name: 'bash', arguments: { command: 'git status' } }, cwd, permission);
  assert.equal(miss, undefined);
});

test('flattenArguments exposes array containers as matchable keys', () => {
  const entries = flattenArguments({ queries: ['a', 'b'], nested: { command: 'x' } });
  const keys = entries.flatMap((entry) => entryKeys(entry));
  assert.ok(keys.includes('queries.0'));
  assert.ok(keys.includes('queries'));
  assert.ok(keys.includes('nested.command'));
  assert.ok(keys.includes('command'));
});

// ---------------------------------------------------------------- agents

test('agents surface separates main, subagent and preset identities', async () => {
  const permission = { ...base, agents: { subagent: 'deny', 'preset:reader': 'ask', main: 'allow' } };
  const sub = { session: { meta: { origin: 'subagent' } } };
  const subHit = await decide({ name: 'read', arguments: { file_path: 'a.txt' }, agent: sub }, cwd, permission);
  assert.equal(subHit.state, 'deny');

  const main = { session: { meta: {} } };
  assert.equal(await decide({ name: 'read', arguments: { file_path: 'a.txt' }, agent: main }, cwd, permission), undefined);

  const reader = { session: { meta: { agentPreset: 'reader' } } };
  const presetHit = await decide({ name: 'read', arguments: { file_path: 'a.txt' }, agent: reader }, cwd, permission);
  assert.equal(presetHit.state, 'ask');
});

test('a forked session is not mistaken for a subagent', () => {
  assert.deepEqual(agentCandidates({ session: { meta: { parentSession: 'p1' } } }), ['main']);
  assert.ok(agentCandidates({ session: { meta: { origin: 'subagent', agentPreset: 'x' } } }).includes('subagent:x'));
});

// ---------------------------------------------------------------- enforce

test('enforce: false audits a dry run and lets every call through', async () => {
  await withHome(async () => {
    const { ctx, listeners } = ctxStub();
    apply(ctx, { enforce: false, audit: true, bash: { 'rm *': 'deny' } });
    const pre = listeners.get('tools/pre-execute');
    const result = await pre(
      { name: 'bash', arguments: { command: 'rm -rf build' }, agent: { session: { id: 's1' } }, callId: 'c1' },
      () => 'NEXT',
    );
    assert.equal(result, 'NEXT');
    const lines = (await readFile(auditPath(), 'utf8')).trim().split('\n');
    const last = JSON.parse(lines.at(-1));
    assert.equal(last.state, 'deny');
    assert.equal(last.dryRun, true);
  });
});

// ---------------------------------------------------------------- audit

test('audit arguments are redacted before they reach the disk', async () => {
  await withHome(async () => {
    const { ctx, listeners } = ctxStub();
    apply(ctx, { audit: true });
    const pre = listeners.get('tools/pre-execute');
    await pre(
      { name: 'bash', arguments: { command: 'echo sk-abcdefghijklmnopqrstuvwxyz' }, agent: { session: { id: 's1' } }, callId: 'c1' },
      () => 'NEXT',
    );
    const text = await readFile(auditPath(), 'utf8');
    assert.equal(text.includes('sk-abcdefghijklmnopqrstuvwxyz'), false);
    assert.ok(text.includes('***'));
  });
});

test('audit file rotates once it passes auditMaxBytes', async () => {
  await withHome(async () => {
    const { ctx, listeners } = ctxStub();
    apply(ctx, { audit: true, auditMaxBytes: 400 });
    const pre = listeners.get('tools/pre-execute');
    for (let index = 0; index < 8; index += 1) {
      await pre(
        { name: 'bash', arguments: { command: `echo ${'x'.repeat(120)}` }, agent: { session: { id: 's1' } }, callId: `c${index}` },
        () => 'NEXT',
      );
    }
    assert.ok(existsSync(`${auditPath()}.1`), 'the rolling file exists');
  });
});

// ---------------------------------------------------------------- data dir

test('plugin data lives under $DSH_HOME/dsh-plugins/dsh-guard', async () => {
  await withHome(async (home) => {
    const { ctx } = ctxStub();
    apply(ctx, { audit: false });
    assert.equal(configDir(), join(home, 'dsh-plugins', 'dsh-guard'));
    assert.equal(statusPath(), join(configDir(), 'status.json'));
    // Regression: the first writeStatus() used to hit `commandRegistered` in its
    // temporal dead zone and fail silently, leaving no status file at all.
    const status = JSON.parse(await readFile(statusPath(), 'utf8'));
    assert.equal(status.version, '1.1.0');
    assert.equal(typeof status.config.enforce, 'boolean');
    assert.equal(status.dataDir, configDir());
  });
});

test('legacy home-root files migrate into the plugin directory', async () => {
  await withHome(async (home) => {
    await writeFile(join(home, 'guard-audit.jsonl'), '{"old":true}\n');
    await writeFile(join(home, 'guard-status.json'), '{"old":true}\n');
    const { ctx } = ctxStub();
    apply(ctx, { audit: false });
    assert.equal(existsSync(join(home, 'guard-audit.jsonl')), false);
    assert.equal(existsSync(join(home, 'guard-status.json')), false);
    assert.equal(existsSync(auditPath()), true);
    assert.equal(existsSync(statusPath()), true);
  });
});

// ---------------------------------------------------------------- grants

test('session grants honor maxUses and TTL', async () => {
  await withHome(async () => {
    let asked = 0;
    const uq = {
      ask: async () => {
        asked += 1;
        return { answers: [{ id: 'guard', selected: ['本会话允许'] }] };
      },
    };
    const { ctx, listeners } = ctxStub({ get: (name) => name === 'userQuestions' ? uq : undefined });
    apply(ctx, { approvalMode: 'question', audit: false, sessionApprovalMaxUses: 1, bash: { 'rm *': 'ask' } });
    const pre = listeners.get('tools/pre-execute');
    const exec = (id) => ({ name: 'bash', arguments: { command: 'rm x' }, agent: { session: { id: 's1' } }, callId: id });

    assert.equal(await pre(exec('c1'), () => 'NEXT'), 'NEXT');
    assert.equal(asked, 1);
    assert.equal(await pre(exec('c2'), () => 'NEXT'), 'NEXT');
    assert.equal(asked, 1, 'the second call used the grant');
    assert.equal(await pre(exec('c3'), () => 'NEXT'), 'NEXT');
    assert.equal(asked, 2, 'the use budget forced a fresh question');
  });
});

// ---------------------------------------------------------------- persist

test('approving with "写入项目规则" appends an allow rule to the project policy', async () => {
  await withHome(async () => {
    const project = await mkdtemp(join(tmpdir(), 'guard-persist-'));
    const uq = { ask: async () => ({ answers: [{ id: 'guard', selected: ['写入项目规则'] }] }) };
    const { ctx, listeners } = ctxStub({
      get: (name) => name === 'userQuestions' ? uq : undefined,
      workingDirectory: { ensure: async () => project },
    });
    apply(ctx, { approvalMode: 'question', audit: false, bash: { 'printf *': 'ask' } });
    const pre = listeners.get('tools/pre-execute');
    const result = await pre(
      { name: 'bash', arguments: { command: 'printf hello' }, agent: { session: { id: 's1' } }, callId: 'c1' },
      () => 'NEXT',
    );
    assert.equal(result, 'NEXT');
    const policy = JSON.parse(await readFile(join(project, '.dsh', 'guard-policy.json'), 'utf8'));
    assert.equal(policy.permission.bash['printf *'], 'allow');
    await rm(project, { recursive: true, force: true });
  });
});

test('a deny with a custom reason reaches the model', async () => {
  await withHome(async () => {
    const uq = { ask: async () => ({ answers: [{ id: 'guard', selected: ['拒绝'], custom: '先用只读命令确认' }] }) };
    const { ctx, listeners } = ctxStub({ get: (name) => name === 'userQuestions' ? uq : undefined });
    apply(ctx, { approvalMode: 'question', audit: false, bash: { 'rm *': 'ask' } });
    const pre = listeners.get('tools/pre-execute');
    const result = await pre(
      { name: 'bash', arguments: { command: 'rm x' }, agent: { session: { id: 's1' } }, callId: 'c1' },
      () => 'NEXT',
    );
    assert.equal(result.kind, 'deny');
    assert.match(result.reason, /先用只读命令确认/);
  });
});

// ---------------------------------------------------------------- commands

test('/guard-test dry-evaluates a call without executing it', async () => {
  await withHome(async () => {
    const registered = new Map();
    const { ctx } = ctxStub({
      get: (name) => name === 'commands' ? { register: (def) => registered.set(def.name, def) } : undefined,
    });
    apply(ctx, { audit: false, bash: { 'rm *': 'deny' }, params: { query: { '*secret*': 'ask' } } });
    await new Promise((resolve) => setTimeout(resolve, 20));

    const command = registered.get('guard-test');
    assert.ok(command, 'guard-test is registered');
    const denied = await command.handler({ rawInput: 'bash {"command":"rm -rf /"}', agent: { session: { id: 's1' } } });
    assert.equal(denied.kind, 'success');
    assert.match(denied.text, /deny/);

    const paramHit = await command.handler({ rawInput: 'web_search {"query":"my secret"}', agent: { session: { id: 's1' } } });
    assert.match(paramHit.text, /ask/);

    const bad = await command.handler({ rawInput: 'bash {not json', agent: { session: { id: 's1' } } });
    assert.equal(bad.kind, 'error');
  });
});

// ---------------------------------------------------------------- patterns

test('glob star runs are bounded and counted correctly', () => {
  assert.equal(countStarRuns('*/.ssh/*'), 2);
  assert.equal(countStarRuns('**/*'), 2);
  assert.equal(countStarRuns('plain'), 0);
  assert.throws(() => compile('*a*a*a*', { maxStars: 2 }), /unbounded/);
  assert.equal(compile('*a*', { maxStars: 2 }).test('xayaz'), true);
});

test('a bad pattern is a validation error, not a crash at call time', () => {
  assert.ok(validate({ params: { command: { '*a*a*a*': 'deny' } } }).length > 0);
  const denied = decide({ name: 'bash', arguments: { command: 'x' } }, cwd, {
    ...base,
    params: { command: { '*a*a*a*': 'deny' } },
  });
  return denied.then((value) => assert.equal(value, undefined));
});

// ---------------------------------------------------------------- redaction

test('redactText still covers the credential shapes the audit trail quotes', () => {
  assert.equal(redactText('sk-abcdefghijklmnopqrstuvwxyz').includes('sk-abcdefghijklmnopqrstuvwxyz'), false);
  assert.equal(redactText('TOKEN=supersecretvalue').includes('supersecretvalue'), false);
});

// ---------------------------------------------------------------- shipped policy

test('the shipped policy still gates the paths and commands it always did', async () => {
  const { mergePermission } = await import('../lib/index.js');
  const permission = mergePermission({});
  assert.equal(permission.invalid, undefined, 'policy.json validates');
  assert.equal(permission.enforce, true);

  const sshPath = ['~', '.ssh', 'id_rsa'].join('/');
  const ssh = await decide({ name: 'read', arguments: { file_path: sshPath } }, cwd, permission);
  assert.equal(ssh.state, 'deny');

  const wipe = await decide({ name: 'bash', arguments: { command: 'rm -rf ~/projects' } }, cwd, permission);
  assert.equal(wipe.state, 'deny');

  const push = await decide({ name: 'bash', arguments: { command: 'git push origin main' } }, cwd, permission);
  assert.equal(push.state, 'ask');

  const plain = await decide({ name: 'read', arguments: { file_path: 'src/index.js' } }, cwd, permission);
  assert.equal(plain, undefined);
});

// ---------------------------------------------------------------- live policy

test('the live policy is the data-directory copy, not the repository seed', async () => {
  await withHome(async (home) => {
    const { mergePermission } = await import('../lib/index.js');
    const dir = join(home, 'dsh-plugins', 'dsh-guard');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'policy.json'), JSON.stringify({ permission: { '*': 'deny' } }));
    const permission = mergePermission({});
    assert.equal(permission['*'], 'deny');
  });
});

test('a missing live policy falls back to the shipped seed', async () => {
  await withHome(async () => {
    const { mergePermission } = await import('../lib/index.js');
    const permission = mergePermission({});
    assert.equal(permission['*'], 'allow', 'the shipped policy allows by default');
    assert.ok(Object.keys(permission.bash).length > 100);
  });
});

// ---------------------------------------------------------------- jsonc

test('policy files may carry comments and trailing commas', () => {
  const sample = `{
    // which file tools are guarded
    "permission": {
      "a": "allow", /* inline */
      "bash": { "curl *": "ask", },
    },
  }`;
  assert.deepEqual(parseJsonc(sample), { permission: { a: 'allow', bash: { 'curl *': 'ask' } } });
});

test('a // inside a string or URL is not a comment', () => {
  assert.equal(JSON.parse(stripJsonc('{"u":"https://x.dev/a//b"}')).u, 'https://x.dev/a//b');
  assert.equal(JSON.parse(stripJsonc('{"a":"// not a comment"}')).a, '// not a comment');
});

test('the loader ignores $schema and parses a commented policy', async () => {
  await withHome(async (home) => {
    const dir = join(home, 'dsh-plugins', 'dsh-guard');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'policy.json'), `{
      // my own policy
      "$schema": "./policy.schema.json",
      "permission": {
        "*": "deny", // everything off
      },
    }`);
    const { mergePermission } = await import('../lib/index.js');
    const permission = mergePermission({});
    assert.equal(permission['*'], 'deny');
  });
});

// ---------------------------------------------------------------- recent window

test('recentDecisions keeps the newest ten decisions, newest first', async () => {
  await withHome(async () => {
    const { ctx, listeners } = ctxStub();
    apply(ctx, { audit: false });
    const pre = listeners.get('tools/pre-execute');
    for (let index = 0; index < 12; index += 1) {
      await pre(
        { name: `probe-${index}`, arguments: {}, agent: { session: { id: 's1' } }, callId: `c${index}` },
        () => 'NEXT',
      );
    }
    const status = JSON.parse(await readFile(statusPath(), 'utf8'));
    assert.equal(status.recentDecisions.length, 10);
    assert.equal(status.recentDecisions[0].tool, 'probe-11');
    assert.equal(status.recentDecisions[9].tool, 'probe-2');
  });
});

test('the recent window is recorded even when the audit file is off', async () => {
  await withHome(async () => {
    const { ctx, listeners } = ctxStub();
    apply(ctx, { audit: false });
    const pre = listeners.get('tools/pre-execute');
    await pre({ name: 'probe', arguments: {}, agent: { session: { id: 's1' } }, callId: 'c1' }, () => 'NEXT');
    const status = JSON.parse(await readFile(statusPath(), 'utf8'));
    assert.equal(status.recentDecisions[0].tool, 'probe');
  });
});

// ---------------------------------------------------------------- project chain

async function projectTree() {
  const repo = await mkdtemp(join(tmpdir(), 'guard-repo-'));
  const pkg = join(repo, 'pkg');
  await mkdir(join(repo, '.dsh'), { recursive: true });
  await mkdir(join(pkg, '.dsh'), { recursive: true });
  await writeFile(join(repo, '.dsh', 'guard-policy.json'), JSON.stringify({
    permission: { bash: { 'root-only *': 'deny', 'shared *': 'deny' } },
  }));
  await writeFile(join(pkg, '.dsh', 'guard-policy.json'), JSON.stringify({
    permission: { bash: { 'near-only *': 'deny', 'shared *': 'allow' } },
  }));
  return { repo, pkg };
}

test('project rules stack from the repository root down to the cwd', async () => {
  const { repo, pkg } = await projectTree();
  const { ctx, listeners } = ctxStub({ workingDirectory: { ensure: async () => pkg } });
  apply(ctx, { audit: false });
  const pre = listeners.get('tools/pre-execute');
  const run = (command, id) => pre(
    { name: 'bash', arguments: { command }, agent: { session: { id: 's1' } }, callId: id },
    () => 'NEXT',
  );

  assert.equal((await run('root-only x', 'c1')).kind, 'deny', 'the repository-root rule applies inside a package');
  assert.equal((await run('near-only x', 'c2')).kind, 'deny', 'the package rule applies too');
  assert.equal(await run('shared x', 'c3'), 'NEXT', 'the nearer package file overrides the root rule');
  await rm(repo, { recursive: true, force: true });
});

test('projectPolicySearchUp: false limits the read to the cwd', async () => {
  const { repo, pkg } = await projectTree();
  const { ctx, listeners } = ctxStub({ workingDirectory: { ensure: async () => pkg } });
  apply(ctx, { audit: false, projectPolicySearchUp: false });
  const pre = listeners.get('tools/pre-execute');
  const run = (command, id) => pre(
    { name: 'bash', arguments: { command }, agent: { session: { id: 's1' } }, callId: id },
    () => 'NEXT',
  );

  assert.equal(await run('root-only x', 'c1'), 'NEXT', 'the root file is out of scope');
  assert.equal((await run('near-only x', 'c2')).kind, 'deny', 'the cwd file still applies');
  await rm(repo, { recursive: true, force: true });
});

// ---------------------------------------------------------------- mcp tools

test('tools keys match tool names as globs, so one MCP server is governed at once', async () => {
  const permission = { ...base, tools: { 'mcp__chrome-devtools__*': { '*': 'deny' } } };
  const click = await decide({ name: 'mcp__chrome-devtools__click', arguments: {} }, cwd, permission);
  assert.equal(click.state, 'deny');
  assert.equal(click.surface, 'tools.mcp__chrome-devtools__click');
  const navigate = await decide({ name: 'mcp__chrome-devtools__navigate_page', arguments: { url: 'https://x' } }, cwd, permission);
  assert.equal(navigate.state, 'deny');
  assert.equal(await decide({ name: 'read', arguments: { file_path: 'a.txt' } }, cwd, permission), undefined);
});

test('toolParams scopes a value rule to one tool, not to every tool with that key', async () => {
  const permission = {
    ...base,
    toolParams: { 'mcp__chrome-devtools__navigate_page': { url: { 'https://prod-*': 'deny' } } },
  };
  const hit = await decide({ name: 'mcp__chrome-devtools__navigate_page', arguments: { url: 'https://prod-1.example/a' } }, cwd, permission);
  assert.equal(hit.state, 'deny');
  assert.match(hit.pattern, /toolParams/);

  const dev = await decide({ name: 'mcp__chrome-devtools__navigate_page', arguments: { url: 'https://dev.example/a' } }, cwd, permission);
  assert.equal(dev, undefined);

  const otherTool = await decide({ name: 'fetch', arguments: { url: 'https://prod-1.example/a' } }, cwd, permission);
  assert.equal(otherTool, undefined, 'another tool with the same key is untouched');
});

test('a toolParams entry with a malformed shape is a validation error', () => {
  assert.ok(validate({ toolParams: { 'mcp__x__y': { url: 'deny' } } }).length > 0);
});

// ---------------------------------------------------------------- approval preview

test('a write preview shows the current and next content', async () => {
  const { writePreview, editPreview, previewFor } = await import('../lib/preview.js');
  const text = writePreview({ path: 'a.md', before: 'one\ntwo\n', after: 'one\nTWO\nthree\n' });
  assert.match(text, /改写 a\.md：3 → 4 行/);
  assert.match(text, /^- one$/m);
  assert.match(text, /^\+ TWO$/m);

  const created = writePreview({ path: 'new.txt', after: 'hello' });
  assert.match(created, /新建 new\.txt/);

  const edit = editPreview({ path: 'a.md', oldString: 'const x = 1', newString: 'const x = 2' });
  assert.match(edit, /编辑 a\.md/);
  assert.match(edit, /- const x = 1/);
  assert.match(edit, /\+ const x = 2/);

  const viaExec = previewFor(
    { name: 'write', arguments: { file_path: '/tmp/x/a.md', content: 'next' } },
    () => 'before',
  );
  assert.match(viaExec, /改写/);
  assert.equal(previewFor({ name: 'bash', arguments: { command: 'ls' } }, () => ''), '');
});

// ---------------------------------------------------------------- policy command

test('deepMerge replaces leaves, keeps siblings, and removes null keys', async () => {
  const { applyPatch } = await import('../lib/policy-edit.js');
  const current = { bash: { 'rm *': 'ask', 'git push *': 'ask' }, params: { query: { '*x*': 'deny' } } };
  const { next, changed } = applyPatch(current, { bash: { 'rm *': 'deny', 'git push *': null } });
  assert.equal(changed, true);
  assert.deepEqual(next, { bash: { 'rm *': 'deny' }, params: { query: { '*x*': 'deny' } } });
  assert.equal(applyPatch(current, { bash: { 'rm *': 'ask' } }).changed, false);
});

test('/guard-policy writes a fragment into the live policy and it takes effect', async () => {
  await withHome(async (home) => {
    const registered = new Map();
    const { ctx } = ctxStub({
      get: (name) => name === 'commands'
        ? { register: (definition) => registered.set(definition.name, definition), notifyChange: () => {} }
        : undefined,
    });
    apply(ctx, { audit: false });
    await new Promise((resolve) => setTimeout(resolve, 20));

    const command = registered.get('guard-policy');
    assert.ok(command, 'guard-policy is registered');
    const file = join(home, 'dsh-plugins', 'dsh-guard', 'policy.json');

    const added = await command.handler({ rawInput: '{"bash":{"custom-cmd *":"deny"}}' });
    assert.equal(added.kind, 'success');
    const after = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(after.permission.bash['custom-cmd *'], 'deny');
    assert.equal(after.$schema, './policy.schema.json');
    assert.ok(existsSync(`${file}.bak`), 'the previous file is kept');

    const removed = await command.handler({ rawInput: '{"bash":{"custom-cmd *":null}}' });
    assert.equal(removed.kind, 'success');
    const cleaned = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(cleaned.permission.bash['custom-cmd *'], undefined);

    const bad = await command.handler({ rawInput: '{"bash":{"custom-cmd *":"block"}}' });
    assert.equal(bad.kind, 'error');
    const untouched = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(untouched.permission.bash['custom-cmd *'], undefined, 'a rejected patch writes nothing');

    const listed = await command.handler({ rawInput: 'list' });
    assert.equal(listed.kind, 'success');
    assert.match(listed.text, /"bash"/);
  });
});

// ---------------------------------------------------------------- repeat detection

test('the same call repeated past repeatLimit asks even when each one is allowed', async () => {
  await withHome(async () => {
    const { ctx, listeners } = ctxStub();
    apply(ctx, { audit: false, repeatLimit: 3 });
    const pre = listeners.get('tools/pre-execute');
    const call = (id) => pre(
      { name: 'probe', arguments: { x: 1 }, agent: { session: { id: 's1' } }, callId: id },
      () => 'NEXT',
    );
    assert.equal(await call('c1'), 'NEXT');
    assert.equal(await call('c2'), 'NEXT');
    const third = await call('c3');
    assert.equal(third.kind, 'ask');
    assert.match(third.reason, /repeat probe ×3/);
  });
});

test('different arguments do not count as the same call', async () => {
  await withHome(async () => {
    const { ctx, listeners } = ctxStub();
    apply(ctx, { audit: false, repeatLimit: 2 });
    const pre = listeners.get('tools/pre-execute');
    const call = (id, x) => pre(
      { name: 'probe', arguments: { x }, agent: { session: { id: 's1' } }, callId: id },
      () => 'NEXT',
    );
    assert.equal(await call('c1', 1), 'NEXT');
    assert.equal(await call('c2', 2), 'NEXT');
    assert.equal(await call('c3', 3), 'NEXT');
  });
});

test('repeatLimit 0 disables loop detection', async () => {
  await withHome(async () => {
    const { ctx, listeners } = ctxStub();
    apply(ctx, { audit: false, repeatLimit: 0 });
    const pre = listeners.get('tools/pre-execute');
    for (let index = 0; index < 10; index += 1) {
      const result = await pre(
        { name: 'probe', arguments: { x: 1 }, agent: { session: { id: 's1' } }, callId: `c${index}` },
        () => 'NEXT',
      );
      assert.equal(result, 'NEXT');
    }
  });
});

// ---------------------------------------------------------------- presets

test('/guard-policy preset applies a named template', async () => {
  await withHome(async (home) => {
    const registered = new Map();
    const { ctx } = ctxStub({
      get: (name) => name === 'commands'
        ? { register: (definition) => registered.set(definition.name, definition), notifyChange: () => {} }
        : undefined,
    });
    apply(ctx, { audit: false });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const command = registered.get('guard-policy');
    const file = join(home, 'dsh-plugins', 'dsh-guard', 'policy.json');

    const listed = await command.handler({ rawInput: 'preset list' });
    assert.equal(listed.kind, 'success');
    assert.match(listed.text, /baseline/);

    const strict = await command.handler({ rawInput: 'preset strict' });
    assert.equal(strict.kind, 'success');
    const after = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(after.permission.bash['*'], 'ask');
    assert.equal(after.permission.externalDirectory['*'], 'deny');
    assert.equal(after.permission.repeatLimit, 3);
    assert.equal(after.permission.path['*.env'], 'deny', 'existing rules are kept');

    const unknown = await command.handler({ rawInput: 'preset nope' });
    assert.equal(unknown.kind, 'error');
  });
});

// ---------------------------------------------------------------- settings API

function fakeResponse() {
  const res = { status: 0, body: '', writeHead(status) { this.status = status; }, end(body) { this.body = body; } };
  return res;
}

function fakeRequest(method, payload) {
  const chunks = payload === undefined ? [] : [JSON.stringify(payload)];
  return {
    method,
    socket: { remoteAddress: '127.0.0.1' },
    headers: {},
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) yield chunk;
    },
  };
}

test('the settings API exposes switches and writes them through validation', async () => {
  await withHome(async (home) => {
    const routes = new Map();
    const { ctx } = ctxStub({
      inject: (services, setup) => {
        if (!services.includes('webServer')) return;
        setup({ webServer: { register: (route) => { routes.set(route.path, route.handler); return () => {}; } } });
      },
      effect: (fn) => { fn(); return () => {}; },
    });
    apply(ctx, { audit: false });
    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.ok(routes.has('/api/dsh-guard/state'));
    assert.ok(routes.has('/api/dsh-guard/config'));
    assert.ok(routes.has('/api/dsh-guard/preset'));

    const stateRes = fakeResponse();
    await routes.get('/api/dsh-guard/state')(fakeRequest('GET'), stateRes);
    assert.equal(stateRes.status, 200);
    const state = JSON.parse(stateRes.body);
    assert.equal(state.config.enforce, true);
    assert.equal(typeof state.config.snapshotRetain, 'number');
    assert.equal(typeof state.config.snapshotMaxBytes, 'number');
    assert.equal(typeof state.config.repeatLimit, 'number');
    assert.equal(typeof state.config.auditMaxBytes, 'number');
    assert.ok(Array.isArray(state.presets));
    assert.ok(state.policyPath.endsWith('policy.json'));

    const configRes = fakeResponse();
    await routes.get('/api/dsh-guard/config')(fakeRequest('POST', { patch: { enforce: false } }), configRes);
    assert.equal(configRes.status, 200);
    const file = join(home, 'dsh-plugins', 'dsh-guard', 'policy.json');
    const after = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(after.permission.enforce, false);

    const badRes = fakeResponse();
    await routes.get('/api/dsh-guard/config')(fakeRequest('POST', { patch: { enforce: 'no' } }), badRes);
    assert.equal(badRes.status, 400);

    const presetRes = fakeResponse();
    await routes.get('/api/dsh-guard/preset')(fakeRequest('POST', { name: 'strict' }), presetRes);
    assert.equal(presetRes.status, 200);
    const presetFile = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(presetFile.permission.bash['*'], 'ask');
  });
});

test('the settings API rejects a non-loopback cross-origin caller', async () => {
  await withHome(async () => {
    const routes = new Map();
    const { ctx } = ctxStub({
      inject: (services, setup) => {
        if (!services.includes('webServer')) return;
        setup({ webServer: { register: (route) => { routes.set(route.path, route.handler); return () => {}; } } });
      },
      effect: (fn) => { fn(); return () => {}; },
    });
    apply(ctx, { audit: false });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const res = fakeResponse();
    const req = { method: 'GET', socket: { remoteAddress: '10.0.0.5' }, headers: { origin: 'https://evil.example' } };
    await routes.get('/api/dsh-guard/state')(req, res);
    assert.equal(res.status, 403);
  });
});

// ---------------------------------------------------------------- audit tail

test('readTail returns the newest rows from a large file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'guard-log-'));
  const file = join(dir, 'audit.jsonl');
  const lines = [];
  for (let index = 0; index < 5000; index += 1) {
    lines.push(JSON.stringify({ at: '2026-10-28T00:00:00.000Z', tool: `t${index}`, state: 'allow', pad: 'x'.repeat(60) }));
  }
  await writeFile(file, lines.join('\n') + '\n');
  const { readTail, describeDecision } = await import('../lib/audit-log.js');

  const rows = readTail(file, 3);
  assert.equal(rows.length, 3);
  assert.equal(rows.at(-1).tool, 't4999', 'the window starts mid-file and drops the partial line');
  assert.match(describeDecision(rows.at(-1)), /allow  t4999/);

  assert.equal(readTail(join(dir, 'missing.jsonl'), 5).length, 0);
  await rm(dir, { recursive: true, force: true });
});
