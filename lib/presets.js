// Named policy templates.
//
// The alternative to a form full of per-category dropdowns: a template is one
// JSON fragment, applied through the same validated merge as `/guard-policy`,
// so a template can never write something a hand edit could not. Applying one
// is additive — it merges into the current policy and leaves everything else
// alone, so a template narrows or widens one area without erasing the rest.
//
// `off` is the exception worth understanding: it sets `enforce: false`, which
// makes the gate audit-only. Turning enforcement back on is `true`, and a
// template is the only thing here that touches that switch.

/** @type {Record<string, {summary: string, permission: object}>} */
export const PRESETS = {
  baseline: {
    summary: '外部目录要问、破坏性命令要问、写 .env 拒绝、子代理要问',
    permission: {
      externalDirectory: { '*': 'ask' },
      bash: { 'rm *': 'ask', 'git push *': 'ask', 'sudo *': 'ask' },
      pathWrite: { '*.env': 'deny' },
      agents: { subagent: 'ask' },
      repeatLimit: 5,
    },
  },
  strict: {
    summary: '所有命令与写入都要问、外部目录拒绝、子代理拒绝',
    permission: {
      bash: { '*': 'ask' },
      pathWrite: { '*': 'ask' },
      externalDirectory: { '*': 'deny' },
      agents: { subagent: 'deny' },
      repeatLimit: 3,
    },
  },
  off: {
    summary: '只审计不拦截（enforce: false），循环检测关闭',
    permission: {
      enforce: false,
      repeatLimit: 0,
    },
  },
};

export function getPreset(name) {
  return Object.prototype.hasOwnProperty.call(PRESETS, name) ? PRESETS[name] : undefined;
}

export function listPresets() {
  return Object.entries(PRESETS).map(([name, preset]) => `${name.padEnd(10)} ${preset.summary}`);
}
