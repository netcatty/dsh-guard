// Editing the live policy from a command line.
//
// The policy is a nested document: `bash: { "rm *": ask }`, `tools: { "mcp__x__*":
// { "*/secrets/*": deny } }`, `toolParams: { tool: { key: { value: state } } }`.
// A `set surface key value` grammar needs three different arities and breaks on
// any key containing the separator.
//
// So the command takes a JSON fragment and deep-merges it. One grammar covers
// every shape, keys keep their exact spelling, and `null` deletes:
//
//   { "bash": { "rm *": "ask" } }
//   { "toolParams": { "navigate_page": { "url": { "https://prod-*": "deny" } } } }
//   { "bash": { "rm *": null } }          // remove the rule
//
// The merge is applied in memory, validated, and only then written — a bad
// fragment leaves the file untouched.

/** Deep-merge `patch` into `base`; `null` removes a key. Arrays replace wholesale. */
export function deepMerge(base, patch) {
  const out = { ...(base ?? {}) };
  for (const [key, value] of Object.entries(patch ?? {})) {
    if (value === null) {
      delete out[key];
      continue;
    }
    const current = out[key];
    if (
      typeof value === 'object' && value !== null && !Array.isArray(value)
      && typeof current === 'object' && current !== null && !Array.isArray(current)
    ) {
      out[key] = deepMerge(current, value);
      continue;
    }
    out[key] = value;
  }
  return out;
}

/**
 * Apply one fragment to a policy body.
 * @param {object} current the current `permission` object
 * @param {object} patch the JSON fragment
 * @returns {{ next: object, changed: boolean }}
 */
export function applyPatch(current, patch) {
  if (typeof patch !== 'object' || patch === null || Array.isArray(patch)) {
    throw new Error('补丁必须是一个 JSON 对象');
  }
  const next = deepMerge(current, patch);
  const changed = JSON.stringify(next) !== JSON.stringify(current);
  return { next, changed };
}

/** Short human summary of what a merged policy now says, for the command reply. */
export function summarize(permission) {
  const parts = [];
  for (const [name, value] of Object.entries(permission ?? {})) {
    if (typeof value === 'string') {
      parts.push(`${name} = ${value}`);
      continue;
    }
    if (Array.isArray(value)) {
      parts.push(`${name}: ${value.length} 条`);
      continue;
    }
    if (typeof value === 'object' && value !== null) {
      const keys = Object.keys(value);
      parts.push(`${name}: ${keys.length} 条`);
      continue;
    }
    parts.push(`${name} = ${String(value)}`);
  }
  return parts.join(' · ');
}
