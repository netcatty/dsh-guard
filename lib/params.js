// Argument flattening and agent identity for dsh-guard's `params` and `agents`
// surfaces.
//
// `flattenArguments` walks a tool's argument object to a bounded depth and
// emits one entry per scalar value, carrying two candidate keys: the full
// dotted path (`arguments.command`, `steps.0.content`) and its last segment
// (`command`, `content`). A rule may therefore name a key at either granularity
// — `command` is shorthand, `arguments.command` is the exact path — and get the
// same value.
//
// Numbers and booleans are stringified; arrays contribute an index segment;
// null/undefined contribute nothing. Depth and count are capped so a hostile
// or huge argument object cannot turn one tool call into unbounded work.

const MAX_DEPTH = 4;
const MAX_ENTRIES = 256;

/**
 * @typedef {{ path: string, key: string, value: string }} ArgumentEntry
 */

/**
 * @param {unknown} value
 * @returns {ArgumentEntry[]}
 */
export function flattenArguments(value) {
  const out = [];
  walk(value, '', 0, out);
  return out;
}

function walk(value, prefix, depth, out) {
  if (out.length >= MAX_ENTRIES || depth > MAX_DEPTH) return;
  if (value === null || value === undefined) return;

  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    const key = prefix === '' ? '' : (prefix.split('.').at(-1) ?? '');
    out.push({ path: prefix, key, value: String(value) });
    return;
  }

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const child = prefix === '' ? String(index) : `${prefix}.${index}`;
      walk(value[index], child, depth + 1, out);
    }
    return;
  }

  if (typeof value === 'object') {
    for (const [name, child] of Object.entries(value)) {
      if (child === undefined) continue;
      const path = prefix === '' ? name : `${prefix}.${name}`;
      walk(child, path, depth + 1, out);
    }
  }
}

/** Candidate keys one entry is matched by, most specific first. */
export function entryKeys(entry) {
  if (entry.path === '') return [];
  const keys = new Set([entry.path]);
  if (entry.key !== '' && !/^\d+$/u.test(entry.key)) keys.add(entry.key);
  // Ancestor paths keep array members reachable by their container's name:
  // `queries.0` is also addressable as the `queries` argument.
  const parts = entry.path.split('.');
  for (let length = parts.length - 1; length > 0; length -= 1) {
    keys.add(parts.slice(0, length).join('.'));
  }
  return [...keys];
}

/**
 * Stable identity strings for one agent, most specific first. The `agents`
 * surface evaluates them in this order and the first matching rule wins, so a
 * `preset:<name>` rule beats the broad `main`/`subagent` fallback.
 *
 * `subagent` follows durable session metadata (`origin: 'subagent'`), so a
 * forked session — which also carries a `parentSession` — is not mistaken for
 * a delegated child. `preset:<name>` names the agent preset that composed the
 * session, when the host recorded one.
 *
 * @param {any} agent
 * @returns {string[]}
 */
export function agentCandidates(agent) {
  const meta = agent?.session?.meta;
  const subagent = meta?.origin === 'subagent' || (typeof meta?.delegationDepth === 'number' && meta.delegationDepth > 0);
  const preset = typeof meta?.agentPreset === 'string' && meta.agentPreset !== '' ? meta.agentPreset : undefined;
  const candidates = [];
  if (preset !== undefined) {
    candidates.push(`preset:${preset}`);
    if (subagent) candidates.push(`subagent:${preset}`);
  }
  candidates.push(subagent ? 'subagent' : 'main');
  return candidates;
}

/** The agent's own reviewable label, used in audit rows. */
export function agentLabel(agent) {
  const meta = agent?.session?.meta;
  const preset = typeof meta?.agentPreset === 'string' ? meta.agentPreset : undefined;
  const kind = meta?.origin === 'subagent' ? 'subagent' : 'main';
  return preset === undefined ? kind : `${kind}/${preset}`;
}
