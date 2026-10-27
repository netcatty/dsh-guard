// Pattern compilation for dsh-guard rules.
//
// Two dialects share one evaluator:
//   glob  — `*` (greedy, crosses `/`), `?` (one character), everything else
//           literal. Anchored at both ends.
//   regex — an unanchored JavaScript regular expression, so `git\s+push`
//           matches a substring.
//
// Glob patterns are bounded by `maxStars`: each run of `*` becomes one `.*`,
// and a pattern with more than that many runs is refused. `*a*a*a*a` compiles
// to nested greedy quantifiers that backtrack exponentially on a long
// non-matching input, so an untrusted rule file must not be able to install it.

const MAX_CACHE = 1024;
const cache = new Map();

export class PatternError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PatternError';
  }
}

export const DEFAULT_MAX_STARS = 2;

/** Number of unbounded `*` runs in a glob pattern. `**` counts as one run. */
export function countStarRuns(pattern) {
  let runs = 0;
  let inRun = false;
  for (const ch of pattern) {
    if (ch === '*') {
      if (!inRun) runs += 1;
      inRun = true;
    } else {
      inRun = false;
    }
  }
  return runs;
}

// Structural backtracking guard for regex mode: a quantified group that is
// itself quantified (`(a+)+`, `(\w*)*`) is the classic ReDoS shape. This is a
// heuristic, not a proof; the documented rule is "prefer glob for untrusted
// files".
const NESTED_QUANTIFIER = /\([^)]*[+*][^)]*\)[+*{]/;

function escapeRegExp(ch) {
  return ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

function compileGlob(pattern, caseInsensitive, maxStars) {
  const runs = countStarRuns(pattern);
  if (maxStars > 0 && runs > maxStars) {
    throw new PatternError(`glob "${pattern}" has ${runs} unbounded '*' runs (max ${maxStars})`);
  }
  let out = '^';
  for (const ch of pattern) {
    if (ch === '*') out += '.*';
    else if (ch === '?') out += '.';
    else out += escapeRegExp(ch);
  }
  return new RegExp(out + '$', caseInsensitive ? 'iu' : 'u');
}

function compileRegex(pattern, caseInsensitive) {
  if (NESTED_QUANTIFIER.test(pattern)) {
    throw new PatternError(`regex "${pattern}" nests a quantified group (ReDoS risk)`);
  }
  try {
    return new RegExp(pattern, caseInsensitive ? 'iu' : 'u');
  } catch (error) {
    throw new PatternError(`regex "${pattern}" is invalid: ${String(error?.message ?? error)}`);
  }
}

/**
 * Compile one pattern through the cache.
 * @param {string} pattern
 * @param {{mode?: 'glob'|'regex', caseInsensitive?: boolean, maxStars?: number}} [options]
 * @returns {RegExp}
 */
export function compile(pattern, options = {}) {
  const mode = options.mode === 'regex' ? 'regex' : 'glob';
  const caseInsensitive = options.caseInsensitive === true;
  const maxStars = options.maxStars ?? DEFAULT_MAX_STARS;
  const key = `${mode}\u0000${caseInsensitive ? 1 : 0}\u0000${maxStars}\u0000${pattern}`;
  const hit = cache.get(key);
  if (hit !== undefined) return hit;
  const compiled = mode === 'regex'
    ? compileRegex(pattern, caseInsensitive)
    : compileGlob(pattern, caseInsensitive, maxStars);
  if (cache.size >= MAX_CACHE) cache.clear();
  cache.set(key, compiled);
  return compiled;
}

/**
 * Test one value. Pattern errors are *not* thrown at call time: a rule file
 * that slipped past validation must not take the whole gate down, so an
 * uncompilable pattern simply never matches.
 */
export function test(pattern, value, options = {}) {
  if (typeof pattern !== 'string' || typeof value !== 'string') return false;
  try {
    return compile(pattern, options).test(value);
  } catch {
    return false;
  }
}

/** Returns a validation error message, or undefined when the pattern compiles. */
export function check(pattern, options = {}) {
  try {
    compile(pattern, options);
    return undefined;
  } catch (error) {
    return error instanceof PatternError ? error.message : String(error);
  }
}
