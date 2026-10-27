// JSON with comments, for hand-edited policy files.
//
// A policy is something a person writes and re-reads later, so it needs to
// explain itself: `// deny everything under ~/.ssh`, a blank line between
// groups, a trailing comma after the last rule. Strict JSON rejects all three
// and the error points at a line that looks fine, which is exactly why people
// stop editing the file.
//
// This parser strips `//` and `/* */` comments and a single trailing comma per
// object/array, then hands the result to `JSON.parse`. It is a character
// scanner, not a regex: `https://example.com` and `"a // b"` survive because a
// comment starts only outside a string.
//
// Accepted extras are limited to trivia. Anything else — unquoted keys, single
// quotes, NaN — still fails, so a typo cannot silently become a rule.

/** @param {string} text @returns {string} */
export function stripJsonc(text) {
  if (typeof text !== 'string') return text;
  let out = '';
  let index = 0;
  let inString = false;
  let quote = '"';
  let inLineComment = false;
  let inBlockComment = false;

  while (index < text.length) {
    const ch = text[index];
    const next = text[index + 1];

    if (inLineComment) {
      if (ch === '\n') {
        inLineComment = false;
        out += ch;
      }
      index += 1;
      continue;
    }
    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        index += 2;
        continue;
      }
      if (ch === '\n') out += '\n';
      index += 1;
      continue;
    }
    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += next ?? '';
        index += 2;
        continue;
      }
      if (ch === quote) inString = false;
      index += 1;
      continue;
    }

    if (ch === '"') {
      inString = true;
      quote = ch;
      out += ch;
      index += 1;
      continue;
    }
    if (ch === '/' && next === '/') {
      inLineComment = true;
      index += 2;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlockComment = true;
      index += 2;
      continue;
    }
    out += ch;
    index += 1;
  }

  return removeTrailingCommas(out);
}

/**
 * Drop a comma that is followed only by whitespace and a closing bracket.
 * Done after comment removal, so `[1, // last\n]` is already `[1,\n]`.
 * @param {string} text
 * @returns {string}
 */
function removeTrailingCommas(text) {
  let out = '';
  let index = 0;
  let inString = false;
  let quote = '"';

  while (index < text.length) {
    const ch = text[index];
    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += text[index + 1] ?? '';
        index += 2;
        continue;
      }
      if (ch === quote) inString = false;
      index += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      quote = ch;
      out += ch;
      index += 1;
      continue;
    }
    if (ch === ',') {
      // Look ahead past whitespace for a closing bracket.
      let look = index + 1;
      while (look < text.length && /\s/u.test(text[look])) look += 1;
      if (text[look] === '}' || text[look] === ']') {
        index += 1;
        continue;
      }
    }
    out += ch;
    index += 1;
  }
  return out;
}

/**
 * Parse a JSONC document.
 * @param {string} text
 * @returns {unknown}
 * @throws {SyntaxError} with the same message JSON.parse would give.
 */
export function parseJsonc(text) {
  return JSON.parse(stripJsonc(text));
}
