// Lexical shell decomposition for permission matching.
//
// Splits one command line into simple commands (pipes, `;`, `&&`, `||`, `&`,
// newlines), and each into command word, argument tokens and redirect targets.
// Quote- and escape-aware; NOT a POSIX parser — command substitution, backticks
// and brace expansion stay opaque.

/**
 * @typedef {{ command: string, args: string[], redirects: string[] }} SimpleCommand
 * @typedef {{ commands: SimpleCommand[] }} Decomposition
 */

/**
 * @param {string} text
 * @returns {Decomposition}
 */
export function decomposeShellCommand(text) {
  const commands = [];
  let words = [];
  let buffer = '';
  let started = false;
  let redirect = false;

  const flush = () => {
    if (!started) return;
    words.push({ text: buffer, redirect });
    buffer = '';
    started = false;
    redirect = false;
  };

  const endCommand = () => {
    flush();
    if (words.length === 0) return;
    const commandIndex = words.findIndex((w) => !w.redirect);
    const command = commandIndex < 0 ? '' : words[commandIndex].text;
    const args = [];
    const redirects = [];
    words.forEach((word, index) => {
      if (index === commandIndex) return;
      if (word.redirect) redirects.push(word.text);
      else args.push(word.text);
    });
    commands.push({ command, args, redirects });
    words = [];
  };

  const endWordBeforeRedirect = () => {
    if (started && /^\d+$/.test(buffer)) {
      buffer = '';
      started = false;
      return;
    }
    flush();
  };

  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '\\' && process.platform !== 'win32') {
      buffer += text[i + 1] ?? '\\';
      started = true;
      i += 2;
      continue;
    }
    if (ch === "'") {
      started = true;
      i += 1;
      while (i < text.length && text[i] !== "'") buffer += text[i++];
      i += 1;
      continue;
    }
    if (ch === '"') {
      started = true;
      i += 1;
      while (i < text.length && text[i] !== '"') {
        const next = text[i + 1];
        if (text[i] === '\\' && (next === '"' || next === '\\' || next === '$' || next === '`')) {
          buffer += next;
          i += 2;
        } else {
          buffer += text[i++];
        }
      }
      i += 1;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      flush();
      i += 1;
      continue;
    }
    if (ch === '\n') {
      endCommand();
      i += 1;
      continue;
    }
    if (ch === ';' || ch === '&' || ch === '|') {
      const pair = text.slice(i, i + 2);
      if (pair === '&&' || pair === '||') {
        endCommand();
        i += 2;
        continue;
      }
      if (ch === ';' || ch === '&' || ch === '|') {
        endCommand();
        i += 1;
        continue;
      }
    }
    if (ch === '>' || ch === '<') {
      endWordBeforeRedirect();
      let op = ch;
      i += 1;
      while (i < text.length && (text[i] === '>' || text[i] === '&' || text[i] === '<')) {
        op += text[i++];
      }
      redirect = true;
      continue;
    }
    buffer += ch;
    started = true;
    i += 1;
  }
  endCommand();
  return { commands };
}
