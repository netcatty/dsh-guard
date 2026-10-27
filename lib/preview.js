// Human-readable previews for an approval prompt.
//
// The gate knows what the call is about to do but a three-button dialog cannot
// show it. Before asking, this module turns the call into a short text block
// that says what the file looks like now and what it will look like after —
// enough to notice "it says it fixes a typo but deletes 40 lines".
//
// It never fails an approval: any unexpected argument shape yields no preview
// rather than an error.

const MAX_CHARS = 1600;
const MAX_LINES = 6;
const MAX_READ_BYTES = 128 * 1024;

function lines(text) {
  return text.split('\n');
}

function head(list, prefix) {
  const shown = list.slice(0, MAX_LINES).map((line) => `${prefix} ${line}`).join('\n');
  const rest = list.length - MAX_LINES;
  return rest > 0 ? `${shown}\n${prefix} …（还有 ${rest} 行）` : shown;
}

/** Keep one preview block bounded so a huge rewrite cannot flood the dialog. */
export function clamp(text) {
  if (typeof text !== 'string' || text.length <= MAX_CHARS) return text;
  return `${text.slice(0, MAX_CHARS)}\n…（预览截断）`;
}

/**
 * Preview a `write` call: the current file against the content being written.
 *
 * @param {{before?: string, after?: string, path?: string}} input
 * @returns {string} empty string when there is nothing useful to show
 */
export function writePreview(input) {
  const after = input?.after;
  if (typeof after !== 'string') return '';
  const path = typeof input?.path === 'string' ? input.path : '文件';
  const newLines = lines(after);
  const before = input?.before;

  if (typeof before !== 'string') {
    return clamp(`新建 ${path}：${newLines.length} 行\n${head(newLines, '+')}`);
  }

  const oldLines = lines(before);
  const delta = newLines.length - oldLines.length;
  const sign = delta >= 0 ? `+${delta}` : String(delta);
  const parts = [`改写 ${path}：${oldLines.length} → ${newLines.length} 行（${sign}）`];

  // Identical content is worth saying out loud: a "write" that changes nothing
  // is often a model mistake.
  if (before === after) return `改写 ${path}：内容与当前完全相同（${newLines.length} 行）`;

  parts.push(`--- 原\n${head(oldLines, '-')}`);
  parts.push(`+++ 新\n${head(newLines, '+')}`);
  return clamp(parts.join('\n'));
}

/**
 * Preview an `edit` call: the exact fragment being replaced.
 *
 * @param {{oldString?: string, newString?: string, replaceAll?: boolean, path?: string}} input
 * @returns {string}
 */
export function editPreview(input) {
  const oldString = input?.oldString;
  const newString = input?.newString;
  if (typeof oldString !== 'string' && typeof newString !== 'string') return '';
  const path = typeof input?.path === 'string' ? input.path : '文件';
  const scope = input?.replaceAll === true ? '全部匹配' : '一处匹配';
  const parts = [`编辑 ${path}（${scope}）`];

  if (typeof oldString === 'string' && oldString !== '') {
    parts.push(`--- 删\n${head(lines(oldString), '-')}`);
  }
  if (typeof newString === 'string' && newString !== '') {
    parts.push(`+++ 增\n${head(lines(newString), '+')}`);
  }
  if (typeof oldString === 'string' && oldString === newString) {
    parts.push('（新旧内容相同）');
  }
  return clamp(parts.join('\n'));
}

/**
 * Build the preview for one tool call, or '' when the tool is not a file write.
 *
 * @param {{name?: string, arguments?: object}} exec
 * @param {(path: string) => string} readFile bounded file read supplied by the caller
 * @returns {string}
 */
export function previewFor(exec, readFile) {
  const args = exec?.arguments;
  if (typeof args !== 'object' || args === null) return '';
  const path = typeof args.file_path === 'string' ? args.file_path : (typeof args.path === 'string' ? args.path : undefined);
  if (exec.name === 'write') {
    const before = path === undefined ? undefined : readFile(path);
    return writePreview({ before, after: args.content, path });
  }
  if (exec.name === 'edit') {
    return editPreview({
      oldString: args.old_string,
      newString: args.new_string,
      replaceAll: args.replace_all,
      path,
    });
  }
  return '';
}

export { MAX_READ_BYTES };
