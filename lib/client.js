// Browser half of dsh-guard: a "dsh-guard" tab inside 设置 → 内置插件.
//
// Only switches and scalar knobs are editable here. Rules stay in policy.json —
// they are nested maps with unlimited combinations, and a form that pretended to
// cover them would end up as a JSON textarea anyway. Everything this panel writes
// goes through POST /api/dsh-guard/config, which runs the same validate + backup
// path as `/guard-policy`, so the panel cannot produce a policy a hand edit could
// not.
//
// Hand-written CJS wrapper so the repository still needs no build step.

window.__ModuleLoader__.load({
  id: 'dsh-guard',
  factory: (require) => {
    const React = require('react');
    const e = React.createElement;

    const styles = {
      wrap: { padding: '4px 2px' },
      head: { display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 14, flexWrap: 'wrap' },
      title: { fontSize: 18, fontWeight: 600, color: 'var(--dsh-text-primary, #111827)' },
      hint: { color: 'var(--dsh-text-secondary, #6b7280)', fontSize: 12 },
      card: { border: '1px solid var(--dsh-border, #e5e7eb)', borderRadius: 10, padding: 14, marginBottom: 12, background: 'var(--dsh-surface, #fff)' },
      cardTitle: { fontSize: 13, fontWeight: 600, marginBottom: 10, color: 'var(--dsh-text-primary, #111827)' },
      row: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' },
      rowLabel: { fontSize: 13, minWidth: 150, color: 'var(--dsh-text-primary, #111827)' },
      rowHint: { fontSize: 11, color: 'var(--dsh-text-secondary, #6b7280)' },
      input: { width: 90, padding: '3px 6px', fontSize: 12, border: '1px solid #d1d5db', borderRadius: 6 },
      select: { padding: '3px 6px', fontSize: 12, border: '1px solid #d1d5db', borderRadius: 6 },
      button: { border: '1px solid #d1d5db', borderRadius: 8, background: '#fff', padding: '4px 10px', fontSize: 12, cursor: 'pointer' },
      list: { fontSize: 12, lineHeight: 1.7, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', maxHeight: 200, overflow: 'auto' },
      error: { color: '#b3261e', fontSize: 12, marginTop: 8 },
      badge: (state) => ({
        display: 'inline-block', borderRadius: 999, padding: '1px 8px', fontSize: 11, fontWeight: 600, marginRight: 6,
        color: state === 'deny' ? '#b3261e' : state === 'ask' ? '#8a5a00' : '#16794a',
        background: state === 'deny' ? '#fdecea' : state === 'ask' ? '#fff4d6' : '#e7f6ee',
      }),
    };

    function Toggle({ label, hint, value, disabled, onChange }) {
      return e('div', { style: styles.row }, [
        e('label', { key: 'l', style: styles.rowLabel }, [
          e('input', {
            key: 'i',
            type: 'checkbox',
            checked: value === true,
            disabled,
            onChange: (event) => onChange(event.target.checked),
            style: { marginRight: 6 },
          }),
          label,
        ]),
        hint === undefined ? null : e('span', { key: 'h', style: styles.rowHint }, hint),
      ]);
    }

    // Non-controlled input: the committed value comes back through `load()`, so
    // the field is keyed by that value to force a remount after a save.
    function NumberField({ label, hint, value, min, disabled, onCommit }) {
      return e('div', { style: styles.row }, [
        e('span', { key: 'l', style: styles.rowLabel }, label),
        e('input', {
          key: `i:${String(value)}`,
          type: 'number',
          min,
          style: styles.input,
          disabled,
          defaultValue: value ?? 0,
          onBlur: (event) => {
            const next = Number(event.target.value);
            if (Number.isInteger(next) && next >= min && next !== value) onCommit(next);
            else event.target.value = String(value ?? 0);
          },
        }),
        hint === undefined ? null : e('span', { key: 'h', style: styles.rowHint }, hint),
      ]);
    }

    function useGuardState() {
      const [state, setState] = React.useState(null);
      const [error, setError] = React.useState('');
      const [busy, setBusy] = React.useState(false);

      const load = React.useCallback(async () => {
        try {
          const response = await fetch('/api/dsh-guard/state', { headers: { accept: 'application/json' } });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          setState(await response.json());
          setError('');
        } catch (problem) {
          setError(problem instanceof Error ? problem.message : String(problem));
        }
      }, []);

      const save = React.useCallback(async (patch) => {
        setBusy(true);
        try {
          const response = await fetch('/api/dsh-guard/config', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ patch }),
          });
          const body = await response.json();
          if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`);
          await load();
        } catch (problem) {
          setError(problem instanceof Error ? problem.message : String(problem));
        } finally {
          setBusy(false);
        }
      }, [load]);

      const applyPreset = React.useCallback(async (name) => {
        setBusy(true);
        try {
          const response = await fetch('/api/dsh-guard/preset', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ name }),
          });
          const body = await response.json();
          if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`);
          await load();
        } catch (problem) {
          setError(problem instanceof Error ? problem.message : String(problem));
        } finally {
          setBusy(false);
        }
      }, [load]);

      React.useEffect(() => { load(); }, [load]);
      return { state, error, busy, load, save, applyPreset };
    }

    function GuardTab() {
      const { state, error, busy, save, applyPreset, load } = useGuardState();
      const [preset, setPreset] = React.useState('baseline');

      if (state === null) {
        return e('div', { style: styles.wrap }, [
          e('div', { key: 't', style: styles.title }, 'dsh-guard'),
          e('div', { key: 'h', style: styles.hint }, error === '' ? '读取中…' : `读取失败：${error}`),
        ]);
      }

      const config = state.config ?? {};
      const presets = Array.isArray(state.presets) ? state.presets : [];
      const recent = Array.isArray(state.recentDecisions) ? state.recentDecisions : [];
      const snapshots = Array.isArray(state.snapshots) ? state.snapshots : [];

      return e('div', { style: styles.wrap }, [
        e('div', { key: 'head', style: styles.head }, [
          e('div', { key: 't', style: styles.title }, 'dsh-guard'),
          e('div', { key: 'h', style: styles.hint }, `策略：${state.policyPath ?? ''}`),
        ]),

        e('div', { key: 'switches', style: styles.card }, [
          e('div', { key: 'title', style: styles.cardTitle }, '总开关'),
          e(Toggle, {
            key: 'enforce', label: 'enforce', hint: '关闭后只审计不拦截（试运行）',
            value: config.enforce, disabled: busy, onChange: (value) => save({ enforce: value }),
          }),
          e(Toggle, {
            key: 'yolo', label: 'yolo', hint: '把 ask 全部当 allow，deny 仍然拦截',
            value: config.yolo, disabled: busy, onChange: (value) => save({ yolo: value }),
          }),
          e(Toggle, {
            key: 'snapshots', label: 'snapshots', hint: '写文件前备份，可 /guard-undo 回滚',
            value: config.snapshots, disabled: busy, onChange: (value) => save({ snapshots: value }),
          }),
          e(Toggle, {
            key: 'audit', label: 'audit', hint: '把每次判定写入 audit.jsonl',
            value: config.audit, disabled: busy, onChange: (value) => save({ audit: value }),
          }),
        ]),

        e('div', { key: 'repeat', style: styles.card }, [
          e('div', { key: 'title', style: styles.cardTitle }, '循环检测'),
          e(NumberField, {
            key: 'limit', label: 'repeatLimit', min: 0, value: config.repeatLimit,
            hint: '0 = 关闭；同一调用第 N 次触发', disabled: busy,
            onCommit: (value) => save({ repeatLimit: value }),
          }),
          e(NumberField, {
            key: 'window', label: 'repeatWindowMs', min: 1, value: config.repeatWindowMs,
            hint: '滚动窗口（毫秒）', disabled: busy,
            onCommit: (value) => save({ repeatWindowMs: value }),
          }),
          e('div', { key: 'action', style: styles.row }, [
            e('span', { key: 'l', style: styles.rowLabel }, 'repeatAction'),
            e('select', {
              key: 's', style: styles.select, disabled: busy, value: config.repeatAction ?? 'ask',
              onChange: (event) => save({ repeatAction: event.target.value }),
            }, ['allow', 'ask', 'deny'].map((option) => e('option', { key: option, value: option }, option))),
          ]),
        ]),

        e('div', { key: 'storage', style: styles.card }, [
          e('div', { key: 'title', style: styles.cardTitle }, '快照与审计'),
          e(NumberField, {
            key: 'files', label: 'snapshotMaxFiles', min: 0, value: config.snapshotMaxFiles,
            hint: '单次调用最多快照几个文件', disabled: busy,
            onCommit: (value) => save({ snapshotMaxFiles: value }),
          }),
          e(NumberField, {
            key: 'bytes', label: 'snapshotMaxBytes', min: 0, value: config.snapshotMaxBytes,
            hint: '单文件字节上限，超出标记 skipped', disabled: busy,
            onCommit: (value) => save({ snapshotMaxBytes: value }),
          }),
          e(NumberField, {
            key: 'retain', label: 'snapshotRetain', min: 0, value: config.snapshotRetain,
            hint: '保留的快照目录数，最旧的先删', disabled: busy,
            onCommit: (value) => save({ snapshotRetain: value }),
          }),
          e(NumberField, {
            key: 'audit', label: 'auditMaxBytes', min: 0, value: config.auditMaxBytes,
            hint: '审计文件超过后滚动到 .1', disabled: busy,
            onCommit: (value) => save({ auditMaxBytes: value }),
          }),
        ]),

        e('div', { key: 'preset', style: styles.card }, [
          e('div', { key: 'title', style: styles.cardTitle }, '模板'),
          e('div', { key: 'row', style: styles.row }, [
            e('select', {
              key: 's', style: styles.select, disabled: busy,
              value: preset, onChange: (event) => setPreset(event.target.value),
            }, presets.map((line) => {
              const name = String(line).split(/\s+/u)[0];
              return e('option', { key: name, value: name }, line);
            })),
            e('button', {
              key: 'b', style: styles.button, disabled: busy,
              onClick: () => applyPreset(preset),
            }, '应用'),
            e('span', { key: 'h', style: styles.rowHint }, '合并进当前策略，不替换'),
          ]),
        ]),

        e('div', { key: 'recent', style: styles.card }, [
          e('div', { key: 'title', style: styles.cardTitle }, `最近判定（${recent.length}）`),
          e('div', { key: 'list', style: styles.list },
            recent.length === 0
              ? [e('div', { key: 'empty', style: styles.hint }, '暂无记录')]
              : recent.map((row, index) => e('div', { key: `${row.at}-${index}` }, [
                e('span', { key: 's', style: styles.badge(row.state) }, row.state),
                e('span', { key: 't' }, `${row.tool}  ${row.pattern ?? ''}`),
              ]))),
        ]),

        e('div', { key: 'snapshots', style: styles.card }, [
          e('div', { key: 'title', style: styles.cardTitle }, `可回滚快照（${snapshots.length}）`),
          e('div', { key: 'list', style: styles.list },
            snapshots.length === 0
              ? [e('div', { key: 'empty', style: styles.hint }, '暂无快照')]
              : snapshots.map((entry) => e('div', { key: entry.id }, [
                e('span', { key: 't' }, `${entry.tool ?? 'tool'}  `),
                e('span', { key: 'p' }, (entry.paths ?? []).map((path) => path.split('/').pop()).join(', ')),
              ]))),
          e('div', { key: 'h', style: styles.rowHint }, '回滚请用 /guard-undo'),
        ]),

        error === '' ? null : e('div', { key: 'err', style: styles.error }, error),
        e('div', { key: 'actions', style: { marginTop: 8 } }, [
          e('button', { key: 'r', style: styles.button, disabled: busy, onClick: () => load() }, '刷新'),
        ]),
      ]);
    }

    async function apply(ctx) {
      ctx.slots.inject('settings.plugins.tab', () => ctx.slots.register({
        name: 'settings.plugins.tab',
        id: 'guard',
        order: 45,
        label: () => 'dsh-guard',
        inject: () => ({}),
      }, GuardTab));
    }

    const module = { exports: { name: 'dsh-guard', inject: ['slots'], apply } };
    return module.exports;
  },
});
