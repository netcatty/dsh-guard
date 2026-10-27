// Browser half of dsh-guard: the 权限守卫 tab inside 设置 → 内置插件.
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

    const C = {
      text: 'var(--dsh-text-primary, #111827)',
      dim: 'var(--dsh-text-secondary, #6b7280)',
      line: 'var(--dsh-border, #e5e7eb)',
      surface: 'var(--dsh-surface, #ffffff)',
      soft: 'var(--dsh-surface-muted, #f9fafb)',
      accent: 'var(--dsh-accent, #2563eb)',
      ok: '#16794a',
      okBg: '#e7f6ee',
      warn: '#8a5a00',
      warnBg: '#fff4d6',
      bad: '#b3261e',
      badBg: '#fdecea',
    };

    const mono = 'ui-monospace, SFMono-Regular, Menlo, monospace';

    // One column geometry for every card, so the two parameter cards line up.
    const GRID = '196px 168px minmax(0, 1fr)';
    const GRID_SWITCH = '196px 38px minmax(0, 1fr)';

    const styles = {
      wrap: { display: 'flex', flexDirection: 'column', gap: 14, padding: '2px 0 8px' },
      head: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' },
      titleRow: { display: 'flex', alignItems: 'center', gap: 10 },
      title: { fontSize: 17, fontWeight: 650, color: C.text, letterSpacing: '-0.01em' },
      titleCode: { fontSize: 11, color: C.dim, fontFamily: mono },
      subtitle: { fontSize: 11.5, color: C.dim, marginTop: 4, fontFamily: mono, wordBreak: 'break-all' },
      pill: (tone) => ({
        display: 'inline-flex', alignItems: 'center', gap: 6, height: 24, padding: '0 10px',
        borderRadius: 999, fontSize: 11.5, fontWeight: 600, whiteSpace: 'nowrap',
        color: tone === 'ok' ? C.ok : tone === 'warn' ? C.warn : C.dim,
        background: tone === 'ok' ? C.okBg : tone === 'warn' ? C.warnBg : C.soft,
        border: `1px solid ${tone === 'ok' ? '#bfe6cf' : tone === 'warn' ? '#f0dfae' : C.line}`,
      }),
      card: {
        border: `1px solid ${C.line}`, borderRadius: 12, padding: '14px 16px 6px',
        background: C.surface, boxShadow: '0 1px 2px rgba(15,23,42,0.03)',
      },
      cardHead: {
        display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10,
        paddingBottom: 10, borderBottom: `1px solid ${C.soft}`,
      },
      cardTitle: { fontSize: 12.5, fontWeight: 650, color: C.text },
      cardHint: { fontSize: 11, color: C.dim, marginLeft: 'auto' },
      row: {
        display: 'grid', gridTemplateColumns: GRID,
        alignItems: 'center', gap: 12, minHeight: 38, paddingBottom: 4,
      },
      rowSwitch: {
        display: 'grid', gridTemplateColumns: GRID_SWITCH,
        alignItems: 'center', gap: 12, minHeight: 38, paddingBottom: 4,
      },
      label: { display: 'flex', alignItems: 'baseline', gap: 6, minWidth: 0 },
      labelZh: { fontSize: 12.5, color: C.text, whiteSpace: 'nowrap' },
      labelCode: { fontSize: 10.5, color: C.dim, fontFamily: mono, whiteSpace: 'nowrap' },
      note: {
        fontSize: 11, color: C.dim, lineHeight: 1.5,
        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
      },
      input: {
        width: '100%', minWidth: 0, maxWidth: '100%', boxSizing: 'border-box',
        padding: '5px 8px', fontSize: 12, color: C.text,
        border: `1px solid ${C.line}`, borderRadius: 7, background: C.surface,
        fontVariantNumeric: 'tabular-nums', textAlign: 'right',
      },
      select: {
        width: '100%', minWidth: 0, maxWidth: '100%', boxSizing: 'border-box',
        padding: '5px 26px 5px 8px', fontSize: 12, color: C.text,
        border: `1px solid ${C.line}`, borderRadius: 7, background: C.surface,
        // Right-align the selected value so it lines up with the numbers above
        // it; the extra right padding keeps the arrow clear of the text.
        textAlign: 'right',
      },
      // A native <select> popup is drawn by the OS and cannot be styled, which is
      // why this panel draws its own list. The trigger mirrors the number inputs;
      // the panel is absolutely positioned under it.
      trigger: {
        width: '100%', boxSizing: 'border-box', display: 'flex', alignItems: 'center', gap: 6,
        padding: '5px 8px', fontSize: 12, color: C.text, cursor: 'pointer',
        border: `1px solid ${C.line}`, borderRadius: 7, background: C.surface,
      },
      caret: { fontSize: 9, color: C.dim, lineHeight: 1, flex: '0 0 auto' },
      menu: {
        position: 'absolute', top: 'calc(100% + 4px)', right: 0, minWidth: '100%',
        background: C.surface, border: `1px solid ${C.line}`, borderRadius: 8,
        boxShadow: '0 10px 28px rgba(15,23,42,0.14)', padding: 4, zIndex: 60,
        display: 'flex', flexDirection: 'column', gap: 1,
      },
      menuItem: (active, align) => ({
        display: 'block', width: '100%', boxSizing: 'border-box',
        padding: '6px 10px', fontSize: 12, border: 'none', borderRadius: 6,
        cursor: 'pointer', textAlign: align, whiteSpace: 'nowrap',
        background: active ? '#eef2ff' : 'transparent',
        color: active ? C.accent : C.text,
        fontWeight: active ? 600 : 400,
      }),
      inlineRow: { display: 'flex', alignItems: 'center', gap: 10, paddingBottom: 12, flexWrap: 'wrap' },
      button: {
        border: `1px solid ${C.line}`, borderRadius: 7, background: C.surface,
        padding: '5px 12px', fontSize: 12, cursor: 'pointer', color: C.text, whiteSpace: 'nowrap',
      },
      buttonPrimary: {
        border: `1px solid ${C.accent}`, borderRadius: 7, background: C.accent,
        padding: '5px 12px', fontSize: 12, cursor: 'pointer', color: '#fff', fontWeight: 600, whiteSpace: 'nowrap',
      },
      listRow: {
        display: 'flex', alignItems: 'center', gap: 8, minHeight: 26,
        fontSize: 12, color: C.text, borderBottom: `1px solid ${C.soft}`, paddingBottom: 4, marginBottom: 4,
      },
      listRowLast: { display: 'flex', alignItems: 'center', gap: 8, minHeight: 26, fontSize: 12, color: C.text, paddingBottom: 2 },
      listCard: { padding: '14px 16px 14px' },
      mono: { fontFamily: mono },
      dim: { color: C.dim },
      empty: { fontSize: 12, color: C.dim, padding: '6px 0' },
      error: {
        color: C.bad, background: C.badBg, border: '1px solid #f5c2c0',
        borderRadius: 8, padding: '8px 10px', fontSize: 12,
      },
      badge: (state) => {
        const tone = state === 'deny' ? { c: C.bad, b: C.badBg } : state === 'ask' ? { c: C.warn, b: C.warnBg } : { c: C.ok, b: C.okBg };
        return {
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 52, height: 20, borderRadius: 999, padding: 0,
          fontSize: 10.5, fontWeight: 700, letterSpacing: '0.02em', color: tone.c, background: tone.b,
          flex: '0 0 auto',
        };
      },
    };

    const PRESET_LABEL = { baseline: '基线', strict: '严格', off: '仅审计' };

    function Label({ zh, code }) {
      return e('span', { style: styles.label }, [
        e('span', { key: 'z', style: styles.labelZh }, zh),
        e('span', { key: 'c', style: styles.labelCode }, code),
      ]);
    }

    function Switch({ checked, disabled, onChange }) {
      return e('button', {
        type: 'button',
        role: 'switch',
        'aria-checked': checked === true,
        disabled,
        onClick: () => onChange(!checked),
        style: {
          width: 38, height: 22, borderRadius: 999, border: 'none', padding: 0,
          position: 'relative', flex: '0 0 auto',
          background: checked ? C.accent : '#cbd5e1',
          cursor: disabled ? 'not-allowed' : 'pointer',
          opacity: disabled ? 0.6 : 1,
          transition: 'background 120ms ease',
        },
      }, e('span', {
        style: {
          position: 'absolute', top: 3, left: checked ? 19 : 3,
          width: 16, height: 16, borderRadius: '50%', background: '#fff',
          boxShadow: '0 1px 2px rgba(15,23,42,0.28)',
          transition: 'left 120ms ease',
        },
      }));
    }

    function SwitchRow({ zh, code, hint, value, disabled, onChange }) {
      return e('div', { style: styles.rowSwitch }, [
        e(Label, { key: 'l', zh, code }),
        e('span', { key: 's' }, e(Switch, { checked: value === true, disabled, onChange })),
        e('span', { key: 'h', style: styles.note, title: hint }, hint),
      ]);
    }

    // Native <select> popups are OS-drawn, so their item spacing, hover colour
    // and radius can never match the panel. This trigger/panel pair can.
    function Select({ value, options, disabled, onChange, align = 'right', boxStyle }) {
      const [open, setOpen] = React.useState(false);
      const boxRef = React.useRef(null);

      React.useEffect(() => {
        if (!open) return undefined;
        const onDown = (event) => {
          if (boxRef.current !== null && !boxRef.current.contains(event.target)) setOpen(false);
        };
        const onKey = (event) => { if (event.key === 'Escape') setOpen(false); };
        document.addEventListener('mousedown', onDown);
        document.addEventListener('keydown', onKey);
        return () => {
          document.removeEventListener('mousedown', onDown);
          document.removeEventListener('keydown', onKey);
        };
      }, [open]);

      const current = options.find((option) => option.value === value);
      const justify = align === 'right' ? 'flex-end' : 'flex-start';

      return e('div', { ref: boxRef, style: { position: 'relative', ...(boxStyle ?? { width: '100%', minWidth: 0 }) } }, [
        e('button', {
          key: 't',
          type: 'button',
          disabled,
          onClick: () => setOpen((was) => !was),
          style: {
            ...styles.trigger,
            justifyContent: justify,
            opacity: disabled ? 0.6 : 1,
            cursor: disabled ? 'not-allowed' : 'pointer',
          },
        }, [
          e('span', { key: 'v', style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, current?.label ?? value),
          e('span', { key: 'c', style: styles.caret }, '▼'),
        ]),
        open
          ? e('div', { key: 'm', style: styles.menu, role: 'listbox' }, options.map((option) => e('button', {
            key: option.value,
            type: 'button',
            role: 'option',
            'aria-selected': option.value === value,
            onClick: () => {
              setOpen(false);
              if (option.value !== value) onChange(option.value);
            },
            style: styles.menuItem(option.value === value, align),
            onMouseEnter: (event) => { event.currentTarget.style.background = option.value === value ? '#e0e7ff' : C.soft; },
            onMouseLeave: (event) => { event.currentTarget.style.background = option.value === value ? '#eef2ff' : 'transparent'; },
          }, option.label)))
          : null,
      ]);
    }

    // Non-controlled input: the committed value comes back through `load()`, so
    // the field is keyed by that value to force a remount after a save.
    function NumberField({ zh, code, hint, value, min, disabled, onCommit }) {
      return e('div', { style: styles.row }, [
        e(Label, { key: 'l', zh, code }),
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
        e('span', { key: 'h', style: styles.note, title: hint }, hint),
      ]);
    }

    function Card({ title, hint, children, list }) {
      return e('div', { style: list === true ? { ...styles.card, ...styles.listCard } : styles.card }, [
        e('div', { key: 'h', style: styles.cardHead }, [
          e('span', { key: 't', style: styles.cardTitle }, title),
          hint === undefined ? null : e('span', { key: 'n', style: styles.cardHint }, hint),
        ]),
        e('div', { key: 'b' }, children),
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

      const post = React.useCallback(async (path, payload) => {
        setBusy(true);
        try {
          const response = await fetch(path, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
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

      const save = React.useCallback((patch) => post('/api/dsh-guard/config', { patch }), [post]);
      const applyPreset = React.useCallback((name) => post('/api/dsh-guard/preset', { name }), [post]);

      React.useEffect(() => { load(); }, [load]);
      return { state, error, busy, load, save, applyPreset };
    }

    function GuardTab() {
      const { state, error, busy, save, applyPreset, load } = useGuardState();
      const [preset, setPreset] = React.useState('baseline');

      if (state === null) {
        return e('div', { style: styles.wrap }, [
          e('div', { key: 't', style: styles.title }, '权限守卫'),
          e('div', { key: 'h', style: styles.note }, error === '' ? '读取中…' : `读取失败：${error}`),
        ]);
      }

      const config = state.config ?? {};
      const presets = Array.isArray(state.presets) ? state.presets : [];
      const presetLines = presets.map((line) => {
        const parts = String(line).trim().split(/\s+/u);
        return { name: parts[0] ?? '', desc: parts.slice(1).join(' ') };
      }).filter((entry) => entry.name !== '');
      const currentPreset = presetLines.find((entry) => entry.name === preset);
      const recent = Array.isArray(state.recentDecisions) ? state.recentDecisions : [];
      const snapshots = Array.isArray(state.snapshots) ? state.snapshots : [];
      const enforcing = config.enforce !== false;

      return e('div', { style: styles.wrap }, [
        e('div', { key: 'head', style: styles.head }, [
          e('div', { key: 'l' }, [
            e('div', { key: 't', style: styles.titleRow }, [
              e('span', { key: 'n', style: styles.title }, '权限守卫'),
              e('span', { key: 'c', style: styles.titleCode }, 'dsh-guard'),
              e('span', { key: 'p', style: styles.pill(enforcing ? 'ok' : 'warn') }, enforcing ? '拦截生效' : '仅审计'),
              e('span', { key: 'r', style: styles.pill(config.repeatLimit > 0 ? 'ok' : 'muted') },
                config.repeatLimit > 0 ? `循环检测 ${config.repeatLimit}` : '循环检测关闭'),
            ]),
            e('div', { key: 's', style: styles.subtitle }, `策略：${state.policyPath ?? ''}`),
          ]),
          e('button', { key: 'r', style: styles.button, disabled: busy, onClick: () => load() }, busy ? '刷新中…' : '刷新'),
        ]),

        e(Card, { key: 'switches', title: '总开关', hint: '改动立即生效', list: true },
          e('div', {}, [
            e(SwitchRow, {
              key: 'enforce', zh: '拦截开关', code: 'enforce', value: config.enforce, disabled: busy,
              hint: '关闭后只审计不拦截', onChange: (value) => save({ enforce: value }),
            }),
            e(SwitchRow, {
              key: 'yolo', zh: '自动放行', code: 'yolo', value: config.yolo, disabled: busy,
              hint: '把询问当放行，拒绝仍然生效', onChange: (value) => save({ yolo: value }),
            }),
            e(SwitchRow, {
              key: 'snapshots', zh: '写前快照', code: 'snapshots', value: config.snapshots, disabled: busy,
              hint: '改文件前备份，可回滚', onChange: (value) => save({ snapshots: value }),
            }),
            e(SwitchRow, {
              key: 'audit', zh: '审计日志', code: 'audit', value: config.audit, disabled: busy,
              hint: '每次判定写入 audit.jsonl', onChange: (value) => save({ audit: value }),
            }),
          ])),

        e(Card, { key: 'repeat', title: '循环检测', hint: '同一调用反复执行时提醒' },
          e('div', {}, [
            e(NumberField, {
              key: 'limit', zh: '触发次数', code: 'repeatLimit', min: 0, value: config.repeatLimit,
              hint: '0 = 关闭', disabled: busy,
              onCommit: (value) => save({ repeatLimit: value }),
            }),
            e(NumberField, {
              key: 'window', zh: '检测窗口', code: 'repeatWindowMs', min: 1, value: config.repeatWindowMs,
              hint: '毫秒', disabled: busy,
              onCommit: (value) => save({ repeatWindowMs: value }),
            }),
            e('div', { key: 'action', style: styles.row }, [
              e(Label, { key: 'l', zh: '超限处置', code: 'repeatAction' }),
              e(Select, {
                key: 's', disabled: busy, value: config.repeatAction ?? 'ask', align: 'right',
                options: ['allow', 'ask', 'deny'].map((option) => ({ value: option, label: option })),
                onChange: (value) => save({ repeatAction: value }),
              }),
              e('span', { key: 'h', style: styles.note }, '超限后如何处理'),
            ]),
          ])),

        e(Card, { key: 'storage', title: '快照与审计', hint: '容量与轮转' },
          e('div', {}, [
            e(NumberField, {
              key: 'files', zh: '快照文件数', code: 'snapshotMaxFiles', min: 0, value: config.snapshotMaxFiles,
              hint: '单次最多几个', disabled: busy,
              onCommit: (value) => save({ snapshotMaxFiles: value }),
            }),
            e(NumberField, {
              key: 'bytes', zh: '单文件上限', code: 'snapshotMaxBytes', min: 0, value: config.snapshotMaxBytes,
              hint: '字节，超出跳过', disabled: busy,
              onCommit: (value) => save({ snapshotMaxBytes: value }),
            }),
            e(NumberField, {
              key: 'retain', zh: '保留份数', code: 'snapshotRetain', min: 0, value: config.snapshotRetain,
              hint: '最旧的先删', disabled: busy,
              onCommit: (value) => save({ snapshotRetain: value }),
            }),
            e(NumberField, {
              key: 'audit', zh: '审计轮转', code: 'auditMaxBytes', min: 0, value: config.auditMaxBytes,
              hint: '超出后滚动到 .1', disabled: busy,
              onCommit: (value) => save({ auditMaxBytes: value }),
            }),
          ])),

        e(Card, { key: 'preset', title: '预设模板', hint: '合并进当前策略，不替换' },
          e('div', { style: styles.inlineRow }, [
            e(Select, {
              key: 's', disabled: busy, value: preset, align: 'left',
              boxStyle: { position: 'relative', width: 'auto', minWidth: 132, flex: '0 0 auto' },
              options: presetLines.map((entry) => ({ value: entry.name, label: PRESET_LABEL[entry.name] ?? entry.name })),
              onChange: setPreset,
            }),
            e('button', {
              key: 'b', style: styles.buttonPrimary, disabled: busy,
              onClick: () => applyPreset(preset),
            }, '应用'),
            e('span', { key: 'h', style: { ...styles.note, flex: '1 1 240px' } }, currentPreset?.desc ?? ''),
          ])),

        e(Card, { key: 'recent', title: '最近判定', hint: `${recent.length} 条`, list: true },
          recent.length === 0
            ? e('div', { style: styles.empty }, '暂无记录')
            : e('div', {}, recent.map((row, index) => e('div', {
              key: `${row.at}-${index}`,
              style: index === recent.length - 1 ? styles.listRowLast : styles.listRow,
            }, [
              e('span', { key: 's', style: styles.badge(row.state) }, row.state),
              e('span', { key: 't', style: styles.mono }, row.tool),
              e('span', { key: 'p', style: { ...styles.mono, ...styles.dim } }, row.pattern ?? ''),
              e('span', { key: 'd', style: { ...styles.dim, marginLeft: 'auto', fontSize: 11 } },
                row.at === undefined ? '' : String(row.at).slice(11, 19)),
            ])))),

        e(Card, {
          key: 'snapshots',
          title: '可回滚快照',
          hint: snapshots.length === 0 ? '' : `${snapshots.length} 条 · 用 /guard-undo 回滚`,
          list: true,
        },
          snapshots.length === 0
            ? e('div', { style: styles.empty }, '暂无快照')
            : e('div', {}, snapshots.map((entry, index) => e('div', {
              key: entry.id,
              style: index === snapshots.length - 1 ? styles.listRowLast : styles.listRow,
            }, [
              e('span', { key: 't', style: styles.mono }, entry.tool ?? 'tool'),
              e('span', { key: 'p', style: { ...styles.mono, ...styles.dim } },
                (entry.paths ?? []).map((path) => String(path).split('/').pop()).join(', ')),
              e('span', { key: 'd', style: { ...styles.dim, marginLeft: 'auto', fontSize: 11 } },
                entry.at === undefined ? '' : String(entry.at).slice(11, 19)),
            ])))),

        error === '' ? null : e('div', { key: 'err', style: styles.error }, error),
      ]);
    }

    async function apply(ctx) {
      ctx.slots.inject('settings.plugins.tab', () => ctx.slots.register({
        name: 'settings.plugins.tab',
        id: 'guard',
        order: 45,
        label: () => '权限守卫',
        inject: () => ({}),
      }, GuardTab));
    }

    const module = { exports: { name: 'dsh-guard', inject: ['slots'], apply } };
    return module.exports;
  },
});
