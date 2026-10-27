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
      field: '#dfe3e8',
      fieldBg: '#fbfcfd',
      focusRing: 'rgba(37,99,235,0.14)',
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
        padding: '6px 9px', fontSize: 12, color: C.text,
        border: `1px solid ${C.field}`, borderRadius: 8, background: C.fieldBg,
        fontVariantNumeric: 'tabular-nums', textAlign: 'right',
        // The native spinner sits right against the digits and gives every field
        // a different content width, so the numbers stop lining up. Hide it.
        appearance: 'textfield',
        WebkitAppearance: 'none',
        MozAppearance: 'textfield',
        transition: 'border-color 120ms ease, box-shadow 120ms ease, background 120ms ease',
      },
      // A native <select> popup is drawn by the OS and cannot be styled, which is
      // why this panel draws its own list. The trigger mirrors the number inputs;
      // the panel is absolutely positioned under it.
      trigger: {
        width: '100%', boxSizing: 'border-box', display: 'flex', alignItems: 'center', gap: 6,
        padding: '6px 9px', fontSize: 12, color: C.text, cursor: 'pointer',
        border: `1px solid ${C.field}`, borderRadius: 8, background: C.fieldBg,
        transition: 'border-color 120ms ease, box-shadow 120ms ease, background 120ms ease',
      },
      caret: { fontSize: 8, color: C.dim, lineHeight: 1, flex: '0 0 auto' },
      menu: {
        position: 'absolute', top: 'calc(100% + 6px)', minWidth: '100%',
        // Without border-box the padding + border make the panel wider than its
        // trigger, so its leading edge sticks out.
        boxSizing: 'border-box',
        background: C.surface, border: `1px solid ${C.line}`, borderRadius: 10,
        boxShadow: '0 12px 32px rgba(15,23,42,0.16), 0 2px 6px rgba(15,23,42,0.06)',
        padding: 5, zIndex: 60,
        display: 'flex', flexDirection: 'column', gap: 1,
      },
      menuItem: (active) => ({
        display: 'flex', alignItems: 'center', gap: 10,
        justifyContent: 'flex-start',
        width: '100%', boxSizing: 'border-box',
        padding: '7px 10px', fontSize: 12, border: 'none', borderRadius: 7,
        cursor: 'pointer', whiteSpace: 'nowrap',
        background: active ? '#eef2ff' : 'transparent',
        color: active ? C.accent : C.text,
        fontWeight: active ? 600 : 400,
        transition: 'background 100ms ease',
      }),
      check: { fontSize: 11, color: C.accent, flex: '0 0 auto', width: 12, textAlign: 'center' },
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
      // Both dropdowns put the value on the left and the caret on the right, so
      // the parameter picker and the preset picker look like the same control.
      const justify = 'space-between';

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
            borderColor: open ? C.accent : C.field,
            background: open ? C.surface : C.fieldBg,
            boxShadow: open ? `0 0 0 3px ${C.focusRing}` : 'none',
          },
        }, [
          e('span', { key: 'v', style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, current?.label ?? value),
          e('span', { key: 'c', style: styles.caret }, '▼'),
        ]),
        open
          ? e('div', { key: 'm', style: { ...styles.menu, ...(align === 'right' ? { right: 0 } : { left: 0 }) }, role: 'listbox' }, options.map((option) => e('button', {
            key: option.value,
            type: 'button',
            role: 'option',
            'aria-selected': option.value === value,
            onClick: () => {
              setOpen(false);
              if (option.value !== value) onChange(option.value);
            },
            style: styles.menuItem(option.value === value),
            onMouseEnter: (event) => { event.currentTarget.style.background = option.value === value ? '#e0e7ff' : C.soft; },
            onMouseLeave: (event) => { event.currentTarget.style.background = option.value === value ? '#eef2ff' : 'transparent'; },
          }, [
            // Every row reserves the check column, so selected and unselected
            // labels start at the same x.
            e('span', { key: 'k', style: styles.check }, option.value === value ? '✓' : ''),
            e('span', { key: 'l' }, option.label),
          ])))
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
          onFocus: (event) => {
            event.target.style.borderColor = C.accent;
            event.target.style.background = C.surface;
            event.target.style.boxShadow = `0 0 0 3px ${C.focusRing}`;
          },
          onBlur: (event) => {
            event.target.style.borderColor = C.field;
            event.target.style.background = C.fieldBg;
            event.target.style.boxShadow = 'none';
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
              boxStyle: { position: 'relative', width: 168, flex: '0 0 auto' },
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

    // Side-by-side rows for the dialog: common prefix/suffix stay aligned and the
    // middle is paired positionally. Mirrors lib/diff-view.js without importing
    // server code into the browser bundle.
    function pairRows(before, after) {
      const a = String(before ?? '').split('\n');
      const b = String(after ?? '').split('\n');
      let head = 0;
      while (head < a.length && head < b.length && a[head] === b[head]) head += 1;
      let tailA = a.length - 1;
      let tailB = b.length - 1;
      while (tailA >= head && tailB >= head && a[tailA] === b[tailB]) { tailA -= 1; tailB -= 1; }
      const rows = [];
      for (let index = 0; index < head; index += 1) rows.push({ left: a[index], right: b[index], kind: 'same' });
      const middle = Math.max(tailA - head + 1, tailB - head + 1);
      for (let index = 0; index < middle; index += 1) {
        const left = head + index <= tailA ? a[head + index] : null;
        const right = head + index <= tailB ? b[head + index] : null;
        const kind = left === right ? 'same' : left === null ? 'add' : right === null ? 'del' : 'change';
        rows.push({ left, right, kind });
      }
      for (let index = 0; tailA + 1 + index < a.length; index += 1) {
        const left = a[tailA + 1 + index];
        const right = b[tailB + 1 + index];
        rows.push({ left, right, kind: left === right ? 'same' : 'change' });
      }
      return rows;
    }

    const overlayStyles = {
      backdrop: { position: 'fixed', inset: 0, background: 'rgba(15,23,42,0.42)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '4vh 16px', zIndex: 900, overflowY: 'auto' },
      card: { width: 'min(940px, 100%)', background: '#fff', borderRadius: 14, boxShadow: '0 24px 60px rgba(15,23,42,0.32)', padding: '18px 20px 16px', fontFamily: 'system-ui, -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif' },
      header: { display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 4 },
      eyebrow: { fontSize: 11, color: '#6b7280', letterSpacing: '0.04em' },
      title: { fontSize: 16, fontWeight: 650, margin: 0, color: '#111827' },
      rule: { fontSize: 12, color: '#6b7280', marginBottom: 12, fontFamily: 'ui-monospace, Menlo, monospace' },
      table: { width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed', fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 12, maxHeight: 340, overflow: 'auto', display: 'block', border: '1px solid #e5e7eb', borderRadius: 8 },
      th: { position: 'sticky', top: 0, background: '#f9fafb', padding: '5px 8px', textAlign: 'left', fontSize: 11, color: '#6b7280', borderBottom: '1px solid #e5e7eb' },
      td: { padding: '1px 8px', verticalAlign: 'top', whiteSpace: 'pre-wrap', wordBreak: 'break-word', borderBottom: '1px solid #f3f4f6' },
      num: { width: 40, textAlign: 'right', color: '#9ca3af', background: '#fafafa', userSelect: 'none' },
      actions: { display: 'flex', gap: 8, marginTop: 14, flexWrap: 'wrap' },
      primary: { border: '1px solid #2563eb', background: '#2563eb', color: '#fff', borderRadius: 8, padding: '6px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer' },
      secondary: { border: '1px solid #e5e7eb', background: '#fff', color: '#111827', borderRadius: 8, padding: '6px 14px', fontSize: 12, cursor: 'pointer' },
      danger: { border: '1px solid #f5c2c0', background: '#fdecea', color: '#b3261e', borderRadius: 8, padding: '6px 14px', fontSize: 12, cursor: 'pointer' },
      error: { color: '#b3261e', fontSize: 12, marginTop: 8 },
    };

    function rowStyle(kind, side) {
      if (kind === 'same') return { background: 'transparent', color: '#6b7280' };
      if (side === 'left' && (kind === 'del' || kind === 'change')) return { background: '#fdecea', color: '#8a1f1a' };
      if (side === 'right' && (kind === 'add' || kind === 'change')) return { background: '#e7f6ee', color: '#0f5c37' };
      return { background: '#fafafa', color: '#9ca3af' };
    }

    function ApprovalOverlay() {
      const [items, setItems] = React.useState([]);
      const [error, setError] = React.useState('');

      React.useEffect(() => {
        let alive = true;
        let lastId = '';
        const tick = async () => {
          try {
            const response = await fetch('/api/dsh-guard/pending', { headers: { accept: 'application/json' } });
            if (!response.ok) return;
            const body = await response.json();
            if (!alive) return;
            const next = Array.isArray(body.pending) ? body.pending : [];
            const nextId = next.map((item) => item.id).join(',');
            if (nextId !== lastId) { lastId = nextId; setItems(next); }
          } catch {
            // A transient poll failure must not clear a visible dialog.
          }
        };
        tick();
        const timer = setInterval(tick, 1500);
        return () => { alive = false; clearInterval(timer); };
      }, []);

      const decide = React.useCallback(async (id, choice, reason) => {
        try {
          const response = await fetch('/api/dsh-guard/decide', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ id, choice, reason }),
          });
          if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            setError(body.error ?? '提交失败');
            return;
          }
          setItems((current) => current.filter((item) => item.id !== id));
        } catch (problem) {
          setError(problem instanceof Error ? problem.message : String(problem));
        }
      }, []);

      if (items.length === 0) return null;
      const item = items[0];
      const rows = pairRows(item.before, item.after).slice(0, 400);

      return e('div', { style: overlayStyles.backdrop }, e('div', { style: overlayStyles.card }, [
        e('div', { key: 'h', style: overlayStyles.header }, [
          e('span', { key: 'e', style: overlayStyles.eyebrow }, '权限守卫'),
          e('span', { key: 't', style: overlayStyles.title }, `允许 ${item.tool} 执行吗？`),
        ]),
        e('div', { key: 'r', style: overlayStyles.rule }, `规则：${item.pattern}${item.path ? '  ·  ' + item.path : ''}`),
        item.before === null && item.after === null ? null : e('div', { key: 'd', style: overlayStyles.table }, [
          e('div', { key: 'head', style: { display: 'flex' } }, [
            e('span', { key: 'n', style: { ...overlayStyles.th, ...overlayStyles.num } }),
            e('span', { key: 'l', style: { ...overlayStyles.th, width: '50%' } }, '原'),
            e('span', { key: 'r2', style: { ...overlayStyles.th, width: '50%' } }, '新'),
          ]),
          ...rows.map((row, index) => e('div', { key: index, style: { display: 'flex' } }, [
            e('span', { key: 'n', style: { ...overlayStyles.td, ...overlayStyles.num } }, index + 1),
            e('span', { key: 'l', style: { ...overlayStyles.td, width: '50%', ...rowStyle(row.kind, 'left') } }, row.left ?? ''),
            e('span', { key: 'r2', style: { ...overlayStyles.td, width: '50%', ...rowStyle(row.kind, 'right') } }, row.right ?? ''),
          ])),
        ]),
        e('div', { key: 'a', style: overlayStyles.actions }, [
          e('button', { key: '1', style: overlayStyles.primary, onClick: () => decide(item.id, 'allow') }, '允许一次'),
          e('button', { key: '2', style: overlayStyles.secondary, onClick: () => decide(item.id, 'session') }, '本会话允许'),
          item.canPersist ? e('button', { key: '3', style: overlayStyles.secondary, onClick: () => decide(item.id, 'persist') }, '写入项目规则') : null,
          e('button', { key: '4', style: overlayStyles.danger, onClick: () => decide(item.id, 'deny', '用户拒绝') }, '拒绝'),
        ]),
        error === '' ? null : e('div', { key: 'err', style: overlayStyles.error }, error),
      ]));
    }

    async function apply(ctx) {
      ctx.slots.inject('settings.plugins.tab', () => ctx.slots.register({
        name: 'settings.plugins.tab',
        id: 'guard',
        order: 45,
        label: () => '权限守卫',
        inject: () => ({}),
      }, GuardTab));
      // The approval overlay is global: it must appear wherever the user is,
      // not only inside the settings tab. Slots are page-relative, so this mounts
      // on document.body instead. react-dom is optional; without it the dialog
      // channel simply stays idle and pre-execute falls back after 10s.
      try {
        const ReactDOM = require('react-dom/client');
        if (ReactDOM !== null && typeof ReactDOM.createRoot === 'function' && typeof document !== 'undefined') {
          const host = document.createElement('div');
          host.dataset.plugin = 'dsh-guard-overlay';
          document.body.appendChild(host);
          const root = ReactDOM.createRoot(host);
          root.render(e(ApprovalOverlay));
          ctx.effect(() => () => {
            try { root.unmount(); } catch {}
            try { host.remove(); } catch {}
          });
        }
      } catch (error) {
        console.warn('dsh-guard: approval overlay not mounted', error);
      }
    }

    const module = { exports: { name: 'dsh-guard', inject: ['slots'], apply } };
    return module.exports;
  },
});
