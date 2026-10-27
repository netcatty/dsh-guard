# dsh-guard

Allow / ask / deny gates for DeepSeek Harness tool calls.

## Install

```sh
git clone git@github.com:netcatty/dsh-guard.git ~/code/dsh-guard
dsh plugin --profile web add link:~/code/dsh-guard
```

No build step: the plugin is plain ESM. On Windows use the clone path, e.g.
`dsh plugin --profile web add link:C:\code\dsh-guard`, then restart `dsh web`.
The repository ships `policy.json`, so rules are versioned with the code and
hot-reload while the plugin is mounted.

## Data directory

Every file the plugin owns lives in one place:

```
$DSH_HOME/dsh-plugins/dsh-guard/policy.json   the live permission policy
$DSH_HOME/dsh-plugins/dsh-guard/audit.jsonl   decision trail (rotates at auditMaxBytes)
$DSH_HOME/dsh-plugins/dsh-guard/status.json   live status projection
$DSH_HOME/dsh-plugins/dsh-guard/snapshots/    pre-write file copies (one dir per call)
```

`$DSH_HOME` defaults to `~/.dsh`. Files written by earlier versions
(`~/.dsh/guard-audit.jsonl`, `~/.dsh/guard-status.json`) move into that
directory once per mount; `auditPath` overrides the audit location.

**The live policy is the data-directory copy.** The repository ships a
`policy.json` too, but only as the seed: on the first mount of a fresh data
directory it is copied to `dsh-plugins/dsh-guard/policy.json`, and from then on
that copy is what runs. Editing the checkout therefore never changes behaviour,
and a `git pull` never overwrites your rules. Deleting the live file falls back
to the shipped seed until you write one again.

## Editing the policy

The file is meant to be read and edited by hand, so it accepts everything strict
JSON refuses:

```jsonc
{
  "$schema": "./policy.schema.json",   // editor completion + validation
  "permission": {
    "*": "allow",
    // destructive commands always ask
    "bash": {
      "git push *": "ask",   /* block comment too */
      "rm -rf /*": "deny",
    },
  },
}
```

- **Comments** — `//` to end of line, `/* … */` anywhere. A `//` inside a string
  or URL is left alone.
- **Trailing commas** — one after the last rule of an object or array is fine.
- **`$schema`** — points an editor at `policy.schema.json` for completion and
  inline validation; the loader strips it before reading rules.
- **Errors stay loud** — anything beyond trivia (unquoted keys, single quotes)
  still fails, and a bad policy fails closed rather than silently applying half
  of it.

Edits hot-reload in about a second. Verify one before trusting it:

```
/guard-test bash {"command":"git push origin main"}
```

Nothing else needs to run: no command writes the policy, no UI owns it.

## Surfaces

| Surface | Applies to | Notes |
|---|---|---|
| `path` | every file tool + bash path tokens | cross-cutting, both directions |
| `pathRead` | `read`, `read_image`, `grep`, `glob` | direction-specific override |
| `pathWrite` | `write`, `edit` | direction-specific override |
| `externalDirectory` | paths outside the session cwd | defaults to allow |
| `bash` | command text | glob, last matching rule wins |
| `params` | any tool's arguments | key/value rules; covers tools with no path argument |
| `toolParams` | one tool's arguments | like `params`, scoped to a tool-name glob |
| `agents` | agent identity | `main` / `subagent` / `preset:<name>` |

Matching uses `*` (greedy, crosses `/`) and `?`. Within one surface the **last**
matching rule wins, so put broad rules first and exceptions after. Across
surfaces the most restrictive result wins: `deny` > `ask` > `allow`.

Path candidates include the literal argument, its cwd-resolved absolute form,
its cwd-relative form, and its symlink-resolved target.

## Params

`params` gates any argument of any tool, which is what the path surfaces cannot
reach: `web_search` queries, `skill` names, MCP arguments that are not paths.

```yaml
params:
  query:            # matches the `query` key at any depth
    "*password*": deny
  command:
    "git push*": ask
```

A key pattern matches either the full dotted path (`arguments.command`) or its
leaf name (`command`), and array members are addressable by their container
(`queries` covers `queries.0`, `queries.1`). Within one key's value map the last
matching rule wins; across keys the most restrictive result wins.

Set `patternMode: regex` to switch **this surface only** to regular expressions
(`^git\s+push`). Path and command rules stay glob: switching them wholesale
would break every `*.env` rule in an existing policy.

## MCP tools

MCP tools are named `mcp__<server>__<tool>` and have no path argument of their
own, so they need their own surfaces. All three forms work:

```jsonc
{
  "permission": {
    // 1. one server at a time, by tool-name glob
    "tools": {
      "mcp__chrome-devtools__*": { "*": "deny" }
    },
    // 2. one tool's arguments, without touching other tools that happen to
    //    use the same key (`fetch.url` stays free)
    "toolParams": {
      "mcp__chrome-devtools__navigate_page": {
        "url": { "https://prod-*": "deny" }
      }
    },
    // 3. refuse one tool outright, before any argument is looked at
    "denyTools": ["mcp__github__delete_repo"]
  }
}
```

`tools` keys are matched as globs against the tool name, and a tool with no path
argument is matched by its own name — so `{ "*": "deny" }` means "every call to
this tool". `toolParams` is `params` narrowed to one tool: `{ tool: { key: {
value: state } } }`, with the same key matching (dotted path or leaf, array
containers included).

## Agents

```yaml
agents:
  subagent: deny        # delegated children never touch the filesystem
  main: allow
  preset:reader: ask    # a read-only preset must still confirm writes
```

The most specific identity wins: `preset:<name>` and `subagent:<name>` are
tried before `subagent`/`main`. A forked session carries a `parentSession` but is
**not** a subagent — identity follows the durable `origin: 'subagent'` marker.

## Defaults

Sensitive paths are denied (`.env`, `*.env.*`, `id_rsa` family, `~/.ssh`,
`~/.aws`, `~/.gnupg`, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`,
`.docker/config.json`, `.kube/config`, `~/.config/gh/hosts.yml`,
`~/.dsh/.credentials.yaml`); `*.env.example` is allowed.

`ask` rules only make sense while the session approval policy is `ask`; under
`never` an `ask` becomes a denial. Wrapper commands (`sudo`, `bash -c`, `eval`,
`xargs`, `find -exec`) and everything else default to `allow`; opt into
approval per surface:

```yaml
wrappers: ask        # or deny
bash:
  "sudo *": ask
```

## Per-tool rules

`tools.<name>` applies path patterns to one tool on top of the cross-cutting
surfaces:

```yaml
tools:
  grep:
    "*": deny
  read:
    "*/secrets/*": deny
```

## Session approvals

`sessionApprovals: true` remembers an ask that was actually approved (the tool
then ran successfully) and auto-allows the same rule pattern for the rest of
that session. It is off by default because it silently widens a one-time
approval; turn it on only when `ask` is your normal posture.

A grant is keyed by `(session, rule pattern)`, so approving `rm *` never widens
to `git push *`. Both limits are opt-in:

```yaml
sessionApprovalTtlMs: 1800000   # 30 minutes; 0 = rest of the session
sessionApprovalMaxUses: 3       # 0 = unlimited
```

## Three-option approval

`approvalMode: question` replaces the two-outcome DSH approval for guard asks with
an explicit question carrying three choices: 允许一次 / 本会话允许 / 拒绝, plus
**写入项目规则** when the hit is a flat surface (`path`, `pathRead`,
`pathWrite`, `externalDirectory`, `bash`, `tools.<name>`). Choosing it appends
`"<pattern>": allow` to `<cwd>/.dsh/guard-policy.json` and applies immediately —
argv/network/params hits cannot be round-tripped into one rule and are refused
rather than guessed at.

A free-text "Other" answer becomes the denial reason the model sees, e.g.
`dsh-guard: 用户拒绝 "rm *"：先用只读命令确认`. Only an explicit session choice
records a standing allow — nothing is widened silently. When no question answerer
is available the plugin falls back to the normal `ask` decision.

### Self-drawn dialog (`approvalMode: dialog`)

`approvalMode: dialog` replaces the DSH question card with a dialog the plugin
draws itself. Because it is our own DOM, it shows the change **side by side**
instead of a text diff:

- two columns, red for the old line, green for the new one, unchanged rows grey
- `允许一次` / `本会话允许` / `写入项目规则` / `拒绝`
- one request at a time, 120 s timeout (`dialogTimeoutMs `) then deny

Mechanism: `tools/pre-execute` parks a Promise in an in-memory map, the browser
polls `GET /api/dsh-guard/pending`, and `POST /api/dsh-guard/decide` resolves it.
If no Client is connected the request waits for the timeout, so this mode assumes
the Web UI is open.

### What the dialog shows

For `write` and `edit` the prompt carries a preview, not just the rule name:

```
规则：tools.write
改写 src/app.ts：120 → 118 行（-2）
--- 原
- import { old } from './old'
- ...
+++ 新
+ import { next } from './next'
+ ...
```

The current bytes are read from disk (capped at 128 KB) and diffed against the
incoming content: common prefix and suffix are trimmed, and the window around the
real change is shown with three lines of context. A one-word edit therefore shows
the line it touches, not the head of the file. `edit` shows the replaced fragment
instead.

The block is sent as a fenced Markdown code block, because the dialog renders
`detail` as Markdown and bare newlines would collapse into spaces.

Set `webBase` to the browser origin of this Web UI (for example
`http://192.168.1.10:3088`) so approval cards can link to the diff page. The
plugin cannot discover that origin by itself: `webApp` is not visible from the
plugin scope and the host process has no `DSH_WEB_URL`. Without it the card still
shows the text preview, just no link.

For `write` calls the card also carries **打开双栏对比**: a link to
`/api/dsh-guard/diff?id=…`, an HTML page that pairs old and new lines row by row
with red/green highlighting. Entries live in memory for 10 minutes (24 at most)
and are never written to disk — the card itself cannot hold a component, so this
is the only way to show a real two-column view.

It is read-only: a preview that cannot be built is simply omitted, and it never
blocks or delays the approval beyond one bounded read.

## Dry run

`enforce: false` audits what the rules **would** have done and lets every call
through, with `dryRun: true` on the audit row:

```yaml
enforce: false
```

Use it to tune a policy without locking yourself out. `deny` is not exempt:
dry-run means dry-run for everything.

## Snapshots and undo

A `write` or `edit` call destroys the previous bytes as soon as it lands. Before
letting one through, the plugin copies the target file into
`snapshots/<id>/` and records the id on the audit row, so a bad edit is
recoverable whether it failed or succeeded:

```
/guard-undo          roll back the most recent snapshot
/guard-undo list     the last 10 snapshots (id, time, tool, files)
/guard-undo <id>     roll back one specific snapshot
```

Restore rewrites the saved bytes and deletes files that did not exist at capture
time. It does **not** silently skip: a file over `snapshotMaxBytes` or a
non-regular path is reported as skipped.

```yaml
snapshots: true           # default
snapshotMaxFiles: 20      # per call
snapshotMaxBytes: 262144  # per file; larger ones are marked skipped
snapshotRetain: 100       # snapshot dirs kept, oldest pruned
```

Denied writes are never snapshotted (nothing was going to change), and a capture
failure never blocks the call — it just leaves nothing to undo.

## Loop detection

A model stuck repeating one identical call is a different failure from a
dangerous one, and rules cannot see it: every individual call may be allowed.
The gate counts byte-identical calls (same tool, same arguments) inside a
window and asks once the count is reached:

```yaml
repeatLimit: 5          # 0 = off (default)
repeatWindowMs: 60000   # rolling window
repeatAction: ask       # allow | ask | deny
```

`repeatLimit: 5` means the fifth identical call asks; the counter resets once
`repeatWindowMs` passes without a repeat. Different arguments are a different
call, so a loop that varies its input is not caught — this targets the stuck
case, not a determined adversary.

## Blocking tools by name

`denyTools: [write, edit]` refuses those tools outright — a read-only posture.
It blocks calls rather than hiding schemas; hiding needs an agent-scoped
`ctx.tools.restrict`, which this plugin does not have from the profile root.

## Config validation

Every rule state is validated (`allow`/`ask`/`deny`, map shapes, boolean
switches, array `denyTools`). An invalid configuration **fails closed**: every
tool call is denied with the validation errors in the reason. Fix the config and
the next mount restores normal operation.

## Command rules

The shipped profile starts from pi's bash policy: destructive, publishing,
network, installer and build commands ask (three-option card in `question`
mode), while `rm -rf /` and `rm -rf ~*` deny. See `cordis.patch.yml` in the
profile for the full list.

Bash tokens are gated only when they look like paths (`/`, `~`, leading `.`,
denied basenames, or a `.env`/`.pfx`/`.p12` suffix), so identifiers such as
`process.env.HOME` are not mistaken for dotenv files.

## argv surface (lexical shell decomposition)

`argv` rules run on a best-effort decomposition of a bash command line: split
on `|`, `||`, `;`, `&&`, `&` and newlines, then each simple command into
command word, argument tokens and redirect targets (quote/escape aware).
Command substitution, backticks and brace expansion stay opaque.

```yaml
argv:
  - match: { command: [rm], args: ["-rf", "/"] }
    action: deny
  - match: { pipeline: ["curl*|*sh", "wget*|*bash"] }
    action: deny
  - match: { command: [python3, node] }
    action: ask
```

Fields: `command` (any simple command word matches), `args` (every pattern
matches some token), `anyArg` (some token matches a pattern; `!` negates),
`pipeline` (command words joined by `|`). Redirect targets also go through the
write-direction path surface, so `echo x > secret.env` is denied by path rules.

## Hot reload, audit, project policy, network

- **Hot reload**: `policy.json` is watched (1s poll). A valid edit replaces the
  live policy without restarting; an invalid edit is rejected and logged.
- **Audit**: every decision appends one JSON line to
  `$DSH_HOME/dsh-plugins/dsh-guard/audit.jsonl` (`auditPath` to change,
  `audit: false` to disable). The `args` field is passed through the same
  redactor as tool results before it is written, so the trail never becomes the
  place a credential survives. The file rolls to `audit.jsonl.1` once it passes
  `auditMaxBytes` (default 5 MiB).
- **Recent decisions**: the last 10 decisions stay in memory, newest first, and
  appear as `recentDecisions` in `guard_status` and `status.json` — checking
  what just happened never reads the audit file.
- **Project policy**: `<project>/.dsh/guard-policy.json` with the same
  `permission` shape, merged over the global policy for sessions whose cwd is
  that project (`projectPolicy: false` disables). Rules **stack from the
  filesystem root down to the cwd**, so a monorepo can keep a baseline at
  `<repo>/.dsh/guard-policy.json` and override one package at
  `<repo>/pkg/.dsh/guard-policy.json`; the nearest file wins for the same key
  (`projectPolicySearchUp: false` reads only the cwd). Changes are picked up by
  mtime on the next call.
- **Network rules**: `network: [{ match: { domains: ["evil.example"] },
  action: deny }]` matches hostnames from URLs in shell commands and tool
  arguments (`url`, `endpoint`, …). This is static inspection, not a proxy.
- **yolo**: `yolo: true` turns every `ask` into allow; `deny` still blocks.
  `sandboxAware` (default) does that automatically under `danger-full-access`
  and `read-only`.

## Windows

- Backslashes are normalized to `/` for matching; drive letters are preserved
  (`C:\Users\…` matches `*.env`, `*/.ssh/*`, …).
- Matching is case-insensitive when `caseInsensitivePaths` is true (default:
  `process.platform === 'win32'`). Set it explicitly on other platforms only if
  the policy targets a case-insensitive filesystem.
- The `pwsh` (and `powershell`) tool reuses the same command surface as bash:
  `bash` rules, `argv` decomposition, opaque-construct checks and redirect
  targets all apply.
- In shell decomposition a backslash is a path separator on Windows rather than
  an escape character.
- Tool basenames are split on both `/` and `\`.

Windows-specific work still pending real-machine verification (install, run
`node --test`, check `%USERPROFILE%` expansion, drive-relative paths, and
PowerShell quoting). Windows separators and drive letters are normalized before
matching; matching is case-insensitive on win32 by default.

## Settings page

A **dsh-guard** tab appears under 设置 → 内置插件 (the shared plugin settings
surface, next to other plugins). It edits only the switches and scalar knobs:

| Control | Writes |
|---|---|
| `enforce` / `yolo` / `snapshots` / `audit` | the four booleans |
| `repeatLimit` / `repeatWindowMs` / `repeatAction` | loop detection |
| `snapshotMaxFiles` / `snapshotMaxBytes` / `snapshotRetain` | snapshot capacity |
| `auditMaxBytes` | audit rotation threshold |
| preset selector | `baseline` / `strict` / `off`, merged like `/guard-policy` |
| recent decisions | read-only, last 10 |
| snapshot list | read-only, last 8; roll back with `/guard-undo` |

Every write goes through `POST /api/dsh-guard/config`, which runs the same
`applyPatch` + `validate` + backup path as the command, so the panel cannot
produce a policy a hand edit could not. Rules themselves stay in `policy.json`:
they are nested maps with unlimited combinations, and a form covering them would
end up as a JSON textarea anyway.

The route fence is loopback-or-same-origin, the same one every plugin uses.

## Commands

`policy.json` is the source of truth. `/guard-policy` writes it from the
composer; `/guard-test` and `/guard-undo` never touch it.

`/guard-policy` deep-merges a JSON fragment into the live policy, validates the
result, backs up the previous file, and lets the hot reload apply it:

```
/guard-policy list
/guard-policy {"bash":{"rm *":"ask"}}
/guard-policy {"toolParams":{"navigate_page":{"url":{"https://prod-*":"deny"}}}}
/guard-policy {"bash":{"rm *":null}}          # null removes a rule
/guard-policy preset list
/guard-policy preset baseline
```

Templates are named fragments merged the same way, so they can only write what a
hand edit could. Three ship:

| Template | What it writes |
|---|---|
| `baseline` | 外部目录 ask、`rm`/`git push`/`sudo` ask、写 `*.env` deny、子代理 ask、`repeatLimit: 5` |
| `strict` | 命令与写入全部 ask、外部目录 deny、子代理 deny、`repeatLimit: 3` |
| `off` | `enforce: false`（只审计不拦截）、`repeatLimit: 0` |

A template merges, it does not replace: applying `strict` leaves your existing
`path` rules alone.

One grammar for every nesting depth, no separator to escape. A fragment that
fails validation is rejected and the file is left untouched. A rewrite
normalizes the file, so hand-written comments are lost; the previous text stays
at `policy.json.bak`, and for comment-preserving edits you can still edit the
file directly.

`/guard-test <tool> <json>` dry-evaluates one call against the live policy
without executing it — the same decision the gate would reach, including the
project overlay:

```
/guard-test bash {"command":"git push origin main"}
bash: ask by "git push *" [bash]
/guard-test web_search {"queries":["my secret"]}
web_search: ask by "params queries=*secret*" [params]
```

`/guard-undo [list|<id>]` rolls back a pre-write snapshot; see
[Snapshots and undo](#snapshots-and-undo).

`/guard-log [n]` prints the last n decisions (default 20, max 200) from
`audit.jsonl`, read as a bounded tail rather than parsing the whole file:

```
/guard-log
00:11:22  deny   bash  rm -rf ~*
00:11:19  ask    bash  git push *  [subagent]
00:11:15  allow  web_search  params queries=*secret*
```

All three are registered when the `commands` service is mounted; without it they
are simply absent. A command that takes arguments must declare `input`, or the
Client treats `/name args` as ordinary chat — the reason all three ship an
`input.hint`.

## Redaction

`tools/post-execute` replaces credential-shaped text in every tool result before
it is persisted: `sk-*`/`rk-*`/`pk-*` keys, GitHub tokens (`ghp_`, `gho_`,
`github_pat_`), Slack tokens, AWS access keys, Google API keys, JWTs, `Bearer`
tokens, PEM private-key blocks, and `SECRET|TOKEN|PASSWORD|API_KEY=...` values.
Only text blocks change; images and structured blocks pass through. Set
`redact: false` to disable.

The replaced text is what the session log stores — verified by inspection, not
just the UI.

## Configuration

```yaml
- id: guard
  name: dsh-guard
  config:
    "*": allow
    path:
      "*": allow
      "*.env": deny
      "*.env.example": allow
    pathRead:
      "~/.cargo/registry/*": allow
    externalDirectory:
      "*": ask
      "~/dev/*": allow
    bash:
      "*": allow
      "sudo *": ask
      "rm -rf /*": deny
    params:
      query:
        "*password*": deny
      command:
        "git push*": ask
    agents:
      subagent: deny
      main: allow
    enforce: true
    snapshots: true
    snapshotRetain: 100
```

## Limits

- `ask` becomes a denial when the session has no approval channel (approval
  policy `never`, or a non-interactive run).
- The bash scanner is a token heuristic, not a shell parser: quoted globs are
  skipped, and shell expansion can hide a path. It catches the common accident,
  not a determined bypass.
- `network` rules inspect URLs in text. They are not a proxy: traffic from a
  process that resolves its own hostnames is out of reach.
- Glob patterns are bounded to `maxGlobStars` (default 2) unbounded `*` runs;
  a third one is a validation error, because nested greedy quantifiers
  backtrack exponentially on untrusted input. Write two rules instead.
- `preset:<name>` identity depends on the host recording `agentPreset` on the
  session; without it only `main`/`subagent` are distinguishable.
