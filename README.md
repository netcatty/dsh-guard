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

## Surfaces

| Surface | Applies to | Notes |
|---|---|---|
| `path` | every file tool + bash path tokens | cross-cutting, both directions |
| `pathRead` | `read`, `read_image`, `grep`, `glob` | direction-specific override |
| `pathWrite` | `write`, `edit` | direction-specific override |
| `externalDirectory` | paths outside the session cwd | defaults to allow |
| `bash` | command text | glob, last matching rule wins |

Matching uses `*` (greedy, crosses `/`) and `?`. Within one surface the **last**
matching rule wins, so put broad rules first and exceptions after. Across
surfaces the most restrictive result wins: `deny` > `ask` > `allow`.

Path candidates include the literal argument, its cwd-resolved absolute form,
its cwd-relative form, and its symlink-resolved target.

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

## Blocking tools by name

`denyTools: [write, edit]` refuses those tools outright — a read-only posture.
It blocks calls rather than hiding schemas; hiding needs an agent-scoped
`ctx.tools.restrict`, which this plugin does not have from the profile root.

## Config validation

Every rule state is validated (`allow`/`ask`/`deny`, map shapes, boolean
switches, array `denyTools`). An invalid configuration **fails closed**: every
tool call is denied with the validation errors in the reason. Fix the config and
the next mount restores normal operation.

## Three-option approval

`approvalMode: question` replaces the two-outcome DSH approval for guard asks with
an explicit question carrying three choices: 允许一次 / 本会话允许 / 拒绝. Only an
explicit session choice records a standing allow for that rule pattern — nothing
is widened silently. When no question answerer is available the plugin falls back
to the normal `ask` decision.

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
  `~/.dsh/guard-audit.jsonl` (`auditPath` to change, `audit: false` to disable).
- **Project policy**: `<project>/.dsh/guard-policy.json` with the same
  `permission` shape, merged over the global policy for sessions whose cwd is
  that project (`projectPolicy: false` disables). Changes are picked up by
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

## Commands

`/guard-clear` clears every session approval this plugin recorded (the
`approved` map shown in the status file). It is registered when the `commands`
service is mounted; without it the command is simply absent.

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
```

## Limits

- `ask` becomes a denial when the session has no approval channel (approval
  policy `never`, or a non-interactive run).
- The bash scanner is a token heuristic, not a shell parser: quoted globs are
  skipped, and shell expansion can hide a path. It catches the common accident,
  not a determined bypass.
- MCP tools, skills, and project trust are out of scope for this version.
