# @netcatty/dsh-guard

给 DeepSeek Harness 的工具调用加 allow / ask / deny 权限门。

## 安装

从 npm 安装：

```sh
dsh plugin --profile web add @netcatty/dsh-guard
```

从本地检出的仓库安装（开发用）：

```sh
git clone git@github.com:netcatty/dsh-guard.git ~/code/dsh-guard
dsh plugin --profile web add link:~/code/dsh-guard
```

无需构建步骤：插件是纯 ESM。Windows 上使用检出路径，例如
`dsh plugin --profile web add link:C:\code\dsh-guard`，然后重启 `dsh web`。
仓库自带 `policy.json`，规则因此与代码一起纳入版本管理，并在插件挂载期间热重载。

## 数据目录

插件写入的所有文件都放在同一处：

```
$DSH_HOME/dsh-plugins/dsh-guard/policy.json   生效中的权限策略
$DSH_HOME/dsh-plugins/dsh-guard/audit.jsonl   判定记录（超过 auditMaxBytes 轮转）
$DSH_HOME/dsh-plugins/dsh-guard/status.json   实时状态快照
$DSH_HOME/dsh-plugins/dsh-guard/snapshots/    写前文件副本（每次调用一个目录）
```

`$DSH_HOME` 默认为 `~/.dsh`。旧版本写在别处的文件（`~/.dsh/guard-audit.jsonl`、
`~/.dsh/guard-status.json`）会在每次挂载时迁移进来；`auditPath` 可以改审计位置。

**生效中的策略是数据目录里的那一份。** 仓库里也有 `policy.json`，但它只是种子：
数据目录首次挂载时会被复制到 `dsh-plugins/dsh-guard/policy.json`，此后运行的一直是
那份副本。因此改仓库不会影响行为，`git pull` 也不会覆盖你的规则。删掉生效文件会回退到
种子策略，直到你重新写一份。

## 编辑策略

这个文件是给人手写的，所以它接受严格 JSON 拒绝的一切：

```jsonc
{
  "$schema": "./policy.schema.json",   // 编辑器补全 + 校验
  "permission": {
    "*": "allow",
    // 破坏性命令一律询问
    "bash": {
      "git push *": "ask",   /* 块注释也可以 */
      "rm -rf /*": "deny",
    },
  },
}
```

- **注释** —— `//` 到行尾，`/* … */` 任意位置。字符串或 URL 里的 `//` 不受影响。
- **尾随逗号** —— 对象或数组最后一项后面可以有。
- **`$schema`** —— 让编辑器指向 `policy.schema.json`，获得补全与内联校验；加载器读取规则前会去掉它。
- **错误依然会抛出** —— 注释和逗号之外的东西（未加引号的键、单引号）仍然失败；策略有错时按关闭处理，而不是悄悄生效一半。

改动约一秒内热重载。信任它之前先试算：

```
/guard-test bash {"command":"git push origin main"}
```

除此之外不需要运行任何东西：没有命令会写策略，也没有界面独占它。

## 规则面

| 规则面 | 作用于 | 说明 |
|---|---|---|
| `path` | 所有文件类工具 + bash 里的路径词元 | 横切，读写双向 |
| `pathRead` | `read`、`read_image`、`grep`、`glob` | 按方向覆盖 |
| `pathWrite` | `write`、`edit` | 按方向覆盖 |
| `externalDirectory` | 会话 cwd 之外的路径 | 默认允许 |
| `bash` | 命令文本 | glob，最后命中者胜 |
| `params` | 任意工具的参数 | 键/值规则；覆盖没有路径参数的工具 |
| `toolParams` | 单个工具的参数 | 同 `params`，限定到某个工具名 glob |
| `agents` | Agent 身份 | `main` / `subagent` / `preset:<name>` |

匹配使用 `*`（贪婪，跨 `/`）和 `?`。同一规则面内**最后**命中的规则生效，所以把宽的放前面、
例外放后面。跨规则面取最严结果：`deny` > `ask` > `allow`。

路径候选包括：字面参数、按 cwd 解析的绝对路径、相对 cwd 的形式、以及解析符号链接后的目标。

## params

`params` 拦截任意工具的参数，这是路径类规则面覆盖不到的地方：`web_search` 的查询词、
`skill` 的名字、没有路径参数的 MCP 参数。

```yaml
params:
  query:            # 匹配任意层级的 `query` 键
    "*password*": deny
  command:
    "git push*": ask
```

键模式可以匹配完整的点分路径（`arguments.command`）或叶子名（`command`）；数组元素通过容器
寻址（`queries` 覆盖 `queries.0`、`queries.1`）。同一个键的值映射内最后命中者胜；跨键取最严。

设 `patternMode: regex` 可把**仅此规则面**切换为正则（`^git\s+push`）。路径与命令规则仍是 glob：
整体切换会让既有策略里每一条 `*.env` 规则失效。

## MCP 工具

MCP 工具命名为 `mcp__<server>__<tool>`，自身没有路径参数，因此需要独立的规则面。三种写法都可用：

```jsonc
{
  "permission": {
    // 1. 按工具名 glob 拦一整个服务
    "tools": {
      "mcp__chrome-devtools__*": { "*": "deny" }
    },
    // 2. 只限某个工具的参数，不影响恰好用同名键的其他工具
    //    （`fetch.url` 不受影响）
    "toolParams": {
      "mcp__chrome-devtools__navigate_page": {
        "url": { "https://prod-*": "deny" }
      }
    },
    // 3. 在检查任何参数之前直接拒绝某个工具
    "denyTools": ["mcp__github__delete_repo"]
  }
}
```

`tools` 的键按 glob 匹配工具名；没有路径参数的工具用自己的名字匹配，所以 `{ "*": "deny" }`
表示“这个工具的每次调用都拒绝”。`toolParams` 是限定到单个工具的 `params`：
`{ tool: { key: { value: state } } }`，键匹配规则相同（点分路径或叶子名，含数组容器）。

## agents

```yaml
agents:
  subagent: deny        # 派生的子代理不碰文件系统
  main: allow
  preset:reader: ask    # 只读预设也必须确认写入
```

越具体的身份优先：先试 `preset:<name>` 和 `subagent:<name>`，再回落到 `subagent`/`main`。
分叉会话带有 `parentSession`，但**不是**子代理——身份跟随持久的 `origin: 'subagent'` 标记。

## 默认值

敏感路径默认拒绝（`.env`、`*.env.*`、`id_rsa` 系列、`~/.ssh`、`~/.aws`、`~/.gnupg`、
`.netrc`、`.git-credentials`、`.npmrc`、`.pypirc`、`.docker/config.json`、`.kube/config`、
`~/.config/gh/hosts.yml`、`~/.dsh/.credentials.yaml`）；`*.env.example` 允许。

`ask` 规则只在会话审批策略为 `ask` 时有意义；在 `never` 下 `ask` 会变成拒绝。包装类命令
（`sudo`、`bash -c`、`eval`、`xargs`、`find -exec`）和其他一切默认允许；按规则面选择性地要求学生审批：

```yaml
wrappers: ask        # 或 deny
bash:
  "sudo *": ask
```

## 单工具规则

`tools.<name>` 在横切规则面之上，把路径模式限定到某个工具：

```yaml
tools:
  grep:
    "*": deny
  read:
    "*/secrets/*": deny
```

## 会话授权

`sessionApprovals: true` 会记住真正被批准过的 ask（即工具随后执行成功），在本会话余下时间内
自动放行同一规则模式。默认关闭，因为它会悄悄放大一次性批准；只有当你日常姿态就是 `ask` 时才打开。

授权的键是 `(会话, 规则模式)`，所以批准 `rm *` 不会扩散到 `git push *`。两个上限都是可选的：

```yaml
sessionApprovalTtlMs: 1800000   # 30 分钟；0 = 本会话余下时间
sessionApprovalMaxUses: 3       # 0 = 不限次数
```

## 三选项审批

`approvalMode: question` 用一个带选项的显式提问替代 DSH 的两结果审批：允许一次 / 本会话允许 / 拒绝，
命中扁平规则面（`path`、`pathRead`、`pathWrite`、`externalDirectory`、`bash`、`tools.<name>`）时
额外提供 **写入项目规则**。选中它会把 `"<pattern>": allow` 追加到 `<cwd>/.dsh/guard-policy.json`
并立即生效——argv/network/params 的命中无法回填成单条规则，会直接拒绝而不是猜。

自由文本的“其他”答案会成为模型看到的拒绝理由，例如
`dsh-guard: 用户拒绝 "rm *"：先用只读命令确认`。只有显式选择会话授权才会记录常驻允许，
不会有任何静默放大。没有可用的问询应答者时，插件回落到普通的 `ask` 判定。

### 自绘弹窗（`approvalMode: dialog`）

`approvalMode: dialog` 用插件自己绘制的弹窗替代 DSH 问询卡片。因为 DOM 是自己的，它可以并排展示
改动，而不只是文本 diff：

- 两栏，旧行标红、新行标绿、未变行灰色
- `允许一次` / `本会话允许` / `写入项目规则` / `拒绝`
- 一次一个请求，默认 120 秒超时（`dialogTimeoutMs`）后拒绝

机制：`tools/pre-execute` 把一个 Promise 挂进内存表，浏览器轮询 `GET /api/dsh-guard/pending`，
由 `POST /api/dsh-guard/decide` 解挂。客户端靠 `POST /api/dsh-guard/hello` 注册并每 20 秒心跳，
**没有在线客户端时立即拒绝**，拒绝理由会说明缺少审批界面，因此不会白等超时。

### 弹窗里显示什么

对 `write` 和 `edit`，提示里带改动预览，而不只是规则名：

```
规则：tools.write
改写 src/app.ts：120 → 118 行（-2）
@@ 第 40 行
- import { old } from './old'
+ import { next } from './next'
```

当前磁盘内容（上限 128 KB）会与即将写入的内容做差异比对：裁掉公共前后缀，只显示真实改动附近
的窗口，带三行上下文。因此改一个词时看到的是那一行，而不是文件开头。`edit` 则显示被替换的片段。

这段内容以 Markdown 代码块下发，因为弹窗按 Markdown 渲染 `detail`，裸换行会被折叠成空格。

把 `webBase` 设成这个 Web UI 的浏览器源（例如 `http://192.168.1.10:3088`），审批卡片就能链接到
对比页。插件自己发现不了这个源：`webApp` 在插件作用域内不可见，宿主进程也没有 `DSH_WEB_URL`。
不配置时卡片仍有文本预览，只是没有链接。

`write` 的卡片还会带 **打开双栏对比**：指向 `/api/dsh-guard/diff?id=…` 的链接，那是一个红绿高亮、
逐行配对的 HTML 页面。条目在内存里保存 10 分钟（最多 24 条），从不落盘——卡片本身装不下组件，
这是展示真正双栏视图的唯一方式。

整个预览是只读的：构建不出来就省略，绝不会在有限读取之外阻塞或延迟审批。

## 试运行

`enforce: false` 只记录规则**本会**怎么做，并放行所有调用，审计行带 `dryRun: true`：

```yaml
enforce: false
```

用来在不把自己锁死的前提下调策略。`deny` 也不豁免：试运行就是对一切都试运行。

## 快照与回滚

`write` 或 `edit` 一落地就销毁了原有字节。放行之前，插件会把目标文件复制到 `snapshots/<id>/`，
并在审计行记下 id，所以无论是失败还是成功，坏改动都可恢复：

```
/guard-undo          回滚最近一次快照
/guard-undo list     最近 10 个快照（id、时间、工具、文件）
/guard-undo <id>     回滚指定快照
```

回滚会重写保存的字节，并删除采集时不存在的文件。它**不会**静默跳过：超过 `snapshotMaxBytes`
的文件或非普通文件会被报告为跳过。

```yaml
snapshots: true           # 默认
snapshotMaxFiles: 20      # 每次调用
snapshotMaxBytes: 262144  # 每个文件；更大的标记为跳过
snapshotRetain: 100       # 保留的快照目录数，最旧的会被清掉
```

被拒绝的写入不做快照（本来就不会改），采集失败也绝不阻塞调用——只是没有东西可回滚。

## 循环检测

模型卡在重复同一次调用，是与危险调用不同的失败模式，规则看不出来：每一次单独的调用可能都合法。
这个闸门统计窗口内字节完全相同的调用（同工具、同参数），达到次数就问一次：

```yaml
repeatLimit: 5          # 0 = 关闭（默认）
repeatWindowMs: 60000   # 滚动窗口
repeatAction: ask       # allow | ask | deny
```

`repeatLimit: 5` 表示第 5 次相同调用触发询问；`repeatWindowMs` 内没有重复后计数重置。参数不同就是
不同调用，所以会变化输入的循环抓不到——它针对的是卡住的情况，不是蓄意绕过。

## 按名拦截工具

`denyTools: [write, edit]` 直接拒绝这些工具，形成只读姿态。它拦截调用而不是隐藏 schema；
隐藏需要 Agent 作用域的 `ctx.tools.restrict`，而插件从 profile 根拿不到这个能力。

## 配置校验

每一条规则状态都会被校验（`allow`/`ask`/`deny`、映射形状、布尔开关、`denyTools` 数组）。
配置无效时**按关闭处理**：每次工具调用都被拒绝，理由里带上校验错误。修好配置后，下次挂载恢复正常。

## 命令规则

随附的配置从 pi 的 bash 策略出发：破坏性、发布、网络、安装器与构建类命令走询问（`question`
模式下是三选项卡片），而 `rm -rf /` 和 `rm -rf ~*` 拒绝。完整列表见 profile 里的 `cordis.patch.yml`。

bash 里的词元只有在看起来像路径时才被拦截（含 `/`、`~`、以 `.` 开头、命中拒绝基名、或以
`.env`/`.pfx`/`.p12` 结尾），所以 `process.env.HOME` 这类标识符不会被误认成 dotenv 文件。

## argv 面（词法级 shell 分解）

`argv` 规则跑在尽力而为的命令行分解上：先按 `|`、`||`、`;`、`&&`、`&` 和换行切分，再把每个简单命令
拆成命令词、参数词元和重定向目标（引号/转义感知）。命令替换、反引号和花括号展开保持不透明。

```yaml
argv:
  - match: { command: [rm], args: ["-rf", "/"] }
    action: deny
  - match: { pipeline: ["curl*|*sh", "wget*|*bash"] }
    action: deny
  - match: { command: [python3, node] }
    action: ask
```

字段：`command`（任一简单命令词命中）、`args`（每个模式都要命中某个词元）、`anyArg`（存在某个词元命中；
`!` 取反）、`pipeline`（用 `|` 连接的��令词）。重定向目标还会走写入方向的路径规则面，所以
`echo x > secret.env` 会被路径规则拒绝。

## 热重载、审计、项目策略、网络

- **热重载**：监听 `policy.json`（1 秒轮询）。有效改动无需重启即可替换生效策略；无效改动会被拒绝并记日志。
- **审计**：每次判定向 `$DSH_HOME/dsh-plugins/dsh-guard/audit.jsonl` 追加一行 JSON
  （`auditPath` 改位置，`audit: false` 关闭）。`args` 字段在写入前会过一遍与工具结果相同的脱敏器，
  所以记录不会成为凭据侥幸存活的地方。文件超过 `auditMaxBytes`（默认 5 MiB）后轮转为 `audit.jsonl.1`。
- **最近判定**：最近 10 条判定留在内存里，最新的在前，通过 `guard_status` 和 `status.json` 的
  `recentDecisions` 暴露——查看刚发生了什么不需要读审计文件。
- **项目策略**：`<project>/.dsh/guard-policy.json`，同样的 `permission` 结构，对 cwd 在该项目内的
  会话叠加到全局策略之上（`projectPolicy: false` 关闭）。规则**从文件系统根一路叠加到 cwd**，所以
  monorepo 可以在 `<repo>/.dsh/guard-policy.json` 放基线，再在 `<repo>/pkg/.dsh/guard-policy.json`
  覆盖某个包；同一个键以最近的为准（`projectPolicySearchUp: false` 只读 cwd）。改动按 mtime 在下次
  调用时生效。合并是**按 key，不是按表**：项目文件给某个路径设了 `tools.write`，继承来的其他写规则依然保留。

  项目规则可以是 `null`，表示**删除**继承来的规则而不是设置一条。这是在不重写全局文件的前提下，
  为单个项目放宽全局规则的唯一办法：

  ```jsonc
  {
    "permission": {
      "bash": { "rm *": null },   // 本项目内不再为 rm 询问
      "tools": { "write": null }  // 丢掉整张继承表
    }
  }
  ```

  在全局文件里写 `null` 会被接受但没有效果——它背后没有可删的继承内容，规则就是不存在。
- **网络规则**：`network: [{ match: { domains: ["evil.example"] }, action: deny }]` 匹配 shell 命令和
  工具参数（`url`、`endpoint` 等）里 URL 的主机名。这是静态检查，不是代理。
- **yolo**：`yolo: true` 把所有 `ask` 变成允许；`deny` 仍然拦截。`sandboxAware`（默认开启）会在
  `danger-full-access` 和 `read-only` 下自动这么做。

## Windows

- 匹配前反斜杠归一化为 `/`；盘符保留（`C:\Users\…` 能命中 `*.env`、`*/.ssh/*` 等）。
- `caseInsensitivePaths` 为 true 时匹配忽略大小写（默认：`process.platform === 'win32'`）。只有在策略
  面向大小写不敏感文件系统时，才需要在其他平台显式设置。
- `pwsh`（和 `powershell`）工具复用与 bash 相同的命令规则面：`bash` 规则、`argv` 分解、不透明构造检查、
  重定向目标都生效。
- shell 分解时，反斜杠在 Windows 上是路径分隔符，而不是转义字符。
- 工具基名按 `/` 和 `\` 双分隔符切分。

已在真实 Windows 机器上验证：安装、`node --test`、`%USERPROFILE%` 展开（`~/` 与 `~\` 两种写法）、
盘符相对路径、PowerShell 引号处理。分隔符与盘符在匹配前归一化；win32 上默认忽略大小写匹配。

## 设置页

设置 → 内置插件 下会出现 **dsh-guard** 标签（与其他插件共用的插件设置界面）。它只改开关和标量：

| 控件 | 写入 |
|---|---|
| `enforce` / `yolo` / `snapshots` / `audit` | 四个布尔开关 |
| `repeatLimit` / `repeatWindowMs` / `repeatAction` | 循环检测 |
| `snapshotMaxFiles` / `snapshotMaxBytes` / `snapshotRetain` | 快照容量 |
| `auditMaxBytes` | 审计轮转阈值 |
| 模板选择器 | `baseline` / `strict` / `off`，合并方式与 `/guard-policy` 相同 |
| 最近判定 | 只读，最近 10 条 |
| 快照列表 | 只读，最近 8 条；用 `/guard-undo` 回滚 |

所有写入都走 `POST /api/dsh-guard/config`，与命令行跑同一条 `applyPatch` + `validate` + 备份路径，
所以面板无法产生手改做不到的策略。规则本身留在 `policy.json`：它们是无上限组合的嵌套映射，
用表单覆盖最终也只会变成一个 JSON 文本域。

路由围栏是回环或同源，与其他插件一致。

## 命令

`policy.json` 是唯一事实来源。`/guard-policy` 从输入框写它；`/guard-test` 和 `/guard-undo` 从不碰它。

`/guard-policy` 把一个 JSON 片段深合并进生效策略，校验结果，备份上一份文件，然后由热重载应用：

```
/guard-policy list
/guard-policy {"bash":{"rm *":"ask"}}
/guard-policy {"toolParams":{"navigate_page":{"url":{"https://prod-*":"deny"}}}}
/guard-policy {"bash":{"rm *":null}}          # null 删除一条规则
/guard-policy preset list
/guard-policy preset baseline
```

模板是同样方式合并的命名片段，因此只能写出与手改等价的东西。随附三个：

| 模板 | 写入内容 |
|---|---|
| `baseline` | 外部目录 ask、`rm`/`git push`/`sudo` ask、写 `*.env` deny、子代理 ask、`repeatLimit: 5` |
| `strict` | 命令与写入全部 ask、外部目录 deny、子代理 deny、`repeatLimit: 3` |
| `off` | `enforce: false`（只审计不拦截）、`repeatLimit: 0` |

模板是合并而不是替换：应用 `strict` 不会动你已有的 `path` 规则。

一套语法覆盖所有嵌套层级，没有需要转义的分隔符。校验失败的片段会被拒绝，文件保持原样。重写会
规范化文件，因此手写的注释会丢失；之前的文本留在 `policy.json.bak`，需要保留注释时仍可直接编辑文件。

`/guard-test <tool> <json>` 在不执行的前提下，用生效策略试算一次调用——与闸门会得出的判定相同，
包含项目策略叠加：

```
/guard-test bash {"command":"git push origin main"}
bash: ask by "git push *" [bash]
/guard-test web_search {"queries":["my secret"]}
web_search: ask by "params queries=*secret*" [params]
```

`/guard-undo [list|<id>]` 回滚写前快照，见[快照与回滚](#快照与回滚)。

`/guard-log [n]` 打印 `audit.jsonl` 里最近 n 条判定（默认 20，上限 200），做法是从文件尾部读一段
有界窗口，而不是解析整个文件：

```
/guard-log
00:11:22  deny   bash  rm -rf ~*
00:11:19  ask    bash  git push *  [subagent]
00:11:15  allow  web_search  params queries=*secret*
```

三者都在 `commands` 服务挂载时注册；没有这个服务就只是不存在。带参数的命令必须声明 `input`，
否则客户端会把 `/name args` 当成普通聊天——这就是三个命令都带 `input.hint` 的原因。

## 脱敏

`tools/post-execute` 在每次工具结果落盘前替换凭据形态的文本：`sk-*`/`rk-*`/`pk-*` 密钥、
GitHub 令牌（`ghp_`、`gho_`、`github_pat_`）、Slack 令牌、AWS 访问密钥、Google API 密钥、JWT、
`Bearer` 令牌、PEM 私钥块、`SECRET|TOKEN|PASSWORD|API_KEY=...` 形式的值，以及键名**任意位置**
包含 `TOKEN` / `SECRET` / `PASSWORD` / `API_KEY` / `AUTHORIZATION` 的 JSON 字符串字段
（含 `"OXIDETERM_MCP_TOKEN": "..."`）。键名允许 `-` 和 `.`，所以 `x-api-key`、`settings.token`
同样覆盖；被转义过的 JSON（`{\"token\":\"…\"}`，shell 命令里常见）也覆盖，替换时保留转义。
只有文本块会被改动；图片和结构化块原样通过。`redact: false` 可关闭。

会话日志保存的是替换后的文本——这一点经过检查确认，不只是界面显示。

## 配置

```yaml
- id: guard
  name: '@netcatty/dsh-guard'
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

## 限制

- 会话没有审批通道时（审批策略为 `never`，或非交互运行），`ask` 会变成拒绝。
- bash 扫描器是词元启发式，不是 shell 解析器：带引号的 glob 会被跳过，shell 展开也可能藏住路径。
  它抓的是常见的误操作，不是蓄意绕过。
- `network` 规则检查文本里的 URL。它不是代理：进程自己解析主机名的流量不在覆盖范围内。
- glob 模式受 `maxGlobStars`（默认 2）限制无界 `*` 段数；第三段是校验错误，因为嵌套贪婪量词在不可信
  输入上会指数级回溯。写成两条规则。
- `preset:<name>` 身份依赖宿主在会话上记录 `agentPreset`；没有它就只能区分 `main`/`subagent`。
