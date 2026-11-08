# Changelog

## 0.2.2

### 修复

- 脱敏漏掉 JSON 形态的复合键名：`"OXIDETERM_MCP_TOKEN": "..."`、`"sessionToken": "..."` 这类键名前/后缀带词的凭据值会原样落盘，只有精确等于 `token`/`secret`/`password` 等白名单键名的才被遮。规则改为键名任意位置命中 `token|api_key|apikey|secret|password|passwd|authorization|private_key|access_key` 即脱敏，与 `KEY=value` 那条口径对齐。

## 0.2.1

Windows 实机验证后的一轮修复。

### 修复

- `expand` 不识别 `~\` 前缀，`~\Documents` 被当成相对路径拼到 cwd 下，路径规则漏判。
- `~\` 展开后未归一化分隔符，POSIX 上会得到 `/home/u/\secret` 这种带反斜杠的路径，`~/secret*` 规则照样匹配不上。

### 变更

- README 的 Windows 章节从「待实机验证」改为已验证：安装、`node --test`、`%USERPROFILE%` 展开、盘符相对路径、PowerShell 引号处理。

## 0.2.0

首个功能完整的版本。0.1.0 只有 `path` / `bash` 两个规则面和基础审批，此后每一轮都在补面。

### 新增

- **规则面**：`pathRead` / `pathWrite` / `externalDirectory` / `params` / `toolParams` / `agents` / `argv` / `network` / `tools.<nameGlob>`；判定规则是同一面内最后命中者胜，跨面取最严。
- **审批**：三种模式 —— `approval`（DSH 原生）、`question`（DSH 问询卡片 + 文本 diff + 双栏链接）、`dialog`（自绘弹窗，红绿双栏、左右独立行号、中缝标记）。四档动作：允许一次 / 本会话允许 / 写入项目规则 / 拒绝。
- **数据**：写前快照与 `/guard-undo` 回滚；审计 `audit.jsonl`（凭据脱敏、按大小轮转）与 `/guard-log` 查询。
- **配置**：JSONC 解析、`policy.schema.json` 编辑器补全、`baseline` / `strict` / `off` 模板、设置页（开关、数值、模板、循环检测）。
- **防护**：循环检测（同调用重复 N 次转为 `ask`）、会话授权 TTL 与次数上限、`enforce: false` 试运行、`denyTools`。
- **命令**：`/guard-test` 试算判定、`/guard-policy` 热改策略、`/guard-log`、`/guard-undo`。
- **项目策略**：`.dsh/guard-policy.json` 沿目录树向上叠加，按 key 深合并，支持用 `null` 删除继承的规则。

### 修复

- 项目层 `tools.<name>` 曾整表替换而非合并，一条项目 `allow` 会顶掉全局整张表。
- `null` 删除规则曾被 `validate` 判为无效，导致整份项目文件被跳过。
- `{ kind: 'ask' }` 在完全权限档下被 DSH approval 自动放行；现由 `dialog` / `question` 自行处置。
- 审批卡片的相对链接被 Markdown 渲染器丢弃，改为绝对地址（`webBase`）。
- 数字输入框的步进按钮挤压数值、两个下拉的箭头位置不一致。
