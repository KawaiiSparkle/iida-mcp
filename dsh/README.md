# DSH（DeepSeek Harness）MCP bridge

这个目录把 iida-mcp 接进内置的 DSH（Tauri Extension）里，配好之后**新开的会话**可以直接调用 IDA：

| MCP server | 传输 | 端点 |
|---|---|---|
| `iida` | streamable HTTP | `http://127.0.0.1:13897/mcp`（插件自带服务，谁开着 IDA 就连谁） |
| `ida_auto` | stdio | `<repo>/tools/ida_auto_mcp/server.py`（负责启动/驱动 IDA） |

工具名形如 `mcp__iida__decompile`、`mcp__ida_auto__ida_launch`。典型用法是先 `mcp__ida_auto__ida_launch` 拉起实例（可带 `platform`/`load_addr`/`entry`/`file_type`），拿到 `port`/`fid` 后再用 `mcp__ida_auto__ida_call` 或直接的 `mcp__iida__*` 工具做分析。

## 安装

DSH 的 profile 把 bundle 列表写在 `%USERPROFILE%\.dsh\profiles\<profile>\package.json` 的 `dsh.profile.bundles` 里，每个 bundle 通过自己的 `package.json` 的 `dsh.bundle.patch` 指向一个 cordis 补丁文件。两条路可以选：

### 方式一：直接写进 profile 补丁层（推荐，无需装包）

把 `cordis.patch.yml` 里的 `- insert:` 段原样追加到

```text
%USERPROFILE%\.dsh\profiles\tauri\cordis.patch.yml
```

这个文件是 DSH 明确留给用户的补丁层（"Edit cordis.patch.yml, not this file"），**保存即热生效**：DSH 会立刻把两个 MCP 客户端拉起来，不必重启 Host，也不必跑 `pnpm install`。

> 本机实测：追加后 DSH 立即启动了 stdio 子进程
> `python.exe <repo>/tools/ida_auto_mcp/server.py`，`list_mcp_resources(server="ida_auto")` 返回成功。

### 方式二：作为独立 bundle 安装

把本目录放到任意位置，然后：

```text
plugin_manager install_bundle link:<本目录绝对路径>
```

注意：`install_bundle` 会触发 profile 的 `pnpm install`，如果 profile 里的其他依赖命中 registry 的 `minimumReleaseAge` 策略（例如某个包刚发布几小时），整次安装会被拒绝，和本插件无关。这种情况下用方式一。

## 验证

1. `mcp__ida_auto__ida_switches` —— 应返回 30 个 IDA 命令行开关，说明 stdio MCP 活着；
2. `mcp__ida_auto__ida_launch` `{"input_path": "<某个 exe/dll>"}` —— 应返回 `pid`/`port`/`fid`/`arch`/`bits`/`analysis_done`；
3. `mcp__ida_auto__ida_call` `{"tool": "list_functions"}` —— 开始真正的分析；
4. `mcp__iida__*` 直连工具有效（此时 13897 上已有实例）；
5. `mcp__ida_auto__ida_close` —— 结束实例（进程退出、标记文件清理干净）。

不需要人工点任何菜单：`ida.exe -A -S<iida_autostart.py>` 会在无窗口模式下自动加载二进制、跑完 auto-analysis、开好 HTTP MCP 服务，并把 `ready_<pid>.json` 写到 `%APPDATA%\Hex-Rays\IDA Pro\mcp\instances`。
