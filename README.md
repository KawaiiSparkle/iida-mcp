# iida-mcp

[中文](README.md) | [English](README_EN.md)

![iida-mcp capability matrix](arts/iida-mcp-capability-matrix.svg)

`iida-mcp` 是一个 IDA Pro 插件，通过本地 HTTP MCP 服务暴露当前 IDB 的静态分析能力。

该 MCP 主要在 x86/x86-64 架构可执行文件及对应 IDA 能力上测试。核心 IDA API 工具、`disasm_bytes` 和 `patch_asm` 同时支持 ARMv8-A/AArch64（`arm64`、`aarch64`、`armv8`、`armv8a`、`armv8-a`）。ARM32/Thumb 目前属于尽力支持范围。

- 84 个 MCP 工具
- 已在 IDA 9.3 / 9.4 / 9.5 验证（9.5 使用 IDA 9.5.261001 + Python 3.14.8 实测）；IDA 8+/9.x API 兼容尽力保持
- 支持多 IDA 实例自动路由
- **打开文件即自动开服**（无需手动点菜单，`-A` 无窗口模式同样生效；服务会先等自动分析结束再启动，避免把分析卡死）
- **可被命令行/AI 全自动拉起**（`tools/ida_auto_mcp` 提供 `ida_auto` MCP，按平台/加载地址/入口点自动加载二进制）
- 可选 Windows 内核驱动能力
- 快捷键：`Alt+Shift+I`

## 功能

- 文件信息、原始字节、PE/ELF 解析
- 函数、反汇编、控制流图、交叉引用、调用树
- Hex-Rays 反编译、函数参数、局部变量
- 结构体、枚举、本地类型、类型化读取
- 名称、字符串、字节模式、立即数搜索
- 重命名、注释、类型、补丁、书签、批量操作
- 会话生命周期：插件状态、分析进度、保存/关闭数据库、退出 IDA、IDA 命令行开关目录
- 可选内核内存读取、内核模块枚举、IDA 地址到运行时地址映射

## 安装

把整个插件目录复制到 IDA 的 `plugins/` 目录。IDA 9.x/HCLI 插件元数据由 `ida-plugin.json` 描述：

```text
plugins/
  iida-mcp/
    ida-plugin.json
    iida.py
    iida_autostart.py        # -S 启动脚本（无窗口自动开服）
    iida_core/
      __init__.py
      cache.py
      kdriver.py
      lifecycle.py           # 会话生命周期工具
      protocol.py
      pump.py                # 主线程 pump（无窗口模式下派发 IDA API 调用）
      registry.py
      router.py
      server.py
      thread_safe.py
      tools.py
      worker.py
    tools/
      ida_auto_mcp/          # ida-auto：stdio MCP，负责启动/驱动 IDA
      ida_cli_switches.json  # 扫描出的 IDA 命令行开关目录
      scan_ida_cli.py        # 开关目录生成/校验脚本
```

IDA 9.4 会同时扫描 `<IDA>\plugins` 与 `%APPDATA%\Hex-Rays\IDA Pro\plugins`。两处都安装时插件有防重复保护：后加载的副本会检测到 `iida_core.ACTIVE_PLUGIN` 已被占用并直接退出（日志里记录 `duplicate plugin copy ignored`）。只装一处也可以。

## 使用

1. 在 IDA 中打开目标文件。
2. 点击 `Edit > Plugins > iida-mcp`，或按 `Alt+Shift+I` 启动/关闭。插件默认在文件加载后自动启动（见下文「自动启动」），菜单/快捷键用于手动启停。
3. 第一个启动的 IDA 实例监听 `0.0.0.0:13897`，可通过本机回环地址或主机网卡 IP 访问；后续 IDA 实例自动作为 Worker 接入。
4. 再次点击菜单项或再次按 `Alt+Shift+I`，关闭当前 IDA 实例中的 iida-mcp 服务/连接。
5. 单 IDB 时工具参数 `f` 可省略；多 IDB 时先调用 `list_files`，再用返回的 file id 指定 `f`。

## 自动启动

两种触发方式：

1. **命令行 `-A -S<iida_autostart.py>`（已实测，推荐，无人值守流水线走这条）**：启动脚本在主线程就绪后直接激活服务，`-A` 自治模式会自动应答 IDA 的阻塞提示框。IDA 9.5 上实测约 5 秒内 `Master on :13897`。
2. **GUI 打开文件（定时器路径）**：`install_startup_watch()` 注册 800ms 定时器，数据库就绪后调用 `_start('autostart')`；并安装 `UI_Hooks.ready_to_run()` 作为补充触发点；两路都失效时（极早阶段、`-A` 无窗口模式等）由 `_thread_autostart(delay=3.0)` 兜底。

关于方式 2 的实测边界（IDA 9.5.261001）：裸 `ida.exe <file>` 打开一个**已存在 `.i64`**（尤其旧格式库）时会先弹模态确认框（窗口标题变成 `Please confirm`），主线程停在模态循环里，定时器与 `ready_to_run` 都不会跑，服务不会启动；打开**全新文件**时实测同样未在 120 秒内起服务。因此无人值守场景请一律使用方式 1，或先让 IDA 无人值守地打开数据库再挂客户端。

需要手动关闭自动启动时设 `IIDA_MCP_AUTOSTART=0`（或 `IDA_MCP_AUTOSTART=0`），然后在 IDA 中手动 `Alt+Shift+I`。

> **为什么必须等分析结束**：在全新（从未分析过的）数据库上，如果服务在自动分析仍在进行时就连网（自建分析缓存、选主、bind），会饿死 `ida_auto.auto_wait()` 驱动的分析本身，整个启动挂死、永远不写实例文件。实测（IDA 9.5.261001）：`auto_wait()` 在插件空闲时约 1 秒返回，在泵/服务已激活时永不返回。已分析过的数据库会掩盖这个问题（`auto_wait()` 立即返回）。因此 `-S` 脚本先等分析、后接管主线程，插件侧所有自动启动入口也会先确认分析已结束（等待上限 300 秒，超时仍会启动以免彻底失活）。

排障日志（同时写 IDA 消息窗口与文件）：`%APPDATA%\Hex-Rays\IDA Pro\mcp\instances\iida-mcp.log`。

实例标记文件（`ida-pro-mcp` 兼容命名，供外部工具发现实例）：

| 文件 | 内容 |
|------|------|
| `instance_<port>.json` | `host` / `port` / `pid` / `binary` / `idb_path` / `started_at` / `backend` |
| `boot_<pid>.json` | `-S` 脚本启动时的原始 `argv`、IDA 版本、状态目录 |
| `ready_<pid>.json` | `port` / `fid` / `name` / `arch` / `bits` / `input_path` / `idb_path` / `analysis_done` |

健康检查：

```text
GET http://127.0.0.1:13897/health    # 或 /healthz、/
```

返回 `ok` / `server` / `version` / `port` / `pid` / `python` / `uptime_s` / `analysis_done` / `hexrays_ready` / `files`。

端口从 `13897` 起向上扫描（最多 100 个，跳过内部端口 13898 与选主端口 13899），因此多个 IDA 实例可以共存。

## 命令行全自动流水线

`tools/ida_auto_mcp/server.py` 是一个**只依赖 Python 标准库**的 stdio MCP server（名字 `ida-auto`），负责在没有人操作的情况下把 IDA 拉起来：

| 工具 | 作用 |
|------|------|
| `ida_launch` | 启动 `ida.exe -A -S<iida_autostart.py> …`，按平台/加载地址/入口点/文件类型加载二进制，等 MCP 服务就绪后返回 `pid`/`port`/`fid`/`arch`/`bits`/`analysis_done` |
| `ida_switches` | 返回扫描出的 IDA 命令行开关目录 |
| `ida_instances` / `ida_status` | 列出实例 / 查实例健康 |
| `ida_tools` | 列出该实例暴露的工具（当前 84 个） |
| `ida_call` | 在任意实例上调用任意 iida-mcp 工具 |
| `ida_close` | 保存并退出实例（`quit_ida` → 超时兜底强制结束 → 清理标记文件） |

`ida_launch` 参数：`input_path`、`platform`、`load_addr`、`entry`、`file_type`、`out_db`、`compiler`、`log_file`、`directives`、`extra_switches`、`ida_exe`、`timeout`、`quit_after`、`fresh_db`、`script`。

命令行组装要点：

- `ida.exe -A -S<script> [-p<平台>] [-b<加载段>] [-i<入口>] [-T<文件类型>] [-o<输出库>] [-C<编译器>] [-L<日志>] [-d<指令>] … <输入>`
- `load_addr` 按 IDA 的 `-b` 语义换算成"16 字节段"十六进制（`addr // 16`）；
- **所有可能含空格的参数值都会加引号**：IDA 会重新解析自己的原始命令行并按空格切分，未加引号的 `-SC:\Users\...\IDA Pro\...` 会被拆成两个参数，表现为 `FATAL ERROR: Can't find input file`；
- 已存在 `.i64/.idb` 时默认直接打开数据库（避开阻塞式"数据库已存在"弹窗），`fresh_db=true` 时用 `-o` 强制新建。

手动调用：

```powershell
python -u tools\ida_auto_mcp\selftest.py <file>   # 端到端自检：11 步，退出码 0 全通过
python tools\ida_auto_mcp\server.py               # 由 MCP 客户端以 stdio 方式拉起
```

MCP 客户端配置（`ida_auto`，stdio）：

```json
{
  "mcpServers": {
    "ida_auto": {
      "command": "python",
      "args": ["<repo>/tools/ida_auto_mcp/server.py"],
      "env": { "IIDA_MCP_STATE_DIR": "%APPDATA%\\Hex-Rays\\IDA Pro\\mcp\\instances" }
    }
  }
}
```

在内置 DSH（Tauri Extension）里，这两行写在 profile 补丁层 `%USERPROFILE%\.dsh\profiles\tauri\cordis.patch.yml`：`iida`（streamable-http，`http://127.0.0.1:13897/mcp`）与 `ida_auto`（stdio，上面的 python 命令）。可复用的 bundle 模板与安装/验证步骤见 [`dsh/`](dsh/README.md)。

### IDA 命令行开关目录

`tools/scan_ida_cli.py` 通过 `ida.exe --help` / `-?` 解析出全部开关与 `-z` 调试位：

```powershell
python tools\scan_ida_cli.py            # 打印摘要
python tools\scan_ida_cli.py --json     # 重新生成 tools/ida_cli_switches.json
python tools\scan_ida_cli.py --verify   # 逐个实测确认（当前 30/30）
```

会话内也可以直接用 `get_cli_switches` 工具读取（`detail=full` 返回完整目录）。

## 环境变量

| 变量 | 作用 |
|------|------|
| `IIDA_MCP_AUTOSTART` / `IDA_MCP_AUTOSTART` | `0` 关闭"打开文件即开服" |
| `IIDA_MCP_STATE_DIR` | 覆盖实例标记目录（插件、`-S` 脚本、`lifecycle` 三处一致生效；实测隔离可用） |
| `IIDA_MCP_AUTOSTART_SCRIPT` | 由 `-S` 脚本设置，标记"主线程已被启动脚本接管" |
| `IIDA_MCP_READY_TIMEOUT` | `-S` 等待服务就绪的超时（默认 1800s） |
| `IIDA_MCP_QUIT_AFTER` | 就绪后自动退出（秒数或 `now`） |
| `IIDA_MCP_PUMP_WAIT` | 等待主线程 pump 的秒数（默认 20s） |
| `IIDA_MCP_PORT` / `IDA_MCP_PORT` | 覆盖起始监听端口 |
| `IIDA_MCP_SCRIPT_PATH` | 覆盖 launcher 使用的 `iida_autostart.py` 路径 |
| `IIDA_MCP_IDA_DIR` | 覆盖插件目录探测（找 `plugins/iida-mcp`） |
| `IIDA_MCP_IDA` / `IDA_DIR` / `IDADIR` / `IDA_PATH` | 覆盖 `ida.exe` 探测 |
| `IIDA_MCP_TEST_BINARY` | 覆盖 `selftest.py` 的默认测试样本 |

## MCP 客户端配置

服务端点：

```text
http://127.0.0.1:13897/mcp
```

如果从其他机器连接，请把 `127.0.0.1` 换成运行 IDA 的主机 IP，例如：

```text
http://192.168.153.1:13897/mcp
```

对支持 HTTP/Streamable HTTP MCP server 的客户端，配置一个远程 MCP server，并把 URL 指向上面的地址即可。

通用示例：

```json
{
  "mcpServers": {
    "iida": {
      "url": "http://127.0.0.1:13897/mcp"
    }
  }
}
```

不同终端或客户端的字段名可能略有差异；核心是使用 HTTP MCP 连接到 `http://127.0.0.1:13897/mcp`。

注意：MCP HTTP 服务当前不做鉴权，并监听所有网卡。远程客户端可以调用重命名、注释、类型修改和补丁写入类工具；插件还会自动确认 IDA 的阻塞提示框。只应在可信网络中使用，或通过本机防火墙限制访问来源。

兼容性说明：

- `set_comment` 保持旧行为，只写反汇编注释；需要写入 Hex-Rays 伪代码注释时使用 `set_pseudocode_comment`。
- `parse_elf` 默认返回精简元数据和依赖信息；传 `detail=full` 才返回 sections、dynamic、symbols、relocations 等采样字段。

## 依赖

插件主体只依赖 IDA 自带的 IDAPython 和 Python 标准库。

- 反编译相关工具需要 Hex-Rays Decompiler。
- `disasm_bytes` 需要在 IDA 的 Python 环境中安装 `capstone`。未安装时会返回 `capstone not installed (pip install capstone)`。
- `patch_asm` 需要在 IDA 的 Python 环境中安装 `keystone-engine`。AArch64 支持 `arm64`、`aarch64`、`armv8a` 等别名，示例汇编包括 `nop`、`ret`、`mov x0, #1`。
- 通过 HCLI 安装时，`ida-plugin.json` 会声明并安装 `capstone` 与 `keystone-engine`，以覆盖完整工具集。
- 内核相关工具需要加载 `iida-mcp-ioctl` 驱动。

## 内核驱动

`driver/` 目录包含 `iida-mcp-ioctl` Windows 内核驱动源码，提供：

- 读取内核内存
- 获取内核模块列表
- 按名称查询模块基址

编译需要 Visual Studio Build Tools 和 WDK。`driver/build.bat` 会优先使用 `MSVC`、`WDK`、`SDK_VER` 环境变量；未设置时会尝试从标准安装路径自动探测。

预编译的 `iida-mcp-ioctl.sys` 位于 `driver/`。加载驱动需要自行处理签名和系统策略。未加载驱动时，内核工具会返回明确错误。

## 端口

| 端口 | 用途 |
|------|------|
| `13897` | MCP HTTP 服务起始端口，监听所有网卡；被占用时向上扫描最多 100 个 |
| `13898` | 内部 Worker 通信，仅本机 |
| `13899` | 多 IDA 实例选主锁，仅本机 |
