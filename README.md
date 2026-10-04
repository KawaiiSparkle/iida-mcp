# iida-mcp

[中文](README.md) | [English](README_EN.md)

![iida-mcp capability matrix](arts/iida-mcp-capability-matrix.svg)

`iida-mcp` 是一个 IDA Pro 插件，通过本地 HTTP MCP 服务暴露当前 IDB 的静态分析能力。

该 MCP 主要在 x86/x86-64 架构可执行文件及对应 IDA 能力上测试。核心 IDA API 工具、`disasm_bytes` 和 `patch_asm` 同时支持 ARMv8-A/AArch64（`arm64`、`aarch64`、`armv8`、`armv8a`、`armv8-a`）。ARM32/Thumb 目前属于尽力支持范围。

- 77 个 MCP 工具
- 已在 IDA 9.3 验证；IDA 8+/9.x API 兼容尽力保持
- 支持多 IDA 实例自动路由
- 可选 Windows 内核驱动能力
- 快捷键：`Alt+Shift+I`

## 功能

- 文件信息、原始字节、PE/ELF 解析
- 函数、反汇编、控制流图、交叉引用、调用树
- Hex-Rays 反编译、函数参数、局部变量
- 结构体、枚举、本地类型、类型化读取
- 名称、字符串、字节模式、立即数搜索
- 重命名、注释、类型、补丁、书签、批量操作
- 可选内核内存读取、内核模块枚举、IDA 地址到运行时地址映射

## 安装

把整个插件目录复制到 IDA 的 `plugins/` 目录。IDA 9.x/HCLI 插件元数据由 `ida-plugin.json` 描述：

```text
plugins/
  iida_mcp/
    ida-plugin.json
    iida.py
    iida_core/
      __init__.py
      cache.py
      kdriver.py
      protocol.py
      registry.py
      router.py
      server.py
      thread_safe.py
      tools.py
      worker.py
```

## 使用

1. 在 IDA 中打开目标文件。
2. 点击 `Edit > Plugins > iida-mcp`，或按 `Alt+Shift+I` 启动。
3. 第一个启动的 IDA 实例监听 `0.0.0.0:13897`，可通过本机回环地址或主机网卡 IP 访问；后续 IDA 实例自动作为 Worker 接入。
4. 再次点击菜单项或再次按 `Alt+Shift+I`，关闭当前 IDA 实例中的 iida-mcp 服务/连接。
5. 单 IDB 时工具参数 `f` 可省略；多 IDB 时先调用 `list_files`，再用返回的 file id 指定 `f`。

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
| `13897` | MCP HTTP 服务，监听所有网卡 |
| `13898` | 内部 Worker 通信，仅本机 |
| `13899` | 多 IDA 实例选主锁，仅本机 |
