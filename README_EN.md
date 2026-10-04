# iida-mcp

[Chinese](README.md) | [English](README_EN.md)

![iida-mcp capability matrix](arts/iida-mcp-capability-matrix.svg)

`iida-mcp` is an IDA Pro plugin that exposes the current IDB through a local HTTP MCP server.

This MCP is primarily tested on x86/x86-64 executables and the corresponding IDA capabilities. Core IDA API tools, `disasm_bytes`, and `patch_asm` also support ARMv8-A/AArch64 (`arm64`, `aarch64`, `armv8`, `armv8a`, `armv8-a`). ARM32/Thumb is currently best-effort.

- 77 MCP tools
- Verified on IDA 9.3; IDA 8+/9.x API compatibility is kept best-effort
- Multi-IDA instance routing
- Optional Windows kernel driver support
- Hotkey: `Alt+Shift+I`

## Overview

- File metadata, raw bytes, PE/ELF parsing
- Functions, disassembly, CFG, xrefs, call trees
- Hex-Rays pseudocode, arguments, local variables
- Structs, enums, local types, typed reads
- Name, string, byte-pattern, and immediate searches
- Renaming, comments, types, patches, bookmarks, batch operations
- Optional kernel memory reads, kernel module enumeration, and IDA-to-runtime address mapping

## Installation

Copy the whole plugin directory into IDA's `plugins/` directory. IDA 9.x/HCLI plugin metadata is described by `ida-plugin.json`:

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

## Usage

1. Open a target file in IDA.
2. Start the plugin from `Edit > Plugins > iida-mcp`, or press `Alt+Shift+I`.
3. The first active IDA instance listens on `0.0.0.0:13897`, so it can be reached through loopback or a host network-interface IP; later instances join as Workers.
4. Trigger the menu item or hotkey again to stop iida-mcp in the current IDA instance.
5. With one IDB, the `f` parameter can be omitted. With multiple IDBs, call `list_files` and pass the returned file id as `f`.

## MCP Client Configuration

Endpoint:

```text
http://127.0.0.1:13897/mcp
```

When connecting from another machine, replace `127.0.0.1` with the IDA host IP, for example:

```text
http://192.168.153.1:13897/mcp
```

For clients that support HTTP/Streamable HTTP MCP servers, add a remote MCP server and point it to the endpoint above.

Generic example:

```json
{
  "mcpServers": {
    "iida": {
      "url": "http://127.0.0.1:13897/mcp"
    }
  }
}
```

Client-specific field names may vary. The required target is the local HTTP MCP endpoint above.

Note: the MCP HTTP server currently has no authentication and listens on all network interfaces. Remote clients can call renaming, commenting, type-editing, and patch-writing tools; the plugin also auto-confirms blocking IDA dialogs. Use it only on trusted networks, or restrict access with the local firewall.

Compatibility notes:

- `set_comment` keeps the old behavior and only writes disassembly comments. Use `set_pseudocode_comment` when a Hex-Rays pseudocode comment is needed.
- `parse_elf` returns a compact metadata/dependency view by default; pass `detail=full` to include sampled sections, dynamic entries, symbols, and relocations.

## Dependencies

The core plugin uses IDA's bundled IDAPython and the Python standard library.

- Decompiler tools require Hex-Rays Decompiler.
- `disasm_bytes` requires `capstone` in IDA's Python environment. If missing, it returns `capstone not installed (pip install capstone)`.
- `patch_asm` requires `keystone-engine` in IDA's Python environment. AArch64 accepts aliases such as `arm64`, `aarch64`, and `armv8a`; sample assembly includes `nop`, `ret`, and `mov x0, #1`.
- HCLI installs declare `capstone` and `keystone-engine` in `ida-plugin.json` so the full tool set is available.
- Kernel tools require the `iida-mcp-ioctl` driver.

## Kernel Driver

The `driver/` directory contains the `iida-mcp-ioctl` Windows kernel driver source. It provides:

- Kernel memory reads
- Kernel module listing
- Module base lookup by name

Building requires Visual Studio Build Tools and WDK. `driver/build.bat` uses the `MSVC`, `WDK`, and `SDK_VER` environment variables when set, otherwise it tries to detect standard installation paths.

A prebuilt `iida-mcp-ioctl.sys` is included under `driver/`. Loading it requires appropriate signing and system policy configuration. If the driver is not loaded, kernel tools return a clear error.

## Ports

| Port | Purpose |
|------|---------|
| `13897` | MCP HTTP server, listens on all network interfaces |
| `13898` | Internal Worker communication, loopback only |
| `13899` | Multi-IDA master election lock, loopback only |
