#!/usr/bin/env python3
"""ida-auto: a stdio MCP server that launches and drives IDA instances.

This is the "no human in the loop" half of iida-mcp. It is a pure standard
library program (no IDA, no third-party packages) so the harness can always
start it:

  * ``ida_launch``   - spawn ``ida.exe -A -S<iida_autostart.py> ...`` to load a
                       binary (optionally at a given platform / load address /
                       entry point / file type), wait for the iida-mcp HTTP
                       server to come up and report pid, port, fid, arch, bits;
  * ``ida_switches`` - the scanned catalog of every IDA command line switch;
  * ``ida_instances``- live instances (instance files + live /health probes);
  * ``ida_status``   - health of one instance;
  * ``ida_tools``    - tool catalog exposed by an instance;
  * ``ida_call``     - invoke any iida-mcp tool on an instance over HTTP;
  * ``ida_close``    - save and quit an instance.

Instance discovery uses the same directory as the plugin:
``%APPDATA%\\Hex-Rays\\IDA Pro\\mcp\\instances`` (override with
``IIDA_MCP_STATE_DIR``).
"""

import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

PROTOCOL_VERSION = '2024-11-05'
SERVER_NAME = 'ida-auto'
SERVER_VERSION = '0.5.1'
DEFAULT_MCP_PORT = 13897
READY_TIMEOUT_DEFAULT = 600.0

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
CATALOG_PATH = os.path.join(REPO_ROOT, 'tools', 'ida_cli_switches.json')
AUTOSTART_SCRIPT = os.path.join(REPO_ROOT, 'iida_autostart.py')


def autostart_candidates(ida_exe=None):
    """Possible locations of ``iida_autostart.py``, best first.

    IDA 9.4 loads Python plugin bundles from the *per-user* plugin directory, so
    the installed copy there must win: the ``-S`` script has to import the same
    ``iida_core`` package as the running plugin, otherwise the pump and the
    plugin would use two different module objects.
    """
    seen = []
    override = os.environ.get('IIDA_MCP_SCRIPT_PATH')
    if override:
        seen.append(override)
    appdata = os.environ.get('APPDATA')
    if appdata:
        seen.append(os.path.join(appdata, 'Hex-Rays', 'IDA Pro', 'plugins',
                                 'iida-mcp', 'iida_autostart.py'))
    if ida_exe:
        seen.append(os.path.join(os.path.dirname(ida_exe), 'plugins',
                                 'iida-mcp', 'iida_autostart.py'))
    for root in (os.environ.get('IIDA_MCP_IDA_DIR'), os.environ.get('IDA_DIR'),
                 os.environ.get('IDADIR'), r'C:\Program Files\IDAPro'):
        if root:
            seen.append(os.path.join(root, 'plugins', 'iida-mcp', 'iida_autostart.py'))
    seen.append(AUTOSTART_SCRIPT)
    unique = []
    for item in seen:
        if item and item not in unique:
            unique.append(item)
    return unique


def resolve_autostart_script(explicit=None, ida_exe=None):
    """First existing autostart script, or the repo copy as a fallback."""
    for candidate in ([explicit] if explicit else []) + autostart_candidates(ida_exe):
        if candidate and os.path.isfile(candidate):
            return candidate
    return AUTOSTART_SCRIPT


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------
def state_dir():
    override = os.environ.get('IIDA_MCP_STATE_DIR')
    if override:
        path = override
    else:
        appdata = os.environ.get('APPDATA')
        if appdata:
            path = os.path.join(appdata, 'Hex-Rays', 'IDA Pro', 'mcp', 'instances')
        else:
            base = os.environ.get('TEMP') or os.environ.get('TMP') or os.path.expanduser('~')
            path = os.path.join(base, 'iida-mcp-instances')
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass
    return path


def find_ida(explicit=None):
    """Locate ida.exe (GUI build: plugins load normally under -A -S)."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    for key in ('IIDA_MCP_IDA', 'IDA_DIR', 'IDADIR'):
        value = os.environ.get(key)
        if not value:
            continue
        if value.lower().endswith('.exe'):
            candidates.append(value)
        else:
            candidates.append(os.path.join(value, 'ida.exe'))
    ida_path = os.environ.get('IDA_PATH')
    if ida_path and ida_path.lower().endswith('.exe'):
        candidates.append(ida_path)
    candidates.append(r'C:\Program Files\IDAPro\ida.exe')
    candidates.extend(sorted(glob.glob(r'C:\Program Files\IDA*\ida.exe')))
    found = shutil.which('ida.exe') or shutil.which('ida')
    if found:
        candidates.append(found)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return None


# --------------------------------------------------------------------------
# instance helpers
# --------------------------------------------------------------------------
def read_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            return json.load(handle)
    except Exception:
        return None


def pid_alive(pid):
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0:
        return False
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong(0)
        ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    except Exception:
        try:
            os.kill(pid, 0)
            return True
        except Exception:
            return False


def terminate_process(pid, timeout=10.0):
    """Force-kill an IDA process (and its children). Returns True when it died."""
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0 or not pid_alive(pid):
        return False
    if os.name == 'nt':
        try:
            subprocess.run(['taskkill', '/PID', str(pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        except Exception:
            pass
    else:
        try:
            os.kill(pid, 9)
        except Exception:
            pass
    deadline = time.time() + timeout
    while time.time() < deadline and pid_alive(pid):
        time.sleep(0.25)
    return not pid_alive(pid)


def cleanup_state(pid, port=None):
    """Drop the boot/ready/instance markers that belong to a dead instance."""
    directory = state_dir()
    try:
        names = os.listdir(directory)
    except Exception:
        return 0
    try:
        pid = int(pid)
    except Exception:
        pid = None
    try:
        port = int(port) if port is not None else None
    except Exception:
        port = None
    removed = 0
    for name in names:
        path = os.path.join(directory, name)
        if pid is not None and name in ('boot_%d.json' % pid, 'ready_%d.json' % pid):
            try:
                os.remove(path)
                removed += 1
            except Exception:
                pass
            continue
        if not (name.startswith('instance_') or name.startswith('worker_')):
            continue
        payload = read_json(path) or {}
        try:
            same_pid = pid is not None and int(payload.get('pid') or 0) == pid
        except Exception:
            same_pid = False
        try:
            same_port = port is not None and int(payload.get('port') or 0) == port
        except Exception:
            same_port = False
        if same_pid or same_port:
            try:
                os.remove(path)
                removed += 1
            except Exception:
                pass
    return removed


def list_instances():
    directory = state_dir()
    instances = []
    try:
        names = os.listdir(directory)
    except Exception:
        return instances
    for name in sorted(names):
        if not (name.startswith('instance_') and name.endswith('.json')):
            continue
        data = read_json(os.path.join(directory, name))
        if not data:
            continue
        data['_instance_file'] = os.path.join(directory, name)
        data['_alive'] = pid_alive(data.get('pid'))
        ready = read_json(os.path.join(directory, 'ready_%s.json' % data.get('pid')))
        data['_ready'] = ready
        if ready:
            data['analysis_done'] = ready.get('analysis_done')
        instances.append(data)
    return instances


def http_json(url, payload=None, timeout=30.0):
    data = None if payload is None else json.dumps(payload).encode('utf-8')
    request = urllib.request.Request(url, data=data, method='POST' if payload is not None else 'GET')
    request.add_header('Content-Type', 'application/json')
    request.add_header('Accept', 'application/json, text/event-stream')
    request.add_header('MCP-Protocol-Version', PROTOCOL_VERSION)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode('utf-8', 'replace')
    body = body.strip()
    if body.startswith('event:') or body.startswith('data:'):
        chunks = [line[5:].strip() for line in body.splitlines() if line.startswith('data:')]
        body = chunks[-1] if chunks else ''
    if not body:
        return None
    return json.loads(body)


def instance_url(instance, path='/mcp'):
    host = instance.get('host') or '127.0.0.1'
    if host in ('0.0.0.0', '::'):
        host = '127.0.0.1'
    return 'http://%s:%s%s' % (host, instance.get('port'), path)


def resolve_instance(ref=None, live_only=True):
    """Resolve 'latest'/'pid:123'/'port:13897'/fid/filename to an instance dict."""
    instances = list_instances()
    if live_only:
        instances = [item for item in instances if item.get('_alive')]
    if not instances:
        return None, 'no live IDA instances; call ida_launch first'
    if ref in (None, '', 'latest', 'any'):
        instances.sort(key=lambda item: float(item.get('started_at') or 0))
        return instances[0], None
    text = str(ref).strip()
    if text.startswith('pid:'):
        wanted = text[4:]
        for item in instances:
            if str(item.get('pid')) == wanted:
                return item, None
    elif text.startswith('port:'):
        wanted = text[5:]
        for item in instances:
            if str(item.get('port')) == wanted:
                return item, None
    for item in instances:
        for key in ('fid', 'binary', 'name', 'idb_path', 'path'):
            value = item.get(key)
            if value and (value == text or os.path.basename(str(value)) == text):
                return item, None
    return None, 'no instance matching %r' % ref


def rpc(url, method, params, timeout=60.0):
    payload = {'jsonrpc': '2.0', 'id': int(time.time() * 1000) % 1000000, 'method': method, 'params': params or {}}
    response = http_json(url, payload, timeout=timeout)
    if not response:
        return None
    if 'error' in response:
        raise RuntimeError('MCP error: %s' % json.dumps(response['error'], ensure_ascii=False))
    return response.get('result')


def call_tool(instance, tool, args=None, timeout=120.0):
    result = rpc(instance_url(instance), 'tools/call', {'name': tool, 'arguments': args or {}}, timeout=timeout)
    if result is None:
        return None
    if result.get('isError'):
        raise RuntimeError('tool %s failed: %s' % (tool, result))
    content = result.get('content') or []
    texts = [item.get('text') for item in content if isinstance(item, dict) and item.get('type') == 'text']
    joined = '\n'.join(text for text in texts if text)
    try:
        return json.loads(joined)
    except Exception:
        return joined


def health(instance, timeout=5.0):
    try:
        return http_json(instance_url(instance, '/health'), None, timeout=timeout)
    except Exception as ex:
        return {'ok': False, 'error': str(ex)}


# --------------------------------------------------------------------------
# command line construction
# --------------------------------------------------------------------------
def existing_database(input_path):
    """Return the existing IDB for *input_path*, if any.

    IDA shows a modal "database already exists - overwrite?" confirmation when a
    binary with a sibling database is opened, and that dialog blocks the whole
    session (it is shown before plugins load, so nothing can dismiss it).  The
    launcher therefore opens the ``.i64`` directly to reuse it, or passes ``-o``
    to force a fresh database.
    """
    if not input_path:
        return None
    for suffix in ('.i64', '.idb'):
        if input_path.lower().endswith(suffix) and os.path.isfile(input_path):
            return input_path
    for suffix in ('.i64', '.idb'):
        candidate = input_path + suffix
        if os.path.isfile(candidate):
            return candidate
    return None


def quote_switch(value):
    """Quote a switch value the way IDA's own command-line parser expects.

    IDA re-parses its raw command line and splits on spaces even inside a
    subprocess argv element, so ``-SC:\\Users\\x\\IDA Pro\\plugins\\...`` makes it
    look for a *second input file* named ``Pro\\plugins\\...`` and abort with
    ``FATAL ERROR: Can't find input file``.  Embedding quotes in the argument
    keeps the path in one piece.
    """
    text = str(value)
    if not text:
        return text
    if any(ch in text for ch in ' \t'):
        return '"%s"' % text.replace('"', '\\"')
    return text


def build_command(ida_exe, input_path, platform=None, load_addr=None, entry=None, file_type=None,
                  out_db=None, compiler=None, log_file=None, directives=None, extra_switches=None,
                  script=None, fresh_db=False):
    command = [ida_exe, '-A']
    script_path = resolve_autostart_script(script, ida_exe)
    if script_path and os.path.isfile(script_path):
        command.append('-S%s' % quote_switch(script_path))
    if platform:
        command.append('-p%s' % quote_switch(platform))
    if load_addr:
        command.append('-b%s' % quote_switch(load_addr))
    if entry:
        command.append('-i%s' % quote_switch(entry))
    if file_type:
        command.append('-T%s' % quote_switch(file_type))
    if out_db:
        command.append('-o%s' % quote_switch(out_db))
    elif fresh_db:
        command.append('-o%s' % quote_switch(input_path + '.i64'))
    if compiler:
        command.append('-C%s' % quote_switch(compiler))
    if log_file:
        command.append('-L%s' % quote_switch(log_file))
    for directive in (directives or []):
        command.append('-d%s' % quote_switch(directive))
    for item in (extra_switches or []):
        item = str(item).strip()
        if item:
            item = item if item.startswith('-') else '-%s' % item
            command.append(quote_switch(item))
    target = input_path
    if not fresh_db and not out_db:
        db_path = existing_database(input_path)
        if db_path:
            # Opening the database directly reuses the previous analysis and
            # avoids the blocking "overwrite existing database?" dialog.
            target = db_path
    command.append(quote_switch(target))
    return command


def load_addr_to_switch(value):
    """IDA -b takes a hexadecimal count of 16-byte 'paragraphs'."""
    if value in (None, ''):
        return None
    text = str(value).strip()
    try:
        number = int(text, 16) if text.lower().startswith('0x') else int(text, 0)
    except Exception:
        return text
    return format(number // 16, 'x')


def spawn(command, env_overrides=None):
    env = os.environ.copy()
    for key, value in (env_overrides or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = str(value)
    flags = 0
    if hasattr(subprocess, 'CREATE_NEW_PROCESS_GROUP'):
        flags |= subprocess.CREATE_NEW_PROCESS_GROUP
    if hasattr(subprocess, 'DETACHED_PROCESS'):
        flags |= subprocess.DETACHED_PROCESS
    return subprocess.Popen(command, env=env, creationflags=flags, close_fds=True,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def wait_ready(pid, timeout=READY_TIMEOUT_DEFAULT, poll=0.5):
    directory = state_dir()
    ready_path = os.path.join(directory, 'ready_%d.json' % pid)
    deadline = time.time() + max(5.0, float(timeout))
    last_state = 'starting'
    while time.time() < deadline:
        ready = read_json(ready_path)
        if ready and ready.get('port'):
            return ready, None
        if not pid_alive(pid):
            return None, 'IDA process %d exited before the MCP server became ready (see boot_%d.json / ida.log)' % (pid, pid)
        boot = read_json(os.path.join(directory, 'boot_%d.json' % pid))
        last_state = 'analysis/server not ready yet' if boot else 'IDA still initializing'
        time.sleep(poll)
    return None, 'timed out after %ss waiting for the MCP server (%s); ready file: %s' % (int(timeout), last_state, ready_path)


def launch_summary(pid, command, ready=None):
    instance = None
    for item in list_instances():
        if str(item.get('pid')) == str(pid):
            instance = item
            break
    info = {
        'ok': True,
        'pid': pid,
        'command': command,
        'port': (ready or {}).get('port') or (instance or {}).get('port'),
        'fid': (ready or {}).get('fid') or (instance or {}).get('fid'),
        'arch': (instance or {}).get('arch'),
        'bits': (instance or {}).get('bits'),
        'binary': (instance or {}).get('binary'),
        'idb_path': (instance or {}).get('idb_path'),
        'analysis_done': (ready or {}).get('analysis_done'),
        'instance_file': (instance or {}).get('_instance_file'),
        'ready_file': os.path.join(state_dir(), 'ready_%d.json' % pid),
        'mcp_url': None,
        'health_url': None,
        'state_dir': state_dir(),
    }
    if info['port']:
        host = (instance or {}).get('host') or '127.0.0.1'
        if host in ('0.0.0.0', '::'):
            host = '127.0.0.1'
        info['mcp_url'] = 'http://%s:%s/mcp' % (host, info['port'])
        info['health_url'] = 'http://%s:%s/health' % (host, info['port'])
    return info


# --------------------------------------------------------------------------
# tool schemas
# --------------------------------------------------------------------------
def tool_definitions():
    return [
        {
            'name': 'ida_launch',
            'description': (
                'Launch IDA (ida.exe) on a binary and wait until its iida-mcp HTTP server is ready '
                '(no dialogs, no user interaction). Auto-loads the file, runs auto-analysis and returns '
                'pid/port/fid/arch/bits so the instance can be driven with ida_call. Use platform/load_addr/'
                'entry/file_type for raw or foreign binaries, extra_switches for anything else (see ida_switches).'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'input_path': {'type': 'string', 'description': 'absolute path of the binary/database to load'},
                    'platform': {'type': 'string', 'description': 'IDA processor name, e.g. x86, x64, arm, arm64, mips, ppc (default: auto-detect)'},
                    'load_addr': {'type': 'string', 'description': 'load base address (hex ok, e.g. 0x400000); converted to the -b paragraph form'},
                    'entry': {'type': 'string', 'description': 'entry point address (hex), maps to -i'},
                    'file_type': {'type': 'string', 'description': 'loader type prefix for -T, e.g. "ZIP:classes.dex", "PE", "ELF"'},
                    'out_db': {'type': 'string', 'description': 'output database path (-o, implies a fresh database)'},
                    'fresh_db': {'type': 'boolean', 'description': 'force a fresh database instead of reusing an existing .i64/.idb. Default false: an existing database is opened directly, which avoids IDA\'s blocking "database already exists" dialog'},
                    'compiler': {'type': 'string', 'description': 'compiler spec for -C, e.g. "gcc:gcc"'},
                    'log_file': {'type': 'string', 'description': 'IDA log file (-L)'},
                    'directives': {'type': 'array', 'items': {'type': 'string'}, 'description': 'config directives, each becomes -d<directive>'},
                    'extra_switches': {'type': 'array', 'items': {'type': 'string'}, 'description': 'extra raw switches, e.g. ["-R"] or ["-z40000"]'},
                    'ida_exe': {'type': 'string', 'description': 'explicit path to ida.exe (default: auto-detected)'},
                    'script': {'type': 'string', 'description': 'explicit path to iida_autostart.py (default: installed plugin copy, then repo copy)'},
                    'timeout': {'type': 'number', 'description': 'seconds to wait for readiness (default 600)'},
                    'quit_after': {'type': 'string', 'description': 'seconds to keep IDA alive after readiness, or "now". Omit to keep it running'},
                },
                'required': ['input_path'],
            },
        },
        {
            'name': 'ida_switches',
            'description': 'Catalog of IDA command-line switches (ida.exe/idat.exe) scanned from the local IDA install, including the -z debug bitmask and ready-made launch recipes.',
            'inputSchema': {
                'type': 'object',
                'properties': {'detail': {'type': 'string', 'description': 'summary (default) or full'}},
            },
        },
        {
            'name': 'ida_instances',
            'description': 'List IDA instances known to iida-mcp with liveness, port, fid, arch, bits, loaded binary and analysis state (live /health probe included).',
            'inputSchema': {'type': 'object', 'properties': {}},
        },
        {
            'name': 'ida_status',
            'description': 'Health/status of one IDA instance (default: the oldest live one).',
            'inputSchema': {
                'type': 'object',
                'properties': {'instance': {'type': 'string', 'description': 'latest | pid:123 | port:13897 | fid | binary name'}},
            },
        },
        {
            'name': 'ida_tools',
            'description': 'List the iida-mcp tools (name + description) exposed by one IDA instance.',
            'inputSchema': {
                'type': 'object',
                'properties': {'instance': {'type': 'string', 'description': 'latest | pid:123 | port:13897 | fid | binary name'}},
            },
        },
        {
            'name': 'ida_call',
            'description': (
                'Call one iida-mcp tool on a running IDA instance over HTTP, e.g. tool="decompile_function", '
                'args={"f":"<fid>","a":"0x401000"}. Use ida_tools to discover names and ida_status for the fid.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'tool': {'type': 'string', 'description': 'iida-mcp tool name'},
                    'args': {'type': 'object', 'description': 'tool arguments'},
                    'instance': {'type': 'string', 'description': 'latest | pid:123 | port:13897 | fid | binary name'},
                    'timeout': {'type': 'number', 'description': 'seconds (default 120)'},
                },
                'required': ['tool'],
            },
        },
        {
            'name': 'ida_close',
            'description': 'Save (optional) and quit a running IDA instance by calling its quit_ida tool.',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'instance': {'type': 'string', 'description': 'latest | pid:123 | port:13897 | fid | binary name'},
                    'save': {'type': 'boolean', 'description': 'save the database before quitting (default true)'},
                },
            },
        },
    ]


# --------------------------------------------------------------------------
# tool implementations
# --------------------------------------------------------------------------
def tool_ida_launch(args):
    input_path = args.get('input_path') or args.get('path')
    if not input_path:
        return {'ok': False, 'error': 'input_path is required'}
    input_path = os.path.abspath(os.path.expandvars(os.path.expanduser(input_path)))
    if not os.path.exists(input_path):
        return {'ok': False, 'error': 'file not found: %s' % input_path}
    ida_exe = find_ida(args.get('ida_exe'))
    if not ida_exe:
        return {'ok': False, 'error': 'ida.exe not found; set IDA_DIR or pass ida_exe'}
    script_path = resolve_autostart_script(args.get('script'), ida_exe)
    if not os.path.isfile(script_path):
        return {'ok': False, 'error': 'autostart script missing: %s' % script_path}

    command = build_command(
        ida_exe,
        input_path,
        platform=args.get('platform'),
        load_addr=load_addr_to_switch(args.get('load_addr')),
        entry=args.get('entry'),
        file_type=args.get('file_type'),
        out_db=args.get('out_db'),
        compiler=args.get('compiler'),
        log_file=args.get('log_file'),
        directives=args.get('directives'),
        extra_switches=args.get('extra_switches'),
        script=script_path,
        fresh_db=bool(args.get('fresh_db')),
    )
    overrides = {'IIDA_MCP_STATE_DIR': state_dir(), 'IIDA_MCP_AUTOSTART_SCRIPT': '1'}
    quit_after = args.get('quit_after')
    if quit_after is not None:
        overrides['IIDA_MCP_QUIT_AFTER'] = str(quit_after)
    try:
        process = spawn(command, overrides)
    except Exception as ex:
        return {'ok': False, 'error': 'could not start IDA: %s' % ex, 'command': command}
    timeout = args.get('timeout') or READY_TIMEOUT_DEFAULT
    ready, error = wait_ready(process.pid, timeout=timeout)
    if error:
        info = launch_summary(process.pid, command, None)
        info.update({'ok': False, 'error': error})
        return info
    info = launch_summary(process.pid, command, ready)
    info['health'] = health({'port': info['port'], 'host': '127.0.0.1'})
    return info


def tool_ida_switches(args):
    detail = (args.get('detail') or 'summary').lower()
    catalog = read_json(CATALOG_PATH)
    if not catalog:
        return {'ok': False, 'error': 'switch catalog not found at %s' % CATALOG_PATH}
    if detail == 'full':
        return catalog
    switches = []
    for entry in catalog.get('switches', []):
        item = {
            'switch': entry.get('switch'),
            'takes_value': entry.get('takes_value'),
            'description': entry.get('description'),
        }
        if entry.get('aliases'):
            item['aliases'] = entry['aliases']
        switches.append(item)
    return {
        'source': catalog.get('source'),
        'verified_on': catalog.get('verified_on'),
        'switches': switches,
        'debug_bits': catalog.get('debug_bits'),
        'usage_recipes': catalog.get('usage_recipes'),
    }


def tool_ida_instances(args):
    instances = []
    for item in list_instances():
        probe = health(item, timeout=2.0) if item.get('_alive') else {'ok': False, 'error': 'process not running'}
        instances.append({
            'pid': item.get('pid'),
            'port': item.get('port'),
            'alive': item.get('_alive'),
            'ready': bool(item.get('_ready')),
            'analysis_done': (item.get('_ready') or {}).get('analysis_done'),
            'fid': item.get('fid'),
            'binary': item.get('binary') or item.get('name'),
            'arch': item.get('arch'),
            'bits': item.get('bits'),
            'idb_path': item.get('idb_path'),
            'role': item.get('role'),
            'started_at': item.get('started_at'),
            'plugin_version': item.get('plugin_version'),
            'health': probe,
            'instance_file': item.get('_instance_file'),
        })
    return {'ok': True, 'state_dir': state_dir(), 'count': len(instances), 'instances': instances}


def tool_ida_status(args):
    instance, error = resolve_instance(args.get('instance'))
    if error:
        return {'ok': False, 'error': error}
    result = health(instance)
    return {'ok': bool(result.get('ok')), 'instance': {
        'pid': instance.get('pid'), 'port': instance.get('port'), 'fid': instance.get('fid'),
        'binary': instance.get('binary') or instance.get('name'), 'arch': instance.get('arch'),
        'bits': instance.get('bits'), 'idb_path': instance.get('idb_path'),
    }, 'health': result}


def tool_ida_tools(args):
    instance, error = resolve_instance(args.get('instance'))
    if error:
        return {'ok': False, 'error': error}
    try:
        result = rpc(instance_url(instance), 'tools/list', {}, timeout=30.0)
    except Exception as ex:
        return {'ok': False, 'error': str(ex)}
    tools = [{'name': item.get('name'), 'description': item.get('description')} for item in (result or {}).get('tools', [])]
    return {'ok': True, 'count': len(tools), 'port': instance.get('port'), 'tools': tools}


def tool_ida_call(args):
    tool = args.get('tool')
    if not tool:
        return {'ok': False, 'error': 'tool is required'}
    instance, error = resolve_instance(args.get('instance'))
    if error:
        return {'ok': False, 'error': error}
    try:
        result = call_tool(instance, tool, args.get('args') or {}, timeout=float(args.get('timeout') or 120))
    except Exception as ex:
        return {'ok': False, 'error': str(ex), 'tool': tool, 'port': instance.get('port')}
    return {'ok': True, 'tool': tool, 'port': instance.get('port'), 'fid': instance.get('fid'), 'result': result}


def tool_ida_close(args):
    instance, error = resolve_instance(args.get('instance'))
    if error:
        return {'ok': False, 'error': error}
    save = args.get('save')
    save = True if save is None else bool(save)
    pid = instance.get('pid')
    port = instance.get('port')
    try:
        call_tool(instance, 'quit_ida', {'save': save}, timeout=30.0)
    except Exception as ex:
        # The instance may already be gone or wedged; fall through to the kill.
        if not pid_alive(pid):
            cleanup_state(pid, port)
            return {'ok': True, 'pid': pid, 'exited': True, 'saved': save, 'forced': False,
                    'note': 'instance had already exited (%s)' % ex}
    deadline = time.time() + 15.0
    while time.time() < deadline and pid_alive(pid):
        time.sleep(0.25)
    forced = False
    if pid_alive(pid):
        forced = terminate_process(pid)
        deadline = time.time() + 10.0
        while time.time() < deadline and pid_alive(pid):
            time.sleep(0.25)
    exit_confirmed = not pid_alive(pid)
    removed = cleanup_state(pid, port) if exit_confirmed else 0
    return {'ok': True, 'pid': pid, 'exited': exit_confirmed, 'forced': forced,
            'saved': save, 'state_files_removed': removed}


HANDLERS = {
    'ida_launch': tool_ida_launch,
    'ida_switches': tool_ida_switches,
    'ida_instances': tool_ida_instances,
    'ida_status': tool_ida_status,
    'ida_tools': tool_ida_tools,
    'ida_call': tool_ida_call,
    'ida_close': tool_ida_close,
}


# --------------------------------------------------------------------------
# stdio MCP plumbing
# --------------------------------------------------------------------------
def send(message):
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + '\n')
    sys.stdout.flush()


def send_result(request_id, result):
    send({'jsonrpc': '2.0', 'id': request_id, 'result': result})


def send_error(request_id, code, message):
    send({'jsonrpc': '2.0', 'id': request_id, 'error': {'code': code, 'message': message}})


def handle_request(message):
    method = message.get('method')
    request_id = message.get('id')
    params = message.get('params') or {}

    if method == 'initialize':
        send_result(request_id, {
            'protocolVersion': params.get('protocolVersion') or PROTOCOL_VERSION,
            'capabilities': {'tools': {'listChanged': False}},
            'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION},
            'instructions': (
                'Launch and drive IDA Pro instances. Typical flow: ida_launch(input_path=...) -> '
                'ida_status -> ida_call(tool=..., args={...}) -> ida_close.'
            ),
        })
        return
    if method in ('notifications/initialized', 'initialized', 'notifications/cancelled'):
        return
    if method == 'ping':
        send_result(request_id, {})
        return
    if method == 'tools/list':
        send_result(request_id, {'tools': tool_definitions()})
        return
    if method == 'tools/call':
        name = params.get('name')
        arguments = params.get('arguments') or {}
        handler = HANDLERS.get(name)
        if handler is None:
            send_result(request_id, {'isError': True, 'content': [{'type': 'text', 'text': 'unknown tool: %s' % name}]})
            return
        try:
            result = handler(arguments)
            text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
            send_result(request_id, {'content': [{'type': 'text', 'text': text}], 'isError': not bool(result.get('ok', True))})
        except Exception as ex:
            send_result(request_id, {'content': [{'type': 'text', 'text': 'error: %s' % ex}], 'isError': True})
        return
    if method == 'resources/list':
        send_result(request_id, {'resources': []})
        return
    if method == 'prompts/list':
        send_result(request_id, {'prompts': []})
        return
    if request_id is not None:
        send_error(request_id, -32601, 'method not found: %s' % method)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except Exception:
            continue
        try:
            handle_request(message)
        except Exception as ex:
            if message.get('id') is not None:
                send_error(message.get('id'), -32603, 'internal error: %s' % ex)
    return 0


if __name__ == '__main__':
    sys.exit(main())
