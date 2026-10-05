"""Automation / lifecycle tools for iida-mcp.

These tools let an external agent (the ``ida-auto`` MCP launcher, a script, or
any other MCP client) drive a whole reverse-engineering session without a human
at the keyboard:

* ``ida_plugin_status``  - health/version/role/analysis-state of this instance
* ``ida_analysis_state`` - is auto-analysis still running?
* ``save_database``      - persist the IDB
* ``close_database``     - close the database, keep IDA running
* ``quit_ida``           - save (optionally) and exit IDA
* ``get_cli_switches``   - the catalog of IDA command-line switches

Every function is executed through :mod:`iida_core.thread_safe`, so all IDA SDK
calls happen on the main thread with modal dialogs suppressed.
"""
import json
import os
import sys

from .thread_safe import read as ida_read, write as ida_write

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HARD_EXIT_DELAY = 5.0


def _state_dir():
    """Same instance-marker directory the plugin and the -S script use."""
    override = os.environ.get('IIDA_MCP_STATE_DIR')
    if override:
        return override
    appdata = os.environ.get('APPDATA')
    if appdata:
        return os.path.join(appdata, 'Hex-Rays', 'IDA Pro', 'mcp', 'instances')
    base = os.environ.get('TEMP') or os.environ.get('TMP') or os.path.expanduser('~')
    return os.path.join(base, 'iida-mcp-instances')


def cleanup_state_files(pid):
    """Drop this process' boot/ready/instance markers (called before hard exit)."""
    directory = _state_dir()
    own = ('boot_%d.json' % pid, 'ready_%d.json' % pid)
    try:
        names = os.listdir(directory)
    except Exception:
        return 0
    removed = 0
    for name in names:
        path = os.path.join(directory, name)
        if name in own:
            try:
                os.remove(path)
                removed += 1
            except Exception:
                pass
        elif name.startswith('instance_') or name.startswith('worker_'):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    payload = json.load(fh)
                if int(payload.get('pid') or 0) == int(pid):
                    os.remove(path)
                    removed += 1
            except Exception:
                pass
    return removed


def _schedule_hard_exit(code=0, delay=None):
    """Force the process to exit after *delay* seconds.

    ``quit_ida`` is expected to end the process, but an autonomous (``-A``)
    session has no message loop to dispatch IDA's own quit request - the request
    is posted and then simply never processed, leaving a headless IDA holding a
    port and a database.  This watchdog finishes the job.
    """
    import threading
    import time as _time
    seconds = HARD_EXIT_DELAY if delay is None else delay

    def _watch():
        _time.sleep(seconds)
        try:
            cleanup_state_files(os.getpid())
        except Exception:
            pass
        os._exit(code)

    thread = threading.Thread(target=_watch, name='iida-mcp-hard-exit')
    thread.daemon = True
    thread.start()
    return thread


def _plugin_version():
    try:
        init_py = os.path.join(PLUGIN_ROOT, 'iida.py')
        with open(init_py, 'r', encoding='utf-8') as fh:
            for line in fh:
                if line.startswith('PLUGIN_VERSION'):
                    return line.split('=', 1)[1].strip().strip('\'"')
    except Exception:
        pass
    return 'unknown'


def _analysis_state():
    """(done: bool, detail: str) - auto-analysis finished?"""
    try:
        import ida_auto
    except Exception as ex:
        return True, 'ida_auto unavailable: %s' % ex
    done = False
    try:
        done = bool(ida_auto.auto_is_ok())
    except Exception as ex:
        return True, 'auto_is_ok failed: %s' % ex
    if done:
        return True, 'finished'
    try:
        state = ida_auto.auto_get_state()
        return False, 'running (state=%s)' % state
    except Exception:
        return False, 'running'


def _hexrays_ready():
    try:
        import ida_hexrays
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


def _module_ready(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False


def _ida_status(args):
    def _impl():
        from iida_core import server as server_mod
        import idaapi
        import ida_nalt

        info = {
            'server': 'iida-mcp',
            'plugin_version': _plugin_version(),
            'pid': os.getpid(),
            'python': sys.version.split()[0],
            'ida_version': None,
            'port': int(getattr(server_mod, 'MCP_PORT', 0) or 0),
            'internal_port': int(getattr(server_mod, 'INTERNAL_PORT', 0) or 0),
            'role': 'master' if _is_master_port(server_mod) else 'worker',
            'autostart': _autostart_enabled(),
            'hexrays_ready': _hexrays_ready(),
            'capstone': _module_ready('capstone'),
            'keystone': _module_ready('keystone'),
            'plugin_root': PLUGIN_ROOT,
            'instances_dir': _instances_dir(),
        }
        try:
            info['ida_version'] = idaapi.get_kernel_version()
        except Exception:
            pass
        try:
            info['idb_path'] = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ''
        except Exception:
            info['idb_path'] = ''
        try:
            info['input_path'] = ida_nalt.get_input_file_path() or ''
        except Exception:
            info['input_path'] = ''
        done, detail = _analysis_state()
        info['analysis_done'] = done
        info['analysis_detail'] = detail
        return info

    return ida_read(_impl)


def _autostart_enabled():
    for name in ('IIDA_MCP_AUTOSTART', 'IDA_MCP_AUTOSTART'):
        raw = os.environ.get(name)
        if raw is not None:
            return raw.strip().lower() not in ('0', 'false', 'no', 'off', '')
    return True


def _instances_dir():
    if os.name == 'nt':
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
        root = os.path.join(base, 'Hex-Rays', 'IDA Pro')
    else:
        root = os.path.join(os.path.expanduser('~'), '.idapro')
    return os.path.join(root, 'mcp', 'instances')


def _is_master_port(server_mod):
    """True when this process is the one owning the MCP HTTP port."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect(('127.0.0.1', int(getattr(server_mod, 'INTERNAL_PORT', 0) or 0)))
        s.close()
    except Exception:
        return False
    return True


def _wait_analysis(args):
    """Poll auto-analysis state for up to ``timeout`` seconds."""
    timeout = float(args.get('timeout', 0) or 0)
    if timeout <= 0:
        done, detail = ida_read(_analysis_state)
        return {'done': done, 'detail': detail}

    import time
    deadline = time.time() + min(timeout, 1800.0)
    while True:
        done, detail = ida_read(_analysis_state)
        if done:
            return {'done': True, 'detail': detail}
        if time.time() >= deadline:
            return {'done': False, 'detail': detail, 'timed_out': True}
        time.sleep(0.5)


def _save_database(args):
    path = args.get('path') or None
    compress = bool(args.get('compress', False))

    def _impl():
        import ida_loader
        flags = 0
        if compress and hasattr(ida_loader, 'DBFL_COMP'):
            flags = ida_loader.DBFL_COMP
        target = path
        if target is None:
            try:
                import idaapi
                target = idaapi.get_path(idaapi.PATH_TYPE_IDB) or None
            except Exception:
                target = None
        ok = ida_loader.save_database(target, flags)
        out = {'ok': bool(ok)}
        if not ok:
            out['e'] = 'save_database returned false'
        if target:
            out['path'] = target
        return out

    return ida_write(_impl)


def _close_database(args):
    save = bool(args.get('save', True))

    def _impl():
        if save:
            try:
                import ida_loader
                import idaapi
                ida_loader.save_database(idaapi.get_path(idaapi.PATH_TYPE_IDB) or None, 0)
            except Exception as ex:
                return {'ok': False, 'e': 'save before close failed: %s' % ex}
        for modname in ('ida_loader', 'idaapi'):
            try:
                mod = __import__(modname)
            except Exception:
                continue
            fn = getattr(mod, 'close_database', None)
            if fn is None:
                continue
            try:
                ok = fn(False)
                return {'ok': True if ok is None else bool(ok)}
            except Exception as ex:
                last = ex
        return {'ok': False, 'e': 'close_database unavailable: %s' % locals().get('last')}

    return ida_write(_impl)


def _quit_ida(args):
    save = bool(args.get('save', True))
    code = int(args.get('exit_code', 0) or 0)

    def _impl():
        import ida_kernwin
        if save:
            try:
                import ida_loader
                import idaapi
                ida_loader.save_database(idaapi.get_path(idaapi.PATH_TYPE_IDB) or None, 0)
            except Exception:
                pass
        # Arm the watchdog *before* asking IDA to quit: in an autonomous (-A)
        # session there is no message loop to dispatch the quit request, and
        # qexit() can sit there waiting forever, so anything scheduled after it
        # would never run.
        _schedule_hard_exit(code)
        try:
            ida_kernwin.qexit(code)
        except Exception as ex:
            return {'ok': False, 'e': str(ex)}
        return {'ok': True, 'exit_code': code, 'hard_exit_in': HARD_EXIT_DELAY}

    return ida_write(_impl)


def _catalog_paths():
    return [
        os.path.join(PLUGIN_ROOT, 'tools', 'ida_cli_switches.json'),
        os.path.join(PLUGIN_ROOT, 'ida_cli_switches.json'),
    ]


def _get_cli_switches(args):
    detail = args.get('detail', 'summary')
    for path in _catalog_paths():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception as ex:
            return {'e': 'failed to read %s: %s' % (path, ex)}
        if detail == 'full':
            return data
        switches = data.get('switches', [])
        return {
            'source': data.get('source', ''),
            'count': len(switches),
            'switches': [
                {'switch': s.get('switch'), 'takes_value': s.get('takes_value'),
                 'description': s.get('description')}
                for s in switches
            ],
            'debug_bits': data.get('debug_bits', {}),
            'usage_recipes': data.get('usage_recipes', []),
        }
    return {'e': 'ida_cli_switches.json not found next to the plugin',
            'searched': _catalog_paths()}


# --------------------------------------------------------------------------
# Public aliases (referenced by tools.DISPATCH)
# --------------------------------------------------------------------------

ida_status = _ida_status
wait_analysis = _wait_analysis
save_database = _save_database
close_database = _close_database
quit_ida = _quit_ida
get_cli_switches = _get_cli_switches
