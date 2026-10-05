"""iida-mcp startup script for automated IDA launches (IDA `-S` script).

Launch example (GUI, plugins load, no dialogs, no user interaction):

    ida.exe -A -S"<IDA>\\plugins\\iida-mcp\\iida_autostart.py" target.bin

What this script does
---------------------
*   records a ``boot_<pid>.json`` marker (proof the launch path worked, plus the
    raw IDA command line arguments IDA passed to the script);
*   takes over IDA's main thread with :mod:`iida_core.pump`.  This is required:
    in ``-A`` autonomous mode IDA services neither UI timers nor
    ``execute_sync`` callbacks, so a background HTTP server could never reach the
    IDA API.  With the pump installed, ``thread_safe`` routes every request to
    the main thread and the whole tool set works headlessly;
*   waits for auto-analysis, then for the iida-mcp plugin to publish its
    instance file, and writes ``ready_<pid>.json`` (port/fid/arch/bits/paths) so
    an external launcher (``tools/ida_auto_mcp``) knows the MCP server is up;
*   optionally exits IDA after ``IIDA_MCP_QUIT_AFTER`` seconds (batch pipelines).

Environment variables
---------------------
``IIDA_MCP_STATE_DIR``     where markers are written (default: the same
                           ``%APPDATA%\\Hex-Rays\\IDA Pro\\mcp\\instances`` dir the
                           plugin publishes instances in; falls back to %TEMP%).
``IIDA_MCP_READY_TIMEOUT`` seconds to wait for analysis + server (default 1800).
``IIDA_MCP_QUIT_AFTER``    seconds to keep IDA alive after readiness, or ``now``
                           to exit as soon as the ready marker is written.

This file intentionally uses only the standard library plus IDA modules; it is
executed by IDA's own Python (idapython), not by the system interpreter.
"""

import json
import os
import sys
import threading
import time

_READY_TIMEOUT_DEFAULT = 1800.0
_TIMER_MS = 500

_written = False
_timer_id = None
_deadline = 0.0
_boot_written = False


# --------------------------------------------------------------------------
# paths / markers
# --------------------------------------------------------------------------
def _state_dir():
    """Directory shared with the plugin's instance files."""
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


def _write_json(path, data):
    tmp = '%s.tmp%d' % (path, os.getpid())
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=True, indent=2)
    try:
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise


def _log(message):
    line = '[iida-mcp autostart %d] %s' % (os.getpid(), message)
    try:
        print(line)
    except Exception:
        pass
    try:
        import ida_kernwin
        ida_kernwin.msg('%s\n' % line)
    except Exception:
        pass
    try:
        with open(os.path.join(_state_dir(), 'iida-mcp.log'), 'a', encoding='utf-8') as fh:
            fh.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), line))
    except Exception:
        pass


# --------------------------------------------------------------------------
# IDA state helpers
# --------------------------------------------------------------------------
def _argv():
    argv = []
    try:
        import idc
        raw = getattr(idc, 'ARGV', None)
        if raw:
            argv = [str(item) for item in raw]
    except Exception:
        pass
    if not argv:
        argv = [str(item) for item in getattr(sys, 'argv', [])[1:]]
    return argv


def _analysis_done():
    try:
        import ida_auto
        return bool(ida_auto.auto_is_ok())
    except Exception:
        return True


def _find_instance(pid):
    """Find the instance file the plugin wrote for this process."""
    directory = _state_dir()
    try:
        names = os.listdir(directory)
    except Exception:
        return None
    for name in sorted(names):
        if not (name.startswith('instance_') and name.endswith('.json')):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception:
            continue
        try:
            same = int(data.get('pid') or 0) == int(pid)
        except Exception:
            same = False
        if same:
            data['_instance_file'] = path
            return data
    return None


# --------------------------------------------------------------------------
# markers
# --------------------------------------------------------------------------
def _write_boot(argv):
    global _boot_written
    if _boot_written:
        return
    try:
        import idaapi
        version = idaapi.get_kernel_version()
    except Exception:
        version = ''
    payload = {
        'pid': os.getpid(),
        'kind': 'boot',
        'argv': argv,
        'ida_version': version,
        'python': sys.version.split()[0],
        'started_at': time.time(),
        'state_dir': _state_dir(),
    }
    try:
        _write_json(os.path.join(_state_dir(), 'boot_%d.json' % os.getpid()), payload)
        _boot_written = True
    except Exception as ex:
        _log('could not write boot marker: %s' % ex)


def _write_ready(instance, analysis_done):
    global _written
    if _written:
        return
    payload = {
        'pid': os.getpid(),
        'kind': 'ready',
        'port': (instance or {}).get('port'),
        'host': (instance or {}).get('host', '127.0.0.1'),
        'fid': (instance or {}).get('fid'),
        'role': (instance or {}).get('role'),
        'name': (instance or {}).get('binary') or (instance or {}).get('name'),
        'arch': (instance or {}).get('arch'),
        'bits': (instance or {}).get('bits'),
        'input_path': (instance or {}).get('idb_path') and (instance or {}).get('binary'),
        'idb_path': (instance or {}).get('idb_path'),
        'instance_file': (instance or {}).get('_instance_file'),
        'analysis_done': bool(analysis_done),
        'plugin_version': (instance or {}).get('plugin_version'),
        'ready_at': time.time(),
        'argv': _argv(),
    }
    try:
        _write_json(os.path.join(_state_dir(), 'ready_%d.json' % os.getpid()), payload)
        _written = True
        _log('MCP server ready on port %s (analysis_done=%s)' % (payload['port'], payload['analysis_done']))
    except Exception as ex:
        _log('could not write ready marker: %s' % ex)


def _schedule_quit():
    """Legacy timer-based quit path (used only when the pump is unavailable)."""
    after = (os.environ.get('IIDA_MCP_QUIT_AFTER') or '').strip().lower()
    if not after:
        return
    try:
        import ida_kernwin
    except Exception:
        return
    if after in ('now', '0', 'immediately'):
        _log('quitting IDA now (IIDA_MCP_QUIT_AFTER=%s)' % after)
        ida_kernwin.qexit(0)
        return
    try:
        delay_ms = max(1, int(float(after) * 1000))
    except Exception:
        return

    def _quit_tick():
        try:
            ida_kernwin.qexit(0)
        except Exception:
            pass
        return -1

    try:
        ida_kernwin.register_timer(delay_ms, _quit_tick)
        _log('IDA will exit %s seconds after readiness' % after)
    except Exception as ex:
        _log('could not schedule quit: %s' % ex)


# --------------------------------------------------------------------------
# main-thread pump path (autonomous `-A -S` launches)
# --------------------------------------------------------------------------
def _plugin_root():
    return os.path.dirname(os.path.abspath(__file__))


def _load_pump():
    """Import ``iida_core.pump`` - preferring the package the plugin loaded.

    The pump must be a *single* object shared with the plugin's
    ``iida_core.thread_safe``, otherwise the two copies would each hold their own
    "active" flag and requests would never be pumped.
    """
    try:
        import importlib
        if 'iida_core.pump' in sys.modules:
            return sys.modules['iida_core.pump']
        if 'iida_core' in sys.modules:
            return importlib.import_module('iida_core.pump')
    except Exception as ex:
        _log('could not reuse the plugin package for the pump: %s' % ex)
    root = _plugin_root()
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from iida_core import pump
        return pump
    except Exception as ex:
        _log('could not import iida_core.pump (%s); falling back to timer mode' % ex)
        return None


def _wait_analysis(pump):
    """Let IDA finish auto-analysis. Runs on the main thread via the pump."""
    def _auto_wait():
        try:
            import ida_auto
            ida_auto.auto_wait()
            return True
        except Exception as ex:
            _log('auto_wait failed: %s' % ex)
            return True

    deadline = time.time() + 30.0
    while time.time() < deadline and not pump.is_active():
        time.sleep(0.05)
    try:
        pump.submit(_auto_wait, timeout=300.0)
    except Exception as ex:
        _log('analysis wait via pump failed: %s' % ex)


def _schedule_quit_pump(pump, stop_event):
    """Quit IDA after readiness when ``IIDA_MCP_QUIT_AFTER`` is set."""
    after = (os.environ.get('IIDA_MCP_QUIT_AFTER') or '').strip().lower()
    if not after:
        return
    if after in ('now', '0', 'immediately'):
        delay = 0.0
    else:
        try:
            delay = float(after)
        except Exception:
            return

    def _quit_later():
        if delay:
            time.sleep(delay)

        def _qexit():
            try:
                import ida_kernwin
                ida_kernwin.qexit(0)
            except Exception as ex:
                _log('qexit failed: %s' % ex)
            return True

        _log('quitting IDA (IIDA_MCP_QUIT_AFTER=%s)' % after)
        try:
            pump.submit(_qexit, timeout=30)
        except Exception as ex:
            _log('qexit via pump failed: %s' % ex)
        stop_event.set()

    threading.Thread(target=_quit_later, name='iida-mcp-quit', daemon=True).start()


def _watch(pump, stop_event):
    """Background supervisor: analysis -> instance file -> ready marker."""
    pid = os.getpid()
    _wait_analysis(pump)
    instance = None
    while time.time() < _deadline:
        instance = _find_instance(pid)
        if instance:
            break
        time.sleep(0.25)
    if instance:
        _write_ready(instance, True)
    else:
        _log('timeout: the plugin never published an instance file')
        _write_ready(None, False)
    _schedule_quit_pump(pump, stop_event)


# --------------------------------------------------------------------------
# legacy timer path (normal GUI sessions without the pump)
# --------------------------------------------------------------------------
def _tick():
    """Timer callback: runs on the IDA UI thread, never blocks it."""
    global _timer_id
    _timer_id = None
    pid = os.getpid()
    instance = _find_instance(pid)
    done = _analysis_done()
    if instance and (done or time.time() >= _deadline):
        _write_ready(instance, done)
        _schedule_quit()
        return -1
    if time.time() >= _deadline:
        _write_ready(instance, False)
        _log('timeout waiting for analysis/instance file; wrote ready marker anyway')
        _schedule_quit()
        return -1
    _arm()
    return 0


def _arm():
    global _timer_id
    try:
        import ida_kernwin
    except Exception:
        return False
    try:
        _timer_id = ida_kernwin.register_timer(_TIMER_MS, _tick)
        return _timer_id is not None
    except Exception as ex:
        _log('register_timer failed: %s' % ex)
        return False


def _blocking_fallback():
    """Used only when no UI timer is available (rare, e.g. text-mode idat)."""
    pid = os.getpid()
    while time.time() < _deadline:
        instance = _find_instance(pid)
        if instance and _analysis_done():
            _write_ready(instance, True)
            _schedule_quit()
            return
        time.sleep(0.5)
    _write_ready(_find_instance(pid), False)


def _legacy_main():
    if not _arm():
        _blocking_fallback()


def main():
    global _deadline
    try:
        timeout = float(os.environ.get('IIDA_MCP_READY_TIMEOUT') or _READY_TIMEOUT_DEFAULT)
    except Exception:
        timeout = _READY_TIMEOUT_DEFAULT
    _deadline = time.time() + max(5.0, timeout)
    argv = _argv()
    _write_boot(argv)
    _log('startup script armed (timeout=%ss, argv=%r)' % (int(_deadline - time.time()), argv))
    pump = _load_pump()
    if pump is None:
        _legacy_main()
        return 0
    # Arm the pump *before* the watcher runs: the plugin may already be calling
    # thread_safe, and those calls must meet an active pump (never execute_sync).
    pump.install()
    _log('pump armed from %s' % getattr(pump, '__file__', '?'))
    stop_event = threading.Event()
    threading.Thread(target=_watch, args=(pump, stop_event), daemon=True,
                     name='iida-mcp-watch').start()
    _log('taking over the main thread (pump); HTTP tools stay responsive')
    try:
        pump.run(idle=0.02)
    except Exception as ex:
        _log('pump loop failed: %s' % ex)
    _log('main-thread pump stopped')
    return 0


def _invoked_as_script():
    """Only auto-run when IDA really executes this file as a ``-S`` script.

    IDAPython also imports every .py inside a plugin bundle at startup, and that
    import must be a no-op: ``main()`` takes over the main thread, so running it
    during the plugin scan would deadlock IDA's startup (and is what made an
    earlier revision exit early).  IDA execs ``-S`` scripts with
    ``__name__ == '__main__'``, which is the only signal we trust.
    """
    return __name__ == '__main__'


if _invoked_as_script():
    main()
