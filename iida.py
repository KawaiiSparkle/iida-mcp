"""iida-mcp plugin - Exposes IDA's static analysis capabilities via MCP protocol.

Supports multiple IDA instances auto-networking on port 13897.

Auto-start (ida-pro-mcp parity): the MCP HTTP server is brought up automatically
as soon as the plugin loads and a database is available, so loading any file in
IDA immediately exposes it to MCP clients.  Set ``IIDA_MCP_AUTOSTART=0`` to opt
out and start manually with ``Edit > Plugins > iida-mcp`` (Alt-Shift-I).

Every running instance publishes a discovery file
``%APPDATA%/Hex-Rays/IDA Pro/mcp/instances/instance_<port>.json`` so external
launchers (the ``ida-auto`` MCP server, scripts, other clients) can find the
live server, its port, its file id and the loaded binary.
"""
import hashlib
import json
import os
import sys
import tempfile
import threading
import time

import idaapi
import ida_nalt
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_segment

PLUGIN_VERSION = '0.5.0'

# Ensure our package is importable
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)


# --------------------------------------------------------------------------
# Environment / discovery helpers
# --------------------------------------------------------------------------

def _log_path():
    return os.path.join(_instances_dir(), 'iida-mcp.log')


def _log(message):
    """Best-effort dual log: message window + file.

    In autonomous launches (``ida.exe -A``) the message window is invisible, so
    every lifecycle decision is also appended to
    ``<instances dir>/iida-mcp.log`` where automation can read it.
    """
    line = '%s [pid %d] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), os.getpid(), message)
    try:
        with open(_log_path(), 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')
    except Exception:
        pass
    try:
        ida_kernwin.msg('[iida-mcp] %s\n' % message)
    except Exception:
        pass


def _env_flag(name, default=True):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ('0', 'false', 'no', 'off', '')


def _autostart_enabled():
    for name in ('IIDA_MCP_AUTOSTART', 'IDA_MCP_AUTOSTART'):
        if name in os.environ:
            return _env_flag(name, True)
    return True


def _ida_user_dir():
    if os.name == 'nt':
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
        return os.path.join(base, 'Hex-Rays', 'IDA Pro')
    return os.path.join(os.path.expanduser('~'), '.idapro')


def _instances_dir():
    """Directory holding one discovery file per running IDA instance."""
    for candidate in (os.path.join(_ida_user_dir(), 'mcp', 'instances'),
                      os.path.join(tempfile.gettempdir(), 'iida-mcp-instances')):
        try:
            os.makedirs(candidate, exist_ok=True)
            return candidate
        except OSError:
            continue
    return tempfile.gettempdir()


def _instance_path(port):
    return os.path.join(_instances_dir(), 'instance_%d.json' % int(port))


def _write_json_atomic(path, obj):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.iida-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_instance_file(file_info, port, role, internal_port=0):
    payload = {
        # ida-pro-mcp compatible keys
        'host': '127.0.0.1',
        'port': int(port),
        'pid': os.getpid(),
        'binary': file_info.get('path') or '',
        'idb_path': file_info.get('idb') or '',
        'started_at': time.time(),
        'backend': 'iida-mcp-gui',
        # iida-mcp extras
        'fid': file_info.get('fid'),
        'name': file_info.get('name') or '',
        'arch': file_info.get('arch') or '',
        'bits': file_info.get('bits') or 0,
        'role': role,
        'internal_port': int(internal_port or 0),
        'plugin_version': PLUGIN_VERSION,
        'python': sys.version.split()[0],
    }
    path = _instance_path(port)
    _write_json_atomic(path, payload)
    return path


def _remove_instance_file(port):
    if not port:
        return
    try:
        os.unlink(_instance_path(port))
    except OSError:
        pass


# --------------------------------------------------------------------------
# IDA state helpers
# --------------------------------------------------------------------------

def _get_idb_path():
    try:
        return idaapi.get_path(idaapi.PATH_TYPE_IDB) or ''
    except Exception:
        return ''


def _get_file_id():
    """Stable 8-char file_id from the IDB path (the .i64/.idb file, truly unique).

    Returns None when no database is open yet.
    """
    idb_path = _get_idb_path()
    if not idb_path:
        return None
    return hashlib.sha256(idb_path.encode('utf-8')).hexdigest()[:8]


def _get_file_info():
    """Collect current file metadata (safe to call with no database open)."""
    idb_path = _get_idb_path()
    if not idb_path:
        return {'fid': None, 'name': '', 'arch': '', 'bits': 0, 'path': '', 'idb': ''}
    try:
        is64 = ida_ida.inf_is_64bit()
    except Exception:
        is64 = False
    try:
        is32 = ida_ida.inf_is_32bit_exactly() if hasattr(ida_ida, 'inf_is_32bit_exactly') else not is64
    except Exception:
        is32 = not is64
    try:
        arch = ida_ida.inf_get_procname().strip()
    except Exception:
        arch = ''
    try:
        path = ida_nalt.get_input_file_path() or ''
    except Exception:
        path = ''
    return {
        'fid': _get_file_id(),
        'name': os.path.basename(path),
        'arch': arch,
        'bits': 64 if is64 else (32 if is32 else 16),
        'path': path,
        'idb': idb_path,
    }


def _apply_port_env():
    """IIDA_MCP_PORT / IDA_MCP_PORT override the default listen port."""
    raw = os.environ.get('IIDA_MCP_PORT') or os.environ.get('IDA_MCP_PORT')
    if not raw:
        return None
    try:
        port = int(raw, 0)
    except ValueError:
        return None
    try:
        from iida_core import server as _server
        _server.MCP_PORT = port
    except Exception:
        pass
    return port


class _SuppressDialogs(ida_kernwin.UI_Hooks):
    """Auto-dismiss all modal dialogs/warnings to prevent MCP from blocking.
    Always answers YES/OK to any question IDA asks."""

    def ask_yn(self, deflt, fmt):
        return 1  # ASKBTN_YES

    def ask_buttons(self, yes_text, no_text, cancel_text, deflt, fmt):
        return 1  # first button (YES/OK)


class _McpUiHooks(ida_kernwin.UI_Hooks):
    """Start the MCP server once the IDA UI is ready (ida-pro-mcp parity).

    Hooking ``ready_to_run`` guarantees autostart happens in a fully
    initialized GUI session instead of during plugin loading.
    """

    def __init__(self, plugmod):
        super().__init__()
        self._plugmod = plugmod

    def ready_to_run(self):
        try:
            self._plugmod.maybe_autostart()
        except Exception as ex:
            ida_kernwin.msg('[iida-mcp] autostart failed: %s\n' % ex)
        finally:
            try:
                self.unhook()
            except Exception:
                pass


_dialog_suppressor = None
_health_timer_id = None


def _reload_core_modules():
    """Reload iida_core modules so plugin restart picks up local edits."""
    import importlib

    # NOTE: iida_core.pump is deliberately *not* reloaded.  Reloading re-executes
    # its module level initialisers, which would reset the live pump (fresh queue,
    # cleared "active" event) and strand the startup script's main-thread loop.
    for name in (
        'iida_core.thread_safe',
        'iida_core.protocol',
        'iida_core.registry',
        'iida_core.cache',
        'iida_core.kdriver',
        'iida_core.router',
        'iida_core.server',
        'iida_core.worker',
        'iida_core.lifecycle',
        'iida_core.tools',
    ):
        mod = sys.modules.get(name)
        if not mod:
            continue
        try:
            importlib.reload(mod)
        except Exception as ex:
            ida_kernwin.msg("[iida-mcp] reload %s failed: %s\n" % (name, ex))


# --------------------------------------------------------------------------
# Plugin
# --------------------------------------------------------------------------

class IdaMcpPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI | getattr(idaapi, 'PLUGIN_KEEP', 0x0400)
    comment = "iida-mcp"
    help = ""
    wanted_name = "iida-mcp"
    wanted_hotkey = "Alt-Shift-I"

    def init(self):
        # IDA loads plugin bundles from *both* the per-user plugin directory and
        # the installation's plugins/ directory, so this very file can be loaded
        # twice in one process.  Only the first copy may serve: two instances
        # would fight over the election lock and register the same database twice.
        try:
            root = os.path.dirname(os.path.abspath(__file__))
            if root not in sys.path:
                sys.path.insert(0, root)
            import iida_core
            owner = getattr(iida_core, 'ACTIVE_PLUGIN', None)
            if owner is not None:
                _log('duplicate plugin copy ignored (active copy is already '
                     'serving this process); this copy: %s' % __file__)
                return None
            iida_core.ACTIVE_PLUGIN = __file__
        except Exception as ex:
            _log('claim check skipped: %s' % ex)
        mod = IdaMcpPlugMod()
        # Autostart must work in every launch mode, including the fully
        # autonomous one used by automation (``ida.exe -A -S<iida_autostart.py>``),
        # where ``ready_to_run`` is never delivered.  An IDA timer therefore
        # triggers the start; the UI hook and a background thread are extra
        # safety nets for modes where timers are unavailable.
        watched = mod.install_startup_watch()
        hooked = mod.install_ui_hooks()
        _log('plugin init: timer=%s ui_hook=%s autostart=%s file=%s'
             % (watched, hooked, _autostart_enabled(), __file__))
        # The delayed thread is the safety net that also covers "register_timer
        # failed because the kernel was not ready yet".
        mod._thread_autostart(delay=3.0)
        return mod

    def term(self):
        pass

    def run(self, arg):
        pass


class IdaMcpPlugMod(idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self._server = None
        self._worker = None
        self._started = False
        self._gen = 0
        self._watch_thread = None
        self._ui_hooks = None
        self._timer_id = None
        self._reloaded = False

    # -- lifecycle ---------------------------------------------------------

    def install_startup_watch(self):
        """Autostart from an IDA timer - fires in GUI and ``-A`` autonomous mode.

        The callback runs on the IDA main thread, so it can inspect the database
        directly and keeps working when ``ready_to_run`` is never delivered.
        """
        if not _autostart_enabled():
            ida_kernwin.msg('[iida-mcp] autostart disabled (IIDA_MCP_AUTOSTART=0); '
                            'use Edit > Plugins > iida-mcp (Alt-Shift-I)\n')
            return False
        try:
            self._timer_id = ida_kernwin.register_timer(800, self._startup_tick)
            return self._timer_id is not None
        except Exception as ex:
            ida_kernwin.msg('[iida-mcp] startup timer unavailable (%s)\n' % ex)
            self._timer_id = None
            return False

    def _startup_tick(self):
        if self._started:
            return -1
        _log('startup timer fired -> autostart')
        self._start('autostart')
        return -1

    def _health_tick(self):
        """Keep the /health snapshot fresh (main thread, GUI sessions).

        ``ida_auto.auto_is_ok()`` / ``init_hexrays_plugin()`` may only be called
        from the main thread; /health is served from an HTTP worker thread, so
        the answer is computed here and cached.
        """
        try:
            from iida_core import server as _server
        except Exception:
            return 2000
        done = None
        try:
            import ida_auto
            done = bool(ida_auto.auto_is_ok())
        except Exception:
            pass
        hexrays = None
        try:
            import ida_hexrays
            hexrays = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            pass
        try:
            _server.update_health_snapshot(done, hexrays)
        except Exception:
            pass
        return 2000

    def _arm_health_timer(self):
        """Register the /health refresh timer (must happen on the main thread).

        ``register_timer`` is an IDA kernel call: from a background thread it
        deadlocks whenever the main thread is busy draining the pump, so hop to
        the main thread first (pump in ``-A`` sessions, ``execute_sync`` in GUI
        sessions).
        """
        global _health_timer_id
        if _health_timer_id is not None:
            return
        if threading.current_thread() is not threading.main_thread():
            try:
                from iida_core import thread_safe as _ts
                _ts.run_in_ida(self._arm_health_timer, timeout=30.0)
            except Exception as ex:
                _log('health timer defer failed: %s' % ex)
            return
        try:
            _health_timer_id = ida_kernwin.register_timer(2000, self._health_tick)
            _log('health timer armed')
        except Exception as ex:
            _health_timer_id = None
            _log('health timer unavailable: %s' % ex)

    def _thread_autostart(self, delay=2.0):
        """Safety net for modes where timers/UI hooks never fire."""

        def _worker():
            try:
                time.sleep(delay)
            except Exception:
                pass
            if self._started:
                return
            _log('delayed autostart check (timer=%s)' % self._timer_id)
            try:
                if self._timer_id is None and self.install_startup_watch():
                    return
            except Exception:
                pass
            try:
                self.maybe_autostart()
            except Exception as ex:
                _log('delayed autostart failed: %s' % ex)

        try:
            threading.Thread(target=_worker, name='iida-mcp-autostart', daemon=True).start()
        except Exception:
            pass

    def install_ui_hooks(self):
        try:
            self._ui_hooks = _McpUiHooks(self)
            self._ui_hooks.hook()
            return True
        except Exception as ex:
            self._ui_hooks = None
            ida_kernwin.msg('[iida-mcp] UI hook unavailable (%s), autostarting directly\n' % ex)
            return False

    def maybe_autostart(self):
        if not _autostart_enabled():
            ida_kernwin.msg('[iida-mcp] autostart disabled (IIDA_MCP_AUTOSTART=0); '
                            'use Edit > Plugins > iida-mcp (Alt-Shift-I)\n')
            return
        self._start('autostart')

    def run(self, arg):
        """Called when the user clicks iida-mcp in Edit>Plugins."""
        if self._started:
            ida_kernwin.msg("[iida-mcp] Stopping current instance...\n")
            self._stop()
            ida_kernwin.msg("[iida-mcp] Stopped\n")
            return
        self._start('manual')

    def _start(self, why):
        if self._started:
            return
        self._started = True
        self._gen += 1

        global _dialog_suppressor
        if _dialog_suppressor is None:
            def _install_suppressor():
                global _dialog_suppressor
                try:
                    _dialog_suppressor = _SuppressDialogs()
                    _dialog_suppressor.hook()
                except Exception:
                    _dialog_suppressor = None

            try:
                from iida_core import thread_safe as _ts
                if _ts._pump.is_active():
                    # Autonomous session: hooks must be installed from the main
                    # thread (the pump), never from this background thread.
                    _ts.run_in_ida(_install_suppressor)
                else:
                    _install_suppressor()
            except Exception:
                _install_suppressor()

        ida_kernwin.msg("[iida-mcp] Activating (%s)...\n" % why)
        _log('activating (%s)' % why)
        self._watch_thread = threading.Thread(target=self._supervise, daemon=True)
        self._watch_thread.start()
        # Keep GET /health honest: IDA SDK queries happen here, on the main thread.
        self._arm_health_timer()

    def _stop(self):
        """Stop serving; the supervisor thread exits on its next iteration."""
        global _health_timer_id
        self._started = False
        self._gen += 1
        if _health_timer_id is not None:
            try:
                ida_kernwin.unregister_timer(_health_timer_id)
            except Exception:
                pass
            _health_timer_id = None
        self._teardown_network()

    def _supervise(self):
        """Keep the network session in sync with the currently loaded database.

        - no database yet        -> wait (server starts once a file is loaded)
        - database loaded        -> start master/worker, publish discovery file
        - database switched      -> re-register the new file
        - database closed        -> tear the session down and wait again
        """
        gen = self._gen
        from iida_core.thread_safe import read as ida_read

        active_fid = None
        announced_wait = False
        while self._started and self._gen == gen:
            try:
                info = ida_read(_get_file_info)
            except Exception as ex:
                ida_kernwin.msg('[iida-mcp] state probe failed: %s\n' % ex)
                info = {'idb': '', 'fid': None}
            if self._gen != gen or not self._started:
                break

            if not info.get('idb'):
                if active_fid is not None:
                    self._teardown_network()
                    active_fid = None
                if not announced_wait:
                    announced_wait = True
                    _log('waiting for a database to be loaded...')
                time.sleep(0.5)
                continue

            if info.get('fid') != active_fid:
                if active_fid is not None:
                    ida_kernwin.msg('[iida-mcp] database switched -> %s\n' % info.get('name'))
                    self._teardown_network()
                    active_fid = None
                if self._gen != gen or not self._started:
                    break
                if self._init_network_for(info):
                    active_fid = info.get('fid')
                else:
                    # retry in a moment (transient bind/registration failure)
                    time.sleep(2.0)
                    continue
            time.sleep(1.0)

    def _show_status(self):
        if self._server:
            from iida_core.server import MCP_PORT
            entries = self._server.registry.list_all()
            names = ', '.join(e.name for e in entries)
            ida_kernwin.msg("[iida-mcp] Master :%d | files: %s\n"
                            % (getattr(self._server, 'port', MCP_PORT), names))
        elif self._worker:
            if self._worker.is_promoted():
                srv = self._worker.get_master_server()
                port = getattr(srv, 'port', 0) if srv else 0
                entries = srv.registry.list_all() if srv else []
                names = ', '.join(e.name for e in entries)
                ida_kernwin.msg("[iida-mcp] Promoted Master :%d | files: %s\n" % (port, names))
            else:
                ida_kernwin.msg("[iida-mcp] Worker connected\n")
        else:
            ida_kernwin.msg("[iida-mcp] Not connected\n")

    def _init_network_for(self, file_info):
        """Start the session, on the main thread when there is no event loop.

        ``_init_network`` builds the analysis caches, which calls IDA APIs; in an
        autonomous ``-A`` session nothing dispatches work to the main thread
        except the startup script's pump, so the whole call has to go through it.
        """
        try:
            from iida_core import thread_safe as _ts
            if _ts._pump.is_active():
                # Cache building can take minutes on large databases, so give the
                # startup call a much longer budget than a regular tool call: a
                # premature timeout would start a second server on the retry.
                return bool(_ts.run_in_ida(self._init_network, file_info, timeout=1800.0))
        except Exception as ex:
            _log('start via main-thread pump failed: %s' % ex)
            return False
        return self._init_network(file_info)

    def _init_network(self, file_info):
        """Start master or worker for ``file_info``. Returns True on success."""
        try:
            if not self._reloaded:
                _reload_core_modules()
                self._reloaded = True
            _apply_port_env()

            from iida_core.server import McpServer, try_bind_master, try_election_lock
            from iida_core.server import INTERNAL_PORT
            from iida_core.worker import Worker
            from iida_core.registry import FileEntry
            from iida_core import tools
            from iida_core.cache import get_cache

            # Pre-build caches (strings, functions, names, imports, exports, segments)
            cache = get_cache()
            cache.ensure_built()

            election_lock = try_election_lock()
            become_master = election_lock is not None and try_bind_master()
            try:
                if become_master:
                    self._server = McpServer(tools, tools.execute_tool, election_lock=election_lock)
                    entry = FileEntry(
                        fid=file_info['fid'],
                        name=file_info['name'],
                        arch=file_info['arch'],
                        bits=file_info['bits'],
                        path=file_info['path'],
                        pid=os.getpid(),
                        conn=None,
                        local=True
                    )
                    self._server.registry.register(entry)
                    self._server.start()
                    election_lock = None
            finally:
                if election_lock:
                    try:
                        election_lock.close()
                    except Exception:
                        pass

            bt = cache.get_build_time()
            if become_master:
                port = getattr(self._server, 'port', 0)
                try:
                    _write_instance_file(file_info, port, 'master', INTERNAL_PORT)
                except Exception as ex:
                    ida_kernwin.msg('[iida-mcp] instance file failed: %s\n' % ex)
                ida_kernwin.msg("[iida-mcp] Master on :%d | %s (%s) | cache %.1fs\n"
                                % (port, file_info['name'], file_info['fid'], bt))
                _log('Master on :%d | %s (%s) | cache %.1fs' % (port, file_info['name'], file_info['fid'], bt))
            else:
                def on_promoted(worker):
                    srv = worker.get_master_server()
                    entries = srv.registry.list_all() if srv else []
                    names = ', '.join(e.name for e in entries)
                    try:
                        _write_instance_file(worker.file_info, getattr(srv, 'port', 0), 'master', INTERNAL_PORT)
                    except Exception:
                        pass
                    ida_kernwin.msg("[iida-mcp] Promoted to Master | files: %s\n" % names)

                self._worker = Worker(file_info, tools.execute_tool, on_promoted=on_promoted)
                self._worker.start()
                from iida_core.server import MCP_PORT
                try:
                    _write_instance_file(file_info, MCP_PORT, 'worker', INTERNAL_PORT)
                except Exception as ex:
                    ida_kernwin.msg('[iida-mcp] instance file failed: %s\n' % ex)
                ida_kernwin.msg("[iida-mcp] Worker | %s (%s) | cache %.1fs\n"
                                % (file_info['name'], file_info['fid'], bt))
                _log('Worker | %s (%s) | cache %.1fs' % (file_info['name'], file_info['fid'], bt))
            return True
        except Exception as ex:
            import traceback
            _log('start failed: %s\n%s' % (ex, traceback.format_exc()))
            self._teardown_network()
            return False

    def _teardown_network(self):
        server, worker = self._server, self._worker
        self._server = None
        self._worker = None
        if server:
            try:
                _remove_instance_file(getattr(server, 'port', 0))
            except Exception:
                pass
            try:
                server.stop()
            except Exception:
                pass
        if worker:
            try:
                srv = worker.get_master_server()
                if srv:
                    _remove_instance_file(getattr(srv, 'port', 0))
                    srv.stop()
            except Exception:
                pass
            try:
                worker.stop()
            except Exception:
                pass

    def __del__(self):
        try:
            self._stop()
        except Exception:
            pass


def PLUGIN_ENTRY():
    try:
        _log('plugin module loaded (version %s, python %s)' % (PLUGIN_VERSION, sys.version.split()[0]))
    except Exception:
        pass
    return IdaMcpPlugin()
