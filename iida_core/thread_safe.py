"""Thread-safe IDA API execution wrapper.

Every IDA API call runs on IDA's main thread and in batch mode, so modal
dialogs/warnings are suppressed.

Two transports are supported:

* normal sessions - ``ida_kernwin.execute_sync``;
* autonomous sessions (``ida.exe -A -S<iida_autostart.py>``), where IDA never
  services ``execute_sync``: the startup script installs
  :mod:`iida_core.pump`, which owns the main thread and drains a task queue.
"""
import os
import threading
import time

import ida_kernwin

from . import pump as _pump

MFF_READ = ida_kernwin.MFF_READ
MFF_WRITE = ida_kernwin.MFF_WRITE

_batch_fn = None  # lazy-init: callable(int) -> old_value, or False if unavailable
IDA_SYNC_TIMEOUT = 60.0

#: In an automated launch (``ida.exe -A -S<iida_autostart.py>``) the startup
#: script installs the main-thread pump a moment after the plugin starts up.
#: Any IDA call made in that window must wait for it - falling back to
#: ``execute_sync`` would block forever, because autonomous IDA never services
#: safe points.
PUMP_WAIT = 20.0


def _pump_wait_seconds():
    try:
        return max(0.0, float(os.environ.get('IIDA_MCP_PUMP_WAIT') or PUMP_WAIT))
    except Exception:
        return PUMP_WAIT


def _await_pump(timeout):
    """Wait for the startup script to arm the pump (automated launches only)."""
    if not os.environ.get('IIDA_MCP_AUTOSTART_SCRIPT'):
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _pump.is_active():
            return True
        time.sleep(0.05)
    return _pump.is_active()


def _get_batch_fn():
    """Lazily detect the batch mode API."""
    global _batch_fn
    if _batch_fn is not None:
        return _batch_fn
    # idc.batch(v) returns the previous batch value -- works on IDA 7.x-9.x
    try:
        import idc
        old = idc.batch(0)
        idc.batch(old)
        _batch_fn = idc.batch
        return _batch_fn
    except:
        pass
    try:
        import idaapi
        if hasattr(idaapi, 'cvar') and hasattr(idaapi.cvar, 'batch'):
            def _set(v):
                old = idaapi.cvar.batch
                idaapi.cvar.batch = v
                return old
            _batch_fn = _set
            return _batch_fn
    except:
        pass
    _batch_fn = False
    return _batch_fn


def _invoke(fn, args):
    """Run fn(*args) with IDA batch mode enabled (suppresses dialogs)."""
    batch = _get_batch_fn()
    prev = None
    try:
        if batch:
            prev = batch(1)
        return fn(*args)
    finally:
        if batch and prev is not None:
            batch(prev)


def run_in_ida(fn, *args, write=False, timeout=None):
    """Execute fn(*args) on IDA's main thread, blocking until done."""
    wait = IDA_SYNC_TIMEOUT if timeout is None else float(timeout)
    if _pump.is_active():
        # Autonomous session: the startup script owns the main thread.
        if _pump.on_pump_thread():
            return _invoke(fn, args)
        return _pump.submit(lambda: _invoke(fn, args), wait)

    if _await_pump(_pump_wait_seconds()):
        return _pump.submit(lambda: _invoke(fn, args), wait)

    result = [None]
    exc = [None]
    ev = threading.Event()

    def _run():
        try:
            result[0] = _invoke(fn, args)
        except Exception as e:
            exc[0] = e
        finally:
            ev.set()
        return 0

    mode = MFF_WRITE if write else MFF_READ
    ida_kernwin.execute_sync(_run, mode)
    if not ev.wait(IDA_SYNC_TIMEOUT):
        raise TimeoutError(f'IDA main thread did not run callback within {IDA_SYNC_TIMEOUT}s')
    if exc[0]:
        raise exc[0]
    return result[0]


def read(fn, *args):
    """Shorthand for run_in_ida with MFF_READ."""
    return run_in_ida(fn, *args, write=False)


def write(fn, *args):
    """Shorthand for run_in_ida with MFF_WRITE."""
    return run_in_ida(fn, *args, write=True)
