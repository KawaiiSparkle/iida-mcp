"""Main-thread task pump for autonomous IDA sessions (pure stdlib).

Why this exists
---------------
With ``ida.exe -A -S<script>`` (the fully automated launch path) IDA does **not**
service UI timers and does **not** run ``execute_sync`` callbacks: the kernel's
event/safe-point machinery stays idle once the startup script returns.  A plugin
that starts an HTTP server in a background thread therefore cannot touch the IDA
API at all - every ``execute_sync`` call just blocks forever.

The fix is to take over the main thread instead of returning from the ``-S``
script: :func:`run` loops on the main thread draining a queue of callables, and
:mod:`iida_core.thread_safe` routes each IDA call through that queue whenever a
pump is active.  This mirrors the ``MainThreadPump`` used by the idalib
supervisor in mrexodia/ida-pro-mcp.

When IDA is started normally (user opens a database), no pump is installed and
``thread_safe`` keeps using ``ida_kernwin.execute_sync``.
"""

import queue as _queue
import threading
import time

_TASKS = None
_ACTIVE = threading.Event()
_STOP = threading.Event()
_OWNER = None


def install():
    """Arm the pump; called on the main thread by the startup script."""
    global _TASKS, _OWNER
    if _TASKS is None:
        _TASKS = _queue.Queue()
    _OWNER = threading.get_ident()
    _ACTIVE.set()
    _STOP.clear()
    return _TASKS


def uninstall():
    global _OWNER
    _ACTIVE.clear()
    _OWNER = None


def is_active():
    return _ACTIVE.is_set() and _TASKS is not None


def on_pump_thread():
    """True when the caller already runs on the pumping (main) thread.

    ``thread_safe`` must execute directly in that case: submitting from the pump
    thread itself would wait for a loop that is busy running the caller.
    """
    return _OWNER is not None and _OWNER == threading.get_ident()


def pending():
    """Number of queued tasks (diagnostics only)."""
    return _TASKS.qsize() if _TASKS is not None else 0


def request_stop():
    """Ask :func:`run` to return (used by ``quit_ida``/``--quit-after``)."""
    _STOP.set()


def stop_requested():
    return _STOP.is_set()


def submit(fn, timeout=60.0):
    """Run ``fn()`` on the pumping main thread and return its result."""
    tasks = _TASKS
    if tasks is None or not _ACTIVE.is_set():
        raise RuntimeError('main-thread pump is not active')
    box = {}
    done = threading.Event()

    def _task():
        try:
            box['result'] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            box['error'] = exc
        finally:
            done.set()

    tasks.put(_task)
    if not done.wait(timeout):
        raise TimeoutError('main-thread pump did not run the task within %ss' % timeout)
    if 'error' in box:
        raise box['error']
    return box.get('result')


def run(idle=0.02, max_seconds=None, on_tick=None):
    """Drain the queue on the calling (main) thread until a stop is requested.

    ``on_tick`` runs on the main thread after each batch of tasks, which the
    startup script uses to publish readiness / honour ``quit_after``.
    """
    tasks = install()
    started = time.time()
    try:
        while True:
            task = None
            try:
                task = tasks.get(timeout=idle)
            except _queue.Empty:
                task = None
            if task is not None:
                task()
                # drain whatever else is queued right away
                while True:
                    try:
                        tasks.get_nowait()()
                    except _queue.Empty:
                        break
            if on_tick is not None:
                try:
                    on_tick()
                except Exception:
                    pass
            if _STOP.is_set():
                break
            if max_seconds is not None and time.time() - started > max_seconds:
                break
    finally:
        uninstall()
    return True
