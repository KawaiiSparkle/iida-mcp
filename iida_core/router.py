"""Request router - dispatches tool calls to the correct IDA instance."""
import socket
from . import protocol

_NO_FILE_TOOLS = frozenset([
    'kernel_read', 'kernel_modules', 'kernel_module_base', 'kernel_read_values',
    'calc', 'disasm_bytes',
    # instance-local automation tools (no database required)
    'ida_plugin_status', 'get_cli_switches',
])


class Router:
    def __init__(self, registry, local_handler):
        self.registry = registry
        self.local_handler = local_handler

    def dispatch(self, tool, args):
        fid = args.get('f')

        if tool == 'list_files':
            return self._list_files()

        if tool == 'batch':
            return self._batch(args)

        if tool in _NO_FILE_TOOLS:
            return self.local_handler(tool, args)

        if not fid:
            entries = self.registry.list_all()
            if len(entries) == 1:
                fid = entries[0].fid
                args['f'] = fid
            else:
                return {'e': 'f required'}

        entry = self.registry.get(fid)
        if not entry:
            return {'e': 'unknown f'}

        if entry.local:
            return self.local_handler(tool, args)
        else:
            return self._call_remote(entry, tool, args)

    def _list_files(self):
        entries = self.registry.list_all()
        return [[e.fid, e.name, e.arch, e.bits, e.path] for e in entries]

    def _batch(self, args):
        ops = args.get('ops', [])
        results = []
        for op in ops:
            t = op[0]
            a = op[1] if len(op) > 1 else {}
            if 'f' not in a and 'f' in args:
                a['f'] = args['f']
            try:
                results.append(self.dispatch(t, a))
            except Exception as ex:
                results.append({'e': str(ex)})
        return results

    def _call_remote(self, entry, tool, args):
        worker_port = entry.call_port
        if not worker_port:
            return {'e': 'worker has no call port'}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60.0)
            sock.connect(('127.0.0.1', worker_port))
            protocol.send_msg(sock, {
                't': protocol.MSG_CALL,
                'tool': tool,
                'args': args
            })
            resp = protocol.recv_msg(sock)
            sock.close()
            if resp is None:
                return {'e': 'worker no response'}
            return resp.get('r', {'e': 'no result'})
        except Exception as ex:
            return {'e': str(ex)}
