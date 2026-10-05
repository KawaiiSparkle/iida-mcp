#!/usr/bin/env python3
"""End-to-end self test for the ida-auto launcher MCP.

Speaks the real stdio MCP protocol to ``server.py`` (the same path DeepSeek
Harness uses) and drives a complete launch -> inspect -> close cycle:

    python tools/ida_auto_mcp/selftest.py [binary] [--keep]

Exits 0 only when every step succeeded.
"""

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, 'server.py')
DEFAULT_BINARY = os.environ.get('IIDA_MCP_TEST_BINARY') or r'C:\Windows\System32\version.dll'
PYTHON = sys.executable or 'python'


class Client:
    def __init__(self):
        self.proc = subprocess.Popen([PYTHON, SERVER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, encoding='utf-8', bufsize=1)
        self.next_id = 1

    def request(self, method, params=None, timeout=900.0):
        request_id = self.next_id
        self.next_id += 1
        payload = {'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params or {}}
        self.proc.stdin.write(json.dumps(payload) + '\n')
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError('server closed stdout; stderr=%s' % self.proc.stderr.read())
            line = line.strip()
            if not line:
                continue
            message = json.loads(line)
            if message.get('id') == request_id:
                if 'error' in message:
                    raise RuntimeError('error: %s' % message['error'])
                return message.get('result')
        raise RuntimeError('timeout waiting for %s' % method)

    def call(self, name, arguments=None, timeout=900.0):
        result = self.request('tools/call', {'name': name, 'arguments': arguments or {}}, timeout=timeout)
        text = '\n'.join(item.get('text', '') for item in result.get('content', []))
        try:
            return json.loads(text), result.get('isError')
        except Exception:
            return text, result.get('isError')

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


def main(argv):
    binary = DEFAULT_BINARY
    keep = '--keep' in argv
    for item in argv[1:]:
        if not item.startswith('--'):
            binary = item
    if not os.path.isfile(binary):
        print('FAIL: test binary not found: %s' % binary)
        return 2

    steps = []

    def record(name, ok, detail=''):
        steps.append((name, ok))
        print('%s %s%s' % ('PASS' if ok else 'FAIL', name, (' - %s' % detail) if detail else ''))

    def unwrap(payload):
        """``ida_call`` wraps the remote tool result under ``result``."""
        if isinstance(payload, dict) and isinstance(payload.get('result'), (dict, list)):
            return payload['result']
        return payload

    client = Client()
    try:
        info = client.request('initialize', {'protocolVersion': '2024-11-05', 'capabilities': {},
                                             'clientInfo': {'name': 'selftest', 'version': '1'}})
        record('initialize', info.get('serverInfo', {}).get('name') == 'ida-auto', json.dumps(info.get('serverInfo')))

        tools = client.request('tools/list')
        names = [item['name'] for item in tools.get('tools', [])]
        record('tools/list', 'ida_launch' in names and 'ida_call' in names, ','.join(names))

        switches, _ = client.call('ida_switches', {'detail': 'summary'})
        record('ida_switches', isinstance(switches, dict) and len(switches.get('switches', [])) >= 25,
               '%s switches' % len(switches.get('switches', [])) if isinstance(switches, dict) else str(switches)[:120])

        launch, is_error = client.call('ida_launch', {'input_path': binary, 'timeout': 600})
        ok = isinstance(launch, dict) and launch.get('ok') and launch.get('port')
        record('ida_launch', bool(ok), json.dumps({k: launch.get(k) for k in ('pid', 'port', 'fid', 'arch', 'bits', 'analysis_done', 'error')}) if isinstance(launch, dict) else str(launch)[:200])
        if not ok:
            print(json.dumps(launch, indent=2)[:2000] if isinstance(launch, dict) else launch)
            for name, passed in steps:
                if not passed:
                    print('first failure: %s' % name)
                    break
            return 1

        pid = launch['pid']
        time.sleep(1.0)

        status, _ = client.call('ida_status', {'instance': 'pid:%s' % pid})
        record('ida_status', isinstance(status, dict) and status.get('ok'), json.dumps(status.get('health', {}).get('files')) if isinstance(status, dict) else str(status)[:200])

        listing, _ = client.call('ida_tools', {'instance': 'pid:%s' % pid})
        count = listing.get('count') if isinstance(listing, dict) else 0
        record('ida_tools', bool(count) and count >= 80, '%s tools' % count)

        info_result, _ = client.call('ida_call', {'instance': 'pid:%s' % pid, 'tool': 'get_info', 'args': {'f': launch['fid']}})
        record('ida_call:get_info', isinstance(info_result, dict) and bool(info_result), json.dumps(info_result)[:200])

        status_call, _ = client.call('ida_call', {'instance': 'pid:%s' % pid, 'tool': 'ida_plugin_status', 'args': {}})
        status_body = unwrap(status_call)
        record('ida_call:ida_plugin_status', isinstance(status_body, dict) and status_body.get('pid') == pid,
               json.dumps(status_call)[:200] if isinstance(status_call, dict) else str(status_call)[:200])

        state_call, _ = client.call('ida_call', {'instance': 'pid:%s' % pid, 'tool': 'ida_analysis_state', 'args': {}})
        state_body = unwrap(state_call)
        record('ida_call:ida_analysis_state', isinstance(state_body, dict) and state_body.get('done') is True,
               json.dumps(state_call)[:160] if isinstance(state_call, dict) else str(state_call)[:160])

        funcs, _ = client.call('ida_call', {'instance': 'pid:%s' % pid, 'tool': 'list_functions', 'args': {'f': launch['fid'], 'n': 5}})
        funcs_body = unwrap(funcs)
        record('ida_call:list_functions', isinstance(funcs_body, list) and len(funcs_body) >= 1, json.dumps(funcs)[:200])

        if keep:
            print('keeping instance pid=%s port=%s (--keep)' % (pid, launch['port']))
        else:
            closed, _ = client.call('ida_close', {'instance': 'pid:%s' % pid, 'save': False}, timeout=60)
            record('ida_close', isinstance(closed, dict) and closed.get('ok'), json.dumps(closed)[:160] if isinstance(closed, dict) else str(closed)[:160])
    finally:
        client.close()

    failed = [name for name, ok in steps if not ok]
    print('\n%d/%d steps passed' % (len(steps) - len(failed), len(steps)))
    if failed:
        print('failed: %s' % ', '.join(failed))
        return 1
    print('RESULT: OK')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
