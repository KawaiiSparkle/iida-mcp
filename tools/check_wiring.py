#!/usr/bin/env python3
"""Static wiring checker for the iida-mcp plugin (pure stdlib, no IDA needed).

It parses the sources with :mod:`ast` and verifies the cross-module wiring that
would otherwise only fail at runtime inside IDA:

1. every ``_lifecycle.NAME`` used by ``iida_core/tools.py`` exists in
   ``iida_core/lifecycle.py``;
2. every name referenced inside ``TOOLS_SCHEMA`` (parameter constants such as
   ``_F_OPT``) is defined at module level in ``tools.py``;
3. ``TOOLS_SCHEMA`` tool names and ``DISPATCH`` keys agree;
4. every ``DISPATCH`` target resolves to a module-level name (``_foo``) or an
   imported-module attribute (``_lifecycle.foo``);
5. ``router._NO_FILE_TOOLS`` entries are real tools;
6. lifecycle entry points used by ``iida.py`` exist in ``lifecycle.py``.

Exit code 0 = clean, 1 = problems found.
"""
import ast
import os
import sys

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = os.path.join(PLUGIN_ROOT, 'iida_core')

TOOLS_PY = os.path.join(CORE, 'tools.py')
ROUTER_PY = os.path.join(CORE, 'router.py')
LIFECYCLE_PY = os.path.join(CORE, 'lifecycle.py')
SERVER_PY = os.path.join(CORE, 'server.py')
IIDA_PY = os.path.join(PLUGIN_ROOT, 'iida.py')

problems = []
notes = []

# Tools handled directly by the router/server rather than the DISPATCH table.
ROUTER_LEVEL_TOOLS = {'list_files', 'batch'}


def parse(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return ast.parse(handle.read(), filename=path)


def module_level_names(tree):
    """Names bound at module level: defs, classes, assignments, imports."""
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split('.')[0])
    return names


def assigned_dict_keys(tree, var_name):
    """String keys of the module-level dict assigned to *var_name*."""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    if isinstance(node.value, ast.Dict):
                        keys = []
                        for key in node.value.keys:
                            if isinstance(key, ast.Constant):
                                keys.append(key.value)
                        return keys
    return None


def error(message):
    problems.append(message)


def main():
    for path in (TOOLS_PY, ROUTER_PY, LIFECYCLE_PY, SERVER_PY, IIDA_PY):
        if not os.path.isfile(path):
            error('missing file: %s' % path)
    if problems:
        report()
        return 1

    tools_tree = parse(TOOLS_PY)
    router_tree = parse(ROUTER_PY)
    lifecycle_tree = parse(LIFECYCLE_PY)
    server_tree = parse(SERVER_PY)
    iida_tree = parse(IIDA_PY)

    tools_names = module_level_names(tools_tree)
    lifecycle_names = module_level_names(lifecycle_tree)
    server_names = module_level_names(server_tree)

    # -- 1. _lifecycle.<attr> references ------------------------------------
    used_lifecycle = set()
    for node in ast.walk(tools_tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == '_lifecycle':
                used_lifecycle.add(node.attr)
    for attr in sorted(used_lifecycle):
        if attr not in lifecycle_names:
            error('tools.py references _lifecycle.%s which lifecycle.py does not define' % attr)

    # -- 2. names used inside TOOLS_SCHEMA ----------------------------------
    schema_node = None
    for node in tools_tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == 'TOOLS_SCHEMA':
                    schema_node = node.value
    if schema_node is None:
        error('TOOLS_SCHEMA assignment not found in tools.py')
    else:
        schema_tools = []
        for node in ast.walk(schema_node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '_t':
                if node.args and isinstance(node.args[0], ast.Constant):
                    schema_tools.append(node.args[0].value)
            if isinstance(node, ast.Name) and node.id.startswith('_') and node.id not in tools_names:
                error('TOOLS_SCHEMA uses undefined name %r' % node.id)
        if len(schema_tools) != len(set(schema_tools)):
            dupes = sorted({t for t in schema_tools if schema_tools.count(t) > 1})
            error('duplicate tool names in TOOLS_SCHEMA: %s' % ', '.join(dupes))

    # -- 3./4. DISPATCH keys and targets ------------------------------------
    dispatch_keys = assigned_dict_keys(tools_tree, 'DISPATCH')
    if dispatch_keys is None:
        error('DISPATCH assignment not found in tools.py')
        dispatch_keys = []
    else:
        for node in tools_tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == 'DISPATCH':
                        for value in node.value.values:
                            if isinstance(value, ast.Name):
                                if value.id not in tools_names:
                                    error('DISPATCH target %r is not defined in tools.py' % value.id)
                            elif isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
                                if value.value.id == '_lifecycle' and value.attr not in lifecycle_names:
                                    error('DISPATCH target _lifecycle.%s is not defined' % value.attr)
        missing = sorted(set(schema_tools) - set(dispatch_keys) - ROUTER_LEVEL_TOOLS)
        if missing:
            error('tools in TOOLS_SCHEMA without DISPATCH entry: %s' % ', '.join(missing))
        extra = sorted(set(dispatch_keys) - set(schema_tools))
        if extra:
            notes.append('DISPATCH entries without schema (informational): %s' % ', '.join(extra))

    # -- 5. router._NO_FILE_TOOLS -------------------------------------------
    no_file = []
    for node in router_tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == '_NO_FILE_TOOLS':
                    for sub in ast.walk(node.value):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            no_file.append(sub.value)
    for tool in no_file:
        if dispatch_keys and tool not in dispatch_keys:
            error('router._NO_FILE_TOOLS lists %r which is not a DISPATCH tool' % tool)
    notes.append('router._NO_FILE_TOOLS: %s' % ', '.join(no_file))

    # -- 6. lifecycle usage from tools.py / iida.py -------------------------
    for name in ('ida_status', 'wait_analysis', 'save_database', 'close_database',
                 'quit_ida', 'get_cli_switches'):
        if name not in lifecycle_names:
            error('lifecycle.py does not export %s' % name)
    notes.append('lifecycle exports OK')

    # -- 7. server API used by the plugin ----------------------------------
    server_functions = {node.name for node in ast.walk(server_tree) if isinstance(node, ast.FunctionDef)}
    for name in ('McpServer', 'MCP_PORT', 'INTERNAL_PORT', 'ELECTION_PORT'):
        if name not in server_names:
            error('server.py does not define %s (used by iida.py)' % name)
    if 'health' not in server_functions:
        error('server.py has no health() method (served on GET /health)')
    if 'port' not in [a.arg for node in ast.walk(server_tree) if isinstance(node, ast.FunctionDef)
                      and node.name == '__init__' for a in node.args.args]:
        error('McpServer.__init__ has no port parameter')

    report()
    return 1 if problems else 0


def report():
    for note in notes:
        print('[ok]   %s' % note)
    for problem in problems:
        print('[FAIL] %s' % problem)
    print('wiring check: %d problem(s)' % len(problems))


if __name__ == '__main__':
    sys.exit(main())
