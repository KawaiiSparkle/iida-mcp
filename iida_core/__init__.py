"""iida-mcp core - Zero-dependency MCP server for IDA Pro 9"""
__version__ = "0.5.0"

#: Path of the plugin copy that owns this process.  IDA loads plugin bundles from
#: both the per-user plugin directory and the installation's ``plugins/``
#: directory, so two copies of iida.py can end up in one IDA process; the second
#: one sees this flag and stays idle instead of racing for the election lock.
ACTIVE_PLUGIN = None
