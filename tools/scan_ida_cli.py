#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Catalog the IDA Pro 9.4 command-line switches and re-derive them from live help.

This script does two jobs:

1. Emit a machine-readable catalog of the IDA Pro command-line switches
   (``tools/ida_cli_switches.json`` by default).  The catalog is generated
   from the embedded seed table below, which was verified by running
   ``idat.exe -h`` against IDA Professional 9.4.

2. Re-derive the switch set live, by executing IDA's own help output
   (``idat.exe -h``) and parsing it (``--verify``).  IDA prints its help
   screen to stdout and then exits with status 2, so a non-zero exit
   status is expected here and is deliberately not treated as an error.

Usage
-----
    python scan_ida_cli.py
        Regenerate tools/ida_cli_switches.json (next to this script).

    python scan_ida_cli.py --json <path>
        Regenerate the catalog at <path>.

    python scan_ida_cli.py --print
        Regenerate, then echo the catalog JSON to stdout.

    python scan_ida_cli.py --verify
        Regenerate, then run ``idat.exe -h`` and report which seed
        switches the live help output confirms, and which it does not.
        Exits 1 when the live run produces no parseable switch lines.

    python scan_ida_cli.py --verify --print
        Both.  The verification report is printed first, then the catalog.

    python scan_ida_cli.py --ida-dir "D:\\IDA 9.4" --verify
        Use an explicit IDA installation directory.

Where the IDA installation is looked up (first hit wins)
--------------------------------------------------------
    1. --ida-dir
    2. %IDADIR%
    3. %IDA_PATH%
    4. C:\\Program Files\\IDAPro
    5. common install roots (C:\\Program Files\\IDA*, C:\\IDA\\*, /opt/IDA*,
       /usr/local/IDA*, ~/IDA*) and the PATH (``where ida.exe`` /
       ``shutil.which``)

Exit codes
----------
    0   success (catalog written; live verification, if requested, passed)
    1   verification failed: IDA not found, help run failed, or the live
        help output produced no parseable switch lines
    2   command-line usage error (raised by argparse)

Notes
-----
* Python 3 standard library only; ASCII-only source.
* ``repeatable`` is False for every switch: IDA's help screen does not
  document any switch as repeatable, so the catalog does not claim
  otherwise.
* The ``aliases`` key is present only on entries that actually have
  aliases (the help family: -? / ? / -h / -H / --help).
* ``verified_on`` is a fixed seed-verification date, not the date the
  script runs, so regenerating the file is byte-for-byte idempotent.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------

SOURCE = "idat.exe -h (IDA Professional 9.4)"
VERIFIED_ON = "2026-10-05"

# --------------------------------------------------------------------------
# Embedded seed: IDA Pro 9.4 command-line switches.
#
# Verified by running `idat.exe -h` on IDA Professional 9.4.  This is the
# ground truth for the catalog; the live parser only cross-checks it.
# --------------------------------------------------------------------------


def _entry(switch, takes_value=False, arg_form="", description="", notes="",
           repeatable=False, aliases=None):
    """Build one catalog entry with a stable key order.

    ``aliases`` is attached only when non-empty, so entries without
    aliases keep exactly the six documented keys.
    """
    item = {
        "switch": switch,
        "takes_value": takes_value,
        "arg_form": arg_form,
        "description": description,
        "notes": notes,
        "repeatable": repeatable,
    }
    if aliases:
        item["aliases"] = list(aliases)
    return item


SWITCHES = [
    _entry(
        "-a",
        description="disable auto analysis (-a- enables it)",
    ),
    _entry(
        "-A",
        description=(
            "autonomous mode; IDA will not display dialog boxes"
        ),
        notes="Designed to be used together with the -S switch.",
    ),
    _entry(
        "-b",
        takes_value=True,
        arg_form="####",
        description=(
            "loading address, a hexadecimal number, in paragraphs "
            "(a paragraph is 16 bytes)"
        ),
    ),
    _entry(
        "-B",
        description=(
            "batch mode; IDA will generate .IDB and .ASM files automatically"
        ),
        notes=(
            "Equivalent to 'ida -c -A -Sanalysis.idc input-file'. "
            "Regular plugins are NOT automatically loaded in batch mode, "
            "because analysis.idc quits and the kernel has no chance to load "
            "them; plugin-driven automation must use 'ida.exe -A -S<script>'. "
            "The text interface (idat.exe/idat) is better for batch mode "
            "because it uses fewer system resources."
        ),
    ),
    _entry(
        "-c",
        description="disassemble a new file (delete the old database)",
    ),
    _entry(
        "-C",
        takes_value=True,
        arg_form="####",
        description="set compiler in format name:abi",
    ),
    _entry(
        "-d",
        takes_value=True,
        arg_form="##",
        description=(
            "a configuration directive which must be processed at the "
            "first pass"
        ),
        notes="Example: -dVPAGESIZE=8192",
    ),
    _entry(
        "-D",
        takes_value=True,
        arg_form="##",
        description=(
            "a configuration directive which must be processed at the "
            "second pass"
        ),
    ),
    _entry(
        "-f",
        description="disable FPP instructions (IBM PC only)",
    ),
    _entry(
        "-h",
        description="help screen",
        notes=(
            "Works for the text version only. Identical to -?, ?, -H and "
            "--help; see the -? entry, which carries the whole help family "
            "in its aliases."
        ),
    ),
    _entry(
        "-i",
        takes_value=True,
        arg_form="####",
        description="program entry point (hex)",
    ),
    _entry(
        "-I",
        takes_value=True,
        arg_form="#",
        description=(
            "set IDA as just-in-time debugger (0 to disable and 1 to enable)"
        ),
    ),
    _entry(
        "-L",
        takes_value=True,
        arg_form="####",
        description="name of the log file",
    ),
    _entry(
        "-M",
        description="disable mouse (text only)",
    ),
    _entry(
        "-O",
        takes_value=True,
        arg_form="####",
        description="options to pass to plugins",
        notes="This switch is not available in the IDA Home edition.",
    ),
    _entry(
        "-o",
        takes_value=True,
        arg_form="####",
        description="specify the output database (implies -c)",
    ),
    _entry(
        "-p",
        takes_value=True,
        arg_form="####",
        description="processor type",
    ),
    _entry(
        "-P+",
        description="compress database (create zipped idb)",
    ),
    _entry(
        "-P",
        description="pack database (create unzipped idb)",
    ),
    _entry(
        "-P-",
        description="do not pack database (not recommended, see Abort command)",
    ),
    _entry(
        "-r",
        takes_value=True,
        arg_form="###",
        description="immediately run the built-in debugger",
    ),
    _entry(
        "-R",
        description="load MS Windows exe file resources",
    ),
    _entry(
        "-S",
        takes_value=True,
        arg_form="###",
        description=(
            "execute a script file when the database is opened; the script "
            "file extension determines which extlang runs the script"
        ),
        notes=(
            'Command line arguments may follow the script name, for example '
            '-S"myscript.idc argument1 \\"argument 2\\" argument3". '
            'The passed parameters are stored in the "ARGV" global IDC '
            'variable: use "ARGV.count" for the number of arguments; the '
            'first argument "ARGV[0]" contains the script name. '
            'This switch is not available in the IDA Home edition.'
        ),
    ),
    _entry(
        "-T",
        takes_value=True,
        arg_form="###",
        description=(
            "interpret the input file as the specified file type; the type "
            "is given as a prefix of a file type visible in the 'load file' "
            "dialog box"
        ),
        notes=(
            "Archive members and nested paths are supported: -TZIP:classes.dex, "
            "-T<ftype>[:<member>{:<ftype>:<member>}[:<ftype>]]. "
            "IDA does not display the 'load file' dialog in this case."
        ),
    ),
    _entry(
        "-t",
        description="create an empty database",
    ),
    _entry(
        "-W",
        takes_value=True,
        arg_form="###",
        description="specify MS Windows directory",
    ),
    _entry(
        "-x",
        description="do not create segmentation",
        notes=(
            "Used in pair with the Dump database command; this switch affects "
            "EXE and COM format files only."
        ),
    ),
    _entry(
        "-z",
        takes_value=True,
        arg_form="",
        description="debug: enable debug output selected by a hexadecimal bitmask",
        notes=(
            "The hexadecimal bitmask is given after the switch, for example "
            "-z40000. See the debug_bits catalog for the meaning of each bit."
        ),
    ),
    _entry(
        "-v",
        description="verbose (works for the text version)",
    ),
    _entry(
        "-?",
        description="print the help screen (works for the text version)",
        notes=(
            "The help family. IDA lists -?, ?, -h, -H and --help as separate "
            "lines of the help screen, all printing the same screen in the "
            "text version (idat.exe/idat) only."
        ),
        aliases=["-?", "?", "-h", "-H", "--help"],
    ),
]

# --------------------------------------------------------------------------
# -z debug bitmask values.  Keyed by integer bit value; names are the short
# forms from the verified seed.
# --------------------------------------------------------------------------

DEBUG_BITS = {
    0x00000001: "drefs",
    0x00000002: "offsets",
    0x00000004: "flirt",
    0x00000008: "idp",
    0x00000010: "ldr",
    0x00000020: "plugin",
    0x00000040: "ids",
    0x00000080: "config",
    0x00000100: "heap",
    0x00000200: "licensing",
    0x00000400: "demangler",
    0x00000800: "queue",
    0x00001000: "rollback",
    0x00002000: "already data/code",
    0x00004000: "type system",
    0x00008000: "notifications",
    0x00010000: "debugger",
    0x00020000: "appcall",
    0x00040000: "source-level debugger",
    0x00080000: "accessibility",
    0x00100000: "network",
    0x00200000: "full stack analysis",
    0x00400000: "debug info (pdb/dwarf)",
    0x00800000: "lumina",
}

# --------------------------------------------------------------------------
# Usage recipes.
# --------------------------------------------------------------------------

USAGE_RECIPES = [
    {
        "name": "batch",
        "command": "ida -B input-file",
        "equivalent": "ida -c -A -Sanalysis.idc input-file",
        "notes": (
            "The text interface (idat.exe/idat) is better for batch mode "
            "because it uses fewer system resources."
        ),
    },
    {
        "name": "gui",
        "command": "ida input-file",
        "equivalent": "",
        "notes": "Start the graphical interface.",
    },
    {
        "name": "text",
        "command": "idat input-file",
        "equivalent": "",
        "notes": "Start the text interface.",
    },
    {
        "name": "plugin_automation",
        "command": "ida.exe -A -S<script> input-file",
        "equivalent": "",
        "notes": (
            "Regular plugins are not automatically loaded in batch mode "
            "because the analysis.idc file quits and the kernel has no chance "
            "to load them, so plugin-driven automation must use -A -S<script> "
            "instead of -B."
        ),
    },
]

# --------------------------------------------------------------------------
# IDA installation discovery
# --------------------------------------------------------------------------

# Text-mode binaries, most preferred first.  Only these can print the help
# screen without opening the GUI.
TEXT_BINARY_NAMES = ("idat.exe", "idat64.exe", "idat", "idat64")

# Any of these marks a directory as a plausible IDA installation.
ANY_BINARY_NAMES = TEXT_BINARY_NAMES + ("ida.exe", "ida64.exe", "ida", "ida64")

WINDOWS_DEFAULT_DIR = r"C:\Program Files\IDAPro"

PROBE_ROOTS = (
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\IDA",
    "/opt",
    "/usr/local",
    "/Applications",
)


def _where(exe_name):
    """Locate an executable via the Windows ``where`` command.

    Returns the first reported path, or None.  Kept separate from
    ``shutil.which`` because the task asks for ``where ida.exe``
    specifically; both are used, so either mechanism suffices.
    """
    for command in (["where.exe", exe_name], ["where", exe_name]):
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines():
                candidate = line.strip()
                if candidate and os.path.isfile(candidate):
                    return candidate
    return None


def _dir_has_ida(directory):
    """Return True when *directory* contains any recognizable IDA binary."""
    if not directory or not os.path.isdir(directory):
        return False
    try:
        present = {name.lower() for name in os.listdir(directory)}
    except OSError:
        return False
    return any(name.lower() in present for name in ANY_BINARY_NAMES)


def _probe_dirs():
    """Auto-probe common install roots plus the PATH, in a stable order."""
    found = []

    for root in PROBE_ROOTS:
        if not os.path.isdir(root):
            continue
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            if not name.lower().startswith("ida"):
                continue
            candidate = os.path.join(root, name)
            if os.path.isdir(candidate):
                found.append(candidate)

    # PATH: `where ida.exe` plus shutil.which for every known binary name.
    for exe_name in ANY_BINARY_NAMES:
        located = _where(exe_name)
        if located:
            found.append(os.path.dirname(located))
        which_hit = shutil.which(exe_name)
        if which_hit:
            found.append(os.path.dirname(os.path.abspath(which_hit)))

    # Preserve order, drop duplicates and empties.
    seen = set()
    unique = []
    for directory in found:
        key = os.path.normcase(os.path.abspath(directory))
        if key not in seen:
            seen.add(key)
            unique.append(directory)
    return unique


def candidate_ida_dirs(explicit_dir=None):
    """Build the ordered list of IDA installation directories to try.

    Order: --ida-dir, %IDADIR%, %IDA_PATH%, C:\\Program Files\\IDAPro,
    then auto-probed roots and PATH.
    """
    if explicit_dir:
        return [explicit_dir]

    dirs = []
    for env_name in ("IDADIR", "IDA_PATH"):
        value = os.environ.get(env_name)
        if value:
            dirs.append(value)
    dirs.append(WINDOWS_DEFAULT_DIR)
    dirs.extend(_probe_dirs())

    seen = set()
    unique = []
    for directory in dirs:
        key = os.path.normcase(os.path.abspath(directory))
        if key not in seen:
            seen.add(key)
            unique.append(directory)
    return unique


def find_ida_text_binary(explicit_dir=None):
    """Find the IDA text-mode binary used to print the help screen.

    Returns ``(path, directory)``, or ``(None, None)`` when nothing usable
    was found.  Only text-mode binaries are accepted, because ``ida.exe -h``
    would open the GUI instead of printing help.
    """
    for directory in candidate_ida_dirs(explicit_dir):
        if not os.path.isdir(directory):
            continue
        try:
            present = {name.lower(): name for name in os.listdir(directory)}
        except OSError:
            continue
        for exe_name in TEXT_BINARY_NAMES:
            actual = present.get(exe_name.lower())
            if actual:
                return os.path.join(directory, actual), directory
    return None, None


# --------------------------------------------------------------------------
# Live help execution and parsing
# --------------------------------------------------------------------------

# One switch line of the help screen: optional indent, a switch token, then
# an optional description.  Only a single space is required before the
# description, because IDA prints ` --help this screen (...)` that way.
#
# The `?` alternative exists because IDA lists the bare `?` help alias as a
# switch line of its own.
_SWITCH_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<token>--?[^\s]+|\?)(?:[ \t]+(?P<desc>\S.*?))?[ \t]*$"
)

# One line of the nested -z bit table, e.g. "                00000001 drefs".
_BIT_LINE_RE = re.compile(r"^[ \t]+(?P<hex>[0-9A-Fa-f]+)[ \t]+(?P<name>\S.*?)[ \t]*$")

# Section markers used to isolate the switch list from the surrounding prose.
_SECTION_START_MARKERS = ("switches are recognized", "command line switches")
_SECTION_END_MARKERS = ("for batch mode",)


def _switch_section(lines):
    """Return the slice of help-output lines that holds the switch list."""
    start = 0
    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(marker in lowered for marker in _SECTION_START_MARKERS):
            start = index + 1
            break
    end = len(lines)
    for index in range(start, len(lines)):
        lowered = lines[index].lower()
        if any(marker in lowered for marker in _SECTION_END_MARKERS):
            end = index
            break
    return lines[start:end]


def normalize_switch_token(token):
    """Map a raw switch token from IDA's help output to a catalog key.

    The help screen writes value placeholders in several styles
    (``-b####``, ``-I#``, ``-ddirective``), so the placeholder suffix is
    dropped and only an explicit ``+`` / ``-`` variant is preserved::

        -a                  -> -a
        -b####              -> -b
        -ddirective         -> -d
        -P+ / -P / -P-      -> -P+ / -P / -P-
        -T<ftype>[:<m>...]  -> -T
        -? / ? / --help     -> -? / ? / --help

    Returns "" for anything that is not a switch token.
    """
    if not token:
        return ""
    tok = token.strip()
    if not tok:
        return ""
    if tok.startswith("--"):
        return "--help" if tok[2:].lower() == "help" else tok.lower()
    if tok == "-?":
        return "-?"
    if not tok.startswith("-"):
        return "?" if tok == "?" else ""
    if len(tok) < 2 or not tok[1].isalpha():
        return ""
    base = "-" + tok[1]
    rest = tok[2:].replace("#", "")
    if rest in ("+", "-"):
        return base + rest
    return base


def parse_help_output(text):
    """Parse IDA's help screen.

    Returns ``(switch_keys, debug_bits, raw_tokens, line_count)`` where
    *switch_keys* is the ordered list of distinct normalized switch keys,
    *debug_bits* maps integer bit value to the live name, and *raw_tokens*
    keeps the original spellings for reporting.
    """
    lines = text.splitlines()
    section = _switch_section(lines)

    switch_keys = []
    raw_tokens = []
    debug_bits = {}
    current = None

    for line in section:
        match = _SWITCH_LINE_RE.match(line)
        if match:
            raw = match.group("token")
            key = normalize_switch_token(raw)
            if not key:
                continue
            raw_tokens.append(raw)
            current = key
            if key not in switch_keys:
                switch_keys.append(key)
            continue

        # Not a switch line: it may be a row of the nested -z bit table.
        if current != "-z":
            continue
        bit_match = _BIT_LINE_RE.match(line)
        if not bit_match:
            continue
        try:
            value = int(bit_match.group("hex"), 16)
        except ValueError:
            continue
        # Bit tables are powers of two; this rejects prose that happens to
        # start with hex-looking characters.
        if value <= 0 or value & (value - 1):
            continue
        debug_bits[value] = bit_match.group("name")

    return switch_keys, debug_bits, raw_tokens, len(lines)


def run_ida_help(idat_path):
    """Run ``<idat> -h`` and return ``(returncode, combined_output)``.

    IDA writes the help screen to stdout and exits with status 2; the exit
    status is returned for reporting but must not be treated as failure.
    """
    proc = subprocess.run(
        [idat_path, "-h"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    parts = [proc.stdout or ""]
    if proc.stderr:
        parts.append(proc.stderr)
    return proc.returncode, "\n".join(parts)


# --------------------------------------------------------------------------
# Catalog
# --------------------------------------------------------------------------


def build_catalog():
    """Build the catalog dictionary from the embedded seed."""
    return {
        "source": SOURCE,
        "verified_on": VERIFIED_ON,
        "switches": [dict(entry) for entry in SWITCHES],
        "debug_bits": {str(bit): name for bit, name in sorted(DEBUG_BITS.items())},
        "usage_recipes": [dict(recipe) for recipe in USAGE_RECIPES],
    }


def catalog_json(catalog):
    """Serialize the catalog exactly the way it is written to disk."""
    return json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"


def write_catalog(catalog, path):
    """Write the catalog to *path*, creating parent directories as needed."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(catalog_json(catalog))


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def verify_against_live(catalog, explicit_dir=None):
    """Compare the catalog against a live ``idat.exe -h`` run.

    Prints a report and returns a process exit code (0 for pass, 1 for
    failure).
    """
    print("IDA command-line switch verification")
    print("  source      : %s" % catalog["source"])

    idat_path, ida_dir = find_ida_text_binary(explicit_dir)
    if not idat_path:
        print("  idat binary : NOT FOUND")
        print("")
        print("  Searched directories (first hit wins):")
        for directory in candidate_ida_dirs(explicit_dir):
            print("    - %s%s" % (directory, "" if os.path.isdir(directory) else "  [missing]"))
        print("")
        print("RESULT: FAIL - no IDA text-mode binary (idat) found; "
              "pass --ida-dir or set IDADIR.")
        return 1

    print("  idat binary : %s" % idat_path)
    print("  ida dir     : %s" % ida_dir)

    try:
        returncode, output = run_ida_help(idat_path)
    except subprocess.TimeoutExpired:
        print("")
        print("RESULT: FAIL - '%s -h' timed out after 60 seconds." % idat_path)
        return 1
    except OSError as exc:
        print("")
        print("RESULT: FAIL - could not run '%s -h': %s" % (idat_path, exc))
        return 1

    live_keys, live_bits, raw_tokens, line_count = parse_help_output(output)

    print("  exit code   : %d (2 is expected for -h)" % returncode)
    print("  help lines  : %d" % line_count)
    print("  raw tokens  : %d -> %d distinct switch key(s)"
          % (len(raw_tokens), len(live_keys)))

    if not live_keys:
        print("")
        print("  --- first 20 lines of the live output ---")
        for line in output.splitlines()[:20]:
            print("  | %s" % line)
        print("")
        print("RESULT: FAIL - the live run produced no parseable switch lines.")
        return 1

    # Map every acceptable live spelling (switch plus aliases) to its entry.
    alias_of = {}
    for entry in catalog["switches"]:
        alias_of[entry["switch"]] = entry["switch"]
        for alias in entry.get("aliases", []):
            alias_of[alias] = entry["switch"]

    live_set = set(live_keys)

    confirmed = []
    missing = []
    for entry in catalog["switches"]:
        spellings = [entry["switch"]] + list(entry.get("aliases", []))
        if any(spelling in live_set for spelling in spellings):
            confirmed.append(entry["switch"])
        else:
            missing.append(entry["switch"])

    extra = sorted(key for key in live_set if key not in alias_of)

    seed_bits = {int(bit) for bit in catalog["debug_bits"]}
    live_bit_values = set(live_bits)
    bits_match = seed_bits == live_bit_values

    print("  seed entries: %d" % len(catalog["switches"]))
    print("")
    print("  confirmed   : %d/%d" % (len(confirmed), len(catalog["switches"])))
    print("  missing     : %s" % (", ".join(missing) if missing else "(none)"))
    print("  extra       : %s" % (", ".join(extra) if extra else "(none)"))
    print("  debug bits  : %d live / %d seed (bit values match: %s)"
          % (len(live_bits), len(seed_bits), "yes" if bits_match else "NO"))

    if not bits_match:
        print("    only seed : %s"
              % (", ".join(str(b) for b in sorted(seed_bits - live_bit_values)) or "(none)"))
        print("    only live : %s"
              % (", ".join(str(b) for b in sorted(live_bit_values - seed_bits)) or "(none)"))

    batch_line = "ida -c -A -Sanalysis.idc input-file"
    print("  batch recipe: %s" % ("confirmed" if batch_line in output else "not found"))

    print("")
    if missing:
        print("RESULT: FAIL - %d seed switch(es) not confirmed by the live help: %s"
              % (len(missing), ", ".join(missing)))
        return 1
    print("RESULT: OK - the live help output confirms every seed switch.")
    if extra:
        print("        (%d live token(s) are not in the seed; see 'extra' above.)" % len(extra))
    return 0


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

DEFAULT_JSON_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "ida_cli_switches.json"
)


def build_parser():
    """Build the argparse parser."""
    parser = argparse.ArgumentParser(
        prog="scan_ida_cli.py",
        description=(
            "Emit a machine-readable catalog of the IDA Pro 9.4 command-line "
            "switches, and optionally re-derive it from a live 'idat.exe -h' "
            "run."
        ),
        epilog=(
            "Without --verify or --print the catalog is simply regenerated "
            "from the embedded seed and written to the --json path "
            "(idempotent)."
        ),
    )
    parser.add_argument(
        "--ida-dir",
        default=None,
        metavar="DIR",
        help=(
            "IDA installation directory. Defaults to %%IDADIR%%, then "
            "%%IDA_PATH%%, then C:\\Program Files\\IDAPro, then auto-probed "
            "install roots and the PATH."
        ),
    )
    parser.add_argument(
        "--json",
        default=DEFAULT_JSON_PATH,
        metavar="PATH",
        help="catalog output path (default: %(default)s)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "run 'idat.exe -h' and report which seed switches the live help "
            "output confirms or misses; exit 1 when nothing parseable is seen"
        ),
    )
    parser.add_argument(
        "--print",
        dest="print_catalog",
        action="store_true",
        help="print the catalog JSON to stdout",
    )
    return parser


def main(argv=None):
    """Entry point.  Returns the process exit code."""
    args = build_parser().parse_args(argv)

    catalog = build_catalog()
    text = catalog_json(catalog)

    exit_code = 0
    if args.verify:
        exit_code = verify_against_live(catalog, args.ida_dir)

    try:
        write_catalog(catalog, args.json)
    except OSError as exc:
        print("error: could not write catalog to '%s': %s" % (args.json, exc),
              file=sys.stderr)
        return 1
    print("catalog written: %s (%d switches, %d debug bits, %d recipes)"
          % (args.json, len(catalog["switches"]), len(catalog["debug_bits"]),
             len(catalog["usage_recipes"])))

    if args.print_catalog:
        print("")
        print("--- catalog JSON ---")
        sys.stdout.write(text)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
