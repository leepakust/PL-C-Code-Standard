#!/usr/bin/env python3
"""Command line front end for the C / C++ coding standard scanner.

    python scan_c_code.py <path> [<path> ...] [options]

Scans C and C++ source for departures from the house C coding standard,
MISRA C:2025, MISRA C++:2023 and the CWE weakness list, and writes an Excel report naming
the file, the line, the rule and the offending code.
"""

import argparse
import datetime
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cstdscan import __version__                             # noqa: E402
from cstdscan.config import Config, DEFAULTS                 # noqa: E402
from cstdscan.model import RULES, SEVERITY_ORDER             # noqa: E402
from cstdscan.misra_cpp_rules import COVERAGE                # noqa: E402
from cstdscan.report import write_csv, write_excel           # noqa: E402
from cstdscan.scanner import scan                            # noqa: E402


SEVERITIES = ["Critical", "High", "Medium", "Low"]


def build_parser():
    p = argparse.ArgumentParser(
        prog="scan_c_code",
        description="Scan C/C++ source against the house C coding standard, "
                    "MISRA C:2025, MISRA C++:2023 and the CWE weakness list, and write an "
                    "Excel report of every violation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples
  python scan_c_code.py .\\src
  python scan_c_code.py .\\src -o Reports\\scan.xlsx
  python scan_c_code.py .\\src --min-severity High --fail-on High
  python scan_c_code.py .\\src --only C-STD-6.1.5,CWE-476
  python scan_c_code.py --list-rules
""")
    p.add_argument("paths", nargs="*",
                   help="files or directories to scan")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Excel report path "
                        "(default: CodeStandardReport_<timestamp>.xlsx)")
    p.add_argument("--csv", metavar="FILE",
                   help="also write the violation list as CSV")
    p.add_argument("-c", "--config", metavar="FILE",
                   help="YAML or JSON configuration file")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="path glob to skip (repeatable)")
    p.add_argument("--exclude-name", action="append", default=[],
                   metavar="GLOB",
                   help='file name glob to skip wherever it appears '
                        'in the tree, e.g. "*- Copy*" (repeatable, '
                        'case-insensitive)')
    p.add_argument("--ext", metavar="LIST",
                   help="comma separated list of extensions to scan")
    p.add_argument("--language", choices=["auto", "c", "c++"],
                   help="source language (default: auto by extension)")
    p.add_argument("--header-language", choices=["auto", "c", "c++"],
                   help="language for ambiguous .h files")
    p.add_argument("--min-severity", choices=SEVERITIES, metavar="SEV",
                   help="report only this severity or worse "
                        "(Critical, High, Medium, Low)")
    p.add_argument("--std", metavar="LIST",
                   help="comma separated standards to apply "
                        "(C-STD, 'MISRA C:2025', 'MISRA C++:2023', CWE)")
    p.add_argument("--only", metavar="LIST",
                   help="comma separated rule ids - run only these")
    p.add_argument("--disable", metavar="LIST",
                   help="comma separated rule ids to switch off")
    p.add_argument("--max-line-length", type=int, metavar="N",
                   help="line length limit (default %d)"
                        % DEFAULTS["max_line_length"])
    p.add_argument("--fail-on", choices=SEVERITIES, metavar="SEV",
                   help="exit with status 1 if any violation of this "
                        "severity or worse is found")
    p.add_argument("--top", type=int, default=15, metavar="N",
                   help="how many findings to print to the console "
                        "(default 15, 0 for none)")
    p.add_argument("--list-rules", action="store_true",
                   help="print the rule catalogue and exit")
    p.add_argument("--write-config", metavar="FILE",
                   help="write a commented default configuration file "
                        "and exit")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress progress output")
    p.add_argument("--version", action="version",
                   version="C/C++ coding standard scanner %s" % __version__)
    return p


def list_rules():
    order = sorted(RULES.values(),
                   key=lambda r: (r.standard, SEVERITY_ORDER[r.severity],
                                  r.id))
    width = max(len(r.id) for r in order)
    current = None
    for rule in order:
        if rule.standard != current:
            current = rule.standard
            print("\n%s" % current)
            print("-" * len(current))
        print("  %-*s  %-8s %-9s %s"
              % (width, rule.id, rule.severity, rule.rule_class, rule.title))
        if rule.id in COVERAGE:
            print("    Coverage: " + COVERAGE[rule.id])
    print("\n%d rules total." % len(order))


CONFIG_TEMPLATE = """# C / C++ coding standard scanner configuration.
# Every key below is optional; anything omitted keeps its built-in default.

# --- what to scan ---------------------------------------------------------
extensions: [".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"]
language: "auto"          # auto | c | c++
header_language: "auto"   # set c++ for C++ .h files in mixed projects
exclude:
  - "*/build/*"
  - "*/Debug/*"
  - "*/Release/*"
  - "*/Drivers/*"          # vendor code you did not write
  - "*/Middlewares/*"
exclude_names:            # matched against the bare file name, anywhere
  - "*- copy*"             # e.g. "Adc1Task - Copy.c"
  - "*.bak"

# --- layout ---------------------------------------------------------------
max_line_length: 120
max_function_lines: 120
max_cyclomatic_complexity: 15
check_trailing_whitespace: true
check_brace_on_own_line: true

# --- documentation --------------------------------------------------------
require_file_header: true
file_header_required_tags: ["DESCRIPTION"]
require_function_header: true
function_header_tags: ["FUNCTION", "DESCRIPTION", "@brief"]

# --- naming ---------------------------------------------------------------
component_prefix_pattern: "^[A-Z][A-Za-z0-9]{1,7}_"
pointer_prefix: "p"
type_prefix: "t"

# --- behaviour ------------------------------------------------------------
magic_number_min_uses: 2
magic_number_allow: ["0", "1", "2", "0x00", "0x01", "0xFF"]
loop_annotation_keywords: ["non-terminating", "task loop", "runs forever"]
isr_name_patterns: ["*IRQHandler", "*_Handler", "*Callback", "*_ISR"]
error_returning_patterns:
  - "malloc"
  - "snprintf"
  - "HAL_*"
  - "os*"
check_project_return_values: true

# --- rule selection -------------------------------------------------------
enabled_standards: ["C-STD", "MISRA C:2025", "MISRA C++:2023", "CWE"]
min_severity: "Low"
disabled_rules: []
# enabled_rules: ["C-STD-6.1.5", "CWE-476"]   # if set, only these run
per_path_disabled_rules:
  "Core/*": ["C-STD-5.1.3", "C-STD-5.4.1"]
"""


def apply_overrides(config, args):
    if args.language:
        config["language"] = args.language
    if args.header_language:
        config["header_language"] = args.header_language
    if args.exclude:
        config["exclude"] = list(config["exclude"]) + args.exclude
    if args.exclude_name:
        config["exclude_names"] = (list(config["exclude_names"]) +
                                   args.exclude_name)
    if args.ext:
        config["extensions"] = [e if e.startswith(".") else "." + e
                                for e in _split(args.ext)]
    if args.min_severity:
        config["min_severity"] = args.min_severity
    if args.std:
        config["enabled_standards"] = _split(args.std)
    if args.only:
        config["enabled_rules"] = _split(args.only)
    if args.disable:
        config["disabled_rules"] = list(config["disabled_rules"]) + \
            _split(args.disable)
    if args.max_line_length:
        config["max_line_length"] = args.max_line_length
    return config


def _split(text):
    return [part.strip() for part in text.split(",") if part.strip()]


def print_findings(violations, limit):
    if limit <= 0 or not violations:
        return
    print("\nMost serious findings")
    print("-" * 78)
    for v in violations[:limit]:
        rule = v.rule()
        print("%-8s %-13s %s:%d" % (rule.severity, v.rule_id, v.file, v.line))
        print("         %s" % rule.title)
        if v.detail:
            print("         found: %s" % v.detail)
        if v.code:
            print("         code : %s" % v.code[:100])
    if len(violations) > limit:
        print("... and %d more in the report." % (len(violations) - limit))


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list_rules:
        list_rules()
        return 0

    if args.write_config:
        with open(args.write_config, "w", encoding="utf-8") as fh:
            fh.write(CONFIG_TEMPLATE)
        print("Wrote %s" % args.write_config)
        return 0

    if not args.paths:
        build_parser().print_help()
        return 2

    for path in args.paths:
        if not os.path.exists(path):
            print("error: no such file or directory: %s" % path,
                  file=sys.stderr)
            return 2

    try:
        config = apply_overrides(Config.load(args.config), args)
        config.language_for("")
    except (KeyError, ValueError) as exc:
        print("error: bad configuration: %s" % exc, file=sys.stderr)
        return 2

    def progress(rel, done, total):
        if not args.quiet and total:
            sys.stdout.write("\rreading %d/%d  %-52s" % (done, total,
                                                         rel[-52:]))
            sys.stdout.flush()

    result = scan(args.paths, config, progress=progress)
    if not args.quiet:
        sys.stdout.write("\r" + " " * 78 + "\r")

    output = args.output
    if not output:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output = "CodeStandardReport_%s.xlsx" % stamp

    write_excel(output, result.violations, result.stats, config)
    if args.csv:
        write_csv(args.csv, result.violations)

    counts = Counter(v.rule().severity for v in result.violations)
    print("Scanned %d files (%d lines) against %d active rules."
          % (result.stats["file_count"], result.stats["line_count"],
             result.stats["active_rules"]))
    print("Violations: %d   (%s)"
          % (len(result.violations),
             ", ".join("%s %d" % (s, counts.get(s, 0)) for s in SEVERITIES)))
    if result.errors:
        print("\n%d file(s) could not be fully processed:"
              % len(result.errors))
        for rel, message in result.errors[:10]:
            print("  %s: %s" % (rel, message.splitlines()[0]))

    print_findings(result.violations, args.top)
    print("\nReport written to %s" % os.path.abspath(output))
    if args.csv:
        print("CSV written to    %s" % os.path.abspath(args.csv))

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        worst = min((SEVERITY_ORDER[v.rule().severity]
                     for v in result.violations), default=99)
        if worst <= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
