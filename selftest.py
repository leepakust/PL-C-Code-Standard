#!/usr/bin/env python3
"""Self test: run the scanner over the samples and check what it reports.

    python selftest.py

`samples/sample_good.*` must scan clean, and `samples/sample_bad.*` must
raise every rule listed in EXPECTED_IN_BAD.  Run this after changing a check.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cstdscan.config import Config          # noqa: E402
from cstdscan.model import RULES            # noqa: E402
from cstdscan.scanner import scan           # noqa: E402


EXPECTED_IN_BAD = [
    "C-STD-4.2.2",      # if without braces
    "C-STD-4.4.1",      # magic number repeated
    "C-STD-5.1.2",      # no file heading
    "C-STD-5.1.3",      # no function heading
    "C-STD-5.3.6a",     # #pragma once
    "C-STD-5.4.1",      # no component prefix
    "C-STD-5.5.3",      # untyped parameter
    "C-STD-5.5.5",      # falls off the end of a non-void function
    "C-STD-5.5.2",      # non-literal format string
    "C-STD-5.6.6b",     # pointer typedef
    "C-STD-5.7.2",      # uninitialised local
    "C-STD-5.8.4",      # string literal to non-const pointer
    "C-STD-5.10.1",     # switch without default
    "C-STD-5.10.3",     # uncommented fall-through
    "C-STD-5.10.4",     # unbounded loop
    "C-STD-5.10.5",     # if/else if chain with no else
    "C-STD-5.12.2",     # unparenthesised macro parameter
    "C-STD-6.1.5",      # prohibited function
    "C-STD-6.1.6",      # dangerous function, no justification
    "MISRA-7.1",        # octal constant
    "MISRA-8.18",       # tentative definition in a header
    "MISRA-11.11",      # implicit NULL comparison
    "MISRA-18.8",       # variable-length array
    "MISRA-21.3",       # dynamic memory
    "MISRA-21.6",       # standard I/O
    "MISRA-21.8",       # exit()
    "CWE-369",          # division with no zero check
    "CWE-416",          # pointer not cleared after free
    "CWE-476",          # unchecked pointer parameter
    "CWE-787",          # unbounded copy length
]


def main():
    failures = []
    samples = os.path.join(HERE, "samples")

    good = scan([os.path.join(samples, "sample_good.c"),
                 os.path.join(samples, "sample_good.h")], Config())
    if good.violations:
        for v in good.violations:
            failures.append("compliant sample raised %s at %s:%d (%s)"
                            % (v.rule_id, v.file, v.line, v.detail))
    if good.errors:
        failures.extend("error: %s: %s" % e for e in good.errors)

    bad = scan([os.path.join(samples, "sample_bad.c"),
                os.path.join(samples, "sample_bad.h")], Config())
    raised = {v.rule_id for v in bad.violations}
    for rule_id in EXPECTED_IN_BAD:
        if rule_id not in RULES:
            failures.append("unknown rule id in the expectation list: %s"
                            % rule_id)
        elif rule_id not in raised:
            failures.append("non-compliant sample did not raise %s (%s)"
                            % (rule_id, RULES[rule_id].title))
    if bad.errors:
        failures.extend("error: %s: %s" % e for e in bad.errors)

    print("compliant sample : %d violations (expected 0)"
          % len(good.violations))
    print("bad sample       : %d violations, %d distinct rules"
          % (len(bad.violations), len(raised)))
    print("rule catalogue   : %d rules" % len(RULES))

    if failures:
        print("\nFAILED")
        for line in failures:
            print("  " + line)
        return 1
    print("\nPASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
