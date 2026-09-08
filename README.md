# C / C++ Coding Standard Scanner

A static scanner for C and C++ source, in the spirit of a lint tool. It reads
the source directly — no build, no include paths, no toolchain — and reports
potential departures from four rule sets, selected by language and configuration:

| Family | What it covers |
|---|---|
| **C-STD** | House C coding standard: layout, naming, file and function structure, types, control flow, error handling, prohibited functions |
| **MISRA C:2025** | The MISRA rules that are checkable from source alone (the 2025 edition, including the new 8.18, 11.11 and 19.3) |
| **MISRA C++:2023** | 28 implemented lexical checks based on the 2023 C++17 guidelines; see the coverage notes below |
| **CWE** | The memory-safety, initialisation, format-string and concurrency weaknesses that matter in C |

The output is an Excel workbook naming **the file, the line, the rule and the
offending code**, plus why the rule exists and how to fix it.

127 rules ship enabled by default. MISRA C rules apply to C files and MISRA
C++ rules to C++ files. `python scan_c_code.py --list-rules` prints the
catalogue and each C++ check's implemented coverage.

---

## Requirements

* Python 3.8 or later
* `openpyxl` (required) and `PyYAML` (only if you use a YAML config file)

```bash
pip install openpyxl pyyaml
```

## Quick start — the window

Double-click **`run_gui.bat`** (or `python cstdscan_gui.py`).

1. **Browse folder...** and pick the tree to scan.
2. Press **Scan** (or F5). Progress runs along the bottom.
3. Work down the **Findings** list. Clicking a row shows the rule, the
   offending line, why it matters and how to fix it in the panel below.
4. **Double-click** a row to open the source file; right-click for *Show it in
   Explorer*, *Copy file and line*, or *Hide this rule for now*.
5. The Excel report is written as you scan, into `Reports\` beside the tool.
   **Open report** opens it.

Other things in the window:

* **Filter** box and **Severity** dropdown narrow the list as you type.
* Click any column heading to sort by it; click again to reverse.
* **By rule** and **By file** tabs show where the weight sits; **Log** shows
  what was scanned and anything that went wrong.
* **Choose rules...** opens the full catalogue — click a row to switch a rule
  on or off, or use *Disable advisory* / *Disable the noisy four*.
* **Skip the four noisiest rules** is a one-tick version of the same thing,
  for a first look at an existing codebase.
* Folder, options and rule choices are remembered between sessions.

## Quick start — the command line

```bash
python scan_c_code.py C:\path\to\src
```

That scans every `.c`, `.h`, `.cpp` and `.hpp` file under the path and writes
`CodeStandardReport_<timestamp>.xlsx` into the current directory. On Windows,
`run_scan.bat <path>` does the same thing with a prompt at the end.

More:

```bash
python scan_c_code.py src -o Reports\scan.xlsx --csv Reports\scan.csv
python scan_c_code.py src --min-severity High
python scan_c_code.py src --only C-STD-6.1.5,CWE-476,CWE-787
python scan_c_code.py src --disable C-STD-5.9.1,C-STD-4.4.1
python scan_c_code.py src --exclude "*/Drivers/*" --exclude "*/Middlewares/*"
python scan_c_code.py src --exclude-name "*- copy*" --exclude-name "*.bak"
python scan_c_code.py src --fail-on High          # exit code 1 for CI
python scan_c_code.py --list-rules
python scan_c_code.py --write-config cstdscan.yaml
```

## MISRA C++:2023 support

Select **MISRA C++:2023** in the window, or use:

```bash
python scan_c_code.py src --std "MISRA C++:2023" -o Reports/cpp_scan.xlsx
python scan_c_code.py src --std "MISRA C++:2023" --language c++ --fail-on High
python scan_c_code.py src --header-language c++
python scan_c_code.py src --only MISRA-CPP-12.3.1,MISRA-CPP-26.3.1
python scan_c_code.py samples/sample_cpp_good.cpp --std "MISRA C++:2023"
python -m unittest -v test_misra_cpp
```

The rule ID `MISRA-CPP-12.3.1` refers to Rule 12.3.1 of MISRA C++:2023.
The existing `MISRA-...` IDs continue to refer to MISRA C:2025.
Rule classes follow the supplied 2023 document. Severity is a scanner
priority: the new Required checks use High and Advisory checks use Low.
For example, dynamic allocation is Advisory (21.6.1).

**Language selection:** `auto` treats `.c` as C, and `.cpp`, `.cc`, `.cxx`,
`.hpp`, `.hh`, `.hxx` as C++. Ambiguous `.h` files default to C when both
MISRA families are selected. Selecting only the C++ MISRA family makes
`.h` files C++. Use `--header-language c++` for C++ headers in mixed projects,
or `--language c++` to interpret every selected file as C++. Both controls
are available in the GUI and YAML/JSON configuration. Existing GUI standard
choices are retained, and the new C++ family is enabled on the first upgrade.

The implementation is a **lexical subset**, not a complete MISRA compliance
checker. It does not compile C++17, resolve types or overloads, instantiate
templates, expand macros, determine active conditional branches, or perform
whole-program lifetime/ownership analysis. A clean scan is not proof of
MISRA compliance. Rules not listed below are not implemented for C++.
House C style and CWE checks remain separately selectable; they retain
their existing heuristics and can be noisy on idiomatic C++.

| Rule numbers (prefix `MISRA-CPP-`) | Implemented checks |
|---|---|
| 5.7.1, 5.7.3 | Nested block-comment openers and line splices in line comments |
| 5.13.3, 5.13.5 | Octal integer literals and suffixes starting with lowercase `l` |
| 7.11.1 | `NULL` tokens; zero-valued pointer expressions are not analyzed |
| 8.2.2 | Built-in scalar C-style/functional casts; excludes `(void)` and brace initialization |
| 8.2.5 | `reinterpret_cast` pointer/reference targets, with byte/character/void-pointer exceptions; integral targets require target-width analysis |
| 9.6.1, 10.3.1, 10.4.1, 12.3.1, 16.5.1 | `goto`, unnamed namespaces in headers, `asm`, `union`, logical operator overloads |
| 18.5.2 | Explicit termination calls and address uses |
| 19.0.2, 19.0.4, 19.1.2, 19.3.1, 19.6.1 | Function macros, externally defined macro undefinition, unmatched conditional groups, stringizing/token pasting, pragmas |
| 21.2.1, 21.2.3, 21.2.4 | C numeric conversions, `system`, `offsetof` |
| 21.6.1 | Ordinary `new`/`delete`, C allocation APIs and `std::make_unique/shared`; placement new and implicit container allocations are not checked |
| 21.10.1, 21.10.2 | C variadic facilities and non-local jump facilities/includes |
| 24.5.2, 25.5.1, 26.3.1, 30.0.1 | Raw memory copy/comparison, global locale changes, explicit `std::vector<bool>`, C stream I/O |

Library-name findings use Medium confidence because the scanner cannot bind
names to declarations. Explicit member calls and other qualified namespaces
are excluded, as are the multi-argument algorithm overloads of `std::remove`.
Aliases, indirect calls, macro-generated constructs and some type-dependent
exceptions require compiler-assisted analysis or review. The rule catalogue
and the workbook's **C++ coverage** sheet document the exact subset for each
implemented rule. The GUI also displays coverage with a selected finding.

Raw strings (including encoding prefixes), digit separators and continued
line comments are masked while preserving physical source line/column
positions. C++ checks inspect namespace and class bodies without relying on
the legacy C function parser; the Function column may be blank in those scopes.

Existing suppression mechanisms also accept C++ rule IDs:

```cpp
union Data { int i; float f; }; // cstd-ignore: MISRA-CPP-12.3.1 reviewed deviation
```

The source reference was the user-supplied `MISRA-CPP-2023-PDF-Cpp17.pdf`.
Rule descriptions here are scanner summaries; the licensed PDF is not
bundled or required to run the scanner.

## What the report contains

| Sheet | Contents |
|---|---|
| **Summary** | Scan metadata and totals by severity, standard, rule class and area; the most frequent rules; the worst files |
| **Violations** | One row per finding: severity, standard, rule id and title, file, line, column, function, the offending source line, what was found, why it matters, how to fix it, cross-referenced rules, confidence |
| **By file** | Per-file counts by severity, and the rule each file breaks most |
| **By rule** | Per-rule counts and how many files are affected |
| **Rules reference** | The full catalogue, with each rule marked enabled or disabled for this scan |
| **C++ coverage** | The implemented lexical scope and limitations of each MISRA C++:2023 check |

The Violations sheet is a filterable Excel table with the header row frozen,
so you can filter to, say, Critical + Security and work down the list.

**Severity** is the engineering impact (Critical / High / Medium / Low).
**Class** is the standards classification: Mandatory, Required, Advisory, or
Security for the CWE entries.
**Confidence** is High when the finding is certain from the source, Medium
when the check made a judgement a compiler would make better (for example,
whether a name is a pointer, or whether a function returns a value).

## Suppressing a finding

Put a comment on the offending line, or on the line above:

```c
/* cstd-ignore: MISRA-21.3 fixed pool allocated once at start-up */
pBlock = malloc(POOL_SIZE);

result = HAL_ADC_Start(&hadc1);   // NOLINT(C-STD-5.11.2)
```

Naming rules after the marker limits the suppression to those rules; a bare
`cstd-ignore` suppresses anything on that line. `cstd-ignore-file` anywhere in
a file's comments silences that whole file.

Suppress permanently instead with `disabled_rules` or
`per_path_disabled_rules` in the config file — that keeps the reason in one
reviewable place rather than scattered through the source.

## Configuration

`python scan_c_code.py --write-config cstdscan.yaml` writes a commented
starting point; pass it back with `-c cstdscan.yaml`. Anything you leave out
keeps its default. The keys worth knowing:

| Key | Purpose |
|---|---|
| `extensions`, `exclude` | which files are scanned, by path |
| `language`, `header_language` | `auto`, `c` or `c++`; language override for all files or ambiguous `.h` headers |
| `exclude_names` | which files are scanned, by bare file name - matches anywhere in the tree, so `"*- copy*"` skips every `... - Copy.c` regardless of folder |
| `max_line_length`, `max_function_lines`, `max_cyclomatic_complexity` | layout and complexity limits |
| `file_header_required_tags`, `function_header_tags` | what a heading comment must contain (set `require_file_header: false` to switch the check off) |
| `component_prefix_pattern`, `pointer_prefix`, `type_prefix`, `accept_type_suffix_t` | naming conventions |
| `magic_number_min_uses`, `magic_number_allow` | how tolerant the magic-number rule is |
| `loop_annotation_keywords` | comment text that marks a deliberate non-terminating task loop |
| `isr_name_patterns` | which function names count as interrupt context |
| `error_returning_patterns`, `void_returning_patterns` | which discarded return values are reported |
| `enabled_standards`, `min_severity`, `disabled_rules`, `enabled_rules`, `per_path_disabled_rules` | rule selection |

### Tuning the first scan

A first scan of an existing codebase is loud, and two rules account for most
of it:

* **C-STD-5.9.1** — every cast needs a justifying comment. Real, but it fires
  on hundreds of ordinary casts in code that was never written to the rule.
* **C-STD-4.4.1** — magic numbers used more than once.

Start with `--min-severity High` to see the findings that can bite, or
`--disable C-STD-5.9.1,C-STD-4.4.1` for a first pass, and turn them back on
per module as the code is brought up to standard.

`--exclude` vendor and generated trees (HAL drivers, RTOS, CubeMX output).
The standard applies to code you write, and scanning code you cannot change
only buries your own findings.

Stray copies and backups left in a working tree - `Adc1Task - Copy.c`, `main (2).c`, `old_main.c.bak` - are worth keeping out for the same reason: they are not the file that builds, so findings in them are usually noise, and duplicate function definitions in another file read as real project-wide violations (`MISRA-8.6`). `exclude_names` is on by default and matches the bare file name anywhere in the tree, not a path, so one pattern catches every copy regardless of which folder it landed in. The GUI has this as a separate **Skip file names like** field; the command line takes `--exclude-name`. Clear the field, or set `exclude_names: []`, to scan them anyway.

## Continuous integration

```bash
python scan_c_code.py src --min-severity High --fail-on Critical -q -o report.xlsx
```

Exit codes: `0` clean (or nothing at or above `--fail-on`), `1` findings at or
above the `--fail-on` severity, `2` a usage or configuration error.

## How it works, and what it cannot do

The scanner masks comments and string literals, tracks brace and paren depth,
and recovers the shape of each file: functions, parameters, declarations,
scopes, macros, typedefs, switch bodies. Checks run against that model, plus a
project-wide index used for the cross-file rules (duplicate definitions,
identifiers not distinct in 31 characters, typedef reuse, unnecessary external
linkage).

It is lexical, not a compiler, so:

* It does not expand macros. A rule broken only after expansion is not seen.
* It does not resolve `#include`, so types declared in headers outside the
  scan root are unknown; checks that need a type report Medium confidence.
* It does not follow inactive `#if` branches — they are read as ordinary code.
* Data-flow rules (uninitialised *use*, exact overflow, aliasing) are
  approximated by local heuristics; that is what the Confidence column is for.

The missing-return check (`C-STD-5.5.5`) does do real terminal-flow analysis
rather than looking at the last line: an if/else in which both arms return, a
switch with a default whose every clause returns, and a non-terminating loop
are all understood to leave the function without falling through. A `break`
inside an `if` is recognised as leaving its enclosing loop, while one inside a
nested loop or switch is not. Functions listed in `noreturn_patterns`
(`abort`, `exit`, `Error_Handler`, `NVIC_SystemReset` and friends) end a path
too.

Every finding names the exact line, so a Medium-confidence finding costs a few
seconds to confirm or dismiss.

## Layout

```
cstdscan_gui.py         the desktop window
run_gui.bat             starts the window
scan_c_code.py          command line front end
run_scan.bat            command line wrapper for Windows
cstdscan/
    model.py            the rule catalogue: id, severity, why, how to fix
    source.py           lexical model of one translation unit
    checks.py           the per-file rule checks
    misra_cpp.py        MISRA C++:2023 lexical checks
    misra_cpp_rules.py  C++ rule catalogue and coverage descriptions
    project.py          file discovery, cross-file index and checks
    report.py           Excel and CSV writers
    config.py           defaults, config file loading, rule filtering
    scanner.py          orchestration
samples/                sample_good.* scans clean; sample_bad.* breaks 50+ rules
selftest.py             checks the scanner against the samples
test_misra_cpp.py        C++ rule, exception, language and report regressions
Reports/                where the window puts its reports (created on first scan)
gui_settings.json       the window's remembered settings (created on first exit)
```

## Adding a rule

1. Add a `Rule(...)` entry to `_CATALOGUE` in `cstdscan/model.py` — id,
   standard, area, severity, class, title, why it matters, how to fix.
2. Add the check to `cstdscan/checks.py` and call `self.add("<rule id>", line,
   column, detail)`.
3. Add a case to `samples/sample_bad.c` and run `python selftest.py`.

The catalogue is what the Rules reference sheet prints, so a rule that is
listed but not implemented would misrepresent the scan — add both together.
