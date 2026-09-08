"""Per-file rule checks.

Each check is deliberately lexical and self-contained: it works from the
masked source produced by `source.SourceFile`, so the scanner runs against
any C or C++ tree without a build, include paths or a toolchain.  Where a
check cannot be certain from the source alone it reports a lower confidence
rather than staying silent.
"""

import fnmatch
import re

from .model import RULES, Violation
from .source import (BASIC_TYPE_WORDS, CONTROL_KEYWORDS, C_KEYWORDS,
                     FIXED_WIDTH_TYPES, STD_HEADERS, TYPE_KEYWORDS,
                     split_top_level)


# --------------------------------------------------------------------------
# library function tables
# --------------------------------------------------------------------------

PROHIBITED_FUNCTIONS = {
    "gets": ("unbounded input, no overflow protection", "fgets", "CWE-242"),
    "strcpy": ("unbounded copy", "strlcpy or snprintf", "CWE-120"),
    "strcat": ("unbounded concatenation", "strlcat or snprintf", "CWE-120"),
    "strncpy": ("does not terminate when the source is longer",
                "strlcpy", "CWE-170"),
    "strncat": ("length is characters to copy, not the destination size",
                "strlcat", "CWE-787"),
    "strtok": ("not re-entrant and modifies its input",
               "a purpose-written parser", "CWE-663"),
    "sprintf": ("no length limit", "snprintf", "CWE-120"),
    "vsprintf": ("no length limit", "vsnprintf", "CWE-120"),
    "wcscat": ("unbounded wide-character concatenation", "wcslcat",
               "CWE-120"),
    "wcscpy": ("unbounded wide-character copy", "wcslcpy", "CWE-120"),
    "wcsncpy": ("no null-termination guarantee", "wcslcpy", "CWE-170"),
    "wcsncat": ("length is characters, not the destination size", "wcslcat",
                "CWE-787"),
    "system": ("arguments are passed to a shell", "CreateProcess or exec*",
               "CWE-78"),
    "popen": ("arguments are passed to a shell", "CreateProcess or exec*",
              "CWE-78"),
    "ShellExecute": ("arguments are passed to a shell", "CreateProcess",
                     "CWE-78"),
    "WinExec": ("arguments are passed to a shell", "CreateProcess",
                "CWE-78"),
    "alloca": ("unbounded stack allocation", "a fixed-size local buffer",
               "CWE-770"),
}

DANGEROUS_FUNCTIONS = {
    "memcpy": "source and destination must not overlap",
    "memmove": "must not be used on sensitive data - it copies via a "
               "temporary",
    "strlen": "the buffer must be known to be null-terminated",
    "malloc": "the returned pointer must be checked",
    "calloc": "the returned pointer must be checked",
    "realloc": "the original pointer is lost when the call fails",
    "free": "the pointer must be set to NULL afterwards",
    "abs": "the type-correct variant must be used (abs/labs/fabs)",
    "labs": "the type-correct variant must be used (abs/labs/fabs)",
    "fabs": "the type-correct variant must be used (abs/labs/fabs)",
}

MISRA_LIBRARY_FUNCTIONS = {
    "malloc": "MISRA-21.3", "calloc": "MISRA-21.3",
    "realloc": "MISRA-21.3", "free": "MISRA-21.3",
    "aligned_alloc": "MISRA-21.3",
    "printf": "MISRA-21.6", "fprintf": "MISRA-21.6", "scanf": "MISRA-21.6",
    "sscanf": "MISRA-21.6", "fscanf": "MISRA-21.6", "puts": "MISRA-21.6",
    "fopen": "MISRA-21.6", "fclose": "MISRA-21.6", "fgets": "MISRA-21.6",
    "putchar": "MISRA-21.6", "getchar": "MISRA-21.6", "perror": "MISRA-21.6",
    "atof": "MISRA-21.7", "atoi": "MISRA-21.7", "atol": "MISRA-21.7",
    "atoll": "MISRA-21.7",
    "abort": "MISRA-21.8", "exit": "MISRA-21.8", "atexit": "MISRA-21.8",
    "quick_exit": "MISRA-21.8", "at_quick_exit": "MISRA-21.8",
    "bsearch": "MISRA-21.9", "qsort": "MISRA-21.9",
    "time": "MISRA-21.10", "clock": "MISRA-21.10", "mktime": "MISRA-21.10",
    "asctime": "MISRA-21.10", "ctime": "MISRA-21.10",
    "gmtime": "MISRA-21.10", "localtime": "MISRA-21.10",
    "strftime": "MISRA-21.10", "difftime": "MISRA-21.10",
    "setjmp": "MISRA-21.4", "longjmp": "MISRA-21.4",
    "signal": "MISRA-21.5", "raise": "MISRA-21.5",
}

FORMAT_FUNCTIONS = {
    "printf": 0, "vprintf": 0, "puts": None,
    "fprintf": 1, "vfprintf": 1,
    "sprintf": 1, "vsprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
    "wprintf": 0, "fwprintf": 1, "swprintf": 2,
    "syslog": 1,
}

RESERVED_PREFIX = re.compile(r"^_[_A-Z]")

NUMBER_RE = re.compile(
    r"(?<![\w.])("
    r"0[xX][0-9a-fA-F]+[uUlL]*"
    r"|\d+\.\d*(?:[eE][-+]?\d+)?[fFlL]?"
    r"|\.\d+(?:[eE][-+]?\d+)?[fFlL]?"
    r"|\d+[uUlLfF]*"
    r")(?![\w.])")

IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def iter_statements(text, start, end):
    """Yield (statement_text, offset, brace_depth) for a region of source.

    Statements are separated by ';', '{' and '}' at paren depth zero, which
    is enough to walk declarations and simple statements.
    """
    depth = 0
    paren = 0
    cur = []
    cur_start = start
    i = start
    while i < end:
        c = text[i]
        if c in "([":
            paren += 1
        elif c in ")]":
            paren = max(0, paren - 1)
        if paren == 0 and c in ";{}":
            chunk = "".join(cur)
            stripped = chunk.strip()
            if stripped:
                off = cur_start + (len(chunk) - len(chunk.lstrip()))
                yield stripped, off, depth
            if c == "{":
                depth += 1
            elif c == "}":
                depth = max(0, depth - 1)
            cur = []
            cur_start = i + 1
        else:
            cur.append(c)
        i += 1
    chunk = "".join(cur)
    if chunk.strip():
        off = cur_start + (len(chunk) - len(chunk.lstrip()))
        yield chunk.strip(), off, depth


def matching_close(text, open_index, open_ch="(", close_ch=")"):
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return -1


def next_code_char(text, index):
    """Index of the next non-whitespace character at or after `index`."""
    while index < len(text) and text[index].isspace():
        index += 1
    return index if index < len(text) else -1


class FileChecker:
    def __init__(self, sf, config, index=None):
        self.sf = sf
        self.cfg = config
        self.index = index
        self.violations = []
        self.globals = {}
        self.locals_by_func = {}

    # ------------------------------------------------------------- plumbing
    def add(self, rule_id, line, col=1, detail="", also=None,
            confidence="High", code=None):
        rule = RULES.get(rule_id)
        if rule is None:
            raise KeyError("undefined rule id %r" % rule_id)
        if not self.cfg.rule_enabled(rule, self.sf.rel):
            return
        if self._suppressed(rule_id, line):
            return
        text = code if code is not None else self.sf.raw(line)
        fn = self.sf.func_at_line.get(line)
        self.violations.append(Violation(
            rule_id=rule_id, file=self.sf.rel, line=line, column=max(1, col),
            code=text.strip()[:400], detail=detail,
            function=fn.name if fn else "",
            also=list(also or []), confidence=confidence))

    def _suppressed(self, rule_id, line):
        blob = self.sf.comments_near(line, before=1)
        if not blob:
            return False
        low = blob.lower()
        if "cstd-ignore-file" in low:
            return True
        for marker in ("cstd-ignore", "nolint", "cstd-suppress"):
            pos = low.find(marker)
            while pos >= 0:
                tail = blob[pos:pos + 200]
                ids = re.findall(r"[A-Za-z]+-[\d.]+[a-z]?|CWE-\d+", tail)
                if not ids or rule_id in ids:
                    return True
                pos = low.find(marker, pos + 1)
        return False

    def _enum_lines(self):
        """Lines that lie inside an enumerator list.

        Enumerator values are named constants already, so the magic-number
        and literal-suffix rules have nothing to say about them.
        """
        out = set()
        for m in re.finditer(r"\benum\b[^{;]*\{", self.sf.masked):
            close = matching_close(self.sf.masked, m.end() - 1, "{", "}")
            if close < 0:
                continue
            for ln in range(self.sf.line_of(m.start()),
                            self.sf.line_of(close) + 1):
                out.add(ln)
        return out

    # ------------------------------------------------------------- run them
    def run(self):
        self.enum_lines = self._enum_lines()
        self.collect_globals()
        self.check_file_identity()
        self.check_layout()
        self.check_includes()
        self.check_preprocessor()
        self.check_header_structure()
        self.check_functions()
        self.check_declarations()
        self.check_control_flow()
        self.check_expressions()
        self.check_library_use()
        self.check_magic_numbers()
        self.check_types_and_naming()
        return self.violations

    # ==================================================== file identity ====
    def check_file_identity(self):
        base = self.sf.name.rsplit(".", 1)[0]
        if not re.match(r"^[A-Za-z0-9_]+$", base):
            bad = "".join(sorted(set(c for c in base
                                     if not re.match(r"[A-Za-z0-9_]", c))))
            self.add("C-STD-4.3.1", 1, 1,
                     "file name contains %r" % bad, code=self.sf.name)

        if not self.cfg["require_file_header"]:
            return
        limit = self.cfg["file_header_scan_lines"]
        head_comments = []
        for start, _end, text in self.sf.comments:
            if start <= limit:
                head_comments.append(text)
        blob = "\n".join(head_comments)
        if not blob.strip():
            self.add("C-STD-5.1.2", 1, 1,
                     "no file heading block in the first %d lines" % limit,
                     code=self.sf.raw(1))
            return
        missing = [tag for tag in self.cfg["file_header_required_tags"]
                   if tag.lower() not in blob.lower()]
        if missing:
            self.add("C-STD-5.1.2", 1, 1,
                     "file heading is missing: %s" % ", ".join(missing),
                     code=self.sf.raw(1))

    # ========================================================== layout ====
    def check_layout(self):
        max_len = self.cfg["max_line_length"]
        for idx, raw in enumerate(self.sf.lines, start=1):
            if "\t" in raw:
                self.add("C-STD-4.2.3", idx, raw.index("\t") + 1,
                         "%d tab character(s) on this line" % raw.count("\t"))
            if len(raw) > max_len:
                self.add("C-STD-5.2.1", idx, max_len + 1,
                         "line is %d characters (limit %d)"
                         % (len(raw), max_len))
            if self.cfg["check_trailing_whitespace"] and \
                    raw != raw.rstrip() and raw.strip():
                self.add("C-STD-4.2.1", idx, len(raw.rstrip()) + 1,
                         "trailing whitespace")

        if self.cfg["check_brace_on_own_line"]:
            for idx, mline in enumerate(self.sf.mlines, start=1):
                if idx in self.sf.pp_lines:
                    continue
                stripped = mline.strip()
                if "{" not in stripped or stripped == "{":
                    continue
                before = stripped[:stripped.index("{")].strip()
                if not before:
                    continue
                # initialiser lists and struct/enum definitions are exempt
                if re.search(r"=\s*$", before) or before.endswith(","):
                    continue
                if re.match(r"^(typedef\s+)?(struct|union|enum)\b", before):
                    continue
                if re.search(r"\b(if|else|for|while|switch|do)\b\s*$",
                             before) or before.endswith(")"):
                    self.add("C-STD-5.2.2", idx,
                             mline.index("{") + 1,
                             "'{' shares a line with '%s'" % before[:60])

    # ======================================================== includes ====
    def check_includes(self):
        for idx, mline in enumerate(self.sf.mlines, start=1):
            if idx not in self.sf.pp_lines:
                continue
            raw = self.sf.raw(idx)
            m = re.match(r'\s*#\s*include\s*([<"])([^>"]+)[>"]', raw)
            if not m:
                continue
            bracket, name = m.group(1), m.group(2)
            base = name.split("/")[-1].lower()
            if base in STD_HEADERS:
                if bracket == '"':
                    self.add("C-STD-5.3.5", idx, 1,
                             "system header <%s> included with quotes" % name)
                if base == "setjmp.h":
                    self.add("MISRA-21.4", idx, 1, "includes <setjmp.h>")
                elif base == "signal.h":
                    self.add("MISRA-21.5", idx, 1, "includes <signal.h>")
                elif base == "stdarg.h":
                    self.add("MISRA-17.1", idx, 1, "includes <stdarg.h>")
            elif bracket == "<" and base.endswith(".h") and \
                    self.index is not None and base in self.index.header_names:
                self.add("C-STD-5.3.5a", idx, 1,
                         "project header %s included with angle brackets"
                         % name)

    # ==================================================== preprocessor ====
    def check_preprocessor(self):
        for idx in sorted(self.sf.pp_lines):
            raw = self.sf.raw(idx)
            stripped = raw.strip()
            if re.match(r"#\s*undef\b", stripped):
                name = stripped.split()[-1] if len(stripped.split()) > 1 \
                    else ""
                self.add("MISRA-20.5", idx, 1, "#undef %s" % name)
            m = re.match(r"#\s*define\s+([A-Za-z_]\w*)(\(([^)]*)\))?"
                         r"(.*)$", stripped)
            if not m:
                continue
            name, has_args, args, bodytext = (m.group(1), m.group(2),
                                              m.group(3), m.group(4))
            if name in C_KEYWORDS:
                self.add("MISRA-20.4", idx, 1,
                         "macro '%s' has the same name as a keyword" % name)
            if RESERVED_PREFIX.match(name) or name.startswith("__"):
                self.add("MISRA-5.10", idx, 1,
                         "'%s' is a reserved identifier" % name)
            body = self._macro_body(idx)
            if "##" in body or re.search(r"(?<![#\w])#(?!#)\s*\w", body):
                self.add("MISRA-20.10", idx, 1,
                         "macro '%s' uses # or ##" % name)
            if has_args and args is not None and args.strip():
                self._check_macro_parens(idx, name, args, body)

    def _macro_body(self, line):
        parts = []
        idx = line
        while idx <= self.sf.line_count:
            raw = self.sf.raw(idx)
            parts.append(raw.rstrip("\\"))
            if not raw.rstrip().endswith("\\"):
                break
            idx += 1
        text = " ".join(parts)
        return text.split("define", 1)[-1]

    def _check_macro_parens(self, line, name, args, body):
        after = body.split(")", 1)[-1].strip()
        if not after or after.startswith("{") or after.startswith("do"):
            return                                   # statement-like macro
        if re.match(r"^[A-Za-z_]\w*\s*\(", after) and after.endswith(")"):
            return                                   # simple forwarding call
        params = [a.strip() for a in args.split(",") if a.strip()]
        problems = []
        for p in params:
            if p == "...":
                continue
            for m in re.finditer(r"(?<![\w#])" + re.escape(p) + r"(?!\w)",
                                 after):
                before_ch = after[:m.start()].rstrip()[-1:]
                after_ch = after[m.end():].lstrip()[:1]
                if before_ch == "(" and after_ch == ")":
                    continue
                problems.append(p)
                break
        needs_outer = bool(re.search(r"[-+*/%<>&|^]", after)) and \
            not (after.startswith("(") and
                 matching_close(after, 0) == len(after) - 1)
        if problems:
            self.add("C-STD-5.12.2", line, 1,
                     "parameter(s) %s are not parenthesised in macro '%s'"
                     % (", ".join(sorted(set(problems))), name),
                     also=["MISRA-20.7"])
        elif needs_outer:
            self.add("C-STD-5.12.2", line, 1,
                     "the body of macro '%s' is not parenthesised as a whole"
                     % name)

    # ================================================ header structure ====
    def check_header_structure(self):
        if not self.sf.is_header:
            self._check_extern_in_source()
            return
        guard = None
        pragma_once = 0
        for idx in sorted(self.sf.pp_lines):
            raw = self.sf.raw(idx).strip()
            if re.match(r"#\s*pragma\s+once", raw):
                pragma_once = idx
                break
            m = re.match(r"#\s*ifndef\s+([A-Za-z_]\w*)", raw)
            if m:
                nxt = None
                for j in range(idx + 1, min(idx + 4, self.sf.line_count + 1)):
                    d = re.match(r"#\s*define\s+([A-Za-z_]\w*)",
                                 self.sf.raw(j).strip())
                    if d:
                        nxt = d.group(1)
                        break
                if nxt == m.group(1):
                    guard = (m.group(1), idx)
                break
        if pragma_once:
            self.add("C-STD-5.3.6a", pragma_once, 1,
                     "'#pragma once' used instead of an include guard")
        elif guard is None:
            self.add("C-STD-5.3.6", 1, 1,
                     "no #ifndef/#define include guard found",
                     also=["MISRA-4.10"],
                     code=self.sf.raw(1))
        else:
            name, line = guard
            expected = re.sub(r"[^A-Za-z0-9]", "_",
                              self.sf.name).upper().strip("_")
            if not name.upper().strip("_").endswith(expected):
                self.add("C-STD-5.3.6b", line, 1,
                         "guard '%s' does not match the file name "
                         "(expected %s)" % (name, expected))
            if RESERVED_PREFIX.match(name):
                self.add("MISRA-5.10", line, 1,
                         "guard macro '%s' is a reserved identifier" % name)

        for gname, info in self.globals.items():
            if info["is_extern"] or info["is_typedef"] or info["is_func"]:
                continue
            if info["is_static"]:
                continue
            self.add("MISRA-8.18", info["line"], 1,
                     "'%s' is defined, not declared, in a header" % gname)

    def _check_extern_in_source(self):
        for idx, mline in enumerate(self.sf.mlines, start=1):
            if idx in self.sf.pp_lines:
                continue
            if re.search(r'\bextern\b(?!\s*"C")', mline):
                self.add("C-STD-5.3.4", idx, mline.index("extern") + 1,
                         "extern declaration inside a .c file",
                         also=["MISRA-8.19"])

    # ===================================================== global scan ====
    def collect_globals(self):
        body = self.sf.body
        spans = []
        prev = 0
        for fn in self.sf.functions:
            spans.append((prev, fn.sig_offset))
            prev = fn.body_end + 1
        spans.append((prev, len(body)))
        for start, end in spans:
            for stmt, off, depth in iter_statements(body, start, end):
                if depth != 0:
                    continue
                self._record_global(stmt, off)

    def _record_global(self, stmt, off):
        line = self.sf.line_of(off)
        norm = re.sub(r"\s+", " ", stmt).strip()
        if not norm or norm.startswith("#"):
            return
        is_typedef = norm.startswith("typedef")
        first = norm.split(" ")[0]
        if first in ("return", "else", "case", "default", "break",
                     "continue", "goto"):
            return
        is_func = bool(re.search(r"[A-Za-z_]\w*\s*\([^;]*\)\s*$", norm))
        looks_declared = re.match(
            r"^[A-Za-z_][\w ]*\s+[*\s]*[A-Za-z_]", norm)
        if not is_typedef and not is_func and not looks_declared:
            return      # the tail of a braced definition, not a decl
        m = re.search(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*(=|$)", norm)
        if not m:
            return
        name = m.group(1)
        if name in C_KEYWORDS:
            return
        if is_typedef:
            names = re.findall(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", norm)
            name = names[0] if names else name
        self.globals[name] = {
            "line": line,
            "decl": norm[:200],
            "is_static": bool(re.match(r"^(static)\b", norm)),
            "is_extern": bool(re.match(r"^(extern)\b", norm)),
            "is_volatile": "volatile" in norm,
            "is_const": bool(re.match(r"^(const)\b", norm)),
            "is_typedef": is_typedef,
            "is_func": is_func,
        }

    # ======================================================= functions ====
    def check_functions(self):
        prefix_re = re.compile(self.cfg["component_prefix_pattern"])
        for fn in self.sf.functions:
            body_text = self.sf.body[fn.body_start:fn.body_end + 1]

            # -- function heading comment --------------------------------
            if self.cfg["require_function_header"]:
                self._check_function_header(fn)

            # -- parameter list ------------------------------------------
            params_src = self.sf.body[
                self.sf.body.find("(", fn.sig_offset):fn.body_start]
            if re.match(r"^\(\s*\)", params_src or ""):
                self.add("C-STD-5.5.4", fn.sig_line, 1,
                         "'%s()' declared with an empty parameter list"
                         % fn.name,
                         also=["MISRA-8.2"])
            for ptype, pname in fn.params:
                if pname and not ptype.strip():
                    self.add("C-STD-5.5.3", fn.sig_line, 1,
                             "parameter '%s' of '%s' has no type"
                             % (pname, fn.name), also=["MISRA-8.2"],
                             confidence="Medium")

            if fn.ret_type.strip() == "":
                self.add("C-STD-5.5.1", fn.sig_line, 1,
                         "'%s' has no explicit return type" % fn.name,
                         confidence="Medium")

            if fn.is_inline and not fn.is_static:
                self.add("MISRA-8.10", fn.sig_line, 1,
                         "inline function '%s' is not static" % fn.name)

            # -- naming ---------------------------------------------------
            if not fn.is_static and not prefix_re.match(fn.name):
                if fn.name not in ("main",) and \
                        not fn.name.startswith("_"):
                    self.add("C-STD-5.4.1", fn.sig_line, 1,
                             "exported function '%s' has no component prefix"
                             % fn.name)
            if RESERVED_PREFIX.match(fn.name):
                self.add("MISRA-5.10", fn.sig_line, 1,
                         "'%s' is a reserved identifier" % fn.name)

            # -- recursion -------------------------------------------------
            if re.search(r"(?<![\w.>])" + re.escape(fn.name) + r"\s*\(",
                         body_text):
                near = self.sf.comments_near(fn.sig_line, before=12).lower()
                if "recursion" not in near and "recursive" not in near:
                    ln = self.sf.line_of(
                        fn.body_start +
                        re.search(r"(?<![\w.>])" + re.escape(fn.name) +
                                  r"\s*\(", body_text).start())
                    self.add("C-STD-5.5.6", ln, 1,
                             "'%s' calls itself" % fn.name,
                             also=["MISRA-17.2"])

            # -- returns ---------------------------------------------------
            self._check_returns(fn, body_text)

            # -- unused parameters ----------------------------------------
            for _ptype, pname in fn.params:
                if not pname:
                    continue
                uses = len(re.findall(r"(?<![\w.])" + re.escape(pname) +
                                      r"(?!\w)", body_text))
                if uses == 0:
                    self.add("MISRA-2.7", fn.sig_line, 1,
                             "parameter '%s' of '%s' is never used"
                             % (pname, fn.name), confidence="Medium")

            # -- size and complexity ---------------------------------------
            length = fn.end_line - fn.open_line
            complexity = 1 + len(re.findall(
                r"\b(if|for|while|case|goto)\b|&&|\|\|", body_text))
            if length > self.cfg["max_function_lines"]:
                self.add("C-STD-4.7.1", fn.sig_line, 1,
                         "'%s' is %d lines (limit %d)"
                         % (fn.name, length, self.cfg["max_function_lines"]))
            elif complexity > self.cfg["max_cyclomatic_complexity"]:
                self.add("C-STD-4.7.1", fn.sig_line, 1,
                         "'%s' has cyclomatic complexity %d (limit %d)"
                         % (fn.name, complexity,
                            self.cfg["max_cyclomatic_complexity"]))

            # -- pointer parameter validation ------------------------------
            self._check_pointer_params(fn, body_text)

            # -- interrupt context -----------------------------------------
            self._check_isr(fn, body_text)

    def _check_function_header(self, fn):
        line = fn.sig_line - 1
        while line >= 1 and not self.sf.raw(line).strip():
            line -= 1
        if line < 1:
            self.add("C-STD-5.1.3", fn.sig_line, 1,
                     "'%s' has no function heading comment" % fn.name)
            return
        blob = " ".join(self.sf.comment_on_line.get(line, []))
        if not blob.strip():
            self.add("C-STD-5.1.3", fn.sig_line, 1,
                     "'%s' has no function heading comment" % fn.name)
            return
        for _s, e, text in self.sf.comments:
            if e == line:
                blob = text
                break
        low = blob.lower()
        if not any(tag.lower() in low
                   for tag in self.cfg["function_header_tags"]):
            self.add("C-STD-5.1.3", fn.sig_line, 1,
                     "the comment above '%s' is not a function heading "
                     "block (none of %s present)"
                     % (fn.name, ", ".join(self.cfg["function_header_tags"])),
                     confidence="Medium")

    def _check_returns(self, fn, body_text):
        if fn.is_void:
            return
        bare = re.search(r"\breturn\s*;", body_text)
        if bare:
            ln = self.sf.line_of(fn.body_start + bare.start())
            self.add("C-STD-5.5.5", ln, 1,
                     "'return;' with no value in non-void function '%s'"
                     % fn.name,
                     also=["MISRA-17.4"])
            return
        inner = body_text
        if inner.startswith("{"):
            inner = inner[1:]
        if inner.endswith("}"):
            inner = inner[:-1]
        if self._always_returns(inner):
            return
        if not re.search(r"\breturn\b", body_text):
            self.add("C-STD-5.5.5", fn.sig_line, 1,
                     "non-void function '%s' contains no return statement"
                     % fn.name,
                     also=["MISRA-17.4"])
        else:
            self.add("C-STD-5.5.5", fn.end_line, 1,
                     "'%s' has a path that reaches the closing brace without "
                     "returning a value" % fn.name, confidence="Medium",
                     also=["MISRA-17.4"])

    # ---------------------------------------------------------------------
    # Terminal-flow analysis.
    #
    # "Can control reach the end of this block?"  The missing-return check
    # needs a real answer rather than the last statement in the text: an
    # if/else in which both arms return, a switch whose every clause
    # returns, and a non-terminating loop all leave the function without
    # ever falling through to the closing brace.
    # ---------------------------------------------------------------------

    @staticmethod
    def _take_unit(text, join_else=True):
        """Split off the first complete statement or construct.

        Returns (unit, remainder).  With `join_else` the else arm stays
        attached to its if, which is what the top-level split wants; a
        branch body has to stop before the else that follows it.  An arm
        written without braces ends at its semicolon, so the else has to
        be looked for at both kinds of boundary.
        """
        depth = 0
        paren = 0
        i = 0
        n = len(text)
        while i < n:
            c = text[i]
            if c in "([":
                paren += 1
            elif c in ")]":
                paren = max(0, paren - 1)
            elif c == "{":
                depth += 1
            elif c == "}":
                depth = max(0, depth - 1)
            at_boundary = ((c == ";" and paren == 0 and depth == 0) or
                           (c == "}" and depth == 0))
            if at_boundary:
                j = i + 1
                while j < n and text[j].isspace():
                    j += 1
                tail = text[j:j + 6]
                if join_else and re.match(r"else(?!\w)", tail):
                    i += 1
                    continue
                if re.match(r"while(?!\w)", tail) and \
                        text[:i].lstrip().startswith("do"):
                    i += 1
                    continue
                return text[:i + 1], text[i + 1:]
            i += 1
        return text, ""

    def _split_units(self, text):
        units = []
        rest = text
        while rest.strip():
            unit, rest = self._take_unit(rest)
            if not unit.strip():
                break
            units.append(unit.strip())
        return units

    def _always_returns(self, text):
        """True when control cannot run off the end of `text`."""
        return any(self._unit_always_returns(u)
                   for u in self._split_units(text))

    def _unit_always_returns(self, unit):
        u = unit.strip()
        u = re.sub(r"^[A-Za-z_]\w*\s*:\s*", "", u)        # drop any label
        if not u:
            return False
        if re.match(r"^return\b", u) or re.match(r"^goto\b", u):
            return True
        if u.startswith("{"):
            close = matching_close(u, 0, "{", "}")
            return self._always_returns(u[1:close] if close > 0 else u[1:])
        if re.match(r"^if\s*\(", u):
            return self._if_always_returns(u)
        if re.match(r"^switch\s*\(", u):
            return self._switch_always_returns(u)
        if re.match(r"^(for|while)\s*\(", u):
            return self._loop_always_returns(u)
        call = re.match(r"^\(?\s*(?:void\s*\)\s*)?([A-Za-z_]\w*)\s*\(", u)
        if call and any(fnmatch.fnmatch(call.group(1), pattern)
                        for pattern in self.cfg["noreturn_patterns"]):
            return True
        return False

    def _if_always_returns(self, unit):
        open_paren = unit.find("(")
        close = matching_close(unit, open_paren)
        if close < 0:
            return False
        then_unit, remainder = self._take_unit(unit[close + 1:],
                                               join_else=False)
        if not then_unit.strip():
            return False
        remainder = remainder.lstrip()
        if not re.match(r"else(?!\w)", remainder):
            return False            # no else, so the if can be skipped
        else_unit, _rest = self._take_unit(remainder[4:].lstrip())
        return (self._unit_always_returns(then_unit) and
                self._unit_always_returns(else_unit))

    @staticmethod
    def _has_own_break(text):
        """True if `text` contains a break belonging to the loop or switch
        it is the body of.

        A break inside a nested loop or switch belongs to that one, so
        those constructs are skipped whole; a break inside an if, or any
        other block, still leaves the enclosing construct.
        """
        pattern = re.compile(r"(?<![\w.])(break|for|while|do|switch)\b")
        i = 0
        n = len(text)
        while i < n:
            m = pattern.search(text, i)
            if m is None:
                return False
            if m.group(1) == "break":
                return True
            j = m.end()
            if m.group(1) != "do":
                while j < n and text[j].isspace():
                    j += 1
                if j < n and text[j] == "(":
                    close = matching_close(text, j)
                    if close < 0:
                        return False
                    j = close + 1
            while j < n and text[j].isspace():
                j += 1
            if j < n and text[j] == "{":
                close = matching_close(text, j, "{", "}")
                i = (close + 1) if close > 0 else n
            else:
                semi = text.find(";", j)
                i = (semi + 1) if semi >= 0 else n
        return False

    def _switch_always_returns(self, unit):
        brace = unit.find("{")
        if brace < 0:
            return False
        close = matching_close(unit, brace, "{", "}")
        inner = unit[brace + 1:close if close > 0 else len(unit)]
        if not re.search(r"(?<![\w.])default\s*:", inner):
            return False        # an unhandled value falls straight through
        return not self._has_own_break(inner)

    def _loop_always_returns(self, unit):
        open_paren = unit.find("(")
        close = matching_close(unit, open_paren)
        if close < 0:
            return False
        keyword = unit[:open_paren].strip()
        condition = unit[open_paren + 1:close].strip()
        if keyword == "for":
            parts = split_top_level(condition, ";")
            infinite = len(parts) == 3 and not parts[1].strip()
        else:
            infinite = condition.replace(" ", "") in ("1", "1U", "true",
                                                      "TRUE", "(1)")
        if not infinite:
            return False
        brace = unit.find("{", close)
        if brace < 0:
            return True                     # while (1);
        end = matching_close(unit, brace, "{", "}")
        body = unit[brace + 1:end if end > 0 else len(unit)]
        return not self._has_own_break(body)


    def _check_pointer_params(self, fn, body_text):
        for ptype, pname in fn.params:
            if not pname or "*" not in ptype:
                continue
            if "const" in ptype and "char" in ptype:
                pass
            deref = re.search(
                r"(?<![\w.])" + re.escape(pname) +
                r"\s*(->|\[)|\*\s*" + re.escape(pname) + r"(?!\w)",
                body_text)
            if not deref:
                continue
            name_re = re.escape(pname)
            guard = re.search(
                r"(NULL\s*[=!]=\s*" + name_re + r"|" +
                name_re + r"\s*[=!]=\s*(NULL|0[uU]?)\b|"
                r"assert\s*\(\s*" + name_re + r"|"
                r"(?:if|while)\s*\(\s*!?\s*" + name_re + r"\s*[)&|]|"
                r"[&|]{2}\s*!?\s*" + name_re + r"\s*[)&|])",
                body_text[:deref.start() + 200])
            if guard:
                continue
            ln = self.sf.line_of(fn.body_start + deref.start())
            self.add("CWE-476", ln, 1,
                     "pointer parameter '%s' is dereferenced without a NULL "
                     "check" % pname,
                     also=["C-STD-4.6.1"],
                     confidence="High" if not fn.is_static else "Medium")

    def _check_isr(self, fn, body_text):
        if not any(fnmatch.fnmatch(fn.name, pat)
                   for pat in self.cfg["isr_name_patterns"]):
            return
        for m in re.finditer(r"(?<![\w.>])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?"
                             r"\s*(?:=[^=]|\+\+|--)", body_text):
            name = m.group(1)
            info = self.globals.get(name)
            if info and not info["is_volatile"] and not info["is_func"] \
                    and not info["is_typedef"]:
                ln = self.sf.line_of(fn.body_start + m.start())
                self.add("CWE-362", ln, 1,
                         "'%s' is written from interrupt context '%s' but is "
                         "not declared volatile" % (name, fn.name),
                         confidence="Medium")

    # ==================================================== declarations ====
    def check_declarations(self):
        known_types = set(FIXED_WIDTH_TYPES)
        known_types |= {t["name"] for t in self.sf.typedefs if t["name"]}
        if self.index is not None:
            known_types |= self.index.typedef_names
        for fn in self.sf.functions:
            self._walk_function_decls(fn, known_types)

    def _looks_like_type(self, word, quals, known_types):
        if word in known_types or word in BASIC_TYPE_WORDS:
            return True
        if quals.strip():
            return True
        if word.endswith("_t") or re.match(r"^t[A-Z]", word) or \
                re.match(r"^[A-Z][A-Za-z0-9]*_t[A-Z_]", word):
            return True
        return False

    def _walk_function_decls(self, fn, known_types):
        body = self.sf.body
        scopes = [{}]
        locals_map = {}
        params = {p[1]: p[0] for p in fn.params if p[1]}
        scopes[0].update(params)
        locals_map.update(params)
        last_depth = 0
        for stmt, off, depth in iter_statements(body, fn.body_start + 1,
                                                fn.body_end):
            while depth > last_depth:
                scopes.append({})
                last_depth += 1
            while depth < last_depth and len(scopes) > 1:
                scopes.pop()
                last_depth -= 1
            line = self.sf.line_of(off)
            norm = re.sub(r"\s+", " ", stmt).strip()
            first = norm.split(" ")[0].split("(")[0]
            if first in CONTROL_KEYWORDS or first in (
                    "break", "continue", "typedef", "static_assert"):
                if not (first in ("for",) and "(" in norm):
                    continue
            m = re.match(
                r"^(?P<quals>(?:(?:static|const|volatile|register|auto|"
                r"unsigned|signed|struct|union|enum)\s+)*)"
                r"(?P<type>[A-Za-z_]\w*)\s+(?P<rest>[*\s]*[A-Za-z_].*)$",
                norm)
            if not m:
                continue
            quals, tname, rest = (m.group("quals"), m.group("type"),
                                  m.group("rest"))
            if tname in C_KEYWORDS and tname not in TYPE_KEYWORDS:
                continue
            if not self._looks_like_type(tname, quals, known_types):
                continue
            if re.match(r"^\w+\s*\(", rest) and "*" not in rest.split("(")[0]:
                continue                       # function call or prototype
            declarators = split_top_level(rest)
            if len(declarators) > 1:
                self.add("C-STD-5.2.3", line, 1,
                         "%d variables declared on one line"
                         % len(declarators))
            for decl in declarators:
                self._check_declarator(fn, line, off, quals, tname,
                                       decl.strip(), scopes, locals_map)
        self.locals_by_func[fn.name] = locals_map

    def _check_declarator(self, fn, line, off, quals, tname, decl, scopes,
                          locals_map):
        if not decl:
            return
        mname = re.match(r"^([*\s]*)([A-Za-z_]\w*)", decl)
        if not mname:
            return
        stars = mname.group(1).count("*")
        name = mname.group(2)
        if name in C_KEYWORDS:
            return
        declarator = decl.split("=", 1)[0]
        array = re.search(r"\[([^\]]*)\]", declarator)
        has_init = "=" in decl

        locals_map[name] = ("%s %s" % (quals, tname)).strip() + "*" * stars

        # shadowing -----------------------------------------------------
        for outer in scopes[:-1]:
            if name in outer:
                self.add("C-STD-5.7.1", line, 1,
                         "'%s' shadows an identifier in an enclosing scope"
                         % name,
                         also=["MISRA-5.3"])
                break
        else:
            if name in self.globals and not self.globals[name]["is_func"]:
                self.add("C-STD-5.7.1", line, 1,
                         "'%s' shadows a file-scope object declared on line "
                         "%d" % (name, self.globals[name]["line"]),
                         also=["MISRA-5.3"])
        scopes[-1][name] = tname

        # initialisation -------------------------------------------------
        if not has_init and "extern" not in quals and "static" not in quals:
            kind = "array" if array else "variable"
            self.add("C-STD-5.7.2", line, 1,
                     "local %s '%s' is not initialised at its declaration"
                     % (kind, name),
                     also=["CWE-457", "MISRA-9.1"])

        # variable-length array ------------------------------------------
        if array:
            size = array.group(1).strip()
            if size and not re.match(r"^[\s\d+\-*/()xXA-F_]*$", size):
                idents = [i for i in IDENT_RE.findall(size)
                          if i not in ("sizeof",)]
                if any(not i.isupper() for i in idents):
                    self.add("MISRA-18.8", line, 1,
                             "array '%s' is sized by the run-time value '%s'"
                             % (name, size),
                             also=["CWE-121"])

        # pointer naming --------------------------------------------------
        if stars > 0 and not name.startswith(self.cfg["pointer_prefix"]):
            self.add("C-STD-5.6.6", line, 1,
                     "pointer '%s' does not use the '%s' prefix"
                     % (name, self.cfg["pointer_prefix"]))

        # string literal to non-const pointer -----------------------------
        if stars > 0 and "char" in tname and "const" not in quals and \
                has_init and '"' in self.sf.raw(line):
            self.add("C-STD-5.8.4", line, 1,
                     "'%s' points at a string literal but is not const"
                     % name,
                     also=["MISRA-7.4"])

        # fixed-width types ------------------------------------------------
        words = set(quals.split()) | {tname}
        if words & BASIC_TYPE_WORDS and not array:
            self.add("C-STD-5.6.3", line, 1,
                     "'%s' is declared '%s' rather than a fixed-width type"
                     % (name, (quals + tname).strip()),
                     confidence="Medium")

        # indirection depth -------------------------------------------------
        if stars > 2:
            self.add("MISRA-18.5", line, 1,
                     "'%s' has %d levels of pointer indirection"
                     % (name, stars))

        # units in the name --------------------------------------------------
        self._check_units(line, name)

        if "restrict" in decl or "restrict" in quals:
            self.add("MISRA-8.14", line, 1, "'restrict' used on '%s'" % name)

    def _check_units(self, line, name):
        for word in self.cfg["unit_bearing_words"]:
            if name.endswith(word):
                self.add("C-STD-4.3.3", line, 1,
                         "'%s' names an amount but states no units" % name,
                         confidence="Medium")
                return

    # =================================================== control flow ====
    def check_control_flow(self):
        body = self.sf.body
        for m in re.finditer(r"(?<![\w.])(if|for|while|switch)\s*\(", body):
            kw = m.group(1)
            open_paren = m.end() - 1
            close = matching_close(body, open_paren)
            if close < 0:
                continue
            nxt = next_code_char(body, close + 1)
            if nxt < 0:
                continue
            line = self.sf.line_of(m.start())
            if body[nxt] not in "{;":
                self.add("C-STD-4.2.2", line, self.sf.col_of(m.start()),
                         "the body of this '%s' is not enclosed in braces"
                         % kw,
                         also=["MISRA-15.6"])
            cond = body[open_paren + 1:close]
            if kw in ("if", "while"):
                self._check_condition(line, cond, kw)
            if kw == "for":
                self._check_for(line, cond)
            if kw == "while":
                self._check_infinite(line, cond, "while")
            if kw == "switch":
                self._check_switch(m.start(), close)

        for m in re.finditer(r"(?<![\w.])else(?!\w)", body):
            nxt = next_code_char(body, m.end())
            if nxt < 0:
                continue
            if body[nxt] != "{" and not re.match(r"if\b", body[nxt:nxt + 3]):
                self.add("C-STD-4.2.2", self.sf.line_of(m.start()),
                         self.sf.col_of(m.start()),
                         "the body of this 'else' is not enclosed in braces",
                         also=["MISRA-15.6"])

        for m in re.finditer(r"(?<![\w.])for\s*\(\s*;\s*;\s*\)", body):
            self._check_infinite(self.sf.line_of(m.start()), "", "for")

        for m in re.finditer(r"(?<![\w.])goto(?!\w)", body):
            self.add("MISRA-15.1", self.sf.line_of(m.start()),
                     self.sf.col_of(m.start()), "goto used")

        self._check_if_else_chains()

    def _check_condition(self, line, cond, kw):
        text = cond.strip()
        if not text:
            return
        # boolean compared with a truth constant
        m = re.search(r"[=!]=\s*(true|false|TRUE|FALSE|eTrue|eFalse)\b", text)
        if m:
            self.add("C-STD-5.6.5", line, 1,
                     "boolean compared with '%s'" % m.group(0).strip())
        # assignment used as a condition
        if re.search(r"(?<![=!<>+\-*/%&|^])=(?!=)", text):
            self.add("C-STD-5.12.4", line, 1,
                     "assignment inside the controlling expression",
                     also=["MISRA-13.4"])
        # nested ternary
        if text.count("?") > 1:
            self.add("C-STD-5.12.4b", line, 1, "nested conditional operators")
        # negated strcmp
        if re.search(r"!\s*(strcmp|strncmp|memcmp|wcscmp)\s*\(", text):
            self.add("C-STD-5.12.4a", line, 1,
                     "negated string comparison reads as 'not equal'")
        # side effects in the right operand of && / ||
        for part in re.split(r"&&|\|\|", text)[1:]:
            if re.search(r"\+\+|--|(?<![=!<>])=(?!=)", part):
                self.add("MISRA-13.5", line, 1,
                         "side effect in the right-hand operand of a "
                         "short-circuit operator")
                break
        # implicit tests
        for atom in re.split(r"&&|\|\|", text):
            atom = atom.strip()
            if not atom:
                continue
            neg = atom.startswith("!")
            core = atom.lstrip("!").strip()
            if re.fullmatch(r"[A-Za-z_]\w*", core):
                declared = self._declared_type(core)
                if "*" in declared or re.match(r"^p{1,2}[A-Z_]", core) or \
                        core.lower().endswith("ptr"):
                    self.add("MISRA-11.11", line, 1,
                             "pointer '%s' tested without an explicit NULL "
                             "comparison" % core,
                             also=["CWE-476"])
                elif not self._is_boolean_name(core):
                    self.add("MISRA-14.4", line, 1,
                             "'%s' is used as a condition without a "
                             "comparison" % core, confidence="Medium")
            elif re.fullmatch(r"[A-Za-z_]\w*\s*\([^()]*\)", core) and neg:
                continue

    def _is_boolean_name(self, name):
        low = name.lower()
        if low.startswith(("is", "has", "b", "flag", "enable", "en_")):
            return True
        if low.endswith(("flag", "valid", "ready", "done", "ok", "enabled",
                         "busy", "found", "active")):
            return True
        decl = ""
        for scope in (self.locals_by_func, ):
            for _fname, table in scope.items():
                if name in table:
                    decl = str(table[name])
                    break
        if not decl and name in self.globals:
            decl = self.globals[name]["decl"]
        return "bool" in decl.lower()

    def _check_for(self, line, cond):
        parts = split_top_level(cond, ";")
        if len(parts) >= 1 and re.search(r"\b(float|double)\b", parts[0]):
            self.add("MISRA-14.1", line, 1,
                     "loop counter has floating-point type")
        if len(parts) == 3 and not parts[1].strip():
            self._check_infinite(line, "", "for")

    def _check_infinite(self, line, cond, kw):
        text = cond.strip().replace(" ", "")
        if kw == "while" and text not in ("1", "true", "TRUE", "1U", "(1)"):
            return
        near = self.sf.comments_near(line, before=3).lower()
        if any(k in near for k in self.cfg["loop_annotation_keywords"]):
            return
        self.add("C-STD-5.10.4", line, 1,
                 "unbounded '%s' loop with no demonstrable termination"
                 % kw, confidence="Medium")

    def _check_switch(self, kw_offset, cond_close):
        body = self.sf.body
        open_brace = next_code_char(body, cond_close + 1)
        if open_brace < 0 or body[open_brace] != "{":
            return
        close_brace = matching_close(body, open_brace, "{", "}")
        if close_brace < 0:
            return
        region = body[open_brace + 1:close_brace]
        line = self.sf.line_of(kw_offset)
        labels = []
        depth = 0
        for m in re.finditer(r"[{}]|(?<![\w.])(case|default)\b", region):
            if m.group(0) == "{":
                depth += 1
            elif m.group(0) == "}":
                depth -= 1
            elif depth == 0:
                labels.append((m.group(1), m.start()))
        if not labels:
            return
        if not any(k == "default" for k, _ in labels):
            self.add("C-STD-5.10.1", line, 1,
                     "switch statement has no default label",
                     also=["MISRA-16.4"])
        clause_count = 0
        prev = None
        for kind, pos in labels:
            if prev is not None:
                seg = region[prev[1]:pos]
                seg_body = seg.split(":", 1)[1] if ":" in seg else ""
                if seg_body.strip() and not re.search(
                        r"\b(break|return|continue|goto|exit)\b", seg_body):
                    ln = self.sf.line_of(open_brace + 1 + pos)
                    near = self.sf.comments_near(ln, before=2).lower()
                    if "fall" not in near:
                        self.add("C-STD-5.10.3", ln, 1,
                                 "fall-through into this label is not "
                                 "commented",
                                 also=["MISRA-16.3"])
                if seg_body.strip():
                    clause_count += 1
            prev = (kind, pos)
        if prev is not None:
            tail = region[prev[1]:]
            if tail.strip():
                clause_count += 1
            if not re.search(r"\b(break|return|goto)\b", tail):
                ln = self.sf.line_of(open_brace + 1 + prev[1])
                self.add("C-STD-5.10.2", ln, 1,
                         "the last switch clause does not end with break",
                         also=["MISRA-16.3"])
        if clause_count < 2:
            self.add("MISRA-16.6", line, 1,
                     "switch statement has fewer than two clauses")

    def _check_if_else_chains(self):
        body = self.sf.body
        consumed = set()
        for m in re.finditer(r"(?<![\w.])if\s*\(", body):
            if m.start() in consumed:
                continue
            pos = m.start()
            elif_count = 0
            has_else = False
            while True:
                open_paren = body.find("(", pos)
                close = matching_close(body, open_paren)
                if close < 0:
                    break
                nxt = next_code_char(body, close + 1)
                if nxt < 0:
                    break
                if body[nxt] == "{":
                    end = matching_close(body, nxt, "{", "}")
                    if end < 0:
                        break
                else:
                    end = body.find(";", nxt)
                    if end < 0:
                        break
                after = next_code_char(body, end + 1)
                if after < 0 or not re.match(r"else(?!\w)", body[after:]):
                    break
                after_else = next_code_char(body, after + 4)
                if after_else >= 0 and \
                        re.match(r"if\s*\(", body[after_else:]):
                    elif_count += 1
                    consumed.add(after_else)
                    pos = after_else
                    continue
                has_else = True
                break
            if elif_count >= 1 and not has_else:
                self.add("C-STD-5.10.5", self.sf.line_of(m.start()), 1,
                         "if / else if chain with %d branches has no final "
                         "else" % (elif_count + 1),
                         also=["MISRA-15.7"])

    # ===================================================== expressions ====
    def check_expressions(self):
        body = self.sf.body
        for stmt, off, _depth in iter_statements(body, 0, len(body)):
            line = self.sf.line_of(off)
            self._check_increments(line, stmt)
            self._check_shift(line, stmt)
            self._check_casts(line, off, stmt)
            self._check_division(line, off, stmt)
        self._check_octal_and_suffixes()
        self._check_sizeof_array_param()

    def _check_increments(self, line, stmt):
        counts = {}
        for m in re.finditer(r"(?:\+\+|--)\s*([A-Za-z_]\w*)|"
                             r"([A-Za-z_]\w*)\s*(?:\+\+|--)", stmt):
            name = m.group(1) or m.group(2)
            counts[name] = counts.get(name, 0) + 1
        for name, count in counts.items():
            if count > 1:
                self.add("C-STD-5.12.6", line, 1,
                         "'%s' is modified %d times in one statement"
                         % (name, count),
                         also=["MISRA-13.3"])

    def _check_shift(self, line, stmt):
        for m in re.finditer(r"<<\s*(\d+)", stmt):
            if int(m.group(1)) >= 32:
                self.add("MISRA-12.2", line, 1,
                         "shift count %s is at or beyond the width of a "
                         "32-bit type" % m.group(1), confidence="Medium")

    def _check_casts(self, line, off, stmt):
        known = set(FIXED_WIDTH_TYPES) | BASIC_TYPE_WORDS
        known |= {t["name"] for t in self.sf.typedefs if t["name"]}
        if self.index is not None:
            known |= self.index.typedef_names
        for m in re.finditer(
                r"\((?P<q>(?:const\s+|volatile\s+|struct\s+|union\s+|enum\s+|"
                r"unsigned\s+|signed\s+)*)(?P<t>[A-Za-z_]\w*)"
                r"(?P<stars>\s*\*+)?\s*\)\s*(?P<operand>[&*]?[A-Za-z_(]\w*)",
                stmt):
            tname = m.group("t")
            if tname not in known and not tname.endswith("_t") and \
                    not re.match(r"^t[A-Z]", tname):
                continue
            stars = (m.group("stars") or "").count("*")
            operand = m.group("operand")
            if tname == "void" and stars == 0:
                continue          # (void) discard of a return value
            follow = stmt[m.end("operand"):m.end("operand") + 2]
            subscripted = follow.startswith(("[", ".", "->"))
            comment = self.sf.comments_near(line, before=1)
            if not comment.strip():
                self.add("C-STD-5.9.1", line, 1,
                         "cast to '%s%s' has no justifying comment"
                         % (tname, "*" * stars),
                         also=["CWE-704"])
            is_pointer_operand = (operand.startswith("&") or
                                  bool(re.match(r"^p{1,2}[A-Z_]",
                                                operand)))
            if stars == 0 and not subscripted and is_pointer_operand:
                if tname not in ("void",):
                    self.add("MISRA-11.4", line, 1,
                             "pointer converted to arithmetic type '%s'"
                             % tname, confidence="Medium")
            if stars == 0 and tname in ("uint8_t", "int8_t", "uint16_t",
                                        "int16_t", "char"):
                if "&" not in stmt:
                    self.add("C-STD-5.9.2", line, 1,
                             "narrowing cast to '%s' with no explicit mask"
                             % tname, confidence="Medium")
            if stars > 0 and "const" not in m.group("q"):
                decl = self._declared_type(operand.lstrip("&*"))
                if decl and "const" in decl:
                    self.add("MISRA-11.8", line, 1,
                             "cast of const object '%s' to a non-const "
                             "pointer" % operand)
                elif decl and stars > 0:
                    base = re.sub(r"[*\s]|const|volatile|static", "", decl)
                    if base and base != tname and "*" in decl:
                        self.add("MISRA-11.3", line, 1,
                                 "'%s' (declared %s) cast to '%s *'"
                                 % (operand, decl.strip(), tname),
                                 confidence="Medium")
        for m in re.finditer(r"\(\s*[A-Za-z_]\w*\s*\**\s*\)\s*[A-Za-z_]\w*"
                             r"\s*=(?!=)", stmt):
            self.add("C-STD-5.8.2", line, 1,
                     "assignment to a cast object")
        for m in re.finditer(r"&\s*\(\s*[A-Za-z_]\w*\s*\)\s*[A-Za-z_]", stmt):
            before = stmt[:m.start()].rstrip()[-1:]
            if before and (before.isalnum() or before in "_)]"):
                continue          # bitwise AND, not address-of
            self.add("C-STD-5.8.2", line, 1,
                     "address taken of a cast object")
        for m in re.finditer(r"(?<![\w.>])([A-Za-z_]\w*)\s*=\s*0\s*;", stmt):
            decl = self._declared_type(m.group(1))
            if decl and "*" in decl:
                self.add("MISRA-11.9", line, 1,
                         "integer 0 assigned to pointer '%s'" % m.group(1))

    def _declared_type(self, name):
        for table in self.locals_by_func.values():
            if name in table:
                return str(table[name])
        if name in self.globals:
            return self.globals[name]["decl"]
        return ""

    def _check_division(self, line, off, stmt):
        for m in re.finditer(r"[/%]\s*(?!=)([A-Za-z_]\w*)", stmt):
            name = m.group(1)
            if name.isupper() or name in ("sizeof",):
                continue
            fn = self.sf.func_at_line.get(line)
            if fn is None:
                continue
            region = self.sf.body[fn.body_start:
                                  self.sf.offset_of(line) + len(stmt)]
            guard = re.search(
                r"(0\s*[=!<>]=?\s*" + re.escape(name) + r"|" +
                re.escape(name) + r"\s*[=!<>]=?\s*0)", region)
            if guard:
                continue
            self.add("CWE-369", line, 1,
                     "'%s' is used as a divisor with no zero check" % name,
                     confidence="Medium")
            break

    def _check_octal_and_suffixes(self):
        for idx, mline in enumerate(self.sf.mlines, start=1):
            if not mline.strip() or idx in self.enum_lines:
                continue
            for m in NUMBER_RE.finditer(mline):
                lit = m.group(1)
                if re.match(r"^0[0-7]+$", lit):
                    self.add("MISRA-7.1", idx, m.start(1) + 1,
                             "octal constant '%s'" % lit)
                if re.search(r"l(?![lL])", lit) and lit[-1] in "lL" and \
                        "l" in lit:
                    self.add("MISRA-7.3", idx, m.start(1) + 1,
                             "lowercase 'l' suffix on '%s'" % lit)
                if re.match(r"^0[xX][0-9a-fA-F]+$", lit) and \
                        not lit.lower().endswith("u"):
                    context = mline[max(0, m.start(1) - 20):m.start(1)]
                    if not re.search(r"(case|enum|#define|\[)\s*$", context):
                        self.add("MISRA-7.2", idx, m.start(1) + 1,
                                 "hexadecimal constant '%s' has no U suffix"
                                 % lit, confidence="Medium")

    def _check_sizeof_array_param(self):
        for fn in self.sf.functions:
            array_params = set()
            raw_params = self.sf.body[
                self.sf.body.find("(", fn.sig_offset):fn.body_start]
            for part in split_top_level(raw_params.strip("()")):
                m = re.search(r"([A-Za-z_]\w*)\s*\[[^\]]*\]\s*$", part)
                if m:
                    array_params.add(m.group(1))
            if not array_params:
                continue
            body_text = self.sf.body[fn.body_start:fn.body_end]
            for m in re.finditer(r"sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)",
                                 body_text):
                if m.group(1) in array_params:
                    self.add("MISRA-12.5",
                             self.sf.line_of(fn.body_start + m.start()), 1,
                             "sizeof applied to array parameter '%s'"
                             % m.group(1))

    # ======================================================== libraries ====
    def check_library_use(self):
        body = self.sf.body
        project_funcs = self.index.function_returns if self.index else {}
        for m in re.finditer(r"(?<![\w.>])([A-Za-z_]\w*)\s*\(", body):
            name = m.group(1)
            line = self.sf.line_of(m.start())
            if name in CONTROL_KEYWORDS or name in C_KEYWORDS:
                continue
            if name in PROHIBITED_FUNCTIONS:
                reason, alt, cwe = PROHIBITED_FUNCTIONS[name]
                self.add("C-STD-6.1.5", line, self.sf.col_of(m.start()),
                         "%s() is prohibited (%s); use %s"
                         % (name, reason, alt),
                         also=[cwe])
            if name in MISRA_LIBRARY_FUNCTIONS:
                rid = MISRA_LIBRARY_FUNCTIONS[name]
                self.add(rid, line, self.sf.col_of(m.start()),
                         "%s() used" % name)
            if name in DANGEROUS_FUNCTIONS:
                comment = self.sf.comments_near(line, before=1)
                if not comment.strip():
                    self.add("C-STD-6.1.6", line, self.sf.col_of(m.start()),
                             "%s() used without a justifying comment (%s)"
                             % (name, DANGEROUS_FUNCTIONS[name]),
                             confidence="Medium")
            if name in FORMAT_FUNCTIONS:
                self._check_format(line, m.end() - 1, name)
            if name in ("memcpy", "memmove", "memset"):
                self._check_copy_bounds(line, m.end() - 1, name)
            if name == "memcmp":
                self._check_memcmp(line, m.end() - 1)
            if name == "free":
                self._check_free(line, m.end() - 1)
        self._check_ignored_returns(project_funcs)
        self._check_crypto()

    def _args_of(self, open_paren):
        close = matching_close(self.sf.body, open_paren)
        if close < 0:
            return []
        return split_top_level(self.sf.body[open_paren + 1:close])

    def _check_format(self, line, open_paren, name):
        pos = FORMAT_FUNCTIONS.get(name)
        if pos is None:
            return
        args = self._args_of(open_paren)
        if len(args) <= pos:
            return
        fmt = args[pos].strip()
        if fmt.startswith('"') or fmt.startswith("L\"") or \
                re.match(r"^[A-Z_][A-Z0-9_]*$", fmt):
            return
        self.add("C-STD-5.5.2", line, 1,
                 "format argument of %s() is '%s', not a literal"
                 % (name, fmt[:40]),
                 also=["CWE-134"])

    def _check_copy_bounds(self, line, open_paren, name):
        args = self._args_of(open_paren)
        if len(args) < 3:
            return
        length = args[2].strip()
        dest = args[0].strip()
        low = length.lower()
        bounded = ("sizeof" in low or "min(" in low or "_min(" in low or
                   re.match(r"^[A-Z_][A-Z0-9_]*$", length) or
                   re.match(r"^\d+[uU]?$", length))
        if not bounded and re.fullmatch(r"[A-Za-z_]\w*", length):
            # a range check on the length earlier in the same function
            # bounds the copy just as well as a sizeof does
            fn = self.sf.func_at_line.get(line)
            if fn is not None:
                before = self.sf.body[fn.body_start:open_paren]
                bounded = bool(re.search(
                    r"(?<![\w.])" + re.escape(length) + r"\s*(<=|<|>=|>)",
                    before))
        if not bounded:
            self.add("CWE-787", line, 1,
                     "%s() length '%s' is not bounded by the size of '%s'"
                     % (name, length[:40], dest[:30]),
                     also=["C-STD-5.7.3"],
                     confidence="Medium")
        if re.search(r"[+*]", length) and "sizeof" not in low:
            self.add("CWE-190", line, 1,
                     "%s() length '%s' is computed without an overflow check"
                     % (name, length[:40]), confidence="Medium")

    def _check_memcmp(self, line, open_paren):
        args = self._args_of(open_paren)
        if len(args) < 2:
            return
        for arg in args[:2]:
            decl = self._declared_type(arg.strip().lstrip("&*"))
            if "char" in decl and "*" in decl:
                self.add("MISRA-21.14", line, 1,
                         "memcmp() used on '%s', a character pointer"
                         % arg.strip()[:30], confidence="Medium")
                return
            if decl and "*" in decl and "void" not in decl and \
                    "uint8" not in decl and "char" not in decl:
                self.add("MISRA-21.16", line, 1,
                         "memcmp() used on pointer values", confidence="Low")
                return

    def _check_free(self, line, open_paren):
        args = self._args_of(open_paren)
        if not args:
            return
        target = args[0].strip()
        if not re.fullmatch(r"[A-Za-z_][\w.>\-\[\]]*", target):
            return
        close = matching_close(self.sf.body, open_paren)
        window = self.sf.body[close:close + 260]
        if re.search(re.escape(target) + r"\s*=\s*NULL", window):
            return
        self.add("CWE-416", line, 1,
                 "'%s' is not set to NULL after free()" % target,
                 also=["C-STD-6.1.2"])

    def _check_ignored_returns(self, project_funcs):
        patterns = self.cfg["error_returning_patterns"]
        body = self.sf.body
        for fn in self.sf.functions:
            for stmt, off, _d in iter_statements(body, fn.body_start + 1,
                                                 fn.body_end):
                norm = re.sub(r"\s+", " ", stmt).strip()
                m = re.match(r"^([A-Za-z_]\w*)\s*\(", norm)
                if not m:
                    continue
                if not norm.endswith(")"):
                    continue
                name = m.group(1)
                if name in CONTROL_KEYWORDS or name in C_KEYWORDS:
                    continue
                if matching_close(norm, norm.index("(")) != len(norm) - 1:
                    continue
                if any(fnmatch.fnmatch(name, p)
                       for p in self.cfg["void_returning_patterns"]):
                    continue
                interesting = any(fnmatch.fnmatch(name, p)
                                  for p in patterns)
                if not interesting and self.cfg["check_project_return_values"]:
                    ret = project_funcs.get(name)
                    interesting = bool(ret) and ret != "void"
                if not interesting:
                    continue
                self.add("C-STD-5.11.2", self.sf.line_of(off), 1,
                         "the value returned by %s() is discarded without a "
                         "(void) cast" % name,
                         also=["MISRA-17.7"],
                         confidence="Medium")

    def _check_crypto(self):
        pattern = re.compile(
            r"\b(aes|des|rsa|md5|sha1|sha256)\b|"
            r"\b(hmac|encrypt|decrypt|cipher|crypto)",
            re.IGNORECASE)
        for idx, mline in enumerate(self.sf.mlines, start=1):
            if idx in self.sf.pp_lines:
                continue
            if not pattern.search(mline):
                continue
            near = self.sf.comments_near(idx, before=3)
            if "CRYPTO" in near:
                continue
            self.add("C-STD-5.12.3", idx, 1,
                     "cryptographic operation with no CRYPTO approval "
                     "reference nearby", confidence="Low")
            return

    # ==================================================== magic numbers ====
    def check_magic_numbers(self):
        allow = set(self.cfg["magic_number_allow"])
        minimum = self.cfg["magic_number_min_uses"]
        seen = {}
        for idx, mline in enumerate(self.sf.mlines, start=1):
            if idx in self.sf.pp_lines or idx in self.enum_lines:
                continue
            if self.sf.depth(idx) == 0 and not self.sf.func_at_line.get(idx):
                continue
            for m in NUMBER_RE.finditer(mline):
                lit = m.group(1)
                if lit in allow or lit.rstrip("uUlL") in allow:
                    continue
                before = mline[:m.start(1)]
                if re.search(r"(case|\benum\b)\s*$", before):
                    continue
                if re.search(r"\[\s*$", before) and lit.isdigit():
                    pass
                seen.setdefault(lit, []).append((idx, m.start(1) + 1))
        for lit, places in seen.items():
            if len(places) < minimum:
                continue
            for idx, col in places[:6]:
                self.add("C-STD-4.4.1", idx, col,
                         "literal %s appears %d times in this file"
                         % (lit, len(places)), confidence="Medium")

    # ================================================= types and naming ====
    def check_types_and_naming(self):
        tpref = self.cfg["type_prefix"]
        prefix_re = re.compile(self.cfg["component_prefix_pattern"])
        for td in self.sf.typedefs:
            name = td["name"]
            if not name:
                continue
            line = td["line"]
            if td["is_pointer"]:
                self.add("C-STD-5.6.6b", line, 1,
                         "'%s' is a typedef of a pointer type" % name)
            stripped = name
            m = prefix_re.match(name)
            if m:
                stripped = name[m.end():]
            suffix_ok = (self.cfg["accept_type_suffix_t"] and
                         name.endswith("_t"))
            prefix_ok = (stripped.startswith(tpref) and
                         (len(stripped) < 2 or stripped[1].isupper()))
            if not prefix_ok and not suffix_ok:
                self.add("C-STD-5.6.6a", line, 1,
                         "type '%s' does not use the '%s' prefix"
                         % (name, tpref))
            if RESERVED_PREFIX.match(name):
                self.add("MISRA-5.10", line, 1,
                         "'%s' is a reserved identifier" % name)
            if td["kind"] == "struct" and re.search(r"\[\s*\]\s*;\s*}",
                                                    td["decl"]):
                self.add("MISRA-18.7", line, 1,
                         "'%s' declares a flexible array member" % name)

        for name, info in self.globals.items():
            if info["is_typedef"] or info["is_func"] or info["is_static"]:
                continue
            if info["is_extern"] and self.sf.is_header:
                pass
            if not prefix_re.match(name) and not name.startswith("_"):
                self.add("C-STD-5.4.1", info["line"], 1,
                         "global object '%s' has no component prefix" % name,
                         confidence="Medium")

        for name, info in self.globals.items():
            decl = info["decl"]
            if info["is_typedef"] or info["is_func"]:
                continue
            if "char" in decl and "*" in decl and "const" not in decl and                     '"' in self.sf.raw(info["line"]):
                self.add("C-STD-5.8.4", info["line"], 1,
                         "'%s' points at a string literal but is not const"
                         % name, also=["MISRA-7.4"])

        self._check_union_reads()

    def _check_union_reads(self):
        unions = {td["name"]: set(td["members"])
                  for td in self.sf.typedefs
                  if td["kind"] == "union" and td["name"] and td["members"]}
        if not unions:
            return
        for fn in self.sf.functions:
            table = self.locals_by_func.get(fn.name, {})
            targets = {v: unions[re.sub(r"[^\w]", "", str(t).split()[-1])]
                       for v, t in table.items()
                       if re.sub(r"[^\w]", "", str(t).split()[-1]) in unions}
            if not targets:
                continue
            body_text = self.sf.body[fn.body_start:fn.body_end]
            last_written = {}
            for m in re.finditer(
                    r"(?<![\w.])([A-Za-z_]\w*)\s*(?:\.|->)\s*([A-Za-z_]\w*)"
                    r"(\s*=(?!=))?", body_text):
                var, member, assign = m.group(1), m.group(2), m.group(3)
                if var not in targets or member not in targets[var]:
                    continue
                if assign:
                    last_written[var] = member
                elif var in last_written and last_written[var] != member:
                    self.add("CWE-843",
                             self.sf.line_of(fn.body_start + m.start()), 1,
                             "'%s.%s' is read but '%s' was the member last "
                             "written" % (var, member, last_written[var]),
                             also=["MISRA-19.3"],
                             confidence="Medium")
