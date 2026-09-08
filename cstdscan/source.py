"""Lexical model of one C/C++ translation unit.

The scanner is a lexical analyser, not a compiler: it masks comments and
string literals, tracks brace depth, and recovers the shape of the file
(functions, parameters, declarations, macros).  That is enough for the large
majority of coding standard rules and it needs no build configuration, no
include paths and no toolchain.
"""

import bisect
import os
import re


C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "bool",
    "_Atomic", "_Generic", "_Noreturn", "_Static_assert", "_Thread_local",
}

CONTROL_KEYWORDS = {"if", "for", "while", "switch", "do", "else", "return",
                    "sizeof", "case", "default", "goto", "catch"}

STD_HEADERS = {
    "assert.h", "complex.h", "ctype.h", "errno.h", "fenv.h", "float.h",
    "inttypes.h", "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h",
    "signal.h", "stdalign.h", "stdarg.h", "stdatomic.h", "stdbool.h",
    "stddef.h", "stdint.h", "stdio.h", "stdlib.h", "stdnoreturn.h",
    "string.h", "tgmath.h", "threads.h", "time.h", "uchar.h", "wchar.h",
    "wctype.h", "windows.h", "unistd.h",
}

FIXED_WIDTH_TYPES = {
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "bool", "float", "double", "void", "char",
}

BASIC_TYPE_WORDS = {"int", "short", "long", "unsigned", "signed"}

TYPE_KEYWORDS = BASIC_TYPE_WORDS | {
    "char", "float", "double", "void", "_Bool", "bool", "struct",
    "union", "enum", "const", "volatile", "static", "register",
}


_RAW_STRING_OPEN = re.compile(r'(?:u8|u|U|L)?R"([^\s()\\]{0,16})\(')
_PP_NUMBER = re.compile(r"(?:\d|\.\d)(?:[\w.']|(?<=[eEpP])[+-])*")


def mask_source(text):
    """Blank out comments and the contents of literals.

    Returns (masked, comments) where `masked` has exactly the same length as
    `text` (so offsets stay valid) with comment bodies and literal contents
    replaced by spaces, and `comments` is a list of (start_line, end_line,
    text) tuples.
    """
    out = list(text)
    comments = []
    n = len(text)
    i = 0
    line = 1
    state = "code"
    start = 0
    start_line = 1
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if (i + 1) < n else ""
        if state == "code":
            raw = _RAW_STRING_OPEN.match(text, i) if ch in 'uULR' else None
            if raw and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                terminator = ")" + raw.group(1) + '"'
                end = text.find(terminator, raw.end())
                end = n if end < 0 else end + len(terminator)
                for j in range(i, end):
                    if text[j] != "\n":
                        out[j] = " "
                line += text[i:end].count("\n")
                i = end
                continue
            # Consume a preprocessing number as one token. Apostrophes in
            # C++14 digit separators must not open a character literal.
            if ch.isdigit() or (ch == "." and nxt.isdigit()):
                number = _PP_NUMBER.match(text, i)
                i = number.end()
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                start, start_line = i, line
                out[i] = " "
                out[i + 1] = " "
                i += 2
                continue
            if ch == "/" and nxt == "/":
                state = "line"
                start, start_line = i, line
                out[i] = " "
                out[i + 1] = " "
                i += 2
                continue
            if ch == '"':
                state = "string"
                i += 1
                continue
            if ch == "'":
                state = "char"
                i += 1
                continue
        elif state == "block":
            if ch == "*" and nxt == "/":
                out[i] = " "
                out[i + 1] = " "
                comments.append((start_line, line, text[start:i + 2]))
                state = "code"
                i += 2
                continue
            if ch != "\n":
                out[i] = " "
        elif state == "line":
            if ch == "\n":
                if i == 0 or text[i - 1] != "\\":
                    comments.append((start_line, line, text[start:i]))
                    state = "code"
            else:
                out[i] = " "
        elif state in ("string", "char"):
            if ch == "\\":
                if i + 1 < n and text[i + 1] != "\n":
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    continue
            elif (state == "string" and ch == '"') or \
                 (state == "char" and ch == "'"):
                state = "code"
                i += 1
                continue
            elif ch == "\n":
                state = "code"          # unterminated literal; recover
            else:
                out[i] = " "
        if ch == "\n":
            line += 1
        i += 1
    if state == "block":
        comments.append((start_line, line, text[start:]))
    elif state == "line":
        comments.append((start_line, line, text[start:]))
    return "".join(out), comments


def split_top_level(text, sep=","):
    """Split on `sep` at paren/bracket/brace depth zero."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


class Function:
    def __init__(self, name, ret_type, params, sig_offset, body_start,
                 body_end, sig_line, open_line, end_line, is_static,
                 is_inline):
        self.name = name
        self.ret_type = ret_type
        self.params = params            # list of (type, name) tuples
        self.sig_offset = sig_offset
        self.body_start = body_start    # offset of '{'
        self.body_end = body_end        # offset of matching '}'
        self.sig_line = sig_line
        self.open_line = open_line
        self.end_line = end_line
        self.is_static = is_static
        self.is_inline = is_inline

    @property
    def is_void(self):
        # The return type may carry storage classes and toolchain
        # qualifiers - "static void", "void __interrupt()",
        # "void __attribute__((weak))" - so look for the word rather
        # than trying to match the whole string.
        rt = self.ret_type
        if "*" in rt:
            return False
        words = set(re.findall(r"[A-Za-z_]\w*", rt))
        if not words - {"static", "inline", "extern", "const",
                        "volatile", "register", "__inline",
                        "__forceinline", "_Noreturn"}:
            return True     # no type at all; C-STD-5.5.1 reports that
        return "void" in words

    def __repr__(self):
        return "<Function %s L%d-%d>" % (self.name, self.sig_line,
                                         self.end_line)


class SourceFile:
    def __init__(self, path, rel_path, text):
        self.path = path
        self.rel = rel_path
        self.name = os.path.basename(path)
        self.ext = os.path.splitext(path)[1].lower()
        self.is_header = self.ext in (".h", ".hpp", ".hh", ".hxx")
        self.text = text
        self.lines = text.split("\n")
        self.masked, self.comments = mask_source(text)
        self.mlines = self.masked.split("\n")

        self._line_starts = [0]
        for m in re.finditer("\n", text):
            self._line_starts.append(m.end())

        # comment text indexed by the line it appears on
        self.comment_on_line = {}
        for s, e, ctext in self.comments:
            for ln in range(s, e + 1):
                self.comment_on_line.setdefault(ln, []).append(ctext)

        self.pp_lines = self._find_preprocessor_lines()
        self.body = self._blank_preprocessor()
        self.blines = self.body.split("\n")
        self.depth_at_line = self._compute_depths()
        self.functions = self._find_functions()
        self.func_at_line = {}
        for fn in self.functions:
            for ln in range(fn.sig_line, fn.end_line + 1):
                self.func_at_line[ln] = fn
        self.typedefs = self._find_typedefs()

    # ------------------------------------------------------------- helpers
    def line_of(self, offset):
        return bisect.bisect_right(self._line_starts, offset)

    def col_of(self, offset):
        return offset - self._line_starts[self.line_of(offset) - 1] + 1

    def offset_of(self, line, col=1):
        return self._line_starts[line - 1] + col - 1

    def raw(self, line):
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    def code(self, line):
        """The line with comments and literal contents blanked."""
        if 1 <= line <= len(self.mlines):
            return self.mlines[line - 1]
        return ""

    def comments_near(self, line, before=1):
        """Comment text on `line` or on the `before` lines above it."""
        out = []
        for ln in range(line - before, line + 1):
            out.extend(self.comment_on_line.get(ln, []))
        return " ".join(out)

    @property
    def line_count(self):
        return len(self.lines)

    # --------------------------------------------------------- preprocessor
    def _find_preprocessor_lines(self):
        pp = set()
        ln = 1
        cont = False
        for raw in self.mlines:
            stripped = raw.strip()
            if cont or stripped.startswith("#"):
                pp.add(ln)
                cont = raw.rstrip().endswith("\\")
            ln += 1
        return pp

    def _blank_preprocessor(self):
        out = []
        for idx, raw in enumerate(self.mlines, start=1):
            if idx in self.pp_lines:
                out.append(" " * len(raw))
            else:
                out.append(raw)
        return "\n".join(out)

    def _compute_depths(self):
        """Brace depth at the start of each line (1-based index)."""
        depths = [0] * (len(self.lines) + 2)
        depth = 0
        line = 1
        for ch in self.body:
            if ch == "\n":
                line += 1
                if line < len(depths):
                    depths[line] = depth
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
        return depths

    def depth(self, line):
        if 0 < line < len(self.depth_at_line):
            return self.depth_at_line[line]
        return 0

    # ------------------------------------------------------------ functions
    def _find_functions(self):
        funcs = []
        body = self.body
        n = len(body)
        depth = 0
        i = 0
        prev_boundary = 0
        pending = None
        while i < n:
            ch = body[i]
            if ch == "{":
                if depth == 0:
                    head = body[prev_boundary:i]
                    parsed = self._parse_head(head, prev_boundary)
                    if parsed is not None:
                        pending = (parsed, i)
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth <= 0:
                    depth = 0
                    if pending is not None:
                        (name, ret, params, sig_off, is_static,
                         is_inline) = pending[0]
                        open_off = pending[1]
                        funcs.append(Function(
                            name, ret, params, sig_off, open_off, i,
                            self.line_of(sig_off), self.line_of(open_off),
                            self.line_of(i), is_static, is_inline))
                        pending = None
                    prev_boundary = i + 1
            elif ch == ";" and depth == 0:
                prev_boundary = i + 1
                pending = None
            i += 1
        return funcs

    def _parse_head(self, head, base_offset):
        """Decide whether `head` is a function definition signature."""
        if not head.strip():
            return None
        close = head.rfind(")")
        if close < 0:
            return None
        after = head[close + 1:]
        if re.search(r"[^\s\w()*,]", after):
            return None
        # match the opening paren of the parameter list
        depth = 0
        open_paren = -1
        for j in range(close, -1, -1):
            if head[j] == ")":
                depth += 1
            elif head[j] == "(":
                depth -= 1
                if depth == 0:
                    open_paren = j
                    break
        if open_paren < 0:
            return None
        before = head[:open_paren]
        m = re.search(r"([A-Za-z_]\w*)\s*$", before)
        if m is None:
            return None
        name = m.group(1)
        if name in CONTROL_KEYWORDS or name in C_KEYWORDS:
            return None
        pre = before[:m.start(1)]
        if "=" in pre or "=" in after:
            return None
        if re.search(r"\breturn\b|\btypedef\b", pre):
            return None
        params_text = head[open_paren + 1:close]
        params = self._parse_params(params_text)
        pre_clean = re.sub(r"\s+", " ", pre).strip()
        if pre_clean == "":
            # No return type at all: either implicit int, or a macro that
            # expands to a definition.  Only treat it as a function when the
            # parameter list looks like a real, typed one.
            if not params_text.strip():
                return None
            typed = any(t.strip() for t, _ in params)
            if not typed and params_text.strip() != "void":
                return None
        if pre_clean.split(" ")[-1:] == ["else"]:
            return None
        is_static = bool(re.search(r"\bstatic\b", pre_clean))
        is_inline = bool(re.search(r"\binline\b", pre_clean))
        sig_off = base_offset + (len(head) - len(head.lstrip()))
        return (name, pre_clean, params, sig_off, is_static, is_inline)

    @staticmethod
    def _parse_params(text):
        """Return a list of (type, name) for a parameter list."""
        out = []
        text = text.strip()
        if text == "" or text == "void":
            return out
        for part in split_top_level(text):
            part = part.strip()
            if part in ("", "void", "..."):
                out.append((part, ""))
                continue
            fp = re.match(r"^(.*?\(\s*\*+\s*)([A-Za-z_]\w*)(\s*\).*)$", part)
            if fp:
                out.append((fp.group(1) + fp.group(3), fp.group(2)))
                continue
            cleaned = re.sub(r"\[[^\]]*\]", "", part).strip()
            if re.fullmatch(r"[A-Za-z_]\w*", cleaned) and                     cleaned not in C_KEYWORDS:
                out.append(("", cleaned))       # K&R: no type given
                continue
            m = re.match(r"^(.*?)([A-Za-z_]\w*)$", cleaned)
            if m and m.group(1).strip():
                out.append((m.group(1).strip(), m.group(2)))
            else:
                out.append((cleaned, ""))
        return out

    # ------------------------------------------------------------- typedefs
    def _find_typedefs(self):
        """Return a list of (name, kind, line, is_pointer, members)."""
        found = []
        for m in re.finditer(r"\btypedef\b", self.masked):
            start = m.start()
            j = start
            depth = 0
            end = -1
            while j < len(self.masked):
                c = self.masked[j]
                if c in "{[(":
                    depth += 1
                elif c in "}])":
                    depth -= 1
                elif c == ";" and depth <= 0:
                    end = j
                    break
                j += 1
            if end < 0:
                continue
            decl = self.masked[start:end]
            kind = "type"
            km = re.search(r"\btypedef\s+(struct|union|enum)\b", decl)
            if km:
                kind = km.group(1)
            names = re.findall(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$",
                               decl.strip())
            name = names[0] if names else ""
            body_text = decl[decl.find("{") + 1:decl.rfind("}")] \
                if "{" in decl and "}" in decl else ""
            members = re.findall(
                r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;", body_text)
            is_ptr = bool(re.search(r"\*\s*" + re.escape(name) + r"\s*$",
                                    decl.strip())) if name else False
            found.append({
                "name": name,
                "kind": kind,
                "line": self.line_of(start),
                "is_pointer": is_ptr,
                "members": members,
                "decl": re.sub(r"\s+", " ", decl).strip(),
            })
        return found


def read_source(path, rel_path):
    with open(path, "rb") as fh:
        data = fh.read()
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:                                       # pragma: no cover
        text = data.decode("latin-1", "replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return SourceFile(path, rel_path, text)
