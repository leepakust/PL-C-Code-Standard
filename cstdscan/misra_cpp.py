"""Source-only MISRA C++:2023 checks. No type or macro expansion claims."""

import re

from .checks import FileChecker
from .misra_cpp_rules import PREFIX


# Match whole preprocessing numbers so suffixes, exponents and separators
# cannot be mistaken for separate integer constants.
NUMBERS = re.compile(r"(?<![\w.])(?:\d|\.\d)(?:[\w.']|(?<=[eEpP])[+-])*")
SCALAR = r"(?:(?:const|volatile|signed|unsigned)\s+)*(?:bool|char|wchar_t|char16_t|char32_t|short|int|long|float|double)(?:\s+(?:int|long|double|const|volatile))*"
LIBRARY_NAMES = {
    "18.5.2": "abort exit _Exit quick_exit terminate",
    "21.2.1": "atof atoi atol atoll",
    "21.2.3": "system",
    "24.5.2": "memcpy memmove memcmp",
    "30.0.1": "remove rename tmpfile tmpnam fclose fflush fopen freopen setbuf setvbuf "
                "fprintf fscanf printf scanf snprintf sprintf sscanf vfprintf vfscanf "
                "vprintf vscanf vsnprintf vsprintf vsscanf fgetc fgets fputc fputs getc "
                "getchar putc putchar puts ungetc fread fwrite fgetpos fseek fsetpos "
                "ftell rewind clearerr feof ferror perror fwprintf fwscanf swprintf "
                "swscanf vfwprintf vfwscanf vswprintf vswscanf vwprintf vwscanf "
                "wprintf wscanf fgetwc fgetws fputwc fputws fwide getwc getwchar "
                "putwc putwchar ungetwc",
}


class CppFileChecker(FileChecker):
    def emit(self, number, offset, detail, confidence="High"):
        self.add(PREFIX + number, self.sf.line_of(offset),
                 self.sf.col_of(offset), detail, confidence=confidence)

    def matches(self, number, pattern, text=None, confidence="High"):
        for match in re.finditer(pattern, self.sf.body if text is None else text):
            self.emit(number, match.start(), match.group().strip(), confidence)

    def run(self):
        self.check_comments_cpp()
        self.check_tokens_cpp()
        self.check_preprocessor_cpp()
        self.check_library_cpp()
        return self.violations

    def check_comments_cpp(self):
        for first, _last, comment in self.sf.comments:
            if comment.startswith("/*"):
                for match in re.finditer(r"/\*", comment[2:]):
                    line = first + comment[:match.start() + 2].count("\n")
                    self.add(PREFIX + "5.7.1", line, detail="nested /* in block comment")
            elif comment.startswith("//"):
                for i, part in enumerate(comment.split("\n")):
                    if part.endswith("\\") and first + i < self.sf.line_count:
                        self.add(PREFIX + "5.7.3", first + i,
                                 detail="backslash immediately before comment newline")

    def check_tokens_cpp(self):
        # Keep macro replacement bodies, but exclude header names.
        text = self.token_text()
        for match in NUMBERS.finditer(text):
            token = match.group().replace("'", "")
            if re.fullmatch(r"0[0-7]+[uUlL]*", token):
                self.emit("5.13.3", match.start(), match.group())
            number = re.fullmatch(
                r"(?:0[xX][0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?(?:[pP][+-]?\d+)?"
                r"|0[bB][01]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)"
                r"([uUlLfF]*)", token)
            if number and number.group(1).startswith("l"):
                self.emit("5.13.5", match.start(), match.group())
        for number, pattern in (
            ("7.11.1", r"\bNULL\b"),
            ("9.6.1", r"\bgoto\b"),
            ("10.4.1", r"\basm\b"),
            ("12.3.1", r"\bunion\b"),
            ("16.5.1", r"\boperator\s*(?:&&|\|\||and\b|or\b)"),
            ("21.2.4", r"\boffsetof\b"),
            ("21.10.1", r"\bva_(?:list|arg|start|end|copy)\b"),
            ("21.10.2", r"\b(?:jmp_buf|setjmp|longjmp)\b"),
            ("26.3.1", r"\bstd\s*::\s*vector\s*<\s*bool\s*(?=[,>])"),
        ):
            self.matches(number, pattern, text)
        if self.sf.is_header:
            self.matches("10.3.1", r"\bnamespace\s*\{")
        # Restrict old-style casts to known scalar spellings. A compiler is
        # needed to distinguish arbitrary type aliases from expressions.
        for match in re.finditer(r"\(\s*(?:" + SCALAR + r"|void\s*\*)\s*[*&]*\s*\)"
                                 r"\s*(?=[\w(&*!~+\-])", self.sf.body):
            before = self.sf.body[:match.start()].rstrip()
            word = re.search(r"(\w+)$", before)
            if word and word.group(1) not in ("return", "co_return", "throw"):
                continue  # Function signatures and sizeof/alignof(type).
            if before.endswith((")", "]")):
                continue
            self.emit("8.2.2", match.start(), match.group().strip(), "Medium")
        for match in re.finditer(r"\b" + SCALAR + r"\s*\(\s*(?=[^\s)])", self.sf.body):
            before = self.sf.body[:match.start()].rstrip()
            after = self.sf.body[match.end():]
            boundary = max(before.rfind(";"), before.rfind("{"), before.rfind("}"))
            declaration = before[boundary + 1:]
            if (before.endswith("<") or re.search(r"\b(?:using|typedef)\b", declaration)
                    or after.startswith(("*", "&"))):
                continue  # Function types/aliases and pointer declarators.
            self.emit("8.2.2", match.start(), match.group().strip(), "Medium")
        for match in re.finditer(r"\breinterpret_cast\s*<([^<>]+)>\s*\(", self.sf.body):
            target = re.sub(r"\b(?:const|volatile)\b", "", match.group(1))
            target = " ".join(target.split())
            if re.fullmatch(r"(?:void|char|unsigned char|std\s*::\s*byte)\s*\*", target):
                continue
            # Integral exceptions depend on target width; do not guess it.
            if "*" in target or "&" in target:
                self.emit("8.2.5", match.start(), "reinterpret_cast target: " + target,
                          "Medium")
        self.matches("21.6.1", r"\bnew\b(?!\s*\()|\bdelete\b(?!\s*[;,)])",
                     confidence="Medium")

    def token_text(self):
        return "\n".join(" " * len(line) if re.match(r"\s*#\s*include\b", line)
                         else line for line in self.sf.mlines)

    def check_preprocessor_cpp(self):
        defined = set()
        stack = []
        lines = self.sf.mlines
        i = 0
        while i < len(lines):
            first = i
            logical = lines[i]
            while logical.endswith("\\") and i + 1 < len(lines):
                i += 1
                logical = logical[:-1] + " " + lines[i]
            i += 1
            match = re.match(r"\s*#\s*(\w+)\b(.*)", logical, re.S)
            if not match:
                continue
            directive, rest = match.groups()
            line = first + 1
            if directive == "define":
                name = re.match(r"\s*([A-Za-z_]\w*)(.*)", rest, re.S)
                if name:
                    defined.add(name.group(1))
                    if name.group(2).startswith("("):
                        self.add(PREFIX + "19.0.2", line, detail=name.group(1))
                    if "#" in name.group(2):
                        self.add(PREFIX + "19.3.1", line, detail=name.group(1))
            elif directive == "undef":
                name = rest.strip().split()[0] if rest.strip() else ""
                if name and name not in defined:
                    self.add(PREFIX + "19.0.4", line, detail=name)
            elif directive in ("if", "ifdef", "ifndef"):
                stack.append(line)
            elif directive in ("else", "elif", "endif"):
                if not stack:
                    self.add(PREFIX + "19.1.2", line, detail="unmatched #" + directive)
                elif directive == "endif":
                    stack.pop()
            elif directive == "pragma":
                self.add(PREFIX + "19.6.1", line, detail="#pragma")
            elif directive == "include":
                # Quotes are retained by the masker but their contents are
                # blanked. Read only the actual include operand from source.
                include = re.match(r'\s*#\s*include\s*[<"](csetjmp|setjmp\.h)[>"]',
                                   self.sf.raw(line))
                if include:
                    self.add(PREFIX + "21.10.2", line, detail=include.group(1))
        for line in stack:
            self.add(PREFIX + "19.1.2", line, detail="conditional group has no #endif")
        self.matches("19.6.1", r"\b_Pragma\s*\(", self.token_text())

    def check_library_cpp(self):
        text = self.token_text()
        # Exclude member calls and other explicit namespaces. Unqualified
        # names cannot be bound without includes/types: report Medium.
        for number, names in LIBRARY_NAMES.items():
            self.library_uses(number, names.split(), text)
        self.library_uses("21.6.1", "malloc calloc realloc aligned_alloc free".split(), text)
        self.matches("21.6.1", r"\bstd\s*::\s*make_(?:unique|shared)\s*<", text)
        self.library_uses("25.5.1", ["setlocale"], text, calls_only=True)
        self.matches("25.5.1", r"\bstd\s*::\s*locale\s*::\s*global\s*\(", text)

    def library_uses(self, number, names, text, calls_only=False):
        pattern = r"\b(?:(std)\s*::\s*)?(" + "|".join(map(re.escape, names)) + r")\b"
        for match in re.finditer(pattern, text):
            before = text[:match.start()].rstrip()
            if before.endswith((".", "->", "::")):
                # Leading :: is global qualification, but another namespace
                # is not the standard library.
                if not (before.endswith("::") and
                        not re.search(r"[\w:>]\s*::$", before)):
                    continue
            after = text[match.end():].lstrip()
            if calls_only and not after.startswith("("):
                continue
            if not calls_only and not (after.startswith("(") or
                                       before.endswith("&") or
                                       re.search(r"(?:=|return)\s*$", before)):
                continue
            # std::remove also has permitted algorithm overloads.
            if number == "30.0.1" and match.group(2) == "remove":
                from .checks import matching_close
                from .source import split_top_level
                opening = match.end() + len(text[match.end():]) - len(after)
                close = matching_close(text, opening) if after.startswith("(") else -1
                if close >= 0 and len(split_top_level(text[opening + 1:close])) != 1:
                    continue
            self.emit(number, match.start(), "library facility: " + match.group(2),
                      "Medium")
