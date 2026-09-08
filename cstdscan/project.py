"""Cross-file index and the checks that need to see the whole project."""

import os
import re

from .model import RULES, Violation
from .source import C_KEYWORDS


class ProjectIndex:
    """Facts gathered from every parsed file, used by the per-file checks."""

    def __init__(self, files):
        self.files = files
        self.header_names = set()
        self.typedef_names = set()
        self.function_returns = {}
        self.definitions = {}        # external name -> [(file, line)]
        self.typedef_sites = {}      # typedef name -> [(file, line, decl)]
        self.header_declared = set()
        self.static_functions = set()

        for sf in files:
            if sf.is_header:
                self.header_names.add(sf.name.lower())
            for td in sf.typedefs:
                if td["name"]:
                    self.typedef_names.add(td["name"])
                    self.typedef_sites.setdefault(td["name"], []).append(
                        (sf.rel, td["line"], td["decl"]))
            for fn in sf.functions:
                if fn.is_static:
                    self.static_functions.add(fn.name)
                    continue
                self.function_returns.setdefault(fn.name, fn.ret_type)
                self.definitions.setdefault(fn.name, []).append(
                    (sf.rel, fn.sig_line))
            if sf.is_header:
                for m in re.finditer(
                        r"(?<![\w.])([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;",
                        sf.masked):
                    self.header_declared.add(m.group(1))

    # ------------------------------------------------------------------
    def reference_count(self, name, exclude_file):
        count = 0
        pattern = re.compile(r"(?<![\w.>])" + re.escape(name) + r"\s*\(")
        for sf in self.files:
            if sf.rel == exclude_file:
                continue
            count += len(pattern.findall(sf.masked))
        return count


def project_checks(index, config, file_globals):
    """Return violations that can only be found by comparing files.

    `file_globals` maps a file's relative path to the globals dictionary the
    per-file checker built for it.
    """
    out = []

    def add(rule_id, rel, line, code, detail, also=None, confidence="High"):
        rule = RULES.get(rule_id)
        if rule is None or not config.rule_enabled(rule, rel):
            return
        out.append(Violation(rule_id=rule_id, file=rel, line=line, column=1,
                             code=code.strip()[:400], detail=detail,
                             also=list(also or []), confidence=confidence))

    by_line = {}
    for sf in index.files:
        by_line[sf.rel] = sf

    def source_line(rel, line):
        sf = by_line.get(rel)
        return sf.raw(line) if sf else ""

    # ---- file names differing only by case ------------------------------
    seen_names = {}
    for sf in index.files:
        seen_names.setdefault(sf.name.lower(), []).append(sf)
    for _lower, group in seen_names.items():
        names = sorted({sf.name for sf in group})
        if len(names) > 1:
            for sf in group:
                add("C-STD-4.3.2", sf.rel, 1, sf.name,
                    "file names differing only by case: %s"
                    % ", ".join(names))

    # ---- duplicate external definitions ---------------------------------
    for name, sites in index.definitions.items():
        if len(sites) > 1:
            files = sorted({rel for rel, _ln in sites})
            if len(files) > 1:
                for rel, line in sites:
                    add("MISRA-8.6", rel, line, source_line(rel, line),
                        "'%s' is also defined in %s"
                        % (name, ", ".join(f for f in files if f != rel)))

    # ---- external identifiers not distinct in 31 characters -------------
    buckets = {}
    for name in list(index.definitions.keys()):
        buckets.setdefault(name[:31], set()).add(name)
    for prefix, names in buckets.items():
        if len(names) > 1 and any(len(n) > 31 for n in names):
            for name in sorted(names):
                rel, line = index.definitions[name][0]
                add("MISRA-5.1", rel, line, source_line(rel, line),
                    "'%s' is not distinct from %s within 31 characters"
                    % (name, ", ".join(sorted(names - {name}))))

    # ---- typedef names reused across files ------------------------------
    for name, sites in index.typedef_sites.items():
        files = sorted({rel for rel, _ln, _decl in sites})
        decls = {decl for _rel, _ln, decl in sites}
        if len(files) > 1 and len(decls) > 1:
            for rel, line, _decl in sites:
                add("MISRA-5.6", rel, line, source_line(rel, line),
                    "type '%s' is also defined in %s"
                    % (name, ", ".join(f for f in files if f != rel)))

    # ---- functions exported but used in only one file --------------------
    for sf in index.files:
        if sf.is_header:
            continue
        for fn in sf.functions:
            if fn.is_static or fn.name in index.header_declared:
                continue
            if fn.name in ("main",):
                continue
            if index.reference_count(fn.name, sf.rel) == 0:
                add("MISRA-8.7", sf.rel, fn.sig_line,
                    sf.raw(fn.sig_line),
                    "'%s' has external linkage but is referenced only in "
                    "this file" % fn.name, confidence="Medium")

    return out


def discover_files(roots, config):
    """Walk the scan roots and return the list of files to parse."""
    found = []
    exts = tuple(e.lower() for e in config["extensions"])
    for root in roots:
        root = os.path.abspath(root)
        if os.path.isfile(root):
            base = os.path.dirname(root)
            rel = os.path.basename(root)
            if rel.lower().endswith(exts) and not config.name_excluded(rel):
                found.append((root, rel, base))
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and
                           not config.name_excluded(d) and
                           not config.path_excluded(
                               os.path.relpath(os.path.join(dirpath, d),
                                               root))]
            for name in sorted(filenames):
                if not name.lower().endswith(exts):
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if config.name_excluded(name) or config.path_excluded(rel):
                    continue
                found.append((full, rel, root))
    return found
