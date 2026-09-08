"""Scan orchestration: parse every file once, then run the checks."""

import os
import traceback

from . import __version__
from .checks import FileChecker
from .config import Config
from .model import RULES
from .misra_cpp import CppFileChecker
from .corrections import add_correction
from .project import ProjectIndex, discover_files, project_checks
from .source import read_source


class ScanResult:
    def __init__(self):
        self.violations = []
        self.stats = {}
        self.errors = []            # (file, message) for files that failed


def scan(roots, config=None, progress=None):
    config = config or Config()
    config.language_for("")  # Validate before discovery, including empty scans.
    result = ScanResult()

    entries = discover_files(roots, config)
    files = []
    for full, rel, _root in entries:
        try:
            files.append(read_source(full, rel))
        except Exception as exc:                     # pragma: no cover
            result.errors.append((rel, "%s: %s" % (type(exc).__name__, exc)))
        if progress is not None:
            progress(rel, len(files), len(entries))

    index = ProjectIndex(files)

    file_globals = {}
    for sf in files:
        if config.language_for(sf.rel) == "c++":
            try:
                result.violations.extend(CppFileChecker(sf, config, index).run())
            except Exception as exc:
                result.errors.append((sf.rel, "C++ check failed: %s: %s\n%s"
                                      % (type(exc).__name__, exc,
                                         traceback.format_exc(limit=3))))
        try:
            checker = FileChecker(sf, config, index)
            result.violations.extend(checker.run())
            file_globals[sf.rel] = checker.globals
        except Exception as exc:                     # pragma: no cover
            result.errors.append(
                (sf.rel, "check failed: %s: %s\n%s"
                 % (type(exc).__name__, exc, traceback.format_exc(limit=3))))

    try:
        result.violations.extend(project_checks(index, config, file_globals))
    except Exception as exc:                         # pragma: no cover
        result.errors.append(("<project>", "%s: %s" % (type(exc).__name__,
                                                       exc)))

    source_by_path = {sf.rel: sf for sf in files}
    for violation in result.violations:
        add_correction(violation, source_by_path.get(violation.file))
    result.violations.sort(key=lambda v: v.sort_key())

    roots_text = ", ".join(os.path.abspath(r) for r in roots)
    result.stats = {
        "root": roots_text,
        "version": __version__,
        "file_count": len(files),
        "line_count": sum(sf.line_count for sf in files),
        "active_rules": sum(1 for r in RULES.values()
                            if config.rule_enabled(r)),
        "file_lines": {sf.rel: sf.line_count for sf in files},
        "file_languages": {sf.rel: config.language_for(sf.rel) for sf in files},
    }
    return result
