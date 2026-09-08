"""Scanner configuration: defaults, file loading and rule filtering."""

import fnmatch
import os


DEFAULTS = {
    # ---- what to scan -----------------------------------------------------
    "extensions": [".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"],
    # Third-party trees are usually scanned only for information; listing a
    # glob here keeps the file out of the report entirely.
    "exclude": [
        "*/build/*", "*/Build/*", "*/Debug/*", "*/Release/*",
        "*/.git/*", "*/node_modules/*", "*/CMakeFiles/*", "*/Output/*",
    ],
    # File-name patterns (matched against the bare name, not the path,
    # case-insensitive) - catches stray copies and backups wherever they
    # turn up in the tree, e.g. "Adc1Task - Copy.c" or "old_main.c.bak".
    "exclude_names": [
        "*- copy*", "*-copy*", "* copy*", "*(copy)*", "*copy of *",
        "*.bak", "*.orig", "*.old", "*~",
    ],
    "exclude_generated": True,          # skip files marked auto-generated

    # ---- layout -----------------------------------------------------------
    "max_line_length": 120,
    "max_function_lines": 120,
    "max_cyclomatic_complexity": 15,
    "check_trailing_whitespace": True,
    "check_brace_on_own_line": True,

    # ---- documentation ----------------------------------------------------
    "require_file_header": True,
    "file_header_scan_lines": 25,
    "file_header_required_tags": ["DESCRIPTION"],
    "require_function_header": True,
    "function_header_tags": ["FUNCTION", "DESCRIPTION", "@brief", "\\brief"],

    # ---- naming -----------------------------------------------------------
    "component_prefix_pattern": r"^[A-Z][A-Za-z0-9]{1,7}_",
    "pointer_prefix": "p",
    "type_prefix": "t",
    "unit_bearing_words": ["Size", "Length", "Timeout", "Period", "Delay",
                           "Interval", "Duration"],
    # A type name may end "_t" instead of carrying the "t" prefix.
    "accept_type_suffix_t": True,
    "unit_suffixes": ["Bytes", "Byte", "Bits", "Bit", "Words", "Word",
                      "Milliseconds", "Microseconds", "Seconds", "Ms", "Us",
                      "Ticks", "Samples", "Entries", "Elements", "Chars",
                      "Percent", "Hz", "InBytes", "InMs"],

    # ---- behaviour --------------------------------------------------------
    "magic_number_min_uses": 2,
    "magic_number_allow": ["0", "1", "0x00", "0x01", "0U", "1U", "0u", "1u",
                           "0.0", "1.0", "2", "0xFF", "0xFFU"],
    "loop_annotation_keywords": ["non-terminating", "never returns",
                                 "task loop", "runs forever", "endless",
                                 "infinite loop", "rtos task"],
    "isr_name_patterns": ["*IRQHandler", "*_Handler", "*Callback",
                          "*_ISR", "*_isr"],
    # Functions whose return value signals an error and must be used.
    "error_returning_patterns": [
        "malloc", "calloc", "realloc", "fopen", "fclose", "fread", "fwrite",
        "fseek", "fflush", "remove", "rename", "snprintf", "vsnprintf",
        "memcmp", "strcmp", "strncmp", "strtol", "strtoul", "strtod",
        "HAL_*", "osMutex*", "osSemaphore*", "osMessageQueue*", "osThread*",
        "osTimer*", "osEventFlags*", "x*Queue*", "x*Semaphore*", "xTask*",
        "pthread_*",
    ],
    # Known void-returning functions that would otherwise match one of the
    # patterns above (a HAL_* glob catches both kinds).
    "void_returning_patterns": [
        "HAL_NVIC_*", "HAL_Delay", "HAL_IncTick", "HAL_GPIO_WritePin",
        "HAL_GPIO_TogglePin", "HAL_SuspendTick", "HAL_ResumeTick",
        "__HAL_*", "HAL_*_MspInit", "HAL_*_MspDeInit", "HAL_*Callback",
        "osDelayUntil",
    ],
    "check_project_return_values": True,
    # Calls that never come back, so control cannot fall off the
    # end of the function after one of them.
    "noreturn_patterns": [
        "abort", "exit", "_Exit", "quick_exit", "longjmp",
        "panic", "Panic", "Error_Handler", "NVIC_SystemReset",
        "__builtin_unreachable", "assert_failed", "HardFault*",
    ],

    # ---- rule selection ---------------------------------------------------
    "enabled_standards": ["C-STD", "MISRA C:2025", "CWE"],
    "min_severity": "Low",              # Critical | High | Medium | Low
    "disabled_rules": [],
    "enabled_rules": [],                # if non-empty, only these run
    "per_path_disabled_rules": {},      # glob -> [rule ids]
}


class Config(dict):
    def __init__(self, data=None):
        super().__init__(DEFAULTS)
        if data:
            for key, value in data.items():
                if key not in DEFAULTS:
                    raise KeyError("unknown configuration key: %r" % key)
                self[key] = value

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path):
        if path is None:
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        data = None
        if path.lower().endswith((".yaml", ".yml")):
            try:
                import yaml
            except ImportError:                       # pragma: no cover
                raise SystemExit(
                    "PyYAML is required to read %s (pip install pyyaml)"
                    % path)
            data = yaml.safe_load(text)
        else:
            import json
            data = json.loads(text)
        return cls(data or {})

    # ------------------------------------------------------------------
    def rule_enabled(self, rule, rel_path=""):
        if self["enabled_rules"]:
            if rule.id not in self["enabled_rules"]:
                return False
        if rule.id in self["disabled_rules"]:
            return False
        if rule.standard not in self["enabled_standards"]:
            return False
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        if order.get(rule.severity, 3) > order.get(self["min_severity"], 3):
            return False
        posix = rel_path.replace(os.sep, "/")
        for pattern, ids in (self["per_path_disabled_rules"] or {}).items():
            if fnmatch.fnmatch(posix, pattern) and rule.id in ids:
                return False
        return True

    def path_excluded(self, rel_path):
        posix = "/" + rel_path.replace(os.sep, "/")
        for pattern in self["exclude"]:
            if fnmatch.fnmatch(posix, pattern) or \
               fnmatch.fnmatch(posix.lstrip("/"), pattern):
                return True
        return False

    def name_excluded(self, file_name):
        """True if `file_name` (the bare name, no directory) matches
        one of the `exclude_names` patterns. Matching is
        case-insensitive, so "*- Copy*" also catches "*- copy*".
        """
        low = file_name.lower()
        for pattern in self["exclude_names"]:
            if fnmatch.fnmatch(low, pattern.lower()):
                return True
        return False
