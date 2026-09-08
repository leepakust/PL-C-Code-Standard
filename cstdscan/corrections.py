"""Reviewable correction guidance. This module never writes source files."""

import re

from .misra_cpp import NUMBERS


# These are teaching examples, not replacements for the user's source line.
# Include requirements and context-dependent decisions belong in the note.
EXAMPLES = {
    "MISRA-CPP-5.7.1": ("/* Explain the operation without a nested comment opener. */",
                         "Check whether the comment accidentally hides executable code."),
    "MISRA-CPP-5.7.3": ("// Explanation ends here.\nperform_operation();",
                         "Removing the splice can make previously commented code execute. Review the following line."),
    "MISRA-CPP-7.11.1": ("int *pointer = nullptr;",
                          "Use nullptr for pointer values; review macro definitions separately."),
    "MISRA-CPP-8.2.2": ("auto converted = static_cast<std::int32_t>(value);",
                         "Illustrates a numeric conversion. Include <cstdint>; verify range, type and conversion intent. Other casts may need a different approach."),
    "MISRA-CPP-8.2.5": ("auto bytes = reinterpret_cast<const std::byte *>(&object);",
                         "Include <cstddef>. This illustrates the object-representation exception only; it does not justify reinterpreting unrelated objects."),
    "MISRA-CPP-9.6.1": ("if (ready)\n{\n    perform_operation();\n}\nelse\n{\n    handle_failure();\n}",
                         "Restructure the actual jump paths and preserve resource cleanup and return behavior."),
    "MISRA-CPP-10.3.1": ("// Header: declarations in a named namespace\nnamespace app { void run(); }\n\n// Source file: private implementation details\nnamespace { constexpr int limit = 10; }",
                          "Split the example between the header and source file. Check linkage before moving entities."),
    "MISRA-CPP-10.4.1": ("// Encapsulate the platform-specific operation.\nvoid platform_operation();",
                          "There is no portable generic replacement for arbitrary assembly. Implement and review the platform interface separately."),
    "MISRA-CPP-12.3.1": ("#include <variant>\nusing Data = std::variant<int, float>;\nData data{42};\nif (const auto *value = std::get_if<int>(&data))\n{\n    use_value(*value);\n}",
                          "Adapt all reads and writes. std::variant changes layout and is unsuitable as a direct replacement for a hardware register or wire format."),
    "MISRA-CPP-16.5.1": ("if (left.is_ready() && right.is_ready())\n{\n    perform_operation();\n}",
                          "Have the predicates return bool so the built-in operator short-circuits. Check whether evaluating fewer operands changes required side effects."),
    "MISRA-CPP-18.5.2": ("int main()\n{\n    const int result = run_application();\n    return result;\n}",
                          "Propagate failures through normal shutdown; confirm the required safety response before removing immediate termination."),
    "MISRA-CPP-19.0.2": ("constexpr int twice(int value)\n{\n    return value * 2;\n}",
                          "Replace the macro with a typed function or template. Check argument evaluation count, numeric range and all call sites."),
    "MISRA-CPP-19.0.4": ("#define LOCAL_OPTION 1\n// Use LOCAL_OPTION in this file.\n#undef LOCAL_OPTION",
                          "For an externally provided macro, remove the #undef or change configuration at its owner. Do not add a dummy definition merely to silence the check."),
    "MISRA-CPP-19.1.2": ("#if defined(FEATURE_ENABLED)\n// Feature implementation.\n#else\n// Alternative implementation.\n#endif",
                          "Match the actual conditional groups in the same file; do not blindly insert directives because that can change compilation."),
    "MISRA-CPP-19.3.1": ("constexpr const char *label = \"status\";",
                          "For stringizing use explicit names where practical; for token pasting redesign with typed functions or templates. No universal replacement exists."),
    "MISRA-CPP-19.6.1": ("#ifndef APP_WIDGET_HPP\n#define APP_WIDGET_HPP\n// Header declarations.\n#endif",
                          "This replaces #pragma once only. Choose a unique, non-reserved guard. Other pragmas require individual review."),
    "MISRA-CPP-21.2.1": ("#include <charconv>\n#include <system_error>\nint value{};\nconst auto result = std::from_chars(first, last, value);\nif (result.ec != std::errc{} || result.ptr != last)\n{\n    handle_invalid_input();\n}\nelse\n{\n    use_value(value);\n}",
                          "first/last must delimit a valid character range. Choose the correct numeric type and base; whitespace/sign handling differs from atoi/atof."),
    "MISRA-CPP-21.2.3": ("// Call the required operation through a controlled API.\nperform_requested_operation();",
                          "Implement an explicit allowlisted operation instead of constructing a shell command. The replacement is platform and application dependent."),
    "MISRA-CPP-21.2.4": ("auto value = object.member;",
                          "Use typed member access when possible. Binary layout, serialization and hardware mapping require a separate design."),
    "MISRA-CPP-21.6.1": ("#include <array>\nstd::array<int, 16> values{};",
                          "Example of fixed storage. Select the actual capacity, check stack/storage limits and preserve object lifetime. Smart pointers can still allocate dynamically."),
    "MISRA-CPP-21.10.1": ("void log_value(const char *label, int value);",
                           "Use typed parameters or a variadic template; update callers and preserve formatting/error handling."),
    "MISRA-CPP-21.10.2": ("bool perform_step();\n\nvoid run()\n{\n    if (!perform_step())\n    {\n        handle_failure();\n        return;\n    }\n    continue_processing();\n}",
                           "Replace non-local jumps with explicit status propagation or an approved exception design, preserving cleanup."),
    "MISRA-CPP-24.5.2": ("destination = source;\nconst bool equal = (left == right);",
                         "Illustrates typed copy/comparison where those operations exist. For ranges use suitable algorithms and verify bounds and overlap."),
    "MISRA-CPP-25.5.1": ("#include <locale>\nconst auto normalized = std::tolower(character, std::locale::classic());",
                         "Pass a locale to the operation. Choose the locale required by the application instead of changing global state."),
    "MISRA-CPP-26.3.1": ("#include <array>\nstd::array<bool, 16> flags{};",
                         "For a fixed count use std::array or std::bitset. For a dynamic count consider a byte/wrapper vector and review allocation policy and changed reference semantics."),
    "MISRA-CPP-30.0.1": ("#include <iostream>\nstd::cout << value << '\\n';\nif (!std::cout)\n{\n    handle_output_failure();\n}",
                         "Adapt formatting, buffering, performance and error handling to the actual I/O operation; this example is for console output."),
    "CWE-369": ("if (denominator != 0)\n{\n    result = numerator / denominator;\n}\nelse\n{\n    /* Handle invalid input using the application's error policy. */\n}",
                "Check the actual divisor before division. For signed integers also consider the minimum-value divided by -1 overflow case."),
    "CWE-476": ("if (pointer != NULL)\n{\n    use_value(*pointer);\n}\nelse\n{\n    /* Handle the missing object. */\n}",
                "Use nullptr in C++. The pointer must also refer to a live object with appropriate bounds; a null check alone cannot prove that."),
    "C-STD-5.1.2": ("/*\n * DESCRIPTION: Explain this file's responsibility.\n */",
                     "Add the configured header tags and describe this specific module."),
    "C-STD-4.2.2": ("if (condition)\n{\n    perform_operation();\n}",
                     "Wrap the intended body. Check which statements currently belong to the condition or loop."),
}


def add_correction(violation, source=None):
    """Attach a suggestion using the full-file mask to protect literal text."""
    violation.correction_kind = "Manual review"
    violation.correction_note = (
        "Apply the rule's How to fix guidance in the surrounding code, then build and test. "
        "No context-independent code replacement is available for this finding.")
    example = EXAMPLES.get(violation.rule_id)
    if example:
        violation.correction_kind = "Illustrative example"
        violation.suggested_code, violation.correction_note = example
    if source is None or not 1 <= violation.line <= source.line_count:
        return
    raw = source.raw(violation.line)
    masked = source.mlines[violation.line - 1]
    rid = violation.rule_id
    replacements = []
    if rid == "MISRA-CPP-7.11.1" and not masked.lstrip().startswith("#"):
        replacements = [(m.start(), m.end(), "nullptr")
                        for m in re.finditer(r"\bNULL\b", masked)]
    elif rid in ("MISRA-CPP-5.13.3", "MISRA-7.1"):
        for match in NUMBERS.finditer(masked):
            number = re.fullmatch(r"(0[0-7]+)([uUlL]*)", match.group().replace("'", ""))
            if number:
                replacements.append((match.start(), match.end(),
                                     str(int(number.group(1), 8)) + number.group(2)))
    elif rid == "MISRA-CPP-5.13.5":
        # Only the exact numeric token already identified by the checker.
        for match in NUMBERS.finditer(masked):
            if match.group() == violation.detail:
                suffix = re.search(r"l[lLuU]*$", match.group())
                if suffix and "_" not in match.group():
                    token = match.group()[:suffix.start()] + suffix.group().replace("l", "L")
                    replacements.append((match.start(), match.end(), token))
    chosen = next((entry for entry in replacements if entry[0] == violation.column - 1), None)
    if chosen is None and len(replacements) == 1:
        chosen = replacements[0]
    if chosen:
        start, end, replacement = chosen
        violation.suggested_code = raw[:start] + replacement + raw[end:]
        violation.correction_kind = "Suggested line (review)"
        violation.correction_note = (
            "Addresses this finding only; other findings on the line may remain. "
            "Review the surrounding code, then build and test. Source files have not been changed.")
        if rid == "MISRA-CPP-7.11.1":
            violation.correction_note += " Confirm the intended value is a pointer; nullptr can change overload resolution."
        elif rid in ("MISRA-CPP-5.13.3", "MISRA-7.1"):
            violation.correction_note += " Preserves the octal numeric value; confirm the intended value and resulting literal type."
