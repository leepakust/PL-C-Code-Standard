"""Rule catalogue and violation record for the C/C++ coding standard scanner.

Three rule families are carried side by side:

    C-STD   -- the house C coding standard (layout, naming, structure, safety)
    MISRA   -- MISRA C:2025 rules that are checkable from source alone
    CWE     -- CWE weaknesses relevant to C/C++ (CWE list 4.20)

Every rule the scanner can raise is listed here, so the "Rules" sheet of the
report is an accurate description of what was actually checked.
"""

from dataclasses import dataclass, field
from typing import List


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
CLASS_ORDER = {"Mandatory": 0, "Required": 1, "Security": 2, "Advisory": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    standard: str        # C-STD | MISRA C:2025 | CWE
    category: str        # grouping used on the summary sheet
    severity: str        # Critical | High | Medium | Low
    rule_class: str      # Mandatory | Required | Advisory | Security
    title: str
    why: str
    fix: str


@dataclass
class Violation:
    rule_id: str
    file: str            # path as reported (relative to the scan root)
    line: int
    column: int
    code: str            # the offending source line, verbatim (trimmed)
    detail: str = ""     # what specifically was found, e.g. the identifier
    function: str = ""   # enclosing function, if any
    also: List[str] = field(default_factory=list)   # cross-referenced rules
    confidence: str = "High"                        # High | Medium | Low

    def rule(self) -> Rule:
        return RULES[self.rule_id]

    def sort_key(self):
        r = self.rule()
        return (SEVERITY_ORDER.get(r.severity, 9), self.file.lower(),
                self.line, self.rule_id)


def _r(*args) -> Rule:
    return Rule(*args)


_CATALOGUE = [
    # ---------------------------------------------------------------- layout
    _r("C-STD-4.2.3", "C-STD", "Layout", "Medium", "Required",
       "Tab character in source file",
       "Tabs render at different widths in different editors, so indentation "
       "that looks aligned to the author is misaligned for the next reader.",
       "Replace every tab with spaces; indent 4 spaces per level."),
    _r("C-STD-5.2.1", "C-STD", "Layout", "Low", "Advisory",
       "Line longer than the configured maximum",
       "Long lines force horizontal scrolling and hide code off the right of "
       "review tools and printed listings.",
       "Split the statement at a suitable point and indent the continuation "
       "to the same level."),
    _r("C-STD-4.2.1", "C-STD", "Layout", "Low", "Advisory",
       "Trailing whitespace at end of line",
       "Trailing whitespace produces noise in diffs and hides real changes.",
       "Strip the whitespace from the end of the line."),
    _r("C-STD-5.2.2", "C-STD", "Layout", "Low", "Advisory",
       "Opening brace is not on a line of its own",
       "The house layout places '{' and '}' on their own lines, aligned, so "
       "the extent of a block is visible at a glance.",
       "Move the '{' to the next line, aligned with the statement keyword."),
    _r("C-STD-4.2.2", "C-STD", "Layout", "High", "Required",
       "Control statement body without braces",
       "A single-statement body without braces silently excludes the next "
       "statement when one is added later - a classic source of live bugs.",
       "Wrap the body in braces, even when it is one statement."),
    _r("C-STD-5.2.3", "C-STD", "Layout", "Low", "Advisory",
       "More than one variable declared on a line",
       "One declaration per line keeps pointer declarators unambiguous and "
       "makes each variable independently reviewable and diffable.",
       "Declare each variable on its own line."),
    _r("C-STD-4.3.1", "C-STD", "Naming", "Medium", "Required",
       "File name contains characters other than letters, digits, underscore",
       "Punctuation in file names breaks build tools, shells and version "
       "control on at least one platform of a mixed toolchain.",
       "Rename the file using only [A-Za-z0-9_] in the base name."),
    _r("C-STD-4.3.3", "C-STD", "Naming", "Low", "Advisory",
       "Name expressing an amount or size does not state its units",
       "A size or duration without units invites the caller to supply the "
       "wrong scale - bytes for words, milliseconds for seconds.",
       "Add the unit to the name, e.g. SizeInBytes, TimeoutInMilliseconds."),

    # ------------------------------------------------------------- structure
    _r("C-STD-5.1.2", "C-STD", "File structure", "Medium", "Required",
       "File heading block missing or incomplete",
       "The file heading is the only place that records what the module is "
       "for; without it the reader must infer the purpose from the code.",
       "Add the standard file heading block with the required tags at the "
       "top of the file."),
    _r("C-STD-5.3.6", "C-STD", "File structure", "High", "Required",
       "Header file has no include guard",
       "Including the header twice redefines its types and objects and stops "
       "the translation unit compiling.",
       "Wrap the header in #ifndef NAME_H / #define NAME_H / #endif."),
    _r("C-STD-5.3.6a", "C-STD", "File structure", "Low", "Advisory",
       "Header uses '#pragma once' instead of an include guard",
       "'#pragma once' is not standard C and behaves differently across "
       "toolchains when a header is reachable by two different paths.",
       "Use the #ifndef / #define / #endif form instead."),
    _r("C-STD-5.3.6b", "C-STD", "File structure", "Low", "Advisory",
       "Include guard macro does not match the file name",
       "A guard name that does not track the file name is easily duplicated "
       "by a copied header, which then silently excludes the original.",
       "Name the guard after the file, e.g. MY_MODULE_H for my_module.h."),
    _r("C-STD-5.3.5", "C-STD", "File structure", "Low", "Advisory",
       "System header included with quotes instead of angle brackets",
       "Quoted includes search the local directory first, so a local file "
       "with the same name silently replaces the system header.",
       "Use the #include <stdint.h> form for system headers."),
    _r("C-STD-5.3.5a", "C-STD", "File structure", "Low", "Advisory",
       "Local header included with angle brackets instead of quotes",
       "Angle-bracket includes search the system path first, so the intended "
       "project header may not be the one that is used.",
       'Use the #include "my_module.h" form for project headers.'),
    _r("C-STD-5.3.4", "C-STD", "File structure", "Medium", "Required",
       "'extern' declaration in a .c file",
       "A local extern duplicates the real declaration; when the definition "
       "changes type, the compiler cannot detect the mismatch.",
       "Delete the extern and #include the owning module's header instead."),
    _r("MISRA-8.18", "MISRA C:2025", "File structure", "High", "Required",
       "Tentative definition in a header file",
       "Every translation unit that includes the header gets its own copy of "
       "the object; whether the linker merges or rejects them is toolchain "
       "dependent.",
       "Declare it 'extern' in the header and define it once in one .c file."),
    _r("C-STD-5.1.3", "C-STD", "Documentation", "Medium", "Required",
       "Function definition has no function heading comment",
       "Without the heading block the caller has no statement of what the "
       "parameters mean, what is returned, or what the side effects are.",
       "Add the standard function heading block above the definition."),
    _r("C-STD-5.4.1", "C-STD", "Naming", "Medium", "Required",
       "Global identifier has no component prefix",
       "Unprefixed global names collide at link time and hide which "
       "component owns the symbol.",
       "Prefix exported names with the component prefix, e.g. XXX_Init()."),
    _r("MISRA-8.7", "MISRA C:2025", "File structure", "Low", "Advisory",
       "Function with external linkage is used in only one file",
       "An unnecessarily exported symbol widens the module interface and "
       "prevents the compiler from inlining or discarding it.",
       "Declare the function 'static', or declare it in the module header if "
       "it really is part of the interface."),
    _r("MISRA-8.10", "MISRA C:2025", "File structure", "Low", "Required",
       "Inline function is not declared static",
       "A non-static inline function has external linkage but may have no "
       "external definition, which is undefined behaviour.",
       "Declare the inline function 'static'."),

    # ------------------------------------------------------------- functions
    _r("C-STD-5.5.4", "C-STD", "Functions", "Medium", "Required",
       "Empty parameter list written as '()' instead of '(void)'",
       "'()' declares an unspecified parameter list, so the compiler cannot "
       "check calls that pass arguments.",
       "Write the parameter list as (void)."),
    _r("C-STD-5.5.3", "C-STD", "Functions", "High", "Required",
       "Parameter declared without an explicit type",
       "An untyped parameter defaults to int, which silently mis-converts "
       "every argument of any other type.",
       "Give every parameter an explicit type."),
    _r("C-STD-5.5.1", "C-STD", "Functions", "High", "Required",
       "Function definition without an explicit return type",
       "An implicit return type is int; the caller then reads a garbage int "
       "from a function that returns something else.",
       "State the return type explicitly, or 'void' when nothing is "
       "returned."),
    _r("C-STD-5.5.6", "C-STD", "Functions", "High", "Required",
       "Function calls itself (recursion)",
       "Recursion consumes stack proportional to its input; on a target with "
       "a fixed per-task stack this overflows into adjacent memory.",
       "Rewrite iteratively, or justify the bounded depth in a comment."),
    _r("C-STD-5.5.5", "C-STD", "Functions", "Critical", "Mandatory",
       "Non-void function can return without a value",
       "The caller reads whatever happens to be in the return register, so "
       "behaviour depends on unrelated code.",
       "Return an explicit value on every path out of the function."),
    _r("MISRA-2.7", "MISRA C:2025", "Functions", "Low", "Advisory",
       "Unused function parameter",
       "An unused parameter usually means the implementation drifted from "
       "the interface, or that a check was dropped.",
       "Remove the parameter, or cast it to void with a comment saying why "
       "it is unused."),
    _r("C-STD-5.5.2", "C-STD", "Security", "Critical", "Mandatory",
       "Format string is not a literal",
       "A format string taken from data lets '%n' and '%s' read and write "
       "arbitrary stack memory - directly exploitable.",
       'Always pass a literal: printf("%s", pText).'),
    _r("C-STD-5.11.2", "C-STD", "Error handling", "High", "Required",
       "Return value of an error-returning function is discarded",
       "A silently dropped error lets the code continue on the assumption "
       "that the operation succeeded.",
       "Test the result, or discard it deliberately with (void) plus a "
       "comment saying why nothing can be done."),
    _r("C-STD-4.7.1", "C-STD", "Complexity", "Low", "Advisory",
       "Function is too long or too complex",
       "A function past this size no longer has one responsibility, and its "
       "paths cannot be covered by review or test with any confidence.",
       "Split the function into cohesive parts."),

    # ------------------------------------------------------- variables/types
    _r("C-STD-5.7.2", "C-STD", "Variables", "High", "Mandatory",
       "Local variable not initialised at declaration",
       "An uninitialised local holds whatever was last on the stack, so the "
       "fault appears only for some call paths.",
       "Initialise at the declaration, to a failsafe or invalid value."),
    _r("C-STD-5.7.1", "C-STD", "Variables", "Medium", "Required",
       "Declaration shadows an identifier in an enclosing scope",
       "The inner name hides the outer one, so an edit that intended the "
       "outer variable silently changes the inner one.",
       "Rename the inner variable."),
    _r("C-STD-5.6.6", "C-STD", "Naming", "Low", "Advisory",
       "Pointer variable without 'p' prefix",
       "The 'p' prefix makes indirection visible at the point of use, where "
       "the declaration is not.",
       "Rename to pName (ppName for a pointer to a pointer)."),
    _r("C-STD-5.6.6a", "C-STD", "Naming", "Low", "Advisory",
       "Type name without 't' prefix",
       "The 't' prefix separates type names from objects and functions at "
       "the point of use.",
       "Rename to tName, or XXX_tName for an exported type."),
    _r("C-STD-5.6.6b", "C-STD", "Naming", "Medium", "Required",
       "typedef of a pointer type",
       "A pointer typedef hides the indirection, so const qualification and "
       "ownership become invisible at the point of use.",
       "Declare the pointer at the point of use: tByte *pHandle."),
    _r("C-STD-5.6.3", "C-STD", "Types", "Medium", "Advisory",
       "Plain basic type used where a fixed-width type is required",
       "The width of int, short, long and char varies by target, so data "
       "that crosses an interface changes size with the toolchain.",
       "Use the <stdint.h> types: uint8_t, int32_t and so on."),
    _r("C-STD-5.8.4", "C-STD", "Types", "Medium", "Required",
       "String literal assigned to a non-const pointer",
       "String literals live in read-only memory; writing through such a "
       "pointer faults or corrupts the contents of flash.",
       "Declare the pointer as 'const char *'."),
    _r("MISRA-18.8", "MISRA C:2025", "Memory", "Critical", "Required",
       "Variable-length array",
       "A run-time sized stack array has no upper bound, so a large input "
       "silently walks off the end of the task stack.",
       "Use a fixed, compile-time size and clamp the length to it."),
    _r("MISRA-18.7", "MISRA C:2025", "Memory", "Medium", "Required",
       "Flexible array member",
       "The member has no size of its own, so sizeof and array bounds "
       "checking cannot protect accesses to it.",
       "Use a fixed-size array member, or a separate buffer plus length."),
    _r("MISRA-18.5", "MISRA C:2025", "Types", "Low", "Advisory",
       "More than two levels of pointer indirection",
       "Deep indirection makes ownership and lifetime impossible to follow "
       "in review.",
       "Introduce a named intermediate type or restructure the data."),
    _r("MISRA-8.14", "MISRA C:2025", "Types", "Low", "Required",
       "'restrict' qualifier used",
       "restrict is a promise the compiler cannot verify; if it is broken "
       "the generated code is wrong in ways no test reliably catches.",
       "Remove the restrict qualifier."),

    # ---------------------------------------------------------- control flow
    _r("C-STD-5.10.1", "C-STD", "Control flow", "High", "Required",
       "switch statement without a default label",
       "An unexpected value falls straight through the switch with no action "
       "and no record that it happened.",
       "Add a default: leg that handles or logs the unexpected value."),
    _r("C-STD-5.10.2", "C-STD", "Control flow", "Medium", "Required",
       "Last switch clause does not end with break",
       "When a new case is appended later it silently becomes a "
       "fall-through target.",
       "End the last case or default leg with break."),
    _r("MISRA-16.6", "MISRA C:2025", "Control flow", "Low", "Required",
       "switch statement has fewer than two clauses",
       "A switch on one value is an if statement written in a form that "
       "hides its own condition.",
       "Replace the switch with if/else."),
    _r("C-STD-5.10.3", "C-STD", "Control flow", "Medium", "Required",
       "Fall-through between non-empty switch clauses is not commented",
       "The reader cannot tell a deliberate fall-through from a missing "
       "break, so the next edit picks the wrong one.",
       "Add a break, or comment the fall-through as intentional."),
    _r("C-STD-5.10.5", "C-STD", "Control flow", "Medium", "Required",
       "if / else if chain has no final else",
       "Values outside the handled set produce no action at all and leave no "
       "trace, so the fault surfaces far from its cause.",
       "Add a final else that handles or logs the unexpected value."),
    _r("C-STD-5.10.4", "C-STD", "Control flow", "Medium", "Required",
       "Loop has no demonstrable termination condition",
       "A loop whose only exit is a break inside the body hangs the task if "
       "the break condition never becomes true.",
       "Add a bounded iteration count, or annotate a genuinely "
       "non-terminating task loop."),
    _r("MISRA-15.1", "MISRA C:2025", "Control flow", "Medium", "Advisory",
       "'goto' statement used",
       "Unstructured jumps make the set of reachable states impossible to "
       "derive from the source.",
       "Restructure with loops and conditionals."),
    _r("MISRA-14.4", "MISRA C:2025", "Control flow", "Medium", "Required",
       "Controlling expression is not essentially boolean",
       "Testing an integer as a condition hides the actual comparison and "
       "changes meaning when the type changes.",
       "Write the comparison out: if (Count != 0U)."),
    _r("MISRA-11.11", "MISRA C:2025", "Security", "High", "Required",
       "Pointer compared to NULL implicitly",
       "An implicit pointer test reads as a boolean flag test, so a missing "
       "or wrong NULL check passes review unnoticed.",
       "Write the comparison out: if (NULL != pBuffer)."),
    _r("C-STD-5.6.5", "C-STD", "Control flow", "Low", "Required",
       "Boolean value compared with == or !=",
       "Comparing against a truth constant breaks as soon as the value is a "
       "non-zero integer rather than exactly that constant.",
       "Use the value directly: if (PortOpen) / if (!PortOpen)."),
    _r("C-STD-5.12.4", "C-STD", "Clarity", "Medium", "Required",
       "Assignment used as a condition",
       "An assignment in a condition reads as a comparison, so '=' typed for "
       "'==' passes review.",
       "Assign first, then test the variable in the condition."),
    _r("C-STD-5.12.4a", "C-STD", "Clarity", "Low", "Advisory",
       "Negated string-compare idiom",
       "'!strcmp(a, b)' reads as 'not equal' but means 'equal'.",
       "Write 0 == strcmp(a, b)."),
    _r("C-STD-5.12.4b", "C-STD", "Clarity", "Low", "Advisory",
       "Nested conditional (ternary) operators",
       "Nested ternaries hide the branch structure the reader has to "
       "follow.",
       "Use if / else if / else."),
    _r("MISRA-14.1", "MISRA C:2025", "Control flow", "Medium", "Required",
       "Loop counter has floating-point type",
       "Accumulated rounding makes the iteration count depend on the target "
       "FPU rather than on the source.",
       "Use an integer loop counter."),
    _r("C-STD-5.12.6", "C-STD", "Expressions", "High", "Required",
       "More than one ++ or -- applied to the same object in a statement",
       "The order of the modifications is undefined, so the result varies "
       "between compilers and optimisation levels.",
       "Split the statement so each object is modified once."),
    _r("MISRA-13.5", "MISRA C:2025", "Expressions", "Medium", "Advisory",
       "Side effect in the right-hand operand of && or ||",
       "Short-circuit evaluation may skip the right operand, so the side "
       "effect happens only sometimes.",
       "Move the side effect out of the condition."),

    # ------------------------------------------------ literals / expressions
    _r("MISRA-7.1", "MISRA C:2025", "Literals", "Medium", "Required",
       "Octal constant used",
       "A leading zero makes 010 mean 8, which reads as 10 to everyone who "
       "has not been bitten by it before.",
       "Write the value in hexadecimal or decimal: 0x08 or 8U."),
    _r("MISRA-7.2", "MISRA C:2025", "Literals", "Low", "Required",
       "Integer constant of unsigned type without a 'U' suffix",
       "Without the suffix the constant is signed, and mixing it with an "
       "unsigned operand converts the other way round to the intent.",
       "Add the suffix: 256U, 0xFFU, 32768UL."),
    _r("MISRA-7.3", "MISRA C:2025", "Literals", "Low", "Required",
       "Lowercase 'l' used as an integer literal suffix",
       "'1l' and '11' are indistinguishable in most fonts used for code.",
       "Use uppercase: 1L, 1UL."),
    _r("C-STD-4.4.1", "C-STD", "Literals", "Medium", "Advisory",
       "Magic number used more than once",
       "The same literal repeated in several places has to be found and "
       "changed in all of them at once, and one is always missed.",
       "Give it a name: a macro, enum constant or const object."),
    _r("C-STD-5.12.2", "C-STD", "Macros", "High", "Required",
       "Macro expression is not fully parenthesised",
       "Without parentheses the macro binds to the surrounding expression by "
       "precedence, producing a different result from the one written.",
       "Parenthesise every parameter and the whole body: "
       "#define PRODUCT(x, y) ((x) * (y))"),
    _r("MISRA-20.4", "MISRA C:2025", "Macros", "Medium", "Required",
       "Macro defined with the same name as a keyword",
       "Redefining a keyword changes the meaning of code the author of that "
       "code cannot see.",
       "Choose a different macro name."),
    _r("MISRA-20.5", "MISRA C:2025", "Macros", "Low", "Advisory",
       "'#undef' used",
       "Undefining a macro makes its meaning depend on position in the file, "
       "so the same source line expands differently in two places.",
       "Restructure so the macro does not need to be undefined."),
    _r("MISRA-20.10", "MISRA C:2025", "Macros", "Low", "Advisory",
       "'#' or '##' preprocessor operator used",
       "Token pasting and stringification produce identifiers that no search "
       "of the source will find.",
       "Write the identifiers out."),
    _r("MISRA-5.10", "MISRA C:2025", "Naming", "Medium", "Required",
       "Reserved identifier or reserved macro name declared or defined",
       "Names starting with an underscore, and standard library names, "
       "belong to the implementation; redefining them is undefined "
       "behaviour.",
       "Rename to an identifier owned by the project."),
    _r("MISRA-12.2", "MISRA C:2025", "Expressions", "High", "Required",
       "Shift count outside the width of the shifted type",
       "Shifting by the type width or more is undefined; some targets shift "
       "modulo the width, others produce zero.",
       "Widen the operand before shifting, or reduce the shift count."),
    _r("MISRA-12.5", "MISRA C:2025", "Expressions", "Critical", "Mandatory",
       "sizeof applied to a parameter declared as an array",
       "An array parameter is a pointer, so sizeof yields the pointer size "
       "and every bounds check built on it is wrong.",
       "Pass the element count as a separate parameter."),
    _r("C-STD-5.9.1", "C-STD", "Casting", "Medium", "Advisory",
       "Cast without a justifying comment",
       "An unexplained cast is indistinguishable from one that silences a "
       "warning the author did not understand.",
       "Add a comment stating why the conversion is safe."),
    _r("C-STD-5.9.2", "C-STD", "Casting", "Medium", "Advisory",
       "Narrowing conversion without an explicit mask",
       "Truncation drops the high bits silently, and the result depends on "
       "the value at run time rather than on the source.",
       "Mask explicitly: (uint8_t)(Value & 0xFFU)."),
    _r("MISRA-11.4", "MISRA C:2025", "Casting", "High", "Required",
       "Conversion between a pointer and an arithmetic type",
       "The integer representation of a pointer is not portable and defeats "
       "every pointer-provenance check the compiler makes.",
       "Keep the value in pointer form, or use a documented deviation."),
    _r("MISRA-11.3", "MISRA C:2025", "Casting", "High", "Required",
       "Cast between pointers to different object types",
       "The target type may have stricter alignment or a different "
       "representation, so the access is undefined.",
       "Copy through an object of the correct type instead."),
    _r("MISRA-11.8", "MISRA C:2025", "Casting", "High", "Required",
       "Cast removes const or volatile qualification",
       "Casting away const permits a write the type system was preventing; "
       "casting away volatile lets the compiler cache a value it must not.",
       "Keep the qualifier, or fix the interface that demands the cast."),
    _r("MISRA-11.9", "MISRA C:2025", "Casting", "Low", "Required",
       "Integer 0 used as a null pointer constant",
       "A bare 0 is not distinguishable from an integer value at the point "
       "of use.",
       "Use NULL."),
    _r("C-STD-5.8.2", "C-STD", "Casting", "High", "Required",
       "Assignment to, or address of, a cast object",
       "A cast produces a value, not an object, so this is a constraint "
       "violation that some compilers accept with surprising results.",
       "Cast the pointer, not the object: *((uint8_t *)&x) = 1U;"),
    _r("C-STD-5.12.3", "C-STD", "Security", "Low", "Advisory",
       "Cryptographic operation without an approval reference",
       "Cryptographic code carries export and compliance obligations that "
       "have to be traceable from the source.",
       "Reference the approval in a comment containing the keyword CRYPTO."),

    # ---------------------------------------------------- library / security
    _r("C-STD-6.1.5", "C-STD", "Security", "Critical", "Mandatory",
       "Prohibited standard library function used",
       "These functions have no bound on what they write, or hand data to a "
       "shell; each one is a documented, routinely exploited weakness.",
       "Use the bounded replacement listed for the function."),
    _r("C-STD-6.1.6", "C-STD", "Security", "Medium", "Advisory",
       "Dangerous function used without a justifying comment",
       "These functions are safe only under preconditions that are not "
       "visible at the call site.",
       "State the precondition in a comment at the call, or use a safer "
       "alternative."),
    _r("MISRA-21.3", "MISRA C:2025", "Memory", "High", "Required",
       "Dynamic memory allocation used",
       "Heap use on a long-running embedded target fragments memory until an "
       "allocation fails at an arbitrary later point.",
       "Use statically allocated storage or a fixed pool."),
    _r("MISRA-21.6", "MISRA C:2025", "Library", "Medium", "Required",
       "Standard library input/output function used in production code",
       "The stdio implementation carries unbounded buffers, locale handling "
       "and a heap dependency that are unwanted on the target.",
       "Use the project logging or I/O abstraction."),
    _r("MISRA-21.7", "MISRA C:2025", "Library", "Medium", "Required",
       "atof, atoi, atol or atoll used",
       "These functions cannot report a conversion failure, so bad input is "
       "indistinguishable from a valid zero.",
       "Use strtol / strtoul / strtof and check errno and the end pointer."),
    _r("MISRA-21.8", "MISRA C:2025", "Library", "High", "Required",
       "Standard library termination function used",
       "abort, exit and system end or hand off the program in ways an "
       "embedded target cannot recover from.",
       "Return an error code and let the caller decide."),
    _r("MISRA-21.9", "MISRA C:2025", "Library", "Low", "Required",
       "bsearch or qsort used",
       "Both call back into user code with library-controlled arguments and "
       "have implementation-defined behaviour on equal keys.",
       "Use a project-written search or sort."),
    _r("MISRA-21.10", "MISRA C:2025", "Library", "Low", "Required",
       "Standard library time or date function used",
       "These functions return pointers to shared static storage that the "
       "next call overwrites.",
       "Use the platform time API."),
    _r("MISRA-21.4", "MISRA C:2025", "Library", "Medium", "Required",
       "<setjmp.h> used",
       "setjmp and longjmp bypass normal stack unwinding, leaving resources "
       "held and automatic objects in indeterminate states.",
       "Use return codes for error propagation."),
    _r("MISRA-21.5", "MISRA C:2025", "Library", "Medium", "Required",
       "<signal.h> used",
       "Signal handling has undefined behaviour for almost everything a "
       "handler might usefully do.",
       "Use the platform's interrupt or event mechanism."),
    _r("MISRA-17.1", "MISRA C:2025", "Library", "Medium", "Required",
       "<stdarg.h> features used",
       "Variadic arguments are unchecked; a mismatch between the format and "
       "the arguments reads arbitrary stack.",
       "Use a fixed parameter list, or a struct of parameters."),
    _r("MISRA-21.14", "MISRA C:2025", "Library", "Medium", "Required",
       "memcmp used to compare null-terminated strings",
       "memcmp compares past the terminator, so the result depends on "
       "whatever padding follows the string.",
       "Use strcmp or strncmp."),
    _r("MISRA-21.16", "MISRA C:2025", "Library", "Medium", "Required",
       "memcmp used to compare pointer values",
       "Two pointers to the same object may have different representations, "
       "so a byte comparison can report them unequal.",
       "Compare the pointers with ==."),
    _r("CWE-416", "CWE", "Security", "High", "Security",
       "Pointer not set to NULL after being freed",
       "The dangling pointer still looks valid, so a later use or a second "
       "free corrupts the allocator - a routinely exploited class of bug.",
       "Set the pointer to NULL immediately after freeing it."),
    _r("CWE-787", "CWE", "Security", "Critical", "Security",
       "Copy length is not bounded by the destination size",
       "A source longer than the destination writes past the end of the "
       "destination object, over whatever follows it in memory.",
       "Bound the length: memcpy(pDest, pSrc, MIN(sizeof(Dest), SrcLen))."),
    _r("CWE-476", "CWE", "Security", "Critical", "Security",
       "Pointer parameter dereferenced without a NULL check",
       "A NULL from any caller faults immediately, and on a target without "
       "an MPU it may instead read whatever is mapped at address zero.",
       "Validate at entry: if (NULL == pData) { return ERROR_PARAM; }"),
    _r("CWE-369", "CWE", "Security", "High", "Security",
       "Division or modulo by a value that is not checked against zero",
       "Division by zero traps on most targets and produces an "
       "implementation-defined result on the rest.",
       "Test the divisor before the operation."),
    _r("CWE-190", "CWE", "Security", "High", "Security",
       "Arithmetic on a length or size without an overflow check",
       "The sum or product wraps to a small value, so the allocation or "
       "bounds check that uses it passes while the copy overruns.",
       "Check against the type maximum before the arithmetic."),
    _r("CWE-843", "CWE", "Security", "High", "Security",
       "Union member read that was not the member last written",
       "The bytes are reinterpreted as a different type, so the value read "
       "depends on the target's representation and padding.",
       "Read only the member last written; pair the union with a tag."),
    _r("CWE-362", "CWE", "Security", "Medium", "Security",
       "Shared object accessed from interrupt context without volatile",
       "The compiler may cache the value in a register, so the main-context "
       "code never observes the update made by the handler.",
       "Declare the shared object volatile and guard multi-byte accesses "
       "with a critical section."),

    # ---------------------------------------------------------- project-wide
    _r("C-STD-4.3.2", "C-STD", "Project", "Medium", "Required",
       "File names differ only by letter case",
       "One of the two files disappears when the project is checked out on a "
       "case-insensitive file system.",
       "Rename one of the files."),
    _r("MISRA-5.1", "MISRA C:2025", "Project", "Medium", "Required",
       "External identifiers are not distinct within 31 characters",
       "A conforming toolchain may consider the names identical, so the "
       "linker silently binds calls to the wrong function.",
       "Make the names differ within the first 31 characters."),
    _r("MISRA-8.6", "MISRA C:2025", "Project", "High", "Required",
       "Identifier with external linkage has more than one definition",
       "Which definition the linker picks is not determined by the source.",
       "Keep one definition; make the others static or remove them."),
    _r("MISRA-5.6", "MISRA C:2025", "Project", "Medium", "Required",
       "typedef name is not unique across the project",
       "Two different types with one name make the meaning of a declaration "
       "depend on which header was included first.",
       "Give each type a unique, component-prefixed name."),
]

RULES = {r.id: r for r in _CATALOGUE}


def rule_ids():
    return list(RULES.keys())


# Rules that are cited alongside a primary finding but are not themselves
# raised by a check.  The report shows the title next to the cross-reference
# so the reader does not have to look the number up.
CROSS_REF_TITLES = {
    "C-STD-4.6.1": "Inputs shall be validated before use",
    "C-STD-5.7.3": "Copy length shall be bounded to the smaller of source "
                   "and destination",
    "C-STD-6.1.2": "Pointer to freed sensitive data shall be set to NULL",
    "MISRA-4.10": "Precautions shall prevent a header being included twice",
    "MISRA-5.3": "An inner-scope identifier shall not hide an outer one",
    "MISRA-8.2": "Function types shall be in prototype form with named "
                 "parameters",
    "MISRA-8.19": "There should be no external declarations in a source file",
    "MISRA-9.1": "An automatic object shall not be read before it is set",
    "MISRA-7.4": "A string literal shall only be assigned to a pointer to "
                 "const char",
    "MISRA-13.3": "An expression with ++ or -- should have no other side "
                  "effects",
    "MISRA-13.4": "The result of an assignment operator should not be used",
    "MISRA-15.6": "The body of an iteration or selection statement shall be "
                  "a compound statement",
    "MISRA-15.7": "All if / else if constructs shall end with an else",
    "MISRA-16.3": "An unconditional break shall terminate every switch "
                  "clause",
    "MISRA-16.4": "Every switch statement shall have a default label",
    "MISRA-17.2": "Functions shall not call themselves",
    "MISRA-17.4": "Every exit path of a non-void function shall return a "
                  "value",
    "MISRA-17.7": "The value returned by a non-void function shall be used",
    "MISRA-19.3": "A union member shall not be read unless it has been set",
    "MISRA-20.7": "Macro parameter expansions shall be appropriately "
                  "delimited",
    "CWE-78": "OS command injection",
    "CWE-120": "Buffer copy without checking size of input",
    "CWE-121": "Stack-based buffer overflow",
    "CWE-134": "Use of externally-controlled format string",
    "CWE-170": "Improper null termination",
    "CWE-242": "Use of an inherently dangerous function",
    "CWE-457": "Use of uninitialised variable",
    "CWE-476": "NULL pointer dereference",
    "CWE-663": "Use of a non-reentrant function in a concurrent context",
    "CWE-704": "Incorrect type conversion or cast",
    "CWE-770": "Allocation of resources without limits",
    "CWE-787": "Out-of-bounds write",
}


def rule_title(rule_id):
    rule = RULES.get(rule_id)
    if rule is not None:
        return rule.title
    return CROSS_REF_TITLES.get(rule_id, "")
