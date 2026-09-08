"""C / C++ coding standard scanner.

A lexical static analyser in the spirit of a lint tool: it reads C and C++
source directly, with no build, no include paths and no toolchain, and
reports where the code departs from the house C coding standard, MISRA
C:2025, MISRA C++:2023 and the CWE weakness list. The result is an Excel workbook naming
the file, the line, the rule and the offending code.
"""

__version__ = "1.1.0"
__all__ = ["__version__"]
