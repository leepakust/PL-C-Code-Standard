"""Correction suggestions must preserve source and identify review scope."""

import csv
import io
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from cstdscan.config import Config
from cstdscan.corrections import add_correction
from cstdscan.model import Violation
from cstdscan.report import write_csv, write_excel
from cstdscan.scanner import scan
from cstdscan.source import SourceFile
from scan_c_code import print_findings


class CorrectionTests(unittest.TestCase):
    def scan_text(self, text, filename="example.cpp", standards=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, filename)
            path.write_text(text, encoding="utf-8")
            before = path.read_bytes()
            cfg = Config({"enabled_standards": standards or ["MISRA C++:2023"]})
            result = scan([str(path)], cfg)
            self.assertEqual([], result.errors)
            self.assertEqual(before, path.read_bytes())
            return result, cfg

    def test_null_suggestion_preserves_strings_comments_and_indentation(self):
        result, _ = self.scan_text('    int *p = NULL; // Keep NULL in this comment.\n'
                                   'auto s = "NULL";\n')
        finding = next(v for v in result.violations if v.rule_id == "MISRA-CPP-7.11.1")
        self.assertEqual('    int *p = nullptr; // Keep NULL in this comment.', finding.suggested_code)
        self.assertEqual("Suggested line (review)", finding.correction_kind)
        self.assertIn("overload", finding.correction_note)

    def test_multi_line_raw_string_is_not_rewritten(self):
        text = 'auto s = R"tag(\nNULL union X;\n)tag"; int *p = NULL;\n'
        result, _ = self.scan_text(text)
        finding = next(v for v in result.violations if v.rule_id == "MISRA-CPP-7.11.1")
        self.assertEqual(')tag"; int *p = nullptr;', finding.suggested_code)

    def test_each_suggestion_targets_only_its_own_token(self):
        result, _ = self.scan_text("int *p = NULL, *q = NULL;\n")
        nulls = [v for v in result.violations if v.rule_id == "MISRA-CPP-7.11.1"]
        self.assertEqual(["int *p = nullptr, *q = NULL;", "int *p = NULL, *q = nullptr;"],
                         [v.suggested_code for v in nulls])

    def test_numeric_value_and_suffix_are_preserved(self):
        result, _ = self.scan_text("auto n = 0'52UL; auto m = 1lU;\n")
        suggestions = {v.rule_id: v.suggested_code for v in result.violations}
        self.assertEqual("auto n = 42UL; auto m = 1lU;", suggestions["MISRA-CPP-5.13.3"])
        self.assertEqual("auto n = 0'52UL; auto m = 1LU;", suggestions["MISRA-CPP-5.13.5"])
        result, _ = self.scan_text("int f(void) { return 052; }\n", "example.c", ["MISRA C:2025"])
        finding = next(v for v in result.violations if v.rule_id == "MISRA-7.1")
        self.assertEqual("int f(void) { return 42; }", finding.suggested_code)

    def test_design_change_is_explicitly_an_example(self):
        result, _ = self.scan_text("union Data { int i; float f; };\n")
        finding = result.violations[0]
        self.assertEqual("Illustrative example", finding.correction_kind)
        self.assertIn("std::variant", finding.suggested_code)
        self.assertIn("layout", finding.correction_note)

    def test_macro_null_definition_is_not_replaced(self):
        result, _ = self.scan_text("#define NULL 0\n")
        finding = next(v for v in result.violations if v.rule_id == "MISRA-CPP-7.11.1")
        self.assertEqual("Illustrative example", finding.correction_kind)
        self.assertNotIn("#define nullptr", finding.suggested_code)

    def test_unknown_context_gets_manual_guidance(self):
        finding = Violation("MISRA-8.6", "a.c", 1, 1, "int f(void);")
        add_correction(finding)
        self.assertEqual("Manual review", finding.correction_kind)
        self.assertEqual("", finding.suggested_code)
        self.assertTrue(finding.rule().fix)
        self.assertIn("surrounding code", finding.correction_note)

    def test_exports_and_console_show_correction(self):
        from openpyxl import load_workbook
        result, cfg = self.scan_text("union Data { int i; float f; };\n")
        finding = result.violations[0]
        with tempfile.TemporaryDirectory() as tmp:
            xlsx = str(Path(tmp, "report.xlsx"))
            csv_path = str(Path(tmp, "report.csv"))
            write_excel(xlsx, result.violations, result.stats, cfg)
            write_csv(csv_path, result.violations)
            wb = load_workbook(xlsx)
            rows = list(wb["Violations"].values)
            row = dict(zip(rows[0], rows[1]))
            self.assertEqual(finding.suggested_code, row["Suggested correction / example"])
            self.assertEqual("Illustrative example", row["Correction type"])
            self.assertEqual(finding.correction_note, row["Correction notes"])
            wb.close()
            with open(csv_path, encoding="utf-8-sig", newline="") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(finding.suggested_code, row["Suggested correction / example"])
        output = io.StringIO()
        with redirect_stdout(output):
            print_findings(result.violations, 1)
        self.assertIn("Illustrative example", output.getvalue())
        self.assertIn("std::variant", output.getvalue())
        self.assertIn(finding.rule().fix, output.getvalue())


if __name__ == "__main__":
    unittest.main()
