#!/usr/bin/env python3
"""Desktop front end for the C / C++ coding standard scanner.

    python cstdscan_gui.py

Pick a folder, press Scan, and work through the findings in the list. The
same engine as the command line tool, so the Excel report is identical.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import traceback
import webbrowser
from collections import Counter

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cstdscan import __version__                                # noqa: E402
from cstdscan.config import Config                              # noqa: E402
from cstdscan.model import RULES, SEVERITY_ORDER                # noqa: E402
from cstdscan.report import write_csv, write_excel              # noqa: E402
from cstdscan.scanner import scan                               # noqa: E402


SETTINGS_FILE = os.path.join(HERE, "gui_settings.json")
SEVERITIES = ["Critical", "High", "Medium", "Low"]
STANDARDS = ["C-STD", "MISRA C:2025", "MISRA C++:2023", "CWE"]


def selected_standards(settings):
    """Enable newly introduced families once; preserve subsequent choices."""
    selected = settings.get("standards", STANDARDS)
    known = settings.get("known_standards", ["C-STD", "MISRA C:2025", "CWE"])
    return [name for name in STANDARDS if name in selected or name not in known]

SEVERITY_COLOUR = {
    "Critical": "#F8CBCB",
    "High": "#FBE0C4",
    "Medium": "#FCF3C6",
    "Low": "#E7ECF0",
}
NOISY_RULES = ["C-STD-5.9.1", "C-STD-4.4.1", "C-STD-5.2.2", "C-STD-4.2.1"]


def open_in_explorer(path, select=True):
    """Show a file or folder in the system file manager."""
    path = os.path.abspath(path)
    try:
        if sys.platform.startswith("win"):
            if select and os.path.isfile(path):
                subprocess.Popen(["explorer", "/select,", path])
            else:
                os.startfile(path if os.path.isdir(path)
                             else os.path.dirname(path))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R" if select else "", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path)])
    except Exception as exc:
        messagebox.showerror("Could not open", str(exc))


def open_document(path):
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            webbrowser.open("file://" + os.path.abspath(path))
    except Exception as exc:
        messagebox.showerror("Could not open", str(exc))


class RuleWindow(tk.Toplevel):
    """The rule catalogue, with a tick box per rule."""

    def __init__(self, master, disabled):
        super().__init__(master)
        self.title("Rule catalogue")
        self.geometry("1000x620")
        self.disabled = set(disabled)
        self.result = None

        bar = ttk.Frame(self, padding=(8, 8, 8, 4))
        bar.pack(fill="x")
        ttk.Label(bar, text="Click a row to switch a rule on or off.  "
                            "%d rules." % len(RULES)).pack(side="left")
        ttk.Button(bar, text="Enable all",
                   command=lambda: self._bulk(set())).pack(side="right",
                                                           padx=2)
        ttk.Button(bar, text="Disable advisory",
                   command=self._disable_advisory).pack(side="right", padx=2)
        ttk.Button(bar, text="Disable the noisy four",
                   command=lambda: self._bulk(set(NOISY_RULES))
                   ).pack(side="right", padx=2)

        columns = ("on", "rule", "standard", "severity", "class", "title")
        self.tree = ttk.Treeview(self, columns=columns, show="headings",
                                 selectmode="browse")
        for name, text, width in (
                ("on", "On", 40), ("rule", "Rule", 170),
                ("standard", "Standard", 150), ("severity", "Severity", 80),
                ("class", "Class", 90), ("title", "Title", 520)):
            self.tree.heading(name, text=text)
            self.tree.column(name, width=width,
                             anchor="center" if name == "on" else "w")
        scroll = ttk.Scrollbar(self, orient="vertical",
                               command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0),
                       pady=4)
        scroll.pack(side="left", fill="y", pady=4, padx=(0, 8))

        for sev, colour in SEVERITY_COLOUR.items():
            self.tree.tag_configure(sev, background=colour)
        self.tree.bind("<Button-1>", self._toggle)

        footer = ttk.Frame(self, padding=8)
        footer.pack(fill="x", side="bottom")
        ttk.Button(footer, text="Cancel",
                   command=self.destroy).pack(side="right")
        ttk.Button(footer, text="Use these rules",
                   command=self._accept).pack(side="right", padx=6)

        self._fill()
        self.transient(master)
        self.grab_set()

    def _fill(self):
        self.tree.delete(*self.tree.get_children())
        order = sorted(RULES.values(),
                       key=lambda r: (r.standard,
                                      SEVERITY_ORDER[r.severity], r.id))
        for rule in order:
            on = "off" if rule.id in self.disabled else "on"
            self.tree.insert("", "end", iid=rule.id,
                             values=("x" if on == "on" else "",
                                     rule.id, rule.standard, rule.severity,
                                     rule.rule_class, rule.title),
                             tags=(rule.severity,))

    def _toggle(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        if row in self.disabled:
            self.disabled.discard(row)
        else:
            self.disabled.add(row)
        self.tree.set(row, "on", "" if row in self.disabled else "x")

    def _bulk(self, disabled):
        self.disabled = set(disabled)
        self._fill()

    def _disable_advisory(self):
        self.disabled = {r.id for r in RULES.values()
                         if r.rule_class == "Advisory"}
        self._fill()

    def _accept(self):
        self.result = sorted(self.disabled)
        self.destroy()


class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("C / C++ Coding Standard Scanner %s" % __version__)
        self.geometry("1280x760")
        self.minsize(980, 600)

        self.violations = []
        self.result = None
        self.report_path = None
        self.queue = queue.Queue()
        self.scanning = False
        self.sort_column = None
        self.sort_reverse = False
        self.disabled_rules = []

        self._build_widgets()
        self._load_settings()

    # ------------------------------------------------------------- layout
    def _build_widgets(self):
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=20)

        self._build_menu()

        top = ttk.Frame(self, padding=(10, 10, 10, 4))
        top.pack(fill="x")
        ttk.Label(top, text="Folder to scan").grid(row=0, column=0,
                                                   sticky="w")
        self.path_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.path_var)
        entry.grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="Browse folder...",
                   command=self.browse_folder).grid(row=0, column=2, padx=2)
        ttk.Button(top, text="Single file...",
                   command=self.browse_file).grid(row=0, column=3, padx=2)
        self.scan_button = ttk.Button(top, text="Scan",
                                      command=self.start_scan)
        self.scan_button.grid(row=0, column=4, padx=(10, 0))
        top.columnconfigure(1, weight=1)

        options = ttk.LabelFrame(self, text="Options",
                                 padding=(10, 6, 10, 8))
        options.pack(fill="x", padx=10, pady=(4, 6))

        ttk.Label(options, text="Report at least").grid(row=0, column=0,
                                                        sticky="w")
        self.severity_var = tk.StringVar(value="Low")
        ttk.Combobox(options, textvariable=self.severity_var, width=10,
                     state="readonly", values=SEVERITIES).grid(
            row=0, column=1, sticky="w", padx=(6, 18))

        self.std_vars = {}
        col = 2
        for name in STANDARDS:
            var = tk.BooleanVar(value=True)
            self.std_vars[name] = var
            ttk.Checkbutton(options, text=name, variable=var).grid(
                row=0, column=col, sticky="w", padx=(0, 12))
            col += 1

        self.quiet_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options, text="Skip the four noisiest rules",
                        variable=self.quiet_var).grid(row=0, column=col,
                                                      sticky="w")

        ttk.Label(options, text="Skip paths matching").grid(row=1, column=0,
                                                            sticky="w",
                                                            pady=(6, 0))
        self.exclude_var = tk.StringVar(
            value="*/Drivers/*; */Middlewares/*; */build/*")
        ttk.Entry(options, textvariable=self.exclude_var).grid(
            row=1, column=1, columnspan=4, sticky="ew", padx=6, pady=(6, 0))

        ttk.Label(options, text="Skip file names like").grid(
            row=2, column=0, sticky="w", pady=(6, 0))
        self.exclude_name_var = tk.StringVar(
            value="*- copy*; *.bak; *.orig; *.old")
        ttk.Entry(options, textvariable=self.exclude_name_var).grid(
            row=2, column=1, columnspan=4, sticky="ew", padx=6,
            pady=(6, 0))
        ttk.Label(options,
                  text="matches anywhere in the tree, e.g. any file "
                       'named "... - Copy.c"').grid(
            row=2, column=5, columnspan=2, sticky="w", pady=(6, 0))

        self.excel_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="Write the Excel report",
                        variable=self.excel_var).grid(row=1, column=5,
                                                      sticky="w",
                                                      pady=(6, 0))
        ttk.Button(options, text="Choose rules...",
                   command=self.choose_rules).grid(row=1, column=6,
                                                   sticky="e", pady=(6, 0))
        options.columnconfigure(1, weight=1)
        ttk.Label(options, text="Language").grid(row=3, column=0, sticky="w", pady=6)
        self.language_var = tk.StringVar(value="auto")
        ttk.Combobox(options, textvariable=self.language_var, width=10,
                     state="readonly", values=["auto", "c", "c++"]).grid(
                         row=3, column=1, sticky="w", padx=6)
        ttk.Label(options, text=".h language").grid(row=3, column=2, sticky="w")
        self.header_language_var = tk.StringVar(value="auto")
        ttk.Combobox(options, textvariable=self.header_language_var, width=10,
                     state="readonly", values=["auto", "c", "c++"]).grid(
                         row=3, column=3, sticky="w")

        filters = ttk.Frame(self, padding=(10, 0, 10, 6))
        filters.pack(fill="x")
        ttk.Label(filters, text="Filter").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_a: self.refresh_table())
        ttk.Entry(filters, textvariable=self.filter_var, width=42).pack(
            side="left", padx=6)
        ttk.Label(filters, text="Severity").pack(side="left", padx=(12, 0))
        self.view_severity = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.view_severity, width=10,
                     state="readonly",
                     values=["All"] + SEVERITIES).pack(side="left", padx=6)
        self.view_severity.trace_add("write",
                                     lambda *_a: self.refresh_table())
        self.count_label = ttk.Label(filters, text="")
        self.count_label.pack(side="right")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10)
        self.notebook = notebook

        findings = ttk.Frame(notebook)
        notebook.add(findings, text="Findings")
        panes = ttk.PanedWindow(findings, orient="vertical")
        panes.pack(fill="both", expand=True)

        table_frame = ttk.Frame(panes)
        columns = ("severity", "rule", "file", "line", "function", "detail")
        self.tree = ttk.Treeview(table_frame, columns=columns,
                                 show="headings", selectmode="browse")
        for name, text, width, anchor in (
                ("severity", "Severity", 80, "center"),
                ("rule", "Rule", 170, "w"),
                ("file", "File", 300, "w"),
                ("line", "Line", 60, "e"),
                ("function", "Function", 160, "w"),
                ("detail", "What was found", 560, "w")):
            self.tree.heading(name, text=text,
                              command=lambda c=name: self.sort_by(c))
            self.tree.column(name, width=width, anchor=anchor)
        yscroll = ttk.Scrollbar(table_frame, orient="vertical",
                                command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        for sev, colour in SEVERITY_COLOUR.items():
            self.tree.tag_configure(sev, background=colour)
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        self.tree.bind("<Double-1>", lambda _e: self.open_source())
        self.tree.bind("<Button-3>", self._context_menu)
        panes.add(table_frame, weight=3)

        detail_frame = ttk.Frame(panes)
        self.detail = tk.Text(detail_frame, height=11, wrap="word",
                              state="disabled", padx=8, pady=6,
                              background="#FBFCFD", relief="flat",
                              font=("Segoe UI", 10))
        dscroll = ttk.Scrollbar(detail_frame, orient="vertical",
                                command=self.detail.yview)
        self.detail.configure(yscrollcommand=dscroll.set)
        self.detail.pack(side="left", fill="both", expand=True)
        dscroll.pack(side="left", fill="y")
        self.detail.tag_configure("h1", font=("Segoe UI", 11, "bold"))
        self.detail.tag_configure("label", font=("Segoe UI", 9, "bold"),
                                  foreground="#1F3B57")
        self.detail.tag_configure("code", font=("Consolas", 10),
                                  background="#F1F3F5")
        panes.add(detail_frame, weight=1)

        self.by_rule = self._summary_tab(
            notebook, "By rule",
            (("rule", "Rule", 170), ("standard", "Standard", 150),
             ("severity", "Severity", 80), ("title", "Title", 480),
             ("count", "Count", 70), ("files", "Files", 70)))
        self.by_file = self._summary_tab(
            notebook, "By file",
            (("file", "File", 460), ("total", "Total", 70),
             ("critical", "Critical", 80), ("high", "High", 70),
             ("medium", "Medium", 80), ("low", "Low", 70),
             ("top", "Most broken rule", 200)))

        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Log")
        self.log = tk.Text(log_frame, wrap="none", state="disabled",
                           font=("Consolas", 9))
        lscroll = ttk.Scrollbar(log_frame, orient="vertical",
                                command=self.log.yview)
        self.log.configure(yscrollcommand=lscroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        lscroll.pack(side="left", fill="y")

        status = ttk.Frame(self, padding=(10, 4, 10, 8))
        status.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Choose a folder and press Scan.")
        ttk.Label(status, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(status, length=220, mode="determinate")
        self.progress.pack(side="right")
        self.open_report_button = ttk.Button(status, text="Open report",
                                             command=self.open_report,
                                             state="disabled")
        self.open_report_button.pack(side="right", padx=8)

    def _summary_tab(self, notebook, title, columns):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=title)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns],
                            show="headings", selectmode="browse")
        for name, text, width in columns:
            tree.heading(name, text=text)
            tree.column(name, width=width,
                        anchor="e" if width < 90 and name != "rule" else "w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")
        for sev, colour in SEVERITY_COLOUR.items():
            tree.tag_configure(sev, background=colour)
        return tree

    def _build_menu(self):
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=0)
        file_menu.add_command(label="Scan a folder...\tCtrl+O",
                              command=self.browse_folder)
        file_menu.add_command(label="Scan a single file...",
                              command=self.browse_file)
        file_menu.add_separator()
        file_menu.add_command(label="Save report as...",
                              command=self.save_report_as)
        file_menu.add_command(label="Export the list as CSV...",
                              command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menu.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menu, tearoff=0)
        view_menu.add_command(label="Rule catalogue...",
                              command=self.choose_rules)
        view_menu.add_command(label="Open the scanned folder",
                              command=lambda: open_in_explorer(
                                  self.path_var.get(), select=False))
        menu.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menu, tearoff=0)
        help_menu.add_command(label="Read me",
                              command=lambda: open_document(
                                  os.path.join(HERE, "README.md")))
        help_menu.add_command(label="About", command=self.about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menu)
        self.bind("<Control-o>", lambda _e: self.browse_folder())
        self.bind("<F5>", lambda _e: self.start_scan())

    # ---------------------------------------------------------- settings
    def _load_settings(self):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        self.path_var.set(data.get("path", ""))
        self.language_var.set(data.get("language", "auto"))
        self.header_language_var.set(data.get("header_language", "auto"))
        self.severity_var.set(data.get("min_severity", "Low"))
        self.exclude_var.set(data.get("exclude", self.exclude_var.get()))
        self.exclude_name_var.set(
            data.get("exclude_names", self.exclude_name_var.get()))
        self.quiet_var.set(data.get("skip_noisy", False))
        self.excel_var.set(data.get("write_excel", True))
        self.disabled_rules = [r for r in data.get("disabled_rules", [])
                               if r in RULES]
        for name, var in self.std_vars.items():
            var.set(name in selected_standards(data))

    def _save_settings(self):
        data = {
            "path": self.path_var.get(),
            "language": self.language_var.get(),
            "header_language": self.header_language_var.get(),
            "min_severity": self.severity_var.get(),
            "exclude": self.exclude_var.get(),
            "exclude_names": self.exclude_name_var.get(),
            "skip_noisy": self.quiet_var.get(),
            "write_excel": self.excel_var.get(),
            "disabled_rules": self.disabled_rules,
            "standards": [n for n, v in self.std_vars.items() if v.get()],
            "known_standards": STANDARDS,
        }
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError:
            pass

    def destroy(self):
        self._save_settings()
        super().destroy()

    # ------------------------------------------------------------ actions
    def browse_folder(self):
        start = self.path_var.get() or os.getcwd()
        chosen = filedialog.askdirectory(
            title="Choose the folder to scan",
            initialdir=start if os.path.isdir(start) else os.getcwd())
        if chosen:
            self.path_var.set(os.path.normpath(chosen))

    def browse_file(self):
        chosen = filedialog.askopenfilename(
            title="Choose a source file",
            filetypes=[("C and C++ source", "*.c *.h *.cpp *.hpp *.cc *.hh"),
                       ("All files", "*.*")])
        if chosen:
            self.path_var.set(os.path.normpath(chosen))

    def choose_rules(self):
        window = RuleWindow(self, self.disabled_rules)
        self.wait_window(window)
        if window.result is not None:
            self.disabled_rules = window.result
            enabled = len(RULES) - len(self.disabled_rules)
            self.set_status("%d of %d rules enabled." % (enabled,
                                                         len(RULES)))

    def build_config(self):
        cfg = Config()
        cfg["language"] = self.language_var.get()
        cfg["header_language"] = self.header_language_var.get()
        cfg["min_severity"] = self.severity_var.get()
        cfg["enabled_standards"] = [n for n, v in self.std_vars.items()
                                    if v.get()]
        disabled = list(self.disabled_rules)
        if self.quiet_var.get():
            disabled += [r for r in NOISY_RULES if r not in disabled]
        cfg["disabled_rules"] = disabled
        extra = [p.strip() for p in self.exclude_var.get().split(";")
                 if p.strip()]
        cfg["exclude"] = list(cfg["exclude"]) + extra
        extra_names = [p.strip() for p in
                      self.exclude_name_var.get().split(";")
                      if p.strip()]
        cfg["exclude_names"] = list(cfg["exclude_names"]) + extra_names
        return cfg

    def start_scan(self):
        if self.scanning:
            return
        path = self.path_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning(
                "No folder", "Choose a folder or file to scan first.")
            return
        if not any(v.get() for v in self.std_vars.values()):
            messagebox.showwarning(
                "No standard", "Tick at least one standard to apply.")
            return

        cfg = self.build_config()
        out = None
        if self.excel_var.get():
            base = os.path.basename(os.path.abspath(path.rstrip("\\/")))
            base = os.path.splitext(base)[0] or "scan"
            out = os.path.join(HERE, "Reports",
                               "CodeStandardReport_%s.xlsx" % base)

        self.scanning = True
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.open_report_button.configure(state="disabled")
        self.progress.configure(value=0, maximum=100)
        self.tree.delete(*self.tree.get_children())
        self._log_clear()
        self.set_status("Reading %s" % path)

        worker = threading.Thread(target=self._worker,
                                  args=(path, cfg, out), daemon=True)
        worker.start()
        self.after(80, self._poll)

    def _worker(self, path, cfg, out):
        try:
            def progress(rel, done, total):
                self.queue.put(("progress", done, total, rel))

            result = scan([path], cfg, progress=progress)
            report = None
            if out:
                self.queue.put(("progress", 1, 1, "writing the report"))
                report = write_excel(out, result.violations, result.stats,
                                     cfg)
            self.queue.put(("done", result, report))
        except Exception:
            self.queue.put(("failed", traceback.format_exc()))

    def _poll(self):
        try:
            while True:
                message = self.queue.get_nowait()
                kind = message[0]
                if kind == "progress":
                    _k, done, total, rel = message
                    self.progress.configure(maximum=max(total, 1), value=done)
                    self.set_status("Reading %d of %d  -  %s"
                                    % (done, total, rel))
                elif kind == "done":
                    self._finish(message[1], message[2])
                    return
                elif kind == "failed":
                    self.scanning = False
                    self.scan_button.configure(state="normal", text="Scan")
                    self._log(message[1])
                    self.notebook.select(3)
                    messagebox.showerror(
                        "The scan failed",
                        "See the Log tab for the details.")
                    return
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _finish(self, result, report):
        self.scanning = False
        self.scan_button.configure(state="normal", text="Scan")
        self.result = result
        self.violations = result.violations
        self.report_path = report
        self.progress.configure(value=self.progress["maximum"])

        counts = Counter(v.rule().severity for v in self.violations)
        stats = result.stats
        self.set_status(
            "%d files, %d lines, %d findings   (%s)"
            % (stats["file_count"], stats["line_count"],
               len(self.violations),
               ", ".join("%s %d" % (s, counts.get(s, 0))
                         for s in SEVERITIES)))
        self.refresh_table()
        self.fill_summaries()

        self._log("Scanned %s" % stats["root"])
        self._log("%d files, %d lines, %d active rules"
                  % (stats["file_count"], stats["line_count"],
                     stats["active_rules"]))
        for rel, message in result.errors:
            self._log("problem in %s: %s" % (rel, message))
        if report:
            self._log("Report written to %s" % report)
            self.open_report_button.configure(state="normal")

    # ------------------------------------------------------------- table
    def visible_violations(self):
        text = self.filter_var.get().strip().lower()
        severity = self.view_severity.get()
        out = []
        for v in self.violations:
            rule = v.rule()
            if severity != "All" and rule.severity != severity:
                continue
            if text:
                haystack = " ".join((v.rule_id, rule.title, v.file,
                                     v.function, v.detail, v.code)).lower()
                if text not in haystack:
                    continue
            out.append(v)
        return out

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        shown = self.visible_violations()
        limit = 4000
        for index, v in enumerate(shown[:limit]):
            self.tree.insert("", "end", iid=str(index),
                             values=(v.rule().severity, v.rule_id, v.file,
                                     v.line, v.function, v.detail),
                             tags=(v.rule().severity,))
        self._shown = shown[:limit]
        extra = ""
        if len(shown) > limit:
            extra = "  (first %d shown - filter to narrow it down)" % limit
        self.count_label.configure(
            text="%d of %d findings%s" % (len(self._shown),
                                          len(self.violations), extra))
        self._set_detail("")

    def sort_by(self, column):
        if not self.violations:
            return
        reverse = (self.sort_column == column) and not self.sort_reverse
        self.sort_column, self.sort_reverse = column, reverse
        keys = {
            "severity": lambda v: SEVERITY_ORDER[v.rule().severity],
            "rule": lambda v: v.rule_id,
            "file": lambda v: (v.file.lower(), v.line),
            "line": lambda v: (v.line, v.file.lower()),
            "function": lambda v: v.function.lower(),
            "detail": lambda v: v.detail.lower(),
        }
        self.violations.sort(key=keys[column], reverse=reverse)
        self.refresh_table()

    def fill_summaries(self):
        self.by_rule.delete(*self.by_rule.get_children())
        counts = Counter(v.rule_id for v in self.violations)
        files = {}
        for v in self.violations:
            files.setdefault(v.rule_id, set()).add(v.file)
        for rid, count in sorted(
                counts.items(),
                key=lambda kv: (SEVERITY_ORDER[RULES[kv[0]].severity],
                                -kv[1])):
            rule = RULES[rid]
            self.by_rule.insert("", "end",
                                values=(rid, rule.standard, rule.severity,
                                        rule.title, count,
                                        len(files[rid])),
                                tags=(rule.severity,))

        self.by_file.delete(*self.by_file.get_children())
        per_file = {}
        for v in self.violations:
            per_file.setdefault(v.file, []).append(v)
        rows = []
        for rel, items in per_file.items():
            sev = Counter(v.rule().severity for v in items)
            top = Counter(v.rule_id for v in items).most_common(1)
            rows.append((rel, len(items), sev.get("Critical", 0),
                         sev.get("High", 0), sev.get("Medium", 0),
                         sev.get("Low", 0),
                         "%s (%d)" % (top[0][0], top[0][1]) if top else ""))
        rows.sort(key=lambda r: (-r[2], -r[3], -r[1]))
        for row in rows:
            tag = ("Critical" if row[2] else
                   "High" if row[3] else
                   "Medium" if row[4] else "Low")
            self.by_file.insert("", "end", values=row, tags=(tag,))

    def selected_violation(self):
        selection = self.tree.selection()
        if not selection:
            return None
        index = int(selection[0])
        if index < len(getattr(self, "_shown", [])):
            return self._shown[index]
        return None

    def show_detail(self, _event=None):
        v = self.selected_violation()
        if v is None:
            return
        rule = v.rule()
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", "%s  %s\n" % (v.rule_id, rule.title), "h1")
        self.detail.insert(
            "end", "%s   %s   %s   confidence %s\n\n"
            % (rule.standard, rule.severity, rule.rule_class, v.confidence))
        self.detail.insert("end", "%s line %d, column %d%s\n"
                           % (v.file, v.line, v.column,
                              ("  in %s()" % v.function)
                              if v.function else ""))
        if v.code:
            self.detail.insert("end", v.code + "\n", "code")
        if v.detail:
            self.detail.insert("end", "\nFound: ", "label")
            self.detail.insert("end", v.detail + "\n")
        self.detail.insert("end", "\nWhy it matters: ", "label")
        self.detail.insert("end", rule.why + "\n")
        self.detail.insert("end", "How to fix it: ", "label")
        self.detail.insert("end", rule.fix + "\n")
        self.detail.insert("end", "\n" + v.correction_kind + ":\n", "label")
        if v.suggested_code:
            self.detail.insert("end", v.suggested_code + "\n", "code")
        if v.correction_note:
            self.detail.insert("end", v.correction_note + "\n")
        from cstdscan.misra_cpp_rules import COVERAGE
        if v.rule_id in COVERAGE:
            self.detail.insert("end", "\nImplemented coverage\n", "h2")
            self.detail.insert("end", COVERAGE[v.rule_id] + "\n")
        if v.also:
            self.detail.insert("end", "Also cites: ", "label")
            self.detail.insert("end", ", ".join(v.also) + "\n")
        self.detail.configure(state="disabled")

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if text:
            self.detail.insert("end", text)
        self.detail.configure(state="disabled")

    def _context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.show_detail()
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Open the file", command=self.open_source)
        menu.add_command(label="Show it in Explorer",
                         command=lambda: self.open_source(reveal=True))
        menu.add_command(label="Copy file and line",
                         command=self.copy_location)
        menu.add_separator()
        menu.add_command(label="Hide this rule for now",
                         command=self.hide_selected_rule)
        menu.tk_popup(event.x_root, event.y_root)

    def full_path(self, v):
        root = self.path_var.get()
        if os.path.isfile(root):
            return root
        return os.path.join(root, v.file.replace("/", os.sep))

    def open_source(self, reveal=False):
        v = self.selected_violation()
        if v is None:
            return
        path = self.full_path(v)
        if not os.path.exists(path):
            messagebox.showwarning("Not found", "Cannot find %s" % path)
            return
        if reveal:
            open_in_explorer(path)
        else:
            open_document(path)

    def copy_location(self):
        v = self.selected_violation()
        if v is None:
            return
        self.clipboard_clear()
        self.clipboard_append("%s:%d" % (self.full_path(v), v.line))
        self.set_status("Copied %s:%d" % (v.file, v.line))

    def hide_selected_rule(self):
        v = self.selected_violation()
        if v is None:
            return
        if v.rule_id not in self.disabled_rules:
            self.disabled_rules.append(v.rule_id)
        self.violations = [x for x in self.violations
                           if x.rule_id != v.rule_id]
        self.refresh_table()
        self.fill_summaries()
        self.set_status("%s hidden. It stays off until you switch it back "
                        "on in the rule catalogue." % v.rule_id)

    # ------------------------------------------------------------ reports
    def open_report(self):
        if self.report_path and os.path.exists(self.report_path):
            open_document(self.report_path)
        else:
            messagebox.showinfo("No report",
                                "Run a scan with the Excel report ticked.")

    def save_report_as(self):
        if not self.violations:
            messagebox.showinfo("Nothing to save", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save the report", defaultextension=".xlsx",
            filetypes=[("Excel workbook", "*.xlsx")])
        if not path:
            return
        write_excel(path, self.violations, self.result.stats,
                    self.build_config())
        self.report_path = path
        self.open_report_button.configure(state="normal")
        self.set_status("Report written to %s" % path)

    def export_csv(self):
        if not self.violations:
            messagebox.showinfo("Nothing to save", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            title="Export as CSV", defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if path:
            write_csv(path, self.violations)
            self.set_status("CSV written to %s" % path)

    # --------------------------------------------------------------- misc
    def set_status(self, text):
        self.status_var.set(text)

    def _log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _log_clear(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def about(self):
        messagebox.showinfo(
            "About",
            "C / C++ Coding Standard Scanner %s\n\n"
            "Scans C and C++ source against the house C coding standard, "
            "MISRA C:2025, MISRA C++:2023 and the CWE weakness list, and writes an Excel "
            "report of every violation.\n\n"
            "%d rules in the catalogue." % (__version__, len(RULES)))


def main():
    app = ScannerApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
