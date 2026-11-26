from __future__ import annotations
import os
import threading
from datetime import datetime
from typing import List

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from ..runner import list_subscriptions, run_audit
from ..report.pdf_report import build_pdf

COLORS = {
    "PASS": "#1E8E3E", "FAIL": "#D93025", "UNKNOWN": "#E37400", "NAVY": "#1F3A5F",
    "PASS_BG": "#E6F4EA", "FAIL_BG": "#FCE8E6", "UNKNOWN_BG": "#FEF3E0",
}
ICONS = {"PASS": "✔ PASS", "FAIL": "✖ FAIL", "UNKNOWN": "? UNKNOWN"}


class App(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master = master
        self.master.title("Azure CIS Configuration Review")
        self.master.geometry("1150x760")
        self.master.minsize(980, 640)

        self.findings = []
        self.subscriptions_cache = []
        self._finding_by_iid = {}
        self._busy = False

        self._setup_style()
        self._build_ui()
        self._on_mode_change()

    # ------------------------------------------------------------ styling
    def _setup_style(self):
        s = ttk.Style()
        s.configure("Header.TLabel", background=COLORS["NAVY"], foreground="white", font=("Helvetica", 16, "bold"))
        s.configure("SubHeader.TLabel", background=COLORS["NAVY"], foreground="#DCE6F5", font=("Helvetica", 10))
        s.configure("Title.TLabel", font=("Helvetica", 12, "bold"))
        s.configure("Hint.TLabel", foreground="#555555")
        s.configure("Primary.TButton", font=("Helvetica", 11, "bold"), padding=(14, 8))
        s.configure("Treeview", rowheight=26)
        s.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))
        s.configure("TNotebook.Tab", padding=(16, 7), font=("Helvetica", 10, "bold"))

    # ------------------------------------------------------------ layout
    def _build_ui(self):
        header = tk.Frame(self.master, bg=COLORS["NAVY"])
        header.pack(fill="x")
        ttk.Label(header, text="☁  Azure CIS Configuration Review", style="Header.TLabel").pack(anchor="w", padx=18, pady=(12, 0))
        ttk.Label(header, text="Read-only audit of your Azure tenant and subscriptions  →  PDF report", style="SubHeader.TLabel").pack(anchor="w", padx=18, pady=(0, 12))

        # status bar first so it stays at the bottom
        bar = ttk.Frame(self.master, padding=(12, 6))
        bar.pack(side="bottom", fill="x")
        self.status = tk.StringVar(value="Ready. Start on the Authentication tab.")
        ttk.Label(bar, textvariable=self.status).pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self.progress.pack(side="right")

        self.nb = ttk.Notebook(self.master)
        self.nb.pack(fill="both", expand=True, padx=12, pady=10)

        self.tab_auth = ttk.Frame(self.nb, padding=16)
        self.tab_scope = ttk.Frame(self.nb, padding=16)
        self.tab_run = ttk.Frame(self.nb, padding=16)
        self.tab_results = ttk.Frame(self.nb, padding=16)
        self.nb.add(self.tab_auth, text="1  Authentication")
        self.nb.add(self.tab_scope, text="2  Scope")
        self.nb.add(self.tab_run, text="3  Run")
        self.nb.add(self.tab_results, text="4  Results")

        self._build_auth()
        self._build_scope()
        self._build_run()
        self._build_results()

    def _build_auth(self):
        f = self.tab_auth
        ttk.Label(f, text="How do you want to sign in?", style="Title.TLabel").pack(anchor="w")

        self.auth_mode = tk.StringVar(value="default")
        modes = ttk.Frame(f)
        modes.pack(fill="x", pady=(8, 4))
        ttk.Radiobutton(modes, text="Azure CLI / Managed Identity  (no secret needed)", variable=self.auth_mode,
                        value="default", command=self._on_mode_change).pack(anchor="w")
        ttk.Label(modes, text="Run 'az login --tenant <tenant-id>' in a terminal first, then continue.", style="Hint.TLabel").pack(anchor="w", padx=24, pady=(0, 6))
        ttk.Radiobutton(modes, text="Service principal  (Tenant ID / Client ID / Client Secret)", variable=self.auth_mode,
                        value="service_principal", command=self._on_mode_change).pack(anchor="w")

        box = ttk.LabelFrame(f, text="Service principal details", padding=12)
        box.pack(fill="x", pady=14)
        self.tenant_id = tk.StringVar()
        self.client_id = tk.StringVar()
        self.client_secret = tk.StringVar()
        self.sp_entries = []
        for i, (label, var, secret) in enumerate((("Tenant ID", self.tenant_id, False),
                                                  ("Client ID", self.client_id, False),
                                                  ("Client Secret", self.client_secret, True))):
            ttk.Label(box, text=label, width=14).grid(row=i, column=0, sticky="w", pady=4)
            e = ttk.Entry(box, textvariable=var, width=60, show="•" if secret else "")
            e.grid(row=i, column=1, sticky="w", pady=4)
            self.sp_entries.append(e)
            if secret:
                self.secret_entry = e
        self.show_secret = tk.BooleanVar(value=False)
        self.show_chk = ttk.Checkbutton(box, text="Show secret", variable=self.show_secret, command=self._toggle_secret)
        self.show_chk.grid(row=2, column=2, padx=10)
        self.sp_entries.append(self.show_chk)

        ttk.Label(f, text="Required permissions: Reader + Security Reader on each subscription; Microsoft Graph "
                          "Policy.Read.All for the Conditional Access checks.", style="Hint.TLabel", wraplength=900).pack(anchor="w")
        ttk.Button(f, text="Next: choose subscriptions  →", command=lambda: self.nb.select(self.tab_scope)).pack(anchor="e", pady=(20, 0))

    def _build_scope(self):
        f = self.tab_scope
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="Subscriptions to audit", style="Title.TLabel").pack(side="left")
        self.load_btn = ttk.Button(top, text="↻  Load subscriptions", command=self.load_subscriptions)
        self.load_btn.pack(side="right")

        row = ttk.Frame(f)
        row.pack(fill="both", expand=True, pady=10)
        self.subs_tree = ttk.Treeview(row, columns=("name", "id"), show="headings", selectmode="extended", height=12)
        self.subs_tree.heading("name", text="Subscription name")
        self.subs_tree.heading("id", text="Subscription ID")
        self.subs_tree.column("name", width=380)
        self.subs_tree.column("id", width=330)
        sb = ttk.Scrollbar(row, orient="vertical", command=self.subs_tree.yview)
        self.subs_tree.configure(yscrollcommand=sb.set)
        self.subs_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        btns = ttk.Frame(f)
        btns.pack(fill="x")
        ttk.Button(btns, text="Select all", command=lambda: self.subs_tree.selection_set(self.subs_tree.get_children())).pack(side="left")
        ttk.Button(btns, text="Clear", command=lambda: self.subs_tree.selection_remove(self.subs_tree.get_children())).pack(side="left", padx=6)
        self.sel_label = tk.StringVar(value="0 selected")
        ttk.Label(btns, textvariable=self.sel_label, style="Hint.TLabel").pack(side="left", padx=10)
        self.subs_tree.bind("<<TreeviewSelect>>", lambda e: self.sel_label.set(f"{len(self.subs_tree.selection())} selected"))

        self.min_retention = tk.IntVar(value=90)
        ttk.Label(btns, text="Min Log Analytics retention (days)").pack(side="right", padx=(0, 6))
        ttk.Spinbox(btns, from_=0, to=730, textvariable=self.min_retention, width=6).pack(side="right")
        ttk.Label(f, text="Tip: hold Ctrl or Shift to select several subscriptions.", style="Hint.TLabel").pack(anchor="w", pady=(8, 0))

    def _build_run(self):
        f = self.tab_run
        ttk.Label(f, text="What to check", style="Title.TLabel").pack(anchor="w")
        self.run_entra = tk.BooleanVar(value=True)
        self.run_subs = tk.BooleanVar(value=True)
        ttk.Checkbutton(f, text="Entra ID checks (Conditional Access via Microsoft Graph)", variable=self.run_entra).pack(anchor="w", pady=(8, 2))
        ttk.Checkbutton(f, text="Subscription checks (Defender, logging, storage, Key Vault, network, App Service, SQL)", variable=self.run_subs).pack(anchor="w", pady=2)

        ttk.Separator(f).pack(fill="x", pady=16)
        ttk.Label(f, text="Report", style="Title.TLabel").pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=8)
        self.out_path = tk.StringVar(value=os.path.join(os.getcwd(), f"azure_cis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"))
        ttk.Entry(row, textvariable=self.out_path).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self.browse_out).pack(side="left", padx=6)

        self.run_btn = ttk.Button(f, text="▶  Run audit", style="Primary.TButton", command=self.run_audit_clicked)
        self.run_btn.pack(anchor="w", pady=(18, 6))
        ttk.Label(f, text="The audit only reads configuration; nothing in Azure is changed. "
                          "It can take a few minutes for large subscriptions.", style="Hint.TLabel").pack(anchor="w")

    def _build_results(self):
        f = self.tab_results
        tiles = ttk.Frame(f)
        tiles.pack(fill="x")
        self.tile_vars = {}
        for key, label, color in (("PASS", "Passed", COLORS["PASS"]), ("FAIL", "Failed", COLORS["FAIL"]),
                                  ("UNKNOWN", "Unknown", COLORS["UNKNOWN"]), ("SCORE", "Compliance score", COLORS["NAVY"])):
            box = tk.Frame(tiles, bg=color)
            box.pack(side="left", fill="x", expand=True, padx=(0, 6))
            var = tk.StringVar(value="-")
            self.tile_vars[key] = var
            tk.Label(box, textvariable=var, bg=color, fg="white", font=("Helvetica", 20, "bold")).pack(pady=(8, 0))
            tk.Label(box, text=label, bg=color, fg="white", font=("Helvetica", 9)).pack(pady=(0, 8))

        flt = ttk.Frame(f)
        flt.pack(fill="x", pady=(10, 4))
        ttk.Label(flt, text="Show:").pack(side="left")
        self.filter_var = tk.StringVar(value="All")
        cb = ttk.Combobox(flt, textvariable=self.filter_var, state="readonly", width=12, values=("All", "FAIL", "UNKNOWN", "PASS"))
        cb.pack(side="left", padx=6)
        cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_results())

        cols = ("status", "issue_id", "issue_name", "scope", "fix_type")
        row = ttk.Frame(f)
        row.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(row, columns=cols, show="headings", height=7)
        for c, w, t in (("status", 90, "Status"), ("issue_id", 90, "ID"), ("issue_name", 380, "Control"),
                        ("scope", 340, "Scope"), ("fix_type", 90, "Fix")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        for st in ("PASS", "FAIL", "UNKNOWN"):
            self.tree.tag_configure(st, background=COLORS[st + "_BG"])
        sb = ttk.Scrollbar(row, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

        det = ttk.LabelFrame(f, text="Details (select a row)", padding=6)
        det.pack(fill="x", pady=8)
        self.detail = tk.Text(det, height=5, wrap="word", state="disabled", relief="flat", background="#F7F8FA")
        self.detail.pack(fill="x")

        btns = ttk.Frame(f)
        btns.pack(fill="x")
        ttk.Button(btns, text="Open report folder", command=self.open_pdf_location).pack(side="left")
        ttk.Button(btns, text="Open PDF", command=self.open_pdf).pack(side="left", padx=6)

    # ------------------------------------------------------------ helpers
    def _on_mode_change(self):
        state = "normal" if self.auth_mode.get() == "service_principal" else "disabled"
        for w in self.sp_entries:
            w.configure(state=state)

    def _toggle_secret(self):
        self.secret_entry.configure(show="" if self.show_secret.get() else "•")

    def _set_busy(self, busy: bool, msg: str | None = None):
        self._busy = busy
        if msg:
            self.status.set(msg)
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()
        st = "disabled" if busy else "normal"
        self.run_btn.configure(state=st)
        self.load_btn.configure(state=st)

    def _validate(self) -> bool:
        if self.auth_mode.get() == "service_principal":
            if not (self.tenant_id.get().strip() and self.client_id.get().strip() and self.client_secret.get().strip()):
                messagebox.showerror("Missing fields", "Tenant ID, Client ID and Client Secret are required for service principal sign-in.")
                self.nb.select(self.tab_auth)
                return False
        return True

    def browse_out(self):
        p = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if p:
            self.out_path.set(p)

    def _selected_subscription_ids(self) -> List[str]:
        return [self.subs_tree.item(i, "values")[1] for i in self.subs_tree.selection()]

    # ------------------------------------------------------------ actions
    def load_subscriptions(self):
        if self._busy or not self._validate():
            return
        self._set_busy(True, "Loading subscriptions...")

        def worker():
            try:
                from ..azure.clients import build_credential
                cred = build_credential(self.auth_mode.get(), self.tenant_id.get().strip(),
                                        self.client_id.get().strip(), self.client_secret.get().strip())
                subs = list_subscriptions(cred)
                self.subscriptions_cache = subs

                def ui():
                    self.subs_tree.delete(*self.subs_tree.get_children())
                    for s in subs:
                        self.subs_tree.insert("", tk.END, values=(s["display_name"], s["subscription_id"]))
                    self.subs_tree.selection_set(self.subs_tree.get_children())
                    self._set_busy(False, f"Loaded {len(subs)} subscription(s). All selected - adjust if needed.")
                self.master.after(0, ui)
            except Exception as e:
                err = str(e)
                self.master.after(0, lambda: (self._set_busy(False, "Failed to load subscriptions."),
                                              messagebox.showerror("Could not load subscriptions", err)))
        threading.Thread(target=worker, daemon=True).start()

    def run_audit_clicked(self):
        if self._busy or not self._validate():
            return
        sub_ids = self._selected_subscription_ids()
        if self.run_subs.get() and not sub_ids:
            messagebox.showerror("No subscriptions selected", "Select at least one subscription on the Scope tab (or untick Subscription checks).")
            self.nb.select(self.tab_scope)
            return

        out_pdf = self.out_path.get().strip()
        if not out_pdf.lower().endswith(".pdf"):
            out_pdf += ".pdf"
            self.out_path.set(out_pdf)

        self._set_busy(True, "Running audit... this can take a few minutes.")

        def worker():
            try:
                findings = run_audit(
                    auth_mode=self.auth_mode.get(),
                    tenant_id=self.tenant_id.get().strip(),
                    client_id=self.client_id.get().strip(),
                    client_secret=self.client_secret.get().strip(),
                    subscription_ids=sub_ids,
                    min_log_retention_days=int(self.min_retention.get()),
                    run_entra_checks=self.run_entra.get(),
                    run_subscription_checks=self.run_subs.get(),
                )
                self.findings = findings
                build_pdf(out_pdf, findings, self.tenant_id.get().strip(), sub_ids, tool_version="1.1")

                def ui():
                    self._refresh_results()
                    self._set_busy(False, f"Audit complete: {len(findings)} findings. PDF saved to {out_pdf}")
                    self.nb.select(self.tab_results)
                self.master.after(0, ui)
            except Exception as e:
                err = str(e)
                self.master.after(0, lambda: (self._set_busy(False, "Audit failed."), messagebox.showerror("Audit failed", err)))
        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------ results
    def _refresh_results(self):
        p = sum(1 for f in self.findings if f.status == "PASS")
        fl = sum(1 for f in self.findings if f.status == "FAIL")
        u = sum(1 for f in self.findings if f.status == "UNKNOWN")
        self.tile_vars["PASS"].set(str(p) if self.findings else "-")
        self.tile_vars["FAIL"].set(str(fl) if self.findings else "-")
        self.tile_vars["UNKNOWN"].set(str(u) if self.findings else "-")
        self.tile_vars["SCORE"].set(f"{round(100 * p / (p + fl))}%" if (p + fl) else "n/a")

        self.tree.delete(*self.tree.get_children())
        self._finding_by_iid = {}
        want = self.filter_var.get()
        order = {"FAIL": 0, "UNKNOWN": 1, "PASS": 2}
        for f in sorted(self.findings, key=lambda x: (order.get(x.status, 9), x.issue_id)):
            if want != "All" and f.status != want:
                continue
            iid = self.tree.insert("", tk.END, tags=(f.status,),
                                   values=(ICONS.get(f.status, f.status), f.issue_id, f.issue_name, f.scope, f.fix_type))
            self._finding_by_iid[iid] = f
        self._set_detail("")

    def _set_detail(self, text: str):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, text)
        self.detail.configure(state="disabled")

    def _show_detail(self, _event=None):
        sel = self.tree.selection()
        f = self._finding_by_iid.get(sel[0]) if sel else None
        if not f:
            return
        parts = [f"{f.issue_id} - {f.issue_name}  [{f.status}]", f"CIS ref: {f.cis_ref}"]
        if f.affected:
            parts.append(f"Affected: {f.affected}")
        parts.append(f"Evidence: {f.evidence}")
        parts.append(f"Remediation: {f.remediation}")
        self._set_detail("\n".join(parts))

    def open_pdf(self):
        self._open_path(self.out_path.get().strip())

    def open_pdf_location(self):
        p = self.out_path.get().strip()
        if p:
            self._open_path(os.path.dirname(os.path.abspath(p)))

    def _open_path(self, path: str):
        if not path or not os.path.exists(path):
            messagebox.showinfo("Not found", f"Nothing to open yet:\n{path}")
            return
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore
            elif os.uname().sysname == "Darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception:
            messagebox.showinfo("Location", path)
