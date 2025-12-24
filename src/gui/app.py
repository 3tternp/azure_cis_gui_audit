from __future__ import annotations
import os
import threading
from dataclasses import asdict
from datetime import datetime
from typing import List, Dict, Any

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from ..runner import list_subscriptions, run_audit
from ..report.pdf_report import build_pdf

class App(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master = master
        self.master.title("Azure CIS Configuration Review (GUI)")
        self.master.geometry("1100x680")

        self.findings = []
        self.subscriptions_cache = []

        self._build_ui()

    def _build_ui(self):
        nb = ttk.Notebook(self.master)
        nb.pack(fill="both", expand=True)

        self.tab_auth = ttk.Frame(nb)
        self.tab_scope = ttk.Frame(nb)
        self.tab_run = ttk.Frame(nb)
        self.tab_results = ttk.Frame(nb)

        nb.add(self.tab_auth, text="Authentication")
        nb.add(self.tab_scope, text="Scope")
        nb.add(self.tab_run, text="Run")
        nb.add(self.tab_results, text="Results")

        # --- Auth tab
        frm = ttk.Frame(self.tab_auth, padding=12)
        frm.pack(fill="both", expand=True)

        self.auth_mode = tk.StringVar(value="service_principal")
        ttk.Label(frm, text="Auth Mode").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(frm, text="Service Principal (Tenant/Client/Secret)", variable=self.auth_mode, value="service_principal").grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(frm, text="DefaultAzureCredential (Azure CLI / Managed Identity)", variable=self.auth_mode, value="default").grid(row=0, column=2, sticky="w")

        self.tenant_id = tk.StringVar()
        self.client_id = tk.StringVar()
        self.client_secret = tk.StringVar()

        ttk.Label(frm, text="Tenant ID").grid(row=1, column=0, sticky="w", pady=(10,2))
        ttk.Entry(frm, textvariable=self.tenant_id, width=55).grid(row=1, column=1, sticky="w", pady=(10,2), columnspan=2)

        ttk.Label(frm, text="Client ID").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.client_id, width=55).grid(row=2, column=1, sticky="w", pady=2, columnspan=2)

        ttk.Label(frm, text="Client Secret").grid(row=3, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.client_secret, width=55, show="*").grid(row=3, column=1, sticky="w", pady=2, columnspan=2)

        ttk.Separator(frm).grid(row=4, column=0, columnspan=3, sticky="ew", pady=12)

        ttk.Label(frm, text="Tip: If you only have Tenant ID, use 'Load Subscriptions' on the Scope tab to discover subscription IDs.").grid(row=5, column=0, columnspan=3, sticky="w")

        # --- Scope tab
        frm2 = ttk.Frame(self.tab_scope, padding=12)
        frm2.pack(fill="both", expand=True)

        ttk.Button(frm2, text="Load Subscriptions", command=self.load_subscriptions).grid(row=0, column=0, sticky="w")
        self.min_retention = tk.IntVar(value=90)
        ttk.Label(frm2, text="Min Log Analytics retention (days)").grid(row=0, column=1, sticky="e", padx=(20,6))
        ttk.Entry(frm2, textvariable=self.min_retention, width=8).grid(row=0, column=2, sticky="w")

        self.subs_list = tk.Listbox(frm2, selectmode="extended", width=120, height=22)
        self.subs_list.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=10)
        frm2.rowconfigure(1, weight=1)
        frm2.columnconfigure(2, weight=1)

        ttk.Label(frm2, text="Select one or more subscriptions to audit.").grid(row=2, column=0, columnspan=3, sticky="w")

        # --- Run tab
        frm3 = ttk.Frame(self.tab_run, padding=12)
        frm3.pack(fill="both", expand=True)

        self.run_entra = tk.BooleanVar(value=True)
        self.run_subs = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm3, text="Run Entra ID (Graph) checks", variable=self.run_entra).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(frm3, text="Run Subscription checks", variable=self.run_subs).grid(row=1, column=0, sticky="w")

        ttk.Separator(frm3).grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)

        self.out_path = tk.StringVar(value=os.path.join(os.getcwd(), f"azure_cis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"))
        ttk.Label(frm3, text="Output PDF").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm3, textvariable=self.out_path, width=95).grid(row=3, column=1, sticky="w")
        ttk.Button(frm3, text="Browse", command=self.browse_out).grid(row=3, column=2, sticky="w", padx=6)

        ttk.Button(frm3, text="Run Audit", command=self.run_audit_clicked).grid(row=4, column=0, sticky="w", pady=(14,6))

        self.progress = ttk.Progressbar(frm3, mode="indeterminate")
        self.progress.grid(row=5, column=0, columnspan=3, sticky="ew")

        self.status = tk.StringVar(value="Idle.")
        ttk.Label(frm3, textvariable=self.status).grid(row=6, column=0, columnspan=3, sticky="w", pady=6)

        # --- Results tab
        frm4 = ttk.Frame(self.tab_results, padding=12)
        frm4.pack(fill="both", expand=True)

        cols = ("issue_id", "issue_name", "status", "scope", "fix_type")
        self.tree = ttk.Treeview(frm4, columns=cols, show="headings", height=22)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=160 if c != "issue_name" else 420, anchor="w")
        self.tree.pack(fill="both", expand=True)

        ttk.Button(frm4, text="Open PDF Location", command=self.open_pdf_location).pack(anchor="w", pady=8)

    def _validate(self) -> bool:
        if self.auth_mode.get() == "service_principal":
            if not self.tenant_id.get().strip() or not self.client_id.get().strip() or not self.client_secret.get().strip():
                messagebox.showerror("Missing fields", "Tenant ID, Client ID, and Client Secret are required for Service Principal mode.")
                return False
        return True

    def browse_out(self):
        p = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if p:
            self.out_path.set(p)

    def load_subscriptions(self):
        if not self._validate():
            return
        self.status.set("Loading subscriptions...")
        self.progress.start(10)
        def worker():
            try:
                from ..azure.clients import build_credential
                cred = build_credential(self.auth_mode.get(), self.tenant_id.get().strip(), self.client_id.get().strip(), self.client_secret.get().strip())
                subs = list_subscriptions(cred)
                self.subscriptions_cache = subs
                def ui():
                    self.subs_list.delete(0, tk.END)
                    for s in subs:
                        self.subs_list.insert(tk.END, f"{s['display_name']} | {s['subscription_id']}")
                    self.status.set(f"Loaded {len(subs)} subscriptions.")
                self.master.after(0, ui)
            except Exception as e:
                self.master.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.master.after(0, lambda: self.status.set("Failed to load subscriptions."))
            finally:
                self.master.after(0, lambda: self.progress.stop())
        threading.Thread(target=worker, daemon=True).start()

    def _selected_subscription_ids(self) -> List[str]:
        ids = []
        for idx in self.subs_list.curselection():
            line = self.subs_list.get(idx)
            sub_id = line.split("|")[-1].strip()
            ids.append(sub_id)
        return ids

    def run_audit_clicked(self):
        if not self._validate():
            return
        sub_ids = self._selected_subscription_ids()
        if self.run_subs.get() and not sub_ids:
            messagebox.showerror("No subscriptions selected", "Select at least one subscription on the Scope tab (or disable Subscription checks).")
            return

        out_pdf = self.out_path.get().strip()
        if not out_pdf.lower().endswith(".pdf"):
            out_pdf += ".pdf"
            self.out_path.set(out_pdf)

        self.status.set("Running audit...")
        self.progress.start(10)

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
                build_pdf(out_pdf, findings, self.tenant_id.get().strip(), sub_ids, tool_version="1.0")
                def ui():
                    self.tree.delete(*self.tree.get_children())
                    for f in findings:
                        self.tree.insert("", tk.END, values=(f.issue_id, f.issue_name, f.status, f.scope, f.fix_type))
                    self.status.set(f"Audit complete. Findings: {len(findings)}. PDF: {out_pdf}")
                    messagebox.showinfo("Done", f"Report generated:\n{out_pdf}")
                self.master.after(0, ui)
            except Exception as e:
                self.master.after(0, lambda: messagebox.showerror("Audit failed", str(e)))
                self.master.after(0, lambda: self.status.set("Audit failed."))
            finally:
                self.master.after(0, lambda: self.progress.stop())
        threading.Thread(target=worker, daemon=True).start()

    def open_pdf_location(self):
        p = self.out_path.get().strip()
        if not p:
            return
        folder = os.path.dirname(os.path.abspath(p))
        try:
            if os.name == "nt":
                os.startfile(folder)  # type: ignore
            elif os.uname().sysname == "Darwin":
                os.system(f'open "{folder}"')
            else:
                os.system(f'xdg-open "{folder}"')
        except Exception:
            messagebox.showinfo("Folder", folder)
