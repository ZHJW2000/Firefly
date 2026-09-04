"""tkinter GUI：目标输入 → 六阶段进度 → 结果预览 → 导出。"""

import json
import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .pipeline import STAGES, Context, Pipeline, default_outdir
from .tools_cfg import check_tools, load, save


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.cfg = load()
        self.q: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.ctx = None
        root.title("AssetRadar — 站点资产与敏感信息测绘 v2.0")
        root.geometry("1020x780")
        self._build()
        self._poll()

    # ---------- UI ----------

    def _build(self):
        pad = {"padx": 6, "pady": 3}
        frm = ttk.LabelFrame(self.root, text="1. 目标与配置")
        frm.pack(fill="x", **pad)
        ttk.Label(frm, text="目标域名:").grid(row=0, column=0, sticky="e", **pad)
        self.ent_target = ttk.Entry(frm, width=28)
        self.ent_target.grid(row=0, column=1, **pad)
        ttk.Label(frm, text="Nmap 模式:").grid(row=0, column=2, sticky="e", **pad)
        self.cmb_mode = ttk.Combobox(frm, width=12, state="readonly",
                                     values=["top1000", "全端口"])
        self.cmb_mode.current(0)
        self.cmb_mode.grid(row=0, column=3, **pad)
        ttk.Button(frm, text="导入子域列表(替代阶段1)", command=self.on_import).grid(row=0, column=4, **pad)
        ttk.Button(frm, text="工具路径设置", command=self.on_paths).grid(row=0, column=5, **pad)
        ttk.Label(frm, text="输出目录:").grid(row=1, column=0, sticky="e", **pad)
        self.ent_out = ttk.Entry(frm, width=60)
        self.ent_out.insert(0, os.path.join(os.getcwd(), "output"))
        self.ent_out.grid(row=1, column=1, columnspan=4, sticky="w", **pad)

        self.frm_reuse = ttk.LabelFrame(self.root, text="2. 复用上次结果（断点续跑）")
        self.frm_reuse.pack(fill="x", **pad)
        self.reuse_vars = []
        for i, (name, _) in enumerate(STAGES):
            v = tk.BooleanVar(value=False)
            ttk.Checkbutton(self.frm_reuse, text=name, variable=v).grid(row=0, column=i, **pad)
            self.reuse_vars.append(v)

        frm_run = ttk.LabelFrame(self.root, text="3. 执行")
        frm_run.pack(fill="x", **pad)
        self.btn_start = ttk.Button(frm_run, text="开始测绘", command=self.on_start)
        self.btn_start.pack(side="left", **pad)
        self.btn_stop = ttk.Button(frm_run, text="停止", command=self.on_stop, state="disabled")
        self.btn_stop.pack(side="left", **pad)
        self.btn_open = ttk.Button(frm_run, text="打开输出目录", command=self.on_open_dir)
        self.btn_open.pack(side="left", **pad)

        frm_prog = ttk.LabelFrame(self.root, text="阶段进度")
        frm_prog.pack(fill="x", **pad)
        self.stage_status = []
        for i, (name, _) in enumerate(STAGES):
            ttk.Label(frm_prog, text=name, width=11).grid(row=i // 3 * 2, column=i % 3, sticky="w", **pad)
            pb = ttk.Progressbar(frm_prog, length=200, mode="determinate")
            pb.grid(row=i // 3 * 2, column=i % 3, sticky="e", **pad)
            lbl = ttk.Label(frm_prog, text="待机", foreground="gray", width=22)
            lbl.grid(row=i // 3 * 2 + 1, column=i % 3, sticky="w", **pad)
            self.stage_status.append((pb, lbl))

        frm_log = ttk.LabelFrame(self.root, text="日志")
        frm_log.pack(fill="both", expand=True, **pad)
        self.txt = tk.Text(frm_log, height=12, state="disabled", font=("Consolas", 9))
        self.txt.pack(fill="both", expand=True)

    # ---------- 交互 ----------

    def _log(self, msg):
        self.q.put(("log", msg))

    def _poll(self):
        try:
            while True:
                kind, *args = self.q.get_nowait()
                if kind == "log":
                    self.txt.config(state="normal")
                    self.txt.insert("end", args[0] + "\n")
                    self.txt.see("end")
                    self.txt.config(state="disabled")
                elif kind == "stage":
                    idx, text = args
                    self.stage_status[idx - 1][1].config(text=text)
                elif kind == "progress":
                    idx, done, total = args
                    pb = self.stage_status[idx - 1][0]
                    pb.config(maximum=total or 1, value=done)
                elif kind == "done":
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    if args[0]:
                        messagebox.showinfo("完成", f"测绘完成！\n报表: {args[0]}")
        except queue.Empty:
            pass
        self.root.after(200, self._poll)

    def on_import(self):
        p = filedialog.askopenfilename(filetypes=[("文本/CSV", "*.txt *.csv"), ("所有文件", "*.*")])
        if not p:
            return
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            subs = [ln.strip().lower() for ln in f if ln.strip()]
        self.manual_subdomains = subs
        self._log(f"已导入 {len(subs)} 条子域（将替代阶段1）。")

    def on_paths(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("工具路径设置")
        entries = {}
        keys = [("oneforall_python", "OneForAll Python(venv)"),
                ("oneforall_py", "oneforall.py"),
                ("nmap_exe", "nmap.exe"),
                ("ehole_exe", "EHole.exe"),
                ("ehole_cwd", "EHole 工作目录"),
                ("katana_exe", "katana.exe")]
        for i, (k, label) in enumerate(keys):
            ttk.Label(dlg, text=label, width=20).grid(row=i, column=0, sticky="w", padx=6, pady=3)
            e = ttk.Entry(dlg, width=70)
            e.insert(0, self.cfg.get(k, ""))
            e.grid(row=i, column=1, padx=6, pady=3)
            entries[k] = e

        def do_save():
            for k, e in entries.items():
                self.cfg[k] = e.get().strip()
            save(self.cfg)
            self._report_tools()
            dlg.destroy()
        ttk.Button(dlg, text="保存", command=do_save).grid(row=len(keys), column=1, sticky="e", pady=6)

    def _report_tools(self):
        checks = check_tools(self.cfg)
        missing = [s for s, (ok, _) in checks.items() if not ok and s != "1-子域"]
        for stage, (ok, hint) in checks.items():
            idx = int(stage.split("-")[0])
            self.stage_status[idx - 1][1].config(
                text=("就绪" if ok else "缺工具"), foreground=("gray" if ok else "red"))
        if missing:
            self._log(f"注意：以下阶段缺工具，将跳过或降级: {', '.join(missing)}")

    def on_open_dir(self):
        out = self.ent_out.get().strip() or os.path.join(os.getcwd(), "output")
        os.makedirs(out, exist_ok=True)
        subprocess.Popen(["explorer", os.path.abspath(out)])

    def on_start(self):
        if self.worker and self.worker.is_alive():
            return
        target = self.ent_target.get().strip().lower()
        if not target or "." not in target:
            messagebox.showwarning("提示", "请输入有效目标域名。")
            return
        self.cfg["nmap_mode"] = "full" if self.cmb_mode.current() == 1 else "top1000"
        save(self.cfg)
        outdir = default_outdir(self.ent_out.get().strip() or os.path.join(os.getcwd(), "output"), target)
        ctx = Context(target=target, outdir=outdir, cfg=dict(self.cfg), stop_event=self.stop_event)
        if getattr(self, "manual_subdomains", None):
            ctx.data["manual_subdomains"] = self.manual_subdomains
        reuse = {i for i, v in enumerate(self.reuse_vars, 1) if v.get()}
        self._report_tools()
        self.stop_event.clear()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.worker = threading.Thread(
            target=self._run, args=(ctx, reuse), daemon=True)
        self.worker.start()

    def on_stop(self):
        self.stop_event.set()
        self._log("已请求停止，当前阶段结束后退出。")

    def _run(self, ctx, reuse):
        report = None
        try:
            pipe = Pipeline(ctx, reuse=reuse, log=self._log,
                            progress=lambda i, d, t: self.q.put(("progress", i, d, t)),
                            stage_status=lambda i, s: self.q.put(("stage", i, s)))
            data = pipe.run()
            report = data.get("report_path")
        except Exception as e:
            self._log(f"流水线异常终止: {e}")
        finally:
            self.q.put(("done", report))


def run():
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    root = tk.Tk()
    App(root)
    root.mainloop()
