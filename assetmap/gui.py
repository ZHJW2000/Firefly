"""tkinter GUI：目标输入 → 六阶段进度 → 结果预览 → 导出。"""

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
        ttk.Label(frm, text="目标域名:").grid(row=0, column=0, sticky="ne", **pad)
        self.txt_targets = tk.Text(frm, width=32, height=3, font=("Consolas", 9))
        self.txt_targets.grid(row=0, column=1, sticky="w", **pad)
        self.lbl_tgt_count = ttk.Label(frm, text="0 个目标\n（每行一个，支持批量）", foreground="gray", justify="left")
        self.lbl_tgt_count.grid(row=0, column=1, sticky="e", **pad)
        self.txt_targets.bind("<KeyRelease>", lambda e: self._update_tgt_count())
        ttk.Label(frm, text="Nmap 模式:").grid(row=1, column=0, sticky="e", **pad)
        self.cmb_mode = ttk.Combobox(frm, width=12, state="readonly",
                                     values=["top1000", "全端口"])
        self.cmb_mode.current(0)
        self.cmb_mode.grid(row=1, column=1, sticky="w", **pad)
        ttk.Button(frm, text="导入目标列表", command=self.on_import_targets).grid(row=1, column=2, **pad)
        ttk.Button(frm, text="导入子域列表(替代阶段1)", command=self.on_import).grid(row=2, column=0, columnspan=2, sticky="w", **pad)
        ttk.Button(frm, text="工具路径设置", command=self.on_paths).grid(row=1, column=3, **pad)
        ttk.Label(frm, text="输出目录:").grid(row=2, column=0, sticky="e", **pad)
        self.ent_out = ttk.Entry(frm, width=60)
        self.ent_out.insert(0, os.path.join(os.getcwd(), "output"))
        self.ent_out.grid(row=2, column=1, columnspan=4, sticky="w", **pad)
        ttk.Button(frm, text="浏览…", command=self.on_browse_out).grid(row=2, column=5, **pad)

        self.var_auth = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frm, variable=self.var_auth,
            text="我确认已获得授权，可对上述范围内的资产进行数据安全评估",
        ).grid(row=3, column=0, columnspan=3, sticky="w", **pad)

        self.var_render = tk.BooleanVar(value=bool(self.cfg.get("headless_render", True)))
        ttk.Checkbutton(
            frm, variable=self.var_render,
            text="Edge 无头渲染动态页面（后台执行，捕获运行时注入的 JS）",
        ).grid(row=3, column=3, columnspan=3, sticky="w", **pad)

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

    def _update_tgt_count(self):
        n = len(self._get_targets())
        self.lbl_tgt_count.config(text=f"{n} 个目标\n（每行一个，支持批量）")

    def _get_targets(self):
        """读取目标输入框，去重、去空行。"""
        seen, out = set(), []
        for ln in self.txt_targets.get("1.0", "end").splitlines():
            t = ln.strip().lower().rstrip("/.")
            if t and t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def on_import_targets(self):
        p = filedialog.askopenfilename(filetypes=[("文本/CSV", "*.txt *.csv"), ("所有文件", "*.*")],
                                       title="选择目标列表（每行一个域名）")
        if not p:
            return
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        cur = self.txt_targets.get("1.0", "end").strip()
        merged = (cur + "\n" if cur else "") + "\n".join(lines)
        self.txt_targets.delete("1.0", "end")
        self.txt_targets.insert("1.0", merged)
        self._update_tgt_count()
        self._log(f"已导入 {len(lines)} 个目标。")

    def on_import(self):
        p = filedialog.askopenfilename(filetypes=[("文本/CSV", "*.txt *.csv"), ("所有文件", "*.*")])
        if not p:
            return
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            subs = [ln.strip().lower() for ln in f if ln.strip()]
        self.manual_subdomains = subs
        self._log(f"已导入 {len(subs)} 条子域（将替代阶段1）。")

    def on_browse_out(self):
        cur = self.ent_out.get().strip()
        p = filedialog.askdirectory(initialdir=cur if os.path.isdir(cur) else os.getcwd(),
                                    title="选择输出目录")
        if p:
            self.ent_out.delete(0, "end")
            self.ent_out.insert(0, os.path.normpath(p))

    def on_paths(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("工具路径设置")
        entries = {}
        # (键, 显示名, 是否目录)
        keys = [("oneforall_python", "OneForAll Python 运行时", False),
                ("oneforall_py", "oneforall.py", False),
                ("nmap_exe", "nmap.exe", False),
                ("ehole_exe", "EHole.exe", False),
                ("ehole_cwd", "EHole 工作目录", True),
                ("katana_exe", "katana.exe", False),
                ("msedge_exe", "Edge/Chrome 路径(留空自动探测)", False)]

        def browse(entry, is_dir):
            cur = entry.get().strip()
            if is_dir:
                p = filedialog.askdirectory(initialdir=cur if os.path.isdir(cur) else os.getcwd(),
                                            title="选择文件夹")
            else:
                p = filedialog.askopenfilename(
                    initialdir=os.path.dirname(cur) if os.path.isfile(cur) else os.getcwd(),
                    title="选择文件")
            if p:
                entry.delete(0, "end")
                entry.insert(0, os.path.normpath(p))

        for i, (k, label, is_dir) in enumerate(keys):
            ttk.Label(dlg, text=label, width=28).grid(row=i, column=0, sticky="w", padx=6, pady=3)
            e = ttk.Entry(dlg, width=60)
            e.insert(0, self.cfg.get(k, ""))
            e.grid(row=i, column=1, padx=6, pady=3)
            entries[k] = e
            ttk.Button(dlg, text="浏览…", command=lambda en=e, d=is_dir: browse(en, d))\
                .grid(row=i, column=2, padx=6, pady=3)

        def do_save():
            for k, e in entries.items():
                self.cfg[k] = e.get().strip()
            save(self.cfg)
            self._report_tools()
            dlg.destroy()
        ttk.Button(dlg, text="保存", command=do_save).grid(row=len(keys), column=2, sticky="e", pady=6)

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
        targets = self._get_targets()
        if not targets or any("." not in t for t in targets):
            messagebox.showwarning("提示", "请输入有效目标域名（每行一个）。")
            return
        if len(targets) > 50:
            messagebox.showwarning("提示", f"目标数 {len(targets)} 过多（上限 50），请拆分批次。")
            return
        if len(targets) > 10:
            self._log(f"提示：批量目标 {len(targets)} 个，子域收集将逐域进行，耗时较长。")
        if not self.var_auth.get():
            messagebox.showwarning("需要授权确认", "请先勾选授权确认。仅允许对有权限评估的资产使用本工具。")
            return
        self.cfg["nmap_mode"] = "full" if self.cmb_mode.current() == 1 else "top1000"
        self.cfg["headless_render"] = bool(self.var_render.get())
        save(self.cfg)
        outdir = default_outdir(self.ent_out.get().strip() or os.path.join(os.getcwd(), "output"),
                                targets[0] if len(targets) == 1 else f"batch_{len(targets)}目标")
        ctx = Context(target=targets[0], outdir=outdir, cfg=dict(self.cfg),
                      stop_event=self.stop_event, targets=targets)
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
