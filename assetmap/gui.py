"""tkinter 图形界面：目标输入 → 六阶段进度 → 日志 → 报表导出。

视觉：卡片式分区 + 统一配色（无需第三方依赖）。
"""

import os
import queue
import re
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .pipeline import STAGES, Context, Pipeline, default_outdir
from .tools_cfg import check_tools, load, save

# ---------- 配色 ----------
C_BG = "#eef1f6"        # 窗口背景
C_CARD = "#ffffff"      # 卡片背景
C_PRIMARY = "#2f6fed"   # 主色（开始按钮/进度条）
C_DANGER = "#d9534f"    # 停止
C_OK = "#27ae60"        # 完成
C_WARN = "#e67e22"      # 运行中
C_HEADER = "#1f2d3d"    # 顶栏
C_LOG_BG = "#141a22"    # 日志背景
C_LOG_FG = "#cfd8e3"    # 日志前景

FONT = ("Microsoft YaHei UI", 9)
FONT_B = ("Microsoft YaHei UI", 9, "bold")
FONT_TITLE = ("Microsoft YaHei UI", 15, "bold")
FONT_SUB = ("Microsoft YaHei UI", 8)


def setup_style(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(bg=C_BG)
    root.option_add("*Font", FONT)

    style.configure("Card.TLabelframe", background=C_CARD, borderwidth=0)
    style.configure("Card.TLabelframe.Label", background=C_CARD,
                    font=FONT_B, foreground="#34495e", padding=(2, 4))
    style.configure("Card.TFrame", background=C_CARD)

    style.configure("TLabel", background=C_CARD, font=FONT)
    style.configure("Gray.TLabel", foreground="#7f8c8d", font=FONT_SUB)
    style.configure("TButton", font=FONT, padding=(10, 4))
    style.map("TButton",
              background=[("active", "#e8ecf3")],
              bordercolor=[("!active", "#d0d7e2")])
    style.configure("Primary.TButton", background=C_PRIMARY, foreground="white", font=FONT_B)
    style.map("Primary.TButton",
              background=[("active", "#1f5fd0"), ("disabled", "#9db9e8")],
              foreground=[("disabled", "#eef2f8")])
    style.configure("Danger.TButton", background=C_DANGER, foreground="white", font=FONT_B)
    style.map("Danger.TButton",
              background=[("active", "#b8433f"), ("disabled", "#e0a9a7")])

    style.configure("TEntry", padding=3)
    style.configure("TCombobox", padding=3)
    style.configure("Stage.Horizontal.TProgressbar", troughcolor="#e4e9f2",
                    background=C_PRIMARY, borderwidth=0, thickness=8)
    style.configure("Done.Horizontal.TProgressbar", troughcolor="#e4e9f2",
                    background=C_OK, borderwidth=0, thickness=8)


def card(parent, text):
    """带标题的白色卡片容器。"""
    lf = ttk.LabelFrame(parent, text=" " + text + " ", style="Card.TLabelframe")
    lf.pack(fill="x", padx=10, pady=(8, 4))
    inner = ttk.Frame(lf, style="Card.TFrame")
    inner.pack(fill="both", expand=True, padx=8, pady=6)
    return inner


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.cfg = load()
        self.q: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.ctx = None
        root.title("AssetRadar — 站点资产与敏感信息测绘 v2.0")
        root.geometry("1040x800")
        root.minsize(900, 700)
        setup_style(root)
        self._build()
        self._poll()

    # ---------- UI ----------

    def _build(self):
        pad = {"padx": 5, "pady": 3}

        # 顶栏
        header = tk.Frame(self.root, bg=C_HEADER, height=54)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="🛡  AssetRadar", bg=C_HEADER, fg="white",
                 font=FONT_TITLE).pack(side="left", padx=16)
        tk.Label(header, text="站点资产与敏感信息测绘 · 仅限授权评估使用", bg=C_HEADER,
                 fg="#9fb3c8", font=FONT_SUB).pack(side="left", padx=0, pady=(16, 0))
        tk.Label(header, text="v2.0", bg=C_HEADER, fg="#5f7a94",
                 font=FONT_SUB).pack(side="right", padx=16)

        # 1. 目标与配置
        frm = card(self.root, "1. 目标与配置")
        ttk.Label(frm, text="目标域名:").grid(row=0, column=0, sticky="ne", **pad)
        tgt_wrap = ttk.Frame(frm, style="Card.TFrame")
        tgt_wrap.grid(row=0, column=1, sticky="w", **pad)
        self.txt_targets = tk.Text(tgt_wrap, width=34, height=3, font=("Consolas", 9),
                                   relief="solid", bd=1, highlightthickness=0,
                                   fg="#111111")
        self.txt_targets.pack(side="left")
        self.txt_targets.tag_config("hint", foreground="#9aa5b1")
        self._TGT_HINT = "每行一个域名，如：\nexample.com\nxjtu.edu.cn"
        self.txt_targets.insert("1.0", self._TGT_HINT, "hint")
        self.txt_targets.bind("<FocusIn>", self._tgt_focus_in)
        self.txt_targets.bind("<FocusOut>", self._tgt_focus_out)
        self.lbl_tgt_count = ttk.Label(frm, text="0 个目标\n每行一个 · 支持批量",
                                       style="Gray.TLabel", justify="left")
        self.lbl_tgt_count.grid(row=0, column=2, sticky="w", padx=(8, 2))
        ttk.Button(frm, text="示例", width=5, command=self.on_show_examples)\
            .grid(row=0, column=3, sticky="w", pady=3)
        self.txt_targets.bind("<KeyRelease>", lambda e: self._update_tgt_count())

        ttk.Label(frm, text="收集方式:").grid(row=1, column=0, sticky="e", **pad)
        bar1 = ttk.Frame(frm, style="Card.TFrame")
        bar1.grid(row=1, column=1, columnspan=3, sticky="w", **pad)
        self.var_fofa = tk.BooleanVar(value=bool(self.cfg.get("fofa_enabled", True)))
        tk.Checkbutton(bar1, text="FOFA 优先收集", variable=self.var_fofa, font=FONT,
                       bg=C_CARD, fg="#2c3e50", activebackground=C_CARD).pack(side="left", padx=(0, 4))
        ttk.Button(bar1, text="FOFA 设置…", command=self.on_fofa_settings).pack(side="left", padx=8)
        ttk.Button(bar1, text="导入列表…", command=self.on_import_list).pack(side="left")
        ttk.Button(frm, text="工具路径设置", command=self.on_paths).grid(row=1, column=4, sticky="e", **pad)

        ttk.Label(frm, text="Nmap 模式:").grid(row=2, column=0, sticky="e", **pad)
        bar2 = ttk.Frame(frm, style="Card.TFrame")
        bar2.grid(row=2, column=1, columnspan=3, sticky="w", **pad)
        self.cmb_mode = ttk.Combobox(bar2, width=12, state="readonly",
                                     values=["top1000", "全端口"])
        self.cmb_mode.current(0)
        self.cmb_mode.pack(side="left")
        self.lbl_nmap_hint = ttk.Label(bar2, style="Gray.TLabel",
                                       text="FOFA 已覆盖的 IP 默认不重扫")
        self.lbl_nmap_hint.pack(side="left", padx=10)
        ttk.Label(frm, text="输出目录:").grid(row=3, column=0, sticky="e", **pad)
        self.ent_out = ttk.Entry(frm, width=62)
        self.ent_out.insert(0, os.path.join(os.getcwd(), "output"))
        self.ent_out.grid(row=3, column=1, columnspan=3, sticky="w", **pad)
        ttk.Button(frm, text="浏览…", command=self.on_browse_out).grid(row=3, column=4, sticky="e", **pad)

        self.var_auth = tk.BooleanVar(value=False)
        self._native_check(frm, self.var_auth,
                           "我确认已获得授权，可对上述范围内的资产进行数据安全评估", 4)

        self.var_render = tk.BooleanVar(value=bool(self.cfg.get("headless_render", True)))
        self._native_check(frm, self.var_render,
                           "Edge 无头渲染动态页面（后台执行，捕获运行时注入的 JS）", 5)

        # 2. 执行
        frm_run = card(self.root, "2. 执行")
        self.btn_start = ttk.Button(frm_run, text="▶  开始测绘", style="Primary.TButton",
                                    command=self.on_start)
        self.btn_start.pack(side="left", padx=(2, 6), pady=2)
        self.btn_stop = ttk.Button(frm_run, text="■  停止", style="Danger.TButton",
                                   command=self.on_stop, state="disabled")
        self.btn_stop.pack(side="left", padx=6, pady=2)
        self.btn_open = ttk.Button(frm_run, text="打开输出目录", command=self.on_open_dir)
        self.btn_open.pack(side="left", padx=6, pady=2)

        self.frm_reuse = ttk.Frame(frm_run, style="Card.TFrame")
        self.frm_reuse.pack(side="left", padx=16)
        ttk.Label(self.frm_reuse, text="复用上次结果:", style="Gray.TLabel").pack(side="left")
        self.reuse_vars = []
        for name, _ in STAGES:
            v = tk.BooleanVar(value=False)
            tk.Checkbutton(self.frm_reuse, text=name.split("-")[-1], variable=v,
                           font=FONT, bg=C_CARD, fg="#2c3e50",
                           activebackground=C_CARD).pack(side="left", padx=3)
            self.reuse_vars.append(v)

        # 3. 阶段进度（卡片网格）
        frm_prog = card(self.root, "3. 阶段进度")
        self.stage_status = []
        for i, (name, _) in enumerate(STAGES):
            r, c = divmod(i, 3)
            cell = ttk.Frame(frm_prog, style="Card.TFrame")
            cell.grid(row=r, column=c, sticky="ew", padx=8, pady=4)
            frm_prog.columnconfigure(c, weight=1)
            top = ttk.Frame(cell, style="Card.TFrame")
            top.pack(fill="x")
            self.dot = tk.Label(top, text="●", fg="#b2bec3", bg=C_CARD, font=FONT_SUB)
            self.dot.pack(side="left")
            ttk.Label(top, text=name, font=FONT_B).pack(side="left", padx=4)
            pb = ttk.Progressbar(top, style="Stage.Horizontal.TProgressbar", length=150,
                                 mode="determinate")
            pb.pack(side="right")
            lbl = ttk.Label(cell, text="待机", style="Gray.TLabel")
            lbl.pack(fill="x")
            self.stage_status.append((pb, lbl, self.dot))

        # 4. 日志
        frm_log = card(self.root, "4. 日志")
        self.txt = tk.Text(frm_log, height=10, state="disabled", font=("Consolas", 9),
                           bg=C_LOG_BG, fg=C_LOG_FG, relief="flat", bd=0,
                           insertbackground=C_LOG_FG)
        self.txt.pack(fill="both", expand=True)
        self.txt.tag_config("ok", foreground="#7ee787")
        self.txt.tag_config("err", foreground="#ff7b72")
        self.txt.tag_config("hi", foreground="#79c0ff")

        # 底部状态栏
        status = tk.Frame(self.root, bg=C_HEADER, height=24)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)
        self.lbl_stat = tk.Label(status, text="就绪 · 输出目录可在下方配置中修改",
                                 bg=C_HEADER, fg="#9fb3c8", font=FONT_SUB)
        self.lbl_stat.pack(side="left", padx=10)

    # ---------- 交互 ----------

    def _log(self, msg):
        self.q.put(("log", msg))

    def _append_log(self, msg):
        tag = None
        if re.search(r"失败|异常|错误|error", msg, re.I):
            tag = "err"
        elif re.search(r"完成 ✓|已生成|全部通过|退出码 0。|OK", msg):
            tag = "ok"
        elif msg.startswith("[阶段"):
            tag = "hi"
        self.txt.config(state="normal")
        self.txt.insert("end", msg + "\n", tag)
        if self.txt.index("end-1c") != "1.0":
            self.txt.see("end")
        self.txt.config(state="disabled")

    def _poll(self):
        try:
            while True:
                kind, *args = self.q.get_nowait()
                if kind == "log":
                    self._append_log(args[0])
                elif kind == "stage":
                    idx, text = args
                    pb, lbl, dot = self.stage_status[idx - 1]
                    lbl.config(text=text)
                    if "运行中" in text:
                        dot.config(fg=C_WARN)
                    elif "完成" in text or "已复用" in text:
                        dot.config(fg=C_OK)
                    elif "失败" in text:
                        dot.config(fg="#e74c3c")
                elif kind == "progress":
                    idx, done, total = args
                    pb = self.stage_status[idx - 1][0]
                    pb.config(maximum=total or 1, value=done)
                    if done >= total and total:
                        pb.config(style="Done.Horizontal.TProgressbar")
                elif kind == "stat":
                    self.lbl_stat.config(text=args[0])
                elif kind == "done":
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    self.lbl_stat.config(text=f"评估结束 · {args[0] or '未生成报表'}")
                    if args[0]:
                        messagebox.showinfo("完成", f"测绘完成！\n报表: {args[0]}")
        except queue.Empty:
            pass
        self.root.after(200, self._poll)

    def _native_check(self, parent, var, text, row):
        """系统原生勾选框（Windows 上显示 ✓ 而非 clam 主题的叉）。"""
        tk.Checkbutton(parent, variable=var, text=text, font=FONT,
                       bg=C_CARD, fg="#2c3e50", activebackground=C_CARD,
                       anchor="w", justify="left").grid(row=row, column=0,
                                                        columnspan=5, sticky="w",
                                                        padx=5, pady=3)

    def _tgt_focus_in(self, e=None):
        if self.txt_targets.get("1.0", "end").strip() == self._TGT_HINT.strip():
            self.txt_targets.delete("1.0", "end")
            self.txt_targets.config(fg="#111111")

    def _tgt_focus_out(self, e=None):
        if not self.txt_targets.get("1.0", "end").strip():
            self.txt_targets.insert("1.0", self._TGT_HINT, "hint")
            self.txt_targets.config(fg="#9aa5b1")

    def on_show_examples(self):
        messagebox.showinfo(
            "目标域名填写示例",
            "填写规则：只填主域名，每行一个，不要带 https:// 和路径\n\n"
            "✅ 正确示例：\n"
            "    example.com          （普通网站）\n"
            "    xjtu.edu.cn          （学校/机构主域）\n"
            "    www.xjtu.edu.cn      （具体子域也可以）\n\n"
            "❌ 错误示例：\n"
            "    https://xjtu.edu.cn  （不要带协议头）\n"
            "    xjtu.edu.cn/login    （不要带路径）\n"
            "    192.168.1.1          （内网 IP 无意义）\n\n"
            "批量：多个目标各占一行，或用「导入列表…」从文件载入\n"
            "工具会自动收集每个目标域名的子域后再测绘")

    def _update_tgt_count(self):
        n = len(self._get_targets())
        self.lbl_tgt_count.config(text=f"{n} 个目标\n每行一个 · 支持批量")

    def _get_targets(self):
        """读取目标输入框，去重、去空行；占位提示不算目标。"""
        body = self.txt_targets.get("1.0", "end").strip()
        if not body or body == self._TGT_HINT.strip():
            return []
        seen, out = set(), []
        for ln in self.txt_targets.get("1.0", "end").splitlines():
            t = ln.strip().lower().rstrip("/.")
            if t and t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def on_import_list(self):
        """统一导入入口：选择文件后决定导入为测绘目标还是子域列表。"""
        p = filedialog.askopenfilename(filetypes=[("文本/CSV", "*.txt *.csv"), ("所有文件", "*.*")],
                                       title="选择列表文件（每行一条）")
        if not p:
            return
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        if not lines:
            return
        purpose = messagebox.askquestion(
            "选择导入类型",
            f"共 {len(lines)} 条记录，请选择导入类型：\n\n"
            "【是】测绘目标 —— 每行一个待测绘域名，将执行完整六阶段流水线\n"
            "【否】子域列表 —— 跳过 OneForAll 收集，直接对这些子域执行测绘",
            icon="question")
        if purpose == "yes":
            cur = self.txt_targets.get("1.0", "end").strip()
            merged = (cur + "\n" if cur else "") + "\n".join(lines)
            self.txt_targets.delete("1.0", "end")
            self.txt_targets.insert("1.0", merged)
            self._update_tgt_count()
            self._log(f"已导入 {len(lines)} 个测绘目标。")
        else:
            self.manual_subdomains = [ln.lower() for ln in lines]
            self._log(f"已导入 {len(lines)} 条子域（将替代阶段1收集）。")

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
        dlg.configure(bg=C_CARD)
        entries = {}
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
        ttk.Button(dlg, text="保存", style="Primary.TButton",
                   command=do_save).grid(row=len(keys), column=2, sticky="e", pady=6)

    def on_fofa_settings(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("FOFA 设置")
        dlg.configure(bg=C_CARD)
        ttk.Label(dlg, text="启用 FOFA 优先收集后，输入资产名称走 org=/title= 查询，"
                            "输入域名走 domain= 查询。", style="Gray.TLabel", wraplength=520,
                  justify="left").grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=4)
        entries = {}
        keys = [("fofa_email", "FOFA Email", False),
                ("fofa_key", "FOFA API Key", False),
                ("fofa_query_type", "名称查询字段(org/title)", False),
                ("fofa_max", "最大拉取资产数", False)]
        for i, (k, label, is_dir) in enumerate(keys, start=1):
            ttk.Label(dlg, text=label, width=24).grid(row=i, column=0, sticky="w", padx=6, pady=3)
            e = ttk.Entry(dlg, width=52, show="*" if k == "fofa_key" else "")
            e.insert(0, str(self.cfg.get(k, "")))
            e.grid(row=i, column=1, padx=6, pady=3)
            entries[k] = e
        self.var_verify = tk.BooleanVar(value=bool(self.cfg.get("fofa_verify_scan", False)))
        ttk.Checkbutton(dlg, text="对 FOFA 资产 IP 再执行 Nmap 验证扫描（更准但更慢）",
                        variable=self.var_verify).grid(row=5, column=0, columnspan=3, sticky="w", padx=6)

        def do_test():
            try:
                from .fofa import FofaClient
                info = FofaClient(entries["fofa_email"].get().strip(),
                                  entries["fofa_key"].get().strip()).account_info()
                messagebox.showinfo("FOFA 连接成功",
                                    "账号: {}\n会员等级: {}\n剩余积分: {}\n免费点数: {}".format(
                                        info.get("email", "?"), info.get("vip_level", "?"),
                                        info.get("fofa_point", "?"), info.get("remain_free_point", "?")))
            except Exception as e:
                messagebox.showerror("FOFA 连接失败", str(e))

        def do_save():
            for k, e in entries.items():
                self.cfg[k] = e.get().strip()
            self.cfg["fofa_verify_scan"] = bool(self.var_verify.get())
            self.cfg["fofa_enabled"] = bool(self.var_fofa.get())
            save(self.cfg)
            dlg.destroy()
        ttk.Button(dlg, text="测试连接", command=do_test).grid(row=6, column=1, sticky="w", pady=6)
        ttk.Button(dlg, text="保存", style="Primary.TButton",
                   command=do_save).grid(row=6, column=2, sticky="e", pady=6, padx=6)

    def _report_tools(self):
        checks = check_tools(self.cfg)
        missing = [s for s, (ok, _) in checks.items() if not ok and s != "1-子域"]
        for stage, (ok, hint) in checks.items():
            idx = int(stage.split("-")[0])
            pb, lbl, dot = self.stage_status[idx - 1]
            lbl.config(text=("就绪" if ok else "缺工具"))
            dot.config(fg=("#27ae60" if ok else "#e74c3c"))
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
        self.cfg["fofa_enabled"] = bool(self.var_fofa.get())
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
