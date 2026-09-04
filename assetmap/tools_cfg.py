"""外部工具路径与运行配置。

便携模式：若 exe 同级存在 tools\\ 目录（内置发行包），自动优先使用内置工具；
否则回退到保存的配置 / 默认 E 盘路径。界面"工具路径设置"可覆盖。
"""

import json
import os
import sys

_CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "AssetRadar")
CONFIG_FILE = os.path.join(_CONFIG_DIR, "tools.json")


def app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tools_dir() -> str:
    return os.path.join(app_dir(), "tools")


DEFAULTS = {
    "oneforall_py": r"E:\Cybersecurity\tools\01-Information-Gathering\OneForAll\oneforall.py",
    "nmap_exe": r"E:\Cybersecurity\tools\01-Information-Gathering\Nmap\nmap.exe",
    "ehole_exe": r"E:\Cybersecurity\One-Fox\tools\gui_scan\ehole\EHole_windows_amd64.exe",
    "ehole_cwd": r"E:\Cybersecurity\One-Fox\tools\gui_scan\ehole",
    "katana_exe": r"E:\Cybersecurity\tools\01-Information-Gathering\katana\katana.exe",
    # OneForAll 运行时 python；为空则用系统 python
    "oneforall_python": "",
    "nmap_mode": "top1000",  # top1000 / full
    "probe_concurrency": 100,
    "katana_depth": 2,
}

# 内置发行包中的相对路径
_BUNDLED = {
    "nmap_exe": ("nmap", "nmap.exe"),
    "katana_exe": ("katana", "katana.exe"),
    "ehole_exe": ("ehole", "EHole_windows_amd64.exe"),
    "ehole_cwd": ("ehole",),
    "oneforall_py": ("oneforall", "oneforall.py"),
    "oneforall_python": ("python311", "python.exe"),
}


def apply_bundled(cfg: dict) -> dict:
    """若存在内置 tools\\ 目录，用其中的工具路径覆盖（仅覆盖实际存在的）。"""
    b = tools_dir()
    for key, rel in _BUNDLED.items():
        p = os.path.join(b, *rel)
        if os.path.isfile(p) or (key == "ehole_cwd" and os.path.isdir(p)):
            cfg[key] = p
    return cfg


def load() -> dict:
    cfg = dict(DEFAULTS)
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
        except Exception:
            pass
    return apply_bundled(cfg)


def save(cfg: dict):
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({k: cfg.get(k, DEFAULTS.get(k)) for k in DEFAULTS}, f, ensure_ascii=False, indent=2)


def check_tools(cfg: dict) -> dict:
    """检查各外部工具是否存在，返回 {阶段: (ok, 提示)}。"""
    checks = {}
    for key, stage in (("oneforall_python", "1-子域"), ("nmap_exe", "2-端口"),
                       ("ehole_exe", "3-指纹"), ("katana_exe", "5-爬取")):
        p = cfg.get(key, "")
        # venv python 可能为空串（尚未创建）
        ok = bool(p) and os.path.isfile(p)
        checks[stage] = (ok, p if ok else f"未找到: {p or '(空)'}")
    checks["4-探测"] = (True, "Python 原生")
    checks["6-报表"] = (True, "内置 openpyxl")
    return checks
