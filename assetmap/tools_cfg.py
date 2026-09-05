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
    "nmap_ports": "",             # 自定义端口范围（如 80-443,8080）；留空按 nmap_mode
    "probe_concurrency": 100,
    "katana_depth": 2,
    "headless_render": True,   # Edge/Chrome 无头渲染动态页面
    "render_max": 100,         # 最多渲染的页面数
    "msedge_exe": "",          # 留空自动探测 Edge/Chrome
    # FOFA 优先收集
    "fofa_enabled": True,         # FOFA 优先收集互联网暴露资产
    "fofa_email": "",
    "fofa_key": "",
    "fofa_query_type": "org",     # org / title / domain / custom
    "fofa_max": 2000,             # 最多拉取资产数（控制积分消耗）
    "fofa_verify_scan": False,    # 对 FOFA 资产再跑 Nmap 复核
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
    """按顺序探测 tools\\ 目录（exe 同级 → 已知部署位置），
    用其中实际存在的工具路径覆盖配置。"""
    candidates = [tools_dir(),
                  r"E:\Cybersecurity\tools\01-Information-Gathering\AssetRadar\tools"]
    for b in candidates:
        found_any = False
        for key, rel in _BUNDLED.items():
            p = os.path.join(b, *rel)
            if os.path.isfile(p) or (key == "ehole_cwd" and os.path.isdir(p)):
                cfg[key] = p
                found_any = True
        if found_any and os.path.isdir(b):
            return cfg
    return cfg


def load() -> dict:
    cfg = dict(DEFAULTS)
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
        except Exception:
            pass
    # 旧版本保存的配置可能含 None，回退默认值
    cfg = {k: (DEFAULTS[k] if v is None else v) for k, v in cfg.items()}
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
