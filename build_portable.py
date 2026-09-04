"""组装便携目录版发行包：dist/AssetRadar-portable/

布局:
  AssetRadar.exe
  tools/
    nmap/        (去除 zenmap 等)
    katana/
    ehole/       (含 finger.json/dict)
    oneforall/   (源码，去除 results/巨型字典等)
    python311/   (官方便携 Python 3.11 + OneForAll 依赖)

运行: python build_portable.py
"""

import os
import shutil
import subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(BASE, "dist", "AssetRadar-portable")
TOOLS = {
    "nmap": r"E:\Cybersecurity\tools\01-Information-Gathering\Nmap",
    "katana": r"E:\Cybersecurity\tools\01-Information-Gathering\katana",
    "ehole": r"E:\Cybersecurity\One-Fox\tools\gui_scan\ehole",
    "oneforall": r"E:\Cybersecurity\tools\01-Information-Gathering\OneForAll",
}
# 每个工具目录要排除的内容
EXCLUDE = {
    "nmap": {"zenmap", "Uninstall.exe", "uninstall.exe", "$PLUGINSDIR", "Ndiff", "ncat", "nping"},
    "oneforall": {"results", "docs", "images", "__pycache__", ".github",
                  "data/ip2location.zip", "data/subnames_big.7z", "test.py"},
    "katana": set(), "ehole": set(),
}


def copy_tree(src, dst, excludes):
    os.makedirs(dst, exist_ok=True)
    exc_dirs, exc_files, exc_rels = set(), set(), set()
    for e in excludes:
        if "/" in e:
            exc_rels.add(e.replace("\\", "/"))
        elif "." in os.path.basename(e):
            exc_files.add(os.path.basename(e))
        else:
            exc_dirs.add(e)
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src).replace("\\", "/")
        parts = set(rel.split("/"))
        if parts & exc_dirs or rel in exc_rels:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in exc_dirs
                   and f"{rel}/{d}" not in exc_rels]
        for f in files:
            if f in exc_files or f.endswith((".log", ".pyc")) \
                    or f"{rel}/{f}" in exc_rels:
                continue
            s = os.path.join(root, f)
            d = os.path.join(dst, rel, f) if rel != "." else os.path.join(dst, f)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            try:
                shutil.copy2(s, d)
            except PermissionError:
                if os.path.isfile(d):
                    os.chmod(d, 0o666)
                    os.remove(d)
                shutil.copy2(s, d)


def main():
    exe = os.path.join(BASE, "dist", "AssetRadar.exe")
    assert os.path.isfile(exe), "先运行 pyinstaller 打包 exe（build_exe.bat）"
    os.makedirs(DIST, exist_ok=True)
    shutil.copy2(exe, DIST)
    py = os.path.join(DIST, "tools", "python311", "python.exe")

    for name, src in TOOLS.items():
        dst = os.path.join(DIST, "tools", name)
        already = (name == "oneforall" and os.path.isfile(os.path.join(dst, "oneforall.py")))
        if already:
            continue  # 已就绪则不重铺（保护 python311 运行时）
        print(f"复制 {name}: {src} -> {dst}")
        shutil.rmtree(dst, ignore_errors=True)
        copy_tree(src, dst, EXCLUDE.get(name, set()))

    # 验证内置工具可执行
    checks = [
        [py, "-c", "import fire, exrex; print('py-ok')"],
        [os.path.join(DIST, "tools", "nmap", "nmap.exe"), "--version"],
        [os.path.join(DIST, "tools", "katana", "katana.exe"), "-version"],
    ]
    for cmd in checks:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                           encoding="utf-8", errors="replace")
        assert r.returncode == 0, f"检查失败: {cmd}\n{r.stderr[:300]}"
        print("OK:", cmd[1] if len(cmd) > 2 else cmd[0])

    size = sum(os.path.getsize(os.path.join(r, f))
               for r, _, fs in os.walk(DIST) for f in fs)
    print(f"\n组装完成: {DIST}（约 {size / 1024 / 1024:.0f} MB）")


if __name__ == "__main__":
    main()
