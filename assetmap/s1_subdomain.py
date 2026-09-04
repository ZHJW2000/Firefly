"""阶段1：OneForAll 子域收集。

调用 OneForAll（子进程）收集子域，过滤无效与泛解析记录。
OneForAll 不可用时降级：从手工提供的子域列表文件导入。
"""

import csv
import os
import re
import subprocess

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def run(ctx, log, progress, should_stop):
    target = ctx.target
    manual = ctx.data.get("manual_subdomains")  # GUI 手工导入
    py = ctx.cfg.get("oneforall_python", "")

    subs = []
    if manual:
        log("使用手工导入的子域列表。")
        subs = list(manual)
    elif py and os.path.isfile(py) and os.path.isfile(ctx.cfg["oneforall_py"]):
        odir = os.path.join(ctx.outdir, "oneforall")
        os.makedirs(odir, exist_ok=True)
        csv_path = os.path.join(odir, f"{target}.csv")
        if os.path.isfile(csv_path):
            os.remove(csv_path)
        cmd = [py, ctx.cfg["oneforall_py"], "--target", target, "--fmt", "csv",
               "--path", odir, "--show", "True", "run"]
        log("调用 OneForAll（被动收集，未开启爆破）…")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=3600, encoding="utf-8", errors="replace",
                                  cwd=os.path.dirname(ctx.cfg["oneforall_py"]))
            log(f"OneForAll 退出码 {proc.returncode}。")
            if proc.returncode != 0:
                log("OneForAll stderr（末尾 500 字符）: " + (proc.stderr or "")[-500:])
        except subprocess.TimeoutExpired:
            log("OneForAll 超时（1 小时），使用已产出的结果。")
        except Exception as e:
            log(f"OneForAll 调用失败: {e}")

        if os.path.isfile(csv_path):
            subs = _parse_oneforall_csv(csv_path, log)
        else:
            # OneForAll 有时命名带通配或时间戳，兜底找最新 csv
            cand = [os.path.join(odir, f) for f in os.listdir(odir) if f.endswith(".csv")]
            if cand:
                newest = max(cand, key=os.path.getmtime)
                subs = _parse_oneforall_csv(newest, log)
    else:
        log("OneForAll venv 未就绪且无手工列表，本阶段结果为空。可先运行 setup_oneforall.py，或在界面导入子域列表。")

    subs = _validate(subs, target, log, manual=bool(manual))
    log(f"有效子域 {len(subs)} 个。")
    return {"data": {"subdomains": subs}}


def _parse_oneforall_csv(path, log):
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                rows.append(r)
    except Exception as e:
        log(f"结果 CSV 解析失败: {e}")
        return []
    sub_col = next((k for k in rows[0] if k and k.lower() == "subdomain"), None) if rows else None
    if not sub_col:
        return []
    def keep(r):
        # OneForAll 存在多个记录行（不同 url/来源）；alive 或 resolve 任一为真即有效
        keys = [k.lower() for k in r.keys() if k]
        if "alive" not in keys and "resolve" not in keys:
            return True
        for key in ("alive", "resolve"):
            for k, v in r.items():
                if k and k.lower() == key and str(v).strip().lower() in ("true", "1", "yes"):
                    return True
        return False
    return [r[sub_col].strip().lower() for r in rows if keep(r)]


def _validate(subs, target, log, manual=False):
    """去重、过滤非法记录。自动收集时还会剔除超出目标域的记录；
    手工导入的列表视为用户明确授权范围，仅做字符合法性检查。"""
    target = target.lower().strip()
    root = ".".join(target.split(".")[-2:])  # 允许 xxx.edu.cn 下的子域
    seen, out, dropped = set(), [], 0
    for s in subs:
        s = s.strip().lower().strip(".$/").replace("http://", "").replace("https://", "").strip("/")
        if not s or s in seen:
            continue
        seen.add(s)
        if not re.match(r"^[a-z0-9._-]+$", s) or len(s) > 253:
            dropped += 1
            continue
        if not manual and not DOMAIN_RE.match(s) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
            dropped += 1
            continue
        if not manual and not (s == target or s == root or s.endswith("." + root)):
            dropped += 1
            continue
        out.append(s)
    if dropped:
        log(f"过滤无效/越界记录 {dropped} 条。")
    return out
