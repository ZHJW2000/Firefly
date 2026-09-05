"""阶段1：OneForAll 子域收集（支持批量目标）。

调用 OneForAll（子进程）收集子域，过滤无效与泛解析记录。
多目标时写入 targets 文件一次调用，逐域解析结果 CSV。
OneForAll 不可用时降级：从手工提供的子域列表文件导入。
"""

import csv
import os
import re
import subprocess
import time

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def run(ctx, log, progress, should_stop):
    targets = ctx.targets or [ctx.target]
    manual = ctx.data.get("manual_subdomains")  # GUI 手工导入
    py = ctx.cfg.get("oneforall_python", "")

    subs = []
    if manual:
        log("使用手工导入的子域列表。")
        subs = list(manual)
    elif py and os.path.isfile(py) and os.path.isfile(ctx.cfg["oneforall_py"]):
        # OneForAll 的 --path 需要已存在的绝对路径目录，否则会把路径当输出文件名
        odir = os.path.abspath(os.path.join(ctx.outdir, "oneforall"))
        os.makedirs(odir, exist_ok=True)
        for f in os.listdir(odir):
            if f.endswith(".csv"):
                os.remove(os.path.join(odir, f))

        if len(targets) == 1:
            sel = ["--target", targets[0]]
        else:
            tgt_file = os.path.join(odir, "targets.txt")
            with open(tgt_file, "w", encoding="utf-8") as f:
                f.write("\n".join(targets))
            sel = ["--targets", tgt_file]
            log(f"批量模式：{len(targets)} 个目标一次调用。")

        cmd = [py, ctx.cfg["oneforall_py"], *sel, "--fmt", "csv",
               "--path", odir, "run"]
        budget = min(3600 * max(1, len(targets)), 4 * 3600)
        log("调用 OneForAll（被动收集，未开启爆破），过程日志实时输出…")
        try:
            # 实时流式读取：OneForAll 运行数分钟，静默等待会让界面看起来像卡死
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace",
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                    cwd=os.path.dirname(ctx.cfg["oneforall_py"]))
            t0 = time.time()
            heartbeat = t0
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                # 只转发关键级别的行，避免刷屏
                if any(k in line for k in ("[INFOR]", "[ALERT]", "[ERROR]")):
                    log("  " + line[-160:])
                elif time.time() - heartbeat >= 30:
                    log(f"  OneForAll 运行中… {int(time.time() - t0)}s")
                    heartbeat = time.time()
                if time.time() - t0 > budget:
                    proc.kill()
                    log("OneForAll 超时被终止，使用已产出的结果。")
                    break
            proc.wait(timeout=60)
            log(f"OneForAll 退出码 {proc.returncode}。")
        except Exception as e:
            log(f"OneForAll 调用失败: {e}")

        for f in sorted(os.listdir(odir)):
            if f.endswith(".csv"):
                subs.extend(_parse_oneforall_csv(os.path.join(odir, f), log))
    else:
        log("OneForAll 运行时未就绪且无手工列表，本阶段结果为空。可在界面导入子域列表。")

    subs = _validate(subs, targets, log, manual=bool(manual))
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


def _validate(subs, targets, log, manual=False):
    """去重、过滤非法记录。自动收集时还会剔除超出目标域的记录；
    手工导入的列表视为用户明确授权范围，仅做字符合法性检查。"""
    if isinstance(targets, str):
        targets = [targets]
    targets = [t.lower().strip() for t in targets]
    roots = {".".join(t.split(".")[-2:]) for t in targets}
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
        if not manual and not any(s == t or s == r or s.endswith("." + r)
                                  for t in targets for r in roots):
            dropped += 1
            continue
        out.append(s)
    if dropped:
        log(f"过滤无效/越界记录 {dropped} 条。")
    return out
