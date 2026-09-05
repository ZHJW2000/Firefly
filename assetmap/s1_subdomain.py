"""阶段1：资产收集 —— FOFA 优先 + OneForAll 补充（串行增强）。

流程：
  1) FOFA 优先：配置了账号即查询互联网暴露资产。
     域名目标走 domain=，资产名称目标走 org=/title=。产出 IP+端口清单。
  2) OneForAll 补充：仅对域名目标做子域收集（名称目标无域可收），
     发现的子域进入阶段2解析；FOFA 未覆盖的新 IP 才会跑 Nmap。
- 手工导入子域列表：OneForAll 不可用时的降级通道。
"""

import csv
import os
import re
import subprocess
import time

from . import fofa as fofa_mod

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def run(ctx, log, progress, should_stop):
    targets = ctx.targets or [ctx.target]
    data = {}

    # ---- 第一步：FOFA 优先收集互联网暴露资产 ----
    fofa_ports = _collect_fofa(ctx, targets, log, progress, should_stop)
    data["fofa_ports"] = fofa_ports
    if should_stop():
        return {"data": {**data, "subdomains": []}}

    # ---- 第二步：OneForAll 补充子域（仅域名目标） ----
    domains = [t for t in targets if DOMAIN_RE.match(t)]
    subs = []
    if domains:
        subs = _collect_oneforall(ctx, domains, log, progress, should_stop)
    else:
        log("输入为资产名称（非域名），跳过 OneForAll 子域收集。")
    data["subdomains"] = subs
    log(f"阶段1完成：FOFA 资产 IP {len(fofa_ports)} 个；子域 {len(subs)} 个。")
    return {"data": data}


def _collect_fofa(ctx, targets, log, progress, should_stop):
    """FOFA 收集：域名走 domain=，名称走 org=/title=。返回端口数据（无则空表）。"""
    email = ctx.cfg.get("fofa_email", "").strip()
    key = ctx.cfg.get("fofa_key", "").strip()
    if not (email and key):
        log("未配置 FOFA 账号，跳过 FOFA 收集（可在界面「FOFA 设置…」配置）。")
        return []
    if not ctx.cfg.get("fofa_enabled", True):
        log("FOFA 收集已关闭，仅用 OneForAll。")
        return []

    domains = [t for t in targets if DOMAIN_RE.match(t)]
    names = [t for t in targets if not DOMAIN_RE.match(t)]
    if ctx.cfg.get("fofa_query_type", "") == "custom":
        query = " ".join(targets)
    else:
        conds = [f'domain="{d}"' for d in domains]
        qtype = ctx.cfg.get("fofa_query_type", "org")  # 名称目标的查询字段
        conds += [f'{qtype}="{n}"' for n in names]
        if not conds:
            return []
        query = " || ".join(conds)

    log(f"FOFA 优先收集: {query}")
    client = fofa_mod.FofaClient(email, key)
    try:
        assets = client.query_all(
            query, max_assets=int(ctx.cfg.get("fofa_max", 2000)),
            progress=lambda d, t: progress(d, max(t, d)),
            should_stop=should_stop)
    except fofa_mod.FofaError as e:
        log(f"FOFA 查询失败（继续 OneForAll 流程）: {e}")
        return []

    ports_data = fofa_mod.assets_to_ports_data(assets)
    domains_found = sorted({a.get("domain", "") for a in assets
                            if a.get("domain") and DOMAIN_RE.match(a["domain"])})
    log(f"FOFA 返回资产 {len(assets)} 条（去重），聚合 {len(ports_data)} 个 IP、"
        f"{len(domains_found)} 个域名。")
    return ports_data


def _collect_oneforall(ctx, domains, log, progress, should_stop):
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

        if len(domains) == 1:
            sel = ["--target", domains[0]]
        else:
            tgt_file = os.path.join(odir, "targets.txt")
            with open(tgt_file, "w", encoding="utf-8") as f:
                f.write("\n".join(domains))
            sel = ["--targets", tgt_file]
            log(f"批量模式：{len(domains)} 个域名一次调用。")

        cmd = [py, ctx.cfg["oneforall_py"], *sel, "--fmt", "csv",
               "--path", odir, "run"]
        budget = min(3600 * max(1, len(domains)), 4 * 3600)
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

    subs = _validate(subs, domains, log, manual=bool(manual))
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
