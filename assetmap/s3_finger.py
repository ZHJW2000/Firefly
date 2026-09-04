"""阶段3：构造候选 URL + EHole 指纹识别。

开放端口 -> 候选 URL（按端口选 http/https，非标端口两种都试）-> 存活预筛 ->
EHole 指纹识别（框架/中间件/版本），解析其 JSON 输出。
"""

import json
import os
import subprocess

from .s4_probe import probe_urls

HTTPS_PORTS = {443, 8443, 8444, 9443, 4430, 44300, 7002, 8843}
WELLKNOWN = {80, 443}


def build_candidate_urls(ports_data) -> list:
    urls = []
    for entry in ports_data:
        ip = entry["ip"]
        for p in entry["ports"]:
            port = p["port"]
            if port in HTTPS_PORTS:
                candidates = [f"https://{ip}:{port}"]
            elif port in WELLKNOWN:
                candidates = [f"http://{ip}:{port}" if port == 80 else f"https://{ip}:{port}"]
            else:
                candidates = [f"http://{ip}:{port}", f"https://{ip}:{port}"]
            urls.extend(candidates)
    return list(dict.fromkeys(urls))


def run(ctx, log, progress, should_stop):
    ports_data = ctx.data.get("ports") or []
    if not ports_data:
        log("无端口数据，跳过。")
        return {"data": {"urls": [], "fingerprints": []}}

    urls = build_candidate_urls(ports_data)
    log(f"构造候选 URL {len(urls)} 个，先做存活预筛…")
    probes = probe_urls(urls, ctx.cfg.get("probe_concurrency", 100))
    live = [p["url"] for p in probes if p["status"] < 500]
    log(f"存活 {len(live)} 个，送 EHole 指纹识别。")
    ctx.data["urls"] = live

    fingerprints = []
    ehole = ctx.cfg.get("ehole_exe", "")
    if live and ehole and os.path.isfile(ehole):
        urls_file = os.path.join(ctx.outdir, "ehole_urls.txt")
        out_file = os.path.join(ctx.outdir, "ehole_result.json")
        with open(urls_file, "w", encoding="utf-8") as f:
            f.write("\n".join(live))
        if os.path.isfile(out_file):
            os.remove(out_file)
        cwd = ctx.cfg.get("ehole_cwd") or os.path.dirname(ehole)
        cmd = [ehole, "finger", "-l", os.path.abspath(urls_file), "-o", os.path.abspath(out_file)]
        log("运行 EHole…")
        try:
            proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                  timeout=1800, encoding="utf-8", errors="replace")
            if proc.returncode != 0:
                log(f"EHole 退出码 {proc.returncode}: {(proc.stderr or proc.stdout or '')[-300:]}")
        except subprocess.TimeoutExpired:
            log("EHole 超时，解析已有输出。")
        fingerprints = _parse_ehole(out_file, log)
        log(f"EHole 识别出指纹 {len(fingerprints)} 条。")
    else:
        log("EHole 不可用或无存活 URL，指纹阶段跳过。")

    # 指纹与探测结果按 url 合并去重
    merged = {}
    for f in fingerprints:
        merged[f["url"]] = f
    return {"data": {"urls": live, "fingerprints": list(merged.values())}}


def _parse_ehole(path, log):
    if not os.path.isfile(path):
        log("EHole 未产出结果文件。")
        return []
    raw = open(path, "r", encoding="utf-8", errors="replace").read().strip()
    items = []
    try:
        data = json.loads(raw)
        items = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in raw.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("["):
                line = line[1:]
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        url = it.get("url") or it.get("Url") or ""
        if not url:
            continue
        out.append({
            "url": url,
            "cms": it.get("cms") or it.get("CMS") or "",
            "server": it.get("server") or "",
            "status": it.get("statuscode") or it.get("status") or "",
            "title": (it.get("title") or "").strip()[:120],
        })
    return out
