"""阶段5：Katana 爬取 API 端点 + 无头渲染动态页面 + JS 硬编码敏感数据扫描。

Katana 深度爬取（默认 -d 2，-js-crawl 解析 JS 内端点）；Edge/Chrome 无头渲染
执行页面 JS，提取运行时注入的 <script src> 与渲染后 DOM 的敏感内容；
对发现的 .js 文件抓取内容按内置正则规则扫描硬编码凭据/连接串/密钥等。
"""

import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

import requests

from . import render

SENSITIVE_RULES = [
    ("硬编码云密钥(AK/SK)", r"(?i)(access[_-]?key|secret[_-]?key|ak|sk)\s*[:=]\s*['\"][A-Za-z0-9/+=_\-]{16,}['\"]"),
    ("云对象存储凭据", r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}"),
    ("数据库连接串", r"(?i)(jdbc:(mysql|oracle|sqlserver|postgresql)|mongodb(\+srv)?://)[^\s'\"<>]{5,}"),
    ("硬编码密码", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    ("JWT Token", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    ("API Key 通用格式", r"\b(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AIza[A-Za-z0-9_-]{30,}|LTAI[A-Za-z0-9]{12,})\b"),
    ("私钥块", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("内网 IP 暴露", r"\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(:\d{2,5})?\b"),
    ("身份证号", r"\b[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"),
]
MAX_JS_BYTES = 512 * 1024


def run(ctx, log, progress, should_stop):
    urls = ctx.data.get("urls") or []
    katana = ctx.cfg.get("katana_exe", "")
    endpoints, sensitive = [], []
    if urls and katana and os.path.isfile(katana):
        depth = str(ctx.cfg.get("katana_depth", 2))
        lst = os.path.join(ctx.outdir, "katana_urls.txt")
        out = os.path.join(ctx.outdir, "katana_endpoints.txt")
        with open(lst, "w", encoding="utf-8") as f:
            f.write("\n".join(urls))
        cmd = [katana, "-list", os.path.abspath(lst), "-d", depth,
               "-jc", "-silent", "-o", os.path.abspath(out)]
        log(f"运行 Katana（深度 {depth}）…")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600,
                                  encoding="utf-8", errors="replace",
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if proc.returncode != 0:
                log(f"Katana 退出码 {proc.returncode}: {(proc.stderr or '')[-300:]}")
        except subprocess.TimeoutExpired:
            log("Katana 超时，解析已有输出。")
        except FileNotFoundError:
            log(f"找不到 katana.exe: {katana}")
        if os.path.isfile(out):
            with open(out, "r", encoding="utf-8", errors="replace") as f:
                endpoints = sorted({ln.strip() for ln in f if ln.strip().startswith("http")})
        log(f"提取端点 {len(endpoints)} 个。")
    else:
        log("Katana 不可用或无存活 URL，端点爬取跳过。")

    js_files = [u for u in endpoints if u.split("?")[0].lower().endswith(".js")]
    log(f"发现 JS 文件 {len(js_files)} 个，扫描硬编码敏感数据…")

    # 无头渲染动态页面：提取运行时注入的 <script>/网络 JS 与渲染后 DOM 的敏感内容
    if ctx.cfg.get("headless_render", True) and urls:
        try:
            doms, dyn_js = render.render_all(
                urls, ctx.outdir, log, progress, should_stop,
                cfg=ctx.cfg, max_pages=ctx.cfg.get("render_max", 100),
            )
            # 渲染后 DOM 也过一遍敏感数据规则
            for item in doms:
                for rule_name, pattern in SENSITIVE_RULES:
                    m = re.search(pattern, item["dom"])
                    if m:
                        ev = item["dom"][max(0, m.start() - 30):m.end() + 60].replace("\n", " ")[:160]
                        sensitive.append({"url": item["url"], "rule": f"渲染DOM-{rule_name}", "evidence": ev})
            # 动态发现的 JS 并入待扫描列表与端点清单
            js_files = sorted(set(js_files) | set(dyn_js))
            endpoints = sorted(set(endpoints) | set(dyn_js))
        except Exception as e:
            log(f"无头渲染异常（已跳过）: {e}")

    sensitive.extend(_scan_js(js_files, log, progress, should_stop))
    log(f"敏感数据命中 {len(sensitive)} 条。")
    return {"data": {"endpoints": endpoints, "sensitive": sensitive}}


def _fetch_js(url):
    try:
        r = requests.get(url, timeout=10, verify=False, stream=True,
                         headers={"User-Agent": "AssetRadar/2.0"})
        content = r.raw.read(MAX_JS_BYTES + 1, decode_content=True)
        if len(content) <= MAX_JS_BYTES:
            return content.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


import urllib3
urllib3.disable_warnings()


def _scan_js(js_files, log, progress, should_stop):
    findings = []
    done = 0
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(_fetch_js, u): u for u in js_files}
        for fut, url in futs.items():
            if should_stop():
                break
            done += 1
            if done % 10 == 0:
                progress(done, len(js_files))
            text = fut.result()
            if not text:
                continue
            for rule_name, pattern in SENSITIVE_RULES:
                m = re.search(pattern, text)
                if m:
                    ev = text[max(0, m.start() - 30):m.end() + 60].replace("\n", " ")[:160]
                    findings.append({"url": url, "rule": rule_name, "evidence": ev})
    progress(len(js_files), len(js_files))
    # 同 URL 同规则去重
    seen, uniq = set(), []
    for f in findings:
        k = (f["url"], f["rule"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq
