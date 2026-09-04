"""阶段4：原生 Web 探测（asyncio + aiohttp）。

批量请求 URL，记录状态码、Title、Server/X-Powered-By 等响应头与响应长度。
供阶段3做存活预筛，也是流水线的独立探测阶段。
"""

import asyncio
import re
import ssl
from typing import Callable, List, Optional

import aiohttp

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
INTERESTING_HEADERS = ["Server", "X-Powered-By", "Content-Type", "Location", "Via"]


async def _probe_one(session: aiohttp.ClientSession, sem: asyncio.Semaphore,
                     url: str, timeout: int) -> Optional[dict]:
    async with sem:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=True, ssl=False) as resp:
                body = await resp.content.read(64 * 1024)
                text = body.decode(resp.get_encoding() or "utf-8", errors="replace") if body else ""
                m = TITLE_RE.search(text)
                headers = {h: resp.headers.get(h, "") for h in INTERESTING_HEADERS}
                headers = {k: v for k, v in headers.items() if v}
                return {
                    "url": str(resp.url),
                    "status": resp.status,
                    "title": re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else "",
                    "length": int(resp.headers.get("Content-Length", 0) or len(body)),
                    "headers": headers,
                }
        except Exception:
            return None


async def _probe_all(urls: List[str], concurrency: int, timeout: int,
                     progress: Optional[Callable[[int, int], None]]) -> List[dict]:
    sem = asyncio.Semaphore(concurrency)
    conn = aiohttp.TCPConnector(limit=concurrency, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=conn, headers={"User-Agent": "AssetMapper/2.0"}) as session:
        tasks = [_probe_one(session, sem, u, timeout) for u in urls]
        results, done = [], 0
        for fut in asyncio.as_completed(tasks):
            r = await fut
            if r:
                results.append(r)
            done += 1
            if progress and done % 20 == 0:
                progress(done, len(urls))
    if progress:
        progress(len(urls), len(urls))
    return results


def probe_urls(urls: List[str], concurrency: int = 100, timeout: int = 10,
               progress: Optional[Callable[[int, int], None]] = None) -> List[dict]:
    results = asyncio.run(_probe_all(urls, concurrency, timeout, progress))
    # 去重（重定向后同 URL）
    seen, uniq = set(), []
    for r in sorted(results, key=lambda x: x["url"]):
        if r["url"] not in seen:
            seen.add(r["url"])
            uniq.append(r)
    return uniq


def alive_urls(urls: List[str], concurrency: int = 100, timeout: int = 10) -> List[str]:
    return [r["url"] for r in probe_urls(urls, concurrency, timeout)]


def run(ctx, log, progress, should_stop):
    urls = ctx.data.get("urls") or []
    if not urls:
        log("无候选 URL，跳过。")
        return {"data": {"probes": []}}
    log(f"探测 {len(urls)} 个 URL（并发 {ctx.cfg.get('probe_concurrency', 100)}）…")
    probes = probe_urls(urls, ctx.cfg.get("probe_concurrency", 100),
                        progress=lambda d, t: progress(d, t))
    alive = [p for p in probes if p["status"] < 500]
    log(f"存活 {len(alive)} / {len(urls)}。")
    return {"data": {"probes": probes}}
