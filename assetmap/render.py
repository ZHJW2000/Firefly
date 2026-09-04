"""Edge/Chrome 无头渲染：执行页面 JS 后提取动态加载的脚本与渲染 DOM。

后台无感执行（headless，无窗口、不弹任务栏）。基于 Playwright 驱动本机
已安装的 Edge/Chrome（channel 方式，无需下载浏览器）；捕获渲染后 DOM、
运行时注入的 <script src> 以及网络层加载的 JS（含 XHR/fetch 拉取的脚本）。
"""

import logging

log = logging.getLogger(__name__)

# Playwright 缺失时的提示（不作为致命错误，渲染阶段自动跳过）
_MISSING = ("未检测到 playwright（pip install playwright），动态渲染跳过。"
            "仍将使用 Katana 静态爬取结果。")


def _launch_browser(playwright, cfg):
    """依次尝试 msedge / chrome / 默认 chromium，返回可用的 browser。"""
    channels = []
    explicit = (cfg.get("msedge_exe") or "").strip()
    if explicit:
        channels.append({"executable_path": explicit})
    channels.append({"channel": "msedge"})
    channels.append({"channel": "chrome"})
    channels.append({})
    last_err = None
    for kwargs in channels:
        try:
            return playwright.chromium.launch(headless=True, **kwargs)
        except Exception as e:
            last_err = e
    raise RuntimeError(f"无法启动无头浏览器: {last_err}")


def render_all(urls, outdir, log, progress, should_stop,
               cfg=None, max_pages=100, timeout_ms=15000, concurrency=3):
    """并发渲染一批 URL。

    返回 (渲染DOM列表, 动态发现的JS URL列表):
      doms = [{"url", "dom"}]
      js_urls = 网络层与 DOM 中捕获的 .js URL
    """
    cfg = cfg or {}
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log(_MISSING)
        return [], []

    targets = list(dict.fromkeys(urls))[:max_pages]
    if not targets:
        return [], []
    log(f"无头渲染 {len(targets)} 个页面（并发 {concurrency}，超时 {timeout_ms // 1000}s）…")

    doms, js_urls = [], []
    done = 0
    with sync_playwright() as p:
        browser = _launch_browser(p, cfg)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AssetRadar/2.0",
            ignore_https_errors=True,
        )

        def render_one(url):
            page = context.new_page()
            js = set()
            page.on("response", lambda r: js.add(r.url)
                    if r.url.split("?")[0].lower().endswith(".js") else None)
            try:
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)  # 留给动态注入的脚本
                dom = page.content()
            except Exception as e:
                log(f"渲染 {url} 失败: {type(e).__name__}")
                dom = None
            finally:
                page.close()
            return url, dom, js

        try:
            for url in targets:
                if should_stop():
                    break
                u, dom, js = render_one(url)
                done += 1
                progress(done, len(targets))
                if dom:
                    doms.append({"url": u, "dom": dom})
                js_urls.extend(js)
        finally:
            context.close()
            browser.close()

    js_urls = sorted(set(js_urls))
    log(f"渲染完成：{len(doms)} 页成功，动态发现 JS {len(js_urls)} 个。")
    return doms, js_urls
