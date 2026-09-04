"""本机集成联调：mock HTTP 服务 + 真实 Nmap/EHole/Katana 调用链。

只扫描 127.0.0.1，不触外网目标。
运行: python tests/integration_local.py
"""

import http.server
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from assetmap import s3_finger, s5_crawl, s2_portscan
from assetmap.s4_probe import probe_urls

INDEX = "<html><head><title>IntegTest OA</title></head><body><a href='/static/app.js'>app</a></body></html>"
APP_JS = "var cfg={password:'IntegTest@123',api:'/api/v1/info'};"


class Handler(http.server.BaseHTTPRequestHandler):
    PAGES = {"/": INDEX, "/static/app.js": APP_JS}

    def do_GET(self):
        body = self.PAGES.get(self.path)
        if body is None:
            self.send_response(404); self.end_headers(); return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def pick_port():
    for p in (8080, 8000, 8888, 8081):
        try:
            s = socket.socket()
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            continue
    raise RuntimeError("no free port")


def main():
    port = pick_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[1] mock 服务已起: http://127.0.0.1:{port}")

    outdir = os.path.abspath("output/_integration")
    os.makedirs(outdir, exist_ok=True)

    # 阶段2：真实 Nmap 扫 127.0.0.1
    gnmap = os.path.join(outdir, "nmap.gnmap")
    nmap = s3_and_nmap_path = r"E:\Cybersecurity\tools\01-Information-Gathering\Nmap\nmap.exe"
    import subprocess
    print("[2] 运行 Nmap (top1000, 127.0.0.1)…")
    subprocess.run([nmap, "-sT", "-Pn", "-T4", "--open", "-p", "1-10000",
                    "-iL", "-", "-oG", gnmap],
                   input=f"127.0.0.1\n", text=True, capture_output=True, timeout=600)
    ports_data = s2_portscan._parse_gnmap(gnmap, {"localhost": "127.0.0.1"})
    entry = next((e for e in ports_data if e["ip"] == "127.0.0.1"), None)
    assert entry and port in [p["port"] for p in entry["ports"]], \
        f"Nmap 未发现 mock 端口 {port}: {entry}"
    print(f"[2] Nmap 发现 {len(entry['ports'])} 个端口，含 mock 端口 {port} ✓")

    # 阶段3+4：候选URL -> 存活探测 -> EHole
    urls = s3_finger.build_candidate_urls([entry])
    print(f"[3] 候选 URL {len(urls)} 个，存活探测…")
    probes = probe_urls(urls, concurrency=60, timeout=3)
    live = [p["url"] for p in probes if p["status"] < 500]
    assert f"http://127.0.0.1:{port}" in live, live
    print(f"[3] 存活 {len(live)} 个 ✓")

    cfg = {"ehole_exe": r"E:\Cybersecurity\One-Fox\tools\gui_scan\ehole\EHole_windows_amd64.exe",
           "ehole_cwd": r"E:\Cybersecurity\One-Fox\tools\gui_scan\ehole"}
    print("[4] 运行 EHole…")
    import json, subprocess as sp
    urls_file, out_file = os.path.join(outdir, "u.txt"), os.path.join(outdir, "e.json")
    open(urls_file, "w").write("\n".join(live))
    r = sp.run([cfg["ehole_exe"], "finger", "-l", os.path.abspath(urls_file), "-o", os.path.abspath(out_file)],
               cwd=cfg["ehole_cwd"], capture_output=True, text=True, timeout=600,
               encoding="utf-8", errors="replace")
    fps = s3_finger._parse_ehole(out_file, print)
    print(f"[4] EHole 输出 {len(fps)} 条: {fps[:2]}")

    # 阶段5：Katana
    print("[5] 运行 Katana…")
    katana = r"E:\Cybersecurity\tools\01-Information-Gathering\katana\katana.exe"
    lst, ep = os.path.join(outdir, "k.txt"), os.path.join(outdir, "k_out.txt")
    open(lst, "w").write(f"http://127.0.0.1:{port}\n")
    r = sp.run([katana, "-list", os.path.abspath(lst), "-d", "1", "-silent", "-o", os.path.abspath(ep)],
               capture_output=True, text=True, timeout=600, encoding="utf-8", errors="replace")
    endpoints = [ln.strip() for ln in open(ep, encoding="utf-8", errors="replace") if ln.strip()] if os.path.isfile(ep) else []
    print(f"[5] Katana 端点 {len(endpoints)} 个: {endpoints[:3]}")

    srv.shutdown()
    print("\n=== 本机集成联调通过 ===")


if __name__ == "__main__":
    main()
