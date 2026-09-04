"""阶段2：子域名解析 + Nmap 端口扫描。

默认 top1000 端口（-T4 --open），可选全端口（-p1-65535 --min-rate 2000）。
解析 grepable 输出，得到 IP -> 开放端口(含服务名)。
"""

import ipaddress
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

_GNMAP_PORT = re.compile(r"(\d+)/open/tcp//([^/]*)/")


def run(ctx, log, progress, should_stop):
    subs = ctx.data.get("subdomains") or []
    if not subs:
        log("无子域数据，跳过。")
        return {"data": {"dns": {}, "ports": [], "ips": []}}

    log(f"解析 {len(subs)} 个子域名…")
    dns = _resolve_all(subs, progress)
    ips = sorted({ip for ip in dns.values() if ip}, key=ipaddress.ip_address)
    log(f"解析成功 {len(ips)} 个 IP（去重后）。")
    if not ips:
        return {"data": {"dns": {}, "ports": [], "ips": []}}

    targets_file = os.path.join(ctx.outdir, "nmap_targets.txt")
    with open(targets_file, "w") as f:
        f.write("\n".join(ips))

    mode = ctx.cfg.get("nmap_mode", "top1000")
    gnmap = os.path.join(ctx.outdir, "nmap_result.gnmap")
    cmd = [ctx.cfg["nmap_exe"], "-sT", "-Pn", "-T4", "--open",
           "--host-timeout", "600s", "--max-retries", "2",
           "-iL", targets_file, "-oG", gnmap]
    if mode == "full":
        cmd = cmd[:4] + ["-p1-65535", "--min-rate", "2000"] + cmd[4:]
        log("全端口模式（1-65535，--min-rate 2000），大网段可能耗时较长…")
    else:
        log("top1000 模式。")
    log("运行 Nmap…")
    # 输出直接落盘：避免工具异常刷屏时把内存撑爆；进程超时后强杀
    timeout = 6 * 3600 if mode == "full" else 1800
    out_f = open(gnmap + ".console", "w", encoding="utf-8", errors="replace")
    try:
        proc = subprocess.Popen(cmd, stdout=out_f, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL)
        try:
            proc.wait(timeout=timeout)
            if proc.returncode != 0:
                log(f"Nmap 退出码 {proc.returncode}（详见 nmap_result.gnmap.console）")
        except subprocess.TimeoutExpired:
            proc.kill()
            log("Nmap 超时被终止，解析已有输出。")
    except FileNotFoundError:
        raise RuntimeError(f"找不到 nmap.exe: {ctx.cfg['nmap_exe']}，请在界面修正路径")
    finally:
        out_f.close()

    ports = _parse_gnmap(gnmap, dns)
    total = sum(len(p["ports"]) for p in ports)
    log(f"扫描完成：{len(ports)} 个 IP，共 {total} 个开放端口。")
    return {"data": {"dns": dns, "ips": ips, "ports": ports}}


def _resolve_one(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _resolve_all(subs, progress):
    dns = {}
    done = 0
    with ThreadPoolExecutor(max_workers=50) as pool:
        futs = {pool.submit(_resolve_one, s): s for s in subs}
        for fut, host in futs.items():
            ip = fut.result()
            dns[host] = ip
            done += 1
            if done % 20 == 0:
                progress(done, len(subs))
    progress(len(subs), len(subs))
    return dns


def _parse_gnmap(path, dns):
    """Host: 1.2.3.4 ()\tPorts: 80/open/tcp//http///, 443/open/..."""
    ip2hosts = {}
    for host, ip in dns.items():
        if ip:
            ip2hosts.setdefault(ip, []).append(host)
    result = []
    if not os.path.isfile(path):
        return result
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("Host:"):
                continue
            m = re.match(r"Host:\s*([\d.]+)", line)
            if not m:
                continue
            ip = m.group(1)
            open_ports = [{"port": int(p), "service": svc or "unknown"}
                          for p, svc in _GNMAP_PORT.findall(line)]
            if open_ports:
                open_ports.sort(key=lambda x: x["port"])
                result.append({"ip": ip, "hosts": ip2hosts.get(ip, []), "ports": open_ports})
    return result
