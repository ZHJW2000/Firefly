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
    # FOFA 优先：阶段1已产出暴露资产端口，只对 OneForAll 新发现的 IP 补扫
    fofa_ports = ctx.data.get("fofa_ports") or []
    fofa_ips = {e["ip"] for e in fofa_ports}

    subs = ctx.data.get("subdomains") or []
    resolved = {}
    if subs:
        log(f"解析 {len(subs)} 个子域名…")
        resolved = _resolve_all(subs, progress)
    dns = resolved
    all_ips = {ip for ip in resolved.values() if ip} | fofa_ips
    def _ip_key(o):
        a = ipaddress.ip_address(o)
        return (a.version, int(a))
    ips = sorted(all_ips, key=_ip_key)

    verify = ctx.cfg.get("fofa_verify_scan", False)
    new_ips = [ip for ip in ips if ip not in fofa_ips]
    if not verify and fofa_ports and not new_ips:
        log(f"FOFA 已覆盖全部 {len(fofa_ips)} 个 IP，跳过端口扫描。")
        progress(1, 1)
        return {"data": {"dns": dns, "ips": ips, "ports": fofa_ports}}

    if fofa_ports and not verify:
        log(f"FOFA 已覆盖 {len(fofa_ips)} 个 IP，对 OneForAll 新发现的 "
            f"{len(new_ips)} 个 IP 补扫 Nmap…")
        scan_ips = new_ips
    else:
        scan_ips = ips
        if verify and fofa_ports:
            log("验证扫描已开启：对全部 IP 执行 Nmap 复核（覆盖 FOFA 端口）…")
    if not scan_ips:
        log("无可扫描 IP，跳过。")
        return {"data": {"dns": dns, "ips": ips, "ports": fofa_ports}}
    # Nmap -sT 为 IPv4 扫描；IPv6 资产复用 FOFA 端口数据，不参与 Nmap
    v4_scan = [ip for ip in scan_ips if ":" not in ip]
    v6_kept = len(scan_ips) - len(v4_scan)
    ips_sorted_scan = sorted(v4_scan, key=lambda o: ipaddress.ip_address(o))
    if v6_kept:
        log(f"其中 {v6_kept} 个 IPv6 资产复用 FOFA 端口数据，不参与 Nmap。")
    log(f"待扫描 {len(ips_sorted_scan)} 个 IPv4 地址。")

    targets_file = os.path.join(ctx.outdir, "nmap_targets.txt")
    with open(targets_file, "w") as f:
        f.write("\n".join(ips_sorted_scan))

    mode = ctx.cfg.get("nmap_mode", "top1000")
    gnmap = os.path.join(ctx.outdir, "nmap_result.gnmap")
    cmd = [ctx.cfg["nmap_exe"], "-sT", "-Pn", "-T4", "--open",
           "--host-timeout", "600s", "--max-retries", "2",
           "-iL", targets_file, "-oG", gnmap]
    ports_spec = (ctx.cfg.get("nmap_ports") or "").strip()
    if mode == "full":
        cmd = cmd[:4] + ["-p1-65535", "--min-rate", "2000"] + cmd[4:]
        log("全端口模式（1-65535，--min-rate 2000），大网段可能耗时较长…")
    elif ports_spec:
        cmd = cmd[:4] + [f"-p{ports_spec}"] + cmd[4:]
        log(f"自定义端口范围: {ports_spec}")
    else:
        log("top1000 模式。")
    log("运行 Nmap…")
    # 输出直接落盘：避免工具异常刷屏时把内存撑爆；进程超时后强杀
    timeout = 6 * 3600 if mode == "full" else 1800
    out_f = open(gnmap + ".console", "w", encoding="utf-8", errors="replace")
    try:
        proc = subprocess.Popen(cmd, stdout=out_f, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
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
    if fofa_ports and not verify:
        # 补扫模式：FOFA 资产端口 + 新发现 IP 的 Nmap 结果合并
        nmap_map = {e["ip"]: e for e in ports}
        ports = fofa_ports + [e for ip, e in nmap_map.items() if ip not in fofa_ips]
        ports.sort(key=lambda x: _ip_key(x["ip"]))
    # 验证扫描模式：Nmap 结果更完整（含服务名），直接覆盖 FOFA 端口
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
