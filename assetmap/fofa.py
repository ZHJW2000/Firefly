"""FOFA API 客户端：资产查询、分页、限速、错误分类。

接口: https://fofa.info/api/v1/search/all
认证: email + key；官方限速 1 req/s，按积分计费。
"""

import base64
import re
import time
from typing import Callable, List, Optional, Tuple

import requests

FOFA_SEARCH_URL = "https://fofa.info/api/v1/search/all"
FOFA_INFO_URL = "https://fofa.info/api/v1/info/my"
REQUEST_INTERVAL = 1.1
FIELDS = "host,ip,port,protocol,title,domain,server,lastupdatetime"
FIELD_NAMES = FIELDS.split(",")

ERROR_HINTS = {
    400: "请求参数错误（查询语法不合法）",
    401: "邮箱或 API Key 无效",
    403: "账号无 API 权限或被禁",
    429: "请求过于频繁",
    451: "该查询被禁止",
    820: "查询语法错误",
    821: "API 积分/配额不足，请到 FOFA 后台确认",
    830: "会员等级不足，无法使用该查询或字段",
    840: "查询资产数超出当前会员可查上限",
}


class FofaError(Exception):
    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(message)
        self.code = code


class FofaClient:
    def __init__(self, email: str, key: str, timeout: int = 30):
        self.email = email.strip()
        self.key = key.strip()
        self.timeout = timeout
        self._last = 0.0
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "AssetRadar/2.0 (authorized-security-assessment)"

    def _throttle(self):
        wait = REQUEST_INTERVAL - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    @staticmethod
    def _qbase64(query: str) -> str:
        return base64.b64encode(query.encode("utf-8")).decode("ascii")

    def _raise_for_body(self, body: dict):
        if body.get("error"):
            errmsg = str(body.get("errmsg", "未知错误"))
            code = next((k for k in ERROR_HINTS if str(k) in errmsg), None)
            hint = ERROR_HINTS.get(code, "") if code else ""
            raise FofaError(f"FOFA 返回错误: {errmsg}" + (f"（{hint}）" if hint else ""), code)

    def account_info(self) -> dict:
        """账号信息（免费接口，用于连接测试与配额展示）。"""
        self._throttle()
        resp = self.session.get(FOFA_INFO_URL,
                                params={"email": self.email, "key": self.key},
                                timeout=self.timeout)
        body = resp.json()
        self._raise_for_body(body)
        return body

    def _search_page(self, query: str, page: int, size: int) -> Tuple[int, list]:
        self._throttle()
        resp = self.session.get(
            FOFA_SEARCH_URL,
            params={"email": self.email, "key": self.key,
                    "qbase64": self._qbase64(query), "fields": FIELDS,
                    "size": size, "page": page},
            timeout=self.timeout)
        if resp.status_code != 200:
            hint = ERROR_HINTS.get(resp.status_code, f"HTTP {resp.status_code}")
            raise FofaError(f"FOFA 请求失败: {hint}", resp.status_code)
        body = resp.json()
        self._raise_for_body(body)
        return body.get("size", 0), body.get("results", [])

    def query_all(self, query: str, max_assets: int = 1000,
                  progress: Optional[Callable[[int, int], None]] = None,
                  should_stop: Optional[Callable[[], bool]] = None) -> List[dict]:
        """分页查询全部资产，返回字段字典列表（去重）。"""
        total, rows = self._search_page(query, page=1, size=1000)
        total = min(total, max_assets)
        assets = [dict(zip(FIELD_NAMES, r)) for r in rows]
        if progress:
            progress(len(assets), total)
        page = 2
        while len(assets) < total:
            if should_stop and should_stop():
                break
            size = min(1000, total - len(assets))
            _, more = self._search_page(query, page=page, size=size)
            if not more:
                break
            assets.extend(dict(zip(FIELD_NAMES, r)) for r in more)
            if progress:
                progress(len(assets), total)
            page += 1
        seen, uniq = set(), []
        for a in assets:
            k = (a.get("host"), a.get("port"))
            if k not in seen:
                seen.add(k)
                uniq.append(a)
        return uniq


def build_query(names: List[str], query_type: str) -> str:
    """根据资产名称列表与查询类型构造 FOFA 语法。"""
    names = [n.strip() for n in names if n.strip()]
    if query_type == "custom":
        return " ".join(names)  # 自定义模式：textarea 内容即完整语法
    cond = " || ".join(f'{query_type}="{n}"' for n in names)
    return cond


def assets_to_ports_data(assets: List[dict]) -> List[dict]:
    """把 FOFA 资产转成流水线端口数据结构（按 IP 聚合）。

    非法 IP / 端口记录直接丢弃，避免污染下游 Nmap 与排序。
    """
    import ipaddress
    grouped = {}
    for a in assets:
        ip = str(a.get("ip", "")).strip()
        host = re.sub(r"^[a-z]+://", "", str(a.get("host", "")).strip(), flags=re.I)
        try:
            ip_obj = ipaddress.ip_address(ip)  # 校验 IP 格式（v4/v6 均可）
            port = int(a.get("port", 0))
        except (ValueError, TypeError):
            continue  # 字段错位/畸形记录直接丢弃
        if not ip or not (0 < port <= 65535):
            continue
        entry = grouped.setdefault(ip, {"ip": ip, "ipv6": ip_obj.version == 6,
                                        "hosts": [], "ports": []})
        domain = str(a.get("domain", "")).strip()
        host_name = host.split(":")[0] if host else domain
        for h in (host_name, domain):
            if h and h != ip and h not in entry["hosts"]:
                entry["hosts"].append(h)
        if port not in [p["port"] for p in entry["ports"]]:
            entry["ports"].append({"port": port, "service": "unknown"})
    for e in grouped.values():
        e["ports"].sort(key=lambda x: x["port"])
    def _key(e):
        o = ipaddress.ip_address(e["ip"])
        return (o.version, int(o))
    return sorted(grouped.values(), key=_key)
