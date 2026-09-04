"""风险评分：端口 + 指纹 + 敏感数据 + 暴露面，0-100 分。"""

HIGH_RISK_PORTS = {
    22: ("SSH 远程管理暴露", 10), 3389: ("RDP 远程桌面暴露", 12),
    3306: ("MySQL 数据库暴露", 18), 1433: ("SQLServer 数据库暴露", 18),
    1521: ("Oracle 数据库暴露", 18), 5432: ("PostgreSQL 数据库暴露", 18),
    6379: ("Redis 未鉴权风险", 20), 27017: ("MongoDB 暴露", 18),
    11211: ("Memcached 暴露", 15), 5900: ("VNC 远程控制", 20),
    23: ("Telnet 明文远程", 20), 21: ("FTP", 8), 135: ("RPC/DCOM", 8),
    445: ("SMB 文件共享", 10), 7001: ("WebLogic", 15), 9200: ("Elasticsearch", 12),
}
RISKY_FINGERPRINTS = {
    "shiro": 25, "struts": 25, "weblogic": 25, "thinkphp": 20, "fastjson": 25,
    "jboss": 20, "tomcat": 10, "jenkins": 25, "nacos": 20, "spring boot": 15,
    "druid": 15, "activemq": 18, "solr": 15, "elasticsearch": 12, "yonyou": 18,
    "用友": 18, "泛微": 18, "weaver": 18, "致远": 18, "seeyon": 18, "通达": 15,
    "蓝凌": 15, "kingdee": 12, "金蝶": 12, "禅道": 12, "gitlab": 15, "nexus": 15,
}
SENSITIVE_WEIGHT = 12   # 每条敏感数据命中
NONSTD_WEB_BONUS = 5    # 非标端口 Web 服务


def score_service(port: int, service: str, fingerprint: str, sensitive_hits: int,
                  is_web: bool) -> tuple:
    """返回 (0-100 分, [命中原因])。"""
    score, reasons = 0, []
    if port in HIGH_RISK_PORTS:
        name, w = HIGH_RISK_PORTS[port]
        score += w
        reasons.append(name)
    fp = (fingerprint or "").lower()
    fp_score = sum(w for key, w in RISKY_FINGERPRINTS.items() if key in fp)
    if fp_score:
        score += min(fp_score, 40)  # 组件分合计封顶 40，防止多指纹叠加虚高
        for key, w in RISKY_FINGERPRINTS.items():
            if key in fp:
                reasons.append(f"高危组件: {key}")
    if sensitive_hits:
        score += min(sensitive_hits * SENSITIVE_WEIGHT, 30)
        reasons.append(f"敏感数据 {sensitive_hits} 条")
    if is_web and port not in (80, 443):
        score += NONSTD_WEB_BONUS
        reasons.append("非标端口 Web 服务")
    return min(score, 100), reasons
