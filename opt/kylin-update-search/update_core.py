#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""麒麟系统更新/安全漏洞联合查询核心逻辑（无 GUI 依赖）

信息源：
1. 系统更新（BUG修复/功能更新）: POST /protalweb/security/ba/list
   详情页: https://support.kylinos.cn/#/support/baDetail?no=<ba_no>
2. 安全漏洞（CVE/KVE）: POST /protalweb/security/cve/query
   详情页: https://support.kylinos.cn/#/security/cveDetail?allTitle=<编号>
"""
import re
import difflib

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

BASE = "https://support.kylinos.cn/protalweb"
BA_LIST_URL = BASE + "/security/ba/list"
CVE_LIST_URL = BASE + "/security/cve/list"
BA_DETAIL_URL = "https://support.kylinos.cn/#/support/baDetail?no="
CVE_DETAIL_URL = "https://support.kylinos.cn/#/security/cveDetail?allTitle="
TIMEOUT = 20

RISK_MAP = {
    "Low": "低风险", "low": "低风险",
    "Normal": "中风险", "Medium": "中风险", "medium": "中风险",
    "Moderate": "中风险",
    "High": "高风险", "high": "高风险",
    "Important": "重要", "Critical": "严重",
    "Urgency": "紧急", "urgent": "紧急",
}

# 结果列定义: (键, 表头)
COLUMNS = [
    ("source", "信息来源"),
    ("no", "公告/漏洞编号"),
    ("risk", "风险等级"),
    ("title", "标题/描述"),
    ("date", "发布时间"),
    ("link", "详情链接"),
]

_header = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Content-Type": "application/json;charset=UTF-8",
    "Referer": "https://support.kylinos.cn/support/ba",
    "Origin": "https://support.kylinos.cn",
    "Accept": "application/json, text/plain, */*",
}

_session = None


def _get_session():
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update(_header)
        try:  # 预热，获取站点 Cookie
            _session.get("https://support.kylinos.cn/", timeout=TIMEOUT)
        except Exception:
            pass
    return _session


def normalize(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"\s+", "", str(s)).upper()


def _fetch_updates(keyword: str, page: int = 1, page_size: int = 100):
    """系统更新（BA 公告）搜索，返回 (total, rows)"""
    body = {"row": page_size, "page": page, "productId": "", "query": keyword,
            "emergency": "", "arch": "", "timeStart": "", "timeEnd": "",
            "sortord": "public_date", "sortOrder": "descending"}
    r = _get_session().post(BA_LIST_URL, json=body, timeout=TIMEOUT)
    r.raise_for_status()
    obj = (r.json().get("obj") or {})
    rows = []
    for d in obj.get("data") or []:
        rows.append({
            "source": "系统更新",
            "no": d.get("ba_no") or "",
            "risk": RISK_MAP.get(d.get("emergency") or "", d.get("emergency") or ""),
            "title": d.get("title") or "",
            "date": d.get("publish_date") or "",
            "link": BA_DETAIL_URL + (d.get("ba_no") or ""),
        })
    return obj.get("numFound", 0) or 0, rows


def _fetch_cves(keyword: str, page: int = 1, page_size: int = 100):
    """安全漏洞（CVE/KVE）搜索，返回 (total, rows)

    注意：必须用 /security/cve/list（query 为全文检索关键词）。
    /security/cve/query 不读关键词，永远返回最新几条，会造成无关结果。
    """
    body = {"row": page_size, "page": page, "query": keyword, "productId": "",
            "arch": "", "timeStart": "", "timeEnd": "",
            "update_time_start": "", "update_time_end": ""}
    r = _get_session().post(CVE_LIST_URL, json=body, timeout=TIMEOUT)
    r.raise_for_status()
    obj = (r.json().get("obj") or {})
    rows = []
    for d in obj.get("data") or []:
        rows.append({
            "source": "安全漏洞",
            "no": d.get("all_title") or "",
            "risk": RISK_MAP.get(d.get("threat_severity") or "",
                                 d.get("threat_severity") or ""),
            "title": d.get("cve_detail") or "",
            "date": d.get("cve_publicdate") or "",
            "link": CVE_DETAIL_URL + (d.get("all_title") or ""),
        })
    return obj.get("numFound") or 0, rows


def query_variants(keyword: str) -> list:
    """生成查询变体，弥补空格/分隔敏感"""
    kw = keyword.strip()
    if not kw:
        return []
    nospace = re.sub(r"\s+", "", kw)
    variants = [kw]
    if nospace != kw:
        variants.append(nospace)
    parts = re.findall(r"[A-Za-z]+|\d+|[\u4e00-\u9fa5]+", nospace)
    if len(parts) > 1:
        joined = " ".join(parts)
        if joined not in variants:
            variants.append(joined)
    return variants[:3]


def _score(text: str, kw_norm: str) -> float:
    if not text or not kw_norm:
        return 0.0
    t = normalize(text)
    if kw_norm in t:
        return 0.85 + 0.15 * (len(kw_norm) / max(len(t), 1))
    return difflib.SequenceMatcher(None, kw_norm, t).ratio() * 0.8


def row_score(row: dict, kw_norm: str, tokens: list) -> float:
    """综合打分：编号命中最高，其次标题/描述"""
    s_no = _score(row.get("no"), kw_norm) * 1.1  # 编号命中加权
    s_title = _score(row.get("title"), kw_norm)
    best = max(s_no, s_title)
    if len(tokens) > 1:
        # 组合词：各词元都要在标题或编号中出现才算高相关
        hay = normalize(row.get("no") + " " + row.get("title"))
        per = []
        for tok in tokens:
            if tok in hay:
                per.append(0.9)
            else:
                per.append(_score(row.get("title"), tok) * 0.6)
        prod = 1.0
        for x in per:
            prod *= max(x, 0.0)
        best = max(best, prod ** (1.0 / len(per)))
    return best


def search(keyword: str, page_size: int = 100, progress_cb=None):
    """联合搜索：系统更新 + 安全漏洞，按相关度排序

    返回 (rows, stats)：rows 为排序后的结果列表，stats 为 {"系统更新": n, "安全漏洞": m}
    """
    kw = keyword.strip()
    if not kw:
        return [], {"系统更新": 0, "安全漏洞": 0}
    kw_norm = normalize(kw)
    tokens = [normalize(t) for t in re.findall(r"[A-Za-z]+|\d+|[\u4e00-\u9fa5]+",
                                               re.sub(r"\s+", "", kw))]

    pool = {}
    stats = {"系统更新": 0, "安全漏洞": 0}
    seen_variants = set()
    for v in query_variants(kw):
        if v in seen_variants:
            continue
        seen_variants.add(v)
        if progress_cb:
            progress_cb("正在检索系统更新（关键词: %s）…" % v)
        try:
            total, rows = _fetch_updates(v, page_size=page_size)
        except Exception:
            rows = []
        stats["系统更新"] = max(stats["系统更新"], total or 0)
        for row in rows:
            pool.setdefault(("BA", row["no"], row["date"]), row)
        if progress_cb:
            progress_cb("正在检索安全漏洞（关键词: %s）…" % v)
        try:
            total, rows = _fetch_cves(v, page_size=page_size)
        except Exception:
            rows = []
        stats["安全漏洞"] = max(stats["安全漏洞"], total or 0)
        for row in rows:
            pool.setdefault(("CVE", row["no"]), row)

    scored = []
    for row in pool.values():
        s = row_score(row, kw_norm, tokens)
        # 服务端命中（如关键词出现在公告正文）保底 0.5，不因标题不含关键词被丢弃
        scored.append((max(s, 0.5), row))
    scored.sort(key=lambda x: -x[0])
    return scored, stats


def apply_filters(scored: list, source: str = "", risk: str = ""):
    """来源/风险筛选；空字符串表示不限"""
    out = []
    for score, row in scored:
        if source and row.get("source") != source:
            continue
        if risk and row.get("risk") != risk:
            continue
        out.append((score, row))
    return out


if __name__ == "__main__":
    import sys
    kw = " ".join(sys.argv[1:]) or "hns3"
    scored, stats = search(kw)
    print("系统更新命中 %s 条 | 安全漏洞命中 %s 条 | 展示 %d 条"
          % (stats["系统更新"], stats["安全漏洞"], len(scored)))
    for s, r in scored[:15]:
        print("%.2f [%s] %s | %s | %s" % (s, r["source"], r["no"], r["risk"],
                                          r["title"][:60]))
