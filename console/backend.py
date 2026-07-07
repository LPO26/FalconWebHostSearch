"""
backend.py
Read-only search logic for the host console. Wraps CrowdStrike Falcon (host
search, detections via the Alerts API, Discover applications, threat intel) and
Tenable (vulnerabilities, open ports). Returns plain data structures; the web
layer renders them. No write/action calls are made anywhere in this module.

Security posture:
  * All user input is sanitized to a strict allowlist before it ever reaches an
    API filter (see sanitize_term), so it cannot break out of an FQL/filter.
  * This module never executes actions; it only reads. Scope the API keys to
    read-only (Falcon Hosts: READ; Tenable Basic/Can-View).

Set DEMO_MODE=1 to preview the UI with built-in sample data and no API keys.
"""

import os
import re

# ----- severity mapping (Tenable 0..4) -------------------------------------
SEV = {
    4: ("Critical", "critical"),
    3: ("High", "high"),
    2: ("Medium", "medium"),
    1: ("Low", "low"),
    0: ("Info", "info"),
}

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
# Allowlist for free text: letters, digits, space, dot, underscore, hyphen.
UNSAFE_RE = re.compile(r"[^A-Za-z0-9 ._\-]")

PLATFORMS = {"windows": "Windows", "linux": "Linux",
             "mac": "Mac", "macos": "Mac", "osx": "Mac"}
TYPE_WORDS = {
    "server": "Server", "servers": "Server",
    "workstation": "Workstation", "workstations": "Workstation",
    "desktop": "Workstation", "desktops": "Workstation", "pc": "Workstation",
    "dc": "Domain Controller", "dcs": "Domain Controller",
}

MAX_TERM_LEN = 64
VULN_HOST_CAP = 50   # don't hammer Tenable: cap per-host vuln lookups per search
TIO_BASE = "https://cloud.tenable.com"


def demo_mode():
    return os.environ.get("DEMO_MODE", "").strip() not in ("", "0", "false", "False")


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def sanitize_term(raw):
    """Strip anything outside the allowlist and cap length. This is the single
    choke point that makes downstream filter-building injection-safe."""
    t = (raw or "").strip()[:MAX_TERM_LEN]
    return UNSAFE_RE.sub("", t).strip()


def clamp_days(raw, default=90):
    try:
        d = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(d, 365))


def build_filter(term):
    """Build a Falcon FQL filter from already-sanitized text."""
    t = term.strip()
    if IP_RE.match(t):
        return f"local_ip:'{t}',external_ip:'{t}'", f"IP = {t}"
    rem = f" {t.lower()} "
    platform = ptype = None
    if " domain controller " in rem:
        ptype = "Domain Controller"
        rem = rem.replace(" domain controller ", " ")
    for word, val in PLATFORMS.items():
        if f" {word} " in rem:
            platform = val
            rem = rem.replace(f" {word} ", " ")
            break
    if not ptype:
        for word, val in TYPE_WORDS.items():
            if f" {word} " in rem:
                ptype = val
                rem = rem.replace(f" {word} ", " ")
                break
    if (platform or ptype) and not rem.strip():
        clauses, desc = [], []
        if platform:
            clauses.append(f"platform_name:'{platform}'")
            desc.append(platform)
        if ptype:
            clauses.append(f"product_type_desc:'{ptype}'")
            desc.append(ptype)
        return "+".join(clauses), " ".join(desc) + " hosts"
    return f"hostname:*'*{t}*',os_version:*'*{t}*'", f"hostname or OS contains \u201c{t}\u201d"


# ---------------------------------------------------------------------------
# CrowdStrike (read-only host search)
# ---------------------------------------------------------------------------

def _falcon_client():
    from falconpy import Hosts
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Falcon keys are not set (FALCON_CLIENT_ID / FALCON_CLIENT_SECRET).")
    return Hosts(client_id=cid, client_secret=secret,
                 base_url=os.environ.get("FALCON_CLOUD", "us1"))


def _falcon_search(client, fql=None):
    aids, offset = [], 0
    while True:
        kwargs = {"limit": 5000, "offset": offset, "sort": "hostname.asc"}
        if fql:
            kwargs["filter"] = fql
        resp = client.query_devices_by_filter(**kwargs)
        if resp["status_code"] >= 400:
            errs = resp["body"].get("errors", [])
            raise RuntimeError(errs[0].get("message") if errs else f"Falcon HTTP {resp['status_code']}")
        body = resp["body"]
        batch = body.get("resources") or []
        aids.extend(batch)
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(batch)
        if not batch or offset >= total:
            break
    hosts = []
    for i in range(0, len(aids), 500):
        dr = client.get_device_details(ids=aids[i:i + 500])
        if dr["status_code"] < 400:
            hosts.extend(dr["body"].get("resources") or [])
    return hosts


def _falcon_logins(client, hosts):
    by_id = {h["device_id"]: h for h in hosts if h.get("device_id")}
    ids = list(by_id)
    for i in range(0, len(ids), 10):
        resp = client.query_device_login_history(ids=ids[i:i + 10])
        if resp["status_code"] >= 400:
            continue
        for rec in resp["body"].get("resources") or []:
            host = by_id.get(rec.get("device_id"))
            logins = rec.get("recent_logins") or []
            if host and logins:
                logins = sorted(logins, key=lambda x: x.get("login_time", ""), reverse=True)
                host["_login_users"] = [l.get("user_name", "") for l in logins]
                if not host.get("last_login_user"):
                    host["last_login_user"] = logins[0].get("user_name", "")


def user_match(host, needle):
    """True if the search string appears in this host's recent login user(s).
    Reads the same last-login-user data shown in the table, so the host view
    and the user search agree."""
    candidates = [host.get("last_login_user", "")] + host.get("_login_users", [])
    return any(needle in (c or "").lower() for c in candidates if c)


# ---------------------------------------------------------------------------
# Tenable (read-only vulnerabilities)
# ---------------------------------------------------------------------------

def _tio_headers():
    ak = os.environ.get("TIO_ACCESS_KEY", "")
    sk = os.environ.get("TIO_SECRET_KEY", "")
    if not ak or not sk:
        raise RuntimeError("Tenable keys are not set (TIO_ACCESS_KEY / TIO_SECRET_KEY).")
    return {"X-ApiKeys": f"accessKey={ak}; secretKey={sk}", "Accept": "application/json"}


def _tio_find_asset(requests, target, headers):
    if IP_RE.match(target):
        attempts = [("ipv4", "eq")]
    else:
        attempts = [("host.target", "eq"), ("fqdn", "match"),
                    ("hostname", "match"), ("netbios_name", "eq")]
    for field, quality in attempts:
        params = {"filter.0.filter": field, "filter.0.quality": quality, "filter.0.value": target}
        r = requests.get(f"{TIO_BASE}/workbenches/assets", headers=headers, params=params, timeout=30)
        r.raise_for_status()
        assets = r.json().get("assets", [])
        if assets:
            return assets[0]
    return None


PORT_FAMILIES = {"port scanners", "service detection"}
PORT_TXT_RE = re.compile(r"[Pp]ort (\d{1,5})/(tcp|udp)")


def _tio_ports(requests, asset_id, raw_vulns, headers):
    """Open ports from the asset's port-scanner / service-detection findings."""
    plugin_ids = [v.get("plugin_id") for v in raw_vulns
                  if (v.get("plugin_family") or "").lower() in PORT_FAMILIES and v.get("plugin_id")]
    found = {}
    for pid in plugin_ids:
        r = requests.get(f"{TIO_BASE}/workbenches/assets/{asset_id}/vulnerabilities/{pid}/outputs",
                         headers=headers, timeout=60)
        if r.status_code >= 400:
            continue
        for out in r.json().get("outputs", []) or []:
            for st in out.get("states", []) or []:
                for res in st.get("results", []) or []:
                    p, proto = res.get("port"), (res.get("protocol") or "tcp").lower()
                    svc = res.get("application_protocol") or ""
                    if p and int(p) > 0:
                        key = (int(p), proto)
                        if svc or key not in found:
                            found[key] = svc or found.get(key, "")
            for m in PORT_TXT_RE.finditer(out.get("plugin_output") or ""):
                found.setdefault((int(m.group(1)), m.group(2).lower()), "")
    return [f"{p}/{proto}" + (f" ({found[(p, proto)]})" if found[(p, proto)] else "")
            for (p, proto) in sorted(found)]


def _tio_host_data(requests, host, days, headers, want_ports, want_vulns, sev_show=None):
    """One Tenable pass per host: resolve the asset once, then vulns and/or ports."""
    name = host.get("hostname") or ""
    ip = host.get("local_ip") or ""
    asset = None
    for target in (name, ip):
        if target:
            asset = _tio_find_asset(requests, target, headers)
            if asset:
                break
    if not asset:
        empty = {"found": False, "tags": [], "total": 0, "tally": {}, "vulns": []}
        return (empty if want_vulns else None), ({"found": False, "ports": []} if want_ports else None)

    tags = [f"{t.get('category_name')}:{t.get('value')}"
            for t in (requests.get(f"{TIO_BASE}/tags/assets/{asset['id']}/assignments",
                                   headers=headers, timeout=30).json().get("tags", []))]
    raw = requests.get(f"{TIO_BASE}/workbenches/assets/{asset['id']}/vulnerabilities",
                       headers=headers, params={"date_range": days},
                       timeout=60).json().get("vulnerabilities", [])
    vulns = _shape_vulns(tags, raw, sev_show) if want_vulns else None
    ports = ({"found": True, "ports": _tio_ports(requests, asset["id"], raw, headers)}
             if want_ports else None)
    return vulns, ports


def _tio_vulns(requests, host, days, headers):
    vulns, _ = _tio_host_data(requests, host, days, headers, False, True)
    return vulns


def _shape_vulns(tags, raw, sev_show=None):
    """sev_show: set of severity ints to display, or None for all."""
    total_raw = len(raw)
    if sev_show is not None:
        raw = [v for v in raw if v.get("severity", 0) in sev_show]
    hidden = total_raw - len(raw)
    raw = sorted(raw, key=lambda v: (-v.get("severity", 0), v.get("plugin_name", "")))
    tally = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
    out = []
    for v in raw:
        s = v.get("severity", 0)
        tally[s] = tally.get(s, 0) + 1
        label, cls = SEV.get(s, ("?", "info"))
        out.append({
            "sev_label": label, "sev_class": cls,
            "plugin_id": v.get("plugin_id", ""),
            "plugin_name": v.get("plugin_name", ""),
            "plugin_family": v.get("plugin_family", ""),
        })
    levels = [s for s in (4, 3, 2, 1, 0) if sev_show is None or s in sev_show]
    filter_label = ("" if sev_show is None else
                    " + ".join(SEV[s][0] for s in sorted(sev_show, reverse=True)))
    return {"found": True, "tags": tags, "total": len(out), "hidden": hidden,
            "filter_label": filter_label,
            "tally": {SEV[s][0]: tally[s] for s in levels}, "vulns": out}


# ---------------------------------------------------------------------------
# CrowdStrike Discover (apps), Alerts (detections), Intel (actors/reports)
# ---------------------------------------------------------------------------

def _discover_client():
    from falconpy import Discover
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Falcon keys are not set (FALCON_CLIENT_ID / FALCON_CLIENT_SECRET).")
    return Discover(client_id=cid, client_secret=secret,
                    base_url=os.environ.get("FALCON_CLOUD", "us1"))


def _apps_for_host(discover, hostname):
    """Installed applications for one host via Discover. {apps, note}."""
    if not hostname:
        return {"apps": [], "note": "no hostname to look up"}
    apps, after, seen = [], None, set()
    for _ in range(25):
        kwargs = {"filter": f"host.hostname:'{hostname}'", "limit": 100}
        if after:
            kwargs["after"] = after
        resp = discover.query_combined_applications(**kwargs)
        sc = resp["status_code"]
        if sc in (401, 403):
            return {"apps": [], "note": "Discover not available (needs Discover: READ)"}
        if sc >= 400:
            return {"apps": [], "note": "Discover query failed"}
        body = resp["body"]
        batch = body.get("resources") or []
        for a in batch:
            key = (a.get("name", ""), a.get("version", ""))
            if a.get("name") and key not in seen:
                seen.add(key)
                apps.append({"name": a.get("name", ""), "version": a.get("version", ""),
                             "vendor": a.get("vendor", "")})
        after = body.get("meta", {}).get("pagination", {}).get("after")
        if not after or not batch:
            break
    apps.sort(key=lambda a: a["name"].lower())
    return {"apps": apps, "note": None if apps else "no apps recorded in Discover"}


def _alerts_client():
    from falconpy import Alerts
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Falcon keys are not set (FALCON_CLIENT_ID / FALCON_CLIENT_SECRET).")
    return Alerts(client_id=cid, client_secret=secret,
                  base_url=os.environ.get("FALCON_CLOUD", "us1"))


def _detections_for_host(alerts, aid, days, limit=20):
    """Recent alerts (detections) for one host via the Alerts API. {rows, note}.
    (The legacy Detects API was decommissioned; this needs Alerts: READ.)"""
    from datetime import datetime, timedelta, timezone
    if not aid:
        return {"rows": [], "note": "no agent ID for this host"}
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fql = f"device.device_id:'{aid}'+created_timestamp:>='{since}'"
    resp = alerts.query_alerts_v2(filter=fql, limit=limit, sort="created_timestamp|desc")
    sc = resp["status_code"]
    if sc in (401, 403):
        return {"rows": [], "note": "no access (client needs the Alerts: READ scope)"}
    if sc >= 400:
        return {"rows": [], "note": f"Alerts API error (HTTP {sc})"}
    ids = resp["body"].get("resources") or []
    total = resp["body"].get("meta", {}).get("pagination", {}).get("total", len(ids))
    if not ids:
        return {"rows": [], "note": None}
    d = alerts.get_alerts_v2(composite_ids=ids)
    if d["status_code"] >= 400:
        return {"rows": [], "note": f"Alerts API error reading details (HTTP {d['status_code']})"}
    rows = []
    for a in d["body"].get("resources") or []:
        sev = (a.get("severity_name") or "").lower() or "info"
        rows.append({
            "sev_label": sev.title(),
            "sev_class": sev if sev in ("critical", "high", "medium", "low") else "info",
            "name": a.get("display_name") or a.get("description") or "(unnamed)",
            "tactic_technique": " / ".join(x for x in (a.get("tactic"), a.get("technique")) if x),
            "status": a.get("status") or "",
            "when": (a.get("created_timestamp") or "")[:10],
        })
    rows.sort(key=lambda r: r["when"], reverse=True)
    note = f"showing latest {len(rows)} of {total}" if total > len(rows) else None
    return {"rows": rows, "note": note}


def _intel_client():
    from falconpy import Intel
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Falcon keys are not set (FALCON_CLIENT_ID / FALCON_CLIENT_SECRET).")
    return Intel(client_id=cid, client_secret=secret,
                 base_url=os.environ.get("FALCON_CLOUD", "us1"))


TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text):
    """CrowdStrike's rich_text_description is HTML; reduce it to plain text so
    we never render third-party HTML in the page."""
    text = re.sub(r"(?i)</(p|div|h\d|li|br)>", "\n", text or "")
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = TAG_RE.sub("", text)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def get_report(report_id):
    """Full detail for one intel report, for the read view."""
    from datetime import datetime, timezone
    if demo_mode():
        return _demo_report(report_id)
    try:
        intel = _intel_client()
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    try:
        resp = intel.get_report_entities(ids=[str(report_id)])
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"Intel request failed: {e}"}
    sc = resp["status_code"]
    if sc in (401, 403):
        return {"ok": False, "error": "No access: the client needs the Falcon Intelligence Reports: READ scope."}
    if sc >= 400:
        return {"ok": False, "error": f"Intel API error (HTTP {sc})."}
    res = resp["body"].get("resources") or []
    if not res:
        return {"ok": False, "error": "Report not found."}
    r = res[0]

    def names(key):
        return [v.get("value") or v.get("name", "") for v in (r.get(key) or [])]

    rtype = (r.get("type") or {}).get("name", "") if isinstance(r.get("type"), dict) else (r.get("type") or "")
    body = r.get("description") or _strip_html(r.get("rich_text_description") or "") \
        or r.get("short_description") or ""
    return {
        "ok": True, "error": None,
        "id": r.get("id"), "name": r.get("name", "?"), "type": rtype,
        "when": (r.get("created_date") and
                 datetime.fromtimestamp(r["created_date"], tz=timezone.utc).strftime("%Y-%m-%d")) or "",
        "industries": names("target_industries"),
        "countries": names("target_countries"),
        "motivations": names("motivations"),
        "actors": [a.get("name", "") for a in (r.get("actors") or [])],
        "body": body,
        "url": r.get("url") or "",
    }


def get_report_pdf_bytes(report_id):
    """The report as PDF. Returns (bytes, None) or (None, error)."""
    if demo_mode():
        return None, "PDF download is disabled in demo mode."
    try:
        intel = _intel_client()
    except RuntimeError as e:
        return None, str(e)
    try:
        resp = intel.get_report_pdf(id=str(report_id))
    except Exception as e:  # noqa: BLE001
        return None, f"Intel request failed: {e}"
    if isinstance(resp, (bytes, bytearray)):
        return bytes(resp), None
    sc = resp.get("status_code", 0) if isinstance(resp, dict) else 0
    if sc in (401, 403):
        return None, "No access: the client needs the Falcon Intelligence Reports: READ scope."
    if sc == 404:
        return None, "No PDF is available for this report."
    return None, f"Intel API error (HTTP {sc})."


def _demo_report(report_id):
    demo = {r["id"]: r for r in [
        {"id": 9001, "name": "CSA-260630 eCrime Landscape Report", "type": "Periodic Report",
         "when": "2026-06-30", "industries": ["Financial Services", "Healthcare"],
         "countries": ["United States", "Canada"], "motivations": ["Criminal"],
         "actors": ["WIZARD SPIDER", "SCATTERED SPIDER"],
         "body": ("This periodic report summarizes eCrime activity observed during June 2026.\n\n"
                  "Key findings: ransomware operators continued shifting toward data-theft-only "
                  "extortion; access brokers advertised a growing volume of VPN and SSO credentials; "
                  "and callback-phishing campaigns expanded into the healthcare sector.\n\n"
                  "Mitigations: enforce phishing-resistant MFA, monitor for anomalous SSO logins, "
                  "and validate EDR coverage on internet-facing servers."),
         "url": "https://falcon.crowdstrike.com/intelligence/reports/9001"},
        {"id": 9002, "name": "Ransomware Trends Q2 2026", "type": "Tipper",
         "when": "2026-06-20", "industries": ["Manufacturing"], "countries": [],
         "motivations": ["Criminal"], "actors": [],
         "body": "Quarterly tipper covering ransomware TTP changes observed in Q2 2026.",
         "url": ""},
        {"id": 9003, "name": "SCATTERED SPIDER Targets Hospitality", "type": "Alert",
         "when": "2026-06-12", "industries": ["Hospitality"], "countries": ["United States"],
         "motivations": ["Criminal"], "actors": ["SCATTERED SPIDER"],
         "body": "Alert describing active social-engineering intrusions against hospitality helpdesks.",
         "url": ""},
    ]}
    r = demo.get(report_id)
    if not r:
        return {"ok": False, "error": "Report not found (demo data has reports 9001-9003)."}
    return {"ok": True, "error": None, **r}


def do_intel(kind, raw_query, limit=15):
    """Standalone threat-intel lookup: kind is 'actors' or 'reports'.
    Empty query lists recent entries; otherwise a keyword search."""
    from datetime import datetime, timezone
    query = (raw_query or "").strip()[:80]
    if demo_mode():
        return _demo_intel(kind, query)
    try:
        intel = _intel_client()
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    fn = intel.query_actor_entities if kind == "actors" else intel.query_report_entities
    kwargs = {"limit": limit}
    if query:
        kwargs["q"] = query
    try:
        resp = fn(**kwargs)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"Intel request failed: {e}"}
    sc = resp["status_code"]
    if sc in (401, 403):
        return {"ok": False, "error": "No access: the client needs the Falcon Intelligence "
                                      f"{'Actors' if kind == 'actors' else 'Reports'}: READ scope."}
    if sc >= 400:
        return {"ok": False, "error": f"Intel API error (HTTP {sc})."}
    body = resp["body"]
    raw_items = body.get("resources") or []
    total = body.get("meta", {}).get("pagination", {}).get("total", len(raw_items))

    def ts(v):
        return (datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d") if v else "")

    items = []
    for x in raw_items:
        if kind == "actors":
            items.append({
                "name": x.get("name", "?"),
                "detail": ", ".join(o.get("value", "") for o in (x.get("origins") or [])[:3]),
                "detail2": ", ".join(t.get("value", "") for t in (x.get("target_industries") or [])[:3]),
                "when": ts(x.get("last_activity_date")),
            })
        else:
            rtype = (x.get("type") or {}).get("name", "") if isinstance(x.get("type"), dict) else (x.get("type") or "")
            items.append({"id": x.get("id"), "name": x.get("name", "?"), "detail": rtype,
                          "detail2": "", "when": ts(x.get("created_date"))})
    return {"ok": True, "error": None, "kind": kind, "query": query,
            "rows": items, "total": total}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def do_search(raw_term, show_vulns=False, days=90, do_login=True, mode="auto",
              show_ports=False, show_apps=False, show_detections=False, sev_show=None):
    days = clamp_days(days)
    user_mode = (mode == "user")

    if user_mode:
        # Match the same last-login-user data shown in the table (not Discover).
        needle = (raw_term or "").strip()[:64].lower()
        if not needle:
            return {"ok": False, "error": "Enter a username to search."}
        if demo_mode():
            return _demo_result(needle, show_vulns, days, mode="user",
                                show_ports=show_ports, show_apps=show_apps,
                                show_detections=show_detections, sev_show=sev_show)
        try:
            client = _falcon_client()
            hosts = _falcon_search(client)  # all hosts; no server-side login-user filter exists
            missing = [h for h in hosts if not h.get("last_login_user")]
            if missing:
                _falcon_logins(client, missing)
            hosts = [h for h in hosts if user_match(h, needle)]
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"Falcon request failed: {e}"}
        description = f"hosts where login user contains \u201c{raw_term.strip()}\u201d"
        show_login = True  # the login user is the whole point of this search
    else:
        term = sanitize_term(raw_term)
        if not term:
            return {"ok": False, "error": "Enter an IP, hostname, or OS to search."}
        if demo_mode():
            return _demo_result(term, show_vulns, days,
                                show_ports=show_ports, show_apps=show_apps,
                                show_detections=show_detections, sev_show=sev_show)
        fql, description = build_filter(term)
        try:
            client = _falcon_client()
            hosts = _falcon_search(client, fql)
            if do_login and hosts:
                _falcon_logins(client, hosts)
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"Falcon request failed: {e}"}
        show_login = do_login

    result = {"ok": True, "error": None, "description": description,
              "term": raw_term, "hosts": hosts, "show_vulns": show_vulns,
              "show_ports": show_ports, "show_apps": show_apps,
              "show_detections": show_detections,
              "show_login": show_login, "days": days,
              "vulns": {}, "ports": {}, "apps": {}, "detections": {},
              "vuln_capped": False}

    targets = hosts[:VULN_HOST_CAP]
    result["vuln_capped"] = (show_vulns or show_ports or show_apps or show_detections) \
        and len(hosts) > VULN_HOST_CAP

    if (show_vulns or show_ports) and hosts:
        import requests
        try:
            headers = _tio_headers()
        except RuntimeError as e:
            result["vuln_error"] = str(e)
            headers = None
        if headers:
            for h in targets:
                try:
                    v, p = _tio_host_data(requests, h, days, headers, show_ports, show_vulns, sev_show)
                    if v is not None:
                        result["vulns"][h.get("device_id")] = v
                    if p is not None:
                        result["ports"][h.get("device_id")] = p
                except requests.HTTPError as e:
                    code = e.response.status_code
                    result["vuln_error"] = (f"Tenable auth failed (HTTP {code})."
                                            if code in (401, 403) else f"Tenable HTTP {code}.")
                    break
                except Exception as e:  # noqa: BLE001
                    if show_vulns:
                        result["vulns"][h.get("device_id")] = {"found": False, "error": str(e),
                                                               "tags": [], "total": 0, "tally": {}, "vulns": []}
                    if show_ports:
                        result["ports"][h.get("device_id")] = {"found": False, "ports": []}

    if show_apps and hosts:
        try:
            discover = _discover_client()
        except RuntimeError as e:
            result["apps_error"] = str(e)
            discover = None
        if discover:
            for h in targets:
                try:
                    result["apps"][h.get("device_id")] = _apps_for_host(discover, h.get("hostname"))
                except Exception as e:  # noqa: BLE001
                    result["apps"][h.get("device_id")] = {"apps": [], "note": f"lookup failed: {e}"}

    if show_detections and hosts:
        try:
            alerts = _alerts_client()
        except RuntimeError as e:
            result["detections_error"] = str(e)
            alerts = None
        if alerts:
            for h in targets:
                try:
                    result["detections"][h.get("device_id")] = _detections_for_host(
                        alerts, h.get("device_id"), days)
                except Exception as e:  # noqa: BLE001
                    result["detections"][h.get("device_id")] = {"rows": [], "note": f"lookup failed: {e}"}
    return result


# ---------------------------------------------------------------------------
# Demo data (DEMO_MODE=1)
# ---------------------------------------------------------------------------

def _demo_result(term, show_vulns, days, mode="auto",
                 show_ports=False, show_apps=False, show_detections=False, sev_show=None):
    hosts = [
        {"device_id": "a1", "hostname": "WEB01", "local_ip": "10.50.10.21",
         "os_version": "Windows Server 2019", "product_type_desc": "Server",
         "system_manufacturer": "VMware, Inc.", "last_login_user": "CORP\\john.smith",
         "last_seen": "2026-06-20T14:03:00Z"},
        {"device_id": "a2", "hostname": "SQL-PROD-03", "local_ip": "10.50.10.40",
         "os_version": "Windows Server 2016", "product_type_desc": "Server",
         "system_manufacturer": "HPE", "last_login_user": "CORP\\dba.team",
         "last_seen": "2026-06-22T02:15:00Z"},
        {"device_id": "a3", "hostname": "CORP-DC01", "local_ip": "10.50.10.10",
         "os_version": "Windows Server 2022", "product_type_desc": "Domain Controller",
         "system_manufacturer": "Dell Inc.", "last_login_user": "CORP\\svc-backup",
         "last_seen": "2026-06-21T11:30:00Z"},
    ]
    if mode == "user":
        needle = term.lower()
        hosts = [h for h in hosts if needle in h.get("last_login_user", "").lower()]
        description = f"hosts where login user contains \u201c{term}\u201d"
    else:
        description = f"demo results for \u201c{term}\u201d"
    result = {"ok": True, "error": None, "description": description,
              "term": term, "hosts": hosts, "show_vulns": show_vulns, "show_login": True,
              "show_ports": show_ports, "show_apps": show_apps,
              "show_detections": show_detections,
              "days": days, "vulns": {}, "ports": {}, "apps": {}, "detections": {},
              "vuln_capped": False, "demo": True}
    present = {h["device_id"] for h in hosts}
    if show_vulns:
        demo_vulns = {
            "a1": _shape_vulns(
                ["Owner:InfraSec", "Env:Prod"],
                [{"plugin_id": 157288, "plugin_name": "Apache Log4j RCE (Log4Shell)", "plugin_family": "CGI abuses", "severity": 4},
                 {"plugin_id": 97994, "plugin_name": "MS17-010 EternalBlue", "plugin_family": "Windows", "severity": 4},
                 {"plugin_id": 156032, "plugin_name": "OpenSSL 3.0 < 3.0.7", "plugin_family": "Web Servers", "severity": 3},
                 {"plugin_id": 42873, "plugin_name": "SMB Signing not required", "plugin_family": "Misc.", "severity": 2},
                 {"plugin_id": 10863, "plugin_name": "SSL Certificate Information", "plugin_family": "General", "severity": 1},
                 {"plugin_id": 19506, "plugin_name": "Nessus Scan Information", "plugin_family": "Settings", "severity": 0}], sev_show),
            "a2": _shape_vulns(
                ["Owner:DBA Team", "Compliance:PCI"],
                [{"plugin_id": 138585, "plugin_name": "Microsoft SQL Server Unsupported Version", "plugin_family": "Databases", "severity": 3},
                 {"plugin_id": 51192, "plugin_name": "SSL Certificate Cannot Be Trusted", "plugin_family": "General", "severity": 2},
                 {"plugin_id": 45590, "plugin_name": "Common Platform Enumeration (CPE)", "plugin_family": "General", "severity": 0}], sev_show),
            "a3": _shape_vulns([], [], sev_show),
        }
        result["vulns"] = {aid: v for aid, v in demo_vulns.items() if aid in present}
    if show_ports:
        demo_ports = {
            "a1": {"found": True, "ports": ["22/tcp (ssh)", "80/tcp (www)", "443/tcp (www)"]},
            "a2": {"found": True, "ports": ["1433/tcp (mssql)", "3389/tcp"]},
            "a3": {"found": True, "ports": ["53/tcp", "53/udp", "88/tcp (kerberos)", "389/tcp (ldap)", "445/tcp"]},
        }
        result["ports"] = {aid: v for aid, v in demo_ports.items() if aid in present}
    if show_apps:
        demo_apps = {
            "a1": {"apps": [{"name": "7-Zip", "version": "23.01", "vendor": "Igor Pavlov"},
                            {"name": "Google Chrome", "version": "126.0.6478", "vendor": "Google LLC"},
                            {"name": "OpenSSH", "version": "9.5", "vendor": "OpenBSD"}], "note": None},
            "a2": {"apps": [{"name": "Microsoft SQL Server 2016", "version": "13.0", "vendor": "Microsoft"},
                            {"name": "SQL Server Management Studio", "version": "19.1", "vendor": "Microsoft"}], "note": None},
            "a3": {"apps": [], "note": "no apps recorded in Discover"},
        }
        result["apps"] = {aid: v for aid, v in demo_apps.items() if aid in present}
    if show_detections:
        demo_det = {
            "a1": {"rows": [
                {"sev_label": "High", "sev_class": "high", "name": "Credential dumping attempt",
                 "tactic_technique": "Credential Access / OS Credential Dumping", "status": "new", "when": "2026-06-28"},
                {"sev_label": "Medium", "sev_class": "medium", "name": "Suspicious PowerShell encoded command",
                 "tactic_technique": "Execution / PowerShell", "status": "in_progress", "when": "2026-06-25"}], "note": None},
            "a2": {"rows": [], "note": None},
            "a3": {"rows": [
                {"sev_label": "Critical", "sev_class": "critical", "name": "DCSync attempt detected",
                 "tactic_technique": "Credential Access / DCSync", "status": "new", "when": "2026-06-29"}], "note": None},
        }
        result["detections"] = {aid: v for aid, v in demo_det.items() if aid in present}
    return result


def _demo_intel(kind, query):
    if kind == "actors":
        items = [
            {"name": "WIZARD SPIDER", "detail": "Russia", "detail2": "Finance, Healthcare", "when": "2026-05-30"},
            {"name": "SCATTERED SPIDER", "detail": "Various", "detail2": "Telecom, Hospitality", "when": "2026-06-12"},
            {"name": "FANCY BEAR", "detail": "Russia", "detail2": "Government, Defense", "when": "2026-04-18"},
            {"name": "COZY BEAR", "detail": "Russia", "detail2": "Government, Think Tanks", "when": "2026-03-02"},
        ]
    else:
        items = [
            {"id": 9001, "name": "CSA-260630 eCrime Landscape Report", "detail": "Periodic Report", "detail2": "", "when": "2026-06-30"},
            {"id": 9002, "name": "Ransomware Trends Q2 2026", "detail": "Tipper", "detail2": "", "when": "2026-06-20"},
            {"id": 9003, "name": "SCATTERED SPIDER Targets Hospitality", "detail": "Alert", "detail2": "", "when": "2026-06-12"},
        ]
    if query:
        q = query.lower()
        items = [i for i in items if q in i["name"].lower()]
    return {"ok": True, "error": None, "kind": kind, "query": query,
            "rows": items, "total": len(items), "demo": True}
