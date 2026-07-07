"""
app.py
Local web console for read-only host search (CrowdStrike Falcon) with an
optional vulnerabilities view (Tenable).

Run:
    pip install flask requests crowdstrike-falconpy
    # set read-only API keys as environment variables (see README), then:
    python app.py
    # open http://127.0.0.1:5000

Preview the UI without any keys:
    DEMO_MODE=1 python app.py     (PowerShell:  $env:DEMO_MODE=1; python app.py)

Notes:
  * Search-only. No endpoint here performs any action on a host.
  * Debug is OFF (never enable it: it would expose an interactive console).
  * Output is rendered through Jinja autoescaping; user/host values are never
    marked |safe, so a hostname like <script> cannot execute in a viewer's
    browser.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, Response
import backend

app = Flask(__name__)


@app.route("/")
def index():
    q = request.args.get("q", "")
    mode = request.args.get("mode", "auto")
    if mode not in ("auto", "user", "intel_actors", "intel_reports"):
        mode = "auto"
    result = None
    intel = None
    if mode in ("intel_actors", "intel_reports"):
        # Standalone threat intel: empty query lists recent, keyword searches.
        kind = "actors" if mode == "intel_actors" else "reports"
        intel = backend.do_intel(kind, q)
    elif q.strip():
        show_vulns = request.args.get("vulns") == "on"
        show_ports = request.args.get("ports") == "on"
        show_apps = request.args.get("apps") == "on"
        show_detections = request.args.get("detections") == "on"
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sev_picked = [v for v in request.args.getlist("sev") if v in sev_map]
        # No boxes checked (or all five) means no filter.
        sev_show = ({sev_map[v] for v in sev_picked}
                    if sev_picked and len(set(sev_picked)) < 5 else None)
        do_login = request.args.get("nologin") != "on"
        show_aid = request.args.get("aid") == "on"
        days = request.args.get("days", "90")
        result = backend.do_search(q, show_vulns=show_vulns, days=days,
                                   do_login=do_login, mode=mode,
                                   show_ports=show_ports, show_apps=show_apps,
                                   show_detections=show_detections, sev_show=sev_show)
        result = result or {}
        result["show_aid"] = show_aid
    return render_template(
        "index.html",
        result=result,
        intel=intel,
        q=q,
        mode=mode,
        vulns=request.args.get("vulns") == "on",
        ports=request.args.get("ports") == "on",
        apps=request.args.get("apps") == "on",
        detections=request.args.get("detections") == "on",
        sev_selected=(request.args.getlist("sev")
                      or ["critical", "high", "medium", "low", "info"]),
        nologin=request.args.get("nologin") == "on",
        aid=request.args.get("aid") == "on",
        days=request.args.get("days", "90"),
        demo=backend.demo_mode(),
    )


@app.route("/report/<int:report_id>")
def report_view(report_id):
    """Read one intel report (name, context, and full text)."""
    report = backend.get_report(report_id)
    return render_template("report.html", report=report, demo=backend.demo_mode())


@app.route("/report/<int:report_id>/pdf")
def report_pdf(report_id):
    """Download the report as PDF (proxied from the Intel API, read-only)."""
    data, err = backend.get_report_pdf_bytes(report_id)
    if err:
        report = {"ok": False, "error": err}
        return render_template("report.html", report=report, demo=backend.demo_mode()), 502
    return Response(data, mimetype="application/pdf",
                    headers={"Content-Disposition":
                             f"attachment; filename=intel-report-{report_id}.pdf"})


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print(f"\n  Host console -> http://{host}:{port}    (Ctrl+C to stop)")
    if backend.demo_mode():
        print("  DEMO_MODE on: showing sample data, no API calls.\n")
    app.run(host=host, port=port, debug=False)