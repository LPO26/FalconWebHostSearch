# Host Console (read-only web search)

A small local web app for searching **CrowdStrike Falcon** and **Tenable** from the browser: hosts by IP / hostname / OS / login user, plus per-host vulnerabilities, open ports, installed applications, and detections — and standalone threat-intel browsing with readable reports. It is the web sibling of the `FalconHostSearch.py` CLI and supports the same features.

**Read-only by design.** No route performs any action on any system; the app only searches and displays.

```
console/
├── app.py              # Flask routes (search, intel, report read / PDF)
├── serve.py            # production LAN server (waitress)
├── backend.py          # read-only Falcon + Tenable logic
├── requirements.txt    # Flask, requests, crowdstrike-falconpy, waitress
├── README.md
├── static/
│   └── style.css       # dark theme, purple accent
└── templates/
    ├── index.html      # search page + results
    └── report.html     # intel report read view
```

## Setup

Python 3.8+.

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Credentials come from environment variables — nothing is stored in the code:

| Variable | Needed for |
| --- | --- |
| `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET` | Everything CrowdStrike (required) |
| `FALCON_CLOUD` | Optional: `us1` (default), `us2`, `eu1`, `usgov1` |
| `TIO_ACCESS_KEY`, `TIO_SECRET_KEY` | Vulnerabilities and Open ports (Tenable) |
| `DEMO_MODE=1` | Run with sample data and no keys at all |

**Read-only scopes for the Falcon API client** — each unlocks one feature; grant only what you want exposed. A missing scope never breaks the page; that section just shows a "no access" note.

| Feature | Scope |
| --- | --- |
| Host search (base) | `Hosts: READ` |
| Applications | `Discover: READ` |
| Detections | `Alerts: READ` (detections use the Alerts API; the legacy Detects API was decommissioned Sept 2025) |
| Threat intel, report reading, report PDFs | `Actors (Falcon Intelligence): READ`, `Reports (Falcon Intelligence): READ` |
| Vulnerabilities / Open ports | Tenable Basic / **Can View** user |

## Run

```bash
DEMO_MODE=1 python app.py     # try the UI with sample data, no keys
python app.py                 # live, local only: http://127.0.0.1:5000
```

`HOST` / `PORT` env vars change the bind address and port. Debug is hard-off; leave it that way (Flask debug exposes an interactive console).

## Using the console

**Search modes** (dropdown): `IP / Hostname / OS`, `Login user`, `Threat intel: actors`, `Threat intel: reports`.
- Host searches accept an IP, a hostname fragment, an OS (e.g. "Windows Server"), or — in Login user mode — a username fragment, matched against the same Last Login User data shown in the table.
- Intel modes are standalone: leave the box empty to list recent entries, or type a keyword to search. They ignore the host options.

**Per-host checkboxes** — each fetched only when checked:
- **Vulnerabilities (Tenable)** with **severity filter chips** (Critical / High / Medium / Low / Info): check exactly the levels you want, e.g. only Critical + High. All or none checked = show everything. Each host's tally notes how many findings were hidden.
- **Open ports (Tenable)** — from the latest port-scanner / service-detection findings, shown as `443/tcp (www)` chips.
- **Applications (CrowdStrike Discover)** — name / version / vendor per host.
- **Detections (Falcon Alerts)** — severity, date, name, tactic/technique, status, newest first, within the look-back window.
- **Look back N days** applies to Tenable data and detections. **Skip login lookup** and **Show Agent ID** adjust the host table.

**Reading intel reports:** in reports mode every report name is a link. The read view shows type, publish date, related actors, target industries/countries, motivations, and the full report text (rich-text HTML from the API is stripped to plain text — third-party HTML never renders in the page). **Download PDF** proxies the official report PDF; **Open in Falcon console** links to the source. Some report types have no inline text; the page says so and the PDF remains the full document.

A subtle **"Searching…" toast** (bottom-right) appears while a search is running and the button disables to prevent double submits.

## Sharing on your local network

Use `serve.py`, which runs the console with a production WSGI server (waitress) and binds to your LAN:

```bash
python serve.py                          # 0.0.0.0:8080, prints the URL to share
HOST=0.0.0.0 PORT=9000 python serve.py
```

It prints something like `Share on your network: http://192.168.1.24:8080/` — that's the link teammates open. Set the same environment variables in the shell that runs it. If nobody can connect, allow the port through the host firewall (Windows Defender Firewall / `ufw allow 8080`).

**Security notes for sharing.** The console has **no login of its own** — anyone who can reach the port can search your host inventory, detections, and intel. Share it only on a trusted network segment; for anything broader, put a firewall rule, VPN, or an authenticating reverse proxy (nginx / Caddy, with TLS) in front. Run it under a low-privilege account holding only the read-only API keys. User input is sanitized before reaching any API, all output is rendered with autoescaping, and every endpoint remains read-only regardless.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| "Falcon keys are not set" | Export `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` in the shell running the app. |
| Vulnerabilities/ports section shows an auth error | Check `TIO_ACCESS_KEY` / `TIO_SECRET_KEY` and the Tenable user's view access. |
| Applications say "Discover not available" | The API client lacks `Discover: READ`, or the tenant isn't licensed for Discover. |
| Detections say "no access" | Add the `Alerts: READ` scope to the API client. |
| Intel says "no access" | The client lacks the Falcon Intelligence `READ` scopes, or there's no Intel subscription. |
| A host shows "Not found in Tenable" | The name/IP differs between Falcon and Tenable, or the host isn't in Tenable. |
| Teammates can't reach the shared URL | Confirm `serve.py` is running, the port is allowed through the firewall, and you shared the printed LAN IP (not 127.0.0.1). |
