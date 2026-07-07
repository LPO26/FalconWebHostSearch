"""
serve.py
Run the host console for your local network with a production WSGI server
(waitress) instead of Flask's development server.

    pip install -r requirements.txt
    python serve.py                       # serves on 0.0.0.0:8080
    HOST=0.0.0.0 PORT=9000 python serve.py

It prints the LAN URL(s) teammates can open. Set the same environment
variables as app.py (FALCON_* / TIO_* keys, or DEMO_MODE=1).

Notes for sharing on a LAN:
  * The console has no login of its own. Anyone who can reach the port can
    search your host inventory, detections, and intel. Share it only on a
    trusted network segment, and prefer a firewall rule, VPN, or an
    authenticating reverse proxy in front of it.
  * Everything stays read-only regardless: no endpoint performs any action.
"""

import os
import socket

from waitress import serve

from app import app


def lan_addresses():
    """Best-effort list of this machine's LAN IPv4 addresses."""
    addrs = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))       # no traffic is sent
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                addrs.add(ip)
    except OSError:
        pass
    return sorted(addrs)


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))

    print(f"Host console (read-only) starting on {host}:{port}")
    if os.environ.get("DEMO_MODE"):
        print("DEMO_MODE is on: serving sample data, no API keys used.")
    urls = [f"http://{ip}:{port}/" for ip in lan_addresses()] or [f"http://<this-machine's-IP>:{port}/"]
    print("Share on your network:  " + "   ".join(urls))
    print("Local:                  http://127.0.0.1:%d/" % port)
    print("Stop with Ctrl+C.")
    serve(app, host=host, port=port, threads=8)


if __name__ == "__main__":
    main()
