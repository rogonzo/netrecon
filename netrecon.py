#!/usr/bin/env python3
"""
netrecon - authorized-use host/port reconnaissance with JSON output.

Only run against systems you own or have explicit written permission to test.
"""
import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

BANNER_PROBES = {
    22: b"",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"",
}


def parse_ports(spec: str) -> list[int]:
    ports = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return ports


def grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    try:
        sock.settimeout(timeout)
        probe = BANNER_PROBES.get(port, b"")
        if probe:
            sock.sendall(probe)
        data = sock.recv(1024)
        return data.decode(errors="replace").strip().splitlines()[0][:120] if data else ""
    except Exception:
        return ""

def scan_port_throttled(host: str, port: int, timeout: float, delay: float) -> dict | None:
    import time
    time.sleep(delay)
    return scan_port(host, port, timeout)


def scan_port(host: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return {"port": port, "state": "open", "banner": grab_banner(s, port, timeout)}
    except Exception:
        pass
    return None


def main() -> int:
    p = argparse.ArgumentParser(description="Authorized-use recon. Scan only what you own or have permission to test.")
    p.add_argument("target", help="Hostname or IP (authorized scope only)")
    p.add_argument("-p", "--ports", default="1-1024", help="Ports, e.g. 22,80,443 or 1-1024")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="Per-port timeout (s)")
    p.add_argument("-w", "--workers", type=int, default=100, help="Thread count")
    p.add_argument("-d", "--delay", type=float, default=0.0, help="Delay between port attempts (s)")
    p.add_argument("-o", "--output", default="output/results.json", help="JSON output path")
    args = p.parse_args()

    try:
        host = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Cannot resolve {args.target}", file=sys.stderr)
        return 1

    ports = parse_ports(args.ports)
    print(f"[*] Target {args.target} ({host})  ports={len(ports)}  workers={args.workers}")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_port_throttled, host, pt, args.timeout, args.delay): pt for pt in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
                banner = f"  {r['banner']}" if r["banner"] else ""
                print(f"[+] {r['port']}/tcp open{banner}")

    results.sort(key=lambda x: x["port"])
    report = {
        "target": args.target,
        "resolved": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open_ports": results,
    }

    import os
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[*] {len(results)} open port(s). Report: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
