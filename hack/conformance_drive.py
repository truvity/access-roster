#!/usr/bin/env python3
"""Run a conformance plan end to end in headless Chrome.

WHY A BROWSER IS REQUIRED, having tried without one: the suite's callback
is an HTML page that posts the result back to the suite with JavaScript.
`curl` follows every redirect, reaches that page, and never runs it — so
the authorization completes, the suite is never told, and the module sits
in WAITING until the next one interrupts it. That reads as a hang and is
the reason a plan showed a row of grey boxes.

Signing in is RECOVERY: a ServiceAccount token the cluster vouches for,
rather than a person at a Google prompt. That is what makes thirty
modules unattended. It is the audited break-glass path, and the issuer
logs every use of it at WARN.

The sign-in is re-established WHENEVER the issuer asks for one, not once
at the start, because the logout modules exist to end it — a driver that
cached a session would pass them by accident.

Usage:
  hack/conformance_drive.py <plan-id> [--from <module>] [--only <module>]

Run ONE plan at a time. The suite serves every plan's callback under its
`alias`, so starting a test in a plan that shares an alias interrupts the
running one, with "Stopping test due to alias conflict" in its log.
"""

import argparse
import base64
import json
import os
import struct
import subprocess
import sys
import time
import urllib.request

SUITE = os.environ.get("SUITE", "https://localhost.emobix.co.uk:8443")
ISSUER = os.environ.get("ISSUER", "https://access.truvity.xyz")
CONTEXT = os.environ.get("CONTEXT", "kernel@oidc")
PORT = 9223


def api(path, method="GET", body=None):
    request = urllib.request.Request(SUITE + path, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
        body = json.dumps(body).encode()
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(request, body, context=ctx, timeout=30) as response:
        raw = response.read().decode()
    return json.loads(raw) if raw else {}


def proof():
    """A fresh recovery token. Minted per sign-in and never stored."""
    return subprocess.run(
        ["kubectl", "--context", CONTEXT, "-n", "access-issuer", "create", "token",
         "access-issuer-recovery", "--audience", "access-issuer-recovery",
         "--duration", "10m"],
        capture_output=True, text=True, check=True).stdout.strip()


class CDP:
    """The smallest DevTools client that can drive a page."""

    def __init__(self, ws_url):
        import socket
        host, rest = ws_url.split("://", 1)[1].split("/", 1)
        hostname, port = host.split(":")
        self.sock = socket.create_connection((hostname, int(port)))
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            ("GET /%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
             "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n\r\n" % (rest, host, key)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.sock.recv(1)
        self.n = 0

    def _send(self, payload):
        data = payload.encode()
        mask = os.urandom(4)
        length = len(data)
        header = b"\x81"
        if length < 126:
            header += bytes([0x80 | length])
        elif length < (1 << 16):
            header += bytes([0x80 | 126]) + struct.pack(">H", length)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", length)
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _recv(self):
        def read(n):
            out = b""
            while len(out) < n:
                chunk = self.sock.recv(n - len(out))
                if not chunk:
                    raise IOError("closed")
                out += chunk
            return out
        first = read(2)
        length = first[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", read(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", read(8))[0]
        return read(length).decode()

    def call(self, method, params=None, timeout=60):
        self.n += 1
        self._send(json.dumps({"id": self.n, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            message = json.loads(self._recv())
            if message.get("id") == self.n:
                if "error" in message:
                    raise RuntimeError("%s: %s" % (method, message["error"]))
                return message.get("result", {})
        raise TimeoutError(method)

    def eval(self, expression):
        result = self.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True})
        return result.get("result", {}).get("value")


def start_chrome():
    chrome = subprocess.Popen([
        "google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox",
        "--ignore-certificate-errors",
        "--remote-debugging-port=%d" % PORT,
        "--user-data-dir=/tmp/claude-1000/chrome-conformance",
        "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for _ in range(60):
        try:
            listed = json.load(urllib.request.urlopen(
                "http://127.0.0.1:%d/json/list" % PORT, timeout=5))
            pages = [t for t in listed if t["type"] == "page"]
            if pages:
                return chrome, CDP(pages[0]["webSocketDebuggerUrl"])
        except Exception:
            pass
        time.sleep(0.5)
    chrome.terminate()
    sys.exit("chrome did not come up")


def visit(cdp, url):
    """Follow one URL the suite is waiting on, signing in if asked.

    Signing in means submitting the recovery form IN THE PAGE, so the
    browser follows the redirects itself and runs the callback's script —
    which is the whole reason this is a browser and not curl.
    """
    cdp.call("Page.navigate", {"url": url})
    time.sleep(2.5)

    for _ in range(3):
        here = cdp.eval("window.location.href") or ""
        if "/login" not in here or ISSUER not in here:
            return
        token = proof()
        filled = cdp.eval("""(() => {
          const form = document.querySelector('form[action="/login/recovery"]');
          if (!form) return 'no-form';
          const field = form.querySelector('input[name="proof"]');
          if (!field) return 'no-field';
          field.value = %s;
          form.submit();
          return 'submitted';
        })()""" % json.dumps(token))
        if filled != "submitted":
            print("      sign-in: %s" % filled)
            return
        time.sleep(3.5)


def run(cdp, plan, module):
    started = api("/api/runner?test=%s&plan=%s" % (module, plan), method="POST")
    test = started.get("id")
    if not test:
        return "NOT-STARTED", ""

    seen = set()
    for _ in range(40):
        info = api("/api/info/%s" % test)
        status = info.get("status")
        if status in ("FINISHED", "INTERRUPTED"):
            break

        for url in api("/api/runner/browser/%s" % test).get("urls") or []:
            if url in seen:
                continue
            seen.add(url)
            visit(cdp, url)

        time.sleep(2)

    info = api("/api/info/%s" % test)
    return info.get("result") or info.get("status") or "?", test


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("plan")
    parser.add_argument("--from", dest="start")
    parser.add_argument("--only")
    args = parser.parse_args()

    modules = [m["testModule"] for m in api("/api/plan/%s" % args.plan).get("modules", [])]
    if not modules:
        sys.exit("plan %s has no modules" % args.plan)
    if args.only:
        modules = [m for m in modules if m == args.only]
    if args.start:
        modules = modules[modules.index(args.start):] if args.start in modules else modules

    print("plan %s: %d module(s)\n" % (args.plan, len(modules)))
    chrome, cdp = start_chrome()
    cdp.call("Page.enable")

    results = {}
    try:
        for i, module in enumerate(modules, 1):
            result, test = run(cdp, args.plan, module)
            results[module] = result
            mark = "  " if result in ("PASSED", "WARNING") else "**"
            print("%s %2d/%d %-10s %s%s" % (
                mark, i, len(modules), result, module,
                "" if result in ("PASSED", "WARNING") else
                "   %s/log-detail.html?log=%s" % (SUITE, test)))
    finally:
        chrome.terminate()

    print()
    counts = {}
    for result in results.values():
        counts[result] = counts.get(result, 0) + 1
    print("  ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())))
    print("plan: %s/plan-detail.html?plan=%s" % (SUITE, args.plan))
    json.dump(results, open("/tmp/conformance-%s.json" % args.plan, "w"), indent=1)

    sys.exit(0 if all(r in ("PASSED", "WARNING") for r in results.values()) else 1)


if __name__ == "__main__":
    main()
