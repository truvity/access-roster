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
import urllib.parse
import urllib.error
import urllib.request

SUITE = os.environ.get("SUITE", "https://localhost.emobix.co.uk:8443")
ISSUER = os.environ.get("ISSUER", "https://access.truvity.xyz")
CONTEXT = os.environ.get("CONTEXT", "kernel@oidc")
# How to run kubectl, because reaching the cluster can need more than the
# binary. A context that authenticates through OIDC needs the
# `kubectl-oidc_login` credential plugin on PATH, and when it is missing
# kubectl says so only once its cached token expires -- so the driver
# runs for a while and then dies mid-plan. Point this at a wrapper that
# has the plugin.
KUBECTL = os.environ.get("KUBECTL", "kubectl").split()
PORT = 9223


def api(path, method="GET", body=None, text=None):
    request = urllib.request.Request(SUITE + path, method=method)
    # The suite refuses any request not marked as having arrived over
    # HTTPS. Its nginx sets this in front of it; reached at the ClusterIP
    # over the tailnet there is no nginx, so the caller says it. Harmless
    # when the suite really is behind TLS.
    request.add_header("X-Forwarded-Proto", "https")
    if text is not None:
        request.add_header("Content-Type", "text/plain")
        body = text.encode()
    elif body is not None:
        request.add_header("Content-Type", "application/json")
        body = json.dumps(body).encode()
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Retried, because the suite is briefly unresponsive while it
    # interrupts a test -- which is exactly when the driver is asking it
    # what happened. One such timeout used to abort the whole plan, with
    # the modules after it never run.
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, body, context=ctx, timeout=30) as response:
                raw = response.read().decode()
            return json.loads(raw) if raw else {}
        except (urllib.error.URLError, TimeoutError, ConnectionError) as failed:
            last = failed
            if isinstance(failed, urllib.error.HTTPError) and failed.code < 500:
                raise
            time.sleep(2 * (attempt + 1))
    raise last


def proof():
    """A fresh recovery token. Minted per sign-in and never stored."""
    minted = subprocess.run(
        KUBECTL + ["--context", CONTEXT, "-n", "access-issuer", "create", "token",
                   "access-issuer-recovery", "--audience", "access-issuer-recovery",
                   "--duration", "10m"],
        capture_output=True, text=True)
    if minted.returncode != 0:
        # The reason, not just the exit status: this fails for exactly
        # one boring reason -- the cluster credential expired mid-run --
        # and a traceback that hides kubectl's own sentence sends you
        # looking at the driver instead of at `kubectl`.
        sys.exit("could not mint a recovery token:\n%s" % minted.stderr.strip())
    return minted.stdout.strip()


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


class Passed(list):
    """Issuer pages passed through, and how long we have waited to use one.

    A plain list would be answered with immediately, which is wrong: the
    page a step asks about is usually the one the browser is ABOUT to
    reach, not the one it last left. `patient` is how many rounds have
    gone by with a step outstanding and the browser not on the issuer --
    long enough means it is never going to arrive, which is the
    re-authentication case.
    """

    rounds = 0

    def patient(self):
        self.rounds += 1
        return self.rounds > 3


def shoot(cdp):
    """One screenshot of the page as it stands, as a data URI."""
    return "data:image/png;base64," + cdp.call(
        "Page.captureScreenshot", {"format": "png"}).get("data", "")


def visit(cdp, url, pages=None):
    """Follow one URL the suite is waiting on, signing in if asked.

    Signing in means submitting the recovery form IN THE PAGE, so the
    browser follows the redirects itself and runs the callback's script —
    which is the whole reason this is a browser and not curl.

    `pages` collects a screenshot of every ISSUER page passed through,
    because some steps ask for a picture of one the driver does not stop
    on — see [review].
    """
    cdp.call("Page.navigate", {"url": url})
    time.sleep(2.5)

    for _ in range(3):
        here = cdp.eval("window.location.href") or ""
        if pages is not None and here.startswith(ISSUER):
            pages.append((here, shoot(cdp)))
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


def review(cdp, test, seen, pages):
    """Answer the suite's manual steps with what the browser is showing.

    A third of the logout modules end at a page the suite CANNOT see: the
    OP must refuse, so there is no redirect back and no callback. The
    suite asks a human for a screenshot and waits. Unanswered, the module
    sits in WAITING until the next one interrupts it, which is what a row
    of eight greyed-out logout results was — not a server fault, a step
    nobody had performed.

    A screenshot is exactly what a browser has. So the driver takes it,
    fills the placeholder, and marks the URL visited so the suite stops
    waiting on a callback that is not coming.

    WHICH PAGE to photograph is the whole of the difficulty, and there
    are two kinds of step.

    The logout steps end ON the page in question: the OP must refuse, so
    the browser stops at the issuer's error page and stays there. But the
    suite logs its review BEFORE handing over the end_session URL, so a
    driver that shoots the moment the placeholder appears photographs the
    suite's own "processing response" page -- which the first run of this
    uploaded, eight identical times.

    The RE-AUTHENTICATION steps (`prompt=login`, `max_age=1`) ask for a
    picture of a page the driver does not stop on at all: the login
    prompt during the second authorization, which it fills in and leaves.
    By the time the placeholder is logged the browser is back on the
    suite's callback. So every issuer page passed through is photographed
    on the way, and the latest one answers.
    """
    outstanding = [e for e in api("/api/log/%s" % test)
                   if e.get("upload") and e.get("upload") not in seen]
    if not outstanding:
        return False

    here = cdp.eval("window.location.href") or ""
    if here.startswith(ISSUER):
        where, shot = here, shoot(cdp)
    elif pages and pages.patient():
        # WAITED FIRST, and this is the whole of the difficulty. The
        # suite logs its review step BEFORE handing over the URL the step
        # is about, so at that moment the browser is still back on the
        # suite's callback -- and answering then with the last issuer
        # page means answering with the SIGN-IN page from the
        # authorization that preceded it.
        #
        # That is not hypothetical: it made ten of twelve screenshots
        # byte-identical pictures of the sign-in page, evidence of
        # nothing, and only a person looking at them caught it.
        #
        # So the current page wins, and a remembered one is used only
        # after the browser has had rounds to arrive and has not -- which
        # is the re-authentication case, where the page asked about is
        # one the driver fills in and leaves.
        where, shot = pages[-1]
    else:
        return False

    for entry in outstanding:
        seen.add(entry["upload"])
        api("/api/log/%s/images/%s" % (test, entry["upload"]), method="POST", text=shot)
        # The path, not the URL: these carry a whole id_token_hint and
        # a state of deliberate punctuation, and a screen of that buries
        # the one thing the line is for.
        print("      screenshot of %s for: %s" % (
            where[len(ISSUER):].split("?")[0] or "/", str(entry.get("msg"))[:80]))
    return True


def attend(plan, module, patience=600):
    """Start one module and hand the browser step to a PERSON.

    Recovery signs in with no name and no email -- deliberately, it is
    the break-glass path -- so four Basic OP modules warn that userinfo
    carries no profile or email claims. Nothing in the issuer is wrong
    there: the claims cannot exist for that identity. Clearing those
    warnings needs a sign-in by somebody who HAS a name, which is a
    person at a Google prompt and cannot be automated.

    So this starts the module and gets out of the way: it prints the URL,
    waits, and reports what the suite concluded.
    """
    started = api("/api/runner?test=%s&plan=%s" % (module, plan), method="POST")
    test = started.get("id")
    if not test:
        return "NOT-STARTED", ""

    print("\n  %s" % module)
    shown, waited = set(), 0
    while waited < patience:
        info = api("/api/info/%s" % test)
        if info.get("status") in ("FINISHED", "INTERRUPTED"):
            break

        for url in api("/api/runner/browser/%s" % test).get("urls") or []:
            if url not in shown:
                shown.add(url)
                print("\n  OPEN THIS AND SIGN IN WITH GOOGLE:\n    %s\n" % url)

        time.sleep(5)
        waited += 5

    info = api("/api/info/%s" % test)
    return info.get("result") or info.get("status") or "?", test


def run(cdp, plan, module):
    # A FRESH BROWSER for every module, which several of them require in
    # so many words: "please remove any cookies you may have received
    # from the OpenID Provider before proceeding".
    #
    # Without this the driver carries one sign-in through the whole plan
    # and `oidcc-prompt-none-not-logged-in` fails — the issuer is asked
    # whether anybody is signed in, a live session says yes, and it
    # completes silently, which is CORRECT behaviour being marked as a
    # defect. The modules that need a session establish it themselves.
    # SIGN OUT first, then clear. Clearing alone drops the cookie and
    # leaves the sign-in RECORD alive at the issuer, so a thirty-five
    # module plan abandons thirty-five of them -- which is how one
    # recovery account came to hold 104 open sign-ins and fill the
    # console's Sessions page with its own litter.
    try:
        cdp.call("Page.navigate", {"url": ISSUER + "/logout"})
        time.sleep(1.5)
    except Exception:
        pass

    cdp.call("Network.clearBrowserCookies")

    started = api("/api/runner?test=%s&plan=%s" % (module, plan), method="POST")
    test = started.get("id")
    if not test:
        return "NOT-STARTED", ""

    seen, filled, pages = set(), set(), Passed()
    for _ in range(40):
        info = api("/api/info/%s" % test)
        status = info.get("status")
        if status in ("FINISHED", "INTERRUPTED"):
            break

        urls = api("/api/runner/browser/%s" % test).get("urls") or []
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            visit(cdp, url, pages)

        # Only after the browser has been somewhere: the screenshot has
        # to be of the page the step asked about.
        if seen and review(cdp, test, filled, pages):
            for url in urls:
                api("/api/runner/browser/%s/visit?url=%s" % (
                    test, urllib.parse.quote(url, safe="")), method="POST")

        time.sleep(2)

    info = api("/api/info/%s" % test)
    return info.get("result") or info.get("status") or "?", test


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("plan")
    parser.add_argument("--from", dest="start")
    parser.add_argument("--only")
    parser.add_argument("--manual", action="store_true",
                        help="print the URL and wait for a PERSON to sign in")
    args = parser.parse_args()

    modules = [m["testModule"] for m in api("/api/plan/%s" % args.plan).get("modules", [])]
    if not modules:
        sys.exit("plan %s has no modules" % args.plan)
    if args.only:
        modules = [m for m in modules if m == args.only]
    if args.start:
        modules = modules[modules.index(args.start):] if args.start in modules else modules

    print("plan %s: %d module(s)\n" % (args.plan, len(modules)))

    if args.manual:
        results = {}
        for module in modules:
            result, test = attend(args.plan, module)
            results[module] = result
            print("  %-10s %s   %s/log-detail.html?log=%s" % (result, module, SUITE, test))
        sys.exit(0 if all(r in ("PASSED", "WARNING", "REVIEW") for r in results.values()) else 1)

    chrome, cdp = start_chrome()
    cdp.call("Page.enable")
    cdp.call("Network.enable")

    results = {}
    try:
        for i, module in enumerate(modules, 1):
            result, test = run(cdp, args.plan, module)
            results[module] = result
            # REVIEW is not a failure: it is the suite saying a human
            # must look at the evidence attached to it. The driver has
            # attached that evidence, so the module is as done as it can
            # be without a person -- flagged, because a person still has
            # to sign it off, but not marked as broken.
            mark = {"PASSED": "  ", "WARNING": "  ", "REVIEW": "??"}.get(result, "**")
            print("%s %2d/%d %-10s %s%s" % (
                mark, i, len(modules), result, module,
                "" if mark == "  " else
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

    sys.exit(0 if all(r in ("PASSED", "WARNING", "REVIEW") for r in results.values()) else 1)


if __name__ == "__main__":
    main()
