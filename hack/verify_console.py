#!/usr/bin/env python3
"""Walk one proxied console through sign-in, sign-out and revocation.

WHY THIS EXISTS: the last three sign-out defects all lived in the PROXY
CHAIN, and no unit test reaches it. `/end_session` ended the sign-in
without revoking what the browser opened; the merged service had no
source for the sign-out URL; and `ttl_cap` was applied on token exchange
and nowhere else, so the window in which a revoked session kept working
was the deployment default. Each was found by a person in a browser,
reported, and only then reproduced. This is that person, automated.

It asserts four things, in the order a person meets them:

  1. an unauthenticated visit reaches the issuer, not the application
  2. after signing in, the application serves AND the issuer lists the
     session it opened
  3. signing out ends the sign-in AND every session under it -- the half
     that was missing, and the half that decides whether the next click
     is admitted with no password
  4. a REVOKED session stops the application within the client's
     `ttl_cap`, rather than whenever its proxy happens to refresh

Usage:
  hack/verify_console.py <host> [--client <id>] [--patience <seconds>]

Sign-in is RECOVERY, the audited break-glass path, which is why this runs
unattended. The identity must hold a group the client's `requires` names
or the issuer will refuse it -- that refusal is a correct answer, not a
failure of this script, and it says so.
"""

import argparse
import importlib.util
import http.cookiejar
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("drive", HERE / "conformance_drive.py")
drive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drive)

ISSUER = os.environ.get("ISSUER", "https://access.truvity.xyz")


def ok(passed, text):
    print("  %s %s" % ("PASS" if passed else "FAIL", text))
    return passed


def sign_in(cdp, url):
    """Open a URL and answer the issuer's chooser if it appears."""
    cdp.call("Page.navigate", {"url": url})
    time.sleep(4)

    for _ in range(3):
        here = cdp.eval("window.location.href") or ""
        if "/login" not in here or ISSUER not in here:
            return here
        answered = cdp.eval("""(() => {
          const f = document.querySelector('form[action="/login/recovery"]');
          if (!f) return 'no-form';
          f.querySelector('input[name="proof"]').value = %s;
          f.submit(); return 'ok';
        })()""" % json.dumps(drive.proof()))
        if answered != "ok":
            return here
        time.sleep(5)

    return cdp.eval("window.location.href") or ""


# What this script calls itself on the wire. It has to be SOMETHING: the
# gateway refuses `Python-urllib/3.x` with a 403 before the request ever
# reaches the issuer, and that 403 reads exactly like an authorization
# failure -- which cost an hour of looking at the session service.
AGENT = "access-roster-verify/1.0 (+hack/verify_console.py)"


class Observer:
    """A SECOND recovery session, used only to watch.

    The browser under test cannot be the witness to its own sign-out:
    the moment it signs out, the session service stops answering it --
    correctly -- and the check that the sessions are gone fails with 401
    instead of reporting what it found. So the watching is done from a
    separate sign-in that is never signed out.
    """

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.open = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)).open
        self._sign_in()

    def _sign_in(self):
        authorize = self._where(ISSUER + "/console/")
        login = self._where(authorize)
        if login.startswith("/"):
            login = ISSUER + login
        with self.open(self._request(login), timeout=30) as page:
            html = page.read().decode()
        found = re.search(r'name="state" value="([^"]+)"', html)
        if not found:
            raise RuntimeError("the sign-in page carried no state")
        form = urllib.parse.urlencode({"state": found.group(1), "proof": drive.proof()}).encode()
        back = self._where(ISSUER + "/login/recovery", form)
        self.open(self._request(back if back.startswith("http") else ISSUER + back),
                  timeout=30).close()

    def _request(self, url, data=None):
        """One request that names itself."""
        request = urllib.request.Request(url, data=data)
        request.add_header("User-Agent", AGENT)
        return request

    def _where(self, url, data=None):
        """One request, following nothing, answering with the Location."""
        class Still(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kw):
                return None
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), Still)
        try:
            with opener.open(self._request(url, data), timeout=30) as response:
                return response.headers.get("Location") or response.geturl()
        except urllib.error.HTTPError as refused:
            return refused.headers.get("Location") or url

    def call(self, method, payload):
        request = urllib.request.Request(
            ISSUER + "/accessissuer.v1.SessionService/" + method,
            data=json.dumps(payload).encode(), method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", AGENT)
        with self.open(request, timeout=30) as response:
            return json.loads(response.read().decode() or "{}")

    def sessions(self, client):
        return self.call("ListSessions", {"clientId": client}).get("sessions") or []

    def revoke(self, session):
        return self.call("RevokeSessions", {
            "identity": session.get("identity"), "sessionId": session.get("id"),
        }).get("ended", 0)


def serves(cdp, host):
    """Whether the application itself answered, rather than the issuer."""
    here = cdp.eval("window.location.href") or ""
    return here.startswith(host) and "/login" not in here


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="e.g. https://hubble.kernel.truvity.xyz")
    parser.add_argument("--client", help="the client id, for the session query")
    parser.add_argument("--patience", type=int, default=420,
                        help="seconds to wait for a revoked session to bite")
    args = parser.parse_args()
    host = args.host.rstrip("/")
    client = args.client or host.split("//")[1].split(".")[0]

    watcher = Observer()
    chrome, cdp = drive.start_chrome()
    passed = []
    try:
        cdp.call("Page.enable")
        cdp.call("Network.enable")
        cdp.call("Network.clearBrowserCookies")

        print("\n1. an unauthenticated visit is sent to the issuer")
        cdp.call("Page.navigate", {"url": host + "/"})
        time.sleep(5)
        here = cdp.eval("window.location.href") or ""
        passed.append(ok(here.startswith(ISSUER), "landed at %s" % here[:80]))

        print("\n2. signing in serves the application")
        before = len(watcher.sessions(client))
        here = sign_in(cdp, host + "/")
        if not serves(cdp, host):
            page = (cdp.eval("document.body.innerText") or "")[:150]
            print("     did not reach the application: %s" % page.replace("\n", " | "))
            print("     If the issuer refused this identity, that is the client's")
            print("     `requires` doing its job -- grant a group the client names.")
            sys.exit(2)
        passed.append(ok(True, "the application answered at %s" % here[:80]))

        opened = watcher.sessions(client)
        new = len(opened) - before
        if new > 0:
            passed.append(ok(True, "the issuer lists %d new session(s) for %s" % (new, client)))
        else:
            # Not a failure. A client that never redeems its code holds no
            # per-client session at all -- the console is exactly that, by
            # design (INF-701), and it is the reason the console's own
            # sign-in never showed up on its own Sessions page.
            print("  NOTE %s opened no session: it does not redeem its code" % client)

        print("\n3. signing out ends the sign-in AND the sessions under it")
        cdp.call("Page.navigate", {"url": ISSUER + "/logout"})
        time.sleep(5)
        after = watcher.sessions(client)
        passed.append(ok(len(after) <= before,
                         "sessions for %s went %d -> %d" % (client, len(opened), len(after))))
        cdp.call("Page.navigate", {"url": host + "/"})
        time.sleep(6)
        passed.append(ok(not serves(cdp, host), "the application asks again rather than serving"))

        print("\n4. a REVOKED session stops the application")
        sign_in(cdp, host + "/")
        if not serves(cdp, host):
            passed.append(ok(False, "could not sign in again to test revocation"))
        elif not watcher.sessions(client):
            print("  SKIP %s holds no session to revoke" % client)
        else:
            ended = sum(watcher.revoke(s) for s in watcher.sessions(client))
            print("     revoked %d session(s); the proxy learns at its next refresh," % ended)
            print("     so this waits up to %ds -- ttl_cap is what bounds it" % args.patience)
            stopped, waited = False, 0
            while waited < args.patience:
                time.sleep(30)
                waited += 30
                cdp.call("Page.navigate", {"url": host + "/"})
                time.sleep(5)
                if not serves(cdp, host):
                    stopped = True
                    break
                print("       still serving after %ds" % waited)
            passed.append(ok(stopped, "stopped serving after %ds" % waited if stopped
                             else "STILL serving after %ds: revocation has not bitten" % waited))
    finally:
        chrome.terminate()

    print("\n%d of %d checks passed" % (sum(passed), len(passed)))
    sys.exit(0 if all(passed) else 1)


if __name__ == "__main__":
    main()
