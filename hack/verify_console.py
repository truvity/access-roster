#!/usr/bin/env python3
"""Walk one proxied console through sign-in, sign-out and revocation.

WHY THIS EXISTS: the last three sign-out defects all lived in the PROXY
CHAIN, and no unit test reaches it. `/end_session` ended the sign-in
without revoking what the browser opened; the merged service had no
source for the sign-out URL; and `ttl_cap` was applied on token exchange
and nowhere else, so the window in which a revoked session kept working
was the deployment default. Each was found by a person in a browser,
reported, and only then reproduced. This is that person, automated.

It asserts five things, in the order a person meets them:

  1. an unauthenticated visit reaches the issuer, not the application
  2. after signing in, the application serves AND the issuer lists the
     session it opened
  3. signing out THROUGH THE PROXY -- what the Sign out button does --
     ends the sign-in and every session under it, and the next visit
     asks again at once, because nothing is left to notice later
  4. signing out AT THE ISSUER -- the console's "Sign out all" -- stops
     the application within the proxy's refresh interval, because the
     issuer answers the next refresh with invalid_grant and oauth2-proxy
     treats that as fatal
  5. REVOKING one session with the sign-in left standing REPLACES it: the
     proxy's refresh fails, it starts a new sign-in, the standing sign-in
     admits it silently, and a fresh session appears where the old one
     was. Revoke is not sign-out, and the Sessions page says so.

The first version of this asserted that a sign-out at the issuer stops
a proxied console immediately, and that a revoke stops it at all. Both
were wrong about the design rather than about the code: the proxy's
cookie is on another host and survives an issuer sign-out, and a revoke
leaves the sign-in that admits the next visit. The run that showed it
had every issuer-side fact right and reported two failures anyway.

Usage:
  hack/verify_console.py <host> [--client <id>]

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
    """Whether the application itself answered, rather than the issuer.

    The proxy's own pages under /oauth2/ are not the application either:
    a browser caught mid-redirect on /oauth2/start is on its way to the
    issuer, and counting that as "served" turned a correct sign-out into
    a reported failure.
    """
    here = cdp.eval("window.location.href") or ""
    return here.startswith(host) and "/login" not in here and "/oauth2/" not in here


def settled(cdp, host, seconds=12):
    """Load the front page and wait for the redirect chain to finish."""
    cdp.call("Page.navigate", {"url": host + "/"})
    waited = 0
    while waited < seconds:
        time.sleep(3)
        waited += 3
        here = cdp.eval("window.location.href") or ""
        if "/oauth2/" not in here and not here.endswith("/authorize"):
            break
    return serves(cdp, host)


def stamp():
    return time.strftime("%H:%M:%S")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="e.g. https://hubble.kernel.truvity.xyz")
    parser.add_argument("--client", help="the client id, for the session query")
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

        print("\n3. signing out THROUGH THE PROXY ends everything, at once")
        # This is what a person's Sign out does: the proxy clears its own
        # cookie, then continues to the issuer's end_session, which ends
        # the sign-in and every session under it. Nothing is left to
        # notice later, so the next visit must ask again immediately.
        chain = "%s/oauth2/sign_out?rd=%s" % (host, urllib.parse.quote(
            "%s/end_session?client_id=%s&post_logout_redirect_uri=%s" % (
                ISSUER, client, urllib.parse.quote(host + "/", safe="")), safe=""))
        cdp.call("Page.navigate", {"url": chain})
        time.sleep(6)
        after = watcher.sessions(client)
        passed.append(ok(len(after) <= before,
                         "sessions for %s went %d -> %d" % (client, len(opened), len(after))))
        passed.append(ok(not settled(cdp, host), "the next visit asks again, immediately"))

        print("\n4. signing out AT THE ISSUER stops the application within cookie_refresh")
        # The console's "Sign out all", or the issuer's own /logout: the
        # issuer ends the sign-in and the sessions, but the proxy's cookie
        # is on another host and survives. The proxy learns when it next
        # refreshes -- which the chart sets to a minute -- and the issuer
        # answers invalid_grant, which oauth2-proxy treats as fatal and
        # clears the session. So this must bite in about a minute, not in
        # ttl_cap, and not at the cookie's own expiry.
        sign_in(cdp, host + "/")
        if not serves(cdp, host):
            passed.append(ok(False, "could not sign in again"))
        else:
            cdp.call("Page.navigate", {"url": ISSUER + "/logout"})
            time.sleep(5)
            print("     %s signed out at the issuer; polling the console" % stamp())
            stopped, waited = False, 0
            while waited < 150:
                time.sleep(15)
                waited += 15
                if not settled(cdp, host):
                    stopped = True
                    break
                print("       %s still serving after %ds" % (stamp(), waited))
            passed.append(ok(stopped, "stopped serving after %ds" % waited if stopped
                             else "STILL serving after %ds: the proxy did not refresh, or the "
                                  "issuer did not refuse" % waited))

        print("\n5. REVOKING one session, with the sign-in left standing, replaces it")
        # Revoke is not sign-out, and the Sessions page says so: ending a
        # session does not stop the next visit being admitted with no
        # password. So the honest expectation for a proxied console is
        # not that it stops -- it is that the proxy's next refresh fails,
        # it starts a new sign-in, the issuer admits it silently on the
        # standing sign-in, and a NEW session appears where the old one
        # was. What must not happen is the old session going on working.
        sign_in(cdp, host + "/")
        held = watcher.sessions(client)
        if not serves(cdp, host) or not held:
            passed.append(ok(False, "could not sign in again to test revocation"))
        else:
            old = {s_["id"] for s_ in held}
            ended = sum(watcher.revoke(s_) for s_ in held)
            print("     %s revoked %d session(s) %s" % (stamp(), ended, sorted(old)))
            replaced, waited = False, 0
            while waited < 150:
                time.sleep(15)
                waited += 15
                settled(cdp, host)
                now = {s_["id"] for s_ in watcher.sessions(client)}
                if not (now & old) and now:
                    replaced = True
                    break
                print("       %s after %ds: %d old still listed, %d new" % (
                    stamp(), waited, len(now & old), len(now - old)))
            passed.append(ok(replaced,
                             "the revoked session is gone and a fresh one stands in %ds" % waited
                             if replaced else
                             "after %ds the revoked session is still listed, or nothing replaced it" % waited))
    finally:
        chrome.terminate()

    print("\n%d of %d checks passed" % (sum(passed), len(passed)))
    sys.exit(0 if all(passed) else 1)


if __name__ == "__main__":
    main()
