#!/usr/bin/env python3
"""Walk Kargo through sign-in, its own Logout, and a revoke.

Kargo is the one relying party here that runs the code flow ITSELF: a
single-page application, PKCE in the browser, tokens in localStorage,
no proxy in front. So what it promises is different from what a
proxied console promises, and this asserts what it actually does:

  1. a clean visit shows Kargo's login page with one SSO button
  2. that button signs in through the issuer and lands on the projects
     page; a hard reload and a fresh visit to the root keep the session
     and open NOTHING new at the issuer -- the two things once reported
     as "the page shows SSO Login" and "refresh opens a new session"
  3. Kargo's own Logout drops its tokens and nothing else: the issuer
     session and the sign-in both stand, and the next SSO click is
     admitted with no password. Kargo has no RP-initiated logout (there
     is no end_session anywhere in its source), so this is what its
     button means. Ending the sign-in is the console's Sign out.
  4. a REVOKED session stops Kargo within `ttl_cap`: it serves on its
     access token until Kargo next renews, the renewal is refused, and
     Kargo drops its tokens and shows the login page. Nothing replaces
     the session, because unlike a proxy Kargo does not start a new
     authorization on its own.

The known Kargo defect is asserted as known, not as a failure: after a
SILENT sign-in -- one the standing issuer sign-in admits without a
prompt, which is what follows its own Logout -- Kargo stores the tokens
and stays on `/login?code=...` showing the SSO button, because its
callback navigates only when a `redirectTo` was carried and Logout
lands on `/login` without one (ui/src/features/auth/oidc-login.tsx).
Opening the root shows the projects. Reloading that URL replays the
code, which the issuer refuses and, correctly, punishes by revoking
what the code issued.

Usage:
  hack/verify_kargo.py [https://kargo.example]

Sign-in is RECOVERY, and only the recovery identity's sessions are
counted or ended -- the console is live, and other people's sessions
on it are not this script's to touch.
"""

import importlib.util
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drive = load("conformance_drive")
console = load("verify_console")


def main():
    host = (sys.argv[1] if len(sys.argv) > 1 else "https://kargo.kernel.truvity.xyz").rstrip("/")
    watcher = console.Observer()
    chrome, cdp = drive.start_chrome()
    passed = []
    ok = console.ok

    def root():
        cdp.call("Page.navigate", {"url": host + "/"})
        time.sleep(7)

    def url():
        return cdp.eval("window.location.href") or ""

    def text():
        return cdp.eval("document.body.innerText") or ""

    def has_tokens():
        return bool(cdp.eval("!!localStorage.getItem('auth_token')"))

    def projects_shown():
        return "PROJECTS" in text() and "/login" not in url()

    def click(pattern):
        return cdp.eval("""(() => {
          const e = [...document.querySelectorAll('button,a,[role=menuitem]')]
            .find(e => new RegExp(%s, 'i').test((e.innerText || '').trim()));
          if (!e) return 'no-such-control'; e.click(); return 'clicked';
        })()""" % repr(pattern))

    def mine():
        return watcher.sessions("kargo")

    try:
        cdp.call("Page.enable")
        cdp.call("Network.enable")
        cdp.call("Network.clearBrowserCookies")
        cdp.call("Network.setCacheDisabled", {"cacheDisabled": True})

        print("\n1. a clean visit shows Kargo's login page")
        root()
        passed.append(ok("/login" in url() and "SSO Login" in text(), "at %s" % url()[:70]))

        print("\n2. the SSO button signs in; reload and a fresh visit keep the session")
        before = len(mine())
        click("^SSO Login$")
        time.sleep(5)
        console.sign_in(cdp, url())
        time.sleep(7)
        root()
        passed.append(ok(projects_shown() and has_tokens(), "projects shown, tokens stored"))
        opened = len(mine())
        passed.append(ok(opened == before + 1, "the issuer lists %d new session(s), want 1" % (opened - before)))
        cdp.call("Page.reload", {"ignoreCache": True})
        time.sleep(7)
        passed.append(ok(projects_shown() and len(mine()) == opened, "a hard reload keeps the session and opens nothing"))
        root()
        passed.append(ok(projects_shown() and len(mine()) == opened, "a fresh visit to the root keeps it too"))

        print("\n3. Kargo's Logout drops its tokens and nothing else")
        click("^Logout$")
        time.sleep(5)
        passed.append(ok("/login" in url() and not has_tokens(), "tokens gone, at the login page"))
        passed.append(ok(len(mine()) == opened, "the issuer session still stands (%d)" % len(mine())))
        click("^SSO Login$")
        time.sleep(10)
        here = url()
        silent = "access.truvity.xyz/login" not in here and has_tokens()
        passed.append(ok(silent, "the next SSO click is admitted with no password"))
        if silent and "/login?code=" in here:
            print("  NOTE Kargo stayed on the callback URL showing its login page -- the known")
            print("       upstream defect; the projects are one visit to the root away")
        root()
        passed.append(ok(projects_shown(), "the root shows the projects"))

        print("\n4. a REVOKED session stops Kargo within ttl_cap, and nothing replaces it")
        held = mine()
        old = {s["id"] for s in held}
        ended = sum(watcher.revoke(s) for s in held)
        print("     %s revoked %d; Kargo serves on its access token until it next renews" % (
            time.strftime("%H:%M:%S"), ended))
        stopped, replaced, waited = False, False, 0
        while waited < 420:
            time.sleep(30)
            waited += 30
            root()
            now = {s["id"] for s in mine()}
            if now - old:
                replaced = True
                break
            if "/login" in url() and not has_tokens():
                stopped = True
                break
            print("       %s still serving after %ds" % (time.strftime("%H:%M:%S"), waited))
        passed.append(ok(stopped and not replaced,
                         "Kargo dropped its tokens and asks again, %ds after the revoke" % waited if stopped
                         else "a NEW session replaced the revoked one: silent re-admission" if replaced
                         else "STILL serving after %ds" % waited))
    finally:
        chrome.terminate()

    print("\n%d of %d checks passed" % (sum(passed), len(passed)))
    sys.exit(0 if all(passed) else 1)


if __name__ == "__main__":
    main()
