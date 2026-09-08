import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchIdentity, whoamiPath } from "./identity.js";

function answering(response: Response | Error) {
  return vi.fn(async () => {
    if (response instanceof Error) throw response;
    return response;
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchIdentity", () => {
  it("reports the caller the application knows", async () => {
    const fetch = answering(
      json({
        status: "signed-in",
        email: "ada@north.example",
        name: "Ada North",
        roles: ["operator", "viewer"],
        signOutUrl: "/logout",
        version: "0.2.0",
      }),
    );
    vi.stubGlobal("fetch", fetch);

    const me = await fetchIdentity();
    expect(me.status).toBe("signed-in");
    expect(me.email).toBe("ada@north.example");
    expect(me.roles).toEqual(["operator", "viewer"]);
    expect(me.signOutUrl).toBe("/logout");

    // Same-origin credentials, or the cookie the application set never
    // arrives and every caller looks signed out.
    expect(fetch).toHaveBeenCalledWith(whoamiPath, expect.objectContaining({ credentials: "same-origin" }));
  });

  it("treats a refusal as an answer", async () => {
    for (const status of [401, 403]) {
      vi.stubGlobal("fetch", answering(new Response("", { status })));
      expect((await fetchIdentity()).status).toBe("signed-out");
    }
    // And so is a 200 that says nobody is there.
    vi.stubGlobal("fetch", answering(json({ status: "signed-out", version: "0.2.0" })));
    expect((await fetchIdentity()).status).toBe("signed-out");
  });

  // The distinction this package exists to keep. A console that showed a
  // sign-in button because one request failed would send a signed-in
  // person to authenticate again for nothing.
  it("does not mistake being unable to ask for being signed out", async () => {
    vi.stubGlobal("fetch", answering(new TypeError("Failed to fetch")));
    const offline = await fetchIdentity();
    expect(offline.status).toBe("unknown");
    expect(offline.error).toContain("Failed to fetch");

    vi.stubGlobal("fetch", answering(new Response("", { status: 502 })));
    const broken = await fetchIdentity();
    expect(broken.status).toBe("unknown");
    expect(broken.error).toContain("502");
  });

  it("stays quiet when the caller went away", async () => {
    vi.stubGlobal(
      "fetch",
      answering(new DOMException("The operation was aborted.", "AbortError")),
    );
    // Not an answer and not an error to show: the component unmounted.
    expect((await fetchIdentity()).status).toBe("loading");
  });

  it("asks where the application says to", async () => {
    const fetch = answering(json({ status: "signed-out" }));
    vi.stubGlobal("fetch", fetch);
    await fetchIdentity({ path: "/api/whoami" });
    expect(fetch).toHaveBeenCalledWith("/api/whoami", expect.anything());
  });
});
