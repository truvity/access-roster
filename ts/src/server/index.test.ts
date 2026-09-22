/// <reference types="node" />
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { exportJWK, generateKeyPair, SignJWT, UnsecuredJWT, type JWTPayload } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  Issuer,
  IssuerUnreachable,
  Unverified,
  identityOf,
  middleware,
  parseServiceAccountSubject,
  requireGroups,
  tokenFrom,
  whoami,
  whoamiPath,
} from "./index.js";

type Key = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

/** An issuer in miniature: discovery naming itself, and one key set. */
async function listen(handler: (request: IncomingMessage, response: ServerResponse) => void): Promise<{ server: Server; url: string }> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { server, url: `http://127.0.0.1:${port}` };
}

let issuer: { server: Server; url: string };
let signing: Key;
let stranger: Key;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  signing = pair.privateKey;
  stranger = (await generateKeyPair("RS256")).privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: "one", alg: "RS256", use: "sig" };

  issuer = await listen((request, response) => {
    response.setHeader("Content-Type", "application/json");
    if (request.url === "/.well-known/openid-configuration") {
      response.end(JSON.stringify({ issuer: issuer.url, jwks_uri: `${issuer.url}/keys`, id_token_signing_alg_values_supported: ["RS256"] }));
      return;
    }
    if (request.url === "/keys") {
      response.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    response.statusCode = 404;
    response.end("{}");
  });
});

afterAll(() => {
  issuer.server.close();
});

async function mint(
  claims: JWTPayload,
  options: { key?: Key; audience?: string; issuer?: string; alg?: string; kid?: string } = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: options.alg ?? "RS256", kid: options.kid ?? "one" })
    .setIssuer(options.issuer ?? issuer.url)
    .setAudience(options.audience ?? "url-shortener-devel")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(options.key ?? signing);
}

const person: JWTPayload = {
  sub: "ada@north.example",
  email: "Ada@North.example",
  name: "Ada Lovelace",
  given_name: "Ada",
  family_name: "Lovelace",
  groups: ["all:access-roster:viewer", "devel:url-shortener:deployer"],
};

describe("Issuer", () => {
  it("returns the person a token names, with the names the directory gave", async () => {
    const verifier = new Issuer({ url: issuer.url, audience: "url-shortener-devel" });
    const who = await verifier.verify(await mint(person));

    expect(who).toEqual({
      subject: "ada@north.example",
      email: "ada@north.example",
      name: "Ada Lovelace",
      givenName: "Ada",
      familyName: "Lovelace",
      groups: ["all:access-roster:viewer", "devel:url-shortener:deployer"],
    });
  });

  // A token minted for another service is valid; taking it would make every
  // audience the issuer serves a way in.
  it("refuses a token minted for another audience", async () => {
    const verifier = new Issuer({ url: issuer.url, audience: "url-shortener-devel" });
    await expect(verifier.verify(await mint(person, { audience: "acme-devel" }))).rejects.toBeInstanceOf(Unverified);
  });

  it("refuses a token signed with a key the issuer does not publish", async () => {
    const verifier = new Issuer({ url: issuer.url, audience: "url-shortener-devel" });
    await expect(verifier.verify(await mint(person, { key: stranger }))).rejects.toBeInstanceOf(Unverified);
  });

  it("refuses a token another issuer signed with a key it happens to hold", async () => {
    const verifier = new Issuer({ url: issuer.url, audience: "url-shortener-devel" });
    await expect(verifier.verify(await mint(person, { issuer: "https://elsewhere.example" }))).rejects.toBeInstanceOf(Unverified);
  });

  it("names nobody for a workload, and says which cluster vouched for it", async () => {
    const verifier = new Issuer({ url: issuer.url, audience: "url-shortener-devel" });
    const who = await verifier.verify(await mint({ sub: "stage:k8s:builds:runner", groups: ["stage:k8s:exchange-probe"] }));

    expect(who.email).toBeUndefined();
    expect(who.name).toBeUndefined();
    expect(who.serviceAccount).toEqual({ cluster: "stage", namespace: "builds", name: "runner" });
  });

  // An outage is not the caller's fault. Answering it as a bad token would
  // send a legitimate caller back to sign in, repeatedly, for nothing.
  it("reports an unreachable issuer as that, not as a bad token, and asks again next time", async () => {
    let reachable = false;
    const flaky: typeof fetch = async (input, init) => {
      if (!reachable) throw new TypeError("fetch failed");
      return fetch(input, init);
    };
    const verifier = new Issuer({ url: issuer.url, audience: "url-shortener-devel", fetch: flaky });
    const token = await mint(person);

    await expect(verifier.verify(token)).rejects.toBeInstanceOf(IssuerUnreachable);

    reachable = true;
    await expect(verifier.verify(token)).resolves.toMatchObject({ subject: "ada@north.example" });
  });

  it("will not trust keys from a discovery document naming another issuer", async () => {
    const liar = await listen((_request, response) => {
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ issuer: "https://someone-else.example", jwks_uri: `${issuer.url}/keys` }));
    });
    try {
      const verifier = new Issuer({ url: liar.url, audience: "url-shortener-devel" });
      await expect(verifier.verify(await mint(person, { issuer: liar.url }))).rejects.toBeInstanceOf(IssuerUnreachable);
    } finally {
      liar.server.close();
    }
  });

  it("will not be built without an audience", () => {
    expect(() => new Issuer({ url: issuer.url, audience: "" })).toThrow(/audience/);
  });
});

// The chart's default key is P-384, so a default install signs ES384. A
// verifier that pinned RS256 refused every one of its tokens; this one
// takes the algorithms discovery advertises, as Go's does.
describe("Issuer and the signing algorithm", () => {
  let ecdsa: Key;
  let rsa: Key;
  let keys: Record<string, unknown>[];

  /** An issuer holding both keys, advertising whichever algorithms it is told to. */
  async function issuerAdvertising(algorithms?: string[]): Promise<{ server: Server; url: string }> {
    const one = await listen((request, response) => {
      response.setHeader("Content-Type", "application/json");
      if (request.url === "/.well-known/openid-configuration") {
        const config: Record<string, unknown> = { issuer: one.url, jwks_uri: `${one.url}/keys` };
        if (algorithms) config.id_token_signing_alg_values_supported = algorithms;
        response.end(JSON.stringify(config));
        return;
      }
      response.end(JSON.stringify({ keys }));
    });
    return one;
  }

  beforeAll(async () => {
    const ec = await generateKeyPair("ES384");
    const rs = await generateKeyPair("RS256");
    ecdsa = ec.privateKey;
    rsa = rs.privateKey;
    keys = [
      { ...(await exportJWK(ec.publicKey)), kid: "p384", alg: "ES384", use: "sig" },
      { ...(await exportJWK(rs.publicKey)), kid: "rsa", alg: "RS256", use: "sig" },
    ];
  });

  it("verifies an ES384 token from an issuer that advertises ES384", async () => {
    const one = await issuerAdvertising(["ES384"]);
    try {
      const verifier = new Issuer({ url: one.url, audience: "url-shortener-devel" });
      const token = await mint(person, { issuer: one.url, key: ecdsa, alg: "ES384", kid: "p384" });
      await expect(verifier.verify(token)).resolves.toMatchObject({ subject: "ada@north.example" });
    } finally {
      one.server.close();
    }
  });

  it("refuses a token whose algorithm the issuer does not advertise, even with the key published", async () => {
    const one = await issuerAdvertising(["ES384"]);
    try {
      const verifier = new Issuer({ url: one.url, audience: "url-shortener-devel" });
      const token = await mint(person, { issuer: one.url, key: rsa, alg: "RS256", kid: "rsa" });
      await expect(verifier.verify(token)).rejects.toBeInstanceOf(Unverified);
    } finally {
      one.server.close();
    }
  });

  it("falls back to what the issuer can sign with when discovery advertises nothing", async () => {
    const one = await issuerAdvertising(undefined);
    try {
      const verifier = new Issuer({ url: one.url, audience: "url-shortener-devel" });
      const es = await mint(person, { issuer: one.url, key: ecdsa, alg: "ES384", kid: "p384" });
      const rs = await mint(person, { issuer: one.url, key: rsa, alg: "RS256", kid: "rsa" });
      await expect(verifier.verify(es)).resolves.toMatchObject({ subject: "ada@north.example" });
      await expect(verifier.verify(rs)).resolves.toMatchObject({ subject: "ada@north.example" });
    } finally {
      one.server.close();
    }
  });

  it("lets a caller narrow to fewer algorithms than the issuer advertises", async () => {
    const one = await issuerAdvertising(["ES384", "RS256"]);
    try {
      const verifier = new Issuer({ url: one.url, audience: "url-shortener-devel", algorithms: ["ES384"] });
      const es = await mint(person, { issuer: one.url, key: ecdsa, alg: "ES384", kid: "p384" });
      const rs = await mint(person, { issuer: one.url, key: rsa, alg: "RS256", kid: "rsa" });
      await expect(verifier.verify(es)).resolves.toMatchObject({ subject: "ada@north.example" });
      await expect(verifier.verify(rs)).rejects.toBeInstanceOf(Unverified);
    } finally {
      one.server.close();
    }
  });

  it("ignores an advertised `none` or HMAC algorithm rather than accepting it", async () => {
    const one = await issuerAdvertising(["none", "HS256", "ES384"]);
    try {
      const verifier = new Issuer({ url: one.url, audience: "url-shortener-devel" });
      const es = await mint(person, { issuer: one.url, key: ecdsa, alg: "ES384", kid: "p384" });
      await expect(verifier.verify(es)).resolves.toMatchObject({ subject: "ada@north.example" });
      const unsigned = new UnsecuredJWT(person).setIssuer(one.url).setAudience("url-shortener-devel").setIssuedAt().setExpirationTime("5m").encode();
      await expect(verifier.verify(unsigned)).rejects.toBeInstanceOf(Unverified);
    } finally {
      one.server.close();
    }
  });

  it("will not be built to accept `none`", () => {
    expect(() => new Issuer({ url: issuer.url, audience: "x", algorithms: ["none"] })).toThrow(/none/);
    expect(() => new Issuer({ url: issuer.url, audience: "x", algorithms: [] })).toThrow(/at least one/);
  });
});

describe("parseServiceAccountSubject", () => {
  it("reads every form Go's policy reads, and nothing else", () => {
    expect(parseServiceAccountSubject("system:serviceaccount:ns:sa")).toEqual({ cluster: "", namespace: "ns", name: "sa" });
    expect(parseServiceAccountSubject("k8s:ns:sa")).toEqual({ cluster: "", namespace: "ns", name: "sa" });
    expect(parseServiceAccountSubject("devel:k8s:ns:sa")).toEqual({ cluster: "devel", namespace: "ns", name: "sa" });
    expect(parseServiceAccountSubject("ada@north.example")).toBeUndefined();
    expect(parseServiceAccountSubject("devel:k8s::sa")).toBeUndefined();
  });
});

describe("tokenFrom", () => {
  it("prefers the proxy's header, and reads a bearer of either case", () => {
    expect(tokenFrom({ "x-auth-request-access-token": "forwarded", authorization: "Bearer bearer" })).toBe("forwarded");
    expect(tokenFrom({ authorization: "bearer lower" })).toBe("lower");
    expect(tokenFrom(new Headers({ Authorization: "Bearer from-headers" }))).toBe("from-headers");
    expect(tokenFrom({ authorization: "Basic dXNlcg==" })).toBe("");
  });
});

// Over a real listener: the middleware establishes, the guard refuses, and
// whoami answers the body Go's WhoAmI writes.
describe("middleware, requireGroups and whoami", () => {
  let app: { server: Server; url: string };

  beforeAll(async () => {
    const verifier = new Issuer({ url: issuer.url, audience: "url-shortener-devel" });
    const establish = middleware(verifier);
    const onlyDeployers = requireGroups("devel:url-shortener:deployer");
    const onlyAdmins = requireGroups("devel:k8s:admin");
    const answer = whoami("1.2.3");

    app = await listen((request, response) => {
      void establish(request, response, () => {
        if (request.url === whoamiPath) return answer(request, response);
        const guard = request.url === "/admin" ? onlyAdmins : onlyDeployers;
        guard(request, response, () => {
          response.end(`hello ${identityOf(request)?.name ?? ""}`);
        });
      });
    });
  });

  afterAll(() => {
    app.server.close();
  });

  it("answers signed-out rather than refusing, with nobody established", async () => {
    const response = await fetch(`${app.url}${whoamiPath}`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "signed-out", version: "1.2.3" });
  });

  it("answers the caller, with the keys the browser package reads", async () => {
    const token = await mint(person);
    const response = await fetch(`${app.url}${whoamiPath}`, { headers: { Authorization: `Bearer ${token}` } });
    expect(await response.json()).toEqual({
      status: "signed-in",
      version: "1.2.3",
      sub: "ada@north.example",
      email: "ada@north.example",
      name: "Ada Lovelace",
      givenName: "Ada",
      familyName: "Lovelace",
      groups: ["all:access-roster:viewer", "devel:url-shortener:deployer"],
    });
  });

  it("refuses nobody with 401, the wrong groups with 403, and lets the right ones through", async () => {
    const token = await mint(person);
    const bearer = { Authorization: `Bearer ${token}` };

    expect((await fetch(`${app.url}/`)).status).toBe(401);
    expect((await fetch(`${app.url}/admin`, { headers: bearer })).status).toBe(403);

    const allowed = await fetch(`${app.url}/`, { headers: bearer });
    expect(allowed.status).toBe(200);
    expect(await allowed.text()).toBe("hello Ada Lovelace");
  });

  it("establishes nobody for a token that does not verify, and does not throw", async () => {
    const forged = await mint(person, { key: stranger });
    const response = await fetch(`${app.url}${whoamiPath}`, { headers: { Authorization: `Bearer ${forged}` } });
    expect(await response.json()).toMatchObject({ status: "signed-out" });
  });
});
