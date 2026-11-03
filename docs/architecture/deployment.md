---
title: Deployment and listeners
description: "L3, enforcement per runtime: how IAM, key-holder, per-actor stores, systemd, nftables and Landlock hold each actor to its manifest, and what listens where."
status: target
sidebar:
  order: 3
---

The [permission manifest](/architecture/#the-permission-manifest-is-the-spine) says what each actor may do. This page says what enforces it on each [runtime](/runtimes/), what accepts connections and where, and what risk remains. The [tested installations](/runtimes/installations/) serve as the worked examples. The goal on every runtime is the baseline that one Lambda function per actor gives for free: one actor is one identity that the resources can see, and nothing else can act as it.

Two axes are enforced separately:

- **The runtime axis** decides who the process is and how the platform proves it.
- **The backend axis** decides what the resource can refuse on its own. A backend that can tell its callers apart is used with per-actor credentials and no mediator. Only a card on a node, or a key file in development, cannot, and `key-holder` owns it ([ADR 0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)).

## Enforcement per runtime

Every mechanism is generated from the manifests; none is written by hand.

| Runtime | Identity to cloud resources | Shared-driver ACLs | systemd sandboxing | nftables per uid | Landlock |
| ------- | --------------------------- | ------------------ | ------------------ | ---------------- | -------- |
| **bare-metal** (a board, a virtual machine, local Docker) | A workload JWT per actor, issued by the node agent from the actor's uid; on a cloud VM the instance role holds almost nothing | `key-holder` for a card on the node; an rqlite cluster with a user per actor for state; IAM and KMS key policies where they apply | Every unit (not in a container) | Default-deny egress with per-uid allow-lists, IMDS closed on a cloud VM, the named ports between peers on N nodes | Per actor where the kernel has it (5.13 or later) |
| **serverless** (AWS Lambda) | The function's execution role, one per actor. Calls between functions are authorized by a resource policy on an alias | None: IAM does the job | The platform's sandbox | Not available. A VPC route can cut `policy` off entirely | Optional, in process |
| **kubernetes** | A projected ServiceAccount token per container, one audience per actor, exchanged for a cloud role; EKS Pod Identity for a single-actor pod | None: KMS key policies. The socket volume mounted into the permitted callers is the first lock | `restricted` Pod Security, a security context per container | NetworkPolicy per pod, an egress policy per integration pod; Cilium optional for egress by FQDN | Optional |

The tested installations read as their runtime's row, with these details:

| Installation | What differs |
| ------------ | ------------ |
| **local** (bare-metal, Docker Compose on a workstation) | Software keys by default; nothing is production. A dedicated development card is opt-in: only the `key-holder` container reaches it, through the host's smart-card service, and `key-holder` has the card to itself ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). Containers run as their actors' uids and mount only the sockets their manifest allows; no systemd sandboxing, nftables or Landlock |
| **boards** (bare-metal, three single-board computers, a YubiKey per node) | `key-holder` for each node's card; one rqlite cluster per owning actor, with the Raft ports over mutual TLS between peers. No cloud credential for the board-only parts. Landlock is missing on the current board image's kernel, so the other layers carry the load ([Bare-metal](/runtimes/bare-metal/)) |
| **lambda**, **kubernetes** | As their runtime rows |

A bare-metal node on a cloud VM is a possible installation, not a tested one: there the workload JWT is exchanged for an IAM role per actor, KMS key policies replace `key-holder`, and the metadata service is closed to every uid but the node agent.

### Workload identity

On bare-metal the node agent issues a short-lived **workload JWT per actor**, from the uid it reads off the socket's peer credentials, and each cloud driver exchanges it for that cloud's credentials. Platform-native identity is used where it exists: the function role on Lambda, a projected ServiceAccount token on Kubernetes. The issuer, the per-cloud exchange and its algorithms are on [Identity](/concepts/identity/) ([ADR 0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)).

### IAM per actor

Each actor has its own IAM role (a function role on serverless, a role that trusts the cluster's issuer and the container's token audience on Kubernetes), generated from its manifest. The trust relationship differs by runtime; the permissions policy is the same in all of them.

KMS key policies name one actor's role each. There is one symmetric key per environment boundary with an encryption context for every sealing use, mint grants included, and one `ECC_NIST_P384` key per enabled signing purpose, because KMS allows one usage per key and `kms:Sign` takes no encryption context ([ADR 0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)). A generated key policy for the audit log key (an example; `<account-id>` and `<install>` are placeholders):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "UseByWriterRoleOnly", "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<account-id>:role/sluis-<install>-writer" },
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"], "Resource": "*" },
    { "Sid": "DenyUseByAnyoneElse", "Effect": "Deny", "Principal": { "AWS": "*" },
      "Action": ["kms:Sign", "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"],
      "Resource": "*",
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::<account-id>:role/sluis-<install>-writer" } } }
  ]
}
```

On a cloud VM the instance role holds only what the node agent needs (the per-actor identities, signed configuration and binaries, lifecycle hooks) and no KMS, secrets or state access; every key policy denies it.

### Who enforces per backend

AWS KMS, DynamoDB and PostgreSQL separate callers themselves (key policies, IAM leading-key conditions, roles and row-level security), and rqlite separates them per user, so each owning actor gets a cluster of its own. A card or a software key cannot, so `key-holder` enforces for it, and emits the audit record before it acts. The check per driver is in [ADR 0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks).

### systemd sandboxing

Every unit gets a generated sandbox profile. An example drop-in for an actor with no network need (illustrative; the real values come from the manifest):

```ini
# /etc/systemd/system/sluis-policy@prod.service.d/10-sandbox.conf
[Service]
User=sluis-policy-prod
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectProc=invisible
ProcSubset=pid
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
CapabilityBoundingSet=
MemoryDenyWriteExecute=yes
RuntimeDirectory=sluis/policy/prod
LoadCredential=policy.cedar:/etc/sluis/policy
```

The packages ship template units only, `sluis-<actor>@.service` and `sluis-<actor>@.socket`, with `User=sluis-<actor>-%i`, `RuntimeDirectory=sluis/<actor>/%i`, `LoadCredentialEncrypted=` per instance and `ListenStream=/run/sluis/<actor>/%i.sock`. A systemd generator in the package reads `/etc/sluis/install.yaml` and creates the instances and their `sysusers.d` entries. Every actor that needs no network, `entry` included, gets `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX`. Integrations get egress through the proxy and `IPAddressAllow=` for it instead. Secrets arrive through `LoadCredential=`.

The systemd floor is 252, which Ubuntu 26.04 LTS, Rocky Linux 10.x and Amazon Linux 2023 meet. A board image older than the floor is a declared exception until board images for the supported distributions exist ([#881](https://github.com/truvity/sluis/issues/881)); there the units use plain `LoadCredential=`.

### nftables per uid

The firewall is default-closed and keyed on the owner of the socket:

- **IMDS** (`169.254.169.254` and its IPv6 address) is dropped for every uid but the node agent, so a compromised actor cannot reach the instance role.
- **Egress** is an allow-list per uid (`meta skuid`): an integration reaches its provider's hosts and nothing else. `entry`, `policy`, `signer`, `key-holder` and every other actor without a provider have no network at all.
- **Inbound** is closed except for the [named flows between nodes](#traffic-between-nodes), each admitted from the declared peers only.

The per-unit `IPAddressAllow=` and `IPAddressDeny=` directives are a second layer, tested so that no unit lacks them.

### Landlock

Each actor restricts itself with Landlock after start-up: it may read its own configuration and credentials directory and read and write its own runtime directory, and nothing else. This holds even if a bug lets code run inside the actor. It needs a kernel with Landlock (5.13 or later); where it is missing, `sluis doctor` warns and the other layers carry the load.

### The deny matrix

The test that proves isolation is generated from the manifests: for every pair of actors, actor X is denied actor Y's records, secrets, keys, sockets and transport. A failing cell is a policy that is too wide, and the build fails.

## Listeners

A TCP port can be reached by anything that can route to it; a Unix socket only by a process that can open the file, and the receiver learns the caller's uid. sluis uses Unix sockets everywhere except for the one API that has to be public ([ADR 0003](/decisions/0003-units-transports-and-fusion/#listeners)).

### The rule

- **`entry`'s public API is the only listener that faces the edge,** and `entry` authenticates every request itself. On bare-metal it is a Unix socket that `cloudflared` forwards to, and `entry` runs with `PrivateNetwork=yes` and no network at all. On Kubernetes it is a Unix socket too, and the key-less edge relay in the pod forwards to it. Only where the edge cannot reach a Unix socket, inside the Lambda sandbox, is it TCP on `127.0.0.1`.
- **An audit front has an `entry` of its own**, on its own host (`sluis-audit.example.com`), and it is its front's only edge listener ([ADR 0028](/decisions/0028-audit-pieces/#the-audit-front)).
- **Every other actor and every driver listens on Unix sockets only,** one socket per instance, `/run/sluis/<actor>/<boundary>.sock`. A key-holding actor and a driver never get a TCP listener.
- **Reachability is generated from the manifest, by group on a host and by mount on Kubernetes.** On a host every socket is mode 0660 with a group that is the set of actors allowed to call it. On Kubernetes supplementary groups are set per pod, not per container, so each callee has its own volume for its socket directory, mounted read-only into exactly the containers the call graph allows ([ADR 0011](/decisions/0011-runtimes-and-installations/#kubernetes)).
- **The callee checks the caller.** It reads the peer's credentials with `SO_PEERCRED`, maps the uid to an actor and checks the call graph, default deny. The pid is not used on Kubernetes, where containers have separate PID namespaces. `key-holder` goes further: each caller has a socket of its own, in a directory only that caller can open.

On Kubernetes the key-less **edge relay** listens on the pod address and forwards to `entry`'s socket, so that a Gateway API implementation or an Ingress controller can route to the pod; `entry` itself is never bound to the pod address. A `cloudflared` sidecar is a supported mode, with no inbound listener at all. The kubelet probes `entry` with an `exec` probe inside its container.

An example of the socket directory on one node (illustrative):

```text
/run/sluis/
  entry/prod-public.sock    entry's public API; cloudflared forwards here
  session/prod.sock         group: entry, console
  exchange/prod.sock        group: entry, console
  console/prod.sock         group: entry
  ssh-ca/prod.sock          group: entry
  signer/prod.sock          group: session, exchange
  policy/prod.sock          group: session, exchange, ssh-ca
  key-holder/signer-prod/   one socket per caller; only that caller opens it
  key-holder/ca-prod/
  writer/prod.sock          group: every actor that emits
  node/cred.sock            workload JWT; one answer per uid
```

### The edge connector reaches a Unix socket

On bare-metal the edge connector is `cloudflared` running as a tunnel. It makes outbound connections only and forwards to `entry`'s Unix socket as a `unix:` origin, so the node accepts no inbound connection from the network. An example `config.yaml` (the tunnel id and the domain are placeholders):

```yaml
tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: sluis.example.com
    service: unix:/run/sluis/entry/prod-public.sock
  - service: http_status:404
```

The listener is public by design, and the actor each request is routed to authenticates it, so a local process that opens the socket gains nothing the public API does not offer. `entry` holds nothing, routes only to sockets that no process outside the call graph can open, and has no network to reach out with.

### Where `entry`'s listener is, per runtime

| Runtime and installation | Listener | Who connects |
| ------------------------ | -------- | ------------ |
| bare-metal: local | A Unix socket on a shared volume; `entry`'s container has no network | The forwarder, a Compose service (a generic reverse proxy that ends TLS) that mounts the socket and publishes a port for the developer's browser or the test harness ([The local installation](/runtimes/local/)). Production installations never publish one ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)) |
| bare-metal: boards, or a virtual machine | A Unix socket | `cloudflared` on the same host, a tunnel to the public hostname |
| serverless: lambda | `127.0.0.1:<port>` inside the function's sandbox, a micro-VM that holds only sluis's own processes | The Lambda Web Adapter, pinned and vendored into sluis's own layer; API Gateway in front |
| kubernetes | A Unix socket in the pod | The edge relay in the same pod (the default), or a `cloudflared` sidecar |

### The console's static host

The console's single-page application is served by each runtime's static host: a directory that `entry` serves on bare-metal, the bucket behind the API gateway on serverless, and on Kubernetes its own Deployment behind the same gateway. That container is a **key-less listener**: it serves static files only, holds no key, no secret and no state, and calls nothing.

### Traffic between nodes

Traffic between nodes and installations is a short, named list, each flow over mutual TLS with a certificate per peer, declared in the manifest and admitted by the firewall from the declared peers only ([ADR 0003](/decisions/0003-units-transports-and-fusion/#listeners)):

- the state clusters' Raft and HTTP ports, one cluster per (boundary, owning actor), each with its own port from a port scheme;
- the `peer` witness's co-signature of another node's log checkpoints;
- the PIN hand-over from an unlocked peer to a node's `key-holder`;
- the `direct-mtls` and `nats-jetstream` audit transports, to a separate audit installation;
- calls between boundaries, which name SPIFFE IDs.

No actor is otherwise reachable from another node: an actor that needs its state talks to its own cluster's member on its own node, and the deny tests check that nothing else binds a TCP address.

## Residual risk

Some guarantees cannot be matched without hardware isolation per process. They are written down here rather than hidden.

| Risk | Why it remains | What reduces it |
| ---- | -------------- | --------------- |
| **Root on the node** | An actor's identity on a bare-metal node is asserted by the host (uid, cgroup), so root acts as every actor on it, as node root does on Kubernetes | A small node agent; short-lived credentials; a separate node per trust domain where it matters |
| **Memory reads** | Secrets stay in long-lived processes, where a same-uid or root attacker or a core dump sees them | `ProtectProc=invisible`, no core dumps, no ptrace. Authority keys never enter process memory: they stay in KMS or on the card |
| **Kernel or sandbox escape** | The actors share one kernel | Minimal syscalls, `NoNewPrivileges`, Landlock; accept |
| **The node agent is a trusted base** | It can obtain credentials for every actor on its node | Keep it tiny and audited; no parsing of caller input beyond a fixed protocol |
| **The mediating driver is one door** | A compromised `key-holder` can use, not extract, every key on its card | One small process with the card to itself, no network, a socket per caller, content-aware signing, a rate limit, fuzzed decoding, an audit record before every action |
| **One PIN per card** | A PIV card has no per-slot caller separation. Unattended signing needs a touch policy of never, so physical theft of a powered host is use | `key-holder` is the only process that opens the card; a stolen board is replaced and its certificate revoked by ritueel, which holds the roots offline |
| **A compromised writer with no witness** | It can get a rewritten checkpoint signed. A compliance lock stops overwriting, not a split view | A `peer` or `external` witness exposes a split view; `sluis config check` warns when there is none ([ADR 0029](/decisions/0029-the-audit-log/#witnesses)) |
| **A cluster is one trust domain** | A compromised node reads replicated state | The blast radius is the installation, not the estate |
| **Shared egress address** | One NAT means no per-actor source identity at the network layer. A proxy is a software control | Make the proxy mandatory by firewall |
| **Account or key-admin compromise** on AWS | A KMS key policy cannot hide use from the account root or a key administrator | The control-plane actions are denied to every actor, and every use of the account's emergency access is audited |

Serverless removes the first three rows: the platform attests the function and runs each in its own micro-VM. That is why serverless needs no node agent.
