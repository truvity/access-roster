---
title: Deployment and listeners
description: "L3, enforcement per installation: how IAM, key policies, systemd, nftables, Landlock and pods hold each unit to the registries, and what listens where."
status: target
sidebar:
  order: 3
---

The [registries](/architecture/#the-registries-are-the-spine) say what each actor may do. This page says what enforces it on each [runtime](/runtimes/), what accepts connections and where, and what risk remains. The four tested installations serve as the worked examples ([0011](/decisions/0011-runtimes-and-installations/#installations)). The goal on every runtime is the baseline that one Lambda function per actor gives for free: one unit is one identity that the resources can see, and nothing else can act as it.

Two things are enforced, and they are enforced separately:

- **Who a unit is.** The runtime decides how the platform proves it: the peer uid of a socket, the role of a function, the service-account token of a pod ([0003](/decisions/0003-units-transports-and-fusion/#transports)).
- **What a unit can reach.** Only the credential holders reach storage, keys, export destinations or the audit blob. A work actor holds no such credential, so what it can do is what its rules in the kind registry and its key purposes in the actor registry allow, checked by store@ and key@ ([0002](/decisions/0002-families-of-actors/#credential-holders)).

## Enforcement per runtime

Every mechanism is generated from the registries; none is written by hand.

| Runtime | Identity of a unit | Who reaches storage and keys | systemd sandboxing | nftables per uid | Landlock |
| ------- | ------------------ | ---------------------------- | ------------------ | ---------------- | -------- |
| **bare-metal** (a board, a virtual machine, local Docker) | The peer uid on the unit's socket; `sluis-node` issues a workload token per actor from that uid | Only store@, key@, exporter@ and the audit pieces, through drivers whose socket only the owner opens. key@ has the card to itself | Every unit (not in a container) | Default-deny egress with per-uid allow-lists, IMDS closed on a cloud VM, rqlite's Raft port between peers | Per actor where the kernel has it (5.13 or later) |
| **serverless** (AWS Lambda) | The function's role, one per actor and per holder. Calls between functions are authorised by a resource policy | Only the roles of the holders' functions; a work function's role may invoke and send to the audit transport | The platform's sandbox | Not available. A VPC route can cut `policy` off entirely | Optional, in process |
| **kubernetes** | A projected service-account token per pod, one audience per callee; a pod per actor and per holder | Only the holders' pods. The token reaches the driver container alone, so a work pod has no cloud identity | `restricted` Pod Security, a security context per container | NetworkPolicy per pod, an egress policy per adapter pod; Cilium optional for egress by host name | Optional |

The tested installations read as their runtime's row, with these details:

| Installation | What differs |
| ------------ | ------------ |
| **local** (bare-metal, Docker Compose on a workstation) | Software keys by default; nothing is production. A dedicated development card is opt-in: only the key@ container reaches it, through the host's smart-card service, and key@ has the card to itself ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). Containers run as their actors' pinned uids and mount only the sockets the registry allows; no systemd sandboxing, nftables or Landlock |
| **boards** (bare-metal, three single-board computers, a YubiKey per node) | key@ for each node's card; one rqlite cluster over the three boards, with the Raft port over mutual TLS between peers. No cloud credential for the board-only parts. Landlock is missing on the current board image's kernel, so the other layers carry the load ([Bare-metal](/runtimes/bare-metal/)) |
| **lambda** | As its runtime row |
| **kubernetes** (Kubernetes on AWS, EKS) | As its runtime row. A holder's driver container exchanges the projected token for its role by web identity through the cluster's IAM OIDC provider; EKS Pod Identity is not used, because its credentials reach every container of the pod ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)). A cluster without AWS is not in 2.0 |

A bare-metal node on a cloud VM is a possible installation, not a tested one: there the workload token is exchanged for a role per holder, KMS key policies name key@'s role alone, and the metadata service is closed to every uid but the node agent.

### Workload identity

On bare-metal `sluis-node` issues a short-lived **workload token per actor**, from the uid it reads off the socket's peer credentials, and asks key@ to sign it ([0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)). The drivers of a holder exchange it for a cloud's credentials where the platform has none of its own. Platform-native identity is used where it exists: the function role on Lambda, a projected service-account token on Kubernetes, exchanged by web identity through the cluster's IAM OIDC provider. The issuer, the per-cloud exchange and its algorithms are on [Identity](/concepts/identity/) ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)).

### IAM per holder

Each holder has its own role (a function role on Lambda, a role that trusts the cluster's issuer and the driver container's token audience on Kubernetes), generated from the registries. A work function's role may only invoke the functions its call graph names and send to the audit transport. The trust relationship differs by runtime; the permissions policy is the same in all of them.

KMS key policies name key@'s role alone. There is one symmetric key per boundary, with an encryption context {boundary, tenant, purpose} for every data key it wraps, and one `ECC_NIST_P384` key per enabled signing purpose (a named exception has a key of its own type), because KMS allows one usage per key and `kms:Sign` takes no encryption context ([0006](/decisions/0006-keys-and-sealing/#keys-per-boundary-on-aws)). A work actor reaches a key only through key@, whose rules say who may ask for which purpose ([0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks)). A generated key policy for the audit log key (an example; `<account-id>` and `<install>` are placeholders):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "UseByKeyRoleOnly", "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<account-id>:role/sluis-key-<boundary>" },
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"], "Resource": "*" },
    { "Sid": "DenyUseByAnyoneElse", "Effect": "Deny", "Principal": { "AWS": "*" },
      "Action": ["kms:Sign", "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"],
      "Resource": "*",
      "Condition": { "ArnNotEquals": { "aws:PrincipalArn": "arn:aws:iam::<account-id>:role/sluis-<install>-key" } } }
  ]
}
```

The role of the restore command is the one other role that may decrypt, and only the archive key ([0010](/decisions/0010-backup-and-recovery/#the-archive-key)). On a cloud VM the instance role holds only what the node agent needs (the per-actor identities, signed configuration and binaries, lifecycle hooks) and no KMS, secrets or storage access; every key policy denies it.

### Two independent checks

A request meets two checks that do not depend on each other, whichever the runtime ([0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks)):

| Check | Where | What it refuses |
| ----- | ----- | --------------- |
| The rule | store@: the actor × kind × verb of the kind registry, plus a grant sealed for the tenant on every tenant-scoped write | A write by an actor that is not the kind's writer, a read the rule does not list, a write with no grant for the address's tenant |
| The grant | key@: the caller's rule for the purpose and a grant sealed for the address's tenant, on every Seal and Open | An open for a tenant the grant does not name, a purpose the actor may not use |

Under both sits the transport: socket groups and sandboxes, invoke resource policies, NetworkPolicies. A fault that disables one check leaves the others in force, and the build tests each with the others switched off.

### systemd sandboxing

Every unit gets a generated sandbox profile. An example drop-in for an actor with no network need (illustrative; the real values come from the registries):

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
```

The packages ship template units only, `sluis-<actor>@.service` and `sluis-<actor>@.socket`, with `User=sluis-<actor>-%i`, `RuntimeDirectory=sluis/<actor>/%i` and `ListenStream=/run/sluis/<actor>/%i.sock`. A generator in the package reads the bootstrap files in `/etc/sluis/bootstrap.d/`, one for each boundary ([Where it lives](/reference/bootstrap-file/#where-it-lives)), and creates the instances and their `sysusers.d` entries. An actor whose registry row lists no egress host, `entry` included, gets `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX` ([0003](/decisions/0003-units-transports-and-fusion/#units)). A work actor needs no credential file: the credentials of a holder, such as store@'s engine login or the PIN of a card, arrive through `LoadCredential=` on that holder's unit alone, and a holder's driver is a unit beside it.

The systemd floor is 252, which Ubuntu 26.04 LTS, Rocky Linux 10.x and Amazon Linux 2023 meet. A board image older than the floor is a declared exception until board images for the supported distributions exist ([#881](https://github.com/truvity/sluis/issues/881)); there the units use plain `LoadCredential=`.

### nftables per uid

The firewall is default-closed and keyed on the owner of the socket:

- **IMDS** (`169.254.169.254` and its IPv6 address) is dropped for every uid but the node agent, so a compromised actor cannot reach the instance role.
- **Egress** is an allow-list per uid (`meta skuid`) from the egress classes of the actor registry: an adapter reaches its vendor's hosts, store@ reaches its engine and its sources, key@ reaches a cloud key service where the installation has one. `entry`, `policy`, `signer` and every other actor with no egress class have no network at all.
- **Inbound** is closed except for the [named flows between nodes](#traffic-between-nodes), each admitted from the declared peers only.

The per-unit `IPAddressAllow=` and `IPAddressDeny=` directives are a second layer, tested so that no unit lacks them.

### Landlock

Each actor restricts itself with Landlock after start-up: it may read its own configuration and credentials directory and read and write its own runtime directory, and nothing else. This holds even if a bug lets code run inside the actor. It needs a kernel with Landlock (5.13 or later); where it is missing, `sluis doctor` warns and the other layers carry the load.

### The deny matrix

The test that proves isolation is generated from the registries: for every pair of actors, actor X is denied actor Y's kinds, keys, sockets and transport. A failing cell is a rule that is too wide, and the build fails.

### The uid table

The uid of every actor and driver is pinned in the actor registry, and is the same in the Compose file and in the chart, because the peer-uid check relies on it ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). A uid is never reused, even for a retired actor. On bare-metal the packages make named system users, `sluis-<actor>-<boundary>` ([0002](/decisions/0002-families-of-actors/#names)), so the table applies to images only. In containers an instance of each boundary has a uid of its own, so no two instances of any actors share one and the peer-uid check on a shared socket tells `ca@dev` from `ca@prod` ([principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule)). The `Boundary` kind carries the block of uids of its boundary ([Kinds](/reference/kinds/)).

## Listeners

A TCP port can be reached by anything that can route to it; a Unix socket only by a process that can open the file, and the receiver learns the caller's uid. sluis uses Unix sockets everywhere except for the one API that has to be public ([0003](/decisions/0003-units-transports-and-fusion/#listeners)).

### The rule

- **`entry`'s public API is the only listener that faces the edge,** and `entry` authenticates every request itself. On bare-metal it is a Unix socket that `cloudflared` forwards to, and `entry` runs with `PrivateNetwork=yes` and no network at all. On Kubernetes it is a Unix socket too, and the key-less edge relay in the pod forwards to it. Only inside the Lambda sandbox, where the edge cannot reach a Unix socket, is it TCP on `127.0.0.1`.
- **An audit front has an `entry` of its own,** on its own host (`sluis-audit.example.com`), and it is its front's only edge listener ([0028](/decisions/0028-audit-pieces/#the-audit-front)).
- **Every other actor and every driver listens on Unix sockets only on a board,** one socket per instance, `/run/sluis/<actor>/<boundary>.sock`. No actor has a TCP listener on a board, and a holder and a driver never get one.
- **Reachability is generated from the registries, by group on a host and by mount on Kubernetes.** On a host every socket is mode 0660 with a group that is the set of actors allowed to call it. On Kubernetes an actor's pod accepts gRPC from its callers on the pod address, admitted by a NetworkPolicy from the callers only; a driver listens on its `emptyDir` socket only, and a generated check fails the build when a container that holds a cloud token exposes a listener ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)).
- **The callee checks the caller.** It reads the peer's credentials with `SO_PEERCRED`, maps the uid to an actor and checks the call graph, default deny. key@ goes further: each caller has a socket of its own, in a directory only that caller can open ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)).

On Kubernetes the key-less **edge relay** listens on the pod address and forwards to `entry`'s socket, so that a Gateway API implementation or an Ingress controller can route to the pod; `entry` itself is never bound to the pod address. A `cloudflared` sidecar is a supported mode, with no inbound listener at all. The kubelet probes `entry` with an `exec` probe inside its container.

An example of the socket directory on one board (illustrative):

```text
/run/sluis/
  entry/prod.sock           entry's public API; cloudflared forwards here
  session/prod.sock         group: entry, console
  exchange/prod.sock        group: entry, session, console
  console/prod.sock         group: entry
  ssh-ca/prod.sock          group: entry
  signer/prod.sock          group: session, exchange
  policy/prod.sock          group: every actor the registry lets call it
  store/prod.sock           group: every actor that has a data port
  key/session-prod/         one socket per caller; only that caller opens it
  key/signer-prod/
  writer/prod.sock          group: every actor that emits in direct mode
  node/cred.sock            workload token; one answer per uid
```

### The edge connector reaches a Unix socket

On bare-metal the edge connector is `cloudflared` running as a tunnel. It makes outbound connections only and forwards to `entry`'s Unix socket as a `unix:` origin, so the node accepts no inbound connection from the network. An example `config.yaml` (the tunnel id and the domain are placeholders):

```yaml
tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: sluis.example.com
    service: unix:/run/sluis/entry/prod.sock
  - service: http_status:404
```

The listener is public by design, and the actor each request is routed to authenticates it, so a local process that opens the socket gains nothing the public API does not offer. `entry` holds nothing, routes only to sockets that no process outside the call graph can open, and has no network to reach out with.

### Where `entry`'s listener is, per runtime

| Runtime and installation | Listener | Who connects |
| ------------------------ | -------- | ------------ |
| bare-metal: local | A Unix socket on a shared volume; `entry`'s container has no network | The forwarder, a Compose service (a generic reverse proxy that ends TLS) that mounts the socket and publishes a port for the developer's browser or the test harness ([The local installation](/runtimes/local/)). Production installations never publish one ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)) |
| bare-metal: boards, or a virtual machine | A Unix socket | `cloudflared` on the same host, a tunnel to the public hostname |
| serverless: lambda | `127.0.0.1:<port>` inside the function's sandbox, a micro-VM that holds only sluis's own processes | The Lambda Web Adapter, pinned and vendored into sluis's own layer; API Gateway in front |
| kubernetes | A Unix socket in the pod | The edge relay in the same pod (the default), or a `cloudflared` sidecar |

### The console's static host

The console's single-page application is served by each runtime's static host: a directory that `entry` serves on bare-metal, the bucket behind the API gateway on serverless, and on Kubernetes its own Deployment behind the same gateway. That container is a **key-less listener**: it serves static files only, holds no key, no secret and no data, and calls nothing ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)).

### Traffic between nodes

On boards the traffic between nodes is one flow: **rqlite's Raft port, over mutual TLS with a certificate per cluster,** admitted by the firewall from the declared peers only ([0003](/decisions/0003-units-transports-and-fusion/#calls-between-nodes)). Everything else crosses through the store or the blob:

- a locked board gets its PIN through the store: its key@ writes a request and an unlocked peer's key@ writes the PIN sealed to it ([0006](/decisions/0006-keys-and-sealing/#touch-and-pin));
- the `peer` witnesses meet through the audit blob ([0029](/decisions/0029-the-audit-log/#witnesses));
- an audit transport to a separate audit installation is a queue or NATS JetStream, not a socket between boards;
- calls between boundaries are federation and name SPIFFE IDs ([0008](/decisions/0008-boundaries-and-tenants/#federation-between-boundaries)).

No actor is otherwise reachable from another node: a work actor asks the holders of its own node, and the deny tests check that nothing else binds a TCP address, apart from rqlite's client API on the loopback address, which only store@'s driver reaches ([0005](/decisions/0005-the-store/#engines)).

## Residual risk

Some guarantees cannot be matched without hardware isolation per process. They are written down here rather than hidden.

| Risk | Why it remains | What reduces it |
| ---- | -------------- | --------------- |
| **Root on the node** | An actor's identity on a bare-metal node is asserted by the host (uid, cgroup), so root acts as every actor on it, as node root does on Kubernetes | A small node agent; short-lived credentials; a separate node per trust domain where it matters |
| **Memory reads** | Opened data keys and the PIN stay in long-lived processes, where a same-uid or root attacker or a core dump sees them | `ProtectProc=invisible`, no core dumps, no ptrace, locked memory. Authority keys never enter process memory: they stay in KMS or on the card |
| **Kernel or sandbox escape** | The units share one kernel | Minimal syscalls, `NoNewPrivileges`, Landlock; accept |
| **The node agent is a trusted base** | It can obtain a workload token for every actor on its node | Keep it tiny and audited; it parses no caller input beyond a fixed protocol and holds no key, because key@ signs its tokens |
| **A holder is one door** | A compromised key@ can use, not extract, every key on its card, and a compromised store@ can read secret-source values and change or delete items in its engine ([0005](/decisions/0005-the-store/#secret-sources)) | One small unit each, running only its own code and its drivers, with no work actor beside it; no network for key@ on a board; a socket per caller; content-aware signing; a rate limit; the audit log and the backup against changed items |
| **One PIN per card** | A PIV card has no per-slot caller separation. Unattended signing needs a touch policy of never, so physical theft of a powered host is use | key@ is the only process that opens the card; a stolen board is replaced and its certificate revoked by ritueel, which holds the roots offline |
| **A compromised writer with no witness** | It can get a rewritten checkpoint signed. A compliance lock stops overwriting, not a split view | A `peer` or `external` witness exposes a split view; `sluis config check` warns when there is none ([0029](/decisions/0029-the-audit-log/#witnesses)) |
| **A cluster is one trust domain** | A compromised node reads replicated data | The blast radius is the installation, not the estate |
| **Shared egress address** | One NAT means no per-actor source identity at the network layer. A proxy is a software control | Make the proxy mandatory by firewall |
| **Account or key-admin compromise** on AWS | A KMS key policy cannot hide use from the account root or a key administrator | The control-plane actions are denied to every actor, and every use of the account's emergency access is audited |

Serverless removes the first three rows: the platform attests the function and runs each in its own micro-VM. That is why serverless needs no node agent. The threat model has the attacker positions and their order ([Threat model](/security/threat-model/)).
