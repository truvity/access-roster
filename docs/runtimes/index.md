---
title: Runtimes
description: The three runtimes sluis runs on (bare-metal, serverless, kubernetes), what each provides, and the four tested installations that name its default drivers.
status: target
sidebar:
  order: 0
---

A **runtime** is the kind of place sluis runs: how processes are started and what they can rely on. There are three ([ADR 0011](/decisions/0011-runtimes-and-installations/#runtime-kinds)). The word "environment" keeps its usual meaning: development, staging or production.

- **[bare-metal](/runtimes/bare-metal/)** covers physical hosts, virtual machines such as EC2, and local Docker. systemd, or a container runtime for local Docker, starts the processes.
- **[serverless](/runtimes/serverless/)** covers AWS Lambda and similar platforms. The platform runs a function per event. Lambda's own term is written "Lambda runtime" in these pages, to keep the two apart.
- **[kubernetes](/runtimes/kubernetes/)** runs sluis as pods, supervised by the kubelet.

The runtime is not the node count and not the cloud account: both are attributes of an installation. Nor is it the [boundary](/concepts/boundaries/), the environment, company or product that an installation keeps apart from the others. The [permission manifest](/architecture/deployment/) of every [actor](/concepts/actors/) is the same on every runtime; the runtime decides how it becomes units, policies and access lists, and sluis enforces it with the means each platform offers.

Each runtime has its own packaging: `.deb` and `.rpm` packages and a tarball on bare-metal, a zip per executable on serverless, and one OCI image per process with one Helm chart on kubernetes. There are no build profiles, and `dev` is not a build ([Packages](/distribution/packages/)).

## What each runtime provides

| Capability | bare-metal | kubernetes | serverless |
|---|---|---|---|
| Long-running processes | Yes | Yes | No (runs per event) |
| Persistent local disk | Yes | Only with a per-pod volume | No |
| Same-host Unix sockets | Yes, on the node | Yes, within a pod | Yes, within one function (extensions) |
| Inbound connections between processes | Yes | Yes (Service) | No (only triggers or a gateway) |
| Hardware devices | Yes | Partly (a pod pinned to its node) | No |
| Nodes | 1 or N | 1 or N | Elastic (no node identity) |
| Supervisor | systemd, or a container runtime for local Docker | kubelet | The platform |

Serverless always comes with a provider, AWS Lambda today, so for serverless the provider is part of the runtime.

## Installations, nodes and dependencies

- **Nodes.** One, N, or elastic on serverless. A bare-metal installation with one node and one with three have the same runtime.
- **Dependency.** Something outside sluis that a [driver](/concepts/drivers/) needs and declares: an AWS account, a Cloudflare account, a YubiKey, a NATS service.
- **Installation.** One concrete deployment: a runtime, a node count, the available dependencies and one driver per port, for example "bare-metal, 3 nodes, AWS account".
- **Tested installation.** One of the four that the documentation, the tutorials and the test matrix use: local, boards, lambda and kubernetes. Any other combination is a possible installation, allowed by the rules but not tested.

`sluis config check` validates an installation against what its drivers declare: a driver that needs a long-running process is refused on serverless, a driver that needs exactly one node is refused on a cluster, and a driver whose dependency is missing is refused everywhere. Which driver fits which runtime is on [Installations](/runtimes/installations/#which-drivers-fit-which-runtime).

Some actors declare **instances: exactly 1**: the audit writer, the FactsSource reconciler and the indexer. With more than one node, or elastic nodes, such an actor takes a lease on the state store ([Data](/concepts/data/#leases-and-fencing-tokens)).

## Choosing an installation

The four tested installations name the default drivers for their runtime. Pick by the failure you have to survive and the key custody you accept; the order in which they are built is on the [Roadmap](/roadmap/).

- **[local](/runtimes/installations/#local):** Docker on a workstation, with software keys; a dedicated development card is opt-in. For learning, development and CI.
- **[boards](/runtimes/installations/#boards):** three single-board computers, a YubiKey in each, with rqlite state. On-premises, and it survives the loss of a node.
- **[lambda](/runtimes/installations/#lambda):** AWS Lambda, a function per actor. No hosts to patch.
- **[kubernetes](/runtimes/installations/#kubernetes):** a container per actor on Amazon EKS, with AWS KMS. For a team that already runs a cluster.

The key mode follows from the installation, not from a switch: KMS on lambda and kubernetes, a YubiKey on boards, software keys on local. The code carries the floor: the `software` keys driver refuses to start in production and warns in staging, and configuration picks only among the modes the floor allows ([ADR 0006](/decisions/0006-keys-and-sealing/#floors-in-code)).

## Pages in this section

- [Installations](/runtimes/installations/): the four tested installations, their default drivers, and which drivers fit which runtime.
- [Bare-metal](/runtimes/bare-metal/): physical hosts, virtual machines and local Docker, with one node or N, and the board capacity.
- [Serverless](/runtimes/serverless/): AWS Lambda, a function per actor.
- [Kubernetes](/runtimes/kubernetes/): a container per actor, one chart with presets.
