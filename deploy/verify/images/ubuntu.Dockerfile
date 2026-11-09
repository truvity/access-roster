# The test image of Ubuntu 26.04: the base image, pinned by digest (deploy/verify/nodes.tsv), with a systemd that can be its init and
# nothing of sluis. It holds what the packages declare as dependencies and nothing more (systemd and ca-certificates), so that the
# test installs with the distribution's own repositories switched off and a dependency the packages forgot to declare is found.
ARG BASE
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
# The container image excludes documentation from installs; a package that ships a file under /usr/share/doc must be able to install it.
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes /etc/dpkg/dpkg.cfg.d/docker \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps python3 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
