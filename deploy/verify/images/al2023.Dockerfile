# The test image of Amazon Linux 2023 (see ubuntu.Dockerfile). The container image of Amazon Linux is minimal: it has neither tar
# nor find, which the boards' deploy script needs and a package does not. The test itself uses find, so findutils is baked in; no
# package of the release may depend on it, and none does.
ARG BASE
FROM ${BASE}
RUN dnf -y -q install systemd dbus-daemon ca-certificates procps-ng python3 findutils \
    && dnf clean all -q && rm -rf /var/cache/dnf
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
