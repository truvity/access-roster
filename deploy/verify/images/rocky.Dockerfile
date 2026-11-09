# The test image of Rocky Linux 10 (see ubuntu.Dockerfile).
ARG BASE
FROM ${BASE}
RUN dnf -y -q install systemd dbus-daemon ca-certificates procps-ng python3 \
    && dnf clean all -q && rm -rf /var/cache/dnf
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
