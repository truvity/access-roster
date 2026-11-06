#!/usr/bin/env bash
# The boards deploy scripts against a real operating system: a systemd container of Ubuntu 26.04 or Rocky 10, driven through a
# stand-in for ssh that runs the board's command in the container. No board and no card. What it checks, in order:
#   1. a deploy of the card variant to an image without the card packages is refused, naming them, before anything is written;
#   2. with the packages installed the deploy goes through: the units verify and start (the executables are stand-ins that
#      sleep), the credentials are encrypted on the board under its host key and read by a unit through LoadCredentialEncrypted=,
#      and a "reflash" (a new host key) is followed by a deploy that encrypts them again;
#   3. the two locks of the card service against a real pcscd: root and the card driver's user reach it; another user does not
#      (the socket group), a member of the socket's group that is not the card driver does not (the polkit rule), and without
#      the rule even the card driver does not, where pcscd asks polkit.
# SELinux is not the container's to enforce, so the labels are not tested here (docs/runtimes/bare-metal.md, "SELinux and the
# firewall"). Needs docker and jq. Run from the repository root: deploy/boards/os-container-test.sh ubuntu:26.04
# shellcheck disable=SC2016 # the command lines run in the container
# shellcheck disable=SC2329,SC2034 # cleanup runs from the trap; the OS_CREDENTIALS_ and OS_CREDENTIAL_ variables are the library's
set -euo pipefail

image=${1:?usage: os-container-test.sh IMAGE (ubuntu:26.04 or rockylinux/rockylinux:10)}
case "$image" in
ubuntu:* | debian:*) fam=deb ;;
rockylinux/* | rockylinux:* | almalinux:* | quay.io/centos/*) fam=rpm ;;
*) echo "os-container-test: no family known for '$image'" >&2; exit 2 ;;
esac

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
ct=sluis-os-$$
fail=0
cleanup() {
	[ -z "${OS_TEST_KEEP:-}" ] || { echo "kept: docker exec -it $ct bash"; return 0; }
	docker rm -f "$ct" >/dev/null 2>&1 || true
	rm -rf "${work:?}"
}
trap cleanup EXIT
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
# x runs a command line in the container as root.
x() { docker exec -i "$ct" bash -c "$1"; }
# shellcheck source=/dev/null
. "$root/deploy/boards/os-test-lib.sh"

# The stand-in for ssh: ssh joins the words after user@host with spaces and hands them to the board's shell, so does this.
os_ssh_stub() { # dir
	cat >"$1/ssh" <<'STUB'
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
	case "$1" in "$SLUIS_BOARD_SSH_USER"@*) shift; break ;; esac
	shift
done
exec docker exec -i "$OS_CONTAINER" bash -c "$*"
STUB
	chmod 0755 "$1/ssh"
}
os_env() { export OS_CONTAINER="$ct"; }

# The container: systemd is its init. The base packages come first and the card packages later, so that the refusal can be checked.
case "$fam" in
deb) base='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus python3 util-linux procps ca-certificates >/dev/null' ;;
rpm) base='dnf -y -q install systemd dbus-daemon python3 util-linux procps-ng >/dev/null' ;;
esac
docker run -d --name "$ct" --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
	--stop-signal SIGRTMIN+3 "$image" bash -c "set -e; $base; exec /usr/lib/systemd/systemd" >/dev/null
for _ in $(seq 1 90); do
	state=$(docker exec "$ct" systemctl is-system-running 2>/dev/null || true)
	case "$state" in running | degraded) break ;; esac
	sleep 2
done
case "$state" in running | degraded) ok "systemd is up in $image ($state)" ;; *) docker logs "$ct" 2>&1 | tail -20; bad "systemd did not come up ($state)"; exit 1 ;; esac
echo "     $(x 'systemctl --version | head -1; . /etc/os-release; echo "$PRETTY_NAME, glibc $(ldd --version | head -1 | grep -o "[0-9.]*$")"' | tr '\n' ' ')"

# The stand-in for sudo: the container is root.
x 'printf "#!/bin/sh\nwhile [ \"\$1\" = -n ]; do shift; done\nexec \"\$@\"\n" >/usr/local/bin/sudo; chmod 0755 /usr/local/bin/sudo'
# Rocky 10's systemd does not set up a credentials directory for any unit in a Docker container on the hosts tried (MEASURED
# 2026-11-04: a plain LoadCredential= fails too, and the same image booted in a virtual machine receives them). The virtual
# machine test proves receipt there, so here a missing credentials directory is a note, and only for the rpm family.
if [ "$fam" = rpm ]; then
	OS_CREDENTIALS_MAY_BE_MISSING=1
	OS_CREDENTIALS_MISSING_REASON="the nightly virtual machine test (os-vm-test.sh) proves receipt on Rocky 10"
fi
# The real credential driver, when the job built one for this machine (docs/runtimes/bare-metal.md, "What the jobs check"):
# SLUIS_OS_CREDENTIAL_DRIVER names a static executable; the job builds it with `cargo zigbuild --release --target
# x86_64-unknown-linux-musl -p credential`. Without it the unit runs a stand-in that only prints what it received.
if [ -n "${SLUIS_OS_CREDENTIAL_DRIVER:-}" ]; then
	[ -x "$SLUIS_OS_CREDENTIAL_DRIVER" ] || { bad "SLUIS_OS_CREDENTIAL_DRIVER=$SLUIS_OS_CREDENTIAL_DRIVER is not an executable"; exit 1; }
	OS_CREDENTIAL_DRIVER=$SLUIS_OS_CREDENTIAL_DRIVER
else
	echo "note the real credential driver is not run (SLUIS_OS_CREDENTIAL_DRIVER is not set): the unit runs a stand-in, so how systemd hands over its credentials directory is not exercised"
fi
os_prepare_repo
os_check_refusal
x "$(os_card_packages)"
# The packages were installed after boot, so the running bus is told of the policy they ship (an image has it from the start).
x 'systemctl reload dbus.service'
os_check_deploy
os_check_card_locks
exit "$fail"
