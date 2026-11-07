#!/usr/bin/env bash
# The boards deploy scripts against Rocky Linux 10 with SELinux enforcing: a virtual machine booted from the distribution's cloud
# image under KVM, reached by real ssh through a forwarded port. No board and no card. It runs the steps of os-container-test.sh
# (deploy, credentials, the card service's locks) and adds what a container cannot show:
#   - the machine enforces SELinux, and the deploy leaves bin_t on the executables and systemd_unit_file_t on the units;
#   - the units run as unconfined_service_t, and pcscd as pcscd_t;
#   - the card driver's unit, a stand-in under that domain, reaches pcscd through its socket;
#   - no AVC denial was logged since boot, after the deploy and the units' start.
# Needs /dev/kvm, qemu-system-x86_64, genisoimage (or xorriso), ssh, curl and jq. The image is kept in SLUIS_VM_CACHE
# (default ~/.cache/sluis-os-vm). Run from the repository root: deploy/boards/os-vm-test.sh
# shellcheck disable=SC2016,SC2329,SC2034 # command lines for the machine; functions called from the library or the trap; fam is the library's
set -euo pipefail

# The pinned image: a dated build, checked against the SHA-256 that the distribution publishes (CHECKSUM beside it). When the
# mirror drops the build, bump the version and the hash together.
image_name=Rocky-10-GenericCloud-Base-10.2-20260525.0.x86_64.qcow2
image_url=https://dl.rockylinux.org/pub/rocky/10/images/x86_64/$image_name
image_sha=9fc9e9ff16888bb68ac39b0392e25c9c92684d50c85f1cce6ab549363bbc4b48
fam=rpm
port=${SLUIS_VM_SSH_PORT:-2222}

[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "os-vm-test: /dev/kvm is not usable: this test needs hardware virtualisation" >&2; exit 2; }
for c in qemu-system-x86_64 ssh ssh-keygen curl jq; do command -v "$c" >/dev/null || { echo "os-vm-test: $c is needed" >&2; exit 2; }; done
mkiso=$(command -v genisoimage || command -v xorriso || true)
[ -n "$mkiso" ] || { echo "os-vm-test: genisoimage or xorriso is needed" >&2; exit 2; }

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
cache=${SLUIS_VM_CACHE:-$HOME/.cache/sluis-os-vm}
fail=0
qpid=""
cleanup() {
	if [ -n "${OS_VM_KEEP:-}" ]; then echo "kept: ssh -p $port -i $work/key -o StrictHostKeyChecking=no tester@127.0.0.1 (pid $qpid)"; return 0; fi
	[ -z "$qpid" ] || kill "$qpid" 2>/dev/null || true
	if [ "$fail" != 0 ] && [ -f "$work/serial.log" ] && [ -n "${SLUIS_VM_LOGS:-}" ]; then
		mkdir -p "$SLUIS_VM_LOGS"
		cp "$work/serial.log" "$work/deploy.log" "$SLUIS_VM_LOGS/" 2>/dev/null || true
	fi
	rm -rf "${work:?}"
}
trap cleanup EXIT
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }

# The image, from the cache or the mirror, checked.
mkdir -p "$cache"
if [ ! -f "$cache/$image_name" ] || ! echo "$image_sha  $cache/$image_name" | sha256sum -c - >/dev/null 2>&1; then
	curl -fsSL --retry 5 --retry-all-errors -o "$cache/$image_name.part" "$image_url"
	echo "$image_sha  $cache/$image_name.part" | sha256sum -c - >/dev/null || { echo "os-vm-test: $image_name does not match its pinned SHA-256" >&2; rm -f "$cache/$image_name.part"; exit 1; }
	mv "$cache/$image_name.part" "$cache/$image_name"
fi

# The machine: a copy-on-write disk over the image, and a cloud-init seed that makes a user with our key and passwordless sudo.
ssh-keygen -q -t ed25519 -N '' -f "$work/key"
qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$image_name" "$work/disk.qcow2" 20G
mkdir -p "$work/seed-iso"
printf 'instance-id: sluis-os-vm\nlocal-hostname: board\n' >"$work/seed-iso/meta-data"
cat >"$work/seed-iso/user-data" <<UD
#cloud-config
users:
  - name: tester
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$work/key.pub")
ssh_pwauth: false
UD
"$mkiso" -quiet -output "$work/seed.iso" -volid cidata -joliet -rock "$work/seed-iso/user-data" "$work/seed-iso/meta-data" 2>/dev/null
qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -smp 2 -display none -serial "file:$work/serial.log" \
	-drive "file=$work/disk.qcow2,if=virtio" -drive "file=$work/seed.iso,if=virtio,format=raw,media=cdrom,readonly=on" \
	-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=n0 &
qpid=$!

real_ssh=$(command -v ssh)
vm_ssh() { "$real_ssh" -p "$port" -i "$work/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=5 tester@127.0.0.1 "$@"; }
# x runs a command line as root in the machine; standard input is passed through.
x() { vm_ssh "sudo bash -c $(printf %q "$1")"; }
up=0
for _ in $(seq 1 90); do
	if vm_ssh true 2>/dev/null; then up=1; break; fi
	kill -0 "$qpid" 2>/dev/null || break
	sleep 5
done
[ "$up" = 1 ] || { tail -20 "$work/serial.log" 2>/dev/null; bad "the machine did not answer ssh"; exit 1; }
x 'cloud-init status --wait >/dev/null 2>&1 || true'
ok "the machine is up: $(x '. /etc/os-release; echo "$PRETTY_NAME, kernel $(uname -r), systemd $(systemctl --version | head -1 | cut -d" " -f2), SELinux $(getenforce)"')"

# shellcheck source=/dev/null
. "$root/deploy/boards/os-test-lib.sh"
# The stand-in for ssh: the deploy's user and host are replaced by the machine's, and the real ssh does the rest.
os_ssh_stub() { # dir
	cat >"$1/ssh" <<STUB
#!/usr/bin/env bash
args=()
for a in "\$@"; do
	case "\$a" in "\$SLUIS_BOARD_SSH_USER"@*) a=tester@127.0.0.1 ;; esac
	args+=("\$a")
done
exec "$real_ssh" -p "$port" -i "$work/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "\${args[@]}"
STUB
	chmod 0755 "$1/ssh"
}
os_env() { :; }

if [ "$(x getenforce)" = Enforcing ]; then ok "SELinux is enforcing"; else bad "SELinux is not enforcing"; fi
x 'dnf -y -q install python3 util-linux audit policycoreutils nftables >/dev/null 2>&1; systemctl enable --now auditd >/dev/null 2>&1 || true'
os_prepare_repo
os_check_refusal
x "$(os_card_packages)"
os_check_deploy
os_check_card_locks

# What only an enforcing machine shows.
label() { x "stat -c %C $1" 2>/dev/null; }
expect_type() { # description path type
	local l
	l=$(label "$2")
	case "$l" in *":$3:"*) ok "$1 is $3 ($l)" ;; *) bad "$1 is '$l', not $3" ;; esac
}
expect_type "an executable of the units" /opt/sluis/bin/actors/key bin_t
expect_type "a unit file" /etc/systemd/system/sluis-key@.service systemd_unit_file_t
expect_type "the polkit rule" /etc/polkit-1/rules.d/49-sluis-pcsc.rules etc_t
echo "     state directory: $(label /var/lib/sluis-state 2>/dev/null || echo none); credentials: $(label /etc/sluis/credentials/dev/sluis-drv-store-credential/client-dev)"
for u in sluis-key-dev sluis-drv-key-yubikey-piv-dev sluis-drv-store-credential-dev; do
	d=$(x "ps -o label= -u $u | head -1" | tr -d ' ')
	case "$d" in *:unconfined_service_t:*) ok "the processes of $u run as unconfined_service_t" ;; *) bad "$u runs as '$d'" ;; esac
done
d=$(x 'ps -o label= -C pcscd | head -1' | tr -d ' ')
case "$d" in *:pcscd_t:*) ok "pcscd runs as pcscd_t" ;; *) bad "pcscd runs as '$d'" ;; esac
if avc=$(x 'ausearch --input-logs -m AVC,USER_AVC -ts boot </dev/null 2>&1'); then
	bad "AVC denials since boot:"
	printf '%s\n' "$avc" | head -30 | sed 's/^/     /'
else
	case "$avc" in *"no matches"*) ok "no AVC denial since boot (ausearch: no matches)" ;; *) bad "ausearch said: $avc" ;; esac
fi
exit "$fail"
