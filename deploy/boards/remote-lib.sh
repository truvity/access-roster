#!/usr/bin/env bash
# shellcheck disable=SC2154 # card_polkit_policy and state_root are the caller's
# shellcheck disable=SC1090 # the board's os-release is read from a path that a test can change
# The checks of remote.sh that depend on the board's operating system, kept apart so that a test can run them against a fake
# package manager and a fake os-release. Sourced by remote.sh, never run. It reads, from the caller:
#   card_polkit_policy   the polkit policy file that a pcscd built with polkit ships
#   state_root           the directory of the units' state
#   manifest             the file that lists what the deploy made (kind<TAB>path)
#   os_release_file      /etc/os-release, unless the caller says otherwise (a test)

# os_family says which package manager the board has: deb (Debian, Ubuntu) or rpm (RHEL, Rocky, Fedora). The deploy installs no
# package: it checks that what the card path needs is there, and refuses with the names if it is not. The image of the board
# carries them (docs/runtimes/bare-metal.md, "Supported operating systems").
os_release_file=${os_release_file:-/etc/os-release}
os_family() {
	local id="" like=""
	[ -r "$os_release_file" ] || os_release_file=/usr/lib/os-release # /etc/os-release is a link to it, and missing in a thin image
	if [ -r "$os_release_file" ]; then
		# shellcheck disable=SC1091 # the board's own file
		id=$(. "$os_release_file" && printf '%s' "${ID:-}")
		# shellcheck disable=SC1091
		like=$(. "$os_release_file" && printf '%s' "${ID_LIKE:-}")
	fi
	case " $id $like " in
	*" debian "* | *" ubuntu "*) echo deb ;;
	*" rhel "* | *" fedora "* | *" centos "*) echo rpm ;;
	*) echo unknown ;;
	esac
}
pkg_installed() { # family package
	case "$1" in
	deb) dpkg -s "$2" >/dev/null 2>&1 ;;
	rpm) rpm -q "$2" >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
}
# check_card_prerequisites refuses, naming the packages of the board's family, when the card service, its CCID driver or, where
# pcscd asks polkit, polkit is missing. The package names differ by family; the checks that do not need a package manager (the
# units and files) decide on a family that is not known.
check_card_prerequisites() {
	local fam missing=() pcscd ccid polkit
	fam=$(os_family)
	case "$fam" in
	deb) pcscd=pcscd ccid=libccid polkit=polkitd ;;
	rpm) pcscd=pcsc-lite ccid=pcsc-lite-ccid polkit=polkit ;;
	*) pcscd="the card service (pcscd)" ccid="its CCID driver" polkit="polkit" ;;
	esac
	if [ "$fam" != unknown ]; then
		pkg_installed "$fam" "$pcscd" || missing+=("$pcscd")
		pkg_installed "$fam" "$ccid" || missing+=("$ccid")
	else
		systemctl cat pcscd.socket >/dev/null 2>&1 || missing+=("$pcscd")
		compgen -G '/usr/lib*/pcsc/drivers/ifd-ccid.bundle' >/dev/null || missing+=("$ccid")
	fi
	# A pcscd built with polkit (it ships its policy; Debian since pcsc-lite 2.0.1, RHEL 10) asks polkit about every client and
	# refuses a system service by default, so without polkit the card driver cannot reach the card.
	if [ -e "$card_polkit_policy" ]; then
		if [ "$fam" != unknown ] && ! pkg_installed "$fam" "$polkit"; then
			missing+=("$polkit")
		elif ! systemctl cat polkit.service >/dev/null 2>&1 && ! command -v pkcheck >/dev/null 2>&1; then
			missing+=("$polkit")
		fi
	fi
	if [ "${#missing[@]}" -gt 0 ]; then
		echo "remote: the card driver needs, on this board (${fam} family): ${missing[*]}. The deploy installs no package: put them in the board image, then deploy again." >&2
		return 1
	fi
}

# require_credential_encryption refuses a board that cannot encrypt a credential for LoadCredentialEncrypted=: no systemd-creds, or
# a systemd older than the floor (252). The units are generated with LoadCredentialEncrypted=, which an older systemd does not
# know, so a credential would never arrive.
credential_floor=252
require_credential_encryption() {
	local v
	if ! command -v systemd-creds >/dev/null 2>&1; then
		echo "remote: the credentials are encrypted on the board, and systemd-creds is missing (it is in systemd ${credential_floor} and later)." >&2
		return 1
	fi
	v=""
	read -r _ v _ < <(systemctl --version 2>/dev/null) || true # "systemd 259 (259-1)"
	case "$v" in *[!0-9]*) v="" ;; esac
	if [ -z "$v" ] || [ "$v" -lt "$credential_floor" ]; then
		echo "remote: the board has systemd ${v:-unknown}; the floor is ${credential_floor} (LoadCredentialEncrypted=). Reflash the board with a supported operating system (docs/runtimes/bare-metal.md, \"Supported operating systems\")." >&2
		return 1
	fi
}
# encrypt_credential name plain-file destination: the credential, encrypted under the host key and named for the unit's
# LoadCredentialEncrypted= line (systemd refuses a blob whose embedded name differs), written 0400 root by a rename, so a unit
# never reads half a file.
encrypt_credential() {
	local name=$1 plain=$2 dest=$3 tmp
	tmp=$(mktemp "$dest.XXXXXX")
	if ! systemd-creds encrypt --with-key=host --name="$name" "$plain" "$tmp"; then
		rm -f -- "$tmp"
		echo "remote: systemd-creds could not encrypt the credential $name" >&2
		return 1
	fi
	chown root:root "$tmp"
	chmod 0400 "$tmp"
	mv -f -- "$tmp" "$dest"
}

# relabel gives the files this deploy made the labels that the SELinux policy has for their paths. It does nothing where SELinux
# is not enabled. The binaries become bin_t and systemd starts them as unconfined_service_t (the policy of RHEL and Rocky); the
# state is var_lib_t and the sockets var_run_t. It touches only what sluis owns: -R over /opt/sluis and /etc/sluis (root's), and
# the state root and the files and directories that the manifest of this deploy lists elsewhere (units, drop-ins, sysusers and
# tmpfiles files, the polkit rule), each one alone, never a whole directory of the system. A failure is a warning: the files are
# there, and the label is what a later restorecon or a policy module is for.
relabel() {
	command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled || return 0
	command -v restorecon >/dev/null 2>&1 || { echo "remote: warning: SELinux is enabled and restorecon is missing; the files keep the labels they were made with" >&2; return 0; }
	local p kind value roots=() singles=()
	# The state directories belong to the sluis service users, who could swap one for a link while a recursive walk is in it: the
	# state root and the directories this deploy made (they are in the manifest) are relabelled alone, never walked. The
	# services make their own files with the labels the policy gives them.
	for p in /opt/sluis /etc/sluis; do
		[ ! -e "$p" ] || roots+=("$p")
	done
	[ ! -e "$state_root" ] || singles+=("$state_root")
	if [ -f "$manifest" ]; then
		while IFS=$'\t' read -r kind value; do
			case "$kind" in file | dir) ;; *) continue ;; esac
			case "$value" in /opt/sluis | /opt/sluis/* | /etc/sluis | /etc/sluis/*) continue ;; esac
			[ ! -e "$value" ] || singles+=("$value")
		done <"$manifest"
	fi
	if [ "${#roots[@]}" -gt 0 ]; then
		restorecon -R "${roots[@]}" || echo "remote: warning: restorecon did not label everything below sluis's own directories" >&2
	fi
	if [ "${#singles[@]}" -gt 0 ]; then
		restorecon -- "${singles[@]}" || echo "remote: warning: restorecon did not label every file of the deploy" >&2
	fi
}


# check_pinned_groups before|after FILE...: the groups of the sysusers files that pin a number ("g NAME GID", the groups of key@'s
# caller directories) must have that number. systemd-sysusers gives a group another number, and says nothing, when the pinned
# one is taken (sysusers.d(5)), and a number in systemd's dynamic range can be. The units join the group by name, so they would
# still work, but Compose, the uid plan and every reader of a number would name another group. `before` refuses, before
# anything is written, a group of that name with another number and a pinned number that another group already has; `after`,
# once systemd-sysusers has run, refuses any group that does not have its pinned number.
check_pinned_groups() {
	local when=$1 f kind name gid line got bad=()
	shift
	for f in "$@"; do
		while read -r kind name gid _; do
			[ "$kind" = g ] || continue
			case "$gid" in '' | *[!0-9]*) continue ;; esac
			line=$(getent group "$name") || line=""
			got=""
			[ -z "$line" ] || IFS=: read -r _ _ got _ <<<"$line"
			if [ -n "$got" ] && [ "$got" != "$gid" ]; then
				bad+=("$name has the number $got, not $gid")
			elif [ -z "$got" ] && [ "$when" = after ]; then
				bad+=("$name does not exist")
			elif [ -z "$got" ]; then
				line=$(getent group "$gid") || line=""
				[ -z "$line" ] || bad+=("$gid, the number of $name, is already the group ${line%%:*}")
			fi
		done <"$f"
	done
	if [ "${#bad[@]}" -gt 0 ]; then
		local IFS=';'
		echo "remote: a group does not have its pinned number (${bad[*]}). systemd-sysusers takes another number when the pinned one is taken, and the deploy refuses that: free the number on the board, run 'just boards-undeploy' if this deploy made the group, then deploy again." >&2
		return 1
	fi
}
