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


# id_entry DB KEY: getent's entry for KEY, a name or a number, in DB (group or passwd), or nothing when there is none (getent's
# exit 2). Any other failure of getent fails, so a lookup that could not be made never reads as a free number.
id_entry() {
	local out rc=0
	out=$(getent "$1" "$2") || rc=$?
	case "$rc" in
	0) printf '%s\n' "$out" ;;
	2) ;;
	*) return 1 ;;
	esac
}

# check_pinned_ids before|after FILE...: the users and groups of the sysusers files that pin a number ("u NAME UID", the users
# of the uid plan; "g NAME GID", the groups of key@'s caller directories) must have that number. systemd-sysusers gives a user
# or group another number, and says nothing, when the pinned one is taken (sysusers.d(5)). It counts a pinned uid as taken
# when a user has it, or a group of another name has it as its gid (uid_is_ok with check_with_gid, for "u NAME UID"; not for
# "u NAME UID:GID"); it counts a pinned gid as taken when a group has it (gid_is_ok, which does not weigh the users for a
# pinned gid). The gids sit in systemd's dynamic range (61184 and up), and so do the uids of every uid block but 0. The units
# join a group by name, so they would still work, but the peer-uid check, Compose, the uid plan and every reader of a number
# would name another user or group.
#   before  refuses, before anything is written, a user or group of the name with another number, a pinned number that
#           systemd-sysusers counts as taken, and a pinned gid that a user of another name has as its uid (systemd-sysusers
#           keeps that gid; the deploy refuses it anyway, because the uid plan keeps one number for one name);
#   after   once systemd-sysusers has run, refuses any user or group that does not have its pinned number.
# A user's own group is checked with it: for "u NAME UID" systemd-sysusers makes the group NAME with the number UID, or puts
# the user in a group NAME that exists with whatever number it has, so a group NAME with another number, and a user whose
# primary group is not UID, are refused (for "u NAME UID:GID", the primary group must be GID).
# Both fail closed: no getent, or a getent that fails for another reason than "not found", is a refusal; so are a line of a
# kind the check does not know (the kinds are u, g, m and r), and a sweep that finds no pinned number to check.
check_pinned_ids() {
	local when=$1 f kind name id raw strict line got ugid pgid pgroup other checked=0 bad=() unknown=()
	shift
	if ! command -v getent >/dev/null 2>&1; then
		echo "remote: getent is missing, so the pinned uids and gids cannot be checked; the deploy refuses rather than take them as free." >&2
		return 1
	fi
	for f in "$@"; do
		while read -r kind name id _; do
			case "$kind" in
			'' | \#*) continue ;;
			m | r) continue ;; # a membership or a range pins no number
			u | g) ;;
			*)
				# A kind this check does not know (u! of a newer systemd, a typo) could make a user or group it never saw.
				unknown+=("${f##*/}: $kind")
				continue
				;;
			esac
			raw=$id strict=""
			case "$kind:$id" in
			u:*:*) strict=1 id=${id%%:*} ;; # "uid:gid": systemd-sysusers does not weigh the groups for the uid
			esac
			case "$id" in '' | *[!0-9]*) continue ;; esac
			checked=$((checked + 1))
			if [ "$kind" = u ]; then
				# The user's primary group: the group of its own name, which systemd-sysusers makes with the uid's number or
				# takes as it finds it when one of that name exists; or the GID of "uid:gid" (a group named there pins no
				# number here).
				pgid=$id pgroup=$name
				if [ -n "$strict" ]; then
					pgid=${raw#*:} pgroup=""
					case "$pgid" in '' | *[!0-9]*) pgid="" ;; esac
				fi
				line=$(id_entry passwd "$name") || { bad+=("getent cannot read the user $name"); continue; }
				got="" ugid=""
				[ -z "$line" ] || IFS=: read -r _ _ got ugid _ <<<"$line"
				if [ -n "$got" ] && [ "$got" != "$id" ]; then
					bad+=("the user $name has the uid $got, not $id")
				elif [ -z "$got" ] && [ "$when" = after ]; then
					bad+=("the user $name does not exist")
				elif [ -z "$got" ]; then
					line=$(id_entry passwd "$id") || { bad+=("getent cannot read the user $id"); continue; }
					[ -z "$line" ] || bad+=("$id, the uid of $name, is already the user ${line%%:*}")
					if [ -z "$strict" ]; then
						line=$(id_entry group "$id") || { bad+=("getent cannot read the group $id"); continue; }
						other=${line%%:*}
						[ -z "$line" ] || [ "$other" = "$name" ] || bad+=("$id, the uid of $name, is already the number of the group $other")
					fi
				elif [ -n "$pgid" ] && [ "$ugid" != "$pgid" ]; then
					bad+=("the user $name has the primary group number $ugid, not $pgid")
				fi
				[ -n "$pgroup" ] || continue
				line=$(id_entry group "$pgroup") || { bad+=("getent cannot read the group $pgroup"); continue; }
				got=""
				[ -z "$line" ] || IFS=: read -r _ _ got _ <<<"$line"
				if [ -n "$got" ] && [ "$got" != "$id" ]; then
					bad+=("the group $pgroup of the user $name has the number $got, not $id")
				elif [ -z "$got" ] && [ "$when" = after ]; then
					bad+=("the group $pgroup of the user $name does not exist")
				fi
				continue
			fi
			line=$(id_entry group "$name") || { bad+=("getent cannot read the group $name"); continue; }
			got=""
			[ -z "$line" ] || IFS=: read -r _ _ got _ <<<"$line"
			if [ -n "$got" ] && [ "$got" != "$id" ]; then
				bad+=("$name has the number $got, not $id")
			elif [ -z "$got" ] && [ "$when" = after ]; then
				bad+=("$name does not exist")
			elif [ -z "$got" ]; then
				line=$(id_entry group "$id") || { bad+=("getent cannot read the group $id"); continue; }
				[ -z "$line" ] || bad+=("$id, the number of $name, is already the group ${line%%:*}")
				line=$(id_entry passwd "$id") || { bad+=("getent cannot read the user $id"); continue; }
				other=${line%%:*}
				[ -z "$line" ] || [ "$other" = "$name" ] || bad+=("$id, the number of $name, is already the uid of the user $other")
			fi
		done <"$f"
	done
	if [ "${#unknown[@]}" -gt 0 ]; then
		local IFS=';'
		echo "remote: a sysusers line of a kind this check does not know (${unknown[*]}); the deploy refuses a user or group it cannot check." >&2
		return 1
	fi
	if [ "${#bad[@]}" -gt 0 ]; then
		local IFS=';'
		echo "remote: a user or group does not have its pinned number (${bad[*]}). systemd-sysusers takes another number when the pinned one is taken, and the deploy refuses that: free the number on the board, run 'just boards-undeploy' if this deploy made the user or group, then deploy again." >&2
		return 1
	fi
	if [ "$checked" -eq 0 ]; then
		echo "remote: no sysusers line with a pinned uid or gid was found in $# file(s): a check of nothing is no check, and the deploy refuses it." >&2
		return 1
	fi
}

# --- rqlite -------------------------------------------------------------------------------------------------------------------
# The engine is rqlite's own upstream package (rqlite.sh puts it on the board and runs remote.sh rqlite-install). The package
# brings /usr/bin/rqlited, the user and group rqlite, /var/lib/rqlite (0750) and rqlited.service, which runs
# `/usr/bin/rqlited /var/lib/rqlite/data` and is not enabled. What the deploy adds is one drop-in of that unit; its presence is
# also what says that this tool installed rqlite on the board, so that undeploy touches no rqlite that someone else made.
rqlite_unit=rqlited.service
rqlite_dropin_dir=/etc/systemd/system/rqlited.service.d
rqlite_dropin=$rqlite_dropin_dir/10-sluis.conf
rqlite_data_dir=/var/lib/rqlite/data

# rqlite_valid_ipv4 says whether the argument is a dotted IPv4 address; rqlite binds and advertises the address of the board, and
# peers dial it, so a name that resolves differently on two boards is not taken.
rqlite_valid_ipv4() {
	local o
	[[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
	local IFS=.
	for o in $1; do [ "$((10#$o))" -le 255 ] || return 1; done
}
rqlite_valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 65535 ]; }

# rqlite_dropin_text node ip http_port raft_port join prints the drop-in: the ExecStart of the package, reset, and again with the
# node id, the HTTP and Raft addresses of the board (-http-addr, -raft-addr: the flags of rqlited 10) and, on a node that is not the
# bootstrap one, -join with the Raft address (host:port) of the bootstrap node. The join is empty for the bootstrap node, which
# then starts a cluster of one. A node that already has state ignores -join on a restart and takes its place in the cluster.
rqlite_dropin_text() { # node ip http_port raft_port join
	[[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || { echo "remote: refusing the rqlite node id '$1'" >&2; return 1; }
	rqlite_valid_ipv4 "$2" || { echo "remote: refusing the rqlite address '$2'" >&2; return 1; }
	if ! rqlite_valid_port "$3" || ! rqlite_valid_port "$4"; then
		echo "remote: refusing the rqlite ports '$3' '$4'" >&2
		return 1
	fi
	local join=""
	if [ -n "${5:-}" ]; then
		if ! [[ "$5" =~ ^[0-9.]+:[0-9]+$ ]] || ! rqlite_valid_ipv4 "${5%:*}" || ! rqlite_valid_port "${5#*:}"; then
			echo "remote: refusing the rqlite join address '$5'" >&2
			return 1
		fi
		join=" -join $5"
	fi
	printf '%s\n' \
		'# Made by sluis (just boards-rqlite). Do not edit: the next run writes it again.' \
		'# No TLS and no authentication yet: the firewall of the board must admit these ports from the peers alone.' \
		'[Service]' \
		'ExecStart=' \
		"ExecStart=/usr/bin/rqlited -node-id $1 -http-addr $2:$3 -raft-addr $2:$4$join $rqlite_data_dir"
}

# rqlite_install_package file installs an upstream package with the package manager of the board's family, from the file, which
# rqlite.sh checked against its pin before it left the workstation. The package manager is not asked to check a signature: upstream
# signs nothing, and the pin is the trust.
rqlite_install_package() { # file
	case "$1" in
	*.deb)
		command -v apt-get >/dev/null 2>&1 || { echo "remote: a .deb package, and the board has no apt-get" >&2; return 1; }
		DEBIAN_FRONTEND=noninteractive apt-get install -y -- "$1"
		;;
	*.rpm)
		command -v dnf >/dev/null 2>&1 || { echo "remote: an .rpm package, and the board has no dnf" >&2; return 1; }
		dnf install -y -- "$1"
		;;
	*) echo "remote: not a package: $1" >&2; return 1 ;;
	esac
}

# rqlite_relabel gives the files of the package and of the drop-in the labels that the policy has for their paths, where SELinux
# is on: the binaries, the unit and its drop-ins, and the data directory alone (never walked: it is the service user's). Without
# it an rqlite that was started before any relabel can fail to execute or run in the wrong domain. A failure is a warning.
rqlite_relabel() {
	command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled || return 0
	command -v restorecon >/dev/null 2>&1 || { echo "remote: warning: SELinux is enabled and restorecon is missing; the rqlite files keep the labels they were made with" >&2; return 0; }
	local p fragment list=()
	fragment=$(systemctl show -p FragmentPath --value "$rqlite_unit" 2>/dev/null || true)
	for p in /usr/bin/rqlited /usr/bin/rqlite /usr/bin/rqbench /var/lib/rqlite "$fragment" "$rqlite_dropin_dir" "$rqlite_dropin"; do
		[ -n "$p" ] && [ -e "$p" ] && list+=("$p")
	done
	[ "${#list[@]}" -gt 0 ] || return 0
	restorecon -v -- "${list[@]}" || echo "remote: warning: restorecon did not label every rqlite file" >&2
}

# --- SELinux denials ----------------------------------------------------------------------------------------------------------

# selinux_enforcing says whether the board runs SELinux in enforcing mode.
selinux_enforcing() {
	command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = Enforcing ]
}

# avc_check prints the AVC and USER_AVC records since the boot of a board with SELinux enforcing, and fails when one of them names
# a sluis or rqlite path or domain (the comm, a path or name, the source or target context). A denial of a program that is not
# ours is printed and does not fail: the check is about the labels of our own files. It also fails when SELinux is enforcing and
# `ausearch` is missing, because then it cannot see a denial and "nothing found" would be a guess (install audit).
avc_check() {
	local out rc=0 all ours
	if ! selinux_enforcing; then
		echo "avc: SELinux is not enforcing on this board; nothing to check"
		return 0
	fi
	command -v ausearch >/dev/null 2>&1 || { echo "avc: SELinux is enforcing and ausearch is missing: install the audit package (dnf install audit), or the denials cannot be read" >&2; return 1; }
	out=$(ausearch -m AVC,USER_AVC -ts boot 2>&1) || rc=$?
	# ausearch exits 1 and says "<no matches>" when there is nothing; any other failure is not a clean board.
	if [ "$rc" -ne 0 ] && ! grep -q 'no matches' <<<"$out"; then
		echo "avc: ausearch failed (status $rc): $out" >&2
		return 1
	fi
	all=$(grep -E 'type=(USER_)?AVC' <<<"$out" || true)
	if [ -z "$all" ]; then
		echo "avc: no AVC or USER_AVC record since boot"
		return 0
	fi
	ours=$(grep -Ei 'sluis|rqlite' <<<"$all" || true)
	local n_all=0 n_ours=0
	n_all=$(wc -l <<<"$all")
	[ -z "$ours" ] || n_ours=$(wc -l <<<"$ours")
	echo "avc: $n_all AVC/USER_AVC records since boot, $n_ours naming sluis or rqlite"
	printf '%s\n' "$all"
	if [ -n "$ours" ]; then
		echo "avc: FAILED: the records above name a sluis or rqlite path or domain" >&2
		return 1
	fi
}
