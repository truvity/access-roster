#!/usr/bin/env bash
# shellcheck disable=SC2154 # card_polkit_policy and state_root are the caller's
# shellcheck disable=SC1090 # the board's os-release is read from a path that a test can change
# The checks of remote.sh that depend on the board's operating system, kept apart so that a test can run them against a fake
# package manager and a fake os-release. Sourced by remote.sh, never run. It reads, from the caller:
#   card_polkit_policy   the polkit policy file that a pcscd built with polkit ships
#   state_root           the directory of the units' state
#   manifest             the file that lists what the deploy made (kind<TAB>path)
#   os_release_file      /etc/os-release, unless the caller says otherwise (a test)
#   selinux_enforce_file /sys/fs/selinux/enforce, unless the caller says otherwise (a test)

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

# SELinux is read from selinuxfs, not from a command: /sys/fs/selinux/enforce exists where SELinux is enabled (its content is 1 when
# enforcing, 0 when permissive), and needs neither libselinux-utils (getenforce, selinuxenabled) nor policycoreutils, which a thin
# image such as the Rocky 10 image of the boards does not carry. Where the file is missing, SELinux is off.
selinux_enforce_file=${selinux_enforce_file:-/sys/fs/selinux/enforce}
selinux_enabled() { [ -e "$selinux_enforce_file" ]; }
selinux_enforcing() {
	local v=""
	if [ -r "$selinux_enforce_file" ]; then read -r v <"$selinux_enforce_file" || true; fi
	[ "$v" = 1 ]
}

# relabel gives the files this deploy made the labels that the SELinux policy has for their paths. It does nothing where SELinux
# is not enabled (selinux_enabled). The binaries become bin_t and systemd starts them as unconfined_service_t (the policy of RHEL and Rocky); the
# state is var_lib_t and the sockets var_run_t. It touches only what sluis owns: -R over /opt/sluis and /etc/sluis (root's), and
# the state root and the files and directories that the manifest of this deploy lists elsewhere (units, drop-ins, sysusers and
# tmpfiles files, the polkit rule), each one alone, never a whole directory of the system. A failure is a warning: the files are
# there, and the label is what a later restorecon or a policy module is for.
relabel() {
	selinux_enabled || return 0
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
# The paths can be moved by the caller for a test; on a board they are these.
rqlite_unit=rqlited.service
rqlite_dropin_dir=${rqlite_dropin_dir:-/etc/systemd/system/rqlited.service.d}
rqlite_dropin=$rqlite_dropin_dir/10-sluis.conf
rqlite_var_dir=${rqlite_var_dir:-/var/lib/rqlite}
rqlite_data_dir=$rqlite_var_dir/data
rqlite_bin=${rqlite_bin:-/usr/bin/rqlited}

# rqlite_valid_ipv4 says whether the argument is a dotted IPv4 address with no leading zeros ("192.0.2.010" is refused: Go's
# parser refuses it at bind); rqlite binds and advertises the address of the board, and peers dial it, so a name that resolves
# differently on two boards is not taken.
rqlite_valid_ipv4() {
	local o
	[[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
	local IFS=.
	for o in $1; do
		[[ "$o" =~ ^(0|[1-9][0-9]*)$ ]] && [ "$o" -le 255 ] || return 1
	done
}
rqlite_valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]; }

# rqlite_dropin_text ip http_port raft_port expect joins prints the drop-in: the ExecStart of the package, reset, and again with
# the HTTP and Raft addresses of the board (-http-addr, -raft-addr: the flags of rqlited 10) and, for a cluster of more than one
# node, -bootstrap-expect with the number of nodes and -join with the Raft addresses (host:port, comma separated) of ALL of them,
# this one included. That is the shape that rqlite documents for a cluster that comes up together, and it is what makes a split
# brain impossible: a node that has no state cannot form a cluster by itself (rqlite 10.6.6, cmd/rqlited/main.go createCluster: a
# node with no -join and no state bootstraps a cluster of one; with -bootstrap-expect it first tries to join a node that is in a
# cluster, and only when N nodes have announced themselves does one of them form the cluster), so a board that was wiped or
# reflashed joins the cluster that the others hold, and N nodes that start together form one cluster. A node that has state
# does not form a cluster again: it takes up its place in the one it was in. (rqlite's Boot does run again on every start of
# a node with -bootstrap-expect, and it finds the node already a member: that is harmless, and the reason the flags can stay in
# the drop-in for good.) There is no -node-id: rqlite takes the Raft address
# as the id, which is the same on every start, is different on every board, and cannot be taken from a host name that moved.
# The join list is the voter set, so a node that is added later is a run with the longer list (every drop-in is written again).
# A cluster of one has neither flag: nothing else can hold state it could split from.
rqlite_dropin_text() { # ip http_port raft_port expect joins
	local ip=$1 http=$2 raft=$3 expect=$4 joins=${5:-} a n=0 self=0 flags=""
	rqlite_valid_ipv4 "$ip" || { echo "remote: refusing the rqlite address '$ip'" >&2; return 1; }
	if ! rqlite_valid_port "$http" || ! rqlite_valid_port "$raft"; then
		echo "remote: refusing the rqlite ports '$http' '$raft'" >&2
		return 1
	fi
	if [ "$http" = "$raft" ]; then
		echo "remote: refusing the rqlite ports '$http' '$raft': the HTTP and the Raft port must differ" >&2
		return 1
	fi
	[[ "$expect" =~ ^[1-9][0-9]{0,2}$ ]] || { echo "remote: refusing the rqlite cluster size '$expect'" >&2; return 1; }
	if [ "$expect" -eq 1 ]; then
		[ -z "$joins" ] || { echo "remote: a cluster of one takes no join list ('$joins')" >&2; return 1; }
	else
		local -A seen=()
		local IFS=,
		for a in $joins; do
			if ! [[ "$a" =~ ^[0-9.]+:[0-9]+$ ]] || ! rqlite_valid_ipv4 "${a%:*}" || ! rqlite_valid_port "${a#*:}"; then
				echo "remote: refusing the rqlite join address '$a'" >&2
				return 1
			fi
			[ -z "${seen[$a]:-}" ] || { echo "remote: the rqlite join address '$a' is listed twice" >&2; return 1; }
			seen[$a]=1
			n=$((n + 1))
			[ "$a" != "$ip:$raft" ] || self=1
		done
		if [ "$n" -ne "$expect" ] || [ "$self" -ne 1 ]; then
			echo "remote: the join list must name all $expect nodes, this one ($ip:$raft) included; it names $n" >&2
			return 1
		fi
		flags=" -bootstrap-expect $expect -join $joins"
	fi
	printf '%s\n' \
		'# Made by sluis (just boards-rqlite). Do not edit: the next run writes it again.' \
		'# No TLS and no authentication yet: the firewall of the board must admit these ports from the peers alone.' \
		'[Service]' \
		'ExecStart=' \
		"ExecStart=$rqlite_bin -http-addr $ip:$http -raft-addr $ip:$raft$flags $rqlite_data_dir"
}

# rqlite_board_has_ip says whether one of the addresses of the board is the argument. rqlite binds the address it is given, and a
# bind to an address the board does not own fails after systemd has already reported the service started; an ssh through a NAT or
# an alias would give such an address. Without `ip` the answer is yes (the bind fails later and the wait says so).
rqlite_board_has_ip() { # ip
	local addrs
	command -v ip >/dev/null 2>&1 || return 0
	addrs=$(ip -o -4 addr show 2>/dev/null) || return 0
	[[ "$addrs" == *" $1/"* ]]
}

# rqlite_install_package file installs an upstream package with the package manager of the board's family, from the file, which
# rqlite.sh checked against its pin before it left the workstation (and the board checks again before this runs). The package
# manager is not asked to check a signature: upstream signs nothing, and the pin is the trust.
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
	selinux_enabled || return 0
	command -v restorecon >/dev/null 2>&1 || { echo "remote: warning: SELinux is enabled and restorecon is missing; the rqlite files keep the labels they were made with" >&2; return 0; }
	local p fragment list=()
	fragment=$(systemctl show -p FragmentPath --value "$rqlite_unit" 2>/dev/null || true)
	for p in "$rqlite_bin" /usr/bin/rqlite /usr/bin/rqbench "$rqlite_var_dir" "$fragment" "$rqlite_dropin_dir" "$rqlite_dropin"; do
		[ -n "$p" ] && [ -e "$p" ] && list+=("$p")
	done
	[ "${#list[@]}" -gt 0 ] || return 0
	restorecon -v -- "${list[@]}" || echo "remote: warning: restorecon did not label every rqlite file" >&2
}

# --- SELinux denials ----------------------------------------------------------------------------------------------------------

# avc_auditd_ok succeeds when auditd is running and the kernel's audit is enabled (auditctl -s: enabled 1, or 2 when the audit
# configuration is locked as immutable, which records as well). ausearch reads auditd's log, so a denial from
# before auditd started (a board where `dnf install audit` was just run, with no reboot) is in the journal only, and "no matches"
# would be a guess: the check refuses to say "clean" then.
avc_auditd_ok() {
	local st enabled=""
	st=$(systemctl is-active auditd 2>/dev/null || true)
	if command -v auditctl >/dev/null 2>&1; then
		enabled=$(auditctl -s 2>/dev/null | sed -n 's/^enabled \([0-9][0-9]*\).*/\1/p' | head -n 1 || true)
	fi
	if [ "$st" = active ] && { [ "$enabled" = 1 ] || [ "$enabled" = 2 ]; }; then return 0; fi
	echo "avc: auditd is not recording (auditd is '${st:-unknown}', audit enabled='${enabled:-unknown}'): denials before auditd started are not visible, so no record would not mean no denial. Install and enable it (dnf install audit; systemctl enable --now auditd) and reboot the board once, so that it records from the start of the boot." >&2
	return 1
}

# avc_exec_names prints the names that the kernel gives the processes of the executables this deploy made (the `comm`: the
# basename of the executable, cut to 15 characters), from the files of the manifest below the bin directory.
avc_exec_names() {
	local kind value b dir=${bin_dir:-/opt/sluis/bin}
	[ -f "${manifest:-}" ] || return 0
	while IFS=$'\t' read -r kind value; do
		[ "$kind" = file ] || continue
		case "$value" in
		"$dir"/actors/* | "$dir"/drivers/* | "$dir"/cli/*)
			b=${value##*/}
			printf '%s\n' "${b:0:15}"
			;;
		esac
	done <"$manifest"
}

# avc_record_is_ours says whether an AVC or USER_AVC record is a denial of sluis or of what it depends on. It is, when the
# denial was enforced (permissive=0, or no permissive field: a userspace USER_AVC has none; a record with permissive=1 was only
# logged) and
#   - its source or target type is unconfined_service_t (what the units run as under the policy of RHEL and Rocky), pcscd_t or
#     pcscd_var_run_t (the card service and its socket), or
#   - its comm is the name of an executable of this deploy ($avc_names, from the manifest), or
#   - its comm, exe, path or name names sluis or rqlite (a field, not the whole record: a host name is not a path).
avc_record_is_ours() { # record
	local rec=$1 f t v re c
	[[ "$rec" != *"permissive=1"* ]] || return 1
	for f in scontext tcontext; do
		re="[[:space:]]$f=[^:[:space:]]*:[^:[:space:]]*:([^:[:space:]]*)"
		if [[ "$rec" =~ $re ]]; then
			t=${BASH_REMATCH[1]}
			case "$t" in unconfined_service_t | pcscd_t | pcscd_var_run_t) return 0 ;; esac
		fi
	done
	re='[[:space:]]comm="([^"]*)"'
	if [[ "$rec" =~ $re ]]; then
		c=${BASH_REMATCH[1]}
		c=${c#\(}
		c=${c%\)} # a unit that is being started shows as "(name)"
		c=${c:0:15}
		case $'\n'"${avc_names:-}"$'\n' in *$'\n'"$c"$'\n'*) [ -z "$c" ] || return 0 ;; esac
	fi
	for f in comm exe path name; do
		re="[[:space:]]$f=\"([^\"]*)\""
		if [[ "$rec" =~ $re ]]; then
			v=${BASH_REMATCH[1],,}
			case "$v" in *sluis* | *rqlite*) return 0 ;; esac
		fi
	done
	return 1
}

# avc_check prints the AVC and USER_AVC records since the boot of a board with SELinux enforcing, and fails when one is a denial of
# ours (avc_record_is_ours). REQ-DEPLOY-033 says "no AVC denial", and these are the denials that can be about us: the domain the
# units run in, the card service and its socket, the executables of the deploy, and any sluis or rqlite path. The other records
# are printed as warnings and do not fail the check. It fails closed when it cannot see: SELinux enforcing and no `ausearch`, or
# no running auditd (avc_auditd_ok).
avc_check() {
	local out rc=0 line n_all=0 avc_names="" ours=() others=()
	if ! selinux_enforcing; then
		echo "avc: SELinux is not enforcing on this board; nothing to check"
		return 0
	fi
	command -v ausearch >/dev/null 2>&1 || { echo "avc: SELinux is enforcing and ausearch is missing: install the audit package (dnf install audit), or the denials cannot be read" >&2; return 1; }
	avc_auditd_ok || return 1
	avc_names=$(avc_exec_names)
	out=$(ausearch -m AVC,USER_AVC -ts boot 2>&1) || rc=$?
	# ausearch exits 1 and says "<no matches>" when there is nothing; any other failure is not a clean board.
	if [ "$rc" -ne 0 ] && ! grep -q 'no matches' <<<"$out"; then
		echo "avc: ausearch failed (status $rc): $out" >&2
		return 1
	fi
	while IFS= read -r line; do
		[[ "$line" =~ ^type=(USER_)?AVC ]] || continue
		n_all=$((n_all + 1))
		if avc_record_is_ours "$line"; then ours+=("$line"); else others+=("$line"); fi
	done <<<"$out"
	if [ "$n_all" -eq 0 ]; then
		echo "avc: no AVC or USER_AVC record since boot"
		return 0
	fi
	echo "avc: $n_all AVC/USER_AVC records since boot, ${#ours[@]} denials of sluis or what it needs, ${#others[@]} others"
	for line in ${others[@]+"${others[@]}"}; do printf 'avc: warning: %s\n' "$line"; done
	for line in ${ours[@]+"${ours[@]}"}; do printf 'avc: DENIED: %s\n' "$line"; done
	if [ "${#ours[@]}" -gt 0 ]; then
		echo "avc: FAILED: the records above marked DENIED are enforced denials in the domain of the units (unconfined_service_t), of the card service (pcscd_t, pcscd_var_run_t), of an executable of this deploy, or of a sluis or rqlite path" >&2
		return 1
	fi
}

# --- The wait for the units after the start -------------------------------------------------------------------------------------------
# `systemd-analyze verify` (remote.sh) only reads the unit files, before anything starts, so its "ok" says nothing about a run.
# What says that the units run is settle_units: it polls them until each one is `active (running)` with its NRestarts standing
# still for settle_stable polls in a row, or until settle_timeout seconds are over. (A unit in a restart loop is "activating
# (auto-restart)" most of the time and `active` for a moment in between, so one sample of `is-active` can say active for a unit
# that dies every two seconds.) Each unit that did not settle is reported with the last lines of its journal, and fails the
# deploy, with one exception: the locked card board.
#
# The locked board (docs/runtimes/bare-metal.md, "The card driver"): a card board starts with no PIN. Its card driver is up and
# waits for `sluis node unlock`; key@ asks the driver to Ensure its keys, the driver refuses with the reason "locked", and key@
# exits with `failed_precondition: locked` until the PIN is given. That is a state the operator ends with boards-unlock and not a
# fault of the deploy, so it is the outcome `locked` (status settle_locked_status, not a failure) when, and only when:
#   - the card driver's unit settled (it holds the PIN, so it must be up);
#   - key@ did not settle, and the last lines of its journal say `failed_precondition: locked`;
#   - every other unit that did not settle names key@'s runtime directory (/run/sluis/key/) in its journal, so it stumbled on
#     key@, which is down. A unit with a fault of its own (the credentials of store@, say) is never taken for a locked board.
# Anything else that did not settle is a failure.
#
# It reads $boundary from the caller. Tunables, for a test: settle_timeout (60 s), settle_step (2 s between polls), settle_stable
# (3 polls in a row), settle_journal_lines (10).
settle_timeout=${settle_timeout:-60}
settle_step=${settle_step:-2}
settle_stable=${settle_stable:-3}
settle_journal_lines=${settle_journal_lines:-10}
settle_locked_status=10

# unit_state UNIT prints "ActiveState SubState NRestarts".
unit_state() {
	local k v a="" s="" n=""
	while IFS='=' read -r k v; do
		case "$k" in ActiveState) a=$v ;; SubState) s=$v ;; NRestarts) n=$v ;; esac
	done < <(systemctl show -p ActiveState -p SubState -p NRestarts "$1" 2>/dev/null || true)
	printf '%s %s %s\n' "${a:-unknown}" "${s:-unknown}" "${n:-0}"
}

# settle_units UNIT... waits as described above and prints one line per unit: `unit U active`, `unit U locked ...`, or
# `unit U FAILED: ...` followed by the last lines of its journal. It returns 0 when all settled, settle_locked_status when the
# board is only locked, and 1 otherwise.
settle_units() {
	local u a s n polls=0 max all key_unit card_unit journal locked=0 failed=0 board_locked=no
	local -A prev=() run=() last=() settled=() verdict=()
	key_unit=sluis-key@$boundary.service
	card_unit=sluis-drv-key-yubikey-piv@$boundary.service
	max=$(awk -v t="$settle_timeout" -v s="$settle_step" 'BEGIN { printf "%d", t / s }')
	while :; do
		all=1
		for u in "$@"; do
			read -r a s n <<<"$(unit_state "$u")"
			if [ "$a" = active ] && [ "$s" = running ] && [ "${prev[$u]:-}" = "$n" ]; then
				run[$u]=$((${run[$u]:-0} + 1))
			else
				run[$u]=0
			fi
			prev[$u]=$n
			last[$u]="$a ($s), restarted $n times"
			[ "${run[$u]}" -ge "$settle_stable" ] || all=0
		done
		[ "$all" = 1 ] && break
		[ "$polls" -lt "$max" ] || break
		sleep "$settle_step"
		polls=$((polls + 1))
	done
	for u in "$@"; do
		if [ "${run[$u]}" -ge "$settle_stable" ]; then settled[$u]=1; else settled[$u]=0; fi
	done
	# The locked board: the card driver is up and key@ says why it is not.
	if [ "${settled[$card_unit]:-0}" = 1 ] && [ "${settled[$key_unit]:-1}" = 0 ]; then
		journal=$(journalctl -u "$key_unit" -n "$settle_journal_lines" --no-pager -o cat 2>/dev/null || true)
		case "$journal" in *'failed_precondition: locked'*) board_locked=yes ;; esac
	fi
	for u in "$@"; do
		if [ "${settled[$u]}" = 1 ]; then
			verdict[$u]=ok
			printf 'unit %s active\n' "$u"
			continue
		fi
		journal=$(journalctl -u "$u" -n "$settle_journal_lines" --no-pager -o cat 2>/dev/null || true)
		if [ "$board_locked" = yes ] && [ "$u" = "$key_unit" ]; then
			verdict[$u]=locked
			printf 'unit %s locked: the card driver waits for its PIN, so key@ cannot make its keys (%s); run boards-unlock\n' "$u" "${last[$u]}"
		elif [ "$board_locked" = yes ] && [[ "$journal" == */run/sluis/key/* ]]; then
			verdict[$u]=locked
			printf 'unit %s waits for key@, which is locked (%s)\n' "$u" "${last[$u]}"
		else
			verdict[$u]=failed
			printf 'unit %s FAILED: not settled after %s s: %s\n' "$u" "$settle_timeout" "${last[$u]}"
			printf '%s\n' "$journal" | sed "s|^|  journal $u: |"
		fi
	done
	for u in "$@"; do
		case "${verdict[$u]}" in failed) failed=1 ;; locked) locked=1 ;; esac
	done
	[ "$failed" = 0 ] || return 1
	[ "$locked" = 0 ] || return "$settle_locked_status"
	return 0
}
