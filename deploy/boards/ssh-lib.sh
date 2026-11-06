#!/usr/bin/env bash
# The ssh of the boards scripts (boards.sh, rqlite.sh), kept in one place. Sourced, never run. It reads, from the caller:
#   SLUIS_BOARD_SSH_USER      the SSH user, with passwordless sudo
#   agent                     the agent socket for ssh; it is set for the ssh commands only, never exported
#   SLUIS_BOARD_SSH_OPTIONS   extra ssh arguments, split at white space, for example
#                             "-o UserKnownHostsFile=/path/to/known_hosts -o StrictHostKeyChecking=yes". A board that was
#                             reinstalled has a new host key; this is how a run trusts it without touching ~/.ssh/known_hosts.
#                             The smoke program (deploy/boards/smoke) reads the same variable. A value with a space in it
#                             (a path) is not supported. All of the value is read, newlines included, as Go's strings.Fields does.
# The options come after the defaults below. ssh keeps the first value it sees for an option, so they add to the defaults and
# do not replace BatchMode, ConnectTimeout or the keep-alive: a connection that is dropped without a reset (a firewall that DROPs)
# ends in about 15 s instead of hanging until the TCP timeout.

ssh_options=()
if [ -n "${SLUIS_BOARD_SSH_OPTIONS:-}" ]; then
	# -d '' reads to the end of the value instead of the first line; read then returns non-zero at the end, which is expected.
	read -rd '' -a ssh_options <<<"$SLUIS_BOARD_SSH_OPTIONS" || true
fi

# board_ssh board command...: the standard input of the caller reaches the command on the board.
board_ssh() {
	local b=$1
	shift
	SSH_AUTH_SOCK=${agent:-} ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 ${ssh_options[@]+"${ssh_options[@]}"} "$SLUIS_BOARD_SSH_USER@$b" "$@"
}

# board_ssh_n is board_ssh for a command that reads nothing: ssh gets /dev/null, so it cannot swallow the standard input of a loop
# or of the script that calls it.
board_ssh_n() { # board command...
	board_ssh "$@" </dev/null
}

# board_ssh_secret is board_ssh for a command that is given a secret on standard input (boards-unlock). -T comes before the options
# of the run: ssh keeps the first value it sees, so neither RequestTTY in ~/.ssh/config nor "-o RequestTTY=force" can give the
# session a terminal, where the remote line discipline would echo what is piped in back to this terminal. A -t in the options is
# refused by the caller (ssh_secret_options_ok).
board_ssh_secret() { # board command...
	local b=$1
	shift
	SSH_AUTH_SOCK=${agent:-} ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 ${ssh_options[@]+"${ssh_options[@]}"} "$SLUIS_BOARD_SSH_USER@$b" "$@"
}

# ssh_secret_options_ok succeeds when SLUIS_BOARD_SSH_OPTIONS suits an ssh that carries a secret: it asks for no terminal (-t, -tt:
# the last of -T and -t wins, so a -t after our -T would win) and it does not turn host-key checking off (StrictHostKeyChecking=no
# or off would hand the secret to whoever answers on the address). accept-new is allowed with a warning: it checks a host that is
# known and trusts the first key of one that is not. The reason is printed on standard error.
ssh_secret_options_ok() {
	local tok joined=" "
	for tok in ${ssh_options[@]+"${ssh_options[@]}"}; do
		if [[ "$tok" =~ ^-[A-Za-z]*t[A-Za-z]*$ ]]; then
			echo "ssh: SLUIS_BOARD_SSH_OPTIONS asks for a terminal ($tok); a secret is never sent through one" >&2
			return 1
		fi
		joined="$joined${tok,,} "
	done
	# -o Key=value, -oKey=value and -o Key value (the last when the value is the next word) all end up as key=value or key value.
	joined=${joined//-ostricthostkeychecking/-o stricthostkeychecking}
	if [[ "$joined" =~ stricthostkeychecking(=|\ )(no|off|false)\  ]]; then
		echo "ssh: SLUIS_BOARD_SSH_OPTIONS turns off host-key checking (StrictHostKeyChecking=no); a secret is not sent over such a connection" >&2
		return 1
	fi
	if [[ "$joined" =~ stricthostkeychecking(=|\ )accept-new\  ]]; then
		echo "ssh: warning: StrictHostKeyChecking=accept-new trusts the key of a board it has not seen before; use a known-hosts file you checked for the PIN" >&2
	fi
}
