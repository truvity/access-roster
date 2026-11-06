#!/usr/bin/env bash
# The ssh of the boards scripts (boards.sh, rqlite.sh), kept in one place. Sourced, never run. It reads, from the caller:
#   SLUIS_BOARD_SSH_USER      the SSH user, with passwordless sudo
#   agent                     the agent socket for ssh; it is set for the ssh commands only, never exported
#   SLUIS_BOARD_SSH_OPTIONS   extra ssh arguments, split at white space, for example
#                             "-o UserKnownHostsFile=/path/to/known_hosts -o StrictHostKeyChecking=yes". A board that was
#                             reinstalled has a new host key; this is how a run trusts it without touching ~/.ssh/known_hosts.
#                             The smoke program (deploy/boards/smoke) reads the same variable. A value with a space in it
#                             (a path) is not supported.
# The options come after the defaults below. ssh keeps the first value it sees for an option, so they add to the defaults and
# do not replace BatchMode or ConnectTimeout.

ssh_options=()
if [ -n "${SLUIS_BOARD_SSH_OPTIONS:-}" ]; then
	read -ra ssh_options <<<"$SLUIS_BOARD_SSH_OPTIONS"
fi

board_ssh() { # board command...
	local b=$1
	shift
	SSH_AUTH_SOCK=${agent:-} ssh -o BatchMode=yes -o ConnectTimeout=10 ${ssh_options[@]+"${ssh_options[@]}"} "$SLUIS_BOARD_SSH_USER@$b" "$@"
}
