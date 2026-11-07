package main

import (
	"strings"
	"testing"
	"time"
)

func TestActiveAt(t *testing.T) {
	since := "2026-11-04T10:00:00Z"
	want := time.Date(2026, 11, 4, 10, 30, 0, 0, time.UTC)
	// Right after a switch the node's OLD key is still active in the ring and the NEW one is pre-published (the signer keeps
	// the old one until the new one is active). The hint is about the key that key@ holds now, so the old active key of the
	// node must not hide it.
	ring := []string{
		"kidOld ES384 active node=board-b since=2026-11-04T08:00:00Z",
		"kidA ES384 active node=board-a since=2026-11-04T08:00:00Z",
		"kidNew ES384 pre-published node=board-b since=" + since,
	}
	if at, ok := activeAt(ring, "kidNew"); !ok || !at.Equal(want) {
		t.Errorf("activeAt(kidNew) = %v, %t; want %v", at, ok, want)
	}
	// The key that key@ holds is active: no wait.
	if _, ok := activeAt(ring, "kidOld"); ok {
		t.Error("an active key was said to wait")
	}
	// A key that is not in the ring says nothing.
	if _, ok := activeAt(ring, "kidMissing"); ok {
		t.Error("a key that is not in the ring was said to wait")
	}
	// Lines without the fields (an older spine) say nothing.
	if _, ok := activeAt([]string{"kidNew ES384 pre-published"}, "kidNew"); ok {
		t.Error("a line without a since was taken")
	}
	// A retiring key is not waiting either.
	if _, ok := activeAt([]string{"kidR ES384 retiring node=n since=" + since}, "kidR"); ok {
		t.Error("a retiring key was said to wait")
	}
}

// The group of an actor's own directory of key@ is joined by its name, never by the number of the uid plan, which
// systemd-sysusers does not keep when it is taken.
func TestAsActorJoinsTheKeyDirectoryGroupByName(t *testing.T) {
	cmd, err := (&board{}).asActor("signer", []string{ownKeyDir})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "--groups sluis-keyc-004-dev ") {
		t.Errorf("the group is not joined by name: %s", cmd)
	}
	if strings.Contains(cmd, "61704") {
		t.Errorf("the group is joined by number: %s", cmd)
	}
	if _, err := (&board{}).asActor("harness-forwarder", []string{ownKeyDir}); err == nil {
		t.Error("an actor that is not a caller of key@ joined a key@ directory group")
	}
}

func TestSSHArgsCarryTheOptionsOfTheRunAfterTheDefaults(t *testing.T) {
	t.Setenv("SLUIS_BOARD_SSH_OPTIONS", "-o UserKnownHostsFile=/run/known_hosts  -o StrictHostKeyChecking=yes")
	got := strings.Join(sshArgs(sshOptions(), "operator@192.0.2.12", "hostname"), " ")
	want := "-o BatchMode=yes -o ConnectTimeout=10 -o UserKnownHostsFile=/run/known_hosts -o StrictHostKeyChecking=yes operator@192.0.2.12 hostname"
	if got != want {
		t.Errorf("ssh arguments = %q, want %q", got, want)
	}
	t.Setenv("SLUIS_BOARD_SSH_OPTIONS", "")
	if got := strings.Join(sshArgs(sshOptions(), "operator@192.0.2.12", "hostname"), " "); got != "-o BatchMode=yes -o ConnectTimeout=10 operator@192.0.2.12 hostname" {
		t.Errorf("with no options the arguments are %q", got)
	}
}

// DataKeyWrap ids are hashes and never name a node: the cross-check compares the item sets and versions instead.
func TestSameWrapsComparesHashShapedItems(t *testing.T) {
	earlier := []itemOut{
		{ID: "evidence/1/gey5lqkxj3mvzsaxk2wnn3a7oq", Version: 3},
		{ID: "pseudonym/202611/r7hq4dnwcmtlh5c6xd2vbzpa4u", Version: 1},
	}
	// The same set, one version bumped, one new item: the later board reads what the earlier wrote.
	now := []itemOut{
		{ID: "evidence/1/gey5lqkxj3mvzsaxk2wnn3a7oq", Version: 4},
		{ID: "evidence/1/mfxgg2djnrsw4y3pnzqxi5lt2e", Version: 1},
		{ID: "pseudonym/202611/r7hq4dnwcmtlh5c6xd2vbzpa4u", Version: 1},
	}
	if err := sameWraps(earlier, now); err != nil {
		t.Errorf("a shared store was refused: %v", err)
	}
	// An item the earlier board read is gone: another store.
	if err := sameWraps(earlier, now[1:]); err == nil || !strings.Contains(err.Error(), "evidence/1/gey5") {
		t.Errorf("a missing item was accepted or not named: %v", err)
	}
	// An item at an older version: another store.
	old := []itemOut{{ID: earlier[0].ID, Version: 2}, earlier[1]}
	if err := sameWraps(earlier, old); err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("an older version was accepted: %v", err)
	}
	// Nothing to compare is not a pass.
	if err := sameWraps(nil, now); err == nil {
		t.Error("an empty earlier set was accepted")
	}
}
