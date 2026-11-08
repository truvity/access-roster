package main

import "testing"

// The tar of the log may list a temporary file of the `fs` blob driver and find it gone (the driver links it to its name and
// removes it at once). Only that complaint is forgiven; any other is a failed copy.
func TestOnlyTheVanishedTemporaryFilesOfTheDriverAreForgiven(t *testing.T) {
	for in, want := range map[string]bool{
		"tar: ./.tmp-1-39: No such file or directory\ntar: error exit delayed from previous errors\n":                                                    true,
		"tar: ./tile/000/.tmp-12-3: No such file or directory\ntar: ./.tmp-1-4: No such file or directory\ntar: error exit delayed from previous errors": true,
		"tar: ./tile/000/x001: No such file or directory\ntar: error exit delayed from previous errors":                                                  false,
		"tar: ./.tmp-1-39: Permission denied\ntar: error exit delayed from previous errors":                                                              false,
		"tar: ./.tmp-1-x: No such file or directory":                                                                                                     false,
		"tar: ./.tmp-1-39: No such file or directory\ntar: ./checkpoint: Permission denied":                                                              false,
		"tar: error exit delayed from previous errors":                                                                                                   false,
		"": false,
	} {
		if got := vanishedTemporaries(in); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
	for name, want := range map[string]bool{".tmp-1-39": true, "tile/000/.tmp-1-2": true, "checkpoint": false, "tile/.tmpfile": false} {
		if isTemporary(name) != want {
			t.Errorf("isTemporary(%q) = %v", name, !want)
		}
	}
}
