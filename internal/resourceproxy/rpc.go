package resourceproxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
)

// rpcCall is what an audit line keeps of one JSON-RPC message: its
// method and, for tools/call, the tool. Nothing else of a body survives
// this function -- arguments are what a caller asked about, and the audit
// trail records who did what, not what they said.
type rpcCall struct {
	Method string `json:"method"`
	Tool   string `json:"tool,omitempty"`
}

const maxNameLen = 128

// maxPathLen caps the request path in an audit line: it is logged for a
// refused, unauthenticated request too, so its length is the caller's.
const maxPathLen = 512

// parseRPC reads the method and tool name out of a JSON-RPC body, a
// single message or a batch. ok is false for anything that is not JSON-RPC
// shaped, which is then audited with no method rather than refused: this
// is a record of the traffic, not a second authorization gate.
func parseRPC(body []byte) (calls []rpcCall, batched, ok bool) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, false, false
	}
	if body[0] == '[' {
		var raws []json.RawMessage
		if json.Unmarshal(body, &raws) != nil {
			return nil, false, false
		}
		for _, raw := range raws {
			if call, good := parseOne(raw); good {
				calls = append(calls, call)
			}
		}
		return calls, true, len(calls) > 0
	}
	call, good := parseOne(body)
	if !good {
		return nil, false, false
	}
	return []rpcCall{call}, false, true
}

func parseOne(raw []byte) (rpcCall, bool) {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name json.RawMessage `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &msg) != nil || msg.Method == "" {
		return rpcCall{}, false
	}
	call := rpcCall{Method: clean(msg.Method)}
	if msg.Method == "tools/call" {
		var name string
		if json.Unmarshal(msg.Params.Name, &name) == nil {
			call.Tool = clean(name)
		}
	}
	return call, true
}

// clean bounds what a caller chose to name: a control character has no
// place in a log line and a megabyte-long tool name none in an audit
// trail.
func clean(s string) string { return bounded(s, maxNameLen) }

// bounded is clean with a caller-chosen cap. Line breaks go first and by
// name, then every other control character; a cut that lands inside a
// multi-byte character drops the broken tail rather than logging it.
func bounded(s string, limit int) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > limit {
		s = strings.ToValidUTF8(s[:limit], "")
	}
	return s
}
