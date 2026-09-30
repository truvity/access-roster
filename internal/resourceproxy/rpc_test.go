package resourceproxy

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRPC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		want    []rpcCall
		batched bool
		ok      bool
	}{
		{"tool call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"query":"up"}}}`,
			[]rpcCall{{"tools/call", "query"}}, false, true},
		{"not a tool call keeps no name", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"name":"x"}}`,
			[]rpcCall{{"tools/list", ""}}, false, true},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"initialize"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"alerts"}},{"nonsense":1}]`,
			[]rpcCall{{"initialize", ""}, {"tools/call", "alerts"}}, true, true},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			[]rpcCall{{"notifications/initialized", ""}}, false, true},
		{"a response has no method", `{"jsonrpc":"2.0","id":1,"result":{}}`, nil, false, false},
		{"not json", `hello`, nil, false, false},
		{"empty", ``, nil, false, false},
		{"non-string tool name", `{"method":"tools/call","params":{"name":{"a":1}}}`, []rpcCall{{"tools/call", ""}}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, batched, ok := parseRPC([]byte(tc.body))
			if ok != tc.ok || batched != tc.batched || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseRPC = %v, %v, %v; want %v, %v, %v", got, batched, ok, tc.want, tc.batched, tc.ok)
			}
		})
	}
}

func TestNamesAreBoundedAndPrintable(t *testing.T) {
	t.Parallel()
	got, _, _ := parseRPC([]byte(`{"method":"tools/call","params":{"name":"a\nb` + strings.Repeat("x", 1000) + `"}}`))
	if len(got) != 1 || strings.ContainsAny(got[0].Tool, "\n") || len(got[0].Tool) > maxNameLen {
		t.Errorf("tool = %q", got[0].Tool)
	}
}
