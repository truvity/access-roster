// Package rpc is the Connect transport of every Go actor and driver of sluis: a server and a client over Unix
// sockets, the identity of the caller from the socket, the default-deny call-graph check, and the deadline and
// correlation id of every call (ADR 0003, "Transports" and "The call graph"; docs/reference/contracts.md,
// "Every call").
//
// The caller is known from the transport only. The server reads the peer credentials of each connection once
// (SO_PEERCRED), maps the uid to an actor or driver name through the registry, and refuses every call whose
// caller the call graph does not allow, before the message is decoded. No request field names a caller.
//
// A unit holds one actor; fusion is not built.
package rpc

import "net/http"

// unixProtocols is the protocol set of both ends: Connect over HTTP/2 without TLS (h2c), the form the Rust kit
// speaks too. The standard library does the h2c; the server also accepts HTTP/1.1.
func serverProtocols() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	return p
}

func clientProtocols() *http.Protocols {
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	return p
}
