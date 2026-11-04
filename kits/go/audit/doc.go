// Package audit is the audit emitter library (0028 "Four pieces"): it lives inside each emitting process, holds no
// credential, and from one call builds one message, an OCSF 1.9.0 audit record as RFC 8785 canonical JSON
// (0030 "The record format"), then hands it to the audit transport on the emit socket.
//
// A person is never named in a record. The emitter asks key@ for Mac under the tenant's pseudonym key before the
// record leaves the process (0029 "Pseudonyms"), so a Subject becomes "p1.<YYYYMM>.<first 128 bits of the MAC>".
//
// Emit hands the message over and returns; EmitBlocking returns only when the transport says the message is
// durable (0029 "Sealing"). Delivery is at least once, and the writer removes a repeat by metadata.uid. The library
// keeps no queue and does not retry: the spool driver behind the socket is the durable buffer, and a failure is
// returned to the caller, who logs it.
//
// The Rust crate sluis-audit produces the same bytes from the same input (kits/conformance/audit).
package audit
