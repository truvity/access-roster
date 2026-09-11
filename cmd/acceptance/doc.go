// Command acceptance exercises access-issuer against a real Kubernetes
// API server.
//
// Everything else in this repository runs against fakes, and the fakes
// are honest about most things and silent about three: a real API server
// validates object names, refuses a create that raced another, and is the
// only thing that can answer a TokenReview. Those three are what the hub
// leans on for its store, its recovery path and its API listener's guard,
// so they are what this exercises.
//
// It is a command rather than a test suite because it needs a cluster,
// and a cluster is not something `go test ./...` should assume. Point it
// at any cluster you may create objects in — kind, a scratch namespace,
// an ephemeral test tier — and it cleans up after itself:
//
//	go run ./cmd/acceptance -namespace acceptance-$USER
//
// The `go test` side of the same thing is `internal/app`, which boots a
// whole hub from the environment and walks the use cases over the real
// handlers with nothing but memory behind it.
package main
