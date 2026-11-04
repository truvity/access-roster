module github.com/truvity/sluis/v2

go 1.27.0

toolchain go1.27.3

require (
	connectrpc.com/connect v1.21.1
	github.com/go-jose/go-jose/v4 v4.1.7
	github.com/go-piv/piv-go/v2 v2.6.0
	go.yaml.in/yaml/v3 v3.0.6
	golang.org/x/mod v0.42.0
	google.golang.org/protobuf v1.36.12
)

require golang.org/x/crypto v0.50.0 // indirect

tool connectrpc.com/connect/cmd/protoc-gen-connect-go
