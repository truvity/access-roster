module github.com/truvity/sluis/v2

go 1.27.0

toolchain go1.27.3

require (
	connectrpc.com/connect v1.21.1
	go.yaml.in/yaml/v3 v3.0.6
	google.golang.org/protobuf v1.36.12
)

tool connectrpc.com/connect/cmd/protoc-gen-connect-go
