module github.com/truvity/sluis/v2

go 1.27.0

toolchain go1.27.3

require (
	connectrpc.com/connect v1.21.1
	filippo.io/torchwood v0.10.0
	github.com/go-jose/go-jose/v4 v4.1.7
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/go-webauthn/webauthn v0.18.2
	github.com/gowebpki/jcs v1.0.2
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/transparency-dev/formats v0.1.1
	go.yaml.in/yaml/v3 v3.0.6
	golang.org/x/mod v0.42.0
	google.golang.org/protobuf v1.36.12
)

require (
	filippo.io/mldsa v0.0.0-20260215214346-43d0283efc3e // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

tool connectrpc.com/connect/cmd/protoc-gen-connect-go
