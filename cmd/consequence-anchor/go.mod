// consequence-anchor is its own module so that Concordium's SDK, and the
// gRPC it brings, stay out of the server's dependencies: consequenced
// itself still needs only pgx and yaml.v3. It uses the server's public
// verify package through the replace below.
module github.com/matutozi/consequence-os/cmd/consequence-anchor

go 1.27

require (
	github.com/Concordium/concordium-go-sdk v0.4.0
	github.com/matutozi/consequence-os v0.0.0
	google.golang.org/grpc v1.66.0
)

require (
	github.com/btcsuite/btcutil v1.0.2 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240604185151-ef581f913117 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/matutozi/consequence-os => ../..
