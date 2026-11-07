# protovalidate options, vendored

`buf/validate/validate.proto` is the file of [bufbuild/protovalidate](https://github.com/bufbuild/protovalidate) (Apache-2.0, the licence is in the file's header), exported unchanged from the Buf Schema Registry commit `511051f7f4374c3ca873b53ae68a9288` (`buf.build/bufbuild/protovalidate`).

It is in the repository so that no build reaches an outside service: the messages under `proto/` import it for their rules, and `buf`, `protoc` and `cargo` find it here. To move to a newer protovalidate, run `buf export buf.build/bufbuild/protovalidate:<commit> -o <dir>`, copy `buf/validate/validate.proto` over this one, change the commit above, and run `just proto-gen` and `just config-schema-gen`. Do not edit the file.
