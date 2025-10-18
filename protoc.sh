#!/bin/sh
cargo install --git https://github.com/billf/protoc-gen-prost.git --branch bump-tonic protoc-gen-prost
cargo install --git https://github.com/billf/protoc-gen-prost.git --branch bump-tonic protoc-gen-tonic --force
protoc -I tests/proto tests/proto/helloworld.proto \
    --prost_out=tests/proto/gen 
protoc -I tests/proto tests/proto/helloworld.proto \
    --tonic_out=tests/proto/gen \
    --tonic_opt=no_include
