#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GOPATH_BIN="$(go env GOPATH)/bin"
export PATH="$GOPATH_BIN:$PATH"

if ! command -v protoc >/dev/null 2>&1; then
  echo "Error: protoc not found. Please install protobuf (e.g. brew install protobuf)."
  exit 1
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
  echo "Installing protoc-gen-go..."
  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi

if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  echo "Installing protoc-gen-go-grpc..."
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

mkdir -p "$ROOT_DIR/gen"

protoc \
  --proto_path="$ROOT_DIR/proto" \
  --go_out="$ROOT_DIR/gen" --go_opt=paths=source_relative \
  --go-grpc_out="$ROOT_DIR/gen" --go-grpc_opt=paths=source_relative \
  proto/cert/v1/cert.proto

echo "Generated protobuf code in gen/cert/v1/"
