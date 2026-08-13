#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

docker run --rm -v "$root:/workspace" -w /workspace/sdk/go golang:1.25 \
  sh -c 'go test ./...'
docker run --rm -v "$root:/workspace" -w /workspace/cli golang:1.25 \
  sh -c 'go test ./... && go vet ./... && go build -o /tmp/wipeme ./cmd/wipeme && /tmp/wipeme --help >/tmp/wipeme-help 2>&1 && grep -q "wipeme read" /tmp/wipeme-help && grep -q "wipeme exec" /tmp/wipeme-help'
