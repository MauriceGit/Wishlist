#!/usr/bin/env bash
echo "go vet: "
go vet
echo "staticcheck: "
staticcheck
echo "govulncheck: "
govulncheck
echo "gosec: "
gosec ./
