#!/usr/bin/env bash

# **START**

# block: get
GO111MODULE=off go get -u github.com/myitcv/gobin

# actually under the hood we want to install the "current" local version
# else we won't be able to take advantage of changes until they are merged
pushd /self > /dev/null
GOBIN=$GOPATH/bin GOPATH=/gopath go install
popd > /dev/null

# block: fix path
export PATH=$(go env GOPATH)/bin:$PATH
which gobin

# ====================================
# global examples

# behind the scenes fix the version of gohack we install
gobin github.com/rogpeppe/gohack@v1.0.0

# block: gohack
gobin github.com/rogpeppe/gohack

# block: gohack latest
gobin github.com/rogpeppe/gohack@latest

# block: gohack v1.0.0
gobin github.com/rogpeppe/gohack@v1.0.0

# block: gohack print
gobin -p github.com/rogpeppe/gohack@v1.0.0

# block: gohack run
gobin -run github.com/rogpeppe/gohack@v1.0.0 -help
assert "$? -eq 2" $LINENO

# ====================================
# main-module examples

mkdir hello
cd hello
go mod init example.com/hello
cat <<EOD > tools.go
// +build tools

package tools

import (
        _ "golang.org/x/tools/cmd/stringer"
)
EOD
gofmt -w tools.go

# block: module
cat go.mod

# block: tools
cat tools.go

# behind the scenes fix the version of gohack we install
gobin -m -p golang.org/x/tools/cmd/stringer@v0.0.0-20181102223251-96e9e165b75e

# block: tools version
gobin -m -p golang.org/x/tools/cmd/stringer

# block: stringer help
gobin -m -run golang.org/x/tools/cmd/stringer -help
assert "$? -eq 2" $LINENO

cat <<EOD | gofmt > main.go
package main

import "fmt"

//go:generate gobin -m -run golang.org/x/tools/cmd/stringer -type=Pill

type Pill int

const (
	Placebo Pill = iota
	Aspirin
	Ibuprofen
	Paracetamol
	Acetaminophen = Paracetamol
)

func main() {
	fmt.Printf("For headaches, take %v\n", Ibuprofen)
}
EOD

# block: use in go generate
cat main.go

# block: go generate and run
go generate
go run .
