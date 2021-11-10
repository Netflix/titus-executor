// +build tools
// See: https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module

package tools

import (
	_ "github.com/golang/protobuf/protoc-gen-go"
	_ "github.com/jteeuwen/go-bindata/go-bindata"
	_ "github.com/myitcv/gobin"
	_ "golang.org/x/tools/cmd/goimports"
)
