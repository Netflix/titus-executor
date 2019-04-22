// +build tools

package tools

import (
	_ "github.com/rogpeppe/go-internal/cmd/txtar-addmod"
	//
	// Temporarily remove this dependency to break the circular module
	// requirement (https://github.com/golang/go/issues/29773)
	//
	// _ "myitcv.io/cmd/egrunner"
	// _ "myitcv.io/cmd/githubcli"
	// _ "myitcv.io/cmd/mdreplace"
)
