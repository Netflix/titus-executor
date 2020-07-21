package standalone

// This is an awful hack.
// Somehow the go coverage tool doesn't explore imports from _test files when exploring
// the tree to decorate files with

import (
	// nolint: golint
	_ "flag"
	_ "fmt"
	_ "math/rand"
	_ "os"
	_ "reflect"
	_ "runtime"
	_ "strconv"
	_ "strings"
	_ "testing"
	_ "time"

	// nolint: golint
	_ "github.com/Netflix/titus-executor/api/netflix/titus"
	_ "github.com/Netflix/titus-executor/executor/mock"
	_ "github.com/Netflix/titus-executor/executor/runtime/docker"
	_ "github.com/pborman/uuid"
	_ "github.com/sirupsen/logrus"
)
