package standalone

// This is an awful hack.
// Somehow the go coverage tool doesn't explore imports from _test files when exploring
// the tree to decorate files with if there is no non-test files in the package.

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
	_ "github.com/Netflix/titus-executor/executor/runtime/docker"
	_ "github.com/google/uuid"
	_ "github.com/sirupsen/logrus"
)
