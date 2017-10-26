package main

import (
	"context"
	"flag"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/metadataserver"
)

// 169 is the first octet of 169.254...
const defaultListeningPort = 8169

var listenerFd int64
var listenPort int
var debug bool
var backingMetadataServer string

func init() {
	flag.StringVar(&backingMetadataServer, "backing-metadata-server", "http://169.254.169.254/", "The URI of the AWS metadata server you want to use")
	flag.Int64Var(&listenerFd, "listener-fd", -1, "Use a specific fd for listening on")
	flag.IntVar(&listenPort, "listener-port", defaultListeningPort, "Use specific port to listen on")
	flag.BoolVar(&debug, "debug", false, "Set to true to debug logging")
}

/* Either returns a listener, or logs a fatal error */
func getListener() net.Listener {
	if listenerFd != -1 && listenPort != defaultListeningPort {
		log.Fatal("You cannot set both listening port, and listener FD")
	}

	if listenerFd != -1 {
		return makeFDListener(listenerFd)
	}

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(listenPort))
	if err != nil {
		log.Fatal("Unable to listen: ", err)
	}
	return ln
}

func makeFDListener(fd int64) net.Listener {
	r0, _, e1 := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), uintptr(0))
	if int(r0) == -1 {
		log.Fatal("Could not get listener FD because: ", e1)
	}
	unix.CloseOnExec(int(listenerFd))

	l, err := net.FileListener(os.NewFile(uintptr(fd), ""))
	if err != nil {
		log.Fatal("Could not create file listener: ", err)
	}
	return l
}

func getEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.WithField("key", key).Fatal("Expected environmental variable unset: ", key)
	}
	return val

}

func main() {
	flag.Parse()
	if debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	logsutil.MaybeSetupLoggerIfOnJournaldAvailable()

	/* Get the requisite configuration from environment variables */
	iamARN := getEnv("TITUS_IAM_ROLE")
	titusTaskInstanceID := getEnv("TITUS_TASK_INSTANCE_ID")
	ipv4Address := getEnv("EC2_LOCAL_IPV4")

	listener := getListener()
	ms := metadataserver.NewMetaDataServer(context.Background(), backingMetadataServer, iamARN, titusTaskInstanceID, ipv4Address)
	go notifySystemd()
	if err := http.Serve(listener, ms); err != nil {
		log.Fatal(err)
	}

}
