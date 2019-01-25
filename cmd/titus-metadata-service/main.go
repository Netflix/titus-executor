package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/metadataserver"
	"github.com/Netflix/titus-executor/metadataserver/identity"
	"github.com/Netflix/titus-executor/metadataserver/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"gopkg.in/urfave/cli.v1"
)

// 169 is the first octet of 169.254...
const defaultListeningPort = 8169

/* Either returns a listener, or logs a fatal error */
func getListener(listenPort int, listenerFd int64) net.Listener {
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
	unix.CloseOnExec(int(fd))

	l, err := net.FileListener(os.NewFile(uintptr(fd), ""))
	if err != nil {
		log.Fatal("Could not create file listener: ", err)
	}
	return l
}

func readTaskConfigFile(taskID string) (*titus.ContainerInfo, error) {
	confFile := filepath.Join(runtimeTypes.TitusEnvironmentsDir, fmt.Sprintf("%s.json", taskID))
	contents, err := ioutil.ReadFile(confFile) // nolint: gosec
	if err != nil {
		log.WithError(err).Errorf("Error reading file %s", confFile)
		return nil, err
	}

	var cInfo titus.ContainerInfo
	if err = json.Unmarshal(contents, &cInfo); err != nil {
		log.WithError(err).Errorf("Error parsing JSON in file %s", confFile)
		return nil, err
	}

	return &cInfo, nil
}

func main() {
	app := cli.NewApp()
	app.Name = "titus-metadata-service"
	var listenerFd int64
	var listenPort int
	var debug bool
	var backingMetadataServer string
	var metatronEnabled bool
	var optimistic bool
	var region string
	var iamARN string
	var titusTaskInstanceID string
	var ipv4Address string
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "backing-metadata-server",
			Value:       "http://169.254.169.254/",
			Usage:       "The URI of the AWS metadata server you want to use",
			Destination: &backingMetadataServer,
		},
		cli.Int64Flag{
			Name:        "listener-fd",
			Value:       -1,
			Usage:       "Use a specific fd for listening on",
			Destination: &listenerFd,
		},
		cli.BoolFlag{
			Name:        "debug",
			Usage:       "Set to true to enable debug logging",
			Destination: &debug,
		},
		cli.IntFlag{
			Name:        "listener-port",
			Value:       defaultListeningPort,
			Usage:       "Use specific port to listen on",
			Destination: &listenPort,
		},
		cli.BoolFlag{
			Name:        "optimistic",
			Usage:       "If you set this to to true, the IAM service will optimistically fetch IAM credentials",
			Destination: &optimistic,
			EnvVar:      types.TitusOptimisticIAMVariableName,
		},
		cli.StringFlag{
			Name:        "region",
			Usage:       "The STS service region to use",
			Destination: &region,
			Value:       "",
			EnvVar:      "EC2_REGION",
		},
		cli.StringFlag{
			Name:        "iam-role",
			EnvVar:      "TITUS_IAM_ROLE",
			Destination: &iamARN,
		},
		cli.StringFlag{
			Name:        "titus-task-instance-id",
			EnvVar:      "TITUS_TASK_INSTANCE_ID",
			Destination: &titusTaskInstanceID,
		},
		cli.StringFlag{
			Name:        "ipv4-address",
			EnvVar:      "EC2_LOCAL_IPV4",
			Destination: &ipv4Address,
		},
		cli.BoolFlag{
			Name:        "metatron",
			Usage:       "If set to true, the server will load certificates and use them to sign task identity documents",
			EnvVar:      types.TitusMetatronVariableName,
			Destination: &metatronEnabled,
		},
	}
	app.Action = func(c *cli.Context) error {
		if debug {
			log.SetLevel(log.DebugLevel)
		} else {
			log.SetLevel(log.InfoLevel)
		}
		logsutil.MaybeSetupLoggerIfOnJournaldAvailable()

		/* Get the requisite configuration from environment variables */
		listener := getListener(listenPort, listenerFd)

		var err error
		var container *titus.ContainerInfo
		var signer *identity.Signer

		if container, err = readTaskConfigFile(titusTaskInstanceID); err != nil {
			log.Fatal(err)
		}
		if metatronEnabled {
			log.Info("Metatron enabled!")
			if signer, err = identity.NewDefaultSigner(); err != nil {
				log.Fatal(err)
			}
		}
		ms := metadataserver.NewMetaDataServer(context.Background(), backingMetadataServer, iamARN, ipv4Address, region, optimistic, container, signer)
		go notifySystemd()
		if err := http.Serve(listener, ms); err != nil {
			return err
		}
		log.Info("Done serving?")
		time.Sleep(1 * time.Second)
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		log.WithError(err).Fatal()
	}
}
