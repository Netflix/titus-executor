package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Netflix/titus-executor/logsutil"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/metadataserver"
	"github.com/Netflix/titus-executor/metadataserver/identity"
	"github.com/Netflix/titus-executor/metadataserver/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"gopkg.in/urfave/cli.v1"
)

// 169 is the first octet of 169.254...
const defaultListeningPort = 8169

const certRefreshTime = 5 * time.Minute

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

func reloadSigner(ms *metadataserver.MetadataServer) {
	t := time.NewTicker(certRefreshTime)
	defer t.Stop()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)

	for {
		select {
		case <-t.C:
		case <-sigs:
		}

		newSigner, err := identity.NewDefaultSigner()
		if err != nil {
			log.WithError(err).Fatal("Cannot instantiate new default signer")
		}

		if err := ms.SetSigner(newSigner); err != nil {
			log.WithError(err).Error("Error reloading signing certificate")
		}
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "titus-metadata-service"
	var (
		listenerFd            int64
		listenPort            int
		debug                 bool
		requireToken          bool
		tokenSalt             string
		apiProtectEnabled     bool
		backingMetadataServer string
		metatronEnabled       bool
		optimistic            bool
		region                string
		iamARN                string
		titusTaskInstanceID   string
		ipv4Address           string
		ipv6Addresses         string
		stateDir              string

		vpcID string
		eniID string
	)

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
		cli.BoolFlag{
			Name:        "api-protect",
			Usage:       "Enable API protect",
			Destination: &apiProtectEnabled,
			EnvVar:      types.TitusAPIProtectEnabledVariableName,
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
		cli.StringFlag{
			Name:        "vpc-id",
			EnvVar:      "EC2_VPC_ID",
			Destination: &vpcID,
		},
		cli.StringFlag{
			Name:        "eni-id",
			EnvVar:      "EC2_INTERFACE_ID",
			Destination: &eniID,
		},
		cli.StringFlag{
			Name:        "ipv6-address",
			EnvVar:      "EC2_IPV6S",
			Destination: &ipv6Addresses,
		},
		cli.StringFlag{
			Name:        "state-dir",
			Value:       "/run/titus-metadata-service",
			Usage:       "Where to store the state, and locker state -- creates directory",
			EnvVar:      "IAM_STATE_DIR",
			Destination: &stateDir,
		},
		cli.BoolFlag{
			Name:        "require-token",
			Usage:       "Set to true to require a token",
			EnvVar:      "REQUIRE_TOKEN",
			Destination: &requireToken,
		},
		cli.StringFlag{
			Name:        "token-key-salt",
			Value:       "",
			Usage:       "Salt to used for key used to generate tokens",
			EnvVar:      "TOKEN_KEY_SALT",
			Destination: &tokenSalt,
		},
	}
	app.Action = func(c *cli.Context) error {
		if debug {
			log.SetLevel(log.DebugLevel)
		} else {
			log.SetLevel(log.InfoLevel)
		}
		// This needs to be if journald available, because titus executors are started by mesos agent, and in order
		// for logs to get from the tasks starts by titus tasks to
		logsutil.MaybeSetupLoggerIfOnJournaldAvailable()
		/* Get the requisite configuration from environment variables */
		listener := getListener(listenPort, listenerFd)

		mdscfg := types.MetadataServerConfiguration{
			IAMARN:              iamARN,
			TitusTaskInstanceID: titusTaskInstanceID,
			Ipv4Address:         net.ParseIP(ipv4Address),
			VpcID:               vpcID,
			EniID:               eniID,
			Region:              region,
			Optimistic:          optimistic,
			APIProtectEnabled:   apiProtectEnabled,
			StateDir:            stateDir,
			RequireToken:        requireToken,
			TokenKey:            titusTaskInstanceID + tokenSalt,
		}
		if parsedURL, err := url.Parse(backingMetadataServer); err == nil {
			mdscfg.BackingMetadataServer = parsedURL
		} else {
			return cli.NewExitError(err.Error(), 1)
		}

		if metatronEnabled {
			log.Info("Metatron enabled!")
			if signer, err := identity.NewDefaultSigner(); err != nil {
				log.WithError(err).Fatal("Cannot instantiate new default signer")
			} else {
				mdscfg.Signer = signer
			}
			if container, err := readTaskConfigFile(titusTaskInstanceID); err != nil {
				log.WithError(err).Fatal("Cannot read container config file")
			} else {
				mdscfg.Container = container
			}
		}

		if ipv6Addresses != "" {
			parsedIPv6Address := net.ParseIP(strings.Split(ipv6Addresses, "\n")[0])
			mdscfg.Ipv6Address = &parsedIPv6Address
		}
		ms, err := metadataserver.NewMetaDataServer(context.Background(), mdscfg)
		if err != nil {
			return cli.NewExitError(err.Error(), 1)
		}

		go notifySystemd()
		go reloadSigner(ms)
		// TODO: Wire up logic to shut down mds on signal
		if err := http.Serve(listener, ms); err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
		log.Info("Done serving?")
		time.Sleep(1 * time.Second)
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		log.WithError(err).Fatal()
	}
}
