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

	corev1 "k8s.io/api/core/v1"

	"contrib.go.opencensus.io/exporter/zipkin"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/metadataserver"
	"github.com/Netflix/titus-executor/metadataserver/identity"
	"github.com/Netflix/titus-executor/metadataserver/types"
	log2 "github.com/Netflix/titus-executor/utils/log"
	openzipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"go.opencensus.io/trace"
	"golang.org/x/sys/unix"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

const (
	// 169 is the first octet of 169.254...
	defaultListeningPort = 8169
	certRefreshTime      = 5 * time.Minute
)

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

func readTaskContainerInfoFile(taskID string) (*titus.ContainerInfo, error) {
	if taskID == "" {
		log.Errorf("task ID is empty: can't read task cinfo file")
		return nil, fmt.Errorf("task ID env var unset: %s", runtimeTypes.TitusTaskInstanceIDEnvVar)
	}
	confFile := filepath.Join(runtimeTypes.TitusEnvironmentsDir, fmt.Sprintf("%s.json", taskID))
	contents, err := ioutil.ReadFile(confFile) // nolint: gosec
	if err != nil {
		log.WithError(err).Errorf("Error reading task cinfo file %s", confFile)
		return nil, err
	}

	var cInfo titus.ContainerInfo
	if err = json.Unmarshal(contents, &cInfo); err != nil {
		log.WithError(err).Errorf("Error parsing JSON in task config file %s", confFile)
		return nil, err
	}

	return &cInfo, nil
}

func readTaskPodFile(taskID string) (*corev1.Pod, error) {
	if taskID == "" {
		log.Errorf("task ID is empty: can't read pod config file")
		return nil, fmt.Errorf("task ID env var unset: %s", runtimeTypes.TitusTaskInstanceIDEnvVar)
	}

	// This filename is from VK, which is /run/titus-executor/$namespace__$podname/pod.json
	// We only use the default namespace, so we hardcode it here.
	confFile := filepath.Join("/run/titus-executor/default__"+taskID, "pod.json")
	contents, err := ioutil.ReadFile(confFile) // nolint: gosec
	if err != nil {
		log.WithError(err).Errorf("Error reading pod config file %s", confFile)
		return nil, err
	}

	var pod corev1.Pod
	if err = json.Unmarshal(contents, &pod); err != nil {
		log.WithError(err).Errorf("Error parsing JSON in pod config file %s", confFile)
		return nil, err
	}

	return &pod, nil
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
		listenerFd                 int64
		listenPort                 int
		debug                      bool
		requireToken               bool
		tokenSalt                  string
		backingMetadataServer      string
		metatronEnabled            bool
		region                     string
		accountID                  string
		iamARN                     string
		logIAMARN                  string
		titusTaskInstanceID        string
		ipv4Address                string
		publicIpv4Address          string
		ipv6Addresses              string
		xFordwardedForBlockingMode bool
		sslCertKey                 string
		sslCert                    string
		sslCA                      string
		iamService                 string
		zipkinURL                  string
		availabilityZone           string
		availabilityZoneID         string
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
			EnvVar:      "LISTEN_PORT",
			Destination: &listenPort,
		},
		cli.StringFlag{
			Name:        "region",
			Usage:       "The STS service region to use (and the region to optionally return for the region endpoint)",
			Destination: &region,
			Value:       "",
			EnvVar:      "EC2_REGION",
		},
		cli.StringFlag{
			Name:        "account-id",
			Usage:       "The 'network' account ID the container is running in",
			Destination: &accountID,
			EnvVar:      "NETFLIX_ACCOUNT_ID",
		},
		cli.StringFlag{
			Name:        "iam-role",
			EnvVar:      "TITUS_IAM_ROLE",
			Destination: &iamARN,
		},
		cli.StringFlag{
			Name:        "logging-iam-role",
			EnvVar:      "TITUS_LOG_IAM_ROLE",
			Destination: &logIAMARN,
		},
		cli.StringFlag{
			Name:        "titus-task-instance-id",
			EnvVar:      runtimeTypes.TitusTaskInstanceIDEnvVar,
			Destination: &titusTaskInstanceID,
		},
		cli.StringFlag{
			Name:        "ipv4-address",
			EnvVar:      types.EC2IPv4EnvVarName,
			Destination: &ipv4Address,
		},
		cli.StringFlag{
			Name:        "public-ipv4-address",
			EnvVar:      types.EC2PublicIPv4EnvVarName,
			Destination: &publicIpv4Address,
		},
		cli.BoolFlag{
			Name:        "metatron",
			Usage:       "If set to true, the server will load certificates and use them to sign task identity documents",
			EnvVar:      types.TitusMetatronVariableName,
			Destination: &metatronEnabled,
		},
		cli.StringFlag{
			Name:        "ipv6-address",
			EnvVar:      "EC2_IPV6S",
			Destination: &ipv6Addresses,
		},
		cli.BoolFlag{
			Name:        "require-token",
			Usage:       "Set to true to require a token",
			EnvVar:      "TITUS_IMDS_REQUIRE_TOKEN",
			Destination: &requireToken,
		},
		cli.StringFlag{
			Name:        "token-key-salt",
			Value:       "",
			Usage:       "Salt used for token generation key",
			EnvVar:      "TOKEN_KEY_SALT",
			Destination: &tokenSalt,
		},
		cli.BoolFlag{
			Name:        "x-forwarded-for-blocking-mode",
			Usage:       "Set to true to block token requests if x-forwarded-for header is present",
			EnvVar:      "X_FORWARDED_FOR_BLOCKING_MODE",
			Destination: &xFordwardedForBlockingMode,
		},
		cli.StringFlag{
			Name:        "iam-service",
			Usage:       "The address of the IAM service to use",
			EnvVar:      "IAM_SERVICE",
			Destination: &iamService,
		},
		cli.StringFlag{
			Name:        "ssl-ca",
			Usage:       "SSL CA used to authenticate the IAM Service",
			EnvVar:      "IAM_SERVICE_SSL_CA",
			Destination: &sslCA,
		},
		cli.StringFlag{
			Name:        "ssl-key",
			Usage:       "The SSL Key used to authenticate to the IAM service",
			EnvVar:      "IAM_SERVICE_SSL_KEY",
			Destination: &sslCertKey,
		},
		cli.StringFlag{
			Name:        "ssl-cert",
			Usage:       "The SSL Certificate used to authenticate to the IAM service",
			EnvVar:      "IAM_SERVICE_SSL_CERT",
			Destination: &sslCert,
		},
		cli.StringFlag{
			Name:        "zipkin",
			Usage:       "The Zipkin URL to send traces to",
			EnvVar:      "ZIPKIN",
			Destination: &zipkinURL,
		},
		cli.StringFlag{
			Name:        "availability-zone",
			Usage:       "The Availability Zone that we are in",
			EnvVar:      "EC2_AVAILABILITY_ZONE",
			Destination: &availabilityZone,
		},
		cli.StringFlag{
			Name:        "availability-zone-id",
			Usage:       "The Availability Zone ID that we are in",
			EnvVar:      "EC2_AVAILABILITY_ZONE_ID",
			Destination: &availabilityZoneID,
		},
	}

	app.Action = func(c *cli.Context) error {
		if debug {
			log.SetLevel(log.DebugLevel)
		} else {
			log.SetLevel(log.InfoLevel)
		}

		log2.MaybeSetupLoggerIfOnJournaldAvailable()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		logruslogger := log.New()
		ctx = logger.WithLogger(ctx, logruslogger)

		trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})
		if zipkinURL != "" {
			hostname, err := os.Hostname()
			if err != nil {
				return err
			}
			// 1. Configure exporter to export traces to Zipkin.
			endpoint, err := openzipkin.NewEndpoint("titus-metadata-service", hostname)
			if err != nil {
				return fmt.Errorf("Failed to create the local zipkin endpoint from URL %q: %w", zipkinURL, err)
			}
			logger.G(ctx).WithField("endpoint", endpoint).WithField("url", zipkinURL).Info("Setting up tracing")
			reporter := zipkinHTTP.NewReporter(zipkinURL)
			defer reporter.Close()

			ze := zipkin.NewExporter(reporter, endpoint)
			trace.RegisterExporter(ze)
		}

		listener := getListener(listenPort, listenerFd)

		mdscfg := types.MetadataServerConfiguration{
			IAMARN:                     iamARN,
			LogIAMARN:                  logIAMARN,
			TitusTaskInstanceID:        titusTaskInstanceID,
			Ipv4Address:                net.ParseIP(ipv4Address),
			PublicIpv4Address:          net.ParseIP(publicIpv4Address),
			Region:                     region,
			AvailabilityZoneID:         availabilityZoneID,
			AvailabilityZone:           availabilityZone,
			RequireToken:               requireToken,
			TokenKey:                   titusTaskInstanceID + tokenSalt,
			XFordwardedForBlockingMode: xFordwardedForBlockingMode,
			NetflixAccountID:           accountID,

			SSLKey:     sslCertKey,
			SSLCert:    sslCert,
			SSLCA:      sslCA,
			IAMService: iamService,
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
			if cInfo, err := readTaskContainerInfoFile(titusTaskInstanceID); err != nil {
				log.WithError(err).Fatal("Cannot read container config file")
			} else {
				mdscfg.ContainerInfo = cInfo
			}
			if pod, err := readTaskPodFile(titusTaskInstanceID); err != nil {
				// TOOD: Make this fatal once we depend on this functionality
				log.WithError(err).Error("Cannot read pod config file, continuing anyway")
			} else {
				mdscfg.Pod = pod
			}
		}

		if len(tokenSalt) == 0 {
			log.Warn("Salt used for token key is empty. This is potentially insecure.")
		}

		if ipv6Addresses != "" {
			parsedIPv6Address := net.ParseIP(strings.Split(ipv6Addresses, "\n")[0])
			mdscfg.Ipv6Address = &parsedIPv6Address
		}
		ms, err := metadataserver.NewMetaDataServer(ctx, mdscfg)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Cannot create metadata server: %s", err.Error()), 2)
		}
		go notifySystemd()

		if metatronEnabled {
			go reloadSigner(ms)
		}

		log.Debug("Beginning serving")
		// TODO: Wire up logic to shut down mds on signal
		if err := http.Serve(listener, ms); err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
		log.Info("Done serving?")
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		time.Sleep(1 * time.Second)
		log.WithError(err).Fatal()
	}
	// Sleep for 1 second (both here and above) to give logs a chance to flush
	time.Sleep(1 * time.Second)
}
