package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/logger"
	titusTLS "github.com/Netflix/titus-executor/utils/tls"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/config"
	"github.com/golang/protobuf/jsonpb" // nolint: staticcheck
	"github.com/pkg/errors"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

type Config struct {
	DBURL                 string
	Key                   vpcapi.PrivateKey
	MaxConcurrentRequests int
	MaxIdleConnections    int
	MaxOpenConnections    int
	ReconcileInterval     time.Duration
	// How often to collect DB table metrics
	TableMetricsInterval time.Duration

	TLSConfig *tls.Config

	EnabledLongLivedTasks []string
	EnabledTaskLoops      []string

	TrunkNetworkInterfaceDescription  string
	BranchNetworkInterfaceDescription string
	SubnetCIDRReservationDescription  string

	WorkerRole string

	ZipkinURL string

	// This is only used for testing.
	disableRouteCache bool

	// The URL from where to fetch dynamic configs
	DynamicConfigURL string
}

func NewConfig(ctx context.Context, v *viper.Viper) (*Config, error) {
	var signingKey vpcapi.PrivateKey
	signingKeyFile, err := os.Open(v.GetString("signingkey"))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open signing key file")
	}

	err = jsonpb.Unmarshal(signingKeyFile, &signingKey)
	if err != nil {
		signingKeyFile.Close()
		return nil, errors.Wrap(err, "Could not deserialize key")
	}
	signingKeyFile.Close()

	tlsConfig, err := getTLSConfig(ctx, v)
	if err != nil {
		return nil, errors.Wrap(err, "Could not generate TLS Config")
	}

	return &Config{
		DBURL:                 v.GetString(config.DBURLFlagName),
		Key:                   signingKey, // nolint:govet
		MaxConcurrentRequests: v.GetInt(config.MaxConcurrentRequestsFlagName),
		MaxIdleConnections:    v.GetInt(config.MaxIdleConnectionsFlagName),
		MaxOpenConnections:    v.GetInt(config.MaxOpenConnectionsFlagName),
		ReconcileInterval:     v.GetDuration(config.ReconcileIntervalFlagName),
		TableMetricsInterval:  v.GetDuration(config.TableMetricsIntervalFlagName),
		TLSConfig:             tlsConfig,

		EnabledLongLivedTasks: v.GetStringSlice(config.EnabledLongLivedTasksFlagName),
		EnabledTaskLoops:      v.GetStringSlice(config.EnabledTaskLoopsFlagName),

		TrunkNetworkInterfaceDescription:  v.GetString(config.TrunkENIDescriptionFlagName),
		BranchNetworkInterfaceDescription: v.GetString(config.BranchENIDescriptionFlagName),
		SubnetCIDRReservationDescription:  v.GetString(config.SubnetCIDRReservationFlagName),

		WorkerRole: v.GetString(config.WorkerRoleFlagName),

		ZipkinURL: v.GetString(config.ZipkinURLFlagName),

		DynamicConfigURL: v.GetString(config.DynamicConfigURLFlagName),
	}, nil
}

// Dynamic configs have a default value, which can be overriden at runtime.
// These configs are periodically updated from the given dynamic config URL.
// Configs put here should be those that change often such as certain timeouts.
// Or killswitches for new features. And once those features become stable, the
// killswitch should be removed or moved to cmdline flags or environment variables.
type DynamicConfig struct {
	sync.Mutex
	configs map[string]string
}

func NewDynamicConfig() *DynamicConfig {
	return &DynamicConfig{configs: make(map[string]string)}
}

func (dynamicConfig *DynamicConfig) fetchConfigs(ctx context.Context, url string) {
	resp, err := http.Get(url) // nolint: gosec
	if err != nil {
		logger.G(ctx).Warningf("Failed to fetch dynamic configs from %s: %s", url, err)
		return
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.G(ctx).Warningf("Failed to read response of dynamic configs from url: %s", url, err)
		return
	}

	var configs map[string]string
	err = json.Unmarshal(bodyBytes, &configs)
	if err != nil {
		logger.G(ctx).Warningf("Failed to parse response of dynamic configs %s: %s", string(bodyBytes), err)
		return
	}
	dynamicConfig.Lock()
	if !reflect.DeepEqual(dynamicConfig.configs, configs) {
		dynamicConfig.configs = configs
		logger.G(ctx).Infof("Dynamic configs updated to %s", string(bodyBytes))
	}
	dynamicConfig.Unlock()
}

func (dynamicConfig *DynamicConfig) GetInt(ctx context.Context, name string, defaultValue int) int {
	dynamicConfig.Lock()
	defer dynamicConfig.Unlock()
	if value, ok := dynamicConfig.configs[name]; ok {
		intValue, err := cast.ToIntE(value)
		if err != nil {
			logger.G(ctx).Errorf("Config %s has an invalid value %s", name, value)
		} else {
			return intValue
		}
	}
	return defaultValue
}

func (dynamicConfig *DynamicConfig) GetBool(ctx context.Context, name string, defaultValue bool) bool {
	dynamicConfig.Lock()
	defer dynamicConfig.Unlock()
	if value, ok := dynamicConfig.configs[name]; ok {
		boolValue, err := cast.ToBoolE(value)
		if err != nil {
			logger.G(ctx).Errorf("Config %s has an invalid value %s", name, value)
		} else {
			return boolValue
		}
	}
	return defaultValue
}

// Start fetching and updating the configs periodically
func (dynamicConfig *DynamicConfig) Start(ctx context.Context, interval time.Duration, url string) {
	url = strings.TrimSuffix(url, "/")
	// Initial fetch
	dynamicConfig.fetchConfigs(ctx, url)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				dynamicConfig.fetchConfigs(ctx, url)
			}
		}
	}()
}

func getTLSConfig(ctx context.Context, v *viper.Viper) (*tls.Config, error) {
	certificateFile := v.GetString(config.SslCertFlagName)
	privateKey := v.GetString(config.SslPrivateKeyFlagName)
	trustedCerts := [1]string{v.GetString(config.SslCAFlagName)}

	if certificateFile == "" && privateKey == "" {
		return nil, nil
	}

	certPool := x509.NewCertPool()
	for _, cert := range trustedCerts {
		logger.G(ctx).WithField("cert", cert).Debug("Loading certificate")
		data, err := ioutil.ReadFile(cert)
		if err != nil {
			return nil, err
		}
		ok := certPool.AppendCertsFromPEM(data)
		if !ok {
			return nil, fmt.Errorf("Cannot load TLS Certificate from %s", cert)
		}
	}

	certLoader := &titusTLS.CachedCertificateLoader{
		CertPath: certificateFile,
		KeyPath:  privateKey,
	}

	tlsConfig := &tls.Config{
		ClientCAs:  certPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certLoader.GetCertificate(tlsConfig.Time)
	}
	return tlsConfig, nil
}
