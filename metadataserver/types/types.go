package types

import (
	"net"
	"net/http"
	"net/url"

	"github.com/Netflix/titus-executor/metadataserver/identity"
	corev1 "k8s.io/api/core/v1"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

const (
	// TitusMetatronVariableName is the name of the environment variable that indicates if metatron is enabled for a container
	TitusMetatronVariableName = "TITUS_METATRON_ENABLED"
	EC2IPv4EnvVarName         = "EC2_LOCAL_IPV4"
	EC2PublicIPv4EnvVarName   = "EC2_PUBLIC_IPV4"
	EC2PublicIPv4sEnvVarName  = "EC2_PUBLIC_IPV4S"
	EC2IPv6sEnvVarName        = "EC2_IPV6S"
	NetflixAccountIDVarName   = "NETFLIX_ACCOUNT_ID"
	NetflixIPv6EnvVarName     = "NETFLIX_IPV6"
	NetflixIPv6sEnvVarName    = "NETFLIX_IPV6S"
	NetflixIPv6HostnameEnvVar = "NETFLIX_IPV6_HOSTNAME"
)

// MetadataServerConfiguration is a configuration for metadata service + IAM Proxy
// optional fields are pointers
type MetadataServerConfiguration struct {
	BackingMetadataServer      *url.URL
	IAMARN                     string
	LogIAMARN                  string
	TitusTaskInstanceID        string
	Ipv4Address                net.IP
	PublicIpv4Address          net.IP
	Ipv6Address                *net.IP
	Pod                        *corev1.Pod
	ContainerInfo              *titus.ContainerInfo
	Signer                     *identity.Signer
	RequireToken               bool
	TokenKey                   string
	XFordwardedForBlockingMode bool
	NetflixAccountID           string
	// Both of these are used for mocking STS during testing
	STSEndpoint   string
	STSHTTPClient *http.Client

	SSLCA      string
	SSLKey     string
	SSLCert    string
	IAMService string

	// These are optional, and will be dynamically resolved if not specified.
	AvailabilityZone   string
	AvailabilityZoneID string
	// Region is also used for configuring the STS client to use that region's STS service
	Region string
}
