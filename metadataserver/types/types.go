package types

import (
	"net"
	"net/http"
	"net/url"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/identity"
)

const (
	// TitusMetatronVariableName is the name of the environment variable that indicates if metatron is enabled for a container
	TitusMetatronVariableName = "TITUS_METATRON_ENABLED"
	EC2IPv4EnvVarName         = "EC2_LOCAL_IPV4"
	EC2PublicIPv4EnvVarName   = "EC2_PUBLIC_IPV4"
	EC2PublicIPv4sEnvVarName  = "EC2_PUBLIC_IPV4S"
	EC2IPv6sEnvVarName        = "EC2_IPV6S"
)

// MetadataServerConfiguration is a configuration for metadata service + IAM Proxy
// optional fields are pointers
type MetadataServerConfiguration struct {
	BackingMetadataServer      *url.URL
	IAMARN                     string
	TitusTaskInstanceID        string
	Ipv4Address                net.IP
	PublicIpv4Address          net.IP
	Ipv6Address                *net.IP
	Region                     string
	Container                  *titus.ContainerInfo
	Signer                     *identity.Signer
	RequireToken               bool
	TokenKey                   string
	XFordwardedForBlockingMode bool
	NetflixAccountID           string
	// Both of these are used for mocking STS during testing
	STSEndpoint   string
	STSHTTPClient *http.Client
}
