package types

import (
	"net"
	"net/url"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/identity"
)

const (
	// TitusMetatronVariableName is the name of the environment variable that indicates if metatron is enabled for a container
	TitusMetatronVariableName = "TITUS_METATRON_ENABLED"
)

// MetadataServerConfiguration is a configuration for metadata service + IAM Proxy
// optional fields are pointers
type MetadataServerConfiguration struct {
	BackingMetadataServer      *url.URL
	IAMARN                     string
	TitusTaskInstanceID        string
	Ipv4Address                net.IP
	Ipv6Address                *net.IP
	Region                     string
	Container                  *titus.ContainerInfo
	Signer                     *identity.Signer
	RequireToken               bool
	TokenKey                   string
	XFordwardedForBlockingMode bool
	NetflixAccountID           string
}
