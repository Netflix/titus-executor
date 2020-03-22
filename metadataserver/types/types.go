package types

import (
	"net"
	"net/url"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/identity"
)

const (
	// TitusOptimisticIAMVariableName is the name of the environment variable to enable optimistic IAM fetch
	TitusOptimisticIAMVariableName = "TITUS_OPTMISTIC_IAM"
	// TitusMetatronVariableName is the name of the environment variable that indicates if metatron is enabled for a container
	TitusMetatronVariableName = "TITUS_METATRON_ENABLED"
	// TitusAPIProtectEnabledVariableName is the name of the environment variable that indicates if API Protect is enabled for a container
	// API protect scopes the API keys used for a given container to just that instance / NAT gateway
	TitusAPIProtectEnabledVariableName = "TITUS_API_PROTECT_ENABLED"
)

// MetadataServerConfiguration is a configuration for metadata service + IAM Proxy
// optional fields are pointers
type MetadataServerConfiguration struct {
	BackingMetadataServer *url.URL
	StateDir              string
	IAMARN                string
	TitusTaskInstanceID   string
	Ipv4Address           net.IP
	Ipv6Address           *net.IP
	VpcID                 string
	EniID                 string
	Region                string
	Optimistic            bool
	APIProtectEnabled     bool
	Container             *titus.ContainerInfo
	Signer                *identity.Signer
	RequireToken          bool
	TokenKey              string
}
