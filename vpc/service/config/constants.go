package config

const (
	AtlasAddrFlagName             = "atlas-addr"
	ZipkinURLFlagName             = "zipkin"
	DebugAddressFlagName          = "debug-address"
	MaxIdleConnectionsFlagName    = "max-idle-connections"
	MaxOpenConnectionsFlagName    = "max-open-connections"
	MaxConcurrentRefreshFlagName  = "max-concurrent-refresh"
	MaxConcurrentRequestsFlagName = "max-concurrent-requests"
	WorkerRoleFlagName            = "worker-role"
	DBURLFlagName                 = "dburl"
	ReconcileIntervalFlagName     = "reconcile-interval"

	SslCertFlagName       = "ssl-cert"
	SslPrivateKeyFlagName = "ssl-private-key"
	SslCAFlagName         = "ssl-ca"

	EnabledLongLivedTasksFlagName = "enabled-long-lived-tasks"
	EnabledTaskLoopsFlagName      = "enabled-task-loops"

	TrunkENIDescriptionFlagName   = "trunk-eni-description"
	BranchENIDescriptionFlagName  = "branch-eni-description"
	SubnetCIDRReservationFlagName = "titus-reserved"

	TableMetricsIntervalFlagName = "table-metrics-interval"
)
