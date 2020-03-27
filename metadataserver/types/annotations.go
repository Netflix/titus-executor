package types

const (
	IamRoleArnAnnotation                = "iam.amazonaws.com/role"
	OptimisticFetchAnnotation           = "imds.titus.netflix.com/optimisticFetch"
	APIProtectEnabledAnnotation         = "imds.titus.netflix.com/apiProtectEnabled"
	RequireTokenAnnotation              = "imds.titus.netflix.com/requireToken" // nolint:gosec
	TokenKeySaltAnnotation              = "imds.titus.netflix.com/tokenKeySalt" // nolint:gosec
	XForwardedForBlockingModeAnnotation = "imds.titus.netflix.com/xForwardedForBlockingMode"

	MetatronEnabledAnnotation = "metatron.titus.netflix.com/enabled"
)
