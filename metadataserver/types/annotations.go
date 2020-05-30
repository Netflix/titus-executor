package types

const (
	IamRoleArnAnnotation                = "iam.amazonaws.com/role"
	RequireTokenAnnotation              = "imds.titus.netflix.com/requireToken" // nolint:gosec
	XForwardedForBlockingModeAnnotation = "imds.titus.netflix.com/xForwardedForBlockingMode"
	MetatronEnabledAnnotation           = "metatron.titus.netflix.com/enabled"
)
