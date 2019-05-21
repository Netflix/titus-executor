package identity

import (
	"regexp"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	accountIdRegex = regexp.MustCompile("^\\d+$")
)

type InstanceIdentityProvider interface {
	GetIdentity() (*vpcapi.InstanceIdentity, error)
}

func GetEnvironmentProvider(v *viper.Viper) (*pflag.FlagSet, InstanceIdentityProvider) {
	flagSet := pflag.NewFlagSet("environmentprovider", pflag.ExitOnError)
	flagSet.String("instance-id", "", "EC2 Instance ID")
	v.BindEnv("instance-id", "EC2_INSTANCE_ID")
	flagSet.String("region", "us-east-1", "EC2 region")
	v.BindEnv("region", "EC2_REGION")
	flagSet.String("account-id", "", "Account ID")
	v.BindEnv("account-id", "EC2_OWNER_ID")
	flagSet.String("instance-type", "", "Instance Type")
	v.BindEnv("instance-type", "EC2_INSTANCE_TYPE")

	// Add flags viper
	v.BindPFlags(flagSet)

	return flagSet, &environmentProvider{
		viper: v,
	}
}
