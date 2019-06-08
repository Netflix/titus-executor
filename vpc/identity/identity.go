package identity

import (
	"context"
	"regexp"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	accountIDRegex = regexp.MustCompile(`^\d+$`)
)

type InstanceIdentityProvider interface {
	GetIdentity(ctx context.Context) (*vpcapi.InstanceIdentity, error)
}

func GetEnvironmentProvider(v *viper.Viper) (*pflag.FlagSet, InstanceIdentityProvider) {
	flagSet := pflag.NewFlagSet("environmentprovider", pflag.ExitOnError)
	flagSet.String("instance-id", "", "EC2 Instance ID")
	if err := v.BindEnv("instance-id", "EC2_INSTANCE_ID"); err != nil {
		panic(err)
	}
	flagSet.String("region", "us-east-1", "EC2 region")
	if err := v.BindEnv("region", "EC2_REGION"); err != nil {
		panic(err)
	}
	flagSet.String("account-id", "", "Account ID")
	if err := v.BindEnv("account-id", "EC2_OWNER_ID"); err != nil {
		panic(err)
	}
	flagSet.String("instance-type", "", "Instance Type")
	if err := v.BindEnv("instance-type", "EC2_INSTANCE_TYPE"); err != nil {
		panic(err)
	}

	// Add flags viper
	if err := v.BindPFlags(flagSet); err != nil {
		panic(err)
	}

	return flagSet, &environmentProvider{
		viper: v,
	}
}

func GetEC2Provider() InstanceIdentityProvider {
	return &ec2Provider{}
}
