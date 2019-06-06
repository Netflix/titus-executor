package identity

import (
	"context"
	"fmt"
	"strings"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/spf13/viper"
)

type environmentProvider struct {
	viper *viper.Viper
}

func (e *environmentProvider) GetIdentity(ctx context.Context) (*vpcapi.InstanceIdentity, error) {
	instanceID := e.viper.GetString("instance-id")
	if !strings.HasPrefix(instanceID, "i-") {
		return nil, fmt.Errorf("Cannot generate instance identity, invalid instance id %q", instanceID)
	}
	accountID := e.viper.GetString("account-id")
	if !accountIDRegex.MatchString(accountID) {
		return nil, fmt.Errorf("Cannot generate account ID, invalid account id %q", accountID)

	}

	region := e.viper.GetString("region")
	partition := endpoints.AwsPartition()

	if _, ok := partition.Regions()[region]; !ok {
		return nil, fmt.Errorf("Cannot generate region, invalid region %q", region)
	}

	instanceType := e.viper.GetString("instance-type")
	if instanceType == "" {
		return nil, fmt.Errorf("Cannot generate instance type, instance type empty")
	}

	return &vpcapi.InstanceIdentity{
		InstanceID:   instanceID,
		Region:       region,
		AccountID:    accountID,
		InstanceType: instanceType,
	}, nil
}
