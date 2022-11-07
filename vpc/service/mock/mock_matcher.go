package mock

import (
	"fmt"
	"reflect"
	"strings"

	ec2 "github.com/aws/aws-sdk-go/service/ec2"
)

// Mock match EC2 CreateNetworkInterfaceInput
type MatchCni struct {
	Eni *ec2.CreateNetworkInterfaceInput
}

func (e MatchCni) Matches(x interface{}) bool {
	reflectedValue := reflect.ValueOf(x).Elem()
	if *e.Eni.Description != reflectedValue.FieldByName("Description").Elem().String() {
		return false
	} else if !reflect.DeepEqual(e.Eni.Groups, reflectedValue.FieldByName("Groups").Interface().([]*string)) {
		return false
	} else if *e.Eni.SubnetId != reflectedValue.FieldByName("SubnetId").Elem().String() {
		return false
	}
	return true
}

func (e MatchCni) String() string {
	securityGroups := []string{}
	for _, p := range e.Eni.Groups {
		securityGroups = append(securityGroups, *p)
	}
	return fmt.Sprintf("{ENI - Description: %s InterfaceType: %s SubnetId: %s Groups: %s}",
		*e.Eni.Description, *e.Eni.InterfaceType, *e.Eni.SubnetId, strings.Join(securityGroups, ","))
}

// Mock match EC2 AssociateTrunkInterfaceInput
type MatchAti struct {
	Ati *ec2.AssociateTrunkInterfaceInput
}

func (e MatchAti) Matches(x interface{}) bool {
	reflectedValue := reflect.ValueOf(x).Elem()
	if *e.Ati.TrunkInterfaceId != reflectedValue.FieldByName("TrunkInterfaceId").Elem().String() {
		return false
	} else if *e.Ati.BranchInterfaceId != reflectedValue.FieldByName("BranchInterfaceId").Elem().String() {
		return false
	}
	return true
}

func (e MatchAti) String() string {
	return fmt.Sprintf("{TrunkId: %s BranchId: %s ClientToken: %s VlanId: %d}",
		*e.Ati.TrunkInterfaceId, *e.Ati.BranchInterfaceId, *e.Ati.ClientToken, *e.Ati.VlanId)
}
