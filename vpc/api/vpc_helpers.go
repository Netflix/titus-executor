package api

import "fmt"

/* These are functions added to help with things like type switches */
func (m *Assignment) IPV4Address() *UsableAddress {
	if m == nil {
		return nil
	}
	switch t := (m.Assignment).(type) {
	case *Assignment_AssignIPResponseV3:
		return t.AssignIPResponseV3.Ipv4Address
	default:
		panic(fmt.Sprintf("Found unexpected type: %T", t))
	}
}

func (m *Assignment) TransitionAddress() *UsableAddress {
	if m == nil {
		return nil
	}
	switch t := (m.Assignment).(type) {
	case *Assignment_AssignIPResponseV3:
		if t.AssignIPResponseV3.TransitionAssignment == nil {
			return nil
		}

		return t.AssignIPResponseV3.TransitionAssignment.Ipv4Address
	default:
		panic(fmt.Sprintf("Found unexpected type: %T", t))
	}
}

func (m *Assignment) IPV6Address() *UsableAddress {
	if m == nil {
		return nil
	}
	switch t := (m.Assignment).(type) {
	case *Assignment_AssignIPResponseV3:
		return t.AssignIPResponseV3.Ipv6Address
	default:
		panic(fmt.Sprintf("Found unexpected type: %T", t))
	}
}

func (m *Assignment) ContainerENI() *NetworkInterface {
	if m == nil {
		return nil
	}
	switch t := (m.Assignment).(type) {
	case *Assignment_AssignIPResponseV3:
		return t.AssignIPResponseV3.BranchNetworkInterface
	default:
		panic(fmt.Sprintf("Found unexpected type: %T", t))
	}
}

func (m *Assignment) DeviceIndex() int {
	if m == nil {
		return 0
	}
	switch t := (m.Assignment).(type) {
	case *Assignment_AssignIPResponseV3:
		return int(t.AssignIPResponseV3.VlanId)
	default:
		panic(fmt.Sprintf("Found unexpected type: %T", t))
	}
}

func (m *Assignment) ElasticAddress() *ElasticAddress {
	if m == nil {
		return nil
	}
	switch t := (m.Assignment).(type) {
	case *Assignment_AssignIPResponseV3:
		return t.AssignIPResponseV3.ElasticAddress
	default:
		panic(fmt.Sprintf("Found unexpected type: %T", t))
	}
}
