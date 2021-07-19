package assignccas

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

type Arguments struct {
	TaskID string
}

func Assign(ctx context.Context, args Arguments) error {
	m := protojson.MarshalOptions{
		Indent: "\t",
	}

	allocation, err := doAllocateNetwork(ctx, args)
	if err != nil {
		err = errors.Wrap(err, "Unable to perform network allocation")
		data, serializationError := m.Marshal(&vpcapi.VPCToolResult{
			Result: &vpcapi.VPCToolResult_Error{
				Error: &vpcapi.Error{
					Error: err.Error(),
				},
			},
		})
		if serializationError != nil {
			err = fmt.Errorf("Unable to serial error %s: %w", err.Error(), serializationError)
		}

		_, writeError := os.Stdout.Write(data)
		if writeError != nil {
			err = fmt.Errorf("Unable to write serialized error %s: %w", err.Error(), writeError)
		}

		return err
	}

	switch a := allocation.Assignment.(type) {
	case *vpcapi.Assignment_AssignIPResponseV3:
		if a.AssignIPResponseV3.Ipv6Address != nil {
			ctx = logger.WithField(ctx, "ip6", a.AssignIPResponseV3.Ipv6Address)
		}
		if a.AssignIPResponseV3.Ipv4Address != nil {
			ctx = logger.WithField(ctx, "ip4", a.AssignIPResponseV3.Ipv4Address)
		}
	}
	logger.G(ctx).Info("Network setup")

	// We do an initial refresh just to "lick" the IPs, in case our allocation lasts a very short period.
	data, err := m.Marshal(&vpcapi.VPCToolResult{
		Result: &vpcapi.VPCToolResult_Assignment{
			Assignment: allocation,
		},
	})
	if err != nil {
		return errors.Wrap(err, "Unable to serialize allocation record")
	}

	_, err = os.Stdout.Write(data)
	if err != nil {
		return errors.Wrap(err, "Unable to write allocation record")
	}

	return nil
}

func doAllocateNetwork(ctx context.Context, args Arguments) (*vpcapi.Assignment, error) {
	// TODO: Make timeout adjustable
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "doAllocateNetwork")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("pid", int64(os.Getpid())))
	_ = ctx

	r := rand.New(rand.NewSource(time.Now().UnixNano())) // nolint: gosec
	lastOctet := r.Intn(250) + 2
	ip := fmt.Sprintf("10.51.40.%d", lastOctet)

	return &vpcapi.Assignment{
		Assignment: &vpcapi.Assignment_Ccas{
			Ccas: &vpcapi.CCAS{
				Ipv4Address: &vpcapi.UsableAddress{
					Address: &vpcapi.Address{
						Address: ip,
					},
					PrefixLength: 22,
				},
				Vlan: 38,
			},
		},
	}, nil
}

func Unassign(ctx context.Context, taskID string) error {
	return nil
}
