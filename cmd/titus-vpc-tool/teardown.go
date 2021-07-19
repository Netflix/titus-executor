package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/container2"
	"github.com/Netflix/titus-executor/vpc/tool/containerccas"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
	"google.golang.org/protobuf/encoding/protojson"
)

func teardownContainercommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "teardown-container",
		Short: "Tear down networking for a particular container",
		RunE: func(cmd *cobra.Command, args []string) error {
			netnsfd := v.GetInt("netns")
			var assignment vpcapi.Assignment
			var b json.RawMessage

			dec := json.NewDecoder(os.Stdin)
			err := dec.Decode(&b)
			if err != nil {
				return fmt.Errorf("Cannot read JSON from stdin: %w", err)
			}
			err = protojson.Unmarshal(b, &assignment)
			if err != nil {
				return fmt.Errorf("Cannot unmarshal JSON: %w", err)
			}
			switch v := assignment.Assignment.(type) {
			case *vpcapi.Assignment_AssignIPResponseV3:
				return container2.DoTeardownContainer(ctx, v.AssignIPResponseV3, netnsfd)
			case *vpcapi.Assignment_Ccas:
				return containerccas.DoTeardownContainer(ctx, v.Ccas, netnsfd)
			default:
				return fmt.Errorf("Unknown assignment type received: %t", v)
			}
		},
	}

	cmd.Flags().Int("netns", 3, "The File Descriptor # of the network namespace to setup")
	return cmd
}
