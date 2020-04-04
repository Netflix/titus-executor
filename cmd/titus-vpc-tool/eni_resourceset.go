package main

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"

	"github.com/Netflix/titus-executor/vpc"
)

func eniResourceSetCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eni-resource-set",
		Short: "print the ENI resource set for this node",
		RunE: func(cmd *cobra.Command, args []string) error {
			iip := iipGetter()
			ident, err := iip.GetIdentity(ctx)
			if err != nil {
				return errors.Wrap(err, "error getting instance identity")
			}

			maxIPAddress, err := vpc.GetMaxIPAddresses(ident.InstanceType)
			if err != nil {
				return errors.Wrap(err, "error getting max IP addresses")
			}

			branchENIs, err := vpc.GetMaxBranchENIs(ident.InstanceType)
			if err != nil {
				return errors.Wrap(err, "error getting max branch ENIs")
			}

			fmt.Printf("ResourceSet-ENIs-%d-%d\n", branchENIs, maxIPAddress)
			return nil
		},
	}

	addSharedFlags(cmd.Flags())

	return cmd
}
