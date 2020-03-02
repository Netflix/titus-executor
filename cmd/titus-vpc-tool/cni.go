package main

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/tool/cni"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
	"google.golang.org/grpc"
)

func cniCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cni",
		Short: "Run as CNI plugin",
		RunE: func(cmd *cobra.Command, args []string) error {
			cniCommand := cni.MakeCommand(ctx, iipGetter(), func(ctx2 context.Context) (*grpc.ClientConn, error) {
				_, c, e := getSharedValues(ctx2, v)
				return c, e
			})
			err := skel.PluginMainWithError(cniCommand.Add, cniCommand.Check, cniCommand.Del, cni.VersionInfo, "Titus CNI Plugin")
			if err != nil {
				err2 := err.Print()
				if err2 != nil {
					err2 = errors.Wrap(err, "Cannot write error JSON")
					return err2
				}
			}
			return nil
		},
	}

	addSharedFlags(cmd.PersistentFlags())

	return cmd
}
