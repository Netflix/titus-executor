package main

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/tool/operator"

	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func operatorCmd(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Perform cluster operations commands",
	}

	describeCmd := &cobra.Command{
		Use:   "describe",
		Short: "Describe the trunk network interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}
			return operator.Describe(ctx, iipGetter(), conn, v.GetString("trunk-eni"))
		},
	}
	describeCmd.Flags().StringP("trunk-eni", "t", "", "Describe a particular trunk network interface, as opposed to this instance's")
	cmd.AddCommand(describeCmd)

	associateCmd := &cobra.Command{
		Use:   "associate",
		Short: "associate the trunk network interface with a branch ENI",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}
			return operator.Associate(ctx, iipGetter(), conn,
				v.GetString("trunk-eni"),
				v.GetString("branch-eni"),
				v.GetInt("idx"),
			)
		},
	}
	associateCmd.Flags().StringP("trunk-eni", "t", "", "A particular trunk network interface, as opposed to this instance's")
	associateCmd.Flags().StringP("branch-eni", "b", "", "A particular branch network interface")
	associateCmd.Flags().IntP("idx", "i", 0, "A particular index to attach the branch ENI")
	cmd.AddCommand(associateCmd)

	disassociatecmd := &cobra.Command{
		Use:   "disassociate",
		Short: "disassociate the trunk network interface with a branch ENI",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}
			return operator.Disassociate(ctx, iipGetter(), conn, v.GetString("association-id"))
		},
	}
	disassociatecmd.Flags().StringP("association-id", "a", "", "Trunk network interface association")
	cmd.AddCommand(disassociatecmd)

	addSharedFlags(cmd.PersistentFlags())

	return cmd
}
