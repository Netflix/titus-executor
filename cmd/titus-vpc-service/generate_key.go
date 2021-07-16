package main

import (
	"context"
	"os"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/golang/protobuf/jsonpb" // nolint: staticcheck
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func generateKeyCommand(ctx context.Context, v *pkgviper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use: "generatekey",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname, err := os.Hostname()
			if err != nil {
				return errors.Wrap(err, "Could not fetch hostname")
			}
			publickey, privatekey, err := ed25519.GenerateKey(nil)
			if err != nil {
				return errors.Wrap(err, "Could not generate key")
			}
			pnow := timestamppb.Now()

			_, db, err := newConnection(ctx, v)
			if err != nil {
				return errors.Wrap(err, "Could not connect to database")
			}

			_, err = db.ExecContext(ctx,
				"INSERT INTO trusted_public_keys(key, hostname, created_at, keytype) VALUES ($1, $2, $3, 'ed25519')",
				publickey, hostname, pnow.AsTime())
			if err != nil {
				return errors.Wrap(err, "Could not store key in DB")
			}

			marshaler := jsonpb.Marshaler{}
			err = marshaler.Marshal(os.Stdout, &vpcapi.PrivateKey{
				Hostname:  hostname,
				Generated: pnow,
				Key: &vpcapi.PrivateKey_Ed25519Key_{
					Ed25519Key: &vpcapi.PrivateKey_Ed25519Key{
						Rfc8032Key: privatekey.Seed(),
					},
				},
			})
			if err != nil {
				return errors.Wrap(err, "Could not serialize key")
			}
			return nil
		},
	}
	return cmd

}
