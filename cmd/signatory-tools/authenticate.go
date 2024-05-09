package main

import (
	"encoding/hex"
	"fmt"

	"github.com/mavryk-network/mavryk-signatory/pkg/cryptoutils"
	"github.com/mavryk-network/mavryk-signatory/pkg/mavryk/utils"
	"github.com/mavryk-network/mavryk-signatory/pkg/signatory"
	"github.com/spf13/cobra"
)

func NewAuthRequestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authenticate <secret key> <request pkh> <request body>",
		Short: "Authenticate (sign) a sign request",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			priv, err := mavryk.ParsePrivateKey(args[0], nil)
			if err != nil {
				return err
			}

			msg, err := hex.DecodeString(args[2])
			if err != nil {
				return err
			}

			req := signatory.SignRequest{
				Message:       msg,
				PublicKeyHash: args[1],
			}

			data, err := signatory.SignRequestAuthenticatedBytes(&req)
			if err != nil {
				return err
			}

			digest := utils.DigestFunc(data)
			sig, err := cryptoutils.Sign(priv, digest[:])
			if err != nil {
				return err
			}

			res, err := mavryk.EncodeSignature(sig)
			if err != nil {
				return err
			}

			fmt.Println(res)
			return nil
		},
	}

	return cmd
}
