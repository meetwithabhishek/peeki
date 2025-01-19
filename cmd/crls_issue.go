package cmd

import (
	"github.com/spf13/cobra"
)

// issueCRLCmd represents the issue CRL command
var issueCRLCmd = &cobra.Command{
	Use:   "issue",
	Short: "issue a crl",
	Long:  `issues/reissues a fresh empty CRL for a CA`,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := issueCRL(caName, nil)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	crlCmd.AddCommand(issueCRLCmd)
	issueCRLCmd.Flags().StringVarP(&caName, "ca-name", "n", "", "CA Name")
}
