package main

import (
	"os"

	"github.com/cverna/coreos-agent-tools/pkg/ocp"
	"github.com/spf13/cobra"
)

var (
	imageOCPVersion string
)

var imageCmd = &cobra.Command{
	Use:   "image",
	Short: "Retrieve RHCOS container image data",
	Long:  `Retrieve the data needed to get the RHCOS container image for a given OCP version.`,
}

var imageGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get RHCOS image data for an OCP version",
	Long: `Get the data needed to retrieve the RHCOS container image for a specific OCP version.

Returns:
  - release_image: The OCP release image
  - rhel_coreos: The RHEL CoreOS component name
  - resolved_version: The full resolved OCP version
  - registry_auth_file: Path to registry auth file (if REGISTRY_AUTH_FILE is set)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := ocp.NewClient(logger)

		// Get registry auth file from environment
		registryAuthFile := os.Getenv("REGISTRY_AUTH_FILE")

		result, err := client.GetRHCOSImageData(imageOCPVersion, registryAuthFile)
		if err != nil {
			printError(err)
			return err
		}

		return printJSON(result)
	},
}

var imageListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available OCP versions",
	Long:  `List all available OCP versions from the OpenShift CI release streams.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := ocp.NewClient(logger)

		versions, err := client.GetLatestOCPVersions()
		if err != nil {
			printError(err)
			return err
		}

		return printJSON(versions)
	},
}

func init() {
	// Add image command to root
	rootCmd.AddCommand(imageCmd)

	// Add get subcommand
	imageGetCmd.Flags().StringVar(&imageOCPVersion, "ocp-version", "", "OpenShift version (e.g., '4.16', '4.17')")
	imageGetCmd.MarkFlagRequired("ocp-version")
	imageGetCmd.SilenceUsage = true
	imageCmd.AddCommand(imageGetCmd)

	// Add list subcommand
	imageListCmd.SilenceUsage = true
	imageCmd.AddCommand(imageListCmd)
}
