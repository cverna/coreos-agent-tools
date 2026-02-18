package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose bool
	logger  *slog.Logger
)

var rootCmd = &cobra.Command{
	Use:   "coreos-tools",
	Short: "CoreOS infrastructure tools",
	Long: `A collection of CLI tools for monitoring and analyzing Red Hat CoreOS (RHCOS) infrastructure.

Tools included:
  - jenkins: Manage Jenkins jobs, builds, queue, and nodes
  - cve: Process RHCOS CVEs and match with RHEL issues
  - image: Retrieve RHCOS container image data`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Setup logger based on verbose flag
		level := slog.LevelWarn
		if verbose {
			level = slog.LevelDebug
		}
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}))
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

// printJSON outputs data as JSON to stdout.
func printJSON(data any) error {
	output, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

// printError outputs an error as JSON to stderr.
func printError(err error) {
	output, _ := json.Marshal(map[string]string{"error": err.Error()})
	fmt.Fprintln(os.Stderr, string(output))
}
