// Package main is the entry point for the coreos-tools CLI.
package main

import (
	"os"

	"github.com/cverna/coreos-agent-tools/pkg/config"
)

func main() {
	// Load environment variables from .env file
	_ = config.LoadEnv()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
