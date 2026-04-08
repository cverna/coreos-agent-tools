package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/cverna/coreos-agent-tools/go/pkg/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Profiles subcommand group
var jenkinsProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "Manage Jenkins profiles",
	Long:  `Create and list Jenkins profiles for connecting to multiple Jenkins instances.`,
}

// ProfilesListOutput represents the JSON output for profiles list
type ProfilesListOutput struct {
	Profiles []string `json:"profiles"`
	Default  string   `json:"default"`
}

var jenkinsProfilesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available Jenkins profiles",
	Long:  `List all available Jenkins profiles with the default profile marked.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		profiles, err := config.ListJenkinsProfiles()
		if err != nil {
			return fmt.Errorf("failed to list profiles: %w", err)
		}

		defaultProfile := config.GetDefaultJenkinsProfile()

		output := ProfilesListOutput{
			Profiles: profiles,
			Default:  defaultProfile,
		}

		// Handle empty profiles list
		if output.Profiles == nil {
			output.Profiles = []string{}
		}

		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal output: %w", err)
		}

		fmt.Println(string(jsonData))
		return nil
	},
}

var (
	profileCreateURL     string
	profileCreateUser    string
	profileCreateDefault bool
)

var jenkinsProfilesCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new Jenkins profile",
	Long: `Create a new Jenkins profile with the specified name.
The Jenkins URL and username are provided via flags, and the API token
is prompted interactively to avoid exposing it in shell history.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		// Validate name
		if strings.ContainsAny(name, "/\\. ") {
			return fmt.Errorf("profile name cannot contain '/', '\\', '.', or spaces")
		}

		// Check if profile already exists
		if config.JenkinsProfileExists(name) {
			return fmt.Errorf("profile '%s' already exists", name)
		}

		// Validate required flags
		if profileCreateURL == "" {
			return fmt.Errorf("--url is required")
		}
		if profileCreateUser == "" {
			return fmt.Errorf("--user is required")
		}

		// Prompt for API token interactively
		token, err := promptForToken()
		if err != nil {
			return fmt.Errorf("failed to read API token: %w", err)
		}

		if token == "" {
			return fmt.Errorf("API token cannot be empty")
		}

		// Create the profile
		if err := config.CreateJenkinsProfile(name, profileCreateURL, profileCreateUser, token); err != nil {
			return fmt.Errorf("failed to create profile: %w", err)
		}

		// Set as default if requested
		if profileCreateDefault {
			if err := config.SetDefaultJenkinsProfile(name); err != nil {
				return fmt.Errorf("profile created but failed to set as default: %w", err)
			}
		}

		// Output result
		result := map[string]interface{}{
			"created":   name,
			"url":       profileCreateURL,
			"user":      profileCreateUser,
			"isDefault": profileCreateDefault,
		}

		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal output: %w", err)
		}

		fmt.Println(string(jsonData))
		return nil
	},
}

// promptForToken prompts the user to enter the Jenkins API token securely
func promptForToken() (string, error) {
	fmt.Fprint(os.Stderr, "Enter Jenkins API token: ")

	// Check if stdin is a terminal
	if term.IsTerminal(int(syscall.Stdin)) {
		// Read password securely (no echo)
		byteToken, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr) // Print newline after hidden input
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(byteToken)), nil
	}

	// If not a terminal, read from stdin normally (for piping)
	reader := bufio.NewReader(os.Stdin)
	token, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(token), nil
}

func init() {
	// Add profiles command to jenkins
	jenkinsCmd.AddCommand(jenkinsProfilesCmd)

	// Add subcommands to profiles
	jenkinsProfilesCmd.AddCommand(jenkinsProfilesListCmd)
	jenkinsProfilesCmd.AddCommand(jenkinsProfilesCreateCmd)

	// Flags for create command
	jenkinsProfilesCreateCmd.Flags().StringVar(&profileCreateURL, "url", "",
		"Jenkins server URL (required)")
	jenkinsProfilesCreateCmd.Flags().StringVar(&profileCreateUser, "user", "",
		"Jenkins username (required)")
	jenkinsProfilesCreateCmd.Flags().BoolVar(&profileCreateDefault, "default", false,
		"Set this profile as the default")

	_ = jenkinsProfilesCreateCmd.MarkFlagRequired("url")
	_ = jenkinsProfilesCreateCmd.MarkFlagRequired("user")
}
