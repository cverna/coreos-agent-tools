// Package config handles loading and validating configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

// JenkinsConfig holds Jenkins connection settings.
type JenkinsConfig struct {
	URL   string
	User  string
	Token string
}

// JiraConfig holds Jira connection settings.
type JiraConfig struct {
	APIToken string
	Email    string
	BaseURL  string
}

// getConfigDir returns the XDG config directory for coreos-tools.
// It respects $XDG_CONFIG_HOME, falling back to ~/.config/coreos-tools.
func getConfigDir() string {
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "coreos-tools")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "coreos-tools")
}

// LoadEnv loads environment variables from .env file.
// It searches in the following order:
// 1. XDG config directory (~/.config/coreos-tools/.env)
// 2. Current directory and parent directories
func LoadEnv() error {
	// First, try XDG config directory
	if configDir := getConfigDir(); configDir != "" {
		envPath := filepath.Join(configDir, ".env")
		if _, err := os.Stat(envPath); err == nil {
			return godotenv.Load(envPath)
		}
	}

	// Fall back to current or parent directories
	dir, err := os.Getwd()
	if err != nil {
		return nil // Ignore error, rely on environment variables
	}

	for {
		envPath := filepath.Join(dir, ".env")
		if _, err := os.Stat(envPath); err == nil {
			return godotenv.Load(envPath)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return nil // No .env file found, rely on environment variables
}

// GetJenkinsConfig returns Jenkins configuration from environment variables.
func GetJenkinsConfig() (*JenkinsConfig, error) {
	url := os.Getenv("JENKINS_URL")
	user := os.Getenv("JENKINS_USER")
	token := os.Getenv("JENKINS_API_TOKEN")

	if url == "" || user == "" || token == "" {
		return nil, fmt.Errorf("JENKINS_URL, JENKINS_USER, and JENKINS_API_TOKEN must be set")
	}

	return &JenkinsConfig{
		URL:   url,
		User:  user,
		Token: token,
	}, nil
}

// GetJiraConfig returns Jira configuration from environment variables.
func GetJiraConfig() (*JiraConfig, error) {
	token := os.Getenv("JIRA_API_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("JIRA_API_TOKEN environment variable is not set")
	}

	email := os.Getenv("JIRA_EMAIL")
	if email == "" {
		return nil, fmt.Errorf("JIRA_EMAIL environment variable is not set")
	}

	baseURL := os.Getenv("JIRA_BASE_URL")
	if baseURL == "" {
		baseURL = "https://redhat.atlassian.net"
	}

	return &JiraConfig{
		APIToken: token,
		Email:    email,
		BaseURL:  baseURL,
	}, nil
}

// GetJenkinsProfilesDir returns the directory for Jenkins profiles.
func GetJenkinsProfilesDir() string {
	configDir := getConfigDir()
	if configDir == "" {
		return ""
	}
	return filepath.Join(configDir, "profiles", "jenkins")
}

// ListJenkinsProfiles returns a list of available Jenkins profile names.
func ListJenkinsProfiles() ([]string, error) {
	profilesDir := GetJenkinsProfilesDir()
	if profilesDir == "" {
		return nil, fmt.Errorf("could not determine config directory")
	}

	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var profiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".env") {
			profiles = append(profiles, strings.TrimSuffix(name, ".env"))
		}
	}

	return profiles, nil
}

// GetDefaultJenkinsProfile returns the default Jenkins profile name.
// Priority: JENKINS_PROFILE env var > JENKINS_DEFAULT_PROFILE in config.env > empty string
func GetDefaultJenkinsProfile() string {
	// First check environment variable
	if profile := os.Getenv("JENKINS_PROFILE"); profile != "" {
		return profile
	}

	// Then check config.env for default
	configDir := getConfigDir()
	if configDir == "" {
		return ""
	}

	configPath := filepath.Join(configDir, "config.env")
	if _, err := os.Stat(configPath); err != nil {
		return ""
	}

	env, err := godotenv.Read(configPath)
	if err != nil {
		return ""
	}

	return env["JENKINS_DEFAULT_PROFILE"]
}

// SetDefaultJenkinsProfile sets the default Jenkins profile in config.env.
func SetDefaultJenkinsProfile(name string) error {
	configDir := getConfigDir()
	if configDir == "" {
		return fmt.Errorf("could not determine config directory")
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "config.env")

	// Read existing config if it exists
	env := make(map[string]string)
	if _, err := os.Stat(configPath); err == nil {
		env, _ = godotenv.Read(configPath)
	}

	env["JENKINS_DEFAULT_PROFILE"] = name

	return godotenv.Write(env, configPath)
}

// JenkinsProfileExists checks if a Jenkins profile exists.
func JenkinsProfileExists(name string) bool {
	profilesDir := GetJenkinsProfilesDir()
	if profilesDir == "" {
		return false
	}

	profilePath := filepath.Join(profilesDir, name+".env")
	_, err := os.Stat(profilePath)
	return err == nil
}

// CreateJenkinsProfile creates a new Jenkins profile with the given credentials.
func CreateJenkinsProfile(name, url, user, token string) error {
	profilesDir := GetJenkinsProfilesDir()
	if profilesDir == "" {
		return fmt.Errorf("could not determine config directory")
	}

	// Ensure profiles directory exists
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}

	profilePath := filepath.Join(profilesDir, name+".env")

	env := map[string]string{
		"JENKINS_URL":       url,
		"JENKINS_USER":      user,
		"JENKINS_API_TOKEN": token,
	}

	return godotenv.Write(env, profilePath)
}

// GetJenkinsConfigWithProfile returns Jenkins configuration from a profile.
// If profileName is empty, it uses the default profile or falls back to legacy .env.
// Priority:
// 1. Explicit profileName parameter
// 2. JENKINS_PROFILE environment variable
// 3. JENKINS_DEFAULT_PROFILE in config.env
// 4. Legacy .env file (backward compatibility)
func GetJenkinsConfigWithProfile(profileName string) (*JenkinsConfig, error) {
	// Determine which profile to use
	if profileName == "" {
		profileName = GetDefaultJenkinsProfile()
	}

	// If we have a profile name, load it
	if profileName != "" {
		profilesDir := GetJenkinsProfilesDir()
		if profilesDir == "" {
			return nil, fmt.Errorf("could not determine config directory")
		}

		profilePath := filepath.Join(profilesDir, profileName+".env")
		if _, err := os.Stat(profilePath); err != nil {
			return nil, fmt.Errorf("profile '%s' not found", profileName)
		}

		env, err := godotenv.Read(profilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read profile '%s': %w", profileName, err)
		}

		url := env["JENKINS_URL"]
		user := env["JENKINS_USER"]
		token := env["JENKINS_API_TOKEN"]

		if url == "" || user == "" || token == "" {
			return nil, fmt.Errorf("profile '%s' is missing required fields (JENKINS_URL, JENKINS_USER, JENKINS_API_TOKEN)", profileName)
		}

		return &JenkinsConfig{
			URL:   url,
			User:  user,
			Token: token,
		}, nil
	}

	// Fall back to legacy GetJenkinsConfig (uses environment variables)
	return GetJenkinsConfig()
}
