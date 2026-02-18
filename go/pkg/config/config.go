// Package config handles loading and validating configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"path/filepath"

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
	BaseURL  string
}

// LoadEnv loads environment variables from .env file.
// It searches in the current directory and parent directories.
func LoadEnv() error {
	// Try to find .env file in current or parent directories
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

	baseURL := os.Getenv("JIRA_BASE_URL")
	if baseURL == "" {
		baseURL = "https://issues.redhat.com"
	}

	return &JiraConfig{
		APIToken: token,
		BaseURL:  baseURL,
	}, nil
}
