// Package ocp provides functions for interacting with OpenShift release data.
package ocp

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cverna/coreos-agent-tools/pkg/httpclient"
)

const (
	// ReleasesAPIURL is the URL for the OCP releases API.
	ReleasesAPIURL = "https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestreams/accepted"
)

var (
	rcPattern       = regexp.MustCompile(`-rc\.\d+`)
	dateTimePattern = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}-\d{6})`)
)

// RHCOSImageData contains the data needed to retrieve the RHCOS container image.
type RHCOSImageData struct {
	ReleaseImage      string   `json:"release_image"`
	RHELCoreOS        string   `json:"rhel_coreos"`
	ResolvedVersion   string   `json:"resolved_version"`
	RegistryAuthFile  string   `json:"registry_auth_file,omitempty"`
	Error             string   `json:"error,omitempty"`
	AvailableVersions []string `json:"available_versions,omitempty"`
}

// Client provides access to OCP release data.
type Client struct {
	httpClient *httpclient.Client
	logger     *slog.Logger
}

// NewClient creates a new OCP client.
func NewClient(logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		httpClient: httpclient.New(logger),
		logger:     logger,
	}
}

// versionInfo holds parsed version information for sorting.
type versionInfo struct {
	version  string
	hasDate  bool
	dateTime time.Time
	major    int
	minor    int
	patch    int
	ec       int
}

// parseVersion parses a version string into versionInfo for sorting.
func parseVersion(version string) versionInfo {
	info := versionInfo{version: version}

	// Check for date pattern first
	if match := dateTimePattern.FindStringSubmatch(version); len(match) > 1 {
		if t, err := time.Parse("2006-01-02-150405", match[1]); err == nil {
			info.hasDate = true
			info.dateTime = t
			return info
		}
	}

	// Parse version numbers
	if strings.Contains(version, "-ec.") {
		parts := strings.Split(version, "-ec.")
		if len(parts) == 2 {
			if ec, err := strconv.Atoi(parts[1]); err == nil {
				info.ec = ec
			}
			version = parts[0]
		}
	}

	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		info.major, _ = strconv.Atoi(parts[0])
		info.minor, _ = strconv.Atoi(parts[1])
		if len(parts) >= 3 {
			info.patch, _ = strconv.Atoi(parts[2])
		}
	}

	return info
}

// ExtractAllOCPVersions fetches and returns all available OCP versions.
func (c *Client) ExtractAllOCPVersions() ([]string, error) {
	resp, err := c.httpClient.Get(ReleasesAPIURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var data map[string][]string
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var versions []string
	for _, versionList := range data {
		for _, version := range versionList {
			// Filter out release candidates
			if !rcPattern.MatchString(version) {
				versions = append(versions, version)
			}
		}
	}

	// Filter for OCP 4.12+
	var filtered []string
	for _, v := range versions {
		if isValidOCPVersion(v) {
			filtered = append(filtered, v)
		}
	}

	// Sort versions (date-based first, then by version number)
	sort.Slice(filtered, func(i, j int) bool {
		vi := parseVersion(filtered[i])
		vj := parseVersion(filtered[j])

		// Date-based versions come first
		if vi.hasDate && !vj.hasDate {
			return true
		}
		if !vi.hasDate && vj.hasDate {
			return false
		}
		if vi.hasDate && vj.hasDate {
			return vi.dateTime.After(vj.dateTime)
		}

		// Compare by version numbers
		if vi.major != vj.major {
			return vi.major > vj.major
		}
		if vi.minor != vj.minor {
			return vi.minor > vj.minor
		}
		if vi.patch != vj.patch {
			return vi.patch > vj.patch
		}
		return vi.ec > vj.ec
	})

	return filtered, nil
}

// isValidOCPVersion checks if version is OCP 4.12 or higher.
func isValidOCPVersion(version string) bool {
	if !strings.HasPrefix(version, "4.") {
		return false
	}
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return minor >= 12
}

// GetLatestOCPVersions returns a mapping of major.minor versions to their latest z-stream.
func (c *Client) GetLatestOCPVersions() (map[string]string, error) {
	versions, err := c.ExtractAllOCPVersions()
	if err != nil {
		return nil, err
	}

	latest := make(map[string]string)
	for _, version := range versions {
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			majorMinor := parts[0] + "." + parts[1]
			if _, exists := latest[majorMinor]; !exists {
				latest[majorMinor] = version
			}
		}
	}

	return latest, nil
}

// GetRHCOSImageData retrieves the data needed to get the RHCOS container image.
func (c *Client) GetRHCOSImageData(ocpVersion, registryAuthFile string) (*RHCOSImageData, error) {
	latestVersions, err := c.GetLatestOCPVersions()
	if err != nil {
		return nil, err
	}

	resolved, ok := latestVersions[ocpVersion]
	if !ok {
		var available []string
		for k := range latestVersions {
			available = append(available, k)
		}
		sort.Strings(available)
		return &RHCOSImageData{
			Error:             fmt.Sprintf("OCP version %s not found in latest OCP versions", ocpVersion),
			AvailableVersions: available,
		}, nil
	}

	// Determine RHEL CoreOS image name
	rhelCoreOS := "rhel-coreos"
	if strings.Contains(resolved, "4.12") {
		rhelCoreOS = "rhel-coreos-8"
	}

	// Determine the release image
	var releaseImage string
	if strings.Contains(resolved, "konflux-nightly") {
		releaseImage = fmt.Sprintf("registry.ci.openshift.org/ocp/konflux-release:%s", resolved)
	} else if (strings.Contains(resolved, "ci") || strings.Contains(resolved, "nightly")) && dateTimePattern.MatchString(resolved) {
		releaseImage = fmt.Sprintf("registry.ci.openshift.org/ocp/release:%s", resolved)
	} else {
		releaseImage = fmt.Sprintf("quay.io/openshift-release-dev/ocp-release:%s-x86_64", resolved)
	}

	result := &RHCOSImageData{
		ReleaseImage:    releaseImage,
		RHELCoreOS:      rhelCoreOS,
		ResolvedVersion: resolved,
	}

	if registryAuthFile != "" {
		result.RegistryAuthFile = registryAuthFile
	}

	return result, nil
}
