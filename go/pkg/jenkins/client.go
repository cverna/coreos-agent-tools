package jenkins

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cverna/coreos-agent-tools/pkg/httpclient"
)

// Client is a Jenkins API client.
type Client struct {
	baseURL    string
	username   string
	token      string
	httpClient *httpclient.Client
	logger     *slog.Logger
}

// NewClient creates a new Jenkins client.
func NewClient(baseURL, username, token string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		username:   username,
		token:      token,
		httpClient: httpclient.New(logger),
		logger:     logger,
	}
}

// get performs a GET request to the Jenkins API.
func (c *Client) get(endpoint string, params map[string]string) ([]byte, error) {
	u, err := url.Parse(c.baseURL + endpoint)
	if err != nil {
		return nil, err
	}

	if params != nil {
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	resp, err := c.httpClient.GetWithAuth(u.String(), c.username, c.token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found: %s", endpoint)
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// getText performs a GET request and returns the response as text.
func (c *Client) getText(endpoint string) (string, error) {
	u := c.baseURL + endpoint

	resp, err := c.httpClient.GetWithAuth(u, c.username, c.token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// post performs a POST request to the Jenkins API.
func (c *Client) post(endpoint string, params map[string]string) (*http.Response, error) {
	u, err := url.Parse(c.baseURL + endpoint)
	if err != nil {
		return nil, err
	}

	if params != nil {
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	return c.httpClient.PostWithAuth(u.String(), c.username, c.token, nil, "")
}

// encodeJobPath encodes a job path for use in Jenkins URLs.
// Handles nested folders: "folder/subfolder/job" -> "job/folder/job/subfolder/job/job"
func encodeJobPath(jobName string) string {
	parts := strings.Split(jobName, "/")
	var encoded []string
	for _, part := range parts {
		encoded = append(encoded, "job", url.PathEscape(part))
	}
	return strings.Join(encoded, "/")
}

// ListJobs returns a list of all jobs.
func (c *Client) ListJobs(folder string, filter string) ([]Job, error) {
	var endpoint string
	if folder != "" {
		endpoint = fmt.Sprintf("/%s/api/json", encodeJobPath(folder))
	} else {
		endpoint = "/api/json"
	}

	data, err := c.get(endpoint, map[string]string{
		"tree": "jobs[name,url,color,_class,buildable,description,fullName,displayName,inQueue]",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	var resp JobsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse jobs response: %w", err)
	}

	// Apply filter if specified
	if filter != "" {
		filter = strings.ToLower(filter)
		var filtered []Job
		for _, job := range resp.Jobs {
			if strings.Contains(strings.ToLower(job.Name), filter) {
				filtered = append(filtered, job)
			}
		}
		return filtered, nil
	}

	return resp.Jobs, nil
}

// GetJobInfo returns detailed information about a job.
func (c *Client) GetJobInfo(jobName string) (*JobInfo, error) {
	endpoint := fmt.Sprintf("/%s/api/json", encodeJobPath(jobName))

	data, err := c.get(endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get job info for '%s': %w", jobName, err)
	}

	var job JobInfo
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, fmt.Errorf("failed to parse job info: %w", err)
	}

	return &job, nil
}

// TriggerBuild triggers a new build for a job.
func (c *Client) TriggerBuild(jobName string, params map[string]string) error {
	var endpoint string
	if len(params) > 0 {
		endpoint = fmt.Sprintf("/%s/buildWithParameters", encodeJobPath(jobName))
	} else {
		endpoint = fmt.Sprintf("/%s/build", encodeJobPath(jobName))
	}

	resp, err := c.post(endpoint, params)
	if err != nil {
		return fmt.Errorf("failed to trigger build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to trigger build (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// AbortBuild aborts a running build.
func (c *Client) AbortBuild(jobName string, buildNumber int) error {
	endpoint := fmt.Sprintf("/%s/%d/stop", encodeJobPath(jobName), buildNumber)

	resp, err := c.post(endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to abort build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to abort build (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// extractParamFromActions extracts a parameter value by name from build actions.
func extractParamFromActions(actions []BuildAction, paramName string) string {
	for _, action := range actions {
		for _, param := range action.Parameters {
			if param.Name == paramName {
				if s, ok := param.Value.(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

// ListBuilds returns a list of builds for a job.
func (c *Client) ListBuilds(jobName string, limit int) ([]BuildSummary, error) {
	endpoint := fmt.Sprintf("/%s/api/json", encodeJobPath(jobName))

	// Include actions with parameters to extract STREAM/ARCH, and description
	tree := fmt.Sprintf("builds[number,url,result,building,duration,timestamp,description,actions[parameters[name,value]]]{0,%d}", limit)
	data, err := c.get(endpoint, map[string]string{"tree": tree})
	if err != nil {
		return nil, fmt.Errorf("failed to list builds: %w", err)
	}

	var resp struct {
		Builds []struct {
			Number      int           `json:"number"`
			URL         string        `json:"url"`
			Result      string        `json:"result"`
			Building    bool          `json:"building"`
			Duration    int64         `json:"duration"`
			Timestamp   int64         `json:"timestamp"`
			Description string        `json:"description"`
			Actions     []BuildAction `json:"actions"`
		} `json:"builds"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse builds response: %w", err)
	}

	var builds []BuildSummary
	for _, b := range resp.Builds {
		builds = append(builds, BuildSummary{
			Number:      b.Number,
			URL:         b.URL,
			Result:      b.Result,
			Building:    b.Building,
			Duration:    b.Duration,
			Timestamp:   time.UnixMilli(b.Timestamp),
			Stream:      extractParamFromActions(b.Actions, "STREAM"),
			Description: b.Description,
		})
	}

	return builds, nil
}

// GetBuildInfo returns detailed information about a build.
func (c *Client) GetBuildInfo(jobName string, buildNumber int) (*Build, error) {
	endpoint := fmt.Sprintf("/%s/%d/api/json", encodeJobPath(jobName), buildNumber)

	data, err := c.get(endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get build info: %w", err)
	}

	var build Build
	if err := json.Unmarshal(data, &build); err != nil {
		return nil, fmt.Errorf("failed to parse build info: %w", err)
	}

	return &build, nil
}

// GetBuildLog returns the console log for a build.
func (c *Client) GetBuildLog(jobName string, buildNumber int) (string, error) {
	endpoint := fmt.Sprintf("/%s/%d/consoleText", encodeJobPath(jobName), buildNumber)
	return c.getText(endpoint)
}

// GetKolaFailures extracts kola test failures from a build's console log.
func (c *Client) GetKolaFailures(jobName string, buildNumber int) (*KolaFailureSummary, error) {
	// Get the build log
	log, err := c.GetBuildLog(jobName, buildNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get build log: %w", err)
	}

	// Get build info for stream
	buildInfo, err := c.GetBuildInfo(jobName, buildNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get build info: %w", err)
	}

	// Extract stream from build parameters (STREAM parameter in actions)
	stream := extractParamFromActions(buildInfo.Actions, "STREAM")

	// Parse kola failures from log
	// Pattern: --- \x1b[31mFAIL\x1b[0m: <test-name> (<duration>s)
	// Note: \x1b is the ESC character for ANSI codes
	// Lines may be prefixed with timestamps like [2026-02-25T09:46:05.650Z]
	failPattern := regexp.MustCompile(`--- \x1b\[31mFAIL\x1b\[0m: (.+?) \(([0-9.]+)s\)`)
	// Pattern for error message (next line after FAIL)
	errorPattern := regexp.MustCompile(`harness\.go:\d+: (.+)`)

	// Track failures by test name for deduplication
	// If a test appears multiple times, it means it was rerun and failed again
	failures := make(map[string]*KolaFailedTest)
	failureOrder := []string{} // Preserve order

	lines := strings.Split(log, "\n")
	var lastFailedTest string

	for _, line := range lines {

		// Check for FAIL line
		if matches := failPattern.FindStringSubmatch(line); len(matches) > 2 {
			testName := matches[1]
			duration, _ := strconv.ParseFloat(matches[2], 64)

			if existing, ok := failures[testName]; ok {
				// Test failed again (in rerun)
				existing.Attempts++
				existing.RerunFailed = true
			} else {
				// First failure for this test
				failures[testName] = &KolaFailedTest{
					Name:            testName,
					DurationSeconds: duration,
					Attempts:        1,
					RerunFailed:     false,
				}
				failureOrder = append(failureOrder, testName)
			}
			lastFailedTest = testName
			continue
		}

		// Check for error message (follows FAIL line)
		if lastFailedTest != "" {
			if matches := errorPattern.FindStringSubmatch(line); len(matches) > 1 {
				if failure, ok := failures[lastFailedTest]; ok {
					// Only set error on first occurrence (don't overwrite with rerun error)
					if failure.Error == "" {
						failure.Error = matches[1]
					}
				}
				lastFailedTest = ""
			}
		}
	}

	// Build result in original order
	// Note: Tests with Attempts=1 and RerunFailed=false passed on rerun (flaky tests)
	resultFailures := make([]KolaFailedTest, 0)
	for _, name := range failureOrder {
		if failure, ok := failures[name]; ok {
			resultFailures = append(resultFailures, *failure)
		}
	}

	return &KolaFailureSummary{
		Build: KolaBuildInfo{
			Job:    jobName,
			Number: buildNumber,
			Stream: stream,
		},
		Failures: resultFailures,
	}, nil
}

// GetUpgrades extracts the "Upgraded:" section from a build's console log.
// Returns raw lines showing package upgrades in the format: "pkg old -> new"
func (c *Client) GetUpgrades(jobName string, buildNumber int) ([]string, error) {
	log, err := c.GetBuildLog(jobName, buildNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get build log: %w", err)
	}

	var upgrades []string
	lines := strings.Split(log, "\n")
	inUpgradedSection := false

	// Pattern for upgrade lines: "  <pkg> <old-version> -> <new-version>"
	// May have timestamp prefix like [2026-02-25T09:37:02.360Z]
	upgradePattern := regexp.MustCompile(`^\s*(?:\[[^\]]+\])?\s{2,}(\S+)\s+(\S+)\s+->\s+(\S+)\s*$`)

	for _, line := range lines {
		// Check for start of Upgraded section
		if strings.Contains(line, "Upgraded:") {
			inUpgradedSection = true
			continue
		}

		if inUpgradedSection {
			// Check if this line matches upgrade pattern
			if matches := upgradePattern.FindStringSubmatch(line); len(matches) > 3 {
				// Format: "pkg old -> new"
				upgrades = append(upgrades, fmt.Sprintf("%s %s -> %s", matches[1], matches[2], matches[3]))
			} else if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "[") {
				// Non-empty, non-timestamp line that doesn't match - end of section
				// But continue looking for more Upgraded sections
				inUpgradedSection = false
			}
		}
	}

	return upgrades, nil
}

// GetInstalledPackages extracts the "Installing X packages:" section from a build's console log.
// Returns raw lines showing installed packages in the format: "name-version.arch (repo)"
func (c *Client) GetInstalledPackages(jobName string, buildNumber int) ([]string, error) {
	log, err := c.GetBuildLog(jobName, buildNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get build log: %w", err)
	}

	var packages []string
	lines := strings.Split(log, "\n")
	inPackagesSection := false

	// Pattern for "Installing X packages:" header
	headerPattern := regexp.MustCompile(`Installing \d+ packages:`)
	// Pattern for package lines: "  <name-version.arch> (<repo>)"
	// May have timestamp prefix like [2026-02-25T09:32:29.156Z]
	packagePattern := regexp.MustCompile(`^\s*(?:\[[^\]]+\])?\s{2,}(\S+)\s+\(([^)]+)\)\s*$`)

	for _, line := range lines {
		// Check for start of Installing packages section
		if headerPattern.MatchString(line) {
			inPackagesSection = true
			packages = nil // Reset - use the last occurrence (actual compose, not download-only)
			continue
		}

		if inPackagesSection {
			// Check if this line matches package pattern
			if matches := packagePattern.FindStringSubmatch(line); len(matches) > 2 {
				// Format: "name-version.arch (repo)"
				packages = append(packages, fmt.Sprintf("%s (%s)", matches[1], matches[2]))
			} else if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "[") {
				// Non-empty, non-timestamp line that doesn't match - end of section
				inPackagesSection = false
			}
		}
	}

	return packages, nil
}

// parsePackageName extracts the package name from a NEVRA string, ignoring architecture.
// Input: "NetworkManager-1:1.46.0-35.el9_4.x86_64 (rhel-9.4-baseos)"
// Output: "NetworkManager"
func parsePackageName(pkg string) string {
	// Remove (repo) suffix if present
	if idx := strings.Index(pkg, " ("); idx != -1 {
		pkg = pkg[:idx]
	}

	// Remove architecture suffix (.x86_64, .noarch, .aarch64, .i686, .src)
	archSuffixes := []string{".x86_64", ".noarch", ".aarch64", ".i686", ".src", ".ppc64le", ".s390x"}
	for _, suffix := range archSuffixes {
		if strings.HasSuffix(pkg, suffix) {
			pkg = pkg[:len(pkg)-len(suffix)]
			break
		}
	}

	// Now we have: name-[epoch:]version-release
	// Split by '-' and work backwards to find where version starts
	// Version segment starts with a digit or epoch (N:)
	parts := strings.Split(pkg, "-")
	if len(parts) < 2 {
		return pkg
	}

	// Find the first part (from the end) that looks like a version
	// Version starts with digit or epoch pattern (digit followed by colon)
	versionIdx := -1
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if len(part) > 0 {
			// Check if starts with digit (version) or epoch pattern (N:)
			if part[0] >= '0' && part[0] <= '9' {
				versionIdx = i
			} else if len(part) > 2 && part[0] >= '0' && part[0] <= '9' && strings.Contains(part, ":") {
				// Epoch pattern like "1:1.46.0"
				versionIdx = i
			}
		}
	}

	if versionIdx <= 0 {
		// Couldn't find version, return as-is
		return pkg
	}

	// Package name is everything before the version
	return strings.Join(parts[:versionIdx], "-")
}

// ComputePackageDiff computes the differences between two builds' package lists.
func (c *Client) ComputePackageDiff(jobName string, build1, build2 int) (*ComputedPackageDiff, error) {
	// Fetch package lists for both builds
	pkgs1, err := c.GetInstalledPackages(jobName, build1)
	if err != nil {
		return nil, fmt.Errorf("failed to get packages for build %d: %w", build1, err)
	}

	pkgs2, err := c.GetInstalledPackages(jobName, build2)
	if err != nil {
		return nil, fmt.Errorf("failed to get packages for build %d: %w", build2, err)
	}

	// Get stream from build2
	buildInfo, err := c.GetBuildInfo(jobName, build2)
	stream := ""
	if err == nil {
		stream = extractParamFromActions(buildInfo.Actions, "STREAM")
	}

	// Build maps: package_name -> full_package_string
	map1 := make(map[string]string)
	for _, pkg := range pkgs1 {
		name := parsePackageName(pkg)
		map1[name] = pkg
	}

	map2 := make(map[string]string)
	for _, pkg := range pkgs2 {
		name := parsePackageName(pkg)
		map2[name] = pkg
	}

	// Initialize as empty slices (not nil) so JSON output shows [] instead of null
	added := []string{}
	removed := []string{}
	changed := []PackageChange{}

	// Find added and changed packages (in build2)
	for name, pkg2 := range map2 {
		if pkg1, exists := map1[name]; exists {
			// Package exists in both - check if changed
			if pkg1 != pkg2 {
				changed = append(changed, PackageChange{
					Name:   name,
					Build1: pkg1,
					Build2: pkg2,
				})
			}
		} else {
			// Package only in build2 - added
			added = append(added, pkg2)
		}
	}

	// Find removed packages (in build1 but not in build2)
	for name, pkg1 := range map1 {
		if _, exists := map2[name]; !exists {
			removed = append(removed, pkg1)
		}
	}

	// Sort for consistent output
	sort.Strings(added)
	sort.Strings(removed)
	sort.Slice(changed, func(i, j int) bool {
		return changed[i].Name < changed[j].Name
	})

	return &ComputedPackageDiff{
		Build1:  build1,
		Build2:  build2,
		Stream:  stream,
		Added:   added,
		Removed: removed,
		Changed: changed,
	}, nil
}

// GetBuildArtifacts returns the artifacts for a build.
func (c *Client) GetBuildArtifacts(jobName string, buildNumber int) ([]Artifact, error) {
	build, err := c.GetBuildInfo(jobName, buildNumber)
	if err != nil {
		return nil, err
	}
	return build.Artifacts, nil
}

// DownloadArtifact downloads an artifact from the given URL to a local file.
// Returns the number of bytes written.
func (c *Client) DownloadArtifact(artifactURL string, outputPath string) (int64, error) {
	// Create a client with longer timeout for downloads
	downloadClient := httpclient.NewWithTimeout(c.logger, httpclient.DownloadTimeout)

	resp, err := downloadClient.GetWithAuth(artifactURL, c.username, c.token)
	if err != nil {
		return 0, fmt.Errorf("failed to download artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, fmt.Errorf("artifact not found: %s", artifactURL)
	}

	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("failed to download artifact (HTTP %d)", resp.StatusCode)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	written, err := io.Copy(file, resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to write artifact: %w", err)
	}

	return written, nil
}

// GetQueue returns the current build queue.
func (c *Client) GetQueue() (*Queue, error) {
	data, err := c.get("/queue/api/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get queue: %w", err)
	}

	var queue Queue
	if err := json.Unmarshal(data, &queue); err != nil {
		return nil, fmt.Errorf("failed to parse queue: %w", err)
	}

	return &queue, nil
}

// CancelQueueItem cancels a queued build.
func (c *Client) CancelQueueItem(itemID int) error {
	endpoint := fmt.Sprintf("/queue/cancelItem?id=%d", itemID)

	resp, err := c.post(endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to cancel queue item: %w", err)
	}
	defer resp.Body.Close()

	// Jenkins returns 204 or 302 on success
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to cancel queue item (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetRunningBuilds returns a list of currently running builds.
func (c *Client) GetRunningBuilds(jobFilter string) ([]RunningBuild, error) {
	data, err := c.get("/computer/api/json", map[string]string{
		"tree": "computer[displayName,executors[currentExecutable[number,url,fullDisplayName],idle,progress]]",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get running builds: %w", err)
	}

	var resp ComputerSet
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var running []RunningBuild
	for _, node := range resp.Computer {
		for _, executor := range node.Executors {
			if executor.CurrentExecutable != nil && !executor.Idle {
				// Extract job name from URL
				jobName := extractJobName(executor.CurrentExecutable.URL)

				// Apply filter if specified
				if jobFilter != "" && !strings.Contains(strings.ToLower(jobName), strings.ToLower(jobFilter)) {
					continue
				}

				running = append(running, RunningBuild{
					JobName:     jobName,
					BuildNumber: executor.CurrentExecutable.Number,
					URL:         executor.CurrentExecutable.URL,
					Node:        node.DisplayName,
					Progress:    executor.Progress,
				})
			}
		}
	}

	return running, nil
}

// extractJobName extracts the job name from a Jenkins build URL.
func extractJobName(buildURL string) string {
	// URL format: http://jenkins/job/folder/job/name/123/
	parts := strings.Split(strings.Trim(buildURL, "/"), "/")
	var jobParts []string
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "job" && i+1 < len(parts) {
			jobParts = append(jobParts, parts[i+1])
		}
	}
	return strings.Join(jobParts, "/")
}

// GetFailedBuilds returns a list of failed builds for a job.
func (c *Client) GetFailedBuilds(jobName string, limit int, days int, stream string, fetchLimit int) ([]BuildSummary, error) {
	builds, err := c.ListBuilds(jobName, fetchLimit)
	if err != nil {
		return nil, err
	}

	var cutoff time.Time
	if days > 0 {
		cutoff = time.Now().AddDate(0, 0, -days)
	}

	var failed []BuildSummary
	for _, build := range builds {
		// Filter by time if days specified
		if days > 0 && build.Timestamp.Before(cutoff) {
			continue
		}

		// Filter by stream if specified
		if stream != "" && build.Stream != stream {
			continue
		}

		// Filter by result
		if build.Result == "FAILURE" || build.Result == "ABORTED" {
			failed = append(failed, build)
			if len(failed) >= limit {
				break
			}
		}
	}

	return failed, nil
}
