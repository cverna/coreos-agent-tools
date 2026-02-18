package jenkins

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

// ListBuilds returns a list of builds for a job.
func (c *Client) ListBuilds(jobName string, limit int) ([]BuildSummary, error) {
	endpoint := fmt.Sprintf("/%s/api/json", encodeJobPath(jobName))

	tree := fmt.Sprintf("builds[number,url,result,building,duration,timestamp]{0,%d}", limit)
	data, err := c.get(endpoint, map[string]string{"tree": tree})
	if err != nil {
		return nil, fmt.Errorf("failed to list builds: %w", err)
	}

	var resp struct {
		Builds []struct {
			Number    int    `json:"number"`
			URL       string `json:"url"`
			Result    string `json:"result"`
			Building  bool   `json:"building"`
			Duration  int64  `json:"duration"`
			Timestamp int64  `json:"timestamp"`
		} `json:"builds"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse builds response: %w", err)
	}

	var builds []BuildSummary
	for _, b := range resp.Builds {
		builds = append(builds, BuildSummary{
			Number:    b.Number,
			URL:       b.URL,
			Result:    b.Result,
			Building:  b.Building,
			Duration:  b.Duration,
			Timestamp: time.UnixMilli(b.Timestamp),
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

// GetBuildArtifacts returns the artifacts for a build.
func (c *Client) GetBuildArtifacts(jobName string, buildNumber int) ([]Artifact, error) {
	build, err := c.GetBuildInfo(jobName, buildNumber)
	if err != nil {
		return nil, err
	}
	return build.Artifacts, nil
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
func (c *Client) GetFailedBuilds(jobName string, limit int, days int) ([]BuildSummary, error) {
	builds, err := c.ListBuilds(jobName, limit*5) // Fetch more to filter
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
