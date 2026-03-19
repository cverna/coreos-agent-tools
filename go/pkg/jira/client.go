package jira

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cverna/coreos-agent-tools/go/pkg/httpclient"
)

const (
	// DefaultBaseURL is the default Jira base URL.
	DefaultBaseURL = "https://redhat.atlassian.net"
	// CacheTTL is the cache time-to-live in seconds.
	CacheTTL = 300
)

// OCP to RHEL version mapping.
var OCPToRHEL = map[string]string{
	"4.12": "8.6",
	"4.13": "9.2",
	"4.14": "9.2",
	"4.15": "9.2",
	"4.16": "9.4",
	"4.17": "9.4",
	"4.18": "9.4",
	"4.19": "9.6",
	"4.20": "9.6",
	"4.21": "9.6",
	"4.22": "9.8",
}

// cacheEntry represents a cached API response.
type cacheEntry struct {
	data      *SearchResponse
	timestamp time.Time
}

// Client is a Jira API client.
type Client struct {
	baseURL    string
	email      string
	token      string
	httpClient *httpclient.Client
	logger     *slog.Logger
	cache      map[string]cacheEntry
	cacheMu    sync.RWMutex
}

// NewClient creates a new Jira client.
func NewClient(baseURL, email, token string, logger *slog.Logger) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		email:      email,
		token:      token,
		httpClient: httpclient.New(logger),
		logger:     logger,
		cache:      make(map[string]cacheEntry),
	}
}

// Query performs a JQL query against Jira with pagination support.
func (c *Client) Query(jql, fields string, maxResults int) (*SearchResponse, error) {
	cacheKey := fmt.Sprintf("%s:%s:%d", jql, fields, maxResults)

	// Check cache
	c.cacheMu.RLock()
	if entry, ok := c.cache[cacheKey]; ok {
		if time.Since(entry.timestamp) < CacheTTL*time.Second {
			c.logger.Debug("Using cached data", "jql", jql[:min(50, len(jql))])
			c.cacheMu.RUnlock()
			return entry.data, nil
		}
	}
	c.cacheMu.RUnlock()

	var allIssues []Issue
	var nextPageToken string
	pageSize := min(100, maxResults) // API v3 max is 100 per page

	for {
		// Build request URL for API v3
		u, err := url.Parse(c.baseURL + "/rest/api/3/search/jql")
		if err != nil {
			return nil, err
		}

		q := u.Query()
		q.Set("jql", jql)
		q.Set("fields", fields)
		q.Set("maxResults", fmt.Sprintf("%d", pageSize))
		if nextPageToken != "" {
			q.Set("nextPageToken", nextPageToken)
		}
		u.RawQuery = q.Encode()

		resp, err := c.httpClient.GetWithBasicAuth(u.String(), c.email, c.token)
		if err != nil {
			return nil, fmt.Errorf("failed to query Jira: %w", err)
		}

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("Jira query failed (HTTP %d): %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		var pageResult SearchResponse
		if err := json.Unmarshal(body, &pageResult); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		allIssues = append(allIssues, pageResult.Issues...)
		c.logger.Debug("Fetched issues", "count", len(allIssues))

		// Check if we've reached max_results or last page
		if pageResult.IsLast || len(allIssues) >= maxResults {
			break
		}

		nextPageToken = pageResult.NextPageToken
		if nextPageToken == "" {
			break
		}
	}

	// Build result with all issues (limited to maxResults)
	if len(allIssues) > maxResults {
		allIssues = allIssues[:maxResults]
	}
	result := &SearchResponse{
		Issues: allIssues,
		IsLast: true,
	}

	// Cache the result
	c.cacheMu.Lock()
	c.cache[cacheKey] = cacheEntry{
		data:      result,
		timestamp: time.Now(),
	}
	c.cacheMu.Unlock()

	return result, nil
}

// CreateIssueLink creates a link between two Jira issues.
func (c *Client) CreateIssueLink(ocpbugKey, rhelKey string) error {
	linkURL := c.baseURL + "/rest/api/3/issueLink"

	payload := CreateIssueLinkRequest{
		Type:         LinkType{Name: "Blocks"},
		InwardIssue:  IssueRef{Key: rhelKey},
		OutwardIssue: IssueRef{Key: ocpbugKey},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.PostWithBasicAuth(linkURL, c.email, c.token, bytes.NewReader(body), "application/json")
	if err != nil {
		return fmt.Errorf("failed to create issue link: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		c.logger.Info("Issue link created", "ocpbug", ocpbugKey, "rhel", rhelKey)
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("failed to create issue link (HTTP %d): %s", resp.StatusCode, string(respBody))
}

// CVEProcessor handles CVE data processing.
type CVEProcessor struct {
	client *Client
	logger *slog.Logger
}

// NewCVEProcessor creates a new CVE processor.
func NewCVEProcessor(client *Client, logger *slog.Logger) *CVEProcessor {
	if logger == nil {
		logger = slog.Default()
	}
	return &CVEProcessor{
		client: client,
		logger: logger,
	}
}

var (
	cvePattern     = regexp.MustCompile(`(?i)(CVE-\d{4}-\d+)`)
	ocpVerPattern  = regexp.MustCompile(`\[openshift-(\d+\.\d+)(?:\.z)?\]`)
	rhelVerPattern = regexp.MustCompile(`\[rhel-(\d+\.\d+)[^\]]*\]`)
)

// ExtractCVEID extracts the CVE ID from a summary string.
func (p *CVEProcessor) ExtractCVEID(summary string) string {
	match := cvePattern.FindStringSubmatch(summary)
	if len(match) > 1 {
		return strings.ToUpper(match[1])
	}
	return ""
}

// ExtractOCPVersion extracts the OCP version from a summary string.
func (p *CVEProcessor) ExtractOCPVersion(summary string) string {
	match := ocpVerPattern.FindStringSubmatch(summary)
	if len(match) > 1 {
		return match[1]
	}
	return "Unknown"
}

// ExtractRHELVersion extracts the RHEL version from a summary string.
func (p *CVEProcessor) ExtractRHELVersion(summary string) string {
	match := rhelVerPattern.FindStringSubmatch(summary)
	if len(match) > 1 {
		return match[1]
	}
	return "Unknown"
}

// GetRHELVersion returns the RHEL version for an OCP version.
func GetRHELVersion(ocpVersion string) string {
	if rhel, ok := OCPToRHEL[ocpVersion]; ok {
		return rhel
	}
	return "Unknown"
}

// GetRHCOSIssues retrieves RHCOS CVE issues from Jira.
func (p *CVEProcessor) GetRHCOSIssues() ([]CVEIssue, error) {
	jql := `project = OCPBUGS AND component = RHCOS AND summary ~ "CVE-* rhcos" AND status not in (Closed, Verified, "Release Pending", ON_QA)`

	data, err := p.client.Query(jql, "summary,key,status,duedate", 1000)
	if err != nil {
		return nil, err
	}

	if data == nil || len(data.Issues) == 0 {
		p.logger.Warn("No RHCOS issues found")
		return nil, nil
	}

	var issues []CVEIssue
	for _, issue := range data.Issues {
		cveID := p.ExtractCVEID(issue.Fields.Summary)
		if cveID == "" {
			p.logger.Debug("No CVE ID found in summary", "summary", issue.Fields.Summary)
			continue
		}

		ocpVer := p.ExtractOCPVersion(issue.Fields.Summary)
		rhelVer := GetRHELVersion(ocpVer)

		issues = append(issues, CVEIssue{
			CVEID:       cveID,
			Summary:     issue.Fields.Summary,
			Key:         issue.Key,
			Link:        fmt.Sprintf("%s/browse/%s", p.client.baseURL, issue.Key),
			OCPVersion:  ocpVer,
			RHELVersion: rhelVer,
			Status:      issue.Fields.Status.Name,
			DueDate:     issue.Fields.DueDate,
		})
	}

	p.logger.Info("Found RHCOS CVE issues", "count", len(issues))
	return issues, nil
}

// GetRHELIssuesBatch retrieves RHEL issues for multiple CVE IDs.
func (p *CVEProcessor) GetRHELIssuesBatch(cveIDs []string) (map[string][]RHELIssue, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	// Build JQL query for all CVEs
	var conditions []string
	for _, cveID := range cveIDs {
		conditions = append(conditions, fmt.Sprintf(`summary ~ "%s"`, cveID))
	}
	jql := fmt.Sprintf("project = RHEL AND issuetype=Vulnerability AND (%s)", strings.Join(conditions, " OR "))

	data, err := p.client.Query(jql, "summary,key,status,duedate,customfield_10578,resolution,issuelinks", 2000)
	if err != nil {
		return nil, err
	}

	if data == nil || len(data.Issues) == 0 {
		return nil, nil
	}

	// Group RHEL issues by CVE
	result := make(map[string][]RHELIssue)

	for _, issue := range data.Issues {
		summary := issue.Fields.Summary

		// Find which CVE this RHEL issue belongs to
		for _, cveID := range cveIDs {
			if strings.Contains(strings.ToLower(summary), strings.ToLower(cveID)) {
				status := issue.Fields.Status.Name
				fixedInBuild := ""
				if strings.ToLower(status) == "closed" {
					fixedInBuild = strings.TrimSpace(issue.Fields.FixedInBuild)
					if fixedInBuild == "" {
						fixedInBuild = "Not specified"
					}
				}

				resolution := "Unresolved"
				if issue.Fields.Resolution != nil {
					resolution = issue.Fields.Resolution.Name
				}

				// Exclude obsolete issues
				if strings.ToLower(resolution) != "obsolete" {
					result[cveID] = append(result[cveID], RHELIssue{
						Summary:      summary,
						Key:          issue.Key,
						Link:         fmt.Sprintf("%s/browse/%s", p.client.baseURL, issue.Key),
						RHELVersion:  p.ExtractRHELVersion(summary),
						Status:       status,
						FixedInBuild: fixedInBuild,
						DueDate:      issue.Fields.DueDate,
						Resolution:   resolution,
						IssueLinks:   issue.Fields.IssueLinks,
					})
				}
				break
			}
		}
	}

	return result, nil
}

// IssueLinkExists checks if a link already exists between two issues.
func IssueLinkExists(links []IssueLink, key string) bool {
	for _, link := range links {
		if link.OutwardIssue != nil && link.OutwardIssue.Key == key {
			return true
		}
		if link.InwardIssue != nil && link.InwardIssue.Key == key {
			return true
		}
	}
	return false
}

// MatchIssues matches RHCOS issues with RHEL issues.
func (p *CVEProcessor) MatchIssues(cveIssues []CVEIssue, rhelIssuesByCVE map[string][]RHELIssue, createLinks bool) *CVEProcessingResult {
	var closedData []CVEData
	var openData []CVEData

	// Group CVE issues by CVE ID
	cveIssuesByID := make(map[string][]CVEIssue)
	for _, issue := range cveIssues {
		cveIssuesByID[issue.CVEID] = append(cveIssuesByID[issue.CVEID], issue)
	}

	for cveID, rhcosIssues := range cveIssuesByID {
		rhelIssues := rhelIssuesByCVE[cveID]

		for _, rhcosIssue := range rhcosIssues {
			// Find matching RHEL issues for the same RHEL version
			var matchingRHEL []RHELIssue
			for _, rhel := range rhelIssues {
				if rhel.RHELVersion == rhcosIssue.RHELVersion && rhel.RHELVersion != "Unknown" {
					matchingRHEL = append(matchingRHEL, rhel)
				}
			}

			if len(matchingRHEL) > 0 {
				// Check if ALL matching RHEL issues are closed
				allClosed := true
				for _, rhel := range matchingRHEL {
					if rhel.Status != "Closed" {
						allClosed = false
						break
					}
				}

				// Create issue links if requested
				if createLinks {
					for _, rhel := range matchingRHEL {
						if !IssueLinkExists(rhel.IssueLinks, rhcosIssue.Key) {
							p.logger.Info("Creating issue link", "rhcos", rhcosIssue.Key, "rhel", rhel.Key)
							if err := p.client.CreateIssueLink(rhcosIssue.Key, rhel.Key); err != nil {
								p.logger.Error("Failed to create issue link", "error", err)
							}
						} else {
							p.logger.Debug("Issue link already exists", "rhcos", rhcosIssue.Key, "rhel", rhel.Key)
						}
					}
				}

				// Use first matching RHEL issue for display
				rhelIssue := matchingRHEL[0]

				// Build status summary
				statusSummary := "Closed"
				if !allClosed {
					statusSummary = "Open"
				}
				if len(matchingRHEL) > 1 {
					var statuses []string
					for _, r := range matchingRHEL {
						statuses = append(statuses, r.Status)
					}
					statusSummary = fmt.Sprintf("%s (%d issues: %s)", statusSummary, len(matchingRHEL), strings.Join(statuses, ", "))
				}

				// Build resolution summary
				resolutions := make(map[string]bool)
				for _, r := range matchingRHEL {
					resolutions[r.Resolution] = true
				}
				var uniqueResolutions []string
				for r := range resolutions {
					uniqueResolutions = append(uniqueResolutions, r)
				}
				resolutionSummary := uniqueResolutions[0]
				if len(uniqueResolutions) > 1 {
					resolutionSummary = fmt.Sprintf("Mixed (%d issues: %s)", len(matchingRHEL), strings.Join(uniqueResolutions, ", "))
				}

				data := CVEData{
					CVEID:        cveID,
					Summary:      rhcosIssue.Summary,
					RHCOSLink:    rhcosIssue.Link,
					RHELVersion:  rhcosIssue.RHELVersion,
					RHELLink:     rhelIssue.Link,
					Status:       statusSummary,
					FixedInBuild: orDefault(rhelIssue.FixedInBuild, "N/A"),
					DueDate:      orDefault(rhcosIssue.DueDate, "N/A"),
					Resolution:   resolutionSummary,
				}

				if allClosed {
					closedData = append(closedData, data)
				} else {
					openData = append(openData, data)
				}
			} else {
				// No matching RHEL issues found
				data := CVEData{
					CVEID:        cveID,
					Summary:      rhcosIssue.Summary,
					RHCOSLink:    rhcosIssue.Link,
					RHELVersion:  rhcosIssue.RHELVersion,
					RHELLink:     "No matching RHEL issues found",
					Status:       "N/A",
					FixedInBuild: "N/A",
					DueDate:      "N/A",
					Resolution:   "N/A",
				}
				openData = append(openData, data)
			}
		}
	}

	return &CVEProcessingResult{
		ClosedCVEData: closedData,
		OpenCVEData:   openData,
		TotalCVEs:     len(cveIssuesByID),
		TotalIssues:   len(cveIssues),
		ClosedCount:   len(closedData),
		OpenCount:     len(openData),
	}
}

// ProcessCVEs processes RHCOS CVEs and matches them with RHEL issues.
func (p *CVEProcessor) ProcessCVEs(statusFilter string, createLinks bool) (*CVEProcessingResult, error) {
	p.logger.Info("Starting RHCOS CVE processing")

	// Get RHCOS issues
	cveIssues, err := p.GetRHCOSIssues()
	if err != nil {
		return nil, fmt.Errorf("failed to get RHCOS issues: %w", err)
	}

	if len(cveIssues) == 0 {
		return &CVEProcessingResult{
			Error: "No RHCOS CVE issues found",
		}, nil
	}

	// Extract unique CVE IDs
	cveIDSet := make(map[string]bool)
	for _, issue := range cveIssues {
		cveIDSet[issue.CVEID] = true
	}
	var cveIDs []string
	for id := range cveIDSet {
		cveIDs = append(cveIDs, id)
	}
	p.logger.Info("Processing unique CVEs", "count", len(cveIDs))

	// Get RHEL issues for all CVEs
	rhelIssuesByCVE, err := p.GetRHELIssuesBatch(cveIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get RHEL issues: %w", err)
	}
	p.logger.Info("Found RHEL issues for CVEs", "count", len(rhelIssuesByCVE))

	// Match and categorize issues
	result := p.MatchIssues(cveIssues, rhelIssuesByCVE, createLinks)
	result.StatusFilter = statusFilter

	// Apply status filter
	switch statusFilter {
	case "closed":
		result.OpenCVEData = nil
		result.OpenCount = 0
	case "open":
		result.ClosedCVEData = nil
		result.ClosedCount = 0
	}

	p.logger.Info("Processing complete",
		"closed", result.ClosedCount,
		"open", result.OpenCount,
		"filter", statusFilter,
	)

	return result, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
