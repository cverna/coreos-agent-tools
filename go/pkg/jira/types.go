// Package jira provides a client for the Jira API.
package jira

// SearchResponse represents a Jira search API response.
type SearchResponse struct {
	StartAt    int     `json:"startAt"`
	MaxResults int     `json:"maxResults"`
	Total      int     `json:"total"`
	Issues     []Issue `json:"issues"`
}

// Issue represents a Jira issue.
type Issue struct {
	Key    string      `json:"key"`
	Fields IssueFields `json:"fields"`
}

// IssueFields represents the fields of a Jira issue.
type IssueFields struct {
	Summary      string      `json:"summary"`
	Status       Status      `json:"status"`
	DueDate      string      `json:"duedate,omitempty"`
	Resolution   *Resolution `json:"resolution,omitempty"`
	FixedInBuild string      `json:"customfield_12318450,omitempty"`
	IssueLinks   []IssueLink `json:"issuelinks,omitempty"`
}

// Status represents a Jira issue status.
type Status struct {
	Name string `json:"name"`
}

// Resolution represents a Jira issue resolution.
type Resolution struct {
	Name string `json:"name"`
}

// IssueLink represents a link between Jira issues.
type IssueLink struct {
	ID           string    `json:"id,omitempty"`
	Type         LinkType  `json:"type,omitempty"`
	InwardIssue  *IssueRef `json:"inwardIssue,omitempty"`
	OutwardIssue *IssueRef `json:"outwardIssue,omitempty"`
}

// LinkType represents a Jira issue link type.
type LinkType struct {
	Name    string `json:"name"`
	Inward  string `json:"inward,omitempty"`
	Outward string `json:"outward,omitempty"`
}

// IssueRef represents a reference to a Jira issue.
type IssueRef struct {
	Key string `json:"key"`
}

// CVEIssue represents a CVE issue from OCPBUGS.
type CVEIssue struct {
	CVEID        string `json:"cve_id"`
	Summary      string `json:"summary"`
	Key          string `json:"key"`
	Link         string `json:"link"`
	OCPVersion   string `json:"ocp_version"`
	RHELVersion  string `json:"rhel_version"`
	Status       string `json:"status"`
	DueDate      string `json:"duedate,omitempty"`
	FixedInBuild string `json:"fixed_in_build,omitempty"`
	Resolution   string `json:"resolution,omitempty"`
}

// RHELIssue represents a RHEL vulnerability issue.
type RHELIssue struct {
	Summary      string      `json:"summary"`
	Key          string      `json:"key"`
	Link         string      `json:"link"`
	RHELVersion  string      `json:"rhel_version"`
	Status       string      `json:"status"`
	FixedInBuild string      `json:"fixed_in_build,omitempty"`
	DueDate      string      `json:"duedate,omitempty"`
	Resolution   string      `json:"resolution,omitempty"`
	IssueLinks   []IssueLink `json:"issuelinks,omitempty"`
}

// CVEData represents a single CVE matching result.
type CVEData struct {
	CVEID        string `json:"cve_id"`
	Summary      string `json:"summary"`
	RHCOSLink    string `json:"rhcos_link"`
	RHELVersion  string `json:"rhel_version"`
	RHELLink     string `json:"rhel_link"`
	Status       string `json:"status"`
	FixedInBuild string `json:"fixed_in_build"`
	DueDate      string `json:"duedate"`
	Resolution   string `json:"resolution"`
}

// CVEProcessingResult represents the result of CVE processing.
type CVEProcessingResult struct {
	ClosedCVEData []CVEData `json:"closed_cve_data"`
	OpenCVEData   []CVEData `json:"open_cve_data"`
	TotalCVEs     int       `json:"total_cves"`
	TotalIssues   int       `json:"total_issues"`
	ClosedCount   int       `json:"closed_count"`
	OpenCount     int       `json:"open_count"`
	StatusFilter  string    `json:"status_filter"`
	Error         string    `json:"error,omitempty"`
}

// CreateIssueLinkRequest represents a request to create an issue link.
type CreateIssueLinkRequest struct {
	Type         LinkType `json:"type"`
	InwardIssue  IssueRef `json:"inwardIssue"`
	OutwardIssue IssueRef `json:"outwardIssue"`
}
