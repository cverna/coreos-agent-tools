// Package jenkins provides a client for the Jenkins API.
package jenkins

import "time"

// Job represents a Jenkins job.
type Job struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Color       string `json:"color,omitempty"`
	Class       string `json:"_class,omitempty"`
	Buildable   bool   `json:"buildable,omitempty"`
	Description string `json:"description,omitempty"`
	FullName    string `json:"fullName,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	InQueue     bool   `json:"inQueue,omitempty"`
}

// JobInfo represents detailed job information.
type JobInfo struct {
	Name                 string         `json:"name"`
	URL                  string         `json:"url"`
	Color                string         `json:"color,omitempty"`
	Class                string         `json:"_class,omitempty"`
	Buildable            bool           `json:"buildable,omitempty"`
	Description          string         `json:"description,omitempty"`
	FullName             string         `json:"fullName,omitempty"`
	DisplayName          string         `json:"displayName,omitempty"`
	InQueue              bool           `json:"inQueue,omitempty"`
	Builds               []BuildRef     `json:"builds,omitempty"`
	LastBuild            *BuildRef      `json:"lastBuild,omitempty"`
	LastSuccessfulBuild  *BuildRef      `json:"lastSuccessfulBuild,omitempty"`
	LastFailedBuild      *BuildRef      `json:"lastFailedBuild,omitempty"`
	LastStableBuild      *BuildRef      `json:"lastStableBuild,omitempty"`
	LastUnstableBuild    *BuildRef      `json:"lastUnstableBuild,omitempty"`
	LastCompletedBuild   *BuildRef      `json:"lastCompletedBuild,omitempty"`
	NextBuildNumber      int            `json:"nextBuildNumber,omitempty"`
	HealthReport         []HealthReport `json:"healthReport,omitempty"`
	Property             []JobProperty  `json:"property,omitempty"`
	Jobs                 []Job          `json:"jobs,omitempty"` // For folders
	Actions              []Action       `json:"actions,omitempty"`
	ParameterDefinitions []ParameterDef `json:"parameterDefinitions,omitempty"`
}

// BuildRef is a reference to a build.
type BuildRef struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
}

// HealthReport represents a job's health status.
type HealthReport struct {
	Description   string `json:"description"`
	IconClassName string `json:"iconClassName,omitempty"`
	IconURL       string `json:"iconUrl,omitempty"`
	Score         int    `json:"score"`
}

// JobProperty represents job configuration properties.
type JobProperty struct {
	Class                string         `json:"_class,omitempty"`
	ParameterDefinitions []ParameterDef `json:"parameterDefinitions,omitempty"`
}

// ParameterDef represents a build parameter definition.
type ParameterDef struct {
	Class                 string      `json:"_class,omitempty"`
	Name                  string      `json:"name"`
	Description           string      `json:"description,omitempty"`
	Type                  string      `json:"type,omitempty"`
	DefaultParameterValue *ParamValue `json:"defaultParameterValue,omitempty"`
	Choices               []string    `json:"choices,omitempty"`
}

// ParamValue represents a parameter value.
type ParamValue struct {
	Class string      `json:"_class,omitempty"`
	Name  string      `json:"name,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// Action represents a Jenkins action.
type Action struct {
	Class                string         `json:"_class,omitempty"`
	ParameterDefinitions []ParameterDef `json:"parameterDefinitions,omitempty"`
}

// Build represents a Jenkins build.
type Build struct {
	Number            int           `json:"number"`
	URL               string        `json:"url"`
	Result            string        `json:"result,omitempty"`
	Building          bool          `json:"building"`
	Duration          int64         `json:"duration"`
	EstimatedDuration int64         `json:"estimatedDuration,omitempty"`
	Timestamp         int64         `json:"timestamp"`
	DisplayName       string        `json:"displayName,omitempty"`
	FullDisplayName   string        `json:"fullDisplayName,omitempty"`
	Description       string        `json:"description,omitempty"`
	ID                string        `json:"id,omitempty"`
	QueueID           int           `json:"queueId,omitempty"`
	Actions           []BuildAction `json:"actions,omitempty"`
	Artifacts         []Artifact    `json:"artifacts,omitempty"`
	ChangeSet         *ChangeSet    `json:"changeSet,omitempty"`
	Executor          *Executor     `json:"executor,omitempty"`
}

// BuildAction represents an action associated with a build.
type BuildAction struct {
	Class      string       `json:"_class,omitempty"`
	Parameters []ParamValue `json:"parameters,omitempty"`
	Causes     []Cause      `json:"causes,omitempty"`
}

// Cause represents the cause of a build.
type Cause struct {
	Class            string `json:"_class,omitempty"`
	ShortDescription string `json:"shortDescription,omitempty"`
	UserID           string `json:"userId,omitempty"`
	UserName         string `json:"userName,omitempty"`
}

// Artifact represents a build artifact.
type Artifact struct {
	DisplayPath  string `json:"displayPath,omitempty"`
	FileName     string `json:"fileName"`
	RelativePath string `json:"relativePath"`
}

// ChangeSet represents changes in a build.
type ChangeSet struct {
	Class string       `json:"_class,omitempty"`
	Items []ChangeItem `json:"items,omitempty"`
	Kind  string       `json:"kind,omitempty"`
}

// ChangeItem represents a single change.
type ChangeItem struct {
	AffectedPaths []string `json:"affectedPaths,omitempty"`
	Author        Author   `json:"author,omitempty"`
	CommitID      string   `json:"commitId,omitempty"`
	Timestamp     int64    `json:"timestamp,omitempty"`
	Comment       string   `json:"comment,omitempty"`
	Message       string   `json:"msg,omitempty"`
}

// Author represents a commit author.
type Author struct {
	FullName    string `json:"fullName,omitempty"`
	AbsoluteURL string `json:"absoluteUrl,omitempty"`
}

// Executor represents a Jenkins executor.
type Executor struct {
	Class string `json:"_class,omitempty"`
}

// QueueItem represents an item in the Jenkins build queue.
type QueueItem struct {
	ID                 int           `json:"id"`
	Blocked            bool          `json:"blocked"`
	Buildable          bool          `json:"buildable"`
	InQueueSince       int64         `json:"inQueueSince"`
	Params             string        `json:"params,omitempty"`
	Stuck              bool          `json:"stuck"`
	URL                string        `json:"url,omitempty"`
	Why                string        `json:"why,omitempty"`
	Task               QueueTask     `json:"task,omitempty"`
	Actions            []QueueAction `json:"actions,omitempty"`
	Executable         *BuildRef     `json:"executable,omitempty"`
	BuildableStartTime int64         `json:"buildableStartMilliseconds,omitempty"`
}

// QueueTask represents the task associated with a queue item.
type QueueTask struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Color string `json:"color,omitempty"`
}

// QueueAction represents an action in the queue.
type QueueAction struct {
	Class      string       `json:"_class,omitempty"`
	Parameters []ParamValue `json:"parameters,omitempty"`
	Causes     []Cause      `json:"causes,omitempty"`
}

// Queue represents the Jenkins build queue.
type Queue struct {
	Items []QueueItem `json:"items"`
}

// Node represents a Jenkins node (agent).
type Node struct {
	Class               string                 `json:"_class,omitempty"`
	DisplayName         string                 `json:"displayName"`
	Description         string                 `json:"description,omitempty"`
	Idle                bool                   `json:"idle"`
	JNLPAgent           bool                   `json:"jnlpAgent"`
	LaunchSupported     bool                   `json:"launchSupported"`
	ManualLaunchAllowed bool                   `json:"manualLaunchAllowed"`
	NumExecutors        int                    `json:"numExecutors"`
	Offline             bool                   `json:"offline"`
	OfflineCause        interface{}            `json:"offlineCause,omitempty"`
	OfflineCauseReason  string                 `json:"offlineCauseReason,omitempty"`
	TemporarilyOffline  bool                   `json:"temporarilyOffline"`
	Executors           []ExecutorInfo         `json:"executors,omitempty"`
	AssignedLabels      []Label                `json:"assignedLabels,omitempty"`
	MonitorData         map[string]interface{} `json:"monitorData,omitempty"`
}

// ExecutorInfo represents an executor on a node.
type ExecutorInfo struct {
	Class             string          `json:"_class,omitempty"`
	CurrentExecutable *ExecutableInfo `json:"currentExecutable,omitempty"`
	Idle              bool            `json:"idle"`
	LikelyStuck       bool            `json:"likelyStuck"`
	Number            int             `json:"number"`
	Progress          int             `json:"progress"`
}

// ExecutableInfo represents a running build on an executor.
type ExecutableInfo struct {
	Class           string `json:"_class,omitempty"`
	Number          int    `json:"number"`
	URL             string `json:"url"`
	FullDisplayName string `json:"fullDisplayName,omitempty"`
}

// Label represents a node label.
type Label struct {
	Name string `json:"name"`
}

// ComputerSet represents the collection of nodes.
type ComputerSet struct {
	Class          string `json:"_class,omitempty"`
	BusyExecutors  int    `json:"busyExecutors"`
	TotalExecutors int    `json:"totalExecutors"`
	Computer       []Node `json:"computer"`
}

// JobsResponse represents a list of jobs from Jenkins.
type JobsResponse struct {
	Jobs []Job `json:"jobs"`
}

// BuildSummary represents a simplified build for listing.
type BuildSummary struct {
	Number      int       `json:"number"`
	URL         string    `json:"url"`
	Result      string    `json:"result,omitempty"`
	Building    bool      `json:"building"`
	Duration    int64     `json:"duration"`
	Timestamp   time.Time `json:"timestamp"`
	Stream      string    `json:"stream,omitempty"`
	Description string    `json:"description,omitempty"`
}

// RunningBuild represents a currently running build.
type RunningBuild struct {
	JobName     string    `json:"job_name"`
	BuildNumber int       `json:"build_number"`
	URL         string    `json:"url"`
	Node        string    `json:"node"`
	Progress    int       `json:"progress"`
	StartTime   time.Time `json:"start_time,omitempty"`
}

// KolaFailureSummary represents a summary of kola test failures for a build.
type KolaFailureSummary struct {
	Build    KolaBuildInfo    `json:"build"`
	Failures []KolaFailedTest `json:"failures"`
}

// KolaBuildInfo contains build identification info.
type KolaBuildInfo struct {
	Job    string `json:"job"`
	Number int    `json:"number"`
	Stream string `json:"stream,omitempty"`
}

// KolaFailedTest represents a failed kola test with deduplication.
type KolaFailedTest struct {
	Name            string  `json:"name"`
	Error           string  `json:"error"`
	DurationSeconds float64 `json:"duration_seconds"`
	Attempts        int     `json:"attempts"`
	RerunFailed     bool    `json:"rerun_failed"`
}

// PackageDiffResult contains package information from builds for comparison.
type PackageDiffResult struct {
	Build1         int      `json:"build1"`
	Build2         int      `json:"build2,omitempty"`
	Stream         string   `json:"stream,omitempty"`
	Mode           string   `json:"mode"`                      // "upgrades" or "packages"
	Upgrades       []string `json:"upgrades,omitempty"`        // single-build: raw lines from "Upgraded:" section
	Build1Packages []string `json:"build1_packages,omitempty"` // two-build: full package list
	Build2Packages []string `json:"build2_packages,omitempty"` // two-build: full package list
}
