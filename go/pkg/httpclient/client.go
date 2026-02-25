// Package httpclient provides an HTTP client with rate limiting and retry logic.
package httpclient

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	// MaxRetries is the maximum number of retry attempts.
	MaxRetries = 3
	// DefaultTimeout is the default request timeout.
	DefaultTimeout = 30 * time.Second
	// DownloadTimeout is the timeout for downloading large files.
	DownloadTimeout = 10 * time.Minute
	// RetryWaitMin is the minimum wait time between retries.
	RetryWaitMin = 1 * time.Second
	// RetryWaitMax is the maximum wait time between retries.
	RetryWaitMax = 30 * time.Second
)

// Client is an HTTP client with rate limiting and retry logic.
type Client struct {
	httpClient *retryablehttp.Client
	logger     *slog.Logger
}

// slogAdapter adapts slog.Logger to retryablehttp.LeveledLogger interface.
type slogAdapter struct {
	logger *slog.Logger
}

func (s *slogAdapter) Error(msg string, keysAndValues ...interface{}) {
	s.logger.Error(msg, keysAndValues...)
}

func (s *slogAdapter) Info(msg string, keysAndValues ...interface{}) {
	s.logger.Info(msg, keysAndValues...)
}

func (s *slogAdapter) Debug(msg string, keysAndValues ...interface{}) {
	s.logger.Debug(msg, keysAndValues...)
}

func (s *slogAdapter) Warn(msg string, keysAndValues ...interface{}) {
	s.logger.Warn(msg, keysAndValues...)
}

// newRetryableClient creates a configured retryablehttp.Client.
func newRetryableClient(timeout time.Duration, logger *slog.Logger) *retryablehttp.Client {
	client := retryablehttp.NewClient()
	client.RetryMax = MaxRetries
	client.RetryWaitMin = RetryWaitMin
	client.RetryWaitMax = RetryWaitMax
	client.HTTPClient.Timeout = timeout
	client.Logger = &slogAdapter{logger: logger}
	return client
}

// New creates a new throttled HTTP client.
func New(logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		httpClient: newRetryableClient(DefaultTimeout, logger),
		logger:     logger,
	}
}

// NewWithTimeout creates a new throttled HTTP client with a custom timeout.
func NewWithTimeout(logger *slog.Logger, timeout time.Duration) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		httpClient: newRetryableClient(timeout, logger),
		logger:     logger,
	}
}

// Get performs a GET request with rate limiting and retry logic.
func (c *Client) Get(url string) (*http.Response, error) {
	return c.httpClient.Get(url)
}

// GetWithAuth performs a GET request with basic authentication.
func (c *Client) GetWithAuth(url, username, password string) (*http.Response, error) {
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	return c.httpClient.Do(req)
}

// PostWithAuth performs a POST request with basic authentication.
func (c *Client) PostWithAuth(url, username, password string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := retryablehttp.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.httpClient.Do(req)
}

// GetWithBearer performs a GET request with Bearer token authentication.
func (c *Client) GetWithBearer(url, token string) (*http.Response, error) {
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.httpClient.Do(req)
}

// PostWithBearer performs a POST request with Bearer token authentication.
func (c *Client) PostWithBearer(url, token string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := retryablehttp.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.httpClient.Do(req)
}
