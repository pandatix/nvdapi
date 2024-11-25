package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gorilla/schema"
)

var (
	// ErrNilClient is an error returned when a given HTTPClient is nil.
	ErrNilClient = errors.New("given client is nil")
	// BaseURL is the base path for all requests; redirect away from NIST if needed
	BaseURL = "https://services.nvd.nist.gov/rest/json/"
)

// ErrUnexpectedStatus is an error meaning the API call returned a response
// with an unexpected status. It may occurs when the server is down or the
// parameters/body is invalid.
type ErrUnexpectedStatus struct {
	Body       []byte
	StatusCode int
}

func (e ErrUnexpectedStatus) Error() string {
	return fmt.Sprintf("unexpected status %d with body %s", e.StatusCode, e.Body)
}

var _ error = (*ErrUnexpectedStatus)(nil)

// HTTPClient defines what is the basic implementation of an HTTP client.
// Used for interconnectability with various implementations of an HTTP client,
// and for mocking purposes.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

var _ HTTPClient = (*http.Client)(nil)

type Option interface {
	apply(*options)
}

type options struct {
	Ctx    context.Context
	APIKey *string
}

type ctxOption struct {
	ctx context.Context
}

func (opt ctxOption) apply(opts *options) {
	opts.Ctx = opt.ctx
}

type apiKeyOption string

func (opt apiKeyOption) apply(opts *options) {
	str := (string)(opt)
	opts.APIKey = &str
}

// WithContext defines the context to use when executing
// the HTTP request.
// Default is context.Background.
func WithContext(ctx context.Context) Option {
	return &ctxOption{
		ctx: ctx,
	}
}

// WithAPIKey defines the API keyto use when executing the
// HTTP request.
// Default won't set the HTTP header in the request.
func WithAPIKey(apiKey string) Option {
	opt := apiKeyOption(apiKey)
	return &opt
}

// GetEndp is an internal function, working as a helper.
func GetEndp(client HTTPClient, endp string, params, dst any, opts ...Option) error {
	if client == nil {
		return ErrNilClient
	}

	// Build the options
	reqopts := &options{
		Ctx: context.Background(),
	}
	for _, opt := range opts {
		opt.apply(reqopts)
	}

	// Build the request
	req, _ := http.NewRequestWithContext(reqopts.Ctx, http.MethodGet, BaseURL+endp, nil)
	if reqopts.APIKey != nil {
		req.Header.Add("apiKey", *reqopts.APIKey)
	}

	// Set params if any
	if params != nil {
		form := url.Values{}
		_ = schema.NewEncoder().Encode(params, form)
		req.URL.RawQuery = form.Encode()
	}

	// Issue the request
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	// Check status code
	if res.StatusCode != http.StatusOK {
		return &ErrUnexpectedStatus{
			Body:       body,
			StatusCode: res.StatusCode,
		}
	}

	// Unmarshal response
	if err := json.Unmarshal(body, dst); err != nil {
		return err
	}

	return nil
}
