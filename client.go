package nvdapi

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrNilClient is an error returned when a given HTTPClient is nil.
	ErrNilClient = errors.New("given client is nil")
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
