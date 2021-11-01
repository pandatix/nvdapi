package nvdapi_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/pandatix/nvdapi"
)

var (
	errStrTypeOf = reflect.TypeOf(errors.New(""))
	errFake      = errors.New("this is a fake error")
)

func checkErr(err, expErr error, t *testing.T) {
	// Check err type
	typeErr := reflect.TypeOf(err)
	typeExpErr := reflect.TypeOf(expErr)
	if typeErr != typeExpErr {
		t.Fatalf("Failed to get expected error type: got \"%s\" instead of \"%s\".", typeErr, typeExpErr)
	}

	// Check Error content is not empty
	if err != nil && err.Error() == "" {
		t.Error("Error should not have an empty content.")
	}

	// Check if the error is generated using errors.New
	if typeErr == errStrTypeOf {
		if err.Error() != expErr.Error() {
			t.Errorf("Error message differs: got \"%s\" instead of \"%s\".", err, expErr)
		}
		return
	}

	switch err.(type) {
	case *url.Error:
		castedErr := err.(*url.Error)
		castedExpErr := expErr.(*url.Error)

		if castedErr.Op != castedExpErr.Op {
			t.Errorf("Failed to get expected Op: got \"%s\" instead of \"%s\".", castedErr.Op, castedExpErr.Op)
		}

		if castedErr.URL != castedExpErr.URL {
			t.Errorf("Failed to get expected URL: got \"%s\" instead of \"%s\".", castedErr.URL, castedExpErr.URL)
		}

	case *json.SyntaxError:
		castedErr := err.(*json.SyntaxError)
		castedExpErr := expErr.(*json.SyntaxError)

		if castedErr.Offset != castedExpErr.Offset {
			t.Errorf("Failed to get expected offset: got %d instead of %d.", castedErr.Offset, castedExpErr.Offset)
		}

	case *nvdapi.ErrUnexpectedStatus:
		castedErr := err.(*nvdapi.ErrUnexpectedStatus)
		castedExpErr := expErr.(*nvdapi.ErrUnexpectedStatus)

		if !reflect.DeepEqual(castedErr.Body, castedExpErr.Body) {
			t.Errorf("Failed to get expected body: got %s instead of %s.", castedErr.Body, castedExpErr.Body)
		}
		if castedErr.StatusCode != castedExpErr.StatusCode {
			t.Errorf("Failed to get expected status code: got %d instead of %d.", castedErr.StatusCode, castedExpErr.StatusCode)
		}

	case nil:
		return

	default:
		t.Logf("\033[31mcheckErr Unsupported type: %s\033[0m\n", typeErr)
	}
}

// FakeHTTPClient is an implementation of HTTPClient that
// does nothing expect returning what you said it to.
type fakeHTTPClient struct {
	Response *http.Response
	Err      error
}

func (f fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return f.Response, f.Err
}

var _ nvdapi.HTTPClient = (*fakeHTTPClient)(nil)

func newFakeHTTPClient(body string, statusCode int, err error) nvdapi.HTTPClient {
	return &fakeHTTPClient{
		Response: &http.Response{
			StatusCode: statusCode,
			Body:       newFakeReadCloser(body),
		},
		Err: err,
	}
}

// FakeReadCloser mocks an io.ReadCloser.
type fakeReadCloser struct {
	data      []byte
	readIndex int64
}

func (f *fakeReadCloser) Read(p []byte) (n int, err error) {
	if f.readIndex >= int64(len(f.data)) {
		err = io.EOF
		return
	}

	n = copy(p, f.data[f.readIndex:])
	f.readIndex += int64(n)
	return
}

func (f *fakeReadCloser) Close() error {
	return nil
}

var _ io.ReadCloser = (*fakeReadCloser)(nil)

func newFakeReadCloser(str string) *fakeReadCloser {
	return &fakeReadCloser{
		data: []byte(str),
	}
}

func str(str string) *string {
	return &str
}

func b(b bool) *bool {
	return &b
}

func f(f float64) *float64 {
	return &f
}

func i(i int) *int {
	return &i
}
