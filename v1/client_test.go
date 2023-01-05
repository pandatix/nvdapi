package nvdapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/pandatix/nvdapi/common"
)

var (
	jsonSyntaxError = "{[}]"

	errFake            = errors.New("this is a fake error")
	errJsonSyntaxError = json.Unmarshal([]byte(jsonSyntaxError), &struct{}{})

	opts = []common.Option{
		common.WithContext(context.Background()),
	}
)

// FakeHTTPClient is an implementation of HTTPClient that
// does nothing expect returning what you said it to.
type fakeHTTPClient struct {
	Response *http.Response
	Err      error
}

func (f fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return f.Response, f.Err
}

var _ common.HTTPClient = (*fakeHTTPClient)(nil)

func newFakeHTTPClient(body string, statusCode int, err error) common.HTTPClient {
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

func ptr[T any](t T) *T {
	return &t
}
