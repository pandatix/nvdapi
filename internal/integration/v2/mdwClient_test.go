package v2_test

import (
	"io"
	"net/http"

	"github.com/pandatix/nvdapi/common"
)

type MdwClient struct {
	LastBody []byte
}

func (c *MdwClient) Do(req *http.Request) (*http.Response, error) {
	// Issue the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Copy the response's body
	c.LastBody, _ = io.ReadAll(resp.Body)
	resp.Body = &fakeReadCloser{
		data: c.LastBody,
	}

	return resp, nil
}

var _ common.HTTPClient = (*MdwClient)(nil)

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

func ptr[T any](t T) *T {
	return &t
}
