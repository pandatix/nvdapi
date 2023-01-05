package nvdapi

import (
	"net/http"

	"github.com/pandatix/nvdapi/common"
)

// NVDClient offers the possibility to set the API key for
// each request without having to specify it for each call.
// This client is the preferred way to use the API.
type NVDClient struct {
	apiKey string
	client common.HTTPClient
}

func (client *NVDClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Add("apiKey", client.apiKey)
	return client.client.Do(req)
}

var _ common.HTTPClient = (*NVDClient)(nil)

func NewNVDClient(client common.HTTPClient, apiKey string) (*NVDClient, error) {
	if client == nil {
		return nil, common.ErrNilClient
	}
	return &NVDClient{
		apiKey: apiKey,
		client: client,
	}, nil
}
