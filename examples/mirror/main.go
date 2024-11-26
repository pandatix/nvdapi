package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/pandatix/nvdapi/common"
	"github.com/pandatix/nvdapi/v2"
)

const (
	cveid = "CVE-2021-28378"
)

func main() {
	// Create a mirror client to redirect request elsewhere
	mc, err := NewMirrorClient(&http.Client{}, "https://nvd.mirror.lan")
	if err != nil {
		log.Fatal(err)
	}

	// Create a NVD client
	cli, _ := nvdapi.NewNVDClient(mc, "<API_KEY>")

	// Make API calls to the mirror (or a proxy)
	res, err := nvdapi.GetCVEs(cli, nvdapi.GetCVEsParams{
		CVEID: ptr(cveid),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[%s]\n%s\n", cveid, res.Vulnerabilities[0].CVE.Descriptions[0].Value)
}

// NewMirrorClient creates a *MirrorClient.
func NewMirrorClient(sub common.HTTPClient, baseUrl string) (*MirrorClient, error) {
	if _, err := url.Parse(baseUrl); err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, common.ErrNilClient
	}
	return &MirrorClient{
		sub:     sub,
		baseUrl: baseUrl,
	}, nil
}

// MirrorClient is a common.HTTPClient implementation to redirect
// requests to a mirror.
type MirrorClient struct {
	sub     common.HTTPClient
	baseUrl string
}

var _ common.HTTPClient = (*MirrorClient)(nil)

func (cli *MirrorClient) Do(req *http.Request) (*http.Response, error) {
	// Redirect to a custom base URL, don't forget to happend
	// the path and the query
	nurl, err := url.Parse(fmt.Sprintf("%s%s?%s", cli.baseUrl, req.URL.Path, req.URL.RawQuery))
	if err != nil {
		return nil, err
	}
	req.URL = nurl

	// Pass to execute by underlying common.HTTPClient.
	return cli.sub.Do(req)
}

func ptr[T any](t T) *T {
	return &t
}
