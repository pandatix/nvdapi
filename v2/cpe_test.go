package nvdapi_test

import (
	"net/http"
	"testing"

	"github.com/pandatix/nvdapi/common"
	"github.com/pandatix/nvdapi/v2"
	"github.com/stretchr/testify/assert"
)

func TestGetCPEs(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Client           common.HTTPClient
		Params           nvdapi.GetCPEsParams
		ExpectedResponse *nvdapi.CPEResponse
		ExpectedErr      error
	}{
		"nil-client": {
			Client:           nil,
			Params:           nvdapi.GetCPEsParams{},
			ExpectedResponse: nil,
			ExpectedErr:      common.ErrNilClient,
		},
		"failing-client": {
			Client:           newFakeHTTPClient(``, 0, errFake),
			Params:           nvdapi.GetCPEsParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errFake,
		},
		"unexpected-statuscode": {
			Client:           newFakeHTTPClient(``, 0, nil),
			Params:           nvdapi.GetCPEsParams{},
			ExpectedResponse: nil,
			ExpectedErr: &common.ErrUnexpectedStatus{
				StatusCode: 0,
				Body:       []byte(``),
			},
		},
		"failing-unmarshal": {
			Client:           newFakeHTTPClient(jsonSyntaxError, http.StatusOK, nil),
			Params:           nvdapi.GetCPEsParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errJsonSyntaxError,
		},
		"valid-call": {
			Client: newFakeHTTPClient(`{"resultsPerPage":1,"startIndex":0,"totalResults":10433,"format":"NVD_CPE","version":"2.0","timestamp":"2023-01-06T07:23:58.003","products":[{"cpe":{"deprecated":false,"cpeName":"cpe:2.3:a:microsoft:access:-:*:*:*:*:*:*:*","cpeNameId":"87316812-5F2C-4286-94FE-CC98B9EAEF53","lastModified":"2011-01-12T14:35:56.427","created":"2007-08-23T21:05:57.937","titles":[{"title":"Microsoft Access","lang":"en"},{"title":"マイクロソフト Access","lang":"ja"}]}}]}`, http.StatusOK, nil),
			Params: nvdapi.GetCPEsParams{
				CPEMatchString: ptr("cpe:2.3:*:microsoft"),
				ResultsPerPage: ptr(1),
			},
			ExpectedResponse: &nvdapi.CPEResponse{
				ResultsPerPage: 1,
				StartIndex:     0,
				TotalResults:   10433,
				Format:         "NVD_CPE",
				Version:        "2.0",
				Timestamp:      "2023-01-06T07:23:58.003",
				Products: []nvdapi.CPEProduct{
					{
						CPE: nvdapi.CPE{
							Deprecated:   false,
							CPEName:      "cpe:2.3:a:microsoft:access:-:*:*:*:*:*:*:*",
							CPENameID:    "87316812-5F2C-4286-94FE-CC98B9EAEF53",
							Created:      "2007-08-23T21:05:57.937",
							LastModified: "2011-01-12T14:35:56.427",
							Titles: []nvdapi.Title{
								{
									Title: "Microsoft Access",
									Lang:  "en",
								}, {
									Title: "マイクロソフト Access",
									Lang:  "ja",
								},
							},
						},
					},
				},
			},
			ExpectedErr: nil,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			resp, err := nvdapi.GetCPEs(tt.Client, tt.Params, opts...)

			assert.Equal(tt.ExpectedResponse, resp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
