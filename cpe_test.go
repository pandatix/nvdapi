package nvdapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pandatix/nvdapi"
	"github.com/stretchr/testify/assert"
)

func TestGetCPEs(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Client           nvdapi.HTTPClient
		Params           nvdapi.GetCPEParams
		ExpectedResponse *nvdapi.CPEResponse
		ExpectedErr      error
	}{
		"nil-client": {
			Client:           nil,
			Params:           nvdapi.GetCPEParams{},
			ExpectedResponse: nil,
			ExpectedErr:      nvdapi.ErrNilClient,
		},
		"failing-client": {
			Client:           newFakeHTTPClient(``, 0, errFake),
			Params:           nvdapi.GetCPEParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errFake,
		},
		"unexpected-statuscode": {
			Client:           newFakeHTTPClient(``, 0, nil),
			Params:           nvdapi.GetCPEParams{},
			ExpectedResponse: nil,
			ExpectedErr: &nvdapi.ErrUnexpectedStatus{
				StatusCode: 0,
				Body:       []byte(``),
			},
		},
		"failing-unmarshal": {
			Client:           newFakeHTTPClient(`{[}]`, http.StatusOK, nil),
			Params:           nvdapi.GetCPEParams{},
			ExpectedResponse: nil,
			ExpectedErr: &json.SyntaxError{
				Offset: 2,
			},
		},
		"valid-call": {
			Client: newFakeHTTPClient(`{"resultsPerPage":1,"startIndex":0,"totalResults":5644,"result":{"dataType":"CPE","feedVersion":"1.0","cpeCount":5644,"feedTimestamp":"2021-11-01T17:24Z","cpes":[{"deprecated":false,"cpe23Uri":"cpe:2.3:a:microsoft:antispyware:-:*:*:*:*:*:*:*","lastModifiedDate":"2007-09-14T17:36Z","titles":[{"title":"Microsoft antispyware","lang":"en_US"}],"refs":[],"deprecatedBy":[],"vulnerabilities":[]}]}}`, http.StatusOK, nil),
			Params: nvdapi.GetCPEParams{
				CPEMatchString: str("cpe:2.3:*:microsoft"),
				ResultsPerPage: i(1),
			},
			ExpectedResponse: &nvdapi.CPEResponse{
				ResultsPerPage: 1,
				StartIndex:     0,
				TotalResults:   5644,
				Result: nvdapi.CPEResult{
					DataType:      "CPE",
					FeedVersion:   "1.0",
					CPECount:      5644,
					FeedTimestamp: str("2021-11-01T17:24Z"),
					CPEs: []nvdapi.CPEName{
						{
							Deprecated:       b(false),
							CPE23URI:         "cpe:2.3:a:microsoft:antispyware:-:*:*:*:*:*:*:*",
							LastModifiedDate: "2007-09-14T17:36Z",
							Titles: &[]nvdapi.Title{
								{
									Title: "Microsoft antispyware",
									Lang:  "en_US",
								},
							},
							Refs:            &[]nvdapi.CPEReference{},
							DeprecatedBy:    &[]string{},
							Vulnerabilities: &[]string{},
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

			resp, err := nvdapi.GetCPEs(tt.Client, tt.Params)

			assert.Equal(tt.ExpectedResponse, resp)
			checkErr(err, tt.ExpectedErr, t)
		})
	}
}
