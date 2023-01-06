package nvdapi_test

import (
	"net/http"
	"testing"

	"github.com/pandatix/nvdapi/common"
	"github.com/pandatix/nvdapi/v2"
	"github.com/stretchr/testify/assert"
)

func TestGetSource(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Client           common.HTTPClient
		Params           nvdapi.GetSourceParams
		ExpectedResponse *nvdapi.SourceResponse
		ExpectedErr      error
	}{
		"nil-client": {
			Client:           nil,
			Params:           nvdapi.GetSourceParams{},
			ExpectedResponse: nil,
			ExpectedErr:      common.ErrNilClient,
		},
		"failing-client": {
			Client:           newFakeHTTPClient(``, 0, errFake),
			Params:           nvdapi.GetSourceParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errFake,
		},
		"unexpected-statuscode": {
			Client:           newFakeHTTPClient(``, 0, nil),
			Params:           nvdapi.GetSourceParams{},
			ExpectedResponse: nil,
			ExpectedErr: &common.ErrUnexpectedStatus{
				StatusCode: 0,
				Body:       []byte(``),
			},
		},
		"failing-unmarshal": {
			Client:           newFakeHTTPClient(jsonSyntaxError, http.StatusOK, nil),
			Params:           nvdapi.GetSourceParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errJsonSyntaxError,
		},
		"valid-call": {
			Client: newFakeHTTPClient(`{"resultsPerPage":1,"startIndex":0,"totalResults":233,"format":"NVD_SOURCE","version":"2.0","timestamp":"2023-01-06T08:41:55.220","sources":[{"name":"MITRE","contactEmail":"cve@mitre.org","sourceIdentifiers":["cve@mitre.org"],"lastModified":"2019-09-09T16:18:45.930","created":"2019-09-09T16:18:45.930","v3AcceptanceLevel":{"description":"Contributor","lastModified":"2023-01-06T00:00:09.680"},"cweAcceptanceLevel":{"description":"Reference","lastModified":"2022-12-30T00:00:00.053"}}]}`, http.StatusOK, nil),
			Params: nvdapi.GetSourceParams{
				ResultsPerPage: ptr(1),
			},
			ExpectedResponse: &nvdapi.SourceResponse{
				ResultsPerPage: 1,
				StartIndex:     0,
				TotalResults:   233,
				Format:         "NVD_SOURCE",
				Version:        "2.0",
				Timestamp:      "2023-01-06T08:41:55.220",
				Sources: []nvdapi.Source{
					{
						Name:         ptr("MITRE"),
						ContactEmail: ptr("cve@mitre.org"),
						SourceIdentifiers: []string{
							"cve@mitre.org",
						},
						LastModified: "2019-09-09T16:18:45.930",
						Created:      "2019-09-09T16:18:45.930",
						V3AcceptanceLevel: &nvdapi.AcceptLevel{
							Description:  "Contributor",
							LastModified: "2023-01-06T00:00:09.680",
						},
						CWEAcceptanceLevel: &nvdapi.AcceptLevel{
							Description:  "Reference",
							LastModified: "2022-12-30T00:00:00.053",
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

			resp, err := nvdapi.GetSource(tt.Client, tt.Params, opts...)

			assert.Equal(tt.ExpectedResponse, resp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
