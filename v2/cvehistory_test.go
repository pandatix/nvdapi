package nvdapi_test

import (
	"net/http"
	"testing"

	"github.com/pandatix/nvdapi/common"
	"github.com/pandatix/nvdapi/v2"
	"github.com/stretchr/testify/assert"
)

func TestGetCVEHistory(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Client           common.HTTPClient
		Params           nvdapi.GetCVEHistoryParams
		ExpectedResponse *nvdapi.CVEHistoryResponse
		ExpectedErr      error
	}{
		"nil-client": {
			Client:           nil,
			Params:           nvdapi.GetCVEHistoryParams{},
			ExpectedResponse: nil,
			ExpectedErr:      common.ErrNilClient,
		},
		"failing-client": {
			Client:           newFakeHTTPClient(``, 0, errFake),
			Params:           nvdapi.GetCVEHistoryParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errFake,
		},
		"unexpected-statuscode": {
			Client:           newFakeHTTPClient(``, 0, nil),
			Params:           nvdapi.GetCVEHistoryParams{},
			ExpectedResponse: nil,
			ExpectedErr: &common.ErrUnexpectedStatus{
				StatusCode: 0,
				Body:       []byte(``),
			},
		},
		"failing-unmarshal": {
			Client:           newFakeHTTPClient(jsonSyntaxError, http.StatusOK, nil),
			Params:           nvdapi.GetCVEHistoryParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errJsonSyntaxError,
		},
		"valid-call": {
			Client: newFakeHTTPClient(`{"resultsPerPage":1,"startIndex":0,"totalResults":3,"format":"NVD_CVEHistory","version":"2.0","timestamp":"2023-01-06T08:25:55.350","cveChanges":[{"change":{"cveId":"CVE-2021-28378","eventName":"Initial Analysis","cveChangeId":"DA505294-21F7-4043-A28B-8242B587EDD3","sourceIdentifier":"nvd@nist.gov","created":"2021-03-18T19:34:08.997","details":[{"action":"Added","type":"CVSS V2 Metadata","newValue":"Victim must voluntarily interact with attack mechanism"},{"action":"Added","type":"CVSS V2","newValue":"NIST (AV:N\/AC:M\/Au:S\/C:N\/I:P\/A:N)"},{"action":"Added","type":"CVSS V3.1","newValue":"NIST AV:N\/AC:L\/PR:L\/UI:R\/S:C\/C:L\/I:L\/A:N"},{"action":"Changed","type":"Reference Type","oldValue":"https:\/\/blog.gitea.io\/2021\/03\/gitea-1.13.4-is-released\/ No Types Assigned","newValue":"https:\/\/blog.gitea.io\/2021\/03\/gitea-1.13.4-is-released\/ Release Notes, Vendor Advisory"},{"action":"Changed","type":"Reference Type","oldValue":"https:\/\/github.com\/go-gitea\/gitea\/pull\/14898 No Types Assigned","newValue":"https:\/\/github.com\/go-gitea\/gitea\/pull\/14898 Patch, Third Party Advisory"},{"action":"Added","type":"CWE","newValue":"NIST CWE-79"},{"action":"Added","type":"CPE Configuration","newValue":"OR\\n     *cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* versions from (including) 1.12.0 up to (including) 1.12.6\\n     *cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* versions from (including) 1.13.0 up to (excluding) 1.13.4"}]}}]}`, http.StatusOK, nil),
			Params: nvdapi.GetCVEHistoryParams{
				CVEID:          ptr("CVE-2021-28387"),
				ResultsPerPage: ptr(1),
			},
			ExpectedResponse: &nvdapi.CVEHistoryResponse{
				ResultsPerPage: 1,
				StartIndex:     0,
				TotalResults:   3,
				Format:         "NVD_CVEHistory",
				Version:        "2.0",
				Timestamp:      "2023-01-06T08:25:55.350",
				CVEChanges: []nvdapi.Change{
					{
						Change: nvdapi.ChangeItem{
							CVEID:            "CVE-2021-28378",
							EventName:        "Initial Analysis",
							CVEChangeID:      "DA505294-21F7-4043-A28B-8242B587EDD3",
							SourceIdentifier: "nvd@nist.gov",
							Created:          ptr("2021-03-18T19:34:08.997"),
							Details: []nvdapi.Detail{
								{
									Action:   ptr("Added"),
									Type:     "CVSS V2 Metadata",
									NewValue: ptr("Victim must voluntarily interact with attack mechanism"),
								}, {
									Action:   ptr("Added"),
									Type:     "CVSS V2",
									NewValue: ptr("NIST (AV:N/AC:M/Au:S/C:N/I:P/A:N)"),
								}, {
									Action:   ptr("Added"),
									Type:     "CVSS V3.1",
									NewValue: ptr("NIST AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
								}, {
									Action:   ptr("Changed"),
									Type:     "Reference Type",
									OldValue: ptr("https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/ No Types Assigned"),
									NewValue: ptr("https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/ Release Notes, Vendor Advisory"),
								}, {
									Action:   ptr("Changed"),
									Type:     "Reference Type",
									OldValue: ptr("https://github.com/go-gitea/gitea/pull/14898 No Types Assigned"),
									NewValue: ptr("https://github.com/go-gitea/gitea/pull/14898 Patch, Third Party Advisory"),
								}, {
									Action:   ptr("Added"),
									Type:     "CWE",
									NewValue: ptr("NIST CWE-79"),
								}, {
									Action:   ptr("Added"),
									Type:     "CPE Configuration",
									NewValue: ptr("OR\\n     *cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* versions from (including) 1.12.0 up to (including) 1.12.6\\n     *cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* versions from (including) 1.13.0 up to (excluding) 1.13.4"),
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

			resp, err := nvdapi.GetCVEHistory(tt.Client, tt.Params, opts...)

			assert.Equal(tt.ExpectedResponse, resp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
