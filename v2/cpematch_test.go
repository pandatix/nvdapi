package nvdapi_test

import (
	"net/http"
	"testing"

	"github.com/pandatix/nvdapi/common"
	"github.com/pandatix/nvdapi/v2"
	"github.com/stretchr/testify/assert"
)

func TestGetCPEMatch(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Client           common.HTTPClient
		Params           nvdapi.GetCPEMatchParams
		ExpectedResponse *nvdapi.CPEMatchResponse
		ExpectedErr      error
	}{
		"nil-client": {
			Client:           nil,
			Params:           nvdapi.GetCPEMatchParams{},
			ExpectedResponse: nil,
			ExpectedErr:      common.ErrNilClient,
		},
		"failing-client": {
			Client:           newFakeHTTPClient(``, 0, errFake),
			Params:           nvdapi.GetCPEMatchParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errFake,
		},
		"unexpected-statuscode": {
			Client:           newFakeHTTPClient(``, 0, nil),
			Params:           nvdapi.GetCPEMatchParams{},
			ExpectedResponse: nil,
			ExpectedErr: &common.ErrUnexpectedStatus{
				StatusCode: 0,
				Body:       []byte(``),
			},
		},
		"failing-unmarshal": {
			Client:           newFakeHTTPClient(jsonSyntaxError, http.StatusOK, nil),
			Params:           nvdapi.GetCPEMatchParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errJsonSyntaxError,
		},
		"valid-call": {
			Client: newFakeHTTPClient(`{"resultsPerPage":1,"startIndex":0,"totalResults":2,"format":"NVD_CPEMatchString","version":"2.0","timestamp":"2023-01-06T07:42:24.300","matchStrings":[{"matchString":{"matchCriteriaId":"F12318F1-F60F-4F82-96FD-41FB2E36714F","criteria":"cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*","versionStartIncluding":"1.12.0","versionEndIncluding":"1.12.6","lastModified":"2021-03-16T14:24:35.680","cpeLastModified":"2021-03-16T14:24:35.680","created":"2021-03-16T14:24:35.680","status":"Active","matches":[{"cpeName":"cpe:2.3:a:gitea:gitea:1.12.0:-:*:*:*:*:*:*","cpeNameId":"297553BB-EA1A-4704-BFC0-AD6F4DFF2A98"},{"cpeName":"cpe:2.3:a:gitea:gitea:1.12.0:dev:*:*:*:*:*:*","cpeNameId":"C35C6C04-CFD3-4412-B5F1-03B9200669F2"},{"cpeName":"cpe:2.3:a:gitea:gitea:1.12.0:rc1:*:*:*:*:*:*","cpeNameId":"EC96AC14-3C9E-4A0F-9875-74155EF08D0B"},{"cpeName":"cpe:2.3:a:gitea:gitea:1.12.5:*:*:*:*:*:*:*","cpeNameId":"749706BB-024B-47CB-9970-26D24BF4546F"},{"cpeName":"cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:*:*:*","cpeNameId":"ACE611BC-1AFC-49A5-AAC8-A6ED0B2FCA6B"}]}}]}`, http.StatusOK, nil),
			Params: nvdapi.GetCPEMatchParams{
				CVEID:          ptr("CVE-2021-28387"),
				ResultsPerPage: ptr(1),
			},
			ExpectedResponse: &nvdapi.CPEMatchResponse{
				ResultsPerPage: 1,
				StartIndex:     0,
				TotalResults:   2,
				Format:         "NVD_CPEMatchString",
				Version:        "2.0",
				Timestamp:      "2023-01-06T07:42:24.300",
				MatchStrings: []nvdapi.MatchString{
					{
						MatchString: nvdapi.CPEMatch{
							Criteria:              "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
							MatchCriteriaID:       "F12318F1-F60F-4F82-96FD-41FB2E36714F",
							VersionStartIncluding: ptr("1.12.0"),
							VersionEndIncluding:   ptr("1.12.6"),
							Created:               "2021-03-16T14:24:35.680",
							LastModified:          "2021-03-16T14:24:35.680",
							CPELastModified:       ptr("2021-03-16T14:24:35.680"),
							Status:                "Active",
							Matches: []nvdapi.CPEName{
								{
									CPEName:   "cpe:2.3:a:gitea:gitea:1.12.0:-:*:*:*:*:*:*",
									CPENameID: "297553BB-EA1A-4704-BFC0-AD6F4DFF2A98",
								}, {
									CPEName:   "cpe:2.3:a:gitea:gitea:1.12.0:dev:*:*:*:*:*:*",
									CPENameID: "C35C6C04-CFD3-4412-B5F1-03B9200669F2",
								}, {
									CPEName:   "cpe:2.3:a:gitea:gitea:1.12.0:rc1:*:*:*:*:*:*",
									CPENameID: "EC96AC14-3C9E-4A0F-9875-74155EF08D0B",
								}, {
									CPEName:   "cpe:2.3:a:gitea:gitea:1.12.5:*:*:*:*:*:*:*",
									CPENameID: "749706BB-024B-47CB-9970-26D24BF4546F",
								}, {
									CPEName:   "cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:*:*:*",
									CPENameID: "ACE611BC-1AFC-49A5-AAC8-A6ED0B2FCA6B",
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

			resp, err := nvdapi.GetCPEMatch(tt.Client, tt.Params, opts...)

			assert.Equal(tt.ExpectedResponse, resp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
