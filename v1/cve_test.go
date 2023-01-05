package nvdapi_test

import (
	"net/http"
	"testing"

	"github.com/pandatix/nvdapi/common"
	"github.com/pandatix/nvdapi/v1"
	"github.com/stretchr/testify/assert"
)

func TestGetCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Client           common.HTTPClient
		Params           nvdapi.GetCVEParams
		ExpectedResponse *nvdapi.CVEResponse
		ExpectedErr      error
	}{
		"nil-client": {
			Client:           nil,
			Params:           nvdapi.GetCVEParams{},
			ExpectedResponse: nil,
			ExpectedErr:      common.ErrNilClient,
		},
		"failing-client": {
			Client:           newFakeHTTPClient(``, 0, errFake),
			Params:           nvdapi.GetCVEParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errFake,
		},
		"unexpected-statuscode": {
			Client:           newFakeHTTPClient(``, 0, nil),
			Params:           nvdapi.GetCVEParams{},
			ExpectedResponse: nil,
			ExpectedErr: &common.ErrUnexpectedStatus{
				StatusCode: 0,
				Body:       []byte(``),
			},
		},
		"failing-unmarshal": {
			Client:           newFakeHTTPClient(jsonSyntaxError, http.StatusOK, nil),
			Params:           nvdapi.GetCVEParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errJsonSyntaxError,
		},
		"valid-call": {
			Client: newFakeHTTPClient(`{"resultsPerPage":1,"startIndex":0,"totalResults":1,"result":{"CVE_data_type":"CVE","CVE_data_format":"MITRE","CVE_data_version":"4.0","CVE_data_timestamp":"2021-10-08T17:25Z","CVE_Items":[{"cve":{"data_type":"CVE","data_format":"MITRE","data_version":"4.0","CVE_data_meta":{"ID":"CVE-2021-28378","ASSIGNER":"cve@mitre.org"},"problemtype":{"problemtype_data":[{"description":[{"lang":"en","value":"CWE-79"}]}]},"references":{"reference_data":[{"url":"https://github.com/go-gitea/gitea/pull/14898","name":"https://github.com/go-gitea/gitea/pull/14898","refsource":"MISC","tags":["Patch","Third Party Advisory"]},{"url":"https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/","name":"https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/","refsource":"MISC","tags":["Release Notes","Vendor Advisory"]},{"url":"https://github.com/PandatiX/CVE-2021-28378","name":"https://github.com/PandatiX/CVE-2021-28378","refsource":"MISC","tags":[]}]},"description":{"description_data":[{"lang":"en","value":"Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations."}]}},"configurations":{"CVE_data_version":"4.0","nodes":[{"operator":"OR","children":[],"cpe_match":[{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*","versionStartIncluding":"1.12.0","versionEndIncluding":"1.12.6","cpe_name":[]},{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*","versionStartIncluding":"1.13.0","versionEndExcluding":"1.13.4","cpe_name":[]}]}]},"impact":{"baseMetricV3":{"cvssV3":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N","attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"LOW","userInteraction":"REQUIRED","scope":"CHANGED","confidentialityImpact":"LOW","integrityImpact":"LOW","availabilityImpact":"NONE","baseScore":5.4,"baseSeverity":"MEDIUM"},"exploitabilityScore":2.3,"impactScore":2.7},"baseMetricV2":{"cvssV2":{"version":"2.0","vectorString":"AV:N/AC:M/Au:S/C:N/I:P/A:N","accessVector":"NETWORK","accessComplexity":"MEDIUM","authentication":"SINGLE","confidentialityImpact":"NONE","integrityImpact":"PARTIAL","availabilityImpact":"NONE","baseScore":3.5},"severity":"LOW","exploitabilityScore":6.8,"impactScore":2.9,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":true}},"publishedDate":"2021-03-15T06:15Z","lastModifiedDate":"2021-09-24T22:15Z"}]}}`, http.StatusOK, nil),
			Params: nvdapi.GetCVEParams{
				CVE: "CVE-2021-28378",
			},
			ExpectedResponse: &nvdapi.CVEResponse{
				ResultsPerPage: 1,
				StartIndex:     0,
				TotalResults:   1,
				Result: nvdapi.CVEResult{
					CVEDataType:      "CVE",
					CVEDataFormat:    "MITRE",
					CVEDataVersion:   "4.0",
					CVEDataTimestamp: "2021-10-08T17:25Z",
					CVEItems: []nvdapi.CVEItem{
						{
							CVE: nvdapi.CVE{
								DataType:    "CVE",
								DataFormat:  "MITRE",
								DataVersion: "4.0",
								CVEDataMeta: nvdapi.CVEDataMeta{
									ID:       "CVE-2021-28378",
									ASSIGNER: "cve@mitre.org",
								},
								ProblemType: nvdapi.ProblemType{
									ProblemTypeData: []nvdapi.ProblemTypeData{
										{
											Description: []nvdapi.LangString{
												{
													Lang:  "en",
													Value: "CWE-79",
												},
											},
										},
									},
								},
								References: nvdapi.References{
									ReferenceData: []nvdapi.CVEReference{
										{
											URL:       "https://github.com/go-gitea/gitea/pull/14898",
											Name:      ptr("https://github.com/go-gitea/gitea/pull/14898"),
											Refsource: ptr("MISC"),
											Tags: []string{
												"Patch",
												"Third Party Advisory",
											},
										}, {
											URL:       "https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/",
											Name:      ptr("https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/"),
											Refsource: ptr("MISC"),
											Tags: []string{
												"Release Notes",
												"Vendor Advisory",
											},
										}, {
											URL:       "https://github.com/PandatiX/CVE-2021-28378",
											Name:      ptr("https://github.com/PandatiX/CVE-2021-28378"),
											Refsource: ptr("MISC"),
											Tags:      []string{},
										},
									},
								},
								Description: nvdapi.Description{
									DescriptionData: []nvdapi.LangString{
										{
											Lang:  "en",
											Value: "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
										},
									},
								},
							},
							Configurations: &nvdapi.Configurations{
								CVEDataVersion: "4.0",
								Nodes: []nvdapi.Node{
									{
										Operator: ptr("OR"),
										Children: []nvdapi.Node{},
										CPEMatch: []nvdapi.CPEMatch{
											{
												Vulnerable:            true,
												CPE23URI:              "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
												VersionStartIncluding: ptr("1.12.0"),
												VersionEndIncluding:   ptr("1.12.6"),
												CPEName:               []nvdapi.CVECPEName{},
											}, {
												Vulnerable:            true,
												CPE23URI:              "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
												VersionStartIncluding: ptr("1.13.0"),
												VersionEndExcluding:   ptr("1.13.4"),
												CPEName:               []nvdapi.CVECPEName{},
											},
										},
									},
								},
							},
							Impact: &nvdapi.Impact{
								BaseMetricV3: &nvdapi.BaseMetricV3{
									CVSSV3: &nvdapi.CVSSV3{
										Version:               "3.1",
										VectorString:          "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
										AttackVector:          ptr("NETWORK"),
										AttackComplexity:      ptr("LOW"),
										PrivilegesRequired:    ptr("LOW"),
										UserInteraction:       ptr("REQUIRED"),
										Scope:                 ptr("CHANGED"),
										ConfidentialityImpact: ptr("LOW"),
										IntegrityImpact:       ptr("LOW"),
										AvailabilityImpact:    ptr("NONE"),
										BaseScore:             5.4,
										BaseSeverity:          "MEDIUM",
									},
									ExploitabilityScore: ptr(2.3),
									ImpactScore:         ptr(2.7),
								},
								BaseMetricV2: &nvdapi.BaseMetricV2{
									CVSSV2: &nvdapi.CVSSV2{
										Version:               "2.0",
										VectorString:          "AV:N/AC:M/Au:S/C:N/I:P/A:N",
										AccessVector:          ptr("NETWORK"),
										AccessComplexity:      ptr("MEDIUM"),
										Authentication:        ptr("SINGLE"),
										ConfidentialityImpact: ptr("NONE"),
										IntegrityImpact:       ptr("PARTIAL"),
										AvailabilityImpact:    ptr("NONE"),
										BaseScore:             3.5,
									},
									Severity:                ptr("LOW"),
									ExploitabilityScore:     ptr(6.8),
									ImpactScore:             ptr(2.9),
									AcInsufInfo:             ptr(false),
									ObtainAllPrivilege:      ptr(false),
									ObtainUserPrivilege:     ptr(false),
									ObtainOtherPrivilege:    ptr(false),
									UserInteractionRequired: ptr(true),
								},
							},
							PublishedDate:    ptr("2021-03-15T06:15Z"),
							LastModifiedDate: ptr("2021-09-24T22:15Z"),
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

			resp, err := nvdapi.GetCVE(tt.Client, tt.Params, opts...)

			assert.Equal(tt.ExpectedResponse, resp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestGetCVEs(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Client           common.HTTPClient
		Params           nvdapi.GetCVEsParams
		ExpectedResponse *nvdapi.CVEResponse
		ExpectedErr      error
	}{
		"nil-client": {
			Client:           nil,
			Params:           nvdapi.GetCVEsParams{},
			ExpectedResponse: nil,
			ExpectedErr:      common.ErrNilClient,
		},
		"failing-client": {
			Client:           newFakeHTTPClient(``, 0, errFake),
			Params:           nvdapi.GetCVEsParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errFake,
		},
		"unexpected-statuscode": {
			Client:           newFakeHTTPClient(``, 0, nil),
			Params:           nvdapi.GetCVEsParams{},
			ExpectedResponse: nil,
			ExpectedErr: &common.ErrUnexpectedStatus{
				StatusCode: 0,
				Body:       []byte(``),
			},
		},
		"failing-unmarshal": {
			Client:           newFakeHTTPClient(jsonSyntaxError, http.StatusOK, nil),
			Params:           nvdapi.GetCVEsParams{},
			ExpectedResponse: nil,
			ExpectedErr:      errJsonSyntaxError,
		},
		"valid-call": {
			// Results have been truncated in payload to avoid having too much data
			// to code for this test.
			Client: newFakeHTTPClient(`{"resultsPerPage":17,"startIndex":0,"totalResults":17,"result":{"CVE_data_type":"CVE","CVE_data_format":"MITRE","CVE_data_version":"4.0","CVE_data_timestamp":"2021-10-07T20:27Z","CVE_Items":[{"cve":{"data_type":"CVE","data_format":"MITRE","data_version":"4.0","CVE_data_meta":{"ID":"CVE-2021-28378","ASSIGNER":"cve@mitre.org"},"problemtype":{"problemtype_data":[{"description":[{"lang":"en","value":"CWE-79"}]}]},"references":{"reference_data":[{"url":"https://github.com/go-gitea/gitea/pull/14898","name":"https://github.com/go-gitea/gitea/pull/14898","refsource":"MISC","tags":["Patch","Third Party Advisory"]},{"url":"https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/","name":"https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/","refsource":"MISC","tags":["Release Notes","Vendor Advisory"]},{"url":"https://github.com/PandatiX/CVE-2021-28378","name":"https://github.com/PandatiX/CVE-2021-28378","refsource":"MISC","tags":[]}]},"description":{"description_data":[{"lang":"en","value":"Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations."}]}},"configurations":{"CVE_data_version":"4.0","nodes":[{"operator":"OR","children":[],"cpe_match":[{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*","versionStartIncluding":"1.12.0","versionEndIncluding":"1.12.6","cpe_name":[]},{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*","versionStartIncluding":"1.13.0","versionEndExcluding":"1.13.4","cpe_name":[]}]}]},"impact":{"baseMetricV3":{"cvssV3":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N","attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"LOW","userInteraction":"REQUIRED","scope":"CHANGED","confidentialityImpact":"LOW","integrityImpact":"LOW","availabilityImpact":"NONE","baseScore":5.4,"baseSeverity":"MEDIUM"},"exploitabilityScore":2.3,"impactScore":2.7},"baseMetricV2":{"cvssV2":{"version":"2.0","vectorString":"AV:N/AC:M/Au:S/C:N/I:P/A:N","accessVector":"NETWORK","accessComplexity":"MEDIUM","authentication":"SINGLE","confidentialityImpact":"NONE","integrityImpact":"PARTIAL","availabilityImpact":"NONE","baseScore":3.5},"severity":"LOW","exploitabilityScore":6.8,"impactScore":2.9,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":true}},"publishedDate":"2021-03-15T06:15Z","lastModifiedDate":"2021-09-24T22:15Z"}]}}`, http.StatusOK, nil),
			Params: nvdapi.GetCVEsParams{
				Keyword: ptr("gitea"),
			},
			ExpectedResponse: &nvdapi.CVEResponse{
				ResultsPerPage: 17,
				StartIndex:     0,
				TotalResults:   17,
				Result: nvdapi.CVEResult{
					CVEDataType:      "CVE",
					CVEDataFormat:    "MITRE",
					CVEDataVersion:   "4.0",
					CVEDataTimestamp: "2021-10-07T20:27Z",
					CVEItems: []nvdapi.CVEItem{
						{
							CVE: nvdapi.CVE{
								DataType:    "CVE",
								DataFormat:  "MITRE",
								DataVersion: "4.0",
								CVEDataMeta: nvdapi.CVEDataMeta{
									ID:       "CVE-2021-28378",
									ASSIGNER: "cve@mitre.org",
								},
								ProblemType: nvdapi.ProblemType{
									ProblemTypeData: []nvdapi.ProblemTypeData{
										{
											Description: []nvdapi.LangString{
												{
													Lang:  "en",
													Value: "CWE-79",
												},
											},
										},
									},
								},
								References: nvdapi.References{
									ReferenceData: []nvdapi.CVEReference{
										{
											URL:       "https://github.com/go-gitea/gitea/pull/14898",
											Name:      ptr("https://github.com/go-gitea/gitea/pull/14898"),
											Refsource: ptr("MISC"),
											Tags: []string{
												"Patch",
												"Third Party Advisory",
											},
										}, {
											URL:       "https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/",
											Name:      ptr("https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/"),
											Refsource: ptr("MISC"),
											Tags: []string{
												"Release Notes",
												"Vendor Advisory",
											},
										}, {
											URL:       "https://github.com/PandatiX/CVE-2021-28378",
											Name:      ptr("https://github.com/PandatiX/CVE-2021-28378"),
											Refsource: ptr("MISC"),
											Tags:      []string{},
										},
									},
								},
								Description: nvdapi.Description{
									DescriptionData: []nvdapi.LangString{
										{
											Lang:  "en",
											Value: "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
										},
									},
								},
							},
							Configurations: &nvdapi.Configurations{
								CVEDataVersion: "4.0",
								Nodes: []nvdapi.Node{
									{
										Operator: ptr("OR"),
										Children: []nvdapi.Node{},
										CPEMatch: []nvdapi.CPEMatch{
											{
												Vulnerable:            true,
												CPE23URI:              "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
												VersionStartIncluding: ptr("1.12.0"),
												VersionEndIncluding:   ptr("1.12.6"),
												CPEName:               []nvdapi.CVECPEName{},
											}, {
												Vulnerable:            true,
												CPE23URI:              "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
												VersionStartIncluding: ptr("1.13.0"),
												VersionEndExcluding:   ptr("1.13.4"),
												CPEName:               []nvdapi.CVECPEName{},
											},
										},
									},
								},
							},
							Impact: &nvdapi.Impact{
								BaseMetricV3: &nvdapi.BaseMetricV3{
									CVSSV3: &nvdapi.CVSSV3{
										Version:               "3.1",
										VectorString:          "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
										AttackVector:          ptr("NETWORK"),
										AttackComplexity:      ptr("LOW"),
										PrivilegesRequired:    ptr("LOW"),
										UserInteraction:       ptr("REQUIRED"),
										Scope:                 ptr("CHANGED"),
										ConfidentialityImpact: ptr("LOW"),
										IntegrityImpact:       ptr("LOW"),
										AvailabilityImpact:    ptr("NONE"),
										BaseScore:             5.4,
										BaseSeverity:          "MEDIUM",
									},
									ExploitabilityScore: ptr(2.3),
									ImpactScore:         ptr(2.7),
								},
								BaseMetricV2: &nvdapi.BaseMetricV2{
									CVSSV2: &nvdapi.CVSSV2{
										Version:               "2.0",
										VectorString:          "AV:N/AC:M/Au:S/C:N/I:P/A:N",
										AccessVector:          ptr("NETWORK"),
										AccessComplexity:      ptr("MEDIUM"),
										Authentication:        ptr("SINGLE"),
										ConfidentialityImpact: ptr("NONE"),
										IntegrityImpact:       ptr("PARTIAL"),
										AvailabilityImpact:    ptr("NONE"),
										BaseScore:             3.5,
									},
									Severity:                ptr("LOW"),
									ExploitabilityScore:     ptr(6.8),
									ImpactScore:             ptr(2.9),
									AcInsufInfo:             ptr(false),
									ObtainAllPrivilege:      ptr(false),
									ObtainUserPrivilege:     ptr(false),
									ObtainOtherPrivilege:    ptr(false),
									UserInteractionRequired: ptr(true),
								},
							},
							PublishedDate:    ptr("2021-03-15T06:15Z"),
							LastModifiedDate: ptr("2021-09-24T22:15Z"),
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

			resp, err := nvdapi.GetCVEs(tt.Client, tt.Params, opts...)

			assert.Equal(tt.ExpectedResponse, resp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
