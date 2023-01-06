package nvdapi_test

import (
	"net/http"
	"testing"

	"github.com/pandatix/nvdapi/common"
	"github.com/pandatix/nvdapi/v2"
	"github.com/stretchr/testify/assert"
)

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
			Client: newFakeHTTPClient(`{"resultsPerPage":1,"startIndex":0,"totalResults":1,"format":"NVD_CVE","version":"2.0","timestamp":"2023-01-06T07:56:53.723","vulnerabilities":[{"cve":{"id":"CVE-2021-28378","sourceIdentifier":"cve@mitre.org","published":"2021-03-15T06:15:12.423","lastModified":"2021-12-16T18:20:22.583","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations."},{"lang":"es","value":"Gitea versiones 1.12.x y versiones 1.13.x anteriores a 1.13.4, permite un ataque de tipo XSS por medio de determinados datos de problemas en algunas situaciones"}],"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1\/AV:N\/AC:L\/PR:L\/UI:R\/S:C\/C:L\/I:L\/A:N","attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"LOW","userInteraction":"REQUIRED","scope":"CHANGED","confidentialityImpact":"LOW","integrityImpact":"LOW","availabilityImpact":"NONE","baseScore":5.4,"baseSeverity":"MEDIUM"},"exploitabilityScore":2.3,"impactScore":2.7},{"source":"cve@mitre.org","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1\/AV:N\/AC:H\/PR:L\/UI:R\/S:U\/C:L\/I:L\/A:N","attackVector":"NETWORK","attackComplexity":"HIGH","privilegesRequired":"LOW","userInteraction":"REQUIRED","scope":"UNCHANGED","confidentialityImpact":"LOW","integrityImpact":"LOW","availabilityImpact":"NONE","baseScore":3.7,"baseSeverity":"LOW"},"exploitabilityScore":1.2,"impactScore":2.5}],"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"2.0","vectorString":"AV:N\/AC:M\/Au:S\/C:N\/I:P\/A:N","accessVector":"NETWORK","accessComplexity":"MEDIUM","authentication":"SINGLE","confidentialityImpact":"NONE","integrityImpact":"PARTIAL","availabilityImpact":"NONE","baseScore":3.5},"baseSeverity":"LOW","exploitabilityScore":6.8,"impactScore":2.9,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":true}]},"weaknesses":[{"source":"nvd@nist.gov","type":"Primary","description":[{"lang":"en","value":"CWE-79"}]}],"configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*","versionStartIncluding":"1.12.0","versionEndIncluding":"1.12.6","matchCriteriaId":"F12318F1-F60F-4F82-96FD-41FB2E36714F"},{"vulnerable":true,"criteria":"cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*","versionStartIncluding":"1.13.0","versionEndExcluding":"1.13.4","matchCriteriaId":"79997226-230B-4DEF-8E0F-98D961399559"}]}]}],"references":[{"url":"https:\/\/blog.gitea.io\/2021\/03\/gitea-1.13.4-is-released\/","source":"cve@mitre.org","tags":["Release Notes","Vendor Advisory"]},{"url":"https:\/\/github.com\/PandatiX\/CVE-2021-28378","source":"cve@mitre.org","tags":["Exploit","Third Party Advisory"]},{"url":"https:\/\/github.com\/go-gitea\/gitea\/pull\/14898","source":"cve@mitre.org","tags":["Patch","Third Party Advisory"]}]}}]}`, http.StatusOK, nil),
			Params: nvdapi.GetCVEsParams{
				CVEID:          ptr("CVE-2021-28387"),
				ResultsPerPage: ptr(1),
			},
			ExpectedResponse: &nvdapi.CVEResponse{
				ResultsPerPage: 1,
				StartIndex:     0,
				TotalResults:   1,
				Format:         "NVD_CVE",
				Version:        "2.0",
				Timestamp:      "2023-01-06T07:56:53.723",
				Vulnerabilities: []nvdapi.CVEItem{
					{
						CVE: nvdapi.CVE{
							ID:               ptr("CVE-2021-28378"),
							SourceIdentifier: ptr("cve@mitre.org"),
							Published:        ptr("2021-03-15T06:15:12.423"),
							LastModified:     ptr("2021-12-16T18:20:22.583"),
							VulnStatus:       ptr("Analyzed"),
							Descriptions: []nvdapi.LangString{
								{
									Lang:  "en",
									Value: "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
								}, {
									Lang:  "es",
									Value: "Gitea versiones 1.12.x y versiones 1.13.x anteriores a 1.13.4, permite un ataque de tipo XSS por medio de determinados datos de problemas en algunas situaciones",
								},
							},
							Metrics: &nvdapi.Metrics{
								CVSSMetricV31: []nvdapi.CVSSMetricV31{
									{
										Source: "nvd@nist.gov",
										Type:   "Primary",
										CVSSData: nvdapi.CVSSV31{
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
										ExploitabilityScore: ptr(nvdapi.Subscore(2.3)),
										ImpactScore:         ptr(nvdapi.Subscore(2.7)),
									}, {
										Source: "cve@mitre.org",
										Type:   "Secondary",
										CVSSData: nvdapi.CVSSV31{
											Version:               "3.1",
											VectorString:          "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
											AttackVector:          ptr("NETWORK"),
											AttackComplexity:      ptr("HIGH"),
											PrivilegesRequired:    ptr("LOW"),
											UserInteraction:       ptr("REQUIRED"),
											Scope:                 ptr("UNCHANGED"),
											ConfidentialityImpact: ptr("LOW"),
											IntegrityImpact:       ptr("LOW"),
											AvailabilityImpact:    ptr("NONE"),
											BaseScore:             3.7,
											BaseSeverity:          "LOW",
										},
										ExploitabilityScore: ptr(nvdapi.Subscore(1.2)),
										ImpactScore:         ptr(nvdapi.Subscore(2.5)),
									},
								},
								CVSSMetricV2: []nvdapi.CVSSMetricV2{
									{
										Source: "nvd@nist.gov",
										Type:   "Primary",
										CVSSData: nvdapi.CVSSV20{
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
										BaseSeverity:            ptr("LOW"),
										ExploitabilityScore:     ptr(nvdapi.Subscore(6.8)),
										ImpactScore:             ptr(nvdapi.Subscore(2.9)),
										ACInsufInfo:             ptr(false),
										ObtainAllPrivilege:      ptr(false),
										ObtainUserPrivilege:     ptr(false),
										ObtainOtherPrivilege:    ptr(false),
										UserInteractionRequired: ptr(true),
									},
								},
							},
							Weaknesses: []nvdapi.Weakness{
								{
									Source: "nvd@nist.gov",
									Type:   "Primary",
									Description: []nvdapi.LangString{
										{
											Lang:  "en",
											Value: "CWE-79",
										},
									},
								},
							},
							Configurations: []nvdapi.Config{
								{
									Nodes: []nvdapi.Node{
										{
											Operator: nvdapi.OperatorOr,
											Negate:   ptr(false),
											CPEMatch: []nvdapi.CVECPEMatch{
												{
													Vulnerable:            true,
													Criteria:              "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
													MatchCriteriaID:       "F12318F1-F60F-4F82-96FD-41FB2E36714F",
													VersionStartIncluding: ptr("1.12.0"),
													VersionEndIncluding:   ptr("1.12.6"),
												}, {
													Vulnerable:            true,
													Criteria:              "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
													MatchCriteriaID:       "79997226-230B-4DEF-8E0F-98D961399559",
													VersionStartIncluding: ptr("1.13.0"),
													VersionEndExcluding:   ptr("1.13.4"),
												},
											},
										},
									},
								},
							},
							References: []nvdapi.CVEReference{
								{
									URL:    "https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/",
									Source: ptr("cve@mitre.org"),
									Tags: []string{
										"Release Notes",
										"Vendor Advisory",
									},
								}, {
									URL:    "https://github.com/PandatiX/CVE-2021-28378",
									Source: ptr("cve@mitre.org"),
									Tags: []string{
										"Exploit",
										"Third Party Advisory",
									},
								}, {
									URL:    "https://github.com/go-gitea/gitea/pull/14898",
									Source: ptr("cve@mitre.org"),
									Tags: []string{
										"Patch",
										"Third Party Advisory",
									},
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

			resp, err := nvdapi.GetCVEs(tt.Client, tt.Params, opts...)

			assert.Equal(tt.ExpectedResponse, resp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
