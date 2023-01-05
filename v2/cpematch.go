package nvdapi

import "github.com/pandatix/nvdapi/common"

type (
	CPEMatchParams struct {
		CVEID            *string `nvd:"cveId,omitempty,"`
		LastModStartDate *string `nvd:"lastModStartDate,omitempty,"`
		LastModEndDate   *string `nvd:"lastModEndDate,omitempty,"`
		MatchCriteriaId  *string `nvd:"matchCriteriaId,omitempty,"`
		ResultsPerPage   *int    `nvd:"resultsPerPage,omitempty,"`
		StartIndex       *int    `nvd:"startIndex,omitempty,"`
	}
)

func GetCPEMatch(client common.HTTPClient, params CPEMatchParams, opts ...common.Option) (*CPEMatchResponse, error) {
	resp := &CPEMatchResponse{}
	if err := getEndp(client, "cpematch/2.0", params, &resp, opts...); err != nil {
		return nil, err
	}
	return resp, nil
}

type (
	CPEMatchResponse struct {
		ResultsPerPage int        `json:"resultsPerPage"`
		StartIndex     int        `json:"startIndex"`
		TotalResults   int        `json:"totalResults"`
		Format         string     `json:"format"`
		Version        string     `json:"version"`
		Timestamp      string     `json:"timestamp"`
		MatchStrings   []CPEMatch `json:"matchStrings"`
	}

	CPEMatch struct {
		Criteria              string    `json:"criteria"`
		MatchCriteriaID       string    `json:"matchCriteriaId"`
		VersionStartExcluding *string   `json:"versionStartExcluding,omitempty"`
		VersionStartIncluding *string   `json:"versionStartIncluding,omitempty"`
		VersionEndExcluding   *string   `json:"versionEndExcluding,omitempty"`
		VersionEndIncluding   *string   `json:"versionEndIncluding,omitempty"`
		Created               string    `json:"created"`
		LastModified          string    `json:"lastModified"`
		CPELastModified       *string   `json:"cpeLastModified,omitempty"`
		Status                string    `json:"status"`
		Matches               []CPEName `json:"matches,omitempty"`
	}

	CPEName struct {
		CPEName   string `json:"cpeName"`
		CPENameID string `json:"cpeNameId"`
	}
)
