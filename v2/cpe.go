package nvdapi

import "github.com/pandatix/nvdapi/common"

type GetCPEsParams struct {
	CPENameID         *string `nvd:"cpeNameId,omitempty,"`
	CPEMatchString    *string `nvd:"cpeMatchString,omitempty,"`
	KeywordExactMatch *bool   `nvd:"keywordExactMatch,omitempty,"`
	KeywordSearch     *string `nvd:"keywordSearch,omitempty,"`
	LastModStartDate  *string `nvd:"lastModStartDate,omitempty,"`
	LastModEndDate    *string `nvd:"lastModEndDate,omitempty,"`
	MatchCriteriaId   *string `nvd:"matchCriteriaId,omitempty,"`
	ResultsPerPage    *int    `nvd:"resultsPerPage,omitempty,"`
	StartIndex        *int    `nvd:"startIndex,omitempty,"`
}

func GetCPEs(client common.HTTPClient, params GetCPEsParams, opts ...common.Option) (*CPEResponse, error) {
	resp := &CPEResponse{}
	if err := getEndp(client, "cpes/2.0/", params, &resp, opts...); err != nil {
		return nil, err
	}
	return resp, nil
}

type (
	CPEResponse struct {
		ResultsPerPage int          `json:"resultsPerPage"`
		StartIndex     int          `json:"startIndex"`
		TotalResults   int          `json:"totalResults"`
		Format         string       `json:"format"`
		Version        string       `json:"version"`
		Timestamp      string       `json:"timestamp"`
		Products       []CPEProduct `json:"products"`
	}

	CPEProduct struct {
		CPE CPE `json:"cpe"`
	}

	CPE struct {
		Deprecated   bool           `json:"deprecated"`
		CPEName      string         `json:"cpeName"`
		CPENameID    string         `json:"cpeNameId"`
		Created      string         `json:"created"`
		LastModified string         `json:"lastModified"`
		Titles       []Title        `json:"titles,omitempty"`
		Refs         []CPEReference `json:"refs,omitempty"`
		DeprecatedBy []DeprecatedBy `json:"deprecatedBy,omitempty"`
		Deprecates   []Deprecates   `json:"deprecates,omitempty"`
	}

	Title struct {
		Title string `json:"title"`
		Lang  string `json:"lang"`
	}

	CPEReference struct {
		Ref  string  `json:"ref"`
		Type *string `json:"type,omitempty"`
	}

	DeprecatedBy struct {
		CPEName   *string `json:"cpeName,omitempty"`
		CPENameID *string `json:"cpeNameId,omitempty"`
	}

	Deprecates struct {
		CPEName   *string `json:"cpeName,omitempty"`
		CPENameID *string `json:"cpeNameId,omitempty"`
	}
)
