package nvdapi

import "github.com/pandatix/nvdapi/common"

type GetSourceParams struct {
	LastModStartDate *string `nvd:"lastModStartDate,omitempty,"`
	LastModEndDate   *string `nvd:"lastModEndDate,omitempty,"`
	ResultsPerPage   *int    `nvd:"resultsPerPage,omitempty,"`
	SourceIdentifier *string `nvd:"sourceIdentifier,omitempty,"`
	StartIndex       *int    `nvd:"startIndex,omitempty,"`
}

func GetSource(client common.HTTPClient, params GetSourceParams, opts ...common.Option) (*SourceResponse, error) {
	resp := &SourceResponse{}
	if err := getEndp(client, "source/2.0", params, &resp, opts...); err != nil {
		return nil, err
	}
	return resp, nil
}

type (
	SourceResponse struct {
		ResultsPerPage int      `json:"resultsPerPage"`
		StartIndex     int      `json:"startIndex"`
		TotalResults   int      `json:"totalResults"`
		Format         string   `json:"format"`
		Version        string   `json:"version"`
		Timestamp      string   `json:"timestamp"`
		Sources        []Source `json:"sources,omitempty"`
	}

	Source struct {
		// Name is not specified in the JSON Source Schema
		Name *string `json:"name,omitempty"`

		ContactEmail       *string      `json:"contactEmail,omitempty"`
		LastModified       string       `json:"lastModified"`
		Created            string       `json:"created"`
		V2AcceptanceLevel  *AcceptLevel `json:"v2AcceptanceLevel,omitempty"`
		V3AcceptanceLevel  *AcceptLevel `json:"v3AcceptanceLevel,omitempty"`
		V4AcceptanceLevel  *AcceptLevel `json:"v4AcceptanceLevel,omitempty"`
		CWEAcceptanceLevel *AcceptLevel `json:"cweAcceptanceLevel,omitempty"`
		// SourceIdentifers is specified as a required property of the source object in the JSON Source Schema
		SourceIdentifiers []string `json:"sourceIdentifiers,omitempty"`
	}

	AcceptLevel struct {
		Description  string `json:"description"`
		LastModified string `json:"lastModified"`
	}
)
