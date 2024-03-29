package nvdapi

import "github.com/pandatix/nvdapi/common"

type GetCPEParams struct {
	AddOns            *AddOns `schema:"addOns,omitempty"`
	APIKey            *string `schema:"apiKey,omitempty"`
	CPEMatchString    *string `schema:"cpeMatchString,omitempty"`
	IncludeDeprecated *bool   `schema:"includeDeprecated,omitempty"`
	Keyword           *string `schema:"keyword,omitempty"`
	ModStartDate      *string `schema:"modStartDate,omitempty"`
	ModEndDate        *string `schema:"modEndDate,omitempty"`
	ResultsPerPage    *int    `schema:"resultsPerPage,omitempty"`
	StartIndex        *int    `schema:"startIndex,omitempty"`
}

func GetCPEs(client common.HTTPClient, params GetCPEParams, opts ...common.Option) (*CPEResponse, error) {
	resp := &CPEResponse{}
	if err := common.GetEndp(client, "cpes/1.0/", params, resp, opts...); err != nil {
		return nil, err
	}
	return resp, nil
}
