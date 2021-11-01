package nvdapi

type GetCPEParams struct {
	AddOns            *AddOns `schema:"addOns,omitempty"`
	APIKey            *string `schema:"apiKey,omitempty"`
	CPEMatchString    *string `schela:"cpeMatchString,omitempty"`
	IncludeDeprecated *bool   `schema:"includeDeprecated"`
	Keyword           *string `schema:"keyword,omitempty"`
	ModStartDate      *string `schema:"modStartDate,omitempty"`
	ModEndDate        *string `schema:"modEndDate,omitempty"`
	ResultsPerPage    *int    `schema:"resultsPerPage,omitempty"`
	StartIndex        *int    `schema:"startIndex,omitempty"`
}

func GetCPEs(client HTTPClient, params GetCPEParams) (*CPEResponse, error) {
	resp := &CPEResponse{}
	err := getEndp(client, "cpes/1.0/", params, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
