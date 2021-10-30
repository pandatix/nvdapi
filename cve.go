package nvdapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/gorilla/schema"
)

type AddOns string

var (
	DictionaryCPEs AddOns = "dictionaryCpes"
)

// GetCVEParams combines the parameters needed for GetCVE.
type GetCVEParams struct {
	CVE    string  `schema:"-"`
	AddOns *AddOns `schema:"addOns,omitempty"`
	APIKey *string `schema:"apiKey,omitempty"`
}

// GetCVE fetches and returns the CVE given the parameters.
func GetCVE(client HTTPClient, params GetCVEParams) (*CVEResponse, error) {
	return getEndp(client, "cve/1.0/"+params.CVE, params)
}

// GetCVEsParams combines the parameters needed for GetCVEs.
type GetCVEsParams struct {
	AddOns                   *AddOns `schema:"addOns,omitempty"`
	APIKey                   *string `schema:"apiKey,omitempty"`
	CPEMatchString           *bool   `schema:"cpeMatchString,omitempty"`
	CVSSV2Metrics            *bool   `schema:"cvssV2Metrics,omitempty"`
	CVSSV2Severity           *bool   `schema:"cvssV2Severity,omitempty"`
	CVSSV3Metrics            *bool   `schema:"cvssV3Metrics,omitempty"`
	CVSSV3Severity           *bool   `schema:"cvssV3Severity,omitempty"`
	CWEID                    *bool   `schema:"cweId,omitempty"`
	IncludeMatchStringChange *bool   `schema:"includeMatchStringChange,omitempty"`
	IsExactMatch             *bool   `schema:"isExactMatch,omitempty"`
	Keyword                  *string `schema:"keyword,omitempty"`
	ModStartDate             *string `schema:"modStartDate,omitempty"`
	ModEndDate               *string `schema:"modEndDate,omitempty"`
	PubStartDate             *string `schema:"pubStartDate,omitempty"`
	PubEndDate               *string `schema:"pubEndDate,omitempty"`
	ResultsPerPage           *int    `schema:"resultsPerPage,omitempty"`
	StartIndex               *int    `schema:"startIndex,omitempty"`
}

// GetCVEs fetches and returns the CVEs given the parameters.
func GetCVEs(client HTTPClient, params GetCVEsParams) (*CVEResponse, error) {
	return getEndp(client, "cves/1.0", params)
}

func getEndp(client HTTPClient, endp string, params interface{}) (*CVEResponse, error) {
	if client == nil {
		return nil, ErrNilClient
	}

	// Build the request
	req, _ := http.NewRequest(http.MethodGet, "https://services.nvd.nist.gov/rest/json/"+endp, nil)
	form := url.Values{}
	_ = schema.NewEncoder().Encode(params, form)
	req.URL.RawQuery = form.Encode()

	// Issue the request
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	// Check status code
	if res.StatusCode != http.StatusOK {
		return nil, &ErrUnexpectedStatus{
			Body:       body,
			StatusCode: res.StatusCode,
		}
	}

	// Unmarshal response
	var resp CVEResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}
