package nvdapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/gorilla/schema"
)

// GetCVEParams combines the parameters needed for GetCVE.
type GetCVEParams struct {
	CVE    string `schema:"-"`
	AddOns *bool  `schema:"addOns,omitempty"`
}

// GetCVE fetches and returns the CVE given the parameters.
func GetCVE(client HTTPClient, params GetCVEParams) (*CVEResponse, error) {
	return getEndp(client, "cve/1.0/"+params.CVE, params)
}

// GetCVEsParams combines the parameters needed for GetCVEs.
type GetCVEsParams struct {
	StartIndex               *int    `schema:"startIndex,omitempty"`
	ResultsPerPage           *int    `schema:"resultsPerPage,omitempty"`
	PubStartDate             *string `schema:"pubStartDate,omitempty"`
	PubEndDate               *string `schema:"pubEndDate,omitempty"`
	ModStartDate             *string `schema:"modStartDate,omitempty"`
	ModEndDate               *string `schema:"modEndDate,omitempty"`
	IncludeMatchStringChange *bool   `schema:"includeMatchStringChange,omitempty"`
	Keyword                  *string `schema:"keyword,omitempty"`
	IsExactMatch             *bool   `schema:"isExactMatch,omitempty"`
	CWEID                    *bool   `schema:"cweId,omitempty"`
	CVSSV2Severity           *bool   `schema:"cvssV2Severity,omitempty"`
	CVSSV3Severity           *bool   `schema:"cvssV3Severity,omitempty"`
	CVSSV2Metrics            *bool   `schema:"cvssV2Metrics,omitempty"`
	CVSSV3Metrics            *bool   `schema:"cvssV3Metrics,omitempty"`
	CPEMatchString           *bool   `schema:"cpeMatchString,omitempty"`
	CPEName                  *string `schema:"cpeName,omitempty"`
	AddOns                   *bool   `schema:"addOns,omitempty"`
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
