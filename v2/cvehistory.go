package nvdapi

import "github.com/pandatix/nvdapi/common"

type CVEHistoryParams struct {
	ChangeStartDate *string    `json:"changeStartDate,omitempty"`
	ChangeEndDate   *string    `json:"changeEndDate,omitempty"`
	CVEID           *string    `json:"cveId,omitempty"`
	EventName       *EventName `json:"eventName,omitempty"`
	ResultsPerPage  *int       `json:"resultsPerPage,omitempty"`
	StartIndex      *int       `json:"startIndex,omitempty"`
}

type EventName string

var (
	EventInitialAnalysis     EventName = "Initial Analysis"
	EventReanalysis          EventName = "Reanalysis"
	EventCVEModified         EventName = "CVE Modified"
	EventModifiedAnalysis    EventName = "Modified Analysis"
	EventCVETranslated       EventName = "CVE Translated"
	EventVendorComment       EventName = "Vendor Comment"
	EventCVESourceUpdate     EventName = "CVE Source Update"
	EventCPEDeprecationRemap EventName = "CPE Deprecation Remap"
	EventCWERemap            EventName = "CWE Remap"
	EventCVERejected         EventName = "CVE Rejected"
	EventCVEUnrejected       EventName = "CVE Unrejected"
)

func GetCVEHistory(client common.HTTPClient, params CVEHistoryParams, opts ...common.Option) (*CVEHistoryResponse, error) {
	resp := &CVEHistoryResponse{}
	if err := getEndp(client, "cvehistory/2.0", params, &resp, opts...); err != nil {
		return nil, err
	}
	return resp, nil
}

type (
	CVEHistoryResponse struct {
		ResultsPerPage int      `json:"resultsPerPage"`
		StartIndex     int      `json:"startIndex"`
		TotalResults   int      `json:"totalResults"`
		Format         string   `json:"format"`
		Version        string   `json:"version"`
		Timestamp      string   `json:"timestamp"`
		CVEChanges     []Change `json:"cveChange,omitempty"`
	}

	Change struct {
		Change ChangeItem `json:"change"`
	}

	ChangeItem struct {
		CVEID            string   `json:"cveId"`
		EventName        string   `json:"eventName"`
		CVEChangeID      string   `json:"cveChangeId"`
		SourceIdentifier string   `json:"sourceIdentifier"`
		Created          *string  `json:"created,omitempty"`
		Details          []Detail `json:"details,omitempty"`
	}

	Detail struct {
		Action   *string `json:"action,omitempty"`
		Type     string  `json:"type"`
		OldValue *string `json:"oldValue,omitempty"`
		NewValue *string `json:"newValue,omitempty"`
	}
)
