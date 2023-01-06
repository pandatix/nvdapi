package v2_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/pandatix/nvdapi/v2"
	"github.com/stretchr/testify/assert"
)

func Test_V2_GetCVEs(t *testing.T) {
	var tests = map[string]struct {
		Params nvdapi.GetCVEsParams
	}{
		"no-specific-cve": {
			Params: nvdapi.GetCVEsParams{},
		},
		"CVE-2021-28378": {
			Params: nvdapi.GetCVEsParams{
				CVEID: ptr("CVE-2021-28378"),
			},
		},
		"boolean-param": {
			Params: nvdapi.GetCVEsParams{
				HasOVAL: ptr(true),
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)
			defer time.Sleep(6 * time.Second)

			mdwclient := &MdwClient{}
			client, _ := nvdapi.NewNVDClient(mdwclient, apiKey)
			resp, err := nvdapi.GetCVEs(client, tt.Params)

			// Ensure no error
			if !assert.Nil(err) {
				t.Errorf("Last body [%s]\n", mdwclient.LastBody)
			}

			// Reencode to JSON
			buf := &bytes.Buffer{}
			_ = json.NewEncoder(buf).Encode(resp)

			// Decode both to interfaces
			var expected any
			var actual any
			_ = json.Unmarshal(mdwclient.LastBody, &expected)
			_ = json.Unmarshal(buf.Bytes(), &actual)

			// Compares both to check valid API (and not nil)
			assert.NotNil(expected)
			assert.Equal(expected, actual)
		})
	}
}
