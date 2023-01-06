package v2_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/pandatix/nvdapi/v2"
	"github.com/stretchr/testify/assert"
)

func Test_V2_GetSource(t *testing.T) {
	var tests = map[string]struct {
		Params nvdapi.GetSourceParams
	}{
		"no-specific-pagination-and-filter": {
			Params: nvdapi.GetSourceParams{},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)
			defer time.Sleep(6 * time.Second)

			mdwclient := &MdwClient{}
			client, _ := nvdapi.NewNVDClient(mdwclient, apiKey)
			resp, err := nvdapi.GetSource(client, tt.Params)

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
