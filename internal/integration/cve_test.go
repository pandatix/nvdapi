//go:build integration
// +build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pandatix/nvdapi"
	"github.com/stretchr/testify/assert"
)

func TestGetCVE(t *testing.T) {
	var cves = []string{
		"CVE-2015-5611",
		"CVE-2020-14144",
		"CVE-2021-28378",
	}

	for _, cve := range cves {
		t.Run(cve, func(t *testing.T) {
			assert := assert.New(t)

			client := &MdwClient{}
			resp, err := nvdapi.GetCVE(client, nvdapi.GetCVEParams{CVE: cve})

			// Ensure no error
			if !assert.Nil(err) {
				t.Errorf("Last body [%s]\n", client.LastBody)
			}

			// Reencode to JSON
			buf := &bytes.Buffer{}
			_ = json.NewEncoder(buf).Encode(resp)

			// Decode both to interfaces
			var expected interface{}
			var actual interface{}
			_ = json.Unmarshal(client.LastBody, &expected)
			_ = json.Unmarshal(buf.Bytes(), &actual)

			// Compares both to check valid API (and not nil)
			assert.NotNil(expected)
			assert.Equal(expected, actual)
		})
	}
}

func TestGetCVEs(t *testing.T) {
	var tests = map[string]struct {
		Params nvdapi.GetCVEsParams
	}{
		"no-params": {
			Params: nvdapi.GetCVEsParams{},
		},
		"keywords": {
			Params: nvdapi.GetCVEsParams{
				Keyword: str("gitea"),
			},
		},
		"CPE v2.2 match string": {
			Params: nvdapi.GetCVEsParams{
				CPEMatchString: str("cpe:/a:gitea:gitea"),
			},
		},
		"CPE v2.3 match string": {
			Params: nvdapi.GetCVEsParams{
				CPEMatchString: str("cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*"),
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			client := &MdwClient{}
			resp, err := nvdapi.GetCVEs(client, tt.Params)

			// Ensure no error
			if !assert.Nil(err) {
				t.Errorf("Last body [%s]\n", client.LastBody)
			}

			// Reencode to JSON
			buf := &bytes.Buffer{}
			_ = json.NewEncoder(buf).Encode(resp)

			// Decode both to interfaces
			var expected interface{}
			var actual interface{}
			_ = json.Unmarshal(client.LastBody, &expected)
			_ = json.Unmarshal(buf.Bytes(), &actual)

			// Compares both to check valid API (and not nil)
			assert.NotNil(expected)
			assert.Equal(expected, actual)
		})
	}
}

func str(str string) *string {
	return &str
}
