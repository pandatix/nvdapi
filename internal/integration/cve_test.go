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
	var keywords = []string{
		"gitea",
		"rocket-chat",
	}

	for _, kwd := range keywords {
		t.Run(kwd, func(t *testing.T) {
			assert := assert.New(t)

			client := &MdwClient{}
			resp, err := nvdapi.GetCVEs(client, nvdapi.GetCVEsParams{Keyword: &kwd})

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
