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

func TestGetCPEs(t *testing.T) {
	assert := assert.New(t)

	client := &MdwClient{}
	resp, err := nvdapi.GetCPEs(client, nvdapi.GetCPEParams{})

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
}
