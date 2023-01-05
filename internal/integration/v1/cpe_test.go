package v1_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/pandatix/nvdapi/v1"
	"github.com/stretchr/testify/assert"
)

func Test_V1_GetCPEs(t *testing.T) {
	assert := assert.New(t)
	defer time.Sleep(6 * time.Second)

	client := &MdwClient{}
	resp, err := nvdapi.GetCPEs(client, nvdapi.GetCPEParams{
		APIKey: &apiKey,
	})

	// Ensure no error
	if !assert.Nil(err) {
		t.Errorf("Last body [%s]\n", client.LastBody)
	}

	// Reencode to JSON
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(resp)

	// Decode both to interfaces
	var expected any
	var actual any
	_ = json.Unmarshal(client.LastBody, &expected)
	_ = json.Unmarshal(buf.Bytes(), &actual)

	// Compares both to check valid API (and not nil)
	assert.NotNil(expected)
	assert.Equal(expected, actual)
}
