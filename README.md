<div align="center">
	<h1>NVD API</h1>
	<p><b>Unofficial but convenient Go wrapper around the <a href="https://nvd.nist.gov/developers">NVD API</a></b></p>
	<a href="https://pkg.go.dev/github.com/pandatix/nvdapi"><img src="https://shields.io/badge/-reference-blue?logo=go&style=for-the-badge" alt="reference"></a>
	<a href="https://goreportcard.com/report/github.com/pandatix/nvdapi"><img src="https://goreportcard.com/badge/github.com/pandatix/nvdapi?style=for-the-badge" alt="go report"></a>
	<a href="https://coveralls.io/github/pandatix/nvdapi?branch=main"><img src="https://img.shields.io/coverallsCoverage/github/pandatix/nvdapi?style=for-the-badge" alt="Coverage Status"></a>
	<br>
	<a href=""><img src="https://img.shields.io/github/license/pandatix/nvdapi?style=for-the-badge" alt="License"></a>
	<a href="https://github.com/pandatix/nvdapi/actions?query=workflow%3Aci+"><img src="https://img.shields.io/github/actions/workflow/status/pandatix/nvdapi/ci.yaml?style=for-the-badge&label=CI" alt="CI"></a>
	<a href="https://github.com/pandatix/nvdapi/actions/workflows/codeql-analysis.yaml"><img src="https://img.shields.io/github/actions/workflow/status/pandatix/nvdapi/codeql-analysis.yaml?style=for-the-badge&label=CodeQL" alt="CodeQL"></a>
	<br>
	<a href="https://securityscorecards.dev/viewer/?uri=github.com/pandatix/nvdapi"><img src="https://img.shields.io/ossf-scorecard/github.com/pandatix/nvdapi?label=openssf%20scorecard&style=for-the-badge" alt="OpenSSF Scoreboard"></a>
</div>

It supports API v2 with full support of endpoints, and keep support of deprecated for v1 for the sake of History.
Notice that this Go module **does not** enforce the [recommended](https://nvd.nist.gov/developers/start-here#divRateLimits) rate limiting between each request.

> **Warning**
>
> This product uses the NVD API but is not endorsed or certified by the NVD.

## How to use

The following shows how to basically use the wrapper to get a CPE for a given wide CPE match string.

```golang
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/pandatix/nvdapi/v2"
)

func main() {
	apiKey := "<your_nvd_api_key>"
	client, err := nvdapi.NewNVDClient(&http.Client{}, apiKey)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := nvdapi.GetCPEs(client, nvdapi.GetCPEsParams{
		CPEMatchString: ptr("cpe:2.3:*:microsoft"),
		ResultsPerPage: ptr(1),
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, prod := range resp.Products {
		fmt.Println(prod.CPE.CPEName)
	}
}

func ptr[T any](t T) *T {
	return &t
}
```
