# NVD API

[![reference](https://godoc.org/github.com/pandatix/nvdapi/v5?status.svg=)](https://pkg.go.dev/github.com/pandatix/nvdapi)
[![go report](https://goreportcard.com/badge/github.com/pandatix/nvdapi)](https://goreportcard.com/report/github.com/pandatix/nvdapi)
[![codecov](https://codecov.io/gh/pandatix/nvdapi/branch/master/graph/badge.svg)](https://codecov.io/gh/pandatix/nvdapi)
[![CI](https://github.com/pandatix/nvdapi/actions/workflows/ci.yaml/badge.svg)](https://github.com/pandatix/nvdapi/actions?query=workflow%3Aci+)

The NVD API is an unofficial Go wrapper around the [NVD API](https://nvd.nist.gov/General/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement).

Supports:
 - [X] [CVE](https://nvd.nist.gov/developers/vulnerabilities)
 - [X] [CPE](https://nvd.nist.gov/developers/products)

## How to use

The following shows how to basically use the wrapper to get all the CVEs for a given keyword.

```golang
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/pandatix/nvdapi"
)

func main() {
	// Configure and issue the request
	params := nvdapi.GetCVEsParams{
		Keyword: str("gitea"),
	}
	resp, err := nvdapi.GetCVEs(&http.Client{}, params)
	if err != nil {
		log.Fatal(err)
	}

	// Make sure there are CVE items
	if resp.Result.CVEItems == nil {
		return
	}

	for _, item := range *resp.Result.CVEItems {
		fmt.Println(item.CVE.CVEDataMeta.ID)
	}
}

func str(str string) *string {
	return &str
}
```

## How to contribute

Please read first the [code of conduct](https://github.com/pandatix/nvdapi/blob/master/CODE_OF_CONDUCT.md).

To contribute, please refers to [the contribution guide](https://github.com/pandatix/nvdapi/blob/master/CONTRIBUTING.md).

## Contact

To provide feedbacks or submitting an issue, please [file and issue](https://github.com/pandatix/nvdapi/issues).
In case it's regarding a security issue, refers to the [Security guide](https://github.com/pandatix/nvdapi/blob/master/SECURITY.md).
