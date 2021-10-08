# NVD API

[![reference](https://godoc.org/github.com/PandatiX/nvdapi/v5?status.svg=)](https://pkg.go.dev/github.com/PandatiX/nvdapi)
[![go report](https://goreportcard.com/badge/github.com/PandatiX/nvdapi)](https://goreportcard.com/report/github.com/PandatiX/nvdapi)
[![codecov](https://codecov.io/gh/PandatiX/nvdapi/branch/master/graph/badge.svg)](https://codecov.io/gh/PandatiX/nvdapi)
[![CI](https://github.com/PandatiX/nvdapi/actions/workflows/ci.yaml/badge.svg)](https://github.com/PandatiX/nvdapi/actions?query=workflow%3Aci+)

The NVD API is an unofficial Go wrapper around the [NVD API](https://nvd.nist.gov/General/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement).

Supports:
 - [X] [CVE](https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf)
 - [ ] [CPE](https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CPE%20Retrieval.pdf)

## How to use

The following shows how to basically use the wrapper to get all the CVEs for a given keyword.

```golang
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Pandatix/nvdapi"
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

Please read first the [code of conduct](https://github.com/PandatiX/nvdapi/blob/master/CODE_OF_CONDUCT.md).

To contribute, please refers to [the contribution guide](https://github.com/PandatiX/nvdapi/blob/master/CONTRIBUTING.md).

## Contact

To provide feedbacks or submitting an issue, please [file and issue](https://github.com/PandatiX/nvdapi/issues).
In case it's regarding a security issue, refers to the [Security guide](https://github.com/PandatiX/nvdapi/blob/master/SECURITY.md).
