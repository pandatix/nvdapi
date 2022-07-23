# NVD API

[![reference](https://godoc.org/github.com/pandatix/nvdapi/v5?status.svg=)](https://pkg.go.dev/github.com/pandatix/nvdapi)
[![go report](https://goreportcard.com/badge/github.com/pandatix/nvdapi)](https://goreportcard.com/report/github.com/pandatix/nvdapi)
[![codecov](https://codecov.io/gh/pandatix/nvdapi/branch/main/graph/badge.svg?token=2I1BWR43GI)](https://codecov.io/gh/pandatix/nvdapi)
[![CI](https://github.com/pandatix/nvdapi/actions/workflows/ci.yaml/badge.svg)](https://github.com/pandatix/nvdapi/actions?query=workflow%3Aci+)

The NVD API is an unofficial Go wrapper around the [NVD API](https://nvd.nist.gov/General/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement).

Supports:
 - [X] [CVE](https://nvd.nist.gov/developers/vulnerabilities)
 - [X] [CPE](https://nvd.nist.gov/developers/products)

This product uses the NVD API but is not endorsed or certified by the NVD.

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
	// Configure and execute the request
	resp, err := nvdapi.GetCVEs(&http.Client{}, nvdapi.GetCVEsParams{
		Keyword: ptr("gitea"),
	})
	if err != nil {
		log.Fatal(err)
	}

	// Print each CVE's ID
	for _, item := range resp.Result.CVEItems {
		fmt.Println(item.CVE.CVEDataMeta.ID)
	}
}

func ptr[T any](t T) *T {
	return &t
}
```

## Reviews on the API

While giving the JSON schema of both main endpoints (CVE and CPE) was a really good practice to enable implementations in various languages and to avoid guessing types, structures and descriptions (what each field means, its goal(s) and how it should get formatted), there are a few things that could get changed to improve this schema. Notice in the last version of the documentation, some requirements changed, and the quality of the schema decreased as we only know how are structured the high-level fields.

First of all, CVE and CPE schemas cannot merge at this point of time: CPEs can be associated to a CVE through this first's schema, but the last's schema is not embeded into the first (without reciprocity). This implies that the API does not have 1 unique schema, but two different ones that lives separately, laying on the same database behind (based on asumptions).

About the schemas, more than they cannot merge, it contains multiple useless layers to access the data, some fields are useless (like the number of fields in an array, that can easily get computed in most languages) and properties contains redundant data (like containing "date" in the name for a property typed as a DateTime, or "score" for Subscore).

Moreover, there is logic implied in the queries at the datastructure level, which can only get checked at the server level without any validation at the client level. This kind of issue can get fixed through splitting the parameters in a same group, making the high level parameter optional and sub-parameters required if needed.
For instance, when time boundaries are required at the same time in a query, they can get in the same optional sub-parameter while being both required. This makes the logic enforced at the schema level without documenting it.

Finally, improvements containing those reviews can be made to move from a REST JSON API to a GraphQL API. This would improve a lot the ability to make queries on CVE and CPE at the same time, while enabling documentation and schema discovery on introspection queries.
Notice this improvement can be made without having to change the data layer. Nevertheless, changing it to a graph-oriented data layer can enable multi-directional relations that can permit travelling through the data as the user may need to according to its specific use case (like entering the data from a CVE id, a vendor name, a product name, a CPE name, or reversing a CVE and its references from a CVSS V3 vector string). This kind of searchs can also be implemented with a relational database, but will need complex computations to retrieve the needed data in complex scenarios.
Notice also that there would be a N+1 issue on the CVE/CPE schema merge where a defense mecanism should be implemented to avoid having too complex queries that could lead to a server crash (in case CVE references CPEs and CPE references CVEs).
Another notice is that types that needs validation (based on regex for URIs, emails addresses, or bound for Subscore) can be enforced by GraphQL Scalars.
Finally, the API key mecanism that is currently being implemented can also work for a GraphQL API, in the queries datastructure or using headers.

## How to contribute

Please read first the [code of conduct](https://github.com/pandatix/nvdapi/blob/master/CODE_OF_CONDUCT.md).

To contribute, please refers to [the contribution guide](https://github.com/pandatix/nvdapi/blob/master/CONTRIBUTING.md).

## Contact

To provide feedbacks or submitting an issue, please [file and issue](https://github.com/pandatix/nvdapi/issues).
In case it's regarding a security issue, refers to the [Security guide](https://github.com/pandatix/nvdapi/blob/master/SECURITY.md).
