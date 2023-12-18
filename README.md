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

 - [How to use](#how-to-use)
 - [Reviews on the API](#reviews-on-the-api)
   - [v1](#v1)
   - [v2](#v2)

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

## Reviews on the API

### v1

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

### v2

In the last decade, the NVD grew beyond what was expected years ago, for the best.
This implied a lot of changes, especially with the NVD API. Some feedbacks on it follows.

 - The limit of 2000 results per query (see [documentation](https://nvd.nist.gov/developers/vulnerabilities#divGetCves) for pagination and experimental calls to the API for current limit) enforce the creation of new workflows. For instance, if you are working with an Offline First approach, you'll want to download the whole NVD. The full download is no longer possible through the `.json.zip` files, so you'll need calls to the API. Each call needs a 6 second wait between each, in order to be compliant with official recommandations. With more than 200k CVEs, it imply >100 requests, so >600s of wait (10 min). In addition, with network and disk IO latencies, a full download of the NVD could take up to 12 minutes with a good connectivity. The previous workflow would take around 20 seconds where the new would take around 12 minutes, which is an important decrease of performances. To avoid it, developers would have to create a proxy that handles the paginated download and exposes a JSON ZIP dump of it.
 - All the workflows don't need the whole data. As for the v1 feedback, a GraphQL API could be a good approach to restrein to what the developer really need. Notice that all the current functionalities would be conserved.
 - The CVE History can have a "Changed" action to a detail while being the First Analysis. This is a nonsense as the first details can't be changed from previous values... as they are new.
 - In the [Source schema](https://csrc.nist.gov/schema/nvd/api/2.0/source_api_json_2.0.schema), the source definition don't have property `name` that is indeed returned in the API.
 - In the [CVSS v2.0 schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json), the property `baseSeverity` is not defined despite existing in the API.
 - In the [CVE History schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_history_api_json_2.0.schema), the property `details` is set as not required. This should imply that if empty, the property is not observable in the API responses. Nevertheless, experiments shows that, for instance with the [CVE-1999-1056](https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-1999-1056), it is returned.
 - The boolean parameters (for instance, the `cves` endpoint have optional parameters `hasCertAlerts`, `hasCertNotes`, `hasKev`, `hasOval`, `isVulnerable`, `keywordExactMatch` and `noRejected`). Those are specified in the query without a parameter value, despite the conventions used by the HTTP community since years, and being part of a non-normative sample from the HTML5 documents. Notice this is not defined in RFC 3986 section 3.4. This imply that, for instance with this Go module, it was necessary to develop a specific query encoder to fit this use case (major implementations such as `github.com/gorilla/schema` can't handle this behaviour). This problem would not be one if it does not had operational drawbacks, but there is one. An optional boolean information could have **3** states that imply different things : **not specified** (imply that it is not important, it could be true or false, so it does not filter on this criteria), **specified to true** (imply that it filters the criteria on true, so it removes all the false results) and **specified to false** (imply that it filters the criteria on false, so it removes all the true results). Using the current NVD strategy, you could only have 2 states : not specified and specified to true. In case you want to filter on false, you have to take them all without specifying it, then take them all with specified to true, then exclude results from second to first. This workflow is a complete nonsense for many obvious reasons. For instance, let's suppose you work for a security company that wants to write private OVAL descriptions for its clients. You'll want to get CVEs that matches a CPE criteria (to limit to your clients needs) and does not have an OVAL file. You'll have to get all the CVEs that matches this criteria, then restart with `hasOval` specified and removes from the whole set the results of the last. Finally, after minutes of unnecessary computation due to the fact that you can't send the `hasOval=false` parameter, you could work on your OVAL descriptions. This idea could be propagated to all the other parameters. The best solution is to go back to the convention used by everyone since years i.e. have a **parameter value for optional boolean parameters**.
 - The new endpoints (source, cpematch and cvehistory) are good to have, as they were missing from the v1. In particular, the CVE history data were a real pain to get as you needed scrapping, but over 200k CVEs this could take days. This offers new possibilites in the study and statistics of the NVD dataset. It is also a big step toward tracability: we can now get the information on changes from the API, as we could only get them using scrapping before, which is a highly time-dependent approach.
 - The configurations field changed drastically. In the API v1 data model, a Node could have a set of children or CPEMatch. This recursive relation generalized the deepness of a configuration circuit, leading to different semantic. For instance, for a deepness of 1, it means that there is a set of vulnerable extensions for version intervals. For a deepness of 2, there is a set of vulnerable extensions for version intervals BUT only if they rely side to something else. There could still go on, but historically never did (experimental observation). The API v2 data model removes this recursive relation by setting only a MDC2 tree. Nevertheless, this removes the semantic layer while a deepness of 1 is now represented using a deepness of 2, using a root operator "AND" with a single child node and then a configuration similar to what could it have been in v1: an operator "OR" and a set of CPEMatch. To give an example the CVE-2017-5753 has both configurations of deepness 1 and 2. In the API v1 the distinction was clear, but now it is handled by the schema. It is an improvement as the handling process is easier, but at same time it removes the semantic possibility to have deeper circuits. For instance, if one day we have the strange case where 3 products have to lie together as a tree in order for the vulnerability to be exploitable, the current schema won't be able to handle it. We can imagine an application A running on an OS B (communicating using its API) itself running on an hardware C (using a specific set of CPU instructions) that is vulnerable. Despite it does not seem so realistic as we try that every product has a certain degree of quality and maturity, it could be theoretically possible. This shows a limitation of this new approach, an oversimplification of the data model.
