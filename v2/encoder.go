package nvdapi

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/pandatix/nvdapi/common"
)

// getEndp is a wrapper around common.GetEndp that reroutes the
// params encoding.
func getEndp(client common.HTTPClient, endp string, params, resp any, opts ...common.Option) error {
	return common.GetEndp(client, endp+"?"+encode(params), nil, resp, opts...)
}

// encode returns an URL query raw string encoded from a given
// struct, due to the NVD services v2 API.
// its formed of 3 parts, separated by a colon (","):
//   - name of attribute
//   - "omitempty" or empty
//   - "noValue" to set the attribute in query but without value,
//     else stays empty
func encode(params any) (out string) {
	elems := []string{}
	v := reflect.ValueOf(params)
	t := reflect.TypeOf(params)

	l := v.NumField()
	for i := 0; i < l; i++ {
		f := v.Field(i)

		tag := t.Field(i).Tag.Get("nvd")
		pts := strings.Split(tag, ",")

		// Skip if omitempty and nil
		if pts[1] == "omitempty" && f.IsNil() {
			continue
		}

		// Deref if pointer
		if f.Kind() == reflect.Pointer {
			f = f.Elem()
		}

		// Write down if don't need value
		if pts[2] == "noValue" && f.Kind() == reflect.Bool && f.Bool() {
			elems = append(elems, pts[0])
			continue
		}

		// Write down
		switch f.Kind() {
		case reflect.String:
			elems = append(elems, pts[0]+"="+url.QueryEscape(f.String()))

		case reflect.Int:
			elems = append(elems, pts[0]+"="+strconv.Itoa(int(f.Int())))

		case reflect.Bool:
			// In this case, will be false.
			// It is problematic as you can't differentiate the complementary binary sets.

		case reflect.TypeOf(EventName("")).Kind():
			// Special kind involved in GetCVEHistoryParams
			elems = append(elems, pts[0]+"="+url.QueryEscape(f.String()))

		default:
			panic(fmt.Sprintf("unhandled type : %v", f.Kind()))
		}
	}

	for i := 0; i < len(elems); i++ {
		if i != 0 {
			out += "&"
		}
		out += elems[i]
	}
	return
}
