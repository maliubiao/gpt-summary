Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:**  The filename `url_test.go` immediately suggests this is a testing file. The presence of `package url` and imports like `testing` reinforce this. The core purpose is to test the `net/url` package.

2. **Look for Test Structures:**  The code defines a struct `URLTest` and a slice of these structs named `urltests`. This is a very common pattern in Go testing. Each `URLTest` likely represents a single test case.

3. **Analyze the `URLTest` Structure:** The fields `in`, `out`, and `roundtrip` are key.
    * `in`:  Likely the input string representing a URL.
    * `out`:  Likely the *expected* parsed `URL` struct after processing `in`.
    * `roundtrip`:  Suggests testing the serialization and deserialization of the URL. An empty string likely means the output of `String()` should match the input.

4. **Examine the `urltests` Data:**  Scanning through the `urltests` data provides concrete examples of how the `url` package is expected to behave. Pay attention to different URL components:
    * Scheme, host, path, query, fragment
    * User info (username, password)
    * Escaped characters
    * Edge cases (empty query, paths without leading slashes, etc.)
    * IPv6 addresses

5. **Identify Key Test Functions:**  The presence of `TestParse` and `BenchmarkString` clearly indicates the testing of the `Parse` function (likely to parse a URL string) and the `String` method (likely to serialize a URL back to a string).

6. **Infer Functionality of `Parse`:** Based on the test data, `Parse` likely takes a string as input and returns a `URL` struct. It needs to handle various URL formats and correctly populate the fields of the `URL` struct. The presence of `RawPath` and `RawQuery` suggests that it also preserves the raw, encoded parts of the URL.

7. **Infer Functionality of `String`:** The `roundtrip` field in `URLTest` and the `BenchmarkString` function confirm that the `String` method serializes the `URL` struct back into a string representation.

8. **Look for Other Test Functions:** The code contains `TestParseRequestURI`, `TestURLString`, `TestURLRedacted`, `TestUnescape`, `TestQueryEscape`, `TestPathEscape`, `TestEncodeQuery`, `TestResolvePath`, `TestResolveReference`, and `TestQueryValues`. Each of these tests likely focuses on a specific aspect of the `net/url` package.

9. **Infer Functionality of Other Tested Functions:** Based on their names and surrounding context:
    * `ParseRequestURI`: Likely parses a URL specifically as a request URI (different from a full URL).
    * `URLString`:  Further tests the `String` method.
    * `URLRedacted`: Tests a method to redact potentially sensitive information in a URL (like the password).
    * `Unescape`, `QueryUnescape`, `PathUnescape`: Functions for decoding URL-encoded strings.
    * `QueryEscape`, `PathEscape`: Functions for encoding strings for use in URLs.
    * `EncodeQuery`:  Likely for encoding a map of key-value pairs into a query string.
    * `ResolvePath`:  Handles resolving relative paths within a base path.
    * `ResolveReference`:  Resolves a relative URL reference against a base URL.
    * `QueryValues`:  Tests how to access and manipulate the query parameters of a URL.

10. **Consider Potential Mistakes:**  Based on the test cases, things like incorrect handling of escaped characters, differences between full URLs and request URIs, and the handling of relative paths are potential areas where users might make mistakes. The test for `URLRedacted` highlights the importance of being mindful of sensitive data in URLs.

11. **Synthesize the Summary:** Combine the understanding of the individual test cases and functions to provide a concise overview of the file's purpose and the functionality it tests. Emphasize the core goal of verifying the correctness of URL parsing, manipulation, and serialization.

12. **Refine the Explanation:** Organize the information logically. Start with the main purpose, then detail the key components (test data, main functions, other tested functionalities). Use clear language and provide illustrative code examples where possible (even if not explicitly asked for in *this* specific prompt, it's a good habit). Think about how a developer would use this information to understand the code.
这是对Go语言标准库 `net/url` 包中 `url_test.go` 文件的一部分内容。这个文件的主要功能是**测试 `net/url` 包中关于 URL 解析和操作的相关功能。**

具体来说，从这段代码中可以看出它正在测试以下核心功能：

1. **`Parse` 函数的正确性:**  `Parse` 函数负责将字符串解析为 `URL` 结构体。  `urltests` 变量定义了一系列测试用例，每个用例包含一个输入字符串 (`in`) 和期望解析得到的 `URL` 结构体 (`out`)。 此外，部分用例还包含 `roundtrip` 字段，用于测试解析后的 `URL` 结构体重新序列化成字符串 (`String()` 方法) 后是否与预期一致。

2. **`String` 方法的正确性:**  `String` 方法将 `URL` 结构体转换回字符串表示形式。 测试用例通过 `roundtrip` 字段验证了 `Parse` 和 `String` 的组合使用是否能保持 URL 的完整性。

3. **URL 结构体的字段解析:**  通过比对 `in` 和 `out`，测试用例涵盖了 URL 的各个组成部分，例如：
    * `Scheme` (协议)
    * `Host` (主机名)
    * `Path` (路径)
    * `RawPath` (原始路径，包含未解码的转义字符)
    * `Fragment` (片段标识符)
    * `RawFragment` (原始片段标识符)
    * `User` (用户信息，包括用户名和密码)
    * `RawQuery` (原始查询字符串)
    * `ForceQuery` (是否强制显示查询字符串的问号)
    * `Opaque` (不透明部分)
    * `OmitHost` (是否省略主机)

**可以推理出 `net/url` 包实现了 URL 的解析和序列化功能。**

**Go 代码示例说明 `Parse` 和 `String` 的用法：**

```go
package main

import (
	"fmt"
	"net/url"
)

func main() {
	urlString := "https://user:password@example.com:8080/path/to/resource?query=param#fragment"
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		fmt.Println("解析 URL 失败:", err)
		return
	}

	fmt.Println("解析后的 URL 结构体:", parsedURL)
	fmt.Println("协议:", parsedURL.Scheme)
	fmt.Println("用户名:", parsedURL.User.Username())
	password, _ := parsedURL.User.Password()
	fmt.Println("密码:", password)
	fmt.Println("主机:", parsedURL.Host)
	fmt.Println("路径:", parsedURL.Path)
	fmt.Println("原始路径:", parsedURL.RawPath)
	fmt.Println("查询参数:", parsedURL.RawQuery)
	fmt.Println("片段标识符:", parsedURL.Fragment)
	fmt.Println("原始片段标识符:", parsedURL.RawFragment)

	reconstructedURL := parsedURL.String()
	fmt.Println("重新构建的 URL 字符串:", reconstructedURL)
}
```

**假设的输入与输出：**

**输入:** `urlString := "http://www.example.com/index.html?param1=value1&param2=value2#section"`

**输出:**

```
解析后的 URL 结构体: &{http user:0xc0000a0180@www.example.com  /index.html  param1=value1&param2=value2 section }
协议: http
用户名:
密码:
主机: www.example.com
路径: /index.html
原始路径:
查询参数: param1=value1&param2=value2
片段标识符: section
原始片段标识符: section
重新构建的 URL 字符串: http://www.example.com/index.html?param1=value1&param2=value2#section
```

**功能归纳：**

这段代码的主要功能是定义了一系列的测试用例，用于验证 `net/url` 包中的 `Parse` 函数能否正确地将 URL 字符串解析为 `URL` 结构体，并且验证 `URL` 结构体的 `String` 方法能否正确地将解析后的 URL 重新序列化为字符串。 这些测试用例覆盖了 URL 的各种常见和特殊情况，旨在确保 `net/url` 包的 URL 解析和序列化功能的正确性和鲁棒性。

Prompt: 
```
这是路径为go/src/net/url/url_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package url

import (
	"bytes"
	encodingPkg "encoding"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

type URLTest struct {
	in        string
	out       *URL   // expected parse
	roundtrip string // expected result of reserializing the URL; empty means same as "in".
}

var urltests = []URLTest{
	// no path
	{
		"http://www.google.com",
		&URL{
			Scheme: "http",
			Host:   "www.google.com",
		},
		"",
	},
	// path
	{
		"http://www.google.com/",
		&URL{
			Scheme: "http",
			Host:   "www.google.com",
			Path:   "/",
		},
		"",
	},
	// path with hex escaping
	{
		"http://www.google.com/file%20one%26two",
		&URL{
			Scheme:  "http",
			Host:    "www.google.com",
			Path:    "/file one&two",
			RawPath: "/file%20one%26two",
		},
		"",
	},
	// fragment with hex escaping
	{
		"http://www.google.com/#file%20one%26two",
		&URL{
			Scheme:      "http",
			Host:        "www.google.com",
			Path:        "/",
			Fragment:    "file one&two",
			RawFragment: "file%20one%26two",
		},
		"",
	},
	// user
	{
		"ftp://webmaster@www.google.com/",
		&URL{
			Scheme: "ftp",
			User:   User("webmaster"),
			Host:   "www.google.com",
			Path:   "/",
		},
		"",
	},
	// escape sequence in username
	{
		"ftp://john%20doe@www.google.com/",
		&URL{
			Scheme: "ftp",
			User:   User("john doe"),
			Host:   "www.google.com",
			Path:   "/",
		},
		"ftp://john%20doe@www.google.com/",
	},
	// empty query
	{
		"http://www.google.com/?",
		&URL{
			Scheme:     "http",
			Host:       "www.google.com",
			Path:       "/",
			ForceQuery: true,
		},
		"",
	},
	// query ending in question mark (Issue 14573)
	{
		"http://www.google.com/?foo=bar?",
		&URL{
			Scheme:   "http",
			Host:     "www.google.com",
			Path:     "/",
			RawQuery: "foo=bar?",
		},
		"",
	},
	// query
	{
		"http://www.google.com/?q=go+language",
		&URL{
			Scheme:   "http",
			Host:     "www.google.com",
			Path:     "/",
			RawQuery: "q=go+language",
		},
		"",
	},
	// query with hex escaping: NOT parsed
	{
		"http://www.google.com/?q=go%20language",
		&URL{
			Scheme:   "http",
			Host:     "www.google.com",
			Path:     "/",
			RawQuery: "q=go%20language",
		},
		"",
	},
	// %20 outside query
	{
		"http://www.google.com/a%20b?q=c+d",
		&URL{
			Scheme:   "http",
			Host:     "www.google.com",
			Path:     "/a b",
			RawQuery: "q=c+d",
		},
		"",
	},
	// path without leading /, so no parsing
	{
		"http:www.google.com/?q=go+language",
		&URL{
			Scheme:   "http",
			Opaque:   "www.google.com/",
			RawQuery: "q=go+language",
		},
		"http:www.google.com/?q=go+language",
	},
	// path without leading /, so no parsing
	{
		"http:%2f%2fwww.google.com/?q=go+language",
		&URL{
			Scheme:   "http",
			Opaque:   "%2f%2fwww.google.com/",
			RawQuery: "q=go+language",
		},
		"http:%2f%2fwww.google.com/?q=go+language",
	},
	// non-authority with path; see golang.org/issue/46059
	{
		"mailto:/webmaster@golang.org",
		&URL{
			Scheme:   "mailto",
			Path:     "/webmaster@golang.org",
			OmitHost: true,
		},
		"",
	},
	// non-authority
	{
		"mailto:webmaster@golang.org",
		&URL{
			Scheme: "mailto",
			Opaque: "webmaster@golang.org",
		},
		"",
	},
	// unescaped :// in query should not create a scheme
	{
		"/foo?query=http://bad",
		&URL{
			Path:     "/foo",
			RawQuery: "query=http://bad",
		},
		"",
	},
	// leading // without scheme should create an authority
	{
		"//foo",
		&URL{
			Host: "foo",
		},
		"",
	},
	// leading // without scheme, with userinfo, path, and query
	{
		"//user@foo/path?a=b",
		&URL{
			User:     User("user"),
			Host:     "foo",
			Path:     "/path",
			RawQuery: "a=b",
		},
		"",
	},
	// Three leading slashes isn't an authority, but doesn't return an error.
	// (We can't return an error, as this code is also used via
	// ServeHTTP -> ReadRequest -> Parse, which is arguably a
	// different URL parsing context, but currently shares the
	// same codepath)
	{
		"///threeslashes",
		&URL{
			Path: "///threeslashes",
		},
		"",
	},
	{
		"http://user:password@google.com",
		&URL{
			Scheme: "http",
			User:   UserPassword("user", "password"),
			Host:   "google.com",
		},
		"http://user:password@google.com",
	},
	// unescaped @ in username should not confuse host
	{
		"http://j@ne:password@google.com",
		&URL{
			Scheme: "http",
			User:   UserPassword("j@ne", "password"),
			Host:   "google.com",
		},
		"http://j%40ne:password@google.com",
	},
	// unescaped @ in password should not confuse host
	{
		"http://jane:p@ssword@google.com",
		&URL{
			Scheme: "http",
			User:   UserPassword("jane", "p@ssword"),
			Host:   "google.com",
		},
		"http://jane:p%40ssword@google.com",
	},
	{
		"http://j@ne:password@google.com/p@th?q=@go",
		&URL{
			Scheme:   "http",
			User:     UserPassword("j@ne", "password"),
			Host:     "google.com",
			Path:     "/p@th",
			RawQuery: "q=@go",
		},
		"http://j%40ne:password@google.com/p@th?q=@go",
	},
	{
		"http://www.google.com/?q=go+language#foo",
		&URL{
			Scheme:   "http",
			Host:     "www.google.com",
			Path:     "/",
			RawQuery: "q=go+language",
			Fragment: "foo",
		},
		"",
	},
	{
		"http://www.google.com/?q=go+language#foo&bar",
		&URL{
			Scheme:   "http",
			Host:     "www.google.com",
			Path:     "/",
			RawQuery: "q=go+language",
			Fragment: "foo&bar",
		},
		"http://www.google.com/?q=go+language#foo&bar",
	},
	{
		"http://www.google.com/?q=go+language#foo%26bar",
		&URL{
			Scheme:      "http",
			Host:        "www.google.com",
			Path:        "/",
			RawQuery:    "q=go+language",
			Fragment:    "foo&bar",
			RawFragment: "foo%26bar",
		},
		"http://www.google.com/?q=go+language#foo%26bar",
	},
	{
		"file:///home/adg/rabbits",
		&URL{
			Scheme: "file",
			Host:   "",
			Path:   "/home/adg/rabbits",
		},
		"file:///home/adg/rabbits",
	},
	// "Windows" paths are no exception to the rule.
	// See golang.org/issue/6027, especially comment #9.
	{
		"file:///C:/FooBar/Baz.txt",
		&URL{
			Scheme: "file",
			Host:   "",
			Path:   "/C:/FooBar/Baz.txt",
		},
		"file:///C:/FooBar/Baz.txt",
	},
	// case-insensitive scheme
	{
		"MaIlTo:webmaster@golang.org",
		&URL{
			Scheme: "mailto",
			Opaque: "webmaster@golang.org",
		},
		"mailto:webmaster@golang.org",
	},
	// Relative path
	{
		"a/b/c",
		&URL{
			Path: "a/b/c",
		},
		"a/b/c",
	},
	// escaped '?' in username and password
	{
		"http://%3Fam:pa%3Fsword@google.com",
		&URL{
			Scheme: "http",
			User:   UserPassword("?am", "pa?sword"),
			Host:   "google.com",
		},
		"",
	},
	// host subcomponent; IPv4 address in RFC 3986
	{
		"http://192.168.0.1/",
		&URL{
			Scheme: "http",
			Host:   "192.168.0.1",
			Path:   "/",
		},
		"",
	},
	// host and port subcomponents; IPv4 address in RFC 3986
	{
		"http://192.168.0.1:8080/",
		&URL{
			Scheme: "http",
			Host:   "192.168.0.1:8080",
			Path:   "/",
		},
		"",
	},
	// host subcomponent; IPv6 address in RFC 3986
	{
		"http://[fe80::1]/",
		&URL{
			Scheme: "http",
			Host:   "[fe80::1]",
			Path:   "/",
		},
		"",
	},
	// host and port subcomponents; IPv6 address in RFC 3986
	{
		"http://[fe80::1]:8080/",
		&URL{
			Scheme: "http",
			Host:   "[fe80::1]:8080",
			Path:   "/",
		},
		"",
	},
	// host subcomponent; IPv6 address with zone identifier in RFC 6874
	{
		"http://[fe80::1%25en0]/", // alphanum zone identifier
		&URL{
			Scheme: "http",
			Host:   "[fe80::1%en0]",
			Path:   "/",
		},
		"",
	},
	// host and port subcomponents; IPv6 address with zone identifier in RFC 6874
	{
		"http://[fe80::1%25en0]:8080/", // alphanum zone identifier
		&URL{
			Scheme: "http",
			Host:   "[fe80::1%en0]:8080",
			Path:   "/",
		},
		"",
	},
	// host subcomponent; IPv6 address with zone identifier in RFC 6874
	{
		"http://[fe80::1%25%65%6e%301-._~]/", // percent-encoded+unreserved zone identifier
		&URL{
			Scheme: "http",
			Host:   "[fe80::1%en01-._~]",
			Path:   "/",
		},
		"http://[fe80::1%25en01-._~]/",
	},
	// host and port subcomponents; IPv6 address with zone identifier in RFC 6874
	{
		"http://[fe80::1%25%65%6e%301-._~]:8080/", // percent-encoded+unreserved zone identifier
		&URL{
			Scheme: "http",
			Host:   "[fe80::1%en01-._~]:8080",
			Path:   "/",
		},
		"http://[fe80::1%25en01-._~]:8080/",
	},
	// alternate escapings of path survive round trip
	{
		"http://rest.rsc.io/foo%2fbar/baz%2Fquux?alt=media",
		&URL{
			Scheme:   "http",
			Host:     "rest.rsc.io",
			Path:     "/foo/bar/baz/quux",
			RawPath:  "/foo%2fbar/baz%2Fquux",
			RawQuery: "alt=media",
		},
		"",
	},
	// issue 12036
	{
		"mysql://a,b,c/bar",
		&URL{
			Scheme: "mysql",
			Host:   "a,b,c",
			Path:   "/bar",
		},
		"",
	},
	// worst case host, still round trips
	{
		"scheme://!$&'()*+,;=hello!:1/path",
		&URL{
			Scheme: "scheme",
			Host:   "!$&'()*+,;=hello!:1",
			Path:   "/path",
		},
		"",
	},
	// worst case path, still round trips
	{
		"http://host/!$&'()*+,;=:@[hello]",
		&URL{
			Scheme:  "http",
			Host:    "host",
			Path:    "/!$&'()*+,;=:@[hello]",
			RawPath: "/!$&'()*+,;=:@[hello]",
		},
		"",
	},
	// golang.org/issue/5684
	{
		"http://example.com/oid/[order_id]",
		&URL{
			Scheme:  "http",
			Host:    "example.com",
			Path:    "/oid/[order_id]",
			RawPath: "/oid/[order_id]",
		},
		"",
	},
	// golang.org/issue/12200 (colon with empty port)
	{
		"http://192.168.0.2:8080/foo",
		&URL{
			Scheme: "http",
			Host:   "192.168.0.2:8080",
			Path:   "/foo",
		},
		"",
	},
	{
		"http://192.168.0.2:/foo",
		&URL{
			Scheme: "http",
			Host:   "192.168.0.2:",
			Path:   "/foo",
		},
		"",
	},
	{
		// Malformed IPv6 but still accepted.
		"http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080/foo",
		&URL{
			Scheme: "http",
			Host:   "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080",
			Path:   "/foo",
		},
		"",
	},
	{
		// Malformed IPv6 but still accepted.
		"http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:/foo",
		&URL{
			Scheme: "http",
			Host:   "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:",
			Path:   "/foo",
		},
		"",
	},
	{
		"http://[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080/foo",
		&URL{
			Scheme: "http",
			Host:   "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080",
			Path:   "/foo",
		},
		"",
	},
	{
		"http://[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:/foo",
		&URL{
			Scheme: "http",
			Host:   "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:",
			Path:   "/foo",
		},
		"",
	},
	// golang.org/issue/7991 and golang.org/issue/12719 (non-ascii %-encoded in host)
	{
		"http://hello.世界.com/foo",
		&URL{
			Scheme: "http",
			Host:   "hello.世界.com",
			Path:   "/foo",
		},
		"http://hello.%E4%B8%96%E7%95%8C.com/foo",
	},
	{
		"http://hello.%e4%b8%96%e7%95%8c.com/foo",
		&URL{
			Scheme: "http",
			Host:   "hello.世界.com",
			Path:   "/foo",
		},
		"http://hello.%E4%B8%96%E7%95%8C.com/foo",
	},
	{
		"http://hello.%E4%B8%96%E7%95%8C.com/foo",
		&URL{
			Scheme: "http",
			Host:   "hello.世界.com",
			Path:   "/foo",
		},
		"",
	},
	// golang.org/issue/10433 (path beginning with //)
	{
		"http://example.com//foo",
		&URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "//foo",
		},
		"",
	},
	// test that we can reparse the host names we accept.
	{
		"myscheme://authority<\"hi\">/foo",
		&URL{
			Scheme: "myscheme",
			Host:   "authority<\"hi\">",
			Path:   "/foo",
		},
		"",
	},
	// spaces in hosts are disallowed but escaped spaces in IPv6 scope IDs are grudgingly OK.
	// This happens on Windows.
	// golang.org/issue/14002
	{
		"tcp://[2020::2020:20:2020:2020%25Windows%20Loves%20Spaces]:2020",
		&URL{
			Scheme: "tcp",
			Host:   "[2020::2020:20:2020:2020%Windows Loves Spaces]:2020",
		},
		"",
	},
	// test we can roundtrip magnet url
	// fix issue https://golang.org/issue/20054
	{
		"magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn",
		&URL{
			Scheme:   "magnet",
			Host:     "",
			Path:     "",
			RawQuery: "xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn",
		},
		"magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn",
	},
	{
		"mailto:?subject=hi",
		&URL{
			Scheme:   "mailto",
			Host:     "",
			Path:     "",
			RawQuery: "subject=hi",
		},
		"mailto:?subject=hi",
	},
}

// more useful string for debugging than fmt's struct printer
func ufmt(u *URL) string {
	var user, pass any
	if u.User != nil {
		user = u.User.Username()
		if p, ok := u.User.Password(); ok {
			pass = p
		}
	}
	return fmt.Sprintf("opaque=%q, scheme=%q, user=%#v, pass=%#v, host=%q, path=%q, rawpath=%q, rawq=%q, frag=%q, rawfrag=%q, forcequery=%v, omithost=%t",
		u.Opaque, u.Scheme, user, pass, u.Host, u.Path, u.RawPath, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery, u.OmitHost)
}

func BenchmarkString(b *testing.B) {
	b.StopTimer()
	b.ReportAllocs()
	for _, tt := range urltests {
		u, err := Parse(tt.in)
		if err != nil {
			b.Errorf("Parse(%q) returned error %s", tt.in, err)
			continue
		}
		if tt.roundtrip == "" {
			continue
		}
		b.StartTimer()
		var g string
		for i := 0; i < b.N; i++ {
			g = u.String()
		}
		b.StopTimer()
		if w := tt.roundtrip; b.N > 0 && g != w {
			b.Errorf("Parse(%q).String() == %q, want %q", tt.in, g, w)
		}
	}
}

func TestParse(t *testing.T) {
	for _, tt := range urltests {
		u, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q) returned error %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(u, tt.out) {
			t.Errorf("Parse(%q):\n\tgot  %v\n\twant %v\n", tt.in, ufmt(u), ufmt(tt.out))
		}
	}
}

const pathThatLooksSchemeRelative = "//not.a.user@not.a.host/just/a/path"

var parseRequestURLTests = []struct {
	url           string
	expectedValid bool
}{
	{"http://foo.com", true},
	{"http://foo.com/", true},
	{"http://foo.com/path", true},
	{"/", true},
	{pathThatLooksSchemeRelative, true},
	{"//not.a.user@%66%6f%6f.com/just/a/path/also", true},
	{"*", true},
	{"http://192.168.0.1/", true},
	{"http://192.168.0.1:8080/", true},
	{"http://[fe80::1]/", true},
	{"http://[fe80::1]:8080/", true},

	// Tests exercising RFC 6874 compliance:
	{"http://[fe80::1%25en0]/", true},                 // with alphanum zone identifier
	{"http://[fe80::1%25en0]:8080/", true},            // with alphanum zone identifier
	{"http://[fe80::1%25%65%6e%301-._~]/", true},      // with percent-encoded+unreserved zone identifier
	{"http://[fe80::1%25%65%6e%301-._~]:8080/", true}, // with percent-encoded+unreserved zone identifier

	{"foo.html", false},
	{"../dir/", false},
	{" http://foo.com", false},
	{"http://192.168.0.%31/", false},
	{"http://192.168.0.%31:8080/", false},
	{"http://[fe80::%31]/", false},
	{"http://[fe80::%31]:8080/", false},
	{"http://[fe80::%31%25en0]/", false},
	{"http://[fe80::%31%25en0]:8080/", false},

	// These two cases are valid as textual representations as
	// described in RFC 4007, but are not valid as address
	// literals with IPv6 zone identifiers in URIs as described in
	// RFC 6874.
	{"http://[fe80::1%en0]/", false},
	{"http://[fe80::1%en0]:8080/", false},
}

func TestParseRequestURI(t *testing.T) {
	for _, test := range parseRequestURLTests {
		_, err := ParseRequestURI(test.url)
		if test.expectedValid && err != nil {
			t.Errorf("ParseRequestURI(%q) gave err %v; want no error", test.url, err)
		} else if !test.expectedValid && err == nil {
			t.Errorf("ParseRequestURI(%q) gave nil error; want some error", test.url)
		}
	}

	url, err := ParseRequestURI(pathThatLooksSchemeRelative)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	if url.Path != pathThatLooksSchemeRelative {
		t.Errorf("ParseRequestURI path:\ngot  %q\nwant %q", url.Path, pathThatLooksSchemeRelative)
	}
}

var stringURLTests = []struct {
	url  URL
	want string
}{
	// No leading slash on path should prepend slash on String() call
	{
		url: URL{
			Scheme: "http",
			Host:   "www.google.com",
			Path:   "search",
		},
		want: "http://www.google.com/search",
	},
	// Relative path with first element containing ":" should be prepended with "./", golang.org/issue/17184
	{
		url: URL{
			Path: "this:that",
		},
		want: "./this:that",
	},
	// Relative path with second element containing ":" should not be prepended with "./"
	{
		url: URL{
			Path: "here/this:that",
		},
		want: "here/this:that",
	},
	// Non-relative path with first element containing ":" should not be prepended with "./"
	{
		url: URL{
			Scheme: "http",
			Host:   "www.google.com",
			Path:   "this:that",
		},
		want: "http://www.google.com/this:that",
	},
}

func TestURLString(t *testing.T) {
	for _, tt := range urltests {
		u, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q) returned error %s", tt.in, err)
			continue
		}
		expected := tt.in
		if tt.roundtrip != "" {
			expected = tt.roundtrip
		}
		s := u.String()
		if s != expected {
			t.Errorf("Parse(%q).String() == %q (expected %q)", tt.in, s, expected)
		}
	}

	for _, tt := range stringURLTests {
		if got := tt.url.String(); got != tt.want {
			t.Errorf("%+v.String() = %q; want %q", tt.url, got, tt.want)
		}
	}
}

func TestURLRedacted(t *testing.T) {
	cases := []struct {
		name string
		url  *URL
		want string
	}{
		{
			name: "non-blank Password",
			url: &URL{
				Scheme: "http",
				Host:   "host.tld",
				Path:   "this:that",
				User:   UserPassword("user", "password"),
			},
			want: "http://user:xxxxx@host.tld/this:that",
		},
		{
			name: "blank Password",
			url: &URL{
				Scheme: "http",
				Host:   "host.tld",
				Path:   "this:that",
				User:   User("user"),
			},
			want: "http://user@host.tld/this:that",
		},
		{
			name: "nil User",
			url: &URL{
				Scheme: "http",
				Host:   "host.tld",
				Path:   "this:that",
				User:   UserPassword("", "password"),
			},
			want: "http://:xxxxx@host.tld/this:that",
		},
		{
			name: "blank Username, blank Password",
			url: &URL{
				Scheme: "http",
				Host:   "host.tld",
				Path:   "this:that",
			},
			want: "http://host.tld/this:that",
		},
		{
			name: "empty URL",
			url:  &URL{},
			want: "",
		},
		{
			name: "nil URL",
			url:  nil,
			want: "",
		},
	}

	for _, tt := range cases {
		t := t
		t.Run(tt.name, func(t *testing.T) {
			if g, w := tt.url.Redacted(), tt.want; g != w {
				t.Fatalf("got: %q\nwant: %q", g, w)
			}
		})
	}
}

type EscapeTest struct {
	in  string
	out string
	err error
}

var unescapeTests = []EscapeTest{
	{
		"",
		"",
		nil,
	},
	{
		"abc",
		"abc",
		nil,
	},
	{
		"1%41",
		"1A",
		nil,
	},
	{
		"1%41%42%43",
		"1ABC",
		nil,
	},
	{
		"%4a",
		"J",
		nil,
	},
	{
		"%6F",
		"o",
		nil,
	},
	{
		"%", // not enough characters after %
		"",
		EscapeError("%"),
	},
	{
		"%a", // not enough characters after %
		"",
		EscapeError("%a"),
	},
	{
		"%1", // not enough characters after %
		"",
		EscapeError("%1"),
	},
	{
		"123%45%6", // not enough characters after %
		"",
		EscapeError("%6"),
	},
	{
		"%zzzzz", // invalid hex digits
		"",
		EscapeError("%zz"),
	},
	{
		"a+b",
		"a b",
		nil,
	},
	{
		"a%20b",
		"a b",
		nil,
	},
}

func TestUnescape(t *testing.T) {
	for _, tt := range unescapeTests {
		actual, err := QueryUnescape(tt.in)
		if actual != tt.out || (err != nil) != (tt.err != nil) {
			t.Errorf("QueryUnescape(%q) = %q, %s; want %q, %s", tt.in, actual, err, tt.out, tt.err)
		}

		in := tt.in
		out := tt.out
		if strings.Contains(tt.in, "+") {
			in = strings.ReplaceAll(tt.in, "+", "%20")
			actual, err := PathUnescape(in)
			if actual != tt.out || (err != nil) != (tt.err != nil) {
				t.Errorf("PathUnescape(%q) = %q, %s; want %q, %s", in, actual, err, tt.out, tt.err)
			}
			if tt.err == nil {
				s, err := QueryUnescape(strings.ReplaceAll(tt.in, "+", "XXX"))
				if err != nil {
					continue
				}
				in = tt.in
				out = strings.ReplaceAll(s, "XXX", "+")
			}
		}

		actual, err = PathUnescape(in)
		if actual != out || (err != nil) != (tt.err != nil) {
			t.Errorf("PathUnescape(%q) = %q, %s; want %q, %s", in, actual, err, out, tt.err)
		}
	}
}

var queryEscapeTests = []EscapeTest{
	{
		"",
		"",
		nil,
	},
	{
		"abc",
		"abc",
		nil,
	},
	{
		"one two",
		"one+two",
		nil,
	},
	{
		"10%",
		"10%25",
		nil,
	},
	{
		" ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;",
		"+%3F%26%3D%23%2B%25%21%3C%3E%23%22%7B%7D%7C%5C%5E%5B%5D%60%E2%98%BA%09%3A%2F%40%24%27%28%29%2A%2C%3B",
		nil,
	},
}

func TestQueryEscape(t *testing.T) {
	for _, tt := range queryEscapeTests {
		actual := QueryEscape(tt.in)
		if tt.out != actual {
			t.Errorf("QueryEscape(%q) = %q, want %q", tt.in, actual, tt.out)
		}

		// for bonus points, verify that escape:unescape is an identity.
		roundtrip, err := QueryUnescape(actual)
		if roundtrip != tt.in || err != nil {
			t.Errorf("QueryUnescape(%q) = %q, %s; want %q, %s", actual, roundtrip, err, tt.in, "[no error]")
		}
	}
}

var pathEscapeTests = []EscapeTest{
	{
		"",
		"",
		nil,
	},
	{
		"abc",
		"abc",
		nil,
	},
	{
		"abc+def",
		"abc+def",
		nil,
	},
	{
		"a/b",
		"a%2Fb",
		nil,
	},
	{
		"one two",
		"one%20two",
		nil,
	},
	{
		"10%",
		"10%25",
		nil,
	},
	{
		" ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;",
		"%20%3F&=%23+%25%21%3C%3E%23%22%7B%7D%7C%5C%5E%5B%5D%60%E2%98%BA%09:%2F@$%27%28%29%2A%2C%3B",
		nil,
	},
}

func TestPathEscape(t *testing.T) {
	for _, tt := range pathEscapeTests {
		actual := PathEscape(tt.in)
		if tt.out != actual {
			t.Errorf("PathEscape(%q) = %q, want %q", tt.in, actual, tt.out)
		}

		// for bonus points, verify that escape:unescape is an identity.
		roundtrip, err := PathUnescape(actual)
		if roundtrip != tt.in || err != nil {
			t.Errorf("PathUnescape(%q) = %q, %s; want %q, %s", actual, roundtrip, err, tt.in, "[no error]")
		}
	}
}

//var userinfoTests = []UserinfoTest{
//	{"user", "password", "user:password"},
//	{"foo:bar", "~!@#$%^&*()_+{}|[]\\-=`:;'\"<>?,./",
//		"foo%3Abar:~!%40%23$%25%5E&*()_+%7B%7D%7C%5B%5D%5C-=%60%3A;'%22%3C%3E?,.%2F"},
//}

type EncodeQueryTest struct {
	m        Values
	expected string
}

var encodeQueryTests = []EncodeQueryTest{
	{nil, ""},
	{Values{}, ""},
	{Values{"q": {"puppies"}, "oe": {"utf8"}}, "oe=utf8&q=puppies"},
	{Values{"q": {"dogs", "&", "7"}}, "q=dogs&q=%26&q=7"},
	{Values{
		"a": {"a1", "a2", "a3"},
		"b": {"b1", "b2", "b3"},
		"c": {"c1", "c2", "c3"},
	}, "a=a1&a=a2&a=a3&b=b1&b=b2&b=b3&c=c1&c=c2&c=c3"},
}

func TestEncodeQuery(t *testing.T) {
	for _, tt := range encodeQueryTests {
		if q := tt.m.Encode(); q != tt.expected {
			t.Errorf(`EncodeQuery(%+v) = %q, want %q`, tt.m, q, tt.expected)
		}
	}
}

var resolvePathTests = []struct {
	base, ref, expected string
}{
	{"a/b", ".", "/a/"},
	{"a/b", "c", "/a/c"},
	{"a/b", "..", "/"},
	{"a/", "..", "/"},
	{"a/", "../..", "/"},
	{"a/b/c", "..", "/a/"},
	{"a/b/c", "../d", "/a/d"},
	{"a/b/c", ".././d", "/a/d"},
	{"a/b", "./..", "/"},
	{"a/./b", ".", "/a/"},
	{"a/../", ".", "/"},
	{"a/.././b", "c", "/c"},
}

func TestResolvePath(t *testing.T) {
	for _, test := range resolvePathTests {
		got := resolvePath(test.base, test.ref)
		if got != test.expected {
			t.Errorf("For %q + %q got %q; expected %q", test.base, test.ref, got, test.expected)
		}
	}
}

func BenchmarkResolvePath(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resolvePath("a/b/c", ".././d")
	}
}

var resolveReferenceTests = []struct {
	base, rel, expected string
}{
	// Absolute URL references
	{"http://foo.com?a=b", "https://bar.com/", "https://bar.com/"},
	{"http://foo.com/", "https://bar.com/?a=b", "https://bar.com/?a=b"},
	{"http://foo.com/", "https://bar.com/?", "https://bar.com/?"},
	{"http://foo.com/bar", "mailto:foo@example.com", "mailto:foo@example.com"},

	// Path-absolute references
	{"http://foo.com/bar", "/baz", "http://foo.com/baz"},
	{"http://foo.com/bar?a=b#f", "/baz", "http://foo.com/baz"},
	{"http://foo.com/bar?a=b", "/baz?", "http://foo.com/baz?"},
	{"http://foo.com/bar?a=b", "/baz?c=d", "http://foo.com/baz?c=d"},

	// Multiple slashes
	{"http://foo.com/bar", "http://foo.com//baz", "http://foo.com//baz"},
	{"http://foo.com/bar", "http://foo.com///baz/quux", "http://foo.com///baz/quux"},

	// Scheme-relative
	{"https://foo.com/bar?a=b", "//bar.com/quux", "https://bar.com/quux"},

	// Path-relative references:

	// ... current directory
	{"http://foo.com", ".", "http://foo.com/"},
	{"http://foo.com/bar", ".", "http://foo.com/"},
	{"http://foo.com/bar/", ".", "http://foo.com/bar/"},

	// ... going down
	{"http://foo.com", "bar", "http://foo.com/bar"},
	{"http://foo.com/", "bar", "http://foo.com/bar"},
	{"http://foo.com/bar/baz", "quux", "http://foo.com/bar/quux"},

	// ... going up
	{"http://foo.com/bar/baz", "../quux", "http://foo.com/quux"},
	{"http://foo.com/bar/baz", "../../../../../quux", "http://foo.com/quux"},
	{"http://foo.com/bar", "..", "http://foo.com/"},
	{"http://foo.com/bar/baz", "./..", "http://foo.com/"},
	// ".." in the middle (issue 3560)
	{"http://foo.com/bar/baz", "quux/dotdot/../tail", "http://foo.com/bar/quux/tail"},
	{"http://foo.com/bar/baz", "quux/./dotdot/../tail", "http://foo.com/bar/quux/tail"},
	{"http://foo.com/bar/baz", "quux/./dotdot/.././tail", "http://foo.com/bar/quux/tail"},
	{"http://foo.com/bar/baz", "quux/./dotdot/./../tail", "http://foo.com/bar/quux/tail"},
	{"http://foo.com/bar/baz", "quux/./dotdot/dotdot/././../../tail", "http://foo.com/bar/quux/tail"},
	{"http://foo.com/bar/baz", "quux/./dotdot/dotdot/./.././../tail", "http://foo.com/bar/quux/tail"},
	{"http://foo.com/bar/baz", "quux/./dotdot/dotdot/dotdot/./../../.././././tail", "http://foo.com/bar/quux/tail"},
	{"http://foo.com/bar/baz", "quux/./dotdot/../dotdot/../dot/./tail/..", "http://foo.com/bar/quux/dot/"},

	// Remove any dot-segments prior to forming the target URI.
	// https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
	{"http://foo.com/dot/./dotdot/../foo/bar", "../baz", "http://foo.com/dot/baz"},

	// Triple dot isn't special
	{"http://foo.com/bar", "...", "http://foo.com/..."},

	// Fragment
	{"http://foo.com/bar", ".#frag", "http://foo.com/#frag"},
	{"http://example.org/", "#!$&%27()*+,;=", "http://example.org/#!$&%27()*+,;="},

	// Paths with escaping (issue 16947).
	{"http://foo.com/foo%2fbar/", "../baz", "http://foo.com/baz"},
	{"http://foo.com/1/2%2f/3%2f4/5", "../../a/b/c", "http://foo.com/1/a/b/c"},
	{"http://foo.com/1/2/3", "./a%2f../../b/..%2fc", "http://foo.com/1/2/b/..%2fc"},
	{"http://foo.com/1/2%2f/3%2f4/5", "./a%2f../b/../c", "http://foo.com/1/2%2f/3%2f4/a%2f../c"},
	{"http://foo.com/foo%20bar/", "../baz", "http://foo.com/baz"},
	{"http://foo.com/foo", "../bar%2fbaz", "http://foo.com/bar%2fbaz"},
	{"http://foo.com/foo%2dbar/", "./baz-quux", "http://foo.com/foo%2dbar/baz-quux"},

	// RFC 3986: Normal Examples
	// https://datatracker.ietf.org/doc/html/rfc3986#section-5.4.1
	{"http://a/b/c/d;p?q", "g:h", "g:h"},
	{"http://a/b/c/d;p?q", "g", "http://a/b/c/g"},
	{"http://a/b/c/d;p?q", "./g", "http://a/b/c/g"},
	{"http://a/b/c/d;p?q", "g/", "http://a/b/c/g/"},
	{"http://a/b/c/d;p?q", "/g", "http://a/g"},
	{"http://a/b/c/d;p?q", "//g", "http://g"},
	{"http://a/b/c/d;p?q", "?y", "http://a/b/c/d;p?y"},
	{"http://a/b/c/d;p?q", "g?y", "http://a/b/c/g?y"},
	{"http://a/b/c/d;p?q", "#s", "http://a/b/c/d;p?q#s"},
	{"http://a/b/c/d;p?q", "g#s", "http://a/b/c/g#s"},
	{"http://a/b/c/d;p?q", "g?y#s", "http://a/b/c/g?y#s"},
	{"http://a/b/c/d;p?q", ";x", "http://a/b/c/;x"},
	{"http://a/b/c/d;p?q", "g;x", "http://a/b/c/g;x"},
	{"http://a/b/c/d;p?q", "g;x?y#s", "http://a/b/c/g;x?y#s"},
	{"http://a/b/c/d;p?q", "", "http://a/b/c/d;p?q"},
	{"http://a/b/c/d;p?q", ".", "http://a/b/c/"},
	{"http://a/b/c/d;p?q", "./", "http://a/b/c/"},
	{"http://a/b/c/d;p?q", "..", "http://a/b/"},
	{"http://a/b/c/d;p?q", "../", "http://a/b/"},
	{"http://a/b/c/d;p?q", "../g", "http://a/b/g"},
	{"http://a/b/c/d;p?q", "../..", "http://a/"},
	{"http://a/b/c/d;p?q", "../../", "http://a/"},
	{"http://a/b/c/d;p?q", "../../g", "http://a/g"},

	// RFC 3986: Abnormal Examples
	// https://datatracker.ietf.org/doc/html/rfc3986#section-5.4.2
	{"http://a/b/c/d;p?q", "../../../g", "http://a/g"},
	{"http://a/b/c/d;p?q", "../../../../g", "http://a/g"},
	{"http://a/b/c/d;p?q", "/./g", "http://a/g"},
	{"http://a/b/c/d;p?q", "/../g", "http://a/g"},
	{"http://a/b/c/d;p?q", "g.", "http://a/b/c/g."},
	{"http://a/b/c/d;p?q", ".g", "http://a/b/c/.g"},
	{"http://a/b/c/d;p?q", "g..", "http://a/b/c/g.."},
	{"http://a/b/c/d;p?q", "..g", "http://a/b/c/..g"},
	{"http://a/b/c/d;p?q", "./../g", "http://a/b/g"},
	{"http://a/b/c/d;p?q", "./g/.", "http://a/b/c/g/"},
	{"http://a/b/c/d;p?q", "g/./h", "http://a/b/c/g/h"},
	{"http://a/b/c/d;p?q", "g/../h", "http://a/b/c/h"},
	{"http://a/b/c/d;p?q", "g;x=1/./y", "http://a/b/c/g;x=1/y"},
	{"http://a/b/c/d;p?q", "g;x=1/../y", "http://a/b/c/y"},
	{"http://a/b/c/d;p?q", "g?y/./x", "http://a/b/c/g?y/./x"},
	{"http://a/b/c/d;p?q", "g?y/../x", "http://a/b/c/g?y/../x"},
	{"http://a/b/c/d;p?q", "g#s/./x", "http://a/b/c/g#s/./x"},
	{"http://a/b/c/d;p?q", "g#s/../x", "http://a/b/c/g#s/../x"},

	// Extras.
	{"https://a/b/c/d;p?q", "//g?q", "https://g?q"},
	{"https://a/b/c/d;p?q", "//g#s", "https://g#s"},
	{"https://a/b/c/d;p?q", "//g/d/e/f?y#s", "https://g/d/e/f?y#s"},
	{"https://a/b/c/d;p#s", "?y", "https://a/b/c/d;p?y"},
	{"https://a/b/c/d;p?q#s", "?y", "https://a/b/c/d;p?y"},

	// Empty path and query but with ForceQuery (issue 46033).
	{"https://a/b/c/d;p?q#s", "?", "https://a/b/c/d;p?"},

	// Opaque URLs (issue 66084).
	{"https://foo.com/bar?a=b", "http:opaque", "http:opaque"},
	{"http:opaque?x=y#zzz", "https:/foo?a=b#frag", "https:/foo?a=b#frag"},
	{"http:opaque?x=y#zzz", "https:foo:bar", "https:foo:bar"},
	{"http:opaque?x=y#zzz", "https:bar/baz?a=b#frag", "https:bar/baz?a=b#frag"},
	{"http:opaque?x=y#zzz", "https://user@host:1234?a=b#frag", "https://user@host:1234?a=b#frag"},
	{"http:opaque?x=y#zzz", "?a=b#frag", "http:opaque?a=b#frag"},
}

func TestResolveReference(t *testing.T) {
	mustParse := func(url string) *URL {
		u, err := Parse(url)
		if err != nil {
			t.Fatalf("Parse(%q) got err %v", url, err)
		}
		return u
	}
	opaque := &URL{Scheme: "scheme", Opaque: "opaque"}
	for _, test := range resolveReferenceTests {
		base := mustParse(test.base)
		rel := mustParse(test.rel)
		url := base.ResolveReference(rel)
		if got := url.String(); got != test.expected {
			t.Errorf("URL(%q).ResolveReference(%q)\ngot  %q\nwant %q", test.base, test.rel, got, test.expected)
		}
		// Ensure that new instances are returned.
		if base == url {
			t.Errorf("Expected URL.ResolveReference to return new URL instance.")
		}
		// Test the convenience wrapper too.
		url, err := base.Parse(test.rel)
		if err != nil {
			t.Errorf("URL(%q).Parse(%q) failed: %v", test.base, test.rel, err)
		} else if got := url.String(); got != test.expected {
			t.Errorf("URL(%q).Parse(%q)\ngot  %q\nwant %q", test.base, test.rel, got, test.expected)
		} else if base == url {
			// Ensure that new instances are returned for the wrapper too.
			t.Errorf("Expected URL.Parse to return new URL instance.")
		}
		// Ensure Opaque resets the URL.
		url = base.ResolveReference(opaque)
		if *url != *opaque {
			t.Errorf("ResolveReference failed to resolve opaque URL:\ngot  %#v\nwant %#v", url, opaque)
		}
		// Test the convenience wrapper with an opaque URL too.
		url, err = base.Parse("scheme:opaque")
		if err != nil {
			t.Errorf(`URL(%q).Parse("scheme:opaque") failed: %v`, test.base, err)
		} else if *url != *opaque {
			t.Errorf("Parse failed to resolve opaque URL:\ngot  %#v\nwant %#v", opaque, url)
		} else if base == url {
			// Ensure that new instances are returned, again.
			t.Errorf("Expected URL.Parse to return new URL instance.")
		}
	}
}

func TestQueryValues(t *testing.T) {
	u, _ := Parse("http://x.com?foo=bar&bar=1&bar=2&baz")
	v := u.Query()
	if len(v) != 3 {
		t.Errorf("got %d keys in Query values, want 3", len(v))
	}
	if g, e := v.Get("foo"), "bar"; g != e {
		t.Errorf("Get(foo) = %q, want %q", g, e)
	}
	// Case sensitive:
	if g, e := v.Get("Foo"), ""; g != e {
		t.Errorf("Get(Foo) = %q, want %q", g, e)
	}
	if g, e := v.Get("bar"), "1"; g != e {
		t.Errorf("Get(bar) = %q, want %q", g, e)
	}
	if g, e := v.Get("baz"), ""; g != e {
		t.Errorf("Get(baz) = %q, want %q", g, e)
	}
	if h, e := v.Has("foo"), true; h != e {
		t.Errorf("Has(foo) = %t, want %t", h, e)
	}
	if h, e := v.Has("bar"), true; h != e {
		t.Errorf("Has(bar) = %t, want %t", h, e)
	}
	if h, e := v.Has("baz"), true; h != e {
		t.Errorf("Has(baz) = %t, want %t", h, e)
	}
	if h, e := v.Has("noexist"), false; h != e {
		t.Errorf("Has(noexist) = %t, want %t", h, e)
	}
	v.Del("bar")
	if g, e := v.Get("bar"), ""; g != e {
		t.Errorf("second Get(bar) = %q, want %q", g, e)
	}
}

type parseTest struct {
	query string
	out   Values
	ok    bool
}

var parseTests = []parseTest{
	{
		query: "a=1",
		out:   Values{"a": []string{"1"}},
		ok:    true,
	},
	{
		query: "a=1&b=2",
		out:   Values{"a": []string{"1"}, "b": []string{"2"}},
		ok:    true,
	},
	{
		query: "a=1&a=2&a=banana",
		out:   Values{"a": []string{"1"
"""




```