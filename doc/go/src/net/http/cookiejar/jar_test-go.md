Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Context:**

The first thing to notice is the package declaration: `package cookiejar`. This immediately tells us we're dealing with code related to managing HTTP cookies in Go's `net/http` package. The filename `jar_test.go` strongly suggests this is a test file for the `cookiejar` functionality.

**2. Examining Imports:**

The import statements are crucial for understanding the dependencies and therefore the capabilities being tested. We see:

* `"fmt"`: For formatted I/O, likely used in error messages or debugging.
* `"net/http"`: The core HTTP package, essential for cookie manipulation.
* `"net/url"`: For parsing URLs, which is fundamental to cookie association with domains and paths.
* `"slices"`:  For slice utility functions, likely used for sorting cookie lists.
* `"strings"`: For string manipulation, probably used for parsing cookie strings and hostnames.
* `"testing"`:  The standard Go testing library, confirming this is a test file.
* `"time"`: For handling time and dates, important for cookie expiration.

**3. Identifying Key Structures and Variables:**

* `tNow`:  A `time.Time` variable initialized to a specific date. This is a strong indicator of *deterministic testing*, where time is controlled to ensure consistent test results.
* `testPSL`: A custom struct implementing a `PublicSuffixList` interface. The comments explicitly mention "intentional bugs," which suggests this is a *mock* or *stub* implementation used to test edge cases and specific public suffix list behavior without relying on a full, accurate list. The `PublicSuffix` method is the core of this interface.
* `newTestJar()`: A function that creates a `Jar` instance using the `testPSL`. This is a setup function for the tests.
* `hasDotSuffixTests`, `canonicalHostTests`, `hasPortTests`, `jarKeyTests`, `jarKeyNilPSLTests`, `isIPTests`, `defaultPathTests`, `domainAndTypeTests`: These are all slices or maps of test cases. The naming conventions are very clear, indicating what each test group is verifying. For example, `canonicalHostTests` is testing the `canonicalHost` function.
* `jarTest` and `query`: These structs define the structure of the more complex end-to-end tests. `jarTest` seems to encapsulate setting cookies and then querying them, while `query` represents a single query.
* `basicsTests`, `updateAndDeleteTests`, `chromiumBasicsTests`, etc.: These are arrays of `jarTest`, grouping related tests. The prefixes (`basics`, `chromium`) give clues about the test focus.

**4. Analyzing Individual Functions and Test Groups:**

* **`testPSL`:**  As mentioned, this is a mock. The intentional bugs are interesting and suggest specific scenarios the developers wanted to cover.
* **`newTestJar()`:**  Simple factory function.
* **`TestHasDotSuffix()`:**  Tests a utility function `hasDotSuffix`. The test cases are comprehensive, covering various combinations of strings and suffixes.
* **`TestCanonicalHost()`:**  Tests the `canonicalHost` function, which likely normalizes hostnames. The test cases include uppercase, ports, IPv4, IPv6, internationalized domains, and *malformed* inputs. The "TODO" comment highlights an area for potential improvement.
* **`TestHasPort()`:** Tests a simple helper function to detect if a host string includes a port.
* **`TestJarKey()` and `TestJarKeyNilPSL()`:** Test the `jarKey` function, which seems to derive a key for storing cookies based on the host and the public suffix list. The separate test for a nil PSL is important.
* **`TestIsIP()`:** Tests a function to determine if a string is a valid IP address.
* **`TestDefaultPath()`:** Tests a function that determines the default path for a URL.
* **`TestDomainAndType()`:**  Tests the `domainAndType` function, which likely parses the domain attribute of a "Set-Cookie" header and determines if it's a host-only cookie. The errors returned are also checked.
* **`expiresIn()` and `mustParseURL()`:** These are helper functions for creating test data.
* **`jarTest.run()`:** This is the core execution logic for the more complex tests. It involves:
    * Setting cookies into the `Jar`.
    * Checking the *content* of the `Jar` after setting the cookies.
    * Performing multiple queries using `Jar.Cookies` and verifying the returned cookies.
* **`TestBasics()`, `TestUpdateAndDelete()`, `TestExpiration()`, `TestChromiumBasics()`, `TestChromiumDomain()`, `TestChromiumDeletion()`, `TestDomainHandling()`:** These functions iterate through the arrays of `jarTest` and execute each one. The names clearly indicate the focus of each test suite. The "Chromium" tests suggest compatibility or testing against behaviors observed in the Chrome browser's cookie handling.

**5. Inferring Functionality and Providing Examples:**

Based on the tests, we can infer the following functionalities of the `cookiejar` package:

* **Storing and Retrieving Cookies:** The core functionality. The tests cover various scenarios of setting and getting cookies based on domain, path, secure flag, and HTTP-only flag.
* **Domain Matching:** The tests thoroughly check how cookies are matched to domains, including subdomain matching and handling of public suffixes.
* **Path Matching:** Tests verify how the `Path` attribute of a cookie is used to determine if it applies to a given URL.
* **Secure and HTTP-Only Flags:** The tests ensure that secure cookies are only returned over HTTPS and HTTP-only cookies are not accessible to JavaScript.
* **Expiration:** Tests confirm that cookies expire correctly based on `Max-Age` and `Expires` attributes.
* **Cookie Deletion:** The tests demonstrate how cookies can be deleted using `Max-Age=-1` or by setting an `Expires` date in the past.
* **Public Suffix List (PSL):**  The use of `testPSL` and tests related to `.co.uk` and `buggy.psl` indicate the importance of the PSL in preventing domain cookies from being set on top-level domains or shared suffixes.
* **Hostname Canonicalization:** The `canonicalHost` function likely handles case-insensitivity and removes default ports.
* **IDNA Domain Handling:** Tests with "bücher.test" show support for internationalized domain names.
* **IP Address Handling:** Tests cover how cookies are handled for IP addresses.

**Go Code Examples (based on inferences):**

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

func main() {
	jar, _ := cookiejar.New(nil) // Create a new cookie jar

	// Example of setting a cookie
	u, _ := url.Parse("http://example.com")
	cookies := []*http.Cookie{
		{Name: "my_cookie", Value: "my_value", Path: "/", Domain: "example.com"},
	}
	jar.SetCookies(u, cookies)
	fmt.Println("Set cookie successfully")

	// Example of getting cookies
	reqURL, _ := url.Parse("http://example.com/path")
	req := &http.Request{URL: reqURL}
	cookiesFromJar := jar.Cookies(reqURL)
	fmt.Println("Retrieved cookies:", cookiesFromJar)

	// Example of setting an expiring cookie
	expireURL, _ := url.Parse("http://anotherexample.com")
	expiry := time.Now().Add(24 * time.Hour)
	expiringCookie := []*http.Cookie{
		{Name: "session_id", Value: "12345", Expires: expiry, Path: "/"},
	}
	jar.SetCookies(expireURL, expiringCookie)
	fmt.Println("Set expiring cookie")

	// Example with a subdomain
	subdomainURL, _ := url.Parse("http://sub.example.com")
	subdomainCookies := jar.Cookies(subdomainURL)
	fmt.Println("Cookies for subdomain:", subdomainCookies)

	// Example of using a custom PublicSuffixList (though the test one is buggy)
	pslJar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: testPSL{}})
	pslURL, _ := url.Parse("http://www.bbc.co.uk")
	pslJar.SetCookies(pslURL, []*http.Cookie{{Name: "test", Value: "psl_value", Domain: ".co.uk"}})
	pslCookies := pslJar.Cookies(pslURL)
	fmt.Println("Cookies with test PSL (expecting none for .co.uk domain):", pslCookies)
}

// The testPSL struct from the original code snippet needs to be included
// for the custom PSL example to compile.
type testPSL struct{}

func (testPSL) String() string {
	return "testPSL"
}
func (testPSL) PublicSuffix(d string) string {
	if d == "co.uk" || strings.HasSuffix(d, ".co.uk") {
		return "co.uk"
	}
	if d == "www.buggy.psl" {
		return "xy"
	}
	if d == "www2.buggy.psl" {
		return "com"
	}
	return d[strings.LastIndex(d, ".")+1:]
}
```

This structured approach allows for a thorough understanding of the code snippet's purpose and functionality.
这是 `go/src/net/http/cookiejar/jar_test.go` 文件的一部分，主要用于测试 `net/http/cookiejar` 包中的 `Jar` 类型的各项功能。`Jar` 类型实现了存储和管理 HTTP Cookie 的功能，类似于浏览器中的 Cookie 管理器。

**功能归纳:**

这部分代码主要测试了 `cookiejar.Jar` 类型的以下核心功能：

1. **`hasDotSuffix` 函数的正确性:**  测试一个字符串是否以另一个带有点号前缀的字符串结尾。
2. **`canonicalHost` 函数的正确性:** 测试将主机名规范化的功能，包括处理大小写、端口号、国际化域名 (IDNA) 以及一些格式错误的域名。
3. **`hasPort` 函数的正确性:** 测试判断主机名字符串是否包含端口号。
4. **`jarKey` 函数的正确性:** 测试根据主机名和公共后缀列表 (Public Suffix List, PSL) 生成用于存储 Cookie 的键。这涉及到如何确定 Cookie 的作用域。
5. **`isIP` 函数的正确性:** 测试判断一个字符串是否为 IP 地址。
6. **`defaultPath` 函数的正确性:** 测试根据 URL 的路径部分获取 Cookie 的默认路径。
7. **`domainAndType` 方法的正确性:** 测试 `Jar` 类型中用于解析 "Set-Cookie" 头部中的 `domain` 属性，并确定 Cookie 是主机 Cookie 还是域名 Cookie 的逻辑。
8. **`Jar` 类型的基本操作:**
    * **设置 Cookie (`SetCookies`)**: 测试将 Cookie 存储到 `Jar` 中的功能，包括处理不同的 Cookie 属性 (如 `secure`, `path`, `httponly`, `domain`, `expires`, `max-age`)。
    * **获取 Cookie (`Cookies`)**: 测试根据请求的 URL 从 `Jar` 中检索匹配的 Cookie 的功能，包括路径匹配、域名匹配、安全性和 HTTP-Only 标志的判断，以及 Cookie 的排序规则。
    * **Cookie 的更新和删除**: 测试更新已存在的 Cookie 以及根据 `max-age` 或 `expires` 属性删除 Cookie 的功能。
    * **Cookie 的过期处理**: 测试 `Jar` 如何根据 Cookie 的过期时间来管理 Cookie。
9. **与公共后缀列表 (PSL) 的交互:** 通过自定义的 `testPSL` 模拟不同的 PSL 规则，测试 `Jar` 如何根据 PSL 来限制域名 Cookie 的设置，防止在公共后缀上设置域名 Cookie。
10. **对国际化域名 (IDNA) 的支持:** 测试 `Jar` 对包含非 ASCII 字符的域名 (如 `bücher.test`) 的处理。
11. **对 IP 地址的处理:** 测试 `Jar` 如何处理针对 IP 地址设置的 Cookie。
12. **处理带引号的 Cookie 值:** 测试 `Jar` 如何存储和检索带有引号的 Cookie 值。

**推断的 Go 语言功能实现 (通过代码举例说明):**

基于测试代码，可以推断 `net/http/cookiejar` 包中的 `Jar` 类型很可能实现了 `http.CookieJar` 接口。该接口定义了 `SetCookies` 和 `Cookies` 两个核心方法。

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

func main() {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	// 假设的服务器端设置 Cookie
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"mycookie=value1; Path=/; Domain=example.com",
				"securecookie=value2; Secure; HttpOnly; Path=/",
			},
		},
		Request: &http.Request{
			URL: &url.URL{Scheme: "http", Host: "example.com"},
		},
	}
	u := resp.Request.URL
	jar.SetCookies(u, resp.Cookies())

	// 假设的客户端发起请求
	reqURL, _ := url.Parse("http://example.com/path")
	req := &http.Request{URL: reqURL}

	// 从 CookieJar 中获取匹配的 Cookie
	cookies := jar.Cookies(req.URL)
	fmt.Println("Cookies:", cookies) // 输出: Cookies: [mycookie=value1]

	// 对于 HTTPS 请求，securecookie 也会被返回
	secureReqURL, _ := url.Parse("https://example.com/path")
	secureReq := &http.Request{URL: secureReqURL}
	secureCookies := jar.Cookies(secureReq.URL)
	fmt.Println("Secure Cookies:", secureCookies) // 输出: Secure Cookies: [mycookie=value1 securecookie=value2]
}
```

**假设的输入与输出 (基于 `TestCanonicalHost`):**

```go
// 假设的 canonicalHost 函数的实现 (仅供说明)
func canonicalHost(host string) (string, error) {
	// ... 一些规范化逻辑 ...
	return strings.ToLower(strings.Split(host, ":")[0]), nil // 简化版，仅用于演示
}

func main() {
	testCases := map[string]string{
		"www.example.com":         "www.example.com",
		"WWW.EXAMPLE.COM":         "www.example.com",
		"www.example.com:80":      "www.example.com",
		"192.168.0.10":            "192.168.0.10",
		// ... 其他测试用例 ...
	}

	for input, want := range testCases {
		output, _ := canonicalHost(input)
		fmt.Printf("Input: %s, Output: %s, Expected: %s\n", input, output, want)
	}
}
```

**命令行参数的具体处理:**

这段代码本身是测试代码，并不直接处理命令行参数。`net/http/cookiejar` 包的功能通常由 `net/http` 包使用，而 `net/http` 包在创建 HTTP 客户端时可以使用 `http.Client` 类型的 `Jar` 字段来指定使用的 Cookie 管理器。

例如：

```go
import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

func main() {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// ... 使用 client 发起 HTTP 请求，Cookie 会被自动管理 ...
}
```

**使用者易犯错的点:**

由于这部分代码是测试代码，它更多地揭示了 `cookiejar` 包的内部逻辑和可能出现的问题。但从测试用例中，我们可以推断出使用者在与 `cookiejar` 包交互时可能犯的错误：

1. **对域名匹配规则的理解不足:** 可能会错误地认为在 `www.example.com` 上设置的域名 Cookie (`domain=example.com`)  无法在 `sub.example.com` 上获取到，或者反之。测试用例 `ValidSubdomainTest` 等就覆盖了这些情况。
2. **对路径匹配规则的理解不足:**  可能会不清楚在哪个路径下设置的 Cookie 能在哪些路径下的请求中被发送。`PathTest` 覆盖了这些情况。
3. **忽略 `secure` 和 `HttpOnly` 标志:** 可能会忘记在 HTTPS 请求下才能发送带有 `secure` 标志的 Cookie，或者尝试通过 JavaScript 访问带有 `HttpOnly` 标志的 Cookie。`Secure cookies are not returned to http.` 测试用例就演示了这一点。
4. **对公共后缀列表 (PSL) 的不了解:** 可能会尝试在公共后缀上设置域名 Cookie，例如在 `co.uk` 上设置 `domain=co.uk`，这会被浏览器（以及 `cookiejar`）阻止。`Disallow domain cookie on public suffix.` 测试用例说明了这一点。
5. **对 Cookie 过期机制的混淆:** 可能会混淆 `max-age` 和 `expires` 的作用，或者不清楚浏览器如何处理会话 Cookie。`TestExpiration` 覆盖了这些场景。

**总结一下它的功能 (针对提供的代码片段):**

这段代码的主要功能是 **全面测试 `net/http/cookiejar` 包中 `Jar` 类型的核心 Cookie 管理逻辑**。它通过大量的测试用例验证了 `Jar` 类型在存储、检索、更新和删除 Cookie 时的各种规则和边界情况，包括域名和路径匹配、安全性和 HTTP-Only 标志、Cookie 过期、与公共后缀列表的交互以及对国际化域名和 IP 地址的处理。

这是第 1 部分的总结，重点在于测试代码的功能和它所反映的被测试代码的行为。

### 提示词
```
这是路径为go/src/net/http/cookiejar/jar_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// tNow is the synthetic current time used as now during testing.
var tNow = time.Date(2013, 1, 1, 12, 0, 0, 0, time.UTC)

// testPSL implements PublicSuffixList with just two rules: "co.uk"
// and the default rule "*".
// The implementation has two intentional bugs:
//
//	PublicSuffix("www.buggy.psl") == "xy"
//	PublicSuffix("www2.buggy.psl") == "com"
type testPSL struct{}

func (testPSL) String() string {
	return "testPSL"
}
func (testPSL) PublicSuffix(d string) string {
	if d == "co.uk" || strings.HasSuffix(d, ".co.uk") {
		return "co.uk"
	}
	if d == "www.buggy.psl" {
		return "xy"
	}
	if d == "www2.buggy.psl" {
		return "com"
	}
	return d[strings.LastIndex(d, ".")+1:]
}

// newTestJar creates an empty Jar with testPSL as the public suffix list.
func newTestJar() *Jar {
	jar, err := New(&Options{PublicSuffixList: testPSL{}})
	if err != nil {
		panic(err)
	}
	return jar
}

var hasDotSuffixTests = [...]struct {
	s, suffix string
}{
	{"", ""},
	{"", "."},
	{"", "x"},
	{".", ""},
	{".", "."},
	{".", ".."},
	{".", "x"},
	{".", "x."},
	{".", ".x"},
	{".", ".x."},
	{"x", ""},
	{"x", "."},
	{"x", ".."},
	{"x", "x"},
	{"x", "x."},
	{"x", ".x"},
	{"x", ".x."},
	{".x", ""},
	{".x", "."},
	{".x", ".."},
	{".x", "x"},
	{".x", "x."},
	{".x", ".x"},
	{".x", ".x."},
	{"x.", ""},
	{"x.", "."},
	{"x.", ".."},
	{"x.", "x"},
	{"x.", "x."},
	{"x.", ".x"},
	{"x.", ".x."},
	{"com", ""},
	{"com", "m"},
	{"com", "om"},
	{"com", "com"},
	{"com", ".com"},
	{"com", "x.com"},
	{"com", "xcom"},
	{"com", "xorg"},
	{"com", "org"},
	{"com", "rg"},
	{"foo.com", ""},
	{"foo.com", "m"},
	{"foo.com", "om"},
	{"foo.com", "com"},
	{"foo.com", ".com"},
	{"foo.com", "o.com"},
	{"foo.com", "oo.com"},
	{"foo.com", "foo.com"},
	{"foo.com", ".foo.com"},
	{"foo.com", "x.foo.com"},
	{"foo.com", "xfoo.com"},
	{"foo.com", "xfoo.org"},
	{"foo.com", "foo.org"},
	{"foo.com", "oo.org"},
	{"foo.com", "o.org"},
	{"foo.com", ".org"},
	{"foo.com", "org"},
	{"foo.com", "rg"},
}

func TestHasDotSuffix(t *testing.T) {
	for _, tc := range hasDotSuffixTests {
		got := hasDotSuffix(tc.s, tc.suffix)
		want := strings.HasSuffix(tc.s, "."+tc.suffix)
		if got != want {
			t.Errorf("s=%q, suffix=%q: got %v, want %v", tc.s, tc.suffix, got, want)
		}
	}
}

var canonicalHostTests = map[string]string{
	"www.example.com":         "www.example.com",
	"WWW.EXAMPLE.COM":         "www.example.com",
	"wWw.eXAmple.CoM":         "www.example.com",
	"www.example.com:80":      "www.example.com",
	"192.168.0.10":            "192.168.0.10",
	"192.168.0.5:8080":        "192.168.0.5",
	"2001:4860:0:2001::68":    "2001:4860:0:2001::68",
	"[2001:4860:0:::68]:8080": "2001:4860:0:::68",
	"www.bücher.de":           "www.xn--bcher-kva.de",
	"www.example.com.":        "www.example.com",
	// TODO: Fix canonicalHost so that all of the following malformed
	// domain names trigger an error. (This list is not exhaustive, e.g.
	// malformed internationalized domain names are missing.)
	".":                       "",
	"..":                      ".",
	"...":                     "..",
	".net":                    ".net",
	".net.":                   ".net",
	"a..":                     "a.",
	"b.a..":                   "b.a.",
	"weird.stuff...":          "weird.stuff..",
	"[bad.unmatched.bracket:": "error",
}

func TestCanonicalHost(t *testing.T) {
	for h, want := range canonicalHostTests {
		got, err := canonicalHost(h)
		if want == "error" {
			if err == nil {
				t.Errorf("%q: got %q and nil error, want non-nil", h, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", h, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", h, got, want)
			continue
		}
	}
}

var hasPortTests = map[string]bool{
	"www.example.com":      false,
	"www.example.com:80":   true,
	"127.0.0.1":            false,
	"127.0.0.1:8080":       true,
	"2001:4860:0:2001::68": false,
	"[2001::0:::68]:80":    true,
}

func TestHasPort(t *testing.T) {
	for host, want := range hasPortTests {
		if got := hasPort(host); got != want {
			t.Errorf("%q: got %t, want %t", host, got, want)
		}
	}
}

var jarKeyTests = map[string]string{
	"foo.www.example.com": "example.com",
	"www.example.com":     "example.com",
	"example.com":         "example.com",
	"com":                 "com",
	"foo.www.bbc.co.uk":   "bbc.co.uk",
	"www.bbc.co.uk":       "bbc.co.uk",
	"bbc.co.uk":           "bbc.co.uk",
	"co.uk":               "co.uk",
	"uk":                  "uk",
	"192.168.0.5":         "192.168.0.5",
	"www.buggy.psl":       "www.buggy.psl",
	"www2.buggy.psl":      "buggy.psl",
	// The following are actual outputs of canonicalHost for
	// malformed inputs to canonicalHost (see above).
	"":              "",
	".":             ".",
	"..":            ".",
	".net":          ".net",
	"a.":            "a.",
	"b.a.":          "a.",
	"weird.stuff..": ".",
}

func TestJarKey(t *testing.T) {
	for host, want := range jarKeyTests {
		if got := jarKey(host, testPSL{}); got != want {
			t.Errorf("%q: got %q, want %q", host, got, want)
		}
	}
}

var jarKeyNilPSLTests = map[string]string{
	"foo.www.example.com": "example.com",
	"www.example.com":     "example.com",
	"example.com":         "example.com",
	"com":                 "com",
	"foo.www.bbc.co.uk":   "co.uk",
	"www.bbc.co.uk":       "co.uk",
	"bbc.co.uk":           "co.uk",
	"co.uk":               "co.uk",
	"uk":                  "uk",
	"192.168.0.5":         "192.168.0.5",
	// The following are actual outputs of canonicalHost for
	// malformed inputs to canonicalHost.
	"":              "",
	".":             ".",
	"..":            "..",
	".net":          ".net",
	"a.":            "a.",
	"b.a.":          "a.",
	"weird.stuff..": "stuff..",
}

func TestJarKeyNilPSL(t *testing.T) {
	for host, want := range jarKeyNilPSLTests {
		if got := jarKey(host, nil); got != want {
			t.Errorf("%q: got %q, want %q", host, got, want)
		}
	}
}

var isIPTests = map[string]bool{
	"127.0.0.1":            true,
	"1.2.3.4":              true,
	"2001:4860:0:2001::68": true,
	"::1%zone":             true,
	"example.com":          false,
	"1.1.1.300":            false,
	"www.foo.bar.net":      false,
	"123.foo.bar.net":      false,
}

func TestIsIP(t *testing.T) {
	for host, want := range isIPTests {
		if got := isIP(host); got != want {
			t.Errorf("%q: got %t, want %t", host, got, want)
		}
	}
}

var defaultPathTests = map[string]string{
	"/":           "/",
	"/abc":        "/",
	"/abc/":       "/abc",
	"/abc/xyz":    "/abc",
	"/abc/xyz/":   "/abc/xyz",
	"/a/b/c.html": "/a/b",
	"":            "/",
	"strange":     "/",
	"//":          "/",
	"/a//b":       "/a/",
	"/a/./b":      "/a/.",
	"/a/../b":     "/a/..",
}

func TestDefaultPath(t *testing.T) {
	for path, want := range defaultPathTests {
		if got := defaultPath(path); got != want {
			t.Errorf("%q: got %q, want %q", path, got, want)
		}
	}
}

var domainAndTypeTests = [...]struct {
	host         string // host Set-Cookie header was received from
	domain       string // domain attribute in Set-Cookie header
	wantDomain   string // expected domain of cookie
	wantHostOnly bool   // expected host-cookie flag
	wantErr      error  // expected error
}{
	{"www.example.com", "", "www.example.com", true, nil},
	{"127.0.0.1", "", "127.0.0.1", true, nil},
	{"2001:4860:0:2001::68", "", "2001:4860:0:2001::68", true, nil},
	{"www.example.com", "example.com", "example.com", false, nil},
	{"www.example.com", ".example.com", "example.com", false, nil},
	{"www.example.com", "www.example.com", "www.example.com", false, nil},
	{"www.example.com", ".www.example.com", "www.example.com", false, nil},
	{"foo.sso.example.com", "sso.example.com", "sso.example.com", false, nil},
	{"bar.co.uk", "bar.co.uk", "bar.co.uk", false, nil},
	{"foo.bar.co.uk", ".bar.co.uk", "bar.co.uk", false, nil},
	{"127.0.0.1", "127.0.0.1", "127.0.0.1", true, nil},
	{"2001:4860:0:2001::68", "2001:4860:0:2001::68", "2001:4860:0:2001::68", true, nil},
	{"www.example.com", ".", "", false, errMalformedDomain},
	{"www.example.com", "..", "", false, errMalformedDomain},
	{"www.example.com", "other.com", "", false, errIllegalDomain},
	{"www.example.com", "com", "", false, errIllegalDomain},
	{"www.example.com", ".com", "", false, errIllegalDomain},
	{"foo.bar.co.uk", ".co.uk", "", false, errIllegalDomain},
	{"127.www.0.0.1", "127.0.0.1", "", false, errIllegalDomain},
	{"com", "", "com", true, nil},
	{"com", "com", "com", true, nil},
	{"com", ".com", "com", true, nil},
	{"co.uk", "", "co.uk", true, nil},
	{"co.uk", "co.uk", "co.uk", true, nil},
	{"co.uk", ".co.uk", "co.uk", true, nil},
}

func TestDomainAndType(t *testing.T) {
	jar := newTestJar()
	for _, tc := range domainAndTypeTests {
		domain, hostOnly, err := jar.domainAndType(tc.host, tc.domain)
		if err != tc.wantErr {
			t.Errorf("%q/%q: got %q error, want %v",
				tc.host, tc.domain, err, tc.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if domain != tc.wantDomain || hostOnly != tc.wantHostOnly {
			t.Errorf("%q/%q: got %q/%t want %q/%t",
				tc.host, tc.domain, domain, hostOnly,
				tc.wantDomain, tc.wantHostOnly)
		}
	}
}

// expiresIn creates an expires attribute delta seconds from tNow.
func expiresIn(delta int) string {
	t := tNow.Add(time.Duration(delta) * time.Second)
	return "expires=" + t.Format(time.RFC1123)
}

// mustParseURL parses s to a URL and panics on error.
func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		panic(fmt.Sprintf("Unable to parse URL %s.", s))
	}
	return u
}

// jarTest encapsulates the following actions on a jar:
//  1. Perform SetCookies with fromURL and the cookies from setCookies.
//     (Done at time tNow + 0 ms.)
//  2. Check that the entries in the jar matches content.
//     (Done at time tNow + 1001 ms.)
//  3. For each query in tests: Check that Cookies with toURL yields the
//     cookies in want.
//     (Query n done at tNow + (n+2)*1001 ms.)
type jarTest struct {
	description string   // The description of what this test is supposed to test
	fromURL     string   // The full URL of the request from which Set-Cookie headers where received
	setCookies  []string // All the cookies received from fromURL
	content     string   // The whole (non-expired) content of the jar
	queries     []query  // Queries to test the Jar.Cookies method
}

// query contains one test of the cookies returned from Jar.Cookies.
type query struct {
	toURL string // the URL in the Cookies call
	want  string // the expected list of cookies (order matters)
}

// run runs the jarTest.
func (test jarTest) run(t *testing.T, jar *Jar) {
	now := tNow

	// Populate jar with cookies.
	setCookies := make([]*http.Cookie, len(test.setCookies))
	for i, cs := range test.setCookies {
		cookies := (&http.Response{Header: http.Header{"Set-Cookie": {cs}}}).Cookies()
		if len(cookies) != 1 {
			panic(fmt.Sprintf("Wrong cookie line %q: %#v", cs, cookies))
		}
		setCookies[i] = cookies[0]
	}
	jar.setCookies(mustParseURL(test.fromURL), setCookies, now)
	now = now.Add(1001 * time.Millisecond)

	// Serialize non-expired entries in the form "name1=val1 name2=val2".
	var cs []string
	for _, submap := range jar.entries {
		for _, cookie := range submap {
			if !cookie.Expires.After(now) {
				continue
			}

			v := cookie.Value
			if strings.ContainsAny(v, " ,") || cookie.Quoted {
				v = `"` + v + `"`
			}
			cs = append(cs, cookie.Name+"="+v)
		}
	}
	slices.Sort(cs)
	got := strings.Join(cs, " ")

	// Make sure jar content matches our expectations.
	if got != test.content {
		t.Errorf("Test %q Content\ngot  %q\nwant %q",
			test.description, got, test.content)
	}

	// Test different calls to Cookies.
	for i, query := range test.queries {
		now = now.Add(1001 * time.Millisecond)
		var s []string
		for _, c := range jar.cookies(mustParseURL(query.toURL), now) {
			s = append(s, c.String())
		}
		if got := strings.Join(s, " "); got != query.want {
			t.Errorf("Test %q #%d\ngot  %q\nwant %q", test.description, i, got, query.want)
		}
	}
}

// basicsTests contains fundamental tests. Each jarTest has to be performed on
// a fresh, empty Jar.
var basicsTests = [...]jarTest{
	{
		"Retrieval of a plain host cookie.",
		"http://www.host.test/",
		[]string{"A=a"},
		"A=a",
		[]query{
			{"http://www.host.test", "A=a"},
			{"http://www.host.test/", "A=a"},
			{"http://www.host.test/some/path", "A=a"},
			{"https://www.host.test", "A=a"},
			{"https://www.host.test/", "A=a"},
			{"https://www.host.test/some/path", "A=a"},
			{"ftp://www.host.test", ""},
			{"ftp://www.host.test/", ""},
			{"ftp://www.host.test/some/path", ""},
			{"http://www.other.org", ""},
			{"http://sibling.host.test", ""},
			{"http://deep.www.host.test", ""},
		},
	},
	{
		"Secure cookies are not returned to http.",
		"http://www.host.test/",
		[]string{"A=a; secure"},
		"A=a",
		[]query{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some/path", ""},
			{"https://www.host.test", "A=a"},
			{"https://www.host.test/", "A=a"},
			{"https://www.host.test/some/path", "A=a"},
		},
	},
	{
		"Explicit path.",
		"http://www.host.test/",
		[]string{"A=a; path=/some/path"},
		"A=a",
		[]query{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some", ""},
			{"http://www.host.test/some/", ""},
			{"http://www.host.test/some/path", "A=a"},
			{"http://www.host.test/some/paths", ""},
			{"http://www.host.test/some/path/foo", "A=a"},
			{"http://www.host.test/some/path/foo/", "A=a"},
		},
	},
	{
		"Implicit path #1: path is a directory.",
		"http://www.host.test/some/path/",
		[]string{"A=a"},
		"A=a",
		[]query{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some", ""},
			{"http://www.host.test/some/", ""},
			{"http://www.host.test/some/path", "A=a"},
			{"http://www.host.test/some/paths", ""},
			{"http://www.host.test/some/path/foo", "A=a"},
			{"http://www.host.test/some/path/foo/", "A=a"},
		},
	},
	{
		"Implicit path #2: path is not a directory.",
		"http://www.host.test/some/path/index.html",
		[]string{"A=a"},
		"A=a",
		[]query{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some", ""},
			{"http://www.host.test/some/", ""},
			{"http://www.host.test/some/path", "A=a"},
			{"http://www.host.test/some/paths", ""},
			{"http://www.host.test/some/path/foo", "A=a"},
			{"http://www.host.test/some/path/foo/", "A=a"},
		},
	},
	{
		"Implicit path #3: no path in URL at all.",
		"http://www.host.test",
		[]string{"A=a"},
		"A=a",
		[]query{
			{"http://www.host.test", "A=a"},
			{"http://www.host.test/", "A=a"},
			{"http://www.host.test/some/path", "A=a"},
		},
	},
	{
		"Cookies are sorted by path length.",
		"http://www.host.test/",
		[]string{
			"A=a; path=/foo/bar",
			"B=b; path=/foo/bar/baz/qux",
			"C=c; path=/foo/bar/baz",
			"D=d; path=/foo"},
		"A=a B=b C=c D=d",
		[]query{
			{"http://www.host.test/foo/bar/baz/qux", "B=b C=c A=a D=d"},
			{"http://www.host.test/foo/bar/baz/", "C=c A=a D=d"},
			{"http://www.host.test/foo/bar", "A=a D=d"},
		},
	},
	{
		"Creation time determines sorting on same length paths.",
		"http://www.host.test/",
		[]string{
			"A=a; path=/foo/bar",
			"X=x; path=/foo/bar",
			"Y=y; path=/foo/bar/baz/qux",
			"B=b; path=/foo/bar/baz/qux",
			"C=c; path=/foo/bar/baz",
			"W=w; path=/foo/bar/baz",
			"Z=z; path=/foo",
			"D=d; path=/foo"},
		"A=a B=b C=c D=d W=w X=x Y=y Z=z",
		[]query{
			{"http://www.host.test/foo/bar/baz/qux", "Y=y B=b C=c W=w A=a X=x Z=z D=d"},
			{"http://www.host.test/foo/bar/baz/", "C=c W=w A=a X=x Z=z D=d"},
			{"http://www.host.test/foo/bar", "A=a X=x Z=z D=d"},
		},
	},
	{
		"Sorting of same-name cookies.",
		"http://www.host.test/",
		[]string{
			"A=1; path=/",
			"A=2; path=/path",
			"A=3; path=/quux",
			"A=4; path=/path/foo",
			"A=5; domain=.host.test; path=/path",
			"A=6; domain=.host.test; path=/quux",
			"A=7; domain=.host.test; path=/path/foo",
		},
		"A=1 A=2 A=3 A=4 A=5 A=6 A=7",
		[]query{
			{"http://www.host.test/path", "A=2 A=5 A=1"},
			{"http://www.host.test/path/foo", "A=4 A=7 A=2 A=5 A=1"},
		},
	},
	{
		"Disallow domain cookie on public suffix.",
		"http://www.bbc.co.uk",
		[]string{
			"a=1",
			"b=2; domain=co.uk",
		},
		"a=1",
		[]query{{"http://www.bbc.co.uk", "a=1"}},
	},
	{
		"Host cookie on IP.",
		"http://192.168.0.10",
		[]string{"a=1"},
		"a=1",
		[]query{{"http://192.168.0.10", "a=1"}},
	},
	{
		"Domain cookies on IP.",
		"http://192.168.0.10",
		[]string{
			"a=1; domain=192.168.0.10",  // allowed
			"b=2; domain=172.31.9.9",    // rejected, can't set cookie for other IP
			"c=3; domain=.192.168.0.10", // rejected like in most browsers
		},
		"a=1",
		[]query{
			{"http://192.168.0.10", "a=1"},
			{"http://172.31.9.9", ""},
			{"http://www.fancy.192.168.0.10", ""},
		},
	},
	{
		"Port is ignored #1.",
		"http://www.host.test/",
		[]string{"a=1"},
		"a=1",
		[]query{
			{"http://www.host.test", "a=1"},
			{"http://www.host.test:8080/", "a=1"},
		},
	},
	{
		"Port is ignored #2.",
		"http://www.host.test:8080/",
		[]string{"a=1"},
		"a=1",
		[]query{
			{"http://www.host.test", "a=1"},
			{"http://www.host.test:8080/", "a=1"},
			{"http://www.host.test:1234/", "a=1"},
		},
	},
	{
		"IPv6 zone is not treated as a host.",
		"https://example.com/",
		[]string{"a=1"},
		"a=1",
		[]query{
			{"https://[::1%25.example.com]:80/", ""},
		},
	},
	{
		"Retrieval of cookies with quoted values", // issue #46443
		"http://www.host.test/",
		[]string{
			`cookie-1="quoted"`,
			`cookie-2="quoted with spaces"`,
			`cookie-3="quoted,with,commas"`,
			`cookie-4= ,`,
		},
		`cookie-1="quoted" cookie-2="quoted with spaces" cookie-3="quoted,with,commas" cookie-4=" ,"`,
		[]query{
			{
				"http://www.host.test",
				`cookie-1="quoted" cookie-2="quoted with spaces" cookie-3="quoted,with,commas" cookie-4=" ,"`,
			},
		},
	},
}

func TestBasics(t *testing.T) {
	for _, test := range basicsTests {
		jar := newTestJar()
		test.run(t, jar)
	}
}

// updateAndDeleteTests contains jarTests which must be performed on the same
// Jar.
var updateAndDeleteTests = [...]jarTest{
	{
		"Set initial cookies.",
		"http://www.host.test",
		[]string{
			"a=1",
			"b=2; secure",
			"c=3; httponly",
			"d=4; secure; httponly"},
		"a=1 b=2 c=3 d=4",
		[]query{
			{"http://www.host.test", "a=1 c=3"},
			{"https://www.host.test", "a=1 b=2 c=3 d=4"},
		},
	},
	{
		"Update value via http.",
		"http://www.host.test",
		[]string{
			"a=w",
			"b=x; secure",
			"c=y; httponly",
			"d=z; secure; httponly"},
		"a=w b=x c=y d=z",
		[]query{
			{"http://www.host.test", "a=w c=y"},
			{"https://www.host.test", "a=w b=x c=y d=z"},
		},
	},
	{
		"Clear Secure flag from an http.",
		"http://www.host.test/",
		[]string{
			"b=xx",
			"d=zz; httponly"},
		"a=w b=xx c=y d=zz",
		[]query{{"http://www.host.test", "a=w b=xx c=y d=zz"}},
	},
	{
		"Delete all.",
		"http://www.host.test/",
		[]string{
			"a=1; max-Age=-1",                    // delete via MaxAge
			"b=2; " + expiresIn(-10),             // delete via Expires
			"c=2; max-age=-1; " + expiresIn(-10), // delete via both
			"d=4; max-age=-1; " + expiresIn(10)}, // MaxAge takes precedence
		"",
		[]query{{"http://www.host.test", ""}},
	},
	{
		"Refill #1.",
		"http://www.host.test",
		[]string{
			"A=1",
			"A=2; path=/foo",
			"A=3; domain=.host.test",
			"A=4; path=/foo; domain=.host.test"},
		"A=1 A=2 A=3 A=4",
		[]query{{"http://www.host.test/foo", "A=2 A=4 A=1 A=3"}},
	},
	{
		"Refill #2.",
		"http://www.google.com",
		[]string{
			"A=6",
			"A=7; path=/foo",
			"A=8; domain=.google.com",
			"A=9; path=/foo; domain=.google.com"},
		"A=1 A=2 A=3 A=4 A=6 A=7 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=4 A=1 A=3"},
			{"http://www.google.com/foo", "A=7 A=9 A=6 A=8"},
		},
	},
	{
		"Delete A7.",
		"http://www.google.com",
		[]string{"A=; path=/foo; max-age=-1"},
		"A=1 A=2 A=3 A=4 A=6 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=4 A=1 A=3"},
			{"http://www.google.com/foo", "A=9 A=6 A=8"},
		},
	},
	{
		"Delete A4.",
		"http://www.host.test",
		[]string{"A=; path=/foo; domain=host.test; max-age=-1"},
		"A=1 A=2 A=3 A=6 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1 A=3"},
			{"http://www.google.com/foo", "A=9 A=6 A=8"},
		},
	},
	{
		"Delete A6.",
		"http://www.google.com",
		[]string{"A=; max-age=-1"},
		"A=1 A=2 A=3 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1 A=3"},
			{"http://www.google.com/foo", "A=9 A=8"},
		},
	},
	{
		"Delete A3.",
		"http://www.host.test",
		[]string{"A=; domain=host.test; max-age=-1"},
		"A=1 A=2 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1"},
			{"http://www.google.com/foo", "A=9 A=8"},
		},
	},
	{
		"No cross-domain delete.",
		"http://www.host.test",
		[]string{
			"A=; domain=google.com; max-age=-1",
			"A=; path=/foo; domain=google.com; max-age=-1"},
		"A=1 A=2 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1"},
			{"http://www.google.com/foo", "A=9 A=8"},
		},
	},
	{
		"Delete A8 and A9.",
		"http://www.google.com",
		[]string{
			"A=; domain=google.com; max-age=-1",
			"A=; path=/foo; domain=google.com; max-age=-1"},
		"A=1 A=2",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1"},
			{"http://www.google.com/foo", ""},
		},
	},
}

func TestUpdateAndDelete(t *testing.T) {
	jar := newTestJar()
	for _, test := range updateAndDeleteTests {
		test.run(t, jar)
	}
}

func TestExpiration(t *testing.T) {
	jar := newTestJar()
	jarTest{
		"Expiration.",
		"http://www.host.test",
		[]string{
			"a=1",
			"b=2; max-age=3",
			"c=3; " + expiresIn(3),
			"d=4; max-age=5",
			"e=5; " + expiresIn(5),
			"f=6; max-age=100",
		},
		"a=1 b=2 c=3 d=4 e=5 f=6", // executed at t0 + 1001 ms
		[]query{
			{"http://www.host.test", "a=1 b=2 c=3 d=4 e=5 f=6"}, // t0 + 2002 ms
			{"http://www.host.test", "a=1 d=4 e=5 f=6"},         // t0 + 3003 ms
			{"http://www.host.test", "a=1 d=4 e=5 f=6"},         // t0 + 4004 ms
			{"http://www.host.test", "a=1 f=6"},                 // t0 + 5005 ms
			{"http://www.host.test", "a=1 f=6"},                 // t0 + 6006 ms
		},
	}.run(t, jar)
}

//
// Tests derived from Chromium's cookie_store_unittest.h.
//

// See http://src.chromium.org/viewvc/chrome/trunk/src/net/cookies/cookie_store_unittest.h?revision=159685&content-type=text/plain
// Some of the original tests are in a bad condition (e.g.
// DomainWithTrailingDotTest) or are not RFC 6265 conforming (e.g.
// TestNonDottedAndTLD #1 and #6) and have not been ported.

// chromiumBasicsTests contains fundamental tests. Each jarTest has to be
// performed on a fresh, empty Jar.
var chromiumBasicsTests = [...]jarTest{
	{
		"DomainWithTrailingDotTest.",
		"http://www.google.com/",
		[]string{
			"a=1; domain=.www.google.com.",
			"b=2; domain=.www.google.com.."},
		"",
		[]query{
			{"http://www.google.com", ""},
		},
	},
	{
		"ValidSubdomainTest #1.",
		"http://a.b.c.d.com",
		[]string{
			"a=1; domain=.a.b.c.d.com",
			"b=2; domain=.b.c.d.com",
			"c=3; domain=.c.d.com",
			"d=4; domain=.d.com"},
		"a=1 b=2 c=3 d=4",
		[]query{
			{"http://a.b.c.d.com", "a=1 b=2 c=3 d=4"},
			{"http://b.c.d.com", "b=2 c=3 d=4"},
			{"http://c.d.com", "c=3 d=4"},
			{"http://d.com", "d=4"},
		},
	},
	{
		"ValidSubdomainTest #2.",
		"http://a.b.c.d.com",
		[]string{
			"a=1; domain=.a.b.c.d.com",
			"b=2; domain=.b.c.d.com",
			"c=3; domain=.c.d.com",
			"d=4; domain=.d.com",
			"X=bcd; domain=.b.c.d.com",
			"X=cd; domain=.c.d.com"},
		"X=bcd X=cd a=1 b=2 c=3 d=4",
		[]query{
			{"http://b.c.d.com", "b=2 c=3 d=4 X=bcd X=cd"},
			{"http://c.d.com", "c=3 d=4 X=cd"},
		},
	},
	{
		"InvalidDomainTest #1.",
		"http://foo.bar.com",
		[]string{
			"a=1; domain=.yo.foo.bar.com",
			"b=2; domain=.foo.com",
			"c=3; domain=.bar.foo.com",
			"d=4; domain=.foo.bar.com.net",
			"e=5; domain=ar.com",
			"f=6; domain=.",
			"g=7; domain=/",
			"h=8; domain=http://foo.bar.com",
			"i=9; domain=..foo.bar.com",
			"j=10; domain=..bar.com",
			"k=11; domain=.foo.bar.com?blah",
			"l=12; domain=.foo.bar.com/blah",
			"m=12; domain=.foo.bar.com:80",
			"n=14; domain=.foo.bar.com:",
			"o=15; domain=.foo.bar.com#sup",
		},
		"", // Jar is empty.
		[]query{{"http://foo.bar.com", ""}},
	},
	{
		"InvalidDomainTest #2.",
		"http://foo.com.com",
		[]string{"a=1; domain=.foo.com.com.com"},
		"",
		[]query{{"http://foo.bar.com", ""}},
	},
	{
		"DomainWithoutLeadingDotTest #1.",
		"http://manage.hosted.filefront.com",
		[]string{"a=1; domain=filefront.com"},
		"a=1",
		[]query{{"http://www.filefront.com", "a=1"}},
	},
	{
		"DomainWithoutLeadingDotTest #2.",
		"http://www.google.com",
		[]string{"a=1; domain=www.google.com"},
		"a=1",
		[]query{
			{"http://www.google.com", "a=1"},
			{"http://sub.www.google.com", "a=1"},
			{"http://something-else.com", ""},
		},
	},
	{
		"CaseInsensitiveDomainTest.",
		"http://www.google.com",
		[]string{
			"a=1; domain=.GOOGLE.COM",
			"b=2; domain=.www.gOOgLE.coM"},
		"a=1 b=2",
		[]query{{"http://www.google.com", "a=1 b=2"}},
	},
	{
		"TestIpAddress #1.",
		"http://1.2.3.4/foo",
		[]string{"a=1; path=/"},
		"a=1",
		[]query{{"http://1.2.3.4/foo", "a=1"}},
	},
	{
		"TestIpAddress #2.",
		"http://1.2.3.4/foo",
		[]string{
			"a=1; domain=.1.2.3.4",
			"b=2; domain=.3.4"},
		"",
		[]query{{"http://1.2.3.4/foo", ""}},
	},
	{
		"TestIpAddress #3.",
		"http://1.2.3.4/foo",
		[]string{"a=1; domain=1.2.3.3"},
		"",
		[]query{{"http://1.2.3.4/foo", ""}},
	},
	{
		"TestIpAddress #4.",
		"http://1.2.3.4/foo",
		[]string{"a=1; domain=1.2.3.4"},
		"a=1",
		[]query{{"http://1.2.3.4/foo", "a=1"}},
	},
	{
		"TestNonDottedAndTLD #2.",
		"http://com./index.html",
		[]string{"a=1"},
		"a=1",
		[]query{
			{"http://com./index.html", "a=1"},
			{"http://no-cookies.com./index.html", ""},
		},
	},
	{
		"TestNonDottedAndTLD #3.",
		"http://a.b",
		[]string{
			"a=1; domain=.b",
			"b=2; domain=b"},
		"",
		[]query{{"http://bar.foo", ""}},
	},
	{
		"TestNonDottedAndTLD #4.",
		"http://google.com",
		[]string{
			"a=1; domain=.com",
			"b=2; domain=com"},
		"",
		[]query{{"http://google.com", ""}},
	},
	{
		"TestNonDottedAndTLD #5.",
		"http://google.co.uk",
		[]string{
			"a=1; domain=.co.uk",
			"b=2; domain=.uk"},
		"",
		[]query{
			{"http://google.co.uk", ""},
			{"http://else.co.com", ""},
			{"http://else.uk", ""},
		},
	},
	{
		"TestHostEndsWithDot.",
		"http://www.google.com",
		[]string{
			"a=1",
			"b=2; domain=.www.google.com."},
		"a=1",
		[]query{{"http://www.google.com", "a=1"}},
	},
	{
		"PathTest",
		"http://www.google.izzle",
		[]string{"a=1; path=/wee"},
		"a=1",
		[]query{
			{"http://www.google.izzle/wee", "a=1"},
			{"http://www.google.izzle/wee/", "a=1"},
			{"http://www.google.izzle/wee/war", "a=1"},
			{"http://www.google.izzle/wee/war/more/more", "a=1"},
			{"http://www.google.izzle/weehee", ""},
			{"http://www.google.izzle/", ""},
		},
	},
}

func TestChromiumBasics(t *testing.T) {
	for _, test := range chromiumBasicsTests {
		jar := newTestJar()
		test.run(t, jar)
	}
}

// chromiumDomainTests contains jarTests which must be executed all on the
// same Jar.
var chromiumDomainTests = [...]jarTest{
	{
		"Fill #1.",
		"http://www.google.izzle",
		[]string{"A=B"},
		"A=B",
		[]query{{"http://www.google.izzle", "A=B"}},
	},
	{
		"Fill #2.",
		"http://www.google.izzle",
		[]string{"C=D; domain=.google.izzle"},
		"A=B C=D",
		[]query{{"http://www.google.izzle", "A=B C=D"}},
	},
	{
		"Verify A is a host cookie and not accessible from subdomain.",
		"http://unused.nil",
		[]string{},
		"A=B C=D",
		[]query{{"http://foo.www.google.izzle", "C=D"}},
	},
	{
		"Verify domain cookies are found on proper domain.",
		"http://www.google.izzle",
		[]string{"E=F; domain=.www.google.izzle"},
		"A=B C=D E=F",
		[]query{{"http://www.google.izzle", "A=B C=D E=F"}},
	},
	{
		"Leading dots in domain attributes are optional.",
		"http://www.google.izzle",
		[]string{"G=H; domain=www.google.izzle"},
		"A=B C=D E=F G=H",
		[]query{{"http://www.google.izzle", "A=B C=D E=F G=H"}},
	},
	{
		"Verify domain enforcement works #1.",
		"http://www.google.izzle",
		[]string{"K=L; domain=.bar.www.google.izzle"},
		"A=B C=D E=F G=H",
		[]query{{"http://bar.www.google.izzle", "C=D E=F G=H"}},
	},
	{
		"Verify domain enforcement works #2.",
		"http://unused.nil",
		[]string{},
		"A=B C=D E=F G=H",
		[]query{{"http://www.google.izzle", "A=B C=D E=F G=H"}},
	},
}

func TestChromiumDomain(t *testing.T) {
	jar := newTestJar()
	for _, test := range chromiumDomainTests {
		test.run(t, jar)
	}

}

// chromiumDeletionTests must be performed all on the same Jar.
var chromiumDeletionTests = [...]jarTest{
	{
		"Create session cookie a1.",
		"http://www.google.com",
		[]string{"a=1"},
		"a=1",
		[]query{{"http://www.google.com", "a=1"}},
	},
	{
		"Delete sc a1 via MaxAge.",
		"http://www.google.com",
		[]string{"a=1; max-age=-1"},
		"",
		[]query{{"http://www.google.com", ""}},
	},
	{
		"Create session cookie b2.",
		"http://www.google.com",
		[]string{"b=2"},
		"b=2",
		[]query{{"http://www.google.com", "b=2"}},
	},
	{
		"Delete sc b2 via Expires.",
		"http://www.google.com",
		[]string{"b=2; " + expiresIn(-10)},
		"",
		[]query{{"http://www.google.com", ""}},
	},
	{
		"Create persistent cookie c3.",
		"http://www.google.com",
		[]string{"c=3; max-age=3600"},
		"c=3",
		[]query{{"http://www.google.com", "c=3"}},
	},
	{
		"Delete pc c3 via MaxAge.",
		"http://www.google.com",
		[]string{"c=3; max-age=-1"},
		"",
		[]query{{"http://www.google.com", ""}},
	},
	{
		"Create persistent cookie d4.",
		"http://www.google.com",
		[]string{"d=4; max-age=3600"},
		"d=4",
		[]query{{"http://www.google.com", "d=4"}},
	},
	{
		"Delete pc d4 via Expires.",
		"http://www.google.com",
		[]string{"d=4; " + expiresIn(-10)},
		"",
		[]query{{"http://www.google.com", ""}},
	},
}

func TestChromiumDeletion(t *testing.T) {
	jar := newTestJar()
	for _, test := range chromiumDeletionTests {
		test.run(t, jar)
	}
}

// domainHandlingTests tests and documents the rules for domain handling.
// Each test must be performed on an empty new Jar.
var domainHandlingTests = [...]jarTest{
	{
		"Host cookie",
		"http://www.host.test",
		[]string{"a=1"},
		"a=1",
		[]query{
			{"http://www.host.test", "a=1"},
			{"http://host.test", ""},
			{"http://bar.host.test", ""},
			{"http://foo.www.host.test", ""},
			{"http://other.test", ""},
			{"http://test", ""},
		},
	},
	{
		"Domain cookie #1",
		"http://www.host.test",
		[]string{"a=1; domain=host.test"},
		"a=1",
		[]query{
			{"http://www.host.test", "a=1"},
			{"http://host.test", "a=1"},
			{"http://bar.host.test", "a=1"},
			{"http://foo.www.host.test", "a=1"},
			{"http://other.test", ""},
			{"http://test", ""},
		},
	},
	{
		"Domain cookie #2",
		"http://www.host.test",
		[]string{"a=1; domain=.host.test"},
		"a=1",
		[]query{
			{"http://www.host.test", "a=1"},
			{"http://host.test", "a=1"},
			{"http://bar.host.test", "a=1"},
			{"http://foo.www.host.test", "a=1"},
			{"http://other.test", ""},
			{"http://test", ""},
		},
	},
	{
		"Host cookie on IDNA domain #1",
		"http://www.bücher.test",
		[]string{"a=1"},
		"a=1",
		[]query{
			{"http://www.bücher.test", "a=1"},
			{"http://www.xn--bcher-kva.test", "a=1"},
			{"http://bücher.test", ""},
			{"http://xn--bcher-kva.test", ""},
			{"http://bar.bücher.test", ""},
			{"http://bar.xn--bcher-kva.test", ""},
			{"http://foo.www.bücher.test", ""},
			{"http://foo.www.xn--bcher-kva.test", ""},
			{"http://other.test", ""},
			{"http://test", ""},
		},
	},
	{
		"Host cookie on IDNA domain #2",
		"http://www.xn--bcher-kva.test",
		[]string{"a=1"},
		"a=1",
		[]query{
			{"http://www.bücher.test", "a=1"},
			{"http://www.xn--bcher-kva.test", "a=1"},
			{"http://bücher.test", ""},
			{"http://xn--bcher-kva.test", ""},
			{"http://bar.bücher.test", ""},
			{"http://bar.xn--bcher-kva.test", ""},
			{"http://foo.www.bücher.test", ""},
			{"http://foo.www.xn--bcher-kva.test", ""},
			{"http://other.test", ""},
			{"http://test", ""},
		},
	},
	{
		"Domain cookie on IDNA domain #1",
		"http://www.bücher.test",
		[]string{"a=1; domain=xn--bcher-kva.test"},
		"a=1",
		[]query{
			{"http://www.bücher.test", "a=1"},
			{"http://www.xn--bcher-kva.test", "a=1"},
			{"http://bücher.test", "a=1"},
			{"http://xn--bcher-kva.test", "a=1"},
			{"http://bar.bücher.test", "a=1"},
			{"http://bar.xn--bcher-kva.test", "a=1"},
			{"http://foo.www.bücher.test", "a=1"},
			{"http://foo.www.xn--bcher-kva.test", "a=1"},
			{"http://other.test", ""},
			{"http://test", ""},
		},
	}
```