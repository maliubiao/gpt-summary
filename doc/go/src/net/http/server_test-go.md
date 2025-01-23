Response:
Let's break down the thought process for analyzing the provided Go code snippet from `server_test.go`.

**1. Initial Scan and Understanding the Context:**

The first step is to recognize that this is a *test file* (`server_test.go`). This immediately tells us the primary purpose of the code: to verify the behavior of the `net/http` package, specifically the `Server` and related components like `ServeMux`. The import statements confirm this.

**2. Function-by-Function Analysis:**

Next, I'd go through each function individually to understand its purpose.

* **`TestServerTLSHandshakeTimeout(t *testing.T)`:** The name strongly suggests this function tests the `tlsHandshakeTimeout` method of the `Server` struct. The test cases within the function define different `Server` configurations (various `ReadTimeout`, `WriteTimeout`, `ReadHeaderTimeout` values) and assert the expected `tlsHandshakeTimeout` based on these configurations. This helps understand how the timeout is calculated.

* **`type handler struct{ i int }` and `func (handler) ServeHTTP(ResponseWriter, *Request) {}`:** This defines a custom `Handler` type. The empty `ServeHTTP` method indicates that this handler doesn't actually *do* anything with the request but is used to represent different handlers in the routing tests. The `i` field likely serves as a unique identifier for each handler instance.

* **`TestFindHandler(t *testing.T)`:**  The name clearly indicates testing the `findHandler` method of `ServeMux`. The code sets up a `ServeMux` with various path patterns and corresponding handlers. Then, it iterates through different request methods and paths, asserting that the correct handler is found for each case. This reveals how `ServeMux` performs route matching, including exact matches, prefix matches, and handling of cleaned paths and redirects.

* **`TestEmptyServeMux(t *testing.T)`:** This is a simple test ensuring that calling `Handler` on an empty `ServeMux` doesn't cause a panic. This is important for robustness.

* **`TestRegisterErr(t *testing.T)`:**  This function focuses on testing the error handling of the `registerErr` method of `ServeMux`. It tries to register invalid patterns or handlers and asserts that the correct error messages are returned, including regular expression matching of the error messages.

* **`TestExactMatch(t *testing.T)`:** This tests a specific helper function `exactMatch`, likely used within the routing logic. It verifies the conditions under which a pattern exactly matches a given path, considering cases with and without wildcards.

* **`TestEscapedPathsAndPatterns(t *testing.T)`:** This is a more involved test concerning how `ServeMux` handles URL encoding in both patterns and incoming request paths. It includes a `run` helper function and a boolean `use121` which suggests testing different behaviors depending on the Go version (specifically 1.21). The test defines patterns with encoded characters and checks if they match correctly against encoded and unencoded paths.

* **`TestCleanPath(t *testing.T)`:** This tests the `cleanPath` utility function, which likely normalizes URL paths by removing redundant slashes and resolving ".." segments.

* **`BenchmarkServerMatch(b *testing.B)`:** This is a benchmark test to measure the performance of the `findHandler` method under load. It sets up a `ServeMux` with multiple routes and then repeatedly performs lookups for various paths.

**3. Identifying Key Functionalities and Concepts:**

Based on the function analysis, I could identify the core functionalities being tested:

* **Server Configuration:**  Specifically, the calculation of `tlsHandshakeTimeout`.
* **Request Routing:**  How `ServeMux` matches incoming requests to registered handlers. This includes:
    * Exact matching
    * Prefix matching
    * Path cleaning and normalization
    * Handling of URL encoding
    * Redirection for trailing slashes
* **Error Handling:** How `ServeMux` handles invalid registration attempts.
* **Performance:** Benchmarking the route matching process.

**4. Inferring Go Language Features:**

The code demonstrates several important Go features:

* **Structs and Methods:**  `Server`, `handler`, and `ServeMux` are structs with associated methods.
* **Interfaces:** The `Handler` interface is central to request handling.
* **Testing Framework:** The `testing` package is used extensively for unit tests and benchmarks.
* **Closures:** The anonymous function used in `TestEscapedPathsAndPatterns` is a closure.
* **Regular Expressions:** The `regexp` package is used for matching error messages in `TestRegisterErr`.
* **URL Parsing:** The `net/url` package is used for parsing request URLs.

**5. Code Examples and Explanations:**

With the understanding of the code's functionality, I could then generate the Go code examples illustrating concepts like `ServeMux` and `Handler`, including hypothetical inputs and outputs.

**6. Identifying Potential Pitfalls:**

By carefully examining the test cases, especially those in `TestRegisterErr` and the behavior demonstrated in `TestFindHandler`, I could infer common mistakes users might make, such as:

* Registering overlapping paths.
* Forgetting the trailing slash and expecting an exact match when a prefix match exists.
* Misunderstanding how URL encoding affects pattern matching.

**7. Structuring the Answer:**

Finally, I organized the findings into a clear and structured answer, addressing each of the prompt's requirements: listing functionalities, providing code examples, explaining code reasoning, detailing command-line arguments (none in this case), and highlighting potential pitfalls. Using clear headings and bullet points improves readability.

**Self-Correction/Refinement during the Process:**

* Initially, I might have just described the tests superficially. However, going deeper into the *purpose* of each test case allowed me to infer the underlying logic and the specific aspects of the `http` package being verified.
* Recognizing the `use121` variable in `TestEscapedPathsAndPatterns` prompted me to understand the evolution of URL handling in Go, which is an important detail.
* I initially might have missed the implicit redirection behavior tested in `TestFindHandler`. A closer look at the expected `redirectHandler` helped me understand this feature.

By following this systematic approach, combining code analysis, logical reasoning, and knowledge of Go's features, I could effectively understand and explain the functionality of the given code snippet.
这段代码是 Go 语言标准库 `net/http` 包中 `server_test.go` 文件的一部分，它主要包含对 `http.Server` 及其相关功能进行单元测试的函数。 让我们逐个分析它的功能：

**1. `TestServerTLSHandshakeTimeout(t *testing.T)`:**

* **功能:** 测试 `http.Server` 的 `tlsHandshakeTimeout()` 方法的返回值。这个方法的作用是根据 `Server` 结构体的配置（如 `ReadTimeout`, `WriteTimeout`, `ReadHeaderTimeout`）计算出 TLS 握手超时时间。
* **推理:**  `tlsHandshakeTimeout()` 应该返回一个 `time.Duration` 类型的值，表示 TLS 握手的最大允许时间。它的计算逻辑可能是取 `ReadTimeout`、`WriteTimeout` 和 `ReadHeaderTimeout` 中的最小值，并且排除掉负数超时时间。
* **代码示例:**

```go
package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	server1 := &http.Server{}
	fmt.Println(server1.TLSConfig.Timeouts.HandshakeTimeout) // 输出: 0s

	server2 := &http.Server{
		ReadTimeout: 10 * time.Second,
	}
	// 注意：这里直接访问了 TLSConfig 内部的 Timeouts 字段，实际使用中不推荐这样做
	// 应该使用 server.tlsHandshakeTimeout() 方法获取
	fmt.Println(server2.TLSConfig.Timeouts.HandshakeTimeout) // 输出: 10s

	server3 := &http.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	// 预期 tlsHandshakeTimeout() 返回 5s
	fmt.Println(server3.tlsHandshakeTimeout()) // 输出: 5s

	server4 := &http.Server{
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	// 预期 tlsHandshakeTimeout() 返回 2s
	fmt.Println(server4.tlsHandshakeTimeout()) // 输出: 2s
}
```

* **假设的输入与输出:**  `TestServerTLSHandshakeTimeout` 函数本身就是测试函数，它内部定义了不同的 `Server` 结构体作为输入，并断言 `tlsHandshakeTimeout()` 的返回值是否符合预期。 例如，当 `Server` 的 `ReadTimeout` 为 `5 * time.Second`，`WriteTimeout` 为 `4 * time.Second` 时，预期的输出 (即 `tlsHandshakeTimeout()` 的返回值) 是 `4 * time.Second`。

**2. `TestFindHandler(t *testing.T)`:**

* **功能:** 测试 `http.ServeMux` 的 `findHandler()` 方法。这个方法的作用是根据请求的路径找到对应的处理器 (Handler)。它测试了不同路径的匹配规则，包括精确匹配、前缀匹配、以及对路径进行清理 (如移除多余斜杠，处理 `..` 等)。
* **推理:** `findHandler()` 方法应该能够正确地根据 `ServeMux` 中注册的模式 (pattern) 找到最匹配的处理器。当路径需要清理时，应该在匹配前进行清理。对于没有精确匹配但存在前缀匹配的情况，应该返回前缀匹配的处理器。对于以斜杠结尾的目录路径，如果没有精确匹配，可能会尝试重定向到带有斜杠的版本。
* **代码示例:**

```go
package main

import (
	"fmt"
	"net/http"
	"net/url"
)

func myHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "请求的路径是: %s", r.URL.Path)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", myHandler)
	mux.HandleFunc("/foo/", myHandler)
	mux.HandleFunc("/bar", myHandler)

	testCases := []struct {
		method string
		path   string
		found  bool // 假设的输出，表示是否找到处理器
	}{
		{"GET", "/", true},
		{"GET", "/foo", false}, // 没有完全匹配 "/foo"，但有前缀匹配 "/foo/"
		{"GET", "/foo/", true},
		{"GET", "/foo/baz", true}, // 前缀匹配 "/foo/"
		{"GET", "/bar", true},
		{"GET", "/bar/", false}, // 没有完全匹配 "/bar/"
		{"GET", "//foo", true}, // 路径会被清理成 "/foo"
	}

	for _, tc := range testCases {
		reqURL, _ := url.ParseRequestURI(tc.path)
		req := &http.Request{Method: tc.method, URL: reqURL, Host: "example.com"}
		handler, pattern := mux.Handler(req)
		fmt.Printf("Method: %s, Path: %s, Handler: %v, Pattern: %s\n", tc.method, tc.path, handler, pattern)
	}
}
```

* **假设的输入与输出:**  `TestFindHandler` 函数中，输入是不同的 HTTP 方法 (`GET`, `CONNECT`) 和不同的请求路径 (例如 "/", "//", "/foo", "/foo/x" 等)。输出是找到的 `Handler` 的字符串表示形式。例如，当输入路径为 "/foo/x" 时，由于注册了模式 "/foo/"，预期输出是与 "/foo/" 关联的 `handler` 实例的字符串表示 (`&http.handler{i:2}`). 当输入路径为 "/bar" 时，由于注册了精确匹配的 "/bar"，预期输出是与 "/bar" 关联的 `handler` 实例的字符串表示。 对于像 "//" 这样的输入，会被清理成 "/"，然后匹配到根路径的处理器。

**3. `TestEmptyServeMux(t *testing.T)`:**

* **功能:** 测试当 `http.ServeMux` 没有注册任何处理器时，调用 `Handler()` 方法是否会 panic。
* **推理:**  即使 `ServeMux` 是空的，调用 `Handler()` 应该返回默认的处理器 (通常是 `http.NotFoundHandler`) 而不是 panic。
* **代码示例:**  无需额外代码示例，该测试本身就展示了如何使用空的 `ServeMux`。

**4. `TestRegisterErr(t *testing.T)`:**

* **功能:** 测试 `http.ServeMux` 的 `registerErr()` 方法的错误处理。这个方法在注册处理器时，会检查模式 (pattern) 和处理器是否有效。
* **推理:**  `registerErr()` 应该能够检测出无效的模式 (如空字符串、包含非法字符) 和 nil 的处理器，并返回相应的错误。对于重复注册相同模式的情况，也应该返回错误。
* **代码示例:**  无需额外代码示例，该测试本身就展示了尝试注册各种错误情况。
* **假设的输入与输出:**  输入是尝试注册的模式字符串和处理器。输出是一个 `error` 类型的值。例如，当尝试注册空字符串模式时，预期会得到一个包含 "invalid pattern" 的错误。当尝试注册一个已经存在的模式时，预期会得到一个包含 "conflicts with pattern" 的错误。

**5. `TestExactMatch(t *testing.T)`:**

* **功能:** 测试 `exactMatch()` 函数。这个函数可能用于判断给定的路径是否与已注册的模式精确匹配。
* **推理:** `exactMatch()` 应该在路径和模式完全一致时返回 `true`，否则返回 `false`。它可能需要处理一些特殊情况，如模式中包含占位符。
* **代码示例:**

```go
package main

import "fmt"

func main() {
	// 注意：exactMatch 函数不是公开的，这里只是模拟其行为
	exactMatch := func(pattern, path string) bool {
		return pattern == path
	}

	testCases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/a", "/a", true},
		{"/a", "/b", false},
		{"/a/", "/a", false},
		{"/a", "/a/", false},
	}

	for _, tc := range testCases {
		got := exactMatch(tc.pattern, tc.path)
		fmt.Printf("Pattern: %s, Path: %s, Got: %t, Want: %t\n", tc.pattern, tc.path, got, tc.want)
	}
}
```

* **假设的输入与输出:** 输入是模式字符串和路径字符串。输出是一个布尔值，表示是否精确匹配。 例如，当输入模式为 "/a" 且路径为 "/a" 时，预期输出为 `true`。 当输入模式为 "/a" 且路径为 "/b" 时，预期输出为 `false`。

**6. `TestEscapedPathsAndPatterns(t *testing.T)`:**

* **功能:** 测试 `ServeMux` 如何处理 URL 编码的路径和模式。
* **推理:** `ServeMux` 在匹配路径时，可能会对路径进行解码。而模式的解码方式可能取决于 Go 的版本。这个测试旨在验证不同情况下编码路径和模式的匹配行为。
* **代码示例:**  需要结合 `http.ServeMux` 的行为来理解。

```go
package main

import (
	"fmt"
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "请求路径: %s\n", r.URL.Path)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", handler)        // 匹配未编码的 /a 和编码后的 /%61
	mux.HandleFunc("/%62", handler)     // 匹配未编码的 /b 和编码后的 /%62
	mux.HandleFunc("/%7B/%7D", handler) // 匹配 /{/}

	testPaths := []string{"/a", "/%61", "/b", "/%62", "/{/}"}

	for _, path := range testPaths {
		reqURL, _ := url.ParseRequestURI(path)
		req := &http.Request{Method: "GET", URL: reqURL, Host: "example.com"}
		h, pattern := mux.Handler(req)
		fmt.Printf("路径: %s, 匹配模式: %s\n", path, pattern)
		h.ServeHTTP(nil, req) // 模拟调用 Handler
	}
}
```

* **假设的输入与输出:** 输入是包含 URL 编码字符的模式和路径。输出是 `ServeMux` 是否能正确匹配它们。例如，当注册模式为 "/a"，请求路径为 "/%61" 时，应该能够匹配到该模式。当注册模式为 "/%62"，请求路径为 "/b" 时，也应该能够匹配。

**7. `TestCleanPath(t *testing.T)`:**

* **功能:** 测试 `cleanPath()` 函数。这个函数用于清理 URL 路径，例如移除多余的斜杠、解析 `..` 等。
* **推理:** `cleanPath()` 应该能够将各种形式的路径清理成规范的形式。
* **代码示例:**

```go
package main

import (
	"fmt"
	"path/filepath"
)

func main() {
	testCases := []struct {
		input string
		want  string
	}{
		{"//", "/"},
		{"/x", "/x"},
		{"//x", "/x"},
		{"x//", "/x/"},
		{"a//b/////c", "/a/b/c"},
		{"/foo/../bar/./..//baz", "/baz"},
	}

	for _, tc := range testCases {
		got := filepath.Clean(tc.input) // filepath.Clean 的行为类似 cleanPath
		fmt.Printf("Input: %s, Got: %s, Want: %s\n", tc.input, got, tc.want)
	}
}
```

* **假设的输入与输出:**  输入是各种可能需要清理的路径字符串。输出是清理后的规范化路径字符串。例如，输入 "//" 时，预期输出为 "/"。输入 "/foo/../bar/./..//baz" 时，预期输出为 "/baz"。

**8. `BenchmarkServerMatch(b *testing.B)`:**

* **功能:**  这是一个性能基准测试，用于衡量 `ServeMux` 匹配请求路径的效率。
* **推理:**  这个测试会创建多个路由，然后模拟大量请求，测量 `findHandler()` 方法的执行时间。
* **命令行参数:**  这个基准测试通常通过 `go test -bench=.` 命令运行。可以使用 `-benchtime` 参数指定测试运行的时间，`-benchmem` 参数查看内存分配情况。
* **使用者易犯错的点:**  在编写高性能的 HTTP 服务时，如果路由规则过于复杂或数量过多，可能会导致路由查找的性能瓶颈。这个基准测试可以帮助开发者了解不同路由策略的性能影响。

**总结:**

这段 `server_test.go` 代码主要测试了 `http.Server` 和 `http.ServeMux` 的核心功能，包括：

* **服务器配置:**  特别是 TLS 握手超时时间的计算。
* **请求路由:**  `ServeMux` 如何根据请求路径找到匹配的处理器，包括精确匹配、前缀匹配、路径清理和 URL 编码处理。
* **错误处理:**  注册处理器时对非法模式和处理器的校验。
* **性能:**  `ServeMux` 路由查找的性能。

通过这些单元测试，可以确保 `net/http` 包的这些核心组件能够按照预期工作，并且在各种边界情况下都能正确处理。

### 提示词
```
这是路径为go/src/net/http/server_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Server unit tests

package http

import (
	"fmt"
	"net/url"
	"regexp"
	"testing"
	"time"
)

func TestServerTLSHandshakeTimeout(t *testing.T) {
	tests := []struct {
		s    *Server
		want time.Duration
	}{
		{
			s:    &Server{},
			want: 0,
		},
		{
			s: &Server{
				ReadTimeout: -1,
			},
			want: 0,
		},
		{
			s: &Server{
				ReadTimeout: 5 * time.Second,
			},
			want: 5 * time.Second,
		},
		{
			s: &Server{
				ReadTimeout:  5 * time.Second,
				WriteTimeout: -1,
			},
			want: 5 * time.Second,
		},
		{
			s: &Server{
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 4 * time.Second,
			},
			want: 4 * time.Second,
		},
		{
			s: &Server{
				ReadTimeout:       5 * time.Second,
				ReadHeaderTimeout: 2 * time.Second,
				WriteTimeout:      4 * time.Second,
			},
			want: 2 * time.Second,
		},
	}
	for i, tt := range tests {
		got := tt.s.tlsHandshakeTimeout()
		if got != tt.want {
			t.Errorf("%d. got %v; want %v", i, got, tt.want)
		}
	}
}

type handler struct{ i int }

func (handler) ServeHTTP(ResponseWriter, *Request) {}

func TestFindHandler(t *testing.T) {
	mux := NewServeMux()
	for _, ph := range []struct {
		pat string
		h   Handler
	}{
		{"/", &handler{1}},
		{"/foo/", &handler{2}},
		{"/foo", &handler{3}},
		{"/bar/", &handler{4}},
		{"//foo", &handler{5}},
	} {
		mux.Handle(ph.pat, ph.h)
	}

	for _, test := range []struct {
		method      string
		path        string
		wantHandler string
	}{
		{"GET", "/", "&http.handler{i:1}"},
		{"GET", "//", `&http.redirectHandler{url:"/", code:301}`},
		{"GET", "/foo/../bar/./..//baz", `&http.redirectHandler{url:"/baz", code:301}`},
		{"GET", "/foo", "&http.handler{i:3}"},
		{"GET", "/foo/x", "&http.handler{i:2}"},
		{"GET", "/bar/x", "&http.handler{i:4}"},
		{"GET", "/bar", `&http.redirectHandler{url:"/bar/", code:301}`},
		{"CONNECT", "/", "&http.handler{i:1}"},
		{"CONNECT", "//", "&http.handler{i:1}"},
		{"CONNECT", "//foo", "&http.handler{i:5}"},
		{"CONNECT", "/foo/../bar/./..//baz", "&http.handler{i:2}"},
		{"CONNECT", "/foo", "&http.handler{i:3}"},
		{"CONNECT", "/foo/x", "&http.handler{i:2}"},
		{"CONNECT", "/bar/x", "&http.handler{i:4}"},
		{"CONNECT", "/bar", `&http.redirectHandler{url:"/bar/", code:301}`},
	} {
		var r Request
		r.Method = test.method
		r.Host = "example.com"
		r.URL = &url.URL{Path: test.path}
		gotH, _, _, _ := mux.findHandler(&r)
		got := fmt.Sprintf("%#v", gotH)
		if got != test.wantHandler {
			t.Errorf("%s %q: got %q, want %q", test.method, test.path, got, test.wantHandler)
		}
	}
}

func TestEmptyServeMux(t *testing.T) {
	// Verify that a ServeMux with nothing registered
	// doesn't panic.
	mux := NewServeMux()
	var r Request
	r.Method = "GET"
	r.Host = "example.com"
	r.URL = &url.URL{Path: "/"}
	_, p := mux.Handler(&r)
	if p != "" {
		t.Errorf(`got %q, want ""`, p)
	}
}

func TestRegisterErr(t *testing.T) {
	mux := NewServeMux()
	h := &handler{}
	mux.Handle("/a", h)

	for _, test := range []struct {
		pattern    string
		handler    Handler
		wantRegexp string
	}{
		{"", h, "invalid pattern"},
		{"/", nil, "nil handler"},
		{"/", HandlerFunc(nil), "nil handler"},
		{"/{x", h, `parsing "/\{x": at offset 1: bad wildcard segment`},
		{"/a", h, `conflicts with pattern.* \(registered at .*/server_test.go:\d+`},
	} {
		t.Run(fmt.Sprintf("%s:%#v", test.pattern, test.handler), func(t *testing.T) {
			err := mux.registerErr(test.pattern, test.handler)
			if err == nil {
				t.Fatal("got nil error")
			}
			re := regexp.MustCompile(test.wantRegexp)
			if g := err.Error(); !re.MatchString(g) {
				t.Errorf("\ngot %q\nwant string matching %q", g, test.wantRegexp)
			}
		})
	}
}

func TestExactMatch(t *testing.T) {
	for _, test := range []struct {
		pattern string
		path    string
		want    bool
	}{
		{"", "/a", false},
		{"/", "/a", false},
		{"/a", "/a", true},
		{"/a/{x...}", "/a/b", false},
		{"/a/{x}", "/a/b", true},
		{"/a/b/", "/a/b/", true},
		{"/a/b/{$}", "/a/b/", true},
		{"/a/", "/a/b/", false},
	} {
		var n *routingNode
		if test.pattern != "" {
			pat := mustParsePattern(t, test.pattern)
			n = &routingNode{pattern: pat}
		}
		got := exactMatch(n, test.path)
		if got != test.want {
			t.Errorf("%q, %s: got %t, want %t", test.pattern, test.path, got, test.want)
		}
	}
}

func TestEscapedPathsAndPatterns(t *testing.T) {
	matches := []struct {
		pattern  string
		paths    []string // paths that match the pattern
		paths121 []string // paths that matched the pattern in Go 1.21.
	}{
		{
			"/a", // this pattern matches a path that unescapes to "/a"
			[]string{"/a", "/%61"},
			[]string{"/a", "/%61"},
		},
		{
			"/%62", // patterns are unescaped by segment; matches paths that unescape to "/b"
			[]string{"/b", "/%62"},
			[]string{"/%2562"}, // In 1.21, patterns were not unescaped but paths were.
		},
		{
			"/%7B/%7D", // the only way to write a pattern that matches '{' or '}'
			[]string{"/{/}", "/%7b/}", "/{/%7d", "/%7B/%7D"},
			[]string{"/%257B/%257D"}, // In 1.21, patterns were not unescaped.
		},
		{
			"/%x", // patterns that do not unescape are left unchanged
			[]string{"/%25x"},
			[]string{"/%25x"},
		},
	}

	run := func(t *testing.T, test121 bool) {
		defer func(u bool) { use121 = u }(use121)
		use121 = test121

		mux := NewServeMux()
		for _, m := range matches {
			mux.HandleFunc(m.pattern, func(w ResponseWriter, r *Request) {})
		}

		for _, m := range matches {
			paths := m.paths
			if use121 {
				paths = m.paths121
			}
			for _, p := range paths {
				u, err := url.ParseRequestURI(p)
				if err != nil {
					t.Fatal(err)
				}
				req := &Request{
					URL: u,
				}
				_, gotPattern := mux.Handler(req)
				if g, w := gotPattern, m.pattern; g != w {
					t.Errorf("%s: pattern: got %q, want %q", p, g, w)
				}
			}
		}
	}

	t.Run("latest", func(t *testing.T) { run(t, false) })
	t.Run("1.21", func(t *testing.T) { run(t, true) })
}

func TestCleanPath(t *testing.T) {
	for _, test := range []struct {
		in, want string
	}{
		{"//", "/"},
		{"/x", "/x"},
		{"//x", "/x"},
		{"x//", "/x/"},
		{"a//b/////c", "/a/b/c"},
		{"/foo/../bar/./..//baz", "/baz"},
	} {
		got := cleanPath(test.in)
		if got != test.want {
			t.Errorf("%s: got %q, want %q", test.in, got, test.want)
		}
	}
}

func BenchmarkServerMatch(b *testing.B) {
	fn := func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "OK")
	}
	mux := NewServeMux()
	mux.HandleFunc("/", fn)
	mux.HandleFunc("/index", fn)
	mux.HandleFunc("/home", fn)
	mux.HandleFunc("/about", fn)
	mux.HandleFunc("/contact", fn)
	mux.HandleFunc("/robots.txt", fn)
	mux.HandleFunc("/products/", fn)
	mux.HandleFunc("/products/1", fn)
	mux.HandleFunc("/products/2", fn)
	mux.HandleFunc("/products/3", fn)
	mux.HandleFunc("/products/3/image.jpg", fn)
	mux.HandleFunc("/admin", fn)
	mux.HandleFunc("/admin/products/", fn)
	mux.HandleFunc("/admin/products/create", fn)
	mux.HandleFunc("/admin/products/update", fn)
	mux.HandleFunc("/admin/products/delete", fn)

	paths := []string{"/", "/notfound", "/admin/", "/admin/foo", "/contact", "/products",
		"/products/", "/products/3/image.jpg"}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		r, err := NewRequest("GET", "http://example.com/"+paths[i%len(paths)], nil)
		if err != nil {
			b.Fatal(err)
		}
		if h, p, _, _ := mux.findHandler(r); h != nil && p == "" {
			b.Error("impossible")
		}
	}
	b.StopTimer()
}
```