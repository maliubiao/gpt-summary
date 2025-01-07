Response:
The user provided a part of a Go test file (`url_test.go`) and asked to summarize its functionality. This is the second part of the file.

Let's break down the code and identify the test cases it covers:

1. **`TestParseQuery`**: This function tests the `ParseQuery` function. It iterates through a series of test cases defined in `parseTests`. Each test case includes an input query string, the expected output `Values` (a map of string to string slices), and a boolean indicating whether the parsing is expected to succeed.

2. **`TestRequestURI`**: This function tests the `RequestURI` method of the `URL` struct. It checks if the method correctly formats the request URI based on the `URL` struct's fields like `Scheme`, `Host`, `Path`, `Opaque`, and `RawQuery`.

3. **`TestParseFailure`**: This function specifically tests how `ParseQuery` handles parsing failures by ensuring that the *first* parsing error is returned.

4. **`TestParseErrors`**: This function tests various scenarios where the `Parse` function is expected to fail due to invalid URL formats. It covers cases with invalid characters in the schema, hostnames, and other parts of the URL.

5. **`TestStarRequest`**: This function tests the behavior of `Parse` and `RequestURI` when the input is a single asterisk (`"*"`).

6. **`TestShouldEscape`**: This function tests the `shouldEscape` helper function, which determines if a given byte should be escaped based on the encoding mode (e.g., for paths, query parameters, etc.).

7. **`TestURLErrorImplementsNetError`**: This function tests if the `Error` type in the `net/url` package correctly implements the `net.Error` interface, which includes `Timeout()` and `Temporary()` methods.

8. **`TestURLHostnameAndPort`**: This function tests the `Hostname()` and `Port()` methods of the `URL` struct, verifying that they correctly extract the hostname and port from the `Host` field.

9. **`TestJSON`**: This function tests the JSON marshaling and unmarshaling of the `URL` struct.

10. **`TestGob`**: This function tests the gob encoding and decoding of the `URL` struct.

11. **`TestNilUser`**: This function tests the behavior of accessing username and password from a `URL` with no user information.

12. **`TestInvalidUserPassword`**: This function tests the `Parse` function's handling of invalid characters in the username or password.

13. **`TestRejectControlCharacters`**: This function tests if the `Parse` function correctly rejects URLs containing control characters.

14. **`BenchmarkQueryEscape`, `BenchmarkPathEscape`, `BenchmarkQueryUnescape`, `BenchmarkPathUnescape`**: These functions are benchmarks to measure the performance of the `QueryEscape`, `PathEscape`, `QueryUnescape`, and `PathUnescape` functions.

15. **`TestJoinPath`**: This function tests the `JoinPath` function (and the `JoinPath` method of the `URL` struct), which joins a base path with subsequent path elements.

Based on these observations, the primary goal of this code snippet is to test the functionality related to parsing and manipulating URLs in Go's `net/url` package. It specifically focuses on:

*   Parsing query strings.
*   Formatting request URIs.
*   Handling various parsing error scenarios.
*   Escaping and unescaping parts of URLs.
*   Extracting hostname and port information.
*   Implementing the `net.Error` interface for URL errors.
*   Encoding and decoding URLs using JSON and gob.
*   Handling user information in URLs.
*   Preventing invalid characters in URLs.
*   Joining path segments.

Now, let's condense this into a concise summary.
这是 Go 语言 `net/url` 包中 `url_test.go` 文件的第二部分，主要负责测试 URL 解析和操作的各种功能。

**主要功能归纳:**

这部分代码主要测试了 `net/url` 包中以下功能：

1. **查询字符串解析 (`ParseQuery`)**: 测试将查询字符串解析为键值对 (`url.Values`) 的功能，并验证解析成功或失败的情况。
2. **请求 URI 构建 (`RequestURI`)**: 测试根据 `url.URL` 结构体的内容生成符合 HTTP 请求的 URI 字符串的功能。
3. **URL 解析错误处理 (`Parse` 错误情况)**: 测试 `Parse` 函数在遇到各种格式错误的 URL 时是否能正确返回错误。
4. **特殊 URL 解析 (`"*"`)**: 测试解析特殊字符如 `"*"` 作为 URL 的行为。
5. **URL 字符转义判断 (`shouldEscape`)**: 测试判断特定字符是否需要在 URL 的不同部分进行转义的逻辑。
6. **URL 错误类型 (`url.Error`)**: 测试 `url.Error` 类型是否实现了 `net.Error` 接口，以及是否正确地传递了底层的 `timeout` 和 `temporary` 属性。
7. **主机名和端口提取 (`Hostname`, `Port`)**: 测试从 `url.URL` 结构体的 `Host` 字段中正确提取主机名和端口号的功能。
8. **URL 的 JSON 和 Gob 编码/解码**: 测试 `url.URL` 结构体是否支持 JSON 和 Gob 格式的序列化和反序列化。
9. **处理空的 `User` 信息**: 测试当 URL 中没有用户信息时，访问 `url.User` 的行为。
10. **验证用户名和密码的有效性**: 测试解析包含非法字符的用户名或密码的 URL 时是否会报错。
11. **拒绝控制字符**: 测试 `Parse` 函数是否会拒绝包含控制字符的 URL。
12. **URL 字符转义和反转义性能 (`QueryEscape`, `PathEscape`, `QueryUnescape`, `PathUnescape` 的 Benchmark 测试)**:  对 URL 编码和解码的性能进行基准测试。
13. **路径拼接 (`JoinPath`)**: 测试将基础路径和后续路径片段拼接成一个完整路径的功能。

**Go 代码举例说明 (查询字符串解析 `ParseQuery`):**

```go
package main

import (
	"fmt"
	"net/url"
)

func main() {
	query := "name=John&age=30&city=New%20York"
	values, err := url.ParseQuery(query)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}

	fmt.Println("解析后的键值对:", values)
	// 输出: 解析后的键值对: map[age:[30] city:[New York] name:[John]]

	fmt.Println("姓名:", values.Get("name"))    // 输出: 姓名: John
	fmt.Println("年龄:", values.Get("age"))     // 输出: 年龄: 30
	fmt.Println("城市:", values.Get("city"))    // 输出: 城市: New York
}
```

**假设的输入与输出 (基于 `parseTests`):**

**输入:** `query: "a=1&b=2"`

**输出:** `out: Values{"a": []string{"1"}, "b": []string{"2"}}, ok: true`

**输入:** `query: "a=1;b=2"`

**输出:** `out: Values{}, ok: false` (因为使用了分号分隔，根据测试用例的定义，这被认为是错误的格式)

**代码推理:**

`TestParseQuery` 函数通过遍历 `parseTests` 中的测试用例，针对每个 `query` 字符串调用 `url.ParseQuery` 函数。它会比较返回的 `url.Values` 是否与预期的 `out` 相同，并检查是否发生了预期的错误（通过 `ok` 字段判断）。

**命令行参数处理:**

这部分代码主要测试的是 Go 语言的标准库功能，并不直接涉及处理命令行参数。`net/url` 包用于解析和操作 URL 字符串，通常被其他网络相关的包或程序使用。如果需要处理命令行参数中的 URL，可以使用 `flag` 包来获取参数值，然后传递给 `url.Parse` 或其他 `net/url` 包的函数。

**使用者易犯错的点举例 (基于 `parseTests`):**

*   **使用分号 `;` 分隔查询参数:**  用户可能会习惯性地使用分号分隔查询参数，但在标准的 URL 格式中，查询参数应该使用 `&` 分隔。`ParseQuery` 函数在这种情况下会返回错误。

    ```go
    package main

    import (
        "fmt"
        "net/url"
    )

    func main() {
        query := "param1=value1;param2=value2" // 错误地使用了分号
        values, err := url.ParseQuery(query)
        if err != nil {
            fmt.Println("解析错误:", err) // 输出: 解析错误: invalid semicolon separator in query
        } else {
            fmt.Println("解析后的值:", values)
        }
    }
    ```

**总结这部分的功能:**

这部分 `url_test.go` 文件的主要功能是**全面测试 Go 语言 `net/url` 包中 URL 解析和操作的各种核心功能，包括查询字符串解析、请求 URI 构建、错误处理、特殊字符处理、编码解码、主机名端口提取以及路径拼接等。**  通过大量的测试用例，确保了该包的稳定性和正确性。

Prompt: 
```
这是路径为go/src/net/url/url_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
, "2", "banana"}},
		ok:    true,
	},
	{
		query: "ascii=%3Ckey%3A+0x90%3E",
		out:   Values{"ascii": []string{"<key: 0x90>"}},
		ok:    true,
	}, {
		query: "a=1;b=2",
		out:   Values{},
		ok:    false,
	}, {
		query: "a;b=1",
		out:   Values{},
		ok:    false,
	}, {
		query: "a=%3B", // hex encoding for semicolon
		out:   Values{"a": []string{";"}},
		ok:    true,
	},
	{
		query: "a%3Bb=1",
		out:   Values{"a;b": []string{"1"}},
		ok:    true,
	},
	{
		query: "a=1&a=2;a=banana",
		out:   Values{"a": []string{"1"}},
		ok:    false,
	},
	{
		query: "a;b&c=1",
		out:   Values{"c": []string{"1"}},
		ok:    false,
	},
	{
		query: "a=1&b=2;a=3&c=4",
		out:   Values{"a": []string{"1"}, "c": []string{"4"}},
		ok:    false,
	},
	{
		query: "a=1&b=2;c=3",
		out:   Values{"a": []string{"1"}},
		ok:    false,
	},
	{
		query: ";",
		out:   Values{},
		ok:    false,
	},
	{
		query: "a=1;",
		out:   Values{},
		ok:    false,
	},
	{
		query: "a=1&;",
		out:   Values{"a": []string{"1"}},
		ok:    false,
	},
	{
		query: ";a=1&b=2",
		out:   Values{"b": []string{"2"}},
		ok:    false,
	},
	{
		query: "a=1&b=2;",
		out:   Values{"a": []string{"1"}},
		ok:    false,
	},
}

func TestParseQuery(t *testing.T) {
	for _, test := range parseTests {
		t.Run(test.query, func(t *testing.T) {
			form, err := ParseQuery(test.query)
			if test.ok != (err == nil) {
				want := "<error>"
				if test.ok {
					want = "<nil>"
				}
				t.Errorf("Unexpected error: %v, want %v", err, want)
			}
			if len(form) != len(test.out) {
				t.Errorf("len(form) = %d, want %d", len(form), len(test.out))
			}
			for k, evs := range test.out {
				vs, ok := form[k]
				if !ok {
					t.Errorf("Missing key %q", k)
					continue
				}
				if len(vs) != len(evs) {
					t.Errorf("len(form[%q]) = %d, want %d", k, len(vs), len(evs))
					continue
				}
				for j, ev := range evs {
					if v := vs[j]; v != ev {
						t.Errorf("form[%q][%d] = %q, want %q", k, j, v, ev)
					}
				}
			}
		})
	}
}

type RequestURITest struct {
	url *URL
	out string
}

var requritests = []RequestURITest{
	{
		&URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "",
		},
		"/",
	},
	{
		&URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "/a b",
		},
		"/a%20b",
	},
	// golang.org/issue/4860 variant 1
	{
		&URL{
			Scheme: "http",
			Host:   "example.com",
			Opaque: "/%2F/%2F/",
		},
		"/%2F/%2F/",
	},
	// golang.org/issue/4860 variant 2
	{
		&URL{
			Scheme: "http",
			Host:   "example.com",
			Opaque: "//other.example.com/%2F/%2F/",
		},
		"http://other.example.com/%2F/%2F/",
	},
	// better fix for issue 4860
	{
		&URL{
			Scheme:  "http",
			Host:    "example.com",
			Path:    "/////",
			RawPath: "/%2F/%2F/",
		},
		"/%2F/%2F/",
	},
	{
		&URL{
			Scheme:  "http",
			Host:    "example.com",
			Path:    "/////",
			RawPath: "/WRONG/", // ignored because doesn't match Path
		},
		"/////",
	},
	{
		&URL{
			Scheme:   "http",
			Host:     "example.com",
			Path:     "/a b",
			RawQuery: "q=go+language",
		},
		"/a%20b?q=go+language",
	},
	{
		&URL{
			Scheme:   "http",
			Host:     "example.com",
			Path:     "/a b",
			RawPath:  "/a b", // ignored because invalid
			RawQuery: "q=go+language",
		},
		"/a%20b?q=go+language",
	},
	{
		&URL{
			Scheme:   "http",
			Host:     "example.com",
			Path:     "/a?b",
			RawPath:  "/a?b", // ignored because invalid
			RawQuery: "q=go+language",
		},
		"/a%3Fb?q=go+language",
	},
	{
		&URL{
			Scheme: "myschema",
			Opaque: "opaque",
		},
		"opaque",
	},
	{
		&URL{
			Scheme:   "myschema",
			Opaque:   "opaque",
			RawQuery: "q=go+language",
		},
		"opaque?q=go+language",
	},
	{
		&URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "//foo",
		},
		"//foo",
	},
	{
		&URL{
			Scheme:     "http",
			Host:       "example.com",
			Path:       "/foo",
			ForceQuery: true,
		},
		"/foo?",
	},
}

func TestRequestURI(t *testing.T) {
	for _, tt := range requritests {
		s := tt.url.RequestURI()
		if s != tt.out {
			t.Errorf("%#v.RequestURI() == %q (expected %q)", tt.url, s, tt.out)
		}
	}
}

func TestParseFailure(t *testing.T) {
	// Test that the first parse error is returned.
	const url = "%gh&%ij"
	_, err := ParseQuery(url)
	errStr := fmt.Sprint(err)
	if !strings.Contains(errStr, "%gh") {
		t.Errorf(`ParseQuery(%q) returned error %q, want something containing %q"`, url, errStr, "%gh")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"http://[::1]", false},
		{"http://[::1]:80", false},
		{"http://[::1]:namedport", true}, // rfc3986 3.2.3
		{"http://x:namedport", true},     // rfc3986 3.2.3
		{"http://[::1]/", false},
		{"http://[::1]a", true},
		{"http://[::1]%23", true},
		{"http://[::1%25en0]", false},    // valid zone id
		{"http://[::1]:", false},         // colon, but no port OK
		{"http://x:", false},             // colon, but no port OK
		{"http://[::1]:%38%30", true},    // not allowed: % encoding only for non-ASCII
		{"http://[::1%25%41]", false},    // RFC 6874 allows over-escaping in zone
		{"http://[%10::1]", true},        // no %xx escapes in IP address
		{"http://[::1]/%48", false},      // %xx in path is fine
		{"http://%41:8080/", true},       // not allowed: % encoding only for non-ASCII
		{"mysql://x@y(z:123)/foo", true}, // not well-formed per RFC 3986, golang.org/issue/33646
		{"mysql://x@y(1.2.3.4:123)/foo", true},

		{" http://foo.com", true},  // invalid character in schema
		{"ht tp://foo.com", true},  // invalid character in schema
		{"ahttp://foo.com", false}, // valid schema characters
		{"1http://foo.com", true},  // invalid character in schema

		{"http://[]%20%48%54%54%50%2f%31%2e%31%0a%4d%79%48%65%61%64%65%72%3a%20%31%32%33%0a%0a/", true}, // golang.org/issue/11208
		{"http://a b.com/", true},    // no space in host name please
		{"cache_object://foo", true}, // scheme cannot have _, relative path cannot have : in first segment
		{"cache_object:foo", true},
		{"cache_object:foo/bar", true},
		{"cache_object/:foo/bar", false},
	}
	for _, tt := range tests {
		u, err := Parse(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %#v; want an error", tt.in, u)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) = %v; want no error", tt.in, err)
		}
	}
}

// Issue 11202
func TestStarRequest(t *testing.T) {
	u, err := Parse("*")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.RequestURI(), "*"; got != want {
		t.Errorf("RequestURI = %q; want %q", got, want)
	}
}

type shouldEscapeTest struct {
	in     byte
	mode   encoding
	escape bool
}

var shouldEscapeTests = []shouldEscapeTest{
	// Unreserved characters (§2.3)
	{'a', encodePath, false},
	{'a', encodeUserPassword, false},
	{'a', encodeQueryComponent, false},
	{'a', encodeFragment, false},
	{'a', encodeHost, false},
	{'z', encodePath, false},
	{'A', encodePath, false},
	{'Z', encodePath, false},
	{'0', encodePath, false},
	{'9', encodePath, false},
	{'-', encodePath, false},
	{'-', encodeUserPassword, false},
	{'-', encodeQueryComponent, false},
	{'-', encodeFragment, false},
	{'.', encodePath, false},
	{'_', encodePath, false},
	{'~', encodePath, false},

	// User information (§3.2.1)
	{':', encodeUserPassword, true},
	{'/', encodeUserPassword, true},
	{'?', encodeUserPassword, true},
	{'@', encodeUserPassword, true},
	{'$', encodeUserPassword, false},
	{'&', encodeUserPassword, false},
	{'+', encodeUserPassword, false},
	{',', encodeUserPassword, false},
	{';', encodeUserPassword, false},
	{'=', encodeUserPassword, false},

	// Host (IP address, IPv6 address, registered name, port suffix; §3.2.2)
	{'!', encodeHost, false},
	{'$', encodeHost, false},
	{'&', encodeHost, false},
	{'\'', encodeHost, false},
	{'(', encodeHost, false},
	{')', encodeHost, false},
	{'*', encodeHost, false},
	{'+', encodeHost, false},
	{',', encodeHost, false},
	{';', encodeHost, false},
	{'=', encodeHost, false},
	{':', encodeHost, false},
	{'[', encodeHost, false},
	{']', encodeHost, false},
	{'0', encodeHost, false},
	{'9', encodeHost, false},
	{'A', encodeHost, false},
	{'z', encodeHost, false},
	{'_', encodeHost, false},
	{'-', encodeHost, false},
	{'.', encodeHost, false},
}

func TestShouldEscape(t *testing.T) {
	for _, tt := range shouldEscapeTests {
		if shouldEscape(tt.in, tt.mode) != tt.escape {
			t.Errorf("shouldEscape(%q, %v) returned %v; expected %v", tt.in, tt.mode, !tt.escape, tt.escape)
		}
	}
}

type timeoutError struct {
	timeout bool
}

func (e *timeoutError) Error() string { return "timeout error" }
func (e *timeoutError) Timeout() bool { return e.timeout }

type temporaryError struct {
	temporary bool
}

func (e *temporaryError) Error() string   { return "temporary error" }
func (e *temporaryError) Temporary() bool { return e.temporary }

type timeoutTemporaryError struct {
	timeoutError
	temporaryError
}

func (e *timeoutTemporaryError) Error() string { return "timeout/temporary error" }

var netErrorTests = []struct {
	err       error
	timeout   bool
	temporary bool
}{{
	err:       &Error{"Get", "http://google.com/", &timeoutError{timeout: true}},
	timeout:   true,
	temporary: false,
}, {
	err:       &Error{"Get", "http://google.com/", &timeoutError{timeout: false}},
	timeout:   false,
	temporary: false,
}, {
	err:       &Error{"Get", "http://google.com/", &temporaryError{temporary: true}},
	timeout:   false,
	temporary: true,
}, {
	err:       &Error{"Get", "http://google.com/", &temporaryError{temporary: false}},
	timeout:   false,
	temporary: false,
}, {
	err:       &Error{"Get", "http://google.com/", &timeoutTemporaryError{timeoutError{timeout: true}, temporaryError{temporary: true}}},
	timeout:   true,
	temporary: true,
}, {
	err:       &Error{"Get", "http://google.com/", &timeoutTemporaryError{timeoutError{timeout: false}, temporaryError{temporary: true}}},
	timeout:   false,
	temporary: true,
}, {
	err:       &Error{"Get", "http://google.com/", &timeoutTemporaryError{timeoutError{timeout: true}, temporaryError{temporary: false}}},
	timeout:   true,
	temporary: false,
}, {
	err:       &Error{"Get", "http://google.com/", &timeoutTemporaryError{timeoutError{timeout: false}, temporaryError{temporary: false}}},
	timeout:   false,
	temporary: false,
}, {
	err:       &Error{"Get", "http://google.com/", io.EOF},
	timeout:   false,
	temporary: false,
}}

// Test that url.Error implements net.Error and that it forwards
func TestURLErrorImplementsNetError(t *testing.T) {
	for i, tt := range netErrorTests {
		err, ok := tt.err.(net.Error)
		if !ok {
			t.Errorf("%d: %T does not implement net.Error", i+1, tt.err)
			continue
		}
		if err.Timeout() != tt.timeout {
			t.Errorf("%d: err.Timeout(): got %v, want %v", i+1, err.Timeout(), tt.timeout)
			continue
		}
		if err.Temporary() != tt.temporary {
			t.Errorf("%d: err.Temporary(): got %v, want %v", i+1, err.Temporary(), tt.temporary)
		}
	}
}

func TestURLHostnameAndPort(t *testing.T) {
	tests := []struct {
		in   string // URL.Host field
		host string
		port string
	}{
		{"foo.com:80", "foo.com", "80"},
		{"foo.com", "foo.com", ""},
		{"foo.com:", "foo.com", ""},
		{"FOO.COM", "FOO.COM", ""}, // no canonicalization
		{"1.2.3.4", "1.2.3.4", ""},
		{"1.2.3.4:80", "1.2.3.4", "80"},
		{"[1:2:3:4]", "1:2:3:4", ""},
		{"[1:2:3:4]:80", "1:2:3:4", "80"},
		{"[::1]:80", "::1", "80"},
		{"[::1]", "::1", ""},
		{"[::1]:", "::1", ""},
		{"localhost", "localhost", ""},
		{"localhost:443", "localhost", "443"},
		{"some.super.long.domain.example.org:8080", "some.super.long.domain.example.org", "8080"},
		{"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:17000", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "17000"},
		{"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", ""},

		// Ensure that even when not valid, Host is one of "Hostname",
		// "Hostname:Port", "[Hostname]" or "[Hostname]:Port".
		// See https://golang.org/issue/29098.
		{"[google.com]:80", "google.com", "80"},
		{"google.com]:80", "google.com]", "80"},
		{"google.com:80_invalid_port", "google.com:80_invalid_port", ""},
		{"[::1]extra]:80", "::1]extra", "80"},
		{"google.com]extra:extra", "google.com]extra:extra", ""},
	}
	for _, tt := range tests {
		u := &URL{Host: tt.in}
		host, port := u.Hostname(), u.Port()
		if host != tt.host {
			t.Errorf("Hostname for Host %q = %q; want %q", tt.in, host, tt.host)
		}
		if port != tt.port {
			t.Errorf("Port for Host %q = %q; want %q", tt.in, port, tt.port)
		}
	}
}

var _ encodingPkg.BinaryMarshaler = (*URL)(nil)
var _ encodingPkg.BinaryUnmarshaler = (*URL)(nil)
var _ encodingPkg.BinaryAppender = (*URL)(nil)

func TestJSON(t *testing.T) {
	u, err := Parse("https://www.google.com/x?y=z")
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}

	// If only we could implement TextMarshaler/TextUnmarshaler,
	// this would work:
	//
	// if string(js) != strconv.Quote(u.String()) {
	// 	t.Errorf("json encoding: %s\nwant: %s\n", js, strconv.Quote(u.String()))
	// }

	u1 := new(URL)
	err = json.Unmarshal(js, u1)
	if err != nil {
		t.Fatal(err)
	}
	if u1.String() != u.String() {
		t.Errorf("json decoded to: %s\nwant: %s\n", u1, u)
	}
}

func TestGob(t *testing.T) {
	u, err := Parse("https://www.google.com/x?y=z")
	if err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	err = gob.NewEncoder(&w).Encode(u)
	if err != nil {
		t.Fatal(err)
	}

	u1 := new(URL)
	err = gob.NewDecoder(&w).Decode(u1)
	if err != nil {
		t.Fatal(err)
	}
	if u1.String() != u.String() {
		t.Errorf("json decoded to: %s\nwant: %s\n", u1, u)
	}
}

func TestNilUser(t *testing.T) {
	defer func() {
		if v := recover(); v != nil {
			t.Fatalf("unexpected panic: %v", v)
		}
	}()

	u, err := Parse("http://foo.com/")

	if err != nil {
		t.Fatalf("parse err: %v", err)
	}

	if v := u.User.Username(); v != "" {
		t.Fatalf("expected empty username, got %s", v)
	}

	if v, ok := u.User.Password(); v != "" || ok {
		t.Fatalf("expected empty password, got %s (%v)", v, ok)
	}

	if v := u.User.String(); v != "" {
		t.Fatalf("expected empty string, got %s", v)
	}
}

func TestInvalidUserPassword(t *testing.T) {
	_, err := Parse("http://user^:passwo^rd@foo.com/")
	if got, wantsub := fmt.Sprint(err), "net/url: invalid userinfo"; !strings.Contains(got, wantsub) {
		t.Errorf("error = %q; want substring %q", got, wantsub)
	}
}

func TestRejectControlCharacters(t *testing.T) {
	tests := []string{
		"http://foo.com/?foo\nbar",
		"http\r://foo.com/",
		"http://foo\x7f.com/",
	}
	for _, s := range tests {
		_, err := Parse(s)
		const wantSub = "net/url: invalid control character in URL"
		if got := fmt.Sprint(err); !strings.Contains(got, wantSub) {
			t.Errorf("Parse(%q) error = %q; want substring %q", s, got, wantSub)
		}
	}

	// But don't reject non-ASCII CTLs, at least for now:
	if _, err := Parse("http://foo.com/ctl\x80"); err != nil {
		t.Errorf("error parsing URL with non-ASCII control byte: %v", err)
	}

}

var escapeBenchmarks = []struct {
	unescaped string
	query     string
	path      string
}{
	{
		unescaped: "one two",
		query:     "one+two",
		path:      "one%20two",
	},
	{
		unescaped: "Фотки собак",
		query:     "%D0%A4%D0%BE%D1%82%D0%BA%D0%B8+%D1%81%D0%BE%D0%B1%D0%B0%D0%BA",
		path:      "%D0%A4%D0%BE%D1%82%D0%BA%D0%B8%20%D1%81%D0%BE%D0%B1%D0%B0%D0%BA",
	},

	{
		unescaped: "shortrun(break)shortrun",
		query:     "shortrun%28break%29shortrun",
		path:      "shortrun%28break%29shortrun",
	},

	{
		unescaped: "longerrunofcharacters(break)anotherlongerrunofcharacters",
		query:     "longerrunofcharacters%28break%29anotherlongerrunofcharacters",
		path:      "longerrunofcharacters%28break%29anotherlongerrunofcharacters",
	},

	{
		unescaped: strings.Repeat("padded/with+various%characters?that=need$some@escaping+paddedsowebreak/256bytes", 4),
		query:     strings.Repeat("padded%2Fwith%2Bvarious%25characters%3Fthat%3Dneed%24some%40escaping%2Bpaddedsowebreak%2F256bytes", 4),
		path:      strings.Repeat("padded%2Fwith+various%25characters%3Fthat=need$some@escaping+paddedsowebreak%2F256bytes", 4),
	},
}

func BenchmarkQueryEscape(b *testing.B) {
	for _, tc := range escapeBenchmarks {
		b.Run("", func(b *testing.B) {
			b.ReportAllocs()
			var g string
			for i := 0; i < b.N; i++ {
				g = QueryEscape(tc.unescaped)
			}
			b.StopTimer()
			if g != tc.query {
				b.Errorf("QueryEscape(%q) == %q, want %q", tc.unescaped, g, tc.query)
			}

		})
	}
}

func BenchmarkPathEscape(b *testing.B) {
	for _, tc := range escapeBenchmarks {
		b.Run("", func(b *testing.B) {
			b.ReportAllocs()
			var g string
			for i := 0; i < b.N; i++ {
				g = PathEscape(tc.unescaped)
			}
			b.StopTimer()
			if g != tc.path {
				b.Errorf("PathEscape(%q) == %q, want %q", tc.unescaped, g, tc.path)
			}

		})
	}
}

func BenchmarkQueryUnescape(b *testing.B) {
	for _, tc := range escapeBenchmarks {
		b.Run("", func(b *testing.B) {
			b.ReportAllocs()
			var g string
			for i := 0; i < b.N; i++ {
				g, _ = QueryUnescape(tc.query)
			}
			b.StopTimer()
			if g != tc.unescaped {
				b.Errorf("QueryUnescape(%q) == %q, want %q", tc.query, g, tc.unescaped)
			}

		})
	}
}

func BenchmarkPathUnescape(b *testing.B) {
	for _, tc := range escapeBenchmarks {
		b.Run("", func(b *testing.B) {
			b.ReportAllocs()
			var g string
			for i := 0; i < b.N; i++ {
				g, _ = PathUnescape(tc.path)
			}
			b.StopTimer()
			if g != tc.unescaped {
				b.Errorf("PathUnescape(%q) == %q, want %q", tc.path, g, tc.unescaped)
			}

		})
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct {
		base string
		elem []string
		out  string
	}{
		{
			base: "https://go.googlesource.com",
			elem: []string{"go"},
			out:  "https://go.googlesource.com/go",
		},
		{
			base: "https://go.googlesource.com/a/b/c",
			elem: []string{"../../../go"},
			out:  "https://go.googlesource.com/go",
		},
		{
			base: "https://go.googlesource.com/",
			elem: []string{"../go"},
			out:  "https://go.googlesource.com/go",
		},
		{
			base: "https://go.googlesource.com",
			elem: []string{"../go"},
			out:  "https://go.googlesource.com/go",
		},
		{
			base: "https://go.googlesource.com",
			elem: []string{"../go", "../../go", "../../../go"},
			out:  "https://go.googlesource.com/go",
		},
		{
			base: "https://go.googlesource.com/../go",
			elem: nil,
			out:  "https://go.googlesource.com/go",
		},
		{
			base: "https://go.googlesource.com/",
			elem: []string{"./go"},
			out:  "https://go.googlesource.com/go",
		},
		{
			base: "https://go.googlesource.com//",
			elem: []string{"/go"},
			out:  "https://go.googlesource.com/go",
		},
		{
			base: "https://go.googlesource.com//",
			elem: []string{"/go", "a", "b", "c"},
			out:  "https://go.googlesource.com/go/a/b/c",
		},
		{
			base: "http://[fe80::1%en0]:8080/",
			elem: []string{"/go"},
		},
		{
			base: "https://go.googlesource.com",
			elem: []string{"go/"},
			out:  "https://go.googlesource.com/go/",
		},
		{
			base: "https://go.googlesource.com",
			elem: []string{"go//"},
			out:  "https://go.googlesource.com/go/",
		},
		{
			base: "https://go.googlesource.com",
			elem: nil,
			out:  "https://go.googlesource.com/",
		},
		{
			base: "https://go.googlesource.com/",
			elem: nil,
			out:  "https://go.googlesource.com/",
		},
		{
			base: "https://go.googlesource.com/a%2fb",
			elem: []string{"c"},
			out:  "https://go.googlesource.com/a%2fb/c",
		},
		{
			base: "https://go.googlesource.com/a%2fb",
			elem: []string{"c%2fd"},
			out:  "https://go.googlesource.com/a%2fb/c%2fd",
		},
		{
			base: "https://go.googlesource.com/a/b",
			elem: []string{"/go"},
			out:  "https://go.googlesource.com/a/b/go",
		},
		{
			base: "/",
			elem: nil,
			out:  "/",
		},
		{
			base: "a",
			elem: nil,
			out:  "a",
		},
		{
			base: "a",
			elem: []string{"b"},
			out:  "a/b",
		},
		{
			base: "a",
			elem: []string{"../b"},
			out:  "b",
		},
		{
			base: "a",
			elem: []string{"../../b"},
			out:  "b",
		},
		{
			base: "",
			elem: []string{"a"},
			out:  "a",
		},
		{
			base: "",
			elem: []string{"../a"},
			out:  "a",
		},
	}
	for _, tt := range tests {
		wantErr := "nil"
		if tt.out == "" {
			wantErr = "non-nil error"
		}
		if out, err := JoinPath(tt.base, tt.elem...); out != tt.out || (err == nil) != (tt.out != "") {
			t.Errorf("JoinPath(%q, %q) = %q, %v, want %q, %v", tt.base, tt.elem, out, err, tt.out, wantErr)
		}
		var out string
		u, err := Parse(tt.base)
		if err == nil {
			u = u.JoinPath(tt.elem...)
			out = u.String()
		}
		if out != tt.out || (err == nil) != (tt.out != "") {
			t.Errorf("Parse(%q).JoinPath(%q) = %q, %v, want %q, %v", tt.base, tt.elem, out, err, tt.out, wantErr)
		}
	}
}

"""




```