Response:
Let's break down the thought process to answer the request about `cookie_test.go`.

**1. Understanding the Core Task:**

The primary goal is to analyze the provided Go code snippet (`cookie_test.go`) and explain its functionality. The request specifically asks about:

* **Functionality Listing:**  What does this code do?
* **Go Feature Identification:** What Go language features is it testing or demonstrating?
* **Code Examples:** Illustrate the features with Go code, including input and output.
* **Command-Line Arguments:** Are there any command-line interactions?
* **Common Mistakes:** What pitfalls should users avoid?

**2. Initial Code Scan and Keyword Identification:**

I'll start by scanning the code for keywords and patterns that suggest its purpose:

* **`package http`:** This immediately tells us it's related to the `net/http` package, specifically concerning HTTP functionality.
* **`import "testing"`:** This confirms it's a testing file. The primary purpose is to test the behavior of HTTP cookies.
* **`var writeSetCookiesTests`, `var addCookieTests`, `var readSetCookiesTests`, `var readCookiesTests`:** These variable names strongly suggest that the code is testing different aspects of cookie handling: writing (setting) and reading cookies. The "Set-" prefix likely refers to the `Set-Cookie` header.
* **Functions like `TestWriteSetCookies`, `TestSetCookie`, `TestAddCookie`, `TestReadSetCookies`, `TestReadCookies`, `TestParseCookie`, `TestParseSetCookie`:** These are standard Go testing function names, further reinforcing the "testing" aspect.
* **Structs like `Cookie`:** This structure likely represents the internal representation of an HTTP cookie within the `net/http` package.
* **Methods like `String()` on the `Cookie` struct:** This suggests a way to serialize or represent a cookie as a string.
* **Functions like `SetCookie`, `AddCookie`, `readSetCookies`, `readCookies`, `ParseCookie`, `ParseSetCookie`:** These are the functions being tested. Their names clearly indicate their intended actions.
* **Benchmarks like `BenchmarkCookieString`, `BenchmarkReadSetCookies`, `BenchmarkReadCookies`:** These functions are for performance testing.

**3. Categorizing Functionality:**

Based on the initial scan, I can group the functionality being tested:

* **Writing/Setting Cookies:**  Testing how `Cookie` objects are converted into `Set-Cookie` header strings.
* **Adding Cookies to Requests:** Testing how `Cookie` objects are added to the `Cookie` header of an HTTP request.
* **Reading/Parsing `Set-Cookie` Headers:** Testing how `Set-Cookie` header strings are parsed into `Cookie` objects.
* **Reading/Parsing `Cookie` Headers:** Testing how `Cookie` header strings are parsed into individual `Cookie` objects.
* **Sanitizing Cookie Values and Paths:** Testing functions that clean up potentially invalid characters in cookie values and paths.
* **Validating Cookies:** Testing the `Valid()` method of the `Cookie` struct.
* **Parsing individual `Cookie` and `Set-Cookie` strings:** Testing functions that handle the parsing of single cookie strings.

**4. Identifying Go Features:**

The code demonstrates several key Go features:

* **Structs:**  The `Cookie` struct is a fundamental data structure.
* **Methods on Structs:**  The `String()` and `Valid()` methods are examples of attaching behavior to data.
* **Slices and Arrays:** Used extensively for test cases (`[]struct{}`).
* **Testing Framework:** The `testing` package is central.
* **String Manipulation:** Functions from the `strings` package are used for comparisons and checks.
* **Time Handling:** The `time` package is used for `Expires` attributes.
* **Error Handling:** The `errors` package is used for comparing expected and actual errors.
* **Reflection:** The `reflect` package is used for deep comparison of data structures (`reflect.DeepEqual`).
* **Logging:** The `log` package is used for debugging and reporting invalid cookie attributes.
* **Benchmarking:** The `testing` package provides benchmarking capabilities.

**5. Crafting Code Examples (with Input and Output):**

For each major functionality area, I'll create a concise Go code example. The key is to show how the relevant functions are used and what the expected output is for a given input.

* **Writing Cookies:**  Demonstrate creating a `Cookie` and using its `String()` method.
* **Setting Cookies in Headers:** Show how `SetCookie` adds `Set-Cookie` headers.
* **Adding Cookies to Requests:** Show how `AddCookie` populates the `Cookie` header.
* **Reading `Set-Cookie` Headers:**  Show how `readSetCookies` parses headers.
* **Reading `Cookie` Headers:** Show how `readCookies` parses headers.
* **Parsing individual cookies:**  Illustrate `ParseCookie` and `ParseSetCookie`.

For each example, I'll invent simple, representative input and the corresponding expected output.

**6. Command-Line Arguments:**

By inspecting the code, I see no direct usage of `os.Args` or the `flag` package. Therefore, there are no specific command-line arguments handled by this *test* file. However, it's important to mention that the tests themselves can be run with standard `go test` commands, and those might have flags.

**7. Identifying Common Mistakes:**

This requires thinking about how developers might misuse the cookie handling functions or misunderstand cookie specifications. Examples include:

* Incorrectly formatting `Set-Cookie` headers manually.
* Not understanding the implications of different cookie attributes (e.g., `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`).
* Trying to set invalid characters in cookie names or values.
* Misinterpreting the `Max-Age` and `Expires` attributes.

**8. Structuring the Answer:**

Finally, I'll organize the information logically, following the structure requested:

* Start with a clear statement of the file's purpose.
* List the functionalities.
* Elaborate on the identified Go features with code examples.
* Address command-line arguments (or the lack thereof).
* Highlight common mistakes.
* Use clear and concise language, in Chinese as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the benchmarks are testing specific optimization techniques. **Correction:** While true, the core purpose is still performance measurement of the cookie handling functions. Focus on the *what* not just the *how*.
* **Initial thought:** Detail *every* test case. **Correction:**  Focus on illustrating the *types* of tests being done, not exhaustively listing each test. The provided examples in the code are sufficient for understanding.
* **Initial thought:** Overly technical explanations. **Correction:** Keep the explanations accessible to a wider audience, even those with a basic understanding of HTTP cookies and Go.

By following this thought process, combining code analysis with domain knowledge about HTTP cookies and Go testing, I can generate a comprehensive and accurate answer to the user's request.
这个`go/src/net/http/cookie_test.go` 文件是 Go 语言 `net/http` 标准库中关于 HTTP Cookie 功能的测试文件。它的主要功能是验证 `net/http` 包中处理 HTTP Cookie 的相关代码是否按照预期工作。

以下是该文件列举的功能以及相关的 Go 语言特性实现和代码示例：

**1. 测试 `Cookie` 结构体的 `String()` 方法:**

   该方法负责将 `Cookie` 结构体转换为符合 HTTP 规范的 `Set-Cookie` 头部字符串。

   **Go 语言特性:** 结构体方法，字符串格式化。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
       "time"
   )

   func main() {
       cookie := &http.Cookie{
           Name:    "my_cookie",
           Value:   "hello_world",
           Path:    "/",
           Domain:  "example.com",
           Expires: time.Now().Add(time.Hour),
           Secure:  true,
           HttpOnly: true,
           SameSite: http.SameSiteStrictMode,
       }
       cookieString := cookie.String()
       fmt.Println(cookieString)
   }
   ```

   **假设的输出:** (输出的时间戳会根据运行时间变化)

   ```
   my_cookie=hello_world; Path=/; Domain=example.com; Expires=Mon, 29 Apr 2024 10:00:00 GMT; Secure; HttpOnly; SameSite=Strict
   ```

   这个测试用 `writeSetCookiesTests` 变量定义了一系列不同的 `Cookie` 对象和它们期望的 `String()` 方法输出，然后通过循环调用 `Cookie.String()` 并与期望值进行比较来验证其正确性。

**2. 测试 `SetCookie` 函数:**

   该函数用于将一个 `Cookie` 对象添加到 HTTP 响应头的 `Set-Cookie` 字段中。

   **Go 语言特性:** 函数，HTTP 头部操作。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
       "net/http/httptest"
   )

   func main() {
       rr := httptest.NewRecorder()
       cookie := &http.Cookie{
           Name:  "session_id",
           Value: "12345",
           Path:  "/app",
       }
       http.SetCookie(rr, cookie)

       headers := rr.Header()
       fmt.Println(headers.Get("Set-Cookie"))
   }
   ```

   **假设的输出:**

   ```
   session_id=12345; Path=/app
   ```

   `TestSetCookie` 函数创建了一个假的 `ResponseWriter`，调用 `SetCookie` 添加 cookie，然后检查 `ResponseWriter` 的头部信息中是否包含了正确的 `Set-Cookie` 字段。

**3. 测试 `AddCookie` 方法:**

   该方法用于将一个 `Cookie` 对象添加到 HTTP 请求头的 `Cookie` 字段中。

   **Go 语言特性:** 结构体方法，HTTP 头部操作。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func main() {
       req, _ := http.NewRequest("GET", "http://example.com", nil)
       cookie := &http.Cookie{
           Name:  "user_id",
           Value: "abc",
       }
       req.AddCookie(cookie)
       fmt.Println(req.Header.Get("Cookie"))
   }
   ```

   **假设的输出:**

   ```
   user_id=abc
   ```

   `TestAddCookie` 函数创建了一个 `Request` 对象，然后使用 `AddCookie` 方法添加 cookie，最后验证 `Request` 的头部信息中 `Cookie` 字段是否正确。

**4. 测试 `readSetCookies` 函数:**

   该函数用于解析 HTTP 响应头中的 `Set-Cookie` 字段，将其转换为 `Cookie` 对象的切片。

   **Go 语言特性:** 函数，字符串解析，HTTP 头部操作。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func main() {
       header := http.Header{
           "Set-Cookie": []string{
               "cookie1=value1; Path=/",
               "cookie2=value2; Domain=example.com",
           },
       }
       cookies := http.ReadSetCookies(header)
       for _, cookie := range cookies {
           fmt.Printf("Name: %s, Value: %s, Path: %s, Domain: %s\n", cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
       }
   }
   ```

   **假设的输出:**

   ```
   Name: cookie1, Value: value1, Path: /, Domain:
   Name: cookie2, Value: value2, Path: , Domain: example.com
   ```

   `TestReadSetCookies` 函数定义了一组包含 `Set-Cookie` 字段的 HTTP 头部，然后调用 `readSetCookies` 函数进行解析，并将解析结果与预期的 `Cookie` 对象进行比较。

**5. 测试 `readCookies` 函数:**

   该函数用于解析 HTTP 请求头中的 `Cookie` 字段，将其转换为 `Cookie` 对象的切片。

   **Go 语言特性:** 函数，字符串解析，HTTP 头部操作。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func main() {
       header := http.Header{
           "Cookie": []string{"cookieA=valA; cookieB=valB"},
       }
       cookies := http.ReadCookies(header)
       for _, cookie := range cookies {
           fmt.Printf("Name: %s, Value: %s\n", cookie.Name, cookie.Value)
       }
   }
   ```

   **假设的输出:**

   ```
   Name: cookieA, Value: valA
   Name: cookieB, Value: valB
   ```

   `TestReadCookies` 函数定义了一组包含 `Cookie` 字段的 HTTP 头部，然后调用 `readCookies` 函数进行解析，并将解析结果与预期的 `Cookie` 对象进行比较。 它还测试了使用 `Filter` 参数来只读取特定名称的 Cookie。

**6. 测试 `ParseCookie` 函数:**

   该函数用于解析一个 `Cookie` 头部字符串 (例如，`name=value`) 为 `Cookie` 对象。

   **Go 语言特性:** 函数，字符串解析。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func main() {
       cookieStr := "my_cookie=test_value"
       cookie, err := http.ParseCookie(cookieStr)
       if err != nil {
           fmt.Println("Error parsing cookie:", err)
           return
       }
       fmt.Printf("Name: %s, Value: %s\n", cookie.Name, cookie.Value)
   }
   ```

   **假设的输出:**

   ```
   Name: my_cookie, Value: test_value
   ```

   `TestParseCookie` 函数测试了各种格式的 `Cookie` 字符串，包括错误的情况，并验证解析结果和错误是否符合预期。

**7. 测试 `ParseSetCookie` 函数:**

   该函数用于解析一个 `Set-Cookie` 头部字符串为 `Cookie` 对象。

   **Go 语言特性:** 函数，字符串解析。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func main() {
       setCookieStr := "session_id=abcdefg; Path=/; HttpOnly"
       cookie, err := http.ParseSetCookie(setCookieStr)
       if err != nil {
           fmt.Println("Error parsing Set-Cookie:", err)
           return
       }
       fmt.Printf("Name: %s, Value: %s, Path: %s, HttpOnly: %t\n", cookie.Name, cookie.Value, cookie.Path, cookie.HttpOnly)
   }
   ```

   **假设的输出:**

   ```
   Name: session_id, Value: abcdefg, Path: /, HttpOnly: true
   ```

   `TestParseSetCookie` 函数测试了各种格式的 `Set-Cookie` 字符串，包括各种属性（如 `Expires`, `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite` 等），并验证解析结果和错误是否符合预期。

**8. 测试 Cookie 值的转义和清理:**

   该文件还包含测试用例来验证 `sanitizeCookieValue` 和 `sanitizeCookiePath` 函数，这些函数负责清理 Cookie 值和路径中不允许出现的字符。

   **Go 语言特性:** 函数，字符串处理，日志记录。

   **代码示例:**  （这些函数通常在内部使用，直接使用场景较少，但可以通过构造特定的 Cookie 对象来观察其行为）

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func main() {
       cookie := &http.Cookie{Name: "bad-value", Value: "value;with;semicolons"}
       fmt.Println(cookie.String()) // 观察输出中 Value 是否被引号包裹
   }
   ```

   **假设的输出:**

   ```
   bad-value="value;with;semicolons"
   ```

   测试用例会检查当 Cookie 值包含空格、逗号等特殊字符时，`String()` 方法是否会正确地使用引号将值包围起来。

**9. 测试 Cookie 属性的有效性 (`Valid()` 方法):**

   `TestCookieValid` 函数测试了 `Cookie` 结构体的 `Valid()` 方法，该方法用于检查 Cookie 的各个属性是否符合规范。

   **Go 语言特性:** 结构体方法，错误处理。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net/http"
       "time"
   )

   func main() {
       validCookie := &http.Cookie{Name: "ok", Value: "good"}
       invalidCookie := &http.Cookie{Name: "bad", Expires: time.Date(1500, 1, 1, 0, 0, 0, 0, time.UTC)}

       errValid := validCookie.Valid()
       errInvalid := invalidCookie.Valid()

       fmt.Println("Valid Cookie Error:", errValid)
       fmt.Println("Invalid Cookie Error:", errInvalid)
   }
   ```

   **假设的输出:**

   ```
   Valid Cookie Error: <nil>
   Invalid Cookie Error: expires: year is not between 1601 and 9999
   ```

**命令行参数处理:**

该测试文件本身并不直接处理命令行参数。Go 语言的测试是通过 `go test` 命令来运行的。`go test` 命令本身有一些标准参数，例如 `-v` (显示详细输出), `-run` (运行特定的测试用例) 等。  你可以使用这些参数来控制测试的运行方式，但这些参数不是由 `cookie_test.go` 文件本身定义的。

例如，要运行 `cookie_test.go` 中的所有测试，可以在该文件所在的目录下执行：

```bash
go test
```

要运行特定的测试用例，可以使用 `-run` 参数，例如运行名为 `TestWriteSetCookies` 的测试：

```bash
go test -run TestWriteSetCookies
```

**使用者易犯错的点:**

在处理 HTTP Cookie 时，使用者容易犯以下错误：

* **手动构造 `Set-Cookie` 头部字符串时格式不正确:**  例如，忘记使用分号分隔属性，或者日期格式不符合 RFC 规范。`net/http` 提供的 `Cookie` 结构体和 `SetCookie` 函数可以避免这个问题。

* **不理解 Cookie 的作用域 (Domain 和 Path):**  导致 Cookie 没有在预期的请求中发送。

* **忽略 `Secure` 和 `HttpOnly` 标志:**  可能导致安全漏洞。`Secure` 标志确保 Cookie 只在 HTTPS 连接中发送，`HttpOnly` 标志防止客户端脚本访问 Cookie。

* **错误地处理 `Expires` 和 `Max-Age` 属性:**  导致 Cookie 的过期时间不正确。

* **不理解 `SameSite` 属性的影响:**  可能导致跨站请求伪造 (CSRF) 漏洞或影响某些跨域场景下的 Cookie 传递。

**总结:**

`go/src/net/http/cookie_test.go` 文件通过大量的测试用例，全面地验证了 Go 语言 `net/http` 包中处理 HTTP Cookie 的各种功能，包括 Cookie 对象的创建、序列化、反序列化，以及在 HTTP 请求和响应中设置和读取 Cookie 的操作。它确保了 `net/http` 包提供的 Cookie 功能的正确性和健壮性。

### 提示词
```
这是路径为go/src/net/http/cookie_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var writeSetCookiesTests = []struct {
	Cookie *Cookie
	Raw    string
}{
	{
		&Cookie{Name: "cookie-1", Value: "v$1"},
		"cookie-1=v$1",
	},
	{
		&Cookie{Name: "cookie-2", Value: "two", MaxAge: 3600},
		"cookie-2=two; Max-Age=3600",
	},
	{
		&Cookie{Name: "cookie-3", Value: "three", Domain: ".example.com"},
		"cookie-3=three; Domain=example.com",
	},
	{
		&Cookie{Name: "cookie-4", Value: "four", Path: "/restricted/"},
		"cookie-4=four; Path=/restricted/",
	},
	{
		&Cookie{Name: "cookie-5", Value: "five", Domain: "wrong;bad.abc"},
		"cookie-5=five",
	},
	{
		&Cookie{Name: "cookie-6", Value: "six", Domain: "bad-.abc"},
		"cookie-6=six",
	},
	{
		&Cookie{Name: "cookie-7", Value: "seven", Domain: "127.0.0.1"},
		"cookie-7=seven; Domain=127.0.0.1",
	},
	{
		&Cookie{Name: "cookie-8", Value: "eight", Domain: "::1"},
		"cookie-8=eight",
	},
	{
		&Cookie{Name: "cookie-9", Value: "expiring", Expires: time.Unix(1257894000, 0)},
		"cookie-9=expiring; Expires=Tue, 10 Nov 2009 23:00:00 GMT",
	},
	// According to IETF 6265 Section 5.1.1.5, the year cannot be less than 1601
	{
		&Cookie{Name: "cookie-10", Value: "expiring-1601", Expires: time.Date(1601, 1, 1, 1, 1, 1, 1, time.UTC)},
		"cookie-10=expiring-1601; Expires=Mon, 01 Jan 1601 01:01:01 GMT",
	},
	{
		&Cookie{Name: "cookie-11", Value: "invalid-expiry", Expires: time.Date(1600, 1, 1, 1, 1, 1, 1, time.UTC)},
		"cookie-11=invalid-expiry",
	},
	{
		&Cookie{Name: "cookie-12", Value: "samesite-default", SameSite: SameSiteDefaultMode},
		"cookie-12=samesite-default",
	},
	{
		&Cookie{Name: "cookie-13", Value: "samesite-lax", SameSite: SameSiteLaxMode},
		"cookie-13=samesite-lax; SameSite=Lax",
	},
	{
		&Cookie{Name: "cookie-14", Value: "samesite-strict", SameSite: SameSiteStrictMode},
		"cookie-14=samesite-strict; SameSite=Strict",
	},
	{
		&Cookie{Name: "cookie-15", Value: "samesite-none", SameSite: SameSiteNoneMode},
		"cookie-15=samesite-none; SameSite=None",
	},
	{
		&Cookie{Name: "cookie-16", Value: "partitioned", SameSite: SameSiteNoneMode, Secure: true, Path: "/", Partitioned: true},
		"cookie-16=partitioned; Path=/; Secure; SameSite=None; Partitioned",
	},
	// The "special" cookies have values containing commas or spaces which
	// are disallowed by RFC 6265 but are common in the wild.
	{
		&Cookie{Name: "special-1", Value: "a z"},
		`special-1="a z"`,
	},
	{
		&Cookie{Name: "special-2", Value: " z"},
		`special-2=" z"`,
	},
	{
		&Cookie{Name: "special-3", Value: "a "},
		`special-3="a "`,
	},
	{
		&Cookie{Name: "special-4", Value: " "},
		`special-4=" "`,
	},
	{
		&Cookie{Name: "special-5", Value: "a,z"},
		`special-5="a,z"`,
	},
	{
		&Cookie{Name: "special-6", Value: ",z"},
		`special-6=",z"`,
	},
	{
		&Cookie{Name: "special-7", Value: "a,"},
		`special-7="a,"`,
	},
	{
		&Cookie{Name: "special-8", Value: ","},
		`special-8=","`,
	},
	{
		&Cookie{Name: "empty-value", Value: ""},
		`empty-value=`,
	},
	{
		nil,
		``,
	},
	{
		&Cookie{Name: ""},
		``,
	},
	{
		&Cookie{Name: "\t"},
		``,
	},
	{
		&Cookie{Name: "\r"},
		``,
	},
	{
		&Cookie{Name: "a\nb", Value: "v"},
		``,
	},
	{
		&Cookie{Name: "a\nb", Value: "v"},
		``,
	},
	{
		&Cookie{Name: "a\rb", Value: "v"},
		``,
	},
	// Quoted values (issue #46443)
	{
		&Cookie{Name: "cookie", Value: "quoted", Quoted: true},
		`cookie="quoted"`,
	},
	{
		&Cookie{Name: "cookie", Value: "quoted with spaces", Quoted: true},
		`cookie="quoted with spaces"`,
	},
	{
		&Cookie{Name: "cookie", Value: "quoted,with,commas", Quoted: true},
		`cookie="quoted,with,commas"`,
	},
}

func TestWriteSetCookies(t *testing.T) {
	defer log.SetOutput(os.Stderr)
	var logbuf strings.Builder
	log.SetOutput(&logbuf)

	for i, tt := range writeSetCookiesTests {
		if g, e := tt.Cookie.String(), tt.Raw; g != e {
			t.Errorf("Test %d, expecting:\n%s\nGot:\n%s\n", i, e, g)
		}
	}

	if got, sub := logbuf.String(), "dropping domain attribute"; !strings.Contains(got, sub) {
		t.Errorf("Expected substring %q in log output. Got:\n%s", sub, got)
	}
}

type headerOnlyResponseWriter Header

func (ho headerOnlyResponseWriter) Header() Header {
	return Header(ho)
}

func (ho headerOnlyResponseWriter) Write([]byte) (int, error) {
	panic("NOIMPL")
}

func (ho headerOnlyResponseWriter) WriteHeader(int) {
	panic("NOIMPL")
}

func TestSetCookie(t *testing.T) {
	m := make(Header)
	SetCookie(headerOnlyResponseWriter(m), &Cookie{Name: "cookie-1", Value: "one", Path: "/restricted/"})
	SetCookie(headerOnlyResponseWriter(m), &Cookie{Name: "cookie-2", Value: "two", MaxAge: 3600})
	if l := len(m["Set-Cookie"]); l != 2 {
		t.Fatalf("expected %d cookies, got %d", 2, l)
	}
	if g, e := m["Set-Cookie"][0], "cookie-1=one; Path=/restricted/"; g != e {
		t.Errorf("cookie #1: want %q, got %q", e, g)
	}
	if g, e := m["Set-Cookie"][1], "cookie-2=two; Max-Age=3600"; g != e {
		t.Errorf("cookie #2: want %q, got %q", e, g)
	}
}

var addCookieTests = []struct {
	Cookies []*Cookie
	Raw     string
}{
	{
		[]*Cookie{},
		"",
	},
	{
		[]*Cookie{{Name: "cookie-1", Value: "v$1"}},
		"cookie-1=v$1",
	},
	{
		[]*Cookie{
			{Name: "cookie-1", Value: "v$1"},
			{Name: "cookie-2", Value: "v$2"},
			{Name: "cookie-3", Value: "v$3"},
		},
		"cookie-1=v$1; cookie-2=v$2; cookie-3=v$3",
	},
	// Quoted values (issue #46443)
	{
		[]*Cookie{
			{Name: "cookie-1", Value: "quoted", Quoted: true},
			{Name: "cookie-2", Value: "quoted with spaces", Quoted: true},
			{Name: "cookie-3", Value: "quoted,with,commas", Quoted: true},
		},
		`cookie-1="quoted"; cookie-2="quoted with spaces"; cookie-3="quoted,with,commas"`,
	},
}

func TestAddCookie(t *testing.T) {
	for i, tt := range addCookieTests {
		req, _ := NewRequest("GET", "http://example.com/", nil)
		for _, c := range tt.Cookies {
			req.AddCookie(c)
		}
		if g := req.Header.Get("Cookie"); g != tt.Raw {
			t.Errorf("Test %d:\nwant: %s\n got: %s\n", i, tt.Raw, g)
		}
	}
}

var readSetCookiesTests = []struct {
	Header  Header
	Cookies []*Cookie
}{
	{
		Header{"Set-Cookie": {"Cookie-1=v$1"}},
		[]*Cookie{{Name: "Cookie-1", Value: "v$1", Raw: "Cookie-1=v$1"}},
	},
	{
		Header{"Set-Cookie": {"NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly"}},
		[]*Cookie{{
			Name:       "NID",
			Value:      "99=YsDT5i3E-CXax-",
			Path:       "/",
			Domain:     ".google.ch",
			HttpOnly:   true,
			Expires:    time.Date(2011, 11, 23, 1, 5, 3, 0, time.UTC),
			RawExpires: "Wed, 23-Nov-2011 01:05:03 GMT",
			Raw:        "NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly",
		}},
	},
	{
		Header{"Set-Cookie": {".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly"}},
		[]*Cookie{{
			Name:       ".ASPXAUTH",
			Value:      "7E3AA",
			Path:       "/",
			Expires:    time.Date(2012, 3, 7, 14, 25, 6, 0, time.UTC),
			RawExpires: "Wed, 07-Mar-2012 14:25:06 GMT",
			HttpOnly:   true,
			Raw:        ".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly",
		}},
	},
	{
		Header{"Set-Cookie": {"ASP.NET_SessionId=foo; path=/; HttpOnly"}},
		[]*Cookie{{
			Name:     "ASP.NET_SessionId",
			Value:    "foo",
			Path:     "/",
			HttpOnly: true,
			Raw:      "ASP.NET_SessionId=foo; path=/; HttpOnly",
		}},
	},
	{
		Header{"Set-Cookie": {"samesitedefault=foo; SameSite"}},
		[]*Cookie{{
			Name:     "samesitedefault",
			Value:    "foo",
			SameSite: SameSiteDefaultMode,
			Raw:      "samesitedefault=foo; SameSite",
		}},
	},
	{
		Header{"Set-Cookie": {"samesiteinvalidisdefault=foo; SameSite=invalid"}},
		[]*Cookie{{
			Name:     "samesiteinvalidisdefault",
			Value:    "foo",
			SameSite: SameSiteDefaultMode,
			Raw:      "samesiteinvalidisdefault=foo; SameSite=invalid",
		}},
	},
	{
		Header{"Set-Cookie": {"samesitelax=foo; SameSite=Lax"}},
		[]*Cookie{{
			Name:     "samesitelax",
			Value:    "foo",
			SameSite: SameSiteLaxMode,
			Raw:      "samesitelax=foo; SameSite=Lax",
		}},
	},
	{
		Header{"Set-Cookie": {"samesitestrict=foo; SameSite=Strict"}},
		[]*Cookie{{
			Name:     "samesitestrict",
			Value:    "foo",
			SameSite: SameSiteStrictMode,
			Raw:      "samesitestrict=foo; SameSite=Strict",
		}},
	},
	{
		Header{"Set-Cookie": {"samesitenone=foo; SameSite=None"}},
		[]*Cookie{{
			Name:     "samesitenone",
			Value:    "foo",
			SameSite: SameSiteNoneMode,
			Raw:      "samesitenone=foo; SameSite=None",
		}},
	},
	// Make sure we can properly read back the Set-Cookie headers we create
	// for values containing spaces or commas:
	{
		Header{"Set-Cookie": {`special-1=a z`}},
		[]*Cookie{{Name: "special-1", Value: "a z", Raw: `special-1=a z`}},
	},
	{
		Header{"Set-Cookie": {`special-2=" z"`}},
		[]*Cookie{{Name: "special-2", Value: " z", Quoted: true, Raw: `special-2=" z"`}},
	},
	{
		Header{"Set-Cookie": {`special-3="a "`}},
		[]*Cookie{{Name: "special-3", Value: "a ", Quoted: true, Raw: `special-3="a "`}},
	},
	{
		Header{"Set-Cookie": {`special-4=" "`}},
		[]*Cookie{{Name: "special-4", Value: " ", Quoted: true, Raw: `special-4=" "`}},
	},
	{
		Header{"Set-Cookie": {`special-5=a,z`}},
		[]*Cookie{{Name: "special-5", Value: "a,z", Raw: `special-5=a,z`}},
	},
	{
		Header{"Set-Cookie": {`special-6=",z"`}},
		[]*Cookie{{Name: "special-6", Value: ",z", Quoted: true, Raw: `special-6=",z"`}},
	},
	{
		Header{"Set-Cookie": {`special-7=a,`}},
		[]*Cookie{{Name: "special-7", Value: "a,", Raw: `special-7=a,`}},
	},
	{
		Header{"Set-Cookie": {`special-8=","`}},
		[]*Cookie{{Name: "special-8", Value: ",", Quoted: true, Raw: `special-8=","`}},
	},
	// Make sure we can properly read back the Set-Cookie headers
	// for names containing spaces:
	{
		Header{"Set-Cookie": {`special-9 =","`}},
		[]*Cookie{{Name: "special-9", Value: ",", Quoted: true, Raw: `special-9 =","`}},
	},
	// Quoted values (issue #46443)
	{
		Header{"Set-Cookie": {`cookie="quoted"`}},
		[]*Cookie{{Name: "cookie", Value: "quoted", Quoted: true, Raw: `cookie="quoted"`}},
	},

	// TODO(bradfitz): users have reported seeing this in the
	// wild, but do browsers handle it? RFC 6265 just says "don't
	// do that" (section 3) and then never mentions header folding
	// again.
	// Header{"Set-Cookie": {"ASP.NET_SessionId=foo; path=/; HttpOnly, .ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly"}},
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

func TestReadSetCookies(t *testing.T) {
	for i, tt := range readSetCookiesTests {
		for n := 0; n < 2; n++ { // to verify readSetCookies doesn't mutate its input
			c := readSetCookies(tt.Header)
			if !reflect.DeepEqual(c, tt.Cookies) {
				t.Errorf("#%d readSetCookies: have\n%s\nwant\n%s\n", i, toJSON(c), toJSON(tt.Cookies))
			}
		}
	}
}

var readCookiesTests = []struct {
	Header  Header
	Filter  string
	Cookies []*Cookie
}{
	{
		Header{"Cookie": {"Cookie-1=v$1", "c2=v2"}},
		"",
		[]*Cookie{
			{Name: "Cookie-1", Value: "v$1"},
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {"Cookie-1=v$1", "c2=v2"}},
		"c2",
		[]*Cookie{
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {"Cookie-1=v$1; c2=v2"}},
		"",
		[]*Cookie{
			{Name: "Cookie-1", Value: "v$1"},
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {"Cookie-1=v$1; c2=v2"}},
		"c2",
		[]*Cookie{
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {`Cookie-1="v$1"; c2="v2"`}},
		"",
		[]*Cookie{
			{Name: "Cookie-1", Value: "v$1", Quoted: true},
			{Name: "c2", Value: "v2", Quoted: true},
		},
	},
	{
		Header{"Cookie": {`Cookie-1="v$1"; c2=v2;`}},
		"",
		[]*Cookie{
			{Name: "Cookie-1", Value: "v$1", Quoted: true},
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {``}},
		"",
		[]*Cookie{},
	},
}

func TestReadCookies(t *testing.T) {
	for i, tt := range readCookiesTests {
		for n := 0; n < 2; n++ { // to verify readCookies doesn't mutate its input
			c := readCookies(tt.Header, tt.Filter)
			if !reflect.DeepEqual(c, tt.Cookies) {
				t.Errorf("#%d readCookies:\nhave: %s\nwant: %s\n", i, toJSON(c), toJSON(tt.Cookies))
			}
		}
	}
}

func TestSetCookieDoubleQuotes(t *testing.T) {
	res := &Response{Header: Header{}}
	res.Header.Add("Set-Cookie", `quoted0=none; max-age=30`)
	res.Header.Add("Set-Cookie", `quoted1="cookieValue"; max-age=31`)
	res.Header.Add("Set-Cookie", `quoted2=cookieAV; max-age="32"`)
	res.Header.Add("Set-Cookie", `quoted3="both"; max-age="33"`)
	got := res.Cookies()
	want := []*Cookie{
		{Name: "quoted0", Value: "none", MaxAge: 30},
		{Name: "quoted1", Value: "cookieValue", MaxAge: 31},
		{Name: "quoted2", Value: "cookieAV"},
		{Name: "quoted3", Value: "both"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d cookies, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.Name || g.Value != w.Value || g.MaxAge != w.MaxAge {
			t.Errorf("cookie #%d:\ngot  %v\nwant %v", i, g, w)
		}
	}
}

func TestCookieSanitizeValue(t *testing.T) {
	defer log.SetOutput(os.Stderr)
	var logbuf strings.Builder
	log.SetOutput(&logbuf)

	tests := []struct {
		in     string
		quoted bool
		want   string
	}{
		{"foo", false, "foo"},
		{"foo;bar", false, "foobar"},
		{"foo\\bar", false, "foobar"},
		{"foo\"bar", false, "foobar"},
		{"\x00\x7e\x7f\x80", false, "\x7e"},
		{`withquotes`, true, `"withquotes"`},
		{`"withquotes"`, true, `"withquotes"`}, // double quotes are not valid octets
		{"a z", false, `"a z"`},
		{" z", false, `" z"`},
		{"a ", false, `"a "`},
		{"a,z", false, `"a,z"`},
		{",z", false, `",z"`},
		{"a,", false, `"a,"`},
	}
	for _, tt := range tests {
		if got := sanitizeCookieValue(tt.in, tt.quoted); got != tt.want {
			t.Errorf("sanitizeCookieValue(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}

	if got, sub := logbuf.String(), "dropping invalid bytes"; !strings.Contains(got, sub) {
		t.Errorf("Expected substring %q in log output. Got:\n%s", sub, got)
	}
}

func TestCookieSanitizePath(t *testing.T) {
	defer log.SetOutput(os.Stderr)
	var logbuf strings.Builder
	log.SetOutput(&logbuf)

	tests := []struct {
		in, want string
	}{
		{"/path", "/path"},
		{"/path with space/", "/path with space/"},
		{"/just;no;semicolon\x00orstuff/", "/justnosemicolonorstuff/"},
	}
	for _, tt := range tests {
		if got := sanitizeCookiePath(tt.in); got != tt.want {
			t.Errorf("sanitizeCookiePath(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}

	if got, sub := logbuf.String(), "dropping invalid bytes"; !strings.Contains(got, sub) {
		t.Errorf("Expected substring %q in log output. Got:\n%s", sub, got)
	}
}

func TestCookieValid(t *testing.T) {
	tests := []struct {
		cookie *Cookie
		valid  bool
	}{
		{nil, false},
		{&Cookie{Name: ""}, false},
		{&Cookie{Name: "invalid-value", Value: "foo\"bar"}, false},
		{&Cookie{Name: "invalid-path", Path: "/foo;bar/"}, false},
		{&Cookie{Name: "invalid-secure-for-partitioned", Value: "foo", Path: "/", Secure: false, Partitioned: true}, false},
		{&Cookie{Name: "invalid-domain", Domain: "example.com:80"}, false},
		{&Cookie{Name: "invalid-expiry", Value: "", Expires: time.Date(1600, 1, 1, 1, 1, 1, 1, time.UTC)}, false},
		{&Cookie{Name: "valid-empty"}, true},
		{&Cookie{Name: "valid-expires", Value: "foo", Path: "/bar", Domain: "example.com", Expires: time.Unix(0, 0)}, true},
		{&Cookie{Name: "valid-max-age", Value: "foo", Path: "/bar", Domain: "example.com", MaxAge: 60}, true},
		{&Cookie{Name: "valid-all-fields", Value: "foo", Path: "/bar", Domain: "example.com", Expires: time.Unix(0, 0), MaxAge: 0}, true},
		{&Cookie{Name: "valid-partitioned", Value: "foo", Path: "/", Secure: true, Partitioned: true}, true},
	}

	for _, tt := range tests {
		err := tt.cookie.Valid()
		if err != nil && tt.valid {
			t.Errorf("%#v.Valid() returned error %v; want nil", tt.cookie, err)
		}
		if err == nil && !tt.valid {
			t.Errorf("%#v.Valid() returned nil; want error", tt.cookie)
		}
	}
}

func BenchmarkCookieString(b *testing.B) {
	const wantCookieString = `cookie-9=i3e01nf61b6t23bvfmplnanol3; Path=/restricted/; Domain=example.com; Expires=Tue, 10 Nov 2009 23:00:00 GMT; Max-Age=3600`
	c := &Cookie{
		Name:    "cookie-9",
		Value:   "i3e01nf61b6t23bvfmplnanol3",
		Expires: time.Unix(1257894000, 0),
		Path:    "/restricted/",
		Domain:  ".example.com",
		MaxAge:  3600,
	}
	var benchmarkCookieString string
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkCookieString = c.String()
	}
	if have, want := benchmarkCookieString, wantCookieString; have != want {
		b.Fatalf("Have: %v Want: %v", have, want)
	}
}

func BenchmarkReadSetCookies(b *testing.B) {
	header := Header{
		"Set-Cookie": {
			"NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly",
			".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly",
		},
	}
	wantCookies := []*Cookie{
		{
			Name:       "NID",
			Value:      "99=YsDT5i3E-CXax-",
			Path:       "/",
			Domain:     ".google.ch",
			HttpOnly:   true,
			Expires:    time.Date(2011, 11, 23, 1, 5, 3, 0, time.UTC),
			RawExpires: "Wed, 23-Nov-2011 01:05:03 GMT",
			Raw:        "NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly",
		},
		{
			Name:       ".ASPXAUTH",
			Value:      "7E3AA",
			Path:       "/",
			Expires:    time.Date(2012, 3, 7, 14, 25, 6, 0, time.UTC),
			RawExpires: "Wed, 07-Mar-2012 14:25:06 GMT",
			HttpOnly:   true,
			Raw:        ".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly",
		},
	}
	var c []*Cookie
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c = readSetCookies(header)
	}
	if !reflect.DeepEqual(c, wantCookies) {
		b.Fatalf("readSetCookies:\nhave: %s\nwant: %s\n", toJSON(c), toJSON(wantCookies))
	}
}

func BenchmarkReadCookies(b *testing.B) {
	header := Header{
		"Cookie": {
			`de=; client_region=0; rpld1=0:hispeed.ch|20:che|21:zh|22:zurich|23:47.36|24:8.53|; rpld0=1:08|; backplane-channel=newspaper.com:1471; devicetype=0; osfam=0; rplmct=2; s_pers=%20s_vmonthnum%3D1472680800496%2526vn%253D1%7C1472680800496%3B%20s_nr%3D1471686767664-New%7C1474278767664%3B%20s_lv%3D1471686767669%7C1566294767669%3B%20s_lv_s%3DFirst%2520Visit%7C1471688567669%3B%20s_monthinvisit%3Dtrue%7C1471688567677%3B%20gvp_p5%3Dsports%253Ablog%253Aearly-lead%2520-%2520184693%2520-%252020160820%2520-%2520u-s%7C1471688567681%3B%20gvp_p51%3Dwp%2520-%2520sports%7C1471688567684%3B; s_sess=%20s_wp_ep%3Dhomepage%3B%20s._ref%3Dhttps%253A%252F%252Fwww.google.ch%252F%3B%20s_cc%3Dtrue%3B%20s_ppvl%3Dsports%25253Ablog%25253Aearly-lead%252520-%252520184693%252520-%25252020160820%252520-%252520u-lawyer%252C12%252C12%252C502%252C1231%252C502%252C1680%252C1050%252C2%252CP%3B%20s_ppv%3Dsports%25253Ablog%25253Aearly-lead%252520-%252520184693%252520-%25252020160820%252520-%252520u-s-lawyer%252C12%252C12%252C502%252C1231%252C502%252C1680%252C1050%252C2%252CP%3B%20s_dslv%3DFirst%2520Visit%3B%20s_sq%3Dwpninewspapercom%253D%252526pid%25253Dsports%2525253Ablog%2525253Aearly-lead%25252520-%25252520184693%25252520-%2525252020160820%25252520-%25252520u-s%252526pidt%25253D1%252526oid%25253Dhttps%2525253A%2525252F%2525252Fwww.newspaper.com%2525252F%2525253Fnid%2525253Dmenu_nav_homepage%252526ot%25253DA%3B`,
		},
	}
	wantCookies := []*Cookie{
		{Name: "de", Value: ""},
		{Name: "client_region", Value: "0"},
		{Name: "rpld1", Value: "0:hispeed.ch|20:che|21:zh|22:zurich|23:47.36|24:8.53|"},
		{Name: "rpld0", Value: "1:08|"},
		{Name: "backplane-channel", Value: "newspaper.com:1471"},
		{Name: "devicetype", Value: "0"},
		{Name: "osfam", Value: "0"},
		{Name: "rplmct", Value: "2"},
		{Name: "s_pers", Value: "%20s_vmonthnum%3D1472680800496%2526vn%253D1%7C1472680800496%3B%20s_nr%3D1471686767664-New%7C1474278767664%3B%20s_lv%3D1471686767669%7C1566294767669%3B%20s_lv_s%3DFirst%2520Visit%7C1471688567669%3B%20s_monthinvisit%3Dtrue%7C1471688567677%3B%20gvp_p5%3Dsports%253Ablog%253Aearly-lead%2520-%2520184693%2520-%252020160820%2520-%2520u-s%7C1471688567681%3B%20gvp_p51%3Dwp%2520-%2520sports%7C1471688567684%3B"},
		{Name: "s_sess", Value: "%20s_wp_ep%3Dhomepage%3B%20s._ref%3Dhttps%253A%252F%252Fwww.google.ch%252F%3B%20s_cc%3Dtrue%3B%20s_ppvl%3Dsports%25253Ablog%25253Aearly-lead%252520-%252520184693%252520-%25252020160820%252520-%252520u-lawyer%252C12%252C12%252C502%252C1231%252C502%252C1680%252C1050%252C2%252CP%3B%20s_ppv%3Dsports%25253Ablog%25253Aearly-lead%252520-%252520184693%252520-%25252020160820%252520-%252520u-s-lawyer%252C12%252C12%252C502%252C1231%252C502%252C1680%252C1050%252C2%252CP%3B%20s_dslv%3DFirst%2520Visit%3B%20s_sq%3Dwpninewspapercom%253D%252526pid%25253Dsports%2525253Ablog%2525253Aearly-lead%25252520-%25252520184693%25252520-%2525252020160820%25252520-%25252520u-s%252526pidt%25253D1%252526oid%25253Dhttps%2525253A%2525252F%2525252Fwww.newspaper.com%2525252F%2525253Fnid%2525253Dmenu_nav_homepage%252526ot%25253DA%3B"},
	}
	var c []*Cookie
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c = readCookies(header, "")
	}
	if !reflect.DeepEqual(c, wantCookies) {
		b.Fatalf("readCookies:\nhave: %s\nwant: %s\n", toJSON(c), toJSON(wantCookies))
	}
}

func TestParseCookie(t *testing.T) {
	tests := []struct {
		line    string
		cookies []*Cookie
		err     error
	}{
		{
			line:    "Cookie-1=v$1",
			cookies: []*Cookie{{Name: "Cookie-1", Value: "v$1"}},
		},
		{
			line:    "Cookie-1=v$1;c2=v2",
			cookies: []*Cookie{{Name: "Cookie-1", Value: "v$1"}, {Name: "c2", Value: "v2"}},
		},
		{
			line:    `Cookie-1="v$1";c2="v2"`,
			cookies: []*Cookie{{Name: "Cookie-1", Value: "v$1", Quoted: true}, {Name: "c2", Value: "v2", Quoted: true}},
		},
		{
			line:    "k1=",
			cookies: []*Cookie{{Name: "k1", Value: ""}},
		},
		{
			line: "",
			err:  errBlankCookie,
		},
		{
			line: "equal-not-found",
			err:  errEqualNotFoundInCookie,
		},
		{
			line: "=v1",
			err:  errInvalidCookieName,
		},
		{
			line: "k1=\\",
			err:  errInvalidCookieValue,
		},
	}
	for i, tt := range tests {
		gotCookies, gotErr := ParseCookie(tt.line)
		if !errors.Is(gotErr, tt.err) {
			t.Errorf("#%d ParseCookie got error %v, want error %v", i, gotErr, tt.err)
		}
		if !reflect.DeepEqual(gotCookies, tt.cookies) {
			t.Errorf("#%d ParseCookie:\ngot cookies: %s\nwant cookies: %s\n", i, toJSON(gotCookies), toJSON(tt.cookies))
		}
	}
}

func TestParseSetCookie(t *testing.T) {
	tests := []struct {
		line   string
		cookie *Cookie
		err    error
	}{
		{
			line:   "Cookie-1=v$1",
			cookie: &Cookie{Name: "Cookie-1", Value: "v$1", Raw: "Cookie-1=v$1"},
		},
		{
			line: "NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly",
			cookie: &Cookie{
				Name:       "NID",
				Value:      "99=YsDT5i3E-CXax-",
				Path:       "/",
				Domain:     ".google.ch",
				HttpOnly:   true,
				Expires:    time.Date(2011, 11, 23, 1, 5, 3, 0, time.UTC),
				RawExpires: "Wed, 23-Nov-2011 01:05:03 GMT",
				Raw:        "NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly",
			},
		},
		{
			line: ".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly",
			cookie: &Cookie{
				Name:       ".ASPXAUTH",
				Value:      "7E3AA",
				Path:       "/",
				Expires:    time.Date(2012, 3, 7, 14, 25, 6, 0, time.UTC),
				RawExpires: "Wed, 07-Mar-2012 14:25:06 GMT",
				HttpOnly:   true,
				Raw:        ".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly",
			},
		},
		{
			line: "ASP.NET_SessionId=foo; path=/; HttpOnly",
			cookie: &Cookie{
				Name:     "ASP.NET_SessionId",
				Value:    "foo",
				Path:     "/",
				HttpOnly: true,
				Raw:      "ASP.NET_SessionId=foo; path=/; HttpOnly",
			},
		},
		{
			line: "samesitedefault=foo; SameSite",
			cookie: &Cookie{
				Name:     "samesitedefault",
				Value:    "foo",
				SameSite: SameSiteDefaultMode,
				Raw:      "samesitedefault=foo; SameSite",
			},
		},
		{
			line: "samesiteinvalidisdefault=foo; SameSite=invalid",
			cookie: &Cookie{
				Name:     "samesiteinvalidisdefault",
				Value:    "foo",
				SameSite: SameSiteDefaultMode,
				Raw:      "samesiteinvalidisdefault=foo; SameSite=invalid",
			},
		},
		{
			line: "samesitelax=foo; SameSite=Lax",
			cookie: &Cookie{
				Name:     "samesitelax",
				Value:    "foo",
				SameSite: SameSiteLaxMode,
				Raw:      "samesitelax=foo; SameSite=Lax",
			},
		},
		{
			line: "samesitestrict=foo; SameSite=Strict",
			cookie: &Cookie{
				Name:     "samesitestrict",
				Value:    "foo",
				SameSite: SameSiteStrictMode,
				Raw:      "samesitestrict=foo; SameSite=Strict",
			},
		},
		{
			line: "samesitenone=foo; SameSite=None",
			cookie: &Cookie{
				Name:     "samesitenone",
				Value:    "foo",
				SameSite: SameSiteNoneMode,
				Raw:      "samesitenone=foo; SameSite=None",
			},
		},
		// Make sure we can properly read back the Set-Cookie headers we create
		// for values containing spaces or commas:
		{
			line:   `special-1=a z`,
			cookie: &Cookie{Name: "special-1", Value: "a z", Raw: `special-1=a z`},
		},
		{
			line:   `special-2=" z"`,
			cookie: &Cookie{Name: "special-2", Value: " z", Quoted: true, Raw: `special-2=" z"`},
		},
		{
			line:   `special-3="a "`,
			cookie: &Cookie{Name: "special-3", Value: "a ", Quoted: true, Raw: `special-3="a "`},
		},
		{
			line:   `special-4=" "`,
			cookie: &Cookie{Name: "special-4", Value: " ", Quoted: true, Raw: `special-4=" "`},
		},
		{
			line:   `special-5=a,z`,
			cookie: &Cookie{Name: "special-5", Value: "a,z", Raw: `special-5=a,z`},
		},
		{
			line:   `special-6=",z"`,
			cookie: &Cookie{Name: "special-6", Value: ",z", Quoted: true, Raw: `special-6=",z"`},
		},
		{
			line:   `special-7=a,`,
			cookie: &Cookie{Name: "special-7", Value: "a,", Raw: `special-7=a,`},
		},
		{
			line:   `special-8=","`,
			cookie: &Cookie{Name: "special-8", Value: ",", Quoted: true, Raw: `special-8=","`},
		},
		// Make sure we can properly read back the Set-Cookie headers
		// for names containing spaces:
		{
			line:   `special-9 =","`,
			cookie: &Cookie{Name: "special-9", Value: ",", Quoted: true, Raw: `special-9 =","`},
		},
		{
			line: "",
			err:  errBlankCookie,
		},
		{
			line: "equal-not-found",
			err:  errEqualNotFoundInCookie,
		},
		{
			line: "=v1",
			err:  errInvalidCookieName,
		},
		{
			line: "k1=\\",
			err:  errInvalidCookieValue,
		},
	}
	for i, tt := range tests {
		gotCookie, gotErr := ParseSetCookie(tt.line)
		if !errors.Is(gotErr, tt.err) {
			t.Errorf("#%d ParseSetCookie got error %v, want error %v", i, gotErr, tt.err)
			continue
		}
		if !reflect.DeepEqual(gotCookie, tt.cookie) {
			t.Errorf("#%d ParseSetCookie:\ngot cookie: %s\nwant cookie: %s\n", i, toJSON(gotCookie), toJSON(tt.cookie))
		}
	}
}
```