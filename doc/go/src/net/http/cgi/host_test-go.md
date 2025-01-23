Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Context:**

The first thing I do is read the comments at the top. They clearly state this is part of the `net/http/cgi` package and provides tests for it. The filename `host_test.go` strongly suggests tests related to how the CGI handler interacts with the host environment and HTTP requests.

**2. Identifying Key Functions and Structures:**

I then skim through the code, looking for function definitions (`func ...`) and type definitions (`type ...`). The following stand out:

* `TestMain`: This is a standard Go testing function. The logic inside checks for the `SERVER_SOFTWARE` environment variable. This immediately hints at a dual purpose: running as a test suite and potentially running *as the CGI itself*.
* `newRequest`:  A helper function for creating `http.Request` objects from string representations. This is common in testing HTTP-related code.
* `runCgiTest`: This function appears to be the core test runner. It takes a `Handler`, an HTTP request string, and expected results. This strongly suggests the code is testing the `Handler` type's behavior.
* `runResponseChecks`:  A helper for verifying the response from the CGI script, including headers and body. It reads the body line by line looking for `key=value` pairs.
* Several `Test...` functions (e.g., `TestCGIBasicGet`, `TestPathInfo`). These are individual test cases, each focusing on a specific aspect of the CGI handler.
* The `Handler` struct (though not explicitly defined in this snippet, its methods are called). The presence of fields like `Path` and `Root` is evident from how the `Handler` is initialized in the tests.

**3. Analyzing the `TestMain` Function:**

The `TestMain` function's conditional execution based on `SERVER_SOFTWARE` is crucial. It tells me:

* **Test Mode:** When `SERVER_SOFTWARE` is not set (the usual case for running `go test`), the standard test execution happens (`m.Run()`).
* **CGI Server Mode:** When `SERVER_SOFTWARE` *is* set, the program enters a different mode. It calls `cgiMain()` and then exits. This implies the test framework is designed to launch the test binary itself as a CGI server in certain test scenarios.

**4. Deconstructing `runCgiTest`:**

This function is central to understanding the testing strategy. It performs the following actions:

1. Creates an `httptest.ResponseRecorder` to capture the CGI's output.
2. Creates an `http.Request` using `newRequest`.
3. Calls `h.ServeHTTP(rw, req)`, which is the core of the CGI handling logic being tested.
4. Calls `runResponseChecks` to validate the response.

**5. Examining `runResponseChecks`:**

This function parses the CGI's output. The key observation is that it expects the CGI script to return key-value pairs in the response body, one per line, formatted as `key=value`. This is a convention used in these tests to communicate information back from the "CGI server" to the test framework. It also checks HTTP headers.

**6. Analyzing Individual `Test...` Functions:**

Each `Test...` function focuses on a specific aspect:

* `TestCGIBasicGet`: Tests a simple GET request, verifying environment variables and headers.
* `TestCGIEnvIPv6`: Tests handling of IPv6 addresses.
* `TestCGIBasicGetAbsPath`: Tests using an absolute path for the CGI script.
* `TestPathInfo`: Tests how `PATH_INFO` is handled.
* `TestDupHeaders`: Tests handling of duplicate headers.
* `TestDropProxyHeader`: Tests that the `Proxy` header is removed.
* `TestPathInfoNoRoot`: Tests the case where `Root` is empty.
* `TestCGIBasicPost`: Tests a simple POST request.
* `TestCGIPostChunked`: Tests that chunked requests are rejected.
* `TestRedirect`: Tests handling of `Location` headers for redirects.
* `TestInternalRedirect`: Tests a mechanism for internal redirects using a `PathLocationHandler`.
* `TestCopyError`: Tests the behavior when the client disconnects during a CGI execution.
* `TestDir`: Tests setting the working directory for the CGI script.
* `TestEnvOverride`: Tests overriding environment variables.
* `TestHandlerStderr`: Tests capturing the CGI's stderr output.
* `TestRemoveLeadingDuplicates`: A utility function test, likely used internally to process environment variables.

**7. Inferring CGI Implementation Details:**

Based on the tests, I can infer some key aspects of the `net/http/cgi` package:

* **Environment Variables:** It sets standard CGI environment variables like `GATEWAY_INTERFACE`, `REQUEST_METHOD`, `SCRIPT_NAME`, etc., based on the incoming HTTP request. It also converts HTTP headers to environment variables prefixed with `HTTP_`.
* **Output Format:** It expects the CGI script to output key-value pairs in the body.
* **Redirection:** It handles `Location` headers for redirection.
* **Error Handling:** It seems to handle client disconnections gracefully.
* **Configuration:** The `Handler` struct allows configuring the CGI script's path, root, working directory, and environment variables.

**8. Addressing the Prompt's Specific Questions:**

With the above understanding, I can now directly address the questions in the prompt:

* **Functionality:** Summarize the purpose of the tests.
* **Go Feature:** Identify the CGI implementation being tested.
* **Code Example:**  Pick a representative test case and explain it with inputs and expected outputs.
* **Command-line Arguments:**  Focus on the `SERVER_SOFTWARE` environment variable and its role.
* **Common Mistakes:** Think about potential misconfigurations (incorrect paths, wrong output format) and how they would manifest in the tests.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the individual test functions. Realizing that `runCgiTest` and `runResponseChecks` are the core mechanisms helps to build a better overall understanding.
* Noticing the `SERVER_SOFTWARE` check in `TestMain` is a key insight that clarifies the test setup.
* Understanding the expected output format of the CGI script is essential for interpreting the test results.

By following these steps, I can systematically analyze the Go code snippet and provide a comprehensive answer to the prompt.
这段Go语言代码是 `net/http/cgi` 包的一部分，专门用于测试 CGI (Common Gateway Interface) 功能的 `Handler` 结构体。它包含了一系列的测试用例，用于验证 CGI 处理程序在处理各种HTTP请求时的行为是否符合预期。

以下是代码的主要功能点：

1. **模拟CGI服务器环境**:  `TestMain` 函数会检查环境变量 `SERVER_SOFTWARE`。如果设置了该环境变量，程序会进入 CGI 服务器模式，调用 `cgiMain()` 并退出。这允许测试框架将当前的测试二进制文件作为 CGI 脚本来运行，从而模拟真实的 CGI 环境。

2. **创建和发送HTTP请求**:  `newRequest` 函数用于方便地创建 `http.Request` 对象，这在测试中模拟客户端发送请求非常有用。

3. **运行CGI测试并验证响应**: `runCgiTest` 函数是核心的测试运行器。它接受一个 `Handler` 实例，一个 HTTP 请求字符串，以及期望的响应数据映射。它会执行以下操作：
    * 创建一个 `httptest.ResponseRecorder` 来捕获 CGI 程序的输出。
    * 使用 `newRequest` 创建 `http.Request` 对象。
    * 调用 `Handler` 的 `ServeHTTP` 方法来处理请求。
    * 调用 `runResponseChecks` 来验证响应是否符合预期。

4. **验证CGI响应**: `runResponseChecks` 函数用于验证 CGI 程序的响应。它会将响应体解析成一个键值对的 map，然后与 `expectedMap` 进行比较。它还会执行一些额外的检查函数 (`checks ...func(reqInfo map[string]string)`)。CGI 脚本通常会输出一系列 `key=value` 格式的行，用于传递信息回 HTTP 服务器。

5. **测试各种HTTP请求场景**:  代码中包含多个以 `Test` 开头的函数，每个函数测试了 `Handler` 在不同 HTTP 请求场景下的行为，例如：
    * **`TestCGIBasicGet`**: 测试基本的 GET 请求，验证环境变量是否正确设置。
    * **`TestCGIEnvIPv6`**: 测试处理 IPv6 地址的情况。
    * **`TestCGIBasicGetAbsPath`**: 测试 CGI 脚本路径使用绝对路径的情况。
    * **`TestPathInfo`**: 测试 `PATH_INFO` 环境变量的设置。
    * **`TestDupHeaders`**: 测试重复 HTTP 头的处理。
    * **`TestDropProxyHeader`**: 验证是否会移除 `Proxy` 头。
    * **`TestPathInfoNoRoot`**: 测试当 `Root` 为空时的 `PATH_INFO` 处理。
    * **`TestCGIBasicPost`**: 测试基本的 POST 请求。
    * **`TestCGIPostChunked`**: 测试处理分块传输的 POST 请求 (预期会失败，因为 CGI 标准不支持)。
    * **`TestRedirect`**: 测试 CGI 脚本返回重定向头的情况。
    * **`TestInternalRedirect`**: 测试使用 `PathLocationHandler` 进行内部重定向的情况。
    * **`TestCopyError`**: 测试当客户端断开连接时，CGI 处理程序的行为。
    * **`TestDir`**: 测试设置 CGI 脚本的工作目录。
    * **`TestEnvOverride`**: 测试覆盖 CGI 脚本的环境变量。
    * **`TestHandlerStderr`**: 测试捕获 CGI 脚本的标准错误输出。

6. **测试辅助函数**: `TestRemoveLeadingDuplicates` 测试了一个用于移除重复环境变量的辅助函数。

**它可以推理出这是 `net/http/cgi` 包中 `Handler` 结构体的测试。** `Handler` 负责处理 HTTP 请求，并将其转发给 CGI 脚本执行，然后将 CGI 脚本的输出返回给客户端。

**Go 代码举例说明:**

以下是一个基于 `TestCGIBasicGet` 的简化例子，展示了 `Handler` 的基本用法：

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestMyCGIHandler(t *testing.T) {
	// 假设当前目录下有一个名为 "mycgi.sh" 的可执行 CGI 脚本
	// 该脚本会输出 "Content-Type: text/plain\n\nHello from CGI!"

	h := &cgi.Handler{
		Path: "./mycgi.sh", // CGI 脚本的路径
		Root: "/mycgi",    // CGI 脚本的虚拟根路径
	}

	req, err := http.NewRequest("GET", "/mycgi", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "Hello from CGI!"
	if strings.TrimSpace(rr.Body.String()) != expected {
		t.Errorf("handler returned unexpected body: got %q want %q",
			rr.Body.String(), expected)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "text/plain" {
		t.Errorf("handler returned unexpected Content-Type: got %q want %q",
			contentType, "text/plain")
	}
}

// 这是一个简单的 CGI 脚本 (mycgi.sh)，用于上面的测试
// #!/bin/bash
// echo "Content-Type: text/plain"
// echo ""
// echo "Hello from CGI!"
```

**假设的输入与输出:**

对于上面的 `TestMyCGIHandler` 例子：

* **输入 (模拟的 HTTP 请求):** `GET /mycgi HTTP/1.1`
* **CGI 脚本 (`mycgi.sh`) 的输出:**
  ```
  Content-Type: text/plain
  ```
  ```
  Hello from CGI!
  ```
* **预期的输出 (`httptest.ResponseRecorder` 的内容):**
    * **状态码:** 200 OK
    * **响应头:** `Content-Type: text/plain`
    * **响应体:** `Hello from CGI!`

**命令行参数的具体处理:**

在提供的代码片段中，并没有直接处理命令行参数。但是，`TestMain` 函数会检查环境变量 `SERVER_SOFTWARE`。

* **如果运行测试**:  通常使用 `go test ./net/http/cgi` 命令运行测试。在这种情况下，`SERVER_SOFTWARE` 环境变量通常不会被设置，`TestMain` 函数会调用 `m.Run()` 来执行测试用例。
* **如果模拟 CGI 服务器**:  为了让测试框架模拟 CGI 服务器，你需要设置 `SERVER_SOFTWARE` 环境变量。例如，在运行测试时可以这样设置：
  ```bash
  SERVER_SOFTWARE=go go test ./net/http/cgi
  ```
  当 `SERVER_SOFTWARE` 被设置后，`TestMain` 函数会调用 `cgiMain()`，这部分代码（未在提供的片段中）应该会启动一个简单的 HTTP 服务器，以便在测试中充当 CGI 服务器的角色。

**使用者易犯错的点:**

1. **CGI 脚本路径错误**: 在 `Handler` 的 `Path` 字段中指定了 CGI 脚本的路径。如果路径不正确，或者脚本不存在、没有执行权限，会导致服务器返回错误。

   ```go
   h := &cgi.Handler{
       Path: "/path/to/your/nonexistent_script.cgi", // 错误路径
       Root: "/cgi-bin",
   }
   ```

2. **CGI 脚本输出格式不正确**:  CGI 脚本需要按照特定的格式输出 HTTP 头部和内容。最常见的错误是忘记输出 `Content-Type` 头，或者头部和内容之间没有空行分隔。

   **错误示例 (CGI 脚本):**
   ```bash
   #!/bin/bash
   echo "Hello from CGI!" # 缺少 Content-Type 头
   ```

   **正确示例 (CGI 脚本):**
   ```bash
   #!/bin/bash
   echo "Content-Type: text/plain"
   echo ""
   echo "Hello from CGI!"
   ```

3. **CGI 脚本没有执行权限**: Web 服务器进程需要有执行 CGI 脚本的权限。如果权限不足，服务器会拒绝执行。

   ```bash
   chmod +x your_cgi_script.cgi  # 确保脚本有执行权限
   ```

4. **对 `Root` 的理解不正确**: `Root` 字段定义了 CGI 脚本的虚拟根路径。当请求的路径与 `Root` 匹配时，才会调用对应的 CGI 脚本。如果 `Root` 设置不当，可能导致请求无法匹配到正确的 CGI 脚本。

   例如，如果 `Root` 设置为 `/cgi-bin`，那么只有访问 `/cgi-bin/your_script.cgi` 这样的 URL 才会触发 `your_script.cgi` 的执行。访问 `/your_script.cgi` 将不会匹配。

理解这些测试用例有助于理解 `net/http/cgi` 包是如何工作的，以及如何正确地配置和使用 CGI 处理程序。

### 提示词
```
这是路径为go/src/net/http/cgi/host_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for package cgi

package cgi

import (
	"bufio"
	"fmt"
	"internal/testenv"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestMain executes the test binary as the cgi server if
// SERVER_SOFTWARE is set, and runs the tests otherwise.
func TestMain(m *testing.M) {
	// SERVER_SOFTWARE swap variable is set when starting the cgi server.
	if os.Getenv("SERVER_SOFTWARE") != "" {
		cgiMain()
		os.Exit(0)
	}

	os.Exit(m.Run())
}

func newRequest(httpreq string) *http.Request {
	buf := bufio.NewReader(strings.NewReader(httpreq))
	req, err := http.ReadRequest(buf)
	if err != nil {
		panic("cgi: bogus http request in test: " + httpreq)
	}
	req.RemoteAddr = "1.2.3.4:1234"
	return req
}

func runCgiTest(t *testing.T, h *Handler,
	httpreq string,
	expectedMap map[string]string, checks ...func(reqInfo map[string]string)) *httptest.ResponseRecorder {
	rw := httptest.NewRecorder()
	req := newRequest(httpreq)
	h.ServeHTTP(rw, req)
	runResponseChecks(t, rw, expectedMap, checks...)
	return rw
}

func runResponseChecks(t *testing.T, rw *httptest.ResponseRecorder,
	expectedMap map[string]string, checks ...func(reqInfo map[string]string)) {
	// Make a map to hold the test map that the CGI returns.
	m := make(map[string]string)
	m["_body"] = rw.Body.String()
	linesRead := 0
readlines:
	for {
		line, err := rw.Body.ReadString('\n')
		switch {
		case err == io.EOF:
			break readlines
		case err != nil:
			t.Fatalf("unexpected error reading from CGI: %v", err)
		}
		linesRead++
		trimmedLine := strings.TrimRight(line, "\r\n")
		k, v, ok := strings.Cut(trimmedLine, "=")
		if !ok {
			t.Fatalf("Unexpected response from invalid line number %v: %q; existing map=%v",
				linesRead, line, m)
		}
		m[k] = v
	}

	for key, expected := range expectedMap {
		got := m[key]
		if key == "cwd" {
			// For Windows. golang.org/issue/4645.
			fi1, _ := os.Stat(got)
			fi2, _ := os.Stat(expected)
			if os.SameFile(fi1, fi2) {
				got = expected
			}
		}
		if got != expected {
			t.Errorf("for key %q got %q; expected %q", key, got, expected)
		}
	}
	for _, check := range checks {
		check(m)
	}
}

func TestCGIBasicGet(t *testing.T) {
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
	}
	expectedMap := map[string]string{
		"test":                  "Hello CGI",
		"param-a":               "b",
		"param-foo":             "bar",
		"env-GATEWAY_INTERFACE": "CGI/1.1",
		"env-HTTP_HOST":         "example.com:80",
		"env-PATH_INFO":         "",
		"env-QUERY_STRING":      "foo=bar&a=b",
		"env-REMOTE_ADDR":       "1.2.3.4",
		"env-REMOTE_HOST":       "1.2.3.4",
		"env-REMOTE_PORT":       "1234",
		"env-REQUEST_METHOD":    "GET",
		"env-REQUEST_URI":       "/test.cgi?foo=bar&a=b",
		"env-SCRIPT_FILENAME":   os.Args[0],
		"env-SCRIPT_NAME":       "/test.cgi",
		"env-SERVER_NAME":       "example.com",
		"env-SERVER_PORT":       "80",
		"env-SERVER_SOFTWARE":   "go",
	}
	replay := runCgiTest(t, h, "GET /test.cgi?foo=bar&a=b HTTP/1.0\nHost: example.com:80\n\n", expectedMap)

	if expected, got := "text/html", replay.Header().Get("Content-Type"); got != expected {
		t.Errorf("got a Content-Type of %q; expected %q", got, expected)
	}
	if expected, got := "X-Test-Value", replay.Header().Get("X-Test-Header"); got != expected {
		t.Errorf("got a X-Test-Header of %q; expected %q", got, expected)
	}
}

func TestCGIEnvIPv6(t *testing.T) {
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
	}
	expectedMap := map[string]string{
		"test":                  "Hello CGI",
		"param-a":               "b",
		"param-foo":             "bar",
		"env-GATEWAY_INTERFACE": "CGI/1.1",
		"env-HTTP_HOST":         "example.com",
		"env-PATH_INFO":         "",
		"env-QUERY_STRING":      "foo=bar&a=b",
		"env-REMOTE_ADDR":       "2000::3000",
		"env-REMOTE_HOST":       "2000::3000",
		"env-REMOTE_PORT":       "12345",
		"env-REQUEST_METHOD":    "GET",
		"env-REQUEST_URI":       "/test.cgi?foo=bar&a=b",
		"env-SCRIPT_FILENAME":   os.Args[0],
		"env-SCRIPT_NAME":       "/test.cgi",
		"env-SERVER_NAME":       "example.com",
		"env-SERVER_PORT":       "80",
		"env-SERVER_SOFTWARE":   "go",
	}

	rw := httptest.NewRecorder()
	req := newRequest("GET /test.cgi?foo=bar&a=b HTTP/1.0\nHost: example.com\n\n")
	req.RemoteAddr = "[2000::3000]:12345"
	h.ServeHTTP(rw, req)
	runResponseChecks(t, rw, expectedMap)
}

func TestCGIBasicGetAbsPath(t *testing.T) {
	absPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: absPath,
		Root: "/test.cgi",
	}
	expectedMap := map[string]string{
		"env-REQUEST_URI":     "/test.cgi?foo=bar&a=b",
		"env-SCRIPT_FILENAME": absPath,
		"env-SCRIPT_NAME":     "/test.cgi",
	}
	runCgiTest(t, h, "GET /test.cgi?foo=bar&a=b HTTP/1.0\nHost: example.com\n\n", expectedMap)
}

func TestPathInfo(t *testing.T) {
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
	}
	expectedMap := map[string]string{
		"param-a":             "b",
		"env-PATH_INFO":       "/extrapath",
		"env-QUERY_STRING":    "a=b",
		"env-REQUEST_URI":     "/test.cgi/extrapath?a=b",
		"env-SCRIPT_FILENAME": os.Args[0],
		"env-SCRIPT_NAME":     "/test.cgi",
	}
	runCgiTest(t, h, "GET /test.cgi/extrapath?a=b HTTP/1.0\nHost: example.com\n\n", expectedMap)
}

func TestPathInfoDirRoot(t *testing.T) {
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: os.Args[0],
		Root: "/myscript//",
	}
	expectedMap := map[string]string{
		"env-PATH_INFO":       "/bar",
		"env-QUERY_STRING":    "a=b",
		"env-REQUEST_URI":     "/myscript/bar?a=b",
		"env-SCRIPT_FILENAME": os.Args[0],
		"env-SCRIPT_NAME":     "/myscript",
	}
	runCgiTest(t, h, "GET /myscript/bar?a=b HTTP/1.0\nHost: example.com\n\n", expectedMap)
}

func TestDupHeaders(t *testing.T) {
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: os.Args[0],
	}
	expectedMap := map[string]string{
		"env-REQUEST_URI":     "/myscript/bar?a=b",
		"env-SCRIPT_FILENAME": os.Args[0],
		"env-HTTP_COOKIE":     "nom=NOM; yum=YUM",
		"env-HTTP_X_FOO":      "val1, val2",
	}
	runCgiTest(t, h, "GET /myscript/bar?a=b HTTP/1.0\n"+
		"Cookie: nom=NOM\n"+
		"Cookie: yum=YUM\n"+
		"X-Foo: val1\n"+
		"X-Foo: val2\n"+
		"Host: example.com\n\n",
		expectedMap)
}

// Issue 16405: CGI+http.Transport differing uses of HTTP_PROXY.
// Verify we don't set the HTTP_PROXY environment variable.
// Hope nobody was depending on it. It's not a known header, though.
func TestDropProxyHeader(t *testing.T) {
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: os.Args[0],
	}
	expectedMap := map[string]string{
		"env-REQUEST_URI":     "/myscript/bar?a=b",
		"env-SCRIPT_FILENAME": os.Args[0],
		"env-HTTP_X_FOO":      "a",
	}
	runCgiTest(t, h, "GET /myscript/bar?a=b HTTP/1.0\n"+
		"X-Foo: a\n"+
		"Proxy: should_be_stripped\n"+
		"Host: example.com\n\n",
		expectedMap,
		func(reqInfo map[string]string) {
			if v, ok := reqInfo["env-HTTP_PROXY"]; ok {
				t.Errorf("HTTP_PROXY = %q; should be absent", v)
			}
		})
}

func TestPathInfoNoRoot(t *testing.T) {
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: os.Args[0],
		Root: "",
	}
	expectedMap := map[string]string{
		"env-PATH_INFO":       "/bar",
		"env-QUERY_STRING":    "a=b",
		"env-REQUEST_URI":     "/bar?a=b",
		"env-SCRIPT_FILENAME": os.Args[0],
		"env-SCRIPT_NAME":     "",
	}
	runCgiTest(t, h, "GET /bar?a=b HTTP/1.0\nHost: example.com\n\n", expectedMap)
}

func TestCGIBasicPost(t *testing.T) {
	testenv.MustHaveExec(t)
	postReq := `POST /test.cgi?a=b HTTP/1.0
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

postfoo=postbar`
	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
	}
	expectedMap := map[string]string{
		"test":               "Hello CGI",
		"param-postfoo":      "postbar",
		"env-REQUEST_METHOD": "POST",
		"env-CONTENT_LENGTH": "15",
		"env-REQUEST_URI":    "/test.cgi?a=b",
	}
	runCgiTest(t, h, postReq, expectedMap)
}

func chunk(s string) string {
	return fmt.Sprintf("%x\r\n%s\r\n", len(s), s)
}

// The CGI spec doesn't allow chunked requests.
func TestCGIPostChunked(t *testing.T) {
	testenv.MustHaveExec(t)
	postReq := `POST /test.cgi?a=b HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

` + chunk("postfoo") + chunk("=") + chunk("postbar") + chunk("")

	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
	}
	expectedMap := map[string]string{}
	resp := runCgiTest(t, h, postReq, expectedMap)
	if got, expected := resp.Code, http.StatusBadRequest; got != expected {
		t.Fatalf("Expected %v response code from chunked request body; got %d",
			expected, got)
	}
}

func TestRedirect(t *testing.T) {
	testenv.MustHaveExec(t)
	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
	}
	rec := runCgiTest(t, h, "GET /test.cgi?loc=http://foo.com/ HTTP/1.0\nHost: example.com\n\n", nil)
	if e, g := 302, rec.Code; e != g {
		t.Errorf("expected status code %d; got %d", e, g)
	}
	if e, g := "http://foo.com/", rec.Header().Get("Location"); e != g {
		t.Errorf("expected Location header of %q; got %q", e, g)
	}
}

func TestInternalRedirect(t *testing.T) {
	testenv.MustHaveExec(t)
	baseHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(rw, "basepath=%s\n", req.URL.Path)
		fmt.Fprintf(rw, "remoteaddr=%s\n", req.RemoteAddr)
	})
	h := &Handler{
		Path:                os.Args[0],
		Root:                "/test.cgi",
		PathLocationHandler: baseHandler,
	}
	expectedMap := map[string]string{
		"basepath":   "/foo",
		"remoteaddr": "1.2.3.4:1234",
	}
	runCgiTest(t, h, "GET /test.cgi?loc=/foo HTTP/1.0\nHost: example.com\n\n", expectedMap)
}

// TestCopyError tests that we kill the process if there's an error copying
// its output. (for example, from the client having gone away)
//
// If we fail to do so, the test will time out (and dump its goroutines) with a
// call to [Handler.ServeHTTP] blocked on a deferred call to [exec.Cmd.Wait].
func TestCopyError(t *testing.T) {
	testenv.MustHaveExec(t)

	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "http://example.com/test.cgi?bigresponse=1", nil)
	err = req.Write(conn)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer res.Body.Close()
	var buf [5000]byte
	n, err := io.ReadFull(res.Body, buf[:])
	if err != nil {
		t.Fatalf("ReadFull: %d bytes, %v", n, err)
	}

	if !handlerRunning() {
		t.Fatalf("pre-conn.Close, expected handler to still be running")
	}
	conn.Close()
	closed := time.Now()

	nextSleep := 1 * time.Millisecond
	for {
		time.Sleep(nextSleep)
		nextSleep *= 2
		if !handlerRunning() {
			break
		}
		t.Logf("handler still running %v after conn.Close", time.Since(closed))
	}
}

// handlerRunning reports whether any goroutine is currently running
// [Handler.ServeHTTP].
func handlerRunning() bool {
	r := regexp.MustCompile(`net/http/cgi\.\(\*Handler\)\.ServeHTTP`)
	buf := make([]byte, 64<<10)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return r.Match(buf[:n])
		}
		// Buffer wasn't large enough for a full goroutine dump.
		// Resize it and try again.
		buf = make([]byte, 2*len(buf))
	}
}

func TestDir(t *testing.T) {
	testenv.MustHaveExec(t)
	cwd, _ := os.Getwd()
	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
		Dir:  cwd,
	}
	expectedMap := map[string]string{
		"cwd": cwd,
	}
	runCgiTest(t, h, "GET /test.cgi HTTP/1.0\nHost: example.com\n\n", expectedMap)

	cwd, _ = os.Getwd()
	cwd, _ = filepath.Split(os.Args[0])
	h = &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
	}
	expectedMap = map[string]string{
		"cwd": cwd,
	}
	runCgiTest(t, h, "GET /test.cgi HTTP/1.0\nHost: example.com\n\n", expectedMap)
}

func TestEnvOverride(t *testing.T) {
	testenv.MustHaveExec(t)
	cgifile, _ := filepath.Abs("testdata/test.cgi")

	cwd, _ := os.Getwd()
	h := &Handler{
		Path: os.Args[0],
		Root: "/test.cgi",
		Dir:  cwd,
		Env: []string{
			"SCRIPT_FILENAME=" + cgifile,
			"REQUEST_URI=/foo/bar",
			"PATH=/wibble"},
	}
	expectedMap := map[string]string{
		"cwd":                 cwd,
		"env-SCRIPT_FILENAME": cgifile,
		"env-REQUEST_URI":     "/foo/bar",
		"env-PATH":            "/wibble",
	}
	runCgiTest(t, h, "GET /test.cgi HTTP/1.0\nHost: example.com\n\n", expectedMap)
}

func TestHandlerStderr(t *testing.T) {
	testenv.MustHaveExec(t)
	var stderr strings.Builder
	h := &Handler{
		Path:   os.Args[0],
		Root:   "/test.cgi",
		Stderr: &stderr,
	}

	rw := httptest.NewRecorder()
	req := newRequest("GET /test.cgi?writestderr=1 HTTP/1.0\nHost: example.com\n\n")
	h.ServeHTTP(rw, req)
	if got, want := stderr.String(), "Hello, stderr!\n"; got != want {
		t.Errorf("Stderr = %q; want %q", got, want)
	}
}

func TestRemoveLeadingDuplicates(t *testing.T) {
	tests := []struct {
		env  []string
		want []string
	}{
		{
			env:  []string{"a=b", "b=c", "a=b2"},
			want: []string{"b=c", "a=b2"},
		},
		{
			env:  []string{"a=b", "b=c", "d", "e=f"},
			want: []string{"a=b", "b=c", "d", "e=f"},
		},
	}
	for _, tt := range tests {
		got := removeLeadingDuplicates(tt.env)
		if !slices.Equal(got, tt.want) {
			t.Errorf("removeLeadingDuplicates(%q) = %q; want %q", tt.env, got, tt.want)
		}
	}
}
```