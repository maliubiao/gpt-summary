Response:
The user wants me to analyze a Go source code file `request_test.go` and describe its functionality.

Here's a breakdown of the code and its functionalities:

1. **Core Functionality:** The file contains unit tests for the `net/http` package, specifically focusing on the `Request` type.

2. **Key Areas of Testing:**
    *   Parsing query parameters from URLs.
    *   Parsing form data from request bodies (URL-encoded and multipart).
    *   Handling different HTTP methods.
    *   Error handling during parsing.
    *   Working with multipart form data (including file uploads).
    *   Request redirection.
    *   Setting basic authentication headers.
    *   Reading and writing HTTP requests.
    *   Handling invalid HTTP formats.
    *   Cloning requests.
    *   Working with `Request.GetBody`.
    *   Using `MaxBytesReader` to limit the size of request bodies.

3. **Specific Test Functions:** Each `Test...` function focuses on a specific aspect of the `Request` type's behavior.

4. **Helper Functions:**  Functions like `newTestMultipartRequest` and `validateTestMultipartContents` are used to set up test scenarios and verify expected outcomes.
这段代码是Go语言标准库 `net/http` 包中 `request_test.go` 文件的一部分，它主要的功能是**对 `net/http.Request` 类型的各种功能进行单元测试**。

具体来说，这段代码测试了 `http.Request` 类型的以下功能：

1. **解析 URL 中的查询参数:**
    *   测试 `Request.FormValue()` 方法获取指定查询参数的值。
    *   测试 `Request.Form` 字段获取所有查询参数。

    ```go
    func TestQuery(t *testing.T) {
        req := &Request{Method: "GET"}
        req.URL, _ = url.Parse("http://www.google.com/search?q=foo&q=bar")
        if q := req.FormValue("q"); q != "foo" {
            t.Errorf(`req.FormValue("q") = %q, want "foo"`, q)
        }
    }
    ```
    **假设输入:**  创建了一个 `Request` 对象，其 URL 被设置为 `"http://www.google.com/search?q=foo&q=bar"`。
    **预期输出:** `req.FormValue("q")` 应该返回 `"foo"`，因为对于相同的键，`FormValue` 返回第一个值。

2. **解析请求体中的表单数据 (URL 编码):**
    *   测试 `Request.ParseForm()` 方法解析请求体中的表单数据。
    *   测试 `Request.PostFormValue()` 方法获取 POST 请求体中指定参数的值。
    *   测试 `Request.PostForm` 字段获取 POST 请求体中的所有参数。
    *   测试不同 HTTP 方法（POST, PUT, PATCH）下 `ParseForm` 的行为。
    *   测试当 URL 中包含分号作为分隔符时 `ParseForm` 的行为。

    ```go
    func TestParseFormQuery(t *testing.T) {
        req, _ := NewRequest("POST", "http://www.google.com/search?q=foo&q=bar&both=x&prio=1&orphan=nope&empty=not",
            strings.NewReader("z=post&both=y&prio=2&=nokey&orphan&empty="))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

        if q := req.FormValue("q"); q != "foo" {
            t.Errorf(`req.FormValue("q") = %q, want "foo"`, q)
        }
        // ... 更多的断言
    }
    ```
    **假设输入:** 创建了一个 `POST` 请求，URL 中带有查询参数，请求体中也包含 URL 编码的表单数据。
    **预期输出:**  各种 `FormValue` 和 `Form` 调用应该返回从 URL 和请求体中解析出的正确的值。例如，`req.FormValue("prio")` 应该返回 `"2"`，因为它在请求体中被指定，并且请求体的参数优先级高于 URL 中的参数。

3. **处理未知的 Content-Type:**
    *   测试 `ParseForm` 在处理不同 `Content-Type` 时的行为，包括 `text/plain`，空 `Content-Type`，以及包含错误 boundary 的 `Content-Type`。

4. **在错误情况下初始化 Form 和 PostForm:**
    *   测试即使在 `ParseForm` 发生错误时，`Request.Form` 和 `Request.PostForm` 也会被初始化为空的 `url.Values`。

5. **处理 multipart/form-data:**
    *   测试 `Request.MultipartReader()` 方法，用于读取 multipart 请求体。
    *   测试 `Request.ParseMultipartForm()` 方法解析 multipart 表单数据，包括文本字段和文件上传。
    *   测试 `Request.FormFile()` 方法获取上传的文件。
    *   测试 `ParseMultipartForm` 是否会同时填充 `PostForm` 字段。
    *   测试当 `ParseMultipartForm` 的 `maxMemory` 参数过大导致溢出时的错误处理。
    *   测试 `ParseMultipartForm` 如何处理文件名中的目录路径。

    ```go
    func TestParseMultipartFormPopulatesPostForm(t *testing.T) {
        postData := `--xxx\nContent-Disposition: form-data; name="field1"\n\nvalue1\n--xxx\nContent-Disposition: form-data; name="field2"\n\nvalue2\n--xxx\nContent-Disposition: form-data; name="file"; filename="file"\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: binary\n\nbinary data\n--xxx--\n`
        req := &Request{
            Method: "POST",
            Header: Header{"Content-Type": {`multipart/form-data; boundary=xxx`}},
            Body:   io.NopCloser(strings.NewReader(postData)),
        }
        // ...
        err := req.ParseMultipartForm(10000)
        // ...
    }
    ```
    **假设输入:** 创建一个 `POST` 请求，其 `Content-Type` 为 `multipart/form-data`，请求体包含 multipart 数据。
    **预期输出:** `req.ParseMultipartForm()` 应该成功解析表单数据，`req.Form` 和 `req.PostForm` 应该包含解析出的字段值，并且可以使用 `req.FormFile()` 获取上传的文件。

6. **请求重定向:**
    *   测试 `Client.Get()` 方法在处理重定向时的行为。

7. **设置 Basic 认证:**
    *   测试 `Request.SetBasicAuth()` 方法设置 `Authorization` 请求头。

    ```go
    func TestSetBasicAuth(t *testing.T) {
        r, _ := NewRequest("GET", "http://example.com/", nil)
        r.SetBasicAuth("Aladdin", "open sesame")
        if g, e := r.Header.Get("Authorization"), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="; g != e {
            t.Errorf("got header %q, want %q", g, e)
        }
    }
    ```
    **假设输入:** 创建一个 `Request` 对象，并调用 `SetBasicAuth` 方法设置用户名和密码。
    **预期输出:** `Request` 对象的 `Authorization` 请求头应该被设置为正确的 Basic 认证字符串。

8. **自动调用 `ParseMultipartForm`:**
    *   测试在调用 `Request.FormValue()` 和 `Request.FormFile()` 时，如果尚未解析 multipart 表单，会自动调用 `ParseMultipartForm`。

9. **`MultipartReader` 和 `ParseMultipartForm` 的调用顺序:**
    *   测试在同一个请求上，`MultipartReader` 和 `ParseMultipartForm` 不能被先后调用，否则会返回错误。

10. **读取请求错误:**
    *   测试 `ReadRequest()` 函数在解析不完整的或格式错误的 HTTP 请求时的错误处理。
    *   测试 `ReadRequest()` 函数处理多个 `Content-Length` 头部和多个 `Host` 头部的情况。

11. **`NewRequest` 的 Host 头部设置:**
    *   测试 `NewRequest()` 函数是否正确设置 `Request.Host` 字段。

12. **无效的请求方法:**
    *   测试使用无效的 HTTP 方法创建请求时的错误处理。

13. **`NewRequest` 的 `ContentLength` 设置:**
    *   测试 `NewRequest()` 函数是否能根据请求体正确设置 `Request.ContentLength` 字段。

14. **解析 HTTP 版本:**
    *   测试 `ParseHTTPVersion()` 函数解析 HTTP 版本字符串。

15. **获取 Basic 认证信息:**
    *   测试 `Request.BasicAuth()` 方法获取请求中的 Basic 认证用户名和密码。

16. **解析 Basic 认证头部:**
    *   测试 `BasicAuth()` 方法解析 `Authorization` 头部。

17. **写入请求:**
    *   测试 `Request.Write()` 方法将请求写入 `io.Writer` 的功能。
    *   测试当 `Host` 头部或 `User-Agent` 头部包含非法字符时的处理。

18. **处理带有 "*" 的请求:**
    *   测试解析和写入带有 "*" 的请求（例如 M-SEARCH）。

19. **`MaxBytesReader` 的功能:**
    *   测试 `MaxBytesReader` 函数限制读取数据量的功能，以及错误处理。

20. **使用 Context 创建请求:**
    *   测试 `Request.WithContext()` 方法创建一个带有新 Context 的请求副本。

21. **克隆请求:**
    *   测试 `Request.Clone()` 方法创建请求的深拷贝，包括 `TransferEncoding` 和 `PathValue` 字段。

22. **在带有 Basic 认证的请求中避免 panic:**
    *   测试在使用带有用户名和密码的 URL 进行请求时，不会发生 panic。

23. **`NewRequest` 设置 `GetBody`:**
    *   测试 `NewRequest()` 函数是否正确设置了 `Request.GetBody` 字段，并验证其功能。

**总结一下这段代码的功能：**

这段代码是 `net/http` 包中关于 `Request` 类型的功能测试集合。它通过各种测试用例，覆盖了 `Request` 对象在处理 URL 查询参数、请求体数据（URL 编码和 multipart）、HTTP 头部、Basic 认证、请求写入等方面的各种场景和边界情况，确保 `http.Request` 的行为符合预期，并且能够正确处理各种合法的和非法的输入。 这部分代码主要集中在对 HTTP 请求的解析和基本属性的处理上。

Prompt: 
```
这是路径为go/src/net/http/request_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package http_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	. "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestQuery(t *testing.T) {
	req := &Request{Method: "GET"}
	req.URL, _ = url.Parse("http://www.google.com/search?q=foo&q=bar")
	if q := req.FormValue("q"); q != "foo" {
		t.Errorf(`req.FormValue("q") = %q, want "foo"`, q)
	}
}

// Issue #25192: Test that ParseForm fails but still parses the form when a URL
// containing a semicolon is provided.
func TestParseFormSemicolonSeparator(t *testing.T) {
	for _, method := range []string{"POST", "PATCH", "PUT", "GET"} {
		req, _ := NewRequest(method, "http://www.google.com/search?q=foo;q=bar&a=1",
			strings.NewReader("q"))
		err := req.ParseForm()
		if err == nil {
			t.Fatalf(`for method %s, ParseForm expected an error, got success`, method)
		}
		wantForm := url.Values{"a": []string{"1"}}
		if !reflect.DeepEqual(req.Form, wantForm) {
			t.Fatalf("for method %s, ParseForm expected req.Form = %v, want %v", method, req.Form, wantForm)
		}
	}
}

func TestParseFormQuery(t *testing.T) {
	req, _ := NewRequest("POST", "http://www.google.com/search?q=foo&q=bar&both=x&prio=1&orphan=nope&empty=not",
		strings.NewReader("z=post&both=y&prio=2&=nokey&orphan&empty=&"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	if q := req.FormValue("q"); q != "foo" {
		t.Errorf(`req.FormValue("q") = %q, want "foo"`, q)
	}
	if z := req.FormValue("z"); z != "post" {
		t.Errorf(`req.FormValue("z") = %q, want "post"`, z)
	}
	if bq, found := req.PostForm["q"]; found {
		t.Errorf(`req.PostForm["q"] = %q, want no entry in map`, bq)
	}
	if bz := req.PostFormValue("z"); bz != "post" {
		t.Errorf(`req.PostFormValue("z") = %q, want "post"`, bz)
	}
	if qs := req.Form["q"]; !slices.Equal(qs, []string{"foo", "bar"}) {
		t.Errorf(`req.Form["q"] = %q, want ["foo", "bar"]`, qs)
	}
	if both := req.Form["both"]; !slices.Equal(both, []string{"y", "x"}) {
		t.Errorf(`req.Form["both"] = %q, want ["y", "x"]`, both)
	}
	if prio := req.FormValue("prio"); prio != "2" {
		t.Errorf(`req.FormValue("prio") = %q, want "2" (from body)`, prio)
	}
	if orphan := req.Form["orphan"]; !slices.Equal(orphan, []string{"", "nope"}) {
		t.Errorf(`req.FormValue("orphan") = %q, want "" (from body)`, orphan)
	}
	if empty := req.Form["empty"]; !slices.Equal(empty, []string{"", "not"}) {
		t.Errorf(`req.FormValue("empty") = %q, want "" (from body)`, empty)
	}
	if nokey := req.Form[""]; !slices.Equal(nokey, []string{"nokey"}) {
		t.Errorf(`req.FormValue("nokey") = %q, want "nokey" (from body)`, nokey)
	}
}

// Tests that we only parse the form automatically for certain methods.
func TestParseFormQueryMethods(t *testing.T) {
	for _, method := range []string{"POST", "PATCH", "PUT", "FOO"} {
		req, _ := NewRequest(method, "http://www.google.com/search",
			strings.NewReader("foo=bar"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		want := "bar"
		if method == "FOO" {
			want = ""
		}
		if got := req.FormValue("foo"); got != want {
			t.Errorf(`for method %s, FormValue("foo") = %q; want %q`, method, got, want)
		}
	}
}

func TestParseFormUnknownContentType(t *testing.T) {
	for _, test := range []struct {
		name        string
		wantErr     string
		contentType Header
	}{
		{"text", "", Header{"Content-Type": {"text/plain"}}},
		// Empty content type is legal - may be treated as
		// application/octet-stream (RFC 7231, section 3.1.1.5)
		{"empty", "", Header{}},
		{"boundary", "mime: invalid media parameter", Header{"Content-Type": {"text/plain; boundary="}}},
		{"unknown", "", Header{"Content-Type": {"application/unknown"}}},
	} {
		t.Run(test.name,
			func(t *testing.T) {
				req := &Request{
					Method: "POST",
					Header: test.contentType,
					Body:   io.NopCloser(strings.NewReader("body")),
				}
				err := req.ParseForm()
				switch {
				case err == nil && test.wantErr != "":
					t.Errorf("unexpected success; want error %q", test.wantErr)
				case err != nil && test.wantErr == "":
					t.Errorf("want success, got error: %v", err)
				case test.wantErr != "" && test.wantErr != fmt.Sprint(err):
					t.Errorf("got error %q; want %q", err, test.wantErr)
				}
			},
		)
	}
}

func TestParseFormInitializeOnError(t *testing.T) {
	nilBody, _ := NewRequest("POST", "http://www.google.com/search?q=foo", nil)
	tests := []*Request{
		nilBody,
		{Method: "GET", URL: nil},
	}
	for i, req := range tests {
		err := req.ParseForm()
		if req.Form == nil {
			t.Errorf("%d. Form not initialized, error %v", i, err)
		}
		if req.PostForm == nil {
			t.Errorf("%d. PostForm not initialized, error %v", i, err)
		}
	}
}

func TestMultipartReader(t *testing.T) {
	tests := []struct {
		shouldError bool
		contentType string
	}{
		{false, `multipart/form-data; boundary="foo123"`},
		{false, `multipart/mixed; boundary="foo123"`},
		{true, `text/plain`},
	}

	for i, test := range tests {
		req := &Request{
			Method: "POST",
			Header: Header{"Content-Type": {test.contentType}},
			Body:   io.NopCloser(new(bytes.Buffer)),
		}
		multipart, err := req.MultipartReader()
		if test.shouldError {
			if err == nil || multipart != nil {
				t.Errorf("test %d: unexpectedly got nil-error (%v) or non-nil-multipart (%v)", i, err, multipart)
			}
			continue
		}
		if err != nil || multipart == nil {
			t.Errorf("test %d: unexpectedly got error (%v) or nil-multipart (%v)", i, err, multipart)
		}
	}
}

// Issue 9305: ParseMultipartForm should populate PostForm too
func TestParseMultipartFormPopulatesPostForm(t *testing.T) {
	postData :=
		`--xxx
Content-Disposition: form-data; name="field1"

value1
--xxx
Content-Disposition: form-data; name="field2"

value2
--xxx
Content-Disposition: form-data; name="file"; filename="file"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary

binary data
--xxx--
`
	req := &Request{
		Method: "POST",
		Header: Header{"Content-Type": {`multipart/form-data; boundary=xxx`}},
		Body:   io.NopCloser(strings.NewReader(postData)),
	}

	initialFormItems := map[string]string{
		"language": "Go",
		"name":     "gopher",
		"skill":    "go-ing",
		"field2":   "initial-value2",
	}

	req.Form = make(url.Values)
	for k, v := range initialFormItems {
		req.Form.Add(k, v)
	}

	err := req.ParseMultipartForm(10000)
	if err != nil {
		t.Fatalf("unexpected multipart error %v", err)
	}

	wantForm := url.Values{
		"language": []string{"Go"},
		"name":     []string{"gopher"},
		"skill":    []string{"go-ing"},
		"field1":   []string{"value1"},
		"field2":   []string{"initial-value2", "value2"},
	}
	if !reflect.DeepEqual(req.Form, wantForm) {
		t.Fatalf("req.Form = %v, want %v", req.Form, wantForm)
	}

	wantPostForm := url.Values{
		"field1": []string{"value1"},
		"field2": []string{"value2"},
	}
	if !reflect.DeepEqual(req.PostForm, wantPostForm) {
		t.Fatalf("req.PostForm = %v, want %v", req.PostForm, wantPostForm)
	}
}

func TestParseMultipartForm(t *testing.T) {
	req := &Request{
		Method: "POST",
		Header: Header{"Content-Type": {`multipart/form-data; boundary="foo123"`}},
		Body:   io.NopCloser(new(bytes.Buffer)),
	}
	err := req.ParseMultipartForm(25)
	if err == nil {
		t.Error("expected multipart EOF, got nil")
	}

	req.Header = Header{"Content-Type": {"text/plain"}}
	err = req.ParseMultipartForm(25)
	if err != ErrNotMultipart {
		t.Error("expected ErrNotMultipart for text/plain")
	}
}

// Issue 45789: multipart form should not include directory path in filename
func TestParseMultipartFormFilename(t *testing.T) {
	postData :=
		`--xxx
Content-Disposition: form-data; name="file"; filename="../usr/foobar.txt/"
Content-Type: text/plain

--xxx--
`
	req := &Request{
		Method: "POST",
		Header: Header{"Content-Type": {`multipart/form-data; boundary=xxx`}},
		Body:   io.NopCloser(strings.NewReader(postData)),
	}
	_, hdr, err := req.FormFile("file")
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Filename != "foobar.txt" {
		t.Errorf("expected only the last element of the path, got %q", hdr.Filename)
	}
}

// Issue #40430: Test that if maxMemory for ParseMultipartForm when combined with
// the payload size and the internal leeway buffer size of 10MiB overflows, that we
// correctly return an error.
func TestMaxInt64ForMultipartFormMaxMemoryOverflow(t *testing.T) {
	run(t, testMaxInt64ForMultipartFormMaxMemoryOverflow)
}
func testMaxInt64ForMultipartFormMaxMemoryOverflow(t *testing.T, mode testMode) {
	payloadSize := 1 << 10
	cst := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		// The combination of:
		//      MaxInt64 + payloadSize + (internal spare of 10MiB)
		// triggers the overflow. See issue https://golang.org/issue/40430/
		if err := req.ParseMultipartForm(math.MaxInt64); err != nil {
			Error(rw, err.Error(), StatusBadRequest)
			return
		}
	})).ts
	fBuf := new(bytes.Buffer)
	mw := multipart.NewWriter(fBuf)
	mf, err := mw.CreateFormFile("file", "myfile.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mf.Write(bytes.Repeat([]byte("abc"), payloadSize)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := NewRequest("POST", cst.URL, fBuf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	res, err := cst.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if g, w := res.StatusCode, StatusOK; g != w {
		t.Fatalf("Status code mismatch: got %d, want %d", g, w)
	}
}

func TestRequestRedirect(t *testing.T) { run(t, testRequestRedirect) }
func testRequestRedirect(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/foo/")
			w.WriteHeader(StatusSeeOther)
		case "/foo/":
			fmt.Fprintf(w, "foo")
		default:
			w.WriteHeader(StatusBadRequest)
		}
	}))

	var end = regexp.MustCompile("/foo/$")
	r, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	url := r.Request.URL.String()
	if r.StatusCode != 200 || !end.MatchString(url) {
		t.Fatalf("Get got status %d at %q, want 200 matching /foo/$", r.StatusCode, url)
	}
}

func TestSetBasicAuth(t *testing.T) {
	r, _ := NewRequest("GET", "http://example.com/", nil)
	r.SetBasicAuth("Aladdin", "open sesame")
	if g, e := r.Header.Get("Authorization"), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="; g != e {
		t.Errorf("got header %q, want %q", g, e)
	}
}

func TestMultipartRequest(t *testing.T) {
	// Test that we can read the values and files of a
	// multipart request with FormValue and FormFile,
	// and that ParseMultipartForm can be called multiple times.
	req := newTestMultipartRequest(t)
	if err := req.ParseMultipartForm(25); err != nil {
		t.Fatal("ParseMultipartForm first call:", err)
	}
	defer req.MultipartForm.RemoveAll()
	validateTestMultipartContents(t, req, false)
	if err := req.ParseMultipartForm(25); err != nil {
		t.Fatal("ParseMultipartForm second call:", err)
	}
	validateTestMultipartContents(t, req, false)
}

// Issue #25192: Test that ParseMultipartForm fails but still parses the
// multi-part form when a URL containing a semicolon is provided.
func TestParseMultipartFormSemicolonSeparator(t *testing.T) {
	req := newTestMultipartRequest(t)
	req.URL = &url.URL{RawQuery: "q=foo;q=bar"}
	if err := req.ParseMultipartForm(25); err == nil {
		t.Fatal("ParseMultipartForm expected error due to invalid semicolon, got nil")
	}
	defer req.MultipartForm.RemoveAll()
	validateTestMultipartContents(t, req, false)
}

func TestMultipartRequestAuto(t *testing.T) {
	// Test that FormValue and FormFile automatically invoke
	// ParseMultipartForm and return the right values.
	req := newTestMultipartRequest(t)
	defer func() {
		if req.MultipartForm != nil {
			req.MultipartForm.RemoveAll()
		}
	}()
	validateTestMultipartContents(t, req, true)
}

func TestMissingFileMultipartRequest(t *testing.T) {
	// Test that FormFile returns an error if
	// the named file is missing.
	req := newTestMultipartRequest(t)
	testMissingFile(t, req)
}

// Test that FormValue invokes ParseMultipartForm.
func TestFormValueCallsParseMultipartForm(t *testing.T) {
	req, _ := NewRequest("POST", "http://www.google.com/", strings.NewReader("z=post"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	if req.Form != nil {
		t.Fatal("Unexpected request Form, want nil")
	}
	req.FormValue("z")
	if req.Form == nil {
		t.Fatal("ParseMultipartForm not called by FormValue")
	}
}

// Test that FormFile invokes ParseMultipartForm.
func TestFormFileCallsParseMultipartForm(t *testing.T) {
	req := newTestMultipartRequest(t)
	if req.Form != nil {
		t.Fatal("Unexpected request Form, want nil")
	}
	req.FormFile("")
	if req.Form == nil {
		t.Fatal("ParseMultipartForm not called by FormFile")
	}
}

// Test that ParseMultipartForm errors if called
// after MultipartReader on the same request.
func TestParseMultipartFormOrder(t *testing.T) {
	req := newTestMultipartRequest(t)
	if _, err := req.MultipartReader(); err != nil {
		t.Fatalf("MultipartReader: %v", err)
	}
	if err := req.ParseMultipartForm(1024); err == nil {
		t.Fatal("expected an error from ParseMultipartForm after call to MultipartReader")
	}
}

// Test that MultipartReader errors if called
// after ParseMultipartForm on the same request.
func TestMultipartReaderOrder(t *testing.T) {
	req := newTestMultipartRequest(t)
	if err := req.ParseMultipartForm(25); err != nil {
		t.Fatalf("ParseMultipartForm: %v", err)
	}
	defer req.MultipartForm.RemoveAll()
	if _, err := req.MultipartReader(); err == nil {
		t.Fatal("expected an error from MultipartReader after call to ParseMultipartForm")
	}
}

// Test that FormFile errors if called after
// MultipartReader on the same request.
func TestFormFileOrder(t *testing.T) {
	req := newTestMultipartRequest(t)
	if _, err := req.MultipartReader(); err != nil {
		t.Fatalf("MultipartReader: %v", err)
	}
	if _, _, err := req.FormFile(""); err == nil {
		t.Fatal("expected an error from FormFile after call to MultipartReader")
	}
}

var readRequestErrorTests = []struct {
	in  string
	err string

	header Header
}{
	0: {"GET / HTTP/1.1\r\nheader:foo\r\n\r\n", "", Header{"Header": {"foo"}}},
	1: {"GET / HTTP/1.1\r\nheader:foo\r\n", io.ErrUnexpectedEOF.Error(), nil},
	2: {"", io.EOF.Error(), nil},
	3: {
		in:     "HEAD / HTTP/1.1\r\n\r\n",
		header: Header{},
	},

	// Multiple Content-Length values should either be
	// deduplicated if same or reject otherwise
	// See Issue 16490.
	4: {
		in:  "POST / HTTP/1.1\r\nContent-Length: 10\r\nContent-Length: 0\r\n\r\nGopher hey\r\n",
		err: "cannot contain multiple Content-Length headers",
	},
	5: {
		in:  "POST / HTTP/1.1\r\nContent-Length: 10\r\nContent-Length: 6\r\n\r\nGopher\r\n",
		err: "cannot contain multiple Content-Length headers",
	},
	6: {
		in:     "PUT / HTTP/1.1\r\nContent-Length: 6 \r\nContent-Length: 6\r\nContent-Length:6\r\n\r\nGopher\r\n",
		err:    "",
		header: Header{"Content-Length": {"6"}},
	},
	7: {
		in:  "PUT / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 6 \r\n\r\n",
		err: "cannot contain multiple Content-Length headers",
	},
	8: {
		in:  "POST / HTTP/1.1\r\nContent-Length:\r\nContent-Length: 3\r\n\r\n",
		err: "cannot contain multiple Content-Length headers",
	},
	9: {
		in:     "HEAD / HTTP/1.1\r\nContent-Length:0\r\nContent-Length: 0\r\n\r\n",
		header: Header{"Content-Length": {"0"}},
	},
	10: {
		in:  "HEAD / HTTP/1.1\r\nHost: foo\r\nHost: bar\r\n\r\n\r\n\r\n",
		err: "too many Host headers",
	},
}

func TestReadRequestErrors(t *testing.T) {
	for i, tt := range readRequestErrorTests {
		req, err := ReadRequest(bufio.NewReader(strings.NewReader(tt.in)))
		if err == nil {
			if tt.err != "" {
				t.Errorf("#%d: got nil err; want %q", i, tt.err)
			}

			if !reflect.DeepEqual(tt.header, req.Header) {
				t.Errorf("#%d: gotHeader: %q wantHeader: %q", i, req.Header, tt.header)
			}
			continue
		}

		if tt.err == "" || !strings.Contains(err.Error(), tt.err) {
			t.Errorf("%d: got error = %v; want %v", i, err, tt.err)
		}
	}
}

var newRequestHostTests = []struct {
	in, out string
}{
	{"http://www.example.com/", "www.example.com"},
	{"http://www.example.com:8080/", "www.example.com:8080"},

	{"http://192.168.0.1/", "192.168.0.1"},
	{"http://192.168.0.1:8080/", "192.168.0.1:8080"},
	{"http://192.168.0.1:/", "192.168.0.1"},

	{"http://[fe80::1]/", "[fe80::1]"},
	{"http://[fe80::1]:8080/", "[fe80::1]:8080"},
	{"http://[fe80::1%25en0]/", "[fe80::1%en0]"},
	{"http://[fe80::1%25en0]:8080/", "[fe80::1%en0]:8080"},
	{"http://[fe80::1%25en0]:/", "[fe80::1%en0]"},
}

func TestNewRequestHost(t *testing.T) {
	for i, tt := range newRequestHostTests {
		req, err := NewRequest("GET", tt.in, nil)
		if err != nil {
			t.Errorf("#%v: %v", i, err)
			continue
		}
		if req.Host != tt.out {
			t.Errorf("got %q; want %q", req.Host, tt.out)
		}
	}
}

func TestRequestInvalidMethod(t *testing.T) {
	_, err := NewRequest("bad method", "http://foo.com/", nil)
	if err == nil {
		t.Error("expected error from NewRequest with invalid method")
	}
	req, err := NewRequest("GET", "http://foo.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Method = "bad method"
	_, err = DefaultClient.Do(req)
	if err == nil || !strings.Contains(err.Error(), "invalid method") {
		t.Errorf("Transport error = %v; want invalid method", err)
	}

	req, err = NewRequest("", "http://foo.com/", nil)
	if err != nil {
		t.Errorf("NewRequest(empty method) = %v; want nil", err)
	} else if req.Method != "GET" {
		t.Errorf("NewRequest(empty method) has method %q; want GET", req.Method)
	}
}

func TestNewRequestContentLength(t *testing.T) {
	readByte := func(r io.Reader) io.Reader {
		var b [1]byte
		r.Read(b[:])
		return r
	}
	tests := []struct {
		r    io.Reader
		want int64
	}{
		{bytes.NewReader([]byte("123")), 3},
		{bytes.NewBuffer([]byte("1234")), 4},
		{strings.NewReader("12345"), 5},
		{strings.NewReader(""), 0},
		{NoBody, 0},

		// Not detected. During Go 1.8 we tried to make these set to -1, but
		// due to Issue 18117, we keep these returning 0, even though they're
		// unknown.
		{struct{ io.Reader }{strings.NewReader("xyz")}, 0},
		{io.NewSectionReader(strings.NewReader("x"), 0, 6), 0},
		{readByte(io.NewSectionReader(strings.NewReader("xy"), 0, 6)), 0},
	}
	for i, tt := range tests {
		req, err := NewRequest("POST", "http://localhost/", tt.r)
		if err != nil {
			t.Fatal(err)
		}
		if req.ContentLength != tt.want {
			t.Errorf("test[%d]: ContentLength(%T) = %d; want %d", i, tt.r, req.ContentLength, tt.want)
		}
	}
}

var parseHTTPVersionTests = []struct {
	vers         string
	major, minor int
	ok           bool
}{
	{"HTTP/0.0", 0, 0, true},
	{"HTTP/0.9", 0, 9, true},
	{"HTTP/1.0", 1, 0, true},
	{"HTTP/1.1", 1, 1, true},

	{"HTTP", 0, 0, false},
	{"HTTP/one.one", 0, 0, false},
	{"HTTP/1.1/", 0, 0, false},
	{"HTTP/-1,0", 0, 0, false},
	{"HTTP/0,-1", 0, 0, false},
	{"HTTP/", 0, 0, false},
	{"HTTP/1,1", 0, 0, false},
	{"HTTP/+1.1", 0, 0, false},
	{"HTTP/1.+1", 0, 0, false},
	{"HTTP/0000000001.1", 0, 0, false},
	{"HTTP/1.0000000001", 0, 0, false},
	{"HTTP/3.14", 0, 0, false},
	{"HTTP/12.3", 0, 0, false},
}

func TestParseHTTPVersion(t *testing.T) {
	for _, tt := range parseHTTPVersionTests {
		major, minor, ok := ParseHTTPVersion(tt.vers)
		if ok != tt.ok || major != tt.major || minor != tt.minor {
			type version struct {
				major, minor int
				ok           bool
			}
			t.Errorf("failed to parse %q, expected: %#v, got %#v", tt.vers, version{tt.major, tt.minor, tt.ok}, version{major, minor, ok})
		}
	}
}

type getBasicAuthTest struct {
	username, password string
	ok                 bool
}

type basicAuthCredentialsTest struct {
	username, password string
}

var getBasicAuthTests = []struct {
	username, password string
	ok                 bool
}{
	{"Aladdin", "open sesame", true},
	{"Aladdin", "open:sesame", true},
	{"", "", true},
}

func TestGetBasicAuth(t *testing.T) {
	for _, tt := range getBasicAuthTests {
		r, _ := NewRequest("GET", "http://example.com/", nil)
		r.SetBasicAuth(tt.username, tt.password)
		username, password, ok := r.BasicAuth()
		if ok != tt.ok || username != tt.username || password != tt.password {
			t.Errorf("BasicAuth() = %#v, want %#v", getBasicAuthTest{username, password, ok},
				getBasicAuthTest{tt.username, tt.password, tt.ok})
		}
	}
	// Unauthenticated request.
	r, _ := NewRequest("GET", "http://example.com/", nil)
	username, password, ok := r.BasicAuth()
	if ok {
		t.Errorf("expected false from BasicAuth when the request is unauthenticated")
	}
	want := basicAuthCredentialsTest{"", ""}
	if username != want.username || password != want.password {
		t.Errorf("expected credentials: %#v when the request is unauthenticated, got %#v",
			want, basicAuthCredentialsTest{username, password})
	}
}

var parseBasicAuthTests = []struct {
	header, username, password string
	ok                         bool
}{
	{"Basic " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")), "Aladdin", "open sesame", true},

	// Case doesn't matter:
	{"BASIC " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")), "Aladdin", "open sesame", true},
	{"basic " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")), "Aladdin", "open sesame", true},

	{"Basic " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open:sesame")), "Aladdin", "open:sesame", true},
	{"Basic " + base64.StdEncoding.EncodeToString([]byte(":")), "", "", true},
	{"Basic" + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")), "", "", false},
	{base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")), "", "", false},
	{"Basic ", "", "", false},
	{"Basic Aladdin:open sesame", "", "", false},
	{`Digest username="Aladdin"`, "", "", false},
}

func TestParseBasicAuth(t *testing.T) {
	for _, tt := range parseBasicAuthTests {
		r, _ := NewRequest("GET", "http://example.com/", nil)
		r.Header.Set("Authorization", tt.header)
		username, password, ok := r.BasicAuth()
		if ok != tt.ok || username != tt.username || password != tt.password {
			t.Errorf("BasicAuth() = %#v, want %#v", getBasicAuthTest{username, password, ok},
				getBasicAuthTest{tt.username, tt.password, tt.ok})
		}
	}
}

type logWrites struct {
	t   *testing.T
	dst *[]string
}

func (l logWrites) WriteByte(c byte) error {
	l.t.Fatalf("unexpected WriteByte call")
	return nil
}

func (l logWrites) Write(p []byte) (n int, err error) {
	*l.dst = append(*l.dst, string(p))
	return len(p), nil
}

func TestRequestWriteBufferedWriter(t *testing.T) {
	got := []string{}
	req, _ := NewRequest("GET", "http://foo.com/", nil)
	req.Write(logWrites{t, &got})
	want := []string{
		"GET / HTTP/1.1\r\n",
		"Host: foo.com\r\n",
		"User-Agent: " + DefaultUserAgent + "\r\n",
		"\r\n",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Writes = %q\n  Want = %q", got, want)
	}
}

func TestRequestBadHostHeader(t *testing.T) {
	got := []string{}
	req, err := NewRequest("GET", "http://foo/after", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "foo.com\nnewline"
	req.URL.Host = "foo.com\nnewline"
	req.Write(logWrites{t, &got})
	want := []string{
		"GET /after HTTP/1.1\r\n",
		"Host: \r\n",
		"User-Agent: " + DefaultUserAgent + "\r\n",
		"\r\n",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Writes = %q\n  Want = %q", got, want)
	}
}

func TestRequestBadUserAgent(t *testing.T) {
	got := []string{}
	req, err := NewRequest("GET", "http://foo/after", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "evil\r\nX-Evil: evil")
	req.Write(logWrites{t, &got})
	want := []string{
		"GET /after HTTP/1.1\r\n",
		"Host: foo\r\n",
		"User-Agent: evil  X-Evil: evil\r\n",
		"\r\n",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Writes = %q\n  Want = %q", got, want)
	}
}

func TestStarRequest(t *testing.T) {
	req, err := ReadRequest(bufio.NewReader(strings.NewReader("M-SEARCH * HTTP/1.1\r\n\r\n")))
	if err != nil {
		return
	}
	if req.ContentLength != 0 {
		t.Errorf("ContentLength = %d; want 0", req.ContentLength)
	}
	if req.Body == nil {
		t.Errorf("Body = nil; want non-nil")
	}

	// Request.Write has Client semantics for Body/ContentLength,
	// where ContentLength 0 means unknown if Body is non-nil, and
	// thus chunking will happen unless we change semantics and
	// signal that we want to serialize it as exactly zero.  The
	// only way to do that for outbound requests is with a nil
	// Body:
	clientReq := *req
	clientReq.Body = nil

	var out strings.Builder
	if err := clientReq.Write(&out); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(out.String(), "chunked") {
		t.Error("wrote chunked request; want no body")
	}
	back, err := ReadRequest(bufio.NewReader(strings.NewReader(out.String())))
	if err != nil {
		t.Fatal(err)
	}
	// Ignore the Headers (the User-Agent breaks the deep equal,
	// but we don't care about it)
	req.Header = nil
	back.Header = nil
	if !reflect.DeepEqual(req, back) {
		t.Errorf("Original request doesn't match Request read back.")
		t.Logf("Original: %#v", req)
		t.Logf("Original.URL: %#v", req.URL)
		t.Logf("Wrote: %s", out.String())
		t.Logf("Read back (doesn't match Original): %#v", back)
	}
}

type responseWriterJustWriter struct {
	io.Writer
}

func (responseWriterJustWriter) Header() Header  { panic("should not be called") }
func (responseWriterJustWriter) WriteHeader(int) { panic("should not be called") }

// delayedEOFReader never returns (n > 0, io.EOF), instead putting
// off the io.EOF until a subsequent Read call.
type delayedEOFReader struct {
	r io.Reader
}

func (dr delayedEOFReader) Read(p []byte) (n int, err error) {
	n, err = dr.r.Read(p)
	if n > 0 && err == io.EOF {
		err = nil
	}
	return
}

func TestIssue10884_MaxBytesEOF(t *testing.T) {
	dst := io.Discard
	_, err := io.Copy(dst, MaxBytesReader(
		responseWriterJustWriter{dst},
		io.NopCloser(delayedEOFReader{strings.NewReader("12345")}),
		5))
	if err != nil {
		t.Fatal(err)
	}
}

// Issue 14981: MaxBytesReader's return error wasn't sticky. It
// doesn't technically need to be, but people expected it to be.
func TestMaxBytesReaderStickyError(t *testing.T) {
	isSticky := func(r io.Reader) error {
		var log bytes.Buffer
		buf := make([]byte, 1000)
		var firstErr error
		for {
			n, err := r.Read(buf)
			fmt.Fprintf(&log, "Read(%d) = %d, %v\n", len(buf), n, err)
			if err == nil {
				continue
			}
			if firstErr == nil {
				firstErr = err
				continue
			}
			if !reflect.DeepEqual(err, firstErr) {
				return fmt.Errorf("non-sticky error. got log:\n%s", log.Bytes())
			}
			t.Logf("Got log: %s", log.Bytes())
			return nil
		}
	}
	tests := [...]struct {
		readable int
		limit    int64
	}{
		0: {99, 100},
		1: {100, 100},
		2: {101, 100},
	}
	for i, tt := range tests {
		rc := MaxBytesReader(nil, io.NopCloser(bytes.NewReader(make([]byte, tt.readable))), tt.limit)
		if err := isSticky(rc); err != nil {
			t.Errorf("%d. error: %v", i, err)
		}
	}
}

// Issue 45101: maxBytesReader's Read panicked when n < -1. This test
// also ensures that Read treats negative limits as equivalent to 0.
func TestMaxBytesReaderDifferentLimits(t *testing.T) {
	const testStr = "1234"
	tests := [...]struct {
		limit   int64
		lenP    int
		wantN   int
		wantErr bool
	}{
		0: {
			limit:   -123,
			lenP:    0,
			wantN:   0,
			wantErr: false, // Ensure we won't return an error when the limit is negative, but we don't need to read.
		},
		1: {
			limit:   -100,
			lenP:    32 * 1024,
			wantN:   0,
			wantErr: true,
		},
		2: {
			limit:   -2,
			lenP:    1,
			wantN:   0,
			wantErr: true,
		},
		3: {
			limit:   -1,
			lenP:    2,
			wantN:   0,
			wantErr: true,
		},
		4: {
			limit:   0,
			lenP:    3,
			wantN:   0,
			wantErr: true,
		},
		5: {
			limit:   1,
			lenP:    4,
			wantN:   1,
			wantErr: true,
		},
		6: {
			limit:   2,
			lenP:    5,
			wantN:   2,
			wantErr: true,
		},
		7: {
			limit:   3,
			lenP:    2,
			wantN:   2,
			wantErr: false,
		},
		8: {
			limit:   int64(len(testStr)),
			lenP:    len(testStr),
			wantN:   len(testStr),
			wantErr: false,
		},
		9: {
			limit:   100,
			lenP:    6,
			wantN:   len(testStr),
			wantErr: false,
		},
		10: { /* Issue 54408 */
			limit:   int64(1<<63 - 1),
			lenP:    len(testStr),
			wantN:   len(testStr),
			wantErr: false,
		},
	}
	for i, tt := range tests {
		rc := MaxBytesReader(nil, io.NopCloser(strings.NewReader(testStr)), tt.limit)

		n, err := rc.Read(make([]byte, tt.lenP))

		if n != tt.wantN {
			t.Errorf("%d. n: %d, want n: %d", i, n, tt.wantN)
		}

		if (err != nil) != tt.wantErr {
			t.Errorf("%d. error: %v", i, err)
		}
	}
}

func TestWithContextNilURL(t *testing.T) {
	req, err := NewRequest("POST", "https://golang.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Issue 20601
	req.URL = nil
	reqCopy := req.WithContext(context.Background())
	if reqCopy.URL != nil {
		t.Error("expected nil URL in cloned request")
	}
}

// Ensure that Request.Clone creates a deep copy of TransferEncoding.
// See issue 41907.
func TestRequestCloneTransferEncoding(t *testing.T) {
	body := strings.NewReader("body")
	req, _ := NewRequest("POST", "https://example.org/", body)
	req.TransferEncoding = []string{
		"encoding1",
	}

	clonedReq := req.Clone(context.Background())
	// modify original after deep copy
	req.TransferEncoding[0] = "encoding2"

	if req.TransferEncoding[0] != "encoding2" {
		t.Error("expected req.TransferEncoding to be changed")
	}
	if clonedReq.TransferEncoding[0] != "encoding1" {
		t.Error("expected clonedReq.TransferEncoding to be unchanged")
	}
}

// Ensure that Request.Clone works correctly with PathValue.
// See issue 64911.
func TestRequestClonePathValue(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.org/", nil)
	req.SetPathValue("p1", "orig")

	clonedReq := req.Clone(context.Background())
	clonedReq.SetPathValue("p2", "copy")

	// Ensure that any modifications to the cloned
	// request do not pollute the original request.
	if g, w := req.PathValue("p2"), ""; g != w {
		t.Fatalf("p2 mismatch got %q, want %q", g, w)
	}
	if g, w := req.PathValue("p1"), "orig"; g != w {
		t.Fatalf("p1 mismatch got %q, want %q", g, w)
	}

	// Assert on the changes to the cloned request.
	if g, w := clonedReq.PathValue("p1"), "orig"; g != w {
		t.Fatalf("p1 mismatch got %q, want %q", g, w)
	}
	if g, w := clonedReq.PathValue("p2"), "copy"; g != w {
		t.Fatalf("p2 mismatch got %q, want %q", g, w)
	}
}

// Issue 34878: verify we don't panic when including basic auth (Go 1.13 regression)
func TestNoPanicOnRoundTripWithBasicAuth(t *testing.T) { run(t, testNoPanicWithBasicAuth) }
func testNoPanicWithBasicAuth(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {}))

	u, err := url.Parse(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("foo", "bar")
	req := &Request{
		URL:    u,
		Method: "GET",
	}
	if _, err := cst.c.Do(req); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// verify that NewRequest sets Request.GetBody and that it works
func TestNewRequestGetBody(t *testing.T) {
	tests := []struct {
		r io.Reader
	}{
		{r: strings.NewReader("hello")},
		{r: bytes.NewReader([]byte("hello"))},
		{r: bytes.NewBuffer([]byte("hello"))},
	}
	for i, tt := range tests {
		req, err := NewRequest("POST", "http://foo.tld/", tt.r)
		if err != nil {
			t.Errorf("test[%d]: %v", i, err)
			continue
		}
		if req.Body == nil {
			t.Errorf("test[%d]: Body = nil", i)
			continue
		}
		if req.GetBody == nil {
			t.Errorf("test[%d]: GetBody = nil", i)
			continue
		}
		slurp1, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("test[%d]: ReadAll(Body) = %v", i, err)
		}
		newBody, err := req.GetBody()
		if err != nil {
			t.Errorf("test[%d]: GetBody = %v", i, err)
		}
		slurp2, err := io.ReadAll(newBody)
		if err != nil {
			t.Errorf("test[%d]: ReadAll(GetBody()) = %v", i, err)
		}
		if string(slurp1) != string(slurp2) {
			t.Errorf("test[%d]: Body %q != GetBody %q", i, slurp1, slurp2)
		}
	}
}

func testMissingFile(t *testing.T, req *Request) {
	f, fh, err := req.FormFile("missing")
	if f != nil {
		t.Errorf("FormFile file = %v, want nil", f)
	}
	if fh != nil {
		t.Errorf("FormFile file header = %v, want nil", fh)
	}
	if err != ErrMissingFile {
		t.Errorf("FormFile err = %q, want ErrMissingFile", err)
	}
}

func newTestMultipartRequest(t *testing.T) *Request {
	b := strings.NewReader(strings.ReplaceAll(message, "\n", "\r\n"))
	req, err := NewRequest("POST", "/", b)
	if err != nil {
"""




```