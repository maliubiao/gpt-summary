Response:
这是对一个Go语言源文件 `go/src/net/http/request_test.go` 的代码片段进行功能归纳。这个文件主要用于测试 `net/http` 包中关于 HTTP 请求 (`Request`) 的相关功能。

**归纳思路：**

1. **识别测试目标：** 代码中大量的 `Test...` 函数表明这是测试代码，目标是测试 `net/http.Request` 的各种方法和属性。
2. **分析测试内容：**  观察每个测试函数，理解它在验证什么行为。例如，`TestNewRequestMultipart` 显然是在测试创建 multipart 请求的功能。
3. **提取核心功能点：**  将各个测试函数覆盖的功能点提炼出来。
4. **分析辅助函数：**  像 `newMultipartRequest` 和 `validateTestMultipartContents` 这样的辅助函数，虽然不是测试函数，但它们为测试特定功能提供了支持。
5. **识别基准测试：** 带有 `Benchmark...` 前缀的函数是性能基准测试，它们测量特定操作的性能。
6. **关注错误处理和边界情况：** 例如 `TestRequestCookie` 测试了在请求中获取 Cookie 的功能，并考虑了 `ErrNoCookie` 的情况。
7. **识别代码示例暗示的功能：**  即使没有明确的 `Test...` 函数，一些代码片段（如 `newMultipartRequest`）也展示了如何使用相关功能。
8. **理解常量和变量的用途：** 代码中定义的常量（如 `fileaContents`, `boundary`）用于构造测试数据。

**详细步骤：**

* 阅读 `newMultipartRequest` 函数，它创建了一个 `multipart/form-data` 类型的请求。
* 阅读 `validateTestMultipartContents` 和 `testMultipartFile` 函数，它们验证了 multipart 请求中表单字段和文件的内容是否正确。
* 阅读 `TestRequestCookie` 和 `TestRequestCookiesByName`，它们测试了获取和管理请求中 Cookie 的功能。
* 阅读 `BenchmarkReadRequest...` 函数，它们测试了读取各种格式 HTTP 请求的性能。
* 阅读 `BenchmarkFileAndServer...` 函数，它们测试了上传大文件的性能。
* 阅读 `TestErrNotSupported`，它测试了 `ErrNotSupported` 错误。
* 阅读 `TestPathValue...` 系列函数，它们测试了与请求路径参数相关的功能。
* 阅读 `TestStatus`，它测试了服务器根据请求方法返回的状态码和 `Allow` 头。

通过以上步骤，就可以较为全面地理解这段代码的功能。
这段代码是 `go/src/net/http/request_test.go` 文件的一部分，它主要用于测试 `net/http` 包中 `Request` 类型的一些功能。这是该测试文件的第二部分，因此会延续第一部分测试的主题，并可能包含一些更细致或特定的测试用例。

**归纳一下它的功能：**

这段代码主要测试了 `net/http.Request` 类型的以下功能：

1. **构建和验证 `multipart/form-data` 请求:**
   - 提供了 `newMultipartRequest` 函数来创建一个包含文本字段和文件上传的 `multipart/form-data` 类型的请求。
   - 提供了 `validateTestMultipartContents` 函数来验证解析后的 multipart 请求内容，包括文本字段的值和上传文件的内容和元数据。
   - 提供了 `testMultipartFile` 函数来辅助验证单个上传文件的内容和文件名。
   - 测试了 `Request.FormValue` 和 `Request.FormFile` 方法，用于获取 multipart 表单中的字段值和文件。

2. **测试 `Request` 的 Cookie 相关功能:**
   - `TestRequestCookie` 测试了 `Request.Cookie` 方法，验证了它能正确返回指定名称的 Cookie，并在未找到 Cookie 或名称为空时返回 `ErrNoCookie`。
   - `TestRequestCookiesByName` 测试了 `Request.CookiesNamed` 方法，验证了它能返回所有具有指定名称的 Cookie 切片。

3. **性能基准测试 (Benchmarking) `ReadRequest`:**
   - 提供了一系列 `BenchmarkReadRequest...` 函数，使用不同的 HTTP 请求头格式（模拟 Chrome, curl, ApacheBench, Siege, wrk 等客户端）来测试 `ReadRequest` 函数的性能。`ReadRequest` 函数用于从 `io.Reader` 中读取并解析 HTTP 请求。
   - 使用 `infiniteReader` 结构体模拟无限读取的输入流，用于基准测试。

4. **性能基准测试文件上传:**
   - `BenchmarkFileAndServer...` 函数测试了使用 `PUT` 方法上传不同大小文件的性能。
   - `benchmarkFileAndServer` 函数创建临时文件并启动测试服务器来模拟文件上传场景。
   - `runFileAndServerBenchmarks` 函数在不同的 HTTP 模式 (HTTP/1.1, HTTPS/1.1, HTTP/2) 下运行文件上传基准测试。

5. **测试错误类型:**
   - `TestErrNotSupported` 确认 `ErrNotSupported` 是否是 `errors.ErrUnsupported` 的一个。

6. **测试请求路径参数 (Path Values):**
   - `TestPathValueNoMatch` 测试了在未匹配路由的请求上使用 `PathValue` 和 `SetPathValue` 的行为。
   - `TestPathValueAndPattern` 测试了在路由匹配的情况下，`PathValue` 方法能否正确获取路径参数，并验证了 `Request.Pattern` 属性的值。
   - `TestSetPathValue` 测试了 `SetPathValue` 方法是否能设置请求的路径参数。

7. **测试 HTTP 状态码和 `Allow` 头:**
   - `TestStatus` 测试了服务器对于不同请求方法和路径返回的 HTTP 状态码，特别是针对 405 "Method Not Allowed" 响应，验证了 `Allow` 头的正确设置。

**Go 语言功能的实现示例 (与代码推理相关):**

**1. 获取 Multipart 表单字段值:**

假设我们有以下 multipart 请求体：

```
--MyBoundary
Content-Disposition: form-data; name="username"

testuser
--MyBoundary--
```

并且已经通过某种方式（例如 `http.ReadRequest`）创建了一个 `Request` 对象 `req`。我们可以使用 `req.FormValue("username")` 来获取 `username` 字段的值：

```go
reqBody := `--MyBoundary\r\n` +
	`Content-Disposition: form-data; name="username"\r\n` +
	`\r\n` +
	`testuser\r\n` +
	`--MyBoundary--\r\n`

req, err := http.NewRequest("POST", "http://example.com", strings.NewReader(reqBody))
if err != nil {
	panic(err)
}
req.Header.Set("Content-Type", `multipart/form-data; boundary="MyBoundary"`)

err = req.ParseMultipartForm(1024) // 限制内存使用
if err != nil {
    panic(err)
}

username := req.FormValue("username")
fmt.Println(username) // 输出: testuser
```

**假设的输入与输出:**

* **输入:** 上述的 multipart 请求体。
* **输出:** `testuser`

**2. 获取 Multipart 上传的文件:**

假设我们有以下 multipart 请求体包含一个文件上传：

```
--MyBoundary
Content-Disposition: form-data; name="file"; filename="example.txt"
Content-Type: text/plain

This is the file content.
--MyBoundary--
```

我们可以使用 `req.FormFile("file")` 来获取文件信息：

```go
reqBody := `--MyBoundary\r\n` +
	`Content-Disposition: form-data; name="file"; filename="example.txt"\r\n` +
	`Content-Type: text/plain\r\n` +
	`\r\n` +
	`This is the file content.\r\n` +
	`--MyBoundary--\r\n`

req, err := http.NewRequest("POST", "http://example.com", strings.NewReader(reqBody))
if err != nil {
	panic(err)
}
req.Header.Set("Content-Type", `multipart/form-data; boundary="MyBoundary"`)

err = req.ParseMultipartForm(1024)
if err != nil {
    panic(err)
}

file, header, err := req.FormFile("file")
if err != nil {
    panic(err)
}
defer file.Close()

fmt.Println(header.Filename) // 输出: example.txt

content, _ := io.ReadAll(file)
fmt.Println(string(content)) // 输出: This is the file content.
```

**假设的输入与输出:**

* **输入:** 上述的 multipart 请求体。
* **输出:** `example.txt`, `This is the file content.`

**命令行参数的具体处理:**

这段代码本身是测试代码，并不直接处理命令行参数。与 HTTP 请求相关的命令行参数处理通常会在使用 `net/http` 构建实际的 HTTP 客户端或服务器时出现。例如，使用 `curl` 命令发送请求时，你可以通过命令行参数指定请求方法、请求头、请求体等。

**使用者易犯错的点:**

在处理 multipart 表单时，一个常见的错误是 **忘记调用 `req.ParseMultipartForm` 方法**。如果不调用此方法，`req.FormValue` 和 `req.FormFile` 将无法正确解析表单数据。

**示例：**

```go
reqBody := `--MyBoundary\r\n` +
	`Content-Disposition: form-data; name="username"\r\n` +
	`\r\n` +
	`testuser\r\n` +
	`--MyBoundary--\r\n`

req, err := http.NewRequest("POST", "http://example.com", strings.NewReader(reqBody))
if err != nil {
	panic(err)
}
req.Header.Set("Content-Type", `multipart/form-data; boundary="MyBoundary"`)

// 错误：忘记调用 req.ParseMultipartForm
username := req.FormValue("username")
fmt.Println(username) // 输出: "" (空字符串)，因为表单未被解析
```

另一个易错点是在处理大文件上传时，**没有设置合适的内存限制给 `req.ParseMultipartForm`**，可能导致内存溢出。应该根据实际情况设置合适的内存大小限制。

总的来说，这段代码专注于 `net/http.Request` 类型的各种功能测试，涵盖了构建 multipart 请求、处理 Cookie、性能测试以及路径参数和状态码相关的测试。

Prompt: 
```
这是路径为go/src/net/http/request_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""

		t.Fatal("NewRequest:", err)
	}
	ctype := fmt.Sprintf(`multipart/form-data; boundary="%s"`, boundary)
	req.Header.Set("Content-type", ctype)
	return req
}

func validateTestMultipartContents(t *testing.T, req *Request, allMem bool) {
	if g, e := req.FormValue("texta"), textaValue; g != e {
		t.Errorf("texta value = %q, want %q", g, e)
	}
	if g, e := req.FormValue("textb"), textbValue; g != e {
		t.Errorf("textb value = %q, want %q", g, e)
	}
	if g := req.FormValue("missing"); g != "" {
		t.Errorf("missing value = %q, want empty string", g)
	}

	assertMem := func(n string, fd multipart.File) {
		if _, ok := fd.(*os.File); ok {
			t.Error(n, " is *os.File, should not be")
		}
	}
	fda := testMultipartFile(t, req, "filea", "filea.txt", fileaContents)
	defer fda.Close()
	assertMem("filea", fda)
	fdb := testMultipartFile(t, req, "fileb", "fileb.txt", filebContents)
	defer fdb.Close()
	if allMem {
		assertMem("fileb", fdb)
	} else {
		if _, ok := fdb.(*os.File); !ok {
			t.Errorf("fileb has unexpected underlying type %T", fdb)
		}
	}

	testMissingFile(t, req)
}

func testMultipartFile(t *testing.T, req *Request, key, expectFilename, expectContent string) multipart.File {
	f, fh, err := req.FormFile(key)
	if err != nil {
		t.Fatalf("FormFile(%q): %q", key, err)
	}
	if fh.Filename != expectFilename {
		t.Errorf("filename = %q, want %q", fh.Filename, expectFilename)
	}
	var b strings.Builder
	_, err = io.Copy(&b, f)
	if err != nil {
		t.Fatal("copying contents:", err)
	}
	if g := b.String(); g != expectContent {
		t.Errorf("contents = %q, want %q", g, expectContent)
	}
	return f
}

// Issue 53181: verify Request.Cookie return the correct Cookie.
// Return ErrNoCookie instead of the first cookie when name is "".
func TestRequestCookie(t *testing.T) {
	for _, tt := range []struct {
		name        string
		value       string
		expectedErr error
	}{
		{
			name:        "foo",
			value:       "bar",
			expectedErr: nil,
		},
		{
			name:        "",
			expectedErr: ErrNoCookie,
		},
	} {
		req, err := NewRequest("GET", "http://example.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&Cookie{Name: tt.name, Value: tt.value})
		c, err := req.Cookie(tt.name)
		if err != tt.expectedErr {
			t.Errorf("got %v, want %v", err, tt.expectedErr)
		}

		// skip if error occurred.
		if err != nil {
			continue
		}
		if c.Value != tt.value {
			t.Errorf("got %v, want %v", c.Value, tt.value)
		}
		if c.Name != tt.name {
			t.Errorf("got %s, want %v", tt.name, c.Name)
		}
	}
}

func TestRequestCookiesByName(t *testing.T) {
	tests := []struct {
		in     []*Cookie
		filter string
		want   []*Cookie
	}{
		{
			in: []*Cookie{
				{Name: "foo", Value: "foo-1"},
				{Name: "bar", Value: "bar"},
			},
			filter: "foo",
			want:   []*Cookie{{Name: "foo", Value: "foo-1"}},
		},
		{
			in: []*Cookie{
				{Name: "foo", Value: "foo-1"},
				{Name: "foo", Value: "foo-2"},
				{Name: "bar", Value: "bar"},
			},
			filter: "foo",
			want: []*Cookie{
				{Name: "foo", Value: "foo-1"},
				{Name: "foo", Value: "foo-2"},
			},
		},
		{
			in: []*Cookie{
				{Name: "bar", Value: "bar"},
			},
			filter: "foo",
			want:   []*Cookie{},
		},
		{
			in: []*Cookie{
				{Name: "bar", Value: "bar"},
			},
			filter: "",
			want:   []*Cookie{},
		},
		{
			in:     []*Cookie{},
			filter: "foo",
			want:   []*Cookie{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			req, err := NewRequest("GET", "http://example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range tt.in {
				req.AddCookie(c)
			}

			got := req.CookiesNamed(tt.filter)

			if !reflect.DeepEqual(got, tt.want) {
				asStr := func(v any) string {
					blob, _ := json.MarshalIndent(v, "", "  ")
					return string(blob)
				}
				t.Fatalf("Result mismatch\n\tGot: %s\n\tWant: %s", asStr(got), asStr(tt.want))
			}
		})
	}
}

const (
	fileaContents = "This is a test file."
	filebContents = "Another test file."
	textaValue    = "foo"
	textbValue    = "bar"
	boundary      = `MyBoundary`
)

const message = `
--MyBoundary
Content-Disposition: form-data; name="filea"; filename="filea.txt"
Content-Type: text/plain

` + fileaContents + `
--MyBoundary
Content-Disposition: form-data; name="fileb"; filename="fileb.txt"
Content-Type: text/plain

` + filebContents + `
--MyBoundary
Content-Disposition: form-data; name="texta"

` + textaValue + `
--MyBoundary
Content-Disposition: form-data; name="textb"

` + textbValue + `
--MyBoundary--
`

func benchmarkReadRequest(b *testing.B, request string) {
	request = request + "\n"                            // final \n
	request = strings.ReplaceAll(request, "\n", "\r\n") // expand \n to \r\n
	b.SetBytes(int64(len(request)))
	r := bufio.NewReader(&infiniteReader{buf: []byte(request)})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ReadRequest(r)
		if err != nil {
			b.Fatalf("failed to read request: %v", err)
		}
	}
}

// infiniteReader satisfies Read requests as if the contents of buf
// loop indefinitely.
type infiniteReader struct {
	buf    []byte
	offset int
}

func (r *infiniteReader) Read(b []byte) (int, error) {
	n := copy(b, r.buf[r.offset:])
	r.offset = (r.offset + n) % len(r.buf)
	return n, nil
}

func BenchmarkReadRequestChrome(b *testing.B) {
	// https://github.com/felixge/node-http-perf/blob/master/fixtures/get.http
	benchmarkReadRequest(b, `GET / HTTP/1.1
Host: localhost:8080
Connection: keep-alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.52 Safari/537.17
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
Cookie: __utma=1.1978842379.1323102373.1323102373.1323102373.1; EPi:NumberOfVisits=1,2012-02-28T13:42:18; CrmSession=5b707226b9563e1bc69084d07a107c98; plushContainerWidth=100%25; plushNoTopMenu=0; hudson_auto_refresh=false
`)
}

func BenchmarkReadRequestCurl(b *testing.B) {
	// curl http://localhost:8080/
	benchmarkReadRequest(b, `GET / HTTP/1.1
User-Agent: curl/7.27.0
Host: localhost:8080
Accept: */*
`)
}

func BenchmarkReadRequestApachebench(b *testing.B) {
	// ab -n 1 -c 1 http://localhost:8080/
	benchmarkReadRequest(b, `GET / HTTP/1.0
Host: localhost:8080
User-Agent: ApacheBench/2.3
Accept: */*
`)
}

func BenchmarkReadRequestSiege(b *testing.B) {
	// siege -r 1 -c 1 http://localhost:8080/
	benchmarkReadRequest(b, `GET / HTTP/1.1
Host: localhost:8080
Accept: */*
Accept-Encoding: gzip
User-Agent: JoeDog/1.00 [en] (X11; I; Siege 2.70)
Connection: keep-alive
`)
}

func BenchmarkReadRequestWrk(b *testing.B) {
	// wrk -t 1 -r 1 -c 1 http://localhost:8080/
	benchmarkReadRequest(b, `GET / HTTP/1.1
Host: localhost:8080
`)
}

func BenchmarkFileAndServer_1KB(b *testing.B) {
	benchmarkFileAndServer(b, 1<<10)
}

func BenchmarkFileAndServer_16MB(b *testing.B) {
	benchmarkFileAndServer(b, 1<<24)
}

func BenchmarkFileAndServer_64MB(b *testing.B) {
	benchmarkFileAndServer(b, 1<<26)
}

func benchmarkFileAndServer(b *testing.B, n int64) {
	f, err := os.CreateTemp(os.TempDir(), "go-bench-http-file-and-server")
	if err != nil {
		b.Fatalf("Failed to create temp file: %v", err)
	}

	defer func() {
		f.Close()
		os.RemoveAll(f.Name())
	}()

	if _, err := io.CopyN(f, rand.Reader, n); err != nil {
		b.Fatalf("Failed to copy %d bytes: %v", n, err)
	}

	run(b, func(b *testing.B, mode testMode) {
		runFileAndServerBenchmarks(b, mode, f, n)
	}, []testMode{http1Mode, https1Mode, http2Mode})
}

func runFileAndServerBenchmarks(b *testing.B, mode testMode, f *os.File, n int64) {
	handler := HandlerFunc(func(rw ResponseWriter, req *Request) {
		defer req.Body.Close()
		nc, err := io.Copy(io.Discard, req.Body)
		if err != nil {
			panic(err)
		}

		if nc != n {
			panic(fmt.Errorf("Copied %d Wanted %d bytes", nc, n))
		}
	})

	cst := newClientServerTest(b, mode, handler).ts

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Perform some setup.
		b.StopTimer()
		if _, err := f.Seek(0, 0); err != nil {
			b.Fatalf("Failed to seek back to file: %v", err)
		}

		b.StartTimer()
		req, err := NewRequest("PUT", cst.URL, io.NopCloser(f))
		if err != nil {
			b.Fatal(err)
		}

		req.ContentLength = n
		// Prevent mime sniffing by setting the Content-Type.
		req.Header.Set("Content-Type", "application/octet-stream")
		res, err := cst.Client().Do(req)
		if err != nil {
			b.Fatalf("Failed to make request to backend: %v", err)
		}

		res.Body.Close()
		b.SetBytes(n)
	}
}

func TestErrNotSupported(t *testing.T) {
	if !errors.Is(ErrNotSupported, errors.ErrUnsupported) {
		t.Error("errors.Is(ErrNotSupported, errors.ErrUnsupported) failed")
	}
}

func TestPathValueNoMatch(t *testing.T) {
	// Check that PathValue and SetPathValue work on a Request that was never matched.
	var r Request
	if g, w := r.PathValue("x"), ""; g != w {
		t.Errorf("got %q, want %q", g, w)
	}
	r.SetPathValue("x", "a")
	if g, w := r.PathValue("x"), "a"; g != w {
		t.Errorf("got %q, want %q", g, w)
	}
}

func TestPathValueAndPattern(t *testing.T) {
	for _, test := range []struct {
		pattern string
		url     string
		want    map[string]string
	}{
		{
			"/{a}/is/{b}/{c...}",
			"/now/is/the/time/for/all",
			map[string]string{
				"a": "now",
				"b": "the",
				"c": "time/for/all",
				"d": "",
			},
		},
		{
			"/names/{name}/{other...}",
			"/names/%2fjohn/address",
			map[string]string{
				"name":  "/john",
				"other": "address",
			},
		},
		{
			"/names/{name}/{other...}",
			"/names/john%2Fdoe/there/is%2F/more",
			map[string]string{
				"name":  "john/doe",
				"other": "there/is//more",
			},
		},
		{
			"/names/{name}/{other...}",
			"/names/n/*",
			map[string]string{
				"name":  "n",
				"other": "*",
			},
		},
	} {
		mux := NewServeMux()
		mux.HandleFunc(test.pattern, func(w ResponseWriter, r *Request) {
			for name, want := range test.want {
				got := r.PathValue(name)
				if got != want {
					t.Errorf("%q, %q: got %q, want %q", test.pattern, name, got, want)
				}
			}
			if r.Pattern != test.pattern {
				t.Errorf("pattern: got %s, want %s", r.Pattern, test.pattern)
			}
		})
		server := httptest.NewServer(mux)
		defer server.Close()
		res, err := Get(server.URL + test.url)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
}

func TestSetPathValue(t *testing.T) {
	mux := NewServeMux()
	mux.HandleFunc("/a/{b}/c/{d...}", func(_ ResponseWriter, r *Request) {
		kvs := map[string]string{
			"b": "X",
			"d": "Y",
			"a": "Z",
		}
		for k, v := range kvs {
			r.SetPathValue(k, v)
		}
		for k, w := range kvs {
			if g := r.PathValue(k); g != w {
				t.Errorf("got %q, want %q", g, w)
			}
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	res, err := Get(server.URL + "/a/b/c/d/e")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestStatus(t *testing.T) {
	// The main purpose of this test is to check 405 responses and the Allow header.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mux := NewServeMux()
	mux.Handle("GET /g", h)
	mux.Handle("POST /p", h)
	mux.Handle("PATCH /p", h)
	mux.Handle("PUT /r", h)
	mux.Handle("GET /r/", h)
	server := httptest.NewServer(mux)
	defer server.Close()

	for _, test := range []struct {
		method, path string
		wantStatus   int
		wantAllow    string
	}{
		{"GET", "/g", 200, ""},
		{"HEAD", "/g", 200, ""},
		{"POST", "/g", 405, "GET, HEAD"},
		{"GET", "/x", 404, ""},
		{"GET", "/p", 405, "PATCH, POST"},
		{"GET", "/./p", 405, "PATCH, POST"},
		{"GET", "/r/", 200, ""},
		{"GET", "/r", 200, ""}, // redirected
		{"HEAD", "/r/", 200, ""},
		{"HEAD", "/r", 200, ""}, // redirected
		{"PUT", "/r/", 405, "GET, HEAD"},
		{"PUT", "/r", 200, ""},
	} {
		req, err := http.NewRequest(test.method, server.URL+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if g, w := res.StatusCode, test.wantStatus; g != w {
			t.Errorf("%s %s: got %d, want %d", test.method, test.path, g, w)
		}
		if g, w := res.Header.Get("Allow"), test.wantAllow; g != w {
			t.Errorf("%s %s, Allow: got %q, want %q", test.method, test.path, g, w)
		}
	}
}

"""




```