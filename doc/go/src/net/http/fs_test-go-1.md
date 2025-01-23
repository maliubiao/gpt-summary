Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a summary of the functionality of the Go code related to `go/src/net/http/fs_test.go`. This immediately tells us we're looking at *testing* code for the `net/http` package, specifically features related to file serving. The prompt mentions this is the *second part* of a larger piece of code, implying the first part covered some initial set of features.

2. **High-Level Scan and Keyword Identification:** Quickly read through the code, looking for key function names, test names, and data structures. Keywords like `Test`, `ServeFile`, `FileServer`, `Range`, `If-Modified-Since`, `If-Unmodified-Since`, `Etag`, `Content-Type`, `Last-Modified`, `StatusCode`, `Header`, `GET`, `HEAD`, `POST`, etc., jump out. These keywords hint at the different aspects of file serving being tested.

3. **Group Tests by Functionality:** Observe how the tests are structured. They often focus on specific HTTP features or error scenarios. Start grouping tests based on their names and the headers/status codes they are examining.

    * **Conditional Requests:** The `TestServeFileConditionalRequests` clearly deals with `If-Modified-Since` and `If-Unmodified-Since` headers.

    * **Error Handling:** `TestServerFileStatError` and `TestFileServerErrorMessages` are about how the server handles errors during file access.

    * **`sendfile` Optimization:** `TestLinuxSendfile` is explicitly about a Linux-specific optimization.

    * **Path Handling:** `TestFileServerNotDirError` focuses on how the server handles requests for non-existent directories. `TestFileServerCleanPath` looks at path cleaning.

    * **Range Requests:** `TestServeFileRejectsInvalidSuffixLengths` checks the validation of `Range` headers.

    * **HTTP Methods:** `TestFileServerMethods` tests various HTTP methods beyond just GET and HEAD.

    * **`FileSystem` Interface:** `TestFileServerFS` and `TestServeFileFS` relate to using the `FileSystem` interface.

    * **Response Writer Issues:** `TestServeFileZippingResponseWriter` highlights a specific (and potentially incorrect) pattern with response writers.

    * **Directory Handling:** `TestFileServerDirWithRootFile` focuses on serving directories when a file with the same name exists at the root.

    * **Error Headers:** `TestServeContentHeadersWithError` tests header behavior when errors occur.

4. **Summarize Each Functional Group:**  For each group of tests, write a concise summary of what it's verifying. Focus on the *what* and *why*. For instance, the conditional request tests verify that the server responds correctly based on the `If-Modified-Since` and `If-Unmodified-Since` headers.

5. **Identify Go Language Features:**  Connect the tests to the underlying Go language features being exercised. The code heavily utilizes `net/http` for request handling, response writing, and header manipulation. The use of `os.Open`, `fs.FileInfo`, `io.ReadSeeker`, `httptest`, `bytes.Buffer`, `strings.Reader`, and the `fs.FS` interface are prominent.

6. **Extract Key Code Examples (as requested):** Where applicable and illustrative, pull out small snippets of Go code that demonstrate the core functionality being tested. For example, showing how `ServeFile` or `FileServer` is used. Since the request asked for *reasoning* behind code, explain what the example demonstrates. Include example inputs and expected outputs where relevant, particularly for conditional request scenarios.

7. **Command-Line Arguments (if applicable):** In this specific snippet, there's mention of setting the `GODEBUG` environment variable (`httpservecontentkeepheaders`). Explain what this variable controls and its effect on the test behavior.

8. **Common Pitfalls:** Based on the tests, infer potential errors users might make. The "zipping response writer" test is a prime example of an anti-pattern. The path handling tests suggest users need to be careful with trailing slashes and ensure the requested paths are valid.

9. **Consolidate and Refine:**  Organize the summarized information logically. Start with a general overview, then delve into specifics. Use clear and concise language. Review the summary for accuracy and completeness against the provided code. Ensure the summary directly addresses all parts of the original prompt.

10. **Address the "Part 2" Instruction:** The prompt specifically mentions "This is part 2". Therefore, the summary should explicitly acknowledge that it's building upon the functionality covered in the (unseen) first part and focus on the *new* features demonstrated here. A concluding sentence summarizing the overall functionality covered by *both* parts would be ideal if the content of part 1 was known. Since it's not, simply acknowledging it's the second part and focusing on the current features suffices.
这是 `go/src/net/http/fs_test.go` 文件第二部分的功能归纳，它主要集中在测试 `net/http` 包中与文件服务相关的更高级和特定的功能，延续了第一部分对基本文件服务的测试。

**功能归纳:**

这部分代码主要测试了 `net/http` 包中 `FileServer` 和 `ServeFile` 函数在处理各种复杂场景下的行为，包括但不限于：

* **条件请求处理:**  测试了服务器如何根据 `If-Modified-Since` 和 `If-Unmodified-Since` 请求头来决定是否返回资源，以及返回的状态码（200 OK, 304 Not Modified, 412 Precondition Failed）。
* **错误处理:** 测试了在文件系统操作发生错误时，服务器如何返回合适的错误状态码（例如 403 Forbidden）和错误信息。
* **Linux `sendfile` 系统调用优化:** 专门针对 Linux 系统测试了 `FileServer` 是否使用了 `sendfile` 系统调用来提高文件传输效率。
* **路径处理和错误:** 测试了当请求路径指向文件内部或不存在的目录时，服务器是否返回正确的 404 Not Found 错误。同时也测试了路径清理 (`CleanPath`) 的行为。
* **`Range` 请求头的处理:**  测试了服务器如何解析和处理 `Range` 请求头，特别是对无效的 `Range` 值的处理，并返回相应的状态码（例如 416 Range Not Satisfiable）。
* **支持的 HTTP 方法:** 测试了 `FileServer` 对多种 HTTP 方法（GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE）的处理，虽然大多数方法返回文件内容（GET）或头部信息（HEAD），但测试了其基本行为。
* **`FileSystem` 接口的使用:** 测试了 `FileServerFS` 和 `ServeFileFS` 函数，它们使用 `fs.FS` 接口来提供文件服务，这使得可以使用不同的文件系统实现。
* **与 `ResponseWriter` 的交互:**  测试了一种可能导致问题的场景，即当 `ResponseWriter` 被包装成会进行额外处理（例如 gzip 压缩）的 writer 时，`ServeFile` 的行为。
* **处理根目录下同名文件和目录:** 测试了当请求根目录时，如果存在一个与目录同名的文件，服务器的错误处理行为。
* **`ServeContent` 函数在错误情况下的头部处理:** 测试了当 `ServeContent` 函数由于 `Range` 请求错误而返回错误时，响应头部的设置情况，以及 `GODEBUG` 环境变量 `httpservecontentkeepheaders` 对保留原有头部的影响。
* **扫描 ETag:** 测试了用于解析 `ETag` 头的内部函数 `scanETag`。

**Go 语言功能实现示例 (条件请求):**

以下代码示例演示了 `FileServer` 如何处理 `If-Modified-Since` 请求头：

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

func main() {
	// 创建一个临时文件
	tmpFile, err := os.CreateTemp("", "example.txt")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tmpFile.Name())
	content := "Hello, world!"
	_, err = tmpFile.WriteString(content)
	if err != nil {
		panic(err)
	}
	err = tmpFile.Close()
	if err != nil {
		panic(err)
	}

	// 获取文件的修改时间
	fileInfo, err := os.Stat(tmpFile.Name())
	if err != nil {
		panic(err)
	}
	modTime := fileInfo.ModTime()

	// 创建一个文件服务器
	fs := http.FileServer(http.Dir("./"))

	// 创建一个测试服务器
	ts := httptest.NewServer(fs)
	defer ts.Close()

	// 创建一个 HTTP 客户端
	client := &http.Client{}

	// 创建一个包含 If-Modified-Since 头的请求 (修改时间之前)
	reqBefore, err := http.NewRequest("GET", ts.URL+"/"+tmpFile.Name(), nil)
	if err != nil {
		panic(err)
	}
	reqBefore.Header.Set("If-Modified-Since", modTime.Add(-1*time.Hour).Format(time.RFC1123))

	respBefore, err := client.Do(reqBefore)
	if err != nil {
		panic(err)
	}
	defer respBefore.Body.Close()

	fmt.Println("状态码 (修改时间之前):", respBefore.StatusCode) // 输出: 状态码 (修改时间之前): 200

	// 创建一个包含 If-Modified-Since 头的请求 (与修改时间相同)
	reqSame, err := http.NewRequest("GET", ts.URL+"/"+tmpFile.Name(), nil)
	if err != nil {
		panic(err)
	}
	reqSame.Header.Set("If-Modified-Since", modTime.Format(time.RFC1123))

	respSame, err := client.Do(reqSame)
	if err != nil {
		panic(err)
	}
	defer respSame.Body.Close()

	fmt.Println("状态码 (与修改时间相同):", respSame.StatusCode) // 输出: 状态码 (与修改时间相同): 304

	// 创建一个包含 If-Modified-Since 头的请求 (修改时间之后)
	reqAfter, err := http.NewRequest("GET", ts.URL+"/"+tmpFile.Name(), nil)
	if err != nil {
		panic(err)
	}
	reqAfter.Header.Set("If-Modified-Since", modTime.Add(1*time.Hour).Format(time.RFC1123))

	respAfter, err := client.Do(reqAfter)
	if err != nil {
		panic(err)
	}
	defer respAfter.Body.Close()

	fmt.Println("状态码 (修改时间之后):", respAfter.StatusCode) // 输出: 状态码 (修改时间之后): 304
}
```

**假设的输入与输出:**

以上代码示例创建了一个名为 `example.txt` 的临时文件，并模拟了三种不同的 `If-Modified-Since` 请求头：

* **输入:**  `If-Modified-Since` 的时间早于文件的实际修改时间。
* **输出:** HTTP 状态码 `200 OK`，表示文件已修改，服务器返回了文件内容。

* **输入:** `If-Modified-Since` 的时间与文件的实际修改时间相同。
* **输出:** HTTP 状态码 `304 Not Modified`，表示文件未修改，服务器没有返回文件内容。

* **输入:** `If-Modified-Since` 的时间晚于文件的实际修改时间。
* **输出:** HTTP 状态码 `304 Not Modified`，因为服务器认为客户端已经拥有了最新的版本。

**命令行参数的具体处理:**

这段代码中并没有直接涉及到处理命令行参数。但是，它使用了 `testing` 包进行单元测试，而 Go 的测试工具 `go test` 可以接受各种命令行参数来控制测试的执行，例如 `-v` (显示详细输出), `-run` (运行特定的测试用例) 等。这些参数是 `go test` 工具提供的，而不是这段代码本身处理的。

此外，代码中还使用了 `t.Setenv("GODEBUG", "httpservecontentkeepheaders=1")` 来设置环境变量 `GODEBUG`，这是一种影响 Go 运行时行为的方式，但不是通过传统的命令行参数传递的。当设置 `httpservecontentkeepheaders=1` 时，即使在发生错误时，`ServeContent` 函数也会尝试保留已设置的响应头。

**使用者易犯错的点:**

基于这段测试代码，使用者在使用 `FileServer` 和 `ServeFile` 时容易犯以下错误：

* **不正确的条件请求头格式:**  `If-Modified-Since` 和 `If-Unmodified-Since` 的时间格式必须符合 RFC1123，否则服务器可能无法正确解析，导致意外的行为。
* **对 `sendfile` 的假设 (Linux 特定):**  依赖于 `sendfile` 的性能优化是平台相关的，不应在跨平台的应用中做出硬性假设。
* **路径遍历漏洞:** 虽然 `FileServer` 提供了基本的保护，但开发者仍然需要注意避免将文件服务器暴露在不受信任的环境中，防止恶意用户通过构造特殊路径来访问不应该访问的文件。
* **错误地修改 `ResponseWriter` 并传递给 `ServeFile`:**  像测试中展示的 `TestServeFileZippingResponseWriter` 例子，在 `ServeFile` 之前对 `ResponseWriter` 进行包装可能会导致 `ServeFile` 无法正确设置 `Content-Length` 等头部信息，特别是在处理范围请求时。
* **对根目录的处理不当:**  当根目录下存在同名文件和目录时，需要理解 `FileServer` 的默认行为，避免出现预料之外的错误。
* **忽略错误处理:**  在自定义的文件系统实现中，需要正确处理 `Open` 和 `Stat` 等方法的错误，否则 `FileServer` 可能会返回不明确的错误信息。

**总结:**

总而言之，这部分 `fs_test.go` 的代码深入测试了 `net/http` 包中文件服务功能的各种边界情况、错误处理、性能优化和特定场景下的行为。它确保了 `FileServer` 和 `ServeFile` 能够在复杂的 HTTP 交互中正确、可靠地工作，并涵盖了条件请求、范围请求、错误处理、平台特定的优化以及与 `FileSystem` 接口的集成等关键方面。 这部分测试也揭示了一些开发者在使用这些功能时可能遇到的陷阱和需要注意的点。

### 提示词
```
这是路径为go/src/net/http/fs_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
us:      200,
			wantContentType: "text/css; charset=utf-8",
			wantLastMod:     htmlModTime.UTC().Format(TimeFormat),
		},
		"if_unmodified_since_false": {
			file:    "testdata/style.css",
			modtime: htmlModTime,
			reqHeader: map[string]string{
				"If-Unmodified-Since": htmlModTime.Add(-2 * time.Second).UTC().Format(TimeFormat),
			},
			wantStatus:  412,
			wantLastMod: htmlModTime.UTC().Format(TimeFormat),
		},
	}
	for testName, tt := range tests {
		var content io.ReadSeeker
		if tt.file != "" {
			f, err := os.Open(tt.file)
			if err != nil {
				t.Fatalf("test %q: %v", testName, err)
			}
			defer f.Close()
			content = f
		} else {
			content = tt.content
		}
		for _, method := range []string{"GET", "HEAD"} {
			//restore content in case it is consumed by previous method
			if content, ok := content.(*strings.Reader); ok {
				content.Seek(0, io.SeekStart)
			}

			servec <- serveParam{
				name:        filepath.Base(tt.file),
				content:     content,
				modtime:     tt.modtime,
				etag:        tt.serveETag,
				contentType: tt.serveContentType,
			}
			req, err := NewRequest(method, ts.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tt.reqHeader {
				req.Header.Set(k, v)
			}

			c := ts.Client()
			res, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != tt.wantStatus {
				t.Errorf("test %q using %q: got status = %d; want %d", testName, method, res.StatusCode, tt.wantStatus)
			}
			if g, e := res.Header.Get("Content-Type"), tt.wantContentType; g != e {
				t.Errorf("test %q using %q: got content-type = %q, want %q", testName, method, g, e)
			}
			if g, e := res.Header.Get("Content-Range"), tt.wantContentRange; g != e {
				t.Errorf("test %q using %q: got content-range = %q, want %q", testName, method, g, e)
			}
			if g, e := res.Header.Get("Last-Modified"), tt.wantLastMod; g != e {
				t.Errorf("test %q using %q: got last-modified = %q, want %q", testName, method, g, e)
			}
		}
	}
}

// Issue 12991
func TestServerFileStatError(t *testing.T) {
	rec := httptest.NewRecorder()
	r, _ := NewRequest("GET", "http://foo/", nil)
	redirect := false
	name := "file.txt"
	fs := issue12991FS{}
	ExportServeFile(rec, r, fs, name, redirect)
	if body := rec.Body.String(); !strings.Contains(body, "403") || !strings.Contains(body, "Forbidden") {
		t.Errorf("wanted 403 forbidden message; got: %s", body)
	}
}

type issue12991FS struct{}

func (issue12991FS) Open(string) (File, error) { return issue12991File{}, nil }

type issue12991File struct{ File }

func (issue12991File) Stat() (fs.FileInfo, error) { return nil, fs.ErrPermission }
func (issue12991File) Close() error               { return nil }

func TestFileServerErrorMessages(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		t.Run("keepheaders=0", func(t *testing.T) {
			testFileServerErrorMessages(t, mode, false)
		})
		t.Run("keepheaders=1", func(t *testing.T) {
			testFileServerErrorMessages(t, mode, true)
		})
	}, testNotParallel)
}
func testFileServerErrorMessages(t *testing.T, mode testMode, keepHeaders bool) {
	if keepHeaders {
		t.Setenv("GODEBUG", "httpservecontentkeepheaders=1")
	}
	fs := fakeFS{
		"/500": &fakeFileInfo{
			err: errors.New("random error"),
		},
		"/403": &fakeFileInfo{
			err: &fs.PathError{Err: fs.ErrPermission},
		},
	}
	server := FileServer(fs)
	h := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", "étude")
		w.Header().Set("Cache-Control", "yes")
		w.Header().Set("Content-Type", "awesome")
		w.Header().Set("Last-Modified", "yesterday")
		server.ServeHTTP(w, r)
	}
	ts := newClientServerTest(t, mode, http.HandlerFunc(h)).ts
	c := ts.Client()
	for _, code := range []int{403, 404, 500} {
		res, err := c.Get(fmt.Sprintf("%s/%d", ts.URL, code))
		if err != nil {
			t.Errorf("Error fetching /%d: %v", code, err)
			continue
		}
		res.Body.Close()
		if res.StatusCode != code {
			t.Errorf("GET /%d: StatusCode = %d; want %d", code, res.StatusCode, code)
		}
		for _, hdr := range []string{"Etag", "Last-Modified", "Cache-Control"} {
			if v, got := res.Header[hdr]; got != keepHeaders {
				want := "not present"
				if keepHeaders {
					want = "present"
				}
				t.Errorf("GET /%d: Header[%q] = %q, want %v", code, hdr, v, want)
			}
		}
	}
}

// verifies that sendfile is being used on Linux
func TestLinuxSendfile(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	if runtime.GOOS != "linux" {
		t.Skip("skipping; linux-only test")
	}
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("skipping; strace not found in path")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lnf, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Attempt to run strace, and skip on failure - this test requires SYS_PTRACE.
	if err := testenv.Command(t, "strace", "-f", "-q", os.Args[0], "-test.run=^$").Run(); err != nil {
		t.Skipf("skipping; failed to run strace: %v", err)
	}

	filename := fmt.Sprintf("1kb-%d", os.Getpid())
	filepath := path.Join(os.TempDir(), filename)

	if err := os.WriteFile(filepath, bytes.Repeat([]byte{'a'}, 1<<10), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filepath)

	var buf strings.Builder
	child := testenv.Command(t, "strace", "-f", "-q", os.Args[0], "-test.run=^TestLinuxSendfileChild$")
	child.ExtraFiles = append(child.ExtraFiles, lnf)
	child.Env = append([]string{"GO_WANT_HELPER_PROCESS=1"}, os.Environ()...)
	child.Stdout = &buf
	child.Stderr = &buf
	if err := child.Start(); err != nil {
		t.Skipf("skipping; failed to start straced child: %v", err)
	}

	res, err := Get(fmt.Sprintf("http://%s/%s", ln.Addr(), filename))
	if err != nil {
		t.Fatalf("http client error: %v", err)
	}
	_, err = io.Copy(io.Discard, res.Body)
	if err != nil {
		t.Fatalf("client body read error: %v", err)
	}
	res.Body.Close()

	// Force child to exit cleanly.
	Post(fmt.Sprintf("http://%s/quit", ln.Addr()), "", nil)
	child.Wait()

	rx := regexp.MustCompile(`\b(n64:)?sendfile(64)?\(`)
	out := buf.String()
	if !rx.MatchString(out) {
		t.Errorf("no sendfile system call found in:\n%s", out)
	}
}

func getBody(t *testing.T, testName string, req Request, client *Client) (*Response, []byte) {
	r, err := client.Do(&req)
	if err != nil {
		t.Fatalf("%s: for URL %q, send error: %v", testName, req.URL.String(), err)
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("%s: for URL %q, reading body: %v", testName, req.URL.String(), err)
	}
	return r, b
}

// TestLinuxSendfileChild isn't a real test. It's used as a helper process
// for TestLinuxSendfile.
func TestLinuxSendfileChild(*testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)
	fd3 := os.NewFile(3, "ephemeral-port-listener")
	ln, err := net.FileListener(fd3)
	if err != nil {
		panic(err)
	}
	mux := NewServeMux()
	mux.Handle("/", FileServer(Dir(os.TempDir())))
	mux.HandleFunc("/quit", func(ResponseWriter, *Request) {
		os.Exit(0)
	})
	s := &Server{Handler: mux}
	err = s.Serve(ln)
	if err != nil {
		panic(err)
	}
}

// Issues 18984, 49552: tests that requests for paths beyond files return not-found errors
func TestFileServerNotDirError(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		t.Run("Dir", func(t *testing.T) {
			testFileServerNotDirError(t, mode, func(path string) FileSystem { return Dir(path) })
		})
		t.Run("FS", func(t *testing.T) {
			testFileServerNotDirError(t, mode, func(path string) FileSystem { return FS(os.DirFS(path)) })
		})
	})
}

func testFileServerNotDirError(t *testing.T, mode testMode, newfs func(string) FileSystem) {
	ts := newClientServerTest(t, mode, FileServer(newfs("testdata"))).ts

	res, err := ts.Client().Get(ts.URL + "/index.html/not-a-file")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Errorf("StatusCode = %v; want 404", res.StatusCode)
	}

	test := func(name string, fsys FileSystem) {
		t.Run(name, func(t *testing.T) {
			_, err = fsys.Open("/index.html/not-a-file")
			if err == nil {
				t.Fatal("err == nil; want != nil")
			}
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("err = %v; errors.Is(err, fs.ErrNotExist) = %v; want true", err,
					errors.Is(err, fs.ErrNotExist))
			}

			_, err = fsys.Open("/index.html/not-a-dir/not-a-file")
			if err == nil {
				t.Fatal("err == nil; want != nil")
			}
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("err = %v; errors.Is(err, fs.ErrNotExist) = %v; want true", err,
					errors.Is(err, fs.ErrNotExist))
			}
		})
	}

	absPath, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal("get abs path:", err)
	}

	test("RelativePath", newfs("testdata"))
	test("AbsolutePath", newfs(absPath))
}

func TestFileServerCleanPath(t *testing.T) {
	tests := []struct {
		path     string
		wantCode int
		wantOpen []string
	}{
		{"/", 200, []string{"/", "/index.html"}},
		{"/dir", 301, []string{"/dir"}},
		{"/dir/", 200, []string{"/dir", "/dir/index.html"}},
	}
	for _, tt := range tests {
		var log []string
		rr := httptest.NewRecorder()
		req, _ := NewRequest("GET", "http://foo.localhost"+tt.path, nil)
		FileServer(fileServerCleanPathDir{&log}).ServeHTTP(rr, req)
		if !slices.Equal(log, tt.wantOpen) {
			t.Logf("For %s: Opens = %q; want %q", tt.path, log, tt.wantOpen)
		}
		if rr.Code != tt.wantCode {
			t.Logf("For %s: Response code = %d; want %d", tt.path, rr.Code, tt.wantCode)
		}
	}
}

type fileServerCleanPathDir struct {
	log *[]string
}

func (d fileServerCleanPathDir) Open(path string) (File, error) {
	*(d.log) = append(*(d.log), path)
	if path == "/" || path == "/dir" || path == "/dir/" {
		// Just return back something that's a directory.
		return Dir(".").Open(".")
	}
	return nil, fs.ErrNotExist
}

type panicOnSeek struct{ io.ReadSeeker }

func TestScanETag(t *testing.T) {
	tests := []struct {
		in         string
		wantETag   string
		wantRemain string
	}{
		{`W/"etag-1"`, `W/"etag-1"`, ""},
		{`"etag-2"`, `"etag-2"`, ""},
		{`"etag-1", "etag-2"`, `"etag-1"`, `, "etag-2"`},
		{"", "", ""},
		{"W/", "", ""},
		{`W/"truc`, "", ""},
		{`w/"case-sensitive"`, "", ""},
		{`"spaced etag"`, "", ""},
	}
	for _, test := range tests {
		etag, remain := ExportScanETag(test.in)
		if etag != test.wantETag || remain != test.wantRemain {
			t.Errorf("scanETag(%q)=%q %q, want %q %q", test.in, etag, remain, test.wantETag, test.wantRemain)
		}
	}
}

// Issue 40940: Ensure that we only accept non-negative suffix-lengths
// in "Range": "bytes=-N", and should reject "bytes=--2".
func TestServeFileRejectsInvalidSuffixLengths(t *testing.T) {
	run(t, testServeFileRejectsInvalidSuffixLengths, []testMode{http1Mode, https1Mode, http2Mode})
}
func testServeFileRejectsInvalidSuffixLengths(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, FileServer(Dir("testdata"))).ts

	tests := []struct {
		r        string
		wantCode int
		wantBody string
	}{
		{"bytes=--6", 416, "invalid range\n"},
		{"bytes=--0", 416, "invalid range\n"},
		{"bytes=---0", 416, "invalid range\n"},
		{"bytes=-6", 206, "hello\n"},
		{"bytes=6-", 206, "html says hello\n"},
		{"bytes=-6-", 416, "invalid range\n"},
		{"bytes=-0", 206, ""},
		{"bytes=", 200, "index.html says hello\n"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.r, func(t *testing.T) {
			req, err := NewRequest("GET", cst.URL+"/index.html", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Range", tt.r)
			res, err := cst.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if g, w := res.StatusCode, tt.wantCode; g != w {
				t.Errorf("StatusCode mismatch: got %d want %d", g, w)
			}
			slurp, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if g, w := string(slurp), tt.wantBody; g != w {
				t.Fatalf("Content mismatch:\nGot:  %q\nWant: %q", g, w)
			}
		})
	}
}

func TestFileServerMethods(t *testing.T) {
	run(t, testFileServerMethods)
}
func testFileServerMethods(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, FileServer(Dir("testdata"))).ts

	file, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatal("reading file:", err)
	}

	// Get contents via various methods.
	//
	// See https://go.dev/issue/59471 for a proposal to limit the set of methods handled.
	// For now, test the historical behavior.
	for _, method := range []string{
		MethodGet,
		MethodHead,
		MethodPost,
		MethodPut,
		MethodPatch,
		MethodDelete,
		MethodOptions,
		MethodTrace,
	} {
		req, _ := NewRequest(method, ts.URL+"/file", nil)
		t.Log(req.URL)
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		wantBody := file
		if method == MethodHead {
			wantBody = nil
		}
		if !bytes.Equal(body, wantBody) {
			t.Fatalf("%v: got body %q, want %q", method, body, wantBody)
		}
		if got, want := res.Header.Get("Content-Length"), fmt.Sprint(len(file)); got != want {
			t.Fatalf("%v: got Content-Length %q, want %q", method, got, want)
		}
	}
}

func TestFileServerFS(t *testing.T) {
	filename := "index.html"
	contents := []byte("index.html says hello")
	fsys := fstest.MapFS{
		filename: {Data: contents},
	}
	ts := newClientServerTest(t, http1Mode, FileServerFS(fsys)).ts
	defer ts.Close()

	res, err := ts.Client().Get(ts.URL + "/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal("reading Body:", err)
	}
	if s := string(b); s != string(contents) {
		t.Errorf("for path %q got %q, want %q", filename, s, contents)
	}
	res.Body.Close()
}

func TestServeFileFS(t *testing.T) {
	filename := "index.html"
	contents := []byte("index.html says hello")
	fsys := fstest.MapFS{
		filename: {Data: contents},
	}
	ts := newClientServerTest(t, http1Mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		ServeFileFS(w, r, fsys, filename)
	})).ts
	defer ts.Close()

	res, err := ts.Client().Get(ts.URL + "/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal("reading Body:", err)
	}
	if s := string(b); s != string(contents) {
		t.Errorf("for path %q got %q, want %q", filename, s, contents)
	}
	res.Body.Close()
}

func TestServeFileZippingResponseWriter(t *testing.T) {
	// This test exercises a pattern which is incorrect,
	// but has been observed enough in the world that we don't want to break it.
	//
	// The server is setting "Content-Encoding: gzip",
	// wrapping the ResponseWriter in an implementation which gzips data written to it,
	// and passing this ResponseWriter to ServeFile.
	//
	// This means ServeFile cannot properly set a Content-Length header, because it
	// doesn't know what content it is going to send--the ResponseWriter is modifying
	// the bytes sent.
	//
	// Range requests are always going to be broken in this scenario,
	// but verify that we can serve non-range requests correctly.
	filename := "index.html"
	contents := []byte("contents will be sent with Content-Encoding: gzip")
	fsys := fstest.MapFS{
		filename: {Data: contents},
	}
	ts := newClientServerTest(t, http1Mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gzw := gzip.NewWriter(w)
		defer gzw.Close()
		ServeFileFS(gzipResponseWriter{w: gzw, ResponseWriter: w}, r, fsys, filename)
	})).ts
	defer ts.Close()

	res, err := ts.Client().Get(ts.URL + "/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal("reading Body:", err)
	}
	if s := string(b); s != string(contents) {
		t.Errorf("for path %q got %q, want %q", filename, s, contents)
	}
	res.Body.Close()
}

type gzipResponseWriter struct {
	ResponseWriter
	w *gzip.Writer
}

func (grw gzipResponseWriter) Write(b []byte) (int, error) {
	return grw.w.Write(b)
}

func (grw gzipResponseWriter) Flush() {
	grw.w.Flush()
	if fw, ok := grw.ResponseWriter.(http.Flusher); ok {
		fw.Flush()
	}
}

// Issue 63769
func TestFileServerDirWithRootFile(t *testing.T) { run(t, testFileServerDirWithRootFile) }
func testFileServerDirWithRootFile(t *testing.T, mode testMode) {
	testDirFile := func(t *testing.T, h Handler) {
		ts := newClientServerTest(t, mode, h).ts
		defer ts.Close()

		res, err := ts.Client().Get(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		if g, w := res.StatusCode, StatusInternalServerError; g != w {
			t.Errorf("StatusCode mismatch: got %d, want: %d", g, w)
		}
		res.Body.Close()
	}

	t.Run("FileServer", func(t *testing.T) {
		testDirFile(t, FileServer(Dir("testdata/index.html")))
	})

	t.Run("FileServerFS", func(t *testing.T) {
		testDirFile(t, FileServerFS(os.DirFS("testdata/index.html")))
	})
}

func TestServeContentHeadersWithError(t *testing.T) {
	t.Run("keepheaders=0", func(t *testing.T) {
		testServeContentHeadersWithError(t, false)
	})
	t.Run("keepheaders=1", func(t *testing.T) {
		testServeContentHeadersWithError(t, true)
	})
}
func testServeContentHeadersWithError(t *testing.T, keepHeaders bool) {
	if keepHeaders {
		t.Setenv("GODEBUG", "httpservecontentkeepheaders=1")
	}
	contents := []byte("content")
	ts := newClientServerTest(t, http1Mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(contents)))
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Etag", `"abcdefgh"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.Header().Set("Cache-Control", "immutable")
		w.Header().Set("Other-Header", "test")
		ServeContent(w, r, "", time.Time{}, bytes.NewReader(contents))
	})).ts
	defer ts.Close()

	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=100-10000")

	c := ts.Client()
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	out, _ := io.ReadAll(res.Body)
	res.Body.Close()

	ifKept := func(s string) string {
		if keepHeaders {
			return s
		}
		return ""
	}
	if g, e := res.StatusCode, 416; g != e {
		t.Errorf("got status = %d; want %d", g, e)
	}
	if g, e := string(out), "invalid range: failed to overlap\n"; g != e {
		t.Errorf("got body = %q; want %q", g, e)
	}
	if g, e := res.Header.Get("Content-Type"), "text/plain; charset=utf-8"; g != e {
		t.Errorf("got content-type = %q, want %q", g, e)
	}
	if g, e := res.Header.Get("Content-Length"), strconv.Itoa(len(out)); g != e {
		t.Errorf("got content-length = %q, want %q", g, e)
	}
	if g, e := res.Header.Get("Content-Encoding"), ifKept("gzip"); g != e {
		t.Errorf("got content-encoding = %q, want %q", g, e)
	}
	if g, e := res.Header.Get("Etag"), ifKept(`"abcdefgh"`); g != e {
		t.Errorf("got etag = %q, want %q", g, e)
	}
	if g, e := res.Header.Get("Last-Modified"), ifKept("Wed, 21 Oct 2015 07:28:00 GMT"); g != e {
		t.Errorf("got last-modified = %q, want %q", g, e)
	}
	if g, e := res.Header.Get("Cache-Control"), ifKept("immutable"); g != e {
		t.Errorf("got cache-control = %q, want %q", g, e)
	}
	if g, e := res.Header.Get("Content-Range"), "bytes */7"; g != e {
		t.Errorf("got content-range = %q, want %q", g, e)
	}
	if g, e := res.Header.Get("Other-Header"), "test"; g != e {
		t.Errorf("got other-header = %q, want %q", g, e)
	}
}
```