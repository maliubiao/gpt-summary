Response:
Let's break down the thought process for answering the request about the `host.go` file.

1. **Understanding the Core Request:** The primary goal is to analyze the provided Go code snippet, specifically from `go/src/net/http/cgi/host.go`, and explain its functionality. The request has several sub-requirements: listing features, inferring the Go feature it implements, providing code examples, explaining command-line parameter handling (if applicable), and highlighting common mistakes.

2. **Initial Code Scan and Identification of the Package:** The first few lines clearly indicate the package is `cgi` and that it implements the "host side of CGI". This is a crucial starting point. The comments also mention RFC 3875, which defines CGI.

3. **Identifying Key Structures and Functions:**  A quick scan reveals the central structure `Handler`. The `ServeHTTP` method is the obvious entry point for handling HTTP requests, given the context of `net/http`. Other important functions to note are `stderr`, `removeLeadingDuplicates`, `printf`, and `handleInternalRedirect`.

4. **Deciphering `Handler`'s Role:** The fields within `Handler` (like `Path`, `Root`, `Dir`, `Env`, `InheritEnv`, etc.) provide strong hints about its purpose. It seems designed to configure and execute a CGI script.

5. **Analyzing `ServeHTTP`'s Logic (Step-by-Step):** This is the heart of the functionality. I'd go through the code block by block:

    * **Chunked Request Check:**  The initial check for chunked transfer encoding indicates a limitation of this CGI implementation.
    * **Path Information Extraction:** The code calculates `pathInfo` and `root`, showing how the URL is parsed to determine the script to execute.
    * **Environment Variable Construction:**  This is a major part of the function. The code meticulously builds the CGI environment variables according to the CGI specification (SERVER_SOFTWARE, SERVER_PROTOCOL, etc.). Pay close attention to how HTTP headers are converted to `HTTP_` prefixed environment variables.
    * **Inherited Environment Variables:** The `InheritEnv` and `osDefaultInheritEnv` fields show how environment variables from the parent process are passed down.
    * **Duplicate Environment Variable Removal:** The `removeLeadingDuplicates` function is interesting and suggests a specific scenario where users might define the same environment variable multiple times.
    * **Command Execution (`exec.Cmd`):** The core of the CGI execution. It shows how the CGI script is launched as a subprocess with the constructed environment.
    * **Capturing Output:**  The code uses `StdoutPipe` to capture the output of the CGI script.
    * **Header Parsing:**  The loop reading from `linebody` clearly parses the HTTP headers returned by the CGI script. The logic for handling the "Status" header is important.
    * **Internal Redirect Handling:** The `handleInternalRedirect` function reveals how the CGI script can trigger internal redirects within the Go server.
    * **Response Writing:** The final part of `ServeHTTP` writes the headers and body back to the client.

6. **Inferring the Go Feature:** Based on the functionality of `Handler` and `ServeHTTP`, it's evident that this code implements the `http.Handler` interface. This is a fundamental building block for handling HTTP requests in Go.

7. **Creating Code Examples:** To illustrate the functionality, I would create a simple Go HTTP server example that uses the `cgi.Handler`. A basic CGI script (`hello.cgi`) is needed to demonstrate the interaction. The example should cover setting up the `Handler`, registering it with the HTTP server, and showcasing how the CGI script's output is returned to the client. It's good to include both a successful and a potentially error-prone scenario (like a missing Content-Type).

8. **Analyzing Command-Line Parameters:**  The `cgi.Handler` itself doesn't directly process command-line arguments *for the Go server*. However, it *passes* arguments to the CGI script through the `Args` field. This distinction is crucial.

9. **Identifying Common Mistakes:** Think about the common pitfalls when working with CGI:

    * **Missing `Content-Type`:**  A classic CGI error.
    * **Incorrect Permissions:**  The CGI script needs to be executable.
    * **Path Issues:**  The `Path` to the CGI script must be correct.
    * **Environment Variable Conflicts:** Understanding how `Env` and `InheritEnv` interact is important.
    * **Chunked Encoding:** The code explicitly rejects chunked requests.

10. **Structuring the Answer:**  Organize the information logically using the headings provided in the request. Use clear and concise language. Provide code examples that are easy to understand and runnable.

11. **Review and Refine:**  Read through the answer to ensure accuracy, completeness, and clarity. Double-check code examples for correctness.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Maybe the `Args` field of `Handler` directly relates to command-line arguments of the Go server.
* **Correction:** Realized that `Args` is for the *CGI script*, not the Go server itself. This clarifies the explanation of command-line parameters.
* **Initial Thought:**  Focus only on successful CGI execution.
* **Refinement:**  Recognized the importance of demonstrating error scenarios (missing Content-Type) and common pitfalls.
* **Initial Thought:** Briefly mention the implemented Go feature.
* **Refinement:** Explicitly state that `cgi.Handler` implements the `http.Handler` interface and explain its significance.

By following these steps and continually refining the understanding of the code, a comprehensive and accurate answer to the request can be constructed.
这段Go语言代码是 `net/http/cgi` 包中用于处理 CGI（Common Gateway Interface）请求的核心部分。它实现了 Web 服务器作为父进程，启动 CGI 脚本作为子进程来处理 HTTP 请求的功能。

**功能列举:**

1. **处理 HTTP 请求:** `Handler` 结构体实现了 `http.Handler` 接口，可以作为 Go HTTP 服务器的处理器来处理客户端的 HTTP 请求。
2. **执行 CGI 脚本:**  `Handler` 结构体定义了执行 CGI 脚本所需的配置信息，例如脚本路径 (`Path`)、工作目录 (`Dir`)、环境变量 (`Env`, `InheritEnv`)、以及传递给脚本的参数 (`Args`)。
3. **构建 CGI 环境变量:**  `ServeHTTP` 方法负责根据 HTTP 请求构建符合 CGI 标准的环境变量，例如 `SERVER_SOFTWARE`, `SERVER_PROTOCOL`, `REQUEST_METHOD`, `QUERY_STRING` 等。它还会将 HTTP 请求头转换为以 `HTTP_` 为前缀的环境变量。
4. **管理子进程:**  代码使用 `os/exec` 包来启动 CGI 脚本作为子进程，并管理其输入、输出和错误流。
5. **传递请求体:**  如果 HTTP 请求包含请求体（例如 POST 请求），则将其传递给 CGI 子进程的标准输入。
6. **解析 CGI 脚本的输出:**  代码读取 CGI 脚本的标准输出，解析其中的 HTTP 响应头（例如 `Status`, `Content-Type`, `Location` 等）。
7. **处理内部重定向:** 如果 CGI 脚本返回以 `/` 开头的 `Location` 头，并且 `Handler` 结构体的 `PathLocationHandler` 字段不为空，则会进行内部重定向，将该请求交由 `PathLocationHandler` 处理。
8. **将响应返回给客户端:**  `ServeHTTP` 方法将解析后的 HTTP 响应头和响应体返回给客户端。
9. **错误处理和日志记录:** 代码包含了错误处理逻辑，例如处理过长的头部行、读取头部错误等，并可以通过 `Logger` 字段记录错误信息。
10. **处理继承的环境变量:**  `InheritEnv` 字段允许指定需要从父进程继承的环境变量，`osDefaultInheritEnv` 定义了不同操作系统默认需要继承的环境变量。
11. **移除重复的环境变量:** `removeLeadingDuplicates` 函数用于移除重复定义的环境变量，避免用户通过 `Env` 字段覆盖已设置的环境变量。

**实现的 Go 语言功能:**

这个代码主要实现了 `net/http` 包中的 `http.Handler` 接口，使得 `cgi.Handler` 能够作为 HTTP 请求的处理器。它还利用了 `os/exec` 包来执行外部命令（CGI 脚本）。

**Go 代码举例说明:**

假设我们有一个简单的 CGI 脚本 `hello.cgi` (可以是 Python, Shell 等):

```python
#!/usr/bin/env python
print("Content-Type: text/plain")
print("")
print("Hello, CGI!")
```

并将其放置在 `/var/www/cgi-bin/` 目录下，并赋予执行权限 (`chmod +x /var/www/cgi-bin/hello.cgi`)。

以下是如何在 Go 中使用 `cgi.Handler` 来处理对这个 CGI 脚本的请求：

```go
package main

import (
	"log"
	"net/http"
	"net/http/cgi"
)

func main() {
	// 创建 CGI Handler
	handler := &cgi.Handler{
		Path: "/var/www/cgi-bin/hello.cgi",
		Root: "/cgi-bin", // 可选，表示 CGI 脚本的根路径
	}

	// 创建 HTTP 服务器
	mux := http.NewServeMux()
	mux.Handle("/cgi-bin/", handler) // 将以 /cgi-bin/ 开头的请求交给 CGI Handler 处理

	// 启动 HTTP 服务器
	log.Println("启动服务器在 :8080")
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("ListenAndServe error: ", err)
	}
}
```

**假设的输入与输出:**

假设客户端发起以下 HTTP 请求：

```
GET /cgi-bin/hello.cgi HTTP/1.1
Host: localhost:8080
```

**输入 (对于 `ServeHTTP` 方法):**

* `rw`:  一个实现了 `http.ResponseWriter` 接口的对象，用于将响应写回客户端。
* `req`:  一个指向 `http.Request` 结构体的指针，包含了客户端的请求信息，例如 URL、方法、头部等。

**输出 (CGI 脚本 `hello.cgi` 的标准输出):**

```
Content-Type: text/plain

Hello, CGI!
```

**输出 (Go 服务器返回给客户端的 HTTP 响应):**

```
HTTP/1.1 200 OK
Content-Type: text/plain

Hello, CGI!
```

**代码推理:**

在 `ServeHTTP` 方法中，当接收到请求后，会执行以下关键步骤：

1. **构建环境变量:**  会生成类似以下的环境变量：
   ```
   SERVER_SOFTWARE=go
   SERVER_PROTOCOL=HTTP/1.1
   HTTP_HOST=localhost:8080
   GATEWAY_INTERFACE=CGI/1.1
   REQUEST_METHOD=GET
   QUERY_STRING=
   REQUEST_URI=/cgi-bin/hello.cgi
   PATH_INFO=/hello.cgi
   SCRIPT_NAME=/cgi-bin
   SCRIPT_FILENAME=/var/www/cgi-bin/hello.cgi
   SERVER_PORT=8080
   REMOTE_ADDR=... // 客户端 IP 地址
   REMOTE_HOST=... // 客户端 IP 地址
   SERVER_NAME=localhost
   PATH=/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin  // 默认 PATH
   // ... 其他继承的环境变量
   ```

2. **执行 CGI 脚本:**  使用 `exec.Command` 启动 `/var/www/cgi-bin/hello.cgi` 子进程，并将上述环境变量传递给它。

3. **解析输出:**  读取 `hello.cgi` 的标准输出，解析出 `Content-Type: text/plain` 头部和一个空行，然后是响应体 `Hello, CGI!`。

4. **返回响应:**  Go 服务器构建 HTTP 响应，设置 `Content-Type` 头部为 `text/plain`，并将响应体设置为 `Hello, CGI!`。

**命令行参数的具体处理:**

`cgi.Handler` 本身不直接处理 Go 服务器的命令行参数。但是，`Handler` 结构体的 `Args` 字段允许你指定在执行 CGI 脚本时传递给它的命令行参数。

例如，如果你的 `Handler` 定义如下：

```go
handler := &cgi.Handler{
    Path: "/var/www/cgi-bin/my_script.sh",
    Args: []string{"--option", "value", "another_arg"},
}
```

当处理请求时，Go 会执行类似于以下的命令：

```bash
/var/www/cgi-bin/my_script.sh --option value another_arg
```

CGI 脚本可以通过标准的环境变量（例如 `$1`, `$2` 等在 Shell 脚本中）或通过解析命令行参数的方式来访问这些参数。

**使用者易犯错的点:**

1. **CGI 脚本没有执行权限:**  如果 CGI 脚本没有设置执行权限，Go 将无法启动它，并会返回错误。

   **例子:** 忘记执行 `chmod +x /var/www/cgi-bin/hello.cgi`。

2. **`Path` 配置错误:**  `Handler.Path` 必须指向实际存在的 CGI 脚本的绝对路径。如果路径不正确，会导致 "file not found" 或类似的错误。

   **例子:**  将 `Path` 设置为 `"./hello.cgi"`，但当前工作目录不是 `/var/www/cgi-bin/`。

3. **CGI 脚本没有输出正确的 HTTP 头部:**  CGI 脚本必须至少输出 `Content-Type` 头部，并在头部和响应体之间有一个空行。如果缺少这些，Go 服务器可能会返回 500 错误或无法正确解析响应。

   **例子:**  CGI 脚本忘记输出 `Content-Type: text/plain`。

4. **处理 POST 请求时未读取标准输入:** 如果 CGI 脚本需要处理 POST 请求中的数据，它需要从标准输入中读取数据。如果脚本没有这样做，数据将会丢失。

   **例子:** 一个处理表单提交的 CGI 脚本没有读取 `os.Stdin`。

5. **内部重定向的误用:**  如果 `PathLocationHandler` 没有正确配置，或者 CGI 脚本返回了错误的本地 URI 路径，可能会导致内部重定向失败或进入循环。

   **例子:** `PathLocationHandler` 为 `nil`，但 CGI 脚本返回 `Location: /another/page`，客户端将收到重定向响应而不是内部处理。

6. **环境变量的覆盖和继承理解不当:**  用户可能会错误地认为 `Env` 中的设置会覆盖所有已存在的环境变量，或者不理解 `InheritEnv` 的作用。

   **例子:** 用户在 `Env` 中设置了 `PATH`，但没有包含必要的路径，导致 CGI 脚本无法找到依赖的程序。

7. **CGI 脚本长时间运行或崩溃:**  如果 CGI 脚本运行时间过长或崩溃，可能会导致 Go 服务器的资源被占用，甚至导致服务器无响应。

理解这些常见错误可以帮助开发者更好地使用 `net/http/cgi` 包来集成现有的 CGI 应用。

Prompt: 
```
这是路径为go/src/net/http/cgi/host.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements the host side of CGI (being the webserver
// parent process).

// Package cgi implements CGI (Common Gateway Interface) as specified
// in RFC 3875.
//
// Note that using CGI means starting a new process to handle each
// request, which is typically less efficient than using a
// long-running server. This package is intended primarily for
// compatibility with existing systems.
package cgi

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

var trailingPort = regexp.MustCompile(`:([0-9]+)$`)

var osDefaultInheritEnv = func() []string {
	switch runtime.GOOS {
	case "darwin", "ios":
		return []string{"DYLD_LIBRARY_PATH"}
	case "android", "linux", "freebsd", "netbsd", "openbsd":
		return []string{"LD_LIBRARY_PATH"}
	case "hpux":
		return []string{"LD_LIBRARY_PATH", "SHLIB_PATH"}
	case "irix":
		return []string{"LD_LIBRARY_PATH", "LD_LIBRARYN32_PATH", "LD_LIBRARY64_PATH"}
	case "illumos", "solaris":
		return []string{"LD_LIBRARY_PATH", "LD_LIBRARY_PATH_32", "LD_LIBRARY_PATH_64"}
	case "windows":
		return []string{"SystemRoot", "COMSPEC", "PATHEXT", "WINDIR"}
	}
	return nil
}()

// Handler runs an executable in a subprocess with a CGI environment.
type Handler struct {
	Path string // path to the CGI executable
	Root string // root URI prefix of handler or empty for "/"

	// Dir specifies the CGI executable's working directory.
	// If Dir is empty, the base directory of Path is used.
	// If Path has no base directory, the current working
	// directory is used.
	Dir string

	Env        []string    // extra environment variables to set, if any, as "key=value"
	InheritEnv []string    // environment variables to inherit from host, as "key"
	Logger     *log.Logger // optional log for errors or nil to use log.Print
	Args       []string    // optional arguments to pass to child process
	Stderr     io.Writer   // optional stderr for the child process; nil means os.Stderr

	// PathLocationHandler specifies the root http Handler that
	// should handle internal redirects when the CGI process
	// returns a Location header value starting with a "/", as
	// specified in RFC 3875 § 6.3.2. This will likely be
	// http.DefaultServeMux.
	//
	// If nil, a CGI response with a local URI path is instead sent
	// back to the client and not redirected internally.
	PathLocationHandler http.Handler
}

func (h *Handler) stderr() io.Writer {
	if h.Stderr != nil {
		return h.Stderr
	}
	return os.Stderr
}

// removeLeadingDuplicates remove leading duplicate in environments.
// It's possible to override environment like following.
//
//	cgi.Handler{
//	  ...
//	  Env: []string{"SCRIPT_FILENAME=foo.php"},
//	}
func removeLeadingDuplicates(env []string) (ret []string) {
	for i, e := range env {
		found := false
		if eq := strings.IndexByte(e, '='); eq != -1 {
			keq := e[:eq+1] // "key="
			for _, e2 := range env[i+1:] {
				if strings.HasPrefix(e2, keq) {
					found = true
					break
				}
			}
		}
		if !found {
			ret = append(ret, e)
		}
	}
	return
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Chunked request bodies are not supported by CGI."))
		return
	}

	root := strings.TrimRight(h.Root, "/")
	pathInfo := strings.TrimPrefix(req.URL.Path, root)

	port := "80"
	if req.TLS != nil {
		port = "443"
	}
	if matches := trailingPort.FindStringSubmatch(req.Host); len(matches) != 0 {
		port = matches[1]
	}

	env := []string{
		"SERVER_SOFTWARE=go",
		"SERVER_PROTOCOL=HTTP/1.1",
		"HTTP_HOST=" + req.Host,
		"GATEWAY_INTERFACE=CGI/1.1",
		"REQUEST_METHOD=" + req.Method,
		"QUERY_STRING=" + req.URL.RawQuery,
		"REQUEST_URI=" + req.URL.RequestURI(),
		"PATH_INFO=" + pathInfo,
		"SCRIPT_NAME=" + root,
		"SCRIPT_FILENAME=" + h.Path,
		"SERVER_PORT=" + port,
	}

	if remoteIP, remotePort, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		env = append(env, "REMOTE_ADDR="+remoteIP, "REMOTE_HOST="+remoteIP, "REMOTE_PORT="+remotePort)
	} else {
		// could not parse ip:port, let's use whole RemoteAddr and leave REMOTE_PORT undefined
		env = append(env, "REMOTE_ADDR="+req.RemoteAddr, "REMOTE_HOST="+req.RemoteAddr)
	}

	if hostDomain, _, err := net.SplitHostPort(req.Host); err == nil {
		env = append(env, "SERVER_NAME="+hostDomain)
	} else {
		env = append(env, "SERVER_NAME="+req.Host)
	}

	if req.TLS != nil {
		env = append(env, "HTTPS=on")
	}

	for k, v := range req.Header {
		k = strings.Map(upperCaseAndUnderscore, k)
		if k == "PROXY" {
			// See Issue 16405
			continue
		}
		joinStr := ", "
		if k == "COOKIE" {
			joinStr = "; "
		}
		env = append(env, "HTTP_"+k+"="+strings.Join(v, joinStr))
	}

	if req.ContentLength > 0 {
		env = append(env, fmt.Sprintf("CONTENT_LENGTH=%d", req.ContentLength))
	}
	if ctype := req.Header.Get("Content-Type"); ctype != "" {
		env = append(env, "CONTENT_TYPE="+ctype)
	}

	envPath := os.Getenv("PATH")
	if envPath == "" {
		envPath = "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin"
	}
	env = append(env, "PATH="+envPath)

	for _, e := range h.InheritEnv {
		if v := os.Getenv(e); v != "" {
			env = append(env, e+"="+v)
		}
	}

	for _, e := range osDefaultInheritEnv {
		if v := os.Getenv(e); v != "" {
			env = append(env, e+"="+v)
		}
	}

	if h.Env != nil {
		env = append(env, h.Env...)
	}

	env = removeLeadingDuplicates(env)

	var cwd, path string
	if h.Dir != "" {
		path = h.Path
		cwd = h.Dir
	} else {
		cwd, path = filepath.Split(h.Path)
	}
	if cwd == "" {
		cwd = "."
	}

	internalError := func(err error) {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("CGI error: %v", err)
	}

	cmd := &exec.Cmd{
		Path:   path,
		Args:   append([]string{h.Path}, h.Args...),
		Dir:    cwd,
		Env:    env,
		Stderr: h.stderr(),
	}
	if req.ContentLength != 0 {
		cmd.Stdin = req.Body
	}
	stdoutRead, err := cmd.StdoutPipe()
	if err != nil {
		internalError(err)
		return
	}

	err = cmd.Start()
	if err != nil {
		internalError(err)
		return
	}
	if hook := testHookStartProcess; hook != nil {
		hook(cmd.Process)
	}
	defer cmd.Wait()
	defer stdoutRead.Close()

	linebody := bufio.NewReaderSize(stdoutRead, 1024)
	headers := make(http.Header)
	statusCode := 0
	headerLines := 0
	sawBlankLine := false
	for {
		line, isPrefix, err := linebody.ReadLine()
		if isPrefix {
			rw.WriteHeader(http.StatusInternalServerError)
			h.printf("cgi: long header line from subprocess.")
			return
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			h.printf("cgi: error reading headers: %v", err)
			return
		}
		if len(line) == 0 {
			sawBlankLine = true
			break
		}
		headerLines++
		header, val, ok := strings.Cut(string(line), ":")
		if !ok {
			h.printf("cgi: bogus header line: %s", line)
			continue
		}
		if !httpguts.ValidHeaderFieldName(header) {
			h.printf("cgi: invalid header name: %q", header)
			continue
		}
		val = textproto.TrimString(val)
		switch {
		case header == "Status":
			if len(val) < 3 {
				h.printf("cgi: bogus status (short): %q", val)
				return
			}
			code, err := strconv.Atoi(val[0:3])
			if err != nil {
				h.printf("cgi: bogus status: %q", val)
				h.printf("cgi: line was %q", line)
				return
			}
			statusCode = code
		default:
			headers.Add(header, val)
		}
	}
	if headerLines == 0 || !sawBlankLine {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("cgi: no headers")
		return
	}

	if loc := headers.Get("Location"); loc != "" {
		if strings.HasPrefix(loc, "/") && h.PathLocationHandler != nil {
			h.handleInternalRedirect(rw, req, loc)
			return
		}
		if statusCode == 0 {
			statusCode = http.StatusFound
		}
	}

	if statusCode == 0 && headers.Get("Content-Type") == "" {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("cgi: missing required Content-Type in headers")
		return
	}

	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	// Copy headers to rw's headers, after we've decided not to
	// go into handleInternalRedirect, which won't want its rw
	// headers to have been touched.
	for k, vv := range headers {
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}

	rw.WriteHeader(statusCode)

	_, err = io.Copy(rw, linebody)
	if err != nil {
		h.printf("cgi: copy error: %v", err)
		// And kill the child CGI process so we don't hang on
		// the deferred cmd.Wait above if the error was just
		// the client (rw) going away. If it was a read error
		// (because the child died itself), then the extra
		// kill of an already-dead process is harmless (the PID
		// won't be reused until the Wait above).
		cmd.Process.Kill()
	}
}

func (h *Handler) printf(format string, v ...any) {
	if h.Logger != nil {
		h.Logger.Printf(format, v...)
	} else {
		log.Printf(format, v...)
	}
}

func (h *Handler) handleInternalRedirect(rw http.ResponseWriter, req *http.Request, path string) {
	url, err := req.URL.Parse(path)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("cgi: error resolving local URI path %q: %v", path, err)
		return
	}
	// TODO: RFC 3875 isn't clear if only GET is supported, but it
	// suggests so: "Note that any message-body attached to the
	// request (such as for a POST request) may not be available
	// to the resource that is the target of the redirect."  We
	// should do some tests against Apache to see how it handles
	// POST, HEAD, etc. Does the internal redirect get the same
	// method or just GET? What about incoming headers?
	// (e.g. Cookies) Which headers, if any, are copied into the
	// second request?
	newReq := &http.Request{
		Method:     "GET",
		URL:        url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       url.Host,
		RemoteAddr: req.RemoteAddr,
		TLS:        req.TLS,
	}
	h.PathLocationHandler.ServeHTTP(rw, newReq)
}

func upperCaseAndUnderscore(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z':
		return r - ('a' - 'A')
	case r == '-':
		return '_'
	case r == '=':
		// Maybe not part of the CGI 'spec' but would mess up
		// the environment in any case, as Go represents the
		// environment as a slice of "key=value" strings.
		return '_'
	}
	// TODO: other transformations in spec or practice?
	return r
}

var testHookStartProcess func(*os.Process) // nil except for some tests

"""



```