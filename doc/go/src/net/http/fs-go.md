Response:
Let's break down the thought process for summarizing the provided Go code snippet.

**1. Initial Understanding and Goal:**

The request asks for a summary of the functionality of the provided Go code, which is a part of `net/http/fs.go`. The specific request is for "Part 1" of the code. The core goal is to identify the main functionalities implemented in this section.

**2. High-Level Scan and Keyword Spotting:**

I first skim the code, looking for recognizable HTTP-related terms and data structures. Keywords like `http`, `FileSystem`, `File`, `ResponseWriter`, `Request`, `ServeFile`, `ServeContent`, `Range`, `ETag`, `Last-Modified`, `Content-Type`, `multipart`, `Dir`, and function names like `Open`, `Stat`, `Readdir`, `ServeHTTP` immediately jump out. These indicate the code is about serving files over HTTP.

**3. Identifying Core Data Structures and Interfaces:**

I then focus on the key data structures and interfaces defined in the snippet:

* **`Dir`:**  This clearly represents a directory on the local file system that can be served.
* **`FileSystem`:** This is an interface for accessing named files. The comment explicitly mentions it predates `fs.FS`.
* **`File`:** This is an interface representing an individual file that can be served. The comment links its methods to `os.File`.

Understanding these foundational types is crucial for understanding the overall functionality.

**4. Analyzing Key Functions and Methods:**

Next, I analyze the purpose of the most important functions and methods:

* **`Dir.Open()`:**  This method implements the `FileSystem` interface for the `Dir` type. It opens a file relative to the directory represented by `Dir`. The code emphasizes security considerations regarding symlinks and hidden files.
* **`ServeContent()`:** This function is central to serving the actual file content. It handles range requests, MIME type detection, conditional requests (using `If-Match`, `If-Modified-Since`, etc.), and sets relevant headers.
* **`serveFile()`:** This function orchestrates the process of serving a file or directory. It handles redirects for directories, looks for `index.html`, and calls `ServeContent` for actual file serving.
* **`FileServer()` and `FileServerFS()`:** These functions create HTTP handlers that use either a `FileSystem` interface or an `fs.FS` interface to serve files.
* **`ServeHTTP()` (on `fileHandler`):** This is the entry point for handling HTTP requests when using `FileServer`. It maps the request path to a file within the configured `FileSystem`.
* **Helper functions:**  Functions like `parseRange`, `checkPreconditions`, `setLastModified`, `writeNotModified`, `toHTTPError`, and the ETag-related functions support the core functionality by handling specific HTTP features.

**5. Grouping Functionality:**

As I analyze the functions, I start grouping them by their logical purpose:

* **File System Abstraction:** `Dir`, `FileSystem`, `File`, `FS`, `ioFS`, `ioFile`, `mapOpenError`. These are about representing and accessing files.
* **Serving Files:** `ServeContent`, `serveFile`, `FileServer`, `FileServerFS`, `fileHandler.ServeHTTP`. These are the core functions for responding to HTTP requests with file content.
* **HTTP Features:**  Functions related to range requests (`parseRange`, `httpRange`, `rangesMIMESize`), conditional requests (`checkPreconditions`, `checkIfMatch`, `checkIfNoneMatch`, etc.), content type detection (`DetectContentType`, using file extensions), and header manipulation (`setLastModified`).
* **Error Handling and Redirection:** `serveError`, `toHTTPError`, `localRedirect`.

**6. Formulating the Summary (Iterative Refinement):**

Based on the identified functionalities, I start drafting the summary. I aim for clarity and conciseness.

* **Initial Draft:** "This code is part of Go's `net/http` package and deals with serving files over HTTP. It provides ways to serve files from the local file system or an abstract `fs.FS`. It handles things like range requests, setting content types, and checking preconditions like `If-Modified-Since`."

* **Adding More Detail:** I then expand on the initial draft, incorporating the key data structures and functions: "This Go code implements the functionality for serving files over HTTP. It defines interfaces like `FileSystem` and `File` for abstracting file access. The `Dir` type allows serving files from a specific directory on the local file system. Key functions include `ServeContent` for handling the actual file data transfer, including range requests and content negotiation, and `ServeFile` for locating and serving files or directories. `FileServer` creates an HTTP handler to serve files."

* **Refining for Conciseness and Accuracy:** I refine the language and ensure accuracy:  "这段 Go 代码是 `net/http` 包的一部分，主要负责处理 HTTP 文件服务相关的逻辑。它定义了 `FileSystem` 和 `File` 接口，用于抽象文件系统的操作。`Dir` 类型实现了 `FileSystem` 接口，允许将本地文件系统中的特定目录作为静态资源对外提供服务。核心功能包括：`ServeContent` 用于处理文件内容的传输，支持 Range 请求，并根据文件扩展名或内容进行 MIME 类型检测；`ServeFile` 用于根据请求的路径查找并提供对应的文件或目录；`FileServer` 和 `FileServerFS` 函数用于创建处理文件服务的 HTTP Handler。"  I make sure to mention the `fs.FS` aspect.

* **Final Polish:** I review the summary for clarity and ensure it directly answers the request. I use precise terminology and structure the answer logically.

This iterative process of understanding, analyzing, grouping, and refining helps arrive at a comprehensive and accurate summary of the code's functionality.
这段 Go 代码是 `net/http` 包的一部分，主要负责处理 HTTP 文件服务相关的逻辑。它定义了 `FileSystem` 和 `File` 接口，用于抽象文件系统的操作。`Dir` 类型实现了 `FileSystem` 接口，允许将本地文件系统中的特定目录作为静态资源对外提供服务。核心功能包括：

1. **定义了 `FileSystem` 接口:**  这个接口定义了 `Open(name string) (File, error)` 方法，用于打开指定名称的文件，返回一个 `File` 接口。

2. **定义了 `File` 接口:** 这个接口继承了 `io.Closer`, `io.Reader`, `io.Seeker`，并增加了 `Readdir(count int) ([]fs.FileInfo, error)` 和 `Stat() (fs.FileInfo, error)` 方法，用于读取目录内容和获取文件元信息。

3. **实现了 `Dir` 类型:** `Dir` 类型是一个字符串类型，表示本地文件系统的一个目录路径。它实现了 `FileSystem` 接口的 `Open` 方法，通过 `os.Open` 打开该目录下的文件。  **注意 `Dir` 的字符串值是本地文件系统的路径，使用 `filepath.Separator`，而不是 URL 中的 `/`。**

4. **提供了 `Open` 方法 (针对 `Dir`):**  `Dir` 类型的 `Open` 方法接收一个相对于 `Dir` 路径的文件名，并返回一个实现了 `File` 接口的 `os.File`。它会进行路径清理和安全检查。

5. **实现了目录列表功能 (`dirList` 函数):** 当请求的是一个目录时，该函数会读取目录下的文件和子目录，并生成一个 HTML 页面展示这些内容，类似一个简单的文件浏览器。

6. **提供了 `ServeContent` 函数:**  这是一个非常核心的函数，用于根据提供的 `io.ReadSeeker` (通常是一个打开的文件)，处理 HTTP 请求并返回文件内容。它支持：
    * **Range 请求:**  允许客户端请求文件的部分内容。
    * **MIME 类型设置:**  根据文件名后缀或内容嗅探来设置 `Content-Type` 头。
    * **条件请求处理:** 支持 `If-Match`, `If-Unmodified-Since`, `If-None-Match`, `If-Modified-Since`, `If-Range` 等请求头，用于优化缓存和减少不必要的传输。
    * **`Last-Modified` 头:**  根据提供的 `modtime` 设置 `Last-Modified` 头。

7. **提供了 `serveFile` 函数:**  该函数接收一个 `FileSystem` 实例和一个文件名，根据文件名打开文件或目录，并调用 `ServeContent` 或 `dirList` 来处理请求。它还处理了目录的重定向（在 URL 末尾添加 `/`）。

8. **提供了 `ServeFile` 和 `ServeFileFS` 函数:** 这两个函数是暴露给用户的便捷方法，用于 serving 本地文件系统中的文件。 `ServeFile` 使用 `http.Dir`，而 `ServeFileFS` 接受一个 `fs.FS` 接口的实现。它们都做了一些安全检查，例如拒绝包含 `..` 的路径。

9. **提供了 `FileServer` 和 `FileServerFS` 函数:** 这两个函数返回一个 `http.Handler`，可以用来处理静态文件请求。`FileServer` 接受一个 `FileSystem` 接口，而 `FileServerFS` 接受一个 `fs.FS` 接口。

10. **处理了条件请求相关的逻辑:** 包括 `checkIfMatch`, `checkIfUnmodifiedSince`, `checkIfNoneMatch`, `checkIfModifiedSince`, `checkIfRange` 等函数，用于判断是否满足条件，从而决定返回 304 Not Modified 或 412 Precondition Failed。

11. **处理了 ETag:** 提供了 `scanETag`, `etagStrongMatch`, `etagWeakMatch` 等函数，用于解析和比较 ETag。

**可以推理出它是什么 go 语言功能的实现：静态文件服务器**

这段代码主要实现了在 Go HTTP 服务器中提供静态文件服务的功能。通过 `Dir` 类型和 `FileServer` 函数，开发者可以很容易地将本地文件系统的某个目录作为静态资源对外提供服务。`ServeContent` 函数是实现这一功能的核心，它处理了各种 HTTP 细节，使得文件传输更加高效和符合标准。

**Go 代码举例说明:**

假设我们有一个目录 `/tmp/static`，里面包含一个文件 `index.html`。

```go
package main

import (
	"net/http"
	"log"
)

func main() {
	// 创建一个文件服务器，服务于 /tmp/static 目录
	fs := http.FileServer(http.Dir("/tmp/static"))

	// 将 /static 路径下的请求交给文件服务器处理
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Println("Server listening on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
```

**假设的输入与输出:**

1. **输入:**  浏览器请求 `http://localhost:8080/static/index.html`
2. **输出:**  服务器会读取 `/tmp/static/index.html` 的内容，并将其作为 HTTP 响应返回，同时设置 `Content-Type` 等头部。

3. **输入:** 浏览器请求 `http://localhost:8080/static/` (假设 `/tmp/static` 目录下没有 `index.html`，但有其他文件如 `test.txt`)
4. **输出:** 服务器会列出 `/tmp/static` 目录下的文件（例如 `test.txt`），并生成一个包含链接的 HTML 页面返回。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它的功能是作为 HTTP 服务器的一部分，处理客户端的请求。如果需要通过命令行指定静态文件的根目录，通常会在调用 `http.Dir()` 时传入通过命令行参数获取的路径。这部分逻辑会在使用 `net/http` 包构建 Web 应用的入口函数中处理，而不是在 `fs.go` 文件内部。

**使用者易犯错的点:**

1. **安全风险:** 使用 `http.Dir` 直接暴露文件系统可能会导致安全风险，例如：
    * **访问敏感文件:** 如果 `Dir` 指向的目录包含 `.git` 或 `.htpasswd` 等敏感文件，它们可能会被访问到。
    * **目录遍历:**  虽然代码中尝试阻止包含 `..` 的路径，但如果配置不当，仍然可能存在目录遍历的风险。
    * **符号链接攻击:** `Dir` 会跟随符号链接，如果用户可以创建任意符号链接，可能会指向服务器上的其他敏感文件。

   **例子:**  如果 `Dir("/home/user")`，那么请求 `/static/.bashrc` 可能会暴露用户的 bash 配置文件。

2. **路径混淆:**  `Dir` 的值是本地文件系统路径，而 HTTP 请求中的路径是 URL 路径，需要注意两者之间的转换和映射关系。

3. **MIME 类型理解不足:**  依赖自动的 MIME 类型检测可能在某些情况下不准确，需要理解其工作原理，必要时手动设置 `Content-Type`。

**归纳一下它的功能（针对提供的代码片段）：**

这段 Go 代码实现了 HTTP 文件服务的基础功能，包括：

* **抽象文件系统访问:** 定义了 `FileSystem` 和 `File` 接口，为不同类型的文件存储提供了统一的访问方式。
* **本地文件系统服务:** 提供了 `Dir` 类型，允许将本地文件系统的目录作为静态资源服务。
* **处理 HTTP 文件请求:** 实现了 `ServeContent` 和 `serveFile` 函数，用于处理客户端的文件请求，支持 Range 请求、MIME 类型设置和条件请求。
* **目录列表:** 当请求的路径是目录时，可以生成 HTML 页面列出目录内容。
* **创建文件服务器 Handler:** 提供了 `FileServer` 和 `FileServerFS` 函数，方便用户创建处理静态文件请求的 HTTP Handler。
* **条件请求处理:** 实现了 HTTP 条件请求相关的逻辑，用于优化缓存和减少不必要的传输。

总的来说，这段代码是 Go 语言 `net/http` 包中用于提供静态文件服务核心组件的一部分。它提供了必要的抽象和功能，使得开发者可以方便地构建静态文件服务器。

### 提示词
```
这是路径为go/src/net/http/fs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP file system request handler

package http

import (
	"errors"
	"fmt"
	"internal/godebug"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A Dir implements [FileSystem] using the native file system restricted to a
// specific directory tree.
//
// While the [FileSystem.Open] method takes '/'-separated paths, a Dir's string
// value is a directory path on the native file system, not a URL, so it is separated
// by [filepath.Separator], which isn't necessarily '/'.
//
// Note that Dir could expose sensitive files and directories. Dir will follow
// symlinks pointing out of the directory tree, which can be especially dangerous
// if serving from a directory in which users are able to create arbitrary symlinks.
// Dir will also allow access to files and directories starting with a period,
// which could expose sensitive directories like .git or sensitive files like
// .htpasswd. To exclude files with a leading period, remove the files/directories
// from the server or create a custom FileSystem implementation.
//
// An empty Dir is treated as ".".
type Dir string

// mapOpenError maps the provided non-nil error from opening name
// to a possibly better non-nil error. In particular, it turns OS-specific errors
// about opening files in non-directories into fs.ErrNotExist. See Issues 18984 and 49552.
func mapOpenError(originalErr error, name string, sep rune, stat func(string) (fs.FileInfo, error)) error {
	if errors.Is(originalErr, fs.ErrNotExist) || errors.Is(originalErr, fs.ErrPermission) {
		return originalErr
	}

	parts := strings.Split(name, string(sep))
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		fi, err := stat(strings.Join(parts[:i+1], string(sep)))
		if err != nil {
			return originalErr
		}
		if !fi.IsDir() {
			return fs.ErrNotExist
		}
	}
	return originalErr
}

// Open implements [FileSystem] using [os.Open], opening files for reading rooted
// and relative to the directory d.
func (d Dir) Open(name string) (File, error) {
	path := path.Clean("/" + name)[1:]
	if path == "" {
		path = "."
	}
	path, err := filepath.Localize(path)
	if err != nil {
		return nil, errors.New("http: invalid or unsafe file path")
	}
	dir := string(d)
	if dir == "" {
		dir = "."
	}
	fullName := filepath.Join(dir, path)
	f, err := os.Open(fullName)
	if err != nil {
		return nil, mapOpenError(err, fullName, filepath.Separator, os.Stat)
	}
	return f, nil
}

// A FileSystem implements access to a collection of named files.
// The elements in a file path are separated by slash ('/', U+002F)
// characters, regardless of host operating system convention.
// See the [FileServer] function to convert a FileSystem to a [Handler].
//
// This interface predates the [fs.FS] interface, which can be used instead:
// the [FS] adapter function converts an fs.FS to a FileSystem.
type FileSystem interface {
	Open(name string) (File, error)
}

// A File is returned by a [FileSystem]'s Open method and can be
// served by the [FileServer] implementation.
//
// The methods should behave the same as those on an [*os.File].
type File interface {
	io.Closer
	io.Reader
	io.Seeker
	Readdir(count int) ([]fs.FileInfo, error)
	Stat() (fs.FileInfo, error)
}

type anyDirs interface {
	len() int
	name(i int) string
	isDir(i int) bool
}

type fileInfoDirs []fs.FileInfo

func (d fileInfoDirs) len() int          { return len(d) }
func (d fileInfoDirs) isDir(i int) bool  { return d[i].IsDir() }
func (d fileInfoDirs) name(i int) string { return d[i].Name() }

type dirEntryDirs []fs.DirEntry

func (d dirEntryDirs) len() int          { return len(d) }
func (d dirEntryDirs) isDir(i int) bool  { return d[i].IsDir() }
func (d dirEntryDirs) name(i int) string { return d[i].Name() }

func dirList(w ResponseWriter, r *Request, f File) {
	// Prefer to use ReadDir instead of Readdir,
	// because the former doesn't require calling
	// Stat on every entry of a directory on Unix.
	var dirs anyDirs
	var err error
	if d, ok := f.(fs.ReadDirFile); ok {
		var list dirEntryDirs
		list, err = d.ReadDir(-1)
		dirs = list
	} else {
		var list fileInfoDirs
		list, err = f.Readdir(-1)
		dirs = list
	}

	if err != nil {
		logf(r, "http: error reading directory: %v", err)
		Error(w, "Error reading directory", StatusInternalServerError)
		return
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs.name(i) < dirs.name(j) })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html>\n")
	fmt.Fprintf(w, "<meta name=\"viewport\" content=\"width=device-width\">\n")
	fmt.Fprintf(w, "<pre>\n")
	for i, n := 0, dirs.len(); i < n; i++ {
		name := dirs.name(i)
		if dirs.isDir(i) {
			name += "/"
		}
		// name may contain '?' or '#', which must be escaped to remain
		// part of the URL path, and not indicate the start of a query
		// string or fragment.
		url := url.URL{Path: name}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", url.String(), htmlReplacer.Replace(name))
	}
	fmt.Fprintf(w, "</pre>\n")
}

// GODEBUG=httpservecontentkeepheaders=1 restores the pre-1.23 behavior of not deleting
// Cache-Control, Content-Encoding, Etag, or Last-Modified headers on ServeContent errors.
var httpservecontentkeepheaders = godebug.New("httpservecontentkeepheaders")

// serveError serves an error from ServeFile, ServeFileFS, and ServeContent.
// Because those can all be configured by the caller by setting headers like
// Etag, Last-Modified, and Cache-Control to send on a successful response,
// the error path needs to clear them, since they may not be meant for errors.
func serveError(w ResponseWriter, text string, code int) {
	h := w.Header()

	nonDefault := false
	for _, k := range []string{
		"Cache-Control",
		"Content-Encoding",
		"Etag",
		"Last-Modified",
	} {
		if !h.has(k) {
			continue
		}
		if httpservecontentkeepheaders.Value() == "1" {
			nonDefault = true
		} else {
			h.Del(k)
		}
	}
	if nonDefault {
		httpservecontentkeepheaders.IncNonDefault()
	}

	Error(w, text, code)
}

// ServeContent replies to the request using the content in the
// provided ReadSeeker. The main benefit of ServeContent over [io.Copy]
// is that it handles Range requests properly, sets the MIME type, and
// handles If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since,
// and If-Range requests.
//
// If the response's Content-Type header is not set, ServeContent
// first tries to deduce the type from name's file extension and,
// if that fails, falls back to reading the first block of the content
// and passing it to [DetectContentType].
// The name is otherwise unused; in particular it can be empty and is
// never sent in the response.
//
// If modtime is not the zero time or Unix epoch, ServeContent
// includes it in a Last-Modified header in the response. If the
// request includes an If-Modified-Since header, ServeContent uses
// modtime to decide whether the content needs to be sent at all.
//
// The content's Seek method must work: ServeContent uses
// a seek to the end of the content to determine its size.
// Note that [*os.File] implements the [io.ReadSeeker] interface.
//
// If the caller has set w's ETag header formatted per RFC 7232, section 2.3,
// ServeContent uses it to handle requests using If-Match, If-None-Match, or If-Range.
//
// If an error occurs when serving the request (for example, when
// handling an invalid range request), ServeContent responds with an
// error message. By default, ServeContent strips the Cache-Control,
// Content-Encoding, ETag, and Last-Modified headers from error responses.
// The GODEBUG setting httpservecontentkeepheaders=1 causes ServeContent
// to preserve these headers.
func ServeContent(w ResponseWriter, req *Request, name string, modtime time.Time, content io.ReadSeeker) {
	sizeFunc := func() (int64, error) {
		size, err := content.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, errSeeker
		}
		_, err = content.Seek(0, io.SeekStart)
		if err != nil {
			return 0, errSeeker
		}
		return size, nil
	}
	serveContent(w, req, name, modtime, sizeFunc, content)
}

// errSeeker is returned by ServeContent's sizeFunc when the content
// doesn't seek properly. The underlying Seeker's error text isn't
// included in the sizeFunc reply so it's not sent over HTTP to end
// users.
var errSeeker = errors.New("seeker can't seek")

// errNoOverlap is returned by serveContent's parseRange if first-byte-pos of
// all of the byte-range-spec values is greater than the content size.
var errNoOverlap = errors.New("invalid range: failed to overlap")

// if name is empty, filename is unknown. (used for mime type, before sniffing)
// if modtime.IsZero(), modtime is unknown.
// content must be seeked to the beginning of the file.
// The sizeFunc is called at most once. Its error, if any, is sent in the HTTP response.
func serveContent(w ResponseWriter, r *Request, name string, modtime time.Time, sizeFunc func() (int64, error), content io.ReadSeeker) {
	setLastModified(w, modtime)
	done, rangeReq := checkPreconditions(w, r, modtime)
	if done {
		return
	}

	code := StatusOK

	// If Content-Type isn't set, use the file's extension to find it, but
	// if the Content-Type is unset explicitly, do not sniff the type.
	ctypes, haveType := w.Header()["Content-Type"]
	var ctype string
	if !haveType {
		ctype = mime.TypeByExtension(filepath.Ext(name))
		if ctype == "" {
			// read a chunk to decide between utf-8 text and binary
			var buf [sniffLen]byte
			n, _ := io.ReadFull(content, buf[:])
			ctype = DetectContentType(buf[:n])
			_, err := content.Seek(0, io.SeekStart) // rewind to output whole file
			if err != nil {
				serveError(w, "seeker can't seek", StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", ctype)
	} else if len(ctypes) > 0 {
		ctype = ctypes[0]
	}

	size, err := sizeFunc()
	if err != nil {
		serveError(w, err.Error(), StatusInternalServerError)
		return
	}
	if size < 0 {
		// Should never happen but just to be sure
		serveError(w, "negative content size computed", StatusInternalServerError)
		return
	}

	// handle Content-Range header.
	sendSize := size
	var sendContent io.Reader = content
	ranges, err := parseRange(rangeReq, size)
	switch err {
	case nil:
	case errNoOverlap:
		if size == 0 {
			// Some clients add a Range header to all requests to
			// limit the size of the response. If the file is empty,
			// ignore the range header and respond with a 200 rather
			// than a 416.
			ranges = nil
			break
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		fallthrough
	default:
		serveError(w, err.Error(), StatusRequestedRangeNotSatisfiable)
		return
	}

	if sumRangesSize(ranges) > size {
		// The total number of bytes in all the ranges
		// is larger than the size of the file by
		// itself, so this is probably an attack, or a
		// dumb client. Ignore the range request.
		ranges = nil
	}
	switch {
	case len(ranges) == 1:
		// RFC 7233, Section 4.1:
		// "If a single part is being transferred, the server
		// generating the 206 response MUST generate a
		// Content-Range header field, describing what range
		// of the selected representation is enclosed, and a
		// payload consisting of the range.
		// ...
		// A server MUST NOT generate a multipart response to
		// a request for a single range, since a client that
		// does not request multiple parts might not support
		// multipart responses."
		ra := ranges[0]
		if _, err := content.Seek(ra.start, io.SeekStart); err != nil {
			serveError(w, err.Error(), StatusRequestedRangeNotSatisfiable)
			return
		}
		sendSize = ra.length
		code = StatusPartialContent
		w.Header().Set("Content-Range", ra.contentRange(size))
	case len(ranges) > 1:
		sendSize = rangesMIMESize(ranges, ctype, size)
		code = StatusPartialContent

		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		w.Header().Set("Content-Type", "multipart/byteranges; boundary="+mw.Boundary())
		sendContent = pr
		defer pr.Close() // cause writing goroutine to fail and exit if CopyN doesn't finish.
		go func() {
			for _, ra := range ranges {
				part, err := mw.CreatePart(ra.mimeHeader(ctype, size))
				if err != nil {
					pw.CloseWithError(err)
					return
				}
				if _, err := content.Seek(ra.start, io.SeekStart); err != nil {
					pw.CloseWithError(err)
					return
				}
				if _, err := io.CopyN(part, content, ra.length); err != nil {
					pw.CloseWithError(err)
					return
				}
			}
			mw.Close()
			pw.Close()
		}()
	}

	w.Header().Set("Accept-Ranges", "bytes")

	// We should be able to unconditionally set the Content-Length here.
	//
	// However, there is a pattern observed in the wild that this breaks:
	// The user wraps the ResponseWriter in one which gzips data written to it,
	// and sets "Content-Encoding: gzip".
	//
	// The user shouldn't be doing this; the serveContent path here depends
	// on serving seekable data with a known length. If you want to compress
	// on the fly, then you shouldn't be using ServeFile/ServeContent, or
	// you should compress the entire file up-front and provide a seekable
	// view of the compressed data.
	//
	// However, since we've observed this pattern in the wild, and since
	// setting Content-Length here breaks code that mostly-works today,
	// skip setting Content-Length if the user set Content-Encoding.
	//
	// If this is a range request, always set Content-Length.
	// If the user isn't changing the bytes sent in the ResponseWrite,
	// the Content-Length will be correct.
	// If the user is changing the bytes sent, then the range request wasn't
	// going to work properly anyway and we aren't worse off.
	//
	// A possible future improvement on this might be to look at the type
	// of the ResponseWriter, and always set Content-Length if it's one
	// that we recognize.
	if len(ranges) > 0 || w.Header().Get("Content-Encoding") == "" {
		w.Header().Set("Content-Length", strconv.FormatInt(sendSize, 10))
	}
	w.WriteHeader(code)

	if r.Method != "HEAD" {
		io.CopyN(w, sendContent, sendSize)
	}
}

// scanETag determines if a syntactically valid ETag is present at s. If so,
// the ETag and remaining text after consuming ETag is returned. Otherwise,
// it returns "", "".
func scanETag(s string) (etag string, remain string) {
	s = textproto.TrimString(s)
	start := 0
	if strings.HasPrefix(s, "W/") {
		start = 2
	}
	if len(s[start:]) < 2 || s[start] != '"' {
		return "", ""
	}
	// ETag is either W/"text" or "text".
	// See RFC 7232 2.3.
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		// Character values allowed in ETags.
		case c == 0x21 || c >= 0x23 && c <= 0x7E || c >= 0x80:
		case c == '"':
			return s[:i+1], s[i+1:]
		default:
			return "", ""
		}
	}
	return "", ""
}

// etagStrongMatch reports whether a and b match using strong ETag comparison.
// Assumes a and b are valid ETags.
func etagStrongMatch(a, b string) bool {
	return a == b && a != "" && a[0] == '"'
}

// etagWeakMatch reports whether a and b match using weak ETag comparison.
// Assumes a and b are valid ETags.
func etagWeakMatch(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// condResult is the result of an HTTP request precondition check.
// See https://tools.ietf.org/html/rfc7232 section 3.
type condResult int

const (
	condNone condResult = iota
	condTrue
	condFalse
)

func checkIfMatch(w ResponseWriter, r *Request) condResult {
	im := r.Header.Get("If-Match")
	if im == "" {
		return condNone
	}
	for {
		im = textproto.TrimString(im)
		if len(im) == 0 {
			break
		}
		if im[0] == ',' {
			im = im[1:]
			continue
		}
		if im[0] == '*' {
			return condTrue
		}
		etag, remain := scanETag(im)
		if etag == "" {
			break
		}
		if etagStrongMatch(etag, w.Header().get("Etag")) {
			return condTrue
		}
		im = remain
	}

	return condFalse
}

func checkIfUnmodifiedSince(r *Request, modtime time.Time) condResult {
	ius := r.Header.Get("If-Unmodified-Since")
	if ius == "" || isZeroTime(modtime) {
		return condNone
	}
	t, err := ParseTime(ius)
	if err != nil {
		return condNone
	}

	// The Last-Modified header truncates sub-second precision so
	// the modtime needs to be truncated too.
	modtime = modtime.Truncate(time.Second)
	if ret := modtime.Compare(t); ret <= 0 {
		return condTrue
	}
	return condFalse
}

func checkIfNoneMatch(w ResponseWriter, r *Request) condResult {
	inm := r.Header.get("If-None-Match")
	if inm == "" {
		return condNone
	}
	buf := inm
	for {
		buf = textproto.TrimString(buf)
		if len(buf) == 0 {
			break
		}
		if buf[0] == ',' {
			buf = buf[1:]
			continue
		}
		if buf[0] == '*' {
			return condFalse
		}
		etag, remain := scanETag(buf)
		if etag == "" {
			break
		}
		if etagWeakMatch(etag, w.Header().get("Etag")) {
			return condFalse
		}
		buf = remain
	}
	return condTrue
}

func checkIfModifiedSince(r *Request, modtime time.Time) condResult {
	if r.Method != "GET" && r.Method != "HEAD" {
		return condNone
	}
	ims := r.Header.Get("If-Modified-Since")
	if ims == "" || isZeroTime(modtime) {
		return condNone
	}
	t, err := ParseTime(ims)
	if err != nil {
		return condNone
	}
	// The Last-Modified header truncates sub-second precision so
	// the modtime needs to be truncated too.
	modtime = modtime.Truncate(time.Second)
	if ret := modtime.Compare(t); ret <= 0 {
		return condFalse
	}
	return condTrue
}

func checkIfRange(w ResponseWriter, r *Request, modtime time.Time) condResult {
	if r.Method != "GET" && r.Method != "HEAD" {
		return condNone
	}
	ir := r.Header.get("If-Range")
	if ir == "" {
		return condNone
	}
	etag, _ := scanETag(ir)
	if etag != "" {
		if etagStrongMatch(etag, w.Header().Get("Etag")) {
			return condTrue
		} else {
			return condFalse
		}
	}
	// The If-Range value is typically the ETag value, but it may also be
	// the modtime date. See golang.org/issue/8367.
	if modtime.IsZero() {
		return condFalse
	}
	t, err := ParseTime(ir)
	if err != nil {
		return condFalse
	}
	if t.Unix() == modtime.Unix() {
		return condTrue
	}
	return condFalse
}

var unixEpochTime = time.Unix(0, 0)

// isZeroTime reports whether t is obviously unspecified (either zero or Unix()=0).
func isZeroTime(t time.Time) bool {
	return t.IsZero() || t.Equal(unixEpochTime)
}

func setLastModified(w ResponseWriter, modtime time.Time) {
	if !isZeroTime(modtime) {
		w.Header().Set("Last-Modified", modtime.UTC().Format(TimeFormat))
	}
}

func writeNotModified(w ResponseWriter) {
	// RFC 7232 section 4.1:
	// a sender SHOULD NOT generate representation metadata other than the
	// above listed fields unless said metadata exists for the purpose of
	// guiding cache updates (e.g., Last-Modified might be useful if the
	// response does not have an ETag field).
	h := w.Header()
	delete(h, "Content-Type")
	delete(h, "Content-Length")
	delete(h, "Content-Encoding")
	if h.Get("Etag") != "" {
		delete(h, "Last-Modified")
	}
	w.WriteHeader(StatusNotModified)
}

// checkPreconditions evaluates request preconditions and reports whether a precondition
// resulted in sending StatusNotModified or StatusPreconditionFailed.
func checkPreconditions(w ResponseWriter, r *Request, modtime time.Time) (done bool, rangeHeader string) {
	// This function carefully follows RFC 7232 section 6.
	ch := checkIfMatch(w, r)
	if ch == condNone {
		ch = checkIfUnmodifiedSince(r, modtime)
	}
	if ch == condFalse {
		w.WriteHeader(StatusPreconditionFailed)
		return true, ""
	}
	switch checkIfNoneMatch(w, r) {
	case condFalse:
		if r.Method == "GET" || r.Method == "HEAD" {
			writeNotModified(w)
			return true, ""
		} else {
			w.WriteHeader(StatusPreconditionFailed)
			return true, ""
		}
	case condNone:
		if checkIfModifiedSince(r, modtime) == condFalse {
			writeNotModified(w)
			return true, ""
		}
	}

	rangeHeader = r.Header.get("Range")
	if rangeHeader != "" && checkIfRange(w, r, modtime) == condFalse {
		rangeHeader = ""
	}
	return false, rangeHeader
}

// name is '/'-separated, not filepath.Separator.
func serveFile(w ResponseWriter, r *Request, fs FileSystem, name string, redirect bool) {
	const indexPage = "/index.html"

	// redirect .../index.html to .../
	// can't use Redirect() because that would make the path absolute,
	// which would be a problem running under StripPrefix
	if strings.HasSuffix(r.URL.Path, indexPage) {
		localRedirect(w, r, "./")
		return
	}

	f, err := fs.Open(name)
	if err != nil {
		msg, code := toHTTPError(err)
		serveError(w, msg, code)
		return
	}
	defer f.Close()

	d, err := f.Stat()
	if err != nil {
		msg, code := toHTTPError(err)
		serveError(w, msg, code)
		return
	}

	if redirect {
		// redirect to canonical path: / at end of directory url
		// r.URL.Path always begins with /
		url := r.URL.Path
		if d.IsDir() {
			if url[len(url)-1] != '/' {
				localRedirect(w, r, path.Base(url)+"/")
				return
			}
		} else if url[len(url)-1] == '/' {
			base := path.Base(url)
			if base == "/" || base == "." {
				// The FileSystem maps a path like "/" or "/./" to a file instead of a directory.
				msg := "http: attempting to traverse a non-directory"
				serveError(w, msg, StatusInternalServerError)
				return
			}
			localRedirect(w, r, "../"+base)
			return
		}
	}

	if d.IsDir() {
		url := r.URL.Path
		// redirect if the directory name doesn't end in a slash
		if url == "" || url[len(url)-1] != '/' {
			localRedirect(w, r, path.Base(url)+"/")
			return
		}

		// use contents of index.html for directory, if present
		index := strings.TrimSuffix(name, "/") + indexPage
		ff, err := fs.Open(index)
		if err == nil {
			defer ff.Close()
			dd, err := ff.Stat()
			if err == nil {
				d = dd
				f = ff
			}
		}
	}

	// Still a directory? (we didn't find an index.html file)
	if d.IsDir() {
		if checkIfModifiedSince(r, d.ModTime()) == condFalse {
			writeNotModified(w)
			return
		}
		setLastModified(w, d.ModTime())
		dirList(w, r, f)
		return
	}

	// serveContent will check modification time
	sizeFunc := func() (int64, error) { return d.Size(), nil }
	serveContent(w, r, d.Name(), d.ModTime(), sizeFunc, f)
}

// toHTTPError returns a non-specific HTTP error message and status code
// for a given non-nil error value. It's important that toHTTPError does not
// actually return err.Error(), since msg and httpStatus are returned to users,
// and historically Go's ServeContent always returned just "404 Not Found" for
// all errors. We don't want to start leaking information in error messages.
func toHTTPError(err error) (msg string, httpStatus int) {
	if errors.Is(err, fs.ErrNotExist) {
		return "404 page not found", StatusNotFound
	}
	if errors.Is(err, fs.ErrPermission) {
		return "403 Forbidden", StatusForbidden
	}
	// Default:
	return "500 Internal Server Error", StatusInternalServerError
}

// localRedirect gives a Moved Permanently response.
// It does not convert relative paths to absolute paths like Redirect does.
func localRedirect(w ResponseWriter, r *Request, newPath string) {
	if q := r.URL.RawQuery; q != "" {
		newPath += "?" + q
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(StatusMovedPermanently)
}

// ServeFile replies to the request with the contents of the named
// file or directory.
//
// If the provided file or directory name is a relative path, it is
// interpreted relative to the current directory and may ascend to
// parent directories. If the provided name is constructed from user
// input, it should be sanitized before calling [ServeFile].
//
// As a precaution, ServeFile will reject requests where r.URL.Path
// contains a ".." path element; this protects against callers who
// might unsafely use [filepath.Join] on r.URL.Path without sanitizing
// it and then use that filepath.Join result as the name argument.
//
// As another special case, ServeFile redirects any request where r.URL.Path
// ends in "/index.html" to the same path, without the final
// "index.html". To avoid such redirects either modify the path or
// use [ServeContent].
//
// Outside of those two special cases, ServeFile does not use
// r.URL.Path for selecting the file or directory to serve; only the
// file or directory provided in the name argument is used.
func ServeFile(w ResponseWriter, r *Request, name string) {
	if containsDotDot(r.URL.Path) {
		// Too many programs use r.URL.Path to construct the argument to
		// serveFile. Reject the request under the assumption that happened
		// here and ".." may not be wanted.
		// Note that name might not contain "..", for example if code (still
		// incorrectly) used filepath.Join(myDir, r.URL.Path).
		serveError(w, "invalid URL path", StatusBadRequest)
		return
	}
	dir, file := filepath.Split(name)
	serveFile(w, r, Dir(dir), file, false)
}

// ServeFileFS replies to the request with the contents
// of the named file or directory from the file system fsys.
// The files provided by fsys must implement [io.Seeker].
//
// If the provided name is constructed from user input, it should be
// sanitized before calling [ServeFileFS].
//
// As a precaution, ServeFileFS will reject requests where r.URL.Path
// contains a ".." path element; this protects against callers who
// might unsafely use [filepath.Join] on r.URL.Path without sanitizing
// it and then use that filepath.Join result as the name argument.
//
// As another special case, ServeFileFS redirects any request where r.URL.Path
// ends in "/index.html" to the same path, without the final
// "index.html". To avoid such redirects either modify the path or
// use [ServeContent].
//
// Outside of those two special cases, ServeFileFS does not use
// r.URL.Path for selecting the file or directory to serve; only the
// file or directory provided in the name argument is used.
func ServeFileFS(w ResponseWriter, r *Request, fsys fs.FS, name string) {
	if containsDotDot(r.URL.Path) {
		// Too many programs use r.URL.Path to construct the argument to
		// serveFile. Reject the request under the assumption that happened
		// here and ".." may not be wanted.
		// Note that name might not contain "..", for example if code (still
		// incorrectly) used filepath.Join(myDir, r.URL.Path).
		serveError(w, "invalid URL path", StatusBadRequest)
		return
	}
	serveFile(w, r, FS(fsys), name, false)
}

func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func isSlashRune(r rune) bool { return r == '/' || r == '\\' }

type fileHandler struct {
	root FileSystem
}

type ioFS struct {
	fsys fs.FS
}

type ioFile struct {
	file fs.File
}

func (f ioFS) Open(name string) (File, error) {
	if name == "/" {
		name = "."
	} else {
		name = strings.TrimPrefix(name, "/")
	}
	file, err := f.fsys.Open(name)
	if err != nil {
		return nil, mapOpenError(err, name, '/', func(path string) (fs.FileInfo, error) {
			return fs.Stat(f.fsys, path)
		})
	}
	return ioFile{file}, nil
}

func (f ioFile) Close() error               { return f.file.Close() }
func (f ioFile) Read(b []byte) (int, error) { return f.file.Read(b) }
func (f ioFile) Stat() (fs.FileInfo, error) { return f.file.Stat() }

var errMissingSeek = errors.New("io.File missing Seek method")
var errMissingReadDir = errors.New("io.File directory missing ReadDir method")

func (f ioFile) Seek(offset int64, whence int) (int64, error) {
	s, ok := f.file.(io.Seeker)
	if !ok {
		return 0, errMissingSeek
	}
	return s.Seek(offset, whence)
}

func (f ioFile) ReadDir(count int) ([]fs.DirEntry, error) {
	d, ok := f.file.(fs.ReadDirFile)
	if !ok {
		return nil, errMissingReadDir
	}
	return d.ReadDir(count)
}

func (f ioFile) Readdir(count int) ([]fs.FileInfo, error) {
	d, ok := f.file.(fs.ReadDirFile)
	if !ok {
		return nil, errMissingReadDir
	}
	var list []fs.FileInfo
	for {
		dirs, err := d.ReadDir(count - len(list))
		for _, dir := range dirs {
			info, err := dir.Info()
			if err != nil {
				// Pretend it doesn't exist, like (*os.File).Readdir does.
				continue
			}
			list = append(list, info)
		}
		if err != nil {
			return list, err
		}
		if count < 0 || len(list) >= count {
			break
		}
	}
	return list, nil
}

// FS converts fsys to a [FileSystem] implementation,
// for use with [FileServer] and [NewFileTransport].
// The files provided by fsys must implement [io.Seeker].
func FS(fsys fs.FS) FileSystem {
	return ioFS{fsys}
}

// FileServer returns a handler that serves HTTP requests
// with the contents of the file system rooted at root.
//
// As a special case, the returned file server redirects any request
// ending in "/index.html" to the same path, without the final
// "index.html".
//
// To use the operating system's file system implementation,
// use [http.Dir]:
//
//	http.Handle("/", http.FileServer(http.Dir("/tmp")))
//
// To use an [fs.FS] implementation, use [http.FileServerFS] instead.
func FileServer(root FileSystem) Handler {
	return &fileHandler{root}
}

// FileServerFS returns a handler that serves HTTP requests
// with the contents of the file system fsys.
// The files provided by fsys must implement [io.Seeker].
//
// As a special case, the returned file server redirects any request
// ending in "/index.html" to the same path, without the final
// "index.html".
//
//	http.Handle("/", http.FileServerFS(fsys))
func FileServerFS(root fs.FS) Handler {
	return FileServer(FS(root))
}

func (f *fileHandler) ServeHTTP(w ResponseWriter, r *Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	serveFile(w, r, f.root, path.Clean(upath), true)
}

// httpRange specifies the byte range to be sent to the client.
type httpRange struct {
	start, length int64
}

func (r httpRange) contentRange(size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.start, r.start+r.length-1, size)
}

func (r httpRange) mimeHeader(contentType string, size int64) textproto.MIMEHeader {
	return textproto.MIMEHeader{
		"Content-Range": {r.contentRange(size)},
		"Content-Type":  {contentType},
	}
}

// parseRange parses a Range header string as per RFC 7233.
// errNoOverlap is returned if none of the ranges overlap.
func parseRange(s string, size int64) ([]httpRange, error) {
	if s == "" {
		return nil, nil // header not present
	}
	const b = "bytes="
	if !strings.HasPrefix(s, b) {
		return nil, errors.New("invalid range")
	}
	var ranges []httpRange
	noOverlap := false
	for _, ra := range strings.Split(s[len(b):], ",") {
		ra = textproto.TrimString(ra)
		if ra == "" {
			continue
		}
		start, end, ok := strings.Cut(ra, "-")
		if !ok {
			return nil, errors.New("invalid range")
		}
		start, end = textproto.TrimString(start), textproto.TrimString(end)
		var r httpRange
		if start == "" {
			// If no start is specified, end specifies the
			// range start relative to the end of the file,
			// and we are dealing with <suffix-length>
			// which has to be a non-negative integer as per
			// RFC 7233 Section 2.1 "Byte-Ranges".
			if end == "" || end[0] == '-' {
				return nil, errors.New("invalid range")
			}
			i, err := strconv.ParseInt(end, 10, 64)
			if i < 0 || err != nil {
				return nil, errors.New("invalid range")
			}
			if i > size {
				i = size
			}
			r.start = size - i
			r.length = size - r.start
		} else {
			i, err := strconv.ParseInt(start, 10, 64)
			if err != nil || i < 0 {
				return nil, errors.New("invalid range")
			}
			if i >= size {
				// If the range begins after the size of the content,
				// then it does not overlap.
				noOverlap = true
				continue
			}
			r.start = i
			if end == "" {
				// If no end is specified, range extends to end of the file.
				r.length = size - r.start
			} else {
				i, err := strconv.ParseInt(end, 10, 64)
				if err != nil || r.start > i {
					return nil, errors.New("invalid range")
				}
				if i >= size {
					i = size - 1
				}
				r.length = i - r.start + 1
			}
		}
		ranges = append(ranges, r)
	}
	if noOverlap && len(ranges) == 0 {
		// The specified ranges did not overlap with the content.
		return nil, errNoOverlap
	}
	return ranges, nil
}

// countingWriter counts how many bytes have been written to it.
type countingWriter int64

func (w *countingWriter) Write(p []byte) (n int, err error) {
	*w += countingWriter(len(p))
	return len(p), nil
}

// rangesMIMESize returns the number of bytes it takes to encode the
// provided ranges as a multipart response.
func rangesMIMESize(ranges []httpRange, contentType string, contentSize int64) (encSize int64) {
	var w countingWriter
	mw := multipart.NewWriter(&w)
	for _, ra := range ranges {
		mw.CreatePart(ra.mimeHeader(contentType, contentSize))
		encSize += ra.length
	}
	mw.Close()
	encSize += int64(w)
```