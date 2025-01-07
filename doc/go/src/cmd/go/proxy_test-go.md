Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The file name `proxy_test.go` immediately suggests this code is for testing the functionality of a Go module proxy. The package `main_test` confirms it's an integration test rather than a unit test.

2. **Identify Key Components:**  Scan the code for important variables, functions, and data structures. I see:
    * `proxyAddr`, `proxyURL`:  Clearly related to the proxy's address.
    * `StartProxy()`: A function to start the proxy.
    * `proxyHandler()`:  This is the core HTTP handler for the proxy.
    * `modList`:  Likely a list of modules served by the test proxy.
    * `readModList()`:  A function to populate `modList`.
    * `sumdbOps`, `sumdbServer`, `sumdbWrongOps`, `sumdbWrongServer`:  Indicate interaction with a SumDB (checksum database).
    * `proxyGoSum`, `proxyGoSumWrong`: Functions to generate `go.sum` entries, one correct and one incorrect.
    * `readArchive()`:  A function to load module data from `testdata/mod`.

3. **Analyze `StartProxy()`:**
    * It uses `sync.Once` to ensure the proxy starts only once.
    * It listens on a TCP address. If `-proxy` is provided, it uses that; otherwise, it picks an available port.
    * It sets `proxyURL`.
    * It starts an HTTP server using `proxyHandler`.
    * It prepopulates the sumdb.

4. **Deep Dive into `proxyHandler()`:** This is where the proxy logic resides. Go through the different `if` conditions:
    * `/mod/`: The base path for module requests.
    * `/mod/invalid/`:  Simulates an invalid response.
    * `/mod/<status_code>/`: Allows testing different HTTP status codes.
    * `/mod/sumdb-<direct|wrong>/`: Handles direct SumDB access (with correct and incorrect hashes).
    * `/mod/redirect/<count>/`: Simulates HTTP redirects.
    * `/mod/sumdb/<name>/supported`:  Handles SumDB supported check.
    * `/mod/sumdb/<name>/...`:  Routes to the SumDB server.
    * `/mod/path/@latest`: Resolves the latest module version.
    * `/mod/path/@v/version.info`: Serves the module info file.
    * `/mod/path/@v/version.mod`: Serves the module's `go.mod` file.
    * `/mod/path/@v/version.zip`: Serves the module's zip archive.

5. **Analyze Supporting Functions:**
    * `readModList()`: Reads the `testdata/mod` directory to create the list of available modules and versions. The naming convention in `testdata/mod` (like `example.com_foo_v1.0.0.txt`) is crucial here. The code parses these filenames.
    * `readArchive()`: Loads the content of a module version from a `.txt` file in `testdata/mod`. These `.txt` files likely contain the `.info`, `.mod`, and individual package files.
    * `proxyGoSum()`:  Generates the `go.sum` lines by hashing the module's contents. It calculates two hashes: one for the entire module content and one specifically for the `go.mod` file.
    * `proxyGoSumWrong()`: Intentionally generates incorrect hashes for testing purposes.

6. **Identify Go Features Implemented:** Based on the analysis of `proxyHandler`, I can identify the following Go proxy features:
    * Module content retrieval (`.info`, `.mod`, `.zip`).
    * Version listing (`list`).
    * `@latest` version resolution.
    * SumDB integration (direct and via proxy).
    * Handling of invalid responses and specific HTTP status codes.
    * Redirection.

7. **Construct Go Code Examples:** For each identified feature, create simple `go get` or manual HTTP request examples to demonstrate how these proxy functionalities are used. Think about the inputs to `go get` and the expected HTTP requests and responses.

8. **Identify Command-Line Arguments:** Look for the `flag` package usage. In this case, it's `-proxy`. Explain its purpose and how to use it.

9. **Identify Common Mistakes:** Consider scenarios where users might misuse the proxy or misunderstand its behavior. The use of `GOPROXY`, the importance of the `/mod` prefix, and the format of module paths and versions are potential areas for mistakes.

10. **Refine and Organize:** Structure the answer logically, starting with a high-level overview, then detailing each feature, providing code examples, and finally discussing potential pitfalls. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  The `testdata/mod` directory seems important. *Correction:* Realized the file naming convention in `testdata/mod` is directly related to how the proxy maps requests to local files.
* **Initial thought:** The SumDB interaction seems complex. *Correction:* Identified the distinction between direct SumDB access (for testing the client's direct interaction) and proxied SumDB access. The `sumdbOps` and `sumdbWrongOps` are for creating test SumDB servers.
* **Missed detail:** Initially didn't fully grasp the purpose of the numeric prefix in paths like `/mod/200/foo`. *Correction:* Realized this is a mechanism to inject specific HTTP status codes for testing error handling.
* **Code Example Improvement:**  Initially thought of just `go get`. *Correction:*  Added examples of manual HTTP requests to show the underlying protocol interactions more clearly.

By following this structured approach, including iterative refinement,  I can effectively analyze the code and provide a comprehensive explanation of its functionality.
这段代码是 Go 语言 `cmd/go` 工具的一部分，用于测试 Go 模块代理的功能。它模拟了一个简单的 Go 模块代理服务器，并提供了一些用于测试 `go` 命令与代理交互的端点。

以下是它的主要功能：

1. **启动一个模拟的 Go 模块代理服务器:**
   - 使用 `-proxy` 命令行参数指定的地址（例如 "localhost:1234"）或者一个随机的可用端口启动一个 HTTP 服务器。
   - 该服务器的根路径是 `/mod`。
   - 使用 `testdata/mod` 目录下的文件来模拟模块数据。`testdata/mod` 目录下的文件名遵循一定的约定，例如 `example.com_foo_v1.0.0.txt`，其中包含了模块 `example.com/foo` 的 `v1.0.0` 版本的信息（`.info` 文件）、`go.mod` 文件以及其他文件。

2. **处理 Go 模块代理协议的请求:**
   - `proxyHandler` 函数是该代理服务器的核心处理函数，它根据请求的路径模拟 Go 模块代理协议的行为。
   - **`/mod/<module>/@latest`**: 返回指定模块的最新版本信息。会模拟 `latest` 在直接模式和 `proxy.golang.org` 的行为，优先返回 released 版本，其次是 prereleased 版本，最后是 pseudo 版本。
   - **`/mod/<module>/@v/<version>.info`**: 返回指定模块指定版本的 `.info` 文件内容。
   - **`/mod/<module>/@v/<version>.mod`**: 返回指定模块指定版本的 `go.mod` 文件内容。
   - **`/mod/<module>/@v/<version>.zip`**: 返回指定模块指定版本的 zip 压缩包。该压缩包由 `testdata/mod` 中对应 `.txt` 文件中的内容动态生成。
   - **`/mod/<module>/@v/list`**: 返回指定模块的所有版本列表（不包括 pseudo-versions）。
   - **`/mod/sumdb/<name>/supported`**:  模拟对 sumdb 的支持检查，始终返回 200。
   - **`/mod/sumdb/<name>/...`**: 将请求转发到模拟的 sumdb 服务器 (`sumdbServer`)。
   - **`/mod/sumdb-direct/...`**: 模拟客户端直接与 sumdb 通信，使用正确的哈希值。
   - **`/mod/sumdb-wrong/...`**: 模拟客户端直接与 sumdb 通信，但返回错误的哈希值。
   - **`/mod/redirect/<count>/<path>`**:  模拟 HTTP 重定向，最多重定向 `<count>` 次。
   - **`/mod/<status_code>/...`**:  允许返回指定的 HTTP 状态码，用于测试客户端对不同状态码的处理。
   - **`/mod/invalid/`**:  返回无效的响应体，用于测试客户端的错误处理。

3. **模拟 Go Checksum Database (SumDB) 的交互:**
   - 使用 `golang.org/x/mod/sumdb` 包创建了两个模拟的 SumDB 服务器：`sumdbServer` 和 `sumdbWrongServer`。
   - `sumdbServer` 使用 `proxyGoSum` 函数生成正确的 `go.sum` 文件内容。
   - `sumdbWrongServer` 使用 `proxyGoSumWrong` 函数生成错误的 `go.sum` 文件内容。
   - `proxyGoSum` 函数会读取 `testdata/mod` 中对应模块版本的信息，并计算模块内容和 `go.mod` 文件的哈希值，然后生成 `go.sum` 文件的行。

4. **缓存机制:**
   - 使用 `par.Cache` 和 `par.ErrCache` 对读取的模块 archive 和生成的 zip 文件进行缓存，以提高性能。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 **Go 模块代理** 的核心功能。Go 模块代理允许 `go` 命令从远程服务器下载模块的元数据（`.info`）、`go.mod` 文件以及源代码（`.zip`）。

**Go 代码举例说明:**

假设 `testdata/mod` 目录下存在一个文件 `example.com_foo_v1.0.0.txt`，其内容如下：

```txtar
-- .info --
{"Version": "v1.0.0"}
-- go.mod --
module example.com/foo

go 1.16

-- foo.go --
package foo

func Hello() string {
	return "Hello, World!"
}
```

在启动代理后（假设 `-proxy` 设置为 "localhost:8080"），我们可以使用以下 `go` 命令与该模拟代理交互：

```bash
export GOPROXY=http://localhost:8080/mod
go get example.com/foo@v1.0.0
```

这个 `go get` 命令会向代理服务器发送以下请求：

- `GET http://localhost:8080/mod/example.com/foo/@v/v1.0.0.info`
- `GET http://localhost:8080/mod/example.com/foo/@v/v1.0.0.mod`
- `GET http://localhost:8080/mod/example.com/foo/@v/v1.0.0.zip`

模拟代理服务器会读取 `example.com_foo_v1.0.0.txt` 文件，并根据请求返回相应的内容。

**代码推理 (假设的输入与输出):**

**假设输入:**  收到一个针对 `example.com/foo@v1.0.0` 的 zip 文件请求 (`GET /mod/example.com/foo/@v/v1.0.0.zip`).

**`readArchive("example.com/foo", "v1.0.0")` 的输出 (从缓存或解析 `example.com_foo_v1.0.0.txt`):**

```
&txtar.Archive{
	Files: []txtar.File{
		{Name: ".info", Data: []byte("{\"Version\": \"v1.0.0\"}")},
		{Name: "go.mod", Data: []byte("module example.com/foo\n\ngo 1.16\n")},
		{Name: "foo.go", Data: []byte("package foo\n\nfunc Hello() string {\n\treturn \"Hello, World!\"\n}\n")},
	},
}
```

**`zipCache.Do(...)` 的输入:** 上面的 `txtar.Archive` 结构。

**`zipCache.Do(...)` 的输出 (生成的 zip 文件的字节流):**

一个包含 `example.com/foo@v1.0.0/go.mod` 和 `example.com/foo@v1.0.0/foo.go` 的 zip 文件的字节流。该 zip 文件的结构大致如下：

```
Archive:  (in memory)
  Length      Date    Time    Name
---------  ---------- -----   ----
       30  2023-10-27 10:00   example.com/foo@v1.0.0/go.mod
       68  2023-10-27 10:00   example.com/foo@v1.0.0/foo.go
---------                     -------
       98                     2 files
```

**`proxyHandler` 的输出 (HTTP 响应):**

HTTP 状态码: `200 OK`
Content-Type: `application/zip`
Body:  上述生成的 zip 文件的字节流。

**命令行参数的具体处理:**

该代码定义了一个名为 `proxyAddr` 的命令行 flag：

```go
var proxyAddr = flag.String("proxy", "", "run proxy on this network address instead of running any tests")
```

- **`-proxy`**:  指定模拟代理服务器监听的网络地址。
    - 如果提供了该参数（例如 `go test -args -proxy=localhost:8080`），则模拟代理服务器会在指定的地址启动，并且测试不会运行。
    - 如果没有提供该参数，则模拟代理服务器会监听一个随机的可用端口，并将端口信息记录下来，以便后续测试可以使用该代理。

**使用者易犯错的点:**

1. **GOPROXY 设置不正确:** 用户可能会忘记设置 `GOPROXY` 环境变量或将其设置为其他值，导致 `go` 命令不会使用该模拟代理。
   ```bash
   # 错误示例：没有设置 GOPROXY
   go get example.com/foo@v1.0.0  # 可能从其他代理或直接下载
   ```
   **正确示例:**
   ```bash
   export GOPROXY=http://localhost:8080/mod
   go get example.com/foo@v1.0.0
   ```

2. **`/mod` 前缀缺失:** 用户可能会直接访问代理服务器的根路径，而不是 `/mod` 子路径，导致请求失败。
   ```bash
   # 错误示例：直接访问根路径
   curl http://localhost:8080/example.com/foo/@v/v1.0.0.info  # 应该访问 http://localhost:8080/mod/example.com/foo/@v/v1.0.0.info
   ```

3. **`testdata/mod` 目录结构或文件内容错误:**  模拟代理依赖 `testdata/mod` 目录下的特定文件命名和内容格式。如果这些文件不存在或格式错误，会导致代理无法找到对应的模块版本信息。

4. **理解 `@latest` 的行为:**  用户可能对 `@latest` 的解析逻辑存在误解，认为它总是返回最新的已发布版本，而实际上它会根据是否存在 prerelease 或 pseudo-version 返回不同的结果。

总而言之，这段代码为 `cmd/go` 工具提供了测试 Go 模块代理功能的 инфраструктура，它通过模拟一个简单的代理服务器，允许开发者测试 `go` 命令与代理交互的各种场景，包括模块下载、版本列表、sumdb 集成等。

Prompt: 
```
这是路径为go/src/cmd/go/proxy_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"internal/txtar"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"cmd/go/internal/modfetch/codehost"
	"cmd/internal/par"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/dirhash"
)

var (
	proxyAddr = flag.String("proxy", "", "run proxy on this network address instead of running any tests")
	proxyURL  string
)

var proxyOnce sync.Once

// StartProxy starts the Go module proxy running on *proxyAddr (like "localhost:1234")
// and sets proxyURL to the GOPROXY setting to use to access the proxy.
// Subsequent calls are no-ops.
//
// The proxy serves from testdata/mod. See testdata/mod/README.
func StartProxy() {
	proxyOnce.Do(func() {
		readModList()
		addr := *proxyAddr
		if addr == "" {
			addr = "localhost:0"
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		*proxyAddr = l.Addr().String()
		proxyURL = "http://" + *proxyAddr + "/mod"
		fmt.Fprintf(os.Stderr, "go test proxy running at GOPROXY=%s\n", proxyURL)
		go func() {
			log.Fatalf("go proxy: http.Serve: %v", http.Serve(l, http.HandlerFunc(proxyHandler)))
		}()

		// Prepopulate main sumdb.
		for _, mod := range modList {
			sumdbOps.Lookup(nil, mod)
		}
	})
}

var modList []module.Version

func readModList() {
	files, err := os.ReadDir("testdata/mod")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		name := f.Name()
		if !strings.HasSuffix(name, ".txt") {
			continue
		}
		name = strings.TrimSuffix(name, ".txt")
		i := strings.LastIndex(name, "_v")
		if i < 0 {
			continue
		}
		encPath := strings.ReplaceAll(name[:i], "_", "/")
		path, err := module.UnescapePath(encPath)
		if err != nil {
			if testing.Verbose() && encPath != "example.com/invalidpath/v1" {
				fmt.Fprintf(os.Stderr, "go proxy_test: %v\n", err)
			}
			continue
		}
		encVers := name[i+1:]
		vers, err := module.UnescapeVersion(encVers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "go proxy_test: %v\n", err)
			continue
		}
		modList = append(modList, module.Version{Path: path, Version: vers})
	}
}

var zipCache par.ErrCache[*txtar.Archive, []byte]

const (
	testSumDBName        = "localhost.localdev/sumdb"
	testSumDBVerifierKey = "localhost.localdev/sumdb+00000c67+AcTrnkbUA+TU4heY3hkjiSES/DSQniBqIeQ/YppAUtK6"
	testSumDBSignerKey   = "PRIVATE+KEY+localhost.localdev/sumdb+00000c67+AXu6+oaVaOYuQOFrf1V59JK1owcFlJcHwwXHDfDGxSPk"
)

var (
	sumdbOps    = sumdb.NewTestServer(testSumDBSignerKey, proxyGoSum)
	sumdbServer = sumdb.NewServer(sumdbOps)

	sumdbWrongOps    = sumdb.NewTestServer(testSumDBSignerKey, proxyGoSumWrong)
	sumdbWrongServer = sumdb.NewServer(sumdbWrongOps)
)

// proxyHandler serves the Go module proxy protocol.
// See the proxy section of https://research.swtch.com/vgo-module.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/mod/") {
		http.NotFound(w, r)
		return
	}
	path := r.URL.Path[len("/mod/"):]

	// /mod/invalid returns faulty responses.
	if strings.HasPrefix(path, "invalid/") {
		w.Write([]byte("invalid"))
		return
	}

	// Next element may opt into special behavior.
	if j := strings.Index(path, "/"); j >= 0 {
		n, err := strconv.Atoi(path[:j])
		if err == nil && n >= 200 {
			w.WriteHeader(n)
			return
		}
		if strings.HasPrefix(path, "sumdb-") {
			n, err := strconv.Atoi(path[len("sumdb-"):j])
			if err == nil && n >= 200 {
				if strings.HasPrefix(path[j:], "/sumdb/") {
					w.WriteHeader(n)
					return
				}
				path = path[j+1:]
			}
		}
	}

	// Request for $GOPROXY/sumdb-direct is direct sumdb access.
	// (Client thinks it is talking directly to a sumdb.)
	if strings.HasPrefix(path, "sumdb-direct/") {
		r.URL.Path = path[len("sumdb-direct"):]
		sumdbServer.ServeHTTP(w, r)
		return
	}

	// Request for $GOPROXY/sumdb-wrong is direct sumdb access
	// but all the hashes are wrong.
	// (Client thinks it is talking directly to a sumdb.)
	if strings.HasPrefix(path, "sumdb-wrong/") {
		r.URL.Path = path[len("sumdb-wrong"):]
		sumdbWrongServer.ServeHTTP(w, r)
		return
	}

	// Request for $GOPROXY/redirect/<count>/... goes to redirects.
	if strings.HasPrefix(path, "redirect/") {
		path = path[len("redirect/"):]
		if j := strings.Index(path, "/"); j >= 0 {
			count, err := strconv.Atoi(path[:j])
			if err != nil {
				return
			}

			// The last redirect.
			if count <= 1 {
				http.Redirect(w, r, fmt.Sprintf("/mod/%s", path[j+1:]), 302)
				return
			}
			http.Redirect(w, r, fmt.Sprintf("/mod/redirect/%d/%s", count-1, path[j+1:]), 302)
			return
		}
	}

	// Request for $GOPROXY/sumdb/<name>/supported
	// is checking whether it's OK to access sumdb via the proxy.
	if path == "sumdb/"+testSumDBName+"/supported" {
		w.WriteHeader(200)
		return
	}

	// Request for $GOPROXY/sumdb/<name>/... goes to sumdb.
	if sumdbPrefix := "sumdb/" + testSumDBName + "/"; strings.HasPrefix(path, sumdbPrefix) {
		r.URL.Path = path[len(sumdbPrefix)-1:]
		sumdbServer.ServeHTTP(w, r)
		return
	}

	// Module proxy request: /mod/path/@latest
	// Rewrite to /mod/path/@v/<latest>.info where <latest> is the semantically
	// latest version, including pseudo-versions.
	if i := strings.LastIndex(path, "/@latest"); i >= 0 {
		enc := path[:i]
		modPath, err := module.UnescapePath(enc)
		if err != nil {
			if testing.Verbose() {
				fmt.Fprintf(os.Stderr, "go proxy_test: %v\n", err)
			}
			http.NotFound(w, r)
			return
		}

		// Imitate what "latest" does in direct mode and what proxy.golang.org does.
		// Use the latest released version.
		// If there is no released version, use the latest prereleased version.
		// Otherwise, use the latest pseudoversion.
		var latestRelease, latestPrerelease, latestPseudo string
		for _, m := range modList {
			if m.Path != modPath {
				continue
			}
			if module.IsPseudoVersion(m.Version) && (latestPseudo == "" || semver.Compare(latestPseudo, m.Version) > 0) {
				latestPseudo = m.Version
			} else if semver.Prerelease(m.Version) != "" && (latestPrerelease == "" || semver.Compare(latestPrerelease, m.Version) > 0) {
				latestPrerelease = m.Version
			} else if latestRelease == "" || semver.Compare(latestRelease, m.Version) > 0 {
				latestRelease = m.Version
			}
		}
		var latest string
		if latestRelease != "" {
			latest = latestRelease
		} else if latestPrerelease != "" {
			latest = latestPrerelease
		} else if latestPseudo != "" {
			latest = latestPseudo
		} else {
			http.NotFound(w, r)
			return
		}

		encVers, err := module.EscapeVersion(latest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		path = fmt.Sprintf("%s/@v/%s.info", enc, encVers)
	}

	// Module proxy request: /mod/path/@v/version[.suffix]
	i := strings.Index(path, "/@v/")
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	enc, file := path[:i], path[i+len("/@v/"):]
	path, err := module.UnescapePath(enc)
	if err != nil {
		if testing.Verbose() {
			fmt.Fprintf(os.Stderr, "go proxy_test: %v\n", err)
		}
		http.NotFound(w, r)
		return
	}
	if file == "list" {
		// list returns a list of versions, not including pseudo-versions.
		// If the module has no tagged versions, we should serve an empty 200.
		// If the module doesn't exist, we should serve 404 or 410.
		found := false
		for _, m := range modList {
			if m.Path != path {
				continue
			}
			found = true
			if !module.IsPseudoVersion(m.Version) {
				if err := module.Check(m.Path, m.Version); err == nil {
					fmt.Fprintf(w, "%s\n", m.Version)
				}
			}
		}
		if !found {
			http.NotFound(w, r)
		}
		return
	}

	i = strings.LastIndex(file, ".")
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	encVers, ext := file[:i], file[i+1:]
	vers, err := module.UnescapeVersion(encVers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "go proxy_test: %v\n", err)
		http.NotFound(w, r)
		return
	}

	if codehost.AllHex(vers) {
		var best string
		// Convert commit hash (only) to known version.
		// Use latest version in semver priority, to match similar logic
		// in the repo-based module server (see modfetch.(*codeRepo).convert).
		for _, m := range modList {
			if m.Path == path && semver.Compare(best, m.Version) < 0 {
				var hash string
				if module.IsPseudoVersion(m.Version) {
					hash = m.Version[strings.LastIndex(m.Version, "-")+1:]
				} else {
					hash = findHash(m)
				}
				if strings.HasPrefix(hash, vers) || strings.HasPrefix(vers, hash) {
					best = m.Version
				}
			}
		}
		if best != "" {
			vers = best
		}
	}

	a, err := readArchive(path, vers)
	if err != nil {
		if testing.Verbose() {
			fmt.Fprintf(os.Stderr, "go proxy: no archive %s %s: %v\n", path, vers, err)
		}
		if errors.Is(err, fs.ErrNotExist) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "cannot load archive", 500)
		}
		return
	}

	switch ext {
	case "info", "mod":
		want := "." + ext
		for _, f := range a.Files {
			if f.Name == want {
				w.Write(f.Data)
				return
			}
		}

	case "zip":
		zipBytes, err := zipCache.Do(a, func() ([]byte, error) {
			var buf bytes.Buffer
			z := zip.NewWriter(&buf)
			for _, f := range a.Files {
				if f.Name == ".info" || f.Name == ".mod" || f.Name == ".zip" {
					continue
				}
				var zipName string
				if strings.HasPrefix(f.Name, "/") {
					zipName = f.Name[1:]
				} else {
					zipName = path + "@" + vers + "/" + f.Name
				}
				zf, err := z.Create(zipName)
				if err != nil {
					return nil, err
				}
				if _, err := zf.Write(f.Data); err != nil {
					return nil, err
				}
			}
			if err := z.Close(); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		})

		if err != nil {
			if testing.Verbose() {
				fmt.Fprintf(os.Stderr, "go proxy: %v\n", err)
			}
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(zipBytes)
		return

	}
	http.NotFound(w, r)
}

func findHash(m module.Version) string {
	a, err := readArchive(m.Path, m.Version)
	if err != nil {
		return ""
	}
	var data []byte
	for _, f := range a.Files {
		if f.Name == ".info" {
			data = f.Data
			break
		}
	}
	var info struct{ Short string }
	json.Unmarshal(data, &info)
	return info.Short
}

var archiveCache par.Cache[string, *txtar.Archive]

var cmdGoDir, _ = os.Getwd()

func readArchive(path, vers string) (*txtar.Archive, error) {
	enc, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	encVers, err := module.EscapeVersion(vers)
	if err != nil {
		return nil, err
	}

	prefix := strings.ReplaceAll(enc, "/", "_")
	name := filepath.Join(cmdGoDir, "testdata/mod", prefix+"_"+encVers+".txt")
	a := archiveCache.Do(name, func() *txtar.Archive {
		a, err := txtar.ParseFile(name)
		if err != nil {
			if testing.Verbose() || !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "go proxy: %v\n", err)
			}
			a = nil
		}
		return a
	})
	if a == nil {
		return nil, fs.ErrNotExist
	}
	return a, nil
}

// proxyGoSum returns the two go.sum lines for path@vers.
func proxyGoSum(path, vers string) ([]byte, error) {
	a, err := readArchive(path, vers)
	if err != nil {
		return nil, err
	}
	var names []string
	files := make(map[string][]byte)
	var gomod []byte
	for _, f := range a.Files {
		if strings.HasPrefix(f.Name, ".") {
			if f.Name == ".mod" {
				gomod = f.Data
			}
			continue
		}
		name := path + "@" + vers + "/" + f.Name
		names = append(names, name)
		files[name] = f.Data
	}
	h1, err := dirhash.Hash1(names, func(name string) (io.ReadCloser, error) {
		data := files[name]
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		return nil, err
	}
	h1mod, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(gomod)), nil
	})
	if err != nil {
		return nil, err
	}
	data := []byte(fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", path, vers, h1, path, vers, h1mod))
	return data, nil
}

// proxyGoSumWrong returns the wrong lines.
func proxyGoSumWrong(path, vers string) ([]byte, error) {
	data := []byte(fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", path, vers, "h1:wrong", path, vers, "h1:wrong"))
	return data, nil
}

"""



```