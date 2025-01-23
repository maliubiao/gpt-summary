Response: Let's break down the thought process for analyzing the `pprof.go` code snippet.

**1. Understanding the Goal:**

The initial request asks for the functionality of the given Go code and potentially related concepts. The core of the request is to understand what this `pprof.go` file *does*.

**2. Initial Scan and Keywords:**

A quick skim reveals important keywords and package names:

* `"github.com/google/pprof/driver"` and `"github.com/google/pprof/profile"`:  This immediately points to this code being related to the `pprof` tool, likely acting as a Go-specific front-end or integration point. The `driver` package suggests a higher-level control structure.
* `flag`:  Indicates command-line argument parsing.
* `http`, `net/url`, `crypto/tls`: Suggests fetching profiles over HTTP/HTTPS.
* `os`:  Interaction with the operating system (file access, exit).
* `debug/dwarf`:  Relates to debugging information in binaries, particularly for C/C++ code.
* `cmd/internal/disasm`, `cmd/internal/objfile`:  Indicates assembly code disassembly and object file parsing, likely for examining the code at a low level.
* `main` function:  This is the entry point of an executable.

**3. Deconstructing the `main` Function:**

The `main` function is the best place to start understanding the overall flow:

```go
func main() {
	counter.Open()
	counter.Inc("pprof/invocations")
	options := &driver.Options{
		Fetch: new(fetcher),
		Obj:   new(objTool),
		UI:    newUI(),
	}
	err := driver.PProf(options)
	counter.CountFlags("pprof/flag:", *flag.CommandLine) // pprof will use the flag package as its default
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}
}
```

* **`counter.Open()` and `counter.Inc()`:**  Likely for internal telemetry or usage tracking.
* **`driver.Options`:**  This is a key data structure. It holds interfaces for fetching profiles (`Fetch`), working with object files (`Obj`), and user interaction (`UI`). This confirms the role of this code as a driver.
* **`new(fetcher)`, `new(objTool)`, `newUI()`:**  These instantiate concrete implementations of the interfaces defined in `driver.Options`. This suggests the core functionality is delegated to these types.
* **`driver.PProf(options)`:** This is the central call. It means the `github.com/google/pprof/driver` package handles the main logic of the `pprof` tool, and this Go code provides the necessary implementations for Go-specific scenarios.
* **`counter.CountFlags(...)`:** Tracks the command-line flags used.
* **Error Handling:** Standard Go error handling.

**4. Analyzing the `fetcher` Type:**

The `fetcher` type implements the `driver.Fetcher` interface. Its `Fetch` method is crucial for understanding how profiles are loaded:

* **File Check (`os.Stat`):** First, it checks if the input `src` is a local file. If so, it delegates to the standard `pprof` (returns `nil, "", nil`).
* **URL Parsing (`url.Parse`):** If not a file, it tries to parse `src` as a URL.
* **`adjustURL`:**  This function is important. It modifies the URL, adding `/debug/pprof/profile` if needed and handling duration/timeout parameters. This reveals a common way to fetch Go profiles via HTTP.
* **`getProfile`:**  This function makes the actual HTTP request to fetch the profile data. It handles HTTPS with potentially insecure connections.
* **Profile Parsing (`profile.Parse`):**  The fetched data is parsed into a `profile.Profile` object.

**5. Analyzing the `objTool` Type:**

The `objTool` type implements `driver.ObjTool`, responsible for interacting with object files (executables, libraries):

* **`Open`:** Uses `objfile.Open` to open the object file. It calculates an offset if needed.
* **`Demangle`:**  Returns an empty map because Go doesn't require symbol demangling like C++.
* **`Disasm`:**  Performs disassembly using the `disasm` package. It caches the disassembler for performance. Importantly, it doesn't support Intel syntax.
* **`cachedDisasm`:**  Manages the caching of disassembler instances.
* **`SetConfig`:**  Ignored, as the Go implementation doesn't need external binary configuration.

**6. Analyzing the `file` Type:**

The `file` type implements `driver.ObjFile`, representing a single analyzed executable:

* **`Name` and `BuildID`:** Basic information about the file.
* **`ObjAddr`:**  Calculates the address within the object file.
* **`SourceLine`:**  Attempts to find the source code line corresponding to a given address. It first tries the Go-specific PC-line table (`pcln`) and then falls back to DWARF information for C/C++ code.
* **`dwarfSourceLine` and `dwarfSourceLineEntry`:** Handle reading DWARF debugging information.
* **`Symbols`:** Extracts symbols (functions, variables) from the object file.
* **`Close`:**  Closes the underlying object file.

**7. Identifying Key Functionality and Go Features:**

Based on the analysis, the key functionalities are:

* **Fetching Profiles:** Primarily via HTTP from Go applications' `/debug/pprof/profile` endpoint.
* **Parsing Profile Data:** Using the `github.com/google/pprof/profile` package.
* **Object File Analysis:** Parsing Go executable files using `cmd/internal/objfile`.
* **Disassembly:** Disassembling Go code using `cmd/internal/disasm`.
* **Source Code Mapping:**  Mapping instruction addresses back to source code lines, handling both Go and C/C++ code (via DWARF).

The Go features used extensively include:

* **Interfaces:** `driver.Fetcher`, `driver.ObjTool`, `driver.ObjFile`, `driver.UI`.
* **Structs and Methods:**  For organizing data and behavior.
* **Error Handling:**  Using the `error` interface.
* **Standard Library Packages:** `net/http`, `net/url`, `os`, `flag`, `regexp`, `strconv`, `strings`, `sync`, `time`, `crypto/tls`, `debug/dwarf`.
* **Internal Packages:** `cmd/internal/disasm`, `cmd/internal/objfile`, `cmd/internal/telemetry/counter`.

**8. Formulating Examples and Identifying Potential Pitfalls:**

* **Fetching via HTTP:**  Easy to demonstrate. The key is the `/debug/pprof/profile` endpoint.
* **Disassembly:**  Demonstrating the command-line usage of `pprof` to trigger disassembly.
* **Command-line Arguments:**  Listing common and important flags.
* **Pitfalls:**  Focusing on the common mistake of forgetting the `http://` prefix or incorrect URL formatting.

**9. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the original request:

* List of functionalities.
* Explanation of Go features implemented with code examples.
* Explanation of command-line argument handling.
* Examples of common user errors.

This detailed thought process, combining code reading, keyword analysis, and understanding of the underlying concepts, leads to a comprehensive and accurate answer to the original question.
这段代码是 Go 语言 `pprof` 工具的一部分，位于 `go/src/cmd/pprof/pprof.go` 文件中。`pprof` 是一个用于可视化性能剖析数据的工具，它可以读取由 Go 程序或其他支持的程序生成的 profile.data 文件，并以多种方式呈现这些数据，帮助开发者分析性能瓶颈。

以下是这段代码的主要功能：

1. **作为 `pprof` 工具的入口点:** `main` 函数是程序的入口，它初始化并启动了 `pprof` 工具的核心逻辑。

2. **使用 `github.com/google/pprof/driver` 驱动:** 代码使用了 `github.com/google/pprof/driver` 包，这是一个通用的 `pprof` 驱动，提供了处理 profile 数据的框架。Go 版本的 `pprof` 基于这个驱动，并提供了 Go 特定的实现。

3. **实现 `driver.Fetcher` 接口:**  `fetcher` 类型实现了 `driver.Fetcher` 接口，负责从不同的来源获取 profile 数据。这包括：
    * **本地文件:**  如果提供的源是一个本地文件，则直接使用该文件。
    * **HTTP(S) 端点:** 如果源是一个 URL，则通过 HTTP(S) 请求获取 profile 数据。它特别处理了 Go 程序的 `/debug/pprof/profile` 端点，允许指定 duration 和 timeout。
    * **处理 `https+insecure` 协议:** 允许在开发或测试环境中使用自签名证书的 HTTPS 端点。

4. **实现 `driver.ObjTool` 接口:** `objTool` 类型实现了 `driver.ObjTool` 接口，负责处理目标文件（例如，Go 二进制文件）的符号和反汇编信息。它使用 Go 内部的 `cmd/internal/objfile` 和 `cmd/internal/disasm` 包来实现这些功能，而不是依赖外部的 `binutils` 工具。

5. **提供 Go 特定的对象文件处理:**  `file` 类型实现了 `driver.ObjFile` 接口，提供了访问 Go 二进制文件内部结构（如符号表、PC-Line 表、DWARF 信息）的能力，用于将地址映射到源代码行，并获取符号信息。

6. **处理命令行参数:** 虽然这段代码本身没有直接处理 `flag.Parse()`，但它将 `*flag.CommandLine` 传递给了 `counter.CountFlags`，这表明 `pprof` 工具使用了 `flag` 包来处理命令行参数。  `driver.PProf(options)` 内部会处理这些参数。

**推理 `pprof` 工具的 Go 语言功能实现：**

`pprof` 工具的核心 Go 语言功能实现体现在 `fetcher` 和 `objTool` 这两个类型中。

* **获取 Go 程序的 Profile 数据 (通过 HTTP):** Go 程序通常会暴露 `/debug/pprof/profile` 端点来提供 CPU profile 数据。`fetcher` 的 `Fetch` 方法就实现了从这个端点获取数据的逻辑。

   ```go
   // 假设我们有一个正在运行的 Go 程序，地址是 localhost:8080
   // 并且它暴露了 /debug/pprof/profile 端点

   // 模拟 pprof 工具的调用
   package main

   import (
       "fmt"
       "net/http"
       "os"
       "time"

       "github.com/google/pprof/profile"
   )

   func main() {
       sourceURL := "http://localhost:8080/debug/pprof/profile?seconds=5" // 获取 5 秒的 CPU profile
       timeout := 10 * time.Second

       client := &http.Client{
           Timeout: timeout,
       }

       resp, err := client.Get(sourceURL)
       if err != nil {
           fmt.Fprintf(os.Stderr, "Error fetching profile: %v\n", err)
           os.Exit(1)
       }
       defer resp.Body.Close()

       if resp.StatusCode != http.StatusOK {
           fmt.Fprintf(os.Stderr, "HTTP error: %s\n", resp.Status)
           os.Exit(1)
       }

       prof, err := profile.Parse(resp.Body)
       if err != nil {
           fmt.Fprintf(os.Stderr, "Error parsing profile: %v\n", err)
           os.Exit(1)
       }

       fmt.Println("Profile data fetched and parsed successfully!")
       fmt.Printf("Number of samples: %d\n", len(prof.Sample))
       // 可以进一步分析 prof 数据
   }
   ```

   **假设输入:** 一个正在运行的 Go 程序，监听在 `localhost:8080`，并且暴露了 `/debug/pprof/profile` 端点。

   **输出:**  `Profile data fetched and parsed successfully!` 以及样本数量。

* **分析 Go 二进制文件:** `objTool` 和 `file` 类型允许 `pprof` 工具理解 Go 二进制文件的结构，例如查找符号信息和将指令地址映射回源代码。这对于诸如 `top`、`weblist` 等命令的实现至关重要。

   ```go
   // 假设我们有一个编译好的 Go 二进制文件名为 "myprogram"

   package main

   import (
       "fmt"
       "os"
       "regexp"

       "cmd/internal/objfile"
   )

   func main() {
       filename := "myprogram" // 替换为你的 Go 二进制文件名
       f, err := objfile.Open(filename)
       if err != nil {
           fmt.Fprintf(os.Stderr, "Error opening object file: %v\n", err)
           os.Exit(1)
       }
       defer f.Close()

       symbols, err := f.Symbols()
       if err != nil {
           fmt.Fprintf(os.Stderr, "Error getting symbols: %v\n", err)
           os.Exit(1)
       }

       // 打印所有以 "main." 开头的符号
       re := regexp.MustCompile("^main\\.")
       for _, sym := range symbols {
           if re.MatchString(sym.Name) {
               fmt.Printf("Symbol: %s, Address: 0x%x, Size: %d\n", sym.Name, sym.Addr, sym.Size)
           }
       }
   }
   ```

   **假设输入:**  一个名为 `myprogram` 的已编译的 Go 二进制文件。

   **输出:**  所有以 `main.` 开头的符号的名称、地址和大小。

**命令行参数的具体处理:**

虽然这段代码没有直接展示 `flag.Parse()`，但通过 `driver.PProf(options)` 的调用，可以推断出 `pprof` 工具会处理一系列命令行参数。 一些常见的 `pprof` 命令行参数包括：

* **`<profile_source>`:**  指定 profile 数据的来源，可以是本地文件路径或 HTTP(S) URL。
* **`-seconds=<duration>`:**  当从 HTTP 端点获取 profile 时，指定采集 profile 的持续时间（秒）。
* **`-timeout=<duration>`:**  设置从 HTTP 端点获取 profile 的超时时间。
* **`-http=<bind_address>`:**  启动一个 HTTP 服务器来查看 profile 数据。
* **`-output=<filename>`:**  指定输出文件的名称。
* **`-symbolize=<mode>`:**  控制符号化的方式 (e.g., `none`, `local`, `remote`)。
* **`-objdump=<path>`:**  指定 `objdump` 工具的路径 (尽管 Go 版本的 `pprof` 主要使用内部实现)。
* **各种报告类型:** 如 `top` (显示最热路径)、`web` (生成调用图)、`list <function>` (列出指定函数的源代码)。

`adjustURL` 函数展示了如何处理 URL 中的 `seconds` 参数，并设置默认的 timeout。

**使用者易犯错的点:**

1. **URL 格式错误:** 当从 HTTP 端点获取 profile 时，容易犯 URL 格式错误，特别是忘记 `http://` 或 `https://` 前缀。

   **错误示例:**
   ```bash
   go tool pprof localhost:8080/debug/pprof/profile
   ```

   **正确示例:**
   ```bash
   go tool pprof http://localhost:8080/debug/pprof/profile
   ```

2. **超时时间不足:**  如果目标程序生成的 profile 数据量很大或网络延迟较高，默认的超时时间可能不足，导致获取 profile 失败。使用者可能需要使用 `-timeout` 参数增加超时时间。

   **错误示例 (假设默认超时时间过短):**
   ```bash
   go tool pprof http://slow-server:8080/debug/pprof/profile
   ```

   **正确示例:**
   ```bash
   go tool pprof -timeout=120s http://slow-server:8080/debug/pprof/profile
   ```

3. **未启动目标程序的 pprof 端点:**  如果尝试从 HTTP 端点获取 profile，但目标程序没有正确导入 `net/http/pprof` 包并在 HTTP 服务器上注册相应的 handler，将会导致连接失败或返回 404 错误。

4. **理解不同的 profile 类型:**  `pprof` 可以处理多种类型的 profile (CPU, 内存, 阻塞, 互斥锁等)。使用者需要了解目标程序提供的 profile 类型，并在 `pprof` 命令中使用正确的 URL (例如 `/debug/pprof/heap` 获取内存 profile)。

这段代码是 Go `pprof` 工具的核心组成部分，它利用 Go 语言的特性和标准库，以及内部的工具链，为开发者提供强大的性能分析能力。

### 提示词
```
这是路径为go/src/cmd/pprof/pprof.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// pprof is a tool for visualization of profile.data. It is based on
// the upstream version at github.com/google/pprof, with minor
// modifications specific to the Go distribution. Please consider
// upstreaming any modifications to these packages.

package main

import (
	"crypto/tls"
	"debug/dwarf"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cmd/internal/disasm"
	"cmd/internal/objfile"
	"cmd/internal/telemetry/counter"

	"github.com/google/pprof/driver"
	"github.com/google/pprof/profile"
)

func main() {
	counter.Open()
	counter.Inc("pprof/invocations")
	options := &driver.Options{
		Fetch: new(fetcher),
		Obj:   new(objTool),
		UI:    newUI(),
	}
	err := driver.PProf(options)
	counter.CountFlags("pprof/flag:", *flag.CommandLine) // pprof will use the flag package as its default
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}
}

type fetcher struct {
}

func (f *fetcher) Fetch(src string, duration, timeout time.Duration) (*profile.Profile, string, error) {
	// Firstly, determine if the src is an existing file on the disk.
	// If it is a file, let regular pprof open it.
	// If it is not a file, when the src contains `:`
	// (e.g. mem_2023-11-02_03:55:24 or abc:123/mem_2023-11-02_03:55:24),
	// url.Parse will recognize it as a link and ultimately report an error,
	// similar to `abc:123/mem_2023-11-02_03:55:24:
	// Get "http://abc:123/mem_2023-11-02_03:55:24": dial tcp: lookup abc: no such host`
	if _, openErr := os.Stat(src); openErr == nil {
		return nil, "", nil
	}
	sourceURL, timeout := adjustURL(src, duration, timeout)
	if sourceURL == "" {
		// Could not recognize URL, let regular pprof attempt to fetch the profile (eg. from a file)
		return nil, "", nil
	}
	fmt.Fprintln(os.Stderr, "Fetching profile over HTTP from", sourceURL)
	if duration > 0 {
		fmt.Fprintf(os.Stderr, "Please wait... (%v)\n", duration)
	}
	p, err := getProfile(sourceURL, timeout)
	return p, sourceURL, err
}

func getProfile(source string, timeout time.Duration) (*profile.Profile, error) {
	url, err := url.Parse(source)
	if err != nil {
		return nil, err
	}

	var tlsConfig *tls.Config
	if url.Scheme == "https+insecure" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		url.Scheme = "https"
		source = url.String()
	}

	client := &http.Client{
		Transport: &http.Transport{
			ResponseHeaderTimeout: timeout + 5*time.Second,
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       tlsConfig,
		},
	}
	resp, err := client.Get(source)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusCodeError(resp)
	}
	return profile.Parse(resp.Body)
}

func statusCodeError(resp *http.Response) error {
	if resp.Header.Get("X-Go-Pprof") != "" && strings.Contains(resp.Header.Get("Content-Type"), "text/plain") {
		// error is from pprof endpoint
		if body, err := io.ReadAll(resp.Body); err == nil {
			return fmt.Errorf("server response: %s - %s", resp.Status, body)
		}
	}
	return fmt.Errorf("server response: %s", resp.Status)
}

// cpuProfileHandler is the Go pprof CPU profile handler URL.
const cpuProfileHandler = "/debug/pprof/profile"

// adjustURL applies the duration/timeout values and Go specific defaults.
func adjustURL(source string, duration, timeout time.Duration) (string, time.Duration) {
	u, err := url.Parse(source)
	if err != nil || (u.Host == "" && u.Scheme != "" && u.Scheme != "file") {
		// Try adding http:// to catch sources of the form hostname:port/path.
		// url.Parse treats "hostname" as the scheme.
		u, err = url.Parse("http://" + source)
	}
	if err != nil || u.Host == "" {
		return "", 0
	}

	if u.Path == "" || u.Path == "/" {
		u.Path = cpuProfileHandler
	}

	// Apply duration/timeout overrides to URL.
	values := u.Query()
	if duration > 0 {
		values.Set("seconds", fmt.Sprint(int(duration.Seconds())))
	} else {
		if urlSeconds := values.Get("seconds"); urlSeconds != "" {
			if us, err := strconv.ParseInt(urlSeconds, 10, 32); err == nil {
				duration = time.Duration(us) * time.Second
			}
		}
	}
	if timeout <= 0 {
		if duration > 0 {
			timeout = duration + duration/2
		} else {
			timeout = 60 * time.Second
		}
	}
	u.RawQuery = values.Encode()
	return u.String(), timeout
}

// objTool implements driver.ObjTool using Go libraries
// (instead of invoking GNU binutils).
type objTool struct {
	mu          sync.Mutex
	disasmCache map[string]*disasm.Disasm
}

func (*objTool) Open(name string, start, limit, offset uint64, relocationSymbol string) (driver.ObjFile, error) {
	of, err := objfile.Open(name)
	if err != nil {
		return nil, err
	}
	f := &file{
		name: name,
		file: of,
	}
	if start != 0 {
		if load, err := of.LoadAddress(); err == nil {
			f.offset = start - load
		}
	}
	return f, nil
}

func (*objTool) Demangle(names []string) (map[string]string, error) {
	// No C++, nothing to demangle.
	return make(map[string]string), nil
}

func (t *objTool) Disasm(file string, start, end uint64, intelSyntax bool) ([]driver.Inst, error) {
	if intelSyntax {
		return nil, fmt.Errorf("printing assembly in Intel syntax is not supported")
	}
	d, err := t.cachedDisasm(file)
	if err != nil {
		return nil, err
	}
	var asm []driver.Inst
	d.Decode(start, end, nil, false, func(pc, size uint64, file string, line int, text string) {
		asm = append(asm, driver.Inst{Addr: pc, File: file, Line: line, Text: text})
	})
	return asm, nil
}

func (t *objTool) cachedDisasm(file string) (*disasm.Disasm, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.disasmCache == nil {
		t.disasmCache = make(map[string]*disasm.Disasm)
	}
	d := t.disasmCache[file]
	if d != nil {
		return d, nil
	}
	f, err := objfile.Open(file)
	if err != nil {
		return nil, err
	}
	d, err = disasm.DisasmForFile(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	t.disasmCache[file] = d
	return d, nil
}

func (*objTool) SetConfig(config string) {
	// config is usually used to say what binaries to invoke.
	// Ignore entirely.
}

// file implements driver.ObjFile using Go libraries
// (instead of invoking GNU binutils).
// A file represents a single executable being analyzed.
type file struct {
	name   string
	offset uint64
	sym    []objfile.Sym
	file   *objfile.File
	pcln   objfile.Liner

	triedDwarf bool
	dwarf      *dwarf.Data
}

func (f *file) Name() string {
	return f.name
}

func (f *file) ObjAddr(addr uint64) (uint64, error) {
	return addr - f.offset, nil
}

func (f *file) BuildID() string {
	// No support for build ID.
	return ""
}

func (f *file) SourceLine(addr uint64) ([]driver.Frame, error) {
	if f.pcln == nil {
		pcln, err := f.file.PCLineTable()
		if err != nil {
			return nil, err
		}
		f.pcln = pcln
	}
	addr -= f.offset
	file, line, fn := f.pcln.PCToLine(addr)
	if fn != nil {
		frame := []driver.Frame{
			{
				Func: fn.Name,
				File: file,
				Line: line,
			},
		}
		return frame, nil
	}

	frames := f.dwarfSourceLine(addr)
	if frames != nil {
		return frames, nil
	}

	return nil, fmt.Errorf("no line information for PC=%#x", addr)
}

// dwarfSourceLine tries to get file/line information using DWARF.
// This is for C functions that appear in the profile.
// Returns nil if there is no information available.
func (f *file) dwarfSourceLine(addr uint64) []driver.Frame {
	if f.dwarf == nil && !f.triedDwarf {
		// Ignore any error--we don't care exactly why there
		// is no DWARF info.
		f.dwarf, _ = f.file.DWARF()
		f.triedDwarf = true
	}

	if f.dwarf != nil {
		r := f.dwarf.Reader()
		unit, err := r.SeekPC(addr)
		if err == nil {
			if frames := f.dwarfSourceLineEntry(r, unit, addr); frames != nil {
				return frames
			}
		}
	}

	return nil
}

// dwarfSourceLineEntry tries to get file/line information from a
// DWARF compilation unit. Returns nil if it doesn't find anything.
func (f *file) dwarfSourceLineEntry(r *dwarf.Reader, entry *dwarf.Entry, addr uint64) []driver.Frame {
	lines, err := f.dwarf.LineReader(entry)
	if err != nil {
		return nil
	}
	var lentry dwarf.LineEntry
	if err := lines.SeekPC(addr, &lentry); err != nil {
		return nil
	}

	// Try to find the function name.
	name := ""
FindName:
	for entry, err := r.Next(); entry != nil && err == nil; entry, err = r.Next() {
		if entry.Tag == dwarf.TagSubprogram {
			ranges, err := f.dwarf.Ranges(entry)
			if err != nil {
				return nil
			}
			for _, pcs := range ranges {
				if pcs[0] <= addr && addr < pcs[1] {
					var ok bool
					// TODO: AT_linkage_name, AT_MIPS_linkage_name.
					name, ok = entry.Val(dwarf.AttrName).(string)
					if ok {
						break FindName
					}
				}
			}
		}
	}

	// TODO: Report inlined functions.

	frames := []driver.Frame{
		{
			Func: name,
			File: lentry.File.Name,
			Line: lentry.Line,
		},
	}

	return frames
}

func (f *file) Symbols(r *regexp.Regexp, addr uint64) ([]*driver.Sym, error) {
	if f.sym == nil {
		sym, err := f.file.Symbols()
		if err != nil {
			return nil, err
		}
		f.sym = sym
	}
	var out []*driver.Sym
	for _, s := range f.sym {
		// Ignore a symbol with address 0 and size 0.
		// An ELF STT_FILE symbol will look like that.
		if s.Addr == 0 && s.Size == 0 {
			continue
		}
		if (r == nil || r.MatchString(s.Name)) && (addr == 0 || s.Addr <= addr && addr < s.Addr+uint64(s.Size)) {
			out = append(out, &driver.Sym{
				Name:  []string{s.Name},
				File:  f.name,
				Start: s.Addr,
				End:   s.Addr + uint64(s.Size) - 1,
			})
		}
	}
	return out, nil
}

func (f *file) Close() error {
	f.file.Close()
	return nil
}

// newUI will be set in readlineui.go in some platforms
// for interactive readline functionality.
var newUI = func() driver.UI { return nil }
```