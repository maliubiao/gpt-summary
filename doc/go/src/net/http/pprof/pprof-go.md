Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for a description of the functionality of the `net/http/pprof` package in Go, along with examples, potential pitfalls, and explanations of command-line parameters.

**2. Initial Reading and Keyword Identification:**

First, I'd read through the comments at the top of the file. Keywords like "pprof," "HTTP server," "runtime profiling," "visualization tool," "/debug/pprof/", "GET," and specific profile names (heap, CPU, goroutine, etc.) immediately jump out. This gives a high-level understanding of the package's purpose.

**3. Identifying Core Functionality Based on Code Structure:**

Next, I'd look at the `init()` function. It registers HTTP handlers under the `/debug/pprof/` path. This signifies the core mechanism: exposing profiling data through HTTP endpoints. The specific handlers registered (`Index`, `Cmdline`, `Profile`, `Symbol`, `Trace`) suggest the different types of information available.

**4. Analyzing Individual Handler Functions:**

I'd then examine each handler function (`Cmdline`, `Profile`, `Trace`, `Symbol`, `Index`, and the `Handler` method of the `handler` type) individually:

* **`Cmdline`:**  Seems straightforward. It returns the command-line arguments of the running program.
* **`Profile`:** Mentions CPU profiling, the `seconds` parameter, and uses `pprof.StartCPUProfile` and `pprof.StopCPUProfile`. This indicates its role in collecting CPU usage data.
* **`Trace`:** Similar to `Profile`, but uses `trace.Start` and `trace.Stop` and focuses on execution tracing. It also mentions the `seconds` parameter.
* **`Symbol`:**  Handles symbol lookups, receiving program counters and returning function names. The comment about POST body or URL query is important.
* **`Index`:**  Serves the main `/debug/pprof/` page. It lists available profiles and links to them. The generation of HTML is a key aspect. It also calls `handler(name).ServeHTTP`, indicating it delegates to the `handler` type for specific profiles.
* **`Handler.ServeHTTP`:**  This is the core logic for serving individual named profiles (like "heap", "goroutine"). It handles the `debug`, `gc`, and `seconds` parameters. The `pprof.Lookup` function is crucial here. The `serveDeltaProfile` method is also important for understanding the "delta" functionality.

**5. Identifying Key Concepts and Relationships:**

As I analyze the handlers, I'd note the relationships between them: `Index` calls `handler.ServeHTTP`. I'd also identify key concepts:

* **Profiles:** The different types of profiling data.
* **`runtime/pprof` and `runtime/trace` packages:** The underlying Go libraries used.
* **HTTP Handlers:** The mechanism for exposing the data.
* **Query Parameters:** The way to customize the data retrieval.
* **`go tool pprof` and `go tool trace`:**  The external tools for analyzing the generated data.

**6. Inferring Functionality and Providing Examples:**

Based on the analysis, I can now infer the main functionality: providing runtime profiling data over HTTP. To create examples, I'd think about the different types of profiles and how to access them using `go tool pprof` and `curl`. I'd focus on illustrating the use of the `seconds` and `debug` parameters.

**7. Identifying Command-Line Parameters:**

The comments and the code itself explicitly mention the query parameters: `debug`, `gc`, and `seconds`. I would list these and describe their effect on different profiles.

**8. Recognizing Potential Pitfalls:**

I'd look for areas where users might make mistakes. The need to import the package for its side effects, starting an HTTP server, and using the correct tools (`go tool pprof`, `go tool trace`) come to mind. The interaction of `seconds` and `debug` parameters also seems like a potential confusion point.

**9. Structuring the Answer:**

Finally, I'd structure the answer logically, starting with a summary of the functionality, then detailing each component, providing examples, explaining parameters, and highlighting potential pitfalls. Using clear headings and formatting would improve readability. I would ensure all aspects requested in the original prompt are addressed.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the package actively collects data.
* **Correction:** The package *exposes* data collected by the `runtime/pprof` and `runtime/trace` packages. The application being profiled is the one generating the data.

* **Initial thought:**  Focus only on the code provided.
* **Correction:** The comments heavily reference external tools and concepts, so understanding those is crucial.

* **Initial thought:**  Examples should be very basic.
* **Refinement:** The examples should demonstrate the core usage scenarios, including using `go tool pprof` and `curl` with different profiles and parameters.

By following these steps, including iterative refinement, I can generate a comprehensive and accurate explanation of the provided Go code snippet.
这段Go语言代码是 `net/http/pprof` 包的一部分，它的主要功能是**通过HTTP接口提供Go程序的运行时性能数据，以便使用 `pprof` 可视化工具进行分析。**  简单来说，它将Go程序的内部运行状态以标准格式暴露出来，方便开发者进行性能监控和问题排查。

下面详细列举其功能并进行解释：

**1. 注册 HTTP 处理函数:**

`init()` 函数是包的初始化函数，它将一些 HTTP 处理函数注册到默认的 HTTP 服务路由器 (DefaultServeMux) 的 `/debug/pprof/` 路径下。这意味着当你的Go程序运行并监听HTTP请求时，你可以通过访问特定的URL来获取性能数据。

```go
func init() {
	prefix := ""
	if godebug.New("httpmuxgo121").Value() != "1" {
		prefix = "GET "
	}
	http.HandleFunc(prefix+"/debug/pprof/", Index)
	http.HandleFunc(prefix+"/debug/pprof/cmdline", Cmdline)
	http.HandleFunc(prefix+"/debug/pprof/profile", Profile)
	http.HandleFunc(prefix+"/debug/pprof/symbol", Symbol)
	http.HandleFunc(prefix+"/debug/pprof/trace", Trace)
}
```

*   **`Index`:**  处理 `/debug/pprof/` 路径的请求，返回一个HTML页面，列出所有可用的性能分析类型及其链接。
*   **`Cmdline`:** 处理 `/debug/pprof/cmdline` 路径的请求，返回当前运行程序的命令行参数，参数之间用空字符分隔。
*   **`Profile`:** 处理 `/debug/pprof/profile` 路径的请求，返回 CPU 的性能分析数据。可以通过 `seconds` 参数指定分析持续的时间。
*   **`Symbol`:** 处理 `/debug/pprof/symbol` 路径的请求，用于将程序计数器 (program counters) 映射到函数名。 可以通过 GET 请求的查询参数或 POST 请求的 body 传递程序计数器。
*   **`Trace`:** 处理 `/debug/pprof/trace` 路径的请求，返回程序的执行跟踪数据。可以通过 `seconds` 参数指定跟踪持续的时间。

**2. 提供不同的性能分析数据:**

该包提供了多种类型的性能分析数据，涵盖了CPU使用、内存分配、goroutine状态、锁竞争等关键方面。

*   **CPU Profile (`/debug/pprof/profile`):**  记录程序在一段时间内 CPU 的使用情况，可以帮助找出 CPU 瓶颈。
*   **Memory Allocation Profile (`/debug/pprof/heap`，通过 `Handler("heap")`):**  记录堆上内存的分配情况，可以帮助分析内存泄漏和高内存占用问题。可以通过 `gc` 参数在采样前强制执行一次垃圾回收。
*   **Goroutine Profile (`/debug/pprof/goroutine`，通过 `Handler("goroutine")`):**  列出当前所有 goroutine 的堆栈信息，可以帮助理解并发程序的运行状态。可以使用 `debug=2` 参数获得类似于 panic 时的详细堆栈信息。
*   **Block Profile (`/debug/pprof/block`，通过 `Handler("block")`):**  记录 goroutine 在等待同步原语（如互斥锁、通道）时阻塞的堆栈信息，可以帮助找出并发阻塞问题。 需要事先调用 `runtime.SetBlockProfileRate` 来启用。
*   **Mutex Profile (`/debug/pprof/mutex`，通过 `Handler("mutex")`):**  记录持有被争用互斥锁的 goroutine 的堆栈信息，可以帮助找出锁竞争问题。 需要事先调用 `runtime.SetMutexProfileFraction` 来启用。
*   **Thread Create Profile (`/debug/pprof/threadcreate`，通过 `Handler("threadcreate")`):**  记录创建新的操作系统线程的堆栈信息。
*   **Allocs Profile (`/debug/pprof/allocs`，通过 `Handler("allocs")`):**  记录所有过去的内存分配采样。

**3. 支持命令行参数:**

通过 GET 请求的查询参数，可以对某些性能分析数据进行定制：

*   **`debug=N` (所有 profiles):**
    *   `N=0` (或不指定): 返回二进制格式的数据 (默认)，用于 `go tool pprof` 工具分析。
    *   `N>0`: 返回文本格式的数据，方便查看，但通常不用于 `go tool pprof` 分析。
*   **`gc=N` (heap profile):**
    *   `N>0`: 在进行 heap 采样之前运行一次垃圾回收。这可以提供更准确的当前活跃对象内存分配信息。
*   **`seconds=N`:**
    *   **`allocs`, `block`, `goroutine`, `heap`, `mutex`, `threadcreate` profiles:** 返回在指定 `N` 秒内的增量 (delta) profile。例如，可以查看在这段时间内新分配的内存。
    *   **`cpu (profile)`, `trace` profiles:**  进行指定 `N` 秒的性能分析或跟踪。

**4. `Handler(name string) http.Handler` 函数:**

这个函数返回一个 `http.Handler`，用于服务指定名称的性能分析数据。  你可以将这个 handler 注册到你自己的 HTTP 服务路由器上，以便更灵活地控制性能数据的访问路径。

**5. `Index(w http.ResponseWriter, r *http.Request)` 函数:**

处理 `/debug/pprof/` 的请求，生成一个 HTML 页面，列出所有可用的 profile 类型，并提供链接。这方便用户快速了解可以获取哪些性能数据。

**Go 代码举例说明:**

假设你的 Go 程序中已经导入了 `net/http/pprof` 包，并且你已经启动了一个 HTTP 服务器，像这样：

```go
package main

import (
	"log"
	"net/http"
	_ "net/http/pprof" // 导入 pprof 包以注册其 HTTP 处理函数
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// 你的程序逻辑
	select {}
}
```

现在，你可以通过浏览器或命令行工具访问以下 URL 来获取性能数据：

*   **查看所有 profiles:** `http://localhost:6060/debug/pprof/` (会显示一个 HTML 页面)
*   **获取 CPU profile (30秒):** `http://localhost:6060/debug/pprof/profile`  或者使用 `go tool pprof http://localhost:6060/debug/pprof/profile`
*   **获取 CPU profile (10秒):** `http://localhost:6060/debug/pprof/profile?seconds=10` 或者使用 `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=10`
*   **获取 heap profile (采样前执行 GC):** `http://localhost:6060/debug/pprof/heap?gc=1` 或者使用 `go tool pprof http://localhost:6060/debug/pprof/heap?gc=1`
*   **获取 goroutine profile (文本格式):** `http://localhost:6060/debug/pprof/goroutine?debug=1`
*   **获取 goroutine profile (更详细的文本格式):** `http://localhost:6060/debug/pprof/goroutine?debug=2`
*   **获取 5 秒的 trace 数据:** `curl -o trace.out http://localhost:6060/debug/pprof/trace?seconds=5` 然后使用 `go tool trace trace.out` 分析。
*   **查询程序计数器对应的函数名 (假设程序计数器为 `0x401000` 和 `0x420000`):** `http://localhost:6060/debug/pprof/symbol?0x401000+0x420000`  或者使用 POST 请求，body 为 `0x401000+0x420000`。

**命令行参数的具体处理:**

代码中通过 `r.FormValue("参数名")` 来获取 GET 请求的查询参数值，并使用 `strconv` 包将其转换为相应的类型 (例如，`strconv.ParseInt` 用于将字符串转换为整数)。

例如，在 `Profile` 函数中：

```go
func Profile(w http.ResponseWriter, r *http.Request) {
	// ...
	sec, err := strconv.ParseInt(r.FormValue("seconds"), 10, 64)
	// ...
}
```

这段代码尝试获取名为 "seconds" 的查询参数的值，并将其解析为 64 位整数。如果解析失败或值小于等于 0，则使用默认值 30 秒。

**使用者易犯错的点:**

1. **忘记导入 `net/http/pprof` 包:**  `net/http/pprof` 包通常只需要导入其副作用 (即 `init()` 函数的执行)，因此需要使用 `import _ "net/http/pprof"` 的形式导入。如果忘记导入，相关的 HTTP 处理函数不会被注册，就无法访问性能数据。

    ```go
    // 错误示例：忘记导入 pprof 包
    package main

    import (
    	"log"
    	"net/http"
    )

    func main() {
    	go func() {
    		log.Println(http.ListenAndServe("localhost:6060", nil))
    	}()
    	select {}
    }
    ```

2. **没有运行 HTTP 服务器:** `net/http/pprof` 是通过 HTTP 接口提供数据的，因此必须确保你的 Go 程序正在运行一个 HTTP 服务器并监听端口。

    ```go
    // 错误示例：没有启动 HTTP 服务器
    package main

    import (
    	_ "net/http/pprof"
    )

    func main() {
    	// 没有启动 HTTP 服务器，无法访问 pprof 数据
    	select {}
    }
    ```

3. **混淆 `debug` 参数的不同值:**  `debug` 参数对于不同的 profile 有不同的含义，特别是 `goroutine` profile 的 `debug=2` 提供了更详细的堆栈信息，容易被忽略。

4. **不理解增量 (delta) profile 的含义:**  对于某些 profile，使用 `seconds` 参数会返回增量数据，这表示在这段时间内发生的变化，而不是这段时间内的所有数据。如果没有理解这一点，可能会对结果产生误解。

5. **在不适合的时间使用 `gc` 参数:**  过度频繁地使用 `gc=1` 可能会影响程序的性能，因为它会强制执行垃圾回收。应该只在需要获取准确的当前活跃对象内存分配信息时使用。

总而言之，`net/http/pprof` 包是 Go 语言中一个非常强大的性能分析工具，它通过简单的 HTTP 接口暴露了程序的内部运行状态，结合 `go tool pprof` 和 `go tool trace` 等工具，可以帮助开发者深入了解程序的性能瓶颈并进行优化。

Prompt: 
```
这是路径为go/src/net/http/pprof/pprof.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pprof serves via its HTTP server runtime profiling data
// in the format expected by the pprof visualization tool.
//
// The package is typically only imported for the side effect of
// registering its HTTP handlers.
// The handled paths all begin with /debug/pprof/.
// As of Go 1.22, all the paths must be requested with GET.
//
// To use pprof, link this package into your program:
//
//	import _ "net/http/pprof"
//
// If your application is not already running an http server, you
// need to start one. Add "net/http" and "log" to your imports and
// the following code to your main function:
//
//	go func() {
//		log.Println(http.ListenAndServe("localhost:6060", nil))
//	}()
//
// By default, all the profiles listed in [runtime/pprof.Profile] are
// available (via [Handler]), in addition to the [Cmdline], [Profile], [Symbol],
// and [Trace] profiles defined in this package.
// If you are not using DefaultServeMux, you will have to register handlers
// with the mux you are using.
//
// # Parameters
//
// Parameters can be passed via GET query params:
//
//   - debug=N (all profiles): response format: N = 0: binary (default), N > 0: plaintext
//   - gc=N (heap profile): N > 0: run a garbage collection cycle before profiling
//   - seconds=N (allocs, block, goroutine, heap, mutex, threadcreate profiles): return a delta profile
//   - seconds=N (cpu (profile), trace profiles): profile for the given duration
//
// # Usage examples
//
// Use the pprof tool to look at the heap profile:
//
//	go tool pprof http://localhost:6060/debug/pprof/heap
//
// Or to look at a 30-second CPU profile:
//
//	go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
//
// Or to look at the goroutine blocking profile, after calling
// [runtime.SetBlockProfileRate] in your program:
//
//	go tool pprof http://localhost:6060/debug/pprof/block
//
// Or to look at the holders of contended mutexes, after calling
// [runtime.SetMutexProfileFraction] in your program:
//
//	go tool pprof http://localhost:6060/debug/pprof/mutex
//
// The package also exports a handler that serves execution trace data
// for the "go tool trace" command. To collect a 5-second execution trace:
//
//	curl -o trace.out http://localhost:6060/debug/pprof/trace?seconds=5
//	go tool trace trace.out
//
// To view all available profiles, open http://localhost:6060/debug/pprof/
// in your browser.
//
// For a study of the facility in action, visit
// https://blog.golang.org/2011/06/profiling-go-programs.html.
package pprof

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"html"
	"internal/godebug"
	"internal/profile"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"slices"
	"strconv"
	"strings"
	"time"
)

func init() {
	prefix := ""
	if godebug.New("httpmuxgo121").Value() != "1" {
		prefix = "GET "
	}
	http.HandleFunc(prefix+"/debug/pprof/", Index)
	http.HandleFunc(prefix+"/debug/pprof/cmdline", Cmdline)
	http.HandleFunc(prefix+"/debug/pprof/profile", Profile)
	http.HandleFunc(prefix+"/debug/pprof/symbol", Symbol)
	http.HandleFunc(prefix+"/debug/pprof/trace", Trace)
}

// Cmdline responds with the running program's
// command line, with arguments separated by NUL bytes.
// The package initialization registers it as /debug/pprof/cmdline.
func Cmdline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, strings.Join(os.Args, "\x00"))
}

func sleep(r *http.Request, d time.Duration) {
	select {
	case <-time.After(d):
	case <-r.Context().Done():
	}
}

func configureWriteDeadline(w http.ResponseWriter, r *http.Request, seconds float64) {
	srv, ok := r.Context().Value(http.ServerContextKey).(*http.Server)
	if ok && srv.WriteTimeout > 0 {
		timeout := srv.WriteTimeout + time.Duration(seconds*float64(time.Second))

		rc := http.NewResponseController(w)
		rc.SetWriteDeadline(time.Now().Add(timeout))
	}
}

func serveError(w http.ResponseWriter, status int, txt string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Go-Pprof", "1")
	w.Header().Del("Content-Disposition")
	w.WriteHeader(status)
	fmt.Fprintln(w, txt)
}

// Profile responds with the pprof-formatted cpu profile.
// Profiling lasts for duration specified in seconds GET parameter, or for 30 seconds if not specified.
// The package initialization registers it as /debug/pprof/profile.
func Profile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	sec, err := strconv.ParseInt(r.FormValue("seconds"), 10, 64)
	if sec <= 0 || err != nil {
		sec = 30
	}

	configureWriteDeadline(w, r, float64(sec))

	// Set Content Type assuming StartCPUProfile will work,
	// because if it does it starts writing.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="profile"`)
	if err := pprof.StartCPUProfile(w); err != nil {
		// StartCPUProfile failed, so no writes yet.
		serveError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not enable CPU profiling: %s", err))
		return
	}
	sleep(r, time.Duration(sec)*time.Second)
	pprof.StopCPUProfile()
}

// Trace responds with the execution trace in binary form.
// Tracing lasts for duration specified in seconds GET parameter, or for 1 second if not specified.
// The package initialization registers it as /debug/pprof/trace.
func Trace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	sec, err := strconv.ParseFloat(r.FormValue("seconds"), 64)
	if sec <= 0 || err != nil {
		sec = 1
	}

	configureWriteDeadline(w, r, sec)

	// Set Content Type assuming trace.Start will work,
	// because if it does it starts writing.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="trace"`)
	if err := trace.Start(w); err != nil {
		// trace.Start failed, so no writes yet.
		serveError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not enable tracing: %s", err))
		return
	}
	sleep(r, time.Duration(sec*float64(time.Second)))
	trace.Stop()
}

// Symbol looks up the program counters listed in the request,
// responding with a table mapping program counters to function names.
// The package initialization registers it as /debug/pprof/symbol.
func Symbol(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// We have to read the whole POST body before
	// writing any output. Buffer the output here.
	var buf bytes.Buffer

	// We don't know how many symbols we have, but we
	// do have symbol information. Pprof only cares whether
	// this number is 0 (no symbols available) or > 0.
	fmt.Fprintf(&buf, "num_symbols: 1\n")

	var b *bufio.Reader
	if r.Method == "POST" {
		b = bufio.NewReader(r.Body)
	} else {
		b = bufio.NewReader(strings.NewReader(r.URL.RawQuery))
	}

	for {
		word, err := b.ReadSlice('+')
		if err == nil {
			word = word[0 : len(word)-1] // trim +
		}
		pc, _ := strconv.ParseUint(string(word), 0, 64)
		if pc != 0 {
			f := runtime.FuncForPC(uintptr(pc))
			if f != nil {
				fmt.Fprintf(&buf, "%#x %s\n", pc, f.Name())
			}
		}

		// Wait until here to check for err; the last
		// symbol will have an err because it doesn't end in +.
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(&buf, "reading request: %v\n", err)
			}
			break
		}
	}

	w.Write(buf.Bytes())
}

// Handler returns an HTTP handler that serves the named profile.
// Available profiles can be found in [runtime/pprof.Profile].
func Handler(name string) http.Handler {
	return handler(name)
}

type handler string

func (name handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	p := pprof.Lookup(string(name))
	if p == nil {
		serveError(w, http.StatusNotFound, "Unknown profile")
		return
	}
	if sec := r.FormValue("seconds"); sec != "" {
		name.serveDeltaProfile(w, r, p, sec)
		return
	}
	gc, _ := strconv.Atoi(r.FormValue("gc"))
	if name == "heap" && gc > 0 {
		runtime.GC()
	}
	debug, _ := strconv.Atoi(r.FormValue("debug"))
	if debug != 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	}
	p.WriteTo(w, debug)
}

func (name handler) serveDeltaProfile(w http.ResponseWriter, r *http.Request, p *pprof.Profile, secStr string) {
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil || sec <= 0 {
		serveError(w, http.StatusBadRequest, `invalid value for "seconds" - must be a positive integer`)
		return
	}
	// 'name' should be a key in profileSupportsDelta.
	if !profileSupportsDelta[name] {
		serveError(w, http.StatusBadRequest, `"seconds" parameter is not supported for this profile type`)
		return
	}

	configureWriteDeadline(w, r, float64(sec))

	debug, _ := strconv.Atoi(r.FormValue("debug"))
	if debug != 0 {
		serveError(w, http.StatusBadRequest, "seconds and debug params are incompatible")
		return
	}
	p0, err := collectProfile(p)
	if err != nil {
		serveError(w, http.StatusInternalServerError, "failed to collect profile")
		return
	}

	t := time.NewTimer(time.Duration(sec) * time.Second)
	defer t.Stop()

	select {
	case <-r.Context().Done():
		err := r.Context().Err()
		if err == context.DeadlineExceeded {
			serveError(w, http.StatusRequestTimeout, err.Error())
		} else { // TODO: what's a good status code for canceled requests? 400?
			serveError(w, http.StatusInternalServerError, err.Error())
		}
		return
	case <-t.C:
	}

	p1, err := collectProfile(p)
	if err != nil {
		serveError(w, http.StatusInternalServerError, "failed to collect profile")
		return
	}
	ts := p1.TimeNanos
	dur := p1.TimeNanos - p0.TimeNanos

	p0.Scale(-1)

	p1, err = profile.Merge([]*profile.Profile{p0, p1})
	if err != nil {
		serveError(w, http.StatusInternalServerError, "failed to compute delta")
		return
	}

	p1.TimeNanos = ts // set since we don't know what profile.Merge set for TimeNanos.
	p1.DurationNanos = dur

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-delta"`, name))
	p1.Write(w)
}

func collectProfile(p *pprof.Profile) (*profile.Profile, error) {
	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 0); err != nil {
		return nil, err
	}
	ts := time.Now().UnixNano()
	p0, err := profile.Parse(&buf)
	if err != nil {
		return nil, err
	}
	p0.TimeNanos = ts
	return p0, nil
}

var profileSupportsDelta = map[handler]bool{
	"allocs":       true,
	"block":        true,
	"goroutine":    true,
	"heap":         true,
	"mutex":        true,
	"threadcreate": true,
}

var profileDescriptions = map[string]string{
	"allocs":       "A sampling of all past memory allocations",
	"block":        "Stack traces that led to blocking on synchronization primitives",
	"cmdline":      "The command line invocation of the current program",
	"goroutine":    "Stack traces of all current goroutines. Use debug=2 as a query parameter to export in the same format as an unrecovered panic.",
	"heap":         "A sampling of memory allocations of live objects. You can specify the gc GET parameter to run GC before taking the heap sample.",
	"mutex":        "Stack traces of holders of contended mutexes",
	"profile":      "CPU profile. You can specify the duration in the seconds GET parameter. After you get the profile file, use the go tool pprof command to investigate the profile.",
	"symbol":       "Maps given program counters to function names. Counters can be specified in a GET raw query or POST body, multiple counters are separated by '+'.",
	"threadcreate": "Stack traces that led to the creation of new OS threads",
	"trace":        "A trace of execution of the current program. You can specify the duration in the seconds GET parameter. After you get the trace file, use the go tool trace command to investigate the trace.",
}

type profileEntry struct {
	Name  string
	Href  string
	Desc  string
	Count int
}

// Index responds with the pprof-formatted profile named by the request.
// For example, "/debug/pprof/heap" serves the "heap" profile.
// Index responds to a request for "/debug/pprof/" with an HTML page
// listing the available profiles.
func Index(w http.ResponseWriter, r *http.Request) {
	if name, found := strings.CutPrefix(r.URL.Path, "/debug/pprof/"); found {
		if name != "" {
			handler(name).ServeHTTP(w, r)
			return
		}
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var profiles []profileEntry
	for _, p := range pprof.Profiles() {
		profiles = append(profiles, profileEntry{
			Name:  p.Name(),
			Href:  p.Name(),
			Desc:  profileDescriptions[p.Name()],
			Count: p.Count(),
		})
	}

	// Adding other profiles exposed from within this package
	for _, p := range []string{"cmdline", "profile", "symbol", "trace"} {
		profiles = append(profiles, profileEntry{
			Name: p,
			Href: p,
			Desc: profileDescriptions[p],
		})
	}

	slices.SortFunc(profiles, func(a, b profileEntry) int {
		return strings.Compare(a.Name, b.Name)
	})

	if err := indexTmplExecute(w, profiles); err != nil {
		log.Print(err)
	}
}

func indexTmplExecute(w io.Writer, profiles []profileEntry) error {
	var b bytes.Buffer
	b.WriteString(`<html>
<head>
<title>/debug/pprof/</title>
<style>
.profile-name{
	display:inline-block;
	width:6rem;
}
</style>
</head>
<body>
/debug/pprof/
<br>
<p>Set debug=1 as a query parameter to export in legacy text format</p>
<br>
Types of profiles available:
<table>
<thead><td>Count</td><td>Profile</td></thead>
`)

	for _, profile := range profiles {
		link := &url.URL{Path: profile.Href, RawQuery: "debug=1"}
		fmt.Fprintf(&b, "<tr><td>%d</td><td><a href='%s'>%s</a></td></tr>\n", profile.Count, link, html.EscapeString(profile.Name))
	}

	b.WriteString(`</table>
<a href="goroutine?debug=2">full goroutine stack dump</a>
<br>
<p>
Profile Descriptions:
<ul>
`)
	for _, profile := range profiles {
		fmt.Fprintf(&b, "<li><div class=profile-name>%s: </div> %s</li>\n", html.EscapeString(profile.Name), html.EscapeString(profile.Desc))
	}
	b.WriteString(`</ul>
</p>
</body>
</html>`)

	_, err := w.Write(b.Bytes())
	return err
}

"""



```