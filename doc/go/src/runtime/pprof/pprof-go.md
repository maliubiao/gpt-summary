Response:
Let's break down the thought process for answering the request about `go/src/runtime/pprof/pprof.go`.

**1. Understanding the Core Task:**

The primary goal is to analyze the provided Go code snippet and explain its functionality, focusing on profiling in Go. The prompt specifically asks for:

* Listing functionalities.
* Inferring the Go feature it implements and providing examples.
* Explaining code inference (input/output assumptions).
* Detailed explanation of command-line arguments.
* Common mistakes users make.

**2. Initial Scan and Keyword Identification:**

I quickly scan the code, looking for keywords and patterns related to profiling. Key terms jump out:

* `pprof` (package name and repeated throughout)
* `Profile` (struct and methods like `Add`, `Remove`, `WriteTo`)
* `StartCPUProfile`, `StopCPUProfile`
* `heap`, `allocs`, `goroutine`, `block`, `mutex`, `threadcreate` (predefined profiles)
* `flag` (used for command-line arguments)
* `net/http/pprof` (HTTP interface for profiling)
* `go test -cpuprofile`, `go tool pprof` (command-line tools)

These keywords strongly suggest the code is about profiling Go applications.

**3. Functionality Listing (Direct Extraction):**

Based on the introductory comments and the identified keywords, I can list the core functionalities directly:

* **生成和管理性能剖析数据:**  The package's primary purpose is to generate and manage profiling data.
* **支持多种剖析类型:** The predefined profiles indicate support for CPU, memory (heap, allocs), goroutine, thread creation, blocking, and mutex profiling.
* **提供API用于自定义剖析:** The `Profile` struct and its methods (`NewProfile`, `Add`, `Remove`) allow users to create and manage their own custom profiles.
* **支持将剖析数据写入文件:**  The examples and `WriteTo` method show how to save profiling data to files.
* **提供HTTP接口用于实时剖析:** The mention of `net/http/pprof` indicates support for accessing profiling data via HTTP.
* **支持不同的输出格式:** The `debug` parameter in `WriteTo` suggests different output formats (protobuf and a human-readable text format).

**4. Inferring the Go Feature and Providing Examples:**

The combination of predefined profiles, the `StartCPUProfile`/`StopCPUProfile` API, and the mention of `go test` clearly points to Go's built-in profiling capabilities.

* **CPU Profiling:** The provided example code using `flag` and `pprof.StartCPUProfile` is a perfect demonstration. I include the code snippet and explain the purpose of each part.
* **Memory Profiling:**  Similarly, the example using `-memprofile` and `pprof.Lookup("allocs").WriteTo` illustrates memory profiling. I explain the different lookup options (`allocs` vs. `heap`).
* **HTTP Profiling:** The `import _ "net/http/pprof"` line is the key. I explain how this registers handlers and how to access the profiles via HTTP.

**5. Code Inference (Input/Output Assumptions):**

For the `Profile.Add` and `Profile.WriteTo` methods, I need to illustrate how they work with a custom profile.

* **`Profile.Add`:**  I create a hypothetical scenario with a custom profile tracking open files. I assume adding a file involves associating the file object (or a unique identifier) with the current stack trace. The output is that the internal map of the `Profile` now contains this association.
* **`Profile.WriteTo`:**  I assume that after adding several files, calling `WriteTo` with `debug=1` will output a human-readable representation of the stacks associated with each file. I emphasize that the order might not be guaranteed without sorting.

**6. Command-Line Arguments:**

The provided example code explicitly uses the `flag` package. I extract the relevant flags (`-cpuprofile`, `-memprofile`) and explain their purpose, how to use them with `go test`, and how the file paths are handled.

**7. Common Mistakes:**

I consider potential issues users might encounter based on the code and documentation:

* **忘记调用 `StopCPUProfile`:** This leads to the profiling continuing indefinitely.
* **在内置 Profile 上调用 `Add` 或 `Remove`:** The code explicitly panics in this case.
* **并发访问自定义 Profile 而不加锁:** While the `Profile` struct has internal locking for its methods, users of custom profiles might forget to add their own synchronization if needed for application-specific data associated with the profile.

**8. Structuring the Answer:**

I organize the answer logically, following the structure requested in the prompt:

* **功能列举:** Start with a concise list of functionalities.
* **实现的 Go 语言功能:**  Explain the core Go profiling feature and provide code examples for CPU, memory, and HTTP profiling.
* **代码推理:** Explain the hypothetical scenarios for `Profile.Add` and `Profile.WriteTo` with assumed inputs and outputs.
* **命令行参数:** Detail the command-line flags.
* **易犯错的点:**  List potential mistakes with clear examples.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on the technical details of the `Profile` struct's internal map. I refine this to focus on the user's perspective and how they interact with the API.
* I ensure the code examples are clear, concise, and directly relevant to the explained functionality.
* I double-check that the explanation of command-line arguments covers the essential aspects.
* I make sure the common mistakes are practical and easy to understand.

By following this thought process, I can systematically analyze the code, extract the necessary information, and present a comprehensive and accurate answer to the user's request.
## 对 go/src/runtime/pprof/pprof.go 的功能列举

这个 `pprof.go` 文件是 Go 语言运行时库中 `pprof` 包的核心实现。它的主要功能是：

1. **生成和管理性能剖析数据 (Profiling Data):**  它提供了创建、存储和导出程序运行时性能数据的机制。这些数据可以用于分析程序的 CPU 使用情况、内存分配、goroutine 状态、锁竞争等。

2. **支持多种预定义的性能剖析类型:** 它内置了对以下几种常见性能剖析的支持：
    * **CPU 剖析 (CPU Profile):**  记录程序在运行过程中 CPU 使用情况的采样数据。
    * **内存剖析 (Memory Profile):**
        * **Heap (堆) 剖析:**  记录当前存活对象的内存分配情况。
        * **Allocs (所有分配) 剖析:** 记录自程序启动以来所有内存分配的情况，包括已被回收的对象。
    * **Goroutine 剖析 (Goroutine Profile):**  捕获所有当前运行 goroutine 的堆栈信息。
    * **线程创建剖析 (ThreadCreate Profile):** 记录创建新的操作系统线程的堆栈信息。
    * **阻塞剖析 (Block Profile):**  记录 goroutine 在同步原语上阻塞的时间。
    * **互斥锁剖析 (Mutex Profile):** 记录互斥锁竞争的情况，包括等待锁的时间。

3. **提供 API 用于自定义性能剖析:**  它允许用户创建和管理自己的自定义性能剖析，用于跟踪特定的资源或事件。

4. **支持将性能剖析数据写入不同的输出目标:** 可以将剖析数据写入 `io.Writer` 接口，例如文件或网络连接。

5. **支持不同的输出格式:**  支持以 gzip 压缩的 Protocol Buffer 格式 (用于 `go tool pprof`) 和人类可读的文本格式输出剖析数据。

6. **提供启动和停止 CPU 剖析的特殊 API:**  由于 CPU 剖析是流式输出的，因此提供了 `StartCPUProfile` 和 `StopCPUProfile` 函数来控制其生命周期。

7. **提供查找和列出所有 Profile 的功能:**  可以通过名称查找特定的 Profile，或者获取所有已注册 Profile 的列表。

8. **与 `net/http/pprof` 包集成:**  允许通过 HTTP 接口访问实时的性能剖析数据。

**推理 `pprof.go` 实现的 Go 语言功能：性能剖析 (Profiling)**

`pprof.go` 实现了 Go 语言的性能剖析功能。性能剖析是一种动态程序分析方法，用于测量程序的执行时间、内存使用、资源消耗等，以便识别性能瓶颈。

**Go 代码示例：使用 `pprof` 包进行 CPU 性能剖析**

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"time"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")

func slowFunction() {
	time.Sleep(100 * time.Millisecond)
}

func main() {
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	for i := 0; i < 10; i++ {
		slowFunction()
		fmt.Println("Doing some work...")
	}
}
```

**假设的输入与输出：**

**输入 (命令行参数):**  `go run main.go -cpuprofile=cpu.prof`

**输出 (文件 `cpu.prof` 的内容):**  `cpu.prof` 文件将包含 CPU 剖析数据，其格式为 gzip 压缩的 Protocol Buffer。可以使用 `go tool pprof cpu.prof` 命令来分析这个文件。

**代码推理：**

1. **`flag.String("cpuprofile", "", "...")`:**  定义了一个名为 `cpuprofile` 的命令行标志，用于指定 CPU 剖析输出文件的路径。

2. **`if *cpuprofile != ""`:**  检查是否提供了 `-cpuprofile` 标志。

3. **`os.Create(*cpuprofile)`:**  如果提供了标志，则创建一个用于写入剖析数据的文件。

4. **`pprof.StartCPUProfile(f)`:**  调用 `pprof` 包的 `StartCPUProfile` 函数，开始 CPU 剖析并将数据写入到指定的文件 `f` 中。

5. **`defer pprof.StopCPUProfile()`:**  使用 `defer` 语句确保在 `main` 函数结束时调用 `StopCPUProfile` 来停止剖析并刷新缓冲区。

6. **`slowFunction()`:**  模拟一个耗时的操作，以便在剖析数据中体现出来。

**命令行参数的具体处理：**

在上面的示例中，`-cpuprofile` 是一个由 `flag` 包处理的命令行参数。

* **`-cpuprofile string`**:  指定 CPU 剖析数据输出的文件路径。如果不提供此参数，则不会生成 CPU 剖析数据。

当使用 `go run main.go -cpuprofile=cpu.prof` 运行程序时，`flag` 包会解析命令行参数，并将 `cpu.prof` 赋值给 `cpuprofile` 变量。`pprof` 包随后会使用这个路径来创建和写入 CPU 剖析文件。

**其他常见的 `pprof` 相关命令行参数 (通常与 `go test` 或 `go tool pprof` 结合使用):**

* **`-memprofile string` (与 `go test` 结合使用):** 指定内存剖析数据输出的文件路径。例如：`go test -memprofile=mem.prof`。
* **`-blockprofile string` (与 `go test` 结合使用):** 指定阻塞剖析数据输出的文件路径。例如：`go test -blockprofile=block.prof`。
* **`-mutexprofile string` (与 `go test` 结合使用):** 指定互斥锁剖析数据输出的文件路径。例如：`go test -mutexprofile=mutex.prof`。
* **`go tool pprof [options] [profile file]`**: `go tool pprof` 是一个独立的命令行工具，用于分析 `pprof` 生成的剖析文件。常见的选项包括：
    * **`top`**: 显示最耗时的函数。
    * **`web`**: 在浏览器中打开交互式的调用图。
    * **`list [function name]`**: 显示指定函数的源代码和性能数据。
    * **`-inuse_space`**:  在内存剖析中，按当前使用的内存大小排序。
    * **`-alloc_space`**: 在内存剖析中，按总分配的内存大小排序。

**使用者易犯错的点：**

1. **忘记调用 `StopCPUProfile()`:** 如果在程序结束前没有调用 `pprof.StopCPUProfile()`，可能会导致 CPU 剖析数据没有被完整地写入文件。

   ```go
   // 错误示例：忘记调用 StopCPUProfile
   if *cpuprofile != "" {
       f, err := os.Create(*cpuprofile)
       // ...
       pprof.StartCPUProfile(f)
       // ... 程序执行 ...
       // 忘记了 pprof.StopCPUProfile()
   }
   ```

2. **在内置的 Profile 上调用 `Add()` 或 `Remove()`:**  内置的 Profile (如 "goroutine", "heap" 等) 由运行时自动维护，不能手动添加或删除条目。调用这些方法会导致 panic。

   ```go
   // 错误示例：在内置的 heap Profile 上调用 Add
   p := pprof.Lookup("heap")
   if p != nil {
       // 运行时会 panic
       p.Add("some value", 0)
   }
   ```

总而言之，`go/src/runtime/pprof/pprof.go` 是 Go 语言性能剖析的核心，它提供了一套强大的工具和 API，帮助开发者理解和优化 Go 程序的性能。

Prompt: 
```
这是路径为go/src/runtime/pprof/pprof.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pprof writes runtime profiling data in the format expected
// by the pprof visualization tool.
//
// # Profiling a Go program
//
// The first step to profiling a Go program is to enable profiling.
// Support for profiling benchmarks built with the standard testing
// package is built into go test. For example, the following command
// runs benchmarks in the current directory and writes the CPU and
// memory profiles to cpu.prof and mem.prof:
//
//	go test -cpuprofile cpu.prof -memprofile mem.prof -bench .
//
// To add equivalent profiling support to a standalone program, add
// code like the following to your main function:
//
//	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
//	var memprofile = flag.String("memprofile", "", "write memory profile to `file`")
//
//	func main() {
//	    flag.Parse()
//	    if *cpuprofile != "" {
//	        f, err := os.Create(*cpuprofile)
//	        if err != nil {
//	            log.Fatal("could not create CPU profile: ", err)
//	        }
//	        defer f.Close() // error handling omitted for example
//	        if err := pprof.StartCPUProfile(f); err != nil {
//	            log.Fatal("could not start CPU profile: ", err)
//	        }
//	        defer pprof.StopCPUProfile()
//	    }
//
//	    // ... rest of the program ...
//
//	    if *memprofile != "" {
//	        f, err := os.Create(*memprofile)
//	        if err != nil {
//	            log.Fatal("could not create memory profile: ", err)
//	        }
//	        defer f.Close() // error handling omitted for example
//	        runtime.GC() // get up-to-date statistics
//	        // Lookup("allocs") creates a profile similar to go test -memprofile.
//	        // Alternatively, use Lookup("heap") for a profile
//	        // that has inuse_space as the default index.
//	        if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
//	            log.Fatal("could not write memory profile: ", err)
//	        }
//	    }
//	}
//
// There is also a standard HTTP interface to profiling data. Adding
// the following line will install handlers under the /debug/pprof/
// URL to download live profiles:
//
//	import _ "net/http/pprof"
//
// See the net/http/pprof package for more details.
//
// Profiles can then be visualized with the pprof tool:
//
//	go tool pprof cpu.prof
//
// There are many commands available from the pprof command line.
// Commonly used commands include "top", which prints a summary of the
// top program hot-spots, and "web", which opens an interactive graph
// of hot-spots and their call graphs. Use "help" for information on
// all pprof commands.
//
// For more information about pprof, see
// https://github.com/google/pprof/blob/main/doc/README.md.
package pprof

import (
	"bufio"
	"cmp"
	"fmt"
	"internal/abi"
	"internal/profilerecord"
	"io"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unsafe"
)

// BUG(rsc): Profiles are only as good as the kernel support used to generate them.
// See https://golang.org/issue/13841 for details about known problems.

// A Profile is a collection of stack traces showing the call sequences
// that led to instances of a particular event, such as allocation.
// Packages can create and maintain their own profiles; the most common
// use is for tracking resources that must be explicitly closed, such as files
// or network connections.
//
// A Profile's methods can be called from multiple goroutines simultaneously.
//
// Each Profile has a unique name. A few profiles are predefined:
//
//	goroutine    - stack traces of all current goroutines
//	heap         - a sampling of memory allocations of live objects
//	allocs       - a sampling of all past memory allocations
//	threadcreate - stack traces that led to the creation of new OS threads
//	block        - stack traces that led to blocking on synchronization primitives
//	mutex        - stack traces of holders of contended mutexes
//
// These predefined profiles maintain themselves and panic on an explicit
// [Profile.Add] or [Profile.Remove] method call.
//
// The CPU profile is not available as a Profile. It has a special API,
// the [StartCPUProfile] and [StopCPUProfile] functions, because it streams
// output to a writer during profiling.
//
// # Heap profile
//
// The heap profile reports statistics as of the most recently completed
// garbage collection; it elides more recent allocation to avoid skewing
// the profile away from live data and toward garbage.
// If there has been no garbage collection at all, the heap profile reports
// all known allocations. This exception helps mainly in programs running
// without garbage collection enabled, usually for debugging purposes.
//
// The heap profile tracks both the allocation sites for all live objects in
// the application memory and for all objects allocated since the program start.
// Pprof's -inuse_space, -inuse_objects, -alloc_space, and -alloc_objects
// flags select which to display, defaulting to -inuse_space (live objects,
// scaled by size).
//
// # Allocs profile
//
// The allocs profile is the same as the heap profile but changes the default
// pprof display to -alloc_space, the total number of bytes allocated since
// the program began (including garbage-collected bytes).
//
// # Block profile
//
// The block profile tracks time spent blocked on synchronization primitives,
// such as [sync.Mutex], [sync.RWMutex], [sync.WaitGroup], [sync.Cond], and
// channel send/receive/select.
//
// Stack traces correspond to the location that blocked (for example,
// [sync.Mutex.Lock]).
//
// Sample values correspond to cumulative time spent blocked at that stack
// trace, subject to time-based sampling specified by
// [runtime.SetBlockProfileRate].
//
// # Mutex profile
//
// The mutex profile tracks contention on mutexes, such as [sync.Mutex],
// [sync.RWMutex], and runtime-internal locks.
//
// Stack traces correspond to the end of the critical section causing
// contention. For example, a lock held for a long time while other goroutines
// are waiting to acquire the lock will report contention when the lock is
// finally unlocked (that is, at [sync.Mutex.Unlock]).
//
// Sample values correspond to the approximate cumulative time other goroutines
// spent blocked waiting for the lock, subject to event-based sampling
// specified by [runtime.SetMutexProfileFraction]. For example, if a caller
// holds a lock for 1s while 5 other goroutines are waiting for the entire
// second to acquire the lock, its unlock call stack will report 5s of
// contention.
//
// Runtime-internal locks are always reported at the location
// "runtime._LostContendedRuntimeLock". More detailed stack traces for
// runtime-internal locks can be obtained by setting
// `GODEBUG=runtimecontentionstacks=1` (see package [runtime] docs for
// caveats).
type Profile struct {
	name  string
	mu    sync.Mutex
	m     map[any][]uintptr
	count func() int
	write func(io.Writer, int) error
}

// profiles records all registered profiles.
var profiles struct {
	mu sync.Mutex
	m  map[string]*Profile
}

var goroutineProfile = &Profile{
	name:  "goroutine",
	count: countGoroutine,
	write: writeGoroutine,
}

var threadcreateProfile = &Profile{
	name:  "threadcreate",
	count: countThreadCreate,
	write: writeThreadCreate,
}

var heapProfile = &Profile{
	name:  "heap",
	count: countHeap,
	write: writeHeap,
}

var allocsProfile = &Profile{
	name:  "allocs",
	count: countHeap, // identical to heap profile
	write: writeAlloc,
}

var blockProfile = &Profile{
	name:  "block",
	count: countBlock,
	write: writeBlock,
}

var mutexProfile = &Profile{
	name:  "mutex",
	count: countMutex,
	write: writeMutex,
}

func lockProfiles() {
	profiles.mu.Lock()
	if profiles.m == nil {
		// Initial built-in profiles.
		profiles.m = map[string]*Profile{
			"goroutine":    goroutineProfile,
			"threadcreate": threadcreateProfile,
			"heap":         heapProfile,
			"allocs":       allocsProfile,
			"block":        blockProfile,
			"mutex":        mutexProfile,
		}
	}
}

func unlockProfiles() {
	profiles.mu.Unlock()
}

// NewProfile creates a new profile with the given name.
// If a profile with that name already exists, NewProfile panics.
// The convention is to use a 'import/path.' prefix to create
// separate name spaces for each package.
// For compatibility with various tools that read pprof data,
// profile names should not contain spaces.
func NewProfile(name string) *Profile {
	lockProfiles()
	defer unlockProfiles()
	if name == "" {
		panic("pprof: NewProfile with empty name")
	}
	if profiles.m[name] != nil {
		panic("pprof: NewProfile name already in use: " + name)
	}
	p := &Profile{
		name: name,
		m:    map[any][]uintptr{},
	}
	profiles.m[name] = p
	return p
}

// Lookup returns the profile with the given name, or nil if no such profile exists.
func Lookup(name string) *Profile {
	lockProfiles()
	defer unlockProfiles()
	return profiles.m[name]
}

// Profiles returns a slice of all the known profiles, sorted by name.
func Profiles() []*Profile {
	lockProfiles()
	defer unlockProfiles()

	all := make([]*Profile, 0, len(profiles.m))
	for _, p := range profiles.m {
		all = append(all, p)
	}

	slices.SortFunc(all, func(a, b *Profile) int {
		return strings.Compare(a.name, b.name)
	})
	return all
}

// Name returns this profile's name, which can be passed to [Lookup] to reobtain the profile.
func (p *Profile) Name() string {
	return p.name
}

// Count returns the number of execution stacks currently in the profile.
func (p *Profile) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.count != nil {
		return p.count()
	}
	return len(p.m)
}

// Add adds the current execution stack to the profile, associated with value.
// Add stores value in an internal map, so value must be suitable for use as
// a map key and will not be garbage collected until the corresponding
// call to [Profile.Remove]. Add panics if the profile already contains a stack for value.
//
// The skip parameter has the same meaning as [runtime.Caller]'s skip
// and controls where the stack trace begins. Passing skip=0 begins the
// trace in the function calling Add. For example, given this
// execution stack:
//
//	Add
//	called from rpc.NewClient
//	called from mypkg.Run
//	called from main.main
//
// Passing skip=0 begins the stack trace at the call to Add inside rpc.NewClient.
// Passing skip=1 begins the stack trace at the call to NewClient inside mypkg.Run.
func (p *Profile) Add(value any, skip int) {
	if p.name == "" {
		panic("pprof: use of uninitialized Profile")
	}
	if p.write != nil {
		panic("pprof: Add called on built-in Profile " + p.name)
	}

	stk := make([]uintptr, 32)
	n := runtime.Callers(skip+1, stk[:])
	stk = stk[:n]
	if len(stk) == 0 {
		// The value for skip is too large, and there's no stack trace to record.
		stk = []uintptr{abi.FuncPCABIInternal(lostProfileEvent)}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m[value] != nil {
		panic("pprof: Profile.Add of duplicate value")
	}
	p.m[value] = stk
}

// Remove removes the execution stack associated with value from the profile.
// It is a no-op if the value is not in the profile.
func (p *Profile) Remove(value any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, value)
}

// WriteTo writes a pprof-formatted snapshot of the profile to w.
// If a write to w returns an error, WriteTo returns that error.
// Otherwise, WriteTo returns nil.
//
// The debug parameter enables additional output.
// Passing debug=0 writes the gzip-compressed protocol buffer described
// in https://github.com/google/pprof/tree/main/proto#overview.
// Passing debug=1 writes the legacy text format with comments
// translating addresses to function names and line numbers, so that a
// programmer can read the profile without tools.
//
// The predefined profiles may assign meaning to other debug values;
// for example, when printing the "goroutine" profile, debug=2 means to
// print the goroutine stacks in the same form that a Go program uses
// when dying due to an unrecovered panic.
func (p *Profile) WriteTo(w io.Writer, debug int) error {
	if p.name == "" {
		panic("pprof: use of zero Profile")
	}
	if p.write != nil {
		return p.write(w, debug)
	}

	// Obtain consistent snapshot under lock; then process without lock.
	p.mu.Lock()
	all := make([][]uintptr, 0, len(p.m))
	for _, stk := range p.m {
		all = append(all, stk)
	}
	p.mu.Unlock()

	// Map order is non-deterministic; make output deterministic.
	slices.SortFunc(all, slices.Compare)

	return printCountProfile(w, debug, p.name, stackProfile(all))
}

type stackProfile [][]uintptr

func (x stackProfile) Len() int              { return len(x) }
func (x stackProfile) Stack(i int) []uintptr { return x[i] }
func (x stackProfile) Label(i int) *labelMap { return nil }

// A countProfile is a set of stack traces to be printed as counts
// grouped by stack trace. There are multiple implementations:
// all that matters is that we can find out how many traces there are
// and obtain each trace in turn.
type countProfile interface {
	Len() int
	Stack(i int) []uintptr
	Label(i int) *labelMap
}

// expandInlinedFrames copies the call stack from pcs into dst, expanding any
// PCs corresponding to inlined calls into the corresponding PCs for the inlined
// functions. Returns the number of frames copied to dst.
func expandInlinedFrames(dst, pcs []uintptr) int {
	cf := runtime.CallersFrames(pcs)
	var n int
	for n < len(dst) {
		f, more := cf.Next()
		// f.PC is a "call PC", but later consumers will expect
		// "return PCs"
		dst[n] = f.PC + 1
		n++
		if !more {
			break
		}
	}
	return n
}

// printCountCycleProfile outputs block profile records (for block or mutex profiles)
// as the pprof-proto format output. Translations from cycle count to time duration
// are done because The proto expects count and time (nanoseconds) instead of count
// and the number of cycles for block, contention profiles.
func printCountCycleProfile(w io.Writer, countName, cycleName string, records []profilerecord.BlockProfileRecord) error {
	// Output profile in protobuf form.
	b := newProfileBuilder(w)
	b.pbValueType(tagProfile_PeriodType, countName, "count")
	b.pb.int64Opt(tagProfile_Period, 1)
	b.pbValueType(tagProfile_SampleType, countName, "count")
	b.pbValueType(tagProfile_SampleType, cycleName, "nanoseconds")

	cpuGHz := float64(pprof_cyclesPerSecond()) / 1e9

	values := []int64{0, 0}
	var locs []uint64
	expandedStack := pprof_makeProfStack()
	for _, r := range records {
		values[0] = r.Count
		values[1] = int64(float64(r.Cycles) / cpuGHz)
		// For count profiles, all stack addresses are
		// return PCs, which is what appendLocsForStack expects.
		n := expandInlinedFrames(expandedStack, r.Stack)
		locs = b.appendLocsForStack(locs[:0], expandedStack[:n])
		b.pbSample(values, locs, nil)
	}
	b.build()
	return nil
}

// printCountProfile prints a countProfile at the specified debug level.
// The profile will be in compressed proto format unless debug is nonzero.
func printCountProfile(w io.Writer, debug int, name string, p countProfile) error {
	// Build count of each stack.
	var buf strings.Builder
	key := func(stk []uintptr, lbls *labelMap) string {
		buf.Reset()
		fmt.Fprintf(&buf, "@")
		for _, pc := range stk {
			fmt.Fprintf(&buf, " %#x", pc)
		}
		if lbls != nil {
			buf.WriteString("\n# labels: ")
			buf.WriteString(lbls.String())
		}
		return buf.String()
	}
	count := map[string]int{}
	index := map[string]int{}
	var keys []string
	n := p.Len()
	for i := 0; i < n; i++ {
		k := key(p.Stack(i), p.Label(i))
		if count[k] == 0 {
			index[k] = i
			keys = append(keys, k)
		}
		count[k]++
	}

	sort.Sort(&keysByCount{keys, count})

	if debug > 0 {
		// Print debug profile in legacy format
		tw := tabwriter.NewWriter(w, 1, 8, 1, '\t', 0)
		fmt.Fprintf(tw, "%s profile: total %d\n", name, p.Len())
		for _, k := range keys {
			fmt.Fprintf(tw, "%d %s\n", count[k], k)
			printStackRecord(tw, p.Stack(index[k]), false)
		}
		return tw.Flush()
	}

	// Output profile in protobuf form.
	b := newProfileBuilder(w)
	b.pbValueType(tagProfile_PeriodType, name, "count")
	b.pb.int64Opt(tagProfile_Period, 1)
	b.pbValueType(tagProfile_SampleType, name, "count")

	values := []int64{0}
	var locs []uint64
	for _, k := range keys {
		values[0] = int64(count[k])
		// For count profiles, all stack addresses are
		// return PCs, which is what appendLocsForStack expects.
		locs = b.appendLocsForStack(locs[:0], p.Stack(index[k]))
		idx := index[k]
		var labels func()
		if p.Label(idx) != nil {
			labels = func() {
				for _, lbl := range p.Label(idx).list {
					b.pbLabel(tagSample_Label, lbl.key, lbl.value, 0)
				}
			}
		}
		b.pbSample(values, locs, labels)
	}
	b.build()
	return nil
}

// keysByCount sorts keys with higher counts first, breaking ties by key string order.
type keysByCount struct {
	keys  []string
	count map[string]int
}

func (x *keysByCount) Len() int      { return len(x.keys) }
func (x *keysByCount) Swap(i, j int) { x.keys[i], x.keys[j] = x.keys[j], x.keys[i] }
func (x *keysByCount) Less(i, j int) bool {
	ki, kj := x.keys[i], x.keys[j]
	ci, cj := x.count[ki], x.count[kj]
	if ci != cj {
		return ci > cj
	}
	return ki < kj
}

// printStackRecord prints the function + source line information
// for a single stack trace.
func printStackRecord(w io.Writer, stk []uintptr, allFrames bool) {
	show := allFrames
	frames := runtime.CallersFrames(stk)
	for {
		frame, more := frames.Next()
		name := frame.Function
		if name == "" {
			show = true
			fmt.Fprintf(w, "#\t%#x\n", frame.PC)
		} else if name != "runtime.goexit" && (show || !strings.HasPrefix(name, "runtime.")) {
			// Hide runtime.goexit and any runtime functions at the beginning.
			// This is useful mainly for allocation traces.
			show = true
			fmt.Fprintf(w, "#\t%#x\t%s+%#x\t%s:%d\n", frame.PC, name, frame.PC-frame.Entry, frame.File, frame.Line)
		}
		if !more {
			break
		}
	}
	if !show {
		// We didn't print anything; do it again,
		// and this time include runtime functions.
		printStackRecord(w, stk, true)
		return
	}
	fmt.Fprintf(w, "\n")
}

// Interface to system profiles.

// WriteHeapProfile is shorthand for [Lookup]("heap").WriteTo(w, 0).
// It is preserved for backwards compatibility.
func WriteHeapProfile(w io.Writer) error {
	return writeHeap(w, 0)
}

// countHeap returns the number of records in the heap profile.
func countHeap() int {
	n, _ := runtime.MemProfile(nil, true)
	return n
}

// writeHeap writes the current runtime heap profile to w.
func writeHeap(w io.Writer, debug int) error {
	return writeHeapInternal(w, debug, "")
}

// writeAlloc writes the current runtime heap profile to w
// with the total allocation space as the default sample type.
func writeAlloc(w io.Writer, debug int) error {
	return writeHeapInternal(w, debug, "alloc_space")
}

func writeHeapInternal(w io.Writer, debug int, defaultSampleType string) error {
	var memStats *runtime.MemStats
	if debug != 0 {
		// Read mem stats first, so that our other allocations
		// do not appear in the statistics.
		memStats = new(runtime.MemStats)
		runtime.ReadMemStats(memStats)
	}

	// Find out how many records there are (the call
	// pprof_memProfileInternal(nil, true) below),
	// allocate that many records, and get the data.
	// There's a race—more records might be added between
	// the two calls—so allocate a few extra records for safety
	// and also try again if we're very unlucky.
	// The loop should only execute one iteration in the common case.
	var p []profilerecord.MemProfileRecord
	n, ok := pprof_memProfileInternal(nil, true)
	for {
		// Allocate room for a slightly bigger profile,
		// in case a few more entries have been added
		// since the call to MemProfile.
		p = make([]profilerecord.MemProfileRecord, n+50)
		n, ok = pprof_memProfileInternal(p, true)
		if ok {
			p = p[0:n]
			break
		}
		// Profile grew; try again.
	}

	if debug == 0 {
		return writeHeapProto(w, p, int64(runtime.MemProfileRate), defaultSampleType)
	}

	slices.SortFunc(p, func(a, b profilerecord.MemProfileRecord) int {
		return cmp.Compare(a.InUseBytes(), b.InUseBytes())
	})

	b := bufio.NewWriter(w)
	tw := tabwriter.NewWriter(b, 1, 8, 1, '\t', 0)
	w = tw

	var total runtime.MemProfileRecord
	for i := range p {
		r := &p[i]
		total.AllocBytes += r.AllocBytes
		total.AllocObjects += r.AllocObjects
		total.FreeBytes += r.FreeBytes
		total.FreeObjects += r.FreeObjects
	}

	// Technically the rate is MemProfileRate not 2*MemProfileRate,
	// but early versions of the C++ heap profiler reported 2*MemProfileRate,
	// so that's what pprof has come to expect.
	rate := 2 * runtime.MemProfileRate

	// pprof reads a profile with alloc == inuse as being a "2-column" profile
	// (objects and bytes, not distinguishing alloc from inuse),
	// but then such a profile can't be merged using pprof *.prof with
	// other 4-column profiles where alloc != inuse.
	// The easiest way to avoid this bug is to adjust allocBytes so it's never == inuseBytes.
	// pprof doesn't use these header values anymore except for checking equality.
	inUseBytes := total.InUseBytes()
	allocBytes := total.AllocBytes
	if inUseBytes == allocBytes {
		allocBytes++
	}

	fmt.Fprintf(w, "heap profile: %d: %d [%d: %d] @ heap/%d\n",
		total.InUseObjects(), inUseBytes,
		total.AllocObjects, allocBytes,
		rate)

	for i := range p {
		r := &p[i]
		fmt.Fprintf(w, "%d: %d [%d: %d] @",
			r.InUseObjects(), r.InUseBytes(),
			r.AllocObjects, r.AllocBytes)
		for _, pc := range r.Stack {
			fmt.Fprintf(w, " %#x", pc)
		}
		fmt.Fprintf(w, "\n")
		printStackRecord(w, r.Stack, false)
	}

	// Print memstats information too.
	// Pprof will ignore, but useful for people
	s := memStats
	fmt.Fprintf(w, "\n# runtime.MemStats\n")
	fmt.Fprintf(w, "# Alloc = %d\n", s.Alloc)
	fmt.Fprintf(w, "# TotalAlloc = %d\n", s.TotalAlloc)
	fmt.Fprintf(w, "# Sys = %d\n", s.Sys)
	fmt.Fprintf(w, "# Lookups = %d\n", s.Lookups)
	fmt.Fprintf(w, "# Mallocs = %d\n", s.Mallocs)
	fmt.Fprintf(w, "# Frees = %d\n", s.Frees)

	fmt.Fprintf(w, "# HeapAlloc = %d\n", s.HeapAlloc)
	fmt.Fprintf(w, "# HeapSys = %d\n", s.HeapSys)
	fmt.Fprintf(w, "# HeapIdle = %d\n", s.HeapIdle)
	fmt.Fprintf(w, "# HeapInuse = %d\n", s.HeapInuse)
	fmt.Fprintf(w, "# HeapReleased = %d\n", s.HeapReleased)
	fmt.Fprintf(w, "# HeapObjects = %d\n", s.HeapObjects)

	fmt.Fprintf(w, "# Stack = %d / %d\n", s.StackInuse, s.StackSys)
	fmt.Fprintf(w, "# MSpan = %d / %d\n", s.MSpanInuse, s.MSpanSys)
	fmt.Fprintf(w, "# MCache = %d / %d\n", s.MCacheInuse, s.MCacheSys)
	fmt.Fprintf(w, "# BuckHashSys = %d\n", s.BuckHashSys)
	fmt.Fprintf(w, "# GCSys = %d\n", s.GCSys)
	fmt.Fprintf(w, "# OtherSys = %d\n", s.OtherSys)

	fmt.Fprintf(w, "# NextGC = %d\n", s.NextGC)
	fmt.Fprintf(w, "# LastGC = %d\n", s.LastGC)
	fmt.Fprintf(w, "# PauseNs = %d\n", s.PauseNs)
	fmt.Fprintf(w, "# PauseEnd = %d\n", s.PauseEnd)
	fmt.Fprintf(w, "# NumGC = %d\n", s.NumGC)
	fmt.Fprintf(w, "# NumForcedGC = %d\n", s.NumForcedGC)
	fmt.Fprintf(w, "# GCCPUFraction = %v\n", s.GCCPUFraction)
	fmt.Fprintf(w, "# DebugGC = %v\n", s.DebugGC)

	// Also flush out MaxRSS on supported platforms.
	addMaxRSS(w)

	tw.Flush()
	return b.Flush()
}

// countThreadCreate returns the size of the current ThreadCreateProfile.
func countThreadCreate() int {
	n, _ := runtime.ThreadCreateProfile(nil)
	return n
}

// writeThreadCreate writes the current runtime ThreadCreateProfile to w.
func writeThreadCreate(w io.Writer, debug int) error {
	// Until https://golang.org/issues/6104 is addressed, wrap
	// ThreadCreateProfile because there's no point in tracking labels when we
	// don't get any stack-traces.
	return writeRuntimeProfile(w, debug, "threadcreate", func(p []profilerecord.StackRecord, _ []unsafe.Pointer) (n int, ok bool) {
		return pprof_threadCreateInternal(p)
	})
}

// countGoroutine returns the number of goroutines.
func countGoroutine() int {
	return runtime.NumGoroutine()
}

// writeGoroutine writes the current runtime GoroutineProfile to w.
func writeGoroutine(w io.Writer, debug int) error {
	if debug >= 2 {
		return writeGoroutineStacks(w)
	}
	return writeRuntimeProfile(w, debug, "goroutine", pprof_goroutineProfileWithLabels)
}

func writeGoroutineStacks(w io.Writer) error {
	// We don't know how big the buffer needs to be to collect
	// all the goroutines. Start with 1 MB and try a few times, doubling each time.
	// Give up and use a truncated trace if 64 MB is not enough.
	buf := make([]byte, 1<<20)
	for i := 0; ; i++ {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		if len(buf) >= 64<<20 {
			// Filled 64 MB - stop there.
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	_, err := w.Write(buf)
	return err
}

func writeRuntimeProfile(w io.Writer, debug int, name string, fetch func([]profilerecord.StackRecord, []unsafe.Pointer) (int, bool)) error {
	// Find out how many records there are (fetch(nil)),
	// allocate that many records, and get the data.
	// There's a race—more records might be added between
	// the two calls—so allocate a few extra records for safety
	// and also try again if we're very unlucky.
	// The loop should only execute one iteration in the common case.
	var p []profilerecord.StackRecord
	var labels []unsafe.Pointer
	n, ok := fetch(nil, nil)

	for {
		// Allocate room for a slightly bigger profile,
		// in case a few more entries have been added
		// since the call to ThreadProfile.
		p = make([]profilerecord.StackRecord, n+10)
		labels = make([]unsafe.Pointer, n+10)
		n, ok = fetch(p, labels)
		if ok {
			p = p[0:n]
			break
		}
		// Profile grew; try again.
	}

	return printCountProfile(w, debug, name, &runtimeProfile{p, labels})
}

type runtimeProfile struct {
	stk    []profilerecord.StackRecord
	labels []unsafe.Pointer
}

func (p *runtimeProfile) Len() int              { return len(p.stk) }
func (p *runtimeProfile) Stack(i int) []uintptr { return p.stk[i].Stack }
func (p *runtimeProfile) Label(i int) *labelMap { return (*labelMap)(p.labels[i]) }

var cpu struct {
	sync.Mutex
	profiling bool
	done      chan bool
}

// StartCPUProfile enables CPU profiling for the current process.
// While profiling, the profile will be buffered and written to w.
// StartCPUProfile returns an error if profiling is already enabled.
//
// On Unix-like systems, StartCPUProfile does not work by default for
// Go code built with -buildmode=c-archive or -buildmode=c-shared.
// StartCPUProfile relies on the SIGPROF signal, but that signal will
// be delivered to the main program's SIGPROF signal handler (if any)
// not to the one used by Go. To make it work, call [os/signal.Notify]
// for [syscall.SIGPROF], but note that doing so may break any profiling
// being done by the main program.
func StartCPUProfile(w io.Writer) error {
	// The runtime routines allow a variable profiling rate,
	// but in practice operating systems cannot trigger signals
	// at more than about 500 Hz, and our processing of the
	// signal is not cheap (mostly getting the stack trace).
	// 100 Hz is a reasonable choice: it is frequent enough to
	// produce useful data, rare enough not to bog down the
	// system, and a nice round number to make it easy to
	// convert sample counts to seconds. Instead of requiring
	// each client to specify the frequency, we hard code it.
	const hz = 100

	cpu.Lock()
	defer cpu.Unlock()
	if cpu.done == nil {
		cpu.done = make(chan bool)
	}
	// Double-check.
	if cpu.profiling {
		return fmt.Errorf("cpu profiling already in use")
	}
	cpu.profiling = true
	runtime.SetCPUProfileRate(hz)
	go profileWriter(w)
	return nil
}

// readProfile, provided by the runtime, returns the next chunk of
// binary CPU profiling stack trace data, blocking until data is available.
// If profiling is turned off and all the profile data accumulated while it was
// on has been returned, readProfile returns eof=true.
// The caller must save the returned data and tags before calling readProfile again.
func readProfile() (data []uint64, tags []unsafe.Pointer, eof bool)

func profileWriter(w io.Writer) {
	b := newProfileBuilder(w)
	var err error
	for {
		time.Sleep(100 * time.Millisecond)
		data, tags, eof := readProfile()
		if e := b.addCPUData(data, tags); e != nil && err == nil {
			err = e
		}
		if eof {
			break
		}
	}
	if err != nil {
		// The runtime should never produce an invalid or truncated profile.
		// It drops records that can't fit into its log buffers.
		panic("runtime/pprof: converting profile: " + err.Error())
	}
	b.build()
	cpu.done <- true
}

// StopCPUProfile stops the current CPU profile, if any.
// StopCPUProfile only returns after all the writes for the
// profile have completed.
func StopCPUProfile() {
	cpu.Lock()
	defer cpu.Unlock()

	if !cpu.profiling {
		return
	}
	cpu.profiling = false
	runtime.SetCPUProfileRate(0)
	<-cpu.done
}

// countBlock returns the number of records in the blocking profile.
func countBlock() int {
	n, _ := runtime.BlockProfile(nil)
	return n
}

// countMutex returns the number of records in the mutex profile.
func countMutex() int {
	n, _ := runtime.MutexProfile(nil)
	return n
}

// writeBlock writes the current blocking profile to w.
func writeBlock(w io.Writer, debug int) error {
	return writeProfileInternal(w, debug, "contention", pprof_blockProfileInternal)
}

// writeMutex writes the current mutex profile to w.
func writeMutex(w io.Writer, debug int) error {
	return writeProfileInternal(w, debug, "mutex", pprof_mutexProfileInternal)
}

// writeProfileInternal writes the current blocking or mutex profile depending on the passed parameters.
func writeProfileInternal(w io.Writer, debug int, name string, runtimeProfile func([]profilerecord.BlockProfileRecord) (int, bool)) error {
	var p []profilerecord.BlockProfileRecord
	n, ok := runtimeProfile(nil)
	for {
		p = make([]profilerecord.BlockProfileRecord, n+50)
		n, ok = runtimeProfile(p)
		if ok {
			p = p[:n]
			break
		}
	}

	slices.SortFunc(p, func(a, b profilerecord.BlockProfileRecord) int {
		return cmp.Compare(b.Cycles, a.Cycles)
	})

	if debug <= 0 {
		return printCountCycleProfile(w, "contentions", "delay", p)
	}

	b := bufio.NewWriter(w)
	tw := tabwriter.NewWriter(w, 1, 8, 1, '\t', 0)
	w = tw

	fmt.Fprintf(w, "--- %v:\n", name)
	fmt.Fprintf(w, "cycles/second=%v\n", pprof_cyclesPerSecond())
	if name == "mutex" {
		fmt.Fprintf(w, "sampling period=%d\n", runtime.SetMutexProfileFraction(-1))
	}
	expandedStack := pprof_makeProfStack()
	for i := range p {
		r := &p[i]
		fmt.Fprintf(w, "%v %v @", r.Cycles, r.Count)
		n := expandInlinedFrames(expandedStack, r.Stack)
		stack := expandedStack[:n]
		for _, pc := range stack {
			fmt.Fprintf(w, " %#x", pc)
		}
		fmt.Fprint(w, "\n")
		if debug > 0 {
			printStackRecord(w, stack, true)
		}
	}

	if tw != nil {
		tw.Flush()
	}
	return b.Flush()
}

//go:linkname pprof_goroutineProfileWithLabels runtime.pprof_goroutineProfileWithLabels
func pprof_goroutineProfileWithLabels(p []profilerecord.StackRecord, labels []unsafe.Pointer) (n int, ok bool)

//go:linkname pprof_cyclesPerSecond runtime/pprof.runtime_cyclesPerSecond
func pprof_cyclesPerSecond() int64

//go:linkname pprof_memProfileInternal runtime.pprof_memProfileInternal
func pprof_memProfileInternal(p []profilerecord.MemProfileRecord, inuseZero bool) (n int, ok bool)

//go:linkname pprof_blockProfileInternal runtime.pprof_blockProfileInternal
func pprof_blockProfileInternal(p []profilerecord.BlockProfileRecord) (n int, ok bool)

//go:linkname pprof_mutexProfileInternal runtime.pprof_mutexProfileInternal
func pprof_mutexProfileInternal(p []profilerecord.BlockProfileRecord) (n int, ok bool)

//go:linkname pprof_threadCreateInternal runtime.pprof_threadCreateInternal
func pprof_threadCreateInternal(p []profilerecord.StackRecord) (n int, ok bool)

//go:linkname pprof_fpunwindExpand runtime.pprof_fpunwindExpand
func pprof_fpunwindExpand(dst, src []uintptr) int

//go:linkname pprof_makeProfStack runtime.pprof_makeProfStack
func pprof_makeProfStack() []uintptr

"""



```