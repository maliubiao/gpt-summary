Response:
Let's break down the thought process for analyzing the provided Go code snippet (`go/src/runtime/extern.go`).

**1. Initial Understanding of the Context:**

* The path `go/src/runtime/extern.go` immediately suggests this file is part of the Go runtime. The `runtime` package deals with low-level operations essential for Go program execution.
* The comment at the top of the file explicitly states this and mentions interactions with the runtime system, controlling goroutines, and low-level type information. This sets the scope and hints at the functionalities within.

**2. Analyzing the File Structure and Content:**

* **Copyright and License:** Standard Go copyright and BSD license information. Not directly functional but important for legal reasons.
* **Package Comment (Doc Comment):** This is a crucial part. It describes the `runtime` package's purpose in detail. It covers:
    * Core functionality (interacting with the runtime, goroutines).
    * Connection to the `reflect` package.
    * **Environment Variables:** A significant portion of the comment is dedicated to explaining various `GODEBUG`, `GOGC`, `GOMEMLIMIT`, `GOMAXPROCS`, `GORACE`, and `GOTRACEBACK` environment variables. This immediately points to a key function of this file/package: managing runtime behavior through environment settings.
    * **Security:**  Highlights security considerations for setuid/setgid binaries.
* **Imports:** `internal/goarch` and `internal/goos`. These internal packages are likely used to get the target OS and architecture, suggesting the file might expose this information.
* **Function Declarations:**
    * `Caller(skip int)`:  Deals with retrieving information about the call stack. The comment explains `skip` and the returned values (program counter, file, line, ok).
    * `Callers(skip int, pc []uintptr)`: Another stack-related function, taking a slice to fill with program counters. The comment emphasizes using `CallersFrames` for proper interpretation due to inlining.
    * `GOROOT() string`:  Returns the Go installation root. The comment mentions environment variable lookup and deprecation warnings.
    * `Version() string`: Returns the Go build version.
    * `GOOS string` (constant): Exposes the operating system.
    * `GOARCH string` (constant): Exposes the architecture.

**3. Inferring Functionality and Purpose:**

Based on the elements above, the primary functions of `extern.go` can be deduced:

* **Exposing Runtime Information:**  Functions like `Version`, `GOOS`, `GOARCH`, and (to some extent) `GOROOT` provide access to information about the Go environment in which the program is running.
* **Stack Inspection:** `Caller` and `Callers` are clearly related to inspecting the call stack, a fundamental debugging and introspection capability.
* **Environment Variable Handling:**  The extensive documentation on environment variables strongly suggests this file (or the broader `runtime` package) is responsible for interpreting and acting upon these settings. While the code *doesn't* show the actual *parsing* logic, the documentation establishes the connection.

**4. Developing Examples (Mental or Actual Code Writing):**

* **Stack Inspection:**  A simple goroutine that calls functions would be a good example to demonstrate `Caller` and `Callers`. The output would show the file and line number of the calls.
* **Environment Variables:**  Demonstrating how changing `GOGC` or `GOTRACEBACK` affects program behavior (GC frequency, traceback output) would be a good way to illustrate this functionality. This requires running the program with different environment settings.
* **Version/OS/Arch:** These are straightforward to demonstrate by simply printing their values.

**5. Considering Edge Cases and Potential Mistakes:**

* **Incorrect `skip` value in `Caller`/`Callers`:**  The documentation mentions the meaning of `skip`. A common mistake would be to misunderstand how many frames to skip.
* **Misinterpreting `Callers` output without `CallersFrames`:** The documentation specifically warns against this due to inlining.
* **Relying on deprecated `GOROOT()` for finding the Go installation:** The deprecation warning highlights a potential error.

**6. Structuring the Answer (in Chinese as requested):**

* Start with a high-level summary of the file's purpose.
* Detail the functionality based on the analysis (stack inspection, environment variables, version info, etc.).
* Provide Go code examples for each key functionality, including assumed inputs and outputs to illustrate the behavior.
* If applicable, elaborate on command-line parameter handling (though this file primarily deals with *environment* variables).
* Explain potential mistakes users might make.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the specific function implementations. However, the extensive documentation on environment variables is a strong indicator of a key function, even if the parsing code isn't directly in this snippet.
* I need to ensure the examples are clear and demonstrate the intended functionality. Simply printing values might not be enough; showing the *effect* of a function or environment variable is better.
* It's important to stick to the prompt's requirements, especially the language (Chinese) and the specific points to address.

This structured thought process, going from general understanding to specific code analysis and example creation, allows for a comprehensive and accurate answer to the prompt. The emphasis on the documentation within the code is crucial for understanding the higher-level purpose and functionality.这个 `go/src/runtime/extern.go` 文件是 Go 运行时库的一部分，它主要定义了一些与外部环境交互的函数和常量，以及一些用于获取运行时状态信息的接口。

以下是它包含的主要功能：

**1. 获取调用栈信息:**

* **`Caller(skip int) (pc uintptr, file string, line int, ok bool)`:**  这个函数用于获取调用栈中指定层级的调用者的信息。
    * `skip`:  指定要跳过的栈帧数，0 表示调用 `Caller` 的函数，1 表示调用 `Caller` 的函数的调用者，以此类推。
    * 返回值：
        * `pc`: 程序计数器，指向被调用函数的指令地址。
        * `file`: 源文件名。
        * `line`: 源文件中的行号。
        * `ok`:  一个布尔值，如果成功获取信息则为 `true`，否则为 `false`。
* **`Callers(skip int, pc []uintptr) int`:** 这个函数用于获取调用栈中指定层级之后的所有函数的程序计数器。
    * `skip`: 指定要跳过的栈帧数，0 表示 `Callers` 自身，1 表示 `Callers` 的调用者，以此类推。
    * `pc`: 一个 `uintptr` 类型的切片，用于存储获取到的程序计数器。
    * 返回值：实际写入 `pc` 切片的程序计数器数量。

**示例代码说明 `Caller` 和 `Callers` 的功能:**

```go
package main

import (
	"fmt"
	"runtime"
)

func innerFunc() {
	pc, file, line, ok := runtime.Caller(0) // 获取当前函数的信息
	if ok {
		f := runtime.FuncForPC(pc)
		fmt.Printf("Caller(0) in innerFunc: %s, file: %s, line: %d\n", f.Name(), file, line)
	}

	pc1, file1, line1, ok1 := runtime.Caller(1) // 获取调用 innerFunc 的函数的信息
	if ok1 {
		f := runtime.FuncForPC(pc1)
		fmt.Printf("Caller(1) in innerFunc: %s, file: %s, line: %d\n", f.Name(), file1, line1)
	}

	pcs := make([]uintptr, 10)
	n := runtime.Callers(0, pcs) // 获取从当前函数开始的 10 个调用栈帧的 PC
	fmt.Printf("Callers(0) in innerFunc: %d PCs captured\n", n)
	for i := 0; i < n; i++ {
		f := runtime.FuncForPC(pcs[i])
		if f != nil {
			fmt.Printf("  PC %d: %s\n", i, f.Name())
		}
	}
}

func outerFunc() {
	innerFunc()
}

func main() {
	outerFunc()
}
```

**假设的输出:**

```
Caller(0) in innerFunc: main.innerFunc, file: /path/to/your/file.go, line: 9
Caller(1) in innerFunc: main.outerFunc, file: /path/to/your/file.go, line: 19
Callers(0) in innerFunc: 3 PCs captured
  PC 0: main.innerFunc
  PC 1: main.outerFunc
  PC 2: main.main
```

**2. 获取 Go 环境信息:**

* **`GOROOT() string`:** 返回 Go 安装的根目录。它会先查找 `GOROOT` 环境变量，如果未设置则返回 Go 构建时使用的根目录。**注意：文档中已标记为 `Deprecated`，建议使用 `go env GOROOT` 命令获取。**
* **`buildVersion string` (变量):**  存储 Go 构建时的版本字符串。
* **`Version() string`:** 返回 Go 的版本字符串，与 `buildVersion` 的值相同。
* **`GOOS string` (常量):**  表示运行程序的操作系统目标，例如 "linux", "windows", "darwin" 等。
* **`GOARCH string` (常量):** 表示运行程序的架构目标，例如 "amd64", "386", "arm" 等。

**示例代码说明获取 Go 环境信息:**

```go
package main

import (
	"fmt"
	"runtime"
)

func main() {
	fmt.Println("GOROOT:", runtime.GOROOT())
	fmt.Println("Version:", runtime.Version())
	fmt.Println("GOOS:", runtime.GOOS)
	fmt.Println("GOARCH:", runtime.GOARCH)
}
```

**假设的输出:**

```
GOROOT: /usr/local/go  (或者你系统中 Go 的安装路径)
Version: go1.21.0 (或者你使用的 Go 版本)
GOOS: linux
GOARCH: amd64
```

**3. 与环境变量相关的说明（虽然代码中没有直接处理，但文档详细介绍了）：**

`extern.go` 文件本身不直接处理命令行参数，但它所属的 `runtime` 包会读取和使用大量的环境变量来控制 Go 程序的运行时行为。这些环境变量在文档中被详细列出和解释，例如：

* **`GOGC`:** 设置垃圾回收的初始目标百分比。
* **`GOMEMLIMIT`:** 设置运行时内存的软限制。
* **`GODEBUG`:**  控制运行时内部的调试变量，例如启用/禁用特定的 GC 行为、CPU 特性等。`GODEBUG` 的值是一个逗号分隔的 `name=val` 对列表。例如，`GODEBUG=gctrace=1` 会在每次垃圾回收时输出统计信息。
* **`GOMAXPROCS`:**  限制可以同时执行用户级 Go 代码的操作系统线程数。
* **`GOTRACEBACK`:** 控制程序发生 panic 或运行时错误时输出的堆栈跟踪信息量。

**`GODEBUG` 环境变量的详细处理:**

`GODEBUG` 环境变量允许用户在不重新编译程序的情况下调整 Go 运行时的某些行为。它的格式是 `name1=value1,name2=value2,...`。运行时会解析这个字符串，并根据 `name` 设置相应的内部标志或变量。

例如，当设置 `GODEBUG=gctrace=1` 时，运行时会在垃圾回收发生时向标准错误输出一行信息，包含内存回收量、暂停时间等。

**使用者易犯错的点:**

* **混淆 `Caller` 和 `Callers` 的 `skip` 参数含义:** `Caller(0)` 获取调用者信息，而 `Callers(0, ...)` 获取的是当前函数的信息开始的栈帧。
* **错误地解析 `Callers` 返回的程序计数器:**  文档明确指出应该使用 `runtime.CallersFrames` 来将程序计数器转换为更友好的信息，因为 `FuncForPC` 可能无法处理内联函数的情况。直接迭代 `Callers` 返回的 `uintptr` 切片并使用 `FuncForPC` 可能会导致不准确的结果。
* **过度依赖 `GOROOT()`:**  由于 `GOROOT()` 的返回值可能不准确（特别是当二进制文件被复制到其他机器时），建议使用 `go env GOROOT` 命令来获取可靠的 Go 根目录信息。
* **不理解 `GODEBUG` 环境变量的影响:** 随意修改 `GODEBUG` 的值可能会对程序的性能和行为产生意想不到的影响。应该仔细阅读文档，了解每个选项的具体含义。例如，禁用 GC (`GOGC=off`) 可能导致内存泄漏。
* **在生产环境中使用调试相关的 `GODEBUG` 选项:**  某些 `GODEBUG` 选项（例如 `efence=1`）会显著降低程序性能，只应该在开发和调试阶段使用。
* **忽视 setuid/setgid 环境下的安全限制:**  当程序以 setuid/setgid 权限运行时，Go 运行时会出于安全考虑限制某些行为，例如 `GOTRACEBACK` 环境变量会被强制设置为 `none`。

总而言之，`go/src/runtime/extern.go` 文件是 Go 运行时与外部环境交互的关键桥梁，它提供了获取调用栈信息、Go 环境信息等功能，并且通过环境变量为用户提供了灵活调整运行时行为的能力。理解这些功能对于进行 Go 程序的调试、性能分析以及深入理解 Go 运行时机制至关重要。

Prompt: 
```
这是路径为go/src/runtime/extern.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package runtime contains operations that interact with Go's runtime system,
such as functions to control goroutines. It also includes the low-level type information
used by the reflect package; see [reflect]'s documentation for the programmable
interface to the run-time type system.

# Environment Variables

The following environment variables ($name or %name%, depending on the host
operating system) control the run-time behavior of Go programs. The meanings
and use may change from release to release.

The GOGC variable sets the initial garbage collection target percentage.
A collection is triggered when the ratio of freshly allocated data to live data
remaining after the previous collection reaches this percentage. The default
is GOGC=100. Setting GOGC=off disables the garbage collector entirely.
[runtime/debug.SetGCPercent] allows changing this percentage at run time.

The GOMEMLIMIT variable sets a soft memory limit for the runtime. This memory limit
includes the Go heap and all other memory managed by the runtime, and excludes
external memory sources such as mappings of the binary itself, memory managed in
other languages, and memory held by the operating system on behalf of the Go
program. GOMEMLIMIT is a numeric value in bytes with an optional unit suffix.
The supported suffixes include B, KiB, MiB, GiB, and TiB. These suffixes
represent quantities of bytes as defined by the IEC 80000-13 standard. That is,
they are based on powers of two: KiB means 2^10 bytes, MiB means 2^20 bytes,
and so on. The default setting is [math.MaxInt64], which effectively disables the
memory limit. [runtime/debug.SetMemoryLimit] allows changing this limit at run
time.

The GODEBUG variable controls debugging variables within the runtime.
It is a comma-separated list of name=val pairs setting these named variables:

	clobberfree: setting clobberfree=1 causes the garbage collector to
	clobber the memory content of an object with bad content when it frees
	the object.

	cpu.*: cpu.all=off disables the use of all optional instruction set extensions.
	cpu.extension=off disables use of instructions from the specified instruction set extension.
	extension is the lower case name for the instruction set extension such as sse41 or avx
	as listed in internal/cpu package. As an example cpu.avx=off disables runtime detection
	and thereby use of AVX instructions.

	cgocheck: setting cgocheck=0 disables all checks for packages
	using cgo to incorrectly pass Go pointers to non-Go code.
	Setting cgocheck=1 (the default) enables relatively cheap
	checks that may miss some errors. A more complete, but slow,
	cgocheck mode can be enabled using GOEXPERIMENT (which
	requires a rebuild), see https://pkg.go.dev/internal/goexperiment for details.

	disablethp: setting disablethp=1 on Linux disables transparent huge pages for the heap.
	It has no effect on other platforms. disablethp is meant for compatibility with versions
	of Go before 1.21, which stopped working around a Linux kernel default that can result
	in significant memory overuse. See https://go.dev/issue/64332. This setting will be
	removed in a future release, so operators should tweak their Linux configuration to suit
	their needs before then. See https://go.dev/doc/gc-guide#Linux_transparent_huge_pages.

	dontfreezetheworld: by default, the start of a fatal panic or throw
	"freezes the world", preempting all threads to stop all running
	goroutines, which makes it possible to traceback all goroutines, and
	keeps their state close to the point of panic. Setting
	dontfreezetheworld=1 disables this preemption, allowing goroutines to
	continue executing during panic processing. Note that goroutines that
	naturally enter the scheduler will still stop. This can be useful when
	debugging the runtime scheduler, as freezetheworld perturbs scheduler
	state and thus may hide problems.

	efence: setting efence=1 causes the allocator to run in a mode
	where each object is allocated on a unique page and addresses are
	never recycled.

	gccheckmark: setting gccheckmark=1 enables verification of the
	garbage collector's concurrent mark phase by performing a
	second mark pass while the world is stopped.  If the second
	pass finds a reachable object that was not found by concurrent
	mark, the garbage collector will panic.

	gcpacertrace: setting gcpacertrace=1 causes the garbage collector to
	print information about the internal state of the concurrent pacer.

	gcshrinkstackoff: setting gcshrinkstackoff=1 disables moving goroutines
	onto smaller stacks. In this mode, a goroutine's stack can only grow.

	gcstoptheworld: setting gcstoptheworld=1 disables concurrent garbage collection,
	making every garbage collection a stop-the-world event. Setting gcstoptheworld=2
	also disables concurrent sweeping after the garbage collection finishes.

	gctrace: setting gctrace=1 causes the garbage collector to emit a single line to standard
	error at each collection, summarizing the amount of memory collected and the
	length of the pause. The format of this line is subject to change. Included in
	the explanation below is also the relevant runtime/metrics metric for each field.
	Currently, it is:
		gc # @#s #%: #+#+# ms clock, #+#/#/#+# ms cpu, #->#-># MB, # MB goal, # MB stacks, #MB globals, # P
	where the fields are as follows:
		gc #         the GC number, incremented at each GC
		@#s          time in seconds since program start
		#%           percentage of time spent in GC since program start
		#+...+#      wall-clock/CPU times for the phases of the GC
		#->#-># MB   heap size at GC start, at GC end, and live heap, or /gc/scan/heap:bytes
		# MB goal    goal heap size, or /gc/heap/goal:bytes
		# MB stacks  estimated scannable stack size, or /gc/scan/stack:bytes
		# MB globals scannable global size, or /gc/scan/globals:bytes
		# P          number of processors used, or /sched/gomaxprocs:threads
	The phases are stop-the-world (STW) sweep termination, concurrent
	mark and scan, and STW mark termination. The CPU times
	for mark/scan are broken down in to assist time (GC performed in
	line with allocation), background GC time, and idle GC time.
	If the line ends with "(forced)", this GC was forced by a
	runtime.GC() call.

	harddecommit: setting harddecommit=1 causes memory that is returned to the OS to
	also have protections removed on it. This is the only mode of operation on Windows,
	but is helpful in debugging scavenger-related issues on other platforms. Currently,
	only supported on Linux.

	inittrace: setting inittrace=1 causes the runtime to emit a single line to standard
	error for each package with init work, summarizing the execution time and memory
	allocation. No information is printed for inits executed as part of plugin loading
	and for packages without both user defined and compiler generated init work.
	The format of this line is subject to change. Currently, it is:
		init # @#ms, # ms clock, # bytes, # allocs
	where the fields are as follows:
		init #      the package name
		@# ms       time in milliseconds when the init started since program start
		# clock     wall-clock time for package initialization work
		# bytes     memory allocated on the heap
		# allocs    number of heap allocations

	madvdontneed: setting madvdontneed=0 will use MADV_FREE
	instead of MADV_DONTNEED on Linux when returning memory to the
	kernel. This is more efficient, but means RSS numbers will
	drop only when the OS is under memory pressure. On the BSDs and
	Illumos/Solaris, setting madvdontneed=1 will use MADV_DONTNEED instead
	of MADV_FREE. This is less efficient, but causes RSS numbers to drop
	more quickly.

	memprofilerate: setting memprofilerate=X will update the value of runtime.MemProfileRate.
	When set to 0 memory profiling is disabled.  Refer to the description of
	MemProfileRate for the default value.

	profstackdepth: profstackdepth=128 (the default) will set the maximum stack
	depth used by all pprof profilers except for the CPU profiler to 128 frames.
	Stack traces that exceed this limit will be truncated to the limit starting
	from the leaf frame. Setting profstackdepth to any value above 1024 will
	silently default to 1024. Future versions of Go may remove this limitation
	and extend profstackdepth to apply to the CPU profiler and execution tracer.

	pagetrace: setting pagetrace=/path/to/file will write out a trace of page events
	that can be viewed, analyzed, and visualized using the x/debug/cmd/pagetrace tool.
	Build your program with GOEXPERIMENT=pagetrace to enable this functionality. Do not
	enable this functionality if your program is a setuid binary as it introduces a security
	risk in that scenario. Currently not supported on Windows, plan9 or js/wasm. Setting this
	option for some applications can produce large traces, so use with care.

	panicnil: setting panicnil=1 disables the runtime error when calling panic with nil
	interface value or an untyped nil.

	runtimecontentionstacks: setting runtimecontentionstacks=1 enables inclusion of call stacks
	related to contention on runtime-internal locks in the "mutex" profile, subject to the
	MutexProfileFraction setting. When runtimecontentionstacks=0, contention on
	runtime-internal locks will report as "runtime._LostContendedRuntimeLock". When
	runtimecontentionstacks=1, the call stacks will correspond to the unlock call that released
	the lock. But instead of the value corresponding to the amount of contention that call
	stack caused, it corresponds to the amount of time the caller of unlock had to wait in its
	original call to lock. A future release is expected to align those and remove this setting.

	invalidptr: invalidptr=1 (the default) causes the garbage collector and stack
	copier to crash the program if an invalid pointer value (for example, 1)
	is found in a pointer-typed location. Setting invalidptr=0 disables this check.
	This should only be used as a temporary workaround to diagnose buggy code.
	The real fix is to not store integers in pointer-typed locations.

	sbrk: setting sbrk=1 replaces the memory allocator and garbage collector
	with a trivial allocator that obtains memory from the operating system and
	never reclaims any memory.

	scavtrace: setting scavtrace=1 causes the runtime to emit a single line to standard
	error, roughly once per GC cycle, summarizing the amount of work done by the
	scavenger as well as the total amount of memory returned to the operating system
	and an estimate of physical memory utilization. The format of this line is subject
	to change, but currently it is:
		scav # KiB work (bg), # KiB work (eager), # KiB total, #% util
	where the fields are as follows:
		# KiB work (bg)    the amount of memory returned to the OS in the background since
		                   the last line
		# KiB work (eager) the amount of memory returned to the OS eagerly since the last line
		# KiB now          the amount of address space currently returned to the OS
		#% util            the fraction of all unscavenged heap memory which is in-use
	If the line ends with "(forced)", then scavenging was forced by a
	debug.FreeOSMemory() call.

	scheddetail: setting schedtrace=X and scheddetail=1 causes the scheduler to emit
	detailed multiline info every X milliseconds, describing state of the scheduler,
	processors, threads and goroutines.

	schedtrace: setting schedtrace=X causes the scheduler to emit a single line to standard
	error every X milliseconds, summarizing the scheduler state.

	tracebackancestors: setting tracebackancestors=N extends tracebacks with the stacks at
	which goroutines were created, where N limits the number of ancestor goroutines to
	report. This also extends the information returned by runtime.Stack.
	Setting N to 0 will report no ancestry information.

	tracefpunwindoff: setting tracefpunwindoff=1 forces the execution tracer to
	use the runtime's default stack unwinder instead of frame pointer unwinding.
	This increases tracer overhead, but could be helpful as a workaround or for
	debugging unexpected regressions caused by frame pointer unwinding.

	traceadvanceperiod: the approximate period in nanoseconds between trace generations. Only
	applies if a program is built with GOEXPERIMENT=exectracer2. Used primarily for testing
	and debugging the execution tracer.

	tracecheckstackownership: setting tracecheckstackownership=1 enables a debug check in the
	execution tracer to double-check stack ownership before taking a stack trace.

	asyncpreemptoff: asyncpreemptoff=1 disables signal-based
	asynchronous goroutine preemption. This makes some loops
	non-preemptible for long periods, which may delay GC and
	goroutine scheduling. This is useful for debugging GC issues
	because it also disables the conservative stack scanning used
	for asynchronously preempted goroutines.

The [net] and [net/http] packages also refer to debugging variables in GODEBUG.
See the documentation for those packages for details.

The GOMAXPROCS variable limits the number of operating system threads that
can execute user-level Go code simultaneously. There is no limit to the number of threads
that can be blocked in system calls on behalf of Go code; those do not count against
the GOMAXPROCS limit. This package's [GOMAXPROCS] function queries and changes
the limit.

The GORACE variable configures the race detector, for programs built using -race.
See the [Race Detector article] for details.

The GOTRACEBACK variable controls the amount of output generated when a Go
program fails due to an unrecovered panic or an unexpected runtime condition.
By default, a failure prints a stack trace for the current goroutine,
eliding functions internal to the run-time system, and then exits with exit code 2.
The failure prints stack traces for all goroutines if there is no current goroutine
or the failure is internal to the run-time.
GOTRACEBACK=none omits the goroutine stack traces entirely.
GOTRACEBACK=single (the default) behaves as described above.
GOTRACEBACK=all adds stack traces for all user-created goroutines.
GOTRACEBACK=system is like “all” but adds stack frames for run-time functions
and shows goroutines created internally by the run-time.
GOTRACEBACK=crash is like “system” but crashes in an operating system-specific
manner instead of exiting. For example, on Unix systems, the crash raises
SIGABRT to trigger a core dump.
GOTRACEBACK=wer is like “crash” but doesn't disable Windows Error Reporting (WER).
For historical reasons, the GOTRACEBACK settings 0, 1, and 2 are synonyms for
none, all, and system, respectively.
The [runtime/debug.SetTraceback] function allows increasing the
amount of output at run time, but it cannot reduce the amount below that
specified by the environment variable.

The GOARCH, GOOS, GOPATH, and GOROOT environment variables complete
the set of Go environment variables. They influence the building of Go programs
(see [cmd/go] and [go/build]).
GOARCH, GOOS, and GOROOT are recorded at compile time and made available by
constants or functions in this package, but they do not influence the execution
of the run-time system.

# Security

On Unix platforms, Go's runtime system behaves slightly differently when a
binary is setuid/setgid or executed with setuid/setgid-like properties, in order
to prevent dangerous behaviors. On Linux this is determined by checking for the
AT_SECURE flag in the auxiliary vector, on the BSDs and Solaris/Illumos it is
determined by checking the issetugid syscall, and on AIX it is determined by
checking if the uid/gid match the effective uid/gid.

When the runtime determines the binary is setuid/setgid-like, it does three main
things:
  - The standard input/output file descriptors (0, 1, 2) are checked to be open.
    If any of them are closed, they are opened pointing at /dev/null.
  - The value of the GOTRACEBACK environment variable is set to 'none'.
  - When a signal is received that terminates the program, or the program
    encounters an unrecoverable panic that would otherwise override the value
    of GOTRACEBACK, the goroutine stack, registers, and other memory related
    information are omitted.

[Race Detector article]: https://go.dev/doc/articles/race_detector
*/
package runtime

import (
	"internal/goarch"
	"internal/goos"
)

// Caller reports file and line number information about function invocations on
// the calling goroutine's stack. The argument skip is the number of stack frames
// to ascend, with 0 identifying the caller of Caller. (For historical reasons the
// meaning of skip differs between Caller and [Callers].) The return values report
// the program counter, the file name (using forward slashes as path separator, even
// on Windows), and the line number within the file of the corresponding call.
// The boolean ok is false if it was not possible to recover the information.
func Caller(skip int) (pc uintptr, file string, line int, ok bool) {
	rpc := make([]uintptr, 1)
	n := callers(skip+1, rpc)
	if n < 1 {
		return
	}
	frame, _ := CallersFrames(rpc).Next()
	return frame.PC, frame.File, frame.Line, frame.PC != 0
}

// Callers fills the slice pc with the return program counters of function invocations
// on the calling goroutine's stack. The argument skip is the number of stack frames
// to skip before recording in pc, with 0 identifying the frame for Callers itself and
// 1 identifying the caller of Callers.
// It returns the number of entries written to pc.
//
// To translate these PCs into symbolic information such as function
// names and line numbers, use [CallersFrames]. CallersFrames accounts
// for inlined functions and adjusts the return program counters into
// call program counters. Iterating over the returned slice of PCs
// directly is discouraged, as is using [FuncForPC] on any of the
// returned PCs, since these cannot account for inlining or return
// program counter adjustment.
func Callers(skip int, pc []uintptr) int {
	// runtime.callers uses pc.array==nil as a signal
	// to print a stack trace. Pick off 0-length pc here
	// so that we don't let a nil pc slice get to it.
	if len(pc) == 0 {
		return 0
	}
	return callers(skip, pc)
}

var defaultGOROOT string // set by cmd/link

// GOROOT returns the root of the Go tree. It uses the
// GOROOT environment variable, if set at process start,
// or else the root used during the Go build.
//
// Deprecated: The root used during the Go build will not be
// meaningful if the binary is copied to another machine.
// Use the system path to locate the “go” binary, and use
// “go env GOROOT” to find its GOROOT.
func GOROOT() string {
	s := gogetenv("GOROOT")
	if s != "" {
		return s
	}
	return defaultGOROOT
}

// buildVersion is the Go tree's version string at build time.
//
// If any GOEXPERIMENTs are set to non-default values, it will include
// "X:<GOEXPERIMENT>".
//
// This is set by the linker.
//
// This is accessed by "go version <binary>".
var buildVersion string

// Version returns the Go tree's version string.
// It is either the commit hash and date at the time of the build or,
// when possible, a release tag like "go1.3".
func Version() string {
	return buildVersion
}

// GOOS is the running program's operating system target:
// one of darwin, freebsd, linux, and so on.
// To view possible combinations of GOOS and GOARCH, run "go tool dist list".
const GOOS string = goos.GOOS

// GOARCH is the running program's architecture target:
// one of 386, amd64, arm, s390x, and so on.
const GOARCH string = goarch.GOARCH

"""



```