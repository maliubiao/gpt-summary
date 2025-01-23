Response:
Let's break down the thought process for analyzing the provided `runtime.go` snippet.

1. **Identify the Core Functionality:** The first step is to skim through the code and comments to get a general idea of what it's doing. Keywords like "ticks," "nanotime," "cputicks," "GODEBUG," "crash output," and "auxv" jump out. This suggests the code deals with:
    * Time measurement (CPU ticks, nanoseconds).
    * Environment variables (specifically `GODEBUG`).
    * Handling crashes and error output.
    * System-level information (auxiliary vector).

2. **Analyze Individual Components:** Now, let's look at each major section or variable:

    * **`ticksType` and related functions (`init`, `ticksPerSecond`):**  The comments are very helpful here. It's clearly about measuring CPU ticks and converting them to nanoseconds. The `ticksPerSecond` function calculates a conversion rate, acknowledging potential inaccuracies and emphasizing its suitability for durations rather than precise timestamps. The `minTimeForTicksPerSecond` constant further reinforces this by setting a minimum measurement period for accuracy.

    * **`envs` and `argslice` with `syscall_runtime_envs` and `os_runtime_args`:**  The `//go:linkname` directives are strong hints. These variables and functions are providing the Go runtime's view of environment variables and command-line arguments to the `syscall` and `os` packages. This is a way for the runtime to manage and control what these lower-level packages see.

    * **`syscall_Exit`:** This is straightforward. It's a runtime-level wrapper around the system's `exit` call.

    * **`godebug` related variables and functions:** The `godebug` prefix and comments about `internal/godebug` point to the implementation of the `GODEBUG` environment variable. The functions `godebug_setUpdate`, `godebug_setNewIncNonDefault`, `godebugNotify`, `syscall_runtimeSetenv`, and `syscall_runtimeUnsetenv` clearly manage the setting and notification of `GODEBUG` changes. The `godebugInc` struct seems like a way to track the usage of specific `GODEBUG` settings.

    * **`writeErrStr` and `writeErrData`:** These functions handle writing error messages to standard error (and potentially a crash output file). The `crashFD` variable and `setCrashFD` function are involved in redirecting crash output.

    * **`auxv` and `getAuxv`:** The comments explicitly state this is related to system information and is used by packages like `golang.org/x/sys/cpu`. The `//go:linkname` again confirms its role in bridging the runtime with external packages.

    * **`zeroVal`:** Similar to `auxv`, the comments and `//go:linkname` indicate its use by the `reflect` package for providing a zero value.

3. **Infer Go Features:**  Based on the identified functionality, we can infer which Go features are being implemented:

    * **Time Measurement:** The `ticks` and related functions directly implement time measurement functionalities accessible through packages like `time`.
    * **Environment Variables and Command-Line Arguments:**  The `envs` and `argslice` sections implement the underlying mechanism for `os.Environ()` and `os.Args`.
    * **Graceful Exit:** `syscall_Exit` is the low-level implementation of `os.Exit()`.
    * **`GODEBUG` Environment Variable:** The `godebug` section provides the core logic for the `GODEBUG` mechanism, which allows for runtime configuration and debugging of various Go features.
    * **Handling Fatal Errors/Panics:** `writeErrStr`, `writeErrData`, `crashFD`, and `setCrashFD` are involved in the process of reporting and potentially redirecting output during panics or fatal errors.
    * **Accessing System Information:** `auxv` and `getAuxv` provide a way for Go programs to access system-level information.
    * **Reflection:** `zeroVal` is a low-level detail supporting the `reflect` package.

4. **Provide Code Examples:** For the more prominent features (time and `GODEBUG`), providing simple Go code examples helps illustrate their usage. The key is to choose examples that directly relate to the functionality observed in the `runtime.go` snippet.

5. **Consider Command-Line Arguments:**  While the code doesn't directly *parse* command-line arguments, it *stores* them in `argslice`. So, it's important to mention how these arguments are typically provided to a Go program. The `GODEBUG` variable itself is a form of command-line/environment configuration.

6. **Identify Potential Pitfalls:** Think about how developers might misuse the features implemented by this code. For `ticksPerSecond`, the comment about its inaccuracy for timestamps is the main pitfall. For `GODEBUG`, misunderstanding its effects or using it without proper context is a potential issue.

7. **Structure the Answer:**  Organize the findings logically. Start with a summary of the overall purpose, then detail each functional area with explanations, code examples, and potential pitfalls. Use clear headings and formatting to improve readability.

8. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. For example, make sure to explicitly state the assumptions made during code reasoning (like the behavior of `nanotime` and `cputicks`).

By following this systematic approach, we can effectively analyze the provided Go runtime code snippet and provide a comprehensive and informative answer.
这段代码是 Go 语言运行时（runtime）包 `runtime.go` 文件的一部分，它包含了 Go 语言程序运行时的核心功能。以下是其主要功能和相关解释：

**1. 时间相关的测量和转换 (基于 CPU ticks 和纳秒):**

*   **`ticksType` 结构体和相关函数 (`init`, `ticksPerSecond`)**: 这部分代码实现了基于 CPU ticks (由 `cputicks()` 获取) 和纳秒时间 (由 `nanotime()` 获取) 之间转换的功能。
    *   `ticksType` 结构体用于存储启动时的 CPU ticks 和纳秒时间，以及计算出的转换率。
    *   `init()` 方法用于初始化 `ticks`，记录初始的 CPU ticks 和纳秒时间，作为后续计算转换率的基础。
    *   `ticksPerSecond()` 函数是核心，它返回 CPU ticks 到纳秒的转换率。为了保证一定的准确性，它会等待一段时间，直到纳秒时间的变化足够大，然后使用浮点数计算转换率，避免溢出。这个转换率主要用于计算时间间隔，而非精确的时间戳。

    **推断的 Go 语言功能:** 这部分代码是 Go 语言中与时间测量和性能分析相关的底层实现。虽然用户代码不会直接使用 `cputicks()`, 但像 `time` 包中的某些函数，以及 `runtime/pprof` 包在进行性能分析时，可能会依赖于这种底层的 ticks 转换。

    **Go 代码举例:**

    ```go
    package main

    import (
        "fmt"
        "runtime"
        "time"
    )

    func main() {
        // 注意: 这里我们无法直接调用 runtime 包中未公开的 ticksPerSecond
        // 但可以观察 time 包和 pprof 的行为，推断其使用。

        start := time.Now()
        // 模拟一段耗时操作
        time.Sleep(10 * time.Millisecond)
        end := time.Now()
        duration := end.Sub(start)

        // pprof 可以利用 ticksPerSecond 来分析 CPU 消耗
        // 可以通过运行程序并生成 pprof 文件来观察

        fmt.Printf("耗时: %v\n", duration)
        // 在某些情况下，time 包内部可能会用到更底层的 ticks 相关的机制
    }
    ```

    **假设的输入与输出:** 上述代码的输出会显示 `time.Sleep` 所消耗的时间，例如 `耗时: 10.00xxxx ms`。  `runtime.ticksPerSecond()` 的目的是提供一个转换因子，使得这种时间间隔的计算在底层能够利用 CPU ticks 这样的高精度计数器。

**2. 访问环境变量和命令行参数:**

*   **`envs` 和 `argslice` 变量:**  这两个变量分别存储了 Go 程序的当前环境变量和命令行参数。
*   **`syscall_runtime_envs()` 和 `os_runtime_args()` 函数:** 这两个函数通过 `//go:linkname` 指令与 `syscall` 和 `os` 标准库包中的函数关联，使得 `syscall` 和 `os` 包可以访问到运行时维护的环境变量和命令行参数。

    **推断的 Go 语言功能:** 这部分代码是 `os` 包中 `os.Environ()` 和 `os.Args` 功能的底层实现。

    **Go 代码举例:**

    ```go
    package main

    import (
        "fmt"
        "os"
    )

    func main() {
        fmt.Println("环境变量:")
        for _, env := range os.Environ() {
            fmt.Println(env)
        }

        fmt.Println("\n命令行参数:")
        for i, arg := range os.Args {
            fmt.Printf("参数 %d: %s\n", i, arg)
        }
    }
    ```

    **假设的输入与输出:** 如果运行程序时设置了环境变量 `MY_VAR=test`，并带有命令行参数 `arg1 arg2`，则输出可能如下：

    ```
    环境变量:
    ...
    MY_VAR=test
    ...

    命令行参数:
    参数 0: /path/to/your/executable  // 可执行文件路径
    参数 1: arg1
    参数 2: arg2
    ```

**3. 程序退出:**

*   **`syscall_Exit()` 函数:**  这个函数通过 `//go:linkname` 指令与 `syscall.Exit()` 关联，并最终调用底层的 `exit()` 系统调用来终止程序。

    **推断的 Go 语言功能:** 这是 `os.Exit()` 函数的底层实现。

    **Go 代码举例:**

    ```go
    package main

    import (
        "fmt"
        "os"
    )

    func main() {
        fmt.Println("程序即将退出")
        os.Exit(1) // 退出码为 1
    }
    ```

    **假设的输入与输出:** 运行该程序会输出 "程序即将退出"，然后程序会立即终止，并且可以通过检查程序的退出状态码看到 `1`。

**4. `GODEBUG` 环境变量处理:**

*   **`godebugDefault`, `godebugUpdate`, `godebugEnv`, `godebugNewIncNonDefault` 变量:** 这些变量用于存储 `GODEBUG` 环境变量的默认值、更新回调函数、当前值等信息。
*   **`godebug_setUpdate()`, `godebug_setNewIncNonDefault()`, `godebugNotify()`, `syscall_runtimeSetenv()`, `syscall_runtimeUnsetenv()` 函数:** 这些函数共同实现了对 `GODEBUG` 环境变量的动态管理和通知机制。当 `GODEBUG` 环境变量被设置或取消设置时，会调用相应的 C 函数 (`setenv_c`, `unsetenv_c`)，并通知相关的回调函数 (`godebugUpdate`)。`godebugInc` 结构体及其方法用于跟踪 `GODEBUG` 中特定选项的使用情况。

    **推断的 Go 语言功能:** 这部分代码实现了 Go 语言的 `GODEBUG` 环境变量功能，允许用户在运行时调整 Go 程序的某些行为，用于调试或性能调优。

    **Go 代码举例:**

    ```go
    package main

    import (
        "fmt"
        "os"
        "runtime/debug"
    )

    func main() {
        // 可以通过 GODEBUG 环境变量影响程序的行为
        // 例如，禁用垃圾回收器的某些优化
        fmt.Println("当前 GODEBUG:", os.Getenv("GODEBUG"))

        // 某些 debug 包的功能会受到 GODEBUG 的影响
        debug.SetGCPercent(-1) // 禁用 GC

        fmt.Println("GC 被禁用 (可能取决于 GODEBUG 设置)")
    }
    ```

    **命令行参数的具体处理:** `GODEBUG` 环境变量通常在运行 Go 程序之前设置，例如：

    ```bash
    GODEBUG=gctrace=1 go run your_program.go
    ```

    在这个例子中，`gctrace=1` 会启用垃圾回收的跟踪信息输出到标准错误。运行时系统会解析 `GODEBUG` 环境变量，并根据其中的键值对配置相应的运行时行为。

**5. 错误输出和崩溃处理:**

*   **`writeErrStr()` 和 `writeErrData()` 函数:** 这两个函数用于向标准错误输出字符串或字节数据。在程序发生 panic 或致命错误时，这些函数会被调用来输出错误信息。
*   **`crashFD` 变量和 `setCrashFD()` 函数:** `crashFD` 存储了一个可选的文件描述符，用于将崩溃信息同时写入到指定的文件。`setCrashFD()` 函数用于设置这个文件描述符，这通常由 `debug.SetCrashOutput()` 函数调用。

    **推断的 Go 语言功能:** 这部分代码实现了 Go 程序在发生错误或崩溃时输出信息的功能，并且允许用户将崩溃信息重定向到特定文件。

    **Go 代码举例:**

    ```go
    package main

    import (
        "fmt"
        "os"
        "runtime/debug"
    )

    func main() {
        // 将崩溃信息输出到 crash.log 文件
        f, err := os.Create("crash.log")
        if err != nil {
            fmt.Println("创建 crash.log 失败:", err)
            return
        }
        defer f.Close()
        debug.SetCrashOutput(f)

        panic("程序发生了致命错误")
    }
    ```

    **假设的输入与输出:** 运行该程序会导致 panic，错误信息会输出到标准错误，并且同时会被写入到 `crash.log` 文件中。

**6. 访问辅助向量 (auxv):**

*   **`auxv` 变量和 `getAuxv()` 函数:** `auxv` 存储了操作系统提供的辅助向量，其中包含了关于系统硬件和能力的信息。`getAuxv()` 函数通过 `//go:linkname` 暴露给外部包 (如 `golang.org/x/sys/cpu`)，允许它们访问这些信息。

    **推断的 Go 语言功能:**  这部分代码提供了访问底层操作系统信息的接口，供 Go 的标准库或第三方库使用，以了解 CPU 特性等信息。

**7. 零值:**

*   **`zeroVal` 变量:**  这是一个字节数组，用于提供各种类型的零值。它通过 `//go:linkname` 暴露给 `reflect` 包。

    **推断的 Go 语言功能:**  这是 `reflect` 包在处理零值时的底层支持。

**使用者易犯错的点:**

*   **误用 `ticksPerSecond()` 获取精确时间戳:**  代码注释中明确指出 `ticksPerSecond()` 主要用于计算时间间隔，而不是精确的时间戳。因为它依赖于一段时间的测量来计算转换率，瞬时的转换可能不准确。开发者应该使用 `time.Now()` 或 `nanotime()` 来获取精确的时间戳。
*   **不理解 `GODEBUG` 的影响:**  随意设置 `GODEBUG` 环境变量可能会对程序的性能或行为产生意想不到的影响。开发者应该查阅 Go 语言文档，了解每个 `GODEBUG` 选项的具体含义和潜在风险。
*   **过度依赖底层运行时细节:**  虽然可以通过 `//go:linkname` 访问某些运行时内部的函数或变量，但这通常是不推荐的做法。这些接口可能在未来的 Go 版本中发生变化，导致代码兼容性问题。应该优先使用 Go 标准库提供的公共 API。

总而言之，这段 `runtime.go` 的代码是 Go 语言运行时的核心组成部分，负责处理底层的系统交互、时间管理、错误处理以及一些调试和配置功能。它为 Go 程序的正常运行提供了基础支撑。

### 提示词
```
这是路径为go/src/runtime/runtime.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"unsafe"
)

//go:generate go run wincallback.go
//go:generate go run mkduff.go
//go:generate go run mkfastlog2table.go
//go:generate go run mklockrank.go -o lockrank.go

var ticks ticksType

type ticksType struct {
	// lock protects access to start* and val.
	lock       mutex
	startTicks int64
	startTime  int64
	val        atomic.Int64
}

// init initializes ticks to maximize the chance that we have a good ticksPerSecond reference.
//
// Must not run concurrently with ticksPerSecond.
func (t *ticksType) init() {
	lock(&ticks.lock)
	t.startTime = nanotime()
	t.startTicks = cputicks()
	unlock(&ticks.lock)
}

// minTimeForTicksPerSecond is the minimum elapsed time we require to consider our ticksPerSecond
// measurement to be of decent enough quality for profiling.
//
// There's a linear relationship here between minimum time and error from the true value.
// The error from the true ticks-per-second in a linux/amd64 VM seems to be:
// -   1 ms -> ~0.02% error
// -   5 ms -> ~0.004% error
// -  10 ms -> ~0.002% error
// -  50 ms -> ~0.0003% error
// - 100 ms -> ~0.0001% error
//
// We're willing to take 0.004% error here, because ticksPerSecond is intended to be used for
// converting durations, not timestamps. Durations are usually going to be much larger, and so
// the tiny error doesn't matter. The error is definitely going to be a problem when trying to
// use this for timestamps, as it'll make those timestamps much less likely to line up.
const minTimeForTicksPerSecond = 5_000_000*(1-osHasLowResClockInt) + 100_000_000*osHasLowResClockInt

// ticksPerSecond returns a conversion rate between the cputicks clock and the nanotime clock.
//
// Note: Clocks are hard. Using this as an actual conversion rate for timestamps is ill-advised
// and should be avoided when possible. Use only for durations, where a tiny error term isn't going
// to make a meaningful difference in even a 1ms duration. If an accurate timestamp is needed,
// use nanotime instead. (The entire Windows platform is a broad exception to this rule, where nanotime
// produces timestamps on such a coarse granularity that the error from this conversion is actually
// preferable.)
//
// The strategy for computing the conversion rate is to write down nanotime and cputicks as
// early in process startup as possible. From then, we just need to wait until we get values
// from nanotime that we can use (some platforms have a really coarse system time granularity).
// We require some amount of time to pass to ensure that the conversion rate is fairly accurate
// in aggregate. But because we compute this rate lazily, there's a pretty good chance a decent
// amount of time has passed by the time we get here.
//
// Must be called from a normal goroutine context (running regular goroutine with a P).
//
// Called by runtime/pprof in addition to runtime code.
//
// TODO(mknyszek): This doesn't account for things like CPU frequency scaling. Consider
// a more sophisticated and general approach in the future.
func ticksPerSecond() int64 {
	// Get the conversion rate if we've already computed it.
	r := ticks.val.Load()
	if r != 0 {
		return r
	}

	// Compute the conversion rate.
	for {
		lock(&ticks.lock)
		r = ticks.val.Load()
		if r != 0 {
			unlock(&ticks.lock)
			return r
		}

		// Grab the current time in both clocks.
		nowTime := nanotime()
		nowTicks := cputicks()

		// See if we can use these times.
		if nowTicks > ticks.startTicks && nowTime-ticks.startTime > minTimeForTicksPerSecond {
			// Perform the calculation with floats. We don't want to risk overflow.
			r = int64(float64(nowTicks-ticks.startTicks) * 1e9 / float64(nowTime-ticks.startTime))
			if r == 0 {
				// Zero is both a sentinel value and it would be bad if callers used this as
				// a divisor. We tried out best, so just make it 1.
				r++
			}
			ticks.val.Store(r)
			unlock(&ticks.lock)
			break
		}
		unlock(&ticks.lock)

		// Sleep in one millisecond increments until we have a reliable time.
		timeSleep(1_000_000)
	}
	return r
}

var envs []string
var argslice []string

//go:linkname syscall_runtime_envs syscall.runtime_envs
func syscall_runtime_envs() []string { return append([]string{}, envs...) }

//go:linkname syscall_Getpagesize syscall.Getpagesize
func syscall_Getpagesize() int { return int(physPageSize) }

//go:linkname os_runtime_args os.runtime_args
func os_runtime_args() []string { return append([]string{}, argslice...) }

//go:linkname syscall_Exit syscall.Exit
//go:nosplit
func syscall_Exit(code int) {
	exit(int32(code))
}

var godebugDefault string
var godebugUpdate atomic.Pointer[func(string, string)]
var godebugEnv atomic.Pointer[string] // set by parsedebugvars
var godebugNewIncNonDefault atomic.Pointer[func(string) func()]

//go:linkname godebug_setUpdate internal/godebug.setUpdate
func godebug_setUpdate(update func(string, string)) {
	p := new(func(string, string))
	*p = update
	godebugUpdate.Store(p)
	godebugNotify(false)
}

//go:linkname godebug_setNewIncNonDefault internal/godebug.setNewIncNonDefault
func godebug_setNewIncNonDefault(newIncNonDefault func(string) func()) {
	p := new(func(string) func())
	*p = newIncNonDefault
	godebugNewIncNonDefault.Store(p)
}

// A godebugInc provides access to internal/godebug's IncNonDefault function
// for a given GODEBUG setting.
// Calls before internal/godebug registers itself are dropped on the floor.
type godebugInc struct {
	name string
	inc  atomic.Pointer[func()]
}

func (g *godebugInc) IncNonDefault() {
	inc := g.inc.Load()
	if inc == nil {
		newInc := godebugNewIncNonDefault.Load()
		if newInc == nil {
			return
		}
		inc = new(func())
		*inc = (*newInc)(g.name)
		if raceenabled {
			racereleasemerge(unsafe.Pointer(&g.inc))
		}
		if !g.inc.CompareAndSwap(nil, inc) {
			inc = g.inc.Load()
		}
	}
	if raceenabled {
		raceacquire(unsafe.Pointer(&g.inc))
	}
	(*inc)()
}

func godebugNotify(envChanged bool) {
	update := godebugUpdate.Load()
	var env string
	if p := godebugEnv.Load(); p != nil {
		env = *p
	}
	if envChanged {
		reparsedebugvars(env)
	}
	if update != nil {
		(*update)(godebugDefault, env)
	}
}

//go:linkname syscall_runtimeSetenv syscall.runtimeSetenv
func syscall_runtimeSetenv(key, value string) {
	setenv_c(key, value)
	if key == "GODEBUG" {
		p := new(string)
		*p = value
		godebugEnv.Store(p)
		godebugNotify(true)
	}
}

//go:linkname syscall_runtimeUnsetenv syscall.runtimeUnsetenv
func syscall_runtimeUnsetenv(key string) {
	unsetenv_c(key)
	if key == "GODEBUG" {
		godebugEnv.Store(nil)
		godebugNotify(true)
	}
}

// writeErrStr writes a string to descriptor 2.
// If SetCrashOutput(f) was called, it also writes to f.
//
//go:nosplit
func writeErrStr(s string) {
	writeErrData(unsafe.StringData(s), int32(len(s)))
}

// writeErrData is the common parts of writeErr{,Str}.
//
//go:nosplit
func writeErrData(data *byte, n int32) {
	write(2, unsafe.Pointer(data), n)

	// If crashing, print a copy to the SetCrashOutput fd.
	gp := getg()
	if gp != nil && gp.m.dying > 0 ||
		gp == nil && panicking.Load() > 0 {
		if fd := crashFD.Load(); fd != ^uintptr(0) {
			write(fd, unsafe.Pointer(data), n)
		}
	}
}

// crashFD is an optional file descriptor to use for fatal panics, as
// set by debug.SetCrashOutput (see #42888). If it is a valid fd (not
// all ones), writeErr and related functions write to it in addition
// to standard error.
//
// Initialized to -1 in schedinit.
var crashFD atomic.Uintptr

//go:linkname setCrashFD
func setCrashFD(fd uintptr) uintptr {
	// Don't change the crash FD if a crash is already in progress.
	//
	// Unlike the case below, this is not required for correctness, but it
	// is generally nicer to have all of the crash output go to the same
	// place rather than getting split across two different FDs.
	if panicking.Load() > 0 {
		return ^uintptr(0)
	}

	old := crashFD.Swap(fd)

	// If we are panicking, don't return the old FD to runtime/debug for
	// closing. writeErrData may have already read the old FD from crashFD
	// before the swap and closing it would cause the write to be lost [1].
	// The old FD will never be closed, but we are about to crash anyway.
	//
	// On the writeErrData thread, panicking.Add(1) happens-before
	// crashFD.Load() [2].
	//
	// On this thread, swapping old FD for new in crashFD happens-before
	// panicking.Load() > 0.
	//
	// Therefore, if panicking.Load() == 0 here (old FD will be closed), it
	// is impossible for the writeErrData thread to observe
	// crashFD.Load() == old FD.
	//
	// [1] Or, if really unlucky, another concurrent open could reuse the
	// FD, sending the write into an unrelated file.
	//
	// [2] If gp != nil, it occurs when incrementing gp.m.dying in
	// startpanic_m. If gp == nil, we read panicking.Load() > 0, so an Add
	// must have happened-before.
	if panicking.Load() > 0 {
		return ^uintptr(0)
	}
	return old
}

// auxv is populated on relevant platforms but defined here for all platforms
// so x/sys/cpu can assume the getAuxv symbol exists without keeping its list
// of auxv-using GOOS build tags in sync.
//
// It contains an even number of elements, (tag, value) pairs.
var auxv []uintptr

// golang.org/x/sys/cpu uses getAuxv via linkname.
// Do not remove or change the type signature.
// (See go.dev/issue/57336.)
//
// getAuxv should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/cilium/ebpf
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname getAuxv
func getAuxv() []uintptr { return auxv }

// zeroVal is used by reflect via linkname.
//
// zeroVal should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname zeroVal
var zeroVal [abi.ZeroValSize]byte
```