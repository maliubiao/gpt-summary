Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the comprehensive answer.

**1. Initial Skim and High-Level Understanding:**

The first step is a quick skim to get a general sense of what the code is doing. Keywords like `runtime`, `atomic`, `unsafe`, and function names like `gotraceback`, `args`, `goenvs_unix`, `testAtomic64`, `check`, `parsedebugvars`, `setTraceback`, `timediv` stand out. This suggests the code is deeply involved in the Go runtime, dealing with low-level operations, debugging features, and environment variables.

**2. Grouping Functionality:**

Next, I'd group related functions together to understand the broader purpose of each section:

* **Traceback (`gotraceback`, `setTraceback`):** These functions clearly deal with managing stack trace information during program execution, especially in error scenarios. The constants `tracebackCrash`, `tracebackAll`, and `tracebackShift` are strong indicators of this.
* **Command Line Arguments and Environment (`args`, `goargs`, `goenvs_unix`, `environ`):** These are responsible for handling command-line arguments and environment variables when the Go program starts.
* **Atomic Operations (`testAtomic64`):** This function tests the functionality of atomic operations like `Cas64`, `Load64`, `Store64`, `Xadd64`, and `Xchg64`.
* **Size and Offset Checks (`check`):**  This section uses `unsafe.Sizeof` and `unsafe.Offsetof` to verify the sizes and layouts of data types, likely as a self-consistency check within the runtime.
* **Debugging Variables (`dbgVar`, `debug`, `dbgvars`, `parsedebugvars`, `reparsedebugvars`, `parsegodebug`):**  This large block is dedicated to managing debugging options that can be set via the `GODEBUG` environment variable.
* **Time Division (`timediv`):** This is a specialized, `nosplit` function for performing integer division with specific overflow handling.
* **Mutex-like Operations (`acquirem`, `releasem`):** These functions appear to manage access to some shared resource (likely the M in GMP).
* **Reflection Helpers (`reflect_typelinks`, `reflect_resolveNameOff`, etc.):** These functions provide support for Go's reflection capabilities.
* **FIPS Indicator (`fips_getIndicator`, `fips_setIndicator`):**  These likely deal with FIPS 140 compliance.

**3. Deep Dive into Key Functions:**

For the most prominent functions, I'd analyze their logic in detail:

* **`gotraceback`:** I'd trace how it reads the `traceback_cache` and `gp.m.traceback` to determine the traceback level and whether to include all goroutines or crash. The `throwing` state of the M is also important.
* **`parsedebugvars` and `parsegodebug`:** I'd examine how they process the `GODEBUG` environment variable, iterate through `dbgvars`, and apply the parsed values. The handling of `seen` for incremental updates is crucial.
* **`setTraceback`:** I'd look at the different string values it accepts ("none", "single", "all", "system", "crash", "wer") and how they map to the bit flags in `traceback_cache`.

**4. Inferring Go Language Features:**

Based on the function groupings and detailed analysis, I can infer the Go language features implemented in this file:

* **Panic and Stack Traces:**  The `gotraceback` and `setTraceback` functions directly relate to Go's panic mechanism and how stack traces are generated and controlled.
* **Command Line Arguments and Environment Variables:** The `args`, `goargs`, `goenvs_unix`, and related functions are the runtime's way of accessing these standard OS features.
* **Atomic Operations:** The `testAtomic64` function demonstrates the use of Go's `sync/atomic` package for thread-safe operations.
* **`unsafe` Package:**  The extensive use of `unsafe.Sizeof`, `unsafe.Offsetof`, and pointer manipulation indicates low-level memory access, which is what the `unsafe` package allows.
* **Debugging and Diagnostics:** The `GODEBUG` environment variable and the associated functions are a key part of Go's debugging infrastructure.
* **Reflection:**  The `reflect_*` functions are explicitly for supporting Go's reflection capabilities.

**5. Generating Code Examples:**

For each inferred feature, I'd create simple, illustrative Go code examples. These examples should be clear and demonstrate the core functionality:

* **Panic/Traceback:** Triggering a panic and showing how `GOTRACEBACK` affects the output.
* **Command Line Arguments:**  Accessing `os.Args`.
* **Environment Variables:** Accessing `os.Getenv`.
* **Atomic Operations:**  A simple counter incremented atomically.
* **`GODEBUG`:** Setting `GODEBUG` and observing its effects (e.g., `gctrace`).

**6. Considering Command Line Arguments:**

While the code itself doesn't directly *parse* command-line arguments in the typical `flag` package sense, it *receives* them from the operating system. The `args` function stores these in `argc` and `argv`. I'd explain this indirect handling.

**7. Identifying Potential Pitfalls:**

I'd think about common mistakes developers might make related to the functionality in this file:

* **Misunderstanding `GOTRACEBACK`:** Incorrectly setting or interpreting the values of `GOTRACEBACK`.
* **Incorrect `GODEBUG` syntax:**  Using invalid key-value pairs in `GODEBUG`.
* **Assuming immediate effect of `GODEBUG` changes:**  While some `GODEBUG` variables update dynamically, others might only be checked at startup.

**8. Structuring the Answer:**

Finally, I'd organize the information logically, using clear headings and bullet points. I'd start with a summary of the file's purpose and then detail each function's functionality, providing code examples, explanations of command-line arguments, and potential pitfalls. Using Chinese as requested is crucial throughout the explanation.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps some functions are related to memory management. **Correction:**  While `sbrk` hints at that, the majority leans towards debugging, arguments, and reflection.
* **Realization:** The `reflect_*` functions are specifically marked with `go:linkname`. **Refinement:** Emphasize the significance of `linkname` and why those packages use it.
* **Considering the audience:**  The request is for a comprehensive explanation. **Refinement:** Provide enough detail and context without being overly technical or assuming deep runtime knowledge. Use clear and concise language.

By following these steps, combining code analysis with an understanding of Go's core features, I can generate a comprehensive and accurate explanation of the given `runtime1.go` snippet.
这段代码是 Go 语言运行时（runtime）包中 `runtime1.go` 文件的一部分，它包含了 Go 语言程序启动和运行时的一些核心功能。下面我将详细列举其功能，并尝试推理出相关的 Go 语言特性，并提供代码示例。

**功能列表:**

1. **控制和获取 Goroutine 的栈回溯信息 (Traceback):**
   - `gotraceback()` 函数用于获取当前的栈回溯设置，包括回溯级别、是否显示所有 Goroutine 的栈、以及是否在回溯后崩溃。
   - `setTraceback()` 函数用于根据环境变量 `GOTRACEBACK` 的值来设置栈回溯的行为。
   - 维护了一个缓存 `traceback_cache` 来提高 `gotraceback` 的性能。

2. **处理命令行参数:**
   - `args(c int32, v **byte)` 函数用于接收 C 语言传递过来的命令行参数的个数和指向参数字符串数组的指针。
   - `goargs()` 函数将 C 风格的命令行参数转换为 Go 语言的字符串切片 `argslice`。

3. **处理环境变量:**
   - `goenvs_unix()` 函数（仅在 Unix 系统上）用于读取 C 语言传递过来的环境变量，并将其存储到 Go 语言的字符串切片 `envs` 中。
   - `environ()` 函数返回当前的环境变量切片。

4. **原子操作的测试:**
   - `testAtomic64()` 函数用于测试 64 位原子操作，例如 `Cas64` (Compare and Swap), `Load64`, `Store64`, `Xadd64` (Add), `Xchg64` (Exchange)。

5. **基本类型大小和偏移量的检查:**
   - `check()` 函数使用 `unsafe.Sizeof` 和 `unsafe.Offsetof` 来断言各种基本数据类型的大小和结构体字段的偏移量是否符合预期。这是一种内部一致性检查。

6. **解析和管理调试变量 (通过 `GODEBUG` 环境变量):**
   - 定义了一个 `dbgVar` 结构体用于表示一个调试变量，包含名称、值（启动时设置）或原子变量（运行时可变）、以及默认值。
   - 定义了一个 `debug` 结构体，包含多个具体的调试变量。
   - `dbgvars` 是一个 `dbgVar` 类型的切片，包含了所有可配置的调试变量。
   - `parsedebugvars()` 函数在程序启动时解析 `GODEBUG` 环境变量，并设置相应的调试变量。它会处理默认值、编译时设置和环境变量设置。
   - `reparsedebugvars()` 函数用于在环境变量更改后重新解析调试变量。
   - `parsegodebug()` 函数是解析 `GODEBUG` 字符串的核心逻辑。

7. **提供低级别的定时器除法函数:**
   - `timediv(v int64, div int32, rem *int32)` 函数提供了一个 64 位整数除以 32 位整数的除法操作，并返回商和余数。这个函数被标记为 `//go:nosplit`，意味着它不能触发栈分裂，用于一些非常底层的操作。

8. **提供获取和释放 M (Machine) 的函数:**
   - `acquirem()` 函数用于获取当前 Goroutine 关联的 M，并增加 M 的锁计数器。
   - `releasem(mp *m)` 函数用于释放指定的 M，并减少其锁计数器。如果锁计数器归零并且当前 Goroutine 有抢占请求，则会恢复抢占标记。

9. **为 `reflect` 包提供支持 (通过 `//go:linkname`):**
   - 提供了多个以 `reflect_` 或 `reflectlite_` 开头的函数，例如 `reflect_typelinks`, `reflect_resolveNameOff`, `reflect_resolveTypeOff`, `reflect_addReflectOff`。这些函数通过 `//go:linkname` 指令链接到 `reflect` 或 `internal/reflectlite` 包中的同名函数，为反射机制提供必要的运行时支持，例如访问类型信息和解析偏移量。

10. **为 `crypto/internal/fips140` 包提供支持 (通过 `//go:linkname`):**
    - `fips_getIndicator()` 和 `fips_setIndicator()` 函数通过 `//go:linkname` 链接到 `crypto/internal/fips140` 包，用于获取和设置 FIPS 指示器。

**Go 语言功能推理和代码示例:**

1. **Panic 和 Stack Trace 控制 (基于 `gotraceback` 和 `setTraceback`):**

   这段代码实现了控制 Go 程序 panic 时栈回溯行为的功能。`GOTRACEBACK` 环境变量可以控制回溯的详细程度。

   ```go
   package main

   import (
       "fmt"
       "os"
       "runtime/debug"
   )

   func main() {
       // 默认情况下，panic 会打印栈回溯
       defer func() {
           if r := recover(); r != nil {
               fmt.Println("Recovered from panic:", r)
           }
       }()

       divideByZero(10)

       // 通过设置 GOTRACEBACK=none 可以禁用栈回溯
       os.Setenv("GOTRACEBACK", "none")
       debug.SetTraceback(os.Getenv("GOTRACEBACK")) // 需要手动调用 setTraceback 更新运行时设置

       divideByZero(5) // 即使 panic 也不会打印栈回溯
   }

   func divideByZero(n int) {
       result := n / 0
       fmt.Println("Result:", result)
   }
   ```

   **假设输入:** 运行上述代码，不设置额外的环境变量。

   **预期输出:**

   ```
   Recovered from panic: runtime error: integer divide by zero
   Recovered from panic: runtime error: integer divide by zero
   ```

   **命令行参数处理:**  虽然这段代码本身没有直接处理命令行参数，但 `args` 函数接收了这些参数，并由 `goargs` 转换成 Go 的形式。`os.Args` 切片在 Go 程序中就可以访问到这些参数。

   ```go
   package main

   import "fmt"
   import "os"

   func main() {
       fmt.Println("命令行参数个数:", len(os.Args))
       fmt.Println("所有命令行参数:", os.Args)
   }
   ```

   **假设输入:** 运行 `go run main.go arg1 arg2`

   **预期输出:**

   ```
   命令行参数个数: 3
   所有命令行参数: [./main arg1 arg2]
   ```

2. **环境变量处理 (基于 `goenvs_unix` 和 `environ`):**

   这段代码负责将操作系统提供的环境变量传递给 Go 程序。`os.Getenv` 和 `os.Environ` 函数就可以访问这些变量。

   ```go
   package main

   import (
       "fmt"
       "os"
   )

   func main() {
       fmt.Println("PATH 环境变量:", os.Getenv("PATH"))
       fmt.Println("所有环境变量:", os.Environ())
   }
   ```

   **假设输入:** 假设系统中设置了 `PATH` 环境变量。

   **预期输出:** (输出会根据系统环境有所不同)

   ```
   PATH 环境变量: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
   所有环境变量: [ ... 包含 PATH 的所有环境变量列表 ... ]
   ```

3. **原子操作 (基于 `testAtomic64`):**

   `testAtomic64` 函数内部测试了 `sync/atomic` 包提供的原子操作。Go 语言提供了原子操作来确保多线程并发访问共享变量时的安全性。

   ```go
   package main

   import (
       "fmt"
       "sync/atomic"
   )

   func main() {
       var counter int64

       // 启动多个 Goroutine 并发增加计数器
       for i := 0; i < 1000; i++ {
           go func() {
               atomic.AddInt64(&counter, 1)
           }()
       }

       // 等待一段时间确保所有 Goroutine 执行完成 (实际应用中应该使用更可靠的同步机制)
       // ...

       fmt.Println("计数器值:", atomic.LoadInt64(&counter))
   }
   ```

   **假设输入:** 无特定输入。

   **预期输出:** (由于并发，每次运行结果可能略有不同，但应该接近 1000)

   ```
   计数器值: 1000
   ```

4. **调试变量 (`GODEBUG`):**

   `parsedebugvars` 等函数实现了通过 `GODEBUG` 环境变量控制运行时行为的功能。例如，可以使用 `GODEBUG=gctrace=1` 来开启垃圾回收的跟踪信息。

   **命令行参数的具体处理:**  与命令行参数类似，`GODEBUG` 是一个环境变量，在程序启动时由操作系统提供。`parsedebugvars` 函数会读取这个环境变量的值，并解析其中的键值对来设置相应的调试变量。

   ```go
   package main

   import (
       "fmt"
       "os"
       "runtime"
       "time"
   )

   func main() {
       // 设置 GODEBUG 环境变量以启用垃圾回收跟踪
       os.Setenv("GODEBUG", "gctrace=1")

       // 触发垃圾回收
       runtime.GC()

       // 等待一段时间，查看垃圾回收的输出 (输出会打印到标准错误)
       time.Sleep(time.Second)
   }
   ```

   **假设输入:** 运行上述代码。

   **预期输出:** (会在标准错误输出中看到类似以下的垃圾回收跟踪信息)

   ```
   gc 1 @0.001s 0%: 0.005+0.080 ms clock, 0.040+0.070 ms cpu, 4->4->3 MB, 4 MB goal, 12 P
   ...
   ```

**使用者易犯错的点:**

1. **误解 `GOTRACEBACK` 的作用域:**  `GOTRACEBACK` 的设置只在程序启动时读取一次，并通过 `setTraceback` 应用。如果在程序运行过程中修改环境变量，需要再次调用 `debug.SetTraceback` 才能生效。

2. **`GODEBUG` 语法错误:**  `GODEBUG` 的格式是逗号分隔的 `key=value` 对。如果格式错误，相关的调试变量可能不会被正确设置。

3. **假设 `GODEBUG` 的更改会立即生效:** 虽然 `reparsedebugvars` 提供了重新解析的功能，但并非所有的 `GODEBUG` 变量都是动态可变的。有些变量只在程序启动时读取。例如，改变 `panicnil` 的值在某些情况下可能不会立即影响正在运行的代码。

4. **依赖未公开的运行时行为:** 直接操作 `runtime` 包的内部变量或函数（即使是通过 `//go:linkname` 访问）都是不推荐的，因为这些接口没有稳定性保证，可能会在未来的 Go 版本中发生变化。

总而言之，`runtime1.go` 文件是 Go 语言运行时的基础组成部分，负责程序的启动、环境配置、错误处理、调试支持以及一些底层的操作。理解这部分代码有助于深入理解 Go 语言的运行机制。

Prompt: 
```
这是路径为go/src/runtime/runtime1.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/bytealg"
	"internal/goarch"
	"internal/runtime/atomic"
	"unsafe"
)

// Keep a cached value to make gotraceback fast,
// since we call it on every call to gentraceback.
// The cached value is a uint32 in which the low bits
// are the "crash" and "all" settings and the remaining
// bits are the traceback value (0 off, 1 on, 2 include system).
const (
	tracebackCrash = 1 << iota
	tracebackAll
	tracebackShift = iota
)

var traceback_cache uint32 = 2 << tracebackShift
var traceback_env uint32

// gotraceback returns the current traceback settings.
//
// If level is 0, suppress all tracebacks.
// If level is 1, show tracebacks, but exclude runtime frames.
// If level is 2, show tracebacks including runtime frames.
// If all is set, print all goroutine stacks. Otherwise, print just the current goroutine.
// If crash is set, crash (core dump, etc) after tracebacking.
//
//go:nosplit
func gotraceback() (level int32, all, crash bool) {
	gp := getg()
	t := atomic.Load(&traceback_cache)
	crash = t&tracebackCrash != 0
	all = gp.m.throwing >= throwTypeUser || t&tracebackAll != 0
	if gp.m.traceback != 0 {
		level = int32(gp.m.traceback)
	} else if gp.m.throwing >= throwTypeRuntime {
		// Always include runtime frames in runtime throws unless
		// otherwise overridden by m.traceback.
		level = 2
	} else {
		level = int32(t >> tracebackShift)
	}
	return
}

var (
	argc int32
	argv **byte
)

// nosplit for use in linux startup sysargs.
//
//go:nosplit
func argv_index(argv **byte, i int32) *byte {
	return *(**byte)(add(unsafe.Pointer(argv), uintptr(i)*goarch.PtrSize))
}

func args(c int32, v **byte) {
	argc = c
	argv = v
	sysargs(c, v)
}

func goargs() {
	if GOOS == "windows" {
		return
	}
	argslice = make([]string, argc)
	for i := int32(0); i < argc; i++ {
		argslice[i] = gostringnocopy(argv_index(argv, i))
	}
}

func goenvs_unix() {
	// TODO(austin): ppc64 in dynamic linking mode doesn't
	// guarantee env[] will immediately follow argv. Might cause
	// problems.
	n := int32(0)
	for argv_index(argv, argc+1+n) != nil {
		n++
	}

	envs = make([]string, n)
	for i := int32(0); i < n; i++ {
		envs[i] = gostring(argv_index(argv, argc+1+i))
	}
}

func environ() []string {
	return envs
}

// TODO: These should be locals in testAtomic64, but we don't 8-byte
// align stack variables on 386.
var test_z64, test_x64 uint64

func testAtomic64() {
	test_z64 = 42
	test_x64 = 0
	if atomic.Cas64(&test_z64, test_x64, 1) {
		throw("cas64 failed")
	}
	if test_x64 != 0 {
		throw("cas64 failed")
	}
	test_x64 = 42
	if !atomic.Cas64(&test_z64, test_x64, 1) {
		throw("cas64 failed")
	}
	if test_x64 != 42 || test_z64 != 1 {
		throw("cas64 failed")
	}
	if atomic.Load64(&test_z64) != 1 {
		throw("load64 failed")
	}
	atomic.Store64(&test_z64, (1<<40)+1)
	if atomic.Load64(&test_z64) != (1<<40)+1 {
		throw("store64 failed")
	}
	if atomic.Xadd64(&test_z64, (1<<40)+1) != (2<<40)+2 {
		throw("xadd64 failed")
	}
	if atomic.Load64(&test_z64) != (2<<40)+2 {
		throw("xadd64 failed")
	}
	if atomic.Xchg64(&test_z64, (3<<40)+3) != (2<<40)+2 {
		throw("xchg64 failed")
	}
	if atomic.Load64(&test_z64) != (3<<40)+3 {
		throw("xchg64 failed")
	}
}

func check() {
	var (
		a     int8
		b     uint8
		c     int16
		d     uint16
		e     int32
		f     uint32
		g     int64
		h     uint64
		i, i1 float32
		j, j1 float64
		k     unsafe.Pointer
		l     *uint16
		m     [4]byte
	)
	type x1t struct {
		x uint8
	}
	type y1t struct {
		x1 x1t
		y  uint8
	}
	var x1 x1t
	var y1 y1t

	if unsafe.Sizeof(a) != 1 {
		throw("bad a")
	}
	if unsafe.Sizeof(b) != 1 {
		throw("bad b")
	}
	if unsafe.Sizeof(c) != 2 {
		throw("bad c")
	}
	if unsafe.Sizeof(d) != 2 {
		throw("bad d")
	}
	if unsafe.Sizeof(e) != 4 {
		throw("bad e")
	}
	if unsafe.Sizeof(f) != 4 {
		throw("bad f")
	}
	if unsafe.Sizeof(g) != 8 {
		throw("bad g")
	}
	if unsafe.Sizeof(h) != 8 {
		throw("bad h")
	}
	if unsafe.Sizeof(i) != 4 {
		throw("bad i")
	}
	if unsafe.Sizeof(j) != 8 {
		throw("bad j")
	}
	if unsafe.Sizeof(k) != goarch.PtrSize {
		throw("bad k")
	}
	if unsafe.Sizeof(l) != goarch.PtrSize {
		throw("bad l")
	}
	if unsafe.Sizeof(x1) != 1 {
		throw("bad unsafe.Sizeof x1")
	}
	if unsafe.Offsetof(y1.y) != 1 {
		throw("bad offsetof y1.y")
	}
	if unsafe.Sizeof(y1) != 2 {
		throw("bad unsafe.Sizeof y1")
	}

	if timediv(12345*1000000000+54321, 1000000000, &e) != 12345 || e != 54321 {
		throw("bad timediv")
	}

	var z uint32
	z = 1
	if !atomic.Cas(&z, 1, 2) {
		throw("cas1")
	}
	if z != 2 {
		throw("cas2")
	}

	z = 4
	if atomic.Cas(&z, 5, 6) {
		throw("cas3")
	}
	if z != 4 {
		throw("cas4")
	}

	z = 0xffffffff
	if !atomic.Cas(&z, 0xffffffff, 0xfffffffe) {
		throw("cas5")
	}
	if z != 0xfffffffe {
		throw("cas6")
	}

	m = [4]byte{1, 1, 1, 1}
	atomic.Or8(&m[1], 0xf0)
	if m[0] != 1 || m[1] != 0xf1 || m[2] != 1 || m[3] != 1 {
		throw("atomicor8")
	}

	m = [4]byte{0xff, 0xff, 0xff, 0xff}
	atomic.And8(&m[1], 0x1)
	if m[0] != 0xff || m[1] != 0x1 || m[2] != 0xff || m[3] != 0xff {
		throw("atomicand8")
	}

	*(*uint64)(unsafe.Pointer(&j)) = ^uint64(0)
	if j == j {
		throw("float64nan")
	}
	if !(j != j) {
		throw("float64nan1")
	}

	*(*uint64)(unsafe.Pointer(&j1)) = ^uint64(1)
	if j == j1 {
		throw("float64nan2")
	}
	if !(j != j1) {
		throw("float64nan3")
	}

	*(*uint32)(unsafe.Pointer(&i)) = ^uint32(0)
	if i == i {
		throw("float32nan")
	}
	if i == i {
		throw("float32nan1")
	}

	*(*uint32)(unsafe.Pointer(&i1)) = ^uint32(1)
	if i == i1 {
		throw("float32nan2")
	}
	if i == i1 {
		throw("float32nan3")
	}

	testAtomic64()

	if fixedStack != round2(fixedStack) {
		throw("FixedStack is not power-of-2")
	}

	if !checkASM() {
		throw("assembly checks failed")
	}
}

type dbgVar struct {
	name   string
	value  *int32        // for variables that can only be set at startup
	atomic *atomic.Int32 // for variables that can be changed during execution
	def    int32         // default value (ideally zero)
}

// Holds variables parsed from GODEBUG env var,
// except for "memprofilerate" since there is an
// existing int var for that value, which may
// already have an initial value.
var debug struct {
	cgocheck                 int32
	clobberfree              int32
	disablethp               int32
	dontfreezetheworld       int32
	efence                   int32
	gccheckmark              int32
	gcpacertrace             int32
	gcshrinkstackoff         int32
	gcstoptheworld           int32
	gctrace                  int32
	invalidptr               int32
	madvdontneed             int32 // for Linux; issue 28466
	runtimeContentionStacks  atomic.Int32
	scavtrace                int32
	scheddetail              int32
	schedtrace               int32
	tracebackancestors       int32
	asyncpreemptoff          int32
	harddecommit             int32
	adaptivestackstart       int32
	tracefpunwindoff         int32
	traceadvanceperiod       int32
	traceCheckStackOwnership int32
	profstackdepth           int32
	dataindependenttiming    int32

	// debug.malloc is used as a combined debug check
	// in the malloc function and should be set
	// if any of the below debug options is != 0.
	malloc    bool
	inittrace int32
	sbrk      int32
	// traceallocfree controls whether execution traces contain
	// detailed trace data about memory allocation. This value
	// affects debug.malloc only if it is != 0 and the execution
	// tracer is enabled, in which case debug.malloc will be
	// set to "true" if it isn't already while tracing is enabled.
	// It will be set while the world is stopped, so it's safe.
	// The value of traceallocfree can be changed any time in response
	// to os.Setenv("GODEBUG").
	traceallocfree atomic.Int32

	panicnil atomic.Int32

	// asynctimerchan controls whether timer channels
	// behave asynchronously (as in Go 1.22 and earlier)
	// instead of their Go 1.23+ synchronous behavior.
	// The value can change at any time (in response to os.Setenv("GODEBUG"))
	// and affects all extant timer channels immediately.
	// Programs wouldn't normally change over an execution,
	// but allowing it is convenient for testing and for programs
	// that do an os.Setenv in main.init or main.main.
	asynctimerchan atomic.Int32
}

var dbgvars = []*dbgVar{
	{name: "adaptivestackstart", value: &debug.adaptivestackstart},
	{name: "asyncpreemptoff", value: &debug.asyncpreemptoff},
	{name: "asynctimerchan", atomic: &debug.asynctimerchan},
	{name: "cgocheck", value: &debug.cgocheck},
	{name: "clobberfree", value: &debug.clobberfree},
	{name: "dataindependenttiming", value: &debug.dataindependenttiming},
	{name: "disablethp", value: &debug.disablethp},
	{name: "dontfreezetheworld", value: &debug.dontfreezetheworld},
	{name: "efence", value: &debug.efence},
	{name: "gccheckmark", value: &debug.gccheckmark},
	{name: "gcpacertrace", value: &debug.gcpacertrace},
	{name: "gcshrinkstackoff", value: &debug.gcshrinkstackoff},
	{name: "gcstoptheworld", value: &debug.gcstoptheworld},
	{name: "gctrace", value: &debug.gctrace},
	{name: "harddecommit", value: &debug.harddecommit},
	{name: "inittrace", value: &debug.inittrace},
	{name: "invalidptr", value: &debug.invalidptr},
	{name: "madvdontneed", value: &debug.madvdontneed},
	{name: "panicnil", atomic: &debug.panicnil},
	{name: "profstackdepth", value: &debug.profstackdepth, def: 128},
	{name: "runtimecontentionstacks", atomic: &debug.runtimeContentionStacks},
	{name: "sbrk", value: &debug.sbrk},
	{name: "scavtrace", value: &debug.scavtrace},
	{name: "scheddetail", value: &debug.scheddetail},
	{name: "schedtrace", value: &debug.schedtrace},
	{name: "traceadvanceperiod", value: &debug.traceadvanceperiod},
	{name: "traceallocfree", atomic: &debug.traceallocfree},
	{name: "tracecheckstackownership", value: &debug.traceCheckStackOwnership},
	{name: "tracebackancestors", value: &debug.tracebackancestors},
	{name: "tracefpunwindoff", value: &debug.tracefpunwindoff},
}

func parsedebugvars() {
	// defaults
	debug.cgocheck = 1
	debug.invalidptr = 1
	debug.adaptivestackstart = 1 // set this to 0 to turn larger initial goroutine stacks off
	if GOOS == "linux" {
		// On Linux, MADV_FREE is faster than MADV_DONTNEED,
		// but doesn't affect many of the statistics that
		// MADV_DONTNEED does until the memory is actually
		// reclaimed. This generally leads to poor user
		// experience, like confusing stats in top and other
		// monitoring tools; and bad integration with
		// management systems that respond to memory usage.
		// Hence, default to MADV_DONTNEED.
		debug.madvdontneed = 1
	}
	debug.traceadvanceperiod = defaultTraceAdvancePeriod

	godebug := gogetenv("GODEBUG")

	p := new(string)
	*p = godebug
	godebugEnv.Store(p)

	// apply runtime defaults, if any
	for _, v := range dbgvars {
		if v.def != 0 {
			// Every var should have either v.value or v.atomic set.
			if v.value != nil {
				*v.value = v.def
			} else if v.atomic != nil {
				v.atomic.Store(v.def)
			}
		}
	}

	// apply compile-time GODEBUG settings
	parsegodebug(godebugDefault, nil)

	// apply environment settings
	parsegodebug(godebug, nil)

	debug.malloc = (debug.inittrace | debug.sbrk) != 0
	debug.profstackdepth = min(debug.profstackdepth, maxProfStackDepth)

	setTraceback(gogetenv("GOTRACEBACK"))
	traceback_env = traceback_cache
}

// reparsedebugvars reparses the runtime's debug variables
// because the environment variable has been changed to env.
func reparsedebugvars(env string) {
	seen := make(map[string]bool)
	// apply environment settings
	parsegodebug(env, seen)
	// apply compile-time GODEBUG settings for as-yet-unseen variables
	parsegodebug(godebugDefault, seen)
	// apply defaults for as-yet-unseen variables
	for _, v := range dbgvars {
		if v.atomic != nil && !seen[v.name] {
			v.atomic.Store(0)
		}
	}
}

// parsegodebug parses the godebug string, updating variables listed in dbgvars.
// If seen == nil, this is startup time and we process the string left to right
// overwriting older settings with newer ones.
// If seen != nil, $GODEBUG has changed and we are doing an
// incremental update. To avoid flapping in the case where a value is
// set multiple times (perhaps in the default and the environment,
// or perhaps twice in the environment), we process the string right-to-left
// and only change values not already seen. After doing this for both
// the environment and the default settings, the caller must also call
// cleargodebug(seen) to reset any now-unset values back to their defaults.
func parsegodebug(godebug string, seen map[string]bool) {
	for p := godebug; p != ""; {
		var field string
		if seen == nil {
			// startup: process left to right, overwriting older settings with newer
			i := bytealg.IndexByteString(p, ',')
			if i < 0 {
				field, p = p, ""
			} else {
				field, p = p[:i], p[i+1:]
			}
		} else {
			// incremental update: process right to left, updating and skipping seen
			i := len(p) - 1
			for i >= 0 && p[i] != ',' {
				i--
			}
			if i < 0 {
				p, field = "", p
			} else {
				p, field = p[:i], p[i+1:]
			}
		}
		i := bytealg.IndexByteString(field, '=')
		if i < 0 {
			continue
		}
		key, value := field[:i], field[i+1:]
		if seen[key] {
			continue
		}
		if seen != nil {
			seen[key] = true
		}

		// Update MemProfileRate directly here since it
		// is int, not int32, and should only be updated
		// if specified in GODEBUG.
		if seen == nil && key == "memprofilerate" {
			if n, ok := atoi(value); ok {
				MemProfileRate = n
			}
		} else {
			for _, v := range dbgvars {
				if v.name == key {
					if n, ok := atoi32(value); ok {
						if seen == nil && v.value != nil {
							*v.value = n
						} else if v.atomic != nil {
							v.atomic.Store(n)
						}
					}
				}
			}
		}
	}

	if debug.cgocheck > 1 {
		throw("cgocheck > 1 mode is no longer supported at runtime. Use GOEXPERIMENT=cgocheck2 at build time instead.")
	}
}

//go:linkname setTraceback runtime/debug.SetTraceback
func setTraceback(level string) {
	var t uint32
	switch level {
	case "none":
		t = 0
	case "single", "":
		t = 1 << tracebackShift
	case "all":
		t = 1<<tracebackShift | tracebackAll
	case "system":
		t = 2<<tracebackShift | tracebackAll
	case "crash":
		t = 2<<tracebackShift | tracebackAll | tracebackCrash
	case "wer":
		if GOOS == "windows" {
			t = 2<<tracebackShift | tracebackAll | tracebackCrash
			enableWER()
			break
		}
		fallthrough
	default:
		t = tracebackAll
		if n, ok := atoi(level); ok && n == int(uint32(n)) {
			t |= uint32(n) << tracebackShift
		}
	}
	// when C owns the process, simply exit'ing the process on fatal errors
	// and panics is surprising. Be louder and abort instead.
	if islibrary || isarchive {
		t |= tracebackCrash
	}

	t |= traceback_env

	atomic.Store(&traceback_cache, t)
}

// Poor mans 64-bit division.
// This is a very special function, do not use it if you are not sure what you are doing.
// int64 division is lowered into _divv() call on 386, which does not fit into nosplit functions.
// Handles overflow in a time-specific manner.
// This keeps us within no-split stack limits on 32-bit processors.
//
//go:nosplit
func timediv(v int64, div int32, rem *int32) int32 {
	res := int32(0)
	for bit := 30; bit >= 0; bit-- {
		if v >= int64(div)<<uint(bit) {
			v = v - (int64(div) << uint(bit))
			// Before this for loop, res was 0, thus all these
			// power of 2 increments are now just bitsets.
			res |= 1 << uint(bit)
		}
	}
	if v >= int64(div) {
		if rem != nil {
			*rem = 0
		}
		return 0x7fffffff
	}
	if rem != nil {
		*rem = int32(v)
	}
	return res
}

// Helpers for Go. Must be NOSPLIT, must only call NOSPLIT functions, and must not block.

//go:nosplit
func acquirem() *m {
	gp := getg()
	gp.m.locks++
	return gp.m
}

//go:nosplit
func releasem(mp *m) {
	gp := getg()
	mp.locks--
	if mp.locks == 0 && gp.preempt {
		// restore the preemption request in case we've cleared it in newstack
		gp.stackguard0 = stackPreempt
	}
}

// reflect_typelinks is meant for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/goccy/json
//   - github.com/modern-go/reflect2
//   - github.com/vmware/govmomi
//   - github.com/pinpoint-apm/pinpoint-go-agent
//   - github.com/timandy/routine
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_typelinks reflect.typelinks
func reflect_typelinks() ([]unsafe.Pointer, [][]int32) {
	modules := activeModules()
	sections := []unsafe.Pointer{unsafe.Pointer(modules[0].types)}
	ret := [][]int32{modules[0].typelinks}
	for _, md := range modules[1:] {
		sections = append(sections, unsafe.Pointer(md.types))
		ret = append(ret, md.typelinks)
	}
	return sections, ret
}

// reflect_resolveNameOff resolves a name offset from a base pointer.
//
// reflect_resolveNameOff is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/agiledragon/gomonkey/v2
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_resolveNameOff reflect.resolveNameOff
func reflect_resolveNameOff(ptrInModule unsafe.Pointer, off int32) unsafe.Pointer {
	return unsafe.Pointer(resolveNameOff(ptrInModule, nameOff(off)).Bytes)
}

// reflect_resolveTypeOff resolves an *rtype offset from a base type.
//
// reflect_resolveTypeOff is meant for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/modern-go/reflect2
//   - github.com/v2pro/plz
//   - github.com/timandy/routine
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_resolveTypeOff reflect.resolveTypeOff
func reflect_resolveTypeOff(rtype unsafe.Pointer, off int32) unsafe.Pointer {
	return unsafe.Pointer(toRType((*_type)(rtype)).typeOff(typeOff(off)))
}

// reflect_resolveTextOff resolves a function pointer offset from a base type.
//
// reflect_resolveTextOff is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/agiledragon/gomonkey/v2
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_resolveTextOff reflect.resolveTextOff
func reflect_resolveTextOff(rtype unsafe.Pointer, off int32) unsafe.Pointer {
	return toRType((*_type)(rtype)).textOff(textOff(off))
}

// reflectlite_resolveNameOff resolves a name offset from a base pointer.
//
//go:linkname reflectlite_resolveNameOff internal/reflectlite.resolveNameOff
func reflectlite_resolveNameOff(ptrInModule unsafe.Pointer, off int32) unsafe.Pointer {
	return unsafe.Pointer(resolveNameOff(ptrInModule, nameOff(off)).Bytes)
}

// reflectlite_resolveTypeOff resolves an *rtype offset from a base type.
//
//go:linkname reflectlite_resolveTypeOff internal/reflectlite.resolveTypeOff
func reflectlite_resolveTypeOff(rtype unsafe.Pointer, off int32) unsafe.Pointer {
	return unsafe.Pointer(toRType((*_type)(rtype)).typeOff(typeOff(off)))
}

// reflect_addReflectOff adds a pointer to the reflection offset lookup map.
//
//go:linkname reflect_addReflectOff reflect.addReflectOff
func reflect_addReflectOff(ptr unsafe.Pointer) int32 {
	reflectOffsLock()
	if reflectOffs.m == nil {
		reflectOffs.m = make(map[int32]unsafe.Pointer)
		reflectOffs.minv = make(map[unsafe.Pointer]int32)
		reflectOffs.next = -1
	}
	id, found := reflectOffs.minv[ptr]
	if !found {
		id = reflectOffs.next
		reflectOffs.next-- // use negative offsets as IDs to aid debugging
		reflectOffs.m[id] = ptr
		reflectOffs.minv[ptr] = id
	}
	reflectOffsUnlock()
	return id
}

//go:linkname fips_getIndicator crypto/internal/fips140.getIndicator
func fips_getIndicator() uint8 {
	return getg().fipsIndicator
}

//go:linkname fips_setIndicator crypto/internal/fips140.setIndicator
func fips_setIndicator(indicator uint8) {
	getg().fipsIndicator = indicator
}

"""



```