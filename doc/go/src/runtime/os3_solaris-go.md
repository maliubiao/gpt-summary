Response:
我的目标是对给定的 Go 语言源代码文件 `os3_solaris.go` 进行分析，并按照要求列出其功能、推断其实现的 Go 语言特性、提供代码示例、解释命令行参数处理（如果适用）、并指出使用者容易犯的错误（如果存在）。

**1. 理解文件路径和名称:**

文件名 `os3_solaris.go` 暗示这是 Go runtime 中特定于 Solaris 操作系统和 32 位架构（通常 `os_OSNAME.go` 对应操作系统，而 `osN_OSNAME.go` 中的 `N` 可能表示架构或变种，但在这个例子中 `3` 的具体含义不太明显，可能只是历史遗留或版本号）。但这部分代码同时适用于 32 位和 64 位，从代码中并未找到特定于 32 位的痕迹。

**2. 分析 `import` 语句:**

导入的包 `internal/abi`, `internal/goarch`, `internal/runtime/atomic`, `unsafe` 表明该文件涉及底层 ABI 交互、架构相关信息、原子操作以及不安全指针操作。这符合 `runtime` 包的功能定位。

**3. 分析 `//go:cgo_export_dynamic` 和 `//go:cgo_import_dynamic` 注释:**

这些注释表明该文件使用了 CGO（C bindings for Go），并动态链接了 `libc.so` 库中的各种函数。这表明此文件通过调用 C 标准库函数来实现 Go runtime 的某些功能。

**4. 分析 `//go:linkname` 注释:**

这些注释用于将 Go 语言中的变量或函数名链接到 C 语言中的符号。例如，`libc____errno` 链接到 `libc.so` 中的 `___errno` 符号。这进一步证实了 CGO 的使用。

**5. 分析变量声明和函数定义:**

*   声明了一系列 `libcFunc` 类型的变量，这些变量用于存储通过 `//go:cgo_import_dynamic` 导入的 C 函数的地址。
*   `sigset_all` 定义了一个包含所有信号的信号集。
*   `getPageSize()`: 获取系统页大小。
*   `osinit()`:  初始化与操作系统相关的部分，包括获取 CPU 核心数和页大小。
*   `newosproc()`: 创建新的操作系统线程。
*   `exitThread()`:  （注释表明在 Solaris 上不会调用）。
*   `readRandom()`: 从 `/dev/urandom` 读取随机数据。
*   `goenvs()`: 调用平台无关的 `goenvs_unix()` 函数处理环境变量。
*   `mpreinit()`: 初始化新 M (machine) 结构体，包括分配信号处理 goroutine 的栈。
*   `miniterrno()`:  （未找到具体实现，可能是 CGO 侧实现，用于在早期阶段安全调用系统调用）。
*   `minit()`: 初始化新线程的 M 结构体，包括设置信号处理。
*   `unminit()`: 撤销 `minit` 的影响。
*   `mdestroy()`: 销毁 M 结构体相关的线程资源。
*   `sigtramp()`: 信号处理跳转函数（可能是汇编实现）。
*   `setsig()`: 设置信号处理函数。
*   `setsigstack()`: 设置信号处理的备用栈。
*   `getsig()`: 获取信号处理函数。
*   `setSignalstackSP()`: 设置信号栈的栈顶指针。
*   `sigaddset()`, `sigdelset()`: 操作信号集。
*   `fixsigcode()`: 修复信号代码。
*   `setProcessCPUProfiler()`, `setThreadCPUProfiler()`: 设置 CPU profiling 定时器。
*   `validSIGPROF()`: 验证 SIGPROF 信号。
*   `semacreate()`: 创建信号量。
*   `semasleep()`, `semawakeup()`: 信号量的睡眠和唤醒操作。
*   一系列直接调用 C 标准库函数的包装函数，例如 `closefd`, `exit`, `getcontext`, `madvise`, `mmap`, `munmap`, `nanotime1`, `open`, `pthread_*`, `raise`, `read`, `sem_*`, `setitimer`, `sigaction`, `sigaltstack`, `sigprocmask`, `sysconf`, `usleep`, `walltime`, `write1`, `pipe2`, `fcntl`, `osyield`, `sysargs`, `sysauxv`.
*   `executablePath`: 存储可执行文件路径的变量。
*   `sigPerThreadSyscall`, `runPerThreadSyscall`: （似乎是 Linux 特有的，在 Solaris 上抛出 panic）。

**6. 推理 Go 语言功能实现:**

基于以上分析，可以推断此文件实现了 Go runtime 在 Solaris 操作系统上的以下核心功能：

*   **线程管理:** `newosproc`, `pthread_*` 函数表明它负责创建和管理操作系统线程，这是 Go 调度器的基础。
*   **内存管理:** `mmap`, `munmap`, `madvise`, `getPageSize` 等函数表明它参与了内存的分配和管理。
*   **信号处理:** `sigaction`, `sigprocmask`, `sigaltstack`, `setsig` 等函数表明它负责处理操作系统信号，包括 goroutine 的中断和恢复。
*   **同步原语:** `semacreate`, `semasleep`, `semawakeup` 表明它实现了基于信号量的同步机制。
*   **时间相关功能:** `nanotime1`, `walltime`, `usleep`, `setitimer` 提供了获取时间、休眠和设置定时器的功能。
*   **文件 I/O:**  `open`, `read`, `write`, `closefd`, `pipe2`, `fcntl` 实现了与文件系统交互的功能。
*   **进程管理:** `exit`, `kill`, `raise`, `getcontext` 提供了进程控制相关的功能。
*   **环境变量和命令行参数:** `goenvs`, `sysargs`, `sysauxv` 负责获取环境变量和解析命令行参数。
*   **CPU Profiling:** `setProcessCPUProfiler`, `setThreadCPUProfiler`, `validSIGPROF` 支持 CPU 性能分析。

**7. 代码示例:**

以下是一些基于代码推理的示例：

*   **创建新的 Goroutine (涉及线程创建):**

```go
package main

import "runtime"

func myFunc() {
    println("Hello from a new goroutine")
}

func main() {
    runtime.GOMAXPROCS(1) // 限制只使用一个操作系统线程，方便观察
    go myFunc()
    // 等待一会，确保新 goroutine 有机会执行
    var input string
    println("Press Enter to exit")
    fmt.Scanln(&input)
}
```

   **假设输入：** 无
   **预期输出：**
   ```
   Hello from a new goroutine
   Press Enter to exit
   ```

   **解释:** `go myFunc()` 会创建一个新的 goroutine，而 Go runtime 会负责将其调度到一个操作系统线程上执行。`os3_solaris.go` 中的 `newosproc` 函数会被调用（在必要时）来创建一个新的操作系统线程来运行这个 goroutine。

*   **使用 `mmap` 进行内存映射:**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	file, err := os.Create("test.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	file.WriteString("This is a test.")
	file.Sync()

	mmapData, err := syscall.Mmap(int(file.Fd()), 0, 16, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		panic(err)
	}
	defer syscall.Munmap(mmapData)

	fmt.Println(string(mmapData))
}
```

   **假设输入：** 无
   **预期输出：**
   ```
   This is a test.
   ```

   **解释:**  `syscall.Mmap` 最终会调用 `os3_solaris.go` 中的 `mmap` 函数，将文件的一部分映射到内存中。

*   **获取当前时间 (涉及 `clock_gettime`):**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	now := time.Now()
	fmt.Println(now)
}
```

   **假设输入：** 无
   **预期输出：** 当前时间，例如 `2023-10-27 10:00:00 +0000 UTC`

   **解释:** `time.Now()` 内部会调用 Go runtime 的时间相关函数，最终会调用 `os3_solaris.go` 中的 `walltime` 函数，而 `walltime` 内部会调用 C 库的 `clock_gettime`。

**8. 命令行参数处理:**

`os3_solaris.go` 中的 `sysargs` 函数负责处理命令行参数。它接收 `argc` (参数数量) 和 `argv` (参数字符串数组的指针)。

*   它首先计算包括程序名在内的参数数量。
*   然后跳过 `argv` 和环境变量指针，定位到 `auxv` (Auxiliary Vector)，这是一个由内核传递给程序的环境信息数组。
*   `sysauxv` 函数解析 `auxv`，提取如页大小 (`_AT_PAGESZ`) 和可执行文件路径 (`_AT_SUN_EXECNAME`) 等信息。

**详细处理流程:**

1. **定位 `auxv`:** 内核在启动程序时，会将命令行参数 (`argv`)、环境变量 (`envp`) 和辅助向量 (`auxv`) 连续存储在进程的栈上。`sysargs` 通过遍历指针数组来跳过 `argv` 和 `envp`，找到 `auxv` 的起始位置。`argv_index(argv, n) != nil` 这个循环用于找到环境变量的结束位置，因为它之后通常会有一个 NULL 指针作为分隔符。
2. **解析 `auxv`:** `auxv` 是一个键值对数组，以 `_AT_NULL` 结尾。`sysauxv` 遍历这个数组，根据 `tag` (键) 来提取相应的值。
3. **存储信息:** 提取出的信息被存储在全局变量中，例如 `physPageSize` 和 `executablePath`。

**9. 使用者易犯错的点:**

*   **不正确的 CGO 使用:**  由于此文件大量使用了 CGO，直接修改或扩展此文件需要非常小心地处理 Go 和 C 之间的交互，包括内存管理、类型转换和线程安全。错误的 CGO 使用可能导致程序崩溃或未定义的行为。例如，在 Go 中分配的内存需要通过 Go 的方式释放，反之亦然。直接操作 C 指针而没有理解其生命周期可能导致问题。

    **错误示例 (假设在 Go 中直接 `free` C 分配的内存):**

    ```go
    // 假设 libc_malloc 和 libc_free 已经通过 cgo 导入
    import "C"
    import "unsafe"

    func main() {
        size := C.size_t(100)
        ptr := C.malloc(size)
        if ptr == nil {
            panic("malloc failed")
        }
        // 错误：应该使用 C.free
        free(unsafe.Pointer(ptr))
    }
    ```

    正确的做法是使用 `C.free(ptr)`.

*   **对信号处理的误解:**  Go 的信号处理模型与传统的 Unix 信号处理有所不同。直接调用底层的 `sigaction` 等函数可能会干扰 Go runtime 的信号处理机制，导致意外的行为，例如程序无法正常响应中断信号。

    **错误示例 (直接使用 `syscall` 包设置信号处理):**

    ```go
    package main

    import (
        "fmt"
        "os"
        "os/signal"
        "syscall"
    )

    func main() {
        // 错误：可能与 Go runtime 的信号处理冲突
        signalChan := make(chan os.Signal, 1)
        signal.Notify(signalChan, syscall.SIGINT)

        go func() {
            sig := <-signalChan
            fmt.Println("Received signal:", sig)
            os.Exit(1)
        }()

        // ... 程序逻辑 ...
        fmt.Println("Running...")
        select {}
    }
    ```

    虽然上面的代码在某些情况下可能工作，但它绕过了 Go runtime 的信号处理机制，可能导致与 Go 调度器的交互出现问题。推荐使用 `os/signal` 包进行信号处理，让 Go runtime 来管理底层的信号机制。

总而言之，`os3_solaris.go` 是 Go runtime 在 Solaris 上的底层实现，负责与操作系统内核交互，提供了线程管理、内存管理、信号处理等核心功能。直接使用或修改此文件需要深入理解操作系统原理和 Go runtime 的内部机制。

这个 Go 语言源文件 `go/src/runtime/os3_solaris.go` 是 Go 运行时环境（runtime）针对 Solaris 操作系统的特定实现。它主要负责提供 Go 程序在 Solaris 上运行所需的底层操作系统接口。

以下是该文件的一些主要功能：

1. **系统调用封装:** 该文件定义了许多与 Solaris 系统调用对应的 Go 函数。通过 `//go:cgo_import_dynamic` 和 `//go:linkname`，它将 Go 函数与 `libc.so` 中的 C 标准库函数动态链接起来。例如，`libc_open` 对应 C 的 `open` 函数，`libc_pthread_create` 对应 C 的 `pthread_create` 函数等。这使得 Go 代码可以调用底层的操作系统功能。

2. **线程管理:**  该文件实现了 Go 协程 (goroutine) 与操作系统线程的交互。`newosproc` 函数负责创建新的操作系统线程来运行 goroutine。它使用了 `pthread_create` 来创建线程，并设置了线程的栈大小和分离状态。

3. **内存管理:**  该文件包含与内存管理相关的系统调用封装，例如 `mmap`（用于内存映射）、`munmap`（取消内存映射）、`madvise`（提供内存使用建议）和 `getPageSize`（获取系统页大小）。

4. **信号处理:** 该文件处理操作系统信号，这是 Go 运行时进行垃圾回收、抢占调度等操作的基础。`setsig` 函数用于设置信号处理函数，`sigaction` 用于修改信号处理的行为，`sigprocmask` 用于屏蔽和取消屏蔽信号。`sigtramp` 可能是信号处理跳转的汇编代码入口（未在此文件中展示）。

5. **同步原语:**  该文件实现了基于信号量的同步机制。`semacreate` 用于创建信号量，`semasleep` 用于等待信号量，`semawakeup` 用于唤醒等待信号量的线程。

6. **时间相关功能:**  `nanotime1` 和 `walltime` 函数用于获取高精度的时间戳。它们分别使用了 `CLOCK_MONOTONIC` 和 `CLOCK_REALTIME` 时钟源。

7. **随机数生成:** `readRandom` 函数通过读取 `/dev/urandom` 设备来获取随机数。

8. **进程和线程信息:**  `pthread_self` 用于获取当前线程的 ID。

9. **程序启动和退出:** `osinit` 函数在程序启动时进行一些初始化操作，例如获取 CPU 核心数。`exit` 函数用于终止程序。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 运行时环境的核心组成部分，它直接支持了 Go 语言的以下功能：

*   **Goroutine 的并发执行:** 通过 `newosproc` 创建操作系统线程，使得 goroutine 能够并行运行。
*   **内存分配和管理:**  `mmap` 等函数为 Go 的内存分配器提供了底层的支持。
*   **垃圾回收:**  信号处理机制允许 Go 运行时在合适的时机触发垃圾回收。
*   **网络编程和系统调用:**  文件 I/O、网络操作等都依赖于这里封装的系统调用。
*   **时间相关操作:** `time` 包中的许多函数最终会调用这里的 `nanotime1` 或 `walltime`。
*   **同步机制:** `sync` 包中的某些同步原语（例如 `sync.Mutex` 的某些实现）可能会使用这里的信号量机制。

**Go 代码示例：**

以下代码示例展示了 Go 程序如何间接地使用 `os3_solaris.go` 中实现的功能：

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
)

func main() {
	// 1. 创建新的 Goroutine (间接使用 newosproc)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Hello from another goroutine!")
	}()

	// 2. 获取当前时间 (间接使用 walltime)
	now := time.Now()
	fmt.Println("Current time:", now)

	// 3. 休眠一段时间 (间接使用 usleep)
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Woke up!")

	// 4. 使用 mmap 进行内存映射 (需要引入 syscall 包)
	pageSize := syscall.Getpagesize()
	fmt.Println("Page size:", pageSize)

	// 设置使用的最大操作系统线程数
	runtime.GOMAXPROCS(2)

	wg.Wait()
}
```

**假设输入与输出：**

该示例代码不涉及用户输入。

**预期输出：** (时间会因运行环境而异)

```
Hello from another goroutine!
Current time: 2023-10-27 16:00:00 +0800 CST  // 实际时间
Woke up!
Page size: 4096 // Solaris 的页大小可能不同
```

**代码推理：**

*   `go func() { ... }()` 创建了一个新的 goroutine。Go 运行时环境可能会在需要时调用 `os3_solaris.go` 中的 `newosproc` 来创建一个新的操作系统线程来执行这个 goroutine。
*   `time.Now()` 最终会调用 `os3_solaris.go` 中的 `walltime` 函数来获取当前时间。
*   `time.Sleep()` 内部会使用 `os3_solaris.go` 中的 `usleep` 或类似的函数来让当前 goroutine 休眠。
*   `syscall.Getpagesize()` 会调用 `os3_solaris.go` 中的 `getPageSize` 函数来获取系统的页大小。
*   `runtime.GOMAXPROCS(2)` 设置了 Go 程序可以同时使用的最大操作系统线程数。这会影响 Go 调度器如何将 goroutine 分配到操作系统线程上运行。

**命令行参数的具体处理：**

`os3_solaris.go` 中的 `sysargs` 函数负责处理传递给 Go 程序的命令行参数。

*   **`sysargs(argc int32, argv **byte)`:** 该函数接收两个参数：
    *   `argc`: 一个整数，表示命令行参数的数量（包括程序名称本身）。
    *   `argv`: 一个指向字符指针数组的指针。这个数组包含了指向每个命令行参数字符串的指针。

*   **处理流程:**
    1. `sysargs` 函数首先确定参数的数量 `n`。
    2. 它然后跳过 `argv` 数组和环境变量数组，找到 `auxv` (Auxiliary Vector) 的起始位置。`auxv` 是内核传递给程序的一些辅助信息，例如页大小、可执行文件路径等。
    3. `sysauxv(auxvp[:])` 函数被调用来解析 `auxv`。
    4. 在 `sysauxv` 中，它遍历 `auxv` 数组，根据 `tag` 值来提取有用的信息。
        *   `_AT_PAGESZ`: 获取系统页大小并赋值给 `physPageSize` 变量。
        *   `_AT_SUN_EXECNAME`: 获取可执行文件的路径并赋值给 `executablePath` 变量。

**使用者易犯错的点：**

由于 `os3_solaris.go` 是 Go 运行时的底层实现，普通 Go 开发者通常不需要直接与之交互。但是，如果涉及到一些需要调用底层系统接口的操作，可能会遇到一些容易犯错的点：

1. **不正确地使用 `syscall` 包:**  `syscall` 包提供了访问底层系统调用的接口。如果直接使用 `syscall` 包中的函数，需要非常清楚地了解系统调用的语义和参数，否则容易出错，例如传递错误的参数类型或大小，导致程序崩溃或行为异常。

    **错误示例:** 假设错误地使用 `syscall.Mmap`，传递了不正确的长度：

    ```go
    package main

    import (
        "fmt"
        "os"
        "syscall"
        "unsafe"
    )

    func main() {
        file, err := os.Create("test.txt")
        if err != nil {
            panic(err)
        }
        defer file.Close()
        file.WriteString("Hello, world!")

        fd := int(file.Fd())
        length := 5 // 错误：长度小于文件实际内容
        prot := syscall.PROT_READ
        flags := syscall.MAP_SHARED
        offset := int64(0)

        data, err := syscall.Mmap(fd, offset, length, prot, flags)
        if err != nil {
            panic(err)
        }
        defer syscall.Munmap(data)

        // 可能读取到不完整的数据或发生错误
        fmt.Println(string(data))
    }
    ```

2. **混淆 Goroutine 和操作系统线程:**  虽然 Go 使用操作系统线程来运行 Goroutine，但它们是不同的概念。试图直接操作操作系统线程的属性（例如使用 `syscall` 包中的 `pthread_*` 函数）可能会干扰 Go 运行时的调度器，导致不可预测的行为。

3. **不正确地处理信号:**  直接使用 `syscall` 包来设置信号处理函数可能会与 Go 运行时的信号处理机制冲突，导致程序无法正常处理信号，例如无法响应 Ctrl+C 中断。应该使用 `os/signal` 包来进行信号处理，让 Go 运行时来管理底层的信号机制。

4. **CGO 的错误使用:** 如果涉及到 CGO，需要小心处理 Go 和 C 之间的内存管理、类型转换和线程安全问题。错误的 CGO 使用可能导致内存泄漏、数据损坏或程序崩溃。

总之，`os3_solaris.go` 是 Go 运行时在 Solaris 上的基石，提供了与操作系统交互的关键功能。理解它的作用有助于更深入地理解 Go 程序的运行机制。然而，普通 Go 开发者应尽量使用 Go 标准库提供的更高级别的抽象，避免直接操作底层的系统调用，以减少出错的可能性。

### 提示词
```
这是路径为go/src/runtime/os3_solaris.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/atomic"
	"unsafe"
)

//go:cgo_export_dynamic runtime.end _end
//go:cgo_export_dynamic runtime.etext _etext
//go:cgo_export_dynamic runtime.edata _edata

//go:cgo_import_dynamic libc____errno ___errno "libc.so"
//go:cgo_import_dynamic libc_clock_gettime clock_gettime "libc.so"
//go:cgo_import_dynamic libc_exit _exit "libc.so"
//go:cgo_import_dynamic libc_getcontext getcontext "libc.so"
//go:cgo_import_dynamic libc_kill kill "libc.so"
//go:cgo_import_dynamic libc_madvise madvise "libc.so"
//go:cgo_import_dynamic libc_malloc malloc "libc.so"
//go:cgo_import_dynamic libc_mmap mmap "libc.so"
//go:cgo_import_dynamic libc_munmap munmap "libc.so"
//go:cgo_import_dynamic libc_open open "libc.so"
//go:cgo_import_dynamic libc_pthread_attr_destroy pthread_attr_destroy "libc.so"
//go:cgo_import_dynamic libc_pthread_attr_getstack pthread_attr_getstack "libc.so"
//go:cgo_import_dynamic libc_pthread_attr_init pthread_attr_init "libc.so"
//go:cgo_import_dynamic libc_pthread_attr_setdetachstate pthread_attr_setdetachstate "libc.so"
//go:cgo_import_dynamic libc_pthread_attr_setstack pthread_attr_setstack "libc.so"
//go:cgo_import_dynamic libc_pthread_create pthread_create "libc.so"
//go:cgo_import_dynamic libc_pthread_self pthread_self "libc.so"
//go:cgo_import_dynamic libc_pthread_kill pthread_kill "libc.so"
//go:cgo_import_dynamic libc_raise raise "libc.so"
//go:cgo_import_dynamic libc_read read "libc.so"
//go:cgo_import_dynamic libc_select select "libc.so"
//go:cgo_import_dynamic libc_sched_yield sched_yield "libc.so"
//go:cgo_import_dynamic libc_sem_init sem_init "libc.so"
//go:cgo_import_dynamic libc_sem_post sem_post "libc.so"
//go:cgo_import_dynamic libc_sem_reltimedwait_np sem_reltimedwait_np "libc.so"
//go:cgo_import_dynamic libc_sem_wait sem_wait "libc.so"
//go:cgo_import_dynamic libc_setitimer setitimer "libc.so"
//go:cgo_import_dynamic libc_sigaction sigaction "libc.so"
//go:cgo_import_dynamic libc_sigaltstack sigaltstack "libc.so"
//go:cgo_import_dynamic libc_sigprocmask sigprocmask "libc.so"
//go:cgo_import_dynamic libc_sysconf sysconf "libc.so"
//go:cgo_import_dynamic libc_usleep usleep "libc.so"
//go:cgo_import_dynamic libc_write write "libc.so"
//go:cgo_import_dynamic libc_pipe2 pipe2 "libc.so"

//go:linkname libc____errno libc____errno
//go:linkname libc_clock_gettime libc_clock_gettime
//go:linkname libc_exit libc_exit
//go:linkname libc_getcontext libc_getcontext
//go:linkname libc_kill libc_kill
//go:linkname libc_madvise libc_madvise
//go:linkname libc_malloc libc_malloc
//go:linkname libc_mmap libc_mmap
//go:linkname libc_munmap libc_munmap
//go:linkname libc_open libc_open
//go:linkname libc_pthread_attr_destroy libc_pthread_attr_destroy
//go:linkname libc_pthread_attr_getstack libc_pthread_attr_getstack
//go:linkname libc_pthread_attr_init libc_pthread_attr_init
//go:linkname libc_pthread_attr_setdetachstate libc_pthread_attr_setdetachstate
//go:linkname libc_pthread_attr_setstack libc_pthread_attr_setstack
//go:linkname libc_pthread_create libc_pthread_create
//go:linkname libc_pthread_self libc_pthread_self
//go:linkname libc_pthread_kill libc_pthread_kill
//go:linkname libc_raise libc_raise
//go:linkname libc_read libc_read
//go:linkname libc_select libc_select
//go:linkname libc_sched_yield libc_sched_yield
//go:linkname libc_sem_init libc_sem_init
//go:linkname libc_sem_post libc_sem_post
//go:linkname libc_sem_reltimedwait_np libc_sem_reltimedwait_np
//go:linkname libc_sem_wait libc_sem_wait
//go:linkname libc_setitimer libc_setitimer
//go:linkname libc_sigaction libc_sigaction
//go:linkname libc_sigaltstack libc_sigaltstack
//go:linkname libc_sigprocmask libc_sigprocmask
//go:linkname libc_sysconf libc_sysconf
//go:linkname libc_usleep libc_usleep
//go:linkname libc_write libc_write
//go:linkname libc_pipe2 libc_pipe2

var (
	libc____errno,
	libc_clock_gettime,
	libc_exit,
	libc_getcontext,
	libc_kill,
	libc_madvise,
	libc_malloc,
	libc_mmap,
	libc_munmap,
	libc_open,
	libc_pthread_attr_destroy,
	libc_pthread_attr_getstack,
	libc_pthread_attr_init,
	libc_pthread_attr_setdetachstate,
	libc_pthread_attr_setstack,
	libc_pthread_create,
	libc_pthread_self,
	libc_pthread_kill,
	libc_raise,
	libc_read,
	libc_sched_yield,
	libc_select,
	libc_sem_init,
	libc_sem_post,
	libc_sem_reltimedwait_np,
	libc_sem_wait,
	libc_setitimer,
	libc_sigaction,
	libc_sigaltstack,
	libc_sigprocmask,
	libc_sysconf,
	libc_usleep,
	libc_write,
	libc_pipe2 libcFunc
)

var sigset_all = sigset{[4]uint32{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)}}

func getPageSize() uintptr {
	n := int32(sysconf(__SC_PAGESIZE))
	if n <= 0 {
		return 0
	}
	return uintptr(n)
}

func osinit() {
	// Call miniterrno so that we can safely make system calls
	// before calling minit on m0.
	asmcgocall(unsafe.Pointer(abi.FuncPCABI0(miniterrno)), unsafe.Pointer(&libc____errno))

	ncpu = getncpu()
	if physPageSize == 0 {
		physPageSize = getPageSize()
	}
}

func tstart_sysvicall(newm *m) uint32

// May run with m.p==nil, so write barriers are not allowed.
//
//go:nowritebarrier
func newosproc(mp *m) {
	var (
		attr pthreadattr
		oset sigset
		tid  pthread
		ret  int32
		size uint64
	)

	if pthread_attr_init(&attr) != 0 {
		throw("pthread_attr_init")
	}
	// Allocate a new 2MB stack.
	if pthread_attr_setstack(&attr, 0, 0x200000) != 0 {
		throw("pthread_attr_setstack")
	}
	// Read back the allocated stack.
	if pthread_attr_getstack(&attr, unsafe.Pointer(&mp.g0.stack.hi), &size) != 0 {
		throw("pthread_attr_getstack")
	}
	mp.g0.stack.lo = mp.g0.stack.hi - uintptr(size)
	if pthread_attr_setdetachstate(&attr, _PTHREAD_CREATE_DETACHED) != 0 {
		throw("pthread_attr_setdetachstate")
	}

	// Disable signals during create, so that the new thread starts
	// with signals disabled. It will enable them in minit.
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)
	ret = retryOnEAGAIN(func() int32 {
		return pthread_create(&tid, &attr, abi.FuncPCABI0(tstart_sysvicall), unsafe.Pointer(mp))
	})
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if ret != 0 {
		print("runtime: failed to create new OS thread (have ", mcount(), " already; errno=", ret, ")\n")
		if ret == _EAGAIN {
			println("runtime: may need to increase max user processes (ulimit -u)")
		}
		throw("newosproc")
	}
}

func exitThread(wait *atomic.Uint32) {
	// We should never reach exitThread on Solaris because we let
	// libc clean up threads.
	throw("exitThread")
}

var urandom_dev = []byte("/dev/urandom\x00")

//go:nosplit
func readRandom(r []byte) int {
	fd := open(&urandom_dev[0], 0 /* O_RDONLY */, 0)
	n := read(fd, unsafe.Pointer(&r[0]), int32(len(r)))
	closefd(fd)
	return int(n)
}

func goenvs() {
	goenvs_unix()
}

// Called to initialize a new m (including the bootstrap m).
// Called on the parent thread (main thread in case of bootstrap), can allocate memory.
func mpreinit(mp *m) {
	mp.gsignal = malg(32 * 1024)
	mp.gsignal.m = mp
}

func miniterrno()

// Called to initialize a new m (including the bootstrap m).
// Called on the new thread, cannot allocate memory.
func minit() {
	asmcgocall(unsafe.Pointer(abi.FuncPCABI0(miniterrno)), unsafe.Pointer(&libc____errno))

	minitSignals()

	getg().m.procid = uint64(pthread_self())
}

// Called from dropm to undo the effect of an minit.
func unminit() {
	unminitSignals()
	getg().m.procid = 0
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
func mdestroy(mp *m) {
}

func sigtramp()

//go:nosplit
//go:nowritebarrierrec
func setsig(i uint32, fn uintptr) {
	var sa sigactiont

	sa.sa_flags = _SA_SIGINFO | _SA_ONSTACK | _SA_RESTART
	sa.sa_mask = sigset_all
	if fn == abi.FuncPCABIInternal(sighandler) { // abi.FuncPCABIInternal(sighandler) matches the callers in signal_unix.go
		fn = abi.FuncPCABI0(sigtramp)
	}
	*((*uintptr)(unsafe.Pointer(&sa._funcptr))) = fn
	sigaction(i, &sa, nil)
}

//go:nosplit
//go:nowritebarrierrec
func setsigstack(i uint32) {
	var sa sigactiont
	sigaction(i, nil, &sa)
	if sa.sa_flags&_SA_ONSTACK != 0 {
		return
	}
	sa.sa_flags |= _SA_ONSTACK
	sigaction(i, &sa, nil)
}

//go:nosplit
//go:nowritebarrierrec
func getsig(i uint32) uintptr {
	var sa sigactiont
	sigaction(i, nil, &sa)
	return *((*uintptr)(unsafe.Pointer(&sa._funcptr)))
}

// setSignalstackSP sets the ss_sp field of a stackt.
//
//go:nosplit
func setSignalstackSP(s *stackt, sp uintptr) {
	*(*uintptr)(unsafe.Pointer(&s.ss_sp)) = sp
}

//go:nosplit
//go:nowritebarrierrec
func sigaddset(mask *sigset, i int) {
	mask.__sigbits[(i-1)/32] |= 1 << ((uint32(i) - 1) & 31)
}

func sigdelset(mask *sigset, i int) {
	mask.__sigbits[(i-1)/32] &^= 1 << ((uint32(i) - 1) & 31)
}

//go:nosplit
func (c *sigctxt) fixsigcode(sig uint32) {
}

func setProcessCPUProfiler(hz int32) {
	setProcessCPUProfilerTimer(hz)
}

func setThreadCPUProfiler(hz int32) {
	setThreadCPUProfilerHz(hz)
}

//go:nosplit
func validSIGPROF(mp *m, c *sigctxt) bool {
	return true
}

//go:nosplit
func semacreate(mp *m) {
	if mp.waitsema != 0 {
		return
	}

	var sem *semt

	// Call libc's malloc rather than malloc. This will
	// allocate space on the C heap. We can't call malloc
	// here because it could cause a deadlock.
	mp.libcall.fn = uintptr(unsafe.Pointer(&libc_malloc))
	mp.libcall.n = 1
	mp.scratch = mscratch{}
	mp.scratch.v[0] = unsafe.Sizeof(*sem)
	mp.libcall.args = uintptr(unsafe.Pointer(&mp.scratch))
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&mp.libcall))
	sem = (*semt)(unsafe.Pointer(mp.libcall.r1))
	if sem_init(sem, 0, 0) != 0 {
		throw("sem_init")
	}
	mp.waitsema = uintptr(unsafe.Pointer(sem))
}

//go:nosplit
func semasleep(ns int64) int32 {
	mp := getg().m
	if ns >= 0 {
		mp.ts.tv_sec = ns / 1000000000
		mp.ts.tv_nsec = ns % 1000000000

		mp.libcall.fn = uintptr(unsafe.Pointer(&libc_sem_reltimedwait_np))
		mp.libcall.n = 2
		mp.scratch = mscratch{}
		mp.scratch.v[0] = mp.waitsema
		mp.scratch.v[1] = uintptr(unsafe.Pointer(&mp.ts))
		mp.libcall.args = uintptr(unsafe.Pointer(&mp.scratch))
		asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&mp.libcall))
		if *mp.perrno != 0 {
			if *mp.perrno == _ETIMEDOUT || *mp.perrno == _EAGAIN || *mp.perrno == _EINTR {
				return -1
			}
			throw("sem_reltimedwait_np")
		}
		return 0
	}
	for {
		mp.libcall.fn = uintptr(unsafe.Pointer(&libc_sem_wait))
		mp.libcall.n = 1
		mp.scratch = mscratch{}
		mp.scratch.v[0] = mp.waitsema
		mp.libcall.args = uintptr(unsafe.Pointer(&mp.scratch))
		asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&mp.libcall))
		if mp.libcall.r1 == 0 {
			break
		}
		if *mp.perrno == _EINTR {
			continue
		}
		throw("sem_wait")
	}
	return 0
}

//go:nosplit
func semawakeup(mp *m) {
	if sem_post((*semt)(unsafe.Pointer(mp.waitsema))) != 0 {
		throw("sem_post")
	}
}

//go:nosplit
func closefd(fd int32) int32 {
	return int32(sysvicall1(&libc_close, uintptr(fd)))
}

//go:nosplit
func exit(r int32) {
	sysvicall1(&libc_exit, uintptr(r))
}

//go:nosplit
func getcontext(context *ucontext) /* int32 */ {
	sysvicall1(&libc_getcontext, uintptr(unsafe.Pointer(context)))
}

//go:nosplit
func madvise(addr unsafe.Pointer, n uintptr, flags int32) {
	sysvicall3(&libc_madvise, uintptr(addr), uintptr(n), uintptr(flags))
}

//go:nosplit
func mmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) (unsafe.Pointer, int) {
	p, err := doMmap(uintptr(addr), n, uintptr(prot), uintptr(flags), uintptr(fd), uintptr(off))
	if p == ^uintptr(0) {
		return nil, int(err)
	}
	return unsafe.Pointer(p), 0
}

//go:nosplit
//go:cgo_unsafe_args
func doMmap(addr, n, prot, flags, fd, off uintptr) (uintptr, uintptr) {
	var libcall libcall
	libcall.fn = uintptr(unsafe.Pointer(&libc_mmap))
	libcall.n = 6
	libcall.args = uintptr(noescape(unsafe.Pointer(&addr)))
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&libcall))
	return libcall.r1, libcall.err
}

//go:nosplit
func munmap(addr unsafe.Pointer, n uintptr) {
	sysvicall2(&libc_munmap, uintptr(addr), uintptr(n))
}

const (
	_CLOCK_REALTIME  = 3
	_CLOCK_MONOTONIC = 4
)

//go:nosplit
func nanotime1() int64 {
	var ts mts
	sysvicall2(&libc_clock_gettime, _CLOCK_MONOTONIC, uintptr(unsafe.Pointer(&ts)))
	return ts.tv_sec*1e9 + ts.tv_nsec
}

//go:nosplit
func open(path *byte, mode, perm int32) int32 {
	return int32(sysvicall3(&libc_open, uintptr(unsafe.Pointer(path)), uintptr(mode), uintptr(perm)))
}

func pthread_attr_destroy(attr *pthreadattr) int32 {
	return int32(sysvicall1(&libc_pthread_attr_destroy, uintptr(unsafe.Pointer(attr))))
}

func pthread_attr_getstack(attr *pthreadattr, addr unsafe.Pointer, size *uint64) int32 {
	return int32(sysvicall3(&libc_pthread_attr_getstack, uintptr(unsafe.Pointer(attr)), uintptr(addr), uintptr(unsafe.Pointer(size))))
}

func pthread_attr_init(attr *pthreadattr) int32 {
	return int32(sysvicall1(&libc_pthread_attr_init, uintptr(unsafe.Pointer(attr))))
}

func pthread_attr_setdetachstate(attr *pthreadattr, state int32) int32 {
	return int32(sysvicall2(&libc_pthread_attr_setdetachstate, uintptr(unsafe.Pointer(attr)), uintptr(state)))
}

func pthread_attr_setstack(attr *pthreadattr, addr uintptr, size uint64) int32 {
	return int32(sysvicall3(&libc_pthread_attr_setstack, uintptr(unsafe.Pointer(attr)), uintptr(addr), uintptr(size)))
}

func pthread_create(thread *pthread, attr *pthreadattr, fn uintptr, arg unsafe.Pointer) int32 {
	return int32(sysvicall4(&libc_pthread_create, uintptr(unsafe.Pointer(thread)), uintptr(unsafe.Pointer(attr)), uintptr(fn), uintptr(arg)))
}

func pthread_self() pthread {
	return pthread(sysvicall0(&libc_pthread_self))
}

func signalM(mp *m, sig int) {
	sysvicall2(&libc_pthread_kill, uintptr(pthread(mp.procid)), uintptr(sig))
}

//go:nosplit
//go:nowritebarrierrec
func raise(sig uint32) /* int32 */ {
	sysvicall1(&libc_raise, uintptr(sig))
}

func raiseproc(sig uint32) /* int32 */ {
	pid := sysvicall0(&libc_getpid)
	sysvicall2(&libc_kill, pid, uintptr(sig))
}

//go:nosplit
func read(fd int32, buf unsafe.Pointer, nbyte int32) int32 {
	r1, err := sysvicall3Err(&libc_read, uintptr(fd), uintptr(buf), uintptr(nbyte))
	if c := int32(r1); c >= 0 {
		return c
	}
	return -int32(err)
}

//go:nosplit
func sem_init(sem *semt, pshared int32, value uint32) int32 {
	return int32(sysvicall3(&libc_sem_init, uintptr(unsafe.Pointer(sem)), uintptr(pshared), uintptr(value)))
}

//go:nosplit
func sem_post(sem *semt) int32 {
	return int32(sysvicall1(&libc_sem_post, uintptr(unsafe.Pointer(sem))))
}

//go:nosplit
func sem_reltimedwait_np(sem *semt, timeout *timespec) int32 {
	return int32(sysvicall2(&libc_sem_reltimedwait_np, uintptr(unsafe.Pointer(sem)), uintptr(unsafe.Pointer(timeout))))
}

//go:nosplit
func sem_wait(sem *semt) int32 {
	return int32(sysvicall1(&libc_sem_wait, uintptr(unsafe.Pointer(sem))))
}

func setitimer(which int32, value *itimerval, ovalue *itimerval) /* int32 */ {
	sysvicall3(&libc_setitimer, uintptr(which), uintptr(unsafe.Pointer(value)), uintptr(unsafe.Pointer(ovalue)))
}

//go:nosplit
//go:nowritebarrierrec
func sigaction(sig uint32, act *sigactiont, oact *sigactiont) /* int32 */ {
	sysvicall3(&libc_sigaction, uintptr(sig), uintptr(unsafe.Pointer(act)), uintptr(unsafe.Pointer(oact)))
}

//go:nosplit
//go:nowritebarrierrec
func sigaltstack(ss *stackt, oss *stackt) /* int32 */ {
	sysvicall2(&libc_sigaltstack, uintptr(unsafe.Pointer(ss)), uintptr(unsafe.Pointer(oss)))
}

//go:nosplit
//go:nowritebarrierrec
func sigprocmask(how int32, set *sigset, oset *sigset) /* int32 */ {
	sysvicall3(&libc_sigprocmask, uintptr(how), uintptr(unsafe.Pointer(set)), uintptr(unsafe.Pointer(oset)))
}

func sysconf(name int32) int64 {
	return int64(sysvicall1(&libc_sysconf, uintptr(name)))
}

func usleep1(usec uint32)

//go:nosplit
func usleep_no_g(µs uint32) {
	usleep1(µs)
}

//go:nosplit
func usleep(µs uint32) {
	usleep1(µs)
}

func walltime() (sec int64, nsec int32) {
	var ts mts
	sysvicall2(&libc_clock_gettime, _CLOCK_REALTIME, uintptr(unsafe.Pointer(&ts)))
	return ts.tv_sec, int32(ts.tv_nsec)
}

//go:nosplit
func write1(fd uintptr, buf unsafe.Pointer, nbyte int32) int32 {
	r1, err := sysvicall3Err(&libc_write, fd, uintptr(buf), uintptr(nbyte))
	if c := int32(r1); c >= 0 {
		return c
	}
	return -int32(err)
}

//go:nosplit
func pipe2(flags int32) (r, w int32, errno int32) {
	var p [2]int32
	_, e := sysvicall2Err(&libc_pipe2, uintptr(noescape(unsafe.Pointer(&p))), uintptr(flags))
	return p[0], p[1], int32(e)
}

//go:nosplit
func fcntl(fd, cmd, arg int32) (ret int32, errno int32) {
	r1, err := sysvicall3Err(&libc_fcntl, uintptr(fd), uintptr(cmd), uintptr(arg))
	return int32(r1), int32(err)
}

func osyield1()

//go:nosplit
func osyield_no_g() {
	osyield1()
}

//go:nosplit
func osyield() {
	sysvicall0(&libc_sched_yield)
}

//go:linkname executablePath os.executablePath
var executablePath string

func sysargs(argc int32, argv **byte) {
	n := argc + 1

	// skip over argv, envp to get to auxv
	for argv_index(argv, n) != nil {
		n++
	}

	// skip NULL separator
	n++

	// now argv+n is auxv
	auxvp := (*[1 << 28]uintptr)(add(unsafe.Pointer(argv), uintptr(n)*goarch.PtrSize))
	pairs := sysauxv(auxvp[:])
	auxv = auxvp[: pairs*2 : pairs*2]
}

const (
	_AT_NULL         = 0    // Terminates the vector
	_AT_PAGESZ       = 6    // Page size in bytes
	_AT_SUN_EXECNAME = 2014 // exec() path name
)

func sysauxv(auxv []uintptr) (pairs int) {
	var i int
	for i = 0; auxv[i] != _AT_NULL; i += 2 {
		tag, val := auxv[i], auxv[i+1]
		switch tag {
		case _AT_PAGESZ:
			physPageSize = val
		case _AT_SUN_EXECNAME:
			executablePath = gostringnocopy((*byte)(unsafe.Pointer(val)))
		}
	}
	return i / 2
}

// sigPerThreadSyscall is only used on linux, so we assign a bogus signal
// number.
const sigPerThreadSyscall = 1 << 31

//go:nosplit
func runPerThreadSyscall() {
	throw("runPerThreadSyscall only valid on linux")
}
```