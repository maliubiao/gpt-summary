Response:
Let's break down the thought process for analyzing this Go runtime code snippet for Plan 9.

**1. Initial Scan and Identification of Key Elements:**

My first step is always to quickly scan the code for recognizable patterns and keywords. I look for:

* **Package and Imports:** `package runtime`, imports like `internal/abi`, `internal/runtime/atomic`, `unsafe`. This immediately tells me it's a low-level part of the Go runtime.
* **Platform-Specific Filename:** `os_plan9.go` strongly indicates it's for the Plan 9 operating system.
* **Type Definitions:** `mOS`, `_Plink`, `sigset`. These are likely structures specific to how the runtime interacts with Plan 9.
* **Function Declarations:** A large number of functions with lowercase names like `closefd`, `open`, `pread`, `pwrite`, `exits`, `rfork`, `plan9_semacquire`, `notify`, `nsec`, etc. The `//go:noescape` and `//go:nosplit` comments are also significant, indicating low-level system calls or performance-critical functions.
* **Global Variables:**  `sysstat`, `devswap`, `pagesize`, `pid`, `goexits`, `emptystatus`, `exiting`, `procdir`, `notefile`. These likely represent file paths, status messages, or shared state.
* **Signal Handling:** Functions like `sigpanic`, `sigtramp`, `initsig`, `raisebadsignal`, and mentions of signals like `_SIGRFAULT`, `_SIGWFAULT`, `_SIGTRAP`.

**2. Grouping Functions by Functionality:**

As I identify these elements, I start mentally grouping them by their apparent purpose:

* **File Operations:** `closefd`, `open`, `pread`, `pwrite`, `seek`. These are standard file system operations.
* **Process Control:** `exits`, `rfork`, `getpid`, `newosproc`, `exit`.
* **Memory Management (Hints):** `brk_`, `getPageSize`, mentions of "arena chunk".
* **Synchronization:** `plan9_semacquire`, `plan9_tsemacquire`, `plan9_semrelease`, `semacreate`, `semasleep`, `semawakeup`. The "sema" prefix is a strong indicator of semaphores.
* **Time:** `sleep`, `nsec`, `nanotime1`, `usleep`.
* **Signals:**  `sigpanic`, `sigtramp`, `notify`, `noted`, `initsig`, `raisebadsignal`.
* **Error Handling:** `errstr`.
* **Concurrency/Threads:** `mpreinit`, `minit`, `unminit`, `mdestroy`, `tstart_plan9`, `exitThread`.
* **Utility/Helper:** `atolwhex`, `indexNoFloat`, `bytesHasPrefix`, `_atoi`, `itoa`, `findnull`.

**3. Inferring Go Functionality Based on Plan 9 Primitives:**

This is the core of the analysis. I look for patterns that map Plan 9 system calls to higher-level Go concepts:

* **Semaphores (`plan9_semacquire`, `plan9_semrelease`):** These clearly implement Go's synchronization primitives, likely used in things like mutexes or wait groups.
* **`rfork`:**  This is Plan 9's equivalent of `fork` with flags. The `_RFPROC` flag strongly suggests it's used to create new OS threads for Go goroutines. `newosproc` confirms this.
* **`notify` and Signals:**  The use of `notify` with `sigtramp` suggests that Go's signal handling mechanism is built on Plan 9's notification system. `sigpanic` confirms the mapping of OS signals to Go panics.
* **`/dev/sysstat`:** Reading this file to get CPU count is a classic Plan 9 way of doing it, and `getproccount`'s purpose is obvious.
* **`/dev/swap`:** Reading this file (specifically looking for "pagesize") is how Plan 9 exposes memory information, hence `getPageSize`.
* **`#c/pid`:**  This Plan 9 "attribute file" provides the process ID, explaining `getpid`.
* **`exits`:** This is the fundamental way to terminate a process on Plan 9, directly corresponding to Go's `os.Exit` or the runtime's internal exit paths.

**4. Code Example Construction (Trial and Error/Refinement):**

Once I have a hypothesis about the functionality, I try to construct a simple Go example that would trigger the use of these underlying Plan 9 functions. This often involves some trial and error:

* **For Goroutines:** I know Go uses threads for concurrency, so a simple `go func() {}()` example should trigger `newosproc` and `rfork`.
* **For Synchronization:**  Using `sync.Mutex` or `sync.WaitGroup` will likely involve the semaphore-related functions.
* **For System Calls:** Operations like reading a file using `os.Open` and `io.ReadAll` should use `open` and `pread`.
* **For Exiting:** `os.Exit()` will directly call `exits`.
* **For Signals/Panics:**  Intentionally causing a division by zero or accessing a nil pointer *might* trigger the signal handling path and `sigpanic`. (This is more complex to reliably trigger without platform-specific knowledge.)

**5. Considering Edge Cases and Potential Errors:**

I then think about common mistakes a developer might make when working with these features:

* **Signal Handling:**  Assuming standard POSIX signal numbers on Plan 9 is a clear error. The `sigpanic` function explicitly parses Plan 9's note strings.
* **Concurrency:**  Not understanding that goroutines map to OS threads on Plan 9 could lead to incorrect assumptions about scheduling or resource usage.
* **File Operations:**  Plan 9's file system namespace is quite different from Unix-like systems. Hardcoding paths might not work.

**6. Structuring the Answer:**

Finally, I organize the information logically:

* **List of Functions:** A straightforward enumeration of the functions and their basic roles.
* **Inferred Functionality:**  A more detailed explanation of the key Go features implemented by this code, with specific examples.
* **Code Examples:** Concrete Go code illustrating the inferred functionality, with hypothetical inputs and outputs where appropriate.
* **Command-Line Arguments:** Checking for any functions that directly process command-line arguments (none in this snippet).
* **Common Mistakes:** Highlighting potential pitfalls for developers.

**Self-Correction/Refinement during the process:**

* **Initial Assumption about `brk_`:** I might initially think `brk_` is the primary memory allocation mechanism. However, seeing `mallocgc` used elsewhere makes me realize `brk_` is likely a lower-level primitive or used in specific scenarios.
* **Signal Handling Complexity:**  Recognizing that triggering `sigpanic` directly is tricky and relies on the OS sending specific signals with specific note formats.
* **Focus on Observable Behavior:**  Prioritizing examples that demonstrate the *effect* of the code (e.g., creating a new thread, synchronizing access) rather than trying to reverse-engineer every internal detail.

By following this structured approach, combining code analysis with knowledge of operating system concepts and Go's runtime architecture, I can effectively understand and explain the functionality of this platform-specific Go code.
这段代码是 Go 语言运行时 (runtime) 在 Plan 9 操作系统上的实现部分。它提供了一系列底层的操作系统接口，使得 Go 程序能够在 Plan 9 环境下运行。

以下是代码中各个部分的主要功能：

**1. `mOS` 结构体:**

*   `waitsemacount uint32`:  用于实现信号量的计数器，用于 goroutine 的同步。
*   `notesig *int8`:  指向一个 C 字符串，用于存储接收到的 Plan 9 注释（类似信号）。
*   `errstr *byte`:  指向一个字节数组，用于存储 Plan 9 系统调用返回的错误字符串。
*   `ignoreHangup bool`:  一个布尔值，用于指示是否忽略挂起信号。

**2. 系统调用包装函数:**

这段代码定义了许多 Go 函数，它们直接包装了 Plan 9 的系统调用。这些函数带有 `//go:noescape` 注释，表明它们不会让参数逃逸到堆上，通常用于与底层系统进行高效交互。

*   `closefd(fd int32) int32`: 关闭文件描述符。
*   `open(name *byte, mode, perm int32) int32`: 打开文件。
*   `pread(fd int32, buf unsafe.Pointer, nbytes int32, offset int64) int32`: 从指定偏移量读取文件。
*   `pwrite(fd int32, buf unsafe.Pointer, nbytes int32, offset int64) int32`: 从指定偏移量写入文件。
*   `seek(fd int32, offset int64, whence int32) int64`: 移动文件读写指针。
*   `exits(msg *byte)`:  终止进程并返回状态信息。
*   `brk_(addr unsafe.Pointer) int32`:  调整进程的数据段大小（用于内存分配，但在 Go 中通常不直接使用）。
*   `sleep(ms int32) int32`:  让当前线程休眠指定的毫秒数。
*   `rfork(flags int32) int32`:  创建一个新的进程或线程。
*   `plan9_semacquire(addr *uint32, block int32) int32`:  获取 Plan 9 信号量。
*   `plan9_tsemacquire(addr *uint32, ms int32) int32`:  限时获取 Plan 9 信号量。
*   `plan9_semrelease(addr *uint32, count int32) int32`:  释放 Plan 9 信号量。
*   `notify(fn unsafe.Pointer) int32`:  发送一个通知（类似于信号）。
*   `noted(mode int32) int32`:  检查是否有未处理的通知。
*   `nsec(*int64) int64`:  获取当前纳秒时间。
*   `sigtramp(ureg, note unsafe.Pointer)`:  信号处理函数的入口点。
*   `setfpmasks()`:  设置浮点数掩码。
*   `tstart_plan9(newm *m)`:  在新创建的操作系统线程上启动一个 Go 的 M (machine)。

**3. `sigpanic()` 函数:**

*   这个函数处理接收到的 Plan 9 注释 (notes)，并将其转化为 Go 的 panic。
*   它会根据不同的注释内容（例如内存访问错误 `_SIGRFAULT`, `_SIGWFAULT`，陷阱指令 `_SIGTRAP` 等）触发不同的 panic 类型。
*   它还会解析注释中的地址信息，并将其包含在 panic 信息中。

**4. 辅助函数:**

*   `indexNoFloat(s, t string) int`:  类似于 `strings.Index`，但在信号处理上下文中安全使用。
*   `atolwhex(p string) int64`:  将字符串转换为整数，支持十进制、八进制和十六进制。

**5. 信号处理相关函数:**

*   `mpreinit(mp *m)`:  初始化一个新的 M 结构体（代表一个操作系统线程）。
*   `sigsave(p *sigset)` 和 `msigrestore(sigmask sigset)`:  在 Plan 9 上为空实现，因为 Plan 9 的信号处理模型不同。
*   `clearSignalHandlers()` 和 `sigblock(exiting bool)`:  在 Plan 9 上为空实现。
*   `initsig(preinit bool)`:  初始化信号处理机制，注册信号处理函数。

**6. 线程管理相关函数:**

*   `minit()`:  在新的操作系统线程上初始化 Go 运行时环境。
*   `unminit()`:  撤销 `minit` 的效果。
*   `mdestroy(mp *m)`:  清理线程相关的资源。
*   `newosproc(mp *m)`:  创建一个新的操作系统线程来运行 Go 代码 (goroutine)。
*   `exitThread(wait *atomic.Uint32)`:  在 Plan 9 上会抛出异常，因为 Plan 9 由操作系统负责清理线程。

**7. 进程和 CPU 管理相关函数:**

*   `getproccount() int32`:  通过读取 `/dev/sysstat` 文件获取 CPU 核心数量。
*   `getPageSize() uintptr`:  通过读取 `/dev/swap` 文件获取系统页大小。
*   `getpid() uint64`:  通过读取 `#c/pid` 文件获取当前进程的 PID。
*   `osinit()`:  初始化与操作系统相关的运行时参数，例如页大小和 CPU 数量。

**8. 其他实用函数:**

*   `crash()`:  人为触发一个 crash，用于调试。
*   `readRandom(r []byte) int`:  在 Plan 9 上总是返回 0，因为没有实现读取随机数。
*   `osyield()` 和 `osyield_no_g()`:  让当前线程让出 CPU 时间片。
*   `usleep(µs uint32)` 和 `usleep_no_g(usec uint32)`:  让当前线程休眠指定的微秒数。
*   `nanotime1() int64`:  获取当前纳秒时间。
*   `goexitsall(status *byte)`:  向所有 Go 创建的线程发送退出通知。
*   `postnote(pid uint64, msg []byte) int`:  向指定的进程发送 Plan 9 注释。
*   `exit(e int32)`:  退出当前进程。
*   `semacreate(mp *m)`:  在 Plan 9 上为空实现。
*   `semasleep(ns int64) int`:  让当前 goroutine 休眠，基于 Plan 9 的信号量实现。
*   `semawakeup(mp *m)`:  唤醒一个等待中的 goroutine，基于 Plan 9 的信号量实现。
*   `read(fd int32, buf unsafe.Pointer, n int32) int32`:  读取文件。
*   `write1(fd uintptr, buf unsafe.Pointer, n int32) int32`:  写入文件。
*   `badsignal2()` 和 `raisebadsignal(sig uint32)`:  处理在非 Go 创建的线程上收到的信号。
*   `_atoi(b []byte) int`:  将字节数组转换为整数。
*   `signame(sig uint32) string`:  获取信号的名称。
*   `preemptM(mp *m)`:  在 Plan 9 上未实现，用于抢占 M。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言运行时在 Plan 9 操作系统上的 **操作系统接口层 (OS Interface)** 的实现。它负责：

*   **线程管理 (Goroutines):**  通过 `rfork` 创建新的操作系统线程来运行 goroutines，并提供 `semacquire` 和 `semrelease` 等基于 Plan 9 信号量的同步机制。
*   **内存管理 (部分):** 虽然 `brk_` 可以调整数据段大小，但 Go 的内存管理主要由更上层的代码负责。这里可能涉及到获取页大小等底层信息。
*   **信号处理 (Panics):**  将 Plan 9 的注释 (类似信号) 转换为 Go 的 panic 机制。
*   **系统调用:**  提供 Go 程序调用底层 Plan 9 系统调用的能力，例如文件操作、进程控制、时间获取等。
*   **进程和 CPU 信息:**  获取 CPU 核心数和进程 ID 等信息。
*   **时间相关:**  提供获取纳秒级时间以及休眠的功能。

**Go 代码示例：**

以下是一些示例，展示了这段代码可能支持的 Go 语言功能：

```go
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

func main() {
	fmt.Println("Go is running on Plan 9")
	fmt.Println("Number of CPUs:", runtime.NumCPU())

	// 创建一个 goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Hello from a goroutine!")
		time.Sleep(time.Second)
	}()
	wg.Wait()

	// 文件操作
	file, err := os.Create("test.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	_, err = file.WriteString("Hello, Plan 9!")
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	// 退出程序
	os.Exit(0)
}
```

**假设的输入与输出：**

运行上述代码，假设 Plan 9 系统配置了 2 个 CPU 核心，预期输出可能如下：

```
Go is running on Plan 9
Number of CPUs: 2
Hello from a goroutine!
```

并在当前目录下创建一个名为 `test.txt` 的文件，内容为 "Hello, Plan 9!".

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。Go 语言处理命令行参数的功能位于 `os` 包中，运行时会将命令行参数传递给 `main` 函数。这段代码更多关注的是底层的操作系统交互，不涉及高层的参数解析。

**使用者易犯错的点：**

*   **信号处理的假设：**  Plan 9 的信号机制与 POSIX 系统（如 Linux, macOS）有很大不同，它使用 "notes"。直接假设 POSIX 信号编号和行为可能会导致错误。例如，尝试使用 `syscall.SIGINT` 等常量可能与 Plan 9 的实际信号不符。

    ```go
    // 错误示例 (可能在 Plan 9 上不起作用或行为不一致)
    // import "syscall"
    // syscall.Kill(syscall.Getpid(), syscall.SIGINT)
    ```

*   **文件路径的假设：** Plan 9 的文件系统命名空间是全局的，与传统 Unix 系统的 `/` 根目录概念不同。硬编码绝对路径可能在不同的 Plan 9 环境中失效。

*   **对线程模型的理解：**  虽然 Go 使用 goroutine 进行并发，但在 Plan 9 上，每个 goroutine 通常会对应一个操作系统线程。过度创建 goroutine 可能会导致系统资源耗尽。

*   **依赖 POSIX 特定的系统调用：**  尝试使用 `syscall` 包中一些 POSIX 特有的系统调用（例如与 socket 相关的调用，如果 Plan 9 的网络实现方式不同）可能会失败。开发者需要了解 Plan 9 提供的系统调用接口。

总而言之，这段代码是 Go 语言运行时的核心组成部分，它负责将 Go 程序的需求转化为 Plan 9 操作系统能够理解和执行的指令，是 Go 能够在 Plan 9 上运行的基石。理解这段代码有助于深入了解 Go 的底层机制以及 Go 如何在不同的操作系统上进行适配。

Prompt: 
```
这是路径为go/src/runtime/os_plan9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"internal/stringslite"
	"unsafe"
)

type mOS struct {
	waitsemacount uint32
	notesig       *int8
	errstr        *byte
	ignoreHangup  bool
}

func closefd(fd int32) int32

//go:noescape
func open(name *byte, mode, perm int32) int32

//go:noescape
func pread(fd int32, buf unsafe.Pointer, nbytes int32, offset int64) int32

//go:noescape
func pwrite(fd int32, buf unsafe.Pointer, nbytes int32, offset int64) int32

func seek(fd int32, offset int64, whence int32) int64

//go:noescape
func exits(msg *byte)

//go:noescape
func brk_(addr unsafe.Pointer) int32

func sleep(ms int32) int32

func rfork(flags int32) int32

//go:noescape
func plan9_semacquire(addr *uint32, block int32) int32

//go:noescape
func plan9_tsemacquire(addr *uint32, ms int32) int32

//go:noescape
func plan9_semrelease(addr *uint32, count int32) int32

//go:noescape
func notify(fn unsafe.Pointer) int32

func noted(mode int32) int32

//go:noescape
func nsec(*int64) int64

//go:noescape
func sigtramp(ureg, note unsafe.Pointer)

func setfpmasks()

//go:noescape
func tstart_plan9(newm *m)

func errstr() string

type _Plink uintptr

func sigpanic() {
	gp := getg()
	if !canpanic() {
		throw("unexpected signal during runtime execution")
	}

	note := gostringnocopy((*byte)(unsafe.Pointer(gp.m.notesig)))
	switch gp.sig {
	case _SIGRFAULT, _SIGWFAULT:
		i := indexNoFloat(note, "addr=")
		if i >= 0 {
			i += 5
		} else if i = indexNoFloat(note, "va="); i >= 0 {
			i += 3
		} else {
			panicmem()
		}
		addr := note[i:]
		gp.sigcode1 = uintptr(atolwhex(addr))
		if gp.sigcode1 < 0x1000 {
			panicmem()
		}
		if gp.paniconfault {
			panicmemAddr(gp.sigcode1)
		}
		if inUserArenaChunk(gp.sigcode1) {
			// We could check that the arena chunk is explicitly set to fault,
			// but the fact that we faulted on accessing it is enough to prove
			// that it is.
			print("accessed data from freed user arena ", hex(gp.sigcode1), "\n")
		} else {
			print("unexpected fault address ", hex(gp.sigcode1), "\n")
		}
		throw("fault")
	case _SIGTRAP:
		if gp.paniconfault {
			panicmem()
		}
		throw(note)
	case _SIGINTDIV:
		panicdivide()
	case _SIGFLOAT:
		panicfloat()
	default:
		panic(errorString(note))
	}
}

// indexNoFloat is bytealg.IndexString but safe to use in a note
// handler.
func indexNoFloat(s, t string) int {
	if len(t) == 0 {
		return 0
	}
	for i := 0; i < len(s); i++ {
		if s[i] == t[0] && stringslite.HasPrefix(s[i:], t) {
			return i
		}
	}
	return -1
}

func atolwhex(p string) int64 {
	for stringslite.HasPrefix(p, " ") || stringslite.HasPrefix(p, "\t") {
		p = p[1:]
	}
	neg := false
	if stringslite.HasPrefix(p, "-") || stringslite.HasPrefix(p, "+") {
		neg = p[0] == '-'
		p = p[1:]
		for stringslite.HasPrefix(p, " ") || stringslite.HasPrefix(p, "\t") {
			p = p[1:]
		}
	}
	var n int64
	switch {
	case stringslite.HasPrefix(p, "0x"), stringslite.HasPrefix(p, "0X"):
		p = p[2:]
		for ; len(p) > 0; p = p[1:] {
			if '0' <= p[0] && p[0] <= '9' {
				n = n*16 + int64(p[0]-'0')
			} else if 'a' <= p[0] && p[0] <= 'f' {
				n = n*16 + int64(p[0]-'a'+10)
			} else if 'A' <= p[0] && p[0] <= 'F' {
				n = n*16 + int64(p[0]-'A'+10)
			} else {
				break
			}
		}
	case stringslite.HasPrefix(p, "0"):
		for ; len(p) > 0 && '0' <= p[0] && p[0] <= '7'; p = p[1:] {
			n = n*8 + int64(p[0]-'0')
		}
	default:
		for ; len(p) > 0 && '0' <= p[0] && p[0] <= '9'; p = p[1:] {
			n = n*10 + int64(p[0]-'0')
		}
	}
	if neg {
		n = -n
	}
	return n
}

type sigset struct{}

// Called to initialize a new m (including the bootstrap m).
// Called on the parent thread (main thread in case of bootstrap), can allocate memory.
func mpreinit(mp *m) {
	// Initialize stack and goroutine for note handling.
	mp.gsignal = malg(32 * 1024)
	mp.gsignal.m = mp
	mp.notesig = (*int8)(mallocgc(_ERRMAX, nil, true))
	// Initialize stack for handling strings from the
	// errstr system call, as used in package syscall.
	mp.errstr = (*byte)(mallocgc(_ERRMAX, nil, true))
}

func sigsave(p *sigset) {
}

func msigrestore(sigmask sigset) {
}

//go:nosplit
//go:nowritebarrierrec
func clearSignalHandlers() {
}

func sigblock(exiting bool) {
}

// Called to initialize a new m (including the bootstrap m).
// Called on the new thread, cannot allocate memory.
func minit() {
	if atomic.Load(&exiting) != 0 {
		exits(&emptystatus[0])
	}
	// Mask all SSE floating-point exceptions
	// when running on the 64-bit kernel.
	setfpmasks()
}

// Called from dropm to undo the effect of an minit.
func unminit() {
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
func mdestroy(mp *m) {
}

var sysstat = []byte("/dev/sysstat\x00")

func getproccount() int32 {
	var buf [2048]byte
	fd := open(&sysstat[0], _OREAD, 0)
	if fd < 0 {
		return 1
	}
	ncpu := int32(0)
	for {
		n := read(fd, unsafe.Pointer(&buf), int32(len(buf)))
		if n <= 0 {
			break
		}
		for i := int32(0); i < n; i++ {
			if buf[i] == '\n' {
				ncpu++
			}
		}
	}
	closefd(fd)
	if ncpu == 0 {
		ncpu = 1
	}
	return ncpu
}

var devswap = []byte("/dev/swap\x00")
var pagesize = []byte(" pagesize\n")

func getPageSize() uintptr {
	var buf [2048]byte
	var pos int
	fd := open(&devswap[0], _OREAD, 0)
	if fd < 0 {
		// There's not much we can do if /dev/swap doesn't
		// exist. However, nothing in the memory manager uses
		// this on Plan 9, so it also doesn't really matter.
		return minPhysPageSize
	}
	for pos < len(buf) {
		n := read(fd, unsafe.Pointer(&buf[pos]), int32(len(buf)-pos))
		if n <= 0 {
			break
		}
		pos += int(n)
	}
	closefd(fd)
	text := buf[:pos]
	// Find "<n> pagesize" line.
	bol := 0
	for i, c := range text {
		if c == '\n' {
			bol = i + 1
		}
		if bytesHasPrefix(text[i:], pagesize) {
			// Parse number at the beginning of this line.
			return uintptr(_atoi(text[bol:]))
		}
	}
	// Again, the page size doesn't really matter, so use a fallback.
	return minPhysPageSize
}

func bytesHasPrefix(s, prefix []byte) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if s[i] != p {
			return false
		}
	}
	return true
}

var pid = []byte("#c/pid\x00")

func getpid() uint64 {
	var b [20]byte
	fd := open(&pid[0], 0, 0)
	if fd >= 0 {
		read(fd, unsafe.Pointer(&b), int32(len(b)))
		closefd(fd)
	}
	c := b[:]
	for c[0] == ' ' || c[0] == '\t' {
		c = c[1:]
	}
	return uint64(_atoi(c))
}

func osinit() {
	physPageSize = getPageSize()
	initBloc()
	ncpu = getproccount()
	getg().m.procid = getpid()
}

//go:nosplit
func crash() {
	notify(nil)
	*(*int)(nil) = 0
}

//go:nosplit
func readRandom(r []byte) int {
	return 0
}

func initsig(preinit bool) {
	if !preinit {
		notify(unsafe.Pointer(abi.FuncPCABI0(sigtramp)))
	}
}

//go:nosplit
func osyield() {
	sleep(0)
}

//go:nosplit
func osyield_no_g() {
	osyield()
}

//go:nosplit
func usleep(µs uint32) {
	ms := int32(µs / 1000)
	if ms == 0 {
		ms = 1
	}
	sleep(ms)
}

//go:nosplit
func usleep_no_g(usec uint32) {
	usleep(usec)
}

//go:nosplit
func nanotime1() int64 {
	var scratch int64
	ns := nsec(&scratch)
	// TODO(aram): remove hack after I fix _nsec in the pc64 kernel.
	if ns == 0 {
		return scratch
	}
	return ns
}

var goexits = []byte("go: exit ")
var emptystatus = []byte("\x00")
var exiting uint32

func goexitsall(status *byte) {
	var buf [_ERRMAX]byte
	if !atomic.Cas(&exiting, 0, 1) {
		return
	}
	getg().m.locks++
	n := copy(buf[:], goexits)
	n = copy(buf[n:], gostringnocopy(status))
	pid := getpid()
	for mp := (*m)(atomic.Loadp(unsafe.Pointer(&allm))); mp != nil; mp = mp.alllink {
		if mp.procid != 0 && mp.procid != pid {
			postnote(mp.procid, buf[:])
		}
	}
	getg().m.locks--
}

var procdir = []byte("/proc/")
var notefile = []byte("/note\x00")

func postnote(pid uint64, msg []byte) int {
	var buf [128]byte
	var tmp [32]byte
	n := copy(buf[:], procdir)
	n += copy(buf[n:], itoa(tmp[:], pid))
	copy(buf[n:], notefile)
	fd := open(&buf[0], _OWRITE, 0)
	if fd < 0 {
		return -1
	}
	len := findnull(&msg[0])
	if write1(uintptr(fd), unsafe.Pointer(&msg[0]), int32(len)) != int32(len) {
		closefd(fd)
		return -1
	}
	closefd(fd)
	return 0
}

//go:nosplit
func exit(e int32) {
	var status []byte
	if e == 0 {
		status = emptystatus
	} else {
		// build error string
		var tmp [32]byte
		sl := itoa(tmp[:len(tmp)-1], uint64(e))
		// Don't append, rely on the existing data being zero.
		status = sl[:len(sl)+1]
	}
	goexitsall(&status[0])
	exits(&status[0])
}

// May run with m.p==nil, so write barriers are not allowed.
//
//go:nowritebarrier
func newosproc(mp *m) {
	if false {
		print("newosproc mp=", mp, " ostk=", &mp, "\n")
	}
	pid := rfork(_RFPROC | _RFMEM | _RFNOWAIT)
	if pid < 0 {
		throw("newosproc: rfork failed")
	}
	if pid == 0 {
		tstart_plan9(mp)
	}
}

func exitThread(wait *atomic.Uint32) {
	// We should never reach exitThread on Plan 9 because we let
	// the OS clean up threads.
	throw("exitThread")
}

//go:nosplit
func semacreate(mp *m) {
}

//go:nosplit
func semasleep(ns int64) int {
	gp := getg()
	if ns >= 0 {
		ms := timediv(ns, 1000000, nil)
		if ms == 0 {
			ms = 1
		}
		ret := plan9_tsemacquire(&gp.m.waitsemacount, ms)
		if ret == 1 {
			return 0 // success
		}
		return -1 // timeout or interrupted
	}
	for plan9_semacquire(&gp.m.waitsemacount, 1) < 0 {
		// interrupted; try again (c.f. lock_sema.go)
	}
	return 0 // success
}

//go:nosplit
func semawakeup(mp *m) {
	plan9_semrelease(&mp.waitsemacount, 1)
}

//go:nosplit
func read(fd int32, buf unsafe.Pointer, n int32) int32 {
	return pread(fd, buf, n, -1)
}

//go:nosplit
func write1(fd uintptr, buf unsafe.Pointer, n int32) int32 {
	return pwrite(int32(fd), buf, n, -1)
}

var _badsignal = []byte("runtime: signal received on thread not created by Go.\n")

// This runs on a foreign stack, without an m or a g. No stack split.
//
//go:nosplit
func badsignal2() {
	pwrite(2, unsafe.Pointer(&_badsignal[0]), int32(len(_badsignal)), -1)
	exits(&_badsignal[0])
}

func raisebadsignal(sig uint32) {
	badsignal2()
}

func _atoi(b []byte) int {
	n := 0
	for len(b) > 0 && '0' <= b[0] && b[0] <= '9' {
		n = n*10 + int(b[0]) - '0'
		b = b[1:]
	}
	return n
}

func signame(sig uint32) string {
	if sig >= uint32(len(sigtable)) {
		return ""
	}
	return sigtable[sig].name
}

const preemptMSupported = false

func preemptM(mp *m) {
	// Not currently supported.
	//
	// TODO: Use a note like we use signals on POSIX OSes
}

"""



```