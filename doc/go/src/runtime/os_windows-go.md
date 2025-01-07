Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Keyword Recognition:**

* **File Path:** `go/src/runtime/os_windows.go` immediately tells us this is part of the Go runtime, specifically for Windows. This means it's likely low-level and deals with operating system interactions.
* **Copyright Notice:** Standard Go copyright. Not functionally relevant.
* **`package runtime`:** Confirms this is core Go runtime code.
* **`import (...)`:** Lists imported packages. `internal/abi`, `internal/goarch`, `internal/runtime/atomic`, `internal/runtime/sys`, `unsafe` all suggest low-level operations and direct memory manipulation.
* **`// TODO(brainman): should not need those`:** A comment indicating potential future cleanup or refactoring. The `const _NSIG = 65` likely relates to signal handling, but is marked as potentially unnecessary on Windows.
* **`//go:cgo_import_dynamic ...`:**  This is a crucial line. `cgo_import_dynamic` strongly indicates that this code interacts with dynamically linked libraries (DLLs) on Windows. Each line represents a Windows API function being imported.
* **`type stdFunction unsafe.Pointer`:** Defines a type representing a function pointer, confirming the DLL interaction.
* **`var (...) _ stdFunction`:**  Declares variables that will hold the addresses of the imported Windows API functions. The comment "Following syscalls are available on every Windows PC" is important.
* **`// Use ProcessPrng to generate cryptographically random data.`:** Explicitly states the purpose of the `_ProcessPrng` function.
* **Comments about `ntdll.dll` and other DLLs:** Highlights specific DLLs being loaded and the reasons why. This points to lower-level functionality.
* **`func tstart_stdcall(newm *m)`:**  A function intended to be the entry point for new OS threads created by Go. The `stdcall` suffix indicates the Windows standard calling convention.
* **`func wintls()`:** Likely related to thread-local storage initialization.
* **`type mOS struct { ... }`:**  A struct that holds Windows-specific data for an `m` (Go machine/OS thread). The fields reveal details about thread handles, semaphores (for synchronization), and potentially timers. The comments about `preemptExtLock` explain a complex synchronization mechanism.
* **Stubs like `open`, `closefd`, `read`:** These are placeholder functions marked as `throw("unimplemented")`. This suggests that these standard Unix-like functions are not directly implemented in this specific file but might be handled elsewhere in the Go runtime or via syscall emulation.
* **`// Call a Windows function with stdcall conventions, ...` and `func asmstdcall(fn unsafe.Pointer)`:**  Confirms the use of the `stdcall` calling convention for interacting with Windows APIs.
* **`type winlibcall libcall`:**  Likely a structure used to pass arguments to the `asmstdcall` function.
* **Functions like `windowsFindfunc`, `initSysDirectory`, `windows_GetSystemDirectory`, `windowsLoadSystemLib`, `windows_QueryPerformanceCounter`, `windows_QueryPerformanceFrequency`:**  These are helper functions for interacting with Windows APIs, like finding function addresses within DLLs, getting system directories, and querying performance counters.
* **`func loadOptionalSyscalls()`:**  Indicates that some system calls are loaded conditionally.
* **`func monitorSuspendResume()`:**  Deals with handling system suspend/resume events, potentially to wake up parked Go threads.
* **`func getproccount()` and `getPageSize()`:**  Functions to get CPU core count and memory page size, respectively.
* **Constants `currentProcess` and `currentThread`:**  Represent special values used with Windows API functions.
* **`func osRelax(relax bool)` and `func initHighResTimer()`:**  Handle timer resolution adjustments and initialization, dealing with power saving and high-precision timing.
* **`func initLongPathSupport()`:**  Enables support for long file paths on Windows.
* **`func osinit()`:**  The primary initialization function for the OS-specific runtime. It calls various other initialization functions.
* **`func readRandom(r []byte) int`:**  Provides a way to generate cryptographically secure random numbers using a Windows API.
* **`func goenvs()`:**  Retrieves and processes environment variables.
* **`func exit(code int32)`:**  Exits the process using the Windows API.
* **`func write1(fd uintptr, buf unsafe.Pointer, n int32) int32` and `func writeConsole(...)`:** Implement writing to file descriptors (especially standard output/error), handling Unicode correctly for consoles.
* **`func semasleep(ns int64)` and `func semawakeup(mp *m)` and `func semacreate(mp *m)`:** Implement semaphore-based sleep and wake-up functionality for synchronization.
* **`func newosproc(mp *m)` and `func newosproc0(mp *m, stk unsafe.Pointer)`:**  Functions for creating new OS threads for Go goroutines.
* **`func exitThread(wait *atomic.Uint32)`:** Marked as `throw("exitThread")` on Windows, suggesting a different thread termination mechanism.
* **`func mpreinit(mp *m)` and `func minit()` and `func unminit()` and `func mdestroy(mp *m)`:** Functions related to the initialization and cleanup of `m` structures, representing OS threads managed by the Go runtime.
* **Signal handling stubs (`sigsave`, `msigrestore`, `clearSignalHandlers`, `sigblock`):**  Suggest that signal handling is present but might be implemented differently on Windows.
* **Functions related to `stdcall` (`asmstdcall_trampoline`, `stdcall_no_g`, `stdcall`, `stdcall0`, `stdcall1`, ..., `stdcall7`):**  Provide a mechanism to call Windows API functions with the `stdcall` calling convention, handling argument passing and potential profiling.

**2. Grouping and Categorization:**

Based on the identified keywords and functionality, we can group the code's responsibilities:

* **Windows API Interfacing (Core Functionality):**  The dominant feature. Importing and calling numerous Windows API functions.
* **Thread Management:** Creating and managing OS threads for Go goroutines.
* **Synchronization Primitives:** Implementing semaphores for thread synchronization.
* **Time and Scheduling:**  Handling timer resolution, high-resolution timers, and potentially interacting with the scheduler.
* **Error Handling:** Implicitly through checking return values of Windows API calls and potentially through the `initExceptionHandler()` call (not shown in the snippet).
* **Memory Management:**  Indirectly through functions like `VirtualAlloc` and `VirtualFree`.
* **Environment Variables:**  Retrieving environment variables.
* **Standard Input/Output:**  Writing to console and files, handling Unicode output.
* **Random Number Generation:**  Using a Windows API for cryptographically secure random numbers.
* **Process and System Information:**  Getting CPU count, page size, system directory.
* **Long Path Support:** Enabling support for longer file paths.
* **Suspend/Resume Handling:**  Responding to system suspend and resume events.
* **Initialization and Cleanup:** Functions for setting up and tearing down OS-specific resources.
* **Internal Utilities:** Helper functions for common tasks.

**3. High-Level Summary (Drafting the Answer):**

Now, we can start formulating the answer, grouping related functionalities and using clearer language. The initial draft might look like:

> This code in `go/src/runtime/os_windows.go` is a crucial part of the Go runtime for Windows. It's responsible for making Go programs work correctly on the Windows operating system by interacting directly with the Windows kernel and system libraries. It does things like: calling Windows APIs, managing threads, synchronization, time, handling input/output, and getting system information.

**4. Refining and Adding Detail:**

The next step is to elaborate on the initial summary, adding more specific details based on the code analysis. This involves mentioning the `cgo_import_dynamic` directive, the types of Windows APIs being used, and the purpose of specific functions.

**5. Adding Examples and Considerations (For Later Parts):**

While the prompt only asks for a summary in this part, the anticipation of future parts (code examples, error points, etc.) guides the analysis to identify areas where examples or explanations might be needed. For instance, the `stdcall` mechanism is a good candidate for a code example. Potential error points might arise from incorrect usage of the imported Windows APIs.

**6. Finalizing the Summary:**

The final summary should be concise yet informative, capturing the key responsibilities of the code. This leads to the kind of answer provided in the initial prompt's example.
这是 `go/src/runtime/os_windows.go` 文件的前半部分代码，主要负责 **Go 运行时在 Windows 操作系统上的底层支持**。

**功能归纳:**

1. **导入必要的 Windows API 函数 (System Calls):** 通过 `//go:cgo_import_dynamic` 指令，动态链接并导入大量的 Windows 系统 DLL (通常是 `kernel32.dll`) 中的 API 函数。这些函数涵盖了进程、线程、内存、同步、IO、时间等多个方面的操作系统功能。

2. **定义 Windows 平台相关的类型和常量:**  例如 `stdFunction` (Windows API 函数指针类型)、`mOS` (Go 运行时 M 结构体在 Windows 上的扩展，包含线程句柄、同步对象等)。

3. **提供调用 Windows API 的基础设施:** 实现了 `asmstdcall` 等函数，用于以 Windows 标准调用约定 (stdcall) 调用导入的 API 函数。这涉及到切换到操作系统栈执行。

4. **实现一些基础的操作系统功能:**  例如获取处理器数量 (`getproccount`)、页面大小 (`getPageSize`)、系统目录 (`initSysDirectory`, `windows_GetSystemDirectory`) 等。

5. **处理高精度时间:**  尝试使用 `CreateWaitableTimerExW` 创建高精度定时器，如果失败则回退到 `timeBeginPeriod` 和 `timeEndPeriod`。

6. **支持长路径:**  检测并启用 Windows 的长路径支持。

7. **初始化操作系统相关的运行时状态:**  `osinit` 函数负责初始化一些全局变量和调用其他初始化函数，例如加载可选的系统调用、禁用错误对话框、初始化异常处理、设置高精度定时器等。

8. **提供安全的随机数生成:**  使用 Windows 的 `ProcessPrng` API 生成加密安全的随机数。

9. **获取和处理环境变量:**  `goenvs` 函数用于获取 Windows 的环境变量。

10. **实现进程退出:** `exit` 函数使用 Windows 的 `ExitProcess` API 安全地退出进程。

11. **提供基本的输出功能:** `write1` 和 `writeConsole` 函数用于向文件描述符 (特别是标准输出和标准错误) 写入数据，并处理 Unicode 输出到控制台的情况。

12. **实现基于 Windows 事件的睡眠和唤醒机制:** `semasleep`，`semawakeup` 和 `semacreate` 函数使用 Windows 事件对象作为 Go 语言层面同步原语 (例如互斥锁) 的底层实现。

13. **创建新的操作系统线程:** `newosproc` 函数使用 Windows 的 `CreateThread` API 创建新的线程来运行 Go 的 goroutine。

14. **管理 M 结构体的生命周期:**  `mpreinit`, `minit`, `unminit`, `mdestroy` 等函数负责初始化、清理与操作系统线程关联的 Go 运行时 `m` 结构体。

**可以推理出的 Go 语言功能实现 (及代码示例):**

从这段代码可以推断出它涉及到 **Go 语言的并发模型 (goroutine) 在 Windows 上的实现** 和 **Go 语言的同步原语 (例如互斥锁)**。

**1. Goroutine 的 OS 线程实现:**

* `newosproc` 函数使用 `CreateThread` 创建新的 OS 线程，这表明 Go 的 goroutine 是通过操作系统的线程来实现的。
* `tstart_stdcall` 函数很可能就是新创建的 OS 线程的入口点，负责执行 goroutine 的代码。

**示例:**

```go
package main

import "runtime"

func main() {
	runtime.GOMAXPROCS(1) // 为了简化，限制只使用一个 OS 线程

	go func() {
		println("Hello from goroutine!")
	}()

	println("Hello from main goroutine!")
	// 为了保证 goroutine 有机会执行，可以等待一下
	var input string
	println("Press Enter to exit")
	_, _ = fmt.Scanln(&input)
}
```

**假设的输入与输出:** (运行上述代码)

```
Hello from main goroutine!
Hello from goroutine!
Press Enter to exit
```

**代码推理:** 当 `go func() { ... }()` 被调用时，Go 运行时会调用 `newosproc` 在 Windows 上创建一个新的 OS 线程。这个新线程的入口点是 `tstart_stdcall`，它会设置好 goroutine 的运行环境并执行 `println("Hello from goroutine!")`。

**2. 基于 Windows 事件的互斥锁实现:**

* `semacreate` 创建 Windows 事件对象 (`CreateEventA`).
* `semasleep` 使用 `WaitForSingleObject` 或 `WaitForMultipleObjects` 等待事件被触发。
* `semawakeup` 使用 `SetEvent` 触发事件。

这表明 Go 的互斥锁等同步原语很可能在 Windows 上是基于事件对象实现的。

**示例 (简化的互斥锁使用):**

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
)

var counter int
var mu sync.Mutex

func increment() {
	mu.Lock()
	defer mu.Unlock()
	counter++
}

func main() {
	runtime.GOMAXPROCS(1) // 简化

	for i := 0; i < 1000; i++ {
		go increment()
	}

	// 等待所有 goroutine 执行完成
	var input string
	fmt.Println("Press Enter to see the counter")
	fmt.Scanln(&input)

	fmt.Println("Counter:", counter)
}
```

**假设的输入与输出:** (运行上述代码，并按下 Enter)

```
Press Enter to see the counter
Counter: 1000
```

**代码推理:** `sync.Mutex` 在 Windows 上的底层实现会调用到 `semacreate`, `semasleep`, `semawakeup` 等函数。当多个 goroutine 同时尝试获取锁 (`mu.Lock()`) 时，只有一个 goroutine 能成功获取，其他 goroutine 会在 `semasleep` 中等待，直到持有锁的 goroutine 调用 `mu.Unlock()`，触发事件，唤醒等待的 goroutine。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常发生在 `os` 包或者 `syscall` 包中，更靠近用户程序入口的地方。`os_windows.go` 更多的是提供底层的操作系统接口支持。

**使用者易犯错的点:**

虽然这段代码是 Go 运行时的内部实现，普通 Go 开发者不会直接接触，但理解其背后的原理可以帮助避免一些潜在的错误，例如：

* **过度依赖 POSIX 信号处理:** Windows 的信号机制与 POSIX 系统 (如 Linux) 有很大不同。直接使用 `syscall` 包中的信号相关函数可能不会在 Windows 上按预期工作。Go 运行时自身已经处理了一些信号，但对于更复杂的信号处理需求，需要考虑 Windows 特定的 API。

**总结 (针对第 1 部分):**

这段 `go/src/runtime/os_windows.go` 代码是 Go 运行时在 Windows 平台上的核心组成部分，它主要负责：

* **作为 Go 运行时与 Windows 操作系统内核之间的桥梁，通过动态链接导入并调用大量的 Windows API 函数。**
* **定义了 Windows 平台特有的数据结构和常量，用于管理线程、同步等操作系统资源。**
* **提供调用 Windows API 的基础机制，并实现了一些关键的操作系统功能，例如线程创建、同步原语、时间管理和随机数生成等。**

总而言之，它是 Go 语言能够在 Windows 上运行的基础，为 Go 程序提供了与底层操作系统交互的能力。

Prompt: 
```
这是路径为go/src/runtime/os_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

// TODO(brainman): should not need those
const (
	_NSIG = 65
)

//go:cgo_import_dynamic runtime._AddVectoredContinueHandler AddVectoredContinueHandler%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._AddVectoredExceptionHandler AddVectoredExceptionHandler%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._CloseHandle CloseHandle%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._CreateEventA CreateEventA%4 "kernel32.dll"
//go:cgo_import_dynamic runtime._CreateIoCompletionPort CreateIoCompletionPort%4 "kernel32.dll"
//go:cgo_import_dynamic runtime._CreateThread CreateThread%6 "kernel32.dll"
//go:cgo_import_dynamic runtime._CreateWaitableTimerA CreateWaitableTimerA%3 "kernel32.dll"
//go:cgo_import_dynamic runtime._CreateWaitableTimerExW CreateWaitableTimerExW%4 "kernel32.dll"
//go:cgo_import_dynamic runtime._DuplicateHandle DuplicateHandle%7 "kernel32.dll"
//go:cgo_import_dynamic runtime._ExitProcess ExitProcess%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._FreeEnvironmentStringsW FreeEnvironmentStringsW%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetConsoleMode GetConsoleMode%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetCurrentThreadId GetCurrentThreadId%0 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetEnvironmentStringsW GetEnvironmentStringsW%0 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetErrorMode GetErrorMode%0 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetProcAddress GetProcAddress%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetProcessAffinityMask GetProcessAffinityMask%3 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetQueuedCompletionStatusEx GetQueuedCompletionStatusEx%6 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetStdHandle GetStdHandle%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetSystemDirectoryA GetSystemDirectoryA%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetSystemInfo GetSystemInfo%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._GetThreadContext GetThreadContext%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._SetThreadContext SetThreadContext%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._LoadLibraryExW LoadLibraryExW%3 "kernel32.dll"
//go:cgo_import_dynamic runtime._LoadLibraryW LoadLibraryW%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._PostQueuedCompletionStatus PostQueuedCompletionStatus%4 "kernel32.dll"
//go:cgo_import_dynamic runtime._QueryPerformanceCounter QueryPerformanceCounter%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._QueryPerformanceFrequency QueryPerformanceFrequency%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._RaiseFailFastException RaiseFailFastException%3 "kernel32.dll"
//go:cgo_import_dynamic runtime._ResumeThread ResumeThread%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._RtlLookupFunctionEntry RtlLookupFunctionEntry%3 "kernel32.dll"
//go:cgo_import_dynamic runtime._RtlVirtualUnwind  RtlVirtualUnwind%8 "kernel32.dll"
//go:cgo_import_dynamic runtime._SetConsoleCtrlHandler SetConsoleCtrlHandler%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._SetErrorMode SetErrorMode%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._SetEvent SetEvent%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._SetProcessPriorityBoost SetProcessPriorityBoost%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._SetThreadPriority SetThreadPriority%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._SetUnhandledExceptionFilter SetUnhandledExceptionFilter%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._SetWaitableTimer SetWaitableTimer%6 "kernel32.dll"
//go:cgo_import_dynamic runtime._SuspendThread SuspendThread%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._SwitchToThread SwitchToThread%0 "kernel32.dll"
//go:cgo_import_dynamic runtime._TlsAlloc TlsAlloc%0 "kernel32.dll"
//go:cgo_import_dynamic runtime._VirtualAlloc VirtualAlloc%4 "kernel32.dll"
//go:cgo_import_dynamic runtime._VirtualFree VirtualFree%3 "kernel32.dll"
//go:cgo_import_dynamic runtime._VirtualQuery VirtualQuery%3 "kernel32.dll"
//go:cgo_import_dynamic runtime._WaitForSingleObject WaitForSingleObject%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._WaitForMultipleObjects WaitForMultipleObjects%4 "kernel32.dll"
//go:cgo_import_dynamic runtime._WerGetFlags WerGetFlags%2 "kernel32.dll"
//go:cgo_import_dynamic runtime._WerSetFlags WerSetFlags%1 "kernel32.dll"
//go:cgo_import_dynamic runtime._WriteConsoleW WriteConsoleW%5 "kernel32.dll"
//go:cgo_import_dynamic runtime._WriteFile WriteFile%5 "kernel32.dll"

type stdFunction unsafe.Pointer

var (
	// Following syscalls are available on every Windows PC.
	// All these variables are set by the Windows executable
	// loader before the Go program starts.
	_AddVectoredContinueHandler,
	_AddVectoredExceptionHandler,
	_CloseHandle,
	_CreateEventA,
	_CreateIoCompletionPort,
	_CreateThread,
	_CreateWaitableTimerA,
	_CreateWaitableTimerExW,
	_DuplicateHandle,
	_ExitProcess,
	_FreeEnvironmentStringsW,
	_GetConsoleMode,
	_GetCurrentThreadId,
	_GetEnvironmentStringsW,
	_GetErrorMode,
	_GetProcAddress,
	_GetProcessAffinityMask,
	_GetQueuedCompletionStatusEx,
	_GetStdHandle,
	_GetSystemDirectoryA,
	_GetSystemInfo,
	_GetThreadContext,
	_SetThreadContext,
	_LoadLibraryExW,
	_LoadLibraryW,
	_PostQueuedCompletionStatus,
	_QueryPerformanceCounter,
	_QueryPerformanceFrequency,
	_RaiseFailFastException,
	_ResumeThread,
	_RtlLookupFunctionEntry,
	_RtlVirtualUnwind,
	_SetConsoleCtrlHandler,
	_SetErrorMode,
	_SetEvent,
	_SetProcessPriorityBoost,
	_SetThreadPriority,
	_SetUnhandledExceptionFilter,
	_SetWaitableTimer,
	_SuspendThread,
	_SwitchToThread,
	_TlsAlloc,
	_VirtualAlloc,
	_VirtualFree,
	_VirtualQuery,
	_WaitForSingleObject,
	_WaitForMultipleObjects,
	_WerGetFlags,
	_WerSetFlags,
	_WriteConsoleW,
	_WriteFile,
	_ stdFunction

	// Use ProcessPrng to generate cryptographically random data.
	_ProcessPrng stdFunction

	// Load ntdll.dll manually during startup, otherwise Mingw
	// links wrong printf function to cgo executable (see issue
	// 12030 for details).
	_NtCreateWaitCompletionPacket    stdFunction
	_NtAssociateWaitCompletionPacket stdFunction
	_NtCancelWaitCompletionPacket    stdFunction
	_RtlGetCurrentPeb                stdFunction
	_RtlGetVersion                   stdFunction

	// These are from non-kernel32.dll, so we prefer to LoadLibraryEx them.
	_timeBeginPeriod,
	_timeEndPeriod,
	_ stdFunction
)

var (
	bcryptprimitivesdll = [...]uint16{'b', 'c', 'r', 'y', 'p', 't', 'p', 'r', 'i', 'm', 'i', 't', 'i', 'v', 'e', 's', '.', 'd', 'l', 'l', 0}
	ntdlldll            = [...]uint16{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0}
	powrprofdll         = [...]uint16{'p', 'o', 'w', 'r', 'p', 'r', 'o', 'f', '.', 'd', 'l', 'l', 0}
	winmmdll            = [...]uint16{'w', 'i', 'n', 'm', 'm', '.', 'd', 'l', 'l', 0}
)

// Function to be called by windows CreateThread
// to start new os thread.
func tstart_stdcall(newm *m)

// Init-time helper
func wintls()

type mOS struct {
	threadLock mutex   // protects "thread" and prevents closing
	thread     uintptr // thread handle

	waitsema   uintptr // semaphore for parking on locks
	resumesema uintptr // semaphore to indicate suspend/resume

	highResTimer   uintptr // high resolution timer handle used in usleep
	waitIocpTimer  uintptr // high resolution timer handle used in netpoll
	waitIocpHandle uintptr // wait completion handle used in netpoll

	// preemptExtLock synchronizes preemptM with entry/exit from
	// external C code.
	//
	// This protects against races between preemptM calling
	// SuspendThread and external code on this thread calling
	// ExitProcess. If these happen concurrently, it's possible to
	// exit the suspending thread and suspend the exiting thread,
	// leading to deadlock.
	//
	// 0 indicates this M is not being preempted or in external
	// code. Entering external code CASes this from 0 to 1. If
	// this fails, a preemption is in progress, so the thread must
	// wait for the preemption. preemptM also CASes this from 0 to
	// 1. If this fails, the preemption fails (as it would if the
	// PC weren't in Go code). The value is reset to 0 when
	// returning from external code or after a preemption is
	// complete.
	//
	// TODO(austin): We may not need this if preemption were more
	// tightly synchronized on the G/P status and preemption
	// blocked transition into _Gsyscall/_Psyscall.
	preemptExtLock uint32
}

// Stubs so tests can link correctly. These should never be called.
func open(name *byte, mode, perm int32) int32 {
	throw("unimplemented")
	return -1
}
func closefd(fd int32) int32 {
	throw("unimplemented")
	return -1
}
func read(fd int32, p unsafe.Pointer, n int32) int32 {
	throw("unimplemented")
	return -1
}

type sigset struct{}

// Call a Windows function with stdcall conventions,
// and switch to os stack during the call.
func asmstdcall(fn unsafe.Pointer)

var asmstdcallAddr unsafe.Pointer

type winlibcall libcall

func windowsFindfunc(lib uintptr, name []byte) stdFunction {
	if name[len(name)-1] != 0 {
		throw("usage")
	}
	f := stdcall2(_GetProcAddress, lib, uintptr(unsafe.Pointer(&name[0])))
	return stdFunction(unsafe.Pointer(f))
}

const _MAX_PATH = 260 // https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
var sysDirectory [_MAX_PATH + 1]byte
var sysDirectoryLen uintptr

func initSysDirectory() {
	l := stdcall2(_GetSystemDirectoryA, uintptr(unsafe.Pointer(&sysDirectory[0])), uintptr(len(sysDirectory)-1))
	if l == 0 || l > uintptr(len(sysDirectory)-1) {
		throw("Unable to determine system directory")
	}
	sysDirectory[l] = '\\'
	sysDirectoryLen = l + 1
}

//go:linkname windows_GetSystemDirectory internal/syscall/windows.GetSystemDirectory
func windows_GetSystemDirectory() string {
	return unsafe.String(&sysDirectory[0], sysDirectoryLen)
}

func windowsLoadSystemLib(name []uint16) uintptr {
	return stdcall3(_LoadLibraryExW, uintptr(unsafe.Pointer(&name[0])), 0, _LOAD_LIBRARY_SEARCH_SYSTEM32)
}

//go:linkname windows_QueryPerformanceCounter internal/syscall/windows.QueryPerformanceCounter
func windows_QueryPerformanceCounter() int64 {
	var counter int64
	stdcall1(_QueryPerformanceCounter, uintptr(unsafe.Pointer(&counter)))
	return counter
}

//go:linkname windows_QueryPerformanceFrequency internal/syscall/windows.QueryPerformanceFrequency
func windows_QueryPerformanceFrequency() int64 {
	var frequency int64
	stdcall1(_QueryPerformanceFrequency, uintptr(unsafe.Pointer(&frequency)))
	return frequency
}

func loadOptionalSyscalls() {
	bcryptPrimitives := windowsLoadSystemLib(bcryptprimitivesdll[:])
	if bcryptPrimitives == 0 {
		throw("bcryptprimitives.dll not found")
	}
	_ProcessPrng = windowsFindfunc(bcryptPrimitives, []byte("ProcessPrng\000"))

	n32 := windowsLoadSystemLib(ntdlldll[:])
	if n32 == 0 {
		throw("ntdll.dll not found")
	}
	_NtCreateWaitCompletionPacket = windowsFindfunc(n32, []byte("NtCreateWaitCompletionPacket\000"))
	if _NtCreateWaitCompletionPacket != nil {
		// These functions should exists if NtCreateWaitCompletionPacket exists.
		_NtAssociateWaitCompletionPacket = windowsFindfunc(n32, []byte("NtAssociateWaitCompletionPacket\000"))
		if _NtAssociateWaitCompletionPacket == nil {
			throw("NtCreateWaitCompletionPacket exists but NtAssociateWaitCompletionPacket does not")
		}
		_NtCancelWaitCompletionPacket = windowsFindfunc(n32, []byte("NtCancelWaitCompletionPacket\000"))
		if _NtCancelWaitCompletionPacket == nil {
			throw("NtCreateWaitCompletionPacket exists but NtCancelWaitCompletionPacket does not")
		}
	}
	_RtlGetCurrentPeb = windowsFindfunc(n32, []byte("RtlGetCurrentPeb\000"))
	_RtlGetVersion = windowsFindfunc(n32, []byte("RtlGetVersion\000"))
}

func monitorSuspendResume() {
	const (
		_DEVICE_NOTIFY_CALLBACK = 2
	)
	type _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS struct {
		callback uintptr
		context  uintptr
	}

	powrprof := windowsLoadSystemLib(powrprofdll[:])
	if powrprof == 0 {
		return // Running on Windows 7, where we don't need it anyway.
	}
	powerRegisterSuspendResumeNotification := windowsFindfunc(powrprof, []byte("PowerRegisterSuspendResumeNotification\000"))
	if powerRegisterSuspendResumeNotification == nil {
		return // Running on Windows 7, where we don't need it anyway.
	}
	var fn any = func(context uintptr, changeType uint32, setting uintptr) uintptr {
		for mp := (*m)(atomic.Loadp(unsafe.Pointer(&allm))); mp != nil; mp = mp.alllink {
			if mp.resumesema != 0 {
				stdcall1(_SetEvent, mp.resumesema)
			}
		}
		return 0
	}
	params := _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS{
		callback: compileCallback(*efaceOf(&fn), true),
	}
	handle := uintptr(0)
	stdcall3(powerRegisterSuspendResumeNotification, _DEVICE_NOTIFY_CALLBACK,
		uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&handle)))
}

func getproccount() int32 {
	var mask, sysmask uintptr
	ret := stdcall3(_GetProcessAffinityMask, currentProcess, uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Pointer(&sysmask)))
	if ret != 0 {
		n := 0
		maskbits := int(unsafe.Sizeof(mask) * 8)
		for i := 0; i < maskbits; i++ {
			if mask&(1<<uint(i)) != 0 {
				n++
			}
		}
		if n != 0 {
			return int32(n)
		}
	}
	// use GetSystemInfo if GetProcessAffinityMask fails
	var info systeminfo
	stdcall1(_GetSystemInfo, uintptr(unsafe.Pointer(&info)))
	return int32(info.dwnumberofprocessors)
}

func getPageSize() uintptr {
	var info systeminfo
	stdcall1(_GetSystemInfo, uintptr(unsafe.Pointer(&info)))
	return uintptr(info.dwpagesize)
}

const (
	currentProcess = ^uintptr(0) // -1 = current process
	currentThread  = ^uintptr(1) // -2 = current thread
)

// in sys_windows_386.s and sys_windows_amd64.s:
func getlasterror() uint32

var timeBeginPeriodRetValue uint32

// osRelaxMinNS indicates that sysmon shouldn't osRelax if the next
// timer is less than 60 ms from now. Since osRelaxing may reduce
// timer resolution to 15.6 ms, this keeps timer error under roughly 1
// part in 4.
const osRelaxMinNS = 60 * 1e6

// osRelax is called by the scheduler when transitioning to and from
// all Ps being idle.
//
// Some versions of Windows have high resolution timer. For those
// versions osRelax is noop.
// For Windows versions without high resolution timer, osRelax
// adjusts the system-wide timer resolution. Go needs a
// high resolution timer while running and there's little extra cost
// if we're already using the CPU, but if all Ps are idle there's no
// need to consume extra power to drive the high-res timer.
func osRelax(relax bool) uint32 {
	if haveHighResTimer {
		// If the high resolution timer is available, the runtime uses the timer
		// to sleep for short durations. This means there's no need to adjust
		// the global clock frequency.
		return 0
	}

	if relax {
		return uint32(stdcall1(_timeEndPeriod, 1))
	} else {
		return uint32(stdcall1(_timeBeginPeriod, 1))
	}
}

// haveHighResTimer indicates that the CreateWaitableTimerEx
// CREATE_WAITABLE_TIMER_HIGH_RESOLUTION flag is available.
var haveHighResTimer = false

// haveHighResSleep indicates that NtCreateWaitCompletionPacket
// exists and haveHighResTimer is true.
// NtCreateWaitCompletionPacket has been available since Windows 10,
// but has just been publicly documented, so some platforms, like Wine,
// doesn't support it yet.
var haveHighResSleep = false

// createHighResTimer calls CreateWaitableTimerEx with
// CREATE_WAITABLE_TIMER_HIGH_RESOLUTION flag to create high
// resolution timer. createHighResTimer returns new timer
// handle or 0, if CreateWaitableTimerEx failed.
func createHighResTimer() uintptr {
	const (
		// As per @jstarks, see
		// https://github.com/golang/go/issues/8687#issuecomment-656259353
		_CREATE_WAITABLE_TIMER_HIGH_RESOLUTION = 0x00000002

		_SYNCHRONIZE        = 0x00100000
		_TIMER_QUERY_STATE  = 0x0001
		_TIMER_MODIFY_STATE = 0x0002
	)
	return stdcall4(_CreateWaitableTimerExW, 0, 0,
		_CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
		_SYNCHRONIZE|_TIMER_QUERY_STATE|_TIMER_MODIFY_STATE)
}

func initHighResTimer() {
	h := createHighResTimer()
	if h != 0 {
		haveHighResTimer = true
		haveHighResSleep = _NtCreateWaitCompletionPacket != nil
		stdcall1(_CloseHandle, h)
	} else {
		// Only load winmm.dll if we need it.
		// This avoids a dependency on winmm.dll for Go programs
		// that run on new Windows versions.
		m32 := windowsLoadSystemLib(winmmdll[:])
		if m32 == 0 {
			print("runtime: LoadLibraryExW failed; errno=", getlasterror(), "\n")
			throw("winmm.dll not found")
		}
		_timeBeginPeriod = windowsFindfunc(m32, []byte("timeBeginPeriod\000"))
		_timeEndPeriod = windowsFindfunc(m32, []byte("timeEndPeriod\000"))
		if _timeBeginPeriod == nil || _timeEndPeriod == nil {
			print("runtime: GetProcAddress failed; errno=", getlasterror(), "\n")
			throw("timeBegin/EndPeriod not found")
		}
	}
}

//go:linkname canUseLongPaths internal/syscall/windows.CanUseLongPaths
var canUseLongPaths bool

// initLongPathSupport enables long path support.
func initLongPathSupport() {
	const (
		IsLongPathAwareProcess = 0x80
		PebBitFieldOffset      = 3
	)

	// Check that we're ≥ 10.0.15063.
	info := _OSVERSIONINFOW{}
	info.osVersionInfoSize = uint32(unsafe.Sizeof(info))
	stdcall1(_RtlGetVersion, uintptr(unsafe.Pointer(&info)))
	if info.majorVersion < 10 || (info.majorVersion == 10 && info.minorVersion == 0 && info.buildNumber < 15063) {
		return
	}

	// Set the IsLongPathAwareProcess flag of the PEB's bit field.
	// This flag is not documented, but it's known to be used
	// by Windows to enable long path support.
	bitField := (*byte)(unsafe.Pointer(stdcall0(_RtlGetCurrentPeb) + PebBitFieldOffset))
	*bitField |= IsLongPathAwareProcess

	canUseLongPaths = true
}

func osinit() {
	asmstdcallAddr = unsafe.Pointer(abi.FuncPCABI0(asmstdcall))

	loadOptionalSyscalls()

	preventErrorDialogs()

	initExceptionHandler()

	initHighResTimer()
	timeBeginPeriodRetValue = osRelax(false)

	initSysDirectory()
	initLongPathSupport()

	ncpu = getproccount()

	physPageSize = getPageSize()

	// Windows dynamic priority boosting assumes that a process has different types
	// of dedicated threads -- GUI, IO, computational, etc. Go processes use
	// equivalent threads that all do a mix of GUI, IO, computations, etc.
	// In such context dynamic priority boosting does nothing but harm, so we turn it off.
	stdcall2(_SetProcessPriorityBoost, currentProcess, 1)
}

//go:nosplit
func readRandom(r []byte) int {
	n := 0
	if stdcall2(_ProcessPrng, uintptr(unsafe.Pointer(&r[0])), uintptr(len(r)))&0xff != 0 {
		n = len(r)
	}
	return n
}

func goenvs() {
	// strings is a pointer to environment variable pairs in the form:
	//     "envA=valA\x00envB=valB\x00\x00" (in UTF-16)
	// Two consecutive zero bytes end the list.
	strings := unsafe.Pointer(stdcall0(_GetEnvironmentStringsW))
	p := (*[1 << 24]uint16)(strings)[:]

	n := 0
	for from, i := 0, 0; true; i++ {
		if p[i] == 0 {
			// empty string marks the end
			if i == from {
				break
			}
			from = i + 1
			n++
		}
	}
	envs = make([]string, n)

	for i := range envs {
		envs[i] = gostringw(&p[0])
		for p[0] != 0 {
			p = p[1:]
		}
		p = p[1:] // skip nil byte
	}

	stdcall1(_FreeEnvironmentStringsW, uintptr(strings))

	// We call these all the way here, late in init, so that malloc works
	// for the callback functions these generate.
	var fn any = ctrlHandler
	ctrlHandlerPC := compileCallback(*efaceOf(&fn), true)
	stdcall2(_SetConsoleCtrlHandler, ctrlHandlerPC, 1)

	monitorSuspendResume()
}

// exiting is set to non-zero when the process is exiting.
var exiting uint32

//go:nosplit
func exit(code int32) {
	// Disallow thread suspension for preemption. Otherwise,
	// ExitProcess and SuspendThread can race: SuspendThread
	// queues a suspension request for this thread, ExitProcess
	// kills the suspending thread, and then this thread suspends.
	lock(&suspendLock)
	atomic.Store(&exiting, 1)
	stdcall1(_ExitProcess, uintptr(code))
}

// write1 must be nosplit because it's used as a last resort in
// functions like badmorestackg0. In such cases, we'll always take the
// ASCII path.
//
//go:nosplit
func write1(fd uintptr, buf unsafe.Pointer, n int32) int32 {
	const (
		_STD_OUTPUT_HANDLE = ^uintptr(10) // -11
		_STD_ERROR_HANDLE  = ^uintptr(11) // -12
	)
	var handle uintptr
	switch fd {
	case 1:
		handle = stdcall1(_GetStdHandle, _STD_OUTPUT_HANDLE)
	case 2:
		handle = stdcall1(_GetStdHandle, _STD_ERROR_HANDLE)
	default:
		// assume fd is real windows handle.
		handle = fd
	}
	isASCII := true
	b := (*[1 << 30]byte)(buf)[:n]
	for _, x := range b {
		if x >= 0x80 {
			isASCII = false
			break
		}
	}

	if !isASCII {
		var m uint32
		isConsole := stdcall2(_GetConsoleMode, handle, uintptr(unsafe.Pointer(&m))) != 0
		// If this is a console output, various non-unicode code pages can be in use.
		// Use the dedicated WriteConsole call to ensure unicode is printed correctly.
		if isConsole {
			return int32(writeConsole(handle, buf, n))
		}
	}
	var written uint32
	stdcall5(_WriteFile, handle, uintptr(buf), uintptr(n), uintptr(unsafe.Pointer(&written)), 0)
	return int32(written)
}

var (
	utf16ConsoleBack     [1000]uint16
	utf16ConsoleBackLock mutex
)

// writeConsole writes bufLen bytes from buf to the console File.
// It returns the number of bytes written.
func writeConsole(handle uintptr, buf unsafe.Pointer, bufLen int32) int {
	const surr2 = (surrogateMin + surrogateMax + 1) / 2

	// Do not use defer for unlock. May cause issues when printing a panic.
	lock(&utf16ConsoleBackLock)

	b := (*[1 << 30]byte)(buf)[:bufLen]
	s := *(*string)(unsafe.Pointer(&b))

	utf16tmp := utf16ConsoleBack[:]

	total := len(s)
	w := 0
	for _, r := range s {
		if w >= len(utf16tmp)-2 {
			writeConsoleUTF16(handle, utf16tmp[:w])
			w = 0
		}
		if r < 0x10000 {
			utf16tmp[w] = uint16(r)
			w++
		} else {
			r -= 0x10000
			utf16tmp[w] = surrogateMin + uint16(r>>10)&0x3ff
			utf16tmp[w+1] = surr2 + uint16(r)&0x3ff
			w += 2
		}
	}
	writeConsoleUTF16(handle, utf16tmp[:w])
	unlock(&utf16ConsoleBackLock)
	return total
}

// writeConsoleUTF16 is the dedicated windows calls that correctly prints
// to the console regardless of the current code page. Input is utf-16 code points.
// The handle must be a console handle.
func writeConsoleUTF16(handle uintptr, b []uint16) {
	l := uint32(len(b))
	if l == 0 {
		return
	}
	var written uint32
	stdcall5(_WriteConsoleW,
		handle,
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(l),
		uintptr(unsafe.Pointer(&written)),
		0,
	)
	return
}

//go:nosplit
func semasleep(ns int64) int32 {
	const (
		_WAIT_ABANDONED = 0x00000080
		_WAIT_OBJECT_0  = 0x00000000
		_WAIT_TIMEOUT   = 0x00000102
		_WAIT_FAILED    = 0xFFFFFFFF
	)

	var result uintptr
	if ns < 0 {
		result = stdcall2(_WaitForSingleObject, getg().m.waitsema, uintptr(_INFINITE))
	} else {
		start := nanotime()
		elapsed := int64(0)
		for {
			ms := int64(timediv(ns-elapsed, 1000000, nil))
			if ms == 0 {
				ms = 1
			}
			result = stdcall4(_WaitForMultipleObjects, 2,
				uintptr(unsafe.Pointer(&[2]uintptr{getg().m.waitsema, getg().m.resumesema})),
				0, uintptr(ms))
			if result != _WAIT_OBJECT_0+1 {
				// Not a suspend/resume event
				break
			}
			elapsed = nanotime() - start
			if elapsed >= ns {
				return -1
			}
		}
	}
	switch result {
	case _WAIT_OBJECT_0: // Signaled
		return 0

	case _WAIT_TIMEOUT:
		return -1

	case _WAIT_ABANDONED:
		systemstack(func() {
			throw("runtime.semasleep wait_abandoned")
		})

	case _WAIT_FAILED:
		systemstack(func() {
			print("runtime: waitforsingleobject wait_failed; errno=", getlasterror(), "\n")
			throw("runtime.semasleep wait_failed")
		})

	default:
		systemstack(func() {
			print("runtime: waitforsingleobject unexpected; result=", result, "\n")
			throw("runtime.semasleep unexpected")
		})
	}

	return -1 // unreachable
}

//go:nosplit
func semawakeup(mp *m) {
	if stdcall1(_SetEvent, mp.waitsema) == 0 {
		systemstack(func() {
			print("runtime: setevent failed; errno=", getlasterror(), "\n")
			throw("runtime.semawakeup")
		})
	}
}

//go:nosplit
func semacreate(mp *m) {
	if mp.waitsema != 0 {
		return
	}
	mp.waitsema = stdcall4(_CreateEventA, 0, 0, 0, 0)
	if mp.waitsema == 0 {
		systemstack(func() {
			print("runtime: createevent failed; errno=", getlasterror(), "\n")
			throw("runtime.semacreate")
		})
	}
	mp.resumesema = stdcall4(_CreateEventA, 0, 0, 0, 0)
	if mp.resumesema == 0 {
		systemstack(func() {
			print("runtime: createevent failed; errno=", getlasterror(), "\n")
			throw("runtime.semacreate")
		})
		stdcall1(_CloseHandle, mp.waitsema)
		mp.waitsema = 0
	}
}

// May run with m.p==nil, so write barriers are not allowed. This
// function is called by newosproc0, so it is also required to
// operate without stack guards.
//
//go:nowritebarrierrec
//go:nosplit
func newosproc(mp *m) {
	// We pass 0 for the stack size to use the default for this binary.
	thandle := stdcall6(_CreateThread, 0, 0,
		abi.FuncPCABI0(tstart_stdcall), uintptr(unsafe.Pointer(mp)),
		0, 0)

	if thandle == 0 {
		if atomic.Load(&exiting) != 0 {
			// CreateThread may fail if called
			// concurrently with ExitProcess. If this
			// happens, just freeze this thread and let
			// the process exit. See issue #18253.
			lock(&deadlock)
			lock(&deadlock)
		}
		print("runtime: failed to create new OS thread (have ", mcount(), " already; errno=", getlasterror(), ")\n")
		throw("runtime.newosproc")
	}

	// Close thandle to avoid leaking the thread object if it exits.
	stdcall1(_CloseHandle, thandle)
}

// Used by the C library build mode. On Linux this function would allocate a
// stack, but that's not necessary for Windows. No stack guards are present
// and the GC has not been initialized, so write barriers will fail.
//
//go:nowritebarrierrec
//go:nosplit
func newosproc0(mp *m, stk unsafe.Pointer) {
	// TODO: this is completely broken. The args passed to newosproc0 (in asm_amd64.s)
	// are stacksize and function, not *m and stack.
	// Check os_linux.go for an implementation that might actually work.
	throw("bad newosproc0")
}

func exitThread(wait *atomic.Uint32) {
	// We should never reach exitThread on Windows because we let
	// the OS clean up threads.
	throw("exitThread")
}

// Called to initialize a new m (including the bootstrap m).
// Called on the parent thread (main thread in case of bootstrap), can allocate memory.
func mpreinit(mp *m) {
}

//go:nosplit
func sigsave(p *sigset) {
}

//go:nosplit
func msigrestore(sigmask sigset) {
}

//go:nosplit
//go:nowritebarrierrec
func clearSignalHandlers() {
}

//go:nosplit
func sigblock(exiting bool) {
}

// Called to initialize a new m (including the bootstrap m).
// Called on the new thread, cannot allocate Go memory.
func minit() {
	var thandle uintptr
	if stdcall7(_DuplicateHandle, currentProcess, currentThread, currentProcess, uintptr(unsafe.Pointer(&thandle)), 0, 0, _DUPLICATE_SAME_ACCESS) == 0 {
		print("runtime.minit: duplicatehandle failed; errno=", getlasterror(), "\n")
		throw("runtime.minit: duplicatehandle failed")
	}

	mp := getg().m
	lock(&mp.threadLock)
	mp.thread = thandle
	mp.procid = uint64(stdcall0(_GetCurrentThreadId))

	// Configure usleep timer, if possible.
	if mp.highResTimer == 0 && haveHighResTimer {
		mp.highResTimer = createHighResTimer()
		if mp.highResTimer == 0 {
			print("runtime: CreateWaitableTimerEx failed; errno=", getlasterror(), "\n")
			throw("CreateWaitableTimerEx when creating timer failed")
		}
	}
	if mp.waitIocpHandle == 0 && haveHighResSleep {
		mp.waitIocpTimer = createHighResTimer()
		if mp.waitIocpTimer == 0 {
			print("runtime: CreateWaitableTimerEx failed; errno=", getlasterror(), "\n")
			throw("CreateWaitableTimerEx when creating timer failed")
		}
		const GENERIC_ALL = 0x10000000
		errno := stdcall3(_NtCreateWaitCompletionPacket, uintptr(unsafe.Pointer(&mp.waitIocpHandle)), GENERIC_ALL, 0)
		if mp.waitIocpHandle == 0 {
			print("runtime: NtCreateWaitCompletionPacket failed; errno=", errno, "\n")
			throw("NtCreateWaitCompletionPacket failed")
		}
	}
	unlock(&mp.threadLock)

	// Query the true stack base from the OS. Currently we're
	// running on a small assumed stack.
	var mbi memoryBasicInformation
	res := stdcall3(_VirtualQuery, uintptr(unsafe.Pointer(&mbi)), uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
	if res == 0 {
		print("runtime: VirtualQuery failed; errno=", getlasterror(), "\n")
		throw("VirtualQuery for stack base failed")
	}
	// The system leaves an 8K PAGE_GUARD region at the bottom of
	// the stack (in theory VirtualQuery isn't supposed to include
	// that, but it does). Add an additional 8K of slop for
	// calling C functions that don't have stack checks and for
	// lastcontinuehandler. We shouldn't be anywhere near this
	// bound anyway.
	base := mbi.allocationBase + 16<<10
	// Sanity check the stack bounds.
	g0 := getg()
	if base > g0.stack.hi || g0.stack.hi-base > 64<<20 {
		print("runtime: g0 stack [", hex(base), ",", hex(g0.stack.hi), ")\n")
		throw("bad g0 stack")
	}
	g0.stack.lo = base
	g0.stackguard0 = g0.stack.lo + stackGuard
	g0.stackguard1 = g0.stackguard0
	// Sanity check the SP.
	stackcheck()
}

// Called from dropm to undo the effect of an minit.
//
//go:nosplit
func unminit() {
	mp := getg().m
	lock(&mp.threadLock)
	if mp.thread != 0 {
		stdcall1(_CloseHandle, mp.thread)
		mp.thread = 0
	}
	unlock(&mp.threadLock)

	mp.procid = 0
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
//
//go:nosplit
func mdestroy(mp *m) {
	if mp.highResTimer != 0 {
		stdcall1(_CloseHandle, mp.highResTimer)
		mp.highResTimer = 0
	}
	if mp.waitIocpTimer != 0 {
		stdcall1(_CloseHandle, mp.waitIocpTimer)
		mp.waitIocpTimer = 0
	}
	if mp.waitIocpHandle != 0 {
		stdcall1(_CloseHandle, mp.waitIocpHandle)
		mp.waitIocpHandle = 0
	}
	if mp.waitsema != 0 {
		stdcall1(_CloseHandle, mp.waitsema)
		mp.waitsema = 0
	}
	if mp.resumesema != 0 {
		stdcall1(_CloseHandle, mp.resumesema)
		mp.resumesema = 0
	}
}

// asmstdcall_trampoline calls asmstdcall converting from Go to C calling convention.
func asmstdcall_trampoline(args unsafe.Pointer)

// stdcall_no_g calls asmstdcall on os stack without using g.
//
//go:nosplit
func stdcall_no_g(fn stdFunction, n int, args uintptr) uintptr {
	libcall := libcall{
		fn:   uintptr(unsafe.Pointer(fn)),
		n:    uintptr(n),
		args: args,
	}
	asmstdcall_trampoline(noescape(unsafe.Pointer(&libcall)))
	return libcall.r1
}

// Calling stdcall on os stack.
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrier
//go:nosplit
func stdcall(fn stdFunction) uintptr {
	gp := getg()
	mp := gp.m
	mp.libcall.fn = uintptr(unsafe.Pointer(fn))
	resetLibcall := false
	if mp.profilehz != 0 && mp.libcallsp == 0 {
		// leave pc/sp for cpu profiler
		mp.libcallg.set(gp)
		mp.libcallpc = sys.GetCallerPC()
		// sp must be the last, because once async cpu profiler finds
		// all three values to be non-zero, it will use them
		mp.libcallsp = sys.GetCallerSP()
		resetLibcall = true // See comment in sys_darwin.go:libcCall
	}
	asmcgocall(asmstdcallAddr, unsafe.Pointer(&mp.libcall))
	if resetLibcall {
		mp.libcallsp = 0
	}
	return mp.libcall.r1
}

//go:nosplit
func stdcall0(fn stdFunction) uintptr {
	mp := getg().m
	mp.libcall.n = 0
	mp.libcall.args = 0
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall1(fn stdFunction, a0 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 1
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall2(fn stdFunction, a0, a1 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 2
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall3(fn stdFunction, a0, a1, a2 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 3
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall4(fn stdFunction, a0, a1, a2, a3 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 4
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall5(fn stdFunction, a0, a1, a2, a3, a4 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 5
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall6(fn stdFunction, a0, a1, a2, a3, a4, a5 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 6
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall7(fn stdFunction, a0, a1, a2, a3, a4, a5, a6 uintptr) uintptr {
	mp := getg().m
	mp.libcall.
"""




```