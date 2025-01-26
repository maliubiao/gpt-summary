Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the comprehensive answer.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided `os/exec.go` code snippet. This involves identifying its core purpose, key data structures, and the operations it supports related to process management. The prompt also asks for illustrative examples, explanations of command-line arguments (if applicable), common mistakes, and clear Chinese explanations.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code looking for keywords and structures that hint at its purpose. Key terms that jump out are:

* `package os`: This immediately tells us it's part of the standard `os` package, dealing with operating system interactions.
* `Process`:  This is a central data structure, likely representing a running process.
* `StartProcess`, `Kill`, `Wait`, `Signal`, `Release`: These are clearly process management operations.
* `ProcAttr`: This seems to define attributes for creating new processes.
* `PID`, `handle`:  These relate to how the process is identified and managed.
* `sync.Mutex`, `sync/atomic`: Indicates concurrency control, likely important in process management.
* `syscall`: Suggests direct interaction with operating system system calls.
* `ErrProcessDone`: An error related to process completion.

**3. Deciphering the `Process` struct:**

The `Process` struct is the heart of this code. It's crucial to understand its members:

* `Pid int`: The process ID.
* `mode processMode`:  Indicates how the process is managed (by PID or handle). The constants `modePID` and `modeHandle` clarify this.
* `state atomic.Uint64`:  This manages the process's lifecycle and concurrency. The `processStatus` constants and the comments explaining reference counting are vital for understanding this.
* `sigMu sync.RWMutex`:  A mutex for synchronizing signal operations.
* `handle uintptr`:  An OS-specific process handle (pidfd on Linux, Windows handle).

The comments within the `Process` struct are extremely helpful in understanding the intricacies of handle management, reference counting, and the `state` atomic variable. Careful reading is necessary.

**4. Analyzing the Functions:**

Next, I examine the functions associated with the `Process` struct and other top-level functions:

* **Constructor Functions (`newPIDProcess`, `newHandleProcess`, `newDoneProcess`):**  These show how `Process` objects are created in different scenarios. `newDoneProcess` is particularly interesting as it represents a process that has already finished.
* **Handle Management Functions (`handleTransientAcquire`, `handleTransientRelease`, `handlePersistentRelease`):** These are critical for understanding how the `handle` is safely accessed and managed, especially with concurrency. The comments and panic conditions provide valuable insights.
* **PID Management Functions (`pidStatus`, `pidDeactivate`):**  These deal with the `modePID` scenario.
* **`FindProcess`:**  Retrieves an existing process.
* **`StartProcess`:**  Launches a new process. The `ProcAttr` struct is used to configure the new process.
* **`Release`:**  Releases resources associated with the process. The comment highlighting the platform-specific differences with `p.Pid` is important.
* **`Kill`:**  Sends a termination signal.
* **`Wait`:**  Waits for process termination and retrieves its status.
* **`Signal`:**  Sends a signal to the process.
* **`ProcessState` related functions (`UserTime`, `SystemTime`, `Exited`, `Success`, `Sys`, `SysUsage`):**  These provide information about the terminated process.

**5. Inferring the Go Functionality:**

Based on the identified components, it becomes clear that this code snippet implements core process management functionality within the `os` package. It provides the building blocks for interacting with operating system processes, allowing users to:

* Start new processes (`StartProcess`).
* Find existing processes (`FindProcess`).
* Send signals to processes (`Signal`, `Kill`).
* Wait for processes to finish (`Wait`).
* Release resources associated with processes (`Release`).
* Obtain information about terminated processes (`ProcessState`).

This directly relates to the fundamental concept of process management in operating systems.

**6. Creating Examples:**

To illustrate the functionality, I think of simple, practical use cases:

* **Starting and Waiting for a process:**  This is the most basic scenario. I use `exec.Command` from the `os/exec` package (as suggested in the comments) for a higher-level approach and show how to access the underlying `os.Process`.
* **Finding a process:**  Demonstrating `FindProcess` and sending a signal (or checking for existence).

**7. Addressing Command-Line Arguments:**

The code itself doesn't *directly* handle command-line arguments in the sense of parsing them. However, `StartProcess` takes `argv` as an argument, which *represents* the command and its arguments for the new process. I explain how this works and how it relates to the `os.Args` in the child process.

**8. Identifying Common Mistakes:**

I consider potential pitfalls for users:

* **Not calling `Wait` or `Release`:** Leading to resource leaks.
* **Assuming platform-independent behavior with `Release` and `Pid`:**  Highlighting the Windows vs. Unix difference.
* **Incorrect signal handling:**  Mentioning the `Interrupt` limitation on Windows.

**9. Structuring the Answer:**

Finally, I organize the information into a clear and structured format using the requested Chinese language:

* Start with a concise summary of the functionality.
* Provide detailed explanations of the key components (`Process`, `ProcAttr`).
* Give concrete Go code examples with input and output.
* Explain the handling of command-line arguments.
* Point out common mistakes.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on `os.StartProcess`.
* **Correction:** Realized the importance of `FindProcess` and the lifecycle management aspects (`Wait`, `Release`).
* **Initial thought:**  Provide very low-level `syscall` examples.
* **Correction:** Used `os/exec.Command` for simpler, more common use cases, noting the connection to `os.Process`.
* **Initial thought:**  Briefly mention concurrency.
* **Correction:** Emphasized the role of `atomic.Uint64` and the handle management functions in ensuring thread safety.
* **Initial thought:** Just list the functions.
* **Correction:**  Grouped functions by their purpose (constructors, handle management, etc.) for better clarity.

By following this structured approach, considering potential user misunderstandings, and providing clear examples, I can generate a comprehensive and helpful answer to the prompt.
这段代码是 Go 语言标准库 `os` 包中 `exec.go` 文件的一部分。它主要负责提供**低级别的进程管理功能**，允许 Go 程序创建、查找、控制和等待操作系统进程。

以下是代码片段功能的详细列举：

**核心功能：进程表示和管理**

1. **`Process` 结构体：** 定义了 Go 语言中进程的抽象表示。它包含了进程 ID (`Pid`) 和一些内部状态信息，用于跟踪进程的生命周期和资源。
2. **`mode processMode`：**  区分 `Process` 对象是如何管理底层操作系统进程的。
    * `modePID`：表示 `Process` 对象仅使用进程 ID (`Pid`) 进行操作。例如，当系统不支持进程句柄或 `Process` 对象是字面量创建时。
    * `modeHandle`：表示 `Process` 对象使用操作系统提供的进程句柄 (`handle`) 进行操作。
3. **`state atomic.Uint64`：** 使用原子操作管理进程的状态，包括进程是否已完成、是否已释放，以及（在 `modeHandle` 模式下）句柄的引用计数。这确保了并发访问 `Process` 对象的安全性。
4. **`handle uintptr`：**  存储操作系统提供的进程句柄。在 Windows 上是 `OpenProcess` 返回的句柄，在 Linux 上是 `pidfd`。
5. **构造函数 (`newPIDProcess`, `newHandleProcess`, `newDoneProcess`)：**  提供了创建 `Process` 对象的不同方式：
    * `newPIDProcess`：创建一个仅包含进程 ID 的 `Process` 对象（`modePID`）。
    * `newHandleProcess`：创建一个包含进程 ID 和操作系统句柄的 `Process` 对象（`modeHandle`）。
    * `newDoneProcess`：创建一个表示已完成进程的 `Process` 对象，不需要有效的操作系统句柄。
6. **句柄管理函数 (`handleTransientAcquire`, `handleTransientRelease`, `handlePersistentRelease`)：**  用于安全地获取和释放操作系统句柄的临时和持久引用，防止在并发操作中出现问题。
7. **PID 模式管理函数 (`pidStatus`, `pidDeactivate`)：**  用于在 `modePID` 模式下获取和设置进程状态。
8. **`Release()` 方法：** 释放与 `Process` 对象关联的资源。如果不再需要等待进程结束，或者希望提前释放资源，可以调用此方法。
9. **`Kill()` 方法：** 立即终止进程。
10. **`Wait()` 方法：** 等待进程结束，并返回进程的状态信息 `ProcessState`。调用 `Wait` 会释放与 `Process` 对象关联的资源。
11. **`Signal()` 方法：** 向进程发送一个信号。

**辅助功能：进程属性和信号**

12. **`ProcAttr` 结构体：**  定义了创建新进程时的属性，例如工作目录 (`Dir`)、环境变量 (`Env`) 和继承的文件描述符 (`Files`)。
13. **`Signal` 接口：**  定义了操作系统信号的抽象表示。
14. **`Getpid()` 函数：** 返回当前进程的 ID。
15. **`Getppid()` 函数：** 返回当前进程父进程的 ID。
16. **`FindProcess()` 函数：** 根据进程 ID 查找正在运行的进程。

**底层进程启动**

17. **`StartProcess()` 函数：**  这是启动新进程的底层函数。它接受程序名、参数和进程属性，并返回新创建的 `Process` 对象。通常情况下，更推荐使用 `os/exec` 包中更高级的接口。

**进程状态信息**

18. **`ProcessState` 结构体 (未在代码片段中完整展示)：**  存储进程结束后的状态信息，例如退出码、使用的 CPU 时间等。
19. **`UserTime()`, `SystemTime()`, `Exited()`, `Success()`, `Sys()`, `SysUsage()` 方法：**  用于从 `ProcessState` 对象中获取进程的用户 CPU 时间、系统 CPU 时间、是否正常退出、是否成功退出以及系统相关的状态和资源使用信息。

**它是什么 Go 语言功能的实现？**

这段代码实现了 Go 语言中与**操作系统进程交互**的核心功能。它是 `os` 包中用于启动、管理和监控外部进程的基础。虽然 `os/exec` 包提供了更易用的高级接口，但 `os.StartProcess` 和相关的 `Process` 结构体是构建这些高级功能的基石。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func main() {
	// 使用 os/exec 包启动一个外部命令
	cmd := exec.Command("ls", "-l")

	// 获取底层的 os.Process 对象
	err := cmd.Start()
	if err != nil {
		fmt.Println("启动进程失败:", err)
		return
	}
	process := cmd.Process
	fmt.Printf("进程 ID: %d\n", process.Pid)

	// 等待进程结束
	state, err := process.Wait()
	if err != nil {
		fmt.Println("等待进程结束失败:", err)
		return
	}
	fmt.Printf("进程退出状态: %v\n", state)
	fmt.Printf("是否成功退出: %t\n", state.Success())

	// 使用 os.FindProcess 查找一个正在运行的进程（假设你知道它的 PID）
	// 这里假设你运行了一个 PID 为 12345 的进程
	pidToFind := 12345
	foundProcess, err := os.FindProcess(pidToFind)
	if err != nil {
		fmt.Println("查找进程失败:", err)
	} else if foundProcess != nil {
		fmt.Printf("找到进程 (PID: %d)\n", foundProcess.Pid)

		// 尝试发送一个信号 (如果进程存在)
		err = foundProcess.Signal(syscall.SIGTERM)
		if err != nil {
			fmt.Println("发送信号失败:", err)
		} else {
			fmt.Println("已向进程发送 SIGTERM 信号")
		}
	}

	// 使用 os.StartProcess 启动一个新进程 (更底层的方式)
	attr := &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}
	newProcess, err := os.StartProcess("/bin/sleep", []string{"sleep", "2"}, attr)
	if err != nil {
		fmt.Println("使用 StartProcess 启动进程失败:", err)
		return
	}
	fmt.Printf("新进程 ID: %d\n", newProcess.Pid)
	time.Sleep(3 * time.Second) // 让新进程运行一段时间
	err = newProcess.Kill()
	if err != nil {
		fmt.Println("杀死新进程失败:", err)
	} else {
		fmt.Println("已杀死新进程")
	}
}
```

**假设的输入与输出:**

**场景 1： 使用 `os/exec` 启动并等待 `ls -l`**

* **输入：** 运行上述 Go 代码。
* **输出（示例）：**
  ```
  进程 ID: 12346
  进程退出状态: &{exit status 0}
  是否成功退出: true
  查找进程失败: os: process not found  // 假设 PID 12345 不存在或已结束
  新进程 ID: 12347
  已杀死新进程
  ```
  实际输出会根据你的系统环境和正在运行的进程而变化。`ls -l` 的输出会显示在标准输出中。

**场景 2： 使用 `os.FindProcess` 找到一个存在的进程**

* **假设：**  你的系统上有一个 PID 为 `1000` 的进程正在运行。
* **修改代码：** 将 `pidToFind` 修改为 `1000`。
* **输出（示例）：**
  ```
  进程 ID: 12348
  进程退出状态: &{exit status 0}
  是否成功退出: true
  找到进程 (PID: 1000)
  已向进程发送 SIGTERM 信号
  新进程 ID: 12349
  已杀死新进程
  ```
  如果进程 1000 不存在或者你没有权限发送信号，则会输出相应的错误信息。

**命令行参数的具体处理:**

`os/exec.go` 本身并不直接处理当前 Go 程序的命令行参数。Go 程序的命令行参数由 `os.Args` 切片提供。

在 `StartProcess` 函数中，`argv` 参数对应于新启动的进程的命令行参数。例如，在上面的 `os.StartProcess("/bin/sleep", []string{"sleep", "2"}, attr)` 调用中：

* `"sleep"` 是新进程执行的程序名。
* `"sleep"` 是 `argv` 的第一个元素，通常是程序名本身。
* `"2"` 是 `argv` 的第二个元素，作为 `sleep` 命令的参数，表示休眠 2 秒。

当新进程启动时，它的 `os.Args` 切片将会是 `[]string{"sleep", "2"}`。

**使用者易犯错的点:**

1. **资源泄露：** 如果使用 `os.StartProcess` 启动进程后，没有调用 `Wait()` 或 `Release()` 方法来释放与 `Process` 对象关联的资源，可能会导致资源泄露。尤其是在需要频繁启动进程的场景下。

   ```go
   // 错误示例：忘记调用 Wait() 或 Release()
   process, err := os.StartProcess("/bin/sleep", []string{"sleep", "1"}, nil)
   if err != nil {
       // 处理错误
   }
   // ... 后续代码没有调用 process.Wait() 或 process.Release()
   ```

2. **平台差异：**  `Release()` 方法的行为在不同操作系统上可能略有不同（注释中有提到 Unix 和 Windows 的区别，关于 `p.Pid` 的修改）。开发者需要注意这些平台差异。

3. **不理解 `os.StartProcess` 的低级别性质：** `os.StartProcess` 是一个相对底层的函数，需要更细致地处理进程的属性和错误。对于大多数场景，推荐使用 `os/exec` 包中的 `Command` 函数，它提供了更方便和安全的接口。

4. **信号处理的平台差异：** 发送信号的行为和支持的信号在不同操作系统上可能有所不同。例如，Windows 上不支持发送 `Interrupt` 信号。

这段代码是 Go 语言进程管理的基础，理解它的工作原理对于编写需要与操作系统进程交互的 Go 程序至关重要。 同时也需要注意其低级别的性质和潜在的平台差异。

Prompt: 
```
这是路径为go/src/os/exec.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

import (
	"errors"
	"internal/testlog"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ErrProcessDone indicates a [Process] has finished.
var ErrProcessDone = errors.New("os: process already finished")

type processMode uint8

const (
	// modePID means that Process operations such use the raw PID from the
	// Pid field. handle is not used.
	//
	// This may be due to the host not supporting handles, or because
	// Process was created as a literal, leaving handle unset.
	//
	// This must be the zero value so Process literals get modePID.
	modePID processMode = iota

	// modeHandle means that Process operations use handle, which is
	// initialized with an OS process handle.
	//
	// Note that Release and Wait will deactivate and eventually close the
	// handle, so acquire may fail, indicating the reason.
	modeHandle
)

type processStatus uint64

const (
	// PID/handle OK to use.
	statusOK processStatus = 0

	// statusDone indicates that the PID/handle should not be used because
	// the process is done (has been successfully Wait'd on).
	statusDone processStatus = 1 << 62

	// statusReleased indicates that the PID/handle should not be used
	// because the process is released.
	statusReleased processStatus = 1 << 63

	processStatusMask = 0x3 << 62
)

// Process stores the information about a process created by [StartProcess].
type Process struct {
	Pid int

	mode processMode

	// State contains the atomic process state.
	//
	// In modePID, this consists only of the processStatus fields, which
	// indicate if the process is done/released.
	//
	// In modeHandle, the lower bits also contain a reference count for the
	// handle field.
	//
	// The Process itself initially holds 1 persistent reference. Any
	// operation that uses the handle with a system call temporarily holds
	// an additional transient reference. This prevents the handle from
	// being closed prematurely, which could result in the OS allocating a
	// different handle with the same value, leading to Process' methods
	// operating on the wrong process.
	//
	// Release and Wait both drop the Process' persistent reference, but
	// other concurrent references may delay actually closing the handle
	// because they hold a transient reference.
	//
	// Regardless, we want new method calls to immediately treat the handle
	// as unavailable after Release or Wait to avoid extending this delay.
	// This is achieved by setting either processStatus flag when the
	// Process' persistent reference is dropped. The only difference in the
	// flags is the reason the handle is unavailable, which affects the
	// errors returned by concurrent calls.
	state atomic.Uint64

	// Used only in modePID.
	sigMu sync.RWMutex // avoid race between wait and signal

	// handle is the OS handle for process actions, used only in
	// modeHandle.
	//
	// handle must be accessed only via the handleTransientAcquire method
	// (or during closeHandle), not directly! handle is immutable.
	//
	// On Windows, it is a handle from OpenProcess.
	// On Linux, it is a pidfd.
	// It is unused on other GOOSes.
	handle uintptr
}

func newPIDProcess(pid int) *Process {
	p := &Process{
		Pid:  pid,
		mode: modePID,
	}
	runtime.SetFinalizer(p, (*Process).Release)
	return p
}

func newHandleProcess(pid int, handle uintptr) *Process {
	p := &Process{
		Pid:    pid,
		mode:   modeHandle,
		handle: handle,
	}
	p.state.Store(1) // 1 persistent reference
	runtime.SetFinalizer(p, (*Process).Release)
	return p
}

func newDoneProcess(pid int) *Process {
	p := &Process{
		Pid:  pid,
		mode: modeHandle,
		// N.B Since we set statusDone, handle will never actually be
		// used, so its value doesn't matter.
	}
	p.state.Store(uint64(statusDone)) // No persistent reference, as there is no handle.
	runtime.SetFinalizer(p, (*Process).Release)
	return p
}

func (p *Process) handleTransientAcquire() (uintptr, processStatus) {
	if p.mode != modeHandle {
		panic("handleTransientAcquire called in invalid mode")
	}

	for {
		refs := p.state.Load()
		if refs&processStatusMask != 0 {
			return 0, processStatus(refs & processStatusMask)
		}
		new := refs + 1
		if !p.state.CompareAndSwap(refs, new) {
			continue
		}
		return p.handle, statusOK
	}
}

func (p *Process) handleTransientRelease() {
	if p.mode != modeHandle {
		panic("handleTransientRelease called in invalid mode")
	}

	for {
		state := p.state.Load()
		refs := state &^ processStatusMask
		status := processStatus(state & processStatusMask)
		if refs == 0 {
			// This should never happen because
			// handleTransientRelease is always paired with
			// handleTransientAcquire.
			panic("release of handle with refcount 0")
		}
		if refs == 1 && status == statusOK {
			// Process holds a persistent reference and always sets
			// a status when releasing that reference
			// (handlePersistentRelease). Thus something has gone
			// wrong if this is the last release but a status has
			// not always been set.
			panic("final release of handle without processStatus")
		}
		new := state - 1
		if !p.state.CompareAndSwap(state, new) {
			continue
		}
		if new&^processStatusMask == 0 {
			p.closeHandle()
		}
		return
	}
}

// Drop the Process' persistent reference on the handle, deactivating future
// Wait/Signal calls with the passed reason.
//
// Returns the status prior to this call. If this is not statusOK, then the
// reference was not dropped or status changed.
func (p *Process) handlePersistentRelease(reason processStatus) processStatus {
	if p.mode != modeHandle {
		panic("handlePersistentRelease called in invalid mode")
	}

	for {
		refs := p.state.Load()
		status := processStatus(refs & processStatusMask)
		if status != statusOK {
			// Both Release and successful Wait will drop the
			// Process' persistent reference on the handle. We
			// can't allow concurrent calls to drop the reference
			// twice, so we use the status as a guard to ensure the
			// reference is dropped exactly once.
			return status
		}
		if refs == 0 {
			// This should never happen because dropping the
			// persistent reference always sets a status.
			panic("release of handle with refcount 0")
		}
		new := (refs - 1) | uint64(reason)
		if !p.state.CompareAndSwap(refs, new) {
			continue
		}
		if new&^processStatusMask == 0 {
			p.closeHandle()
		}
		return status
	}
}

func (p *Process) pidStatus() processStatus {
	if p.mode != modePID {
		panic("pidStatus called in invalid mode")
	}

	return processStatus(p.state.Load())
}

func (p *Process) pidDeactivate(reason processStatus) {
	if p.mode != modePID {
		panic("pidDeactivate called in invalid mode")
	}

	// Both Release and successful Wait will deactivate the PID. Only one
	// of those should win, so nothing left to do here if the compare
	// fails.
	//
	// N.B. This means that results can be inconsistent. e.g., with a
	// racing Release and Wait, Wait may successfully wait on the process,
	// returning the wait status, while future calls error with "process
	// released" rather than "process done".
	p.state.CompareAndSwap(0, uint64(reason))
}

// ProcAttr holds the attributes that will be applied to a new process
// started by StartProcess.
type ProcAttr struct {
	// If Dir is non-empty, the child changes into the directory before
	// creating the process.
	Dir string
	// If Env is non-nil, it gives the environment variables for the
	// new process in the form returned by Environ.
	// If it is nil, the result of Environ will be used.
	Env []string
	// Files specifies the open files inherited by the new process. The
	// first three entries correspond to standard input, standard output, and
	// standard error. An implementation may support additional entries,
	// depending on the underlying operating system. A nil entry corresponds
	// to that file being closed when the process starts.
	// On Unix systems, StartProcess will change these File values
	// to blocking mode, which means that SetDeadline will stop working
	// and calling Close will not interrupt a Read or Write.
	Files []*File

	// Operating system-specific process creation attributes.
	// Note that setting this field means that your program
	// may not execute properly or even compile on some
	// operating systems.
	Sys *syscall.SysProcAttr
}

// A Signal represents an operating system signal.
// The usual underlying implementation is operating system-dependent:
// on Unix it is syscall.Signal.
type Signal interface {
	String() string
	Signal() // to distinguish from other Stringers
}

// Getpid returns the process id of the caller.
func Getpid() int { return syscall.Getpid() }

// Getppid returns the process id of the caller's parent.
func Getppid() int { return syscall.Getppid() }

// FindProcess looks for a running process by its pid.
//
// The [Process] it returns can be used to obtain information
// about the underlying operating system process.
//
// On Unix systems, FindProcess always succeeds and returns a Process
// for the given pid, regardless of whether the process exists. To test whether
// the process actually exists, see whether p.Signal(syscall.Signal(0)) reports
// an error.
func FindProcess(pid int) (*Process, error) {
	return findProcess(pid)
}

// StartProcess starts a new process with the program, arguments and attributes
// specified by name, argv and attr. The argv slice will become [os.Args] in the
// new process, so it normally starts with the program name.
//
// If the calling goroutine has locked the operating system thread
// with [runtime.LockOSThread] and modified any inheritable OS-level
// thread state (for example, Linux or Plan 9 name spaces), the new
// process will inherit the caller's thread state.
//
// StartProcess is a low-level interface. The [os/exec] package provides
// higher-level interfaces.
//
// If there is an error, it will be of type [*PathError].
func StartProcess(name string, argv []string, attr *ProcAttr) (*Process, error) {
	testlog.Open(name)
	return startProcess(name, argv, attr)
}

// Release releases any resources associated with the [Process] p,
// rendering it unusable in the future.
// Release only needs to be called if [Process.Wait] is not.
func (p *Process) Release() error {
	// Note to future authors: the Release API is cursed.
	//
	// On Unix and Plan 9, Release sets p.Pid = -1. This is the only part of the
	// Process API that is not thread-safe, but it can't be changed now.
	//
	// On Windows, Release does _not_ modify p.Pid.
	//
	// On Windows, Wait calls Release after successfully waiting to
	// proactively clean up resources.
	//
	// On Unix and Plan 9, Wait also proactively cleans up resources, but
	// can not call Release, as Wait does not set p.Pid = -1.
	//
	// On Unix and Plan 9, calling Release a second time has no effect.
	//
	// On Windows, calling Release a second time returns EINVAL.
	return p.release()
}

// Kill causes the [Process] to exit immediately. Kill does not wait until
// the Process has actually exited. This only kills the Process itself,
// not any other processes it may have started.
func (p *Process) Kill() error {
	return p.kill()
}

// Wait waits for the [Process] to exit, and then returns a
// ProcessState describing its status and an error, if any.
// Wait releases any resources associated with the Process.
// On most operating systems, the Process must be a child
// of the current process or an error will be returned.
func (p *Process) Wait() (*ProcessState, error) {
	return p.wait()
}

// Signal sends a signal to the [Process].
// Sending [Interrupt] on Windows is not implemented.
func (p *Process) Signal(sig Signal) error {
	return p.signal(sig)
}

// UserTime returns the user CPU time of the exited process and its children.
func (p *ProcessState) UserTime() time.Duration {
	return p.userTime()
}

// SystemTime returns the system CPU time of the exited process and its children.
func (p *ProcessState) SystemTime() time.Duration {
	return p.systemTime()
}

// Exited reports whether the program has exited.
// On Unix systems this reports true if the program exited due to calling exit,
// but false if the program terminated due to a signal.
func (p *ProcessState) Exited() bool {
	return p.exited()
}

// Success reports whether the program exited successfully,
// such as with exit status 0 on Unix.
func (p *ProcessState) Success() bool {
	return p.success()
}

// Sys returns system-dependent exit information about
// the process. Convert it to the appropriate underlying
// type, such as [syscall.WaitStatus] on Unix, to access its contents.
func (p *ProcessState) Sys() any {
	return p.sys()
}

// SysUsage returns system-dependent resource usage information about
// the exited process. Convert it to the appropriate underlying
// type, such as [*syscall.Rusage] on Unix, to access its contents.
// (On Unix, *syscall.Rusage matches struct rusage as defined in the
// getrusage(2) manual page.)
func (p *ProcessState) SysUsage() any {
	return p.sysUsage()
}

"""



```