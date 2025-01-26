Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding & Context:**

* **File Path:** `go/src/syscall/exec_plan9.go` immediately tells us this code is part of the `syscall` package in Go's standard library, specifically for the Plan 9 operating system. This implies it deals with low-level system calls related to process execution.
* **Copyright & License:** Standard Go boilerplate, indicating open-source nature.
* **Package Declaration:** `package syscall` confirms the context.
* **Imports:**  `internal/itoa`, `runtime`, `sync`, `unsafe`. These hint at string conversions, interaction with the Go runtime, synchronization primitives, and potentially direct memory manipulation (common in syscall packages).
* **Comment: `// Fork, exec, wait, etc.`**: This is a high-level summary of the file's purpose – core process management operations.

**2. Function-by-Function Analysis (and Internal Functions):**

I'd go through each function, understanding its purpose and how it contributes to the overall goal. Here’s a more detailed breakdown of the reasoning for some key functions:

* **`gstringb(b []byte) []byte`:**
    * **Purpose:**  The name suggests reading a string from a byte slice. The comment mentions a 16-bit length prefix in little-endian order. This is a common encoding scheme.
    * **Logic:** Check for minimum length (2 bytes for the length). Extract the length. Verify the remaining buffer is long enough for the string. Return the string slice.
    * **`go:nosplit`:** This directive is crucial in syscall packages. It prevents the Go runtime from inserting stack checks, which can interfere with low-level operations.

* **`gdirname(buf []byte) (name []byte, rest []byte)`:**
    * **Purpose:**  Extract a filename from a buffer of directory entries. The name suggests parsing directory data. The comment mentions `UnmarshalDir()` in `dir_plan9.go`, establishing a connection to how Plan 9 represents directory entries.
    * **Logic:** Similar pattern to `gstringb`: read a length, check bounds. `nameOffset` hints at the structure of the directory entry. Extracts the name using `gstringb`. Returns the name and the remaining buffer.

* **`StringSlicePtr(ss []string) []*byte` and `SlicePtrFromStrings(ss []string) ([]*byte, error)`:**
    * **Purpose:** Convert Go string slices to C-style `char**` (slice of `*byte`). Essential for passing strings to system calls.
    * **Difference:** `StringSlicePtr` panics on null bytes, while `SlicePtrFromStrings` returns an error. The latter is generally preferred for robustness.

* **`readdirnames(dirfd int) (names []string, err error)`:**
    * **Purpose:** Read filenames from a directory file descriptor. This builds upon `gdirname`.
    * **Logic:** Repeatedly reads directory entries using `Read`. Uses `gdirname` to extract individual filenames. Appends names to a slice.

* **`forkAndExecInChild(...)`:** This is the *core* of the process creation. It's the most complex and requires careful examination of each step:
    * **Purpose:**  Fork the process, perform necessary setup in the child (duplicating file descriptors, setting environment, changing directory), and finally `exec`.
    * **Key aspects:**
        * **`go:norace`:** Another important directive for syscall-heavy code, disabling race detection for performance in critical sections.
        * **`RawSyscall`:** Directly interacting with Plan 9 system calls (e.g., `SYS_RFORK`, `SYS_OPEN`, `SYS_DUP`, `SYS_EXEC`).
        * **Child-specific logic:** The code after the `fork` call (`r1 == 0`) is executed in the child process. It's crucial to avoid allocations and locking here due to potential deadlocks.
        * **Error Handling:**  Uses a pipe to communicate errors from the child back to the parent.
        * **File Descriptor Management:** The complex logic around `dup` and `close` ensures that the child process has the correct file descriptors inherited from the parent. The passes (1, 2, 3) are a clever way to avoid conflicts.
        * **Environment Variables:**  Creates files in `/env/` to set environment variables.

* **`cexecPipe(p []int) error`:**
    * **Purpose:** Creates a pipe that is close-on-exec for the write end. This is used for the child process to signal back to the parent.

* **`forkExec(...)`:**
    * **Purpose:** A higher-level wrapper around `forkAndExecInChild`, preparing arguments and handling the error pipe.

* **`startProcess(...)`:**
    * **Purpose:**  Introduces a goroutine to handle the `forkExec` and `wait` operations. This is necessary on Plan 9 because only the parent thread can reliably wait for child processes.

* **`ForkExec(...)` and `StartProcess(...)`:**  Public interfaces for initiating process creation. `StartProcess` is the version used by the `os` package.

* **`Exec(...)`:**  The simpler `exec` system call, replacing the current process.

* **`WaitProcess(...)`:**  Mechanism for the parent to wait for a child process started with `ForkExec` or `StartProcess`. Uses a channel-based approach for synchronization.

**3. Identifying Functionality & Go Language Features:**

After understanding the individual functions, I'd connect them to higher-level concepts:

* **Process Creation:** `ForkExec`, `StartProcess`, and the underlying `forkAndExecInChild` clearly implement process creation. This involves the `fork` and `exec` system calls.
* **Waiting for Processes:** `WaitProcess` uses the `Await` function (not shown but assumed to be a wrapper around Plan 9's `wait` system call) and Go channels for synchronization.
* **File Descriptor Management:** The code demonstrates how to manipulate file descriptors during `fork` and `exec`, ensuring proper inheritance.
* **Environment Variables:**  The code shows how environment variables are set up for the child process.
* **Error Handling:**  The use of a pipe to communicate errors from the child is a notable pattern.
* **Go Language Features:** Goroutines and channels are used for managing the waiting process. `unsafe` is used for low-level pointer manipulation when interacting with system calls. The `sync` package provides mutexes for thread safety.

**4. Code Examples and Reasoning:**

Once the functionality is clear, providing code examples becomes easier. The examples should demonstrate the typical use cases of the identified functions (spawning a process, waiting for it, executing a command directly). The input and output assumptions are based on how these system calls generally work.

**5. Command-Line Arguments:**

The code itself *doesn't* directly parse command-line arguments in the way a typical `main` function would. Instead, it *prepares* the arguments (`argv`) to be passed to the `exec` system call. The command-line argument handling would occur in the *calling* Go program (likely the `os/exec` package).

**6. Common Mistakes:**

This section requires thinking about potential pitfalls when using these low-level functions. Incorrect file descriptor handling, not waiting for child processes, and misuse of environment variables are common issues.

**7. Refinement and Structuring the Answer:**

Finally, organize the information logically, using clear headings and explanations. Provide context, then detail the functionality, illustrate with examples, and point out potential issues. Use precise language and avoid jargon where possible.

This methodical approach, moving from low-level code analysis to high-level understanding and practical examples, is key to dissecting and explaining complex code like this.
这段代码是 Go 语言 `syscall` 包中为 Plan 9 操作系统实现进程执行相关功能的一部分。它主要处理进程的创建（fork）、程序执行（exec）以及等待子进程结束（wait）等操作。

下面详细列举其功能和相关解释：

**1. 辅助函数:**

* **`gstringb(b []byte) []byte`:**  从字节切片 `b` 中读取一个字符串。这个字符串以一个 16 位的长度（小端序）作为前缀。如果 `b` 的长度不足以包含长度信息或完整的字符串，则返回 `nil`。这是一种在 Plan 9 中常见的字符串编码方式。

* **`gdirname(buf []byte) (name []byte, rest []byte)`:** 从包含目录项的缓冲区 `buf` 中提取第一个文件名。它假设 `buf` 的开头是一个有效的目录项。返回提取出的文件名（字节切片）以及剩余的目录项。

* **`StringSlicePtr(ss []string) []*byte` (Deprecated):** 将字符串切片 `ss` 转换为指向以 NULL 结尾的字节数组的指针切片。如果任何字符串包含 NULL 字节，此函数会 panic。现在推荐使用 `SlicePtrFromStrings`。

* **`SlicePtrFromStrings(ss []string) ([]*byte, error)`:**  将字符串切片 `ss` 转换为指向以 NULL 结尾的字节数组的指针切片。如果任何字符串包含 NULL 字节，则返回 `(nil, [EINVAL])`。这是将 Go 字符串传递给 C 风格的系统调用的常用方法。

* **`readdirnames(dirfd int) (names []string, err error)`:** 读取由文件描述符 `dirfd` 代表的目录中的文件名。它使用 `Read` 系统调用读取目录项，然后使用 `gdirname` 解析文件名。

* **`closeFdExcept(n int, fd1 int, fd2 int, fds []int)`:** 关闭文件描述符 `n`，除非它等于 `fd1`、`fd2` 或在切片 `fds` 中。这通常用于在 `fork` 后关闭不需要的文件描述符。

* **`cexecPipe(p []int) error`:** 创建一个管道，并将管道的写端设置为 close-on-exec。这通常用于父进程和子进程之间的通信，子进程在 `exec` 成功后会自动关闭写端。

**2. 核心进程管理功能:**

* **`forkAndExecInChild(argv0 *byte, argv []*byte, envv []envItem, dir *byte, attr *ProcAttr, pipe int, rflag int) (pid int, err error)`:** 这是实现 `fork` 和 `exec` 的核心函数。
    * **`fork`:** 使用 `RawSyscall(SYS_RFORK, ...)` 创建子进程。
    * **在子进程中:**
        * 关闭不需要的文件描述符，除了 `pipe` 和 `dupdevfd` 以及 `attr.Files` 中指定的文件描述符。它通过读取 `/dev/fd` (Plan 9 中是 `#d`) 来遍历打开的文件描述符。
        * 设置环境变量，通过创建 `/env/` 下的文件来实现。
        * 使用 `SYS_CHDIR` 改变当前工作目录（如果 `attr.Dir` 指定了）。
        * 使用 `SYS_DUP` 将 `attr.Files` 中指定的文件描述符复制到目标位置。
        * 使用 `SYS_EXEC` 执行新的程序。
    * **错误处理:** 如果在子进程中发生错误（例如 `dup` 或 `exec` 失败），会将错误信息写入到管道 `pipe` 中。
    * **重要约束:** 在子进程中，此函数必须避免获取任何锁、调用可能导致重新调度的函数、分配内存或增长栈，因为父进程可能持有锁。

* **`forkExec(argv0 string, argv []string, attr *ProcAttr) (pid int, err error)`:**  `forkAndExecInChild` 的一个更高级的封装。
    * 准备传递给 `forkAndExecInChild` 的参数，例如将 Go 字符串转换为 C 风格的字符串指针。
    * 创建用于父子进程通信的管道。
    * 调用 `forkAndExecInChild` 创建并执行子进程。
    * 从管道中读取子进程的错误信息。
    * 如果子进程执行失败，会等待子进程退出以避免僵尸进程。

* **`startProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, err error)`:**  启动一个新的 goroutine，并将其绑定到操作系统线程。这个 goroutine 负责调用 `forkExec` 并等待子进程结束。
    * 在 Plan 9 上，只有父线程才能等待子进程，而 Go 的 goroutine 可能会在不同的 OS 线程上运行，因此需要创建一个专门的 goroutine来处理等待。
    * 使用 channel `forkc` 将 `forkExec` 的结果传递回调用者。
    * 创建一个 channel `waitc` 用于等待子进程结束。
    * 将子进程的 PID 和 `waitc` 存储在全局的 `procs` map 中。

* **`ForkExec(argv0 string, argv []string, attr *ProcAttr) (pid int, err error)`:**  `startProcess` 的简单包装，是提供给外部使用的创建进程的接口。

* **`StartProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, handle uintptr, err error)`:**  `ForkExec` 的包装，用于兼容 `os` 包的接口。在 Plan 9 上，`handle` 没有实际意义，始终为 0。

* **`Exec(argv0 string, argv []string, envv []string) (err error)`:**  执行一个新的程序，替换当前进程。
    * 如果提供了环境变量 `envv`，则先使用 `SYS_RFORK` 和 `RFCENVG` 清空当前环境变量。
    * 然后，通过在 `/env/` 目录下创建文件来设置新的环境变量。
    * 最后，使用 `SYS_EXEC` 执行新的程序。

* **`WaitProcess(pid int, w *Waitmsg) (err error)`:** 等待指定 PID 的进程结束。
    * 从全局的 `procs` map 中查找与 PID 关联的 channel `waitc`。
    * 从 `waitc` 中接收子进程的退出状态信息。
    * 将子进程的 `Waitmsg` 复制到 `w` 中（如果 `w` 不为 `nil`）。

**3. 数据结构:**

* **`envItem`:**  表示一个环境变量，包含名称指针 `name`、值指针 `value` 和值长度 `nvalue`。

* **`ProcAttr`:** 包含进程启动时的属性，例如当前工作目录 `Dir`、环境变量 `Env`、文件描述符 `Files` 和系统特定的属性 `Sys`。

* **`SysProcAttr`:**  包含特定于操作系统的进程属性，例如 `Rfork` 标志，用于传递给 `rfork` 系统调用。

* **`waitErr`:**  用于在 goroutine 中传递等待结果，包含 `Waitmsg` 和可能的错误 `err`。

* **`procs`:** 一个全局结构体，用于存储正在运行的进程的 PID 和用于等待其结束的 channel。

**它是什么 Go 语言功能的实现：**

这段代码实现了 Go 语言中与进程创建、执行和等待相关的核心功能，特别是 `os/exec` 包的基础。它允许 Go 程序像其他编程语言一样启动新的进程并与之交互。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	// 使用 exec.Command 创建一个命令
	cmd := exec.Command("ls", "-l")

	// 设置一些进程属性（可选）
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// 在 Plan 9 上可以设置 rfork 标志
		Rfork: syscall.RFNAMEG, // 例如，共享名字空间
	}

	// 启动进程
	err := cmd.Start()
	if err != nil {
		fmt.Println("Error starting process:", err)
		return
	}

	fmt.Println("Process started with PID:", cmd.Process.Pid)

	// 等待进程结束
	err = cmd.Wait()
	if err != nil {
		fmt.Println("Error waiting for process:", err)
		return
	}

	fmt.Println("Process finished.")

	// 直接使用 syscall.ForkExec (更底层的方式)
	attr := &syscall.ProcAttr{}
	pid, err := syscall.ForkExec("/bin/ls", []string{"ls", "-a"}, attr)
	if err != nil {
		fmt.Println("Error using ForkExec:", err)
		return
	}
	fmt.Println("Process forked and exec'ed with PID:", pid)

	// 等待使用 syscall.WaitProcess
	var w syscall.Waitmsg
	err = syscall.WaitProcess(pid, &w)
	if err != nil {
		fmt.Println("Error waiting for process using WaitProcess:", err)
		return
	}
	fmt.Println("Process waited for, Waitmsg:", w)
}
```

**假设的输入与输出（针对 `gstringb`）：**

**假设输入:** `b := []byte{0x05, 0x00, 'h', 'e', 'l', 'l', 'o'}` (长度为 5 的 "hello"，小端序长度前缀)

**输出:** `[]byte{'h', 'e', 'l', 'l', 'o'}`

**假设输入:** `b := []byte{0x0a, 0x00, 't', 'o', 'o', ' ', 'l', 'o', 'n', 'g', ' ', 's', 't', 'r'}`，但实际上字符串只有 "too long"

**输出:**  `nil` (因为声明的长度超过了实际剩余的字节数)

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数的解析。命令行参数的处理通常发生在 `main` 函数中，并作为参数传递给 `exec.Command` 或直接传递给 `syscall.ForkExec`。

例如，在使用 `exec.Command("ls", "-l")` 时，`"ls"` 是要执行的程序路径，`"-l"` 是传递给 `ls` 命令的参数。`exec.Command` 会将这些参数转换为 C 风格的字符串数组，最终传递给 `syscall.ForkExec` 或其底层函数。

在 `forkAndExecInChild` 函数中，`argv0 *byte` 指向可执行文件的路径，`argv []*byte` 是指向以 NULL 结尾的参数字符串的指针数组。这些参数是由调用者（例如 `forkExec`）准备好的。

**使用者易犯错的点：**

* **文件描述符管理不当:** 在 `ProcAttr` 的 `Files` 字段中指定错误的文件描述符可能会导致程序崩溃或行为异常。例如，传递一个未打开或已关闭的文件描述符。

  ```go
  // 错误示例：尝试传递一个未打开的文件描述符
  attr := &syscall.ProcAttr{
      Files: []uintptr{0, 1, 100}, // 假设文件描述符 100 没有打开
  }
  _, err := syscall.ForkExec("/bin/ls", []string{"ls"}, attr)
  if err != nil {
      fmt.Println("Error:", err) // 很可能会出现 "bad file descriptor" 错误
  }
  ```

* **忘记等待子进程:** 如果使用 `syscall.ForkExec` 创建了子进程，但没有使用 `syscall.WaitProcess` 或其他等待机制，可能会导致子进程变为僵尸进程，占用系统资源。

  ```go
  // 创建子进程但不等待
  pid, err := syscall.ForkExec("/bin/sleep", []string{"sleep", "10"}, nil)
  if err != nil {
      fmt.Println("Error:", err)
  }
  fmt.Println("Child process started, PID:", pid)
  // ... 主进程继续执行，子进程可能会变成僵尸进程

  // 正确的做法是等待
  var w syscall.Waitmsg
  err = syscall.WaitProcess(pid, &w)
  if err != nil {
      fmt.Println("Error waiting:", err)
  }
  ```

* **环境变量设置错误:** 在 `ProcAttr` 的 `Env` 字段中设置错误的环境变量格式可能会导致子进程无法正确启动或运行。环境变量应该遵循 `key=value` 的格式。

  ```go
  // 错误示例：环境变量格式错误
  attr := &syscall.ProcAttr{
      Env: []string{"PATH /usr/bin"}, // 缺少等号
  }
  _, err := syscall.ForkExec("/bin/ls", []string{"ls"}, attr)
  if err != nil {
      fmt.Println("Error:", err)
  }
  ```

这段代码是 Go 语言在 Plan 9 操作系统上进行底层进程控制的关键部分，理解它的功能有助于深入了解 Go 如何与操作系统进行交互。

Prompt: 
```
这是路径为go/src/syscall/exec_plan9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Fork, exec, wait, etc.

package syscall

import (
	"internal/itoa"
	"runtime"
	"sync"
	"unsafe"
)

// ForkLock is not used on plan9.
var ForkLock sync.RWMutex

// gstringb reads a non-empty string from b, prefixed with a 16-bit length in little-endian order.
// It returns the string as a byte slice, or nil if b is too short to contain the length or
// the full string.
//
//go:nosplit
func gstringb(b []byte) []byte {
	if len(b) < 2 {
		return nil
	}
	n, b := gbit16(b)
	if int(n) > len(b) {
		return nil
	}
	return b[:n]
}

// Offset of the name field in a 9P directory entry - see UnmarshalDir() in dir_plan9.go
const nameOffset = 39

// gdirname returns the first filename from a buffer of directory entries,
// and a slice containing the remaining directory entries.
// If the buffer doesn't start with a valid directory entry, the returned name is nil.
//
//go:nosplit
func gdirname(buf []byte) (name []byte, rest []byte) {
	if len(buf) < 2 {
		return
	}
	size, buf := gbit16(buf)
	if size < STATFIXLEN || int(size) > len(buf) {
		return
	}
	name = gstringb(buf[nameOffset:size])
	rest = buf[size:]
	return
}

// StringSlicePtr converts a slice of strings to a slice of pointers
// to NUL-terminated byte arrays. If any string contains a NUL byte
// this function panics instead of returning an error.
//
// Deprecated: Use SlicePtrFromStrings instead.
func StringSlicePtr(ss []string) []*byte {
	bb := make([]*byte, len(ss)+1)
	for i := 0; i < len(ss); i++ {
		bb[i] = StringBytePtr(ss[i])
	}
	bb[len(ss)] = nil
	return bb
}

// SlicePtrFromStrings converts a slice of strings to a slice of
// pointers to NUL-terminated byte arrays. If any string contains
// a NUL byte, it returns (nil, [EINVAL]).
func SlicePtrFromStrings(ss []string) ([]*byte, error) {
	var err error
	bb := make([]*byte, len(ss)+1)
	for i := 0; i < len(ss); i++ {
		bb[i], err = BytePtrFromString(ss[i])
		if err != nil {
			return nil, err
		}
	}
	bb[len(ss)] = nil
	return bb, nil
}

// readdirnames returns the names of files inside the directory represented by dirfd.
func readdirnames(dirfd int) (names []string, err error) {
	names = make([]string, 0, 100)
	var buf [STATMAX]byte

	for {
		n, e := Read(dirfd, buf[:])
		if e != nil {
			return nil, e
		}
		if n == 0 {
			break
		}
		for b := buf[:n]; len(b) > 0; {
			var s []byte
			s, b = gdirname(b)
			if s == nil {
				return nil, ErrBadStat
			}
			names = append(names, string(s))
		}
	}
	return
}

// name of the directory containing names and control files for all open file descriptors
var dupdev, _ = BytePtrFromString("#d")

// forkAndExecInChild forks the process, calling dup onto 0..len(fd)
// and finally invoking exec(argv0, argvv, envv) in the child.
// If a dup or exec fails, it writes the error string to pipe.
// (The pipe write end is close-on-exec so if exec succeeds, it will be closed.)
//
// In the child, this function must not acquire any locks, because
// they might have been locked at the time of the fork. This means
// no rescheduling, no malloc calls, and no new stack segments.
// The calls to RawSyscall are okay because they are assembly
// functions that do not grow the stack.
//
//go:norace
func forkAndExecInChild(argv0 *byte, argv []*byte, envv []envItem, dir *byte, attr *ProcAttr, pipe int, rflag int) (pid int, err error) {
	// Declare all variables at top in case any
	// declarations require heap allocation (e.g., errbuf).
	var (
		r1       uintptr
		nextfd   int
		i        int
		clearenv int
		envfd    int
		errbuf   [ERRMAX]byte
		statbuf  [STATMAX]byte
		dupdevfd int
		n        int
		b        []byte
	)

	// Guard against side effects of shuffling fds below.
	// Make sure that nextfd is beyond any currently open files so
	// that we can't run the risk of overwriting any of them.
	fd := make([]int, len(attr.Files))
	nextfd = len(attr.Files)
	for i, ufd := range attr.Files {
		if nextfd < int(ufd) {
			nextfd = int(ufd)
		}
		fd[i] = int(ufd)
	}
	nextfd++

	if envv != nil {
		clearenv = RFCENVG
	}

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	r1, _, _ = RawSyscall(SYS_RFORK, uintptr(RFPROC|RFFDG|RFREND|clearenv|rflag), 0, 0)

	if r1 != 0 {
		if int32(r1) == -1 {
			return 0, NewError(errstr())
		}
		// parent; return PID
		return int(r1), nil
	}

	// Fork succeeded, now in child.

	// Close fds we don't need.
	r1, _, _ = RawSyscall(SYS_OPEN, uintptr(unsafe.Pointer(dupdev)), uintptr(O_RDONLY), 0)
	dupdevfd = int(r1)
	if dupdevfd == -1 {
		goto childerror
	}
dirloop:
	for {
		r1, _, _ = RawSyscall6(SYS_PREAD, uintptr(dupdevfd), uintptr(unsafe.Pointer(&statbuf[0])), uintptr(len(statbuf)), ^uintptr(0), ^uintptr(0), 0)
		n = int(r1)
		switch n {
		case -1:
			goto childerror
		case 0:
			break dirloop
		}
		for b = statbuf[:n]; len(b) > 0; {
			var s []byte
			s, b = gdirname(b)
			if s == nil {
				copy(errbuf[:], ErrBadStat.Error())
				goto childerror1
			}
			if s[len(s)-1] == 'l' {
				// control file for descriptor <N> is named <N>ctl
				continue
			}
			closeFdExcept(int(atoi(s)), pipe, dupdevfd, fd)
		}
	}
	RawSyscall(SYS_CLOSE, uintptr(dupdevfd), 0, 0)

	// Write new environment variables.
	if envv != nil {
		for i = 0; i < len(envv); i++ {
			r1, _, _ = RawSyscall(SYS_CREATE, uintptr(unsafe.Pointer(envv[i].name)), uintptr(O_WRONLY), uintptr(0666))

			if int32(r1) == -1 {
				goto childerror
			}

			envfd = int(r1)

			r1, _, _ = RawSyscall6(SYS_PWRITE, uintptr(envfd), uintptr(unsafe.Pointer(envv[i].value)), uintptr(envv[i].nvalue),
				^uintptr(0), ^uintptr(0), 0)

			if int32(r1) == -1 || int(r1) != envv[i].nvalue {
				goto childerror
			}

			r1, _, _ = RawSyscall(SYS_CLOSE, uintptr(envfd), 0, 0)

			if int32(r1) == -1 {
				goto childerror
			}
		}
	}

	// Chdir
	if dir != nil {
		r1, _, _ = RawSyscall(SYS_CHDIR, uintptr(unsafe.Pointer(dir)), 0, 0)
		if int32(r1) == -1 {
			goto childerror
		}
	}

	// Pass 1: look for fd[i] < i and move those up above len(fd)
	// so that pass 2 won't stomp on an fd it needs later.
	if pipe < nextfd {
		r1, _, _ = RawSyscall(SYS_DUP, uintptr(pipe), uintptr(nextfd), 0)
		if int32(r1) == -1 {
			goto childerror
		}
		pipe = nextfd
		nextfd++
	}
	for i = 0; i < len(fd); i++ {
		if fd[i] >= 0 && fd[i] < i {
			if nextfd == pipe { // don't stomp on pipe
				nextfd++
			}
			r1, _, _ = RawSyscall(SYS_DUP, uintptr(fd[i]), uintptr(nextfd), 0)
			if int32(r1) == -1 {
				goto childerror
			}

			fd[i] = nextfd
			nextfd++
		}
	}

	// Pass 2: dup fd[i] down onto i.
	for i = 0; i < len(fd); i++ {
		if fd[i] == -1 {
			RawSyscall(SYS_CLOSE, uintptr(i), 0, 0)
			continue
		}
		if fd[i] == i {
			continue
		}
		r1, _, _ = RawSyscall(SYS_DUP, uintptr(fd[i]), uintptr(i), 0)
		if int32(r1) == -1 {
			goto childerror
		}
	}

	// Pass 3: close fd[i] if it was moved in the previous pass.
	for i = 0; i < len(fd); i++ {
		if fd[i] >= len(fd) {
			RawSyscall(SYS_CLOSE, uintptr(fd[i]), 0, 0)
		}
	}

	// Time to exec.
	r1, _, _ = RawSyscall(SYS_EXEC,
		uintptr(unsafe.Pointer(argv0)),
		uintptr(unsafe.Pointer(&argv[0])), 0)

childerror:
	// send error string on pipe
	RawSyscall(SYS_ERRSTR, uintptr(unsafe.Pointer(&errbuf[0])), uintptr(len(errbuf)), 0)
childerror1:
	errbuf[len(errbuf)-1] = 0
	i = 0
	for i < len(errbuf) && errbuf[i] != 0 {
		i++
	}

	RawSyscall6(SYS_PWRITE, uintptr(pipe), uintptr(unsafe.Pointer(&errbuf[0])), uintptr(i),
		^uintptr(0), ^uintptr(0), 0)

	for {
		RawSyscall(SYS_EXITS, 0, 0, 0)
	}
}

// close the numbered file descriptor, unless it is fd1, fd2, or a member of fds.
//
//go:nosplit
func closeFdExcept(n int, fd1 int, fd2 int, fds []int) {
	if n == fd1 || n == fd2 {
		return
	}
	for _, fd := range fds {
		if n == fd {
			return
		}
	}
	RawSyscall(SYS_CLOSE, uintptr(n), 0, 0)
}

func cexecPipe(p []int) error {
	e := Pipe(p)
	if e != nil {
		return e
	}

	fd, e := Open("#d/"+itoa.Itoa(p[1]), O_RDWR|O_CLOEXEC)
	if e != nil {
		Close(p[0])
		Close(p[1])
		return e
	}

	Close(p[1])
	p[1] = fd
	return nil
}

type envItem struct {
	name   *byte
	value  *byte
	nvalue int
}

type ProcAttr struct {
	Dir   string    // Current working directory.
	Env   []string  // Environment.
	Files []uintptr // File descriptors.
	Sys   *SysProcAttr
}

type SysProcAttr struct {
	Rfork int // additional flags to pass to rfork
}

var zeroProcAttr ProcAttr
var zeroSysProcAttr SysProcAttr

func forkExec(argv0 string, argv []string, attr *ProcAttr) (pid int, err error) {
	var (
		p      [2]int
		n      int
		errbuf [ERRMAX]byte
		wmsg   Waitmsg
	)

	if attr == nil {
		attr = &zeroProcAttr
	}
	sys := attr.Sys
	if sys == nil {
		sys = &zeroSysProcAttr
	}

	p[0] = -1
	p[1] = -1

	// Convert args to C form.
	argv0p, err := BytePtrFromString(argv0)
	if err != nil {
		return 0, err
	}
	argvp, err := SlicePtrFromStrings(argv)
	if err != nil {
		return 0, err
	}

	destDir := attr.Dir
	if destDir == "" {
		wdmu.Lock()
		destDir = wdStr
		wdmu.Unlock()
	}
	var dir *byte
	if destDir != "" {
		dir, err = BytePtrFromString(destDir)
		if err != nil {
			return 0, err
		}
	}
	var envvParsed []envItem
	if attr.Env != nil {
		envvParsed = make([]envItem, 0, len(attr.Env))
		for _, v := range attr.Env {
			i := 0
			for i < len(v) && v[i] != '=' {
				i++
			}

			envname, err := BytePtrFromString("/env/" + v[:i])
			if err != nil {
				return 0, err
			}
			envvalue := make([]byte, len(v)-i)
			copy(envvalue, v[i+1:])
			envvParsed = append(envvParsed, envItem{envname, &envvalue[0], len(v) - i})
		}
	}

	// Allocate child status pipe close on exec.
	e := cexecPipe(p[:])

	if e != nil {
		return 0, e
	}

	// Kick off child.
	pid, err = forkAndExecInChild(argv0p, argvp, envvParsed, dir, attr, p[1], sys.Rfork)

	if err != nil {
		if p[0] >= 0 {
			Close(p[0])
			Close(p[1])
		}
		return 0, err
	}

	// Read child error status from pipe.
	Close(p[1])
	n, err = Read(p[0], errbuf[:])
	Close(p[0])

	if err != nil || n != 0 {
		if n > 0 {
			err = NewError(string(errbuf[:n]))
		} else if err == nil {
			err = NewError("failed to read exec status")
		}

		// Child failed; wait for it to exit, to make sure
		// the zombies don't accumulate.
		for wmsg.Pid != pid {
			Await(&wmsg)
		}
		return 0, err
	}

	// Read got EOF, so pipe closed on exec, so exec succeeded.
	return pid, nil
}

type waitErr struct {
	Waitmsg
	err error
}

var procs struct {
	sync.Mutex
	waits map[int]chan *waitErr
}

// startProcess starts a new goroutine, tied to the OS
// thread, which runs the process and subsequently waits
// for it to finish, communicating the process stats back
// to any goroutines that may have been waiting on it.
//
// Such a dedicated goroutine is needed because on
// Plan 9, only the parent thread can wait for a child,
// whereas goroutines tend to jump OS threads (e.g.,
// between starting a process and running Wait(), the
// goroutine may have been rescheduled).
func startProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, err error) {
	type forkRet struct {
		pid int
		err error
	}

	forkc := make(chan forkRet, 1)
	go func() {
		runtime.LockOSThread()
		var ret forkRet

		ret.pid, ret.err = forkExec(argv0, argv, attr)
		// If fork fails there is nothing to wait for.
		if ret.err != nil || ret.pid == 0 {
			forkc <- ret
			return
		}

		waitc := make(chan *waitErr, 1)

		// Mark that the process is running.
		procs.Lock()
		if procs.waits == nil {
			procs.waits = make(map[int]chan *waitErr)
		}
		procs.waits[ret.pid] = waitc
		procs.Unlock()

		forkc <- ret

		var w waitErr
		for w.err == nil && w.Pid != ret.pid {
			w.err = Await(&w.Waitmsg)
		}
		waitc <- &w
		close(waitc)
	}()
	ret := <-forkc
	return ret.pid, ret.err
}

// Combination of fork and exec, careful to be thread safe.
func ForkExec(argv0 string, argv []string, attr *ProcAttr) (pid int, err error) {
	return startProcess(argv0, argv, attr)
}

// StartProcess wraps [ForkExec] for package os.
func StartProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, handle uintptr, err error) {
	pid, err = startProcess(argv0, argv, attr)
	return pid, 0, err
}

// Ordinary exec.
func Exec(argv0 string, argv []string, envv []string) (err error) {
	if envv != nil {
		r1, _, _ := RawSyscall(SYS_RFORK, RFCENVG, 0, 0)
		if int32(r1) == -1 {
			return NewError(errstr())
		}

		for _, v := range envv {
			i := 0
			for i < len(v) && v[i] != '=' {
				i++
			}

			fd, e := Create("/env/"+v[:i], O_WRONLY, 0666)
			if e != nil {
				return e
			}

			_, e = Write(fd, []byte(v[i+1:]))
			if e != nil {
				Close(fd)
				return e
			}
			Close(fd)
		}
	}

	argv0p, err := BytePtrFromString(argv0)
	if err != nil {
		return err
	}
	argvp, err := SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	_, _, e1 := Syscall(SYS_EXEC,
		uintptr(unsafe.Pointer(argv0p)),
		uintptr(unsafe.Pointer(&argvp[0])),
		0)

	return e1
}

// WaitProcess waits until the pid of a
// running process is found in the queue of
// wait messages. It is used in conjunction
// with [ForkExec]/[StartProcess] to wait for a
// running process to exit.
func WaitProcess(pid int, w *Waitmsg) (err error) {
	procs.Lock()
	ch := procs.waits[pid]
	procs.Unlock()

	var wmsg *waitErr
	if ch != nil {
		wmsg = <-ch
		procs.Lock()
		if procs.waits[pid] == ch {
			delete(procs.waits, pid)
		}
		procs.Unlock()
	}
	if wmsg == nil {
		// ch was missing or ch is closed
		return NewError("process not found")
	}
	if wmsg.err != nil {
		return wmsg.err
	}
	if w != nil {
		*w = wmsg.Waitmsg
	}
	return nil
}

"""



```