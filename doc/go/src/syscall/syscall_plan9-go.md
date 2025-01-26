Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The first line, "// Plan 9 system calls," is a massive clue. This file is about interacting with the Plan 9 operating system at a low level. The `package syscall` further reinforces this.

2. **Examine Imports:** The `import` statements tell us about dependencies. `errors`, `internal/oserror`, `runtime`, and `unsafe` point towards error handling, OS-specific error types, runtime interactions (like locking), and direct memory manipulation respectively. This signals a system-level focus.

3. **Analyze Constants and Types:**
    * `ImplementsGetwd = true`:  This immediately suggests that `syscall` package in Go for Plan 9 provides a `Getwd` function (getting the current working directory).
    * `bitSize16 = 2`: This constant is used later in `Mkdir`, likely related to the size of the stat buffer. It's platform-specific.
    * `ErrorString`: This custom type implementing the `error` interface is a crucial part of how Plan 9 syscall errors are represented in Go. The `Is` method implementing `errors.Is` is important for error checking.
    * `Note`:  This type represents process notes, a Plan 9 concept similar to signals.
    * `Stdin`, `Stdout`, `Stderr`: Standard file descriptors.

4. **System Call Declarations:** The lines starting with `func Syscall(...)`, `func Syscall6(...)`, `func RawSyscall(...)`, and `func RawSyscall6(...)` are the fundamental building blocks. The names and argument types (`uintptr`) strongly indicate these are direct interfaces to the operating system's system calls. The `//sys` comments are markers for a code generation tool (`mksyscall`).

5. **Helper Functions:**  Look for functions that abstract or simplify common tasks:
    * `atoi`: Converts byte slices to unsigned integers.
    * `cstring`: Converts a null-terminated byte slice to a string.
    * `errstr`: Retrieves the last system error string.
    * `readnum`: Reads a number from a file (used for getting PID and PPID).
    * `Getpid`, `Getppid`:  Convenience functions leveraging `readnum`.
    * `Read`, `Write`:  Wrappers around `Pread` and `Pwrite`, likely for simplified usage.
    * `Fd2path`: Converts a file descriptor to a path.
    * `Pipe`: Creates a pipe.
    * `Seek`: Seeks within a file.
    * `Mkdir`: Creates a directory, with a workaround for a potential Plan 9 quirk.
    * `Await`: Waits for a process to change state.
    * `Unmount`: Unmounts a file system.
    * `Fchdir`: Changes the current working directory using a file descriptor.
    * Time-related functions (`Timespec`, `Timeval`, `NsecToTimeval`, `nsec`, `Gettimeofday`): Handle time conversions and getting the current time.
    * Placeholder getters for user and group IDs (returning -1, indicating they aren't directly applicable in Plan 9's user model).
    * `Open`, `Create`, `Remove`, `Stat`, `Bind`, `Mount`, `Wstat`, `Chdir`, `Dup`, `Pread`, `Pwrite`, `Close`, `Fstat`, `Fwstat`: These are direct system call wrappers (indicated by the `//sys` comments). They likely correspond directly to Plan 9 system calls.

6. **Error Handling:** The `ErrorString` type and the `checkErrMessageContent` function highlight a specific approach to error checking on Plan 9, relying on string comparisons of error messages. The `Temporary()` and `Timeout()` methods further categorize errors.

7. **Plan 9 Specifics:** Pay attention to code that seems unique to Plan 9:
    * The `Note` type.
    * The handling of paths starting with `#` (as seen in `readnum`).
    * The workaround in `Mkdir`.
    * The format of the `Waitmsg`.
    * The use of `bind` and `mount` system calls.

8. **Code Generation (`//sys`):** Recognize that the `//sys` lines are not just comments; they are instructions for a tool that generates the actual low-level syscall implementations. This separation is common in system-level programming.

9. **Infer Functionality and Examples:** Based on the function names and the context of interacting with Plan 9, start inferring the purpose of each function and constructing examples. For example, `Open` likely opens a file, `Read` reads from it, `Write` writes to it, etc. Consider the input and output types to formulate plausible scenarios.

10. **Identify Potential Pitfalls:**  Think about common errors developers might make when using these functions. For example, incorrect error checking due to the custom `ErrorString` type, or misunderstanding Plan 9's path conventions.

11. **Structure the Answer:** Organize the findings logically. Start with a high-level overview, then detail the functionality, provide examples, explain command-line argument handling (if applicable, which it isn't heavily in this case), and finally point out potential mistakes.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe some functions directly map to POSIX equivalents. **Correction:** While some concepts are similar (like `open`, `read`, `write`), the underlying system calls and error handling are Plan 9 specific. Focus on those differences.
* **Wondering about command-line arguments:**  Scan the code for any parsing of `os.Args` or similar. **Correction:** This file primarily deals with system calls, not command-line argument handling at the application level.
* **Thinking about error handling:**  Notice the `ErrorString` and its `Is` method. **Correction:** Emphasize this custom error handling mechanism as a key feature and a potential point of confusion for developers used to standard Go error comparisons.

By following this systematic approach, combining code analysis with knowledge of operating system concepts (specifically Plan 9 in this case), and constantly refining interpretations, we can arrive at a comprehensive understanding of the provided code snippet.
这段代码是 Go 语言 `syscall` 包中针对 Plan 9 操作系统的实现部分。它提供了一系列用于与 Plan 9 内核进行交互的底层系统调用接口和辅助函数。

**主要功能列举:**

1. **系统调用接口:** 定义了与 Plan 9 系统调用对应的 Go 函数，例如 `Syscall`, `Syscall6`, `RawSyscall`, `RawSyscall6`。这些函数允许 Go 程序直接调用底层的 Plan 9 系统调用。

2. **错误处理:**
   - 定义了 `ErrorString` 类型，用于表示系统调用返回的错误。
   - 提供了 `NewError` 函数将字符串转换为 `ErrorString`。
   - 实现了 `ErrorString` 的 `Error()`, `Is()`, `Temporary()`, `Timeout()` 方法，用于错误信息的获取、判断和分类。
   - `checkErrMessageContent` 和 `contains` 函数用于检查错误信息中是否包含特定的字符串，用于更细粒度的错误判断。

3. **文件和目录操作:**
   - 提供了 `Open`, `Create`, `Remove`, `Stat`, `Wstat`, `Fstat`, `Fwstat`, `Mkdir`, `Chdir`, `Fchdir` 等函数，用于进行文件和目录的打开、创建、删除、状态查询、修改、创建目录、改变当前工作目录等操作。

4. **进程管理:**
   - 提供了 `Getpid`, `Getppid`, `Await` 等函数，用于获取进程 ID、父进程 ID，以及等待子进程状态变化。

5. **管道和文件描述符操作:**
   - 提供了 `Pipe`, `Dup`, `Close` 等函数，用于创建管道、复制文件描述符、关闭文件描述符。
   - `Fd2path` 函数可以将文件描述符转换为对应的路径。

6. **文件读写操作:**
   - 提供了 `Read`, `Write`, `Pread`, `Pwrite` 等函数，用于进行文件的读写操作，包括指定偏移量的读写。

7. **挂载和卸载:**
   - 提供了 `Bind`, `Mount`, `Unmount` 等函数，用于进行文件系统的绑定、挂载和卸载操作。

8. **时间相关:**
   - 提供了 `Timespec`, `Timeval` 结构体，以及 `NsecToTimeval`, `nsec`, `Gettimeofday` 等函数，用于处理时间和获取当前时间。

9. **其他:**
   - 定义了 `Note` 类型，用于表示进程 note (类似于信号)。
   - 定义了 `Stdin`, `Stdout`, `Stderr` 常量，表示标准输入、输出和错误的文件描述符。
   - 提供了 `Seek` 函数，用于设置文件读写偏移量。
   - 提供了 `cstring` 函数，用于将 byte 数组转换为以 null 结尾的 C 字符串。
   - 提供了 `errstr` 函数，用于获取 Plan 9 的错误字符串。
   - 提供了 `readnum` 函数，用于从文件中读取数字。

**推理 Go 语言功能的实现并举例:**

这个文件是 `syscall` 包的一部分，它实现了 Go 语言中与操作系统交互的基础功能。例如，`os` 包中的很多文件和进程操作最终会调用到 `syscall` 包中的这些函数。

**示例 1: 读取文件内容**

假设我们想读取 `/etc/passwd` 文件的内容。以下 Go 代码会使用到 `syscall` 包中的函数：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	path := "/etc/passwd"
	fd, err := syscall.Open(path, syscall.O_RDONLY)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd)

	buf := make([]byte, 1024)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Printf("Read %d bytes:\n%s", n, string(buf[:n]))
}
```

**假设的输入与输出:**

* **假设输入:** 系统中存在 `/etc/passwd` 文件，并且用户有读取权限。
* **预期输出:**  程序会打印出 `/etc/passwd` 文件的内容，以及读取的字节数。例如：

```
Read 409 bytes:
root::0:0:System Administrator,:/sbin/sh
daemon:*:1:1::/:
... (更多 passwd 文件内容)
```

**代码推理:**

1. `syscall.Open(path, syscall.O_RDONLY)`:  调用 `syscall` 包中的 `Open` 函数打开 `/etc/passwd` 文件，`syscall.O_RDONLY` 表示以只读模式打开。这个函数最终会调用 Plan 9 的 `open` 系统调用。
2. `syscall.Read(fd, buf)`: 调用 `syscall` 包中的 `Read` 函数从文件描述符 `fd` 中读取数据到 `buf` 中。这个函数最终会调用 Plan 9 的 `read` 系统调用 (实际上在 Plan 9 中对应的是 `pread`，因为 `Read` 内部调用了 `Pread`，偏移量为 -1)。
3. `syscall.Close(fd)`: 调用 `syscall` 包中的 `Close` 函数关闭文件描述符。这个函数最终会调用 Plan 9 的 `close` 系统调用。

**示例 2: 创建目录**

假设我们想创建一个名为 `testdir` 的目录。

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	path := "testdir"
	mode := uint32(0777) // 假设权限为 777
	err := syscall.Mkdir(path, mode)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	fmt.Println("Directory created successfully.")
}
```

**假设的输入与输出:**

* **假设输入:** 当前目录下不存在名为 `testdir` 的文件或目录。
* **预期输出:** 程序会在当前目录下创建一个名为 `testdir` 的目录，并打印 "Directory created successfully."

**代码推理:**

1. `syscall.Mkdir(path, mode)`: 调用 `syscall` 包中的 `Mkdir` 函数创建目录。`mode` 参数指定了目录的权限。这个函数内部会进行一些检查，然后调用 Plan 9 的 `create` 系统调用，并设置 `DMDIR` 标志来创建目录。

**命令行参数处理:**

这段代码本身没有直接处理命令行参数的逻辑。 命令行参数的处理通常在 `main` 函数中使用 `os.Args` 切片来实现，然后可能会调用 `syscall` 包中的函数来执行与命令行参数相关的操作。例如，一个程序接收一个文件名作为参数，然后使用 `syscall.Open` 打开该文件。

**使用者易犯错的点:**

1. **错误处理不当:** `syscall` 包返回的错误通常是 `syscall.ErrorString` 类型。使用者需要正确地检查和处理这些错误。直接与字符串进行比较可能不够健壮，应该使用 `errors.Is` 或检查特定的错误码（如果适用）。例如：

   ```go
   _, err := syscall.Open("nonexistent_file", syscall.O_RDONLY)
   if err != nil {
       // 错误的错误处理方式
       if err.Error() == "file does not exist" {
           fmt.Println("File not found")
       }

       // 推荐的错误处理方式 (假设 syscall.ErrNotExist 存在，但实际上这段代码里通过字符串匹配实现)
       // if errors.Is(err, syscall.ErrNotExist) {
       //     fmt.Println("File not found")
       // }
   }
   ```
   在提供的代码中，错误判断依赖于检查错误字符串是否包含特定内容，例如 "does not exist"。虽然 `ErrorString` 实现了 `Is` 方法，但它内部也是通过字符串匹配来实现的。使用者需要注意这种特定的错误判断方式。

2. **权限问题:**  进行文件或目录操作时，可能会遇到权限不足的错误。使用者需要确保程序有足够的权限执行相应的操作。

3. **文件描述符管理:**  打开文件或创建管道后，需要及时关闭文件描述符，避免资源泄漏。

4. **理解 Plan 9 的特性:** Plan 9 在文件系统、进程模型等方面与传统的 Unix-like 系统有所不同。使用者需要了解这些差异，才能正确使用 `syscall` 包中的函数。例如，Plan 9 的挂载和绑定机制与 Linux 等系统有所不同。

总而言之，`go/src/syscall/syscall_plan9.go` 文件是 Go 语言与 Plan 9 操作系统交互的桥梁，它提供了底层的系统调用接口，使得 Go 程序能够在 Plan 9 上执行文件操作、进程管理等各种系统级任务。使用者需要仔细理解这些接口的功能和限制，并进行适当的错误处理。

Prompt: 
```
这是路径为go/src/syscall/syscall_plan9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Plan 9 system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and
// wrap it in our own nicer implementation.

package syscall

import (
	"errors"
	"internal/oserror"
	"runtime"
	"unsafe"
)

const ImplementsGetwd = true
const bitSize16 = 2

// ErrorString implements Error's String method by returning itself.
//
// ErrorString values can be tested against error values using [errors.Is].
// For example:
//
//	_, _, err := syscall.Syscall(...)
//	if errors.Is(err, fs.ErrNotExist) ...
type ErrorString string

func (e ErrorString) Error() string { return string(e) }

// NewError converts s to an ErrorString, which satisfies the Error interface.
func NewError(s string) error { return ErrorString(s) }

func (e ErrorString) Is(target error) bool {
	switch target {
	case oserror.ErrPermission:
		return checkErrMessageContent(e, "permission denied")
	case oserror.ErrExist:
		return checkErrMessageContent(e, "exists", "is a directory")
	case oserror.ErrNotExist:
		return checkErrMessageContent(e, "does not exist", "not found",
			"has been removed", "no parent")
	case errors.ErrUnsupported:
		return checkErrMessageContent(e, "not supported")
	}
	return false
}

// checkErrMessageContent checks if err message contains one of msgs.
func checkErrMessageContent(e ErrorString, msgs ...string) bool {
	for _, msg := range msgs {
		if contains(string(e), msg) {
			return true
		}
	}
	return false
}

// contains is a local version of strings.Contains. It knows len(sep) > 1.
func contains(s, sep string) bool {
	n := len(sep)
	c := sep[0]
	for i := 0; i+n <= len(s); i++ {
		if s[i] == c && s[i:i+n] == sep {
			return true
		}
	}
	return false
}

func (e ErrorString) Temporary() bool {
	return e == EINTR || e == EMFILE || e.Timeout()
}

func (e ErrorString) Timeout() bool {
	return e == EBUSY || e == ETIMEDOUT
}

var emptystring string

// A Note is a string describing a process note.
// It implements the os.Signal interface.
type Note string

func (n Note) Signal() {}

func (n Note) String() string {
	return string(n)
}

var (
	Stdin  = 0
	Stdout = 1
	Stderr = 2
)

// For testing: clients can set this flag to force
// creation of IPv6 sockets to return [EAFNOSUPPORT].
var SocketDisableIPv6 bool

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err ErrorString)
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err ErrorString)
func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2, err uintptr)
func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr)

//go:nosplit
func atoi(b []byte) (n uint) {
	n = 0
	for i := 0; i < len(b); i++ {
		n = n*10 + uint(b[i]-'0')
	}
	return
}

func cstring(s []byte) string {
	for i := range s {
		if s[i] == 0 {
			return string(s[0:i])
		}
	}
	return string(s)
}

func errstr() string {
	var buf [ERRMAX]byte

	RawSyscall(SYS_ERRSTR, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)

	buf[len(buf)-1] = 0
	return cstring(buf[:])
}

func readnum(path string) (uint, error) {
	var b [12]byte

	fd, e := Open(path, O_RDONLY)
	if e != nil {
		return 0, e
	}
	defer Close(fd)

	n, e := Pread(fd, b[:], 0)

	if e != nil {
		return 0, e
	}

	m := 0
	for ; m < n && b[m] == ' '; m++ {
	}

	return atoi(b[m : n-1]), nil
}

func Getpid() (pid int) {
	n, _ := readnum("#c/pid")
	return int(n)
}

func Getppid() (ppid int) {
	n, _ := readnum("#c/ppid")
	return int(n)
}

func Read(fd int, p []byte) (n int, err error) {
	return Pread(fd, p, -1)
}

func Write(fd int, p []byte) (n int, err error) {
	if faketime && (fd == 1 || fd == 2) {
		n = faketimeWrite(fd, p)
		if n < 0 {
			return 0, ErrorString("error")
		}
		return n, nil
	}

	return Pwrite(fd, p, -1)
}

var ioSync int64

//sys	fd2path(fd int, buf []byte) (err error)

func Fd2path(fd int) (path string, err error) {
	var buf [512]byte

	e := fd2path(fd, buf[:])
	if e != nil {
		return "", e
	}
	return cstring(buf[:]), nil
}

//sys	pipe(p *[2]int32) (err error)

func Pipe(p []int) (err error) {
	if len(p) != 2 {
		return NewError("bad arg in system call")
	}
	var pp [2]int32
	err = pipe(&pp)
	if err == nil {
		p[0] = int(pp[0])
		p[1] = int(pp[1])
	}
	return
}

// Underlying system call writes to newoffset via pointer.
// Implemented in assembly to avoid allocation.
func seek(placeholder uintptr, fd int, offset int64, whence int) (newoffset int64, err string)

func Seek(fd int, offset int64, whence int) (newoffset int64, err error) {
	newoffset, e := seek(0, fd, offset, whence)

	if newoffset == -1 {
		err = NewError(e)
	}
	return
}

func Mkdir(path string, mode uint32) (err error) {
	// If path exists and is not a directory, Create will fail silently.
	// Work around this by rejecting Mkdir if path exists.
	statbuf := make([]byte, bitSize16)
	// Remove any trailing slashes from path, otherwise the Stat will
	// fail with ENOTDIR.
	n := len(path)
	for n > 1 && path[n-1] == '/' {
		n--
	}
	_, err = Stat(path[0:n], statbuf)
	if err == nil {
		return EEXIST
	}

	fd, err := Create(path, O_RDONLY, DMDIR|mode)

	if fd != -1 {
		Close(fd)
	}

	return
}

type Waitmsg struct {
	Pid  int
	Time [3]uint32
	Msg  string
}

func (w Waitmsg) Exited() bool   { return true }
func (w Waitmsg) Signaled() bool { return false }

func (w Waitmsg) ExitStatus() int {
	if len(w.Msg) == 0 {
		// a normal exit returns no message
		return 0
	}
	return 1
}

//sys	await(s []byte) (n int, err error)

func Await(w *Waitmsg) (err error) {
	var buf [512]byte
	var f [5][]byte

	n, err := await(buf[:])

	if err != nil || w == nil {
		return
	}

	nf := 0
	p := 0
	for i := 0; i < n && nf < len(f)-1; i++ {
		if buf[i] == ' ' {
			f[nf] = buf[p:i]
			p = i + 1
			nf++
		}
	}
	f[nf] = buf[p:]
	nf++

	if nf != len(f) {
		return NewError("invalid wait message")
	}
	w.Pid = int(atoi(f[0]))
	w.Time[0] = uint32(atoi(f[1]))
	w.Time[1] = uint32(atoi(f[2]))
	w.Time[2] = uint32(atoi(f[3]))
	w.Msg = cstring(f[4])
	if w.Msg == "''" {
		// await() returns '' for no error
		w.Msg = ""
	}
	return
}

func Unmount(name, old string) (err error) {
	if fixwd(name, old) {
		defer runtime.UnlockOSThread()
	}
	oldp, err := BytePtrFromString(old)
	if err != nil {
		return err
	}
	oldptr := uintptr(unsafe.Pointer(oldp))

	var r0 uintptr
	var e ErrorString

	// bind(2) man page: If name is zero, everything bound or mounted upon old is unbound or unmounted.
	if name == "" {
		r0, _, e = Syscall(SYS_UNMOUNT, _zero, oldptr, 0)
	} else {
		namep, err := BytePtrFromString(name)
		if err != nil {
			return err
		}
		r0, _, e = Syscall(SYS_UNMOUNT, uintptr(unsafe.Pointer(namep)), oldptr, 0)
	}

	if int32(r0) == -1 {
		err = e
	}
	return
}

func Fchdir(fd int) (err error) {
	path, err := Fd2path(fd)

	if err != nil {
		return
	}

	return Chdir(path)
}

type Timespec struct {
	Sec  int32
	Nsec int32
}

type Timeval struct {
	Sec  int32
	Usec int32
}

func NsecToTimeval(nsec int64) (tv Timeval) {
	nsec += 999 // round up to microsecond
	tv.Usec = int32(nsec % 1e9 / 1e3)
	tv.Sec = int32(nsec / 1e9)
	return
}

func nsec() int64 {
	var scratch int64

	r0, _, _ := Syscall(SYS_NSEC, uintptr(unsafe.Pointer(&scratch)), 0, 0)
	// TODO(aram): remove hack after I fix _nsec in the pc64 kernel.
	if r0 == 0 {
		return scratch
	}
	return int64(r0)
}

func Gettimeofday(tv *Timeval) error {
	nsec := nsec()
	*tv = NsecToTimeval(nsec)
	return nil
}

func Getegid() (egid int) { return -1 }
func Geteuid() (euid int) { return -1 }
func Getgid() (gid int)   { return -1 }
func Getuid() (uid int)   { return -1 }

func Getgroups() (gids []int, err error) {
	return make([]int, 0), nil
}

//sys	open(path string, mode int) (fd int, err error)

func Open(path string, mode int) (fd int, err error) {
	if fixwd(path) {
		defer runtime.UnlockOSThread()
	}
	return open(path, mode)
}

//sys	create(path string, mode int, perm uint32) (fd int, err error)

func Create(path string, mode int, perm uint32) (fd int, err error) {
	if fixwd(path) {
		defer runtime.UnlockOSThread()
	}
	return create(path, mode, perm)
}

//sys	remove(path string) (err error)

func Remove(path string) error {
	if fixwd(path) {
		defer runtime.UnlockOSThread()
	}
	return remove(path)
}

//sys	stat(path string, edir []byte) (n int, err error)

func Stat(path string, edir []byte) (n int, err error) {
	if fixwd(path) {
		defer runtime.UnlockOSThread()
	}
	return stat(path, edir)
}

//sys	bind(name string, old string, flag int) (err error)

func Bind(name string, old string, flag int) (err error) {
	if fixwd(name, old) {
		defer runtime.UnlockOSThread()
	}
	return bind(name, old, flag)
}

//sys	mount(fd int, afd int, old string, flag int, aname string) (err error)

func Mount(fd int, afd int, old string, flag int, aname string) (err error) {
	if fixwd(old) {
		defer runtime.UnlockOSThread()
	}
	return mount(fd, afd, old, flag, aname)
}

//sys	wstat(path string, edir []byte) (err error)

func Wstat(path string, edir []byte) (err error) {
	if fixwd(path) {
		defer runtime.UnlockOSThread()
	}
	return wstat(path, edir)
}

//sys	chdir(path string) (err error)
//sys	Dup(oldfd int, newfd int) (fd int, err error)
//sys	Pread(fd int, p []byte, offset int64) (n int, err error)
//sys	Pwrite(fd int, p []byte, offset int64) (n int, err error)
//sys	Close(fd int) (err error)
//sys	Fstat(fd int, edir []byte) (n int, err error)
//sys	Fwstat(fd int, edir []byte) (err error)

"""



```