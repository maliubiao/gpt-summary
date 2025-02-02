Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code and identify key Go language elements. I see:

* `package unix`:  This immediately tells me it's interacting with the underlying operating system.
* `const`:  This signifies constants are being defined.
* Capitalized names like `O_RDONLY`, `TIOCGETA`, `EACCES`, `SIGABRT`:  These strongly suggest they are representing system-level constants, likely related to system calls, file I/O, terminal I/O control, errors, and signals.
* `syscall.Errno` and `syscall.Signal`:  This confirms the constants are related to the `syscall` package, which provides a low-level interface to the operating system.
* `var errorList`: A slice of structs containing error numbers, names, and descriptions.
* `var signalList`: A slice of structs containing signal numbers, names, and descriptions.

**2. Deduction of Purpose (High-Level):**

Based on the keywords and naming conventions, I can deduce that this file is defining constants related to system calls, errors, and signals specifically for OpenBSD on the AMD64 architecture. The `zerrors_openbsd_amd64.go` naming convention is a strong hint that it's autogenerated or specifically tailored for this platform. The `zerrors` part likely implies it's related to error and potentially signal definitions.

**3. Inferring Go Language Feature:**

The core Go feature being demonstrated here is **defining constants**. Specifically, it's using Go constants to represent operating system-level concepts. This allows Go programs to interact with the OS in a platform-specific way while maintaining some level of abstraction through the `syscall` package.

**4. Generating a Go Code Example:**

To illustrate how these constants are used, I need to create a simple example that interacts with the operating system. The most straightforward examples are related to file I/O and error handling.

* **File I/O:**  Opening a file is a classic system call. The constants like `O_RDONLY`, `O_WRONLY`, `O_CREAT`, etc., are directly used with the `os.OpenFile` function (which internally uses the `syscall` package). I'd include examples of opening for reading and writing.

* **Error Handling:** The error constants (`EACCES`, `ENOENT`, etc.) are returned by system calls. The `errors.Is` function is the idiomatic way to check for specific errors. I'd show how to check if a file open operation failed due to "permission denied" or "no such file or directory."

* **Signals (Less Common in Simple Examples):**  While signal handling exists in Go, it's less common in basic scenarios. For brevity and clarity, focusing on file I/O and errors is more effective for a concise example. I'd acknowledge signals are present but not delve into complex signal handling examples in this initial demonstration.

**5. Considering Command-Line Arguments:**

The provided code snippet doesn't directly handle command-line arguments. The constants are *used by* functions that might be involved in processing command-line arguments, but the snippet itself is purely declarative. Therefore, the correct answer is to state that command-line argument processing isn't directly handled in this file.

**6. Identifying Potential User Errors:**

The most likely error users might make is **incorrectly comparing errors**.

* **Direct Comparison:**  New Go programmers might try to compare errors directly using `err == syscall.EACCES`. This is generally discouraged because errors can be wrapped, and the underlying error might be hidden.

* **Correct Approach:** The `errors.Is` function should be highlighted as the correct way to check for specific errors. I'd provide a simple example demonstrating the difference between the incorrect and correct approaches.

**7. Synthesizing the Summary:**

Finally, I need to summarize the function of the code. The key points are:

* Defines OS-specific constants for OpenBSD/AMD64.
* Includes constants for file I/O, terminal I/O control, errors, and signals.
* Serves as a mapping between symbolic names and integer values used in system calls.
* Is part of the `syscall` package, enabling low-level OS interaction in Go.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this file *generates* code. Looking closer at the content, it seems to be the *generated output* rather than the generator itself. The specific architecture in the filename reinforces this.
* **Considering edge cases:** Are there any nuances to how these constants are used in different system calls? While true, for a general explanation, sticking to common use cases like file I/O provides a clearer initial understanding. More specific details could be added if the prompt demanded it.
* **Balancing detail and conciseness:**  The goal is to be informative but not overwhelming. Providing enough detail to be useful while keeping the explanation focused is crucial. For example, listing *every* possible system call that uses these constants isn't necessary.

By following this thought process, breaking down the code, identifying key features, and generating illustrative examples, I can effectively analyze and explain the purpose and functionality of the given Go code snippet.
这是路径为 `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_amd64.go` 的 Go 语言实现的一部分，它定义了与 OpenBSD 操作系统在 AMD64 架构上的系统调用相关的常量、错误码和信号。

**功能归纳:**

这个 Go 语言文件的主要功能是：

1. **定义了大量的常量 (const):**  这些常量代表了 OpenBSD 系统调用中使用的各种标志、选项和魔数。 例如：
   - 文件操作相关的标志 (如 `O_RDONLY`, `O_WRONLY`, `O_CREAT`)
   - 终端 I/O 控制相关的常量 (如 `TIOCGETA`, `TIOCSETA`, `TIOCGWINSZ`)
   - 进程控制相关的常量 (如 `SIGCHLD`, `SIGTERM`, `WUNTRACED`)
   - 虚拟机相关的常量 (如 `VM_LOADAVG`, `VM_METER`)
2. **定义了错误码 (Errors const):** 这些常量对应于系统调用失败时返回的错误代码，方便 Go 程序判断和处理不同类型的错误。例如：`EACCES` (权限被拒绝), `ENOENT` (文件或目录不存在)。
3. **定义了信号 (Signals const):** 这些常量代表了可以发送给进程的各种信号。例如：`SIGINT` (中断信号), `SIGKILL` (强制终止信号)。
4. **提供了错误码的映射表 (errorList):**  这是一个结构体数组，将错误码数值 (`num`)、符号名称 (`name`) 和描述 (`desc`) 关联起来，方便在程序中查找和理解错误信息。
5. **提供了信号的映射表 (signalList):**  类似于错误码映射表，它将信号数值、符号名称和描述关联起来。

**它是什么 Go 语言功能的实现:**

这个文件是 Go 语言 `syscall` 标准库的一部分的实现。 `syscall` 包提供了对底层操作系统调用的访问。为了实现跨平台兼容性，`syscall` 包通常会针对不同的操作系统和架构提供特定的实现文件。 `zerrors_openbsd_amd64.go` 就是针对 OpenBSD 操作系统在 AMD64 架构上的特定实现，它定义了该平台上系统调用所使用的常量。

**Go 代码举例说明:**

假设我们要打开一个文件并读取其内容，并处理可能发生的错误：

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"errors"
)

func main() {
	filename := "myfile.txt"
	f, err := os.OpenFile(filename, syscall.O_RDONLY, 0) // 使用 syscall.O_RDONLY 常量
	if err != nil {
		if errors.Is(err, syscall.ENOENT) { // 使用 syscall.ENOENT 常量
			fmt.Printf("Error: File '%s' not found.\n", filename)
		} else if errors.Is(err, syscall.EACCES) { // 使用 syscall.EACCES 常量
			fmt.Printf("Error: Permission denied to open '%s'.\n", filename)
		} else {
			fmt.Printf("Error opening file: %v\n", err)
		}
		return
	}
	defer f.Close()

	// 读取文件内容...
	fmt.Println("File opened successfully.")
}
```

**假设的输入与输出：**

* **假设输入 1:** `myfile.txt` 文件不存在。
* **假设输出 1:** `Error: File 'myfile.txt' not found.`

* **假设输入 2:** `myfile.txt` 文件存在，但当前用户没有读取权限。
* **假设输出 2:** `Error: Permission denied to open 'myfile.txt'.`

* **假设输入 3:** `myfile.txt` 文件存在且具有读取权限。
* **假设输出 3:** `File opened successfully.`

**命令行参数的具体处理:**

这个代码片段本身**不直接处理命令行参数**。它只是定义了在与操作系统交互时使用的常量。命令行参数的处理通常发生在 `main` 函数中，使用 `os.Args` 或 `flag` 包来解析。这些常量可能会被使用在处理命令行参数的过程中，例如，当需要根据命令行参数打开特定模式的文件时。

**使用者易犯错的点:**

* **直接比较错误码:**  新手可能会直接比较 `err` 和 `syscall.ENOENT` 等常量，而不是使用 `errors.Is`。由于 Go 的错误可以被包装，直接比较可能会失败。

   **错误示例：**
   ```go
   if err == syscall.ENOENT { // 容易出错
       // ...
   }
   ```

   **正确示例：**
   ```go
   if errors.Is(err, syscall.ENOENT) { // 推荐使用
       // ...
   }
   ```

* **不理解常量的含义:**  不熟悉 OpenBSD 系统编程的开发者可能不清楚某些常量的具体作用，导致在编写代码时使用不当。 查阅相关的 OpenBSD 系统调用文档是必要的。

**功能归纳 (基于完整上下文，包含第 1 部分):**

作为 `zerrors_openbsd_amd64.go` 文件的第二部分，结合第一部分，可以归纳出它的完整功能是：

**为 Go 语言在 OpenBSD (AMD64 架构) 上与操作系统进行底层交互提供必要的常量、错误码和信号定义。 它通过 `syscall` 包，使得 Go 程序能够调用 OpenBSD 的系统调用，并能正确地处理系统调用返回的错误和信号。 该文件是平台特定的，确保了 Go 程序在 OpenBSD/AMD64 上能够准确地与操作系统进行交互。**

简单来说，这个文件就像一本 "字典"，告诉 Go 程序在 OpenBSD 系统中各种操作对应的数字代码，以及各种错误和信号的含义。 这使得 Go 程序能够理解和控制底层的操作系统行为。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
= 0x8
	TIOCFLAG_PPS                      = 0x10
	TIOCFLAG_SOFTCAR                  = 0x1
	TIOCFLUSH                         = 0x80047410
	TIOCGETA                          = 0x402c7413
	TIOCGETD                          = 0x4004741a
	TIOCGFLAGS                        = 0x4004745d
	TIOCGPGRP                         = 0x40047477
	TIOCGSID                          = 0x40047463
	TIOCGTSTAMP                       = 0x4010745b
	TIOCGWINSZ                        = 0x40087468
	TIOCMBIC                          = 0x8004746b
	TIOCMBIS                          = 0x8004746c
	TIOCMGET                          = 0x4004746a
	TIOCMODG                          = 0x4004746a
	TIOCMODS                          = 0x8004746d
	TIOCMSET                          = 0x8004746d
	TIOCM_CAR                         = 0x40
	TIOCM_CD                          = 0x40
	TIOCM_CTS                         = 0x20
	TIOCM_DSR                         = 0x100
	TIOCM_DTR                         = 0x2
	TIOCM_LE                          = 0x1
	TIOCM_RI                          = 0x80
	TIOCM_RNG                         = 0x80
	TIOCM_RTS                         = 0x4
	TIOCM_SR                          = 0x10
	TIOCM_ST                          = 0x8
	TIOCNOTTY                         = 0x20007471
	TIOCNXCL                          = 0x2000740e
	TIOCOUTQ                          = 0x40047473
	TIOCPKT                           = 0x80047470
	TIOCPKT_DATA                      = 0x0
	TIOCPKT_DOSTOP                    = 0x20
	TIOCPKT_FLUSHREAD                 = 0x1
	TIOCPKT_FLUSHWRITE                = 0x2
	TIOCPKT_IOCTL                     = 0x40
	TIOCPKT_NOSTOP                    = 0x10
	TIOCPKT_START                     = 0x8
	TIOCPKT_STOP                      = 0x4
	TIOCREMOTE                        = 0x80047469
	TIOCSBRK                          = 0x2000747b
	TIOCSCTTY                         = 0x20007461
	TIOCSDTR                          = 0x20007479
	TIOCSETA                          = 0x802c7414
	TIOCSETAF                         = 0x802c7416
	TIOCSETAW                         = 0x802c7415
	TIOCSETD                          = 0x8004741b
	TIOCSETVERAUTH                    = 0x8004741c
	TIOCSFLAGS                        = 0x8004745c
	TIOCSIG                           = 0x8004745f
	TIOCSPGRP                         = 0x80047476
	TIOCSTART                         = 0x2000746e
	TIOCSTAT                          = 0x20007465
	TIOCSTOP                          = 0x2000746f
	TIOCSTSTAMP                       = 0x8008745a
	TIOCSWINSZ                        = 0x80087467
	TIOCUCNTL                         = 0x80047466
	TIOCUCNTL_CBRK                    = 0x7a
	TIOCUCNTL_SBRK                    = 0x7b
	TOSTOP                            = 0x400000
	UTIME_NOW                         = -0x2
	UTIME_OMIT                        = -0x1
	VDISCARD                          = 0xf
	VDSUSP                            = 0xb
	VEOF                              = 0x0
	VEOL                              = 0x1
	VEOL2                             = 0x2
	VERASE                            = 0x3
	VINTR                             = 0x8
	VKILL                             = 0x5
	VLNEXT                            = 0xe
	VMIN                              = 0x10
	VM_ANONMIN                        = 0x7
	VM_LOADAVG                        = 0x2
	VM_MALLOC_CONF                    = 0xc
	VM_MAXID                          = 0xd
	VM_MAXSLP                         = 0xa
	VM_METER                          = 0x1
	VM_NKMEMPAGES                     = 0x6
	VM_PSSTRINGS                      = 0x3
	VM_SWAPENCRYPT                    = 0x5
	VM_USPACE                         = 0xb
	VM_UVMEXP                         = 0x4
	VM_VNODEMIN                       = 0x9
	VM_VTEXTMIN                       = 0x8
	VQUIT                             = 0x9
	VREPRINT                          = 0x6
	VSTART                            = 0xc
	VSTATUS                           = 0x12
	VSTOP                             = 0xd
	VSUSP                             = 0xa
	VTIME                             = 0x11
	VWERASE                           = 0x4
	WALTSIG                           = 0x4
	WCONTINUED                        = 0x8
	WCOREFLAG                         = 0x80
	WNOHANG                           = 0x1
	WUNTRACED                         = 0x2
	XCASE                             = 0x1000000
)

// Errors
const (
	E2BIG           = syscall.Errno(0x7)
	EACCES          = syscall.Errno(0xd)
	EADDRINUSE      = syscall.Errno(0x30)
	EADDRNOTAVAIL   = syscall.Errno(0x31)
	EAFNOSUPPORT    = syscall.Errno(0x2f)
	EAGAIN          = syscall.Errno(0x23)
	EALREADY        = syscall.Errno(0x25)
	EAUTH           = syscall.Errno(0x50)
	EBADF           = syscall.Errno(0x9)
	EBADMSG         = syscall.Errno(0x5c)
	EBADRPC         = syscall.Errno(0x48)
	EBUSY           = syscall.Errno(0x10)
	ECANCELED       = syscall.Errno(0x58)
	ECHILD          = syscall.Errno(0xa)
	ECONNABORTED    = syscall.Errno(0x35)
	ECONNREFUSED    = syscall.Errno(0x3d)
	ECONNRESET      = syscall.Errno(0x36)
	EDEADLK         = syscall.Errno(0xb)
	EDESTADDRREQ    = syscall.Errno(0x27)
	EDOM            = syscall.Errno(0x21)
	EDQUOT          = syscall.Errno(0x45)
	EEXIST          = syscall.Errno(0x11)
	EFAULT          = syscall.Errno(0xe)
	EFBIG           = syscall.Errno(0x1b)
	EFTYPE          = syscall.Errno(0x4f)
	EHOSTDOWN       = syscall.Errno(0x40)
	EHOSTUNREACH    = syscall.Errno(0x41)
	EIDRM           = syscall.Errno(0x59)
	EILSEQ          = syscall.Errno(0x54)
	EINPROGRESS     = syscall.Errno(0x24)
	EINTR           = syscall.Errno(0x4)
	EINVAL          = syscall.Errno(0x16)
	EIO             = syscall.Errno(0x5)
	EIPSEC          = syscall.Errno(0x52)
	EISCONN         = syscall.Errno(0x38)
	EISDIR          = syscall.Errno(0x15)
	ELAST           = syscall.Errno(0x5f)
	ELOOP           = syscall.Errno(0x3e)
	EMEDIUMTYPE     = syscall.Errno(0x56)
	EMFILE          = syscall.Errno(0x18)
	EMLINK          = syscall.Errno(0x1f)
	EMSGSIZE        = syscall.Errno(0x28)
	ENAMETOOLONG    = syscall.Errno(0x3f)
	ENEEDAUTH       = syscall.Errno(0x51)
	ENETDOWN        = syscall.Errno(0x32)
	ENETRESET       = syscall.Errno(0x34)
	ENETUNREACH     = syscall.Errno(0x33)
	ENFILE          = syscall.Errno(0x17)
	ENOATTR         = syscall.Errno(0x53)
	ENOBUFS         = syscall.Errno(0x37)
	ENODEV          = syscall.Errno(0x13)
	ENOENT          = syscall.Errno(0x2)
	ENOEXEC         = syscall.Errno(0x8)
	ENOLCK          = syscall.Errno(0x4d)
	ENOMEDIUM       = syscall.Errno(0x55)
	ENOMEM          = syscall.Errno(0xc)
	ENOMSG          = syscall.Errno(0x5a)
	ENOPROTOOPT     = syscall.Errno(0x2a)
	ENOSPC          = syscall.Errno(0x1c)
	ENOSYS          = syscall.Errno(0x4e)
	ENOTBLK         = syscall.Errno(0xf)
	ENOTCONN        = syscall.Errno(0x39)
	ENOTDIR         = syscall.Errno(0x14)
	ENOTEMPTY       = syscall.Errno(0x42)
	ENOTRECOVERABLE = syscall.Errno(0x5d)
	ENOTSOCK        = syscall.Errno(0x26)
	ENOTSUP         = syscall.Errno(0x5b)
	ENOTTY          = syscall.Errno(0x19)
	ENXIO           = syscall.Errno(0x6)
	EOPNOTSUPP      = syscall.Errno(0x2d)
	EOVERFLOW       = syscall.Errno(0x57)
	EOWNERDEAD      = syscall.Errno(0x5e)
	EPERM           = syscall.Errno(0x1)
	EPFNOSUPPORT    = syscall.Errno(0x2e)
	EPIPE           = syscall.Errno(0x20)
	EPROCLIM        = syscall.Errno(0x43)
	EPROCUNAVAIL    = syscall.Errno(0x4c)
	EPROGMISMATCH   = syscall.Errno(0x4b)
	EPROGUNAVAIL    = syscall.Errno(0x4a)
	EPROTO          = syscall.Errno(0x5f)
	EPROTONOSUPPORT = syscall.Errno(0x2b)
	EPROTOTYPE      = syscall.Errno(0x29)
	ERANGE          = syscall.Errno(0x22)
	EREMOTE         = syscall.Errno(0x47)
	EROFS           = syscall.Errno(0x1e)
	ERPCMISMATCH    = syscall.Errno(0x49)
	ESHUTDOWN       = syscall.Errno(0x3a)
	ESOCKTNOSUPPORT = syscall.Errno(0x2c)
	ESPIPE          = syscall.Errno(0x1d)
	ESRCH           = syscall.Errno(0x3)
	ESTALE          = syscall.Errno(0x46)
	ETIMEDOUT       = syscall.Errno(0x3c)
	ETOOMANYREFS    = syscall.Errno(0x3b)
	ETXTBSY         = syscall.Errno(0x1a)
	EUSERS          = syscall.Errno(0x44)
	EWOULDBLOCK     = syscall.Errno(0x23)
	EXDEV           = syscall.Errno(0x12)
)

// Signals
const (
	SIGABRT   = syscall.Signal(0x6)
	SIGALRM   = syscall.Signal(0xe)
	SIGBUS    = syscall.Signal(0xa)
	SIGCHLD   = syscall.Signal(0x14)
	SIGCONT   = syscall.Signal(0x13)
	SIGEMT    = syscall.Signal(0x7)
	SIGFPE    = syscall.Signal(0x8)
	SIGHUP    = syscall.Signal(0x1)
	SIGILL    = syscall.Signal(0x4)
	SIGINFO   = syscall.Signal(0x1d)
	SIGINT    = syscall.Signal(0x2)
	SIGIO     = syscall.Signal(0x17)
	SIGIOT    = syscall.Signal(0x6)
	SIGKILL   = syscall.Signal(0x9)
	SIGPIPE   = syscall.Signal(0xd)
	SIGPROF   = syscall.Signal(0x1b)
	SIGQUIT   = syscall.Signal(0x3)
	SIGSEGV   = syscall.Signal(0xb)
	SIGSTOP   = syscall.Signal(0x11)
	SIGSYS    = syscall.Signal(0xc)
	SIGTERM   = syscall.Signal(0xf)
	SIGTHR    = syscall.Signal(0x20)
	SIGTRAP   = syscall.Signal(0x5)
	SIGTSTP   = syscall.Signal(0x12)
	SIGTTIN   = syscall.Signal(0x15)
	SIGTTOU   = syscall.Signal(0x16)
	SIGURG    = syscall.Signal(0x10)
	SIGUSR1   = syscall.Signal(0x1e)
	SIGUSR2   = syscall.Signal(0x1f)
	SIGVTALRM = syscall.Signal(0x1a)
	SIGWINCH  = syscall.Signal(0x1c)
	SIGXCPU   = syscall.Signal(0x18)
	SIGXFSZ   = syscall.Signal(0x19)
)

// Error table
var errorList = [...]struct {
	num  syscall.Errno
	name string
	desc string
}{
	{1, "EPERM", "operation not permitted"},
	{2, "ENOENT", "no such file or directory"},
	{3, "ESRCH", "no such process"},
	{4, "EINTR", "interrupted system call"},
	{5, "EIO", "input/output error"},
	{6, "ENXIO", "device not configured"},
	{7, "E2BIG", "argument list too long"},
	{8, "ENOEXEC", "exec format error"},
	{9, "EBADF", "bad file descriptor"},
	{10, "ECHILD", "no child processes"},
	{11, "EDEADLK", "resource deadlock avoided"},
	{12, "ENOMEM", "cannot allocate memory"},
	{13, "EACCES", "permission denied"},
	{14, "EFAULT", "bad address"},
	{15, "ENOTBLK", "block device required"},
	{16, "EBUSY", "device busy"},
	{17, "EEXIST", "file exists"},
	{18, "EXDEV", "cross-device link"},
	{19, "ENODEV", "operation not supported by device"},
	{20, "ENOTDIR", "not a directory"},
	{21, "EISDIR", "is a directory"},
	{22, "EINVAL", "invalid argument"},
	{23, "ENFILE", "too many open files in system"},
	{24, "EMFILE", "too many open files"},
	{25, "ENOTTY", "inappropriate ioctl for device"},
	{26, "ETXTBSY", "text file busy"},
	{27, "EFBIG", "file too large"},
	{28, "ENOSPC", "no space left on device"},
	{29, "ESPIPE", "illegal seek"},
	{30, "EROFS", "read-only file system"},
	{31, "EMLINK", "too many links"},
	{32, "EPIPE", "broken pipe"},
	{33, "EDOM", "numerical argument out of domain"},
	{34, "ERANGE", "result too large"},
	{35, "EAGAIN", "resource temporarily unavailable"},
	{36, "EINPROGRESS", "operation now in progress"},
	{37, "EALREADY", "operation already in progress"},
	{38, "ENOTSOCK", "socket operation on non-socket"},
	{39, "EDESTADDRREQ", "destination address required"},
	{40, "EMSGSIZE", "message too long"},
	{41, "EPROTOTYPE", "protocol wrong type for socket"},
	{42, "ENOPROTOOPT", "protocol not available"},
	{43, "EPROTONOSUPPORT", "protocol not supported"},
	{44, "ESOCKTNOSUPPORT", "socket type not supported"},
	{45, "EOPNOTSUPP", "operation not supported"},
	{46, "EPFNOSUPPORT", "protocol family not supported"},
	{47, "EAFNOSUPPORT", "address family not supported by protocol family"},
	{48, "EADDRINUSE", "address already in use"},
	{49, "EADDRNOTAVAIL", "can't assign requested address"},
	{50, "ENETDOWN", "network is down"},
	{51, "ENETUNREACH", "network is unreachable"},
	{52, "ENETRESET", "network dropped connection on reset"},
	{53, "ECONNABORTED", "software caused connection abort"},
	{54, "ECONNRESET", "connection reset by peer"},
	{55, "ENOBUFS", "no buffer space available"},
	{56, "EISCONN", "socket is already connected"},
	{57, "ENOTCONN", "socket is not connected"},
	{58, "ESHUTDOWN", "can't send after socket shutdown"},
	{59, "ETOOMANYREFS", "too many references: can't splice"},
	{60, "ETIMEDOUT", "operation timed out"},
	{61, "ECONNREFUSED", "connection refused"},
	{62, "ELOOP", "too many levels of symbolic links"},
	{63, "ENAMETOOLONG", "file name too long"},
	{64, "EHOSTDOWN", "host is down"},
	{65, "EHOSTUNREACH", "no route to host"},
	{66, "ENOTEMPTY", "directory not empty"},
	{67, "EPROCLIM", "too many processes"},
	{68, "EUSERS", "too many users"},
	{69, "EDQUOT", "disk quota exceeded"},
	{70, "ESTALE", "stale NFS file handle"},
	{71, "EREMOTE", "too many levels of remote in path"},
	{72, "EBADRPC", "RPC struct is bad"},
	{73, "ERPCMISMATCH", "RPC version wrong"},
	{74, "EPROGUNAVAIL", "RPC program not available"},
	{75, "EPROGMISMATCH", "program version wrong"},
	{76, "EPROCUNAVAIL", "bad procedure for program"},
	{77, "ENOLCK", "no locks available"},
	{78, "ENOSYS", "function not implemented"},
	{79, "EFTYPE", "inappropriate file type or format"},
	{80, "EAUTH", "authentication error"},
	{81, "ENEEDAUTH", "need authenticator"},
	{82, "EIPSEC", "IPsec processing failure"},
	{83, "ENOATTR", "attribute not found"},
	{84, "EILSEQ", "illegal byte sequence"},
	{85, "ENOMEDIUM", "no medium found"},
	{86, "EMEDIUMTYPE", "wrong medium type"},
	{87, "EOVERFLOW", "value too large to be stored in data type"},
	{88, "ECANCELED", "operation canceled"},
	{89, "EIDRM", "identifier removed"},
	{90, "ENOMSG", "no message of desired type"},
	{91, "ENOTSUP", "not supported"},
	{92, "EBADMSG", "bad message"},
	{93, "ENOTRECOVERABLE", "state not recoverable"},
	{94, "EOWNERDEAD", "previous owner died"},
	{95, "ELAST", "protocol error"},
}

// Signal table
var signalList = [...]struct {
	num  syscall.Signal
	name string
	desc string
}{
	{1, "SIGHUP", "hangup"},
	{2, "SIGINT", "interrupt"},
	{3, "SIGQUIT", "quit"},
	{4, "SIGILL", "illegal instruction"},
	{5, "SIGTRAP", "trace/BPT trap"},
	{6, "SIGIOT", "abort trap"},
	{7, "SIGEMT", "EMT trap"},
	{8, "SIGFPE", "floating point exception"},
	{9, "SIGKILL", "killed"},
	{10, "SIGBUS", "bus error"},
	{11, "SIGSEGV", "segmentation fault"},
	{12, "SIGSYS", "bad system call"},
	{13, "SIGPIPE", "broken pipe"},
	{14, "SIGALRM", "alarm clock"},
	{15, "SIGTERM", "terminated"},
	{16, "SIGURG", "urgent I/O condition"},
	{17, "SIGSTOP", "suspended (signal)"},
	{18, "SIGTSTP", "suspended"},
	{19, "SIGCONT", "continued"},
	{20, "SIGCHLD", "child exited"},
	{21, "SIGTTIN", "stopped (tty input)"},
	{22, "SIGTTOU", "stopped (tty output)"},
	{23, "SIGIO", "I/O possible"},
	{24, "SIGXCPU", "cputime limit exceeded"},
	{25, "SIGXFSZ", "filesize limit exceeded"},
	{26, "SIGVTALRM", "virtual timer expired"},
	{27, "SIGPROF", "profiling timer expired"},
	{28, "SIGWINCH", "window size changes"},
	{29, "SIGINFO", "information request"},
	{30, "SIGUSR1", "user defined signal 1"},
	{31, "SIGUSR2", "user defined signal 2"},
	{32, "SIGTHR", "thread AST"},
	{28672, "SIGSTKSZ", "unknown signal"},
}
```