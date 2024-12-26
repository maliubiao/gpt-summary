Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Context:**

The first thing I notice is the file path: `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_riscv64.go`. This immediately tells me several things:

* **`vendor` directory:** This suggests the code is a vendored dependency, likely part of the `golang.org/x/sys` package.
* **`unix` package:**  This means it's dealing with low-level Unix system calls.
* **`zerrors_openbsd_riscv64.go`:** The `zerrors` prefix often indicates automatically generated code. The `openbsd` and `riscv64` parts specify the operating system and architecture. This strongly suggests the file defines constants specific to this platform.

**2. Code Structure Analysis:**

I then scan the content of the file, noting the distinct sections:

* **Constants:**  A large number of `const` declarations are present. They have names like `O_RDONLY`, `TIOCGETA`, `EACCES`, `SIGABRT`, etc. These look like symbolic names for numerical values.
* **Error Table:**  A `var errorList` of type `[...]struct` appears, containing `num`, `name`, and `desc` fields. The `num` values likely correspond to the `E...` constants.
* **Signal Table:** Similar to the error table, a `var signalList` exists for signals (`SIG...` constants).

**3. Deduction of Functionality:**

Based on the structure and the names of the constants and tables, I can infer the primary purpose of this file:

* **Defining System Call Constants:**  The constants clearly represent values used in system calls related to file operations (`O_*`), terminal I/O control (`TIOC*`), process signaling (`SIG*`), and error codes (`E*`).
* **Providing Human-Readable Error and Signal Information:** The `errorList` and `signalList` arrays map the numerical values of errors and signals to their symbolic names and textual descriptions. This is crucial for turning raw system call results into something developers can understand.

**4. Reasoning about Go Language Features:**

I consider how this code is used within the broader Go ecosystem:

* **`syscall` package:** The code imports `syscall`. This package provides the low-level interface to the operating system. The constants defined here are clearly intended for use with functions in the `syscall` package.
* **Error Handling:** Go's error handling often involves checking for specific error types. The `errorList` helps the `syscall` package or higher-level libraries translate raw error numbers into standard Go `error` values that can be inspected.
* **Signal Handling:** Similarly, the `signalList` assists in interpreting signals received by a Go program.

**5. Constructing Examples:**

To illustrate the functionality, I think about typical scenarios involving system calls:

* **Opening a file:** This uses `O_RDONLY`, `O_CREATE`, etc.
* **Working with terminals:** This involves `TIOCGETA`, `TIOCSWINSZ`, etc.
* **Handling errors:**  Checking `err == syscall.EACCES`, etc.
* **Responding to signals:** Using `signal.Notify` and checking the received signal.

This leads to the example code provided in the prompt's answer.

**6. Considering Command-Line Arguments and Potential Pitfalls:**

I consider if this file directly processes command-line arguments. Given its nature (defining constants), it's unlikely. However, the *usage* of these constants in other parts of the `syscall` package or user code could involve command-line arguments.

Regarding pitfalls, the main one is using the raw numerical values directly instead of the symbolic constants. This makes the code less readable and maintainable. Also, platform-specific constants like these highlight the importance of writing platform-aware code if necessary.

**7. Synthesizing the Summary:**

Finally, I condense my understanding into a concise summary that captures the key aspects: defining constants for system calls, providing error and signal information, and its role in the `syscall` package.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this file *implements* certain system call functionalities.
* **Correction:**  The `zerrors` prefix and the presence of constant definitions strongly suggest it's *declarative* rather than *imperative*. It defines values, not the logic itself.
* **Initial thought:** Focus heavily on the `open` system call given the filename.
* **Refinement:** While relevant, the constants cover a broader range of system calls, including terminal control and signals. The filename is just a convention for where these error definitions are placed.

By following these steps, I can systematically analyze the code snippet, infer its purpose, provide relevant examples, and highlight potential issues. The key is to combine code structure analysis with knowledge of the Go standard library and operating system concepts.
这是提供的Go语言代码文件的第二部分，与第一部分共同定义了在 OpenBSD RISC-V 64 位架构下的系统调用相关的常量、错误码和信号量。

**功能归纳:**

总的来说，这个文件 (`zerrors_openbsd_riscv64.go`) 的主要功能是：

1. **定义系统调用相关的常量:**  它声明了大量的 `const` 常量，这些常量代表了 OpenBSD RISC-V 64 位架构下系统调用中使用的各种标志、选项和控制码。这些常量涵盖了：
    * **文件操作:** 如 `O_RDONLY`, `O_WRONLY`, `O_CREATE` 等，用于 `open` 系统调用。
    * **终端 I/O 控制:**  如 `TIOCGETA`, `TIOCSWINSZ`, `TIOCMSET` 等，用于 `ioctl` 系统调用来控制终端行为。
    * **进程控制:** 如 `WNOHANG`, `WUNTRACED`，用于 `wait` 系统调用。
    * **虚拟内存管理:** 如 `VM_ANONMIN`, `VM_LOADAVG` 等，用于获取或设置虚拟内存相关信息。
    * **其他系统级别的常量:** 如 `UTIME_NOW`, `UTIME_OMIT` 用于时间操作。

2. **定义错误码 (Errno):** 它声明了 `const` 常量，这些常量是 `syscall.Errno` 类型，代表了各种系统调用可能返回的错误代码，例如 `EACCES` (权限不足), `ENOENT` (文件不存在) 等。

3. **定义信号量 (Signal):** 它声明了 `const` 常量，这些常量是 `syscall.Signal` 类型，代表了操作系统可以发送给进程的各种信号，例如 `SIGINT` (中断信号), `SIGKILL` (强制终止信号) 等。

4. **提供错误码和信号量的描述信息:**  它定义了两个 `var` 变量 `errorList` 和 `signalList`，分别是结构体数组，用于将错误码和信号量的数值映射到其名称和描述字符串。这为开发者提供了更易读的错误和信号信息。

**与第一部分的关系:**

第一部分很可能包含了与文件打开模式 (`O_...`) 相关的常量定义，而第二部分则侧重于终端控制 (`TIOC_...`)、进程状态 (`W_...`)、虚拟内存 (`VM_...`)、时间 (`UTIME_...`) 以及错误码和信号量的定义及描述。 两部分共同构成了该平台下系统调用相关常量的完整定义。

**Go 语言功能的实现 (推断):**

这个文件是 Go 语言标准库中 `syscall` 包的一部分实现。 `syscall` 包提供了对底层操作系统调用的访问。  这个文件中的常量、错误码和信号量定义，被 `syscall` 包内部的函数使用，以便 Go 程序能够以类型安全和可移植的方式调用操作系统功能。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	// 使用 O_RDONLY 常量打开文件
	fd, err := syscall.Open("test.txt", syscall.O_RDONLY, 0)
	if err != nil {
		// 使用 EACCES 常量判断是否是权限错误
		if err == syscall.EACCES {
			fmt.Println("权限不足，无法打开文件")
		} else if err == syscall.ENOENT {
			fmt.Println("文件不存在")
		} else {
			fmt.Println("打开文件出错:", err)
		}
		return
	}
	fmt.Println("成功打开文件，文件描述符:", fd)
	syscall.Close(fd)

	// 发送 SIGKILL 信号给指定进程 (需要进程ID)
	pid := os.Getpid() // 获取当前进程ID，仅作演示
	pro, err := os.FindProcess(pid)
	if err == nil {
		err = pro.Signal(syscall.SIGKILL)
		if err != nil {
			fmt.Println("发送信号出错:", err)
		} else {
			fmt.Println("成功发送 SIGKILL 信号给进程:", pid)
		}
	}
}
```

**假设的输入与输出:**

* **假设输入:**
    * `test.txt` 文件不存在。
* **预期输出:**
    ```
    文件不存在
    成功发送 SIGKILL 信号给进程: <当前进程ID>
    ```

* **假设输入:**
    * `test.txt` 文件存在，但当前用户没有读取权限。
* **预期输出:**
    ```
    权限不足，无法打开文件
    成功发送 SIGKILL 信号给进程: <当前进程ID>
    ```

**命令行参数的具体处理:**

这个文件本身并不直接处理命令行参数。 它的作用是定义常量，这些常量会被其他使用 `syscall` 包的 Go 代码使用。  那些使用这些常量的代码可能会处理命令行参数，例如 `os` 包的函数在解析命令行参数时，可能会根据用户输入的参数来决定使用哪些 `open` 标志 (例如，如果用户指定创建文件，则可能使用 `syscall.O_CREAT`)。

**使用者易犯错的点:**

1. **直接使用数字而不是常量:**  开发者可能会直接使用 `0` 或 `1` 来表示 `O_RDONLY` 或 `O_WRONLY`，而不是使用 `syscall.O_RDONLY` 和 `syscall.O_WRONLY`。这降低了代码的可读性和可维护性，并且在不同操作系统或架构下可能会出现问题。

   ```go
   // 错误的做法
   fd, err := syscall.Open("test.txt", 0, 0) // 0 代表什么？难以理解

   // 正确的做法
   fd, err := syscall.Open("test.txt", syscall.O_RDONLY, 0)
   ```

2. **混淆不同平台的常量:** 虽然 `syscall` 包尝试提供跨平台的抽象，但某些常量是平台特定的。 直接复制其他平台的代码并使用其常量可能会导致在 OpenBSD RISC-V 64 位上出现意外行为或错误。

**总结:**

这个 `zerrors_openbsd_riscv64.go` 文件是 Go 语言 `syscall` 包在 OpenBSD RISC-V 64 位架构下的底层基础，它定义了与操作系统交互所需的各种常量、错误码和信号量，并提供了它们的描述信息，使得 Go 程序能够安全且方便地进行系统调用。 它是 Go 语言实现跨平台能力的重要组成部分，通过针对不同平台提供特定的定义，实现了与底层操作系统的桥梁。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_riscv64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
            = 0x10
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
	{6, "SIGABRT", "abort trap"},
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
}

"""




```