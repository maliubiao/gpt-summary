Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Identification of Core Elements:**

The first step is to quickly scan the code and identify the major structural components. I see:

* **Package Declaration:**  `package unix` confirms this is part of a lower-level system interface.
* **Import:** `import "syscall"` tells me it's interacting with the operating system's system calls.
* **Constant Declarations (`const`):**  A large number of constants are defined. The names of these constants strongly suggest they represent:
    * Terminal I/O Control (TIOC...)
    * Virtual Memory parameters (VM_...)
    * Standard C library constants related to signals and process control (TOSTOP, UTIME_NOW, etc.)
    * Error numbers (E...)
    * Signal numbers (SIG...)
* **Variable Declarations (`var`):** Two variables are declared: `errorList` and `signalList`. These are arrays of structs, each containing a number, a name, and a description.

**2. Categorization and Interpretation of Constants:**

Next, I'll go through the constant groups more systematically:

* **TIOC Constants:** These are clearly related to terminal input/output control. They represent various commands and flags used to interact with terminal devices (e.g., getting terminal attributes, setting baud rates, flushing buffers).
* **VM Constants:** These constants likely represent parameters that can be retrieved or configured related to the virtual memory system. Terms like "ANONMIN," "LOADAVG," "USPACE" reinforce this.
* **Other Constants (TOSTOP, UTIME, V*, W*):**  These seem to be a mixed bag of constants related to process control, time, and terminal settings. The `V*` constants often represent special characters for terminal input (e.g., EOF, interrupt). The `W*` constants relate to wait status.
* **Error Constants (E...):**  These are standard POSIX error numbers. The `syscall.Errno` type confirms this.
* **Signal Constants (SIG...):** These are standard POSIX signal numbers. The `syscall.Signal` type confirms this.

**3. Analyzing `errorList` and `signalList`:**

The structure of these variables is straightforward. They are arrays of structs, providing a mapping between the numeric value of an error or signal, its symbolic name, and a human-readable description. This is a common pattern for making error and signal handling more user-friendly.

**4. Inferring the Overall Purpose:**

Based on the constants and the `syscall` import, it's clear this file provides Go-level definitions for various system-level constants related to terminal I/O, virtual memory, errors, and signals on OpenBSD for the ARM architecture. The `zerrors_openbsd_arm.go` filename convention suggests this is auto-generated or at least specifically tailored for this operating system and architecture. The "z" might indicate it's a generated or supplementary file.

**5. Considering Potential Go Language Features:**

This file isn't *implementing* a specific Go language feature in the sense of `sync.Mutex` or `net/http`. Instead, it's providing *access* to operating system features by defining the necessary constants. Go's `syscall` package allows interaction with raw system calls, and this file makes it easier by providing meaningful names for the numerical constants that those system calls use.

**6. Constructing the Go Code Example:**

To illustrate how these constants are used, I need to demonstrate a scenario where system calls are involved. A good example is interacting with a terminal. The `golang.org/x/term` package is a high-level wrapper around some of these low-level functionalities. I would show:

* Opening a terminal.
* Getting the terminal size using `TIOCGWINSZ`.
* Sending a signal to a process using `SIGKILL`.
* Checking for a specific error like `ENOENT`.

**7. Considering Command-Line Arguments:**

This file doesn't directly handle command-line arguments. It defines constants that *might* be used in programs that process command-line arguments (e.g., a command that changes terminal settings). Therefore, I'd explain that it provides the building blocks, but not the argument parsing logic itself.

**8. Identifying Potential User Errors:**

The main area for errors is likely incorrect usage of the constants with system calls. Specifically:

* **Using the wrong constant for a system call:**  This could lead to unexpected behavior or errors.
* **Misinterpreting the meaning of a constant:**  Understanding the documentation for the relevant system calls is crucial.

**9. Summarizing the Functionality:**

The final step is to concisely summarize the purpose of the file, emphasizing that it's providing a Go-friendly interface to low-level OpenBSD system constants for the ARM architecture.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on *how* these constants are generated. While the "z" in the filename hints at generation, the immediate task is understanding their *purpose*.
* I needed to be careful not to confuse the definition of these constants with the actual system call implementations, which reside in the operating system kernel.
* When creating the code example, I considered using raw `syscall` calls but opted for the `golang.org/x/term` package to provide a more practical and understandable demonstration. This avoids getting bogged down in the complexities of setting up raw system call arguments.
这是路径为 `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_arm.go` 的 Go 语言实现的一部分，它定义了一系列用于 OpenBSD 操作系统在 ARM 架构下的系统调用相关的常量、错误码和信号量。由于这是第 2 部分，我们可以结合你在第 1 部分提供的信息来更全面地理解它的功能。

**综合第 1 部分和第 2 部分，此文件的主要功能是：**

1. **定义系统调用相关的常量 (Constants):**
   -  这部分代码定义了大量的常量，这些常量通常与底层的操作系统接口相关。
   -  **终端 I/O 控制 (TIOC...):**  例如 `TIOCGETA`, `TIOCSETA`, `TIOCGWINSZ` 等，用于获取和设置终端属性，如波特率、行规程、窗口大小等。
   -  **虚拟内存 (VM_...):** 例如 `VM_LOADAVG`, `VM_UVMEXP` 等，用于获取虚拟内存相关的统计信息。
   -  **其他常量:**  例如 `TOSTOP`, `UTIME_NOW`, `UTIME_OMIT`, 以及与终端特殊字符相关的常量 `VDISCARD`, `VEOF` 等。
   -  **进程状态相关的常量 (W...):** 例如 `WCONTINUED`, `WNOHANG`, `WUNTRACED`，这些常量用于 `wait` 系统调用返回的状态信息。
   -  **终端标志位 (XCASE):**  例如 `XCASE`。

2. **定义错误码 (Errors):**
   -  这部分代码定义了 OpenBSD 系统中常见的错误码，例如 `EACCES` (权限不足), `ENOENT` (文件不存在), `EINVAL` (参数无效) 等。
   -  每个错误码都与 `syscall.Errno` 类型关联，方便 Go 语言进行错误处理。

3. **定义信号量 (Signals):**
   -  这部分代码定义了 OpenBSD 系统中常见的信号量，例如 `SIGINT` (中断信号), `SIGKILL` (终止信号), `SIGSEGV` (段错误) 等。
   -  每个信号量都与 `syscall.Signal` 类型关联，方便 Go 语言进行信号处理。

4. **提供错误码和信号量的描述信息:**
   -  `errorList` 变量是一个结构体数组，将错误码的数值、名称和描述信息关联起来。这使得在 Go 语言中处理错误时，可以方便地获取错误码的文字描述。
   -  `signalList` 变量也是一个结构体数组，将信号量的数值、名称和描述信息关联起来，方便程序理解和处理信号。

**它是什么 Go 语言功能的实现？**

这个文件本身并不是一个“功能”的实现，而是为 Go 语言的 `syscall` 包在 OpenBSD 的 ARM 架构下提供底层系统接口的常量定义。`syscall` 包允许 Go 程序直接调用操作系统的系统调用。这个 `zerrors_openbsd_arm.go` 文件就提供了这些系统调用所需的参数和返回值的常量定义。

**Go 代码举例说明:**

假设我们要获取终端的窗口大小，可以使用 `TIOCGWINSZ` 常量：

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// 从 vendor 目录导入定义
import _ "cmd/vendor/golang.org/x/sys/unix"

func main() {
	// 打开标准输入的文件描述符
	fd := int(os.Stdin.Fd())

	// 定义 winsize 结构体
	type winsize struct {
		rows    uint16
		cols    uint16
		xpixels uint16
		ypixels uint16
	}

	ws := winsize{}
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if err != 0 {
		fmt.Printf("ioctl error: %v\n", err)
		return
	}

	fmt.Printf("Rows: %d, Columns: %d\n", ws.rows, ws.cols)
}
```

**假设的输入与输出:**

如果在一个终端窗口中运行这段代码，并且终端的窗口大小是 80 行和 24 列，则输出可能如下：

```
Rows: 24, Columns: 80
```

**代码推理:**

1. **导入 `syscall`:**  我们需要使用 `syscall` 包来执行系统调用。
2. **导入 vendor 目录:** 使用 `import _ "cmd/vendor/golang.org/x/sys/unix"` 来确保常量定义被加载。
3. **获取文件描述符:**  `os.Stdin.Fd()` 获取标准输入的文件描述符，终端通常与标准输入关联。
4. **定义 `winsize` 结构体:**  这个结构体对应于 `TIOCGWINSZ` 系统调用需要的数据结构。
5. **调用 `syscall.Syscall`:**
   - `syscall.SYS_IOCTL` 表示执行 `ioctl` 系统调用。
   - `uintptr(fd)` 是文件描述符。
   - `uintptr(syscall.TIOCGWINSZ)` 是要执行的 `ioctl` 命令，这里使用了在 `zerrors_openbsd_arm.go` 中定义的常量。
   - `uintptr(unsafe.Pointer(&ws))` 是指向 `winsize` 结构体的指针，用于接收返回的窗口大小信息。
6. **处理错误:** 检查 `syscall.Syscall` 的返回值 `err`。
7. **打印结果:** 如果调用成功，打印获取到的行数和列数。

**命令行参数的具体处理:**

这个文件本身不处理命令行参数。命令行参数的处理通常在 `main` 函数中使用 `os.Args` 或 `flag` 包进行。但是，这里定义的常量可能会被用于处理与终端相关的命令行工具中。例如，一个设置终端大小的命令可能会使用 `TIOCSWINSZ` 常量。

**使用者易犯错的点:**

1. **使用了错误的常量值:** 手动输入这些常量值容易出错，最好直接使用 `syscall` 包或者 `golang.org/x/sys/unix` 中已经定义的常量。
2. **平台依赖性:** 这些常量是针对 OpenBSD 和 ARM 架构的，在其他操作系统或架构下使用可能会导致错误或不期望的行为。
3. **不理解系统调用的含义:** 错误地使用这些常量通常是因为不理解它们对应的系统调用的具体功能和参数。需要查阅相关的 OpenBSD 系统调用文档。

**归纳一下它的功能:**

总而言之，`go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_arm.go` 文件的功能是为 Go 语言在 OpenBSD 操作系统和 ARM 架构下进行底层系统编程提供必要的常量定义，包括终端控制、虚拟内存管理、错误码和信号量等，使得 Go 程序可以直接与操作系统内核进行交互。它作为 `golang.org/x/sys/unix` 包的一部分，为开发者提供了访问底层系统功能的桥梁。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_arm.go的go语言实现的一部分， 请列举一下它的功能, 　
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