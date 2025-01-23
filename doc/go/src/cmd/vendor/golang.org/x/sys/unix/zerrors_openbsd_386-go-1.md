Response:
The user wants to understand the functionality of a Go file containing constants related to system calls on OpenBSD for the 386 architecture.

**Plan:**

1. **Identify the purpose of the file:** The filename `zerrors_openbsd_386.go` suggests it defines system-level constants for a specific operating system and architecture. The `errors`, `signals`, and `ioctl` prefixes reinforce this.
2. **Categorize the constants:**  The provided code clearly divides constants into `Ioctls`, `Errors`, and `Signals`. These represent different categories of system-level interactions.
3. **Explain each category:**
    * **Ioctls:**  These are control operations for devices, particularly terminal devices.
    * **Errors:** These represent different types of errors that can occur during system calls.
    * **Signals:** These are notifications sent to processes to indicate events.
4. **Infer the Go feature:** This file is part of the `syscall` package, which provides a low-level interface to the operating system.
5. **Provide Go code examples:** Show how these constants are typically used with the `syscall` package.
6. **Address potential errors:**  Highlight common mistakes developers might make when working with these low-level constants.
7. **Summarize the functionality:** Briefly restate the main purpose of the file.
这是路径为 `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_386.go` 的 Go 语言实现的一部分，它定义了在 OpenBSD 操作系统 386 架构下进行系统调用时使用的一些常量。

**功能列举:**

1. **定义 IO 控制命令 (IOCTLS):**  以 `TIOC` 开头的常量，如 `TIOCGETA`, `TIOCGWINSZ` 等，这些常量代表了用于控制终端设备和其他 I/O 设备的各种操作命令。例如，`TIOCGWINSZ` 用于获取终端窗口大小。
2. **定义错误码 (Errors):**  以 `E` 开头的常量，如 `EACCES`, `ENOENT` 等，这些常量代表了系统调用可能返回的各种错误类型。例如，`EACCES` 表示权限被拒绝，`ENOENT` 表示文件或目录不存在。
3. **定义信号 (Signals):** 以 `SIG` 开头的常量，如 `SIGINT`, `SIGTERM` 等，这些常量代表了可以发送给进程的各种信号。例如，`SIGINT` 是中断信号 (通常由 Ctrl+C 触发)，`SIGTERM` 是终止信号。
4. **提供错误码和信号的详细信息:** `errorList` 和 `signalList` 变量分别包含了错误码和信号的数值、名称以及简短的描述。这有助于在调试和错误处理时提供更清晰的信息。

**Go 语言功能的实现 (推断和举例):**

这个文件是 `golang.org/x/sys/unix` 包的一部分，该包提供了对 Unix 系统调用的底层访问。这些常量定义了与 OpenBSD 操作系统交互时使用的具体数值。

**示例代码 (假设使用 `syscall` 包进行系统调用):**

假设我们要获取终端窗口的大小，并处理可能出现的错误：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// 从提供的代码片段中复制 TIOCGWINSZ 的定义
const TIOCGWINSZ = 0x40087468

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func main() {
	// 获取标准输出的文件描述符
	fd := int(syscall.Stdout)

	var ws winsize
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if err != 0 {
		fmt.Printf("获取窗口大小失败: %v\n", err)
		return
	}

	fmt.Printf("终端窗口大小: 行=%d, 列=%d\n", ws.Row, ws.Col)
}
```

**假设的输入与输出:**

* **输入:**  运行上述 Go 程序在一个终端中。
* **输出:**  终端窗口的行数和列数，例如：`终端窗口大小: 行=24, 列=80`。如果获取失败，则会输出错误信息。

**代码推理:**

1. **`syscall.Stdout`:**  获取标准输出的文件描述符。
2. **`syscall.SYS_IOCTL`:**  指定要执行的系统调用是 `ioctl`。
3. **`uintptr(fd)`:** 将文件描述符转换为 `uintptr` 作为 `ioctl` 的第一个参数。
4. **`uintptr(TIOCGWINSZ)`:** 将 `TIOCGWINSZ` 常量转换为 `uintptr` 作为 `ioctl` 的第二个参数，指定要执行的操作。
5. **`uintptr(unsafe.Pointer(&ws))`:** 将 `winsize` 结构体的地址转换为 `uintptr` 作为 `ioctl` 的第三个参数，用于接收返回的窗口大小信息。
6. **`syscall.Syscall`:** 执行系统调用，并返回结果 (通常是 0 表示成功，非零表示错误) 和可能的错误。
7. **错误处理:** 检查 `err` 是否为非零，如果是，则表示 `ioctl` 调用失败，打印错误信息。

**使用者易犯错的点:**

* **直接使用数值而不是常量:**  开发者可能会直接使用像 `0x40087468` 这样的魔术数字，而不是使用 `TIOCGWINSZ` 这样的常量，降低了代码的可读性和可维护性。如果底层数值发生变化，则需要手动修改所有使用的地方。
* **不正确的类型转换:** 在使用 `syscall` 包进行系统调用时，需要将参数正确地转换为 `uintptr`，并且要确保传递的结构体指针是正确的。
* **忽略错误处理:**  系统调用可能会失败，因此必须检查返回值和错误信息，并进行适当的处理。

**归纳一下它的功能 (第2部分):**

作为整个 `zerrors_openbsd_386.go` 文件的一部分，这个代码片段的主要功能是为 Go 语言在 OpenBSD 386 架构上进行系统编程提供必要的常量定义。它涵盖了用于设备控制的 IO 控制命令、系统调用可能返回的错误代码以及进程间通信和控制的信号。这些常量使得 Go 程序员能够以类型安全且易于理解的方式与底层的 OpenBSD 内核进行交互，而无需记住和硬编码具体的数值。它通过提供预定义的常量，提高了代码的可读性、可维护性和跨平台兼容性（在同一操作系统族的不同架构之间）。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_386.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	TIOCGTSTAMP                       = 0x400c745b
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