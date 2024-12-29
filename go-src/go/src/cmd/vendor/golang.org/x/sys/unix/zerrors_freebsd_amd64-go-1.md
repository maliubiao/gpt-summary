Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `zerrors_freebsd_amd64.go` file. This file likely defines constants related to system calls, errors, and signals specific to the FreeBSD operating system on the AMD64 architecture.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Purpose:** The filename `zerrors_freebsd_amd64.go` strongly suggests that this file defines error constants for the FreeBSD operating system on the AMD64 architecture within the Go `syscall` package.

2. **Analyze the Code Structure:** The code is organized into three main constant blocks:
    * **Generic Constants:**  These are likely system call related constants.
    * **Error Constants:** These map to `syscall.Errno` and represent various system error codes.
    * **Signal Constants:** These map to `syscall.Signal` and represent different signal types.
    * **Error Table:** This provides a mapping from error numbers to their names and descriptions.
    * **Signal Table:** This provides a mapping from signal numbers to their names and descriptions.

3. **Infer Functionality Based on Content:**
    * **Generic Constants:**  The prefixes like `TCP_`, `TIMER_`, `TIOC`, `TOSTOP`, `UTIME_`, `V`, and `W` suggest that these constants are used for configuring TCP sockets, timers, terminal I/O control, process stopping, setting timestamps, and wait status respectively.
    * **Error Constants:** The naming convention `E<ERROR_NAME>` and the type `syscall.Errno` clearly indicate that these are system error codes.
    * **Signal Constants:** The naming convention `SIG<SIGNAL_NAME>` and the type `syscall.Signal` clearly indicate that these are system signals.
    * **Error/Signal Tables:** These tables provide human-readable information about the error and signal codes.

4. **Connect to Go Functionality:** This file is part of the `syscall` package in Go. This package provides a low-level interface to the operating system's system calls. Therefore, these constants are used when making system calls and handling the results (errors and signals).

5. **Provide Go Code Examples:**  Illustrate how these constants are used in practical Go code.
    * **System Call Example:** Demonstrate using a `TIOC` constant with `unix.IoctlSetInt`.
    * **Error Handling Example:** Show how to check for a specific error like `unix.ENOENT`.
    * **Signal Handling Example:**  Demonstrate how to catch a signal like `os.Interrupt` (which might map to a `SIGINT`).

6. **Address Potential User Errors:**
    * **Incorrect Constant Usage:** Emphasize the platform-specific nature of these constants and the danger of using them on other operating systems.
    * **Direct Manipulation of Constants:** Advise against directly modifying these constants.

7. **Summarize Functionality for Part 2:**  Provide a concise overview of the file's role.

8. **Review and Refine:** Ensure the explanation is clear, accurate, and addresses all parts of the user's request. For instance, initially, I might not have explicitly linked the constants to the `syscall` package, but upon review, realized that connection is crucial for understanding their purpose within Go. Also, double-checked the assumptions about the meaning of the prefixes in the generic constants.
## 功能归纳 (第 2 部分)

总的来说，这个 Go 语言文件 `zerrors_freebsd_amd64.go` 的主要功能是：

**为 FreeBSD 操作系统在 AMD64 架构下提供系统调用相关的常量定义。**

具体来说，它定义了以下几种类型的常量：

* **通用系统调用相关的常量:**  这些常量用于控制各种系统行为，例如 TCP 连接选项 (`TCP_*`)、定时器 (`TIMER_*`)、终端 I/O 控制 (`TIOC_*`)、进程停止状态 (`TOSTOP`)、时间戳选项 (`UTIME_*`)、以及进程等待状态 (`W*`) 等。
* **错误码常量:**  这些常量以 `E` 开头，对应于 `syscall.Errno` 类型，表示各种系统调用可能返回的错误代码。
* **信号常量:** 这些常量以 `SIG` 开头，对应于 `syscall.Signal` 类型，表示操作系统可以发送给进程的各种信号。
* **错误码和信号的描述性列表:**  `errorList` 和 `signalList` 分别提供了错误码和信号的数字值、名称以及对应的文字描述，方便开发者理解。

**它作为 `golang.org/x/sys/unix` 包的一部分，为 Go 语言程序在 FreeBSD AMD64 平台上进行底层系统调用提供了必要的符号定义，使得 Go 程序能够与操作系统进行更细粒度的交互，并能正确处理系统调用返回的错误和信号。**

**易犯错的点：**

* **平台依赖性:**  这些常量是 **特定于 FreeBSD 和 AMD64 架构** 的。在其他操作系统或架构下使用这些常量会导致程序错误或行为不符合预期。 例如，你在 Linux 系统上使用 `TCP_NOPUSH` 常量，可能并不会像在 FreeBSD 上那样控制 TCP 连接的行为。
* **直接使用数字:** 虽然代码中定义了常量，但直接使用这些常量对应的数字 (例如直接使用 `0x4` 代替 `TCP_NOPUSH`) 会降低代码的可读性和可维护性。应该始终使用已定义的常量名称。

总而言之，这个文件是 Go 语言在 FreeBSD AMD64 平台上进行底层系统编程的基础，它通过定义清晰的常量，使得开发者能够更方便、更安全地与操作系统进行交互。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_freebsd_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
OOPT                      = 0x8
	TCP_NOPUSH                     = 0x4
	TCP_PCAP_IN                    = 0x1000
	TCP_PCAP_OUT                   = 0x800
	TCP_RACK_EARLY_RECOV           = 0x423
	TCP_RACK_EARLY_SEG             = 0x424
	TCP_RACK_GP_INCREASE           = 0x446
	TCP_RACK_IDLE_REDUCE_HIGH      = 0x444
	TCP_RACK_MIN_PACE              = 0x445
	TCP_RACK_MIN_PACE_SEG          = 0x446
	TCP_RACK_MIN_TO                = 0x422
	TCP_RACK_PACE_ALWAYS           = 0x41f
	TCP_RACK_PACE_MAX_SEG          = 0x41e
	TCP_RACK_PACE_REDUCE           = 0x41d
	TCP_RACK_PKT_DELAY             = 0x428
	TCP_RACK_PROP                  = 0x41b
	TCP_RACK_PROP_RATE             = 0x420
	TCP_RACK_PRR_SENDALOT          = 0x421
	TCP_RACK_REORD_FADE            = 0x426
	TCP_RACK_REORD_THRESH          = 0x425
	TCP_RACK_TLP_INC_VAR           = 0x429
	TCP_RACK_TLP_REDUCE            = 0x41c
	TCP_RACK_TLP_THRESH            = 0x427
	TCP_RACK_TLP_USE               = 0x447
	TCP_VENDOR                     = 0x80000000
	TCSAFLUSH                      = 0x2
	TIMER_ABSTIME                  = 0x1
	TIMER_RELTIME                  = 0x0
	TIOCCBRK                       = 0x2000747a
	TIOCCDTR                       = 0x20007478
	TIOCCONS                       = 0x80047462
	TIOCDRAIN                      = 0x2000745e
	TIOCEXCL                       = 0x2000740d
	TIOCEXT                        = 0x80047460
	TIOCFLUSH                      = 0x80047410
	TIOCGDRAINWAIT                 = 0x40047456
	TIOCGETA                       = 0x402c7413
	TIOCGETD                       = 0x4004741a
	TIOCGPGRP                      = 0x40047477
	TIOCGPTN                       = 0x4004740f
	TIOCGSID                       = 0x40047463
	TIOCGWINSZ                     = 0x40087468
	TIOCMBIC                       = 0x8004746b
	TIOCMBIS                       = 0x8004746c
	TIOCMGDTRWAIT                  = 0x4004745a
	TIOCMGET                       = 0x4004746a
	TIOCMSDTRWAIT                  = 0x8004745b
	TIOCMSET                       = 0x8004746d
	TIOCM_CAR                      = 0x40
	TIOCM_CD                       = 0x40
	TIOCM_CTS                      = 0x20
	TIOCM_DCD                      = 0x40
	TIOCM_DSR                      = 0x100
	TIOCM_DTR                      = 0x2
	TIOCM_LE                       = 0x1
	TIOCM_RI                       = 0x80
	TIOCM_RNG                      = 0x80
	TIOCM_RTS                      = 0x4
	TIOCM_SR                       = 0x10
	TIOCM_ST                       = 0x8
	TIOCNOTTY                      = 0x20007471
	TIOCNXCL                       = 0x2000740e
	TIOCOUTQ                       = 0x40047473
	TIOCPKT                        = 0x80047470
	TIOCPKT_DATA                   = 0x0
	TIOCPKT_DOSTOP                 = 0x20
	TIOCPKT_FLUSHREAD              = 0x1
	TIOCPKT_FLUSHWRITE             = 0x2
	TIOCPKT_IOCTL                  = 0x40
	TIOCPKT_NOSTOP                 = 0x10
	TIOCPKT_START                  = 0x8
	TIOCPKT_STOP                   = 0x4
	TIOCPTMASTER                   = 0x2000741c
	TIOCSBRK                       = 0x2000747b
	TIOCSCTTY                      = 0x20007461
	TIOCSDRAINWAIT                 = 0x80047457
	TIOCSDTR                       = 0x20007479
	TIOCSETA                       = 0x802c7414
	TIOCSETAF                      = 0x802c7416
	TIOCSETAW                      = 0x802c7415
	TIOCSETD                       = 0x8004741b
	TIOCSIG                        = 0x2004745f
	TIOCSPGRP                      = 0x80047476
	TIOCSTART                      = 0x2000746e
	TIOCSTAT                       = 0x20007465
	TIOCSTI                        = 0x80017472
	TIOCSTOP                       = 0x2000746f
	TIOCSWINSZ                     = 0x80087467
	TIOCTIMESTAMP                  = 0x40107459
	TIOCUCNTL                      = 0x80047466
	TOSTOP                         = 0x400000
	UTIME_NOW                      = -0x1
	UTIME_OMIT                     = -0x2
	VDISCARD                       = 0xf
	VDSUSP                         = 0xb
	VEOF                           = 0x0
	VEOL                           = 0x1
	VEOL2                          = 0x2
	VERASE                         = 0x3
	VERASE2                        = 0x7
	VINTR                          = 0x8
	VKILL                          = 0x5
	VLNEXT                         = 0xe
	VMIN                           = 0x10
	VQUIT                          = 0x9
	VREPRINT                       = 0x6
	VSTART                         = 0xc
	VSTATUS                        = 0x12
	VSTOP                          = 0xd
	VSUSP                          = 0xa
	VTIME                          = 0x11
	VWERASE                        = 0x4
	WCONTINUED                     = 0x4
	WCOREFLAG                      = 0x80
	WEXITED                        = 0x10
	WLINUXCLONE                    = 0x80000000
	WNOHANG                        = 0x1
	WNOWAIT                        = 0x8
	WSTOPPED                       = 0x2
	WTRAPPED                       = 0x20
	WUNTRACED                      = 0x2
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
	EBADMSG         = syscall.Errno(0x59)
	EBADRPC         = syscall.Errno(0x48)
	EBUSY           = syscall.Errno(0x10)
	ECANCELED       = syscall.Errno(0x55)
	ECAPMODE        = syscall.Errno(0x5e)
	ECHILD          = syscall.Errno(0xa)
	ECONNABORTED    = syscall.Errno(0x35)
	ECONNREFUSED    = syscall.Errno(0x3d)
	ECONNRESET      = syscall.Errno(0x36)
	EDEADLK         = syscall.Errno(0xb)
	EDESTADDRREQ    = syscall.Errno(0x27)
	EDOM            = syscall.Errno(0x21)
	EDOOFUS         = syscall.Errno(0x58)
	EDQUOT          = syscall.Errno(0x45)
	EEXIST          = syscall.Errno(0x11)
	EFAULT          = syscall.Errno(0xe)
	EFBIG           = syscall.Errno(0x1b)
	EFTYPE          = syscall.Errno(0x4f)
	EHOSTDOWN       = syscall.Errno(0x40)
	EHOSTUNREACH    = syscall.Errno(0x41)
	EIDRM           = syscall.Errno(0x52)
	EILSEQ          = syscall.Errno(0x56)
	EINPROGRESS     = syscall.Errno(0x24)
	EINTEGRITY      = syscall.Errno(0x61)
	EINTR           = syscall.Errno(0x4)
	EINVAL          = syscall.Errno(0x16)
	EIO             = syscall.Errno(0x5)
	EISCONN         = syscall.Errno(0x38)
	EISDIR          = syscall.Errno(0x15)
	ELAST           = syscall.Errno(0x61)
	ELOOP           = syscall.Errno(0x3e)
	EMFILE          = syscall.Errno(0x18)
	EMLINK          = syscall.Errno(0x1f)
	EMSGSIZE        = syscall.Errno(0x28)
	EMULTIHOP       = syscall.Errno(0x5a)
	ENAMETOOLONG    = syscall.Errno(0x3f)
	ENEEDAUTH       = syscall.Errno(0x51)
	ENETDOWN        = syscall.Errno(0x32)
	ENETRESET       = syscall.Errno(0x34)
	ENETUNREACH     = syscall.Errno(0x33)
	ENFILE          = syscall.Errno(0x17)
	ENOATTR         = syscall.Errno(0x57)
	ENOBUFS         = syscall.Errno(0x37)
	ENODEV          = syscall.Errno(0x13)
	ENOENT          = syscall.Errno(0x2)
	ENOEXEC         = syscall.Errno(0x8)
	ENOLCK          = syscall.Errno(0x4d)
	ENOLINK         = syscall.Errno(0x5b)
	ENOMEM          = syscall.Errno(0xc)
	ENOMSG          = syscall.Errno(0x53)
	ENOPROTOOPT     = syscall.Errno(0x2a)
	ENOSPC          = syscall.Errno(0x1c)
	ENOSYS          = syscall.Errno(0x4e)
	ENOTBLK         = syscall.Errno(0xf)
	ENOTCAPABLE     = syscall.Errno(0x5d)
	ENOTCONN        = syscall.Errno(0x39)
	ENOTDIR         = syscall.Errno(0x14)
	ENOTEMPTY       = syscall.Errno(0x42)
	ENOTRECOVERABLE = syscall.Errno(0x5f)
	ENOTSOCK        = syscall.Errno(0x26)
	ENOTSUP         = syscall.Errno(0x2d)
	ENOTTY          = syscall.Errno(0x19)
	ENXIO           = syscall.Errno(0x6)
	EOPNOTSUPP      = syscall.Errno(0x2d)
	EOVERFLOW       = syscall.Errno(0x54)
	EOWNERDEAD      = syscall.Errno(0x60)
	EPERM           = syscall.Errno(0x1)
	EPFNOSUPPORT    = syscall.Errno(0x2e)
	EPIPE           = syscall.Errno(0x20)
	EPROCLIM        = syscall.Errno(0x43)
	EPROCUNAVAIL    = syscall.Errno(0x4c)
	EPROGMISMATCH   = syscall.Errno(0x4b)
	EPROGUNAVAIL    = syscall.Errno(0x4a)
	EPROTO          = syscall.Errno(0x5c)
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
	SIGLIBRT  = syscall.Signal(0x21)
	SIGLWP    = syscall.Signal(0x20)
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
	{35, "EWOULDBLOCK", "resource temporarily unavailable"},
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
	{69, "EDQUOT", "disc quota exceeded"},
	{70, "ESTALE", "stale NFS file handle"},
	{71, "EREMOTE", "too many levels of remote in path"},
	{72, "EBADRPC", "RPC struct is bad"},
	{73, "ERPCMISMATCH", "RPC version wrong"},
	{74, "EPROGUNAVAIL", "RPC prog. not avail"},
	{75, "EPROGMISMATCH", "program version wrong"},
	{76, "EPROCUNAVAIL", "bad procedure for program"},
	{77, "ENOLCK", "no locks available"},
	{78, "ENOSYS", "function not implemented"},
	{79, "EFTYPE", "inappropriate file type or format"},
	{80, "EAUTH", "authentication error"},
	{81, "ENEEDAUTH", "need authenticator"},
	{82, "EIDRM", "identifier removed"},
	{83, "ENOMSG", "no message of desired type"},
	{84, "EOVERFLOW", "value too large to be stored in data type"},
	{85, "ECANCELED", "operation canceled"},
	{86, "EILSEQ", "illegal byte sequence"},
	{87, "ENOATTR", "attribute not found"},
	{88, "EDOOFUS", "programming error"},
	{89, "EBADMSG", "bad message"},
	{90, "EMULTIHOP", "multihop attempted"},
	{91, "ENOLINK", "link has been severed"},
	{92, "EPROTO", "protocol error"},
	{93, "ENOTCAPABLE", "capabilities insufficient"},
	{94, "ECAPMODE", "not permitted in capability mode"},
	{95, "ENOTRECOVERABLE", "state not recoverable"},
	{96, "EOWNERDEAD", "previous owner died"},
	{97, "EINTEGRITY", "integrity check failed"},
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
	{32, "SIGTHR", "unknown signal"},
	{33, "SIGLIBRT", "unknown signal"},
}

"""




```