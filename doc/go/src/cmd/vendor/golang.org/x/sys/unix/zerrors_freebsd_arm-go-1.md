Response:
The user is asking for the functionalities of a Go file defining constants for the FreeBSD ARM architecture related to system calls, errors, and signals.

**Plan:**

1. **Identify the core function:** The file primarily defines constants.
2. **Categorize the constants:**  Group them into system call related constants (likely involving `ioctl`), error codes, and signals.
3. **Explain the purpose of each category:** Describe why these constants are needed in system-level programming.
4. **Provide a Go code example:**  Show a hypothetical use case for one of the constants, focusing on `ioctl` as there are many constants starting with `TIOC`.
5. **Summarize the file's overall function.**
这个Go语言文件 (`go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_freebsd_arm.go`) 的主要功能是**定义了在FreeBSD ARM架构下进行系统调用时使用的一系列常量**。

这些常量可以大致分为以下几类：

1. **TCP选项常量 (TCP_*)**: 这些常量用于设置或获取TCP连接的特定选项，例如拥塞控制算法、延迟确认、时间戳等。它们允许程序更精细地控制TCP的行为。

2. **RACK相关常量 (TCP_RACK_*)**:  RACK（Recent ACKnowledgment）是TCP的一种拥塞控制算法。这些常量用于配置和控制RACK算法的各种参数。

3. **终端控制常量 (TIOCCBRK, TIOCCDTR, 等)**:  这些常量用于 `ioctl` 系统调用，用于对终端设备进行各种控制操作，例如发送断开信号、控制DTR信号线、刷新输入/输出队列、获取/设置终端属性、获取窗口大小等。

4. **定时器常量 (TIMER_ABSTIME, TIMER_RELTIME)**: 用于指定定时器是绝对时间还是相对时间。

5. **`ioctl` 系统调用相关的其他常量 (TIOCPKT_*, TIOCM_*)**:  这些常量也是用于 `ioctl` 系统调用，用于更底层的终端控制，例如设置数据包模式、控制调制解调器线路状态（如CARRIER DETECT, CLEAR TO SEND）。

6. **进程状态常量 (TOSTOP)**:  用于表示进程停止的原因。

7. **`utime` 系统调用常量 (UTIME_NOW, UTIME_OMIT)**: 用于 `utimes` 系统调用，允许将文件访问或修改时间设置为当前时间或保持不变。

8. **终端字符常量 (VDISCARD, VDSUSP, 等)**: 定义了终端特殊字符的含义，例如擦除字符、挂起字符、行尾字符等。

9. **`wait` 系统调用常量 (WCONTINUED, WEXITED, 等)**:  定义了 `wait` 系列系统调用的选项，用于判断子进程的状态（例如是否已退出、是否被信号停止）。

10. **错误码常量 (E2BIG, EACCES, 等)**:  定义了各种系统调用可能返回的错误码，方便程序判断操作失败的原因。

11. **信号常量 (SIGABRT, SIGALRM, 等)**: 定义了各种信号的编号，程序可以使用这些常量来捕获或发送信号。

12. **错误码和信号的描述性信息**:  `errorList` 和 `signalList` 变量提供了错误码和信号的名称和描述，方便程序员理解其含义。

**它是什么Go语言功能的实现：**

这个文件是 `syscall` 标准库的一部分，它提供了对底层操作系统系统调用的访问。更具体地说，它为 FreeBSD ARM 架构定义了与系统调用相关的常量。Go 语言通过 `syscall` 包来抽象不同操作系统的系统调用接口，使得 Go 程序可以在不同平台上运行，而无需修改大量的系统调用代码。

**Go代码举例说明 (关于 `ioctl` 和终端控制):**

假设我们想要获取当前终端的窗口大小。可以使用 `syscall.Syscall` 来调用底层的 `ioctl` 系统调用，并使用 `TIOCGWINSZ` 常量来指定操作类型。

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// 定义 winsize 结构体，与 C 语言中的 struct winsize 对应
type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func main() {
	// 假设输入的是标准输出的文件描述符
	fd := int(os.Stdout.Fd())

	var ws winsize
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if err != 0 {
		fmt.Println("获取窗口大小失败:", err)
		return
	}

	fmt.Printf("窗口大小: 行=%d, 列=%d\n", ws.Row, ws.Col)
}
```

**假设的输入与输出:**

* **输入:**  程序的标准输出连接到一个终端。
* **输出:**  例如 `窗口大小: 行=24, 列=80` (实际输出取决于终端的设置)。

**命令行参数的具体处理:**

这个代码片段本身不处理命令行参数。它定义的是常量，这些常量通常会被其他使用 `syscall` 包的代码所引用。那些引用这些常量的代码可能会处理命令行参数，以决定是否进行某些系统调用操作。

**使用者易犯错的点:**

* **常量值的平台依赖性:**  这些常量的值在不同的操作系统和架构下可能不同。直接硬编码这些常量值在跨平台程序中是不可取的。应该使用 `syscall` 包提供的平台相关的常量。
* **不理解 `ioctl` 的含义:**  `ioctl` 是一个功能非常强大的系统调用，但也很复杂。不理解其具体操作的含义可能会导致错误的使用，甚至导致系统不稳定。
* **结构体内存布局:**  在使用 `ioctl` 时，需要传递结构体指针。必须确保 Go 语言中定义的结构体与底层 C 语言结构体的内存布局完全一致，否则会导致数据解析错误。

**功能归纳 (第2部分):**

总而言之，这个 `zerrors_freebsd_arm.go` 文件在 Go 语言的 `syscall` 包中扮演着**为 FreeBSD ARM 架构提供底层系统调用接口定义**的关键角色。它通过定义一系列常量，使得 Go 程序能够以平台特定的方式与操作系统内核进行交互，进行诸如网络配置、终端控制、进程管理等底层操作。这些常量是构建更高级抽象的基础，使得 Go 语言能够跨平台运行的同时，也能充分利用底层操作系统的特定功能。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_freebsd_arm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
      = 0x446
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