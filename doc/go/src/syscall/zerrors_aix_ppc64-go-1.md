Response:
The user has provided the second part of a Go source code file, `zerrors_aix_ppc64.go`, which defines constants for system calls, errors, and signals specific to the AIX operating system on the ppc64 architecture. The first part likely contained similar definitions.

The goal is to summarize the functionality of this second part and, combining it with the knowledge from the first part (implicitly), provide a complete overview.

**Breakdown of the content:**

1. **Constant Definitions:** The code defines a large number of constants. These constants are categorized into:
    *   System call related constants (starting with `S_`, `TC`, `TIO`, etc.)
    *   TCP related constants (starting with `TCP_`)
    *   Error numbers (starting with `E`)
    *   Signal numbers (starting with `SIG`)

2. **Error Table:**  The `errors` variable is a string array mapping error numbers to their textual descriptions.

3. **Signal Table:** The `signals` variable is a string array mapping signal numbers to their textual descriptions.

**Combining with the knowledge of the first part:**

The first part likely defined similar constants and potentially other data structures relevant to system calls on AIX ppc64. The combination of both parts provides a comprehensive set of system-level definitions.

**High-level Functionality:**

This file provides Go programs with a way to interact with the underlying AIX operating system. It defines the necessary constants and data structures that Go's `syscall` package uses to make system calls, handle errors, and manage signals.

**Reasoning for the file name:**

*   `zerrors`:  Indicates that this file likely auto-generates some of its content (the 'z' prefix is common for such files in Go's standard library). It also deals with error definitions.
*   `aix`: Specifies the target operating system.
*   `ppc64`: Specifies the target architecture.

**Steps to generate the summary:**

1. Identify the main categories of constants and data structures.
2. Explain the purpose of each category.
3. Infer how these elements are used within the `syscall` package.
4. Combine the functionality of both parts (even without seeing the first part explicitly, the pattern is clear).
这是 `go/src/syscall/zerrors_aix_ppc64.go` 文件的第二部分，与第一部分结合来看，其主要功能是为 Go 语言在 AIX (IBM 的 Unix 操作系统) 的 ppc64 架构上进行系统调用提供必要的常量定义和错误、信号的文本描述。

**归纳一下它的功能:**

这部分代码主要定义了以下内容，它们是 Go 语言 `syscall` 包在 AIX ppc64 平台上与操作系统底层交互的基础：

1. **系统调用相关的常量:**  定义了大量的常量，用于表示各种系统调用相关的参数、选项和标志。例如：
    *   以 `S_` 开头的常量，可能与文件系统操作相关。
    *   以 `TC` 开头的常量，可能与终端控制相关。
    *   以 `TIO` 开头的常量，可能与终端 I/O 控制相关。
    *   以 `TCP_` 开头的常量，用于配置 TCP 网络连接的选项。

2. **错误码常量:** 定义了以 `E` 开头的常量，它们对应 AIX 操作系统返回的各种错误码。每个常量都被转换为 `syscall.Errno` 类型，方便 Go 程序处理系统调用返回的错误。

3. **信号常量:** 定义了以 `SIG` 开头的常量，它们对应 AIX 操作系统支持的各种信号。每个常量都被转换为 `syscall.Signal` 类型，用于 Go 程序处理和发送信号。

4. **错误码到错误信息的映射表 (`errors` 变量):**  提供了一个字符串数组，将错误码（`Errno` 类型）映射到对应的文本描述，方便开发者理解错误原因。

5. **信号到信号名称的映射表 (`signals` 变量):** 提供了一个字符串数组，将信号（`Signal` 类型）映射到对应的文本名称，方便开发者理解接收到的信号类型。

**总而言之，这部分代码和第一部分一起，是 Go 语言在 AIX ppc64 平台上进行底层系统编程的“字典”和“说明书”，它定义了 Go 程序与 AIX 内核交互时使用的各种“术语”（常量）以及这些“术语”的含义（错误和信号的文本描述）。**

由于这是第二部分，我们可以推断出第一部分可能包含了其他一些基础的常量定义，例如文件访问权限、文件状态标志等。这两部分共同构成了 `syscall` 包在 AIX ppc64 平台上的完整定义。

**代码推理和示例 (假设)：**

假设我们想在 AIX ppc64 平台上使用 Go 语言来设置一个 TCP 连接的 `NODELAY` 选项，我们可以推断出 `TCP_NODELAY` 常量会被使用。

```go
package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		fmt.Println("Error getting raw connection:", err)
		return
	}

	err = rawConn.Control(func(fd uintptr) {
		// 假设 TCP_NODELAY 在 zerrors_aix_ppc64.go 中定义
		err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		if err != nil {
			fmt.Println("Error setting TCP_NODELAY:", err)
		} else {
			fmt.Println("Successfully set TCP_NODELAY")
		}
	})

	if err != nil {
		fmt.Println("Error controlling raw connection:", err)
	}
}
```

**假设的输入与输出：**

如果连接成功，并且 `syscall.TCP_NODELAY` 常量在 `zerrors_aix_ppc64.go` 中被正确定义为 `1`，那么输出可能是：

```
Successfully set TCP_NODELAY
```

如果连接失败，或者设置 `TCP_NODELAY` 选项失败，则会输出相应的错误信息。

**命令行参数的具体处理：**

这部分代码主要定义常量和数据结构，并不直接处理命令行参数。命令行参数的处理通常发生在应用程序的 `main` 函数中，或者由相关的库函数来处理。`syscall` 包提供的常量可以被使用在处理网络配置等需要与操作系统交互的场景中，这些配置信息可能来源于命令行参数。

**使用者易犯错的点：**

在直接使用 `syscall` 包进行系统编程时，常见的错误包括：

1. **错误码理解错误：**  不理解每个错误码的具体含义，导致处理错误的方式不正确。例如，将临时的资源不可用错误（如 `EAGAIN`）当作永久性错误处理。
2. **信号处理不当：**  忽略或错误地处理信号可能导致程序行为异常甚至崩溃。例如，没有正确处理 `SIGCHLD` 信号可能导致僵尸进程。
3. **常量使用错误：** 使用了不适用于当前操作系统或架构的常量。虽然这个文件是特定于 AIX ppc64 的，但在编写跨平台代码时，需要注意不同平台常量的差异。
4. **直接操作文件描述符的风险：**  直接使用 `syscall` 操作文件描述符需要非常谨慎，容易引发资源泄露或其他问题。建议尽可能使用 Go 标准库中更高级的封装。

**总结：**

总的来说，`go/src/syscall/zerrors_aix_ppc64.go` 的第二部分延续了第一部分的功能，共同为 Go 语言在 AIX ppc64 平台上提供了与操作系统进行底层交互所需的常量、错误码和信号定义以及相应的文本描述，是 Go 语言 `syscall` 包在该平台上实现其功能的关键组成部分。它使得 Go 程序员能够执行如文件操作、网络编程、进程控制等需要直接与操作系统交互的任务。

Prompt: 
```
这是路径为go/src/syscall/zerrors_aix_ppc64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
RESFMT7                     = 0x28000000
	S_RESFMT8                     = 0x2c000000
	S_WRBAND                      = 0x80
	S_WRNORM                      = 0x40
	TCIFLUSH                      = 0x0
	TCIOFLUSH                     = 0x2
	TCOFLUSH                      = 0x1
	TCP_24DAYS_WORTH_OF_SLOWTICKS = 0x3f4800
	TCP_ACLADD                    = 0x23
	TCP_ACLBIND                   = 0x26
	TCP_ACLCLEAR                  = 0x22
	TCP_ACLDEL                    = 0x24
	TCP_ACLDENY                   = 0x8
	TCP_ACLFLUSH                  = 0x21
	TCP_ACLGID                    = 0x1
	TCP_ACLLS                     = 0x25
	TCP_ACLSUBNET                 = 0x4
	TCP_ACLUID                    = 0x2
	TCP_CWND_DF                   = 0x16
	TCP_CWND_IF                   = 0x15
	TCP_DELAY_ACK_FIN             = 0x2
	TCP_DELAY_ACK_SYN             = 0x1
	TCP_FASTNAME                  = 0x101080a
	TCP_KEEPCNT                   = 0x13
	TCP_KEEPIDLE                  = 0x11
	TCP_KEEPINTVL                 = 0x12
	TCP_LSPRIV                    = 0x29
	TCP_LUID                      = 0x20
	TCP_MAXBURST                  = 0x8
	TCP_MAXDF                     = 0x64
	TCP_MAXIF                     = 0x64
	TCP_MAXSEG                    = 0x2
	TCP_MAXWIN                    = 0xffff
	TCP_MAXWINDOWSCALE            = 0xe
	TCP_MAX_SACK                  = 0x4
	TCP_MSS                       = 0x5b4
	TCP_NODELAY                   = 0x1
	TCP_NODELAYACK                = 0x14
	TCP_NOREDUCE_CWND_EXIT_FRXMT  = 0x19
	TCP_NOREDUCE_CWND_IN_FRXMT    = 0x18
	TCP_NOTENTER_SSTART           = 0x17
	TCP_OPT                       = 0x19
	TCP_RFC1323                   = 0x4
	TCP_SETPRIV                   = 0x27
	TCP_STDURG                    = 0x10
	TCP_TIMESTAMP_OPTLEN          = 0xc
	TCP_UNSETPRIV                 = 0x28
	TCSAFLUSH                     = 0x2
	TIOCCBRK                      = 0x2000747a
	TIOCCDTR                      = 0x20007478
	TIOCCONS                      = 0xffffffff80047462
	TIOCEXCL                      = 0x2000740d
	TIOCFLUSH                     = 0xffffffff80047410
	TIOCGETC                      = 0x40067412
	TIOCGETD                      = 0x40047400
	TIOCGETP                      = 0x40067408
	TIOCGLTC                      = 0x40067474
	TIOCGPGRP                     = 0x40047477
	TIOCGSID                      = 0x40047448
	TIOCGSIZE                     = 0x40087468
	TIOCGWINSZ                    = 0x40087468
	TIOCHPCL                      = 0x20007402
	TIOCLBIC                      = 0xffffffff8004747e
	TIOCLBIS                      = 0xffffffff8004747f
	TIOCLGET                      = 0x4004747c
	TIOCLSET                      = 0xffffffff8004747d
	TIOCMBIC                      = 0xffffffff8004746b
	TIOCMBIS                      = 0xffffffff8004746c
	TIOCMGET                      = 0x4004746a
	TIOCMIWAIT                    = 0xffffffff80047464
	TIOCMODG                      = 0x40047403
	TIOCMODS                      = 0xffffffff80047404
	TIOCMSET                      = 0xffffffff8004746d
	TIOCM_CAR                     = 0x40
	TIOCM_CD                      = 0x40
	TIOCM_CTS                     = 0x20
	TIOCM_DSR                     = 0x100
	TIOCM_DTR                     = 0x2
	TIOCM_LE                      = 0x1
	TIOCM_RI                      = 0x80
	TIOCM_RNG                     = 0x80
	TIOCM_RTS                     = 0x4
	TIOCM_SR                      = 0x10
	TIOCM_ST                      = 0x8
	TIOCNOTTY                     = 0x20007471
	TIOCNXCL                      = 0x2000740e
	TIOCOUTQ                      = 0x40047473
	TIOCPKT                       = 0xffffffff80047470
	TIOCPKT_DATA                  = 0x0
	TIOCPKT_DOSTOP                = 0x20
	TIOCPKT_FLUSHREAD             = 0x1
	TIOCPKT_FLUSHWRITE            = 0x2
	TIOCPKT_NOSTOP                = 0x10
	TIOCPKT_START                 = 0x8
	TIOCPKT_STOP                  = 0x4
	TIOCREMOTE                    = 0xffffffff80047469
	TIOCSBRK                      = 0x2000747b
	TIOCSDTR                      = 0x20007479
	TIOCSETC                      = 0xffffffff80067411
	TIOCSETD                      = 0xffffffff80047401
	TIOCSETN                      = 0xffffffff8006740a
	TIOCSETP                      = 0xffffffff80067409
	TIOCSLTC                      = 0xffffffff80067475
	TIOCSPGRP                     = 0xffffffff80047476
	TIOCSSIZE                     = 0xffffffff80087467
	TIOCSTART                     = 0x2000746e
	TIOCSTI                       = 0xffffffff80017472
	TIOCSTOP                      = 0x2000746f
	TIOCSWINSZ                    = 0xffffffff80087467
	TIOCUCNTL                     = 0xffffffff80047466
	TOSTOP                        = 0x10000
	VDISCRD                       = 0xc
	VDSUSP                        = 0xa
	VEOF                          = 0x4
	VEOL                          = 0x5
	VEOL2                         = 0x6
	VERASE                        = 0x2
	VINTR                         = 0x0
	VKILL                         = 0x3
	VLNEXT                        = 0xe
	VMIN                          = 0x4
	VQUIT                         = 0x1
	VREPRINT                      = 0xb
	VSTART                        = 0x7
	VSTOP                         = 0x8
	VSTRT                         = 0x7
	VSUSP                         = 0x9
	VT0                           = 0x0
	VT1                           = 0x8000
	VTDELAY                       = 0x2000
	VTDLY                         = 0x8000
	VTIME                         = 0x5
	VWERSE                        = 0xd
	WPARSTART                     = 0x1
	WPARSTOP                      = 0x2
	WPARTTYNAME                   = "Global"
	_FDATAFLUSH                   = 0x2000000000
)

// Errors
const (
	E2BIG           = Errno(0x7)
	EACCES          = Errno(0xd)
	EADDRINUSE      = Errno(0x43)
	EADDRNOTAVAIL   = Errno(0x44)
	EAFNOSUPPORT    = Errno(0x42)
	EAGAIN          = Errno(0xb)
	EALREADY        = Errno(0x38)
	EBADF           = Errno(0x9)
	EBADMSG         = Errno(0x78)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x75)
	ECHILD          = Errno(0xa)
	ECHRNG          = Errno(0x25)
	ECLONEME        = Errno(0x52)
	ECONNABORTED    = Errno(0x48)
	ECONNREFUSED    = Errno(0x4f)
	ECONNRESET      = Errno(0x49)
	ECORRUPT        = Errno(0x59)
	EDEADLK         = Errno(0x2d)
	EDESTADDREQ     = Errno(0x3a)
	EDESTADDRREQ    = Errno(0x3a)
	EDIST           = Errno(0x35)
	EDOM            = Errno(0x21)
	EDQUOT          = Errno(0x58)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EFORMAT         = Errno(0x30)
	EHOSTDOWN       = Errno(0x50)
	EHOSTUNREACH    = Errno(0x51)
	EIDRM           = Errno(0x24)
	EILSEQ          = Errno(0x74)
	EINPROGRESS     = Errno(0x37)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EISCONN         = Errno(0x4b)
	EISDIR          = Errno(0x15)
	EL2HLT          = Errno(0x2c)
	EL2NSYNC        = Errno(0x26)
	EL3HLT          = Errno(0x27)
	EL3RST          = Errno(0x28)
	ELNRNG          = Errno(0x29)
	ELOOP           = Errno(0x55)
	EMEDIA          = Errno(0x6e)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x3b)
	EMULTIHOP       = Errno(0x7d)
	ENAMETOOLONG    = Errno(0x56)
	ENETDOWN        = Errno(0x45)
	ENETRESET       = Errno(0x47)
	ENETUNREACH     = Errno(0x46)
	ENFILE          = Errno(0x17)
	ENOATTR         = Errno(0x70)
	ENOBUFS         = Errno(0x4a)
	ENOCONNECT      = Errno(0x32)
	ENOCSI          = Errno(0x2b)
	ENODATA         = Errno(0x7a)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOLCK          = Errno(0x31)
	ENOLINK         = Errno(0x7e)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x23)
	ENOPROTOOPT     = Errno(0x3d)
	ENOSPC          = Errno(0x1c)
	ENOSR           = Errno(0x76)
	ENOSTR          = Errno(0x7b)
	ENOSYS          = Errno(0x6d)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x4c)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x11)
	ENOTREADY       = Errno(0x2e)
	ENOTRECOVERABLE = Errno(0x5e)
	ENOTRUST        = Errno(0x72)
	ENOTSOCK        = Errno(0x39)
	ENOTSUP         = Errno(0x7c)
	ENOTTY          = Errno(0x19)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x40)
	EOVERFLOW       = Errno(0x7f)
	EOWNERDEAD      = Errno(0x5f)
	EPERM           = Errno(0x1)
	EPFNOSUPPORT    = Errno(0x41)
	EPIPE           = Errno(0x20)
	EPROCLIM        = Errno(0x53)
	EPROTO          = Errno(0x79)
	EPROTONOSUPPORT = Errno(0x3e)
	EPROTOTYPE      = Errno(0x3c)
	ERANGE          = Errno(0x22)
	EREMOTE         = Errno(0x5d)
	ERESTART        = Errno(0x52)
	EROFS           = Errno(0x1e)
	ESAD            = Errno(0x71)
	ESHUTDOWN       = Errno(0x4d)
	ESOCKTNOSUPPORT = Errno(0x3f)
	ESOFT           = Errno(0x6f)
	ESPIPE          = Errno(0x1d)
	ESRCH           = Errno(0x3)
	ESTALE          = Errno(0x34)
	ESYSERROR       = Errno(0x5a)
	ETIME           = Errno(0x77)
	ETIMEDOUT       = Errno(0x4e)
	ETOOMANYREFS    = Errno(0x73)
	ETXTBSY         = Errno(0x1a)
	EUNATCH         = Errno(0x2a)
	EUSERS          = Errno(0x54)
	EWOULDBLOCK     = Errno(0xb)
	EWRPROTECT      = Errno(0x2f)
	EXDEV           = Errno(0x12)
)

// Signals
const (
	SIGABRT     = Signal(0x6)
	SIGAIO      = Signal(0x17)
	SIGALRM     = Signal(0xe)
	SIGALRM1    = Signal(0x26)
	SIGBUS      = Signal(0xa)
	SIGCAPI     = Signal(0x31)
	SIGCHLD     = Signal(0x14)
	SIGCLD      = Signal(0x14)
	SIGCONT     = Signal(0x13)
	SIGCPUFAIL  = Signal(0x3b)
	SIGDANGER   = Signal(0x21)
	SIGEMT      = Signal(0x7)
	SIGFPE      = Signal(0x8)
	SIGGRANT    = Signal(0x3c)
	SIGHUP      = Signal(0x1)
	SIGILL      = Signal(0x4)
	SIGINT      = Signal(0x2)
	SIGIO       = Signal(0x17)
	SIGIOINT    = Signal(0x10)
	SIGIOT      = Signal(0x6)
	SIGKAP      = Signal(0x3c)
	SIGKILL     = Signal(0x9)
	SIGLOST     = Signal(0x6)
	SIGMAX      = Signal(0xff)
	SIGMAX32    = Signal(0x3f)
	SIGMAX64    = Signal(0xff)
	SIGMIGRATE  = Signal(0x23)
	SIGMSG      = Signal(0x1b)
	SIGPIPE     = Signal(0xd)
	SIGPOLL     = Signal(0x17)
	SIGPRE      = Signal(0x24)
	SIGPROF     = Signal(0x20)
	SIGPTY      = Signal(0x17)
	SIGPWR      = Signal(0x1d)
	SIGQUIT     = Signal(0x3)
	SIGRECONFIG = Signal(0x3a)
	SIGRETRACT  = Signal(0x3d)
	SIGSAK      = Signal(0x3f)
	SIGSEGV     = Signal(0xb)
	SIGSOUND    = Signal(0x3e)
	SIGSTOP     = Signal(0x11)
	SIGSYS      = Signal(0xc)
	SIGSYSERROR = Signal(0x30)
	SIGTALRM    = Signal(0x26)
	SIGTERM     = Signal(0xf)
	SIGTRAP     = Signal(0x5)
	SIGTSTP     = Signal(0x12)
	SIGTTIN     = Signal(0x15)
	SIGTTOU     = Signal(0x16)
	SIGURG      = Signal(0x10)
	SIGUSR1     = Signal(0x1e)
	SIGUSR2     = Signal(0x1f)
	SIGVIRT     = Signal(0x25)
	SIGVTALRM   = Signal(0x22)
	SIGWAITING  = Signal(0x27)
	SIGWINCH    = Signal(0x1c)
	SIGXCPU     = Signal(0x18)
	SIGXFSZ     = Signal(0x19)
)

// Error table
var errors = [...]string{
	1:   "not owner",
	2:   "no such file or directory",
	3:   "no such process",
	4:   "interrupted system call",
	5:   "I/O error",
	6:   "no such device or address",
	7:   "arg list too long",
	8:   "exec format error",
	9:   "bad file number",
	10:  "no child processes",
	11:  "resource temporarily unavailable",
	12:  "not enough space",
	13:  "permission denied",
	14:  "bad address",
	15:  "block device required",
	16:  "device busy",
	17:  "file exists",
	18:  "cross-device link",
	19:  "no such device",
	20:  "not a directory",
	21:  "is a directory",
	22:  "invalid argument",
	23:  "file table overflow",
	24:  "too many open files",
	25:  "not a typewriter",
	26:  "text file busy",
	27:  "file too large",
	28:  "no space left on device",
	29:  "illegal seek",
	30:  "read-only file system",
	31:  "too many links",
	32:  "broken pipe",
	33:  "argument out of domain",
	34:  "result too large",
	35:  "no message of desired type",
	36:  "identifier removed",
	37:  "channel number out of range",
	38:  "level 2 not synchronized",
	39:  "level 3 halted",
	40:  "level 3 reset",
	41:  "link number out of range",
	42:  "protocol driver not attached",
	43:  "no CSI structure available",
	44:  "level 2 halted",
	45:  "deadlock condition if locked",
	46:  "device not ready",
	47:  "write-protected media",
	48:  "unformatted or incompatible media",
	49:  "no locks available",
	50:  "cannot Establish Connection",
	52:  "missing file or filesystem",
	53:  "requests blocked by Administrator",
	55:  "operation now in progress",
	56:  "operation already in progress",
	57:  "socket operation on non-socket",
	58:  "destination address required",
	59:  "message too long",
	60:  "protocol wrong type for socket",
	61:  "protocol not available",
	62:  "protocol not supported",
	63:  "socket type not supported",
	64:  "operation not supported on socket",
	65:  "protocol family not supported",
	66:  "addr family not supported by protocol",
	67:  "address already in use",
	68:  "can't assign requested address",
	69:  "network is down",
	70:  "network is unreachable",
	71:  "network dropped connection on reset",
	72:  "software caused connection abort",
	73:  "connection reset by peer",
	74:  "no buffer space available",
	75:  "socket is already connected",
	76:  "socket is not connected",
	77:  "can't send after socket shutdown",
	78:  "connection timed out",
	79:  "connection refused",
	80:  "host is down",
	81:  "no route to host",
	82:  "restart the system call",
	83:  "too many processes",
	84:  "too many users",
	85:  "too many levels of symbolic links",
	86:  "file name too long",
	88:  "disk quota exceeded",
	89:  "invalid file system control data detected",
	90:  "for future use ",
	93:  "item is not local to host",
	94:  "state not recoverable ",
	95:  "previous owner died ",
	109: "function not implemented",
	110: "media surface error",
	111: "I/O completed, but needs relocation",
	112: "no attribute found",
	113: "security Authentication Denied",
	114: "not a Trusted Program",
	115: "too many references: can't splice",
	116: "invalid wide character",
	117: "asynchronous I/O cancelled",
	118: "out of STREAMS resources",
	119: "system call timed out",
	120: "next message has wrong type",
	121: "error in protocol",
	122: "no message on stream head read q",
	123: "fd not associated with a stream",
	124: "unsupported attribute value",
	125: "multihop is not allowed",
	126: "the server link has been severed",
	127: "value too large to be stored in data type",
}

// Signal table
var signals = [...]string{
	1:   "hangup",
	2:   "interrupt",
	3:   "quit",
	4:   "illegal instruction",
	5:   "trace/BPT trap",
	6:   "IOT/Abort trap",
	7:   "EMT trap",
	8:   "floating point exception",
	9:   "killed",
	10:  "bus error",
	11:  "segmentation fault",
	12:  "bad system call",
	13:  "broken pipe",
	14:  "alarm clock",
	15:  "terminated",
	16:  "urgent I/O condition",
	17:  "stopped (signal)",
	18:  "stopped",
	19:  "continued",
	20:  "child exited",
	21:  "stopped (tty input)",
	22:  "stopped (tty output)",
	23:  "I/O possible/complete",
	24:  "cputime limit exceeded",
	25:  "filesize limit exceeded",
	27:  "input device data",
	28:  "window size changes",
	29:  "power-failure",
	30:  "user defined signal 1",
	31:  "user defined signal 2",
	32:  "profiling timer expired",
	33:  "paging space low",
	34:  "virtual timer expired",
	35:  "signal 35",
	36:  "signal 36",
	37:  "signal 37",
	38:  "signal 38",
	39:  "signal 39",
	48:  "signal 48",
	49:  "signal 49",
	58:  "signal 58",
	59:  "CPU Failure Predicted",
	60:  "monitor mode granted",
	61:  "monitor mode retracted",
	62:  "sound completed",
	63:  "secure attention",
	255: "signal 255",
}

"""




```