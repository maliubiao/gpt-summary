Response:
The user provided a second part of a Go source code file and asked for a summary of its functionality. This part defines constants representing system call numbers, socket options, terminal control codes, error numbers, and signal numbers for the Solaris AMD64 architecture. It also defines string arrays that map error numbers and signal numbers to human-readable descriptions.

Therefore, the main functionality of this code snippet is to provide a mapping between symbolic names and integer values for various system-level constants and to provide human-readable descriptions for error and signal codes, specifically for the Solaris AMD64 operating system.
这是 `go/src/syscall/zerrors_solaris_amd64.go` 文件的第二部分，它主要功能是：

1. **定义了更多的系统调用相关的常量 (Constants)**：延续了第一部分的功能，定义了更多与系统调用相关的常量。这些常量通常以 `SIOCS`、`SOCK_`、`SOL_`、`SO_`、`TC`、`TIO`、`V` 等前缀开头。
    * `SIOCS...`:  可能与设置（Set）网络接口相关的操作码。
    * `SOCK_...`: 定义了 socket 的类型，如数据报 (`SOCK_DGRAM`)、流式 (`SOCK_STREAM`) 等。
    * `SOL_...`: 定义了 socket 选项的层级，例如 `SOL_SOCKET` 表示通用的 socket 选项。
    * `SO_...`: 定义了具体的 socket 选项，例如是否允许地址重用 (`SO_REUSEADDR`)、发送缓冲区大小 (`SO_SNDBUF`) 等。
    * `TC...`:  可能与终端控制相关的操作，如刷新输入/输出队列 (`TCIFLUSH`, `TCOFLUSH`)。
    * `TIO...`: 定义了与 ioctl 系统调用配合使用的终端 I/O 控制命令，例如获取窗口大小 (`TIOCGWINSZ`)、发送 BREAK 信号 (`TIOCSBRK`) 等。
    * `V...`: 定义了终端的特殊字符，如 EOF 字符 (`VEOF`)、换行符 (`VEOL`) 等。

2. **定义了错误码常量 (Error Codes)**：定义了各种系统错误码，以 `E` 开头，并将其赋值为 `Errno` 类型。例如，`EACCES` 表示权限被拒绝，`ENOENT` 表示文件不存在等。

3. **定义了信号常量 (Signals)**：定义了各种信号常量，以 `SIG` 开头，并将其赋值为 `Signal` 类型。例如，`SIGINT` 表示中断信号，`SIGKILL` 表示强制终止信号等。

4. **定义了错误码到字符串的映射表 (Error Table)**：`errors` 变量是一个字符串数组，它将错误码的数值映射到对应的文本描述。例如，索引为 2 的元素是 "no such file or directory"，对应 `ENOENT` 错误码。

5. **定义了信号到字符串的映射表 (Signal Table)**：`signals` 变量是一个字符串数组，它将信号的数值映射到对应的文本描述。例如，索引为 1 的元素是 "hangup"，对应 `SIGHUP` 信号。

**归纳其功能：**

总而言之，这个代码片段（结合第一部分）为 Go 语言在 Solaris AMD64 平台上进行底层系统编程提供了必要的常量定义，包括了系统调用号、socket 选项、终端控制、错误码和信号等，并提供了将数字错误码和信号转换为人类可读字符串的映射。这使得 Go 语言程序可以直接使用这些常量进行系统调用，而无需记住具体的数值，提高了代码的可读性和可维护性。这些常量和映射表是 Go 语言 `syscall` 包实现与操作系统交互的基础。

Prompt: 
```
这是路径为go/src/syscall/zerrors_solaris_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
fdf96e6
	SIOCSIP6ADDRPOLICY            = -0x7fff965d
	SIOCSIPMSFILTER               = -0x7ffb964b
	SIOCSIPSECONFIG               = -0x7ffb966a
	SIOCSLGETREQ                  = -0x3fdf96b9
	SIOCSLIFADDR                  = -0x7f879690
	SIOCSLIFBRDADDR               = -0x7f879684
	SIOCSLIFDSTADDR               = -0x7f87968e
	SIOCSLIFFLAGS                 = -0x7f87968c
	SIOCSLIFGROUPNAME             = -0x7f879665
	SIOCSLIFINDEX                 = -0x7f87967a
	SIOCSLIFLNKINFO               = -0x7f879675
	SIOCSLIFMETRIC                = -0x7f879680
	SIOCSLIFMTU                   = -0x7f879687
	SIOCSLIFMUXID                 = -0x7f87967c
	SIOCSLIFNAME                  = -0x3f87967f
	SIOCSLIFNETMASK               = -0x7f879682
	SIOCSLIFPREFIX                = -0x3f879641
	SIOCSLIFSUBNET                = -0x7f879677
	SIOCSLIFTOKEN                 = -0x7f879679
	SIOCSLIFUSESRC                = -0x7f879650
	SIOCSLIFZONE                  = -0x7f879655
	SIOCSLOWAT                    = -0x7ffb8cfe
	SIOCSLSTAT                    = -0x7fdf96b8
	SIOCSMSFILTER                 = -0x7ffb964d
	SIOCSPGRP                     = -0x7ffb8cf8
	SIOCSPROMISC                  = -0x7ffb96d0
	SIOCSQPTR                     = -0x3ffb9648
	SIOCSSDSTATS                  = -0x3fdf96d2
	SIOCSSESTATS                  = -0x3fdf96d1
	SIOCSXARP                     = -0x7fff965a
	SIOCTMYADDR                   = -0x3ff79670
	SIOCTMYSITE                   = -0x3ff7966e
	SIOCTONLINK                   = -0x3ff7966f
	SIOCUPPER                     = -0x7fdf96d8
	SIOCX25RCV                    = -0x3fdf96c4
	SIOCX25TBL                    = -0x3fdf96c3
	SIOCX25XMT                    = -0x3fdf96c5
	SIOCXPROTO                    = 0x20007337
	SOCK_CLOEXEC                  = 0x80000
	SOCK_DGRAM                    = 0x1
	SOCK_NDELAY                   = 0x200000
	SOCK_NONBLOCK                 = 0x100000
	SOCK_RAW                      = 0x4
	SOCK_RDM                      = 0x5
	SOCK_SEQPACKET                = 0x6
	SOCK_STREAM                   = 0x2
	SOCK_TYPE_MASK                = 0xffff
	SOL_FILTER                    = 0xfffc
	SOL_PACKET                    = 0xfffd
	SOL_ROUTE                     = 0xfffe
	SOL_SOCKET                    = 0xffff
	SOMAXCONN                     = 0x80
	SO_ACCEPTCONN                 = 0x2
	SO_ALL                        = 0x3f
	SO_ALLZONES                   = 0x1014
	SO_ANON_MLP                   = 0x100a
	SO_ATTACH_FILTER              = 0x40000001
	SO_BAND                       = 0x4000
	SO_BROADCAST                  = 0x20
	SO_COPYOPT                    = 0x80000
	SO_DEBUG                      = 0x1
	SO_DELIM                      = 0x8000
	SO_DETACH_FILTER              = 0x40000002
	SO_DGRAM_ERRIND               = 0x200
	SO_DOMAIN                     = 0x100c
	SO_DONTLINGER                 = -0x81
	SO_DONTROUTE                  = 0x10
	SO_ERROPT                     = 0x40000
	SO_ERROR                      = 0x1007
	SO_EXCLBIND                   = 0x1015
	SO_HIWAT                      = 0x10
	SO_ISNTTY                     = 0x800
	SO_ISTTY                      = 0x400
	SO_KEEPALIVE                  = 0x8
	SO_LINGER                     = 0x80
	SO_LOWAT                      = 0x20
	SO_MAC_EXEMPT                 = 0x100b
	SO_MAC_IMPLICIT               = 0x1016
	SO_MAXBLK                     = 0x100000
	SO_MAXPSZ                     = 0x8
	SO_MINPSZ                     = 0x4
	SO_MREADOFF                   = 0x80
	SO_MREADON                    = 0x40
	SO_NDELOFF                    = 0x200
	SO_NDELON                     = 0x100
	SO_NODELIM                    = 0x10000
	SO_OOBINLINE                  = 0x100
	SO_PROTOTYPE                  = 0x1009
	SO_RCVBUF                     = 0x1002
	SO_RCVLOWAT                   = 0x1004
	SO_RCVPSH                     = 0x100d
	SO_RCVTIMEO                   = 0x1006
	SO_READOPT                    = 0x1
	SO_RECVUCRED                  = 0x400
	SO_REUSEADDR                  = 0x4
	SO_SECATTR                    = 0x1011
	SO_SNDBUF                     = 0x1001
	SO_SNDLOWAT                   = 0x1003
	SO_SNDTIMEO                   = 0x1005
	SO_STRHOLD                    = 0x20000
	SO_TAIL                       = 0x200000
	SO_TIMESTAMP                  = 0x1013
	SO_TONSTOP                    = 0x2000
	SO_TOSTOP                     = 0x1000
	SO_TYPE                       = 0x1008
	SO_USELOOPBACK                = 0x40
	SO_VRRP                       = 0x1017
	SO_WROFF                      = 0x2
	TCFLSH                        = 0x5407
	TCIFLUSH                      = 0x0
	TCIOFLUSH                     = 0x2
	TCOFLUSH                      = 0x1
	TCP_ABORT_THRESHOLD           = 0x11
	TCP_ANONPRIVBIND              = 0x20
	TCP_CONN_ABORT_THRESHOLD      = 0x13
	TCP_CONN_NOTIFY_THRESHOLD     = 0x12
	TCP_CORK                      = 0x18
	TCP_EXCLBIND                  = 0x21
	TCP_INIT_CWND                 = 0x15
	TCP_KEEPALIVE                 = 0x8
	TCP_KEEPALIVE_ABORT_THRESHOLD = 0x17
	TCP_KEEPALIVE_THRESHOLD       = 0x16
	TCP_KEEPCNT                   = 0x23
	TCP_KEEPIDLE                  = 0x22
	TCP_KEEPINTVL                 = 0x24
	TCP_LINGER2                   = 0x1c
	TCP_MAXSEG                    = 0x2
	TCP_MSS                       = 0x218
	TCP_NODELAY                   = 0x1
	TCP_NOTIFY_THRESHOLD          = 0x10
	TCP_RECVDSTADDR               = 0x14
	TCP_RTO_INITIAL               = 0x19
	TCP_RTO_MAX                   = 0x1b
	TCP_RTO_MIN                   = 0x1a
	TCSAFLUSH                     = 0x5410
	TIOC                          = 0x5400
	TIOCCBRK                      = 0x747a
	TIOCCDTR                      = 0x7478
	TIOCCILOOP                    = 0x746c
	TIOCEXCL                      = 0x740d
	TIOCFLUSH                     = 0x7410
	TIOCGETC                      = 0x7412
	TIOCGETD                      = 0x7400
	TIOCGETP                      = 0x7408
	TIOCGLTC                      = 0x7474
	TIOCGPGRP                     = 0x7414
	TIOCGPPS                      = 0x547d
	TIOCGPPSEV                    = 0x547f
	TIOCGSID                      = 0x7416
	TIOCGSOFTCAR                  = 0x5469
	TIOCGWINSZ                    = 0x5468
	TIOCHPCL                      = 0x7402
	TIOCKBOF                      = 0x5409
	TIOCKBON                      = 0x5408
	TIOCLBIC                      = 0x747e
	TIOCLBIS                      = 0x747f
	TIOCLGET                      = 0x747c
	TIOCLSET                      = 0x747d
	TIOCMBIC                      = 0x741c
	TIOCMBIS                      = 0x741b
	TIOCMGET                      = 0x741d
	TIOCMSET                      = 0x741a
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
	TIOCNOTTY                     = 0x7471
	TIOCNXCL                      = 0x740e
	TIOCOUTQ                      = 0x7473
	TIOCREMOTE                    = 0x741e
	TIOCSBRK                      = 0x747b
	TIOCSCTTY                     = 0x7484
	TIOCSDTR                      = 0x7479
	TIOCSETC                      = 0x7411
	TIOCSETD                      = 0x7401
	TIOCSETN                      = 0x740a
	TIOCSETP                      = 0x7409
	TIOCSIGNAL                    = 0x741f
	TIOCSILOOP                    = 0x746d
	TIOCSLTC                      = 0x7475
	TIOCSPGRP                     = 0x7415
	TIOCSPPS                      = 0x547e
	TIOCSSOFTCAR                  = 0x546a
	TIOCSTART                     = 0x746e
	TIOCSTI                       = 0x7417
	TIOCSTOP                      = 0x746f
	TIOCSWINSZ                    = 0x5467
	TOSTOP                        = 0x100
	VCEOF                         = 0x8
	VCEOL                         = 0x9
	VDISCARD                      = 0xd
	VDSUSP                        = 0xb
	VEOF                          = 0x4
	VEOL                          = 0x5
	VEOL2                         = 0x6
	VERASE                        = 0x2
	VINTR                         = 0x0
	VKILL                         = 0x3
	VLNEXT                        = 0xf
	VMIN                          = 0x4
	VQUIT                         = 0x1
	VREPRINT                      = 0xc
	VSTART                        = 0x8
	VSTOP                         = 0x9
	VSUSP                         = 0xa
	VSWTCH                        = 0x7
	VT0                           = 0x0
	VT1                           = 0x4000
	VTDLY                         = 0x4000
	VTIME                         = 0x5
	VWERASE                       = 0xe
	WCONTFLG                      = 0xffff
	WCONTINUED                    = 0x8
	WCOREFLG                      = 0x80
	WEXITED                       = 0x1
	WNOHANG                       = 0x40
	WNOWAIT                       = 0x80
	WOPTMASK                      = 0xcf
	WRAP                          = 0x20000
	WSIGMASK                      = 0x7f
	WSTOPFLG                      = 0x7f
	WSTOPPED                      = 0x4
	WTRAPPED                      = 0x2
	WUNTRACED                     = 0x4
)

// Errors
const (
	E2BIG           = Errno(0x7)
	EACCES          = Errno(0xd)
	EADDRINUSE      = Errno(0x7d)
	EADDRNOTAVAIL   = Errno(0x7e)
	EADV            = Errno(0x44)
	EAFNOSUPPORT    = Errno(0x7c)
	EAGAIN          = Errno(0xb)
	EALREADY        = Errno(0x95)
	EBADE           = Errno(0x32)
	EBADF           = Errno(0x9)
	EBADFD          = Errno(0x51)
	EBADMSG         = Errno(0x4d)
	EBADR           = Errno(0x33)
	EBADRQC         = Errno(0x36)
	EBADSLT         = Errno(0x37)
	EBFONT          = Errno(0x39)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x2f)
	ECHILD          = Errno(0xa)
	ECHRNG          = Errno(0x25)
	ECOMM           = Errno(0x46)
	ECONNABORTED    = Errno(0x82)
	ECONNREFUSED    = Errno(0x92)
	ECONNRESET      = Errno(0x83)
	EDEADLK         = Errno(0x2d)
	EDEADLOCK       = Errno(0x38)
	EDESTADDRREQ    = Errno(0x60)
	EDOM            = Errno(0x21)
	EDQUOT          = Errno(0x31)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EHOSTDOWN       = Errno(0x93)
	EHOSTUNREACH    = Errno(0x94)
	EIDRM           = Errno(0x24)
	EILSEQ          = Errno(0x58)
	EINPROGRESS     = Errno(0x96)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EISCONN         = Errno(0x85)
	EISDIR          = Errno(0x15)
	EL2HLT          = Errno(0x2c)
	EL2NSYNC        = Errno(0x26)
	EL3HLT          = Errno(0x27)
	EL3RST          = Errno(0x28)
	ELIBACC         = Errno(0x53)
	ELIBBAD         = Errno(0x54)
	ELIBEXEC        = Errno(0x57)
	ELIBMAX         = Errno(0x56)
	ELIBSCN         = Errno(0x55)
	ELNRNG          = Errno(0x29)
	ELOCKUNMAPPED   = Errno(0x48)
	ELOOP           = Errno(0x5a)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x61)
	EMULTIHOP       = Errno(0x4a)
	ENAMETOOLONG    = Errno(0x4e)
	ENETDOWN        = Errno(0x7f)
	ENETRESET       = Errno(0x81)
	ENETUNREACH     = Errno(0x80)
	ENFILE          = Errno(0x17)
	ENOANO          = Errno(0x35)
	ENOBUFS         = Errno(0x84)
	ENOCSI          = Errno(0x2b)
	ENODATA         = Errno(0x3d)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOLCK          = Errno(0x2e)
	ENOLINK         = Errno(0x43)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x23)
	ENONET          = Errno(0x40)
	ENOPKG          = Errno(0x41)
	ENOPROTOOPT     = Errno(0x63)
	ENOSPC          = Errno(0x1c)
	ENOSR           = Errno(0x3f)
	ENOSTR          = Errno(0x3c)
	ENOSYS          = Errno(0x59)
	ENOTACTIVE      = Errno(0x49)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x86)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x5d)
	ENOTRECOVERABLE = Errno(0x3b)
	ENOTSOCK        = Errno(0x5f)
	ENOTSUP         = Errno(0x30)
	ENOTTY          = Errno(0x19)
	ENOTUNIQ        = Errno(0x50)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x7a)
	EOVERFLOW       = Errno(0x4f)
	EOWNERDEAD      = Errno(0x3a)
	EPERM           = Errno(0x1)
	EPFNOSUPPORT    = Errno(0x7b)
	EPIPE           = Errno(0x20)
	EPROTO          = Errno(0x47)
	EPROTONOSUPPORT = Errno(0x78)
	EPROTOTYPE      = Errno(0x62)
	ERANGE          = Errno(0x22)
	EREMCHG         = Errno(0x52)
	EREMOTE         = Errno(0x42)
	ERESTART        = Errno(0x5b)
	EROFS           = Errno(0x1e)
	ESHUTDOWN       = Errno(0x8f)
	ESOCKTNOSUPPORT = Errno(0x79)
	ESPIPE          = Errno(0x1d)
	ESRCH           = Errno(0x3)
	ESRMNT          = Errno(0x45)
	ESTALE          = Errno(0x97)
	ESTRPIPE        = Errno(0x5c)
	ETIME           = Errno(0x3e)
	ETIMEDOUT       = Errno(0x91)
	ETOOMANYREFS    = Errno(0x90)
	ETXTBSY         = Errno(0x1a)
	EUNATCH         = Errno(0x2a)
	EUSERS          = Errno(0x5e)
	EWOULDBLOCK     = Errno(0xb)
	EXDEV           = Errno(0x12)
	EXFULL          = Errno(0x34)
)

// Signals
const (
	SIGABRT    = Signal(0x6)
	SIGALRM    = Signal(0xe)
	SIGBUS     = Signal(0xa)
	SIGCANCEL  = Signal(0x24)
	SIGCHLD    = Signal(0x12)
	SIGCLD     = Signal(0x12)
	SIGCONT    = Signal(0x19)
	SIGEMT     = Signal(0x7)
	SIGFPE     = Signal(0x8)
	SIGFREEZE  = Signal(0x22)
	SIGHUP     = Signal(0x1)
	SIGILL     = Signal(0x4)
	SIGINT     = Signal(0x2)
	SIGIO      = Signal(0x16)
	SIGIOT     = Signal(0x6)
	SIGJVM1    = Signal(0x27)
	SIGJVM2    = Signal(0x28)
	SIGKILL    = Signal(0x9)
	SIGLOST    = Signal(0x25)
	SIGLWP     = Signal(0x21)
	SIGPIPE    = Signal(0xd)
	SIGPOLL    = Signal(0x16)
	SIGPROF    = Signal(0x1d)
	SIGPWR     = Signal(0x13)
	SIGQUIT    = Signal(0x3)
	SIGSEGV    = Signal(0xb)
	SIGSTOP    = Signal(0x17)
	SIGSYS     = Signal(0xc)
	SIGTERM    = Signal(0xf)
	SIGTHAW    = Signal(0x23)
	SIGTRAP    = Signal(0x5)
	SIGTSTP    = Signal(0x18)
	SIGTTIN    = Signal(0x1a)
	SIGTTOU    = Signal(0x1b)
	SIGURG     = Signal(0x15)
	SIGUSR1    = Signal(0x10)
	SIGUSR2    = Signal(0x11)
	SIGVTALRM  = Signal(0x1c)
	SIGWAITING = Signal(0x20)
	SIGWINCH   = Signal(0x14)
	SIGXCPU    = Signal(0x1e)
	SIGXFSZ    = Signal(0x1f)
	SIGXRES    = Signal(0x26)
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
	25:  "inappropriate ioctl for device",
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
	45:  "deadlock situation detected/avoided",
	46:  "no record locks available",
	47:  "operation canceled",
	48:  "operation not supported",
	49:  "disc quota exceeded",
	50:  "bad exchange descriptor",
	51:  "bad request descriptor",
	52:  "message tables full",
	53:  "anode table overflow",
	54:  "bad request code",
	55:  "invalid slot",
	56:  "file locking deadlock",
	57:  "bad font file format",
	58:  "owner of the lock died",
	59:  "lock is not recoverable",
	60:  "not a stream device",
	61:  "no data available",
	62:  "timer expired",
	63:  "out of stream resources",
	64:  "machine is not on the network",
	65:  "package not installed",
	66:  "object is remote",
	67:  "link has been severed",
	68:  "advertise error",
	69:  "srmount error",
	70:  "communication error on send",
	71:  "protocol error",
	72:  "locked lock was unmapped ",
	73:  "facility is not active",
	74:  "multihop attempted",
	77:  "not a data message",
	78:  "file name too long",
	79:  "value too large for defined data type",
	80:  "name not unique on network",
	81:  "file descriptor in bad state",
	82:  "remote address changed",
	83:  "can not access a needed shared library",
	84:  "accessing a corrupted shared library",
	85:  ".lib section in a.out corrupted",
	86:  "attempting to link in more shared libraries than system limit",
	87:  "can not exec a shared library directly",
	88:  "illegal byte sequence",
	89:  "operation not applicable",
	90:  "number of symbolic links encountered during path name traversal exceeds MAXSYMLINKS",
	91:  "error 91",
	92:  "error 92",
	93:  "directory not empty",
	94:  "too many users",
	95:  "socket operation on non-socket",
	96:  "destination address required",
	97:  "message too long",
	98:  "protocol wrong type for socket",
	99:  "option not supported by protocol",
	120: "protocol not supported",
	121: "socket type not supported",
	122: "operation not supported on transport endpoint",
	123: "protocol family not supported",
	124: "address family not supported by protocol family",
	125: "address already in use",
	126: "cannot assign requested address",
	127: "network is down",
	128: "network is unreachable",
	129: "network dropped connection because of reset",
	130: "software caused connection abort",
	131: "connection reset by peer",
	132: "no buffer space available",
	133: "transport endpoint is already connected",
	134: "transport endpoint is not connected",
	143: "cannot send after socket shutdown",
	144: "too many references: cannot splice",
	145: "connection timed out",
	146: "connection refused",
	147: "host is down",
	148: "no route to host",
	149: "operation already in progress",
	150: "operation now in progress",
	151: "stale NFS file handle",
}

// Signal table
var signals = [...]string{
	1:  "hangup",
	2:  "interrupt",
	3:  "quit",
	4:  "illegal Instruction",
	5:  "trace/Breakpoint Trap",
	6:  "abort",
	7:  "emulation Trap",
	8:  "arithmetic Exception",
	9:  "killed",
	10: "bus Error",
	11: "segmentation Fault",
	12: "bad System Call",
	13: "broken Pipe",
	14: "alarm Clock",
	15: "terminated",
	16: "user Signal 1",
	17: "user Signal 2",
	18: "child Status Changed",
	19: "power-Fail/Restart",
	20: "window Size Change",
	21: "urgent Socket Condition",
	22: "pollable Event",
	23: "stopped (signal)",
	24: "stopped (user)",
	25: "continued",
	26: "stopped (tty input)",
	27: "stopped (tty output)",
	28: "virtual Timer Expired",
	29: "profiling Timer Expired",
	30: "cpu Limit Exceeded",
	31: "file Size Limit Exceeded",
	32: "no runnable lwp",
	33: "inter-lwp signal",
	34: "checkpoint Freeze",
	35: "checkpoint Thaw",
	36: "thread Cancellation",
	37: "resource Lost",
	38: "resource Control Exceeded",
	39: "reserved for JVM 1",
	40: "reserved for JVM 2",
}

"""




```