Response:
The user is asking for a summary of the provided Go code snippet. This is the second part of a two-part code listing. The first part was not provided, but based on the naming convention (`zerrors_darwin_arm64.go`) and the content of this part, it's highly likely the first part contained definitions for constants related to system calls and related structures for the Darwin operating system on the ARM64 architecture.

This second part focuses on:
1. **Constants**: Defining various integer constants related to socket options, file modes, terminal I/O control, TCP options, and extended attributes.
2. **Errors**: Defining `syscall.Errno` constants representing various system error codes.
3. **Signals**: Defining `syscall.Signal` constants representing various system signals.
4. **Error Table**: An array (`errorList`) mapping error numbers to their names and descriptions.
5. **Signal Table**: An array (`signalList`) mapping signal numbers to their names and descriptions.

Therefore, the primary function of this code is to provide a comprehensive list of system-level constants, error codes, and signals specific to the Darwin operating system on the ARM64 architecture for use within Go programs. It acts as a lookup table and definition source for these low-level system concepts.
该Go语言文件的主要功能是**定义了在 Darwin 操作系统 (arm64 架构) 下使用的系统调用相关的常量、错误码和信号**。

具体来说，它做了以下几件事：

1. **定义了大量的常量 (Constants)**：
   - 这些常量通常用于与操作系统进行底层交互，例如：
     - `SIOCGIFADDR` 等 `SIOC` 开头的常量是用于网络接口控制的 ioctl 命令。
     - `SOCK_DGRAM`, `SOCK_STREAM` 等 `SOCK_` 开头的常量定义了 socket 的类型。
     - `SOL_LOCAL`, `SOL_SOCKET` 等 `SOL_` 开头的常量定义了 `getsockopt` 和 `setsockopt` 函数中的 level 参数。
     - `SO_ACCEPTCONN`, `SO_REUSEADDR` 等 `SO_` 开头的常量定义了 socket 的选项。
     - `S_IEXEC`, `S_IFREG` 等 `S_` 开头的常量定义了文件模式的位。
     - `TAB0`, `TCIFLUSH` 等 `TC` 开头的常量定义了终端控制相关的参数。
     - `TCPOPT_CC`, `TCP_NODELAY` 等 `TCP_` 开头的常量定义了 TCP 协议的选项。
     - `TIOCCBRK`, `TIOCGETA` 等 `TIOC` 开头的常量定义了终端 I/O 控制的 ioctl 命令。
     - `UF_APPEND`, `XATTR_CREATE` 等 `UF_` 和 `XATTR_` 开头的常量定义了文件系统标志和扩展属性相关的标志。
     - `VMADDR_CID_ANY` 等 `VMADDR_` 开头的常量可能与虚拟机相关的地址定义有关。
     - `VEOF`, `VINTR` 等 `V` 开头的常量定义了终端特殊字符。
     - `WCONTINUED`, `WEXITED` 等 `W` 开头的常量与进程退出状态相关。

2. **定义了错误码 (Errors)**：
   - 使用 `syscall.Errno` 类型定义了大量的以 `E` 开头的常量，例如 `EACCES` (权限被拒绝), `ENOENT` (文件或目录不存在) 等。这些常量对应于操作系统返回的错误代码。

3. **定义了信号 (Signals)**：
   - 使用 `syscall.Signal` 类型定义了大量的以 `SIG` 开头的常量，例如 `SIGINT` (中断信号), `SIGKILL` (终止信号) 等。这些常量代表了可以发送给进程的各种信号。

4. **提供了错误码的描述 (Error table)**：
   - 定义了一个名为 `errorList` 的结构体数组，将每个错误码 (`num`) 关联到其名称 (`name`) 和描述 (`desc`)。这可以方便地将数字错误码转换为更易读的字符串。

5. **提供了信号的描述 (Signal table)**：
   - 定义了一个名为 `signalList` 的结构体数组，将每个信号 (`num`) 关联到其名称 (`name`) 和描述 (`desc`)。这可以方便地将数字信号转换为更易读的字符串。

**总结其功能：**

该文件的主要功能是为 Go 语言程序在 Darwin (arm64) 平台上进行底层系统调用操作提供必要的常量定义、错误码定义和信号定义，并提供了错误码和信号的文字描述，方便开发者理解和使用。  它是 Go 语言 `syscall` 包在特定平台上的具体实现细节的一部分。

由于这部分代码主要定义常量，不容易直接用 Go 代码举例说明其功能，因为它本身就是底层的基础设施。  它的作用体现在其他使用这些常量的 Go 代码中。

**易犯错的点：**

开发者容易犯错的点在于**混淆不同操作系统或不同架构下的常量值**。例如，在 Linux 系统下，`SO_REUSEADDR` 的值可能与 Darwin 下不同。  因此，在编写跨平台代码时，需要特别注意这些平台相关的常量。  这个文件正是为了特定平台而存在的，避免了直接使用 magic number，提高了代码的可读性和可维护性。

由于没有具体的命令行参数处理，此处不涉及相关说明。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_darwin_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
         = 0x80206939
	SIOCSIFKPI                              = 0x80206986
	SIOCSIFLLADDR                           = 0x8020693c
	SIOCSIFMAC                              = 0x80206983
	SIOCSIFMEDIA                            = 0xc0206937
	SIOCSIFMETRIC                           = 0x80206918
	SIOCSIFMTU                              = 0x80206934
	SIOCSIFNETMASK                          = 0x80206916
	SIOCSIFPHYADDR                          = 0x8040693e
	SIOCSIFPHYS                             = 0x80206936
	SIOCSIFVLAN                             = 0x8020697e
	SIOCSLOWAT                              = 0x80047302
	SIOCSPGRP                               = 0x80047308
	SOCK_DGRAM                              = 0x2
	SOCK_MAXADDRLEN                         = 0xff
	SOCK_RAW                                = 0x3
	SOCK_RDM                                = 0x4
	SOCK_SEQPACKET                          = 0x5
	SOCK_STREAM                             = 0x1
	SOL_LOCAL                               = 0x0
	SOL_SOCKET                              = 0xffff
	SOMAXCONN                               = 0x80
	SO_ACCEPTCONN                           = 0x2
	SO_BROADCAST                            = 0x20
	SO_DEBUG                                = 0x1
	SO_DONTROUTE                            = 0x10
	SO_DONTTRUNC                            = 0x2000
	SO_ERROR                                = 0x1007
	SO_KEEPALIVE                            = 0x8
	SO_LABEL                                = 0x1010
	SO_LINGER                               = 0x80
	SO_LINGER_SEC                           = 0x1080
	SO_NETSVC_MARKING_LEVEL                 = 0x1119
	SO_NET_SERVICE_TYPE                     = 0x1116
	SO_NKE                                  = 0x1021
	SO_NOADDRERR                            = 0x1023
	SO_NOSIGPIPE                            = 0x1022
	SO_NOTIFYCONFLICT                       = 0x1026
	SO_NP_EXTENSIONS                        = 0x1083
	SO_NREAD                                = 0x1020
	SO_NUMRCVPKT                            = 0x1112
	SO_NWRITE                               = 0x1024
	SO_OOBINLINE                            = 0x100
	SO_PEERLABEL                            = 0x1011
	SO_RANDOMPORT                           = 0x1082
	SO_RCVBUF                               = 0x1002
	SO_RCVLOWAT                             = 0x1004
	SO_RCVTIMEO                             = 0x1006
	SO_REUSEADDR                            = 0x4
	SO_REUSEPORT                            = 0x200
	SO_REUSESHAREUID                        = 0x1025
	SO_SNDBUF                               = 0x1001
	SO_SNDLOWAT                             = 0x1003
	SO_SNDTIMEO                             = 0x1005
	SO_TIMESTAMP                            = 0x400
	SO_TIMESTAMP_MONOTONIC                  = 0x800
	SO_TRACKER_ATTRIBUTE_FLAGS_APP_APPROVED = 0x1
	SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT = 0x4
	SO_TRACKER_ATTRIBUTE_FLAGS_TRACKER      = 0x2
	SO_TRACKER_TRANSPARENCY_VERSION         = 0x3
	SO_TYPE                                 = 0x1008
	SO_UPCALLCLOSEWAIT                      = 0x1027
	SO_USELOOPBACK                          = 0x40
	SO_WANTMORE                             = 0x4000
	SO_WANTOOBFLAG                          = 0x8000
	S_IEXEC                                 = 0x40
	S_IFBLK                                 = 0x6000
	S_IFCHR                                 = 0x2000
	S_IFDIR                                 = 0x4000
	S_IFIFO                                 = 0x1000
	S_IFLNK                                 = 0xa000
	S_IFMT                                  = 0xf000
	S_IFREG                                 = 0x8000
	S_IFSOCK                                = 0xc000
	S_IFWHT                                 = 0xe000
	S_IREAD                                 = 0x100
	S_IRGRP                                 = 0x20
	S_IROTH                                 = 0x4
	S_IRUSR                                 = 0x100
	S_IRWXG                                 = 0x38
	S_IRWXO                                 = 0x7
	S_IRWXU                                 = 0x1c0
	S_ISGID                                 = 0x400
	S_ISTXT                                 = 0x200
	S_ISUID                                 = 0x800
	S_ISVTX                                 = 0x200
	S_IWGRP                                 = 0x10
	S_IWOTH                                 = 0x2
	S_IWRITE                                = 0x80
	S_IWUSR                                 = 0x80
	S_IXGRP                                 = 0x8
	S_IXOTH                                 = 0x1
	S_IXUSR                                 = 0x40
	TAB0                                    = 0x0
	TAB1                                    = 0x400
	TAB2                                    = 0x800
	TAB3                                    = 0x4
	TABDLY                                  = 0xc04
	TCIFLUSH                                = 0x1
	TCIOFF                                  = 0x3
	TCIOFLUSH                               = 0x3
	TCION                                   = 0x4
	TCOFLUSH                                = 0x2
	TCOOFF                                  = 0x1
	TCOON                                   = 0x2
	TCPOPT_CC                               = 0xb
	TCPOPT_CCECHO                           = 0xd
	TCPOPT_CCNEW                            = 0xc
	TCPOPT_EOL                              = 0x0
	TCPOPT_FASTOPEN                         = 0x22
	TCPOPT_MAXSEG                           = 0x2
	TCPOPT_NOP                              = 0x1
	TCPOPT_SACK                             = 0x5
	TCPOPT_SACK_HDR                         = 0x1010500
	TCPOPT_SACK_PERMITTED                   = 0x4
	TCPOPT_SACK_PERMIT_HDR                  = 0x1010402
	TCPOPT_SIGNATURE                        = 0x13
	TCPOPT_TIMESTAMP                        = 0x8
	TCPOPT_TSTAMP_HDR                       = 0x101080a
	TCPOPT_WINDOW                           = 0x3
	TCP_CONNECTIONTIMEOUT                   = 0x20
	TCP_CONNECTION_INFO                     = 0x106
	TCP_ENABLE_ECN                          = 0x104
	TCP_FASTOPEN                            = 0x105
	TCP_KEEPALIVE                           = 0x10
	TCP_KEEPCNT                             = 0x102
	TCP_KEEPINTVL                           = 0x101
	TCP_MAXHLEN                             = 0x3c
	TCP_MAXOLEN                             = 0x28
	TCP_MAXSEG                              = 0x2
	TCP_MAXWIN                              = 0xffff
	TCP_MAX_SACK                            = 0x4
	TCP_MAX_WINSHIFT                        = 0xe
	TCP_MINMSS                              = 0xd8
	TCP_MSS                                 = 0x200
	TCP_NODELAY                             = 0x1
	TCP_NOOPT                               = 0x8
	TCP_NOPUSH                              = 0x4
	TCP_NOTSENT_LOWAT                       = 0x201
	TCP_RXT_CONNDROPTIME                    = 0x80
	TCP_RXT_FINDROP                         = 0x100
	TCP_SENDMOREACKS                        = 0x103
	TCSAFLUSH                               = 0x2
	TIOCCBRK                                = 0x2000747a
	TIOCCDTR                                = 0x20007478
	TIOCCONS                                = 0x80047462
	TIOCDCDTIMESTAMP                        = 0x40107458
	TIOCDRAIN                               = 0x2000745e
	TIOCDSIMICROCODE                        = 0x20007455
	TIOCEXCL                                = 0x2000740d
	TIOCEXT                                 = 0x80047460
	TIOCFLUSH                               = 0x80047410
	TIOCGDRAINWAIT                          = 0x40047456
	TIOCGETA                                = 0x40487413
	TIOCGETD                                = 0x4004741a
	TIOCGPGRP                               = 0x40047477
	TIOCGWINSZ                              = 0x40087468
	TIOCIXOFF                               = 0x20007480
	TIOCIXON                                = 0x20007481
	TIOCMBIC                                = 0x8004746b
	TIOCMBIS                                = 0x8004746c
	TIOCMGDTRWAIT                           = 0x4004745a
	TIOCMGET                                = 0x4004746a
	TIOCMODG                                = 0x40047403
	TIOCMODS                                = 0x80047404
	TIOCMSDTRWAIT                           = 0x8004745b
	TIOCMSET                                = 0x8004746d
	TIOCM_CAR                               = 0x40
	TIOCM_CD                                = 0x40
	TIOCM_CTS                               = 0x20
	TIOCM_DSR                               = 0x100
	TIOCM_DTR                               = 0x2
	TIOCM_LE                                = 0x1
	TIOCM_RI                                = 0x80
	TIOCM_RNG                               = 0x80
	TIOCM_RTS                               = 0x4
	TIOCM_SR                                = 0x10
	TIOCM_ST                                = 0x8
	TIOCNOTTY                               = 0x20007471
	TIOCNXCL                                = 0x2000740e
	TIOCOUTQ                                = 0x40047473
	TIOCPKT                                 = 0x80047470
	TIOCPKT_DATA                            = 0x0
	TIOCPKT_DOSTOP                          = 0x20
	TIOCPKT_FLUSHREAD                       = 0x1
	TIOCPKT_FLUSHWRITE                      = 0x2
	TIOCPKT_IOCTL                           = 0x40
	TIOCPKT_NOSTOP                          = 0x10
	TIOCPKT_START                           = 0x8
	TIOCPKT_STOP                            = 0x4
	TIOCPTYGNAME                            = 0x40807453
	TIOCPTYGRANT                            = 0x20007454
	TIOCPTYUNLK                             = 0x20007452
	TIOCREMOTE                              = 0x80047469
	TIOCSBRK                                = 0x2000747b
	TIOCSCONS                               = 0x20007463
	TIOCSCTTY                               = 0x20007461
	TIOCSDRAINWAIT                          = 0x80047457
	TIOCSDTR                                = 0x20007479
	TIOCSETA                                = 0x80487414
	TIOCSETAF                               = 0x80487416
	TIOCSETAW                               = 0x80487415
	TIOCSETD                                = 0x8004741b
	TIOCSIG                                 = 0x2000745f
	TIOCSPGRP                               = 0x80047476
	TIOCSTART                               = 0x2000746e
	TIOCSTAT                                = 0x20007465
	TIOCSTI                                 = 0x80017472
	TIOCSTOP                                = 0x2000746f
	TIOCSWINSZ                              = 0x80087467
	TIOCTIMESTAMP                           = 0x40107459
	TIOCUCNTL                               = 0x80047466
	TOSTOP                                  = 0x400000
	UF_APPEND                               = 0x4
	UF_COMPRESSED                           = 0x20
	UF_DATAVAULT                            = 0x80
	UF_HIDDEN                               = 0x8000
	UF_IMMUTABLE                            = 0x2
	UF_NODUMP                               = 0x1
	UF_OPAQUE                               = 0x8
	UF_SETTABLE                             = 0xffff
	UF_TRACKED                              = 0x40
	VDISCARD                                = 0xf
	VDSUSP                                  = 0xb
	VEOF                                    = 0x0
	VEOL                                    = 0x1
	VEOL2                                   = 0x2
	VERASE                                  = 0x3
	VINTR                                   = 0x8
	VKILL                                   = 0x5
	VLNEXT                                  = 0xe
	VMADDR_CID_ANY                          = 0xffffffff
	VMADDR_CID_HOST                         = 0x2
	VMADDR_CID_HYPERVISOR                   = 0x0
	VMADDR_CID_RESERVED                     = 0x1
	VMADDR_PORT_ANY                         = 0xffffffff
	VMIN                                    = 0x10
	VM_LOADAVG                              = 0x2
	VM_MACHFACTOR                           = 0x4
	VM_MAXID                                = 0x6
	VM_METER                                = 0x1
	VM_SWAPUSAGE                            = 0x5
	VQUIT                                   = 0x9
	VREPRINT                                = 0x6
	VSTART                                  = 0xc
	VSTATUS                                 = 0x12
	VSTOP                                   = 0xd
	VSUSP                                   = 0xa
	VT0                                     = 0x0
	VT1                                     = 0x10000
	VTDLY                                   = 0x10000
	VTIME                                   = 0x11
	VWERASE                                 = 0x4
	WCONTINUED                              = 0x10
	WCOREFLAG                               = 0x80
	WEXITED                                 = 0x4
	WNOHANG                                 = 0x1
	WNOWAIT                                 = 0x20
	WORDSIZE                                = 0x40
	WSTOPPED                                = 0x8
	WUNTRACED                               = 0x2
	XATTR_CREATE                            = 0x2
	XATTR_NODEFAULT                         = 0x10
	XATTR_NOFOLLOW                          = 0x1
	XATTR_NOSECURITY                        = 0x8
	XATTR_REPLACE                           = 0x4
	XATTR_SHOWCOMPRESSION                   = 0x20
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
	EBADARCH        = syscall.Errno(0x56)
	EBADEXEC        = syscall.Errno(0x55)
	EBADF           = syscall.Errno(0x9)
	EBADMACHO       = syscall.Errno(0x58)
	EBADMSG         = syscall.Errno(0x5e)
	EBADRPC         = syscall.Errno(0x48)
	EBUSY           = syscall.Errno(0x10)
	ECANCELED       = syscall.Errno(0x59)
	ECHILD          = syscall.Errno(0xa)
	ECONNABORTED    = syscall.Errno(0x35)
	ECONNREFUSED    = syscall.Errno(0x3d)
	ECONNRESET      = syscall.Errno(0x36)
	EDEADLK         = syscall.Errno(0xb)
	EDESTADDRREQ    = syscall.Errno(0x27)
	EDEVERR         = syscall.Errno(0x53)
	EDOM            = syscall.Errno(0x21)
	EDQUOT          = syscall.Errno(0x45)
	EEXIST          = syscall.Errno(0x11)
	EFAULT          = syscall.Errno(0xe)
	EFBIG           = syscall.Errno(0x1b)
	EFTYPE          = syscall.Errno(0x4f)
	EHOSTDOWN       = syscall.Errno(0x40)
	EHOSTUNREACH    = syscall.Errno(0x41)
	EIDRM           = syscall.Errno(0x5a)
	EILSEQ          = syscall.Errno(0x5c)
	EINPROGRESS     = syscall.Errno(0x24)
	EINTR           = syscall.Errno(0x4)
	EINVAL          = syscall.Errno(0x16)
	EIO             = syscall.Errno(0x5)
	EISCONN         = syscall.Errno(0x38)
	EISDIR          = syscall.Errno(0x15)
	ELAST           = syscall.Errno(0x6a)
	ELOOP           = syscall.Errno(0x3e)
	EMFILE          = syscall.Errno(0x18)
	EMLINK          = syscall.Errno(0x1f)
	EMSGSIZE        = syscall.Errno(0x28)
	EMULTIHOP       = syscall.Errno(0x5f)
	ENAMETOOLONG    = syscall.Errno(0x3f)
	ENEEDAUTH       = syscall.Errno(0x51)
	ENETDOWN        = syscall.Errno(0x32)
	ENETRESET       = syscall.Errno(0x34)
	ENETUNREACH     = syscall.Errno(0x33)
	ENFILE          = syscall.Errno(0x17)
	ENOATTR         = syscall.Errno(0x5d)
	ENOBUFS         = syscall.Errno(0x37)
	ENODATA         = syscall.Errno(0x60)
	ENODEV          = syscall.Errno(0x13)
	ENOENT          = syscall.Errno(0x2)
	ENOEXEC         = syscall.Errno(0x8)
	ENOLCK          = syscall.Errno(0x4d)
	ENOLINK         = syscall.Errno(0x61)
	ENOMEM          = syscall.Errno(0xc)
	ENOMSG          = syscall.Errno(0x5b)
	ENOPOLICY       = syscall.Errno(0x67)
	ENOPROTOOPT     = syscall.Errno(0x2a)
	ENOSPC          = syscall.Errno(0x1c)
	ENOSR           = syscall.Errno(0x62)
	ENOSTR          = syscall.Errno(0x63)
	ENOSYS          = syscall.Errno(0x4e)
	ENOTBLK         = syscall.Errno(0xf)
	ENOTCONN        = syscall.Errno(0x39)
	ENOTDIR         = syscall.Errno(0x14)
	ENOTEMPTY       = syscall.Errno(0x42)
	ENOTRECOVERABLE = syscall.Errno(0x68)
	ENOTSOCK        = syscall.Errno(0x26)
	ENOTSUP         = syscall.Errno(0x2d)
	ENOTTY          = syscall.Errno(0x19)
	ENXIO           = syscall.Errno(0x6)
	EOPNOTSUPP      = syscall.Errno(0x66)
	EOVERFLOW       = syscall.Errno(0x54)
	EOWNERDEAD      = syscall.Errno(0x69)
	EPERM           = syscall.Errno(0x1)
	EPFNOSUPPORT    = syscall.Errno(0x2e)
	EPIPE           = syscall.Errno(0x20)
	EPROCLIM        = syscall.Errno(0x43)
	EPROCUNAVAIL    = syscall.Errno(0x4c)
	EPROGMISMATCH   = syscall.Errno(0x4b)
	EPROGUNAVAIL    = syscall.Errno(0x4a)
	EPROTO          = syscall.Errno(0x64)
	EPROTONOSUPPORT = syscall.Errno(0x2b)
	EPROTOTYPE      = syscall.Errno(0x29)
	EPWROFF         = syscall.Errno(0x52)
	EQFULL          = syscall.Errno(0x6a)
	ERANGE          = syscall.Errno(0x22)
	EREMOTE         = syscall.Errno(0x47)
	EROFS           = syscall.Errno(0x1e)
	ERPCMISMATCH    = syscall.Errno(0x49)
	ESHLIBVERS      = syscall.Errno(0x57)
	ESHUTDOWN       = syscall.Errno(0x3a)
	ESOCKTNOSUPPORT = syscall.Errno(0x2c)
	ESPIPE          = syscall.Errno(0x1d)
	ESRCH           = syscall.Errno(0x3)
	ESTALE          = syscall.Errno(0x46)
	ETIME           = syscall.Errno(0x65)
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
	{16, "EBUSY", "resource busy"},
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
	{45, "ENOTSUP", "operation not supported"},
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
	{82, "EPWROFF", "device power is off"},
	{83, "EDEVERR", "device error"},
	{84, "EOVERFLOW", "value too large to be stored in data type"},
	{85, "EBADEXEC", "bad executable (or shared library)"},
	{86, "EBADARCH", "bad CPU type in executable"},
	{87, "ESHLIBVERS", "shared library version mismatch"},
	{88, "EBADMACHO", "malformed Mach-o file"},
	{89, "ECANCELED", "operation canceled"},
	{90, "EIDRM", "identifier removed"},
	{91, "ENOMSG", "no message of desired type"},
	{92, "EILSEQ", "illegal byte sequence"},
	{93, "ENOATTR", "attribute not found"},
	{94, "EBADMSG", "bad message"},
	{95, "EMULTIHOP", "EMULTIHOP (Reserved)"},
	{96, "ENODATA", "no message available on STREAM"},
	{97, "ENOLINK", "ENOLINK (Reserved)"},
	{98, "ENOSR", "no STREAM resources"},
	{99, "ENOSTR", "not a STREAM"},
	{100, "EPROTO", "protocol error"},
	{101, "ETIME", "STREAM ioctl timeout"},
	{102, "EOPNOTSUPP", "operation not supported on socket"},
	{103, "ENOPOLICY", "policy not found"},
	{104, "ENOTRECOVERABLE", "state not recoverable"},
	{105, "EOWNERDEAD", "previous owner died"},
	{106, "EQFULL", "interface output queue is full"},
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
}

"""




```