Response:
The user is asking for a summary of the functionality provided by the given Go code snippet. This is the second part of a two-part question. Since I have both parts, I should synthesize the information from both to give a complete picture.

**Part 1 (assumed, as it's the counterpart to this Part 2):**  Likely contained definitions of system call numbers, constants related to system calls, and potentially some basic type definitions for errors and signals.

**Part 2 (the current snippet):** Defines a large number of constants related to various system-level functionalities on Darwin/AMD64. It also defines error numbers and signal numbers, and provides string representations for these errors and signals.

**Overall Functionality:** This file essentially provides Go with the necessary definitions to interact with the underlying Darwin (macOS) operating system kernel on AMD64 architecture. It acts as a bridge between Go's high-level abstractions and the low-level system calls.

**Key Areas Covered:**

*   **Resource Limits (RLIMIT_*) and related constants (RLIM_INFINITY):** Control resource usage.
*   **Routing Table Attributes (RTAX_*) and Flags (RTA_*, RTF_*):**  Deal with network routing information.
*   **Routing Message Types (RTM_*):** Define types of routing messages.
*   **Routing Tree Values (RTV_*):**  Related to routing metrics.
*   **Resource Usage (RUSAGE_*):** Identify different contexts for resource usage.
*   **Socket Control Messages (SCM_*):**  Used for passing ancillary data with socket messages.
*   **Socket Shutdown Options (SHUT_*):**  Control how a socket connection is closed.
*   **Socket I/O Control Commands (SIOC*):** A large set of constants representing various socket-related operations, often for network interface configuration.
*   **Socket Types (SOCK_*):** Define different types of sockets (e.g., stream, datagram).
*   **Socket Options (SOL_SOCKET, SO_*):**  Options for configuring socket behavior.
*   **File Mode Bits (S_IF*, S_I*):**  Represent file types and permissions.
*   **Terminal Control Constants (TCIFLUSH, TCIOFLUSH, TCOFLUSH, TCSAFLUSH):**  Control terminal input/output flushing.
*   **TCP Options (TCP_*):**  Options for configuring TCP socket behavior.
*   **Terminal I/O Control Commands (TIOCCBRK, TIOCDTR, etc.):** A large set of constants for interacting with terminal devices.
*   **Terminal Special Characters (VDISCARD, VDSUSP, etc.):**  Define special characters used in terminal input processing.
*   **Wait Options (WCONTINUED, WCOREFLAG, etc.):** Options for the `wait` system call.
*   **Word Size (WORDSIZE):**  Indicates the architecture's word size.
*   **Error Numbers (E*):**  Standard POSIX error codes.
*   **Signal Numbers (SIG*):**  Standard POSIX signal numbers.
*   **Error Table (errors):** Maps error numbers to human-readable strings.
*   **Signal Table (signals):** Maps signal numbers to human-readable strings.
基于您提供的代码片段（第 2 部分），并结合您提到这是路径为 `go/src/syscall/zerrors_darwin_amd64.go` 的 Go 语言实现的一部分，我们可以归纳出以下功能：

**核心功能：提供 Darwin (macOS) 操作系统在 AMD64 架构下的系统调用相关的常量定义，以及错误码和信号量的字符串映射。**

**具体来说，这个文件主要完成了以下任务：**

1. **定义了大量的常量:** 这些常量以十六进制形式定义，涵盖了操作系统底层的各种属性和操作，例如：
    *   **资源限制 (RLIMIT_*)**:  用于控制进程可以使用的系统资源，如 CPU 时间、内存等。
    *   **路由表属性 (RTAX_*) 和标志 (RTA_*, RTF_*)**:  与网络路由配置相关，用于描述路由信息的各个方面。
    *   **路由消息类型 (RTM_*)**:  定义了不同类型的路由消息，用于内核间的路由信息交换。
    *   **路由条目值 (RTV_*)**:  表示路由条目的各种度量值，如跳数、MTU 等。
    *   **资源使用情况 (RUSAGE_*)**:  区分了进程自身及其子进程的资源使用情况。
    *   **Socket 控制消息 (SCM_*)**:  用于在进程间通过 socket 传递辅助数据（如文件描述符）。
    *   **Socket 关闭方式 (SHUT_*)**:  定义了 socket 关闭读、写或双向连接的方式。
    *   **Socket I/O 控制命令 (SIOC*)**:  这是一大类常量，用于通过 `ioctl` 系统调用控制 socket 的行为和网络接口的配置。
    *   **Socket 类型 (SOCK_*)**:  定义了不同类型的 socket，如流式 socket (TCP) 和数据报 socket (UDP)。
    *   **Socket 选项 (SOL_SOCKET, SO_*)**:  用于设置 socket 的各种选项，如是否允许广播、是否保持连接等。
    *   **文件模式位 (S_IF*, S_I*)**:  用于表示文件类型（如目录、普通文件、链接等）和文件权限。
    *   **终端控制常量 (TCIFLUSH, TCIOFLUSH, TCOFLUSH, TCSAFLUSH)**:  用于控制终端的输入输出缓冲区刷新。
    *   **TCP 选项 (TCP_*)**:  用于配置 TCP 连接的各种参数，如是否禁用 Nagle 算法、最大报文段大小等。
    *   **终端 I/O 控制命令 (TIOCCBRK, TIOCDTR 等)**:  用于通过 `ioctl` 系统调用控制终端设备的各种行为。
    *   **终端特殊字符 (VDISCARD, VDSUSP 等)**:  定义了终端输入中具有特殊含义的字符。
    *   **进程等待选项 (WCONTINUED, WCOREFLAG 等)**:  用于 `wait` 系统调用，控制父进程如何等待子进程的状态变化。
    *   **字长 (WORDSIZE)**:  定义了系统的字长。

2. **定义了错误码常量 (E*)**:  这些常量对应于操作系统返回的错误码，用于指示系统调用失败的原因。

3. **定义了信号量常量 (SIG*)**:  这些常量对应于操作系统可以发送给进程的信号，用于通知进程发生了某些事件。

4. **提供了错误码到字符串的映射 (errors 变量)**:  这是一个字符串数组，将错误码（作为索引）映射到对应的可读错误信息。

5. **提供了信号量到字符串的映射 (signals 变量)**:  这是一个字符串数组，将信号量（作为索引）映射到对应的可读信号名称。

**总而言之，这个文件是 Go 语言 `syscall` 包在 Darwin/AMD64 平台上实现与操作系统底层交互的关键组成部分。它将操作系统底层的常量、错误码和信号量以 Go 语言可以理解的方式定义出来，使得 Go 程序能够调用系统调用，并处理来自操作系统的错误和信号。**

由于这是第二部分，我们没有看到具体的系统调用代码，所以无法直接推理出特定 Go 语言功能的实现，也无法提供具体的 Go 代码示例或命令行参数处理的说明。

**总结来说，这个文件的核心功能是为 Go 语言在 Darwin/AMD64 平台上进行底层系统编程提供必要的常量和映射。**

Prompt: 
```
这是路径为go/src/syscall/zerrors_darwin_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
           = 0x8
	RLIMIT_STACK                      = 0x3
	RLIM_INFINITY                     = 0x7fffffffffffffff
	RTAX_AUTHOR                       = 0x6
	RTAX_BRD                          = 0x7
	RTAX_DST                          = 0x0
	RTAX_GATEWAY                      = 0x1
	RTAX_GENMASK                      = 0x3
	RTAX_IFA                          = 0x5
	RTAX_IFP                          = 0x4
	RTAX_MAX                          = 0x8
	RTAX_NETMASK                      = 0x2
	RTA_AUTHOR                        = 0x40
	RTA_BRD                           = 0x80
	RTA_DST                           = 0x1
	RTA_GATEWAY                       = 0x2
	RTA_GENMASK                       = 0x8
	RTA_IFA                           = 0x20
	RTA_IFP                           = 0x10
	RTA_NETMASK                       = 0x4
	RTF_BLACKHOLE                     = 0x1000
	RTF_BROADCAST                     = 0x400000
	RTF_CLONING                       = 0x100
	RTF_CONDEMNED                     = 0x2000000
	RTF_DELCLONE                      = 0x80
	RTF_DONE                          = 0x40
	RTF_DYNAMIC                       = 0x10
	RTF_GATEWAY                       = 0x2
	RTF_HOST                          = 0x4
	RTF_IFREF                         = 0x4000000
	RTF_IFSCOPE                       = 0x1000000
	RTF_LLINFO                        = 0x400
	RTF_LOCAL                         = 0x200000
	RTF_MODIFIED                      = 0x20
	RTF_MULTICAST                     = 0x800000
	RTF_PINNED                        = 0x100000
	RTF_PRCLONING                     = 0x10000
	RTF_PROTO1                        = 0x8000
	RTF_PROTO2                        = 0x4000
	RTF_PROTO3                        = 0x40000
	RTF_REJECT                        = 0x8
	RTF_STATIC                        = 0x800
	RTF_UP                            = 0x1
	RTF_WASCLONED                     = 0x20000
	RTF_XRESOLVE                      = 0x200
	RTM_ADD                           = 0x1
	RTM_CHANGE                        = 0x3
	RTM_DELADDR                       = 0xd
	RTM_DELETE                        = 0x2
	RTM_DELMADDR                      = 0x10
	RTM_GET                           = 0x4
	RTM_GET2                          = 0x14
	RTM_IFINFO                        = 0xe
	RTM_IFINFO2                       = 0x12
	RTM_LOCK                          = 0x8
	RTM_LOSING                        = 0x5
	RTM_MISS                          = 0x7
	RTM_NEWADDR                       = 0xc
	RTM_NEWMADDR                      = 0xf
	RTM_NEWMADDR2                     = 0x13
	RTM_OLDADD                        = 0x9
	RTM_OLDDEL                        = 0xa
	RTM_REDIRECT                      = 0x6
	RTM_RESOLVE                       = 0xb
	RTM_RTTUNIT                       = 0xf4240
	RTM_VERSION                       = 0x5
	RTV_EXPIRE                        = 0x4
	RTV_HOPCOUNT                      = 0x2
	RTV_MTU                           = 0x1
	RTV_RPIPE                         = 0x8
	RTV_RTT                           = 0x40
	RTV_RTTVAR                        = 0x80
	RTV_SPIPE                         = 0x10
	RTV_SSTHRESH                      = 0x20
	RUSAGE_CHILDREN                   = -0x1
	RUSAGE_SELF                       = 0x0
	SCM_CREDS                         = 0x3
	SCM_RIGHTS                        = 0x1
	SCM_TIMESTAMP                     = 0x2
	SCM_TIMESTAMP_MONOTONIC           = 0x4
	SHUT_RD                           = 0x0
	SHUT_RDWR                         = 0x2
	SHUT_WR                           = 0x1
	SIOCADDMULTI                      = 0x80206931
	SIOCAIFADDR                       = 0x8040691a
	SIOCALIFADDR                      = 0x8118691d
	SIOCARPIPLL                       = 0xc0206928
	SIOCATMARK                        = 0x40047307
	SIOCAUTOADDR                      = 0xc0206926
	SIOCAUTONETMASK                   = 0x80206927
	SIOCDELMULTI                      = 0x80206932
	SIOCDIFADDR                       = 0x80206919
	SIOCDIFPHYADDR                    = 0x80206941
	SIOCDLIFADDR                      = 0x8118691f
	SIOCGDRVSPEC                      = 0xc028697b
	SIOCGETSGCNT                      = 0xc014721c
	SIOCGETVIFCNT                     = 0xc014721b
	SIOCGETVLAN                       = 0xc020697f
	SIOCGHIWAT                        = 0x40047301
	SIOCGIFADDR                       = 0xc0206921
	SIOCGIFALTMTU                     = 0xc0206948
	SIOCGIFASYNCMAP                   = 0xc020697c
	SIOCGIFBOND                       = 0xc0206947
	SIOCGIFBRDADDR                    = 0xc0206923
	SIOCGIFCAP                        = 0xc020695b
	SIOCGIFCONF                       = 0xc00c6924
	SIOCGIFDEVMTU                     = 0xc0206944
	SIOCGIFDSTADDR                    = 0xc0206922
	SIOCGIFFLAGS                      = 0xc0206911
	SIOCGIFGENERIC                    = 0xc020693a
	SIOCGIFKPI                        = 0xc0206987
	SIOCGIFMAC                        = 0xc0206982
	SIOCGIFMEDIA                      = 0xc02c6938
	SIOCGIFMETRIC                     = 0xc0206917
	SIOCGIFMTU                        = 0xc0206933
	SIOCGIFNETMASK                    = 0xc0206925
	SIOCGIFPDSTADDR                   = 0xc0206940
	SIOCGIFPHYS                       = 0xc0206935
	SIOCGIFPSRCADDR                   = 0xc020693f
	SIOCGIFSTATUS                     = 0xc331693d
	SIOCGIFVLAN                       = 0xc020697f
	SIOCGIFWAKEFLAGS                  = 0xc0206988
	SIOCGLIFADDR                      = 0xc118691e
	SIOCGLIFPHYADDR                   = 0xc1186943
	SIOCGLOWAT                        = 0x40047303
	SIOCGPGRP                         = 0x40047309
	SIOCIFCREATE                      = 0xc0206978
	SIOCIFCREATE2                     = 0xc020697a
	SIOCIFDESTROY                     = 0x80206979
	SIOCRSLVMULTI                     = 0xc010693b
	SIOCSDRVSPEC                      = 0x8028697b
	SIOCSETVLAN                       = 0x8020697e
	SIOCSHIWAT                        = 0x80047300
	SIOCSIFADDR                       = 0x8020690c
	SIOCSIFALTMTU                     = 0x80206945
	SIOCSIFASYNCMAP                   = 0x8020697d
	SIOCSIFBOND                       = 0x80206946
	SIOCSIFBRDADDR                    = 0x80206913
	SIOCSIFCAP                        = 0x8020695a
	SIOCSIFDSTADDR                    = 0x8020690e
	SIOCSIFFLAGS                      = 0x80206910
	SIOCSIFGENERIC                    = 0x80206939
	SIOCSIFKPI                        = 0x80206986
	SIOCSIFLLADDR                     = 0x8020693c
	SIOCSIFMAC                        = 0x80206983
	SIOCSIFMEDIA                      = 0xc0206937
	SIOCSIFMETRIC                     = 0x80206918
	SIOCSIFMTU                        = 0x80206934
	SIOCSIFNETMASK                    = 0x80206916
	SIOCSIFPHYADDR                    = 0x8040693e
	SIOCSIFPHYS                       = 0x80206936
	SIOCSIFVLAN                       = 0x8020697e
	SIOCSLIFPHYADDR                   = 0x81186942
	SIOCSLOWAT                        = 0x80047302
	SIOCSPGRP                         = 0x80047308
	SOCK_DGRAM                        = 0x2
	SOCK_MAXADDRLEN                   = 0xff
	SOCK_RAW                          = 0x3
	SOCK_RDM                          = 0x4
	SOCK_SEQPACKET                    = 0x5
	SOCK_STREAM                       = 0x1
	SOL_SOCKET                        = 0xffff
	SOMAXCONN                         = 0x80
	SO_ACCEPTCONN                     = 0x2
	SO_BROADCAST                      = 0x20
	SO_DEBUG                          = 0x1
	SO_DONTROUTE                      = 0x10
	SO_DONTTRUNC                      = 0x2000
	SO_ERROR                          = 0x1007
	SO_KEEPALIVE                      = 0x8
	SO_LABEL                          = 0x1010
	SO_LINGER                         = 0x80
	SO_LINGER_SEC                     = 0x1080
	SO_NKE                            = 0x1021
	SO_NOADDRERR                      = 0x1023
	SO_NOSIGPIPE                      = 0x1022
	SO_NOTIFYCONFLICT                 = 0x1026
	SO_NP_EXTENSIONS                  = 0x1083
	SO_NREAD                          = 0x1020
	SO_NWRITE                         = 0x1024
	SO_OOBINLINE                      = 0x100
	SO_PEERLABEL                      = 0x1011
	SO_RANDOMPORT                     = 0x1082
	SO_RCVBUF                         = 0x1002
	SO_RCVLOWAT                       = 0x1004
	SO_RCVTIMEO                       = 0x1006
	SO_RESTRICTIONS                   = 0x1081
	SO_RESTRICT_DENYIN                = 0x1
	SO_RESTRICT_DENYOUT               = 0x2
	SO_RESTRICT_DENYSET               = 0x80000000
	SO_REUSEADDR                      = 0x4
	SO_REUSEPORT                      = 0x200
	SO_REUSESHAREUID                  = 0x1025
	SO_SNDBUF                         = 0x1001
	SO_SNDLOWAT                       = 0x1003
	SO_SNDTIMEO                       = 0x1005
	SO_TIMESTAMP                      = 0x400
	SO_TIMESTAMP_MONOTONIC            = 0x800
	SO_TYPE                           = 0x1008
	SO_UPCALLCLOSEWAIT                = 0x1027
	SO_USELOOPBACK                    = 0x40
	SO_WANTMORE                       = 0x4000
	SO_WANTOOBFLAG                    = 0x8000
	S_IEXEC                           = 0x40
	S_IFBLK                           = 0x6000
	S_IFCHR                           = 0x2000
	S_IFDIR                           = 0x4000
	S_IFIFO                           = 0x1000
	S_IFLNK                           = 0xa000
	S_IFMT                            = 0xf000
	S_IFREG                           = 0x8000
	S_IFSOCK                          = 0xc000
	S_IFWHT                           = 0xe000
	S_IREAD                           = 0x100
	S_IRGRP                           = 0x20
	S_IROTH                           = 0x4
	S_IRUSR                           = 0x100
	S_IRWXG                           = 0x38
	S_IRWXO                           = 0x7
	S_IRWXU                           = 0x1c0
	S_ISGID                           = 0x400
	S_ISTXT                           = 0x200
	S_ISUID                           = 0x800
	S_ISVTX                           = 0x200
	S_IWGRP                           = 0x10
	S_IWOTH                           = 0x2
	S_IWRITE                          = 0x80
	S_IWUSR                           = 0x80
	S_IXGRP                           = 0x8
	S_IXOTH                           = 0x1
	S_IXUSR                           = 0x40
	TCIFLUSH                          = 0x1
	TCIOFLUSH                         = 0x3
	TCOFLUSH                          = 0x2
	TCP_CONNECTIONTIMEOUT             = 0x20
	TCP_KEEPALIVE                     = 0x10
	TCP_MAXHLEN                       = 0x3c
	TCP_MAXOLEN                       = 0x28
	TCP_MAXSEG                        = 0x2
	TCP_MAXWIN                        = 0xffff
	TCP_MAX_SACK                      = 0x3
	TCP_MAX_WINSHIFT                  = 0xe
	TCP_MINMSS                        = 0xd8
	TCP_MINMSSOVERLOAD                = 0x3e8
	TCP_MSS                           = 0x200
	TCP_NODELAY                       = 0x1
	TCP_NOOPT                         = 0x8
	TCP_NOPUSH                        = 0x4
	TCP_RXT_CONNDROPTIME              = 0x80
	TCP_RXT_FINDROP                   = 0x100
	TCSAFLUSH                         = 0x2
	TIOCCBRK                          = 0x2000747a
	TIOCCDTR                          = 0x20007478
	TIOCCONS                          = 0x80047462
	TIOCDCDTIMESTAMP                  = 0x40107458
	TIOCDRAIN                         = 0x2000745e
	TIOCDSIMICROCODE                  = 0x20007455
	TIOCEXCL                          = 0x2000740d
	TIOCEXT                           = 0x80047460
	TIOCFLUSH                         = 0x80047410
	TIOCGDRAINWAIT                    = 0x40047456
	TIOCGETA                          = 0x40487413
	TIOCGETD                          = 0x4004741a
	TIOCGPGRP                         = 0x40047477
	TIOCGWINSZ                        = 0x40087468
	TIOCIXOFF                         = 0x20007480
	TIOCIXON                          = 0x20007481
	TIOCMBIC                          = 0x8004746b
	TIOCMBIS                          = 0x8004746c
	TIOCMGDTRWAIT                     = 0x4004745a
	TIOCMGET                          = 0x4004746a
	TIOCMODG                          = 0x40047403
	TIOCMODS                          = 0x80047404
	TIOCMSDTRWAIT                     = 0x8004745b
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
	TIOCPTYGNAME                      = 0x40807453
	TIOCPTYGRANT                      = 0x20007454
	TIOCPTYUNLK                       = 0x20007452
	TIOCREMOTE                        = 0x80047469
	TIOCSBRK                          = 0x2000747b
	TIOCSCONS                         = 0x20007463
	TIOCSCTTY                         = 0x20007461
	TIOCSDRAINWAIT                    = 0x80047457
	TIOCSDTR                          = 0x20007479
	TIOCSETA                          = 0x80487414
	TIOCSETAF                         = 0x80487416
	TIOCSETAW                         = 0x80487415
	TIOCSETD                          = 0x8004741b
	TIOCSIG                           = 0x2000745f
	TIOCSPGRP                         = 0x80047476
	TIOCSTART                         = 0x2000746e
	TIOCSTAT                          = 0x20007465
	TIOCSTI                           = 0x80017472
	TIOCSTOP                          = 0x2000746f
	TIOCSWINSZ                        = 0x80087467
	TIOCTIMESTAMP                     = 0x40107459
	TIOCUCNTL                         = 0x80047466
	TOSTOP                            = 0x400000
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
	VQUIT                             = 0x9
	VREPRINT                          = 0x6
	VSTART                            = 0xc
	VSTATUS                           = 0x12
	VSTOP                             = 0xd
	VSUSP                             = 0xa
	VT0                               = 0x0
	VT1                               = 0x10000
	VTDLY                             = 0x10000
	VTIME                             = 0x11
	VWERASE                           = 0x4
	WCONTINUED                        = 0x10
	WCOREFLAG                         = 0x80
	WEXITED                           = 0x4
	WNOHANG                           = 0x1
	WNOWAIT                           = 0x20
	WORDSIZE                          = 0x40
	WSTOPPED                          = 0x8
	WUNTRACED                         = 0x2
)

// Errors
const (
	E2BIG           = Errno(0x7)
	EACCES          = Errno(0xd)
	EADDRINUSE      = Errno(0x30)
	EADDRNOTAVAIL   = Errno(0x31)
	EAFNOSUPPORT    = Errno(0x2f)
	EAGAIN          = Errno(0x23)
	EALREADY        = Errno(0x25)
	EAUTH           = Errno(0x50)
	EBADARCH        = Errno(0x56)
	EBADEXEC        = Errno(0x55)
	EBADF           = Errno(0x9)
	EBADMACHO       = Errno(0x58)
	EBADMSG         = Errno(0x5e)
	EBADRPC         = Errno(0x48)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x59)
	ECHILD          = Errno(0xa)
	ECONNABORTED    = Errno(0x35)
	ECONNREFUSED    = Errno(0x3d)
	ECONNRESET      = Errno(0x36)
	EDEADLK         = Errno(0xb)
	EDESTADDRREQ    = Errno(0x27)
	EDEVERR         = Errno(0x53)
	EDOM            = Errno(0x21)
	EDQUOT          = Errno(0x45)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EFTYPE          = Errno(0x4f)
	EHOSTDOWN       = Errno(0x40)
	EHOSTUNREACH    = Errno(0x41)
	EIDRM           = Errno(0x5a)
	EILSEQ          = Errno(0x5c)
	EINPROGRESS     = Errno(0x24)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EISCONN         = Errno(0x38)
	EISDIR          = Errno(0x15)
	ELAST           = Errno(0x69)
	ELOOP           = Errno(0x3e)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x28)
	EMULTIHOP       = Errno(0x5f)
	ENAMETOOLONG    = Errno(0x3f)
	ENEEDAUTH       = Errno(0x51)
	ENETDOWN        = Errno(0x32)
	ENETRESET       = Errno(0x34)
	ENETUNREACH     = Errno(0x33)
	ENFILE          = Errno(0x17)
	ENOATTR         = Errno(0x5d)
	ENOBUFS         = Errno(0x37)
	ENODATA         = Errno(0x60)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOLCK          = Errno(0x4d)
	ENOLINK         = Errno(0x61)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x5b)
	ENOPOLICY       = Errno(0x67)
	ENOPROTOOPT     = Errno(0x2a)
	ENOSPC          = Errno(0x1c)
	ENOSR           = Errno(0x62)
	ENOSTR          = Errno(0x63)
	ENOSYS          = Errno(0x4e)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x39)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x42)
	ENOTRECOVERABLE = Errno(0x68)
	ENOTSOCK        = Errno(0x26)
	ENOTSUP         = Errno(0x2d)
	ENOTTY          = Errno(0x19)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x66)
	EOVERFLOW       = Errno(0x54)
	EOWNERDEAD      = Errno(0x69)
	EPERM           = Errno(0x1)
	EPFNOSUPPORT    = Errno(0x2e)
	EPIPE           = Errno(0x20)
	EPROCLIM        = Errno(0x43)
	EPROCUNAVAIL    = Errno(0x4c)
	EPROGMISMATCH   = Errno(0x4b)
	EPROGUNAVAIL    = Errno(0x4a)
	EPROTO          = Errno(0x64)
	EPROTONOSUPPORT = Errno(0x2b)
	EPROTOTYPE      = Errno(0x29)
	EPWROFF         = Errno(0x52)
	ERANGE          = Errno(0x22)
	EREMOTE         = Errno(0x47)
	EROFS           = Errno(0x1e)
	ERPCMISMATCH    = Errno(0x49)
	ESHLIBVERS      = Errno(0x57)
	ESHUTDOWN       = Errno(0x3a)
	ESOCKTNOSUPPORT = Errno(0x2c)
	ESPIPE          = Errno(0x1d)
	ESRCH           = Errno(0x3)
	ESTALE          = Errno(0x46)
	ETIME           = Errno(0x65)
	ETIMEDOUT       = Errno(0x3c)
	ETOOMANYREFS    = Errno(0x3b)
	ETXTBSY         = Errno(0x1a)
	EUSERS          = Errno(0x44)
	EWOULDBLOCK     = Errno(0x23)
	EXDEV           = Errno(0x12)
)

// Signals
const (
	SIGABRT   = Signal(0x6)
	SIGALRM   = Signal(0xe)
	SIGBUS    = Signal(0xa)
	SIGCHLD   = Signal(0x14)
	SIGCONT   = Signal(0x13)
	SIGEMT    = Signal(0x7)
	SIGFPE    = Signal(0x8)
	SIGHUP    = Signal(0x1)
	SIGILL    = Signal(0x4)
	SIGINFO   = Signal(0x1d)
	SIGINT    = Signal(0x2)
	SIGIO     = Signal(0x17)
	SIGIOT    = Signal(0x6)
	SIGKILL   = Signal(0x9)
	SIGPIPE   = Signal(0xd)
	SIGPROF   = Signal(0x1b)
	SIGQUIT   = Signal(0x3)
	SIGSEGV   = Signal(0xb)
	SIGSTOP   = Signal(0x11)
	SIGSYS    = Signal(0xc)
	SIGTERM   = Signal(0xf)
	SIGTRAP   = Signal(0x5)
	SIGTSTP   = Signal(0x12)
	SIGTTIN   = Signal(0x15)
	SIGTTOU   = Signal(0x16)
	SIGURG    = Signal(0x10)
	SIGUSR1   = Signal(0x1e)
	SIGUSR2   = Signal(0x1f)
	SIGVTALRM = Signal(0x1a)
	SIGWINCH  = Signal(0x1c)
	SIGXCPU   = Signal(0x18)
	SIGXFSZ   = Signal(0x19)
)

// Error table
var errors = [...]string{
	1:   "operation not permitted",
	2:   "no such file or directory",
	3:   "no such process",
	4:   "interrupted system call",
	5:   "input/output error",
	6:   "device not configured",
	7:   "argument list too long",
	8:   "exec format error",
	9:   "bad file descriptor",
	10:  "no child processes",
	11:  "resource deadlock avoided",
	12:  "cannot allocate memory",
	13:  "permission denied",
	14:  "bad address",
	15:  "block device required",
	16:  "resource busy",
	17:  "file exists",
	18:  "cross-device link",
	19:  "operation not supported by device",
	20:  "not a directory",
	21:  "is a directory",
	22:  "invalid argument",
	23:  "too many open files in system",
	24:  "too many open files",
	25:  "inappropriate ioctl for device",
	26:  "text file busy",
	27:  "file too large",
	28:  "no space left on device",
	29:  "illegal seek",
	30:  "read-only file system",
	31:  "too many links",
	32:  "broken pipe",
	33:  "numerical argument out of domain",
	34:  "result too large",
	35:  "resource temporarily unavailable",
	36:  "operation now in progress",
	37:  "operation already in progress",
	38:  "socket operation on non-socket",
	39:  "destination address required",
	40:  "message too long",
	41:  "protocol wrong type for socket",
	42:  "protocol not available",
	43:  "protocol not supported",
	44:  "socket type not supported",
	45:  "operation not supported",
	46:  "protocol family not supported",
	47:  "address family not supported by protocol family",
	48:  "address already in use",
	49:  "can't assign requested address",
	50:  "network is down",
	51:  "network is unreachable",
	52:  "network dropped connection on reset",
	53:  "software caused connection abort",
	54:  "connection reset by peer",
	55:  "no buffer space available",
	56:  "socket is already connected",
	57:  "socket is not connected",
	58:  "can't send after socket shutdown",
	59:  "too many references: can't splice",
	60:  "operation timed out",
	61:  "connection refused",
	62:  "too many levels of symbolic links",
	63:  "file name too long",
	64:  "host is down",
	65:  "no route to host",
	66:  "directory not empty",
	67:  "too many processes",
	68:  "too many users",
	69:  "disc quota exceeded",
	70:  "stale NFS file handle",
	71:  "too many levels of remote in path",
	72:  "RPC struct is bad",
	73:  "RPC version wrong",
	74:  "RPC prog. not avail",
	75:  "program version wrong",
	76:  "bad procedure for program",
	77:  "no locks available",
	78:  "function not implemented",
	79:  "inappropriate file type or format",
	80:  "authentication error",
	81:  "need authenticator",
	82:  "device power is off",
	83:  "device error",
	84:  "value too large to be stored in data type",
	85:  "bad executable (or shared library)",
	86:  "bad CPU type in executable",
	87:  "shared library version mismatch",
	88:  "malformed Mach-o file",
	89:  "operation canceled",
	90:  "identifier removed",
	91:  "no message of desired type",
	92:  "illegal byte sequence",
	93:  "attribute not found",
	94:  "bad message",
	95:  "EMULTIHOP (Reserved)",
	96:  "no message available on STREAM",
	97:  "ENOLINK (Reserved)",
	98:  "no STREAM resources",
	99:  "not a STREAM",
	100: "protocol error",
	101: "STREAM ioctl timeout",
	102: "operation not supported on socket",
	103: "policy not found",
	104: "state not recoverable",
	105: "previous owner died",
}

// Signal table
var signals = [...]string{
	1:  "hangup",
	2:  "interrupt",
	3:  "quit",
	4:  "illegal instruction",
	5:  "trace/BPT trap",
	6:  "abort trap",
	7:  "EMT trap",
	8:  "floating point exception",
	9:  "killed",
	10: "bus error",
	11: "segmentation fault",
	12: "bad system call",
	13: "broken pipe",
	14: "alarm clock",
	15: "terminated",
	16: "urgent I/O condition",
	17: "suspended (signal)",
	18: "suspended",
	19: "continued",
	20: "child exited",
	21: "stopped (tty input)",
	22: "stopped (tty output)",
	23: "I/O possible",
	24: "cputime limit exceeded",
	25: "filesize limit exceeded",
	26: "virtual timer expired",
	27: "profiling timer expired",
	28: "window size changes",
	29: "information request",
	30: "user defined signal 1",
	31: "user defined signal 2",
}

"""




```