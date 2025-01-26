Response:
The user provided a Go source code snippet from `go/src/syscall/zerrors_darwin_arm64.go` and asked for its functionality, providing the second part of the code.

**Part 2 Analysis:**

This part of the code defines:

1. **Constants:** A large number of integer constants prefixed with `PT_`, `RLIMIT_`, `RTAX_`, `RTA_`, `RTF_`, `RTM_`, `RTV_`, `RUSAGE_`, `SCM_`, `SHUT_`, `SIOC`, `SOCK_`, `SOL_`, `SOMAXCONN`, `SO_`, `S_IF`, `S_I`, `TCIFLUSH`, `TCIOFLUSH`, `TCOFLUSH`, `TCP_`, `TCSAFLUSH`, `TIOC`, `TIOCM_`, `TIOCPKT_`, `TOSTOP`, `VDISCARD`, `VDSUSP`, `VEOF`, `VEOL`, `VERASE`, `VINTR`, `VKILL`, `VLNEXT`, `VMIN`, `VQUIT`, `VREPRINT`, `VSTART`, `VSTATUS`, `VSTOP`, `VSUSP`, `VT0`, `VTDLY`, `VTIME`, `VWERASE`, `WCONTINUED`, `WCOREFLAG`, `WEXITED`, `WNOHANG`, `WNOWAIT`, `WORDSIZE`, `WSTOPPED`, `WUNTRACED`. These constants represent various system call arguments, flags, and options specific to the Darwin operating system on the ARM64 architecture. They are likely used within the `syscall` package to interact with the operating system kernel.

2. **Error Constants:** Constants prefixed with `E` (e.g., `E2BIG`, `EACCES`). These represent standard POSIX error numbers.

3. **Signal Constants:** Constants prefixed with `SIG` (e.g., `SIGABRT`, `SIGINT`). These represent standard POSIX signal numbers.

4. **Error Table:** A string array named `errors`. This array maps error numbers (the values of the `E...` constants) to their corresponding human-readable error messages.

5. **Signal Table:** A string array named `signals`. This array maps signal numbers (the values of the `SIG...` constants) to their corresponding human-readable signal names.

**Functionality Summary (Part 2):**

This part of the `zerrors_darwin_arm64.go` file primarily defines a comprehensive set of **system-level constants, error codes, and signal numbers** specific to the Darwin operating system on the ARM64 architecture. It also provides **human-readable descriptions for these error codes and signal numbers**.

**Overall Functionality (Combining Part 1 and Part 2):**

The entire `zerrors_darwin_arm64.go` file serves as a critical component of the Go `syscall` package on Darwin/ARM64. It provides:

1. **System Call Number Definitions:**  Defines constants representing the numerical identifiers for various system calls.
2. **System-Level Constant Definitions:** Defines a wide range of constants used as arguments, flags, and options for these system calls.
3. **Error Code Definitions and Descriptions:** Defines constants for error codes and provides human-readable messages for them.
4. **Signal Number Definitions and Descriptions:** Defines constants for signal numbers and provides human-readable names for them.

Essentially, this file acts as a **translation layer** between the Go programming language and the underlying Darwin operating system kernel on ARM64. It allows Go programs to interact with the operating system at a low level using symbolic names (the constants) instead of raw numbers, making the code more readable and maintainable. It also provides a way to understand the errors and signals returned by the operating system.
## 功能归纳 (第 2 部分)

这是 `go/src/syscall/zerrors_darwin_arm64.go` 文件的第二部分，其主要功能是定义了大量的**常量**，以及两个**查找表**，用于将数字错误码和信号量转换为人类可读的字符串。

具体来说，这部分定义了以下内容：

1. **系统调用相关的常量 (以 `PT_`, `RLIMIT_`, `RTAX_`, `RTA_`, `RTF_`, `RTM_`, `RTV_`, `RUSAGE_`, `SCM_`, `SHUT_`, `SIOC`, `SOCK_`, `SOL_`, `SOMAXCONN`, `SO_`, `S_IF`, `S_I`, `TCIFLUSH`, `TCIOFLUSH`, `TCOFLUSH`, `TCP_`, `TCSAFLUSH`, `TIOC`, `TIOCM_`, `TIOCPKT_`, `TOSTOP`, `VDISCARD` 等为前缀):**  这些常量代表了在与 Darwin (macOS) 内核进行交互时使用的各种选项、标志、参数和结构体成员。例如，网络相关的常量 (如 `SOCK_STREAM`, `SOL_SOCKET`, `SO_REUSEADDR`)，文件操作相关的常量 (如 `S_IFREG`, `S_IREAD`)，进程控制相关的常量 (如 `RLIMIT_CPU`, `PT_TRACE_ME`)，以及终端控制相关的常量 (如 `TIOCGWINSZ`, `TIOCOUTQ`) 等等。

2. **错误常量 (以 `E` 为前缀):**  这些常量定义了 Darwin 系统调用可能返回的各种错误码，例如 `EACCES` (权限被拒绝), `ENOENT` (文件或目录不存在) 等。

3. **信号常量 (以 `SIG` 为前缀):** 这些常量定义了 Darwin 系统中可以传递给进程的各种信号量，例如 `SIGINT` (中断信号), `SIGKILL` (强制终止信号) 等。

4. **错误码到错误信息的映射表 (`errors` 变量):**  这是一个字符串数组，索引对应错误码的值，存储的是该错误码的文字描述。这使得程序可以将数字错误码转换为更易于理解的错误信息。

5. **信号量到信号名称的映射表 (`signals` 变量):** 这是一个字符串数组，索引对应信号量的值，存储的是该信号量的文字名称。这使得程序可以将数字信号量转换为更易于理解的信号名称。

**总结来说，这部分代码的功能是为 Go 语言的 `syscall` 包在 Darwin ARM64 平台上提供了与操作系统底层交互时所需的各种常量定义以及错误和信号的名称映射，方便 Go 开发者使用符号化的常量，并能理解系统调用返回的错误和信号。**

结合第一部分，整个 `zerrors_darwin_arm64.go` 文件的核心作用是定义了在 Darwin ARM64 架构下进行系统调用所需的各种常量和查找表，是 Go 语言 `syscall` 包与操作系统底层交互的基础。

Prompt: 
```
这是路径为go/src/syscall/zerrors_darwin_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
1
	PT_READ_U                         = 0x3
	PT_SIGEXC                         = 0xc
	PT_STEP                           = 0x9
	PT_THUPDATE                       = 0xd
	PT_TRACE_ME                       = 0x0
	PT_WRITE_D                        = 0x5
	PT_WRITE_I                        = 0x4
	PT_WRITE_U                        = 0x6
	RLIMIT_AS                         = 0x5
	RLIMIT_CORE                       = 0x4
	RLIMIT_CPU                        = 0x0
	RLIMIT_CPU_USAGE_MONITOR          = 0x2
	RLIMIT_DATA                       = 0x2
	RLIMIT_FSIZE                      = 0x1
	RLIMIT_NOFILE                     = 0x8
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
	RTF_PROXY                         = 0x8000000
	RTF_REJECT                        = 0x8
	RTF_ROUTER                        = 0x10000000
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
	SIOCARPIPLL                       = 0xc0206928
	SIOCATMARK                        = 0x40047307
	SIOCAUTOADDR                      = 0xc0206926
	SIOCAUTONETMASK                   = 0x80206927
	SIOCDELMULTI                      = 0x80206932
	SIOCDIFADDR                       = 0x80206919
	SIOCDIFPHYADDR                    = 0x80206941
	SIOCGDRVSPEC                      = 0xc028697b
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
	SIOCGLOWAT                        = 0x40047303
	SIOCGPGRP                         = 0x40047309
	SIOCIFCREATE                      = 0xc0206978
	SIOCIFCREATE2                     = 0xc020697a
	SIOCIFDESTROY                     = 0x80206979
	SIOCIFGCLONERS                    = 0xc0106981
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
	SO_NUMRCVPKT                      = 0x1112
	SO_NWRITE                         = 0x1024
	SO_OOBINLINE                      = 0x100
	SO_PEERLABEL                      = 0x1011
	SO_RANDOMPORT                     = 0x1082
	SO_RCVBUF                         = 0x1002
	SO_RCVLOWAT                       = 0x1004
	SO_RCVTIMEO                       = 0x1006
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
	TCP_ENABLE_ECN                    = 0x104
	TCP_KEEPALIVE                     = 0x10
	TCP_KEEPCNT                       = 0x102
	TCP_KEEPINTVL                     = 0x101
	TCP_MAXHLEN                       = 0x3c
	TCP_MAXOLEN                       = 0x28
	TCP_MAXSEG                        = 0x2
	TCP_MAXWIN                        = 0xffff
	TCP_MAX_SACK                      = 0x4
	TCP_MAX_WINSHIFT                  = 0xe
	TCP_MINMSS                        = 0xd8
	TCP_MSS                           = 0x200
	TCP_NODELAY                       = 0x1
	TCP_NOOPT                         = 0x8
	TCP_NOPUSH                        = 0x4
	TCP_NOTSENT_LOWAT                 = 0x201
	TCP_RXT_CONNDROPTIME              = 0x80
	TCP_RXT_FINDROP                   = 0x100
	TCP_SENDMOREACKS                  = 0x103
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
	ELAST           = Errno(0x6a)
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
	EQFULL          = Errno(0x6a)
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
	106: "interface output queue is full",
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