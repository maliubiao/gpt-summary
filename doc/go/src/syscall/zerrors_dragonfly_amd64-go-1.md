Response:
The user is asking for a summary of the functionality of the provided Go code snippet. This is the second part of the code, focusing on constants for errors and signals, and tables to map these to their string representations.

Therefore, the main functionalities are:
1. **Defining constants for error numbers**: These constants represent different types of system errors.
2. **Defining constants for signal numbers**: These constants represent different types of signals that can be sent to a process.
3. **Providing a mapping from error numbers to error messages**: The `errors` array provides a human-readable description for each error code.
4. **Providing a mapping from signal numbers to signal names**: The `signals` array provides a human-readable name for each signal code.
这是 `go/src/syscall/zerrors_dragonfly_amd64.go` 文件的第二部分，主要功能是定义了与 Dragonfly BSD (amd64 架构) 操作系统相关的错误码和信号量常量，并提供了将这些数字常量映射到字符串描述的表。

**功能归纳：**

1. **定义错误码常量 (Error Codes):**  这部分定义了在 Dragonfly BSD 系统上可能发生的各种错误的数字表示。例如，`EACCES` 代表 "Permission denied" 错误，它的值是 `Errno(0xd)`。 这些常量用于 Go 程序中判断和处理系统调用返回的错误。

2. **定义信号量常量 (Signals):** 这部分定义了 Dragonfly BSD 系统中可用的各种信号的数字表示。例如，`SIGINT` 代表 "Interrupt" 信号，它的值是 `Signal(0x2)`。 这些常量用于 Go 程序中处理进程收到的信号。

3. **提供错误码到错误信息的映射表 (Error Table):**  `errors` 数组是一个字符串数组，它的索引对应错误码的值，存储的是该错误码的文字描述。这使得程序可以将数字错误码转换为更易于理解的文本信息。

4. **提供信号量到信号名称的映射表 (Signal Table):** `signals` 数组是一个字符串数组，它的索引对应信号量的值，存储的是该信号量的名称。这使得程序可以将数字信号量转换为更易于理解的文本信息。

总而言之，这个代码片段为 Go 程序在 Dragonfly BSD (amd64) 平台上与操作系统交互提供了必要的常量和映射，以便于理解和处理系统调用和信号相关的操作。

Prompt: 
```
这是路径为go/src/syscall/zerrors_dragonfly_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
                             = 0x2000
	IP_MINTTL                         = 0x42
	IP_MSS                            = 0x240
	IP_MULTICAST_IF                   = 0x9
	IP_MULTICAST_LOOP                 = 0xb
	IP_MULTICAST_TTL                  = 0xa
	IP_MULTICAST_VIF                  = 0xe
	IP_OFFMASK                        = 0x1fff
	IP_OPTIONS                        = 0x1
	IP_PORTRANGE                      = 0x13
	IP_PORTRANGE_DEFAULT              = 0x0
	IP_PORTRANGE_HIGH                 = 0x1
	IP_PORTRANGE_LOW                  = 0x2
	IP_RECVDSTADDR                    = 0x7
	IP_RECVIF                         = 0x14
	IP_RECVOPTS                       = 0x5
	IP_RECVRETOPTS                    = 0x6
	IP_RECVTTL                        = 0x41
	IP_RETOPTS                        = 0x8
	IP_RF                             = 0x8000
	IP_RSVP_OFF                       = 0x10
	IP_RSVP_ON                        = 0xf
	IP_RSVP_VIF_OFF                   = 0x12
	IP_RSVP_VIF_ON                    = 0x11
	IP_TOS                            = 0x3
	IP_TTL                            = 0x4
	ISIG                              = 0x80
	ISTRIP                            = 0x20
	IXANY                             = 0x800
	IXOFF                             = 0x400
	IXON                              = 0x200
	LOCK_EX                           = 0x2
	LOCK_NB                           = 0x4
	LOCK_SH                           = 0x1
	LOCK_UN                           = 0x8
	MADV_AUTOSYNC                     = 0x7
	MADV_CONTROL_END                  = 0xb
	MADV_CONTROL_START                = 0xa
	MADV_CORE                         = 0x9
	MADV_DONTNEED                     = 0x4
	MADV_FREE                         = 0x5
	MADV_INVAL                        = 0xa
	MADV_NOCORE                       = 0x8
	MADV_NORMAL                       = 0x0
	MADV_NOSYNC                       = 0x6
	MADV_RANDOM                       = 0x1
	MADV_SEQUENTIAL                   = 0x2
	MADV_SETMAP                       = 0xb
	MADV_WILLNEED                     = 0x3
	MAP_ANON                          = 0x1000
	MAP_COPY                          = 0x2
	MAP_FILE                          = 0x0
	MAP_FIXED                         = 0x10
	MAP_HASSEMAPHORE                  = 0x200
	MAP_INHERIT                       = 0x80
	MAP_NOCORE                        = 0x20000
	MAP_NOEXTEND                      = 0x100
	MAP_NORESERVE                     = 0x40
	MAP_NOSYNC                        = 0x800
	MAP_PRIVATE                       = 0x2
	MAP_RENAME                        = 0x20
	MAP_SHARED                        = 0x1
	MAP_SIZEALIGN                     = 0x40000
	MAP_STACK                         = 0x400
	MAP_TRYFIXED                      = 0x10000
	MAP_VPAGETABLE                    = 0x2000
	MCL_CURRENT                       = 0x1
	MCL_FUTURE                        = 0x2
	MSG_CMSG_CLOEXEC                  = 0x1000
	MSG_CTRUNC                        = 0x20
	MSG_DONTROUTE                     = 0x4
	MSG_DONTWAIT                      = 0x80
	MSG_EOF                           = 0x100
	MSG_EOR                           = 0x8
	MSG_FBLOCKING                     = 0x10000
	MSG_FMASK                         = 0xffff0000
	MSG_FNONBLOCKING                  = 0x20000
	MSG_NOSIGNAL                      = 0x400
	MSG_NOTIFICATION                  = 0x200
	MSG_OOB                           = 0x1
	MSG_PEEK                          = 0x2
	MSG_SYNC                          = 0x800
	MSG_TRUNC                         = 0x10
	MSG_WAITALL                       = 0x40
	MS_ASYNC                          = 0x1
	MS_INVALIDATE                     = 0x2
	MS_SYNC                           = 0x0
	NAME_MAX                          = 0xff
	NET_RT_DUMP                       = 0x1
	NET_RT_FLAGS                      = 0x2
	NET_RT_IFLIST                     = 0x3
	NET_RT_MAXID                      = 0x4
	NOFLSH                            = 0x80000000
	NOTE_ATTRIB                       = 0x8
	NOTE_CHILD                        = 0x4
	NOTE_DELETE                       = 0x1
	NOTE_EXEC                         = 0x20000000
	NOTE_EXIT                         = 0x80000000
	NOTE_EXTEND                       = 0x4
	NOTE_FORK                         = 0x40000000
	NOTE_LINK                         = 0x10
	NOTE_LOWAT                        = 0x1
	NOTE_OOB                          = 0x2
	NOTE_PCTRLMASK                    = 0xf0000000
	NOTE_PDATAMASK                    = 0xfffff
	NOTE_RENAME                       = 0x20
	NOTE_REVOKE                       = 0x40
	NOTE_TRACK                        = 0x1
	NOTE_TRACKERR                     = 0x2
	NOTE_WRITE                        = 0x2
	OCRNL                             = 0x10
	ONLCR                             = 0x2
	ONLRET                            = 0x40
	ONOCR                             = 0x20
	ONOEOT                            = 0x8
	OPOST                             = 0x1
	O_ACCMODE                         = 0x3
	O_APPEND                          = 0x8
	O_ASYNC                           = 0x40
	O_CLOEXEC                         = 0x20000
	O_CREAT                           = 0x200
	O_DIRECT                          = 0x10000
	O_DIRECTORY                       = 0x8000000
	O_EXCL                            = 0x800
	O_EXLOCK                          = 0x20
	O_FAPPEND                         = 0x100000
	O_FASYNCWRITE                     = 0x800000
	O_FBLOCKING                       = 0x40000
	O_FBUFFERED                       = 0x2000000
	O_FMASK                           = 0x7fc0000
	O_FNONBLOCKING                    = 0x80000
	O_FOFFSET                         = 0x200000
	O_FSYNC                           = 0x80
	O_FSYNCWRITE                      = 0x400000
	O_FUNBUFFERED                     = 0x1000000
	O_MAPONREAD                       = 0x4000000
	O_NDELAY                          = 0x4
	O_NOCTTY                          = 0x8000
	O_NOFOLLOW                        = 0x100
	O_NONBLOCK                        = 0x4
	O_RDONLY                          = 0x0
	O_RDWR                            = 0x2
	O_SHLOCK                          = 0x10
	O_SYNC                            = 0x80
	O_TRUNC                           = 0x400
	O_WRONLY                          = 0x1
	PARENB                            = 0x1000
	PARMRK                            = 0x8
	PARODD                            = 0x2000
	PENDIN                            = 0x20000000
	PRIO_PGRP                         = 0x1
	PRIO_PROCESS                      = 0x0
	PRIO_USER                         = 0x2
	PROT_EXEC                         = 0x4
	PROT_NONE                         = 0x0
	PROT_READ                         = 0x1
	PROT_WRITE                        = 0x2
	RLIMIT_AS                         = 0xa
	RLIMIT_CORE                       = 0x4
	RLIMIT_CPU                        = 0x0
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
	RTAX_MAX                          = 0xb
	RTAX_MPLS1                        = 0x8
	RTAX_MPLS2                        = 0x9
	RTAX_MPLS3                        = 0xa
	RTAX_NETMASK                      = 0x2
	RTA_AUTHOR                        = 0x40
	RTA_BRD                           = 0x80
	RTA_DST                           = 0x1
	RTA_GATEWAY                       = 0x2
	RTA_GENMASK                       = 0x8
	RTA_IFA                           = 0x20
	RTA_IFP                           = 0x10
	RTA_MPLS1                         = 0x100
	RTA_MPLS2                         = 0x200
	RTA_MPLS3                         = 0x400
	RTA_NETMASK                       = 0x4
	RTF_BLACKHOLE                     = 0x1000
	RTF_BROADCAST                     = 0x400000
	RTF_CLONING                       = 0x100
	RTF_DONE                          = 0x40
	RTF_DYNAMIC                       = 0x10
	RTF_GATEWAY                       = 0x2
	RTF_HOST                          = 0x4
	RTF_LLINFO                        = 0x400
	RTF_LOCAL                         = 0x200000
	RTF_MODIFIED                      = 0x20
	RTF_MPLSOPS                       = 0x1000000
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
	RTM_IEEE80211                     = 0x12
	RTM_IFANNOUNCE                    = 0x11
	RTM_IFINFO                        = 0xe
	RTM_LOCK                          = 0x8
	RTM_LOSING                        = 0x5
	RTM_MISS                          = 0x7
	RTM_NEWADDR                       = 0xc
	RTM_NEWMADDR                      = 0xf
	RTM_OLDADD                        = 0x9
	RTM_OLDDEL                        = 0xa
	RTM_REDIRECT                      = 0x6
	RTM_RESOLVE                       = 0xb
	RTM_RTTUNIT                       = 0xf4240
	RTM_VERSION                       = 0x6
	RTV_EXPIRE                        = 0x4
	RTV_HOPCOUNT                      = 0x2
	RTV_IWCAPSEGS                     = 0x400
	RTV_IWMAXSEGS                     = 0x200
	RTV_MSL                           = 0x100
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
	SHUT_RD                           = 0x0
	SHUT_RDWR                         = 0x2
	SHUT_WR                           = 0x1
	SIOCADDMULTI                      = 0x80206931
	SIOCADDRT                         = 0x8040720a
	SIOCAIFADDR                       = 0x8040691a
	SIOCALIFADDR                      = 0x8118691b
	SIOCATMARK                        = 0x40047307
	SIOCDELMULTI                      = 0x80206932
	SIOCDELRT                         = 0x8040720b
	SIOCDIFADDR                       = 0x80206919
	SIOCDIFPHYADDR                    = 0x80206949
	SIOCDLIFADDR                      = 0x8118691d
	SIOCGDRVSPEC                      = 0xc028697b
	SIOCGETSGCNT                      = 0xc0207210
	SIOCGETVIFCNT                     = 0xc028720f
	SIOCGHIWAT                        = 0x40047301
	SIOCGIFADDR                       = 0xc0206921
	SIOCGIFBRDADDR                    = 0xc0206923
	SIOCGIFCAP                        = 0xc020691f
	SIOCGIFCONF                       = 0xc0106924
	SIOCGIFDATA                       = 0xc0206926
	SIOCGIFDSTADDR                    = 0xc0206922
	SIOCGIFFLAGS                      = 0xc0206911
	SIOCGIFGENERIC                    = 0xc020693a
	SIOCGIFGMEMB                      = 0xc028698a
	SIOCGIFINDEX                      = 0xc0206920
	SIOCGIFMEDIA                      = 0xc0306938
	SIOCGIFMETRIC                     = 0xc0206917
	SIOCGIFMTU                        = 0xc0206933
	SIOCGIFNETMASK                    = 0xc0206925
	SIOCGIFPDSTADDR                   = 0xc0206948
	SIOCGIFPHYS                       = 0xc0206935
	SIOCGIFPOLLCPU                    = 0xc020697e
	SIOCGIFPSRCADDR                   = 0xc0206947
	SIOCGIFSTATUS                     = 0xc331693b
	SIOCGIFTSOLEN                     = 0xc0206980
	SIOCGLIFADDR                      = 0xc118691c
	SIOCGLIFPHYADDR                   = 0xc118694b
	SIOCGLOWAT                        = 0x40047303
	SIOCGPGRP                         = 0x40047309
	SIOCGPRIVATE_0                    = 0xc0206950
	SIOCGPRIVATE_1                    = 0xc0206951
	SIOCIFCREATE                      = 0xc020697a
	SIOCIFCREATE2                     = 0xc020697c
	SIOCIFDESTROY                     = 0x80206979
	SIOCIFGCLONERS                    = 0xc0106978
	SIOCSDRVSPEC                      = 0x8028697b
	SIOCSHIWAT                        = 0x80047300
	SIOCSIFADDR                       = 0x8020690c
	SIOCSIFBRDADDR                    = 0x80206913
	SIOCSIFCAP                        = 0x8020691e
	SIOCSIFDSTADDR                    = 0x8020690e
	SIOCSIFFLAGS                      = 0x80206910
	SIOCSIFGENERIC                    = 0x80206939
	SIOCSIFLLADDR                     = 0x8020693c
	SIOCSIFMEDIA                      = 0xc0206937
	SIOCSIFMETRIC                     = 0x80206918
	SIOCSIFMTU                        = 0x80206934
	SIOCSIFNAME                       = 0x80206928
	SIOCSIFNETMASK                    = 0x80206916
	SIOCSIFPHYADDR                    = 0x80406946
	SIOCSIFPHYS                       = 0x80206936
	SIOCSIFPOLLCPU                    = 0x8020697d
	SIOCSIFTSOLEN                     = 0x8020697f
	SIOCSLIFPHYADDR                   = 0x8118694a
	SIOCSLOWAT                        = 0x80047302
	SIOCSPGRP                         = 0x80047308
	SOCK_CLOEXEC                      = 0x10000000
	SOCK_DGRAM                        = 0x2
	SOCK_MAXADDRLEN                   = 0xff
	SOCK_NONBLOCK                     = 0x20000000
	SOCK_RAW                          = 0x3
	SOCK_RDM                          = 0x4
	SOCK_SEQPACKET                    = 0x5
	SOCK_STREAM                       = 0x1
	SOL_SOCKET                        = 0xffff
	SOMAXCONN                         = 0x80
	SO_ACCEPTCONN                     = 0x2
	SO_ACCEPTFILTER                   = 0x1000
	SO_BROADCAST                      = 0x20
	SO_DEBUG                          = 0x1
	SO_DONTROUTE                      = 0x10
	SO_ERROR                          = 0x1007
	SO_KEEPALIVE                      = 0x8
	SO_LINGER                         = 0x80
	SO_NOSIGPIPE                      = 0x800
	SO_OOBINLINE                      = 0x100
	SO_RCVBUF                         = 0x1002
	SO_RCVLOWAT                       = 0x1004
	SO_RCVTIMEO                       = 0x1006
	SO_REUSEADDR                      = 0x4
	SO_REUSEPORT                      = 0x200
	SO_SNDBUF                         = 0x1001
	SO_SNDLOWAT                       = 0x1003
	SO_SNDSPACE                       = 0x100a
	SO_SNDTIMEO                       = 0x1005
	SO_TIMESTAMP                      = 0x400
	SO_TYPE                           = 0x1008
	SO_USELOOPBACK                    = 0x40
	TCIFLUSH                          = 0x1
	TCIOFLUSH                         = 0x3
	TCOFLUSH                          = 0x2
	TCP_FASTKEEP                      = 0x80
	TCP_KEEPCNT                       = 0x400
	TCP_KEEPIDLE                      = 0x100
	TCP_KEEPINIT                      = 0x20
	TCP_KEEPINTVL                     = 0x200
	TCP_MAXBURST                      = 0x4
	TCP_MAXHLEN                       = 0x3c
	TCP_MAXOLEN                       = 0x28
	TCP_MAXSEG                        = 0x2
	TCP_MAXWIN                        = 0xffff
	TCP_MAX_WINSHIFT                  = 0xe
	TCP_MINMSS                        = 0x100
	TCP_MIN_WINSHIFT                  = 0x5
	TCP_MSS                           = 0x200
	TCP_NODELAY                       = 0x1
	TCP_NOOPT                         = 0x8
	TCP_NOPUSH                        = 0x4
	TCP_SIGNATURE_ENABLE              = 0x10
	TCSAFLUSH                         = 0x2
	TIOCCBRK                          = 0x2000747a
	TIOCCDTR                          = 0x20007478
	TIOCCONS                          = 0x80047462
	TIOCDCDTIMESTAMP                  = 0x40107458
	TIOCDRAIN                         = 0x2000745e
	TIOCEXCL                          = 0x2000740d
	TIOCEXT                           = 0x80047460
	TIOCFLUSH                         = 0x80047410
	TIOCGDRAINWAIT                    = 0x40047456
	TIOCGETA                          = 0x402c7413
	TIOCGETD                          = 0x4004741a
	TIOCGPGRP                         = 0x40047477
	TIOCGSID                          = 0x40047463
	TIOCGSIZE                         = 0x40087468
	TIOCGWINSZ                        = 0x40087468
	TIOCISPTMASTER                    = 0x20007455
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
	TIOCREMOTE                        = 0x80047469
	TIOCSBRK                          = 0x2000747b
	TIOCSCTTY                         = 0x20007461
	TIOCSDRAINWAIT                    = 0x80047457
	TIOCSDTR                          = 0x20007479
	TIOCSETA                          = 0x802c7414
	TIOCSETAF                         = 0x802c7416
	TIOCSETAW                         = 0x802c7415
	TIOCSETD                          = 0x8004741b
	TIOCSIG                           = 0x2000745f
	TIOCSPGRP                         = 0x80047476
	TIOCSSIZE                         = 0x80087467
	TIOCSTART                         = 0x2000746e
	TIOCSTAT                          = 0x20007465
	TIOCSTI                           = 0x80017472
	TIOCSTOP                          = 0x2000746f
	TIOCSWINSZ                        = 0x80087467
	TIOCTIMESTAMP                     = 0x40107459
	TIOCUCNTL                         = 0x80047466
	TOSTOP                            = 0x400000
	VCHECKPT                          = 0x13
	VDISCARD                          = 0xf
	VDSUSP                            = 0xb
	VEOF                              = 0x0
	VEOL                              = 0x1
	VEOL2                             = 0x2
	VERASE                            = 0x3
	VERASE2                           = 0x7
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
	VTIME                             = 0x11
	VWERASE                           = 0x4
	WCONTINUED                        = 0x4
	WCOREFLAG                         = 0x80
	WEXITED                           = 0x10
	WLINUXCLONE                       = 0x80000000
	WNOHANG                           = 0x1
	WNOWAIT                           = 0x8
	WSTOPPED                          = 0x7f
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
	EASYNC          = Errno(0x63)
	EAUTH           = Errno(0x50)
	EBADF           = Errno(0x9)
	EBADMSG         = Errno(0x59)
	EBADRPC         = Errno(0x48)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x55)
	ECHILD          = Errno(0xa)
	ECONNABORTED    = Errno(0x35)
	ECONNREFUSED    = Errno(0x3d)
	ECONNRESET      = Errno(0x36)
	EDEADLK         = Errno(0xb)
	EDESTADDRREQ    = Errno(0x27)
	EDOM            = Errno(0x21)
	EDOOFUS         = Errno(0x58)
	EDQUOT          = Errno(0x45)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EFTYPE          = Errno(0x4f)
	EHOSTDOWN       = Errno(0x40)
	EHOSTUNREACH    = Errno(0x41)
	EIDRM           = Errno(0x52)
	EILSEQ          = Errno(0x56)
	EINPROGRESS     = Errno(0x24)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EISCONN         = Errno(0x38)
	EISDIR          = Errno(0x15)
	ELAST           = Errno(0x63)
	ELOOP           = Errno(0x3e)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x28)
	EMULTIHOP       = Errno(0x5a)
	ENAMETOOLONG    = Errno(0x3f)
	ENEEDAUTH       = Errno(0x51)
	ENETDOWN        = Errno(0x32)
	ENETRESET       = Errno(0x34)
	ENETUNREACH     = Errno(0x33)
	ENFILE          = Errno(0x17)
	ENOATTR         = Errno(0x57)
	ENOBUFS         = Errno(0x37)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOLCK          = Errno(0x4d)
	ENOLINK         = Errno(0x5b)
	ENOMEDIUM       = Errno(0x5d)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x53)
	ENOPROTOOPT     = Errno(0x2a)
	ENOSPC          = Errno(0x1c)
	ENOSYS          = Errno(0x4e)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x39)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x42)
	ENOTSOCK        = Errno(0x26)
	ENOTSUP         = Errno(0x2d)
	ENOTTY          = Errno(0x19)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x2d)
	EOVERFLOW       = Errno(0x54)
	EPERM           = Errno(0x1)
	EPFNOSUPPORT    = Errno(0x2e)
	EPIPE           = Errno(0x20)
	EPROCLIM        = Errno(0x43)
	EPROCUNAVAIL    = Errno(0x4c)
	EPROGMISMATCH   = Errno(0x4b)
	EPROGUNAVAIL    = Errno(0x4a)
	EPROTO          = Errno(0x5c)
	EPROTONOSUPPORT = Errno(0x2b)
	EPROTOTYPE      = Errno(0x29)
	ERANGE          = Errno(0x22)
	EREMOTE         = Errno(0x47)
	EROFS           = Errno(0x1e)
	ERPCMISMATCH    = Errno(0x49)
	ESHUTDOWN       = Errno(0x3a)
	ESOCKTNOSUPPORT = Errno(0x2c)
	ESPIPE          = Errno(0x1d)
	ESRCH           = Errno(0x3)
	ESTALE          = Errno(0x46)
	ETIMEDOUT       = Errno(0x3c)
	ETOOMANYREFS    = Errno(0x3b)
	ETXTBSY         = Errno(0x1a)
	EUNUSED94       = Errno(0x5e)
	EUNUSED95       = Errno(0x5f)
	EUNUSED96       = Errno(0x60)
	EUNUSED97       = Errno(0x61)
	EUNUSED98       = Errno(0x62)
	EUSERS          = Errno(0x44)
	EWOULDBLOCK     = Errno(0x23)
	EXDEV           = Errno(0x12)
)

// Signals
const (
	SIGABRT     = Signal(0x6)
	SIGALRM     = Signal(0xe)
	SIGBUS      = Signal(0xa)
	SIGCHLD     = Signal(0x14)
	SIGCKPT     = Signal(0x21)
	SIGCKPTEXIT = Signal(0x22)
	SIGCONT     = Signal(0x13)
	SIGEMT      = Signal(0x7)
	SIGFPE      = Signal(0x8)
	SIGHUP      = Signal(0x1)
	SIGILL      = Signal(0x4)
	SIGINFO     = Signal(0x1d)
	SIGINT      = Signal(0x2)
	SIGIO       = Signal(0x17)
	SIGIOT      = Signal(0x6)
	SIGKILL     = Signal(0x9)
	SIGPIPE     = Signal(0xd)
	SIGPROF     = Signal(0x1b)
	SIGQUIT     = Signal(0x3)
	SIGSEGV     = Signal(0xb)
	SIGSTOP     = Signal(0x11)
	SIGSYS      = Signal(0xc)
	SIGTERM     = Signal(0xf)
	SIGTHR      = Signal(0x20)
	SIGTRAP     = Signal(0x5)
	SIGTSTP     = Signal(0x12)
	SIGTTIN     = Signal(0x15)
	SIGTTOU     = Signal(0x16)
	SIGURG      = Signal(0x10)
	SIGUSR1     = Signal(0x1e)
	SIGUSR2     = Signal(0x1f)
	SIGVTALRM   = Signal(0x1a)
	SIGWINCH    = Signal(0x1c)
	SIGXCPU     = Signal(0x18)
	SIGXFSZ     = Signal(0x19)
)

// Error table
var errors = [...]string{
	1:  "operation not permitted",
	2:  "no such file or directory",
	3:  "no such process",
	4:  "interrupted system call",
	5:  "input/output error",
	6:  "device not configured",
	7:  "argument list too long",
	8:  "exec format error",
	9:  "bad file descriptor",
	10: "no child processes",
	11: "resource deadlock avoided",
	12: "cannot allocate memory",
	13: "permission denied",
	14: "bad address",
	15: "block device required",
	16: "device busy",
	17: "file exists",
	18: "cross-device link",
	19: "operation not supported by device",
	20: "not a directory",
	21: "is a directory",
	22: "invalid argument",
	23: "too many open files in system",
	24: "too many open files",
	25: "inappropriate ioctl for device",
	26: "text file busy",
	27: "file too large",
	28: "no space left on device",
	29: "illegal seek",
	30: "read-only file system",
	31: "too many links",
	32: "broken pipe",
	33: "numerical argument out of domain",
	34: "result too large",
	35: "resource temporarily unavailable",
	36: "operation now in progress",
	37: "operation already in progress",
	38: "socket operation on non-socket",
	39: "destination address required",
	40: "message too long",
	41: "protocol wrong type for socket",
	42: "protocol not available",
	43: "protocol not supported",
	44: "socket type not supported",
	45: "operation not supported",
	46: "protocol family not supported",
	47: "address family not supported by protocol family",
	48: "address already in use",
	49: "can't assign requested address",
	50: "network is down",
	51: "network is unreachable",
	52: "network dropped connection on reset",
	53: "software caused connection abort",
	54: "connection reset by peer",
	55: "no buffer space available",
	56: "socket is already connected",
	57: "socket is not connected",
	58: "can't send after socket shutdown",
	59: "too many references: can't splice",
	60: "operation timed out",
	61: "connection refused",
	62: "too many levels of symbolic links",
	63: "file name too long",
	64: "host is down",
	65: "no route to host",
	66: "directory not empty",
	67: "too many processes",
	68: "too many users",
	69: "disc quota exceeded",
	70: "stale NFS file handle",
	71: "too many levels of remote in path",
	72: "RPC struct is bad",
	73: "RPC version wrong",
	74: "RPC prog. not avail",
	75: "program version wrong",
	76: "bad procedure for program",
	77: "no locks available",
	78: "function not implemented",
	79: "inappropriate file type or format",
	80: "authentication error",
	81: "need authenticator",
	82: "identifier removed",
	83: "no message of desired type",
	84: "value too large to be stored in data type",
	85: "operation canceled",
	86: "illegal byte sequence",
	87: "attribute not found",
	88: "programming error",
	89: "bad message",
	90: "multihop attempted",
	91: "link has been severed",
	92: "protocol error",
	93: "no medium found",
	94: "unknown error: 94",
	95: "unknown error: 95",
	96: "unknown error: 96",
	97: "unknown error: 97",
	98: "unknown error: 98",
	99: "unknown error: 99",
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
	32: "thread Scheduler",
	33: "checkPoint",
	34: "checkPointExit",
}

"""




```