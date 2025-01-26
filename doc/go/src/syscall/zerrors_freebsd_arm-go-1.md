Response:
The user wants me to summarize the functionality of the provided Go code snippet, which is the second part of a three-part file named `zerrors_freebsd_arm.go`. This file seems to define system-level constants and error codes specific to the FreeBSD operating system on the ARM architecture.

The previous part likely defined more constants, and the next part will probably continue with more definitions.

Therefore, the functionality of this specific part is to define a set of **system-level constants** related to networking protocols (IPPROTO_), IPv6 options (IPV6_), IP options (IP_), terminal I/O (ISIG, ISTRIP, IXON, etc.), file locking (LOCK_), memory mapping (MADV_, MAP_), message passing (MSG_), memory synchronization (MS_), routing (NET_RT_, RTAX_, RTA_, RTF_, RTM_, RTV_), resource usage (RUSAGE_), socket control messages (SCM_), socket shutting down (SHUT_), socket I/O control (SIOC), socket options (SOCK_, SOL_, SO_), and TCP options (TCP_).

It also defines constants for **error numbers** (E2BIG, EACCES, etc.) and **signals** (SIGABRT, SIGALRM, etc.).

In essence, this file provides Go with a way to interact with the FreeBSD kernel at a low level by defining these symbolic constants that correspond to specific numerical values used by the operating system.
这段代码是Go语言 `syscall` 包中用于 FreeBSD 操作系统在 ARM 架构下的实现的一部分，它主要定义了大量的系统常量。 具体来说，这部分代码定义了以下类型的常量：

* **网络协议常量 (IPPROTO_*)**:  定义了各种网络协议的数字标识，例如 `IPPROTO_TCP` 代表 TCP 协议，`IPPROTO_UDP` 代表 UDP 协议等等。这些常量用于在网络编程中指定使用的协议类型。

* **IPv6 相关常量 (IPV6_*)**: 定义了与 IPv6 协议相关的选项和标志，例如 `IPV6_V6ONLY` 用于设置 socket 是否仅支持 IPv6 连接，`IPV6_JOIN_GROUP` 用于加入 IPv6 组播组等等。

* **IP 相关常量 (IP_*)**: 定义了与 IPv4 协议相关的选项和标志，例如 `IP_ADD_MEMBERSHIP` 用于加入 IPv4 组播组，`IP_TTL` 用于设置 IP 数据包的生存时间等等。

* **终端 I/O 相关常量**: 这部分常量以 `ISIG`, `ISTRIP`, `IXON` 等开头，涉及到终端的输入输出控制，例如是否忽略信号，是否剥离输入字符的第八位，是否启用软件流控制等等。

* **文件锁相关常量 (LOCK_*)**: 定义了文件锁的不同类型，例如 `LOCK_SH` 表示共享锁，`LOCK_EX` 表示排他锁。

* **内存映射相关常量 (MADV_*, MAP_*)**: 定义了内存映射的建议和标志，例如 `MAP_SHARED` 表示共享映射，`MAP_PRIVATE` 表示私有映射，`MADV_DONTNEED` 表示不再需要某个内存区域等等。

* **消息传递相关常量 (MSG_*)**: 定义了在发送和接收消息时可以使用的标志，例如 `MSG_DONTROUTE` 表示不要使用路由表，`MSG_OOB` 表示发送或接收带外数据等等。

* **内存同步相关常量 (MS_*)**: 定义了 `msync` 系统调用的同步选项，例如 `MS_SYNC` 表示同步写入。

* **路由相关常量 (NET_RT_*, RTAX_*, RTA_*, RTF_*, RTM_*, RTV_*)**:  定义了与网络路由相关的各种信息，包括路由表的操作类型、路由属性、标志等等。

* **资源使用相关常量 (RUSAGE_*)**: 定义了 `getrusage` 系统调用中可以获取的资源使用信息的类型，例如 `RUSAGE_SELF` 表示当前进程的资源使用情况。

* **Socket 控制消息相关常量 (SCM_*)**: 定义了在 socket 控制消息中可以传递的数据类型，例如 `SCM_RIGHTS` 用于传递文件描述符。

* **Socket 关闭相关常量 (SHUT_*)**: 定义了 `shutdown` 系统调用中关闭 socket 的方式，例如 `SHUT_RD` 表示关闭读端。

* **Socket I/O 控制相关常量 (SIOC*)**:  定义了大量的 socket I/O 控制命令，这些命令用于获取或设置网络接口的各种属性，例如 IP 地址、MAC 地址、接口状态等等。

* **Socket 选项相关常量 (SOCK_*, SOL_*, SO_*)**: 定义了 socket 的类型和选项，例如 `SOCK_STREAM` 表示 TCP socket，`SOCK_DGRAM` 表示 UDP socket，`SO_REUSEADDR` 表示允许重用本地地址等等。

* **TCP 选项相关常量 (TCP_*)**: 定义了 TCP 协议特有的选项，例如 `TCP_NODELAY` 表示禁用 Nagle 算法，`TCP_KEEPIDLE` 表示 TCP 保活探测的空闲时间等等。

* **错误码常量 (E*)**: 定义了各种系统错误的数字标识，例如 `EACCES` 表示权限不足，`ENOENT` 表示文件不存在等等。

* **信号常量 (SIG*)**: 定义了各种系统信号的数字标识，例如 `SIGINT` 表示中断信号，`SIGKILL` 表示强制终止信号等等。

**归纳一下它的功能：**

这部分 `zerrors_freebsd_arm.go` 代码片段的主要功能是**定义了大量的与底层操作系统交互相关的常量**，这些常量用于 Go 语言程序在 FreeBSD ARM 架构下进行系统调用和底层操作时，能够以符号化的方式引用各种系统资源、选项、错误和信号，提高了代码的可读性和可维护性。它为 Go 程序提供了与 FreeBSD 内核进行交互的基础词汇表。

Prompt: 
```
这是路径为go/src/syscall/zerrors_freebsd_arm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
CV                      = 0x47
	IPPROTO_IPEIP                     = 0x5e
	IPPROTO_IPIP                      = 0x4
	IPPROTO_IPPC                      = 0x43
	IPPROTO_IPV4                      = 0x4
	IPPROTO_IPV6                      = 0x29
	IPPROTO_IRTP                      = 0x1c
	IPPROTO_KRYPTOLAN                 = 0x41
	IPPROTO_LARP                      = 0x5b
	IPPROTO_LEAF1                     = 0x19
	IPPROTO_LEAF2                     = 0x1a
	IPPROTO_MAX                       = 0x100
	IPPROTO_MAXID                     = 0x34
	IPPROTO_MEAS                      = 0x13
	IPPROTO_MH                        = 0x87
	IPPROTO_MHRP                      = 0x30
	IPPROTO_MICP                      = 0x5f
	IPPROTO_MOBILE                    = 0x37
	IPPROTO_MPLS                      = 0x89
	IPPROTO_MTP                       = 0x5c
	IPPROTO_MUX                       = 0x12
	IPPROTO_ND                        = 0x4d
	IPPROTO_NHRP                      = 0x36
	IPPROTO_NONE                      = 0x3b
	IPPROTO_NSP                       = 0x1f
	IPPROTO_NVPII                     = 0xb
	IPPROTO_OLD_DIVERT                = 0xfe
	IPPROTO_OSPFIGP                   = 0x59
	IPPROTO_PFSYNC                    = 0xf0
	IPPROTO_PGM                       = 0x71
	IPPROTO_PIGP                      = 0x9
	IPPROTO_PIM                       = 0x67
	IPPROTO_PRM                       = 0x15
	IPPROTO_PUP                       = 0xc
	IPPROTO_PVP                       = 0x4b
	IPPROTO_RAW                       = 0xff
	IPPROTO_RCCMON                    = 0xa
	IPPROTO_RDP                       = 0x1b
	IPPROTO_ROUTING                   = 0x2b
	IPPROTO_RSVP                      = 0x2e
	IPPROTO_RVD                       = 0x42
	IPPROTO_SATEXPAK                  = 0x40
	IPPROTO_SATMON                    = 0x45
	IPPROTO_SCCSP                     = 0x60
	IPPROTO_SCTP                      = 0x84
	IPPROTO_SDRP                      = 0x2a
	IPPROTO_SEND                      = 0x103
	IPPROTO_SEP                       = 0x21
	IPPROTO_SKIP                      = 0x39
	IPPROTO_SPACER                    = 0x7fff
	IPPROTO_SRPC                      = 0x5a
	IPPROTO_ST                        = 0x7
	IPPROTO_SVMTP                     = 0x52
	IPPROTO_SWIPE                     = 0x35
	IPPROTO_TCF                       = 0x57
	IPPROTO_TCP                       = 0x6
	IPPROTO_TLSP                      = 0x38
	IPPROTO_TP                        = 0x1d
	IPPROTO_TPXX                      = 0x27
	IPPROTO_TRUNK1                    = 0x17
	IPPROTO_TRUNK2                    = 0x18
	IPPROTO_TTP                       = 0x54
	IPPROTO_UDP                       = 0x11
	IPPROTO_VINES                     = 0x53
	IPPROTO_VISA                      = 0x46
	IPPROTO_VMTP                      = 0x51
	IPPROTO_WBEXPAK                   = 0x4f
	IPPROTO_WBMON                     = 0x4e
	IPPROTO_WSN                       = 0x4a
	IPPROTO_XNET                      = 0xf
	IPPROTO_XTP                       = 0x24
	IPV6_AUTOFLOWLABEL                = 0x3b
	IPV6_BINDANY                      = 0x40
	IPV6_BINDV6ONLY                   = 0x1b
	IPV6_CHECKSUM                     = 0x1a
	IPV6_DEFAULT_MULTICAST_HOPS       = 0x1
	IPV6_DEFAULT_MULTICAST_LOOP       = 0x1
	IPV6_DEFHLIM                      = 0x40
	IPV6_DONTFRAG                     = 0x3e
	IPV6_DSTOPTS                      = 0x32
	IPV6_FAITH                        = 0x1d
	IPV6_FLOWINFO_MASK                = 0xffffff0f
	IPV6_FLOWLABEL_MASK               = 0xffff0f00
	IPV6_FRAGTTL                      = 0x78
	IPV6_FW_ADD                       = 0x1e
	IPV6_FW_DEL                       = 0x1f
	IPV6_FW_FLUSH                     = 0x20
	IPV6_FW_GET                       = 0x22
	IPV6_FW_ZERO                      = 0x21
	IPV6_HLIMDEC                      = 0x1
	IPV6_HOPLIMIT                     = 0x2f
	IPV6_HOPOPTS                      = 0x31
	IPV6_IPSEC_POLICY                 = 0x1c
	IPV6_JOIN_GROUP                   = 0xc
	IPV6_LEAVE_GROUP                  = 0xd
	IPV6_MAXHLIM                      = 0xff
	IPV6_MAXOPTHDR                    = 0x800
	IPV6_MAXPACKET                    = 0xffff
	IPV6_MAX_GROUP_SRC_FILTER         = 0x200
	IPV6_MAX_MEMBERSHIPS              = 0xfff
	IPV6_MAX_SOCK_SRC_FILTER          = 0x80
	IPV6_MIN_MEMBERSHIPS              = 0x1f
	IPV6_MMTU                         = 0x500
	IPV6_MSFILTER                     = 0x4a
	IPV6_MULTICAST_HOPS               = 0xa
	IPV6_MULTICAST_IF                 = 0x9
	IPV6_MULTICAST_LOOP               = 0xb
	IPV6_NEXTHOP                      = 0x30
	IPV6_PATHMTU                      = 0x2c
	IPV6_PKTINFO                      = 0x2e
	IPV6_PORTRANGE                    = 0xe
	IPV6_PORTRANGE_DEFAULT            = 0x0
	IPV6_PORTRANGE_HIGH               = 0x1
	IPV6_PORTRANGE_LOW                = 0x2
	IPV6_PREFER_TEMPADDR              = 0x3f
	IPV6_RECVDSTOPTS                  = 0x28
	IPV6_RECVHOPLIMIT                 = 0x25
	IPV6_RECVHOPOPTS                  = 0x27
	IPV6_RECVPATHMTU                  = 0x2b
	IPV6_RECVPKTINFO                  = 0x24
	IPV6_RECVRTHDR                    = 0x26
	IPV6_RECVTCLASS                   = 0x39
	IPV6_RTHDR                        = 0x33
	IPV6_RTHDRDSTOPTS                 = 0x23
	IPV6_RTHDR_LOOSE                  = 0x0
	IPV6_RTHDR_STRICT                 = 0x1
	IPV6_RTHDR_TYPE_0                 = 0x0
	IPV6_SOCKOPT_RESERVED1            = 0x3
	IPV6_TCLASS                       = 0x3d
	IPV6_UNICAST_HOPS                 = 0x4
	IPV6_USE_MIN_MTU                  = 0x2a
	IPV6_V6ONLY                       = 0x1b
	IPV6_VERSION                      = 0x60
	IPV6_VERSION_MASK                 = 0xf0
	IP_ADD_MEMBERSHIP                 = 0xc
	IP_ADD_SOURCE_MEMBERSHIP          = 0x46
	IP_BINDANY                        = 0x18
	IP_BLOCK_SOURCE                   = 0x48
	IP_DEFAULT_MULTICAST_LOOP         = 0x1
	IP_DEFAULT_MULTICAST_TTL          = 0x1
	IP_DF                             = 0x4000
	IP_DONTFRAG                       = 0x43
	IP_DROP_MEMBERSHIP                = 0xd
	IP_DROP_SOURCE_MEMBERSHIP         = 0x47
	IP_DUMMYNET3                      = 0x31
	IP_DUMMYNET_CONFIGURE             = 0x3c
	IP_DUMMYNET_DEL                   = 0x3d
	IP_DUMMYNET_FLUSH                 = 0x3e
	IP_DUMMYNET_GET                   = 0x40
	IP_FAITH                          = 0x16
	IP_FW3                            = 0x30
	IP_FW_ADD                         = 0x32
	IP_FW_DEL                         = 0x33
	IP_FW_FLUSH                       = 0x34
	IP_FW_GET                         = 0x36
	IP_FW_NAT_CFG                     = 0x38
	IP_FW_NAT_DEL                     = 0x39
	IP_FW_NAT_GET_CONFIG              = 0x3a
	IP_FW_NAT_GET_LOG                 = 0x3b
	IP_FW_RESETLOG                    = 0x37
	IP_FW_TABLE_ADD                   = 0x28
	IP_FW_TABLE_DEL                   = 0x29
	IP_FW_TABLE_FLUSH                 = 0x2a
	IP_FW_TABLE_GETSIZE               = 0x2b
	IP_FW_TABLE_LIST                  = 0x2c
	IP_FW_ZERO                        = 0x35
	IP_HDRINCL                        = 0x2
	IP_IPSEC_POLICY                   = 0x15
	IP_MAXPACKET                      = 0xffff
	IP_MAX_GROUP_SRC_FILTER           = 0x200
	IP_MAX_MEMBERSHIPS                = 0xfff
	IP_MAX_SOCK_MUTE_FILTER           = 0x80
	IP_MAX_SOCK_SRC_FILTER            = 0x80
	IP_MAX_SOURCE_FILTER              = 0x400
	IP_MF                             = 0x2000
	IP_MINTTL                         = 0x42
	IP_MIN_MEMBERSHIPS                = 0x1f
	IP_MSFILTER                       = 0x4a
	IP_MSS                            = 0x240
	IP_MULTICAST_IF                   = 0x9
	IP_MULTICAST_LOOP                 = 0xb
	IP_MULTICAST_TTL                  = 0xa
	IP_MULTICAST_VIF                  = 0xe
	IP_OFFMASK                        = 0x1fff
	IP_ONESBCAST                      = 0x17
	IP_OPTIONS                        = 0x1
	IP_PORTRANGE                      = 0x13
	IP_PORTRANGE_DEFAULT              = 0x0
	IP_PORTRANGE_HIGH                 = 0x1
	IP_PORTRANGE_LOW                  = 0x2
	IP_RECVDSTADDR                    = 0x7
	IP_RECVIF                         = 0x14
	IP_RECVOPTS                       = 0x5
	IP_RECVRETOPTS                    = 0x6
	IP_RECVTOS                        = 0x44
	IP_RECVTTL                        = 0x41
	IP_RETOPTS                        = 0x8
	IP_RF                             = 0x8000
	IP_RSVP_OFF                       = 0x10
	IP_RSVP_ON                        = 0xf
	IP_RSVP_VIF_OFF                   = 0x12
	IP_RSVP_VIF_ON                    = 0x11
	IP_SENDSRCADDR                    = 0x7
	IP_TOS                            = 0x3
	IP_TTL                            = 0x4
	IP_UNBLOCK_SOURCE                 = 0x49
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
	MADV_CORE                         = 0x9
	MADV_DONTNEED                     = 0x4
	MADV_FREE                         = 0x5
	MADV_NOCORE                       = 0x8
	MADV_NORMAL                       = 0x0
	MADV_NOSYNC                       = 0x6
	MADV_PROTECT                      = 0xa
	MADV_RANDOM                       = 0x1
	MADV_SEQUENTIAL                   = 0x2
	MADV_WILLNEED                     = 0x3
	MAP_ALIGNED_SUPER                 = 0x1000000
	MAP_ALIGNMENT_MASK                = -0x1000000
	MAP_ALIGNMENT_SHIFT               = 0x18
	MAP_ANON                          = 0x1000
	MAP_ANONYMOUS                     = 0x1000
	MAP_COPY                          = 0x2
	MAP_FILE                          = 0x0
	MAP_FIXED                         = 0x10
	MAP_HASSEMAPHORE                  = 0x200
	MAP_NOCORE                        = 0x20000
	MAP_NORESERVE                     = 0x40
	MAP_NOSYNC                        = 0x800
	MAP_PREFAULT_READ                 = 0x40000
	MAP_PRIVATE                       = 0x2
	MAP_RENAME                        = 0x20
	MAP_RESERVED0080                  = 0x80
	MAP_RESERVED0100                  = 0x100
	MAP_SHARED                        = 0x1
	MAP_STACK                         = 0x400
	MCL_CURRENT                       = 0x1
	MCL_FUTURE                        = 0x2
	MSG_CMSG_CLOEXEC                  = 0x40000
	MSG_COMPAT                        = 0x8000
	MSG_CTRUNC                        = 0x20
	MSG_DONTROUTE                     = 0x4
	MSG_DONTWAIT                      = 0x80
	MSG_EOF                           = 0x100
	MSG_EOR                           = 0x8
	MSG_NBIO                          = 0x4000
	MSG_NOSIGNAL                      = 0x20000
	MSG_NOTIFICATION                  = 0x2000
	MSG_OOB                           = 0x1
	MSG_PEEK                          = 0x2
	MSG_TRUNC                         = 0x10
	MSG_WAITALL                       = 0x40
	MS_ASYNC                          = 0x1
	MS_INVALIDATE                     = 0x2
	MS_SYNC                           = 0x0
	NAME_MAX                          = 0xff
	NET_RT_DUMP                       = 0x1
	NET_RT_FLAGS                      = 0x2
	NET_RT_IFLIST                     = 0x3
	NET_RT_IFLISTL                    = 0x5
	NET_RT_IFMALIST                   = 0x4
	NET_RT_MAXID                      = 0x6
	NOFLSH                            = 0x80000000
	NOTE_ATTRIB                       = 0x8
	NOTE_CHILD                        = 0x4
	NOTE_DELETE                       = 0x1
	NOTE_EXEC                         = 0x20000000
	NOTE_EXIT                         = 0x80000000
	NOTE_EXTEND                       = 0x4
	NOTE_FFAND                        = 0x40000000
	NOTE_FFCOPY                       = 0xc0000000
	NOTE_FFCTRLMASK                   = 0xc0000000
	NOTE_FFLAGSMASK                   = 0xffffff
	NOTE_FFNOP                        = 0x0
	NOTE_FFOR                         = 0x80000000
	NOTE_FORK                         = 0x40000000
	NOTE_LINK                         = 0x10
	NOTE_LOWAT                        = 0x1
	NOTE_PCTRLMASK                    = 0xf0000000
	NOTE_PDATAMASK                    = 0xfffff
	NOTE_RENAME                       = 0x20
	NOTE_REVOKE                       = 0x40
	NOTE_TRACK                        = 0x1
	NOTE_TRACKERR                     = 0x2
	NOTE_TRIGGER                      = 0x1000000
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
	O_CLOEXEC                         = 0x100000
	O_CREAT                           = 0x200
	O_DIRECT                          = 0x10000
	O_DIRECTORY                       = 0x20000
	O_EXCL                            = 0x800
	O_EXEC                            = 0x40000
	O_EXLOCK                          = 0x20
	O_FSYNC                           = 0x80
	O_NDELAY                          = 0x4
	O_NOCTTY                          = 0x8000
	O_NOFOLLOW                        = 0x100
	O_NONBLOCK                        = 0x4
	O_RDONLY                          = 0x0
	O_RDWR                            = 0x2
	O_SHLOCK                          = 0x10
	O_SYNC                            = 0x80
	O_TRUNC                           = 0x400
	O_TTY_INIT                        = 0x80000
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
	RTF_DONE                          = 0x40
	RTF_DYNAMIC                       = 0x10
	RTF_FMASK                         = 0x1004d808
	RTF_GATEWAY                       = 0x2
	RTF_GWFLAG_COMPAT                 = 0x80000000
	RTF_HOST                          = 0x4
	RTF_LLDATA                        = 0x400
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
	RTF_RNH_LOCKED                    = 0x40000000
	RTF_STATIC                        = 0x800
	RTF_STICKY                        = 0x10000000
	RTF_UP                            = 0x1
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
	RTM_VERSION                       = 0x5
	RTV_EXPIRE                        = 0x4
	RTV_HOPCOUNT                      = 0x2
	RTV_MTU                           = 0x1
	RTV_RPIPE                         = 0x8
	RTV_RTT                           = 0x40
	RTV_RTTVAR                        = 0x80
	RTV_SPIPE                         = 0x10
	RTV_SSTHRESH                      = 0x20
	RTV_WEIGHT                        = 0x100
	RT_CACHING_CONTEXT                = 0x1
	RT_DEFAULT_FIB                    = 0x0
	RT_NORTREF                        = 0x2
	RUSAGE_CHILDREN                   = -0x1
	RUSAGE_SELF                       = 0x0
	RUSAGE_THREAD                     = 0x1
	SCM_BINTIME                       = 0x4
	SCM_CREDS                         = 0x3
	SCM_RIGHTS                        = 0x1
	SCM_TIMESTAMP                     = 0x2
	SHUT_RD                           = 0x0
	SHUT_RDWR                         = 0x2
	SHUT_WR                           = 0x1
	SIOCADDMULTI                      = 0x80206931
	SIOCADDRT                         = 0x8030720a
	SIOCAIFADDR                       = 0x8040691a
	SIOCAIFGROUP                      = 0x80246987
	SIOCALIFADDR                      = 0x8118691b
	SIOCATMARK                        = 0x40047307
	SIOCDELMULTI                      = 0x80206932
	SIOCDELRT                         = 0x8030720b
	SIOCDIFADDR                       = 0x80206919
	SIOCDIFGROUP                      = 0x80246989
	SIOCDIFPHYADDR                    = 0x80206949
	SIOCDLIFADDR                      = 0x8118691d
	SIOCGDRVSPEC                      = 0xc01c697b
	SIOCGETSGCNT                      = 0xc0147210
	SIOCGETVIFCNT                     = 0xc014720f
	SIOCGHIWAT                        = 0x40047301
	SIOCGIFADDR                       = 0xc0206921
	SIOCGIFBRDADDR                    = 0xc0206923
	SIOCGIFCAP                        = 0xc020691f
	SIOCGIFCONF                       = 0xc0086924
	SIOCGIFDESCR                      = 0xc020692a
	SIOCGIFDSTADDR                    = 0xc0206922
	SIOCGIFFIB                        = 0xc020695c
	SIOCGIFFLAGS                      = 0xc0206911
	SIOCGIFGENERIC                    = 0xc020693a
	SIOCGIFGMEMB                      = 0xc024698a
	SIOCGIFGROUP                      = 0xc0246988
	SIOCGIFINDEX                      = 0xc0206920
	SIOCGIFMAC                        = 0xc0206926
	SIOCGIFMEDIA                      = 0xc0286938
	SIOCGIFMETRIC                     = 0xc0206917
	SIOCGIFMTU                        = 0xc0206933
	SIOCGIFNETMASK                    = 0xc0206925
	SIOCGIFPDSTADDR                   = 0xc0206948
	SIOCGIFPHYS                       = 0xc0206935
	SIOCGIFPSRCADDR                   = 0xc0206947
	SIOCGIFSTATUS                     = 0xc331693b
	SIOCGLIFADDR                      = 0xc118691c
	SIOCGLIFPHYADDR                   = 0xc118694b
	SIOCGLOWAT                        = 0x40047303
	SIOCGPGRP                         = 0x40047309
	SIOCGPRIVATE_0                    = 0xc0206950
	SIOCGPRIVATE_1                    = 0xc0206951
	SIOCIFCREATE                      = 0xc020697a
	SIOCIFCREATE2                     = 0xc020697c
	SIOCIFDESTROY                     = 0x80206979
	SIOCIFGCLONERS                    = 0xc00c6978
	SIOCSDRVSPEC                      = 0x801c697b
	SIOCSHIWAT                        = 0x80047300
	SIOCSIFADDR                       = 0x8020690c
	SIOCSIFBRDADDR                    = 0x80206913
	SIOCSIFCAP                        = 0x8020691e
	SIOCSIFDESCR                      = 0x80206929
	SIOCSIFDSTADDR                    = 0x8020690e
	SIOCSIFFIB                        = 0x8020695d
	SIOCSIFFLAGS                      = 0x80206910
	SIOCSIFGENERIC                    = 0x80206939
	SIOCSIFLLADDR                     = 0x8020693c
	SIOCSIFMAC                        = 0x80206927
	SIOCSIFMEDIA                      = 0xc0206937
	SIOCSIFMETRIC                     = 0x80206918
	SIOCSIFMTU                        = 0x80206934
	SIOCSIFNAME                       = 0x80206928
	SIOCSIFNETMASK                    = 0x80206916
	SIOCSIFPHYADDR                    = 0x80406946
	SIOCSIFPHYS                       = 0x80206936
	SIOCSIFRVNET                      = 0xc020695b
	SIOCSIFVNET                       = 0xc020695a
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
	SO_BINTIME                        = 0x2000
	SO_BROADCAST                      = 0x20
	SO_DEBUG                          = 0x1
	SO_DONTROUTE                      = 0x10
	SO_ERROR                          = 0x1007
	SO_KEEPALIVE                      = 0x8
	SO_LABEL                          = 0x1009
	SO_LINGER                         = 0x80
	SO_LISTENINCQLEN                  = 0x1013
	SO_LISTENQLEN                     = 0x1012
	SO_LISTENQLIMIT                   = 0x1011
	SO_NOSIGPIPE                      = 0x800
	SO_NO_DDP                         = 0x8000
	SO_NO_OFFLOAD                     = 0x4000
	SO_OOBINLINE                      = 0x100
	SO_PEERLABEL                      = 0x1010
	SO_PROTOCOL                       = 0x1016
	SO_PROTOTYPE                      = 0x1016
	SO_RCVBUF                         = 0x1002
	SO_RCVLOWAT                       = 0x1004
	SO_RCVTIMEO                       = 0x1006
	SO_REUSEADDR                      = 0x4
	SO_REUSEPORT                      = 0x200
	SO_SETFIB                         = 0x1014
	SO_SNDBUF                         = 0x1001
	SO_SNDLOWAT                       = 0x1003
	SO_SNDTIMEO                       = 0x1005
	SO_TIMESTAMP                      = 0x400
	SO_TYPE                           = 0x1008
	SO_USELOOPBACK                    = 0x40
	SO_USER_COOKIE                    = 0x1015
	SO_VENDOR                         = 0x80000000
	TCIFLUSH                          = 0x1
	TCIOFLUSH                         = 0x3
	TCOFLUSH                          = 0x2
	TCP_CA_NAME_MAX                   = 0x10
	TCP_CONGESTION                    = 0x40
	TCP_INFO                          = 0x20
	TCP_KEEPCNT                       = 0x400
	TCP_KEEPIDLE                      = 0x100
	TCP_KEEPINIT                      = 0x80
	TCP_KEEPINTVL                     = 0x200
	TCP_MAXBURST                      = 0x4
	TCP_MAXHLEN                       = 0x3c
	TCP_MAXOLEN                       = 0x28
	TCP_MAXSEG                        = 0x2
	TCP_MAXWIN                        = 0xffff
	TCP_MAX_SACK                      = 0x4
	TCP_MAX_WINSHIFT                  = 0xe
	TCP_MD5SIG                        = 0x10
	TCP_MINMSS                        = 0xd8
	TCP_MSS                           = 0x218
	TCP_NODELAY                       = 0x1
	TCP_NOOPT                         = 0x8
	TCP_NOPUSH                        = 0x4
	TCP_VENDOR                        = 0x80000000
	TCSAFLUSH                         = 0x2
	TIOCCBRK                          = 0x2000747a
	TIOCCDTR                          = 0x20007478
	TIOCCONS                          = 0x80047462
	TIOCDRAIN                         = 0x2000745e
	TIOCEXCL                          = 0x2000740d
	TIOCEXT                           = 0x80047460
	TIOCFLUSH                         = 0x80047410
	TIOCGDRAINWAIT                    = 0x40047456
	TIOCGETA                          = 0x402c7413
	TIOCGETD                          = 0x4004741a
	TIOCGPGRP                         = 0x40047477
	TIOCGPTN                          = 0x4004740f
	TIOCGSID                          = 0x40047463
	TIOCGWINSZ                        = 0x40087468
	TIOCMBIC                          = 0x8004746b
	TIOCMBIS                          = 0x8004746c
	TIOCMGDTRWAIT                     = 0x4004745a
	TIOCMGET                          = 0x4004746a
	TIOCMSDTRWAIT                     = 0x8004745b
	TIOCMSET                          = 0x8004746d
	TIOCM_CAR                         = 0x40
	TIOCM_CD                          = 0x40
	TIOCM_CTS                         = 0x20
	TIOCM_DCD                         = 0x40
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
	TIOCPTMASTER                      = 0x2000741c
	TIOCSBRK                          = 0x2000747b
	TIOCSCTTY                         = 0x20007461
	TIOCSDRAINWAIT                    = 0x80047457
	TIOCSDTR                          = 0x20007479
	TIOCSETA                          = 0x802c7414
	TIOCSETAF                         = 0x802c7416
	TIOCSETAW                         = 0x802c7415
	TIOCSETD                          = 0x8004741b
	TIOCSIG                           = 0x2004745f
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
	WSTOPPED                          = 0x2
	WTRAPPED                          = 0x20
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
	EBADF           = Errno(0x9)
	EBADMSG         = Errno(0x59)
	EBADRPC         = Errno(0x48)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x55)
	ECAPMODE        = Errno(0x5e)
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
	ELAST           = Errno(0x60)
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
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x53)
	ENOPROTOOPT     = Errno(0x2a)
	ENOSPC          = Errno(0x1c)
	ENOSYS          = Errno(0x4e)
	ENOTBLK         = Errno(0xf)
	ENOTCAPABLE     = Errno(0x5d)
	ENOTCONN        = Errno(0x39)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x42)
	ENOTRECOVERABLE = Errno(0x5f)
	ENOTSOCK        = Errno(0x26)
	ENOTSUP         = Errno(0x2d)
	ENOTTY          = Errno(0x19)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x2d)
	EOVERFLOW       = Errno(0x54)
	EOWNERDEAD      = Errno(0x60)
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
	SIGLIBRT  = Signal(0x21)
	SIGLWP    = Signal(0x20)
	SIGPIPE   = Signal(0xd)
	SIGPROF   = Signal(0x1b)
	SIGQUIT   = Signal(0x3)
	SIGSEGV   = Signal(0xb)
	SIGSTOP   = Signal(0x11)
	SIGSYS    = Signal(0xc)
	SIGTERM   = Signal(0xf)
	SIGTHR    = Signal(0x20)
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
	14: "ba
"""




```