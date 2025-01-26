Response:
The user is asking for the functionalities of a Go file named `zerrors_netbsd_arm64.go` located in the `syscall` package. This file likely defines platform-specific constants related to system calls for the NetBSD operating system on the ARM64 architecture.

**Breakdown of the request:**

1. **List functionalities:** Identify the main purpose of the code.
2. **Infer Go language feature:** Determine which Go language features this file implements. It's highly likely to be related to system calls and error handling.
3. **Go code example:** Provide a code snippet illustrating the use of these constants.
4. **Code reasoning:** Explain the logic behind the code example, including assumed inputs and outputs.
5. **Command-line argument handling:** Check if the code involves processing command-line arguments. This is unlikely for a file defining constants.
6. **Common mistakes:** Identify potential pitfalls for users.
7. **Summarize functionalities (Part 2):** Provide a concise summary of the file's purpose.

**Plan:**

1. **Analyze the code:** Examine the constants defined in the file. They appear to be related to various system-level entities like network interfaces, IP protocols, socket options, file system flags, signals, and error numbers.
2. **Identify the core functionality:** The file primarily defines constants used by system calls.
3. **Determine the Go feature:** This is related to the `syscall` package, which provides a low-level interface to the operating system.
4. **Create a Go example:** Demonstrate how to use some of these constants in a syscall context. Focus on network-related constants, as the filename suggests a network focus.
5. **Explain the example:** Describe the example's purpose, assumed inputs, and expected outputs.
6. **Address other points:**  Confirm that command-line argument handling is not relevant and discuss potential mistakes (like using incorrect platform-specific constants on other operating systems).
7. **Summarize:** Provide a concise summary of the file's function as part 2 of the response.
## 功能归纳 (第2部分)

这部分 `go/src/syscall/zerrors_netbsd_arm64.go` 文件主要定义了在 NetBSD 操作系统 ARM64 架构下，用于系统调用的**常量**。这些常量涵盖了多个方面，可以归纳为以下几类：

1. **网络接口类型 (IFT_ 开头):**  定义了各种网络接口的类型，例如以太网、令牌环、隧道接口等等。这些常量在处理网络设备和接口信息时非常有用。
2. **终端控制标志 (IGNBRK, IGNCR, IMAXBEL 等):** 定义了与终端输入输出相关的控制标志，用于配置终端的行为，例如忽略断开信号、忽略回车符、响铃等等。
3. **网络地址类 (IN_CLASSA_HOST, IN_CLASSB_NET 等):** 定义了用于区分 IPv4 地址类别的常量，方便进行网络地址的解析和判断。
4. **IP 协议类型 (IPPROTO_ 开头):** 定义了各种 IP 协议的类型，例如 TCP、UDP、ICMP 等等。在进行网络编程时，需要指定使用的协议类型。
5. **IPv6 选项 (IPV6_CHECKSUM, IPV6_DEFAULT_MULTICAST_HOPS 等):** 定义了与 IPv6 协议相关的选项，例如校验和计算、默认组播跳数限制等等。
6. **IP 选项 (IP_ADD_MEMBERSHIP, IP_DEFAULT_MULTICAST_LOOP 等):** 定义了与 IPv4 协议相关的选项，例如添加/删除组成员、默认组播环回等等。
7. **终端输入输出控制标志 (ISIG, ISTRIP, IXON 等):** 定义了更底层的终端输入输出控制标志，用于精细地控制终端的行为。
8. **文件锁类型 (LOCK_EX, LOCK_NB 等):** 定义了文件锁的类型，例如排他锁、非阻塞锁等等，用于实现进程间的文件访问同步。
9. **内存映射选项 (MADV_DONTNEED, MAP_ANON 等):** 定义了内存映射相关的选项，例如建议内核释放内存、创建匿名映射等等。
10. **消息传递标志 (MSG_BCAST, MSG_DONTWAIT 等):** 定义了在发送和接收消息时可以使用的标志，例如广播消息、非阻塞发送/接收等等。
11. **内存同步标志 (MS_ASYNC, MS_SYNC 等):** 定义了内存同步相关的标志，用于控制内存数据何时写入磁盘。
12. **路由表操作类型 (NET_RT_DUMP, NET_RT_FLAGS 等):**  定义了对网络路由表进行操作的类型，例如导出路由表、设置路由标志等等。
13. **文件事件通知标志 (NOTE_ATTRIB, NOTE_CHILD 等):** 定义了用于文件事件通知的标志，可以监控文件属性变化、子进程事件等等。
14. **终端输出控制标志 (OCRNL, ONLCR 等):** 定义了终端输出相关的控制标志，例如将回车转换为换行、将换行转换为回车换行等等。
15. **文件打开选项 (O_ACCMODE, O_APPEND 等):** 定义了打开文件时可以使用的选项，例如读写模式、追加模式等等。
16. **终端奇偶校验 (PARENB, PARMRK 等):** 定义了终端奇偶校验相关的设置。
17. **进程优先级 (PRIO_PGRP, PRIO_PROCESS 等):** 定义了设置进程优先级的类别。
18. **内存保护标志 (PROT_EXEC, PROT_READ 等):** 定义了内存保护的类型，例如可执行、可读等等。
19. **资源限制类型 (RLIMIT_AS, RLIMIT_CPU 等):** 定义了各种资源限制的类型，例如地址空间限制、CPU 时间限制等等。
20. **路由属性类型 (RTAX_AUTHOR, RTAX_DST 等):** 定义了路由信息的各个属性字段。
21. **路由标志 (RTA_AUTHOR, RTA_BRD 等):** 定义了路由信息的标志位。
22. **路由表消息类型 (RTM_ADD, RTM_DELETE 等):** 定义了路由表操作的消息类型，例如添加路由、删除路由等等。
23. **路由估算变量 (RTV_EXPIRE, RTV_HOPCOUNT 等):** 定义了路由估算的一些变量。
24. **资源使用类型 (RUSAGE_CHILDREN, RUSAGE_SELF):** 定义了获取资源使用情况的进程范围。
25. **Socket 控制消息类型 (SCM_CREDS, SCM_RIGHTS 等):** 定义了 socket 控制消息的类型，例如传递凭据、传递文件描述符等等。
26. **Socket 关闭方式 (SHUT_RD, SHUT_RDWR 等):** 定义了 socket 关闭的方式，例如禁止读取、禁止读写等等。
27. **Socket IO 控制命令 (SIOCADDMULTI, SIOCADDRT 等):**  定义了用于控制 socket IO 的各种命令，例如添加组播成员、添加路由等等。这些通常对应于系统调用。
28. **Socket 类型 (SOCK_DGRAM, SOCK_STREAM 等):** 定义了 socket 的类型，例如数据报 socket、流式 socket 等等。
29. **Socket 选项 (SOL_SOCKET, SO_ACCEPTCONN 等):** 定义了 socket 的各种选项，例如是否监听连接、是否允许广播等等。
30. **Sysctl 版本 (SYSCTL_VERSION, SYSCTL_VERS_0 等):** 定义了 sysctl 接口的版本信息。
31. **文件状态标志 (S_ARCH1, S_IFBLK 等):** 定义了用于表示文件状态的标志，例如文件类型、权限等等。
32. **终端控制命令 (TCIFLUSH, TCIOFLUSH 等):** 定义了用于控制终端的命令，例如刷新输入缓冲区、刷新输出缓冲区等等。
33. **TCP 选项 (TCP_CONGCTL, TCP_KEEPCNT 等):** 定义了 TCP 协议相关的选项，例如拥塞控制算法、保持连接探测次数等等。
34. **终端控制 ioctl 命令 (TIOCCBRK, TIOCCDTR 等):** 定义了用于终端控制的 ioctl 命令，例如发送中断信号、清除 DTR 信号等等。这些是更底层的终端控制操作。
35. **终端控制标志 (TIOCFLAG_CDTRCTS, TIOCFLAG_CLOCAL 等):**  定义了更详细的终端控制标志。
36. **终端包模式标志 (TIOCPKT_DATA, TIOCPKT_FLUSHREAD 等):** 定义了终端包模式下的标志。
37. **终端窗口大小 (TIOCGWINSZ, TIOCSWINSZ):**  定义了获取和设置终端窗口大小的 ioctl 命令。
38. **终端 V 字符 (VDISCARD, VEOF 等):**  定义了终端特殊控制字符的常量，例如丢弃字符、文件结束符等等。
39. **进程等待选项 (WALL, WEXITED 等):** 定义了进程等待时可以使用的选项，例如等待所有子进程、只等待正常退出的子进程等等。

总而言之，这个文件是 Go 语言 `syscall` 包在 NetBSD ARM64 架构下的基石之一，它通过定义大量的常量，为 Go 程序提供了与操作系统底层交互的能力，特别是涉及到网络、终端、文件操作等方面。

Prompt: 
```
这是路径为go/src/syscall/zerrors_netbsd_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
CHANNEL          = 0xb9
	IFT_SONETPATH                     = 0x32
	IFT_SONETVT                       = 0x33
	IFT_SRP                           = 0x97
	IFT_SS7SIGLINK                    = 0x9c
	IFT_STACKTOSTACK                  = 0x6f
	IFT_STARLAN                       = 0xb
	IFT_STF                           = 0xd7
	IFT_T1                            = 0x12
	IFT_TDLC                          = 0x74
	IFT_TELINK                        = 0xc8
	IFT_TERMPAD                       = 0x5b
	IFT_TR008                         = 0xb0
	IFT_TRANSPHDLC                    = 0x7b
	IFT_TUNNEL                        = 0x83
	IFT_ULTRA                         = 0x1d
	IFT_USB                           = 0xa0
	IFT_V11                           = 0x40
	IFT_V35                           = 0x2d
	IFT_V36                           = 0x41
	IFT_V37                           = 0x78
	IFT_VDSL                          = 0x61
	IFT_VIRTUALIPADDRESS              = 0x70
	IFT_VIRTUALTG                     = 0xca
	IFT_VOICEDID                      = 0xd5
	IFT_VOICEEM                       = 0x64
	IFT_VOICEEMFGD                    = 0xd3
	IFT_VOICEENCAP                    = 0x67
	IFT_VOICEFGDEANA                  = 0xd4
	IFT_VOICEFXO                      = 0x65
	IFT_VOICEFXS                      = 0x66
	IFT_VOICEOVERATM                  = 0x98
	IFT_VOICEOVERCABLE                = 0xc6
	IFT_VOICEOVERFRAMERELAY           = 0x99
	IFT_VOICEOVERIP                   = 0x68
	IFT_X213                          = 0x5d
	IFT_X25                           = 0x5
	IFT_X25DDN                        = 0x4
	IFT_X25HUNTGROUP                  = 0x7a
	IFT_X25MLP                        = 0x79
	IFT_X25PLE                        = 0x28
	IFT_XETHER                        = 0x1a
	IGNBRK                            = 0x1
	IGNCR                             = 0x80
	IGNPAR                            = 0x4
	IMAXBEL                           = 0x2000
	INLCR                             = 0x40
	INPCK                             = 0x10
	IN_CLASSA_HOST                    = 0xffffff
	IN_CLASSA_MAX                     = 0x80
	IN_CLASSA_NET                     = 0xff000000
	IN_CLASSA_NSHIFT                  = 0x18
	IN_CLASSB_HOST                    = 0xffff
	IN_CLASSB_MAX                     = 0x10000
	IN_CLASSB_NET                     = 0xffff0000
	IN_CLASSB_NSHIFT                  = 0x10
	IN_CLASSC_HOST                    = 0xff
	IN_CLASSC_NET                     = 0xffffff00
	IN_CLASSC_NSHIFT                  = 0x8
	IN_CLASSD_HOST                    = 0xfffffff
	IN_CLASSD_NET                     = 0xf0000000
	IN_CLASSD_NSHIFT                  = 0x1c
	IN_LOOPBACKNET                    = 0x7f
	IPPROTO_AH                        = 0x33
	IPPROTO_CARP                      = 0x70
	IPPROTO_DONE                      = 0x101
	IPPROTO_DSTOPTS                   = 0x3c
	IPPROTO_EGP                       = 0x8
	IPPROTO_ENCAP                     = 0x62
	IPPROTO_EON                       = 0x50
	IPPROTO_ESP                       = 0x32
	IPPROTO_ETHERIP                   = 0x61
	IPPROTO_FRAGMENT                  = 0x2c
	IPPROTO_GGP                       = 0x3
	IPPROTO_GRE                       = 0x2f
	IPPROTO_HOPOPTS                   = 0x0
	IPPROTO_ICMP                      = 0x1
	IPPROTO_ICMPV6                    = 0x3a
	IPPROTO_IDP                       = 0x16
	IPPROTO_IGMP                      = 0x2
	IPPROTO_IP                        = 0x0
	IPPROTO_IPCOMP                    = 0x6c
	IPPROTO_IPIP                      = 0x4
	IPPROTO_IPV4                      = 0x4
	IPPROTO_IPV6                      = 0x29
	IPPROTO_IPV6_ICMP                 = 0x3a
	IPPROTO_MAX                       = 0x100
	IPPROTO_MAXID                     = 0x34
	IPPROTO_MOBILE                    = 0x37
	IPPROTO_NONE                      = 0x3b
	IPPROTO_PFSYNC                    = 0xf0
	IPPROTO_PIM                       = 0x67
	IPPROTO_PUP                       = 0xc
	IPPROTO_RAW                       = 0xff
	IPPROTO_ROUTING                   = 0x2b
	IPPROTO_RSVP                      = 0x2e
	IPPROTO_TCP                       = 0x6
	IPPROTO_TP                        = 0x1d
	IPPROTO_UDP                       = 0x11
	IPPROTO_VRRP                      = 0x70
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
	IPV6_HLIMDEC                      = 0x1
	IPV6_HOPLIMIT                     = 0x2f
	IPV6_HOPOPTS                      = 0x31
	IPV6_IPSEC_POLICY                 = 0x1c
	IPV6_JOIN_GROUP                   = 0xc
	IPV6_LEAVE_GROUP                  = 0xd
	IPV6_MAXHLIM                      = 0xff
	IPV6_MAXPACKET                    = 0xffff
	IPV6_MMTU                         = 0x500
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
	IP_DEFAULT_MULTICAST_LOOP         = 0x1
	IP_DEFAULT_MULTICAST_TTL          = 0x1
	IP_DF                             = 0x4000
	IP_DROP_MEMBERSHIP                = 0xd
	IP_EF                             = 0x8000
	IP_ERRORMTU                       = 0x15
	IP_HDRINCL                        = 0x2
	IP_IPSEC_POLICY                   = 0x16
	IP_MAXPACKET                      = 0xffff
	IP_MAX_MEMBERSHIPS                = 0x14
	IP_MF                             = 0x2000
	IP_MINFRAGSIZE                    = 0x45
	IP_MINTTL                         = 0x18
	IP_MSS                            = 0x240
	IP_MULTICAST_IF                   = 0x9
	IP_MULTICAST_LOOP                 = 0xb
	IP_MULTICAST_TTL                  = 0xa
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
	IP_RECVTTL                        = 0x17
	IP_RETOPTS                        = 0x8
	IP_RF                             = 0x8000
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
	MADV_DONTNEED                     = 0x4
	MADV_FREE                         = 0x6
	MADV_NORMAL                       = 0x0
	MADV_RANDOM                       = 0x1
	MADV_SEQUENTIAL                   = 0x2
	MADV_SPACEAVAIL                   = 0x5
	MADV_WILLNEED                     = 0x3
	MAP_ALIGNMENT_16MB                = 0x18000000
	MAP_ALIGNMENT_1TB                 = 0x28000000
	MAP_ALIGNMENT_256TB               = 0x30000000
	MAP_ALIGNMENT_4GB                 = 0x20000000
	MAP_ALIGNMENT_64KB                = 0x10000000
	MAP_ALIGNMENT_64PB                = 0x38000000
	MAP_ALIGNMENT_MASK                = -0x1000000
	MAP_ALIGNMENT_SHIFT               = 0x18
	MAP_ANON                          = 0x1000
	MAP_FILE                          = 0x0
	MAP_FIXED                         = 0x10
	MAP_HASSEMAPHORE                  = 0x200
	MAP_INHERIT                       = 0x80
	MAP_INHERIT_COPY                  = 0x1
	MAP_INHERIT_DEFAULT               = 0x1
	MAP_INHERIT_DONATE_COPY           = 0x3
	MAP_INHERIT_NONE                  = 0x2
	MAP_INHERIT_SHARE                 = 0x0
	MAP_NORESERVE                     = 0x40
	MAP_PRIVATE                       = 0x2
	MAP_RENAME                        = 0x20
	MAP_SHARED                        = 0x1
	MAP_STACK                         = 0x2000
	MAP_TRYFIXED                      = 0x400
	MAP_WIRED                         = 0x800
	MCL_CURRENT                       = 0x1
	MCL_FUTURE                        = 0x2
	MSG_BCAST                         = 0x100
	MSG_CMSG_CLOEXEC                  = 0x800
	MSG_CONTROLMBUF                   = 0x2000000
	MSG_CTRUNC                        = 0x20
	MSG_DONTROUTE                     = 0x4
	MSG_DONTWAIT                      = 0x80
	MSG_EOR                           = 0x8
	MSG_IOVUSRSPACE                   = 0x4000000
	MSG_LENUSRSPACE                   = 0x8000000
	MSG_MCAST                         = 0x200
	MSG_NAMEMBUF                      = 0x1000000
	MSG_NBIO                          = 0x1000
	MSG_NOSIGNAL                      = 0x400
	MSG_OOB                           = 0x1
	MSG_PEEK                          = 0x2
	MSG_TRUNC                         = 0x10
	MSG_USERFLAGS                     = 0xffffff
	MSG_WAITALL                       = 0x40
	MS_ASYNC                          = 0x1
	MS_INVALIDATE                     = 0x2
	MS_SYNC                           = 0x4
	NAME_MAX                          = 0x1ff
	NET_RT_DUMP                       = 0x1
	NET_RT_FLAGS                      = 0x2
	NET_RT_IFLIST                     = 0x5
	NET_RT_MAXID                      = 0x6
	NET_RT_OIFLIST                    = 0x4
	NET_RT_OOIFLIST                   = 0x3
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
	NOTE_PCTRLMASK                    = 0xf0000000
	NOTE_PDATAMASK                    = 0xfffff
	NOTE_RENAME                       = 0x20
	NOTE_REVOKE                       = 0x40
	NOTE_TRACK                        = 0x1
	NOTE_TRACKERR                     = 0x2
	NOTE_WRITE                        = 0x2
	OCRNL                             = 0x10
	OFIOGETBMAP                       = 0xc004667a
	ONLCR                             = 0x2
	ONLRET                            = 0x40
	ONOCR                             = 0x20
	ONOEOT                            = 0x8
	OPOST                             = 0x1
	O_ACCMODE                         = 0x3
	O_ALT_IO                          = 0x40000
	O_APPEND                          = 0x8
	O_ASYNC                           = 0x40
	O_CLOEXEC                         = 0x400000
	O_CREAT                           = 0x200
	O_DIRECT                          = 0x80000
	O_DIRECTORY                       = 0x200000
	O_DSYNC                           = 0x10000
	O_EXCL                            = 0x800
	O_EXLOCK                          = 0x20
	O_FSYNC                           = 0x80
	O_NDELAY                          = 0x4
	O_NOCTTY                          = 0x8000
	O_NOFOLLOW                        = 0x100
	O_NONBLOCK                        = 0x4
	O_NOSIGPIPE                       = 0x1000000
	O_RDONLY                          = 0x0
	O_RDWR                            = 0x2
	O_RSYNC                           = 0x20000
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
	PRI_IOFLUSH                       = 0x7c
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
	RTAX_MAX                          = 0x9
	RTAX_NETMASK                      = 0x2
	RTAX_TAG                          = 0x8
	RTA_AUTHOR                        = 0x40
	RTA_BRD                           = 0x80
	RTA_DST                           = 0x1
	RTA_GATEWAY                       = 0x2
	RTA_GENMASK                       = 0x8
	RTA_IFA                           = 0x20
	RTA_IFP                           = 0x10
	RTA_NETMASK                       = 0x4
	RTA_TAG                           = 0x100
	RTF_ANNOUNCE                      = 0x20000
	RTF_BLACKHOLE                     = 0x1000
	RTF_CLONED                        = 0x2000
	RTF_CLONING                       = 0x100
	RTF_DONE                          = 0x40
	RTF_DYNAMIC                       = 0x10
	RTF_GATEWAY                       = 0x2
	RTF_HOST                          = 0x4
	RTF_LLINFO                        = 0x400
	RTF_MASK                          = 0x80
	RTF_MODIFIED                      = 0x20
	RTF_PROTO1                        = 0x8000
	RTF_PROTO2                        = 0x4000
	RTF_REJECT                        = 0x8
	RTF_SRC                           = 0x10000
	RTF_STATIC                        = 0x800
	RTF_UP                            = 0x1
	RTF_XRESOLVE                      = 0x200
	RTM_ADD                           = 0x1
	RTM_CHANGE                        = 0x3
	RTM_CHGADDR                       = 0x15
	RTM_DELADDR                       = 0xd
	RTM_DELETE                        = 0x2
	RTM_GET                           = 0x4
	RTM_IEEE80211                     = 0x11
	RTM_IFANNOUNCE                    = 0x10
	RTM_IFINFO                        = 0x14
	RTM_LLINFO_UPD                    = 0x13
	RTM_LOCK                          = 0x8
	RTM_LOSING                        = 0x5
	RTM_MISS                          = 0x7
	RTM_NEWADDR                       = 0xc
	RTM_OIFINFO                       = 0xf
	RTM_OLDADD                        = 0x9
	RTM_OLDDEL                        = 0xa
	RTM_OOIFINFO                      = 0xe
	RTM_REDIRECT                      = 0x6
	RTM_RESOLVE                       = 0xb
	RTM_RTTUNIT                       = 0xf4240
	RTM_SETGATE                       = 0x12
	RTM_VERSION                       = 0x4
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
	SCM_CREDS                         = 0x4
	SCM_RIGHTS                        = 0x1
	SCM_TIMESTAMP                     = 0x8
	SHUT_RD                           = 0x0
	SHUT_RDWR                         = 0x2
	SHUT_WR                           = 0x1
	SIOCADDMULTI                      = 0x80906931
	SIOCADDRT                         = 0x8038720a
	SIOCAIFADDR                       = 0x8040691a
	SIOCALIFADDR                      = 0x8118691c
	SIOCATMARK                        = 0x40047307
	SIOCDELMULTI                      = 0x80906932
	SIOCDELRT                         = 0x8038720b
	SIOCDIFADDR                       = 0x80906919
	SIOCDIFPHYADDR                    = 0x80906949
	SIOCDLIFADDR                      = 0x8118691e
	SIOCGDRVSPEC                      = 0xc028697b
	SIOCGETPFSYNC                     = 0xc09069f8
	SIOCGETSGCNT                      = 0xc0207534
	SIOCGETVIFCNT                     = 0xc0287533
	SIOCGHIWAT                        = 0x40047301
	SIOCGIFADDR                       = 0xc0906921
	SIOCGIFADDRPREF                   = 0xc0986920
	SIOCGIFALIAS                      = 0xc040691b
	SIOCGIFBRDADDR                    = 0xc0906923
	SIOCGIFCAP                        = 0xc0206976
	SIOCGIFCONF                       = 0xc0106926
	SIOCGIFDATA                       = 0xc0986985
	SIOCGIFDLT                        = 0xc0906977
	SIOCGIFDSTADDR                    = 0xc0906922
	SIOCGIFFLAGS                      = 0xc0906911
	SIOCGIFGENERIC                    = 0xc090693a
	SIOCGIFMEDIA                      = 0xc0306936
	SIOCGIFMETRIC                     = 0xc0906917
	SIOCGIFMTU                        = 0xc090697e
	SIOCGIFNETMASK                    = 0xc0906925
	SIOCGIFPDSTADDR                   = 0xc0906948
	SIOCGIFPSRCADDR                   = 0xc0906947
	SIOCGLIFADDR                      = 0xc118691d
	SIOCGLIFPHYADDR                   = 0xc118694b
	SIOCGLINKSTR                      = 0xc0286987
	SIOCGLOWAT                        = 0x40047303
	SIOCGPGRP                         = 0x40047309
	SIOCGVH                           = 0xc0906983
	SIOCIFCREATE                      = 0x8090697a
	SIOCIFDESTROY                     = 0x80906979
	SIOCIFGCLONERS                    = 0xc0106978
	SIOCINITIFADDR                    = 0xc0706984
	SIOCSDRVSPEC                      = 0x8028697b
	SIOCSETPFSYNC                     = 0x809069f7
	SIOCSHIWAT                        = 0x80047300
	SIOCSIFADDR                       = 0x8090690c
	SIOCSIFADDRPREF                   = 0x8098691f
	SIOCSIFBRDADDR                    = 0x80906913
	SIOCSIFCAP                        = 0x80206975
	SIOCSIFDSTADDR                    = 0x8090690e
	SIOCSIFFLAGS                      = 0x80906910
	SIOCSIFGENERIC                    = 0x80906939
	SIOCSIFMEDIA                      = 0xc0906935
	SIOCSIFMETRIC                     = 0x80906918
	SIOCSIFMTU                        = 0x8090697f
	SIOCSIFNETMASK                    = 0x80906916
	SIOCSIFPHYADDR                    = 0x80406946
	SIOCSLIFPHYADDR                   = 0x8118694a
	SIOCSLINKSTR                      = 0x80286988
	SIOCSLOWAT                        = 0x80047302
	SIOCSPGRP                         = 0x80047308
	SIOCSVH                           = 0xc0906982
	SIOCZIFDATA                       = 0xc0986986
	SOCK_CLOEXEC                      = 0x10000000
	SOCK_DGRAM                        = 0x2
	SOCK_FLAGS_MASK                   = 0xf0000000
	SOCK_NONBLOCK                     = 0x20000000
	SOCK_NOSIGPIPE                    = 0x40000000
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
	SO_NOHEADER                       = 0x100a
	SO_NOSIGPIPE                      = 0x800
	SO_OOBINLINE                      = 0x100
	SO_OVERFLOWED                     = 0x1009
	SO_RCVBUF                         = 0x1002
	SO_RCVLOWAT                       = 0x1004
	SO_RCVTIMEO                       = 0x100c
	SO_REUSEADDR                      = 0x4
	SO_REUSEPORT                      = 0x200
	SO_SNDBUF                         = 0x1001
	SO_SNDLOWAT                       = 0x1003
	SO_SNDTIMEO                       = 0x100b
	SO_TIMESTAMP                      = 0x2000
	SO_TYPE                           = 0x1008
	SO_USELOOPBACK                    = 0x40
	SYSCTL_VERSION                    = 0x1000000
	SYSCTL_VERS_0                     = 0x0
	SYSCTL_VERS_1                     = 0x1000000
	SYSCTL_VERS_MASK                  = 0xff000000
	S_ARCH1                           = 0x10000
	S_ARCH2                           = 0x20000
	S_BLKSIZE                         = 0x200
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
	S_LOGIN_SET                       = 0x1
	TCIFLUSH                          = 0x1
	TCIOFLUSH                         = 0x3
	TCOFLUSH                          = 0x2
	TCP_CONGCTL                       = 0x20
	TCP_KEEPCNT                       = 0x6
	TCP_KEEPIDLE                      = 0x3
	TCP_KEEPINIT                      = 0x7
	TCP_KEEPINTVL                     = 0x5
	TCP_MAXBURST                      = 0x4
	TCP_MAXSEG                        = 0x2
	TCP_MAXWIN                        = 0xffff
	TCP_MAX_WINSHIFT                  = 0xe
	TCP_MD5SIG                        = 0x10
	TCP_MINMSS                        = 0xd8
	TCP_MSS                           = 0x218
	TCP_NODELAY                       = 0x1
	TCSAFLUSH                         = 0x2
	TIOCCBRK                          = 0x2000747a
	TIOCCDTR                          = 0x20007478
	TIOCCONS                          = 0x80047462
	TIOCDCDTIMESTAMP                  = 0x40107458
	TIOCDRAIN                         = 0x2000745e
	TIOCEXCL                          = 0x2000740d
	TIOCEXT                           = 0x80047460
	TIOCFLAG_CDTRCTS                  = 0x10
	TIOCFLAG_CLOCAL                   = 0x2
	TIOCFLAG_CRTSCTS                  = 0x4
	TIOCFLAG_MDMBUF                   = 0x8
	TIOCFLAG_SOFTCAR                  = 0x1
	TIOCFLUSH                         = 0x80047410
	TIOCGETA                          = 0x402c7413
	TIOCGETD                          = 0x4004741a
	TIOCGFLAGS                        = 0x4004745d
	TIOCGLINED                        = 0x40207442
	TIOCGPGRP                         = 0x40047477
	TIOCGQSIZE                        = 0x40047481
	TIOCGRANTPT                       = 0x20007447
	TIOCGSID                          = 0x40047463
	TIOCGSIZE                         = 0x40087468
	TIOCGWINSZ                        = 0x40087468
	TIOCMBIC                          = 0x8004746b
	TIOCMBIS                          = 0x8004746c
	TIOCMGET                          = 0x4004746a
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
	TIOCPTMGET                        = 0x40287446
	TIOCPTSNAME                       = 0x40287448
	TIOCRCVFRAME                      = 0x80087445
	TIOCREMOTE                        = 0x80047469
	TIOCSBRK                          = 0x2000747b
	TIOCSCTTY                         = 0x20007461
	TIOCSDTR                          = 0x20007479
	TIOCSETA                          = 0x802c7414
	TIOCSETAF                         = 0x802c7416
	TIOCSETAW                         = 0x802c7415
	TIOCSETD                          = 0x8004741b
	TIOCSFLAGS                        = 0x8004745c
	TIOCSIG                           = 0x2000745f
	TIOCSLINED                        = 0x80207443
	TIOCSPGRP                         = 0x80047476
	TIOCSQSIZE                        = 0x80047480
	TIOCSSIZE                         = 0x80087467
	TIOCSTART                         = 0x2000746e
	TIOCSTAT                          = 0x80047465
	TIOCSTI                           = 0x80017472
	TIOCSTOP                          = 0x2000746f
	TIOCSWINSZ                        = 0x80087467
	TIOCUCNTL                         = 0x80047466
	TIOCXMTFRAME                      = 0x80087444
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
	VTIME                             = 0x11
	VWERASE                           = 0x4
	WALL                              = 0x8
	WALLSIG                           = 0x8
	WALTSIG                           = 0x4
	WCLONE                            = 0x4
	WCOREFLAG                         = 0x80
	WEXITED                           = 0x20
	WNOHANG                           = 0x1
	WNOWAIT                           = 0x10000
	WNOZOMBIE                         = 0x20000
	WOPTSCHECKED                      = 0x40000
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
	EAUTH           = Errno(0x50)
	EBADF           = Errno(0x9)
	EBADMSG         = Errno(0x58)
	EBADRPC         = Errno(0x48)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x57)
	ECHILD          = Errno(0xa)
	ECONNABORTED    = Errno(0x35)
	ECONNREFUSED    = Errno(0x3d)
	ECONNRESET      = Errno(0x36)
	EDEADLK         = Errno(0xb)
	EDESTADDRREQ    = Errno(0x27)
	EDOM            = Errno(0x21)
	EDQUOT          = Errno(0x45)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EFTYPE          = Errno(0x4f)
	EHOSTDOWN       = Errno(0x40)
	EHOSTUNREACH    = Errno(0x41)
	EIDRM           = Errno(0x52)
	EILSEQ          = Errno(0x55)
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
	EMULTIHOP       = Errno(0x5e)
	ENAMETOOLONG    = Errno(0x3f)
	ENEEDAUTH       = Errno(0x51)
	ENETDOWN        = Errno(0x32)
	ENETRESET       = Errno(0x34)
	ENETUNREACH     = Errno(0x33)
	ENFILE          = Errno(0x17)
	ENOATTR         = Errno(0x5d)
	ENOBUFS         = Errno(0x37)
	ENODATA         = Errno(0x59)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOLCK          = Errno(0x4d)
	ENOLINK         = Errno(0x5f)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x53)
	ENOPROTOOPT     = Errno(0x2a)
	ENOSPC          = Errno(0x1c)
	ENOSR           = Errno(0x5a)
	ENOSTR          = Errno(0x5b)
	ENOSYS          = Errno(0x4e)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x39)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x42)
	ENOTSOCK        = Errno(0x26)
	ENOTSUP         = Errno(0x56)
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
	EPROTO          = Errno(0x60)
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
	ETIME           = Errno(0x5c)
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
	SIGPWR    = Signal(0x20)
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
	2
"""




```