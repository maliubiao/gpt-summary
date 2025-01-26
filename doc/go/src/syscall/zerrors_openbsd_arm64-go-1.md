Response:
The user wants me to summarize the functionality of the provided Go code snippet, which is part of the `syscall` package for OpenBSD on the ARM64 architecture. This part seems to define various constants related to system calls, specifically:

1. **Network protocols:**  Constants starting with `IPPROTO_`.
2. **IPv6 socket options:** Constants starting with `IPV6_`.
3. **IP socket options:** Constants starting with `IP_`.
4. **Terminal I/O control:** Constants like `ISIG`, `ISTRIP`, `IXON`, etc.
5. **File locking:** Constants like `LOCK_EX`, `LOCK_SH`.
6. **Memory mapping:** Constants starting with `MAP_`.
7. **Message flags:** Constants starting with `MSG_`.
8. **Memory synchronization:** Constants starting with `MS_`.
9. **Maximum name length:** `NAME_MAX`.
10. **Routing table events:** Constants starting with `NET_RT_`.
11. **File notification events:** Constants starting with `NOTE_`.
12. **Terminal output control:** Constants like `OCRNL`, `ONLCR`.
13. **File open flags:** Constants starting with `O_`.
14. **Terminal parity options:** Constants like `PARENB`, `PARODD`.
15. **Pseudo-file system flags:** `PF_FLUSH`.
16. **Process priority levels:** Constants starting with `PRIO_`.
17. **Memory protection options:** Constants starting with `PROT_`.
18. **Resource limits:** Constants starting with `RLIMIT_`.
19. **Routing message attributes:** Constants starting with `RTAX_`.
20. **Routing attributes:** Constants starting with `RTA_`.
21. **Routing flags:** Constants starting with `RTF_`.
22. **Routing message types:** Constants starting with `RTM_`.
23. **Routing table values:** Constants starting with `RTV_`.
24. **Routing table ID:** Constants starting with `RT_TABLEID_`.
25. **Resource usage options:** Constants starting with `RUSAGE_`.
26. **Socket control message levels:** `SCM_RIGHTS`, `SCM_TIMESTAMP`.
27. **Socket shutdown options:** Constants starting with `SHUT_`.
28. **Socket I/O control commands:** Constants starting with `SIOC`.
29. **Socket types:** Constants starting with `SOCK_`.
30. **Socket options:** Constants starting with `SOL_SOCKET` and `SO_`.
31. **Terminal control flow:** Constants starting with `TCIFLUSH`, `TCOFLUSH`, `TCIOFLUSH`.
32. **TCP options:** Constants starting with `TCP_`.
33. **Terminal control actions:** Constants starting with `TCSAFLUSH`.
34. **Terminal I/O control commands (ioctl):** Constants starting with `TIOC`.
35. **Terminal output control:** `TOSTOP`.
36. **Terminal special characters:** Constants starting with `V`.
37. **Wait options:** `WALTSIG`, `WCONTINUED`, `WCOREFLAG`, `WNOHANG`, `WUNTRACED`.
38. **Error numbers:** Constants starting with `E`.
39. **Signal numbers:** Constants starting with `SIG`.
40. **Error message table:** The `errors` array.
41. **Signal names:** Implicitly through the `Signal` type.

Essentially, this file provides a comprehensive list of numerical constants that represent various system-level entities and options on OpenBSD for ARM64. These constants are used by Go programs when interacting with the operating system kernel through system calls.
这是 `go/src/syscall/zerrors_openbsd_arm64.go` 文件的一部分，它定义了在 OpenBSD ARM64 架构下的系统调用相关的常量。

**它的主要功能是定义了一系列常量，这些常量代表了操作系统级别的各种值，例如：**

* **网络协议类型 (IPPROTO_...)**：定义了各种网络协议的数字标识符，如 TCP、UDP、ICMP 等。
* **IP 和 IPv6 协议的选项 (IP_..., IPV6_...)**：定义了可以设置在 IP 和 IPv6 套接字上的各种选项，例如是否允许分片、多播设置、接收选项等。
* **终端 I/O 控制常量 (ISIG, IXON, OPOST, PARENB, VEOF 等)**：定义了用于控制终端输入输出行为的各种标志和特殊字符。
* **文件锁定常量 (LOCK_EX, LOCK_SH)**：定义了用于文件锁定的类型，如排他锁和共享锁。
* **内存映射常量 (MAP_ANON, MAP_PRIVATE, PROT_READ, PROT_WRITE 等)**：定义了在使用 `mmap` 系统调用进行内存映射时可以使用的各种选项和保护标志。
* **消息传递常量 (MSG_DONTROUTE, MSG_OOB, SCM_RIGHTS 等)**：定义了在发送和接收消息时可以使用的各种标志和控制消息类型。
* **文件系统相关的常量 (O_RDONLY, O_CREAT, NAME_MAX 等)**：定义了用于文件操作的各种标志，以及文件名的最大长度等。
* **进程优先级常量 (PRIO_PGRP, PRIO_USER)**：定义了设置进程优先级的不同级别。
* **资源限制常量 (RLIMIT_CPU, RLIMIT_NOFILE)**：定义了可以设置的各种资源限制类型。
* **路由相关的常量 (RTF_UP, RTA_DST, RTM_ADD)**：定义了与网络路由相关的各种标志、属性和消息类型。
* **套接字相关的常量 (SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR)**：定义了套接字类型和可以设置在套接字上的各种选项。
* **错误码常量 (EACCES, ENOENT, ETIMEDOUT 等)**：定义了各种系统调用可能返回的错误码。
* **信号常量 (SIGINT, SIGKILL, SIGSEGV 等)**：定义了操作系统可以发送给进程的各种信号。

**归纳一下，这个文件的功能是提供了一个在 Go 语言中访问 OpenBSD ARM64 操作系统底层功能的桥梁，它将底层的数字常量定义为 Go 语言中的常量，使得 Go 程序能够以类型安全的方式与操作系统进行交互。** 这些常量通常被用于 `syscall` 包中的函数调用，以便进行文件操作、网络编程、进程控制等系统级任务。

**这个文件是 `zerrors_openbsd_arm64.go` 的一部分，通常由 `go generate` 工具自动生成，以确保它与 OpenBSD ARM64 系统的头文件保持同步。** 这意味着开发者通常不需要手动修改这个文件。

在 Go 语言中，这些常量会被用于调用 `syscall` 包提供的函数。例如，在进行网络编程时，你可以使用 `syscall.SOCK_STREAM` 来创建一个 TCP 套接字，使用 `syscall.IPPROTO_TCP` 来指定 TCP 协议。

由于这是第 2 部分，且没有提供上下文，我只能根据你提供的代码片段进行分析。  这部分代码主要集中在定义各种系统级的常量，这些常量是构建更高级抽象的基础。

Prompt: 
```
这是路径为go/src/syscall/zerrors_openbsd_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
  = 0x3b
	IPPROTO_PFSYNC                    = 0xf0
	IPPROTO_PIM                       = 0x67
	IPPROTO_PUP                       = 0xc
	IPPROTO_RAW                       = 0xff
	IPPROTO_ROUTING                   = 0x2b
	IPPROTO_RSVP                      = 0x2e
	IPPROTO_TCP                       = 0x6
	IPPROTO_TP                        = 0x1d
	IPPROTO_UDP                       = 0x11
	IPV6_AUTH_LEVEL                   = 0x35
	IPV6_AUTOFLOWLABEL                = 0x3b
	IPV6_CHECKSUM                     = 0x1a
	IPV6_DEFAULT_MULTICAST_HOPS       = 0x1
	IPV6_DEFAULT_MULTICAST_LOOP       = 0x1
	IPV6_DEFHLIM                      = 0x40
	IPV6_DONTFRAG                     = 0x3e
	IPV6_DSTOPTS                      = 0x32
	IPV6_ESP_NETWORK_LEVEL            = 0x37
	IPV6_ESP_TRANS_LEVEL              = 0x36
	IPV6_FAITH                        = 0x1d
	IPV6_FLOWINFO_MASK                = 0xffffff0f
	IPV6_FLOWLABEL_MASK               = 0xffff0f00
	IPV6_FRAGTTL                      = 0x78
	IPV6_HLIMDEC                      = 0x1
	IPV6_HOPLIMIT                     = 0x2f
	IPV6_HOPOPTS                      = 0x31
	IPV6_IPCOMP_LEVEL                 = 0x3c
	IPV6_JOIN_GROUP                   = 0xc
	IPV6_LEAVE_GROUP                  = 0xd
	IPV6_MAXHLIM                      = 0xff
	IPV6_MAXPACKET                    = 0xffff
	IPV6_MINHOPCOUNT                  = 0x41
	IPV6_MMTU                         = 0x500
	IPV6_MULTICAST_HOPS               = 0xa
	IPV6_MULTICAST_IF                 = 0x9
	IPV6_MULTICAST_LOOP               = 0xb
	IPV6_NEXTHOP                      = 0x30
	IPV6_OPTIONS                      = 0x1
	IPV6_PATHMTU                      = 0x2c
	IPV6_PIPEX                        = 0x3f
	IPV6_PKTINFO                      = 0x2e
	IPV6_PORTRANGE                    = 0xe
	IPV6_PORTRANGE_DEFAULT            = 0x0
	IPV6_PORTRANGE_HIGH               = 0x1
	IPV6_PORTRANGE_LOW                = 0x2
	IPV6_RECVDSTOPTS                  = 0x28
	IPV6_RECVDSTPORT                  = 0x40
	IPV6_RECVHOPLIMIT                 = 0x25
	IPV6_RECVHOPOPTS                  = 0x27
	IPV6_RECVPATHMTU                  = 0x2b
	IPV6_RECVPKTINFO                  = 0x24
	IPV6_RECVRTHDR                    = 0x26
	IPV6_RECVTCLASS                   = 0x39
	IPV6_RTABLE                       = 0x1021
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
	IP_AUTH_LEVEL                     = 0x14
	IP_DEFAULT_MULTICAST_LOOP         = 0x1
	IP_DEFAULT_MULTICAST_TTL          = 0x1
	IP_DF                             = 0x4000
	IP_DROP_MEMBERSHIP                = 0xd
	IP_ESP_NETWORK_LEVEL              = 0x16
	IP_ESP_TRANS_LEVEL                = 0x15
	IP_HDRINCL                        = 0x2
	IP_IPCOMP_LEVEL                   = 0x1d
	IP_IPDEFTTL                       = 0x25
	IP_IPSECFLOWINFO                  = 0x24
	IP_IPSEC_LOCAL_AUTH               = 0x1b
	IP_IPSEC_LOCAL_CRED               = 0x19
	IP_IPSEC_LOCAL_ID                 = 0x17
	IP_IPSEC_REMOTE_AUTH              = 0x1c
	IP_IPSEC_REMOTE_CRED              = 0x1a
	IP_IPSEC_REMOTE_ID                = 0x18
	IP_MAXPACKET                      = 0xffff
	IP_MAX_MEMBERSHIPS                = 0xfff
	IP_MF                             = 0x2000
	IP_MINTTL                         = 0x20
	IP_MIN_MEMBERSHIPS                = 0xf
	IP_MSS                            = 0x240
	IP_MULTICAST_IF                   = 0x9
	IP_MULTICAST_LOOP                 = 0xb
	IP_MULTICAST_TTL                  = 0xa
	IP_OFFMASK                        = 0x1fff
	IP_OPTIONS                        = 0x1
	IP_PIPEX                          = 0x22
	IP_PORTRANGE                      = 0x13
	IP_PORTRANGE_DEFAULT              = 0x0
	IP_PORTRANGE_HIGH                 = 0x1
	IP_PORTRANGE_LOW                  = 0x2
	IP_RECVDSTADDR                    = 0x7
	IP_RECVDSTPORT                    = 0x21
	IP_RECVIF                         = 0x1e
	IP_RECVOPTS                       = 0x5
	IP_RECVRETOPTS                    = 0x6
	IP_RECVRTABLE                     = 0x23
	IP_RECVTTL                        = 0x1f
	IP_RETOPTS                        = 0x8
	IP_RF                             = 0x8000
	IP_RTABLE                         = 0x1021
	IP_SENDSRCADDR                    = 0x7
	IP_TOS                            = 0x3
	IP_TTL                            = 0x4
	ISIG                              = 0x80
	ISTRIP                            = 0x20
	IXANY                             = 0x800
	IXOFF                             = 0x400
	IXON                              = 0x200
	LCNT_OVERLOAD_FLUSH               = 0x6
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
	MAP_ANON                          = 0x1000
	MAP_ANONYMOUS                     = 0x1000
	MAP_CONCEAL                       = 0x8000
	MAP_COPY                          = 0x2
	MAP_FILE                          = 0x0
	MAP_FIXED                         = 0x10
	MAP_FLAGMASK                      = 0xfff7
	MAP_HASSEMAPHORE                  = 0x0
	MAP_INHERIT                       = 0x0
	MAP_INHERIT_COPY                  = 0x1
	MAP_INHERIT_NONE                  = 0x2
	MAP_INHERIT_SHARE                 = 0x0
	MAP_INHERIT_ZERO                  = 0x3
	MAP_NOEXTEND                      = 0x0
	MAP_NORESERVE                     = 0x0
	MAP_PRIVATE                       = 0x2
	MAP_RENAME                        = 0x0
	MAP_SHARED                        = 0x1
	MAP_STACK                         = 0x4000
	MAP_TRYFIXED                      = 0x0
	MCL_CURRENT                       = 0x1
	MCL_FUTURE                        = 0x2
	MSG_BCAST                         = 0x100
	MSG_CMSG_CLOEXEC                  = 0x800
	MSG_CTRUNC                        = 0x20
	MSG_DONTROUTE                     = 0x4
	MSG_DONTWAIT                      = 0x80
	MSG_EOR                           = 0x8
	MSG_MCAST                         = 0x200
	MSG_NOSIGNAL                      = 0x400
	MSG_OOB                           = 0x1
	MSG_PEEK                          = 0x2
	MSG_TRUNC                         = 0x10
	MSG_WAITALL                       = 0x40
	MS_ASYNC                          = 0x1
	MS_INVALIDATE                     = 0x4
	MS_SYNC                           = 0x2
	NAME_MAX                          = 0xff
	NET_RT_DUMP                       = 0x1
	NET_RT_FLAGS                      = 0x2
	NET_RT_IFLIST                     = 0x3
	NET_RT_IFNAMES                    = 0x6
	NET_RT_MAXID                      = 0x7
	NET_RT_STATS                      = 0x4
	NET_RT_TABLE                      = 0x5
	NOFLSH                            = 0x80000000
	NOTE_ATTRIB                       = 0x8
	NOTE_CHANGE                       = 0x1
	NOTE_CHILD                        = 0x4
	NOTE_DELETE                       = 0x1
	NOTE_EOF                          = 0x2
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
	NOTE_TRUNCATE                     = 0x80
	NOTE_WRITE                        = 0x2
	OCRNL                             = 0x10
	ONLCR                             = 0x2
	ONLRET                            = 0x80
	ONOCR                             = 0x40
	ONOEOT                            = 0x8
	OPOST                             = 0x1
	O_ACCMODE                         = 0x3
	O_APPEND                          = 0x8
	O_ASYNC                           = 0x40
	O_CLOEXEC                         = 0x10000
	O_CREAT                           = 0x200
	O_DIRECTORY                       = 0x20000
	O_DSYNC                           = 0x80
	O_EXCL                            = 0x800
	O_EXLOCK                          = 0x20
	O_FSYNC                           = 0x80
	O_NDELAY                          = 0x4
	O_NOCTTY                          = 0x8000
	O_NOFOLLOW                        = 0x100
	O_NONBLOCK                        = 0x4
	O_RDONLY                          = 0x0
	O_RDWR                            = 0x2
	O_RSYNC                           = 0x80
	O_SHLOCK                          = 0x10
	O_SYNC                            = 0x80
	O_TRUNC                           = 0x400
	O_WRONLY                          = 0x1
	PARENB                            = 0x1000
	PARMRK                            = 0x8
	PARODD                            = 0x2000
	PENDIN                            = 0x20000000
	PF_FLUSH                          = 0x1
	PRIO_PGRP                         = 0x1
	PRIO_PROCESS                      = 0x0
	PRIO_USER                         = 0x2
	PROT_EXEC                         = 0x4
	PROT_NONE                         = 0x0
	PROT_READ                         = 0x1
	PROT_WRITE                        = 0x2
	RLIMIT_CORE                       = 0x4
	RLIMIT_CPU                        = 0x0
	RLIMIT_DATA                       = 0x2
	RLIMIT_FSIZE                      = 0x1
	RLIMIT_NOFILE                     = 0x8
	RLIMIT_STACK                      = 0x3
	RLIM_INFINITY                     = 0x7fffffffffffffff
	RTAX_AUTHOR                       = 0x6
	RTAX_BFD                          = 0xb
	RTAX_BRD                          = 0x7
	RTAX_DNS                          = 0xc
	RTAX_DST                          = 0x0
	RTAX_GATEWAY                      = 0x1
	RTAX_GENMASK                      = 0x3
	RTAX_IFA                          = 0x5
	RTAX_IFP                          = 0x4
	RTAX_LABEL                        = 0xa
	RTAX_MAX                          = 0xf
	RTAX_NETMASK                      = 0x2
	RTAX_SEARCH                       = 0xe
	RTAX_SRC                          = 0x8
	RTAX_SRCMASK                      = 0x9
	RTAX_STATIC                       = 0xd
	RTA_AUTHOR                        = 0x40
	RTA_BFD                           = 0x800
	RTA_BRD                           = 0x80
	RTA_DNS                           = 0x1000
	RTA_DST                           = 0x1
	RTA_GATEWAY                       = 0x2
	RTA_GENMASK                       = 0x8
	RTA_IFA                           = 0x20
	RTA_IFP                           = 0x10
	RTA_LABEL                         = 0x400
	RTA_NETMASK                       = 0x4
	RTA_SEARCH                        = 0x4000
	RTA_SRC                           = 0x100
	RTA_SRCMASK                       = 0x200
	RTA_STATIC                        = 0x2000
	RTF_ANNOUNCE                      = 0x4000
	RTF_BFD                           = 0x1000000
	RTF_BLACKHOLE                     = 0x1000
	RTF_BROADCAST                     = 0x400000
	RTF_CACHED                        = 0x20000
	RTF_CLONED                        = 0x10000
	RTF_CLONING                       = 0x100
	RTF_CONNECTED                     = 0x800000
	RTF_DONE                          = 0x40
	RTF_DYNAMIC                       = 0x10
	RTF_FMASK                         = 0x110fc08
	RTF_GATEWAY                       = 0x2
	RTF_HOST                          = 0x4
	RTF_LLINFO                        = 0x400
	RTF_LOCAL                         = 0x200000
	RTF_MODIFIED                      = 0x20
	RTF_MPATH                         = 0x40000
	RTF_MPLS                          = 0x100000
	RTF_MULTICAST                     = 0x200
	RTF_PERMANENT_ARP                 = 0x2000
	RTF_PROTO1                        = 0x8000
	RTF_PROTO2                        = 0x4000
	RTF_PROTO3                        = 0x2000
	RTF_REJECT                        = 0x8
	RTF_STATIC                        = 0x800
	RTF_UP                            = 0x1
	RTF_USETRAILERS                   = 0x8000
	RTM_80211INFO                     = 0x15
	RTM_ADD                           = 0x1
	RTM_BFD                           = 0x12
	RTM_CHANGE                        = 0x3
	RTM_CHGADDRATTR                   = 0x14
	RTM_DELADDR                       = 0xd
	RTM_DELETE                        = 0x2
	RTM_DESYNC                        = 0x10
	RTM_GET                           = 0x4
	RTM_IFANNOUNCE                    = 0xf
	RTM_IFINFO                        = 0xe
	RTM_INVALIDATE                    = 0x11
	RTM_LOSING                        = 0x5
	RTM_MAXSIZE                       = 0x800
	RTM_MISS                          = 0x7
	RTM_NEWADDR                       = 0xc
	RTM_PROPOSAL                      = 0x13
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
	RT_TABLEID_BITS                   = 0x8
	RT_TABLEID_MASK                   = 0xff
	RT_TABLEID_MAX                    = 0xff
	RUSAGE_CHILDREN                   = -0x1
	RUSAGE_SELF                       = 0x0
	RUSAGE_THREAD                     = 0x1
	SCM_RIGHTS                        = 0x1
	SCM_TIMESTAMP                     = 0x4
	SHUT_RD                           = 0x0
	SHUT_RDWR                         = 0x2
	SHUT_WR                           = 0x1
	SIOCADDMULTI                      = 0x80206931
	SIOCAIFADDR                       = 0x8040691a
	SIOCAIFGROUP                      = 0x80286987
	SIOCATMARK                        = 0x40047307
	SIOCBRDGADD                       = 0x8060693c
	SIOCBRDGADDL                      = 0x80606949
	SIOCBRDGADDS                      = 0x80606941
	SIOCBRDGARL                       = 0x808c694d
	SIOCBRDGDADDR                     = 0x81286947
	SIOCBRDGDEL                       = 0x8060693d
	SIOCBRDGDELS                      = 0x80606942
	SIOCBRDGFLUSH                     = 0x80606948
	SIOCBRDGFRL                       = 0x808c694e
	SIOCBRDGGCACHE                    = 0xc0186941
	SIOCBRDGGFD                       = 0xc0186952
	SIOCBRDGGHT                       = 0xc0186951
	SIOCBRDGGIFFLGS                   = 0xc060693e
	SIOCBRDGGMA                       = 0xc0186953
	SIOCBRDGGPARAM                    = 0xc0406958
	SIOCBRDGGPRI                      = 0xc0186950
	SIOCBRDGGRL                       = 0xc030694f
	SIOCBRDGGTO                       = 0xc0186946
	SIOCBRDGIFS                       = 0xc0606942
	SIOCBRDGRTS                       = 0xc0206943
	SIOCBRDGSADDR                     = 0xc1286944
	SIOCBRDGSCACHE                    = 0x80186940
	SIOCBRDGSFD                       = 0x80186952
	SIOCBRDGSHT                       = 0x80186951
	SIOCBRDGSIFCOST                   = 0x80606955
	SIOCBRDGSIFFLGS                   = 0x8060693f
	SIOCBRDGSIFPRIO                   = 0x80606954
	SIOCBRDGSIFPROT                   = 0x8060694a
	SIOCBRDGSMA                       = 0x80186953
	SIOCBRDGSPRI                      = 0x80186950
	SIOCBRDGSPROTO                    = 0x8018695a
	SIOCBRDGSTO                       = 0x80186945
	SIOCBRDGSTXHC                     = 0x80186959
	SIOCDELLABEL                      = 0x80206997
	SIOCDELMULTI                      = 0x80206932
	SIOCDIFADDR                       = 0x80206919
	SIOCDIFGROUP                      = 0x80286989
	SIOCDIFPARENT                     = 0x802069b4
	SIOCDIFPHYADDR                    = 0x80206949
	SIOCDPWE3NEIGHBOR                 = 0x802069de
	SIOCDVNETID                       = 0x802069af
	SIOCGETKALIVE                     = 0xc01869a4
	SIOCGETLABEL                      = 0x8020699a
	SIOCGETMPWCFG                     = 0xc02069ae
	SIOCGETPFLOW                      = 0xc02069fe
	SIOCGETPFSYNC                     = 0xc02069f8
	SIOCGETSGCNT                      = 0xc0207534
	SIOCGETVIFCNT                     = 0xc0287533
	SIOCGETVLAN                       = 0xc0206990
	SIOCGIFADDR                       = 0xc0206921
	SIOCGIFBRDADDR                    = 0xc0206923
	SIOCGIFCONF                       = 0xc0106924
	SIOCGIFDATA                       = 0xc020691b
	SIOCGIFDESCR                      = 0xc0206981
	SIOCGIFDSTADDR                    = 0xc0206922
	SIOCGIFFLAGS                      = 0xc0206911
	SIOCGIFGATTR                      = 0xc028698b
	SIOCGIFGENERIC                    = 0xc020693a
	SIOCGIFGLIST                      = 0xc028698d
	SIOCGIFGMEMB                      = 0xc028698a
	SIOCGIFGROUP                      = 0xc0286988
	SIOCGIFHARDMTU                    = 0xc02069a5
	SIOCGIFLLPRIO                     = 0xc02069b6
	SIOCGIFMEDIA                      = 0xc0406938
	SIOCGIFMETRIC                     = 0xc0206917
	SIOCGIFMTU                        = 0xc020697e
	SIOCGIFNETMASK                    = 0xc0206925
	SIOCGIFPAIR                       = 0xc02069b1
	SIOCGIFPARENT                     = 0xc02069b3
	SIOCGIFPRIORITY                   = 0xc020699c
	SIOCGIFRDOMAIN                    = 0xc02069a0
	SIOCGIFRTLABEL                    = 0xc0206983
	SIOCGIFRXR                        = 0x802069aa
	SIOCGIFSFFPAGE                    = 0xc1126939
	SIOCGIFXFLAGS                     = 0xc020699e
	SIOCGLIFPHYADDR                   = 0xc218694b
	SIOCGLIFPHYDF                     = 0xc02069c2
	SIOCGLIFPHYECN                    = 0xc02069c8
	SIOCGLIFPHYRTABLE                 = 0xc02069a2
	SIOCGLIFPHYTTL                    = 0xc02069a9
	SIOCGPGRP                         = 0x40047309
	SIOCGPWE3                         = 0xc0206998
	SIOCGPWE3CTRLWORD                 = 0xc02069dc
	SIOCGPWE3FAT                      = 0xc02069dd
	SIOCGPWE3NEIGHBOR                 = 0xc21869de
	SIOCGSPPPPARAMS                   = 0xc0206994
	SIOCGTXHPRIO                      = 0xc02069c6
	SIOCGUMBINFO                      = 0xc02069be
	SIOCGUMBPARAM                     = 0xc02069c0
	SIOCGVH                           = 0xc02069f6
	SIOCGVNETFLOWID                   = 0xc02069c4
	SIOCGVNETID                       = 0xc02069a7
	SIOCIFAFATTACH                    = 0x801169ab
	SIOCIFAFDETACH                    = 0x801169ac
	SIOCIFCREATE                      = 0x8020697a
	SIOCIFDESTROY                     = 0x80206979
	SIOCIFGCLONERS                    = 0xc0106978
	SIOCSETKALIVE                     = 0x801869a3
	SIOCSETLABEL                      = 0x80206999
	SIOCSETMPWCFG                     = 0x802069ad
	SIOCSETPFLOW                      = 0x802069fd
	SIOCSETPFSYNC                     = 0x802069f7
	SIOCSETVLAN                       = 0x8020698f
	SIOCSIFADDR                       = 0x8020690c
	SIOCSIFBRDADDR                    = 0x80206913
	SIOCSIFDESCR                      = 0x80206980
	SIOCSIFDSTADDR                    = 0x8020690e
	SIOCSIFFLAGS                      = 0x80206910
	SIOCSIFGATTR                      = 0x8028698c
	SIOCSIFGENERIC                    = 0x80206939
	SIOCSIFLLADDR                     = 0x8020691f
	SIOCSIFLLPRIO                     = 0x802069b5
	SIOCSIFMEDIA                      = 0xc0206937
	SIOCSIFMETRIC                     = 0x80206918
	SIOCSIFMTU                        = 0x8020697f
	SIOCSIFNETMASK                    = 0x80206916
	SIOCSIFPAIR                       = 0x802069b0
	SIOCSIFPARENT                     = 0x802069b2
	SIOCSIFPRIORITY                   = 0x8020699b
	SIOCSIFRDOMAIN                    = 0x8020699f
	SIOCSIFRTLABEL                    = 0x80206982
	SIOCSIFXFLAGS                     = 0x8020699d
	SIOCSLIFPHYADDR                   = 0x8218694a
	SIOCSLIFPHYDF                     = 0x802069c1
	SIOCSLIFPHYECN                    = 0x802069c7
	SIOCSLIFPHYRTABLE                 = 0x802069a1
	SIOCSLIFPHYTTL                    = 0x802069a8
	SIOCSPGRP                         = 0x80047308
	SIOCSPWE3CTRLWORD                 = 0x802069dc
	SIOCSPWE3FAT                      = 0x802069dd
	SIOCSPWE3NEIGHBOR                 = 0x821869de
	SIOCSSPPPPARAMS                   = 0x80206993
	SIOCSTXHPRIO                      = 0x802069c5
	SIOCSUMBPARAM                     = 0x802069bf
	SIOCSVH                           = 0xc02069f5
	SIOCSVNETFLOWID                   = 0x802069c3
	SIOCSVNETID                       = 0x802069a6
	SIOCSWGDPID                       = 0xc018695b
	SIOCSWGMAXFLOW                    = 0xc0186960
	SIOCSWGMAXGROUP                   = 0xc018695d
	SIOCSWSDPID                       = 0x8018695c
	SIOCSWSPORTNO                     = 0xc060695f
	SOCK_CLOEXEC                      = 0x8000
	SOCK_DGRAM                        = 0x2
	SOCK_DNS                          = 0x1000
	SOCK_NONBLOCK                     = 0x4000
	SOCK_RAW                          = 0x3
	SOCK_RDM                          = 0x4
	SOCK_SEQPACKET                    = 0x5
	SOCK_STREAM                       = 0x1
	SOL_SOCKET                        = 0xffff
	SOMAXCONN                         = 0x80
	SO_ACCEPTCONN                     = 0x2
	SO_BINDANY                        = 0x1000
	SO_BROADCAST                      = 0x20
	SO_DEBUG                          = 0x1
	SO_DONTROUTE                      = 0x10
	SO_ERROR                          = 0x1007
	SO_KEEPALIVE                      = 0x8
	SO_LINGER                         = 0x80
	SO_NETPROC                        = 0x1020
	SO_OOBINLINE                      = 0x100
	SO_PEERCRED                       = 0x1022
	SO_RCVBUF                         = 0x1002
	SO_RCVLOWAT                       = 0x1004
	SO_RCVTIMEO                       = 0x1006
	SO_REUSEADDR                      = 0x4
	SO_REUSEPORT                      = 0x200
	SO_RTABLE                         = 0x1021
	SO_SNDBUF                         = 0x1001
	SO_SNDLOWAT                       = 0x1003
	SO_SNDTIMEO                       = 0x1005
	SO_SPLICE                         = 0x1023
	SO_TIMESTAMP                      = 0x800
	SO_TYPE                           = 0x1008
	SO_USELOOPBACK                    = 0x40
	SO_ZEROIZE                        = 0x2000
	TCIFLUSH                          = 0x1
	TCIOFLUSH                         = 0x3
	TCOFLUSH                          = 0x2
	TCP_MAXBURST                      = 0x4
	TCP_MAXSEG                        = 0x2
	TCP_MAXWIN                        = 0xffff
	TCP_MAX_SACK                      = 0x3
	TCP_MAX_WINSHIFT                  = 0xe
	TCP_MD5SIG                        = 0x4
	TCP_MSS                           = 0x200
	TCP_NODELAY                       = 0x1
	TCP_NOPUSH                        = 0x10
	TCP_SACK_ENABLE                   = 0x8
	TCSAFLUSH                         = 0x2
	TIOCCBRK                          = 0x2000747a
	TIOCCDTR                          = 0x20007478
	TIOCCHKVERAUTH                    = 0x2000741e
	TIOCCLRVERAUTH                    = 0x2000741d
	TIOCCONS                          = 0x80047462
	TIOCDRAIN                         = 0x2000745e
	TIOCEXCL                          = 0x2000740d
	TIOCEXT                           = 0x80047460
	TIOCFLAG_CLOCAL                   = 0x2
	TIOCFLAG_CRTSCTS                  = 0x4
	TIOCFLAG_MDMBUF                   = 0x8
	TIOCFLAG_PPS                      = 0x10
	TIOCFLAG_SOFTCAR                  = 0x1
	TIOCFLUSH                         = 0x80047410
	TIOCGETA                          = 0x402c7413
	TIOCGETD                          = 0x4004741a
	TIOCGFLAGS                        = 0x4004745d
	TIOCGPGRP                         = 0x40047477
	TIOCGSID                          = 0x40047463
	TIOCGTSTAMP                       = 0x4010745b
	TIOCGWINSZ                        = 0x40087468
	TIOCMBIC                          = 0x8004746b
	TIOCMBIS                          = 0x8004746c
	TIOCMGET                          = 0x4004746a
	TIOCMODG                          = 0x4004746a
	TIOCMODS                          = 0x8004746d
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
	TIOCSDTR                          = 0x20007479
	TIOCSETA                          = 0x802c7414
	TIOCSETAF                         = 0x802c7416
	TIOCSETAW                         = 0x802c7415
	TIOCSETD                          = 0x8004741b
	TIOCSETVERAUTH                    = 0x8004741c
	TIOCSFLAGS                        = 0x8004745c
	TIOCSIG                           = 0x8004745f
	TIOCSPGRP                         = 0x80047476
	TIOCSTART                         = 0x2000746e
	TIOCSTAT                          = 0x20007465
	TIOCSTOP                          = 0x2000746f
	TIOCSTSTAMP                       = 0x8008745a
	TIOCSWINSZ                        = 0x80087467
	TIOCUCNTL                         = 0x80047466
	TIOCUCNTL_CBRK                    = 0x7a
	TIOCUCNTL_SBRK                    = 0x7b
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
	WALTSIG                           = 0x4
	WCONTINUED                        = 0x8
	WCOREFLAG                         = 0x80
	WNOHANG                           = 0x1
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
	EBADMSG         = Errno(0x5c)
	EBADRPC         = Errno(0x48)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x58)
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
	EIDRM           = Errno(0x59)
	EILSEQ          = Errno(0x54)
	EINPROGRESS     = Errno(0x24)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EIPSEC          = Errno(0x52)
	EISCONN         = Errno(0x38)
	EISDIR          = Errno(0x15)
	ELAST           = Errno(0x5f)
	ELOOP           = Errno(0x3e)
	EMEDIUMTYPE     = Errno(0x56)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x28)
	ENAMETOOLONG    = Errno(0x3f)
	ENEEDAUTH       = Errno(0x51)
	ENETDOWN        = Errno(0x32)
	ENETRESET       = Errno(0x34)
	ENETUNREACH     = Errno(0x33)
	ENFILE          = Errno(0x17)
	ENOATTR         = Errno(0x53)
	ENOBUFS         = Errno(0x37)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOLCK          = Errno(0x4d)
	ENOMEDIUM       = Errno(0x55)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x5a)
	ENOPROTOOPT     = Errno(0x2a)
	ENOSPC          = Errno(0x1c)
	ENOSYS          = Errno(0x4e)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x39)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x42)
	ENOTRECOVERABLE = Errno(0x5d)
	ENOTSOCK        = Errno(0x26)
	ENOTSUP         = Errno(0x5b)
	ENOTTY          = Errno(0x19)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x2d)
	EOVERFLOW       = Errno(0x57)
	EOWNERDEAD      = Errno(0x5e)
	EPERM           = Errno(0x1)
	EPFNOSUPPORT    = Errno(0x2e)
	EPIPE           = Errno(0x20)
	EPROCLIM        = Errno(0x43)
	EPROCUNAVAIL    = Errno(0x4c)
	EPROGMISMATCH   = Errno(0x4b)
	EPROGUNAVAIL    = Errno(0x4a)
	EPROTO          = Errno(0x5f)
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
	45: 
"""




```