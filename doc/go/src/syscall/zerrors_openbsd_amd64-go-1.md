Response:
The user wants to understand the purpose of the provided Go code snippet, which is part of the `syscall` package for OpenBSD on the AMD64 architecture. This file seems to define constants related to system calls, errors, and signals.

**Plan:**
1. Summarize the general purpose of the code.
2. Identify the main categories of constants defined in the file.
3. Infer the Go language features being implemented based on the content.
4. Provide a Go code example that uses these constants.
5. Explain how the constants might be used in system calls.
6. Mention potential pitfalls for users.
这是 `go/src/syscall/zerrors_openbsd_amd64.go` 文件的一部分，它定义了一系列用于 OpenBSD 操作系统在 AMD64 架构下的系统调用相关的常量、错误码和信号。

**功能归纳:**

该文件定义了在 OpenBSD AMD64 平台上进行底层系统操作时需要用到的各种常量。这些常量主要分为以下几类：

1. **网络相关的常量 (以 `IP_` 和 `IPV6_` 开头):**  定义了 IP 和 IPv6 协议相关的选项、标志和控制信息，例如设置 IP 报文头的字段、多播选项、端口范围等等。
2. **文件操作相关的常量 (以 `O_`, `LOCK_`, `MADV_`, `MAP_`, `MCL_` 开头):** 定义了文件打开模式、文件锁类型、内存映射选项、内存锁定选项等。
3. **消息传递相关的常量 (以 `MSG_` 开头):** 定义了在发送和接收消息时可以使用的标志。
4. **路由相关的常量 (以 `NET_RT_`, `RTAX_`, `RTA_`, `RTF_`, `RTM_`, `RTV_` 开头):** 定义了路由表操作、路由属性、路由标志和路由消息类型。
5. **ioctl 系统调用相关的常量 (以 `SIOC` 开头):** 定义了用于设备控制的 ioctl 系统调用的各种命令，包括网络接口配置、桥接配置、VLAN 配置等。
6. **Socket 相关的常量 (以 `SOCK_`, `SOL_`, `SOMAXCONN`, `SO_` 开头):** 定义了 socket 类型、socket 选项和连接相关的常量。
7. **TCP 相关的常量 (以 `TCP_` 开头):** 定义了 TCP 协议相关的选项，例如最大报文段大小、Nagle 算法控制等。
8. **终端控制相关的常量 (以 `TC`, `TIOCC`, `TIOCD`, `TIOCG`, `TIOCTL`, `TIOCM`, `TIOCS`, `TIOCU`, `TOSTOP`, `V` 开头):** 定义了终端的各种控制参数，例如波特率、回显、信号字符等。
9. **资源限制相关的常量 (以 `RLIMIT_`, `RLIM_INFINITY` 开头):** 定义了进程可以使用的各种资源的上限。
10. **进程状态相关的常量 (以 `W` 开头):** 定义了等待子进程时的状态标志。
11. **错误码常量 (以 `E` 开头):**  定义了各种系统调用可能返回的错误码，例如文件不存在、权限不足等。
12. **信号常量 (以 `SIG` 开头):** 定义了各种信号，例如中断信号、终止信号等。

**Go 语言功能实现推断 (系统调用)**

这个文件是 `syscall` 包的一部分，其核心功能是提供对操作系统底层系统调用的访问。Go 语言通过 `syscall` 包封装了不同操作系统的系统调用接口，使得 Go 程序可以在不同的平台上执行底层操作。

**Go 代码示例:**

假设我们想创建一个 UDP socket 并设置其接收缓冲区大小，可以使用该文件中定义的常量：

```go
package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		fmt.Println("创建 socket 失败:", err)
		return
	}
	defer syscall.Close(fd)

	// 设置接收缓冲区大小为 8192 字节
	recvBufSize := 8192
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, recvBufSize)
	if err != nil {
		fmt.Println("设置接收缓冲区失败:", err)
		return
	}

	// 获取接收缓冲区大小进行验证
	var getBufSize int
	var getBufLen uint32 = uint32(unsafe.Sizeof(getBufSize))
	_, _, err = syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_RCVBUF), uintptr(unsafe.Pointer(&getBufSize)), uintptr(unsafe.Pointer(&getBufLen)), 0)
	if err != 0 {
		fmt.Println("获取接收缓冲区失败:", err)
		return
	}

	fmt.Printf("成功创建 UDP socket，接收缓冲区大小设置为: %d\n", getBufSize)
}
```

**假设的输入与输出:**

由于此代码示例不涉及用户直接输入，其行为取决于操作系统。

*   **成功情况:**  程序将成功创建一个 UDP socket，并设置接收缓冲区大小为 8192 字节。输出将类似于：`成功创建 UDP socket，接收缓冲区大小设置为: 8192`
*   **失败情况 (例如权限不足):** 如果由于权限或其他原因无法创建 socket 或设置 socket 选项，程序将打印相应的错误信息。例如，可能输出 `创建 socket 失败: operation not permitted`。

**命令行参数处理:**

该文件本身不处理命令行参数。命令行参数的处理通常在应用程序的主函数中进行，并可能使用 `flag` 包或其他库来解析。

**使用者易犯错的点:**

1. **平台依赖性:** 这些常量是特定于 OpenBSD AMD64 平台的。如果在其他操作系统或架构上使用这些常量，可能会导致程序崩溃或行为异常。例如，在 Linux 系统下，`syscall.SO_RCVBUF` 的值可能与 OpenBSD 下的不同。
2. **错误的常量值:** 直接使用这些常量时，需要确保使用正确的常量名和值。错误地使用了常量可能导致系统调用失败或产生意想不到的结果。例如，将 socket 类型错误地设置为 `syscall.SOCK_STREAM` 而期望使用 UDP 通信。
3. **不理解底层原理:**  直接使用 `syscall` 包需要对操作系统的底层机制有一定的了解，例如 socket 编程、文件描述符等。不理解这些概念容易导致错误的使用。

**功能归纳 (第2部分):**

总而言之，`go/src/syscall/zerrors_openbsd_amd64.go` 文件的主要功能是**为 Go 语言在 OpenBSD AMD64 平台上提供访问操作系统底层系统调用所需的常量定义**。它作为 `syscall` 包的基础组成部分，使得 Go 开发者能够进行诸如网络编程、文件操作、进程控制等底层操作。这些常量涵盖了网络协议、文件系统、进程管理、终端控制等多个方面，是 Go 语言跨平台能力在特定平台上的具体实现。

Prompt: 
```
这是路径为go/src/syscall/zerrors_openbsd_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
     = 0xffff
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
	IP_DIVERTFL                       = 0x1022
	IP_DROP_MEMBERSHIP                = 0xd
	IP_ESP_NETWORK_LEVEL              = 0x16
	IP_ESP_TRANS_LEVEL                = 0x15
	IP_HDRINCL                        = 0x2
	IP_IPCOMP_LEVEL                   = 0x1d
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
	MAP_COPY                          = 0x4
	MAP_FILE                          = 0x0
	MAP_FIXED                         = 0x10
	MAP_FLAGMASK                      = 0x1ff7
	MAP_HASSEMAPHORE                  = 0x200
	MAP_INHERIT                       = 0x80
	MAP_INHERIT_COPY                  = 0x1
	MAP_INHERIT_DONATE_COPY           = 0x3
	MAP_INHERIT_NONE                  = 0x2
	MAP_INHERIT_SHARE                 = 0x0
	MAP_NOEXTEND                      = 0x100
	MAP_NORESERVE                     = 0x40
	MAP_PRIVATE                       = 0x2
	MAP_RENAME                        = 0x20
	MAP_SHARED                        = 0x1
	MAP_TRYFIXED                      = 0x400
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
	NET_RT_MAXID                      = 0x6
	NET_RT_STATS                      = 0x4
	NET_RT_TABLE                      = 0x5
	NOFLSH                            = 0x80000000
	NOTE_ATTRIB                       = 0x8
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
	RTAX_BRD                          = 0x7
	RTAX_DST                          = 0x0
	RTAX_GATEWAY                      = 0x1
	RTAX_GENMASK                      = 0x3
	RTAX_IFA                          = 0x5
	RTAX_IFP                          = 0x4
	RTAX_LABEL                        = 0xa
	RTAX_MAX                          = 0xb
	RTAX_NETMASK                      = 0x2
	RTAX_SRC                          = 0x8
	RTAX_SRCMASK                      = 0x9
	RTA_AUTHOR                        = 0x40
	RTA_BRD                           = 0x80
	RTA_DST                           = 0x1
	RTA_GATEWAY                       = 0x2
	RTA_GENMASK                       = 0x8
	RTA_IFA                           = 0x20
	RTA_IFP                           = 0x10
	RTA_LABEL                         = 0x400
	RTA_NETMASK                       = 0x4
	RTA_SRC                           = 0x100
	RTA_SRCMASK                       = 0x200
	RTF_ANNOUNCE                      = 0x4000
	RTF_BLACKHOLE                     = 0x1000
	RTF_CLONED                        = 0x10000
	RTF_CLONING                       = 0x100
	RTF_DONE                          = 0x40
	RTF_DYNAMIC                       = 0x10
	RTF_FMASK                         = 0x10f808
	RTF_GATEWAY                       = 0x2
	RTF_HOST                          = 0x4
	RTF_LLINFO                        = 0x400
	RTF_MASK                          = 0x80
	RTF_MODIFIED                      = 0x20
	RTF_MPATH                         = 0x40000
	RTF_MPLS                          = 0x100000
	RTF_PERMANENT_ARP                 = 0x2000
	RTF_PROTO1                        = 0x8000
	RTF_PROTO2                        = 0x4000
	RTF_PROTO3                        = 0x2000
	RTF_REJECT                        = 0x8
	RTF_SOURCE                        = 0x20000
	RTF_STATIC                        = 0x800
	RTF_TUNNEL                        = 0x100000
	RTF_UP                            = 0x1
	RTF_USETRAILERS                   = 0x8000
	RTF_XRESOLVE                      = 0x200
	RTM_ADD                           = 0x1
	RTM_CHANGE                        = 0x3
	RTM_DELADDR                       = 0xd
	RTM_DELETE                        = 0x2
	RTM_DESYNC                        = 0x10
	RTM_GET                           = 0x4
	RTM_IFANNOUNCE                    = 0xf
	RTM_IFINFO                        = 0xe
	RTM_LOCK                          = 0x8
	RTM_LOSING                        = 0x5
	RTM_MAXSIZE                       = 0x800
	RTM_MISS                          = 0x7
	RTM_NEWADDR                       = 0xc
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
	SIOCALIFADDR                      = 0x8218691c
	SIOCATMARK                        = 0x40047307
	SIOCBRDGADD                       = 0x8058693c
	SIOCBRDGADDS                      = 0x80586941
	SIOCBRDGARL                       = 0x806e694d
	SIOCBRDGDADDR                     = 0x81286947
	SIOCBRDGDEL                       = 0x8058693d
	SIOCBRDGDELS                      = 0x80586942
	SIOCBRDGFLUSH                     = 0x80586948
	SIOCBRDGFRL                       = 0x806e694e
	SIOCBRDGGCACHE                    = 0xc0146941
	SIOCBRDGGFD                       = 0xc0146952
	SIOCBRDGGHT                       = 0xc0146951
	SIOCBRDGGIFFLGS                   = 0xc058693e
	SIOCBRDGGMA                       = 0xc0146953
	SIOCBRDGGPARAM                    = 0xc0406958
	SIOCBRDGGPRI                      = 0xc0146950
	SIOCBRDGGRL                       = 0xc030694f
	SIOCBRDGGSIFS                     = 0xc058693c
	SIOCBRDGGTO                       = 0xc0146946
	SIOCBRDGIFS                       = 0xc0586942
	SIOCBRDGRTS                       = 0xc0206943
	SIOCBRDGSADDR                     = 0xc1286944
	SIOCBRDGSCACHE                    = 0x80146940
	SIOCBRDGSFD                       = 0x80146952
	SIOCBRDGSHT                       = 0x80146951
	SIOCBRDGSIFCOST                   = 0x80586955
	SIOCBRDGSIFFLGS                   = 0x8058693f
	SIOCBRDGSIFPRIO                   = 0x80586954
	SIOCBRDGSMA                       = 0x80146953
	SIOCBRDGSPRI                      = 0x80146950
	SIOCBRDGSPROTO                    = 0x8014695a
	SIOCBRDGSTO                       = 0x80146945
	SIOCBRDGSTXHC                     = 0x80146959
	SIOCDELMULTI                      = 0x80206932
	SIOCDIFADDR                       = 0x80206919
	SIOCDIFGROUP                      = 0x80286989
	SIOCDIFPHYADDR                    = 0x80206949
	SIOCDLIFADDR                      = 0x8218691e
	SIOCGETKALIVE                     = 0xc01869a4
	SIOCGETLABEL                      = 0x8020699a
	SIOCGETPFLOW                      = 0xc02069fe
	SIOCGETPFSYNC                     = 0xc02069f8
	SIOCGETSGCNT                      = 0xc0207534
	SIOCGETVIFCNT                     = 0xc0287533
	SIOCGETVLAN                       = 0xc0206990
	SIOCGHIWAT                        = 0x40047301
	SIOCGIFADDR                       = 0xc0206921
	SIOCGIFASYNCMAP                   = 0xc020697c
	SIOCGIFBRDADDR                    = 0xc0206923
	SIOCGIFCONF                       = 0xc0106924
	SIOCGIFDATA                       = 0xc020691b
	SIOCGIFDESCR                      = 0xc0206981
	SIOCGIFDSTADDR                    = 0xc0206922
	SIOCGIFFLAGS                      = 0xc0206911
	SIOCGIFGATTR                      = 0xc028698b
	SIOCGIFGENERIC                    = 0xc020693a
	SIOCGIFGMEMB                      = 0xc028698a
	SIOCGIFGROUP                      = 0xc0286988
	SIOCGIFHARDMTU                    = 0xc02069a5
	SIOCGIFMEDIA                      = 0xc0306936
	SIOCGIFMETRIC                     = 0xc0206917
	SIOCGIFMTU                        = 0xc020697e
	SIOCGIFNETMASK                    = 0xc0206925
	SIOCGIFPDSTADDR                   = 0xc0206948
	SIOCGIFPRIORITY                   = 0xc020699c
	SIOCGIFPSRCADDR                   = 0xc0206947
	SIOCGIFRDOMAIN                    = 0xc02069a0
	SIOCGIFRTLABEL                    = 0xc0206983
	SIOCGIFTIMESLOT                   = 0xc0206986
	SIOCGIFXFLAGS                     = 0xc020699e
	SIOCGLIFADDR                      = 0xc218691d
	SIOCGLIFPHYADDR                   = 0xc218694b
	SIOCGLIFPHYRTABLE                 = 0xc02069a2
	SIOCGLIFPHYTTL                    = 0xc02069a9
	SIOCGLOWAT                        = 0x40047303
	SIOCGPGRP                         = 0x40047309
	SIOCGSPPPPARAMS                   = 0xc0206994
	SIOCGVH                           = 0xc02069f6
	SIOCGVNETID                       = 0xc02069a7
	SIOCIFCREATE                      = 0x8020697a
	SIOCIFDESTROY                     = 0x80206979
	SIOCIFGCLONERS                    = 0xc0106978
	SIOCSETKALIVE                     = 0x801869a3
	SIOCSETLABEL                      = 0x80206999
	SIOCSETPFLOW                      = 0x802069fd
	SIOCSETPFSYNC                     = 0x802069f7
	SIOCSETVLAN                       = 0x8020698f
	SIOCSHIWAT                        = 0x80047300
	SIOCSIFADDR                       = 0x8020690c
	SIOCSIFASYNCMAP                   = 0x8020697d
	SIOCSIFBRDADDR                    = 0x80206913
	SIOCSIFDESCR                      = 0x80206980
	SIOCSIFDSTADDR                    = 0x8020690e
	SIOCSIFFLAGS                      = 0x80206910
	SIOCSIFGATTR                      = 0x8028698c
	SIOCSIFGENERIC                    = 0x80206939
	SIOCSIFLLADDR                     = 0x8020691f
	SIOCSIFMEDIA                      = 0xc0206935
	SIOCSIFMETRIC                     = 0x80206918
	SIOCSIFMTU                        = 0x8020697f
	SIOCSIFNETMASK                    = 0x80206916
	SIOCSIFPHYADDR                    = 0x80406946
	SIOCSIFPRIORITY                   = 0x8020699b
	SIOCSIFRDOMAIN                    = 0x8020699f
	SIOCSIFRTLABEL                    = 0x80206982
	SIOCSIFTIMESLOT                   = 0x80206985
	SIOCSIFXFLAGS                     = 0x8020699d
	SIOCSLIFPHYADDR                   = 0x8218694a
	SIOCSLIFPHYRTABLE                 = 0x802069a1
	SIOCSLIFPHYTTL                    = 0x802069a8
	SIOCSLOWAT                        = 0x80047302
	SIOCSPGRP                         = 0x80047308
	SIOCSSPPPPARAMS                   = 0x80206993
	SIOCSVH                           = 0xc02069f5
	SIOCSVNETID                       = 0x802069a6
	SOCK_CLOEXEC                      = 0x8000
	SOCK_DGRAM                        = 0x2
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
	TCP_NSTATES                       = 0xb
	TCP_SACK_ENABLE                   = 0x8
	TCSAFLUSH                         = 0x2
	TIOCCBRK                          = 0x2000747a
	TIOCCDTR                          = 0x20007478
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
	TIOCSFLAGS                        = 0x8004745c
	TIOCSIG                           = 0x8004745f
	TIOCSPGRP                         = 0x80047476
	TIOCSTART                         = 0x2000746e
	TIOCSTAT                          = 0x80047465
	TIOCSTI                           = 0x80017472
	TIOCSTOP                          = 0x2000746f
	TIOCSTSTAMP                       = 0x8008745a
	TIOCSWINSZ                        = 0x80087467
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
	VTIME                             = 0x11
	VWERASE                           = 0x4
	WALTSIG                           = 0x4
	WCONTINUED                        = 0x8
	WCOREFLAG                         = 0x80
	WNOHANG                           = 0x1
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
	69: "disk quota exceeded",
	70: "stale NFS file handle",
	71: "too many levels of remote in path",
	72: "RPC struct is bad",
	73: "RPC version wrong",
	74: "RPC program not available",
	75: "program version wrong",
	76: "bad procedure for program",
	77: "no locks available",
	78: "function not implemented",
	79: "inappropriate file type or format",
	80: "authentication error",
	81: "need authenticator",
	82: "IPsec processing failure",
	83: "attribute not found",
	84: "illegal byte sequence",
	85: "no medium found",
	86: "wrong medium type",
	87: "value too large to be stored in data type",
	88: "operation canceled",
	89: "identifier removed",
	90: "no message of desired type",
	91: "not supported",
	92: "bad message",
	93: "state not recoverable",
	94: "previous owner died",
	95: "protocol error",
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
	32: "thread AST",
}

"""




```