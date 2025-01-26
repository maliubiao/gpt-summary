Response:
The user wants to understand the functionality of a Go source code file, specifically `go/src/syscall/zerrors_netbsd_amd64.go`. They've provided a snippet of the file content and marked it as the second part of a three-part series.

Based on the content, it seems this file defines constants related to system calls and networking on the NetBSD operating system for the amd64 architecture. These constants represent various flags, error codes, signal numbers, and other system-level definitions.

My plan is to:
1. **Summarize the purpose of the code snippet**: It defines numerical constants used in system calls for NetBSD on amd64.
2. **Infer the broader Go functionality**: This file is part of the `syscall` package, which provides a low-level interface to the operating system. It's used by other Go code to interact with the kernel.
3. **Provide a Go code example**: Demonstrate how these constants might be used, for instance, when opening a file with specific flags.
4. **Explain the lack of command-line argument processing**: This file primarily defines constants and doesn't handle command-line arguments directly.
5. **Illustrate potential pitfalls**:  Mention the risk of using these low-level constants directly, as it can lead to platform-specific code. Highlight the preference for using higher-level Go abstractions.
6. **Summarize the functionality of this part**: Reiterate that this specific section defines constants related to network interfaces, IP protocols, and socket options.
这段代码是 `go/src/syscall/zerrors_netbsd_amd64.go` 文件的一部分，它定义了一系列的常量。

**它的主要功能是定义了用于 NetBSD 操作系统在 amd64 架构下的系统调用相关的常量。**

这些常量可以分为以下几类：

1. **网络接口类型 (IFT_*)**:  例如 `IFT_ETHER` 代表以太网接口，`IFT_LOOP` 代表回环接口等。这些常量用于标识网络接口的类型。
2. **终端控制标志 (IGNBRK, IGNCR, 等)**: 例如 `IGNBRK` 代表忽略 BREAK 信号，`IGNCR` 代表忽略回车符等。这些常量用于控制终端输入输出的行为。
3. **网络地址类 (IN_CLASSA_HOST, IN_CLASSB_NET, 等)**:  例如 `IN_CLASSA_HOST` 代表 A 类地址的主机部分掩码，`IN_CLASSB_NET` 代表 B 类地址的网络部分掩码等。这些常量用于处理 IP 地址。
4. **IP 协议类型 (IPPROTO_AH, IPPROTO_TCP, 等)**: 例如 `IPPROTO_TCP` 代表 TCP 协议，`IPPROTO_UDP` 代表 UDP 协议等。这些常量用于标识 IP 数据包中使用的协议。
5. **IPv6 相关选项 (IPV6_CHECKSUM, IPV6_JOIN_GROUP, 等)**: 例如 `IPV6_CHECKSUM` 代表 IPv6 校验和选项，`IPV6_JOIN_GROUP` 代表加入 IPv6 组播组选项等。这些常量用于配置 IPv6 的行为。
6. **IP 相关选项 (IP_ADD_MEMBERSHIP, IP_HDRINCL, 等)**: 例如 `IP_ADD_MEMBERSHIP` 代表加入组播组选项，`IP_HDRINCL` 代表 IP 头包含在数据中选项等。这些常量用于配置 IP 协议的行为。
7. **终端输入标志 (ISIG, ISTRIP, 等)**: 例如 `ISIG` 代表启用信号处理，`ISTRIP` 代表去除输入字符的第八位等。这些常量用于控制终端输入的行为。
8. **文件锁常量 (LOCK_EX, LOCK_SH, 等)**: 例如 `LOCK_EX` 代表排他锁，`LOCK_SH` 代表共享锁等。这些常量用于进行文件锁定操作。
9. **内存映射常量 (MADV_DONTNEED, MAP_ANON, 等)**: 例如 `MADV_DONTNEED` 代表建议内核不再需要此内存区域，`MAP_ANON` 代表创建匿名映射等。这些常量用于内存映射相关的操作。
10. **消息发送接收标志 (MSG_DONTWAIT, MSG_OOB, 等)**: 例如 `MSG_DONTWAIT` 代表非阻塞操作，`MSG_OOB` 代表发送或接收带外数据等。这些常量用于 `send` 和 `recv` 等系统调用。
11. **内存同步标志 (MS_ASYNC, MS_SYNC)**: 例如 `MS_ASYNC` 代表异步写入，`MS_SYNC` 代表同步写入等。这些常量用于 `msync` 系统调用。
12. **路由表操作常量 (NET_RT_DUMP, NET_RT_FLAGS)**: 例如 `NET_RT_DUMP` 代表转储路由表，`NET_RT_FLAGS` 代表获取/设置路由标志等。这些常量用于操作路由表。
13. **文件事件通知常量 (NOTE_ATTRIB, NOTE_DELETE, 等)**: 例如 `NOTE_ATTRIB` 代表文件属性被修改，`NOTE_DELETE` 代表文件被删除等。这些常量用于文件事件通知机制，例如 `kqueue`。
14. **终端输出标志 (OCRNL, ONLCR, 等)**: 例如 `OCRNL` 代表将输出的回车符映射为换行符，`ONLCR` 代表将输出的换行符映射为回车换行符等。这些常量用于控制终端输出的行为。
15. **文件打开标志 (O_ACCMODE, O_CREAT, 等)**: 例如 `O_RDONLY` 代表只读模式，`O_WRONLY` 代表只写模式，`O_CREAT` 代表如果文件不存在则创建文件等。这些常量用于 `open` 系统调用。
16. **终端奇偶校验标志 (PARENB, PARODD)**: 例如 `PARENB` 代表启用奇偶校验，`PARODD` 代表使用奇校验等。
17. **进程优先级常量 (PRIO_PGRP, PRIO_USER)**: 例如 `PRIO_PGRP` 代表进程组优先级，`PRIO_USER` 代表用户优先级等。这些常量用于 `getpriority` 和 `setpriority` 系统调用。
18. **内存保护标志 (PROT_EXEC, PROT_READ, 等)**: 例如 `PROT_READ` 代表可读，`PROT_WRITE` 代表可写，`PROT_EXEC` 代表可执行等。这些常量用于 `mmap` 等系统调用。
19. **资源限制常量 (RLIMIT_AS, RLIMIT_CPU, 等)**: 例如 `RLIMIT_AS` 代表进程地址空间大小限制，`RLIMIT_CPU` 代表 CPU 时间限制等。这些常量用于 `getrlimit` 和 `setrlimit` 系统调用。
20. **路由属性常量 (RTAX_AUTHOR, RTAX_DST, 等)** 和 **路由标志常量 (RTA_AUTHOR, RTA_DST, 等)** 以及 **路由信息标志常量 (RTF_ANNOUNCE, RTF_GATEWAY, 等)**：这些常量用于操作路由表。
21. **路由消息类型常量 (RTM_ADD, RTM_DELETE, 等)**: 例如 `RTM_ADD` 代表添加路由，`RTM_DELETE` 代表删除路由等。这些常量用于路由消息。
22. **路由存活时间属性常量 (RTV_EXPIRE, RTV_HOPCOUNT)**: 这些常量用于表示路由信息的有效性。
23. **资源使用常量 (RUSAGE_CHILDREN, RUSAGE_SELF)**: 例如 `RUSAGE_SELF` 代表当前进程的资源使用情况，`RUSAGE_CHILDREN` 代表子进程的资源使用情况等。这些常量用于 `getrusage` 系统调用。
24. **控制消息头常量 (SCM_CREDS, SCM_RIGHTS, 等)**: 例如 `SCM_RIGHTS` 代表传递文件描述符，`SCM_TIMESTAMP` 代表传递时间戳等。这些常量用于 `sendmsg` 和 `recvmsg` 系统调用传递辅助数据。
25. **套接字关闭方式常量 (SHUT_RD, SHUT_WR, 等)**: 例如 `SHUT_RD` 代表关闭读端，`SHUT_WR` 代表关闭写端等。这些常量用于 `shutdown` 系统调用。
26. **套接字操作常量 (SIOCADDMULTI, SIOCADDRT, 等)**: 这些是以 `SIOC` 开头的常量，代表 Socket I/O Control，用于执行各种套接字相关的操作，例如添加多播成员、添加路由等。这些通常用于 `ioctl` 系统调用。
27. **套接字选项常量 (SOCK_CLOEXEC, SOCK_DGRAM, 等)**: 例如 `SOCK_STREAM` 代表 TCP 流式套接字，`SOCK_DGRAM` 代表 UDP 数据报套接字，`SOCK_NONBLOCK` 代表非阻塞套接字等。这些常量用于 `socket` 系统调用。
28. **通用套接字层选项 (SOL_SOCKET)**:  通常与 `setsockopt` 和 `getsockopt` 一起使用。
29. **套接字选项 (SO_ACCEPTCONN, SO_BROADCAST, 等)**: 例如 `SO_REUSEADDR` 代表允许重用本地地址和端口，`SO_KEEPALIVE` 代表启用 TCP Keep-Alive 探测等。这些常量用于 `setsockopt` 和 `getsockopt` 系统调用。
30. **系统控制常量 (SYSCTL_VERSION, SYSCTL_VERS_0, 等)**: 这些常量用于 `sysctl` 系统调用，用于获取或设置内核参数。
31. **文件状态标志 (S_ARCH1, S_IFBLK, 等)**: 例如 `S_IFREG` 代表普通文件，`S_IFDIR` 代表目录，`S_IRUSR` 代表用户可读权限等。这些常量用于表示文件的类型和权限。
32. **终端控制流常量 (TCIFLUSH, TCOFLUSH, 等)**: 例如 `TCIFLUSH` 代表刷新输入缓冲区，`TCOFLUSH` 代表刷新输出缓冲区等。这些常量用于 `tcflush` 函数。
33. **TCP 选项常量 (TCP_CONGCTL, TCP_KEEPCNT, 等)**: 例如 `TCP_NODELAY` 代表禁用 Nagle 算法，`TCP_KEEPIDLE` 代表 TCP 保活探测空闲时间等。这些常量用于 `setsockopt` 和 `getsockopt` 系统调用配置 TCP 连接。
34. **终端控制操作常量 (TIOCCBRK, TIOCGETA, 等)**: 这些是以 `TIOC` 开头的常量，代表 Terminal Input/Output Control，用于执行各种终端相关的控制操作，例如发送 BREAK 信号、获取终端属性等。这些通常用于 `ioctl` 系统调用。
35. **终端控制模式常量 (TOSTOP)**:  用于控制后台进程尝试写入控制终端时的行为。
36. **终端特殊字符索引 (VDISCARD, VEOF, 等)**: 例如 `VEOF` 代表文件结束符，`VINTR` 代表中断字符等。这些常量用于配置终端的特殊控制字符。
37. **进程等待选项常量 (WALL, WEXITED, 等)**: 例如 `WNOHANG` 代表非阻塞等待，`WEXITED` 代表只等待正常退出的子进程等。这些常量用于 `wait` 和 `waitpid` 等系统调用。

总而言之，这个文件是 Go 语言运行时系统在 NetBSD amd64 平台上进行底层系统交互的基础。

**Go 代码示例：**

假设我们需要创建一个 UDP socket：

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	fmt.Println("Socket created successfully with file descriptor:", fd)
	syscall.Close(fd)
}
```

**假设的输入与输出：**

这个代码段本身不涉及输入，它的输出取决于 `syscall.Socket` 函数的执行结果。如果成功创建套接字，输出会类似于：

```
Socket created successfully with file descriptor: 3
```

如果创建失败，则会输出错误信息，例如：

```
Error creating socket: operation not permitted
```

**命令行参数处理：**

这个代码文件本身不处理命令行参数。它是底层的常量定义。命令行参数的处理通常发生在应用程序的 `main` 函数中，可以使用 `os.Args` 或 `flag` 包来完成。

**易犯错的点：**

直接使用这些底层的常量进行系统调用是比较底层的操作，容易出错。

* **平台依赖性:** 这些常量是特定于 NetBSD amd64 平台的。直接使用这些常量编写的代码将不具备跨平台性。在其他操作系统或架构上编译和运行可能会失败或者行为不一致。

**示例：**

如果你在 Linux 系统上使用 `syscall.AF_INET`，它可能仍然能工作，因为 `AF_INET` 的值在不同平台之间通常是一致的。但是，如果你使用了像 `syscall.SIOCADDMULTI` 这样的特定于 NetBSD 的 ioctl 命令，那么这段代码在 Linux 上将会出错。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// 尝试在非 NetBSD 系统上使用 NetBSD 特有的 ioctl 命令
	var ifreq struct {
		Name [16]byte
		Addr syscall.RawSockaddrInet4
	}
	copy(ifreq.Name[:], "eth0") // 假设 Linux 下的网卡名

	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCADDMULTI), uintptr(unsafe.Pointer(&ifreq)))
	if ep != 0 {
		fmt.Println("Error using ioctl (SIOCADDMULTI):", ep) // 在非 NetBSD 系统上会报错
	}
}
```

在这个例子中，`SIOCADDMULTI` 是 NetBSD 特有的常量。在 Linux 或 macOS 上运行这段代码，`syscall.SYS_IOCTL` 系统调用会返回一个错误，因为该 ioctl 命令在这些系统上不存在。

**总结一下这个部分的功能：**

这个代码片段定义了大量的常量，这些常量用于 NetBSD 操作系统在 amd64 架构下的底层网络相关的系统调用，包括网络接口类型、IP 协议、IPv6 和 IP 选项等。它是 Go 语言 `syscall` 包在特定平台上的实现细节，为更上层网络功能的实现提供了基础的数值定义。

Prompt: 
```
这是路径为go/src/syscall/zerrors_netbsd_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
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