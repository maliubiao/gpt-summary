Response:
The user provided a Go source code snippet from `go/src/syscall/zerrors_openbsd_arm.go`. This is the second part of a two-part question. The first part was not provided.

The task is to:
1. **Summarize the functionality** of this code snippet.
2. If possible, **infer the higher-level Go functionality** it implements and provide a code example.
3. If code inference is involved, provide **hypothetical input and output**.
4. If it involves command-line arguments, explain them.
5. Point out **common mistakes** users might make (if any).
6. Finally, **summarize the functionality of this second part**.

Based on the content, this file defines constants related to system calls and networking on OpenBSD for the ARM architecture. It includes:

* **IP and IPv6 socket options:**  Constants starting with `IPV6_` and `IP_`. These are used to configure network sockets.
* **File locking:** Constants starting with `LOCK_`. These are used with the `flock` system call.
* **Memory mapping:** Constants starting with `MADV_` and `MAP_`. These are used with the `mmap` and `madvise` system calls.
* **Message flags:** Constants starting with `MSG_`. These are used with `send` and `recv` system calls.
* **Memory synchronization:** Constants starting with `MS_`. These are used with the `msync` system call.
* **Network routing:** Constants starting with `NET_RT_`, `RTAX_`, `RTA_`, `RTF_`, `RTM_`, `RTV_`, and `RT_TABLEID_MAX`. These are used for network routing operations.
* **Kernel event notifications:** Constants starting with `NOTE_`. These are used with the `kqueue` system call.
* **Terminal I/O:** Constants related to terminal settings, starting with `OCRNL`, `ONLCR`, `ONLRET`, `ONOCR`, `ONOEOT`, `OPOST`, `O_`, `PARENB`, `PARMRK`, `PARODD`, `PENDIN`, `TIOCCBRK`, etc. These are used to configure terminal behavior.
* **Process priority:** Constants starting with `PRIO_`. Used with `getpriority` and `setpriority`.
* **Memory protection:** Constants starting with `PROT_`. Used with `mmap`.
* **Resource limits:** Constants starting with `RLIMIT_` and `RLIM_INFINITY`. Used with `getrlimit` and `setrlimit`.
* **Socket options:** Constants starting with `SCM_`, `SHUT_`, `SIOC`, `SOCK_`, `SOL_SOCKET`, `SOMAXCONN`, `SO_`, `TCP_`. These are used to configure socket behavior.
* **Terminal control:** Constants starting with `TCIFLUSH`, `TCIOFLUSH`, `TCOFLUSH`, `TCSAFLUSH`, and those under terminal I/O.
* **Virtual terminal characters:** Constants starting with `VDISCARD`, `VDSUSP`, `VEOF`, etc.
* **Wait options:** Constants starting with `WALTSIG`, `WCONTINUED`, `WCOREFLAG`, `WNOHANG`, `WUNTRACED`. Used with `waitpid`.
* **Error numbers:** Constants starting with `E`. These represent various error conditions.
* **Signals:** Constants starting with `SIG`. These represent different signals that can be sent to a process.
* **Error and signal string tables:** `errors` and `signals` are arrays mapping error and signal numbers to their string descriptions.

**Overall Functionality:** This file defines a large set of constants and lookup tables used for interacting with the OpenBSD kernel on ARM architecture. It provides symbolic names for various system call arguments, options, error codes, and signals. This makes the `syscall` package in Go more readable and less prone to errors caused by using magic numbers.

**Inferred Go Functionality:** This file is a part of the `syscall` package, which provides a low-level interface to the operating system's system calls. It allows Go programs to directly interact with the kernel.

**Go Code Example:**  While this file itself doesn't contain executable code, it defines constants used by other parts of the `syscall` package. Here's an example of how some of these constants might be used:

```go
package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	// Create a raw socket to send IP packets
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// Set the IP_HDRINCL option to manually construct IP headers
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		fmt.Println("Error setting socket option:", err)
		return
	}

	fmt.Println("Raw socket created and IP_HDRINCL set successfully.")

	// Example of using signal constants
	signalChan := make(chan syscall.Signal, 1)
	syscall.NotifySignal(signalChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Waiting for SIGINT or SIGTERM...")
	sig := <-signalChan
	fmt.Println("Received signal:", sig)

	// Example of using error constants
	_, err = syscall.Open("/nonexistentfile", syscall.O_RDONLY, 0)
	if err == syscall.ENOENT {
		fmt.Println("File not found, as expected.")
	} else if err != nil {
		fmt.Println("Unexpected error:", err)
	}
}
```

**Hypothetical Input and Output:**  This file primarily defines constants, so there's no direct input and output in the traditional sense. However, if a system call using these constants fails, the output might include the string representation of an error, which is derived from the `errors` table in this file. For example, if `syscall.Open` fails because the file doesn't exist, the error returned would likely have a string representation based on `errors[2]`, which is "no such file or directory".

**Command-line Arguments:** This file does not directly process command-line arguments. The constants defined here are used internally by the `syscall` package and other parts of the Go standard library.

**Common Mistakes:** Users generally don't interact with this file directly. Mistakes are more likely to happen when using the `syscall` package by:

* **Using incorrect constant values:** Although unlikely due to the defined constants, manually using incorrect numerical values for system call arguments or options can lead to unexpected behavior or errors.
* **Misinterpreting error codes:**  Users might not correctly handle different error codes returned by system calls, leading to incorrect program logic. For instance, treating `EAGAIN` (resource temporarily unavailable) as a fatal error instead of retrying the operation.
* **Incorrectly using socket options:**  Setting inappropriate socket options can lead to networking issues. For example, not understanding the implications of setting `SO_REUSEADDR`.

**归纳一下它的功能 (Summary of Part 2):**

这是 `go/src/syscall/zerrors_openbsd_arm.go` 文件的第二部分，它主要定义了大量的常量，这些常量代表了在 OpenBSD (ARM 架构) 操作系统中进行系统调用和网络编程时使用的各种选项、标志、错误码和信号。

具体来说，它包含了：

* **网络相关的常量:**  例如 IP 和 IPv6 协议的套接字选项 (`IPV6_MULTICAST_HOPS`, `IP_ADD_MEMBERSHIP` 等)。
* **文件锁定的常量:** 用于 `flock` 系统调用 (`LOCK_EX`, `LOCK_SH` 等)。
* **内存映射的常量:** 用于 `mmap` 和 `madvise` 系统调用 (`MADV_DONTNEED`, `MAP_ANON` 等)。
* **消息传递的标志:** 用于 `send` 和 `recv` 系统调用 (`MSG_DONTWAIT`, `MSG_OOB` 等)。
* **内存同步的常量:** 用于 `msync` 系统调用 (`MS_ASYNC`, `MS_SYNC` 等)。
* **网络路由的常量:** 用于配置和查询网络路由表 (`NET_RT_DUMP`, `RTA_DST`, `RTF_UP` 等)。
* **内核事件通知的常量:** 用于 `kqueue` 系统调用 (`NOTE_ATTRIB`, `NOTE_DELETE` 等)。
* **终端 I/O 的常量:** 用于配置终端行为 (`O_APPEND`, `PARENB`, `TIOCGETA` 等)。
* **进程优先级的常量:** 用于 `getpriority` 和 `setpriority` (`PRIO_PGRP`, `PRIO_USER` 等)。
* **内存保护的常量:** 用于 `mmap` (`PROT_READ`, `PROT_WRITE` 等)。
* **资源限制的常量:** 用于 `getrlimit` 和 `setrlimit` (`RLIMIT_CPU`, `RLIM_INFINITY` 等)。
* **套接字选项的常量:** 用于配置套接字行为 (`SOCK_DGRAM`, `SOL_SOCKET`, `SO_REUSEADDR`, `TCP_NODELAY` 等)。
* **错误码常量:** 代表各种错误情况 (`EACCES`, `ENOENT` 等)。
* **信号常量:** 代表可以发送给进程的各种信号 (`SIGINT`, `SIGKILL` 等)。
* **错误信息和信号信息的查找表:**  `errors` 和 `signals` 数组分别将错误码和信号值映射到相应的字符串描述。

总而言之，这部分代码通过定义这些常量，为 Go 语言的 `syscall` 包提供了与 OpenBSD (ARM 架构) 内核交互的基础，使得 Go 程序可以使用符号化的名称来调用系统调用，提高了代码的可读性和可维护性。

这是 `go/src/syscall/zerrors_openbsd_arm.go` 文件的第二部分，它主要定义了大量的常量，这些常量代表了在 OpenBSD (ARM 架构) 操作系统中进行系统调用和网络编程时使用的各种选项、标志、错误码和信号。

具体来说，它包含了：

* **网络相关的常量:**  例如 IP 和 IPv6 协议的套接字选项 (`IPV6_MULTICAST_HOPS`, `IP_ADD_MEMBERSHIP` 等)。
* **文件锁定的常量:** 用于 `flock` 系统调用 (`LOCK_EX`, `LOCK_SH` 等)。
* **内存映射的常量:** 用于 `mmap` 和 `madvise` 系统调用 (`MADV_DONTNEED`, `MAP_ANON` 等)。
* **消息传递的标志:** 用于 `send` 和 `recv` 系统调用 (`MSG_DONTWAIT`, `MSG_OOB` 等)。
* **内存同步的常量:** 用于 `msync` 系统调用 (`MS_ASYNC`, `MS_SYNC` 等)。
* **网络路由的常量:** 用于配置和查询网络路由表 (`NET_RT_DUMP`, `RTA_DST`, `RTF_UP` 等)。
* **内核事件通知的常量:** 用于 `kqueue` 系统调用 (`NOTE_ATTRIB`, `NOTE_DELETE` 等)。
* **终端 I/O 的常量:** 用于配置终端行为 (`O_APPEND`, `PARENB`, `TIOCGETA` 等)。
* **进程优先级的常量:** 用于 `getpriority` 和 `setpriority` (`PRIO_PGRP`, `PRIO_USER` 等)。
* **内存保护的常量:** 用于 `mmap` (`PROT_READ`, `PROT_WRITE` 等)。
* **资源限制的常量:** 用于 `getrlimit` 和 `setrlimit` (`RLIMIT_CPU`, `RLIM_INFINITY` 等)。
* **套接字选项的常量:** 用于配置套接字行为 (`SOCK_DGRAM`, `SOL_SOCKET`, `SO_REUSEADDR`, `TCP_NODELAY` 等)。
* **错误码常量:** 代表各种错误情况 (`EACCES`, `ENOENT` 等)。
* **信号常量:** 代表可以发送给进程的各种信号 (`SIGINT`, `SIGKILL` 等)。
* **错误信息和信号信息的查找表:**  `errors` 和 `signals` 数组分别将错误码和信号值映射到相应的字符串描述。

总而言之，这部分代码通过定义这些常量，为 Go 语言的 `syscall` 包提供了与 OpenBSD (ARM 架构) 内核交互的基础，使得 Go 程序可以使用符号化的名称来调用系统调用，提高了代码的可读性和可维护性。

Prompt: 
```
这是路径为go/src/syscall/zerrors_openbsd_arm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
0x500
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
	MAP_ANONYMOUS                     = 0x1000
	MAP_COPY                          = 0x2
	MAP_FILE                          = 0x0
	MAP_FIXED                         = 0x10
	MAP_FLAGMASK                      = 0x3ff7
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
	RTF_BROADCAST                     = 0x400000
	RTF_CLONED                        = 0x10000
	RTF_CLONING                       = 0x100
	RTF_DONE                          = 0x40
	RTF_DYNAMIC                       = 0x10
	RTF_FMASK                         = 0x70f808
	RTF_GATEWAY                       = 0x2
	RTF_HOST                          = 0x4
	RTF_LLINFO                        = 0x400
	RTF_LOCAL                         = 0x200000
	RTF_MASK                          = 0x80
	RTF_MODIFIED                      = 0x20
	RTF_MPATH                         = 0x40000
	RTF_MPLS                          = 0x100000
	RTF_PERMANENT_ARP                 = 0x2000
	RTF_PROTO1                        = 0x8000
	RTF_PROTO2                        = 0x4000
	RTF_PROTO3                        = 0x2000
	RTF_REJECT                        = 0x8
	RTF_STATIC                        = 0x800
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
	SIOCAIFGROUP                      = 0x80246987
	SIOCALIFADDR                      = 0x8218691c
	SIOCATMARK                        = 0x40047307
	SIOCBRDGADD                       = 0x8054693c
	SIOCBRDGADDS                      = 0x80546941
	SIOCBRDGARL                       = 0x806e694d
	SIOCBRDGDADDR                     = 0x81286947
	SIOCBRDGDEL                       = 0x8054693d
	SIOCBRDGDELS                      = 0x80546942
	SIOCBRDGFLUSH                     = 0x80546948
	SIOCBRDGFRL                       = 0x806e694e
	SIOCBRDGGCACHE                    = 0xc0146941
	SIOCBRDGGFD                       = 0xc0146952
	SIOCBRDGGHT                       = 0xc0146951
	SIOCBRDGGIFFLGS                   = 0xc054693e
	SIOCBRDGGMA                       = 0xc0146953
	SIOCBRDGGPARAM                    = 0xc03c6958
	SIOCBRDGGPRI                      = 0xc0146950
	SIOCBRDGGRL                       = 0xc028694f
	SIOCBRDGGSIFS                     = 0xc054693c
	SIOCBRDGGTO                       = 0xc0146946
	SIOCBRDGIFS                       = 0xc0546942
	SIOCBRDGRTS                       = 0xc0186943
	SIOCBRDGSADDR                     = 0xc1286944
	SIOCBRDGSCACHE                    = 0x80146940
	SIOCBRDGSFD                       = 0x80146952
	SIOCBRDGSHT                       = 0x80146951
	SIOCBRDGSIFCOST                   = 0x80546955
	SIOCBRDGSIFFLGS                   = 0x8054693f
	SIOCBRDGSIFPRIO                   = 0x80546954
	SIOCBRDGSMA                       = 0x80146953
	SIOCBRDGSPRI                      = 0x80146950
	SIOCBRDGSPROTO                    = 0x8014695a
	SIOCBRDGSTO                       = 0x80146945
	SIOCBRDGSTXHC                     = 0x80146959
	SIOCDELMULTI                      = 0x80206932
	SIOCDIFADDR                       = 0x80206919
	SIOCDIFGROUP                      = 0x80246989
	SIOCDIFPHYADDR                    = 0x80206949
	SIOCDLIFADDR                      = 0x8218691e
	SIOCGETKALIVE                     = 0xc01869a4
	SIOCGETLABEL                      = 0x8020699a
	SIOCGETPFLOW                      = 0xc02069fe
	SIOCGETPFSYNC                     = 0xc02069f8
	SIOCGETSGCNT                      = 0xc0147534
	SIOCGETVIFCNT                     = 0xc0147533
	SIOCGETVLAN                       = 0xc0206990
	SIOCGHIWAT                        = 0x40047301
	SIOCGIFADDR                       = 0xc0206921
	SIOCGIFASYNCMAP                   = 0xc020697c
	SIOCGIFBRDADDR                    = 0xc0206923
	SIOCGIFCONF                       = 0xc0086924
	SIOCGIFDATA                       = 0xc020691b
	SIOCGIFDESCR                      = 0xc0206981
	SIOCGIFDSTADDR                    = 0xc0206922
	SIOCGIFFLAGS                      = 0xc0206911
	SIOCGIFGATTR                      = 0xc024698b
	SIOCGIFGENERIC                    = 0xc020693a
	SIOCGIFGMEMB                      = 0xc024698a
	SIOCGIFGROUP                      = 0xc0246988
	SIOCGIFHARDMTU                    = 0xc02069a5
	SIOCGIFMEDIA                      = 0xc0286936
	SIOCGIFMETRIC                     = 0xc0206917
	SIOCGIFMTU                        = 0xc020697e
	SIOCGIFNETMASK                    = 0xc0206925
	SIOCGIFPDSTADDR                   = 0xc0206948
	SIOCGIFPRIORITY                   = 0xc020699c
	SIOCGIFPSRCADDR                   = 0xc0206947
	SIOCGIFRDOMAIN                    = 0xc02069a0
	SIOCGIFRTLABEL                    = 0xc0206983
	SIOCGIFRXR                        = 0x802069aa
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
	SIOCIFGCLONERS                    = 0xc00c6978
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
	SIOCSIFGATTR                      = 0x8024698c
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
	TIOCGTSTAMP                       = 0x400c745b
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