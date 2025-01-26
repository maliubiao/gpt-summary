Response:
The user is asking for a summary of the functionality of the provided Go code snippet. This is the second part of a three-part series. The code appears to define a large number of constants related to system calls on a Linux MIPS architecture.

Therefore, the main function of this code is to provide symbolic names for various numerical constants used in low-level system interactions on Linux/MIPS. These constants represent things like socket options, file access modes, process priorities, error codes, and signals.

To summarize the functionality for the second part, I need to identify the major categories of constants defined in this particular section.

Looking at the code, this part primarily defines constants related to:
- **Packet Socket Options:** Constants starting with `PACKET_`.
- **Terminal I/O Options:** Constants starting with `PARENB`, `PARITY_`, `PARMRK`, `PARODD`, `PENDIN`, and constants related to `TIOC...`.
- **Process Resource Limits and Priorities:** Constants starting with `PRIO_`, `PROT_`, `PR_`, and `RLIMIT_`, `RLIM_`.
- **Routing Table Attributes and Flags:** Constants starting with `RTAX_`, `RTA_`, `RTCF_`, `RTF_`, `RTM_`, `RTNH_`, `RTPROT_`, `RT_CLASS_`.
- **Resource Usage:** Constants starting with `RUSAGE_`.
- **Socket Control Messages:** Constants starting with `SCM_`.
- **Socket Shutdown Options:** Constants starting with `SHUT_`.
- **Socket Ioctl Commands:** Constants starting with `SIOC`.
- **Socket Options:** Constants starting with `SOCK_` and `SOL_` and `SO_`.
- **File Mode Constants:** Constants starting with `S_`.
- **Terminal Control Constants:** Constants starting with `TC`.
- **TCP Options:** Constants starting with `TCP_`.
- **TTY Ioctl Commands:** Constants starting with `TIOC`.
- **TUN/TAP Device Ioctl Commands:** Constants starting with `TUN`.
- **Terminal V-Codes:** Constants starting with `V`.
- **Wait Options:** Constants starting with `W`.

The second part of the code primarily focuses on constants related to **terminal input/output control, process and memory management, networking (especially routing and socket options), and file system operations**.
这是 `go/src/syscall/zerrors_linux_mips.go` 文件的一部分，专门针对 Linux MIPS 架构。这部分代码的主要功能是 **定义了大量的常量，这些常量对应于 Linux MIPS 系统调用中使用的各种标志、选项、错误码和信号**。

具体来说，这部分代码定义了以下类别的常量：

* **网络相关的常量:**
    * `PACKET_*`:  与数据包套接字相关的选项，例如数据包类型、多播选项等。
    * `RTAX_*`, `RTA_*`, `RTCF_*`, `RTF_*`, `RTM_*`, `RTNH_*`, `RTPROT_*`, `RT_CLASS_*`: 与路由表相关的属性、标志和消息类型。
    * `SCM_*`:  与套接字控制消息相关的常量。
    * `SHUT_*`:  `shutdown` 系统调用中使用的关闭套接字的方式。
    * `SIOC*`:  `ioctl` 系统调用中用于套接字操作的命令，例如添加/删除路由、获取/设置接口地址等。
    * `SOCK_*`:  创建套接字时指定的类型和选项。
    * `SOL_*`:  `setsockopt` 和 `getsockopt` 系统调用中使用的协议层。
    * `SO_*`:   `setsockopt` 和 `getsockopt` 系统调用中使用的套接字选项。
* **文件和目录相关的常量:**
    * `S_*`:  与文件模式和权限相关的常量，例如文件类型、读写执行权限等。
* **终端控制相关的常量:**
    * `TC*`:  与终端控制相关的常量，例如刷新输入/输出队列。
    * `TIOC*`:  `ioctl` 系统调用中用于终端控制的命令，例如获取/设置终端属性、发送信号等。
    * `V*`:   与终端特殊字符相关的常量，例如 `Ctrl+C`，`Ctrl+D` 等。
* **进程控制相关的常量:**
    * `PRIO_*`:  用于设置进程优先级的常量。
    * `PROT_*`:  用于内存保护的标志，例如可读、可写、可执行。
    * `PR_*`:   用于 `prctl` 系统调用的选项，可以控制进程的各种行为，例如设置子进程的 subreaper 状态、获取/设置内存布局信息、控制信号等。
    * `RLIMIT_*`, `RLIM_INFINITY`:  用于设置进程资源限制的常量。
    * `RUSAGE_*`: 用于 `Getrusage` 系统调用，表示要获取的资源使用情况的类型。
    * `W*`:   用于 `wait` 系统调用，表示等待的子进程状态。
* **其他常量:**
    * `WORDSIZE`: 表示机器字的大小。

**可以推理出它是什么go语言功能的实现：**

这部分代码是 Go 语言标准库中 `syscall` 包的一部分。`syscall` 包提供了访问底层操作系统调用的能力。Go 语言为了实现跨平台，会将不同平台的系统调用进行抽象。而像 `zerrors_linux_mips.go` 这样的文件，则包含了特定平台（这里是 Linux MIPS）的系统调用相关的常量定义。

**Go 代码示例：**

假设我们要设置一个非阻塞的 TCP 套接字：

```go
package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	// 创建一个 TCP 套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("创建套接字失败:", err)
		return
	}
	defer syscall.Close(fd)

	// 设置为非阻塞模式
	err = syscall.SetNonblock(fd, true)
	if err != nil {
		fmt.Println("设置非阻塞失败:", err)
		return
	}

	// 或者使用更 Go 风格的方式
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("监听失败:", err)
		return
	}
	defer ln.Close()

	file, err := ln.(*net.TCPListener).File()
	if err != nil {
		fmt.Println("获取文件描述符失败:", err)
		return
	}
	defer file.Close()

	err = syscall.SetNonblock(int(file.Fd()), true)
	if err != nil {
		fmt.Println("设置非阻塞失败:", err)
		return
	}

	fmt.Println("TCP 套接字已创建并设置为非阻塞模式。")
}
```

**假设输入与输出：**

上面的代码示例不需要特定的输入。输出结果会根据执行环境是否成功创建和设置套接字而定。如果成功，会输出 "TCP 套接字已创建并设置为非阻塞模式。"，否则会输出相应的错误信息。

**命令行参数的具体处理：**

这段代码本身不涉及命令行参数的处理。命令行参数的处理通常发生在 `main` 函数中，使用 `os.Args` 获取。

**归纳一下它的功能 (第2部分):**

这部分代码定义了大量的常量，主要涵盖了 **终端输入/输出控制，进程和内存管理，网络 (特别是路由和套接字选项)，以及文件系统操作** 相关的系统调用参数和选项，为在 Linux MIPS 架构下进行底层系统编程提供了必要的符号常量。 这些常量使得代码更易读和维护，避免了直接使用难以理解的数字。

Prompt: 
```
这是路径为go/src/syscall/zerrors_linux_mips.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
            = 0xb
	PACKET_HOST                      = 0x0
	PACKET_KERNEL                    = 0x7
	PACKET_LOOPBACK                  = 0x5
	PACKET_LOSS                      = 0xe
	PACKET_MR_ALLMULTI               = 0x2
	PACKET_MR_MULTICAST              = 0x0
	PACKET_MR_PROMISC                = 0x1
	PACKET_MR_UNICAST                = 0x3
	PACKET_MULTICAST                 = 0x2
	PACKET_ORIGDEV                   = 0x9
	PACKET_OTHERHOST                 = 0x3
	PACKET_OUTGOING                  = 0x4
	PACKET_QDISC_BYPASS              = 0x14
	PACKET_RECV_OUTPUT               = 0x3
	PACKET_RESERVE                   = 0xc
	PACKET_RX_RING                   = 0x5
	PACKET_STATISTICS                = 0x6
	PACKET_TIMESTAMP                 = 0x11
	PACKET_TX_HAS_OFF                = 0x13
	PACKET_TX_RING                   = 0xd
	PACKET_TX_TIMESTAMP              = 0x10
	PACKET_USER                      = 0x6
	PACKET_VERSION                   = 0xa
	PACKET_VNET_HDR                  = 0xf
	PARENB                           = 0x100
	PARITY_CRC16_PR0                 = 0x2
	PARITY_CRC16_PR0_CCITT           = 0x4
	PARITY_CRC16_PR1                 = 0x3
	PARITY_CRC16_PR1_CCITT           = 0x5
	PARITY_CRC32_PR0_CCITT           = 0x6
	PARITY_CRC32_PR1_CCITT           = 0x7
	PARITY_DEFAULT                   = 0x0
	PARITY_NONE                      = 0x1
	PARMRK                           = 0x8
	PARODD                           = 0x200
	PENDIN                           = 0x4000
	PRIO_PGRP                        = 0x1
	PRIO_PROCESS                     = 0x0
	PRIO_USER                        = 0x2
	PROT_EXEC                        = 0x4
	PROT_GROWSDOWN                   = 0x1000000
	PROT_GROWSUP                     = 0x2000000
	PROT_NONE                        = 0x0
	PROT_READ                        = 0x1
	PROT_WRITE                       = 0x2
	PR_CAPBSET_DROP                  = 0x18
	PR_CAPBSET_READ                  = 0x17
	PR_ENDIAN_BIG                    = 0x0
	PR_ENDIAN_LITTLE                 = 0x1
	PR_ENDIAN_PPC_LITTLE             = 0x2
	PR_FPEMU_NOPRINT                 = 0x1
	PR_FPEMU_SIGFPE                  = 0x2
	PR_FP_EXC_ASYNC                  = 0x2
	PR_FP_EXC_DISABLED               = 0x0
	PR_FP_EXC_DIV                    = 0x10000
	PR_FP_EXC_INV                    = 0x100000
	PR_FP_EXC_NONRECOV               = 0x1
	PR_FP_EXC_OVF                    = 0x20000
	PR_FP_EXC_PRECISE                = 0x3
	PR_FP_EXC_RES                    = 0x80000
	PR_FP_EXC_SW_ENABLE              = 0x80
	PR_FP_EXC_UND                    = 0x40000
	PR_GET_CHILD_SUBREAPER           = 0x25
	PR_GET_DUMPABLE                  = 0x3
	PR_GET_ENDIAN                    = 0x13
	PR_GET_FPEMU                     = 0x9
	PR_GET_FPEXC                     = 0xb
	PR_GET_KEEPCAPS                  = 0x7
	PR_GET_NAME                      = 0x10
	PR_GET_NO_NEW_PRIVS              = 0x27
	PR_GET_PDEATHSIG                 = 0x2
	PR_GET_SECCOMP                   = 0x15
	PR_GET_SECUREBITS                = 0x1b
	PR_GET_THP_DISABLE               = 0x2a
	PR_GET_TID_ADDRESS               = 0x28
	PR_GET_TIMERSLACK                = 0x1e
	PR_GET_TIMING                    = 0xd
	PR_GET_TSC                       = 0x19
	PR_GET_UNALIGN                   = 0x5
	PR_MCE_KILL                      = 0x21
	PR_MCE_KILL_CLEAR                = 0x0
	PR_MCE_KILL_DEFAULT              = 0x2
	PR_MCE_KILL_EARLY                = 0x1
	PR_MCE_KILL_GET                  = 0x22
	PR_MCE_KILL_LATE                 = 0x0
	PR_MCE_KILL_SET                  = 0x1
	PR_SET_CHILD_SUBREAPER           = 0x24
	PR_SET_DUMPABLE                  = 0x4
	PR_SET_ENDIAN                    = 0x14
	PR_SET_FPEMU                     = 0xa
	PR_SET_FPEXC                     = 0xc
	PR_SET_KEEPCAPS                  = 0x8
	PR_SET_MM                        = 0x23
	PR_SET_MM_ARG_END                = 0x9
	PR_SET_MM_ARG_START              = 0x8
	PR_SET_MM_AUXV                   = 0xc
	PR_SET_MM_BRK                    = 0x7
	PR_SET_MM_END_CODE               = 0x2
	PR_SET_MM_END_DATA               = 0x4
	PR_SET_MM_ENV_END                = 0xb
	PR_SET_MM_ENV_START              = 0xa
	PR_SET_MM_EXE_FILE               = 0xd
	PR_SET_MM_START_BRK              = 0x6
	PR_SET_MM_START_CODE             = 0x1
	PR_SET_MM_START_DATA             = 0x3
	PR_SET_MM_START_STACK            = 0x5
	PR_SET_NAME                      = 0xf
	PR_SET_NO_NEW_PRIVS              = 0x26
	PR_SET_PDEATHSIG                 = 0x1
	PR_SET_PTRACER                   = 0x59616d61
	PR_SET_PTRACER_ANY               = 0xffffffff
	PR_SET_SECCOMP                   = 0x16
	PR_SET_SECUREBITS                = 0x1c
	PR_SET_THP_DISABLE               = 0x29
	PR_SET_TIMERSLACK                = 0x1d
	PR_SET_TIMING                    = 0xe
	PR_SET_TSC                       = 0x1a
	PR_SET_UNALIGN                   = 0x6
	PR_TASK_PERF_EVENTS_DISABLE      = 0x1f
	PR_TASK_PERF_EVENTS_ENABLE       = 0x20
	PR_TIMING_STATISTICAL            = 0x0
	PR_TIMING_TIMESTAMP              = 0x1
	PR_TSC_ENABLE                    = 0x1
	PR_TSC_SIGSEGV                   = 0x2
	PR_UNALIGN_NOPRINT               = 0x1
	PR_UNALIGN_SIGBUS                = 0x2
	PTRACE_ATTACH                    = 0x10
	PTRACE_CONT                      = 0x7
	PTRACE_DETACH                    = 0x11
	PTRACE_EVENT_CLONE               = 0x3
	PTRACE_EVENT_EXEC                = 0x4
	PTRACE_EVENT_EXIT                = 0x6
	PTRACE_EVENT_FORK                = 0x1
	PTRACE_EVENT_SECCOMP             = 0x7
	PTRACE_EVENT_STOP                = 0x80
	PTRACE_EVENT_VFORK               = 0x2
	PTRACE_EVENT_VFORK_DONE          = 0x5
	PTRACE_GETEVENTMSG               = 0x4201
	PTRACE_GETFPREGS                 = 0xe
	PTRACE_GETREGS                   = 0xc
	PTRACE_GETREGSET                 = 0x4204
	PTRACE_GETSIGINFO                = 0x4202
	PTRACE_GETSIGMASK                = 0x420a
	PTRACE_GET_THREAD_AREA           = 0x19
	PTRACE_GET_THREAD_AREA_3264      = 0xc4
	PTRACE_GET_WATCH_REGS            = 0xd0
	PTRACE_INTERRUPT                 = 0x4207
	PTRACE_KILL                      = 0x8
	PTRACE_LISTEN                    = 0x4208
	PTRACE_OLDSETOPTIONS             = 0x15
	PTRACE_O_EXITKILL                = 0x100000
	PTRACE_O_MASK                    = 0x1000ff
	PTRACE_O_TRACECLONE              = 0x8
	PTRACE_O_TRACEEXEC               = 0x10
	PTRACE_O_TRACEEXIT               = 0x40
	PTRACE_O_TRACEFORK               = 0x2
	PTRACE_O_TRACESECCOMP            = 0x80
	PTRACE_O_TRACESYSGOOD            = 0x1
	PTRACE_O_TRACEVFORK              = 0x4
	PTRACE_O_TRACEVFORKDONE          = 0x20
	PTRACE_PEEKDATA                  = 0x2
	PTRACE_PEEKDATA_3264             = 0xc1
	PTRACE_PEEKSIGINFO               = 0x4209
	PTRACE_PEEKSIGINFO_SHARED        = 0x1
	PTRACE_PEEKTEXT                  = 0x1
	PTRACE_PEEKTEXT_3264             = 0xc0
	PTRACE_PEEKUSR                   = 0x3
	PTRACE_POKEDATA                  = 0x5
	PTRACE_POKEDATA_3264             = 0xc3
	PTRACE_POKETEXT                  = 0x4
	PTRACE_POKETEXT_3264             = 0xc2
	PTRACE_POKEUSR                   = 0x6
	PTRACE_SEIZE                     = 0x4206
	PTRACE_SETFPREGS                 = 0xf
	PTRACE_SETOPTIONS                = 0x4200
	PTRACE_SETREGS                   = 0xd
	PTRACE_SETREGSET                 = 0x4205
	PTRACE_SETSIGINFO                = 0x4203
	PTRACE_SETSIGMASK                = 0x420b
	PTRACE_SET_THREAD_AREA           = 0x1a
	PTRACE_SET_WATCH_REGS            = 0xd1
	PTRACE_SINGLESTEP                = 0x9
	PTRACE_SYSCALL                   = 0x18
	PTRACE_TRACEME                   = 0x0
	RLIMIT_AS                        = 0x6
	RLIMIT_CORE                      = 0x4
	RLIMIT_CPU                       = 0x0
	RLIMIT_DATA                      = 0x2
	RLIMIT_FSIZE                     = 0x1
	RLIMIT_NOFILE                    = 0x5
	RLIMIT_STACK                     = 0x3
	RLIM_INFINITY                    = -0x1
	RTAX_ADVMSS                      = 0x8
	RTAX_CWND                        = 0x7
	RTAX_FEATURES                    = 0xc
	RTAX_FEATURE_ALLFRAG             = 0x8
	RTAX_FEATURE_ECN                 = 0x1
	RTAX_FEATURE_SACK                = 0x2
	RTAX_FEATURE_TIMESTAMP           = 0x4
	RTAX_HOPLIMIT                    = 0xa
	RTAX_INITCWND                    = 0xb
	RTAX_INITRWND                    = 0xe
	RTAX_LOCK                        = 0x1
	RTAX_MAX                         = 0xf
	RTAX_MTU                         = 0x2
	RTAX_QUICKACK                    = 0xf
	RTAX_REORDERING                  = 0x9
	RTAX_RTO_MIN                     = 0xd
	RTAX_RTT                         = 0x4
	RTAX_RTTVAR                      = 0x5
	RTAX_SSTHRESH                    = 0x6
	RTAX_UNSPEC                      = 0x0
	RTAX_WINDOW                      = 0x3
	RTA_ALIGNTO                      = 0x4
	RTA_MAX                          = 0x11
	RTCF_DIRECTSRC                   = 0x4000000
	RTCF_DOREDIRECT                  = 0x1000000
	RTCF_LOG                         = 0x2000000
	RTCF_MASQ                        = 0x400000
	RTCF_NAT                         = 0x800000
	RTCF_VALVE                       = 0x200000
	RTF_ADDRCLASSMASK                = 0xf8000000
	RTF_ADDRCONF                     = 0x40000
	RTF_ALLONLINK                    = 0x20000
	RTF_BROADCAST                    = 0x10000000
	RTF_CACHE                        = 0x1000000
	RTF_DEFAULT                      = 0x10000
	RTF_DYNAMIC                      = 0x10
	RTF_FLOW                         = 0x2000000
	RTF_GATEWAY                      = 0x2
	RTF_HOST                         = 0x4
	RTF_INTERFACE                    = 0x40000000
	RTF_IRTT                         = 0x100
	RTF_LINKRT                       = 0x100000
	RTF_LOCAL                        = 0x80000000
	RTF_MODIFIED                     = 0x20
	RTF_MSS                          = 0x40
	RTF_MTU                          = 0x40
	RTF_MULTICAST                    = 0x20000000
	RTF_NAT                          = 0x8000000
	RTF_NOFORWARD                    = 0x1000
	RTF_NONEXTHOP                    = 0x200000
	RTF_NOPMTUDISC                   = 0x4000
	RTF_POLICY                       = 0x4000000
	RTF_REINSTATE                    = 0x8
	RTF_REJECT                       = 0x200
	RTF_STATIC                       = 0x400
	RTF_THROW                        = 0x2000
	RTF_UP                           = 0x1
	RTF_WINDOW                       = 0x80
	RTF_XRESOLVE                     = 0x800
	RTM_BASE                         = 0x10
	RTM_DELACTION                    = 0x31
	RTM_DELADDR                      = 0x15
	RTM_DELADDRLABEL                 = 0x49
	RTM_DELLINK                      = 0x11
	RTM_DELMDB                       = 0x55
	RTM_DELNEIGH                     = 0x1d
	RTM_DELQDISC                     = 0x25
	RTM_DELROUTE                     = 0x19
	RTM_DELRULE                      = 0x21
	RTM_DELTCLASS                    = 0x29
	RTM_DELTFILTER                   = 0x2d
	RTM_F_CLONED                     = 0x200
	RTM_F_EQUALIZE                   = 0x400
	RTM_F_NOTIFY                     = 0x100
	RTM_F_PREFIX                     = 0x800
	RTM_GETACTION                    = 0x32
	RTM_GETADDR                      = 0x16
	RTM_GETADDRLABEL                 = 0x4a
	RTM_GETANYCAST                   = 0x3e
	RTM_GETDCB                       = 0x4e
	RTM_GETLINK                      = 0x12
	RTM_GETMDB                       = 0x56
	RTM_GETMULTICAST                 = 0x3a
	RTM_GETNEIGH                     = 0x1e
	RTM_GETNEIGHTBL                  = 0x42
	RTM_GETNETCONF                   = 0x52
	RTM_GETQDISC                     = 0x26
	RTM_GETROUTE                     = 0x1a
	RTM_GETRULE                      = 0x22
	RTM_GETTCLASS                    = 0x2a
	RTM_GETTFILTER                   = 0x2e
	RTM_MAX                          = 0x57
	RTM_NEWACTION                    = 0x30
	RTM_NEWADDR                      = 0x14
	RTM_NEWADDRLABEL                 = 0x48
	RTM_NEWLINK                      = 0x10
	RTM_NEWMDB                       = 0x54
	RTM_NEWNDUSEROPT                 = 0x44
	RTM_NEWNEIGH                     = 0x1c
	RTM_NEWNEIGHTBL                  = 0x40
	RTM_NEWNETCONF                   = 0x50
	RTM_NEWPREFIX                    = 0x34
	RTM_NEWQDISC                     = 0x24
	RTM_NEWROUTE                     = 0x18
	RTM_NEWRULE                      = 0x20
	RTM_NEWTCLASS                    = 0x28
	RTM_NEWTFILTER                   = 0x2c
	RTM_NR_FAMILIES                  = 0x12
	RTM_NR_MSGTYPES                  = 0x48
	RTM_SETDCB                       = 0x4f
	RTM_SETLINK                      = 0x13
	RTM_SETNEIGHTBL                  = 0x43
	RTNH_ALIGNTO                     = 0x4
	RTNH_F_DEAD                      = 0x1
	RTNH_F_ONLINK                    = 0x4
	RTNH_F_PERVASIVE                 = 0x2
	RTN_MAX                          = 0xb
	RTPROT_BIRD                      = 0xc
	RTPROT_BOOT                      = 0x3
	RTPROT_DHCP                      = 0x10
	RTPROT_DNROUTED                  = 0xd
	RTPROT_GATED                     = 0x8
	RTPROT_KERNEL                    = 0x2
	RTPROT_MROUTED                   = 0x11
	RTPROT_MRT                       = 0xa
	RTPROT_NTK                       = 0xf
	RTPROT_RA                        = 0x9
	RTPROT_REDIRECT                  = 0x1
	RTPROT_STATIC                    = 0x4
	RTPROT_UNSPEC                    = 0x0
	RTPROT_XORP                      = 0xe
	RTPROT_ZEBRA                     = 0xb
	RT_CLASS_DEFAULT                 = 0xfd
	RT_CLASS_LOCAL                   = 0xff
	RT_CLASS_MAIN                    = 0xfe
	RT_CLASS_MAX                     = 0xff
	RT_CLASS_UNSPEC                  = 0x0
	RUSAGE_CHILDREN                  = -0x1
	RUSAGE_SELF                      = 0x0
	RUSAGE_THREAD                    = 0x1
	SCM_CREDENTIALS                  = 0x2
	SCM_RIGHTS                       = 0x1
	SCM_TIMESTAMP                    = 0x1d
	SCM_TIMESTAMPING                 = 0x25
	SCM_TIMESTAMPNS                  = 0x23
	SCM_WIFI_STATUS                  = 0x29
	SHUT_RD                          = 0x0
	SHUT_RDWR                        = 0x2
	SHUT_WR                          = 0x1
	SIOCADDDLCI                      = 0x8980
	SIOCADDMULTI                     = 0x8931
	SIOCADDRT                        = 0x890b
	SIOCATMARK                       = 0x40047307
	SIOCDARP                         = 0x8953
	SIOCDELDLCI                      = 0x8981
	SIOCDELMULTI                     = 0x8932
	SIOCDELRT                        = 0x890c
	SIOCDEVPRIVATE                   = 0x89f0
	SIOCDIFADDR                      = 0x8936
	SIOCDRARP                        = 0x8960
	SIOCGARP                         = 0x8954
	SIOCGIFADDR                      = 0x8915
	SIOCGIFBR                        = 0x8940
	SIOCGIFBRDADDR                   = 0x8919
	SIOCGIFCONF                      = 0x8912
	SIOCGIFCOUNT                     = 0x8938
	SIOCGIFDSTADDR                   = 0x8917
	SIOCGIFENCAP                     = 0x8925
	SIOCGIFFLAGS                     = 0x8913
	SIOCGIFHWADDR                    = 0x8927
	SIOCGIFINDEX                     = 0x8933
	SIOCGIFMAP                       = 0x8970
	SIOCGIFMEM                       = 0x891f
	SIOCGIFMETRIC                    = 0x891d
	SIOCGIFMTU                       = 0x8921
	SIOCGIFNAME                      = 0x8910
	SIOCGIFNETMASK                   = 0x891b
	SIOCGIFPFLAGS                    = 0x8935
	SIOCGIFSLAVE                     = 0x8929
	SIOCGIFTXQLEN                    = 0x8942
	SIOCGPGRP                        = 0x40047309
	SIOCGRARP                        = 0x8961
	SIOCGSTAMP                       = 0x8906
	SIOCGSTAMPNS                     = 0x8907
	SIOCPROTOPRIVATE                 = 0x89e0
	SIOCRTMSG                        = 0x890d
	SIOCSARP                         = 0x8955
	SIOCSIFADDR                      = 0x8916
	SIOCSIFBR                        = 0x8941
	SIOCSIFBRDADDR                   = 0x891a
	SIOCSIFDSTADDR                   = 0x8918
	SIOCSIFENCAP                     = 0x8926
	SIOCSIFFLAGS                     = 0x8914
	SIOCSIFHWADDR                    = 0x8924
	SIOCSIFHWBROADCAST               = 0x8937
	SIOCSIFLINK                      = 0x8911
	SIOCSIFMAP                       = 0x8971
	SIOCSIFMEM                       = 0x8920
	SIOCSIFMETRIC                    = 0x891e
	SIOCSIFMTU                       = 0x8922
	SIOCSIFNAME                      = 0x8923
	SIOCSIFNETMASK                   = 0x891c
	SIOCSIFPFLAGS                    = 0x8934
	SIOCSIFSLAVE                     = 0x8930
	SIOCSIFTXQLEN                    = 0x8943
	SIOCSPGRP                        = 0x80047308
	SIOCSRARP                        = 0x8962
	SOCK_CLOEXEC                     = 0x80000
	SOCK_DCCP                        = 0x6
	SOCK_DGRAM                       = 0x1
	SOCK_NONBLOCK                    = 0x80
	SOCK_PACKET                      = 0xa
	SOCK_RAW                         = 0x3
	SOCK_RDM                         = 0x4
	SOCK_SEQPACKET                   = 0x5
	SOCK_STREAM                      = 0x2
	SOL_AAL                          = 0x109
	SOL_ATM                          = 0x108
	SOL_DECNET                       = 0x105
	SOL_ICMPV6                       = 0x3a
	SOL_IP                           = 0x0
	SOL_IPV6                         = 0x29
	SOL_IRDA                         = 0x10a
	SOL_PACKET                       = 0x107
	SOL_RAW                          = 0xff
	SOL_SOCKET                       = 0xffff
	SOL_TCP                          = 0x6
	SOL_X25                          = 0x106
	SOMAXCONN                        = 0x80
	SO_ACCEPTCONN                    = 0x1009
	SO_ATTACH_FILTER                 = 0x1a
	SO_BINDTODEVICE                  = 0x19
	SO_BPF_EXTENSIONS                = 0x30
	SO_BROADCAST                     = 0x20
	SO_BSDCOMPAT                     = 0xe
	SO_BUSY_POLL                     = 0x2e
	SO_DEBUG                         = 0x1
	SO_DETACH_FILTER                 = 0x1b
	SO_DOMAIN                        = 0x1029
	SO_DONTROUTE                     = 0x10
	SO_ERROR                         = 0x1007
	SO_GET_FILTER                    = 0x1a
	SO_KEEPALIVE                     = 0x8
	SO_LINGER                        = 0x80
	SO_LOCK_FILTER                   = 0x2c
	SO_MARK                          = 0x24
	SO_MAX_PACING_RATE               = 0x2f
	SO_NOFCS                         = 0x2b
	SO_NO_CHECK                      = 0xb
	SO_OOBINLINE                     = 0x100
	SO_PASSCRED                      = 0x11
	SO_PASSSEC                       = 0x22
	SO_PEEK_OFF                      = 0x2a
	SO_PEERCRED                      = 0x12
	SO_PEERNAME                      = 0x1c
	SO_PEERSEC                       = 0x1e
	SO_PRIORITY                      = 0xc
	SO_PROTOCOL                      = 0x1028
	SO_RCVBUF                        = 0x1002
	SO_RCVBUFFORCE                   = 0x21
	SO_RCVLOWAT                      = 0x1004
	SO_RCVTIMEO                      = 0x1006
	SO_REUSEADDR                     = 0x4
	SO_REUSEPORT                     = 0x200
	SO_RXQ_OVFL                      = 0x28
	SO_SECURITY_AUTHENTICATION       = 0x16
	SO_SECURITY_ENCRYPTION_NETWORK   = 0x18
	SO_SECURITY_ENCRYPTION_TRANSPORT = 0x17
	SO_SELECT_ERR_QUEUE              = 0x2d
	SO_SNDBUF                        = 0x1001
	SO_SNDBUFFORCE                   = 0x1f
	SO_SNDLOWAT                      = 0x1003
	SO_SNDTIMEO                      = 0x1005
	SO_STYLE                         = 0x1008
	SO_TIMESTAMP                     = 0x1d
	SO_TIMESTAMPING                  = 0x25
	SO_TIMESTAMPNS                   = 0x23
	SO_TYPE                          = 0x1008
	SO_WIFI_STATUS                   = 0x29
	S_BLKSIZE                        = 0x200
	S_IEXEC                          = 0x40
	S_IFBLK                          = 0x6000
	S_IFCHR                          = 0x2000
	S_IFDIR                          = 0x4000
	S_IFIFO                          = 0x1000
	S_IFLNK                          = 0xa000
	S_IFMT                           = 0xf000
	S_IFREG                          = 0x8000
	S_IFSOCK                         = 0xc000
	S_IREAD                          = 0x100
	S_IRGRP                          = 0x20
	S_IROTH                          = 0x4
	S_IRUSR                          = 0x100
	S_IRWXG                          = 0x38
	S_IRWXO                          = 0x7
	S_IRWXU                          = 0x1c0
	S_ISGID                          = 0x400
	S_ISUID                          = 0x800
	S_ISVTX                          = 0x200
	S_IWGRP                          = 0x10
	S_IWOTH                          = 0x2
	S_IWRITE                         = 0x80
	S_IWUSR                          = 0x80
	S_IXGRP                          = 0x8
	S_IXOTH                          = 0x1
	S_IXUSR                          = 0x40
	TCFLSH                           = 0x5407
	TCIFLUSH                         = 0x0
	TCIOFLUSH                        = 0x2
	TCOFLUSH                         = 0x1
	TCP_CONGESTION                   = 0xd
	TCP_COOKIE_IN_ALWAYS             = 0x1
	TCP_COOKIE_MAX                   = 0x10
	TCP_COOKIE_MIN                   = 0x8
	TCP_COOKIE_OUT_NEVER             = 0x2
	TCP_COOKIE_PAIR_SIZE             = 0x20
	TCP_COOKIE_TRANSACTIONS          = 0xf
	TCP_CORK                         = 0x3
	TCP_DEFER_ACCEPT                 = 0x9
	TCP_FASTOPEN                     = 0x17
	TCP_INFO                         = 0xb
	TCP_KEEPCNT                      = 0x6
	TCP_KEEPIDLE                     = 0x4
	TCP_KEEPINTVL                    = 0x5
	TCP_LINGER2                      = 0x8
	TCP_MAXSEG                       = 0x2
	TCP_MAXWIN                       = 0xffff
	TCP_MAX_WINSHIFT                 = 0xe
	TCP_MD5SIG                       = 0xe
	TCP_MD5SIG_MAXKEYLEN             = 0x50
	TCP_MSS                          = 0x200
	TCP_MSS_DEFAULT                  = 0x218
	TCP_MSS_DESIRED                  = 0x4c4
	TCP_NODELAY                      = 0x1
	TCP_QUEUE_SEQ                    = 0x15
	TCP_QUICKACK                     = 0xc
	TCP_REPAIR                       = 0x13
	TCP_REPAIR_OPTIONS               = 0x16
	TCP_REPAIR_QUEUE                 = 0x14
	TCP_SYNCNT                       = 0x7
	TCP_S_DATA_IN                    = 0x4
	TCP_S_DATA_OUT                   = 0x8
	TCP_THIN_DUPACK                  = 0x11
	TCP_THIN_LINEAR_TIMEOUTS         = 0x10
	TCP_TIMESTAMP                    = 0x18
	TCP_USER_TIMEOUT                 = 0x12
	TCP_WINDOW_CLAMP                 = 0xa
	TCSAFLUSH                        = 0x5410
	TIOCCBRK                         = 0x5428
	TIOCCONS                         = 0x80047478
	TIOCEXCL                         = 0x740d
	TIOCGDEV                         = 0x40045432
	TIOCGETD                         = 0x7400
	TIOCGETP                         = 0x7408
	TIOCGEXCL                        = 0x40045440
	TIOCGICOUNT                      = 0x5492
	TIOCGLCKTRMIOS                   = 0x548b
	TIOCGLTC                         = 0x7474
	TIOCGPGRP                        = 0x40047477
	TIOCGPKT                         = 0x40045438
	TIOCGPTLCK                       = 0x40045439
	TIOCGPTN                         = 0x40045430
	TIOCGSERIAL                      = 0x5484
	TIOCGSID                         = 0x7416
	TIOCGSOFTCAR                     = 0x5481
	TIOCGWINSZ                       = 0x40087468
	TIOCINQ                          = 0x467f
	TIOCLINUX                        = 0x5483
	TIOCMBIC                         = 0x741c
	TIOCMBIS                         = 0x741b
	TIOCMGET                         = 0x741d
	TIOCMIWAIT                       = 0x5491
	TIOCMSET                         = 0x741a
	TIOCM_CAR                        = 0x100
	TIOCM_CD                         = 0x100
	TIOCM_CTS                        = 0x40
	TIOCM_DSR                        = 0x400
	TIOCM_DTR                        = 0x2
	TIOCM_LE                         = 0x1
	TIOCM_RI                         = 0x200
	TIOCM_RNG                        = 0x200
	TIOCM_RTS                        = 0x4
	TIOCM_SR                         = 0x20
	TIOCM_ST                         = 0x10
	TIOCNOTTY                        = 0x5471
	TIOCNXCL                         = 0x740e
	TIOCOUTQ                         = 0x7472
	TIOCPKT                          = 0x5470
	TIOCPKT_DATA                     = 0x0
	TIOCPKT_DOSTOP                   = 0x20
	TIOCPKT_FLUSHREAD                = 0x1
	TIOCPKT_FLUSHWRITE               = 0x2
	TIOCPKT_IOCTL                    = 0x40
	TIOCPKT_NOSTOP                   = 0x10
	TIOCPKT_START                    = 0x8
	TIOCPKT_STOP                     = 0x4
	TIOCSBRK                         = 0x5427
	TIOCSCTTY                        = 0x5480
	TIOCSERCONFIG                    = 0x5488
	TIOCSERGETLSR                    = 0x548e
	TIOCSERGETMULTI                  = 0x548f
	TIOCSERGSTRUCT                   = 0x548d
	TIOCSERGWILD                     = 0x5489
	TIOCSERSETMULTI                  = 0x5490
	TIOCSERSWILD                     = 0x548a
	TIOCSER_TEMT                     = 0x1
	TIOCSETD                         = 0x7401
	TIOCSETN                         = 0x740a
	TIOCSETP                         = 0x7409
	TIOCSIG                          = 0x80045436
	TIOCSLCKTRMIOS                   = 0x548c
	TIOCSLTC                         = 0x7475
	TIOCSPGRP                        = 0x80047476
	TIOCSPTLCK                       = 0x80045431
	TIOCSSERIAL                      = 0x5485
	TIOCSSOFTCAR                     = 0x5482
	TIOCSTI                          = 0x5472
	TIOCSWINSZ                       = 0x80087467
	TIOCVHANGUP                      = 0x5437
	TOSTOP                           = 0x8000
	TUNATTACHFILTER                  = 0x800854d5
	TUNDETACHFILTER                  = 0x800854d6
	TUNGETFEATURES                   = 0x400454cf
	TUNGETFILTER                     = 0x400854db
	TUNGETIFF                        = 0x400454d2
	TUNGETSNDBUF                     = 0x400454d3
	TUNGETVNETHDRSZ                  = 0x400454d7
	TUNSETDEBUG                      = 0x800454c9
	TUNSETGROUP                      = 0x800454ce
	TUNSETIFF                        = 0x800454ca
	TUNSETIFINDEX                    = 0x800454da
	TUNSETLINK                       = 0x800454cd
	TUNSETNOCSUM                     = 0x800454c8
	TUNSETOFFLOAD                    = 0x800454d0
	TUNSETOWNER                      = 0x800454cc
	TUNSETPERSIST                    = 0x800454cb
	TUNSETQUEUE                      = 0x800454d9
	TUNSETSNDBUF                     = 0x800454d4
	TUNSETTXFILTER                   = 0x800454d1
	TUNSETVNETHDRSZ                  = 0x800454d8
	VDISCARD                         = 0xd
	VEOF                             = 0x10
	VEOL                             = 0x11
	VEOL2                            = 0x6
	VERASE                           = 0x2
	VINTR                            = 0x0
	VKILL                            = 0x3
	VLNEXT                           = 0xf
	VMIN                             = 0x4
	VQUIT                            = 0x1
	VREPRINT                         = 0xc
	VSTART                           = 0x8
	VSTOP                            = 0x9
	VSUSP                            = 0xa
	VSWTC                            = 0x7
	VSWTCH                           = 0x7
	VT0                              = 0x0
	VT1                              = 0x4000
	VTDLY                            = 0x4000
	VTIME                            = 0x5
	VWERASE                          = 0xe
	WALL                             = 0x40000000
	WCLONE                           = 0x80000000
	WCONTINUED                       = 0x8
	WEXITED                          = 0x4
	WNOHANG                          = 0x1
	WNOTHREAD                        = 0x20000000
	WNOWAIT                          = 0x1000000
	WORDSIZE                         = 0x20
	WSTOPPED                         = 0x2
	WUNTRACED                        = 0x2
)

// Errors
const (
	E2BIG           = Errno(0x7)
	EACCES          = Errno(0xd)
	EADDRINUSE      = Errno(0x7d)
	EADDRNOTAVAIL   = Errno(0x7e)
	EADV            = Errno(0x44)
	EAFNOSUPPORT    = Errno(0x7c)
	EAGAIN          = Errno(0xb)
	EALREADY        = Errno(0x95)
	EBADE           = Errno(0x32)
	EBADF           = Errno(0x9)
	EBADFD          = Errno(0x51)
	EBADMSG         = Errno(0x4d)
	EBADR           = Errno(0x33)
	EBADRQC         = Errno(0x36)
	EBADSLT         = Errno(0x37)
	EBFONT          = Errno(0x3b)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x9e)
	ECHILD          = Errno(0xa)
	ECHRNG          = Errno(0x25)
	ECOMM           = Errno(0x46)
	ECONNABORTED    = Errno(0x82)
	ECONNREFUSED    = Errno(0x92)
	ECONNRESET      = Errno(0x83)
	EDEADLK         = Errno(0x2d)
	EDEADLOCK       = Errno(0x38)
	EDESTADDRREQ    = Errno(0x60)
	EDOM            = Errno(0x21)
	EDOTDOT         = Errno(0x49)
	EDQUOT          = Errno(0x46d)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EHOSTDOWN       = Errno(0x93)
	EHOSTUNREACH    = Errno(0x94)
	EHWPOISON       = Errno(0xa8)
	EIDRM           = Errno(0x24)
	EILSEQ          = Errno(0x58)
	EINIT           = Errno(0x8d)
	EINPROGRESS     = Errno(0x96)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EISCONN         = Errno(0x85)
	EISDIR          = Errno(0x15)
	EISNAM          = Errno(0x8b)
	EKEYEXPIRED     = Errno(0xa2)
	EKEYREJECTED    = Errno(0xa4)
	EKEYREVOKED     = Errno(0xa3)
	EL2HLT          = Errno(0x2c)
	EL2NSYNC        = Errno(0x26)
	EL3HLT          = Errno(0x27)
	EL3RST          = Errno(0x28)
	ELIBACC         = Errno(0x53)
	ELIBBAD         = Errno(0x54)
	ELIBEXEC        = Errno(0x57)
	ELIBMAX         = Errno(0x56)
	ELIBSCN         = Errno(0x55)
	ELNRNG          = Errno(0x29)
	ELOOP           = Errno(0x5a)
	EMEDIUMTYPE     = Errno(0xa0)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x61)
	EMULTIHOP       = Errno(0x4a)
	ENAMETOOLONG    = Errno(0x4e)
	ENAVAIL         = Errno(0x8a)
	ENETDOWN        = Errno(0x7f)
	ENETRESET       = Errno(0x81)
	ENETUNREACH     = Errno(0x80)
	ENFILE          = Errno(0x17)
	ENOANO          = Errno(0x35)
	ENOBUFS         = Errno(0x84)
	ENOCSI          = Errno(0x2b)
	ENODATA         = Errno(0x3d)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOKEY          = Errno(0xa1)
	ENOLCK          = Errno(0x2e)
	ENOLINK         = Errno(0x43)
	ENOMEDIUM       = Errno(0x9f)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x23)
	ENONET          = Errno(0x40)
	ENOPKG          = Errno(0x41)
	ENOPROTOOPT     = Errno(0x63)
	ENOSPC          = Errno(0x1c)
	ENOSR           = Errno(0x3f)
	ENOSTR          = Errno(0x3c)
	ENOSYS          = Errno(0x59)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x86)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x5d)
	ENOTNAM         = Errno(0x89)
	ENOTRECOVERABLE = Errno(0xa6)
	ENOTSOCK        = Errno(0x5f)
	ENOTSUP         = Errno(0x7a)
	ENOTTY          = Errno(0x19)
	ENOTUNIQ        = Errno(0x50)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x7a)
	EOVERFLOW       = Errno(0x4f)
	EOWNERDEAD      = Errno(0xa5)
	EPERM           = Errno(0x1)
	EPFNOSUPPORT    = Errno(0x7b)
	EPIPE           = Errno(0x20)
	EPROTO          = Errno(0x47)
	EPROTONOSUPPORT = Errno(0x78)
	EPROTOTYPE      = Errno(0x62)
	ERANGE          = Errno(0x22)
	EREMCHG         = Errno(0x52)
	EREMDEV         = Errno(0x8e)
	EREMOTE         = Errno(0x42)
	EREMOTEIO       = Errno(0x8c)
	ERESTART        = Errno(0x5b)
	ERFKILL         = Errno(0xa7)
	EROFS           = Errno(0x1e)
	ESHUTDOWN       = Errno(0x8f)
	ESOCKTNOSUPPORT = Errno(0x79)
	ESPIPE          = Errno(0x1d)
	ESRCH           = Errno(0x3)
	ESRMNT          = Errno(0x45)
	ESTALE          = Errno(0x97)
	ESTRPIPE        = Errno(0x5c)
	ETIME           = Errno(0x3e)
	ETIMEDOUT       = Errno(0x91)
	ETOOMANYREFS    = Errno(0x90)
	ETXTBSY         = Errno(0x1a)
	EUCLEAN         = Errno(0x87)
	EUNATCH         = Errno(0x2a)
	EUSERS          = Errno(0x5e)
	EWOULDBLOCK     = Errno(0xb)
	EXDEV           = Errno(0x12)
	EXFULL          = Errno(0x34)
)

// Signals
const (
	SIGABRT   = Signal(0x6)
	SIGALRM   = Signal(0xe)
	SIGBUS    = Signal(0xa)
	SIGCHLD   = Signal(0x12)
	SIGCLD    = Signal(0x12)
	SIGCONT   = Signal(0x19)
	SIGEMT    = Signal(0x7)
	SIGFPE    = Signal(0x8)
	SIGHUP    = Signal(0x1)
	SIGILL    = Signal(0x4)
	SIGINT    = Signal(0x2)
	SIGIO     = Signal(0x16)
	SIGIOT    = Signal(0x6)
	SIGKILL   = Signal(0x9)
	SIGPIPE   = Signal(0xd)
	SIGPOLL   = Signal(0x16)
	SIGPROF   = Signal(0x1d)
	SIGPWR    = Signal(0x13)
	SIGQUIT   = Signal(0x3)
	SIGSEGV   = Signal(0xb)
	SIGSTOP   = Signal(0x17)
	SIGSYS    = Signal(0xc)
	SIGTERM   = Signal(0xf)
	SIGTRAP   = Signal(0x5)
	SIGTSTP   = Signal(0x18)
	SIGTTIN   = Signal(0x1a)
	SIGTTOU   = Signal(0x1b)
	SIGURG    = Signal(0x15)
	SIGUSR1   = Signal(0x10)
	SIGUSR2   = Signal(0x11)
	SIGVTALRM = Signal(0x1c)
	SIGWINCH  = Signal(0x14)
	SIGXCPU   = Signal(0x1e)
	SIGXFSZ   = Signal(0x1f)
)

// Error tabl
"""




```