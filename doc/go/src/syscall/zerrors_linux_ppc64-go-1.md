Response:
The user is asking for a summary of the functionality of the provided Go code snippet. This code defines a large number of constants, which appear to be related to system calls and error codes on a Linux system, specifically for the ppc64 architecture.

Therefore, the core functionality is to define platform-specific numerical values for various system-level concepts.
这是路径为go/src/syscall/zerrors_linux_ppc64.go的go语言实现的一部分，它定义了一系列与Linux操作系统在ppc64架构下相关的常量。这些常量主要用于系统调用（syscall）相关的操作，包括：

1. **网络相关的常量 (PACKET\_*, SOL\_*, SO\_*, SIOC\*)**:  定义了网络协议栈中使用的各种标志、选项和ioctl命令。例如，`PACKET_FANOUT` 定义了数据包扇出的类型， `SOL_SOCKET` 定义了通用套接字选项的级别， `SO_REUSEADDR` 定义了允许重用本地地址和端口的套接字选项， `SIOCGIFADDR` 定义了获取网络接口地址的ioctl命令。

2. **进程控制相关的常量 (PRIO\_*, PR\_*, PTRACE\_*, RLIMIT\_*, RUSAGE\_*)**:  定义了与进程优先级、进程属性、ptrace调试以及资源限制相关的常量。例如，`PRIO_PROCESS` 定义了进程优先级的类型， `PR_SET_DUMPABLE` 定义了设置进程是否可被dump的选项， `PTRACE_ATTACH` 定义了ptrace attach操作的常量， `RLIMIT_NOFILE` 定义了可以打开的最大文件描述符数量的资源限制， `RUSAGE_SELF` 定义了获取当前进程资源使用情况的选项。

3. **文件系统和IO相关的常量 (S\_IF\*, S\_IR\*,  TC\*)**: 定义了文件类型、文件权限以及终端控制相关的常量。例如，`S_IFREG` 定义了普通文件的类型， `S_IRUSR` 定义了用户读权限， `TCIFLUSH` 定义了清空终端输入缓冲区的常量。

4. **错误码常量 (E\*)**:  定义了各种系统调用可能返回的错误码。例如， `EACCES` 表示权限被拒绝错误， `ENOENT` 表示没有该文件或目录的错误。

5. **路由相关的常量 (RTAX\_*, RTF\_*, RTM\_*, RTNH\_*, RTPROT\_*, RT\_CLASS\_*)**: 定义了与网络路由相关的属性、标志和消息类型。例如，`RTAX_MTU` 定义了最大传输单元的路由属性， `RTF_UP` 定义了路由是激活的标志， `RTM_NEWROUTE` 定义了创建新路由的消息类型。

6. **Socket选项相关的常量 (SOCK\_*)**: 定义了创建socket时可以指定的类型。例如，`SOCK_STREAM` 定义了TCP流式socket， `SOCK_DGRAM` 定义了UDP数据报socket。

7. **信号相关的常量 (SIG\*)**: 虽然这部分代码片段中没有直接包含 `SIG*` 常量，但是从其定义的大量系统调用相关常量来看，整个文件很可能也包含了信号相关的定义。

8. **其他常量**:  还包含了一些不属于上述明确分类的常量，例如 `SCM_RIGHTS` 用于在进程间传递文件描述符。

**总结：** 这个代码片段定义了Linux操作系统在ppc64架构下进行系统编程时需要用到的大量常量，涵盖了网络、进程控制、文件系统、错误处理、路由等多个方面。 这些常量是Go语言的 `syscall` 包与底层操作系统交互的基础。

由于这部分代码主要定义的是常量，很难直接用Go代码示例来“实现”它的功能。它的作用更多的是提供预定义的数值，供其他 `syscall` 包中的函数使用。

**可以推理出它是什么go语言功能的实现：**

这部分代码是 Go 语言 `syscall` 包的一部分，该包提供了访问底层操作系统调用的能力。 `zerrors_linux_ppc64.go` 文件专门为 Linux 操作系统和 ppc64 架构定义了相关的常量。

**使用者易犯错的点：**

由于这些是底层常量，普通 Go 开发者一般不会直接使用。 开发者更容易犯错的是**误解或错误使用 `syscall` 包中的函数**，而不是直接使用这些常量。 例如，如果错误地设置了传递给 `syscall.Socket` 函数的协议族或套接字类型参数，就可能导致网络连接失败。

**归纳一下它的功能 (第2部分):**

此代码片段的主要功能是**为Go语言在Linux ppc64架构上进行底层系统编程提供必要的数值常量**。 这些常量用于标识各种系统调用参数、选项、标志和错误码，是 Go 语言 `syscall` 包与 Linux 内核交互的基础。 它就像一本“字典”，定义了 Go 程序与操作系统沟通时使用的“术语”。

Prompt: 
```
这是路径为go/src/syscall/zerrors_linux_ppc64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
ROP_MEMBERSHIP           = 0x2
	PACKET_FANOUT                    = 0x12
	PACKET_FANOUT_CPU                = 0x2
	PACKET_FANOUT_FLAG_DEFRAG        = 0x8000
	PACKET_FANOUT_FLAG_ROLLOVER      = 0x1000
	PACKET_FANOUT_HASH               = 0x0
	PACKET_FANOUT_LB                 = 0x1
	PACKET_FANOUT_RND                = 0x4
	PACKET_FANOUT_ROLLOVER           = 0x3
	PACKET_FASTROUTE                 = 0x6
	PACKET_HDRLEN                    = 0xb
	PACKET_HOST                      = 0x0
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
	PACKET_RECV_OUTPUT               = 0x3
	PACKET_RESERVE                   = 0xc
	PACKET_RX_RING                   = 0x5
	PACKET_STATISTICS                = 0x6
	PACKET_TIMESTAMP                 = 0x11
	PACKET_TX_HAS_OFF                = 0x13
	PACKET_TX_RING                   = 0xd
	PACKET_TX_TIMESTAMP              = 0x10
	PACKET_VERSION                   = 0xa
	PACKET_VNET_HDR                  = 0xf
	PARENB                           = 0x1000
	PARITY_CRC16_PR0                 = 0x2
	PARITY_CRC16_PR0_CCITT           = 0x4
	PARITY_CRC16_PR1                 = 0x3
	PARITY_CRC16_PR1_CCITT           = 0x5
	PARITY_CRC32_PR0_CCITT           = 0x6
	PARITY_CRC32_PR1_CCITT           = 0x7
	PARITY_DEFAULT                   = 0x0
	PARITY_NONE                      = 0x1
	PARMRK                           = 0x8
	PARODD                           = 0x2000
	PENDIN                           = 0x20000000
	PRIO_PGRP                        = 0x1
	PRIO_PROCESS                     = 0x0
	PRIO_USER                        = 0x2
	PROT_EXEC                        = 0x4
	PROT_GROWSDOWN                   = 0x1000000
	PROT_GROWSUP                     = 0x2000000
	PROT_NONE                        = 0x0
	PROT_READ                        = 0x1
	PROT_SAO                         = 0x10
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
	PR_SET_PTRACER_ANY               = -0x1
	PR_SET_SECCOMP                   = 0x16
	PR_SET_SECUREBITS                = 0x1c
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
	PTRACE_GETEVRREGS                = 0x14
	PTRACE_GETFPREGS                 = 0xe
	PTRACE_GETREGS                   = 0xc
	PTRACE_GETREGS64                 = 0x16
	PTRACE_GETREGSET                 = 0x4204
	PTRACE_GETSIGINFO                = 0x4202
	PTRACE_GETSIGMASK                = 0x420a
	PTRACE_GETVRREGS                 = 0x12
	PTRACE_GETVSRREGS                = 0x1b
	PTRACE_GET_DEBUGREG              = 0x19
	PTRACE_INTERRUPT                 = 0x4207
	PTRACE_KILL                      = 0x8
	PTRACE_LISTEN                    = 0x4208
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
	PTRACE_PEEKSIGINFO               = 0x4209
	PTRACE_PEEKSIGINFO_SHARED        = 0x1
	PTRACE_PEEKTEXT                  = 0x1
	PTRACE_PEEKUSR                   = 0x3
	PTRACE_POKEDATA                  = 0x5
	PTRACE_POKETEXT                  = 0x4
	PTRACE_POKEUSR                   = 0x6
	PTRACE_SEIZE                     = 0x4206
	PTRACE_SETEVRREGS                = 0x15
	PTRACE_SETFPREGS                 = 0xf
	PTRACE_SETOPTIONS                = 0x4200
	PTRACE_SETREGS                   = 0xd
	PTRACE_SETREGS64                 = 0x17
	PTRACE_SETREGSET                 = 0x4205
	PTRACE_SETSIGINFO                = 0x4203
	PTRACE_SETSIGMASK                = 0x420b
	PTRACE_SETVRREGS                 = 0x13
	PTRACE_SETVSRREGS                = 0x1c
	PTRACE_SET_DEBUGREG              = 0x1a
	PTRACE_SINGLEBLOCK               = 0x100
	PTRACE_SINGLESTEP                = 0x9
	PTRACE_SYSCALL                   = 0x18
	PTRACE_TRACEME                   = 0x0
	PT_CCR                           = 0x26
	PT_CTR                           = 0x23
	PT_DAR                           = 0x29
	PT_DSCR                          = 0x2c
	PT_DSISR                         = 0x2a
	PT_FPR0                          = 0x30
	PT_FPSCR                         = 0x50
	PT_LNK                           = 0x24
	PT_MSR                           = 0x21
	PT_NIP                           = 0x20
	PT_ORIG_R3                       = 0x22
	PT_R0                            = 0x0
	PT_R1                            = 0x1
	PT_R10                           = 0xa
	PT_R11                           = 0xb
	PT_R12                           = 0xc
	PT_R13                           = 0xd
	PT_R14                           = 0xe
	PT_R15                           = 0xf
	PT_R16                           = 0x10
	PT_R17                           = 0x11
	PT_R18                           = 0x12
	PT_R19                           = 0x13
	PT_R2                            = 0x2
	PT_R20                           = 0x14
	PT_R21                           = 0x15
	PT_R22                           = 0x16
	PT_R23                           = 0x17
	PT_R24                           = 0x18
	PT_R25                           = 0x19
	PT_R26                           = 0x1a
	PT_R27                           = 0x1b
	PT_R28                           = 0x1c
	PT_R29                           = 0x1d
	PT_R3                            = 0x3
	PT_R30                           = 0x1e
	PT_R31                           = 0x1f
	PT_R4                            = 0x4
	PT_R5                            = 0x5
	PT_R6                            = 0x6
	PT_R7                            = 0x7
	PT_R8                            = 0x8
	PT_R9                            = 0x9
	PT_REGS_COUNT                    = 0x2c
	PT_RESULT                        = 0x2b
	PT_SOFTE                         = 0x27
	PT_TRAP                          = 0x28
	PT_VR0                           = 0x52
	PT_VRSAVE                        = 0x94
	PT_VSCR                          = 0x93
	PT_VSR0                          = 0x96
	PT_VSR31                         = 0xd4
	PT_XER                           = 0x25
	RLIMIT_AS                        = 0x9
	RLIMIT_CORE                      = 0x4
	RLIMIT_CPU                       = 0x0
	RLIMIT_DATA                      = 0x2
	RLIMIT_FSIZE                     = 0x1
	RLIMIT_NOFILE                    = 0x7
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
	SIOCATMARK                       = 0x8905
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
	SIOCGPGRP                        = 0x8904
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
	SIOCSPGRP                        = 0x8902
	SIOCSRARP                        = 0x8962
	SOCK_CLOEXEC                     = 0x80000
	SOCK_DCCP                        = 0x6
	SOCK_DGRAM                       = 0x2
	SOCK_NONBLOCK                    = 0x800
	SOCK_PACKET                      = 0xa
	SOCK_RAW                         = 0x3
	SOCK_RDM                         = 0x4
	SOCK_SEQPACKET                   = 0x5
	SOCK_STREAM                      = 0x1
	SOL_AAL                          = 0x109
	SOL_ATM                          = 0x108
	SOL_DECNET                       = 0x105
	SOL_ICMPV6                       = 0x3a
	SOL_IP                           = 0x0
	SOL_IPV6                         = 0x29
	SOL_IRDA                         = 0x10a
	SOL_PACKET                       = 0x107
	SOL_RAW                          = 0xff
	SOL_SOCKET                       = 0x1
	SOL_TCP                          = 0x6
	SOL_X25                          = 0x106
	SOMAXCONN                        = 0x80
	SO_ACCEPTCONN                    = 0x1e
	SO_ATTACH_FILTER                 = 0x1a
	SO_BINDTODEVICE                  = 0x19
	SO_BROADCAST                     = 0x6
	SO_BSDCOMPAT                     = 0xe
	SO_BUSY_POLL                     = 0x2e
	SO_DEBUG                         = 0x1
	SO_DETACH_FILTER                 = 0x1b
	SO_DOMAIN                        = 0x27
	SO_DONTROUTE                     = 0x5
	SO_ERROR                         = 0x4
	SO_GET_FILTER                    = 0x1a
	SO_KEEPALIVE                     = 0x9
	SO_LINGER                        = 0xd
	SO_LOCK_FILTER                   = 0x2c
	SO_MARK                          = 0x24
	SO_MAX_PACING_RATE               = 0x2f
	SO_NOFCS                         = 0x2b
	SO_NO_CHECK                      = 0xb
	SO_OOBINLINE                     = 0xa
	SO_PASSCRED                      = 0x14
	SO_PASSSEC                       = 0x22
	SO_PEEK_OFF                      = 0x2a
	SO_PEERCRED                      = 0x15
	SO_PEERNAME                      = 0x1c
	SO_PEERSEC                       = 0x1f
	SO_PRIORITY                      = 0xc
	SO_PROTOCOL                      = 0x26
	SO_RCVBUF                        = 0x8
	SO_RCVBUFFORCE                   = 0x21
	SO_RCVLOWAT                      = 0x10
	SO_RCVTIMEO                      = 0x12
	SO_REUSEADDR                     = 0x2
	SO_REUSEPORT                     = 0xf
	SO_RXQ_OVFL                      = 0x28
	SO_SECURITY_AUTHENTICATION       = 0x16
	SO_SECURITY_ENCRYPTION_NETWORK   = 0x18
	SO_SECURITY_ENCRYPTION_TRANSPORT = 0x17
	SO_SELECT_ERR_QUEUE              = 0x2d
	SO_SNDBUF                        = 0x7
	SO_SNDBUFFORCE                   = 0x20
	SO_SNDLOWAT                      = 0x11
	SO_SNDTIMEO                      = 0x13
	SO_TIMESTAMP                     = 0x1d
	SO_TIMESTAMPING                  = 0x25
	SO_TIMESTAMPNS                   = 0x23
	SO_TYPE                          = 0x3
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
	TCFLSH                           = 0x2000741f
	TCIFLUSH                         = 0x0
	TCIOFLUSH                        = 0x2
	TCOFLUSH                         = 0x1
	TCP_CONGESTION                   = 0xd
	TCP_CORK                         = 0x3
	TCP_DEFER_ACCEPT                 = 0x9
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
	TCP_NODELAY                      = 0x1
	TCP_QUICKACK                     = 0xc
	TCP_SYNCNT                       = 0x7
	TCP_WINDOW_CLAMP                 = 0xa
	TCSAFLUSH                        = 0x2
	TIOCCBRK                         = 0x5428
	TIOCCONS                         = 0x541d
	TIOCEXCL                         = 0x540c
	TIOCGDEV                         = 0x40045432
	TIOCGETC                         = 0x40067412
	TIOCGETD                         = 0x5424
	TIOCGETP                         = 0x40067408
	TIOCGEXCL                        = 0x40045440
	TIOCGICOUNT                      = 0x545d
	TIOCGLCKTRMIOS                   = 0x5456
	TIOCGLTC                         = 0x40067474
	TIOCGPGRP                        = 0x40047477
	TIOCGPKT                         = 0x40045438
	TIOCGPTLCK                       = 0x40045439
	TIOCGPTN                         = 0x40045430
	TIOCGRS485                       = 0x542e
	TIOCGSERIAL                      = 0x541e
	TIOCGSID                         = 0x5429
	TIOCGSOFTCAR                     = 0x5419
	TIOCGWINSZ                       = 0x40087468
	TIOCINQ                          = 0x4004667f
	TIOCLINUX                        = 0x541c
	TIOCMBIC                         = 0x5417
	TIOCMBIS                         = 0x5416
	TIOCMGET                         = 0x5415
	TIOCMIWAIT                       = 0x545c
	TIOCMSET                         = 0x5418
	TIOCM_CAR                        = 0x40
	TIOCM_CD                         = 0x40
	TIOCM_CTS                        = 0x20
	TIOCM_DSR                        = 0x100
	TIOCM_DTR                        = 0x2
	TIOCM_LE                         = 0x1
	TIOCM_LOOP                       = 0x8000
	TIOCM_OUT1                       = 0x2000
	TIOCM_OUT2                       = 0x4000
	TIOCM_RI                         = 0x80
	TIOCM_RNG                        = 0x80
	TIOCM_RTS                        = 0x4
	TIOCM_SR                         = 0x10
	TIOCM_ST                         = 0x8
	TIOCNOTTY                        = 0x5422
	TIOCNXCL                         = 0x540d
	TIOCOUTQ                         = 0x40047473
	TIOCPKT                          = 0x5420
	TIOCPKT_DATA                     = 0x0
	TIOCPKT_DOSTOP                   = 0x20
	TIOCPKT_FLUSHREAD                = 0x1
	TIOCPKT_FLUSHWRITE               = 0x2
	TIOCPKT_IOCTL                    = 0x40
	TIOCPKT_NOSTOP                   = 0x10
	TIOCPKT_START                    = 0x8
	TIOCPKT_STOP                     = 0x4
	TIOCSBRK                         = 0x5427
	TIOCSCTTY                        = 0x540e
	TIOCSERCONFIG                    = 0x5453
	TIOCSERGETLSR                    = 0x5459
	TIOCSERGETMULTI                  = 0x545a
	TIOCSERGSTRUCT                   = 0x5458
	TIOCSERGWILD                     = 0x5454
	TIOCSERSETMULTI                  = 0x545b
	TIOCSERSWILD                     = 0x5455
	TIOCSER_TEMT                     = 0x1
	TIOCSETC                         = 0x80067411
	TIOCSETD                         = 0x5423
	TIOCSETN                         = 0x8006740a
	TIOCSETP                         = 0x80067409
	TIOCSIG                          = 0x80045436
	TIOCSLCKTRMIOS                   = 0x5457
	TIOCSLTC                         = 0x80067475
	TIOCSPGRP                        = 0x80047476
	TIOCSPTLCK                       = 0x80045431
	TIOCSRS485                       = 0x542f
	TIOCSSERIAL                      = 0x541f
	TIOCSSOFTCAR                     = 0x541a
	TIOCSTART                        = 0x2000746e
	TIOCSTI                          = 0x5412
	TIOCSTOP                         = 0x2000746f
	TIOCSWINSZ                       = 0x80087467
	TIOCVHANGUP                      = 0x5437
	TOSTOP                           = 0x400000
	TUNATTACHFILTER                  = 0x801054d5
	TUNDETACHFILTER                  = 0x801054d6
	TUNGETFEATURES                   = 0x400454cf
	TUNGETFILTER                     = 0x401054db
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
	VDISCARD                         = 0x10
	VEOF                             = 0x4
	VEOL                             = 0x6
	VEOL2                            = 0x8
	VERASE                           = 0x2
	VINTR                            = 0x0
	VKILL                            = 0x3
	VLNEXT                           = 0xf
	VMIN                             = 0x5
	VQUIT                            = 0x1
	VREPRINT                         = 0xb
	VSTART                           = 0xd
	VSTOP                            = 0xe
	VSUSP                            = 0xc
	VSWTC                            = 0x9
	VT0                              = 0x0
	VT1                              = 0x10000
	VTDLY                            = 0x10000
	VTIME                            = 0x7
	VWERASE                          = 0xa
	WALL                             = 0x40000000
	WCLONE                           = 0x80000000
	WCONTINUED                       = 0x8
	WEXITED                          = 0x4
	WNOHANG                          = 0x1
	WNOTHREAD                        = 0x20000000
	WNOWAIT                          = 0x1000000
	WORDSIZE                         = 0x40
	WSTOPPED                         = 0x2
	WUNTRACED                        = 0x2
)

// Errors
const (
	E2BIG           = Errno(0x7)
	EACCES          = Errno(0xd)
	EADDRINUSE      = Errno(0x62)
	EADDRNOTAVAIL   = Errno(0x63)
	EADV            = Errno(0x44)
	EAFNOSUPPORT    = Errno(0x61)
	EAGAIN          = Errno(0xb)
	EALREADY        = Errno(0x72)
	EBADE           = Errno(0x34)
	EBADF           = Errno(0x9)
	EBADFD          = Errno(0x4d)
	EBADMSG         = Errno(0x4a)
	EBADR           = Errno(0x35)
	EBADRQC         = Errno(0x38)
	EBADSLT         = Errno(0x39)
	EBFONT          = Errno(0x3b)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x7d)
	ECHILD          = Errno(0xa)
	ECHRNG          = Errno(0x2c)
	ECOMM           = Errno(0x46)
	ECONNABORTED    = Errno(0x67)
	ECONNREFUSED    = Errno(0x6f)
	ECONNRESET      = Errno(0x68)
	EDEADLK         = Errno(0x23)
	EDEADLOCK       = Errno(0x3a)
	EDESTADDRREQ    = Errno(0x59)
	EDOM            = Errno(0x21)
	EDOTDOT         = Errno(0x49)
	EDQUOT          = Errno(0x7a)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EHOSTDOWN       = Errno(0x70)
	EHOSTUNREACH    = Errno(0x71)
	EHWPOISON       = Errno(0x85)
	EIDRM           = Errno(0x2b)
	EILSEQ          = Errno(0x54)
	EINPROGRESS     = Errno(0x73)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EISCONN         = Errno(0x6a)
	EISDIR          = Errno(0x15)
	EISNAM          = Errno(0x78)
	EKEYEXPIRED     = Errno(0x7f)
	EKEYREJECTED    = Errno(0x81)
	EKEYREVOKED     = Errno(0x80)
	EL2HLT          = Errno(0x33)
	EL2NSYNC        = Errno(0x2d)
	EL3HLT          = Errno(0x2e)
	EL3RST          = Errno(0x2f)
	ELIBACC         = Errno(0x4f)
	ELIBBAD         = Errno(0x50)
	ELIBEXEC        = Errno(0x53)
	ELIBMAX         = Errno(0x52)
	ELIBSCN         = Errno(0x51)
	ELNRNG          = Errno(0x30)
	ELOOP           = Errno(0x28)
	EMEDIUMTYPE     = Errno(0x7c)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x5a)
	EMULTIHOP       = Errno(0x48)
	ENAMETOOLONG    = Errno(0x24)
	ENAVAIL         = Errno(0x77)
	ENETDOWN        = Errno(0x64)
	ENETRESET       = Errno(0x66)
	ENETUNREACH     = Errno(0x65)
	ENFILE          = Errno(0x17)
	ENOANO          = Errno(0x37)
	ENOBUFS         = Errno(0x69)
	ENOCSI          = Errno(0x32)
	ENODATA         = Errno(0x3d)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOKEY          = Errno(0x7e)
	ENOLCK          = Errno(0x25)
	ENOLINK         = Errno(0x43)
	ENOMEDIUM       = Errno(0x7b)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x2a)
	ENONET          = Errno(0x40)
	ENOPKG          = Errno(0x41)
	ENOPROTOOPT     = Errno(0x5c)
	ENOSPC          = Errno(0x1c)
	ENOSR           = Errno(0x3f)
	ENOSTR          = Errno(0x3c)
	ENOSYS          = Errno(0x26)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x6b)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x27)
	ENOTNAM         = Errno(0x76)
	ENOTRECOVERABLE = Errno(0x83)
	ENOTSOCK        = Errno(0x58)
	ENOTSUP         = Errno(0x5f)
	ENOTTY          = Errno(0x19)
	ENOTUNIQ        = Errno(0x4c)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x5f)
	EOVERFLOW       = Er
"""




```