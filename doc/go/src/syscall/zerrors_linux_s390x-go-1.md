Response:
The user has provided a snippet of a Go file and wants to understand its functionality. Specifically, they are asking for a summary of the functionality of the provided constants.

**Plan:**

1. **Identify the purpose of the file:** The file path `go/src/syscall/zerrors_linux_s390x.go` strongly suggests that this file defines system call related constants for the Linux operating system on the s390x architecture. The `zerrors` prefix likely indicates error code definitions.
2. **Analyze the constants:** The snippet contains a large number of `const` definitions. These appear to be numeric representations of various system-level flags, options, and error codes.
3. **Categorize the constants:**  Group the constants based on their prefixes or common themes to understand their specific areas of influence. Look for patterns like `O_`, `PACKET_`, `PR_`, `PTRACE_`, `RLIMIT_`, `RT_`, `RTM_`, `RTNH_`, `SO_`, `S_`, `TCP_`, `TIOC_`, `TUN_`, and `E`.
4. **Infer Go features:** Based on the categories, infer which Go standard library packages and functionalities would utilize these constants. For example, constants starting with `O_` are likely related to file operations, `PACKET_` to network packet handling, `PTRACE_` to process tracing, and so on.
5. **Provide a concise summary:**  Synthesize the findings into a high-level description of the file's purpose.
这是 `go/src/syscall/zerrors_linux_s390x.go` 文件的一部分，定义了一系列的常量。这些常量主要用于在 Linux s390x 架构上进行系统调用时使用。具体来说，它们代表了各种系统级别的标志、选项、参数和错误代码。

**功能归纳：**

这段代码定义了用于 Linux s390x 平台的系统调用相关的各种常量。这些常量可以大致分为以下几类：

1. **文件操作相关的常量 (以 `O_` 开头):**  例如 `O_TRUNC` (截断文件), `O_WRONLY` (只写打开) 等，用于 `open` 等系统调用中指定文件打开的模式和选项。

2. **网络数据包相关的常量 (以 `PACKET_` 开头):**  例如 `PACKET_BROADCAST`, `PACKET_MR_PROMISC` 等，这些常量用于 `socket` 系统调用创建的数据包套接字，用于配置数据包的接收和发送行为。 这部分与网络编程中的数据包捕获和处理有关。

3. **进程控制相关的常量 (以 `PR_` 开头):** 例如 `PR_SET_DUMPABLE`, `PR_GET_NAME` 等，这些常量用于 `prctl` 系统调用，用于获取和设置进程的各种属性和行为，例如是否生成 core dump 文件，获取进程名等。

4. **进程跟踪相关的常量 (以 `PTRACE_` 开头):** 例如 `PTRACE_ATTACH`, `PTRACE_CONT` 等，这些常量用于 `ptrace` 系统调用，用于调试和监控进程的执行。

5. **资源限制相关的常量 (以 `RLIMIT_` 开头):** 例如 `RLIMIT_CPU`, `RLIMIT_NOFILE` 等，这些常量用于 `getrlimit` 和 `setrlimit` 系统调用，用于获取和设置进程的资源使用限制。

6. **路由相关的常量 (以 `RT_`, `RTM_`, `RTNH_` 开头):** 例如 `RTF_UP`, `RTM_NEWROUTE` 等，这些常量用于网络路由相关的系统调用和数据结构，用于管理和配置网络路由表。

7. **Socket 选项相关的常量 (以 `SO_` 开头):** 例如 `SO_REUSEADDR`, `SO_BROADCAST` 等，这些常量用于 `getsockopt` 和 `setsockopt` 系统调用，用于获取和设置套接字的各种选项。

8. **文件类型和权限相关的常量 (以 `S_IF` 或 `S_I` 开头):** 例如 `S_IFREG`, `S_IRUSR` 等，这些常量用于表示文件类型和访问权限。

9. **TCP 协议相关的常量 (以 `TCP_` 开头):** 例如 `TCP_NODELAY`, `TCP_KEEPALIVE` 等，这些常量用于设置 TCP 连接的各种选项。

10. **终端控制相关的常量 (以 `TC` 或 `TIOC` 开头):** 例如 `TCOFLUSH`, `TIOCGWINSZ` 等，这些常量用于控制终端的行为，例如刷新缓冲区，获取窗口大小等。

11. **TUN/TAP 设备相关的常量 (以 `TUN` 开头):**  例如 `TUNSETIFF`, `TUNGETIFF` 等，用于配置虚拟网络接口。

12. **错误代码常量 (以 `E` 开头):** 例如 `EACCES` (权限被拒绝), `ENOENT` (文件不存在) 等，这些常量表示系统调用执行失败时返回的错误代码。

**功能总结：**

总而言之，`go/src/syscall/zerrors_linux_s390x.go` 的这一部分定义了在 Linux s390x 架构上进行底层系统编程时需要用到的各种常量。  它为 Go 语言提供了与操作系统内核交互的基础，使得 Go 程序能够执行文件操作、网络通信、进程管理、资源控制等底层任务。 这些常量在 `syscall` 包中被广泛使用，为开发者提供了访问操作系统底层功能的接口。

由于这部分代码主要是常量定义，并不涉及复杂的逻辑，因此很难直接用 Go 代码举例说明其具体的“实现”。  它更像是构建 Go 语言 `syscall` 包的基础砖块。  在实际使用中，这些常量会被传递给 `syscall` 包提供的函数，以控制系统调用的行为。

**易犯错的点：**

由于这部分代码是常量定义，使用者直接使用这些常量本身不太容易犯错。 常见的错误可能发生在 **错误码的判断** 上。 例如，不应该直接比较错误码的数值，而应该使用 `errors.Is` 或 `errors.As` 来判断具体的错误类型，因为不同架构或操作系统上的错误码数值可能不同。

例如，错误的判断方式：

```go
package main

import (
	"fmt"
	"syscall"
	"os"
)

func main() {
	_, err := os.Open("/nonexistent_file")
	if err != nil {
		// 这种直接比较错误码的方式是不可靠的
		if err == syscall.ENOENT {
			fmt.Println("文件不存在")
		} else {
			fmt.Println("其他错误:", err)
		}
	}
}
```

正确的判断方式应该使用 `errors.Is`:

```go
package main

import (
	"errors"
	"fmt"
	"syscall"
	"os"
)

func main() {
	_, err := os.Open("/nonexistent_file")
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			fmt.Println("文件不存在")
		} else {
			fmt.Println("其他错误:", err)
		}
	}
}
```

这是因为 `errors.Is` 会向上查找错误链，判断是否包含 `syscall.ENOENT` 错误，更加健壮和跨平台。

由于这段代码不涉及命令行参数处理，因此没有相关的说明。

Prompt: 
```
这是路径为go/src/syscall/zerrors_linux_s390x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
O_TRUNC                          = 0x200
	O_WRONLY                         = 0x1
	PACKET_ADD_MEMBERSHIP            = 0x1
	PACKET_AUXDATA                   = 0x8
	PACKET_BROADCAST                 = 0x1
	PACKET_COPY_THRESH               = 0x7
	PACKET_DROP_MEMBERSHIP           = 0x2
	PACKET_FANOUT                    = 0x12
	PACKET_FANOUT_CBPF               = 0x6
	PACKET_FANOUT_CPU                = 0x2
	PACKET_FANOUT_DATA               = 0x16
	PACKET_FANOUT_EBPF               = 0x7
	PACKET_FANOUT_FLAG_DEFRAG        = 0x8000
	PACKET_FANOUT_FLAG_ROLLOVER      = 0x1000
	PACKET_FANOUT_HASH               = 0x0
	PACKET_FANOUT_LB                 = 0x1
	PACKET_FANOUT_QM                 = 0x5
	PACKET_FANOUT_RND                = 0x4
	PACKET_FANOUT_ROLLOVER           = 0x3
	PACKET_FASTROUTE                 = 0x6
	PACKET_HDRLEN                    = 0xb
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
	PACKET_ROLLOVER_STATS            = 0x15
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
	PR_CAP_AMBIENT                   = 0x2f
	PR_CAP_AMBIENT_CLEAR_ALL         = 0x4
	PR_CAP_AMBIENT_IS_SET            = 0x1
	PR_CAP_AMBIENT_LOWER             = 0x3
	PR_CAP_AMBIENT_RAISE             = 0x2
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
	PR_FP_MODE_FR                    = 0x1
	PR_FP_MODE_FRE                   = 0x2
	PR_GET_CHILD_SUBREAPER           = 0x25
	PR_GET_DUMPABLE                  = 0x3
	PR_GET_ENDIAN                    = 0x13
	PR_GET_FPEMU                     = 0x9
	PR_GET_FPEXC                     = 0xb
	PR_GET_FP_MODE                   = 0x2e
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
	PR_MPX_DISABLE_MANAGEMENT        = 0x2c
	PR_MPX_ENABLE_MANAGEMENT         = 0x2b
	PR_SET_CHILD_SUBREAPER           = 0x24
	PR_SET_DUMPABLE                  = 0x4
	PR_SET_ENDIAN                    = 0x14
	PR_SET_FPEMU                     = 0xa
	PR_SET_FPEXC                     = 0xc
	PR_SET_FP_MODE                   = 0x2d
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
	PR_SET_MM_MAP                    = 0xe
	PR_SET_MM_MAP_SIZE               = 0xf
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
	PTRACE_DISABLE_TE                = 0x5010
	PTRACE_ENABLE_TE                 = 0x5009
	PTRACE_EVENT_CLONE               = 0x3
	PTRACE_EVENT_EXEC                = 0x4
	PTRACE_EVENT_EXIT                = 0x6
	PTRACE_EVENT_FORK                = 0x1
	PTRACE_EVENT_SECCOMP             = 0x7
	PTRACE_EVENT_STOP                = 0x80
	PTRACE_EVENT_VFORK               = 0x2
	PTRACE_EVENT_VFORK_DONE          = 0x5
	PTRACE_GETEVENTMSG               = 0x4201
	PTRACE_GETREGS                   = 0xc
	PTRACE_GETREGSET                 = 0x4204
	PTRACE_GETSIGINFO                = 0x4202
	PTRACE_GETSIGMASK                = 0x420a
	PTRACE_GET_LAST_BREAK            = 0x5006
	PTRACE_INTERRUPT                 = 0x4207
	PTRACE_KILL                      = 0x8
	PTRACE_LISTEN                    = 0x4208
	PTRACE_OLDSETOPTIONS             = 0x15
	PTRACE_O_EXITKILL                = 0x100000
	PTRACE_O_MASK                    = 0x3000ff
	PTRACE_O_SUSPEND_SECCOMP         = 0x200000
	PTRACE_O_TRACECLONE              = 0x8
	PTRACE_O_TRACEEXEC               = 0x10
	PTRACE_O_TRACEEXIT               = 0x40
	PTRACE_O_TRACEFORK               = 0x2
	PTRACE_O_TRACESECCOMP            = 0x80
	PTRACE_O_TRACESYSGOOD            = 0x1
	PTRACE_O_TRACEVFORK              = 0x4
	PTRACE_O_TRACEVFORKDONE          = 0x20
	PTRACE_PEEKDATA                  = 0x2
	PTRACE_PEEKDATA_AREA             = 0x5003
	PTRACE_PEEKSIGINFO               = 0x4209
	PTRACE_PEEKSIGINFO_SHARED        = 0x1
	PTRACE_PEEKTEXT                  = 0x1
	PTRACE_PEEKTEXT_AREA             = 0x5002
	PTRACE_PEEKUSR                   = 0x3
	PTRACE_PEEKUSR_AREA              = 0x5000
	PTRACE_PEEK_SYSTEM_CALL          = 0x5007
	PTRACE_POKEDATA                  = 0x5
	PTRACE_POKEDATA_AREA             = 0x5005
	PTRACE_POKETEXT                  = 0x4
	PTRACE_POKETEXT_AREA             = 0x5004
	PTRACE_POKEUSR                   = 0x6
	PTRACE_POKEUSR_AREA              = 0x5001
	PTRACE_POKE_SYSTEM_CALL          = 0x5008
	PTRACE_PROT                      = 0x15
	PTRACE_SECCOMP_GET_FILTER        = 0x420c
	PTRACE_SEIZE                     = 0x4206
	PTRACE_SETOPTIONS                = 0x4200
	PTRACE_SETREGS                   = 0xd
	PTRACE_SETREGSET                 = 0x4205
	PTRACE_SETSIGINFO                = 0x4203
	PTRACE_SETSIGMASK                = 0x420b
	PTRACE_SINGLEBLOCK               = 0xc
	PTRACE_SINGLESTEP                = 0x9
	PTRACE_SYSCALL                   = 0x18
	PTRACE_TE_ABORT_RAND             = 0x5011
	PTRACE_TRACEME                   = 0x0
	PT_ACR0                          = 0x90
	PT_ACR1                          = 0x94
	PT_ACR10                         = 0xb8
	PT_ACR11                         = 0xbc
	PT_ACR12                         = 0xc0
	PT_ACR13                         = 0xc4
	PT_ACR14                         = 0xc8
	PT_ACR15                         = 0xcc
	PT_ACR2                          = 0x98
	PT_ACR3                          = 0x9c
	PT_ACR4                          = 0xa0
	PT_ACR5                          = 0xa4
	PT_ACR6                          = 0xa8
	PT_ACR7                          = 0xac
	PT_ACR8                          = 0xb0
	PT_ACR9                          = 0xb4
	PT_CR_10                         = 0x168
	PT_CR_11                         = 0x170
	PT_CR_9                          = 0x160
	PT_ENDREGS                       = 0x1af
	PT_FPC                           = 0xd8
	PT_FPR0                          = 0xe0
	PT_FPR1                          = 0xe8
	PT_FPR10                         = 0x130
	PT_FPR11                         = 0x138
	PT_FPR12                         = 0x140
	PT_FPR13                         = 0x148
	PT_FPR14                         = 0x150
	PT_FPR15                         = 0x158
	PT_FPR2                          = 0xf0
	PT_FPR3                          = 0xf8
	PT_FPR4                          = 0x100
	PT_FPR5                          = 0x108
	PT_FPR6                          = 0x110
	PT_FPR7                          = 0x118
	PT_FPR8                          = 0x120
	PT_FPR9                          = 0x128
	PT_GPR0                          = 0x10
	PT_GPR1                          = 0x18
	PT_GPR10                         = 0x60
	PT_GPR11                         = 0x68
	PT_GPR12                         = 0x70
	PT_GPR13                         = 0x78
	PT_GPR14                         = 0x80
	PT_GPR15                         = 0x88
	PT_GPR2                          = 0x20
	PT_GPR3                          = 0x28
	PT_GPR4                          = 0x30
	PT_GPR5                          = 0x38
	PT_GPR6                          = 0x40
	PT_GPR7                          = 0x48
	PT_GPR8                          = 0x50
	PT_GPR9                          = 0x58
	PT_IEEE_IP                       = 0x1a8
	PT_LASTOFF                       = 0x1a8
	PT_ORIGGPR2                      = 0xd0
	PT_PSWADDR                       = 0x8
	PT_PSWMASK                       = 0x0
	RLIMIT_AS                        = 0x9
	RLIMIT_CORE                      = 0x4
	RLIMIT_CPU                       = 0x0
	RLIMIT_DATA                      = 0x2
	RLIMIT_FSIZE                     = 0x1
	RLIMIT_NOFILE                    = 0x7
	RLIMIT_STACK                     = 0x3
	RLIM_INFINITY                    = -0x1
	RTAX_ADVMSS                      = 0x8
	RTAX_CC_ALGO                     = 0x10
	RTAX_CWND                        = 0x7
	RTAX_FEATURES                    = 0xc
	RTAX_FEATURE_ALLFRAG             = 0x8
	RTAX_FEATURE_ECN                 = 0x1
	RTAX_FEATURE_MASK                = 0xf
	RTAX_FEATURE_SACK                = 0x2
	RTAX_FEATURE_TIMESTAMP           = 0x4
	RTAX_HOPLIMIT                    = 0xa
	RTAX_INITCWND                    = 0xb
	RTAX_INITRWND                    = 0xe
	RTAX_LOCK                        = 0x1
	RTAX_MAX                         = 0x10
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
	RTA_MAX                          = 0x16
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
	RTM_DELNSID                      = 0x59
	RTM_DELQDISC                     = 0x25
	RTM_DELROUTE                     = 0x19
	RTM_DELRULE                      = 0x21
	RTM_DELTCLASS                    = 0x29
	RTM_DELTFILTER                   = 0x2d
	RTM_F_CLONED                     = 0x200
	RTM_F_EQUALIZE                   = 0x400
	RTM_F_LOOKUP_TABLE               = 0x1000
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
	RTM_GETNSID                      = 0x5a
	RTM_GETQDISC                     = 0x26
	RTM_GETROUTE                     = 0x1a
	RTM_GETRULE                      = 0x22
	RTM_GETTCLASS                    = 0x2a
	RTM_GETTFILTER                   = 0x2e
	RTM_MAX                          = 0x5b
	RTM_NEWACTION                    = 0x30
	RTM_NEWADDR                      = 0x14
	RTM_NEWADDRLABEL                 = 0x48
	RTM_NEWLINK                      = 0x10
	RTM_NEWMDB                       = 0x54
	RTM_NEWNDUSEROPT                 = 0x44
	RTM_NEWNEIGH                     = 0x1c
	RTM_NEWNEIGHTBL                  = 0x40
	RTM_NEWNETCONF                   = 0x50
	RTM_NEWNSID                      = 0x58
	RTM_NEWPREFIX                    = 0x34
	RTM_NEWQDISC                     = 0x24
	RTM_NEWROUTE                     = 0x18
	RTM_NEWRULE                      = 0x20
	RTM_NEWTCLASS                    = 0x28
	RTM_NEWTFILTER                   = 0x2c
	RTM_NR_FAMILIES                  = 0x13
	RTM_NR_MSGTYPES                  = 0x4c
	RTM_SETDCB                       = 0x4f
	RTM_SETLINK                      = 0x13
	RTM_SETNEIGHTBL                  = 0x43
	RTNH_ALIGNTO                     = 0x4
	RTNH_COMPARE_MASK                = 0x11
	RTNH_F_DEAD                      = 0x1
	RTNH_F_LINKDOWN                  = 0x10
	RTNH_F_OFFLOAD                   = 0x8
	RTNH_F_ONLINK                    = 0x4
	RTNH_F_PERVASIVE                 = 0x2
	RTN_MAX                          = 0xb
	RTPROT_BABEL                     = 0x2a
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
	SO_ATTACH_BPF                    = 0x32
	SO_ATTACH_FILTER                 = 0x1a
	SO_BINDTODEVICE                  = 0x19
	SO_BPF_EXTENSIONS                = 0x30
	SO_BROADCAST                     = 0x6
	SO_BSDCOMPAT                     = 0xe
	SO_BUSY_POLL                     = 0x2e
	SO_DEBUG                         = 0x1
	SO_DETACH_BPF                    = 0x1b
	SO_DETACH_FILTER                 = 0x1b
	SO_DOMAIN                        = 0x27
	SO_DONTROUTE                     = 0x5
	SO_ERROR                         = 0x4
	SO_GET_FILTER                    = 0x1a
	SO_INCOMING_CPU                  = 0x31
	SO_KEEPALIVE                     = 0x9
	SO_LINGER                        = 0xd
	SO_LOCK_FILTER                   = 0x2c
	SO_MARK                          = 0x24
	SO_MAX_PACING_RATE               = 0x2f
	SO_NOFCS                         = 0x2b
	SO_NO_CHECK                      = 0xb
	SO_OOBINLINE                     = 0xa
	SO_PASSCRED                      = 0x10
	SO_PASSSEC                       = 0x22
	SO_PEEK_OFF                      = 0x2a
	SO_PEERCRED                      = 0x11
	SO_PEERNAME                      = 0x1c
	SO_PEERSEC                       = 0x1f
	SO_PRIORITY                      = 0xc
	SO_PROTOCOL                      = 0x26
	SO_RCVBUF                        = 0x8
	SO_RCVBUFFORCE                   = 0x21
	SO_RCVLOWAT                      = 0x12
	SO_RCVTIMEO                      = 0x14
	SO_REUSEADDR                     = 0x2
	SO_REUSEPORT                     = 0xf
	SO_RXQ_OVFL                      = 0x28
	SO_SECURITY_AUTHENTICATION       = 0x16
	SO_SECURITY_ENCRYPTION_NETWORK   = 0x18
	SO_SECURITY_ENCRYPTION_TRANSPORT = 0x17
	SO_SELECT_ERR_QUEUE              = 0x2d
	SO_SNDBUF                        = 0x7
	SO_SNDBUFFORCE                   = 0x20
	SO_SNDLOWAT                      = 0x13
	SO_SNDTIMEO                      = 0x15
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
	TCFLSH                           = 0x540b
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
	TCSAFLUSH                        = 0x2
	TIOCCBRK                         = 0x5428
	TIOCCONS                         = 0x541d
	TIOCEXCL                         = 0x540c
	TIOCGDEV                         = 0x80045432
	TIOCGETD                         = 0x5424
	TIOCGEXCL                        = 0x80045440
	TIOCGICOUNT                      = 0x545d
	TIOCGLCKTRMIOS                   = 0x5456
	TIOCGPGRP                        = 0x540f
	TIOCGPKT                         = 0x80045438
	TIOCGPTLCK                       = 0x80045439
	TIOCGPTN                         = 0x80045430
	TIOCGRS485                       = 0x542e
	TIOCGSERIAL                      = 0x541e
	TIOCGSID                         = 0x5429
	TIOCGSOFTCAR                     = 0x5419
	TIOCGWINSZ                       = 0x5413
	TIOCINQ                          = 0x541b
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
	TIOCM_RI                         = 0x80
	TIOCM_RNG                        = 0x80
	TIOCM_RTS                        = 0x4
	TIOCM_SR                         = 0x10
	TIOCM_ST                         = 0x8
	TIOCNOTTY                        = 0x5422
	TIOCNXCL                         = 0x540d
	TIOCOUTQ                         = 0x5411
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
	TIOCSETD                         = 0x5423
	TIOCSIG                          = 0x40045436
	TIOCSLCKTRMIOS                   = 0x5457
	TIOCSPGRP                        = 0x5410
	TIOCSPTLCK                       = 0x40045431
	TIOCSRS485                       = 0x542f
	TIOCSSERIAL                      = 0x541f
	TIOCSSOFTCAR                     = 0x541a
	TIOCSTI                          = 0x5412
	TIOCSWINSZ                       = 0x5414
	TIOCVHANGUP                      = 0x5437
	TOSTOP                           = 0x100
	TUNATTACHFILTER                  = 0x401054d5
	TUNDETACHFILTER                  = 0x401054d6
	TUNGETFEATURES                   = 0x800454cf
	TUNGETFILTER                     = 0x801054db
	TUNGETIFF                        = 0x800454d2
	TUNGETSNDBUF                     = 0x800454d3
	TUNGETVNETBE                     = 0x800454df
	TUNGETVNETHDRSZ                  = 0x800454d7
	TUNGETVNETLE                     = 0x800454dd
	TUNSETDEBUG                      = 0x400454c9
	TUNSETGROUP                      = 0x400454ce
	TUNSETIFF                        = 0x400454ca
	TUNSETIFINDEX                    = 0x400454da
	TUNSETLINK                       = 0x400454cd
	TUNSETNOCSUM                     = 0x400454c8
	TUNSETOFFLOAD                    = 0x400454d0
	TUNSETOWNER                      = 0x400454cc
	TUNSETPERSIST                    = 0x400454cb
	TUNSETQUEUE                      = 0x400454d9
	TUNSETSNDBUF                     = 0x400454d4
	TUNSETTXFILTER                   = 0x400454d1
	TUNSETVNETBE                     = 0x400454de
	TUNSETVNETHDRSZ                  = 0x400454d8
	TUNSETVNETLE                     = 0x400454dc
	VDISCARD                         = 0xd
	VEOF                             = 0x4
	VEOL                             = 0xb
	VEOL2                            = 0x10
	VERASE                           = 0x2
	VINTR                            = 0x0
	VKILL                            = 0x3
	VLNEXT                           = 0xf
	VMIN                             = 0x6
	VQUIT                            = 0x1
	VREPRINT                         = 0xc
	VSTART                           = 0x8
	VSTOP                            = 0x9
	VSUSP                            = 0xa
	VSWTC                            = 0x7
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
	ECONNA
"""




```