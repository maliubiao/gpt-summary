Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding & Context:**

* **File Path:**  `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_linux.go`. This is a strong indicator that the file is part of the Go standard library (or an extended package) and deals with low-level system calls on Linux. The "z" prefix often suggests auto-generated code or constants. The "errors" part is a key hint.
* **"Part 3 of 3":**  This tells us there are likely related files containing more definitions. The current file probably focuses on specific types of constants.
* **Content Structure:**  The code consists primarily of `const` blocks with uppercase identifiers and hexadecimal values. This strongly suggests it defines symbolic constants representing system-level entities.

**2. Deciphering the Constants:**

* **Large Number of Constants:** The sheer volume of constants indicates that this file covers a wide range of system-level features.
* **Prefix Analysis:**  Looking at common prefixes reveals groupings:
    * `ILL_`:  Likely related to illegal instructions or CPU exceptions.
    * `PR_`:  Strongly suggests "prctl" system call constants. `prctl` is used for process control operations.
    * `PTP_`:  Likely related to Precision Time Protocol.
    * `PTRACE_`:  Constants for the `ptrace` system call, used for debugging and process tracing.
    * `P_`: Process targeting options (e.g., PID, PGID).
    * `QNX_`, `RAMFS_`, `REISERFS_`, etc.:  File system magic numbers.
    * `RLIMIT_`, `RLIM_`: Resource limits.
    * `RTAX_`, `RTA_`, `RTCF_`, `RTC_`, `RTF_`, `RTMGRP_`, `RTM_`, `RTNH_`, `RTPROT_`, `RT_CLASS_`:  Routing and networking related constants.
    * `RUSAGE_`: Resource usage.
    * `RWF_`: Read/Write flags.
    * `SCHED_`:  Scheduling policies and flags.
    * `SCM_`: Socket control messages.
    * `SC_`:  Likely system configuration options.
    * `SECCOMP_`:  Secure computing mode constants.
    * `SECRETMEM_`, `SECURITYFS_`, `SELINUX_`: Security-related file system magic numbers.
    * `SEEK_`:  `lseek` system call constants.
    * `SHUT_`: `shutdown` system call constants.
    * `SIOC`:  Socket I/O control codes.
    * `SK_DIAG_`: Socket diagnostics.
    * `SMACK_`, `SMART_`, `SMB2_`, `SMB_`, `SOCKFS_`, `SOCK_`, `SOL_`:  More socket-related and security-related constants.
    * `SPLICE_`:  `splice` system call flags.
    * `SQUASHFS_`, `STACK_END_`, `STATX_`, `SYNC_FILE_RANGE_`, `SYSFS_`, `S_IF`, `S_I`, `S_IS`: File system and file mode constants.
    * `TAB_`, `TASKSTATS_`, `TCIFLUSH_`, `TCIOFF_`, `TCOFLUSH_`, `TCOOFF_`, `TCPOPT_`, `TCP_`: Terminal and TCP options.
    * `TFD_TIMER_`, `TIMER_`: Timer-related constants.
    * `TIOCM_`, `TIOCPKT_`: Terminal I/O control and packet modes.
    * `TIPC_`:  TIPC (Transparent Inter-Process Communication) constants.
    * `TMPFS_`, `TPACKET_`, `TP_STATUS_`, `TRACEFS_`, `TS_COMM_`, `UDF_`, `UDP_`, `UMOUNT_`, `USBDEVICE_`, `UTIME_`, `V9FS_`, `VERASE_`, `VINTR_`, `VKILL_`, `VLNEXT_`, `VMADDR_`, `VM_SOCKETS_`, `VQUIT_`, `VT_`: More file system, networking, and virtual machine related constants.
    * `WAKE_`, `WALL_`, `WCLONE_`, `WCONTINUED_`, `WDIOC_`, `WDIOF_`, `WDIOS_`, `WEXITED_`, `WGALLOWEDIP_`, `WGDEVICE_`, `WGPEER_`, `WG_CMD_`, `WG_GENL_`, `WG_KEY_LEN_`, `WIN_`:  Various miscellaneous constants, including watchdog timer controls, wireguard, and potentially Windows-related (though in a Linux context, likely related to compatibility or low-level hardware interfaces).
    * `WNOHANG_`, `WNOTHREAD_`, `WNOWAIT_`, `WSTOPPED_`, `WUNTRACED_`:  Constants for `wait` system calls.
    * `XATTR_`: Extended attribute constants.
    * `XDP_`:  eXpress Data Path constants (high-performance networking).
    * `XENFS_`, `XFS_`, `ZONEFS_`: File system magic numbers.
    * `_HIDIOCGRAWNAME_LEN_`, `_HIDIOCGRAWPHYS_LEN_`, `_HIDIOCGRAWUNIQ_LEN_`:  HID (Human Interface Device) constants.

* **Error Constants (`E...`) and Signal Constants (`SIG...`)**: These are clearly defined standard error numbers and signal numbers used in system calls.

**3. Reasoning about Functionality:**

Based on the constants, the primary function of this file is to define symbolic names for numerical values used in Linux system calls and related kernel interfaces. This makes the code more readable and maintainable.

**4. Inferring Go Feature Implementation:**

The file itself *doesn't implement* a Go feature. Instead, it provides the *building blocks* for other Go code to interact with Linux system calls. The `syscall` package in Go is the most likely user of these constants.

**5. Code Example (Illustrative):**

To show how these constants are used, I considered common system calls related to the prefixes I identified:

* **`prctl` Example:**  This was a clear candidate due to the many `PR_` constants.
* **`ptrace` Example:**  Another likely candidate with many `PTRACE_` constants.
* **Socket Options Example:**  The `SO_` constants pointed to socket-related system calls.

**6. Assumptions, Inputs, and Outputs:**

For the code examples, I made simple assumptions to demonstrate the usage of the constants. The "input" is generally a file descriptor or process ID, and the "output" is an error or a modified state.

**7. Command-Line Arguments:**

I considered if any of the constants directly related to command-line argument parsing. While some constants might *influence* the behavior of command-line tools, the `zerrors_linux.go` file itself doesn't handle command-line arguments.

**8. Common Mistakes:**

Thinking about how developers might misuse these constants led to the example of using the wrong constant for a system call. This highlights the importance of referring to the documentation.

**9. Final Summarization:**

The final step was to synthesize the information gathered into a concise summary of the file's purpose.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on individual constants. Recognizing the prefixes was crucial to understanding the broader categories of system features covered.
*  It's important to distinguish between *defining* constants and *implementing* features. This file defines, it doesn't implement.
*  When generating code examples, it's better to choose common and illustrative system calls rather than obscure ones.

By following this structured approach, moving from the general to the specific, and making educated inferences based on naming conventions and context, it's possible to effectively analyze and understand the purpose of this Go code snippet.
这是路径为 `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_linux.go` 的 Go 语言实现的一部分，它定义了大量的常量。根据其内容和上下文，我们可以推断出以下功能：

**主要功能：定义 Linux 系统调用的常量和错误码、信号量**

这个文件主要作用是提供 Go 语言与 Linux 内核进行交互时所需的各种常量定义。这些常量涵盖了：

* **`prctl` 操作码 (`PR_*`)**:  用于 `prctl` 系统调用，该调用用于对进程行为进行各种控制和查询，例如设置内存合并、设置 dumpable 属性、管理 CPU speculation 漏洞缓解等。
* **PTRACE 请求 (`PTRACE_*`)**:  用于 `ptrace` 系统调用，该调用是 Linux 下强大的进程跟踪和调试工具。这些常量定义了各种 `ptrace` 的操作，如附加进程、继续执行、获取寄存器信息、设置选项等。
* **进程/线程组 ID (`P_*`)**:  定义了可以作为进程相关系统调用目标的进程或线程组的类型，如所有进程、特定 PGID、特定 PID 等。
* **文件系统 Magic Number (`*_SUPER_MAGIC`)**:  用于识别不同文件系统的类型。
* **资源限制 (`RLIMIT_*`, `RLIM_*`)**:  定义了可以使用 `setrlimit` 和 `getrlimit` 系统调用设置和获取的各种资源限制，如 CPU 时间、文件大小、内存使用等。
* **路由属性 (`RTAX_*`)**:  定义了与网络路由相关的各种属性，例如窗口大小、RTT、MTU 等。
* **路由控制标志 (`RTCF_*`)**:  用于控制路由行为的标志。
* **实时时钟特性和参数 (`RTC_*`)**:  与实时时钟（RTC）设备交互相关的常量。
* **路由标志 (`RTF_*`)**:  定义了路由表项的各种标志，如 UP、GATEWAY、HOST 等。
* **路由组播组 (`RTMGRP_*`)**:  定义了各种路由消息的组播组。
* **路由消息类型 (`RTM_*`)**:  定义了各种路由消息的类型，例如添加路由、删除路由、获取路由等。
* **下一跳属性 (`RTNH_*`)**:  定义了路由下一跳的各种属性。
* **路由协议 (`RTPROT_*`)**:  定义了各种路由协议的类型，如 BGP、OSPF、静态路由等。
* **路由类 (`RT_CLASS_*`)**:  定义了路由的类别。
* **资源使用类型 (`RUSAGE_*`)**:  定义了 `getrusage` 系统调用可以获取的资源使用信息的类型，如自身、子进程、线程。
* **读写标志 (`RWF_*`)**:  用于 `preadv2` 和 `pwritev2` 系统调用，定义了读写操作的各种标志，如追加、原子操作等。
* **调度策略 (`SCHED_*`)**:  定义了 Linux 进程调度器的各种调度策略，如 FIFO、RR、BATCH 等，以及相关的标志。
* **Socket 控制消息 (`SCM_*`)**:  定义了通过 `sendmsg` 和 `recvmsg` 传递的控制消息的类型，如凭据、文件描述符等。
* **SECCOMP 相关 (`SECCOMP_*`)**:  定义了与 Secure Computing Mode (seccomp) 相关的常量，用于限制进程可以执行的系统调用。
* **安全相关的 Magic Number (`*_MAGIC`)**:  与安全相关的特定文件系统或机制的 Magic Number。
* **Seek 操作 (`SEEK_*`)**:  定义了 `lseek` 系统调用的各种 seek 方式。
* **Socket 关闭方式 (`SHUT_*`)**:  定义了 `shutdown` 系统调用的关闭方式。
* **Socket IO 控制请求 (`SIOC*`)**:  定义了 `ioctl` 系统调用中用于控制 socket 的各种请求。
* **Socket 诊断 (`SK_DIAG_*`)**:  定义了用于 socket 诊断的常量。
* **SMART 相关 (`SMART_*`)**:  与硬盘 SMART (Self-Monitoring, Analysis and Reporting Technology) 功能相关的常量。
* **Socket 类型 (`SOCK_*`)**:  定义了各种 socket 的类型，如 TCP、UDP、RAW 等。
* **Socket 选项 (`SO_*`)**:  定义了可以使用 `setsockopt` 和 `getsockopt` 系统调用设置和获取的各种 socket 选项。
* **`splice` 系统调用标志 (`SPLICE_F_*`)**:  定义了 `splice` 系统调用的各种标志。
* **文件状态 (`STATX_*`)**:  定义了 `statx` 系统调用可以获取的文件状态信息的字段。
* **`sync_file_range` 标志 (`SYNC_FILE_RANGE_*`)**:  定义了 `sync_file_range` 系统调用的各种标志。
* **文件类型宏 (`S_IF*`) 和权限宏 (`S_I*`, `S_IS*`)**:  用于检查文件类型的宏定义。
* **Taskstats (`TASKSTATS_*`)**:  与任务统计相关的常量。
* **终端控制 (`TC*`)**:  定义了与终端控制相关的常量。
* **TCP 选项 (`TCPOPT_*`) 和参数 (`TCP_*`)**:  定义了 TCP 协议的各种选项和参数。
* **定时器 (`TFD_TIMER_*`, `TIMER_*`)**:  定义了与定时器相关的常量。
* **串口控制 (`TIOCM_*`, `TIOCPKT_*`)**:  定义了与串口控制相关的常量。
* **TIPC (Transparent Inter-Process Communication) 相关 (`TIPC_*`)**:  定义了与 TIPC 协议相关的常量。
* **TPACKET (`TPACKET_*`, `TP_STATUS_*`)**:  定义了与 Linux 的 `packet(7)` socket 相关的常量。
* **UDP 选项 (`UDP_*`)**:  定义了 UDP 协议的各种选项。
* **`umount` 标志 (`UMOUNT_*`)**:  定义了 `umount` 系统调用的标志。
* **UTIME (`UTIME_*`)**:  定义了 `utimensat` 系统调用的特殊时间值。
* **虚拟机 Socket (`VMADDR_*`, `VM_SOCKETS_*`)**:  定义了与虚拟机 socket 相关的常量。
* **`wait` 系统调用标志 (`W*`)**:  定义了 `wait` 系列系统调用的标志。
* **看门狗 (`WDIOC_*`, `WDIOF_*`, `WDIOS_*`)**:  定义了与看门狗设备交互相关的常量。
* **WireGuard (`WG*`)**:  定义了与 WireGuard VPN 相关的常量。
* **IDE/ATA 设备 (`WIN_*`)**:  定义了与 IDE/ATA 设备交互的命令。
* **XATTR (`XATTR_*`)**:  定义了扩展属性相关的常量。
* **XDP (`XDP_*`)**:  定义了与 eXpress Data Path (XDP) 相关的常量，用于高性能网络数据包处理。
* **错误码 (`E*`)**:  定义了 Linux 系统调用可能返回的各种错误码。
* **信号量 (`SIG*`)**:  定义了 Linux 支持的各种信号。

**它可以被用于实现哪些 Go 语言功能？**

这个文件定义的常量是 `golang.org/x/sys/unix` 包的基础，该包提供了访问 Linux 系统调用的能力。 任何需要在 Go 语言中直接调用 Linux 系统调用的功能，都可能会用到这里定义的常量。

**Go 代码示例：**

假设我们要使用 `prctl` 系统调用来设置进程的 `dumpable` 属性为 1，允许进程在崩溃时生成 core dump 文件。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	err := unix.Prctl(unix.PR_SET_DUMPABLE, uintptr(1), 0, 0, 0)
	if err != nil {
		fmt.Println("Error setting dumpable:", err)
		return
	}
	fmt.Println("Successfully set dumpable.")
}
```

**假设的输入与输出：**

* **输入：**  执行上述 Go 程序。
* **输出：** 如果 `prctl` 调用成功，控制台会输出 "Successfully set dumpable."。如果失败，会输出 "Error setting dumpable: [错误信息]"。

**涉及命令行参数的具体处理：**

这个文件本身不涉及命令行参数的处理。它只是定义了在进行系统调用时使用的常量。命令行参数的处理通常发生在应用程序的入口点 `main` 函数中，并可能根据参数的值来决定调用哪些系统调用以及传递哪些参数（包括这里定义的常量）。

**使用者易犯错的点：**

* **使用错误的常量值：**  选择了不适用于特定系统调用的常量，导致系统调用失败或行为不符合预期。例如，将一个用于 `ptrace` 的常量错误地用于 `prctl`。
* **常量值的含义理解错误：**  对常量的具体作用和含义理解不透彻，导致在系统调用中使用了错误的参数。例如，混淆了不同 `PR_*` 常量的作用。

**归纳一下它的功能 (第3部分):**

作为第 3 部分，结合之前可能的部分（尽管我们没有看到），这个文件（以及可能相关的其他 `zerrors_linux.go` 文件）的功能是 **定义了 Go 语言在 Linux 系统上进行底层操作所需要的大量常量，包括系统调用号、选项、标志位、错误码和信号量。**  这些常量使得 Go 语言能够方便且类型安全地调用 Linux 系统调用，实现各种系统级功能。它构成了 `golang.org/x/sys/unix` 包的基础，并被上层需要直接与 Linux 内核交互的 Go 代码所使用。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
ILL_GET                             = 0x22
	PR_MCE_KILL_LATE                            = 0x0
	PR_MCE_KILL_SET                             = 0x1
	PR_MDWE_NO_INHERIT                          = 0x2
	PR_MDWE_REFUSE_EXEC_GAIN                    = 0x1
	PR_MPX_DISABLE_MANAGEMENT                   = 0x2c
	PR_MPX_ENABLE_MANAGEMENT                    = 0x2b
	PR_MTE_TAG_MASK                             = 0x7fff8
	PR_MTE_TAG_SHIFT                            = 0x3
	PR_MTE_TCF_ASYNC                            = 0x4
	PR_MTE_TCF_MASK                             = 0x6
	PR_MTE_TCF_NONE                             = 0x0
	PR_MTE_TCF_SHIFT                            = 0x1
	PR_MTE_TCF_SYNC                             = 0x2
	PR_PAC_APDAKEY                              = 0x4
	PR_PAC_APDBKEY                              = 0x8
	PR_PAC_APGAKEY                              = 0x10
	PR_PAC_APIAKEY                              = 0x1
	PR_PAC_APIBKEY                              = 0x2
	PR_PAC_GET_ENABLED_KEYS                     = 0x3d
	PR_PAC_RESET_KEYS                           = 0x36
	PR_PAC_SET_ENABLED_KEYS                     = 0x3c
	PR_PPC_DEXCR_CTRL_CLEAR                     = 0x4
	PR_PPC_DEXCR_CTRL_CLEAR_ONEXEC              = 0x10
	PR_PPC_DEXCR_CTRL_EDITABLE                  = 0x1
	PR_PPC_DEXCR_CTRL_MASK                      = 0x1f
	PR_PPC_DEXCR_CTRL_SET                       = 0x2
	PR_PPC_DEXCR_CTRL_SET_ONEXEC                = 0x8
	PR_PPC_DEXCR_IBRTPD                         = 0x1
	PR_PPC_DEXCR_NPHIE                          = 0x3
	PR_PPC_DEXCR_SBHE                           = 0x0
	PR_PPC_DEXCR_SRAPD                          = 0x2
	PR_PPC_GET_DEXCR                            = 0x48
	PR_PPC_SET_DEXCR                            = 0x49
	PR_RISCV_CTX_SW_FENCEI_OFF                  = 0x1
	PR_RISCV_CTX_SW_FENCEI_ON                   = 0x0
	PR_RISCV_SCOPE_PER_PROCESS                  = 0x0
	PR_RISCV_SCOPE_PER_THREAD                   = 0x1
	PR_RISCV_SET_ICACHE_FLUSH_CTX               = 0x47
	PR_RISCV_V_GET_CONTROL                      = 0x46
	PR_RISCV_V_SET_CONTROL                      = 0x45
	PR_RISCV_V_VSTATE_CTRL_CUR_MASK             = 0x3
	PR_RISCV_V_VSTATE_CTRL_DEFAULT              = 0x0
	PR_RISCV_V_VSTATE_CTRL_INHERIT              = 0x10
	PR_RISCV_V_VSTATE_CTRL_MASK                 = 0x1f
	PR_RISCV_V_VSTATE_CTRL_NEXT_MASK            = 0xc
	PR_RISCV_V_VSTATE_CTRL_OFF                  = 0x1
	PR_RISCV_V_VSTATE_CTRL_ON                   = 0x2
	PR_SCHED_CORE                               = 0x3e
	PR_SCHED_CORE_CREATE                        = 0x1
	PR_SCHED_CORE_GET                           = 0x0
	PR_SCHED_CORE_MAX                           = 0x4
	PR_SCHED_CORE_SCOPE_PROCESS_GROUP           = 0x2
	PR_SCHED_CORE_SCOPE_THREAD                  = 0x0
	PR_SCHED_CORE_SCOPE_THREAD_GROUP            = 0x1
	PR_SCHED_CORE_SHARE_FROM                    = 0x3
	PR_SCHED_CORE_SHARE_TO                      = 0x2
	PR_SET_CHILD_SUBREAPER                      = 0x24
	PR_SET_DUMPABLE                             = 0x4
	PR_SET_ENDIAN                               = 0x14
	PR_SET_FPEMU                                = 0xa
	PR_SET_FPEXC                                = 0xc
	PR_SET_FP_MODE                              = 0x2d
	PR_SET_IO_FLUSHER                           = 0x39
	PR_SET_KEEPCAPS                             = 0x8
	PR_SET_MDWE                                 = 0x41
	PR_SET_MEMORY_MERGE                         = 0x43
	PR_SET_MM                                   = 0x23
	PR_SET_MM_ARG_END                           = 0x9
	PR_SET_MM_ARG_START                         = 0x8
	PR_SET_MM_AUXV                              = 0xc
	PR_SET_MM_BRK                               = 0x7
	PR_SET_MM_END_CODE                          = 0x2
	PR_SET_MM_END_DATA                          = 0x4
	PR_SET_MM_ENV_END                           = 0xb
	PR_SET_MM_ENV_START                         = 0xa
	PR_SET_MM_EXE_FILE                          = 0xd
	PR_SET_MM_MAP                               = 0xe
	PR_SET_MM_MAP_SIZE                          = 0xf
	PR_SET_MM_START_BRK                         = 0x6
	PR_SET_MM_START_CODE                        = 0x1
	PR_SET_MM_START_DATA                        = 0x3
	PR_SET_MM_START_STACK                       = 0x5
	PR_SET_NAME                                 = 0xf
	PR_SET_NO_NEW_PRIVS                         = 0x26
	PR_SET_PDEATHSIG                            = 0x1
	PR_SET_PTRACER                              = 0x59616d61
	PR_SET_SECCOMP                              = 0x16
	PR_SET_SECUREBITS                           = 0x1c
	PR_SET_SPECULATION_CTRL                     = 0x35
	PR_SET_SYSCALL_USER_DISPATCH                = 0x3b
	PR_SET_TAGGED_ADDR_CTRL                     = 0x37
	PR_SET_THP_DISABLE                          = 0x29
	PR_SET_TIMERSLACK                           = 0x1d
	PR_SET_TIMING                               = 0xe
	PR_SET_TSC                                  = 0x1a
	PR_SET_UNALIGN                              = 0x6
	PR_SET_VMA                                  = 0x53564d41
	PR_SET_VMA_ANON_NAME                        = 0x0
	PR_SME_GET_VL                               = 0x40
	PR_SME_SET_VL                               = 0x3f
	PR_SME_SET_VL_ONEXEC                        = 0x40000
	PR_SME_VL_INHERIT                           = 0x20000
	PR_SME_VL_LEN_MASK                          = 0xffff
	PR_SPEC_DISABLE                             = 0x4
	PR_SPEC_DISABLE_NOEXEC                      = 0x10
	PR_SPEC_ENABLE                              = 0x2
	PR_SPEC_FORCE_DISABLE                       = 0x8
	PR_SPEC_INDIRECT_BRANCH                     = 0x1
	PR_SPEC_L1D_FLUSH                           = 0x2
	PR_SPEC_NOT_AFFECTED                        = 0x0
	PR_SPEC_PRCTL                               = 0x1
	PR_SPEC_STORE_BYPASS                        = 0x0
	PR_SVE_GET_VL                               = 0x33
	PR_SVE_SET_VL                               = 0x32
	PR_SVE_SET_VL_ONEXEC                        = 0x40000
	PR_SVE_VL_INHERIT                           = 0x20000
	PR_SVE_VL_LEN_MASK                          = 0xffff
	PR_SYS_DISPATCH_OFF                         = 0x0
	PR_SYS_DISPATCH_ON                          = 0x1
	PR_TAGGED_ADDR_ENABLE                       = 0x1
	PR_TASK_PERF_EVENTS_DISABLE                 = 0x1f
	PR_TASK_PERF_EVENTS_ENABLE                  = 0x20
	PR_TIMING_STATISTICAL                       = 0x0
	PR_TIMING_TIMESTAMP                         = 0x1
	PR_TSC_ENABLE                               = 0x1
	PR_TSC_SIGSEGV                              = 0x2
	PR_UNALIGN_NOPRINT                          = 0x1
	PR_UNALIGN_SIGBUS                           = 0x2
	PSTOREFS_MAGIC                              = 0x6165676c
	PTP_CLK_MAGIC                               = '='
	PTP_ENABLE_FEATURE                          = 0x1
	PTP_EXTTS_EDGES                             = 0x6
	PTP_EXTTS_EVENT_VALID                       = 0x1
	PTP_EXTTS_V1_VALID_FLAGS                    = 0x7
	PTP_EXTTS_VALID_FLAGS                       = 0x1f
	PTP_EXT_OFFSET                              = 0x10
	PTP_FALLING_EDGE                            = 0x4
	PTP_MAX_SAMPLES                             = 0x19
	PTP_PEROUT_DUTY_CYCLE                       = 0x2
	PTP_PEROUT_ONE_SHOT                         = 0x1
	PTP_PEROUT_PHASE                            = 0x4
	PTP_PEROUT_V1_VALID_FLAGS                   = 0x0
	PTP_PEROUT_VALID_FLAGS                      = 0x7
	PTP_PIN_GETFUNC                             = 0xc0603d06
	PTP_PIN_GETFUNC2                            = 0xc0603d0f
	PTP_RISING_EDGE                             = 0x2
	PTP_STRICT_FLAGS                            = 0x8
	PTP_SYS_OFFSET_EXTENDED                     = 0xc4c03d09
	PTP_SYS_OFFSET_EXTENDED2                    = 0xc4c03d12
	PTP_SYS_OFFSET_PRECISE                      = 0xc0403d08
	PTP_SYS_OFFSET_PRECISE2                     = 0xc0403d11
	PTRACE_ATTACH                               = 0x10
	PTRACE_CONT                                 = 0x7
	PTRACE_DETACH                               = 0x11
	PTRACE_EVENTMSG_SYSCALL_ENTRY               = 0x1
	PTRACE_EVENTMSG_SYSCALL_EXIT                = 0x2
	PTRACE_EVENT_CLONE                          = 0x3
	PTRACE_EVENT_EXEC                           = 0x4
	PTRACE_EVENT_EXIT                           = 0x6
	PTRACE_EVENT_FORK                           = 0x1
	PTRACE_EVENT_SECCOMP                        = 0x7
	PTRACE_EVENT_STOP                           = 0x80
	PTRACE_EVENT_VFORK                          = 0x2
	PTRACE_EVENT_VFORK_DONE                     = 0x5
	PTRACE_GETEVENTMSG                          = 0x4201
	PTRACE_GETREGS                              = 0xc
	PTRACE_GETREGSET                            = 0x4204
	PTRACE_GETSIGINFO                           = 0x4202
	PTRACE_GETSIGMASK                           = 0x420a
	PTRACE_GET_RSEQ_CONFIGURATION               = 0x420f
	PTRACE_GET_SYSCALL_INFO                     = 0x420e
	PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG     = 0x4211
	PTRACE_INTERRUPT                            = 0x4207
	PTRACE_KILL                                 = 0x8
	PTRACE_LISTEN                               = 0x4208
	PTRACE_O_EXITKILL                           = 0x100000
	PTRACE_O_MASK                               = 0x3000ff
	PTRACE_O_SUSPEND_SECCOMP                    = 0x200000
	PTRACE_O_TRACECLONE                         = 0x8
	PTRACE_O_TRACEEXEC                          = 0x10
	PTRACE_O_TRACEEXIT                          = 0x40
	PTRACE_O_TRACEFORK                          = 0x2
	PTRACE_O_TRACESECCOMP                       = 0x80
	PTRACE_O_TRACESYSGOOD                       = 0x1
	PTRACE_O_TRACEVFORK                         = 0x4
	PTRACE_O_TRACEVFORKDONE                     = 0x20
	PTRACE_PEEKDATA                             = 0x2
	PTRACE_PEEKSIGINFO                          = 0x4209
	PTRACE_PEEKSIGINFO_SHARED                   = 0x1
	PTRACE_PEEKTEXT                             = 0x1
	PTRACE_PEEKUSR                              = 0x3
	PTRACE_POKEDATA                             = 0x5
	PTRACE_POKETEXT                             = 0x4
	PTRACE_POKEUSR                              = 0x6
	PTRACE_SECCOMP_GET_FILTER                   = 0x420c
	PTRACE_SECCOMP_GET_METADATA                 = 0x420d
	PTRACE_SEIZE                                = 0x4206
	PTRACE_SETOPTIONS                           = 0x4200
	PTRACE_SETREGS                              = 0xd
	PTRACE_SETREGSET                            = 0x4205
	PTRACE_SETSIGINFO                           = 0x4203
	PTRACE_SETSIGMASK                           = 0x420b
	PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG     = 0x4210
	PTRACE_SINGLESTEP                           = 0x9
	PTRACE_SYSCALL                              = 0x18
	PTRACE_SYSCALL_INFO_ENTRY                   = 0x1
	PTRACE_SYSCALL_INFO_EXIT                    = 0x2
	PTRACE_SYSCALL_INFO_NONE                    = 0x0
	PTRACE_SYSCALL_INFO_SECCOMP                 = 0x3
	PTRACE_TRACEME                              = 0x0
	P_ALL                                       = 0x0
	P_PGID                                      = 0x2
	P_PID                                       = 0x1
	P_PIDFD                                     = 0x3
	QNX4_SUPER_MAGIC                            = 0x2f
	QNX6_SUPER_MAGIC                            = 0x68191122
	RAMFS_MAGIC                                 = 0x858458f6
	RAW_PAYLOAD_DIGITAL                         = 0x3
	RAW_PAYLOAD_HCI                             = 0x2
	RAW_PAYLOAD_LLCP                            = 0x0
	RAW_PAYLOAD_NCI                             = 0x1
	RAW_PAYLOAD_PROPRIETARY                     = 0x4
	RDTGROUP_SUPER_MAGIC                        = 0x7655821
	REISERFS_SUPER_MAGIC                        = 0x52654973
	RENAME_EXCHANGE                             = 0x2
	RENAME_NOREPLACE                            = 0x1
	RENAME_WHITEOUT                             = 0x4
	RLIMIT_CORE                                 = 0x4
	RLIMIT_CPU                                  = 0x0
	RLIMIT_DATA                                 = 0x2
	RLIMIT_FSIZE                                = 0x1
	RLIMIT_LOCKS                                = 0xa
	RLIMIT_MSGQUEUE                             = 0xc
	RLIMIT_NICE                                 = 0xd
	RLIMIT_RTPRIO                               = 0xe
	RLIMIT_RTTIME                               = 0xf
	RLIMIT_SIGPENDING                           = 0xb
	RLIMIT_STACK                                = 0x3
	RLIM_INFINITY                               = 0xffffffffffffffff
	RTAX_ADVMSS                                 = 0x8
	RTAX_CC_ALGO                                = 0x10
	RTAX_CWND                                   = 0x7
	RTAX_FASTOPEN_NO_COOKIE                     = 0x11
	RTAX_FEATURES                               = 0xc
	RTAX_FEATURE_ALLFRAG                        = 0x8
	RTAX_FEATURE_ECN                            = 0x1
	RTAX_FEATURE_MASK                           = 0x1f
	RTAX_FEATURE_SACK                           = 0x2
	RTAX_FEATURE_TCP_USEC_TS                    = 0x10
	RTAX_FEATURE_TIMESTAMP                      = 0x4
	RTAX_HOPLIMIT                               = 0xa
	RTAX_INITCWND                               = 0xb
	RTAX_INITRWND                               = 0xe
	RTAX_LOCK                                   = 0x1
	RTAX_MAX                                    = 0x11
	RTAX_MTU                                    = 0x2
	RTAX_QUICKACK                               = 0xf
	RTAX_REORDERING                             = 0x9
	RTAX_RTO_MIN                                = 0xd
	RTAX_RTT                                    = 0x4
	RTAX_RTTVAR                                 = 0x5
	RTAX_SSTHRESH                               = 0x6
	RTAX_UNSPEC                                 = 0x0
	RTAX_WINDOW                                 = 0x3
	RTA_ALIGNTO                                 = 0x4
	RTA_MAX                                     = 0x1e
	RTCF_DIRECTSRC                              = 0x4000000
	RTCF_DOREDIRECT                             = 0x1000000
	RTCF_LOG                                    = 0x2000000
	RTCF_MASQ                                   = 0x400000
	RTCF_NAT                                    = 0x800000
	RTCF_VALVE                                  = 0x200000
	RTC_AF                                      = 0x20
	RTC_BSM_DIRECT                              = 0x1
	RTC_BSM_DISABLED                            = 0x0
	RTC_BSM_LEVEL                               = 0x2
	RTC_BSM_STANDBY                             = 0x3
	RTC_FEATURE_ALARM                           = 0x0
	RTC_FEATURE_ALARM_RES_2S                    = 0x3
	RTC_FEATURE_ALARM_RES_MINUTE                = 0x1
	RTC_FEATURE_ALARM_WAKEUP_ONLY               = 0x7
	RTC_FEATURE_BACKUP_SWITCH_MODE              = 0x6
	RTC_FEATURE_CNT                             = 0x8
	RTC_FEATURE_CORRECTION                      = 0x5
	RTC_FEATURE_NEED_WEEK_DAY                   = 0x2
	RTC_FEATURE_UPDATE_INTERRUPT                = 0x4
	RTC_IRQF                                    = 0x80
	RTC_MAX_FREQ                                = 0x2000
	RTC_PARAM_BACKUP_SWITCH_MODE                = 0x2
	RTC_PARAM_CORRECTION                        = 0x1
	RTC_PARAM_FEATURES                          = 0x0
	RTC_PF                                      = 0x40
	RTC_UF                                      = 0x10
	RTF_ADDRCLASSMASK                           = 0xf8000000
	RTF_ADDRCONF                                = 0x40000
	RTF_ALLONLINK                               = 0x20000
	RTF_BROADCAST                               = 0x10000000
	RTF_CACHE                                   = 0x1000000
	RTF_DEFAULT                                 = 0x10000
	RTF_DYNAMIC                                 = 0x10
	RTF_FLOW                                    = 0x2000000
	RTF_GATEWAY                                 = 0x2
	RTF_HOST                                    = 0x4
	RTF_INTERFACE                               = 0x40000000
	RTF_IRTT                                    = 0x100
	RTF_LINKRT                                  = 0x100000
	RTF_LOCAL                                   = 0x80000000
	RTF_MODIFIED                                = 0x20
	RTF_MSS                                     = 0x40
	RTF_MTU                                     = 0x40
	RTF_MULTICAST                               = 0x20000000
	RTF_NAT                                     = 0x8000000
	RTF_NOFORWARD                               = 0x1000
	RTF_NONEXTHOP                               = 0x200000
	RTF_NOPMTUDISC                              = 0x4000
	RTF_POLICY                                  = 0x4000000
	RTF_REINSTATE                               = 0x8
	RTF_REJECT                                  = 0x200
	RTF_STATIC                                  = 0x400
	RTF_THROW                                   = 0x2000
	RTF_UP                                      = 0x1
	RTF_WINDOW                                  = 0x80
	RTF_XRESOLVE                                = 0x800
	RTMGRP_DECnet_IFADDR                        = 0x1000
	RTMGRP_DECnet_ROUTE                         = 0x4000
	RTMGRP_IPV4_IFADDR                          = 0x10
	RTMGRP_IPV4_MROUTE                          = 0x20
	RTMGRP_IPV4_ROUTE                           = 0x40
	RTMGRP_IPV4_RULE                            = 0x80
	RTMGRP_IPV6_IFADDR                          = 0x100
	RTMGRP_IPV6_IFINFO                          = 0x800
	RTMGRP_IPV6_MROUTE                          = 0x200
	RTMGRP_IPV6_PREFIX                          = 0x20000
	RTMGRP_IPV6_ROUTE                           = 0x400
	RTMGRP_LINK                                 = 0x1
	RTMGRP_NEIGH                                = 0x4
	RTMGRP_NOTIFY                               = 0x2
	RTMGRP_TC                                   = 0x8
	RTM_BASE                                    = 0x10
	RTM_DELACTION                               = 0x31
	RTM_DELADDR                                 = 0x15
	RTM_DELADDRLABEL                            = 0x49
	RTM_DELCHAIN                                = 0x65
	RTM_DELLINK                                 = 0x11
	RTM_DELLINKPROP                             = 0x6d
	RTM_DELMDB                                  = 0x55
	RTM_DELNEIGH                                = 0x1d
	RTM_DELNETCONF                              = 0x51
	RTM_DELNEXTHOP                              = 0x69
	RTM_DELNEXTHOPBUCKET                        = 0x75
	RTM_DELNSID                                 = 0x59
	RTM_DELQDISC                                = 0x25
	RTM_DELROUTE                                = 0x19
	RTM_DELRULE                                 = 0x21
	RTM_DELTCLASS                               = 0x29
	RTM_DELTFILTER                              = 0x2d
	RTM_DELTUNNEL                               = 0x79
	RTM_DELVLAN                                 = 0x71
	RTM_F_CLONED                                = 0x200
	RTM_F_EQUALIZE                              = 0x400
	RTM_F_FIB_MATCH                             = 0x2000
	RTM_F_LOOKUP_TABLE                          = 0x1000
	RTM_F_NOTIFY                                = 0x100
	RTM_F_OFFLOAD                               = 0x4000
	RTM_F_OFFLOAD_FAILED                        = 0x20000000
	RTM_F_PREFIX                                = 0x800
	RTM_F_TRAP                                  = 0x8000
	RTM_GETACTION                               = 0x32
	RTM_GETADDR                                 = 0x16
	RTM_GETADDRLABEL                            = 0x4a
	RTM_GETANYCAST                              = 0x3e
	RTM_GETCHAIN                                = 0x66
	RTM_GETDCB                                  = 0x4e
	RTM_GETLINK                                 = 0x12
	RTM_GETLINKPROP                             = 0x6e
	RTM_GETMDB                                  = 0x56
	RTM_GETMULTICAST                            = 0x3a
	RTM_GETNEIGH                                = 0x1e
	RTM_GETNEIGHTBL                             = 0x42
	RTM_GETNETCONF                              = 0x52
	RTM_GETNEXTHOP                              = 0x6a
	RTM_GETNEXTHOPBUCKET                        = 0x76
	RTM_GETNSID                                 = 0x5a
	RTM_GETQDISC                                = 0x26
	RTM_GETROUTE                                = 0x1a
	RTM_GETRULE                                 = 0x22
	RTM_GETSTATS                                = 0x5e
	RTM_GETTCLASS                               = 0x2a
	RTM_GETTFILTER                              = 0x2e
	RTM_GETTUNNEL                               = 0x7a
	RTM_GETVLAN                                 = 0x72
	RTM_MAX                                     = 0x7b
	RTM_NEWACTION                               = 0x30
	RTM_NEWADDR                                 = 0x14
	RTM_NEWADDRLABEL                            = 0x48
	RTM_NEWCACHEREPORT                          = 0x60
	RTM_NEWCHAIN                                = 0x64
	RTM_NEWLINK                                 = 0x10
	RTM_NEWLINKPROP                             = 0x6c
	RTM_NEWMDB                                  = 0x54
	RTM_NEWNDUSEROPT                            = 0x44
	RTM_NEWNEIGH                                = 0x1c
	RTM_NEWNEIGHTBL                             = 0x40
	RTM_NEWNETCONF                              = 0x50
	RTM_NEWNEXTHOP                              = 0x68
	RTM_NEWNEXTHOPBUCKET                        = 0x74
	RTM_NEWNSID                                 = 0x58
	RTM_NEWNVLAN                                = 0x70
	RTM_NEWPREFIX                               = 0x34
	RTM_NEWQDISC                                = 0x24
	RTM_NEWROUTE                                = 0x18
	RTM_NEWRULE                                 = 0x20
	RTM_NEWSTATS                                = 0x5c
	RTM_NEWTCLASS                               = 0x28
	RTM_NEWTFILTER                              = 0x2c
	RTM_NEWTUNNEL                               = 0x78
	RTM_NR_FAMILIES                             = 0x1b
	RTM_NR_MSGTYPES                             = 0x6c
	RTM_SETDCB                                  = 0x4f
	RTM_SETLINK                                 = 0x13
	RTM_SETNEIGHTBL                             = 0x43
	RTM_SETSTATS                                = 0x5f
	RTNH_ALIGNTO                                = 0x4
	RTNH_COMPARE_MASK                           = 0x59
	RTNH_F_DEAD                                 = 0x1
	RTNH_F_LINKDOWN                             = 0x10
	RTNH_F_OFFLOAD                              = 0x8
	RTNH_F_ONLINK                               = 0x4
	RTNH_F_PERVASIVE                            = 0x2
	RTNH_F_TRAP                                 = 0x40
	RTNH_F_UNRESOLVED                           = 0x20
	RTN_MAX                                     = 0xb
	RTPROT_BABEL                                = 0x2a
	RTPROT_BGP                                  = 0xba
	RTPROT_BIRD                                 = 0xc
	RTPROT_BOOT                                 = 0x3
	RTPROT_DHCP                                 = 0x10
	RTPROT_DNROUTED                             = 0xd
	RTPROT_EIGRP                                = 0xc0
	RTPROT_GATED                                = 0x8
	RTPROT_ISIS                                 = 0xbb
	RTPROT_KEEPALIVED                           = 0x12
	RTPROT_KERNEL                               = 0x2
	RTPROT_MROUTED                              = 0x11
	RTPROT_MRT                                  = 0xa
	RTPROT_NTK                                  = 0xf
	RTPROT_OPENR                                = 0x63
	RTPROT_OSPF                                 = 0xbc
	RTPROT_RA                                   = 0x9
	RTPROT_REDIRECT                             = 0x1
	RTPROT_RIP                                  = 0xbd
	RTPROT_STATIC                               = 0x4
	RTPROT_UNSPEC                               = 0x0
	RTPROT_XORP                                 = 0xe
	RTPROT_ZEBRA                                = 0xb
	RT_CLASS_DEFAULT                            = 0xfd
	RT_CLASS_LOCAL                              = 0xff
	RT_CLASS_MAIN                               = 0xfe
	RT_CLASS_MAX                                = 0xff
	RT_CLASS_UNSPEC                             = 0x0
	RUSAGE_CHILDREN                             = -0x1
	RUSAGE_SELF                                 = 0x0
	RUSAGE_THREAD                               = 0x1
	RWF_APPEND                                  = 0x10
	RWF_ATOMIC                                  = 0x40
	RWF_DSYNC                                   = 0x2
	RWF_HIPRI                                   = 0x1
	RWF_NOAPPEND                                = 0x20
	RWF_NOWAIT                                  = 0x8
	RWF_SUPPORTED                               = 0x7f
	RWF_SYNC                                    = 0x4
	RWF_WRITE_LIFE_NOT_SET                      = 0x0
	SCHED_BATCH                                 = 0x3
	SCHED_DEADLINE                              = 0x6
	SCHED_EXT                                   = 0x7
	SCHED_FIFO                                  = 0x1
	SCHED_FLAG_ALL                              = 0x7f
	SCHED_FLAG_DL_OVERRUN                       = 0x4
	SCHED_FLAG_KEEP_ALL                         = 0x18
	SCHED_FLAG_KEEP_PARAMS                      = 0x10
	SCHED_FLAG_KEEP_POLICY                      = 0x8
	SCHED_FLAG_RECLAIM                          = 0x2
	SCHED_FLAG_RESET_ON_FORK                    = 0x1
	SCHED_FLAG_UTIL_CLAMP                       = 0x60
	SCHED_FLAG_UTIL_CLAMP_MAX                   = 0x40
	SCHED_FLAG_UTIL_CLAMP_MIN                   = 0x20
	SCHED_IDLE                                  = 0x5
	SCHED_NORMAL                                = 0x0
	SCHED_RESET_ON_FORK                         = 0x40000000
	SCHED_RR                                    = 0x2
	SCM_CREDENTIALS                             = 0x2
	SCM_PIDFD                                   = 0x4
	SCM_RIGHTS                                  = 0x1
	SCM_SECURITY                                = 0x3
	SCM_TIMESTAMP                               = 0x1d
	SC_LOG_FLUSH                                = 0x100000
	SECCOMP_ADDFD_FLAG_SEND                     = 0x2
	SECCOMP_ADDFD_FLAG_SETFD                    = 0x1
	SECCOMP_FILTER_FLAG_LOG                     = 0x2
	SECCOMP_FILTER_FLAG_NEW_LISTENER            = 0x8
	SECCOMP_FILTER_FLAG_SPEC_ALLOW              = 0x4
	SECCOMP_FILTER_FLAG_TSYNC                   = 0x1
	SECCOMP_FILTER_FLAG_TSYNC_ESRCH             = 0x10
	SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV      = 0x20
	SECCOMP_GET_ACTION_AVAIL                    = 0x2
	SECCOMP_GET_NOTIF_SIZES                     = 0x3
	SECCOMP_IOCTL_NOTIF_RECV                    = 0xc0502100
	SECCOMP_IOCTL_NOTIF_SEND                    = 0xc0182101
	SECCOMP_IOC_MAGIC                           = '!'
	SECCOMP_MODE_DISABLED                       = 0x0
	SECCOMP_MODE_FILTER                         = 0x2
	SECCOMP_MODE_STRICT                         = 0x1
	SECCOMP_RET_ACTION                          = 0x7fff0000
	SECCOMP_RET_ACTION_FULL                     = 0xffff0000
	SECCOMP_RET_ALLOW                           = 0x7fff0000
	SECCOMP_RET_DATA                            = 0xffff
	SECCOMP_RET_ERRNO                           = 0x50000
	SECCOMP_RET_KILL                            = 0x0
	SECCOMP_RET_KILL_PROCESS                    = 0x80000000
	SECCOMP_RET_KILL_THREAD                     = 0x0
	SECCOMP_RET_LOG                             = 0x7ffc0000
	SECCOMP_RET_TRACE                           = 0x7ff00000
	SECCOMP_RET_TRAP                            = 0x30000
	SECCOMP_RET_USER_NOTIF                      = 0x7fc00000
	SECCOMP_SET_MODE_FILTER                     = 0x1
	SECCOMP_SET_MODE_STRICT                     = 0x0
	SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP          = 0x1
	SECCOMP_USER_NOTIF_FLAG_CONTINUE            = 0x1
	SECRETMEM_MAGIC                             = 0x5345434d
	SECURITYFS_MAGIC                            = 0x73636673
	SEEK_CUR                                    = 0x1
	SEEK_DATA                                   = 0x3
	SEEK_END                                    = 0x2
	SEEK_HOLE                                   = 0x4
	SEEK_MAX                                    = 0x4
	SEEK_SET                                    = 0x0
	SELINUX_MAGIC                               = 0xf97cff8c
	SHUT_RD                                     = 0x0
	SHUT_RDWR                                   = 0x2
	SHUT_WR                                     = 0x1
	SIOCADDDLCI                                 = 0x8980
	SIOCADDMULTI                                = 0x8931
	SIOCADDRT                                   = 0x890b
	SIOCBONDCHANGEACTIVE                        = 0x8995
	SIOCBONDENSLAVE                             = 0x8990
	SIOCBONDINFOQUERY                           = 0x8994
	SIOCBONDRELEASE                             = 0x8991
	SIOCBONDSETHWADDR                           = 0x8992
	SIOCBONDSLAVEINFOQUERY                      = 0x8993
	SIOCBRADDBR                                 = 0x89a0
	SIOCBRADDIF                                 = 0x89a2
	SIOCBRDELBR                                 = 0x89a1
	SIOCBRDELIF                                 = 0x89a3
	SIOCDARP                                    = 0x8953
	SIOCDELDLCI                                 = 0x8981
	SIOCDELMULTI                                = 0x8932
	SIOCDELRT                                   = 0x890c
	SIOCDEVPRIVATE                              = 0x89f0
	SIOCDIFADDR                                 = 0x8936
	SIOCDRARP                                   = 0x8960
	SIOCETHTOOL                                 = 0x8946
	SIOCGARP                                    = 0x8954
	SIOCGETLINKNAME                             = 0x89e0
	SIOCGETNODEID                               = 0x89e1
	SIOCGHWTSTAMP                               = 0x89b1
	SIOCGIFADDR                                 = 0x8915
	SIOCGIFBR                                   = 0x8940
	SIOCGIFBRDADDR                              = 0x8919
	SIOCGIFCONF                                 = 0x8912
	SIOCGIFCOUNT                                = 0x8938
	SIOCGIFDSTADDR                              = 0x8917
	SIOCGIFENCAP                                = 0x8925
	SIOCGIFFLAGS                                = 0x8913
	SIOCGIFHWADDR                               = 0x8927
	SIOCGIFINDEX                                = 0x8933
	SIOCGIFMAP                                  = 0x8970
	SIOCGIFMEM                                  = 0x891f
	SIOCGIFMETRIC                               = 0x891d
	SIOCGIFMTU                                  = 0x8921
	SIOCGIFNAME                                 = 0x8910
	SIOCGIFNETMASK                              = 0x891b
	SIOCGIFPFLAGS                               = 0x8935
	SIOCGIFSLAVE                                = 0x8929
	SIOCGIFTXQLEN                               = 0x8942
	SIOCGIFVLAN                                 = 0x8982
	SIOCGMIIPHY                                 = 0x8947
	SIOCGMIIREG                                 = 0x8948
	SIOCGPPPCSTATS                              = 0x89f2
	SIOCGPPPSTATS                               = 0x89f0
	SIOCGPPPVER                                 = 0x89f1
	SIOCGRARP                                   = 0x8961
	SIOCGSKNS                                   = 0x894c
	SIOCGSTAMP                                  = 0x8906
	SIOCGSTAMPNS                                = 0x8907
	SIOCGSTAMPNS_OLD                            = 0x8907
	SIOCGSTAMP_OLD                              = 0x8906
	SIOCKCMATTACH                               = 0x89e0
	SIOCKCMCLONE                                = 0x89e2
	SIOCKCMUNATTACH                             = 0x89e1
	SIOCOUTQNSD                                 = 0x894b
	SIOCPROTOPRIVATE                            = 0x89e0
	SIOCRTMSG                                   = 0x890d
	SIOCSARP                                    = 0x8955
	SIOCSHWTSTAMP                               = 0x89b0
	SIOCSIFADDR                                 = 0x8916
	SIOCSIFBR                                   = 0x8941
	SIOCSIFBRDADDR                              = 0x891a
	SIOCSIFDSTADDR                              = 0x8918
	SIOCSIFENCAP                                = 0x8926
	SIOCSIFFLAGS                                = 0x8914
	SIOCSIFHWADDR                               = 0x8924
	SIOCSIFHWBROADCAST                          = 0x8937
	SIOCSIFLINK                                 = 0x8911
	SIOCSIFMAP                                  = 0x8971
	SIOCSIFMEM                                  = 0x8920
	SIOCSIFMETRIC                               = 0x891e
	SIOCSIFMTU                                  = 0x8922
	SIOCSIFNAME                                 = 0x8923
	SIOCSIFNETMASK                              = 0x891c
	SIOCSIFPFLAGS                               = 0x8934
	SIOCSIFSLAVE                                = 0x8930
	SIOCSIFTXQLEN                               = 0x8943
	SIOCSIFVLAN                                 = 0x8983
	SIOCSMIIREG                                 = 0x8949
	SIOCSRARP                                   = 0x8962
	SIOCWANDEV                                  = 0x894a
	SK_DIAG_BPF_STORAGE_MAX                     = 0x3
	SK_DIAG_BPF_STORAGE_REQ_MAX                 = 0x1
	SMACK_MAGIC                                 = 0x43415d53
	SMART_AUTOSAVE                              = 0xd2
	SMART_AUTO_OFFLINE                          = 0xdb
	SMART_DISABLE                               = 0xd9
	SMART_ENABLE                                = 0xd8
	SMART_HCYL_PASS                             = 0xc2
	SMART_IMMEDIATE_OFFLINE                     = 0xd4
	SMART_LCYL_PASS                             = 0x4f
	SMART_READ_LOG_SECTOR                       = 0xd5
	SMART_READ_THRESHOLDS                       = 0xd1
	SMART_READ_VALUES                           = 0xd0
	SMART_SAVE                                  = 0xd3
	SMART_STATUS                                = 0xda
	SMART_WRITE_LOG_SECTOR                      = 0xd6
	SMART_WRITE_THRESHOLDS                      = 0xd7
	SMB2_SUPER_MAGIC                            = 0xfe534d42
	SMB_SUPER_MAGIC                             = 0x517b
	SOCKFS_MAGIC                                = 0x534f434b
	SOCK_BUF_LOCK_MASK                          = 0x3
	SOCK_DCCP                                   = 0x6
	SOCK_DESTROY                                = 0x15
	SOCK_DIAG_BY_FAMILY                         = 0x14
	SOCK_IOC_TYPE                               = 0x89
	SOCK_PACKET                                 = 0xa
	SOCK_RAW                                    = 0x3
	SOCK_RCVBUF_LOCK                            = 0x2
	SOCK_RDM                                    = 0x4
	SOCK_SEQPACKET                              = 0x5
	SOCK_SNDBUF_LOCK                            = 0x1
	SOCK_TXREHASH_DEFAULT                       = 0xff
	SOCK_TXREHASH_DISABLED                      = 0x0
	SOCK_TXREHASH_ENABLED                       = 0x1
	SOL_AAL                                     = 0x109
	SOL_ALG                                     = 0x117
	SOL_ATM                                     = 0x108
	SOL_CAIF                                    = 0x116
	SOL_CAN_BASE                                = 0x64
	SOL_CAN_RAW                                 = 0x65
	SOL_DCCP                                    = 0x10d
	SOL_DECNET                                  = 0x105
	SOL_ICMPV6                                  = 0x3a
	SOL_IP                                      = 0x0
	SOL_IPV6                                    = 0x29
	SOL_IRDA                                    = 0x10a
	SOL_IUCV                                    = 0x115
	SOL_KCM                                     = 0x119
	SOL_LLC                                     = 0x10c
	SOL_MCTP                                    = 0x11d
	SOL_MPTCP                                   = 0x11c
	SOL_NETBEUI                                 = 0x10b
	SOL_NETLINK                                 = 0x10e
	SOL_NFC                                     = 0x118
	SOL_PACKET                                  = 0x107
	SOL_PNPIPE                                  = 0x113
	SOL_PPPOL2TP                                = 0x111
	SOL_RAW                                     = 0xff
	SOL_RDS                                     = 0x114
	SOL_RXRPC                                   = 0x110
	SOL_SMC                                     = 0x11e
	SOL_TCP                                     = 0x6
	SOL_TIPC                                    = 0x10f
	SOL_TLS                                     = 0x11a
	SOL_UDP                                     = 0x11
	SOL_VSOCK                                   = 0x11f
	SOL_X25                                     = 0x106
	SOL_XDP                                     = 0x11b
	SOMAXCONN                                   = 0x1000
	SO_ATTACH_FILTER                            = 0x1a
	SO_DEBUG                                    = 0x1
	SO_DETACH_BPF                               = 0x1b
	SO_DETACH_FILTER                            = 0x1b
	SO_EE_CODE_TXTIME_INVALID_PARAM             = 0x1
	SO_EE_CODE_TXTIME_MISSED                    = 0x2
	SO_EE_CODE_ZEROCOPY_COPIED                  = 0x1
	SO_EE_ORIGIN_ICMP                           = 0x2
	SO_EE_ORIGIN_ICMP6                          = 0x3
	SO_EE_ORIGIN_LOCAL                          = 0x1
	SO_EE_ORIGIN_NONE                           = 0x0
	SO_EE_ORIGIN_TIMESTAMPING                   = 0x4
	SO_EE_ORIGIN_TXSTATUS                       = 0x4
	SO_EE_ORIGIN_TXTIME                         = 0x6
	SO_EE_ORIGIN_ZEROCOPY                       = 0x5
	SO_EE_RFC4884_FLAG_INVALID                  = 0x1
	SO_GET_FILTER                               = 0x1a
	SO_NO_CHECK                                 = 0xb
	SO_PEERNAME                                 = 0x1c
	SO_PRIORITY                                 = 0xc
	SO_TIMESTAMP                                = 0x1d
	SO_TIMESTAMP_OLD                            = 0x1d
	SO_VM_SOCKETS_BUFFER_MAX_SIZE               = 0x2
	SO_VM_SOCKETS_BUFFER_MIN_SIZE               = 0x1
	SO_VM_SOCKETS_BUFFER_SIZE                   = 0x0
	SO_VM_SOCKETS_CONNECT_TIMEOUT               = 0x6
	SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW           = 0x8
	SO_VM_SOCKETS_CONNECT_TIMEOUT_OLD           = 0x6
	SO_VM_SOCKETS_NONBLOCK_TXRX                 = 0x7
	SO_VM_SOCKETS_PEER_HOST_VM_ID               = 0x3
	SO_VM_SOCKETS_TRUSTED                       = 0x5
	SPLICE_F_GIFT                               = 0x8
	SPLICE_F_MORE                               = 0x4
	SPLICE_F_MOVE                               = 0x1
	SPLICE_F_NONBLOCK                           = 0x2
	SQUASHFS_MAGIC                              = 0x73717368
	STACK_END_MAGIC                             = 0x57ac6e9d
	STATX_ALL                                   = 0xfff
	STATX_ATIME                                 = 0x20
	STATX_ATTR_APPEND                           = 0x20
	STATX_ATTR_AUTOMOUNT                        = 0x1000
	STATX_ATTR_COMPRESSED                       = 0x4
	STATX_ATTR_DAX                              = 0x200000
	STATX_ATTR_ENCRYPTED                        = 0x800
	STATX_ATTR_IMMUTABLE                        = 0x10
	STATX_ATTR_MOUNT_ROOT                       = 0x2000
	STATX_ATTR_NODUMP                           = 0x40
	STATX_ATTR_VERITY                           = 0x100000
	STATX_ATTR_WRITE_ATOMIC                     = 0x400000
	STATX_BASIC_STATS                           = 0x7ff
	STATX_BLOCKS                                = 0x400
	STATX_BTIME                                 = 0x800
	STATX_CTIME                                 = 0x80
	STATX_DIOALIGN                              = 0x2000
	STATX_GID                                   = 0x10
	STATX_INO                                   = 0x100
	STATX_MNT_ID                                = 0x1000
	STATX_MNT_ID_UNIQUE                         = 0x4000
	STATX_MODE                                  = 0x2
	STATX_MTIME                                 = 0x40
	STATX_NLINK                                 = 0x4
	STATX_SIZE                                  = 0x200
	STATX_SUBVOL                                = 0x8000
	STATX_TYPE                                  = 0x1
	STATX_UID                                   = 0x8
	STATX_WRITE_ATOMIC                          = 0x10000
	STATX__RESERVED                             = 0x80000000
	SYNC_FILE_RANGE_WAIT_AFTER                  = 0x4
	SYNC_FILE_RANGE_WAIT_BEFORE                 = 0x1
	SYNC_FILE_RANGE_WRITE                       = 0x2
	SYNC_FILE_RANGE_WRITE_AND_WAIT              = 0x7
	SYSFS_MAGIC                                 = 0x62656572
	S_BLKSIZE                                   = 0x200
	S_IEXEC                                     = 0x40
	S_IFBLK                                     = 0x6000
	S_IFCHR                                     = 0x2000
	S_IFDIR                                     = 0x4000
	S_IFIFO                                     = 0x1000
	S_IFLNK                                     = 0xa000
	S_IFMT                                      = 0xf000
	S_IFREG                                     = 0x8000
	S_IFSOCK                                    = 0xc000
	S_IREAD                                     = 0x100
	S_IRGRP                                     = 0x20
	S_IROTH                                     = 0x4
	S_IRUSR                                     = 0x100
	S_IRWXG                                     = 0x38
	S_IRWXO                                     = 0x7
	S_IRWXU                                     = 0x1c0
	S_ISGID                                     = 0x400
	S_ISUID                                     = 0x800
	S_ISVTX                                     = 0x200
	S_IWGRP                                     = 0x10
	S_IWOTH                                     = 0x2
	S_IWRITE                                    = 0x80
	S_IWUSR                                     = 0x80
	S_IXGRP                                     = 0x8
	S_IXOTH                                     = 0x1
	S_IXUSR                                     = 0x40
	TAB0                                        = 0x0
	TASKSTATS_CMD_ATTR_MAX                      = 0x4
	TASKSTATS_CMD_MAX                           = 0x2
	TASKSTATS_GENL_NAME                         = "TASKSTATS"
	TASKSTATS_GENL_VERSION                      = 0x1
	TASKSTATS_TYPE_MAX                          = 0x6
	TASKSTATS_VERSION                           = 0xe
	TCIFLUSH                                    = 0x0
	TCIOFF                                      = 0x2
	TCIOFLUSH                                   = 0x2
	TCION                                       = 0x3
	TCOFLUSH                                    = 0x1
	TCOOFF                                      = 0x0
	TCOON                                       = 0x1
	TCPOPT_EOL                                  = 0x0
	TCPOPT_MAXSEG                               = 0x2
	TCPOPT_NOP                                  = 0x1
	TCPOPT_SACK                                 = 0x5
	TCPOPT_SACK_PERMITTED                       = 0x4
	TCPOPT_TIMESTAMP                            = 0x8
	TCPOPT_TSTAMP_HDR                           = 0x101080a
	TCPOPT_WINDOW                               = 0x3
	TCP_CC_INFO                                 = 0x1a
	TCP_CM_INQ                                  = 0x24
	TCP_CONGESTION                              = 0xd
	TCP_COOKIE_IN_ALWAYS                        = 0x1
	TCP_COOKIE_MAX                              = 0x10
	TCP_COOKIE_MIN                              = 0x8
	TCP_COOKIE_OUT_NEVER                        = 0x2
	TCP_COOKIE_PAIR_SIZE                        = 0x20
	TCP_COOKIE_TRANSACTIONS                     = 0xf
	TCP_CORK                                    = 0x3
	TCP_DEFER_ACCEPT                            = 0x9
	TCP_FASTOPEN                                = 0x17
	TCP_FASTOPEN_CONNECT                        = 0x1e
	TCP_FASTOPEN_KEY                            = 0x21
	TCP_FASTOPEN_NO_COOKIE                      = 0x22
	TCP_INFO                                    = 0xb
	TCP_INQ                                     = 0x24
	TCP_KEEPCNT                                 = 0x6
	TCP_KEEPIDLE                                = 0x4
	TCP_KEEPINTVL                               = 0x5
	TCP_LINGER2                                 = 0x8
	TCP_MAXSEG                                  = 0x2
	TCP_MAXWIN                                  = 0xffff
	TCP_MAX_WINSHIFT                            = 0xe
	TCP_MD5SIG                                  = 0xe
	TCP_MD5SIG_EXT                              = 0x20
	TCP_MD5SIG_FLAG_IFINDEX                     = 0x2
	TCP_MD5SIG_FLAG_PREFIX                      = 0x1
	TCP_MD5SIG_MAXKEYLEN                        = 0x50
	TCP_MSS                                     = 0x200
	TCP_MSS_DEFAULT                             = 0x218
	TCP_MSS_DESIRED                             = 0x4c4
	TCP_NODELAY                                 = 0x1
	TCP_NOTSENT_LOWAT                           = 0x19
	TCP_QUEUE_SEQ                               = 0x15
	TCP_QUICKACK                                = 0xc
	TCP_REPAIR                                  = 0x13
	TCP_REPAIR_OFF                              = 0x0
	TCP_REPAIR_OFF_NO_WP                        = -0x1
	TCP_REPAIR_ON                               = 0x1
	TCP_REPAIR_OPTIONS                          = 0x16
	TCP_REPAIR_QUEUE                            = 0x14
	TCP_REPAIR_WINDOW                           = 0x1d
	TCP_SAVED_SYN                               = 0x1c
	TCP_SAVE_SYN                                = 0x1b
	TCP_SYNCNT                                  = 0x7
	TCP_S_DATA_IN                               = 0x4
	TCP_S_DATA_OUT                              = 0x8
	TCP_THIN_DUPACK                             = 0x11
	TCP_THIN_LINEAR_TIMEOUTS                    = 0x10
	TCP_TIMESTAMP                               = 0x18
	TCP_TX_DELAY                                = 0x25
	TCP_ULP                                     = 0x1f
	TCP_USER_TIMEOUT                            = 0x12
	TCP_V4_FLOW                                 = 0x1
	TCP_V6_FLOW                                 = 0x5
	TCP_WINDOW_CLAMP                            = 0xa
	TCP_ZEROCOPY_RECEIVE                        = 0x23
	TFD_TIMER_ABSTIME                           = 0x1
	TFD_TIMER_CANCEL_ON_SET                     = 0x2
	TIMER_ABSTIME                               = 0x1
	TIOCM_DTR                                   = 0x2
	TIOCM_LE                                    = 0x1
	TIOCM_RTS                                   = 0x4
	TIOCPKT_DATA                                = 0x0
	TIOCPKT_DOSTOP                              = 0x20
	TIOCPKT_FLUSHREAD                           = 0x1
	TIOCPKT_FLUSHWRITE                          = 0x2
	TIOCPKT_IOCTL                               = 0x40
	TIOCPKT_NOSTOP                              = 0x10
	TIOCPKT_START                               = 0x8
	TIOCPKT_STOP                                = 0x4
	TIPC_ADDR_ID                                = 0x3
	TIPC_ADDR_MCAST                             = 0x1
	TIPC_ADDR_NAME                              = 0x2
	TIPC_ADDR_NAMESEQ                           = 0x1
	TIPC_AEAD_ALG_NAME                          = 0x20
	TIPC_AEAD_KEYLEN_MAX                        = 0x24
	TIPC_AEAD_KEYLEN_MIN                        = 0x14
	TIPC_AEAD_KEY_SIZE_MAX                      = 0x48
	TIPC_CFG_SRV                                = 0x0
	TIPC_CLUSTER_BITS                           = 0xc
	TIPC_CLUSTER_MASK                           = 0xfff000
	TIPC_CLUSTER_OFFSET                         = 0xc
	TIPC_CLUSTER_SIZE                           = 0xfff
	TIPC_CONN_SHUTDOWN                          = 0x5
	TIPC_CONN_TIMEOUT                           = 0x82
	TIPC_CRITICAL_IMPORTANCE                    = 0x3
	TIPC_DESTNAME                               = 0x3
	TIPC_DEST_DROPPABLE                         = 0x81
	TIPC_ERRINFO                                = 0x1
	TIPC_ERR_NO_NAME                            = 0x1
	TIPC_ERR_NO_NODE                            = 0x3
	TIPC_ERR_NO_PORT                            = 0x2
	TIPC_ERR_OVERLOAD                           = 0x4
	TIPC_GROUP_JOIN                             = 0x87
	TIPC_GROUP_LEAVE                            = 0x88
	TIPC_GROUP_LOOPBACK                         = 0x1
	TIPC_GROUP_MEMBER_EVTS                      = 0x2
	TIPC_HIGH_IMPORTANCE                        = 0x2
	TIPC_IMPORTANCE                             = 0x7f
	TIPC_LINK_STATE                             = 0x2
	TIPC_LOW_IMPORTANCE                         = 0x0
	TIPC_MAX_BEARER_NAME                        = 0x20
	TIPC_MAX_IF_NAME                            = 0x10
	TIPC_MAX_LINK_NAME                          = 0x44
	TIPC_MAX_MEDIA_NAME                         = 0x10
	TIPC_MAX_USER_MSG_SIZE                      = 0x101d0
	TIPC_MCAST_BROADCAST                        = 0x85
	TIPC_MCAST_REPLICAST                        = 0x86
	TIPC_MEDIUM_IMPORTANCE                      = 0x1
	TIPC_NODEID_LEN                             = 0x10
	TIPC_NODELAY                                = 0x8a
	TIPC_NODE_BITS                              = 0xc
	TIPC_NODE_MASK                              = 0xfff
	TIPC_NODE_OFFSET                            = 0x0
	TIPC_NODE_RECVQ_DEPTH                       = 0x83
	TIPC_NODE_SIZE                              = 0xfff
	TIPC_NODE_STATE                             = 0x0
	TIPC_OK                                     = 0x0
	TIPC_PUBLISHED                              = 0x1
	TIPC_REKEYING_NOW                           = 0xffffffff
	TIPC_RESERVED_TYPES                         = 0x40
	TIPC_RETDATA                                = 0x2
	TIPC_SERVICE_ADDR                           = 0x2
	TIPC_SERVICE_RANGE                          = 0x1
	TIPC_SOCKET_ADDR                            = 0x3
	TIPC_SOCK_RECVQ_DEPTH                       = 0x84
	TIPC_SOCK_RECVQ_USED                        = 0x89
	TIPC_SRC_DROPPABLE                          = 0x80
	TIPC_SUBSCR_TIMEOUT                         = 0x3
	TIPC_SUB_CANCEL                             = 0x4
	TIPC_SUB_PORTS                              = 0x1
	TIPC_SUB_SERVICE                            = 0x2
	TIPC_TOP_SRV                                = 0x1
	TIPC_WAIT_FOREVER                           = 0xffffffff
	TIPC_WITHDRAWN                              = 0x2
	TIPC_ZONE_BITS                              = 0x8
	TIPC_ZONE_CLUSTER_MASK                      = 0xfffff000
	TIPC_ZONE_MASK                              = 0xff000000
	TIPC_ZONE_OFFSET                            = 0x18
	TIPC_ZONE_SCOPE                             = 0x1
	TIPC_ZONE_SIZE                              = 0xff
	TMPFS_MAGIC                                 = 0x1021994
	TPACKET_ALIGNMENT                           = 0x10
	TPACKET_HDRLEN                              = 0x34
	TP_STATUS_AVAILABLE                         = 0x0
	TP_STATUS_BLK_TMO                           = 0x20
	TP_STATUS_COPY                              = 0x2
	TP_STATUS_CSUMNOTREADY                      = 0x8
	TP_STATUS_CSUM_VALID                        = 0x80
	TP_STATUS_GSO_TCP                           = 0x100
	TP_STATUS_KERNEL                            = 0x0
	TP_STATUS_LOSING                            = 0x4
	TP_STATUS_SENDING                           = 0x2
	TP_STATUS_SEND_REQUEST                      = 0x1
	TP_STATUS_TS_RAW_HARDWARE                   = 0x80000000
	TP_STATUS_TS_SOFTWARE                       = 0x20000000
	TP_STATUS_TS_SYS_HARDWARE                   = 0x40000000
	TP_STATUS_USER                              = 0x1
	TP_STATUS_VLAN_TPID_VALID                   = 0x40
	TP_STATUS_VLAN_VALID                        = 0x10
	TP_STATUS_WRONG_FORMAT                      = 0x4
	TRACEFS_MAGIC                               = 0x74726163
	TS_COMM_LEN                                 = 0x20
	UDF_SUPER_MAGIC                             = 0x15013346
	UDP_CORK                                    = 0x1
	UDP_ENCAP                                   = 0x64
	UDP_ENCAP_ESPINUDP                          = 0x2
	UDP_ENCAP_ESPINUDP_NON_IKE                  = 0x1
	UDP_ENCAP_GTP0                              = 0x4
	UDP_ENCAP_GTP1U                             = 0x5
	UDP_ENCAP_L2TPINUDP                         = 0x3
	UDP_GRO                                     = 0x68
	UDP_NO_CHECK6_RX                            = 0x66
	UDP_NO_CHECK6_TX                            = 0x65
	UDP_SEGMENT                                 = 0x67
	UDP_V4_FLOW                                 = 0x2
	UDP_V6_FLOW                                 = 0x6
	UMOUNT_NOFOLLOW                             = 0x8
	USBDEVICE_SUPER_MAGIC                       = 0x9fa2
	UTIME_NOW                                   = 0x3fffffff
	UTIME_OMIT                                  = 0x3ffffffe
	V9FS_MAGIC                                  = 0x1021997
	VERASE                                      = 0x2
	VINTR                                       = 0x0
	VKILL                                       = 0x3
	VLNEXT                                      = 0xf
	VMADDR_CID_ANY                              = 0xffffffff
	VMADDR_CID_HOST                             = 0x2
	VMADDR_CID_HYPERVISOR                       = 0x0
	VMADDR_CID_LOCAL                            = 0x1
	VMADDR_FLAG_TO_HOST                         = 0x1
	VMADDR_PORT_ANY                             = 0xffffffff
	VM_SOCKETS_INVALID_VERSION                  = 0xffffffff
	VQUIT                                       = 0x1
	VT0                                         = 0x0
	WAKE_MAGIC                                  = 0x20
	WALL                                        = 0x40000000
	WCLONE                                      = 0x80000000
	WCONTINUED                                  = 0x8
	WDIOC_SETPRETIMEOUT                         = 0xc0045708
	WDIOC_SETTIMEOUT                            = 0xc0045706
	WDIOF_ALARMONLY                             = 0x400
	WDIOF_CARDRESET                             = 0x20
	WDIOF_EXTERN1                               = 0x4
	WDIOF_EXTERN2                               = 0x8
	WDIOF_FANFAULT                              = 0x2
	WDIOF_KEEPALIVEPING                         = 0x8000
	WDIOF_MAGICCLOSE                            = 0x100
	WDIOF_OVERHEAT                              = 0x1
	WDIOF_POWEROVER                             = 0x40
	WDIOF_POWERUNDER                            = 0x10
	WDIOF_PRETIMEOUT                            = 0x200
	WDIOF_SETTIMEOUT                            = 0x80
	WDIOF_UNKNOWN                               = -0x1
	WDIOS_DISABLECARD                           = 0x1
	WDIOS_ENABLECARD                            = 0x2
	WDIOS_TEMPPANIC                             = 0x4
	WDIOS_UNKNOWN                               = -0x1
	WEXITED                                     = 0x4
	WGALLOWEDIP_A_MAX                           = 0x3
	WGDEVICE_A_MAX                              = 0x8
	WGPEER_A_MAX                                = 0xa
	WG_CMD_MAX                                  = 0x1
	WG_GENL_NAME                                = "wireguard"
	WG_GENL_VERSION                             = 0x1
	WG_KEY_LEN                                  = 0x20
	WIN_ACKMEDIACHANGE                          = 0xdb
	WIN_CHECKPOWERMODE1                         = 0xe5
	WIN_CHECKPOWERMODE2                         = 0x98
	WIN_DEVICE_RESET                            = 0x8
	WIN_DIAGNOSE                                = 0x90
	WIN_DOORLOCK                                = 0xde
	WIN_DOORUNLOCK                              = 0xdf
	WIN_DOWNLOAD_MICROCODE                      = 0x92
	WIN_FLUSH_CACHE                             = 0xe7
	WIN_FLUSH_CACHE_EXT                         = 0xea
	WIN_FORMAT                                  = 0x50
	WIN_GETMEDIASTATUS                          = 0xda
	WIN_IDENTIFY                                = 0xec
	WIN_IDENTIFY_DMA                            = 0xee
	WIN_IDLEIMMEDIATE                           = 0xe1
	WIN_INIT                                    = 0x60
	WIN_MEDIAEJECT                              = 0xed
	WIN_MULTREAD                                = 0xc4
	WIN_MULTREAD_EXT                            = 0x29
	WIN_MULTWRITE                               = 0xc5
	WIN_MULTWRITE_EXT                           = 0x39
	WIN_NOP                                     = 0x0
	WIN_PACKETCMD                               = 0xa0
	WIN_PIDENTIFY                               = 0xa1
	WIN_POSTBOOT                                = 0xdc
	WIN_PREBOOT                                 = 0xdd
	WIN_QUEUED_SERVICE                          = 0xa2
	WIN_READ                                    = 0x20
	WIN_READDMA                                 = 0xc8
	WIN_READDMA_EXT                             = 0x25
	WIN_READDMA_ONCE                            = 0xc9
	WIN_READDMA_QUEUED                          = 0xc7
	WIN_READDMA_QUEUED_EXT                      = 0x26
	WIN_READ_BUFFER                             = 0xe4
	WIN_READ_EXT                                = 0x24
	WIN_READ_LONG                               = 0x22
	WIN_READ_LONG_ONCE                          = 0x23
	WIN_READ_NATIVE_MAX                         = 0xf8
	WIN_READ_NATIVE_MAX_EXT                     = 0x27
	WIN_READ_ONCE                               = 0x21
	WIN_RECAL                                   = 0x10
	WIN_RESTORE                                 = 0x10
	WIN_SECURITY_DISABLE                        = 0xf6
	WIN_SECURITY_ERASE_PREPARE                  = 0xf3
	WIN_SECURITY_ERASE_UNIT                     = 0xf4
	WIN_SECURITY_FREEZE_LOCK                    = 0xf5
	WIN_SECURITY_SET_PASS                       = 0xf1
	WIN_SECURITY_UNLOCK                         = 0xf2
	WIN_SEEK                                    = 0x70
	WIN_SETFEATURES                             = 0xef
	WIN_SETIDLE1                                = 0xe3
	WIN_SETIDLE2                                = 0x97
	WIN_SETMULT                                 = 0xc6
	WIN_SET_MAX                                 = 0xf9
	WIN_SET_MAX_EXT                             = 0x37
	WIN_SLEEPNOW1                               = 0xe6
	WIN_SLEEPNOW2                               = 0x99
	WIN_SMART                                   = 0xb0
	WIN_SPECIFY                                 = 0x91
	WIN_SRST                                    = 0x8
	WIN_STANDBY                                 = 0xe2
	WIN_STANDBY2                                = 0x96
	WIN_STANDBYNOW1                             = 0xe0
	WIN_STANDBYNOW2                             = 0x94
	WIN_VERIFY                                  = 0x40
	WIN_VERIFY_EXT                              = 0x42
	WIN_VERIFY_ONCE                             = 0x41
	WIN_WRITE                                   = 0x30
	WIN_WRITEDMA                                = 0xca
	WIN_WRITEDMA_EXT                            = 0x35
	WIN_WRITEDMA_ONCE                           = 0xcb
	WIN_WRITEDMA_QUEUED                         = 0xcc
	WIN_WRITEDMA_QUEUED_EXT                     = 0x36
	WIN_WRITE_BUFFER                            = 0xe8
	WIN_WRITE_EXT                               = 0x34
	WIN_WRITE_LONG                              = 0x32
	WIN_WRITE_LONG_ONCE                         = 0x33
	WIN_WRITE_ONCE                              = 0x31
	WIN_WRITE_SAME                              = 0xe9
	WIN_WRITE_VERIFY                            = 0x3c
	WNOHANG                                     = 0x1
	WNOTHREAD                                   = 0x20000000
	WNOWAIT                                     = 0x1000000
	WSTOPPED                                    = 0x2
	WUNTRACED                                   = 0x2
	XATTR_CREATE                                = 0x1
	XATTR_REPLACE                               = 0x2
	XDP_COPY                                    = 0x2
	XDP_FLAGS_DRV_MODE                          = 0x4
	XDP_FLAGS_HW_MODE                           = 0x8
	XDP_FLAGS_MASK                              = 0x1f
	XDP_FLAGS_MODES                             = 0xe
	XDP_FLAGS_REPLACE                           = 0x10
	XDP_FLAGS_SKB_MODE                          = 0x2
	XDP_FLAGS_UPDATE_IF_NOEXIST                 = 0x1
	XDP_MMAP_OFFSETS                            = 0x1
	XDP_OPTIONS                                 = 0x8
	XDP_OPTIONS_ZEROCOPY                        = 0x1
	XDP_PACKET_HEADROOM                         = 0x100
	XDP_PGOFF_RX_RING                           = 0x0
	XDP_PGOFF_TX_RING                           = 0x80000000
	XDP_PKT_CONTD                               = 0x1
	XDP_RING_NEED_WAKEUP                        = 0x1
	XDP_RX_RING                                 = 0x2
	XDP_SHARED_UMEM                             = 0x1
	XDP_STATISTICS                              = 0x7
	XDP_TXMD_FLAGS_CHECKSUM                     = 0x2
	XDP_TXMD_FLAGS_TIMESTAMP                    = 0x1
	XDP_TX_METADATA                             = 0x2
	XDP_TX_RING                                 = 0x3
	XDP_UMEM_COMPLETION_RING                    = 0x6
	XDP_UMEM_FILL_RING                          = 0x5
	XDP_UMEM_PGOFF_COMPLETION_RING              = 0x180000000
	XDP_UMEM_PGOFF_FILL_RING                    = 0x100000000
	XDP_UMEM_REG                                = 0x4
	XDP_UMEM_TX_METADATA_LEN                    = 0x4
	XDP_UMEM_TX_SW_CSUM                         = 0x2
	XDP_UMEM_UNALIGNED_CHUNK_FLAG               = 0x1
	XDP_USE_NEED_WAKEUP                         = 0x8
	XDP_USE_SG                                  = 0x10
	XDP_ZEROCOPY                                = 0x4
	XENFS_SUPER_MAGIC                           = 0xabba1974
	XFS_SUPER_MAGIC                             = 0x58465342
	ZONEFS_MAGIC                                = 0x5a4f4653
	_HIDIOCGRAWNAME_LEN                         = 0x80
	_HIDIOCGRAWPHYS_LEN                         = 0x40
	_HIDIOCGRAWUNIQ_LEN                         = 0x40
)

// Errors
const (
	E2BIG       = syscall.Errno(0x7)
	EACCES      = syscall.Errno(0xd)
	EAGAIN      = syscall.Errno(0xb)
	EBADF       = syscall.Errno(0x9)
	EBUSY       = syscall.Errno(0x10)
	ECHILD      = syscall.Errno(0xa)
	EDOM        = syscall.Errno(0x21)
	EEXIST      = syscall.Errno(0x11)
	EFAULT      = syscall.Errno(0xe)
	EFBIG       = syscall.Errno(0x1b)
	EINTR       = syscall.Errno(0x4)
	EINVAL      = syscall.Errno(0x16)
	EIO         = syscall.Errno(0x5)
	EISDIR      = syscall.Errno(0x15)
	EMFILE      = syscall.Errno(0x18)
	EMLINK      = syscall.Errno(0x1f)
	ENFILE      = syscall.Errno(0x17)
	ENODEV      = syscall.Errno(0x13)
	ENOENT      = syscall.Errno(0x2)
	ENOEXEC     = syscall.Errno(0x8)
	ENOMEM      = syscall.Errno(0xc)
	ENOSPC      = syscall.Errno(0x1c)
	ENOTBLK     = syscall.Errno(0xf)
	ENOTDIR     = syscall.Errno(0x14)
	ENOTTY      = syscall.Errno(0x19)
	ENXIO       = syscall.Errno(0x6)
	EPERM       = syscall.Errno(0x1)
	EPIPE       = syscall.Errno(0x20)
	ERANGE      = syscall.Errno(0x22)
	EROFS       = syscall.Errno(0x1e)
	ESPIPE      = syscall.Errno(0x1d)
	ESRCH       = syscall.Errno(0x3)
	ETXTBSY     = syscall.Errno(0x1a)
	EWOULDBLOCK = syscall.Errno(0xb)
	EXDEV       = syscall.Errno(0x12)
)

// Signals
const (
	SIGABRT = syscall.Signal(0x6)
	SIGALRM = syscall.Signal(0xe)
	SIGFPE  = syscall.Signal(0x8)
	SIGHUP  = syscall.Signal(0x1)
	SIGILL  = syscall.Signal(0x4)
	SIGINT  = syscall.Signal(0x2)
	SIGIOT  = syscall.Signal(0x6)
	SIGKILL = syscall.Signal(0x9)
	SIGPIPE = syscall.Signal(0xd)
	SIGQUIT = syscall.Signal(0x3)
	SIGSEGV = syscall.Signal(0xb)
	SIGTERM = syscall.Signal(0xf)
	SIGTRAP = syscall.Signal(0x5)
)
```