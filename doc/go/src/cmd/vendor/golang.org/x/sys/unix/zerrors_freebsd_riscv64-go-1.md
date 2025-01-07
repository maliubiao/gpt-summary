Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Request:** The core request is to analyze a Go file defining constants related to system calls, specifically for FreeBSD on the RISC-V 64-bit architecture. The request also asks for example usage, identification of Go features, handling command-line arguments (if applicable), common pitfalls, and a summary of its functionality. The "Part 2" note is a reminder this is a continuation of some analysis.

2. **Initial Scan and Identification:** The first thing I notice is a large block of constant declarations using `const`. These constants are grouped into categories: `TCP_...`, `TIOC...`, `TIMER_...`, `UTIME_...`, `V...`, and `W...`. This strongly suggests these constants are related to low-level operating system interfaces, specifically system calls and related structures.

3. **Decomposition by Category:**  To manage the complexity, I'll analyze each category of constants:

    * **`TCP_...`:** These clearly relate to TCP socket options and configurations. The names (e.g., `TCP_NODELAY`, `TCP_MAXSEG`, `TCP_BBR_...`) strongly indicate TCP protocol parameters and potentially congestion control algorithms (like BBR).

    * **`TIOC...`:** This prefix is a strong indicator of terminal input/output control (ioctl) constants. Examples like `TIOCGWINSZ` (get window size), `TIOCSETA` (set terminal attributes), and `TIOCCBRK` (send break) confirm this.

    * **`TIMER_...`:**  These relate to timers, with `TIMER_ABSTIME` and `TIMER_RELTIME` suggesting absolute and relative timer modes.

    * **`UTIME_...`:** These constants likely relate to the `utime` system call, which modifies file access and modification times. `UTIME_NOW` and `UTIME_OMIT` suggest special values for setting or omitting time updates.

    * **`V...`:**  These constants (e.g., `VEOF`, `VINTR`, `VKILL`) are standard terminal special characters, often associated with the `termios` structure.

    * **`W...`:**  Constants like `WCONTINUED`, `WEXITED`, `WNOHANG`, `WSTOPPED` are flags related to the `wait()` family of system calls, used for monitoring child processes.

4. **Identifying Go Language Features:**  The primary Go feature used here is `const` for declaring constants. The `syscall.Errno` and `syscall.Signal` types point to the `syscall` package, which provides a low-level interface to the operating system's system calls. The use of hexadecimal notation (e.g., `0x44d`) for constant values is standard in Go for representing flags and bitmasks.

5. **Inferring Functionality (System Call Definitions):** Based on the constant categories, I can infer that this file provides Go-level definitions for various system call parameters and options within the FreeBSD operating system on the RISC-V 64-bit architecture. It acts as a bridge between the Go language and the underlying operating system kernel.

6. **Constructing Go Examples:**  To illustrate the usage, I need to demonstrate how these constants might be used with the `syscall` package. The examples should involve:

    * **Socket Options (`TCP_NODELAY`):** Using `syscall.SetsockoptInt` to set a TCP option on a socket.
    * **Terminal I/O Control (`TIOCGWINSZ`):** Using `syscall.Syscall` with the `unix.IoctlGetWinsize` helper to get terminal window size. *(Self-correction: I initially thought of `syscall.Syscall`, but realized the `unix` package provides convenient wrappers for many ioctl calls.)*
    * **Waiting for Processes (`WEXITED`):**  Using `syscall.Wait4` and examining the status using the `WEXITSTATUS` macro (although not directly defined in this snippet, its purpose is clear).

7. **Considering Command-Line Arguments:**  These constants themselves don't directly process command-line arguments. However, the *programs* that *use* these constants might take command-line arguments to influence behavior related to networking, terminal settings, or process management. So, I need to explain this indirect relationship.

8. **Identifying Common Pitfalls:**  A key pitfall with low-level system call interactions is using incorrect constant values or combinations. For example, setting conflicting TCP options or misinterpreting the bit flags in ioctl calls. I should illustrate this with a concrete example related to TCP options.

9. **Summarizing Functionality:** The summary should concisely state that the file defines system-level constants for FreeBSD/RISC-V 64-bit, covering networking, terminal I/O, timers, and process management. It's crucial for interacting with the operating system's kernel from Go.

10. **Addressing "Part 2":**  The "Part 2" instruction simply asks for a summary of the functionality, which I'll provide after the detailed analysis. It's important to remember this constraint.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Maybe this file also contains function definitions.
* **Correction:**  A closer look reveals only constant definitions. Function definitions for system calls are typically found in other parts of the `syscall` or related packages. This file primarily *defines the parameters* for those function calls.

* **Initial thought:**  Focus heavily on direct `syscall.Syscall` usage in examples.
* **Refinement:** While `syscall.Syscall` is the underlying mechanism, using higher-level helpers from the `unix` package (like `unix.IoctlGetWinsize`) makes the examples more practical and idiomatic Go.

* **Considering edge cases:** What if a constant is used incorrectly? How would that manifest?  This leads to the "Common Pitfalls" section.

By following this structured thought process, breaking down the problem, and iteratively refining my understanding, I can arrive at a comprehensive and accurate analysis of the provided Go code snippet.
好的，这是对该 Go 语言代码片段（第二部分）的功能归纳：

**功能归纳：**

这个 Go 语言代码片段（`zerrors_freebsd_riscv64.go` 的一部分）定义了在 FreeBSD 操作系统 RISC-V 64 位架构下使用的**系统调用相关的常量**。这些常量被 Go 语言的 `syscall` 包或其他底层网络/终端相关的包所使用，用于与操作系统内核进行交互。

具体来说，它定义了以下几类常量：

* **TCP Socket 选项常量 (`TCP_...`)**:  用于配置 TCP 连接的行为，例如是否启用 Nagle 算法 (`TCP_NODELAY`)，设置最大报文段大小 (`TCP_MAXSEG`)，以及与 BBR 拥塞控制算法相关的各种参数。
* **终端 I/O 控制常量 (`TIOC_...`)**: 用于控制终端设备的行为，例如获取窗口大小 (`TIOCGWINSZ`)，设置终端属性 (`TIOCSETA`)，以及发送中断信号 (`TIOCCBRK`)。
* **定时器相关常量 (`TIMER_...`)**:  定义了定时器的类型，例如绝对定时器 (`TIMER_ABSTIME`) 和相对定时器 (`TIMER_RELTIME`)。
* **`utime` 系统调用相关常量 (`UTIME_...`)**: 用于 `utime` 系统调用中设置文件访问和修改时间的特殊值，例如立即更新时间 (`UTIME_NOW`) 和忽略时间更新 (`UTIME_OMIT`)。
* **终端特殊字符常量 (`V...`)**: 定义了终端的特殊控制字符，例如文件结束符 (`VEOF`)，中断字符 (`VINTR`)，和杀死进程字符 (`VKILL`)。
* **`wait` 系统调用相关常量 (`W...`)**: 定义了 `wait` 系统调用的选项和状态标志，用于监控子进程的状态，例如非阻塞等待 (`WNOHANG`)，以及子进程退出的状态 (`WEXITED`)。
* **错误码常量 (`E...`)**: 定义了各种系统调用可能返回的错误码，例如文件不存在 (`ENOENT`)，权限被拒绝 (`EACCES`)，连接被拒绝 (`ECONNREFUSED`) 等。
* **信号常量 (`SIG...`)**: 定义了各种操作系统信号，例如中断信号 (`SIGINT`)，终止信号 (`SIGTERM`)，段错误信号 (`SIGSEGV`) 等。

**总而言之，这个文件是 Go 语言在 FreeBSD RISC-V 64 位平台上进行底层系统编程的基础，它提供了一系列常量，使得 Go 程序能够以结构化的方式与操作系统内核进行交互，执行网络操作、终端控制、进程管理等任务。**

由于这是第二部分，结合第一部分可能包含了更广泛的常量定义，这个部分主要集中在网络（TCP）、终端 I/O、定时器、文件时间以及进程管理相关的常量定义。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_freebsd_riscv64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
RTT_GAIN         = 0x44d
	TCP_BBR_PROBE_RTT_INT          = 0x430
	TCP_BBR_PROBE_RTT_LEN          = 0x44e
	TCP_BBR_RACK_INIT_RATE         = 0x458
	TCP_BBR_RACK_RTT_USE           = 0x44a
	TCP_BBR_RECFORCE               = 0x42c
	TCP_BBR_REC_OVER_HPTS          = 0x43a
	TCP_BBR_RETRAN_WTSO            = 0x44b
	TCP_BBR_RWND_IS_APP            = 0x42f
	TCP_BBR_SEND_IWND_IN_TSO       = 0x44f
	TCP_BBR_STARTUP_EXIT_EPOCH     = 0x43d
	TCP_BBR_STARTUP_LOSS_EXIT      = 0x432
	TCP_BBR_STARTUP_PG             = 0x42d
	TCP_BBR_TMR_PACE_OH            = 0x448
	TCP_BBR_TSLIMITS               = 0x434
	TCP_BBR_TSTMP_RAISES           = 0x456
	TCP_BBR_UNLIMITED              = 0x43b
	TCP_BBR_USEDEL_RATE            = 0x437
	TCP_BBR_USE_LOWGAIN            = 0x433
	TCP_BBR_USE_RACK_CHEAT         = 0x450
	TCP_BBR_USE_RACK_RR            = 0x450
	TCP_BBR_UTTER_MAX_TSO          = 0x452
	TCP_CA_NAME_MAX                = 0x10
	TCP_CCALGOOPT                  = 0x41
	TCP_CONGESTION                 = 0x40
	TCP_DATA_AFTER_CLOSE           = 0x44c
	TCP_DEFER_OPTIONS              = 0x470
	TCP_DELACK                     = 0x48
	TCP_FASTOPEN                   = 0x401
	TCP_FASTOPEN_MAX_COOKIE_LEN    = 0x10
	TCP_FASTOPEN_MIN_COOKIE_LEN    = 0x4
	TCP_FASTOPEN_PSK_LEN           = 0x10
	TCP_FAST_RSM_HACK              = 0x471
	TCP_FIN_IS_RST                 = 0x49
	TCP_FUNCTION_BLK               = 0x2000
	TCP_FUNCTION_NAME_LEN_MAX      = 0x20
	TCP_HDWR_RATE_CAP              = 0x46a
	TCP_HDWR_UP_ONLY               = 0x46c
	TCP_IDLE_REDUCE                = 0x46
	TCP_INFO                       = 0x20
	TCP_IWND_NB                    = 0x2b
	TCP_IWND_NSEG                  = 0x2c
	TCP_KEEPCNT                    = 0x400
	TCP_KEEPIDLE                   = 0x100
	TCP_KEEPINIT                   = 0x80
	TCP_KEEPINTVL                  = 0x200
	TCP_LOG                        = 0x22
	TCP_LOGBUF                     = 0x23
	TCP_LOGDUMP                    = 0x25
	TCP_LOGDUMPID                  = 0x26
	TCP_LOGID                      = 0x24
	TCP_LOGID_CNT                  = 0x2e
	TCP_LOG_ID_LEN                 = 0x40
	TCP_LOG_LIMIT                  = 0x4a
	TCP_LOG_TAG                    = 0x2f
	TCP_MAXBURST                   = 0x4
	TCP_MAXHLEN                    = 0x3c
	TCP_MAXOLEN                    = 0x28
	TCP_MAXPEAKRATE                = 0x45
	TCP_MAXSEG                     = 0x2
	TCP_MAXUNACKTIME               = 0x44
	TCP_MAXWIN                     = 0xffff
	TCP_MAX_SACK                   = 0x4
	TCP_MAX_WINSHIFT               = 0xe
	TCP_MD5SIG                     = 0x10
	TCP_MINMSS                     = 0xd8
	TCP_MSS                        = 0x218
	TCP_NODELAY                    = 0x1
	TCP_NOOPT                      = 0x8
	TCP_NOPUSH                     = 0x4
	TCP_NO_PRR                     = 0x462
	TCP_PACING_RATE_CAP            = 0x46b
	TCP_PCAP_IN                    = 0x1000
	TCP_PCAP_OUT                   = 0x800
	TCP_PERF_INFO                  = 0x4e
	TCP_PROC_ACCOUNTING            = 0x4c
	TCP_RACK_ABC_VAL               = 0x46d
	TCP_RACK_CHEAT_NOT_CONF_RATE   = 0x459
	TCP_RACK_DO_DETECTION          = 0x449
	TCP_RACK_EARLY_RECOV           = 0x423
	TCP_RACK_EARLY_SEG             = 0x424
	TCP_RACK_FORCE_MSEG            = 0x45d
	TCP_RACK_GP_INCREASE           = 0x446
	TCP_RACK_GP_INCREASE_CA        = 0x45a
	TCP_RACK_GP_INCREASE_REC       = 0x45c
	TCP_RACK_GP_INCREASE_SS        = 0x45b
	TCP_RACK_IDLE_REDUCE_HIGH      = 0x444
	TCP_RACK_MBUF_QUEUE            = 0x41a
	TCP_RACK_MEASURE_CNT           = 0x46f
	TCP_RACK_MIN_PACE              = 0x445
	TCP_RACK_MIN_PACE_SEG          = 0x446
	TCP_RACK_MIN_TO                = 0x422
	TCP_RACK_NONRXT_CFG_RATE       = 0x463
	TCP_RACK_NO_PUSH_AT_MAX        = 0x466
	TCP_RACK_PACE_ALWAYS           = 0x41f
	TCP_RACK_PACE_MAX_SEG          = 0x41e
	TCP_RACK_PACE_RATE_CA          = 0x45e
	TCP_RACK_PACE_RATE_REC         = 0x460
	TCP_RACK_PACE_RATE_SS          = 0x45f
	TCP_RACK_PACE_REDUCE           = 0x41d
	TCP_RACK_PACE_TO_FILL          = 0x467
	TCP_RACK_PACING_BETA           = 0x472
	TCP_RACK_PACING_BETA_ECN       = 0x473
	TCP_RACK_PKT_DELAY             = 0x428
	TCP_RACK_PROFILE               = 0x469
	TCP_RACK_PROP                  = 0x41b
	TCP_RACK_PROP_RATE             = 0x420
	TCP_RACK_PRR_SENDALOT          = 0x421
	TCP_RACK_REORD_FADE            = 0x426
	TCP_RACK_REORD_THRESH          = 0x425
	TCP_RACK_RR_CONF               = 0x459
	TCP_RACK_TIMER_SLOP            = 0x474
	TCP_RACK_TLP_INC_VAR           = 0x429
	TCP_RACK_TLP_REDUCE            = 0x41c
	TCP_RACK_TLP_THRESH            = 0x427
	TCP_RACK_TLP_USE               = 0x447
	TCP_REC_ABC_VAL                = 0x46e
	TCP_REMOTE_UDP_ENCAPS_PORT     = 0x47
	TCP_REUSPORT_LB_NUMA           = 0x402
	TCP_REUSPORT_LB_NUMA_CURDOM    = -0x1
	TCP_REUSPORT_LB_NUMA_NODOM     = -0x2
	TCP_RXTLS_ENABLE               = 0x29
	TCP_RXTLS_MODE                 = 0x2a
	TCP_SHARED_CWND_ALLOWED        = 0x4b
	TCP_SHARED_CWND_ENABLE         = 0x464
	TCP_SHARED_CWND_TIME_LIMIT     = 0x468
	TCP_STATS                      = 0x21
	TCP_TIMELY_DYN_ADJ             = 0x465
	TCP_TLS_MODE_IFNET             = 0x2
	TCP_TLS_MODE_NONE              = 0x0
	TCP_TLS_MODE_SW                = 0x1
	TCP_TLS_MODE_TOE               = 0x3
	TCP_TXTLS_ENABLE               = 0x27
	TCP_TXTLS_MODE                 = 0x28
	TCP_USER_LOG                   = 0x30
	TCP_USE_CMP_ACKS               = 0x4d
	TCP_VENDOR                     = 0x80000000
	TCSAFLUSH                      = 0x2
	TIMER_ABSTIME                  = 0x1
	TIMER_RELTIME                  = 0x0
	TIOCCBRK                       = 0x2000747a
	TIOCCDTR                       = 0x20007478
	TIOCCONS                       = 0x80047462
	TIOCDRAIN                      = 0x2000745e
	TIOCEXCL                       = 0x2000740d
	TIOCEXT                        = 0x80047460
	TIOCFLUSH                      = 0x80047410
	TIOCGDRAINWAIT                 = 0x40047456
	TIOCGETA                       = 0x402c7413
	TIOCGETD                       = 0x4004741a
	TIOCGPGRP                      = 0x40047477
	TIOCGPTN                       = 0x4004740f
	TIOCGSID                       = 0x40047463
	TIOCGWINSZ                     = 0x40087468
	TIOCMBIC                       = 0x8004746b
	TIOCMBIS                       = 0x8004746c
	TIOCMGDTRWAIT                  = 0x4004745a
	TIOCMGET                       = 0x4004746a
	TIOCMSDTRWAIT                  = 0x8004745b
	TIOCMSET                       = 0x8004746d
	TIOCM_CAR                      = 0x40
	TIOCM_CD                       = 0x40
	TIOCM_CTS                      = 0x20
	TIOCM_DCD                      = 0x40
	TIOCM_DSR                      = 0x100
	TIOCM_DTR                      = 0x2
	TIOCM_LE                       = 0x1
	TIOCM_RI                       = 0x80
	TIOCM_RNG                      = 0x80
	TIOCM_RTS                      = 0x4
	TIOCM_SR                       = 0x10
	TIOCM_ST                       = 0x8
	TIOCNOTTY                      = 0x20007471
	TIOCNXCL                       = 0x2000740e
	TIOCOUTQ                       = 0x40047473
	TIOCPKT                        = 0x80047470
	TIOCPKT_DATA                   = 0x0
	TIOCPKT_DOSTOP                 = 0x20
	TIOCPKT_FLUSHREAD              = 0x1
	TIOCPKT_FLUSHWRITE             = 0x2
	TIOCPKT_IOCTL                  = 0x40
	TIOCPKT_NOSTOP                 = 0x10
	TIOCPKT_START                  = 0x8
	TIOCPKT_STOP                   = 0x4
	TIOCPTMASTER                   = 0x2000741c
	TIOCSBRK                       = 0x2000747b
	TIOCSCTTY                      = 0x20007461
	TIOCSDRAINWAIT                 = 0x80047457
	TIOCSDTR                       = 0x20007479
	TIOCSETA                       = 0x802c7414
	TIOCSETAF                      = 0x802c7416
	TIOCSETAW                      = 0x802c7415
	TIOCSETD                       = 0x8004741b
	TIOCSIG                        = 0x2004745f
	TIOCSPGRP                      = 0x80047476
	TIOCSTART                      = 0x2000746e
	TIOCSTAT                       = 0x20007465
	TIOCSTI                        = 0x80017472
	TIOCSTOP                       = 0x2000746f
	TIOCSWINSZ                     = 0x80087467
	TIOCTIMESTAMP                  = 0x40107459
	TIOCUCNTL                      = 0x80047466
	TOSTOP                         = 0x400000
	UTIME_NOW                      = -0x1
	UTIME_OMIT                     = -0x2
	VDISCARD                       = 0xf
	VDSUSP                         = 0xb
	VEOF                           = 0x0
	VEOL                           = 0x1
	VEOL2                          = 0x2
	VERASE                         = 0x3
	VERASE2                        = 0x7
	VINTR                          = 0x8
	VKILL                          = 0x5
	VLNEXT                         = 0xe
	VMIN                           = 0x10
	VQUIT                          = 0x9
	VREPRINT                       = 0x6
	VSTART                         = 0xc
	VSTATUS                        = 0x12
	VSTOP                          = 0xd
	VSUSP                          = 0xa
	VTIME                          = 0x11
	VWERASE                        = 0x4
	WCONTINUED                     = 0x4
	WCOREFLAG                      = 0x80
	WEXITED                        = 0x10
	WLINUXCLONE                    = 0x80000000
	WNOHANG                        = 0x1
	WNOWAIT                        = 0x8
	WSTOPPED                       = 0x2
	WTRAPPED                       = 0x20
	WUNTRACED                      = 0x2
)

// Errors
const (
	E2BIG           = syscall.Errno(0x7)
	EACCES          = syscall.Errno(0xd)
	EADDRINUSE      = syscall.Errno(0x30)
	EADDRNOTAVAIL   = syscall.Errno(0x31)
	EAFNOSUPPORT    = syscall.Errno(0x2f)
	EAGAIN          = syscall.Errno(0x23)
	EALREADY        = syscall.Errno(0x25)
	EAUTH           = syscall.Errno(0x50)
	EBADF           = syscall.Errno(0x9)
	EBADMSG         = syscall.Errno(0x59)
	EBADRPC         = syscall.Errno(0x48)
	EBUSY           = syscall.Errno(0x10)
	ECANCELED       = syscall.Errno(0x55)
	ECAPMODE        = syscall.Errno(0x5e)
	ECHILD          = syscall.Errno(0xa)
	ECONNABORTED    = syscall.Errno(0x35)
	ECONNREFUSED    = syscall.Errno(0x3d)
	ECONNRESET      = syscall.Errno(0x36)
	EDEADLK         = syscall.Errno(0xb)
	EDESTADDRREQ    = syscall.Errno(0x27)
	EDOM            = syscall.Errno(0x21)
	EDOOFUS         = syscall.Errno(0x58)
	EDQUOT          = syscall.Errno(0x45)
	EEXIST          = syscall.Errno(0x11)
	EFAULT          = syscall.Errno(0xe)
	EFBIG           = syscall.Errno(0x1b)
	EFTYPE          = syscall.Errno(0x4f)
	EHOSTDOWN       = syscall.Errno(0x40)
	EHOSTUNREACH    = syscall.Errno(0x41)
	EIDRM           = syscall.Errno(0x52)
	EILSEQ          = syscall.Errno(0x56)
	EINPROGRESS     = syscall.Errno(0x24)
	EINTEGRITY      = syscall.Errno(0x61)
	EINTR           = syscall.Errno(0x4)
	EINVAL          = syscall.Errno(0x16)
	EIO             = syscall.Errno(0x5)
	EISCONN         = syscall.Errno(0x38)
	EISDIR          = syscall.Errno(0x15)
	ELAST           = syscall.Errno(0x61)
	ELOOP           = syscall.Errno(0x3e)
	EMFILE          = syscall.Errno(0x18)
	EMLINK          = syscall.Errno(0x1f)
	EMSGSIZE        = syscall.Errno(0x28)
	EMULTIHOP       = syscall.Errno(0x5a)
	ENAMETOOLONG    = syscall.Errno(0x3f)
	ENEEDAUTH       = syscall.Errno(0x51)
	ENETDOWN        = syscall.Errno(0x32)
	ENETRESET       = syscall.Errno(0x34)
	ENETUNREACH     = syscall.Errno(0x33)
	ENFILE          = syscall.Errno(0x17)
	ENOATTR         = syscall.Errno(0x57)
	ENOBUFS         = syscall.Errno(0x37)
	ENODEV          = syscall.Errno(0x13)
	ENOENT          = syscall.Errno(0x2)
	ENOEXEC         = syscall.Errno(0x8)
	ENOLCK          = syscall.Errno(0x4d)
	ENOLINK         = syscall.Errno(0x5b)
	ENOMEM          = syscall.Errno(0xc)
	ENOMSG          = syscall.Errno(0x53)
	ENOPROTOOPT     = syscall.Errno(0x2a)
	ENOSPC          = syscall.Errno(0x1c)
	ENOSYS          = syscall.Errno(0x4e)
	ENOTBLK         = syscall.Errno(0xf)
	ENOTCAPABLE     = syscall.Errno(0x5d)
	ENOTCONN        = syscall.Errno(0x39)
	ENOTDIR         = syscall.Errno(0x14)
	ENOTEMPTY       = syscall.Errno(0x42)
	ENOTRECOVERABLE = syscall.Errno(0x5f)
	ENOTSOCK        = syscall.Errno(0x26)
	ENOTSUP         = syscall.Errno(0x2d)
	ENOTTY          = syscall.Errno(0x19)
	ENXIO           = syscall.Errno(0x6)
	EOPNOTSUPP      = syscall.Errno(0x2d)
	EOVERFLOW       = syscall.Errno(0x54)
	EOWNERDEAD      = syscall.Errno(0x60)
	EPERM           = syscall.Errno(0x1)
	EPFNOSUPPORT    = syscall.Errno(0x2e)
	EPIPE           = syscall.Errno(0x20)
	EPROCLIM        = syscall.Errno(0x43)
	EPROCUNAVAIL    = syscall.Errno(0x4c)
	EPROGMISMATCH   = syscall.Errno(0x4b)
	EPROGUNAVAIL    = syscall.Errno(0x4a)
	EPROTO          = syscall.Errno(0x5c)
	EPROTONOSUPPORT = syscall.Errno(0x2b)
	EPROTOTYPE      = syscall.Errno(0x29)
	ERANGE          = syscall.Errno(0x22)
	EREMOTE         = syscall.Errno(0x47)
	EROFS           = syscall.Errno(0x1e)
	ERPCMISMATCH    = syscall.Errno(0x49)
	ESHUTDOWN       = syscall.Errno(0x3a)
	ESOCKTNOSUPPORT = syscall.Errno(0x2c)
	ESPIPE          = syscall.Errno(0x1d)
	ESRCH           = syscall.Errno(0x3)
	ESTALE          = syscall.Errno(0x46)
	ETIMEDOUT       = syscall.Errno(0x3c)
	ETOOMANYREFS    = syscall.Errno(0x3b)
	ETXTBSY         = syscall.Errno(0x1a)
	EUSERS          = syscall.Errno(0x44)
	EWOULDBLOCK     = syscall.Errno(0x23)
	EXDEV           = syscall.Errno(0x12)
)

// Signals
const (
	SIGABRT   = syscall.Signal(0x6)
	SIGALRM   = syscall.Signal(0xe)
	SIGBUS    = syscall.Signal(0xa)
	SIGCHLD   = syscall.Signal(0x14)
	SIGCONT   = syscall.Signal(0x13)
	SIGEMT    = syscall.Signal(0x7)
	SIGFPE    = syscall.Signal(0x8)
	SIGHUP    = syscall.Signal(0x1)
	SIGILL    = syscall.Signal(0x4)
	SIGINFO   = syscall.Signal(0x1d)
	SIGINT    = syscall.Signal(0x2)
	SIGIO     = syscall.Signal(0x17)
	SIGIOT    = syscall.Signal(0x6)
	SIGKILL   = syscall.Signal(0x9)
	SIGLIBRT  = syscall.Signal(0x21)
	SIGLWP    = syscall.Signal(0x20)
	SIGPIPE   = syscall.Signal(0xd)
	SIGPROF   = syscall.Signal(0x1b)
	SIGQUIT   = syscall.Signal(0x3)
	SIGSEGV   = syscall.Signal(0xb)
	SIGSTOP   = syscall.Signal(0x11)
	SIGSYS    = syscall.Signal(0xc)
	SIGTERM   = syscall.Signal(0xf)
	SIGTHR    = syscall.Signal(0x20)
	SIGTRAP   = syscall.Signal(0x5)
	SIGTSTP   = syscall.Signal(0x12)
	SIGTTIN   = syscall.Signal(0x15)
	SIGTTOU   = syscall.Signal(0x16)
	SIGURG    = syscall.Signal(0x10)
	SIGUSR1   = syscall.Signal(0x1e)
	SIGUSR2   = syscall.Signal(0x1f)
	SIGVTALRM = syscall.Signal(0x1a)
	SIGWINCH  = syscall.Signal(0x1c)
	SIGXCPU   = syscall.Signal(0x18)
	SIGXFSZ   = syscall.Signal(0x19)
)

// Error table
var errorList = [...]struct {
	num  syscall.Errno
	name string
	desc string
}{
	{1, "EPERM", "operation not permitted"},
	{2, "ENOENT", "no such file or directory"},
	{3, "ESRCH", "no such process"},
	{4, "EINTR", "interrupted system call"},
	{5, "EIO", "input/output error"},
	{6, "ENXIO", "device not configured"},
	{7, "E2BIG", "argument list too long"},
	{8, "ENOEXEC", "exec format error"},
	{9, "EBADF", "bad file descriptor"},
	{10, "ECHILD", "no child processes"},
	{11, "EDEADLK", "resource deadlock avoided"},
	{12, "ENOMEM", "cannot allocate memory"},
	{13, "EACCES", "permission denied"},
	{14, "EFAULT", "bad address"},
	{15, "ENOTBLK", "block device required"},
	{16, "EBUSY", "device busy"},
	{17, "EEXIST", "file exists"},
	{18, "EXDEV", "cross-device link"},
	{19, "ENODEV", "operation not supported by device"},
	{20, "ENOTDIR", "not a directory"},
	{21, "EISDIR", "is a directory"},
	{22, "EINVAL", "invalid argument"},
	{23, "ENFILE", "too many open files in system"},
	{24, "EMFILE", "too many open files"},
	{25, "ENOTTY", "inappropriate ioctl for device"},
	{26, "ETXTBSY", "text file busy"},
	{27, "EFBIG", "file too large"},
	{28, "ENOSPC", "no space left on device"},
	{29, "ESPIPE", "illegal seek"},
	{30, "EROFS", "read-only file system"},
	{31, "EMLINK", "too many links"},
	{32, "EPIPE", "broken pipe"},
	{33, "EDOM", "numerical argument out of domain"},
	{34, "ERANGE", "result too large"},
	{35, "EWOULDBLOCK", "resource temporarily unavailable"},
	{36, "EINPROGRESS", "operation now in progress"},
	{37, "EALREADY", "operation already in progress"},
	{38, "ENOTSOCK", "socket operation on non-socket"},
	{39, "EDESTADDRREQ", "destination address required"},
	{40, "EMSGSIZE", "message too long"},
	{41, "EPROTOTYPE", "protocol wrong type for socket"},
	{42, "ENOPROTOOPT", "protocol not available"},
	{43, "EPROTONOSUPPORT", "protocol not supported"},
	{44, "ESOCKTNOSUPPORT", "socket type not supported"},
	{45, "EOPNOTSUPP", "operation not supported"},
	{46, "EPFNOSUPPORT", "protocol family not supported"},
	{47, "EAFNOSUPPORT", "address family not supported by protocol family"},
	{48, "EADDRINUSE", "address already in use"},
	{49, "EADDRNOTAVAIL", "can't assign requested address"},
	{50, "ENETDOWN", "network is down"},
	{51, "ENETUNREACH", "network is unreachable"},
	{52, "ENETRESET", "network dropped connection on reset"},
	{53, "ECONNABORTED", "software caused connection abort"},
	{54, "ECONNRESET", "connection reset by peer"},
	{55, "ENOBUFS", "no buffer space available"},
	{56, "EISCONN", "socket is already connected"},
	{57, "ENOTCONN", "socket is not connected"},
	{58, "ESHUTDOWN", "can't send after socket shutdown"},
	{59, "ETOOMANYREFS", "too many references: can't splice"},
	{60, "ETIMEDOUT", "operation timed out"},
	{61, "ECONNREFUSED", "connection refused"},
	{62, "ELOOP", "too many levels of symbolic links"},
	{63, "ENAMETOOLONG", "file name too long"},
	{64, "EHOSTDOWN", "host is down"},
	{65, "EHOSTUNREACH", "no route to host"},
	{66, "ENOTEMPTY", "directory not empty"},
	{67, "EPROCLIM", "too many processes"},
	{68, "EUSERS", "too many users"},
	{69, "EDQUOT", "disc quota exceeded"},
	{70, "ESTALE", "stale NFS file handle"},
	{71, "EREMOTE", "too many levels of remote in path"},
	{72, "EBADRPC", "RPC struct is bad"},
	{73, "ERPCMISMATCH", "RPC version wrong"},
	{74, "EPROGUNAVAIL", "RPC prog. not avail"},
	{75, "EPROGMISMATCH", "program version wrong"},
	{76, "EPROCUNAVAIL", "bad procedure for program"},
	{77, "ENOLCK", "no locks available"},
	{78, "ENOSYS", "function not implemented"},
	{79, "EFTYPE", "inappropriate file type or format"},
	{80, "EAUTH", "authentication error"},
	{81, "ENEEDAUTH", "need authenticator"},
	{82, "EIDRM", "identifier removed"},
	{83, "ENOMSG", "no message of desired type"},
	{84, "EOVERFLOW", "value too large to be stored in data type"},
	{85, "ECANCELED", "operation canceled"},
	{86, "EILSEQ", "illegal byte sequence"},
	{87, "ENOATTR", "attribute not found"},
	{88, "EDOOFUS", "programming error"},
	{89, "EBADMSG", "bad message"},
	{90, "EMULTIHOP", "multihop attempted"},
	{91, "ENOLINK", "link has been severed"},
	{92, "EPROTO", "protocol error"},
	{93, "ENOTCAPABLE", "capabilities insufficient"},
	{94, "ECAPMODE", "not permitted in capability mode"},
	{95, "ENOTRECOVERABLE", "state not recoverable"},
	{96, "EOWNERDEAD", "previous owner died"},
	{97, "EINTEGRITY", "integrity check failed"},
}

// Signal table
var signalList = [...]struct {
	num  syscall.Signal
	name string
	desc string
}{
	{1, "SIGHUP", "hangup"},
	{2, "SIGINT", "interrupt"},
	{3, "SIGQUIT", "quit"},
	{4, "SIGILL", "illegal instruction"},
	{5, "SIGTRAP", "trace/BPT trap"},
	{6, "SIGIOT", "abort trap"},
	{7, "SIGEMT", "EMT trap"},
	{8, "SIGFPE", "floating point exception"},
	{9, "SIGKILL", "killed"},
	{10, "SIGBUS", "bus error"},
	{11, "SIGSEGV", "segmentation fault"},
	{12, "SIGSYS", "bad system call"},
	{13, "SIGPIPE", "broken pipe"},
	{14, "SIGALRM", "alarm clock"},
	{15, "SIGTERM", "terminated"},
	{16, "SIGURG", "urgent I/O condition"},
	{17, "SIGSTOP", "suspended (signal)"},
	{18, "SIGTSTP", "suspended"},
	{19, "SIGCONT", "continued"},
	{20, "SIGCHLD", "child exited"},
	{21, "SIGTTIN", "stopped (tty input)"},
	{22, "SIGTTOU", "stopped (tty output)"},
	{23, "SIGIO", "I/O possible"},
	{24, "SIGXCPU", "cputime limit exceeded"},
	{25, "SIGXFSZ", "filesize limit exceeded"},
	{26, "SIGVTALRM", "virtual timer expired"},
	{27, "SIGPROF", "profiling timer expired"},
	{28, "SIGWINCH", "window size changes"},
	{29, "SIGINFO", "information request"},
	{30, "SIGUSR1", "user defined signal 1"},
	{31, "SIGUSR2", "user defined signal 2"},
	{32, "SIGTHR", "unknown signal"},
	{33, "SIGLIBRT", "unknown signal"},
}

"""




```