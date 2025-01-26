Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Observation & Core Task:**

The first thing that jumps out is the `// Code generated` comment at the very top. This is a crucial clue. It immediately tells us this file isn't likely to be hand-written code that implements complex logic. Instead, it's probably the output of some code generation process. The task is to figure out what it *is* and what it *does*.

**2. Identifying the Generator:**

The comments provide more specific information:

* `"mkerrors.sh -m64"`: This suggests a shell script named `mkerrors.sh` was used, likely with a `-m64` flag (indicating 64-bit architecture).
* `"cmd/cgo -godefs; DO NOT EDIT."`: This is another key piece. It points to the `cgo` tool, specifically its `-godefs` subcommand. This tool is used to generate Go definitions from C headers.
* `"_const.go"`: This indicates the input file to `cgo -godefs` was likely a C header file named `_const.go`.

**3. Inferring the Purpose:**

Combining these observations leads to the following deduction: This file contains Go constants that were automatically generated from C preprocessor definitions (macros, enums, etc.). The `syscall` package in Go often needs to interact with operating system APIs, which are typically defined in C. `cgo -godefs` bridges this gap.

**4. Understanding the Content:**

A quick scan of the constants confirms this. We see prefixes like `AF_` (Address Family), `B` (Baud Rate), `BIOC` (Berkeley Internet Options Control), `BPF_` (Berkeley Packet Filter), `CTL_` (Control), `DLT_` (Data Link Type), `DT_` (Directory Entry Type), `ECHO`, `EVFILT_` (Event Filter), `EV_` (Event), `F_` (fcntl), `IFF_` (Interface Flags), `IFT_` (Interface Type), `IGN`, `IMAXBEL`, `IN_` (Internet), `IPPROTO_` (IP Protocol), `IPV6_`, `IP_`, `ISIG`, `ISTRIP`, `IUTF8`, `IXANY`, `IXOFF`, `IXON`, `LOCK_`, `MADV_`, `MAP_`, `MCL_`, `MSG_`, `MS_`, `NAME_MAX`, `NET_RT_`, `NOFLSH`, `NOTE_`, `OCRNL`, `OFDEL`, `OFILL`, `ONLCR`, `ONLRET`, `ONOCR`, `ONOEOT`, `OPOST`, `O_` (Open flags), `PARENB`, `PARMRK`, `PARODD`, `PENDIN`, `PRIO_`, `PROT_`, `PT_`. These prefixes are strongly indicative of system-level definitions.

**5. Formulating the Function Summary:**

Based on the above, the core function of the file is to provide Go constants that mirror system-level definitions, primarily from the Darwin (macOS) operating system for the ARM64 architecture. These constants are essential for low-level system calls and network programming within the `syscall` package.

**6. Considering Example Usage (and why it's difficult here):**

While we know *what* the constants are, demonstrating their usage directly in Go code is tricky without more context. These constants are building blocks for lower-level functions within the `syscall` package. A simple "hello world" program wouldn't use `AF_INET` directly. Instead, you'd use higher-level functions like `net.Dial()` which internally utilize these constants.

This leads to the conclusion that a *direct* code example showing these constants in action is less informative than explaining their *purpose* within the broader `syscall` package.

**7. Reasoning About Potential Mistakes:**

Because this is generated code, users aren't expected to *modify* it. The primary risk is misunderstanding *what* these constants represent or using an incorrect constant for a particular system call or operation.

* **Incorrect Value Assumption:**  A developer might assume a constant has a specific value across all platforms, which isn't guaranteed. This file being specific to `darwin_arm64` highlights that system-level constants can vary.
* **Misunderstanding Constant Meaning:**  Using `O_NONBLOCK` when `O_NDELAY` is needed, or vice-versa, due to a misunderstanding of their nuances, is a possible error.

**8. Structuring the Answer:**

Finally, the answer should be structured logically, starting with the core function, explaining the generation process, providing an illustrative (even if not directly runnable) example of how such constants are *used* (within `syscall` functions), and then addressing potential pitfalls. Using clear headings and formatting makes the information easier to digest.

**Self-Correction/Refinement:**

Initially, I might have considered trying to reverse-engineer the C header file based on the Go constants. However, given the `cgo -godefs` information, it's more efficient to focus on the generation process and the role of the output. Also, initially, I might have tried to create a very contrived Go example directly using these constants. However, realizing their role as building blocks for `syscall` functions led to a more accurate and useful explanation.
这是对位于 `go/src/syscall/zerrors_darwin_arm64.go` 的 Go 语言实现部分的功能进行分析。

**功能归纳:**

这个 Go 语言源文件的主要功能是 **定义了一系列常量**。这些常量代表了 Darwin (macOS) 操作系统针对 ARM64 架构定义的各种系统级常量，例如：

* **地址族 (Address Family):**  `AF_INET`, `AF_INET6`, `AF_UNIX` 等，用于指定网络通信的协议族。
* **波特率 (Baud Rate):** `B9600`, `B115200` 等，用于串口通信中指定数据传输速率。
* **BPF (Berkeley Packet Filter) 相关常量:** `BPF_A`, `BPF_JEQ` 等，用于网络数据包过滤。
* **终端控制常量:** `ECHO`, `ICANON`, `IGNCR` 等，用于配置终端的行为。
* **kqueue 事件过滤器常量:** `EVFILT_READ`, `EVFILT_WRITE` 等，用于监控文件描述符上的事件。
* **kqueue 事件标志常量:** `EV_ADD`, `EV_DELETE` 等，用于控制事件的添加和删除。
* **文件控制 (fcntl) 相关常量:** `F_RDLCK`, `F_WRLCK`, `F_GETFL` 等，用于操作文件描述符。
* **网络接口标志常量:** `IFF_UP`, `IFF_BROADCAST` 等，用于描述网络接口的状态。
* **网络接口类型常量:** `IFT_ETHER`, `IFT_LOOP` 等，用于表示网络接口的物理类型。
* **IP 协议常量:** `IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_ICMP` 等，用于指定 IP 数据包的协议类型。
* **IPv6 相关常量:** `IPV6_V6ONLY`, `IPV6_JOIN_GROUP` 等，用于配置 IPv6 网络。
* **IP 套接字选项常量:** `IP_ADD_MEMBERSHIP`, `IP_MULTICAST_TTL` 等，用于设置 IP 套接字的行为。
* **终端输入/输出标志常量:** `IGNBRK`, `OCRNL` 等，用于控制终端输入和输出的处理。
* **文件锁常量:** `LOCK_EX`, `LOCK_SH` 等，用于实现文件互斥访问。
* **内存映射常量:** `MAP_ANON`, `MAP_SHARED` 等，用于控制内存映射的行为。
* **消息标志常量:** `MSG_DONTWAIT`, `MSG_OOB` 等，用于控制 socket 消息的发送和接收。
* **内存同步常量:** `MS_SYNC`, `MS_INVALIDATE` 等，用于控制内存与磁盘的同步。
* **路由表操作常量:** `NET_RT_DUMP`, `NET_RT_FLAGS` 等，用于访问和操作系统的路由表。
* **kqueue 节点通知常量:** `NOTE_WRITE`, `NOTE_DELETE` 等，用于监控文件系统对象的变化。
* **打开文件标志常量:** `O_RDONLY`, `O_CREAT`, `O_NONBLOCK` 等，用于指定打开文件的方式。
* **进程优先级常量:** `PRIO_PROCESS`, `PRIO_USER` 等，用于设置进程的优先级。
* **内存保护常量:** `PROT_READ`, `PROT_WRITE`, `PROT_EXEC` 等，用于设置内存区域的访问权限。
* **ptrace 系统调用常量:** `PT_ATTACH`, `PT_CONTINUE` 等，用于控制进程的执行。

**更深入的理解:**

这个文件是由 `mkerrors.sh` 脚本配合 `cgo` 工具自动生成的。 `cgo` 是 Go 语言提供的一种机制，允许 Go 代码调用 C 代码。在这种情况下，`cgo -godefs` 命令被用来解析 C 头文件 (`_const.go`)，提取其中的宏定义、枚举值等常量，并将它们转换成 Go 语言的常量定义。

因此，这个文件的作用是为 Go 语言的 `syscall` 包提供访问底层操作系统 API 所需的常量。这些常量在进行系统调用时被用作参数，指示操作类型、选项等等。

**Go 代码示例说明:**

虽然这个文件本身只定义了常量，但这些常量在 `syscall` 包的其他函数中被广泛使用。例如，在进行网络编程时，你会使用 `syscall.Socket` 函数创建一个套接字，这时就需要指定地址族和套接字类型：

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	// 创建一个 IPv4 的 TCP 套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("创建套接字失败:", err)
		return
	}
	fmt.Println("成功创建套接字，文件描述符为:", fd)

	// ... 其他网络操作 ...

	syscall.Close(fd)
}
```

**假设的输入与输出:**

由于这个文件是自动生成的，它的“输入”是 `_const.go` 文件（其中包含了 C 语言的常量定义），而“输出”就是这个 Go 语言源文件本身。 无法直接从用户的角度触发其输入输出。

**命令行参数处理:**

这个文件本身不处理命令行参数。 它的生成依赖于 `mkerrors.sh` 脚本和 `cgo` 工具，这些工具可能有自己的命令行参数。例如，`cgo -godefs -- -m64 _const.go` 中的 `-m64` 就是 `cgo` 的参数，指示生成 64 位架构的代码。

**使用者易犯错的点:**

由于这个文件是自动生成的，用户通常不会直接修改它。 但使用者可能会犯以下错误：

* **假设常量值在所有平台上相同:**  不同的操作系统或者不同的架构，相同的常量名称可能对应不同的数值。例如，在 Linux 和 macOS 上，`AF_INET` 的值可能相同，但其他一些特定于操作系统的常量值可能不同。  因此，在编写跨平台代码时，需要注意这些差异。

**总结:**

`go/src/syscall/zerrors_darwin_arm64.go` 的功能是 **为 Go 语言的 `syscall` 包提供 Darwin (macOS) 操作系统针对 ARM64 架构定义的系统级常量**。 这些常量是进行底层系统调用和操作系统交互的基础。这个文件由 `cgo` 工具根据 C 头文件自动生成，方便 Go 语言访问操作系统的功能。

Prompt: 
```
这是路径为go/src/syscall/zerrors_darwin_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// mkerrors.sh -m64
// Code generated by the command above; DO NOT EDIT.

// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -m64 _const.go

package syscall

const (
	AF_APPLETALK                      = 0x10
	AF_CCITT                          = 0xa
	AF_CHAOS                          = 0x5
	AF_CNT                            = 0x15
	AF_COIP                           = 0x14
	AF_DATAKIT                        = 0x9
	AF_DECnet                         = 0xc
	AF_DLI                            = 0xd
	AF_E164                           = 0x1c
	AF_ECMA                           = 0x8
	AF_HYLINK                         = 0xf
	AF_IEEE80211                      = 0x25
	AF_IMPLINK                        = 0x3
	AF_INET                           = 0x2
	AF_INET6                          = 0x1e
	AF_IPX                            = 0x17
	AF_ISDN                           = 0x1c
	AF_ISO                            = 0x7
	AF_LAT                            = 0xe
	AF_LINK                           = 0x12
	AF_LOCAL                          = 0x1
	AF_MAX                            = 0x28
	AF_NATM                           = 0x1f
	AF_NDRV                           = 0x1b
	AF_NETBIOS                        = 0x21
	AF_NS                             = 0x6
	AF_OSI                            = 0x7
	AF_PPP                            = 0x22
	AF_PUP                            = 0x4
	AF_RESERVED_36                    = 0x24
	AF_ROUTE                          = 0x11
	AF_SIP                            = 0x18
	AF_SNA                            = 0xb
	AF_SYSTEM                         = 0x20
	AF_UNIX                           = 0x1
	AF_UNSPEC                         = 0x0
	AF_UTUN                           = 0x26
	B0                                = 0x0
	B110                              = 0x6e
	B115200                           = 0x1c200
	B1200                             = 0x4b0
	B134                              = 0x86
	B14400                            = 0x3840
	B150                              = 0x96
	B1800                             = 0x708
	B19200                            = 0x4b00
	B200                              = 0xc8
	B230400                           = 0x38400
	B2400                             = 0x960
	B28800                            = 0x7080
	B300                              = 0x12c
	B38400                            = 0x9600
	B4800                             = 0x12c0
	B50                               = 0x32
	B57600                            = 0xe100
	B600                              = 0x258
	B7200                             = 0x1c20
	B75                               = 0x4b
	B76800                            = 0x12c00
	B9600                             = 0x2580
	BIOCFLUSH                         = 0x20004268
	BIOCGBLEN                         = 0x40044266
	BIOCGDLT                          = 0x4004426a
	BIOCGDLTLIST                      = 0xc00c4279
	BIOCGETIF                         = 0x4020426b
	BIOCGHDRCMPLT                     = 0x40044274
	BIOCGRSIG                         = 0x40044272
	BIOCGRTIMEOUT                     = 0x4010426e
	BIOCGSEESENT                      = 0x40044276
	BIOCGSTATS                        = 0x4008426f
	BIOCIMMEDIATE                     = 0x80044270
	BIOCPROMISC                       = 0x20004269
	BIOCSBLEN                         = 0xc0044266
	BIOCSDLT                          = 0x80044278
	BIOCSETF                          = 0x80104267
	BIOCSETIF                         = 0x8020426c
	BIOCSHDRCMPLT                     = 0x80044275
	BIOCSRSIG                         = 0x80044273
	BIOCSRTIMEOUT                     = 0x8010426d
	BIOCSSEESENT                      = 0x80044277
	BIOCVERSION                       = 0x40044271
	BPF_A                             = 0x10
	BPF_ABS                           = 0x20
	BPF_ADD                           = 0x0
	BPF_ALIGNMENT                     = 0x4
	BPF_ALU                           = 0x4
	BPF_AND                           = 0x50
	BPF_B                             = 0x10
	BPF_DIV                           = 0x30
	BPF_H                             = 0x8
	BPF_IMM                           = 0x0
	BPF_IND                           = 0x40
	BPF_JA                            = 0x0
	BPF_JEQ                           = 0x10
	BPF_JGE                           = 0x30
	BPF_JGT                           = 0x20
	BPF_JMP                           = 0x5
	BPF_JSET                          = 0x40
	BPF_K                             = 0x0
	BPF_LD                            = 0x0
	BPF_LDX                           = 0x1
	BPF_LEN                           = 0x80
	BPF_LSH                           = 0x60
	BPF_MAJOR_VERSION                 = 0x1
	BPF_MAXBUFSIZE                    = 0x80000
	BPF_MAXINSNS                      = 0x200
	BPF_MEM                           = 0x60
	BPF_MEMWORDS                      = 0x10
	BPF_MINBUFSIZE                    = 0x20
	BPF_MINOR_VERSION                 = 0x1
	BPF_MISC                          = 0x7
	BPF_MSH                           = 0xa0
	BPF_MUL                           = 0x20
	BPF_NEG                           = 0x80
	BPF_OR                            = 0x40
	BPF_RELEASE                       = 0x30bb6
	BPF_RET                           = 0x6
	BPF_RSH                           = 0x70
	BPF_ST                            = 0x2
	BPF_STX                           = 0x3
	BPF_SUB                           = 0x10
	BPF_TAX                           = 0x0
	BPF_TXA                           = 0x80
	BPF_W                             = 0x0
	BPF_X                             = 0x8
	BRKINT                            = 0x2
	CFLUSH                            = 0xf
	CLOCAL                            = 0x8000
	CREAD                             = 0x800
	CS5                               = 0x0
	CS6                               = 0x100
	CS7                               = 0x200
	CS8                               = 0x300
	CSIZE                             = 0x300
	CSTART                            = 0x11
	CSTATUS                           = 0x14
	CSTOP                             = 0x13
	CSTOPB                            = 0x400
	CSUSP                             = 0x1a
	CTL_MAXNAME                       = 0xc
	CTL_NET                           = 0x4
	DLT_APPLE_IP_OVER_IEEE1394        = 0x8a
	DLT_ARCNET                        = 0x7
	DLT_ATM_CLIP                      = 0x13
	DLT_ATM_RFC1483                   = 0xb
	DLT_AX25                          = 0x3
	DLT_CHAOS                         = 0x5
	DLT_CHDLC                         = 0x68
	DLT_C_HDLC                        = 0x68
	DLT_EN10MB                        = 0x1
	DLT_EN3MB                         = 0x2
	DLT_FDDI                          = 0xa
	DLT_IEEE802                       = 0x6
	DLT_IEEE802_11                    = 0x69
	DLT_IEEE802_11_RADIO              = 0x7f
	DLT_IEEE802_11_RADIO_AVS          = 0xa3
	DLT_LINUX_SLL                     = 0x71
	DLT_LOOP                          = 0x6c
	DLT_NULL                          = 0x0
	DLT_PFLOG                         = 0x75
	DLT_PFSYNC                        = 0x12
	DLT_PPP                           = 0x9
	DLT_PPP_BSDOS                     = 0x10
	DLT_PPP_SERIAL                    = 0x32
	DLT_PRONET                        = 0x4
	DLT_RAW                           = 0xc
	DLT_SLIP                          = 0x8
	DLT_SLIP_BSDOS                    = 0xf
	DT_BLK                            = 0x6
	DT_CHR                            = 0x2
	DT_DIR                            = 0x4
	DT_FIFO                           = 0x1
	DT_LNK                            = 0xa
	DT_REG                            = 0x8
	DT_SOCK                           = 0xc
	DT_UNKNOWN                        = 0x0
	DT_WHT                            = 0xe
	ECHO                              = 0x8
	ECHOCTL                           = 0x40
	ECHOE                             = 0x2
	ECHOK                             = 0x4
	ECHOKE                            = 0x1
	ECHONL                            = 0x10
	ECHOPRT                           = 0x20
	EVFILT_AIO                        = -0x3
	EVFILT_FS                         = -0x9
	EVFILT_MACHPORT                   = -0x8
	EVFILT_PROC                       = -0x5
	EVFILT_READ                       = -0x1
	EVFILT_SIGNAL                     = -0x6
	EVFILT_SYSCOUNT                   = 0xe
	EVFILT_THREADMARKER               = 0xe
	EVFILT_TIMER                      = -0x7
	EVFILT_USER                       = -0xa
	EVFILT_VM                         = -0xc
	EVFILT_VNODE                      = -0x4
	EVFILT_WRITE                      = -0x2
	EV_ADD                            = 0x1
	EV_CLEAR                          = 0x20
	EV_DELETE                         = 0x2
	EV_DISABLE                        = 0x8
	EV_DISPATCH                       = 0x80
	EV_ENABLE                         = 0x4
	EV_EOF                            = 0x8000
	EV_ERROR                          = 0x4000
	EV_FLAG0                          = 0x1000
	EV_FLAG1                          = 0x2000
	EV_ONESHOT                        = 0x10
	EV_OOBAND                         = 0x2000
	EV_POLL                           = 0x1000
	EV_RECEIPT                        = 0x40
	EV_SYSFLAGS                       = 0xf000
	EXTA                              = 0x4b00
	EXTB                              = 0x9600
	EXTPROC                           = 0x800
	FD_CLOEXEC                        = 0x1
	FD_SETSIZE                        = 0x400
	FLUSHO                            = 0x800000
	F_ADDFILESIGS                     = 0x3d
	F_ADDSIGS                         = 0x3b
	F_ALLOCATEALL                     = 0x4
	F_ALLOCATECONTIG                  = 0x2
	F_CHKCLEAN                        = 0x29
	F_DUPFD                           = 0x0
	F_DUPFD_CLOEXEC                   = 0x43
	F_FINDSIGS                        = 0x4e
	F_FLUSH_DATA                      = 0x28
	F_FREEZE_FS                       = 0x35
	F_FULLFSYNC                       = 0x33
	F_GETCODEDIR                      = 0x48
	F_GETFD                           = 0x1
	F_GETFL                           = 0x3
	F_GETLK                           = 0x7
	F_GETLKPID                        = 0x42
	F_GETNOSIGPIPE                    = 0x4a
	F_GETOWN                          = 0x5
	F_GETPATH                         = 0x32
	F_GETPATH_MTMINFO                 = 0x47
	F_GETPROTECTIONCLASS              = 0x3f
	F_GETPROTECTIONLEVEL              = 0x4d
	F_GLOBAL_NOCACHE                  = 0x37
	F_LOG2PHYS                        = 0x31
	F_LOG2PHYS_EXT                    = 0x41
	F_NOCACHE                         = 0x30
	F_NODIRECT                        = 0x3e
	F_OK                              = 0x0
	F_PATHPKG_CHECK                   = 0x34
	F_PEOFPOSMODE                     = 0x3
	F_PREALLOCATE                     = 0x2a
	F_RDADVISE                        = 0x2c
	F_RDAHEAD                         = 0x2d
	F_RDLCK                           = 0x1
	F_SETBACKINGSTORE                 = 0x46
	F_SETFD                           = 0x2
	F_SETFL                           = 0x4
	F_SETLK                           = 0x8
	F_SETLKW                          = 0x9
	F_SETLKWTIMEOUT                   = 0xa
	F_SETNOSIGPIPE                    = 0x49
	F_SETOWN                          = 0x6
	F_SETPROTECTIONCLASS              = 0x40
	F_SETSIZE                         = 0x2b
	F_SINGLE_WRITER                   = 0x4c
	F_THAW_FS                         = 0x36
	F_TRANSCODEKEY                    = 0x4b
	F_UNLCK                           = 0x2
	F_VOLPOSMODE                      = 0x4
	F_WRLCK                           = 0x3
	HUPCL                             = 0x4000
	ICANON                            = 0x100
	ICMP6_FILTER                      = 0x12
	ICRNL                             = 0x100
	IEXTEN                            = 0x400
	IFF_ALLMULTI                      = 0x200
	IFF_ALTPHYS                       = 0x4000
	IFF_BROADCAST                     = 0x2
	IFF_DEBUG                         = 0x4
	IFF_LINK0                         = 0x1000
	IFF_LINK1                         = 0x2000
	IFF_LINK2                         = 0x4000
	IFF_LOOPBACK                      = 0x8
	IFF_MULTICAST                     = 0x8000
	IFF_NOARP                         = 0x80
	IFF_NOTRAILERS                    = 0x20
	IFF_OACTIVE                       = 0x400
	IFF_POINTOPOINT                   = 0x10
	IFF_PROMISC                       = 0x100
	IFF_RUNNING                       = 0x40
	IFF_SIMPLEX                       = 0x800
	IFF_UP                            = 0x1
	IFNAMSIZ                          = 0x10
	IFT_1822                          = 0x2
	IFT_AAL5                          = 0x31
	IFT_ARCNET                        = 0x23
	IFT_ARCNETPLUS                    = 0x24
	IFT_ATM                           = 0x25
	IFT_BRIDGE                        = 0xd1
	IFT_CARP                          = 0xf8
	IFT_CELLULAR                      = 0xff
	IFT_CEPT                          = 0x13
	IFT_DS3                           = 0x1e
	IFT_ENC                           = 0xf4
	IFT_EON                           = 0x19
	IFT_ETHER                         = 0x6
	IFT_FAITH                         = 0x38
	IFT_FDDI                          = 0xf
	IFT_FRELAY                        = 0x20
	IFT_FRELAYDCE                     = 0x2c
	IFT_GIF                           = 0x37
	IFT_HDH1822                       = 0x3
	IFT_HIPPI                         = 0x2f
	IFT_HSSI                          = 0x2e
	IFT_HY                            = 0xe
	IFT_IEEE1394                      = 0x90
	IFT_IEEE8023ADLAG                 = 0x88
	IFT_ISDNBASIC                     = 0x14
	IFT_ISDNPRIMARY                   = 0x15
	IFT_ISO88022LLC                   = 0x29
	IFT_ISO88023                      = 0x7
	IFT_ISO88024                      = 0x8
	IFT_ISO88025                      = 0x9
	IFT_ISO88026                      = 0xa
	IFT_L2VLAN                        = 0x87
	IFT_LAPB                          = 0x10
	IFT_LOCALTALK                     = 0x2a
	IFT_LOOP                          = 0x18
	IFT_MIOX25                        = 0x26
	IFT_MODEM                         = 0x30
	IFT_NSIP                          = 0x1b
	IFT_OTHER                         = 0x1
	IFT_P10                           = 0xc
	IFT_P80                           = 0xd
	IFT_PARA                          = 0x22
	IFT_PDP                           = 0xff
	IFT_PFLOG                         = 0xf5
	IFT_PFSYNC                        = 0xf6
	IFT_PPP                           = 0x17
	IFT_PROPMUX                       = 0x36
	IFT_PROPVIRTUAL                   = 0x35
	IFT_PTPSERIAL                     = 0x16
	IFT_RS232                         = 0x21
	IFT_SDLC                          = 0x11
	IFT_SIP                           = 0x1f
	IFT_SLIP                          = 0x1c
	IFT_SMDSDXI                       = 0x2b
	IFT_SMDSICIP                      = 0x34
	IFT_SONET                         = 0x27
	IFT_SONETPATH                     = 0x32
	IFT_SONETVT                       = 0x33
	IFT_STARLAN                       = 0xb
	IFT_STF                           = 0x39
	IFT_T1                            = 0x12
	IFT_ULTRA                         = 0x1d
	IFT_V35                           = 0x2d
	IFT_X25                           = 0x5
	IFT_X25DDN                        = 0x4
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
	IN_LINKLOCALNETNUM                = 0xa9fe0000
	IN_LOOPBACKNET                    = 0x7f
	IPPROTO_3PC                       = 0x22
	IPPROTO_ADFS                      = 0x44
	IPPROTO_AH                        = 0x33
	IPPROTO_AHIP                      = 0x3d
	IPPROTO_APES                      = 0x63
	IPPROTO_ARGUS                     = 0xd
	IPPROTO_AX25                      = 0x5d
	IPPROTO_BHA                       = 0x31
	IPPROTO_BLT                       = 0x1e
	IPPROTO_BRSATMON                  = 0x4c
	IPPROTO_CFTP                      = 0x3e
	IPPROTO_CHAOS                     = 0x10
	IPPROTO_CMTP                      = 0x26
	IPPROTO_CPHB                      = 0x49
	IPPROTO_CPNX                      = 0x48
	IPPROTO_DDP                       = 0x25
	IPPROTO_DGP                       = 0x56
	IPPROTO_DIVERT                    = 0xfe
	IPPROTO_DONE                      = 0x101
	IPPROTO_DSTOPTS                   = 0x3c
	IPPROTO_EGP                       = 0x8
	IPPROTO_EMCON                     = 0xe
	IPPROTO_ENCAP                     = 0x62
	IPPROTO_EON                       = 0x50
	IPPROTO_ESP                       = 0x32
	IPPROTO_ETHERIP                   = 0x61
	IPPROTO_FRAGMENT                  = 0x2c
	IPPROTO_GGP                       = 0x3
	IPPROTO_GMTP                      = 0x64
	IPPROTO_GRE                       = 0x2f
	IPPROTO_HELLO                     = 0x3f
	IPPROTO_HMP                       = 0x14
	IPPROTO_HOPOPTS                   = 0x0
	IPPROTO_ICMP                      = 0x1
	IPPROTO_ICMPV6                    = 0x3a
	IPPROTO_IDP                       = 0x16
	IPPROTO_IDPR                      = 0x23
	IPPROTO_IDRP                      = 0x2d
	IPPROTO_IGMP                      = 0x2
	IPPROTO_IGP                       = 0x55
	IPPROTO_IGRP                      = 0x58
	IPPROTO_IL                        = 0x28
	IPPROTO_INLSP                     = 0x34
	IPPROTO_INP                       = 0x20
	IPPROTO_IP                        = 0x0
	IPPROTO_IPCOMP                    = 0x6c
	IPPROTO_IPCV                      = 0x47
	IPPROTO_IPEIP                     = 0x5e
	IPPROTO_IPIP                      = 0x4
	IPPROTO_IPPC                      = 0x43
	IPPROTO_IPV4                      = 0x4
	IPPROTO_IPV6                      = 0x29
	IPPROTO_IRTP                      = 0x1c
	IPPROTO_KRYPTOLAN                 = 0x41
	IPPROTO_LARP                      = 0x5b
	IPPROTO_LEAF1                     = 0x19
	IPPROTO_LEAF2                     = 0x1a
	IPPROTO_MAX                       = 0x100
	IPPROTO_MAXID                     = 0x34
	IPPROTO_MEAS                      = 0x13
	IPPROTO_MHRP                      = 0x30
	IPPROTO_MICP                      = 0x5f
	IPPROTO_MTP                       = 0x5c
	IPPROTO_MUX                       = 0x12
	IPPROTO_ND                        = 0x4d
	IPPROTO_NHRP                      = 0x36
	IPPROTO_NONE                      = 0x3b
	IPPROTO_NSP                       = 0x1f
	IPPROTO_NVPII                     = 0xb
	IPPROTO_OSPFIGP                   = 0x59
	IPPROTO_PGM                       = 0x71
	IPPROTO_PIGP                      = 0x9
	IPPROTO_PIM                       = 0x67
	IPPROTO_PRM                       = 0x15
	IPPROTO_PUP                       = 0xc
	IPPROTO_PVP                       = 0x4b
	IPPROTO_RAW                       = 0xff
	IPPROTO_RCCMON                    = 0xa
	IPPROTO_RDP                       = 0x1b
	IPPROTO_ROUTING                   = 0x2b
	IPPROTO_RSVP                      = 0x2e
	IPPROTO_RVD                       = 0x42
	IPPROTO_SATEXPAK                  = 0x40
	IPPROTO_SATMON                    = 0x45
	IPPROTO_SCCSP                     = 0x60
	IPPROTO_SCTP                      = 0x84
	IPPROTO_SDRP                      = 0x2a
	IPPROTO_SEP                       = 0x21
	IPPROTO_SRPC                      = 0x5a
	IPPROTO_ST                        = 0x7
	IPPROTO_SVMTP                     = 0x52
	IPPROTO_SWIPE                     = 0x35
	IPPROTO_TCF                       = 0x57
	IPPROTO_TCP                       = 0x6
	IPPROTO_TP                        = 0x1d
	IPPROTO_TPXX                      = 0x27
	IPPROTO_TRUNK1                    = 0x17
	IPPROTO_TRUNK2                    = 0x18
	IPPROTO_TTP                       = 0x54
	IPPROTO_UDP                       = 0x11
	IPPROTO_VINES                     = 0x53
	IPPROTO_VISA                      = 0x46
	IPPROTO_VMTP                      = 0x51
	IPPROTO_WBEXPAK                   = 0x4f
	IPPROTO_WBMON                     = 0x4e
	IPPROTO_WSN                       = 0x4a
	IPPROTO_XNET                      = 0xf
	IPPROTO_XTP                       = 0x24
	IPV6_2292DSTOPTS                  = 0x17
	IPV6_2292HOPLIMIT                 = 0x14
	IPV6_2292HOPOPTS                  = 0x16
	IPV6_2292NEXTHOP                  = 0x15
	IPV6_2292PKTINFO                  = 0x13
	IPV6_2292PKTOPTIONS               = 0x19
	IPV6_2292RTHDR                    = 0x18
	IPV6_BINDV6ONLY                   = 0x1b
	IPV6_BOUND_IF                     = 0x7d
	IPV6_CHECKSUM                     = 0x1a
	IPV6_DEFAULT_MULTICAST_HOPS       = 0x1
	IPV6_DEFAULT_MULTICAST_LOOP       = 0x1
	IPV6_DEFHLIM                      = 0x40
	IPV6_FAITH                        = 0x1d
	IPV6_FLOWINFO_MASK                = 0xffffff0f
	IPV6_FLOWLABEL_MASK               = 0xffff0f00
	IPV6_FRAGTTL                      = 0x78
	IPV6_FW_ADD                       = 0x1e
	IPV6_FW_DEL                       = 0x1f
	IPV6_FW_FLUSH                     = 0x20
	IPV6_FW_GET                       = 0x22
	IPV6_FW_ZERO                      = 0x21
	IPV6_HLIMDEC                      = 0x1
	IPV6_IPSEC_POLICY                 = 0x1c
	IPV6_JOIN_GROUP                   = 0xc
	IPV6_LEAVE_GROUP                  = 0xd
	IPV6_MAXHLIM                      = 0xff
	IPV6_MAXOPTHDR                    = 0x800
	IPV6_MAXPACKET                    = 0xffff
	IPV6_MAX_GROUP_SRC_FILTER         = 0x200
	IPV6_MAX_MEMBERSHIPS              = 0xfff
	IPV6_MAX_SOCK_SRC_FILTER          = 0x80
	IPV6_MIN_MEMBERSHIPS              = 0x1f
	IPV6_MMTU                         = 0x500
	IPV6_MULTICAST_HOPS               = 0xa
	IPV6_MULTICAST_IF                 = 0x9
	IPV6_MULTICAST_LOOP               = 0xb
	IPV6_PORTRANGE                    = 0xe
	IPV6_PORTRANGE_DEFAULT            = 0x0
	IPV6_PORTRANGE_HIGH               = 0x1
	IPV6_PORTRANGE_LOW                = 0x2
	IPV6_RECVTCLASS                   = 0x23
	IPV6_RTHDR_LOOSE                  = 0x0
	IPV6_RTHDR_STRICT                 = 0x1
	IPV6_RTHDR_TYPE_0                 = 0x0
	IPV6_SOCKOPT_RESERVED1            = 0x3
	IPV6_TCLASS                       = 0x24
	IPV6_UNICAST_HOPS                 = 0x4
	IPV6_V6ONLY                       = 0x1b
	IPV6_VERSION                      = 0x60
	IPV6_VERSION_MASK                 = 0xf0
	IP_ADD_MEMBERSHIP                 = 0xc
	IP_ADD_SOURCE_MEMBERSHIP          = 0x46
	IP_BLOCK_SOURCE                   = 0x48
	IP_BOUND_IF                       = 0x19
	IP_DEFAULT_MULTICAST_LOOP         = 0x1
	IP_DEFAULT_MULTICAST_TTL          = 0x1
	IP_DF                             = 0x4000
	IP_DROP_MEMBERSHIP                = 0xd
	IP_DROP_SOURCE_MEMBERSHIP         = 0x47
	IP_DUMMYNET_CONFIGURE             = 0x3c
	IP_DUMMYNET_DEL                   = 0x3d
	IP_DUMMYNET_FLUSH                 = 0x3e
	IP_DUMMYNET_GET                   = 0x40
	IP_FAITH                          = 0x16
	IP_FW_ADD                         = 0x28
	IP_FW_DEL                         = 0x29
	IP_FW_FLUSH                       = 0x2a
	IP_FW_GET                         = 0x2c
	IP_FW_RESETLOG                    = 0x2d
	IP_FW_ZERO                        = 0x2b
	IP_HDRINCL                        = 0x2
	IP_IPSEC_POLICY                   = 0x15
	IP_MAXPACKET                      = 0xffff
	IP_MAX_GROUP_SRC_FILTER           = 0x200
	IP_MAX_MEMBERSHIPS                = 0xfff
	IP_MAX_SOCK_MUTE_FILTER           = 0x80
	IP_MAX_SOCK_SRC_FILTER            = 0x80
	IP_MF                             = 0x2000
	IP_MIN_MEMBERSHIPS                = 0x1f
	IP_MSFILTER                       = 0x4a
	IP_MSS                            = 0x240
	IP_MULTICAST_IF                   = 0x9
	IP_MULTICAST_IFINDEX              = 0x42
	IP_MULTICAST_LOOP                 = 0xb
	IP_MULTICAST_TTL                  = 0xa
	IP_MULTICAST_VIF                  = 0xe
	IP_NAT__XXX                       = 0x37
	IP_OFFMASK                        = 0x1fff
	IP_OLD_FW_ADD                     = 0x32
	IP_OLD_FW_DEL                     = 0x33
	IP_OLD_FW_FLUSH                   = 0x34
	IP_OLD_FW_GET                     = 0x36
	IP_OLD_FW_RESETLOG                = 0x38
	IP_OLD_FW_ZERO                    = 0x35
	IP_OPTIONS                        = 0x1
	IP_PKTINFO                        = 0x1a
	IP_PORTRANGE                      = 0x13
	IP_PORTRANGE_DEFAULT              = 0x0
	IP_PORTRANGE_HIGH                 = 0x1
	IP_PORTRANGE_LOW                  = 0x2
	IP_RECVDSTADDR                    = 0x7
	IP_RECVIF                         = 0x14
	IP_RECVOPTS                       = 0x5
	IP_RECVPKTINFO                    = 0x1a
	IP_RECVRETOPTS                    = 0x6
	IP_RECVTTL                        = 0x18
	IP_RETOPTS                        = 0x8
	IP_RF                             = 0x8000
	IP_RSVP_OFF                       = 0x10
	IP_RSVP_ON                        = 0xf
	IP_RSVP_VIF_OFF                   = 0x12
	IP_RSVP_VIF_ON                    = 0x11
	IP_STRIPHDR                       = 0x17
	IP_TOS                            = 0x3
	IP_TRAFFIC_MGT_BACKGROUND         = 0x41
	IP_TTL                            = 0x4
	IP_UNBLOCK_SOURCE                 = 0x49
	ISIG                              = 0x80
	ISTRIP                            = 0x20
	IUTF8                             = 0x4000
	IXANY                             = 0x800
	IXOFF                             = 0x400
	IXON                              = 0x200
	LOCK_EX                           = 0x2
	LOCK_NB                           = 0x4
	LOCK_SH                           = 0x1
	LOCK_UN                           = 0x8
	MADV_CAN_REUSE                    = 0x9
	MADV_DONTNEED                     = 0x4
	MADV_FREE                         = 0x5
	MADV_FREE_REUSABLE                = 0x7
	MADV_FREE_REUSE                   = 0x8
	MADV_NORMAL                       = 0x0
	MADV_RANDOM                       = 0x1
	MADV_SEQUENTIAL                   = 0x2
	MADV_WILLNEED                     = 0x3
	MADV_ZERO_WIRED_PAGES             = 0x6
	MAP_ANON                          = 0x1000
	MAP_COPY                          = 0x2
	MAP_FILE                          = 0x0
	MAP_FIXED                         = 0x10
	MAP_HASSEMAPHORE                  = 0x200
	MAP_JIT                           = 0x800
	MAP_NOCACHE                       = 0x400
	MAP_NOEXTEND                      = 0x100
	MAP_NORESERVE                     = 0x40
	MAP_PRIVATE                       = 0x2
	MAP_RENAME                        = 0x20
	MAP_RESERVED0080                  = 0x80
	MAP_SHARED                        = 0x1
	MCL_CURRENT                       = 0x1
	MCL_FUTURE                        = 0x2
	MSG_CTRUNC                        = 0x20
	MSG_DONTROUTE                     = 0x4
	MSG_DONTWAIT                      = 0x80
	MSG_EOF                           = 0x100
	MSG_EOR                           = 0x8
	MSG_FLUSH                         = 0x400
	MSG_HAVEMORE                      = 0x2000
	MSG_HOLD                          = 0x800
	MSG_NEEDSA                        = 0x10000
	MSG_OOB                           = 0x1
	MSG_PEEK                          = 0x2
	MSG_RCVMORE                       = 0x4000
	MSG_SEND                          = 0x1000
	MSG_TRUNC                         = 0x10
	MSG_WAITALL                       = 0x40
	MSG_WAITSTREAM                    = 0x200
	MS_ASYNC                          = 0x1
	MS_DEACTIVATE                     = 0x8
	MS_INVALIDATE                     = 0x2
	MS_KILLPAGES                      = 0x4
	MS_SYNC                           = 0x10
	NAME_MAX                          = 0xff
	NET_RT_DUMP                       = 0x1
	NET_RT_DUMP2                      = 0x7
	NET_RT_FLAGS                      = 0x2
	NET_RT_IFLIST                     = 0x3
	NET_RT_IFLIST2                    = 0x6
	NET_RT_MAXID                      = 0xa
	NET_RT_STAT                       = 0x4
	NET_RT_TRASH                      = 0x5
	NOFLSH                            = 0x80000000
	NOTE_ABSOLUTE                     = 0x8
	NOTE_ATTRIB                       = 0x8
	NOTE_BACKGROUND                   = 0x40
	NOTE_CHILD                        = 0x4
	NOTE_CRITICAL                     = 0x20
	NOTE_DELETE                       = 0x1
	NOTE_EXEC                         = 0x20000000
	NOTE_EXIT                         = 0x80000000
	NOTE_EXITSTATUS                   = 0x4000000
	NOTE_EXIT_CSERROR                 = 0x40000
	NOTE_EXIT_DECRYPTFAIL             = 0x10000
	NOTE_EXIT_DETAIL                  = 0x2000000
	NOTE_EXIT_DETAIL_MASK             = 0x70000
	NOTE_EXIT_MEMORY                  = 0x20000
	NOTE_EXIT_REPARENTED              = 0x80000
	NOTE_EXTEND                       = 0x4
	NOTE_FFAND                        = 0x40000000
	NOTE_FFCOPY                       = 0xc0000000
	NOTE_FFCTRLMASK                   = 0xc0000000
	NOTE_FFLAGSMASK                   = 0xffffff
	NOTE_FFNOP                        = 0x0
	NOTE_FFOR                         = 0x80000000
	NOTE_FORK                         = 0x40000000
	NOTE_LEEWAY                       = 0x10
	NOTE_LINK                         = 0x10
	NOTE_LOWAT                        = 0x1
	NOTE_NONE                         = 0x80
	NOTE_NSECONDS                     = 0x4
	NOTE_PCTRLMASK                    = -0x100000
	NOTE_PDATAMASK                    = 0xfffff
	NOTE_REAP                         = 0x10000000
	NOTE_RENAME                       = 0x20
	NOTE_REVOKE                       = 0x40
	NOTE_SECONDS                      = 0x1
	NOTE_SIGNAL                       = 0x8000000
	NOTE_TRACK                        = 0x1
	NOTE_TRACKERR                     = 0x2
	NOTE_TRIGGER                      = 0x1000000
	NOTE_USECONDS                     = 0x2
	NOTE_VM_ERROR                     = 0x10000000
	NOTE_VM_PRESSURE                  = 0x80000000
	NOTE_VM_PRESSURE_SUDDEN_TERMINATE = 0x20000000
	NOTE_VM_PRESSURE_TERMINATE        = 0x40000000
	NOTE_WRITE                        = 0x2
	OCRNL                             = 0x10
	OFDEL                             = 0x20000
	OFILL                             = 0x80
	ONLCR                             = 0x2
	ONLRET                            = 0x40
	ONOCR                             = 0x20
	ONOEOT                            = 0x8
	OPOST                             = 0x1
	O_ACCMODE                         = 0x3
	O_ALERT                           = 0x20000000
	O_APPEND                          = 0x8
	O_ASYNC                           = 0x40
	O_CLOEXEC                         = 0x1000000
	O_CREAT                           = 0x200
	O_DIRECTORY                       = 0x100000
	O_DP_GETRAWENCRYPTED              = 0x1
	O_DSYNC                           = 0x400000
	O_EVTONLY                         = 0x8000
	O_EXCL                            = 0x800
	O_EXLOCK                          = 0x20
	O_FSYNC                           = 0x80
	O_NDELAY                          = 0x4
	O_NOCTTY                          = 0x20000
	O_NOFOLLOW                        = 0x100
	O_NONBLOCK                        = 0x4
	O_POPUP                           = 0x80000000
	O_RDONLY                          = 0x0
	O_RDWR                            = 0x2
	O_SHLOCK                          = 0x10
	O_SYMLINK                         = 0x200000
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
	PROT_EXEC                         = 0x4
	PROT_NONE                         = 0x0
	PROT_READ                         = 0x1
	PROT_WRITE                        = 0x2
	PT_ATTACH                         = 0xa
	PT_ATTACHEXC                      = 0xe
	PT_CONTINUE                       = 0x7
	PT_DENY_ATTACH                    = 0x1f
	PT_DETACH                         = 0xb
	PT_FIRSTMACH                      = 0x20
	PT_FORCEQUOTA                     = 0x1e
	PT_KILL                           = 0x8
	PT_READ_D                         = 0x2
	PT_READ_I                         = 0x
"""




```