Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Observation and Context:** The first thing I notice is the file path: `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_netbsd_amd64.go`. The `vendor` directory strongly suggests this is part of vendored dependencies. The `golang.org/x/sys/unix` path indicates it's related to system calls and Unix-like operating systems. The `zerrors_netbsd_amd64.go` filename is a big clue: "zerrors" likely means generated error constants, "netbsd" specifies the operating system, and "amd64" the architecture. The `// mkerrors.sh -m64` comment at the top confirms it's generated.

2. **Code Structure:** I scan the code's structure. It starts with build constraints (`//go:build amd64 && netbsd`), indicating this file is only compiled for the specified platform. It imports the `syscall` package. Then there are two `const` blocks.

3. **First `const` Block Analysis:** The first `const` block contains a large number of uppercase identifiers assigned integer values. Many of these identifiers start with prefixes like `AF_`, `ARPHRD_`, `B`, `BIOC`, `BPF_`, `CLONE_`, `CP_`, `CREAD`, `CRTSCTS`, etc. These prefixes suggest different categories of constants. Specifically:
    * `AF_`: Address Family (networking)
    * `ARPHRD_`: ARP Hardware Type
    * `B`: Baud rates (serial communication)
    * `BIOC`: Berkeley Internet Options Control (packet filtering)
    * `BPF_`: Berkeley Packet Filter
    * `CLONE_`: Flags for the `clone` system call
    * `CP_`: CPU states
    * `CREAD`, `CRTSCTS`: Terminal control flags

    As I continue reading, I see more patterns: `DLT_` (Data Link Type), `DT_` (Directory Entry Type), `ETHERTYPE_` (Ethernet Type), `EVFILT_`, `EV_` (kqueue event filters and flags), `F_` (fcntl flags), `IFT_` (Interface Type), `IPPROTO_` (IP Protocol), `IPV6_`, `IP_` (IPv6 and IPv4 options), `KERN_` (Kernel sysctl names), `LOCK_` (File locking constants), `MADV_` (Memory advice constants), `MAP_` (Memory mapping flags), `MCL_` (Memory locking constants), `MNT_` (Mount flags), `MSG_` (Socket message flags), `MS_` (msync flags), `NET_RT_` (Networking routing constants), `NOTE_` (kqueue notification flags), `O_` (Open flags), `PRIO_` (Priority levels), `PROT_` (Memory protection flags), `RLIMIT_` (Resource limits), `RTAX_`, `RTA_`, `RTF_`, `RTM_`, `RTV_` (Routing table related constants), `RUSAGE_` (Resource usage), `SCM_` (Socket control message types), `SHUT_` (Socket shutdown flags), `SIOC` (Socket I/O Control requests), `SOCK_` (Socket types and flags), `SOL_` (Socket options levels), `SOMAXCONN` (Maximum socket listen backlog), `SO_` (Socket options), `SYSCTL_` (Sysctl names), `S_` (File mode bits), `TCIFLUSH`, `TCIOFLUSH`, `TCOFLUSH`, `TCP_` (TCP options), `TCSAFLUSH`, `TIOC` (Terminal I/O Control requests), `TOSTOP`, `V` (Terminal special characters), `WALL`, `WCLONE`, `WCOREFLAG`, `WNOHANG`, `WNOWAIT`, `WNOZOMBIE`, `WOPTSCHECKED`, `WSTOPPED`, `WUNTRACED` (Wait options).

    This detailed listing allows me to infer the broad functionality: **It defines constants used for interacting with the NetBSD operating system's kernel, specifically related to networking, file systems, process management, and terminal control.**

4. **Second `const` Block Analysis:** The second `const` block is much smaller and contains identifiers starting with `E`. These are followed by common error names like `EACCES`, `EADDRINUSE`, `ENOENT`, etc. The values are assigned using `syscall.Errno(0x...)`. This confirms that **this block defines error constants that map to specific error numbers returned by system calls on NetBSD.**

5. **Inferring Go Functionality:**  Given the types of constants defined, I can infer the Go language features this file supports:
    * **Networking:** The `AF_`, `IPPROTO_`, `SOCK_`, `SO_`, and `SIOC` constants strongly indicate support for socket programming.
    * **File I/O:** `O_`, `F_`, `S_`, and `DT_` constants suggest support for file operations like opening, closing, reading, writing, and getting file information.
    * **Process Management:** `CLONE_`, `PRIO_`, `RLIMIT_`, and wait-related constants indicate support for process creation, priority management, and resource limits.
    * **Terminal I/O:** The `B`, `TIOC`, and `V` constants clearly point to terminal control functionalities.
    * **Memory Management:** `MAP_`, `MADV_`, and `MCL_` constants relate to memory mapping and locking.
    * **System Information:** `KERN_` constants suggest access to kernel-level information via `sysctl`.
    * **Error Handling:** The `E` constants are crucial for interpreting errors returned by system calls.
    * **Packet Filtering:** `BIOC` and `BPF_` constants suggest support for raw socket access and packet filtering using Berkeley Packet Filter.
    * **Routing:** `NET_RT_`, `RTAX_`, `RTA_`, `RTF_`, `RTM_`, and `RTV_` constants indicate support for interacting with the routing table.

6. **Go Code Examples (with Assumptions):** Based on the inferred functionality, I can construct example Go code snippets. Since the prompt asks for assumptions, I'll make reasonable assumptions about what a user might want to do.

7. **Command-Line Arguments:** I review the constants for anything that seems related to command-line tools. The presence of `SIOC` constants suggests that tools like `ifconfig` or `route` might internally use these constants when interacting with the kernel. However, this file itself doesn't directly *process* command-line arguments. It only *defines the constants* that such tools might use.

8. **Common Mistakes:** I think about common pitfalls when working with low-level system calls: incorrect usage of flags, misunderstanding the meaning of specific constants, and not properly handling errors. I try to connect these potential errors to the specific constants defined in the file.

9. **Functionality Summary:** Finally, I synthesize all the observations and inferences into a concise summary of the file's purpose. The key is to emphasize that this file defines constants for system-level interactions on NetBSD.

**Self-Correction/Refinement during Thought Process:**

* **Initial thought:** "This just defines a bunch of numbers."  **Correction:**  Realized the prefixes are key to understanding the *meaning* of these numbers and their relation to different system functionalities.
* **Overgeneralization:** "This is for all system calls." **Correction:**  The filename and specific constant prefixes point to *networking*, *file I/O*, *terminal control*, etc., not *every* possible system call.
* **Focusing too much on specific constants:**  Initially, I might have gotten bogged down trying to understand the exact meaning of *every* constant. **Correction:** Shifted focus to the *categories* of constants and the broader functionalities they represent.
* **Assuming direct usage in applications:** While these constants *can* be used directly, they are more likely used by lower-level libraries like the `net` package or by system utilities. **Correction:**  Emphasized the role of this file as providing the foundation for higher-level abstractions.

By following this iterative process of observation, pattern recognition, inference, and refinement, I can arrive at a comprehensive understanding of the Go code snippet's purpose and its role in the Go ecosystem.
`go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_netbsd_amd64.go` 是 Go 语言标准库 `syscall` 包在 NetBSD amd64 架构下的一个组成部分，其主要功能是 **定义了大量的操作系统级别的常量和错误码**。 这些常量和错误码用于 Go 程序与 NetBSD 操作系统进行底层交互，例如进行系统调用、网络编程、文件操作等。

以下是它的具体功能归纳：

1. **定义系统调用相关的常量:**  文件中定义了大量的以 `AF_`, `SOCK_`, `IPPROTO_`, `IFF_`, `SIOC` 等前缀开头的常量。这些常量分别代表了：
    * `AF_`: 地址族 (Address Family)，用于指定网络通信的协议族，如 `AF_INET` (IPv4), `AF_INET6` (IPv6), `AF_UNIX` (Unix 域套接字) 等。
    * `SOCK_`: 套接字类型，用于指定套接字的通信方式，如 `SOCK_STREAM` (TCP), `SOCK_DGRAM` (UDP), `SOCK_RAW` (原始套接字) 等。
    * `IPPROTO_`: IP 协议类型，用于指定 IP 层使用的协议，如 `IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_ICMP` 等。
    * `IFF_`: 网络接口标志 (Interface Flags)，用于表示网络接口的属性，如 `IFF_UP` (接口已启动), `IFF_BROADCAST` (支持广播) 等。
    * `SIOC`: 套接字 I/O 控制命令 (Socket I/O Control)，用于执行各种网络相关的操作，如获取/设置接口地址、路由信息等。

2. **定义文件操作相关的常量:** 文件中也定义了一些以 `O_`, `S_`, `DT_` 等前缀开头的常量，用于文件操作：
    * `O_`: `open()` 系统调用的标志，用于指定文件打开模式，如 `O_RDONLY` (只读), `O_WRONLY` (只写), `O_CREAT` (创建文件) 等。
    * `S_`: 文件状态标志，用于表示文件类型和权限，如 `S_IFREG` (普通文件), `S_IFDIR` (目录), `S_IRUSR` (用户可读权限) 等。
    * `DT_`: 目录项类型 (Directory Entry Type)，用于表示目录中条目的类型，如 `DT_REG` (普通文件), `DT_DIR` (目录) 等。

3. **定义终端控制相关的常量:** 文件中包含以 `B`, `TIOC`, `V` 等前缀开头的常量，用于终端 I/O 控制：
    * `B`: 波特率 (Baud Rate)，用于设置串口通信的速率，如 `B9600`, `B115200` 等。
    * `TIOC`: 终端 I/O 控制命令 (Terminal I/O Control)，用于执行各种终端相关的操作，如获取/设置终端属性、发送控制信号等。
    * `V`: 特殊控制字符 (Special Characters)，用于终端的特殊功能，如 `VINTR` (中断字符), `VQUIT` (退出字符) 等。

4. **定义进程控制相关的常量:** 文件中还定义了一些以 `CLONE_`, `PRIO_`, `RLIMIT_` 等前缀开头的常量，用于进程控制：
    * `CLONE_`: `clone()` 系统调用的标志，用于控制新进程共享的资源，如 `CLONE_VM` (共享内存), `CLONE_FILES` (共享文件描述符) 等。
    * `PRIO_`: 进程优先级相关的常量，如 `PRIO_PROCESS`, `PRIO_USER` 等。
    * `RLIMIT_`: 资源限制 (Resource Limit)，用于限制进程可以使用的系统资源，如 `RLIMIT_CPU` (CPU 时间限制), `RLIMIT_NOFILE` (打开文件数限制) 等。

5. **定义错误码:**  文件末尾的 `const` 代码块定义了以 `E` 开头的常量，这些常量对应着 NetBSD 系统调用可能返回的各种错误码，例如 `EACCES` (权限不足), `ENOENT` (文件不存在), `ECONNREFUSED` (连接被拒绝) 等。

**可以推理出这是 Go 语言 `syscall` 包为了能够在 NetBSD amd64 架构下进行系统调用而做的准备工作。** Go 的 `syscall` 包提供了一种与操作系统底层进行交互的方式。为了屏蔽不同操作系统之间的差异，`syscall` 包在不同的操作系统和架构下会有不同的实现文件，`zerrors_netbsd_amd64.go` 就是其中之一。

**Go 代码示例:**

假设我们要创建一个 TCP socket 并监听一个端口：

```go
package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	// 创建一个 TCP socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// 监听地址和端口
	addr := &syscall.SockaddrInet4{
		Port: 8080,
		Addr: [4]byte{0, 0, 0, 0}, // 监听所有地址
	}
	err = syscall.Bind(fd, addr)
	if err != nil {
		fmt.Println("Error binding socket:", err)
		return
	}

	// 开始监听
	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		fmt.Println("Error listening on socket:", err)
		return
	}

	fmt.Println("Listening on port 8080...")

	// (后续处理连接的代码...)
}
```

**假设的输入与输出:**

在这个例子中，没有直接的 "输入"。代码执行后，如果成功，会在控制台输出 "Listening on port 8080..."。如果创建、绑定或监听套接字失败，则会输出相应的错误信息。例如，如果端口 8080 已经被占用，`syscall.Bind` 会返回 `syscall.EADDRINUSE` 错误。

**代码推理:**

在这个例子中，`syscall.Socket` 函数使用了 `syscall.AF_INET` 和 `syscall.SOCK_STREAM` 这两个常量，它们在 `zerrors_netbsd_amd64.go` 中被定义为 `AF_INET = 0x2` 和 `SOCK_STREAM = 0x1`。  当 Go 代码调用 `syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)` 时，实际上是在 NetBSD 系统上调用了底层的 `socket(AF_INET, SOCK_STREAM, 0)` 系统调用。

同样，`syscall.Bind` 和 `syscall.Listen` 函数也会使用到该文件中定义的其他常量，以便与操作系统进行正确的交互。

**命令行参数的具体处理:**

这个文件本身不涉及命令行参数的处理。它只是定义了常量。命令行参数的处理通常发生在应用程序的主函数中，并可能根据参数的值来选择使用哪些系统调用和相关的常量。

**使用者易犯错的点:**

* **不理解常量的含义:** 使用者可能会错误地使用常量，例如将 `syscall.SOCK_DGRAM` 用于需要可靠连接的场景。
* **操作系统差异:** 直接使用这些常量编写的代码可能不具备跨平台性，因为不同操作系统的常量定义可能不同。Go 语言的 `net` 包等更高级别的抽象通常会处理这些差异。
* **错误码处理不当:**  忽略系统调用返回的错误，或者不正确地判断错误类型，会导致程序出现未预期的行为。 例如，没有检查 `syscall.Bind` 是否返回 `syscall.EADDRINUSE` 就继续执行可能会导致程序崩溃或行为异常。

**总结:**

`go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_netbsd_amd64.go` 的主要功能是 **为 Go 语言在 NetBSD amd64 架构下进行系统级编程提供必要的常量和错误码定义**。它是 Go 语言 `syscall` 包在特定平台上的底层实现基础，使得 Go 程序能够与 NetBSD 内核进行交互，完成诸如网络通信、文件操作、进程控制等任务。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_netbsd_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能

"""
// mkerrors.sh -m64
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build amd64 && netbsd

// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -m64 _const.go

package unix

import "syscall"

const (
	AF_APPLETALK                      = 0x10
	AF_ARP                            = 0x1c
	AF_BLUETOOTH                      = 0x1f
	AF_CCITT                          = 0xa
	AF_CHAOS                          = 0x5
	AF_CNT                            = 0x15
	AF_COIP                           = 0x14
	AF_DATAKIT                        = 0x9
	AF_DECnet                         = 0xc
	AF_DLI                            = 0xd
	AF_E164                           = 0x1a
	AF_ECMA                           = 0x8
	AF_HYLINK                         = 0xf
	AF_IEEE80211                      = 0x20
	AF_IMPLINK                        = 0x3
	AF_INET                           = 0x2
	AF_INET6                          = 0x18
	AF_IPX                            = 0x17
	AF_ISDN                           = 0x1a
	AF_ISO                            = 0x7
	AF_LAT                            = 0xe
	AF_LINK                           = 0x12
	AF_LOCAL                          = 0x1
	AF_MAX                            = 0x23
	AF_MPLS                           = 0x21
	AF_NATM                           = 0x1b
	AF_NS                             = 0x6
	AF_OROUTE                         = 0x11
	AF_OSI                            = 0x7
	AF_PUP                            = 0x4
	AF_ROUTE                          = 0x22
	AF_SNA                            = 0xb
	AF_UNIX                           = 0x1
	AF_UNSPEC                         = 0x0
	ARPHRD_ARCNET                     = 0x7
	ARPHRD_ETHER                      = 0x1
	ARPHRD_FRELAY                     = 0xf
	ARPHRD_IEEE1394                   = 0x18
	ARPHRD_IEEE802                    = 0x6
	ARPHRD_STRIP                      = 0x17
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
	B460800                           = 0x70800
	B4800                             = 0x12c0
	B50                               = 0x32
	B57600                            = 0xe100
	B600                              = 0x258
	B7200                             = 0x1c20
	B75                               = 0x4b
	B76800                            = 0x12c00
	B921600                           = 0xe1000
	B9600                             = 0x2580
	BIOCFEEDBACK                      = 0x8004427d
	BIOCFLUSH                         = 0x20004268
	BIOCGBLEN                         = 0x40044266
	BIOCGDLT                          = 0x4004426a
	BIOCGDLTLIST                      = 0xc0104277
	BIOCGETIF                         = 0x4090426b
	BIOCGFEEDBACK                     = 0x4004427c
	BIOCGHDRCMPLT                     = 0x40044274
	BIOCGRTIMEOUT                     = 0x4010427b
	BIOCGSEESENT                      = 0x40044278
	BIOCGSTATS                        = 0x4080426f
	BIOCGSTATSOLD                     = 0x4008426f
	BIOCIMMEDIATE                     = 0x80044270
	BIOCPROMISC                       = 0x20004269
	BIOCSBLEN                         = 0xc0044266
	BIOCSDLT                          = 0x80044276
	BIOCSETF                          = 0x80104267
	BIOCSETIF                         = 0x8090426c
	BIOCSFEEDBACK                     = 0x8004427d
	BIOCSHDRCMPLT                     = 0x80044275
	BIOCSRTIMEOUT                     = 0x8010427a
	BIOCSSEESENT                      = 0x80044279
	BIOCSTCPF                         = 0x80104272
	BIOCSUDPF                         = 0x80104273
	BIOCVERSION                       = 0x40044271
	BPF_A                             = 0x10
	BPF_ABS                           = 0x20
	BPF_ADD                           = 0x0
	BPF_ALIGNMENT                     = 0x8
	BPF_ALIGNMENT32                   = 0x4
	BPF_ALU                           = 0x4
	BPF_AND                           = 0x50
	BPF_B                             = 0x10
	BPF_DFLTBUFSIZE                   = 0x100000
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
	BPF_MAXBUFSIZE                    = 0x1000000
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
	CLONE_CSIGNAL                     = 0xff
	CLONE_FILES                       = 0x400
	CLONE_FS                          = 0x200
	CLONE_PID                         = 0x1000
	CLONE_PTRACE                      = 0x2000
	CLONE_SIGHAND                     = 0x800
	CLONE_VFORK                       = 0x4000
	CLONE_VM                          = 0x100
	CPUSTATES                         = 0x5
	CP_IDLE                           = 0x4
	CP_INTR                           = 0x3
	CP_NICE                           = 0x1
	CP_SYS                            = 0x2
	CP_USER                           = 0x0
	CREAD                             = 0x800
	CRTSCTS                           = 0x10000
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
	CTL_HW                            = 0x6
	CTL_KERN                          = 0x1
	CTL_MAXNAME                       = 0xc
	CTL_NET                           = 0x4
	CTL_QUERY                         = -0x2
	DIOCBSFLUSH                       = 0x20006478
	DLT_A429                          = 0xb8
	DLT_A653_ICM                      = 0xb9
	DLT_AIRONET_HEADER                = 0x78
	DLT_AOS                           = 0xde
	DLT_APPLE_IP_OVER_IEEE1394        = 0x8a
	DLT_ARCNET                        = 0x7
	DLT_ARCNET_LINUX                  = 0x81
	DLT_ATM_CLIP                      = 0x13
	DLT_ATM_RFC1483                   = 0xb
	DLT_AURORA                        = 0x7e
	DLT_AX25                          = 0x3
	DLT_AX25_KISS                     = 0xca
	DLT_BACNET_MS_TP                  = 0xa5
	DLT_BLUETOOTH_HCI_H4              = 0xbb
	DLT_BLUETOOTH_HCI_H4_WITH_PHDR    = 0xc9
	DLT_CAN20B                        = 0xbe
	DLT_CAN_SOCKETCAN                 = 0xe3
	DLT_CHAOS                         = 0x5
	DLT_CISCO_IOS                     = 0x76
	DLT_C_HDLC                        = 0x68
	DLT_C_HDLC_WITH_DIR               = 0xcd
	DLT_DECT                          = 0xdd
	DLT_DOCSIS                        = 0x8f
	DLT_ECONET                        = 0x73
	DLT_EN10MB                        = 0x1
	DLT_EN3MB                         = 0x2
	DLT_ENC                           = 0x6d
	DLT_ERF                           = 0xc5
	DLT_ERF_ETH                       = 0xaf
	DLT_ERF_POS                       = 0xb0
	DLT_FC_2                          = 0xe0
	DLT_FC_2_WITH_FRAME_DELIMS        = 0xe1
	DLT_FDDI                          = 0xa
	DLT_FLEXRAY                       = 0xd2
	DLT_FRELAY                        = 0x6b
	DLT_FRELAY_WITH_DIR               = 0xce
	DLT_GCOM_SERIAL                   = 0xad
	DLT_GCOM_T1E1                     = 0xac
	DLT_GPF_F                         = 0xab
	DLT_GPF_T                         = 0xaa
	DLT_GPRS_LLC                      = 0xa9
	DLT_GSMTAP_ABIS                   = 0xda
	DLT_GSMTAP_UM                     = 0xd9
	DLT_HDLC                          = 0x10
	DLT_HHDLC                         = 0x79
	DLT_HIPPI                         = 0xf
	DLT_IBM_SN                        = 0x92
	DLT_IBM_SP                        = 0x91
	DLT_IEEE802                       = 0x6
	DLT_IEEE802_11                    = 0x69
	DLT_IEEE802_11_RADIO              = 0x7f
	DLT_IEEE802_11_RADIO_AVS          = 0xa3
	DLT_IEEE802_15_4                  = 0xc3
	DLT_IEEE802_15_4_LINUX            = 0xbf
	DLT_IEEE802_15_4_NONASK_PHY       = 0xd7
	DLT_IEEE802_16_MAC_CPS            = 0xbc
	DLT_IEEE802_16_MAC_CPS_RADIO      = 0xc1
	DLT_IPMB                          = 0xc7
	DLT_IPMB_LINUX                    = 0xd1
	DLT_IPNET                         = 0xe2
	DLT_IPV4                          = 0xe4
	DLT_IPV6                          = 0xe5
	DLT_IP_OVER_FC                    = 0x7a
	DLT_JUNIPER_ATM1                  = 0x89
	DLT_JUNIPER_ATM2                  = 0x87
	DLT_JUNIPER_CHDLC                 = 0xb5
	DLT_JUNIPER_ES                    = 0x84
	DLT_JUNIPER_ETHER                 = 0xb2
	DLT_JUNIPER_FRELAY                = 0xb4
	DLT_JUNIPER_GGSN                  = 0x85
	DLT_JUNIPER_ISM                   = 0xc2
	DLT_JUNIPER_MFR                   = 0x86
	DLT_JUNIPER_MLFR                  = 0x83
	DLT_JUNIPER_MLPPP                 = 0x82
	DLT_JUNIPER_MONITOR               = 0xa4
	DLT_JUNIPER_PIC_PEER              = 0xae
	DLT_JUNIPER_PPP                   = 0xb3
	DLT_JUNIPER_PPPOE                 = 0xa7
	DLT_JUNIPER_PPPOE_ATM             = 0xa8
	DLT_JUNIPER_SERVICES              = 0x88
	DLT_JUNIPER_ST                    = 0xc8
	DLT_JUNIPER_VP                    = 0xb7
	DLT_LAPB_WITH_DIR                 = 0xcf
	DLT_LAPD                          = 0xcb
	DLT_LIN                           = 0xd4
	DLT_LINUX_EVDEV                   = 0xd8
	DLT_LINUX_IRDA                    = 0x90
	DLT_LINUX_LAPD                    = 0xb1
	DLT_LINUX_SLL                     = 0x71
	DLT_LOOP                          = 0x6c
	DLT_LTALK                         = 0x72
	DLT_MFR                           = 0xb6
	DLT_MOST                          = 0xd3
	DLT_MPLS                          = 0xdb
	DLT_MTP2                          = 0x8c
	DLT_MTP2_WITH_PHDR                = 0x8b
	DLT_MTP3                          = 0x8d
	DLT_NULL                          = 0x0
	DLT_PCI_EXP                       = 0x7d
	DLT_PFLOG                         = 0x75
	DLT_PFSYNC                        = 0x12
	DLT_PPI                           = 0xc0
	DLT_PPP                           = 0x9
	DLT_PPP_BSDOS                     = 0xe
	DLT_PPP_ETHER                     = 0x33
	DLT_PPP_PPPD                      = 0xa6
	DLT_PPP_SERIAL                    = 0x32
	DLT_PPP_WITH_DIR                  = 0xcc
	DLT_PRISM_HEADER                  = 0x77
	DLT_PRONET                        = 0x4
	DLT_RAIF1                         = 0xc6
	DLT_RAW                           = 0xc
	DLT_RAWAF_MASK                    = 0x2240000
	DLT_RIO                           = 0x7c
	DLT_SCCP                          = 0x8e
	DLT_SITA                          = 0xc4
	DLT_SLIP                          = 0x8
	DLT_SLIP_BSDOS                    = 0xd
	DLT_SUNATM                        = 0x7b
	DLT_SYMANTEC_FIREWALL             = 0x63
	DLT_TZSP                          = 0x80
	DLT_USB                           = 0xba
	DLT_USB_LINUX                     = 0xbd
	DLT_USB_LINUX_MMAPPED             = 0xdc
	DLT_WIHART                        = 0xdf
	DLT_X2E_SERIAL                    = 0xd5
	DLT_X2E_XORAYA                    = 0xd6
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
	EMUL_LINUX                        = 0x1
	EMUL_LINUX32                      = 0x5
	EMUL_MAXID                        = 0x6
	ETHERCAP_JUMBO_MTU                = 0x4
	ETHERCAP_VLAN_HWTAGGING           = 0x2
	ETHERCAP_VLAN_MTU                 = 0x1
	ETHERMIN                          = 0x2e
	ETHERMTU                          = 0x5dc
	ETHERMTU_JUMBO                    = 0x2328
	ETHERTYPE_8023                    = 0x4
	ETHERTYPE_AARP                    = 0x80f3
	ETHERTYPE_ACCTON                  = 0x8390
	ETHERTYPE_AEONIC                  = 0x8036
	ETHERTYPE_ALPHA                   = 0x814a
	ETHERTYPE_AMBER                   = 0x6008
	ETHERTYPE_AMOEBA                  = 0x8145
	ETHERTYPE_APOLLO                  = 0x80f7
	ETHERTYPE_APOLLODOMAIN            = 0x8019
	ETHERTYPE_APPLETALK               = 0x809b
	ETHERTYPE_APPLITEK                = 0x80c7
	ETHERTYPE_ARGONAUT                = 0x803a
	ETHERTYPE_ARP                     = 0x806
	ETHERTYPE_AT                      = 0x809b
	ETHERTYPE_ATALK                   = 0x809b
	ETHERTYPE_ATOMIC                  = 0x86df
	ETHERTYPE_ATT                     = 0x8069
	ETHERTYPE_ATTSTANFORD             = 0x8008
	ETHERTYPE_AUTOPHON                = 0x806a
	ETHERTYPE_AXIS                    = 0x8856
	ETHERTYPE_BCLOOP                  = 0x9003
	ETHERTYPE_BOFL                    = 0x8102
	ETHERTYPE_CABLETRON               = 0x7034
	ETHERTYPE_CHAOS                   = 0x804
	ETHERTYPE_COMDESIGN               = 0x806c
	ETHERTYPE_COMPUGRAPHIC            = 0x806d
	ETHERTYPE_COUNTERPOINT            = 0x8062
	ETHERTYPE_CRONUS                  = 0x8004
	ETHERTYPE_CRONUSVLN               = 0x8003
	ETHERTYPE_DCA                     = 0x1234
	ETHERTYPE_DDE                     = 0x807b
	ETHERTYPE_DEBNI                   = 0xaaaa
	ETHERTYPE_DECAM                   = 0x8048
	ETHERTYPE_DECCUST                 = 0x6006
	ETHERTYPE_DECDIAG                 = 0x6005
	ETHERTYPE_DECDNS                  = 0x803c
	ETHERTYPE_DECDTS                  = 0x803e
	ETHERTYPE_DECEXPER                = 0x6000
	ETHERTYPE_DECLAST                 = 0x8041
	ETHERTYPE_DECLTM                  = 0x803f
	ETHERTYPE_DECMUMPS                = 0x6009
	ETHERTYPE_DECNETBIOS              = 0x8040
	ETHERTYPE_DELTACON                = 0x86de
	ETHERTYPE_DIDDLE                  = 0x4321
	ETHERTYPE_DLOG1                   = 0x660
	ETHERTYPE_DLOG2                   = 0x661
	ETHERTYPE_DN                      = 0x6003
	ETHERTYPE_DOGFIGHT                = 0x1989
	ETHERTYPE_DSMD                    = 0x8039
	ETHERTYPE_ECMA                    = 0x803
	ETHERTYPE_ENCRYPT                 = 0x803d
	ETHERTYPE_ES                      = 0x805d
	ETHERTYPE_EXCELAN                 = 0x8010
	ETHERTYPE_EXPERDATA               = 0x8049
	ETHERTYPE_FLIP                    = 0x8146
	ETHERTYPE_FLOWCONTROL             = 0x8808
	ETHERTYPE_FRARP                   = 0x808
	ETHERTYPE_GENDYN                  = 0x8068
	ETHERTYPE_HAYES                   = 0x8130
	ETHERTYPE_HIPPI_FP                = 0x8180
	ETHERTYPE_HITACHI                 = 0x8820
	ETHERTYPE_HP                      = 0x8005
	ETHERTYPE_IEEEPUP                 = 0xa00
	ETHERTYPE_IEEEPUPAT               = 0xa01
	ETHERTYPE_IMLBL                   = 0x4c42
	ETHERTYPE_IMLBLDIAG               = 0x424c
	ETHERTYPE_IP                      = 0x800
	ETHERTYPE_IPAS                    = 0x876c
	ETHERTYPE_IPV6                    = 0x86dd
	ETHERTYPE_IPX                     = 0x8137
	ETHERTYPE_IPXNEW                  = 0x8037
	ETHERTYPE_KALPANA                 = 0x8582
	ETHERTYPE_LANBRIDGE               = 0x8038
	ETHERTYPE_LANPROBE                = 0x8888
	ETHERTYPE_LAT                     = 0x6004
	ETHERTYPE_LBACK                   = 0x9000
	ETHERTYPE_LITTLE                  = 0x8060
	ETHERTYPE_LOGICRAFT               = 0x8148
	ETHERTYPE_LOOPBACK                = 0x9000
	ETHERTYPE_MATRA                   = 0x807a
	ETHERTYPE_MAX                     = 0xffff
	ETHERTYPE_MERIT                   = 0x807c
	ETHERTYPE_MICP                    = 0x873a
	ETHERTYPE_MOPDL                   = 0x6001
	ETHERTYPE_MOPRC                   = 0x6002
	ETHERTYPE_MOTOROLA                = 0x818d
	ETHERTYPE_MPLS                    = 0x8847
	ETHERTYPE_MPLS_MCAST              = 0x8848
	ETHERTYPE_MUMPS                   = 0x813f
	ETHERTYPE_NBPCC                   = 0x3c04
	ETHERTYPE_NBPCLAIM                = 0x3c09
	ETHERTYPE_NBPCLREQ                = 0x3c05
	ETHERTYPE_NBPCLRSP                = 0x3c06
	ETHERTYPE_NBPCREQ                 = 0x3c02
	ETHERTYPE_NBPCRSP                 = 0x3c03
	ETHERTYPE_NBPDG                   = 0x3c07
	ETHERTYPE_NBPDGB                  = 0x3c08
	ETHERTYPE_NBPDLTE                 = 0x3c0a
	ETHERTYPE_NBPRAR                  = 0x3c0c
	ETHERTYPE_NBPRAS                  = 0x3c0b
	ETHERTYPE_NBPRST                  = 0x3c0d
	ETHERTYPE_NBPSCD                  = 0x3c01
	ETHERTYPE_NBPVCD                  = 0x3c00
	ETHERTYPE_NBS                     = 0x802
	ETHERTYPE_NCD                     = 0x8149
	ETHERTYPE_NESTAR                  = 0x8006
	ETHERTYPE_NETBEUI                 = 0x8191
	ETHERTYPE_NOVELL                  = 0x8138
	ETHERTYPE_NS                      = 0x600
	ETHERTYPE_NSAT                    = 0x601
	ETHERTYPE_NSCOMPAT                = 0x807
	ETHERTYPE_NTRAILER                = 0x10
	ETHERTYPE_OS9                     = 0x7007
	ETHERTYPE_OS9NET                  = 0x7009
	ETHERTYPE_PACER                   = 0x80c6
	ETHERTYPE_PAE                     = 0x888e
	ETHERTYPE_PCS                     = 0x4242
	ETHERTYPE_PLANNING                = 0x8044
	ETHERTYPE_PPP                     = 0x880b
	ETHERTYPE_PPPOE                   = 0x8864
	ETHERTYPE_PPPOEDISC               = 0x8863
	ETHERTYPE_PRIMENTS                = 0x7031
	ETHERTYPE_PUP                     = 0x200
	ETHERTYPE_PUPAT                   = 0x200
	ETHERTYPE_RACAL                   = 0x7030
	ETHERTYPE_RATIONAL                = 0x8150
	ETHERTYPE_RAWFR                   = 0x6559
	ETHERTYPE_RCL                     = 0x1995
	ETHERTYPE_RDP                     = 0x8739
	ETHERTYPE_RETIX                   = 0x80f2
	ETHERTYPE_REVARP                  = 0x8035
	ETHERTYPE_SCA                     = 0x6007
	ETHERTYPE_SECTRA                  = 0x86db
	ETHERTYPE_SECUREDATA              = 0x876d
	ETHERTYPE_SGITW                   = 0x817e
	ETHERTYPE_SG_BOUNCE               = 0x8016
	ETHERTYPE_SG_DIAG                 = 0x8013
	ETHERTYPE_SG_NETGAMES             = 0x8014
	ETHERTYPE_SG_RESV                 = 0x8015
	ETHERTYPE_SIMNET                  = 0x5208
	ETHERTYPE_SLOWPROTOCOLS           = 0x8809
	ETHERTYPE_SNA                     = 0x80d5
	ETHERTYPE_SNMP                    = 0x814c
	ETHERTYPE_SONIX                   = 0xfaf5
	ETHERTYPE_SPIDER                  = 0x809f
	ETHERTYPE_SPRITE                  = 0x500
	ETHERTYPE_STP                     = 0x8181
	ETHERTYPE_TALARIS                 = 0x812b
	ETHERTYPE_TALARISMC               = 0x852b
	ETHERTYPE_TCPCOMP                 = 0x876b
	ETHERTYPE_TCPSM                   = 0x9002
	ETHERTYPE_TEC                     = 0x814f
	ETHERTYPE_TIGAN                   = 0x802f
	ETHERTYPE_TRAIL                   = 0x1000
	ETHERTYPE_TRANSETHER              = 0x6558
	ETHERTYPE_TYMSHARE                = 0x802e
	ETHERTYPE_UBBST                   = 0x7005
	ETHERTYPE_UBDEBUG                 = 0x900
	ETHERTYPE_UBDIAGLOOP              = 0x7002
	ETHERTYPE_UBDL                    = 0x7000
	ETHERTYPE_UBNIU                   = 0x7001
	ETHERTYPE_UBNMC                   = 0x7003
	ETHERTYPE_VALID                   = 0x1600
	ETHERTYPE_VARIAN                  = 0x80dd
	ETHERTYPE_VAXELN                  = 0x803b
	ETHERTYPE_VEECO                   = 0x8067
	ETHERTYPE_VEXP                    = 0x805b
	ETHERTYPE_VGLAB                   = 0x8131
	ETHERTYPE_VINES                   = 0xbad
	ETHERTYPE_VINESECHO               = 0xbaf
	ETHERTYPE_VINESLOOP               = 0xbae
	ETHERTYPE_VITAL                   = 0xff00
	ETHERTYPE_VLAN                    = 0x8100
	ETHERTYPE_VLTLMAN                 = 0x8080
	ETHERTYPE_VPROD                   = 0x805c
	ETHERTYPE_VURESERVED              = 0x8147
	ETHERTYPE_WATERLOO                = 0x8130
	ETHERTYPE_WELLFLEET               = 0x8103
	ETHERTYPE_X25                     = 0x805
	ETHERTYPE_X75                     = 0x801
	ETHERTYPE_XNSSM                   = 0x9001
	ETHERTYPE_XTP                     = 0x817d
	ETHER_ADDR_LEN                    = 0x6
	ETHER_CRC_LEN                     = 0x4
	ETHER_CRC_POLY_BE                 = 0x4c11db6
	ETHER_CRC_POLY_LE                 = 0xedb88320
	ETHER_HDR_LEN                     = 0xe
	ETHER_MAX_LEN                     = 0x5ee
	ETHER_MAX_LEN_JUMBO               = 0x233a
	ETHER_MIN_LEN                     = 0x40
	ETHER_PPPOE_ENCAP_LEN             = 0x8
	ETHER_TYPE_LEN                    = 0x2
	ETHER_VLAN_ENCAP_LEN              = 0x4
	EVFILT_AIO                        = 0x2
	EVFILT_PROC                       = 0x4
	EVFILT_READ                       = 0x0
	EVFILT_SIGNAL                     = 0x5
	EVFILT_SYSCOUNT                   = 0x7
	EVFILT_TIMER                      = 0x6
	EVFILT_VNODE                      = 0x3
	EVFILT_WRITE                      = 0x1
	EV_ADD                            = 0x1
	EV_CLEAR                          = 0x20
	EV_DELETE                         = 0x2
	EV_DISABLE                        = 0x8
	EV_ENABLE                         = 0x4
	EV_EOF                            = 0x8000
	EV_ERROR                          = 0x4000
	EV_FLAG1                          = 0x2000
	EV_ONESHOT                        = 0x10
	EV_SYSFLAGS                       = 0xf000
	EXTA                              = 0x4b00
	EXTATTR_CMD_START                 = 0x1
	EXTATTR_CMD_STOP                  = 0x2
	EXTATTR_NAMESPACE_SYSTEM          = 0x2
	EXTATTR_NAMESPACE_USER            = 0x1
	EXTB                              = 0x9600
	EXTPROC                           = 0x800
	FD_CLOEXEC                        = 0x1
	FD_SETSIZE                        = 0x100
	FLUSHO                            = 0x800000
	F_CLOSEM                          = 0xa
	F_DUPFD                           = 0x0
	F_DUPFD_CLOEXEC                   = 0xc
	F_FSCTL                           = -0x80000000
	F_FSDIRMASK                       = 0x70000000
	F_FSIN                            = 0x10000000
	F_FSINOUT                         = 0x30000000
	F_FSOUT                           = 0x20000000
	F_FSPRIV                          = 0x8000
	F_FSVOID                          = 0x40000000
	F_GETFD                           = 0x1
	F_GETFL                           = 0x3
	F_GETLK                           = 0x7
	F_GETNOSIGPIPE                    = 0xd
	F_GETOWN                          = 0x5
	F_MAXFD                           = 0xb
	F_OK                              = 0x0
	F_PARAM_MASK                      = 0xfff
	F_PARAM_MAX                       = 0xfff
	F_RDLCK                           = 0x1
	F_SETFD                           = 0x2
	F_SETFL                           = 0x4
	F_SETLK                           = 0x8
	F_SETLKW                          = 0x9
	F_SETNOSIGPIPE                    = 0xe
	F_SETOWN                          = 0x6
	F_UNLCK                           = 0x2
	F_WRLCK                           = 0x3
	HUPCL                             = 0x4000
	HW_MACHINE                        = 0x1
	ICANON                            = 0x100
	ICMP6_FILTER                      = 0x12
	ICRNL                             = 0x100
	IEXTEN                            = 0x400
	IFAN_ARRIVAL                      = 0x0
	IFAN_DEPARTURE                    = 0x1
	IFA_ROUTE                         = 0x1
	IFF_ALLMULTI                      = 0x200
	IFF_BROADCAST                     = 0x2
	IFF_CANTCHANGE                    = 0x8f52
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
	IFT_A12MPPSWITCH                  = 0x82
	IFT_AAL2                          = 0xbb
	IFT_AAL5                          = 0x31
	IFT_ADSL                          = 0x5e
	IFT_AFLANE8023                    = 0x3b
	IFT_AFLANE8025                    = 0x3c
	IFT_ARAP                          = 0x58
	IFT_ARCNET                        = 0x23
	IFT_ARCNETPLUS                    = 0x24
	IFT_ASYNC                         = 0x54
	IFT_ATM                           = 0x25
	IFT_ATMDXI                        = 0x69
	IFT_ATMFUNI                       = 0x6a
	IFT_ATMIMA                        = 0x6b
	IFT_ATMLOGICAL                    = 0x50
	IFT_ATMRADIO                      = 0xbd
	IFT_ATMSUBINTERFACE               = 0x86
	IFT_ATMVCIENDPT                   = 0xc2
	IFT_ATMVIRTUAL                    = 0x95
	IFT_BGPPOLICYACCOUNTING           = 0xa2
	IFT_BRIDGE                        = 0xd1
	IFT_BSC                           = 0x53
	IFT_CARP                          = 0xf8
	IFT_CCTEMUL                       = 0x3d
	IFT_CEPT                          = 0x13
	IFT_CES                           = 0x85
	IFT_CHANNEL                       = 0x46
	IFT_CNR                           = 0x55
	IFT_COFFEE                        = 0x84
	IFT_COMPOSITELINK                 = 0x9b
	IFT_DCN                           = 0x8d
	IFT_DIGITALPOWERLINE              = 0x8a
	IFT_DIGITALWRAPPEROVERHEADCHANNEL = 0xba
	IFT_DLSW                          = 0x4a
	IFT_DOCSCABLEDOWNSTREAM           = 0x80
	IFT_DOCSCABLEMACLAYER             = 0x7f
	IFT_DOCSCABLEUPSTREAM             = 0x81
	IFT_DOCSCABLEUPSTREAMCHANNEL      = 0xcd
	IFT_DS0                           = 0x51
	IFT_DS0BUNDLE                     = 0x52
	IFT_DS1FDL                        = 0xaa
	IFT_DS3                           = 0x1e
	IFT_DTM                           = 0x8c
	IFT_DVBASILN                      = 0xac
	IFT_DVBASIOUT                     = 0xad
	IFT_DVBRCCDOWNSTREAM              = 0x93
	IFT_DVBRCCMACLAYER                = 0x92
	IFT_DVBRCCUPSTREAM                = 0x94
	IFT_ECONET                        = 0xce
	IFT_EON                           = 0x19
	IFT_EPLRS                         = 0x57
	IFT_ESCON                         = 0x49
	IFT_ETHER                         = 0x6
	IFT_FAITH                         = 0xf2
	IFT_FAST                          = 0x7d
	IFT_FASTETHER                     = 0x3e
	IFT_FASTETHERFX                   = 0x45
	IFT_FDDI                          = 0xf
	IFT_FIBRECHANNEL                  = 0x38
	IFT_FRAMERELAYINTERCONNECT        = 0x3a
	IFT_FRAMERELAYMPI                 = 0x5c
	IFT_FRDLCIENDPT                   = 0xc1
	IFT_FRELAY                        = 0x20
	IFT_FRELAYDCE                     = 0x2c
	IFT_FRF16MFRBUNDLE                = 0xa3
	IFT_FRFORWARD                     = 0x9e
	IFT_G703AT2MB                     = 0x43
	IFT_G703AT64K                     = 0x42
	IFT_GIF                           = 0xf0
	IFT_GIGABITETHERNET               = 0x75
	IFT_GR303IDT                      = 0xb2
	IFT_GR303RDT                      = 0xb1
	IFT_H323GATEKEEPER                = 0xa4
	IFT_H323PROXY                     = 0xa5
	IFT_HDH1822                       = 0x3
	IFT_HDLC                          = 0x76
	IFT_HDSL2                         = 0xa8
	IFT_HIPERLAN2                     = 0xb7
	IFT_HIPPI                         = 0x2f
	IFT_HIPPIINTERFACE                = 0x39
	IFT_HOSTPAD                       = 0x5a
	IFT_HSSI                          = 0x2e
	IFT_HY                            = 0xe
	IFT_IBM370PARCHAN                 = 0x48
	IFT_IDSL                          = 0x9a
	IFT_IEEE1394                      = 0x90
	IFT_IEEE80211                     = 0x47
	IFT_IEEE80212                     = 0x37
	IFT_IEEE8023ADLAG                 = 0xa1
	IFT_IFGSN                         = 0x91
	IFT_IMT                           = 0xbe
	IFT_INFINIBAND                    = 0xc7
	IFT_INTERLEAVE                    = 0x7c
	IFT_IP                            = 0x7e
	IFT_IPFORWARD                     = 0x8e
	IFT_IPOVERATM                     = 0x72
	IFT_IPOVERCDLC                    = 0x6d
	IFT_IPOVERCLAW                    = 0x6e
	IFT_IPSWITCH                      = 0x4e
	IFT_ISDN                          = 0x3f
	IFT_ISDNBASIC                     = 0x14
	IFT_ISDNPRIMARY                   = 0x15
	IFT_ISDNS                         = 0x4b
	IFT_ISDNU                         = 0x4c
	IFT_ISO88022LLC                   = 0x29
	IFT_ISO88023                      = 0x7
	IFT_ISO88024                      = 0x8
	IFT_ISO88025                      = 0x9
	IFT_ISO88025CRFPINT               = 0x62
	IFT_ISO88025DTR                   = 0x56
	IFT_ISO88025FIBER                 = 0x73
	IFT_ISO88026                      = 0xa
	IFT_ISUP                          = 0xb3
	IFT_L2VLAN                        = 0x87
	IFT_L3IPVLAN                      = 0x88
	IFT_L3IPXVLAN                     = 0x89
	IFT_LAPB                          = 0x10
	IFT_LAPD                          = 0x4d
	IFT_LAPF                          = 0x77
	IFT_LINEGROUP                     = 0xd2
	IFT_LOCALTALK                     = 0x2a
	IFT_LOOP                          = 0x18
	IFT_MEDIAMAILOVERIP               = 0x8b
	IFT_MFSIGLINK                     = 0xa7
	IFT_MIOX25                        = 0x26
	IFT_MODEM                         = 0x30
	IFT_MPC                           = 0x71
	IFT_MPLS                          = 0xa6
	IFT_MPLSTUNNEL                    = 0x96
	IFT_MSDSL                         = 0x8f
	IFT_MVL                           = 0xbf
	IFT_MYRINET                       = 0x63
	IFT_NFAS                          = 0xaf
	IFT_NSIP                          = 0x1b
	IFT_OPTICALCHANNEL                = 0xc3
	IFT_OPTICALTRANSPORT              = 0xc4
	IFT_OTHER                         = 0x1
	IFT_P10                           = 0xc
	IFT_P80                           = 0xd
	IFT_PARA                          = 0x22
	IFT_PFLOG                         = 0xf5
	IFT_PFSYNC                        = 0xf6
	IFT_PLC                           = 0xae
	IFT_PON155                        = 0xcf
	IFT_PON622                        = 0xd0
	IFT_POS                           = 0xab
	IFT_PPP                           = 0x17
	IFT_PPPMULTILINKBUNDLE            = 0x6c
	IFT_PROPATM                       = 0xc5
	IFT_PROPBWAP2MP                   = 0xb8
	IFT_PROPCNLS                      = 0x59
	IFT_PROPDOCSWIRELESSDOWNSTREAM    = 0xb5
	IFT_PROPDOCSWIRELESSMACLAYER      = 0xb4
	IFT_PROPDOCSWIRELESSUPSTREAM      = 0xb6
	IFT_PROPMUX                       = 0x36
	IFT_PROPVIRTUAL                   = 0x35
	IFT_PROPWIRELESSP2P               = 0x9d
	IFT_PTPSERIAL                     = 0x16
	IFT_PVC                           = 0xf1
	IFT_Q2931                         = 0xc9
	IFT_QLLC                          = 0x44
	IFT_RADIOMAC                      = 0xbc
	IFT_RADSL                         = 0x5f
	IFT_REACHDSL                      = 0xc0
	IFT_RFC1483                       = 0x9f
	IFT_RS232                         = 0x21
	IFT_RSRB                          = 0x4f
	IFT_SDLC                          = 0x11
	IFT_SDSL                          = 0x60
	IFT_SHDSL                         = 0xa9
	IFT_SIP                           = 0x1f
	IFT_SIPSIG                        = 0xcc
	IFT_SIPTG                         = 0xcb
	IFT_SLIP                          = 0x1c
	IFT_SMDSDXI                       = 0x2b
	IFT_SMDSICIP                      = 0x34
	IFT_SONET                         = 0x27
	IFT_SONETOVERHEADCHANNEL          = 0xb9
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
	KERN_HOSTNAME                     = 0xa
	KERN_OSRELEASE                    = 0x2
	KERN_OSTYPE                       = 0x1
	KERN_VERSION                      = 0x4
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
	MNT_ASYNC                         = 0x40
	MNT_BASIC_FLAGS                   = 0xe782807f
	MNT_DEFEXPORTED                   = 0x200
	MNT_DISCARD                       = 0x800000
	MNT_EXKERB                        = 0x800
	MNT_EXNORESPORT                   = 0x8000000
	MNT_EXPORTANON                    = 0x400
	MNT_EXPORTED                      = 0x100
	MNT_EXPUBLIC                      = 0x10000000
	MNT_EXRDONLY                      = 0x80
	MNT_EXTATTR                       = 0x1000000
	MNT_FORCE                         = 0x80000
	MNT_GETARGS                       = 0x400000
	MNT_IGNORE                        = 0x100000
	MNT_LAZY                          = 0x3
	MNT_LOCAL                         = 0x1000
	MNT_LOG                           = 0x2000000
	MNT_NOATIME                       = 0x4000000
	MNT_NOCOREDUMP                    = 0x8000
	MNT_NODEV                         = 0x10
	MNT_NODEVMTIME                    = 0x40000000
	MNT_NOEXEC                        = 0x4
	MNT_NOSUID                        = 0x8
	MNT_NOWAIT                        = 0x2
	MNT_OP_FLAGS                      = 0x4d0000
	MNT_QUOTA                         = 0x2000
	MNT_RDONLY                        = 0x1
	MNT_RELATIME                      = 0x20000
	MNT_RELOAD                        = 0x40000
	MNT_ROOTFS                        = 0x4000
	MNT_SOFTDEP                       = 0x80000000
	MNT_SYMPERM                       = 0x20000000
	MNT_SYNCHRONOUS                   = 0x2
	MNT_UNION                         = 0x20
	MNT_UPDATE                        = 0x10000
	MNT_VISFLAGMASK                   = 0xff90ffff
	MNT_WAIT                          = 0x1
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
	NFDBITS                           = 0x20
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
	RLIMIT_MEMLOCK                    = 0x6
	RLIMIT_NOFILE                     = 0x8
	RLIMIT_NPROC                      = 0x7
	RLIMIT_RSS                        = 0x5
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
	WNOHANG                           = 0x1
	WNOWAIT                           = 0x10000
	WNOZOMBIE                         = 0x20000
	WOPTSCHECKED                      = 0x40000
	WSTOPPED                          = 0x7f
	WUNTRACED                         = 0x2
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
	EBADMSG         = syscall.Errno(0x58)
	EBADRPC         = syscall.Errno(0x48)
	EBUSY           = syscall.Errno(0x10)
	ECANCELED       = syscall.Errno(0x57)
	ECHILD          = syscall.Errno(0xa)
	ECONNABORTED    = syscall.Errno(0x35)
	ECONNREFUSED    = syscall.Errno(0x3d)
	ECONNRESET      = syscall.Errno(0x36)
	EDEADLK         = syscall.Errno(0xb)
	EDESTADDRREQ    = syscall.Errno(0x27)
	EDOM            = syscall.Errno(0x21)
	EDQUOT          = syscall.Errno(0x45)
	EEXIST          = syscall.Errno(0x11)
	EFAULT          = syscall.Errno(0xe)
	EFBIG           = syscall.Errno(0x1b)
	EFTYPE          = syscall.Errno(0x4f)
	EHOSTDOWN       = syscall.Errno(0x40)
	EHOSTUNREACH    = syscall.Errno(0x41)
	EIDRM           = syscall.Errno(0x52)
	EILSEQ          = syscall.Errno(0x55)
	EINPROGRESS     = syscall.Errno(0x24)
	EINTR           = syscall.Errno(0x4)
	EINVAL          = syscall.Errno(0x16)
	EIO             = syscall.Errno(0x5)
	EISCONN         = syscall.Errno(0x38)
	EISDIR          = syscall.Errno(0x15)
	ELAST           = syscall.Errno(0x60)
	ELOOP           = syscall.Errno(0x3e)
	EMFILE          = syscall.Errno(0x18)
	EMLINK          = syscall.Errno(0x1f)
	EMSGSIZE        = syscall.Errno(0x28)
	EMULTIHOP       = syscall.Errno(0x5e)
	ENAMETOOLONG    = syscall.Errno(0x3f)
	ENEEDAUTH       = syscall.Errno(0x51)
	ENETDOWN        = syscall.Errno(0x32)
	ENETRESET       = syscall.Errno(0x34)
	ENETUNREACH     = syscall.Errno(0x33)
	ENFILE          = syscall.Errno(0x17)
	ENOATTR         = syscall.Errno(0x5d)
	ENOBUFS         = syscall.Errno(0x37)
	ENODATA         = syscall.Errno(0x59)
	ENODEV          = syscall.Errno(0x13)
	ENOENT          = syscall.Errno(0x2
"""




```