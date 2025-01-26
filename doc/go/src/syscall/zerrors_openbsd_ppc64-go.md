Response:
The user wants to understand the functionality of a Go file named `zerrors_openbsd_ppc64.go` located in the `go/src/syscall` directory. This file appears to be a generated file containing constant definitions specific to the OpenBSD operating system on the ppc64 architecture.

Here's a breakdown of the thought process:

1. **Identify the file's purpose:** The filename strongly suggests this file defines error codes or other syscall-related constants. The `zerrors` prefix is a common convention in the Go standard library for platform-specific error definitions. The `openbsd` and `ppc64` parts confirm the target OS and architecture.

2. **Analyze the content:** The content consists of Go `const` declarations. The names of the constants (e.g., `AF_INET`, `B9600`, `BIOCFLUSH`) are indicative of system-level programming and likely related to system calls, networking, and terminal I/O. The hexadecimal values assigned to these constants are typical for low-level system definitions.

3. **Infer the Go feature:** This file directly supports the `syscall` package in Go. The `syscall` package provides a low-level interface to the operating system's system calls. These constants are used as arguments to system calls or as return values.

4. **Provide a Go code example:**  To illustrate the usage, I need to show a scenario where these constants are used. Networking is a good candidate because many constants like `AF_INET` and socket options are present. Creating a socket is a common operation that uses address family constants.

5. **Develop the code example:**
    * Import the `syscall` package.
    * Use `syscall.Socket()` to create a socket.
    * Use `syscall.AF_INET` for the address family (IPv4).
    * Use `syscall.SOCK_STREAM` for the socket type (TCP).
    * Use `syscall.IPPROTO_TCP` for the protocol.
    * Include error handling for the `syscall.Socket()` call.
    * Provide a basic output indicating success or failure.

6. **Explain the code example:** Describe the purpose of each line and how the constants from the file are used.

7. **Address command-line arguments:** This file contains constant *definitions*, not the code that *processes* command-line arguments. Therefore, it's unlikely to directly handle command-line arguments. I should clarify this.

8. **Identify potential pitfalls:**  A common mistake when working with the `syscall` package is using platform-specific constants on the wrong operating system or architecture. This can lead to unexpected behavior or errors. I should provide an example of this.

9. **Summarize the functionality:**  Concise summary of the file's role in providing OS-specific constants for the `syscall` package.

10. **Structure the answer:** Organize the information into clear sections as requested by the user. Use code blocks for the Go example and format the explanation appropriately. Use Chinese as requested.

**Self-Correction/Refinement:**

* Initially, I might have thought about including more complex examples involving ioctl calls since many `BIOC*` constants are present. However, a simple socket example is more accessible and directly illustrates the use of address family constants, which are clearly defined in the provided snippet.
* I considered mentioning the `cgo` part of the header. While relevant to the generation process, it's less directly related to the *functionality* of the final generated file from the perspective of a user. It's better to focus on the constants themselves.
* Ensuring the Go code example is runnable and demonstrates the use of the constants is crucial. The error handling is important.

By following these steps, I can create a comprehensive and accurate answer to the user's request.这是Go语言 `syscall` 包的一部分，专门为 OpenBSD 操作系统和 ppc64 架构定义了一些常量。

**它的主要功能是:**

1. **定义了大量的系统级常量:**  这些常量在与操作系统底层交互时使用，例如：
    * **地址族 (Address Families, AF_*)**:  例如 `AF_INET` (IPv4), `AF_INET6` (IPv6), `AF_UNIX` (本地socket) 等，用于创建socket时指定地址类型。
    * **BPF 相关常量 (BPF_*)**: 用于 Berkeley Packet Filter，这是一种原始网络数据包捕获机制。这些常量定义了BPF指令、操作码、版本号等。
    * **终端 I/O 相关常量 (B*, CSIZE, ECHO, 等)**:  用于配置终端的行为，例如波特率 (B9600)，字符大小 (CS8)，回显控制 (ECHO)。
    * **ioctl 操作码 (BIOC*, DIOCOSFPFLUSH)**:  用于 `ioctl` 系统调用，控制设备的行为，例如网络接口 (BIOCGETIF) 或磁盘 I/O (DIOCOSFPFLUSH)。
    * **数据链路类型 (DLT_*)**:  用于数据包捕获，指明网络接口使用的链路层协议，例如 `DLT_EN10MB` (以太网)。
    * **目录项类型 (DT_*)**:  用于描述文件系统目录项的类型，例如 `DT_REG` (普通文件), `DT_DIR` (目录)。
    * **以太网类型 (ETHERTYPE_*)**: 定义了以太网帧中 EtherType 字段的各种值，用于指示上层协议，例如 `ETHERTYPE_IP` (IPv4), `ETHERTYPE_ARP` (ARP)。
    * **kqueue 事件过滤器 (EVFILT_*) 和事件标志 (EV_*)**:  用于 kqueue 事件通知机制，例如 `EVFILT_READ` (读事件), `EV_ADD` (添加事件)。
    * **文件描述符标志 (FD_*)**:  例如 `FD_CLOEXEC`，用于控制文件描述符在 `exec` 时的行为。
    * **fcntl 操作 (F_*)**: 用于 `fcntl` 系统调用，控制文件描述符的属性，例如文件锁 (F_RDLCK, F_WRLCK)。
    * **终端标志 (HUPCL, ICANON, 等)**:  用于配置终端的各种特性。
    * **网络接口标志 (IFF_*)**:  用于描述网络接口的状态和特性，例如 `IFF_UP` (接口已启动), `IFF_BROADCAST` (支持广播)。
    * **接口类型 (IFT_*)**:  定义了网络接口的类型，例如 `IFT_ETHER` (以太网), `IFT_LOOP` (回环接口)。
    * **IP 协议号 (IPPROTO_*)**:  定义了IP包头中 Protocol 字段的值，指示上层协议，例如 `IPPROTO_TCP` (TCP), `IPPROTO_UDP` (UDP)。
    * **其他常量**:  还包含一些其他的系统级常量，例如网络地址类的定义 (`IN_CLASSA_HOST`)。

2. **为 `syscall` 包提供平台特定的定义:** Go 的 `syscall` 包提供了一个跨平台的系统调用接口。然而，不同的操作系统在系统调用和相关的常量上存在差异。这个文件就是为了解决这个问题，为 OpenBSD/ppc64 架构提供了专属的常量定义。

**可以推理出它是什么Go语言功能的实现:**

这个文件是 Go 语言 `syscall` 包实现的一部分，用于提供对底层操作系统系统调用的访问。更具体地说，它实现了在 OpenBSD/ppc64 平台上使用的常量定义。

**Go 代码举例说明:**

以下代码示例展示了如何使用这个文件中定义的常量来创建一个 IPv4 的 TCP socket：

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Println("创建socket失败:", err)
		return
	}
	fmt.Println("Socket创建成功，文件描述符:", fd)
	syscall.Close(fd) // 记得关闭文件描述符
}
```

**假设的输入与输出:**

在这个例子中，没有直接的输入。

**输出:**

如果 socket 创建成功，输出类似：

```
Socket创建成功，文件描述符: 3
```

如果创建失败，输出类似：

```
创建socket失败: socket: permission denied
```

**命令行参数的具体处理:**

这个文件本身不处理命令行参数。它只是定义常量。命令行参数的处理通常发生在程序的 `main` 函数中使用 `os.Args` 或 `flag` 包进行解析。

**使用者易犯错的点:**

* **平台依赖性:**  直接使用 `syscall` 包中的常量是具有平台依赖性的。这段代码只能在 OpenBSD 的 ppc64 架构上正确运行。如果在其他操作系统或架构上运行，可能会导致编译错误或运行时错误，因为其他平台可能没有定义相同的常量或者常量的值不同。

**例子:** 如果你在 Linux 系统上运行上述代码，尽管 `syscall.AF_INET`, `syscall.SOCK_STREAM`, `syscall.IPPROTO_TCP` 这些常量在 Linux 中也有定义，但其他的特定于 OpenBSD 的常量将不存在，导致编译错误。即使是通用的常量，其数值也可能不同，导致意想不到的行为。

**功能归纳:**

这是 Go 语言 `syscall` 包为 OpenBSD 操作系统和 ppc64 架构提供的平台特定常量定义文件。它包含了网络编程、终端控制、文件系统操作等底层系统交互所需的各种常量，是 Go 语言能够进行底层系统编程的基础组成部分。

Prompt: 
```
这是路径为go/src/syscall/zerrors_openbsd_ppc64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// mkerrors.sh -m64
// Code generated by the command above; DO NOT EDIT.

// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -m64 _const.go

package syscall

const (
	AF_APPLETALK                      = 0x10
	AF_BLUETOOTH                      = 0x20
	AF_CCITT                          = 0xa
	AF_CHAOS                          = 0x5
	AF_CNT                            = 0x15
	AF_COIP                           = 0x14
	AF_DATAKIT                        = 0x9
	AF_DECnet                         = 0xc
	AF_DLI                            = 0xd
	AF_E164                           = 0x1a
	AF_ECMA                           = 0x8
	AF_ENCAP                          = 0x1c
	AF_HYLINK                         = 0xf
	AF_IMPLINK                        = 0x3
	AF_INET                           = 0x2
	AF_INET6                          = 0x18
	AF_IPX                            = 0x17
	AF_ISDN                           = 0x1a
	AF_ISO                            = 0x7
	AF_KEY                            = 0x1e
	AF_LAT                            = 0xe
	AF_LINK                           = 0x12
	AF_LOCAL                          = 0x1
	AF_MAX                            = 0x24
	AF_MPLS                           = 0x21
	AF_NATM                           = 0x1b
	AF_NS                             = 0x6
	AF_OSI                            = 0x7
	AF_PUP                            = 0x4
	AF_ROUTE                          = 0x11
	AF_SIP                            = 0x1d
	AF_SNA                            = 0xb
	AF_UNIX                           = 0x1
	AF_UNSPEC                         = 0x0
	ARPHRD_ETHER                      = 0x1
	ARPHRD_FRELAY                     = 0xf
	ARPHRD_IEEE1394                   = 0x18
	ARPHRD_IEEE802                    = 0x6
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
	BIOCGDIRFILT                      = 0x4004427c
	BIOCGDLT                          = 0x4004426a
	BIOCGDLTLIST                      = 0xc010427b
	BIOCGETIF                         = 0x4020426b
	BIOCGFILDROP                      = 0x40044278
	BIOCGHDRCMPLT                     = 0x40044274
	BIOCGRSIG                         = 0x40044273
	BIOCGRTIMEOUT                     = 0x4010426e
	BIOCGSTATS                        = 0x4008426f
	BIOCIMMEDIATE                     = 0x80044270
	BIOCLOCK                          = 0x20004276
	BIOCPROMISC                       = 0x20004269
	BIOCSBLEN                         = 0xc0044266
	BIOCSDIRFILT                      = 0x8004427d
	BIOCSDLT                          = 0x8004427a
	BIOCSETF                          = 0x80104267
	BIOCSETIF                         = 0x8020426c
	BIOCSETWF                         = 0x80104277
	BIOCSFILDROP                      = 0x80044279
	BIOCSHDRCMPLT                     = 0x80044275
	BIOCSRSIG                         = 0x80044272
	BIOCSRTIMEOUT                     = 0x8010426d
	BIOCVERSION                       = 0x40044271
	BPF_A                             = 0x10
	BPF_ABS                           = 0x20
	BPF_ADD                           = 0x0
	BPF_ALIGNMENT                     = 0x4
	BPF_ALU                           = 0x4
	BPF_AND                           = 0x50
	BPF_B                             = 0x10
	BPF_DIRECTION_IN                  = 0x1
	BPF_DIRECTION_OUT                 = 0x2
	BPF_DIV                           = 0x30
	BPF_FILDROP_CAPTURE               = 0x1
	BPF_FILDROP_DROP                  = 0x2
	BPF_FILDROP_PASS                  = 0x0
	BPF_F_DIR_IN                      = 0x10
	BPF_F_DIR_MASK                    = 0x30
	BPF_F_DIR_OUT                     = 0x20
	BPF_F_DIR_SHIFT                   = 0x4
	BPF_F_FLOWID                      = 0x8
	BPF_F_PRI_MASK                    = 0x7
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
	BPF_MAXBUFSIZE                    = 0x200000
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
	BPF_RND                           = 0xc0
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
	CSTATUS                           = 0xff
	CSTOP                             = 0x13
	CSTOPB                            = 0x400
	CSUSP                             = 0x1a
	CTL_MAXNAME                       = 0xc
	CTL_NET                           = 0x4
	DIOCOSFPFLUSH                     = 0x2000444e
	DLT_ARCNET                        = 0x7
	DLT_ATM_RFC1483                   = 0xb
	DLT_AX25                          = 0x3
	DLT_CHAOS                         = 0x5
	DLT_C_HDLC                        = 0x68
	DLT_EN10MB                        = 0x1
	DLT_EN3MB                         = 0x2
	DLT_ENC                           = 0xd
	DLT_FDDI                          = 0xa
	DLT_IEEE802                       = 0x6
	DLT_IEEE802_11                    = 0x69
	DLT_IEEE802_11_RADIO              = 0x7f
	DLT_LOOP                          = 0xc
	DLT_MPLS                          = 0xdb
	DLT_NULL                          = 0x0
	DLT_OPENFLOW                      = 0x10b
	DLT_PFLOG                         = 0x75
	DLT_PFSYNC                        = 0x12
	DLT_PPP                           = 0x9
	DLT_PPP_BSDOS                     = 0x10
	DLT_PPP_ETHER                     = 0x33
	DLT_PPP_SERIAL                    = 0x32
	DLT_PRONET                        = 0x4
	DLT_RAW                           = 0xe
	DLT_SLIP                          = 0x8
	DLT_SLIP_BSDOS                    = 0xf
	DLT_USBPCAP                       = 0xf9
	DLT_USER0                         = 0x93
	DLT_USER1                         = 0x94
	DLT_USER10                        = 0x9d
	DLT_USER11                        = 0x9e
	DLT_USER12                        = 0x9f
	DLT_USER13                        = 0xa0
	DLT_USER14                        = 0xa1
	DLT_USER15                        = 0xa2
	DLT_USER2                         = 0x95
	DLT_USER3                         = 0x96
	DLT_USER4                         = 0x97
	DLT_USER5                         = 0x98
	DLT_USER6                         = 0x99
	DLT_USER7                         = 0x9a
	DLT_USER8                         = 0x9b
	DLT_USER9                         = 0x9c
	DT_BLK                            = 0x6
	DT_CHR                            = 0x2
	DT_DIR                            = 0x4
	DT_FIFO                           = 0x1
	DT_LNK                            = 0xa
	DT_REG                            = 0x8
	DT_SOCK                           = 0xc
	DT_UNKNOWN                        = 0x0
	ECHO                              = 0x8
	ECHOCTL                           = 0x40
	ECHOE                             = 0x2
	ECHOK                             = 0x4
	ECHOKE                            = 0x1
	ECHONL                            = 0x10
	ECHOPRT                           = 0x20
	EMT_TAGOVF                        = 0x1
	EMUL_ENABLED                      = 0x1
	EMUL_NATIVE                       = 0x2
	ENDRUNDISC                        = 0x9
	ETH64_8021_RSVD_MASK              = 0xfffffffffff0
	ETH64_8021_RSVD_PREFIX            = 0x180c2000000
	ETHERMIN                          = 0x2e
	ETHERMTU                          = 0x5dc
	ETHERTYPE_8023                    = 0x4
	ETHERTYPE_AARP                    = 0x80f3
	ETHERTYPE_ACCTON                  = 0x8390
	ETHERTYPE_AEONIC                  = 0x8036
	ETHERTYPE_ALPHA                   = 0x814a
	ETHERTYPE_AMBER                   = 0x6008
	ETHERTYPE_AMOEBA                  = 0x8145
	ETHERTYPE_AOE                     = 0x88a2
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
	ETHERTYPE_EAPOL                   = 0x888e
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
	ETHERTYPE_LLDP                    = 0x88cc
	ETHERTYPE_LOGICRAFT               = 0x8148
	ETHERTYPE_LOOPBACK                = 0x9000
	ETHERTYPE_MACSEC                  = 0x88e5
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
	ETHERTYPE_NHRP                    = 0x2001
	ETHERTYPE_NOVELL                  = 0x8138
	ETHERTYPE_NS                      = 0x600
	ETHERTYPE_NSAT                    = 0x601
	ETHERTYPE_NSCOMPAT                = 0x807
	ETHERTYPE_NSH                     = 0x984f
	ETHERTYPE_NTRAILER                = 0x10
	ETHERTYPE_OS9                     = 0x7007
	ETHERTYPE_OS9NET                  = 0x7009
	ETHERTYPE_PACER                   = 0x80c6
	ETHERTYPE_PBB                     = 0x88e7
	ETHERTYPE_PCS                     = 0x4242
	ETHERTYPE_PLANNING                = 0x8044
	ETHERTYPE_PPP                     = 0x880b
	ETHERTYPE_PPPOE                   = 0x8864
	ETHERTYPE_PPPOEDISC               = 0x8863
	ETHERTYPE_PRIMENTS                = 0x7031
	ETHERTYPE_PUP                     = 0x200
	ETHERTYPE_PUPAT                   = 0x200
	ETHERTYPE_QINQ                    = 0x88a8
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
	ETHERTYPE_SLOW                    = 0x8809
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
	ETHER_ALIGN                       = 0x2
	ETHER_CRC_LEN                     = 0x4
	ETHER_CRC_POLY_BE                 = 0x4c11db6
	ETHER_CRC_POLY_LE                 = 0xedb88320
	ETHER_HDR_LEN                     = 0xe
	ETHER_MAX_DIX_LEN                 = 0x600
	ETHER_MAX_HARDMTU_LEN             = 0xff9b
	ETHER_MAX_LEN                     = 0x5ee
	ETHER_MIN_LEN                     = 0x40
	ETHER_TYPE_LEN                    = 0x2
	ETHER_VLAN_ENCAP_LEN              = 0x4
	EVFILT_AIO                        = -0x3
	EVFILT_DEVICE                     = -0x8
	EVFILT_EXCEPT                     = -0x9
	EVFILT_PROC                       = -0x5
	EVFILT_READ                       = -0x1
	EVFILT_SIGNAL                     = -0x6
	EVFILT_SYSCOUNT                   = 0x9
	EVFILT_TIMER                      = -0x7
	EVFILT_VNODE                      = -0x4
	EVFILT_WRITE                      = -0x2
	EVL_ENCAPLEN                      = 0x4
	EVL_PRIO_BITS                     = 0xd
	EVL_PRIO_MAX                      = 0x7
	EVL_VLID_MASK                     = 0xfff
	EVL_VLID_MAX                      = 0xffe
	EVL_VLID_MIN                      = 0x1
	EVL_VLID_NULL                     = 0x0
	EV_ADD                            = 0x1
	EV_CLEAR                          = 0x20
	EV_DELETE                         = 0x2
	EV_DISABLE                        = 0x8
	EV_DISPATCH                       = 0x80
	EV_ENABLE                         = 0x4
	EV_EOF                            = 0x8000
	EV_ERROR                          = 0x4000
	EV_FLAG1                          = 0x2000
	EV_ONESHOT                        = 0x10
	EV_RECEIPT                        = 0x40
	EV_SYSFLAGS                       = 0xf800
	EXTA                              = 0x4b00
	EXTB                              = 0x9600
	EXTPROC                           = 0x800
	FD_CLOEXEC                        = 0x1
	FD_SETSIZE                        = 0x400
	FLUSHO                            = 0x800000
	F_DUPFD                           = 0x0
	F_DUPFD_CLOEXEC                   = 0xa
	F_GETFD                           = 0x1
	F_GETFL                           = 0x3
	F_GETLK                           = 0x7
	F_GETOWN                          = 0x5
	F_ISATTY                          = 0xb
	F_RDLCK                           = 0x1
	F_SETFD                           = 0x2
	F_SETFL                           = 0x4
	F_SETLK                           = 0x8
	F_SETLKW                          = 0x9
	F_SETOWN                          = 0x6
	F_UNLCK                           = 0x2
	F_WRLCK                           = 0x3
	HUPCL                             = 0x4000
	ICANON                            = 0x100
	ICMP6_FILTER                      = 0x12
	ICRNL                             = 0x100
	IEXTEN                            = 0x400
	IFAN_ARRIVAL                      = 0x0
	IFAN_DEPARTURE                    = 0x1
	IFF_ALLMULTI                      = 0x200
	IFF_BROADCAST                     = 0x2
	IFF_CANTCHANGE                    = 0x8e52
	IFF_DEBUG                         = 0x4
	IFF_LINK0                         = 0x1000
	IFF_LINK1                         = 0x2000
	IFF_LINK2                         = 0x4000
	IFF_LOOPBACK                      = 0x8
	IFF_MULTICAST                     = 0x8000
	IFF_NOARP                         = 0x80
	IFF_OACTIVE                       = 0x400
	IFF_POINTOPOINT                   = 0x10
	IFF_PROMISC                       = 0x100
	IFF_RUNNING                       = 0x40
	IFF_SIMPLEX                       = 0x800
	IFF_STATICARP                     = 0x20
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
	IFT_BLUETOOTH                     = 0xf8
	IFT_BRIDGE                        = 0xd1
	IFT_BSC                           = 0x53
	IFT_CARP                          = 0xf7
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
	IFT_DUMMY                         = 0xf1
	IFT_DVBASILN                      = 0xac
	IFT_DVBASIOUT                     = 0xad
	IFT_DVBRCCDOWNSTREAM              = 0x93
	IFT_DVBRCCMACLAYER                = 0x92
	IFT_DVBRCCUPSTREAM                = 0x94
	IFT_ECONET                        = 0xce
	IFT_ENC                           = 0xf4
	IFT_EON                           = 0x19
	IFT_EPLRS                         = 0x57
	IFT_ESCON                         = 0x49
	IFT_ETHER                         = 0x6
	IFT_FAITH                         = 0xf3
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
	IFT_MBIM                          = 0xfa
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
	IFT_PFLOW                         = 0xf9
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
	IFT_PVC                           = 0xf2
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
	IFT_WIREGUARD                     = 0xfb
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
	IN_RFC3021_HOST                   = 0x1
	IN_RFC3021_NET                    = 0xfffffffe
	IN_RFC3021_NSHIFT                 = 0x1f
	IPPROTO_AH                        = 0x33
	IPPROTO_CARP                      = 0x70
	IPPROTO_DIVERT                    = 0x102
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
	IPPROT
"""




```