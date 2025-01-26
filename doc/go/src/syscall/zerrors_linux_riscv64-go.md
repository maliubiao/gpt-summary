Response:
The user provided a snippet of a Go file located at `go/src/syscall/zerrors_linux_riscv64.go`. This file appears to contain constant definitions related to system calls on the Linux RISC-V 64-bit architecture. The task is to summarize the functionality of this code.

**Plan:**

1. **Identify the core purpose:** The code defines constants.
2. **Infer the usage context:**  These constants are likely used for interacting with the operating system kernel through system calls.
3. **Categorize the constants:** Group the constants by their prefixes or apparent purpose (e.g., `AF_` for address families, `ARPHRD_` for hardware address types, `O_` for file open flags, etc.). This helps in understanding the breadth of the defined constants.
4. **Summarize the overall function:** Concisely describe that the file provides definitions for various system-level constants used in system calls on Linux/RISC-V 64-bit.
这个Go语言文件 (`go/src/syscall/zerrors_linux_riscv64.go`) 的主要功能是**定义了一系列用于Linux RISC-V 64位架构的系统调用相关的常量**。

这些常量涵盖了以下几个方面：

* **地址族 (Address Families, `AF_` 开头):**  例如 `AF_INET`, `AF_INET6`, `AF_UNIX` 等，定义了网络通信中使用的地址类型。
* **硬件地址类型 (ARP Hardware Types, `ARPHRD_` 开头):** 例如 `ARPHRD_ETHER`, `ARPHRD_LOOPBACK` 等，定义了不同网络接口的硬件地址类型。
* **波特率 (Baud Rates, `B` 开头):** 例如 `B115200`, `B9600` 等，定义了串口通信中常用的波特率。
* **BPF (Berkeley Packet Filter, `BPF_` 开头):**  例如 `BPF_LD`, `BPF_JMP` 等，定义了用于网络数据包过滤的指令和操作码。
* **终端控制标志 (Terminal Control Flags, 如 `CREAD`, `ECHO`, `ICANON` 等):**  用于配置终端的行为，例如是否回显输入，是否启用规范模式等。
* **目录项类型 (Directory Entry Types, `DT_` 开头):** 例如 `DT_REG`, `DT_DIR`, `DT_SOCK` 等，定义了文件系统中不同类型的文件。
* **EPOLL 事件类型 (EPOLL Event Types, `EPOLL` 开头):** 例如 `EPOLLIN`, `EPOLLOUT`, `EPOLLERR` 等，用于多路复用I/O中的事件通知。
* **以太网协议类型 (Ethernet Protocol Types, `ETH_P_` 开头):** 例如 `ETH_P_IP`, `ETH_P_ARP` 等，定义了以太网帧中携带的不同协议类型。
* **终端扩展控制 (Extended Terminal Control, `EXTA`, `EXTB`, `EXTPROC`):**  额外的终端控制标志。
* **文件描述符标志 (File Descriptor Flags, `FD_` 开头):** 例如 `FD_CLOEXEC`，用于控制文件描述符的继承行为。
* **fcntl 函数使用的标志 (fcntl Flags, `F_` 开头):** 例如 `F_RDLCK`, `F_WRLCK`, `F_SETFL` 等，用于文件锁和文件控制操作。
* **终端挂断控制 (Hang Up Control, `HUPCL`):** 用于控制终端连接断开时的行为。
* **输入标志 (Input Flags, `ICANON`, `IGNBRK` 等):** 用于配置终端输入的处理方式。
* **接口地址标志 (Interface Address Flags, `IFA_F_` 开头):** 例如 `IFA_F_TEMPORARY`, `IFA_F_DEPRECATED` 等，用于描述网络接口地址的属性。
* **接口标志 (Interface Flags, `IFF_` 开头):** 例如 `IFF_UP`, `IFF_BROADCAST`, `IFF_LOOPBACK` 等，用于配置网络接口的属性。
* **接口名称大小限制 (Interface Name Size, `IFNAMSIZ`):** 定义了网络接口名称的最大长度。
* **忽略标志 (Ignore Flags, `IGNBRK`, `IGNCR` 等):**  用于设置终端输入时需要忽略的字符或条件。
* **输入最大字节数 (Input Maximum Bytes, `IMAXBEL`):** 用于限制终端输入的最大字节数。
* **输入换行符转换标志 (Input Newline Conversion Flags, `INLCR`, `ICRNL`):** 用于控制终端输入时的换行符转换。
* **输入奇偶校验标志 (Input Parity Check Flag, `INPCK`):** 用于启用或禁用终端输入的奇偶校验。
* **inotify 事件标志 (inotify Event Flags, `IN_` 开头):** 例如 `IN_CREATE`, `IN_DELETE`, `IN_MODIFY` 等，用于文件系统事件监控。
* **IP协议号 (IP Protocol Numbers, `IPPROTO_` 开头):** 例如 `IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_ICMP` 等，定义了IP协议栈中不同协议的编号。
* **IPv6选项 (IPv6 Options, `IPV6_` 开头):** 例如 `IPV6_V6ONLY`, `IPV6_JOIN_GROUP` 等，用于配置IPv6套接字的行为。
* **IP选项 (IP Options, `IP_` 开头):** 例如 `IP_TTL`, `IP_ADD_MEMBERSHIP` 等，用于配置IPv4套接字的行为。
* **输入信号处理标志 (Input Signal Handling Flag, `ISIG`):**  用于控制终端输入是否产生信号。
* **输入剥离标志 (Input Strip Flag, `ISTRIP`):** 用于剥离终端输入字符的第八位。
* **UTF-8 输入标志 (UTF-8 Input Flag, `IUTF8`):**  用于声明终端支持UTF-8输入。
* **流控标志 (Flow Control Flags, `IXANY`, `IXOFF`, `IXON`):** 用于控制终端的输入输出流。
* **Linux 重启命令 (Linux Reboot Commands, `LINUX_REBOOT_CMD_` 开头):** 例如 `LINUX_REBOOT_CMD_RESTART`, `LINUX_REBOOT_CMD_POWER_OFF` 等，用于系统重启和关机。
* **文件锁类型 (Lock Types, `LOCK_EX`, `LOCK_SH` 等):** 用于文件加锁操作。
* **madvise 函数使用的建议 (madvise Hints, `MADV_` 开头):** 例如 `MADV_DONTNEED`, `MADV_SEQUENTIAL` 等，向内核提供关于内存使用模式的建议。
* **mmap 函数使用的标志 (mmap Flags, `MAP_` 开头):** 例如 `MAP_SHARED`, `MAP_PRIVATE`, `MAP_ANON` 等，用于内存映射操作。
* **内存锁定标志 (Memory Locking Flags, `MCL_CURRENT`, `MCL_FUTURE`):** 用于锁定进程的内存到RAM中。
* **卸载标志 (Mount Flags for umount, `MNT_DETACH`, `MNT_FORCE`):** 用于控制文件系统卸载的行为。
* **消息标志 (Message Flags, `MSG_` 开头):** 例如 `MSG_DONTWAIT`, `MSG_PEEK`, `MSG_OOB` 等，用于套接字发送和接收消息。
* **挂载标志 (Mount Flags, `MS_` 开头):** 例如 `MS_RDONLY`, `MS_BIND`, `MS_REMOUNT` 等，用于文件系统的挂载操作。
* **文件名最大长度 (Maximum File Name Length, `NAME_MAX`):** 定义了文件名的最大长度。
* **Netlink 协议族 (Netlink Families, `NETLINK_` 开头):** 例如 `NETLINK_ROUTE`, `NETLINK_NETFILTER` 等，用于内核和用户空间进程之间的通信。
* **Netlink 属性标志 (Netlink Attribute Flags, `NLA_F_` 开头):** 用于Netlink消息中的属性处理。
* **Netlink 消息标志 (Netlink Message Flags, `NLMSG_` 开头):**  用于标识Netlink消息的类型。
* **Netlink 消息头部标志 (Netlink Message Header Flags, `NLM_F_` 开头):** 用于控制Netlink消息的处理方式。
* **不刷新标志 (No Flush Flag, `NOFLSH`):**  用于终端控制。
* **输出换行符转换标志 (Output Newline Conversion Flags, `OCRNL`, `ONLCR` 等):** 用于控制终端输出时的换行符转换。
* **输出填充标志 (Output Fill Flags, `OFILL`):**  用于终端输出的填充控制。
* **输出处理标志 (Output Processing Flag, `OPOST`):** 用于启用或禁用终端输出处理。
* **文件打开标志 (Open Flags, `O_` 开头):** 例如 `O_RDONLY`, `O_CREAT`, `O_APPEND` 等，用于控制文件打开的方式。

**总结:**

这个代码片段定义了在 Linux RISC-V 64位架构下进行底层系统编程时需要用到的各种常量。它为 Go 语言的 `syscall` 包提供了与操作系统内核交互的基础，使得 Go 程序能够调用底层的系统功能，例如网络操作、文件操作、进程控制等。

Prompt: 
```
这是路径为go/src/syscall/zerrors_linux_riscv64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// mkerrors.sh
// Code generated by the command above; DO NOT EDIT.

// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- _const.go

package syscall

const (
	AF_ALG                           = 0x26
	AF_APPLETALK                     = 0x5
	AF_ASH                           = 0x12
	AF_ATMPVC                        = 0x8
	AF_ATMSVC                        = 0x14
	AF_AX25                          = 0x3
	AF_BLUETOOTH                     = 0x1f
	AF_BRIDGE                        = 0x7
	AF_CAIF                          = 0x25
	AF_CAN                           = 0x1d
	AF_DECnet                        = 0xc
	AF_ECONET                        = 0x13
	AF_FILE                          = 0x1
	AF_IB                            = 0x1b
	AF_IEEE802154                    = 0x24
	AF_INET                          = 0x2
	AF_INET6                         = 0xa
	AF_IPX                           = 0x4
	AF_IRDA                          = 0x17
	AF_ISDN                          = 0x22
	AF_IUCV                          = 0x20
	AF_KCM                           = 0x29
	AF_KEY                           = 0xf
	AF_LLC                           = 0x1a
	AF_LOCAL                         = 0x1
	AF_MAX                           = 0x2a
	AF_MPLS                          = 0x1c
	AF_NETBEUI                       = 0xd
	AF_NETLINK                       = 0x10
	AF_NETROM                        = 0x6
	AF_NFC                           = 0x27
	AF_PACKET                        = 0x11
	AF_PHONET                        = 0x23
	AF_PPPOX                         = 0x18
	AF_RDS                           = 0x15
	AF_ROSE                          = 0xb
	AF_ROUTE                         = 0x10
	AF_RXRPC                         = 0x21
	AF_SECURITY                      = 0xe
	AF_SNA                           = 0x16
	AF_TIPC                          = 0x1e
	AF_UNIX                          = 0x1
	AF_UNSPEC                        = 0x0
	AF_VSOCK                         = 0x28
	AF_WANPIPE                       = 0x19
	AF_X25                           = 0x9
	ARPHRD_6LOWPAN                   = 0x339
	ARPHRD_ADAPT                     = 0x108
	ARPHRD_APPLETLK                  = 0x8
	ARPHRD_ARCNET                    = 0x7
	ARPHRD_ASH                       = 0x30d
	ARPHRD_ATM                       = 0x13
	ARPHRD_AX25                      = 0x3
	ARPHRD_BIF                       = 0x307
	ARPHRD_CAIF                      = 0x336
	ARPHRD_CAN                       = 0x118
	ARPHRD_CHAOS                     = 0x5
	ARPHRD_CISCO                     = 0x201
	ARPHRD_CSLIP                     = 0x101
	ARPHRD_CSLIP6                    = 0x103
	ARPHRD_DDCMP                     = 0x205
	ARPHRD_DLCI                      = 0xf
	ARPHRD_ECONET                    = 0x30e
	ARPHRD_EETHER                    = 0x2
	ARPHRD_ETHER                     = 0x1
	ARPHRD_EUI64                     = 0x1b
	ARPHRD_FCAL                      = 0x311
	ARPHRD_FCFABRIC                  = 0x313
	ARPHRD_FCPL                      = 0x312
	ARPHRD_FCPP                      = 0x310
	ARPHRD_FDDI                      = 0x306
	ARPHRD_FRAD                      = 0x302
	ARPHRD_HDLC                      = 0x201
	ARPHRD_HIPPI                     = 0x30c
	ARPHRD_HWX25                     = 0x110
	ARPHRD_IEEE1394                  = 0x18
	ARPHRD_IEEE802                   = 0x6
	ARPHRD_IEEE80211                 = 0x321
	ARPHRD_IEEE80211_PRISM           = 0x322
	ARPHRD_IEEE80211_RADIOTAP        = 0x323
	ARPHRD_IEEE802154                = 0x324
	ARPHRD_IEEE802154_MONITOR        = 0x325
	ARPHRD_IEEE802_TR                = 0x320
	ARPHRD_INFINIBAND                = 0x20
	ARPHRD_IP6GRE                    = 0x337
	ARPHRD_IPDDP                     = 0x309
	ARPHRD_IPGRE                     = 0x30a
	ARPHRD_IRDA                      = 0x30f
	ARPHRD_LAPB                      = 0x204
	ARPHRD_LOCALTLK                  = 0x305
	ARPHRD_LOOPBACK                  = 0x304
	ARPHRD_METRICOM                  = 0x17
	ARPHRD_NETLINK                   = 0x338
	ARPHRD_NETROM                    = 0x0
	ARPHRD_NONE                      = 0xfffe
	ARPHRD_PHONET                    = 0x334
	ARPHRD_PHONET_PIPE               = 0x335
	ARPHRD_PIMREG                    = 0x30b
	ARPHRD_PPP                       = 0x200
	ARPHRD_PRONET                    = 0x4
	ARPHRD_RAWHDLC                   = 0x206
	ARPHRD_ROSE                      = 0x10e
	ARPHRD_RSRVD                     = 0x104
	ARPHRD_SIT                       = 0x308
	ARPHRD_SKIP                      = 0x303
	ARPHRD_SLIP                      = 0x100
	ARPHRD_SLIP6                     = 0x102
	ARPHRD_TUNNEL                    = 0x300
	ARPHRD_TUNNEL6                   = 0x301
	ARPHRD_VOID                      = 0xffff
	ARPHRD_X25                       = 0x10f
	B0                               = 0x0
	B1000000                         = 0x1008
	B110                             = 0x3
	B115200                          = 0x1002
	B1152000                         = 0x1009
	B1200                            = 0x9
	B134                             = 0x4
	B150                             = 0x5
	B1500000                         = 0x100a
	B1800                            = 0xa
	B19200                           = 0xe
	B200                             = 0x6
	B2000000                         = 0x100b
	B230400                          = 0x1003
	B2400                            = 0xb
	B2500000                         = 0x100c
	B300                             = 0x7
	B3000000                         = 0x100d
	B3500000                         = 0x100e
	B38400                           = 0xf
	B4000000                         = 0x100f
	B460800                          = 0x1004
	B4800                            = 0xc
	B50                              = 0x1
	B500000                          = 0x1005
	B57600                           = 0x1001
	B576000                          = 0x1006
	B600                             = 0x8
	B75                              = 0x2
	B921600                          = 0x1007
	B9600                            = 0xd
	BPF_A                            = 0x10
	BPF_ABS                          = 0x20
	BPF_ADD                          = 0x0
	BPF_ALU                          = 0x4
	BPF_AND                          = 0x50
	BPF_B                            = 0x10
	BPF_DIV                          = 0x30
	BPF_H                            = 0x8
	BPF_IMM                          = 0x0
	BPF_IND                          = 0x40
	BPF_JA                           = 0x0
	BPF_JEQ                          = 0x10
	BPF_JGE                          = 0x30
	BPF_JGT                          = 0x20
	BPF_JMP                          = 0x5
	BPF_JSET                         = 0x40
	BPF_K                            = 0x0
	BPF_LD                           = 0x0
	BPF_LDX                          = 0x1
	BPF_LEN                          = 0x80
	BPF_LL_OFF                       = -0x200000
	BPF_LSH                          = 0x60
	BPF_MAJOR_VERSION                = 0x1
	BPF_MAXINSNS                     = 0x1000
	BPF_MEM                          = 0x60
	BPF_MEMWORDS                     = 0x10
	BPF_MINOR_VERSION                = 0x1
	BPF_MISC                         = 0x7
	BPF_MOD                          = 0x90
	BPF_MSH                          = 0xa0
	BPF_MUL                          = 0x20
	BPF_NEG                          = 0x80
	BPF_NET_OFF                      = -0x100000
	BPF_OR                           = 0x40
	BPF_RET                          = 0x6
	BPF_RSH                          = 0x70
	BPF_ST                           = 0x2
	BPF_STX                          = 0x3
	BPF_SUB                          = 0x10
	BPF_TAX                          = 0x0
	BPF_TXA                          = 0x80
	BPF_W                            = 0x0
	BPF_X                            = 0x8
	BPF_XOR                          = 0xa0
	BRKINT                           = 0x2
	CFLUSH                           = 0xf
	CLOCAL                           = 0x800
	CREAD                            = 0x80
	CS5                              = 0x0
	CS6                              = 0x10
	CS7                              = 0x20
	CS8                              = 0x30
	CSIGNAL                          = 0xff
	CSIZE                            = 0x30
	CSTART                           = 0x11
	CSTATUS                          = 0x0
	CSTOP                            = 0x13
	CSTOPB                           = 0x40
	CSUSP                            = 0x1a
	DT_BLK                           = 0x6
	DT_CHR                           = 0x2
	DT_DIR                           = 0x4
	DT_FIFO                          = 0x1
	DT_LNK                           = 0xa
	DT_REG                           = 0x8
	DT_SOCK                          = 0xc
	DT_UNKNOWN                       = 0x0
	DT_WHT                           = 0xe
	ECHO                             = 0x8
	ECHOCTL                          = 0x200
	ECHOE                            = 0x10
	ECHOK                            = 0x20
	ECHOKE                           = 0x800
	ECHONL                           = 0x40
	ECHOPRT                          = 0x400
	ENCODING_DEFAULT                 = 0x0
	ENCODING_FM_MARK                 = 0x3
	ENCODING_FM_SPACE                = 0x4
	ENCODING_MANCHESTER              = 0x5
	ENCODING_NRZ                     = 0x1
	ENCODING_NRZI                    = 0x2
	EPOLLERR                         = 0x8
	EPOLLET                          = 0x80000000
	EPOLLEXCLUSIVE                   = 0x10000000
	EPOLLHUP                         = 0x10
	EPOLLIN                          = 0x1
	EPOLLMSG                         = 0x400
	EPOLLONESHOT                     = 0x40000000
	EPOLLOUT                         = 0x4
	EPOLLPRI                         = 0x2
	EPOLLRDBAND                      = 0x80
	EPOLLRDHUP                       = 0x2000
	EPOLLRDNORM                      = 0x40
	EPOLLWAKEUP                      = 0x20000000
	EPOLLWRBAND                      = 0x200
	EPOLLWRNORM                      = 0x100
	EPOLL_CLOEXEC                    = 0x80000
	EPOLL_CTL_ADD                    = 0x1
	EPOLL_CTL_DEL                    = 0x2
	EPOLL_CTL_MOD                    = 0x3
	ETH_P_1588                       = 0x88f7
	ETH_P_8021AD                     = 0x88a8
	ETH_P_8021AH                     = 0x88e7
	ETH_P_8021Q                      = 0x8100
	ETH_P_80221                      = 0x8917
	ETH_P_802_2                      = 0x4
	ETH_P_802_3                      = 0x1
	ETH_P_802_3_MIN                  = 0x600
	ETH_P_802_EX1                    = 0x88b5
	ETH_P_AARP                       = 0x80f3
	ETH_P_AF_IUCV                    = 0xfbfb
	ETH_P_ALL                        = 0x3
	ETH_P_AOE                        = 0x88a2
	ETH_P_ARCNET                     = 0x1a
	ETH_P_ARP                        = 0x806
	ETH_P_ATALK                      = 0x809b
	ETH_P_ATMFATE                    = 0x8884
	ETH_P_ATMMPOA                    = 0x884c
	ETH_P_AX25                       = 0x2
	ETH_P_BATMAN                     = 0x4305
	ETH_P_BPQ                        = 0x8ff
	ETH_P_CAIF                       = 0xf7
	ETH_P_CAN                        = 0xc
	ETH_P_CANFD                      = 0xd
	ETH_P_CONTROL                    = 0x16
	ETH_P_CUST                       = 0x6006
	ETH_P_DDCMP                      = 0x6
	ETH_P_DEC                        = 0x6000
	ETH_P_DIAG                       = 0x6005
	ETH_P_DNA_DL                     = 0x6001
	ETH_P_DNA_RC                     = 0x6002
	ETH_P_DNA_RT                     = 0x6003
	ETH_P_DSA                        = 0x1b
	ETH_P_ECONET                     = 0x18
	ETH_P_EDSA                       = 0xdada
	ETH_P_FCOE                       = 0x8906
	ETH_P_FIP                        = 0x8914
	ETH_P_HDLC                       = 0x19
	ETH_P_IEEE802154                 = 0xf6
	ETH_P_IEEEPUP                    = 0xa00
	ETH_P_IEEEPUPAT                  = 0xa01
	ETH_P_IP                         = 0x800
	ETH_P_IPV6                       = 0x86dd
	ETH_P_IPX                        = 0x8137
	ETH_P_IRDA                       = 0x17
	ETH_P_LAT                        = 0x6004
	ETH_P_LINK_CTL                   = 0x886c
	ETH_P_LOCALTALK                  = 0x9
	ETH_P_LOOP                       = 0x60
	ETH_P_LOOPBACK                   = 0x9000
	ETH_P_MOBITEX                    = 0x15
	ETH_P_MPLS_MC                    = 0x8848
	ETH_P_MPLS_UC                    = 0x8847
	ETH_P_MVRP                       = 0x88f5
	ETH_P_PAE                        = 0x888e
	ETH_P_PAUSE                      = 0x8808
	ETH_P_PHONET                     = 0xf5
	ETH_P_PPPTALK                    = 0x10
	ETH_P_PPP_DISC                   = 0x8863
	ETH_P_PPP_MP                     = 0x8
	ETH_P_PPP_SES                    = 0x8864
	ETH_P_PRP                        = 0x88fb
	ETH_P_PUP                        = 0x200
	ETH_P_PUPAT                      = 0x201
	ETH_P_QINQ1                      = 0x9100
	ETH_P_QINQ2                      = 0x9200
	ETH_P_QINQ3                      = 0x9300
	ETH_P_RARP                       = 0x8035
	ETH_P_SCA                        = 0x6007
	ETH_P_SLOW                       = 0x8809
	ETH_P_SNAP                       = 0x5
	ETH_P_TDLS                       = 0x890d
	ETH_P_TEB                        = 0x6558
	ETH_P_TIPC                       = 0x88ca
	ETH_P_TRAILER                    = 0x1c
	ETH_P_TR_802_2                   = 0x11
	ETH_P_WAN_PPP                    = 0x7
	ETH_P_WCCP                       = 0x883e
	ETH_P_X25                        = 0x805
	ETH_P_XDSA                       = 0xf8
	EXTA                             = 0xe
	EXTB                             = 0xf
	EXTPROC                          = 0x10000
	FD_CLOEXEC                       = 0x1
	FD_SETSIZE                       = 0x400
	FLUSHO                           = 0x1000
	F_DUPFD                          = 0x0
	F_DUPFD_CLOEXEC                  = 0x406
	F_EXLCK                          = 0x4
	F_GETFD                          = 0x1
	F_GETFL                          = 0x3
	F_GETLEASE                       = 0x401
	F_GETLK                          = 0x5
	F_GETLK64                        = 0x5
	F_GETOWN                         = 0x9
	F_GETOWN_EX                      = 0x10
	F_GETPIPE_SZ                     = 0x408
	F_GETSIG                         = 0xb
	F_LOCK                           = 0x1
	F_NOTIFY                         = 0x402
	F_OFD_GETLK                      = 0x24
	F_OFD_SETLK                      = 0x25
	F_OFD_SETLKW                     = 0x26
	F_OK                             = 0x0
	F_RDLCK                          = 0x0
	F_SETFD                          = 0x2
	F_SETFL                          = 0x4
	F_SETLEASE                       = 0x400
	F_SETLK                          = 0x6
	F_SETLK64                        = 0x6
	F_SETLKW                         = 0x7
	F_SETLKW64                       = 0x7
	F_SETOWN                         = 0x8
	F_SETOWN_EX                      = 0xf
	F_SETPIPE_SZ                     = 0x407
	F_SETSIG                         = 0xa
	F_SHLCK                          = 0x8
	F_TEST                           = 0x3
	F_TLOCK                          = 0x2
	F_ULOCK                          = 0x0
	F_UNLCK                          = 0x2
	F_WRLCK                          = 0x1
	HUPCL                            = 0x400
	ICANON                           = 0x2
	ICMPV6_FILTER                    = 0x1
	ICRNL                            = 0x100
	IEXTEN                           = 0x8000
	IFA_F_DADFAILED                  = 0x8
	IFA_F_DEPRECATED                 = 0x20
	IFA_F_HOMEADDRESS                = 0x10
	IFA_F_MANAGETEMPADDR             = 0x100
	IFA_F_MCAUTOJOIN                 = 0x400
	IFA_F_NODAD                      = 0x2
	IFA_F_NOPREFIXROUTE              = 0x200
	IFA_F_OPTIMISTIC                 = 0x4
	IFA_F_PERMANENT                  = 0x80
	IFA_F_SECONDARY                  = 0x1
	IFA_F_STABLE_PRIVACY             = 0x800
	IFA_F_TEMPORARY                  = 0x1
	IFA_F_TENTATIVE                  = 0x40
	IFA_MAX                          = 0x8
	IFF_ALLMULTI                     = 0x200
	IFF_ATTACH_QUEUE                 = 0x200
	IFF_AUTOMEDIA                    = 0x4000
	IFF_BROADCAST                    = 0x2
	IFF_DEBUG                        = 0x4
	IFF_DETACH_QUEUE                 = 0x400
	IFF_DORMANT                      = 0x20000
	IFF_DYNAMIC                      = 0x8000
	IFF_ECHO                         = 0x40000
	IFF_LOOPBACK                     = 0x8
	IFF_LOWER_UP                     = 0x10000
	IFF_MASTER                       = 0x400
	IFF_MULTICAST                    = 0x1000
	IFF_MULTI_QUEUE                  = 0x100
	IFF_NOARP                        = 0x80
	IFF_NOFILTER                     = 0x1000
	IFF_NOTRAILERS                   = 0x20
	IFF_NO_PI                        = 0x1000
	IFF_ONE_QUEUE                    = 0x2000
	IFF_PERSIST                      = 0x800
	IFF_POINTOPOINT                  = 0x10
	IFF_PORTSEL                      = 0x2000
	IFF_PROMISC                      = 0x100
	IFF_RUNNING                      = 0x40
	IFF_SLAVE                        = 0x800
	IFF_TAP                          = 0x2
	IFF_TUN                          = 0x1
	IFF_TUN_EXCL                     = 0x8000
	IFF_UP                           = 0x1
	IFF_VNET_HDR                     = 0x4000
	IFF_VOLATILE                     = 0x70c5a
	IFNAMSIZ                         = 0x10
	IGNBRK                           = 0x1
	IGNCR                            = 0x80
	IGNPAR                           = 0x4
	IMAXBEL                          = 0x2000
	INLCR                            = 0x40
	INPCK                            = 0x10
	IN_ACCESS                        = 0x1
	IN_ALL_EVENTS                    = 0xfff
	IN_ATTRIB                        = 0x4
	IN_CLASSA_HOST                   = 0xffffff
	IN_CLASSA_MAX                    = 0x80
	IN_CLASSA_NET                    = 0xff000000
	IN_CLASSA_NSHIFT                 = 0x18
	IN_CLASSB_HOST                   = 0xffff
	IN_CLASSB_MAX                    = 0x10000
	IN_CLASSB_NET                    = 0xffff0000
	IN_CLASSB_NSHIFT                 = 0x10
	IN_CLASSC_HOST                   = 0xff
	IN_CLASSC_NET                    = 0xffffff00
	IN_CLASSC_NSHIFT                 = 0x8
	IN_CLOEXEC                       = 0x80000
	IN_CLOSE                         = 0x18
	IN_CLOSE_NOWRITE                 = 0x10
	IN_CLOSE_WRITE                   = 0x8
	IN_CREATE                        = 0x100
	IN_DELETE                        = 0x200
	IN_DELETE_SELF                   = 0x400
	IN_DONT_FOLLOW                   = 0x2000000
	IN_EXCL_UNLINK                   = 0x4000000
	IN_IGNORED                       = 0x8000
	IN_ISDIR                         = 0x40000000
	IN_LOOPBACKNET                   = 0x7f
	IN_MASK_ADD                      = 0x20000000
	IN_MODIFY                        = 0x2
	IN_MOVE                          = 0xc0
	IN_MOVED_FROM                    = 0x40
	IN_MOVED_TO                      = 0x80
	IN_MOVE_SELF                     = 0x800
	IN_NONBLOCK                      = 0x800
	IN_ONESHOT                       = 0x80000000
	IN_ONLYDIR                       = 0x1000000
	IN_OPEN                          = 0x20
	IN_Q_OVERFLOW                    = 0x4000
	IN_UNMOUNT                       = 0x2000
	IPPROTO_AH                       = 0x33
	IPPROTO_BEETPH                   = 0x5e
	IPPROTO_COMP                     = 0x6c
	IPPROTO_DCCP                     = 0x21
	IPPROTO_DSTOPTS                  = 0x3c
	IPPROTO_EGP                      = 0x8
	IPPROTO_ENCAP                    = 0x62
	IPPROTO_ESP                      = 0x32
	IPPROTO_FRAGMENT                 = 0x2c
	IPPROTO_GRE                      = 0x2f
	IPPROTO_HOPOPTS                  = 0x0
	IPPROTO_ICMP                     = 0x1
	IPPROTO_ICMPV6                   = 0x3a
	IPPROTO_IDP                      = 0x16
	IPPROTO_IGMP                     = 0x2
	IPPROTO_IP                       = 0x0
	IPPROTO_IPIP                     = 0x4
	IPPROTO_IPV6                     = 0x29
	IPPROTO_MH                       = 0x87
	IPPROTO_MPLS                     = 0x89
	IPPROTO_MTP                      = 0x5c
	IPPROTO_NONE                     = 0x3b
	IPPROTO_PIM                      = 0x67
	IPPROTO_PUP                      = 0xc
	IPPROTO_RAW                      = 0xff
	IPPROTO_ROUTING                  = 0x2b
	IPPROTO_RSVP                     = 0x2e
	IPPROTO_SCTP                     = 0x84
	IPPROTO_TCP                      = 0x6
	IPPROTO_TP                       = 0x1d
	IPPROTO_UDP                      = 0x11
	IPPROTO_UDPLITE                  = 0x88
	IPV6_2292DSTOPTS                 = 0x4
	IPV6_2292HOPLIMIT                = 0x8
	IPV6_2292HOPOPTS                 = 0x3
	IPV6_2292PKTINFO                 = 0x2
	IPV6_2292PKTOPTIONS              = 0x6
	IPV6_2292RTHDR                   = 0x5
	IPV6_ADDRFORM                    = 0x1
	IPV6_ADD_MEMBERSHIP              = 0x14
	IPV6_AUTHHDR                     = 0xa
	IPV6_CHECKSUM                    = 0x7
	IPV6_DONTFRAG                    = 0x3e
	IPV6_DROP_MEMBERSHIP             = 0x15
	IPV6_DSTOPTS                     = 0x3b
	IPV6_HDRINCL                     = 0x24
	IPV6_HOPLIMIT                    = 0x34
	IPV6_HOPOPTS                     = 0x36
	IPV6_IPSEC_POLICY                = 0x22
	IPV6_JOIN_ANYCAST                = 0x1b
	IPV6_JOIN_GROUP                  = 0x14
	IPV6_LEAVE_ANYCAST               = 0x1c
	IPV6_LEAVE_GROUP                 = 0x15
	IPV6_MTU                         = 0x18
	IPV6_MTU_DISCOVER                = 0x17
	IPV6_MULTICAST_HOPS              = 0x12
	IPV6_MULTICAST_IF                = 0x11
	IPV6_MULTICAST_LOOP              = 0x13
	IPV6_NEXTHOP                     = 0x9
	IPV6_PATHMTU                     = 0x3d
	IPV6_PKTINFO                     = 0x32
	IPV6_PMTUDISC_DO                 = 0x2
	IPV6_PMTUDISC_DONT               = 0x0
	IPV6_PMTUDISC_INTERFACE          = 0x4
	IPV6_PMTUDISC_OMIT               = 0x5
	IPV6_PMTUDISC_PROBE              = 0x3
	IPV6_PMTUDISC_WANT               = 0x1
	IPV6_RECVDSTOPTS                 = 0x3a
	IPV6_RECVERR                     = 0x19
	IPV6_RECVHOPLIMIT                = 0x33
	IPV6_RECVHOPOPTS                 = 0x35
	IPV6_RECVPATHMTU                 = 0x3c
	IPV6_RECVPKTINFO                 = 0x31
	IPV6_RECVRTHDR                   = 0x38
	IPV6_RECVTCLASS                  = 0x42
	IPV6_ROUTER_ALERT                = 0x16
	IPV6_RTHDR                       = 0x39
	IPV6_RTHDRDSTOPTS                = 0x37
	IPV6_RTHDR_LOOSE                 = 0x0
	IPV6_RTHDR_STRICT                = 0x1
	IPV6_RTHDR_TYPE_0                = 0x0
	IPV6_RXDSTOPTS                   = 0x3b
	IPV6_RXHOPOPTS                   = 0x36
	IPV6_TCLASS                      = 0x43
	IPV6_UNICAST_HOPS                = 0x10
	IPV6_V6ONLY                      = 0x1a
	IPV6_XFRM_POLICY                 = 0x23
	IP_ADD_MEMBERSHIP                = 0x23
	IP_ADD_SOURCE_MEMBERSHIP         = 0x27
	IP_BIND_ADDRESS_NO_PORT          = 0x18
	IP_BLOCK_SOURCE                  = 0x26
	IP_CHECKSUM                      = 0x17
	IP_DEFAULT_MULTICAST_LOOP        = 0x1
	IP_DEFAULT_MULTICAST_TTL         = 0x1
	IP_DF                            = 0x4000
	IP_DROP_MEMBERSHIP               = 0x24
	IP_DROP_SOURCE_MEMBERSHIP        = 0x28
	IP_FREEBIND                      = 0xf
	IP_HDRINCL                       = 0x3
	IP_IPSEC_POLICY                  = 0x10
	IP_MAXPACKET                     = 0xffff
	IP_MAX_MEMBERSHIPS               = 0x14
	IP_MF                            = 0x2000
	IP_MINTTL                        = 0x15
	IP_MSFILTER                      = 0x29
	IP_MSS                           = 0x240
	IP_MTU                           = 0xe
	IP_MTU_DISCOVER                  = 0xa
	IP_MULTICAST_ALL                 = 0x31
	IP_MULTICAST_IF                  = 0x20
	IP_MULTICAST_LOOP                = 0x22
	IP_MULTICAST_TTL                 = 0x21
	IP_NODEFRAG                      = 0x16
	IP_OFFMASK                       = 0x1fff
	IP_OPTIONS                       = 0x4
	IP_ORIGDSTADDR                   = 0x14
	IP_PASSSEC                       = 0x12
	IP_PKTINFO                       = 0x8
	IP_PKTOPTIONS                    = 0x9
	IP_PMTUDISC                      = 0xa
	IP_PMTUDISC_DO                   = 0x2
	IP_PMTUDISC_DONT                 = 0x0
	IP_PMTUDISC_INTERFACE            = 0x4
	IP_PMTUDISC_OMIT                 = 0x5
	IP_PMTUDISC_PROBE                = 0x3
	IP_PMTUDISC_WANT                 = 0x1
	IP_RECVERR                       = 0xb
	IP_RECVOPTS                      = 0x6
	IP_RECVORIGDSTADDR               = 0x14
	IP_RECVRETOPTS                   = 0x7
	IP_RECVTOS                       = 0xd
	IP_RECVTTL                       = 0xc
	IP_RETOPTS                       = 0x7
	IP_RF                            = 0x8000
	IP_ROUTER_ALERT                  = 0x5
	IP_TOS                           = 0x1
	IP_TRANSPARENT                   = 0x13
	IP_TTL                           = 0x2
	IP_UNBLOCK_SOURCE                = 0x25
	IP_UNICAST_IF                    = 0x32
	IP_XFRM_POLICY                   = 0x11
	ISIG                             = 0x1
	ISTRIP                           = 0x20
	IUTF8                            = 0x4000
	IXANY                            = 0x800
	IXOFF                            = 0x1000
	IXON                             = 0x400
	LINUX_REBOOT_CMD_CAD_OFF         = 0x0
	LINUX_REBOOT_CMD_CAD_ON          = 0x89abcdef
	LINUX_REBOOT_CMD_HALT            = 0xcdef0123
	LINUX_REBOOT_CMD_KEXEC           = 0x45584543
	LINUX_REBOOT_CMD_POWER_OFF       = 0x4321fedc
	LINUX_REBOOT_CMD_RESTART         = 0x1234567
	LINUX_REBOOT_CMD_RESTART2        = 0xa1b2c3d4
	LINUX_REBOOT_CMD_SW_SUSPEND      = 0xd000fce2
	LINUX_REBOOT_MAGIC1              = 0xfee1dead
	LINUX_REBOOT_MAGIC2              = 0x28121969
	LOCK_EX                          = 0x2
	LOCK_NB                          = 0x4
	LOCK_SH                          = 0x1
	LOCK_UN                          = 0x8
	MADV_DODUMP                      = 0x11
	MADV_DOFORK                      = 0xb
	MADV_DONTDUMP                    = 0x10
	MADV_DONTFORK                    = 0xa
	MADV_DONTNEED                    = 0x4
	MADV_FREE                        = 0x8
	MADV_HUGEPAGE                    = 0xe
	MADV_HWPOISON                    = 0x64
	MADV_MERGEABLE                   = 0xc
	MADV_NOHUGEPAGE                  = 0xf
	MADV_NORMAL                      = 0x0
	MADV_RANDOM                      = 0x1
	MADV_REMOVE                      = 0x9
	MADV_SEQUENTIAL                  = 0x2
	MADV_UNMERGEABLE                 = 0xd
	MADV_WILLNEED                    = 0x3
	MAP_ANON                         = 0x20
	MAP_ANONYMOUS                    = 0x20
	MAP_DENYWRITE                    = 0x800
	MAP_EXECUTABLE                   = 0x1000
	MAP_FILE                         = 0x0
	MAP_FIXED                        = 0x10
	MAP_GROWSDOWN                    = 0x100
	MAP_HUGETLB                      = 0x40000
	MAP_HUGE_MASK                    = 0x3f
	MAP_HUGE_SHIFT                   = 0x1a
	MAP_LOCKED                       = 0x2000
	MAP_NONBLOCK                     = 0x10000
	MAP_NORESERVE                    = 0x4000
	MAP_POPULATE                     = 0x8000
	MAP_PRIVATE                      = 0x2
	MAP_SHARED                       = 0x1
	MAP_STACK                        = 0x20000
	MAP_TYPE                         = 0xf
	MCL_CURRENT                      = 0x1
	MCL_FUTURE                       = 0x2
	MCL_ONFAULT                      = 0x4
	MNT_DETACH                       = 0x2
	MNT_EXPIRE                       = 0x4
	MNT_FORCE                        = 0x1
	MSG_BATCH                        = 0x40000
	MSG_CMSG_CLOEXEC                 = 0x40000000
	MSG_CONFIRM                      = 0x800
	MSG_CTRUNC                       = 0x8
	MSG_DONTROUTE                    = 0x4
	MSG_DONTWAIT                     = 0x40
	MSG_EOR                          = 0x80
	MSG_ERRQUEUE                     = 0x2000
	MSG_FASTOPEN                     = 0x20000000
	MSG_FIN                          = 0x200
	MSG_MORE                         = 0x8000
	MSG_NOSIGNAL                     = 0x4000
	MSG_OOB                          = 0x1
	MSG_PEEK                         = 0x2
	MSG_PROXY                        = 0x10
	MSG_RST                          = 0x1000
	MSG_SYN                          = 0x400
	MSG_TRUNC                        = 0x20
	MSG_TRYHARD                      = 0x4
	MSG_WAITALL                      = 0x100
	MSG_WAITFORONE                   = 0x10000
	MS_ACTIVE                        = 0x40000000
	MS_ASYNC                         = 0x1
	MS_BIND                          = 0x1000
	MS_DIRSYNC                       = 0x80
	MS_INVALIDATE                    = 0x2
	MS_I_VERSION                     = 0x800000
	MS_KERNMOUNT                     = 0x400000
	MS_LAZYTIME                      = 0x2000000
	MS_MANDLOCK                      = 0x40
	MS_MGC_MSK                       = 0xffff0000
	MS_MGC_VAL                       = 0xc0ed0000
	MS_MOVE                          = 0x2000
	MS_NOATIME                       = 0x400
	MS_NODEV                         = 0x4
	MS_NODIRATIME                    = 0x800
	MS_NOEXEC                        = 0x8
	MS_NOSUID                        = 0x2
	MS_NOUSER                        = -0x80000000
	MS_POSIXACL                      = 0x10000
	MS_PRIVATE                       = 0x40000
	MS_RDONLY                        = 0x1
	MS_REC                           = 0x4000
	MS_RELATIME                      = 0x200000
	MS_REMOUNT                       = 0x20
	MS_RMT_MASK                      = 0x2800051
	MS_SHARED                        = 0x100000
	MS_SILENT                        = 0x8000
	MS_SLAVE                         = 0x80000
	MS_STRICTATIME                   = 0x1000000
	MS_SYNC                          = 0x4
	MS_SYNCHRONOUS                   = 0x10
	MS_UNBINDABLE                    = 0x20000
	NAME_MAX                         = 0xff
	NETLINK_ADD_MEMBERSHIP           = 0x1
	NETLINK_AUDIT                    = 0x9
	NETLINK_BROADCAST_ERROR          = 0x4
	NETLINK_CONNECTOR                = 0xb
	NETLINK_CRYPTO                   = 0x15
	NETLINK_DNRTMSG                  = 0xe
	NETLINK_DROP_MEMBERSHIP          = 0x2
	NETLINK_ECRYPTFS                 = 0x13
	NETLINK_FIB_LOOKUP               = 0xa
	NETLINK_FIREWALL                 = 0x3
	NETLINK_GENERIC                  = 0x10
	NETLINK_INET_DIAG                = 0x4
	NETLINK_IP6_FW                   = 0xd
	NETLINK_ISCSI                    = 0x8
	NETLINK_KOBJECT_UEVENT           = 0xf
	NETLINK_NETFILTER                = 0xc
	NETLINK_NFLOG                    = 0x5
	NETLINK_NO_ENOBUFS               = 0x5
	NETLINK_PKTINFO                  = 0x3
	NETLINK_RDMA                     = 0x14
	NETLINK_ROUTE                    = 0x0
	NETLINK_RX_RING                  = 0x6
	NETLINK_SCSITRANSPORT            = 0x12
	NETLINK_SELINUX                  = 0x7
	NETLINK_SOCK_DIAG                = 0x4
	NETLINK_TX_RING                  = 0x7
	NETLINK_UNUSED                   = 0x1
	NETLINK_USERSOCK                 = 0x2
	NETLINK_XFRM                     = 0x6
	NLA_ALIGNTO                      = 0x4
	NLA_F_NESTED                     = 0x8000
	NLA_F_NET_BYTEORDER              = 0x4000
	NLA_HDRLEN                       = 0x4
	NLMSG_ALIGNTO                    = 0x4
	NLMSG_DONE                       = 0x3
	NLMSG_ERROR                      = 0x2
	NLMSG_HDRLEN                     = 0x10
	NLMSG_MIN_TYPE                   = 0x10
	NLMSG_NOOP                       = 0x1
	NLMSG_OVERRUN                    = 0x4
	NLM_F_ACK                        = 0x4
	NLM_F_APPEND                     = 0x800
	NLM_F_ATOMIC                     = 0x400
	NLM_F_CREATE                     = 0x400
	NLM_F_DUMP                       = 0x300
	NLM_F_DUMP_INTR                  = 0x10
	NLM_F_ECHO                       = 0x8
	NLM_F_EXCL                       = 0x200
	NLM_F_MATCH                      = 0x200
	NLM_F_MULTI                      = 0x2
	NLM_F_REPLACE                    = 0x100
	NLM_F_REQUEST                    = 0x1
	NLM_F_ROOT                       = 0x100
	NOFLSH                           = 0x80
	OCRNL                            = 0x8
	OFDEL                            = 0x80
	OFILL                            = 0x40
	ONLCR                            = 0x4
	ONLRET                           = 0x20
	ONOCR                            = 0x10
	OPOST                            = 0x1
	O_ACCMODE                        = 0x3
	O_APPEND                         = 0x400
	O_ASYNC                          = 0x2000
	O_CLOEXEC                        = 0x80000
	O_CREAT                          = 0x40
	O_DIRECT                         = 0x4000
	O_DIRECTORY                      = 0x10000
	O_DSYNC                          = 0x1000
	O_EXCL                           = 0x80
	O_FSYNC                          = 0x101000
	O_LARGEFILE                      = 0x0
	O_NDELAY                         = 0x800
	O_NOATIME         
"""




```