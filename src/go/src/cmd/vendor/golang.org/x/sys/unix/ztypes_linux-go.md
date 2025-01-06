Response:
The user wants to understand the functionality of the provided Go code snippet. This file seems to define constants and data structures that are used for interacting with the Linux kernel, specifically related to system calls and low-level functionalities.

Here's a breakdown of how to analyze this:

1. **Identify the purpose of the file:** The path `go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go` strongly suggests that this file is part of the `golang.org/x/sys/unix` package and is specific to the Linux operating system. The `ztypes` prefix often indicates auto-generated files containing type definitions.

2. **Analyze the constants:** The `const` declarations define numerical values for various system-level parameters and flags. These can be grouped by their prefixes (e.g., `Sizeof`, `ADJ_`, `STA_`, `TIME_`).

3. **Analyze the types:** The `type` declarations define data structures (structs) that mirror structures used in the Linux kernel. They also define aliases for basic C types.

4. **Look for patterns and groupings:** Notice how constants and types are grouped together based on functionality (e.g., timer-related, network-related, filesystem-related).

5. **Infer the Go functionality:** By examining the defined types and constants, we can deduce which Go packages and functionalities might use these definitions. For example, types like `ItimerSpec` and `Itimerval` are likely related to the `time` package for setting timers. Socket-related types like `RawSockaddrInet4` and `RawSockaddrInet6` are used by the `net` package for low-level network operations. Filesystem types like `Statx_t` are used by functions that interact with the filesystem.

6. **Provide examples:**  Illustrate the usage of these types with Go code snippets. This requires making assumptions about how these types would be used in real-world scenarios.

7. **Consider error-prone areas:** Think about common mistakes developers might make when working with these low-level structures, such as incorrect sizes or misinterpreting flag values.

8. **Summarize the functionality:**  Provide a concise overview of the file's purpose.
Let's break down the functionality of this Go code snippet from `go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go`.

**Core Functionality:**

This Go file defines a collection of **constants and data structures** that directly correspond to types and values used within the Linux kernel's system call interface. It acts as a bridge, allowing Go programs to interact with low-level Linux functionalities.

**Detailed Breakdown:**

* **Size Definitions:** It starts by defining constants representing the size in bytes of fundamental C data types (`short`, `int`, `long long`) and the maximum path length (`PathMax`). These are crucial for memory layout when interacting with C code or the kernel.

* **C Type Aliases:** It defines Go type aliases (`_C_short`, `_C_int`, `_C_long_long`) for corresponding C integer types. This ensures type compatibility when making system calls or interacting with C libraries.

* **System Call Structures:** The majority of the file defines Go structs that directly map to structures used in Linux system calls and kernel interfaces. Examples include:
    * **`ItimerSpec`, `Itimerval`:**  Related to interval timers (like `setitimer`).
    * **`Rlimit`:** Defines resource limits (used with `getrlimit`, `setrlimit`).
    * **`Statx_t`:** Contains extended file status information (used with the `statx` system call).
    * **Socket Address Structures (`RawSockaddrInet4`, `RawSockaddrInet6`, `RawSockaddrUnix`, etc.):**  Represent different types of network addresses.
    * **Netlink Structures (`NlMsghdr`, `RtMsg`, `IfInfomsg`, etc.):** Used for communication with the kernel's netlink interface, often for network configuration and monitoring.
    * **Perf Event Structures (`PerfEventAttr`, `PerfEventMmapPage`):**  Related to the Linux Performance Counters subsystem.
    * **And many more related to specific kernel features like file cloning, filesystem encryption (fscrypt), device mapper (dm), key management (keyctl), etc.**

* **Flag and Constant Definitions:**  Alongside the structures, it defines numerous constants, often as bitmasks or specific values, that are used as arguments or return values in system calls related to the defined structures. These constants control the behavior of system calls or represent specific states or options. For instance, `ADJ_OFFSET`, `STA_PLL`, `TIME_OK` are used with time-related system calls; `POLLIN`, `POLLOUT` are used with the `poll` system call.

**Inferred Go Functionality and Examples:**

This file is fundamental to the `syscall` and `golang.org/x/sys/unix` packages in Go. These packages provide a way to directly invoke Linux system calls from Go code.

**Example: Using `ItimerSpec` for setting an interval timer**

```go
package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	itv := syscall.ItimerSpec{
		Interval: syscall.Timespec{Sec: 1, Nsec: 0},
		Value:    syscall.Timespec{Sec: 1, Nsec: 0},
	}

	// Assume we have a signal handler set up for SIGALRM

	_, _, err := syscall.Syscall6(syscall.SYS_TIMER_SETTIME,
		uintptr(syscall.ITIMER_REAL), // timer type
		uintptr(0),                 // flags (0 for relative timer)
		uintptr(unsafe.Pointer(&itv)),
		uintptr(0), // Old value (can be nil)
		0,
		0)

	if err != 0 {
		fmt.Println("Error setting timer:", err)
		return
	}

	fmt.Println("Timer set. Will trigger SIGALRM every 1 second.")
	time.Sleep(5 * time.Second) // Let the timer run for a while
}

```

**Assumptions and Input/Output:**

* **Input:** The `syscall.ItimerSpec` struct is populated with the desired interval (1 second in this case).
* **Output:**  After running this code, the operating system will send a `SIGALRM` signal to the process every second. You'd typically have a signal handler registered to respond to this signal. The `fmt.Println` statements are for illustrative purposes.

**Example: Using `Statx_t` to get extended file information**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	filename := "test.txt" // Assume this file exists

	var statx syscall.Statx_t

	_, _, err := syscall.Syscall6(syscall.SYS_STATX,
		uintptr(syscall.AT_FDCWD), // Current working directory
		uintptr(unsafe.Pointer(syscall.StringBytePtr(filename))),
		uintptr(0), // Flags (0 for basic stat)
		uintptr(syscall.STATX_ALL), // Mask for all information
		uintptr(unsafe.Pointer(&statx)),
		0)

	if err != 0 {
		fmt.Println("Error getting statx:", err)
		return
	}

	fmt.Printf("File Size: %d bytes\n", statx.Size)
	fmt.Printf("Inode: %d\n", statx.Ino)
	fmt.Printf("Access Time (sec): %d\n", statx.Atime.Sec)
	// ... access other fields of the statx struct
}
```

**Assumptions and Input/Output:**

* **Input:**  The `filename` variable holds the path to the file we want to inspect.
* **Output:** The code will print various attributes of the file, such as its size, inode number, and access time, extracted from the `statx` struct.

**Command-Line Arguments:**

This specific file primarily deals with data structures and constants. It doesn't directly handle command-line arguments. Command-line argument processing would happen in other parts of a Go program that utilizes the functionalities defined here.

**Common User Errors:**

* **Incorrect Sizeof Calculations:** When interacting with system calls or C libraries that expect pointers to specific data structures, providing data with incorrect sizes (e.g., not accounting for padding or using the wrong type) can lead to crashes or unexpected behavior. For example, if you were manually allocating memory for a `RawSockaddrInet4` and used the wrong size, you might have buffer overflows.
* **Misinterpreting Flag Values:**  The numerous constants defined in this file represent flags and options for system calls. Using the wrong flag or misinterpreting its meaning can lead to the system call behaving unexpectedly or returning errors. For instance, incorrectly setting the flags when opening a file could result in the wrong access mode.
* **Endianness Issues (Less Common in Go):** While Go handles endianness relatively transparently, when dealing with low-level structures that might be shared with systems using different endianness, developers need to be aware of potential byte order issues, though this is less of a direct concern with this specific file.
* **Incorrectly Passing Pointers:**  System calls often require pointers to data structures. Passing the wrong type of pointer or a null pointer can lead to segmentation faults.

**Summary of Functionality (Part 1):**

This initial section of `ztypes_linux.go` defines fundamental size constants, C type aliases, and a variety of Go structs that mirror Linux kernel data structures. It also includes constants used as flags and values in conjunction with these structures. Its primary function is to provide the necessary type definitions for Go programs to interact with the Linux kernel's system call interface and low-level functionalities related to timers, resource limits, file information, and the beginning of networking structures.

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共4部分，请归纳一下它的功能

"""
// Code generated by mkmerge; DO NOT EDIT.

//go:build linux

package unix

const (
	SizeofShort    = 0x2
	SizeofInt      = 0x4
	SizeofLongLong = 0x8
	PathMax        = 0x1000
)

type (
	_C_short int16
	_C_int   int32

	_C_long_long int64
)

type ItimerSpec struct {
	Interval Timespec
	Value    Timespec
}

type Itimerval struct {
	Interval Timeval
	Value    Timeval
}

const (
	ADJ_OFFSET            = 0x1
	ADJ_FREQUENCY         = 0x2
	ADJ_MAXERROR          = 0x4
	ADJ_ESTERROR          = 0x8
	ADJ_STATUS            = 0x10
	ADJ_TIMECONST         = 0x20
	ADJ_TAI               = 0x80
	ADJ_SETOFFSET         = 0x100
	ADJ_MICRO             = 0x1000
	ADJ_NANO              = 0x2000
	ADJ_TICK              = 0x4000
	ADJ_OFFSET_SINGLESHOT = 0x8001
	ADJ_OFFSET_SS_READ    = 0xa001
)

const (
	STA_PLL       = 0x1
	STA_PPSFREQ   = 0x2
	STA_PPSTIME   = 0x4
	STA_FLL       = 0x8
	STA_INS       = 0x10
	STA_DEL       = 0x20
	STA_UNSYNC    = 0x40
	STA_FREQHOLD  = 0x80
	STA_PPSSIGNAL = 0x100
	STA_PPSJITTER = 0x200
	STA_PPSWANDER = 0x400
	STA_PPSERROR  = 0x800
	STA_CLOCKERR  = 0x1000
	STA_NANO      = 0x2000
	STA_MODE      = 0x4000
	STA_CLK       = 0x8000
)

const (
	TIME_OK    = 0x0
	TIME_INS   = 0x1
	TIME_DEL   = 0x2
	TIME_OOP   = 0x3
	TIME_WAIT  = 0x4
	TIME_ERROR = 0x5
	TIME_BAD   = 0x5
)

type Rlimit struct {
	Cur uint64
	Max uint64
}

type _Gid_t uint32

type StatxTimestamp struct {
	Sec  int64
	Nsec uint32
	_    int32
}

type Statx_t struct {
	Mask                      uint32
	Blksize                   uint32
	Attributes                uint64
	Nlink                     uint32
	Uid                       uint32
	Gid                       uint32
	Mode                      uint16
	_                         [1]uint16
	Ino                       uint64
	Size                      uint64
	Blocks                    uint64
	Attributes_mask           uint64
	Atime                     StatxTimestamp
	Btime                     StatxTimestamp
	Ctime                     StatxTimestamp
	Mtime                     StatxTimestamp
	Rdev_major                uint32
	Rdev_minor                uint32
	Dev_major                 uint32
	Dev_minor                 uint32
	Mnt_id                    uint64
	Dio_mem_align             uint32
	Dio_offset_align          uint32
	Subvol                    uint64
	Atomic_write_unit_min     uint32
	Atomic_write_unit_max     uint32
	Atomic_write_segments_max uint32
	_                         [1]uint32
	_                         [9]uint64
}

type Fsid struct {
	Val [2]int32
}

type FileCloneRange struct {
	Src_fd      int64
	Src_offset  uint64
	Src_length  uint64
	Dest_offset uint64
}

type RawFileDedupeRange struct {
	Src_offset uint64
	Src_length uint64
	Dest_count uint16
	Reserved1  uint16
	Reserved2  uint32
}

type RawFileDedupeRangeInfo struct {
	Dest_fd       int64
	Dest_offset   uint64
	Bytes_deduped uint64
	Status        int32
	Reserved      uint32
}

const (
	SizeofRawFileDedupeRange     = 0x18
	SizeofRawFileDedupeRangeInfo = 0x20
	FILE_DEDUPE_RANGE_SAME       = 0x0
	FILE_DEDUPE_RANGE_DIFFERS    = 0x1
)

type FscryptPolicy struct {
	Version                   uint8
	Contents_encryption_mode  uint8
	Filenames_encryption_mode uint8
	Flags                     uint8
	Master_key_descriptor     [8]uint8
}

type FscryptKey struct {
	Mode uint32
	Raw  [64]uint8
	Size uint32
}

type FscryptPolicyV1 struct {
	Version                   uint8
	Contents_encryption_mode  uint8
	Filenames_encryption_mode uint8
	Flags                     uint8
	Master_key_descriptor     [8]uint8
}

type FscryptPolicyV2 struct {
	Version                   uint8
	Contents_encryption_mode  uint8
	Filenames_encryption_mode uint8
	Flags                     uint8
	Log2_data_unit_size       uint8
	_                         [3]uint8
	Master_key_identifier     [16]uint8
}

type FscryptGetPolicyExArg struct {
	Size   uint64
	Policy [24]byte
}

type FscryptKeySpecifier struct {
	Type uint32
	_    uint32
	U    [32]byte
}

type FscryptAddKeyArg struct {
	Key_spec FscryptKeySpecifier
	Raw_size uint32
	Key_id   uint32
	_        [8]uint32
}

type FscryptRemoveKeyArg struct {
	Key_spec             FscryptKeySpecifier
	Removal_status_flags uint32
	_                    [5]uint32
}

type FscryptGetKeyStatusArg struct {
	Key_spec     FscryptKeySpecifier
	_            [6]uint32
	Status       uint32
	Status_flags uint32
	User_count   uint32
	_            [13]uint32
}

type DmIoctl struct {
	Version      [3]uint32
	Data_size    uint32
	Data_start   uint32
	Target_count uint32
	Open_count   int32
	Flags        uint32
	Event_nr     uint32
	_            uint32
	Dev          uint64
	Name         [128]byte
	Uuid         [129]byte
	Data         [7]byte
}

type DmTargetSpec struct {
	Sector_start uint64
	Length       uint64
	Status       int32
	Next         uint32
	Target_type  [16]byte
}

type DmTargetDeps struct {
	Count uint32
	_     uint32
}

type DmTargetVersions struct {
	Next    uint32
	Version [3]uint32
}

type DmTargetMsg struct {
	Sector uint64
}

const (
	SizeofDmIoctl      = 0x138
	SizeofDmTargetSpec = 0x28
)

type KeyctlDHParams struct {
	Private int32
	Prime   int32
	Base    int32
}

const (
	FADV_NORMAL     = 0x0
	FADV_RANDOM     = 0x1
	FADV_SEQUENTIAL = 0x2
	FADV_WILLNEED   = 0x3
)

type RawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte /* in_addr */
	Zero   [8]uint8
}

type RawSockaddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte /* in6_addr */
	Scope_id uint32
}

type RawSockaddrUnix struct {
	Family uint16
	Path   [108]int8
}

type RawSockaddrLinklayer struct {
	Family   uint16
	Protocol uint16
	Ifindex  int32
	Hatype   uint16
	Pkttype  uint8
	Halen    uint8
	Addr     [8]uint8
}

type RawSockaddrNetlink struct {
	Family uint16
	Pad    uint16
	Pid    uint32
	Groups uint32
}

type RawSockaddrHCI struct {
	Family  uint16
	Dev     uint16
	Channel uint16
}

type RawSockaddrL2 struct {
	Family      uint16
	Psm         uint16
	Bdaddr      [6]uint8
	Cid         uint16
	Bdaddr_type uint8
	_           [1]byte
}

type RawSockaddrRFCOMM struct {
	Family  uint16
	Bdaddr  [6]uint8
	Channel uint8
	_       [1]byte
}

type RawSockaddrCAN struct {
	Family  uint16
	Ifindex int32
	Addr    [16]byte
}

type RawSockaddrALG struct {
	Family uint16
	Type   [14]uint8
	Feat   uint32
	Mask   uint32
	Name   [64]uint8
}

type RawSockaddrVM struct {
	Family    uint16
	Reserved1 uint16
	Port      uint32
	Cid       uint32
	Flags     uint8
	Zero      [3]uint8
}

type RawSockaddrXDP struct {
	Family         uint16
	Flags          uint16
	Ifindex        uint32
	Queue_id       uint32
	Shared_umem_fd uint32
}

type RawSockaddrPPPoX [0x1e]byte

type RawSockaddrTIPC struct {
	Family   uint16
	Addrtype uint8
	Scope    int8
	Addr     [12]byte
}

type RawSockaddrL2TPIP struct {
	Family  uint16
	Unused  uint16
	Addr    [4]byte /* in_addr */
	Conn_id uint32
	_       [4]uint8
}

type RawSockaddrL2TPIP6 struct {
	Family   uint16
	Unused   uint16
	Flowinfo uint32
	Addr     [16]byte /* in6_addr */
	Scope_id uint32
	Conn_id  uint32
}

type RawSockaddrIUCV struct {
	Family  uint16
	Port    uint16
	Addr    uint32
	Nodeid  [8]int8
	User_id [8]int8
	Name    [8]int8
}

type RawSockaddrNFC struct {
	Sa_family    uint16
	Dev_idx      uint32
	Target_idx   uint32
	Nfc_protocol uint32
}

type _Socklen uint32

type Linger struct {
	Onoff  int32
	Linger int32
}

type IPMreq struct {
	Multiaddr [4]byte /* in_addr */
	Interface [4]byte /* in_addr */
}

type IPMreqn struct {
	Multiaddr [4]byte /* in_addr */
	Address   [4]byte /* in_addr */
	Ifindex   int32
}

type IPv6Mreq struct {
	Multiaddr [16]byte /* in6_addr */
	Interface uint32
}

type PacketMreq struct {
	Ifindex int32
	Type    uint16
	Alen    uint16
	Address [8]uint8
}

type Inet4Pktinfo struct {
	Ifindex  int32
	Spec_dst [4]byte /* in_addr */
	Addr     [4]byte /* in_addr */
}

type Inet6Pktinfo struct {
	Addr    [16]byte /* in6_addr */
	Ifindex uint32
}

type IPv6MTUInfo struct {
	Addr RawSockaddrInet6
	Mtu  uint32
}

type ICMPv6Filter struct {
	Data [8]uint32
}

type Ucred struct {
	Pid int32
	Uid uint32
	Gid uint32
}

type TCPInfo struct {
	State                uint8
	Ca_state             uint8
	Retransmits          uint8
	Probes               uint8
	Backoff              uint8
	Options              uint8
	Rto                  uint32
	Ato                  uint32
	Snd_mss              uint32
	Rcv_mss              uint32
	Unacked              uint32
	Sacked               uint32
	Lost                 uint32
	Retrans              uint32
	Fackets              uint32
	Last_data_sent       uint32
	Last_ack_sent        uint32
	Last_data_recv       uint32
	Last_ack_recv        uint32
	Pmtu                 uint32
	Rcv_ssthresh         uint32
	Rtt                  uint32
	Rttvar               uint32
	Snd_ssthresh         uint32
	Snd_cwnd             uint32
	Advmss               uint32
	Reordering           uint32
	Rcv_rtt              uint32
	Rcv_space            uint32
	Total_retrans        uint32
	Pacing_rate          uint64
	Max_pacing_rate      uint64
	Bytes_acked          uint64
	Bytes_received       uint64
	Segs_out             uint32
	Segs_in              uint32
	Notsent_bytes        uint32
	Min_rtt              uint32
	Data_segs_in         uint32
	Data_segs_out        uint32
	Delivery_rate        uint64
	Busy_time            uint64
	Rwnd_limited         uint64
	Sndbuf_limited       uint64
	Delivered            uint32
	Delivered_ce         uint32
	Bytes_sent           uint64
	Bytes_retrans        uint64
	Dsack_dups           uint32
	Reord_seen           uint32
	Rcv_ooopack          uint32
	Snd_wnd              uint32
	Rcv_wnd              uint32
	Rehash               uint32
	Total_rto            uint16
	Total_rto_recoveries uint16
	Total_rto_time       uint32
}

type TCPVegasInfo struct {
	Enabled uint32
	Rttcnt  uint32
	Rtt     uint32
	Minrtt  uint32
}

type TCPDCTCPInfo struct {
	Enabled  uint16
	Ce_state uint16
	Alpha    uint32
	Ab_ecn   uint32
	Ab_tot   uint32
}

type TCPBBRInfo struct {
	Bw_lo       uint32
	Bw_hi       uint32
	Min_rtt     uint32
	Pacing_gain uint32
	Cwnd_gain   uint32
}

type CanFilter struct {
	Id   uint32
	Mask uint32
}

type TCPRepairOpt struct {
	Code uint32
	Val  uint32
}

const (
	SizeofSockaddrInet4     = 0x10
	SizeofSockaddrInet6     = 0x1c
	SizeofSockaddrAny       = 0x70
	SizeofSockaddrUnix      = 0x6e
	SizeofSockaddrLinklayer = 0x14
	SizeofSockaddrNetlink   = 0xc
	SizeofSockaddrHCI       = 0x6
	SizeofSockaddrL2        = 0xe
	SizeofSockaddrRFCOMM    = 0xa
	SizeofSockaddrCAN       = 0x18
	SizeofSockaddrALG       = 0x58
	SizeofSockaddrVM        = 0x10
	SizeofSockaddrXDP       = 0x10
	SizeofSockaddrPPPoX     = 0x1e
	SizeofSockaddrTIPC      = 0x10
	SizeofSockaddrL2TPIP    = 0x10
	SizeofSockaddrL2TPIP6   = 0x20
	SizeofSockaddrIUCV      = 0x20
	SizeofSockaddrNFC       = 0x10
	SizeofLinger            = 0x8
	SizeofIPMreq            = 0x8
	SizeofIPMreqn           = 0xc
	SizeofIPv6Mreq          = 0x14
	SizeofPacketMreq        = 0x10
	SizeofInet4Pktinfo      = 0xc
	SizeofInet6Pktinfo      = 0x14
	SizeofIPv6MTUInfo       = 0x20
	SizeofICMPv6Filter      = 0x20
	SizeofUcred             = 0xc
	SizeofTCPInfo           = 0xf8
	SizeofTCPCCInfo         = 0x14
	SizeofCanFilter         = 0x8
	SizeofTCPRepairOpt      = 0x8
)

const (
	NDA_UNSPEC         = 0x0
	NDA_DST            = 0x1
	NDA_LLADDR         = 0x2
	NDA_CACHEINFO      = 0x3
	NDA_PROBES         = 0x4
	NDA_VLAN           = 0x5
	NDA_PORT           = 0x6
	NDA_VNI            = 0x7
	NDA_IFINDEX        = 0x8
	NDA_MASTER         = 0x9
	NDA_LINK_NETNSID   = 0xa
	NDA_SRC_VNI        = 0xb
	NTF_USE            = 0x1
	NTF_SELF           = 0x2
	NTF_MASTER         = 0x4
	NTF_PROXY          = 0x8
	NTF_EXT_LEARNED    = 0x10
	NTF_OFFLOADED      = 0x20
	NTF_ROUTER         = 0x80
	NUD_INCOMPLETE     = 0x1
	NUD_REACHABLE      = 0x2
	NUD_STALE          = 0x4
	NUD_DELAY          = 0x8
	NUD_PROBE          = 0x10
	NUD_FAILED         = 0x20
	NUD_NOARP          = 0x40
	NUD_PERMANENT      = 0x80
	NUD_NONE           = 0x0
	IFA_UNSPEC         = 0x0
	IFA_ADDRESS        = 0x1
	IFA_LOCAL          = 0x2
	IFA_LABEL          = 0x3
	IFA_BROADCAST      = 0x4
	IFA_ANYCAST        = 0x5
	IFA_CACHEINFO      = 0x6
	IFA_MULTICAST      = 0x7
	IFA_FLAGS          = 0x8
	IFA_RT_PRIORITY    = 0x9
	IFA_TARGET_NETNSID = 0xa
	RT_SCOPE_UNIVERSE  = 0x0
	RT_SCOPE_SITE      = 0xc8
	RT_SCOPE_LINK      = 0xfd
	RT_SCOPE_HOST      = 0xfe
	RT_SCOPE_NOWHERE   = 0xff
	RT_TABLE_UNSPEC    = 0x0
	RT_TABLE_COMPAT    = 0xfc
	RT_TABLE_DEFAULT   = 0xfd
	RT_TABLE_MAIN      = 0xfe
	RT_TABLE_LOCAL     = 0xff
	RT_TABLE_MAX       = 0xffffffff
	RTA_UNSPEC         = 0x0
	RTA_DST            = 0x1
	RTA_SRC            = 0x2
	RTA_IIF            = 0x3
	RTA_OIF            = 0x4
	RTA_GATEWAY        = 0x5
	RTA_PRIORITY       = 0x6
	RTA_PREFSRC        = 0x7
	RTA_METRICS        = 0x8
	RTA_MULTIPATH      = 0x9
	RTA_FLOW           = 0xb
	RTA_CACHEINFO      = 0xc
	RTA_TABLE          = 0xf
	RTA_MARK           = 0x10
	RTA_MFC_STATS      = 0x11
	RTA_VIA            = 0x12
	RTA_NEWDST         = 0x13
	RTA_PREF           = 0x14
	RTA_ENCAP_TYPE     = 0x15
	RTA_ENCAP          = 0x16
	RTA_EXPIRES        = 0x17
	RTA_PAD            = 0x18
	RTA_UID            = 0x19
	RTA_TTL_PROPAGATE  = 0x1a
	RTA_IP_PROTO       = 0x1b
	RTA_SPORT          = 0x1c
	RTA_DPORT          = 0x1d
	RTN_UNSPEC         = 0x0
	RTN_UNICAST        = 0x1
	RTN_LOCAL          = 0x2
	RTN_BROADCAST      = 0x3
	RTN_ANYCAST        = 0x4
	RTN_MULTICAST      = 0x5
	RTN_BLACKHOLE      = 0x6
	RTN_UNREACHABLE    = 0x7
	RTN_PROHIBIT       = 0x8
	RTN_THROW          = 0x9
	RTN_NAT            = 0xa
	RTN_XRESOLVE       = 0xb
	SizeofNlMsghdr     = 0x10
	SizeofNlMsgerr     = 0x14
	SizeofRtGenmsg     = 0x1
	SizeofNlAttr       = 0x4
	SizeofRtAttr       = 0x4
	SizeofIfInfomsg    = 0x10
	SizeofIfAddrmsg    = 0x8
	SizeofIfaCacheinfo = 0x10
	SizeofRtMsg        = 0xc
	SizeofRtNexthop    = 0x8
	SizeofNdUseroptmsg = 0x10
	SizeofNdMsg        = 0xc
)

type NlMsghdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

type NlMsgerr struct {
	Error int32
	Msg   NlMsghdr
}

type RtGenmsg struct {
	Family uint8
}

type NlAttr struct {
	Len  uint16
	Type uint16
}

type RtAttr struct {
	Len  uint16
	Type uint16
}

type IfInfomsg struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

type IfAddrmsg struct {
	Family    uint8
	Prefixlen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

type IfaCacheinfo struct {
	Prefered uint32
	Valid    uint32
	Cstamp   uint32
	Tstamp   uint32
}

type RtMsg struct {
	Family   uint8
	Dst_len  uint8
	Src_len  uint8
	Tos      uint8
	Table    uint8
	Protocol uint8
	Scope    uint8
	Type     uint8
	Flags    uint32
}

type RtNexthop struct {
	Len     uint16
	Flags   uint8
	Hops    uint8
	Ifindex int32
}

type NdUseroptmsg struct {
	Family    uint8
	Pad1      uint8
	Opts_len  uint16
	Ifindex   int32
	Icmp_type uint8
	Icmp_code uint8
	Pad2      uint16
	Pad3      uint32
}

type NdMsg struct {
	Family  uint8
	Pad1    uint8
	Pad2    uint16
	Ifindex int32
	State   uint16
	Flags   uint8
	Type    uint8
}

const (
	ICMP_FILTER = 0x1

	ICMPV6_FILTER             = 0x1
	ICMPV6_FILTER_BLOCK       = 0x1
	ICMPV6_FILTER_BLOCKOTHERS = 0x3
	ICMPV6_FILTER_PASS        = 0x2
	ICMPV6_FILTER_PASSONLY    = 0x4
)

const (
	SizeofSockFilter = 0x8
)

type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type SockFprog struct {
	Len    uint16
	Filter *SockFilter
}

type InotifyEvent struct {
	Wd     int32
	Mask   uint32
	Cookie uint32
	Len    uint32
}

const SizeofInotifyEvent = 0x10

const SI_LOAD_SHIFT = 0x10

type Utsname struct {
	Sysname    [65]byte
	Nodename   [65]byte
	Release    [65]byte
	Version    [65]byte
	Machine    [65]byte
	Domainname [65]byte
}

const (
	AT_EMPTY_PATH   = 0x1000
	AT_FDCWD        = -0x64
	AT_NO_AUTOMOUNT = 0x800
	AT_REMOVEDIR    = 0x200

	AT_STATX_SYNC_AS_STAT = 0x0
	AT_STATX_FORCE_SYNC   = 0x2000
	AT_STATX_DONT_SYNC    = 0x4000

	AT_RECURSIVE = 0x8000

	AT_SYMLINK_FOLLOW   = 0x400
	AT_SYMLINK_NOFOLLOW = 0x100

	AT_EACCESS = 0x200

	OPEN_TREE_CLONE = 0x1

	MOVE_MOUNT_F_SYMLINKS   = 0x1
	MOVE_MOUNT_F_AUTOMOUNTS = 0x2
	MOVE_MOUNT_F_EMPTY_PATH = 0x4
	MOVE_MOUNT_T_SYMLINKS   = 0x10
	MOVE_MOUNT_T_AUTOMOUNTS = 0x20
	MOVE_MOUNT_T_EMPTY_PATH = 0x40
	MOVE_MOUNT_SET_GROUP    = 0x100

	FSOPEN_CLOEXEC = 0x1

	FSPICK_CLOEXEC          = 0x1
	FSPICK_SYMLINK_NOFOLLOW = 0x2
	FSPICK_NO_AUTOMOUNT     = 0x4
	FSPICK_EMPTY_PATH       = 0x8

	FSMOUNT_CLOEXEC = 0x1

	FSCONFIG_SET_FLAG        = 0x0
	FSCONFIG_SET_STRING      = 0x1
	FSCONFIG_SET_BINARY      = 0x2
	FSCONFIG_SET_PATH        = 0x3
	FSCONFIG_SET_PATH_EMPTY  = 0x4
	FSCONFIG_SET_FD          = 0x5
	FSCONFIG_CMD_CREATE      = 0x6
	FSCONFIG_CMD_RECONFIGURE = 0x7
)

type OpenHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

const SizeofOpenHow = 0x18

const (
	RESOLVE_BENEATH       = 0x8
	RESOLVE_IN_ROOT       = 0x10
	RESOLVE_NO_MAGICLINKS = 0x2
	RESOLVE_NO_SYMLINKS   = 0x4
	RESOLVE_NO_XDEV       = 0x1
)

type PollFd struct {
	Fd      int32
	Events  int16
	Revents int16
}

const (
	POLLIN   = 0x1
	POLLPRI  = 0x2
	POLLOUT  = 0x4
	POLLERR  = 0x8
	POLLHUP  = 0x10
	POLLNVAL = 0x20
)

type sigset_argpack struct {
	ss    *Sigset_t
	ssLen uintptr
}

type SignalfdSiginfo struct {
	Signo     uint32
	Errno     int32
	Code      int32
	Pid       uint32
	Uid       uint32
	Fd        int32
	Tid       uint32
	Band      uint32
	Overrun   uint32
	Trapno    uint32
	Status    int32
	Int       int32
	Ptr       uint64
	Utime     uint64
	Stime     uint64
	Addr      uint64
	Addr_lsb  uint16
	_         uint16
	Syscall   int32
	Call_addr uint64
	Arch      uint32
	_         [28]uint8
}

type Winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

const (
	TASKSTATS_CMD_UNSPEC                  = 0x0
	TASKSTATS_CMD_GET                     = 0x1
	TASKSTATS_CMD_NEW                     = 0x2
	TASKSTATS_TYPE_UNSPEC                 = 0x0
	TASKSTATS_TYPE_PID                    = 0x1
	TASKSTATS_TYPE_TGID                   = 0x2
	TASKSTATS_TYPE_STATS                  = 0x3
	TASKSTATS_TYPE_AGGR_PID               = 0x4
	TASKSTATS_TYPE_AGGR_TGID              = 0x5
	TASKSTATS_TYPE_NULL                   = 0x6
	TASKSTATS_CMD_ATTR_UNSPEC             = 0x0
	TASKSTATS_CMD_ATTR_PID                = 0x1
	TASKSTATS_CMD_ATTR_TGID               = 0x2
	TASKSTATS_CMD_ATTR_REGISTER_CPUMASK   = 0x3
	TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK = 0x4
)

type CGroupStats struct {
	Sleeping        uint64
	Running         uint64
	Stopped         uint64
	Uninterruptible uint64
	Io_wait         uint64
}

const (
	CGROUPSTATS_CMD_UNSPEC        = 0x3
	CGROUPSTATS_CMD_GET           = 0x4
	CGROUPSTATS_CMD_NEW           = 0x5
	CGROUPSTATS_TYPE_UNSPEC       = 0x0
	CGROUPSTATS_TYPE_CGROUP_STATS = 0x1
	CGROUPSTATS_CMD_ATTR_UNSPEC   = 0x0
	CGROUPSTATS_CMD_ATTR_FD       = 0x1
)

type Genlmsghdr struct {
	Cmd      uint8
	Version  uint8
	Reserved uint16
}

const (
	CTRL_CMD_UNSPEC            = 0x0
	CTRL_CMD_NEWFAMILY         = 0x1
	CTRL_CMD_DELFAMILY         = 0x2
	CTRL_CMD_GETFAMILY         = 0x3
	CTRL_CMD_NEWOPS            = 0x4
	CTRL_CMD_DELOPS            = 0x5
	CTRL_CMD_GETOPS            = 0x6
	CTRL_CMD_NEWMCAST_GRP      = 0x7
	CTRL_CMD_DELMCAST_GRP      = 0x8
	CTRL_CMD_GETMCAST_GRP      = 0x9
	CTRL_CMD_GETPOLICY         = 0xa
	CTRL_ATTR_UNSPEC           = 0x0
	CTRL_ATTR_FAMILY_ID        = 0x1
	CTRL_ATTR_FAMILY_NAME      = 0x2
	CTRL_ATTR_VERSION          = 0x3
	CTRL_ATTR_HDRSIZE          = 0x4
	CTRL_ATTR_MAXATTR          = 0x5
	CTRL_ATTR_OPS              = 0x6
	CTRL_ATTR_MCAST_GROUPS     = 0x7
	CTRL_ATTR_POLICY           = 0x8
	CTRL_ATTR_OP_POLICY        = 0x9
	CTRL_ATTR_OP               = 0xa
	CTRL_ATTR_OP_UNSPEC        = 0x0
	CTRL_ATTR_OP_ID            = 0x1
	CTRL_ATTR_OP_FLAGS         = 0x2
	CTRL_ATTR_MCAST_GRP_UNSPEC = 0x0
	CTRL_ATTR_MCAST_GRP_NAME   = 0x1
	CTRL_ATTR_MCAST_GRP_ID     = 0x2
	CTRL_ATTR_POLICY_UNSPEC    = 0x0
	CTRL_ATTR_POLICY_DO        = 0x1
	CTRL_ATTR_POLICY_DUMP      = 0x2
	CTRL_ATTR_POLICY_DUMP_MAX  = 0x2
)

const (
	_CPU_SETSIZE = 0x400
)

const (
	BDADDR_BREDR     = 0x0
	BDADDR_LE_PUBLIC = 0x1
	BDADDR_LE_RANDOM = 0x2
)

type PerfEventAttr struct {
	Type               uint32
	Size               uint32
	Config             uint64
	Sample             uint64
	Sample_type        uint64
	Read_format        uint64
	Bits               uint64
	Wakeup             uint32
	Bp_type            uint32
	Ext1               uint64
	Ext2               uint64
	Branch_sample_type uint64
	Sample_regs_user   uint64
	Sample_stack_user  uint32
	Clockid            int32
	Sample_regs_intr   uint64
	Aux_watermark      uint32
	Sample_max_stack   uint16
	_                  uint16
	Aux_sample_size    uint32
	_                  uint32
	Sig_data           uint64
}

type PerfEventMmapPage struct {
	Version        uint32
	Compat_version uint32
	Lock           uint32
	Index          uint32
	Offset         int64
	Time_enabled   uint64
	Time_running   uint64
	Capabilities   uint64
	Pmc_width      uint16
	Time_shift     uint16
	Time_mult      uint32
	Time_offset    uint64
	Time_zero      uint64
	Size           uint32
	_              uint32
	Time_cycles    uint64
	Time_mask      uint64
	_              [928]uint8
	Data_head      uint64
	Data_tail      uint64
	Data_offset    uint64
	Data_size      uint64
	Aux_head       uint64
	Aux_tail       uint64
	Aux_offset     uint64
	Aux_size       uint64
}

const (
	PerfBitDisabled               uint64 = CBitFieldMaskBit0
	PerfBitInherit                       = CBitFieldMaskBit1
	PerfBitPinned                        = CBitFieldMaskBit2
	PerfBitExclusive                     = CBitFieldMaskBit3
	PerfBitExcludeUser                   = CBitFieldMaskBit4
	PerfBitExcludeKernel                 = CBitFieldMaskBit5
	PerfBitExcludeHv                     = CBitFieldMaskBit6
	PerfBitExcludeIdle                   = CBitFieldMaskBit7
	PerfBitMmap                          = CBitFieldMaskBit8
	PerfBitComm                          = CBitFieldMaskBit9
	PerfBitFreq                          = CBitFieldMaskBit10
	PerfBitInheritStat                   = CBitFieldMaskBit11
	PerfBitEnableOnExec                  = CBitFieldMaskBit12
	PerfBitTask                          = CBitFieldMaskBit13
	PerfBitWatermark                     = CBitFieldMaskBit14
	PerfBitPreciseIPBit1                 = CBitFieldMaskBit15
	PerfBitPreciseIPBit2                 = CBitFieldMaskBit16
	PerfBitMmapData                      = CBitFieldMaskBit17
	PerfBitSampleIDAll                   = CBitFieldMaskBit18
	PerfBitExcludeHost                   = CBitFieldMaskBit19
	PerfBitExcludeGuest                  = CBitFieldMaskBit20
	PerfBitExcludeCallchainKernel        = CBitFieldMaskBit21
	PerfBitExcludeCallchainUser          = CBitFieldMaskBit22
	PerfBitMmap2                         = CBitFieldMaskBit23
	PerfBitCommExec                      = CBitFieldMaskBit24
	PerfBitUseClockID                    = CBitFieldMaskBit25
	PerfBitContextSwitch                 = CBitFieldMaskBit26
	PerfBitWriteBackward                 = CBitFieldMaskBit27
)

const (
	PERF_TYPE_HARDWARE                    = 0x0
	PERF_TYPE_SOFTWARE                    = 0x1
	PERF_TYPE_TRACEPOINT                  = 0x2
	PERF_TYPE_HW_CACHE                    = 0x3
	PERF_TYPE_RAW                         = 0x4
	PERF_TYPE_BREAKPOINT                  = 0x5
	PERF_TYPE_MAX                         = 0x6
	PERF_COUNT_HW_CPU_CYCLES              = 0x0
	PERF_COUNT_HW_INSTRUCTIONS            = 0x1
	PERF_COUNT_HW_CACHE_REFERENCES        = 0x2
	PERF_COUNT_HW_CACHE_MISSES            = 0x3
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS     = 0x4
	PERF_COUNT_HW_BRANCH_MISSES           = 0x5
	PERF_COUNT_HW_BUS_CYCLES              = 0x6
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 0x7
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND  = 0x8
	PERF_COUNT_HW_REF_CPU_CYCLES          = 0x9
	PERF_COUNT_HW_MAX                     = 0xa
	PERF_COUNT_HW_CACHE_L1D               = 0x0
	PERF_COUNT_HW_CACHE_L1I               = 0x1
	PERF_COUNT_HW_CACHE_LL                = 0x2
	PERF_COUNT_HW_CACHE_DTLB              = 0x3
	PERF_COUNT_HW_CACHE_ITLB              = 0x4
	PERF_COUNT_HW_CACHE_BPU               = 0x5
	PERF_COUNT_HW_CACHE_NODE              = 0x6
	PERF_COUNT_HW_CACHE_MAX               = 0x7
	PERF_COUNT_HW_CACHE_OP_READ           = 0x0
	PERF_COUNT_HW_CACHE_OP_WRITE          = 0x1
	PERF_COUNT_HW_CACHE_OP_PREFETCH       = 0x2
	PERF_COUNT_HW_CACHE_OP_MAX            = 0x3
	PERF_COUNT_HW_CACHE_RESULT_ACCESS     = 0x0
	PERF_COUNT_HW_CACHE_RESULT_MISS       = 0x1
	PERF_COUNT_HW_CACHE_RESULT_MAX        = 0x2
	PERF_COUNT_SW_CPU_CLOCK               = 0x0
	PERF_COUNT_SW_TASK_CLOCK              = 0x1
	PERF_COUNT_SW_PAGE_FAULTS             = 0x2
	PERF_COUNT_SW_CONTEXT_SWITCHES        = 0x3
	PERF_COUNT_SW_CPU_MIGRATIONS          = 0x4
	PERF_COUNT_SW_PAGE_FAULTS_MIN         = 0x5
	PERF_COUNT_SW_PAGE_FAULTS_MAJ         = 0x6
	PERF_COUNT_SW_ALIGNMENT_FAULTS        = 0x7
	PERF_COUNT_SW_EMULATION_FAULTS        = 0x8
	PERF_COUNT_SW_DUMMY                   = 0x9
	PERF_COUNT_SW_BPF_OUTPUT              = 0xa
	PERF_COUNT_SW_MAX                     = 0xc
	PERF_SAMPLE_IP                        = 0x1
	PERF_SAMPLE_TID                       = 0x2
	PERF_SAMPLE_TIME                      = 0x4
	PERF_SAMPLE_ADDR                      = 0x8
	PERF_SAMPLE_READ                      = 0x10
	PERF_SAMPLE_CALLCHAIN                 = 0x20
	PERF_SAMPLE_ID                        = 0x40
	PERF_SAMPLE_CPU                       = 0x80
	PERF_SAMPLE_PERIOD                    = 0x100
	PERF_SAMPLE_STREAM_ID                 = 0x200
	PERF_SAMPLE_RAW                       = 0x400
	PERF_SAMPLE_BRANCH_STACK              = 0x800
	PERF_SAMPLE_REGS_USER                 = 0x1000
	PERF_SAMPLE_STACK_USER                = 0x2000
	PERF_SAMPLE_WEIGHT                    = 0x4000
	PERF_SAMPLE_DATA_SRC                  = 0x8000
	PERF_SAMPLE_IDENTIFIER                = 0x10000
	PERF_SAMPLE_TRANSACTION               = 0x20000
	PERF_SAMPLE_REGS_INTR                 = 0x40000
	PERF_SAMPLE_PHYS_ADDR                 = 0x80000
	PERF_SAMPLE_AUX                       = 0x100000
	PERF_SAMPLE_CGROUP                    = 0x200000
	PERF_SAMPLE_DATA_PAGE_SIZE            = 0x400000
	PERF_SAMPLE_CODE_PAGE_SIZE            = 0x800000
	PERF_SAMPLE_WEIGHT_STRUCT             = 0x1000000
	PERF_SAMPLE_MAX                       = 0x2000000
	PERF_SAMPLE_BRANCH_USER_SHIFT         = 0x0
	PERF_SAMPLE_BRANCH_KERNEL_SHIFT       = 0x1
	PERF_SAMPLE_BRANCH_HV_SHIFT           = 0x2
	PERF_SAMPLE_BRANCH_ANY_SHIFT          = 0x3
	PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT     = 0x4
	PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT   = 0x5
	PERF_SAMPLE_BRANCH_IND_CALL_SHIFT     = 0x6
	PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT     = 0x7
	PERF_SAMPLE_BRANCH_IN_TX_SHIFT        = 0x8
	PERF_SAMPLE_BRANCH_NO_TX_SHIFT        = 0x9
	PERF_SAMPLE_BRANCH_COND_SHIFT         = 0xa
	PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT   = 0xb
	PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT     = 0xc
	PERF_SAMPLE_BRANCH_CALL_SHIFT         = 0xd
	PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT     = 0xe
	PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT    = 0xf
	PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT    = 0x10
	PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT     = 0x11
	PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT    = 0x12
	PERF_SAMPLE_BRANCH_COUNTERS           = 0x80000
	PERF_SAMPLE_BRANCH_MAX_SHIFT          = 0x14
	PERF_SAMPLE_BRANCH_USER               = 0x1
	PERF_SAMPLE_BRANCH_KERNEL             = 0x2
	PERF_SAMPLE_BRANCH_HV                 = 0x4
	PERF_SAMPLE_BRANCH_ANY                = 0x8
	PERF_SAMPLE_BRANCH_ANY_CALL           = 0x10
	PERF_SAMPLE_BRANCH_ANY_RETURN         = 0x20
	PERF_SAMPLE_BRANCH_IND_CALL           = 0x40
	PERF_SAMPLE_BRANCH_ABORT_TX           = 0x80
	PERF_SAMPLE_BRANCH_IN_TX              = 0x100
	PERF_SAMPLE_BRANCH_NO_TX              = 0x200
	PERF_SAMPLE_BRANCH_COND               = 0x400
	PERF_SAMPLE_BRANCH_CALL_STACK         = 0x800
	PERF_SAMPLE_BRANCH_IND_JUMP           = 0x1000
	PERF_SAMPLE_BRANCH_CALL               = 0x2000
	PERF_SAMPLE_BRANCH_NO_FLAGS           = 0x4000
	PERF_SAMPLE_BRANCH_NO_CYCLES          = 0x8000
	PERF_SAMPLE_BRANCH_TYPE_SAVE          = 0x10000
	PERF_SAMPLE_BRANCH_HW_INDEX           = 0x20000
	PERF_SAMPLE_BRANCH_PRIV_SAVE          = 0x40000
	PERF_SAMPLE_BRANCH_MAX                = 0x100000
	PERF_BR_UNKNOWN                       = 0x0
	PERF_BR_COND                          = 0x1
	PERF_BR_UNCOND                        = 0x2
	PERF_BR_IND                           = 0x3
	PERF_BR_CALL                          = 0x4
	PERF_BR_IND_CALL                      = 0x5
	PERF_BR_RET                           = 0x6
	PERF_BR_SYSCALL                       = 0x7
	PERF_BR_SYSRET                        = 0x8
	PERF_BR_COND_CALL                     = 0x9
	PERF_BR_COND_RET                      = 0xa
	PERF_BR_ERET                          = 0xb
	PERF_BR_IRQ                           = 0xc
	PERF_BR_SERROR                        = 0xd
	PERF_BR_NO_TX                         = 0xe
	PERF_BR_EXTEND_ABI                    = 0xf
	PERF_BR_MAX                           = 0x10
	PERF_SAMPLE_REGS_ABI_NONE             = 0x0
	PERF_SAMPLE_REGS_ABI_32               = 0x1
	PERF_SAMPLE_REGS_ABI_64               = 0x2
	PERF_TXN_ELISION                      = 0x1
	PERF_TXN_TRANSACTION                  = 0x2
	PERF_TXN_SYNC                         = 0x4
	PERF_TXN_ASYNC                        = 0x8
	PERF_TXN_RETRY                        = 0x10
	PERF_TXN_CONFLICT                     = 0x20
	PERF_TXN_CAPACITY_WRITE               = 0x40
	PERF_TXN_CAPACITY_READ                = 0x80
	PERF_TXN_MAX                          = 0x100
	PERF_TXN_ABORT_MASK                   = -0x100000000
	PERF_TXN_ABORT_SHIFT                  = 0x20
	PERF_FORMAT_TOTAL_TIME_ENABLED        = 0x1
	PERF_FORMAT_TOTAL_TIME_RUNNING        = 0x2
	PERF_FORMAT_ID                        = 0x4
	PERF_FORMAT_GROUP                     = 0x8
	PERF_FORMAT_LOST                      = 0x10
	PERF_FORMAT_MAX                       = 0x20
	PERF_IOC_FLAG_GROUP                   = 0x1
	PERF_RECORD_MMAP                      = 0x1
	PERF_RECORD_LOST                      = 0x2
	PERF_RECORD_COMM                      = 0x3
	PERF_RECORD_EXIT                      = 0x4
	PERF_RECORD_THROTTLE                  = 0x5
	PERF_RECORD_UNTHROTTLE                = 0x6
	PERF_RECORD_FORK                      = 0x7
	PERF_RECORD_READ                      = 0x8
	PERF_RECORD_SAMPLE                    = 0x9
	PERF_RECORD_MMAP2                     = 0xa
	PERF_RECORD_AUX                       = 0xb
	PERF_RECORD_ITRACE_START              = 0xc
	PERF_RECORD_LOST_SAMPLES              = 0xd
	PERF_RECORD_SWITCH                    = 0xe
	PERF_RECORD_SWITCH_CPU_WIDE           = 0xf
	PERF_RECORD_NAMESPACES                = 0x10
	PERF_RECORD_KSYMBOL                   = 0x11
	PERF_RECORD_BPF_EVENT                 = 0x12
	PERF_RECORD_CGROUP                    = 0x13
	PERF_RECORD_TEXT_POKE                 = 0x14
	PERF_RECORD_AUX_OUTPUT_HW_ID          = 0x15
	PERF_RECORD_MAX                       = 0x16
	PERF_RECORD_KSYMBOL_TYPE_UNKNOWN      = 0x0
	PERF_RECORD_KSYMBOL_TYPE_BPF          = 0x1
	PERF_RECORD_KSYMBOL_TYPE_OOL          = 0x2
	PERF_RECORD_KSYMBOL_TYPE_MAX          = 0x3
	PERF_BPF_EVENT_UNKNOWN                = 0x0
	PERF_BPF_EVENT_PROG_LOAD              = 0x1
	PERF_BPF_EVENT_PROG_UNLOAD            = 0x2
	PERF_BPF_EVENT_MAX                    = 0x3
	PERF_CONTEXT_HV                       = -0x20
	PERF_CONTEXT_KERNEL                   = -0x80
	PERF_CONTEXT_USER                     = -0x200
	PERF_CONTEXT_GUEST                    = -0x800
	PERF_CONTEXT_GUEST_KERNEL             = -0x880
	PERF_CONTEXT_GUEST_USER               = -0xa00
	PERF_CONTEXT_MAX                      = -0xfff
)

type TCPMD5Sig struct {
	Addr      SockaddrStorage
	Flags     uint8
	Prefixlen uint8
	Keylen    uint16
	Ifindex   int32
	Key       [80]uint8
}

type HDDriveCmdHdr struct {
	Command uint8
	Number  uint8
	Feature uint8
	Count   uint8
}

type HDDriveID struct {
	Config         uint16
	Cyls           uint16
	Reserved2      uint16
	Heads          uint16
	Track_bytes    uint16
	Sector_bytes   uint16
	Sectors        uint16
	Vendor0        uint16
	Vendor1        uint16
	Vendor2        uint16
	Serial_no      [20]uint8
	Buf_type       uint16
	Buf_size       uint16
	Ecc_bytes      uint16
	Fw_rev         [8]uint8
	Model          [40]uint8
	Max_multsect   uint8
	Vendor3        uint8
	Dword_io       uint16
	Vendor4        uint8
	Capability     uint8
	Reserved50     uint16
	Vendor5        uint8
	TPIO           uint8
	Vendor6        uint8
	TDMA           uint8
	Field_valid    uint16
	Cur_cyls       uint16
	Cur_heads      uint16
	Cur_sectors    uint16
	Cur_capacity0  uint16
	Cur_capacity1  uint16
	Multsect       uint8
	Multsect_valid uint8
	Lba_capacity   uint32
	Dma_1word      uint16
	Dma_mword      uint16
	Eide_pio_modes uint16
	Eide_dma_min   uint16
	Eide_dma_time  uint16
	Eide_pio       uint16
	Eide_pio_iordy uint16
	Words69_70     [2]uint16
	Words71_74     [4]uint16
	Queue_depth    uint16
	Words76_79     [4]uint16
	Major_rev_num  uint16
	Minor_rev_num  uint16
	Command_set_1  uint16
	Command_set_2  uint16
	Cfsse          uint16
	Cfs_enable_1   uint16
	Cfs_enable_2   uint16
	Csf_default    uint16
	Dma_ultra      uint16
	Trseuc         uint16
	TrsEuc         uint16
	CurAPMvalues   uint16
	Mprc           uint16
	Hw_config      uint16
	Acoustic       uint16
	Msrqs          uint16
	Sxfert         uint16
	Sal            uint16
	Spg            uint32
	Lba_capacity_2 uint64
	Words104_125   [22]uint16
	Last_lun       uint16
	Word127        uint16
	Dlf            uint16
	Csfo           uint16
	Words130_155   [26]uint16
	Word156        uint16
	Words157_159   [3]uint16
	Cfa_power      uint16
	Words161_175   [15]uint16
	Words176_205   [30]uint16
	Words206_254   [49]uint16
	Integrity_word uint16
}

const (
	ST_MANDLOCK    = 0x40
	ST_NOATIME     = 0x400
	ST_NODEV       = 0x4
	ST_NODIRATIME  = 0x800
	ST_NOEXEC      = 0x8
	ST_NOSUID      = 0x2
	ST_RDONLY      = 0x1
	ST_RELATIME    = 0x1000
	ST_SYNCHRONOUS = 0x10
)

type Tpacket2Hdr struct {
	Status    uint32
	Len       uint32
	Snaplen   uint32
	Mac       uint16
	Net       uint16
	Sec       uint32
	Nsec      uint32
	Vlan_tci  uint16
	Vlan_tpid uint16
	_         [4]uint8
}

type Tpacket3Hdr struct {
	Next_offset uint32
	Sec         uint32
	Nsec        uint32
	Snaplen     uint32
	Len         uint32
	Status      uint32
	Mac         uint16
	Net         uint16
	Hv1         TpacketHdrVariant1
	_           [8]uint8
}

type TpacketHdrVariant1 struct {
	Rxhash    uint32
	Vlan_tci  uint32
	Vlan_tpid uint16
	_         uint16
}

type TpacketBlockDesc struct {
	Version uint32
	To_priv uint32
	Hdr     [40]byte
}

type TpacketBDTS struct {
	Sec  uint32
	Usec uint32
}

type TpacketHdrV1 struct {
	Block_status        uint32
	Num_pkts            uint32
	Offset_to_first_pkt uint32
	Blk_len             uint32
	Seq_num             uint64
	Ts_first_pkt        TpacketBDTS
	Ts_last_pkt         TpacketBDTS
}

type TpacketReq struct {
	Block_size uint32
	Block_nr   uint32
	Frame_size uint32
	Frame_nr   uint32
}

type TpacketReq3 struct {
	Block_size       uint32
	Block_nr         uint32
	Frame_size       uint32
	Frame_nr         uint32
	Retire_blk_tov   uint32
	Sizeof_priv      uint32
	Feature_req_word uint32
}

type TpacketStats struct {
	Packets uint32
	Drops   uint32
}

type TpacketStatsV3 struct {
	Packets      uint32
	Drops        uint32
	Freeze_q_cnt uint32
}

type TpacketAuxdata struct {
	Status    uint32
	Len       uint32
	Snaplen   uint32
	Mac       uint16
	Net       uint16
	Vlan_tci  uint16
	Vlan_tpid uint16
}

const (
	TPACKET_V1 = 0x0
	TPACKET_V2 = 0x1
	TPACKET_V3 = 0x2
)

const (
	SizeofTpacket2Hdr = 0x20
	SizeofTpacket3Hdr = 0x30

	SizeofTpacketStats   = 0x8
	SizeofTpacketStatsV3 = 0xc
)

const (
	IFLA_UNSPEC                                = 0x0
	IFLA_ADDRESS                               = 0x1
	IFLA_BROADCAST                             = 0x2
	IFLA_IFNAME                                = 0x3
	IFLA_MTU                                   = 0x4
	IFLA_LINK                                  = 0x5
	IFLA_QDISC                                 = 0x6
	IFLA_STATS                                 = 0x7
	IFLA_COST                                  = 0x8
	IFLA_PRIORITY                              = 0x9
	IFLA_MASTER                                = 0xa
	IFLA_WIRELESS                              = 0xb
	IFLA_PROTINFO                              = 0xc
	IFLA_TXQLEN                                = 0xd
	IFLA_MAP                                   = 0xe
	IFLA_WEIGHT                                = 0xf
	IFLA_OPERSTATE                             = 0x10
	IFLA_LINKMODE                              = 0x11
	IFLA_LINKINFO                              = 0x12
	IFLA_NET_NS_PID                            = 0x13
	IFLA_IFALIAS                               = 0x14
	IFLA_NUM_VF                                = 0x15
	IFLA_VFINFO_LIST                           = 0x16
	IFLA_STATS64                               = 0x17
	IFLA_VF_PORTS                              = 0x18
	IFLA_PORT_SELF                             = 0x19
	IFLA_AF_SPEC                               = 0x1a
	IFLA_GROUP                                 = 0x1b
	IFLA_NET_NS_FD                             = 0x1c
	IFLA_EXT_MASK                              = 0x1d
	IFLA_PROMISCUITY                           = 0x1e
	IFLA_NUM_TX_QUEUES                         = 0x1f
	IFLA_NUM_RX_QUEUES                         = 0x20
	IFLA_CARRIER                               = 0x21
	IFLA_PHYS_PORT_ID                          = 0x22
	IFLA_CARRIER_CHANGES                       = 0x23
	IFLA_PHYS_SWITCH_ID                        = 0x24
	IFLA_LINK_NETNSID                          = 0x25
	IFLA_PHYS_PORT_NAME                        = 0x26
	IFLA_PROTO_DOWN                            = 0x27
	IFLA_GSO_MAX_SEGS                          = 0x28
	IFLA_GSO_MAX_SIZE                          = 0x29
	IFLA_PAD                                   = 0x2a
	IFLA_XDP                                   = 0x2b
	IFLA_EVENT                                 = 0x2c
	IFLA_NEW_NETNSID                           = 0x2d
	IFLA_IF_NETNSID                            = 0x2e
	IFLA_TARGET_NETNSID                        = 0x2e
	IFLA_CARRIER_UP_COUNT                      = 0x2f
	IFLA_CARRIER_DOWN_COUNT                    = 0x30
	IFLA_NEW_IFINDEX                           = 0x31
	IFLA_MIN_MTU                               = 0x32
	IFLA_MAX_MTU                               = 0x33
	IFLA_PROP_LIST                             = 0x34
	IFLA_ALT_IFNAME                            = 0x35
	IFLA_PERM_ADDRESS                          = 0x36
	IFLA_PROTO_DOWN_REASON                     = 0x37
	IFLA_PARENT_DEV_NAME                       = 0x38
	IFLA_PARENT_DEV_BUS_NAME                   = 0x39
	IFLA_GRO_MAX_SIZE                          = 0x3a
	IFLA_TSO_MAX_SIZE                          = 0x3b
	IFLA_TSO_MAX_SEGS                          = 0x3c
	IFLA_ALLMULTI                              = 0x3d
	IFLA_DEVLINK_PORT                          = 0x3e
	IFLA_GSO_IPV4_MAX_SIZE                     = 0x3f
	IFLA_GRO_IPV4_MAX_SIZE                     = 0x40
	IFLA_DPLL_PIN                              = 0x41
	IFLA_PROTO_DOWN_REASON_UNSPEC              = 0x0
	IFLA_PROTO_DOWN_REASON_MASK                = 0x1
	IFLA_PROTO_DOWN_REASON_VALUE               = 0x2
	IFLA_PROTO_DOWN_REASON_MAX                 = 0x2
	IFLA_INET_UNSPEC                           = 0x0
	IFLA_INET_CONF                             = 0x1
	IFLA_INET6_UNSPEC                          = 0x0
	IFLA_INET6_FLAGS                           = 0x1
	IFLA_INET6_CONF                            = 0x2
	IFLA_INET6_STATS                           = 0x3
	IFLA_INET6_MCAST                           = 0x4
	IFLA_INET6_CACHEINFO                       = 0x5
	IFLA_INET6_ICMP6STATS                      = 0x6
	IFLA_INET6_TOKEN                           = 0x7
	IFLA_INET6_ADDR_GEN_MODE                   = 0x8
	IFLA_INET6_RA_MTU                          = 0x9
	IFLA_BR_UNSPEC                             = 0x0
	IFLA_BR_FORWARD_DELAY                      = 0x1
	IFLA_BR_HELLO_TIME                         = 0x2
	IFLA_BR_MAX_AGE                            = 0x3
	IFLA_BR_AGEING_TIME                        = 0x4
	IFLA_BR_STP_STATE                          = 0x5
	IFLA_BR_PRIORITY                           = 0x6
	IFLA_BR_VLAN_FILTERING                     = 0x7
	IFLA_BR_VLAN_PROTOCOL                      = 0x8
	IFLA_BR_GROUP_FWD_MASK                     = 0x9
	IFLA_BR_ROOT_ID                            = 0xa
	IFLA_BR_BRIDGE_ID                          = 0xb
	IFLA_BR_ROOT_PORT                          = 0xc
	IFLA_BR_ROOT_PATH_COST                     = 0xd
	IFLA_BR_TOPOLOGY_CHANGE                    = 0xe
	IFLA_BR_TOPOLOGY_CHANGE_DETECTED           = 0xf
	IFLA_BR_HELLO_TIMER                        = 0x10
	IFLA_BR_TCN_TIMER                          = 0x11
	IFLA_BR_TOPOLOGY_CHANGE_TIMER              = 0x12
	IFLA_BR_GC_TIMER                           = 0x13
	IFLA_BR_GROUP_ADDR                         = 0x14
	IFLA_BR_FDB_FLUSH                          = 0x15
	IFLA_BR_MCAST_ROUTER                       = 0x16
	IFLA_BR_MCAST_SNOOPING                     = 0x17
	IFLA_BR_MCAST_QUERY_USE_IFADDR             = 0x18
	IFLA_BR_MCAST_QUERIER                      = 0x19
	IFLA_BR_MCAST_HASH_ELASTICITY              = 0x1a
	IFLA_BR_MCAST_HASH_MAX                     = 0x1b
	IFLA_BR_MCAST_LAST_MEMBER_CNT              = 0x1c
	IFLA_BR_MCAST_STARTUP_QUERY_CNT            = 0x1d
	IFLA_BR_MCAST_LAST_MEMBER_INTVL            = 0x1e
	IFLA_BR_MCAST_MEMBERSHIP_INTVL             = 0x1f
	IFLA_BR_MCAST_QUERIER_INTVL                = 0x20
	IFLA_BR_MCAST_QUERY_INTVL                  = 0x21
	IFLA_BR_MCAST_QUERY_RESPONSE_INTVL         = 0x22
	IFLA_BR_MCAST_STARTUP_QUERY_INTVL          = 0x23
	IFLA_BR_NF_CALL_IPTABLES                   = 0x24
	IFLA_BR_NF_CALL_IP6TABLES                  = 0x25
	IFLA_BR_NF_CALL_ARPTABLES                  = 0x26
	IFLA_BR_VLAN_DEFAULT_PVID                  = 0x27
	IFLA_BR_PAD                                = 0x28
	IFLA_BR_VLAN_STATS_ENABLED                 = 0x29
	IFLA_BR_MCAST_STATS_ENABLED                = 0x2a
	IFLA_BR_MCAST_IGMP_VERSION                 = 0x2b
	IFLA_BR_MCAST_MLD_VERSION                  = 0x2c
	IFLA_BR_VLAN_STATS_PER_PORT                = 0x2d
	IFLA_BR_MULTI_BOOLOPT                      = 0x2e
	IFLA_BR_MCAST_QUERIER_STATE                = 0x2f
	IFLA_BR_FDB_N_LEARNED                      = 0x30
	IFLA_BR_FDB_MAX_LEARNED                    = 0x31
	IFLA_BRPORT_UNSPEC                         = 0x0
	IFLA_BRPORT_STATE                          = 0x1
	IFLA_BRPORT_PRIORITY                       = 0x2
	IFLA_BRPORT_COST                           = 0x3
	IFLA_BRPORT_MODE                           = 0x4
	IFLA_BRPORT_GUARD                          = 0x5
	IFLA_BRPORT_PROTECT                        = 0x6
	IFLA_BRPORT_FAST_LEAVE                     = 0x7
	IFLA_BRPORT_LEARNING                       = 0x8
	IFLA_BRPORT_UNICAST_FLOOD                  = 0x9
	IFLA_BRPORT_PROXYARP                       = 0xa
	IFLA_BRPORT_LEARNING_SYNC                  = 0xb
	IFLA_BRPORT_PROXYARP_WIFI                  = 0xc
	IFLA_BRPORT_ROOT_ID                        = 0xd
	IFLA_BRPORT_BRIDGE_ID                      = 0xe
	IFLA_BRPORT_DESIGNATED_PORT                = 0xf
	IFLA_BRPORT_DESIGNATED_COST                = 0x10
	IFLA_BRPORT_ID                             = 0x11
	IFLA_BRPORT_NO                             = 0x12
	IFLA_BRPORT_TOPOLOGY_CHANGE_ACK            = 0x13
	IFLA_BRPORT_CONFIG_PENDING                 = 0x14
	IFLA_BRPORT_MESSAGE_AGE_TIMER              = 0x15
	IFLA_BRPORT_FORWARD_DELAY_TIMER            = 0x16
	IFLA_BRPORT_HOLD_TIMER                     = 0x17
	IFLA_BRPORT_FLUSH                          = 0x18
	IFLA_BRPORT_MULTICAST_ROUTER               = 0x19
	IFLA_BRPORT_PAD                            = 0x1a
	IFLA_BRPORT_MCAST_FLOOD                    = 0x1b
	IFLA_BRPORT_MCAST_TO_UCAST                 = 0x1c
	IFLA_BRPORT_VLAN_TUNNEL                    = 0x1d
	IFLA_BRPORT_BCAST_FLOOD                    = 0x1e
	IFLA_BRPORT_GROUP_FWD_MASK                 = 0x1f
	IFLA_BRPORT_NEIGH_SUPPRESS                 = 0x20
	IFLA_BRPORT_ISOLATED                       = 0x21
	IFLA_BRPORT_BACKUP_PORT                    = 0x22
	IFLA_BRPORT_MRP_RING_OPEN                  = 0x23
	IFLA_BRPORT_MRP_IN_OPEN                    = 0x24
	IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT          = 0x25
	IFLA_BRPORT_MCAST_EHT_HOSTS_CNT            = 0x26
	IFLA_BRPORT_LOCKED                         = 0x27
	IFLA_BRPORT_MAB                            = 0x28
	IFLA_BRPORT_MCAST_N_GROUPS                 = 0x29
	IFLA_BRPORT_MCAST_MAX_GROUPS               = 0x2a
	IFLA_BRPORT_NEIGH_VLAN_SUPPRESS            = 0x2b
	IFLA_BRPORT_BACKUP_NHID                    = 0x2c
	IFLA_INFO_UNSPEC                           = 0x0
	IFLA_INFO_KIND                             = 0x1
	IFLA_INFO_DATA                             = 0x2
	IFLA_INFO_XSTATS                           = 0x3
	IFLA_INFO_SLAVE_KIND                       = 0x4
	IFLA_INFO_SLAVE_DATA                       = 0x5
	IFLA_VLAN_UNSPEC                           = 0x0
	IFLA_VLAN_ID                               = 0x1
	IFLA_VLAN_FLAGS                            = 0x2
	IFLA_VLAN_EGRESS_QOS                       = 0x3
	IFLA_VLAN_INGRESS_QOS                      = 0x4
	IFLA_VLAN_PROTOCOL                         = 0x5
	IFLA_VLAN_QOS_UNSPEC                       = 0x0
	IFLA_VLAN_QOS_MAPPING                      = 0x1
	IFLA_MACVLAN_UNSPEC                        = 0x0
	IFLA_MACVLAN_MODE                          = 0x1
	IFLA_MACVLAN_FLAGS                         = 0x2
	IFLA_MACVLAN_MACADDR_MODE                  = 0x3
	IFLA_MACVLAN_MACADDR                       = 0x4
	IFLA_MACVLAN_MACADDR_DATA                  = 0x5
	IFLA_MACVLAN_MACADDR_COUNT                 = 0x6
	IFLA_MACVLAN_BC_QUEUE_LEN                  = 0x7
	IFLA_MACVLAN_BC_QUEUE_LEN_USED             = 0x8
	IFLA_MACVLAN_BC_CUTOFF                     = 0x9
	IFLA_VRF_UNSPEC                            = 0x0
	IFLA_VRF_TABLE                             = 0x1
	IFLA_VRF_PORT_UNSPEC                       = 0x0
	IFLA_VRF_PORT_TABLE                        = 0x1
	IFLA_MACSEC_UNSPEC                         = 0x0
	IFLA_MACSEC_SCI                            = 0x1
	IFLA_MACSEC_PORT                           = 0x2
	IFLA_MACSEC_ICV_LEN                        = 0x3
	IFLA_MACSEC_CIPHER_SUITE                   = 0x4
	IFLA_MACSEC_WINDOW                         = 0x5
	IFLA_MACSEC_ENCODING_SA                    = 0x6
	IFLA_MACSEC_ENCRYPT                        = 0x7
	IFLA_MACSEC_PROTECT                        = 0x8
	IFLA_MACSEC_INC_SCI                        = 0x9
	IFLA_MACSEC_ES                             = 0xa
	IFLA_MACSEC_SCB                            = 0xb
	IFLA_MACSEC_REPLAY_PROTECT                 = 0xc
	IFLA_MACSEC_VALIDATION                     = 0xd
	IFLA_MACSEC_PAD                            = 0xe
	IFLA_MACSEC_OFFLOAD                        = 0xf
	IFLA_XFRM_UNSPEC                           = 0x0
	IFLA_XFRM_LINK                             = 0x1
	IFLA_XFRM_IF_ID                            = 0x2
	IFLA_XFRM_COLLECT_METADATA                 = 0x3
	IFLA_IPVLAN_UNSPEC                         = 0x0
	IFLA_IPVLAN_MODE                           = 0x1
	IFLA_IPVLAN_FLAGS                          = 0x2
	IFLA_NETKIT_UNSPEC                         = 0x0
	IFLA_NETKIT_PEER_INFO                      = 0x1
	IFLA_NETKIT_PRIMARY                        = 0x2
	IFLA_NETKIT_POLICY                         = 0x3
	IFLA_NETKIT_PEER_POLICY                    = 0x4
	IFLA_NETKIT_MODE                           = 0x5
	IFLA_VXLAN_UNSPEC                          = 0x0
	IFLA_VXLAN_ID                              = 0x1
	IFLA_VXLAN_GROUP                           = 0x2
	IFLA_VXLAN_LINK                            = 0x3
	IFLA_VXLAN_LOCAL                           = 0x4
	IFLA_VXLAN_TTL                             = 0x5
	IFLA_VXLAN_TOS                             = 0x6
	IFLA_VXLAN_LEARNING                        = 0x7
	IFLA_VXLAN_AGEING                          = 0x8
	IFLA_VXLAN_LIMIT                           = 0x9
	IFLA_VXLAN_PORT_RANGE                      = 0xa
	IFLA_VXLAN_PROXY                           = 0xb
	IFLA_VXLAN_RSC                             = 0xc
	IFLA_VXLAN_L2MISS                          = 0xd
	IFLA_VXLAN_L3MISS                          = 0xe
	IFLA_VXLAN_PORT                            = 0xf
	IFLA_VXLAN_GROUP6                          = 0x10
	IFLA_VXLAN_LOCAL6                          = 0x11
	IFLA_VXLAN_UDP_CSUM                        = 0x12
	IFLA_VXLAN_UDP_ZERO_CSUM6_TX               = 0x13
	IFLA_VXLAN_UDP_ZERO_CSUM6_RX               = 0x14
	IFLA_VXLAN_REMCSUM_TX                      = 0x15
	IFLA_VXLAN_REMCSUM_RX                      = 0x16
	IFLA_VXLAN_GBP                             = 0x17
	IFLA_VXLAN_REMCSUM_NOPARTIAL               = 0x18
	IFLA_VXLAN_COLLECT_METADATA                = 0x19
	IFLA_VXLAN_LABEL                           = 0x1a
	IFLA_VXLAN_GPE                             = 0x1b
	IFLA_VXLAN_TTL_INHERIT                     = 0x1c
	IFLA_VXLAN_DF                              = 0x1d
	IFLA_VXLAN_VNIFILTER                       = 0x1e
	IFLA_VXLAN_LOCALBYPASS                     = 0x1f
	IFLA_VXLAN_LABEL_POLICY                    = 0x20
	IFLA_GENEVE_UNSPEC                         = 0x0
	IFLA_GENEVE_ID                             = 0x1
	IFLA_GENEVE_REMOTE                         = 0x2
	IFLA_GENEVE_TTL                            = 0x3
	IFLA_GENEVE_TOS                            = 0x4
	IFLA_GENEVE_PORT                           = 0x5
	IFLA_GENEVE_COLLECT_METADATA               = 0x6
	IFLA_GENEVE_REMOTE6                        = 0x7
	IFLA_GENEVE_UDP_CSUM                       = 0x8
	IFLA_GENEVE_UDP_ZERO_CSUM6_TX              = 0x9
	IFLA_GENEVE_UDP_ZERO_CSUM6_RX              = 0xa
	IFLA_GENEVE_LABEL                          = 0xb
	IFLA_GENEVE_TTL_INHERIT                    = 0xc
	IFLA_GENEVE_DF                             = 0xd
	IFLA_GENEVE_INNER_PROTO_INHERIT            = 0xe
	IFLA_BAREUDP_UNSPEC                        = 0x0
	IFLA_BAREUDP_PORT                          = 0x1
	IFLA_BAREUDP_ETHERTYPE                     = 0x2
	IFLA_BAREUDP_SRCPORT_MIN                   = 0x3
	IFLA_BAREUDP_MULTIPROTO_MODE               = 0x4
	IFLA_PPP_UNSPEC                            = 0x0
	IFLA_PPP_DEV_FD                            = 0x1
	IFLA_GTP_UNSPEC                            = 0x0
	IFLA_GTP_FD0                               = 0x1
	IFLA_GTP_FD1                               = 0x2
	IFLA_GTP_PDP_HASHSIZE                      = 0x3
	IFLA_GTP_ROLE                              = 0x4
	IFLA_GTP_CREATE_SOCKETS                    = 0x5
	IFLA_GTP_RESTART_COUNT                     = 0x6
	IFLA_GTP_LOCAL                             = 0x7
	IFLA_GTP_LOCAL6                            = 0x8
	IFLA_BOND_UNSPEC                           = 0x0
	IFLA_BOND_MODE                             = 0x1
	IFLA_BOND_ACTIVE_SLAVE                     = 0x2
	IFLA_BOND_MIIMON                           = 0x3
	IFLA_BOND_UPDELAY                          = 0x4
	IFLA_BOND_DOWNDELAY                        = 0x5
	IFLA_BOND_USE_CARRIER                      = 0x6
	IFLA_BOND_ARP_INTERVAL                     = 0x7
	IFLA_BOND_ARP_IP_TARGET                    = 0x8
	IFLA_BOND_ARP_VALIDATE                     = 0x9
	IFLA_BOND_ARP_ALL_TARGETS                  = 0xa
	IFLA_BOND_PRIMARY                          = 0xb
	IFLA_BOND_PRIMARY_RESELECT                 = 0xc
	IFLA_BOND_FAIL_OVER_MAC                    = 0xd
	IFLA_BOND_XMIT_HASH_POLICY                 = 0xe
	IFLA_BOND_RESEND_IGMP                      = 0xf
	IFLA_BOND_NUM_PEER_NOTIF                   = 0x10
	IFLA_BOND_ALL_SLAVES_ACTIVE                = 0x11
	IFLA_BOND_MIN_LINKS                        = 0x12
	IFLA_BOND_LP_INTERVAL                      = 0x13
	IFLA_BOND_PACKETS_PER_SLAVE                = 0x14
	IFLA_BOND_AD_LACP_RATE                     = 0x15
	IFLA_BOND_AD_SELECT                        = 0x16
	IFLA_BOND_AD_INFO                          = 0x17
	IFLA_BOND_AD_ACTOR_SYS_PRIO                = 0x18
	IFLA_BOND_AD_USER_PORT_KEY                 = 0x19
	IFLA_BOND_AD_ACTOR_SYSTEM                  = 0x1a
	IFLA_BOND_TLB_DYNAMIC_LB                   = 0x1b
	IFLA_BOND_PEER_NOTIF_DELAY                 = 0x1c
	IFLA_BOND_AD_LACP_ACTIVE                   = 0x1d
	IFLA_BOND_MISSED_MAX                       = 0x1e
	IFLA_BOND_NS_IP6_TARGET                    = 0x1f
	IFLA_BOND_COUPLED_CONTROL                  = 0x20
	IFLA_BOND_AD_INFO_UNSPEC                   = 0x0
	IFLA_BOND_AD_INFO_AGGREGATOR               = 0x1
	IFLA_BOND_AD_INFO_NUM_PORTS                = 0x2
	IFLA_BOND_AD_INFO_ACTOR_KEY                = 0x3
	IFLA_BOND_AD_INFO_PARTNER_KEY              = 0x4
	IFLA_BOND_AD_INFO_PARTNER_MAC              = 0x5
	IFLA_BOND_SLAVE_UNSPEC                     = 0x0
	IFLA_BOND_SLAVE_STATE                      = 0x1
	IFLA_BOND_SLAVE_MII_STATUS                 = 0x2
	IFLA_BOND_SLAVE_LINK_FAILURE_COUNT         = 0x3
	IFLA_BOND_SLAVE_PERM_HWADDR                = 0x4
	IFLA_BOND_SLAVE_QUEUE_ID                   = 0x5
	IFLA_BOND_SLAVE_AD_AGGREGATOR_ID           = 0x6
	IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE   = 0x7
	IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE = 0x8
	IFLA_BOND_SLAVE_PRIO                       = 0x9
	IFLA_VF_INFO_UNSPEC                        = 0x0
	IFLA_VF_INFO                               = 0x1
	IFLA_VF_UNSPEC                             = 0x0
	IFLA_VF_MAC                                = 0x1
	IFLA_VF_VLAN                               = 0x2
	IFLA_VF_TX_RATE                            = 0x3
	IFLA_VF_SPOOFCHK                           = 0x4
	IFLA_VF_LINK_STATE                         = 0x5
	IFLA_VF_RATE                               = 0x6
	IFLA_VF_RSS_QUERY_EN                       = 0x7
	IFLA_VF_STATS                              = 0x8
	IFLA_VF_TRUST                              = 0x9
	IFLA_VF_IB_NODE_GUID                       = 0xa
	IFLA_VF_IB_PORT_GUID                       = 0xb
	IFLA_VF_VLAN_LIST                          = 0xc
	IFLA_VF_BROADCAST                          = 0xd
	IFLA_VF_VLAN_INFO_UNSPEC                   = 0x0
	IFLA_VF_VLAN_INFO                          = 0x1
	IFLA_VF_LINK_STATE_AUTO                    = 0x0
	IFLA_VF_LINK_STATE_ENABLE                  = 0x1
	IFLA_VF_LINK_STATE_DISABLE                 = 0x2
	IFLA_VF_STATS_RX_PACKETS                   = 0x0
	IFLA_VF_STATS_TX_PACKETS                   = 0x1
	IFLA_VF_STATS_RX_BYTES                     = 0x2
	IFLA_VF_STATS_TX_BYTES                     = 0x3
	IFLA_VF_STATS_BROADCAST                    = 0x4
	IFLA_VF_STATS_MULTICAST                    = 0x5
	IFLA_VF_STATS_PAD                          = 0x6
	IFLA_VF_STATS_RX_DROPPED                   = 0x7
	IFLA_VF_STATS_TX_DROPPED                   = 0x8
	IFLA_VF_PORT_UNSPEC                        = 0x0
	IFLA_VF_PORT                               = 0x1
	IFLA_PORT_UNSPEC                           = 0x0
	IFLA_PORT_VF                               = 0x1
	IFLA_PORT_PROFILE                          = 0x2
	IFLA_PORT_VSI_TYPE                         = 0x3
	IFLA_PORT_INSTANCE_UUID                    = 0x4
	IFLA_PORT_HOST_UUID                        = 0x5
	IFLA_PORT_REQUEST                          = 0x6
	IFLA_PORT_RESPONSE                         = 0x7
	IFLA_IPOIB_UNSPEC                          = 0x0
	IFLA_IPOIB_PKEY                            = 0x1
	IFLA_IPOIB_MODE                            = 0x2
	IFLA_IPOIB_UMCAST                          = 0x3
	IFLA_HSR_UNSPEC                            = 0x0
	IFLA_HSR_SLAVE1                            = 0x1
	IFLA_HSR_SLAVE2                            = 0x2
	IFLA_HSR_MULTICAST_SPEC                    = 0x3
	IFLA_HSR_SUPERVISION_ADDR                  = 0x4
	IFLA_HSR_SEQ_NR                            = 0x5
	IFLA_HSR_VERSION                           = 0x6
	IFLA_HSR_PROTOCOL                          = 0x7
	IFLA_HSR_INTERLINK                         = 0x8
	IFLA_STATS_UNSPEC                          = 0x0
	IFLA_STATS_LINK_64                         = 0x1
	IFLA_STATS_LINK_XSTATS                     = 0x2
	IFLA_STATS_LINK_XSTATS_SLAVE               = 0x3
	IFLA_STATS_LINK_OFFLOAD_XSTATS             = 0x4
	IFLA_STATS_AF_SPEC                         = 0x5
	IFLA_STATS_GETSET_UNSPEC                   = 0x0
	IFLA_STATS_GET_FILTERS                     = 0x1
	IFLA_STATS_SET_OFFLOAD_XSTATS_L3_STATS     = 0x2
	IFLA_OFFLOAD_XSTATS_UNSPEC                 = 0x0
	IFLA_OFFLOAD_XSTATS_CPU_HIT                = 0x1
	IFLA_OFFLOAD_XSTATS_HW_S_INFO              = 0x2
	IFLA_OFFLOAD_XSTATS_L3_STATS               = 0x3
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_UNSPEC       = 0x0
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST      = 0x1
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED         = 0x2
	IFLA_XDP_UNSPEC                            = 0x0
	IFLA_XDP_FD                                = 0x1
	IFLA_XDP_ATTACHED                          = 0x2
	IFLA_XDP_FLAGS                             = 0x3
	IFLA_XDP_PROG_ID                           = 0x4
	IFLA_XDP_DRV_PROG_ID                       = 0x5
	IFLA_XDP_SKB_PROG_ID                       = 0x6
	IFLA_XDP_HW_PROG_ID                        = 0x7
	IFLA_XDP_EXPECTED_FD                       = 0x8
	IFLA_EVENT_NONE                            = 0x0
	IFLA_EVENT_REBOOT                          = 0x1
	IFLA_EVENT_FEATURES                        = 0x2
	IFLA_EVENT_BONDING_FAILOVER                = 0x3
	IFLA_EVENT_NOTIFY_PEERS                    = 0x4
	IFLA_EVENT_IGMP_RESEND                     = 0x5
	IFLA_EVENT_BONDING_OPTIONS                 = 0x6
	IFLA_TUN_UNSPEC                            = 0x0
	IFLA_TUN_OWNER                             = 0x1
	IFLA_TUN_GROUP                             = 0x2
	IFLA_TUN_TYPE                              = 0x3
	IFLA_TUN_PI                                = 0x4
	IFLA_TUN_VNET_HDR                          = 0x5
	IFLA_TUN_PERSIST                           = 0x6
	IFLA_TUN_MULTI_QUEUE                       = 0x7
	IFLA_TUN_NUM_QUEUES                        = 0x8
	IFLA_TUN_NUM_DISABLED_QUEUES               = 0x9
	IFLA_RMNET_UNSPEC                          = 0x0
	IFLA_RMNET_MUX_ID                          = 0x1
	IFLA_RMNET_FLAGS                           = 0x2
	IFLA_MCTP_UNSPEC                           = 0x0
	IFLA_MCTP_NET                              = 0x1
	IFLA_DSA_UNSPEC                            = 0x0
	IFLA_DSA_CONDUIT                           = 0x1
	IFLA_DSA_MASTER                            = 0x1
)

const (
	NETKIT_NEXT     = -0x1
	NETKIT_PASS     = 0x0
	NETKIT_DROP     = 0x2
	NETKIT_REDIRECT = 0x7
	NETKIT_L2       = 0x0
	NETKIT_L3       = 0x1
)

const (
	NF_INET_PRE_ROUTING  = 0x0
	NF_INET_LOCAL_IN     = 0x1
	NF_INET_FORWARD      = 0x2
	NF_INET_LOCAL_OUT    = 0x3
	NF_INET_POST_ROUTING = 0x4
	NF_INET_NUMHOOKS     = 0x5
)

const (
	NF_NETDEV_INGRESS  = 0x0
	NF_NETDEV_EGRESS   = 0x1
	NF_NETDEV_NUMHOOKS = 0x2
)

const (
	NFPROTO_UNSPEC   = 0x0
	NFPROTO_INET     = 0x1
	NFPROTO_IPV4     = 0x2
	NFPROTO_ARP      = 0x3
	NFPROTO_NETDEV   = 0x5
	NFPROTO_BRIDGE   = 0x7
	NFPROTO_IPV6     = 0xa
	NFPROTO_DECNET   = 0xc
	NFPROTO_NUMPROTO = 0xd
)

const SO_ORIGINAL_DST = 0x50

type Nfgenmsg struct {
	Nfgen_family uint8
	Version      uint8
	Res_id       uint16
}

const (
	NFNL_BATCH_UNSPEC = 0x0
	NFNL_BATCH_GENID  = 0x1
)

const (
	NFT_REG_VERDICT                   = 0x0
	NFT_REG_1                         = 0x1
	NFT_REG_2                         = 0x2
	NFT_REG_3                         = 0x3
	NFT_REG_4                         = 0x4
	NFT_REG32_00                      = 0x8
	NFT_REG32_01                      = 0x9
	NFT_REG32_02                      = 0xa
	NFT_REG32_03                      = 0xb
	NFT_REG32_04                      = 0xc
	NFT_REG32_05                      = 0xd
	NFT_REG32_06                      = 0xe
	NFT_REG32_07                      = 0xf
	NFT_REG32_08                      = 0x10
	NFT_REG32_09                      = 0x11
	NFT_REG32_10                      = 0x12
	NFT_REG32_11                      = 0x13
	NFT_REG32_12                      = 0x14
	NFT_REG32_13                      = 0x15
	NFT_REG32_14                      = 0x16
	NFT_REG32_15                      = 0x17
	NFT_CONTINUE                      = -0x1
	NFT_BREAK                         = -0x2
	NFT_JUMP                          = -0x3
	NFT_GOTO                          = -0x4
	NFT_RETURN                        = -0x5
	NFT_MSG_NEWTABLE                  = 0x0
	NFT_MSG_GETTABLE                  = 0x1
	NFT_MSG_DELTABLE                  = 0x2
	NFT_MSG_NEWCHAIN                  = 0x3
	NFT_MSG_GETCHAIN                  = 0x4
	NFT_MSG_DELCHAIN                  = 0x5
	NFT_MSG_NEWRULE                   = 0x6
	NFT_MSG_GETRULE                   = 0x7
	NFT_MSG_DELRULE                   = 0x8
	NFT_MSG_NEWSET                    = 0x9
	NFT_MSG_GETSET                    = 0xa
	NFT_MSG_DELSET                    = 0xb
	NFT_MSG_NEWSETELEM                = 0xc
	NFT_MSG_GETSETELEM                = 0xd
	NFT_MSG_DELSETELEM                = 0xe
	NFT_MSG_NEWGEN                    = 0xf
	NFT_MSG_GETGEN                    = 0x10
	NFT_MSG_TRACE                     = 0x11
	NFT_MSG_NEWOBJ                    = 0x12
	NFT_MSG_GETOBJ                    = 0x13
	NFT_MSG_DELOBJ                    = 0x14
	NFT_MSG_GETOBJ_RESET              = 0x15
	NFT_MSG_NEWFLOWTABLE              = 0x16
	NFT_MSG_GETFLOWTABLE              = 0x17
	NFT_MSG_DELFLOWTABLE              = 0x18
	NFT_MSG_GETRULE_RESET             = 0x19
	NFT_MSG_MAX                       = 0x22
	NFTA_LIST_UNSPEC                  = 0x0
	NFTA_LIST_ELEM                    = 0x1
	NFTA_HOOK_UNSPEC                  = 0x0
	NFTA_HOOK_HOOKNUM                 = 0x1
	NFTA_HOOK_PRIORITY                = 0x2
	NFTA_HOOK_DEV                     = 0x3
	NFT_TABLE_F_DORMANT               = 0x1
	NFTA_TABLE_UNSPEC                 = 0x0
	NFTA_TABLE_NAME                   = 0x1
	NFTA_TABLE_FLAGS                  = 0x2
	NFTA_TABLE_USE                    = 0x3
	NFTA_CHAIN_UNSPEC                 = 0x0
	NFTA_CHAIN_TABLE                  = 0x1
	NFTA_CHAIN_HANDLE                 = 0x2
	NFTA_CHAIN_NAME                   = 0x3
	NFTA_CHAIN_HOOK                   = 0x4
	NFTA_CHAIN_POLICY                 = 0x5
	NFTA_CHAIN_USE                    = 0x6
	NFTA_CHAIN_TYPE                   = 0x7
	NFTA_CHAIN_COUNTERS               = 0x8
	NFTA_CHAIN_PAD                    = 0x9
	NFTA_RULE_UNSPEC                  = 0x0
	NFTA_RULE_TABLE                   = 0x1
	NFTA_RULE_CHAIN                   = 0x2
	NFTA_RULE_HANDLE                  = 0x3
	NFTA_RULE_EXPRESSIONS             = 0x4
	NFTA_RULE_COMPAT                  = 0x5
	NFTA_RULE_POSITION                = 0x6
	NFTA_RULE_USERDATA                = 0x7
	NFTA_RULE_PAD                     = 0x8
	NFTA_RULE_ID                      = 0x9
	NFT_RULE_COMPAT_F_INV             = 0x2
	NFT_RULE_COMPAT_F_MASK            = 0x2
	NFTA_RULE_COMPAT_UNSPEC           = 0x0
	NFTA_RULE_COMPAT_PROTO            = 0x1
	NFTA_RULE_COMPAT_FLAGS            = 0x2
	NFT_SET_ANONYMOUS                 = 0x1
	NFT_SET_CONSTANT                  = 0x2
	NFT_SET_INTERVAL                  = 0x4
	NFT_SET_MAP                       = 0x8
	NFT_SET_TIMEOUT                   = 0x10
	NFT_SET_EVAL                      = 0x20
	NFT_SET_OBJECT                    = 0x40
	NFT_SET_POL_PERFORMANCE           = 0x0
	NFT_SET_POL_MEMORY                = 0x1
	NFTA_SET_DESC_UNSPEC              = 0x0
	NFTA_SET_DESC_SIZE                = 0x1
	NFTA_SET_UNSPEC                   = 0x0
	NFTA_SET_TABLE                    = 0x1
	NFTA_SET_NAME                     = 0x2
	NFTA_SET_FLAGS                    = 0x3
	NFTA_SET_KEY_TYPE                 = 0x4
	NFTA_SET_KEY_LEN                  = 0x5
	NFTA_SET_DATA_TYPE                = 0x6
	NFTA_SET_DATA_LEN                 = 0x7
	NFTA_SET_POLICY                   = 0x8
	NFTA_SET_DESC                     = 0x9
	NFTA_SET_ID                       = 0xa
	NFTA_SET_TIMEOUT                  = 0xb
	NFTA_SET_GC_INTERVAL              = 0xc
	NFTA_SET_USERDATA                 = 0xd
	NFTA_SET_PAD                      = 0xe
	NFTA_SET_OBJ_TYPE                 = 0xf
	NFT_SET_ELEM_INTERVAL_END         = 0x1
	NFTA_SET_ELEM_UNSPEC              = 0x0
	NFTA_SET_ELEM_KEY                 = 0x1
	NFTA_SET_ELEM_DATA                = 0x2
	NFTA_SET_ELEM_FLAGS               = 0x3
	NFTA_SET_ELEM_TIMEOUT             = 0x4
	NFTA_SET_ELEM_EXPIRATION          = 0x5
	NFTA_SET_ELEM_USERDATA            = 0x6
	NFTA_SET_ELEM_EXPR                = 0x7
	NFTA_SET_ELEM_PAD                 = 0x8
	NFTA_SET_ELEM_OBJREF              = 0x9
	NFTA_SET_ELEM_LIST_UNSPEC         = 0x0
	NFTA_SET_ELEM_LIST_TABLE          = 0x1
	NFTA_SET_ELEM_LIST_SET            = 0x2
	NFTA_SET_ELEM_LIST_ELEMENTS       = 0x3
	NFTA_SET_ELEM_LIST_SET_ID         = 0x4
	NFT_DATA_VALUE                    = 0x0
	NFT_DATA_VERDICT                  = 0xffffff00
	NFTA_DATA_UNSPEC                  = 0x0
	NFTA_DATA_VALUE                   = 0x1
	NFTA_DATA_VERDICT                 = 0x2
	NFTA_VERDICT_UNSPEC               = 0x0
	NFTA_VERDICT_CODE                 = 0x1
	NFTA_VERDICT_CHAIN                = 0x2
	NFTA_EXPR_UNSPEC                  = 0x0
	NFTA_EXPR_NAME                    = 0x1
	NFTA_EXPR_DATA                    = 0x2
	NFTA_IMMEDIATE_UNSPEC             = 0x0
	NFTA_IMMEDIATE_DREG               = 0x1
	NFTA_IMMEDIATE_DATA               = 0x2
	NFTA_BITWISE_UNSPEC               = 0x0
	NFTA_BITWISE_SREG                 = 0x1
	NFTA_BITWISE_DREG                 = 0x2
	NFTA_BITWISE_LEN                  = 0x3
	NFTA_BITWISE_MASK                 = 0x4
	NFTA_BITWISE_XOR      
"""




```