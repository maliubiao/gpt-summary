Response:
My thought process for analyzing the provided Go code and generating the response went through these stages:

1. **Understanding the File's Purpose and Context:**

   - The file path `go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux_mips64.go` immediately tells me a few key things:
     - It's part of the `golang.org/x/sys/unix` package, indicating it deals with low-level system calls and data structures specific to Unix-like systems.
     - The `vendor` directory suggests it's a vendored dependency, likely for internal use by the Go standard library or related tools.
     - `ztypes_linux_mips64.go` is a strong indicator that this file defines Go types corresponding to C structures used in Linux system calls for the MIPS64 architecture. The `z` prefix likely means "generated" or "architecture-specific".

   - The `//go:build mips64 && linux` comment confirms that this code is only compiled for the `mips64` architecture on Linux.

   - The first comment line `// cgo -godefs ...` reveals how this file was generated: using `cgo` to translate C definitions into Go. This is a crucial piece of information.

2. **Analyzing the Content - Identifying Key Features:**

   - **Constants:** I scanned for `const` declarations. `SizeofPtr` and `SizeofLong` are immediately apparent, indicating the size of pointers and long integers on this architecture. Later, I noticed other constants like `FADV_DONTNEED`, `FADV_NOREUSE`, `SizeofSockaddrNFCLLCP`, etc., which are likely flags or sizes related to specific system calls or data structures.

   - **Types:**  The majority of the file consists of `type` declarations. These are almost all `struct` types. I recognized many of these struct names (`Timespec`, `Timeval`, `Stat_t`, `Dirent`, `SockaddrStorage`, etc.) as common structures used in Unix/Linux system programming. This reinforces the idea that the file's primary function is to provide Go-compatible representations of these C structures.

   - **Specific System Call/Feature Associations:**  As I went through the types, I tried to connect them to known system calls or concepts:
     - `Timespec`, `Timeval`, `Timex`:  Time-related system calls (`clock_gettime`, `adjtimex`).
     - `Rusage`:  Resource usage information (`getrusage`).
     - `Stat_t`, `Dirent`: File system operations (`stat`, directory entries).
     - `Flock_t`: File locking (`flock`).
     - `RawSockaddr*`, `Iovec`, `Msghdr`, `Cmsghdr`: Network programming and socket-related system calls (`sendmsg`, `recvmsg`).
     - `PtraceRegs`: Process tracing (`ptrace`).
     - `FdSet`: File descriptor sets (`select`, `pselect`, `poll`).
     - `Sysinfo_t`: System information (`sysinfo`).
     - `EpollEvent`:  Epoll event notification (`epoll_wait`).
     - `Sigset_t`, `Siginfo`, `Termios`: Signal handling and terminal control.
     - `Taskstats`: Task statistics.
     - `SockaddrStorage`: Generic socket address structure.
     - `Statfs_t`: File system statistics (`statfs`).
     - `TpacketHdr`:  Packet socket header.
     - `RTCPLLInfo`: Real-time clock PLL information.
     - `BlkpgPartition`: Block device partition information.
     - `Crypto*`: Cryptographic API structures.
     - `LoopInfo`: Loop device information.
     - `TIPC*`:  Transparent Inter-Process Communication structures.
     - `PPSKInfo`: Pulse Per Second (PPS) kernel information.
     - `SysvIpcPerm`, `SysvShmDesc`: System V IPC structures (shared memory).

3. **Inferring the Overall Function:**

   - Based on the types and the generation method, I concluded that the file's primary function is to define the Go data structures that mirror corresponding C structures used in Linux system calls for the MIPS64 architecture. This allows Go programs to interact with the operating system at a low level.

4. **Constructing the Explanation:**

   - I started by stating the file's purpose clearly.
   - I listed the categories of functionalities, grouping related types together for better organization.
   - For each category, I mentioned relevant system calls or areas of operating system functionality.
   - I emphasized that this file *doesn't* implement the logic of system calls but provides the necessary data structures.

5. **Generating Go Code Examples:**

   - I selected a few representative examples that demonstrate how these types are used in conjunction with functions from the `syscall` or `golang.org/x/sys/unix` packages. I chose `Stat` for file information and `Gettimeofday` for time.
   - I included assumed input and output to make the examples concrete.

6. **Addressing Command-Line Arguments:**

   - I focused on the `cgo` command in the header, explaining its role in generating the file and highlighting the key arguments like `-godefs`, `-objdir`, `-I`, and the input C header file.

7. **Identifying Potential Pitfalls:**

   - I considered common errors when working with low-level system programming:
     - **Incorrect Size/Alignment:** This is a major reason for having architecture-specific files like this. I emphasized the importance of using these defined types to avoid size and alignment issues.
     - **Endianness:** While not explicitly shown in this file, it's a general concern when interacting with C structures from different architectures.
     - **Pointer Usage:**  Working with raw pointers requires careful attention to memory management and safety.
     - **Platform Differences:**  Code using these types is inherently platform-specific.

8. **Review and Refinement:**

   - I reviewed the entire response for clarity, accuracy, and completeness, making sure the language was precise and easy to understand. I ensured the code examples were correct and the explanations were logical.

Essentially, I leveraged my knowledge of operating systems, system programming, and the Go language to dissect the file, infer its purpose, and explain its significance within the Go ecosystem. The `cgo` comment was a crucial starting point, and recognizing the names of common C structures was key to understanding the types defined in the file.
这个 Go 语言文件的主要功能是为 `mips64` 架构的 Linux 系统定义了与 C 语言系统调用和底层数据结构相对应的 Go 类型和常量。由于 Go 语言可以直接调用 C 代码，为了保证数据结构在 Go 和 C 之间能够正确传递和解析，需要定义与 C 结构体布局一致的 Go 结构体。

**具体功能列举如下：**

1. **定义常量:**
   - `SizeofPtr`:  定义了指针的大小，在 `mips64` 架构上是 8 字节。
   - `SizeofLong`: 定义了 `long` 类型的大小，在 `mips64` 架构上是 8 字节。
   - 其他常量，例如 `FADV_DONTNEED`, `FADV_NOREUSE`, `OPEN_TREE_CLOEXEC`, `POLLRDHUP`, `SIG_BLOCK` 等，这些通常是 Linux 系统调用中使用的标志或选项。
   - 以 `Sizeof` 开头的常量，例如 `SizeofSockaddrNFCLLCP`, `SizeofIovec`, `SizeofMsghdr`, `SizeofCmsghdr`, `SizeofSockFprog`, `SizeofTpacketHdr`，定义了特定数据结构的大小。
   - 以 `_C__NSIG` 开头的常量，定义了信号的数量。

2. **定义类型:**
   - `_C_long`:  定义了与 C 语言 `long` 类型对应的 Go 类型 `int64`。
   - `Timespec`:  表示高精度的时间，通常用于系统调用中表示时间。
   - `Timeval`:  表示秒和微秒的时间，也是系统调用中常用的时间表示。
   - `Timex`:  用于微调系统时钟的结构体，与 `adjtimex` 系统调用相关。
   - `Time_t`:  表示时间类型，通常是秒数。
   - `Tms`:  用于获取进程的时间统计信息，与 `times` 系统调用相关。
   - `Utimbuf`:  用于设置文件的访问和修改时间，与 `utime` 系统调用相关。
   - `Rusage`:  包含进程的资源使用信息，与 `getrusage` 系统调用相关。
   - `Stat_t`:  包含文件或文件系统的状态信息，与 `stat`, `fstat`, `lstat` 等系统调用相关。
   - `Dirent`:  表示目录项，与读取目录的系统调用 (`readdir`) 相关。
   - `Flock_t`:  用于文件锁定的结构体，与 `fcntl` 系统调用配合使用。
   - `DmNameList`:  与设备映射 (Device Mapper) 相关。
   - `RawSockaddrNFCLLCP`, `RawSockaddr`, `RawSockaddrAny`:  与网络编程中的 socket 地址相关。
   - `Iovec`:  用于在 `readv` 和 `writev` 等 scatter/gather I/O 操作中描述内存块。
   - `Msghdr`, `Cmsghdr`:  用于高级 socket 通信，例如发送和接收辅助数据。
   - `ifreq`:  用于配置和获取网络接口信息的结构体，与 `ioctl` 系统调用配合使用。
   - `PtraceRegs`:  用于 `ptrace` 系统调用中获取和设置进程寄存器。
   - `FdSet`:  用于表示文件描述符集合，常用于 `select`, `pselect` 等系统调用。
   - `Sysinfo_t`:  包含系统总体信息的结构体，与 `sysinfo` 系统调用相关。
   - `Ustat_t`:  提供文件系统使用情况统计信息（已过时）。
   - `EpollEvent`:  用于 `epoll` 事件通知机制。
   - `Sigset_t`:  表示信号集合。
   - `Siginfo`:  包含信号的详细信息。
   - `Termios`:  用于配置终端接口。
   - `Taskstats`:  用于获取进程的详细统计信息。
   - `cpuMask`:  表示 CPU 掩码。
   - `SockaddrStorage`:  通用 socket 地址结构体，可以容纳各种 socket 地址类型。
   - `HDGeometry`:  用于获取硬盘几何信息（已过时）。
   - `Statfs_t`:  包含文件系统统计信息，与 `statfs` 系统调用相关。
   - `TpacketHdr`:  用于 packet socket。
   - `RTCPLLInfo`:  与实时时钟 (RTC) 的 PLL (锁相环) 相关。
   - `BlkpgPartition`:  与块设备分区相关。
   - `CryptoUserAlg`, `CryptoStat*`, `CryptoReport*`:  与 Linux 内核的加密 API (Crypto API) 相关。
   - `LoopInfo`:  用于配置 loop 设备。
   - `TIPCSubscr`, `TIPCSIOCLNReq`, `TIPCSIOCNodeIDReq`:  与 TIPC (Transparent Inter-Process Communication) 相关。
   - `PPSKInfo`:  与 PPS (Pulse Per Second) 时间同步相关。
   - `SysvIpcPerm`, `SysvShmDesc`:  与 System V IPC 机制中的共享内存相关。

**Go 语言功能实现示例：**

这个文件本身并不实现 Go 语言的特定功能，而是为其他 Go 代码提供与底层系统交互所需的数据结构定义。其他 Go 代码会使用这些类型来调用 `syscall` 或 `golang.org/x/sys/unix` 包中的函数，从而间接实现各种系统功能。

例如，获取文件信息的 `stat` 功能：

```go
package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"
)

func main() {
	filename := "/tmp/test.txt" // 假设存在一个名为 /tmp/test.txt 的文件

	var stat syscall.Stat_t
	err := syscall.Stat(filename, &stat)
	if err != nil {
		log.Fatalf("stat error: %v", err)
	}

	fmt.Printf("File: %s\n", filename)
	fmt.Printf("Size: %d bytes\n", stat.Size)
	fmt.Printf("Mode: 0%o\n", stat.Mode) // 以八进制显示权限
	fmt.Printf("UID: %d\n", stat.Uid)
	fmt.Printf("GID: %d\n", stat.Gid)
	fmt.Printf("Last Access Time: %v\n", syscall.NsecToTime(stat.Atim.Nsec))
	fmt.Printf("Last Modify Time: %v\n", syscall.NsecToTime(stat.Mtim.Nsec))
	fmt.Printf("Last Change Time: %v\n", syscall.NsecToTime(stat.Ctim.Nsec))
}
```

**假设的输入与输出：**

假设 `/tmp/test.txt` 是一个大小为 1024 字节，所有者 UID 为 1000，所属组 GID 为 100 的普通文件。

**可能的输出：**

```
File: /tmp/test.txt
Size: 1024 bytes
Mode: 0100644
UID: 1000
GID: 100
Last Access Time: 2023-10-27 10:00:00 +0000 UTC
Last Modify Time: 2023-10-26 18:30:00 +0000 UTC
Last Change Time: 2023-10-26 18:30:00 +0000 UTC
```

在这个例子中，`syscall.Stat_t` 类型（定义在 `ztypes_linux_mips64.go` 中）被用来接收 `syscall.Stat` 函数返回的文件状态信息。

**涉及命令行参数的具体处理：**

这个文件本身是由 `cgo` 命令生成的，其命令行参数如下：

```
cgo -godefs -objdir=/tmp/mips64/cgo -- -Wall -Werror -static -I/tmp/mips64/include linux/types.go | go run mkpost.go
```

- `cgo`:  Go 的 C 互操作工具。
- `-godefs`:  指示 `cgo` 生成 Go 定义。
- `-objdir=/tmp/mips64/cgo`:  指定生成的目标文件目录。
- `--`:  分隔 `cgo` 自身的参数和传递给 C 编译器的参数。
- `-Wall`:  启用所有警告。
- `-Werror`:  将所有警告视为错误。
- `-static`:  进行静态链接。
- `-I/tmp/mips64/include`:  指定 C 头文件搜索路径。
- `linux/types.go`:  一个（可能是临时的）包含 C 代码片段的文件，用于 `cgo` 生成 Go 定义。
- `| go run mkpost.go`:  将 `cgo` 的输出传递给 `mkpost.go` 脚本进行后处理。

这个命令的目的是从 C 头文件（通常是系统提供的，或者通过 `-I` 指定）中提取类型定义，并将其转换为 Go 代码。对于 `mips64` 架构的 Linux 系统，它会读取相关的 C 类型定义，并生成与这些定义匹配的 Go 结构体。

**使用者易犯错的点：**

1. **直接修改此文件:**  由于此文件是通过代码生成的，手动修改后可能会在下次重新生成时被覆盖。如果需要自定义类型或常量，应该修改生成过程或提供额外的定义。

2. **假设跨平台兼容性:**  此文件中的类型定义是针对 `mips64` 架构的 Linux 系统的。在其他架构或操作系统上，这些类型的大小、布局可能会不同。因此，直接使用这些类型编写的代码不具备跨平台兼容性。应该使用 `golang.org/x/sys/unix` 包中提供的平台无关的接口，或者在构建时根据目标平台选择相应的 `ztypes_*.go` 文件。

3. **不理解 C 和 Go 的内存布局差异:** 虽然 `cgo` 尝试生成匹配的 Go 结构体，但在某些复杂情况下，例如包含位域或联合体的 C 结构体，直接映射到 Go 可能会很困难或不可靠。开发者需要仔细理解 C 结构体的布局，并确保 Go 代码能够正确地与之交互。

总而言之，`ztypes_linux_mips64.go` 是 Go 语言与 `mips64` 架构 Linux 系统底层交互的桥梁，它定义了 Go 语言中用于表示操作系统数据结构的基础类型和常量，使得 Go 程序能够调用系统调用并操作底层资源。开发者通常不会直接修改或操作这个文件，而是通过 `syscall` 或 `golang.org/x/sys/unix` 等更高级别的包来间接使用其中定义的类型。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux_mips64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// cgo -godefs -objdir=/tmp/mips64/cgo -- -Wall -Werror -static -I/tmp/mips64/include linux/types.go | go run mkpost.go
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build mips64 && linux

package unix

const (
	SizeofPtr  = 0x8
	SizeofLong = 0x8
)

type (
	_C_long int64
)

type Timespec struct {
	Sec  int64
	Nsec int64
}

type Timeval struct {
	Sec  int64
	Usec int64
}

type Timex struct {
	Modes     uint32
	Offset    int64
	Freq      int64
	Maxerror  int64
	Esterror  int64
	Status    int32
	Constant  int64
	Precision int64
	Tolerance int64
	Time      Timeval
	Tick      int64
	Ppsfreq   int64
	Jitter    int64
	Shift     int32
	Stabil    int64
	Jitcnt    int64
	Calcnt    int64
	Errcnt    int64
	Stbcnt    int64
	Tai       int32
	_         [44]byte
}

type Time_t int64

type Tms struct {
	Utime  int64
	Stime  int64
	Cutime int64
	Cstime int64
}

type Utimbuf struct {
	Actime  int64
	Modtime int64
}

type Rusage struct {
	Utime    Timeval
	Stime    Timeval
	Maxrss   int64
	Ixrss    int64
	Idrss    int64
	Isrss    int64
	Minflt   int64
	Majflt   int64
	Nswap    int64
	Inblock  int64
	Oublock  int64
	Msgsnd   int64
	Msgrcv   int64
	Nsignals int64
	Nvcsw    int64
	Nivcsw   int64
}

type Stat_t struct {
	Dev     uint32
	Pad1    [3]uint32
	Ino     uint64
	Mode    uint32
	Nlink   uint32
	Uid     uint32
	Gid     uint32
	Rdev    uint32
	Pad2    [3]uint32
	Size    int64
	Atim    Timespec
	Mtim    Timespec
	Ctim    Timespec
	Blksize uint32
	Pad4    uint32
	Blocks  int64
}

type Dirent struct {
	Ino    uint64
	Off    int64
	Reclen uint16
	Type   uint8
	Name   [256]int8
	_      [5]byte
}

type Flock_t struct {
	Type   int16
	Whence int16
	Start  int64
	Len    int64
	Pid    int32
	_      [4]byte
}

type DmNameList struct {
	Dev  uint64
	Next uint32
	Name [0]byte
	_    [4]byte
}

const (
	FADV_DONTNEED = 0x4
	FADV_NOREUSE  = 0x5
)

type RawSockaddrNFCLLCP struct {
	Sa_family        uint16
	Dev_idx          uint32
	Target_idx       uint32
	Nfc_protocol     uint32
	Dsap             uint8
	Ssap             uint8
	Service_name     [63]uint8
	Service_name_len uint64
}

type RawSockaddr struct {
	Family uint16
	Data   [14]int8
}

type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [96]int8
}

type Iovec struct {
	Base *byte
	Len  uint64
}

type Msghdr struct {
	Name       *byte
	Namelen    uint32
	Iov        *Iovec
	Iovlen     uint64
	Control    *byte
	Controllen uint64
	Flags      int32
	_          [4]byte
}

type Cmsghdr struct {
	Len   uint64
	Level int32
	Type  int32
}

type ifreq struct {
	Ifrn [16]byte
	Ifru [24]byte
}

const (
	SizeofSockaddrNFCLLCP = 0x60
	SizeofIovec           = 0x10
	SizeofMsghdr          = 0x38
	SizeofCmsghdr         = 0x10
)

const (
	SizeofSockFprog = 0x10
)

type PtraceRegs struct {
	Regs     [32]uint64
	Lo       uint64
	Hi       uint64
	Epc      uint64
	Badvaddr uint64
	Status   uint64
	Cause    uint64
}

type FdSet struct {
	Bits [16]int64
}

type Sysinfo_t struct {
	Uptime    int64
	Loads     [3]uint64
	Totalram  uint64
	Freeram   uint64
	Sharedram uint64
	Bufferram uint64
	Totalswap uint64
	Freeswap  uint64
	Procs     uint16
	Pad       uint16
	Totalhigh uint64
	Freehigh  uint64
	Unit      uint32
	_         [0]int8
	_         [4]byte
}

type Ustat_t struct {
	Tfree  int32
	Tinode uint64
	Fname  [6]int8
	Fpack  [6]int8
	_      [4]byte
}

type EpollEvent struct {
	Events uint32
	_      int32
	Fd     int32
	Pad    int32
}

const (
	OPEN_TREE_CLOEXEC = 0x80000
)

const (
	POLLRDHUP = 0x2000
)

type Sigset_t struct {
	Val [16]uint64
}

const _C__NSIG = 0x80

const (
	SIG_BLOCK   = 0x1
	SIG_UNBLOCK = 0x2
	SIG_SETMASK = 0x3
)

type Siginfo struct {
	Signo int32
	Code  int32
	Errno int32
	_     int32
	_     [112]byte
}

type Termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [23]uint8
	Ispeed uint32
	Ospeed uint32
}

type Taskstats struct {
	Version                   uint16
	Ac_exitcode               uint32
	Ac_flag                   uint8
	Ac_nice                   uint8
	Cpu_count                 uint64
	Cpu_delay_total           uint64
	Blkio_count               uint64
	Blkio_delay_total         uint64
	Swapin_count              uint64
	Swapin_delay_total        uint64
	Cpu_run_real_total        uint64
	Cpu_run_virtual_total     uint64
	Ac_comm                   [32]int8
	Ac_sched                  uint8
	Ac_pad                    [3]uint8
	_                         [4]byte
	Ac_uid                    uint32
	Ac_gid                    uint32
	Ac_pid                    uint32
	Ac_ppid                   uint32
	Ac_btime                  uint32
	Ac_etime                  uint64
	Ac_utime                  uint64
	Ac_stime                  uint64
	Ac_minflt                 uint64
	Ac_majflt                 uint64
	Coremem                   uint64
	Virtmem                   uint64
	Hiwater_rss               uint64
	Hiwater_vm                uint64
	Read_char                 uint64
	Write_char                uint64
	Read_syscalls             uint64
	Write_syscalls            uint64
	Read_bytes                uint64
	Write_bytes               uint64
	Cancelled_write_bytes     uint64
	Nvcsw                     uint64
	Nivcsw                    uint64
	Ac_utimescaled            uint64
	Ac_stimescaled            uint64
	Cpu_scaled_run_real_total uint64
	Freepages_count           uint64
	Freepages_delay_total     uint64
	Thrashing_count           uint64
	Thrashing_delay_total     uint64
	Ac_btime64                uint64
	Compact_count             uint64
	Compact_delay_total       uint64
	Ac_tgid                   uint32
	Ac_tgetime                uint64
	Ac_exe_dev                uint64
	Ac_exe_inode              uint64
	Wpcopy_count              uint64
	Wpcopy_delay_total        uint64
	Irq_count                 uint64
	Irq_delay_total           uint64
}

type cpuMask uint64

const (
	_NCPUBITS = 0x40
)

const (
	CBitFieldMaskBit0  = 0x8000000000000000
	CBitFieldMaskBit1  = 0x4000000000000000
	CBitFieldMaskBit2  = 0x2000000000000000
	CBitFieldMaskBit3  = 0x1000000000000000
	CBitFieldMaskBit4  = 0x800000000000000
	CBitFieldMaskBit5  = 0x400000000000000
	CBitFieldMaskBit6  = 0x200000000000000
	CBitFieldMaskBit7  = 0x100000000000000
	CBitFieldMaskBit8  = 0x80000000000000
	CBitFieldMaskBit9  = 0x40000000000000
	CBitFieldMaskBit10 = 0x20000000000000
	CBitFieldMaskBit11 = 0x10000000000000
	CBitFieldMaskBit12 = 0x8000000000000
	CBitFieldMaskBit13 = 0x4000000000000
	CBitFieldMaskBit14 = 0x2000000000000
	CBitFieldMaskBit15 = 0x1000000000000
	CBitFieldMaskBit16 = 0x800000000000
	CBitFieldMaskBit17 = 0x400000000000
	CBitFieldMaskBit18 = 0x200000000000
	CBitFieldMaskBit19 = 0x100000000000
	CBitFieldMaskBit20 = 0x80000000000
	CBitFieldMaskBit21 = 0x40000000000
	CBitFieldMaskBit22 = 0x20000000000
	CBitFieldMaskBit23 = 0x10000000000
	CBitFieldMaskBit24 = 0x8000000000
	CBitFieldMaskBit25 = 0x4000000000
	CBitFieldMaskBit26 = 0x2000000000
	CBitFieldMaskBit27 = 0x1000000000
	CBitFieldMaskBit28 = 0x800000000
	CBitFieldMaskBit29 = 0x400000000
	CBitFieldMaskBit30 = 0x200000000
	CBitFieldMaskBit31 = 0x100000000
	CBitFieldMaskBit32 = 0x80000000
	CBitFieldMaskBit33 = 0x40000000
	CBitFieldMaskBit34 = 0x20000000
	CBitFieldMaskBit35 = 0x10000000
	CBitFieldMaskBit36 = 0x8000000
	CBitFieldMaskBit37 = 0x4000000
	CBitFieldMaskBit38 = 0x2000000
	CBitFieldMaskBit39 = 0x1000000
	CBitFieldMaskBit40 = 0x800000
	CBitFieldMaskBit41 = 0x400000
	CBitFieldMaskBit42 = 0x200000
	CBitFieldMaskBit43 = 0x100000
	CBitFieldMaskBit44 = 0x80000
	CBitFieldMaskBit45 = 0x40000
	CBitFieldMaskBit46 = 0x20000
	CBitFieldMaskBit47 = 0x10000
	CBitFieldMaskBit48 = 0x8000
	CBitFieldMaskBit49 = 0x4000
	CBitFieldMaskBit50 = 0x2000
	CBitFieldMaskBit51 = 0x1000
	CBitFieldMaskBit52 = 0x800
	CBitFieldMaskBit53 = 0x400
	CBitFieldMaskBit54 = 0x200
	CBitFieldMaskBit55 = 0x100
	CBitFieldMaskBit56 = 0x80
	CBitFieldMaskBit57 = 0x40
	CBitFieldMaskBit58 = 0x20
	CBitFieldMaskBit59 = 0x10
	CBitFieldMaskBit60 = 0x8
	CBitFieldMaskBit61 = 0x4
	CBitFieldMaskBit62 = 0x2
	CBitFieldMaskBit63 = 0x1
)

type SockaddrStorage struct {
	Family uint16
	Data   [118]byte
	_      uint64
}

type HDGeometry struct {
	Heads     uint8
	Sectors   uint8
	Cylinders uint16
	Start     uint64
}

type Statfs_t struct {
	Type    int64
	Bsize   int64
	Frsize  int64
	Blocks  uint64
	Bfree   uint64
	Files   uint64
	Ffree   uint64
	Bavail  uint64
	Fsid    Fsid
	Namelen int64
	Flags   int64
	Spare   [5]int64
}

type TpacketHdr struct {
	Status  uint64
	Len     uint32
	Snaplen uint32
	Mac     uint16
	Net     uint16
	Sec     uint32
	Usec    uint32
	_       [4]byte
}

const (
	SizeofTpacketHdr = 0x20
)

type RTCPLLInfo struct {
	Ctrl    int32
	Value   int32
	Max     int32
	Min     int32
	Posmult int32
	Negmult int32
	Clock   int64
}

type BlkpgPartition struct {
	Start   int64
	Length  int64
	Pno     int32
	Devname [64]uint8
	Volname [64]uint8
	_       [4]byte
}

const (
	BLKPG = 0x20001269
)

type CryptoUserAlg struct {
	Name        [64]int8
	Driver_name [64]int8
	Module_name [64]int8
	Type        uint32
	Mask        uint32
	Refcnt      uint32
	Flags       uint32
}

type CryptoStatAEAD struct {
	Type         [64]int8
	Encrypt_cnt  uint64
	Encrypt_tlen uint64
	Decrypt_cnt  uint64
	Decrypt_tlen uint64
	Err_cnt      uint64
}

type CryptoStatAKCipher struct {
	Type         [64]int8
	Encrypt_cnt  uint64
	Encrypt_tlen uint64
	Decrypt_cnt  uint64
	Decrypt_tlen uint64
	Verify_cnt   uint64
	Sign_cnt     uint64
	Err_cnt      uint64
}

type CryptoStatCipher struct {
	Type         [64]int8
	Encrypt_cnt  uint64
	Encrypt_tlen uint64
	Decrypt_cnt  uint64
	Decrypt_tlen uint64
	Err_cnt      uint64
}

type CryptoStatCompress struct {
	Type            [64]int8
	Compress_cnt    uint64
	Compress_tlen   uint64
	Decompress_cnt  uint64
	Decompress_tlen uint64
	Err_cnt         uint64
}

type CryptoStatHash struct {
	Type      [64]int8
	Hash_cnt  uint64
	Hash_tlen uint64
	Err_cnt   uint64
}

type CryptoStatKPP struct {
	Type                      [64]int8
	Setsecret_cnt             uint64
	Generate_public_key_cnt   uint64
	Compute_shared_secret_cnt uint64
	Err_cnt                   uint64
}

type CryptoStatRNG struct {
	Type          [64]int8
	Generate_cnt  uint64
	Generate_tlen uint64
	Seed_cnt      uint64
	Err_cnt       uint64
}

type CryptoStatLarval struct {
	Type [64]int8
}

type CryptoReportLarval struct {
	Type [64]int8
}

type CryptoReportHash struct {
	Type       [64]int8
	Blocksize  uint32
	Digestsize uint32
}

type CryptoReportCipher struct {
	Type        [64]int8
	Blocksize   uint32
	Min_keysize uint32
	Max_keysize uint32
}

type CryptoReportBlkCipher struct {
	Type        [64]int8
	Geniv       [64]int8
	Blocksize   uint32
	Min_keysize uint32
	Max_keysize uint32
	Ivsize      uint32
}

type CryptoReportAEAD struct {
	Type        [64]int8
	Geniv       [64]int8
	Blocksize   uint32
	Maxauthsize uint32
	Ivsize      uint32
}

type CryptoReportComp struct {
	Type [64]int8
}

type CryptoReportRNG struct {
	Type     [64]int8
	Seedsize uint32
}

type CryptoReportAKCipher struct {
	Type [64]int8
}

type CryptoReportKPP struct {
	Type [64]int8
}

type CryptoReportAcomp struct {
	Type [64]int8
}

type LoopInfo struct {
	Number           int32
	Device           uint32
	Inode            uint64
	Rdevice          uint32
	Offset           int32
	Encrypt_type     int32
	Encrypt_key_size int32
	Flags            int32
	Name             [64]int8
	Encrypt_key      [32]uint8
	Init             [2]uint64
	Reserved         [4]int8
	_                [4]byte
}

type TIPCSubscr struct {
	Seq     TIPCServiceRange
	Timeout uint32
	Filter  uint32
	Handle  [8]int8
}

type TIPCSIOCLNReq struct {
	Peer     uint32
	Id       uint32
	Linkname [68]int8
}

type TIPCSIOCNodeIDReq struct {
	Peer uint32
	Id   [16]int8
}

type PPSKInfo struct {
	Assert_sequence uint32
	Clear_sequence  uint32
	Assert_tu       PPSKTime
	Clear_tu        PPSKTime
	Current_mode    int32
	_               [4]byte
}

const (
	PPS_GETPARAMS = 0x400870a1
	PPS_SETPARAMS = 0x800870a2
	PPS_GETCAP    = 0x400870a3
	PPS_FETCH     = 0xc00870a4
)

const (
	PIDFD_NONBLOCK = 0x80
)

type SysvIpcPerm struct {
	Key  int32
	Uid  uint32
	Gid  uint32
	Cuid uint32
	Cgid uint32
	Mode uint32
	_    [0]uint8
	Seq  uint16
	_    uint16
	_    uint64
	_    uint64
}
type SysvShmDesc struct {
	Perm   SysvIpcPerm
	Segsz  uint64
	Atime  int64
	Dtime  int64
	Ctime  int64
	Cpid   int32
	Lpid   int32
	Nattch uint64
	_      uint64
	_      uint64
}
```