Response:
Let's break down the thought process to arrive at the answer.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, specifically the `go/src/internal/syscall/windows/syscall_windows.go` file. It wants a summary of what the code does, examples of its usage, potential pitfalls, and all in Chinese.

2. **Initial Scan and Categorization:**  Read through the code and identify major categories of elements. I see:
    * **Imports:** `sync`, `syscall`, `unsafe`. This immediately suggests low-level interaction with the OS and concurrency management.
    * **Global Variables:** `CanUseLongPaths`, `sendRecvMsgFunc`. These control specific behaviors or store state.
    * **Constants:**  Large blocks of constants starting with `ERROR_`, `GAA_FLAG_`, `IF_TYPE_`, `TH32CS_`, `WSA_FLAG_`, etc. This screams "Windows API constants" related to error codes, network configuration, process handling, and sockets.
    * **Structs:** `SocketAddress`, `IpAdapterAddresses`, `SecurityAttributes`, `FILE_BASIC_INFO`, `ModuleEntry32`, `WSAMsg`, `SHARE_INFO_2`, `FILE_ID_BOTH_DIR_INFO`, `FILE_FULL_DIR_INFO`, `SERVICE_STATUS`. These represent data structures used in Windows system calls.
    * **System Calls (//sys):**  Lines like `//sys GetAdaptersAddresses(...)`. These are direct bindings to Windows API functions. This is a *key* part of the file's functionality.
    * **Regular Functions:**  `UTF16PtrToString`, `Rename`, `loadWSASendRecvMsg`, `WSASendMsg`, `WSARecvMsg`, `FinalPath`, `langID`. These are helper functions built on top of the system calls.
    * **Linkname Directives:** `//go:linkname`. This indicates that certain functions (like `QueryPerformanceCounter` and `QueryPerformanceFrequency`) are implemented elsewhere (in the `runtime` package).
    * **NT Status Related:** `NTStatus` type, `rtlNtStatusToDosErrorNoTeb`, and `STATUS_` constants. This points to interacting with lower-level NT kernel APIs.

3. **Focus on Key Functionality Areas:** Based on the categorization, I can group the functionality into logical areas:

    * **String Conversion:** `UTF16PtrToString`. Essential for dealing with Windows' UTF-16 encoded strings.
    * **Error Handling:** The `ERROR_` constants define common Windows error codes. The `NTStatus` type and related functions handle more specific NT kernel errors.
    * **Network Information:**  `IpAdapterAddresses` and related structs, `GetAdaptersAddresses`. This is clearly about retrieving network adapter configuration.
    * **Process and Module Handling:** `ModuleEntry32`, `Module32First`, `Module32Next`. This is about enumerating loaded modules in a process.
    * **Socket Programming:** `WSASocket`, `WSASendMsg`, `WSARecvMsg`, `WSAID_WSASENDMSG`, `WSAID_WSARECVMSG`, `WSAMsg`. This is for advanced socket operations, likely including features like sending and receiving control messages.
    * **File System Operations:** `MoveFileEx`, `Rename`, `LockFileEx`, `UnlockFileEx`, `GetFinalPathNameByHandle`, `FILE_BASIC_INFO`, `FILE_ID_BOTH_DIR_INFO`, `FILE_FULL_DIR_INFO`, `GetVolumeInformationByHandle`, `GetVolumeNameForVolumeMountPoint`. This covers file renaming, locking, getting canonical paths, and file/volume information.
    * **Computer and Environment Information:** `GetComputerNameEx`, `CreateEnvironmentBlock`, `DestroyEnvironmentBlock`. Getting computer names and managing environment variables.
    * **Service Management:** `SERVICE_STATUS`, `OpenService`, `QueryServiceStatus`, `OpenSCManager`. Interacting with Windows services.
    * **Time/Performance Counters:** `QueryPerformanceCounter`, `QueryPerformanceFrequency`. Accessing high-resolution timers.
    * **Low-Level NT APIs:**  `NtCreateFile`, `NtOpenFile`, `NtSetInformationFile`. Direct interaction with the NT kernel.

4. **Explain Each Area with Examples (Where Applicable):** For each functional area, try to provide a concise explanation in Chinese. Where it's straightforward, give a simple Go code example.

    * **String Conversion:**  Easy to demonstrate.
    * **Error Handling:**  Show how to check for specific error codes.
    * **Network Information:** Show how to iterate through network adapters (even without providing a fully runnable example, the *structure* is important). Mention the flags for more advanced usage.
    * **Process and Module Handling:** Briefly illustrate the snapshot and iteration process.
    * **Socket Programming:** Focus on the `WSASendMsg`/`WSARecvMsg` functions and their purpose (sending/receiving with control data).
    * **File System Operations:** Give examples of renaming and locking files.
    * **Computer and Environment Information:** Show how to get the computer name.
    * **Service Management:**  Illustrate opening and querying a service.
    * **Time/Performance Counters:**  Mention their use in benchmarking.
    * **Low-Level NT APIs:** Explain their nature as direct kernel interaction.

5. **Address Specific Instructions:**

    * **"推理出它是什么go语言功能的实现" (Infer Go features implemented):** This is about understanding *why* this code exists. It's implementing parts of the `os`, `syscall`, and `net` packages for Windows.
    * **"如果涉及代码推理，需要带上假设的输入与输出" (If code inference is involved, include assumed input and output):** For the examples, provide plausible input values and describe the expected output.
    * **"如果涉及命令行参数的具体处理，请详细介绍一下" (If command-line parameter handling is involved, explain it in detail):**  This file doesn't directly handle command-line arguments. State this explicitly.
    * **"如果有哪些使用者易犯错的点，请举例说明" (If there are common user errors, provide examples):**  Think about the common pitfalls of working with syscalls: incorrect string conversion, forgetting error checking, and the complexities of network programming.

6. **Structure and Refine the Answer:** Organize the information logically using headings and bullet points. Use clear and concise Chinese. Review and refine the language for accuracy and clarity. Ensure all parts of the original request are addressed. For example, double-check if "功能 (functions)" was fully covered and if the examples were helpful. Make sure to explicitly state when something *isn't* present (like command-line argument handling).

7. **Self-Correction Example During the Process:** Initially, I might have focused too much on listing every single constant and struct. However, the request emphasizes *functionality*. So, I'd shift the focus to the *actions* the code enables, using the constants and structs as supporting details. I might also initially forget to mention the `//go:linkname` aspect, so a review would catch that. Similarly, the explanation of `WSASendMsg` and `WSARecvMsg` needs to highlight their *specialized* nature compared to regular `send` and `recv`.

By following these steps, I can build a comprehensive and accurate answer that addresses all aspects of the prompt. The key is to break down the code into manageable parts, understand the underlying concepts, and communicate that understanding clearly with relevant examples.
这个 `go/src/internal/syscall/windows/syscall_windows.go` 文件是 Go 语言标准库中 `syscall` 包在 Windows 平台上的底层实现部分。它主要负责直接调用 Windows API (Win32 API 或 NT API)，让 Go 程序能够执行底层的操作系统操作。

以下是它的主要功能分解：

**1. 提供访问 Windows 系统调用的接口:**

   - **直接系统调用绑定 (`//sys`)**:  文件中大量使用了 `//sys` 注释，这表明这些 Go 函数直接对应底层的 Windows API 函数。例如：
     ```go
     //sys	GetAdaptersAddresses(family uint32, flags uint32, reserved uintptr, adapterAddresses *IpAdapterAddresses, sizePointer *uint32) (errcode error) = iphlpapi.GetAdaptersAddresses
     ```
     这行代码将 Go 函数 `GetAdaptersAddresses` 绑定到 Windows 的 `iphlpapi.dll` 中的 `GetAdaptersAddresses` 函数。Go 代码调用 `GetAdaptersAddresses` 时，实际上会执行底层的 Windows API 函数。

   - **结构体定义**: 定义了许多与 Windows API 交互时需要用到的数据结构，例如：`IpAdapterAddresses` (网络适配器信息), `SecurityAttributes` (安全属性), `FILE_BASIC_INFO` (文件基本信息), `ModuleEntry32` (模块信息), `WSAMsg` (Winsock 消息) 等。这些结构体与 Windows API 中对应的结构体一一对应。

   - **常量定义**: 定义了大量的 Windows API 常量，例如错误码 (`ERROR_BAD_LENGTH`), 网络适配器类型 (`IF_TYPE_ETHERNET_CSMACD`), 文件操作标志 (`MOVEFILE_REPLACE_EXISTING`), 套接字标志 (`WSA_FLAG_OVERLAPPED`) 等。这些常量在调用 Windows API 时作为参数使用。

**2. 实现 Go 语言层面的特定功能:**

   - **长路径支持 (`CanUseLongPaths`)**:  该变量指示操作系统是否原生支持长路径，而无需进行额外的处理。Go 的文件操作相关功能会根据这个值来决定如何处理长路径。

   - **UTF-16 字符串转换 (`UTF16PtrToString`)**: Windows API 很多字符串使用 UTF-16 编码。这个函数将指向 UTF-16 字符串的指针转换为 Go 的 `string` 类型。

   - **文件重命名 (`Rename`)**:  封装了 `MoveFileExW` API，并提供了更符合 Go 习惯的 `Rename` 函数。

   - **文件锁 (`LockFileEx`, `UnlockFileEx`)**:  提供了在文件上加锁和解锁的功能，用于实现文件互斥访问。

   - **获取最终路径名 (`FinalPath`)**:  使用 `GetFinalPathNameByHandleW` API 获取文件的规范化绝对路径。

   - **获取计算机名称 (`GetComputerNameEx`)**: 允许获取不同格式的计算机名称。

   - **模块枚举 (`Module32First`, `Module32Next`)**:  用于遍历进程中加载的模块 (DLL)。

   - **高级套接字操作 (`WSASocket`, `WSASendMsg`, `WSARecvMsg`)**: 提供了使用 `WSA` (Windows Sockets Asynchronous) 模型进行高级套接字操作的接口，例如发送和接收控制信息。

   - **性能计数器 (`QueryPerformanceCounter`, `QueryPerformanceFrequency`)**:  这两个函数（通过 `//go:linkname` 链接到 `runtime` 包中的实现）用于获取高精度的时间戳，常用于性能测试和基准测试。

   - **NT 状态码处理 (`NTStatus`)**: 定义了表示 NT 内核返回状态码的类型，并提供了将其转换为 `syscall.Errno` 的方法。这用于处理一些更底层的 API 调用返回的错误。

**3. 示例：获取网络适配器信息**

假设我们想获取计算机的网络适配器信息，我们可以使用 `GetAdaptersAddresses` 函数。

```go
package main

import (
	"fmt"
	"internal/syscall/windows"
	"syscall"
	"unsafe"
)

func main() {
	var size uint32 = 15000 // 初始大小，如果不够会被系统修改
	var adapters *windows.IpAdapterAddresses
	err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX|windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, adapters, &size)
	if err == syscall.ERROR_BUFFER_OVERFLOW {
		adapters = (*windows.IpAdapterAddresses)(unsafe.Pointer(syscall.MustSyscall(syscall.VirtualAlloc(0, uintptr(size), syscall.MEM_COMMIT|syscall.MEM_RESERVE, syscall.PAGE_READWRITE))))
		err = windows.GetAdaptersAddresses(syscall.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX|windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, adapters, &size)
	}
	if err != nil {
		fmt.Println("获取适配器信息失败:", err)
		return
	}
	defer syscall.VirtualFree(unsafe.Pointer(adapters), 0, syscall.MEM_RELEASE)

	a := adapters
	for a != nil {
		fmt.Printf("适配器名称: %s\n", syscall.UTF16ToString((*[syscall.MAX_ADAPTER_DESCRIPTION_LENGTH]uint16)(unsafe.Pointer(a.Description))[:]))
		unicast := a.FirstUnicastAddress
		for unicast != nil {
			addr, _ := syscall.SockaddrInet4FromRaw(unicast.Address.Sockaddr)
			if addr != nil {
				fmt.Printf("  IP 地址: %s\n", addr.Addr.String())
			} else {
				addr6, _ := syscall.SockaddrInet6FromRaw(unicast.Address.Sockaddr)
				if addr6 != nil {
					fmt.Printf("  IPv6 地址: %s\n", addr6.Addr.String())
				}
			}
			unicast = unicast.Next
		}
		gateway := a.FirstGatewayAddress
		for gateway != nil {
			addr, _ := syscall.SockaddrInet4FromRaw(gateway.Address.Sockaddr)
			if addr != nil {
				fmt.Printf("  网关: %s\n", addr.Addr.String())
			} else {
				addr6, _ := syscall.SockaddrInet6FromRaw(gateway.Address.Sockaddr)
				if addr6 != nil {
					fmt.Printf("  IPv6 网关: %s\n", addr6.Addr.String())
				}
			}
			gateway = gateway.Next
		}
		fmt.Println("---")
		a = a.Next
	}
}
```

**假设的输入与输出：**

这个例子没有直接的外部输入（如命令行参数）。它的输入是计算机的网络配置信息。

输出会类似：

```
适配器名称: Realtek PCIe GbE Family Controller
  IP 地址: 192.168.1.100
  网关: 192.168.1.1
---
适配器名称: Microsoft Wi-Fi Direct Virtual Adapter
---
适配器名称: VMware Virtual Ethernet Adapter for VMnet8
  IP 地址: 172.16.187.1
  网关: 172.16.187.2
---
...
```

**4. 命令行参数处理：**

这个文件本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 包中，然后可能会调用 `syscall` 包中的函数来执行与操作系统相关的操作。

**5. 使用者易犯错的点：**

- **字符串编码**:  忘记 Windows API 使用 UTF-16 编码，直接传递 Go 的 UTF-8 字符串可能导致乱码或错误。必须使用 `syscall.UTF16PtrFromString` 将 Go 字符串转换为 UTF-16 指针。

  ```go
  // 错误示例
  // err := windows.MoveFileEx([]byte(oldPath), []byte(newPath), windows.MOVEFILE_REPLACE_EXISTING)

  // 正确示例
  oldPathUTF16, _ := syscall.UTF16PtrFromString(oldPath)
  newPathUTF16, _ := syscall.UTF16PtrFromString(newPath)
  err := windows.MoveFileEx(oldPathUTF16, newPathUTF16, windows.MOVEFILE_REPLACE_EXISTING)
  ```

- **错误处理**:  调用 Windows API 后必须检查返回值（通常是 `error` 类型），以确定操作是否成功。忽略错误可能导致程序行为不符合预期。

  ```go
  handle, err := syscall.CreateFile(filename, ...)
  if err != nil {
      // 处理错误
      fmt.Println("创建文件失败:", err)
      return
  }
  defer syscall.CloseHandle(handle)
  ```

- **内存管理**:  在某些情况下，需要自己分配和释放内存，例如在使用 `GetAdaptersAddresses` 时，可能需要先调用一次获取所需缓冲区大小，然后分配缓冲区，再调用一次获取数据。忘记释放分配的内存会导致内存泄漏。

- **结构体字段对齐**:  与 Windows API 交互时，定义的 Go 结构体必须与 Windows 中对应的结构体在内存布局上完全一致，包括字段顺序和对齐方式。`FILE_BASIC_INFO` 结构体中的匿名 `uint32` 字段就是一个为了保证 8 字节对齐的填充。

- **权限问题**:  某些 Windows API 需要特定的权限才能调用成功。如果程序没有足够的权限，调用会失败并返回相应的错误码。

总而言之，`go/src/internal/syscall/windows/syscall_windows.go` 是 Go 语言与 Windows 操作系统交互的桥梁，它通过直接调用 Windows API 实现了许多底层功能，使得 Go 程序能够在 Windows 平台上执行各种系统级操作。开发者在使用 `syscall` 包与 Windows 交互时，需要特别注意字符串编码、错误处理和内存管理等问题。

### 提示词
```
这是路径为go/src/internal/syscall/windows/syscall_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package windows

import (
	"sync"
	"syscall"
	"unsafe"
)

// CanUseLongPaths is true when the OS supports opting into
// proper long path handling without the need for fixups.
//
//go:linkname CanUseLongPaths
var CanUseLongPaths bool

// UTF16PtrToString is like UTF16ToString, but takes *uint16
// as a parameter instead of []uint16.
func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	n := 0
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}

const (
	ERROR_BAD_LENGTH             syscall.Errno = 24
	ERROR_SHARING_VIOLATION      syscall.Errno = 32
	ERROR_LOCK_VIOLATION         syscall.Errno = 33
	ERROR_NOT_SUPPORTED          syscall.Errno = 50
	ERROR_CALL_NOT_IMPLEMENTED   syscall.Errno = 120
	ERROR_INVALID_NAME           syscall.Errno = 123
	ERROR_LOCK_FAILED            syscall.Errno = 167
	ERROR_NO_TOKEN               syscall.Errno = 1008
	ERROR_NO_UNICODE_TRANSLATION syscall.Errno = 1113
	ERROR_CANT_ACCESS_FILE       syscall.Errno = 1920
)

const (
	GAA_FLAG_INCLUDE_PREFIX   = 0x00000010
	GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
)

const (
	IF_TYPE_OTHER              = 1
	IF_TYPE_ETHERNET_CSMACD    = 6
	IF_TYPE_ISO88025_TOKENRING = 9
	IF_TYPE_PPP                = 23
	IF_TYPE_SOFTWARE_LOOPBACK  = 24
	IF_TYPE_ATM                = 37
	IF_TYPE_IEEE80211          = 71
	IF_TYPE_TUNNEL             = 131
	IF_TYPE_IEEE1394           = 144
)

type SocketAddress struct {
	Sockaddr       *syscall.RawSockaddrAny
	SockaddrLength int32
}

type IpAdapterUnicastAddress struct {
	Length             uint32
	Flags              uint32
	Next               *IpAdapterUnicastAddress
	Address            SocketAddress
	PrefixOrigin       int32
	SuffixOrigin       int32
	DadState           int32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	LeaseLifetime      uint32
	OnLinkPrefixLength uint8
}

type IpAdapterAnycastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *IpAdapterAnycastAddress
	Address SocketAddress
}

type IpAdapterMulticastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *IpAdapterMulticastAddress
	Address SocketAddress
}

type IpAdapterDnsServerAdapter struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterDnsServerAdapter
	Address  SocketAddress
}

type IpAdapterPrefix struct {
	Length       uint32
	Flags        uint32
	Next         *IpAdapterPrefix
	Address      SocketAddress
	PrefixLength uint32
}

type IpAdapterWinsServerAddress struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterWinsServerAddress
	Address  SocketAddress
}

type IpAdapterGatewayAddress struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterGatewayAddress
	Address  SocketAddress
}

type IpAdapterAddresses struct {
	Length                 uint32
	IfIndex                uint32
	Next                   *IpAdapterAddresses
	AdapterName            *byte
	FirstUnicastAddress    *IpAdapterUnicastAddress
	FirstAnycastAddress    *IpAdapterAnycastAddress
	FirstMulticastAddress  *IpAdapterMulticastAddress
	FirstDnsServerAddress  *IpAdapterDnsServerAdapter
	DnsSuffix              *uint16
	Description            *uint16
	FriendlyName           *uint16
	PhysicalAddress        [syscall.MAX_ADAPTER_ADDRESS_LENGTH]byte
	PhysicalAddressLength  uint32
	Flags                  uint32
	Mtu                    uint32
	IfType                 uint32
	OperStatus             uint32
	Ipv6IfIndex            uint32
	ZoneIndices            [16]uint32
	FirstPrefix            *IpAdapterPrefix
	TransmitLinkSpeed      uint64
	ReceiveLinkSpeed       uint64
	FirstWinsServerAddress *IpAdapterWinsServerAddress
	FirstGatewayAddress    *IpAdapterGatewayAddress
	/* more fields might be present here. */
}

type SecurityAttributes struct {
	Length             uint16
	SecurityDescriptor uintptr
	InheritHandle      bool
}

type FILE_BASIC_INFO struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangedTime    int64
	FileAttributes uint32

	// Pad out to 8-byte alignment.
	//
	// Without this padding, TestChmod fails due to an argument validation error
	// in SetFileInformationByHandle on windows/386.
	//
	// https://learn.microsoft.com/en-us/cpp/build/reference/zp-struct-member-alignment?view=msvc-170
	// says that “The C/C++ headers in the Windows SDK assume the platform's
	// default alignment is used.” What we see here is padding rather than
	// alignment, but maybe it is related.
	_ uint32
}

const (
	IfOperStatusUp             = 1
	IfOperStatusDown           = 2
	IfOperStatusTesting        = 3
	IfOperStatusUnknown        = 4
	IfOperStatusDormant        = 5
	IfOperStatusNotPresent     = 6
	IfOperStatusLowerLayerDown = 7
)

//sys	GetAdaptersAddresses(family uint32, flags uint32, reserved uintptr, adapterAddresses *IpAdapterAddresses, sizePointer *uint32) (errcode error) = iphlpapi.GetAdaptersAddresses
//sys	GetComputerNameEx(nameformat uint32, buf *uint16, n *uint32) (err error) = GetComputerNameExW
//sys	MoveFileEx(from *uint16, to *uint16, flags uint32) (err error) = MoveFileExW
//sys	GetModuleFileName(module syscall.Handle, fn *uint16, len uint32) (n uint32, err error) = kernel32.GetModuleFileNameW
//sys	SetFileInformationByHandle(handle syscall.Handle, fileInformationClass uint32, buf unsafe.Pointer, bufsize uint32) (err error) = kernel32.SetFileInformationByHandle
//sys	VirtualQuery(address uintptr, buffer *MemoryBasicInformation, length uintptr) (err error) = kernel32.VirtualQuery
//sys	GetTempPath2(buflen uint32, buf *uint16) (n uint32, err error) = GetTempPath2W

const (
	// flags for CreateToolhelp32Snapshot
	TH32CS_SNAPMODULE   = 0x08
	TH32CS_SNAPMODULE32 = 0x10
)

const MAX_MODULE_NAME32 = 255

type ModuleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	ModuleHandle syscall.Handle
	Module       [MAX_MODULE_NAME32 + 1]uint16
	ExePath      [syscall.MAX_PATH]uint16
}

const SizeofModuleEntry32 = unsafe.Sizeof(ModuleEntry32{})

//sys	Module32First(snapshot syscall.Handle, moduleEntry *ModuleEntry32) (err error) = kernel32.Module32FirstW
//sys	Module32Next(snapshot syscall.Handle, moduleEntry *ModuleEntry32) (err error) = kernel32.Module32NextW

const (
	WSA_FLAG_OVERLAPPED        = 0x01
	WSA_FLAG_NO_HANDLE_INHERIT = 0x80

	WSAEINVAL       syscall.Errno = 10022
	WSAEMSGSIZE     syscall.Errno = 10040
	WSAEAFNOSUPPORT syscall.Errno = 10047

	MSG_PEEK   = 0x2
	MSG_TRUNC  = 0x0100
	MSG_CTRUNC = 0x0200

	socket_error = uintptr(^uint32(0))
)

var WSAID_WSASENDMSG = syscall.GUID{
	Data1: 0xa441e712,
	Data2: 0x754f,
	Data3: 0x43ca,
	Data4: [8]byte{0x84, 0xa7, 0x0d, 0xee, 0x44, 0xcf, 0x60, 0x6d},
}

var WSAID_WSARECVMSG = syscall.GUID{
	Data1: 0xf689d7c8,
	Data2: 0x6f1f,
	Data3: 0x436b,
	Data4: [8]byte{0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22},
}

var sendRecvMsgFunc struct {
	once     sync.Once
	sendAddr uintptr
	recvAddr uintptr
	err      error
}

type WSAMsg struct {
	Name        syscall.Pointer
	Namelen     int32
	Buffers     *syscall.WSABuf
	BufferCount uint32
	Control     syscall.WSABuf
	Flags       uint32
}

//sys	WSASocket(af int32, typ int32, protocol int32, protinfo *syscall.WSAProtocolInfo, group uint32, flags uint32) (handle syscall.Handle, err error) [failretval==syscall.InvalidHandle] = ws2_32.WSASocketW
//sys	WSAGetOverlappedResult(h syscall.Handle, o *syscall.Overlapped, bytes *uint32, wait bool, flags *uint32) (err error) = ws2_32.WSAGetOverlappedResult

func loadWSASendRecvMsg() error {
	sendRecvMsgFunc.once.Do(func() {
		var s syscall.Handle
		s, sendRecvMsgFunc.err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if sendRecvMsgFunc.err != nil {
			return
		}
		defer syscall.CloseHandle(s)
		var n uint32
		sendRecvMsgFunc.err = syscall.WSAIoctl(s,
			syscall.SIO_GET_EXTENSION_FUNCTION_POINTER,
			(*byte)(unsafe.Pointer(&WSAID_WSARECVMSG)),
			uint32(unsafe.Sizeof(WSAID_WSARECVMSG)),
			(*byte)(unsafe.Pointer(&sendRecvMsgFunc.recvAddr)),
			uint32(unsafe.Sizeof(sendRecvMsgFunc.recvAddr)),
			&n, nil, 0)
		if sendRecvMsgFunc.err != nil {
			return
		}
		sendRecvMsgFunc.err = syscall.WSAIoctl(s,
			syscall.SIO_GET_EXTENSION_FUNCTION_POINTER,
			(*byte)(unsafe.Pointer(&WSAID_WSASENDMSG)),
			uint32(unsafe.Sizeof(WSAID_WSASENDMSG)),
			(*byte)(unsafe.Pointer(&sendRecvMsgFunc.sendAddr)),
			uint32(unsafe.Sizeof(sendRecvMsgFunc.sendAddr)),
			&n, nil, 0)
	})
	return sendRecvMsgFunc.err
}

func WSASendMsg(fd syscall.Handle, msg *WSAMsg, flags uint32, bytesSent *uint32, overlapped *syscall.Overlapped, croutine *byte) error {
	err := loadWSASendRecvMsg()
	if err != nil {
		return err
	}
	r1, _, e1 := syscall.Syscall6(sendRecvMsgFunc.sendAddr, 6, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(flags), uintptr(unsafe.Pointer(bytesSent)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return err
}

func WSARecvMsg(fd syscall.Handle, msg *WSAMsg, bytesReceived *uint32, overlapped *syscall.Overlapped, croutine *byte) error {
	err := loadWSASendRecvMsg()
	if err != nil {
		return err
	}
	r1, _, e1 := syscall.Syscall6(sendRecvMsgFunc.recvAddr, 5, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(bytesReceived)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)), 0)
	if r1 == socket_error {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return err
}

const (
	ComputerNameNetBIOS                   = 0
	ComputerNameDnsHostname               = 1
	ComputerNameDnsDomain                 = 2
	ComputerNameDnsFullyQualified         = 3
	ComputerNamePhysicalNetBIOS           = 4
	ComputerNamePhysicalDnsHostname       = 5
	ComputerNamePhysicalDnsDomain         = 6
	ComputerNamePhysicalDnsFullyQualified = 7
	ComputerNameMax                       = 8

	MOVEFILE_REPLACE_EXISTING      = 0x1
	MOVEFILE_COPY_ALLOWED          = 0x2
	MOVEFILE_DELAY_UNTIL_REBOOT    = 0x4
	MOVEFILE_WRITE_THROUGH         = 0x8
	MOVEFILE_CREATE_HARDLINK       = 0x10
	MOVEFILE_FAIL_IF_NOT_TRACKABLE = 0x20
)

func Rename(oldpath, newpath string) error {
	from, err := syscall.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	return MoveFileEx(from, to, MOVEFILE_REPLACE_EXISTING)
}

//sys LockFileEx(file syscall.Handle, flags uint32, reserved uint32, bytesLow uint32, bytesHigh uint32, overlapped *syscall.Overlapped) (err error) = kernel32.LockFileEx
//sys UnlockFileEx(file syscall.Handle, reserved uint32, bytesLow uint32, bytesHigh uint32, overlapped *syscall.Overlapped) (err error) = kernel32.UnlockFileEx

const (
	LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
	LOCKFILE_EXCLUSIVE_LOCK   = 0x00000002
)

const MB_ERR_INVALID_CHARS = 8

//sys	GetACP() (acp uint32) = kernel32.GetACP
//sys	GetConsoleCP() (ccp uint32) = kernel32.GetConsoleCP
//sys	MultiByteToWideChar(codePage uint32, dwFlags uint32, str *byte, nstr int32, wchar *uint16, nwchar int32) (nwrite int32, err error) = kernel32.MultiByteToWideChar
//sys	GetCurrentThread() (pseudoHandle syscall.Handle, err error) = kernel32.GetCurrentThread

// Constants from lmshare.h
const (
	STYPE_DISKTREE  = 0x00
	STYPE_TEMPORARY = 0x40000000
)

type SHARE_INFO_2 struct {
	Netname     *uint16
	Type        uint32
	Remark      *uint16
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        *uint16
	Passwd      *uint16
}

//sys  NetShareAdd(serverName *uint16, level uint32, buf *byte, parmErr *uint16) (neterr error) = netapi32.NetShareAdd
//sys  NetShareDel(serverName *uint16, netName *uint16, reserved uint32) (neterr error) = netapi32.NetShareDel

const (
	FILE_NAME_NORMALIZED = 0x0
	FILE_NAME_OPENED     = 0x8

	VOLUME_NAME_DOS  = 0x0
	VOLUME_NAME_GUID = 0x1
	VOLUME_NAME_NONE = 0x4
	VOLUME_NAME_NT   = 0x2
)

//sys	GetFinalPathNameByHandle(file syscall.Handle, filePath *uint16, filePathSize uint32, flags uint32) (n uint32, err error) = kernel32.GetFinalPathNameByHandleW

func ErrorLoadingGetTempPath2() error {
	return procGetTempPath2W.Find()
}

//sys	CreateEnvironmentBlock(block **uint16, token syscall.Token, inheritExisting bool) (err error) = userenv.CreateEnvironmentBlock
//sys	DestroyEnvironmentBlock(block *uint16) (err error) = userenv.DestroyEnvironmentBlock
//sys	CreateEvent(eventAttrs *SecurityAttributes, manualReset uint32, initialState uint32, name *uint16) (handle syscall.Handle, err error) = kernel32.CreateEventW

//sys	ProcessPrng(buf []byte) (err error) = bcryptprimitives.ProcessPrng

type FILE_ID_BOTH_DIR_INFO struct {
	NextEntryOffset uint32
	FileIndex       uint32
	CreationTime    syscall.Filetime
	LastAccessTime  syscall.Filetime
	LastWriteTime   syscall.Filetime
	ChangeTime      syscall.Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	FileNameLength  uint32
	EaSize          uint32
	ShortNameLength uint32
	ShortName       [12]uint16
	FileID          uint64
	FileName        [1]uint16
}

type FILE_FULL_DIR_INFO struct {
	NextEntryOffset uint32
	FileIndex       uint32
	CreationTime    syscall.Filetime
	LastAccessTime  syscall.Filetime
	LastWriteTime   syscall.Filetime
	ChangeTime      syscall.Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	FileNameLength  uint32
	EaSize          uint32
	FileName        [1]uint16
}

//sys	GetVolumeInformationByHandle(file syscall.Handle, volumeNameBuffer *uint16, volumeNameSize uint32, volumeNameSerialNumber *uint32, maximumComponentLength *uint32, fileSystemFlags *uint32, fileSystemNameBuffer *uint16, fileSystemNameSize uint32) (err error) = GetVolumeInformationByHandleW
//sys	GetVolumeNameForVolumeMountPoint(volumeMountPoint *uint16, volumeName *uint16, bufferlength uint32) (err error) = GetVolumeNameForVolumeMountPointW

//sys	RtlLookupFunctionEntry(pc uintptr, baseAddress *uintptr, table *byte) (ret uintptr) = kernel32.RtlLookupFunctionEntry
//sys	RtlVirtualUnwind(handlerType uint32, baseAddress uintptr, pc uintptr, entry uintptr, ctxt uintptr, data *uintptr, frame *uintptr, ctxptrs *byte) (ret uintptr) = kernel32.RtlVirtualUnwind

type SERVICE_STATUS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

const (
	SERVICE_RUNNING      = 4
	SERVICE_QUERY_STATUS = 4
)

//sys    OpenService(mgr syscall.Handle, serviceName *uint16, access uint32) (handle syscall.Handle, err error) = advapi32.OpenServiceW
//sys	QueryServiceStatus(hService syscall.Handle, lpServiceStatus *SERVICE_STATUS) (err error)  = advapi32.QueryServiceStatus
//sys    OpenSCManager(machineName *uint16, databaseName *uint16, access uint32) (handle syscall.Handle, err error)  [failretval==0] = advapi32.OpenSCManagerW

func FinalPath(h syscall.Handle, flags uint32) (string, error) {
	buf := make([]uint16, 100)
	for {
		n, err := GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), flags)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			break
		}
		buf = make([]uint16, n)
	}
	return syscall.UTF16ToString(buf), nil
}

// QueryPerformanceCounter retrieves the current value of performance counter.
//
//go:linkname QueryPerformanceCounter
func QueryPerformanceCounter() int64 // Implemented in runtime package.

// QueryPerformanceFrequency retrieves the frequency of the performance counter.
// The returned value is represented as counts per second.
//
//go:linkname QueryPerformanceFrequency
func QueryPerformanceFrequency() int64 // Implemented in runtime package.

//sys   GetModuleHandle(modulename *uint16) (handle syscall.Handle, err error) = kernel32.GetModuleHandleW

// NTStatus corresponds with NTSTATUS, error values returned by ntdll.dll and
// other native functions.
type NTStatus uint32

func (s NTStatus) Errno() syscall.Errno {
	return rtlNtStatusToDosErrorNoTeb(s)
}

func langID(pri, sub uint16) uint32 { return uint32(sub)<<10 | uint32(pri) }

func (s NTStatus) Error() string {
	return s.Errno().Error()
}

// x/sys/windows/mkerrors.bash can generate a complete list of NTStatus codes.
//
// At the moment, we only need a couple, so just put them here manually.
// If this list starts getting long, we should consider generating the full set.
const (
	STATUS_FILE_IS_A_DIRECTORY       NTStatus = 0xC00000BA
	STATUS_DIRECTORY_NOT_EMPTY       NTStatus = 0xC0000101
	STATUS_NOT_A_DIRECTORY           NTStatus = 0xC0000103
	STATUS_CANNOT_DELETE             NTStatus = 0xC0000121
	STATUS_REPARSE_POINT_ENCOUNTERED NTStatus = 0xC000050B
)

// NT Native APIs
//sys   NtCreateFile(handle *syscall.Handle, access uint32, oa *OBJECT_ATTRIBUTES, iosb *IO_STATUS_BLOCK, allocationSize *int64, attributes uint32, share uint32, disposition uint32, options uint32, eabuffer uintptr, ealength uint32) (ntstatus error) = ntdll.NtCreateFile
//sys   NtOpenFile(handle *syscall.Handle, access uint32, oa *OBJECT_ATTRIBUTES, iosb *IO_STATUS_BLOCK, share uint32, options uint32) (ntstatus error) = ntdll.NtOpenFile
//sys   rtlNtStatusToDosErrorNoTeb(ntstatus NTStatus) (ret syscall.Errno) = ntdll.RtlNtStatusToDosErrorNoTeb
//sys   NtSetInformationFile(handle syscall.Handle, iosb *IO_STATUS_BLOCK, inBuffer uintptr, inBufferLen uint32, class uint32) (ntstatus error) = ntdll.NtSetInformationFile
```