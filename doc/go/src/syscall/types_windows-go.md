Response:
Thinking Process:

1. **Identify the core purpose:** The file name `types_windows.go` and the package `syscall` strongly suggest that this file defines data structures and constants specific to the Windows operating system for system calls.

2. **Break down the content:**  Scan the file and categorize the different types of declarations:
    * `const`: These are constant values. Look for patterns and comments to understand their purpose. Keywords like `ERROR_`, `O_`, `SIG`, `GENERIC_`, `FILE_`, `CREATE_`, `HANDLE_`, `STD_`, `FILE_BEGIN`, `LANG_`, `FORMAT_MESSAGE_`, `MAX_PATH`, `TIME_ZONE_`, `WAIT_`, `CREATE_NEW_PROCESS_GROUP`, `PROCESS_`, `PAGE_`, `FILE_MAP_`, `CTRL_`, `TH32CS_`, `FILE_NOTIFY_CHANGE_`, `FILE_ACTION_`, `PROV_`, `CRYPT_`, `USAGE_MATCH_TYPE_`, `X509_ASN_ENCODING`, `CERT_STORE_`, `CERT_TRUST_`, `CERT_CHAIN_POLICY_`, `CERT_E_`, `AUTHTYPE_`, `OID_`, `AF_`, `SOCK_`, `IPPROTO_`, `SOL_`, `SO_`, `IOC_`, `SIO_`, `IP_`, `IPV6_`, `SOMAXCONN`, `TCP_`, `SHUT_`, `WSADESCRIPTION_LEN`, `S_IF`, `S_IS`, `S_IRUSR`, `FILE_TYPE_`, `DNS_TYPE_`, `DNS_INFO_`, `DnsSection`, `TF_`, `IFF_`, `SIO_GET_INTERFACE_LIST`, `HKEY_`, `KEY_`, `REG_`, `AI_`, `FILE_SKIP_`, `WSAPROTOCOL_LEN`, `XP1_`, `PFL_`, `FSCTL_`, `MAXIMUM_REPARSE_DATA_BUFFER_SIZE`, `IO_REPARSE_TAG_`, `SYMBOLIC_LINK_FLAG_`, `_SYMLINK_FLAG_`, `UNIX_PATH_MAX` provide clues.

3. **Infer functionality from constants:**
    * `ERROR_*`: Windows system error codes.
    * `O_*`: File open flags (like read-only, create, truncate). Relates to file I/O operations.
    * `SIG*`:  Signal numbers. Relates to process signaling.
    * `GENERIC_*`, `FILE_*`, `CREATE_*`, `HANDLE_*`:  Constants related to file and directory manipulation, permissions, and handle creation.
    * `STD_*`: Standard input/output/error handles.
    * `FILE_BEGIN`, `FILE_CURRENT`, `FILE_END`: Seek origins for file operations.
    * `LANG_*`, `FORMAT_MESSAGE_*`: Constants for formatting error messages in different languages.
    * `MAX_PATH`: Maximum length for file paths.
    * `TIME_ZONE_*`: Time zone related constants.
    * `WAIT_*`: Constants for waiting on events or handles.
    * `PROCESS_*`, `PAGE_*`, `FILE_MAP_*`: Constants related to process management, memory management (page protection), and memory mapping.
    * `CTRL_*`: Constants for control events (like Ctrl+C).
    * `TH32CS_*`: Constants for taking snapshots of processes and threads.
    * `FILE_NOTIFY_CHANGE_*`, `FILE_ACTION_*`: Constants for file system change notifications.
    * `PROV_*`, `CRYPT_*`, `CERT_*`, `OID_*`: Cryptography and certificate related constants.
    * `AF_*`, `SOCK_*`, `IPPROTO_*`, `SOL_*`, `SO_*`, `IOC_*`, `SIO_*`, `IP_*`, `IPV6_*`, `TCP_*`, `SHUT_*`:  Network socket programming related constants.
    * `S_IF*`, `S_IS*`, `S_IRUSR`: File mode and permission constants (mimicking Unix-like systems).
    * `FILE_TYPE_*`:  File type constants.
    * `DNS_TYPE_*`, `DNS_INFO_*`, `DnsSection*`: DNS (Domain Name System) related constants.
    * `TF_*`: Constants for `TransmitFile`.
    * `IFF_*`, `SIO_GET_INTERFACE_LIST`: Network interface related constants.
    * `HKEY_*`, `KEY_*`, `REG_*`: Windows Registry related constants.
    * `AI_*`: Address information flags.
    * `FILE_SKIP_*`: Flags for file I/O completion ports.
    * `WSAPROTOCOL_LEN`, `XP1_*`, `PFL_*`: Windows Sockets (Winsock) protocol information.
    * `FSCTL_*`, `IO_REPARSE_TAG_*`, `SYMBOLIC_LINK_FLAG_*`: File system control codes and reparse point tags (for symbolic links and mount points).
    * `UNIX_PATH_MAX`: Maximum length for Unix domain socket paths.

4. **Analyze struct definitions:**  Examine the `type` declarations for structs. Their names and fields usually indicate what kind of data they represent.
    * `Timeval`, `Filetime`: Time-related structures.
    * `SecurityAttributes`, `Overlapped`: Structures used with asynchronous operations and security.
    * `FileNotifyInformation`: Information about file system changes.
    * `Win32finddata`: Information returned by file searching functions.
    * `ByHandleFileInformation`, `Win32FileAttributeData`: File metadata.
    * `StartupInfo`, `ProcessInformation`, `ProcessEntry32`: Process creation and management information.
    * `Systemtime`, `Timezoneinformation`: Time and time zone information.
    * `WSABuf`: Buffer structure for Winsock.
    * `Hostent`, `Protoent`: Network host and protocol information.
    * `DNSRecord`, `DNSSRVData`, `DNSPTRData`, `DNSMXData`, `DNSTXTData`: DNS record structures.
    * `SockaddrGen`, `InterfaceInfo`, `IpAddressString`, `IpAdapterInfo`, `MibIfRow`: Network interface information.
    * `Cert*`: Structures related to X.509 certificates and certificate chains.
    * `AddrinfoW`: Address information for network resolution.
    * `GUID`: Globally Unique Identifier.
    * `WSAProtocolInfo`, `WSAProtocolChain`: Winsock protocol details.
    * `TCPKeepalive`: TCP keep-alive settings.
    * `symbolicLinkReparseBuffer`, `mountPointReparseBuffer`, `reparseDataBuffer`: Structures for reparse points (symbolic links and mount points).

5. **Look for functions:**  The file contains a few utility functions:
    * `Nanoseconds()` methods for `Timeval` and `Filetime`: Convert to nanoseconds.
    * `NsecToTimeval()`, `NsecToFiletime()`: Convert nanoseconds to the respective structures.
    * `copyFindData()`: Copies data between different `Win32finddata` structures.

6. **Infer Go language feature:** This file is part of the `syscall` package, which provides low-level access to the operating system's system calls. It defines the data types and constants necessary to interact with Windows system calls directly from Go. This is a core part of Go's ability to interact with the underlying OS.

7. **Code Example:** To demonstrate the usage, consider a simple file opening operation. The `O_RDONLY` and `syscall.Open` (though not defined in this file, it uses these constants) would be involved.

8. **Assumptions and I/O:** For the code example, assume the existence of a file named "test.txt". The output would be either a file descriptor (Handle) or an error.

9. **Command-line arguments:** This specific file doesn't handle command-line arguments. It primarily defines data structures.

10. **Common mistakes:** One common mistake is incorrectly using the bitwise OR operator to combine file open flags, which can lead to unexpected behavior if the flag values are not powers of 2.

11. **Structure the answer:** Organize the information logically, starting with the overall purpose, then detailing the functionality based on the content analysis, providing a code example, and finally addressing potential pitfalls. Use clear and concise language in Chinese.
这个文件是 Go 语言标准库 `syscall` 包在 Windows 操作系统下的类型定义部分 (`types_windows.go`)。它的主要功能是：

**1. 定义了与 Windows 系统调用相关的常量:**

   - **Windows 错误码 (Windows errors):**  例如 `ERROR_FILE_NOT_FOUND`, `ERROR_ACCESS_DENIED` 等，这些常量对应 Windows API 返回的错误代码，用于判断系统调用是否成功以及失败原因。
   - **文件操作相关的常量 (File operation constants):** 例如 `O_RDONLY`, `O_CREAT`, `GENERIC_READ`, `FILE_SHARE_READ`, `CREATE_NEW` 等，这些常量用于指定文件打开模式、访问权限、共享模式和创建方式等。它们与 `os` 包中的文件操作标志相对应，但更接近底层的 Windows API。
   - **信号量相关的常量 (Signal constants):** 例如 `SIGHUP`, `SIGINT`, `SIGKILL` 等，虽然 Windows 的信号处理机制与 Unix-like 系统不同，但 Go 尝试提供跨平台的抽象。这些常量在 Windows 下的实现可能与 Unix 下的行为有所差异。
   - **句柄操作相关的常量 (Handle constants):** 例如 `INVALID_FILE_ATTRIBUTES`, `STD_INPUT_HANDLE`, `DUPLICATE_SAME_ACCESS` 等，用于操作 Windows 的句柄，例如标准输入输出错误、复制句柄等。
   - **消息格式化相关的常量 (Message formatting constants):** 例如 `FORMAT_MESSAGE_FROM_SYSTEM`，用于获取系统错误消息。
   - **路径相关的常量 (Path constants):** 例如 `MAX_PATH`，定义了最大路径长度。
   - **时间相关的常量 (Time constants):** 例如 `TIME_ZONE_ID_STANDARD`。
   - **等待相关的常量 (Wait constants):** 例如 `WAIT_TIMEOUT`, `WAIT_OBJECT_0`，用于等待事件或进程。
   - **进程创建相关的常量 (Process creation constants):** 例如 `CREATE_NEW_PROCESS_GROUP`, `CREATE_UNICODE_ENVIRONMENT`。
   - **进程操作相关的常量 (Process operation constants):** 例如 `PROCESS_TERMINATE`, `PROCESS_QUERY_INFORMATION`。
   - **内存管理相关的常量 (Memory management constants):** 例如 `PAGE_READONLY`, `FILE_MAP_READ`，用于指定内存页的保护属性和内存映射的访问权限。
   - **控制台事件相关的常量 (Console event constants):** 例如 `CTRL_C_EVENT`。
   - **进程快照相关的常量 (Process snapshot constants):** 例如 `TH32CS_SNAPPROCESS`，用于创建进程快照。
   - **文件通知相关的常量 (File notification constants):** 例如 `FILE_NOTIFY_CHANGE_FILE_NAME`, `FILE_ACTION_ADDED`，用于监控文件系统变化。
   - **加密相关的常量 (Cryptography constants):** 例如 `PROV_RSA_FULL`, `CERT_STORE_ADD_ALWAYS`，用于 Windows 的加密 API。
   - **网络相关的常量 (Network constants):** 例如 `AF_INET`, `SOCK_STREAM`, `IPPROTO_TCP`, `SOL_SOCKET`, `SO_REUSEADDR` 等，定义了地址族、套接字类型、协议类型和套接字选项等。
   - **文件类型相关的常量 (File type constants):** 例如 `FILE_TYPE_DISK`, `FILE_TYPE_PIPE`。
   - **DNS 相关的常量 (DNS constants):** 例如 `DNS_TYPE_A`, `DNS_TYPE_MX`，定义了 DNS 查询的类型。
   - **`TransmitFile` 相关的常量 (TransmitFile constants):** 例如 `TF_DISCONNECT`。
   - **网络接口相关的常量 (Network interface constants):** 例如 `IFF_UP`。
   - **注册表相关的常量 (Registry constants):** 例如 `HKEY_LOCAL_MACHINE`, `KEY_READ`, `REG_SZ`，用于访问 Windows 注册表。
   - **地址信息相关的常量 (Address information constants):** 例如 `AI_PASSIVE`。
   - **`ConnectEx` 相关的 GUID (ConnectEx GUID):**  用于异步连接的扩展函数。
   - **文件操作优化相关的常量 (File operation optimization constants):** 例如 `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`。
   - **Winsock 协议相关的常量 (Winsock protocol constants):** 例如 `WSAPROTOCOL_LEN`, `XP1_CONNECTIONLESS`。
   - **符号链接和挂载点相关的常量 (Symbolic link and mount point constants):** 例如 `FSCTL_GET_REPARSE_POINT`, `IO_REPARSE_TAG_SYMLINK`。
   - **Unix 域套接字路径最大长度常量 (Unix domain socket path maximum length constant):** `UNIX_PATH_MAX`。

**2. 定义了与 Windows 系统调用相关的数据结构 (Data Structures):**

   - **时间相关的结构体 (Time structures):** `Timeval`, `Filetime`，用于表示时间和日期。
   - **安全相关的结构体 (Security structures):** `SecurityAttributes`，用于设置对象的安全属性。
   - **异步操作相关的结构体 (Asynchronous operation structures):** `Overlapped`，用于支持异步 I/O 操作。
   - **文件通知相关的结构体 (File notification structures):** `FileNotifyInformation`，包含文件变化的详细信息。
   - **文件查找相关的结构体 (File finding structures):** `Win32finddata` (和内部使用的 `win32finddata1`)，用于存储查找到的文件信息。
   - **文件信息相关的结构体 (File information structures):** `ByHandleFileInformation`, `Win32FileAttributeData`，包含文件的各种属性。
   - **进程创建相关的结构体 (Process creation structures):** `StartupInfo`, `ProcessInformation`，用于启动新进程。
   - **进程信息相关的结构体 (Process information structures):** `ProcessEntry32`，包含进程的各种信息。
   - **系统时间相关的结构体 (System time structures):** `Systemtime`, `Timezoneinformation`，用于获取和设置系统时间和时区信息。
   - **网络相关的结构体 (Network structures):** `WSABuf`, `Hostent`, `Protoent`, `SockaddrGen`, `InterfaceInfo`, `IpAddressString`, `IpAdapterInfo`, `MibIfRow`, `AddrinfoW` 等，用于网络编程，包含缓冲区、主机信息、协议信息、套接字地址、网络接口信息等。
   - **证书相关的结构体 (Certificate structures):** `CertInfo`, `CertContext`, `CertChainContext`, `CertSimpleChain`, `CertChainElement`, `CertRevocationInfo`, `CertTrustStatus`, `CertUsageMatch`, `CertEnhKeyUsage`, `CertChainPara`, `CertChainPolicyPara`, `SSLExtraCertChainPolicyPara`, `CertChainPolicyStatus`，用于处理 X.509 证书。
   - **注册表相关的结构体 (Registry structures):**  虽然这里没有显式定义注册表相关的结构体，但涉及到注册表操作的常量。
   - **DNS 相关的结构体 (DNS structures):** `DNSSRVData`, `DNSPTRData`, `DNSMXData`, `DNSTXTData`, `DNSRecord`，用于解析 DNS 记录。
   - **`TransmitFile` 相关的结构体 (TransmitFile structures):** `TransmitFileBuffers`。
   - **符号链接和挂载点相关的结构体 (Symbolic link and mount point structures):** `symbolicLinkReparseBuffer`, `mountPointReparseBuffer`, `reparseDataBuffer`。
   - **GUID 结构体 (GUID structure):** `GUID`，用于表示全局唯一标识符。
   - **Winsock 协议相关的结构体 (Winsock protocol structures):** `WSAProtocolInfo`, `WSAProtocolChain`。
   - **TCP Keep-Alive 相关的结构体 (TCP Keep-Alive structure):** `TCPKeepalive`。

**3. 定义了一些辅助函数 (Helper Functions):**

   - **时间转换函数 (Time conversion functions):** `Nanoseconds()` (将 `Timeval` 和 `Filetime` 转换为纳秒), `NsecToTimeval()`, `NsecToFiletime()` (将纳秒转换为 `Timeval` 和 `Filetime`)。
   - **数据复制函数 (Data copy function):** `copyFindData()`，用于在 `Win32finddata` 和 `win32finddata1` 之间复制数据。

**这个文件是 `syscall` 包在 Windows 平台实现的基础，它定义了 Go 代码与 Windows 系统底层交互所需的数据类型和常量。**  其他 `syscall` 包的源文件会使用这里定义的类型和常量来调用具体的 Windows API 函数。

**可以推理出它是什么 Go 语言功能的实现:**

这个文件是 Go 语言的 **系统调用 (syscall)** 功能在 Windows 平台上的具体实现的一部分。 `syscall` 包允许 Go 程序直接调用操作系统提供的底层 API。在跨平台的编程中，`syscall` 包会针对不同的操作系统提供不同的实现。这个 `types_windows.go` 文件就是为 Windows 操作系统量身定制的。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 假设我们要打开一个文件进行只读操作
	filename := "C:\\test.txt" // 假设文件存在

	// 使用 syscall 包中定义的常量 O_RDONLY
	fd, err := syscall.Open(filename, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Printf("打开文件失败: %v\n", err)
		return
	}
	defer syscall.Close(fd)

	fmt.Printf("成功打开文件，文件描述符: %d\n", fd)

	// 假设我们要获取文件信息
	var findData syscall.Win32finddata
	// 注意: FindFirstFileW 需要 UTF-16 编码的路径
	filenameUTF16, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		fmt.Printf("转换文件名失败: %v\n", err)
		return
	}

	h, err := syscall.FindFirstFile(filenameUTF16, &findData)
	if h == syscall.InvalidHandle {
		fmt.Printf("FindFirstFile 失败: %v\n", err)
		return
	}
	defer syscall.FindClose(h)

	fmt.Printf("文件名: %s\n", syscall.UTF16ToString(findData.FileName[:]))
	fmt.Printf("文件大小 (低位): %d\n", findData.FileSizeLow)
	fmt.Printf("文件大小 (高位): %d\n", findData.FileSizeHigh)
}
```

**假设的输入与输出:**

**假设输入:**

- 存在一个名为 `C:\test.txt` 的文本文件。

**假设输出:**

```
成功打开文件，文件描述符: 3  // 文件描述符的值可能不同
文件名: test.txt
文件大小 (低位): 1234  // 假设文件大小低位是 1234
文件大小 (高位): 0     // 假设文件大小高位是 0
```

**涉及命令行参数的具体处理:**

这个 `types_windows.go` 文件本身 **不涉及** 命令行参数的具体处理。它只是定义了数据类型和常量。命令行参数的处理通常发生在 `main` 函数所在的 Go 源文件中，并可能使用 `os` 包来获取和解析命令行参数。

**使用者易犯错的点:**

1. **文件路径编码问题:**  Windows API 中的许多函数需要 UTF-16 编码的字符串，而 Go 的字符串是 UTF-8 编码的。直接将 Go 字符串传递给 Windows API 函数可能会导致错误。需要使用 `syscall.UTF16PtrFromString` 等函数进行转换。

   ```go
   filename := "C:\\中文文件名.txt" // UTF-8 编码
   filenamePtr, _ := syscall.UTF16PtrFromString(filename) // 转换为 UTF-16
   // syscall.CreateFile(filenamePtr, ...) // 正确使用
   ```

2. **常量值的理解和使用:**  `syscall` 包中的常量通常是与 Windows API 定义一致的，直接使用这些常量需要对 Windows API 有一定的了解。错误地组合或使用这些常量会导致不可预测的行为。例如，在打开文件时，`O_RDONLY`、`O_WRONLY` 和 `O_RDWR` 是互斥的，不能同时使用。

3. **结构体字段的含义和使用:**  `syscall` 包中定义的结构体通常直接映射到 Windows API 的结构体。理解每个字段的含义和正确赋值非常重要。例如，在使用 `StartupInfo` 结构体创建进程时，需要正确设置 `Cb` 字段为结构体的大小。

4. **错误处理:** 系统调用可能会失败，必须检查返回的 `error` 值。`syscall.Errno` 类型可以转换为标准的 `error` 类型进行处理，并可以使用 `syscall.Error` 类型来获取更详细的错误信息。

5. **句柄的管理:**  Windows 中的句柄（例如文件描述符、进程句柄等）是有限的资源，必须在使用完毕后正确关闭，否则会导致资源泄漏。需要使用 `syscall.Close`、`syscall.CloseHandle` 等函数来释放句柄。

总而言之，`go/src/syscall/types_windows.go` 是 Go 语言在 Windows 平台上进行底层系统编程的关键组成部分，它提供了与 Windows API 交互所需的基石。理解这个文件中的定义对于编写需要直接调用 Windows 系统功能的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/syscall/types_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

const (
	// Windows errors.
	ERROR_FILE_NOT_FOUND      Errno = 2
	ERROR_PATH_NOT_FOUND      Errno = 3
	ERROR_ACCESS_DENIED       Errno = 5
	ERROR_NO_MORE_FILES       Errno = 18
	ERROR_HANDLE_EOF          Errno = 38
	ERROR_NETNAME_DELETED     Errno = 64
	ERROR_FILE_EXISTS         Errno = 80
	ERROR_BROKEN_PIPE         Errno = 109
	ERROR_BUFFER_OVERFLOW     Errno = 111
	ERROR_INSUFFICIENT_BUFFER Errno = 122
	ERROR_MOD_NOT_FOUND       Errno = 126
	ERROR_PROC_NOT_FOUND      Errno = 127
	ERROR_DIR_NOT_EMPTY       Errno = 145
	ERROR_ALREADY_EXISTS      Errno = 183
	ERROR_ENVVAR_NOT_FOUND    Errno = 203
	ERROR_MORE_DATA           Errno = 234
	ERROR_OPERATION_ABORTED   Errno = 995
	ERROR_IO_PENDING          Errno = 997
	ERROR_NOT_FOUND           Errno = 1168
	ERROR_PRIVILEGE_NOT_HELD  Errno = 1314
	WSAEACCES                 Errno = 10013
	WSAENOPROTOOPT            Errno = 10042
	WSAECONNABORTED           Errno = 10053
	WSAECONNRESET             Errno = 10054
)

const (
	// Invented values to support what package os expects.
	O_RDONLY       = 0x00000
	O_WRONLY       = 0x00001
	O_RDWR         = 0x00002
	O_CREAT        = 0x00040
	O_EXCL         = 0x00080
	O_NOCTTY       = 0x00100
	O_TRUNC        = 0x00200
	O_NONBLOCK     = 0x00800
	O_APPEND       = 0x00400
	O_SYNC         = 0x01000
	O_ASYNC        = 0x02000
	O_CLOEXEC      = 0x80000
	o_DIRECTORY    = 0x100000   // used by internal/syscall/windows
	o_NOFOLLOW_ANY = 0x20000000 // used by internal/syscall/windows
	o_OPEN_REPARSE = 0x40000000 // used by internal/syscall/windows
)

const (
	// More invented values for signals
	SIGHUP  = Signal(0x1)
	SIGINT  = Signal(0x2)
	SIGQUIT = Signal(0x3)
	SIGILL  = Signal(0x4)
	SIGTRAP = Signal(0x5)
	SIGABRT = Signal(0x6)
	SIGBUS  = Signal(0x7)
	SIGFPE  = Signal(0x8)
	SIGKILL = Signal(0x9)
	SIGSEGV = Signal(0xb)
	SIGPIPE = Signal(0xd)
	SIGALRM = Signal(0xe)
	SIGTERM = Signal(0xf)
)

var signals = [...]string{
	1:  "hangup",
	2:  "interrupt",
	3:  "quit",
	4:  "illegal instruction",
	5:  "trace/breakpoint trap",
	6:  "aborted",
	7:  "bus error",
	8:  "floating point exception",
	9:  "killed",
	10: "user defined signal 1",
	11: "segmentation fault",
	12: "user defined signal 2",
	13: "broken pipe",
	14: "alarm clock",
	15: "terminated",
}

const (
	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000

	FILE_LIST_DIRECTORY   = 0x00000001
	FILE_APPEND_DATA      = 0x00000004
	_FILE_WRITE_EA        = 0x00000010
	FILE_WRITE_ATTRIBUTES = 0x00000100

	FILE_SHARE_READ              = 0x00000001
	FILE_SHARE_WRITE             = 0x00000002
	FILE_SHARE_DELETE            = 0x00000004
	FILE_ATTRIBUTE_READONLY      = 0x00000001
	FILE_ATTRIBUTE_HIDDEN        = 0x00000002
	FILE_ATTRIBUTE_SYSTEM        = 0x00000004
	FILE_ATTRIBUTE_DIRECTORY     = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE       = 0x00000020
	FILE_ATTRIBUTE_NORMAL        = 0x00000080
	FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

	INVALID_FILE_ATTRIBUTES = 0xffffffff

	CREATE_NEW        = 1
	CREATE_ALWAYS     = 2
	OPEN_EXISTING     = 3
	OPEN_ALWAYS       = 4
	TRUNCATE_EXISTING = 5

	FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
	FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000
	FILE_FLAG_OVERLAPPED         = 0x40000000

	HANDLE_FLAG_INHERIT    = 0x00000001
	STARTF_USESTDHANDLES   = 0x00000100
	STARTF_USESHOWWINDOW   = 0x00000001
	DUPLICATE_CLOSE_SOURCE = 0x00000001
	DUPLICATE_SAME_ACCESS  = 0x00000002

	STD_INPUT_HANDLE  = -10
	STD_OUTPUT_HANDLE = -11
	STD_ERROR_HANDLE  = -12

	FILE_BEGIN   = 0
	FILE_CURRENT = 1
	FILE_END     = 2

	LANG_ENGLISH       = 0x09
	SUBLANG_ENGLISH_US = 0x01

	FORMAT_MESSAGE_ALLOCATE_BUFFER = 256
	FORMAT_MESSAGE_IGNORE_INSERTS  = 512
	FORMAT_MESSAGE_FROM_STRING     = 1024
	FORMAT_MESSAGE_FROM_HMODULE    = 2048
	FORMAT_MESSAGE_FROM_SYSTEM     = 4096
	FORMAT_MESSAGE_ARGUMENT_ARRAY  = 8192
	FORMAT_MESSAGE_MAX_WIDTH_MASK  = 255

	MAX_PATH      = 260
	MAX_LONG_PATH = 32768

	MAX_COMPUTERNAME_LENGTH = 15

	TIME_ZONE_ID_UNKNOWN  = 0
	TIME_ZONE_ID_STANDARD = 1

	TIME_ZONE_ID_DAYLIGHT = 2
	IGNORE                = 0
	INFINITE              = 0xffffffff

	WAIT_TIMEOUT   = 258
	WAIT_ABANDONED = 0x00000080
	WAIT_OBJECT_0  = 0x00000000
	WAIT_FAILED    = 0xFFFFFFFF

	CREATE_NEW_PROCESS_GROUP   = 0x00000200
	CREATE_UNICODE_ENVIRONMENT = 0x00000400

	PROCESS_TERMINATE         = 1
	PROCESS_QUERY_INFORMATION = 0x00000400
	SYNCHRONIZE               = 0x00100000

	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80

	FILE_MAP_COPY    = 0x01
	FILE_MAP_WRITE   = 0x02
	FILE_MAP_READ    = 0x04
	FILE_MAP_EXECUTE = 0x20

	CTRL_C_EVENT        = 0
	CTRL_BREAK_EVENT    = 1
	CTRL_CLOSE_EVENT    = 2
	CTRL_LOGOFF_EVENT   = 5
	CTRL_SHUTDOWN_EVENT = 6
)

const (
	// flags for CreateToolhelp32Snapshot
	TH32CS_SNAPHEAPLIST = 0x01
	TH32CS_SNAPPROCESS  = 0x02
	TH32CS_SNAPTHREAD   = 0x04
	TH32CS_SNAPMODULE   = 0x08
	TH32CS_SNAPMODULE32 = 0x10
	TH32CS_SNAPALL      = TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD
	TH32CS_INHERIT      = 0x80000000
)

const (
	// do not reorder
	FILE_NOTIFY_CHANGE_FILE_NAME = 1 << iota
	FILE_NOTIFY_CHANGE_DIR_NAME
	FILE_NOTIFY_CHANGE_ATTRIBUTES
	FILE_NOTIFY_CHANGE_SIZE
	FILE_NOTIFY_CHANGE_LAST_WRITE
	FILE_NOTIFY_CHANGE_LAST_ACCESS
	FILE_NOTIFY_CHANGE_CREATION
)

const (
	// do not reorder
	FILE_ACTION_ADDED = iota + 1
	FILE_ACTION_REMOVED
	FILE_ACTION_MODIFIED
	FILE_ACTION_RENAMED_OLD_NAME
	FILE_ACTION_RENAMED_NEW_NAME
)

const (
	// wincrypt.h
	PROV_RSA_FULL                    = 1
	PROV_RSA_SIG                     = 2
	PROV_DSS                         = 3
	PROV_FORTEZZA                    = 4
	PROV_MS_EXCHANGE                 = 5
	PROV_SSL                         = 6
	PROV_RSA_SCHANNEL                = 12
	PROV_DSS_DH                      = 13
	PROV_EC_ECDSA_SIG                = 14
	PROV_EC_ECNRA_SIG                = 15
	PROV_EC_ECDSA_FULL               = 16
	PROV_EC_ECNRA_FULL               = 17
	PROV_DH_SCHANNEL                 = 18
	PROV_SPYRUS_LYNKS                = 20
	PROV_RNG                         = 21
	PROV_INTEL_SEC                   = 22
	PROV_REPLACE_OWF                 = 23
	PROV_RSA_AES                     = 24
	CRYPT_VERIFYCONTEXT              = 0xF0000000
	CRYPT_NEWKEYSET                  = 0x00000008
	CRYPT_DELETEKEYSET               = 0x00000010
	CRYPT_MACHINE_KEYSET             = 0x00000020
	CRYPT_SILENT                     = 0x00000040
	CRYPT_DEFAULT_CONTAINER_OPTIONAL = 0x00000080

	USAGE_MATCH_TYPE_AND = 0
	USAGE_MATCH_TYPE_OR  = 1

	X509_ASN_ENCODING   = 0x00000001
	PKCS_7_ASN_ENCODING = 0x00010000

	CERT_STORE_PROV_MEMORY = 2

	CERT_STORE_ADD_ALWAYS = 4

	CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG = 0x00000004

	CERT_TRUST_NO_ERROR                          = 0x00000000
	CERT_TRUST_IS_NOT_TIME_VALID                 = 0x00000001
	CERT_TRUST_IS_REVOKED                        = 0x00000004
	CERT_TRUST_IS_NOT_SIGNATURE_VALID            = 0x00000008
	CERT_TRUST_IS_NOT_VALID_FOR_USAGE            = 0x00000010
	CERT_TRUST_IS_UNTRUSTED_ROOT                 = 0x00000020
	CERT_TRUST_REVOCATION_STATUS_UNKNOWN         = 0x00000040
	CERT_TRUST_IS_CYCLIC                         = 0x00000080
	CERT_TRUST_INVALID_EXTENSION                 = 0x00000100
	CERT_TRUST_INVALID_POLICY_CONSTRAINTS        = 0x00000200
	CERT_TRUST_INVALID_BASIC_CONSTRAINTS         = 0x00000400
	CERT_TRUST_INVALID_NAME_CONSTRAINTS          = 0x00000800
	CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT = 0x00001000
	CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT   = 0x00002000
	CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT = 0x00004000
	CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT      = 0x00008000
	CERT_TRUST_IS_OFFLINE_REVOCATION             = 0x01000000
	CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY          = 0x02000000
	CERT_TRUST_IS_EXPLICIT_DISTRUST              = 0x04000000
	CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT    = 0x08000000

	CERT_CHAIN_POLICY_BASE              = 1
	CERT_CHAIN_POLICY_AUTHENTICODE      = 2
	CERT_CHAIN_POLICY_AUTHENTICODE_TS   = 3
	CERT_CHAIN_POLICY_SSL               = 4
	CERT_CHAIN_POLICY_BASIC_CONSTRAINTS = 5
	CERT_CHAIN_POLICY_NT_AUTH           = 6
	CERT_CHAIN_POLICY_MICROSOFT_ROOT    = 7
	CERT_CHAIN_POLICY_EV                = 8

	CERT_E_EXPIRED       = 0x800B0101
	CERT_E_ROLE          = 0x800B0103
	CERT_E_PURPOSE       = 0x800B0106
	CERT_E_UNTRUSTEDROOT = 0x800B0109
	CERT_E_CN_NO_MATCH   = 0x800B010F

	AUTHTYPE_CLIENT = 1
	AUTHTYPE_SERVER = 2
)

var (
	OID_PKIX_KP_SERVER_AUTH = []byte("1.3.6.1.5.5.7.3.1\x00")
	OID_SERVER_GATED_CRYPTO = []byte("1.3.6.1.4.1.311.10.3.3\x00")
	OID_SGC_NETSCAPE        = []byte("2.16.840.1.113730.4.1\x00")
)

// Pointer represents a pointer to an arbitrary Windows type.
//
// Pointer-typed fields may point to one of many different types. It's
// up to the caller to provide a pointer to the appropriate type, cast
// to Pointer. The caller must obey the unsafe.Pointer rules while
// doing so.
type Pointer *struct{}

// Invented values to support what package os expects.
type Timeval struct {
	Sec  int32
	Usec int32
}

func (tv *Timeval) Nanoseconds() int64 {
	return (int64(tv.Sec)*1e6 + int64(tv.Usec)) * 1e3
}

func NsecToTimeval(nsec int64) (tv Timeval) {
	tv.Sec = int32(nsec / 1e9)
	tv.Usec = int32(nsec % 1e9 / 1e3)
	return
}

type SecurityAttributes struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      uint32
}

type Overlapped struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       Handle
}

type FileNotifyInformation struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        uint16
}

type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// Nanoseconds returns Filetime ft in nanoseconds
// since Epoch (00:00:00 UTC, January 1, 1970).
func (ft *Filetime) Nanoseconds() int64 {
	// 100-nanosecond intervals since January 1, 1601
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100
	return nsec
}

func NsecToFiletime(nsec int64) (ft Filetime) {
	// convert into 100-nanosecond
	nsec /= 100
	// change starting time to January 1, 1601
	nsec += 116444736000000000
	// split into high / low
	ft.LowDateTime = uint32(nsec & 0xffffffff)
	ft.HighDateTime = uint32(nsec >> 32 & 0xffffffff)
	return ft
}

type Win32finddata struct {
	FileAttributes    uint32
	CreationTime      Filetime
	LastAccessTime    Filetime
	LastWriteTime     Filetime
	FileSizeHigh      uint32
	FileSizeLow       uint32
	Reserved0         uint32
	Reserved1         uint32
	FileName          [MAX_PATH - 1]uint16
	AlternateFileName [13]uint16
}

// This is the actual system call structure.
// Win32finddata is what we committed to in Go 1.
type win32finddata1 struct {
	FileAttributes    uint32
	CreationTime      Filetime
	LastAccessTime    Filetime
	LastWriteTime     Filetime
	FileSizeHigh      uint32
	FileSizeLow       uint32
	Reserved0         uint32
	Reserved1         uint32
	FileName          [MAX_PATH]uint16
	AlternateFileName [14]uint16

	// The Microsoft documentation for this struct¹ describes three additional
	// fields: dwFileType, dwCreatorType, and wFinderFlags. However, those fields
	// are empirically only present in the macOS port of the Win32 API,² and thus
	// not needed for binaries built for Windows.
	//
	// ¹ https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataw
	// ² https://golang.org/issue/42637#issuecomment-760715755
}

func copyFindData(dst *Win32finddata, src *win32finddata1) {
	dst.FileAttributes = src.FileAttributes
	dst.CreationTime = src.CreationTime
	dst.LastAccessTime = src.LastAccessTime
	dst.LastWriteTime = src.LastWriteTime
	dst.FileSizeHigh = src.FileSizeHigh
	dst.FileSizeLow = src.FileSizeLow
	dst.Reserved0 = src.Reserved0
	dst.Reserved1 = src.Reserved1

	// The src is 1 element bigger than dst, but it must be NUL.
	copy(dst.FileName[:], src.FileName[:])
	copy(dst.AlternateFileName[:], src.AlternateFileName[:])
}

type ByHandleFileInformation struct {
	FileAttributes     uint32
	CreationTime       Filetime
	LastAccessTime     Filetime
	LastWriteTime      Filetime
	VolumeSerialNumber uint32
	FileSizeHigh       uint32
	FileSizeLow        uint32
	NumberOfLinks      uint32
	FileIndexHigh      uint32
	FileIndexLow       uint32
}

const (
	GetFileExInfoStandard = 0
	GetFileExMaxInfoLevel = 1
)

type Win32FileAttributeData struct {
	FileAttributes uint32
	CreationTime   Filetime
	LastAccessTime Filetime
	LastWriteTime  Filetime
	FileSizeHigh   uint32
	FileSizeLow    uint32
}

// ShowWindow constants
const (
	// winuser.h
	SW_HIDE            = 0
	SW_NORMAL          = 1
	SW_SHOWNORMAL      = 1
	SW_SHOWMINIMIZED   = 2
	SW_SHOWMAXIMIZED   = 3
	SW_MAXIMIZE        = 3
	SW_SHOWNOACTIVATE  = 4
	SW_SHOW            = 5
	SW_MINIMIZE        = 6
	SW_SHOWMINNOACTIVE = 7
	SW_SHOWNA          = 8
	SW_RESTORE         = 9
	SW_SHOWDEFAULT     = 10
	SW_FORCEMINIMIZE   = 11
)

type StartupInfo struct {
	Cb            uint32
	_             *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	_             uint16
	_             *byte
	StdInput      Handle
	StdOutput     Handle
	StdErr        Handle
}

type _PROC_THREAD_ATTRIBUTE_LIST struct {
	_ [1]byte
}

const (
	_PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	_PROC_THREAD_ATTRIBUTE_HANDLE_LIST    = 0x00020002
)

type _STARTUPINFOEXW struct {
	StartupInfo
	ProcThreadAttributeList *_PROC_THREAD_ATTRIBUTE_LIST
}

const _EXTENDED_STARTUPINFO_PRESENT = 0x00080000

type ProcessInformation struct {
	Process   Handle
	Thread    Handle
	ProcessId uint32
	ThreadId  uint32
}

type ProcessEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [MAX_PATH]uint16
}

type Systemtime struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

type Timezoneinformation struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate Systemtime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate Systemtime
	DaylightBias int32
}

// Socket related.

const (
	AF_UNSPEC  = 0
	AF_UNIX    = 1
	AF_INET    = 2
	AF_INET6   = 23
	AF_NETBIOS = 17

	SOCK_STREAM    = 1
	SOCK_DGRAM     = 2
	SOCK_RAW       = 3
	SOCK_SEQPACKET = 5

	IPPROTO_IP   = 0
	IPPROTO_IPV6 = 0x29
	IPPROTO_TCP  = 6
	IPPROTO_UDP  = 17

	SOL_SOCKET                = 0xffff
	SO_REUSEADDR              = 4
	SO_KEEPALIVE              = 8
	SO_DONTROUTE              = 16
	SO_BROADCAST              = 32
	SO_LINGER                 = 128
	SO_RCVBUF                 = 0x1002
	SO_SNDBUF                 = 0x1001
	SO_UPDATE_ACCEPT_CONTEXT  = 0x700b
	SO_UPDATE_CONNECT_CONTEXT = 0x7010

	IOC_OUT                            = 0x40000000
	IOC_IN                             = 0x80000000
	IOC_VENDOR                         = 0x18000000
	IOC_INOUT                          = IOC_IN | IOC_OUT
	IOC_WS2                            = 0x08000000
	SIO_GET_EXTENSION_FUNCTION_POINTER = IOC_INOUT | IOC_WS2 | 6
	SIO_KEEPALIVE_VALS                 = IOC_IN | IOC_VENDOR | 4
	SIO_UDP_CONNRESET                  = IOC_IN | IOC_VENDOR | 12

	// cf. https://learn.microsoft.com/en-US/troubleshoot/windows/win32/header-library-requirement-socket-ipproto-ip

	IP_TOS             = 0x3
	IP_TTL             = 0x4
	IP_MULTICAST_IF    = 0x9
	IP_MULTICAST_TTL   = 0xa
	IP_MULTICAST_LOOP  = 0xb
	IP_ADD_MEMBERSHIP  = 0xc
	IP_DROP_MEMBERSHIP = 0xd

	IPV6_V6ONLY         = 0x1b
	IPV6_UNICAST_HOPS   = 0x4
	IPV6_MULTICAST_IF   = 0x9
	IPV6_MULTICAST_HOPS = 0xa
	IPV6_MULTICAST_LOOP = 0xb
	IPV6_JOIN_GROUP     = 0xc
	IPV6_LEAVE_GROUP    = 0xd

	SOMAXCONN = 0x7fffffff

	TCP_NODELAY = 1

	SHUT_RD   = 0
	SHUT_WR   = 1
	SHUT_RDWR = 2

	WSADESCRIPTION_LEN = 256
	WSASYS_STATUS_LEN  = 128
)

type WSABuf struct {
	Len uint32
	Buf *byte
}

// Invented values to support what package os expects.
const (
	S_IFMT   = 0x1f000
	S_IFIFO  = 0x1000
	S_IFCHR  = 0x2000
	S_IFDIR  = 0x4000
	S_IFBLK  = 0x6000
	S_IFREG  = 0x8000
	S_IFLNK  = 0xa000
	S_IFSOCK = 0xc000
	S_ISUID  = 0x800
	S_ISGID  = 0x400
	S_ISVTX  = 0x200
	S_IRUSR  = 0x100
	S_IWRITE = 0x80
	S_IWUSR  = 0x80
	S_IXUSR  = 0x40
)

const (
	FILE_TYPE_CHAR    = 0x0002
	FILE_TYPE_DISK    = 0x0001
	FILE_TYPE_PIPE    = 0x0003
	FILE_TYPE_REMOTE  = 0x8000
	FILE_TYPE_UNKNOWN = 0x0000
)

type Hostent struct {
	Name     *byte
	Aliases  **byte
	AddrType uint16
	Length   uint16
	AddrList **byte
}

type Protoent struct {
	Name    *byte
	Aliases **byte
	Proto   uint16
}

const (
	DNS_TYPE_A       = 0x0001
	DNS_TYPE_NS      = 0x0002
	DNS_TYPE_MD      = 0x0003
	DNS_TYPE_MF      = 0x0004
	DNS_TYPE_CNAME   = 0x0005
	DNS_TYPE_SOA     = 0x0006
	DNS_TYPE_MB      = 0x0007
	DNS_TYPE_MG      = 0x0008
	DNS_TYPE_MR      = 0x0009
	DNS_TYPE_NULL    = 0x000a
	DNS_TYPE_WKS     = 0x000b
	DNS_TYPE_PTR     = 0x000c
	DNS_TYPE_HINFO   = 0x000d
	DNS_TYPE_MINFO   = 0x000e
	DNS_TYPE_MX      = 0x000f
	DNS_TYPE_TEXT    = 0x0010
	DNS_TYPE_RP      = 0x0011
	DNS_TYPE_AFSDB   = 0x0012
	DNS_TYPE_X25     = 0x0013
	DNS_TYPE_ISDN    = 0x0014
	DNS_TYPE_RT      = 0x0015
	DNS_TYPE_NSAP    = 0x0016
	DNS_TYPE_NSAPPTR = 0x0017
	DNS_TYPE_SIG     = 0x0018
	DNS_TYPE_KEY     = 0x0019
	DNS_TYPE_PX      = 0x001a
	DNS_TYPE_GPOS    = 0x001b
	DNS_TYPE_AAAA    = 0x001c
	DNS_TYPE_LOC     = 0x001d
	DNS_TYPE_NXT     = 0x001e
	DNS_TYPE_EID     = 0x001f
	DNS_TYPE_NIMLOC  = 0x0020
	DNS_TYPE_SRV     = 0x0021
	DNS_TYPE_ATMA    = 0x0022
	DNS_TYPE_NAPTR   = 0x0023
	DNS_TYPE_KX      = 0x0024
	DNS_TYPE_CERT    = 0x0025
	DNS_TYPE_A6      = 0x0026
	DNS_TYPE_DNAME   = 0x0027
	DNS_TYPE_SINK    = 0x0028
	DNS_TYPE_OPT     = 0x0029
	DNS_TYPE_DS      = 0x002B
	DNS_TYPE_RRSIG   = 0x002E
	DNS_TYPE_NSEC    = 0x002F
	DNS_TYPE_DNSKEY  = 0x0030
	DNS_TYPE_DHCID   = 0x0031
	DNS_TYPE_UINFO   = 0x0064
	DNS_TYPE_UID     = 0x0065
	DNS_TYPE_GID     = 0x0066
	DNS_TYPE_UNSPEC  = 0x0067
	DNS_TYPE_ADDRS   = 0x00f8
	DNS_TYPE_TKEY    = 0x00f9
	DNS_TYPE_TSIG    = 0x00fa
	DNS_TYPE_IXFR    = 0x00fb
	DNS_TYPE_AXFR    = 0x00fc
	DNS_TYPE_MAILB   = 0x00fd
	DNS_TYPE_MAILA   = 0x00fe
	DNS_TYPE_ALL     = 0x00ff
	DNS_TYPE_ANY     = 0x00ff
	DNS_TYPE_WINS    = 0xff01
	DNS_TYPE_WINSR   = 0xff02
	DNS_TYPE_NBSTAT  = 0xff01
)

const (
	DNS_INFO_NO_RECORDS = 0x251D
)

const (
	// flags inside DNSRecord.Dw
	DnsSectionQuestion   = 0x0000
	DnsSectionAnswer     = 0x0001
	DnsSectionAuthority  = 0x0002
	DnsSectionAdditional = 0x0003
)

type DNSSRVData struct {
	Target   *uint16
	Priority uint16
	Weight   uint16
	Port     uint16
	Pad      uint16
}

type DNSPTRData struct {
	Host *uint16
}

type DNSMXData struct {
	NameExchange *uint16
	Preference   uint16
	Pad          uint16
}

type DNSTXTData struct {
	StringCount uint16
	StringArray [1]*uint16
}

type DNSRecord struct {
	Next     *DNSRecord
	Name     *uint16
	Type     uint16
	Length   uint16
	Dw       uint32
	Ttl      uint32
	Reserved uint32
	Data     [40]byte
}

const (
	TF_DISCONNECT         = 1
	TF_REUSE_SOCKET       = 2
	TF_WRITE_BEHIND       = 4
	TF_USE_DEFAULT_WORKER = 0
	TF_USE_SYSTEM_THREAD  = 16
	TF_USE_KERNEL_APC     = 32
)

type TransmitFileBuffers struct {
	Head       uintptr
	HeadLength uint32
	Tail       uintptr
	TailLength uint32
}

const (
	IFF_UP           = 1
	IFF_BROADCAST    = 2
	IFF_LOOPBACK     = 4
	IFF_POINTTOPOINT = 8
	IFF_MULTICAST    = 16
)

const SIO_GET_INTERFACE_LIST = 0x4004747F

// TODO(mattn): SockaddrGen is union of sockaddr/sockaddr_in/sockaddr_in6_old.
// will be fixed to change variable type as suitable.

type SockaddrGen [24]byte

type InterfaceInfo struct {
	Flags            uint32
	Address          SockaddrGen
	BroadcastAddress SockaddrGen
	Netmask          SockaddrGen
}

type IpAddressString struct {
	String [16]byte
}

type IpMaskString IpAddressString

type IpAddrString struct {
	Next      *IpAddrString
	IpAddress IpAddressString
	IpMask    IpMaskString
	Context   uint32
}

const MAX_ADAPTER_NAME_LENGTH = 256
const MAX_ADAPTER_DESCRIPTION_LENGTH = 128
const MAX_ADAPTER_ADDRESS_LENGTH = 8

type IpAdapterInfo struct {
	Next                *IpAdapterInfo
	ComboIndex          uint32
	AdapterName         [MAX_ADAPTER_NAME_LENGTH + 4]byte
	Description         [MAX_ADAPTER_DESCRIPTION_LENGTH + 4]byte
	AddressLength       uint32
	Address             [MAX_ADAPTER_ADDRESS_LENGTH]byte
	Index               uint32
	Type                uint32
	DhcpEnabled         uint32
	CurrentIpAddress    *IpAddrString
	IpAddressList       IpAddrString
	GatewayList         IpAddrString
	DhcpServer          IpAddrString
	HaveWins            bool
	PrimaryWinsServer   IpAddrString
	SecondaryWinsServer IpAddrString
	LeaseObtained       int64
	LeaseExpires        int64
}

const MAXLEN_PHYSADDR = 8
const MAX_INTERFACE_NAME_LEN = 256
const MAXLEN_IFDESCR = 256

type MibIfRow struct {
	Name            [MAX_INTERFACE_NAME_LEN]uint16
	Index           uint32
	Type            uint32
	Mtu             uint32
	Speed           uint32
	PhysAddrLen     uint32
	PhysAddr        [MAXLEN_PHYSADDR]byte
	AdminStatus     uint32
	OperStatus      uint32
	LastChange      uint32
	InOctets        uint32
	InUcastPkts     uint32
	InNUcastPkts    uint32
	InDiscards      uint32
	InErrors        uint32
	InUnknownProtos uint32
	OutOctets       uint32
	OutUcastPkts    uint32
	OutNUcastPkts   uint32
	OutDiscards     uint32
	OutErrors       uint32
	OutQLen         uint32
	DescrLen        uint32
	Descr           [MAXLEN_IFDESCR]byte
}

type CertInfo struct {
	// Not implemented
}

type CertContext struct {
	EncodingType uint32
	EncodedCert  *byte
	Length       uint32
	CertInfo     *CertInfo
	Store        Handle
}

type CertChainContext struct {
	Size                       uint32
	TrustStatus                CertTrustStatus
	ChainCount                 uint32
	Chains                     **CertSimpleChain
	LowerQualityChainCount     uint32
	LowerQualityChains         **CertChainContext
	HasRevocationFreshnessTime uint32
	RevocationFreshnessTime    uint32
}

type CertTrustListInfo struct {
	// Not implemented
}

type CertSimpleChain struct {
	Size                       uint32
	TrustStatus                CertTrustStatus
	NumElements                uint32
	Elements                   **CertChainElement
	TrustListInfo              *CertTrustListInfo
	HasRevocationFreshnessTime uint32
	RevocationFreshnessTime    uint32
}

type CertChainElement struct {
	Size              uint32
	CertContext       *CertContext
	TrustStatus       CertTrustStatus
	RevocationInfo    *CertRevocationInfo
	IssuanceUsage     *CertEnhKeyUsage
	ApplicationUsage  *CertEnhKeyUsage
	ExtendedErrorInfo *uint16
}

type CertRevocationCrlInfo struct {
	// Not implemented
}

type CertRevocationInfo struct {
	Size             uint32
	RevocationResult uint32
	RevocationOid    *byte
	OidSpecificInfo  Pointer
	HasFreshnessTime uint32
	FreshnessTime    uint32
	CrlInfo          *CertRevocationCrlInfo
}

type CertTrustStatus struct {
	ErrorStatus uint32
	InfoStatus  uint32
}

type CertUsageMatch struct {
	Type  uint32
	Usage CertEnhKeyUsage
}

type CertEnhKeyUsage struct {
	Length           uint32
	UsageIdentifiers **byte
}

type CertChainPara struct {
	Size                         uint32
	RequestedUsage               CertUsageMatch
	RequstedIssuancePolicy       CertUsageMatch
	URLRetrievalTimeout          uint32
	CheckRevocationFreshnessTime uint32
	RevocationFreshnessTime      uint32
	CacheResync                  *Filetime
}

type CertChainPolicyPara struct {
	Size            uint32
	Flags           uint32
	ExtraPolicyPara Pointer
}

type SSLExtraCertChainPolicyPara struct {
	Size       uint32
	AuthType   uint32
	Checks     uint32
	ServerName *uint16
}

type CertChainPolicyStatus struct {
	Size              uint32
	Error             uint32
	ChainIndex        uint32
	ElementIndex      uint32
	ExtraPolicyStatus Pointer
}

const (
	// do not reorder
	HKEY_CLASSES_ROOT = 0x80000000 + iota
	HKEY_CURRENT_USER
	HKEY_LOCAL_MACHINE
	HKEY_USERS
	HKEY_PERFORMANCE_DATA
	HKEY_CURRENT_CONFIG
	HKEY_DYN_DATA

	KEY_QUERY_VALUE        = 1
	KEY_SET_VALUE          = 2
	KEY_CREATE_SUB_KEY     = 4
	KEY_ENUMERATE_SUB_KEYS = 8
	KEY_NOTIFY             = 16
	KEY_CREATE_LINK        = 32
	KEY_WRITE              = 0x20006
	KEY_EXECUTE            = 0x20019
	KEY_READ               = 0x20019
	KEY_WOW64_64KEY        = 0x0100
	KEY_WOW64_32KEY        = 0x0200
	KEY_ALL_ACCESS         = 0xf003f
)

const (
	// do not reorder
	REG_NONE = iota
	REG_SZ
	REG_EXPAND_SZ
	REG_BINARY
	REG_DWORD_LITTLE_ENDIAN
	REG_DWORD_BIG_ENDIAN
	REG_LINK
	REG_MULTI_SZ
	REG_RESOURCE_LIST
	REG_FULL_RESOURCE_DESCRIPTOR
	REG_RESOURCE_REQUIREMENTS_LIST
	REG_QWORD_LITTLE_ENDIAN
	REG_DWORD = REG_DWORD_LITTLE_ENDIAN
	REG_QWORD = REG_QWORD_LITTLE_ENDIAN
)

type AddrinfoW struct {
	Flags     int32
	Family    int32
	Socktype  int32
	Protocol  int32
	Addrlen   uintptr
	Canonname *uint16
	Addr      Pointer
	Next      *AddrinfoW
}

const (
	AI_PASSIVE     = 1
	AI_CANONNAME   = 2
	AI_NUMERICHOST = 4
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var WSAID_CONNECTEX = GUID{
	0x25a207b9,
	0xddf3,
	0x4660,
	[8]byte{0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e},
}

const (
	FILE_SKIP_COMPLETION_PORT_ON_SUCCESS = 1
	FILE_SKIP_SET_EVENT_ON_HANDLE        = 2
)

const (
	WSAPROTOCOL_LEN    = 255
	MAX_PROTOCOL_CHAIN = 7
	BASE_PROTOCOL      = 1
	LAYERED_PROTOCOL   = 0

	XP1_CONNECTIONLESS           = 0x00000001
	XP1_GUARANTEED_DELIVERY      = 0x00000002
	XP1_GUARANTEED_ORDER         = 0x00000004
	XP1_MESSAGE_ORIENTED         = 0x00000008
	XP1_PSEUDO_STREAM            = 0x00000010
	XP1_GRACEFUL_CLOSE           = 0x00000020
	XP1_EXPEDITED_DATA           = 0x00000040
	XP1_CONNECT_DATA             = 0x00000080
	XP1_DISCONNECT_DATA          = 0x00000100
	XP1_SUPPORT_BROADCAST        = 0x00000200
	XP1_SUPPORT_MULTIPOINT       = 0x00000400
	XP1_MULTIPOINT_CONTROL_PLANE = 0x00000800
	XP1_MULTIPOINT_DATA_PLANE    = 0x00001000
	XP1_QOS_SUPPORTED            = 0x00002000
	XP1_UNI_SEND                 = 0x00008000
	XP1_UNI_RECV                 = 0x00010000
	XP1_IFS_HANDLES              = 0x00020000
	XP1_PARTIAL_MESSAGE          = 0x00040000
	XP1_SAN_SUPPORT_SDP          = 0x00080000

	PFL_MULTIPLE_PROTO_ENTRIES  = 0x00000001
	PFL_RECOMMENDED_PROTO_ENTRY = 0x00000002
	PFL_HIDDEN                  = 0x00000004
	PFL_MATCHES_PROTOCOL_ZERO   = 0x00000008
	PFL_NETWORKDIRECT_PROVIDER  = 0x00000010
)

type WSAProtocolInfo struct {
	ServiceFlags1     uint32
	ServiceFlags2     uint32
	ServiceFlags3     uint32
	ServiceFlags4     uint32
	ProviderFlags     uint32
	ProviderId        GUID
	CatalogEntryId    uint32
	ProtocolChain     WSAProtocolChain
	Version           int32
	AddressFamily     int32
	MaxSockAddr       int32
	MinSockAddr       int32
	SocketType        int32
	Protocol          int32
	ProtocolMaxOffset int32
	NetworkByteOrder  int32
	SecurityScheme    int32
	MessageSize       uint32
	ProviderReserved  uint32
	ProtocolName      [WSAPROTOCOL_LEN + 1]uint16
}

type WSAProtocolChain struct {
	ChainLen     int32
	ChainEntries [MAX_PROTOCOL_CHAIN]uint32
}

type TCPKeepalive struct {
	OnOff    uint32
	Time     uint32
	Interval uint32
}

type symbolicLinkReparseBuffer struct {
	SubstituteNameOffset uint16
	SubstituteNameLength uint16
	PrintNameOffset      uint16
	PrintNameLength      uint16
	Flags                uint32
	PathBuffer           [1]uint16
}

type mountPointReparseBuffer struct {
	SubstituteNameOffset uint16
	SubstituteNameLength uint16
	PrintNameOffset      uint16
	PrintNameLength      uint16
	PathBuffer           [1]uint16
}

type reparseDataBuffer struct {
	ReparseTag        uint32
	ReparseDataLength uint16
	Reserved          uint16

	// GenericReparseBuffer
	reparseBuffer byte
}

const (
	FSCTL_GET_REPARSE_POINT          = 0x900A8
	MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16 * 1024
	_IO_REPARSE_TAG_MOUNT_POINT      = 0xA0000003
	IO_REPARSE_TAG_SYMLINK           = 0xA000000C
	SYMBOLIC_LINK_FLAG_DIRECTORY     = 0x1
	_SYMLINK_FLAG_RELATIVE           = 1
)

const UNIX_PATH_MAX = 108 // defined in afunix.h

"""



```