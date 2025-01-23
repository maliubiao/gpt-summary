Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the provided Go code, its purpose within the larger Go ecosystem, examples of its use, and a summary. The path `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` immediately suggests this is about Windows-specific system calls and error codes. The `vendor` directory implies it's a dependency of some other Go project. The `zerrors` part strongly hints at "generated errors."

2. **Initial Code Scan and Interpretation:**  The code consists primarily of Go constant declarations. Each constant has the form `STATUS_... NTStatus = 0x...`. This pattern is very clear:  it's defining symbolic names for specific numerical error codes returned by the Windows operating system. The `NTStatus` type suggests these are related to the NT kernel.

3. **Identifying the Core Functionality:** The primary function is to provide human-readable names for Windows error codes. Instead of just seeing a cryptic hexadecimal number, developers can use these constants, making the code more understandable and maintainable.

4. **Connecting to Go Concepts:** How does this fit into Go?
    * **Constants:**  Go's `const` keyword is used for defining these error codes.
    * **Error Handling:**  Go has a standard way of handling errors using the `error` interface. While this code *defines* the errors, it's likely used in conjunction with functions that *return* errors.
    * **`golang.org/x/sys/windows`:** This package is the standard Go library for interacting with Windows system calls. This file is a part of that ecosystem.

5. **Inferring the Use Case:**  When would a developer use these constants?  When interacting with Windows-specific APIs that might return these errors. This could involve file system operations, networking, device management, security, etc.

6. **Generating a Go Code Example:**  To illustrate the use, an example needs to demonstrate how these constants are used in practice. This involves:
    * Calling a Windows API function (simulated here since we don't have a specific context from the snippet). `syscall.GetLastError()` is a good example, even though the provided constants are `NTStatus` rather than direct `GetLastError` codes. The key is to show the *intent* of using these constants.
    * Checking for an error.
    * Comparing the returned error code with the defined constants.
    * Printing a user-friendly error message based on the constant.

7. **Considering Command-Line Arguments (and realizing they're unlikely here):** The filename and content don't suggest any command-line argument processing. This file is about *defining* error codes, not *running* a program that takes arguments.

8. **Identifying Potential Pitfalls:**  What mistakes could developers make?
    * **Incorrect Error Checking:**  Not properly checking the error return of Windows API calls.
    * **Assuming All Errors Are Listed:** The file might not contain *every* possible Windows error code.
    * **Misinterpreting the Error Meaning:**  While the names are descriptive, developers should still consult the official Windows documentation for a complete understanding.

9. **Summarizing the Functionality (as the 15th part):** The final step is to provide a concise summary, emphasizing the core purpose of the file: providing named constants for Windows-specific error codes, particularly those related to volume management, virtual disks, secure boot, etc. Highlight that it improves code readability and maintainability when dealing with low-level Windows APIs.

10. **Review and Refine:**  Read through the entire analysis to ensure clarity, accuracy, and completeness. Check that the example code is correct and demonstrates the intended usage. Make sure the summary accurately reflects the file's purpose. For instance, initially, I might have focused solely on `NTStatus`. However, a closer look reveals categories like `STATUS_VOLMGR`, `STATUS_VHD`, `STATUS_SECUREBOOT`, which suggests a broader scope within the system.

This iterative process of understanding, interpreting, connecting, illustrating, and summarizing helps in generating a comprehensive and accurate analysis of the given Go code snippet.
这是提供的 Go 语言代码片段，位于 `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` 路径下，是该文件的第 15 部分，也是最后一部分。

**它的功能：**

这个代码片段的主要功能是**定义了大量的 Windows NT 状态码（NTStatus）常量**。

具体来说：

* **`NTStatus` 类型：**  虽然代码中没有显式定义 `NTStatus` 类型，但通过赋值可以推断出它是一个可以存储 Windows NT 状态码的类型（很可能是一个 `uint32` 或 `int32`）。
* **常量定义：** 代码块中定义了大量的以 `STATUS_` 开头的常量，例如 `STATUS_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC`， `STATUS_VHD_DRIVE_FOOTER_MISSING` 等。
* **Windows 错误码映射：**  每个常量都被赋予一个十六进制的数值，这个数值对应着 Windows 操作系统中特定的错误或状态代码。
* **分类组织：** 这些常量似乎是按照功能模块或子系统进行组织的，例如 `STATUS_VOLMGR_` 开头的与卷管理器相关，`STATUS_VHD_` 开头的与虚拟硬盘相关，`STATUS_SECUREBOOT_` 开头的与安全启动相关等等。

**推理其实现的 Go 语言功能：**

这个代码片段的核心是利用 Go 语言的**常量声明**功能 (`const`) 来为 Windows 系统级的错误码提供有意义的名称。这极大地提高了代码的可读性和可维护性。开发者在处理 Windows API 调用返回的错误码时，可以使用这些常量，而不是直接使用难以理解的数字。

**Go 代码举例说明：**

假设我们调用了一个可能返回与虚拟硬盘 (VHD) 相关的错误的 Windows API 函数。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 假设存在一个 Windows API 函数 CreateVirtualDisk
// (这只是一个示例，实际 API 可能更复杂)
var (
	kernel32           = syscall.MustLoadDLL("kernel32.dll")
	procCreateVirtualDisk = kernel32.MustFindProc("CreateVirtualDisk")
)

// 模拟 CreateVirtualDisk 函数的返回值结构
type CreateVirtualDiskResult struct {
	Handle windows.Handle
	Error  windows.Errno
}

func CreateVirtualDisk(path string, size uint64) CreateVirtualDiskResult {
	// ... (模拟调用 Windows API 的过程) ...
	// 这里为了演示，假设 API 调用失败，并返回一个特定的 VHD 错误码
	return CreateVirtualDiskResult{Handle: 0, Error: windows.Errno(windows.STATUS_VHD_DRIVE_FOOTER_MISSING)}
}

func main() {
	diskPath := "C:\\MyVirtualDisk.vhdx"
	diskSize := uint64(1024 * 1024 * 1024) // 1GB

	result := CreateVirtualDisk(diskPath, diskSize)

	if result.Error != 0 {
		switch result.Error {
		case windows.Errno(windows.STATUS_VHD_DRIVE_FOOTER_MISSING):
			fmt.Println("错误：虚拟硬盘驱动器页脚丢失。")
		case windows.Errno(windows.STATUS_VHD_INVALID_SIZE):
			fmt.Println("错误：虚拟硬盘大小无效。")
		// ... 可以处理更多的 VHD 相关错误 ...
		default:
			fmt.Printf("未知错误：%#x\n", result.Error)
		}
	} else {
		fmt.Println("虚拟硬盘创建成功！")
		windows.CloseHandle(result.Handle)
	}
}
```

**假设的输入与输出：**

在上面的例子中，假设 `CreateVirtualDisk` 函数被调用，但由于某种原因（例如，指定的文件不存在或损坏），它返回了一个错误码 `STATUS_VHD_DRIVE_FOOTER_MISSING`。

**输出：**

```
错误：虚拟硬盘驱动器页脚丢失。
```

**命令行参数的具体处理：**

这个代码片段本身不涉及任何命令行参数的处理。它只是定义了一些常量。命令行参数的处理通常发生在调用 Windows API 的上层代码中。

**使用者易犯错的点：**

* **错误的类型转换：**  需要注意将 Windows API 返回的错误码转换为 `windows.Errno` 类型，以便与定义的常量进行比较。例如，在上面的例子中，我们使用了 `windows.Errno(windows.STATUS_VHD_DRIVE_FOOTER_MISSING)`。
* **未处理所有可能的错误：**  开发者可能会忽略某些不太常见的错误码，导致程序在遇到这些错误时无法给出清晰的提示或采取正确的处理措施。
* **直接使用数字错误码：**  虽然可以使用数字错误码，但强烈建议使用这些预定义的常量，以提高代码的可读性和可维护性。

**归纳一下它的功能（作为第 15 部分）：**

作为 `zerrors_windows.go` 文件的最后一部分，这个代码片段延续了该文件的核心功能：**详细定义了 Windows 操作系统中与各种子系统相关的 NT 状态码常量**。  这部分特别涵盖了：

* **卷管理器 (Volume Manager):**  与磁盘和卷管理相关的错误，例如磁盘配置不同步、磁盘包含非简单卷、磁盘重复等等。
* **引导配置数据 (BCD):** 与启动配置数据相关的错误。
* **虚拟硬盘 (VHD/VHDX):**  与虚拟硬盘操作相关的错误，例如驱动器页脚丢失、校验和不匹配、格式未知等等。
* **安全启动 (Secure Boot):** 与安全启动机制相关的错误，例如检测到回滚、策略冲突、策略未签名等等。
* **系统完整性 (System Integrity):** 与系统完整性保护相关的错误。
* **应用程序执行 (AppExec):** 与应用程序执行环境相关的错误。
* **音频 (Audio):** 与音频设备相关的错误。
* **存储空间 (Storage Spaces):** 与存储空间功能相关的错误。
* **卷影复制服务 (Volume Shadow Copy Service):** 与卷影复制相关的错误。
* **Server Virtual Hard Disk Extended (SVHDX):**  与共享虚拟硬盘相关的错误。
* **服务器消息块协议 (SMB):** 与 SMB 协议相关的错误。
* **安全核心 (SecCore):** 与安全核心相关的错误。
* **虚拟机监控程序 (VSM):** 与虚拟机监控程序相关的错误。
* **平台清单 (Platform Manifest):** 与平台清单验证相关的错误。
* **许可证 (License):** 与应用程序许可证相关的错误。

**总结来说，这最后一部分涵盖了各种系统级错误，进一步完善了 Go 语言对 Windows 错误码的抽象，使得 Go 程序能够更精细、更准确地处理 Windows 平台上的各种潜在错误情况。** 整个 `zerrors_windows.go` 文件为 Go 开发者提供了一个方便且全面的 Windows 错误码参考，极大地简化了 Windows 平台编程的错误处理工作。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第15部分，共15部分，请归纳一下它的功能
```

### 源代码
```go
NTStatus      = 0xC0380002
	STATUS_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC                              NTStatus      = 0xC0380003
	STATUS_VOLMGR_PACK_CONFIG_UPDATE_FAILED                                   NTStatus      = 0xC0380004
	STATUS_VOLMGR_DISK_CONTAINS_NON_SIMPLE_VOLUME                             NTStatus      = 0xC0380005
	STATUS_VOLMGR_DISK_DUPLICATE                                              NTStatus      = 0xC0380006
	STATUS_VOLMGR_DISK_DYNAMIC                                                NTStatus      = 0xC0380007
	STATUS_VOLMGR_DISK_ID_INVALID                                             NTStatus      = 0xC0380008
	STATUS_VOLMGR_DISK_INVALID                                                NTStatus      = 0xC0380009
	STATUS_VOLMGR_DISK_LAST_VOTER                                             NTStatus      = 0xC038000A
	STATUS_VOLMGR_DISK_LAYOUT_INVALID                                         NTStatus      = 0xC038000B
	STATUS_VOLMGR_DISK_LAYOUT_NON_BASIC_BETWEEN_BASIC_PARTITIONS              NTStatus      = 0xC038000C
	STATUS_VOLMGR_DISK_LAYOUT_NOT_CYLINDER_ALIGNED                            NTStatus      = 0xC038000D
	STATUS_VOLMGR_DISK_LAYOUT_PARTITIONS_TOO_SMALL                            NTStatus      = 0xC038000E
	STATUS_VOLMGR_DISK_LAYOUT_PRIMARY_BETWEEN_LOGICAL_PARTITIONS              NTStatus      = 0xC038000F
	STATUS_VOLMGR_DISK_LAYOUT_TOO_MANY_PARTITIONS                             NTStatus      = 0xC0380010
	STATUS_VOLMGR_DISK_MISSING                                                NTStatus      = 0xC0380011
	STATUS_VOLMGR_DISK_NOT_EMPTY                                              NTStatus      = 0xC0380012
	STATUS_VOLMGR_DISK_NOT_ENOUGH_SPACE                                       NTStatus      = 0xC0380013
	STATUS_VOLMGR_DISK_REVECTORING_FAILED                                     NTStatus      = 0xC0380014
	STATUS_VOLMGR_DISK_SECTOR_SIZE_INVALID                                    NTStatus      = 0xC0380015
	STATUS_VOLMGR_DISK_SET_NOT_CONTAINED                                      NTStatus      = 0xC0380016
	STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_MEMBERS                               NTStatus      = 0xC0380017
	STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_PLEXES                                NTStatus      = 0xC0380018
	STATUS_VOLMGR_DYNAMIC_DISK_NOT_SUPPORTED                                  NTStatus      = 0xC0380019
	STATUS_VOLMGR_EXTENT_ALREADY_USED                                         NTStatus      = 0xC038001A
	STATUS_VOLMGR_EXTENT_NOT_CONTIGUOUS                                       NTStatus      = 0xC038001B
	STATUS_VOLMGR_EXTENT_NOT_IN_PUBLIC_REGION                                 NTStatus      = 0xC038001C
	STATUS_VOLMGR_EXTENT_NOT_SECTOR_ALIGNED                                   NTStatus      = 0xC038001D
	STATUS_VOLMGR_EXTENT_OVERLAPS_EBR_PARTITION                               NTStatus      = 0xC038001E
	STATUS_VOLMGR_EXTENT_VOLUME_LENGTHS_DO_NOT_MATCH                          NTStatus      = 0xC038001F
	STATUS_VOLMGR_FAULT_TOLERANT_NOT_SUPPORTED                                NTStatus      = 0xC0380020
	STATUS_VOLMGR_INTERLEAVE_LENGTH_INVALID                                   NTStatus      = 0xC0380021
	STATUS_VOLMGR_MAXIMUM_REGISTERED_USERS                                    NTStatus      = 0xC0380022
	STATUS_VOLMGR_MEMBER_IN_SYNC                                              NTStatus      = 0xC0380023
	STATUS_VOLMGR_MEMBER_INDEX_DUPLICATE                                      NTStatus      = 0xC0380024
	STATUS_VOLMGR_MEMBER_INDEX_INVALID                                        NTStatus      = 0xC0380025
	STATUS_VOLMGR_MEMBER_MISSING                                              NTStatus      = 0xC0380026
	STATUS_VOLMGR_MEMBER_NOT_DETACHED                                         NTStatus      = 0xC0380027
	STATUS_VOLMGR_MEMBER_REGENERATING                                         NTStatus      = 0xC0380028
	STATUS_VOLMGR_ALL_DISKS_FAILED                                            NTStatus      = 0xC0380029
	STATUS_VOLMGR_NO_REGISTERED_USERS                                         NTStatus      = 0xC038002A
	STATUS_VOLMGR_NO_SUCH_USER                                                NTStatus      = 0xC038002B
	STATUS_VOLMGR_NOTIFICATION_RESET                                          NTStatus      = 0xC038002C
	STATUS_VOLMGR_NUMBER_OF_MEMBERS_INVALID                                   NTStatus      = 0xC038002D
	STATUS_VOLMGR_NUMBER_OF_PLEXES_INVALID                                    NTStatus      = 0xC038002E
	STATUS_VOLMGR_PACK_DUPLICATE                                              NTStatus      = 0xC038002F
	STATUS_VOLMGR_PACK_ID_INVALID                                             NTStatus      = 0xC0380030
	STATUS_VOLMGR_PACK_INVALID                                                NTStatus      = 0xC0380031
	STATUS_VOLMGR_PACK_NAME_INVALID                                           NTStatus      = 0xC0380032
	STATUS_VOLMGR_PACK_OFFLINE                                                NTStatus      = 0xC0380033
	STATUS_VOLMGR_PACK_HAS_QUORUM                                             NTStatus      = 0xC0380034
	STATUS_VOLMGR_PACK_WITHOUT_QUORUM                                         NTStatus      = 0xC0380035
	STATUS_VOLMGR_PARTITION_STYLE_INVALID                                     NTStatus      = 0xC0380036
	STATUS_VOLMGR_PARTITION_UPDATE_FAILED                                     NTStatus      = 0xC0380037
	STATUS_VOLMGR_PLEX_IN_SYNC                                                NTStatus      = 0xC0380038
	STATUS_VOLMGR_PLEX_INDEX_DUPLICATE                                        NTStatus      = 0xC0380039
	STATUS_VOLMGR_PLEX_INDEX_INVALID                                          NTStatus      = 0xC038003A
	STATUS_VOLMGR_PLEX_LAST_ACTIVE                                            NTStatus      = 0xC038003B
	STATUS_VOLMGR_PLEX_MISSING                                                NTStatus      = 0xC038003C
	STATUS_VOLMGR_PLEX_REGENERATING                                           NTStatus      = 0xC038003D
	STATUS_VOLMGR_PLEX_TYPE_INVALID                                           NTStatus      = 0xC038003E
	STATUS_VOLMGR_PLEX_NOT_RAID5                                              NTStatus      = 0xC038003F
	STATUS_VOLMGR_PLEX_NOT_SIMPLE                                             NTStatus      = 0xC0380040
	STATUS_VOLMGR_STRUCTURE_SIZE_INVALID                                      NTStatus      = 0xC0380041
	STATUS_VOLMGR_TOO_MANY_NOTIFICATION_REQUESTS                              NTStatus      = 0xC0380042
	STATUS_VOLMGR_TRANSACTION_IN_PROGRESS                                     NTStatus      = 0xC0380043
	STATUS_VOLMGR_UNEXPECTED_DISK_LAYOUT_CHANGE                               NTStatus      = 0xC0380044
	STATUS_VOLMGR_VOLUME_CONTAINS_MISSING_DISK                                NTStatus      = 0xC0380045
	STATUS_VOLMGR_VOLUME_ID_INVALID                                           NTStatus      = 0xC0380046
	STATUS_VOLMGR_VOLUME_LENGTH_INVALID                                       NTStatus      = 0xC0380047
	STATUS_VOLMGR_VOLUME_LENGTH_NOT_SECTOR_SIZE_MULTIPLE                      NTStatus      = 0xC0380048
	STATUS_VOLMGR_VOLUME_NOT_MIRRORED                                         NTStatus      = 0xC0380049
	STATUS_VOLMGR_VOLUME_NOT_RETAINED                                         NTStatus      = 0xC038004A
	STATUS_VOLMGR_VOLUME_OFFLINE                                              NTStatus      = 0xC038004B
	STATUS_VOLMGR_VOLUME_RETAINED                                             NTStatus      = 0xC038004C
	STATUS_VOLMGR_NUMBER_OF_EXTENTS_INVALID                                   NTStatus      = 0xC038004D
	STATUS_VOLMGR_DIFFERENT_SECTOR_SIZE                                       NTStatus      = 0xC038004E
	STATUS_VOLMGR_BAD_BOOT_DISK                                               NTStatus      = 0xC038004F
	STATUS_VOLMGR_PACK_CONFIG_OFFLINE                                         NTStatus      = 0xC0380050
	STATUS_VOLMGR_PACK_CONFIG_ONLINE                                          NTStatus      = 0xC0380051
	STATUS_VOLMGR_NOT_PRIMARY_PACK                                            NTStatus      = 0xC0380052
	STATUS_VOLMGR_PACK_LOG_UPDATE_FAILED                                      NTStatus      = 0xC0380053
	STATUS_VOLMGR_NUMBER_OF_DISKS_IN_PLEX_INVALID                             NTStatus      = 0xC0380054
	STATUS_VOLMGR_NUMBER_OF_DISKS_IN_MEMBER_INVALID                           NTStatus      = 0xC0380055
	STATUS_VOLMGR_VOLUME_MIRRORED                                             NTStatus      = 0xC0380056
	STATUS_VOLMGR_PLEX_NOT_SIMPLE_SPANNED                                     NTStatus      = 0xC0380057
	STATUS_VOLMGR_NO_VALID_LOG_COPIES                                         NTStatus      = 0xC0380058
	STATUS_VOLMGR_PRIMARY_PACK_PRESENT                                        NTStatus      = 0xC0380059
	STATUS_VOLMGR_NUMBER_OF_DISKS_INVALID                                     NTStatus      = 0xC038005A
	STATUS_VOLMGR_MIRROR_NOT_SUPPORTED                                        NTStatus      = 0xC038005B
	STATUS_VOLMGR_RAID5_NOT_SUPPORTED                                         NTStatus      = 0xC038005C
	STATUS_BCD_NOT_ALL_ENTRIES_IMPORTED                                       NTStatus      = 0x80390001
	STATUS_BCD_TOO_MANY_ELEMENTS                                              NTStatus      = 0xC0390002
	STATUS_BCD_NOT_ALL_ENTRIES_SYNCHRONIZED                                   NTStatus      = 0x80390003
	STATUS_VHD_DRIVE_FOOTER_MISSING                                           NTStatus      = 0xC03A0001
	STATUS_VHD_DRIVE_FOOTER_CHECKSUM_MISMATCH                                 NTStatus      = 0xC03A0002
	STATUS_VHD_DRIVE_FOOTER_CORRUPT                                           NTStatus      = 0xC03A0003
	STATUS_VHD_FORMAT_UNKNOWN                                                 NTStatus      = 0xC03A0004
	STATUS_VHD_FORMAT_UNSUPPORTED_VERSION                                     NTStatus      = 0xC03A0005
	STATUS_VHD_SPARSE_HEADER_CHECKSUM_MISMATCH                                NTStatus      = 0xC03A0006
	STATUS_VHD_SPARSE_HEADER_UNSUPPORTED_VERSION                              NTStatus      = 0xC03A0007
	STATUS_VHD_SPARSE_HEADER_CORRUPT                                          NTStatus      = 0xC03A0008
	STATUS_VHD_BLOCK_ALLOCATION_FAILURE                                       NTStatus      = 0xC03A0009
	STATUS_VHD_BLOCK_ALLOCATION_TABLE_CORRUPT                                 NTStatus      = 0xC03A000A
	STATUS_VHD_INVALID_BLOCK_SIZE                                             NTStatus      = 0xC03A000B
	STATUS_VHD_BITMAP_MISMATCH                                                NTStatus      = 0xC03A000C
	STATUS_VHD_PARENT_VHD_NOT_FOUND                                           NTStatus      = 0xC03A000D
	STATUS_VHD_CHILD_PARENT_ID_MISMATCH                                       NTStatus      = 0xC03A000E
	STATUS_VHD_CHILD_PARENT_TIMESTAMP_MISMATCH                                NTStatus      = 0xC03A000F
	STATUS_VHD_METADATA_READ_FAILURE                                          NTStatus      = 0xC03A0010
	STATUS_VHD_METADATA_WRITE_FAILURE                                         NTStatus      = 0xC03A0011
	STATUS_VHD_INVALID_SIZE                                                   NTStatus      = 0xC03A0012
	STATUS_VHD_INVALID_FILE_SIZE                                              NTStatus      = 0xC03A0013
	STATUS_VIRTDISK_PROVIDER_NOT_FOUND                                        NTStatus      = 0xC03A0014
	STATUS_VIRTDISK_NOT_VIRTUAL_DISK                                          NTStatus      = 0xC03A0015
	STATUS_VHD_PARENT_VHD_ACCESS_DENIED                                       NTStatus      = 0xC03A0016
	STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH                                     NTStatus      = 0xC03A0017
	STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED                              NTStatus      = 0xC03A0018
	STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT                             NTStatus      = 0xC03A0019
	STATUS_VIRTUAL_DISK_LIMITATION                                            NTStatus      = 0xC03A001A
	STATUS_VHD_INVALID_TYPE                                                   NTStatus      = 0xC03A001B
	STATUS_VHD_INVALID_STATE                                                  NTStatus      = 0xC03A001C
	STATUS_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE                              NTStatus      = 0xC03A001D
	STATUS_VIRTDISK_DISK_ALREADY_OWNED                                        NTStatus      = 0xC03A001E
	STATUS_VIRTDISK_DISK_ONLINE_AND_WRITABLE                                  NTStatus      = 0xC03A001F
	STATUS_CTLOG_TRACKING_NOT_INITIALIZED                                     NTStatus      = 0xC03A0020
	STATUS_CTLOG_LOGFILE_SIZE_EXCEEDED_MAXSIZE                                NTStatus      = 0xC03A0021
	STATUS_CTLOG_VHD_CHANGED_OFFLINE                                          NTStatus      = 0xC03A0022
	STATUS_CTLOG_INVALID_TRACKING_STATE                                       NTStatus      = 0xC03A0023
	STATUS_CTLOG_INCONSISTENT_TRACKING_FILE                                   NTStatus      = 0xC03A0024
	STATUS_VHD_METADATA_FULL                                                  NTStatus      = 0xC03A0028
	STATUS_VHD_INVALID_CHANGE_TRACKING_ID                                     NTStatus      = 0xC03A0029
	STATUS_VHD_CHANGE_TRACKING_DISABLED                                       NTStatus      = 0xC03A002A
	STATUS_VHD_MISSING_CHANGE_TRACKING_INFORMATION                            NTStatus      = 0xC03A0030
	STATUS_VHD_RESIZE_WOULD_TRUNCATE_DATA                                     NTStatus      = 0xC03A0031
	STATUS_VHD_COULD_NOT_COMPUTE_MINIMUM_VIRTUAL_SIZE                         NTStatus      = 0xC03A0032
	STATUS_VHD_ALREADY_AT_OR_BELOW_MINIMUM_VIRTUAL_SIZE                       NTStatus      = 0xC03A0033
	STATUS_QUERY_STORAGE_ERROR                                                NTStatus      = 0x803A0001
	STATUS_GDI_HANDLE_LEAK                                                    NTStatus      = 0x803F0001
	STATUS_RKF_KEY_NOT_FOUND                                                  NTStatus      = 0xC0400001
	STATUS_RKF_DUPLICATE_KEY                                                  NTStatus      = 0xC0400002
	STATUS_RKF_BLOB_FULL                                                      NTStatus      = 0xC0400003
	STATUS_RKF_STORE_FULL                                                     NTStatus      = 0xC0400004
	STATUS_RKF_FILE_BLOCKED                                                   NTStatus      = 0xC0400005
	STATUS_RKF_ACTIVE_KEY                                                     NTStatus      = 0xC0400006
	STATUS_RDBSS_RESTART_OPERATION                                            NTStatus      = 0xC0410001
	STATUS_RDBSS_CONTINUE_OPERATION                                           NTStatus      = 0xC0410002
	STATUS_RDBSS_POST_OPERATION                                               NTStatus      = 0xC0410003
	STATUS_RDBSS_RETRY_LOOKUP                                                 NTStatus      = 0xC0410004
	STATUS_BTH_ATT_INVALID_HANDLE                                             NTStatus      = 0xC0420001
	STATUS_BTH_ATT_READ_NOT_PERMITTED                                         NTStatus      = 0xC0420002
	STATUS_BTH_ATT_WRITE_NOT_PERMITTED                                        NTStatus      = 0xC0420003
	STATUS_BTH_ATT_INVALID_PDU                                                NTStatus      = 0xC0420004
	STATUS_BTH_ATT_INSUFFICIENT_AUTHENTICATION                                NTStatus      = 0xC0420005
	STATUS_BTH_ATT_REQUEST_NOT_SUPPORTED                                      NTStatus      = 0xC0420006
	STATUS_BTH_ATT_INVALID_OFFSET                                             NTStatus      = 0xC0420007
	STATUS_BTH_ATT_INSUFFICIENT_AUTHORIZATION                                 NTStatus      = 0xC0420008
	STATUS_BTH_ATT_PREPARE_QUEUE_FULL                                         NTStatus      = 0xC0420009
	STATUS_BTH_ATT_ATTRIBUTE_NOT_FOUND                                        NTStatus      = 0xC042000A
	STATUS_BTH_ATT_ATTRIBUTE_NOT_LONG                                         NTStatus      = 0xC042000B
	STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE                           NTStatus      = 0xC042000C
	STATUS_BTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH                             NTStatus      = 0xC042000D
	STATUS_BTH_ATT_UNLIKELY                                                   NTStatus      = 0xC042000E
	STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION                                    NTStatus      = 0xC042000F
	STATUS_BTH_ATT_UNSUPPORTED_GROUP_TYPE                                     NTStatus      = 0xC0420010
	STATUS_BTH_ATT_INSUFFICIENT_RESOURCES                                     NTStatus      = 0xC0420011
	STATUS_BTH_ATT_UNKNOWN_ERROR                                              NTStatus      = 0xC0421000
	STATUS_SECUREBOOT_ROLLBACK_DETECTED                                       NTStatus      = 0xC0430001
	STATUS_SECUREBOOT_POLICY_VIOLATION                                        NTStatus      = 0xC0430002
	STATUS_SECUREBOOT_INVALID_POLICY                                          NTStatus      = 0xC0430003
	STATUS_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND                              NTStatus      = 0xC0430004
	STATUS_SECUREBOOT_POLICY_NOT_SIGNED                                       NTStatus      = 0xC0430005
	STATUS_SECUREBOOT_NOT_ENABLED                                             NTStatus      = 0x80430006
	STATUS_SECUREBOOT_FILE_REPLACED                                           NTStatus      = 0xC0430007
	STATUS_SECUREBOOT_POLICY_NOT_AUTHORIZED                                   NTStatus      = 0xC0430008
	STATUS_SECUREBOOT_POLICY_UNKNOWN                                          NTStatus      = 0xC0430009
	STATUS_SECUREBOOT_POLICY_MISSING_ANTIROLLBACKVERSION                      NTStatus      = 0xC043000A
	STATUS_SECUREBOOT_PLATFORM_ID_MISMATCH                                    NTStatus      = 0xC043000B
	STATUS_SECUREBOOT_POLICY_ROLLBACK_DETECTED                                NTStatus      = 0xC043000C
	STATUS_SECUREBOOT_POLICY_UPGRADE_MISMATCH                                 NTStatus      = 0xC043000D
	STATUS_SECUREBOOT_REQUIRED_POLICY_FILE_MISSING                            NTStatus      = 0xC043000E
	STATUS_SECUREBOOT_NOT_BASE_POLICY                                         NTStatus      = 0xC043000F
	STATUS_SECUREBOOT_NOT_SUPPLEMENTAL_POLICY                                 NTStatus      = 0xC0430010
	STATUS_PLATFORM_MANIFEST_NOT_AUTHORIZED                                   NTStatus      = 0xC0EB0001
	STATUS_PLATFORM_MANIFEST_INVALID                                          NTStatus      = 0xC0EB0002
	STATUS_PLATFORM_MANIFEST_FILE_NOT_AUTHORIZED                              NTStatus      = 0xC0EB0003
	STATUS_PLATFORM_MANIFEST_CATALOG_NOT_AUTHORIZED                           NTStatus      = 0xC0EB0004
	STATUS_PLATFORM_MANIFEST_BINARY_ID_NOT_FOUND                              NTStatus      = 0xC0EB0005
	STATUS_PLATFORM_MANIFEST_NOT_ACTIVE                                       NTStatus      = 0xC0EB0006
	STATUS_PLATFORM_MANIFEST_NOT_SIGNED                                       NTStatus      = 0xC0EB0007
	STATUS_SYSTEM_INTEGRITY_ROLLBACK_DETECTED                                 NTStatus      = 0xC0E90001
	STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION                                  NTStatus      = 0xC0E90002
	STATUS_SYSTEM_INTEGRITY_INVALID_POLICY                                    NTStatus      = 0xC0E90003
	STATUS_SYSTEM_INTEGRITY_POLICY_NOT_SIGNED                                 NTStatus      = 0xC0E90004
	STATUS_SYSTEM_INTEGRITY_TOO_MANY_POLICIES                                 NTStatus      = 0xC0E90005
	STATUS_SYSTEM_INTEGRITY_SUPPLEMENTAL_POLICY_NOT_AUTHORIZED                NTStatus      = 0xC0E90006
	STATUS_NO_APPLICABLE_APP_LICENSES_FOUND                                   NTStatus      = 0xC0EA0001
	STATUS_CLIP_LICENSE_NOT_FOUND                                             NTStatus      = 0xC0EA0002
	STATUS_CLIP_DEVICE_LICENSE_MISSING                                        NTStatus      = 0xC0EA0003
	STATUS_CLIP_LICENSE_INVALID_SIGNATURE                                     NTStatus      = 0xC0EA0004
	STATUS_CLIP_KEYHOLDER_LICENSE_MISSING_OR_INVALID                          NTStatus      = 0xC0EA0005
	STATUS_CLIP_LICENSE_EXPIRED                                               NTStatus      = 0xC0EA0006
	STATUS_CLIP_LICENSE_SIGNED_BY_UNKNOWN_SOURCE                              NTStatus      = 0xC0EA0007
	STATUS_CLIP_LICENSE_NOT_SIGNED                                            NTStatus      = 0xC0EA0008
	STATUS_CLIP_LICENSE_HARDWARE_ID_OUT_OF_TOLERANCE                          NTStatus      = 0xC0EA0009
	STATUS_CLIP_LICENSE_DEVICE_ID_MISMATCH                                    NTStatus      = 0xC0EA000A
	STATUS_AUDIO_ENGINE_NODE_NOT_FOUND                                        NTStatus      = 0xC0440001
	STATUS_HDAUDIO_EMPTY_CONNECTION_LIST                                      NTStatus      = 0xC0440002
	STATUS_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED                              NTStatus      = 0xC0440003
	STATUS_HDAUDIO_NO_LOGICAL_DEVICES_CREATED                                 NTStatus      = 0xC0440004
	STATUS_HDAUDIO_NULL_LINKED_LIST_ENTRY                                     NTStatus      = 0xC0440005
	STATUS_SPACES_REPAIRED                                                    NTStatus      = 0x00E70000
	STATUS_SPACES_PAUSE                                                       NTStatus      = 0x00E70001
	STATUS_SPACES_COMPLETE                                                    NTStatus      = 0x00E70002
	STATUS_SPACES_REDIRECT                                                    NTStatus      = 0x00E70003
	STATUS_SPACES_FAULT_DOMAIN_TYPE_INVALID                                   NTStatus      = 0xC0E70001
	STATUS_SPACES_RESILIENCY_TYPE_INVALID                                     NTStatus      = 0xC0E70003
	STATUS_SPACES_DRIVE_SECTOR_SIZE_INVALID                                   NTStatus      = 0xC0E70004
	STATUS_SPACES_DRIVE_REDUNDANCY_INVALID                                    NTStatus      = 0xC0E70006
	STATUS_SPACES_NUMBER_OF_DATA_COPIES_INVALID                               NTStatus      = 0xC0E70007
	STATUS_SPACES_INTERLEAVE_LENGTH_INVALID                                   NTStatus      = 0xC0E70009
	STATUS_SPACES_NUMBER_OF_COLUMNS_INVALID                                   NTStatus      = 0xC0E7000A
	STATUS_SPACES_NOT_ENOUGH_DRIVES                                           NTStatus      = 0xC0E7000B
	STATUS_SPACES_EXTENDED_ERROR                                              NTStatus      = 0xC0E7000C
	STATUS_SPACES_PROVISIONING_TYPE_INVALID                                   NTStatus      = 0xC0E7000D
	STATUS_SPACES_ALLOCATION_SIZE_INVALID                                     NTStatus      = 0xC0E7000E
	STATUS_SPACES_ENCLOSURE_AWARE_INVALID                                     NTStatus      = 0xC0E7000F
	STATUS_SPACES_WRITE_CACHE_SIZE_INVALID                                    NTStatus      = 0xC0E70010
	STATUS_SPACES_NUMBER_OF_GROUPS_INVALID                                    NTStatus      = 0xC0E70011
	STATUS_SPACES_DRIVE_OPERATIONAL_STATE_INVALID                             NTStatus      = 0xC0E70012
	STATUS_SPACES_UPDATE_COLUMN_STATE                                         NTStatus      = 0xC0E70013
	STATUS_SPACES_MAP_REQUIRED                                                NTStatus      = 0xC0E70014
	STATUS_SPACES_UNSUPPORTED_VERSION                                         NTStatus      = 0xC0E70015
	STATUS_SPACES_CORRUPT_METADATA                                            NTStatus      = 0xC0E70016
	STATUS_SPACES_DRT_FULL                                                    NTStatus      = 0xC0E70017
	STATUS_SPACES_INCONSISTENCY                                               NTStatus      = 0xC0E70018
	STATUS_SPACES_LOG_NOT_READY                                               NTStatus      = 0xC0E70019
	STATUS_SPACES_NO_REDUNDANCY                                               NTStatus      = 0xC0E7001A
	STATUS_SPACES_DRIVE_NOT_READY                                             NTStatus      = 0xC0E7001B
	STATUS_SPACES_DRIVE_SPLIT                                                 NTStatus      = 0xC0E7001C
	STATUS_SPACES_DRIVE_LOST_DATA                                             NTStatus      = 0xC0E7001D
	STATUS_SPACES_ENTRY_INCOMPLETE                                            NTStatus      = 0xC0E7001E
	STATUS_SPACES_ENTRY_INVALID                                               NTStatus      = 0xC0E7001F
	STATUS_SPACES_MARK_DIRTY                                                  NTStatus      = 0xC0E70020
	STATUS_VOLSNAP_BOOTFILE_NOT_VALID                                         NTStatus      = 0xC0500003
	STATUS_VOLSNAP_ACTIVATION_TIMEOUT                                         NTStatus      = 0xC0500004
	STATUS_IO_PREEMPTED                                                       NTStatus      = 0xC0510001
	STATUS_SVHDX_ERROR_STORED                                                 NTStatus      = 0xC05C0000
	STATUS_SVHDX_ERROR_NOT_AVAILABLE                                          NTStatus      = 0xC05CFF00
	STATUS_SVHDX_UNIT_ATTENTION_AVAILABLE                                     NTStatus      = 0xC05CFF01
	STATUS_SVHDX_UNIT_ATTENTION_CAPACITY_DATA_CHANGED                         NTStatus      = 0xC05CFF02
	STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_PREEMPTED                        NTStatus      = 0xC05CFF03
	STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_RELEASED                         NTStatus      = 0xC05CFF04
	STATUS_SVHDX_UNIT_ATTENTION_REGISTRATIONS_PREEMPTED                       NTStatus      = 0xC05CFF05
	STATUS_SVHDX_UNIT_ATTENTION_OPERATING_DEFINITION_CHANGED                  NTStatus      = 0xC05CFF06
	STATUS_SVHDX_RESERVATION_CONFLICT                                         NTStatus      = 0xC05CFF07
	STATUS_SVHDX_WRONG_FILE_TYPE                                              NTStatus      = 0xC05CFF08
	STATUS_SVHDX_VERSION_MISMATCH                                             NTStatus      = 0xC05CFF09
	STATUS_VHD_SHARED                                                         NTStatus      = 0xC05CFF0A
	STATUS_SVHDX_NO_INITIATOR                                                 NTStatus      = 0xC05CFF0B
	STATUS_VHDSET_BACKING_STORAGE_NOT_FOUND                                   NTStatus      = 0xC05CFF0C
	STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP                              NTStatus      = 0xC05D0000
	STATUS_SMB_BAD_CLUSTER_DIALECT                                            NTStatus      = 0xC05D0001
	STATUS_SMB_GUEST_LOGON_BLOCKED                                            NTStatus      = 0xC05D0002
	STATUS_SECCORE_INVALID_COMMAND                                            NTStatus      = 0xC0E80000
	STATUS_VSM_NOT_INITIALIZED                                                NTStatus      = 0xC0450000
	STATUS_VSM_DMA_PROTECTION_NOT_IN_USE                                      NTStatus      = 0xC0450001
	STATUS_APPEXEC_CONDITION_NOT_SATISFIED                                    NTStatus      = 0xC0EC0000
	STATUS_APPEXEC_HANDLE_INVALIDATED                                         NTStatus      = 0xC0EC0001
	STATUS_APPEXEC_INVALID_HOST_GENERATION                                    NTStatus      = 0xC0EC0002
	STATUS_APPEXEC_UNEXPECTED_PROCESS_REGISTRATION                            NTStatus      = 0xC0EC0003
	STATUS_APPEXEC_INVALID_HOST_STATE                                         NTStatus      = 0xC0EC0004
	STATUS_APPEXEC_NO_DONOR                                                   NTStatus      = 0xC0EC0005
	STATUS_APPEXEC_HOST_ID_MISMATCH                                           NTStatus      = 0xC0EC0006
	STATUS_APPEXEC_UNKNOWN_USER                                               NTStatus      = 0xC0EC0007
)
```