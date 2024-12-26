Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Scan and Identification:** The first thing that jumps out is the repetitive structure: `STATUS_... NTStatus = 0x...`. This strongly suggests a set of constants being defined. The `NTStatus` type hints at Windows-specific error codes.

2. **Contextual Understanding (File Path):** The file path `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` is crucial. `vendor` indicates this code is a dependency. `golang.org/x/sys/windows` tells us it's part of the Go standard library's extended system package for Windows. `zerrors_windows.go` suggests auto-generated or carefully curated Windows error codes. The "z" prefix often indicates it's a foundational or core component.

3. **Purpose Deduction:** Combining the constants and the file path, the primary function is clearly to define a large collection of Windows NT status codes as Go constants. These constants are likely used to represent specific error conditions returned by Windows system calls.

4. **Go Language Feature:** The code uses the `const` keyword to declare named constants. It also defines a custom type `NTStatus` (likely an alias for an integer type like `uint32`) to provide type safety and clarity.

5. **Code Example (Illustrative):**  To demonstrate the use, we need to imagine a scenario where a Windows API call might return one of these error codes. File operations are a common source of errors. The `os.Open` function in Go can return errors. We can simulate a scenario where opening a non-existent file might, at a low level, result in a `STATUS_OBJECT_NAME_NOT_FOUND` error. The key here is *not* that `os.Open` directly returns `NTStatus`, but rather that the underlying Windows system call *would*. The Go `syscall` package provides access to these lower-level calls.

   * **Initial Thought:** "Let's directly use `syscall`."
   * **Refinement:** "While `syscall` is the underlying mechanism, it's more user-friendly to show how these might be *indirectly* encountered through higher-level Go APIs like `os`. This makes the example more practical."
   * **Code Construction:**  The example should attempt an operation that could fail, check the error, and then potentially compare the error against one of the defined `NTStatus` constants. The `errors.Is` function is the idiomatic Go way to check for specific error types. We'll need a way to access the underlying `NTStatus` if the error is a `syscall.Errno`.

6. **Code Reasoning (Input/Output):**

   * **Input:**  The example code attempts to open a file that doesn't exist ("non_existent_file.txt").
   * **Expected Output:** `os.Open` will return an error. If we can access the underlying `syscall.Errno`, its value should correspond to `STATUS_OBJECT_NAME_NOT_FOUND`. The example will print a message indicating whether the error matches the expected `NTStatus`.

7. **Command-Line Arguments:** This code snippet doesn't directly process command-line arguments. It's a definition of constants. Therefore, this section is not applicable.

8. **Common Mistakes:**  The most common mistake is directly comparing a generic `error` returned by a Go function with an `NTStatus` constant. Go's error handling often wraps lower-level errors. The correct approach is to unwrap the error to access the underlying system error code, often a `syscall.Errno`. The example demonstrates this using `errors.As`.

9. **Part Number and Overall Function:** This is part 12 of 15, implying a larger collection of Windows system-related definitions. The overall function of this specific part is to define a significant range of Windows NT status codes related to various system operations, including device interactions, networking, security, file system operations, and more. These constants provide a way for Go programs interacting with the Windows API to understand the specific nature of errors returned by the operating system.

10. **Self-Correction/Refinement:** Throughout this process, it's essential to double-check assumptions and ensure the example code is correct and illustrative. For instance, initially, I considered directly comparing error values. However, remembering Go's error wrapping led to the more accurate use of `errors.As`. Similarly, starting with a direct `syscall` example and then pivoting to the more common `os` package improves the example's practical relevance.
这部分代码定义了一系列的 Go 常量，这些常量都是 `NTStatus` 类型的，并且对应着 Windows 操作系统中定义的各种错误状态码。这些状态码以 `STATUS_` 开头，后跟描述性的名称，例如 `STATUS_DEVICE_DOES_NOT_EXIST`。

**功能归纳:**

这部分代码的主要功能是：

* **定义 Windows NT 状态码常量:** 它将大量的 Windows NT 状态码（通常在 C/C++ 头文件中定义）转换成 Go 语言的具名常量。
* **提供 Windows 错误代码的类型安全表示:** 通过将这些状态码定义为自定义类型 `NTStatus`，可以提高代码的可读性和类型安全性，避免将这些数值与其他整数类型混淆。
* **作为与 Windows 系统交互的基础:** 这些常量可以在 Go 程序中用于判断 Windows API 调用返回的具体错误原因。

**它是什么 Go 语言功能的实现:**

这部分代码主要使用了 Go 语言的以下功能：

* **常量定义 (`const`):**  用于声明不可修改的常量值。
* **自定义类型 (`type`):**  虽然代码片段中没有显式地定义 `NTStatus` 类型，但根据命名和使用方式可以推断出 `NTStatus` 是一个自定义的整数类型（很可能是 `uint32`），用于表示 Windows 的状态码。

**Go 代码举例说明:**

假设在与 Windows 系统交互的过程中，我们调用了一个可能会返回 `STATUS_DEVICE_DOES_NOT_EXIST` 错误的函数。我们可以使用这里定义的常量来判断是否发生了该错误。

```go
package main

import (
	"fmt"
	"syscall" // 假设需要使用 syscall 包来调用 Windows API
	"unsafe"
)

// 假设 zerrors_windows.go 文件中的常量已经定义

func main() {
	// 假设这是一个可能会返回 NTStatus 的 Windows API 调用
	// 实际使用中，你需要替换成具体的 Windows API 调用和参数
	// 这里仅为演示目的
	var filename *uint16 = syscall.StringToUTF16Ptr("\\\\.\\NonExistentDevice")
	handle, err := syscall.CreateFile(
		filename,
		syscall.GENERIC_READ,
		0,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0)

	if err != nil {
		errno, ok := err.(syscall.Errno)
		if ok {
			status := NTStatus(errno) // 将 syscall.Errno 转换为 NTStatus 类型
			if status == STATUS_DEVICE_DOES_NOT_EXIST {
				fmt.Println("错误：指定的设备不存在。")
			} else {
				fmt.Printf("其他错误：%#x\n", status)
			}
		} else {
			fmt.Println("发生未知错误:", err)
		}
		return
	}
	defer syscall.CloseHandle(handle)
	fmt.Println("设备打开成功！")
}

// 假设 NTStatus 类型的定义如下（实际可能在其他文件中）
type NTStatus uint32

// 这里粘贴从提供的代码片段中复制的常量定义
const (
	STATUS_DEVICE_DOES_NOT_EXIST NTStatus = 0xC00000C0
	STATUS_TOO_MANY_COMMANDS       NTStatus = 0xC00000C1
	// ... 其他常量
)
```

**假设的输入与输出:**

在上面的例子中，假设我们尝试打开一个不存在的设备 `\\\\.\\NonExistentDevice`。

* **输入:** 调用 `syscall.CreateFile` 尝试打开不存在的设备。
* **输出:**  程序会打印 "错误：指定的设备不存在。"。这是因为 `syscall.CreateFile` 会失败并返回一个 `syscall.Errno` 类型的错误，当转换为 `NTStatus` 后，其值会等于 `STATUS_DEVICE_DOES_NOT_EXIST` 常量的值。

**命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。它只是定义了一些常量。命令行参数的处理通常发生在 `main` 函数中，使用 `os.Args` 或 `flag` 包。

**使用者易犯错的点:**

* **直接比较 `error` 类型和 `NTStatus`:**  Go 函数通常返回 `error` 接口类型。如果需要判断是否是特定的 Windows 错误，需要先将 `error` 断言为 `syscall.Errno` 类型，然后再转换为 `NTStatus` 进行比较。直接比较 `error` 和 `NTStatus` 是不正确的。
* **不理解 `vendor` 目录的含义:** `vendor` 目录下的代码是项目依赖的一部分。不应该直接修改 `vendor` 目录下的代码。

**总结一下它的功能 (基于第12部分):**

作为第12部分，这部分代码延续了整个 `zerrors_windows.go` 文件的主要功能：**定义大量的 Windows NT 状态码常量，以便 Go 程序能够以类型安全的方式处理 Windows API 调用可能返回的各种错误状态。** 这一部分具体定义了状态码从 `0xC00000C0` 到 `0xC0000481` 的常量，涵盖了设备、网络、打印、命名、会话、共享、重定向、内存管理、安全、域控制、文件系统、日志、别名、登录、注册表、硬件、驱动程序、事件日志、信任关系、配额、消息队列、事务、调试、浏览器服务、VDM、时间同步、DLL加载、异常处理、连接、地址、通信协议、窗口消息、剪贴板、电源管理、即插即用、DFS、WMI、目录服务等多个方面的错误。

总而言之，这部分代码是 Go 语言与 Windows 系统底层交互的重要桥梁，它提供了标准化的方式来理解和处理 Windows 操作系统返回的错误信息。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第12部分，共15部分，请归纳一下它的功能

"""
	STATUS_DEVICE_DOES_NOT_EXIST                                              NTStatus      = 0xC00000C0
	STATUS_TOO_MANY_COMMANDS                                                  NTStatus      = 0xC00000C1
	STATUS_ADAPTER_HARDWARE_ERROR                                             NTStatus      = 0xC00000C2
	STATUS_INVALID_NETWORK_RESPONSE                                           NTStatus      = 0xC00000C3
	STATUS_UNEXPECTED_NETWORK_ERROR                                           NTStatus      = 0xC00000C4
	STATUS_BAD_REMOTE_ADAPTER                                                 NTStatus      = 0xC00000C5
	STATUS_PRINT_QUEUE_FULL                                                   NTStatus      = 0xC00000C6
	STATUS_NO_SPOOL_SPACE                                                     NTStatus      = 0xC00000C7
	STATUS_PRINT_CANCELLED                                                    NTStatus      = 0xC00000C8
	STATUS_NETWORK_NAME_DELETED                                               NTStatus      = 0xC00000C9
	STATUS_NETWORK_ACCESS_DENIED                                              NTStatus      = 0xC00000CA
	STATUS_BAD_DEVICE_TYPE                                                    NTStatus      = 0xC00000CB
	STATUS_BAD_NETWORK_NAME                                                   NTStatus      = 0xC00000CC
	STATUS_TOO_MANY_NAMES                                                     NTStatus      = 0xC00000CD
	STATUS_TOO_MANY_SESSIONS                                                  NTStatus      = 0xC00000CE
	STATUS_SHARING_PAUSED                                                     NTStatus      = 0xC00000CF
	STATUS_REQUEST_NOT_ACCEPTED                                               NTStatus      = 0xC00000D0
	STATUS_REDIRECTOR_PAUSED                                                  NTStatus      = 0xC00000D1
	STATUS_NET_WRITE_FAULT                                                    NTStatus      = 0xC00000D2
	STATUS_PROFILING_AT_LIMIT                                                 NTStatus      = 0xC00000D3
	STATUS_NOT_SAME_DEVICE                                                    NTStatus      = 0xC00000D4
	STATUS_FILE_RENAMED                                                       NTStatus      = 0xC00000D5
	STATUS_VIRTUAL_CIRCUIT_CLOSED                                             NTStatus      = 0xC00000D6
	STATUS_NO_SECURITY_ON_OBJECT                                              NTStatus      = 0xC00000D7
	STATUS_CANT_WAIT                                                          NTStatus      = 0xC00000D8
	STATUS_PIPE_EMPTY                                                         NTStatus      = 0xC00000D9
	STATUS_CANT_ACCESS_DOMAIN_INFO                                            NTStatus      = 0xC00000DA
	STATUS_CANT_TERMINATE_SELF                                                NTStatus      = 0xC00000DB
	STATUS_INVALID_SERVER_STATE                                               NTStatus      = 0xC00000DC
	STATUS_INVALID_DOMAIN_STATE                                               NTStatus      = 0xC00000DD
	STATUS_INVALID_DOMAIN_ROLE                                                NTStatus      = 0xC00000DE
	STATUS_NO_SUCH_DOMAIN                                                     NTStatus      = 0xC00000DF
	STATUS_DOMAIN_EXISTS                                                      NTStatus      = 0xC00000E0
	STATUS_DOMAIN_LIMIT_EXCEEDED                                              NTStatus      = 0xC00000E1
	STATUS_OPLOCK_NOT_GRANTED                                                 NTStatus      = 0xC00000E2
	STATUS_INVALID_OPLOCK_PROTOCOL                                            NTStatus      = 0xC00000E3
	STATUS_INTERNAL_DB_CORRUPTION                                             NTStatus      = 0xC00000E4
	STATUS_INTERNAL_ERROR                                                     NTStatus      = 0xC00000E5
	STATUS_GENERIC_NOT_MAPPED                                                 NTStatus      = 0xC00000E6
	STATUS_BAD_DESCRIPTOR_FORMAT                                              NTStatus      = 0xC00000E7
	STATUS_INVALID_USER_BUFFER                                                NTStatus      = 0xC00000E8
	STATUS_UNEXPECTED_IO_ERROR                                                NTStatus      = 0xC00000E9
	STATUS_UNEXPECTED_MM_CREATE_ERR                                           NTStatus      = 0xC00000EA
	STATUS_UNEXPECTED_MM_MAP_ERROR                                            NTStatus      = 0xC00000EB
	STATUS_UNEXPECTED_MM_EXTEND_ERR                                           NTStatus      = 0xC00000EC
	STATUS_NOT_LOGON_PROCESS                                                  NTStatus      = 0xC00000ED
	STATUS_LOGON_SESSION_EXISTS                                               NTStatus      = 0xC00000EE
	STATUS_INVALID_PARAMETER_1                                                NTStatus      = 0xC00000EF
	STATUS_INVALID_PARAMETER_2                                                NTStatus      = 0xC00000F0
	STATUS_INVALID_PARAMETER_3                                                NTStatus      = 0xC00000F1
	STATUS_INVALID_PARAMETER_4                                                NTStatus      = 0xC00000F2
	STATUS_INVALID_PARAMETER_5                                                NTStatus      = 0xC00000F3
	STATUS_INVALID_PARAMETER_6                                                NTStatus      = 0xC00000F4
	STATUS_INVALID_PARAMETER_7                                                NTStatus      = 0xC00000F5
	STATUS_INVALID_PARAMETER_8                                                NTStatus      = 0xC00000F6
	STATUS_INVALID_PARAMETER_9                                                NTStatus      = 0xC00000F7
	STATUS_INVALID_PARAMETER_10                                               NTStatus      = 0xC00000F8
	STATUS_INVALID_PARAMETER_11                                               NTStatus      = 0xC00000F9
	STATUS_INVALID_PARAMETER_12                                               NTStatus      = 0xC00000FA
	STATUS_REDIRECTOR_NOT_STARTED                                             NTStatus      = 0xC00000FB
	STATUS_REDIRECTOR_STARTED                                                 NTStatus      = 0xC00000FC
	STATUS_STACK_OVERFLOW                                                     NTStatus      = 0xC00000FD
	STATUS_NO_SUCH_PACKAGE                                                    NTStatus      = 0xC00000FE
	STATUS_BAD_FUNCTION_TABLE                                                 NTStatus      = 0xC00000FF
	STATUS_VARIABLE_NOT_FOUND                                                 NTStatus      = 0xC0000100
	STATUS_DIRECTORY_NOT_EMPTY                                                NTStatus      = 0xC0000101
	STATUS_FILE_CORRUPT_ERROR                                                 NTStatus      = 0xC0000102
	STATUS_NOT_A_DIRECTORY                                                    NTStatus      = 0xC0000103
	STATUS_BAD_LOGON_SESSION_STATE                                            NTStatus      = 0xC0000104
	STATUS_LOGON_SESSION_COLLISION                                            NTStatus      = 0xC0000105
	STATUS_NAME_TOO_LONG                                                      NTStatus      = 0xC0000106
	STATUS_FILES_OPEN                                                         NTStatus      = 0xC0000107
	STATUS_CONNECTION_IN_USE                                                  NTStatus      = 0xC0000108
	STATUS_MESSAGE_NOT_FOUND                                                  NTStatus      = 0xC0000109
	STATUS_PROCESS_IS_TERMINATING                                             NTStatus      = 0xC000010A
	STATUS_INVALID_LOGON_TYPE                                                 NTStatus      = 0xC000010B
	STATUS_NO_GUID_TRANSLATION                                                NTStatus      = 0xC000010C
	STATUS_CANNOT_IMPERSONATE                                                 NTStatus      = 0xC000010D
	STATUS_IMAGE_ALREADY_LOADED                                               NTStatus      = 0xC000010E
	STATUS_ABIOS_NOT_PRESENT                                                  NTStatus      = 0xC000010F
	STATUS_ABIOS_LID_NOT_EXIST                                                NTStatus      = 0xC0000110
	STATUS_ABIOS_LID_ALREADY_OWNED                                            NTStatus      = 0xC0000111
	STATUS_ABIOS_NOT_LID_OWNER                                                NTStatus      = 0xC0000112
	STATUS_ABIOS_INVALID_COMMAND                                              NTStatus      = 0xC0000113
	STATUS_ABIOS_INVALID_LID                                                  NTStatus      = 0xC0000114
	STATUS_ABIOS_SELECTOR_NOT_AVAILABLE                                       NTStatus      = 0xC0000115
	STATUS_ABIOS_INVALID_SELECTOR                                             NTStatus      = 0xC0000116
	STATUS_NO_LDT                                                             NTStatus      = 0xC0000117
	STATUS_INVALID_LDT_SIZE                                                   NTStatus      = 0xC0000118
	STATUS_INVALID_LDT_OFFSET                                                 NTStatus      = 0xC0000119
	STATUS_INVALID_LDT_DESCRIPTOR                                             NTStatus      = 0xC000011A
	STATUS_INVALID_IMAGE_NE_FORMAT                                            NTStatus      = 0xC000011B
	STATUS_RXACT_INVALID_STATE                                                NTStatus      = 0xC000011C
	STATUS_RXACT_COMMIT_FAILURE                                               NTStatus      = 0xC000011D
	STATUS_MAPPED_FILE_SIZE_ZERO                                              NTStatus      = 0xC000011E
	STATUS_TOO_MANY_OPENED_FILES                                              NTStatus      = 0xC000011F
	STATUS_CANCELLED                                                          NTStatus      = 0xC0000120
	STATUS_CANNOT_DELETE                                                      NTStatus      = 0xC0000121
	STATUS_INVALID_COMPUTER_NAME                                              NTStatus      = 0xC0000122
	STATUS_FILE_DELETED                                                       NTStatus      = 0xC0000123
	STATUS_SPECIAL_ACCOUNT                                                    NTStatus      = 0xC0000124
	STATUS_SPECIAL_GROUP                                                      NTStatus      = 0xC0000125
	STATUS_SPECIAL_USER                                                       NTStatus      = 0xC0000126
	STATUS_MEMBERS_PRIMARY_GROUP                                              NTStatus      = 0xC0000127
	STATUS_FILE_CLOSED                                                        NTStatus      = 0xC0000128
	STATUS_TOO_MANY_THREADS                                                   NTStatus      = 0xC0000129
	STATUS_THREAD_NOT_IN_PROCESS                                              NTStatus      = 0xC000012A
	STATUS_TOKEN_ALREADY_IN_USE                                               NTStatus      = 0xC000012B
	STATUS_PAGEFILE_QUOTA_EXCEEDED                                            NTStatus      = 0xC000012C
	STATUS_COMMITMENT_LIMIT                                                   NTStatus      = 0xC000012D
	STATUS_INVALID_IMAGE_LE_FORMAT                                            NTStatus      = 0xC000012E
	STATUS_INVALID_IMAGE_NOT_MZ                                               NTStatus      = 0xC000012F
	STATUS_INVALID_IMAGE_PROTECT                                              NTStatus      = 0xC0000130
	STATUS_INVALID_IMAGE_WIN_16                                               NTStatus      = 0xC0000131
	STATUS_LOGON_SERVER_CONFLICT                                              NTStatus      = 0xC0000132
	STATUS_TIME_DIFFERENCE_AT_DC                                              NTStatus      = 0xC0000133
	STATUS_SYNCHRONIZATION_REQUIRED                                           NTStatus      = 0xC0000134
	STATUS_DLL_NOT_FOUND                                                      NTStatus      = 0xC0000135
	STATUS_OPEN_FAILED                                                        NTStatus      = 0xC0000136
	STATUS_IO_PRIVILEGE_FAILED                                                NTStatus      = 0xC0000137
	STATUS_ORDINAL_NOT_FOUND                                                  NTStatus      = 0xC0000138
	STATUS_ENTRYPOINT_NOT_FOUND                                               NTStatus      = 0xC0000139
	STATUS_CONTROL_C_EXIT                                                     NTStatus      = 0xC000013A
	STATUS_LOCAL_DISCONNECT                                                   NTStatus      = 0xC000013B
	STATUS_REMOTE_DISCONNECT                                                  NTStatus      = 0xC000013C
	STATUS_REMOTE_RESOURCES                                                   NTStatus      = 0xC000013D
	STATUS_LINK_FAILED                                                        NTStatus      = 0xC000013E
	STATUS_LINK_TIMEOUT                                                       NTStatus      = 0xC000013F
	STATUS_INVALID_CONNECTION                                                 NTStatus      = 0xC0000140
	STATUS_INVALID_ADDRESS                                                    NTStatus      = 0xC0000141
	STATUS_DLL_INIT_FAILED                                                    NTStatus      = 0xC0000142
	STATUS_MISSING_SYSTEMFILE                                                 NTStatus      = 0xC0000143
	STATUS_UNHANDLED_EXCEPTION                                                NTStatus      = 0xC0000144
	STATUS_APP_INIT_FAILURE                                                   NTStatus      = 0xC0000145
	STATUS_PAGEFILE_CREATE_FAILED                                             NTStatus      = 0xC0000146
	STATUS_NO_PAGEFILE                                                        NTStatus      = 0xC0000147
	STATUS_INVALID_LEVEL                                                      NTStatus      = 0xC0000148
	STATUS_WRONG_PASSWORD_CORE                                                NTStatus      = 0xC0000149
	STATUS_ILLEGAL_FLOAT_CONTEXT                                              NTStatus      = 0xC000014A
	STATUS_PIPE_BROKEN                                                        NTStatus      = 0xC000014B
	STATUS_REGISTRY_CORRUPT                                                   NTStatus      = 0xC000014C
	STATUS_REGISTRY_IO_FAILED                                                 NTStatus      = 0xC000014D
	STATUS_NO_EVENT_PAIR                                                      NTStatus      = 0xC000014E
	STATUS_UNRECOGNIZED_VOLUME                                                NTStatus      = 0xC000014F
	STATUS_SERIAL_NO_DEVICE_INITED                                            NTStatus      = 0xC0000150
	STATUS_NO_SUCH_ALIAS                                                      NTStatus      = 0xC0000151
	STATUS_MEMBER_NOT_IN_ALIAS                                                NTStatus      = 0xC0000152
	STATUS_MEMBER_IN_ALIAS                                                    NTStatus      = 0xC0000153
	STATUS_ALIAS_EXISTS                                                       NTStatus      = 0xC0000154
	STATUS_LOGON_NOT_GRANTED                                                  NTStatus      = 0xC0000155
	STATUS_TOO_MANY_SECRETS                                                   NTStatus      = 0xC0000156
	STATUS_SECRET_TOO_LONG                                                    NTStatus      = 0xC0000157
	STATUS_INTERNAL_DB_ERROR                                                  NTStatus      = 0xC0000158
	STATUS_FULLSCREEN_MODE                                                    NTStatus      = 0xC0000159
	STATUS_TOO_MANY_CONTEXT_IDS                                               NTStatus      = 0xC000015A
	STATUS_LOGON_TYPE_NOT_GRANTED                                             NTStatus      = 0xC000015B
	STATUS_NOT_REGISTRY_FILE                                                  NTStatus      = 0xC000015C
	STATUS_NT_CROSS_ENCRYPTION_REQUIRED                                       NTStatus      = 0xC000015D
	STATUS_DOMAIN_CTRLR_CONFIG_ERROR                                          NTStatus      = 0xC000015E
	STATUS_FT_MISSING_MEMBER                                                  NTStatus      = 0xC000015F
	STATUS_ILL_FORMED_SERVICE_ENTRY                                           NTStatus      = 0xC0000160
	STATUS_ILLEGAL_CHARACTER                                                  NTStatus      = 0xC0000161
	STATUS_UNMAPPABLE_CHARACTER                                               NTStatus      = 0xC0000162
	STATUS_UNDEFINED_CHARACTER                                                NTStatus      = 0xC0000163
	STATUS_FLOPPY_VOLUME                                                      NTStatus      = 0xC0000164
	STATUS_FLOPPY_ID_MARK_NOT_FOUND                                           NTStatus      = 0xC0000165
	STATUS_FLOPPY_WRONG_CYLINDER                                              NTStatus      = 0xC0000166
	STATUS_FLOPPY_UNKNOWN_ERROR                                               NTStatus      = 0xC0000167
	STATUS_FLOPPY_BAD_REGISTERS                                               NTStatus      = 0xC0000168
	STATUS_DISK_RECALIBRATE_FAILED                                            NTStatus      = 0xC0000169
	STATUS_DISK_OPERATION_FAILED                                              NTStatus      = 0xC000016A
	STATUS_DISK_RESET_FAILED                                                  NTStatus      = 0xC000016B
	STATUS_SHARED_IRQ_BUSY                                                    NTStatus      = 0xC000016C
	STATUS_FT_ORPHANING                                                       NTStatus      = 0xC000016D
	STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT                                   NTStatus      = 0xC000016E
	STATUS_PARTITION_FAILURE                                                  NTStatus      = 0xC0000172
	STATUS_INVALID_BLOCK_LENGTH                                               NTStatus      = 0xC0000173
	STATUS_DEVICE_NOT_PARTITIONED                                             NTStatus      = 0xC0000174
	STATUS_UNABLE_TO_LOCK_MEDIA                                               NTStatus      = 0xC0000175
	STATUS_UNABLE_TO_UNLOAD_MEDIA                                             NTStatus      = 0xC0000176
	STATUS_EOM_OVERFLOW                                                       NTStatus      = 0xC0000177
	STATUS_NO_MEDIA                                                           NTStatus      = 0xC0000178
	STATUS_NO_SUCH_MEMBER                                                     NTStatus      = 0xC000017A
	STATUS_INVALID_MEMBER                                                     NTStatus      = 0xC000017B
	STATUS_KEY_DELETED                                                        NTStatus      = 0xC000017C
	STATUS_NO_LOG_SPACE                                                       NTStatus      = 0xC000017D
	STATUS_TOO_MANY_SIDS                                                      NTStatus      = 0xC000017E
	STATUS_LM_CROSS_ENCRYPTION_REQUIRED                                       NTStatus      = 0xC000017F
	STATUS_KEY_HAS_CHILDREN                                                   NTStatus      = 0xC0000180
	STATUS_CHILD_MUST_BE_VOLATILE                                             NTStatus      = 0xC0000181
	STATUS_DEVICE_CONFIGURATION_ERROR                                         NTStatus      = 0xC0000182
	STATUS_DRIVER_INTERNAL_ERROR                                              NTStatus      = 0xC0000183
	STATUS_INVALID_DEVICE_STATE                                               NTStatus      = 0xC0000184
	STATUS_IO_DEVICE_ERROR                                                    NTStatus      = 0xC0000185
	STATUS_DEVICE_PROTOCOL_ERROR                                              NTStatus      = 0xC0000186
	STATUS_BACKUP_CONTROLLER                                                  NTStatus      = 0xC0000187
	STATUS_LOG_FILE_FULL                                                      NTStatus      = 0xC0000188
	STATUS_TOO_LATE                                                           NTStatus      = 0xC0000189
	STATUS_NO_TRUST_LSA_SECRET                                                NTStatus      = 0xC000018A
	STATUS_NO_TRUST_SAM_ACCOUNT                                               NTStatus      = 0xC000018B
	STATUS_TRUSTED_DOMAIN_FAILURE                                             NTStatus      = 0xC000018C
	STATUS_TRUSTED_RELATIONSHIP_FAILURE                                       NTStatus      = 0xC000018D
	STATUS_EVENTLOG_FILE_CORRUPT                                              NTStatus      = 0xC000018E
	STATUS_EVENTLOG_CANT_START                                                NTStatus      = 0xC000018F
	STATUS_TRUST_FAILURE                                                      NTStatus      = 0xC0000190
	STATUS_MUTANT_LIMIT_EXCEEDED                                              NTStatus      = 0xC0000191
	STATUS_NETLOGON_NOT_STARTED                                               NTStatus      = 0xC0000192
	STATUS_ACCOUNT_EXPIRED                                                    NTStatus      = 0xC0000193
	STATUS_POSSIBLE_DEADLOCK                                                  NTStatus      = 0xC0000194
	STATUS_NETWORK_CREDENTIAL_CONFLICT                                        NTStatus      = 0xC0000195
	STATUS_REMOTE_SESSION_LIMIT                                               NTStatus      = 0xC0000196
	STATUS_EVENTLOG_FILE_CHANGED                                              NTStatus      = 0xC0000197
	STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT                                  NTStatus      = 0xC0000198
	STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT                                  NTStatus      = 0xC0000199
	STATUS_NOLOGON_SERVER_TRUST_ACCOUNT                                       NTStatus      = 0xC000019A
	STATUS_DOMAIN_TRUST_INCONSISTENT                                          NTStatus      = 0xC000019B
	STATUS_FS_DRIVER_REQUIRED                                                 NTStatus      = 0xC000019C
	STATUS_IMAGE_ALREADY_LOADED_AS_DLL                                        NTStatus      = 0xC000019D
	STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING               NTStatus      = 0xC000019E
	STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME                                  NTStatus      = 0xC000019F
	STATUS_SECURITY_STREAM_IS_INCONSISTENT                                    NTStatus      = 0xC00001A0
	STATUS_INVALID_LOCK_RANGE                                                 NTStatus      = 0xC00001A1
	STATUS_INVALID_ACE_CONDITION                                              NTStatus      = 0xC00001A2
	STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT                                        NTStatus      = 0xC00001A3
	STATUS_NOTIFICATION_GUID_ALREADY_DEFINED                                  NTStatus      = 0xC00001A4
	STATUS_INVALID_EXCEPTION_HANDLER                                          NTStatus      = 0xC00001A5
	STATUS_DUPLICATE_PRIVILEGES                                               NTStatus      = 0xC00001A6
	STATUS_NOT_ALLOWED_ON_SYSTEM_FILE                                         NTStatus      = 0xC00001A7
	STATUS_REPAIR_NEEDED                                                      NTStatus      = 0xC00001A8
	STATUS_QUOTA_NOT_ENABLED                                                  NTStatus      = 0xC00001A9
	STATUS_NO_APPLICATION_PACKAGE                                             NTStatus      = 0xC00001AA
	STATUS_FILE_METADATA_OPTIMIZATION_IN_PROGRESS                             NTStatus      = 0xC00001AB
	STATUS_NOT_SAME_OBJECT                                                    NTStatus      = 0xC00001AC
	STATUS_FATAL_MEMORY_EXHAUSTION                                            NTStatus      = 0xC00001AD
	STATUS_ERROR_PROCESS_NOT_IN_JOB                                           NTStatus      = 0xC00001AE
	STATUS_CPU_SET_INVALID                                                    NTStatus      = 0xC00001AF
	STATUS_IO_DEVICE_INVALID_DATA                                             NTStatus      = 0xC00001B0
	STATUS_IO_UNALIGNED_WRITE                                                 NTStatus      = 0xC00001B1
	STATUS_NETWORK_OPEN_RESTRICTION                                           NTStatus      = 0xC0000201
	STATUS_NO_USER_SESSION_KEY                                                NTStatus      = 0xC0000202
	STATUS_USER_SESSION_DELETED                                               NTStatus      = 0xC0000203
	STATUS_RESOURCE_LANG_NOT_FOUND                                            NTStatus      = 0xC0000204
	STATUS_INSUFF_SERVER_RESOURCES                                            NTStatus      = 0xC0000205
	STATUS_INVALID_BUFFER_SIZE                                                NTStatus      = 0xC0000206
	STATUS_INVALID_ADDRESS_COMPONENT                                          NTStatus      = 0xC0000207
	STATUS_INVALID_ADDRESS_WILDCARD                                           NTStatus      = 0xC0000208
	STATUS_TOO_MANY_ADDRESSES                                                 NTStatus      = 0xC0000209
	STATUS_ADDRESS_ALREADY_EXISTS                                             NTStatus      = 0xC000020A
	STATUS_ADDRESS_CLOSED                                                     NTStatus      = 0xC000020B
	STATUS_CONNECTION_DISCONNECTED                                            NTStatus      = 0xC000020C
	STATUS_CONNECTION_RESET                                                   NTStatus      = 0xC000020D
	STATUS_TOO_MANY_NODES                                                     NTStatus      = 0xC000020E
	STATUS_TRANSACTION_ABORTED                                                NTStatus      = 0xC000020F
	STATUS_TRANSACTION_TIMED_OUT                                              NTStatus      = 0xC0000210
	STATUS_TRANSACTION_NO_RELEASE                                             NTStatus      = 0xC0000211
	STATUS_TRANSACTION_NO_MATCH                                               NTStatus      = 0xC0000212
	STATUS_TRANSACTION_RESPONDED                                              NTStatus      = 0xC0000213
	STATUS_TRANSACTION_INVALID_ID                                             NTStatus      = 0xC0000214
	STATUS_TRANSACTION_INVALID_TYPE                                           NTStatus      = 0xC0000215
	STATUS_NOT_SERVER_SESSION                                                 NTStatus      = 0xC0000216
	STATUS_NOT_CLIENT_SESSION                                                 NTStatus      = 0xC0000217
	STATUS_CANNOT_LOAD_REGISTRY_FILE                                          NTStatus      = 0xC0000218
	STATUS_DEBUG_ATTACH_FAILED                                                NTStatus      = 0xC0000219
	STATUS_SYSTEM_PROCESS_TERMINATED                                          NTStatus      = 0xC000021A
	STATUS_DATA_NOT_ACCEPTED                                                  NTStatus      = 0xC000021B
	STATUS_NO_BROWSER_SERVERS_FOUND                                           NTStatus      = 0xC000021C
	STATUS_VDM_HARD_ERROR                                                     NTStatus      = 0xC000021D
	STATUS_DRIVER_CANCEL_TIMEOUT                                              NTStatus      = 0xC000021E
	STATUS_REPLY_MESSAGE_MISMATCH                                             NTStatus      = 0xC000021F
	STATUS_MAPPED_ALIGNMENT                                                   NTStatus      = 0xC0000220
	STATUS_IMAGE_CHECKSUM_MISMATCH                                            NTStatus      = 0xC0000221
	STATUS_LOST_WRITEBEHIND_DATA                                              NTStatus      = 0xC0000222
	STATUS_CLIENT_SERVER_PARAMETERS_INVALID                                   NTStatus      = 0xC0000223
	STATUS_PASSWORD_MUST_CHANGE                                               NTStatus      = 0xC0000224
	STATUS_NOT_FOUND                                                          NTStatus      = 0xC0000225
	STATUS_NOT_TINY_STREAM                                                    NTStatus      = 0xC0000226
	STATUS_RECOVERY_FAILURE                                                   NTStatus      = 0xC0000227
	STATUS_STACK_OVERFLOW_READ                                                NTStatus      = 0xC0000228
	STATUS_FAIL_CHECK                                                         NTStatus      = 0xC0000229
	STATUS_DUPLICATE_OBJECTID                                                 NTStatus      = 0xC000022A
	STATUS_OBJECTID_EXISTS                                                    NTStatus      = 0xC000022B
	STATUS_CONVERT_TO_LARGE                                                   NTStatus      = 0xC000022C
	STATUS_RETRY                                                              NTStatus      = 0xC000022D
	STATUS_FOUND_OUT_OF_SCOPE                                                 NTStatus      = 0xC000022E
	STATUS_ALLOCATE_BUCKET                                                    NTStatus      = 0xC000022F
	STATUS_PROPSET_NOT_FOUND                                                  NTStatus      = 0xC0000230
	STATUS_MARSHALL_OVERFLOW                                                  NTStatus      = 0xC0000231
	STATUS_INVALID_VARIANT                                                    NTStatus      = 0xC0000232
	STATUS_DOMAIN_CONTROLLER_NOT_FOUND                                        NTStatus      = 0xC0000233
	STATUS_ACCOUNT_LOCKED_OUT                                                 NTStatus      = 0xC0000234
	STATUS_HANDLE_NOT_CLOSABLE                                                NTStatus      = 0xC0000235
	STATUS_CONNECTION_REFUSED                                                 NTStatus      = 0xC0000236
	STATUS_GRACEFUL_DISCONNECT                                                NTStatus      = 0xC0000237
	STATUS_ADDRESS_ALREADY_ASSOCIATED                                         NTStatus      = 0xC0000238
	STATUS_ADDRESS_NOT_ASSOCIATED                                             NTStatus      = 0xC0000239
	STATUS_CONNECTION_INVALID                                                 NTStatus      = 0xC000023A
	STATUS_CONNECTION_ACTIVE                                                  NTStatus      = 0xC000023B
	STATUS_NETWORK_UNREACHABLE                                                NTStatus      = 0xC000023C
	STATUS_HOST_UNREACHABLE                                                   NTStatus      = 0xC000023D
	STATUS_PROTOCOL_UNREACHABLE                                               NTStatus      = 0xC000023E
	STATUS_PORT_UNREACHABLE                                                   NTStatus      = 0xC000023F
	STATUS_REQUEST_ABORTED                                                    NTStatus      = 0xC0000240
	STATUS_CONNECTION_ABORTED                                                 NTStatus      = 0xC0000241
	STATUS_BAD_COMPRESSION_BUFFER                                             NTStatus      = 0xC0000242
	STATUS_USER_MAPPED_FILE                                                   NTStatus      = 0xC0000243
	STATUS_AUDIT_FAILED                                                       NTStatus      = 0xC0000244
	STATUS_TIMER_RESOLUTION_NOT_SET                                           NTStatus      = 0xC0000245
	STATUS_CONNECTION_COUNT_LIMIT                                             NTStatus      = 0xC0000246
	STATUS_LOGIN_TIME_RESTRICTION                                             NTStatus      = 0xC0000247
	STATUS_LOGIN_WKSTA_RESTRICTION                                            NTStatus      = 0xC0000248
	STATUS_IMAGE_MP_UP_MISMATCH                                               NTStatus      = 0xC0000249
	STATUS_INSUFFICIENT_LOGON_INFO                                            NTStatus      = 0xC0000250
	STATUS_BAD_DLL_ENTRYPOINT                                                 NTStatus      = 0xC0000251
	STATUS_BAD_SERVICE_ENTRYPOINT                                             NTStatus      = 0xC0000252
	STATUS_LPC_REPLY_LOST                                                     NTStatus      = 0xC0000253
	STATUS_IP_ADDRESS_CONFLICT1                                               NTStatus      = 0xC0000254
	STATUS_IP_ADDRESS_CONFLICT2                                               NTStatus      = 0xC0000255
	STATUS_REGISTRY_QUOTA_LIMIT                                               NTStatus      = 0xC0000256
	STATUS_PATH_NOT_COVERED                                                   NTStatus      = 0xC0000257
	STATUS_NO_CALLBACK_ACTIVE                                                 NTStatus      = 0xC0000258
	STATUS_LICENSE_QUOTA_EXCEEDED                                             NTStatus      = 0xC0000259
	STATUS_PWD_TOO_SHORT                                                      NTStatus      = 0xC000025A
	STATUS_PWD_TOO_RECENT                                                     NTStatus      = 0xC000025B
	STATUS_PWD_HISTORY_CONFLICT                                               NTStatus      = 0xC000025C
	STATUS_PLUGPLAY_NO_DEVICE                                                 NTStatus      = 0xC000025E
	STATUS_UNSUPPORTED_COMPRESSION                                            NTStatus      = 0xC000025F
	STATUS_INVALID_HW_PROFILE                                                 NTStatus      = 0xC0000260
	STATUS_INVALID_PLUGPLAY_DEVICE_PATH                                       NTStatus      = 0xC0000261
	STATUS_DRIVER_ORDINAL_NOT_FOUND                                           NTStatus      = 0xC0000262
	STATUS_DRIVER_ENTRYPOINT_NOT_FOUND                                        NTStatus      = 0xC0000263
	STATUS_RESOURCE_NOT_OWNED                                                 NTStatus      = 0xC0000264
	STATUS_TOO_MANY_LINKS                                                     NTStatus      = 0xC0000265
	STATUS_QUOTA_LIST_INCONSISTENT                                            NTStatus      = 0xC0000266
	STATUS_FILE_IS_OFFLINE                                                    NTStatus      = 0xC0000267
	STATUS_EVALUATION_EXPIRATION                                              NTStatus      = 0xC0000268
	STATUS_ILLEGAL_DLL_RELOCATION                                             NTStatus      = 0xC0000269
	STATUS_LICENSE_VIOLATION                                                  NTStatus      = 0xC000026A
	STATUS_DLL_INIT_FAILED_LOGOFF                                             NTStatus      = 0xC000026B
	STATUS_DRIVER_UNABLE_TO_LOAD                                              NTStatus      = 0xC000026C
	STATUS_DFS_UNAVAILABLE                                                    NTStatus      = 0xC000026D
	STATUS_VOLUME_DISMOUNTED                                                  NTStatus      = 0xC000026E
	STATUS_WX86_INTERNAL_ERROR                                                NTStatus      = 0xC000026F
	STATUS_WX86_FLOAT_STACK_CHECK                                             NTStatus      = 0xC0000270
	STATUS_VALIDATE_CONTINUE                                                  NTStatus      = 0xC0000271
	STATUS_NO_MATCH                                                           NTStatus      = 0xC0000272
	STATUS_NO_MORE_MATCHES                                                    NTStatus      = 0xC0000273
	STATUS_NOT_A_REPARSE_POINT                                                NTStatus      = 0xC0000275
	STATUS_IO_REPARSE_TAG_INVALID                                             NTStatus      = 0xC0000276
	STATUS_IO_REPARSE_TAG_MISMATCH                                            NTStatus      = 0xC0000277
	STATUS_IO_REPARSE_DATA_INVALID                                            NTStatus      = 0xC0000278
	STATUS_IO_REPARSE_TAG_NOT_HANDLED                                         NTStatus      = 0xC0000279
	STATUS_PWD_TOO_LONG                                                       NTStatus      = 0xC000027A
	STATUS_STOWED_EXCEPTION                                                   NTStatus      = 0xC000027B
	STATUS_CONTEXT_STOWED_EXCEPTION                                           NTStatus      = 0xC000027C
	STATUS_REPARSE_POINT_NOT_RESOLVED                                         NTStatus      = 0xC0000280
	STATUS_DIRECTORY_IS_A_REPARSE_POINT                                       NTStatus      = 0xC0000281
	STATUS_RANGE_LIST_CONFLICT                                                NTStatus      = 0xC0000282
	STATUS_SOURCE_ELEMENT_EMPTY                                               NTStatus      = 0xC0000283
	STATUS_DESTINATION_ELEMENT_FULL                                           NTStatus      = 0xC0000284
	STATUS_ILLEGAL_ELEMENT_ADDRESS                                            NTStatus      = 0xC0000285
	STATUS_MAGAZINE_NOT_PRESENT                                               NTStatus      = 0xC0000286
	STATUS_REINITIALIZATION_NEEDED                                            NTStatus      = 0xC0000287
	STATUS_DEVICE_REQUIRES_CLEANING                                           NTStatus      = 0x80000288
	STATUS_DEVICE_DOOR_OPEN                                                   NTStatus      = 0x80000289
	STATUS_ENCRYPTION_FAILED                                                  NTStatus      = 0xC000028A
	STATUS_DECRYPTION_FAILED                                                  NTStatus      = 0xC000028B
	STATUS_RANGE_NOT_FOUND                                                    NTStatus      = 0xC000028C
	STATUS_NO_RECOVERY_POLICY                                                 NTStatus      = 0xC000028D
	STATUS_NO_EFS                                                             NTStatus      = 0xC000028E
	STATUS_WRONG_EFS                                                          NTStatus      = 0xC000028F
	STATUS_NO_USER_KEYS                                                       NTStatus      = 0xC0000290
	STATUS_FILE_NOT_ENCRYPTED                                                 NTStatus      = 0xC0000291
	STATUS_NOT_EXPORT_FORMAT                                                  NTStatus      = 0xC0000292
	STATUS_FILE_ENCRYPTED                                                     NTStatus      = 0xC0000293
	STATUS_WAKE_SYSTEM                                                        NTStatus      = 0x40000294
	STATUS_WMI_GUID_NOT_FOUND                                                 NTStatus      = 0xC0000295
	STATUS_WMI_INSTANCE_NOT_FOUND                                             NTStatus      = 0xC0000296
	STATUS_WMI_ITEMID_NOT_FOUND                                               NTStatus      = 0xC0000297
	STATUS_WMI_TRY_AGAIN                                                      NTStatus      = 0xC0000298
	STATUS_SHARED_POLICY                                                      NTStatus      = 0xC0000299
	STATUS_POLICY_OBJECT_NOT_FOUND                                            NTStatus      = 0xC000029A
	STATUS_POLICY_ONLY_IN_DS                                                  NTStatus      = 0xC000029B
	STATUS_VOLUME_NOT_UPGRADED                                                NTStatus      = 0xC000029C
	STATUS_REMOTE_STORAGE_NOT_ACTIVE                                          NTStatus      = 0xC000029D
	STATUS_REMOTE_STORAGE_MEDIA_ERROR                                         NTStatus      = 0xC000029E
	STATUS_NO_TRACKING_SERVICE                                                NTStatus      = 0xC000029F
	STATUS_SERVER_SID_MISMATCH                                                NTStatus      = 0xC00002A0
	STATUS_DS_NO_ATTRIBUTE_OR_VALUE                                           NTStatus      = 0xC00002A1
	STATUS_DS_INVALID_ATTRIBUTE_SYNTAX                                        NTStatus      = 0xC00002A2
	STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED                                        NTStatus      = 0xC00002A3
	STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS                                       NTStatus      = 0xC00002A4
	STATUS_DS_BUSY                                                            NTStatus      = 0xC00002A5
	STATUS_DS_UNAVAILABLE                                                     NTStatus      = 0xC00002A6
	STATUS_DS_NO_RIDS_ALLOCATED                                               NTStatus      = 0xC00002A7
	STATUS_DS_NO_MORE_RIDS                                                    NTStatus      = 0xC00002A8
	STATUS_DS_INCORRECT_ROLE_OWNER                                            NTStatus      = 0xC00002A9
	STATUS_DS_RIDMGR_INIT_ERROR                                               NTStatus      = 0xC00002AA
	STATUS_DS_OBJ_CLASS_VIOLATION                                             NTStatus      = 0xC00002AB
	STATUS_DS_CANT_ON_NON_LEAF                                                NTStatus      = 0xC00002AC
	STATUS_DS_CANT_ON_RDN                                                     NTStatus      = 0xC00002AD
	STATUS_DS_CANT_MOD_OBJ_CLASS                                              NTStatus      = 0xC00002AE
	STATUS_DS_CROSS_DOM_MOVE_FAILED                                           NTStatus      = 0xC00002AF
	STATUS_DS_GC_NOT_AVAILABLE                                                NTStatus      = 0xC00002B0
	STATUS_DIRECTORY_SERVICE_REQUIRED                                         NTStatus      = 0xC00002B1
	STATUS_REPARSE_ATTRIBUTE_CONFLICT                                         NTStatus      = 0xC00002B2
	STATUS_CANT_ENABLE_DENY_ONLY                                              NTStatus      = 0xC00002B3
	STATUS_FLOAT_MULTIPLE_FAULTS                                              NTStatus      = 0xC00002B4
	STATUS_FLOAT_MULTIPLE_TRAPS                                               NTStatus      = 0xC00002B5
	STATUS_DEVICE_REMOVED                                                     NTStatus      = 0xC00002B6
	STATUS_JOURNAL_DELETE_IN_PROGRESS                                         NTStatus      = 0xC00002B7
	STATUS_JOURNAL_NOT_ACTIVE                                                 NTStatus      = 0xC00002B8
	STATUS_NOINTERFACE                                                        NTStatus      = 0xC00002B9
	STATUS_DS_RIDMGR_DISABLED                                                 NTStatus      = 0xC00002BA
	STATUS_DS_ADMIN_LIMIT_EXCEEDED                                            NTStatus      = 0xC00002C1
	STATUS_DRIVER_FAILED_SLEEP                                                NTStatus      = 0xC00002C2
	STATUS_MUTUAL_AUTHENTICATION_FAILED                                       NTStatus      = 0xC00002C3
	STATUS_CORRUPT_SYSTEM_FILE                                                NTStatus      = 0xC00002C4
	STATUS_DATATYPE_MISALIGNMENT_ERROR                                        NTStatus      = 0xC00002C5
	STATUS_WMI_READ_ONLY                                                      NTStatus      = 0xC00002C6
	STATUS_WMI_SET_FAILURE                                                    NTStatus      = 0xC00002C7
	STATUS_COMMITMENT_MINIMUM                                                 NTStatus      = 0xC00002C8
	STATUS_REG_NAT_CONSUMPTION                                                NTStatus      = 0xC00002C9
	STATUS_TRANSPORT_FULL                                                     NTStatus      = 0xC00002CA
	STATUS_DS_SAM_INIT_FAILURE                                                NTStatus      = 0xC00002CB
	STATUS_ONLY_IF_CONNECTED                                                  NTStatus      = 0xC00002CC
	STATUS_DS_SENSITIVE_GROUP_VIOLATION                                       NTStatus      = 0xC00002CD
	STATUS_PNP_RESTART_ENUMERATION                                            NTStatus      = 0xC00002CE
	STATUS_JOURNAL_ENTRY_DELETED                                              NTStatus      = 0xC00002CF
	STATUS_DS_CANT_MOD_PRIMARYGROUPID                                         NTStatus      = 0xC00002D0
	STATUS_SYSTEM_IMAGE_BAD_SIGNATURE                                         NTStatus      = 0xC00002D1
	STATUS_PNP_REBOOT_REQUIRED                                                NTStatus      = 0xC00002D2
	STATUS_POWER_STATE_INVALID                                                NTStatus      = 0xC00002D3
	STATUS_DS_INVALID_GROUP_TYPE                                              NTStatus      = 0xC00002D4
	STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN                              NTStatus      = 0xC00002D5
	STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN                               NTStatus      = 0xC00002D6
	STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER                                   NTStatus      = 0xC00002D7
	STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER                               NTStatus      = 0xC00002D8
	STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER                                NTStatus      = 0xC00002D9
	STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER                             NTStatus      = 0xC00002DA
	STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER                        NTStatus      = 0xC00002DB
	STATUS_DS_HAVE_PRIMARY_MEMBERS                                            NTStatus      = 0xC00002DC
	STATUS_WMI_NOT_SUPPORTED                                                  NTStatus      = 0xC00002DD
	STATUS_INSUFFICIENT_POWER                                                 NTStatus      = 0xC00002DE
	STATUS_SAM_NEED_BOOTKEY_PASSWORD                                          NTStatus      = 0xC00002DF
	STATUS_SAM_NEED_BOOTKEY_FLOPPY                                            NTStatus      = 0xC00002E0
	STATUS_DS_CANT_START                                                      NTStatus      = 0xC00002E1
	STATUS_DS_INIT_FAILURE                                                    NTStatus      = 0xC00002E2
	STATUS_SAM_INIT_FAILURE                                                   NTStatus      = 0xC00002E3
	STATUS_DS_GC_REQUIRED                                                     NTStatus      = 0xC00002E4
	STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY                                      NTStatus      = 0xC00002E5
	STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS                                      NTStatus      = 0xC00002E6
	STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED                                  NTStatus      = 0xC00002E7
	STATUS_MULTIPLE_FAULT_VIOLATION                                           NTStatus      = 0xC00002E8
	STATUS_CURRENT_DOMAIN_NOT_ALLOWED                                         NTStatus      = 0xC00002E9
	STATUS_CANNOT_MAKE                                                        NTStatus      = 0xC00002EA
	STATUS_SYSTEM_SHUTDOWN                                                    NTStatus      = 0xC00002EB
	STATUS_DS_INIT_FAILURE_CONSOLE                                            NTStatus      = 0xC00002EC
	STATUS_DS_SAM_INIT_FAILURE_CONSOLE                                        NTStatus      = 0xC00002ED
	STATUS_UNFINISHED_CONTEXT_DELETED                                         NTStatus      = 0xC00002EE
	STATUS_NO_TGT_REPLY                                                       NTStatus      = 0xC00002EF
	STATUS_OBJECTID_NOT_FOUND                                                 NTStatus      = 0xC00002F0
	STATUS_NO_IP_ADDRESSES                                                    NTStatus      = 0xC00002F1
	STATUS_WRONG_CREDENTIAL_HANDLE                                            NTStatus      = 0xC00002F2
	STATUS_CRYPTO_SYSTEM_INVALID                                              NTStatus      = 0xC00002F3
	STATUS_MAX_REFERRALS_EXCEEDED                                             NTStatus      = 0xC00002F4
	STATUS_MUST_BE_KDC                                                        NTStatus      = 0xC00002F5
	STATUS_STRONG_CRYPTO_NOT_SUPPORTED                                        NTStatus      = 0xC00002F6
	STATUS_TOO_MANY_PRINCIPALS                                                NTStatus      = 0xC00002F7
	STATUS_NO_PA_DATA                                                         NTStatus      = 0xC00002F8
	STATUS_PKINIT_NAME_MISMATCH                                               NTStatus      = 0xC00002F9
	STATUS_SMARTCARD_LOGON_REQUIRED                                           NTStatus      = 0xC00002FA
	STATUS_KDC_INVALID_REQUEST                                                NTStatus      = 0xC00002FB
	STATUS_KDC_UNABLE_TO_REFER                                                NTStatus      = 0xC00002FC
	STATUS_KDC_UNKNOWN_ETYPE                                                  NTStatus      = 0xC00002FD
	STATUS_SHUTDOWN_IN_PROGRESS                                               NTStatus      = 0xC00002FE
	STATUS_SERVER_SHUTDOWN_IN_PROGRESS                                        NTStatus      = 0xC00002FF
	STATUS_NOT_SUPPORTED_ON_SBS                                               NTStatus      = 0xC0000300
	STATUS_WMI_GUID_DISCONNECTED                                              NTStatus      = 0xC0000301
	STATUS_WMI_ALREADY_DISABLED                                               NTStatus      = 0xC0000302
	STATUS_WMI_ALREADY_ENABLED                                                NTStatus      = 0xC0000303
	STATUS_MFT_TOO_FRAGMENTED                                                 NTStatus      = 0xC0000304
	STATUS_COPY_PROTECTION_FAILURE                                            NTStatus      = 0xC0000305
	STATUS_CSS_AUTHENTICATION_FAILURE                                         NTStatus      = 0xC0000306
	STATUS_CSS_KEY_NOT_PRESENT                                                NTStatus      = 0xC0000307
	STATUS_CSS_KEY_NOT_ESTABLISHED                                            NTStatus      = 0xC0000308
	STATUS_CSS_SCRAMBLED_SECTOR                                               NTStatus      = 0xC0000309
	STATUS_CSS_REGION_MISMATCH                                                NTStatus      = 0xC000030A
	STATUS_CSS_RESETS_EXHAUSTED                                               NTStatus      = 0xC000030B
	STATUS_PASSWORD_CHANGE_REQUIRED                                           NTStatus      = 0xC000030C
	STATUS_LOST_MODE_LOGON_RESTRICTION                                        NTStatus      = 0xC000030D
	STATUS_PKINIT_FAILURE                                                     NTStatus      = 0xC0000320
	STATUS_SMARTCARD_SUBSYSTEM_FAILURE                                        NTStatus      = 0xC0000321
	STATUS_NO_KERB_KEY                                                        NTStatus      = 0xC0000322
	STATUS_HOST_DOWN                                                          NTStatus      = 0xC0000350
	STATUS_UNSUPPORTED_PREAUTH                                                NTStatus      = 0xC0000351
	STATUS_EFS_ALG_BLOB_TOO_BIG                                               NTStatus      = 0xC0000352
	STATUS_PORT_NOT_SET                                                       NTStatus      = 0xC0000353
	STATUS_DEBUGGER_INACTIVE                                                  NTStatus      = 0xC0000354
	STATUS_DS_VERSION_CHECK_FAILURE                                           NTStatus      = 0xC0000355
	STATUS_AUDITING_DISABLED                                                  NTStatus      = 0xC0000356
	STATUS_PRENT4_MACHINE_ACCOUNT                                             NTStatus      = 0xC0000357
	STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER                                   NTStatus      = 0xC0000358
	STATUS_INVALID_IMAGE_WIN_32                                               NTStatus      = 0xC0000359
	STATUS_INVALID_IMAGE_WIN_64                                               NTStatus      = 0xC000035A
	STATUS_BAD_BINDINGS                                                       NTStatus      = 0xC000035B
	STATUS_NETWORK_SESSION_EXPIRED                                            NTStatus      = 0xC000035C
	STATUS_APPHELP_BLOCK                                                      NTStatus      = 0xC000035D
	STATUS_ALL_SIDS_FILTERED                                                  NTStatus      = 0xC000035E
	STATUS_NOT_SAFE_MODE_DRIVER                                               NTStatus      = 0xC000035F
	STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT                                  NTStatus      = 0xC0000361
	STATUS_ACCESS_DISABLED_BY_POLICY_PATH                                     NTStatus      = 0xC0000362
	STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER                                NTStatus      = 0xC0000363
	STATUS_ACCESS_DISABLED_BY_POLICY_OTHER                                    NTStatus      = 0xC0000364
	STATUS_FAILED_DRIVER_ENTRY                                                NTStatus      = 0xC0000365
	STATUS_DEVICE_ENUMERATION_ERROR                                           NTStatus      = 0xC0000366
	STATUS_MOUNT_POINT_NOT_RESOLVED                                           NTStatus      = 0xC0000368
	STATUS_INVALID_DEVICE_OBJECT_PARAMETER                                    NTStatus      = 0xC0000369
	STATUS_MCA_OCCURED                                                        NTStatus      = 0xC000036A
	STATUS_DRIVER_BLOCKED_CRITICAL                                            NTStatus      = 0xC000036B
	STATUS_DRIVER_BLOCKED                                                     NTStatus      = 0xC000036C
	STATUS_DRIVER_DATABASE_ERROR                                              NTStatus      = 0xC000036D
	STATUS_SYSTEM_HIVE_TOO_LARGE                                              NTStatus      = 0xC000036E
	STATUS_INVALID_IMPORT_OF_NON_DLL                                          NTStatus      = 0xC000036F
	STATUS_DS_SHUTTING_DOWN                                                   NTStatus      = 0x40000370
	STATUS_NO_SECRETS                                                         NTStatus      = 0xC0000371
	STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY                              NTStatus      = 0xC0000372
	STATUS_FAILED_STACK_SWITCH                                                NTStatus      = 0xC0000373
	STATUS_HEAP_CORRUPTION                                                    NTStatus      = 0xC0000374
	STATUS_SMARTCARD_WRONG_PIN                                                NTStatus      = 0xC0000380
	STATUS_SMARTCARD_CARD_BLOCKED                                             NTStatus      = 0xC0000381
	STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED                                   NTStatus      = 0xC0000382
	STATUS_SMARTCARD_NO_CARD                                                  NTStatus      = 0xC0000383
	STATUS_SMARTCARD_NO_KEY_CONTAINER                                         NTStatus      = 0xC0000384
	STATUS_SMARTCARD_NO_CERTIFICATE                                           NTStatus      = 0xC0000385
	STATUS_SMARTCARD_NO_KEYSET                                                NTStatus      = 0xC0000386
	STATUS_SMARTCARD_IO_ERROR                                                 NTStatus      = 0xC0000387
	STATUS_DOWNGRADE_DETECTED                                                 NTStatus      = 0xC0000388
	STATUS_SMARTCARD_CERT_REVOKED                                             NTStatus      = 0xC0000389
	STATUS_ISSUING_CA_UNTRUSTED                                               NTStatus      = 0xC000038A
	STATUS_REVOCATION_OFFLINE_C                                               NTStatus      = 0xC000038B
	STATUS_PKINIT_CLIENT_FAILURE                                              NTStatus      = 0xC000038C
	STATUS_SMARTCARD_CERT_EXPIRED                                             NTStatus      = 0xC000038D
	STATUS_DRIVER_FAILED_PRIOR_UNLOAD                                         NTStatus      = 0xC000038E
	STATUS_SMARTCARD_SILENT_CONTEXT                                           NTStatus      = 0xC000038F
	STATUS_PER_USER_TRUST_QUOTA_EXCEEDED                                      NTStatus      = 0xC0000401
	STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED                                      NTStatus      = 0xC0000402
	STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED                                   NTStatus      = 0xC0000403
	STATUS_DS_NAME_NOT_UNIQUE                                                 NTStatus      = 0xC0000404
	STATUS_DS_DUPLICATE_ID_FOUND                                              NTStatus      = 0xC0000405
	STATUS_DS_GROUP_CONVERSION_ERROR                                          NTStatus      = 0xC0000406
	STATUS_VOLSNAP_PREPARE_HIBERNATE                                          NTStatus      = 0xC0000407
	STATUS_USER2USER_REQUIRED                                                 NTStatus      = 0xC0000408
	STATUS_STACK_BUFFER_OVERRUN                                               NTStatus      = 0xC0000409
	STATUS_NO_S4U_PROT_SUPPORT                                                NTStatus      = 0xC000040A
	STATUS_CROSSREALM_DELEGATION_FAILURE                                      NTStatus      = 0xC000040B
	STATUS_REVOCATION_OFFLINE_KDC                                             NTStatus      = 0xC000040C
	STATUS_ISSUING_CA_UNTRUSTED_KDC                                           NTStatus      = 0xC000040D
	STATUS_KDC_CERT_EXPIRED                                                   NTStatus      = 0xC000040E
	STATUS_KDC_CERT_REVOKED                                                   NTStatus      = 0xC000040F
	STATUS_PARAMETER_QUOTA_EXCEEDED                                           NTStatus      = 0xC0000410
	STATUS_HIBERNATION_FAILURE                                                NTStatus      = 0xC0000411
	STATUS_DELAY_LOAD_FAILED                                                  NTStatus      = 0xC0000412
	STATUS_AUTHENTICATION_FIREWALL_FAILED                                     NTStatus      = 0xC0000413
	STATUS_VDM_DISALLOWED                                                     NTStatus      = 0xC0000414
	STATUS_HUNG_DISPLAY_DRIVER_THREAD                                         NTStatus      = 0xC0000415
	STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE            NTStatus      = 0xC0000416
	STATUS_INVALID_CRUNTIME_PARAMETER                                         NTStatus      = 0xC0000417
	STATUS_NTLM_BLOCKED                                                       NTStatus      = 0xC0000418
	STATUS_DS_SRC_SID_EXISTS_IN_FOREST                                        NTStatus      = 0xC0000419
	STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST                                    NTStatus      = 0xC000041A
	STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST                                      NTStatus      = 0xC000041B
	STATUS_INVALID_USER_PRINCIPAL_NAME                                        NTStatus      = 0xC000041C
	STATUS_FATAL_USER_CALLBACK_EXCEPTION                                      NTStatus      = 0xC000041D
	STATUS_ASSERTION_FAILURE                                                  NTStatus      = 0xC0000420
	STATUS_VERIFIER_STOP                                                      NTStatus      = 0xC0000421
	STATUS_CALLBACK_POP_STACK                                                 NTStatus      = 0xC0000423
	STATUS_INCOMPATIBLE_DRIVER_BLOCKED                                        NTStatus      = 0xC0000424
	STATUS_HIVE_UNLOADED                                                      NTStatus      = 0xC0000425
	STATUS_COMPRESSION_DISABLED                                               NTStatus      = 0xC0000426
	STATUS_FILE_SYSTEM_LIMITATION                                             NTStatus      = 0xC0000427
	STATUS_INVALID_IMAGE_HASH                                                 NTStatus      = 0xC0000428
	STATUS_NOT_CAPABLE                                                        NTStatus      = 0xC0000429
	STATUS_REQUEST_OUT_OF_SEQUENCE                                            NTStatus      = 0xC000042A
	STATUS_IMPLEMENTATION_LIMIT                                               NTStatus      = 0xC000042B
	STATUS_ELEVATION_REQUIRED                                                 NTStatus      = 0xC000042C
	STATUS_NO_SECURITY_CONTEXT                                                NTStatus      = 0xC000042D
	STATUS_PKU2U_CERT_FAILURE                                                 NTStatus      = 0xC000042F
	STATUS_BEYOND_VDL                                                         NTStatus      = 0xC0000432
	STATUS_ENCOUNTERED_WRITE_IN_PROGRESS                                      NTStatus      = 0xC0000433
	STATUS_PTE_CHANGED                                                        NTStatus      = 0xC0000434
	STATUS_PURGE_FAILED                                                       NTStatus      = 0xC0000435
	STATUS_CRED_REQUIRES_CONFIRMATION                                         NTStatus      = 0xC0000440
	STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE                              NTStatus      = 0xC0000441
	STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER                                   NTStatus      = 0xC0000442
	STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE                              NTStatus      = 0xC0000443
	STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE                                   NTStatus      = 0xC0000444
	STATUS_CS_ENCRYPTION_FILE_NOT_CSE                                         NTStatus      = 0xC0000445
	STATUS_INVALID_LABEL                                                      NTStatus      = 0xC0000446
	STATUS_DRIVER_PROCESS_TERMINATED                                          NTStatus      = 0xC0000450
	STATUS_AMBIGUOUS_SYSTEM_DEVICE                                            NTStatus      = 0xC0000451
	STATUS_SYSTEM_DEVICE_NOT_FOUND                                            NTStatus      = 0xC0000452
	STATUS_RESTART_BOOT_APPLICATION                                           NTStatus      = 0xC0000453
	STATUS_INSUFFICIENT_NVRAM_RESOURCES                                       NTStatus      = 0xC0000454
	STATUS_INVALID_SESSION                                                    NTStatus      = 0xC0000455
	STATUS_THREAD_ALREADY_IN_SESSION                                          NTStatus      = 0xC0000456
	STATUS_THREAD_NOT_IN_SESSION                                              NTStatus      = 0xC0000457
	STATUS_INVALID_WEIGHT                                                     NTStatus      = 0xC0000458
	STATUS_REQUEST_PAUSED                                                     NTStatus      = 0xC0000459
	STATUS_NO_RANGES_PROCESSED                                                NTStatus      = 0xC0000460
	STATUS_DISK_RESOURCES_EXHAUSTED                                           NTStatus      = 0xC0000461
	STATUS_NEEDS_REMEDIATION                                                  NTStatus      = 0xC0000462
	STATUS_DEVICE_FEATURE_NOT_SUPPORTED                                       NTStatus      = 0xC0000463
	STATUS_DEVICE_UNREACHABLE                                                 NTStatus      = 0xC0000464
	STATUS_INVALID_TOKEN                                                      NTStatus      = 0xC0000465
	STATUS_SERVER_UNAVAILABLE                                                 NTStatus      = 0xC0000466
	STATUS_FILE_NOT_AVAILABLE                                                 NTStatus      = 0xC0000467
	STATUS_DEVICE_INSUFFICIENT_RESOURCES                                      NTStatus      = 0xC0000468
	STATUS_PACKAGE_UPDATING                                                   NTStatus      = 0xC0000469
	STATUS_NOT_READ_FROM_COPY                                                 NTStatus      = 0xC000046A
	STATUS_FT_WRITE_FAILURE                                                   NTStatus      = 0xC000046B
	STATUS_FT_DI_SCAN_REQUIRED                                                NTStatus      = 0xC000046C
	STATUS_OBJECT_NOT_EXTERNALLY_BACKED                                       NTStatus      = 0xC000046D
	STATUS_EXTERNAL_BACKING_PROVIDER_UNKNOWN                                  NTStatus      = 0xC000046E
	STATUS_COMPRESSION_NOT_BENEFICIAL                                         NTStatus      = 0xC000046F
	STATUS_DATA_CHECKSUM_ERROR                                                NTStatus      = 0xC0000470
	STATUS_INTERMIXED_KERNEL_EA_OPERATION                                     NTStatus      = 0xC0000471
	STATUS_TRIM_READ_ZERO_NOT_SUPPORTED                                       NTStatus      = 0xC0000472
	STATUS_TOO_MANY_SEGMENT_DESCRIPTORS                                       NTStatus      = 0xC0000473
	STATUS_INVALID_OFFSET_ALIGNMENT                                           NTStatus      = 0xC0000474
	STATUS_INVALID_FIELD_IN_PARAMETER_LIST                                    NTStatus      = 0xC0000475
	STATUS_OPERATION_IN_PROGRESS                                              NTStatus      = 0xC0000476
	STATUS_INVALID_INITIATOR_TARGET_PATH                                      NTStatus      = 0xC0000477
	STATUS_SCRUB_DATA_DISABLED                                                NTStatus      = 0xC0000478
	STATUS_NOT_REDUNDANT_STORAGE                                              NTStatus      = 0xC0000479
	STATUS_RESIDENT_FILE_NOT_SUPPORTED                                        NTStatus      = 0xC000047A
	STATUS_COMPRESSED_FILE_NOT_SUPPORTED                                      NTStatus      = 0xC000047B
	STATUS_DIRECTORY_NOT_SUPPORTED                                            NTStatus      = 0xC000047C
	STATUS_IO_OPERATION_TIMEOUT                                               NTStatus      = 0xC000047D
	STATUS_SYSTEM_NEEDS_REMEDIATION                                           NTStatus      = 0xC000047E
	STATUS_APPX_INTEGRITY_FAILURE_CLR_NGEN                                    NTStatus      = 0xC000047F
	STATUS_SHARE_UNAVAILABLE                                                  NTStatus      = 0xC0000480
	STATUS_APISET_NOT_HOSTED                                                  NTStatus      = 0xC0000481
	STATUS_APISET_NOT_PRESENT                          
"""




```