Response:
Let's break down the thought process for answering the request about the Go code snippet.

**1. Understanding the Core Task:**

The request asks for the *functionality* of the provided Go code. Immediately, the structure of the code stands out: a series of constant declarations. Each constant assigns a hexadecimal value to a name prefixed with `STATUS_`. The type of these constants is `NTStatus`.

**2. Identifying the Obvious:**

The most direct functionality is the declaration of these named constants. This is the primary function of the code.

**3. Deducing the Purpose of the Constants:**

The `STATUS_` prefix strongly suggests these constants represent error codes. The `NTStatus` type further reinforces this, hinting at a connection to the Windows NT operating system. The sheer number of these constants confirms this: it's a comprehensive list of potential error conditions.

**4. Inferring the Broader Context:**

Since this is a Go file within the `golang.org/x/sys/windows` package, it's reasonable to assume these constants are used for interacting with the Windows API. Specifically, they represent error codes returned by Windows system calls.

**5. Considering Go Language Features:**

The request specifically asks about what Go language feature is being implemented. The answer is straightforward: constant declaration. Go's `const` keyword is used to define these values.

**6. Constructing a Code Example:**

To illustrate the usage, a simple example of making a Windows system call and checking for these errors is needed. The `syscall` package is the standard Go way to interact with system calls.

* **Choosing a System Call:**  A common and simple system call to demonstrate is `CreateFile`. This function returns an error, making it suitable.

* **Error Handling:**  The example needs to show how to receive the error from `CreateFile` and how to compare it to the declared constants. Type assertion (`err.(syscall.Errno)`) is crucial for accessing the underlying Windows error code.

* **Input and Output (Hypothetical):** Since the example involves file creation, the input would be a file path. The output would be a success message or an error message corresponding to one of the declared `STATUS_` constants.

**7. Addressing Other Points in the Request:**

* **Command-Line Arguments:**  The provided code doesn't directly handle command-line arguments. It's a definition of constants. So, this part of the request is not applicable.

* **Common Mistakes:**  One potential mistake users might make is comparing errors directly without type assertion. A raw `error` interface cannot be directly compared to the `NTStatus` constants. This needs to be highlighted. Another mistake would be assuming all errors are of type `syscall.Errno`. While many are, some errors might be different.

* **Summarizing Functionality (for part 13/15):** The main function remains the definition of Windows NT status codes. The context of being part 13 of 15 suggests this is a larger set of definitions, and this particular part covers a specific range of error codes.

**8. Structuring the Answer:**

The answer should be organized logically, following the points in the original request:

* **Functionality:** Start with the most basic function – declaring constants.
* **Go Feature:** Identify the Go language feature used (constant declaration).
* **Code Example:** Provide a clear and concise Go code example demonstrating usage.
* **Input/Output:**  Explain the hypothetical input and output of the example.
* **Command-Line Arguments:** State that this isn't applicable.
* **Common Mistakes:**  Point out the crucial type assertion for error comparison.
* **Part 13 Summary:** Briefly summarize the function within the context of the larger set of files.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Could this file be related to some form of error translation or mapping? While it *is* defining error codes, its primary function is declaration, not active translation. The translation likely happens in other parts of the `syscall` package or higher-level APIs.

* **Code Example Improvement:** Initially, the example might just check for one specific error. It's better to show a more general approach of using a `switch` statement or multiple `if` conditions to handle different potential errors.

By following this structured thought process, the comprehensive and accurate answer can be generated, addressing all aspects of the user's request.
好的，让我们来分析一下这段 Go 代码的功能。

**功能列举：**

这段代码的主要功能是**定义了一系列常量**。这些常量以 `STATUS_` 开头，并关联一个 `NTStatus` 类型的十六进制数值。

具体来说，它定义了 Windows 操作系统中各种错误和状态码。这些代码涵盖了非常广泛的系统层面问题，例如：

* **设备硬件错误:** `STATUS_DEVICE_HARDWARE_ERROR`
* **文件系统错误:** `STATUS_FILE_NOT_FOUND`, `STATUS_DISK_FULL`
* **内存管理错误:** `STATUS_NO_MEMORY`
* **网络错误:** `STATUS_NETWORK_ACCESS_DENIED_EDP`
* **安全错误:** `STATUS_ACCESS_DENIED`
* **驱动程序相关错误:** `STATUS_PNP_NO_COMPAT_DRIVERS`
* **虚拟化相关错误:** `STATUS_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE`
* **云文件相关错误:** `STATUS_CLOUD_FILE_NOT_IN_SYNC`
* **事务处理相关错误:** `STATUS_TRANSACTIONAL_CONFLICT`
* **日志相关错误:** `STATUS_LOG_FULL`
* **图形显示相关错误:** `STATUS_GRAPHICS_NO_VIDEO_MEMORY`

等等。

**Go 语言功能实现推断：**

这段代码实现的是 Go 语言的**常量定义 (Constant Declaration)** 功能。

**Go 代码示例：**

假设我们想在 Go 代码中检查文件操作是否因为文件未找到而失败。我们可以使用这里定义的常量：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// 假设 zerrors_windows.go 中的常量已经被引入或者在同一个包中

func main() {
	// 尝试打开一个不存在的文件
	_, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr("non_existent_file.txt"),
		syscall.GENERIC_READ,
		0,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0)

	if err != nil {
		// 将 error 断言为 syscall.Errno 以获取底层的 Windows 错误码
		errno, ok := err.(syscall.Errno)
		if ok {
			// 与 STATUS_FILE_NOT_FOUND 进行比较
			if errno == syscall.Errno(STATUS_FILE_NOT_FOUND) {
				fmt.Println("错误：文件未找到")
			} else {
				fmt.Printf("其他错误：%#x\n", errno)
			}
		} else {
			fmt.Println("未知错误类型")
		}
	} else {
		fmt.Println("文件打开成功 (不应该发生)")
	}
}
```

**假设的输入与输出：**

* **输入：** 尝试打开一个名为 "non_existent_file.txt" 的文件，该文件不存在。
* **输出：** `错误：文件未找到`

**代码推理：**

1. `syscall.CreateFile` 函数尝试使用指定的参数打开文件。由于文件不存在，它会返回一个错误。
2. 我们将返回的 `error` 类型的值 `err` 断言为 `syscall.Errno` 类型。这是因为 Windows 系统调用返回的错误通常可以转换为 `syscall.Errno`，它底层存储了 Windows 的错误码。
3. 如果断言成功 (`ok` 为 `true`)，我们将 `errno` (syscall.Errno 类型) 与我们代码片段中定义的常量 `STATUS_FILE_NOT_FOUND` 进行比较。需要注意的是，这里需要将 `STATUS_FILE_NOT_FOUND` 转换为 `syscall.Errno` 类型才能进行比较。
4. 如果 `errno` 的值与 `STATUS_FILE_NOT_FOUND` 相等，我们就知道错误是因为文件未找到。

**命令行参数的具体处理：**

这段代码本身不涉及命令行参数的处理。它只是定义了一些常量。命令行参数的处理通常发生在应用程序的 `main` 函数中，使用 `os.Args` 等方式获取和解析。

**使用者易犯错的点：**

* **直接比较 `error` 类型：** 初学者可能会尝试直接将 `syscall.CreateFile` 返回的 `error` 与 `STATUS_FILE_NOT_FOUND` 进行比较，这是错误的。需要先将 `error` 断言为 `syscall.Errno` 才能访问到真正的 Windows 错误码。
* **忘记类型转换：**  在比较 `syscall.Errno` 和 `STATUS_FILE_NOT_FOUND` 时，需要确保类型一致，即将 `STATUS_FILE_NOT_FOUND` 转换为 `syscall.Errno`。
* **假设所有系统调用错误都是 `syscall.Errno`：** 虽然大部分情况下是这样，但并非所有系统调用错误都能直接转换为 `syscall.Errno`。更健壮的错误处理可能需要检查不同的错误类型。

**第 13 部分功能归纳：**

作为第 13 部分，这段代码延续了之前部分的功能，**继续定义了大量的 Windows NT 状态码常量**。它涵盖了从 `0xC0000482` 到 `0xC01E031E` 这一范围内的错误代码。这些常量为 Go 语言的 `syscall` 包以及其他需要与底层 Windows API 交互的库提供了标准化的错误表示，使得 Go 开发者能够以更清晰和类型安全的方式处理 Windows 系统调用返回的错误。整个 `zerrors_windows.go` 文件（以及它的多个部分）共同构成了一个 Windows 错误码的完整映射，是 Go 语言在 Windows 平台上进行系统编程的重要基础。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第13部分，共15部分，请归纳一下它的功能

"""
                       NTStatus      = 0xC0000482
	STATUS_DEVICE_HARDWARE_ERROR                                              NTStatus      = 0xC0000483
	STATUS_FIRMWARE_SLOT_INVALID                                              NTStatus      = 0xC0000484
	STATUS_FIRMWARE_IMAGE_INVALID                                             NTStatus      = 0xC0000485
	STATUS_STORAGE_TOPOLOGY_ID_MISMATCH                                       NTStatus      = 0xC0000486
	STATUS_WIM_NOT_BOOTABLE                                                   NTStatus      = 0xC0000487
	STATUS_BLOCKED_BY_PARENTAL_CONTROLS                                       NTStatus      = 0xC0000488
	STATUS_NEEDS_REGISTRATION                                                 NTStatus      = 0xC0000489
	STATUS_QUOTA_ACTIVITY                                                     NTStatus      = 0xC000048A
	STATUS_CALLBACK_INVOKE_INLINE                                             NTStatus      = 0xC000048B
	STATUS_BLOCK_TOO_MANY_REFERENCES                                          NTStatus      = 0xC000048C
	STATUS_MARKED_TO_DISALLOW_WRITES                                          NTStatus      = 0xC000048D
	STATUS_NETWORK_ACCESS_DENIED_EDP                                          NTStatus      = 0xC000048E
	STATUS_ENCLAVE_FAILURE                                                    NTStatus      = 0xC000048F
	STATUS_PNP_NO_COMPAT_DRIVERS                                              NTStatus      = 0xC0000490
	STATUS_PNP_DRIVER_PACKAGE_NOT_FOUND                                       NTStatus      = 0xC0000491
	STATUS_PNP_DRIVER_CONFIGURATION_NOT_FOUND                                 NTStatus      = 0xC0000492
	STATUS_PNP_DRIVER_CONFIGURATION_INCOMPLETE                                NTStatus      = 0xC0000493
	STATUS_PNP_FUNCTION_DRIVER_REQUIRED                                       NTStatus      = 0xC0000494
	STATUS_PNP_DEVICE_CONFIGURATION_PENDING                                   NTStatus      = 0xC0000495
	STATUS_DEVICE_HINT_NAME_BUFFER_TOO_SMALL                                  NTStatus      = 0xC0000496
	STATUS_PACKAGE_NOT_AVAILABLE                                              NTStatus      = 0xC0000497
	STATUS_DEVICE_IN_MAINTENANCE                                              NTStatus      = 0xC0000499
	STATUS_NOT_SUPPORTED_ON_DAX                                               NTStatus      = 0xC000049A
	STATUS_FREE_SPACE_TOO_FRAGMENTED                                          NTStatus      = 0xC000049B
	STATUS_DAX_MAPPING_EXISTS                                                 NTStatus      = 0xC000049C
	STATUS_CHILD_PROCESS_BLOCKED                                              NTStatus      = 0xC000049D
	STATUS_STORAGE_LOST_DATA_PERSISTENCE                                      NTStatus      = 0xC000049E
	STATUS_VRF_CFG_ENABLED                                                    NTStatus      = 0xC000049F
	STATUS_PARTITION_TERMINATING                                              NTStatus      = 0xC00004A0
	STATUS_EXTERNAL_SYSKEY_NOT_SUPPORTED                                      NTStatus      = 0xC00004A1
	STATUS_ENCLAVE_VIOLATION                                                  NTStatus      = 0xC00004A2
	STATUS_FILE_PROTECTED_UNDER_DPL                                           NTStatus      = 0xC00004A3
	STATUS_VOLUME_NOT_CLUSTER_ALIGNED                                         NTStatus      = 0xC00004A4
	STATUS_NO_PHYSICALLY_ALIGNED_FREE_SPACE_FOUND                             NTStatus      = 0xC00004A5
	STATUS_APPX_FILE_NOT_ENCRYPTED                                            NTStatus      = 0xC00004A6
	STATUS_RWRAW_ENCRYPTED_FILE_NOT_ENCRYPTED                                 NTStatus      = 0xC00004A7
	STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILEOFFSET                       NTStatus      = 0xC00004A8
	STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILERANGE                        NTStatus      = 0xC00004A9
	STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_PARAMETER                        NTStatus      = 0xC00004AA
	STATUS_FT_READ_FAILURE                                                    NTStatus      = 0xC00004AB
	STATUS_PATCH_CONFLICT                                                     NTStatus      = 0xC00004AC
	STATUS_STORAGE_RESERVE_ID_INVALID                                         NTStatus      = 0xC00004AD
	STATUS_STORAGE_RESERVE_DOES_NOT_EXIST                                     NTStatus      = 0xC00004AE
	STATUS_STORAGE_RESERVE_ALREADY_EXISTS                                     NTStatus      = 0xC00004AF
	STATUS_STORAGE_RESERVE_NOT_EMPTY                                          NTStatus      = 0xC00004B0
	STATUS_NOT_A_DAX_VOLUME                                                   NTStatus      = 0xC00004B1
	STATUS_NOT_DAX_MAPPABLE                                                   NTStatus      = 0xC00004B2
	STATUS_CASE_DIFFERING_NAMES_IN_DIR                                        NTStatus      = 0xC00004B3
	STATUS_FILE_NOT_SUPPORTED                                                 NTStatus      = 0xC00004B4
	STATUS_NOT_SUPPORTED_WITH_BTT                                             NTStatus      = 0xC00004B5
	STATUS_ENCRYPTION_DISABLED                                                NTStatus      = 0xC00004B6
	STATUS_ENCRYPTING_METADATA_DISALLOWED                                     NTStatus      = 0xC00004B7
	STATUS_CANT_CLEAR_ENCRYPTION_FLAG                                         NTStatus      = 0xC00004B8
	STATUS_INVALID_TASK_NAME                                                  NTStatus      = 0xC0000500
	STATUS_INVALID_TASK_INDEX                                                 NTStatus      = 0xC0000501
	STATUS_THREAD_ALREADY_IN_TASK                                             NTStatus      = 0xC0000502
	STATUS_CALLBACK_BYPASS                                                    NTStatus      = 0xC0000503
	STATUS_UNDEFINED_SCOPE                                                    NTStatus      = 0xC0000504
	STATUS_INVALID_CAP                                                        NTStatus      = 0xC0000505
	STATUS_NOT_GUI_PROCESS                                                    NTStatus      = 0xC0000506
	STATUS_DEVICE_HUNG                                                        NTStatus      = 0xC0000507
	STATUS_CONTAINER_ASSIGNED                                                 NTStatus      = 0xC0000508
	STATUS_JOB_NO_CONTAINER                                                   NTStatus      = 0xC0000509
	STATUS_DEVICE_UNRESPONSIVE                                                NTStatus      = 0xC000050A
	STATUS_REPARSE_POINT_ENCOUNTERED                                          NTStatus      = 0xC000050B
	STATUS_ATTRIBUTE_NOT_PRESENT                                              NTStatus      = 0xC000050C
	STATUS_NOT_A_TIERED_VOLUME                                                NTStatus      = 0xC000050D
	STATUS_ALREADY_HAS_STREAM_ID                                              NTStatus      = 0xC000050E
	STATUS_JOB_NOT_EMPTY                                                      NTStatus      = 0xC000050F
	STATUS_ALREADY_INITIALIZED                                                NTStatus      = 0xC0000510
	STATUS_ENCLAVE_NOT_TERMINATED                                             NTStatus      = 0xC0000511
	STATUS_ENCLAVE_IS_TERMINATING                                             NTStatus      = 0xC0000512
	STATUS_SMB1_NOT_AVAILABLE                                                 NTStatus      = 0xC0000513
	STATUS_SMR_GARBAGE_COLLECTION_REQUIRED                                    NTStatus      = 0xC0000514
	STATUS_INTERRUPTED                                                        NTStatus      = 0xC0000515
	STATUS_THREAD_NOT_RUNNING                                                 NTStatus      = 0xC0000516
	STATUS_FAIL_FAST_EXCEPTION                                                NTStatus      = 0xC0000602
	STATUS_IMAGE_CERT_REVOKED                                                 NTStatus      = 0xC0000603
	STATUS_DYNAMIC_CODE_BLOCKED                                               NTStatus      = 0xC0000604
	STATUS_IMAGE_CERT_EXPIRED                                                 NTStatus      = 0xC0000605
	STATUS_STRICT_CFG_VIOLATION                                               NTStatus      = 0xC0000606
	STATUS_SET_CONTEXT_DENIED                                                 NTStatus      = 0xC000060A
	STATUS_CROSS_PARTITION_VIOLATION                                          NTStatus      = 0xC000060B
	STATUS_PORT_CLOSED                                                        NTStatus      = 0xC0000700
	STATUS_MESSAGE_LOST                                                       NTStatus      = 0xC0000701
	STATUS_INVALID_MESSAGE                                                    NTStatus      = 0xC0000702
	STATUS_REQUEST_CANCELED                                                   NTStatus      = 0xC0000703
	STATUS_RECURSIVE_DISPATCH                                                 NTStatus      = 0xC0000704
	STATUS_LPC_RECEIVE_BUFFER_EXPECTED                                        NTStatus      = 0xC0000705
	STATUS_LPC_INVALID_CONNECTION_USAGE                                       NTStatus      = 0xC0000706
	STATUS_LPC_REQUESTS_NOT_ALLOWED                                           NTStatus      = 0xC0000707
	STATUS_RESOURCE_IN_USE                                                    NTStatus      = 0xC0000708
	STATUS_HARDWARE_MEMORY_ERROR                                              NTStatus      = 0xC0000709
	STATUS_THREADPOOL_HANDLE_EXCEPTION                                        NTStatus      = 0xC000070A
	STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED                          NTStatus      = 0xC000070B
	STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED                  NTStatus      = 0xC000070C
	STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED                      NTStatus      = 0xC000070D
	STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED                       NTStatus      = 0xC000070E
	STATUS_THREADPOOL_RELEASED_DURING_OPERATION                               NTStatus      = 0xC000070F
	STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING                              NTStatus      = 0xC0000710
	STATUS_APC_RETURNED_WHILE_IMPERSONATING                                   NTStatus      = 0xC0000711
	STATUS_PROCESS_IS_PROTECTED                                               NTStatus      = 0xC0000712
	STATUS_MCA_EXCEPTION                                                      NTStatus      = 0xC0000713
	STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE                                     NTStatus      = 0xC0000714
	STATUS_SYMLINK_CLASS_DISABLED                                             NTStatus      = 0xC0000715
	STATUS_INVALID_IDN_NORMALIZATION                                          NTStatus      = 0xC0000716
	STATUS_NO_UNICODE_TRANSLATION                                             NTStatus      = 0xC0000717
	STATUS_ALREADY_REGISTERED                                                 NTStatus      = 0xC0000718
	STATUS_CONTEXT_MISMATCH                                                   NTStatus      = 0xC0000719
	STATUS_PORT_ALREADY_HAS_COMPLETION_LIST                                   NTStatus      = 0xC000071A
	STATUS_CALLBACK_RETURNED_THREAD_PRIORITY                                  NTStatus      = 0xC000071B
	STATUS_INVALID_THREAD                                                     NTStatus      = 0xC000071C
	STATUS_CALLBACK_RETURNED_TRANSACTION                                      NTStatus      = 0xC000071D
	STATUS_CALLBACK_RETURNED_LDR_LOCK                                         NTStatus      = 0xC000071E
	STATUS_CALLBACK_RETURNED_LANG                                             NTStatus      = 0xC000071F
	STATUS_CALLBACK_RETURNED_PRI_BACK                                         NTStatus      = 0xC0000720
	STATUS_CALLBACK_RETURNED_THREAD_AFFINITY                                  NTStatus      = 0xC0000721
	STATUS_LPC_HANDLE_COUNT_EXCEEDED                                          NTStatus      = 0xC0000722
	STATUS_EXECUTABLE_MEMORY_WRITE                                            NTStatus      = 0xC0000723
	STATUS_KERNEL_EXECUTABLE_MEMORY_WRITE                                     NTStatus      = 0xC0000724
	STATUS_ATTACHED_EXECUTABLE_MEMORY_WRITE                                   NTStatus      = 0xC0000725
	STATUS_TRIGGERED_EXECUTABLE_MEMORY_WRITE                                  NTStatus      = 0xC0000726
	STATUS_DISK_REPAIR_DISABLED                                               NTStatus      = 0xC0000800
	STATUS_DS_DOMAIN_RENAME_IN_PROGRESS                                       NTStatus      = 0xC0000801
	STATUS_DISK_QUOTA_EXCEEDED                                                NTStatus      = 0xC0000802
	STATUS_DATA_LOST_REPAIR                                                   NTStatus      = 0x80000803
	STATUS_CONTENT_BLOCKED                                                    NTStatus      = 0xC0000804
	STATUS_BAD_CLUSTERS                                                       NTStatus      = 0xC0000805
	STATUS_VOLUME_DIRTY                                                       NTStatus      = 0xC0000806
	STATUS_DISK_REPAIR_REDIRECTED                                             NTStatus      = 0x40000807
	STATUS_DISK_REPAIR_UNSUCCESSFUL                                           NTStatus      = 0xC0000808
	STATUS_CORRUPT_LOG_OVERFULL                                               NTStatus      = 0xC0000809
	STATUS_CORRUPT_LOG_CORRUPTED                                              NTStatus      = 0xC000080A
	STATUS_CORRUPT_LOG_UNAVAILABLE                                            NTStatus      = 0xC000080B
	STATUS_CORRUPT_LOG_DELETED_FULL                                           NTStatus      = 0xC000080C
	STATUS_CORRUPT_LOG_CLEARED                                                NTStatus      = 0xC000080D
	STATUS_ORPHAN_NAME_EXHAUSTED                                              NTStatus      = 0xC000080E
	STATUS_PROACTIVE_SCAN_IN_PROGRESS                                         NTStatus      = 0xC000080F
	STATUS_ENCRYPTED_IO_NOT_POSSIBLE                                          NTStatus      = 0xC0000810
	STATUS_CORRUPT_LOG_UPLEVEL_RECORDS                                        NTStatus      = 0xC0000811
	STATUS_FILE_CHECKED_OUT                                                   NTStatus      = 0xC0000901
	STATUS_CHECKOUT_REQUIRED                                                  NTStatus      = 0xC0000902
	STATUS_BAD_FILE_TYPE                                                      NTStatus      = 0xC0000903
	STATUS_FILE_TOO_LARGE                                                     NTStatus      = 0xC0000904
	STATUS_FORMS_AUTH_REQUIRED                                                NTStatus      = 0xC0000905
	STATUS_VIRUS_INFECTED                                                     NTStatus      = 0xC0000906
	STATUS_VIRUS_DELETED                                                      NTStatus      = 0xC0000907
	STATUS_BAD_MCFG_TABLE                                                     NTStatus      = 0xC0000908
	STATUS_CANNOT_BREAK_OPLOCK                                                NTStatus      = 0xC0000909
	STATUS_BAD_KEY                                                            NTStatus      = 0xC000090A
	STATUS_BAD_DATA                                                           NTStatus      = 0xC000090B
	STATUS_NO_KEY                                                             NTStatus      = 0xC000090C
	STATUS_FILE_HANDLE_REVOKED                                                NTStatus      = 0xC0000910
	STATUS_WOW_ASSERTION                                                      NTStatus      = 0xC0009898
	STATUS_INVALID_SIGNATURE                                                  NTStatus      = 0xC000A000
	STATUS_HMAC_NOT_SUPPORTED                                                 NTStatus      = 0xC000A001
	STATUS_AUTH_TAG_MISMATCH                                                  NTStatus      = 0xC000A002
	STATUS_INVALID_STATE_TRANSITION                                           NTStatus      = 0xC000A003
	STATUS_INVALID_KERNEL_INFO_VERSION                                        NTStatus      = 0xC000A004
	STATUS_INVALID_PEP_INFO_VERSION                                           NTStatus      = 0xC000A005
	STATUS_HANDLE_REVOKED                                                     NTStatus      = 0xC000A006
	STATUS_EOF_ON_GHOSTED_RANGE                                               NTStatus      = 0xC000A007
	STATUS_IPSEC_QUEUE_OVERFLOW                                               NTStatus      = 0xC000A010
	STATUS_ND_QUEUE_OVERFLOW                                                  NTStatus      = 0xC000A011
	STATUS_HOPLIMIT_EXCEEDED                                                  NTStatus      = 0xC000A012
	STATUS_PROTOCOL_NOT_SUPPORTED                                             NTStatus      = 0xC000A013
	STATUS_FASTPATH_REJECTED                                                  NTStatus      = 0xC000A014
	STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED                         NTStatus      = 0xC000A080
	STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR                         NTStatus      = 0xC000A081
	STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR                             NTStatus      = 0xC000A082
	STATUS_XML_PARSE_ERROR                                                    NTStatus      = 0xC000A083
	STATUS_XMLDSIG_ERROR                                                      NTStatus      = 0xC000A084
	STATUS_WRONG_COMPARTMENT                                                  NTStatus      = 0xC000A085
	STATUS_AUTHIP_FAILURE                                                     NTStatus      = 0xC000A086
	STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS                              NTStatus      = 0xC000A087
	STATUS_DS_OID_NOT_FOUND                                                   NTStatus      = 0xC000A088
	STATUS_INCORRECT_ACCOUNT_TYPE                                             NTStatus      = 0xC000A089
	STATUS_HASH_NOT_SUPPORTED                                                 NTStatus      = 0xC000A100
	STATUS_HASH_NOT_PRESENT                                                   NTStatus      = 0xC000A101
	STATUS_SECONDARY_IC_PROVIDER_NOT_REGISTERED                               NTStatus      = 0xC000A121
	STATUS_GPIO_CLIENT_INFORMATION_INVALID                                    NTStatus      = 0xC000A122
	STATUS_GPIO_VERSION_NOT_SUPPORTED                                         NTStatus      = 0xC000A123
	STATUS_GPIO_INVALID_REGISTRATION_PACKET                                   NTStatus      = 0xC000A124
	STATUS_GPIO_OPERATION_DENIED                                              NTStatus      = 0xC000A125
	STATUS_GPIO_INCOMPATIBLE_CONNECT_MODE                                     NTStatus      = 0xC000A126
	STATUS_GPIO_INTERRUPT_ALREADY_UNMASKED                                    NTStatus      = 0x8000A127
	STATUS_CANNOT_SWITCH_RUNLEVEL                                             NTStatus      = 0xC000A141
	STATUS_INVALID_RUNLEVEL_SETTING                                           NTStatus      = 0xC000A142
	STATUS_RUNLEVEL_SWITCH_TIMEOUT                                            NTStatus      = 0xC000A143
	STATUS_SERVICES_FAILED_AUTOSTART                                          NTStatus      = 0x4000A144
	STATUS_RUNLEVEL_SWITCH_AGENT_TIMEOUT                                      NTStatus      = 0xC000A145
	STATUS_RUNLEVEL_SWITCH_IN_PROGRESS                                        NTStatus      = 0xC000A146
	STATUS_NOT_APPCONTAINER                                                   NTStatus      = 0xC000A200
	STATUS_NOT_SUPPORTED_IN_APPCONTAINER                                      NTStatus      = 0xC000A201
	STATUS_INVALID_PACKAGE_SID_LENGTH                                         NTStatus      = 0xC000A202
	STATUS_LPAC_ACCESS_DENIED                                                 NTStatus      = 0xC000A203
	STATUS_ADMINLESS_ACCESS_DENIED                                            NTStatus      = 0xC000A204
	STATUS_APP_DATA_NOT_FOUND                                                 NTStatus      = 0xC000A281
	STATUS_APP_DATA_EXPIRED                                                   NTStatus      = 0xC000A282
	STATUS_APP_DATA_CORRUPT                                                   NTStatus      = 0xC000A283
	STATUS_APP_DATA_LIMIT_EXCEEDED                                            NTStatus      = 0xC000A284
	STATUS_APP_DATA_REBOOT_REQUIRED                                           NTStatus      = 0xC000A285
	STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED                                     NTStatus      = 0xC000A2A1
	STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED                                    NTStatus      = 0xC000A2A2
	STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED                                    NTStatus      = 0xC000A2A3
	STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED                                   NTStatus      = 0xC000A2A4
	STATUS_WOF_WIM_HEADER_CORRUPT                                             NTStatus      = 0xC000A2A5
	STATUS_WOF_WIM_RESOURCE_TABLE_CORRUPT                                     NTStatus      = 0xC000A2A6
	STATUS_WOF_FILE_RESOURCE_TABLE_CORRUPT                                    NTStatus      = 0xC000A2A7
	STATUS_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE                             NTStatus      = 0xC000CE01
	STATUS_FILE_SYSTEM_VIRTUALIZATION_METADATA_CORRUPT                        NTStatus      = 0xC000CE02
	STATUS_FILE_SYSTEM_VIRTUALIZATION_BUSY                                    NTStatus      = 0xC000CE03
	STATUS_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_UNKNOWN                        NTStatus      = 0xC000CE04
	STATUS_FILE_SYSTEM_VIRTUALIZATION_INVALID_OPERATION                       NTStatus      = 0xC000CE05
	STATUS_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT                              NTStatus      = 0xC000CF00
	STATUS_CLOUD_FILE_PROVIDER_NOT_RUNNING                                    NTStatus      = 0xC000CF01
	STATUS_CLOUD_FILE_METADATA_CORRUPT                                        NTStatus      = 0xC000CF02
	STATUS_CLOUD_FILE_METADATA_TOO_LARGE                                      NTStatus      = 0xC000CF03
	STATUS_CLOUD_FILE_PROPERTY_BLOB_TOO_LARGE                                 NTStatus      = 0x8000CF04
	STATUS_CLOUD_FILE_TOO_MANY_PROPERTY_BLOBS                                 NTStatus      = 0x8000CF05
	STATUS_CLOUD_FILE_PROPERTY_VERSION_NOT_SUPPORTED                          NTStatus      = 0xC000CF06
	STATUS_NOT_A_CLOUD_FILE                                                   NTStatus      = 0xC000CF07
	STATUS_CLOUD_FILE_NOT_IN_SYNC                                             NTStatus      = 0xC000CF08
	STATUS_CLOUD_FILE_ALREADY_CONNECTED                                       NTStatus      = 0xC000CF09
	STATUS_CLOUD_FILE_NOT_SUPPORTED                                           NTStatus      = 0xC000CF0A
	STATUS_CLOUD_FILE_INVALID_REQUEST                                         NTStatus      = 0xC000CF0B
	STATUS_CLOUD_FILE_READ_ONLY_VOLUME                                        NTStatus      = 0xC000CF0C
	STATUS_CLOUD_FILE_CONNECTED_PROVIDER_ONLY                                 NTStatus      = 0xC000CF0D
	STATUS_CLOUD_FILE_VALIDATION_FAILED                                       NTStatus      = 0xC000CF0E
	STATUS_CLOUD_FILE_AUTHENTICATION_FAILED                                   NTStatus      = 0xC000CF0F
	STATUS_CLOUD_FILE_INSUFFICIENT_RESOURCES                                  NTStatus      = 0xC000CF10
	STATUS_CLOUD_FILE_NETWORK_UNAVAILABLE                                     NTStatus      = 0xC000CF11
	STATUS_CLOUD_FILE_UNSUCCESSFUL                                            NTStatus      = 0xC000CF12
	STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT                                     NTStatus      = 0xC000CF13
	STATUS_CLOUD_FILE_IN_USE                                                  NTStatus      = 0xC000CF14
	STATUS_CLOUD_FILE_PINNED                                                  NTStatus      = 0xC000CF15
	STATUS_CLOUD_FILE_REQUEST_ABORTED                                         NTStatus      = 0xC000CF16
	STATUS_CLOUD_FILE_PROPERTY_CORRUPT                                        NTStatus      = 0xC000CF17
	STATUS_CLOUD_FILE_ACCESS_DENIED                                           NTStatus      = 0xC000CF18
	STATUS_CLOUD_FILE_INCOMPATIBLE_HARDLINKS                                  NTStatus      = 0xC000CF19
	STATUS_CLOUD_FILE_PROPERTY_LOCK_CONFLICT                                  NTStatus      = 0xC000CF1A
	STATUS_CLOUD_FILE_REQUEST_CANCELED                                        NTStatus      = 0xC000CF1B
	STATUS_CLOUD_FILE_PROVIDER_TERMINATED                                     NTStatus      = 0xC000CF1D
	STATUS_NOT_A_CLOUD_SYNC_ROOT                                              NTStatus      = 0xC000CF1E
	STATUS_CLOUD_FILE_REQUEST_TIMEOUT                                         NTStatus      = 0xC000CF1F
	STATUS_ACPI_INVALID_OPCODE                                                NTStatus      = 0xC0140001
	STATUS_ACPI_STACK_OVERFLOW                                                NTStatus      = 0xC0140002
	STATUS_ACPI_ASSERT_FAILED                                                 NTStatus      = 0xC0140003
	STATUS_ACPI_INVALID_INDEX                                                 NTStatus      = 0xC0140004
	STATUS_ACPI_INVALID_ARGUMENT                                              NTStatus      = 0xC0140005
	STATUS_ACPI_FATAL                                                         NTStatus      = 0xC0140006
	STATUS_ACPI_INVALID_SUPERNAME                                             NTStatus      = 0xC0140007
	STATUS_ACPI_INVALID_ARGTYPE                                               NTStatus      = 0xC0140008
	STATUS_ACPI_INVALID_OBJTYPE                                               NTStatus      = 0xC0140009
	STATUS_ACPI_INVALID_TARGETTYPE                                            NTStatus      = 0xC014000A
	STATUS_ACPI_INCORRECT_ARGUMENT_COUNT                                      NTStatus      = 0xC014000B
	STATUS_ACPI_ADDRESS_NOT_MAPPED                                            NTStatus      = 0xC014000C
	STATUS_ACPI_INVALID_EVENTTYPE                                             NTStatus      = 0xC014000D
	STATUS_ACPI_HANDLER_COLLISION                                             NTStatus      = 0xC014000E
	STATUS_ACPI_INVALID_DATA                                                  NTStatus      = 0xC014000F
	STATUS_ACPI_INVALID_REGION                                                NTStatus      = 0xC0140010
	STATUS_ACPI_INVALID_ACCESS_SIZE                                           NTStatus      = 0xC0140011
	STATUS_ACPI_ACQUIRE_GLOBAL_LOCK                                           NTStatus      = 0xC0140012
	STATUS_ACPI_ALREADY_INITIALIZED                                           NTStatus      = 0xC0140013
	STATUS_ACPI_NOT_INITIALIZED                                               NTStatus      = 0xC0140014
	STATUS_ACPI_INVALID_MUTEX_LEVEL                                           NTStatus      = 0xC0140015
	STATUS_ACPI_MUTEX_NOT_OWNED                                               NTStatus      = 0xC0140016
	STATUS_ACPI_MUTEX_NOT_OWNER                                               NTStatus      = 0xC0140017
	STATUS_ACPI_RS_ACCESS                                                     NTStatus      = 0xC0140018
	STATUS_ACPI_INVALID_TABLE                                                 NTStatus      = 0xC0140019
	STATUS_ACPI_REG_HANDLER_FAILED                                            NTStatus      = 0xC0140020
	STATUS_ACPI_POWER_REQUEST_FAILED                                          NTStatus      = 0xC0140021
	STATUS_CTX_WINSTATION_NAME_INVALID                                        NTStatus      = 0xC00A0001
	STATUS_CTX_INVALID_PD                                                     NTStatus      = 0xC00A0002
	STATUS_CTX_PD_NOT_FOUND                                                   NTStatus      = 0xC00A0003
	STATUS_CTX_CDM_CONNECT                                                    NTStatus      = 0x400A0004
	STATUS_CTX_CDM_DISCONNECT                                                 NTStatus      = 0x400A0005
	STATUS_CTX_CLOSE_PENDING                                                  NTStatus      = 0xC00A0006
	STATUS_CTX_NO_OUTBUF                                                      NTStatus      = 0xC00A0007
	STATUS_CTX_MODEM_INF_NOT_FOUND                                            NTStatus      = 0xC00A0008
	STATUS_CTX_INVALID_MODEMNAME                                              NTStatus      = 0xC00A0009
	STATUS_CTX_RESPONSE_ERROR                                                 NTStatus      = 0xC00A000A
	STATUS_CTX_MODEM_RESPONSE_TIMEOUT                                         NTStatus      = 0xC00A000B
	STATUS_CTX_MODEM_RESPONSE_NO_CARRIER                                      NTStatus      = 0xC00A000C
	STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE                                     NTStatus      = 0xC00A000D
	STATUS_CTX_MODEM_RESPONSE_BUSY                                            NTStatus      = 0xC00A000E
	STATUS_CTX_MODEM_RESPONSE_VOICE                                           NTStatus      = 0xC00A000F
	STATUS_CTX_TD_ERROR                                                       NTStatus      = 0xC00A0010
	STATUS_CTX_LICENSE_CLIENT_INVALID                                         NTStatus      = 0xC00A0012
	STATUS_CTX_LICENSE_NOT_AVAILABLE                                          NTStatus      = 0xC00A0013
	STATUS_CTX_LICENSE_EXPIRED                                                NTStatus      = 0xC00A0014
	STATUS_CTX_WINSTATION_NOT_FOUND                                           NTStatus      = 0xC00A0015
	STATUS_CTX_WINSTATION_NAME_COLLISION                                      NTStatus      = 0xC00A0016
	STATUS_CTX_WINSTATION_BUSY                                                NTStatus      = 0xC00A0017
	STATUS_CTX_BAD_VIDEO_MODE                                                 NTStatus      = 0xC00A0018
	STATUS_CTX_GRAPHICS_INVALID                                               NTStatus      = 0xC00A0022
	STATUS_CTX_NOT_CONSOLE                                                    NTStatus      = 0xC00A0024
	STATUS_CTX_CLIENT_QUERY_TIMEOUT                                           NTStatus      = 0xC00A0026
	STATUS_CTX_CONSOLE_DISCONNECT                                             NTStatus      = 0xC00A0027
	STATUS_CTX_CONSOLE_CONNECT                                                NTStatus      = 0xC00A0028
	STATUS_CTX_SHADOW_DENIED                                                  NTStatus      = 0xC00A002A
	STATUS_CTX_WINSTATION_ACCESS_DENIED                                       NTStatus      = 0xC00A002B
	STATUS_CTX_INVALID_WD                                                     NTStatus      = 0xC00A002E
	STATUS_CTX_WD_NOT_FOUND                                                   NTStatus      = 0xC00A002F
	STATUS_CTX_SHADOW_INVALID                                                 NTStatus      = 0xC00A0030
	STATUS_CTX_SHADOW_DISABLED                                                NTStatus      = 0xC00A0031
	STATUS_RDP_PROTOCOL_ERROR                                                 NTStatus      = 0xC00A0032
	STATUS_CTX_CLIENT_LICENSE_NOT_SET                                         NTStatus      = 0xC00A0033
	STATUS_CTX_CLIENT_LICENSE_IN_USE                                          NTStatus      = 0xC00A0034
	STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE                                    NTStatus      = 0xC00A0035
	STATUS_CTX_SHADOW_NOT_RUNNING                                             NTStatus      = 0xC00A0036
	STATUS_CTX_LOGON_DISABLED                                                 NTStatus      = 0xC00A0037
	STATUS_CTX_SECURITY_LAYER_ERROR                                           NTStatus      = 0xC00A0038
	STATUS_TS_INCOMPATIBLE_SESSIONS                                           NTStatus      = 0xC00A0039
	STATUS_TS_VIDEO_SUBSYSTEM_ERROR                                           NTStatus      = 0xC00A003A
	STATUS_PNP_BAD_MPS_TABLE                                                  NTStatus      = 0xC0040035
	STATUS_PNP_TRANSLATION_FAILED                                             NTStatus      = 0xC0040036
	STATUS_PNP_IRQ_TRANSLATION_FAILED                                         NTStatus      = 0xC0040037
	STATUS_PNP_INVALID_ID                                                     NTStatus      = 0xC0040038
	STATUS_IO_REISSUE_AS_CACHED                                               NTStatus      = 0xC0040039
	STATUS_MUI_FILE_NOT_FOUND                                                 NTStatus      = 0xC00B0001
	STATUS_MUI_INVALID_FILE                                                   NTStatus      = 0xC00B0002
	STATUS_MUI_INVALID_RC_CONFIG                                              NTStatus      = 0xC00B0003
	STATUS_MUI_INVALID_LOCALE_NAME                                            NTStatus      = 0xC00B0004
	STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME                                  NTStatus      = 0xC00B0005
	STATUS_MUI_FILE_NOT_LOADED                                                NTStatus      = 0xC00B0006
	STATUS_RESOURCE_ENUM_USER_STOP                                            NTStatus      = 0xC00B0007
	STATUS_FLT_NO_HANDLER_DEFINED                                             NTStatus      = 0xC01C0001
	STATUS_FLT_CONTEXT_ALREADY_DEFINED                                        NTStatus      = 0xC01C0002
	STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST                                   NTStatus      = 0xC01C0003
	STATUS_FLT_DISALLOW_FAST_IO                                               NTStatus      = 0xC01C0004
	STATUS_FLT_INVALID_NAME_REQUEST                                           NTStatus      = 0xC01C0005
	STATUS_FLT_NOT_SAFE_TO_POST_OPERATION                                     NTStatus      = 0xC01C0006
	STATUS_FLT_NOT_INITIALIZED                                                NTStatus      = 0xC01C0007
	STATUS_FLT_FILTER_NOT_READY                                               NTStatus      = 0xC01C0008
	STATUS_FLT_POST_OPERATION_CLEANUP                                         NTStatus      = 0xC01C0009
	STATUS_FLT_INTERNAL_ERROR                                                 NTStatus      = 0xC01C000A
	STATUS_FLT_DELETING_OBJECT                                                NTStatus      = 0xC01C000B
	STATUS_FLT_MUST_BE_NONPAGED_POOL                                          NTStatus      = 0xC01C000C
	STATUS_FLT_DUPLICATE_ENTRY                                                NTStatus      = 0xC01C000D
	STATUS_FLT_CBDQ_DISABLED                                                  NTStatus      = 0xC01C000E
	STATUS_FLT_DO_NOT_ATTACH                                                  NTStatus      = 0xC01C000F
	STATUS_FLT_DO_NOT_DETACH                                                  NTStatus      = 0xC01C0010
	STATUS_FLT_INSTANCE_ALTITUDE_COLLISION                                    NTStatus      = 0xC01C0011
	STATUS_FLT_INSTANCE_NAME_COLLISION                                        NTStatus      = 0xC01C0012
	STATUS_FLT_FILTER_NOT_FOUND                                               NTStatus      = 0xC01C0013
	STATUS_FLT_VOLUME_NOT_FOUND                                               NTStatus      = 0xC01C0014
	STATUS_FLT_INSTANCE_NOT_FOUND                                             NTStatus      = 0xC01C0015
	STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND                                   NTStatus      = 0xC01C0016
	STATUS_FLT_INVALID_CONTEXT_REGISTRATION                                   NTStatus      = 0xC01C0017
	STATUS_FLT_NAME_CACHE_MISS                                                NTStatus      = 0xC01C0018
	STATUS_FLT_NO_DEVICE_OBJECT                                               NTStatus      = 0xC01C0019
	STATUS_FLT_VOLUME_ALREADY_MOUNTED                                         NTStatus      = 0xC01C001A
	STATUS_FLT_ALREADY_ENLISTED                                               NTStatus      = 0xC01C001B
	STATUS_FLT_CONTEXT_ALREADY_LINKED                                         NTStatus      = 0xC01C001C
	STATUS_FLT_NO_WAITER_FOR_REPLY                                            NTStatus      = 0xC01C0020
	STATUS_FLT_REGISTRATION_BUSY                                              NTStatus      = 0xC01C0023
	STATUS_SXS_SECTION_NOT_FOUND                                              NTStatus      = 0xC0150001
	STATUS_SXS_CANT_GEN_ACTCTX                                                NTStatus      = 0xC0150002
	STATUS_SXS_INVALID_ACTCTXDATA_FORMAT                                      NTStatus      = 0xC0150003
	STATUS_SXS_ASSEMBLY_NOT_FOUND                                             NTStatus      = 0xC0150004
	STATUS_SXS_MANIFEST_FORMAT_ERROR                                          NTStatus      = 0xC0150005
	STATUS_SXS_MANIFEST_PARSE_ERROR                                           NTStatus      = 0xC0150006
	STATUS_SXS_ACTIVATION_CONTEXT_DISABLED                                    NTStatus      = 0xC0150007
	STATUS_SXS_KEY_NOT_FOUND                                                  NTStatus      = 0xC0150008
	STATUS_SXS_VERSION_CONFLICT                                               NTStatus      = 0xC0150009
	STATUS_SXS_WRONG_SECTION_TYPE                                             NTStatus      = 0xC015000A
	STATUS_SXS_THREAD_QUERIES_DISABLED                                        NTStatus      = 0xC015000B
	STATUS_SXS_ASSEMBLY_MISSING                                               NTStatus      = 0xC015000C
	STATUS_SXS_RELEASE_ACTIVATION_CONTEXT                                     NTStatus      = 0x4015000D
	STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET                                    NTStatus      = 0xC015000E
	STATUS_SXS_EARLY_DEACTIVATION                                             NTStatus      = 0xC015000F
	STATUS_SXS_INVALID_DEACTIVATION                                           NTStatus      = 0xC0150010
	STATUS_SXS_MULTIPLE_DEACTIVATION                                          NTStatus      = 0xC0150011
	STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY                        NTStatus      = 0xC0150012
	STATUS_SXS_PROCESS_TERMINATION_REQUESTED                                  NTStatus      = 0xC0150013
	STATUS_SXS_CORRUPT_ACTIVATION_STACK                                       NTStatus      = 0xC0150014
	STATUS_SXS_CORRUPTION                                                     NTStatus      = 0xC0150015
	STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE                               NTStatus      = 0xC0150016
	STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME                                NTStatus      = 0xC0150017
	STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE                                   NTStatus      = 0xC0150018
	STATUS_SXS_IDENTITY_PARSE_ERROR                                           NTStatus      = 0xC0150019
	STATUS_SXS_COMPONENT_STORE_CORRUPT                                        NTStatus      = 0xC015001A
	STATUS_SXS_FILE_HASH_MISMATCH                                             NTStatus      = 0xC015001B
	STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT                  NTStatus      = 0xC015001C
	STATUS_SXS_IDENTITIES_DIFFERENT                                           NTStatus      = 0xC015001D
	STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT                                   NTStatus      = 0xC015001E
	STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY                                      NTStatus      = 0xC015001F
	STATUS_ADVANCED_INSTALLER_FAILED                                          NTStatus      = 0xC0150020
	STATUS_XML_ENCODING_MISMATCH                                              NTStatus      = 0xC0150021
	STATUS_SXS_MANIFEST_TOO_BIG                                               NTStatus      = 0xC0150022
	STATUS_SXS_SETTING_NOT_REGISTERED                                         NTStatus      = 0xC0150023
	STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE                                 NTStatus      = 0xC0150024
	STATUS_SMI_PRIMITIVE_INSTALLER_FAILED                                     NTStatus      = 0xC0150025
	STATUS_GENERIC_COMMAND_FAILED                                             NTStatus      = 0xC0150026
	STATUS_SXS_FILE_HASH_MISSING                                              NTStatus      = 0xC0150027
	STATUS_CLUSTER_INVALID_NODE                                               NTStatus      = 0xC0130001
	STATUS_CLUSTER_NODE_EXISTS                                                NTStatus      = 0xC0130002
	STATUS_CLUSTER_JOIN_IN_PROGRESS                                           NTStatus      = 0xC0130003
	STATUS_CLUSTER_NODE_NOT_FOUND                                             NTStatus      = 0xC0130004
	STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND                                       NTStatus      = 0xC0130005
	STATUS_CLUSTER_NETWORK_EXISTS                                             NTStatus      = 0xC0130006
	STATUS_CLUSTER_NETWORK_NOT_FOUND                                          NTStatus      = 0xC0130007
	STATUS_CLUSTER_NETINTERFACE_EXISTS                                        NTStatus      = 0xC0130008
	STATUS_CLUSTER_NETINTERFACE_NOT_FOUND                                     NTStatus      = 0xC0130009
	STATUS_CLUSTER_INVALID_REQUEST                                            NTStatus      = 0xC013000A
	STATUS_CLUSTER_INVALID_NETWORK_PROVIDER                                   NTStatus      = 0xC013000B
	STATUS_CLUSTER_NODE_DOWN                                                  NTStatus      = 0xC013000C
	STATUS_CLUSTER_NODE_UNREACHABLE                                           NTStatus      = 0xC013000D
	STATUS_CLUSTER_NODE_NOT_MEMBER                                            NTStatus      = 0xC013000E
	STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS                                       NTStatus      = 0xC013000F
	STATUS_CLUSTER_INVALID_NETWORK                                            NTStatus      = 0xC0130010
	STATUS_CLUSTER_NO_NET_ADAPTERS                                            NTStatus      = 0xC0130011
	STATUS_CLUSTER_NODE_UP                                                    NTStatus      = 0xC0130012
	STATUS_CLUSTER_NODE_PAUSED                                                NTStatus      = 0xC0130013
	STATUS_CLUSTER_NODE_NOT_PAUSED                                            NTStatus      = 0xC0130014
	STATUS_CLUSTER_NO_SECURITY_CONTEXT                                        NTStatus      = 0xC0130015
	STATUS_CLUSTER_NETWORK_NOT_INTERNAL                                       NTStatus      = 0xC0130016
	STATUS_CLUSTER_POISONED                                                   NTStatus      = 0xC0130017
	STATUS_CLUSTER_NON_CSV_PATH                                               NTStatus      = 0xC0130018
	STATUS_CLUSTER_CSV_VOLUME_NOT_LOCAL                                       NTStatus      = 0xC0130019
	STATUS_CLUSTER_CSV_READ_OPLOCK_BREAK_IN_PROGRESS                          NTStatus      = 0xC0130020
	STATUS_CLUSTER_CSV_AUTO_PAUSE_ERROR                                       NTStatus      = 0xC0130021
	STATUS_CLUSTER_CSV_REDIRECTED                                             NTStatus      = 0xC0130022
	STATUS_CLUSTER_CSV_NOT_REDIRECTED                                         NTStatus      = 0xC0130023
	STATUS_CLUSTER_CSV_VOLUME_DRAINING                                        NTStatus      = 0xC0130024
	STATUS_CLUSTER_CSV_SNAPSHOT_CREATION_IN_PROGRESS                          NTStatus      = 0xC0130025
	STATUS_CLUSTER_CSV_VOLUME_DRAINING_SUCCEEDED_DOWNLEVEL                    NTStatus      = 0xC0130026
	STATUS_CLUSTER_CSV_NO_SNAPSHOTS                                           NTStatus      = 0xC0130027
	STATUS_CSV_IO_PAUSE_TIMEOUT                                               NTStatus      = 0xC0130028
	STATUS_CLUSTER_CSV_INVALID_HANDLE                                         NTStatus      = 0xC0130029
	STATUS_CLUSTER_CSV_SUPPORTED_ONLY_ON_COORDINATOR                          NTStatus      = 0xC0130030
	STATUS_CLUSTER_CAM_TICKET_REPLAY_DETECTED                                 NTStatus      = 0xC0130031
	STATUS_TRANSACTIONAL_CONFLICT                                             NTStatus      = 0xC0190001
	STATUS_INVALID_TRANSACTION                                                NTStatus      = 0xC0190002
	STATUS_TRANSACTION_NOT_ACTIVE                                             NTStatus      = 0xC0190003
	STATUS_TM_INITIALIZATION_FAILED                                           NTStatus      = 0xC0190004
	STATUS_RM_NOT_ACTIVE                                                      NTStatus      = 0xC0190005
	STATUS_RM_METADATA_CORRUPT                                                NTStatus      = 0xC0190006
	STATUS_TRANSACTION_NOT_JOINED                                             NTStatus      = 0xC0190007
	STATUS_DIRECTORY_NOT_RM                                                   NTStatus      = 0xC0190008
	STATUS_COULD_NOT_RESIZE_LOG                                               NTStatus      = 0x80190009
	STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE                                    NTStatus      = 0xC019000A
	STATUS_LOG_RESIZE_INVALID_SIZE                                            NTStatus      = 0xC019000B
	STATUS_REMOTE_FILE_VERSION_MISMATCH                                       NTStatus      = 0xC019000C
	STATUS_CRM_PROTOCOL_ALREADY_EXISTS                                        NTStatus      = 0xC019000F
	STATUS_TRANSACTION_PROPAGATION_FAILED                                     NTStatus      = 0xC0190010
	STATUS_CRM_PROTOCOL_NOT_FOUND                                             NTStatus      = 0xC0190011
	STATUS_TRANSACTION_SUPERIOR_EXISTS                                        NTStatus      = 0xC0190012
	STATUS_TRANSACTION_REQUEST_NOT_VALID                                      NTStatus      = 0xC0190013
	STATUS_TRANSACTION_NOT_REQUESTED                                          NTStatus      = 0xC0190014
	STATUS_TRANSACTION_ALREADY_ABORTED                                        NTStatus      = 0xC0190015
	STATUS_TRANSACTION_ALREADY_COMMITTED                                      NTStatus      = 0xC0190016
	STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER                                NTStatus      = 0xC0190017
	STATUS_CURRENT_TRANSACTION_NOT_VALID                                      NTStatus      = 0xC0190018
	STATUS_LOG_GROWTH_FAILED                                                  NTStatus      = 0xC0190019
	STATUS_OBJECT_NO_LONGER_EXISTS                                            NTStatus      = 0xC0190021
	STATUS_STREAM_MINIVERSION_NOT_FOUND                                       NTStatus      = 0xC0190022
	STATUS_STREAM_MINIVERSION_NOT_VALID                                       NTStatus      = 0xC0190023
	STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION                NTStatus      = 0xC0190024
	STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT                           NTStatus      = 0xC0190025
	STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS                               NTStatus      = 0xC0190026
	STATUS_HANDLE_NO_LONGER_VALID                                             NTStatus      = 0xC0190028
	STATUS_NO_TXF_METADATA                                                    NTStatus      = 0x80190029
	STATUS_LOG_CORRUPTION_DETECTED                                            NTStatus      = 0xC0190030
	STATUS_CANT_RECOVER_WITH_HANDLE_OPEN                                      NTStatus      = 0x80190031
	STATUS_RM_DISCONNECTED                                                    NTStatus      = 0xC0190032
	STATUS_ENLISTMENT_NOT_SUPERIOR                                            NTStatus      = 0xC0190033
	STATUS_RECOVERY_NOT_NEEDED                                                NTStatus      = 0x40190034
	STATUS_RM_ALREADY_STARTED                                                 NTStatus      = 0x40190035
	STATUS_FILE_IDENTITY_NOT_PERSISTENT                                       NTStatus      = 0xC0190036
	STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY                                NTStatus      = 0xC0190037
	STATUS_CANT_CROSS_RM_BOUNDARY                                             NTStatus      = 0xC0190038
	STATUS_TXF_DIR_NOT_EMPTY                                                  NTStatus      = 0xC0190039
	STATUS_INDOUBT_TRANSACTIONS_EXIST                                         NTStatus      = 0xC019003A
	STATUS_TM_VOLATILE                                                        NTStatus      = 0xC019003B
	STATUS_ROLLBACK_TIMER_EXPIRED                                             NTStatus      = 0xC019003C
	STATUS_TXF_ATTRIBUTE_CORRUPT                                              NTStatus      = 0xC019003D
	STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION                                     NTStatus      = 0xC019003E
	STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED                                     NTStatus      = 0xC019003F
	STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE                              NTStatus      = 0xC0190040
	STATUS_TXF_METADATA_ALREADY_PRESENT                                       NTStatus      = 0x80190041
	STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET                                NTStatus      = 0x80190042
	STATUS_TRANSACTION_REQUIRED_PROMOTION                                     NTStatus      = 0xC0190043
	STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION                                 NTStatus      = 0xC0190044
	STATUS_TRANSACTIONS_NOT_FROZEN                                            NTStatus      = 0xC0190045
	STATUS_TRANSACTION_FREEZE_IN_PROGRESS                                     NTStatus      = 0xC0190046
	STATUS_NOT_SNAPSHOT_VOLUME                                                NTStatus      = 0xC0190047
	STATUS_NO_SAVEPOINT_WITH_OPEN_FILES                                       NTStatus      = 0xC0190048
	STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION                                  NTStatus      = 0xC0190049
	STATUS_TM_IDENTITY_MISMATCH                                               NTStatus      = 0xC019004A
	STATUS_FLOATED_SECTION                                                    NTStatus      = 0xC019004B
	STATUS_CANNOT_ACCEPT_TRANSACTED_WORK                                      NTStatus      = 0xC019004C
	STATUS_CANNOT_ABORT_TRANSACTIONS                                          NTStatus      = 0xC019004D
	STATUS_TRANSACTION_NOT_FOUND                                              NTStatus      = 0xC019004E
	STATUS_RESOURCEMANAGER_NOT_FOUND                                          NTStatus      = 0xC019004F
	STATUS_ENLISTMENT_NOT_FOUND                                               NTStatus      = 0xC0190050
	STATUS_TRANSACTIONMANAGER_NOT_FOUND                                       NTStatus      = 0xC0190051
	STATUS_TRANSACTIONMANAGER_NOT_ONLINE                                      NTStatus      = 0xC0190052
	STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION                         NTStatus      = 0xC0190053
	STATUS_TRANSACTION_NOT_ROOT                                               NTStatus      = 0xC0190054
	STATUS_TRANSACTION_OBJECT_EXPIRED                                         NTStatus      = 0xC0190055
	STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION                             NTStatus      = 0xC0190056
	STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED                                  NTStatus      = 0xC0190057
	STATUS_TRANSACTION_RECORD_TOO_LONG                                        NTStatus      = 0xC0190058
	STATUS_NO_LINK_TRACKING_IN_TRANSACTION                                    NTStatus      = 0xC0190059
	STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION                             NTStatus      = 0xC019005A
	STATUS_TRANSACTION_INTEGRITY_VIOLATED                                     NTStatus      = 0xC019005B
	STATUS_TRANSACTIONMANAGER_IDENTITY_MISMATCH                               NTStatus      = 0xC019005C
	STATUS_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT                                   NTStatus      = 0xC019005D
	STATUS_TRANSACTION_MUST_WRITETHROUGH                                      NTStatus      = 0xC019005E
	STATUS_TRANSACTION_NO_SUPERIOR                                            NTStatus      = 0xC019005F
	STATUS_EXPIRED_HANDLE                                                     NTStatus      = 0xC0190060
	STATUS_TRANSACTION_NOT_ENLISTED                                           NTStatus      = 0xC0190061
	STATUS_LOG_SECTOR_INVALID                                                 NTStatus      = 0xC01A0001
	STATUS_LOG_SECTOR_PARITY_INVALID                                          NTStatus      = 0xC01A0002
	STATUS_LOG_SECTOR_REMAPPED                                                NTStatus      = 0xC01A0003
	STATUS_LOG_BLOCK_INCOMPLETE                                               NTStatus      = 0xC01A0004
	STATUS_LOG_INVALID_RANGE                                                  NTStatus      = 0xC01A0005
	STATUS_LOG_BLOCKS_EXHAUSTED                                               NTStatus      = 0xC01A0006
	STATUS_LOG_READ_CONTEXT_INVALID                                           NTStatus      = 0xC01A0007
	STATUS_LOG_RESTART_INVALID                                                NTStatus      = 0xC01A0008
	STATUS_LOG_BLOCK_VERSION                                                  NTStatus      = 0xC01A0009
	STATUS_LOG_BLOCK_INVALID                                                  NTStatus      = 0xC01A000A
	STATUS_LOG_READ_MODE_INVALID                                              NTStatus      = 0xC01A000B
	STATUS_LOG_NO_RESTART                                                     NTStatus      = 0x401A000C
	STATUS_LOG_METADATA_CORRUPT                                               NTStatus      = 0xC01A000D
	STATUS_LOG_METADATA_INVALID                                               NTStatus      = 0xC01A000E
	STATUS_LOG_METADATA_INCONSISTENT                                          NTStatus      = 0xC01A000F
	STATUS_LOG_RESERVATION_INVALID                                            NTStatus      = 0xC01A0010
	STATUS_LOG_CANT_DELETE                                                    NTStatus      = 0xC01A0011
	STATUS_LOG_CONTAINER_LIMIT_EXCEEDED                                       NTStatus      = 0xC01A0012
	STATUS_LOG_START_OF_LOG                                                   NTStatus      = 0xC01A0013
	STATUS_LOG_POLICY_ALREADY_INSTALLED                                       NTStatus      = 0xC01A0014
	STATUS_LOG_POLICY_NOT_INSTALLED                                           NTStatus      = 0xC01A0015
	STATUS_LOG_POLICY_INVALID                                                 NTStatus      = 0xC01A0016
	STATUS_LOG_POLICY_CONFLICT                                                NTStatus      = 0xC01A0017
	STATUS_LOG_PINNED_ARCHIVE_TAIL                                            NTStatus      = 0xC01A0018
	STATUS_LOG_RECORD_NONEXISTENT                                             NTStatus      = 0xC01A0019
	STATUS_LOG_RECORDS_RESERVED_INVALID                                       NTStatus      = 0xC01A001A
	STATUS_LOG_SPACE_RESERVED_INVALID                                         NTStatus      = 0xC01A001B
	STATUS_LOG_TAIL_INVALID                                                   NTStatus      = 0xC01A001C
	STATUS_LOG_FULL                                                           NTStatus      = 0xC01A001D
	STATUS_LOG_MULTIPLEXED                                                    NTStatus      = 0xC01A001E
	STATUS_LOG_DEDICATED                                                      NTStatus      = 0xC01A001F
	STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS                                        NTStatus      = 0xC01A0020
	STATUS_LOG_ARCHIVE_IN_PROGRESS                                            NTStatus      = 0xC01A0021
	STATUS_LOG_EPHEMERAL                                                      NTStatus      = 0xC01A0022
	STATUS_LOG_NOT_ENOUGH_CONTAINERS                                          NTStatus      = 0xC01A0023
	STATUS_LOG_CLIENT_ALREADY_REGISTERED                                      NTStatus      = 0xC01A0024
	STATUS_LOG_CLIENT_NOT_REGISTERED                                          NTStatus      = 0xC01A0025
	STATUS_LOG_FULL_HANDLER_IN_PROGRESS                                       NTStatus      = 0xC01A0026
	STATUS_LOG_CONTAINER_READ_FAILED                                          NTStatus      = 0xC01A0027
	STATUS_LOG_CONTAINER_WRITE_FAILED                                         NTStatus      = 0xC01A0028
	STATUS_LOG_CONTAINER_OPEN_FAILED                                          NTStatus      = 0xC01A0029
	STATUS_LOG_CONTAINER_STATE_INVALID                                        NTStatus      = 0xC01A002A
	STATUS_LOG_STATE_INVALID                                                  NTStatus      = 0xC01A002B
	STATUS_LOG_PINNED                                                         NTStatus      = 0xC01A002C
	STATUS_LOG_METADATA_FLUSH_FAILED                                          NTStatus      = 0xC01A002D
	STATUS_LOG_INCONSISTENT_SECURITY                                          NTStatus      = 0xC01A002E
	STATUS_LOG_APPENDED_FLUSH_FAILED                                          NTStatus      = 0xC01A002F
	STATUS_LOG_PINNED_RESERVATION                                             NTStatus      = 0xC01A0030
	STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD                                   NTStatus      = 0xC01B00EA
	STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED                         NTStatus      = 0x801B00EB
	STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST                                  NTStatus      = 0x401B00EC
	STATUS_MONITOR_NO_DESCRIPTOR                                              NTStatus      = 0xC01D0001
	STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT                                  NTStatus      = 0xC01D0002
	STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM                                NTStatus      = 0xC01D0003
	STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK                              NTStatus      = 0xC01D0004
	STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED                          NTStatus      = 0xC01D0005
	STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK                         NTStatus      = 0xC01D0006
	STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK                         NTStatus      = 0xC01D0007
	STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA                                    NTStatus      = 0xC01D0008
	STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK                              NTStatus      = 0xC01D0009
	STATUS_MONITOR_INVALID_MANUFACTURE_DATE                                   NTStatus      = 0xC01D000A
	STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER                                  NTStatus      = 0xC01E0000
	STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER                                   NTStatus      = 0xC01E0001
	STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER                                   NTStatus      = 0xC01E0002
	STATUS_GRAPHICS_ADAPTER_WAS_RESET                                         NTStatus      = 0xC01E0003
	STATUS_GRAPHICS_INVALID_DRIVER_MODEL                                      NTStatus      = 0xC01E0004
	STATUS_GRAPHICS_PRESENT_MODE_CHANGED                                      NTStatus      = 0xC01E0005
	STATUS_GRAPHICS_PRESENT_OCCLUDED                                          NTStatus      = 0xC01E0006
	STATUS_GRAPHICS_PRESENT_DENIED                                            NTStatus      = 0xC01E0007
	STATUS_GRAPHICS_CANNOTCOLORCONVERT                                        NTStatus      = 0xC01E0008
	STATUS_GRAPHICS_DRIVER_MISMATCH                                           NTStatus      = 0xC01E0009
	STATUS_GRAPHICS_PARTIAL_DATA_POPULATED                                    NTStatus      = 0x401E000A
	STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED                              NTStatus      = 0xC01E000B
	STATUS_GRAPHICS_PRESENT_UNOCCLUDED                                        NTStatus      = 0xC01E000C
	STATUS_GRAPHICS_WINDOWDC_NOT_AVAILABLE                                    NTStatus      = 0xC01E000D
	STATUS_GRAPHICS_WINDOWLESS_PRESENT_DISABLED                               NTStatus      = 0xC01E000E
	STATUS_GRAPHICS_PRESENT_INVALID_WINDOW                                    NTStatus      = 0xC01E000F
	STATUS_GRAPHICS_PRESENT_BUFFER_NOT_BOUND                                  NTStatus      = 0xC01E0010
	STATUS_GRAPHICS_VAIL_STATE_CHANGED                                        NTStatus      = 0xC01E0011
	STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN                        NTStatus      = 0xC01E0012
	STATUS_GRAPHICS_INDIRECT_DISPLAY_DEVICE_STOPPED                           NTStatus      = 0xC01E0013
	STATUS_GRAPHICS_NO_VIDEO_MEMORY                                           NTStatus      = 0xC01E0100
	STATUS_GRAPHICS_CANT_LOCK_MEMORY                                          NTStatus      = 0xC01E0101
	STATUS_GRAPHICS_ALLOCATION_BUSY                                           NTStatus      = 0xC01E0102
	STATUS_GRAPHICS_TOO_MANY_REFERENCES                                       NTStatus      = 0xC01E0103
	STATUS_GRAPHICS_TRY_AGAIN_LATER                                           NTStatus      = 0xC01E0104
	STATUS_GRAPHICS_TRY_AGAIN_NOW                                             NTStatus      = 0xC01E0105
	STATUS_GRAPHICS_ALLOCATION_INVALID                                        NTStatus      = 0xC01E0106
	STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE                          NTStatus      = 0xC01E0107
	STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED                          NTStatus      = 0xC01E0108
	STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION                              NTStatus      = 0xC01E0109
	STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE                                  NTStatus      = 0xC01E0110
	STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION                             NTStatus      = 0xC01E0111
	STATUS_GRAPHICS_ALLOCATION_CLOSED                                         NTStatus      = 0xC01E0112
	STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE                               NTStatus      = 0xC01E0113
	STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE                                 NTStatus      = 0xC01E0114
	STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE                                   NTStatus      = 0xC01E0115
	STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST                                   NTStatus      = 0xC01E0116
	STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE                                   NTStatus      = 0xC01E0200
	STATUS_GRAPHICS_SKIP_ALLOCATION_PREPARATION                               NTStatus      = 0x401E0201
	STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY                                    NTStatus      = 0xC01E0300
	STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED                              NTStatus      = 0xC01E0301
	STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED                    NTStatus      = 0xC01E0302
	STATUS_GRAPHICS_INVALID_VIDPN                                             NTStatus      = 0xC01E0303
	STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE                              NTStatus      = 0xC01E0304
	STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET                              NTStatus      = 0xC01E0305
	STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED                              NTStatus      = 0xC01E0306
	STATUS_GRAPHICS_MODE_NOT_PINNED                                           NTStatus      = 0x401E0307
	STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET                               NTStatus      = 0xC01E0308
	STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET                               NTStatus      = 0xC01E0309
	STATUS_GRAPHICS_INVALID_FREQUENCY                                         NTStatus      = 0xC01E030A
	STATUS_GRAPHICS_INVALID_ACTIVE_REGION                                     NTStatus      = 0xC01E030B
	STATUS_GRAPHICS_INVALID_TOTAL_REGION                                      NTStatus      = 0xC01E030C
	STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE                         NTStatus      = 0xC01E0310
	STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE                         NTStatus      = 0xC01E0311
	STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET                            NTStatus      = 0xC01E0312
	STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY                                  NTStatus      = 0xC01E0313
	STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET                                   NTStatus      = 0xC01E0314
	STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET                             NTStatus      = 0xC01E0315
	STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET                             NTStatus      = 0xC01E0316
	STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET                                     NTStatus      = 0xC01E0317
	STATUS_GRAPHICS_TARGET_ALREADY_IN_SET                                     NTStatus      = 0xC01E0318
	STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH                                NTStatus      = 0xC01E0319
	STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY                             NTStatus      = 0xC01E031A
	STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET                         NTStatus      = 0xC01E031B
	STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE                            NTStatus      = 0xC01E031C
	STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET                                 NTStatus      = 0xC01E031D
	STATUS_GRAPHICS_NO_PREFERRED_MODE                                         NTStatus      = 0x401E031E
	S
"""




```