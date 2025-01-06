Response:
The user has provided a snippet of Go code from `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go`. This file appears to define a large number of Windows error codes as constants of type `syscall.Errno`.

The request asks for the following:
1. **Functionality:** Describe what this code does.
2. **Go Feature:** Identify the Go language feature being used and provide a code example.
3. **Code Reasoning:** If code reasoning is involved, provide assumptions, inputs, and outputs.
4. **Command-line Arguments:** Detail any command-line argument processing.
5. **Common Mistakes:**  Point out potential user errors.
6. **Summary:**  Summarize the functionality of this part of the file.

**Thinking Process:**

1. **Analyze the code:** The code consists of a series of constant declarations. Each constant is assigned a specific integer value and is of type `syscall.Errno`. The constant names follow a pattern, often starting with `ERROR_` or `RPC_S_`. These names strongly suggest they represent Windows error codes.

2. **Identify the Go feature:** The code uses constant declarations (`const`). The type `syscall.Errno` is likely an alias for `int32` or `int` and is part of the `syscall` package, which provides low-level operating system primitives.

3. **Determine the functionality:** The primary function of this code is to define a set of named constants that correspond to specific Windows error codes. This allows Go programs to refer to these errors symbolically instead of using raw numerical values. This improves code readability and maintainability.

4. **Provide a Go code example:**  Demonstrate how these constants can be used in Go code. A typical scenario would involve checking the error returned by a syscall.

5. **Address code reasoning, command-line arguments, and common mistakes:**
    * **Code Reasoning:**  The code is a direct mapping of error codes to constants. There's no complex logic to reason about.
    * **Command-line Arguments:** This code doesn't process any command-line arguments. It's a static data definition.
    * **Common Mistakes:**  Users might mistakenly use the integer value directly instead of the named constant, which reduces readability. They might also try to modify these constants, which is not possible.

6. **Summarize the functionality:**  Provide a concise summary of the code's purpose.

**Constraint Checklist:**

* [x] 列举一下它的功能
* [x] 推理出它是什么go语言功能的实现
* [x] 用go代码举例说明
* [x] 涉及代码推理，需要带上假设的输入与输出
* [x] 涉及命令行参数的具体处理，请详细介绍一下
* [x] 哪些使用者易犯错的点，请举例说明
* [x] 这是第3部分，共15部分，请归纳一下它的功能

**Response Generation:**  Based on the analysis, construct the response with the requested information.
这段Go语言代码的主要功能是**定义了一系列与Windows操作系统相关的错误码常量**。

具体来说，它使用了Go语言的 `const` 关键字来声明常量，并将这些常量赋值为 `syscall.Errno` 类型。 `syscall.Errno` 是 Go 语言 `syscall` 包中定义的一个类型，通常是 `int` 或 `int32` 的别名，用来表示操作系统级别的错误码。

每个常量名都对应一个特定的Windows错误码，例如 `ERROR_INVALID_PRINTER_STATE` 对应错误码 `1906`。 通过这种方式，Go 开发者可以使用有意义的常量名来代替难以记忆的数字，从而提高代码的可读性和可维护性。

**它是什么go语言功能的实现：定义常量**

这段代码的核心是使用了 Go 语言的 **常量定义 (Constant Declaration)** 功能。  常量在编译时就被确定下来，运行时无法修改。这对于表示操作系统错误码这种固定不变的值非常合适。

**Go代码举例说明:**

假设我们调用了一个可能失败的 Windows API，并希望根据返回的错误码进行处理。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	// 引入包含错误码定义的包
	_ "cmd/vendor/golang.org/x/sys/windows"
)

func main() {
	// 假设我们调用了 CreateFileW 并得到了一个错误
	// 这里我们模拟一个 ERROR_FILE_NOT_FOUND 的错误
	err := syscall.Errno(2) // ERROR_FILE_NOT_FOUND 的错误码

	if err == syscall.ERROR_FILE_NOT_FOUND {
		fmt.Println("文件未找到")
	} else if err == syscall.ERROR_ACCESS_DENIED {
		fmt.Println("访问被拒绝")
	} else {
		fmt.Printf("发生其他错误: %d\n", err)
	}
}
```

**假设的输入与输出:**

在上面的例子中，我们假设 `err` 的值为 `syscall.Errno(2)`，这对应于 `ERROR_FILE_NOT_FOUND`。

**输出:**

```
文件未找到
```

如果 `err` 的值是 `syscall.Errno(5)`，这对应于 `ERROR_ACCESS_DENIED`。

**输出:**

```
访问被拒绝
```

**命令行参数的具体处理:**

这段代码本身不涉及任何命令行参数的处理。它只是定义了一些常量。这些常量可以在其他 Go 代码中使用，而那些使用这些常量的代码可能会处理命令行参数。

**使用者易犯错的点:**

一个常见的错误是**直接使用数字错误码而不是使用定义的常量**。 例如：

```go
// 不推荐的做法
if err == 1906 {
  fmt.Println("打印机状态无效")
}

// 推荐的做法
if err == syscall.ERROR_INVALID_PRINTER_STATE {
  fmt.Println("打印机状态无效")
}
```

直接使用数字会降低代码的可读性，并且如果 Windows 的错误码发生变化，代码将变得难以维护。使用常量可以提高代码的清晰度和可维护性。

另一个潜在的错误是**误以为可以修改这些常量的值**。常量在 Go 语言中是不可变的。

**归纳一下它的功能 (作为第3部分，共15部分):**

作为 `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` 文件的一部分，并且是该文件的第3部分，这段代码延续了前几部分的功能，即 **定义了大量的Windows操作系统错误码常量**，并将其关联到 `syscall.Errno` 类型。  这为 Go 语言在 Windows 平台上进行系统调用和错误处理提供了必要的符号定义，使得开发者可以使用易于理解的常量名来代表特定的 Windows 错误，而不是直接使用数字。 考虑到这是一个共15部分的文件，可以推断出整个文件的目的是为了覆盖尽可能多的 Windows 错误码，以便 `golang.org/x/sys/windows` 包能够提供更全面的 Windows 系统调用支持。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共15部分，请归纳一下它的功能

"""
       syscall.Errno = 1905
	ERROR_INVALID_PRINTER_STATE                                               syscall.Errno = 1906
	ERROR_PASSWORD_MUST_CHANGE                                                syscall.Errno = 1907
	ERROR_DOMAIN_CONTROLLER_NOT_FOUND                                         syscall.Errno = 1908
	ERROR_ACCOUNT_LOCKED_OUT                                                  syscall.Errno = 1909
	OR_INVALID_OXID                                                           syscall.Errno = 1910
	OR_INVALID_OID                                                            syscall.Errno = 1911
	OR_INVALID_SET                                                            syscall.Errno = 1912
	RPC_S_SEND_INCOMPLETE                                                     syscall.Errno = 1913
	RPC_S_INVALID_ASYNC_HANDLE                                                syscall.Errno = 1914
	RPC_S_INVALID_ASYNC_CALL                                                  syscall.Errno = 1915
	RPC_X_PIPE_CLOSED                                                         syscall.Errno = 1916
	RPC_X_PIPE_DISCIPLINE_ERROR                                               syscall.Errno = 1917
	RPC_X_PIPE_EMPTY                                                          syscall.Errno = 1918
	ERROR_NO_SITENAME                                                         syscall.Errno = 1919
	ERROR_CANT_ACCESS_FILE                                                    syscall.Errno = 1920
	ERROR_CANT_RESOLVE_FILENAME                                               syscall.Errno = 1921
	RPC_S_ENTRY_TYPE_MISMATCH                                                 syscall.Errno = 1922
	RPC_S_NOT_ALL_OBJS_EXPORTED                                               syscall.Errno = 1923
	RPC_S_INTERFACE_NOT_EXPORTED                                              syscall.Errno = 1924
	RPC_S_PROFILE_NOT_ADDED                                                   syscall.Errno = 1925
	RPC_S_PRF_ELT_NOT_ADDED                                                   syscall.Errno = 1926
	RPC_S_PRF_ELT_NOT_REMOVED                                                 syscall.Errno = 1927
	RPC_S_GRP_ELT_NOT_ADDED                                                   syscall.Errno = 1928
	RPC_S_GRP_ELT_NOT_REMOVED                                                 syscall.Errno = 1929
	ERROR_KM_DRIVER_BLOCKED                                                   syscall.Errno = 1930
	ERROR_CONTEXT_EXPIRED                                                     syscall.Errno = 1931
	ERROR_PER_USER_TRUST_QUOTA_EXCEEDED                                       syscall.Errno = 1932
	ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED                                       syscall.Errno = 1933
	ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED                                    syscall.Errno = 1934
	ERROR_AUTHENTICATION_FIREWALL_FAILED                                      syscall.Errno = 1935
	ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED                                    syscall.Errno = 1936
	ERROR_NTLM_BLOCKED                                                        syscall.Errno = 1937
	ERROR_PASSWORD_CHANGE_REQUIRED                                            syscall.Errno = 1938
	ERROR_LOST_MODE_LOGON_RESTRICTION                                         syscall.Errno = 1939
	ERROR_INVALID_PIXEL_FORMAT                                                syscall.Errno = 2000
	ERROR_BAD_DRIVER                                                          syscall.Errno = 2001
	ERROR_INVALID_WINDOW_STYLE                                                syscall.Errno = 2002
	ERROR_METAFILE_NOT_SUPPORTED                                              syscall.Errno = 2003
	ERROR_TRANSFORM_NOT_SUPPORTED                                             syscall.Errno = 2004
	ERROR_CLIPPING_NOT_SUPPORTED                                              syscall.Errno = 2005
	ERROR_INVALID_CMM                                                         syscall.Errno = 2010
	ERROR_INVALID_PROFILE                                                     syscall.Errno = 2011
	ERROR_TAG_NOT_FOUND                                                       syscall.Errno = 2012
	ERROR_TAG_NOT_PRESENT                                                     syscall.Errno = 2013
	ERROR_DUPLICATE_TAG                                                       syscall.Errno = 2014
	ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE                                  syscall.Errno = 2015
	ERROR_PROFILE_NOT_FOUND                                                   syscall.Errno = 2016
	ERROR_INVALID_COLORSPACE                                                  syscall.Errno = 2017
	ERROR_ICM_NOT_ENABLED                                                     syscall.Errno = 2018
	ERROR_DELETING_ICM_XFORM                                                  syscall.Errno = 2019
	ERROR_INVALID_TRANSFORM                                                   syscall.Errno = 2020
	ERROR_COLORSPACE_MISMATCH                                                 syscall.Errno = 2021
	ERROR_INVALID_COLORINDEX                                                  syscall.Errno = 2022
	ERROR_PROFILE_DOES_NOT_MATCH_DEVICE                                       syscall.Errno = 2023
	ERROR_CONNECTED_OTHER_PASSWORD                                            syscall.Errno = 2108
	ERROR_CONNECTED_OTHER_PASSWORD_DEFAULT                                    syscall.Errno = 2109
	ERROR_BAD_USERNAME                                                        syscall.Errno = 2202
	ERROR_NOT_CONNECTED                                                       syscall.Errno = 2250
	ERROR_OPEN_FILES                                                          syscall.Errno = 2401
	ERROR_ACTIVE_CONNECTIONS                                                  syscall.Errno = 2402
	ERROR_DEVICE_IN_USE                                                       syscall.Errno = 2404
	ERROR_UNKNOWN_PRINT_MONITOR                                               syscall.Errno = 3000
	ERROR_PRINTER_DRIVER_IN_USE                                               syscall.Errno = 3001
	ERROR_SPOOL_FILE_NOT_FOUND                                                syscall.Errno = 3002
	ERROR_SPL_NO_STARTDOC                                                     syscall.Errno = 3003
	ERROR_SPL_NO_ADDJOB                                                       syscall.Errno = 3004
	ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED                                   syscall.Errno = 3005
	ERROR_PRINT_MONITOR_ALREADY_INSTALLED                                     syscall.Errno = 3006
	ERROR_INVALID_PRINT_MONITOR                                               syscall.Errno = 3007
	ERROR_PRINT_MONITOR_IN_USE                                                syscall.Errno = 3008
	ERROR_PRINTER_HAS_JOBS_QUEUED                                             syscall.Errno = 3009
	ERROR_SUCCESS_REBOOT_REQUIRED                                             syscall.Errno = 3010
	ERROR_SUCCESS_RESTART_REQUIRED                                            syscall.Errno = 3011
	ERROR_PRINTER_NOT_FOUND                                                   syscall.Errno = 3012
	ERROR_PRINTER_DRIVER_WARNED                                               syscall.Errno = 3013
	ERROR_PRINTER_DRIVER_BLOCKED                                              syscall.Errno = 3014
	ERROR_PRINTER_DRIVER_PACKAGE_IN_USE                                       syscall.Errno = 3015
	ERROR_CORE_DRIVER_PACKAGE_NOT_FOUND                                       syscall.Errno = 3016
	ERROR_FAIL_REBOOT_REQUIRED                                                syscall.Errno = 3017
	ERROR_FAIL_REBOOT_INITIATED                                               syscall.Errno = 3018
	ERROR_PRINTER_DRIVER_DOWNLOAD_NEEDED                                      syscall.Errno = 3019
	ERROR_PRINT_JOB_RESTART_REQUIRED                                          syscall.Errno = 3020
	ERROR_INVALID_PRINTER_DRIVER_MANIFEST                                     syscall.Errno = 3021
	ERROR_PRINTER_NOT_SHAREABLE                                               syscall.Errno = 3022
	ERROR_REQUEST_PAUSED                                                      syscall.Errno = 3050
	ERROR_APPEXEC_CONDITION_NOT_SATISFIED                                     syscall.Errno = 3060
	ERROR_APPEXEC_HANDLE_INVALIDATED                                          syscall.Errno = 3061
	ERROR_APPEXEC_INVALID_HOST_GENERATION                                     syscall.Errno = 3062
	ERROR_APPEXEC_UNEXPECTED_PROCESS_REGISTRATION                             syscall.Errno = 3063
	ERROR_APPEXEC_INVALID_HOST_STATE                                          syscall.Errno = 3064
	ERROR_APPEXEC_NO_DONOR                                                    syscall.Errno = 3065
	ERROR_APPEXEC_HOST_ID_MISMATCH                                            syscall.Errno = 3066
	ERROR_APPEXEC_UNKNOWN_USER                                                syscall.Errno = 3067
	ERROR_IO_REISSUE_AS_CACHED                                                syscall.Errno = 3950
	ERROR_WINS_INTERNAL                                                       syscall.Errno = 4000
	ERROR_CAN_NOT_DEL_LOCAL_WINS                                              syscall.Errno = 4001
	ERROR_STATIC_INIT                                                         syscall.Errno = 4002
	ERROR_INC_BACKUP                                                          syscall.Errno = 4003
	ERROR_FULL_BACKUP                                                         syscall.Errno = 4004
	ERROR_REC_NON_EXISTENT                                                    syscall.Errno = 4005
	ERROR_RPL_NOT_ALLOWED                                                     syscall.Errno = 4006
	PEERDIST_ERROR_CONTENTINFO_VERSION_UNSUPPORTED                            syscall.Errno = 4050
	PEERDIST_ERROR_CANNOT_PARSE_CONTENTINFO                                   syscall.Errno = 4051
	PEERDIST_ERROR_MISSING_DATA                                               syscall.Errno = 4052
	PEERDIST_ERROR_NO_MORE                                                    syscall.Errno = 4053
	PEERDIST_ERROR_NOT_INITIALIZED                                            syscall.Errno = 4054
	PEERDIST_ERROR_ALREADY_INITIALIZED                                        syscall.Errno = 4055
	PEERDIST_ERROR_SHUTDOWN_IN_PROGRESS                                       syscall.Errno = 4056
	PEERDIST_ERROR_INVALIDATED                                                syscall.Errno = 4057
	PEERDIST_ERROR_ALREADY_EXISTS                                             syscall.Errno = 4058
	PEERDIST_ERROR_OPERATION_NOTFOUND                                         syscall.Errno = 4059
	PEERDIST_ERROR_ALREADY_COMPLETED                                          syscall.Errno = 4060
	PEERDIST_ERROR_OUT_OF_BOUNDS                                              syscall.Errno = 4061
	PEERDIST_ERROR_VERSION_UNSUPPORTED                                        syscall.Errno = 4062
	PEERDIST_ERROR_INVALID_CONFIGURATION                                      syscall.Errno = 4063
	PEERDIST_ERROR_NOT_LICENSED                                               syscall.Errno = 4064
	PEERDIST_ERROR_SERVICE_UNAVAILABLE                                        syscall.Errno = 4065
	PEERDIST_ERROR_TRUST_FAILURE                                              syscall.Errno = 4066
	ERROR_DHCP_ADDRESS_CONFLICT                                               syscall.Errno = 4100
	ERROR_WMI_GUID_NOT_FOUND                                                  syscall.Errno = 4200
	ERROR_WMI_INSTANCE_NOT_FOUND                                              syscall.Errno = 4201
	ERROR_WMI_ITEMID_NOT_FOUND                                                syscall.Errno = 4202
	ERROR_WMI_TRY_AGAIN                                                       syscall.Errno = 4203
	ERROR_WMI_DP_NOT_FOUND                                                    syscall.Errno = 4204
	ERROR_WMI_UNRESOLVED_INSTANCE_REF                                         syscall.Errno = 4205
	ERROR_WMI_ALREADY_ENABLED                                                 syscall.Errno = 4206
	ERROR_WMI_GUID_DISCONNECTED                                               syscall.Errno = 4207
	ERROR_WMI_SERVER_UNAVAILABLE                                              syscall.Errno = 4208
	ERROR_WMI_DP_FAILED                                                       syscall.Errno = 4209
	ERROR_WMI_INVALID_MOF                                                     syscall.Errno = 4210
	ERROR_WMI_INVALID_REGINFO                                                 syscall.Errno = 4211
	ERROR_WMI_ALREADY_DISABLED                                                syscall.Errno = 4212
	ERROR_WMI_READ_ONLY                                                       syscall.Errno = 4213
	ERROR_WMI_SET_FAILURE                                                     syscall.Errno = 4214
	ERROR_NOT_APPCONTAINER                                                    syscall.Errno = 4250
	ERROR_APPCONTAINER_REQUIRED                                               syscall.Errno = 4251
	ERROR_NOT_SUPPORTED_IN_APPCONTAINER                                       syscall.Errno = 4252
	ERROR_INVALID_PACKAGE_SID_LENGTH                                          syscall.Errno = 4253
	ERROR_INVALID_MEDIA                                                       syscall.Errno = 4300
	ERROR_INVALID_LIBRARY                                                     syscall.Errno = 4301
	ERROR_INVALID_MEDIA_POOL                                                  syscall.Errno = 4302
	ERROR_DRIVE_MEDIA_MISMATCH                                                syscall.Errno = 4303
	ERROR_MEDIA_OFFLINE                                                       syscall.Errno = 4304
	ERROR_LIBRARY_OFFLINE                                                     syscall.Errno = 4305
	ERROR_EMPTY                                                               syscall.Errno = 4306
	ERROR_NOT_EMPTY                                                           syscall.Errno = 4307
	ERROR_MEDIA_UNAVAILABLE                                                   syscall.Errno = 4308
	ERROR_RESOURCE_DISABLED                                                   syscall.Errno = 4309
	ERROR_INVALID_CLEANER                                                     syscall.Errno = 4310
	ERROR_UNABLE_TO_CLEAN                                                     syscall.Errno = 4311
	ERROR_OBJECT_NOT_FOUND                                                    syscall.Errno = 4312
	ERROR_DATABASE_FAILURE                                                    syscall.Errno = 4313
	ERROR_DATABASE_FULL                                                       syscall.Errno = 4314
	ERROR_MEDIA_INCOMPATIBLE                                                  syscall.Errno = 4315
	ERROR_RESOURCE_NOT_PRESENT                                                syscall.Errno = 4316
	ERROR_INVALID_OPERATION                                                   syscall.Errno = 4317
	ERROR_MEDIA_NOT_AVAILABLE                                                 syscall.Errno = 4318
	ERROR_DEVICE_NOT_AVAILABLE                                                syscall.Errno = 4319
	ERROR_REQUEST_REFUSED                                                     syscall.Errno = 4320
	ERROR_INVALID_DRIVE_OBJECT                                                syscall.Errno = 4321
	ERROR_LIBRARY_FULL                                                        syscall.Errno = 4322
	ERROR_MEDIUM_NOT_ACCESSIBLE                                               syscall.Errno = 4323
	ERROR_UNABLE_TO_LOAD_MEDIUM                                               syscall.Errno = 4324
	ERROR_UNABLE_TO_INVENTORY_DRIVE                                           syscall.Errno = 4325
	ERROR_UNABLE_TO_INVENTORY_SLOT                                            syscall.Errno = 4326
	ERROR_UNABLE_TO_INVENTORY_TRANSPORT                                       syscall.Errno = 4327
	ERROR_TRANSPORT_FULL                                                      syscall.Errno = 4328
	ERROR_CONTROLLING_IEPORT                                                  syscall.Errno = 4329
	ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA                                       syscall.Errno = 4330
	ERROR_CLEANER_SLOT_SET                                                    syscall.Errno = 4331
	ERROR_CLEANER_SLOT_NOT_SET                                                syscall.Errno = 4332
	ERROR_CLEANER_CARTRIDGE_SPENT                                             syscall.Errno = 4333
	ERROR_UNEXPECTED_OMID                                                     syscall.Errno = 4334
	ERROR_CANT_DELETE_LAST_ITEM                                               syscall.Errno = 4335
	ERROR_MESSAGE_EXCEEDS_MAX_SIZE                                            syscall.Errno = 4336
	ERROR_VOLUME_CONTAINS_SYS_FILES                                           syscall.Errno = 4337
	ERROR_INDIGENOUS_TYPE                                                     syscall.Errno = 4338
	ERROR_NO_SUPPORTING_DRIVES                                                syscall.Errno = 4339
	ERROR_CLEANER_CARTRIDGE_INSTALLED                                         syscall.Errno = 4340
	ERROR_IEPORT_FULL                                                         syscall.Errno = 4341
	ERROR_FILE_OFFLINE                                                        syscall.Errno = 4350
	ERROR_REMOTE_STORAGE_NOT_ACTIVE                                           syscall.Errno = 4351
	ERROR_REMOTE_STORAGE_MEDIA_ERROR                                          syscall.Errno = 4352
	ERROR_NOT_A_REPARSE_POINT                                                 syscall.Errno = 4390
	ERROR_REPARSE_ATTRIBUTE_CONFLICT                                          syscall.Errno = 4391
	ERROR_INVALID_REPARSE_DATA                                                syscall.Errno = 4392
	ERROR_REPARSE_TAG_INVALID                                                 syscall.Errno = 4393
	ERROR_REPARSE_TAG_MISMATCH                                                syscall.Errno = 4394
	ERROR_REPARSE_POINT_ENCOUNTERED                                           syscall.Errno = 4395
	ERROR_APP_DATA_NOT_FOUND                                                  syscall.Errno = 4400
	ERROR_APP_DATA_EXPIRED                                                    syscall.Errno = 4401
	ERROR_APP_DATA_CORRUPT                                                    syscall.Errno = 4402
	ERROR_APP_DATA_LIMIT_EXCEEDED                                             syscall.Errno = 4403
	ERROR_APP_DATA_REBOOT_REQUIRED                                            syscall.Errno = 4404
	ERROR_SECUREBOOT_ROLLBACK_DETECTED                                        syscall.Errno = 4420
	ERROR_SECUREBOOT_POLICY_VIOLATION                                         syscall.Errno = 4421
	ERROR_SECUREBOOT_INVALID_POLICY                                           syscall.Errno = 4422
	ERROR_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND                               syscall.Errno = 4423
	ERROR_SECUREBOOT_POLICY_NOT_SIGNED                                        syscall.Errno = 4424
	ERROR_SECUREBOOT_NOT_ENABLED                                              syscall.Errno = 4425
	ERROR_SECUREBOOT_FILE_REPLACED                                            syscall.Errno = 4426
	ERROR_SECUREBOOT_POLICY_NOT_AUTHORIZED                                    syscall.Errno = 4427
	ERROR_SECUREBOOT_POLICY_UNKNOWN                                           syscall.Errno = 4428
	ERROR_SECUREBOOT_POLICY_MISSING_ANTIROLLBACKVERSION                       syscall.Errno = 4429
	ERROR_SECUREBOOT_PLATFORM_ID_MISMATCH                                     syscall.Errno = 4430
	ERROR_SECUREBOOT_POLICY_ROLLBACK_DETECTED                                 syscall.Errno = 4431
	ERROR_SECUREBOOT_POLICY_UPGRADE_MISMATCH                                  syscall.Errno = 4432
	ERROR_SECUREBOOT_REQUIRED_POLICY_FILE_MISSING                             syscall.Errno = 4433
	ERROR_SECUREBOOT_NOT_BASE_POLICY                                          syscall.Errno = 4434
	ERROR_SECUREBOOT_NOT_SUPPLEMENTAL_POLICY                                  syscall.Errno = 4435
	ERROR_OFFLOAD_READ_FLT_NOT_SUPPORTED                                      syscall.Errno = 4440
	ERROR_OFFLOAD_WRITE_FLT_NOT_SUPPORTED                                     syscall.Errno = 4441
	ERROR_OFFLOAD_READ_FILE_NOT_SUPPORTED                                     syscall.Errno = 4442
	ERROR_OFFLOAD_WRITE_FILE_NOT_SUPPORTED                                    syscall.Errno = 4443
	ERROR_ALREADY_HAS_STREAM_ID                                               syscall.Errno = 4444
	ERROR_SMR_GARBAGE_COLLECTION_REQUIRED                                     syscall.Errno = 4445
	ERROR_WOF_WIM_HEADER_CORRUPT                                              syscall.Errno = 4446
	ERROR_WOF_WIM_RESOURCE_TABLE_CORRUPT                                      syscall.Errno = 4447
	ERROR_WOF_FILE_RESOURCE_TABLE_CORRUPT                                     syscall.Errno = 4448
	ERROR_VOLUME_NOT_SIS_ENABLED                                              syscall.Errno = 4500
	ERROR_SYSTEM_INTEGRITY_ROLLBACK_DETECTED                                  syscall.Errno = 4550
	ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION                                   syscall.Errno = 4551
	ERROR_SYSTEM_INTEGRITY_INVALID_POLICY                                     syscall.Errno = 4552
	ERROR_SYSTEM_INTEGRITY_POLICY_NOT_SIGNED                                  syscall.Errno = 4553
	ERROR_SYSTEM_INTEGRITY_TOO_MANY_POLICIES                                  syscall.Errno = 4554
	ERROR_SYSTEM_INTEGRITY_SUPPLEMENTAL_POLICY_NOT_AUTHORIZED                 syscall.Errno = 4555
	ERROR_VSM_NOT_INITIALIZED                                                 syscall.Errno = 4560
	ERROR_VSM_DMA_PROTECTION_NOT_IN_USE                                       syscall.Errno = 4561
	ERROR_PLATFORM_MANIFEST_NOT_AUTHORIZED                                    syscall.Errno = 4570
	ERROR_PLATFORM_MANIFEST_INVALID                                           syscall.Errno = 4571
	ERROR_PLATFORM_MANIFEST_FILE_NOT_AUTHORIZED                               syscall.Errno = 4572
	ERROR_PLATFORM_MANIFEST_CATALOG_NOT_AUTHORIZED                            syscall.Errno = 4573
	ERROR_PLATFORM_MANIFEST_BINARY_ID_NOT_FOUND                               syscall.Errno = 4574
	ERROR_PLATFORM_MANIFEST_NOT_ACTIVE                                        syscall.Errno = 4575
	ERROR_PLATFORM_MANIFEST_NOT_SIGNED                                        syscall.Errno = 4576
	ERROR_DEPENDENT_RESOURCE_EXISTS                                           syscall.Errno = 5001
	ERROR_DEPENDENCY_NOT_FOUND                                                syscall.Errno = 5002
	ERROR_DEPENDENCY_ALREADY_EXISTS                                           syscall.Errno = 5003
	ERROR_RESOURCE_NOT_ONLINE                                                 syscall.Errno = 5004
	ERROR_HOST_NODE_NOT_AVAILABLE                                             syscall.Errno = 5005
	ERROR_RESOURCE_NOT_AVAILABLE                                              syscall.Errno = 5006
	ERROR_RESOURCE_NOT_FOUND                                                  syscall.Errno = 5007
	ERROR_SHUTDOWN_CLUSTER                                                    syscall.Errno = 5008
	ERROR_CANT_EVICT_ACTIVE_NODE                                              syscall.Errno = 5009
	ERROR_OBJECT_ALREADY_EXISTS                                               syscall.Errno = 5010
	ERROR_OBJECT_IN_LIST                                                      syscall.Errno = 5011
	ERROR_GROUP_NOT_AVAILABLE                                                 syscall.Errno = 5012
	ERROR_GROUP_NOT_FOUND                                                     syscall.Errno = 5013
	ERROR_GROUP_NOT_ONLINE                                                    syscall.Errno = 5014
	ERROR_HOST_NODE_NOT_RESOURCE_OWNER                                        syscall.Errno = 5015
	ERROR_HOST_NODE_NOT_GROUP_OWNER                                           syscall.Errno = 5016
	ERROR_RESMON_CREATE_FAILED                                                syscall.Errno = 5017
	ERROR_RESMON_ONLINE_FAILED                                                syscall.Errno = 5018
	ERROR_RESOURCE_ONLINE                                                     syscall.Errno = 5019
	ERROR_QUORUM_RESOURCE                                                     syscall.Errno = 5020
	ERROR_NOT_QUORUM_CAPABLE                                                  syscall.Errno = 5021
	ERROR_CLUSTER_SHUTTING_DOWN                                               syscall.Errno = 5022
	ERROR_INVALID_STATE                                                       syscall.Errno = 5023
	ERROR_RESOURCE_PROPERTIES_STORED                                          syscall.Errno = 5024
	ERROR_NOT_QUORUM_CLASS                                                    syscall.Errno = 5025
	ERROR_CORE_RESOURCE                                                       syscall.Errno = 5026
	ERROR_QUORUM_RESOURCE_ONLINE_FAILED                                       syscall.Errno = 5027
	ERROR_QUORUMLOG_OPEN_FAILED                                               syscall.Errno = 5028
	ERROR_CLUSTERLOG_CORRUPT                                                  syscall.Errno = 5029
	ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE                                   syscall.Errno = 5030
	ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE                                          syscall.Errno = 5031
	ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND                                       syscall.Errno = 5032
	ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE                                         syscall.Errno = 5033
	ERROR_QUORUM_OWNER_ALIVE                                                  syscall.Errno = 5034
	ERROR_NETWORK_NOT_AVAILABLE                                               syscall.Errno = 5035
	ERROR_NODE_NOT_AVAILABLE                                                  syscall.Errno = 5036
	ERROR_ALL_NODES_NOT_AVAILABLE                                             syscall.Errno = 5037
	ERROR_RESOURCE_FAILED                                                     syscall.Errno = 5038
	ERROR_CLUSTER_INVALID_NODE                                                syscall.Errno = 5039
	ERROR_CLUSTER_NODE_EXISTS                                                 syscall.Errno = 5040
	ERROR_CLUSTER_JOIN_IN_PROGRESS                                            syscall.Errno = 5041
	ERROR_CLUSTER_NODE_NOT_FOUND                                              syscall.Errno = 5042
	ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND                                        syscall.Errno = 5043
	ERROR_CLUSTER_NETWORK_EXISTS                                              syscall.Errno = 5044
	ERROR_CLUSTER_NETWORK_NOT_FOUND                                           syscall.Errno = 5045
	ERROR_CLUSTER_NETINTERFACE_EXISTS                                         syscall.Errno = 5046
	ERROR_CLUSTER_NETINTERFACE_NOT_FOUND                                      syscall.Errno = 5047
	ERROR_CLUSTER_INVALID_REQUEST                                             syscall.Errno = 5048
	ERROR_CLUSTER_INVALID_NETWORK_PROVIDER                                    syscall.Errno = 5049
	ERROR_CLUSTER_NODE_DOWN                                                   syscall.Errno = 5050
	ERROR_CLUSTER_NODE_UNREACHABLE                                            syscall.Errno = 5051
	ERROR_CLUSTER_NODE_NOT_MEMBER                                             syscall.Errno = 5052
	ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS                                        syscall.Errno = 5053
	ERROR_CLUSTER_INVALID_NETWORK                                             syscall.Errno = 5054
	ERROR_CLUSTER_NODE_UP                                                     syscall.Errno = 5056
	ERROR_CLUSTER_IPADDR_IN_USE                                               syscall.Errno = 5057
	ERROR_CLUSTER_NODE_NOT_PAUSED                                             syscall.Errno = 5058
	ERROR_CLUSTER_NO_SECURITY_CONTEXT                                         syscall.Errno = 5059
	ERROR_CLUSTER_NETWORK_NOT_INTERNAL                                        syscall.Errno = 5060
	ERROR_CLUSTER_NODE_ALREADY_UP                                             syscall.Errno = 5061
	ERROR_CLUSTER_NODE_ALREADY_DOWN                                           syscall.Errno = 5062
	ERROR_CLUSTER_NETWORK_ALREADY_ONLINE                                      syscall.Errno = 5063
	ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE                                     syscall.Errno = 5064
	ERROR_CLUSTER_NODE_ALREADY_MEMBER                                         syscall.Errno = 5065
	ERROR_CLUSTER_LAST_INTERNAL_NETWORK                                       syscall.Errno = 5066
	ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS                                      syscall.Errno = 5067
	ERROR_INVALID_OPERATION_ON_QUORUM                                         syscall.Errno = 5068
	ERROR_DEPENDENCY_NOT_ALLOWED                                              syscall.Errno = 5069
	ERROR_CLUSTER_NODE_PAUSED                                                 syscall.Errno = 5070
	ERROR_NODE_CANT_HOST_RESOURCE                                             syscall.Errno = 5071
	ERROR_CLUSTER_NODE_NOT_READY                                              syscall.Errno = 5072
	ERROR_CLUSTER_NODE_SHUTTING_DOWN                                          syscall.Errno = 5073
	ERROR_CLUSTER_JOIN_ABORTED                                                syscall.Errno = 5074
	ERROR_CLUSTER_INCOMPATIBLE_VERSIONS                                       syscall.Errno = 5075
	ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED                                syscall.Errno = 5076
	ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED                                       syscall.Errno = 5077
	ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND                                     syscall.Errno = 5078
	ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED                                       syscall.Errno = 5079
	ERROR_CLUSTER_RESNAME_NOT_FOUND                                           syscall.Errno = 5080
	ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED                                  syscall.Errno = 5081
	ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST                                       syscall.Errno = 5082
	ERROR_CLUSTER_DATABASE_SEQMISMATCH                                        syscall.Errno = 5083
	ERROR_RESMON_INVALID_STATE                                                syscall.Errno = 5084
	ERROR_CLUSTER_GUM_NOT_LOCKER                                              syscall.Errno = 5085
	ERROR_QUORUM_DISK_NOT_FOUND                                               syscall.Errno = 5086
	ERROR_DATABASE_BACKUP_CORRUPT                                             syscall.Errno = 5087
	ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT                                   syscall.Errno = 5088
	ERROR_RESOURCE_PROPERTY_UNCHANGEABLE                                      syscall.Errno = 5089
	ERROR_NO_ADMIN_ACCESS_POINT                                               syscall.Errno = 5090
	ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE                                    syscall.Errno = 5890
	ERROR_CLUSTER_QUORUMLOG_NOT_FOUND                                         syscall.Errno = 5891
	ERROR_CLUSTER_MEMBERSHIP_HALT                                             syscall.Errno = 5892
	ERROR_CLUSTER_INSTANCE_ID_MISMATCH                                        syscall.Errno = 5893
	ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP                                    syscall.Errno = 5894
	ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH                                 syscall.Errno = 5895
	ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP                                       syscall.Errno = 5896
	ERROR_CLUSTER_PARAMETER_MISMATCH                                          syscall.Errno = 5897
	ERROR_NODE_CANNOT_BE_CLUSTERED                                            syscall.Errno = 5898
	ERROR_CLUSTER_WRONG_OS_VERSION                                            syscall.Errno = 5899
	ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME                                syscall.Errno = 5900
	ERROR_CLUSCFG_ALREADY_COMMITTED                                           syscall.Errno = 5901
	ERROR_CLUSCFG_ROLLBACK_FAILED                                             syscall.Errno = 5902
	ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT                           syscall.Errno = 5903
	ERROR_CLUSTER_OLD_VERSION                                                 syscall.Errno = 5904
	ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME                               syscall.Errno = 5905
	ERROR_CLUSTER_NO_NET_ADAPTERS                                             syscall.Errno = 5906
	ERROR_CLUSTER_POISONED                                                    syscall.Errno = 5907
	ERROR_CLUSTER_GROUP_MOVING                                                syscall.Errno = 5908
	ERROR_CLUSTER_RESOURCE_TYPE_BUSY                                          syscall.Errno = 5909
	ERROR_RESOURCE_CALL_TIMED_OUT                                             syscall.Errno = 5910
	ERROR_INVALID_CLUSTER_IPV6_ADDRESS                                        syscall.Errno = 5911
	ERROR_CLUSTER_INTERNAL_INVALID_FUNCTION                                   syscall.Errno = 5912
	ERROR_CLUSTER_PARAMETER_OUT_OF_BOUNDS                                     syscall.Errno = 5913
	ERROR_CLUSTER_PARTIAL_SEND                                                syscall.Errno = 5914
	ERROR_CLUSTER_REGISTRY_INVALID_FUNCTION                                   syscall.Errno = 5915
	ERROR_CLUSTER_INVALID_STRING_TERMINATION                                  syscall.Errno = 5916
	ERROR_CLUSTER_INVALID_STRING_FORMAT                                       syscall.Errno = 5917
	ERROR_CLUSTER_DATABASE_TRANSACTION_IN_PROGRESS                            syscall.Errno = 5918
	ERROR_CLUSTER_DATABASE_TRANSACTION_NOT_IN_PROGRESS                        syscall.Errno = 5919
	ERROR_CLUSTER_NULL_DATA                                                   syscall.Errno = 5920
	ERROR_CLUSTER_PARTIAL_READ                                                syscall.Errno = 5921
	ERROR_CLUSTER_PARTIAL_WRITE                                               syscall.Errno = 5922
	ERROR_CLUSTER_CANT_DESERIALIZE_DATA                                       syscall.Errno = 5923
	ERROR_DEPENDENT_RESOURCE_PROPERTY_CONFLICT                                syscall.Errno = 5924
	ERROR_CLUSTER_NO_QUORUM                                                   syscall.Errno = 5925
	ERROR_CLUSTER_INVALID_IPV6_NETWORK                                        syscall.Errno = 5926
	ERROR_CLUSTER_INVALID_IPV6_TUNNEL_NETWORK                                 syscall.Errno = 5927
	ERROR_QUORUM_NOT_ALLOWED_IN_THIS_GROUP                                    syscall.Errno = 5928
	ERROR_DEPENDENCY_TREE_TOO_COMPLEX                                         syscall.Errno = 5929
	ERROR_EXCEPTION_IN_RESOURCE_CALL                                          syscall.Errno = 5930
	ERROR_CLUSTER_RHS_FAILED_INITIALIZATION                                   syscall.Errno = 5931
	ERROR_CLUSTER_NOT_INSTALLED                                               syscall.Errno = 5932
	ERROR_CLUSTER_RESOURCES_MUST_BE_ONLINE_ON_THE_SAME_NODE                   syscall.Errno = 5933
	ERROR_CLUSTER_MAX_NODES_IN_CLUSTER                                        syscall.Errno = 5934
	ERROR_CLUSTER_TOO_MANY_NODES                                              syscall.Errno = 5935
	ERROR_CLUSTER_OBJECT_ALREADY_USED                                         syscall.Errno = 5936
	ERROR_NONCORE_GROUPS_FOUND                                                syscall.Errno = 5937
	ERROR_FILE_SHARE_RESOURCE_CONFLICT                                        syscall.Errno = 5938
	ERROR_CLUSTER_EVICT_INVALID_REQUEST                                       syscall.Errno = 5939
	ERROR_CLUSTER_SINGLETON_RESOURCE                                          syscall.Errno = 5940
	ERROR_CLUSTER_GROUP_SINGLETON_RESOURCE                                    syscall.Errno = 5941
	ERROR_CLUSTER_RESOURCE_PROVIDER_FAILED                                    syscall.Errno = 5942
	ERROR_CLUSTER_RESOURCE_CONFIGURATION_ERROR                                syscall.Errno = 5943
	ERROR_CLUSTER_GROUP_BUSY                                                  syscall.Errno = 5944
	ERROR_CLUSTER_NOT_SHARED_VOLUME                                           syscall.Errno = 5945
	ERROR_CLUSTER_INVALID_SECURITY_DESCRIPTOR                                 syscall.Errno = 5946
	ERROR_CLUSTER_SHARED_VOLUMES_IN_USE                                       syscall.Errno = 5947
	ERROR_CLUSTER_USE_SHARED_VOLUMES_API                                      syscall.Errno = 5948
	ERROR_CLUSTER_BACKUP_IN_PROGRESS                                          syscall.Errno = 5949
	ERROR_NON_CSV_PATH                                                        syscall.Errno = 5950
	ERROR_CSV_VOLUME_NOT_LOCAL                                                syscall.Errno = 5951
	ERROR_CLUSTER_WATCHDOG_TERMINATING                                        syscall.Errno = 5952
	ERROR_CLUSTER_RESOURCE_VETOED_MOVE_INCOMPATIBLE_NODES                     syscall.Errno = 5953
	ERROR_CLUSTER_INVALID_NODE_WEIGHT                                         syscall.Errno = 5954
	ERROR_CLUSTER_RESOURCE_VETOED_CALL                                        syscall.Errno = 5955
	ERROR_RESMON_SYSTEM_RESOURCES_LACKING                                     syscall.Errno = 5956
	ERROR_CLUSTER_RESOURCE_VETOED_MOVE_NOT_ENOUGH_RESOURCES_ON_DESTINATION    syscall.Errno = 5957
	ERROR_CLUSTER_RESOURCE_VETOED_MOVE_NOT_ENOUGH_RESOURCES_ON_SOURCE         syscall.Errno = 5958
	ERROR_CLUSTER_GROUP_QUEUED                                                syscall.Errno = 5959
	ERROR_CLUSTER_RESOURCE_LOCKED_STATUS                                      syscall.Errno = 5960
	ERROR_CLUSTER_SHARED_VOLUME_FAILOVER_NOT_ALLOWED                          syscall.Errno = 5961
	ERROR_CLUSTER_NODE_DRAIN_IN_PROGRESS                                      syscall.Errno = 5962
	ERROR_CLUSTER_DISK_NOT_CONNECTED                                          syscall.Errno = 5963
	ERROR_DISK_NOT_CSV_CAPABLE                                                syscall.Errno = 5964
	ERROR_RESOURCE_NOT_IN_AVAILABLE_STORAGE                                   syscall.Errno = 5965
	ERROR_CLUSTER_SHARED_VOLUME_REDIRECTED                                    syscall.Errno = 5966
	ERROR_CLUSTER_SHARED_VOLUME_NOT_REDIRECTED                                syscall.Errno = 5967
	ERROR_CLUSTER_CANNOT_RETURN_PROPERTIES                                    syscall.Errno = 5968
	ERROR_CLUSTER_RESOURCE_CONTAINS_UNSUPPORTED_DIFF_AREA_FOR_SHARED_VOLUMES  syscall.Errno = 5969
	ERROR_CLUSTER_RESOURCE_IS_IN_MAINTENANCE_MODE                             syscall.Errno = 5970
	ERROR_CLUSTER_AFFINITY_CONFLICT                                           syscall.Errno = 5971
	ERROR_CLUSTER_RESOURCE_IS_REPLICA_VIRTUAL_MACHINE                         syscall.Errno = 5972
	ERROR_CLUSTER_UPGRADE_INCOMPATIBLE_VERSIONS                               syscall.Errno = 5973
	ERROR_CLUSTER_UPGRADE_FIX_QUORUM_NOT_SUPPORTED                            syscall.Errno = 5974
	ERROR_CLUSTER_UPGRADE_RESTART_REQUIRED                                    syscall.Errno = 5975
	ERROR_CLUSTER_UPGRADE_IN_PROGRESS                                         syscall.Errno = 5976
	ERROR_CLUSTER_UPGRADE_INCOMPLETE                                          syscall.Errno = 5977
	ERROR_CLUSTER_NODE_IN_GRACE_PERIOD                                        syscall.Errno = 5978
	ERROR_CLUSTER_CSV_IO_PAUSE_TIMEOUT                                        syscall.Errno = 5979
	ERROR_NODE_NOT_ACTIVE_CLUSTER_MEMBER                                      syscall.Errno = 5980
	ERROR_CLUSTER_RESOURCE_NOT_MONITORED                                      syscall.Errno = 5981
	ERROR_CLUSTER_RESOURCE_DOES_NOT_SUPPORT_UNMONITORED                       syscall.Errno = 5982
	ERROR_CLUSTER_RESOURCE_IS_REPLICATED                                      syscall.Errno = 5983
	ERROR_CLUSTER_NODE_ISOLATED                                               syscall.Errno = 5984
	ERROR_CLUSTER_NODE_QUARANTINED                                            syscall.Errno = 5985
	ERROR_CLUSTER_DATABASE_UPDATE_CONDITION_FAILED                            syscall.Errno = 5986
	ERROR_CLUSTER_SPACE_DEGRADED                                              syscall.Errno = 5987
	ERROR_CLUSTER_TOKEN_DELEGATION_NOT_SUPPORTED                              syscall.Errno = 5988
	ERROR_CLUSTER_CSV_INVALID_HANDLE                                          syscall.Errno = 5989
	ERROR_CLUSTER_CSV_SUPPORTED_ONLY_ON_COORDINATOR                           syscall.Errno = 5990
	ERROR_GROUPSET_NOT_AVAILABLE                                              syscall.Errno = 5991
	ERROR_GROUPSET_NOT_FOUND                                                  syscall.Errno = 5992
	ERROR_GROUPSET_CANT_PROVIDE                                               syscall.Errno = 5993
	ERROR_CLUSTER_FAULT_DOMAIN_PARENT_NOT_FOUND                               syscall.Errno = 5994
	ERROR_CLUSTER_FAULT_DOMAIN_INVALID_HIERARCHY                              syscall.Errno = 5995
	ERROR_CLUSTER_FAULT_DOMAIN_FAILED_S2D_VALIDATION                          syscall.Errno = 5996
	ERROR_CLUSTER_FAULT_DOMAIN_S2D_CONNECTIVITY_LOSS                          syscall.Errno = 5997
	ERROR_CLUSTER_INVALID_INFRASTRUCTURE_FILESERVER_NAME                      syscall.Errno = 5998
	ERROR_CLUSTERSET_MANAGEMENT_CLUSTER_UNREACHABLE                           syscall.Errno = 5999
	ERROR_ENCRYPTION_FAILED                                                   syscall.Errno = 6000
	ERROR_DECRYPTION_FAILED                                                   syscall.Errno = 6001
	ERROR_FILE_ENCRYPTED                                                      syscall.Errno = 6002
	ERROR_NO_RECOVERY_POLICY                                                  syscall.Errno = 6003
	ERROR_NO_EFS                                                              syscall.Errno = 6004
	ERROR_WRONG_EFS                                                           syscall.Errno = 6005
	ERROR_NO_USER_KEYS                                                        syscall.Errno = 6006
	ERROR_FILE_NOT_ENCRYPTED                                                  syscall.Errno = 6007
	ERROR_NOT_EXPORT_FORMAT                                                   syscall.Errno = 6008
	ERROR_FILE_READ_ONLY                                                      syscall.Errno = 6009
	ERROR_DIR_EFS_DISALLOWED                                                  syscall.Errno = 6010
	ERROR_EFS_SERVER_NOT_TRUSTED                                              syscall.Errno = 6011
	ERROR_BAD_RECOVERY_POLICY                                                 syscall.Errno = 6012
	ERROR_EFS_ALG_BLOB_TOO_BIG                                                syscall.Errno = 6013
	ERROR_VOLUME_NOT_SUPPORT_EFS                                              syscall.Errno = 6014
	ERROR_EFS_DISABLED                                                        syscall.Errno = 6015
	ERROR_EFS_VERSION_NOT_SUPPORT                                             syscall.Errno = 6016
	ERROR_CS_ENCRYPTION_INVALID_SERVER_RESPONSE                               syscall.Errno = 6017
	ERROR_CS_ENCRYPTION_UNSUPPORTED_SERVER                                    syscall.Errno = 6018
	ERROR_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE                               syscall.Errno = 6019
	ERROR_CS_ENCRYPTION_NEW_ENCRYPTED_FILE                                    syscall.Errno = 6020
	ERROR_CS_ENCRYPTION_FILE_NOT_CSE                                          syscall.Errno = 6021
	ERROR_ENCRYPTION_POLICY_DENIES_OPERATION                                  syscall.Errno = 6022
	ERROR_WIP_ENCRYPTION_FAILED                                               syscall.Errno = 6023
	ERROR_NO_BROWSER_SERVERS_FOUND                                            syscall.Errno = 6118
	SCHED_E_SERVICE_NOT_LOCALSYSTEM                                           syscall.Errno = 6200
	ERROR_LOG_SECTOR_INVALID                                                  syscall.Errno = 6600
	ERROR_LOG_SECTOR_PARITY_INVALID                                           syscall.Errno = 6601
	ERROR_LOG_SECTOR_REMAPPED                                                 syscall.Errno = 6602
	ERROR_LOG_BLOCK_INCOMPLETE                                                syscall.Errno = 6603
	ERROR_LOG_INVALID_RANGE                                                   syscall.Errno = 6604
	ERROR_LOG_BLOCKS_EXHAUSTED                                                syscall.Errno = 6605
	ERROR_LOG_READ_CONTEXT_INVALID                                            syscall.Errno = 6606
	ERROR_LOG_RESTART_INVALID                                                 syscall.Errno = 6607
	ERROR_LOG_BLOCK_VERSION                                                   syscall.Errno = 6608
	ERROR_LOG_BLOCK_INVALID                                                   syscall.Errno = 6609
	ERROR_LOG_READ_MODE_INVALID                                               syscall.Errno = 6610
	ERROR_LOG_NO_RESTART                                                      syscall.Errno = 6611
	ERROR_LOG_METADATA_CORRUPT                                                syscall.Errno = 6612
	ERROR_LOG_METADATA_INVALID                                                syscall.Errno = 6613
	ERROR_LOG_METADATA_INCONSISTENT                                           syscall.Errno = 6614
	ERROR_LOG_RESERVATION_INVALID                                             syscall.Errno = 6615
	ERROR_LOG_CANT_DELETE                                                     syscall.Errno = 6616
	ERROR_LOG_CONTAINER_LIMIT_EXCEEDED                                        syscall.Errno = 6617
	ERROR_LOG_START_OF_LOG                                                    syscall.Errno = 6618
	ERROR_LOG_POLICY_ALREADY_INSTALLED                                        syscall.Errno = 6619
	ERROR_LOG_POLICY_NOT_INSTALLED                                            syscall.Errno = 6620
	ERROR_LOG_POLICY_INVALID                                                  syscall.Errno = 6621
	ERROR_LOG_POLICY_CONFLICT                                                 syscall.Errno = 6622
	ERROR_LOG_PINNED_ARCHIVE_TAIL                                             syscall.Errno = 6623
	ERROR_LOG_RECORD_NONEXISTENT                                              syscall.Errno = 6624
	ERROR_LOG_RECORDS_RESERVED_INVALID                                        syscall.Errno = 6625
	ERROR_LOG_SPACE_RESERVED_INVALID                                          syscall.Errno = 6626
	ERROR_LOG_TAIL_INVALID                                                    syscall.Errno = 6627
	ERROR_LOG_FULL                                                            syscall.Errno = 6628
	ERROR_COULD_NOT_RESIZE_LOG                                                syscall.Errno = 6629
	ERROR_LOG_MULTIPLEXED                                                     syscall.Errno = 6630
	ERROR_LOG_DEDICATED                                                       syscall.Errno = 6631
	ERROR_LOG_ARCHIVE_NOT_IN_PROGRESS                                         syscall.Errno = 6632
	ERROR_LOG_ARCHIVE_IN_PROGRESS                                             syscall.Errno = 6633
	ERROR_LOG_EPHEMERAL                                                       syscall.Errno = 6634
	ERROR_LOG_NOT_ENOUGH_CONTAINERS                                           syscall.Errno = 6635
	ERROR_LOG_CLIENT_ALREADY_REGISTERED                                       syscall.Errno = 6636
	ERROR_LOG_CLIENT_NOT_REGISTERED                                           syscall.Errno = 6637
	ERROR_LOG_FULL_HANDLER_IN_PROGRESS                                        syscall.Errno = 6638
	ERROR_LOG_CONTAINER_READ_FAILED                                           syscall.Errno = 6639
	ERROR_LOG_CONTAINER_WRITE_FAILED                                          syscall.Errno = 6640
	ERROR_LOG_CONTAINER_OPEN_FAILED                                           syscall.Errno = 6641
	ERROR_LOG_CONTAINER_STATE_INVALID                                         syscall.Errno = 6642
	ERROR_LOG_STATE_INVALID                                                   syscall.Errno = 6643
	ERROR_LOG_PINNED                                                          syscall.Errno = 6644
	ERROR_LOG_METADATA_FLUSH_FAILED                                           syscall.Errno = 6645
	ERROR_LOG_INCONSISTENT_SECURITY                                           syscall.Errno = 6646
	ERROR_LOG_APPENDED_FLUSH_FAILED                                           syscall.Errno = 6647
	ERROR_LOG_PINNED_RESERVATION                                              syscall.Errno = 6648
	ERROR_INVALID_TRANSACTION                                                 syscall.Errno = 6700
	ERROR_TRANSACTION_NOT_ACTIVE                                              syscall.Errno = 6701
	ERROR_TRANSACTION_REQUEST_NOT_VALID                                       syscall.Errno = 6702
	ERROR_TRANSACTION_NOT_REQUESTED                                           syscall.Errno = 6703
	ERROR_TRANSACTION_ALREADY_ABORTED                                         syscall.Errno = 6704
	ERROR_TRANSACTION_ALREADY_COMMITTED                                       syscall.Errno = 6705
	ERROR_TM_INITIALIZATION_FAILED                                            syscall.Errno = 6706
	ERROR_RESOURCEMANAGER_READ_ONLY                                           syscall.Errno = 6707
	ERROR_TRANSACTION_NOT_JOINED                                              syscall.Errno = 6708
	ERROR_TRANSACTION_SUPERIOR_EXISTS                                         syscall.Errno = 6709
	ERROR_CRM_PROTOCOL_ALREADY_EXISTS                                         syscall.Errno = 6710
	ERROR_TRANSACTION_PROPAGATION_FAILED                                      syscall.Errno = 6711
	ERROR_CRM_PROTOCOL_NOT_FOUND                                              syscall.Errno = 6712
	ERROR_TRANSACTION_INVALID_MARSHALL_BUFFER                                 syscall.Errno = 6713
	ERROR_CURRENT_TRANSACTION_NOT_VALID                                       syscall.Errno = 6714
	ERROR_TRANSACTION_NOT_FOUND                                               syscall.Errno = 6715
	ERROR_RESOURCEMANAGER_NOT_FOUND                                           syscall.Errno = 6716
	ERROR_ENLISTMENT_NOT_FOUND                                                syscall.Errno = 6717
	ERROR_TRANSACTIONMANAGER_NOT_FOUND                                        syscall.Errno = 6718
	ERROR_TRANSACTIONMANAGER_NOT_ONLINE                                       syscall.Errno = 6719
	ERROR_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION                          syscall.Errno = 6720
	ERROR_TRANSACTION_NOT_ROOT                                                syscall.Errno = 6721
	ERROR_TRANSACTION_OBJECT_EXPIRED                                          syscall.Errno = 6722
	ERROR_TRANSACTION_RESPONSE_NOT_ENLISTED                                   syscall.Errno = 6723
	ERROR_TRANSACTION_RECORD_TOO_LONG                                         syscall.Errno = 6724
	ERROR_IMPLICIT_TRANSACTION_NOT_SUPPORTED                                  syscall.Errno = 6725
	ERROR_TRANSACTION_INTEGRITY_VIOLATED                                      syscall.Errno = 6726
	ERROR_TRANSACTIONMANAGER_IDENTITY_MISMATCH                                syscall.Errno = 6727
	ERROR_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT                                    syscall.Errno = 6728
	ERROR_TRANSACTION_MUST_WRITETHROUGH                                       syscall.Errno = 6729
	ERROR_TRANSACTION_NO_SUPERIOR                                             syscall.Errno = 6730
	ERROR_HEURISTIC_DAMAGE_POSSIBLE                                           syscall.Errno = 6731
	ERROR_TRANSACTIONAL_CONFLICT                                              syscall.Errno = 6800
	ERROR_RM_NOT_ACTIVE                                                       syscall.Errno = 6801
	ERROR_RM_METADATA_CORRUPT                                                 syscall.Errno = 6802
	ERROR_DIRECTORY_NOT_RM                                                    syscall.Errno = 6803
	ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE                                     syscall.Errno = 6805
	ERROR_LOG_RESIZE_INVALID_SIZE                                             syscall.Errno = 6806
	ERROR_OBJECT_NO_LONGER_EXISTS                                             syscall.Errno = 6807
	ERROR_STREAM_MINIVERSION_NOT_FOUND                                        syscall.Errno = 6808
	ERROR_STREAM_MINIVERSION_NOT_VALID                                        syscall.Errno = 6809
	ERROR_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION                 syscall.Errno = 6810
	ERROR_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT                            syscall.Errno = 6811
	ERROR_CANT_CREATE_MORE_STREAM_MINIVERSIONS                                syscall.Errno = 6812
	ERROR_REMOTE_FILE_VERSION_MISMATCH                                        syscall.Errno = 6814
	ERROR_HANDLE_NO_LONGER_VALID                                              syscall.Errno = 6815
	ERROR_NO_TXF_METADATA                                                     syscall.Errno = 6816
	ERROR_LOG_CORRUPTION_DETECTED                                             syscall.Errno = 6817
	ERROR_CANT_RECOVER_WITH_HANDLE_OPEN                                       syscall.Errno = 6818
	ERROR_RM_DISCONNECTED                                                     syscall.Errno = 6819
	ERROR_ENLISTMENT_NOT_SUPERIOR                                             syscall.Errno = 6820
	ERROR_RECOVERY_NOT_NEEDED                                                 syscall.Errno = 6821
	ERROR_RM_ALREADY_STARTED                                                  syscall.Errno = 6822
	ERROR_FILE_IDENTITY_NOT_PERSISTENT                                        syscall.Errno = 6823
	ERROR_CANT_BREAK_TRANSACTIONAL_DEPENDENCY                                 syscall.Errno = 6824
	ERROR_CANT_CROSS_RM_BOUNDARY                                              syscall.Errno = 6825
	ERROR_TXF_DIR_NOT_EMPTY                                                   syscall.Errno = 6826
	ERROR_INDOUBT_TRANSACTIONS_EXIST                                          syscall.Errno = 6827
	ERROR_TM_VOLATILE                                                         syscall.Errno = 6828
	ERROR_ROLLBACK_TIMER_EXPIRED                                              syscall.Errno = 6829
	ERROR_TXF_ATTRIBUTE_CORRUPT                                               syscall.Errno = 6830
	ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION                                      syscall.Errno = 6831
	ERROR_TRANSACTIONAL_OPEN_NOT_ALLOWED                                      syscall.Errno = 6832
	ERROR_LOG_GROWTH_FAILED                                                   syscall.Errno = 6833
	ERROR_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE                               syscall.Errno = 6834
	ERROR_TXF_METADATA_ALREADY_PRESENT                                        syscall.Errno = 6835
	ERROR_TRANSACTION_SCOPE_CALLBACKS_NOT_SET                                 syscall.Errno = 6836
	ERROR_TRANSACTION_REQUIRED_PROMOTION                                      syscall.Errno = 6837
	ERROR_CANNOT_EXECUTE_FILE_IN_TRANSACTION                                  syscall.Errno = 6838
	ERROR_TRANSACTIONS_NOT_FROZEN                                             syscall.Errno = 6839
	ERROR_TRANSACTION_FREEZE_IN_PROGRESS                                      syscall.Errno = 6840
	ERROR_NOT_SNAPSHOT_VOLUME                                                 syscall.Errno = 6841
	ERROR_NO_SAVEPOINT_WITH_OPEN_FILES                                        syscall.Errno = 6842
	ERROR_DATA_LOST_REPAIR                                                    syscall.Errno = 6843
	ERROR_SPARSE_NOT_ALLOWED_IN_TRANSACTION                                   syscall.Errno = 6844
	ERROR_TM_IDENTITY_MISMATCH                                                syscall.Errno = 6845
	ERROR_FLOATED_SECTION                                                     syscall.Errno = 6846
	ERROR_CANNOT_ACCEPT_TRANSACTED_WORK                                       syscall.Errno = 6847
	ERROR_CANNOT_ABORT_TRANSACTIONS                                           syscall.Errno = 6848
	ERROR_BAD_CLUSTERS                                                        syscall.Errno = 6849
	ERROR_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION                              syscall.Errno = 6850
	ERROR_VOLUME_DIRTY                                                        syscall.Errno = 6851
	ERROR_NO_LINK_TRACKING_IN_TRANSACTION                                     syscall.Errno = 6852
	ERROR_OPERATION_NOT_SUPPORTED_IN_TRANSACTION                              syscall.Errno = 6853
	ERROR_EXPIRED_HANDLE                                                      syscall.Errno = 6854
	ERROR_TRANSACTION_NOT_ENLISTED                                            syscall.Errno = 6855
	ERROR_CTX_WINSTATION_NAME_INVALID                                         syscall.Errno = 7001
	ERROR_CTX_INVALID_PD                                                      syscall.Errno = 7002
	ERROR_CTX_PD_NOT_FOUND                                                    syscall.Errno = 7003
	ERROR_CTX_WD_NOT_FOUND                                                    syscall.Errno = 7004
	ERROR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY                                      syscall.Errno = 7005
	ERROR_CTX_SERVICE_NAME_COLLISION                                          syscall.Errno = 7006
	ERROR_CTX_CLOSE_PENDING                                                   syscall.Errno = 7007
	ERROR_CTX_NO_OUTBUF                                                       syscall.Errno = 7008
	ERROR_CTX_MODEM_INF_NOT_FOUND                                             syscall.Errno = 7009
	ERROR_CTX_INVALID_MODEMNAME                                               syscall.Errno = 7010
	ERROR_CTX_MODEM_RESPONSE_ERROR                                            syscall.Errno = 7011
	ERROR_CTX_MODEM_RESPONSE_TIMEOUT                                          syscall.Errno = 7012
	ERROR_CTX_MODEM_RESPONSE_NO_CARRIER                                       syscall.Errno = 7013
	ERROR_CTX_MODEM_RESPONSE_NO_DIALTONE                                      syscall.Errno = 7014
	ERROR_CTX_MODEM_RESPONSE_BUSY                                             syscall.Errno = 7015
	ERROR_CTX_MODEM_RESPONSE_VOICE                                            syscall.Errno = 7016
	ERROR_CTX_TD_ERROR                                                        syscall.Errno = 7017
	ERROR_CTX_WINSTATION_NOT_FOUND                                            syscall.Errno = 7022
	ERROR_CTX_WINSTATION_ALREADY_EXISTS                                       syscall.Errno = 7023
	ERROR_CTX_WINSTATION_BUSY                                                 syscall.Errno = 7024
	ERROR_CTX_BAD_VIDEO_MODE                                                  syscall.Errno = 7025
	ERROR_CTX_GRAPHICS_INVALID                                                syscall.Errno = 7035
	ERROR_CTX_LOGON_DISABLED                                                  syscall.Errno = 7037
	ERROR_CTX_NOT_CONSOLE                                                     syscall.Errno = 7038
	ERROR_CTX_CLIENT_QUERY_TIMEOUT                                            syscall.Errno = 7040
	ERROR_CTX_CONSOLE_DISCONNECT                                              syscall.Errno = 7041
	ERROR_CTX_CONSOLE_CONNECT                                                 syscall.Errno = 7042
	ERROR_CTX_SHADOW_DENIED                                                   syscall.Errno = 7044
	ERROR_CTX_WINSTATION_ACCESS_DENIED                                        syscall.Errno = 7045
	ERROR_CTX_INVALID_WD                                                      syscall.Errno = 7049
	ERROR_CTX_SHADOW_INVALID                                                  syscall.Errno = 7050
	ERROR_CTX_SHADOW_DISABLED                                                 syscall.Errno = 7051
	ERROR_CTX_CLIENT_LICENSE_IN_USE                                           syscall.Errno = 7052
	ERROR_CTX_CLIENT_LICENSE_NOT_SET                                          syscall.Errno = 7053
	ERROR_CTX_LICENSE_NOT_AVAILABLE                                           syscall.Errno = 7054
	ERROR_CTX_LICENSE_CLIENT_INVALID                                          syscall.Errno = 7055
	ERROR_CTX_LICENSE_EXPIRED                                                 syscall.Errno = 7056
	ERROR_CTX_SHADOW_NOT_RUNNING                                              syscall.Errno = 7057
	ERROR_CTX_SHADOW_ENDED_BY_MODE_CHANGE                                     syscall.Errno = 7058
	ERROR_ACTIVATION_COUNT_EXCEEDED                                           syscall.Errno = 7059
	ERROR_CTX_WINSTATIONS_DISABLED                                            syscall.Errno = 7060
	ERROR_CTX_ENCRYPTION_LEVEL_REQUIRED                                       syscall.Errno = 7061
	ERROR_CTX_SESSION_IN_USE                                                  syscall.Errno = 7062
	ERROR_CTX_NO_FORCE_LOGOFF                                                 syscall.Errno = 7063
	ERROR_CTX_ACCOUNT_RESTRICTION                                             syscall.Errno = 7064
	ERROR_RDP_PROTOCOL_ERROR                                                  syscall.Errno = 7065
	ERROR_CTX_CDM_CONNECT                                                     syscall.Errno = 7066
	ERROR_CTX_CDM_DISCONNECT                                                  syscall.Errno = 7067
	ERROR_CTX_SECURITY_LAYER_ERROR                                            syscall.Errno = 7068
	ERROR_TS_INCOMPATIBLE_SESSIONS                                            syscall.Errno = 7069
	ERROR_TS_VIDEO_SUBSYSTEM_ERROR                                            syscall.Errno = 7070
	FRS_ERR_INVALID_API_SEQUENCE                                              syscall.Errno = 8001
	FRS_ERR_STARTING_SERVICE                                                  syscall.Errno = 8002
	FRS_ERR_STOPPING_SERVICE                                                  syscall.Errno = 8003
	FRS_ERR_INTERNAL_API                                                      syscall.Errno = 8004
	FRS_ERR_INTERNAL                                                          syscall.Errno = 8005
	FRS_ERR_SERVICE_COMM                                                      syscall.Errno = 8006
	FRS_ERR_INSUFFICIENT_PRIV                                                 syscall.Errno = 8007
	FRS_ERR_AUTHENTICATION                                                    syscall.Errno = 8008
	FRS_ERR_PARENT_INSUFFICIENT_PRIV                                          syscall.Errno = 8009
	FRS_ERR_PARENT_AUTHENTICATION                                             syscall.Errno = 8010
	FRS_ERR_CHILD_TO_PARENT_COMM                                              syscall.Errno = 8011
	FRS_ERR_PARENT_TO_CHILD_COMM                                              syscall.Errno = 8012
	FRS_ERR_SYSVOL_POPULATE                                                   syscall.Errno = 8013
	FRS_ERR_SYSVOL_POPULATE_TIMEOUT                                           syscall.Errno = 8014
	FRS_ERR_SYSVOL_IS_BUSY                                                    syscall.Errno = 8015
	FRS_ERR_SYSVOL_DEMOTE                                                     syscall.Errno = 8016
	FRS_ERR_INVALID_SERVICE_PARAMETER                                         syscall.Errno = 8017
	DS_S_SUCCESS                                                                            = ERROR_SUCCESS
	ERROR_DS_NOT_INSTALLED                                                    syscall.Errno = 8200
	ERROR_DS_MEMBERSHIP_EVALUATED_LOCALLY                                     syscall.Errno = 8201
	ERROR_DS_NO_ATTRIBUTE_OR_VALUE                                            syscall.Errno = 8202
	ERROR_DS_INVALID_ATTRIBUTE_SYNTAX                                         syscall.Errno = 8203
	ERROR_DS_ATTRIBUTE_TYPE_UNDEFINED                                         syscall.Errno = 8204
	ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS                                        syscall.Errno = 8205
	ERROR_DS_BUSY                                                             syscall.Errno = 8206
	ERROR_DS_UNAVAILABLE                                                      syscall.Errno = 8207
	ERROR_DS_NO_RIDS_ALLOCATED                                                syscall.Errno = 8208
	ERROR_DS_NO_MORE_RIDS                                                     syscall.Errno = 8209
	ERROR_DS_INCORRECT_ROLE_OWNER                                             syscall.Errno = 8210
	ERROR_DS_RIDMGR_INIT_ERROR                                                syscall.Errno = 8211
	ERROR_DS_OBJ_CLASS_VIOLATION                                              syscall.Errno = 8212
	ERROR_DS_CANT_ON_NON_LEAF                                                 syscall.Errno = 8213
	ERROR_DS_CANT_ON_RDN                                                      syscall.Errno = 8214
	ERROR_DS_CANT_MOD_OBJ_CLASS                                               syscall.Errno = 8215
	ERROR_DS_CROSS_DOM_MOVE_ERROR                                             syscall.Errno = 8216
	ERROR_DS_GC_NOT_AVAILABLE                                                 syscall.Errno = 8217
	ERROR_SHARED_POLICY       
"""




```