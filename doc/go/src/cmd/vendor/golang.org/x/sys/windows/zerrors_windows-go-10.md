Response:
Let's break down the thought process for answering this request.

1. **Understanding the Core Request:** The user provided a snippet of Go code defining constants with `Handle` or `NTStatus` types, all within a specific file path, and asked for its function, potential Go language feature implementation, examples, command-line arguments (if any), common mistakes, and a summary. The "part 11 of 15" is a meta-instruction, likely indicating a larger context but doesn't directly influence the analysis of *this specific snippet*.

2. **Initial Analysis of the Code:**
    * **Constants:** The code primarily defines a large number of constants.
    * **Types:** The constants are assigned values and are of type `Handle` or `NTStatus`. This suggests these are custom types, likely defined elsewhere in the same package or a related one. The hexadecimal values are typical for error codes or status codes in Windows.
    * **Naming Convention:** The constant names are descriptive, often using underscores and all caps, which is a common convention for constants in many programming languages. The prefixing like `WEP_E_`, `ERROR_SVHDX_`, `WININET_E_`, `SQLITE_E_`, `UTC_E_`, `WINML_ERR_`, `STATUS_` clearly indicates different subsystems or libraries these errors relate to.
    * **File Path:** The path `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` is crucial. `vendor` implies this is a dependency, `golang.org/x/sys/windows` points to the Go standard library's system-level functionality for Windows. The `zerrors_windows.go` name strongly suggests it's related to Windows error codes.

3. **Inferring the Function:** Based on the above observations, the primary function of this code is to **define a comprehensive set of Windows-specific error codes and status codes as Go constants.**  These constants provide symbolic names for the numerical error values, making the code more readable and maintainable.

4. **Identifying the Go Language Feature:** This directly corresponds to Go's **constant declaration** feature. Go allows you to define named constants with specific types.

5. **Creating a Go Code Example:**
    * **Goal:** Demonstrate how these constants would be used in practice.
    * **Key Idea:**  Error handling is the most obvious use case for error codes. Simulating a function that might return one of these specific errors makes sense.
    * **Structure:** Define a function that could potentially fail, returning an error. Inside the function, simulate a scenario where one of these error conditions might occur (for simplicity, just return one directly). In the `main` function, call the function and check the returned error. Use type assertion or comparison to check if the returned error is one of the defined constants.
    * **Imports:**  Need `fmt` for printing and potentially the `errors` package if creating generic errors for comparison (though in this specific case, direct comparison with the constants is sufficient).
    * **Assumptions (for the example):** Assume the `Handle` and `NTStatus` types are comparable to integers or have a `String()` method for easier printing.

6. **Command-Line Arguments:**  Reviewing the code snippet, there's no indication of any command-line argument processing. This file is purely about constant definitions. So, the answer here is simply that it doesn't handle command-line arguments.

7. **Common Mistakes:**  Think about how developers might misuse or misunderstand these constants:
    * **Incorrect Comparison:** Comparing against the wrong type or using incorrect equality checks.
    * **Ignoring Error Types:** Not checking the specific error type and just assuming a generic error occurred. This can lead to incorrect error handling logic.
    * **Not Understanding the Scope:** While not directly shown in the snippet, it's possible a developer might try to use these constants without importing the correct package.

8. **Summarizing the Function:** Condense the primary function into a concise statement. Highlight that it provides a mapping between symbolic names and numerical values for Windows errors, improving code clarity and maintainability.

9. **Review and Refine:**  Read through the entire answer, ensuring it's clear, accurate, and addresses all parts of the user's request. Check for typos and grammatical errors. Make sure the Go code example is functional and easy to understand.

**(Self-Correction Example during the process):** Initially, I might think about ways to convert these constants *to* error types. However, the code snippet itself doesn't show that logic. It only *defines* the constants. So, the example should focus on *using* these pre-defined constants in error handling, rather than creating them dynamically. This leads to the example focusing on direct comparison. Also, initially, I considered using `errors.Is` for error comparison, but since these are specific constants, direct equality checks are simpler and sufficient for demonstration purposes.
这个Go语言代码片段定义了一系列常量，这些常量代表了Windows操作系统中各种各样的错误码和状态码。  它们被组织在不同的命名空间下，例如 `WEP_E_`, `ERROR_SVHDX_`, `WININET_E_`, `SQLITE_E_`, `UTC_E_`, `WINML_ERR_`, `STATUS_` 等， 每一个常量都被赋值为一个十六进制的数值，并且类型被定义为 `Handle` 或者 `NTStatus`。

**它的主要功能是:**

1. **提供Windows错误码的符号化表示:** 将难以记忆的数字错误码转换为具有语义的常量名，提高代码的可读性和可维护性。
2. **作为Go程序处理Windows错误的参考:**  开发者可以在Go程序中引用这些常量，用于判断Windows API调用是否成功，以及具体遇到了哪种错误。

**它可以被推断为是Go语言中用于处理Windows系统调用或API错误的一种实现方式。** Go的 `syscall` 包允许Go程序调用底层的操作系统API，而这些常量则用于解释这些API调用返回的错误代码。

**Go代码举例说明:**

假设我们有一个函数尝试创建一个文件，如果失败，我们想根据返回的错误码进行不同的处理。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 假设 CreateFileW 是一个用于创建文件的 Windows API 函数的封装
// (实际上 syscall 包已经提供了，这里只是为了演示)
var (
	kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
	createFileW = kernel32DLL.NewProc("CreateFileW")
)

func CreateFile(filename string) error {
	filenameUTF16, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return err
	}
	handle, _, err := syscall.SyscallN(createFileW.Addr(), uintptr(unsafe.Pointer(filenameUTF16)), syscall.GENERIC_WRITE, 0, 0, syscall.CREATE_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if handle == syscall.InvalidHandle {
		// 将 syscall.Errno 转换为更具描述性的错误
		if errno, ok := err.(syscall.Errno); ok {
			switch errno {
			case windows.ERROR_FILE_EXISTS:
				return fmt.Errorf("文件已存在: %w", err)
			case windows.ERROR_ACCESS_DENIED:
				return fmt.Errorf("访问被拒绝: %w", err)
			// ... 可以添加更多错误码的判断
			default:
				return fmt.Errorf("创建文件失败，错误码: %d", errno)
			}
		}
		return fmt.Errorf("创建文件失败: %w", err)
	}
	syscall.CloseHandle(syscall.Handle(handle))
	return nil
}

func main() {
	err := CreateFile("test.txt")
	if err != nil {
		fmt.Println("创建文件出错:", err)
	} else {
		fmt.Println("文件创建成功")
	}
}
```

**假设的输入与输出:**

* **假设输入:**  `filename = "test.txt"`， 并且当前目录下已经存在名为 `test.txt` 的文件。
* **预期输出:** `创建文件出错: 文件已存在: The file exists.`

* **假设输入:** `filename = "/protected/test.txt"`， 并且当前用户没有权限在 `/protected/` 目录下创建文件。
* **预期输出:** `创建文件出错: 访问被拒绝: Access is denied.`

**代码推理:**

在这个例子中，`CreateFile` 函数尝试调用 Windows API `CreateFileW` 来创建一个文件。 如果 `CreateFileW` 调用失败，它会返回一个 `syscall.Errno` 类型的错误。 通过将 `syscall.Errno` 与 `zerrors_windows.go` 中定义的常量进行比较，我们可以更精确地判断出具体的错误原因，并返回更具描述性的错误信息。

**命令行参数的具体处理:**

这个代码片段本身不涉及命令行参数的处理。 它只是定义了一些常量。 命令行参数的处理通常会在 `main` 函数中使用 `os.Args` 或者使用 `flag` 包来实现。

**使用者易犯错的点:**

* **错误地比较错误码:**  直接比较 `error` 类型的值可能是不准确的，因为 `error` 是一个接口。  应该先将 `error` 类型断言为 `syscall.Errno`，然后再与常量进行比较。  例如，错误地使用 `err == windows.ERROR_FILE_EXISTS` 可能不会得到预期的结果。  应该使用类型断言：

```go
if errno, ok := err.(syscall.Errno); ok && errno == windows.ERROR_FILE_EXISTS {
    // ...
}
```

* **忽略了错误的类型:**  有时 Windows API 可能会返回不同类型的错误。 只检查 `syscall.Errno` 可能无法捕获所有类型的错误。

**功能归纳:**

这段 `zerrors_windows.go` 代码片段是Go语言 `golang.org/x/sys/windows` 包的一部分， 其主要功能是**定义了大量的Windows操作系统相关的错误码和状态码常量， 用于在Go程序中处理Windows系统调用或API调用时返回的错误信息，提高代码的可读性和错误处理的准确性。**  它是Go语言与底层Windows系统交互的重要组成部分。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第11部分，共15部分，请归纳一下它的功能

"""
                         Handle        = 0x88010003
	WEP_E_LOCK_NOT_CONFIGURED                                                 Handle        = 0x88010004
	WEP_E_PROTECTION_SUSPENDED                                                Handle        = 0x88010005
	WEP_E_NO_LICENSE                                                          Handle        = 0x88010006
	WEP_E_OS_NOT_PROTECTED                                                    Handle        = 0x88010007
	WEP_E_UNEXPECTED_FAIL                                                     Handle        = 0x88010008
	WEP_E_BUFFER_TOO_LARGE                                                    Handle        = 0x88010009
	ERROR_SVHDX_ERROR_STORED                                                  Handle        = 0xC05C0000
	ERROR_SVHDX_ERROR_NOT_AVAILABLE                                           Handle        = 0xC05CFF00
	ERROR_SVHDX_UNIT_ATTENTION_AVAILABLE                                      Handle        = 0xC05CFF01
	ERROR_SVHDX_UNIT_ATTENTION_CAPACITY_DATA_CHANGED                          Handle        = 0xC05CFF02
	ERROR_SVHDX_UNIT_ATTENTION_RESERVATIONS_PREEMPTED                         Handle        = 0xC05CFF03
	ERROR_SVHDX_UNIT_ATTENTION_RESERVATIONS_RELEASED                          Handle        = 0xC05CFF04
	ERROR_SVHDX_UNIT_ATTENTION_REGISTRATIONS_PREEMPTED                        Handle        = 0xC05CFF05
	ERROR_SVHDX_UNIT_ATTENTION_OPERATING_DEFINITION_CHANGED                   Handle        = 0xC05CFF06
	ERROR_SVHDX_RESERVATION_CONFLICT                                          Handle        = 0xC05CFF07
	ERROR_SVHDX_WRONG_FILE_TYPE                                               Handle        = 0xC05CFF08
	ERROR_SVHDX_VERSION_MISMATCH                                              Handle        = 0xC05CFF09
	ERROR_VHD_SHARED                                                          Handle        = 0xC05CFF0A
	ERROR_SVHDX_NO_INITIATOR                                                  Handle        = 0xC05CFF0B
	ERROR_VHDSET_BACKING_STORAGE_NOT_FOUND                                    Handle        = 0xC05CFF0C
	ERROR_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP                               Handle        = 0xC05D0000
	ERROR_SMB_BAD_CLUSTER_DIALECT                                             Handle        = 0xC05D0001
	WININET_E_OUT_OF_HANDLES                                                  Handle        = 0x80072EE1
	WININET_E_TIMEOUT                                                         Handle        = 0x80072EE2
	WININET_E_EXTENDED_ERROR                                                  Handle        = 0x80072EE3
	WININET_E_INTERNAL_ERROR                                                  Handle        = 0x80072EE4
	WININET_E_INVALID_URL                                                     Handle        = 0x80072EE5
	WININET_E_UNRECOGNIZED_SCHEME                                             Handle        = 0x80072EE6
	WININET_E_NAME_NOT_RESOLVED                                               Handle        = 0x80072EE7
	WININET_E_PROTOCOL_NOT_FOUND                                              Handle        = 0x80072EE8
	WININET_E_INVALID_OPTION                                                  Handle        = 0x80072EE9
	WININET_E_BAD_OPTION_LENGTH                                               Handle        = 0x80072EEA
	WININET_E_OPTION_NOT_SETTABLE                                             Handle        = 0x80072EEB
	WININET_E_SHUTDOWN                                                        Handle        = 0x80072EEC
	WININET_E_INCORRECT_USER_NAME                                             Handle        = 0x80072EED
	WININET_E_INCORRECT_PASSWORD                                              Handle        = 0x80072EEE
	WININET_E_LOGIN_FAILURE                                                   Handle        = 0x80072EEF
	WININET_E_INVALID_OPERATION                                               Handle        = 0x80072EF0
	WININET_E_OPERATION_CANCELLED                                             Handle        = 0x80072EF1
	WININET_E_INCORRECT_HANDLE_TYPE                                           Handle        = 0x80072EF2
	WININET_E_INCORRECT_HANDLE_STATE                                          Handle        = 0x80072EF3
	WININET_E_NOT_PROXY_REQUEST                                               Handle        = 0x80072EF4
	WININET_E_REGISTRY_VALUE_NOT_FOUND                                        Handle        = 0x80072EF5
	WININET_E_BAD_REGISTRY_PARAMETER                                          Handle        = 0x80072EF6
	WININET_E_NO_DIRECT_ACCESS                                                Handle        = 0x80072EF7
	WININET_E_NO_CONTEXT                                                      Handle        = 0x80072EF8
	WININET_E_NO_CALLBACK                                                     Handle        = 0x80072EF9
	WININET_E_REQUEST_PENDING                                                 Handle        = 0x80072EFA
	WININET_E_INCORRECT_FORMAT                                                Handle        = 0x80072EFB
	WININET_E_ITEM_NOT_FOUND                                                  Handle        = 0x80072EFC
	WININET_E_CANNOT_CONNECT                                                  Handle        = 0x80072EFD
	WININET_E_CONNECTION_ABORTED                                              Handle        = 0x80072EFE
	WININET_E_CONNECTION_RESET                                                Handle        = 0x80072EFF
	WININET_E_FORCE_RETRY                                                     Handle        = 0x80072F00
	WININET_E_INVALID_PROXY_REQUEST                                           Handle        = 0x80072F01
	WININET_E_NEED_UI                                                         Handle        = 0x80072F02
	WININET_E_HANDLE_EXISTS                                                   Handle        = 0x80072F04
	WININET_E_SEC_CERT_DATE_INVALID                                           Handle        = 0x80072F05
	WININET_E_SEC_CERT_CN_INVALID                                             Handle        = 0x80072F06
	WININET_E_HTTP_TO_HTTPS_ON_REDIR                                          Handle        = 0x80072F07
	WININET_E_HTTPS_TO_HTTP_ON_REDIR                                          Handle        = 0x80072F08
	WININET_E_MIXED_SECURITY                                                  Handle        = 0x80072F09
	WININET_E_CHG_POST_IS_NON_SECURE                                          Handle        = 0x80072F0A
	WININET_E_POST_IS_NON_SECURE                                              Handle        = 0x80072F0B
	WININET_E_CLIENT_AUTH_CERT_NEEDED                                         Handle        = 0x80072F0C
	WININET_E_INVALID_CA                                                      Handle        = 0x80072F0D
	WININET_E_CLIENT_AUTH_NOT_SETUP                                           Handle        = 0x80072F0E
	WININET_E_ASYNC_THREAD_FAILED                                             Handle        = 0x80072F0F
	WININET_E_REDIRECT_SCHEME_CHANGE                                          Handle        = 0x80072F10
	WININET_E_DIALOG_PENDING                                                  Handle        = 0x80072F11
	WININET_E_RETRY_DIALOG                                                    Handle        = 0x80072F12
	WININET_E_NO_NEW_CONTAINERS                                               Handle        = 0x80072F13
	WININET_E_HTTPS_HTTP_SUBMIT_REDIR                                         Handle        = 0x80072F14
	WININET_E_SEC_CERT_ERRORS                                                 Handle        = 0x80072F17
	WININET_E_SEC_CERT_REV_FAILED                                             Handle        = 0x80072F19
	WININET_E_HEADER_NOT_FOUND                                                Handle        = 0x80072F76
	WININET_E_DOWNLEVEL_SERVER                                                Handle        = 0x80072F77
	WININET_E_INVALID_SERVER_RESPONSE                                         Handle        = 0x80072F78
	WININET_E_INVALID_HEADER                                                  Handle        = 0x80072F79
	WININET_E_INVALID_QUERY_REQUEST                                           Handle        = 0x80072F7A
	WININET_E_HEADER_ALREADY_EXISTS                                           Handle        = 0x80072F7B
	WININET_E_REDIRECT_FAILED                                                 Handle        = 0x80072F7C
	WININET_E_SECURITY_CHANNEL_ERROR                                          Handle        = 0x80072F7D
	WININET_E_UNABLE_TO_CACHE_FILE                                            Handle        = 0x80072F7E
	WININET_E_TCPIP_NOT_INSTALLED                                             Handle        = 0x80072F7F
	WININET_E_DISCONNECTED                                                    Handle        = 0x80072F83
	WININET_E_SERVER_UNREACHABLE                                              Handle        = 0x80072F84
	WININET_E_PROXY_SERVER_UNREACHABLE                                        Handle        = 0x80072F85
	WININET_E_BAD_AUTO_PROXY_SCRIPT                                           Handle        = 0x80072F86
	WININET_E_UNABLE_TO_DOWNLOAD_SCRIPT                                       Handle        = 0x80072F87
	WININET_E_SEC_INVALID_CERT                                                Handle        = 0x80072F89
	WININET_E_SEC_CERT_REVOKED                                                Handle        = 0x80072F8A
	WININET_E_FAILED_DUETOSECURITYCHECK                                       Handle        = 0x80072F8B
	WININET_E_NOT_INITIALIZED                                                 Handle        = 0x80072F8C
	WININET_E_LOGIN_FAILURE_DISPLAY_ENTITY_BODY                               Handle        = 0x80072F8E
	WININET_E_DECODING_FAILED                                                 Handle        = 0x80072F8F
	WININET_E_NOT_REDIRECTED                                                  Handle        = 0x80072F80
	WININET_E_COOKIE_NEEDS_CONFIRMATION                                       Handle        = 0x80072F81
	WININET_E_COOKIE_DECLINED                                                 Handle        = 0x80072F82
	WININET_E_REDIRECT_NEEDS_CONFIRMATION                                     Handle        = 0x80072F88
	SQLITE_E_ERROR                                                            Handle        = 0x87AF0001
	SQLITE_E_INTERNAL                                                         Handle        = 0x87AF0002
	SQLITE_E_PERM                                                             Handle        = 0x87AF0003
	SQLITE_E_ABORT                                                            Handle        = 0x87AF0004
	SQLITE_E_BUSY                                                             Handle        = 0x87AF0005
	SQLITE_E_LOCKED                                                           Handle        = 0x87AF0006
	SQLITE_E_NOMEM                                                            Handle        = 0x87AF0007
	SQLITE_E_READONLY                                                         Handle        = 0x87AF0008
	SQLITE_E_INTERRUPT                                                        Handle        = 0x87AF0009
	SQLITE_E_IOERR                                                            Handle        = 0x87AF000A
	SQLITE_E_CORRUPT                                                          Handle        = 0x87AF000B
	SQLITE_E_NOTFOUND                                                         Handle        = 0x87AF000C
	SQLITE_E_FULL                                                             Handle        = 0x87AF000D
	SQLITE_E_CANTOPEN                                                         Handle        = 0x87AF000E
	SQLITE_E_PROTOCOL                                                         Handle        = 0x87AF000F
	SQLITE_E_EMPTY                                                            Handle        = 0x87AF0010
	SQLITE_E_SCHEMA                                                           Handle        = 0x87AF0011
	SQLITE_E_TOOBIG                                                           Handle        = 0x87AF0012
	SQLITE_E_CONSTRAINT                                                       Handle        = 0x87AF0013
	SQLITE_E_MISMATCH                                                         Handle        = 0x87AF0014
	SQLITE_E_MISUSE                                                           Handle        = 0x87AF0015
	SQLITE_E_NOLFS                                                            Handle        = 0x87AF0016
	SQLITE_E_AUTH                                                             Handle        = 0x87AF0017
	SQLITE_E_FORMAT                                                           Handle        = 0x87AF0018
	SQLITE_E_RANGE                                                            Handle        = 0x87AF0019
	SQLITE_E_NOTADB                                                           Handle        = 0x87AF001A
	SQLITE_E_NOTICE                                                           Handle        = 0x87AF001B
	SQLITE_E_WARNING                                                          Handle        = 0x87AF001C
	SQLITE_E_ROW                                                              Handle        = 0x87AF0064
	SQLITE_E_DONE                                                             Handle        = 0x87AF0065
	SQLITE_E_IOERR_READ                                                       Handle        = 0x87AF010A
	SQLITE_E_IOERR_SHORT_READ                                                 Handle        = 0x87AF020A
	SQLITE_E_IOERR_WRITE                                                      Handle        = 0x87AF030A
	SQLITE_E_IOERR_FSYNC                                                      Handle        = 0x87AF040A
	SQLITE_E_IOERR_DIR_FSYNC                                                  Handle        = 0x87AF050A
	SQLITE_E_IOERR_TRUNCATE                                                   Handle        = 0x87AF060A
	SQLITE_E_IOERR_FSTAT                                                      Handle        = 0x87AF070A
	SQLITE_E_IOERR_UNLOCK                                                     Handle        = 0x87AF080A
	SQLITE_E_IOERR_RDLOCK                                                     Handle        = 0x87AF090A
	SQLITE_E_IOERR_DELETE                                                     Handle        = 0x87AF0A0A
	SQLITE_E_IOERR_BLOCKED                                                    Handle        = 0x87AF0B0A
	SQLITE_E_IOERR_NOMEM                                                      Handle        = 0x87AF0C0A
	SQLITE_E_IOERR_ACCESS                                                     Handle        = 0x87AF0D0A
	SQLITE_E_IOERR_CHECKRESERVEDLOCK                                          Handle        = 0x87AF0E0A
	SQLITE_E_IOERR_LOCK                                                       Handle        = 0x87AF0F0A
	SQLITE_E_IOERR_CLOSE                                                      Handle        = 0x87AF100A
	SQLITE_E_IOERR_DIR_CLOSE                                                  Handle        = 0x87AF110A
	SQLITE_E_IOERR_SHMOPEN                                                    Handle        = 0x87AF120A
	SQLITE_E_IOERR_SHMSIZE                                                    Handle        = 0x87AF130A
	SQLITE_E_IOERR_SHMLOCK                                                    Handle        = 0x87AF140A
	SQLITE_E_IOERR_SHMMAP                                                     Handle        = 0x87AF150A
	SQLITE_E_IOERR_SEEK                                                       Handle        = 0x87AF160A
	SQLITE_E_IOERR_DELETE_NOENT                                               Handle        = 0x87AF170A
	SQLITE_E_IOERR_MMAP                                                       Handle        = 0x87AF180A
	SQLITE_E_IOERR_GETTEMPPATH                                                Handle        = 0x87AF190A
	SQLITE_E_IOERR_CONVPATH                                                   Handle        = 0x87AF1A0A
	SQLITE_E_IOERR_VNODE                                                      Handle        = 0x87AF1A02
	SQLITE_E_IOERR_AUTH                                                       Handle        = 0x87AF1A03
	SQLITE_E_LOCKED_SHAREDCACHE                                               Handle        = 0x87AF0106
	SQLITE_E_BUSY_RECOVERY                                                    Handle        = 0x87AF0105
	SQLITE_E_BUSY_SNAPSHOT                                                    Handle        = 0x87AF0205
	SQLITE_E_CANTOPEN_NOTEMPDIR                                               Handle        = 0x87AF010E
	SQLITE_E_CANTOPEN_ISDIR                                                   Handle        = 0x87AF020E
	SQLITE_E_CANTOPEN_FULLPATH                                                Handle        = 0x87AF030E
	SQLITE_E_CANTOPEN_CONVPATH                                                Handle        = 0x87AF040E
	SQLITE_E_CORRUPT_VTAB                                                     Handle        = 0x87AF010B
	SQLITE_E_READONLY_RECOVERY                                                Handle        = 0x87AF0108
	SQLITE_E_READONLY_CANTLOCK                                                Handle        = 0x87AF0208
	SQLITE_E_READONLY_ROLLBACK                                                Handle        = 0x87AF0308
	SQLITE_E_READONLY_DBMOVED                                                 Handle        = 0x87AF0408
	SQLITE_E_ABORT_ROLLBACK                                                   Handle        = 0x87AF0204
	SQLITE_E_CONSTRAINT_CHECK                                                 Handle        = 0x87AF0113
	SQLITE_E_CONSTRAINT_COMMITHOOK                                            Handle        = 0x87AF0213
	SQLITE_E_CONSTRAINT_FOREIGNKEY                                            Handle        = 0x87AF0313
	SQLITE_E_CONSTRAINT_FUNCTION                                              Handle        = 0x87AF0413
	SQLITE_E_CONSTRAINT_NOTNULL                                               Handle        = 0x87AF0513
	SQLITE_E_CONSTRAINT_PRIMARYKEY                                            Handle        = 0x87AF0613
	SQLITE_E_CONSTRAINT_TRIGGER                                               Handle        = 0x87AF0713
	SQLITE_E_CONSTRAINT_UNIQUE                                                Handle        = 0x87AF0813
	SQLITE_E_CONSTRAINT_VTAB                                                  Handle        = 0x87AF0913
	SQLITE_E_CONSTRAINT_ROWID                                                 Handle        = 0x87AF0A13
	SQLITE_E_NOTICE_RECOVER_WAL                                               Handle        = 0x87AF011B
	SQLITE_E_NOTICE_RECOVER_ROLLBACK                                          Handle        = 0x87AF021B
	SQLITE_E_WARNING_AUTOINDEX                                                Handle        = 0x87AF011C
	UTC_E_TOGGLE_TRACE_STARTED                                                Handle        = 0x87C51001
	UTC_E_ALTERNATIVE_TRACE_CANNOT_PREEMPT                                    Handle        = 0x87C51002
	UTC_E_AOT_NOT_RUNNING                                                     Handle        = 0x87C51003
	UTC_E_SCRIPT_TYPE_INVALID                                                 Handle        = 0x87C51004
	UTC_E_SCENARIODEF_NOT_FOUND                                               Handle        = 0x87C51005
	UTC_E_TRACEPROFILE_NOT_FOUND                                              Handle        = 0x87C51006
	UTC_E_FORWARDER_ALREADY_ENABLED                                           Handle        = 0x87C51007
	UTC_E_FORWARDER_ALREADY_DISABLED                                          Handle        = 0x87C51008
	UTC_E_EVENTLOG_ENTRY_MALFORMED                                            Handle        = 0x87C51009
	UTC_E_DIAGRULES_SCHEMAVERSION_MISMATCH                                    Handle        = 0x87C5100A
	UTC_E_SCRIPT_TERMINATED                                                   Handle        = 0x87C5100B
	UTC_E_INVALID_CUSTOM_FILTER                                               Handle        = 0x87C5100C
	UTC_E_TRACE_NOT_RUNNING                                                   Handle        = 0x87C5100D
	UTC_E_REESCALATED_TOO_QUICKLY                                             Handle        = 0x87C5100E
	UTC_E_ESCALATION_ALREADY_RUNNING                                          Handle        = 0x87C5100F
	UTC_E_PERFTRACK_ALREADY_TRACING                                           Handle        = 0x87C51010
	UTC_E_REACHED_MAX_ESCALATIONS                                             Handle        = 0x87C51011
	UTC_E_FORWARDER_PRODUCER_MISMATCH                                         Handle        = 0x87C51012
	UTC_E_INTENTIONAL_SCRIPT_FAILURE                                          Handle        = 0x87C51013
	UTC_E_SQM_INIT_FAILED                                                     Handle        = 0x87C51014
	UTC_E_NO_WER_LOGGER_SUPPORTED                                             Handle        = 0x87C51015
	UTC_E_TRACERS_DONT_EXIST                                                  Handle        = 0x87C51016
	UTC_E_WINRT_INIT_FAILED                                                   Handle        = 0x87C51017
	UTC_E_SCENARIODEF_SCHEMAVERSION_MISMATCH                                  Handle        = 0x87C51018
	UTC_E_INVALID_FILTER                                                      Handle        = 0x87C51019
	UTC_E_EXE_TERMINATED                                                      Handle        = 0x87C5101A
	UTC_E_ESCALATION_NOT_AUTHORIZED                                           Handle        = 0x87C5101B
	UTC_E_SETUP_NOT_AUTHORIZED                                                Handle        = 0x87C5101C
	UTC_E_CHILD_PROCESS_FAILED                                                Handle        = 0x87C5101D
	UTC_E_COMMAND_LINE_NOT_AUTHORIZED                                         Handle        = 0x87C5101E
	UTC_E_CANNOT_LOAD_SCENARIO_EDITOR_XML                                     Handle        = 0x87C5101F
	UTC_E_ESCALATION_TIMED_OUT                                                Handle        = 0x87C51020
	UTC_E_SETUP_TIMED_OUT                                                     Handle        = 0x87C51021
	UTC_E_TRIGGER_MISMATCH                                                    Handle        = 0x87C51022
	UTC_E_TRIGGER_NOT_FOUND                                                   Handle        = 0x87C51023
	UTC_E_SIF_NOT_SUPPORTED                                                   Handle        = 0x87C51024
	UTC_E_DELAY_TERMINATED                                                    Handle        = 0x87C51025
	UTC_E_DEVICE_TICKET_ERROR                                                 Handle        = 0x87C51026
	UTC_E_TRACE_BUFFER_LIMIT_EXCEEDED                                         Handle        = 0x87C51027
	UTC_E_API_RESULT_UNAVAILABLE                                              Handle        = 0x87C51028
	UTC_E_RPC_TIMEOUT                                                         Handle        = 0x87C51029
	UTC_E_RPC_WAIT_FAILED                                                     Handle        = 0x87C5102A
	UTC_E_API_BUSY                                                            Handle        = 0x87C5102B
	UTC_E_TRACE_MIN_DURATION_REQUIREMENT_NOT_MET                              Handle        = 0x87C5102C
	UTC_E_EXCLUSIVITY_NOT_AVAILABLE                                           Handle        = 0x87C5102D
	UTC_E_GETFILE_FILE_PATH_NOT_APPROVED                                      Handle        = 0x87C5102E
	UTC_E_ESCALATION_DIRECTORY_ALREADY_EXISTS                                 Handle        = 0x87C5102F
	UTC_E_TIME_TRIGGER_ON_START_INVALID                                       Handle        = 0x87C51030
	UTC_E_TIME_TRIGGER_ONLY_VALID_ON_SINGLE_TRANSITION                        Handle        = 0x87C51031
	UTC_E_TIME_TRIGGER_INVALID_TIME_RANGE                                     Handle        = 0x87C51032
	UTC_E_MULTIPLE_TIME_TRIGGER_ON_SINGLE_STATE                               Handle        = 0x87C51033
	UTC_E_BINARY_MISSING                                                      Handle        = 0x87C51034
	UTC_E_NETWORK_CAPTURE_NOT_ALLOWED                                         Handle        = 0x87C51035
	UTC_E_FAILED_TO_RESOLVE_CONTAINER_ID                                      Handle        = 0x87C51036
	UTC_E_UNABLE_TO_RESOLVE_SESSION                                           Handle        = 0x87C51037
	UTC_E_THROTTLED                                                           Handle        = 0x87C51038
	UTC_E_UNAPPROVED_SCRIPT                                                   Handle        = 0x87C51039
	UTC_E_SCRIPT_MISSING                                                      Handle        = 0x87C5103A
	UTC_E_SCENARIO_THROTTLED                                                  Handle        = 0x87C5103B
	UTC_E_API_NOT_SUPPORTED                                                   Handle        = 0x87C5103C
	UTC_E_GETFILE_EXTERNAL_PATH_NOT_APPROVED                                  Handle        = 0x87C5103D
	UTC_E_TRY_GET_SCENARIO_TIMEOUT_EXCEEDED                                   Handle        = 0x87C5103E
	UTC_E_CERT_REV_FAILED                                                     Handle        = 0x87C5103F
	UTC_E_FAILED_TO_START_NDISCAP                                             Handle        = 0x87C51040
	UTC_E_KERNELDUMP_LIMIT_REACHED                                            Handle        = 0x87C51041
	UTC_E_MISSING_AGGREGATE_EVENT_TAG                                         Handle        = 0x87C51042
	UTC_E_INVALID_AGGREGATION_STRUCT                                          Handle        = 0x87C51043
	UTC_E_ACTION_NOT_SUPPORTED_IN_DESTINATION                                 Handle        = 0x87C51044
	UTC_E_FILTER_MISSING_ATTRIBUTE                                            Handle        = 0x87C51045
	UTC_E_FILTER_INVALID_TYPE                                                 Handle        = 0x87C51046
	UTC_E_FILTER_VARIABLE_NOT_FOUND                                           Handle        = 0x87C51047
	UTC_E_FILTER_FUNCTION_RESTRICTED                                          Handle        = 0x87C51048
	UTC_E_FILTER_VERSION_MISMATCH                                             Handle        = 0x87C51049
	UTC_E_FILTER_INVALID_FUNCTION                                             Handle        = 0x87C51050
	UTC_E_FILTER_INVALID_FUNCTION_PARAMS                                      Handle        = 0x87C51051
	UTC_E_FILTER_INVALID_COMMAND                                              Handle        = 0x87C51052
	UTC_E_FILTER_ILLEGAL_EVAL                                                 Handle        = 0x87C51053
	UTC_E_TTTRACER_RETURNED_ERROR                                             Handle        = 0x87C51054
	UTC_E_AGENT_DIAGNOSTICS_TOO_LARGE                                         Handle        = 0x87C51055
	UTC_E_FAILED_TO_RECEIVE_AGENT_DIAGNOSTICS                                 Handle        = 0x87C51056
	UTC_E_SCENARIO_HAS_NO_ACTIONS                                             Handle        = 0x87C51057
	UTC_E_TTTRACER_STORAGE_FULL                                               Handle        = 0x87C51058
	UTC_E_INSUFFICIENT_SPACE_TO_START_TRACE                                   Handle        = 0x87C51059
	UTC_E_ESCALATION_CANCELLED_AT_SHUTDOWN                                    Handle        = 0x87C5105A
	UTC_E_GETFILEINFOACTION_FILE_NOT_APPROVED                                 Handle        = 0x87C5105B
	UTC_E_SETREGKEYACTION_TYPE_NOT_APPROVED                                   Handle        = 0x87C5105C
	WINML_ERR_INVALID_DEVICE                                                  Handle        = 0x88900001
	WINML_ERR_INVALID_BINDING                                                 Handle        = 0x88900002
	WINML_ERR_VALUE_NOTFOUND                                                  Handle        = 0x88900003
	WINML_ERR_SIZE_MISMATCH                                                   Handle        = 0x88900004
	STATUS_WAIT_0                                                             NTStatus      = 0x00000000
	STATUS_SUCCESS                                                            NTStatus      = 0x00000000
	STATUS_WAIT_1                                                             NTStatus      = 0x00000001
	STATUS_WAIT_2                                                             NTStatus      = 0x00000002
	STATUS_WAIT_3                                                             NTStatus      = 0x00000003
	STATUS_WAIT_63                                                            NTStatus      = 0x0000003F
	STATUS_ABANDONED                                                          NTStatus      = 0x00000080
	STATUS_ABANDONED_WAIT_0                                                   NTStatus      = 0x00000080
	STATUS_ABANDONED_WAIT_63                                                  NTStatus      = 0x000000BF
	STATUS_USER_APC                                                           NTStatus      = 0x000000C0
	STATUS_ALREADY_COMPLETE                                                   NTStatus      = 0x000000FF
	STATUS_KERNEL_APC                                                         NTStatus      = 0x00000100
	STATUS_ALERTED                                                            NTStatus      = 0x00000101
	STATUS_TIMEOUT                                                            NTStatus      = 0x00000102
	STATUS_PENDING                                                            NTStatus      = 0x00000103
	STATUS_REPARSE                                                            NTStatus      = 0x00000104
	STATUS_MORE_ENTRIES                                                       NTStatus      = 0x00000105
	STATUS_NOT_ALL_ASSIGNED                                                   NTStatus      = 0x00000106
	STATUS_SOME_NOT_MAPPED                                                    NTStatus      = 0x00000107
	STATUS_OPLOCK_BREAK_IN_PROGRESS                                           NTStatus      = 0x00000108
	STATUS_VOLUME_MOUNTED                                                     NTStatus      = 0x00000109
	STATUS_RXACT_COMMITTED                                                    NTStatus      = 0x0000010A
	STATUS_NOTIFY_CLEANUP                                                     NTStatus      = 0x0000010B
	STATUS_NOTIFY_ENUM_DIR                                                    NTStatus      = 0x0000010C
	STATUS_NO_QUOTAS_FOR_ACCOUNT                                              NTStatus      = 0x0000010D
	STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED                                   NTStatus      = 0x0000010E
	STATUS_PAGE_FAULT_TRANSITION                                              NTStatus      = 0x00000110
	STATUS_PAGE_FAULT_DEMAND_ZERO                                             NTStatus      = 0x00000111
	STATUS_PAGE_FAULT_COPY_ON_WRITE                                           NTStatus      = 0x00000112
	STATUS_PAGE_FAULT_GUARD_PAGE                                              NTStatus      = 0x00000113
	STATUS_PAGE_FAULT_PAGING_FILE                                             NTStatus      = 0x00000114
	STATUS_CACHE_PAGE_LOCKED                                                  NTStatus      = 0x00000115
	STATUS_CRASH_DUMP                                                         NTStatus      = 0x00000116
	STATUS_BUFFER_ALL_ZEROS                                                   NTStatus      = 0x00000117
	STATUS_REPARSE_OBJECT                                                     NTStatus      = 0x00000118
	STATUS_RESOURCE_REQUIREMENTS_CHANGED                                      NTStatus      = 0x00000119
	STATUS_TRANSLATION_COMPLETE                                               NTStatus      = 0x00000120
	STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY                                    NTStatus      = 0x00000121
	STATUS_NOTHING_TO_TERMINATE                                               NTStatus      = 0x00000122
	STATUS_PROCESS_NOT_IN_JOB                                                 NTStatus      = 0x00000123
	STATUS_PROCESS_IN_JOB                                                     NTStatus      = 0x00000124
	STATUS_VOLSNAP_HIBERNATE_READY                                            NTStatus      = 0x00000125
	STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY                                 NTStatus      = 0x00000126
	STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED                                 NTStatus      = 0x00000127
	STATUS_INTERRUPT_STILL_CONNECTED                                          NTStatus      = 0x00000128
	STATUS_PROCESS_CLONED                                                     NTStatus      = 0x00000129
	STATUS_FILE_LOCKED_WITH_ONLY_READERS                                      NTStatus      = 0x0000012A
	STATUS_FILE_LOCKED_WITH_WRITERS                                           NTStatus      = 0x0000012B
	STATUS_VALID_IMAGE_HASH                                                   NTStatus      = 0x0000012C
	STATUS_VALID_CATALOG_HASH                                                 NTStatus      = 0x0000012D
	STATUS_VALID_STRONG_CODE_HASH                                             NTStatus      = 0x0000012E
	STATUS_GHOSTED                                                            NTStatus      = 0x0000012F
	STATUS_DATA_OVERWRITTEN                                                   NTStatus      = 0x00000130
	STATUS_RESOURCEMANAGER_READ_ONLY                                          NTStatus      = 0x00000202
	STATUS_RING_PREVIOUSLY_EMPTY                                              NTStatus      = 0x00000210
	STATUS_RING_PREVIOUSLY_FULL                                               NTStatus      = 0x00000211
	STATUS_RING_PREVIOUSLY_ABOVE_QUOTA                                        NTStatus      = 0x00000212
	STATUS_RING_NEWLY_EMPTY                                                   NTStatus      = 0x00000213
	STATUS_RING_SIGNAL_OPPOSITE_ENDPOINT                                      NTStatus      = 0x00000214
	STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE                                      NTStatus      = 0x00000215
	STATUS_OPLOCK_HANDLE_CLOSED                                               NTStatus      = 0x00000216
	STATUS_WAIT_FOR_OPLOCK                                                    NTStatus      = 0x00000367
	STATUS_REPARSE_GLOBAL                                                     NTStatus      = 0x00000368
	STATUS_FLT_IO_COMPLETE                                                    NTStatus      = 0x001C0001
	STATUS_OBJECT_NAME_EXISTS                                                 NTStatus      = 0x40000000
	STATUS_THREAD_WAS_SUSPENDED                                               NTStatus      = 0x40000001
	STATUS_WORKING_SET_LIMIT_RANGE                                            NTStatus      = 0x40000002
	STATUS_IMAGE_NOT_AT_BASE                                                  NTStatus      = 0x40000003
	STATUS_RXACT_STATE_CREATED                                                NTStatus      = 0x40000004
	STATUS_SEGMENT_NOTIFICATION                                               NTStatus      = 0x40000005
	STATUS_LOCAL_USER_SESSION_KEY                                             NTStatus      = 0x40000006
	STATUS_BAD_CURRENT_DIRECTORY                                              NTStatus      = 0x40000007
	STATUS_SERIAL_MORE_WRITES                                                 NTStatus      = 0x40000008
	STATUS_REGISTRY_RECOVERED                                                 NTStatus      = 0x40000009
	STATUS_FT_READ_RECOVERY_FROM_BACKUP                                       NTStatus      = 0x4000000A
	STATUS_FT_WRITE_RECOVERY                                                  NTStatus      = 0x4000000B
	STATUS_SERIAL_COUNTER_TIMEOUT                                             NTStatus      = 0x4000000C
	STATUS_NULL_LM_PASSWORD                                                   NTStatus      = 0x4000000D
	STATUS_IMAGE_MACHINE_TYPE_MISMATCH                                        NTStatus      = 0x4000000E
	STATUS_RECEIVE_PARTIAL                                                    NTStatus      = 0x4000000F
	STATUS_RECEIVE_EXPEDITED                                                  NTStatus      = 0x40000010
	STATUS_RECEIVE_PARTIAL_EXPEDITED                                          NTStatus      = 0x40000011
	STATUS_EVENT_DONE                                                         NTStatus      = 0x40000012
	STATUS_EVENT_PENDING                                                      NTStatus      = 0x40000013
	STATUS_CHECKING_FILE_SYSTEM                                               NTStatus      = 0x40000014
	STATUS_FATAL_APP_EXIT                                                     NTStatus      = 0x40000015
	STATUS_PREDEFINED_HANDLE                                                  NTStatus      = 0x40000016
	STATUS_WAS_UNLOCKED                                                       NTStatus      = 0x40000017
	STATUS_SERVICE_NOTIFICATION                                               NTStatus      = 0x40000018
	STATUS_WAS_LOCKED                                                         NTStatus      = 0x40000019
	STATUS_LOG_HARD_ERROR                                                     NTStatus      = 0x4000001A
	STATUS_ALREADY_WIN32                                                      NTStatus      = 0x4000001B
	STATUS_WX86_UNSIMULATE                                                    NTStatus      = 0x4000001C
	STATUS_WX86_CONTINUE                                                      NTStatus      = 0x4000001D
	STATUS_WX86_SINGLE_STEP                                                   NTStatus      = 0x4000001E
	STATUS_WX86_BREAKPOINT                                                    NTStatus      = 0x4000001F
	STATUS_WX86_EXCEPTION_CONTINUE                                            NTStatus      = 0x40000020
	STATUS_WX86_EXCEPTION_LASTCHANCE                                          NTStatus      = 0x40000021
	STATUS_WX86_EXCEPTION_CHAIN                                               NTStatus      = 0x40000022
	STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE                                    NTStatus      = 0x40000023
	STATUS_NO_YIELD_PERFORMED                                                 NTStatus      = 0x40000024
	STATUS_TIMER_RESUME_IGNORED                                               NTStatus      = 0x40000025
	STATUS_ARBITRATION_UNHANDLED                                              NTStatus      = 0x40000026
	STATUS_CARDBUS_NOT_SUPPORTED                                              NTStatus      = 0x40000027
	STATUS_WX86_CREATEWX86TIB                                                 NTStatus      = 0x40000028
	STATUS_MP_PROCESSOR_MISMATCH                                              NTStatus      = 0x40000029
	STATUS_HIBERNATED                                                         NTStatus      = 0x4000002A
	STATUS_RESUME_HIBERNATION                                                 NTStatus      = 0x4000002B
	STATUS_FIRMWARE_UPDATED                                                   NTStatus      = 0x4000002C
	STATUS_DRIVERS_LEAKING_LOCKED_PAGES                                       NTStatus      = 0x4000002D
	STATUS_MESSAGE_RETRIEVED                                                  NTStatus      = 0x4000002E
	STATUS_SYSTEM_POWERSTATE_TRANSITION                                       NTStatus      = 0x4000002F
	STATUS_ALPC_CHECK_COMPLETION_LIST                                         NTStatus      = 0x40000030
	STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION                               NTStatus      = 0x40000031
	STATUS_ACCESS_AUDIT_BY_POLICY                                             NTStatus      = 0x40000032
	STATUS_ABANDON_HIBERFILE                                                  NTStatus      = 0x40000033
	STATUS_BIZRULES_NOT_ENABLED                                               NTStatus      = 0x40000034
	STATUS_FT_READ_FROM_COPY                                                  NTStatus      = 0x40000035
	STATUS_IMAGE_AT_DIFFERENT_BASE                                            NTStatus      = 0x40000036
	STATUS_PATCH_DEFERRED                                                     NTStatus      = 0x40000037
	STATUS_HEURISTIC_DAMAGE_POSSIBLE                                          NTStatus      = 0x40190001
	STATUS_GUARD_PAGE_VIOLATION                                               NTStatus      = 0x80000001
	STATUS_DATATYPE_MISALIGNMENT                                              NTStatus      = 0x80000002
	STATUS_BREAKPOINT                                                         NTStatus      = 0x80000003
	STATUS_SINGLE_STEP                                                        NTStatus      = 0x80000004
	STATUS_BUFFER_OVERFLOW                                                    NTStatus      = 0x80000005
	STATUS_NO_MORE_FILES                                                      NTStatus      = 0x80000006
	STATUS_WAKE_SYSTEM_DEBUGGER                                               NTStatus      = 0x80000007
	STATUS_HANDLES_CLOSED                                                     NTStatus      = 0x8000000A
	STATUS_NO_INHERITANCE                                                     NTStatus      = 0x8000000B
	STATUS_GUID_SUBSTITUTION_MADE                                             NTStatus      = 0x8000000C
	STATUS_PARTIAL_COPY                                                       NTStatus      = 0x8000000D
	STATUS_DEVICE_PAPER_EMPTY                                                 NTStatus      = 0x8000000E
	STATUS_DEVICE_POWERED_OFF                                                 NTStatus      = 0x8000000F
	STATUS_DEVICE_OFF_LINE                                                    NTStatus      = 0x80000010
	STATUS_DEVICE_BUSY                                                        NTStatus      = 0x80000011
	STATUS_NO_MORE_EAS                                                        NTStatus      = 0x80000012
	STATUS_INVALID_EA_NAME                                                    NTStatus      = 0x80000013
	STATUS_EA_LIST_INCONSISTENT                                               NTStatus      = 0x80000014
	STATUS_INVALID_EA_FLAG                                                    NTStatus      = 0x80000015
	STATUS_VERIFY_REQUIRED                                                    NTStatus      = 0x80000016
	STATUS_EXTRANEOUS_INFORMATION                                             NTStatus      = 0x80000017
	STATUS_RXACT_COMMIT_NECESSARY                                             NTStatus      = 0x80000018
	STATUS_NO_MORE_ENTRIES                                                    NTStatus      = 0x8000001A
	STATUS_FILEMARK_DETECTED                                                  NTStatus      = 0x8000001B
	STATUS_MEDIA_CHANGED                                                      NTStatus      = 0x8000001C
	STATUS_BUS_RESET                                                          NTStatus      = 0x8000001D
	STATUS_END_OF_MEDIA                                                       NTStatus      = 0x8000001E
	STATUS_BEGINNING_OF_MEDIA                                                 NTStatus      = 0x8000001F
	STATUS_MEDIA_CHECK                                                        NTStatus      = 0x80000020
	STATUS_SETMARK_DETECTED                                                   NTStatus      = 0x80000021
	STATUS_NO_DATA_DETECTED                                                   NTStatus      = 0x80000022
	STATUS_REDIRECTOR_HAS_OPEN_HANDLES                                        NTStatus      = 0x80000023
	STATUS_SERVER_HAS_OPEN_HANDLES                                            NTStatus      = 0x80000024
	STATUS_ALREADY_DISCONNECTED                                               NTStatus      = 0x80000025
	STATUS_LONGJUMP                                                           NTStatus      = 0x80000026
	STATUS_CLEANER_CARTRIDGE_INSTALLED                                        NTStatus      = 0x80000027
	STATUS_PLUGPLAY_QUERY_VETOED                                              NTStatus      = 0x80000028
	STATUS_UNWIND_CONSOLIDATE                                                 NTStatus      = 0x80000029
	STATUS_REGISTRY_HIVE_RECOVERED                                            NTStatus      = 0x8000002A
	STATUS_DLL_MIGHT_BE_INSECURE                                              NTStatus      = 0x8000002B
	STATUS_DLL_MIGHT_BE_INCOMPATIBLE                                          NTStatus      = 0x8000002C
	STATUS_STOPPED_ON_SYMLINK                                                 NTStatus      = 0x8000002D
	STATUS_CANNOT_GRANT_REQUESTED_OPLOCK                                      NTStatus      = 0x8000002E
	STATUS_NO_ACE_CONDITION                                                   NTStatus      = 0x8000002F
	STATUS_DEVICE_SUPPORT_IN_PROGRESS                                         NTStatus      = 0x80000030
	STATUS_DEVICE_POWER_CYCLE_REQUIRED                                        NTStatus      = 0x80000031
	STATUS_NO_WORK_DONE                                                       NTStatus      = 0x80000032
	STATUS_CLUSTER_NODE_ALREADY_UP                                            NTStatus      = 0x80130001
	STATUS_CLUSTER_NODE_ALREADY_DOWN                                          NTStatus      = 0x80130002
	STATUS_CLUSTER_NETWORK_ALREADY_ONLINE                                     NTStatus      = 0x80130003
	STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE                                    NTStatus      = 0x80130004
	STATUS_CLUSTER_NODE_ALREADY_MEMBER                                        NTStatus      = 0x80130005
	STATUS_FLT_BUFFER_TOO_SMALL                                               NTStatus      = 0x801C0001
	STATUS_FVE_PARTIAL_METADATA                                               NTStatus      = 0x80210001
	STATUS_FVE_TRANSIENT_STATE                                                NTStatus      = 0x80210002
	STATUS_CLOUD_FILE_PROPERTY_BLOB_CHECKSUM_MISMATCH                         NTStatus      = 0x8000CF00
	STATUS_UNSUCCESSFUL                                                       NTStatus      = 0xC0000001
	STATUS_NOT_IMPLEMENTED                                                    NTStatus      = 0xC0000002
	STATUS_INVALID_INFO_CLASS                                                 NTStatus      = 0xC0000003
	STATUS_INFO_LENGTH_MISMATCH                                               NTStatus      = 0xC0000004
	STATUS_ACCESS_VIOLATION                                                   NTStatus      = 0xC0000005
	STATUS_IN_PAGE_ERROR                                                      NTStatus      = 0xC0000006
	STATUS_PAGEFILE_QUOTA                                                     NTStatus      = 0xC0000007
	STATUS_INVALID_HANDLE                                                     NTStatus      = 0xC0000008
	STATUS_BAD_INITIAL_STACK                                                  NTStatus      = 0xC0000009
	STATUS_BAD_INITIAL_PC                                                     NTStatus      = 0xC000000A
	STATUS_INVALID_CID                                                        NTStatus      = 0xC000000B
	STATUS_TIMER_NOT_CANCELED                                                 NTStatus      = 0xC000000C
	STATUS_INVALID_PARAMETER                                                  NTStatus      = 0xC000000D
	STATUS_NO_SUCH_DEVICE                                                     NTStatus      = 0xC000000E
	STATUS_NO_SUCH_FILE                                                       NTStatus      = 0xC000000F
	STATUS_INVALID_DEVICE_REQUEST                                             NTStatus      = 0xC0000010
	STATUS_END_OF_FILE                                                        NTStatus      = 0xC0000011
	STATUS_WRONG_VOLUME                                                       NTStatus      = 0xC0000012
	STATUS_NO_MEDIA_IN_DEVICE                                                 NTStatus      = 0xC0000013
	STATUS_UNRECOGNIZED_MEDIA                                                 NTStatus      = 0xC0000014
	STATUS_NONEXISTENT_SECTOR                                                 NTStatus      = 0xC0000015
	STATUS_MORE_PROCESSING_REQUIRED                                           NTStatus      = 0xC0000016
	STATUS_NO_MEMORY                                                          NTStatus      = 0xC0000017
	STATUS_CONFLICTING_ADDRESSES                                              NTStatus      = 0xC0000018
	STATUS_NOT_MAPPED_VIEW                                                    NTStatus      = 0xC0000019
	STATUS_UNABLE_TO_FREE_VM                                                  NTStatus      = 0xC000001A
	STATUS_UNABLE_TO_DELETE_SECTION                                           NTStatus      = 0xC000001B
	STATUS_INVALID_SYSTEM_SERVICE                                             NTStatus      = 0xC000001C
	STATUS_ILLEGAL_INSTRUCTION                                                NTStatus      = 0xC000001D
	STATUS_INVALID_LOCK_SEQUENCE                                              NTStatus      = 0xC000001E
	STATUS_INVALID_VIEW_SIZE                                                  NTStatus      = 0xC000001F
	STATUS_INVALID_FILE_FOR_SECTION                                           NTStatus      = 0xC0000020
	STATUS_ALREADY_COMMITTED                                                  NTStatus      = 0xC0000021
	STATUS_ACCESS_DENIED                                                      NTStatus      = 0xC0000022
	STATUS_BUFFER_TOO_SMALL                                                   NTStatus      = 0xC0000023
	STATUS_OBJECT_TYPE_MISMATCH                                               NTStatus      = 0xC0000024
	STATUS_NONCONTINUABLE_EXCEPTION                                           NTStatus      = 0xC0000025
	STATUS_INVALID_DISPOSITION                                                NTStatus      = 0xC0000026
	STATUS_UNWIND                                                             NTStatus      = 0xC0000027
	STATUS_BAD_STACK                                                          NTStatus      = 0xC0000028
	STATUS_INVALID_UNWIND_TARGET                                              NTStatus      = 0xC0000029
	STATUS_NOT_LOCKED                                                         NTStatus      = 0xC000002A
	STATUS_PARITY_ERROR                                                       NTStatus      = 0xC000002B
	STATUS_UNABLE_TO_DECOMMIT_VM                                              NTStatus      = 0xC000002C
	STATUS_NOT_COMMITTED                                                      NTStatus      = 0xC000002D
	STATUS_INVALID_PORT_ATTRIBUTES                                            NTStatus      = 0xC000002E
	STATUS_PORT_MESSAGE_TOO_LONG                                              NTStatus      = 0xC000002F
	STATUS_INVALID_PARAMETER_MIX                                              NTStatus      = 0xC0000030
	STATUS_INVALID_QUOTA_LOWER                                                NTStatus      = 0xC0000031
	STATUS_DISK_CORRUPT_ERROR                                                 NTStatus      = 0xC0000032
	STATUS_OBJECT_NAME_INVALID                                                NTStatus      = 0xC0000033
	STATUS_OBJECT_NAME_NOT_FOUND                                              NTStatus      = 0xC0000034
	STATUS_OBJECT_NAME_COLLISION                                              NTStatus      = 0xC0000035
	STATUS_PORT_DO_NOT_DISTURB                                                NTStatus      = 0xC0000036
	STATUS_PORT_DISCONNECTED                                                  NTStatus      = 0xC0000037
	STATUS_DEVICE_ALREADY_ATTACHED                                            NTStatus      = 0xC0000038
	STATUS_OBJECT_PATH_INVALID                                                NTStatus      = 0xC0000039
	STATUS_OBJECT_PATH_NOT_FOUND                                              NTStatus      = 0xC000003A
	STATUS_OBJECT_PATH_SYNTAX_BAD                                             NTStatus      = 0xC000003B
	STATUS_DATA_OVERRUN                                                       NTStatus      = 0xC000003C
	STATUS_DATA_LATE_ERROR                                                    NTStatus      = 0xC000003D
	STATUS_DATA_ERROR                                                         NTStatus      = 0xC000003E
	STATUS_CRC_ERROR                                                          NTStatus      = 0xC000003F
	STATUS_SECTION_TOO_BIG                                                    NTStatus      = 0xC0000040
	STATUS_PORT_CONNECTION_REFUSED                                            NTStatus      = 0xC0000041
	STATUS_INVALID_PORT_HANDLE                                                NTStatus      = 0xC0000042
	STATUS_SHARING_VIOLATION                                                  NTStatus      = 0xC0000043
	STATUS_QUOTA_EXCEEDED                                                     NTStatus      = 0xC0000044
	STATUS_INVALID_PAGE_PROTECTION                                            NTStatus      = 0xC0000045
	STATUS_MUTANT_NOT_OWNED                                                   NTStatus      = 0xC0000046
	STATUS_SEMAPHORE_LIMIT_EXCEEDED                                           NTStatus      = 0xC0000047
	STATUS_PORT_ALREADY_SET                                                   NTStatus      = 0xC0000048
	STATUS_SECTION_NOT_IMAGE                                                  NTStatus      = 0xC0000049
	STATUS_SUSPEND_COUNT_EXCEEDED                                             NTStatus      = 0xC000004A
	STATUS_THREAD_IS_TERMINATING                                              NTStatus      = 0xC000004B
	STATUS_BAD_WORKING_SET_LIMIT                                              NTStatus      = 0xC000004C
	STATUS_INCOMPATIBLE_FILE_MAP                                              NTStatus      = 0xC000004D
	STATUS_SECTION_PROTECTION                                                 NTStatus      = 0xC000004E
	STATUS_EAS_NOT_SUPPORTED                                                  NTStatus      = 0xC000004F
	STATUS_EA_TOO_LARGE                                                       NTStatus      = 0xC0000050
	STATUS_NONEXISTENT_EA_ENTRY                                               NTStatus      = 0xC0000051
	STATUS_NO_EAS_ON_FILE                                                     NTStatus      = 0xC0000052
	STATUS_EA_CORRUPT_ERROR                                                   NTStatus      = 0xC0000053
	STATUS_FILE_LOCK_CONFLICT                                                 NTStatus      = 0xC0000054
	STATUS_LOCK_NOT_GRANTED                                                   NTStatus      = 0xC0000055
	STATUS_DELETE_PENDING                                                     NTStatus      = 0xC0000056
	STATUS_CTL_FILE_NOT_SUPPORTED                                             NTStatus      = 0xC0000057
	STATUS_UNKNOWN_REVISION                                                   NTStatus      = 0xC0000058
	STATUS_REVISION_MISMATCH                                                  NTStatus      = 0xC0000059
	STATUS_INVALID_OWNER                                                      NTStatus      = 0xC000005A
	STATUS_INVALID_PRIMARY_GROUP                                              NTStatus      = 0xC000005B
	STATUS_NO_IMPERSONATION_TOKEN                                             NTStatus      = 0xC000005C
	STATUS_CANT_DISABLE_MANDATORY                                             NTStatus      = 0xC000005D
	STATUS_NO_LOGON_SERVERS                                                   NTStatus      = 0xC000005E
	STATUS_NO_SUCH_LOGON_SESSION                                              NTStatus      = 0xC000005F
	STATUS_NO_SUCH_PRIVILEGE                                                  NTStatus      = 0xC0000060
	STATUS_PRIVILEGE_NOT_HELD                                                 NTStatus      = 0xC0000061
	STATUS_INVALID_ACCOUNT_NAME                                               NTStatus      = 0xC0000062
	STATUS_USER_EXISTS                                                        NTStatus      = 0xC0000063
	STATUS_NO_SUCH_USER                                                       NTStatus      = 0xC0000064
	STATUS_GROUP_EXISTS                                                       NTStatus      = 0xC0000065
	STATUS_NO_SUCH_GROUP                                                      NTStatus      = 0xC0000066
	STATUS_MEMBER_IN_GROUP                                                    NTStatus      = 0xC0000067
	STATUS_MEMBER_NOT_IN_GROUP                                                NTStatus      = 0xC0000068
	STATUS_LAST_ADMIN                                                         NTStatus      = 0xC0000069
	STATUS_WRONG_PASSWORD                                                     NTStatus      = 0xC000006A
	STATUS_ILL_FORMED_PASSWORD                                                NTStatus      = 0xC000006B
	STATUS_PASSWORD_RESTRICTION                                               NTStatus      = 0xC000006C
	STATUS_LOGON_FAILURE                                                      NTStatus      = 0xC000006D
	STATUS_ACCOUNT_RESTRICTION                                                NTStatus      = 0xC000006E
	STATUS_INVALID_LOGON_HOURS                                                NTStatus      = 0xC000006F
	STATUS_INVALID_WORKSTATION                                                NTStatus      = 0xC0000070
	STATUS_PASSWORD_EXPIRED                                                   NTStatus      = 0xC0000071
	STATUS_ACCOUNT_DISABLED                                                   NTStatus      = 0xC0000072
	STATUS_NONE_MAPPED                                                        NTStatus      = 0xC0000073
	STATUS_TOO_MANY_LUIDS_REQUESTED                                           NTStatus      = 0xC0000074
	STATUS_LUIDS_EXHAUSTED                                                    NTStatus      = 0xC0000075
	STATUS_INVALID_SUB_AUTHORITY                                              NTStatus      = 0xC0000076
	STATUS_INVALID_ACL                                                        NTStatus      = 0xC0000077
	STATUS_INVALID_SID                                                        NTStatus      = 0xC0000078
	STATUS_INVALID_SECURITY_DESCR                                             NTStatus      = 0xC0000079
	STATUS_PROCEDURE_NOT_FOUND                                                NTStatus      = 0xC000007A
	STATUS_INVALID_IMAGE_FORMAT                                               NTStatus      = 0xC000007B
	STATUS_NO_TOKEN                                                           NTStatus      = 0xC000007C
	STATUS_BAD_INHERITANCE_ACL                                                NTStatus      = 0xC000007D
	STATUS_RANGE_NOT_LOCKED                                                   NTStatus      = 0xC000007E
	STATUS_DISK_FULL                                                          NTStatus      = 0xC000007F
	STATUS_SERVER_DISABLED                                                    NTStatus      = 0xC0000080
	STATUS_SERVER_NOT_DISABLED                                                NTStatus      = 0xC0000081
	STATUS_TOO_MANY_GUIDS_REQUESTED                                           NTStatus      = 0xC0000082
	STATUS_GUIDS_EXHAUSTED                                                    NTStatus      = 0xC0000083
	STATUS_INVALID_ID_AUTHORITY                                               NTStatus      = 0xC0000084
	STATUS_AGENTS_EXHAUSTED                                                   NTStatus      = 0xC0000085
	STATUS_INVALID_VOLUME_LABEL                                               NTStatus      = 0xC0000086
	STATUS_SECTION_NOT_EXTENDED                                               NTStatus      = 0xC0000087
	STATUS_NOT_MAPPED_DATA                                                    NTStatus      = 0xC0000088
	STATUS_RESOURCE_DATA_NOT_FOUND                                            NTStatus      = 0xC0000089
	STATUS_RESOURCE_TYPE_NOT_FOUND                                            NTStatus      = 0xC000008A
	STATUS_RESOURCE_NAME_NOT_FOUND                                            NTStatus      = 0xC000008B
	STATUS_ARRAY_BOUNDS_EXCEEDED                                              NTStatus      = 0xC000008C
	STATUS_FLOAT_DENORMAL_OPERAND                                             NTStatus      = 0xC000008D
	STATUS_FLOAT_DIVIDE_BY_ZERO                                               NTStatus      = 0xC000008E
	STATUS_FLOAT_INEXACT_RESULT                                               NTStatus      = 0xC000008F
	STATUS_FLOAT_INVALID_OPERATION                                            NTStatus      = 0xC0000090
	STATUS_FLOAT_OVERFLOW                                                     NTStatus      = 0xC0000091
	STATUS_FLOAT_STACK_CHECK                                                  NTStatus      = 0xC0000092
	STATUS_FLOAT_UNDERFLOW                                                    NTStatus      = 0xC0000093
	STATUS_INTEGER_DIVIDE_BY_ZERO                                             NTStatus      = 0xC0000094
	STATUS_INTEGER_OVERFLOW                                                   NTStatus      = 0xC0000095
	STATUS_PRIVILEGED_INSTRUCTION                                             NTStatus      = 0xC0000096
	STATUS_TOO_MANY_PAGING_FILES                                              NTStatus      = 0xC0000097
	STATUS_FILE_INVALID                                                       NTStatus      = 0xC0000098
	STATUS_ALLOTTED_SPACE_EXCEEDED                                            NTStatus      = 0xC0000099
	STATUS_INSUFFICIENT_RESOURCES                                             NTStatus      = 0xC000009A
	STATUS_DFS_EXIT_PATH_FOUND                                                NTStatus      = 0xC000009B
	STATUS_DEVICE_DATA_ERROR                                                  NTStatus      = 0xC000009C
	STATUS_DEVICE_NOT_CONNECTED                                               NTStatus      = 0xC000009D
	STATUS_DEVICE_POWER_FAILURE                                               NTStatus      = 0xC000009E
	STATUS_FREE_VM_NOT_AT_BASE                                                NTStatus      = 0xC000009F
	STATUS_MEMORY_NOT_ALLOCATED                                               NTStatus      = 0xC00000A0
	STATUS_WORKING_SET_QUOTA                                                  NTStatus      = 0xC00000A1
	STATUS_MEDIA_WRITE_PROTECTED                                              NTStatus      = 0xC00000A2
	STATUS_DEVICE_NOT_READY                                                   NTStatus      = 0xC00000A3
	STATUS_INVALID_GROUP_ATTRIBUTES                                           NTStatus      = 0xC00000A4
	STATUS_BAD_IMPERSONATION_LEVEL                                            NTStatus      = 0xC00000A5
	STATUS_CANT_OPEN_ANONYMOUS                                                NTStatus      = 0xC00000A6
	STATUS_BAD_VALIDATION_CLASS                                               NTStatus      = 0xC00000A7
	STATUS_BAD_TOKEN_TYPE                                                     NTStatus      = 0xC00000A8
	STATUS_BAD_MASTER_BOOT_RECORD                                             NTStatus      = 0xC00000A9
	STATUS_INSTRUCTION_MISALIGNMENT                                           NTStatus      = 0xC00000AA
	STATUS_INSTANCE_NOT_AVAILABLE                                             NTStatus      = 0xC00000AB
	STATUS_PIPE_NOT_AVAILABLE                                                 NTStatus      = 0xC00000AC
	STATUS_INVALID_PIPE_STATE                                                 NTStatus      = 0xC00000AD
	STATUS_PIPE_BUSY                                                          NTStatus      = 0xC00000AE
	STATUS_ILLEGAL_FUNCTION                                                   NTStatus      = 0xC00000AF
	STATUS_PIPE_DISCONNECTED                                                  NTStatus      = 0xC00000B0
	STATUS_PIPE_CLOSING                                                       NTStatus      = 0xC00000B1
	STATUS_PIPE_CONNECTED                                                     NTStatus      = 0xC00000B2
	STATUS_PIPE_LISTENING                                                     NTStatus      = 0xC00000B3
	STATUS_INVALID_READ_MODE                                                  NTStatus      = 0xC00000B4
	STATUS_IO_TIMEOUT                                                         NTStatus      = 0xC00000B5
	STATUS_FILE_FORCED_CLOSED                                                 NTStatus      = 0xC00000B6
	STATUS_PROFILING_NOT_STARTED                                              NTStatus      = 0xC00000B7
	STATUS_PROFILING_NOT_STOPPED                                              NTStatus      = 0xC00000B8
	STATUS_COULD_NOT_INTERPRET                                                NTStatus      = 0xC00000B9
	STATUS_FILE_IS_A_DIRECTORY                                                NTStatus      = 0xC00000BA
	STATUS_NOT_SUPPORTED                                                      NTStatus      = 0xC00000BB
	STATUS_REMOTE_NOT_LISTENING                                               NTStatus      = 0xC00000BC
	STATUS_DUPLICATE_NAME                                                     NTStatus      = 0xC00000BD
	STATUS_BAD_NETWORK_PATH                                                   NTStatus      = 0xC00000BE
	STATUS_NETWORK_BUSY                                                       NTStatus      = 0xC00000BF

"""




```