Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Functionality:** The first and most obvious thing is the presence of a large number of constant definitions. These constants are all named in a way that suggests they represent error codes. The values assigned to them (hexadecimal numbers) further support this idea. The naming convention like `FVE_E_...`, `FWP_E_...`, `WS_E_...`, `ERROR_NDIS_...` etc., clearly indicates different subsystems or components.

2. **Recognize the Go Context:** The file path `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` strongly suggests this code is part of the Go standard library's extended system functionality for Windows. The `vendor` directory indicates it might be an external dependency that's been incorporated. The `syscall` import in some of the definitions reinforces the idea that these are Windows system error codes.

3. **Infer the Purpose of `zerrors_windows.go`:** Given that these are error codes, the purpose of this file is likely to provide Go-friendly names for common Windows error codes. This allows Go programs to handle Windows-specific errors in a more readable and maintainable way. Instead of dealing with raw numerical error codes, developers can use these named constants.

4. **Connect to Go's Error Handling:**  Go's error handling relies on the `error` interface. A common pattern is to return an `error` value from functions that might fail. This file likely facilitates the creation of concrete `error` types that represent these specific Windows errors.

5. **Formulate the Basic Functionality Summary:** Based on the above points, the core functionality is:  "Defines a large set of constants representing Windows error codes."

6. **Deduce the Go Language Feature:** The most relevant Go feature here is the use of **named constants** (using `const`). These constants are associated with specific Windows error values.

7. **Construct a Go Code Example:**  To illustrate how these constants are used, we need a scenario where a Windows API call might fail and return one of these error codes. A good example is file operations. Trying to open a non-existent file will result in a Windows error.

   * **Initial thought (too simple):** Just accessing the constant directly. `fmt.Println(syscall.ERROR_FILE_NOT_FOUND)` - While technically correct, it doesn't demonstrate error *handling*.

   * **Improved thought (demonstrates error handling):** Simulate a Windows API call and check the error. We need to cast the `syscall.Errno` to an `error` to work with Go's error handling mechanisms.

   ```go
   package main

   import (
       "fmt"
       "syscall"
   )

   func main() {
       err := syscall.Access("nonexistent_file", syscall.O_RDONLY)
       if err == syscall.ERROR_FILE_NOT_FOUND {
           fmt.Println("File not found error:", err)
       } else if err != nil {
           fmt.Println("An unexpected error occurred:", err)
       }
   }
   ```

   * **Refinement (making the example clearer and more relevant to the provided code):** Since many of the constants are of type `Handle`, let's use a hypothetical function that returns a `Handle` and an error. This is more aligned with the structure of the provided code. Also, let's show how the defined constants (`FVE_E_*`, `FWP_E_*`, etc.) might be used.

   ```go
   package main

   import (
       "fmt"
   )

   // Assume these constants are defined in zerrors_windows.go
   const FVE_E_POLICY_NOT_ALLOWED Handle = 0x80310075
   const FWP_E_CALLOUT_NOT_FOUND Handle = 0x80320001

   type Handle uintptr

   func someWindowsFunction() (Handle, error) {
       // Simulate a Windows function call that might fail
       // For example, interacting with BitLocker or the Windows Filtering Platform
       if someCondition {
           return 0, FVE_E_POLICY_NOT_ALLOWED
       } else if anotherCondition {
           return 0, FWP_E_CALLOUT_NOT_FOUND
       }
       return 123, nil // Success
   }

   func main() {
       handle, err := someWindowsFunction()
       if err == FVE_E_POLICY_NOT_ALLOWED {
           fmt.Println("Error: BitLocker policy not allowed")
       } else if err == FWP_E_CALLOUT_NOT_FOUND {
           fmt.Println("Error: Windows Filtering Platform callout not found")
       } else if err != nil {
           fmt.Println("An unexpected error occurred:", err)
       } else {
           fmt.Println("Function succeeded, handle:", handle)
       }
   }
   ```

8. **Address Input/Output and Command-Line Arguments:** This file primarily defines constants. It doesn't directly process input or output in the traditional sense, nor does it handle command-line arguments. Therefore, this section should state that it's not applicable.

9. **Identify Common Pitfalls:**  A key mistake users might make is comparing errors incorrectly. Go's `error` interface requires careful handling. Directly comparing different error types might not work as expected.

   * **Example of a pitfall:**  Assuming a function returns a `syscall.Errno` and trying to compare it to a general `error` without proper casting or type assertion.

10. **Summarize the Functionality (Concise):**  Reiterate the main purpose in a short, clear sentence: "This Go code snippet defines a comprehensive list of Windows-specific error codes as named constants."

11. **Address the "Part X of Y" Instruction:**  Since this is part 9 of 15, acknowledge this context in the final summary.

This step-by-step thought process allows for a systematic analysis of the code, progressing from basic identification to more detailed understanding and illustrative examples. It also anticipates potential user errors and provides a clear and concise summary.
这个Go语言实现文件 `zerrors_windows.go` 的主要功能是：**定义了一系列常量，这些常量代表了Windows操作系统中各种错误代码。**

这些错误代码涵盖了多个Windows子系统，从文件名中的 "zerrors" 可以推断出它可能旨在汇总和规范化这些错误代码，方便Go程序在Windows平台上进行错误处理。

**它可以被认为是Go语言中用于访问和使用Windows特定错误代码的实现基础。**

**Go语言功能的实现举例：**

这个文件本身主要是定义常量，它的作用体现在Go程序如何使用这些常量来判断和处理Windows API调用返回的错误。

假设我们调用了一个Windows API来操作BitLocker（磁盘加密功能），如果策略不允许当前操作，API可能会返回一个特定的错误代码。  `zerrors_windows.go` 中就定义了相关的常量。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// 假设我们有这样一个Windows API调用的封装
// func SomeBitLockerOperation() error { ... }

// 为了演示，我们模拟一个返回特定错误码的场景
func SomeBitLockerOperation() error {
	// 假设Windows API返回了 FVE_E_POLICY_NOT_ALLOWED 这个错误码
	return syscall.Errno(0x80310075)
}

func main() {
	err := SomeBitLockerOperation()
	if err != nil {
		// 使用 zerrors_windows.go 中定义的常量进行错误判断
		if err == syscall.Errno(ALLOWED) { // 这里使用了文件中定义的 ALLOWED 常量
			fmt.Println("操作被允许。")
		} else if err == syscall.Errno(FVE_E_POLICY_NOT_ALLOWED) {
			fmt.Println("错误：BitLocker策略不允许此操作。")
		} else {
			fmt.Printf("发生未知错误: 0x%x\n", err)
		}
	} else {
		fmt.Println("BitLocker操作成功。")
	}
}
```

**假设的输入与输出：**

在上面的代码示例中：

* **假设输入：**  `SomeBitLockerOperation()` 函数模拟调用Windows API，并且这次API返回了 `FVE_E_POLICY_NOT_ALLOWED` 错误码。
* **预期输出：**
  ```
  错误：BitLocker策略不允许此操作。
  ```

**代码推理：**

代码通过比较 `SomeBitLockerOperation()` 返回的错误值 (`syscall.Errno(0x80310075)`) 和 `zerrors_windows.go` 中定义的常量 `FVE_E_POLICY_NOT_ALLOWED` 来判断具体的错误类型。这种方式比直接比较魔法数字 (0x80310075) 更具可读性和维护性。

**命令行参数的具体处理：**

这个文件本身不涉及命令行参数的处理。它只是定义了一组常量。命令行参数的处理通常发生在应用程序的主入口函数 `main` 中，并可能根据参数的值来调用使用这些错误代码的Windows API。

**归纳一下它的功能 (第9部分，共15部分):**

作为整个 `golang.org/x/sys/windows` 库的一部分，并且是错误代码定义的第9部分，这个 `zerrors_windows.go` 文件专注于**定义与Windows操作系统相关的错误代码常量**。

它的功能可以概括为：

1. **提供结构化的错误代码定义：**  将大量的Windows错误代码以Go语言常量的形式进行定义，方便在Go程序中使用。
2. **提高代码可读性：** 使用有意义的常量名代替原始的数字错误代码，使代码更易于理解和维护。
3. **支持Windows特定的错误处理：**  允许Go程序针对不同的Windows错误采取特定的处理措施。
4. **作为 `golang.org/x/sys/windows` 库的基础组成部分：**  为该库中涉及到Windows系统调用的其他部分提供错误代码的参考和使用。

总而言之，`zerrors_windows.go` 是Go语言与Windows操作系统交互时，进行错误处理的重要基础文件，它定义了错误代码的“词汇表”。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第9部分，共15部分，请归纳一下它的功能
```

### 源代码
```go
ALLOWED                    Handle        = 0x80310075
	FVE_E_POLICY_USER_CONFIGURE_RDV_AUTOUNLOCK_NOT_ALLOWED                    Handle        = 0x80310076
	FVE_E_POLICY_USER_CONFIGURE_RDV_NOT_ALLOWED                               Handle        = 0x80310077
	FVE_E_POLICY_USER_ENABLE_RDV_NOT_ALLOWED                                  Handle        = 0x80310078
	FVE_E_POLICY_USER_DISABLE_RDV_NOT_ALLOWED                                 Handle        = 0x80310079
	FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH                                    Handle        = 0x80310080
	FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE                                        Handle        = 0x80310081
	FVE_E_RECOVERY_PARTITION                                                  Handle        = 0x80310082
	FVE_E_POLICY_CONFLICT_FDV_RK_OFF_AUK_ON                                   Handle        = 0x80310083
	FVE_E_POLICY_CONFLICT_RDV_RK_OFF_AUK_ON                                   Handle        = 0x80310084
	FVE_E_NON_BITLOCKER_OID                                                   Handle        = 0x80310085
	FVE_E_POLICY_PROHIBITS_SELFSIGNED                                         Handle        = 0x80310086
	FVE_E_POLICY_CONFLICT_RO_AND_STARTUP_KEY_REQUIRED                         Handle        = 0x80310087
	FVE_E_CONV_RECOVERY_FAILED                                                Handle        = 0x80310088
	FVE_E_VIRTUALIZED_SPACE_TOO_BIG                                           Handle        = 0x80310089
	FVE_E_POLICY_CONFLICT_OSV_RP_OFF_ADB_ON                                   Handle        = 0x80310090
	FVE_E_POLICY_CONFLICT_FDV_RP_OFF_ADB_ON                                   Handle        = 0x80310091
	FVE_E_POLICY_CONFLICT_RDV_RP_OFF_ADB_ON                                   Handle        = 0x80310092
	FVE_E_NON_BITLOCKER_KU                                                    Handle        = 0x80310093
	FVE_E_PRIVATEKEY_AUTH_FAILED                                              Handle        = 0x80310094
	FVE_E_REMOVAL_OF_DRA_FAILED                                               Handle        = 0x80310095
	FVE_E_OPERATION_NOT_SUPPORTED_ON_VISTA_VOLUME                             Handle        = 0x80310096
	FVE_E_CANT_LOCK_AUTOUNLOCK_ENABLED_VOLUME                                 Handle        = 0x80310097
	FVE_E_FIPS_HASH_KDF_NOT_ALLOWED                                           Handle        = 0x80310098
	FVE_E_ENH_PIN_INVALID                                                     Handle        = 0x80310099
	FVE_E_INVALID_PIN_CHARS                                                   Handle        = 0x8031009A
	FVE_E_INVALID_DATUM_TYPE                                                  Handle        = 0x8031009B
	FVE_E_EFI_ONLY                                                            Handle        = 0x8031009C
	FVE_E_MULTIPLE_NKP_CERTS                                                  Handle        = 0x8031009D
	FVE_E_REMOVAL_OF_NKP_FAILED                                               Handle        = 0x8031009E
	FVE_E_INVALID_NKP_CERT                                                    Handle        = 0x8031009F
	FVE_E_NO_EXISTING_PIN                                                     Handle        = 0x803100A0
	FVE_E_PROTECTOR_CHANGE_PIN_MISMATCH                                       Handle        = 0x803100A1
	FVE_E_PIN_PROTECTOR_CHANGE_BY_STD_USER_DISALLOWED                         Handle        = 0x803100A2
	FVE_E_PROTECTOR_CHANGE_MAX_PIN_CHANGE_ATTEMPTS_REACHED                    Handle        = 0x803100A3
	FVE_E_POLICY_PASSPHRASE_REQUIRES_ASCII                                    Handle        = 0x803100A4
	FVE_E_FULL_ENCRYPTION_NOT_ALLOWED_ON_TP_STORAGE                           Handle        = 0x803100A5
	FVE_E_WIPE_NOT_ALLOWED_ON_TP_STORAGE                                      Handle        = 0x803100A6
	FVE_E_KEY_LENGTH_NOT_SUPPORTED_BY_EDRIVE                                  Handle        = 0x803100A7
	FVE_E_NO_EXISTING_PASSPHRASE                                              Handle        = 0x803100A8
	FVE_E_PROTECTOR_CHANGE_PASSPHRASE_MISMATCH                                Handle        = 0x803100A9
	FVE_E_PASSPHRASE_TOO_LONG                                                 Handle        = 0x803100AA
	FVE_E_NO_PASSPHRASE_WITH_TPM                                              Handle        = 0x803100AB
	FVE_E_NO_TPM_WITH_PASSPHRASE                                              Handle        = 0x803100AC
	FVE_E_NOT_ALLOWED_ON_CSV_STACK                                            Handle        = 0x803100AD
	FVE_E_NOT_ALLOWED_ON_CLUSTER                                              Handle        = 0x803100AE
	FVE_E_EDRIVE_NO_FAILOVER_TO_SW                                            Handle        = 0x803100AF
	FVE_E_EDRIVE_BAND_IN_USE                                                  Handle        = 0x803100B0
	FVE_E_EDRIVE_DISALLOWED_BY_GP                                             Handle        = 0x803100B1
	FVE_E_EDRIVE_INCOMPATIBLE_VOLUME                                          Handle        = 0x803100B2
	FVE_E_NOT_ALLOWED_TO_UPGRADE_WHILE_CONVERTING                             Handle        = 0x803100B3
	FVE_E_EDRIVE_DV_NOT_SUPPORTED                                             Handle        = 0x803100B4
	FVE_E_NO_PREBOOT_KEYBOARD_DETECTED                                        Handle        = 0x803100B5
	FVE_E_NO_PREBOOT_KEYBOARD_OR_WINRE_DETECTED                               Handle        = 0x803100B6
	FVE_E_POLICY_REQUIRES_STARTUP_PIN_ON_TOUCH_DEVICE                         Handle        = 0x803100B7
	FVE_E_POLICY_REQUIRES_RECOVERY_PASSWORD_ON_TOUCH_DEVICE                   Handle        = 0x803100B8
	FVE_E_WIPE_CANCEL_NOT_APPLICABLE                                          Handle        = 0x803100B9
	FVE_E_SECUREBOOT_DISABLED                                                 Handle        = 0x803100BA
	FVE_E_SECUREBOOT_CONFIGURATION_INVALID                                    Handle        = 0x803100BB
	FVE_E_EDRIVE_DRY_RUN_FAILED                                               Handle        = 0x803100BC
	FVE_E_SHADOW_COPY_PRESENT                                                 Handle        = 0x803100BD
	FVE_E_POLICY_INVALID_ENHANCED_BCD_SETTINGS                                Handle        = 0x803100BE
	FVE_E_EDRIVE_INCOMPATIBLE_FIRMWARE                                        Handle        = 0x803100BF
	FVE_E_PROTECTOR_CHANGE_MAX_PASSPHRASE_CHANGE_ATTEMPTS_REACHED             Handle        = 0x803100C0
	FVE_E_PASSPHRASE_PROTECTOR_CHANGE_BY_STD_USER_DISALLOWED                  Handle        = 0x803100C1
	FVE_E_LIVEID_ACCOUNT_SUSPENDED                                            Handle        = 0x803100C2
	FVE_E_LIVEID_ACCOUNT_BLOCKED                                              Handle        = 0x803100C3
	FVE_E_NOT_PROVISIONED_ON_ALL_VOLUMES                                      Handle        = 0x803100C4
	FVE_E_DE_FIXED_DATA_NOT_SUPPORTED                                         Handle        = 0x803100C5
	FVE_E_DE_HARDWARE_NOT_COMPLIANT                                           Handle        = 0x803100C6
	FVE_E_DE_WINRE_NOT_CONFIGURED                                             Handle        = 0x803100C7
	FVE_E_DE_PROTECTION_SUSPENDED                                             Handle        = 0x803100C8
	FVE_E_DE_OS_VOLUME_NOT_PROTECTED                                          Handle        = 0x803100C9
	FVE_E_DE_DEVICE_LOCKEDOUT                                                 Handle        = 0x803100CA
	FVE_E_DE_PROTECTION_NOT_YET_ENABLED                                       Handle        = 0x803100CB
	FVE_E_INVALID_PIN_CHARS_DETAILED                                          Handle        = 0x803100CC
	FVE_E_DEVICE_LOCKOUT_COUNTER_UNAVAILABLE                                  Handle        = 0x803100CD
	FVE_E_DEVICELOCKOUT_COUNTER_MISMATCH                                      Handle        = 0x803100CE
	FVE_E_BUFFER_TOO_LARGE                                                    Handle        = 0x803100CF
	FVE_E_NO_SUCH_CAPABILITY_ON_TARGET                                        Handle        = 0x803100D0
	FVE_E_DE_PREVENTED_FOR_OS                                                 Handle        = 0x803100D1
	FVE_E_DE_VOLUME_OPTED_OUT                                                 Handle        = 0x803100D2
	FVE_E_DE_VOLUME_NOT_SUPPORTED                                             Handle        = 0x803100D3
	FVE_E_EOW_NOT_SUPPORTED_IN_VERSION                                        Handle        = 0x803100D4
	FVE_E_ADBACKUP_NOT_ENABLED                                                Handle        = 0x803100D5
	FVE_E_VOLUME_EXTEND_PREVENTS_EOW_DECRYPT                                  Handle        = 0x803100D6
	FVE_E_NOT_DE_VOLUME                                                       Handle        = 0x803100D7
	FVE_E_PROTECTION_CANNOT_BE_DISABLED                                       Handle        = 0x803100D8
	FVE_E_OSV_KSR_NOT_ALLOWED                                                 Handle        = 0x803100D9
	FVE_E_AD_BACKUP_REQUIRED_POLICY_NOT_SET_OS_DRIVE                          Handle        = 0x803100DA
	FVE_E_AD_BACKUP_REQUIRED_POLICY_NOT_SET_FIXED_DRIVE                       Handle        = 0x803100DB
	FVE_E_AD_BACKUP_REQUIRED_POLICY_NOT_SET_REMOVABLE_DRIVE                   Handle        = 0x803100DC
	FVE_E_KEY_ROTATION_NOT_SUPPORTED                                          Handle        = 0x803100DD
	FVE_E_EXECUTE_REQUEST_SENT_TOO_SOON                                       Handle        = 0x803100DE
	FVE_E_KEY_ROTATION_NOT_ENABLED                                            Handle        = 0x803100DF
	FVE_E_DEVICE_NOT_JOINED                                                   Handle        = 0x803100E0
	FWP_E_CALLOUT_NOT_FOUND                                                   Handle        = 0x80320001
	FWP_E_CONDITION_NOT_FOUND                                                 Handle        = 0x80320002
	FWP_E_FILTER_NOT_FOUND                                                    Handle        = 0x80320003
	FWP_E_LAYER_NOT_FOUND                                                     Handle        = 0x80320004
	FWP_E_PROVIDER_NOT_FOUND                                                  Handle        = 0x80320005
	FWP_E_PROVIDER_CONTEXT_NOT_FOUND                                          Handle        = 0x80320006
	FWP_E_SUBLAYER_NOT_FOUND                                                  Handle        = 0x80320007
	FWP_E_NOT_FOUND                                                           Handle        = 0x80320008
	FWP_E_ALREADY_EXISTS                                                      Handle        = 0x80320009
	FWP_E_IN_USE                                                              Handle        = 0x8032000A
	FWP_E_DYNAMIC_SESSION_IN_PROGRESS                                         Handle        = 0x8032000B
	FWP_E_WRONG_SESSION                                                       Handle        = 0x8032000C
	FWP_E_NO_TXN_IN_PROGRESS                                                  Handle        = 0x8032000D
	FWP_E_TXN_IN_PROGRESS                                                     Handle        = 0x8032000E
	FWP_E_TXN_ABORTED                                                         Handle        = 0x8032000F
	FWP_E_SESSION_ABORTED                                                     Handle        = 0x80320010
	FWP_E_INCOMPATIBLE_TXN                                                    Handle        = 0x80320011
	FWP_E_TIMEOUT                                                             Handle        = 0x80320012
	FWP_E_NET_EVENTS_DISABLED                                                 Handle        = 0x80320013
	FWP_E_INCOMPATIBLE_LAYER                                                  Handle        = 0x80320014
	FWP_E_KM_CLIENTS_ONLY                                                     Handle        = 0x80320015
	FWP_E_LIFETIME_MISMATCH                                                   Handle        = 0x80320016
	FWP_E_BUILTIN_OBJECT                                                      Handle        = 0x80320017
	FWP_E_TOO_MANY_CALLOUTS                                                   Handle        = 0x80320018
	FWP_E_NOTIFICATION_DROPPED                                                Handle        = 0x80320019
	FWP_E_TRAFFIC_MISMATCH                                                    Handle        = 0x8032001A
	FWP_E_INCOMPATIBLE_SA_STATE                                               Handle        = 0x8032001B
	FWP_E_NULL_POINTER                                                        Handle        = 0x8032001C
	FWP_E_INVALID_ENUMERATOR                                                  Handle        = 0x8032001D
	FWP_E_INVALID_FLAGS                                                       Handle        = 0x8032001E
	FWP_E_INVALID_NET_MASK                                                    Handle        = 0x8032001F
	FWP_E_INVALID_RANGE                                                       Handle        = 0x80320020
	FWP_E_INVALID_INTERVAL                                                    Handle        = 0x80320021
	FWP_E_ZERO_LENGTH_ARRAY                                                   Handle        = 0x80320022
	FWP_E_NULL_DISPLAY_NAME                                                   Handle        = 0x80320023
	FWP_E_INVALID_ACTION_TYPE                                                 Handle        = 0x80320024
	FWP_E_INVALID_WEIGHT                                                      Handle        = 0x80320025
	FWP_E_MATCH_TYPE_MISMATCH                                                 Handle        = 0x80320026
	FWP_E_TYPE_MISMATCH                                                       Handle        = 0x80320027
	FWP_E_OUT_OF_BOUNDS                                                       Handle        = 0x80320028
	FWP_E_RESERVED                                                            Handle        = 0x80320029
	FWP_E_DUPLICATE_CONDITION                                                 Handle        = 0x8032002A
	FWP_E_DUPLICATE_KEYMOD                                                    Handle        = 0x8032002B
	FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER                                      Handle        = 0x8032002C
	FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER                                   Handle        = 0x8032002D
	FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER                                     Handle        = 0x8032002E
	FWP_E_CONTEXT_INCOMPATIBLE_WITH_CALLOUT                                   Handle        = 0x8032002F
	FWP_E_INCOMPATIBLE_AUTH_METHOD                                            Handle        = 0x80320030
	FWP_E_INCOMPATIBLE_DH_GROUP                                               Handle        = 0x80320031
	FWP_E_EM_NOT_SUPPORTED                                                    Handle        = 0x80320032
	FWP_E_NEVER_MATCH                                                         Handle        = 0x80320033
	FWP_E_PROVIDER_CONTEXT_MISMATCH                                           Handle        = 0x80320034
	FWP_E_INVALID_PARAMETER                                                   Handle        = 0x80320035
	FWP_E_TOO_MANY_SUBLAYERS                                                  Handle        = 0x80320036
	FWP_E_CALLOUT_NOTIFICATION_FAILED                                         Handle        = 0x80320037
	FWP_E_INVALID_AUTH_TRANSFORM                                              Handle        = 0x80320038
	FWP_E_INVALID_CIPHER_TRANSFORM                                            Handle        = 0x80320039
	FWP_E_INCOMPATIBLE_CIPHER_TRANSFORM                                       Handle        = 0x8032003A
	FWP_E_INVALID_TRANSFORM_COMBINATION                                       Handle        = 0x8032003B
	FWP_E_DUPLICATE_AUTH_METHOD                                               Handle        = 0x8032003C
	FWP_E_INVALID_TUNNEL_ENDPOINT                                             Handle        = 0x8032003D
	FWP_E_L2_DRIVER_NOT_READY                                                 Handle        = 0x8032003E
	FWP_E_KEY_DICTATOR_ALREADY_REGISTERED                                     Handle        = 0x8032003F
	FWP_E_KEY_DICTATION_INVALID_KEYING_MATERIAL                               Handle        = 0x80320040
	FWP_E_CONNECTIONS_DISABLED                                                Handle        = 0x80320041
	FWP_E_INVALID_DNS_NAME                                                    Handle        = 0x80320042
	FWP_E_STILL_ON                                                            Handle        = 0x80320043
	FWP_E_IKEEXT_NOT_RUNNING                                                  Handle        = 0x80320044
	FWP_E_DROP_NOICMP                                                         Handle        = 0x80320104
	WS_S_ASYNC                                                                Handle        = 0x003D0000
	WS_S_END                                                                  Handle        = 0x003D0001
	WS_E_INVALID_FORMAT                                                       Handle        = 0x803D0000
	WS_E_OBJECT_FAULTED                                                       Handle        = 0x803D0001
	WS_E_NUMERIC_OVERFLOW                                                     Handle        = 0x803D0002
	WS_E_INVALID_OPERATION                                                    Handle        = 0x803D0003
	WS_E_OPERATION_ABORTED                                                    Handle        = 0x803D0004
	WS_E_ENDPOINT_ACCESS_DENIED                                               Handle        = 0x803D0005
	WS_E_OPERATION_TIMED_OUT                                                  Handle        = 0x803D0006
	WS_E_OPERATION_ABANDONED                                                  Handle        = 0x803D0007
	WS_E_QUOTA_EXCEEDED                                                       Handle        = 0x803D0008
	WS_E_NO_TRANSLATION_AVAILABLE                                             Handle        = 0x803D0009
	WS_E_SECURITY_VERIFICATION_FAILURE                                        Handle        = 0x803D000A
	WS_E_ADDRESS_IN_USE                                                       Handle        = 0x803D000B
	WS_E_ADDRESS_NOT_AVAILABLE                                                Handle        = 0x803D000C
	WS_E_ENDPOINT_NOT_FOUND                                                   Handle        = 0x803D000D
	WS_E_ENDPOINT_NOT_AVAILABLE                                               Handle        = 0x803D000E
	WS_E_ENDPOINT_FAILURE                                                     Handle        = 0x803D000F
	WS_E_ENDPOINT_UNREACHABLE                                                 Handle        = 0x803D0010
	WS_E_ENDPOINT_ACTION_NOT_SUPPORTED                                        Handle        = 0x803D0011
	WS_E_ENDPOINT_TOO_BUSY                                                    Handle        = 0x803D0012
	WS_E_ENDPOINT_FAULT_RECEIVED                                              Handle        = 0x803D0013
	WS_E_ENDPOINT_DISCONNECTED                                                Handle        = 0x803D0014
	WS_E_PROXY_FAILURE                                                        Handle        = 0x803D0015
	WS_E_PROXY_ACCESS_DENIED                                                  Handle        = 0x803D0016
	WS_E_NOT_SUPPORTED                                                        Handle        = 0x803D0017
	WS_E_PROXY_REQUIRES_BASIC_AUTH                                            Handle        = 0x803D0018
	WS_E_PROXY_REQUIRES_DIGEST_AUTH                                           Handle        = 0x803D0019
	WS_E_PROXY_REQUIRES_NTLM_AUTH                                             Handle        = 0x803D001A
	WS_E_PROXY_REQUIRES_NEGOTIATE_AUTH                                        Handle        = 0x803D001B
	WS_E_SERVER_REQUIRES_BASIC_AUTH                                           Handle        = 0x803D001C
	WS_E_SERVER_REQUIRES_DIGEST_AUTH                                          Handle        = 0x803D001D
	WS_E_SERVER_REQUIRES_NTLM_AUTH                                            Handle        = 0x803D001E
	WS_E_SERVER_REQUIRES_NEGOTIATE_AUTH                                       Handle        = 0x803D001F
	WS_E_INVALID_ENDPOINT_URL                                                 Handle        = 0x803D0020
	WS_E_OTHER                                                                Handle        = 0x803D0021
	WS_E_SECURITY_TOKEN_EXPIRED                                               Handle        = 0x803D0022
	WS_E_SECURITY_SYSTEM_FAILURE                                              Handle        = 0x803D0023
	ERROR_NDIS_INTERFACE_CLOSING                                              syscall.Errno = 0x80340002
	ERROR_NDIS_BAD_VERSION                                                    syscall.Errno = 0x80340004
	ERROR_NDIS_BAD_CHARACTERISTICS                                            syscall.Errno = 0x80340005
	ERROR_NDIS_ADAPTER_NOT_FOUND                                              syscall.Errno = 0x80340006
	ERROR_NDIS_OPEN_FAILED                                                    syscall.Errno = 0x80340007
	ERROR_NDIS_DEVICE_FAILED                                                  syscall.Errno = 0x80340008
	ERROR_NDIS_MULTICAST_FULL                                                 syscall.Errno = 0x80340009
	ERROR_NDIS_MULTICAST_EXISTS                                               syscall.Errno = 0x8034000A
	ERROR_NDIS_MULTICAST_NOT_FOUND                                            syscall.Errno = 0x8034000B
	ERROR_NDIS_REQUEST_ABORTED                                                syscall.Errno = 0x8034000C
	ERROR_NDIS_RESET_IN_PROGRESS                                              syscall.Errno = 0x8034000D
	ERROR_NDIS_NOT_SUPPORTED                                                  syscall.Errno = 0x803400BB
	ERROR_NDIS_INVALID_PACKET                                                 syscall.Errno = 0x8034000F
	ERROR_NDIS_ADAPTER_NOT_READY                                              syscall.Errno = 0x80340011
	ERROR_NDIS_INVALID_LENGTH                                                 syscall.Errno = 0x80340014
	ERROR_NDIS_INVALID_DATA                                                   syscall.Errno = 0x80340015
	ERROR_NDIS_BUFFER_TOO_SHORT                                               syscall.Errno = 0x80340016
	ERROR_NDIS_INVALID_OID                                                    syscall.Errno = 0x80340017
	ERROR_NDIS_ADAPTER_REMOVED                                                syscall.Errno = 0x80340018
	ERROR_NDIS_UNSUPPORTED_MEDIA                                              syscall.Errno = 0x80340019
	ERROR_NDIS_GROUP_ADDRESS_IN_USE                                           syscall.Errno = 0x8034001A
	ERROR_NDIS_FILE_NOT_FOUND                                                 syscall.Errno = 0x8034001B
	ERROR_NDIS_ERROR_READING_FILE                                             syscall.Errno = 0x8034001C
	ERROR_NDIS_ALREADY_MAPPED                                                 syscall.Errno = 0x8034001D
	ERROR_NDIS_RESOURCE_CONFLICT                                              syscall.Errno = 0x8034001E
	ERROR_NDIS_MEDIA_DISCONNECTED                                             syscall.Errno = 0x8034001F
	ERROR_NDIS_INVALID_ADDRESS                                                syscall.Errno = 0x80340022
	ERROR_NDIS_INVALID_DEVICE_REQUEST                                         syscall.Errno = 0x80340010
	ERROR_NDIS_PAUSED                                                         syscall.Errno = 0x8034002A
	ERROR_NDIS_INTERFACE_NOT_FOUND                                            syscall.Errno = 0x8034002B
	ERROR_NDIS_UNSUPPORTED_REVISION                                           syscall.Errno = 0x8034002C
	ERROR_NDIS_INVALID_PORT                                                   syscall.Errno = 0x8034002D
	ERROR_NDIS_INVALID_PORT_STATE                                             syscall.Errno = 0x8034002E
	ERROR_NDIS_LOW_POWER_STATE                                                syscall.Errno = 0x8034002F
	ERROR_NDIS_REINIT_REQUIRED                                                syscall.Errno = 0x80340030
	ERROR_NDIS_NO_QUEUES                                                      syscall.Errno = 0x80340031
	ERROR_NDIS_DOT11_AUTO_CONFIG_ENABLED                                      syscall.Errno = 0x80342000
	ERROR_NDIS_DOT11_MEDIA_IN_USE                                             syscall.Errno = 0x80342001
	ERROR_NDIS_DOT11_POWER_STATE_INVALID                                      syscall.Errno = 0x80342002
	ERROR_NDIS_PM_WOL_PATTERN_LIST_FULL                                       syscall.Errno = 0x80342003
	ERROR_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL                                  syscall.Errno = 0x80342004
	ERROR_NDIS_DOT11_AP_CHANNEL_CURRENTLY_NOT_AVAILABLE                       syscall.Errno = 0x80342005
	ERROR_NDIS_DOT11_AP_BAND_CURRENTLY_NOT_AVAILABLE                          syscall.Errno = 0x80342006
	ERROR_NDIS_DOT11_AP_CHANNEL_NOT_ALLOWED                                   syscall.Errno = 0x80342007
	ERROR_NDIS_DOT11_AP_BAND_NOT_ALLOWED                                      syscall.Errno = 0x80342008
	ERROR_NDIS_INDICATION_REQUIRED                                            syscall.Errno = 0x00340001
	ERROR_NDIS_OFFLOAD_POLICY                                                 syscall.Errno = 0xC034100F
	ERROR_NDIS_OFFLOAD_CONNECTION_REJECTED                                    syscall.Errno = 0xC0341012
	ERROR_NDIS_OFFLOAD_PATH_REJECTED                                          syscall.Errno = 0xC0341013
	ERROR_HV_INVALID_HYPERCALL_CODE                                           syscall.Errno = 0xC0350002
	ERROR_HV_INVALID_HYPERCALL_INPUT                                          syscall.Errno = 0xC0350003
	ERROR_HV_INVALID_ALIGNMENT                                                syscall.Errno = 0xC0350004
	ERROR_HV_INVALID_PARAMETER                                                syscall.Errno = 0xC0350005
	ERROR_HV_ACCESS_DENIED                                                    syscall.Errno = 0xC0350006
	ERROR_HV_INVALID_PARTITION_STATE                                          syscall.Errno = 0xC0350007
	ERROR_HV_OPERATION_DENIED                                                 syscall.Errno = 0xC0350008
	ERROR_HV_UNKNOWN_PROPERTY                                                 syscall.Errno = 0xC0350009
	ERROR_HV_PROPERTY_VALUE_OUT_OF_RANGE                                      syscall.Errno = 0xC035000A
	ERROR_HV_INSUFFICIENT_MEMORY                                              syscall.Errno = 0xC035000B
	ERROR_HV_PARTITION_TOO_DEEP                                               syscall.Errno = 0xC035000C
	ERROR_HV_INVALID_PARTITION_ID                                             syscall.Errno = 0xC035000D
	ERROR_HV_INVALID_VP_INDEX                                                 syscall.Errno = 0xC035000E
	ERROR_HV_INVALID_PORT_ID                                                  syscall.Errno = 0xC0350011
	ERROR_HV_INVALID_CONNECTION_ID                                            syscall.Errno = 0xC0350012
	ERROR_HV_INSUFFICIENT_BUFFERS                                             syscall.Errno = 0xC0350013
	ERROR_HV_NOT_ACKNOWLEDGED                                                 syscall.Errno = 0xC0350014
	ERROR_HV_INVALID_VP_STATE                                                 syscall.Errno = 0xC0350015
	ERROR_HV_ACKNOWLEDGED                                                     syscall.Errno = 0xC0350016
	ERROR_HV_INVALID_SAVE_RESTORE_STATE                                       syscall.Errno = 0xC0350017
	ERROR_HV_INVALID_SYNIC_STATE                                              syscall.Errno = 0xC0350018
	ERROR_HV_OBJECT_IN_USE                                                    syscall.Errno = 0xC0350019
	ERROR_HV_INVALID_PROXIMITY_DOMAIN_INFO                                    syscall.Errno = 0xC035001A
	ERROR_HV_NO_DATA                                                          syscall.Errno = 0xC035001B
	ERROR_HV_INACTIVE                                                         syscall.Errno = 0xC035001C
	ERROR_HV_NO_RESOURCES                                                     syscall.Errno = 0xC035001D
	ERROR_HV_FEATURE_UNAVAILABLE                                              syscall.Errno = 0xC035001E
	ERROR_HV_INSUFFICIENT_BUFFER                                              syscall.Errno = 0xC0350033
	ERROR_HV_INSUFFICIENT_DEVICE_DOMAINS                                      syscall.Errno = 0xC0350038
	ERROR_HV_CPUID_FEATURE_VALIDATION                                         syscall.Errno = 0xC035003C
	ERROR_HV_CPUID_XSAVE_FEATURE_VALIDATION                                   syscall.Errno = 0xC035003D
	ERROR_HV_PROCESSOR_STARTUP_TIMEOUT                                        syscall.Errno = 0xC035003E
	ERROR_HV_SMX_ENABLED                                                      syscall.Errno = 0xC035003F
	ERROR_HV_INVALID_LP_INDEX                                                 syscall.Errno = 0xC0350041
	ERROR_HV_INVALID_REGISTER_VALUE                                           syscall.Errno = 0xC0350050
	ERROR_HV_INVALID_VTL_STATE                                                syscall.Errno = 0xC0350051
	ERROR_HV_NX_NOT_DETECTED                                                  syscall.Errno = 0xC0350055
	ERROR_HV_INVALID_DEVICE_ID                                                syscall.Errno = 0xC0350057
	ERROR_HV_INVALID_DEVICE_STATE                                             syscall.Errno = 0xC0350058
	ERROR_HV_PENDING_PAGE_REQUESTS                                            syscall.Errno = 0x00350059
	ERROR_HV_PAGE_REQUEST_INVALID                                             syscall.Errno = 0xC0350060
	ERROR_HV_INVALID_CPU_GROUP_ID                                             syscall.Errno = 0xC035006F
	ERROR_HV_INVALID_CPU_GROUP_STATE                                          syscall.Errno = 0xC0350070
	ERROR_HV_OPERATION_FAILED                                                 syscall.Errno = 0xC0350071
	ERROR_HV_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE                              syscall.Errno = 0xC0350072
	ERROR_HV_INSUFFICIENT_ROOT_MEMORY                                         syscall.Errno = 0xC0350073
	ERROR_HV_NOT_PRESENT                                                      syscall.Errno = 0xC0351000
	ERROR_VID_DUPLICATE_HANDLER                                               syscall.Errno = 0xC0370001
	ERROR_VID_TOO_MANY_HANDLERS                                               syscall.Errno = 0xC0370002
	ERROR_VID_QUEUE_FULL                                                      syscall.Errno = 0xC0370003
	ERROR_VID_HANDLER_NOT_PRESENT                                             syscall.Errno = 0xC0370004
	ERROR_VID_INVALID_OBJECT_NAME                                             syscall.Errno = 0xC0370005
	ERROR_VID_PARTITION_NAME_TOO_LONG                                         syscall.Errno = 0xC0370006
	ERROR_VID_MESSAGE_QUEUE_NAME_TOO_LONG                                     syscall.Errno = 0xC0370007
	ERROR_VID_PARTITION_ALREADY_EXISTS                                        syscall.Errno = 0xC0370008
	ERROR_VID_PARTITION_DOES_NOT_EXIST                                        syscall.Errno = 0xC0370009
	ERROR_VID_PARTITION_NAME_NOT_FOUND                                        syscall.Errno = 0xC037000A
	ERROR_VID_MESSAGE_QUEUE_ALREADY_EXISTS                                    syscall.Errno = 0xC037000B
	ERROR_VID_EXCEEDED_MBP_ENTRY_MAP_LIMIT                                    syscall.Errno = 0xC037000C
	ERROR_VID_MB_STILL_REFERENCED                                             syscall.Errno = 0xC037000D
	ERROR_VID_CHILD_GPA_PAGE_SET_CORRUPTED                                    syscall.Errno = 0xC037000E
	ERROR_VID_INVALID_NUMA_SETTINGS                                           syscall.Errno = 0xC037000F
	ERROR_VID_INVALID_NUMA_NODE_INDEX                                         syscall.Errno = 0xC0370010
	ERROR_VID_NOTIFICATION_QUEUE_ALREADY_ASSOCIATED                           syscall.Errno = 0xC0370011
	ERROR_VID_INVALID_MEMORY_BLOCK_HANDLE                                     syscall.Errno = 0xC0370012
	ERROR_VID_PAGE_RANGE_OVERFLOW                                             syscall.Errno = 0xC0370013
	ERROR_VID_INVALID_MESSAGE_QUEUE_HANDLE                                    syscall.Errno = 0xC0370014
	ERROR_VID_INVALID_GPA_RANGE_HANDLE                                        syscall.Errno = 0xC0370015
	ERROR_VID_NO_MEMORY_BLOCK_NOTIFICATION_QUEUE                              syscall.Errno = 0xC0370016
	ERROR_VID_MEMORY_BLOCK_LOCK_COUNT_EXCEEDED                                syscall.Errno = 0xC0370017
	ERROR_VID_INVALID_PPM_HANDLE                                              syscall.Errno = 0xC0370018
	ERROR_VID_MBPS_ARE_LOCKED                                                 syscall.Errno = 0xC0370019
	ERROR_VID_MESSAGE_QUEUE_CLOSED                                            syscall.Errno = 0xC037001A
	ERROR_VID_VIRTUAL_PROCESSOR_LIMIT_EXCEEDED                                syscall.Errno = 0xC037001B
	ERROR_VID_STOP_PENDING                                                    syscall.Errno = 0xC037001C
	ERROR_VID_INVALID_PROCESSOR_STATE                                         syscall.Errno = 0xC037001D
	ERROR_VID_EXCEEDED_KM_CONTEXT_COUNT_LIMIT                                 syscall.Errno = 0xC037001E
	ERROR_VID_KM_INTERFACE_ALREADY_INITIALIZED                                syscall.Errno = 0xC037001F
	ERROR_VID_MB_PROPERTY_ALREADY_SET_RESET                                   syscall.Errno = 0xC0370020
	ERROR_VID_MMIO_RANGE_DESTROYED                                            syscall.Errno = 0xC0370021
	ERROR_VID_INVALID_CHILD_GPA_PAGE_SET                                      syscall.Errno = 0xC0370022
	ERROR_VID_RESERVE_PAGE_SET_IS_BEING_USED                                  syscall.Errno = 0xC0370023
	ERROR_VID_RESERVE_PAGE_SET_TOO_SMALL                                      syscall.Errno = 0xC0370024
	ERROR_VID_MBP_ALREADY_LOCKED_USING_RESERVED_PAGE                          syscall.Errno = 0xC0370025
	ERROR_VID_MBP_COUNT_EXCEEDED_LIMIT                                        syscall.Errno = 0xC0370026
	ERROR_VID_SAVED_STATE_CORRUPT                                             syscall.Errno = 0xC0370027
	ERROR_VID_SAVED_STATE_UNRECOGNIZED_ITEM                                   syscall.Errno = 0xC0370028
	ERROR_VID_SAVED_STATE_INCOMPATIBLE                                        syscall.Errno = 0xC0370029
	ERROR_VID_VTL_ACCESS_DENIED                                               syscall.Errno = 0xC037002A
	ERROR_VMCOMPUTE_TERMINATED_DURING_START                                   syscall.Errno = 0xC0370100
	ERROR_VMCOMPUTE_IMAGE_MISMATCH                                            syscall.Errno = 0xC0370101
	ERROR_VMCOMPUTE_HYPERV_NOT_INSTALLED                                      syscall.Errno = 0xC0370102
	ERROR_VMCOMPUTE_OPERATION_PENDING                                         syscall.Errno = 0xC0370103
	ERROR_VMCOMPUTE_TOO_MANY_NOTIFICATIONS                                    syscall.Errno = 0xC0370104
	ERROR_VMCOMPUTE_INVALID_STATE                                             syscall.Errno = 0xC0370105
	ERROR_VMCOMPUTE_UNEXPECTED_EXIT                                           syscall.Errno = 0xC0370106
	ERROR_VMCOMPUTE_TERMINATED                                                syscall.Errno = 0xC0370107
	ERROR_VMCOMPUTE_CONNECT_FAILED                                            syscall.Errno = 0xC0370108
	ERROR_VMCOMPUTE_TIMEOUT                                                   syscall.Errno = 0xC0370109
	ERROR_VMCOMPUTE_CONNECTION_CLOSED                                         syscall.Errno = 0xC037010A
	ERROR_VMCOMPUTE_UNKNOWN_MESSAGE                                           syscall.Errno = 0xC037010B
	ERROR_VMCOMPUTE_UNSUPPORTED_PROTOCOL_VERSION                              syscall.Errno = 0xC037010C
	ERROR_VMCOMPUTE_INVALID_JSON                                              syscall.Errno = 0xC037010D
	ERROR_VMCOMPUTE_SYSTEM_NOT_FOUND                                          syscall.Errno = 0xC037010E
	ERROR_VMCOMPUTE_SYSTEM_ALREADY_EXISTS                                     syscall.Errno = 0xC037010F
	ERROR_VMCOMPUTE_SYSTEM_ALREADY_STOPPED                                    syscall.Errno = 0xC0370110
	ERROR_VMCOMPUTE_PROTOCOL_ERROR                                            syscall.Errno = 0xC0370111
	ERROR_VMCOMPUTE_INVALID_LAYER                                             syscall.Errno = 0xC0370112
	ERROR_VMCOMPUTE_WINDOWS_INSIDER_REQUIRED                                  syscall.Errno = 0xC0370113
	HCS_E_TERMINATED_DURING_START                                             Handle        = 0x80370100
	HCS_E_IMAGE_MISMATCH                                                      Handle        = 0x80370101
	HCS_E_HYPERV_NOT_INSTALLED                                                Handle        = 0x80370102
	HCS_E_INVALID_STATE                                                       Handle        = 0x80370105
	HCS_E_UNEXPECTED_EXIT                                                     Handle        = 0x80370106
	HCS_E_TERMINATED                                                          Handle        = 0x80370107
	HCS_E_CONNECT_FAILED                                                      Handle        = 0x80370108
	HCS_E_CONNECTION_TIMEOUT                                                  Handle        = 0x80370109
	HCS_E_CONNECTION_CLOSED                                                   Handle        = 0x8037010A
	HCS_E_UNKNOWN_MESSAGE                                                     Handle        = 0x8037010B
	HCS_E_UNSUPPORTED_PROTOCOL_VERSION                                        Handle        = 0x8037010C
	HCS_E_INVALID_JSON                                                        Handle        = 0x8037010D
	HCS_E_SYSTEM_NOT_FOUND                                                    Handle        = 0x8037010E
	HCS_E_SYSTEM_ALREADY_EXISTS                                               Handle        = 0x8037010F
	HCS_E_SYSTEM_ALREADY_STOPPED                                              Handle        = 0x80370110
	HCS_E_PROTOCOL_ERROR                                                      Handle        = 0x80370111
	HCS_E_INVALID_LAYER                                                       Handle        = 0x80370112
	HCS_E_WINDOWS_INSIDER_REQUIRED                                            Handle        = 0x80370113
	HCS_E_SERVICE_NOT_AVAILABLE                                               Handle        = 0x80370114
	HCS_E_OPERATION_NOT_STARTED                                               Handle        = 0x80370115
	HCS_E_OPERATION_ALREADY_STARTED                                           Handle        = 0x80370116
	HCS_E_OPERATION_PENDING                                                   Handle        = 0x80370117
	HCS_E_OPERATION_TIMEOUT                                                   Handle        = 0x80370118
	HCS_E_OPERATION_SYSTEM_CALLBACK_ALREADY_SET                               Handle        = 0x80370119
	HCS_E_OPERATION_RESULT_ALLOCATION_FAILED                                  Handle        = 0x8037011A
	HCS_E_ACCESS_DENIED                                                       Handle        = 0x8037011B
	HCS_E_GUEST_CRITICAL_ERROR                                                Handle        = 0x8037011C
	ERROR_VNET_VIRTUAL_SWITCH_NAME_NOT_FOUND                                  syscall.Errno = 0xC0370200
	ERROR_VID_REMOTE_NODE_PARENT_GPA_PAGES_USED                               syscall.Errno = 0x80370001
	WHV_E_UNKNOWN_CAPABILITY                                                  Handle        = 0x80370300
	WHV_E_INSUFFICIENT_BUFFER                                                 Handle        = 0x80370301
	WHV_E_UNKNOWN_PROPERTY                                                    Handle        = 0x80370302
	WHV_E_UNSUPPORTED_HYPERVISOR_CONFIG                                       Handle        = 0x80370303
	WHV_E_INVALID_PARTITION_CONFIG                                            Handle        = 0x80370304
	WHV_E_GPA_RANGE_NOT_FOUND                                                 Handle        = 0x80370305
	WHV_E_VP_ALREADY_EXISTS                                                   Handle        = 0x80370306
	WHV_E_VP_DOES_NOT_EXIST                                                   Handle        = 0x80370307
	WHV_E_INVALID_VP_STATE                                                    Handle        = 0x80370308
	WHV_E_INVALID_VP_REGISTER_NAME                                            Handle        = 0x80370309
	ERROR_VSMB_SAVED_STATE_FILE_NOT_FOUND                                     syscall.Errno = 0xC0370400
	ERROR_VSMB_SAVED_STATE_CORRUPT                                            syscall.Errno = 0xC0370401
	ERROR_VOLMGR_INCOMPLETE_REGENERATION                                      syscall.Errno = 0x80380001
	ERROR_VOLMGR_INCOMPLETE_DISK_MIGRATION                                    syscall.Errno = 0x80380002
	ERROR_VOLMGR_DATABASE_FULL                                                syscall.Errno = 0xC0380001
	ERROR_VOLMGR_DISK_CONFIGURATION_CORRUPTED                                 syscall.Errno = 0xC0380002
	ERROR_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC                               syscall.Errno = 0xC0380003
	ERROR_VOLMGR_PACK_CONFIG_UPDATE_FAILED                                    syscall.Errno = 0xC0380004
	ERROR_VOLMGR_DISK_CONTAINS_NON_SIMPLE_VOLUME                              syscall.Errno = 0xC0380005
	ERROR_VOLMGR_DISK_DUPLICATE                                               syscall.Errno = 0xC0380006
	ERROR_VOLMGR_DISK_DYNAMIC                                                 syscall.Errno = 0xC0380007
	ERROR_VOLMGR_DISK_ID_INVALID                                              syscall.Errno = 0xC0380008
	ERROR_VOLMGR_DISK_INVALID                                                 syscall.Errno = 0xC0380009
	ERROR_VOLMGR_DISK_LAST_VOTER                                              syscall.Errno = 0xC038000A
	ERROR_VOLMGR_DISK_LAYOUT_INVALID                                          syscall.Errno = 0xC038000B
	ERROR_VOLMGR_DISK_LAYOUT_NON_BASIC_BETWEEN_BASIC_PARTITIONS               syscall.Errno = 0xC038000C
	ERROR_VOLMGR_DISK_LAYOUT_NOT_CYLINDER_ALIGNED                             syscall.Errno = 0xC038000D
	ERROR_VOLMGR_DISK_LAYOUT_PARTITIONS_TOO_SMALL                             syscall.Errno = 0xC038000E
	ERROR_VOLMGR_DISK_LAYOUT_PRIMARY_BETWEEN_LOGICAL_PARTITIONS               syscall.Errno = 0xC038000F
	ERROR_VOLMGR_DISK_LAYOUT_TOO_MANY_PARTITIONS                              syscall.Errno = 0xC0380010
	ERROR_VOLMGR_DISK_MISSING                                                 syscall.Errno = 0xC0380011
	ERROR_VOLMGR_DISK_NOT_EMPTY                                               syscall.Errno = 0xC0380012
	ERROR_VOLMGR_DISK_NOT_ENOUGH_SPACE                                        syscall.Errno = 0xC0380013
	ERROR_VOLMGR_DISK_REVECTORING_FAILED                                      syscall.Errno = 0xC0380014
	ERROR_VOLMGR_DISK_SECTOR_SIZE_INVALID                                     syscall.Errno = 0xC0380015
	ERROR_VOLMGR_DISK_SET_NOT_CONTAINED                                       syscall.Errno = 0xC0380016
	ERROR_VOLMGR_DISK_USED_BY_MULTIPLE_MEMBERS                                syscall.Errno = 0xC0380017
	ERROR_VOLMGR_DISK_USED_BY_MULTIPLE_PLEXES                                 syscall.Errno = 0xC0380018
	ERROR_VOLMGR_DYNAMIC_DISK_NOT_SUPPORTED                                   syscall.Errno = 0xC0380019
	ERROR_VOLMGR_EXTENT_ALREADY_USED                                          syscall.Errno = 0xC038001A
	ERROR_VOLMGR_EXTENT_NOT_CONTIGUOUS                                        syscall.Errno = 0xC038001B
	ERROR_VOLMGR_EXTENT_NOT_IN_PUBLIC_REGION                                  syscall.Errno = 0xC038001C
	ERROR_VOLMGR_EXTENT_NOT_SECTOR_ALIGNED                                    syscall.Errno = 0xC038001D
	ERROR_VOLMGR_EXTENT_OVERLAPS_EBR_PARTITION                                syscall.Errno = 0xC038001E
	ERROR_VOLMGR_EXTENT_VOLUME_LENGTHS_DO_NOT_MATCH                           syscall.Errno = 0xC038001F
	ERROR_VOLMGR_FAULT_TOLERANT_NOT_SUPPORTED                                 syscall.Errno = 0xC0380020
	ERROR_VOLMGR_INTERLEAVE_LENGTH_INVALID                                    syscall.Errno = 0xC0380021
	ERROR_VOLMGR_MAXIMUM_REGISTERED_USERS                                     syscall.Errno = 0xC0380022
	ERROR_VOLMGR_MEMBER_IN_SYNC                                               syscall.Errno = 0xC0380023
	ERROR_VOLMGR_MEMBER_INDEX_DUPLICATE                                       syscall.Errno = 0xC0380024
	ERROR_VOLMGR_MEMBER_INDEX_INVALID                                         syscall.Errno = 0xC0380025
	ERROR_VOLMGR_MEMBER_MISSING                                               syscall.Errno = 0xC0380026
	ERROR_VOLMGR_MEMBER_NOT_DETACHED                                          syscall.Errno = 0xC0380027
	ERROR_VOLMGR_MEMBER_REGENERATING                                          syscall.Errno = 0xC0380028
	ERROR_VOLMGR_ALL_DISKS_FAILED                                             syscall.Errno = 0xC0380029
	ERROR_VOLMGR_NO_REGISTERED_USERS                                          syscall.Errno = 0xC038002A
	ERROR_VOLMGR_NO_SUCH_USER                                                 syscall.Errno = 0xC038002B
	ERROR_VOLMGR_NOTIFICATION_RESET                                           syscall.Errno = 0xC038002C
	ERROR_VOLMGR_NUMBER_OF_MEMBERS_INVALID                                    syscall.Errno = 0xC038002D
	ERROR_VOLMGR_NUMBER_OF_PLEXES_INVALID                                     syscall.Errno = 0xC038002E
	ERROR_VOLMGR_PACK_DUPLICATE                                               syscall.Errno = 0xC038002F
	ERROR_VOLMGR_PACK_ID_INVALID                                              syscall.Errno = 0xC0380030
	ERROR_VOLMGR_PACK_INVALID                                                 syscall.Errno = 0xC0380031
	ERROR_VOLMGR_PACK_NAME_INVALID                                            syscall.Errno = 0xC0380032
	ERROR_VOLMGR_PACK_OFFLINE                                                 syscall.Errno = 0xC0380033
	ERROR_VOLMGR_PACK_HAS_QUORUM                                              syscall.Errno = 0xC0380034
	ERROR_VOLMGR_PACK_WITHOUT_QUORUM                                          syscall.Errno = 0xC0380035
	ERROR_VOLMGR_PARTITION_STYLE_INVALID                                      syscall.Errno = 0xC0380036
	ERROR_VOLMGR_PARTITION_UPDATE_FAILED                                      syscall.Errno = 0xC0380037
	ERROR_VOLMGR_PLEX_IN_SYNC                                                 syscall.Errno = 0xC0380038
	ERROR_VOLMGR_PLEX_INDEX_DUPLICATE                                         syscall.Errno = 0xC0380039
	ERROR_VOLMGR_PLEX_INDEX_INVALID                                           syscall.Errno = 0xC038003A
	ERROR_VOLMGR_PLEX_LAST_ACTIVE                                             syscall.Errno = 0xC038003B
	ERROR_VOLMGR_PLEX_MISSING                                                 syscall.Errno = 0xC038003C
	ERROR_VOLMGR_PLEX_REGENERATING                                            syscall.Errno = 0xC038003D
	ERROR_VOLMGR_PLEX_TYPE_INVALID                                            syscall.Errno = 0xC038003E
	ERROR_VOLMGR_PLEX_NOT_RAID5                                               syscall.Errno = 0xC038003F
	ERROR_VOLMGR_PLEX_NOT_SIMPLE                                              syscall.Errno = 0xC0380040
	ERROR_VOLMGR_STRUCTURE_SIZE_INVALID                                       syscall.Errno = 0xC0380041
	ERROR_VOLMGR_TOO_MANY_NOTIFICATION_REQUESTS                               syscall.Errno = 0xC0380042
	ERROR_VOLMGR_TRANSACTION_IN_PROGRESS                                      syscall.Errno = 0xC0380043
	ERROR_VOLMGR_UNEXPECTED_DISK_LAYOUT_CHANGE                                syscall.Errno = 0xC0380044
	ERROR_VOLMGR_VOLUME_CONTAINS_MISSING_DISK                                 syscall.Errno = 0xC0380045
	ERROR_VOLMGR_VOLUME_ID_INVALID                                            syscall.Errno = 0xC0380046
	ERROR_VOLMGR_VOLUME_LENGTH_INVALID                                        syscall.Errno = 0xC0380047
	ERROR_VOLMGR_VOLUME_LENGTH_NOT_SECTOR_SIZE_MULTIPLE                       syscall.Errno = 0xC0380048
	ERROR_VOLMGR_VOLUME_NOT_MIRRORED                                          syscall.Errno = 0xC0380049
	ERROR_VOLMGR_VOLUME_NOT_RETAINED                                          syscall.Errno = 0xC038004A
	ERROR_VOLMGR_VOLUME_OFFLINE                                               syscall.Errno = 0xC038004B
	ERROR_VOLMGR_VOLUME_RETAINED                                              syscall.Errno = 0xC038004C
	ERROR_VOLMGR_NUMBER_OF_EXTENTS_INVALID                                    syscall.Errno = 0xC038004D
	ERROR_VOLMGR_DIFFERENT_SECTOR_SIZE                                        syscall.Errno = 0xC038004E
	ERROR_VOLMGR_BAD_BOOT_DISK                                                syscall.Errno = 0xC038004F
	ERROR_VOLMGR_PACK_CONFIG_OFFLINE                                          syscall.Errno = 0xC0380050
	ERROR_VOLMGR_PACK_CONFIG_ONLINE                                           syscall.Errno = 0xC0380051
	ERROR_VOLMGR_NOT_PRIMARY_PACK                                             syscall.Errno = 0xC0380052
	ERROR_VOLMGR_PACK_LOG_UPDATE_FAILED                                       syscall.Errno = 0xC0380053
	ERROR_VOLMGR_NUMBER_OF_DISKS_IN_PLEX_INVALID                              syscall.Errno = 0xC0380054
	ERROR_VOLMGR_NUMBER_OF_DISKS_IN_MEMBER_INVALID                            syscall.Errno = 0xC0380055
	ERROR_VOLMGR_VOLUME_MIRRORED                                              syscall.Errno = 0xC0380056
	ERROR_VOLMGR_PLEX_NOT_SIMPLE_SPANNED                                      syscall.Errno = 0xC0380057
	ERROR_VOLMGR_NO_VALID_LOG_COPIES                                          syscall.Errno = 0xC0380058
	ERROR_VOLMGR_PRIMARY_PACK_PRESENT                                         syscall.Errno = 0xC0380059
	ERROR_VOLMGR_NUMBER_OF_DISKS_INVALID                                      syscall.Errno = 0xC038005A
	ERROR_VOLMGR_MIRROR_NOT_SUPPORTED                                         syscall.Errno = 0xC038005B
	ERROR_VOLMGR_RAID5_NOT_SUPPORTED                                          syscall.Errno = 0xC038005C
	ERROR_BCD_NOT_ALL_ENTRIES_IMPORTED                                        syscall.Errno = 0x80390001
	ERROR_BCD_TOO_MANY_ELEMENTS                                               syscall.Errno = 0xC0390002
	ERROR_BCD_NOT_ALL_ENTRIES_SYNCHRONIZED                                    syscall.Errno = 0x80390003
	ERROR_VHD_DRIVE_FOOTER_MISSING                                            syscall.Errno = 0xC03A0001
	ERROR_VHD_DRIVE_FOOTER_CHECKSUM_MISMATCH                                  syscall.Errno = 0xC03A0002
	ERROR_VHD_DRIVE_FOOTER_CORRUPT                                            syscall.Errno = 0xC03A0003
	ERROR_VHD_FORMAT_UNKNOWN                                                  syscall.Errno = 0xC03A0004
	ERROR_VHD_FORMAT_UNSUPPORTED_VERSION                                      syscall.Errno = 0xC03A0005
	ERROR_VHD_SPARSE_HEADER_CHECKSUM_MISMATCH                                 syscall.Errno = 0xC03A0006
	ERROR_VHD_SPARSE_HEADER_UNSUPPORTED_VERSION                               syscall.Errno = 0xC03A0007
	ERROR_VHD_SPARSE_HEADER_CORRUPT                                           syscall.Errno = 0xC03A0008
	ERROR_VHD_BLOCK_ALLOCATION_FAILURE                                        syscall.Errno = 0xC03A0009
	ERROR_VHD_BLOCK_ALLOCATION_TABLE_CORRUPT                                  syscall.Errno = 0xC03A000A
	ERROR_VHD_INVALID_BLOCK_SIZE                                              syscall.Errno = 0xC03A000B
	ERROR_VHD_BITMAP_MISMATCH                                                 syscall.Errno = 0xC03A000C
	ERROR_VHD_PARENT_VHD_NOT_FOUND                                            syscall.Errno = 0xC03A000D
	ERROR_VHD_CHILD_PARENT_ID_MISMATCH                                        syscall.Errno = 0xC03A000E
	ERROR_VHD_CHILD_PARENT_TIMESTAMP_MISMATCH                                 syscall.Errno = 0xC03A000F
	ERROR_VHD_METADATA_READ_FAILURE                                           syscall.Errno = 0xC03A0010
	ERROR_VHD_METADATA_WRITE_FAILURE                                          syscall.Errno = 0xC03A0011
	ERROR_VHD_INVALID_SIZE                                                    syscall.Errno = 0xC03A0012
	ERROR_VHD_INVALID_FILE_SIZE                                               syscall.Errno = 0xC03A0013
	ERROR_VIRTDISK_PROVIDER_NOT_FOUND                                         syscall.Errno = 0xC03A0014
	ERROR_VIRTDISK_NOT_VIRTUAL_DISK                                           syscall.Errno = 0xC03A0015
	ERROR_VHD_PARENT_VHD_ACCESS_DENIED                                        syscall.Errno = 0xC03A0016
	ERROR_VHD_CHILD_PARENT_SIZE_MISMATCH                                      syscall.Errno = 0xC03A0017
	ERROR_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED                               syscall.Errno = 0xC03A0018
	ERROR_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT                              syscall.Errno = 0xC03A0019
	ERROR_VIRTUAL_DISK_LIMITATION                                             syscall.Errno = 0xC03A001A
	ERROR_VHD_INVALID_TYPE                                                    syscall.Errno = 0xC03A001B
	ERROR_VHD_INVALID_STATE                                                   syscall.Errno = 0xC03A001C
	ERROR_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE                               syscall.Errno = 0xC03A001D
	ERROR_VIRTDISK_DISK_ALREADY_OWNED                                         syscall.Errno = 0xC03A001E
	ERROR_VIRTDISK_DISK_ONLINE_AND_WRITABLE                                   syscall.Errno = 0xC03A001F
	ERROR_CTLOG_TRACKING_NOT_INITIALIZED                                      syscall.Errno = 0xC03A0020
	ERROR_CTLOG_LOGFILE_SIZE_EXCEEDED_MAXSIZE                                 syscall.Errno = 0xC03A0021
	ERROR_CTLOG_VHD_CHANGED_OFFLINE                                           syscall.Errno = 0xC03A0022
	ERROR_CTLOG_INVALID_TRACKING_STATE                                        syscall.Errno = 0xC03A0023
	ERROR_CTLOG_INCONSISTENT_TRACKING_FILE                                    syscall.Errno = 0xC03A0024
	ERROR_VHD_RESIZE_WOULD_TRUNCATE_DATA                                      syscall.Errno = 0xC03A0025
	ERROR_VHD_COULD_NOT_COMPUTE_MINIMUM_VIRTUAL_SIZE                          syscall.Errno = 0xC03A0026
	ERROR_VHD_ALREADY_AT_OR_BELOW_MINIMUM_VIRTUAL_SIZE                        syscall.Errno = 0xC03A0027
	ERROR_VHD_METADATA_FULL                                                   syscall.Errno = 0xC03A0028
	ERROR_VHD_INVALID_CHANGE_TRACKING_ID                                      syscall.Errno = 0xC03A0029
	ERROR_VHD_CHANGE_TRACKING_DISABLED                                        syscall.Errno = 0xC03A002A
	ERROR_VHD_MISSING_CHANGE_TRACKING_INFORMATION                             syscall.Errno = 0xC03A0030
	ERROR_QUERY_STORAGE_ERROR                                                 syscall.Errno = 0x803A0001
	HCN_E_NETWORK_NOT_FOUND                                                   Handle        = 0x803B0001
	HCN_E_ENDPOINT_NOT_FOUND                                                  Handle        = 0x803B0002
	HCN_E_LAYER_NOT_FOUND                                                     Handle        = 0x803B0003
	HCN_E_SWITCH_NOT_FOUND                                                    Handle        = 0x803B0004
	HCN_E_SUBNET_NOT_FOUND                                                    Handle        = 0x803B0005
	HCN_E_ADAPTER_NOT_FOUND                                                   Handle        = 0x803B0006
	HCN_E_PORT_NOT_FOUND                                                      Handle        = 0x803B0007
	HCN_E_POLICY_NOT_FOUND                                                    Handle        = 0x803B0008
	HCN_E_VFP_PORTSETTING_NOT_FOUND                                           Handle        = 0x803B0009
	HCN_E_INVALID_NETWORK                                                     Handle        = 0x803B000A
	HCN_E_INVALID_NETWORK_TYPE                                                Handle        = 0x803B000B
	HCN_E_INVALID_ENDPOINT                                                    Handle        = 0x803B000C
	HCN_E_INVALID_POLICY                                                      Handle        = 0x803B000D
	HCN_E_INVALID_POLICY_TYPE                                                 Handle        = 0x803B000E
	HCN_E_INVALID_REMOTE_ENDPOINT_OPERATION                                   Handle        = 0x803B000F
	HCN_E_NETWORK_ALREADY_EXISTS                                              Handle        = 0x803B0010
	HCN_E_LAYER_ALREADY_EXISTS                                                Handle        = 0x803B0011
	HCN_E_POLICY_ALREADY_EXISTS                                               Handle        = 0x803B0012
	HCN_E_PORT_ALREADY_EXISTS                                                 Handle        = 0x803B0013
	HCN_E_ENDPOINT_ALREADY_ATTACHED                                           Handle        = 0x803B0014
	HCN_E_REQUEST_UNSUPPORTED                                                 Handle        = 0x803B0015
	HCN_E_MAPPING_NOT_SUPPORTED                                               Handle        = 0x803B0016
	HCN_E_DEGRADED_OPERATION                                                  Handle        = 0x803B0017
	HCN_E_SHARED_SWITCH_MODIFICATION                                          Handle        = 0x803B0018
	HCN_E_GUID_CONVERSION_FAILURE                                             Handle        = 0x803B0019
	HCN_E_REGKEY_FAILURE                                                      Handle        = 0x803B001A
	HCN_E_INVALID_JSON                                                        Handle        = 0x803B001B
	HCN_E_INVALID_JSON_REFERENCE                                              Handle        = 0x803B001C
	HCN_E_ENDPOINT_SHARING_DISABLED                                           Handle        = 0x803B001D
	HCN_E_INVALID_IP                                                          Handle        = 0x803B001E
	HCN_E_SWITCH_EXTENSION_NOT_FOUND                                          Handle        = 0x803B001F
	HCN_E_MANAGER_STOPPED                                                     Handle        = 0x803B0020
	GCN_E_MODULE_NOT_FOUND                                                    Handle        = 0x803B0021
	GCN_E_NO_REQUEST_HANDLERS                                                 Handle        = 0x803B0022
	GCN_E_REQUEST_UNSUPPORTED                                                 Handle        = 0x803B0023
	GCN_E_RUNTIMEKEYS_FAILED                                                  Handle        = 0x803B0024
	GCN_E_NETADAPTER_TIMEOUT                                                  Handle        = 0x803B0025
	GCN_E_NETADAPTER_NOT_FOUND                                                Handle        = 0x803B0026
	GCN_E_NETCOMPARTMENT_NOT_FOUND                                            Handle        = 0x803B0027
	GCN_E_NETINTERFACE_NOT_FOUND                                              Handle        = 0x803B0028
	GCN_E_DEFAULTNAMESPACE_EXISTS                                             Handle        = 0x803B0029
	HCN_E_ICS_DISABLED                                                        Handle        = 0x803B002A
	HCN_E_ENDPOINT_NAMESPACE_ALREADY_EXISTS                                   Handle        = 0x803B002B
	HCN_E_ENTITY_HAS_REFERENCES                                               Handle        = 0x803B002C
	HCN_E_INVALID_INTERNAL_PORT                                               Handle        = 0x803B002D
	HCN_E_NAMESPACE_ATTACH_FAILED                                             Handle        = 0x803B002E
	HCN_E_ADDR_INVALID_OR_RESERVED                                            Handle        = 0x803B002F
	SDIAG_E_CANCELLED                                                         syscall.Errno = 0x803C0100
	SDIAG_E_SCRIPT                                                            syscall.Errno = 0x803C0101
	SDIAG_E_POWERSHELL                                                        syscall.Errno = 0x803C0102
	SDIAG_E_MANAGEDHOST                                                       syscall.Errno = 0x803C0103
	SDIAG_E_NOVERIFIER                                                        syscall.Errno = 0x803C0104
	SDIAG_S_CANNOTRUN                                                         syscall.Errno = 0x003C0105
	SDIAG_E_DISABLED                                                          syscall.Errno = 0x803C0106
	SDIAG_E_TRUST                                                             syscall.Errno = 0x803C0107
	SDIAG_E_CANNOTRUN                                                         syscall.Errno = 0x803C0108
	SDIAG_E_VERSION                                                           syscall.Errno = 0x803C0109
	SDIAG_E_RESOURCE                                                          syscall.Errno = 0x803C010A
	SDIAG_E_ROOTCAUSE                                                         syscall.Errno = 0x803C010B
	WPN_E_CHANNEL_CLOSED                                                      Handle        = 0x803E0100
	WPN_E_CHANNEL_REQUEST_NOT_COMPLETE                                        Handle        = 0x803E0101
	WPN_E_INVALID_APP                                                         Handle        = 0x803E0102
	WPN_E_OUTSTANDING_CHANNEL_REQUEST                                         Handle        = 0x803E0103
	WPN_E_DUPLICATE_CHANNEL                                                   Handle        = 0x803E0104
	WPN_E_PLATFORM_UNAVAILABLE                                                Handle        = 0x803E0105
	WPN_E_NOTIFICATION_POSTED                                                 Handle        = 0x803E0106
	WPN_E_NOTIFICATION_HIDDEN                                                 Handle        = 0x803E0107
	WPN_E_NOTIFICATION_NOT_POSTED                                             Handle        = 0x803E0108
	WPN_E_CLOUD_DISABLED                                                      Handle        = 0x803E0109
	WPN_E_CLOUD_INCAPABLE                                                     Handle        = 0x803E0110
	WPN_E_CLOUD_AUTH_UNAVAILABLE                                              Handle        = 0x803E011A
	WPN_E_CLOUD_SERVICE_UNAVAILABLE                                           Handle        = 0x803E011B
	WPN_E_FAILED_LOCK_SCREEN_UPDATE_INTIALIZATION                             Handle        = 0x803E011C
	WPN_E_NOTIFICATION_DISABLED                                               Handle        = 0x803E0111
	WPN_E_NOTIFICATION_INCAPABLE                                              Handle        = 0x803E0112
	WPN_E_INTERNET_INCAPABLE                                                  Handle        = 0x803E0113
	WPN_E_NOTIFICATION_TYPE_DISABLED                                          Handle        = 0x803E0114
	WPN_E_NOTIFICATION_SIZE                                                   Handle        = 0x803E0115
	WPN_E_TAG_SIZE                                                            Handle        = 0x803E0116
	WPN_E_ACCESS_DENIED                                                       Handle        = 0x803E0117
	WPN_E_DUPLICATE_REGISTRATION                                              Handle        = 0x803E0118
	WPN_E_PUSH_NOTIFICATION_INCAPABLE                                         Handle        = 0x803E0119
	WPN_E_DEV_ID_SIZE                                                         Handle        = 0x803E0120
	WPN_E_TAG_ALPHANUMERIC                                                    Handle        = 0x803E012A
	WPN_E_INVALID_HTTP_STATUS_CODE                                            Handle        = 0x803E012B
	WPN_E_OUT_OF_SESSION                                                      Handle        = 0x803E0200
	WPN_E_POWER_SAVE                                                          Handle        = 0x803E0201
	WPN_E_IMAGE_NOT_FOUND_IN_CACHE                                            Handle        = 0x803E0202
	WPN_E_ALL_URL_NOT_COMPLETED                                               Handle        = 0x803E0203
	WPN_E_INVALID_CLOUD_IMAGE                                                 Handle        = 0x803E0204
	WPN_E_NOTIFICATION_ID_MATCHED                                             Handle        = 0x803E0205
	WPN_E_CALLBACK_ALREADY_REGISTERED                                         Handle        = 0x803E0206
	WPN_E_TOAST_NOTIFICATION_DROPPED                                          Handle        = 0x803E0207
	WPN_E_STORAGE_LOCKED                                                      Handle        = 0x803E0208
	WPN_E_GROUP_SIZE                                                          Handle        = 0x803E0209
	WPN_E_GROUP_ALPHANUMERIC                                                  Handle        = 0x803E020A
	WPN_E_CLOUD_DISABLED_FOR_APP                                              Handle        = 0x803E020B
	E_MBN_CONTEXT_NOT_ACTIVATED                                               Handle        = 0x80548201
	E_MBN_BAD_SIM                                                             Handle        = 0x80548202
	E_MBN_DATA_CLASS_NOT_AVAILABLE                                            Handle        = 0x8054820
```