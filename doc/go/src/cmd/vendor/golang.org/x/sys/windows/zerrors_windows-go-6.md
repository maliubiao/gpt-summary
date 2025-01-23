Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Observation and Context:**

* **File Path:** `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go`. This immediately tells us several things:
    * It's Go code.
    * It's part of the `golang.org/x/sys` project, which is the Go team's package for interacting with low-level system APIs.
    * It's within the `windows` subdirectory, meaning it's specific to Windows.
    * It's in a `vendor` directory, implying it's a vendored dependency (likely within the `cmd` package, though not strictly confirmed by this snippet alone).
    * The `zerrors_windows.go` name strongly suggests it defines error codes. The "z" likely signifies it's automatically generated or has a specific purpose in the build process (though for this analysis, we treat it as a regular source file).

* **Content:** The content is a long list of constants defined using the Go syntax `Identifier = Value`. The values are hexadecimal numbers. Many of the identifiers follow a pattern like `SEC_E_...`, `CRYPT_E_...`, `SCARD_E_...`, etc. The `E` often hints at "Error" and `S` at "Success" or "Status."

**2. Core Functionality Identification:**

* **Error Code Definition:** The most obvious function is defining a collection of named constants that represent Windows error codes or status codes. The hexadecimal values reinforce this.

**3. Inferring Go Language Feature:**

* **Constants:** The code directly uses Go's `const` keyword (implicitly through the `=` assignment at the package level). This is the fundamental mechanism for defining named constants in Go.

**4. Code Example (Illustrative):**

* The need is to show how these constants are used. The most common use case for error codes is checking them after a system call or a function that interacts with the Windows API.
* A plausible example would involve a function from the `syscall` package, which is often used for direct system calls. A function related to security (given the `SEC_E` prefixes) or cryptography (`CRYPT_E`) would be relevant. `syscall.GetLastError()` is a classic example of retrieving the last error.
* The thought process would be: "How do I get an error code from Windows?" -> "Oh, `syscall.GetLastError()`." -> "How do I check if the error code is a specific one?" -> "By comparing it to the defined constants."

**5. Assumptions for the Code Example:**

* The code assumes a hypothetical function `AuthenticateUser()` that might return a Windows error code.
* It assumes that the `syscall` package is imported.

**6. Output of the Code Example:**

* The output would depend on the actual error returned by the hypothetical `AuthenticateUser()` function. The example shows checking for `SEC_E_LOGON_DENIED` and printing a message accordingly.

**7. Command-Line Arguments:**

* Reviewing the code snippet, there's no indication of command-line argument processing. It's just a definition of constants. Therefore, this section of the prompt is not applicable.

**8. Common Mistakes:**

* **Incorrect Comparison:** A common mistake when working with error codes is incorrect comparison. For instance, using `==` when the function might return a *different* error code that still signifies a failure. The example uses direct equality for simplicity, but a more robust approach might involve checking a range or category of errors. However, since the prompt asked for *easy* mistakes, direct comparison is a simple and valid example.

**9. 归纳 (Summarization):**

* Combine the identified functionalities: defining Windows error codes, specifically related to security, cryptography, smart cards, COM, WER, and filter management.

**10. Part Number:**

* Acknowledge that this is part 7 of 15.

**Self-Correction/Refinement:**

* Initially, I might have thought about more complex scenarios involving these error codes, such as using them with specific Windows APIs like the Security Support Provider Interface (SSPI) for `SEC_E` errors. However, the prompt asked for a *simple* example. Sticking with `syscall.GetLastError()` makes the example easier to understand.
* I considered mentioning the `errors` package and how to create Go error values from these constants, but that might be too advanced for a basic functional description. The focus should be on the direct use of the constants.
* Initially, I overlooked the `Handle` type in the constant definitions. While it's an alias for `uint32`, mentioning its presence is a detail that improves accuracy.

By following this structured thought process, we can systematically analyze the code snippet and address all parts of the prompt effectively.
这是一个Go语言实现的片段，其主要功能是**定义了一系列代表Windows系统错误的常量**。

这些常量主要来源于不同的Windows API领域，例如：

* **SEC_E_...:**  与安全相关的错误，例如身份验证、授权等。
* **CRYPT_E_...:** 与加密相关的错误，例如算法不支持、数据格式错误等。
* **OSS_...:**  可能与ASN.1（Abstract Syntax Notation One）编码/解码相关的错误。
* **CERTSRV_E_...:** 与证书服务相关的错误。
* **XENROLL_E_...:** 与证书注册相关的错误。
* **TRUST_E_...:** 与信任验证相关的错误。
* **MSSIPOTF_E_...:**  可能与微软签名对象文件格式（Microsoft Signed Package Object File Format）相关的错误。
* **SPAPI_E_...:** 与设备安装和配置相关的错误（SetupAPI）。
* **SCARD_...:** 与智能卡相关的状态码和错误码。
* **COMADMIN_E_...:** 与COM+组件管理相关的错误。
* **COMQC_E_...:** 与COM+排队组件相关的错误。
* **MSDTC_E_...:** 与分布式事务协调器（Microsoft Distributed Transaction Coordinator）相关的错误。
* **WER_...:** 与Windows错误报告相关的状态和错误。
* **ERROR_FLT_...:** 与文件系统过滤驱动相关的错误。
* **DWM_...:** 与桌面窗口管理器（Desktop Window Manager）相关的状态和错误。
* **ERROR_MONITOR_...:** 与显示器相关的错误。
* **ERROR_GRAPHICS_...:** 与图形设备相关的错误。

**它是什么Go语言功能的实现？**

这个代码片段主要是利用Go语言的**常量 (const)** 定义功能来实现的。Go语言的常量用于声明在编译时就已知其值的标识符。在这里，每个Windows错误码都被赋予了一个有意义的Go常量名。

**Go代码举例说明:**

假设你正在编写一个Go程序，需要调用Windows API来执行某些安全相关的操作，例如用户登录。如果登录失败，Windows API可能会返回一个特定的错误码。你可以使用这里定义的常量来判断具体的错误原因。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows" // 假设你的代码中引入了这个包
)

// 假设这是一个调用Windows API进行用户认证的函数（简化示例）
func AuthenticateUser(username, password string) (bool, error) {
	// ... 这里会调用 Windows API，例如 LogonUser
	// 为了演示，我们假设登录失败并返回一个特定的错误码
	return false, syscall.Errno(windows.SEC_E_LOGON_DENIED)
}

func main() {
	authenticated, err := AuthenticateUser("testuser", "wrongpassword")
	if err != nil {
		errno, ok := err.(syscall.Errno)
		if ok {
			switch errno {
			case windows.SEC_E_LOGON_DENIED:
				fmt.Println("登录失败：用户名或密码错误")
			case windows.SEC_E_ACCOUNT_DISABLED:
				fmt.Println("登录失败：账户已被禁用")
			// ... 其他可能的错误处理
			default:
				fmt.Printf("登录失败，未知错误代码: 0x%x\n", uintptr(errno))
			}
		} else {
			fmt.Println("登录失败，发生未知错误:", err)
		}
		return
	}

	if authenticated {
		fmt.Println("登录成功!")
	}
}
```

**假设的输入与输出:**

在上面的例子中，假设 `AuthenticateUser` 函数内部调用了 Windows API 的登录函数，并且由于密码错误，Windows API 返回了错误码 `SEC_E_LOGON_DENIED` (其值在提供的代码片段中可以找到)。

**输出:**

```
登录失败：用户名或密码错误
```

**命令行参数的具体处理:**

这个代码片段本身不涉及命令行参数的处理。它只是定义了一些常量。命令行参数的处理通常发生在程序的 `main` 函数中，使用 `os.Args` 或 `flag` 包进行解析。

**使用者易犯错的点:**

* **错误码的直接比较:**  容易直接将系统调用返回的错误码与这些常量进行比较。需要注意的是，系统调用返回的 `error` 类型可能需要类型断言才能转换为 `syscall.Errno`，才能进行比较。就像上面的代码示例中展示的那样。
* **忽略错误码的范围:**  有些错误可能属于一个大的类别，直接比较可能不够精确。例如，`CRYPT_E_` 开头的错误都与加密相关，你可能需要检查错误码是否在这个范围内，而不是只关注特定的几个错误。
* **假设所有错误都是 `syscall.Errno`:** 虽然大多数情况下Windows API的错误会转换为 `syscall.Errno`，但也存在其他类型的错误。因此，在处理错误时，应该先进行类型判断。

**归纳一下它的功能 (第7部分，共15部分):**

这个代码片段（作为 `zerrors_windows.go` 文件的一部分）的主要功能是**定义了大量的Windows系统错误码常量，方便Go程序在与Windows系统交互时，能够以可读性强的方式识别和处理各种错误情况**。它为开发者提供了一组预定义的符号来代表底层的Windows错误，提高了代码的可维护性和可读性。这些常量涵盖了安全、加密、设备管理、智能卡、COM 等多个Windows API领域。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第7部分，共15部分，请归纳一下它的功能
```

### 源代码
```go
Handle        = 0x00090360
	SEC_E_NO_CONTEXT                                                          Handle        = 0x80090361
	SEC_E_PKU2U_CERT_FAILURE                                                  Handle        = 0x80090362
	SEC_E_MUTUAL_AUTH_FAILED                                                  Handle        = 0x80090363
	SEC_I_MESSAGE_FRAGMENT                                                    Handle        = 0x00090364
	SEC_E_ONLY_HTTPS_ALLOWED                                                  Handle        = 0x80090365
	SEC_I_CONTINUE_NEEDED_MESSAGE_OK                                          Handle        = 0x00090366
	SEC_E_APPLICATION_PROTOCOL_MISMATCH                                       Handle        = 0x80090367
	SEC_I_ASYNC_CALL_PENDING                                                  Handle        = 0x00090368
	SEC_E_INVALID_UPN_NAME                                                    Handle        = 0x80090369
	SEC_E_EXT_BUFFER_TOO_SMALL                                                Handle        = 0x8009036A
	SEC_E_INSUFFICIENT_BUFFERS                                                Handle        = 0x8009036B
	SEC_E_NO_SPM                                                                            = SEC_E_INTERNAL_ERROR
	SEC_E_NOT_SUPPORTED                                                                     = SEC_E_UNSUPPORTED_FUNCTION
	CRYPT_E_MSG_ERROR                                                         Handle        = 0x80091001
	CRYPT_E_UNKNOWN_ALGO                                                      Handle        = 0x80091002
	CRYPT_E_OID_FORMAT                                                        Handle        = 0x80091003
	CRYPT_E_INVALID_MSG_TYPE                                                  Handle        = 0x80091004
	CRYPT_E_UNEXPECTED_ENCODING                                               Handle        = 0x80091005
	CRYPT_E_AUTH_ATTR_MISSING                                                 Handle        = 0x80091006
	CRYPT_E_HASH_VALUE                                                        Handle        = 0x80091007
	CRYPT_E_INVALID_INDEX                                                     Handle        = 0x80091008
	CRYPT_E_ALREADY_DECRYPTED                                                 Handle        = 0x80091009
	CRYPT_E_NOT_DECRYPTED                                                     Handle        = 0x8009100A
	CRYPT_E_RECIPIENT_NOT_FOUND                                               Handle        = 0x8009100B
	CRYPT_E_CONTROL_TYPE                                                      Handle        = 0x8009100C
	CRYPT_E_ISSUER_SERIALNUMBER                                               Handle        = 0x8009100D
	CRYPT_E_SIGNER_NOT_FOUND                                                  Handle        = 0x8009100E
	CRYPT_E_ATTRIBUTES_MISSING                                                Handle        = 0x8009100F
	CRYPT_E_STREAM_MSG_NOT_READY                                              Handle        = 0x80091010
	CRYPT_E_STREAM_INSUFFICIENT_DATA                                          Handle        = 0x80091011
	CRYPT_I_NEW_PROTECTION_REQUIRED                                           Handle        = 0x00091012
	CRYPT_E_BAD_LEN                                                           Handle        = 0x80092001
	CRYPT_E_BAD_ENCODE                                                        Handle        = 0x80092002
	CRYPT_E_FILE_ERROR                                                        Handle        = 0x80092003
	CRYPT_E_NOT_FOUND                                                         Handle        = 0x80092004
	CRYPT_E_EXISTS                                                            Handle        = 0x80092005
	CRYPT_E_NO_PROVIDER                                                       Handle        = 0x80092006
	CRYPT_E_SELF_SIGNED                                                       Handle        = 0x80092007
	CRYPT_E_DELETED_PREV                                                      Handle        = 0x80092008
	CRYPT_E_NO_MATCH                                                          Handle        = 0x80092009
	CRYPT_E_UNEXPECTED_MSG_TYPE                                               Handle        = 0x8009200A
	CRYPT_E_NO_KEY_PROPERTY                                                   Handle        = 0x8009200B
	CRYPT_E_NO_DECRYPT_CERT                                                   Handle        = 0x8009200C
	CRYPT_E_BAD_MSG                                                           Handle        = 0x8009200D
	CRYPT_E_NO_SIGNER                                                         Handle        = 0x8009200E
	CRYPT_E_PENDING_CLOSE                                                     Handle        = 0x8009200F
	CRYPT_E_REVOKED                                                           Handle        = 0x80092010
	CRYPT_E_NO_REVOCATION_DLL                                                 Handle        = 0x80092011
	CRYPT_E_NO_REVOCATION_CHECK                                               Handle        = 0x80092012
	CRYPT_E_REVOCATION_OFFLINE                                                Handle        = 0x80092013
	CRYPT_E_NOT_IN_REVOCATION_DATABASE                                        Handle        = 0x80092014
	CRYPT_E_INVALID_NUMERIC_STRING                                            Handle        = 0x80092020
	CRYPT_E_INVALID_PRINTABLE_STRING                                          Handle        = 0x80092021
	CRYPT_E_INVALID_IA5_STRING                                                Handle        = 0x80092022
	CRYPT_E_INVALID_X500_STRING                                               Handle        = 0x80092023
	CRYPT_E_NOT_CHAR_STRING                                                   Handle        = 0x80092024
	CRYPT_E_FILERESIZED                                                       Handle        = 0x80092025
	CRYPT_E_SECURITY_SETTINGS                                                 Handle        = 0x80092026
	CRYPT_E_NO_VERIFY_USAGE_DLL                                               Handle        = 0x80092027
	CRYPT_E_NO_VERIFY_USAGE_CHECK                                             Handle        = 0x80092028
	CRYPT_E_VERIFY_USAGE_OFFLINE                                              Handle        = 0x80092029
	CRYPT_E_NOT_IN_CTL                                                        Handle        = 0x8009202A
	CRYPT_E_NO_TRUSTED_SIGNER                                                 Handle        = 0x8009202B
	CRYPT_E_MISSING_PUBKEY_PARA                                               Handle        = 0x8009202C
	CRYPT_E_OBJECT_LOCATOR_OBJECT_NOT_FOUND                                   Handle        = 0x8009202D
	CRYPT_E_OSS_ERROR                                                         Handle        = 0x80093000
	OSS_MORE_BUF                                                              Handle        = 0x80093001
	OSS_NEGATIVE_UINTEGER                                                     Handle        = 0x80093002
	OSS_PDU_RANGE                                                             Handle        = 0x80093003
	OSS_MORE_INPUT                                                            Handle        = 0x80093004
	OSS_DATA_ERROR                                                            Handle        = 0x80093005
	OSS_BAD_ARG                                                               Handle        = 0x80093006
	OSS_BAD_VERSION                                                           Handle        = 0x80093007
	OSS_OUT_MEMORY                                                            Handle        = 0x80093008
	OSS_PDU_MISMATCH                                                          Handle        = 0x80093009
	OSS_LIMITED                                                               Handle        = 0x8009300A
	OSS_BAD_PTR                                                               Handle        = 0x8009300B
	OSS_BAD_TIME                                                              Handle        = 0x8009300C
	OSS_INDEFINITE_NOT_SUPPORTED                                              Handle        = 0x8009300D
	OSS_MEM_ERROR                                                             Handle        = 0x8009300E
	OSS_BAD_TABLE                                                             Handle        = 0x8009300F
	OSS_TOO_LONG                                                              Handle        = 0x80093010
	OSS_CONSTRAINT_VIOLATED                                                   Handle        = 0x80093011
	OSS_FATAL_ERROR                                                           Handle        = 0x80093012
	OSS_ACCESS_SERIALIZATION_ERROR                                            Handle        = 0x80093013
	OSS_NULL_TBL                                                              Handle        = 0x80093014
	OSS_NULL_FCN                                                              Handle        = 0x80093015
	OSS_BAD_ENCRULES                                                          Handle        = 0x80093016
	OSS_UNAVAIL_ENCRULES                                                      Handle        = 0x80093017
	OSS_CANT_OPEN_TRACE_WINDOW                                                Handle        = 0x80093018
	OSS_UNIMPLEMENTED                                                         Handle        = 0x80093019
	OSS_OID_DLL_NOT_LINKED                                                    Handle        = 0x8009301A
	OSS_CANT_OPEN_TRACE_FILE                                                  Handle        = 0x8009301B
	OSS_TRACE_FILE_ALREADY_OPEN                                               Handle        = 0x8009301C
	OSS_TABLE_MISMATCH                                                        Handle        = 0x8009301D
	OSS_TYPE_NOT_SUPPORTED                                                    Handle        = 0x8009301E
	OSS_REAL_DLL_NOT_LINKED                                                   Handle        = 0x8009301F
	OSS_REAL_CODE_NOT_LINKED                                                  Handle        = 0x80093020
	OSS_OUT_OF_RANGE                                                          Handle        = 0x80093021
	OSS_COPIER_DLL_NOT_LINKED                                                 Handle        = 0x80093022
	OSS_CONSTRAINT_DLL_NOT_LINKED                                             Handle        = 0x80093023
	OSS_COMPARATOR_DLL_NOT_LINKED                                             Handle        = 0x80093024
	OSS_COMPARATOR_CODE_NOT_LINKED                                            Handle        = 0x80093025
	OSS_MEM_MGR_DLL_NOT_LINKED                                                Handle        = 0x80093026
	OSS_PDV_DLL_NOT_LINKED                                                    Handle        = 0x80093027
	OSS_PDV_CODE_NOT_LINKED                                                   Handle        = 0x80093028
	OSS_API_DLL_NOT_LINKED                                                    Handle        = 0x80093029
	OSS_BERDER_DLL_NOT_LINKED                                                 Handle        = 0x8009302A
	OSS_PER_DLL_NOT_LINKED                                                    Handle        = 0x8009302B
	OSS_OPEN_TYPE_ERROR                                                       Handle        = 0x8009302C
	OSS_MUTEX_NOT_CREATED                                                     Handle        = 0x8009302D
	OSS_CANT_CLOSE_TRACE_FILE                                                 Handle        = 0x8009302E
	CRYPT_E_ASN1_ERROR                                                        Handle        = 0x80093100
	CRYPT_E_ASN1_INTERNAL                                                     Handle        = 0x80093101
	CRYPT_E_ASN1_EOD                                                          Handle        = 0x80093102
	CRYPT_E_ASN1_CORRUPT                                                      Handle        = 0x80093103
	CRYPT_E_ASN1_LARGE                                                        Handle        = 0x80093104
	CRYPT_E_ASN1_CONSTRAINT                                                   Handle        = 0x80093105
	CRYPT_E_ASN1_MEMORY                                                       Handle        = 0x80093106
	CRYPT_E_ASN1_OVERFLOW                                                     Handle        = 0x80093107
	CRYPT_E_ASN1_BADPDU                                                       Handle        = 0x80093108
	CRYPT_E_ASN1_BADARGS                                                      Handle        = 0x80093109
	CRYPT_E_ASN1_BADREAL                                                      Handle        = 0x8009310A
	CRYPT_E_ASN1_BADTAG                                                       Handle        = 0x8009310B
	CRYPT_E_ASN1_CHOICE                                                       Handle        = 0x8009310C
	CRYPT_E_ASN1_RULE                                                         Handle        = 0x8009310D
	CRYPT_E_ASN1_UTF8                                                         Handle        = 0x8009310E
	CRYPT_E_ASN1_PDU_TYPE                                                     Handle        = 0x80093133
	CRYPT_E_ASN1_NYI                                                          Handle        = 0x80093134
	CRYPT_E_ASN1_EXTENDED                                                     Handle        = 0x80093201
	CRYPT_E_ASN1_NOEOD                                                        Handle        = 0x80093202
	CERTSRV_E_BAD_REQUESTSUBJECT                                              Handle        = 0x80094001
	CERTSRV_E_NO_REQUEST                                                      Handle        = 0x80094002
	CERTSRV_E_BAD_REQUESTSTATUS                                               Handle        = 0x80094003
	CERTSRV_E_PROPERTY_EMPTY                                                  Handle        = 0x80094004
	CERTSRV_E_INVALID_CA_CERTIFICATE                                          Handle        = 0x80094005
	CERTSRV_E_SERVER_SUSPENDED                                                Handle        = 0x80094006
	CERTSRV_E_ENCODING_LENGTH                                                 Handle        = 0x80094007
	CERTSRV_E_ROLECONFLICT                                                    Handle        = 0x80094008
	CERTSRV_E_RESTRICTEDOFFICER                                               Handle        = 0x80094009
	CERTSRV_E_KEY_ARCHIVAL_NOT_CONFIGURED                                     Handle        = 0x8009400A
	CERTSRV_E_NO_VALID_KRA                                                    Handle        = 0x8009400B
	CERTSRV_E_BAD_REQUEST_KEY_ARCHIVAL                                        Handle        = 0x8009400C
	CERTSRV_E_NO_CAADMIN_DEFINED                                              Handle        = 0x8009400D
	CERTSRV_E_BAD_RENEWAL_CERT_ATTRIBUTE                                      Handle        = 0x8009400E
	CERTSRV_E_NO_DB_SESSIONS                                                  Handle        = 0x8009400F
	CERTSRV_E_ALIGNMENT_FAULT                                                 Handle        = 0x80094010
	CERTSRV_E_ENROLL_DENIED                                                   Handle        = 0x80094011
	CERTSRV_E_TEMPLATE_DENIED                                                 Handle        = 0x80094012
	CERTSRV_E_DOWNLEVEL_DC_SSL_OR_UPGRADE                                     Handle        = 0x80094013
	CERTSRV_E_ADMIN_DENIED_REQUEST                                            Handle        = 0x80094014
	CERTSRV_E_NO_POLICY_SERVER                                                Handle        = 0x80094015
	CERTSRV_E_WEAK_SIGNATURE_OR_KEY                                           Handle        = 0x80094016
	CERTSRV_E_KEY_ATTESTATION_NOT_SUPPORTED                                   Handle        = 0x80094017
	CERTSRV_E_ENCRYPTION_CERT_REQUIRED                                        Handle        = 0x80094018
	CERTSRV_E_UNSUPPORTED_CERT_TYPE                                           Handle        = 0x80094800
	CERTSRV_E_NO_CERT_TYPE                                                    Handle        = 0x80094801
	CERTSRV_E_TEMPLATE_CONFLICT                                               Handle        = 0x80094802
	CERTSRV_E_SUBJECT_ALT_NAME_REQUIRED                                       Handle        = 0x80094803
	CERTSRV_E_ARCHIVED_KEY_REQUIRED                                           Handle        = 0x80094804
	CERTSRV_E_SMIME_REQUIRED                                                  Handle        = 0x80094805
	CERTSRV_E_BAD_RENEWAL_SUBJECT                                             Handle        = 0x80094806
	CERTSRV_E_BAD_TEMPLATE_VERSION                                            Handle        = 0x80094807
	CERTSRV_E_TEMPLATE_POLICY_REQUIRED                                        Handle        = 0x80094808
	CERTSRV_E_SIGNATURE_POLICY_REQUIRED                                       Handle        = 0x80094809
	CERTSRV_E_SIGNATURE_COUNT                                                 Handle        = 0x8009480A
	CERTSRV_E_SIGNATURE_REJECTED                                              Handle        = 0x8009480B
	CERTSRV_E_ISSUANCE_POLICY_REQUIRED                                        Handle        = 0x8009480C
	CERTSRV_E_SUBJECT_UPN_REQUIRED                                            Handle        = 0x8009480D
	CERTSRV_E_SUBJECT_DIRECTORY_GUID_REQUIRED                                 Handle        = 0x8009480E
	CERTSRV_E_SUBJECT_DNS_REQUIRED                                            Handle        = 0x8009480F
	CERTSRV_E_ARCHIVED_KEY_UNEXPECTED                                         Handle        = 0x80094810
	CERTSRV_E_KEY_LENGTH                                                      Handle        = 0x80094811
	CERTSRV_E_SUBJECT_EMAIL_REQUIRED                                          Handle        = 0x80094812
	CERTSRV_E_UNKNOWN_CERT_TYPE                                               Handle        = 0x80094813
	CERTSRV_E_CERT_TYPE_OVERLAP                                               Handle        = 0x80094814
	CERTSRV_E_TOO_MANY_SIGNATURES                                             Handle        = 0x80094815
	CERTSRV_E_RENEWAL_BAD_PUBLIC_KEY                                          Handle        = 0x80094816
	CERTSRV_E_INVALID_EK                                                      Handle        = 0x80094817
	CERTSRV_E_INVALID_IDBINDING                                               Handle        = 0x80094818
	CERTSRV_E_INVALID_ATTESTATION                                             Handle        = 0x80094819
	CERTSRV_E_KEY_ATTESTATION                                                 Handle        = 0x8009481A
	CERTSRV_E_CORRUPT_KEY_ATTESTATION                                         Handle        = 0x8009481B
	CERTSRV_E_EXPIRED_CHALLENGE                                               Handle        = 0x8009481C
	CERTSRV_E_INVALID_RESPONSE                                                Handle        = 0x8009481D
	CERTSRV_E_INVALID_REQUESTID                                               Handle        = 0x8009481E
	CERTSRV_E_REQUEST_PRECERTIFICATE_MISMATCH                                 Handle        = 0x8009481F
	CERTSRV_E_PENDING_CLIENT_RESPONSE                                         Handle        = 0x80094820
	XENROLL_E_KEY_NOT_EXPORTABLE                                              Handle        = 0x80095000
	XENROLL_E_CANNOT_ADD_ROOT_CERT                                            Handle        = 0x80095001
	XENROLL_E_RESPONSE_KA_HASH_NOT_FOUND                                      Handle        = 0x80095002
	XENROLL_E_RESPONSE_UNEXPECTED_KA_HASH                                     Handle        = 0x80095003
	XENROLL_E_RESPONSE_KA_HASH_MISMATCH                                       Handle        = 0x80095004
	XENROLL_E_KEYSPEC_SMIME_MISMATCH                                          Handle        = 0x80095005
	TRUST_E_SYSTEM_ERROR                                                      Handle        = 0x80096001
	TRUST_E_NO_SIGNER_CERT                                                    Handle        = 0x80096002
	TRUST_E_COUNTER_SIGNER                                                    Handle        = 0x80096003
	TRUST_E_CERT_SIGNATURE                                                    Handle        = 0x80096004
	TRUST_E_TIME_STAMP                                                        Handle        = 0x80096005
	TRUST_E_BAD_DIGEST                                                        Handle        = 0x80096010
	TRUST_E_MALFORMED_SIGNATURE                                               Handle        = 0x80096011
	TRUST_E_BASIC_CONSTRAINTS                                                 Handle        = 0x80096019
	TRUST_E_FINANCIAL_CRITERIA                                                Handle        = 0x8009601E
	MSSIPOTF_E_OUTOFMEMRANGE                                                  Handle        = 0x80097001
	MSSIPOTF_E_CANTGETOBJECT                                                  Handle        = 0x80097002
	MSSIPOTF_E_NOHEADTABLE                                                    Handle        = 0x80097003
	MSSIPOTF_E_BAD_MAGICNUMBER                                                Handle        = 0x80097004
	MSSIPOTF_E_BAD_OFFSET_TABLE                                               Handle        = 0x80097005
	MSSIPOTF_E_TABLE_TAGORDER                                                 Handle        = 0x80097006
	MSSIPOTF_E_TABLE_LONGWORD                                                 Handle        = 0x80097007
	MSSIPOTF_E_BAD_FIRST_TABLE_PLACEMENT                                      Handle        = 0x80097008
	MSSIPOTF_E_TABLES_OVERLAP                                                 Handle        = 0x80097009
	MSSIPOTF_E_TABLE_PADBYTES                                                 Handle        = 0x8009700A
	MSSIPOTF_E_FILETOOSMALL                                                   Handle        = 0x8009700B
	MSSIPOTF_E_TABLE_CHECKSUM                                                 Handle        = 0x8009700C
	MSSIPOTF_E_FILE_CHECKSUM                                                  Handle        = 0x8009700D
	MSSIPOTF_E_FAILED_POLICY                                                  Handle        = 0x80097010
	MSSIPOTF_E_FAILED_HINTS_CHECK                                             Handle        = 0x80097011
	MSSIPOTF_E_NOT_OPENTYPE                                                   Handle        = 0x80097012
	MSSIPOTF_E_FILE                                                           Handle        = 0x80097013
	MSSIPOTF_E_CRYPT                                                          Handle        = 0x80097014
	MSSIPOTF_E_BADVERSION                                                     Handle        = 0x80097015
	MSSIPOTF_E_DSIG_STRUCTURE                                                 Handle        = 0x80097016
	MSSIPOTF_E_PCONST_CHECK                                                   Handle        = 0x80097017
	MSSIPOTF_E_STRUCTURE                                                      Handle        = 0x80097018
	ERROR_CRED_REQUIRES_CONFIRMATION                                          Handle        = 0x80097019
	NTE_OP_OK                                                                 syscall.Errno = 0
	TRUST_E_PROVIDER_UNKNOWN                                                  Handle        = 0x800B0001
	TRUST_E_ACTION_UNKNOWN                                                    Handle        = 0x800B0002
	TRUST_E_SUBJECT_FORM_UNKNOWN                                              Handle        = 0x800B0003
	TRUST_E_SUBJECT_NOT_TRUSTED                                               Handle        = 0x800B0004
	DIGSIG_E_ENCODE                                                           Handle        = 0x800B0005
	DIGSIG_E_DECODE                                                           Handle        = 0x800B0006
	DIGSIG_E_EXTENSIBILITY                                                    Handle        = 0x800B0007
	DIGSIG_E_CRYPTO                                                           Handle        = 0x800B0008
	PERSIST_E_SIZEDEFINITE                                                    Handle        = 0x800B0009
	PERSIST_E_SIZEINDEFINITE                                                  Handle        = 0x800B000A
	PERSIST_E_NOTSELFSIZING                                                   Handle        = 0x800B000B
	TRUST_E_NOSIGNATURE                                                       Handle        = 0x800B0100
	CERT_E_EXPIRED                                                            Handle        = 0x800B0101
	CERT_E_VALIDITYPERIODNESTING                                              Handle        = 0x800B0102
	CERT_E_ROLE                                                               Handle        = 0x800B0103
	CERT_E_PATHLENCONST                                                       Handle        = 0x800B0104
	CERT_E_CRITICAL                                                           Handle        = 0x800B0105
	CERT_E_PURPOSE                                                            Handle        = 0x800B0106
	CERT_E_ISSUERCHAINING                                                     Handle        = 0x800B0107
	CERT_E_MALFORMED                                                          Handle        = 0x800B0108
	CERT_E_UNTRUSTEDROOT                                                      Handle        = 0x800B0109
	CERT_E_CHAINING                                                           Handle        = 0x800B010A
	TRUST_E_FAIL                                                              Handle        = 0x800B010B
	CERT_E_REVOKED                                                            Handle        = 0x800B010C
	CERT_E_UNTRUSTEDTESTROOT                                                  Handle        = 0x800B010D
	CERT_E_REVOCATION_FAILURE                                                 Handle        = 0x800B010E
	CERT_E_CN_NO_MATCH                                                        Handle        = 0x800B010F
	CERT_E_WRONG_USAGE                                                        Handle        = 0x800B0110
	TRUST_E_EXPLICIT_DISTRUST                                                 Handle        = 0x800B0111
	CERT_E_UNTRUSTEDCA                                                        Handle        = 0x800B0112
	CERT_E_INVALID_POLICY                                                     Handle        = 0x800B0113
	CERT_E_INVALID_NAME                                                       Handle        = 0x800B0114
	SPAPI_E_EXPECTED_SECTION_NAME                                             Handle        = 0x800F0000
	SPAPI_E_BAD_SECTION_NAME_LINE                                             Handle        = 0x800F0001
	SPAPI_E_SECTION_NAME_TOO_LONG                                             Handle        = 0x800F0002
	SPAPI_E_GENERAL_SYNTAX                                                    Handle        = 0x800F0003
	SPAPI_E_WRONG_INF_STYLE                                                   Handle        = 0x800F0100
	SPAPI_E_SECTION_NOT_FOUND                                                 Handle        = 0x800F0101
	SPAPI_E_LINE_NOT_FOUND                                                    Handle        = 0x800F0102
	SPAPI_E_NO_BACKUP                                                         Handle        = 0x800F0103
	SPAPI_E_NO_ASSOCIATED_CLASS                                               Handle        = 0x800F0200
	SPAPI_E_CLASS_MISMATCH                                                    Handle        = 0x800F0201
	SPAPI_E_DUPLICATE_FOUND                                                   Handle        = 0x800F0202
	SPAPI_E_NO_DRIVER_SELECTED                                                Handle        = 0x800F0203
	SPAPI_E_KEY_DOES_NOT_EXIST                                                Handle        = 0x800F0204
	SPAPI_E_INVALID_DEVINST_NAME                                              Handle        = 0x800F0205
	SPAPI_E_INVALID_CLASS                                                     Handle        = 0x800F0206
	SPAPI_E_DEVINST_ALREADY_EXISTS                                            Handle        = 0x800F0207
	SPAPI_E_DEVINFO_NOT_REGISTERED                                            Handle        = 0x800F0208
	SPAPI_E_INVALID_REG_PROPERTY                                              Handle        = 0x800F0209
	SPAPI_E_NO_INF                                                            Handle        = 0x800F020A
	SPAPI_E_NO_SUCH_DEVINST                                                   Handle        = 0x800F020B
	SPAPI_E_CANT_LOAD_CLASS_ICON                                              Handle        = 0x800F020C
	SPAPI_E_INVALID_CLASS_INSTALLER                                           Handle        = 0x800F020D
	SPAPI_E_DI_DO_DEFAULT                                                     Handle        = 0x800F020E
	SPAPI_E_DI_NOFILECOPY                                                     Handle        = 0x800F020F
	SPAPI_E_INVALID_HWPROFILE                                                 Handle        = 0x800F0210
	SPAPI_E_NO_DEVICE_SELECTED                                                Handle        = 0x800F0211
	SPAPI_E_DEVINFO_LIST_LOCKED                                               Handle        = 0x800F0212
	SPAPI_E_DEVINFO_DATA_LOCKED                                               Handle        = 0x800F0213
	SPAPI_E_DI_BAD_PATH                                                       Handle        = 0x800F0214
	SPAPI_E_NO_CLASSINSTALL_PARAMS                                            Handle        = 0x800F0215
	SPAPI_E_FILEQUEUE_LOCKED                                                  Handle        = 0x800F0216
	SPAPI_E_BAD_SERVICE_INSTALLSECT                                           Handle        = 0x800F0217
	SPAPI_E_NO_CLASS_DRIVER_LIST                                              Handle        = 0x800F0218
	SPAPI_E_NO_ASSOCIATED_SERVICE                                             Handle        = 0x800F0219
	SPAPI_E_NO_DEFAULT_DEVICE_INTERFACE                                       Handle        = 0x800F021A
	SPAPI_E_DEVICE_INTERFACE_ACTIVE                                           Handle        = 0x800F021B
	SPAPI_E_DEVICE_INTERFACE_REMOVED                                          Handle        = 0x800F021C
	SPAPI_E_BAD_INTERFACE_INSTALLSECT                                         Handle        = 0x800F021D
	SPAPI_E_NO_SUCH_INTERFACE_CLASS                                           Handle        = 0x800F021E
	SPAPI_E_INVALID_REFERENCE_STRING                                          Handle        = 0x800F021F
	SPAPI_E_INVALID_MACHINENAME                                               Handle        = 0x800F0220
	SPAPI_E_REMOTE_COMM_FAILURE                                               Handle        = 0x800F0221
	SPAPI_E_MACHINE_UNAVAILABLE                                               Handle        = 0x800F0222
	SPAPI_E_NO_CONFIGMGR_SERVICES                                             Handle        = 0x800F0223
	SPAPI_E_INVALID_PROPPAGE_PROVIDER                                         Handle        = 0x800F0224
	SPAPI_E_NO_SUCH_DEVICE_INTERFACE                                          Handle        = 0x800F0225
	SPAPI_E_DI_POSTPROCESSING_REQUIRED                                        Handle        = 0x800F0226
	SPAPI_E_INVALID_COINSTALLER                                               Handle        = 0x800F0227
	SPAPI_E_NO_COMPAT_DRIVERS                                                 Handle        = 0x800F0228
	SPAPI_E_NO_DEVICE_ICON                                                    Handle        = 0x800F0229
	SPAPI_E_INVALID_INF_LOGCONFIG                                             Handle        = 0x800F022A
	SPAPI_E_DI_DONT_INSTALL                                                   Handle        = 0x800F022B
	SPAPI_E_INVALID_FILTER_DRIVER                                             Handle        = 0x800F022C
	SPAPI_E_NON_WINDOWS_NT_DRIVER                                             Handle        = 0x800F022D
	SPAPI_E_NON_WINDOWS_DRIVER                                                Handle        = 0x800F022E
	SPAPI_E_NO_CATALOG_FOR_OEM_INF                                            Handle        = 0x800F022F
	SPAPI_E_DEVINSTALL_QUEUE_NONNATIVE                                        Handle        = 0x800F0230
	SPAPI_E_NOT_DISABLEABLE                                                   Handle        = 0x800F0231
	SPAPI_E_CANT_REMOVE_DEVINST                                               Handle        = 0x800F0232
	SPAPI_E_INVALID_TARGET                                                    Handle        = 0x800F0233
	SPAPI_E_DRIVER_NONNATIVE                                                  Handle        = 0x800F0234
	SPAPI_E_IN_WOW64                                                          Handle        = 0x800F0235
	SPAPI_E_SET_SYSTEM_RESTORE_POINT                                          Handle        = 0x800F0236
	SPAPI_E_INCORRECTLY_COPIED_INF                                            Handle        = 0x800F0237
	SPAPI_E_SCE_DISABLED                                                      Handle        = 0x800F0238
	SPAPI_E_UNKNOWN_EXCEPTION                                                 Handle        = 0x800F0239
	SPAPI_E_PNP_REGISTRY_ERROR                                                Handle        = 0x800F023A
	SPAPI_E_REMOTE_REQUEST_UNSUPPORTED                                        Handle        = 0x800F023B
	SPAPI_E_NOT_AN_INSTALLED_OEM_INF                                          Handle        = 0x800F023C
	SPAPI_E_INF_IN_USE_BY_DEVICES                                             Handle        = 0x800F023D
	SPAPI_E_DI_FUNCTION_OBSOLETE                                              Handle        = 0x800F023E
	SPAPI_E_NO_AUTHENTICODE_CATALOG                                           Handle        = 0x800F023F
	SPAPI_E_AUTHENTICODE_DISALLOWED                                           Handle        = 0x800F0240
	SPAPI_E_AUTHENTICODE_TRUSTED_PUBLISHER                                    Handle        = 0x800F0241
	SPAPI_E_AUTHENTICODE_TRUST_NOT_ESTABLISHED                                Handle        = 0x800F0242
	SPAPI_E_AUTHENTICODE_PUBLISHER_NOT_TRUSTED                                Handle        = 0x800F0243
	SPAPI_E_SIGNATURE_OSATTRIBUTE_MISMATCH                                    Handle        = 0x800F0244
	SPAPI_E_ONLY_VALIDATE_VIA_AUTHENTICODE                                    Handle        = 0x800F0245
	SPAPI_E_DEVICE_INSTALLER_NOT_READY                                        Handle        = 0x800F0246
	SPAPI_E_DRIVER_STORE_ADD_FAILED                                           Handle        = 0x800F0247
	SPAPI_E_DEVICE_INSTALL_BLOCKED                                            Handle        = 0x800F0248
	SPAPI_E_DRIVER_INSTALL_BLOCKED                                            Handle        = 0x800F0249
	SPAPI_E_WRONG_INF_TYPE                                                    Handle        = 0x800F024A
	SPAPI_E_FILE_HASH_NOT_IN_CATALOG                                          Handle        = 0x800F024B
	SPAPI_E_DRIVER_STORE_DELETE_FAILED                                        Handle        = 0x800F024C
	SPAPI_E_UNRECOVERABLE_STACK_OVERFLOW                                      Handle        = 0x800F0300
	SPAPI_E_ERROR_NOT_INSTALLED                                               Handle        = 0x800F1000
	SCARD_S_SUCCESS                                                                         = S_OK
	SCARD_F_INTERNAL_ERROR                                                    Handle        = 0x80100001
	SCARD_E_CANCELLED                                                         Handle        = 0x80100002
	SCARD_E_INVALID_HANDLE                                                    Handle        = 0x80100003
	SCARD_E_INVALID_PARAMETER                                                 Handle        = 0x80100004
	SCARD_E_INVALID_TARGET                                                    Handle        = 0x80100005
	SCARD_E_NO_MEMORY                                                         Handle        = 0x80100006
	SCARD_F_WAITED_TOO_LONG                                                   Handle        = 0x80100007
	SCARD_E_INSUFFICIENT_BUFFER                                               Handle        = 0x80100008
	SCARD_E_UNKNOWN_READER                                                    Handle        = 0x80100009
	SCARD_E_TIMEOUT                                                           Handle        = 0x8010000A
	SCARD_E_SHARING_VIOLATION                                                 Handle        = 0x8010000B
	SCARD_E_NO_SMARTCARD                                                      Handle        = 0x8010000C
	SCARD_E_UNKNOWN_CARD                                                      Handle        = 0x8010000D
	SCARD_E_CANT_DISPOSE                                                      Handle        = 0x8010000E
	SCARD_E_PROTO_MISMATCH                                                    Handle        = 0x8010000F
	SCARD_E_NOT_READY                                                         Handle        = 0x80100010
	SCARD_E_INVALID_VALUE                                                     Handle        = 0x80100011
	SCARD_E_SYSTEM_CANCELLED                                                  Handle        = 0x80100012
	SCARD_F_COMM_ERROR                                                        Handle        = 0x80100013
	SCARD_F_UNKNOWN_ERROR                                                     Handle        = 0x80100014
	SCARD_E_INVALID_ATR                                                       Handle        = 0x80100015
	SCARD_E_NOT_TRANSACTED                                                    Handle        = 0x80100016
	SCARD_E_READER_UNAVAILABLE                                                Handle        = 0x80100017
	SCARD_P_SHUTDOWN                                                          Handle        = 0x80100018
	SCARD_E_PCI_TOO_SMALL                                                     Handle        = 0x80100019
	SCARD_E_READER_UNSUPPORTED                                                Handle        = 0x8010001A
	SCARD_E_DUPLICATE_READER                                                  Handle        = 0x8010001B
	SCARD_E_CARD_UNSUPPORTED                                                  Handle        = 0x8010001C
	SCARD_E_NO_SERVICE                                                        Handle        = 0x8010001D
	SCARD_E_SERVICE_STOPPED                                                   Handle        = 0x8010001E
	SCARD_E_UNEXPECTED                                                        Handle        = 0x8010001F
	SCARD_E_ICC_INSTALLATION                                                  Handle        = 0x80100020
	SCARD_E_ICC_CREATEORDER                                                   Handle        = 0x80100021
	SCARD_E_UNSUPPORTED_FEATURE                                               Handle        = 0x80100022
	SCARD_E_DIR_NOT_FOUND                                                     Handle        = 0x80100023
	SCARD_E_FILE_NOT_FOUND                                                    Handle        = 0x80100024
	SCARD_E_NO_DIR                                                            Handle        = 0x80100025
	SCARD_E_NO_FILE                                                           Handle        = 0x80100026
	SCARD_E_NO_ACCESS                                                         Handle        = 0x80100027
	SCARD_E_WRITE_TOO_MANY                                                    Handle        = 0x80100028
	SCARD_E_BAD_SEEK                                                          Handle        = 0x80100029
	SCARD_E_INVALID_CHV                                                       Handle        = 0x8010002A
	SCARD_E_UNKNOWN_RES_MNG                                                   Handle        = 0x8010002B
	SCARD_E_NO_SUCH_CERTIFICATE                                               Handle        = 0x8010002C
	SCARD_E_CERTIFICATE_UNAVAILABLE                                           Handle        = 0x8010002D
	SCARD_E_NO_READERS_AVAILABLE                                              Handle        = 0x8010002E
	SCARD_E_COMM_DATA_LOST                                                    Handle        = 0x8010002F
	SCARD_E_NO_KEY_CONTAINER                                                  Handle        = 0x80100030
	SCARD_E_SERVER_TOO_BUSY                                                   Handle        = 0x80100031
	SCARD_E_PIN_CACHE_EXPIRED                                                 Handle        = 0x80100032
	SCARD_E_NO_PIN_CACHE                                                      Handle        = 0x80100033
	SCARD_E_READ_ONLY_CARD                                                    Handle        = 0x80100034
	SCARD_W_UNSUPPORTED_CARD                                                  Handle        = 0x80100065
	SCARD_W_UNRESPONSIVE_CARD                                                 Handle        = 0x80100066
	SCARD_W_UNPOWERED_CARD                                                    Handle        = 0x80100067
	SCARD_W_RESET_CARD                                                        Handle        = 0x80100068
	SCARD_W_REMOVED_CARD                                                      Handle        = 0x80100069
	SCARD_W_SECURITY_VIOLATION                                                Handle        = 0x8010006A
	SCARD_W_WRONG_CHV                                                         Handle        = 0x8010006B
	SCARD_W_CHV_BLOCKED                                                       Handle        = 0x8010006C
	SCARD_W_EOF                                                               Handle        = 0x8010006D
	SCARD_W_CANCELLED_BY_USER                                                 Handle        = 0x8010006E
	SCARD_W_CARD_NOT_AUTHENTICATED                                            Handle        = 0x8010006F
	SCARD_W_CACHE_ITEM_NOT_FOUND                                              Handle        = 0x80100070
	SCARD_W_CACHE_ITEM_STALE                                                  Handle        = 0x80100071
	SCARD_W_CACHE_ITEM_TOO_BIG                                                Handle        = 0x80100072
	COMADMIN_E_OBJECTERRORS                                                   Handle        = 0x80110401
	COMADMIN_E_OBJECTINVALID                                                  Handle        = 0x80110402
	COMADMIN_E_KEYMISSING                                                     Handle        = 0x80110403
	COMADMIN_E_ALREADYINSTALLED                                               Handle        = 0x80110404
	COMADMIN_E_APP_FILE_WRITEFAIL                                             Handle        = 0x80110407
	COMADMIN_E_APP_FILE_READFAIL                                              Handle        = 0x80110408
	COMADMIN_E_APP_FILE_VERSION                                               Handle        = 0x80110409
	COMADMIN_E_BADPATH                                                        Handle        = 0x8011040A
	COMADMIN_E_APPLICATIONEXISTS                                              Handle        = 0x8011040B
	COMADMIN_E_ROLEEXISTS                                                     Handle        = 0x8011040C
	COMADMIN_E_CANTCOPYFILE                                                   Handle        = 0x8011040D
	COMADMIN_E_NOUSER                                                         Handle        = 0x8011040F
	COMADMIN_E_INVALIDUSERIDS                                                 Handle        = 0x80110410
	COMADMIN_E_NOREGISTRYCLSID                                                Handle        = 0x80110411
	COMADMIN_E_BADREGISTRYPROGID                                              Handle        = 0x80110412
	COMADMIN_E_AUTHENTICATIONLEVEL                                            Handle        = 0x80110413
	COMADMIN_E_USERPASSWDNOTVALID                                             Handle        = 0x80110414
	COMADMIN_E_CLSIDORIIDMISMATCH                                             Handle        = 0x80110418
	COMADMIN_E_REMOTEINTERFACE                                                Handle        = 0x80110419
	COMADMIN_E_DLLREGISTERSERVER                                              Handle        = 0x8011041A
	COMADMIN_E_NOSERVERSHARE                                                  Handle        = 0x8011041B
	COMADMIN_E_DLLLOADFAILED                                                  Handle        = 0x8011041D
	COMADMIN_E_BADREGISTRYLIBID                                               Handle        = 0x8011041E
	COMADMIN_E_APPDIRNOTFOUND                                                 Handle        = 0x8011041F
	COMADMIN_E_REGISTRARFAILED                                                Handle        = 0x80110423
	COMADMIN_E_COMPFILE_DOESNOTEXIST                                          Handle        = 0x80110424
	COMADMIN_E_COMPFILE_LOADDLLFAIL                                           Handle        = 0x80110425
	COMADMIN_E_COMPFILE_GETCLASSOBJ                                           Handle        = 0x80110426
	COMADMIN_E_COMPFILE_CLASSNOTAVAIL                                         Handle        = 0x80110427
	COMADMIN_E_COMPFILE_BADTLB                                                Handle        = 0x80110428
	COMADMIN_E_COMPFILE_NOTINSTALLABLE                                        Handle        = 0x80110429
	COMADMIN_E_NOTCHANGEABLE                                                  Handle        = 0x8011042A
	COMADMIN_E_NOTDELETEABLE                                                  Handle        = 0x8011042B
	COMADMIN_E_SESSION                                                        Handle        = 0x8011042C
	COMADMIN_E_COMP_MOVE_LOCKED                                               Handle        = 0x8011042D
	COMADMIN_E_COMP_MOVE_BAD_DEST                                             Handle        = 0x8011042E
	COMADMIN_E_REGISTERTLB                                                    Handle        = 0x80110430
	COMADMIN_E_SYSTEMAPP                                                      Handle        = 0x80110433
	COMADMIN_E_COMPFILE_NOREGISTRAR                                           Handle        = 0x80110434
	COMADMIN_E_COREQCOMPINSTALLED                                             Handle        = 0x80110435
	COMADMIN_E_SERVICENOTINSTALLED                                            Handle        = 0x80110436
	COMADMIN_E_PROPERTYSAVEFAILED                                             Handle        = 0x80110437
	COMADMIN_E_OBJECTEXISTS                                                   Handle        = 0x80110438
	COMADMIN_E_COMPONENTEXISTS                                                Handle        = 0x80110439
	COMADMIN_E_REGFILE_CORRUPT                                                Handle        = 0x8011043B
	COMADMIN_E_PROPERTY_OVERFLOW                                              Handle        = 0x8011043C
	COMADMIN_E_NOTINREGISTRY                                                  Handle        = 0x8011043E
	COMADMIN_E_OBJECTNOTPOOLABLE                                              Handle        = 0x8011043F
	COMADMIN_E_APPLID_MATCHES_CLSID                                           Handle        = 0x80110446
	COMADMIN_E_ROLE_DOES_NOT_EXIST                                            Handle        = 0x80110447
	COMADMIN_E_START_APP_NEEDS_COMPONENTS                                     Handle        = 0x80110448
	COMADMIN_E_REQUIRES_DIFFERENT_PLATFORM                                    Handle        = 0x80110449
	COMADMIN_E_CAN_NOT_EXPORT_APP_PROXY                                       Handle        = 0x8011044A
	COMADMIN_E_CAN_NOT_START_APP                                              Handle        = 0x8011044B
	COMADMIN_E_CAN_NOT_EXPORT_SYS_APP                                         Handle        = 0x8011044C
	COMADMIN_E_CANT_SUBSCRIBE_TO_COMPONENT                                    Handle        = 0x8011044D
	COMADMIN_E_EVENTCLASS_CANT_BE_SUBSCRIBER                                  Handle        = 0x8011044E
	COMADMIN_E_LIB_APP_PROXY_INCOMPATIBLE                                     Handle        = 0x8011044F
	COMADMIN_E_BASE_PARTITION_ONLY                                            Handle        = 0x80110450
	COMADMIN_E_START_APP_DISABLED                                             Handle        = 0x80110451
	COMADMIN_E_CAT_DUPLICATE_PARTITION_NAME                                   Handle        = 0x80110457
	COMADMIN_E_CAT_INVALID_PARTITION_NAME                                     Handle        = 0x80110458
	COMADMIN_E_CAT_PARTITION_IN_USE                                           Handle        = 0x80110459
	COMADMIN_E_FILE_PARTITION_DUPLICATE_FILES                                 Handle        = 0x8011045A
	COMADMIN_E_CAT_IMPORTED_COMPONENTS_NOT_ALLOWED                            Handle        = 0x8011045B
	COMADMIN_E_AMBIGUOUS_APPLICATION_NAME                                     Handle        = 0x8011045C
	COMADMIN_E_AMBIGUOUS_PARTITION_NAME                                       Handle        = 0x8011045D
	COMADMIN_E_REGDB_NOTINITIALIZED                                           Handle        = 0x80110472
	COMADMIN_E_REGDB_NOTOPEN                                                  Handle        = 0x80110473
	COMADMIN_E_REGDB_SYSTEMERR                                                Handle        = 0x80110474
	COMADMIN_E_REGDB_ALREADYRUNNING                                           Handle        = 0x80110475
	COMADMIN_E_MIG_VERSIONNOTSUPPORTED                                        Handle        = 0x80110480
	COMADMIN_E_MIG_SCHEMANOTFOUND                                             Handle        = 0x80110481
	COMADMIN_E_CAT_BITNESSMISMATCH                                            Handle        = 0x80110482
	COMADMIN_E_CAT_UNACCEPTABLEBITNESS                                        Handle        = 0x80110483
	COMADMIN_E_CAT_WRONGAPPBITNESS                                            Handle        = 0x80110484
	COMADMIN_E_CAT_PAUSE_RESUME_NOT_SUPPORTED                                 Handle        = 0x80110485
	COMADMIN_E_CAT_SERVERFAULT                                                Handle        = 0x80110486
	COMQC_E_APPLICATION_NOT_QUEUED                                            Handle        = 0x80110600
	COMQC_E_NO_QUEUEABLE_INTERFACES                                           Handle        = 0x80110601
	COMQC_E_QUEUING_SERVICE_NOT_AVAILABLE                                     Handle        = 0x80110602
	COMQC_E_NO_IPERSISTSTREAM                                                 Handle        = 0x80110603
	COMQC_E_BAD_MESSAGE                                                       Handle        = 0x80110604
	COMQC_E_UNAUTHENTICATED                                                   Handle        = 0x80110605
	COMQC_E_UNTRUSTED_ENQUEUER                                                Handle        = 0x80110606
	MSDTC_E_DUPLICATE_RESOURCE                                                Handle        = 0x80110701
	COMADMIN_E_OBJECT_PARENT_MISSING                                          Handle        = 0x80110808
	COMADMIN_E_OBJECT_DOES_NOT_EXIST                                          Handle        = 0x80110809
	COMADMIN_E_APP_NOT_RUNNING                                                Handle        = 0x8011080A
	COMADMIN_E_INVALID_PARTITION                                              Handle        = 0x8011080B
	COMADMIN_E_SVCAPP_NOT_POOLABLE_OR_RECYCLABLE                              Handle        = 0x8011080D
	COMADMIN_E_USER_IN_SET                                                    Handle        = 0x8011080E
	COMADMIN_E_CANTRECYCLELIBRARYAPPS                                         Handle        = 0x8011080F
	COMADMIN_E_CANTRECYCLESERVICEAPPS                                         Handle        = 0x80110811
	COMADMIN_E_PROCESSALREADYRECYCLED                                         Handle        = 0x80110812
	COMADMIN_E_PAUSEDPROCESSMAYNOTBERECYCLED                                  Handle        = 0x80110813
	COMADMIN_E_CANTMAKEINPROCSERVICE                                          Handle        = 0x80110814
	COMADMIN_E_PROGIDINUSEBYCLSID                                             Handle        = 0x80110815
	COMADMIN_E_DEFAULT_PARTITION_NOT_IN_SET                                   Handle        = 0x80110816
	COMADMIN_E_RECYCLEDPROCESSMAYNOTBEPAUSED                                  Handle        = 0x80110817
	COMADMIN_E_PARTITION_ACCESSDENIED                                         Handle        = 0x80110818
	COMADMIN_E_PARTITION_MSI_ONLY                                             Handle        = 0x80110819
	COMADMIN_E_LEGACYCOMPS_NOT_ALLOWED_IN_1_0_FORMAT                          Handle        = 0x8011081A
	COMADMIN_E_LEGACYCOMPS_NOT_ALLOWED_IN_NONBASE_PARTITIONS                  Handle        = 0x8011081B
	COMADMIN_E_COMP_MOVE_SOURCE                                               Handle        = 0x8011081C
	COMADMIN_E_COMP_MOVE_DEST                                                 Handle        = 0x8011081D
	COMADMIN_E_COMP_MOVE_PRIVATE                                              Handle        = 0x8011081E
	COMADMIN_E_BASEPARTITION_REQUIRED_IN_SET                                  Handle        = 0x8011081F
	COMADMIN_E_CANNOT_ALIAS_EVENTCLASS                                        Handle        = 0x80110820
	COMADMIN_E_PRIVATE_ACCESSDENIED                                           Handle        = 0x80110821
	COMADMIN_E_SAFERINVALID                                                   Handle        = 0x80110822
	COMADMIN_E_REGISTRY_ACCESSDENIED                                          Handle        = 0x80110823
	COMADMIN_E_PARTITIONS_DISABLED                                            Handle        = 0x80110824
	WER_S_REPORT_DEBUG                                                        Handle        = 0x001B0000
	WER_S_REPORT_UPLOADED                                                     Handle        = 0x001B0001
	WER_S_REPORT_QUEUED                                                       Handle        = 0x001B0002
	WER_S_DISABLED                                                            Handle        = 0x001B0003
	WER_S_SUSPENDED_UPLOAD                                                    Handle        = 0x001B0004
	WER_S_DISABLED_QUEUE                                                      Handle        = 0x001B0005
	WER_S_DISABLED_ARCHIVE                                                    Handle        = 0x001B0006
	WER_S_REPORT_ASYNC                                                        Handle        = 0x001B0007
	WER_S_IGNORE_ASSERT_INSTANCE                                              Handle        = 0x001B0008
	WER_S_IGNORE_ALL_ASSERTS                                                  Handle        = 0x001B0009
	WER_S_ASSERT_CONTINUE                                                     Handle        = 0x001B000A
	WER_S_THROTTLED                                                           Handle        = 0x001B000B
	WER_S_REPORT_UPLOADED_CAB                                                 Handle        = 0x001B000C
	WER_E_CRASH_FAILURE                                                       Handle        = 0x801B8000
	WER_E_CANCELED                                                            Handle        = 0x801B8001
	WER_E_NETWORK_FAILURE                                                     Handle        = 0x801B8002
	WER_E_NOT_INITIALIZED                                                     Handle        = 0x801B8003
	WER_E_ALREADY_REPORTING                                                   Handle        = 0x801B8004
	WER_E_DUMP_THROTTLED                                                      Handle        = 0x801B8005
	WER_E_INSUFFICIENT_CONSENT                                                Handle        = 0x801B8006
	WER_E_TOO_HEAVY                                                           Handle        = 0x801B8007
	ERROR_FLT_IO_COMPLETE                                                     Handle        = 0x001F0001
	ERROR_FLT_NO_HANDLER_DEFINED                                              Handle        = 0x801F0001
	ERROR_FLT_CONTEXT_ALREADY_DEFINED                                         Handle        = 0x801F0002
	ERROR_FLT_INVALID_ASYNCHRONOUS_REQUEST                                    Handle        = 0x801F0003
	ERROR_FLT_DISALLOW_FAST_IO                                                Handle        = 0x801F0004
	ERROR_FLT_INVALID_NAME_REQUEST                                            Handle        = 0x801F0005
	ERROR_FLT_NOT_SAFE_TO_POST_OPERATION                                      Handle        = 0x801F0006
	ERROR_FLT_NOT_INITIALIZED                                                 Handle        = 0x801F0007
	ERROR_FLT_FILTER_NOT_READY                                                Handle        = 0x801F0008
	ERROR_FLT_POST_OPERATION_CLEANUP                                          Handle        = 0x801F0009
	ERROR_FLT_INTERNAL_ERROR                                                  Handle        = 0x801F000A
	ERROR_FLT_DELETING_OBJECT                                                 Handle        = 0x801F000B
	ERROR_FLT_MUST_BE_NONPAGED_POOL                                           Handle        = 0x801F000C
	ERROR_FLT_DUPLICATE_ENTRY                                                 Handle        = 0x801F000D
	ERROR_FLT_CBDQ_DISABLED                                                   Handle        = 0x801F000E
	ERROR_FLT_DO_NOT_ATTACH                                                   Handle        = 0x801F000F
	ERROR_FLT_DO_NOT_DETACH                                                   Handle        = 0x801F0010
	ERROR_FLT_INSTANCE_ALTITUDE_COLLISION                                     Handle        = 0x801F0011
	ERROR_FLT_INSTANCE_NAME_COLLISION                                         Handle        = 0x801F0012
	ERROR_FLT_FILTER_NOT_FOUND                                                Handle        = 0x801F0013
	ERROR_FLT_VOLUME_NOT_FOUND                                                Handle        = 0x801F0014
	ERROR_FLT_INSTANCE_NOT_FOUND                                              Handle        = 0x801F0015
	ERROR_FLT_CONTEXT_ALLOCATION_NOT_FOUND                                    Handle        = 0x801F0016
	ERROR_FLT_INVALID_CONTEXT_REGISTRATION                                    Handle        = 0x801F0017
	ERROR_FLT_NAME_CACHE_MISS                                                 Handle        = 0x801F0018
	ERROR_FLT_NO_DEVICE_OBJECT                                                Handle        = 0x801F0019
	ERROR_FLT_VOLUME_ALREADY_MOUNTED                                          Handle        = 0x801F001A
	ERROR_FLT_ALREADY_ENLISTED                                                Handle        = 0x801F001B
	ERROR_FLT_CONTEXT_ALREADY_LINKED                                          Handle        = 0x801F001C
	ERROR_FLT_NO_WAITER_FOR_REPLY                                             Handle        = 0x801F0020
	ERROR_FLT_REGISTRATION_BUSY                                               Handle        = 0x801F0023
	ERROR_HUNG_DISPLAY_DRIVER_THREAD                                          Handle        = 0x80260001
	DWM_E_COMPOSITIONDISABLED                                                 Handle        = 0x80263001
	DWM_E_REMOTING_NOT_SUPPORTED                                              Handle        = 0x80263002
	DWM_E_NO_REDIRECTION_SURFACE_AVAILABLE                                    Handle        = 0x80263003
	DWM_E_NOT_QUEUING_PRESENTS                                                Handle        = 0x80263004
	DWM_E_ADAPTER_NOT_FOUND                                                   Handle        = 0x80263005
	DWM_S_GDI_REDIRECTION_SURFACE                                             Handle        = 0x00263005
	DWM_E_TEXTURE_TOO_LARGE                                                   Handle        = 0x80263007
	DWM_S_GDI_REDIRECTION_SURFACE_BLT_VIA_GDI                                 Handle        = 0x00263008
	ERROR_MONITOR_NO_DESCRIPTOR                                               Handle        = 0x00261001
	ERROR_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT                                   Handle        = 0x00261002
	ERROR_MONITOR_INVALID_DESCRIPTOR_CHECKSUM                                 Handle        = 0xC0261003
	ERROR_MONITOR_INVALID_STANDARD_TIMING_BLOCK                               Handle        = 0xC0261004
	ERROR_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED                           Handle        = 0xC0261005
	ERROR_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK                          Handle        = 0xC0261006
	ERROR_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK                          Handle        = 0xC0261007
	ERROR_MONITOR_NO_MORE_DESCRIPTOR_DATA                                     Handle        = 0xC0261008
	ERROR_MONITOR_INVALID_DETAILED_TIMING_BLOCK                               Handle        = 0xC0261009
	ERROR_MONITOR_INVALID_MANUFACTURE_DATE                                    Handle        = 0xC026100A
	ERROR_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER                                   Handle        = 0xC0262000
	ERROR_GRAPHICS_INSUFFICIENT_DMA_BUFFER                                    Handle        = 0xC0262001
	ERROR_GRAPHICS_INVALID_DISPLAY_ADAPTER                                    Handle        = 0xC0262002
	ERROR_GRAPHICS_ADAPTER_WAS_RESET                                          Handle        = 0xC0262003
	ERROR_GRAPHICS_INVALID_DRIVER_MODEL                                       Handle        = 0xC0262004
	ERROR_GRAPHICS_PRESENT_MODE_CHANGED                                       Handle        = 0xC0262005
	ERROR_GRAPHICS_PRESENT_OCCLUDED                                           Handle        = 0xC0262006
	ERROR_GRAPHICS_PRESENT_DENIED                                             Handle        = 0xC0262007
	ERROR_GRAPHICS_CANNOTCOLORCONVERT                                         Handle        = 0xC0262008
	ERROR_GRAPHICS_DRIVER_MISMATCH                                            Handle        = 0xC0262009
	ERROR_GRAPHICS_PARTIAL_DATA_POPULATED                                     Handle        = 0x4026200A
	ERROR_GRAPHICS_PRESENT_REDIRECTION_DISABLED                               Handle        = 0xC026200B
	ERROR_GRAPHICS_PRESENT_UNOCCLUDED                                         Handle        = 0xC026200C
	ERROR_GRAPHICS_WINDOWDC_NOT_AVAILABLE                                     Handle        = 0xC026200D
	ERROR_GRAPHICS_WINDOWLESS_PRESENT_DISABLED                                Handle        = 0xC026200E
	ERROR_GRAPHICS_PRESENT_INVALID_WINDOW                                     Handle        = 0xC026200F
	ERROR_GRAPHICS_PRESENT_BUFFER_NOT_BOUND                                   Handle        = 0xC0262010
	ERROR_GRAPHICS_VAIL_STATE_CHANGED                                         Handle        = 0xC0262011
	ERROR_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN                         Handle        = 0xC0262012
	ERROR_GRAPHICS_INDIRECT_DISPLAY_DEVICE_STOPPED                            Handle        = 0xC0262013
	ERROR_GRAPHICS_NO_VIDEO_MEMORY                                            Handle        = 0xC0262100
	ERROR_GRAPHICS_CANT_LOCK_MEMORY                                           Handle        = 0xC0262101
	ERROR_GRAPHICS_ALLOCATION_BUSY                                            Handle        = 0xC0262102
	ERROR_GRAPHICS_TOO_MANY_REFERENCES                                        Handle        = 0xC0262103
	ERROR_GRAPHICS_TRY_AGAIN_LATER                                            Handle        = 0xC0262104
	ERROR_GRAPHICS_TRY_AGAIN_NOW                                              Handle        = 0xC0262105
	ERROR_GRAPHICS_ALLOCATION_INVALID                                         Handle        = 0xC0262106
	ERROR_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE                           Handle        = 0xC0262107
	ERROR_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED                           Handle        = 0xC0262108
	ERROR_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION                               Handle        = 0xC0262109
	ERROR_GRAPHICS_INVALID_ALLOCATION_USAGE                                   Handle        = 0xC0262110
	ERROR_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION                              Handle        = 0xC0262111
	ERROR_GRAPHICS_ALLOCATION_CLOSED                                          Handle        = 0xC0262112
	ERROR_GRAPHICS_INVALID_ALLOCATION_INSTANCE                                Handle        = 0xC0262113
	ERROR_GRAPHICS_INVALID_ALLOCATION_HANDLE                                  Handle        = 0xC0262114
	ERROR_GRAPHICS_WRONG_ALLOCATION_DEVICE                                    Handle        = 0xC0262115
	ERROR_GRAPHICS_ALLOCATION_CONTENT_LOST                                    Handle        = 0xC0262116
	ERROR_GRAPHICS_GPU_EXCEPTION_ON_DEVICE                                    Handle        = 0xC0262200
	ERROR_GRAPHICS_SKIP_ALLOCATION_PREPARATION                                Handle        = 0x40262201
	ERROR_GRAPHICS_INVALID_VIDPN_TOPOLOGY                                     Handle        = 0xC0262300
	ERROR_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED                               Handle        = 0xC0262301
	ERROR_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED                     Handle        = 0xC0262302
	ERROR_GRAPHICS_INVALID_VIDPN                                              Handle        = 0xC0262303
	ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE                               Handle        = 0xC0262304
	ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET                               Handle        = 0xC0262
```