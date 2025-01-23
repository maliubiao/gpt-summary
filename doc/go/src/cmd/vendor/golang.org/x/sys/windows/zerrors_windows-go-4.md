Response:
The user wants to understand the functionality of a Go file that defines Windows error codes.

**Plan:**

1. **Identify the core purpose:** The file defines constants representing Windows error codes.
2. **Explain the Go feature:** This leverages Go's constant declaration feature, specifically using `syscall.Errno` to associate the numeric error code with a meaningful name.
3. **Provide a Go code example:** Demonstrate how these constants can be used to check for specific errors returned by Windows API calls.
4. **Explain the lack of command-line arguments:** This file primarily defines constants, not an executable program.
5. **Highlight potential pitfalls:**  The primary risk is misunderstanding the meaning of specific error codes.
6. **Summarize the functionality:** Concisely describe the purpose of the file.
这是一个Go语言源文件，其主要功能是定义了一系列Windows系统错误码常量。

**功能:**

1. **定义Windows错误码常量:** 该文件将Windows API中定义的各种错误码，例如网络相关的错误(`WSA_QOS_EPSFLOWSPEC`)，IPSec相关的错误(`ERROR_IPSEC_QM_POLICY_EXISTS`)，SXS (Side-by-Side) 组件相关的错误 (`ERROR_SXS_SECTION_NOT_FOUND`)，事件日志相关的错误(`ERROR_EVT_INVALID_CHANNEL_PATH`)，安装相关的错误 (`ERROR_INSTALL_OPEN_PACKAGE_FAILED`) 等等，都定义为Go语言的常量。
2. **使用`syscall.Errno`类型:**  这些常量都被定义为 `syscall.Errno` 类型。`syscall.Errno` 是 Go 语言 `syscall` 包中用于表示系统错误的类型。通过将这些Windows错误码转换为 `syscall.Errno` 类型，Go程序可以方便地处理来自Windows API调用的错误。
3. **提供错误名称:**  为每个错误码提供了一个易于理解的常量名称，这比直接使用数字错误码更具可读性和维护性。

**Go语言功能实现 (使用 `syscall` 包处理Windows API错误):**

这个文件是 Go 语言 `syscall` 包在 Windows 平台实现的一部分。 `syscall` 包允许 Go 程序直接调用底层的操作系统 API。当调用 Windows API 函数时，如果发生错误，通常会返回一个表示错误的数字代码。`zerrors_windows.go` 文件中定义的常量可以用来判断具体的错误类型。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	// 假设我们尝试打开一个不存在的文件
	filename := "non_existent_file.txt"
	var sa windows.SecurityAttributes
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(filename),
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		&sa,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)

	if err != nil {
		// 将 error 断言为 syscall.Errno 类型
		errno, ok := err.(syscall.Errno)
		if ok {
			// 检查是否是文件不存在的错误
			if errno == syscall.ERROR_FILE_NOT_FOUND {
				fmt.Println("Error: File not found")
				fmt.Printf("Error code: %d\n", errno)
			} else {
				fmt.Printf("An unexpected error occurred: %v (Error code: %d)\n", err, errno)
			}
		} else {
			fmt.Printf("An error occurred: %v\n", err)
		}
		return
	}
	defer windows.CloseHandle(handle)

	fmt.Println("File opened successfully.")
}
```

**假设的输入与输出:**

在这个例子中，输入是尝试打开一个不存在的文件 "non_existent_file.txt"。

**输出:**

```
Error: File not found
Error code: 2
```

这里，`syscall.ERROR_FILE_NOT_FOUND` (其值为2) 对应于 `zerrors_windows.go` 中定义的 `ERROR_FILE_NOT_FOUND` 常量。

**命令行参数处理:**

该文件本身不处理命令行参数。它只是一个定义常量的源文件，被其他的 Go 代码引用。

**使用者易犯错的点:**

* **混淆错误码的来源:**  需要明确这些错误码是 Windows API 返回的，而不是 Go 语言运行时或者其他库的错误。
* **错误码的平台依赖性:** 这些错误码是特定于 Windows 平台的，在其他操作系统上可能没有意义或者有不同的含义。
* **错误码的范围:** 需要查阅 Windows API 的文档来理解特定错误码的详细含义和上下文。虽然常量名提供了一定的信息，但不足以完全替代官方文档。

**功能归纳 (第5部分，共15部分):**

作为 `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` 文件的第 5 部分，此部分主要定义了与 **IPSec (Internet Protocol Security)** 相关的错误码常量以及一部分 **QoS (Quality of Service)** 相关的错误码常量。这些常量用于在 Go 程序中识别和处理与网络安全策略和网络服务质量相关的 Windows API 调用返回的特定错误。具体来说，它涵盖了 IPsec 策略的创建、查找、使用、删除等操作中可能出现的错误，以及 IKE 协商过程中可能遇到的各种问题，例如认证失败、超时、证书问题等等。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共15部分，请归纳一下它的功能
```

### 源代码
```go
OS_EPSFLOWSPEC                                                       syscall.Errno = 11027
	WSA_QOS_EPSFILTERSPEC                                                     syscall.Errno = 11028
	WSA_QOS_ESDMODEOBJ                                                        syscall.Errno = 11029
	WSA_QOS_ESHAPERATEOBJ                                                     syscall.Errno = 11030
	WSA_QOS_RESERVED_PETYPE                                                   syscall.Errno = 11031
	WSA_SECURE_HOST_NOT_FOUND                                                 syscall.Errno = 11032
	WSA_IPSEC_NAME_POLICY_ERROR                                               syscall.Errno = 11033
	ERROR_IPSEC_QM_POLICY_EXISTS                                              syscall.Errno = 13000
	ERROR_IPSEC_QM_POLICY_NOT_FOUND                                           syscall.Errno = 13001
	ERROR_IPSEC_QM_POLICY_IN_USE                                              syscall.Errno = 13002
	ERROR_IPSEC_MM_POLICY_EXISTS                                              syscall.Errno = 13003
	ERROR_IPSEC_MM_POLICY_NOT_FOUND                                           syscall.Errno = 13004
	ERROR_IPSEC_MM_POLICY_IN_USE                                              syscall.Errno = 13005
	ERROR_IPSEC_MM_FILTER_EXISTS                                              syscall.Errno = 13006
	ERROR_IPSEC_MM_FILTER_NOT_FOUND                                           syscall.Errno = 13007
	ERROR_IPSEC_TRANSPORT_FILTER_EXISTS                                       syscall.Errno = 13008
	ERROR_IPSEC_TRANSPORT_FILTER_NOT_FOUND                                    syscall.Errno = 13009
	ERROR_IPSEC_MM_AUTH_EXISTS                                                syscall.Errno = 13010
	ERROR_IPSEC_MM_AUTH_NOT_FOUND                                             syscall.Errno = 13011
	ERROR_IPSEC_MM_AUTH_IN_USE                                                syscall.Errno = 13012
	ERROR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND                                   syscall.Errno = 13013
	ERROR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND                                     syscall.Errno = 13014
	ERROR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND                                   syscall.Errno = 13015
	ERROR_IPSEC_TUNNEL_FILTER_EXISTS                                          syscall.Errno = 13016
	ERROR_IPSEC_TUNNEL_FILTER_NOT_FOUND                                       syscall.Errno = 13017
	ERROR_IPSEC_MM_FILTER_PENDING_DELETION                                    syscall.Errno = 13018
	ERROR_IPSEC_TRANSPORT_FILTER_PENDING_DELETION                             syscall.Errno = 13019
	ERROR_IPSEC_TUNNEL_FILTER_PENDING_DELETION                                syscall.Errno = 13020
	ERROR_IPSEC_MM_POLICY_PENDING_DELETION                                    syscall.Errno = 13021
	ERROR_IPSEC_MM_AUTH_PENDING_DELETION                                      syscall.Errno = 13022
	ERROR_IPSEC_QM_POLICY_PENDING_DELETION                                    syscall.Errno = 13023
	WARNING_IPSEC_MM_POLICY_PRUNED                                            syscall.Errno = 13024
	WARNING_IPSEC_QM_POLICY_PRUNED                                            syscall.Errno = 13025
	ERROR_IPSEC_IKE_NEG_STATUS_BEGIN                                          syscall.Errno = 13800
	ERROR_IPSEC_IKE_AUTH_FAIL                                                 syscall.Errno = 13801
	ERROR_IPSEC_IKE_ATTRIB_FAIL                                               syscall.Errno = 13802
	ERROR_IPSEC_IKE_NEGOTIATION_PENDING                                       syscall.Errno = 13803
	ERROR_IPSEC_IKE_GENERAL_PROCESSING_ERROR                                  syscall.Errno = 13804
	ERROR_IPSEC_IKE_TIMED_OUT                                                 syscall.Errno = 13805
	ERROR_IPSEC_IKE_NO_CERT                                                   syscall.Errno = 13806
	ERROR_IPSEC_IKE_SA_DELETED                                                syscall.Errno = 13807
	ERROR_IPSEC_IKE_SA_REAPED                                                 syscall.Errno = 13808
	ERROR_IPSEC_IKE_MM_ACQUIRE_DROP                                           syscall.Errno = 13809
	ERROR_IPSEC_IKE_QM_ACQUIRE_DROP                                           syscall.Errno = 13810
	ERROR_IPSEC_IKE_QUEUE_DROP_MM                                             syscall.Errno = 13811
	ERROR_IPSEC_IKE_QUEUE_DROP_NO_MM                                          syscall.Errno = 13812
	ERROR_IPSEC_IKE_DROP_NO_RESPONSE                                          syscall.Errno = 13813
	ERROR_IPSEC_IKE_MM_DELAY_DROP                                             syscall.Errno = 13814
	ERROR_IPSEC_IKE_QM_DELAY_DROP                                             syscall.Errno = 13815
	ERROR_IPSEC_IKE_ERROR                                                     syscall.Errno = 13816
	ERROR_IPSEC_IKE_CRL_FAILED                                                syscall.Errno = 13817
	ERROR_IPSEC_IKE_INVALID_KEY_USAGE                                         syscall.Errno = 13818
	ERROR_IPSEC_IKE_INVALID_CERT_TYPE                                         syscall.Errno = 13819
	ERROR_IPSEC_IKE_NO_PRIVATE_KEY                                            syscall.Errno = 13820
	ERROR_IPSEC_IKE_SIMULTANEOUS_REKEY                                        syscall.Errno = 13821
	ERROR_IPSEC_IKE_DH_FAIL                                                   syscall.Errno = 13822
	ERROR_IPSEC_IKE_CRITICAL_PAYLOAD_NOT_RECOGNIZED                           syscall.Errno = 13823
	ERROR_IPSEC_IKE_INVALID_HEADER                                            syscall.Errno = 13824
	ERROR_IPSEC_IKE_NO_POLICY                                                 syscall.Errno = 13825
	ERROR_IPSEC_IKE_INVALID_SIGNATURE                                         syscall.Errno = 13826
	ERROR_IPSEC_IKE_KERBEROS_ERROR                                            syscall.Errno = 13827
	ERROR_IPSEC_IKE_NO_PUBLIC_KEY                                             syscall.Errno = 13828
	ERROR_IPSEC_IKE_PROCESS_ERR                                               syscall.Errno = 13829
	ERROR_IPSEC_IKE_PROCESS_ERR_SA                                            syscall.Errno = 13830
	ERROR_IPSEC_IKE_PROCESS_ERR_PROP                                          syscall.Errno = 13831
	ERROR_IPSEC_IKE_PROCESS_ERR_TRANS                                         syscall.Errno = 13832
	ERROR_IPSEC_IKE_PROCESS_ERR_KE                                            syscall.Errno = 13833
	ERROR_IPSEC_IKE_PROCESS_ERR_ID                                            syscall.Errno = 13834
	ERROR_IPSEC_IKE_PROCESS_ERR_CERT                                          syscall.Errno = 13835
	ERROR_IPSEC_IKE_PROCESS_ERR_CERT_REQ                                      syscall.Errno = 13836
	ERROR_IPSEC_IKE_PROCESS_ERR_HASH                                          syscall.Errno = 13837
	ERROR_IPSEC_IKE_PROCESS_ERR_SIG                                           syscall.Errno = 13838
	ERROR_IPSEC_IKE_PROCESS_ERR_NONCE                                         syscall.Errno = 13839
	ERROR_IPSEC_IKE_PROCESS_ERR_NOTIFY                                        syscall.Errno = 13840
	ERROR_IPSEC_IKE_PROCESS_ERR_DELETE                                        syscall.Errno = 13841
	ERROR_IPSEC_IKE_PROCESS_ERR_VENDOR                                        syscall.Errno = 13842
	ERROR_IPSEC_IKE_INVALID_PAYLOAD                                           syscall.Errno = 13843
	ERROR_IPSEC_IKE_LOAD_SOFT_SA                                              syscall.Errno = 13844
	ERROR_IPSEC_IKE_SOFT_SA_TORN_DOWN                                         syscall.Errno = 13845
	ERROR_IPSEC_IKE_INVALID_COOKIE                                            syscall.Errno = 13846
	ERROR_IPSEC_IKE_NO_PEER_CERT                                              syscall.Errno = 13847
	ERROR_IPSEC_IKE_PEER_CRL_FAILED                                           syscall.Errno = 13848
	ERROR_IPSEC_IKE_POLICY_CHANGE                                             syscall.Errno = 13849
	ERROR_IPSEC_IKE_NO_MM_POLICY                                              syscall.Errno = 13850
	ERROR_IPSEC_IKE_NOTCBPRIV                                                 syscall.Errno = 13851
	ERROR_IPSEC_IKE_SECLOADFAIL                                               syscall.Errno = 13852
	ERROR_IPSEC_IKE_FAILSSPINIT                                               syscall.Errno = 13853
	ERROR_IPSEC_IKE_FAILQUERYSSP                                              syscall.Errno = 13854
	ERROR_IPSEC_IKE_SRVACQFAIL                                                syscall.Errno = 13855
	ERROR_IPSEC_IKE_SRVQUERYCRED                                              syscall.Errno = 13856
	ERROR_IPSEC_IKE_GETSPIFAIL                                                syscall.Errno = 13857
	ERROR_IPSEC_IKE_INVALID_FILTER                                            syscall.Errno = 13858
	ERROR_IPSEC_IKE_OUT_OF_MEMORY                                             syscall.Errno = 13859
	ERROR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED                                     syscall.Errno = 13860
	ERROR_IPSEC_IKE_INVALID_POLICY                                            syscall.Errno = 13861
	ERROR_IPSEC_IKE_UNKNOWN_DOI                                               syscall.Errno = 13862
	ERROR_IPSEC_IKE_INVALID_SITUATION                                         syscall.Errno = 13863
	ERROR_IPSEC_IKE_DH_FAILURE                                                syscall.Errno = 13864
	ERROR_IPSEC_IKE_INVALID_GROUP                                             syscall.Errno = 13865
	ERROR_IPSEC_IKE_ENCRYPT                                                   syscall.Errno = 13866
	ERROR_IPSEC_IKE_DECRYPT                                                   syscall.Errno = 13867
	ERROR_IPSEC_IKE_POLICY_MATCH                                              syscall.Errno = 13868
	ERROR_IPSEC_IKE_UNSUPPORTED_ID                                            syscall.Errno = 13869
	ERROR_IPSEC_IKE_INVALID_HASH                                              syscall.Errno = 13870
	ERROR_IPSEC_IKE_INVALID_HASH_ALG                                          syscall.Errno = 13871
	ERROR_IPSEC_IKE_INVALID_HASH_SIZE                                         syscall.Errno = 13872
	ERROR_IPSEC_IKE_INVALID_ENCRYPT_ALG                                       syscall.Errno = 13873
	ERROR_IPSEC_IKE_INVALID_AUTH_ALG                                          syscall.Errno = 13874
	ERROR_IPSEC_IKE_INVALID_SIG                                               syscall.Errno = 13875
	ERROR_IPSEC_IKE_LOAD_FAILED                                               syscall.Errno = 13876
	ERROR_IPSEC_IKE_RPC_DELETE                                                syscall.Errno = 13877
	ERROR_IPSEC_IKE_BENIGN_REINIT                                             syscall.Errno = 13878
	ERROR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY                         syscall.Errno = 13879
	ERROR_IPSEC_IKE_INVALID_MAJOR_VERSION                                     syscall.Errno = 13880
	ERROR_IPSEC_IKE_INVALID_CERT_KEYLEN                                       syscall.Errno = 13881
	ERROR_IPSEC_IKE_MM_LIMIT                                                  syscall.Errno = 13882
	ERROR_IPSEC_IKE_NEGOTIATION_DISABLED                                      syscall.Errno = 13883
	ERROR_IPSEC_IKE_QM_LIMIT                                                  syscall.Errno = 13884
	ERROR_IPSEC_IKE_MM_EXPIRED                                                syscall.Errno = 13885
	ERROR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID                                   syscall.Errno = 13886
	ERROR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH                                syscall.Errno = 13887
	ERROR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID                                     syscall.Errno = 13888
	ERROR_IPSEC_IKE_INVALID_AUTH_PAYLOAD                                      syscall.Errno = 13889
	ERROR_IPSEC_IKE_DOS_COOKIE_SENT                                           syscall.Errno = 13890
	ERROR_IPSEC_IKE_SHUTTING_DOWN                                             syscall.Errno = 13891
	ERROR_IPSEC_IKE_CGA_AUTH_FAILED                                           syscall.Errno = 13892
	ERROR_IPSEC_IKE_PROCESS_ERR_NATOA                                         syscall.Errno = 13893
	ERROR_IPSEC_IKE_INVALID_MM_FOR_QM                                         syscall.Errno = 13894
	ERROR_IPSEC_IKE_QM_EXPIRED                                                syscall.Errno = 13895
	ERROR_IPSEC_IKE_TOO_MANY_FILTERS                                          syscall.Errno = 13896
	ERROR_IPSEC_IKE_NEG_STATUS_END                                            syscall.Errno = 13897
	ERROR_IPSEC_IKE_KILL_DUMMY_NAP_TUNNEL                                     syscall.Errno = 13898
	ERROR_IPSEC_IKE_INNER_IP_ASSIGNMENT_FAILURE                               syscall.Errno = 13899
	ERROR_IPSEC_IKE_REQUIRE_CP_PAYLOAD_MISSING                                syscall.Errno = 13900
	ERROR_IPSEC_KEY_MODULE_IMPERSONATION_NEGOTIATION_PENDING                  syscall.Errno = 13901
	ERROR_IPSEC_IKE_COEXISTENCE_SUPPRESS                                      syscall.Errno = 13902
	ERROR_IPSEC_IKE_RATELIMIT_DROP                                            syscall.Errno = 13903
	ERROR_IPSEC_IKE_PEER_DOESNT_SUPPORT_MOBIKE                                syscall.Errno = 13904
	ERROR_IPSEC_IKE_AUTHORIZATION_FAILURE                                     syscall.Errno = 13905
	ERROR_IPSEC_IKE_STRONG_CRED_AUTHORIZATION_FAILURE                         syscall.Errno = 13906
	ERROR_IPSEC_IKE_AUTHORIZATION_FAILURE_WITH_OPTIONAL_RETRY                 syscall.Errno = 13907
	ERROR_IPSEC_IKE_STRONG_CRED_AUTHORIZATION_AND_CERTMAP_FAILURE             syscall.Errno = 13908
	ERROR_IPSEC_IKE_NEG_STATUS_EXTENDED_END                                   syscall.Errno = 13909
	ERROR_IPSEC_BAD_SPI                                                       syscall.Errno = 13910
	ERROR_IPSEC_SA_LIFETIME_EXPIRED                                           syscall.Errno = 13911
	ERROR_IPSEC_WRONG_SA                                                      syscall.Errno = 13912
	ERROR_IPSEC_REPLAY_CHECK_FAILED                                           syscall.Errno = 13913
	ERROR_IPSEC_INVALID_PACKET                                                syscall.Errno = 13914
	ERROR_IPSEC_INTEGRITY_CHECK_FAILED                                        syscall.Errno = 13915
	ERROR_IPSEC_CLEAR_TEXT_DROP                                               syscall.Errno = 13916
	ERROR_IPSEC_AUTH_FIREWALL_DROP                                            syscall.Errno = 13917
	ERROR_IPSEC_THROTTLE_DROP                                                 syscall.Errno = 13918
	ERROR_IPSEC_DOSP_BLOCK                                                    syscall.Errno = 13925
	ERROR_IPSEC_DOSP_RECEIVED_MULTICAST                                       syscall.Errno = 13926
	ERROR_IPSEC_DOSP_INVALID_PACKET                                           syscall.Errno = 13927
	ERROR_IPSEC_DOSP_STATE_LOOKUP_FAILED                                      syscall.Errno = 13928
	ERROR_IPSEC_DOSP_MAX_ENTRIES                                              syscall.Errno = 13929
	ERROR_IPSEC_DOSP_KEYMOD_NOT_ALLOWED                                       syscall.Errno = 13930
	ERROR_IPSEC_DOSP_NOT_INSTALLED                                            syscall.Errno = 13931
	ERROR_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES                              syscall.Errno = 13932
	ERROR_SXS_SECTION_NOT_FOUND                                               syscall.Errno = 14000
	ERROR_SXS_CANT_GEN_ACTCTX                                                 syscall.Errno = 14001
	ERROR_SXS_INVALID_ACTCTXDATA_FORMAT                                       syscall.Errno = 14002
	ERROR_SXS_ASSEMBLY_NOT_FOUND                                              syscall.Errno = 14003
	ERROR_SXS_MANIFEST_FORMAT_ERROR                                           syscall.Errno = 14004
	ERROR_SXS_MANIFEST_PARSE_ERROR                                            syscall.Errno = 14005
	ERROR_SXS_ACTIVATION_CONTEXT_DISABLED                                     syscall.Errno = 14006
	ERROR_SXS_KEY_NOT_FOUND                                                   syscall.Errno = 14007
	ERROR_SXS_VERSION_CONFLICT                                                syscall.Errno = 14008
	ERROR_SXS_WRONG_SECTION_TYPE                                              syscall.Errno = 14009
	ERROR_SXS_THREAD_QUERIES_DISABLED                                         syscall.Errno = 14010
	ERROR_SXS_PROCESS_DEFAULT_ALREADY_SET                                     syscall.Errno = 14011
	ERROR_SXS_UNKNOWN_ENCODING_GROUP                                          syscall.Errno = 14012
	ERROR_SXS_UNKNOWN_ENCODING                                                syscall.Errno = 14013
	ERROR_SXS_INVALID_XML_NAMESPACE_URI                                       syscall.Errno = 14014
	ERROR_SXS_ROOT_MANIFEST_DEPENDENCY_NOT_INSTALLED                          syscall.Errno = 14015
	ERROR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED                          syscall.Errno = 14016
	ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE                             syscall.Errno = 14017
	ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE                     syscall.Errno = 14018
	ERROR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE                     syscall.Errno = 14019
	ERROR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT                  syscall.Errno = 14020
	ERROR_SXS_DUPLICATE_DLL_NAME                                              syscall.Errno = 14021
	ERROR_SXS_DUPLICATE_WINDOWCLASS_NAME                                      syscall.Errno = 14022
	ERROR_SXS_DUPLICATE_CLSID                                                 syscall.Errno = 14023
	ERROR_SXS_DUPLICATE_IID                                                   syscall.Errno = 14024
	ERROR_SXS_DUPLICATE_TLBID                                                 syscall.Errno = 14025
	ERROR_SXS_DUPLICATE_PROGID                                                syscall.Errno = 14026
	ERROR_SXS_DUPLICATE_ASSEMBLY_NAME                                         syscall.Errno = 14027
	ERROR_SXS_FILE_HASH_MISMATCH                                              syscall.Errno = 14028
	ERROR_SXS_POLICY_PARSE_ERROR                                              syscall.Errno = 14029
	ERROR_SXS_XML_E_MISSINGQUOTE                                              syscall.Errno = 14030
	ERROR_SXS_XML_E_COMMENTSYNTAX                                             syscall.Errno = 14031
	ERROR_SXS_XML_E_BADSTARTNAMECHAR                                          syscall.Errno = 14032
	ERROR_SXS_XML_E_BADNAMECHAR                                               syscall.Errno = 14033
	ERROR_SXS_XML_E_BADCHARINSTRING                                           syscall.Errno = 14034
	ERROR_SXS_XML_E_XMLDECLSYNTAX                                             syscall.Errno = 14035
	ERROR_SXS_XML_E_BADCHARDATA                                               syscall.Errno = 14036
	ERROR_SXS_XML_E_MISSINGWHITESPACE                                         syscall.Errno = 14037
	ERROR_SXS_XML_E_EXPECTINGTAGEND                                           syscall.Errno = 14038
	ERROR_SXS_XML_E_MISSINGSEMICOLON                                          syscall.Errno = 14039
	ERROR_SXS_XML_E_UNBALANCEDPAREN                                           syscall.Errno = 14040
	ERROR_SXS_XML_E_INTERNALERROR                                             syscall.Errno = 14041
	ERROR_SXS_XML_E_UNEXPECTED_WHITESPACE                                     syscall.Errno = 14042
	ERROR_SXS_XML_E_INCOMPLETE_ENCODING                                       syscall.Errno = 14043
	ERROR_SXS_XML_E_MISSING_PAREN                                             syscall.Errno = 14044
	ERROR_SXS_XML_E_EXPECTINGCLOSEQUOTE                                       syscall.Errno = 14045
	ERROR_SXS_XML_E_MULTIPLE_COLONS                                           syscall.Errno = 14046
	ERROR_SXS_XML_E_INVALID_DECIMAL                                           syscall.Errno = 14047
	ERROR_SXS_XML_E_INVALID_HEXIDECIMAL                                       syscall.Errno = 14048
	ERROR_SXS_XML_E_INVALID_UNICODE                                           syscall.Errno = 14049
	ERROR_SXS_XML_E_WHITESPACEORQUESTIONMARK                                  syscall.Errno = 14050
	ERROR_SXS_XML_E_UNEXPECTEDENDTAG                                          syscall.Errno = 14051
	ERROR_SXS_XML_E_UNCLOSEDTAG                                               syscall.Errno = 14052
	ERROR_SXS_XML_E_DUPLICATEATTRIBUTE                                        syscall.Errno = 14053
	ERROR_SXS_XML_E_MULTIPLEROOTS                                             syscall.Errno = 14054
	ERROR_SXS_XML_E_INVALIDATROOTLEVEL                                        syscall.Errno = 14055
	ERROR_SXS_XML_E_BADXMLDECL                                                syscall.Errno = 14056
	ERROR_SXS_XML_E_MISSINGROOT                                               syscall.Errno = 14057
	ERROR_SXS_XML_E_UNEXPECTEDEOF                                             syscall.Errno = 14058
	ERROR_SXS_XML_E_BADPEREFINSUBSET                                          syscall.Errno = 14059
	ERROR_SXS_XML_E_UNCLOSEDSTARTTAG                                          syscall.Errno = 14060
	ERROR_SXS_XML_E_UNCLOSEDENDTAG                                            syscall.Errno = 14061
	ERROR_SXS_XML_E_UNCLOSEDSTRING                                            syscall.Errno = 14062
	ERROR_SXS_XML_E_UNCLOSEDCOMMENT                                           syscall.Errno = 14063
	ERROR_SXS_XML_E_UNCLOSEDDECL                                              syscall.Errno = 14064
	ERROR_SXS_XML_E_UNCLOSEDCDATA                                             syscall.Errno = 14065
	ERROR_SXS_XML_E_RESERVEDNAMESPACE                                         syscall.Errno = 14066
	ERROR_SXS_XML_E_INVALIDENCODING                                           syscall.Errno = 14067
	ERROR_SXS_XML_E_INVALIDSWITCH                                             syscall.Errno = 14068
	ERROR_SXS_XML_E_BADXMLCASE                                                syscall.Errno = 14069
	ERROR_SXS_XML_E_INVALID_STANDALONE                                        syscall.Errno = 14070
	ERROR_SXS_XML_E_UNEXPECTED_STANDALONE                                     syscall.Errno = 14071
	ERROR_SXS_XML_E_INVALID_VERSION                                           syscall.Errno = 14072
	ERROR_SXS_XML_E_MISSINGEQUALS                                             syscall.Errno = 14073
	ERROR_SXS_PROTECTION_RECOVERY_FAILED                                      syscall.Errno = 14074
	ERROR_SXS_PROTECTION_PUBLIC_KEY_TOO_SHORT                                 syscall.Errno = 14075
	ERROR_SXS_PROTECTION_CATALOG_NOT_VALID                                    syscall.Errno = 14076
	ERROR_SXS_UNTRANSLATABLE_HRESULT                                          syscall.Errno = 14077
	ERROR_SXS_PROTECTION_CATALOG_FILE_MISSING                                 syscall.Errno = 14078
	ERROR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE                             syscall.Errno = 14079
	ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME                        syscall.Errno = 14080
	ERROR_SXS_ASSEMBLY_MISSING                                                syscall.Errno = 14081
	ERROR_SXS_CORRUPT_ACTIVATION_STACK                                        syscall.Errno = 14082
	ERROR_SXS_CORRUPTION                                                      syscall.Errno = 14083
	ERROR_SXS_EARLY_DEACTIVATION                                              syscall.Errno = 14084
	ERROR_SXS_INVALID_DEACTIVATION                                            syscall.Errno = 14085
	ERROR_SXS_MULTIPLE_DEACTIVATION                                           syscall.Errno = 14086
	ERROR_SXS_PROCESS_TERMINATION_REQUESTED                                   syscall.Errno = 14087
	ERROR_SXS_RELEASE_ACTIVATION_CONTEXT                                      syscall.Errno = 14088
	ERROR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY                         syscall.Errno = 14089
	ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE                                syscall.Errno = 14090
	ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME                                 syscall.Errno = 14091
	ERROR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE                                    syscall.Errno = 14092
	ERROR_SXS_IDENTITY_PARSE_ERROR                                            syscall.Errno = 14093
	ERROR_MALFORMED_SUBSTITUTION_STRING                                       syscall.Errno = 14094
	ERROR_SXS_INCORRECT_PUBLIC_KEY_TOKEN                                      syscall.Errno = 14095
	ERROR_UNMAPPED_SUBSTITUTION_STRING                                        syscall.Errno = 14096
	ERROR_SXS_ASSEMBLY_NOT_LOCKED                                             syscall.Errno = 14097
	ERROR_SXS_COMPONENT_STORE_CORRUPT                                         syscall.Errno = 14098
	ERROR_ADVANCED_INSTALLER_FAILED                                           syscall.Errno = 14099
	ERROR_XML_ENCODING_MISMATCH                                               syscall.Errno = 14100
	ERROR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT                   syscall.Errno = 14101
	ERROR_SXS_IDENTITIES_DIFFERENT                                            syscall.Errno = 14102
	ERROR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT                                    syscall.Errno = 14103
	ERROR_SXS_FILE_NOT_PART_OF_ASSEMBLY                                       syscall.Errno = 14104
	ERROR_SXS_MANIFEST_TOO_BIG                                                syscall.Errno = 14105
	ERROR_SXS_SETTING_NOT_REGISTERED                                          syscall.Errno = 14106
	ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE                                  syscall.Errno = 14107
	ERROR_SMI_PRIMITIVE_INSTALLER_FAILED                                      syscall.Errno = 14108
	ERROR_GENERIC_COMMAND_FAILED                                              syscall.Errno = 14109
	ERROR_SXS_FILE_HASH_MISSING                                               syscall.Errno = 14110
	ERROR_SXS_DUPLICATE_ACTIVATABLE_CLASS                                     syscall.Errno = 14111
	ERROR_EVT_INVALID_CHANNEL_PATH                                            syscall.Errno = 15000
	ERROR_EVT_INVALID_QUERY                                                   syscall.Errno = 15001
	ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND                                    syscall.Errno = 15002
	ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND                                        syscall.Errno = 15003
	ERROR_EVT_INVALID_PUBLISHER_NAME                                          syscall.Errno = 15004
	ERROR_EVT_INVALID_EVENT_DATA                                              syscall.Errno = 15005
	ERROR_EVT_CHANNEL_NOT_FOUND                                               syscall.Errno = 15007
	ERROR_EVT_MALFORMED_XML_TEXT                                              syscall.Errno = 15008
	ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL                                  syscall.Errno = 15009
	ERROR_EVT_CONFIGURATION_ERROR                                             syscall.Errno = 15010
	ERROR_EVT_QUERY_RESULT_STALE                                              syscall.Errno = 15011
	ERROR_EVT_QUERY_RESULT_INVALID_POSITION                                   syscall.Errno = 15012
	ERROR_EVT_NON_VALIDATING_MSXML                                            syscall.Errno = 15013
	ERROR_EVT_FILTER_ALREADYSCOPED                                            syscall.Errno = 15014
	ERROR_EVT_FILTER_NOTELTSET                                                syscall.Errno = 15015
	ERROR_EVT_FILTER_INVARG                                                   syscall.Errno = 15016
	ERROR_EVT_FILTER_INVTEST                                                  syscall.Errno = 15017
	ERROR_EVT_FILTER_INVTYPE                                                  syscall.Errno = 15018
	ERROR_EVT_FILTER_PARSEERR                                                 syscall.Errno = 15019
	ERROR_EVT_FILTER_UNSUPPORTEDOP                                            syscall.Errno = 15020
	ERROR_EVT_FILTER_UNEXPECTEDTOKEN                                          syscall.Errno = 15021
	ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL                   syscall.Errno = 15022
	ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE                                  syscall.Errno = 15023
	ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE                                syscall.Errno = 15024
	ERROR_EVT_CHANNEL_CANNOT_ACTIVATE                                         syscall.Errno = 15025
	ERROR_EVT_FILTER_TOO_COMPLEX                                              syscall.Errno = 15026
	ERROR_EVT_MESSAGE_NOT_FOUND                                               syscall.Errno = 15027
	ERROR_EVT_MESSAGE_ID_NOT_FOUND                                            syscall.Errno = 15028
	ERROR_EVT_UNRESOLVED_VALUE_INSERT                                         syscall.Errno = 15029
	ERROR_EVT_UNRESOLVED_PARAMETER_INSERT                                     syscall.Errno = 15030
	ERROR_EVT_MAX_INSERTS_REACHED                                             syscall.Errno = 15031
	ERROR_EVT_EVENT_DEFINITION_NOT_FOUND                                      syscall.Errno = 15032
	ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND                                        syscall.Errno = 15033
	ERROR_EVT_VERSION_TOO_OLD                                                 syscall.Errno = 15034
	ERROR_EVT_VERSION_TOO_NEW                                                 syscall.Errno = 15035
	ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY                                    syscall.Errno = 15036
	ERROR_EVT_PUBLISHER_DISABLED                                              syscall.Errno = 15037
	ERROR_EVT_FILTER_OUT_OF_RANGE                                             syscall.Errno = 15038
	ERROR_EC_SUBSCRIPTION_CANNOT_ACTIVATE                                     syscall.Errno = 15080
	ERROR_EC_LOG_DISABLED                                                     syscall.Errno = 15081
	ERROR_EC_CIRCULAR_FORWARDING                                              syscall.Errno = 15082
	ERROR_EC_CREDSTORE_FULL                                                   syscall.Errno = 15083
	ERROR_EC_CRED_NOT_FOUND                                                   syscall.Errno = 15084
	ERROR_EC_NO_ACTIVE_CHANNEL                                                syscall.Errno = 15085
	ERROR_MUI_FILE_NOT_FOUND                                                  syscall.Errno = 15100
	ERROR_MUI_INVALID_FILE                                                    syscall.Errno = 15101
	ERROR_MUI_INVALID_RC_CONFIG                                               syscall.Errno = 15102
	ERROR_MUI_INVALID_LOCALE_NAME                                             syscall.Errno = 15103
	ERROR_MUI_INVALID_ULTIMATEFALLBACK_NAME                                   syscall.Errno = 15104
	ERROR_MUI_FILE_NOT_LOADED                                                 syscall.Errno = 15105
	ERROR_RESOURCE_ENUM_USER_STOP                                             syscall.Errno = 15106
	ERROR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED                               syscall.Errno = 15107
	ERROR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME                                syscall.Errno = 15108
	ERROR_MRM_RUNTIME_NO_DEFAULT_OR_NEUTRAL_RESOURCE                          syscall.Errno = 15110
	ERROR_MRM_INVALID_PRICONFIG                                               syscall.Errno = 15111
	ERROR_MRM_INVALID_FILE_TYPE                                               syscall.Errno = 15112
	ERROR_MRM_UNKNOWN_QUALIFIER                                               syscall.Errno = 15113
	ERROR_MRM_INVALID_QUALIFIER_VALUE                                         syscall.Errno = 15114
	ERROR_MRM_NO_CANDIDATE                                                    syscall.Errno = 15115
	ERROR_MRM_NO_MATCH_OR_DEFAULT_CANDIDATE                                   syscall.Errno = 15116
	ERROR_MRM_RESOURCE_TYPE_MISMATCH                                          syscall.Errno = 15117
	ERROR_MRM_DUPLICATE_MAP_NAME                                              syscall.Errno = 15118
	ERROR_MRM_DUPLICATE_ENTRY                                                 syscall.Errno = 15119
	ERROR_MRM_INVALID_RESOURCE_IDENTIFIER                                     syscall.Errno = 15120
	ERROR_MRM_FILEPATH_TOO_LONG                                               syscall.Errno = 15121
	ERROR_MRM_UNSUPPORTED_DIRECTORY_TYPE                                      syscall.Errno = 15122
	ERROR_MRM_INVALID_PRI_FILE                                                syscall.Errno = 15126
	ERROR_MRM_NAMED_RESOURCE_NOT_FOUND                                        syscall.Errno = 15127
	ERROR_MRM_MAP_NOT_FOUND                                                   syscall.Errno = 15135
	ERROR_MRM_UNSUPPORTED_PROFILE_TYPE                                        syscall.Errno = 15136
	ERROR_MRM_INVALID_QUALIFIER_OPERATOR                                      syscall.Errno = 15137
	ERROR_MRM_INDETERMINATE_QUALIFIER_VALUE                                   syscall.Errno = 15138
	ERROR_MRM_AUTOMERGE_ENABLED                                               syscall.Errno = 15139
	ERROR_MRM_TOO_MANY_RESOURCES                                              syscall.Errno = 15140
	ERROR_MRM_UNSUPPORTED_FILE_TYPE_FOR_MERGE                                 syscall.Errno = 15141
	ERROR_MRM_UNSUPPORTED_FILE_TYPE_FOR_LOAD_UNLOAD_PRI_FILE                  syscall.Errno = 15142
	ERROR_MRM_NO_CURRENT_VIEW_ON_THREAD                                       syscall.Errno = 15143
	ERROR_DIFFERENT_PROFILE_RESOURCE_MANAGER_EXIST                            syscall.Errno = 15144
	ERROR_OPERATION_NOT_ALLOWED_FROM_SYSTEM_COMPONENT                         syscall.Errno = 15145
	ERROR_MRM_DIRECT_REF_TO_NON_DEFAULT_RESOURCE                              syscall.Errno = 15146
	ERROR_MRM_GENERATION_COUNT_MISMATCH                                       syscall.Errno = 15147
	ERROR_PRI_MERGE_VERSION_MISMATCH                                          syscall.Errno = 15148
	ERROR_PRI_MERGE_MISSING_SCHEMA                                            syscall.Errno = 15149
	ERROR_PRI_MERGE_LOAD_FILE_FAILED                                          syscall.Errno = 15150
	ERROR_PRI_MERGE_ADD_FILE_FAILED                                           syscall.Errno = 15151
	ERROR_PRI_MERGE_WRITE_FILE_FAILED                                         syscall.Errno = 15152
	ERROR_PRI_MERGE_MULTIPLE_PACKAGE_FAMILIES_NOT_ALLOWED                     syscall.Errno = 15153
	ERROR_PRI_MERGE_MULTIPLE_MAIN_PACKAGES_NOT_ALLOWED                        syscall.Errno = 15154
	ERROR_PRI_MERGE_BUNDLE_PACKAGES_NOT_ALLOWED                               syscall.Errno = 15155
	ERROR_PRI_MERGE_MAIN_PACKAGE_REQUIRED                                     syscall.Errno = 15156
	ERROR_PRI_MERGE_RESOURCE_PACKAGE_REQUIRED                                 syscall.Errno = 15157
	ERROR_PRI_MERGE_INVALID_FILE_NAME                                         syscall.Errno = 15158
	ERROR_MRM_PACKAGE_NOT_FOUND                                               syscall.Errno = 15159
	ERROR_MRM_MISSING_DEFAULT_LANGUAGE                                        syscall.Errno = 15160
	ERROR_MCA_INVALID_CAPABILITIES_STRING                                     syscall.Errno = 15200
	ERROR_MCA_INVALID_VCP_VERSION                                             syscall.Errno = 15201
	ERROR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION                             syscall.Errno = 15202
	ERROR_MCA_MCCS_VERSION_MISMATCH                                           syscall.Errno = 15203
	ERROR_MCA_UNSUPPORTED_MCCS_VERSION                                        syscall.Errno = 15204
	ERROR_MCA_INTERNAL_ERROR                                                  syscall.Errno = 15205
	ERROR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED                                syscall.Errno = 15206
	ERROR_MCA_UNSUPPORTED_COLOR_TEMPERATURE                                   syscall.Errno = 15207
	ERROR_AMBIGUOUS_SYSTEM_DEVICE                                             syscall.Errno = 15250
	ERROR_SYSTEM_DEVICE_NOT_FOUND                                             syscall.Errno = 15299
	ERROR_HASH_NOT_SUPPORTED                                                  syscall.Errno = 15300
	ERROR_HASH_NOT_PRESENT                                                    syscall.Errno = 15301
	ERROR_SECONDARY_IC_PROVIDER_NOT_REGISTERED                                syscall.Errno = 15321
	ERROR_GPIO_CLIENT_INFORMATION_INVALID                                     syscall.Errno = 15322
	ERROR_GPIO_VERSION_NOT_SUPPORTED                                          syscall.Errno = 15323
	ERROR_GPIO_INVALID_REGISTRATION_PACKET                                    syscall.Errno = 15324
	ERROR_GPIO_OPERATION_DENIED                                               syscall.Errno = 15325
	ERROR_GPIO_INCOMPATIBLE_CONNECT_MODE                                      syscall.Errno = 15326
	ERROR_GPIO_INTERRUPT_ALREADY_UNMASKED                                     syscall.Errno = 15327
	ERROR_CANNOT_SWITCH_RUNLEVEL                                              syscall.Errno = 15400
	ERROR_INVALID_RUNLEVEL_SETTING                                            syscall.Errno = 15401
	ERROR_RUNLEVEL_SWITCH_TIMEOUT                                             syscall.Errno = 15402
	ERROR_RUNLEVEL_SWITCH_AGENT_TIMEOUT                                       syscall.Errno = 15403
	ERROR_RUNLEVEL_SWITCH_IN_PROGRESS                                         syscall.Errno = 15404
	ERROR_SERVICES_FAILED_AUTOSTART                                           syscall.Errno = 15405
	ERROR_COM_TASK_STOP_PENDING                                               syscall.Errno = 15501
	ERROR_INSTALL_OPEN_PACKAGE_FAILED                                         syscall.Errno = 15600
	ERROR_INSTALL_PACKAGE_NOT_FOUND                                           syscall.Errno = 15601
	ERROR_INSTALL_INVALID_PACKAGE                                             syscall.Errno = 15602
	ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED                                   syscall.Errno = 15603
	ERROR_INSTALL_OUT_OF_DISK_SPACE                                           syscall.Errno = 15604
	ERROR_INSTALL_NETWORK_FAILURE                                             syscall.Errno = 15605
	ERROR_INSTALL_REGISTRATION_FAILURE                                        syscall.Errno = 15606
	ERROR_INSTALL_DEREGISTRATION_FAILURE                                      syscall.Errno = 15607
	ERROR_INSTALL_CANCEL                                                      syscall.Errno = 15608
	ERROR_INSTALL_FAILED                                                      syscall.Errno = 15609
	ERROR_REMOVE_FAILED                                                       syscall.Errno = 15610
	ERROR_PACKAGE_ALREADY_EXISTS                                              syscall.Errno = 15611
	ERROR_NEEDS_REMEDIATION                                                   syscall.Errno = 15612
	ERROR_INSTALL_PREREQUISITE_FAILED                                         syscall.Errno = 15613
	ERROR_PACKAGE_REPOSITORY_CORRUPTED                                        syscall.Errno = 15614
	ERROR_INSTALL_POLICY_FAILURE                                              syscall.Errno = 15615
	ERROR_PACKAGE_UPDATING                                                    syscall.Errno = 15616
	ERROR_DEPLOYMENT_BLOCKED_BY_POLICY                                        syscall.Errno = 15617
	ERROR_PACKAGES_IN_USE                                                     syscall.Errno = 15618
	ERROR_RECOVERY_FILE_CORRUPT                                               syscall.Errno = 15619
	ERROR_INVALID_STAGED_SIGNATURE                                            syscall.Errno = 15620
	ERROR_DELETING_EXISTING_APPLICATIONDATA_STORE_FAILED                      syscall.Errno = 15621
	ERROR_INSTALL_PACKAGE_DOWNGRADE                                           syscall.Errno = 15622
	ERROR_SYSTEM_NEEDS_REMEDIATION                                            syscall.Errno = 15623
	ERROR_APPX_INTEGRITY_FAILURE_CLR_NGEN                                     syscall.Errno = 15624
	ERROR_RESILIENCY_FILE_CORRUPT                                             syscall.Errno = 15625
	ERROR_INSTALL_FIREWALL_SERVICE_NOT_RUNNING                                syscall.Errno = 15626
	ERROR_PACKAGE_MOVE_FAILED                                                 syscall.Errno = 15627
	ERROR_INSTALL_VOLUME_NOT_EMPTY                                            syscall.Errno = 15628
	ERROR_INSTALL_VOLUME_OFFLINE                                              syscall.Errno = 15629
	ERROR_INSTALL_VOLUME_CORRUPT                                              syscall.Errno = 15630
	ERROR_NEEDS_REGISTRATION                                                  syscall.Errno = 15631
	ERROR_INSTALL_WRONG_PROCESSOR_ARCHITECTURE                                syscall.Errno = 15632
	ERROR_DEV_SIDELOAD_LIMIT_EXCEEDED                                         syscall.Errno = 15633
	ERROR_INSTALL_OPTIONAL_PACKAGE_REQUIRES_MAIN_PACKAGE                      syscall.Errno = 15634
	ERROR_PACKAGE_NOT_SUPPORTED_ON_FILESYSTEM                                 syscall.Errno = 15635
	ERROR_PACKAGE_MOVE_BLOCKED_BY_STREAMING                                   syscall.Errno = 15636
	ERROR_INSTALL_OPTIONAL_PACKAGE_APPLICATIONID_NOT_UNIQUE                   syscall.Errno = 15637
	ERROR_PACKAGE_STAGING_ONHOLD                                              syscall.Errno = 15638
	ERROR_INSTALL_INVALID_RELATED_SET_UPDATE                                  syscall.Errno = 15639
	ERROR_INSTALL_OPTIONAL_PACKAGE_REQUIRES_MAIN_PACKAGE_FULLTRUST_CAPABILITY syscall.Errno = 15640
	ERROR_DEPLOYMENT_BLOCKED_BY_USER_LOG_OFF                                  syscall.Errno = 15641
	ERROR_PROVISION_OPTIONAL_PACKAGE_REQUIRES_MAIN_PACKAGE_PROVISIONED        syscall.Errno = 15642
	ERROR_PACKAGES_REPUTATION_CHECK_FAILED                                    syscall.Errno = 15643
	ERROR_PACKAGES_REPUTATION_CHECK_TIMEDOUT                                  syscall.Errno = 15644
	ERROR_DEPLOYMENT_OPTION_NOT_SUPPORTED                                     syscall.Errno = 15645
	ERROR_APPINSTALLER_ACTIVATION_BLOCKED                                     syscall.Errno = 15646
	ERROR_REGISTRATION_FROM_REMOTE_DRIVE_NOT_SUPPORTED                        syscall.Errno = 15647
	ERROR_APPX_RAW_DATA_WRITE_FAILED                                          syscall.Errno = 15648
	ERROR_DEPLOYMENT_BLOCKED_BY_VOLUME_POLICY_PACKAGE                         syscall.Errno = 15649
	ERROR_DEPLOYMENT_BLOCKED_BY_VOLUME_POLICY_MACHINE                         syscall.Errno = 15650
	ERROR_DEPLOYMENT_BLOCKED_BY_PROFILE_POLICY                                syscall.Errno = 15651
	ERROR_DEPLOYMENT_FAILED_CONFLICTING_MUTABLE_PACKAGE_DIRECTORY             syscall.Errno = 15652
	ERROR_SINGLETON_RESOURCE_INSTALLED_IN_ACTIVE_USER                         syscall.Errno = 15653
	ERROR_DIFFERENT_VERSION_OF_PACKAGED_SERVICE_INSTALLED                     syscall.Errno = 15654
	ERROR_SERVICE_EXISTS_AS_NON_PACKAGED_SERVICE                              syscall.Errno = 15655
	ERROR_PACKAGED_SERVICE_REQUIRES_ADMIN_PRIVILEGES                          syscall.Errno = 15656
	APPMODEL_ERROR_NO_PACKAGE                                                 syscall.Errno = 15700
	APPMODEL_ERROR_PACKAGE_RUNTIME_CORRUPT                                    syscall.Errno = 15701
	APPMODEL_ERROR_PACKAGE_IDENTITY_CORRUPT                                   syscall.Errno = 15702
	APPMODEL_ERROR_NO_APPLICATION                                             syscall.Errno = 15703
	APPMODEL_ERROR_DYNAMIC_PROPERTY_READ_FAILED                               syscall.Errno = 15704
	APPMODEL_ERROR_DYNAMIC_PROPERTY_INVALID                                   syscall.Errno = 15705
	APPMODEL_ERROR_PACKAGE_NOT_AVAILABLE                                      syscall.Errno = 15706
	APPMODEL_ERROR_NO_MUTABLE_DIRECTORY                                       syscall.Errno = 15707
	ERROR_STATE_LOAD_STORE_FAILED                                             syscall.Errno = 15800
	ERROR_STATE_GET_VERSION_FAILED                                            syscall.Errno = 15801
	ERROR_STATE_SET_VERSION_FAILED                                            syscall.Errno = 15802
	ERROR_STATE_STRUCTURED_RESET_FAILED                                       syscall.Errno = 15803
	ERROR_STATE_OPEN_CONTAINER_FAILED                                         syscall.Errno = 15804
	ERROR_STATE_CREATE_CONTAINER_FAILED                                       syscall.Errno = 15805
	ERROR_STATE_DELETE_CONTAINER_FAILED                                       syscall.Errno = 15806
	ERROR_STATE_READ_SETTING_FAILED                                           syscall.Errno = 15807
	ERROR_STATE_WRITE_SETTING_FAILED                                          syscall.Errno = 15808
	ERROR_STATE_DELETE_SETTING_FAILED                                         syscall.Errno = 15809
	ERROR_STATE_QUERY_SETTING_FAILED                                          syscall.Errno = 15810
	ERROR_STATE_READ_COMPOSITE_SETTING_FAILED                                 syscall.Errno = 15811
	ERROR_STATE_WRITE_COMPOSITE_SETTING_FAILED                                syscall.Errno = 15812
	ERROR_STATE_ENUMERATE_CONTAINER_FAILED                                    syscall.Errno = 15813
	ERROR_STATE_ENUMERATE_SETTINGS_FAILED                                     syscall.Errno = 15814
	ERROR_STATE_COMPOSITE_SETTING_VALUE_SIZE_LIMIT_EXCEEDED                   syscall.Errno = 15815
	ERROR_STATE_SETTING_VALUE_SIZE_LIMIT_EXCEEDED                             syscall.Errno = 15816
	ERROR_STATE_SETTING_NAME_SIZE_LIMIT_EXCEEDED                              syscall.Errno = 15817
	ERROR_STATE_CONTAINER_NAME_SIZE_LIMIT_EXCEEDED                            syscall.Errno = 15818
	ERROR_API_UNAVAILABLE                                                     syscall.Errno = 15841
	STORE_ERROR_UNLICENSED                                                    syscall.Errno = 15861
	STORE_ERROR_UNLICENSED_USER                                               syscall.Errno = 15862
	STORE_ERROR_PENDING_COM_TRANSACTION                                       syscall.Errno = 15863
	STORE_ERROR_LICENSE_REVOKED                                               syscall.Errno = 15864
	SEVERITY_SUCCESS                                                          syscall.Errno = 0
	SEVERITY_ERROR                                                            syscall.Errno = 1
	FACILITY_NT_BIT                                                                         = 0x10000000
	E_NOT_SET                                                                               = ERROR_NOT_FOUND
	E_NOT_VALID_STATE                                                                       = ERROR_INVALID_STATE
	E_NOT_SUFFICIENT_BUFFER                                                                 = ERROR_INSUFFICIENT_BUFFER
	E_TIME_SENSITIVE_THREAD                                                                 = ERROR_TIME_SENSITIVE_THREAD
	E_NO_TASK_QUEUE                                                                         = ERROR_NO_TASK_QUEUE
	NOERROR                                                                   syscall.Errno = 0
	E_UNEXPECTED                                                              Handle        = 0x8000FFFF
	E_NOTIMPL                                                                 Handle        = 0x80004001
	E_OUTOFMEMORY                                                             Handle        = 0x8007000E
	E_INVALIDARG                                                              Handle        = 0x80070057
	E_NOINTERFACE                                                             Handle        = 0x80004002
	E_POINTER                                                                 Handle        = 0x80004003
	E_HANDLE                                                                  Handle        = 0x80070006
	E_ABORT                                                                   Handle        = 0x80004004
	E_FAIL                                                                    Handle        = 0x80004005
	E_ACCESSDENIED                                                            Handle        = 0x80070005
	E_PENDING                                                                 Handle        = 0x8000000A
	E_BOUNDS                                                                  Handle        = 0x8000000B
	E_CHANGED_STATE                                                           Handle        = 0x8000000C
	E_ILLEGAL_STATE_CHANGE                                                    Handle        = 0x8000000D
	E_ILLEGAL_METHOD_CALL                                                     Handle        = 0x8000000E
	RO_E_METADATA_NAME_NOT_FOUND                                              Handle        = 0x8000000F
	RO_E_METADATA_NAME_IS_NAMESPACE                                           Handle        = 0x80000010
	RO_E_METADATA_INVALID_TYPE_FORMAT                                         Handle        = 0x80000011
	RO_E_INVALID_METADATA_FILE                                                Handle        = 0x80000012
	RO_E_CLOSED                                                               Handle        = 0x80000013
	RO_E_EXCLUSIVE_WRITE                                                      Handle        = 0x80000014
	RO_E_CHANGE_NOTIFICATION_IN_PROGRESS                                      Handle        = 0x80000015
	RO_E_ERROR_STRING_NOT_FOUND                                               Handle        = 0x80000016
	E_STRING_NOT_NULL_TERMINATED                                              Handle        = 0x80000017
	E_ILLEGAL_DELEGATE_ASSIGNMENT                                             Handle        = 0x80000018
	E_ASYNC_OPERATION_NOT_STARTED                                             Handle        = 0x80000019
	E_APPLICATION_EXITING                                                     Handle        = 0x8000001A
	E_APPLICATION_VIEW_EXITING                                                Handle        = 0x8000001B
	RO_E_MUST_BE_AGILE                                                        Handle        = 0x8000001C
	RO_E_UNSUPPORTED_FROM_MTA                                                 Handle        = 0x8000001D
	RO_E_COMMITTED                                                            Handle        = 0x8000001E
	RO_E_BLOCKED_CROSS_ASTA_CALL                                              Handle        = 0x8000001F
	RO_E_CANNOT_ACTIVATE_FULL_TRUST_SERVER                                    Handle        = 0x80000020
	RO_E_CANNOT_ACTIVATE_UNIVERSAL_APPLICATION_SERVER                         Handle        = 0x80000021
	CO_E_INIT_TLS                                                             Handle        = 0x80004006
	CO_E_INIT_SHARED_ALLOCATOR                                                Handle        = 0x80004007
	CO_E_INIT_MEMORY_ALLOCATOR                                                Handle        = 0x80004008
	CO_E_INIT_CLASS_CACHE                                                     Handle        = 0x80004009
	CO_E_INIT_RPC_CHANNEL                                                     Handle        = 0x8000400A
	CO_E_INIT_TLS_SET_CHANNEL_CONTROL                                         Handle        = 0x8000400B
	CO_E_INIT_TLS_CHANNEL_CONTROL                                             Handle        = 0x8000400C
	CO_E_INIT_UNACCEPTED_USER_ALLOCATOR                                       Handle        = 0x8000400D
	CO_E_INIT_SCM_MUTEX_EXISTS                                                Handle        = 0x8000400E
	CO_E_INIT_SCM_FILE_MAPPING_EXISTS                                         Handle        = 0x8000400F
	CO_E_INIT_SCM_MAP_VIEW_OF_FILE                                            Handle        = 0x80004010
	CO_E_INIT_SCM_EXEC_FAILURE                                                Handle        = 0x80004011
	CO_E_INIT_ONLY_SINGLE_THREADED                                            Handle        = 0x80004012
	CO_E_CANT_REMOTE                                                          Handle        = 0x80004013
	CO_E_BAD_SERVER_NAME                                                      Handle        = 0x80004014
	CO_E_WRONG_SERVER_IDENTITY                                                Handle        = 0x80004015
	CO_E_OLE1DDE_DISABLED                                                     Handle        = 0x80004016
	CO_E_RUNAS_SYNTAX                                                         Handle        = 0x80004017
	CO_E_CREATEPROCESS_FAILURE                                                Handle        = 0x80004018
	CO_E_RUNAS_CREATEPROCESS_FAILURE                                          Handle        = 0x80004019
	CO_E_RUNAS_LOGON_FAILURE                                                  Handle        = 0x8000401A
	CO_E_LAUNCH_PERMSSION_DENIED                                              Handle        = 0x8000401B
	CO_E_START_SERVICE_FAILURE                                                Handle        = 0x8000401C
	CO_E_REMOTE_COMMUNICATION_FAILURE                                         Handle        = 0x8000401D
	CO_E_SERVER_START_TIMEOUT                                                 Handle        = 0x8000401E
	CO_E_CLSREG_INCONSISTENT                                                  Handle        = 0x8000401F
	CO_E_IIDREG_INCONSISTENT                                                  Handle        = 0x80004020
	CO_E_NOT_SUPPORTED                                                        Handle        = 0x80004021
	CO_E_RELOAD_DLL                                                           Handle        = 0x80004022
	CO_E_MSI_ERROR                                                            Handle        = 0x80004023
	CO_E_ATTEMPT_TO_CREATE_OUTSIDE_CLIENT_CONTEXT                             Handle        = 0x80004024
	CO_E_SERVER_PAUSED                                                        Handle        = 0x80004025
	CO_E_SERVER_NOT_PAUSED                                                    Handle        = 0x80004026
	CO_E_CLASS_DISABLED                                                       Handle        = 0x80004027
	CO_E_CLRNOTAVAILABLE                                                      Handle        = 0x80004028
	CO_E_ASYNC_WORK_REJECTED                                                  Handle        = 0x80004029
	CO_E_SERVER_INIT_TIMEOUT                                                  Handle        = 0x8000402A
	CO_E_NO_SECCTX_IN_ACTIVATE                                                Handle        = 0x8000402B
	CO_E_TRACKER_CONFIG                                                       Handle        = 0x80004030
	CO_E_THREADPOOL_CONFIG                                                    Handle        = 0x80004031
	CO_E_SXS_CONFIG                                                           Handle        = 0x80004032
	CO_E_MALFORMED_SPN                                                        Handle        = 0x80004033
	CO_E_UNREVOKED_REGISTRATION_ON_APARTMENT_SHUTDOWN                         Handle        = 0x80004034
	CO_E_PREMATURE_STUB_RUNDOWN                                               Handle        = 0x80004035
	S_OK                                                                      Handle        = 0
	S_FALSE                                                                   Handle        = 1
	OLE_E_FIRST                                                               Handle        = 0x80040000
	OLE_E_LAST                                                                Handle        = 0x800400FF
	OLE_S_FIRST                                                               Handle        = 0x00040000
	OLE_S_LAST                                                                Handle        = 0x000400FF
	OLE_E_OLEVERB                                                             Handle        = 0x80040000
	OLE_E_ADVF                                                                Handle        = 0x80040001
	OLE_E_ENUM_NOMORE                                                         Handle        = 0x80040002
	OLE_E_ADVISENOTSUPPORTED                                                  Handle        = 0x80040003
	OLE_E_NOCONNECTION                                                        Handle        = 0x80040004
	OLE_E_NOTRUNNING                                                          Handle        = 0x80040005
	OLE_E_NOCACHE                                                             Handle        = 0x80040006
	OLE_E_BLANK                                                               Handle        = 0x80040007
	OLE_E_CLASSDIFF                                                           Handle        = 0x80040008
	OLE_E_CANT_GETMONIKER                                                     Handle        = 0x80040009
	OLE_E_CANT_BINDTOSOURCE                                                   Handle        = 0x8004000A
	OLE_E_STATIC                                                              Handle        = 0x8004000B
	OLE_E_PROMPTSAVECANCELLED                                                 Handle        = 0x8004000C
	OLE_E_INVALIDRECT                                                         Handle        = 0x8004000D
	OLE_E_WRONGCOMPOBJ                                                        Handle        = 0x8004000E
	OLE_E_INVALIDHWND                                                         Handle        = 0x8004000F
	OLE_E_NOT_INPLACEACTIVE                                                   Handle        = 0x80040010
	OLE_E_CANTCONVERT                                                         Handle        = 0x80040011
	OLE_E_NOSTORAGE                                                           Handle        = 0x80040012
	DV_E_FORMATETC                                                            Handle        = 0x80040064
	DV_E_DVTARGETDEVICE                                                       Handle        = 0x80040065
	DV_E_STGMEDIUM                                                            Handle        = 0x80040066
	DV_E_STATDATA                                                             Handle        = 0x80040067
	DV_E_LINDEX                                                               Handle        = 0x80040068
	DV_E_TYMED                                                                Handle        = 0x80040069
	DV_E_CLIPFORMAT                                                           Handle        = 0x8004006A
	DV_E_DVASPECT                                                             Handle        = 0x8004006B
	DV_E_DVTARGETDEVICE_SIZE                                                  Handle        = 0x8004006C
	DV_E_NOIVIEWOBJECT                                                        Handle        = 0x8004006D
	DRAGDROP_E_FIRST                                                          syscall.Errno = 0x80040100
	DRAGDROP_E_LAST                                                           syscall.Errno = 0x8004010F
	DRAGDROP_S_FIRST                                                          syscall.Errno = 0x00040100
	DRAGDROP_S_LAST                                                           syscall.Errno = 0x0004010F
	DRAGDROP_E_NOTREGISTERED                                                  Handle        = 0x80040100
	DRAGDROP_E_ALREADYREGISTERED                                              Handle        = 0x80040101
	DRAGDROP_E_INVALIDHWND                                                    Handle        = 0x80040102
	DRAGDROP_E_CONCURRENT_DRAG_ATTEMPTED                                      Handle        = 0x80040103
	CLASSFACTORY_E_FIRST                                                      syscall.Errno = 0x80040110
	CLASSFACTORY_E_LAST                                                       syscall.Errno = 0x8004011F
	CLASSFACTORY_S_FIRST                                                      syscall.Errno = 0x00040110
	CLASSFACTORY_S_LAST                                                       syscall.Errno = 0x0004011F
	CLASS_E_NOAGGREGATION                                                     Handle        = 0x80040110
	CLASS_E_CLASSNOTAVAILABLE                                                 Handle        = 0x80040111
	CLASS_E_NOTLICENSED                                                       Handle        = 0x80040112
	MARSHAL_E_FIRST                                                           syscall.Errno = 0x80040120
	MARSHAL_E_LAST                                                            syscall.Errno = 0x8004012F
	MARSHAL_S_FIRST                                                           syscall.Errno = 0x00040120
	MARSHAL_S_LAST                                                            syscall.Errno = 0x0004012F
	DATA_E_FIRST                                                              syscall.Errno = 0x80040130
	DATA_E_LAST                                                               syscall.Errno = 0x8004013F
	DATA_S_FIRST                                                              syscall.Errno = 0x00040130
	DATA_S_LAST                                                               syscall.Errno = 0x0004013F
	VIEW_E_FIRST                                                              syscall.Errno = 0x80040140
	VIEW_E_LAST                                                               syscall.Errno = 0x8004014F
	VIEW_S_FIRST                                                              syscall.Errno = 0x00040140
	VIEW_S_LAST                                                               syscall.Errno = 0x0004014F
	VIEW_E_DRAW                                                               Handle        = 0x80040140
	REGDB_E_FIRST                                                             syscall.Errno = 0x80040150
	REGDB_E_LAST                                                              syscall.Errno = 0x8004015F
	REGDB_S_FIRST                                                             syscall.Errno = 0x00040150
	REGDB_S_LAST                                                              syscall.Errno = 0x0004015F
	REGDB_E_READREGDB                                                         Handle        = 0x80040150
	REGDB_E_WRITEREGDB                                                        Handle        = 0x80040151
	REGDB_E_KEYMISSING                                                        Handle        = 0x80040152
	REGDB_E_INVALIDVALUE                                                      Handle        = 0x80040153
	REGDB_E_CLASSNOTREG                                                       Handle        = 0x80040154
	REGDB_E_IIDNOTREG                                                         Handle        = 0x80040155
	REGDB_E_BADTHREADINGMODEL                                                 Handle        = 0x80040156
	REGDB_E_PACKAGEPOLICYVIOLATION                                            Handle        = 0x80040157
	CAT_E_FIRST                                                               syscall.Errno = 0x80040160
	CAT_E_LAST                                                                syscall.Errno = 0x80040161
	CAT_E_CATIDNOEXIST                                                        Handle        = 0x80040160
	CAT_E_NODESCRIPTION                                                       Handle        = 0x80040161
	CS_E_FIRST                                                                syscall.Errno = 0x80040164
	CS_E_LAST                                                                 syscall.Errno = 0x8004016F
	CS_E_PACKAGE_NOTFOUND                                                     Handle        = 0x80040164
	CS_E_NOT_DELETABLE                                                        Handle        = 0x80040165
	CS_E_CLASS_NOTFOUND                                                       Handle        = 0x80040166
	CS_E_INVALID_VERSION                                                      Handle        = 0x80040167
	CS_E_NO_CLASSSTORE                                                        Handle        = 0x80040168
	CS_E_OBJECT_NOTFOUND                                                      Handle        = 0x80040169
	CS_E_OBJECT_ALREADY_EXISTS                                                Handle        = 0x8004016A
	CS_E_INVALID_PATH                                                         Handle        = 0x8004016B
	CS_E_NETWORK_ERROR                                                        Handle        = 0x8004016C
	CS_E_ADMIN_LIMIT_EXCEEDED                                                 Handle        = 0x8004016D
	CS_E_SCHEMA_MISMATCH                                                      Handle        = 0x8004016E
	CS_E_INTERNAL_ERROR                                                       Handle        = 0x8004016F
	CACHE_E_FIRST                                                             syscall.Errno = 0x80040170
	CACHE_E_LAST                                                              syscall.Errno = 0x8004017F
	CACHE_S_FIRST                                                             syscall.Errno = 0x00040170
	CACHE_S_LAST                                                              syscall.Errno = 0x0004017F
	CACHE_E_NOCACHE_UPDATED                                                   Handle        = 0x80040170
	OLEO
```