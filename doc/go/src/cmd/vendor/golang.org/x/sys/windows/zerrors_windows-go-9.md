Response:
Let's break down the thought process to analyze this Go code snippet and fulfill the request.

**1. Initial Observation and Goal Identification:**

The first thing I notice is the structure: a series of Go constants being declared. They all have a similar format: `Name Type = Value`. Specifically, the `Type` is consistently `Handle`. The `Value` is a hexadecimal number. The names are descriptive, often starting with prefixes like `E_MBN_`, `PEER_E_`, `UI_E_`, etc.

The request asks for the *functionality* of this code. Since it's just constant declarations, the direct functionality is simply defining these constants. However, the request also hints at a *deeper* purpose and asks to infer the Go language feature being implemented.

**2. Inferring the Purpose: Error Handling**

The prefixes like `E_` (likely for "Error") and the descriptive names strongly suggest that these constants represent error codes. The `Handle` type further reinforces this, as handles are often used in Windows API interactions, where error codes are common. The numerical values, especially the high bit being set (suggesting negative numbers when interpreted as signed integers), are also typical of error codes.

**3. Identifying the Go Language Feature: Custom Error Types**

Knowing these are likely error codes, the next step is to figure out how Go handles them. Go has a built-in `error` interface. While these constants aren't directly implementing that interface *here*, they are clearly intended to be used in conjunction with it. A common pattern is to define custom error types or use these constants to create more informative error values.

**4. Constructing a Go Code Example:**

Now, I need to demonstrate how these constants would be used in a real Go scenario. I'll make the following assumptions and build the example around them:

* **Assumption:** These constants are used when interacting with some Windows API related to mobile broadband (`MBN`), peer-to-peer networking (`PEER`), and potentially other subsystems.
* **Goal:**  Show how to check for specific errors using these constants.

The example should:
* Import necessary packages (likely `fmt` and potentially Windows-specific packages if simulating an API call).
* Define a hypothetical function that could return one of these errors. Since I don't have the actual API, I'll simulate this by returning a specific constant.
* Demonstrate how to compare the returned error with the predefined constants.

This leads to the example code provided in the initial good answer, focusing on the `E_MBN_SIM_NOT_INSERTED` error.

**5. Explaining the Code Example:**

The explanation needs to cover:

* What the example does: Simulates a function call and checks for a specific error.
* How the constants are used:  Direct comparison with the returned "error".
* Why this is useful: Provides specific error information.

**6. Addressing Other Aspects of the Request:**

* **Command-line parameters:** This snippet doesn't directly handle command-line arguments, so I'll state that.
* **User errors:** A common mistake is directly comparing error values without considering the underlying type. I'll provide an example of this and explain the correct way using type assertions or error unwrapping (although this example is simple enough that direct comparison works).
* **Code inference (input/output):** Since the code is just constant definitions, there's no dynamic input or output to infer in the same way as a function. The "input" is the constant definition, and the "output" is the constant value itself. The example demonstrates how these values are *used* as output in an error handling context.

**7. Summarizing the Functionality:**

The core functionality is defining a set of named constants representing Windows error codes. These constants enhance code readability and maintainability by providing meaningful names for specific error conditions.

**8. Considering the "Part 10 of 15" Context:**

The fact that this is part of a larger set suggests that other parts likely define the actual functions or APIs that *return* these error codes. This part is simply laying the groundwork for error identification and handling.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe these are flags or configuration values?  No, the `E_` prefix and descriptive names strongly point to errors.
* **Should I simulate a real Windows API call?** While more realistic, it adds complexity and requires importing Windows-specific packages. For this example, simulating the return is sufficient to illustrate the core concept.
* **How much detail about error handling in Go should I include?** Focus on the direct use of these constants. Mentioning more advanced techniques like error wrapping is good but keep the example focused.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive answer that addresses all aspects of the user's request.
这是一个Go语言实现的片段，它定义了一系列常量，这些常量代表了Windows操作系统中特定的错误代码或状态码。 这些常量主要用于与Windows API进行交互时，表示操作的结果或者遇到的问题。

**它的功能：**

1. **定义Windows错误常量:** 该文件定义了大量的Go语言常量，每个常量都对应一个特定的Windows错误码或状态码。这些常量通常用于判断Windows API调用的结果，并根据不同的错误码采取相应的处理措施。

2. **提高代码可读性:**  使用有意义的常量名（例如 `E_MBN_SIM_NOT_INSERTED` 而不是直接使用 `0x8054820A`）可以显著提高代码的可读性和可维护性。 开发者可以更容易理解代码中正在检查的错误类型。

3. **方便错误处理:** 通过预定义的常量，可以方便地在Go代码中对特定的Windows错误进行判断和处理。

**它是什么Go语言功能的实现：**

这个代码片段主要使用了Go语言的**常量 (const)** 定义功能。  它将Windows API中定义的错误码映射到了Go语言的常量。

**Go代码举例说明:**

假设我们有一个Go函数，它调用了一个Windows API来检查SIM卡是否插入。  如果SIM卡未插入，该API会返回一个特定的错误码，对应于我们提供的代码片段中的 `E_MBN_SIM_NOT_INSERTED` 常量。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	// 假设我们定义了一个Windows API调用相关的包
	"golang.org/x/sys/windows"
)

// 假设这是从 zerrors_windows.go 中提取的相关常量定义
const (
	E_MBN_SIM_NOT_INSERTED windows.Handle = 0x8054820A
	ERROR_SUCCESS          windows.Handle = 0 // 假设定义了成功码
)

// 假设的Windows API调用 (简化表示)
func checkSimCardStatus() error {
	// 在实际场景中，这里会调用一个Windows API，并获取其返回的错误码
	// 这里为了演示，我们假设返回了 E_MBN_SIM_NOT_INSERTED
	ret := E_MBN_SIM_NOT_INSERTED

	if ret != ERROR_SUCCESS {
		return syscall.Errno(ret) // 将Windows错误码转换为Go的error
	}
	return nil
}

func main() {
	err := checkSimCardStatus()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if windows.Handle(errno) == E_MBN_SIM_NOT_INSERTED {
				fmt.Println("错误：SIM卡未插入")
			} else {
				fmt.Printf("发生其他错误: %x\n", errno)
			}
		} else {
			fmt.Println("发生未知错误:", err)
		}
	} else {
		fmt.Println("SIM卡已插入")
	}
}
```

**假设的输入与输出:**

在这个例子中，`checkSimCardStatus` 函数内部是模拟的，实际情况下它会调用Windows API。

* **假设的输入:**  系统状态，例如SIM卡是否真的插入。
* **可能的输出:**
    * 如果SIM卡未插入：控制台输出 "错误：SIM卡未插入"。
    * 如果API调用成功（假设我们模拟返回了 `ERROR_SUCCESS`）：控制台输出 "SIM卡已插入"。
    * 如果发生其他Windows错误：控制台输出 "发生其他错误: [错误码的十六进制表示]"。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。 它的作用是定义常量，这些常量可以在其他处理Windows API调用的代码中使用。  处理命令行参数通常会在 `main` 函数中使用 `os.Args` 或第三方库来实现，与这些错误常量的定义是分离的。

**使用者易犯错的点:**

* **直接比较错误值:**  初学者可能直接比较 `error` 类型的值，而不是将其转换为 `syscall.Errno` 并与常量进行比较。  Go的错误处理机制中，错误类型是很重要的。

  ```go
  // 错误的做法
  if err == syscall.Errno(E_MBN_SIM_NOT_INSERTED) { // 这样做可能不会按预期工作
      // ...
  }

  // 正确的做法 (如上面的例子)
  if errno, ok := err.(syscall.Errno); ok {
      if windows.Handle(errno) == E_MBN_SIM_NOT_INSERTED {
          // ...
      }
  }
  ```

* **忽略错误类型:**  仅仅检查错误码，而忽略错误的具体类型，可能导致处理不当。例如，不同的子系统可能有相同的错误码，但含义不同。

**归纳一下它的功能 (第10部分):**

作为第10部分，这个 `zerrors_windows.go` 文件（的这个片段）的主要功能是**定义了一系列Go语言常量，这些常量对应于Windows操作系统中各种子系统（如移动宽带MBN、对等网络PEER、用户界面UI、蓝牙、音频等）的特定错误代码和状态码。**  这些常量为Go程序在与Windows系统交互时提供了结构化的方式来识别和处理操作过程中可能出现的各种错误情况，提高了代码的可读性和可维护性。  可以推断，这个文件是`golang.org/x/sys/windows` 包中用于处理Windows API错误的重要组成部分。  其他部分（例如，第11部分等）可能会包含使用这些常量的具体Windows API调用封装。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第10部分，共15部分，请归纳一下它的功能

"""
3
	E_MBN_INVALID_ACCESS_STRING                                               Handle        = 0x80548204
	E_MBN_MAX_ACTIVATED_CONTEXTS                                              Handle        = 0x80548205
	E_MBN_PACKET_SVC_DETACHED                                                 Handle        = 0x80548206
	E_MBN_PROVIDER_NOT_VISIBLE                                                Handle        = 0x80548207
	E_MBN_RADIO_POWER_OFF                                                     Handle        = 0x80548208
	E_MBN_SERVICE_NOT_ACTIVATED                                               Handle        = 0x80548209
	E_MBN_SIM_NOT_INSERTED                                                    Handle        = 0x8054820A
	E_MBN_VOICE_CALL_IN_PROGRESS                                              Handle        = 0x8054820B
	E_MBN_INVALID_CACHE                                                       Handle        = 0x8054820C
	E_MBN_NOT_REGISTERED                                                      Handle        = 0x8054820D
	E_MBN_PROVIDERS_NOT_FOUND                                                 Handle        = 0x8054820E
	E_MBN_PIN_NOT_SUPPORTED                                                   Handle        = 0x8054820F
	E_MBN_PIN_REQUIRED                                                        Handle        = 0x80548210
	E_MBN_PIN_DISABLED                                                        Handle        = 0x80548211
	E_MBN_FAILURE                                                             Handle        = 0x80548212
	E_MBN_INVALID_PROFILE                                                     Handle        = 0x80548218
	E_MBN_DEFAULT_PROFILE_EXIST                                               Handle        = 0x80548219
	E_MBN_SMS_ENCODING_NOT_SUPPORTED                                          Handle        = 0x80548220
	E_MBN_SMS_FILTER_NOT_SUPPORTED                                            Handle        = 0x80548221
	E_MBN_SMS_INVALID_MEMORY_INDEX                                            Handle        = 0x80548222
	E_MBN_SMS_LANG_NOT_SUPPORTED                                              Handle        = 0x80548223
	E_MBN_SMS_MEMORY_FAILURE                                                  Handle        = 0x80548224
	E_MBN_SMS_NETWORK_TIMEOUT                                                 Handle        = 0x80548225
	E_MBN_SMS_UNKNOWN_SMSC_ADDRESS                                            Handle        = 0x80548226
	E_MBN_SMS_FORMAT_NOT_SUPPORTED                                            Handle        = 0x80548227
	E_MBN_SMS_OPERATION_NOT_ALLOWED                                           Handle        = 0x80548228
	E_MBN_SMS_MEMORY_FULL                                                     Handle        = 0x80548229
	PEER_E_IPV6_NOT_INSTALLED                                                 Handle        = 0x80630001
	PEER_E_NOT_INITIALIZED                                                    Handle        = 0x80630002
	PEER_E_CANNOT_START_SERVICE                                               Handle        = 0x80630003
	PEER_E_NOT_LICENSED                                                       Handle        = 0x80630004
	PEER_E_INVALID_GRAPH                                                      Handle        = 0x80630010
	PEER_E_DBNAME_CHANGED                                                     Handle        = 0x80630011
	PEER_E_DUPLICATE_GRAPH                                                    Handle        = 0x80630012
	PEER_E_GRAPH_NOT_READY                                                    Handle        = 0x80630013
	PEER_E_GRAPH_SHUTTING_DOWN                                                Handle        = 0x80630014
	PEER_E_GRAPH_IN_USE                                                       Handle        = 0x80630015
	PEER_E_INVALID_DATABASE                                                   Handle        = 0x80630016
	PEER_E_TOO_MANY_ATTRIBUTES                                                Handle        = 0x80630017
	PEER_E_CONNECTION_NOT_FOUND                                               Handle        = 0x80630103
	PEER_E_CONNECT_SELF                                                       Handle        = 0x80630106
	PEER_E_ALREADY_LISTENING                                                  Handle        = 0x80630107
	PEER_E_NODE_NOT_FOUND                                                     Handle        = 0x80630108
	PEER_E_CONNECTION_FAILED                                                  Handle        = 0x80630109
	PEER_E_CONNECTION_NOT_AUTHENTICATED                                       Handle        = 0x8063010A
	PEER_E_CONNECTION_REFUSED                                                 Handle        = 0x8063010B
	PEER_E_CLASSIFIER_TOO_LONG                                                Handle        = 0x80630201
	PEER_E_TOO_MANY_IDENTITIES                                                Handle        = 0x80630202
	PEER_E_NO_KEY_ACCESS                                                      Handle        = 0x80630203
	PEER_E_GROUPS_EXIST                                                       Handle        = 0x80630204
	PEER_E_RECORD_NOT_FOUND                                                   Handle        = 0x80630301
	PEER_E_DATABASE_ACCESSDENIED                                              Handle        = 0x80630302
	PEER_E_DBINITIALIZATION_FAILED                                            Handle        = 0x80630303
	PEER_E_MAX_RECORD_SIZE_EXCEEDED                                           Handle        = 0x80630304
	PEER_E_DATABASE_ALREADY_PRESENT                                           Handle        = 0x80630305
	PEER_E_DATABASE_NOT_PRESENT                                               Handle        = 0x80630306
	PEER_E_IDENTITY_NOT_FOUND                                                 Handle        = 0x80630401
	PEER_E_EVENT_HANDLE_NOT_FOUND                                             Handle        = 0x80630501
	PEER_E_INVALID_SEARCH                                                     Handle        = 0x80630601
	PEER_E_INVALID_ATTRIBUTES                                                 Handle        = 0x80630602
	PEER_E_INVITATION_NOT_TRUSTED                                             Handle        = 0x80630701
	PEER_E_CHAIN_TOO_LONG                                                     Handle        = 0x80630703
	PEER_E_INVALID_TIME_PERIOD                                                Handle        = 0x80630705
	PEER_E_CIRCULAR_CHAIN_DETECTED                                            Handle        = 0x80630706
	PEER_E_CERT_STORE_CORRUPTED                                               Handle        = 0x80630801
	PEER_E_NO_CLOUD                                                           Handle        = 0x80631001
	PEER_E_CLOUD_NAME_AMBIGUOUS                                               Handle        = 0x80631005
	PEER_E_INVALID_RECORD                                                     Handle        = 0x80632010
	PEER_E_NOT_AUTHORIZED                                                     Handle        = 0x80632020
	PEER_E_PASSWORD_DOES_NOT_MEET_POLICY                                      Handle        = 0x80632021
	PEER_E_DEFERRED_VALIDATION                                                Handle        = 0x80632030
	PEER_E_INVALID_GROUP_PROPERTIES                                           Handle        = 0x80632040
	PEER_E_INVALID_PEER_NAME                                                  Handle        = 0x80632050
	PEER_E_INVALID_CLASSIFIER                                                 Handle        = 0x80632060
	PEER_E_INVALID_FRIENDLY_NAME                                              Handle        = 0x80632070
	PEER_E_INVALID_ROLE_PROPERTY                                              Handle        = 0x80632071
	PEER_E_INVALID_CLASSIFIER_PROPERTY                                        Handle        = 0x80632072
	PEER_E_INVALID_RECORD_EXPIRATION                                          Handle        = 0x80632080
	PEER_E_INVALID_CREDENTIAL_INFO                                            Handle        = 0x80632081
	PEER_E_INVALID_CREDENTIAL                                                 Handle        = 0x80632082
	PEER_E_INVALID_RECORD_SIZE                                                Handle        = 0x80632083
	PEER_E_UNSUPPORTED_VERSION                                                Handle        = 0x80632090
	PEER_E_GROUP_NOT_READY                                                    Handle        = 0x80632091
	PEER_E_GROUP_IN_USE                                                       Handle        = 0x80632092
	PEER_E_INVALID_GROUP                                                      Handle        = 0x80632093
	PEER_E_NO_MEMBERS_FOUND                                                   Handle        = 0x80632094
	PEER_E_NO_MEMBER_CONNECTIONS                                              Handle        = 0x80632095
	PEER_E_UNABLE_TO_LISTEN                                                   Handle        = 0x80632096
	PEER_E_IDENTITY_DELETED                                                   Handle        = 0x806320A0
	PEER_E_SERVICE_NOT_AVAILABLE                                              Handle        = 0x806320A1
	PEER_E_CONTACT_NOT_FOUND                                                  Handle        = 0x80636001
	PEER_S_GRAPH_DATA_CREATED                                                 Handle        = 0x00630001
	PEER_S_NO_EVENT_DATA                                                      Handle        = 0x00630002
	PEER_S_ALREADY_CONNECTED                                                  Handle        = 0x00632000
	PEER_S_SUBSCRIPTION_EXISTS                                                Handle        = 0x00636000
	PEER_S_NO_CONNECTIVITY                                                    Handle        = 0x00630005
	PEER_S_ALREADY_A_MEMBER                                                   Handle        = 0x00630006
	PEER_E_CANNOT_CONVERT_PEER_NAME                                           Handle        = 0x80634001
	PEER_E_INVALID_PEER_HOST_NAME                                             Handle        = 0x80634002
	PEER_E_NO_MORE                                                            Handle        = 0x80634003
	PEER_E_PNRP_DUPLICATE_PEER_NAME                                           Handle        = 0x80634005
	PEER_E_INVITE_CANCELLED                                                   Handle        = 0x80637000
	PEER_E_INVITE_RESPONSE_NOT_AVAILABLE                                      Handle        = 0x80637001
	PEER_E_NOT_SIGNED_IN                                                      Handle        = 0x80637003
	PEER_E_PRIVACY_DECLINED                                                   Handle        = 0x80637004
	PEER_E_TIMEOUT                                                            Handle        = 0x80637005
	PEER_E_INVALID_ADDRESS                                                    Handle        = 0x80637007
	PEER_E_FW_EXCEPTION_DISABLED                                              Handle        = 0x80637008
	PEER_E_FW_BLOCKED_BY_POLICY                                               Handle        = 0x80637009
	PEER_E_FW_BLOCKED_BY_SHIELDS_UP                                           Handle        = 0x8063700A
	PEER_E_FW_DECLINED                                                        Handle        = 0x8063700B
	UI_E_CREATE_FAILED                                                        Handle        = 0x802A0001
	UI_E_SHUTDOWN_CALLED                                                      Handle        = 0x802A0002
	UI_E_ILLEGAL_REENTRANCY                                                   Handle        = 0x802A0003
	UI_E_OBJECT_SEALED                                                        Handle        = 0x802A0004
	UI_E_VALUE_NOT_SET                                                        Handle        = 0x802A0005
	UI_E_VALUE_NOT_DETERMINED                                                 Handle        = 0x802A0006
	UI_E_INVALID_OUTPUT                                                       Handle        = 0x802A0007
	UI_E_BOOLEAN_EXPECTED                                                     Handle        = 0x802A0008
	UI_E_DIFFERENT_OWNER                                                      Handle        = 0x802A0009
	UI_E_AMBIGUOUS_MATCH                                                      Handle        = 0x802A000A
	UI_E_FP_OVERFLOW                                                          Handle        = 0x802A000B
	UI_E_WRONG_THREAD                                                         Handle        = 0x802A000C
	UI_E_STORYBOARD_ACTIVE                                                    Handle        = 0x802A0101
	UI_E_STORYBOARD_NOT_PLAYING                                               Handle        = 0x802A0102
	UI_E_START_KEYFRAME_AFTER_END                                             Handle        = 0x802A0103
	UI_E_END_KEYFRAME_NOT_DETERMINED                                          Handle        = 0x802A0104
	UI_E_LOOPS_OVERLAP                                                        Handle        = 0x802A0105
	UI_E_TRANSITION_ALREADY_USED                                              Handle        = 0x802A0106
	UI_E_TRANSITION_NOT_IN_STORYBOARD                                         Handle        = 0x802A0107
	UI_E_TRANSITION_ECLIPSED                                                  Handle        = 0x802A0108
	UI_E_TIME_BEFORE_LAST_UPDATE                                              Handle        = 0x802A0109
	UI_E_TIMER_CLIENT_ALREADY_CONNECTED                                       Handle        = 0x802A010A
	UI_E_INVALID_DIMENSION                                                    Handle        = 0x802A010B
	UI_E_PRIMITIVE_OUT_OF_BOUNDS                                              Handle        = 0x802A010C
	UI_E_WINDOW_CLOSED                                                        Handle        = 0x802A0201
	E_BLUETOOTH_ATT_INVALID_HANDLE                                            Handle        = 0x80650001
	E_BLUETOOTH_ATT_READ_NOT_PERMITTED                                        Handle        = 0x80650002
	E_BLUETOOTH_ATT_WRITE_NOT_PERMITTED                                       Handle        = 0x80650003
	E_BLUETOOTH_ATT_INVALID_PDU                                               Handle        = 0x80650004
	E_BLUETOOTH_ATT_INSUFFICIENT_AUTHENTICATION                               Handle        = 0x80650005
	E_BLUETOOTH_ATT_REQUEST_NOT_SUPPORTED                                     Handle        = 0x80650006
	E_BLUETOOTH_ATT_INVALID_OFFSET                                            Handle        = 0x80650007
	E_BLUETOOTH_ATT_INSUFFICIENT_AUTHORIZATION                                Handle        = 0x80650008
	E_BLUETOOTH_ATT_PREPARE_QUEUE_FULL                                        Handle        = 0x80650009
	E_BLUETOOTH_ATT_ATTRIBUTE_NOT_FOUND                                       Handle        = 0x8065000A
	E_BLUETOOTH_ATT_ATTRIBUTE_NOT_LONG                                        Handle        = 0x8065000B
	E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE                          Handle        = 0x8065000C
	E_BLUETOOTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH                            Handle        = 0x8065000D
	E_BLUETOOTH_ATT_UNLIKELY                                                  Handle        = 0x8065000E
	E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION                                   Handle        = 0x8065000F
	E_BLUETOOTH_ATT_UNSUPPORTED_GROUP_TYPE                                    Handle        = 0x80650010
	E_BLUETOOTH_ATT_INSUFFICIENT_RESOURCES                                    Handle        = 0x80650011
	E_BLUETOOTH_ATT_UNKNOWN_ERROR                                             Handle        = 0x80651000
	E_AUDIO_ENGINE_NODE_NOT_FOUND                                             Handle        = 0x80660001
	E_HDAUDIO_EMPTY_CONNECTION_LIST                                           Handle        = 0x80660002
	E_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED                                   Handle        = 0x80660003
	E_HDAUDIO_NO_LOGICAL_DEVICES_CREATED                                      Handle        = 0x80660004
	E_HDAUDIO_NULL_LINKED_LIST_ENTRY                                          Handle        = 0x80660005
	STATEREPOSITORY_E_CONCURRENCY_LOCKING_FAILURE                             Handle        = 0x80670001
	STATEREPOSITORY_E_STATEMENT_INPROGRESS                                    Handle        = 0x80670002
	STATEREPOSITORY_E_CONFIGURATION_INVALID                                   Handle        = 0x80670003
	STATEREPOSITORY_E_UNKNOWN_SCHEMA_VERSION                                  Handle        = 0x80670004
	STATEREPOSITORY_ERROR_DICTIONARY_CORRUPTED                                Handle        = 0x80670005
	STATEREPOSITORY_E_BLOCKED                                                 Handle        = 0x80670006
	STATEREPOSITORY_E_BUSY_RETRY                                              Handle        = 0x80670007
	STATEREPOSITORY_E_BUSY_RECOVERY_RETRY                                     Handle        = 0x80670008
	STATEREPOSITORY_E_LOCKED_RETRY                                            Handle        = 0x80670009
	STATEREPOSITORY_E_LOCKED_SHAREDCACHE_RETRY                                Handle        = 0x8067000A
	STATEREPOSITORY_E_TRANSACTION_REQUIRED                                    Handle        = 0x8067000B
	STATEREPOSITORY_E_BUSY_TIMEOUT_EXCEEDED                                   Handle        = 0x8067000C
	STATEREPOSITORY_E_BUSY_RECOVERY_TIMEOUT_EXCEEDED                          Handle        = 0x8067000D
	STATEREPOSITORY_E_LOCKED_TIMEOUT_EXCEEDED                                 Handle        = 0x8067000E
	STATEREPOSITORY_E_LOCKED_SHAREDCACHE_TIMEOUT_EXCEEDED                     Handle        = 0x8067000F
	STATEREPOSITORY_E_SERVICE_STOP_IN_PROGRESS                                Handle        = 0x80670010
	STATEREPOSTORY_E_NESTED_TRANSACTION_NOT_SUPPORTED                         Handle        = 0x80670011
	STATEREPOSITORY_ERROR_CACHE_CORRUPTED                                     Handle        = 0x80670012
	STATEREPOSITORY_TRANSACTION_CALLER_ID_CHANGED                             Handle        = 0x00670013
	STATEREPOSITORY_TRANSACTION_IN_PROGRESS                                   Handle        = 0x00670014
	ERROR_SPACES_POOL_WAS_DELETED                                             Handle        = 0x00E70001
	ERROR_SPACES_FAULT_DOMAIN_TYPE_INVALID                                    Handle        = 0x80E70001
	ERROR_SPACES_INTERNAL_ERROR                                               Handle        = 0x80E70002
	ERROR_SPACES_RESILIENCY_TYPE_INVALID                                      Handle        = 0x80E70003
	ERROR_SPACES_DRIVE_SECTOR_SIZE_INVALID                                    Handle        = 0x80E70004
	ERROR_SPACES_DRIVE_REDUNDANCY_INVALID                                     Handle        = 0x80E70006
	ERROR_SPACES_NUMBER_OF_DATA_COPIES_INVALID                                Handle        = 0x80E70007
	ERROR_SPACES_PARITY_LAYOUT_INVALID                                        Handle        = 0x80E70008
	ERROR_SPACES_INTERLEAVE_LENGTH_INVALID                                    Handle        = 0x80E70009
	ERROR_SPACES_NUMBER_OF_COLUMNS_INVALID                                    Handle        = 0x80E7000A
	ERROR_SPACES_NOT_ENOUGH_DRIVES                                            Handle        = 0x80E7000B
	ERROR_SPACES_EXTENDED_ERROR                                               Handle        = 0x80E7000C
	ERROR_SPACES_PROVISIONING_TYPE_INVALID                                    Handle        = 0x80E7000D
	ERROR_SPACES_ALLOCATION_SIZE_INVALID                                      Handle        = 0x80E7000E
	ERROR_SPACES_ENCLOSURE_AWARE_INVALID                                      Handle        = 0x80E7000F
	ERROR_SPACES_WRITE_CACHE_SIZE_INVALID                                     Handle        = 0x80E70010
	ERROR_SPACES_NUMBER_OF_GROUPS_INVALID                                     Handle        = 0x80E70011
	ERROR_SPACES_DRIVE_OPERATIONAL_STATE_INVALID                              Handle        = 0x80E70012
	ERROR_SPACES_ENTRY_INCOMPLETE                                             Handle        = 0x80E70013
	ERROR_SPACES_ENTRY_INVALID                                                Handle        = 0x80E70014
	ERROR_VOLSNAP_BOOTFILE_NOT_VALID                                          Handle        = 0x80820001
	ERROR_VOLSNAP_ACTIVATION_TIMEOUT                                          Handle        = 0x80820002
	ERROR_TIERING_NOT_SUPPORTED_ON_VOLUME                                     Handle        = 0x80830001
	ERROR_TIERING_VOLUME_DISMOUNT_IN_PROGRESS                                 Handle        = 0x80830002
	ERROR_TIERING_STORAGE_TIER_NOT_FOUND                                      Handle        = 0x80830003
	ERROR_TIERING_INVALID_FILE_ID                                             Handle        = 0x80830004
	ERROR_TIERING_WRONG_CLUSTER_NODE                                          Handle        = 0x80830005
	ERROR_TIERING_ALREADY_PROCESSING                                          Handle        = 0x80830006
	ERROR_TIERING_CANNOT_PIN_OBJECT                                           Handle        = 0x80830007
	ERROR_TIERING_FILE_IS_NOT_PINNED                                          Handle        = 0x80830008
	ERROR_NOT_A_TIERED_VOLUME                                                 Handle        = 0x80830009
	ERROR_ATTRIBUTE_NOT_PRESENT                                               Handle        = 0x8083000A
	ERROR_SECCORE_INVALID_COMMAND                                             Handle        = 0xC0E80000
	ERROR_NO_APPLICABLE_APP_LICENSES_FOUND                                    Handle        = 0xC0EA0001
	ERROR_CLIP_LICENSE_NOT_FOUND                                              Handle        = 0xC0EA0002
	ERROR_CLIP_DEVICE_LICENSE_MISSING                                         Handle        = 0xC0EA0003
	ERROR_CLIP_LICENSE_INVALID_SIGNATURE                                      Handle        = 0xC0EA0004
	ERROR_CLIP_KEYHOLDER_LICENSE_MISSING_OR_INVALID                           Handle        = 0xC0EA0005
	ERROR_CLIP_LICENSE_EXPIRED                                                Handle        = 0xC0EA0006
	ERROR_CLIP_LICENSE_SIGNED_BY_UNKNOWN_SOURCE                               Handle        = 0xC0EA0007
	ERROR_CLIP_LICENSE_NOT_SIGNED                                             Handle        = 0xC0EA0008
	ERROR_CLIP_LICENSE_HARDWARE_ID_OUT_OF_TOLERANCE                           Handle        = 0xC0EA0009
	ERROR_CLIP_LICENSE_DEVICE_ID_MISMATCH                                     Handle        = 0xC0EA000A
	DXGI_STATUS_OCCLUDED                                                      Handle        = 0x087A0001
	DXGI_STATUS_CLIPPED                                                       Handle        = 0x087A0002
	DXGI_STATUS_NO_REDIRECTION                                                Handle        = 0x087A0004
	DXGI_STATUS_NO_DESKTOP_ACCESS                                             Handle        = 0x087A0005
	DXGI_STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE                                  Handle        = 0x087A0006
	DXGI_STATUS_MODE_CHANGED                                                  Handle        = 0x087A0007
	DXGI_STATUS_MODE_CHANGE_IN_PROGRESS                                       Handle        = 0x087A0008
	DXGI_ERROR_INVALID_CALL                                                   Handle        = 0x887A0001
	DXGI_ERROR_NOT_FOUND                                                      Handle        = 0x887A0002
	DXGI_ERROR_MORE_DATA                                                      Handle        = 0x887A0003
	DXGI_ERROR_UNSUPPORTED                                                    Handle        = 0x887A0004
	DXGI_ERROR_DEVICE_REMOVED                                                 Handle        = 0x887A0005
	DXGI_ERROR_DEVICE_HUNG                                                    Handle        = 0x887A0006
	DXGI_ERROR_DEVICE_RESET                                                   Handle        = 0x887A0007
	DXGI_ERROR_WAS_STILL_DRAWING                                              Handle        = 0x887A000A
	DXGI_ERROR_FRAME_STATISTICS_DISJOINT                                      Handle        = 0x887A000B
	DXGI_ERROR_GRAPHICS_VIDPN_SOURCE_IN_USE                                   Handle        = 0x887A000C
	DXGI_ERROR_DRIVER_INTERNAL_ERROR                                          Handle        = 0x887A0020
	DXGI_ERROR_NONEXCLUSIVE                                                   Handle        = 0x887A0021
	DXGI_ERROR_NOT_CURRENTLY_AVAILABLE                                        Handle        = 0x887A0022
	DXGI_ERROR_REMOTE_CLIENT_DISCONNECTED                                     Handle        = 0x887A0023
	DXGI_ERROR_REMOTE_OUTOFMEMORY                                             Handle        = 0x887A0024
	DXGI_ERROR_ACCESS_LOST                                                    Handle        = 0x887A0026
	DXGI_ERROR_WAIT_TIMEOUT                                                   Handle        = 0x887A0027
	DXGI_ERROR_SESSION_DISCONNECTED                                           Handle        = 0x887A0028
	DXGI_ERROR_RESTRICT_TO_OUTPUT_STALE                                       Handle        = 0x887A0029
	DXGI_ERROR_CANNOT_PROTECT_CONTENT                                         Handle        = 0x887A002A
	DXGI_ERROR_ACCESS_DENIED                                                  Handle        = 0x887A002B
	DXGI_ERROR_NAME_ALREADY_EXISTS                                            Handle        = 0x887A002C
	DXGI_ERROR_SDK_COMPONENT_MISSING                                          Handle        = 0x887A002D
	DXGI_ERROR_NOT_CURRENT                                                    Handle        = 0x887A002E
	DXGI_ERROR_HW_PROTECTION_OUTOFMEMORY                                      Handle        = 0x887A0030
	DXGI_ERROR_DYNAMIC_CODE_POLICY_VIOLATION                                  Handle        = 0x887A0031
	DXGI_ERROR_NON_COMPOSITED_UI                                              Handle        = 0x887A0032
	DXGI_STATUS_UNOCCLUDED                                                    Handle        = 0x087A0009
	DXGI_STATUS_DDA_WAS_STILL_DRAWING                                         Handle        = 0x087A000A
	DXGI_ERROR_MODE_CHANGE_IN_PROGRESS                                        Handle        = 0x887A0025
	DXGI_STATUS_PRESENT_REQUIRED                                              Handle        = 0x087A002F
	DXGI_ERROR_CACHE_CORRUPT                                                  Handle        = 0x887A0033
	DXGI_ERROR_CACHE_FULL                                                     Handle        = 0x887A0034
	DXGI_ERROR_CACHE_HASH_COLLISION                                           Handle        = 0x887A0035
	DXGI_ERROR_ALREADY_EXISTS                                                 Handle        = 0x887A0036
	DXGI_DDI_ERR_WASSTILLDRAWING                                              Handle        = 0x887B0001
	DXGI_DDI_ERR_UNSUPPORTED                                                  Handle        = 0x887B0002
	DXGI_DDI_ERR_NONEXCLUSIVE                                                 Handle        = 0x887B0003
	D3D10_ERROR_TOO_MANY_UNIQUE_STATE_OBJECTS                                 Handle        = 0x88790001
	D3D10_ERROR_FILE_NOT_FOUND                                                Handle        = 0x88790002
	D3D11_ERROR_TOO_MANY_UNIQUE_STATE_OBJECTS                                 Handle        = 0x887C0001
	D3D11_ERROR_FILE_NOT_FOUND                                                Handle        = 0x887C0002
	D3D11_ERROR_TOO_MANY_UNIQUE_VIEW_OBJECTS                                  Handle        = 0x887C0003
	D3D11_ERROR_DEFERRED_CONTEXT_MAP_WITHOUT_INITIAL_DISCARD                  Handle        = 0x887C0004
	D3D12_ERROR_ADAPTER_NOT_FOUND                                             Handle        = 0x887E0001
	D3D12_ERROR_DRIVER_VERSION_MISMATCH                                       Handle        = 0x887E0002
	D2DERR_WRONG_STATE                                                        Handle        = 0x88990001
	D2DERR_NOT_INITIALIZED                                                    Handle        = 0x88990002
	D2DERR_UNSUPPORTED_OPERATION                                              Handle        = 0x88990003
	D2DERR_SCANNER_FAILED                                                     Handle        = 0x88990004
	D2DERR_SCREEN_ACCESS_DENIED                                               Handle        = 0x88990005
	D2DERR_DISPLAY_STATE_INVALID                                              Handle        = 0x88990006
	D2DERR_ZERO_VECTOR                                                        Handle        = 0x88990007
	D2DERR_INTERNAL_ERROR                                                     Handle        = 0x88990008
	D2DERR_DISPLAY_FORMAT_NOT_SUPPORTED                                       Handle        = 0x88990009
	D2DERR_INVALID_CALL                                                       Handle        = 0x8899000A
	D2DERR_NO_HARDWARE_DEVICE                                                 Handle        = 0x8899000B
	D2DERR_RECREATE_TARGET                                                    Handle        = 0x8899000C
	D2DERR_TOO_MANY_SHADER_ELEMENTS                                           Handle        = 0x8899000D
	D2DERR_SHADER_COMPILE_FAILED                                              Handle        = 0x8899000E
	D2DERR_MAX_TEXTURE_SIZE_EXCEEDED                                          Handle        = 0x8899000F
	D2DERR_UNSUPPORTED_VERSION                                                Handle        = 0x88990010
	D2DERR_BAD_NUMBER                                                         Handle        = 0x88990011
	D2DERR_WRONG_FACTORY                                                      Handle        = 0x88990012
	D2DERR_LAYER_ALREADY_IN_USE                                               Handle        = 0x88990013
	D2DERR_POP_CALL_DID_NOT_MATCH_PUSH                                        Handle        = 0x88990014
	D2DERR_WRONG_RESOURCE_DOMAIN                                              Handle        = 0x88990015
	D2DERR_PUSH_POP_UNBALANCED                                                Handle        = 0x88990016
	D2DERR_RENDER_TARGET_HAS_LAYER_OR_CLIPRECT                                Handle        = 0x88990017
	D2DERR_INCOMPATIBLE_BRUSH_TYPES                                           Handle        = 0x88990018
	D2DERR_WIN32_ERROR                                                        Handle        = 0x88990019
	D2DERR_TARGET_NOT_GDI_COMPATIBLE                                          Handle        = 0x8899001A
	D2DERR_TEXT_EFFECT_IS_WRONG_TYPE                                          Handle        = 0x8899001B
	D2DERR_TEXT_RENDERER_NOT_RELEASED                                         Handle        = 0x8899001C
	D2DERR_EXCEEDS_MAX_BITMAP_SIZE                                            Handle        = 0x8899001D
	D2DERR_INVALID_GRAPH_CONFIGURATION                                        Handle        = 0x8899001E
	D2DERR_INVALID_INTERNAL_GRAPH_CONFIGURATION                               Handle        = 0x8899001F
	D2DERR_CYCLIC_GRAPH                                                       Handle        = 0x88990020
	D2DERR_BITMAP_CANNOT_DRAW                                                 Handle        = 0x88990021
	D2DERR_OUTSTANDING_BITMAP_REFERENCES                                      Handle        = 0x88990022
	D2DERR_ORIGINAL_TARGET_NOT_BOUND                                          Handle        = 0x88990023
	D2DERR_INVALID_TARGET                                                     Handle        = 0x88990024
	D2DERR_BITMAP_BOUND_AS_TARGET                                             Handle        = 0x88990025
	D2DERR_INSUFFICIENT_DEVICE_CAPABILITIES                                   Handle        = 0x88990026
	D2DERR_INTERMEDIATE_TOO_LARGE                                             Handle        = 0x88990027
	D2DERR_EFFECT_IS_NOT_REGISTERED                                           Handle        = 0x88990028
	D2DERR_INVALID_PROPERTY                                                   Handle        = 0x88990029
	D2DERR_NO_SUBPROPERTIES                                                   Handle        = 0x8899002A
	D2DERR_PRINT_JOB_CLOSED                                                   Handle        = 0x8899002B
	D2DERR_PRINT_FORMAT_NOT_SUPPORTED                                         Handle        = 0x8899002C
	D2DERR_TOO_MANY_TRANSFORM_INPUTS                                          Handle        = 0x8899002D
	D2DERR_INVALID_GLYPH_IMAGE                                                Handle        = 0x8899002E
	DWRITE_E_FILEFORMAT                                                       Handle        = 0x88985000
	DWRITE_E_UNEXPECTED                                                       Handle        = 0x88985001
	DWRITE_E_NOFONT                                                           Handle        = 0x88985002
	DWRITE_E_FILENOTFOUND                                                     Handle        = 0x88985003
	DWRITE_E_FILEACCESS                                                       Handle        = 0x88985004
	DWRITE_E_FONTCOLLECTIONOBSOLETE                                           Handle        = 0x88985005
	DWRITE_E_ALREADYREGISTERED                                                Handle        = 0x88985006
	DWRITE_E_CACHEFORMAT                                                      Handle        = 0x88985007
	DWRITE_E_CACHEVERSION                                                     Handle        = 0x88985008
	DWRITE_E_UNSUPPORTEDOPERATION                                             Handle        = 0x88985009
	DWRITE_E_TEXTRENDERERINCOMPATIBLE                                         Handle        = 0x8898500A
	DWRITE_E_FLOWDIRECTIONCONFLICTS                                           Handle        = 0x8898500B
	DWRITE_E_NOCOLOR                                                          Handle        = 0x8898500C
	DWRITE_E_REMOTEFONT                                                       Handle        = 0x8898500D
	DWRITE_E_DOWNLOADCANCELLED                                                Handle        = 0x8898500E
	DWRITE_E_DOWNLOADFAILED                                                   Handle        = 0x8898500F
	DWRITE_E_TOOMANYDOWNLOADS                                                 Handle        = 0x88985010
	WINCODEC_ERR_WRONGSTATE                                                   Handle        = 0x88982F04
	WINCODEC_ERR_VALUEOUTOFRANGE                                              Handle        = 0x88982F05
	WINCODEC_ERR_UNKNOWNIMAGEFORMAT                                           Handle        = 0x88982F07
	WINCODEC_ERR_UNSUPPORTEDVERSION                                           Handle        = 0x88982F0B
	WINCODEC_ERR_NOTINITIALIZED                                               Handle        = 0x88982F0C
	WINCODEC_ERR_ALREADYLOCKED                                                Handle        = 0x88982F0D
	WINCODEC_ERR_PROPERTYNOTFOUND                                             Handle        = 0x88982F40
	WINCODEC_ERR_PROPERTYNOTSUPPORTED                                         Handle        = 0x88982F41
	WINCODEC_ERR_PROPERTYSIZE                                                 Handle        = 0x88982F42
	WINCODEC_ERR_CODECPRESENT                                                 Handle        = 0x88982F43
	WINCODEC_ERR_CODECNOTHUMBNAIL                                             Handle        = 0x88982F44
	WINCODEC_ERR_PALETTEUNAVAILABLE                                           Handle        = 0x88982F45
	WINCODEC_ERR_CODECTOOMANYSCANLINES                                        Handle        = 0x88982F46
	WINCODEC_ERR_INTERNALERROR                                                Handle        = 0x88982F48
	WINCODEC_ERR_SOURCERECTDOESNOTMATCHDIMENSIONS                             Handle        = 0x88982F49
	WINCODEC_ERR_COMPONENTNOTFOUND                                            Handle        = 0x88982F50
	WINCODEC_ERR_IMAGESIZEOUTOFRANGE                                          Handle        = 0x88982F51
	WINCODEC_ERR_TOOMUCHMETADATA                                              Handle        = 0x88982F52
	WINCODEC_ERR_BADIMAGE                                                     Handle        = 0x88982F60
	WINCODEC_ERR_BADHEADER                                                    Handle        = 0x88982F61
	WINCODEC_ERR_FRAMEMISSING                                                 Handle        = 0x88982F62
	WINCODEC_ERR_BADMETADATAHEADER                                            Handle        = 0x88982F63
	WINCODEC_ERR_BADSTREAMDATA                                                Handle        = 0x88982F70
	WINCODEC_ERR_STREAMWRITE                                                  Handle        = 0x88982F71
	WINCODEC_ERR_STREAMREAD                                                   Handle        = 0x88982F72
	WINCODEC_ERR_STREAMNOTAVAILABLE                                           Handle        = 0x88982F73
	WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT                                       Handle        = 0x88982F80
	WINCODEC_ERR_UNSUPPORTEDOPERATION                                         Handle        = 0x88982F81
	WINCODEC_ERR_INVALIDREGISTRATION                                          Handle        = 0x88982F8A
	WINCODEC_ERR_COMPONENTINITIALIZEFAILURE                                   Handle        = 0x88982F8B
	WINCODEC_ERR_INSUFFICIENTBUFFER                                           Handle        = 0x88982F8C
	WINCODEC_ERR_DUPLICATEMETADATAPRESENT                                     Handle        = 0x88982F8D
	WINCODEC_ERR_PROPERTYUNEXPECTEDTYPE                                       Handle        = 0x88982F8E
	WINCODEC_ERR_UNEXPECTEDSIZE                                               Handle        = 0x88982F8F
	WINCODEC_ERR_INVALIDQUERYREQUEST                                          Handle        = 0x88982F90
	WINCODEC_ERR_UNEXPECTEDMETADATATYPE                                       Handle        = 0x88982F91
	WINCODEC_ERR_REQUESTONLYVALIDATMETADATAROOT                               Handle        = 0x88982F92
	WINCODEC_ERR_INVALIDQUERYCHARACTER                                        Handle        = 0x88982F93
	WINCODEC_ERR_WIN32ERROR                                                   Handle        = 0x88982F94
	WINCODEC_ERR_INVALIDPROGRESSIVELEVEL                                      Handle        = 0x88982F95
	WINCODEC_ERR_INVALIDJPEGSCANINDEX                                         Handle        = 0x88982F96
	MILERR_OBJECTBUSY                                                         Handle        = 0x88980001
	MILERR_INSUFFICIENTBUFFER                                                 Handle        = 0x88980002
	MILERR_WIN32ERROR                                                         Handle        = 0x88980003
	MILERR_SCANNER_FAILED                                                     Handle        = 0x88980004
	MILERR_SCREENACCESSDENIED                                                 Handle        = 0x88980005
	MILERR_DISPLAYSTATEINVALID                                                Handle        = 0x88980006
	MILERR_NONINVERTIBLEMATRIX                                                Handle        = 0x88980007
	MILERR_ZEROVECTOR                                                         Handle        = 0x88980008
	MILERR_TERMINATED                                                         Handle        = 0x88980009
	MILERR_BADNUMBER                                                          Handle        = 0x8898000A
	MILERR_INTERNALERROR                                                      Handle        = 0x88980080
	MILERR_DISPLAYFORMATNOTSUPPORTED                                          Handle        = 0x88980084
	MILERR_INVALIDCALL                                                        Handle        = 0x88980085
	MILERR_ALREADYLOCKED                                                      Handle        = 0x88980086
	MILERR_NOTLOCKED                                                          Handle        = 0x88980087
	MILERR_DEVICECANNOTRENDERTEXT                                             Handle        = 0x88980088
	MILERR_GLYPHBITMAPMISSED                                                  Handle        = 0x88980089
	MILERR_MALFORMEDGLYPHCACHE                                                Handle        = 0x8898008A
	MILERR_GENERIC_IGNORE                                                     Handle        = 0x8898008B
	MILERR_MALFORMED_GUIDELINE_DATA                                           Handle        = 0x8898008C
	MILERR_NO_HARDWARE_DEVICE                                                 Handle        = 0x8898008D
	MILERR_NEED_RECREATE_AND_PRESENT                                          Handle        = 0x8898008E
	MILERR_ALREADY_INITIALIZED                                                Handle        = 0x8898008F
	MILERR_MISMATCHED_SIZE                                                    Handle        = 0x88980090
	MILERR_NO_REDIRECTION_SURFACE_AVAILABLE                                   Handle        = 0x88980091
	MILERR_REMOTING_NOT_SUPPORTED                                             Handle        = 0x88980092
	MILERR_QUEUED_PRESENT_NOT_SUPPORTED                                       Handle        = 0x88980093
	MILERR_NOT_QUEUING_PRESENTS                                               Handle        = 0x88980094
	MILERR_NO_REDIRECTION_SURFACE_RETRY_LATER                                 Handle        = 0x88980095
	MILERR_TOOMANYSHADERELEMNTS                                               Handle        = 0x88980096
	MILERR_MROW_READLOCK_FAILED                                               Handle        = 0x88980097
	MILERR_MROW_UPDATE_FAILED                                                 Handle        = 0x88980098
	MILERR_SHADER_COMPILE_FAILED                                              Handle        = 0x88980099
	MILERR_MAX_TEXTURE_SIZE_EXCEEDED                                          Handle        = 0x8898009A
	MILERR_QPC_TIME_WENT_BACKWARD                                             Handle        = 0x8898009B
	MILERR_DXGI_ENUMERATION_OUT_OF_SYNC                                       Handle        = 0x8898009D
	MILERR_ADAPTER_NOT_FOUND                                                  Handle        = 0x8898009E
	MILERR_COLORSPACE_NOT_SUPPORTED                                           Handle        = 0x8898009F
	MILERR_PREFILTER_NOT_SUPPORTED                                            Handle        = 0x889800A0
	MILERR_DISPLAYID_ACCESS_DENIED                                            Handle        = 0x889800A1
	UCEERR_INVALIDPACKETHEADER                                                Handle        = 0x88980400
	UCEERR_UNKNOWNPACKET                                                      Handle        = 0x88980401
	UCEERR_ILLEGALPACKET                                                      Handle        = 0x88980402
	UCEERR_MALFORMEDPACKET                                                    Handle        = 0x88980403
	UCEERR_ILLEGALHANDLE                                                      Handle        = 0x88980404
	UCEERR_HANDLELOOKUPFAILED                                                 Handle        = 0x88980405
	UCEERR_RENDERTHREADFAILURE                                                Handle        = 0x88980406
	UCEERR_CTXSTACKFRSTTARGETNULL                                             Handle        = 0x88980407
	UCEERR_CONNECTIONIDLOOKUPFAILED                                           Handle        = 0x88980408
	UCEERR_BLOCKSFULL                                                         Handle        = 0x88980409
	UCEERR_MEMORYFAILURE                                                      Handle        = 0x8898040A
	UCEERR_PACKETRECORDOUTOFRANGE                                             Handle        = 0x8898040B
	UCEERR_ILLEGALRECORDTYPE                                                  Handle        = 0x8898040C
	UCEERR_OUTOFHANDLES                                                       Handle        = 0x8898040D
	UCEERR_UNCHANGABLE_UPDATE_ATTEMPTED                                       Handle        = 0x8898040E
	UCEERR_NO_MULTIPLE_WORKER_THREADS                                         Handle        = 0x8898040F
	UCEERR_REMOTINGNOTSUPPORTED                                               Handle        = 0x88980410
	UCEERR_MISSINGENDCOMMAND                                                  Handle        = 0x88980411
	UCEERR_MISSINGBEGINCOMMAND                                                Handle        = 0x88980412
	UCEERR_CHANNELSYNCTIMEDOUT                                                Handle        = 0x88980413
	UCEERR_CHANNELSYNCABANDONED                                               Handle        = 0x88980414
	UCEERR_UNSUPPORTEDTRANSPORTVERSION                                        Handle        = 0x88980415
	UCEERR_TRANSPORTUNAVAILABLE                                               Handle        = 0x88980416
	UCEERR_FEEDBACK_UNSUPPORTED                                               Handle        = 0x88980417
	UCEERR_COMMANDTRANSPORTDENIED                                             Handle        = 0x88980418
	UCEERR_GRAPHICSSTREAMUNAVAILABLE                                          Handle        = 0x88980419
	UCEERR_GRAPHICSSTREAMALREADYOPEN                                          Handle        = 0x88980420
	UCEERR_TRANSPORTDISCONNECTED                                              Handle        = 0x88980421
	UCEERR_TRANSPORTOVERLOADED                                                Handle        = 0x88980422
	UCEERR_PARTITION_ZOMBIED                                                  Handle        = 0x88980423
	MILAVERR_NOCLOCK                                                          Handle        = 0x88980500
	MILAVERR_NOMEDIATYPE                                                      Handle        = 0x88980501
	MILAVERR_NOVIDEOMIXER                                                     Handle        = 0x88980502
	MILAVERR_NOVIDEOPRESENTER                                                 Handle        = 0x88980503
	MILAVERR_NOREADYFRAMES                                                    Handle        = 0x88980504
	MILAVERR_MODULENOTLOADED                                                  Handle        = 0x88980505
	MILAVERR_WMPFACTORYNOTREGISTERED                                          Handle        = 0x88980506
	MILAVERR_INVALIDWMPVERSION                                                Handle        = 0x88980507
	MILAVERR_INSUFFICIENTVIDEORESOURCES                                       Handle        = 0x88980508
	MILAVERR_VIDEOACCELERATIONNOTAVAILABLE                                    Handle        = 0x88980509
	MILAVERR_REQUESTEDTEXTURETOOBIG                                           Handle        = 0x8898050A
	MILAVERR_SEEKFAILED                                                       Handle        = 0x8898050B
	MILAVERR_UNEXPECTEDWMPFAILURE                                             Handle        = 0x8898050C
	MILAVERR_MEDIAPLAYERCLOSED                                                Handle        = 0x8898050D
	MILAVERR_UNKNOWNHARDWAREERROR                                             Handle        = 0x8898050E
	MILEFFECTSERR_UNKNOWNPROPERTY                                             Handle        = 0x8898060E
	MILEFFECTSERR_EFFECTNOTPARTOFGROUP                                        Handle        = 0x8898060F
	MILEFFECTSERR_NOINPUTSOURCEATTACHED                                       Handle        = 0x88980610
	MILEFFECTSERR_CONNECTORNOTCONNECTED                                       Handle        = 0x88980611
	MILEFFECTSERR_CONNECTORNOTASSOCIATEDWITHEFFECT                            Handle        = 0x88980612
	MILEFFECTSERR_RESERVED                                                    Handle        = 0x88980613
	MILEFFECTSERR_CYCLEDETECTED                                               Handle        = 0x88980614
	MILEFFECTSERR_EFFECTINMORETHANONEGRAPH                                    Handle        = 0x88980615
	MILEFFECTSERR_EFFECTALREADYINAGRAPH                                       Handle        = 0x88980616
	MILEFFECTSERR_EFFECTHASNOCHILDREN                                         Handle        = 0x88980617
	MILEFFECTSERR_ALREADYATTACHEDTOLISTENER                                   Handle        = 0x88980618
	MILEFFECTSERR_NOTAFFINETRANSFORM                                          Handle        = 0x88980619
	MILEFFECTSERR_EMPTYBOUNDS                                                 Handle        = 0x8898061A
	MILEFFECTSERR_OUTPUTSIZETOOLARGE                                          Handle        = 0x8898061B
	DWMERR_STATE_TRANSITION_FAILED                                            Handle        = 0x88980700
	DWMERR_THEME_FAILED                                                       Handle        = 0x88980701
	DWMERR_CATASTROPHIC_FAILURE                                               Handle        = 0x88980702
	DCOMPOSITION_ERROR_WINDOW_ALREADY_COMPOSED                                Handle        = 0x88980800
	DCOMPOSITION_ERROR_SURFACE_BEING_RENDERED                                 Handle        = 0x88980801
	DCOMPOSITION_ERROR_SURFACE_NOT_BEING_RENDERED                             Handle        = 0x88980802
	ONL_E_INVALID_AUTHENTICATION_TARGET                                       Handle        = 0x80860001
	ONL_E_ACCESS_DENIED_BY_TOU                                                Handle        = 0x80860002
	ONL_E_INVALID_APPLICATION                                                 Handle        = 0x80860003
	ONL_E_PASSWORD_UPDATE_REQUIRED                                            Handle        = 0x80860004
	ONL_E_ACCOUNT_UPDATE_REQUIRED                                             Handle        = 0x80860005
	ONL_E_FORCESIGNIN                                                         Handle        = 0x80860006
	ONL_E_ACCOUNT_LOCKED                                                      Handle        = 0x80860007
	ONL_E_PARENTAL_CONSENT_REQUIRED                                           Handle        = 0x80860008
	ONL_E_EMAIL_VERIFICATION_REQUIRED                                         Handle        = 0x80860009
	ONL_E_ACCOUNT_SUSPENDED_COMPROIMISE                                       Handle        = 0x8086000A
	ONL_E_ACCOUNT_SUSPENDED_ABUSE                                             Handle        = 0x8086000B
	ONL_E_ACTION_REQUIRED                                                     Handle        = 0x8086000C
	ONL_CONNECTION_COUNT_LIMIT                                                Handle        = 0x8086000D
	ONL_E_CONNECTED_ACCOUNT_CAN_NOT_SIGNOUT                                   Handle        = 0x8086000E
	ONL_E_USER_AUTHENTICATION_REQUIRED                                        Handle        = 0x8086000F
	ONL_E_REQUEST_THROTTLED                                                   Handle        = 0x80860010
	FA_E_MAX_PERSISTED_ITEMS_REACHED                                          Handle        = 0x80270220
	FA_E_HOMEGROUP_NOT_AVAILABLE                                              Handle        = 0x80270222
	E_MONITOR_RESOLUTION_TOO_LOW                                              Handle        = 0x80270250
	E_ELEVATED_ACTIVATION_NOT_SUPPORTED                                       Handle        = 0x80270251
	E_UAC_DISABLED                                                            Handle        = 0x80270252
	E_FULL_ADMIN_NOT_SUPPORTED                                                Handle        = 0x80270253
	E_APPLICATION_NOT_REGISTERED                                              Handle        = 0x80270254
	E_MULTIPLE_EXTENSIONS_FOR_APPLICATION                                     Handle        = 0x80270255
	E_MULTIPLE_PACKAGES_FOR_FAMILY                                            Handle        = 0x80270256
	E_APPLICATION_MANAGER_NOT_RUNNING                                         Handle        = 0x80270257
	S_STORE_LAUNCHED_FOR_REMEDIATION                                          Handle        = 0x00270258
	S_APPLICATION_ACTIVATION_ERROR_HANDLED_BY_DIALOG                          Handle        = 0x00270259
	E_APPLICATION_ACTIVATION_TIMED_OUT                                        Handle        = 0x8027025A
	E_APPLICATION_ACTIVATION_EXEC_FAILURE                                     Handle        = 0x8027025B
	E_APPLICATION_TEMPORARY_LICENSE_ERROR                                     Handle        = 0x8027025C
	E_APPLICATION_TRIAL_LICENSE_EXPIRED                                       Handle        = 0x8027025D
	E_SKYDRIVE_ROOT_TARGET_FILE_SYSTEM_NOT_SUPPORTED                          Handle        = 0x80270260
	E_SKYDRIVE_ROOT_TARGET_OVERLAP                                            Handle        = 0x80270261
	E_SKYDRIVE_ROOT_TARGET_CANNOT_INDEX                                       Handle        = 0x80270262
	E_SKYDRIVE_FILE_NOT_UPLOADED                                              Handle        = 0x80270263
	E_SKYDRIVE_UPDATE_AVAILABILITY_FAIL                                       Handle        = 0x80270264
	E_SKYDRIVE_ROOT_TARGET_VOLUME_ROOT_NOT_SUPPORTED                          Handle        = 0x80270265
	E_SYNCENGINE_FILE_SIZE_OVER_LIMIT                                         Handle        = 0x8802B001
	E_SYNCENGINE_FILE_SIZE_EXCEEDS_REMAINING_QUOTA                            Handle        = 0x8802B002
	E_SYNCENGINE_UNSUPPORTED_FILE_NAME                                        Handle        = 0x8802B003
	E_SYNCENGINE_FOLDER_ITEM_COUNT_LIMIT_EXCEEDED                             Handle        = 0x8802B004
	E_SYNCENGINE_FILE_SYNC_PARTNER_ERROR                                      Handle        = 0x8802B005
	E_SYNCENGINE_SYNC_PAUSED_BY_SERVICE                                       Handle        = 0x8802B006
	E_SYNCENGINE_FILE_IDENTIFIER_UNKNOWN                                      Handle        = 0x8802C002
	E_SYNCENGINE_SERVICE_AUTHENTICATION_FAILED                                Handle        = 0x8802C003
	E_SYNCENGINE_UNKNOWN_SERVICE_ERROR                                        Handle        = 0x8802C004
	E_SYNCENGINE_SERVICE_RETURNED_UNEXPECTED_SIZE                             Handle        = 0x8802C005
	E_SYNCENGINE_REQUEST_BLOCKED_BY_SERVICE                                   Handle        = 0x8802C006
	E_SYNCENGINE_REQUEST_BLOCKED_DUE_TO_CLIENT_ERROR                          Handle        = 0x8802C007
	E_SYNCENGINE_FOLDER_INACCESSIBLE                                          Handle        = 0x8802D001
	E_SYNCENGINE_UNSUPPORTED_FOLDER_NAME                                      Handle        = 0x8802D002
	E_SYNCENGINE_UNSUPPORTED_MARKET                                           Handle        = 0x8802D003
	E_SYNCENGINE_PATH_LENGTH_LIMIT_EXCEEDED                                   Handle        = 0x8802D004
	E_SYNCENGINE_REMOTE_PATH_LENGTH_LIMIT_EXCEEDED                            Handle        = 0x8802D005
	E_SYNCENGINE_CLIENT_UPDATE_NEEDED                                         Handle        = 0x8802D006
	E_SYNCENGINE_PROXY_AUTHENTICATION_REQUIRED                                Handle        = 0x8802D007
	E_SYNCENGINE_STORAGE_SERVICE_PROVISIONING_FAILED                          Handle        = 0x8802D008
	E_SYNCENGINE_UNSUPPORTED_REPARSE_POINT                                    Handle        = 0x8802D009
	E_SYNCENGINE_STORAGE_SERVICE_BLOCKED                                      Handle        = 0x8802D00A
	E_SYNCENGINE_FOLDER_IN_REDIRECTION                                        Handle        = 0x8802D00B
	EAS_E_POLICY_NOT_MANAGED_BY_OS                                            Handle        = 0x80550001
	EAS_E_POLICY_COMPLIANT_WITH_ACTIONS                                       Handle        = 0x80550002
	EAS_E_REQUESTED_POLICY_NOT_ENFORCEABLE                                    Handle        = 0x80550003
	EAS_E_CURRENT_USER_HAS_BLANK_PASSWORD                                     Handle        = 0x80550004
	EAS_E_REQUESTED_POLICY_PASSWORD_EXPIRATION_INCOMPATIBLE                   Handle        = 0x80550005
	EAS_E_USER_CANNOT_CHANGE_PASSWORD                                         Handle        = 0x80550006
	EAS_E_ADMINS_HAVE_BLANK_PASSWORD                                          Handle        = 0x80550007
	EAS_E_ADMINS_CANNOT_CHANGE_PASSWORD                                       Handle        = 0x80550008
	EAS_E_LOCAL_CONTROLLED_USERS_CANNOT_CHANGE_PASSWORD                       Handle        = 0x80550009
	EAS_E_PASSWORD_POLICY_NOT_ENFORCEABLE_FOR_CONNECTED_ADMINS                Handle        = 0x8055000A
	EAS_E_CONNECTED_ADMINS_NEED_TO_CHANGE_PASSWORD                            Handle        = 0x8055000B
	EAS_E_PASSWORD_POLICY_NOT_ENFORCEABLE_FOR_CURRENT_CONNECTED_USER          Handle        = 0x8055000C
	EAS_E_CURRENT_CONNECTED_USER_NEED_TO_CHANGE_PASSWORD                      Handle        = 0x8055000D
	WEB_E_UNSUPPORTED_FORMAT                                                  Handle        = 0x83750001
	WEB_E_INVALID_XML                                                         Handle        = 0x83750002
	WEB_E_MISSING_REQUIRED_ELEMENT                                            Handle        = 0x83750003
	WEB_E_MISSING_REQUIRED_ATTRIBUTE                                          Handle        = 0x83750004
	WEB_E_UNEXPECTED_CONTENT                                                  Handle        = 0x83750005
	WEB_E_RESOURCE_TOO_LARGE                                                  Handle        = 0x83750006
	WEB_E_INVALID_JSON_STRING                                                 Handle        = 0x83750007
	WEB_E_INVALID_JSON_NUMBER                                                 Handle        = 0x83750008
	WEB_E_JSON_VALUE_NOT_FOUND                                                Handle        = 0x83750009
	HTTP_E_STATUS_UNEXPECTED                                                  Handle        = 0x80190001
	HTTP_E_STATUS_UNEXPECTED_REDIRECTION                                      Handle        = 0x80190003
	HTTP_E_STATUS_UNEXPECTED_CLIENT_ERROR                                     Handle        = 0x80190004
	HTTP_E_STATUS_UNEXPECTED_SERVER_ERROR                                     Handle        = 0x80190005
	HTTP_E_STATUS_AMBIGUOUS                                                   Handle        = 0x8019012C
	HTTP_E_STATUS_MOVED                                                       Handle        = 0x8019012D
	HTTP_E_STATUS_REDIRECT                                                    Handle        = 0x8019012E
	HTTP_E_STATUS_REDIRECT_METHOD                                             Handle        = 0x8019012F
	HTTP_E_STATUS_NOT_MODIFIED                                                Handle        = 0x80190130
	HTTP_E_STATUS_USE_PROXY                                                   Handle        = 0x80190131
	HTTP_E_STATUS_REDIRECT_KEEP_VERB                                          Handle        = 0x80190133
	HTTP_E_STATUS_BAD_REQUEST                                                 Handle        = 0x80190190
	HTTP_E_STATUS_DENIED                                                      Handle        = 0x80190191
	HTTP_E_STATUS_PAYMENT_REQ                                                 Handle        = 0x80190192
	HTTP_E_STATUS_FORBIDDEN                                                   Handle        = 0x80190193
	HTTP_E_STATUS_NOT_FOUND                                                   Handle        = 0x80190194
	HTTP_E_STATUS_BAD_METHOD                                                  Handle        = 0x80190195
	HTTP_E_STATUS_NONE_ACCEPTABLE                                             Handle        = 0x80190196
	HTTP_E_STATUS_PROXY_AUTH_REQ                                              Handle        = 0x80190197
	HTTP_E_STATUS_REQUEST_TIMEOUT                                             Handle        = 0x80190198
	HTTP_E_STATUS_CONFLICT                                                    Handle        = 0x80190199
	HTTP_E_STATUS_GONE                                                        Handle        = 0x8019019A
	HTTP_E_STATUS_LENGTH_REQUIRED                                             Handle        = 0x8019019B
	HTTP_E_STATUS_PRECOND_FAILED                                              Handle        = 0x8019019C
	HTTP_E_STATUS_REQUEST_TOO_LARGE                                           Handle        = 0x8019019D
	HTTP_E_STATUS_URI_TOO_LONG                                                Handle        = 0x8019019E
	HTTP_E_STATUS_UNSUPPORTED_MEDIA                                           Handle        = 0x8019019F
	HTTP_E_STATUS_RANGE_NOT_SATISFIABLE                                       Handle        = 0x801901A0
	HTTP_E_STATUS_EXPECTATION_FAILED                                          Handle        = 0x801901A1
	HTTP_E_STATUS_SERVER_ERROR                                                Handle        = 0x801901F4
	HTTP_E_STATUS_NOT_SUPPORTED                                               Handle        = 0x801901F5
	HTTP_E_STATUS_BAD_GATEWAY                                                 Handle        = 0x801901F6
	HTTP_E_STATUS_SERVICE_UNAVAIL                                             Handle        = 0x801901F7
	HTTP_E_STATUS_GATEWAY_TIMEOUT                                             Handle        = 0x801901F8
	HTTP_E_STATUS_VERSION_NOT_SUP                                             Handle        = 0x801901F9
	E_INVALID_PROTOCOL_OPERATION                                              Handle        = 0x83760001
	E_INVALID_PROTOCOL_FORMAT                                                 Handle        = 0x83760002
	E_PROTOCOL_EXTENSIONS_NOT_SUPPORTED                                       Handle        = 0x83760003
	E_SUBPROTOCOL_NOT_SUPPORTED                                               Handle        = 0x83760004
	E_PROTOCOL_VERSION_NOT_SUPPORTED                                          Handle        = 0x83760005
	INPUT_E_OUT_OF_ORDER                                                      Handle        = 0x80400000
	INPUT_E_REENTRANCY                                                        Handle        = 0x80400001
	INPUT_E_MULTIMODAL                                                        Handle        = 0x80400002
	INPUT_E_PACKET                                                            Handle        = 0x80400003
	INPUT_E_FRAME                                                             Handle        = 0x80400004
	INPUT_E_HISTORY                                                           Handle        = 0x80400005
	INPUT_E_DEVICE_INFO                                                       Handle        = 0x80400006
	INPUT_E_TRANSFORM                                                         Handle        = 0x80400007
	INPUT_E_DEVICE_PROPERTY                                                   Handle        = 0x80400008
	INET_E_INVALID_URL                                                        Handle        = 0x800C0002
	INET_E_NO_SESSION                                                         Handle        = 0x800C0003
	INET_E_CANNOT_CONNECT                                                     Handle        = 0x800C0004
	INET_E_RESOURCE_NOT_FOUND                                                 Handle        = 0x800C0005
	INET_E_OBJECT_NOT_FOUND                                                   Handle        = 0x800C0006
	INET_E_DATA_NOT_AVAILABLE                                                 Handle        = 0x800C0007
	INET_E_DOWNLOAD_FAILURE                                                   Handle        = 0x800C0008
	INET_E_AUTHENTICATION_REQUIRED                                            Handle        = 0x800C0009
	INET_E_NO_VALID_MEDIA                                                     Handle        = 0x800C000A
	INET_E_CONNECTION_TIMEOUT                                                 Handle        = 0x800C000B
	INET_E_INVALID_REQUEST                                                    Handle        = 0x800C000C
	INET_E_UNKNOWN_PROTOCOL                                                   Handle        = 0x800C000D
	INET_E_SECURITY_PROBLEM                                                   Handle        = 0x800C000E
	INET_E_CANNOT_LOAD_DATA                                                   Handle        = 0x800C000F
	INET_E_CANNOT_INSTANTIATE_OBJECT                                          Handle        = 0x800C0010
	INET_E_INVALID_CERTIFICATE                                                Handle        = 0x800C0019
	INET_E_REDIRECT_FAILED                                                    Handle        = 0x800C0014
	INET_E_REDIRECT_TO_DIR                                                    Handle        = 0x800C0015
	ERROR_DBG_CREATE_PROCESS_FAILURE_LOCKDOWN                                 Handle        = 0x80B00001
	ERROR_DBG_ATTACH_PROCESS_FAILURE_LOCKDOWN                                 Handle        = 0x80B00002
	ERROR_DBG_CONNECT_SERVER_FAILURE_LOCKDOWN                                 Handle        = 0x80B00003
	ERROR_DBG_START_SERVER_FAILURE_LOCKDOWN                                   Handle        = 0x80B00004
	ERROR_IO_PREEMPTED                                                        Handle        = 0x89010001
	JSCRIPT_E_CANTEXECUTE                                                     Handle        = 0x89020001
	WEP_E_NOT_PROVISIONED_ON_ALL_VOLUMES                                      Handle        = 0x88010001
	WEP_E_FIXED_DATA_NOT_SUPPORTED                                            Handle        = 0x88010002
	WEP_E_HARDWARE_NOT_COMPLIANT                     
"""




```