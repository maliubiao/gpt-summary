Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Observation & Keyword Scan:**

The first thing that jumps out is the sheer volume of constants being defined. A quick scan reveals patterns:

*  `BJ_E_FIRST`, `OLEOBJ_E_LAST`, etc.: These look like the start and end of ranges for error codes.
*  `syscall.Errno`:  This immediately suggests these constants are related to system-level errors. The `syscall` package in Go deals with low-level operating system interactions.
*  `Handle = 0x...`:  This indicates that many of these constants are assigned hexadecimal values, and often have the name `Handle`. This is a strong hint that they represent specific error codes or status codes in the Windows API.
*  Groups of constants with similar prefixes (e.g., `OLEOBJ_E_`, `CLIENTSITE_E_`, `INPLACE_E_`). This suggests organization by functional area or component within Windows.

**2. Formulating the Core Function:**

Based on the `syscall.Errno` type and the naming conventions, the primary function of this code is clearly: **Defining a large set of Windows-specific error codes.**  These are likely used to provide more specific error information than the generic error types in Go's standard library.

**3. Inferring the Broader Context:**

Knowing the file path `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` provides crucial context:

*  `golang.org/x/sys/windows`: This signifies that the code is part of the Go extended system library specifically for Windows. It's not part of the core `syscall` package but a supplementary set of Windows-related functionalities.
*  `vendor`: This usually means the code is a vendored dependency, suggesting it might be generated or copied from another source (like the Windows SDK).
*  `cmd`: This might indicate that these error codes are used by other Go commands or tools that interact with Windows.

**4. Reasoning about the "Why":**

Why would Go need so many specific Windows error codes?

* **Interoperability:** When interacting with the Windows API, Go programs need a way to understand and report the specific errors returned by Windows functions. Generic error codes aren't enough for debugging or providing detailed feedback to the user.
* **Error Handling:** Go's error handling relies on comparing error values. Having these constants allows for specific error checks like `if err == windows.OLEOBJ_E_NOVERBS { ... }`.
* **Completeness:** To provide a comprehensive interface to the Windows API, the Go `sys` package needs to represent the possible error scenarios.

**5. Constructing the Go Code Example:**

To illustrate the usage, I need a scenario where a Windows API call might return one of these specific errors. Object Linking and Embedding (OLE) is a good candidate given the presence of `OLEOBJ_E_` constants. A hypothetical function attempting to interact with an OLE object that has no available verbs (actions) makes sense. This leads to the example code structure:

```go
package main

import (
	"fmt"
	"syscall"
	"golang.org/x/sys/windows" // Important: Using the correct package
)

func someWindowsAPICall() error {
	// ... (Simulate a Windows API call that might return an OLE error) ...
	return windows.OLEOBJ_E_NOVERBS // Simulate the specific error
}

func main() {
	err := someWindowsAPICall()
	if err != nil {
		if err == windows.OLEOBJ_E_NOVERBS {
			fmt.Println("Error: The OLE object has no available verbs.")
		} else {
			fmt.Printf("An unexpected error occurred: %v\n", err)
		}
	}
}
```

**6. Considering Common Mistakes:**

What errors might a developer make when using these constants?

* **Incorrect Package Import:**  Forgetting to import `golang.org/x/sys/windows` is a common mistake. Developers might incorrectly assume these constants are part of the standard `syscall` package.
* **Confusing `syscall.Errno` and `Handle`:** Not realizing that some constants are of type `syscall.Errno` and others are just `Handle` (which is likely an alias for `uint32` or similar). This could lead to type mismatch errors.
* **Assuming Exhaustiveness:**  While this file is large, it might not contain *every* possible Windows error code. Developers should be prepared to handle generic errors as well.

**7. Addressing Other Points (Command-line arguments, code reasoning):**

* **Command-line Arguments:**  This file defines constants, not command-line argument handling logic. So, this point is not applicable.
* **Code Reasoning with Input/Output:** The core function is about defining constants. While the *use* of these constants would involve function calls with inputs and outputs, this specific file doesn't perform that logic itself. The example code shows a *potential* output based on a *hypothetical* input (an API call returning a specific error).

**8. Summarizing the Functionality (Part 6 of 15):**

Since this is part 6 of a larger set of files, it's important to connect it to the potential purpose of the entire `zerrors_windows.go` file. The most logical conclusion is that this file provides a comprehensive mapping of Windows error codes to Go constants, enhancing error handling capabilities for Go programs interacting with the Windows operating system. The "Part 6" aspect suggests that the file is likely broken down into sections, possibly organized by different Windows subsystems or API areas.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the `syscall.Errno` part. Realizing that many are just `Handle` and that `Handle` is likely a numeric type was important.
* I also had to make sure the example code used the *correct* import path (`golang.org/x/sys/windows`), not just `syscall`.
*  Considering the "Part 6" context helped to frame the summary more accurately within the larger project.

By following this thought process, combining observation, deduction, and domain knowledge (Windows API, Go's `syscall` package), I can arrive at a comprehensive and accurate understanding of the code snippet's functionality.
好的，让我们来分析一下这段 Go 语言代码片段的功能。

**功能列举:**

1. **定义 Windows API 错误码常量:**  这段代码的主要功能是定义了大量的常量，这些常量代表了 Windows API 中各种操作可能返回的特定错误代码和成功代码。
2. **区分错误和成功:**  通过观察常量名称的命名方式，可以发现它使用了 `_E_` 表示错误 (Error)，`_S_` 表示成功 (Success)。 例如 `OLEOBJ_E_NOVERBS` 表示 OLE 对象没有动词的错误，而 `OLEOBJ_S_INVALIDVERB` 表示无效动词的成功状态。
3. **关联到 `syscall.Errno` 类型:**  一些错误码常量被定义为 `syscall.Errno` 类型。这表明这些常量可以被 Go 语言的 `syscall` 包直接识别和处理，用于表示系统调用级别的错误。
4. **定义 Handle 类型常量:**  另一些常量被定义为 `Handle` 类型（根据上下文，`Handle` 很可能是 `uintptr` 或类似的整数类型）。这些可能代表更细粒度的状态或特定的返回值，不一定是系统调用错误，但仍然是 Windows API 返回的重要信息。
5. **按功能模块组织:**  常量被按照功能模块进行分组，例如 `OLEOBJ_` 开头的与 OLE 对象相关，`CLIENTSITE_` 开头的与客户端站点相关，`INPLACE_` 开头的与原地激活相关，等等。这种组织方式提高了代码的可读性和可维护性。
6. **定义错误码范围:**  通过 `_FIRST` 和 `_LAST` 后缀的常量，定义了特定功能模块的错误码范围，例如 `OLEOBJ_E_FIRST` 和 `OLEOBJ_E_LAST` 定义了 OLE 对象错误码的起始和结束。

**推断 Go 语言功能的实现:**

这段代码是 Go 语言中与 Windows 系统交互的重要组成部分，它实现了对 Windows API 返回值的结构化表示。更具体地说，它为 Go 程序提供了便捷的方式来识别和处理来自 Windows API 的特定错误和状态。

**Go 代码举例说明:**

假设我们调用了一个 Windows API 函数来操作 OLE 对象，并且该对象没有可用的动词。

```go
package main

import (
	"fmt"
	"syscall"
	"golang.org/x/sys/windows"
)

func main() {
	// 假设 result 是调用某个 Windows API 函数的返回值，
	// 该函数尝试操作一个没有可执行动词的 OLE 对象
	result := windows.OLEOBJ_E_NOVERBS // 模拟返回了 OLEOBJ_E_NOVERBS 错误码

	if result == windows.OLEOBJ_E_NOVERBS {
		fmt.Println("错误：OLE 对象没有可用的动词。")
	} else if result == windows.OLEOBJ_S_INVALIDVERB {
		fmt.Println("成功：操作使用了无效的动词。")
	} else {
		fmt.Printf("其他结果码: 0x%x\n", result)
	}

	// 如果 result 是 syscall.Errno 类型，可以直接使用 error 处理
	var err error = result
	if err == windows.OLEOBJ_E_NOVERBS {
		fmt.Println("使用 error 接口捕获到错误：OLE 对象没有可用的动词。")
	}
}
```

**假设的输入与输出:**

* **假设的输入:**  调用一个操作 OLE 对象的 Windows API 函数，该对象没有预定义的动词。
* **可能的输出:**  程序会根据返回的常量值，打印相应的错误信息，例如 "错误：OLE 对象没有可用的动词。" 或 "使用 error 接口捕获到错误：OLE 对象没有可用的动词。"

**命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。它只是定义了一些常量。命令行参数的处理通常发生在 `main` 函数或者使用 `flag` 等包进行解析。

**使用者易犯错的点:**

1. **错误地使用 `Handle` 类型的常量作为 `error`:**  需要区分哪些常量是 `syscall.Errno` 类型（可以作为 `error` 处理），哪些是 `Handle` 类型（需要根据具体 API 的文档来理解其含义）。直接将 `Handle` 类型的常量赋值给 `error` 类型的变量可能会导致类型不匹配或无法正确进行错误处理。

   ```go
   // 错误示例
   var err error = windows.OLEOBJ_E_NOVERBS // 如果 OLEOBJ_E_NOVERBS 被定义为 Handle，这将导致类型不匹配

   // 正确示例 (如果 OLEOBJ_E_NOVERBS 被定义为 syscall.Errno)
   var err error = windows.OLEOBJ_E_NOVERBS
   if err != nil {
       // 处理错误
   }
   ```

2. **忽略成功状态:** 虽然代码中定义了 `_S_` 开头的成功状态常量，但在实际使用中，开发者可能会过于关注错误处理，而忽略对成功状态的判断，这可能导致程序逻辑错误。

**归纳一下它的功能 (第 6 部分，共 15 部分):**

作为 `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` 文件的第 6 部分，这段代码的主要功能是 **定义了与 OLE (Object Linking and Embedding), 剪贴板, Moniker, COM (Component Object Model), 事件, 触摸笔输入 (TPC), 事务 (XACT), 上下文 (CONTEXT), 以及一些 OLE 相关的成功状态码的常量**。这些常量用于表示在 Windows 系统中执行相关操作时可能遇到的特定错误和状态。考虑到这是一个大型错误码定义文件的分段，可以推测整个 `zerrors_windows.go` 文件的目标是为 Go 语言在 Windows 平台上进行系统编程提供详尽的错误码支持，方便开发者进行精确的错误识别和处理。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第6部分，共15部分，请归纳一下它的功能

"""
BJ_E_FIRST                                                            syscall.Errno = 0x80040180
	OLEOBJ_E_LAST                                                             syscall.Errno = 0x8004018F
	OLEOBJ_S_FIRST                                                            syscall.Errno = 0x00040180
	OLEOBJ_S_LAST                                                             syscall.Errno = 0x0004018F
	OLEOBJ_E_NOVERBS                                                          Handle        = 0x80040180
	OLEOBJ_E_INVALIDVERB                                                      Handle        = 0x80040181
	CLIENTSITE_E_FIRST                                                        syscall.Errno = 0x80040190
	CLIENTSITE_E_LAST                                                         syscall.Errno = 0x8004019F
	CLIENTSITE_S_FIRST                                                        syscall.Errno = 0x00040190
	CLIENTSITE_S_LAST                                                         syscall.Errno = 0x0004019F
	INPLACE_E_NOTUNDOABLE                                                     Handle        = 0x800401A0
	INPLACE_E_NOTOOLSPACE                                                     Handle        = 0x800401A1
	INPLACE_E_FIRST                                                           syscall.Errno = 0x800401A0
	INPLACE_E_LAST                                                            syscall.Errno = 0x800401AF
	INPLACE_S_FIRST                                                           syscall.Errno = 0x000401A0
	INPLACE_S_LAST                                                            syscall.Errno = 0x000401AF
	ENUM_E_FIRST                                                              syscall.Errno = 0x800401B0
	ENUM_E_LAST                                                               syscall.Errno = 0x800401BF
	ENUM_S_FIRST                                                              syscall.Errno = 0x000401B0
	ENUM_S_LAST                                                               syscall.Errno = 0x000401BF
	CONVERT10_E_FIRST                                                         syscall.Errno = 0x800401C0
	CONVERT10_E_LAST                                                          syscall.Errno = 0x800401CF
	CONVERT10_S_FIRST                                                         syscall.Errno = 0x000401C0
	CONVERT10_S_LAST                                                          syscall.Errno = 0x000401CF
	CONVERT10_E_OLESTREAM_GET                                                 Handle        = 0x800401C0
	CONVERT10_E_OLESTREAM_PUT                                                 Handle        = 0x800401C1
	CONVERT10_E_OLESTREAM_FMT                                                 Handle        = 0x800401C2
	CONVERT10_E_OLESTREAM_BITMAP_TO_DIB                                       Handle        = 0x800401C3
	CONVERT10_E_STG_FMT                                                       Handle        = 0x800401C4
	CONVERT10_E_STG_NO_STD_STREAM                                             Handle        = 0x800401C5
	CONVERT10_E_STG_DIB_TO_BITMAP                                             Handle        = 0x800401C6
	CLIPBRD_E_FIRST                                                           syscall.Errno = 0x800401D0
	CLIPBRD_E_LAST                                                            syscall.Errno = 0x800401DF
	CLIPBRD_S_FIRST                                                           syscall.Errno = 0x000401D0
	CLIPBRD_S_LAST                                                            syscall.Errno = 0x000401DF
	CLIPBRD_E_CANT_OPEN                                                       Handle        = 0x800401D0
	CLIPBRD_E_CANT_EMPTY                                                      Handle        = 0x800401D1
	CLIPBRD_E_CANT_SET                                                        Handle        = 0x800401D2
	CLIPBRD_E_BAD_DATA                                                        Handle        = 0x800401D3
	CLIPBRD_E_CANT_CLOSE                                                      Handle        = 0x800401D4
	MK_E_FIRST                                                                syscall.Errno = 0x800401E0
	MK_E_LAST                                                                 syscall.Errno = 0x800401EF
	MK_S_FIRST                                                                syscall.Errno = 0x000401E0
	MK_S_LAST                                                                 syscall.Errno = 0x000401EF
	MK_E_CONNECTMANUALLY                                                      Handle        = 0x800401E0
	MK_E_EXCEEDEDDEADLINE                                                     Handle        = 0x800401E1
	MK_E_NEEDGENERIC                                                          Handle        = 0x800401E2
	MK_E_UNAVAILABLE                                                          Handle        = 0x800401E3
	MK_E_SYNTAX                                                               Handle        = 0x800401E4
	MK_E_NOOBJECT                                                             Handle        = 0x800401E5
	MK_E_INVALIDEXTENSION                                                     Handle        = 0x800401E6
	MK_E_INTERMEDIATEINTERFACENOTSUPPORTED                                    Handle        = 0x800401E7
	MK_E_NOTBINDABLE                                                          Handle        = 0x800401E8
	MK_E_NOTBOUND                                                             Handle        = 0x800401E9
	MK_E_CANTOPENFILE                                                         Handle        = 0x800401EA
	MK_E_MUSTBOTHERUSER                                                       Handle        = 0x800401EB
	MK_E_NOINVERSE                                                            Handle        = 0x800401EC
	MK_E_NOSTORAGE                                                            Handle        = 0x800401ED
	MK_E_NOPREFIX                                                             Handle        = 0x800401EE
	MK_E_ENUMERATION_FAILED                                                   Handle        = 0x800401EF
	CO_E_FIRST                                                                syscall.Errno = 0x800401F0
	CO_E_LAST                                                                 syscall.Errno = 0x800401FF
	CO_S_FIRST                                                                syscall.Errno = 0x000401F0
	CO_S_LAST                                                                 syscall.Errno = 0x000401FF
	CO_E_NOTINITIALIZED                                                       Handle        = 0x800401F0
	CO_E_ALREADYINITIALIZED                                                   Handle        = 0x800401F1
	CO_E_CANTDETERMINECLASS                                                   Handle        = 0x800401F2
	CO_E_CLASSSTRING                                                          Handle        = 0x800401F3
	CO_E_IIDSTRING                                                            Handle        = 0x800401F4
	CO_E_APPNOTFOUND                                                          Handle        = 0x800401F5
	CO_E_APPSINGLEUSE                                                         Handle        = 0x800401F6
	CO_E_ERRORINAPP                                                           Handle        = 0x800401F7
	CO_E_DLLNOTFOUND                                                          Handle        = 0x800401F8
	CO_E_ERRORINDLL                                                           Handle        = 0x800401F9
	CO_E_WRONGOSFORAPP                                                        Handle        = 0x800401FA
	CO_E_OBJNOTREG                                                            Handle        = 0x800401FB
	CO_E_OBJISREG                                                             Handle        = 0x800401FC
	CO_E_OBJNOTCONNECTED                                                      Handle        = 0x800401FD
	CO_E_APPDIDNTREG                                                          Handle        = 0x800401FE
	CO_E_RELEASED                                                             Handle        = 0x800401FF
	EVENT_E_FIRST                                                             syscall.Errno = 0x80040200
	EVENT_E_LAST                                                              syscall.Errno = 0x8004021F
	EVENT_S_FIRST                                                             syscall.Errno = 0x00040200
	EVENT_S_LAST                                                              syscall.Errno = 0x0004021F
	EVENT_S_SOME_SUBSCRIBERS_FAILED                                           Handle        = 0x00040200
	EVENT_E_ALL_SUBSCRIBERS_FAILED                                            Handle        = 0x80040201
	EVENT_S_NOSUBSCRIBERS                                                     Handle        = 0x00040202
	EVENT_E_QUERYSYNTAX                                                       Handle        = 0x80040203
	EVENT_E_QUERYFIELD                                                        Handle        = 0x80040204
	EVENT_E_INTERNALEXCEPTION                                                 Handle        = 0x80040205
	EVENT_E_INTERNALERROR                                                     Handle        = 0x80040206
	EVENT_E_INVALID_PER_USER_SID                                              Handle        = 0x80040207
	EVENT_E_USER_EXCEPTION                                                    Handle        = 0x80040208
	EVENT_E_TOO_MANY_METHODS                                                  Handle        = 0x80040209
	EVENT_E_MISSING_EVENTCLASS                                                Handle        = 0x8004020A
	EVENT_E_NOT_ALL_REMOVED                                                   Handle        = 0x8004020B
	EVENT_E_COMPLUS_NOT_INSTALLED                                             Handle        = 0x8004020C
	EVENT_E_CANT_MODIFY_OR_DELETE_UNCONFIGURED_OBJECT                         Handle        = 0x8004020D
	EVENT_E_CANT_MODIFY_OR_DELETE_CONFIGURED_OBJECT                           Handle        = 0x8004020E
	EVENT_E_INVALID_EVENT_CLASS_PARTITION                                     Handle        = 0x8004020F
	EVENT_E_PER_USER_SID_NOT_LOGGED_ON                                        Handle        = 0x80040210
	TPC_E_INVALID_PROPERTY                                                    Handle        = 0x80040241
	TPC_E_NO_DEFAULT_TABLET                                                   Handle        = 0x80040212
	TPC_E_UNKNOWN_PROPERTY                                                    Handle        = 0x8004021B
	TPC_E_INVALID_INPUT_RECT                                                  Handle        = 0x80040219
	TPC_E_INVALID_STROKE                                                      Handle        = 0x80040222
	TPC_E_INITIALIZE_FAIL                                                     Handle        = 0x80040223
	TPC_E_NOT_RELEVANT                                                        Handle        = 0x80040232
	TPC_E_INVALID_PACKET_DESCRIPTION                                          Handle        = 0x80040233
	TPC_E_RECOGNIZER_NOT_REGISTERED                                           Handle        = 0x80040235
	TPC_E_INVALID_RIGHTS                                                      Handle        = 0x80040236
	TPC_E_OUT_OF_ORDER_CALL                                                   Handle        = 0x80040237
	TPC_E_QUEUE_FULL                                                          Handle        = 0x80040238
	TPC_E_INVALID_CONFIGURATION                                               Handle        = 0x80040239
	TPC_E_INVALID_DATA_FROM_RECOGNIZER                                        Handle        = 0x8004023A
	TPC_S_TRUNCATED                                                           Handle        = 0x00040252
	TPC_S_INTERRUPTED                                                         Handle        = 0x00040253
	TPC_S_NO_DATA_TO_PROCESS                                                  Handle        = 0x00040254
	XACT_E_FIRST                                                              syscall.Errno = 0x8004D000
	XACT_E_LAST                                                               syscall.Errno = 0x8004D02B
	XACT_S_FIRST                                                              syscall.Errno = 0x0004D000
	XACT_S_LAST                                                               syscall.Errno = 0x0004D010
	XACT_E_ALREADYOTHERSINGLEPHASE                                            Handle        = 0x8004D000
	XACT_E_CANTRETAIN                                                         Handle        = 0x8004D001
	XACT_E_COMMITFAILED                                                       Handle        = 0x8004D002
	XACT_E_COMMITPREVENTED                                                    Handle        = 0x8004D003
	XACT_E_HEURISTICABORT                                                     Handle        = 0x8004D004
	XACT_E_HEURISTICCOMMIT                                                    Handle        = 0x8004D005
	XACT_E_HEURISTICDAMAGE                                                    Handle        = 0x8004D006
	XACT_E_HEURISTICDANGER                                                    Handle        = 0x8004D007
	XACT_E_ISOLATIONLEVEL                                                     Handle        = 0x8004D008
	XACT_E_NOASYNC                                                            Handle        = 0x8004D009
	XACT_E_NOENLIST                                                           Handle        = 0x8004D00A
	XACT_E_NOISORETAIN                                                        Handle        = 0x8004D00B
	XACT_E_NORESOURCE                                                         Handle        = 0x8004D00C
	XACT_E_NOTCURRENT                                                         Handle        = 0x8004D00D
	XACT_E_NOTRANSACTION                                                      Handle        = 0x8004D00E
	XACT_E_NOTSUPPORTED                                                       Handle        = 0x8004D00F
	XACT_E_UNKNOWNRMGRID                                                      Handle        = 0x8004D010
	XACT_E_WRONGSTATE                                                         Handle        = 0x8004D011
	XACT_E_WRONGUOW                                                           Handle        = 0x8004D012
	XACT_E_XTIONEXISTS                                                        Handle        = 0x8004D013
	XACT_E_NOIMPORTOBJECT                                                     Handle        = 0x8004D014
	XACT_E_INVALIDCOOKIE                                                      Handle        = 0x8004D015
	XACT_E_INDOUBT                                                            Handle        = 0x8004D016
	XACT_E_NOTIMEOUT                                                          Handle        = 0x8004D017
	XACT_E_ALREADYINPROGRESS                                                  Handle        = 0x8004D018
	XACT_E_ABORTED                                                            Handle        = 0x8004D019
	XACT_E_LOGFULL                                                            Handle        = 0x8004D01A
	XACT_E_TMNOTAVAILABLE                                                     Handle        = 0x8004D01B
	XACT_E_CONNECTION_DOWN                                                    Handle        = 0x8004D01C
	XACT_E_CONNECTION_DENIED                                                  Handle        = 0x8004D01D
	XACT_E_REENLISTTIMEOUT                                                    Handle        = 0x8004D01E
	XACT_E_TIP_CONNECT_FAILED                                                 Handle        = 0x8004D01F
	XACT_E_TIP_PROTOCOL_ERROR                                                 Handle        = 0x8004D020
	XACT_E_TIP_PULL_FAILED                                                    Handle        = 0x8004D021
	XACT_E_DEST_TMNOTAVAILABLE                                                Handle        = 0x8004D022
	XACT_E_TIP_DISABLED                                                       Handle        = 0x8004D023
	XACT_E_NETWORK_TX_DISABLED                                                Handle        = 0x8004D024
	XACT_E_PARTNER_NETWORK_TX_DISABLED                                        Handle        = 0x8004D025
	XACT_E_XA_TX_DISABLED                                                     Handle        = 0x8004D026
	XACT_E_UNABLE_TO_READ_DTC_CONFIG                                          Handle        = 0x8004D027
	XACT_E_UNABLE_TO_LOAD_DTC_PROXY                                           Handle        = 0x8004D028
	XACT_E_ABORTING                                                           Handle        = 0x8004D029
	XACT_E_PUSH_COMM_FAILURE                                                  Handle        = 0x8004D02A
	XACT_E_PULL_COMM_FAILURE                                                  Handle        = 0x8004D02B
	XACT_E_LU_TX_DISABLED                                                     Handle        = 0x8004D02C
	XACT_E_CLERKNOTFOUND                                                      Handle        = 0x8004D080
	XACT_E_CLERKEXISTS                                                        Handle        = 0x8004D081
	XACT_E_RECOVERYINPROGRESS                                                 Handle        = 0x8004D082
	XACT_E_TRANSACTIONCLOSED                                                  Handle        = 0x8004D083
	XACT_E_INVALIDLSN                                                         Handle        = 0x8004D084
	XACT_E_REPLAYREQUEST                                                      Handle        = 0x8004D085
	XACT_S_ASYNC                                                              Handle        = 0x0004D000
	XACT_S_DEFECT                                                             Handle        = 0x0004D001
	XACT_S_READONLY                                                           Handle        = 0x0004D002
	XACT_S_SOMENORETAIN                                                       Handle        = 0x0004D003
	XACT_S_OKINFORM                                                           Handle        = 0x0004D004
	XACT_S_MADECHANGESCONTENT                                                 Handle        = 0x0004D005
	XACT_S_MADECHANGESINFORM                                                  Handle        = 0x0004D006
	XACT_S_ALLNORETAIN                                                        Handle        = 0x0004D007
	XACT_S_ABORTING                                                           Handle        = 0x0004D008
	XACT_S_SINGLEPHASE                                                        Handle        = 0x0004D009
	XACT_S_LOCALLY_OK                                                         Handle        = 0x0004D00A
	XACT_S_LASTRESOURCEMANAGER                                                Handle        = 0x0004D010
	CONTEXT_E_FIRST                                                           syscall.Errno = 0x8004E000
	CONTEXT_E_LAST                                                            syscall.Errno = 0x8004E02F
	CONTEXT_S_FIRST                                                           syscall.Errno = 0x0004E000
	CONTEXT_S_LAST                                                            syscall.Errno = 0x0004E02F
	CONTEXT_E_ABORTED                                                         Handle        = 0x8004E002
	CONTEXT_E_ABORTING                                                        Handle        = 0x8004E003
	CONTEXT_E_NOCONTEXT                                                       Handle        = 0x8004E004
	CONTEXT_E_WOULD_DEADLOCK                                                  Handle        = 0x8004E005
	CONTEXT_E_SYNCH_TIMEOUT                                                   Handle        = 0x8004E006
	CONTEXT_E_OLDREF                                                          Handle        = 0x8004E007
	CONTEXT_E_ROLENOTFOUND                                                    Handle        = 0x8004E00C
	CONTEXT_E_TMNOTAVAILABLE                                                  Handle        = 0x8004E00F
	CO_E_ACTIVATIONFAILED                                                     Handle        = 0x8004E021
	CO_E_ACTIVATIONFAILED_EVENTLOGGED                                         Handle        = 0x8004E022
	CO_E_ACTIVATIONFAILED_CATALOGERROR                                        Handle        = 0x8004E023
	CO_E_ACTIVATIONFAILED_TIMEOUT                                             Handle        = 0x8004E024
	CO_E_INITIALIZATIONFAILED                                                 Handle        = 0x8004E025
	CONTEXT_E_NOJIT                                                           Handle        = 0x8004E026
	CONTEXT_E_NOTRANSACTION                                                   Handle        = 0x8004E027
	CO_E_THREADINGMODEL_CHANGED                                               Handle        = 0x8004E028
	CO_E_NOIISINTRINSICS                                                      Handle        = 0x8004E029
	CO_E_NOCOOKIES                                                            Handle        = 0x8004E02A
	CO_E_DBERROR                                                              Handle        = 0x8004E02B
	CO_E_NOTPOOLED                                                            Handle        = 0x8004E02C
	CO_E_NOTCONSTRUCTED                                                       Handle        = 0x8004E02D
	CO_E_NOSYNCHRONIZATION                                                    Handle        = 0x8004E02E
	CO_E_ISOLEVELMISMATCH                                                     Handle        = 0x8004E02F
	CO_E_CALL_OUT_OF_TX_SCOPE_NOT_ALLOWED                                     Handle        = 0x8004E030
	CO_E_EXIT_TRANSACTION_SCOPE_NOT_CALLED                                    Handle        = 0x8004E031
	OLE_S_USEREG                                                              Handle        = 0x00040000
	OLE_S_STATIC                                                              Handle        = 0x00040001
	OLE_S_MAC_CLIPFORMAT                                                      Handle        = 0x00040002
	DRAGDROP_S_DROP                                                           Handle        = 0x00040100
	DRAGDROP_S_CANCEL                                                         Handle        = 0x00040101
	DRAGDROP_S_USEDEFAULTCURSORS                                              Handle        = 0x00040102
	DATA_S_SAMEFORMATETC                                                      Handle        = 0x00040130
	VIEW_S_ALREADY_FROZEN                                                     Handle        = 0x00040140
	CACHE_S_FORMATETC_NOTSUPPORTED                                            Handle        = 0x00040170
	CACHE_S_SAMECACHE                                                         Handle        = 0x00040171
	CACHE_S_SOMECACHES_NOTUPDATED                                             Handle        = 0x00040172
	OLEOBJ_S_INVALIDVERB                                                      Handle        = 0x00040180
	OLEOBJ_S_CANNOT_DOVERB_NOW                                                Handle        = 0x00040181
	OLEOBJ_S_INVALIDHWND                                                      Handle        = 0x00040182
	INPLACE_S_TRUNCATED                                                       Handle        = 0x000401A0
	CONVERT10_S_NO_PRESENTATION                                               Handle        = 0x000401C0
	MK_S_REDUCED_TO_SELF                                                      Handle        = 0x000401E2
	MK_S_ME                                                                   Handle        = 0x000401E4
	MK_S_HIM                                                                  Handle        = 0x000401E5
	MK_S_US                                                                   Handle        = 0x000401E6
	MK_S_MONIKERALREADYREGISTERED                                             Handle        = 0x000401E7
	SCHED_S_TASK_READY                                                        Handle        = 0x00041300
	SCHED_S_TASK_RUNNING                                                      Handle        = 0x00041301
	SCHED_S_TASK_DISABLED                                                     Handle        = 0x00041302
	SCHED_S_TASK_HAS_NOT_RUN                                                  Handle        = 0x00041303
	SCHED_S_TASK_NO_MORE_RUNS                                                 Handle        = 0x00041304
	SCHED_S_TASK_NOT_SCHEDULED                                                Handle        = 0x00041305
	SCHED_S_TASK_TERMINATED                                                   Handle        = 0x00041306
	SCHED_S_TASK_NO_VALID_TRIGGERS                                            Handle        = 0x00041307
	SCHED_S_EVENT_TRIGGER                                                     Handle        = 0x00041308
	SCHED_E_TRIGGER_NOT_FOUND                                                 Handle        = 0x80041309
	SCHED_E_TASK_NOT_READY                                                    Handle        = 0x8004130A
	SCHED_E_TASK_NOT_RUNNING                                                  Handle        = 0x8004130B
	SCHED_E_SERVICE_NOT_INSTALLED                                             Handle        = 0x8004130C
	SCHED_E_CANNOT_OPEN_TASK                                                  Handle        = 0x8004130D
	SCHED_E_INVALID_TASK                                                      Handle        = 0x8004130E
	SCHED_E_ACCOUNT_INFORMATION_NOT_SET                                       Handle        = 0x8004130F
	SCHED_E_ACCOUNT_NAME_NOT_FOUND                                            Handle        = 0x80041310
	SCHED_E_ACCOUNT_DBASE_CORRUPT                                             Handle        = 0x80041311
	SCHED_E_NO_SECURITY_SERVICES                                              Handle        = 0x80041312
	SCHED_E_UNKNOWN_OBJECT_VERSION                                            Handle        = 0x80041313
	SCHED_E_UNSUPPORTED_ACCOUNT_OPTION                                        Handle        = 0x80041314
	SCHED_E_SERVICE_NOT_RUNNING                                               Handle        = 0x80041315
	SCHED_E_UNEXPECTEDNODE                                                    Handle        = 0x80041316
	SCHED_E_NAMESPACE                                                         Handle        = 0x80041317
	SCHED_E_INVALIDVALUE                                                      Handle        = 0x80041318
	SCHED_E_MISSINGNODE                                                       Handle        = 0x80041319
	SCHED_E_MALFORMEDXML                                                      Handle        = 0x8004131A
	SCHED_S_SOME_TRIGGERS_FAILED                                              Handle        = 0x0004131B
	SCHED_S_BATCH_LOGON_PROBLEM                                               Handle        = 0x0004131C
	SCHED_E_TOO_MANY_NODES                                                    Handle        = 0x8004131D
	SCHED_E_PAST_END_BOUNDARY                                                 Handle        = 0x8004131E
	SCHED_E_ALREADY_RUNNING                                                   Handle        = 0x8004131F
	SCHED_E_USER_NOT_LOGGED_ON                                                Handle        = 0x80041320
	SCHED_E_INVALID_TASK_HASH                                                 Handle        = 0x80041321
	SCHED_E_SERVICE_NOT_AVAILABLE                                             Handle        = 0x80041322
	SCHED_E_SERVICE_TOO_BUSY                                                  Handle        = 0x80041323
	SCHED_E_TASK_ATTEMPTED                                                    Handle        = 0x80041324
	SCHED_S_TASK_QUEUED                                                       Handle        = 0x00041325
	SCHED_E_TASK_DISABLED                                                     Handle        = 0x80041326
	SCHED_E_TASK_NOT_V1_COMPAT                                                Handle        = 0x80041327
	SCHED_E_START_ON_DEMAND                                                   Handle        = 0x80041328
	SCHED_E_TASK_NOT_UBPM_COMPAT                                              Handle        = 0x80041329
	SCHED_E_DEPRECATED_FEATURE_USED                                           Handle        = 0x80041330
	CO_E_CLASS_CREATE_FAILED                                                  Handle        = 0x80080001
	CO_E_SCM_ERROR                                                            Handle        = 0x80080002
	CO_E_SCM_RPC_FAILURE                                                      Handle        = 0x80080003
	CO_E_BAD_PATH                                                             Handle        = 0x80080004
	CO_E_SERVER_EXEC_FAILURE                                                  Handle        = 0x80080005
	CO_E_OBJSRV_RPC_FAILURE                                                   Handle        = 0x80080006
	MK_E_NO_NORMALIZED                                                        Handle        = 0x80080007
	CO_E_SERVER_STOPPING                                                      Handle        = 0x80080008
	MEM_E_INVALID_ROOT                                                        Handle        = 0x80080009
	MEM_E_INVALID_LINK                                                        Handle        = 0x80080010
	MEM_E_INVALID_SIZE                                                        Handle        = 0x80080011
	CO_S_NOTALLINTERFACES                                                     Handle        = 0x00080012
	CO_S_MACHINENAMENOTFOUND                                                  Handle        = 0x00080013
	CO_E_MISSING_DISPLAYNAME                                                  Handle        = 0x80080015
	CO_E_RUNAS_VALUE_MUST_BE_AAA                                              Handle        = 0x80080016
	CO_E_ELEVATION_DISABLED                                                   Handle        = 0x80080017
	APPX_E_PACKAGING_INTERNAL                                                 Handle        = 0x80080200
	APPX_E_INTERLEAVING_NOT_ALLOWED                                           Handle        = 0x80080201
	APPX_E_RELATIONSHIPS_NOT_ALLOWED                                          Handle        = 0x80080202
	APPX_E_MISSING_REQUIRED_FILE                                              Handle        = 0x80080203
	APPX_E_INVALID_MANIFEST                                                   Handle        = 0x80080204
	APPX_E_INVALID_BLOCKMAP                                                   Handle        = 0x80080205
	APPX_E_CORRUPT_CONTENT                                                    Handle        = 0x80080206
	APPX_E_BLOCK_HASH_INVALID                                                 Handle        = 0x80080207
	APPX_E_REQUESTED_RANGE_TOO_LARGE                                          Handle        = 0x80080208
	APPX_E_INVALID_SIP_CLIENT_DATA                                            Handle        = 0x80080209
	APPX_E_INVALID_KEY_INFO                                                   Handle        = 0x8008020A
	APPX_E_INVALID_CONTENTGROUPMAP                                            Handle        = 0x8008020B
	APPX_E_INVALID_APPINSTALLER                                               Handle        = 0x8008020C
	APPX_E_DELTA_BASELINE_VERSION_MISMATCH                                    Handle        = 0x8008020D
	APPX_E_DELTA_PACKAGE_MISSING_FILE                                         Handle        = 0x8008020E
	APPX_E_INVALID_DELTA_PACKAGE                                              Handle        = 0x8008020F
	APPX_E_DELTA_APPENDED_PACKAGE_NOT_ALLOWED                                 Handle        = 0x80080210
	APPX_E_INVALID_PACKAGING_LAYOUT                                           Handle        = 0x80080211
	APPX_E_INVALID_PACKAGESIGNCONFIG                                          Handle        = 0x80080212
	APPX_E_RESOURCESPRI_NOT_ALLOWED                                           Handle        = 0x80080213
	APPX_E_FILE_COMPRESSION_MISMATCH                                          Handle        = 0x80080214
	APPX_E_INVALID_PAYLOAD_PACKAGE_EXTENSION                                  Handle        = 0x80080215
	APPX_E_INVALID_ENCRYPTION_EXCLUSION_FILE_LIST                             Handle        = 0x80080216
	BT_E_SPURIOUS_ACTIVATION                                                  Handle        = 0x80080300
	DISP_E_UNKNOWNINTERFACE                                                   Handle        = 0x80020001
	DISP_E_MEMBERNOTFOUND                                                     Handle        = 0x80020003
	DISP_E_PARAMNOTFOUND                                                      Handle        = 0x80020004
	DISP_E_TYPEMISMATCH                                                       Handle        = 0x80020005
	DISP_E_UNKNOWNNAME                                                        Handle        = 0x80020006
	DISP_E_NONAMEDARGS                                                        Handle        = 0x80020007
	DISP_E_BADVARTYPE                                                         Handle        = 0x80020008
	DISP_E_EXCEPTION                                                          Handle        = 0x80020009
	DISP_E_OVERFLOW                                                           Handle        = 0x8002000A
	DISP_E_BADINDEX                                                           Handle        = 0x8002000B
	DISP_E_UNKNOWNLCID                                                        Handle        = 0x8002000C
	DISP_E_ARRAYISLOCKED                                                      Handle        = 0x8002000D
	DISP_E_BADPARAMCOUNT                                                      Handle        = 0x8002000E
	DISP_E_PARAMNOTOPTIONAL                                                   Handle        = 0x8002000F
	DISP_E_BADCALLEE                                                          Handle        = 0x80020010
	DISP_E_NOTACOLLECTION                                                     Handle        = 0x80020011
	DISP_E_DIVBYZERO                                                          Handle        = 0x80020012
	DISP_E_BUFFERTOOSMALL                                                     Handle        = 0x80020013
	TYPE_E_BUFFERTOOSMALL                                                     Handle        = 0x80028016
	TYPE_E_FIELDNOTFOUND                                                      Handle        = 0x80028017
	TYPE_E_INVDATAREAD                                                        Handle        = 0x80028018
	TYPE_E_UNSUPFORMAT                                                        Handle        = 0x80028019
	TYPE_E_REGISTRYACCESS                                                     Handle        = 0x8002801C
	TYPE_E_LIBNOTREGISTERED                                                   Handle        = 0x8002801D
	TYPE_E_UNDEFINEDTYPE                                                      Handle        = 0x80028027
	TYPE_E_QUALIFIEDNAMEDISALLOWED                                            Handle        = 0x80028028
	TYPE_E_INVALIDSTATE                                                       Handle        = 0x80028029
	TYPE_E_WRONGTYPEKIND                                                      Handle        = 0x8002802A
	TYPE_E_ELEMENTNOTFOUND                                                    Handle        = 0x8002802B
	TYPE_E_AMBIGUOUSNAME                                                      Handle        = 0x8002802C
	TYPE_E_NAMECONFLICT                                                       Handle        = 0x8002802D
	TYPE_E_UNKNOWNLCID                                                        Handle        = 0x8002802E
	TYPE_E_DLLFUNCTIONNOTFOUND                                                Handle        = 0x8002802F
	TYPE_E_BADMODULEKIND                                                      Handle        = 0x800288BD
	TYPE_E_SIZETOOBIG                                                         Handle        = 0x800288C5
	TYPE_E_DUPLICATEID                                                        Handle        = 0x800288C6
	TYPE_E_INVALIDID                                                          Handle        = 0x800288CF
	TYPE_E_TYPEMISMATCH                                                       Handle        = 0x80028CA0
	TYPE_E_OUTOFBOUNDS                                                        Handle        = 0x80028CA1
	TYPE_E_IOERROR                                                            Handle        = 0x80028CA2
	TYPE_E_CANTCREATETMPFILE                                                  Handle        = 0x80028CA3
	TYPE_E_CANTLOADLIBRARY                                                    Handle        = 0x80029C4A
	TYPE_E_INCONSISTENTPROPFUNCS                                              Handle        = 0x80029C83
	TYPE_E_CIRCULARTYPE                                                       Handle        = 0x80029C84
	STG_E_INVALIDFUNCTION                                                     Handle        = 0x80030001
	STG_E_FILENOTFOUND                                                        Handle        = 0x80030002
	STG_E_PATHNOTFOUND                                                        Handle        = 0x80030003
	STG_E_TOOMANYOPENFILES                                                    Handle        = 0x80030004
	STG_E_ACCESSDENIED                                                        Handle        = 0x80030005
	STG_E_INVALIDHANDLE                                                       Handle        = 0x80030006
	STG_E_INSUFFICIENTMEMORY                                                  Handle        = 0x80030008
	STG_E_INVALIDPOINTER                                                      Handle        = 0x80030009
	STG_E_NOMOREFILES                                                         Handle        = 0x80030012
	STG_E_DISKISWRITEPROTECTED                                                Handle        = 0x80030013
	STG_E_SEEKERROR                                                           Handle        = 0x80030019
	STG_E_WRITEFAULT                                                          Handle        = 0x8003001D
	STG_E_READFAULT                                                           Handle        = 0x8003001E
	STG_E_SHAREVIOLATION                                                      Handle        = 0x80030020
	STG_E_LOCKVIOLATION                                                       Handle        = 0x80030021
	STG_E_FILEALREADYEXISTS                                                   Handle        = 0x80030050
	STG_E_INVALIDPARAMETER                                                    Handle        = 0x80030057
	STG_E_MEDIUMFULL                                                          Handle        = 0x80030070
	STG_E_PROPSETMISMATCHED                                                   Handle        = 0x800300F0
	STG_E_ABNORMALAPIEXIT                                                     Handle        = 0x800300FA
	STG_E_INVALIDHEADER                                                       Handle        = 0x800300FB
	STG_E_INVALIDNAME                                                         Handle        = 0x800300FC
	STG_E_UNKNOWN                                                             Handle        = 0x800300FD
	STG_E_UNIMPLEMENTEDFUNCTION                                               Handle        = 0x800300FE
	STG_E_INVALIDFLAG                                                         Handle        = 0x800300FF
	STG_E_INUSE                                                               Handle        = 0x80030100
	STG_E_NOTCURRENT                                                          Handle        = 0x80030101
	STG_E_REVERTED                                                            Handle        = 0x80030102
	STG_E_CANTSAVE                                                            Handle        = 0x80030103
	STG_E_OLDFORMAT                                                           Handle        = 0x80030104
	STG_E_OLDDLL                                                              Handle        = 0x80030105
	STG_E_SHAREREQUIRED                                                       Handle        = 0x80030106
	STG_E_NOTFILEBASEDSTORAGE                                                 Handle        = 0x80030107
	STG_E_EXTANTMARSHALLINGS                                                  Handle        = 0x80030108
	STG_E_DOCFILECORRUPT                                                      Handle        = 0x80030109
	STG_E_BADBASEADDRESS                                                      Handle        = 0x80030110
	STG_E_DOCFILETOOLARGE                                                     Handle        = 0x80030111
	STG_E_NOTSIMPLEFORMAT                                                     Handle        = 0x80030112
	STG_E_INCOMPLETE                                                          Handle        = 0x80030201
	STG_E_TERMINATED                                                          Handle        = 0x80030202
	STG_S_CONVERTED                                                           Handle        = 0x00030200
	STG_S_BLOCK                                                               Handle        = 0x00030201
	STG_S_RETRYNOW                                                            Handle        = 0x00030202
	STG_S_MONITORING                                                          Handle        = 0x00030203
	STG_S_MULTIPLEOPENS                                                       Handle        = 0x00030204
	STG_S_CONSOLIDATIONFAILED                                                 Handle        = 0x00030205
	STG_S_CANNOTCONSOLIDATE                                                   Handle        = 0x00030206
	STG_S_POWER_CYCLE_REQUIRED                                                Handle        = 0x00030207
	STG_E_FIRMWARE_SLOT_INVALID                                               Handle        = 0x80030208
	STG_E_FIRMWARE_IMAGE_INVALID                                              Handle        = 0x80030209
	STG_E_DEVICE_UNRESPONSIVE                                                 Handle        = 0x8003020A
	STG_E_STATUS_COPY_PROTECTION_FAILURE                                      Handle        = 0x80030305
	STG_E_CSS_AUTHENTICATION_FAILURE                                          Handle        = 0x80030306
	STG_E_CSS_KEY_NOT_PRESENT                                                 Handle        = 0x80030307
	STG_E_CSS_KEY_NOT_ESTABLISHED                                             Handle        = 0x80030308
	STG_E_CSS_SCRAMBLED_SECTOR                                                Handle        = 0x80030309
	STG_E_CSS_REGION_MISMATCH                                                 Handle        = 0x8003030A
	STG_E_RESETS_EXHAUSTED                                                    Handle        = 0x8003030B
	RPC_E_CALL_REJECTED                                                       Handle        = 0x80010001
	RPC_E_CALL_CANCELED                                                       Handle        = 0x80010002
	RPC_E_CANTPOST_INSENDCALL                                                 Handle        = 0x80010003
	RPC_E_CANTCALLOUT_INASYNCCALL                                             Handle        = 0x80010004
	RPC_E_CANTCALLOUT_INEXTERNALCALL                                          Handle        = 0x80010005
	RPC_E_CONNECTION_TERMINATED                                               Handle        = 0x80010006
	RPC_E_SERVER_DIED                                                         Handle        = 0x80010007
	RPC_E_CLIENT_DIED                                                         Handle        = 0x80010008
	RPC_E_INVALID_DATAPACKET                                                  Handle        = 0x80010009
	RPC_E_CANTTRANSMIT_CALL                                                   Handle        = 0x8001000A
	RPC_E_CLIENT_CANTMARSHAL_DATA                                             Handle        = 0x8001000B
	RPC_E_CLIENT_CANTUNMARSHAL_DATA                                           Handle        = 0x8001000C
	RPC_E_SERVER_CANTMARSHAL_DATA                                             Handle        = 0x8001000D
	RPC_E_SERVER_CANTUNMARSHAL_DATA                                           Handle        = 0x8001000E
	RPC_E_INVALID_DATA                                                        Handle        = 0x8001000F
	RPC_E_INVALID_PARAMETER                                                   Handle        = 0x80010010
	RPC_E_CANTCALLOUT_AGAIN                                                   Handle        = 0x80010011
	RPC_E_SERVER_DIED_DNE                                                     Handle        = 0x80010012
	RPC_E_SYS_CALL_FAILED                                                     Handle        = 0x80010100
	RPC_E_OUT_OF_RESOURCES                                                    Handle        = 0x80010101
	RPC_E_ATTEMPTED_MULTITHREAD                                               Handle        = 0x80010102
	RPC_E_NOT_REGISTERED                                                      Handle        = 0x80010103
	RPC_E_FAULT                                                               Handle        = 0x80010104
	RPC_E_SERVERFAULT                                                         Handle        = 0x80010105
	RPC_E_CHANGED_MODE                                                        Handle        = 0x80010106
	RPC_E_INVALIDMETHOD                                                       Handle        = 0x80010107
	RPC_E_DISCONNECTED                                                        Handle        = 0x80010108
	RPC_E_RETRY                                                               Handle        = 0x80010109
	RPC_E_SERVERCALL_RETRYLATER                                               Handle        = 0x8001010A
	RPC_E_SERVERCALL_REJECTED                                                 Handle        = 0x8001010B
	RPC_E_INVALID_CALLDATA                                                    Handle        = 0x8001010C
	RPC_E_CANTCALLOUT_ININPUTSYNCCALL                                         Handle        = 0x8001010D
	RPC_E_WRONG_THREAD                                                        Handle        = 0x8001010E
	RPC_E_THREAD_NOT_INIT                                                     Handle        = 0x8001010F
	RPC_E_VERSION_MISMATCH                                                    Handle        = 0x80010110
	RPC_E_INVALID_HEADER                                                      Handle        = 0x80010111
	RPC_E_INVALID_EXTENSION                                                   Handle        = 0x80010112
	RPC_E_INVALID_IPID                                                        Handle        = 0x80010113
	RPC_E_INVALID_OBJECT                                                      Handle        = 0x80010114
	RPC_S_CALLPENDING                                                         Handle        = 0x80010115
	RPC_S_WAITONTIMER                                                         Handle        = 0x80010116
	RPC_E_CALL_COMPLETE                                                       Handle        = 0x80010117
	RPC_E_UNSECURE_CALL                                                       Handle        = 0x80010118
	RPC_E_TOO_LATE                                                            Handle        = 0x80010119
	RPC_E_NO_GOOD_SECURITY_PACKAGES                                           Handle        = 0x8001011A
	RPC_E_ACCESS_DENIED                                                       Handle        = 0x8001011B
	RPC_E_REMOTE_DISABLED                                                     Handle        = 0x8001011C
	RPC_E_INVALID_OBJREF                                                      Handle        = 0x8001011D
	RPC_E_NO_CONTEXT                                                          Handle        = 0x8001011E
	RPC_E_TIMEOUT                                                             Handle        = 0x8001011F
	RPC_E_NO_SYNC                                                             Handle        = 0x80010120
	RPC_E_FULLSIC_REQUIRED                                                    Handle        = 0x80010121
	RPC_E_INVALID_STD_NAME                                                    Handle        = 0x80010122
	CO_E_FAILEDTOIMPERSONATE                                                  Handle        = 0x80010123
	CO_E_FAILEDTOGETSECCTX                                                    Handle        = 0x80010124
	CO_E_FAILEDTOOPENTHREADTOKEN                                              Handle        = 0x80010125
	CO_E_FAILEDTOGETTOKENINFO                                                 Handle        = 0x80010126
	CO_E_TRUSTEEDOESNTMATCHCLIENT                                             Handle        = 0x80010127
	CO_E_FAILEDTOQUERYCLIENTBLANKET                                           Handle        = 0x80010128
	CO_E_FAILEDTOSETDACL                                                      Handle        = 0x80010129
	CO_E_ACCESSCHECKFAILED                                                    Handle        = 0x8001012A
	CO_E_NETACCESSAPIFAILED                                                   Handle        = 0x8001012B
	CO_E_WRONGTRUSTEENAMESYNTAX                                               Handle        = 0x8001012C
	CO_E_INVALIDSID                                                           Handle        = 0x8001012D
	CO_E_CONVERSIONFAILED                                                     Handle        = 0x8001012E
	CO_E_NOMATCHINGSIDFOUND                                                   Handle        = 0x8001012F
	CO_E_LOOKUPACCSIDFAILED                                                   Handle        = 0x80010130
	CO_E_NOMATCHINGNAMEFOUND                                                  Handle        = 0x80010131
	CO_E_LOOKUPACCNAMEFAILED                                                  Handle        = 0x80010132
	CO_E_SETSERLHNDLFAILED                                                    Handle        = 0x80010133
	CO_E_FAILEDTOGETWINDIR                                                    Handle        = 0x80010134
	CO_E_PATHTOOLONG                                                          Handle        = 0x80010135
	CO_E_FAILEDTOGENUUID                                                      Handle        = 0x80010136
	CO_E_FAILEDTOCREATEFILE                                                   Handle        = 0x80010137
	CO_E_FAILEDTOCLOSEHANDLE                                                  Handle        = 0x80010138
	CO_E_EXCEEDSYSACLLIMIT                                                    Handle        = 0x80010139
	CO_E_ACESINWRONGORDER                                                     Handle        = 0x8001013A
	CO_E_INCOMPATIBLESTREAMVERSION                                            Handle        = 0x8001013B
	CO_E_FAILEDTOOPENPROCESSTOKEN                                             Handle        = 0x8001013C
	CO_E_DECODEFAILED                                                         Handle        = 0x8001013D
	CO_E_ACNOTINITIALIZED                                                     Handle        = 0x8001013F
	CO_E_CANCEL_DISABLED                                                      Handle        = 0x80010140
	RPC_E_UNEXPECTED                                                          Handle        = 0x8001FFFF
	ERROR_AUDITING_DISABLED                                                   Handle        = 0xC0090001
	ERROR_ALL_SIDS_FILTERED                                                   Handle        = 0xC0090002
	ERROR_BIZRULES_NOT_ENABLED                                                Handle        = 0xC0090003
	NTE_BAD_UID                                                               Handle        = 0x80090001
	NTE_BAD_HASH                                                              Handle        = 0x80090002
	NTE_BAD_KEY                                                               Handle        = 0x80090003
	NTE_BAD_LEN                                                               Handle        = 0x80090004
	NTE_BAD_DATA                                                              Handle        = 0x80090005
	NTE_BAD_SIGNATURE                                                         Handle        = 0x80090006
	NTE_BAD_VER                                                               Handle        = 0x80090007
	NTE_BAD_ALGID                                                             Handle        = 0x80090008
	NTE_BAD_FLAGS                                                             Handle        = 0x80090009
	NTE_BAD_TYPE                                                              Handle        = 0x8009000A
	NTE_BAD_KEY_STATE                                                         Handle        = 0x8009000B
	NTE_BAD_HASH_STATE                                                        Handle        = 0x8009000C
	NTE_NO_KEY                                                                Handle        = 0x8009000D
	NTE_NO_MEMORY                                                             Handle        = 0x8009000E
	NTE_EXISTS                                                                Handle        = 0x8009000F
	NTE_PERM                                                                  Handle        = 0x80090010
	NTE_NOT_FOUND                                                             Handle        = 0x80090011
	NTE_DOUBLE_ENCRYPT                                                        Handle        = 0x80090012
	NTE_BAD_PROVIDER                                                          Handle        = 0x80090013
	NTE_BAD_PROV_TYPE                                                         Handle        = 0x80090014
	NTE_BAD_PUBLIC_KEY                                                        Handle        = 0x80090015
	NTE_BAD_KEYSET                                                            Handle        = 0x80090016
	NTE_PROV_TYPE_NOT_DEF                                                     Handle        = 0x80090017
	NTE_PROV_TYPE_ENTRY_BAD                                                   Handle        = 0x80090018
	NTE_KEYSET_NOT_DEF                                                        Handle        = 0x80090019
	NTE_KEYSET_ENTRY_BAD                                                      Handle        = 0x8009001A
	NTE_PROV_TYPE_NO_MATCH                                                    Handle        = 0x8009001B
	NTE_SIGNATURE_FILE_BAD                                                    Handle        = 0x8009001C
	NTE_PROVIDER_DLL_FAIL                                                     Handle        = 0x8009001D
	NTE_PROV_DLL_NOT_FOUND                                                    Handle        = 0x8009001E
	NTE_BAD_KEYSET_PARAM                                                      Handle        = 0x8009001F
	NTE_FAIL                                                                  Handle        = 0x80090020
	NTE_SYS_ERR                                                               Handle        = 0x80090021
	NTE_SILENT_CONTEXT                                                        Handle        = 0x80090022
	NTE_TOKEN_KEYSET_STORAGE_FULL                                             Handle        = 0x80090023
	NTE_TEMPORARY_PROFILE                                                     Handle        = 0x80090024
	NTE_FIXEDPARAMETER                                                        Handle        = 0x80090025
	NTE_INVALID_HANDLE                                                        Handle        = 0x80090026
	NTE_INVALID_PARAMETER                                                     Handle        = 0x80090027
	NTE_BUFFER_TOO_SMALL                                                      Handle        = 0x80090028
	NTE_NOT_SUPPORTED                                                         Handle        = 0x80090029
	NTE_NO_MORE_ITEMS                                                         Handle        = 0x8009002A
	NTE_BUFFERS_OVERLAP                                                       Handle        = 0x8009002B
	NTE_DECRYPTION_FAILURE                                                    Handle        = 0x8009002C
	NTE_INTERNAL_ERROR                                                        Handle        = 0x8009002D
	NTE_UI_REQUIRED                                                           Handle        = 0x8009002E
	NTE_HMAC_NOT_SUPPORTED                                                    Handle        = 0x8009002F
	NTE_DEVICE_NOT_READY                                                      Handle        = 0x80090030
	NTE_AUTHENTICATION_IGNORED                                                Handle        = 0x80090031
	NTE_VALIDATION_FAILED                                                     Handle        = 0x80090032
	NTE_INCORRECT_PASSWORD                                                    Handle        = 0x80090033
	NTE_ENCRYPTION_FAILURE                                                    Handle        = 0x80090034
	NTE_DEVICE_NOT_FOUND                                                      Handle        = 0x80090035
	NTE_USER_CANCELLED                                                        Handle        = 0x80090036
	NTE_PASSWORD_CHANGE_REQUIRED                                              Handle        = 0x80090037
	NTE_NOT_ACTIVE_CONSOLE                                                    Handle        = 0x80090038
	SEC_E_INSUFFICIENT_MEMORY                                                 Handle        = 0x80090300
	SEC_E_INVALID_HANDLE                                                      Handle        = 0x80090301
	SEC_E_UNSUPPORTED_FUNCTION                                                Handle        = 0x80090302
	SEC_E_TARGET_UNKNOWN                                                      Handle        = 0x80090303
	SEC_E_INTERNAL_ERROR                                                      Handle        = 0x80090304
	SEC_E_SECPKG_NOT_FOUND                                                    Handle        = 0x80090305
	SEC_E_NOT_OWNER                                                           Handle        = 0x80090306
	SEC_E_CANNOT_INSTALL                                                      Handle        = 0x80090307
	SEC_E_INVALID_TOKEN                                                       Handle        = 0x80090308
	SEC_E_CANNOT_PACK                                                         Handle        = 0x80090309
	SEC_E_QOP_NOT_SUPPORTED                                                   Handle        = 0x8009030A
	SEC_E_NO_IMPERSONATION                                                    Handle        = 0x8009030B
	SEC_E_LOGON_DENIED                                                        Handle        = 0x8009030C
	SEC_E_UNKNOWN_CREDENTIALS                                                 Handle        = 0x8009030D
	SEC_E_NO_CREDENTIALS                                                      Handle        = 0x8009030E
	SEC_E_MESSAGE_ALTERED                                                     Handle        = 0x8009030F
	SEC_E_OUT_OF_SEQUENCE                                                     Handle        = 0x80090310
	SEC_E_NO_AUTHENTICATING_AUTHORITY                                         Handle        = 0x80090311
	SEC_I_CONTINUE_NEEDED                                                     Handle        = 0x00090312
	SEC_I_COMPLETE_NEEDED                                                     Handle        = 0x00090313
	SEC_I_COMPLETE_AND_CONTINUE                                               Handle        = 0x00090314
	SEC_I_LOCAL_LOGON                                                         Handle        = 0x00090315
	SEC_I_GENERIC_EXTENSION_RECEIVED                                          Handle        = 0x00090316
	SEC_E_BAD_PKGID                                                           Handle        = 0x80090316
	SEC_E_CONTEXT_EXPIRED                                                     Handle        = 0x80090317
	SEC_I_CONTEXT_EXPIRED                                                     Handle        = 0x00090317
	SEC_E_INCOMPLETE_MESSAGE                                                  Handle        = 0x80090318
	SEC_E_INCOMPLETE_CREDENTIALS                                              Handle        = 0x80090320
	SEC_E_BUFFER_TOO_SMALL                                                    Handle        = 0x80090321
	SEC_I_INCOMPLETE_CREDENTIALS                                              Handle        = 0x00090320
	SEC_I_RENEGOTIATE                                                         Handle        = 0x00090321
	SEC_E_WRONG_PRINCIPAL                                                     Handle        = 0x80090322
	SEC_I_NO_LSA_CONTEXT                                                      Handle        = 0x00090323
	SEC_E_TIME_SKEW                                                           Handle        = 0x80090324
	SEC_E_UNTRUSTED_ROOT                                                      Handle        = 0x80090325
	SEC_E_ILLEGAL_MESSAGE                                                     Handle        = 0x80090326
	SEC_E_CERT_UNKNOWN                                                        Handle        = 0x80090327
	SEC_E_CERT_EXPIRED                                                        Handle        = 0x80090328
	SEC_E_ENCRYPT_FAILURE                                                     Handle        = 0x80090329
	SEC_E_DECRYPT_FAILURE                                                     Handle        = 0x80090330
	SEC_E_ALGORITHM_MISMATCH                                                  Handle        = 0x80090331
	SEC_E_SECURITY_QOS_FAILED                                                 Handle        = 0x80090332
	SEC_E_UNFINISHED_CONTEXT_DELETED                                          Handle        = 0x80090333
	SEC_E_NO_TGT_REPLY                                                        Handle        = 0x80090334
	SEC_E_NO_IP_ADDRESSES                                                     Handle        = 0x80090335
	SEC_E_WRONG_CREDENTIAL_HANDLE                                             Handle        = 0x80090336
	SEC_E_CRYPTO_SYSTEM_INVALID                                               Handle        = 0x80090337
	SEC_E_MAX_REFERRALS_EXCEEDED                                              Handle        = 0x80090338
	SEC_E_MUST_BE_KDC                                                         Handle        = 0x80090339
	SEC_E_STRONG_CRYPTO_NOT_SUPPORTED                                         Handle        = 0x8009033A
	SEC_E_TOO_MANY_PRINCIPALS                                                 Handle        = 0x8009033B
	SEC_E_NO_PA_DATA                                                          Handle        = 0x8009033C
	SEC_E_PKINIT_NAME_MISMATCH                                                Handle        = 0x8009033D
	SEC_E_SMARTCARD_LOGON_REQUIRED                                            Handle        = 0x8009033E
	SEC_E_SHUTDOWN_IN_PROGRESS                                                Handle        = 0x8009033F
	SEC_E_KDC_INVALID_REQUEST                                                 Handle        = 0x80090340
	SEC_E_KDC_UNABLE_TO_REFER                                                 Handle        = 0x80090341
	SEC_E_KDC_UNKNOWN_ETYPE                                                   Handle        = 0x80090342
	SEC_E_UNSUPPORTED_PREAUTH                                                 Handle        = 0x80090343
	SEC_E_DELEGATION_REQUIRED                                                 Handle        = 0x80090345
	SEC_E_BAD_BINDINGS                                                        Handle        = 0x80090346
	SEC_E_MULTIPLE_ACCOUNTS                                                   Handle        = 0x80090347
	SEC_E_NO_KERB_KEY                                                         Handle        = 0x80090348
	SEC_E_CERT_WRONG_USAGE                                                    Handle        = 0x80090349
	SEC_E_DOWNGRADE_DETECTED                                                  Handle        = 0x80090350
	SEC_E_SMARTCARD_CERT_REVOKED                                              Handle        = 0x80090351
	SEC_E_ISSUING_CA_UNTRUSTED                                                Handle        = 0x80090352
	SEC_E_REVOCATION_OFFLINE_C                                                Handle        = 0x80090353
	SEC_E_PKINIT_CLIENT_FAILURE                                               Handle        = 0x80090354
	SEC_E_SMARTCARD_CERT_EXPIRED                                              Handle        = 0x80090355
	SEC_E_NO_S4U_PROT_SUPPORT                                                 Handle        = 0x80090356
	SEC_E_CROSSREALM_DELEGATION_FAILURE                                       Handle        = 0x80090357
	SEC_E_REVOCATION_OFFLINE_KDC                                              Handle        = 0x80090358
	SEC_E_ISSUING_CA_UNTRUSTED_KDC                                            Handle        = 0x80090359
	SEC_E_KDC_CERT_EXPIRED                                                    Handle        = 0x8009035A
	SEC_E_KDC_CERT_REVOKED                                                    Handle        = 0x8009035B
	SEC_I_SIGNATURE_NEEDED                                                    Handle        = 0x0009035C
	SEC_E_INVALID_PARAMETER                                                   Handle        = 0x8009035D
	SEC_E_DELEGATION_POLICY                                                   Handle        = 0x8009035E
	SEC_E_POLICY_NLTM_ONLY                                                    Handle        = 0x8009035F
	SEC_I_NO_RENEGOTIATION                                  
"""




```