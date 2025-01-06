Response:
Let's break down the thought process for analyzing the provided Go code snippet for Windows service management.

**1. Initial Understanding & Purpose Identification:**

* **Keywords:** The package name `windows`, the file path `go/src/cmd/vendor/golang.org/x/sys/windows/service.go`, and the constants defined (starting with `SC_MANAGER_`, `SERVICE_`) immediately suggest this code interacts with the Windows Service Control Manager (SCM).
* **Copyright:**  Knowing it's from the Go standard library (or an extended package) implies it's likely a low-level interface to Windows system calls.
* **`//go:build windows`:** This confirms the platform specificity.

**2. Categorization of Content:**

* **Constants:**  The large number of `const` declarations clearly represent enumerations and bit flags used by the Windows API for service management. They categorize various aspects like:
    * Manager access rights (`SC_MANAGER_*`)
    * Service types (`SERVICE_KERNEL_DRIVER`, `SERVICE_WIN32_OWN_PROCESS`, etc.)
    * Service start modes (`SERVICE_BOOT_START`, `SERVICE_AUTO_START`, etc.)
    * Error handling (`SERVICE_ERROR_*`)
    * Service control actions (`SERVICE_CONTROL_*`)
    * Service states (`SERVICE_STOPPED`, `SERVICE_RUNNING`, etc.)
    * Actions on failure (`SC_ACTION_*`)
    * Service configuration options (`SERVICE_CONFIG_*`)
    * Service notification events (`SERVICE_NOTIFY_*`)
    * Service start reasons (`SERVICE_START_REASON_*`)
* **Types (Structs):** The `type` declarations define Go structures that mirror corresponding structures in the Windows API. These structures are used to pass data to and receive data from the Windows system calls. Examples:
    * `ENUM_SERVICE_STATUS`:  Information about a service.
    * `SERVICE_STATUS`:  The current status of a service.
    * `SERVICE_TABLE_ENTRY`:  Used for the service's main function registration.
    * `QUERY_SERVICE_CONFIG`:  Configuration details of a service.
    * `SERVICE_FAILURE_ACTIONS`: How the system should react to service failures.
* **System Calls (`//sys` comments):**  These are the crucial part. They indicate direct calls to the Windows API functions (DLL imports). The syntax `//sys functionName(...) (returnType, err error) [failretval==...] = library.WindowsFunctionName` is a special Go directive for generating system call wrappers.

**3. Deduction of Functionality:**

Based on the constants, types, and system calls, we can infer the core functionalities provided by this code:

* **Service Management:** Creating, opening, deleting, starting, stopping, pausing, and continuing services.
* **Service Configuration:** Modifying various service settings like start type, error control, description, failure actions, dependencies, etc.
* **Service Status Monitoring:** Querying the current status of a service, including its state, exit codes, and control acceptance.
* **Service Enumeration:** Listing services on the system.
* **Service Control Handling:** Implementing the logic for a service to respond to control requests (stop, pause, etc.).
* **Service Notifications:**  Registering for notifications about service state changes.
* **Service Locking:** Managing exclusive access to the service control manager database.

**4. Go Code Examples (Illustrative):**

At this point, I'd start thinking about how to use these functions. The system calls provide the low-level interface. Higher-level functions would likely be built on top of these. The provided example scenarios for creating, starting, and stopping a service are good illustrations of how these underlying functions might be used. Key steps in constructing the examples:

* **Identify the necessary system calls:** For creating a service, `OpenSCManager` and `CreateService` are essential. For starting, `OpenService` and `StartService`. For stopping, `OpenService` and `ControlService`.
* **Figure out the necessary data structures:**  The constants and types provide the structure for the arguments. For `CreateService`, you need a service name, display name, type, start type, etc.
* **Handle errors:** System calls return errors, so error checking is crucial.
* **Memory management (implicitly handled by `syscall` but important to be aware of):**  String conversions to `*uint16` are often needed for Windows API calls.

**5. Command-Line Parameter Handling (Thinking Ahead):**

While the provided code *itself* doesn't handle command-line arguments, it's often used *by* programs that *do*. A typical service application would use libraries built on top of this code and would need to parse command-line arguments to determine actions like "install," "uninstall," or just to run the service. This is where thinking about the broader context comes in.

**6. Common Mistakes:**

Consider what could go wrong when using these low-level functions:

* **Incorrect permissions:**  Operations like creating or starting services require administrator privileges.
* **Incorrect constants:** Using the wrong service type or start type can lead to unexpected behavior.
* **Resource leaks (less common in modern Go due to garbage collection, but still conceptually important for handles):** Forgetting to close handles obtained from `OpenSCManager` or `OpenService`.
* **Error handling:** Ignoring errors returned by the system calls.
* **String encoding:**  Windows APIs often use UTF-16 (represented as `*uint16` in Go). Incorrect string conversions can cause problems.

**7. Refinement and Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, covering:

* Functionality: Summarize the capabilities.
* Go Functionality Implementation: Provide illustrative Go code examples.
* Code Reasoning (Input/Output): Explain what the example code does.
* Command-Line Arguments: Discuss the *typical* use case in service applications.
* Common Mistakes: List potential pitfalls.

This systematic approach of identifying keywords, categorizing content, deducing functionality, creating examples, and considering potential issues helps in understanding and explaining the purpose and usage of such low-level system interface code.
这是对 Windows 服务控制管理器 (SCM) API 的 Go 语言封装。它定义了与 Windows 服务交互所需的常量、数据结构和底层系统调用。

**功能列举:**

1. **定义了访问 SCM 和服务的各种权限常量:** 例如 `SC_MANAGER_ALL_ACCESS`, `SERVICE_START`, `SERVICE_STOP` 等，用于控制对服务管理器的操作权限以及对特定服务的操作权限。
2. **定义了服务类型常量:**  例如 `SERVICE_WIN32_OWN_PROCESS`, `SERVICE_KERNEL_DRIVER` 等，用于指定服务的运行方式。
3. **定义了服务启动类型常量:** 例如 `SERVICE_AUTO_START`, `SERVICE_DEMAND_START`, `SERVICE_DISABLED` 等，用于设置服务的启动方式。
4. **定义了错误控制常量:** 例如 `SERVICE_ERROR_NORMAL`, `SERVICE_ERROR_CRITICAL` 等，用于指定服务启动失败时的处理方式。
5. **定义了服务状态常量:** 例如 `SERVICE_RUNNING`, `SERVICE_STOPPED`, `SERVICE_START_PENDING` 等，表示服务的当前状态。
6. **定义了服务控制代码常量:** 例如 `SERVICE_CONTROL_STOP`, `SERVICE_CONTROL_PAUSE`, `SERVICE_CONTROL_INTERROGATE` 等，用于向服务发送控制命令。
7. **定义了服务接受的控制代码常量:** 例如 `SERVICE_ACCEPT_STOP`, `SERVICE_ACCEPT_PAUSE_CONTINUE` 等，用于指定服务可以处理哪些控制命令。
8. **定义了服务失败操作类型常量:** 例如 `SC_ACTION_RESTART`, `SC_ACTION_REBOOT` 等，用于配置服务失败后应该执行的操作。
9. **定义了各种数据结构:**  例如 `ENUM_SERVICE_STATUS`, `SERVICE_STATUS`, `QUERY_SERVICE_CONFIG` 等，这些结构体映射了 Windows API 中用于传递服务信息的结构。
10. **声明了与 Windows SCM API 对应的系统调用函数:** 使用 `//sys` 注释，例如 `OpenSCManager`, `CreateService`, `StartService`, `ControlService` 等，这些函数是 Go 程序直接调用 Windows API 的桥梁。

**它是什么 Go 语言功能的实现：**

这个文件实现了 Go 语言与 Windows 服务控制管理器交互的功能。它提供了一种在 Go 程序中创建、管理和监控 Windows 服务的底层接口。它使用了 Go 的 `syscall` 包来直接调用 Windows API。

**Go 代码举例说明:**

假设我们想创建一个简单的 Windows 服务。以下代码片段展示了如何使用该文件中的常量和系统调用来创建一个服务：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	serviceName := "MyGoService"
	displayName := "My Go Service"
	binaryPath := `C:\path\to\your\service.exe` // 替换为你的服务可执行文件路径

	// 打开服务控制管理器
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		fmt.Printf("OpenSCManager error: %v\n", err)
		return
	}
	defer windows.CloseServiceHandle(scm)

	// 创建服务
	service, err := windows.CreateService(
		scm,
		syscall.StringToUTF16Ptr(serviceName),
		syscall.StringToUTF16Ptr(displayName),
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_WIN32_OWN_PROCESS,
		windows.SERVICE_AUTO_START,
		windows.SERVICE_ERROR_NORMAL,
		syscall.StringToUTF16Ptr(binaryPath),
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	if err != nil {
		fmt.Printf("CreateService error: %v\n", err)
		return
	}
	defer windows.CloseServiceHandle(service)

	fmt.Println("Service created successfully.")
}
```

**假设的输入与输出:**

* **输入 (通过代码设置):**
    * `serviceName`: "MyGoService"
    * `displayName`: "My Go Service"
    * `binaryPath`: "C:\path\to\your\service.exe"
* **输出 (成功情况下):**
    * 在 Windows 服务管理器中可以看到名为 "My Go Service" 的服务，其服务名称为 "MyGoService"，启动类型为自动。
    * 控制台输出 "Service created successfully."

**命令行参数的具体处理:**

该文件本身并不直接处理命令行参数。命令行参数的处理通常发生在服务应用程序的主逻辑中。但是，这个文件提供的功能是创建和管理服务的基础，因此服务应用程序可能会使用这个文件提供的函数来实现安装、卸载或启动服务的命令行操作。

例如，一个服务应用程序可能会包含以下逻辑：

```go
package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

const serviceName = "MyGoService"
const displayName = "My Go Service"
const binaryPath = `C:\path\to\your\service.exe` // 需要根据实际情况修改

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			err := installService()
			if err != nil {
				fmt.Println("安装服务失败:", err)
				os.Exit(1)
			}
			fmt.Println("服务安装成功。")
		case "uninstall":
			err := uninstallService()
			if err != nil {
				fmt.Println("卸载服务失败:", err)
				os.Exit(1)
			}
			fmt.Println("服务卸载成功。")
		case "start":
			err := startService()
			if err != nil {
				fmt.Println("启动服务失败:", err)
				os.Exit(1)
			}
			fmt.Println("服务启动成功。")
		case "stop":
			err := stopService()
			if err != nil {
				fmt.Println("停止服务失败:", err)
				os.Exit(1)
			}
			fmt.Println("服务停止成功。")
		default:
			fmt.Println("用法: [install|uninstall|start|stop]")
			os.Exit(1)
		}
		return
	}

	// 服务主逻辑
	fmt.Println("服务正在运行...")
	// ... 你的服务逻辑 ...
}

func installService() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)

	service, err := windows.CreateService(
		scm,
		syscall.StringToUTF16Ptr(serviceName),
		syscall.StringToUTF16Ptr(displayName),
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_WIN32_OWN_PROCESS,
		windows.SERVICE_AUTO_START,
		windows.SERVICE_ERROR_NORMAL,
		syscall.StringToUTF16Ptr(binaryPath),
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)
	return nil
}

func uninstallService() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)

	service, err := windows.OpenService(scm, syscall.StringToUTF16Ptr(serviceName), windows.SERVICE_STOP | windows.DELETE)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)

	_, err = windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &windows.SERVICE_STATUS{})
	if err != nil {
		// 忽略服务可能已经停止的错误
		if err != syscall.ERROR_SERVICE_NOT_ACTIVE {
			return err
		}
	}

	err = windows.DeleteService(service)
	return err
}

func startService() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)

	service, err := windows.OpenService(scm, syscall.StringToUTF16Ptr(serviceName), windows.SERVICE_START)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)

	return windows.StartService(service, 0, nil)
}

func stopService() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)

	service, err := windows.OpenService(scm, syscall.StringToUTF16Ptr(serviceName), windows.SERVICE_STOP)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)

	_, err = windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &windows.SERVICE_STATUS{})
	return err
}
```

在这个例子中，服务应用程序会根据命令行参数 `install`, `uninstall`, `start`, `stop` 调用相应的服务管理函数。

**使用者易犯错的点:**

1. **权限不足:**  创建、修改或删除服务通常需要管理员权限。如果程序没有以管理员身份运行，相关的系统调用会失败并返回权限错误。

   **示例:**  尝试在非管理员权限下运行上面创建服务的示例代码，`OpenSCManager` 或 `CreateService` 会返回错误。

2. **路径错误:**  在创建服务时，提供的可执行文件路径 (`binaryPathName`) 必须是正确的，否则服务启动会失败。

   **示例:** 如果 `binaryPath` 指向一个不存在的文件，服务创建成功后，尝试启动该服务会失败，并在系统事件查看器中记录错误。

3. **忘记关闭句柄:**  使用 `OpenSCManager` 或 `OpenService` 获取的句柄需要使用 `CloseServiceHandle` 关闭，否则可能导致资源泄漏。虽然 Go 的垃圾回收最终会回收资源，但及时关闭句柄是一个良好的编程习惯。

4. **字符串编码问题:** Windows API 通常使用 UTF-16 编码的字符串。在 Go 中，需要使用 `syscall.StringToUTF16Ptr` 将 Go 的 `string` 转换为 Windows API 可以接受的 `*uint16` 类型。忘记进行此转换或转换错误会导致 API 调用失败。

   **示例:**  直接将 Go 的 `string` 传递给需要 `*uint16` 的参数，会导致程序崩溃或 API 调用失败。

5. **错误处理不当:**  系统调用可能会返回错误，应该检查错误并进行适当的处理，而不是忽略它们。

   **示例:**  在上面的代码示例中，如果 `OpenSCManager` 返回错误，程序应该打印错误信息并退出，而不是继续执行后续操作。

6. **服务名称冲突:**  尝试创建已存在的服务名称的服务会失败。

   **示例:**  如果已经存在一个名为 "MyGoService" 的服务，再次运行创建服务的代码会返回错误。

理解和正确使用这些常量、数据结构和系统调用对于编写可靠的 Windows 服务管理程序至关重要。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/service.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package windows

const (
	SC_MANAGER_CONNECT            = 1
	SC_MANAGER_CREATE_SERVICE     = 2
	SC_MANAGER_ENUMERATE_SERVICE  = 4
	SC_MANAGER_LOCK               = 8
	SC_MANAGER_QUERY_LOCK_STATUS  = 16
	SC_MANAGER_MODIFY_BOOT_CONFIG = 32
	SC_MANAGER_ALL_ACCESS         = 0xf003f
)

const (
	SERVICE_KERNEL_DRIVER       = 1
	SERVICE_FILE_SYSTEM_DRIVER  = 2
	SERVICE_ADAPTER             = 4
	SERVICE_RECOGNIZER_DRIVER   = 8
	SERVICE_WIN32_OWN_PROCESS   = 16
	SERVICE_WIN32_SHARE_PROCESS = 32
	SERVICE_WIN32               = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS
	SERVICE_INTERACTIVE_PROCESS = 256
	SERVICE_DRIVER              = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER
	SERVICE_TYPE_ALL            = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS

	SERVICE_BOOT_START   = 0
	SERVICE_SYSTEM_START = 1
	SERVICE_AUTO_START   = 2
	SERVICE_DEMAND_START = 3
	SERVICE_DISABLED     = 4

	SERVICE_ERROR_IGNORE   = 0
	SERVICE_ERROR_NORMAL   = 1
	SERVICE_ERROR_SEVERE   = 2
	SERVICE_ERROR_CRITICAL = 3

	SC_STATUS_PROCESS_INFO = 0

	SC_ACTION_NONE        = 0
	SC_ACTION_RESTART     = 1
	SC_ACTION_REBOOT      = 2
	SC_ACTION_RUN_COMMAND = 3

	SERVICE_STOPPED          = 1
	SERVICE_START_PENDING    = 2
	SERVICE_STOP_PENDING     = 3
	SERVICE_RUNNING          = 4
	SERVICE_CONTINUE_PENDING = 5
	SERVICE_PAUSE_PENDING    = 6
	SERVICE_PAUSED           = 7
	SERVICE_NO_CHANGE        = 0xffffffff

	SERVICE_ACCEPT_STOP                  = 1
	SERVICE_ACCEPT_PAUSE_CONTINUE        = 2
	SERVICE_ACCEPT_SHUTDOWN              = 4
	SERVICE_ACCEPT_PARAMCHANGE           = 8
	SERVICE_ACCEPT_NETBINDCHANGE         = 16
	SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 32
	SERVICE_ACCEPT_POWEREVENT            = 64
	SERVICE_ACCEPT_SESSIONCHANGE         = 128
	SERVICE_ACCEPT_PRESHUTDOWN           = 256

	SERVICE_CONTROL_STOP                  = 1
	SERVICE_CONTROL_PAUSE                 = 2
	SERVICE_CONTROL_CONTINUE              = 3
	SERVICE_CONTROL_INTERROGATE           = 4
	SERVICE_CONTROL_SHUTDOWN              = 5
	SERVICE_CONTROL_PARAMCHANGE           = 6
	SERVICE_CONTROL_NETBINDADD            = 7
	SERVICE_CONTROL_NETBINDREMOVE         = 8
	SERVICE_CONTROL_NETBINDENABLE         = 9
	SERVICE_CONTROL_NETBINDDISABLE        = 10
	SERVICE_CONTROL_DEVICEEVENT           = 11
	SERVICE_CONTROL_HARDWAREPROFILECHANGE = 12
	SERVICE_CONTROL_POWEREVENT            = 13
	SERVICE_CONTROL_SESSIONCHANGE         = 14
	SERVICE_CONTROL_PRESHUTDOWN           = 15

	SERVICE_ACTIVE    = 1
	SERVICE_INACTIVE  = 2
	SERVICE_STATE_ALL = 3

	SERVICE_QUERY_CONFIG         = 1
	SERVICE_CHANGE_CONFIG        = 2
	SERVICE_QUERY_STATUS         = 4
	SERVICE_ENUMERATE_DEPENDENTS = 8
	SERVICE_START                = 16
	SERVICE_STOP                 = 32
	SERVICE_PAUSE_CONTINUE       = 64
	SERVICE_INTERROGATE          = 128
	SERVICE_USER_DEFINED_CONTROL = 256
	SERVICE_ALL_ACCESS           = STANDARD_RIGHTS_REQUIRED | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL

	SERVICE_RUNS_IN_SYSTEM_PROCESS = 1

	SERVICE_CONFIG_DESCRIPTION              = 1
	SERVICE_CONFIG_FAILURE_ACTIONS          = 2
	SERVICE_CONFIG_DELAYED_AUTO_START_INFO  = 3
	SERVICE_CONFIG_FAILURE_ACTIONS_FLAG     = 4
	SERVICE_CONFIG_SERVICE_SID_INFO         = 5
	SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6
	SERVICE_CONFIG_PRESHUTDOWN_INFO         = 7
	SERVICE_CONFIG_TRIGGER_INFO             = 8
	SERVICE_CONFIG_PREFERRED_NODE           = 9
	SERVICE_CONFIG_LAUNCH_PROTECTED         = 12

	SERVICE_SID_TYPE_NONE         = 0
	SERVICE_SID_TYPE_UNRESTRICTED = 1
	SERVICE_SID_TYPE_RESTRICTED   = 2 | SERVICE_SID_TYPE_UNRESTRICTED

	SC_ENUM_PROCESS_INFO = 0

	SERVICE_NOTIFY_STATUS_CHANGE    = 2
	SERVICE_NOTIFY_STOPPED          = 0x00000001
	SERVICE_NOTIFY_START_PENDING    = 0x00000002
	SERVICE_NOTIFY_STOP_PENDING     = 0x00000004
	SERVICE_NOTIFY_RUNNING          = 0x00000008
	SERVICE_NOTIFY_CONTINUE_PENDING = 0x00000010
	SERVICE_NOTIFY_PAUSE_PENDING    = 0x00000020
	SERVICE_NOTIFY_PAUSED           = 0x00000040
	SERVICE_NOTIFY_CREATED          = 0x00000080
	SERVICE_NOTIFY_DELETED          = 0x00000100
	SERVICE_NOTIFY_DELETE_PENDING   = 0x00000200

	SC_EVENT_DATABASE_CHANGE = 0
	SC_EVENT_PROPERTY_CHANGE = 1
	SC_EVENT_STATUS_CHANGE   = 2

	SERVICE_START_REASON_DEMAND             = 0x00000001
	SERVICE_START_REASON_AUTO               = 0x00000002
	SERVICE_START_REASON_TRIGGER            = 0x00000004
	SERVICE_START_REASON_RESTART_ON_FAILURE = 0x00000008
	SERVICE_START_REASON_DELAYEDAUTO        = 0x00000010

	SERVICE_DYNAMIC_INFORMATION_LEVEL_START_REASON = 1
)

type ENUM_SERVICE_STATUS struct {
	ServiceName   *uint16
	DisplayName   *uint16
	ServiceStatus SERVICE_STATUS
}

type SERVICE_STATUS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type SERVICE_TABLE_ENTRY struct {
	ServiceName *uint16
	ServiceProc uintptr
}

type QUERY_SERVICE_CONFIG struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *uint16
	LoadOrderGroup   *uint16
	TagId            uint32
	Dependencies     *uint16
	ServiceStartName *uint16
	DisplayName      *uint16
}

type SERVICE_DESCRIPTION struct {
	Description *uint16
}

type SERVICE_DELAYED_AUTO_START_INFO struct {
	IsDelayedAutoStartUp uint32
}

type SERVICE_STATUS_PROCESS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessId               uint32
	ServiceFlags            uint32
}

type ENUM_SERVICE_STATUS_PROCESS struct {
	ServiceName          *uint16
	DisplayName          *uint16
	ServiceStatusProcess SERVICE_STATUS_PROCESS
}

type SERVICE_NOTIFY struct {
	Version               uint32
	NotifyCallback        uintptr
	Context               uintptr
	NotificationStatus    uint32
	ServiceStatus         SERVICE_STATUS_PROCESS
	NotificationTriggered uint32
	ServiceNames          *uint16
}

type SERVICE_FAILURE_ACTIONS struct {
	ResetPeriod  uint32
	RebootMsg    *uint16
	Command      *uint16
	ActionsCount uint32
	Actions      *SC_ACTION
}

type SERVICE_FAILURE_ACTIONS_FLAG struct {
	FailureActionsOnNonCrashFailures int32
}

type SC_ACTION struct {
	Type  uint32
	Delay uint32
}

type QUERY_SERVICE_LOCK_STATUS struct {
	IsLocked     uint32
	LockOwner    *uint16
	LockDuration uint32
}

//sys	OpenSCManager(machineName *uint16, databaseName *uint16, access uint32) (handle Handle, err error) [failretval==0] = advapi32.OpenSCManagerW
//sys	CloseServiceHandle(handle Handle) (err error) = advapi32.CloseServiceHandle
//sys	CreateService(mgr Handle, serviceName *uint16, displayName *uint16, access uint32, srvType uint32, startType uint32, errCtl uint32, pathName *uint16, loadOrderGroup *uint16, tagId *uint32, dependencies *uint16, serviceStartName *uint16, password *uint16) (handle Handle, err error) [failretval==0] = advapi32.CreateServiceW
//sys	OpenService(mgr Handle, serviceName *uint16, access uint32) (handle Handle, err error) [failretval==0] = advapi32.OpenServiceW
//sys	DeleteService(service Handle) (err error) = advapi32.DeleteService
//sys	StartService(service Handle, numArgs uint32, argVectors **uint16) (err error) = advapi32.StartServiceW
//sys	QueryServiceStatus(service Handle, status *SERVICE_STATUS) (err error) = advapi32.QueryServiceStatus
//sys	QueryServiceLockStatus(mgr Handle, lockStatus *QUERY_SERVICE_LOCK_STATUS, bufSize uint32, bytesNeeded *uint32) (err error) = advapi32.QueryServiceLockStatusW
//sys	ControlService(service Handle, control uint32, status *SERVICE_STATUS) (err error) = advapi32.ControlService
//sys	StartServiceCtrlDispatcher(serviceTable *SERVICE_TABLE_ENTRY) (err error) = advapi32.StartServiceCtrlDispatcherW
//sys	SetServiceStatus(service Handle, serviceStatus *SERVICE_STATUS) (err error) = advapi32.SetServiceStatus
//sys	ChangeServiceConfig(service Handle, serviceType uint32, startType uint32, errorControl uint32, binaryPathName *uint16, loadOrderGroup *uint16, tagId *uint32, dependencies *uint16, serviceStartName *uint16, password *uint16, displayName *uint16) (err error) = advapi32.ChangeServiceConfigW
//sys	QueryServiceConfig(service Handle, serviceConfig *QUERY_SERVICE_CONFIG, bufSize uint32, bytesNeeded *uint32) (err error) = advapi32.QueryServiceConfigW
//sys	ChangeServiceConfig2(service Handle, infoLevel uint32, info *byte) (err error) = advapi32.ChangeServiceConfig2W
//sys	QueryServiceConfig2(service Handle, infoLevel uint32, buff *byte, buffSize uint32, bytesNeeded *uint32) (err error) = advapi32.QueryServiceConfig2W
//sys	EnumServicesStatusEx(mgr Handle, infoLevel uint32, serviceType uint32, serviceState uint32, services *byte, bufSize uint32, bytesNeeded *uint32, servicesReturned *uint32, resumeHandle *uint32, groupName *uint16) (err error) = advapi32.EnumServicesStatusExW
//sys	QueryServiceStatusEx(service Handle, infoLevel uint32, buff *byte, buffSize uint32, bytesNeeded *uint32) (err error) = advapi32.QueryServiceStatusEx
//sys	NotifyServiceStatusChange(service Handle, notifyMask uint32, notifier *SERVICE_NOTIFY) (ret error) = advapi32.NotifyServiceStatusChangeW
//sys	SubscribeServiceChangeNotifications(service Handle, eventType uint32, callback uintptr, callbackCtx uintptr, subscription *uintptr) (ret error) = sechost.SubscribeServiceChangeNotifications?
//sys	UnsubscribeServiceChangeNotifications(subscription uintptr) = sechost.UnsubscribeServiceChangeNotifications?
//sys	RegisterServiceCtrlHandlerEx(serviceName *uint16, handlerProc uintptr, context uintptr) (handle Handle, err error) = advapi32.RegisterServiceCtrlHandlerExW
//sys	QueryServiceDynamicInformation(service Handle, infoLevel uint32, dynamicInfo unsafe.Pointer) (err error) = advapi32.QueryServiceDynamicInformation?
//sys	EnumDependentServices(service Handle, activityState uint32, services *ENUM_SERVICE_STATUS, buffSize uint32, bytesNeeded *uint32, servicesReturned *uint32) (err error) = advapi32.EnumDependentServicesW

"""



```