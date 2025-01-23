Response:
The user wants to understand the functionalities of the provided Go code snippet, which seems to be a part of Windows system type definitions.

**Plan:**

1. **Identify the main purpose:** The code primarily defines structures and constants related to Windows system calls and data structures.
2. **Categorize the structures and constants:** Group them based on their apparent functionality (e.g., networking, process management, console, file system).
3. **Explain the functionality of each category:** Describe the purpose of the structures and constants within each category.
4. **Provide Go code examples:** Illustrate how some of these structures might be used in Go for interacting with Windows APIs.
5. **Address potential errors:** Think about common mistakes when using these low-level types (though the prompt says not to if there aren't any obvious ones).
6. **Summarize the functionality:** Provide a concise overview of the code's purpose.
这是 `go/src/cmd/vendor/golang.org/x/sys/windows/types_windows.go` 文件的第二部分，延续了第一部分的内容，主要定义了用于与 Windows 系统进行底层交互的各种数据结构（`struct`）和常量（`const`）。

**功能归纳:**

这部分代码延续了第一部分的功能，继续定义了用于在 Go 语言中与 Windows 系统 API 进行交互时需要用到的各种类型定义和常量。  这些定义涵盖了更广泛的 Windows 系统功能，包括：

*   **网络适配器信息 (Continuation):**  延续了对网络适配器相关信息的定义，包括 WINS 服务器地址、网关地址和 DNS 后缀等。
*   **接口状态:** 定义了网络接口的操作状态常量，如 `IfOperStatusUp`, `IfOperStatusDown` 等。
*   **MIB (Management Information Base) 相关:** 定义了与网络管理相关的结构体和常量，例如 `MibIfRow2`（接口信息）、`MibUnicastIpAddressRow`（单播 IP 地址信息）、`MibIpInterfaceRow`（IP 接口信息）以及相关的枚举类型。这些结构体用于获取和设置网络接口的各种属性和统计信息。
*   **控制台相关:** 定义了用于控制台输入/输出模式的常量，例如 `ENABLE_PROCESSED_INPUT`, `ENABLE_VIRTUAL_TERMINAL_PROCESSING` 以及用于获取和设置控制台屏幕缓冲区信息的结构体 `ConsoleScreenBufferInfo` 和相关类型 `Coord`, `SmallRect`。
*   **Job 对象相关:** 定义了用于管理 Job 对象的结构体和常量，例如 `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` 和相关的限制标志，用于控制进程组的资源使用和行为。
*   **Known Folder (特殊文件夹) 相关:** 定义了与获取 Windows 特殊文件夹路径相关的常量，例如 `KF_FLAG_DEFAULT`。
*   **操作系统版本信息:** 定义了获取操作系统详细版本信息的结构体 `OsVersionInfoEx`。
*   **系统关机相关:** 定义了与系统关机、重启相关的常量，例如 `EWX_SHUTDOWN`, `EWX_REBOOT` 以及关机原因代码。
*   **模块句柄相关:** 定义了 `GetModuleHandleEx` 函数的标志常量，用于指定如何获取模块句柄。
*   **MUI (Multilingual User Interface) 相关:** 定义了与多语言用户界面相关的常量，用于指定语言和区域设置。
*   **文件信息相关:** 定义了用于 `SetFileInformationByHandle`/`GetFileInformationByHandleEx` 函数的 `FILE_INFO_BY_HANDLE_CLASS` 常量，用于指定要设置或获取的文件信息类型。
*   **动态链接库加载相关:** 定义了 `LoadLibrary` 函数的标志常量，用于指定加载 DLL 的方式和搜索路径。
*   **注册表更改通知:** 定义了 `RegNotifyChangeKeyValue` 函数的通知过滤器标志，用于监控注册表键值的变化。
*   **串口通信超时:** 定义了串口通信超时的结构体 `CommTimeouts`。
*   **NT Native API 相关:** 定义了与 Windows NT 内核 API 相关的字符串结构体 `NTUnicodeString`, `NTString`，以及其他底层数据结构，例如 `LIST_ENTRY`, `RUNTIME_FUNCTION`, `LDR_DATA_TABLE_ENTRY`, `PEB`（进程环境块）等。这些结构体通常用于更底层的系统编程。
*   **对象属性:** 定义了 `OBJECT_ATTRIBUTES` 结构体和相关常量，用于创建和打开内核对象时指定对象的属性。
*   **I/O 状态块:** 定义了 `IO_STATUS_BLOCK` 结构体，用于异步 I/O 操作的结果。
*   **文件创建和操作相关:** 定义了用于 `NtCreateFile` 和 `NtSetInformationFile` 等 NT API 的常量，例如文件创建方式、选项和信息类。
*   **进程信息相关:** 定义了用于查询和设置进程信息的常量和结构体，例如 `ProcessBasicInformation`, `SYSTEM_PROCESS_INFORMATION`。
*   **系统信息相关:** 定义了用于查询系统信息的常量，例如 `SystemProcessInformation`, `SystemModuleInformation`。
*   **内存管理相关:** 定义了 `LocalAlloc` 函数的标志常量，用于指定内存分配的方式。
*   **命名管道相关:** 定义了创建和操作命名管道的常量，例如管道访问模式、类型和等待模式。
*   **安全属性:** 定义了在打开命名管道时使用的安全属性常量。
*   **资源管理:** 定义了与资源相关的 `ResourceID` 类型和预定义的资源名称和类型常量，用于访问程序内部的资源。
*   **版本信息:** 定义了获取文件版本信息的结构体 `VS_FIXEDFILEINFO`。
*   **COM (Component Object Model) 相关:** 定义了与 COM 相关的结构体和常量，例如身份验证信息、服务器信息和绑定选项，用于进行跨进程或跨网络的 COM 调用。
*   **模块信息:** 定义了获取模块信息的结构体 `ModuleInfo`。
*   **处理器组:** 定义了 `ALL_PROCESSOR_GROUPS` 常量。
*   **GUI 线程信息:** 定义了获取 GUI 线程信息的结构体 `GUIThreadInfo`。
*   **DWM (Desktop Window Manager) API 相关:** 定义了与 DWM 窗口属性相关的常量，例如 `DWMWA_USE_IMMERSIVE_DARK_MODE`。
*   **Winsock (Windows Sockets) 相关:** 定义了与网络编程相关的结构体，例如 `WSAQUERYSET`（用于服务查询）、`WSAVersion`、`AFProtocols`、`CSAddrInfo` 和 `BLOB`。
*   **串口状态:** 定义了串口状态结构体 `ComStat`。
*   **DCB (Device Control Block) 相关:** 定义了串口配置结构体 `DCB`。
*   **键盘布局相关:** 定义了加载键盘布局的标志常量。

**Go 代码示例 (基于假设的应用场景):**

假设我们需要获取当前进程的基本信息，可以使用 `syscall` 包结合这些类型定义来实现：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	handle, err := syscall.GetCurrentProcess()
	if err != nil {
		fmt.Println("Error getting current process handle:", err)
		return
	}
	defer syscall.CloseHandle(handle)

	var basicInfo windows.PROCESS_BASIC_INFORMATION
	size := uint32(unsafe.Sizeof(basicInfo))
	var returnLength uint32

	r1, _, err := windows.NtQueryInformationProcess(
		handle,
		windows.ProcessBasicInformation,
		unsafe.Pointer(&basicInfo),
		size,
		&returnLength,
	)
	if r1 != 0 { // 0 表示成功，非 0 表示错误
		fmt.Printf("NtQueryInformationProcess failed with status: 0x%x, error: %v\n", r1, err)
		return
	}

	fmt.Println("Exit Status:", basicInfo.ExitStatus)
	fmt.Printf("PEB Base Address: 0x%x\n", uintptr(unsafe.Pointer(basicInfo.PebBaseAddress)))
	fmt.Printf("Affinity Mask: 0x%x\n", basicInfo.AffinityMask)
	fmt.Println("Base Priority:", basicInfo.BasePriority)
	fmt.Printf("Unique Process ID: %d\n", basicInfo.UniqueProcessId)
	fmt.Printf("Inherited From Unique Process ID: %d\n", basicInfo.InheritedFromUniqueProcessId)
}
```

**假设的输入与输出:**

*   **输入:**  运行上述 Go 程序。
*   **输出:**  类似以下的进程基本信息：

```
Exit Status: 0
PEB Base Address: 0x7ffd9000000
Affinity Mask: 0xff
Base Priority: 8
Unique Process ID: 12345
Inherited From Unique Process ID: 6789
```

**使用者易犯错的点:**

*   **结构体大小不匹配:** 在调用 Windows API 时，传递的结构体大小必须与 API 期望的大小完全一致。如果结构体定义不正确，或者使用了错误的 `unsafe.Sizeof`，可能会导致程序崩溃或返回错误的数据。
*   **Unicode 字符串处理:** 许多 Windows API 使用 Unicode 字符串（UTF-16）。在 Go 中与这些 API 交互时，需要正确地将 Go 字符串转换为 UTF-16 格式，并注意字符串的结尾符。
*   **内存管理:** 一些 Windows API 需要调用者分配和释放内存。如果忘记释放内存，可能会导致内存泄漏。
*   **错误码处理:** Windows API 通常通过返回值（`HRESULT` 或 `NTSTATUS`）来指示操作是否成功。必须仔细检查这些错误码，并采取相应的处理措施。

总的来说，这部分代码是 Go 语言 `golang.org/x/sys/windows` 库为了实现底层 Windows 系统交互而定义的基础类型集合。开发者可以通过使用这些类型和 `syscall` 包中的函数来调用 Windows API，实现更底层的系统功能。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/types_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
ss SocketAddress
}

type IpAdapterMulticastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *IpAdapterMulticastAddress
	Address SocketAddress
}

type IpAdapterDnsServerAdapter struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterDnsServerAdapter
	Address  SocketAddress
}

type IpAdapterPrefix struct {
	Length       uint32
	Flags        uint32
	Next         *IpAdapterPrefix
	Address      SocketAddress
	PrefixLength uint32
}

type IpAdapterAddresses struct {
	Length                 uint32
	IfIndex                uint32
	Next                   *IpAdapterAddresses
	AdapterName            *byte
	FirstUnicastAddress    *IpAdapterUnicastAddress
	FirstAnycastAddress    *IpAdapterAnycastAddress
	FirstMulticastAddress  *IpAdapterMulticastAddress
	FirstDnsServerAddress  *IpAdapterDnsServerAdapter
	DnsSuffix              *uint16
	Description            *uint16
	FriendlyName           *uint16
	PhysicalAddress        [syscall.MAX_ADAPTER_ADDRESS_LENGTH]byte
	PhysicalAddressLength  uint32
	Flags                  uint32
	Mtu                    uint32
	IfType                 uint32
	OperStatus             uint32
	Ipv6IfIndex            uint32
	ZoneIndices            [16]uint32
	FirstPrefix            *IpAdapterPrefix
	TransmitLinkSpeed      uint64
	ReceiveLinkSpeed       uint64
	FirstWinsServerAddress *IpAdapterWinsServerAddress
	FirstGatewayAddress    *IpAdapterGatewayAddress
	Ipv4Metric             uint32
	Ipv6Metric             uint32
	Luid                   uint64
	Dhcpv4Server           SocketAddress
	CompartmentId          uint32
	NetworkGuid            GUID
	ConnectionType         uint32
	TunnelType             uint32
	Dhcpv6Server           SocketAddress
	Dhcpv6ClientDuid       [MAX_DHCPV6_DUID_LENGTH]byte
	Dhcpv6ClientDuidLength uint32
	Dhcpv6Iaid             uint32
	FirstDnsSuffix         *IpAdapterDNSSuffix
}

type IpAdapterWinsServerAddress struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterWinsServerAddress
	Address  SocketAddress
}

type IpAdapterGatewayAddress struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterGatewayAddress
	Address  SocketAddress
}

type IpAdapterDNSSuffix struct {
	Next   *IpAdapterDNSSuffix
	String [MAX_DNS_SUFFIX_STRING_LENGTH]uint16
}

const (
	IfOperStatusUp             = 1
	IfOperStatusDown           = 2
	IfOperStatusTesting        = 3
	IfOperStatusUnknown        = 4
	IfOperStatusDormant        = 5
	IfOperStatusNotPresent     = 6
	IfOperStatusLowerLayerDown = 7
)

const (
	IF_MAX_PHYS_ADDRESS_LENGTH = 32
	IF_MAX_STRING_SIZE         = 256
)

// MIB_IF_ENTRY_LEVEL enumeration from netioapi.h or
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2ex.
const (
	MibIfEntryNormal                  = 0
	MibIfEntryNormalWithoutStatistics = 2
)

// MIB_NOTIFICATION_TYPE enumeration from netioapi.h or
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ne-netioapi-mib_notification_type.
const (
	MibParameterNotification = 0
	MibAddInstance           = 1
	MibDeleteInstance        = 2
	MibInitialNotification   = 3
)

// MibIfRow2 stores information about a particular interface. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2.
type MibIfRow2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               GUID
	Alias                       [IF_MAX_STRING_SIZE + 1]uint16
	Description                 [IF_MAX_STRING_SIZE + 1]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [IF_MAX_PHYS_ADDRESS_LENGTH]uint8
	PermanentPhysicalAddress    [IF_MAX_PHYS_ADDRESS_LENGTH]uint8
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint8
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 GUID
	ConnectionType              uint32
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

// MIB_UNICASTIPADDRESS_ROW stores information about a unicast IP address. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row.
type MibUnicastIpAddressRow struct {
	Address            RawSockaddrInet6 // SOCKADDR_INET union
	InterfaceLuid      uint64
	InterfaceIndex     uint32
	PrefixOrigin       uint32
	SuffixOrigin       uint32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       uint8
	DadState           uint32
	ScopeId            uint32
	CreationTimeStamp  Filetime
}

const ScopeLevelCount = 16

// MIB_IPINTERFACE_ROW stores interface management information for a particular IP address family on a network interface.
// See https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row.
type MibIpInterfaceRow struct {
	Family                               uint16
	InterfaceLuid                        uint64
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   uint8
	ForwardingEnabled                    uint8
	WeakHostSend                         uint8
	WeakHostReceive                      uint8
	UseAutomaticMetric                   uint8
	UseNeighborUnreachabilityDetection   uint8
	ManagedAddressConfigurationSupported uint8
	OtherStatefulConfigurationSupported  uint8
	AdvertiseDefaultRoute                uint8
	RouterDiscoveryBehavior              uint32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMtuDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             uint32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [ScopeLevelCount]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NlMtu                                uint32
	Connected                            uint8
	SupportsWakeUpPatterns               uint8
	SupportsNeighborDiscovery            uint8
	SupportsRouterDiscovery              uint8
	ReachableTime                        uint32
	TransmitOffload                      uint32
	ReceiveOffload                       uint32
	DisableDefaultRoutes                 uint8
}

// Console related constants used for the mode parameter to SetConsoleMode. See
// https://docs.microsoft.com/en-us/windows/console/setconsolemode for details.

const (
	ENABLE_PROCESSED_INPUT        = 0x1
	ENABLE_LINE_INPUT             = 0x2
	ENABLE_ECHO_INPUT             = 0x4
	ENABLE_WINDOW_INPUT           = 0x8
	ENABLE_MOUSE_INPUT            = 0x10
	ENABLE_INSERT_MODE            = 0x20
	ENABLE_QUICK_EDIT_MODE        = 0x40
	ENABLE_EXTENDED_FLAGS         = 0x80
	ENABLE_AUTO_POSITION          = 0x100
	ENABLE_VIRTUAL_TERMINAL_INPUT = 0x200

	ENABLE_PROCESSED_OUTPUT            = 0x1
	ENABLE_WRAP_AT_EOL_OUTPUT          = 0x2
	ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4
	DISABLE_NEWLINE_AUTO_RETURN        = 0x8
	ENABLE_LVB_GRID_WORLDWIDE          = 0x10
)

// Pseudo console related constants used for the flags parameter to
// CreatePseudoConsole. See: https://learn.microsoft.com/en-us/windows/console/createpseudoconsole
const (
	PSEUDOCONSOLE_INHERIT_CURSOR = 0x1
)

type Coord struct {
	X int16
	Y int16
}

type SmallRect struct {
	Left   int16
	Top    int16
	Right  int16
	Bottom int16
}

// Used with GetConsoleScreenBuffer to retrieve information about a console
// screen buffer. See
// https://docs.microsoft.com/en-us/windows/console/console-screen-buffer-info-str
// for details.

type ConsoleScreenBufferInfo struct {
	Size              Coord
	CursorPosition    Coord
	Attributes        uint16
	Window            SmallRect
	MaximumWindowSize Coord
}

const UNIX_PATH_MAX = 108 // defined in afunix.h

const (
	// flags for JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags
	JOB_OBJECT_LIMIT_ACTIVE_PROCESS             = 0x00000008
	JOB_OBJECT_LIMIT_AFFINITY                   = 0x00000010
	JOB_OBJECT_LIMIT_BREAKAWAY_OK               = 0x00000800
	JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
	JOB_OBJECT_LIMIT_JOB_MEMORY                 = 0x00000200
	JOB_OBJECT_LIMIT_JOB_TIME                   = 0x00000004
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          = 0x00002000
	JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME          = 0x00000040
	JOB_OBJECT_LIMIT_PRIORITY_CLASS             = 0x00000020
	JOB_OBJECT_LIMIT_PROCESS_MEMORY             = 0x00000100
	JOB_OBJECT_LIMIT_PROCESS_TIME               = 0x00000002
	JOB_OBJECT_LIMIT_SCHEDULING_CLASS           = 0x00000080
	JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK        = 0x00001000
	JOB_OBJECT_LIMIT_SUBSET_AFFINITY            = 0x00004000
	JOB_OBJECT_LIMIT_WORKINGSET                 = 0x00000001
)

type IO_COUNTERS struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type JOBOBJECT_EXTENDED_LIMIT_INFORMATION struct {
	BasicLimitInformation JOBOBJECT_BASIC_LIMIT_INFORMATION
	IoInfo                IO_COUNTERS
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

const (
	// UIRestrictionsClass
	JOB_OBJECT_UILIMIT_DESKTOP          = 0x00000040
	JOB_OBJECT_UILIMIT_DISPLAYSETTINGS  = 0x00000010
	JOB_OBJECT_UILIMIT_EXITWINDOWS      = 0x00000080
	JOB_OBJECT_UILIMIT_GLOBALATOMS      = 0x00000020
	JOB_OBJECT_UILIMIT_HANDLES          = 0x00000001
	JOB_OBJECT_UILIMIT_READCLIPBOARD    = 0x00000002
	JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008
	JOB_OBJECT_UILIMIT_WRITECLIPBOARD   = 0x00000004
)

type JOBOBJECT_BASIC_UI_RESTRICTIONS struct {
	UIRestrictionsClass uint32
}

const (
	// JobObjectInformationClass for QueryInformationJobObject and SetInformationJobObject
	JobObjectAssociateCompletionPortInformation = 7
	JobObjectBasicAccountingInformation         = 1
	JobObjectBasicAndIoAccountingInformation    = 8
	JobObjectBasicLimitInformation              = 2
	JobObjectBasicProcessIdList                 = 3
	JobObjectBasicUIRestrictions                = 4
	JobObjectCpuRateControlInformation          = 15
	JobObjectEndOfJobTimeInformation            = 6
	JobObjectExtendedLimitInformation           = 9
	JobObjectGroupInformation                   = 11
	JobObjectGroupInformationEx                 = 14
	JobObjectLimitViolationInformation          = 13
	JobObjectLimitViolationInformation2         = 34
	JobObjectNetRateControlInformation          = 32
	JobObjectNotificationLimitInformation       = 12
	JobObjectNotificationLimitInformation2      = 33
	JobObjectSecurityLimitInformation           = 5
)

const (
	KF_FLAG_DEFAULT                          = 0x00000000
	KF_FLAG_FORCE_APP_DATA_REDIRECTION       = 0x00080000
	KF_FLAG_RETURN_FILTER_REDIRECTION_TARGET = 0x00040000
	KF_FLAG_FORCE_PACKAGE_REDIRECTION        = 0x00020000
	KF_FLAG_NO_PACKAGE_REDIRECTION           = 0x00010000
	KF_FLAG_FORCE_APPCONTAINER_REDIRECTION   = 0x00020000
	KF_FLAG_NO_APPCONTAINER_REDIRECTION      = 0x00010000
	KF_FLAG_CREATE                           = 0x00008000
	KF_FLAG_DONT_VERIFY                      = 0x00004000
	KF_FLAG_DONT_UNEXPAND                    = 0x00002000
	KF_FLAG_NO_ALIAS                         = 0x00001000
	KF_FLAG_INIT                             = 0x00000800
	KF_FLAG_DEFAULT_PATH                     = 0x00000400
	KF_FLAG_NOT_PARENT_RELATIVE              = 0x00000200
	KF_FLAG_SIMPLE_IDLIST                    = 0x00000100
	KF_FLAG_ALIAS_ONLY                       = 0x80000000
)

type OsVersionInfoEx struct {
	osVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CsdVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	_                 byte
}

const (
	EWX_LOGOFF          = 0x00000000
	EWX_SHUTDOWN        = 0x00000001
	EWX_REBOOT          = 0x00000002
	EWX_FORCE           = 0x00000004
	EWX_POWEROFF        = 0x00000008
	EWX_FORCEIFHUNG     = 0x00000010
	EWX_QUICKRESOLVE    = 0x00000020
	EWX_RESTARTAPPS     = 0x00000040
	EWX_HYBRID_SHUTDOWN = 0x00400000
	EWX_BOOTOPTIONS     = 0x01000000

	SHTDN_REASON_FLAG_COMMENT_REQUIRED          = 0x01000000
	SHTDN_REASON_FLAG_DIRTY_PROBLEM_ID_REQUIRED = 0x02000000
	SHTDN_REASON_FLAG_CLEAN_UI                  = 0x04000000
	SHTDN_REASON_FLAG_DIRTY_UI                  = 0x08000000
	SHTDN_REASON_FLAG_USER_DEFINED              = 0x40000000
	SHTDN_REASON_FLAG_PLANNED                   = 0x80000000
	SHTDN_REASON_MAJOR_OTHER                    = 0x00000000
	SHTDN_REASON_MAJOR_NONE                     = 0x00000000
	SHTDN_REASON_MAJOR_HARDWARE                 = 0x00010000
	SHTDN_REASON_MAJOR_OPERATINGSYSTEM          = 0x00020000
	SHTDN_REASON_MAJOR_SOFTWARE                 = 0x00030000
	SHTDN_REASON_MAJOR_APPLICATION              = 0x00040000
	SHTDN_REASON_MAJOR_SYSTEM                   = 0x00050000
	SHTDN_REASON_MAJOR_POWER                    = 0x00060000
	SHTDN_REASON_MAJOR_LEGACY_API               = 0x00070000
	SHTDN_REASON_MINOR_OTHER                    = 0x00000000
	SHTDN_REASON_MINOR_NONE                     = 0x000000ff
	SHTDN_REASON_MINOR_MAINTENANCE              = 0x00000001
	SHTDN_REASON_MINOR_INSTALLATION             = 0x00000002
	SHTDN_REASON_MINOR_UPGRADE                  = 0x00000003
	SHTDN_REASON_MINOR_RECONFIG                 = 0x00000004
	SHTDN_REASON_MINOR_HUNG                     = 0x00000005
	SHTDN_REASON_MINOR_UNSTABLE                 = 0x00000006
	SHTDN_REASON_MINOR_DISK                     = 0x00000007
	SHTDN_REASON_MINOR_PROCESSOR                = 0x00000008
	SHTDN_REASON_MINOR_NETWORKCARD              = 0x00000009
	SHTDN_REASON_MINOR_POWER_SUPPLY             = 0x0000000a
	SHTDN_REASON_MINOR_CORDUNPLUGGED            = 0x0000000b
	SHTDN_REASON_MINOR_ENVIRONMENT              = 0x0000000c
	SHTDN_REASON_MINOR_HARDWARE_DRIVER          = 0x0000000d
	SHTDN_REASON_MINOR_OTHERDRIVER              = 0x0000000e
	SHTDN_REASON_MINOR_BLUESCREEN               = 0x0000000F
	SHTDN_REASON_MINOR_SERVICEPACK              = 0x00000010
	SHTDN_REASON_MINOR_HOTFIX                   = 0x00000011
	SHTDN_REASON_MINOR_SECURITYFIX              = 0x00000012
	SHTDN_REASON_MINOR_SECURITY                 = 0x00000013
	SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY     = 0x00000014
	SHTDN_REASON_MINOR_WMI                      = 0x00000015
	SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL    = 0x00000016
	SHTDN_REASON_MINOR_HOTFIX_UNINSTALL         = 0x00000017
	SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL    = 0x00000018
	SHTDN_REASON_MINOR_MMC                      = 0x00000019
	SHTDN_REASON_MINOR_SYSTEMRESTORE            = 0x0000001a
	SHTDN_REASON_MINOR_TERMSRV                  = 0x00000020
	SHTDN_REASON_MINOR_DC_PROMOTION             = 0x00000021
	SHTDN_REASON_MINOR_DC_DEMOTION              = 0x00000022
	SHTDN_REASON_UNKNOWN                        = SHTDN_REASON_MINOR_NONE
	SHTDN_REASON_LEGACY_API                     = SHTDN_REASON_MAJOR_LEGACY_API | SHTDN_REASON_FLAG_PLANNED
	SHTDN_REASON_VALID_BIT_MASK                 = 0xc0ffffff

	SHUTDOWN_NORETRY = 0x1
)

// Flags used for GetModuleHandleEx
const (
	GET_MODULE_HANDLE_EX_FLAG_PIN                = 1
	GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 2
	GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS       = 4
)

// MUI function flag values
const (
	MUI_LANGUAGE_ID                    = 0x4
	MUI_LANGUAGE_NAME                  = 0x8
	MUI_MERGE_SYSTEM_FALLBACK          = 0x10
	MUI_MERGE_USER_FALLBACK            = 0x20
	MUI_UI_FALLBACK                    = MUI_MERGE_SYSTEM_FALLBACK | MUI_MERGE_USER_FALLBACK
	MUI_THREAD_LANGUAGES               = 0x40
	MUI_CONSOLE_FILTER                 = 0x100
	MUI_COMPLEX_SCRIPT_FILTER          = 0x200
	MUI_RESET_FILTERS                  = 0x001
	MUI_USER_PREFERRED_UI_LANGUAGES    = 0x10
	MUI_USE_INSTALLED_LANGUAGES        = 0x20
	MUI_USE_SEARCH_ALL_LANGUAGES       = 0x40
	MUI_LANG_NEUTRAL_PE_FILE           = 0x100
	MUI_NON_LANG_NEUTRAL_FILE          = 0x200
	MUI_MACHINE_LANGUAGE_SETTINGS      = 0x400
	MUI_FILETYPE_NOT_LANGUAGE_NEUTRAL  = 0x001
	MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN = 0x002
	MUI_FILETYPE_LANGUAGE_NEUTRAL_MUI  = 0x004
	MUI_QUERY_TYPE                     = 0x001
	MUI_QUERY_CHECKSUM                 = 0x002
	MUI_QUERY_LANGUAGE_NAME            = 0x004
	MUI_QUERY_RESOURCE_TYPES           = 0x008
	MUI_FILEINFO_VERSION               = 0x001

	MUI_FULL_LANGUAGE      = 0x01
	MUI_PARTIAL_LANGUAGE   = 0x02
	MUI_LIP_LANGUAGE       = 0x04
	MUI_LANGUAGE_INSTALLED = 0x20
	MUI_LANGUAGE_LICENSED  = 0x40
)

// FILE_INFO_BY_HANDLE_CLASS constants for SetFileInformationByHandle/GetFileInformationByHandleEx
const (
	FileBasicInfo                  = 0
	FileStandardInfo               = 1
	FileNameInfo                   = 2
	FileRenameInfo                 = 3
	FileDispositionInfo            = 4
	FileAllocationInfo             = 5
	FileEndOfFileInfo              = 6
	FileStreamInfo                 = 7
	FileCompressionInfo            = 8
	FileAttributeTagInfo           = 9
	FileIdBothDirectoryInfo        = 10
	FileIdBothDirectoryRestartInfo = 11
	FileIoPriorityHintInfo         = 12
	FileRemoteProtocolInfo         = 13
	FileFullDirectoryInfo          = 14
	FileFullDirectoryRestartInfo   = 15
	FileStorageInfo                = 16
	FileAlignmentInfo              = 17
	FileIdInfo                     = 18
	FileIdExtdDirectoryInfo        = 19
	FileIdExtdDirectoryRestartInfo = 20
	FileDispositionInfoEx          = 21
	FileRenameInfoEx               = 22
	FileCaseSensitiveInfo          = 23
	FileNormalizedNameInfo         = 24
)

// LoadLibrary flags for determining from where to search for a DLL
const (
	DONT_RESOLVE_DLL_REFERENCES               = 0x1
	LOAD_LIBRARY_AS_DATAFILE                  = 0x2
	LOAD_WITH_ALTERED_SEARCH_PATH             = 0x8
	LOAD_IGNORE_CODE_AUTHZ_LEVEL              = 0x10
	LOAD_LIBRARY_AS_IMAGE_RESOURCE            = 0x20
	LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE        = 0x40
	LOAD_LIBRARY_REQUIRE_SIGNED_TARGET        = 0x80
	LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR          = 0x100
	LOAD_LIBRARY_SEARCH_APPLICATION_DIR       = 0x200
	LOAD_LIBRARY_SEARCH_USER_DIRS             = 0x400
	LOAD_LIBRARY_SEARCH_SYSTEM32              = 0x800
	LOAD_LIBRARY_SEARCH_DEFAULT_DIRS          = 0x1000
	LOAD_LIBRARY_SAFE_CURRENT_DIRS            = 0x00002000
	LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER = 0x00004000
	LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY      = 0x00008000
)

// RegNotifyChangeKeyValue notifyFilter flags.
const (
	// REG_NOTIFY_CHANGE_NAME notifies the caller if a subkey is added or deleted.
	REG_NOTIFY_CHANGE_NAME = 0x00000001

	// REG_NOTIFY_CHANGE_ATTRIBUTES notifies the caller of changes to the attributes of the key, such as the security descriptor information.
	REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002

	// REG_NOTIFY_CHANGE_LAST_SET notifies the caller of changes to a value of the key. This can include adding or deleting a value, or changing an existing value.
	REG_NOTIFY_CHANGE_LAST_SET = 0x00000004

	// REG_NOTIFY_CHANGE_SECURITY notifies the caller of changes to the security descriptor of the key.
	REG_NOTIFY_CHANGE_SECURITY = 0x00000008

	// REG_NOTIFY_THREAD_AGNOSTIC indicates that the lifetime of the registration must not be tied to the lifetime of the thread issuing the RegNotifyChangeKeyValue call. Note: This flag value is only supported in Windows 8 and later.
	REG_NOTIFY_THREAD_AGNOSTIC = 0x10000000
)

type CommTimeouts struct {
	ReadIntervalTimeout         uint32
	ReadTotalTimeoutMultiplier  uint32
	ReadTotalTimeoutConstant    uint32
	WriteTotalTimeoutMultiplier uint32
	WriteTotalTimeoutConstant   uint32
}

// NTUnicodeString is a UTF-16 string for NT native APIs, corresponding to UNICODE_STRING.
type NTUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// NTString is an ANSI string for NT native APIs, corresponding to STRING.
type NTString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type RUNTIME_FUNCTION struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
}

type LDR_DATA_TABLE_ENTRY struct {
	reserved1          [2]uintptr
	InMemoryOrderLinks LIST_ENTRY
	reserved2          [2]uintptr
	DllBase            uintptr
	reserved3          [2]uintptr
	FullDllName        NTUnicodeString
	reserved4          [8]byte
	reserved5          [3]uintptr
	reserved6          uintptr
	TimeDateStamp      uint32
}

type PEB_LDR_DATA struct {
	reserved1               [8]byte
	reserved2               [3]uintptr
	InMemoryOrderModuleList LIST_ENTRY
}

type CURDIR struct {
	DosPath NTUnicodeString
	Handle  Handle
}

type RTL_DRIVE_LETTER_CURDIR struct {
	Flags     uint16
	Length    uint16
	TimeStamp uint32
	DosPath   NTString
}

type RTL_USER_PROCESS_PARAMETERS struct {
	MaximumLength, Length uint32

	Flags, DebugFlags uint32

	ConsoleHandle                                Handle
	ConsoleFlags                                 uint32
	StandardInput, StandardOutput, StandardError Handle

	CurrentDirectory CURDIR
	DllPath          NTUnicodeString
	ImagePathName    NTUnicodeString
	CommandLine      NTUnicodeString
	Environment      unsafe.Pointer

	StartingX, StartingY, CountX, CountY, CountCharsX, CountCharsY, FillAttribute uint32

	WindowFlags, ShowWindowFlags                     uint32
	WindowTitle, DesktopInfo, ShellInfo, RuntimeData NTUnicodeString
	CurrentDirectories                               [32]RTL_DRIVE_LETTER_CURDIR

	EnvironmentSize, EnvironmentVersion uintptr

	PackageDependencyData unsafe.Pointer
	ProcessGroupId        uint32
	LoaderThreads         uint32

	RedirectionDllName               NTUnicodeString
	HeapPartitionName                NTUnicodeString
	DefaultThreadpoolCpuSetMasks     uintptr
	DefaultThreadpoolCpuSetMaskCount uint32
}

type PEB struct {
	reserved1              [2]byte
	BeingDebugged          byte
	BitField               byte
	reserved3              uintptr
	ImageBaseAddress       uintptr
	Ldr                    *PEB_LDR_DATA
	ProcessParameters      *RTL_USER_PROCESS_PARAMETERS
	reserved4              [3]uintptr
	AtlThunkSListPtr       uintptr
	reserved5              uintptr
	reserved6              uint32
	reserved7              uintptr
	reserved8              uint32
	AtlThunkSListPtr32     uint32
	reserved9              [45]uintptr
	reserved10             [96]byte
	PostProcessInitRoutine uintptr
	reserved11             [128]byte
	reserved12             [1]uintptr
	SessionId              uint32
}

type OBJECT_ATTRIBUTES struct {
	Length             uint32
	RootDirectory      Handle
	ObjectName         *NTUnicodeString
	Attributes         uint32
	SecurityDescriptor *SECURITY_DESCRIPTOR
	SecurityQoS        *SECURITY_QUALITY_OF_SERVICE
}

// Values for the Attributes member of OBJECT_ATTRIBUTES.
const (
	OBJ_INHERIT                       = 0x00000002
	OBJ_PERMANENT                     = 0x00000010
	OBJ_EXCLUSIVE                     = 0x00000020
	OBJ_CASE_INSENSITIVE              = 0x00000040
	OBJ_OPENIF                        = 0x00000080
	OBJ_OPENLINK                      = 0x00000100
	OBJ_KERNEL_HANDLE                 = 0x00000200
	OBJ_FORCE_ACCESS_CHECK            = 0x00000400
	OBJ_IGNORE_IMPERSONATED_DEVICEMAP = 0x00000800
	OBJ_DONT_REPARSE                  = 0x00001000
	OBJ_VALID_ATTRIBUTES              = 0x00001FF2
)

type IO_STATUS_BLOCK struct {
	Status      NTStatus
	Information uintptr
}

type RTLP_CURDIR_REF struct {
	RefCount int32
	Handle   Handle
}

type RTL_RELATIVE_NAME struct {
	RelativeName        NTUnicodeString
	ContainingDirectory Handle
	CurDirRef           *RTLP_CURDIR_REF
}

const (
	// CreateDisposition flags for NtCreateFile and NtCreateNamedPipeFile.
	FILE_SUPERSEDE           = 0x00000000
	FILE_OPEN                = 0x00000001
	FILE_CREATE              = 0x00000002
	FILE_OPEN_IF             = 0x00000003
	FILE_OVERWRITE           = 0x00000004
	FILE_OVERWRITE_IF        = 0x00000005
	FILE_MAXIMUM_DISPOSITION = 0x00000005

	// CreateOptions flags for NtCreateFile and NtCreateNamedPipeFile.
	FILE_DIRECTORY_FILE            = 0x00000001
	FILE_WRITE_THROUGH             = 0x00000002
	FILE_SEQUENTIAL_ONLY           = 0x00000004
	FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
	FILE_SYNCHRONOUS_IO_ALERT      = 0x00000010
	FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020
	FILE_NON_DIRECTORY_FILE        = 0x00000040
	FILE_CREATE_TREE_CONNECTION    = 0x00000080
	FILE_COMPLETE_IF_OPLOCKED      = 0x00000100
	FILE_NO_EA_KNOWLEDGE           = 0x00000200
	FILE_OPEN_REMOTE_INSTANCE      = 0x00000400
	FILE_RANDOM_ACCESS             = 0x00000800
	FILE_DELETE_ON_CLOSE           = 0x00001000
	FILE_OPEN_BY_FILE_ID           = 0x00002000
	FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000
	FILE_NO_COMPRESSION            = 0x00008000
	FILE_OPEN_REQUIRING_OPLOCK     = 0x00010000
	FILE_DISALLOW_EXCLUSIVE        = 0x00020000
	FILE_RESERVE_OPFILTER          = 0x00100000
	FILE_OPEN_REPARSE_POINT        = 0x00200000
	FILE_OPEN_NO_RECALL            = 0x00400000
	FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000

	// Parameter constants for NtCreateNamedPipeFile.

	FILE_PIPE_BYTE_STREAM_TYPE = 0x00000000
	FILE_PIPE_MESSAGE_TYPE     = 0x00000001

	FILE_PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000
	FILE_PIPE_REJECT_REMOTE_CLIENTS = 0x00000002

	FILE_PIPE_TYPE_VALID_MASK = 0x00000003

	FILE_PIPE_BYTE_STREAM_MODE = 0x00000000
	FILE_PIPE_MESSAGE_MODE     = 0x00000001

	FILE_PIPE_QUEUE_OPERATION    = 0x00000000
	FILE_PIPE_COMPLETE_OPERATION = 0x00000001

	FILE_PIPE_INBOUND     = 0x00000000
	FILE_PIPE_OUTBOUND    = 0x00000001
	FILE_PIPE_FULL_DUPLEX = 0x00000002

	FILE_PIPE_DISCONNECTED_STATE = 0x00000001
	FILE_PIPE_LISTENING_STATE    = 0x00000002
	FILE_PIPE_CONNECTED_STATE    = 0x00000003
	FILE_PIPE_CLOSING_STATE      = 0x00000004

	FILE_PIPE_CLIENT_END = 0x00000000
	FILE_PIPE_SERVER_END = 0x00000001
)

const (
	// FileInformationClass for NtSetInformationFile
	FileBasicInformation                         = 4
	FileRenameInformation                        = 10
	FileDispositionInformation                   = 13
	FilePositionInformation                      = 14
	FileEndOfFileInformation                     = 20
	FileValidDataLengthInformation               = 39
	FileShortNameInformation                     = 40
	FileIoPriorityHintInformation                = 43
	FileReplaceCompletionInformation             = 61
	FileDispositionInformationEx                 = 64
	FileCaseSensitiveInformation                 = 71
	FileLinkInformation                          = 72
	FileCaseSensitiveInformationForceAccessCheck = 75
	FileKnownFolderInformation                   = 76

	// Flags for FILE_RENAME_INFORMATION
	FILE_RENAME_REPLACE_IF_EXISTS                    = 0x00000001
	FILE_RENAME_POSIX_SEMANTICS                      = 0x00000002
	FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE       = 0x00000004
	FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE = 0x00000008
	FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE          = 0x00000010
	FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE          = 0x00000020
	FILE_RENAME_PRESERVE_AVAILABLE_SPACE             = 0x00000030
	FILE_RENAME_IGNORE_READONLY_ATTRIBUTE            = 0x00000040
	FILE_RENAME_FORCE_RESIZE_TARGET_SR               = 0x00000080
	FILE_RENAME_FORCE_RESIZE_SOURCE_SR               = 0x00000100
	FILE_RENAME_FORCE_RESIZE_SR                      = 0x00000180

	// Flags for FILE_DISPOSITION_INFORMATION_EX
	FILE_DISPOSITION_DO_NOT_DELETE             = 0x00000000
	FILE_DISPOSITION_DELETE                    = 0x00000001
	FILE_DISPOSITION_POSIX_SEMANTICS           = 0x00000002
	FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK = 0x00000004
	FILE_DISPOSITION_ON_CLOSE                  = 0x00000008
	FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE = 0x00000010

	// Flags for FILE_CASE_SENSITIVE_INFORMATION
	FILE_CS_FLAG_CASE_SENSITIVE_DIR = 0x00000001

	// Flags for FILE_LINK_INFORMATION
	FILE_LINK_REPLACE_IF_EXISTS                    = 0x00000001
	FILE_LINK_POSIX_SEMANTICS                      = 0x00000002
	FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE = 0x00000008
	FILE_LINK_NO_INCREASE_AVAILABLE_SPACE          = 0x00000010
	FILE_LINK_NO_DECREASE_AVAILABLE_SPACE          = 0x00000020
	FILE_LINK_PRESERVE_AVAILABLE_SPACE             = 0x00000030
	FILE_LINK_IGNORE_READONLY_ATTRIBUTE            = 0x00000040
	FILE_LINK_FORCE_RESIZE_TARGET_SR               = 0x00000080
	FILE_LINK_FORCE_RESIZE_SOURCE_SR               = 0x00000100
	FILE_LINK_FORCE_RESIZE_SR                      = 0x00000180
)

// ProcessInformationClasses for NtQueryInformationProcess and NtSetInformationProcess.
const (
	ProcessBasicInformation = iota
	ProcessQuotaLimits
	ProcessIoCounters
	ProcessVmCounters
	ProcessTimes
	ProcessBasePriority
	ProcessRaisePriority
	ProcessDebugPort
	ProcessExceptionPort
	ProcessAccessToken
	ProcessLdtInformation
	ProcessLdtSize
	ProcessDefaultHardErrorMode
	ProcessIoPortHandlers
	ProcessPooledUsageAndLimits
	ProcessWorkingSetWatch
	ProcessUserModeIOPL
	ProcessEnableAlignmentFaultFixup
	ProcessPriorityClass
	ProcessWx86Information
	ProcessHandleCount
	ProcessAffinityMask
	ProcessPriorityBoost
	ProcessDeviceMap
	ProcessSessionInformation
	ProcessForegroundInformation
	ProcessWow64Information
	ProcessImageFileName
	ProcessLUIDDeviceMapsEnabled
	ProcessBreakOnTermination
	ProcessDebugObjectHandle
	ProcessDebugFlags
	ProcessHandleTracing
	ProcessIoPriority
	ProcessExecuteFlags
	ProcessTlsInformation
	ProcessCookie
	ProcessImageInformation
	ProcessCycleTime
	ProcessPagePriority
	ProcessInstrumentationCallback
	ProcessThreadStackAllocation
	ProcessWorkingSetWatchEx
	ProcessImageFileNameWin32
	ProcessImageFileMapping
	ProcessAffinityUpdateMode
	ProcessMemoryAllocationMode
	ProcessGroupInformation
	ProcessTokenVirtualizationEnabled
	ProcessConsoleHostProcess
	ProcessWindowInformation
	ProcessHandleInformation
	ProcessMitigationPolicy
	ProcessDynamicFunctionTableInformation
	ProcessHandleCheckingMode
	ProcessKeepAliveCount
	ProcessRevokeFileHandles
	ProcessWorkingSetControl
	ProcessHandleTable
	ProcessCheckStackExtentsMode
	ProcessCommandLineInformation
	ProcessProtectionInformation
	ProcessMemoryExhaustion
	ProcessFaultInformation
	ProcessTelemetryIdInformation
	ProcessCommitReleaseInformation
	ProcessDefaultCpuSetsInformation
	ProcessAllowedCpuSetsInformation
	ProcessSubsystemProcess
	ProcessJobMemoryInformation
	ProcessInPrivate
	ProcessRaiseUMExceptionOnInvalidHandleClose
	ProcessIumChallengeResponse
	ProcessChildProcessInformation
	ProcessHighGraphicsPriorityInformation
	ProcessSubsystemInformation
	ProcessEnergyValues
	ProcessActivityThrottleState
	ProcessActivityThrottlePolicy
	ProcessWin32kSyscallFilterInformation
	ProcessDisableSystemAllowedCpuSets
	ProcessWakeInformation
	ProcessEnergyTrackingState
	ProcessManageWritesToExecutableMemory
	ProcessCaptureTrustletLiveDump
	ProcessTelemetryCoverage
	ProcessEnclaveInformation
	ProcessEnableReadWriteVmLogging
	ProcessUptimeInformation
	ProcessImageSection
	ProcessDebugAuthInformation
	ProcessSystemResourceManagement
	ProcessSequenceNumber
	ProcessLoaderDetour
	ProcessSecurityDomainInformation
	ProcessCombineSecurityDomainsInformation
	ProcessEnableLogging
	ProcessLeapSecondInformation
	ProcessFiberShadowStackAllocation
	ProcessFreeFiberShadowStackAllocation
	ProcessAltSystemCallInformation
	ProcessDynamicEHContinuationTargets
	ProcessDynamicEnforcedCetCompatibleRanges
)

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   NTStatus
	PebBaseAddress               *PEB
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

type SYSTEM_PROCESS_INFORMATION struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   int64
	UserTime                     int64
	KernelTime                   int64
	ImageName                    NTUnicodeString
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
	HandleCount                  uint32
	SessionID                    uint32
	UniqueProcessKey             *uint32
	PeakVirtualSize              uintptr
	VirtualSize                  uintptr
	PageFaultCount               uint32
	PeakWorkingSetSize           uintptr
	WorkingSetSize               uintptr
	QuotaPeakPagedPoolUsage      uintptr
	QuotaPagedPoolUsage          uintptr
	QuotaPeakNonPagedPoolUsage   uintptr
	QuotaNonPagedPoolUsage       uintptr
	PagefileUsage                uintptr
	PeakPagefileUsage            uintptr
	PrivatePageCount             uintptr
	ReadOperationCount           int64
	WriteOperationCount          int64
	OtherOperationCount          int64
	ReadTransferCount            int64
	WriteTransferCount           int64
	OtherTransferCount           int64
}

// SystemInformationClasses for NtQuerySystemInformation and NtSetSystemInformation
const (
	SystemBasicInformation = iota
	SystemProcessorInformation
	SystemPerformanceInformation
	SystemTimeOfDayInformation
	SystemPathInformation
	SystemProcessInformation
	SystemCallCountInformation
	SystemDeviceInformation
	SystemProcessorPerformanceInformation
	SystemFlagsInformation
	SystemCallTimeInformation
	SystemModuleInformation
	SystemLocksInformation
	SystemStackTraceInformation
	SystemPagedPoolInformation
	SystemNonPagedPoolInformation
	SystemHandleInformation
	SystemObjectInformation
	SystemPageFileInformation
	SystemVdmInstemulInformation
	SystemVdmBopInformation
	SystemFileCacheInformation
	SystemPoolTagInformation
	SystemInterruptInformation
	SystemDpcBehaviorInformation
	SystemFullMemoryInformation
	SystemLoadGdiDriverInformation
	SystemUnloadGdiDriverInformation
	SystemTimeAdjustmentInformation
	SystemSummaryMemoryInformation
	SystemMirrorMemoryInformation
	SystemPerformanceTraceInformation
	systemObsolete0
	SystemExceptionInformation
	SystemCrashDumpStateInformation
	SystemKernelDebuggerInformation
	SystemContextSwitchInformation
	SystemRegistryQuotaInformation
	SystemExtendServiceTableInformation
	SystemPrioritySeperation
	SystemVerifierAddDriverInformation
	SystemVerifierRemoveDriverInformation
	SystemProcessorIdleInformation
	SystemLegacyDriverInformation
	SystemCurrentTimeZoneInformation
	SystemLookasideInformation
	SystemTimeSlipNotification
	SystemSessionCreate
	SystemSessionDetach
	SystemSessionInformation
	SystemRangeStartInformation
	SystemVerifierInformation
	SystemVerifierThunkExtend
	SystemSessionProcessInformation
	SystemLoadGdiDriverInSystemSpace
	SystemNumaProcessorMap
	SystemPrefetcherInformation
	SystemExtendedProcessInformation
	SystemRecommendedSharedDataAlignment
	SystemComPlusPackage
	SystemNumaAvailableMemory
	SystemProcessorPowerInformation
	SystemEmulationBasicInformation
	SystemEmulationProcessorInformation
	SystemExtendedHandleInformation
	SystemLostDelayedWriteInformation
	SystemBigPoolInformation
	SystemSessionPoolTagInformation
	SystemSessionMappedViewInformation
	SystemHotpatchInformation
	SystemObjectSecurityMode
	SystemWatchdogTimerHandler
	SystemWatchdogTimerInformation
	SystemLogicalProcessorInformation
	SystemWow64SharedInformationObsolete
	SystemRegisterFirmwareTableInformationHandler
	SystemFirmwareTableInformation
	SystemModuleInformationEx
	SystemVerifierTriageInformation
	SystemSuperfetchInformation
	SystemMemoryListInformation
	SystemFileCacheInformationEx
	SystemThreadPriorityClientIdInformation
	SystemProcessorIdleCycleTimeInformation
	SystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx
	SystemRefTraceInformation
	SystemSpecialPoolInformation
	SystemProcessIdInformation
	SystemErrorPortInformation
	SystemBootEnvironmentInformation
	SystemHypervisorInformation
	SystemVerifierInformationEx
	SystemTimeZoneInformation
	SystemImageFileExecutionOptionsInformation
	SystemCoverageInformation
	SystemPrefetchPatchInformation
	SystemVerifierFaultsInformation
	SystemSystemPartitionInformation
	SystemSystemDiskInformation
	SystemProcessorPerformanceDistribution
	SystemNumaProximityNodeInformation
	SystemDynamicTimeZoneInformation
	SystemCodeIntegrityInformation
	SystemProcessorMicrocodeUpdateInformation
	SystemProcessorBrandString
	SystemVirtualAddressInformation
	SystemLogicalProcessorAndGroupInformation
	SystemProcessorCycleTimeInformation
	SystemStoreInformation
	SystemRegistryAppendString
	SystemAitSamplingValue
	SystemVhdBootInformation
	SystemCpuQuotaInformation
	SystemNativeBasicInformation
	systemSpare1
	SystemLowPriorityIoInformation
	SystemTpmBootEntropyInformation
	SystemVerifierCountersInformation
	SystemPagedPoolInformationEx
	SystemSystemPtesInformationEx
	SystemNodeDistanceInformation
	SystemAcpiAuditInformation
	SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation
	SystemSessionBigPoolInformation
	SystemBootGraphicsInformation
	SystemScrubPhysicalMemoryInformation
	SystemBadPageInformation
	SystemProcessorProfileControlArea
	SystemCombinePhysicalMemoryInformation
	SystemEntropyInterruptTimingCallback
	SystemConsoleInformation
	SystemPlatformBinaryInformation
	SystemThrottleNotificationInformation
	SystemHypervisorProcessorCountInformation
	SystemDeviceDataInformation
	SystemDeviceDataEnumerationInformation
	SystemMemoryTopologyInformation
	SystemMemoryChannelInformation
	SystemBootLogoInformation
	SystemProcessorPerformanceInformationEx
	systemSpare0
	SystemSecureBootPolicyInformation
	SystemPageFileInformationEx
	SystemSecureBootInformation
	SystemEntropyInterruptTimingRawInformation
	SystemPortableWorkspaceEfiLauncherInformation
	SystemFullProcessInformation
	SystemKernelDebuggerInformationEx
	SystemBootMetadataInformation
	SystemSoftRebootInformation
	SystemElamCertificateInformation
	SystemOfflineDumpConfigInformation
	SystemProcessorFeaturesInformation
	SystemRegistryReconciliationInformation
	SystemEdidInformation
	SystemManufacturingInformation
	SystemEnergyEstimationConfigInformation
	SystemHypervisorDetailInformation
	SystemProcessorCycleStatsInformation
	SystemVmGenerationCountInformation
	SystemTrustedPlatformModuleInformation
	SystemKernelDebuggerFlags
	SystemCodeIntegrityPolicyInformation
	SystemIsolatedUserModeInformation
	SystemHardwareSecurityTestInterfaceResultsInformation
	SystemSingleModuleInformation
	SystemAllowedCpuSetsInformation
	SystemDmaProtectionInformation
	SystemInterruptCpuSetsInformation
	SystemSecureBootPolicyFullInformation
	SystemCodeIntegrityPolicyFullInformation
	SystemAffinitizedInterruptProcessorInformation
	SystemRootSiloInformation
)

type RTL_PROCESS_MODULE_INFORMATION struct {
	Section          Handle
	MappedBase       uintptr
	ImageBase        uintptr
	ImageSize        uint32
	Flags            uint32
	LoadOrderIndex   uint16
	InitOrderIndex   uint16
	LoadCount        uint16
	OffsetToFileName uint16
	FullPathName     [256]byte
}

type RTL_PROCESS_MODULES struct {
	NumberOfModules uint32
	Modules         [1]RTL_PROCESS_MODULE_INFORMATION
}

// Constants for LocalAlloc flags.
const (
	LMEM_FIXED          = 0x0
	LMEM_MOVEABLE       = 0x2
	LMEM_NOCOMPACT      = 0x10
	LMEM_NODISCARD      = 0x20
	LMEM_ZEROINIT       = 0x40
	LMEM_MODIFY         = 0x80
	LMEM_DISCARDABLE    = 0xf00
	LMEM_VALID_FLAGS    = 0xf72
	LMEM_INVALID_HANDLE = 0x8000
	LHND                = LMEM_MOVEABLE | LMEM_ZEROINIT
	LPTR                = LMEM_FIXED | LMEM_ZEROINIT
	NONZEROLHND         = LMEM_MOVEABLE
	NONZEROLPTR         = LMEM_FIXED
)

// Constants for the CreateNamedPipe-family of functions.
const (
	PIPE_ACCESS_INBOUND  = 0x1
	PIPE_ACCESS_OUTBOUND = 0x2
	PIPE_ACCESS_DUPLEX   = 0x3

	PIPE_CLIENT_END = 0x0
	PIPE_SERVER_END = 0x1

	PIPE_WAIT                  = 0x0
	PIPE_NOWAIT                = 0x1
	PIPE_READMODE_BYTE         = 0x0
	PIPE_READMODE_MESSAGE      = 0x2
	PIPE_TYPE_BYTE             = 0x0
	PIPE_TYPE_MESSAGE          = 0x4
	PIPE_ACCEPT_REMOTE_CLIENTS = 0x0
	PIPE_REJECT_REMOTE_CLIENTS = 0x8

	PIPE_UNLIMITED_INSTANCES = 255
)

// Constants for security attributes when opening named pipes.
const (
	SECURITY_ANONYMOUS      = SecurityAnonymous << 16
	SECURITY_IDENTIFICATION = SecurityIdentification << 16
	SECURITY_IMPERSONATION  = SecurityImpersonation << 16
	SECURITY_DELEGATION     = SecurityDelegation << 16

	SECURITY_CONTEXT_TRACKING = 0x40000
	SECURITY_EFFECTIVE_ONLY   = 0x80000

	SECURITY_SQOS_PRESENT     = 0x100000
	SECURITY_VALID_SQOS_FLAGS = 0x1f0000
)

// ResourceID represents a 16-bit resource identifier, traditionally created with the MAKEINTRESOURCE macro.
type ResourceID uint16

// ResourceIDOrString must be either a ResourceID, to specify a resource or resource type by ID,
// or a string, to specify a resource or resource type by name.
type ResourceIDOrString interface{}

// Predefined resource names and types.
var (
	// Predefined names.
	CREATEPROCESS_MANIFEST_RESOURCE_ID                 ResourceID = 1
	ISOLATIONAWARE_MANIFEST_RESOURCE_ID                ResourceID = 2
	ISOLATIONAWARE_NOSTATICIMPORT_MANIFEST_RESOURCE_ID ResourceID = 3
	ISOLATIONPOLICY_MANIFEST_RESOURCE_ID               ResourceID = 4
	ISOLATIONPOLICY_BROWSER_MANIFEST_RESOURCE_ID       ResourceID = 5
	MINIMUM_RESERVED_MANIFEST_RESOURCE_ID              ResourceID = 1  // inclusive
	MAXIMUM_RESERVED_MANIFEST_RESOURCE_ID              ResourceID = 16 // inclusive

	// Predefined types.
	RT_CURSOR       ResourceID = 1
	RT_BITMAP       ResourceID = 2
	RT_ICON         ResourceID = 3
	RT_MENU         ResourceID = 4
	RT_DIALOG       ResourceID = 5
	RT_STRING       ResourceID = 6
	RT_FONTDIR      ResourceID = 7
	RT_FONT         ResourceID = 8
	RT_ACCELERATOR  ResourceID = 9
	RT_RCDATA       ResourceID = 10
	RT_MESSAGETABLE ResourceID = 11
	RT_GROUP_CURSOR ResourceID = 12
	RT_GROUP_ICON   ResourceID = 14
	RT_VERSION      ResourceID = 16
	RT_DLGINCLUDE   ResourceID = 17
	RT_PLUGPLAY     ResourceID = 19
	RT_VXD          ResourceID = 20
	RT_ANICURSOR    ResourceID = 21
	RT_ANIICON      ResourceID = 22
	RT_HTML         ResourceID = 23
	RT_MANIFEST     ResourceID = 24
)

type VS_FIXEDFILEINFO struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

type COAUTHIDENTITY struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

type COAUTHINFO struct {
	AuthnSvc           uint32
	AuthzSvc           uint32
	ServerPrincName    *uint16
	AuthnLevel         uint32
	ImpersonationLevel uint32
	AuthIdentityData   *COAUTHIDENTITY
	Capabilities       uint32
}

type COSERVERINFO struct {
	Reserved1 uint32
	Aame      *uint16
	AuthInfo  *COAUTHINFO
	Reserved2 uint32
}

type BIND_OPTS3 struct {
	CbStruct          uint32
	Flags             uint32
	Mode              uint32
	TickCountDeadline uint32
	TrackFlags        uint32
	ClassContext      uint32
	Locale            uint32
	ServerInfo        *COSERVERINFO
	Hwnd              HWND
}

const (
	CLSCTX_INPROC_SERVER          = 0x1
	CLSCTX_INPROC_HANDLER         = 0x2
	CLSCTX_LOCAL_SERVER           = 0x4
	CLSCTX_INPROC_SERVER16        = 0x8
	CLSCTX_REMOTE_SERVER          = 0x10
	CLSCTX_INPROC_HANDLER16       = 0x20
	CLSCTX_RESERVED1              = 0x40
	CLSCTX_RESERVED2              = 0x80
	CLSCTX_RESERVED3              = 0x100
	CLSCTX_RESERVED4              = 0x200
	CLSCTX_NO_CODE_DOWNLOAD       = 0x400
	CLSCTX_RESERVED5              = 0x800
	CLSCTX_NO_CUSTOM_MARSHAL      = 0x1000
	CLSCTX_ENABLE_CODE_DOWNLOAD   = 0x2000
	CLSCTX_NO_FAILURE_LOG         = 0x4000
	CLSCTX_DISABLE_AAA            = 0x8000
	CLSCTX_ENABLE_AAA             = 0x10000
	CLSCTX_FROM_DEFAULT_CONTEXT   = 0x20000
	CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000
	CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000
	CLSCTX_ENABLE_CLOAKING        = 0x100000
	CLSCTX_APPCONTAINER           = 0x400000
	CLSCTX_ACTIVATE_AAA_AS_IU     = 0x800000
	CLSCTX_PS_DLL                 = 0x80000000

	COINIT_MULTITHREADED     = 0x0
	COINIT_APARTMENTTHREADED = 0x2
	COINIT_DISABLE_OLE1DDE   = 0x4
	COINIT_SPEED_OVER_MEMORY = 0x8
)

// Flag for QueryFullProcessImageName.
const PROCESS_NAME_NATIVE = 1

type ModuleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

const ALL_PROCESSOR_GROUPS = 0xFFFF

type Rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type GUIThreadInfo struct {
	Size        uint32
	Flags       uint32
	Active      HWND
	Focus       HWND
	Capture     HWND
	MenuOwner   HWND
	MoveSize    HWND
	CaretHandle HWND
	CaretRect   Rect
}

const (
	DWMWA_NCRENDERING_ENABLED            = 1
	DWMWA_NCRENDERING_POLICY             = 2
	DWMWA_TRANSITIONS_FORCEDISABLED      = 3
	DWMWA_ALLOW_NCPAINT                  = 4
	DWMWA_CAPTION_BUTTON_BOUNDS          = 5
	DWMWA_NONCLIENT_RTL_LAYOUT           = 6
	DWMWA_FORCE_ICONIC_REPRESENTATION    = 7
	DWMWA_FLIP3D_POLICY                  = 8
	DWMWA_EXTENDED_FRAME_BOUNDS          = 9
	DWMWA_HAS_ICONIC_BITMAP              = 10
	DWMWA_DISALLOW_PEEK                  = 11
	DWMWA_EXCLUDED_FROM_PEEK             = 12
	DWMWA_CLOAK                          = 13
	DWMWA_CLOAKED                        = 14
	DWMWA_FREEZE_REPRESENTATION          = 15
	DWMWA_PASSIVE_UPDATE_MODE            = 16
	DWMWA_USE_HOSTBACKDROPBRUSH          = 17
	DWMWA_USE_IMMERSIVE_DARK_MODE        = 20
	DWMWA_WINDOW_CORNER_PREFERENCE       = 33
	DWMWA_BORDER_COLOR                   = 34
	DWMWA_CAPTION_COLOR                  = 35
	DWMWA_TEXT_COLOR                     = 36
	DWMWA_VISIBLE_FRAME_BORDER_THICKNESS = 37
)

type WSAQUERYSET struct {
	Size                uint32
	ServiceInstanceName *uint16
	ServiceClassId      *GUID
	Version             *WSAVersion
	Comment             *uint16
	NameSpace           uint32
	NSProviderId        *GUID
	Context             *uint16
	NumberOfProtocols   uint32
	AfpProtocols        *AFProtocols
	QueryString         *uint16
	NumberOfCsAddrs     uint32
	SaBuffer            *CSAddrInfo
	OutputFlags         uint32
	Blob                *BLOB
}

type WSAVersion struct {
	Version                 uint32
	EnumerationOfComparison int32
}

type AFProtocols struct {
	AddressFamily int32
	Protocol      int32
}

type CSAddrInfo struct {
	LocalAddr  SocketAddress
	RemoteAddr SocketAddress
	SocketType int32
	Protocol   int32
}

type BLOB struct {
	Size     uint32
	BlobData *byte
}

type ComStat struct {
	Flags    uint32
	CBInQue  uint32
	CBOutQue uint32
}

type DCB struct {
	DCBlength  uint32
	BaudRate   uint32
	Flags      uint32
	wReserved  uint16
	XonLim     uint16
	XoffLim    uint16
	ByteSize   uint8
	Parity     uint8
	StopBits   uint8
	XonChar    byte
	XoffChar   byte
	ErrorChar  byte
	EofChar    byte
	EvtChar    byte
	wReserved1 uint16
}

// Keyboard Layout Flags.
// See https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadkeyboardlayoutw
const (
	KLF_ACTIVATE      = 0x00000001
	KLF_SUBSTITUTE_OK = 0x00000002
	KLF_REORDER       = 0x00000008
	KLF_REPLACELANG   = 0x00000010
	KLF_NOTELLSHELL   = 0x00000080
	KLF_SETFORPROCESS = 0x00000100
)
```