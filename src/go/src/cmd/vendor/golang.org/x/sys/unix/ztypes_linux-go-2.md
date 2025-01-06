Response:
The user has provided a snippet of a Go file (`ztypes_linux.go`) and wants to know its functionality.
The file path suggests it's part of the `golang.org/x/sys/unix` package and contains Linux-specific type definitions.
The provided code consists mainly of constant definitions, some struct definitions, and more constant definitions.
These constants and structs likely represent low-level system interfaces related to networking and other hardware functionalities on Linux.

Let's break down the content:

1. **`ETHTOOL_LINK_MODE_*` constants:** These constants clearly relate to Ethernet link modes, specifying different speeds and duplex settings. This hints at functionalities related to network interface configuration.

2. **`ETHTOOL_MSG_*` constants:** These constants seem to define message types used in communication with the `ethtool` utility, a command-line tool for controlling network driver and hardware settings.

3. **`ETHTOOL_FLAG_*` and `ETHTOOL_A_*` constants:** These likely define flags and attribute types used in the `ethtool` communication protocol. The `ETHTOOL_A_*` constants appear to represent attributes for various aspects of network interface configuration and status.

4. **`SPEED_UNKNOWN` constant:** This is a simple constant representing an unknown speed.

5. **`EthtoolDrvinfo` struct:** This structure likely holds information about the network driver.

6. **`EthtoolTsInfo` and `HwTstampConfig` structs, `HWTSTAMP_FILTER_*` and `HWTSTAMP_TX_*` constants:** These are related to hardware timestamping, a feature for precise time measurements on network packets.

7. **`PtpClockCaps`, `PtpClockTime`, `PtpExttsEvent`, `PtpExttsRequest`, `PtpPeroutRequest`, `PtpPinDesc`, `PtpSysOffset`, `PtpSysOffsetExtended`, `PtpSysOffsetPrecise` structs, `PTP_PF_*` constants:** These definitions are related to the Precision Time Protocol (PTP), used for synchronizing clocks over a network.

8. **`HIDRawReportDescriptor`, `HIDRawDevInfo` structs:** These structures are related to interacting with raw Human Interface Devices (HID).

9. **`CLOSE_RANGE_UNSHARE`, `CLOSE_RANGE_CLOEXEC` constants:** These are related to the `close_range` syscall, used for closing a range of file descriptors.

10. **`NLMSGERR_ATTR_*` constants:** These constants are related to attributes within Netlink error messages.

11. **`EraseInfo`, `EraseInfo64`, `MtdOobBuf`, `MtdOobBuf64`, `MtdWriteReq`, `MtdInfo`, `RegionInfo`, `OtpInfo`, `NandOobinfo`, `NandOobfree`, `NandEcclayout`, `MtdEccStats` structs, `MTD_OPS_*` and `MTD_FILE_MODE_*` constants:** These structures and constants relate to Memory Technology Devices (MTD), often used for flash memory on embedded systems.

12. **`NFC_CMD_*`, `NFC_EVENT_*`, `NFC_ATTR_*`, `NFC_SDP_ATTR_*` constants:** These constants are related to Near-Field Communication (NFC).

13. **`LandlockRulesetAttr`, `LandlockPathBeneathAttr` structs, `LANDLOCK_RULE_*` constants:** These are related to Landlock, a Linux security feature that restricts file system access for processes.

14. **`IPC_CREAT`, `IPC_EXCL`, `IPC_NOWAIT`, `IPC_PRIVATE`, `ipc_64`, `IPC_RMID`, `IPC_SET`, `IPC_STAT`, `SHM_RDONLY`, `SHM_RND` constants:** These constants are related to Inter-Process Communication (IPC) mechanisms like shared memory.

15. **`MountAttr` struct:** This structure is related to mount operations.

16. **`WG_CMD_*`, `WGDEVICE_F_*`, `WGDEVICE_A_*`, `WGPEER_F_*`, `WGPEER_A_*`, `WGALLOWEDIP_A_*` constants:** These constants are related to WireGuard, a modern VPN protocol.

17. **`NL_ATTR_TYPE_*`, `NL_POLICY_TYPE_ATTR_*` constants:** These constants are related to Netlink attributes and their policy types.

18. **`CANBitTiming`, `CANBitTimingConst`, `CANClock`, `CANBusErrorCounters`, `CANCtrlMode`, `CANDeviceStats` structs, `CAN_STATE_*` and `IFLA_CAN_*` constants:** These definitions are related to Controller Area Network (CAN) bus communication.

19. **`KCMAttach`, `KCMUnattach`, `KCMClone` structs:** These are related to Kernel Connection Multiplexor (KCM).

20. **`NL80211_AC_*`, `NL80211_ACL_POLICY_*`, `NL80211_AP_SETTINGS_*`, `NL80211_AP_SME_*`, `NL80211_ATTR_*`, `NL80211_AUTHTYPE_*`, `NL80211_BAND_*`, `NL80211_BITRATE_ATTR_*`, `NL80211_BSS_*`, `NL80211_CHAN_*`, `NL80211_CMD_*` constants:**  These are extensive definitions related to the `nl80211` Netlink family, which is used for configuring and controlling Wi-Fi devices.

Based on the constant and struct definitions, this part of the file primarily deals with **defining data structures and constants related to various Linux kernel subsystems and hardware interfaces.**  It provides the building blocks for Go programs to interact with these low-level functionalities.

**Hypothesized Go Functionality and Examples:**

This file doesn't implement a specific high-level Go feature directly. Instead, it provides the necessary type definitions for interacting with lower-level Linux kernel APIs. The `golang.org/x/sys/unix` package provides functions that use these types to make system calls or interact with kernel modules.

**Example 1: Using `ETHTOOL_LINK_MODE_*` constants to check link capabilities (Hypothetical):**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Assuming there's a function in "golang.org/x/sys/unix" to get ethtool info
// that includes supported link modes. This is a simplification.
// In reality, it involves ioctl calls with specific ethtool commands.
func getEthtoolLinkModes(iface string) (uint64, error) {
	// This is a placeholder, the actual implementation would be more complex.
	// It would likely involve opening a socket and using ioctl with ETHTOOL commands.
	// For demonstration purposes, we'll just return a hardcoded value.
	return uint64(0x1FFFFFFFFFFFF), nil // Assuming all link modes are supported
}

func main() {
	ifaceName := "eth0" // Replace with your interface name
	supportedModes, err := getEthtoolLinkModes(ifaceName)
	if err != nil {
		fmt.Println("Error getting link modes:", err)
		return
	}

	if (supportedModes & (1 << unix.ETHTOOL_LINK_MODE_1000baseT_Full_BIT)) != 0 {
		fmt.Printf("%s supports 1000baseT Full Duplex\n", ifaceName)
	}
	if (supportedModes & (1 << unix.ETHTOOL_LINK_MODE_100baseT_Half_BIT)) != 0 {
		fmt.Printf("%s supports 100baseT Half Duplex\n", ifaceName)
	}
	// ... check for other link modes
}
```

**Hypothetical Input/Output:**

If `getEthtoolLinkModes("eth0")` returned `0x1FFFFFFFFFFFF`, the output would include:

```
eth0 supports 1000baseT Full Duplex
eth0 supports 100baseT Half Duplex
... (and many other supported modes)
```

**Example 2: Using `NFC_CMD_*` constants for NFC interaction (Hypothetical):**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Assuming a function to send NFC commands via Netlink.
func sendNFCCommand(cmd uint16, attrs ...unix.NetlinkRouteAttr) error {
	// ... implementation using Netlink socket ...
	fmt.Printf("Sending NFC Command: 0x%x\n", cmd)
	for _, attr := range attrs {
		fmt.Printf("  Attribute Type: 0x%x, Data: %v\n", attr.Attr.Type, attr.Data)
	}
	return nil
}

func main() {
	err := sendNFCCommand(unix.NFC_CMD_GET_DEVICE)
	if err != nil {
		fmt.Println("Error sending NFC command:", err)
	}

	err = sendNFCCommand(unix.NFC_CMD_DEV_UP, unix.NetlinkRouteAttr{
		Attr: syscall.NlAttr{Type: unix.NFC_ATTR_DEVICE_INDEX},
		Data: []byte{0, 0, 0, 0}, // Assuming device index 0
	})
	if err != nil {
		fmt.Println("Error sending NFC command:", err)
	}
}
```

**Hypothetical Input/Output:**

```
Sending NFC Command: 0x1
Sending NFC Command: 0x2
  Attribute Type: 0x1, Data: [0 0 0 0]
```

**Code Reasoning:**

The examples demonstrate how the defined constants could be used in conjunction with functions (likely provided by the `golang.org/x/sys/unix` package or a higher-level library) to interact with the Linux kernel for network interface configuration and NFC communication. The constants provide symbolic names for the underlying integer values used in system calls or ioctl commands.

**Command-Line Arguments:**

This file itself doesn't handle command-line arguments. It provides type definitions. Command-line argument processing would occur in the Go programs that *use* these definitions, often in conjunction with libraries like `flag`.

**User Mistakes:**

A common mistake when working with this kind of low-level code is **incorrectly interpreting or using the constants.** For example, using a bitwise OR instead of a bitwise AND to check for a specific link mode, or passing the wrong constant value to a system call.

**Example of a potential mistake:**

```go
// Incorrectly checking if 1000baseT Full is supported (using OR instead of AND)
if (supportedModes | (1 << unix.ETHTOOL_LINK_MODE_1000baseT_Full_BIT)) != 0 {
    fmt.Println("This check is likely incorrect.")
}
```

This incorrect check would always evaluate to true if `supportedModes` has *any* bits set, not just the specific bit for 1000baseT Full.

**Summary of Functionality (Part 3):**

This section of `ztypes_linux.go` defines a large set of **constants and structures** primarily related to the **`ethtool` interface for network device configuration, hardware timestamping, Precision Time Protocol (PTP), raw HID devices, range closing of file descriptors, Netlink error messages, Memory Technology Devices (MTD), Near-Field Communication (NFC), Landlock security features, Inter-Process Communication (IPC), mount attributes, WireGuard VPN, generic Netlink attributes, Controller Area Network (CAN) bus, Kernel Connection Multiplexor (KCM), and the `nl80211` interface for Wi-Fi.** It provides the necessary low-level type definitions for Go programs to interact with these Linux kernel subsystems and hardware features. This part focuses heavily on network-related functionalities and also includes definitions for other hardware and security features.

这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go的go语言实现的一部分，其功能是定义了与Linux操作系统相关的多种底层系统调用和接口中使用到的**常量**和**数据结构 (struct)**。

具体来说，这部分代码主要涵盖了以下几个方面的定义：

1. **ETHTOOL相关的常量:**  `ETHTOOL_LINK_MODE_*`, `ETHTOOL_MSG_*`, `ETHTOOL_FLAG_*`, `ETHTOOL_A_*` 等常量定义了与 `ethtool` 工具交互时使用的链路模式、消息类型、标志位和属性类型。`ethtool` 是一个Linux下用于显示和修改网络接口卡设置的命令行工具。

2. **`EthtoolDrvinfo` 和 `EthtoolTsInfo` 结构体:** 定义了用于获取网络驱动信息和时间戳信息的结构。

3. **硬件时间戳相关的常量和结构体:** `HWTSTAMP_FILTER_*`, `HWTSTAMP_TX_*` 常量以及 `HwTstampConfig` 结构体用于配置和获取网络接口卡的硬件时间戳功能。

4. **PTP (Precision Time Protocol) 相关的常量和结构体:**  `PtpClockCaps`, `PtpClockTime`, `PtpExttsEvent` 等结构体和 `PTP_PF_*` 常量用于与PTP硬件时钟交互。

5. **HID (Human Interface Device) 相关的结构体:** `HIDRawReportDescriptor` 和 `HIDRawDevInfo` 定义了与原始HID设备交互时使用的数据结构。

6. **`CLOSE_RANGE_*` 常量:**  定义了 `close_range` 系统调用的标志位，用于批量关闭文件描述符。

7. **Netlink 错误消息相关的常量:** `NLMSGERR_ATTR_*` 定义了Netlink错误消息中属性的类型。

8. **MTD (Memory Technology Device) 相关的常量和结构体:** `EraseInfo`, `MtdOobBuf`, `MtdInfo` 等结构体和 `MTD_OPS_*`, `MTD_FILE_MODE_*` 常量用于与 Flash 存储设备交互。

9. **NFC (Near-Field Communication) 相关的常量:** `NFC_CMD_*`, `NFC_EVENT_*`, `NFC_ATTR_*`, `NFC_SDP_ATTR_*` 定义了与NFC子系统交互时使用的命令、事件和属性。

10. **Landlock 相关的常量和结构体:** `LandlockRulesetAttr`, `LandlockPathBeneathAttr` 结构体和 `LANDLOCK_RULE_*` 常量用于配置 Landlock 安全模块，限制进程的文件系统访问权限。

11. **IPC (Inter-Process Communication) 相关的常量:** `IPC_CREAT`, `IPC_EXCL`, `SHM_RDONLY` 等常量用于控制进程间通信，例如共享内存。

12. **`MountAttr` 结构体:** 定义了 `mount` 系统调用的属性。

13. **WireGuard 相关的常量:** `WG_CMD_*`, `WGDEVICE_A_*`, `WGPEER_A_*`, `WGALLOWEDIP_A_*` 定义了与 WireGuard VPN 交互时使用的命令和属性。

14. **Netlink 通用属性相关的常量:** `NL_ATTR_TYPE_*`, `NL_POLICY_TYPE_ATTR_*` 定义了 Netlink 消息中属性的类型和策略。

15. **CAN (Controller Area Network) 总线相关的结构体和常量:** `CANBitTiming`, `CANCtrlMode` 等结构体和 `CAN_STATE_*`, `IFLA_CAN_*` 常量用于配置和监控 CAN 总线设备。

16. **KCM (Kernel Connection Multiplexor) 相关的结构体:** `KCMAttach`, `KCMUnattach`, `KCMClone` 定义了与 KCM 相关的操作。

17. **`nl80211` 相关的常量:** `NL80211_AC_*`, `NL80211_ATTR_*`, `NL80211_CMD_*` 等常量定义了与 `nl80211` Netlink 协议族交互时使用的属性、命令和定义，用于配置和管理 Wi-Fi 设备。

**它可以推理出这是 Go 语言为了能够与 Linux 内核的各种功能进行交互而定义的一些底层的数据结构和常量。**  这些定义使得 Go 程序可以直接调用 Linux 的系统调用或者通过 Netlink 等接口与内核模块通信。

**Go 代码示例 (假设):**

由于这部分代码主要是定义，实际使用时会配合 `golang.org/x/sys/unix` 包提供的函数进行系统调用或者 Netlink 消息的构建和解析。以下是一些假设的示例，展示如何使用这些常量：

**示例 1: 获取网络接口的驱动信息:**

```go
package main

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	ifaceName := "eth0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Println("Error getting interface:", err)
		return
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer unix.Close(fd)

	var ethtoolReq unix.Ifreq
	copy(ethtoolReq.Name[:], iface.Name)
	ethtoolReqP := unsafe.Pointer(&ethtoolReq)

	var drvInfo unix.EthtoolDrvinfo
	drvInfo.Cmd = unix.ETHTOOL_GDRVINFO
	ethtoolReq.Data = (*byte)(unsafe.Pointer(&drvInfo))

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(ethtoolReqP))
	if errno != 0 {
		fmt.Println("IOCTL error:", errno)
		return
	}

	fmt.Printf("Driver: %s\n", string(drvInfo.Driver[:]))
	fmt.Printf("Version: %s\n", string(drvInfo.Version[:]))
}
```

**假设的输出:**

```
Driver: r8169
Version: 5.15.0-78-generic
```

**代码推理:**

此示例演示了如何使用 `EthtoolDrvinfo` 结构体和 `ETHTOOL_GDRVINFO` 常量来通过 `ioctl` 系统调用获取网络接口的驱动信息。  `unix.Ifreq` 结构体用于传递接口名和数据指针。

**示例 2: 开启 NFC 设备 (假设使用 Netlink):**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	// 假设存在一个函数用于发送 Netlink 消息
	err := sendNFCCommand(unix.NFC_CMD_DEV_UP, []syscall.NetlinkRouteAttr{
		{
			Attr: syscall.NlAttr{Type: unix.NFC_ATTR_DEVICE_INDEX},
			Data: []byte{0, 0, 0, 0}, // 假设设备索引为 0
		},
	})
	if err != nil {
		fmt.Println("Error sending NFC command:", err)
	}
}

// 假设的发送 Netlink 消息的函数
func sendNFCCommand(cmd uint16, attrs []syscall.NetlinkRouteAttr) error {
	fmt.Printf("Sending NFC command: 0x%x\n", cmd)
	for _, attr := range attrs {
		fmt.Printf("  Attribute Type: 0x%x, Data: %v\n", attr.Attr.Type, attr.Data)
	}
	// ... 实际的 Netlink 消息构建和发送逻辑 ...
	return nil
}
```

**假设的输出:**

```
Sending NFC command: 0x2
  Attribute Type: 0x1, Data: [0 0 0 0]
```

**代码推理:**

此示例演示了如何使用 `NFC_CMD_DEV_UP` 和 `NFC_ATTR_DEVICE_INDEX` 常量来构建一个 Netlink 消息，用于启动 NFC 设备。

**命令行参数的具体处理:**

这部分代码本身不处理命令行参数。命令行参数的处理通常发生在使用了这些定义的 Go 语言程序中，可以使用 `flag` 标准库或者第三方库来实现。例如，一个程序可能会使用 `flag` 来接收网络接口名作为参数，然后使用这里定义的常量来获取该接口的特定信息。

**使用者易犯错的点:**

1. **常量值的误用:**  例如，错误地将不同的 `ETHTOOL_LINK_MODE_*` 常量进行位运算，导致逻辑错误。
2. **结构体字段的理解偏差:**  不清楚各个结构体字段的具体含义和单位，导致传递错误的数据。
3. **系统调用或 Netlink 消息构建错误:**  在使用这些常量和结构体进行系统调用或构建 Netlink 消息时，参数顺序、大小或类型错误。

**示例 (易错点):**

```go
// 错误地使用 ETHTOOL_LINK_MODE 常量进行判断
func checkLinkMode(supportedModes uint64) {
	if supportedModes | unix.ETHTOOL_LINK_MODE_1000baseT_Full_BIT != 0 { // 错误地使用了 | 运算符
		fmt.Println("1000baseT Full Duplex is supported") // 这可能不是期望的结果
	}
}
```

正确的做法是使用 `&` 运算符进行位与操作来检查特定的 bit 是否被设置。

**归纳一下它的功能 (第3部分):**

这部分 `ztypes_linux.go` 文件的主要功能是定义了大量的 **常量** 和 **数据结构 (struct)**，这些定义是 Go 语言程序与 Linux 内核进行底层交互的基础。它涵盖了网络设备配置 (`ethtool`), 硬件时间戳, 精确时间协议 (PTP), 人机接口设备 (HID), 文件描述符管理, Netlink 消息, 闪存设备 (MTD), 近场通信 (NFC), 进程安全 (Landlock), 进程间通信 (IPC), 文件系统挂载, VPN (WireGuard), 网络配置 (Netlink), CAN 总线通信以及 Wi-Fi 设备管理 (`nl80211`) 等多个 Linux 子系统和硬件接口的定义。 这些定义使得 Go 程序能够以类型安全的方式访问和操作 Linux 底层的各项功能。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共4部分，请归纳一下它的功能

"""
ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT                                 = 0x18
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT                                 = 0x19
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT                                 = 0x1a
	ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT                                 = 0x1b
	ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT                                 = 0x1c
	ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT                                 = 0x1d
	ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT                                 = 0x1e
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT                                  = 0x1f
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT                                  = 0x20
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT                                  = 0x21
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT                                 = 0x22
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT                                 = 0x23
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT                                = 0x24
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT                                = 0x25
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT                                = 0x26
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT                            = 0x27
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT                                 = 0x28
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT                                    = 0x29
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT                                  = 0x2a
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT                                  = 0x2b
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT                                  = 0x2c
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT                                 = 0x2d
	ETHTOOL_LINK_MODE_10000baseER_Full_BIT                                  = 0x2e
	ETHTOOL_LINK_MODE_2500baseT_Full_BIT                                    = 0x2f
	ETHTOOL_LINK_MODE_5000baseT_Full_BIT                                    = 0x30
	ETHTOOL_LINK_MODE_FEC_NONE_BIT                                          = 0x31
	ETHTOOL_LINK_MODE_FEC_RS_BIT                                            = 0x32
	ETHTOOL_LINK_MODE_FEC_BASER_BIT                                         = 0x33
	ETHTOOL_LINK_MODE_50000baseKR_Full_BIT                                  = 0x34
	ETHTOOL_LINK_MODE_50000baseSR_Full_BIT                                  = 0x35
	ETHTOOL_LINK_MODE_50000baseCR_Full_BIT                                  = 0x36
	ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT                            = 0x37
	ETHTOOL_LINK_MODE_50000baseDR_Full_BIT                                  = 0x38
	ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT                                = 0x39
	ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT                                = 0x3a
	ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT                                = 0x3b
	ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT                        = 0x3c
	ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT                                = 0x3d
	ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT                                = 0x3e
	ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT                                = 0x3f
	ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT                        = 0x40
	ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT                                = 0x41
	ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT                                = 0x42
	ETHTOOL_LINK_MODE_100baseT1_Full_BIT                                    = 0x43
	ETHTOOL_LINK_MODE_1000baseT1_Full_BIT                                   = 0x44
	ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT                                = 0x45
	ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT                                = 0x46
	ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT                        = 0x47
	ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT                                = 0x48
	ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT                                = 0x49
	ETHTOOL_LINK_MODE_FEC_LLRS_BIT                                          = 0x4a
	ETHTOOL_LINK_MODE_100000baseKR_Full_BIT                                 = 0x4b
	ETHTOOL_LINK_MODE_100000baseSR_Full_BIT                                 = 0x4c
	ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT                           = 0x4d
	ETHTOOL_LINK_MODE_100000baseCR_Full_BIT                                 = 0x4e
	ETHTOOL_LINK_MODE_100000baseDR_Full_BIT                                 = 0x4f
	ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT                                = 0x50
	ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT                                = 0x51
	ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT                        = 0x52
	ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT                                = 0x53
	ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT                                = 0x54
	ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT                                = 0x55
	ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT                                = 0x56
	ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT                        = 0x57
	ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT                                = 0x58
	ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT                                = 0x59
	ETHTOOL_LINK_MODE_100baseFX_Half_BIT                                    = 0x5a
	ETHTOOL_LINK_MODE_100baseFX_Full_BIT                                    = 0x5b

	ETHTOOL_MSG_USER_NONE                     = 0x0
	ETHTOOL_MSG_STRSET_GET                    = 0x1
	ETHTOOL_MSG_LINKINFO_GET                  = 0x2
	ETHTOOL_MSG_LINKINFO_SET                  = 0x3
	ETHTOOL_MSG_LINKMODES_GET                 = 0x4
	ETHTOOL_MSG_LINKMODES_SET                 = 0x5
	ETHTOOL_MSG_LINKSTATE_GET                 = 0x6
	ETHTOOL_MSG_DEBUG_GET                     = 0x7
	ETHTOOL_MSG_DEBUG_SET                     = 0x8
	ETHTOOL_MSG_WOL_GET                       = 0x9
	ETHTOOL_MSG_WOL_SET                       = 0xa
	ETHTOOL_MSG_FEATURES_GET                  = 0xb
	ETHTOOL_MSG_FEATURES_SET                  = 0xc
	ETHTOOL_MSG_PRIVFLAGS_GET                 = 0xd
	ETHTOOL_MSG_PRIVFLAGS_SET                 = 0xe
	ETHTOOL_MSG_RINGS_GET                     = 0xf
	ETHTOOL_MSG_RINGS_SET                     = 0x10
	ETHTOOL_MSG_CHANNELS_GET                  = 0x11
	ETHTOOL_MSG_CHANNELS_SET                  = 0x12
	ETHTOOL_MSG_COALESCE_GET                  = 0x13
	ETHTOOL_MSG_COALESCE_SET                  = 0x14
	ETHTOOL_MSG_PAUSE_GET                     = 0x15
	ETHTOOL_MSG_PAUSE_SET                     = 0x16
	ETHTOOL_MSG_EEE_GET                       = 0x17
	ETHTOOL_MSG_EEE_SET                       = 0x18
	ETHTOOL_MSG_TSINFO_GET                    = 0x19
	ETHTOOL_MSG_CABLE_TEST_ACT                = 0x1a
	ETHTOOL_MSG_CABLE_TEST_TDR_ACT            = 0x1b
	ETHTOOL_MSG_TUNNEL_INFO_GET               = 0x1c
	ETHTOOL_MSG_FEC_GET                       = 0x1d
	ETHTOOL_MSG_FEC_SET                       = 0x1e
	ETHTOOL_MSG_MODULE_EEPROM_GET             = 0x1f
	ETHTOOL_MSG_STATS_GET                     = 0x20
	ETHTOOL_MSG_PHC_VCLOCKS_GET               = 0x21
	ETHTOOL_MSG_MODULE_GET                    = 0x22
	ETHTOOL_MSG_MODULE_SET                    = 0x23
	ETHTOOL_MSG_PSE_GET                       = 0x24
	ETHTOOL_MSG_PSE_SET                       = 0x25
	ETHTOOL_MSG_RSS_GET                       = 0x26
	ETHTOOL_MSG_USER_MAX                      = 0x2d
	ETHTOOL_MSG_KERNEL_NONE                   = 0x0
	ETHTOOL_MSG_STRSET_GET_REPLY              = 0x1
	ETHTOOL_MSG_LINKINFO_GET_REPLY            = 0x2
	ETHTOOL_MSG_LINKINFO_NTF                  = 0x3
	ETHTOOL_MSG_LINKMODES_GET_REPLY           = 0x4
	ETHTOOL_MSG_LINKMODES_NTF                 = 0x5
	ETHTOOL_MSG_LINKSTATE_GET_REPLY           = 0x6
	ETHTOOL_MSG_DEBUG_GET_REPLY               = 0x7
	ETHTOOL_MSG_DEBUG_NTF                     = 0x8
	ETHTOOL_MSG_WOL_GET_REPLY                 = 0x9
	ETHTOOL_MSG_WOL_NTF                       = 0xa
	ETHTOOL_MSG_FEATURES_GET_REPLY            = 0xb
	ETHTOOL_MSG_FEATURES_SET_REPLY            = 0xc
	ETHTOOL_MSG_FEATURES_NTF                  = 0xd
	ETHTOOL_MSG_PRIVFLAGS_GET_REPLY           = 0xe
	ETHTOOL_MSG_PRIVFLAGS_NTF                 = 0xf
	ETHTOOL_MSG_RINGS_GET_REPLY               = 0x10
	ETHTOOL_MSG_RINGS_NTF                     = 0x11
	ETHTOOL_MSG_CHANNELS_GET_REPLY            = 0x12
	ETHTOOL_MSG_CHANNELS_NTF                  = 0x13
	ETHTOOL_MSG_COALESCE_GET_REPLY            = 0x14
	ETHTOOL_MSG_COALESCE_NTF                  = 0x15
	ETHTOOL_MSG_PAUSE_GET_REPLY               = 0x16
	ETHTOOL_MSG_PAUSE_NTF                     = 0x17
	ETHTOOL_MSG_EEE_GET_REPLY                 = 0x18
	ETHTOOL_MSG_EEE_NTF                       = 0x19
	ETHTOOL_MSG_TSINFO_GET_REPLY              = 0x1a
	ETHTOOL_MSG_CABLE_TEST_NTF                = 0x1b
	ETHTOOL_MSG_CABLE_TEST_TDR_NTF            = 0x1c
	ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY         = 0x1d
	ETHTOOL_MSG_FEC_GET_REPLY                 = 0x1e
	ETHTOOL_MSG_FEC_NTF                       = 0x1f
	ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY       = 0x20
	ETHTOOL_MSG_STATS_GET_REPLY               = 0x21
	ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY         = 0x22
	ETHTOOL_MSG_MODULE_GET_REPLY              = 0x23
	ETHTOOL_MSG_MODULE_NTF                    = 0x24
	ETHTOOL_MSG_PSE_GET_REPLY                 = 0x25
	ETHTOOL_MSG_RSS_GET_REPLY                 = 0x26
	ETHTOOL_MSG_KERNEL_MAX                    = 0x2e
	ETHTOOL_FLAG_COMPACT_BITSETS              = 0x1
	ETHTOOL_FLAG_OMIT_REPLY                   = 0x2
	ETHTOOL_FLAG_STATS                        = 0x4
	ETHTOOL_A_HEADER_UNSPEC                   = 0x0
	ETHTOOL_A_HEADER_DEV_INDEX                = 0x1
	ETHTOOL_A_HEADER_DEV_NAME                 = 0x2
	ETHTOOL_A_HEADER_FLAGS                    = 0x3
	ETHTOOL_A_HEADER_MAX                      = 0x4
	ETHTOOL_A_BITSET_BIT_UNSPEC               = 0x0
	ETHTOOL_A_BITSET_BIT_INDEX                = 0x1
	ETHTOOL_A_BITSET_BIT_NAME                 = 0x2
	ETHTOOL_A_BITSET_BIT_VALUE                = 0x3
	ETHTOOL_A_BITSET_BIT_MAX                  = 0x3
	ETHTOOL_A_BITSET_BITS_UNSPEC              = 0x0
	ETHTOOL_A_BITSET_BITS_BIT                 = 0x1
	ETHTOOL_A_BITSET_BITS_MAX                 = 0x1
	ETHTOOL_A_BITSET_UNSPEC                   = 0x0
	ETHTOOL_A_BITSET_NOMASK                   = 0x1
	ETHTOOL_A_BITSET_SIZE                     = 0x2
	ETHTOOL_A_BITSET_BITS                     = 0x3
	ETHTOOL_A_BITSET_VALUE                    = 0x4
	ETHTOOL_A_BITSET_MASK                     = 0x5
	ETHTOOL_A_BITSET_MAX                      = 0x5
	ETHTOOL_A_STRING_UNSPEC                   = 0x0
	ETHTOOL_A_STRING_INDEX                    = 0x1
	ETHTOOL_A_STRING_VALUE                    = 0x2
	ETHTOOL_A_STRING_MAX                      = 0x2
	ETHTOOL_A_STRINGS_UNSPEC                  = 0x0
	ETHTOOL_A_STRINGS_STRING                  = 0x1
	ETHTOOL_A_STRINGS_MAX                     = 0x1
	ETHTOOL_A_STRINGSET_UNSPEC                = 0x0
	ETHTOOL_A_STRINGSET_ID                    = 0x1
	ETHTOOL_A_STRINGSET_COUNT                 = 0x2
	ETHTOOL_A_STRINGSET_STRINGS               = 0x3
	ETHTOOL_A_STRINGSET_MAX                   = 0x3
	ETHTOOL_A_STRINGSETS_UNSPEC               = 0x0
	ETHTOOL_A_STRINGSETS_STRINGSET            = 0x1
	ETHTOOL_A_STRINGSETS_MAX                  = 0x1
	ETHTOOL_A_STRSET_UNSPEC                   = 0x0
	ETHTOOL_A_STRSET_HEADER                   = 0x1
	ETHTOOL_A_STRSET_STRINGSETS               = 0x2
	ETHTOOL_A_STRSET_COUNTS_ONLY              = 0x3
	ETHTOOL_A_STRSET_MAX                      = 0x3
	ETHTOOL_A_LINKINFO_UNSPEC                 = 0x0
	ETHTOOL_A_LINKINFO_HEADER                 = 0x1
	ETHTOOL_A_LINKINFO_PORT                   = 0x2
	ETHTOOL_A_LINKINFO_PHYADDR                = 0x3
	ETHTOOL_A_LINKINFO_TP_MDIX                = 0x4
	ETHTOOL_A_LINKINFO_TP_MDIX_CTRL           = 0x5
	ETHTOOL_A_LINKINFO_TRANSCEIVER            = 0x6
	ETHTOOL_A_LINKINFO_MAX                    = 0x6
	ETHTOOL_A_LINKMODES_UNSPEC                = 0x0
	ETHTOOL_A_LINKMODES_HEADER                = 0x1
	ETHTOOL_A_LINKMODES_AUTONEG               = 0x2
	ETHTOOL_A_LINKMODES_OURS                  = 0x3
	ETHTOOL_A_LINKMODES_PEER                  = 0x4
	ETHTOOL_A_LINKMODES_SPEED                 = 0x5
	ETHTOOL_A_LINKMODES_DUPLEX                = 0x6
	ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG      = 0x7
	ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE    = 0x8
	ETHTOOL_A_LINKMODES_LANES                 = 0x9
	ETHTOOL_A_LINKMODES_RATE_MATCHING         = 0xa
	ETHTOOL_A_LINKMODES_MAX                   = 0xa
	ETHTOOL_A_LINKSTATE_UNSPEC                = 0x0
	ETHTOOL_A_LINKSTATE_HEADER                = 0x1
	ETHTOOL_A_LINKSTATE_LINK                  = 0x2
	ETHTOOL_A_LINKSTATE_SQI                   = 0x3
	ETHTOOL_A_LINKSTATE_SQI_MAX               = 0x4
	ETHTOOL_A_LINKSTATE_EXT_STATE             = 0x5
	ETHTOOL_A_LINKSTATE_EXT_SUBSTATE          = 0x6
	ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT          = 0x7
	ETHTOOL_A_LINKSTATE_MAX                   = 0x7
	ETHTOOL_A_DEBUG_UNSPEC                    = 0x0
	ETHTOOL_A_DEBUG_HEADER                    = 0x1
	ETHTOOL_A_DEBUG_MSGMASK                   = 0x2
	ETHTOOL_A_DEBUG_MAX                       = 0x2
	ETHTOOL_A_WOL_UNSPEC                      = 0x0
	ETHTOOL_A_WOL_HEADER                      = 0x1
	ETHTOOL_A_WOL_MODES                       = 0x2
	ETHTOOL_A_WOL_SOPASS                      = 0x3
	ETHTOOL_A_WOL_MAX                         = 0x3
	ETHTOOL_A_FEATURES_UNSPEC                 = 0x0
	ETHTOOL_A_FEATURES_HEADER                 = 0x1
	ETHTOOL_A_FEATURES_HW                     = 0x2
	ETHTOOL_A_FEATURES_WANTED                 = 0x3
	ETHTOOL_A_FEATURES_ACTIVE                 = 0x4
	ETHTOOL_A_FEATURES_NOCHANGE               = 0x5
	ETHTOOL_A_FEATURES_MAX                    = 0x5
	ETHTOOL_A_PRIVFLAGS_UNSPEC                = 0x0
	ETHTOOL_A_PRIVFLAGS_HEADER                = 0x1
	ETHTOOL_A_PRIVFLAGS_FLAGS                 = 0x2
	ETHTOOL_A_PRIVFLAGS_MAX                   = 0x2
	ETHTOOL_A_RINGS_UNSPEC                    = 0x0
	ETHTOOL_A_RINGS_HEADER                    = 0x1
	ETHTOOL_A_RINGS_RX_MAX                    = 0x2
	ETHTOOL_A_RINGS_RX_MINI_MAX               = 0x3
	ETHTOOL_A_RINGS_RX_JUMBO_MAX              = 0x4
	ETHTOOL_A_RINGS_TX_MAX                    = 0x5
	ETHTOOL_A_RINGS_RX                        = 0x6
	ETHTOOL_A_RINGS_RX_MINI                   = 0x7
	ETHTOOL_A_RINGS_RX_JUMBO                  = 0x8
	ETHTOOL_A_RINGS_TX                        = 0x9
	ETHTOOL_A_RINGS_RX_BUF_LEN                = 0xa
	ETHTOOL_A_RINGS_TCP_DATA_SPLIT            = 0xb
	ETHTOOL_A_RINGS_CQE_SIZE                  = 0xc
	ETHTOOL_A_RINGS_TX_PUSH                   = 0xd
	ETHTOOL_A_RINGS_MAX                       = 0x10
	ETHTOOL_A_CHANNELS_UNSPEC                 = 0x0
	ETHTOOL_A_CHANNELS_HEADER                 = 0x1
	ETHTOOL_A_CHANNELS_RX_MAX                 = 0x2
	ETHTOOL_A_CHANNELS_TX_MAX                 = 0x3
	ETHTOOL_A_CHANNELS_OTHER_MAX              = 0x4
	ETHTOOL_A_CHANNELS_COMBINED_MAX           = 0x5
	ETHTOOL_A_CHANNELS_RX_COUNT               = 0x6
	ETHTOOL_A_CHANNELS_TX_COUNT               = 0x7
	ETHTOOL_A_CHANNELS_OTHER_COUNT            = 0x8
	ETHTOOL_A_CHANNELS_COMBINED_COUNT         = 0x9
	ETHTOOL_A_CHANNELS_MAX                    = 0x9
	ETHTOOL_A_COALESCE_UNSPEC                 = 0x0
	ETHTOOL_A_COALESCE_HEADER                 = 0x1
	ETHTOOL_A_COALESCE_RX_USECS               = 0x2
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES          = 0x3
	ETHTOOL_A_COALESCE_RX_USECS_IRQ           = 0x4
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ      = 0x5
	ETHTOOL_A_COALESCE_TX_USECS               = 0x6
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES          = 0x7
	ETHTOOL_A_COALESCE_TX_USECS_IRQ           = 0x8
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ      = 0x9
	ETHTOOL_A_COALESCE_STATS_BLOCK_USECS      = 0xa
	ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX        = 0xb
	ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX        = 0xc
	ETHTOOL_A_COALESCE_PKT_RATE_LOW           = 0xd
	ETHTOOL_A_COALESCE_RX_USECS_LOW           = 0xe
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW      = 0xf
	ETHTOOL_A_COALESCE_TX_USECS_LOW           = 0x10
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW      = 0x11
	ETHTOOL_A_COALESCE_PKT_RATE_HIGH          = 0x12
	ETHTOOL_A_COALESCE_RX_USECS_HIGH          = 0x13
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH     = 0x14
	ETHTOOL_A_COALESCE_TX_USECS_HIGH          = 0x15
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH     = 0x16
	ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL   = 0x17
	ETHTOOL_A_COALESCE_USE_CQE_MODE_TX        = 0x18
	ETHTOOL_A_COALESCE_USE_CQE_MODE_RX        = 0x19
	ETHTOOL_A_COALESCE_MAX                    = 0x1e
	ETHTOOL_A_PAUSE_UNSPEC                    = 0x0
	ETHTOOL_A_PAUSE_HEADER                    = 0x1
	ETHTOOL_A_PAUSE_AUTONEG                   = 0x2
	ETHTOOL_A_PAUSE_RX                        = 0x3
	ETHTOOL_A_PAUSE_TX                        = 0x4
	ETHTOOL_A_PAUSE_STATS                     = 0x5
	ETHTOOL_A_PAUSE_MAX                       = 0x6
	ETHTOOL_A_PAUSE_STAT_UNSPEC               = 0x0
	ETHTOOL_A_PAUSE_STAT_PAD                  = 0x1
	ETHTOOL_A_PAUSE_STAT_TX_FRAMES            = 0x2
	ETHTOOL_A_PAUSE_STAT_RX_FRAMES            = 0x3
	ETHTOOL_A_PAUSE_STAT_MAX                  = 0x3
	ETHTOOL_A_EEE_UNSPEC                      = 0x0
	ETHTOOL_A_EEE_HEADER                      = 0x1
	ETHTOOL_A_EEE_MODES_OURS                  = 0x2
	ETHTOOL_A_EEE_MODES_PEER                  = 0x3
	ETHTOOL_A_EEE_ACTIVE                      = 0x4
	ETHTOOL_A_EEE_ENABLED                     = 0x5
	ETHTOOL_A_EEE_TX_LPI_ENABLED              = 0x6
	ETHTOOL_A_EEE_TX_LPI_TIMER                = 0x7
	ETHTOOL_A_EEE_MAX                         = 0x7
	ETHTOOL_A_TSINFO_UNSPEC                   = 0x0
	ETHTOOL_A_TSINFO_HEADER                   = 0x1
	ETHTOOL_A_TSINFO_TIMESTAMPING             = 0x2
	ETHTOOL_A_TSINFO_TX_TYPES                 = 0x3
	ETHTOOL_A_TSINFO_RX_FILTERS               = 0x4
	ETHTOOL_A_TSINFO_PHC_INDEX                = 0x5
	ETHTOOL_A_TSINFO_MAX                      = 0x6
	ETHTOOL_A_CABLE_TEST_UNSPEC               = 0x0
	ETHTOOL_A_CABLE_TEST_HEADER               = 0x1
	ETHTOOL_A_CABLE_TEST_MAX                  = 0x1
	ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC        = 0x0
	ETHTOOL_A_CABLE_RESULT_CODE_OK            = 0x1
	ETHTOOL_A_CABLE_RESULT_CODE_OPEN          = 0x2
	ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT    = 0x3
	ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT   = 0x4
	ETHTOOL_A_CABLE_PAIR_A                    = 0x0
	ETHTOOL_A_CABLE_PAIR_B                    = 0x1
	ETHTOOL_A_CABLE_PAIR_C                    = 0x2
	ETHTOOL_A_CABLE_PAIR_D                    = 0x3
	ETHTOOL_A_CABLE_RESULT_UNSPEC             = 0x0
	ETHTOOL_A_CABLE_RESULT_PAIR               = 0x1
	ETHTOOL_A_CABLE_RESULT_CODE               = 0x2
	ETHTOOL_A_CABLE_RESULT_MAX                = 0x3
	ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC       = 0x0
	ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR         = 0x1
	ETHTOOL_A_CABLE_FAULT_LENGTH_CM           = 0x2
	ETHTOOL_A_CABLE_FAULT_LENGTH_MAX          = 0x3
	ETHTOOL_A_CABLE_TEST_NTF_STATUS_UNSPEC    = 0x0
	ETHTOOL_A_CABLE_TEST_NTF_STATUS_STARTED   = 0x1
	ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED = 0x2
	ETHTOOL_A_CABLE_NEST_UNSPEC               = 0x0
	ETHTOOL_A_CABLE_NEST_RESULT               = 0x1
	ETHTOOL_A_CABLE_NEST_FAULT_LENGTH         = 0x2
	ETHTOOL_A_CABLE_NEST_MAX                  = 0x2
	ETHTOOL_A_CABLE_TEST_NTF_UNSPEC           = 0x0
	ETHTOOL_A_CABLE_TEST_NTF_HEADER           = 0x1
	ETHTOOL_A_CABLE_TEST_NTF_STATUS           = 0x2
	ETHTOOL_A_CABLE_TEST_NTF_NEST             = 0x3
	ETHTOOL_A_CABLE_TEST_NTF_MAX              = 0x3
	ETHTOOL_A_CABLE_TEST_TDR_CFG_UNSPEC       = 0x0
	ETHTOOL_A_CABLE_TEST_TDR_CFG_FIRST        = 0x1
	ETHTOOL_A_CABLE_TEST_TDR_CFG_LAST         = 0x2
	ETHTOOL_A_CABLE_TEST_TDR_CFG_STEP         = 0x3
	ETHTOOL_A_CABLE_TEST_TDR_CFG_PAIR         = 0x4
	ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX          = 0x4
	ETHTOOL_A_CABLE_TEST_TDR_UNSPEC           = 0x0
	ETHTOOL_A_CABLE_TEST_TDR_HEADER           = 0x1
	ETHTOOL_A_CABLE_TEST_TDR_CFG              = 0x2
	ETHTOOL_A_CABLE_TEST_TDR_MAX              = 0x2
	ETHTOOL_A_CABLE_AMPLITUDE_UNSPEC          = 0x0
	ETHTOOL_A_CABLE_AMPLITUDE_PAIR            = 0x1
	ETHTOOL_A_CABLE_AMPLITUDE_mV              = 0x2
	ETHTOOL_A_CABLE_AMPLITUDE_MAX             = 0x2
	ETHTOOL_A_CABLE_PULSE_UNSPEC              = 0x0
	ETHTOOL_A_CABLE_PULSE_mV                  = 0x1
	ETHTOOL_A_CABLE_PULSE_MAX                 = 0x1
	ETHTOOL_A_CABLE_STEP_UNSPEC               = 0x0
	ETHTOOL_A_CABLE_STEP_FIRST_DISTANCE       = 0x1
	ETHTOOL_A_CABLE_STEP_LAST_DISTANCE        = 0x2
	ETHTOOL_A_CABLE_STEP_STEP_DISTANCE        = 0x3
	ETHTOOL_A_CABLE_STEP_MAX                  = 0x3
	ETHTOOL_A_CABLE_TDR_NEST_UNSPEC           = 0x0
	ETHTOOL_A_CABLE_TDR_NEST_STEP             = 0x1
	ETHTOOL_A_CABLE_TDR_NEST_AMPLITUDE        = 0x2
	ETHTOOL_A_CABLE_TDR_NEST_PULSE            = 0x3
	ETHTOOL_A_CABLE_TDR_NEST_MAX              = 0x3
	ETHTOOL_A_CABLE_TEST_TDR_NTF_UNSPEC       = 0x0
	ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER       = 0x1
	ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS       = 0x2
	ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST         = 0x3
	ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX          = 0x3
	ETHTOOL_UDP_TUNNEL_TYPE_VXLAN             = 0x0
	ETHTOOL_UDP_TUNNEL_TYPE_GENEVE            = 0x1
	ETHTOOL_UDP_TUNNEL_TYPE_VXLAN_GPE         = 0x2
	ETHTOOL_A_TUNNEL_UDP_ENTRY_UNSPEC         = 0x0
	ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT           = 0x1
	ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE           = 0x2
	ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX            = 0x2
	ETHTOOL_A_TUNNEL_UDP_TABLE_UNSPEC         = 0x0
	ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE           = 0x1
	ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES          = 0x2
	ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY          = 0x3
	ETHTOOL_A_TUNNEL_UDP_TABLE_MAX            = 0x3
	ETHTOOL_A_TUNNEL_UDP_UNSPEC               = 0x0
	ETHTOOL_A_TUNNEL_UDP_TABLE                = 0x1
	ETHTOOL_A_TUNNEL_UDP_MAX                  = 0x1
	ETHTOOL_A_TUNNEL_INFO_UNSPEC              = 0x0
	ETHTOOL_A_TUNNEL_INFO_HEADER              = 0x1
	ETHTOOL_A_TUNNEL_INFO_UDP_PORTS           = 0x2
	ETHTOOL_A_TUNNEL_INFO_MAX                 = 0x2
)

const SPEED_UNKNOWN = -0x1

type EthtoolDrvinfo struct {
	Cmd          uint32
	Driver       [32]byte
	Version      [32]byte
	Fw_version   [32]byte
	Bus_info     [32]byte
	Erom_version [32]byte
	Reserved2    [12]byte
	N_priv_flags uint32
	N_stats      uint32
	Testinfo_len uint32
	Eedump_len   uint32
	Regdump_len  uint32
}

type EthtoolTsInfo struct {
	Cmd             uint32
	So_timestamping uint32
	Phc_index       int32
	Tx_types        uint32
	Tx_reserved     [3]uint32
	Rx_filters      uint32
	Rx_reserved     [3]uint32
}

type HwTstampConfig struct {
	Flags     int32
	Tx_type   int32
	Rx_filter int32
}

const (
	HWTSTAMP_FILTER_NONE            = 0x0
	HWTSTAMP_FILTER_ALL             = 0x1
	HWTSTAMP_FILTER_SOME            = 0x2
	HWTSTAMP_FILTER_PTP_V1_L4_EVENT = 0x3
	HWTSTAMP_FILTER_PTP_V2_L4_EVENT = 0x6
	HWTSTAMP_FILTER_PTP_V2_L2_EVENT = 0x9
	HWTSTAMP_FILTER_PTP_V2_EVENT    = 0xc
)

const (
	HWTSTAMP_TX_OFF          = 0x0
	HWTSTAMP_TX_ON           = 0x1
	HWTSTAMP_TX_ONESTEP_SYNC = 0x2
)

type (
	PtpClockCaps struct {
		Max_adj            int32
		N_alarm            int32
		N_ext_ts           int32
		N_per_out          int32
		Pps                int32
		N_pins             int32
		Cross_timestamping int32
		Adjust_phase       int32
		Max_phase_adj      int32
		Rsv                [11]int32
	}
	PtpClockTime struct {
		Sec      int64
		Nsec     uint32
		Reserved uint32
	}
	PtpExttsEvent struct {
		T     PtpClockTime
		Index uint32
		Flags uint32
		Rsv   [2]uint32
	}
	PtpExttsRequest struct {
		Index uint32
		Flags uint32
		Rsv   [2]uint32
	}
	PtpPeroutRequest struct {
		StartOrPhase PtpClockTime
		Period       PtpClockTime
		Index        uint32
		Flags        uint32
		On           PtpClockTime
	}
	PtpPinDesc struct {
		Name  [64]byte
		Index uint32
		Func  uint32
		Chan  uint32
		Rsv   [5]uint32
	}
	PtpSysOffset struct {
		Samples uint32
		Rsv     [3]uint32
		Ts      [51]PtpClockTime
	}
	PtpSysOffsetExtended struct {
		Samples uint32
		Clockid int32
		Rsv     [2]uint32
		Ts      [25][3]PtpClockTime
	}
	PtpSysOffsetPrecise struct {
		Device   PtpClockTime
		Realtime PtpClockTime
		Monoraw  PtpClockTime
		Rsv      [4]uint32
	}
)

const (
	PTP_PF_NONE    = 0x0
	PTP_PF_EXTTS   = 0x1
	PTP_PF_PEROUT  = 0x2
	PTP_PF_PHYSYNC = 0x3
)

type (
	HIDRawReportDescriptor struct {
		Size  uint32
		Value [4096]uint8
	}
	HIDRawDevInfo struct {
		Bustype uint32
		Vendor  int16
		Product int16
	}
)

const (
	CLOSE_RANGE_UNSHARE = 0x2
	CLOSE_RANGE_CLOEXEC = 0x4
)

const (
	NLMSGERR_ATTR_MSG    = 0x1
	NLMSGERR_ATTR_OFFS   = 0x2
	NLMSGERR_ATTR_COOKIE = 0x3
)

type (
	EraseInfo struct {
		Start  uint32
		Length uint32
	}
	EraseInfo64 struct {
		Start  uint64
		Length uint64
	}
	MtdOobBuf struct {
		Start  uint32
		Length uint32
		Ptr    *uint8
	}
	MtdOobBuf64 struct {
		Start  uint64
		Pad    uint32
		Length uint32
		Ptr    uint64
	}
	MtdWriteReq struct {
		Start  uint64
		Len    uint64
		Ooblen uint64
		Data   uint64
		Oob    uint64
		Mode   uint8
		_      [7]uint8
	}
	MtdInfo struct {
		Type      uint8
		Flags     uint32
		Size      uint32
		Erasesize uint32
		Writesize uint32
		Oobsize   uint32
		_         uint64
	}
	RegionInfo struct {
		Offset      uint32
		Erasesize   uint32
		Numblocks   uint32
		Regionindex uint32
	}
	OtpInfo struct {
		Start  uint32
		Length uint32
		Locked uint32
	}
	NandOobinfo struct {
		Useecc   uint32
		Eccbytes uint32
		Oobfree  [8][2]uint32
		Eccpos   [32]uint32
	}
	NandOobfree struct {
		Offset uint32
		Length uint32
	}
	NandEcclayout struct {
		Eccbytes uint32
		Eccpos   [64]uint32
		Oobavail uint32
		Oobfree  [8]NandOobfree
	}
	MtdEccStats struct {
		Corrected uint32
		Failed    uint32
		Badblocks uint32
		Bbtblocks uint32
	}
)

const (
	MTD_OPS_PLACE_OOB = 0x0
	MTD_OPS_AUTO_OOB  = 0x1
	MTD_OPS_RAW       = 0x2
)

const (
	MTD_FILE_MODE_NORMAL      = 0x0
	MTD_FILE_MODE_OTP_FACTORY = 0x1
	MTD_FILE_MODE_OTP_USER    = 0x2
	MTD_FILE_MODE_RAW         = 0x3
)

const (
	NFC_CMD_UNSPEC                    = 0x0
	NFC_CMD_GET_DEVICE                = 0x1
	NFC_CMD_DEV_UP                    = 0x2
	NFC_CMD_DEV_DOWN                  = 0x3
	NFC_CMD_DEP_LINK_UP               = 0x4
	NFC_CMD_DEP_LINK_DOWN             = 0x5
	NFC_CMD_START_POLL                = 0x6
	NFC_CMD_STOP_POLL                 = 0x7
	NFC_CMD_GET_TARGET                = 0x8
	NFC_EVENT_TARGETS_FOUND           = 0x9
	NFC_EVENT_DEVICE_ADDED            = 0xa
	NFC_EVENT_DEVICE_REMOVED          = 0xb
	NFC_EVENT_TARGET_LOST             = 0xc
	NFC_EVENT_TM_ACTIVATED            = 0xd
	NFC_EVENT_TM_DEACTIVATED          = 0xe
	NFC_CMD_LLC_GET_PARAMS            = 0xf
	NFC_CMD_LLC_SET_PARAMS            = 0x10
	NFC_CMD_ENABLE_SE                 = 0x11
	NFC_CMD_DISABLE_SE                = 0x12
	NFC_CMD_LLC_SDREQ                 = 0x13
	NFC_EVENT_LLC_SDRES               = 0x14
	NFC_CMD_FW_DOWNLOAD               = 0x15
	NFC_EVENT_SE_ADDED                = 0x16
	NFC_EVENT_SE_REMOVED              = 0x17
	NFC_EVENT_SE_CONNECTIVITY         = 0x18
	NFC_EVENT_SE_TRANSACTION          = 0x19
	NFC_CMD_GET_SE                    = 0x1a
	NFC_CMD_SE_IO                     = 0x1b
	NFC_CMD_ACTIVATE_TARGET           = 0x1c
	NFC_CMD_VENDOR                    = 0x1d
	NFC_CMD_DEACTIVATE_TARGET         = 0x1e
	NFC_ATTR_UNSPEC                   = 0x0
	NFC_ATTR_DEVICE_INDEX             = 0x1
	NFC_ATTR_DEVICE_NAME              = 0x2
	NFC_ATTR_PROTOCOLS                = 0x3
	NFC_ATTR_TARGET_INDEX             = 0x4
	NFC_ATTR_TARGET_SENS_RES          = 0x5
	NFC_ATTR_TARGET_SEL_RES           = 0x6
	NFC_ATTR_TARGET_NFCID1            = 0x7
	NFC_ATTR_TARGET_SENSB_RES         = 0x8
	NFC_ATTR_TARGET_SENSF_RES         = 0x9
	NFC_ATTR_COMM_MODE                = 0xa
	NFC_ATTR_RF_MODE                  = 0xb
	NFC_ATTR_DEVICE_POWERED           = 0xc
	NFC_ATTR_IM_PROTOCOLS             = 0xd
	NFC_ATTR_TM_PROTOCOLS             = 0xe
	NFC_ATTR_LLC_PARAM_LTO            = 0xf
	NFC_ATTR_LLC_PARAM_RW             = 0x10
	NFC_ATTR_LLC_PARAM_MIUX           = 0x11
	NFC_ATTR_SE                       = 0x12
	NFC_ATTR_LLC_SDP                  = 0x13
	NFC_ATTR_FIRMWARE_NAME            = 0x14
	NFC_ATTR_SE_INDEX                 = 0x15
	NFC_ATTR_SE_TYPE                  = 0x16
	NFC_ATTR_SE_AID                   = 0x17
	NFC_ATTR_FIRMWARE_DOWNLOAD_STATUS = 0x18
	NFC_ATTR_SE_APDU                  = 0x19
	NFC_ATTR_TARGET_ISO15693_DSFID    = 0x1a
	NFC_ATTR_TARGET_ISO15693_UID      = 0x1b
	NFC_ATTR_SE_PARAMS                = 0x1c
	NFC_ATTR_VENDOR_ID                = 0x1d
	NFC_ATTR_VENDOR_SUBCMD            = 0x1e
	NFC_ATTR_VENDOR_DATA              = 0x1f
	NFC_SDP_ATTR_UNSPEC               = 0x0
	NFC_SDP_ATTR_URI                  = 0x1
	NFC_SDP_ATTR_SAP                  = 0x2
)

type LandlockRulesetAttr struct {
	Access_fs  uint64
	Access_net uint64
	Scoped     uint64
}

type LandlockPathBeneathAttr struct {
	Allowed_access uint64
	Parent_fd      int32
}

const (
	LANDLOCK_RULE_PATH_BENEATH = 0x1
)

const (
	IPC_CREAT   = 0x200
	IPC_EXCL    = 0x400
	IPC_NOWAIT  = 0x800
	IPC_PRIVATE = 0x0

	ipc_64 = 0x100
)

const (
	IPC_RMID = 0x0
	IPC_SET  = 0x1
	IPC_STAT = 0x2
)

const (
	SHM_RDONLY = 0x1000
	SHM_RND    = 0x2000
)

type MountAttr struct {
	Attr_set    uint64
	Attr_clr    uint64
	Propagation uint64
	Userns_fd   uint64
}

const (
	WG_CMD_GET_DEVICE                      = 0x0
	WG_CMD_SET_DEVICE                      = 0x1
	WGDEVICE_F_REPLACE_PEERS               = 0x1
	WGDEVICE_A_UNSPEC                      = 0x0
	WGDEVICE_A_IFINDEX                     = 0x1
	WGDEVICE_A_IFNAME                      = 0x2
	WGDEVICE_A_PRIVATE_KEY                 = 0x3
	WGDEVICE_A_PUBLIC_KEY                  = 0x4
	WGDEVICE_A_FLAGS                       = 0x5
	WGDEVICE_A_LISTEN_PORT                 = 0x6
	WGDEVICE_A_FWMARK                      = 0x7
	WGDEVICE_A_PEERS                       = 0x8
	WGPEER_F_REMOVE_ME                     = 0x1
	WGPEER_F_REPLACE_ALLOWEDIPS            = 0x2
	WGPEER_F_UPDATE_ONLY                   = 0x4
	WGPEER_A_UNSPEC                        = 0x0
	WGPEER_A_PUBLIC_KEY                    = 0x1
	WGPEER_A_PRESHARED_KEY                 = 0x2
	WGPEER_A_FLAGS                         = 0x3
	WGPEER_A_ENDPOINT                      = 0x4
	WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL = 0x5
	WGPEER_A_LAST_HANDSHAKE_TIME           = 0x6
	WGPEER_A_RX_BYTES                      = 0x7
	WGPEER_A_TX_BYTES                      = 0x8
	WGPEER_A_ALLOWEDIPS                    = 0x9
	WGPEER_A_PROTOCOL_VERSION              = 0xa
	WGALLOWEDIP_A_UNSPEC                   = 0x0
	WGALLOWEDIP_A_FAMILY                   = 0x1
	WGALLOWEDIP_A_IPADDR                   = 0x2
	WGALLOWEDIP_A_CIDR_MASK                = 0x3
)

const (
	NL_ATTR_TYPE_INVALID      = 0x0
	NL_ATTR_TYPE_FLAG         = 0x1
	NL_ATTR_TYPE_U8           = 0x2
	NL_ATTR_TYPE_U16          = 0x3
	NL_ATTR_TYPE_U32          = 0x4
	NL_ATTR_TYPE_U64          = 0x5
	NL_ATTR_TYPE_S8           = 0x6
	NL_ATTR_TYPE_S16          = 0x7
	NL_ATTR_TYPE_S32          = 0x8
	NL_ATTR_TYPE_S64          = 0x9
	NL_ATTR_TYPE_BINARY       = 0xa
	NL_ATTR_TYPE_STRING       = 0xb
	NL_ATTR_TYPE_NUL_STRING   = 0xc
	NL_ATTR_TYPE_NESTED       = 0xd
	NL_ATTR_TYPE_NESTED_ARRAY = 0xe
	NL_ATTR_TYPE_BITFIELD32   = 0xf

	NL_POLICY_TYPE_ATTR_UNSPEC          = 0x0
	NL_POLICY_TYPE_ATTR_TYPE            = 0x1
	NL_POLICY_TYPE_ATTR_MIN_VALUE_S     = 0x2
	NL_POLICY_TYPE_ATTR_MAX_VALUE_S     = 0x3
	NL_POLICY_TYPE_ATTR_MIN_VALUE_U     = 0x4
	NL_POLICY_TYPE_ATTR_MAX_VALUE_U     = 0x5
	NL_POLICY_TYPE_ATTR_MIN_LENGTH      = 0x6
	NL_POLICY_TYPE_ATTR_MAX_LENGTH      = 0x7
	NL_POLICY_TYPE_ATTR_POLICY_IDX      = 0x8
	NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE  = 0x9
	NL_POLICY_TYPE_ATTR_BITFIELD32_MASK = 0xa
	NL_POLICY_TYPE_ATTR_PAD             = 0xb
	NL_POLICY_TYPE_ATTR_MASK            = 0xc
	NL_POLICY_TYPE_ATTR_MAX             = 0xc
)

type CANBitTiming struct {
	Bitrate      uint32
	Sample_point uint32
	Tq           uint32
	Prop_seg     uint32
	Phase_seg1   uint32
	Phase_seg2   uint32
	Sjw          uint32
	Brp          uint32
}

type CANBitTimingConst struct {
	Name      [16]uint8
	Tseg1_min uint32
	Tseg1_max uint32
	Tseg2_min uint32
	Tseg2_max uint32
	Sjw_max   uint32
	Brp_min   uint32
	Brp_max   uint32
	Brp_inc   uint32
}

type CANClock struct {
	Freq uint32
}

type CANBusErrorCounters struct {
	Txerr uint16
	Rxerr uint16
}

type CANCtrlMode struct {
	Mask  uint32
	Flags uint32
}

type CANDeviceStats struct {
	Bus_error        uint32
	Error_warning    uint32
	Error_passive    uint32
	Bus_off          uint32
	Arbitration_lost uint32
	Restarts         uint32
}

const (
	CAN_STATE_ERROR_ACTIVE  = 0x0
	CAN_STATE_ERROR_WARNING = 0x1
	CAN_STATE_ERROR_PASSIVE = 0x2
	CAN_STATE_BUS_OFF       = 0x3
	CAN_STATE_STOPPED       = 0x4
	CAN_STATE_SLEEPING      = 0x5
	CAN_STATE_MAX           = 0x6
)

const (
	IFLA_CAN_UNSPEC               = 0x0
	IFLA_CAN_BITTIMING            = 0x1
	IFLA_CAN_BITTIMING_CONST      = 0x2
	IFLA_CAN_CLOCK                = 0x3
	IFLA_CAN_STATE                = 0x4
	IFLA_CAN_CTRLMODE             = 0x5
	IFLA_CAN_RESTART_MS           = 0x6
	IFLA_CAN_RESTART              = 0x7
	IFLA_CAN_BERR_COUNTER         = 0x8
	IFLA_CAN_DATA_BITTIMING       = 0x9
	IFLA_CAN_DATA_BITTIMING_CONST = 0xa
	IFLA_CAN_TERMINATION          = 0xb
	IFLA_CAN_TERMINATION_CONST    = 0xc
	IFLA_CAN_BITRATE_CONST        = 0xd
	IFLA_CAN_DATA_BITRATE_CONST   = 0xe
	IFLA_CAN_BITRATE_MAX          = 0xf
)

type KCMAttach struct {
	Fd     int32
	Bpf_fd int32
}

type KCMUnattach struct {
	Fd int32
}

type KCMClone struct {
	Fd int32
}

const (
	NL80211_AC_BE                                           = 0x2
	NL80211_AC_BK                                           = 0x3
	NL80211_ACL_POLICY_ACCEPT_UNLESS_LISTED                 = 0x0
	NL80211_ACL_POLICY_DENY_UNLESS_LISTED                   = 0x1
	NL80211_AC_VI                                           = 0x1
	NL80211_AC_VO                                           = 0x0
	NL80211_AP_SETTINGS_EXTERNAL_AUTH_SUPPORT               = 0x1
	NL80211_AP_SETTINGS_SA_QUERY_OFFLOAD_SUPPORT            = 0x2
	NL80211_AP_SME_SA_QUERY_OFFLOAD                         = 0x1
	NL80211_ATTR_4ADDR                                      = 0x53
	NL80211_ATTR_ACK                                        = 0x5c
	NL80211_ATTR_ACK_SIGNAL                                 = 0x107
	NL80211_ATTR_ACL_POLICY                                 = 0xa5
	NL80211_ATTR_ADMITTED_TIME                              = 0xd4
	NL80211_ATTR_AIRTIME_WEIGHT                             = 0x112
	NL80211_ATTR_AKM_SUITES                                 = 0x4c
	NL80211_ATTR_AP_ISOLATE                                 = 0x60
	NL80211_ATTR_AP_SETTINGS_FLAGS                          = 0x135
	NL80211_ATTR_AUTH_DATA                                  = 0x9c
	NL80211_ATTR_AUTH_TYPE                                  = 0x35
	NL80211_ATTR_BANDS                                      = 0xef
	NL80211_ATTR_BEACON_HEAD                                = 0xe
	NL80211_ATTR_BEACON_INTERVAL                            = 0xc
	NL80211_ATTR_BEACON_TAIL                                = 0xf
	NL80211_ATTR_BG_SCAN_PERIOD                             = 0x98
	NL80211_ATTR_BSS_BASIC_RATES                            = 0x24
	NL80211_ATTR_BSS                                        = 0x2f
	NL80211_ATTR_BSS_CTS_PROT                               = 0x1c
	NL80211_ATTR_BSS_HT_OPMODE                              = 0x6d
	NL80211_ATTR_BSSID                                      = 0xf5
	NL80211_ATTR_BSS_SELECT                                 = 0xe3
	NL80211_ATTR_BSS_SHORT_PREAMBLE                         = 0x1d
	NL80211_ATTR_BSS_SHORT_SLOT_TIME                        = 0x1e
	NL80211_ATTR_CENTER_FREQ1                               = 0xa0
	NL80211_ATTR_CENTER_FREQ1_OFFSET                        = 0x123
	NL80211_ATTR_CENTER_FREQ2                               = 0xa1
	NL80211_ATTR_CHANNEL_WIDTH                              = 0x9f
	NL80211_ATTR_CH_SWITCH_BLOCK_TX                         = 0xb8
	NL80211_ATTR_CH_SWITCH_COUNT                            = 0xb7
	NL80211_ATTR_CIPHER_SUITE_GROUP                         = 0x4a
	NL80211_ATTR_CIPHER_SUITES                              = 0x39
	NL80211_ATTR_CIPHER_SUITES_PAIRWISE                     = 0x49
	NL80211_ATTR_CNTDWN_OFFS_BEACON                         = 0xba
	NL80211_ATTR_CNTDWN_OFFS_PRESP                          = 0xbb
	NL80211_ATTR_COALESCE_RULE                              = 0xb6
	NL80211_ATTR_COALESCE_RULE_CONDITION                    = 0x2
	NL80211_ATTR_COALESCE_RULE_DELAY                        = 0x1
	NL80211_ATTR_COALESCE_RULE_MAX                          = 0x3
	NL80211_ATTR_COALESCE_RULE_PKT_PATTERN                  = 0x3
	NL80211_ATTR_COLOR_CHANGE_COLOR                         = 0x130
	NL80211_ATTR_COLOR_CHANGE_COUNT                         = 0x12f
	NL80211_ATTR_COLOR_CHANGE_ELEMS                         = 0x131
	NL80211_ATTR_CONN_FAILED_REASON                         = 0x9b
	NL80211_ATTR_CONTROL_PORT                               = 0x44
	NL80211_ATTR_CONTROL_PORT_ETHERTYPE                     = 0x66
	NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT                    = 0x67
	NL80211_ATTR_CONTROL_PORT_NO_PREAUTH                    = 0x11e
	NL80211_ATTR_CONTROL_PORT_OVER_NL80211                  = 0x108
	NL80211_ATTR_COOKIE                                     = 0x58
	NL80211_ATTR_CQM_BEACON_LOSS_EVENT                      = 0x8
	NL80211_ATTR_CQM                                        = 0x5e
	NL80211_ATTR_CQM_MAX                                    = 0x9
	NL80211_ATTR_CQM_PKT_LOSS_EVENT                         = 0x4
	NL80211_ATTR_CQM_RSSI_HYST                              = 0x2
	NL80211_ATTR_CQM_RSSI_LEVEL                             = 0x9
	NL80211_ATTR_CQM_RSSI_THOLD                             = 0x1
	NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT                   = 0x3
	NL80211_ATTR_CQM_TXE_INTVL                              = 0x7
	NL80211_ATTR_CQM_TXE_PKTS                               = 0x6
	NL80211_ATTR_CQM_TXE_RATE                               = 0x5
	NL80211_ATTR_CRIT_PROT_ID                               = 0xb3
	NL80211_ATTR_CSA_C_OFF_BEACON                           = 0xba
	NL80211_ATTR_CSA_C_OFF_PRESP                            = 0xbb
	NL80211_ATTR_CSA_C_OFFSETS_TX                           = 0xcd
	NL80211_ATTR_CSA_IES                                    = 0xb9
	NL80211_ATTR_DEVICE_AP_SME                              = 0x8d
	NL80211_ATTR_DFS_CAC_TIME                               = 0x7
	NL80211_ATTR_DFS_REGION                                 = 0x92
	NL80211_ATTR_DISABLE_EHT                                = 0x137
	NL80211_ATTR_DISABLE_HE                                 = 0x12d
	NL80211_ATTR_DISABLE_HT                                 = 0x93
	NL80211_ATTR_DISABLE_VHT                                = 0xaf
	NL80211_ATTR_DISCONNECTED_BY_AP                         = 0x47
	NL80211_ATTR_DONT_WAIT_FOR_ACK                          = 0x8e
	NL80211_ATTR_DTIM_PERIOD                                = 0xd
	NL80211_ATTR_DURATION                                   = 0x57
	NL80211_ATTR_EHT_CAPABILITY                             = 0x136
	NL80211_ATTR_EML_CAPABILITY                             = 0x13d
	NL80211_ATTR_EXT_CAPA                                   = 0xa9
	NL80211_ATTR_EXT_CAPA_MASK                              = 0xaa
	NL80211_ATTR_EXTERNAL_AUTH_ACTION                       = 0x104
	NL80211_ATTR_EXTERNAL_AUTH_SUPPORT                      = 0x105
	NL80211_ATTR_EXT_FEATURES                               = 0xd9
	NL80211_ATTR_FEATURE_FLAGS                              = 0x8f
	NL80211_ATTR_FILS_CACHE_ID                              = 0xfd
	NL80211_ATTR_FILS_DISCOVERY                             = 0x126
	NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM                      = 0xfb
	NL80211_ATTR_FILS_ERP_REALM                             = 0xfa
	NL80211_ATTR_FILS_ERP_RRK                               = 0xfc
	NL80211_ATTR_FILS_ERP_USERNAME                          = 0xf9
	NL80211_ATTR_FILS_KEK                                   = 0xf2
	NL80211_ATTR_FILS_NONCES                                = 0xf3
	NL80211_ATTR_FRAME                                      = 0x33
	NL80211_ATTR_FRAME_MATCH                                = 0x5b
	NL80211_ATTR_FRAME_TYPE                                 = 0x65
	NL80211_ATTR_FREQ_AFTER                                 = 0x3b
	NL80211_ATTR_FREQ_BEFORE                                = 0x3a
	NL80211_ATTR_FREQ_FIXED                                 = 0x3c
	NL80211_ATTR_FREQ_RANGE_END                             = 0x3
	NL80211_ATTR_FREQ_RANGE_MAX_BW                          = 0x4
	NL80211_ATTR_FREQ_RANGE_START                           = 0x2
	NL80211_ATTR_FTM_RESPONDER                              = 0x10e
	NL80211_ATTR_FTM_RESPONDER_STATS                        = 0x10f
	NL80211_ATTR_GENERATION                                 = 0x2e
	NL80211_ATTR_HANDLE_DFS                                 = 0xbf
	NL80211_ATTR_HE_6GHZ_CAPABILITY                         = 0x125
	NL80211_ATTR_HE_BSS_COLOR                               = 0x11b
	NL80211_ATTR_HE_CAPABILITY                              = 0x10d
	NL80211_ATTR_HE_OBSS_PD                                 = 0x117
	NL80211_ATTR_HIDDEN_SSID                                = 0x7e
	NL80211_ATTR_HT_CAPABILITY                              = 0x1f
	NL80211_ATTR_HT_CAPABILITY_MASK                         = 0x94
	NL80211_ATTR_IE_ASSOC_RESP                              = 0x80
	NL80211_ATTR_IE                                         = 0x2a
	NL80211_ATTR_IE_PROBE_RESP                              = 0x7f
	NL80211_ATTR_IE_RIC                                     = 0xb2
	NL80211_ATTR_IFACE_SOCKET_OWNER                         = 0xcc
	NL80211_ATTR_IFINDEX                                    = 0x3
	NL80211_ATTR_IFNAME                                     = 0x4
	NL80211_ATTR_IFTYPE_AKM_SUITES                          = 0x11c
	NL80211_ATTR_IFTYPE                                     = 0x5
	NL80211_ATTR_IFTYPE_EXT_CAPA                            = 0xe6
	NL80211_ATTR_INACTIVITY_TIMEOUT                         = 0x96
	NL80211_ATTR_INTERFACE_COMBINATIONS                     = 0x78
	NL80211_ATTR_KEY_CIPHER                                 = 0x9
	NL80211_ATTR_KEY                                        = 0x50
	NL80211_ATTR_KEY_DATA                                   = 0x7
	NL80211_ATTR_KEY_DEFAULT                                = 0xb
	NL80211_ATTR_KEY_DEFAULT_MGMT                           = 0x28
	NL80211_ATTR_KEY_DEFAULT_TYPES                          = 0x6e
	NL80211_ATTR_KEY_IDX                                    = 0x8
	NL80211_ATTR_KEYS                                       = 0x51
	NL80211_ATTR_KEY_SEQ                                    = 0xa
	NL80211_ATTR_KEY_TYPE                                   = 0x37
	NL80211_ATTR_LOCAL_MESH_POWER_MODE                      = 0xa4
	NL80211_ATTR_LOCAL_STATE_CHANGE                         = 0x5f
	NL80211_ATTR_MAC_ACL_MAX                                = 0xa7
	NL80211_ATTR_MAC_ADDRS                                  = 0xa6
	NL80211_ATTR_MAC                                        = 0x6
	NL80211_ATTR_MAC_HINT                                   = 0xc8
	NL80211_ATTR_MAC_MASK                                   = 0xd7
	NL80211_ATTR_MAX_AP_ASSOC_STA                           = 0xca
	NL80211_ATTR_MAX                                        = 0x14c
	NL80211_ATTR_MAX_CRIT_PROT_DURATION                     = 0xb4
	NL80211_ATTR_MAX_CSA_COUNTERS                           = 0xce
	NL80211_ATTR_MAX_MATCH_SETS                             = 0x85
	NL80211_ATTR_MAX_NUM_AKM_SUITES                         = 0x13c
	NL80211_ATTR_MAX_NUM_PMKIDS                             = 0x56
	NL80211_ATTR_MAX_NUM_SCAN_SSIDS                         = 0x2b
	NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS                   = 0xde
	NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS                   = 0x7b
	NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION             = 0x6f
	NL80211_ATTR_MAX_SCAN_IE_LEN                            = 0x38
	NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL                     = 0xdf
	NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS                   = 0xe0
	NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN                      = 0x7c
	NL80211_ATTR_MBSSID_CONFIG                              = 0x132
	NL80211_ATTR_MBSSID_ELEMS                               = 0x133
	NL80211_ATTR_MCAST_RATE                                 = 0x6b
	NL80211_ATTR_MDID                                       = 0xb1
	NL80211_ATTR_MEASUREMENT_DURATION                       = 0xeb
	NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY             = 0xec
	NL80211_ATTR_MESH_CONFIG                                = 0x23
	NL80211_ATTR_MESH_ID                                    = 0x18
	NL80211_ATTR_MESH_PEER_AID                              = 0xed
	NL80211_ATTR_MESH_SETUP                                 = 0x70
	NL80211_ATTR_MGMT_SUBTYPE                               = 0x29
	NL80211_ATTR_MLD_ADDR                                   = 0x13a
	NL80211_ATTR_MLD_CAPA_AND_OPS                           = 0x13e
	NL80211_ATTR_MLO_LINK_ID                                = 0x139
	NL80211_ATTR_MLO_LINKS                                  = 0x138
	NL80211_ATTR_MLO_SUPPORT                                = 0x13b
	NL80211_ATTR_MNTR_FLAGS                                 = 0x17
	NL80211_ATTR_MPATH_INFO                                 = 0x1b
	NL80211_ATTR_MPATH_NEXT_HOP                             = 0x1a
	NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED               = 0xf4
	NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR                    = 0xe8
	NL80211_ATTR_MU_MIMO_GROUP_DATA                         = 0xe7
	NL80211_ATTR_NAN_FUNC                                   = 0xf0
	NL80211_ATTR_NAN_MASTER_PREF                            = 0xee
	NL80211_ATTR_NAN_MATCH                                  = 0xf1
	NL80211_ATTR_NETNS_FD                                   = 0xdb
	NL80211_ATTR_NOACK_MAP                                  = 0x95
	NL80211_ATTR_NSS                                        = 0x106
	NL80211_ATTR_OBSS_COLOR_BITMAP                          = 0x12e
	NL80211_ATTR_OFFCHANNEL_TX_OK                           = 0x6c
	NL80211_ATTR_OPER_CLASS                                 = 0xd6
	NL80211_ATTR_OPMODE_NOTIF                               = 0xc2
	NL80211_ATTR_P2P_CTWINDOW                               = 0xa2
	NL80211_ATTR_P2P_OPPPS                                  = 0xa3
	NL80211_ATTR_PAD                                        = 0xe5
	NL80211_ATTR_PBSS                                       = 0xe2
	NL80211_ATTR_PEER_AID                                   = 0xb5
	NL80211_ATTR_PEER_MEASUREMENTS                          = 0x111
	NL80211_ATTR_PID                                        = 0x52
	NL80211_ATTR_PMK                                        = 0xfe
	NL80211_ATTR_PMKID                                      = 0x55
	NL80211_ATTR_PMK_LIFETIME                               = 0x11f
	NL80211_ATTR_PMKR0_NAME                                 = 0x102
	NL80211_ATTR_PMK_REAUTH_THRESHOLD                       = 0x120
	NL80211_ATTR_PMKSA_CANDIDATE                            = 0x86
	NL80211_ATTR_PORT_AUTHORIZED                            = 0x103
	NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN                    = 0x5
	NL80211_ATTR_POWER_RULE_MAX_EIRP                        = 0x6
	NL80211_ATTR_PREV_BSSID                                 = 0x4f
	NL80211_ATTR_PRIVACY                                    = 0x46
	NL80211_ATTR_PROBE_RESP                                 = 0x91
	NL80211_ATTR_PROBE_RESP_OFFLOAD                         = 0x90
	NL80211_ATTR_PROTOCOL_FEATURES                          = 0xad
	NL80211_ATTR_PS_STATE                                   = 0x5d
	NL80211_ATTR_QOS_MAP                                    = 0xc7
	NL80211_ATTR_RADAR_BACKGROUND                           = 0x134
	NL80211_ATTR_RADAR_EVENT                                = 0xa8
	NL80211_ATTR_REASON_CODE                                = 0x36
	NL80211_ATTR_RECEIVE_MULTICAST                          = 0x121
	NL80211_ATTR_RECONNECT_REQUESTED                        = 0x12b
	NL80211_ATTR_REG_ALPHA2                                 = 0x21
	NL80211_ATTR_REG_INDOOR                                 = 0xdd
	NL80211_ATTR_REG_INITIATOR                              = 0x30
	NL80211_ATTR_REG_RULE_FLAGS                             = 0x1
	NL80211_ATTR_REG_RULES                                  = 0x22
	NL80211_ATTR_REG_TYPE                                   = 0x31
	NL80211_ATTR_REKEY_DATA                                 = 0x7a
	NL80211_ATTR_REQ_IE                                     = 0x4d
	NL80211_ATTR_RESP_IE                                    = 0x4e
	NL80211_ATTR_ROAM_SUPPORT                               = 0x83
	NL80211_ATTR_RX_FRAME_TYPES                             = 0x64
	NL80211_ATTR_RX_HW_TIMESTAMP                            = 0x140
	NL80211_ATTR_RXMGMT_FLAGS                               = 0xbc
	NL80211_ATTR_RX_SIGNAL_DBM                              = 0x97
	NL80211_ATTR_S1G_CAPABILITY                             = 0x128
	NL80211_ATTR_S1G_CAPABILITY_MASK                        = 0x129
	NL80211_ATTR_SAE_DATA                                   = 0x9c
	NL80211_ATTR_SAE_PASSWORD                               = 0x115
	NL80211_ATTR_SAE_PWE                                    = 0x12a
	NL80211_ATTR_SAR_SPEC                                   = 0x12c
	NL80211_ATTR_SCAN_FLAGS                                 = 0x9e
	NL80211_ATTR_SCAN_FREQ_KHZ                              = 0x124
	NL80211_ATTR_SCAN_FREQUENCIES                           = 0x2c
	NL80211_ATTR_SCAN_GENERATION                            = 0x2e
	NL80211_ATTR_SCAN_SSIDS                                 = 0x2d
	NL80211_ATTR_SCAN_START_TIME_TSF_BSSID                  = 0xea
	NL80211_ATTR_SCAN_START_TIME_TSF                        = 0xe9
	NL80211_ATTR_SCAN_SUPP_RATES                            = 0x7d
	NL80211_ATTR_SCHED_SCAN_DELAY                           = 0xdc
	NL80211_ATTR_SCHED_SCAN_INTERVAL                        = 0x77
	NL80211_ATTR_SCHED_SCAN_MATCH                           = 0x84
	NL80211_ATTR_SCHED_SCAN_MATCH_SSID                      = 0x1
	NL80211_ATTR_SCHED_SCAN_MAX_REQS                        = 0x100
	NL80211_ATTR_SCHED_SCAN_MULTI                           = 0xff
	NL80211_ATTR_SCHED_SCAN_PLANS                           = 0xe1
	NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI                   = 0xf6
	NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST                     = 0xf7
	NL80211_ATTR_SMPS_MODE                                  = 0xd5
	NL80211_ATTR_SOCKET_OWNER                               = 0xcc
	NL80211_ATTR_SOFTWARE_IFTYPES                           = 0x79
	NL80211_ATTR_SPLIT_WIPHY_DUMP                           = 0xae
	NL80211_ATTR_SSID                                       = 0x34
	NL80211_ATTR_STA_AID                                    = 0x10
	NL80211_ATTR_STA_CAPABILITY                             = 0xab
	NL80211_ATTR_STA_EXT_CAPABILITY                         = 0xac
	NL80211_ATTR_STA_FLAGS2                                 = 0x43
	NL80211_ATTR_STA_FLAGS                                  = 0x11
	NL80211_ATTR_STA_INFO                                   = 0x15
	NL80211_ATTR_STA_LISTEN_INTERVAL                        = 0x12
	NL80211_ATTR_STA_PLINK_ACTION                           = 0x19
	NL80211_ATTR_STA_PLINK_STATE                            = 0x74
	NL80211_ATTR_STA_SUPPORTED_CHANNELS                     = 0xbd
	NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES                 = 0xbe
	NL80211_ATTR_STA_SUPPORTED_RATES                        = 0x13
	NL80211_ATTR_STA_SUPPORT_P2P_PS                         = 0xe4
	NL80211_ATTR_STATUS_CODE                                = 0x48
	NL80211_ATTR_STA_TX_POWER                               = 0x114
	NL80211_ATTR_STA_TX_POWER_SETTING                       = 0x113
	NL80211_ATTR_STA_VLAN                                   = 0x14
	NL80211_ATTR_STA_WME                                    = 0x81
	NL80211_ATTR_SUPPORT_10_MHZ                             = 0xc1
	NL80211_ATTR_SUPPORT_5_MHZ                              = 0xc0
	NL80211_ATTR_SUPPORT_AP_UAPSD                           = 0x82
	NL80211_ATTR_SUPPORTED_COMMANDS                         = 0x32
	NL80211_ATTR_SUPPORTED_IFTYPES                          = 0x20
	NL80211_ATTR_SUPPORT_IBSS_RSN                           = 0x68
	NL80211_ATTR_SUPPORT_MESH_AUTH                          = 0x73
	NL80211_ATTR_SURVEY_INFO                                = 0x54
	NL80211_ATTR_SURVEY_RADIO_STATS                         = 0xda
	NL80211_ATTR_TD_BITMAP                                  = 0x141
	NL80211_ATTR_TDLS_ACTION                                = 0x88
	NL80211_ATTR_TDLS_DIALOG_TOKEN                          = 0x89
	NL80211_ATTR_TDLS_EXTERNAL_SETUP                        = 0x8c
	NL80211_ATTR_TDLS_INITIATOR                             = 0xcf
	NL80211_ATTR_TDLS_OPERATION                             = 0x8a
	NL80211_ATTR_TDLS_PEER_CAPABILITY                       = 0xcb
	NL80211_ATTR_TDLS_SUPPORT                               = 0x8b
	NL80211_ATTR_TESTDATA                                   = 0x45
	NL80211_ATTR_TID_CONFIG                                 = 0x11d
	NL80211_ATTR_TIMED_OUT                                  = 0x41
	NL80211_ATTR_TIMEOUT                                    = 0x110
	NL80211_ATTR_TIMEOUT_REASON                             = 0xf8
	NL80211_ATTR_TSID                                       = 0xd2
	NL80211_ATTR_TWT_RESPONDER                              = 0x116
	NL80211_ATTR_TX_FRAME_TYPES                             = 0x63
	NL80211_ATTR_TX_HW_TIMESTAMP                            = 0x13f
	NL80211_ATTR_TX_NO_CCK_RATE                             = 0x87
	NL80211_ATTR_TXQ_LIMIT                                  = 0x10a
	NL80211_ATTR_TXQ_MEMORY_LIMIT                           = 0x10b
	NL80211_ATTR_TXQ_QUANTUM                                = 0x10c
	NL80211_ATTR_TXQ_STATS                                  = 0x109
	NL80211_ATTR_TX_RATES                                   = 0x5a
	NL80211_ATTR_UNSOL_BCAST_PROBE_RESP                     = 0x127
	NL80211_ATTR_UNSPEC                                     = 0x0
	NL80211_ATTR_USE_MFP                                    = 0x42
	NL80211_ATTR_USER_PRIO                                  = 0xd3
	NL80211_ATTR_USER_REG_HINT_TYPE                         = 0x9a
	NL80211_ATTR_USE_RRM                                    = 0xd0
	NL80211_ATTR_VENDOR_DATA                                = 0xc5
	NL80211_ATTR_VENDOR_EVENTS                              = 0xc6
	NL80211_ATTR_VENDOR_ID                                  = 0xc3
	NL80211_ATTR_VENDOR_SUBCMD                              = 0xc4
	NL80211_ATTR_VHT_CAPABILITY                             = 0x9d
	NL80211_ATTR_VHT_CAPABILITY_MASK                        = 0xb0
	NL80211_ATTR_VLAN_ID                                    = 0x11a
	NL80211_ATTR_WANT_1X_4WAY_HS                            = 0x101
	NL80211_ATTR_WDEV                                       = 0x99
	NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX                     = 0x72
	NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX                     = 0x71
	NL80211_ATTR_WIPHY_ANTENNA_RX                           = 0x6a
	NL80211_ATTR_WIPHY_ANTENNA_TX                           = 0x69
	NL80211_ATTR_WIPHY_BANDS                                = 0x16
	NL80211_ATTR_WIPHY_CHANNEL_TYPE                         = 0x27
	NL80211_ATTR_WIPHY                                      = 0x1
	NL80211_ATTR_WIPHY_COVERAGE_CLASS                       = 0x59
	NL80211_ATTR_WIPHY_DYN_ACK                              = 0xd1
	NL80211_ATTR_WIPHY_EDMG_BW_CONFIG                       = 0x119
	NL80211_ATTR_WIPHY_EDMG_CHANNELS                        = 0x118
	NL80211_ATTR_WIPHY_FRAG_THRESHOLD                       = 0x3f
	NL80211_ATTR_WIPHY_FREQ                                 = 0x26
	NL80211_ATTR_WIPHY_FREQ_HINT                            = 0xc9
	NL80211_ATTR_WIPHY_FREQ_OFFSET                          = 0x122
	NL80211_ATTR_WIPHY_NAME                                 = 0x2
	NL80211_ATTR_WIPHY_RETRY_LONG                           = 0x3e
	NL80211_ATTR_WIPHY_RETRY_SHORT                          = 0x3d
	NL80211_ATTR_WIPHY_RTS_THRESHOLD                        = 0x40
	NL80211_ATTR_WIPHY_SELF_MANAGED_REG                     = 0xd8
	NL80211_ATTR_WIPHY_TX_POWER_LEVEL                       = 0x62
	NL80211_ATTR_WIPHY_TX_POWER_SETTING                     = 0x61
	NL80211_ATTR_WIPHY_TXQ_PARAMS                           = 0x25
	NL80211_ATTR_WOWLAN_TRIGGERS                            = 0x75
	NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED                  = 0x76
	NL80211_ATTR_WPA_VERSIONS                               = 0x4b
	NL80211_AUTHTYPE_AUTOMATIC                              = 0x8
	NL80211_AUTHTYPE_FILS_PK                                = 0x7
	NL80211_AUTHTYPE_FILS_SK                                = 0x5
	NL80211_AUTHTYPE_FILS_SK_PFS                            = 0x6
	NL80211_AUTHTYPE_FT                                     = 0x2
	NL80211_AUTHTYPE_MAX                                    = 0x7
	NL80211_AUTHTYPE_NETWORK_EAP                            = 0x3
	NL80211_AUTHTYPE_OPEN_SYSTEM                            = 0x0
	NL80211_AUTHTYPE_SAE                                    = 0x4
	NL80211_AUTHTYPE_SHARED_KEY                             = 0x1
	NL80211_BAND_2GHZ                                       = 0x0
	NL80211_BAND_5GHZ                                       = 0x1
	NL80211_BAND_60GHZ                                      = 0x2
	NL80211_BAND_6GHZ                                       = 0x3
	NL80211_BAND_ATTR_EDMG_BW_CONFIG                        = 0xb
	NL80211_BAND_ATTR_EDMG_CHANNELS                         = 0xa
	NL80211_BAND_ATTR_FREQS                                 = 0x1
	NL80211_BAND_ATTR_HT_AMPDU_DENSITY                      = 0x6
	NL80211_BAND_ATTR_HT_AMPDU_FACTOR                       = 0x5
	NL80211_BAND_ATTR_HT_CAPA                               = 0x4
	NL80211_BAND_ATTR_HT_MCS_SET                            = 0x3
	NL80211_BAND_ATTR_IFTYPE_DATA                           = 0x9
	NL80211_BAND_ATTR_MAX                                   = 0xd
	NL80211_BAND_ATTR_RATES                                 = 0x2
	NL80211_BAND_ATTR_VHT_CAPA                              = 0x8
	NL80211_BAND_ATTR_VHT_MCS_SET                           = 0x7
	NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC                    = 0x8
	NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET                = 0xa
	NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY                    = 0x9
	NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE                    = 0xb
	NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA                   = 0x6
	NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC                     = 0x2
	NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET                 = 0x4
	NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY                     = 0x3
	NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE                     = 0x5
	NL80211_BAND_IFTYPE_ATTR_IFTYPES                        = 0x1
	NL80211_BAND_IFTYPE_ATTR_MAX                            = 0xb
	NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS                   = 0x7
	NL80211_BAND_LC                                         = 0x5
	NL80211_BAND_S1GHZ                                      = 0x4
	NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE                 = 0x2
	NL80211_BITRATE_ATTR_MAX                                = 0x2
	NL80211_BITRATE_ATTR_RATE                               = 0x1
	NL80211_BSS_BEACON_IES                                  = 0xb
	NL80211_BSS_BEACON_INTERVAL                             = 0x4
	NL80211_BSS_BEACON_TSF                                  = 0xd
	NL80211_BSS_BSSID                                       = 0x1
	NL80211_BSS_CAPABILITY                                  = 0x5
	NL80211_BSS_CHAIN_SIGNAL                                = 0x13
	NL80211_BSS_CHAN_WIDTH_10                               = 0x1
	NL80211_BSS_CHAN_WIDTH_1                                = 0x3
	NL80211_BSS_CHAN_WIDTH_20                               = 0x0
	NL80211_BSS_CHAN_WIDTH_2                                = 0x4
	NL80211_BSS_CHAN_WIDTH_5                                = 0x2
	NL80211_BSS_CHAN_WIDTH                                  = 0xc
	NL80211_BSS_FREQUENCY                                   = 0x2
	NL80211_BSS_FREQUENCY_OFFSET                            = 0x14
	NL80211_BSS_INFORMATION_ELEMENTS                        = 0x6
	NL80211_BSS_LAST_SEEN_BOOTTIME                          = 0xf
	NL80211_BSS_MAX                                         = 0x18
	NL80211_BSS_MLD_ADDR                                    = 0x16
	NL80211_BSS_MLO_LINK_ID                                 = 0x15
	NL80211_BSS_PAD                                         = 0x10
	NL80211_BSS_PARENT_BSSID                                = 0x12
	NL80211_BSS_PARENT_TSF                                  = 0x11
	NL80211_BSS_PRESP_DATA                                  = 0xe
	NL80211_BSS_SEEN_MS_AGO                                 = 0xa
	NL80211_BSS_SELECT_ATTR_BAND_PREF                       = 0x2
	NL80211_BSS_SELECT_ATTR_MAX                             = 0x3
	NL80211_BSS_SELECT_ATTR_RSSI_ADJUST                     = 0x3
	NL80211_BSS_SELECT_ATTR_RSSI                            = 0x1
	NL80211_BSS_SIGNAL_MBM                                  = 0x7
	NL80211_BSS_SIGNAL_UNSPEC                               = 0x8
	NL80211_BSS_STATUS_ASSOCIATED                           = 0x1
	NL80211_BSS_STATUS_AUTHENTICATED                        = 0x0
	NL80211_BSS_STATUS                                      = 0x9
	NL80211_BSS_STATUS_IBSS_JOINED                          = 0x2
	NL80211_BSS_TSF                                         = 0x3
	NL80211_CHAN_HT20                                       = 0x1
	NL80211_CHAN_HT40MINUS                                  = 0x2
	NL80211_CHAN_HT40PLUS                                   = 0x3
	NL80211_CHAN_NO_HT                                      = 0x0
	NL80211_CHAN_WIDTH_10                                   = 0x7
	NL80211_CHAN_WIDTH_160                                  = 0x5
	NL80211_CHAN_WIDTH_16                                   = 0xc
	NL80211_CHAN_WIDTH_1                                    = 0x8
	NL80211_CHAN_WIDTH_20                                   = 0x1
	NL80211_CHAN_WIDTH_20_NOHT                              = 0x0
	NL80211_CHAN_WIDTH_2                                    = 0x9
	NL80211_CHAN_WIDTH_320                                  = 0xd
	NL80211_CHAN_WIDTH_40                                   = 0x2
	NL80211_CHAN_WIDTH_4                                    = 0xa
	NL80211_CHAN_WIDTH_5                                    = 0x6
	NL80211_CHAN_WIDTH_80                                   = 0x3
	NL80211_CHAN_WIDTH_80P80                                = 0x4
	NL80211_CHAN_WIDTH_8                                    = 0xb
	NL80211_CMD_ABORT_SCAN                                  = 0x72
	NL80211_CMD_ACTION                                      = 0x3b
	NL80211_CMD_ACTION_TX_STATUS                            = 0x3c
	NL80211_CMD_ADD_LINK                                    = 0x94
	NL80211_CMD_ADD_LINK_STA                                = 0x96
	NL80211_CMD_ADD_NAN_FUNCTION                            = 0x75
	NL80211_CMD_ADD_TX_TS                                   = 0x69
	NL80211_CMD_ASSOC_COMEBACK                              = 0x93
	NL80211_CMD_ASSOCIATE                                   = 0x26
	NL80211_CMD_AUTHENTICATE                                = 0x25
	NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL                    = 0x38
	NL80211_CMD_CHANGE_NAN_CONFIG                           = 0x77
	NL80211_CMD_CHANNEL_SWITCH                              = 0x66
	NL80211_CMD_CH_SWITCH_NOTIFY                            = 0x58
	NL80211_CMD_CH_SWITCH_STARTED_NOTIFY                    = 0x6e
	NL80211_CMD_COLOR_CHANGE_ABORTED                        = 0x90
	NL80211_CMD_COLOR_CHANGE_COMPLETED                      = 0x91
	NL80211_CMD_COLOR_CHANGE_REQUEST                        = 0x8e
	NL80211_CMD_COLOR_CHANGE_STARTED                        = 0x8f
	NL80211_CMD_CONNECT                                     = 0x2e
	NL80211_CMD_CONN_FAILED                                 = 0x5b
	NL80211_CMD_CONTROL_PORT_FRAME                          = 0x81
	NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS                = 0x8b
	NL80211_CMD_CRIT_PROTOCOL_START                         = 0x62
	NL80211_CMD_CRIT_PROTOCOL_STOP                          = 0x63
	NL80211_CMD_DEAUTHENTICATE                              = 0x27
	NL80211_CMD_DEL_BEACON                                  = 0x10
	NL80211_CMD_DEL_INTERFACE                               = 0x8
	NL80211_CMD_DEL_KEY                                     = 0xc
	NL80211_CMD_DEL_MPATH                                   = 0x18
	NL80211_CMD_DEL_NAN_FUNCTION                            = 0x76
	NL80211_CMD_DEL_PMK                                     = 0x7c
	NL80211_CMD_DEL_PMKSA                                   = 0x35
	NL80211_CMD_DEL_STATION                                 = 0x14
	NL80211_CMD_DEL_TX_TS                                   = 0x6a
	NL80211_CMD_DEL_WIPHY                                   = 0x4
	NL80211_CMD_DISASSOCIATE                                = 0x28
	NL80211_CMD_DISCONNECT                                  = 0x30
	NL80211_CMD_EXTERNAL_AUTH                               = 0x7f
	NL80211_CMD_FLUSH_PMKSA                                 = 0x36
	NL80211_CMD_FRAME                                       = 0x3b
	NL80211_CMD_FRAME_TX_STATUS                             = 0x3c
	NL80211_CMD_FRAME_WAIT_CANCEL                           = 0x43
	NL80211_CMD_FT_EVENT                                    = 0x61
	NL80211_CMD_GET_BEACON                                  = 0xd
	NL80211_CMD_GET_COALESCE                                = 0x64
	NL80211_CMD_GET_FTM_RESPONDER_STATS                     = 0x82
	NL80211_CMD_GET_INTERFACE            
"""




```