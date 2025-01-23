Response:
The user wants to understand the functionality of a Go file that seems to define constants related to network configuration, specifically for Linux.

**Plan:**

1. **Identify the Core Functionality:** Based on the constant prefixes (e.g., `NL80211_CMD_`, `NL80211_FEATURE_`), the file is clearly related to the `nl80211` Linux kernel subsystem.
2. **Explain `nl80211`:** Describe what `nl80211` is and its purpose.
3. **Categorize the Constants:** Group the constants into logical categories (commands, features, attributes, etc.) to explain their purpose.
4. **Provide Go Code Examples:**  Show how these constants might be used in Go code that interacts with `nl80211`. Since this is a low-level interface, direct usage might be complex. I'll focus on demonstrating how the constants represent different options or settings.
5. **Address Potential Pitfalls:** Think about common mistakes developers might make when working with these low-level constants. Since this is part 4, I need to also summarize the overall functionality.
6. **Summarize the Functionality:** Provide a concise summary of the file's role.
这是路径为`go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go` 的Go语言实现的一部分，它主要定义了与 Linux `nl80211` 协议族相关的常量。`nl80211` 是 Linux 内核中用于配置和管理无线网络接口的 netlink 协议族。

**功能列举：**

1. **定义 `nl80211` 命令常量 (以 `NL80211_CMD_` 开头):**  这些常量代表了可以通过 `nl80211` 协议发送给内核的不同命令。例如，`NL80211_CMD_GET_WIPHY` 表示获取无线物理设备的信息， `NL80211_CMD_SET_WIPHY` 表示设置无线物理设备的属性。
2. **定义 `nl80211` 特性常量 (以 `NL80211_FEATURE_` 和 `NL80211_EXT_FEATURE_` 开头):** 这些常量定义了无线设备和驱动程序支持的各种功能和扩展特性。例如，`NL80211_FEATURE_HT_IBSS` 表示支持 HT (High Throughput) 的独立基本服务集 (IBSS) 网络， `NL80211_EXT_FEATURE_FILS_STA` 表示支持 FILS (Fast Initial Link Setup) 的 Station 模式。
3. **定义 `nl80211` 属性常量 (以 `NL80211_` 开头，但不属于 `CMD_` 或 `FEATURE_`):** 这些常量定义了与 `nl80211` 消息相关的各种属性。例如，`NL80211_IFTYPE_STATION` 表示网络接口类型为 Station (客户端模式)， `NL80211_KEY_CIPHER` 表示加密算法。
4. **定义其他相关的常量 (以 `FRA_`, `AUDIT_NLGRP_`, `TUN_F_`, `VIRTIO_NET_HDR_F_`, `VIRTIO_NET_HDR_GSO_`, `SK_MEMINFO_`, `SKNLGRP_`, `SK_DIAG_BPF_STORAGE_REQ_`, `SK_DIAG_BPF_STORAGE_REP_`, `SK_DIAG_BPF_STORAGE_` 开头):** 这些常量可能与网络过滤 (FRA\_), 审计 (AUDIT\_NLGRP\_), TUN/TAP 设备 (TUN\_F\_), 虚拟化网络 (VIRTIO\_NET\_HDR\_), 以及 socket 诊断信息 (SK\_) 等其他网络相关的 Linux 功能有关。虽然它们出现在这个文件中，但可能不是 `nl80211` 的核心部分，而是 Go 语言为了方便将相关的网络常量放在一起。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言的 `syscall` 包为了在 Linux 系统上进行底层系统调用和与内核交互而提供支持的一部分。特别是，它定义了与网络配置和管理相关的常量，这使得 Go 程序可以通过 Netlink 套接字与 Linux 内核的 `nl80211` 子系统进行通信。这通常用于实现诸如 WiFi 管理工具之类的功能。

**Go 代码举例说明：**

由于这些常量是底层的系统级常量，直接在应用层代码中使用的情况可能比较少见。通常，你会使用更高级别的库（例如 `github.com/mdlayher/netlink` 或专门的 WiFi 管理库）来间接使用这些常量。

以下是一个简化的例子，说明如何使用 `golang.org/x/unix` 包（其中包含了 `ztypes_linux.go` 定义的常量）来创建一个 Netlink 套接字并发送一个 `nl80211` 命令：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	// 假设我们要获取无线物理设备的信息 (NL80211_CMD_GET_WIPHY)

	// 创建一个 Netlink 套接字
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_GENERIC)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// 构造 Netlink 消息头
	var nlMsg unix.NlMsghdr
	nlMsg.Len = unix.NLMSG_HDRLEN // 初始长度，后续会更新
	nlMsg.Type = uint16(unix.NLMSG_MIN_TYPE)
	nlMsg.Flags = unix.NLM_F_REQUEST | unix.NLM_F_ACK
	nlMsg.Seq = 1
	nlMsg.Pid = uint32(syscall.Getpid())

	// 构造 Generic Netlink 消息头
	var gnMsg unix.GenlMsghdr
	// 假设已经通过其他方式获取了 NL80211 家族的 ID
	gnMsg.Cmd = uint8(unix.NL80211_CMD_GET_WIPHY)
	gnMsg.Version = 0

	// 构造请求负载 (这里假设不需要额外的属性)
	payload := []byte{}

	// 计算完整的消息长度
	nlMsg.Len = uint32(unix.NLMSG_HDRLEN + unix.GENL_HDRLEN + len(payload))

	// 将消息头和负载组合在一起
	msg := make([]byte, nlMsg.Len)
	*(*unix.NlMsghdr)(unsafe.Pointer(&msg[0])) = nlMsg
	*(*unix.GenlMsghdr)(unsafe.Pointer(&msg[unix.NLMSG_HDRLEN])) = gnMsg
	copy(msg[unix.NLMSG_HDRLEN+unix.GENL_HDRLEN:], payload)

	// 构造 socket 地址
	addr := syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
	}

	// 发送消息
	err = syscall.Sendto(fd, msg, 0, (*syscall.Sockaddr)(&addr))
	if err != nil {
		fmt.Println("Error sending message:", err)
		return
	}

	fmt.Println("Sent NL80211_CMD_GET_WIPHY command")

	// ... 接收和解析内核的响应 ...
}
```

**假设的输入与输出：**

在这个例子中，没有直接的用户输入。代码的功能是构造并发送一个请求内核信息的 Netlink 消息。

**输出：**

如果发送成功，控制台会输出 "Sent NL80211\_CMD\_GET\_WIPHY command"。实际的响应需要从 Netlink 套接字读取并解析，这部分代码在示例中被省略了。内核的响应会包含有关无线物理设备的信息，其格式会根据 `nl80211` 协议的定义。

**命令行参数的具体处理：**

这个代码片段本身不处理命令行参数。它是一个底层的网络通信示例。更高级别的工具可能会使用命令行参数来指定要执行的 `nl80211` 命令和相关的参数。

**使用者易犯错的点：**

1. **错误地使用常量值:**  直接使用这些常量需要非常了解 `nl80211` 协议的细节。错误地使用命令码、特性标志或属性值会导致内核返回错误或产生未预期的行为。例如，错误地使用 `NL80211_IFTYPE_` 常量可能导致接口创建失败。
2. **不理解 Netlink 消息结构:** 构造正确的 Netlink 消息（包括消息头、Generic Netlink 头和属性）是至关重要的。不正确的消息结构会被内核拒绝。
3. **缺少必要的权限:** 某些 `nl80211` 命令需要 root 权限才能执行。如果程序没有足够的权限，发送这些命令会失败。
4. **处理内核响应的复杂性:**  内核的响应也需要按照 `nl80211` 协议进行解析，这涉及到理解不同的属性类型和结构。

**归纳一下它的功能（第4部分）：**

总而言之，这个代码片段 (`go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go` 的一部分)  **定义了 Go 语言中用于与 Linux 内核的 `nl80211` 无线子系统进行交互的底层常量**。这些常量代表了可以发送给内核的命令、无线设备支持的特性以及与这些命令和特性相关的各种属性。这个文件是 Go 语言 `syscall` 包中用于支持底层网络操作的重要组成部分，使得 Go 程序能够进行无线网络的配置和管理。它为更高级别的网络库提供了基础，使得开发者可以使用 Go 语言构建复杂的网络应用，例如 WiFi 管理工具。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
= 0x5
	NL80211_CMD_GET_KEY                                     = 0x9
	NL80211_CMD_GET_MESH_CONFIG                             = 0x1c
	NL80211_CMD_GET_MESH_PARAMS                             = 0x1c
	NL80211_CMD_GET_MPATH                                   = 0x15
	NL80211_CMD_GET_MPP                                     = 0x6b
	NL80211_CMD_GET_POWER_SAVE                              = 0x3e
	NL80211_CMD_GET_PROTOCOL_FEATURES                       = 0x5f
	NL80211_CMD_GET_REG                                     = 0x1f
	NL80211_CMD_GET_SCAN                                    = 0x20
	NL80211_CMD_GET_STATION                                 = 0x11
	NL80211_CMD_GET_SURVEY                                  = 0x32
	NL80211_CMD_GET_WIPHY                                   = 0x1
	NL80211_CMD_GET_WOWLAN                                  = 0x49
	NL80211_CMD_JOIN_IBSS                                   = 0x2b
	NL80211_CMD_JOIN_MESH                                   = 0x44
	NL80211_CMD_JOIN_OCB                                    = 0x6c
	NL80211_CMD_LEAVE_IBSS                                  = 0x2c
	NL80211_CMD_LEAVE_MESH                                  = 0x45
	NL80211_CMD_LEAVE_OCB                                   = 0x6d
	NL80211_CMD_MAX                                         = 0x9b
	NL80211_CMD_MICHAEL_MIC_FAILURE                         = 0x29
	NL80211_CMD_MODIFY_LINK_STA                             = 0x97
	NL80211_CMD_NAN_MATCH                                   = 0x78
	NL80211_CMD_NEW_BEACON                                  = 0xf
	NL80211_CMD_NEW_INTERFACE                               = 0x7
	NL80211_CMD_NEW_KEY                                     = 0xb
	NL80211_CMD_NEW_MPATH                                   = 0x17
	NL80211_CMD_NEW_PEER_CANDIDATE                          = 0x48
	NL80211_CMD_NEW_SCAN_RESULTS                            = 0x22
	NL80211_CMD_NEW_STATION                                 = 0x13
	NL80211_CMD_NEW_SURVEY_RESULTS                          = 0x33
	NL80211_CMD_NEW_WIPHY                                   = 0x3
	NL80211_CMD_NOTIFY_CQM                                  = 0x40
	NL80211_CMD_NOTIFY_RADAR                                = 0x86
	NL80211_CMD_OBSS_COLOR_COLLISION                        = 0x8d
	NL80211_CMD_PEER_MEASUREMENT_COMPLETE                   = 0x85
	NL80211_CMD_PEER_MEASUREMENT_RESULT                     = 0x84
	NL80211_CMD_PEER_MEASUREMENT_START                      = 0x83
	NL80211_CMD_PMKSA_CANDIDATE                             = 0x50
	NL80211_CMD_PORT_AUTHORIZED                             = 0x7d
	NL80211_CMD_PROBE_CLIENT                                = 0x54
	NL80211_CMD_PROBE_MESH_LINK                             = 0x88
	NL80211_CMD_RADAR_DETECT                                = 0x5e
	NL80211_CMD_REG_BEACON_HINT                             = 0x2a
	NL80211_CMD_REG_CHANGE                                  = 0x24
	NL80211_CMD_REGISTER_ACTION                             = 0x3a
	NL80211_CMD_REGISTER_BEACONS                            = 0x55
	NL80211_CMD_REGISTER_FRAME                              = 0x3a
	NL80211_CMD_RELOAD_REGDB                                = 0x7e
	NL80211_CMD_REMAIN_ON_CHANNEL                           = 0x37
	NL80211_CMD_REMOVE_LINK                                 = 0x95
	NL80211_CMD_REMOVE_LINK_STA                             = 0x98
	NL80211_CMD_REQ_SET_REG                                 = 0x1b
	NL80211_CMD_ROAM                                        = 0x2f
	NL80211_CMD_SCAN_ABORTED                                = 0x23
	NL80211_CMD_SCHED_SCAN_RESULTS                          = 0x4d
	NL80211_CMD_SCHED_SCAN_STOPPED                          = 0x4e
	NL80211_CMD_SET_BEACON                                  = 0xe
	NL80211_CMD_SET_BSS                                     = 0x19
	NL80211_CMD_SET_CHANNEL                                 = 0x41
	NL80211_CMD_SET_COALESCE                                = 0x65
	NL80211_CMD_SET_CQM                                     = 0x3f
	NL80211_CMD_SET_FILS_AAD                                = 0x92
	NL80211_CMD_SET_INTERFACE                               = 0x6
	NL80211_CMD_SET_KEY                                     = 0xa
	NL80211_CMD_SET_MAC_ACL                                 = 0x5d
	NL80211_CMD_SET_MCAST_RATE                              = 0x5c
	NL80211_CMD_SET_MESH_CONFIG                             = 0x1d
	NL80211_CMD_SET_MESH_PARAMS                             = 0x1d
	NL80211_CMD_SET_MGMT_EXTRA_IE                           = 0x1e
	NL80211_CMD_SET_MPATH                                   = 0x16
	NL80211_CMD_SET_MULTICAST_TO_UNICAST                    = 0x79
	NL80211_CMD_SET_NOACK_MAP                               = 0x57
	NL80211_CMD_SET_PMK                                     = 0x7b
	NL80211_CMD_SET_PMKSA                                   = 0x34
	NL80211_CMD_SET_POWER_SAVE                              = 0x3d
	NL80211_CMD_SET_QOS_MAP                                 = 0x68
	NL80211_CMD_SET_REG                                     = 0x1a
	NL80211_CMD_SET_REKEY_OFFLOAD                           = 0x4f
	NL80211_CMD_SET_SAR_SPECS                               = 0x8c
	NL80211_CMD_SET_STATION                                 = 0x12
	NL80211_CMD_SET_TID_CONFIG                              = 0x89
	NL80211_CMD_SET_TX_BITRATE_MASK                         = 0x39
	NL80211_CMD_SET_WDS_PEER                                = 0x42
	NL80211_CMD_SET_WIPHY                                   = 0x2
	NL80211_CMD_SET_WIPHY_NETNS                             = 0x31
	NL80211_CMD_SET_WOWLAN                                  = 0x4a
	NL80211_CMD_STA_OPMODE_CHANGED                          = 0x80
	NL80211_CMD_START_AP                                    = 0xf
	NL80211_CMD_START_NAN                                   = 0x73
	NL80211_CMD_START_P2P_DEVICE                            = 0x59
	NL80211_CMD_START_SCHED_SCAN                            = 0x4b
	NL80211_CMD_STOP_AP                                     = 0x10
	NL80211_CMD_STOP_NAN                                    = 0x74
	NL80211_CMD_STOP_P2P_DEVICE                             = 0x5a
	NL80211_CMD_STOP_SCHED_SCAN                             = 0x4c
	NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH                  = 0x70
	NL80211_CMD_TDLS_CHANNEL_SWITCH                         = 0x6f
	NL80211_CMD_TDLS_MGMT                                   = 0x52
	NL80211_CMD_TDLS_OPER                                   = 0x51
	NL80211_CMD_TESTMODE                                    = 0x2d
	NL80211_CMD_TRIGGER_SCAN                                = 0x21
	NL80211_CMD_UNEXPECTED_4ADDR_FRAME                      = 0x56
	NL80211_CMD_UNEXPECTED_FRAME                            = 0x53
	NL80211_CMD_UNPROT_BEACON                               = 0x8a
	NL80211_CMD_UNPROT_DEAUTHENTICATE                       = 0x46
	NL80211_CMD_UNPROT_DISASSOCIATE                         = 0x47
	NL80211_CMD_UNSPEC                                      = 0x0
	NL80211_CMD_UPDATE_CONNECT_PARAMS                       = 0x7a
	NL80211_CMD_UPDATE_FT_IES                               = 0x60
	NL80211_CMD_UPDATE_OWE_INFO                             = 0x87
	NL80211_CMD_VENDOR                                      = 0x67
	NL80211_CMD_WIPHY_REG_CHANGE                            = 0x71
	NL80211_COALESCE_CONDITION_MATCH                        = 0x0
	NL80211_COALESCE_CONDITION_NO_MATCH                     = 0x1
	NL80211_CONN_FAIL_BLOCKED_CLIENT                        = 0x1
	NL80211_CONN_FAIL_MAX_CLIENTS                           = 0x0
	NL80211_CQM_RSSI_BEACON_LOSS_EVENT                      = 0x2
	NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH                   = 0x1
	NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW                    = 0x0
	NL80211_CQM_TXE_MAX_INTVL                               = 0x708
	NL80211_CRIT_PROTO_APIPA                                = 0x3
	NL80211_CRIT_PROTO_DHCP                                 = 0x1
	NL80211_CRIT_PROTO_EAPOL                                = 0x2
	NL80211_CRIT_PROTO_MAX_DURATION                         = 0x1388
	NL80211_CRIT_PROTO_UNSPEC                               = 0x0
	NL80211_DFS_AVAILABLE                                   = 0x2
	NL80211_DFS_ETSI                                        = 0x2
	NL80211_DFS_FCC                                         = 0x1
	NL80211_DFS_JP                                          = 0x3
	NL80211_DFS_UNAVAILABLE                                 = 0x1
	NL80211_DFS_UNSET                                       = 0x0
	NL80211_DFS_USABLE                                      = 0x0
	NL80211_EDMG_BW_CONFIG_MAX                              = 0xf
	NL80211_EDMG_BW_CONFIG_MIN                              = 0x4
	NL80211_EDMG_CHANNELS_MAX                               = 0x3c
	NL80211_EDMG_CHANNELS_MIN                               = 0x1
	NL80211_EHT_MAX_CAPABILITY_LEN                          = 0x33
	NL80211_EHT_MIN_CAPABILITY_LEN                          = 0xd
	NL80211_EXTERNAL_AUTH_ABORT                             = 0x1
	NL80211_EXTERNAL_AUTH_START                             = 0x0
	NL80211_EXT_FEATURE_4WAY_HANDSHAKE_AP_PSK               = 0x32
	NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X               = 0x10
	NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK              = 0xf
	NL80211_EXT_FEATURE_ACCEPT_BCAST_PROBE_RESP             = 0x12
	NL80211_EXT_FEATURE_ACK_SIGNAL_SUPPORT                  = 0x1b
	NL80211_EXT_FEATURE_AIRTIME_FAIRNESS                    = 0x21
	NL80211_EXT_FEATURE_AP_PMKSA_CACHING                    = 0x22
	NL80211_EXT_FEATURE_AQL                                 = 0x28
	NL80211_EXT_FEATURE_BEACON_PROTECTION_CLIENT            = 0x2e
	NL80211_EXT_FEATURE_BEACON_PROTECTION                   = 0x29
	NL80211_EXT_FEATURE_BEACON_RATE_HE                      = 0x36
	NL80211_EXT_FEATURE_BEACON_RATE_HT                      = 0x7
	NL80211_EXT_FEATURE_BEACON_RATE_LEGACY                  = 0x6
	NL80211_EXT_FEATURE_BEACON_RATE_VHT                     = 0x8
	NL80211_EXT_FEATURE_BSS_COLOR                           = 0x3a
	NL80211_EXT_FEATURE_BSS_PARENT_TSF                      = 0x4
	NL80211_EXT_FEATURE_CAN_REPLACE_PTK0                    = 0x1f
	NL80211_EXT_FEATURE_CONTROL_PORT_NO_PREAUTH             = 0x2a
	NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211           = 0x1a
	NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211_TX_STATUS = 0x30
	NL80211_EXT_FEATURE_CQM_RSSI_LIST                       = 0xd
	NL80211_EXT_FEATURE_DATA_ACK_SIGNAL_SUPPORT             = 0x1b
	NL80211_EXT_FEATURE_DEL_IBSS_STA                        = 0x2c
	NL80211_EXT_FEATURE_DFS_OFFLOAD                         = 0x19
	NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER                = 0x20
	NL80211_EXT_FEATURE_EXT_KEY_ID                          = 0x24
	NL80211_EXT_FEATURE_FILS_CRYPTO_OFFLOAD                 = 0x3b
	NL80211_EXT_FEATURE_FILS_DISCOVERY                      = 0x34
	NL80211_EXT_FEATURE_FILS_MAX_CHANNEL_TIME               = 0x11
	NL80211_EXT_FEATURE_FILS_SK_OFFLOAD                     = 0xe
	NL80211_EXT_FEATURE_FILS_STA                            = 0x9
	NL80211_EXT_FEATURE_HIGH_ACCURACY_SCAN                  = 0x18
	NL80211_EXT_FEATURE_LOW_POWER_SCAN                      = 0x17
	NL80211_EXT_FEATURE_LOW_SPAN_SCAN                       = 0x16
	NL80211_EXT_FEATURE_MFP_OPTIONAL                        = 0x15
	NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA                   = 0xa
	NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA_CONNECTED         = 0xb
	NL80211_EXT_FEATURE_MULTICAST_REGISTRATIONS             = 0x2d
	NL80211_EXT_FEATURE_MU_MIMO_AIR_SNIFFER                 = 0x2
	NL80211_EXT_FEATURE_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION  = 0x14
	NL80211_EXT_FEATURE_OCE_PROBE_REQ_HIGH_TX_RATE          = 0x13
	NL80211_EXT_FEATURE_OPERATING_CHANNEL_VALIDATION        = 0x31
	NL80211_EXT_FEATURE_POWERED_ADDR_CHANGE                 = 0x3d
	NL80211_EXT_FEATURE_PROTECTED_TWT                       = 0x2b
	NL80211_EXT_FEATURE_PROT_RANGE_NEGO_AND_MEASURE         = 0x39
	NL80211_EXT_FEATURE_RADAR_BACKGROUND                    = 0x3c
	NL80211_EXT_FEATURE_RRM                                 = 0x1
	NL80211_EXT_FEATURE_SAE_OFFLOAD_AP                      = 0x33
	NL80211_EXT_FEATURE_SAE_OFFLOAD                         = 0x26
	NL80211_EXT_FEATURE_SCAN_FREQ_KHZ                       = 0x2f
	NL80211_EXT_FEATURE_SCAN_MIN_PREQ_CONTENT               = 0x1e
	NL80211_EXT_FEATURE_SCAN_RANDOM_SN                      = 0x1d
	NL80211_EXT_FEATURE_SCAN_START_TIME                     = 0x3
	NL80211_EXT_FEATURE_SCHED_SCAN_BAND_SPECIFIC_RSSI_THOLD = 0x23
	NL80211_EXT_FEATURE_SCHED_SCAN_RELATIVE_RSSI            = 0xc
	NL80211_EXT_FEATURE_SECURE_LTF                          = 0x37
	NL80211_EXT_FEATURE_SECURE_RTT                          = 0x38
	NL80211_EXT_FEATURE_SET_SCAN_DWELL                      = 0x5
	NL80211_EXT_FEATURE_STA_TX_PWR                          = 0x25
	NL80211_EXT_FEATURE_TXQS                                = 0x1c
	NL80211_EXT_FEATURE_UNSOL_BCAST_PROBE_RESP              = 0x35
	NL80211_EXT_FEATURE_VHT_IBSS                            = 0x0
	NL80211_EXT_FEATURE_VLAN_OFFLOAD                        = 0x27
	NL80211_FEATURE_ACKTO_ESTIMATION                        = 0x800000
	NL80211_FEATURE_ACTIVE_MONITOR                          = 0x20000
	NL80211_FEATURE_ADVERTISE_CHAN_LIMITS                   = 0x4000
	NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE               = 0x40000
	NL80211_FEATURE_AP_SCAN                                 = 0x100
	NL80211_FEATURE_CELL_BASE_REG_HINTS                     = 0x8
	NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES               = 0x80000
	NL80211_FEATURE_DYNAMIC_SMPS                            = 0x2000000
	NL80211_FEATURE_FULL_AP_CLIENT_STATE                    = 0x8000
	NL80211_FEATURE_HT_IBSS                                 = 0x2
	NL80211_FEATURE_INACTIVITY_TIMER                        = 0x4
	NL80211_FEATURE_LOW_PRIORITY_SCAN                       = 0x40
	NL80211_FEATURE_MAC_ON_CREATE                           = 0x8000000
	NL80211_FEATURE_ND_RANDOM_MAC_ADDR                      = 0x80000000
	NL80211_FEATURE_NEED_OBSS_SCAN                          = 0x400
	NL80211_FEATURE_P2P_DEVICE_NEEDS_CHANNEL                = 0x10
	NL80211_FEATURE_P2P_GO_CTWIN                            = 0x800
	NL80211_FEATURE_P2P_GO_OPPPS                            = 0x1000
	NL80211_FEATURE_QUIET                                   = 0x200000
	NL80211_FEATURE_SAE                                     = 0x20
	NL80211_FEATURE_SCAN_FLUSH                              = 0x80
	NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR                    = 0x20000000
	NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR              = 0x40000000
	NL80211_FEATURE_SK_TX_STATUS                            = 0x1
	NL80211_FEATURE_STATIC_SMPS                             = 0x1000000
	NL80211_FEATURE_SUPPORTS_WMM_ADMISSION                  = 0x4000000
	NL80211_FEATURE_TDLS_CHANNEL_SWITCH                     = 0x10000000
	NL80211_FEATURE_TX_POWER_INSERTION                      = 0x400000
	NL80211_FEATURE_USERSPACE_MPM                           = 0x10000
	NL80211_FEATURE_VIF_TXPOWER                             = 0x200
	NL80211_FEATURE_WFA_TPC_IE_IN_PROBES                    = 0x100000
	NL80211_FILS_DISCOVERY_ATTR_INT_MAX                     = 0x2
	NL80211_FILS_DISCOVERY_ATTR_INT_MIN                     = 0x1
	NL80211_FILS_DISCOVERY_ATTR_MAX                         = 0x3
	NL80211_FILS_DISCOVERY_ATTR_TMPL                        = 0x3
	NL80211_FILS_DISCOVERY_TMPL_MIN_LEN                     = 0x2a
	NL80211_FREQUENCY_ATTR_16MHZ                            = 0x19
	NL80211_FREQUENCY_ATTR_1MHZ                             = 0x15
	NL80211_FREQUENCY_ATTR_2MHZ                             = 0x16
	NL80211_FREQUENCY_ATTR_4MHZ                             = 0x17
	NL80211_FREQUENCY_ATTR_8MHZ                             = 0x18
	NL80211_FREQUENCY_ATTR_DFS_CAC_TIME                     = 0xd
	NL80211_FREQUENCY_ATTR_DFS_STATE                        = 0x7
	NL80211_FREQUENCY_ATTR_DFS_TIME                         = 0x8
	NL80211_FREQUENCY_ATTR_DISABLED                         = 0x2
	NL80211_FREQUENCY_ATTR_FREQ                             = 0x1
	NL80211_FREQUENCY_ATTR_GO_CONCURRENT                    = 0xf
	NL80211_FREQUENCY_ATTR_INDOOR_ONLY                      = 0xe
	NL80211_FREQUENCY_ATTR_IR_CONCURRENT                    = 0xf
	NL80211_FREQUENCY_ATTR_MAX                              = 0x21
	NL80211_FREQUENCY_ATTR_MAX_TX_POWER                     = 0x6
	NL80211_FREQUENCY_ATTR_NO_10MHZ                         = 0x11
	NL80211_FREQUENCY_ATTR_NO_160MHZ                        = 0xc
	NL80211_FREQUENCY_ATTR_NO_20MHZ                         = 0x10
	NL80211_FREQUENCY_ATTR_NO_320MHZ                        = 0x1a
	NL80211_FREQUENCY_ATTR_NO_80MHZ                         = 0xb
	NL80211_FREQUENCY_ATTR_NO_EHT                           = 0x1b
	NL80211_FREQUENCY_ATTR_NO_HE                            = 0x13
	NL80211_FREQUENCY_ATTR_NO_HT40_MINUS                    = 0x9
	NL80211_FREQUENCY_ATTR_NO_HT40_PLUS                     = 0xa
	NL80211_FREQUENCY_ATTR_NO_IBSS                          = 0x3
	NL80211_FREQUENCY_ATTR_NO_IR                            = 0x3
	NL80211_FREQUENCY_ATTR_OFFSET                           = 0x14
	NL80211_FREQUENCY_ATTR_PASSIVE_SCAN                     = 0x3
	NL80211_FREQUENCY_ATTR_RADAR                            = 0x5
	NL80211_FREQUENCY_ATTR_WMM                              = 0x12
	NL80211_FTM_RESP_ATTR_CIVICLOC                          = 0x3
	NL80211_FTM_RESP_ATTR_ENABLED                           = 0x1
	NL80211_FTM_RESP_ATTR_LCI                               = 0x2
	NL80211_FTM_RESP_ATTR_MAX                               = 0x3
	NL80211_FTM_STATS_ASAP_NUM                              = 0x4
	NL80211_FTM_STATS_FAILED_NUM                            = 0x3
	NL80211_FTM_STATS_MAX                                   = 0xa
	NL80211_FTM_STATS_NON_ASAP_NUM                          = 0x5
	NL80211_FTM_STATS_OUT_OF_WINDOW_TRIGGERS_NUM            = 0x9
	NL80211_FTM_STATS_PAD                                   = 0xa
	NL80211_FTM_STATS_PARTIAL_NUM                           = 0x2
	NL80211_FTM_STATS_RESCHEDULE_REQUESTS_NUM               = 0x8
	NL80211_FTM_STATS_SUCCESS_NUM                           = 0x1
	NL80211_FTM_STATS_TOTAL_DURATION_MSEC                   = 0x6
	NL80211_FTM_STATS_UNKNOWN_TRIGGERS_NUM                  = 0x7
	NL80211_GENL_NAME                                       = "nl80211"
	NL80211_HE_BSS_COLOR_ATTR_COLOR                         = 0x1
	NL80211_HE_BSS_COLOR_ATTR_DISABLED                      = 0x2
	NL80211_HE_BSS_COLOR_ATTR_MAX                           = 0x3
	NL80211_HE_BSS_COLOR_ATTR_PARTIAL                       = 0x3
	NL80211_HE_MAX_CAPABILITY_LEN                           = 0x36
	NL80211_HE_MIN_CAPABILITY_LEN                           = 0x10
	NL80211_HE_NSS_MAX                                      = 0x8
	NL80211_HE_OBSS_PD_ATTR_BSS_COLOR_BITMAP                = 0x4
	NL80211_HE_OBSS_PD_ATTR_MAX                             = 0x6
	NL80211_HE_OBSS_PD_ATTR_MAX_OFFSET                      = 0x2
	NL80211_HE_OBSS_PD_ATTR_MIN_OFFSET                      = 0x1
	NL80211_HE_OBSS_PD_ATTR_NON_SRG_MAX_OFFSET              = 0x3
	NL80211_HE_OBSS_PD_ATTR_PARTIAL_BSSID_BITMAP            = 0x5
	NL80211_HE_OBSS_PD_ATTR_SR_CTRL                         = 0x6
	NL80211_HIDDEN_SSID_NOT_IN_USE                          = 0x0
	NL80211_HIDDEN_SSID_ZERO_CONTENTS                       = 0x2
	NL80211_HIDDEN_SSID_ZERO_LEN                            = 0x1
	NL80211_HT_CAPABILITY_LEN                               = 0x1a
	NL80211_IFACE_COMB_BI_MIN_GCD                           = 0x7
	NL80211_IFACE_COMB_LIMITS                               = 0x1
	NL80211_IFACE_COMB_MAXNUM                               = 0x2
	NL80211_IFACE_COMB_NUM_CHANNELS                         = 0x4
	NL80211_IFACE_COMB_RADAR_DETECT_REGIONS                 = 0x6
	NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS                  = 0x5
	NL80211_IFACE_COMB_STA_AP_BI_MATCH                      = 0x3
	NL80211_IFACE_COMB_UNSPEC                               = 0x0
	NL80211_IFACE_LIMIT_MAX                                 = 0x1
	NL80211_IFACE_LIMIT_TYPES                               = 0x2
	NL80211_IFACE_LIMIT_UNSPEC                              = 0x0
	NL80211_IFTYPE_ADHOC                                    = 0x1
	NL80211_IFTYPE_AKM_ATTR_IFTYPES                         = 0x1
	NL80211_IFTYPE_AKM_ATTR_MAX                             = 0x2
	NL80211_IFTYPE_AKM_ATTR_SUITES                          = 0x2
	NL80211_IFTYPE_AP                                       = 0x3
	NL80211_IFTYPE_AP_VLAN                                  = 0x4
	NL80211_IFTYPE_MAX                                      = 0xc
	NL80211_IFTYPE_MESH_POINT                               = 0x7
	NL80211_IFTYPE_MONITOR                                  = 0x6
	NL80211_IFTYPE_NAN                                      = 0xc
	NL80211_IFTYPE_OCB                                      = 0xb
	NL80211_IFTYPE_P2P_CLIENT                               = 0x8
	NL80211_IFTYPE_P2P_DEVICE                               = 0xa
	NL80211_IFTYPE_P2P_GO                                   = 0x9
	NL80211_IFTYPE_STATION                                  = 0x2
	NL80211_IFTYPE_UNSPECIFIED                              = 0x0
	NL80211_IFTYPE_WDS                                      = 0x5
	NL80211_KCK_EXT_LEN                                     = 0x18
	NL80211_KCK_LEN                                         = 0x10
	NL80211_KEK_EXT_LEN                                     = 0x20
	NL80211_KEK_LEN                                         = 0x10
	NL80211_KEY_CIPHER                                      = 0x3
	NL80211_KEY_DATA                                        = 0x1
	NL80211_KEY_DEFAULT_BEACON                              = 0xa
	NL80211_KEY_DEFAULT                                     = 0x5
	NL80211_KEY_DEFAULT_MGMT                                = 0x6
	NL80211_KEY_DEFAULT_TYPE_MULTICAST                      = 0x2
	NL80211_KEY_DEFAULT_TYPES                               = 0x8
	NL80211_KEY_DEFAULT_TYPE_UNICAST                        = 0x1
	NL80211_KEY_IDX                                         = 0x2
	NL80211_KEY_MAX                                         = 0xa
	NL80211_KEY_MODE                                        = 0x9
	NL80211_KEY_NO_TX                                       = 0x1
	NL80211_KEY_RX_TX                                       = 0x0
	NL80211_KEY_SEQ                                         = 0x4
	NL80211_KEY_SET_TX                                      = 0x2
	NL80211_KEY_TYPE                                        = 0x7
	NL80211_KEYTYPE_GROUP                                   = 0x0
	NL80211_KEYTYPE_PAIRWISE                                = 0x1
	NL80211_KEYTYPE_PEERKEY                                 = 0x2
	NL80211_MAX_NR_AKM_SUITES                               = 0x2
	NL80211_MAX_NR_CIPHER_SUITES                            = 0x5
	NL80211_MAX_SUPP_HT_RATES                               = 0x4d
	NL80211_MAX_SUPP_RATES                                  = 0x20
	NL80211_MAX_SUPP_REG_RULES                              = 0x80
	NL80211_MBSSID_CONFIG_ATTR_EMA                          = 0x5
	NL80211_MBSSID_CONFIG_ATTR_INDEX                        = 0x3
	NL80211_MBSSID_CONFIG_ATTR_MAX                          = 0x5
	NL80211_MBSSID_CONFIG_ATTR_MAX_EMA_PROFILE_PERIODICITY  = 0x2
	NL80211_MBSSID_CONFIG_ATTR_MAX_INTERFACES               = 0x1
	NL80211_MBSSID_CONFIG_ATTR_TX_IFINDEX                   = 0x4
	NL80211_MESHCONF_ATTR_MAX                               = 0x1f
	NL80211_MESHCONF_AUTO_OPEN_PLINKS                       = 0x7
	NL80211_MESHCONF_AWAKE_WINDOW                           = 0x1b
	NL80211_MESHCONF_CONFIRM_TIMEOUT                        = 0x2
	NL80211_MESHCONF_CONNECTED_TO_AS                        = 0x1f
	NL80211_MESHCONF_CONNECTED_TO_GATE                      = 0x1d
	NL80211_MESHCONF_ELEMENT_TTL                            = 0xf
	NL80211_MESHCONF_FORWARDING                             = 0x13
	NL80211_MESHCONF_GATE_ANNOUNCEMENTS                     = 0x11
	NL80211_MESHCONF_HOLDING_TIMEOUT                        = 0x3
	NL80211_MESHCONF_HT_OPMODE                              = 0x16
	NL80211_MESHCONF_HWMP_ACTIVE_PATH_TIMEOUT               = 0xb
	NL80211_MESHCONF_HWMP_CONFIRMATION_INTERVAL             = 0x19
	NL80211_MESHCONF_HWMP_MAX_PREQ_RETRIES                  = 0x8
	NL80211_MESHCONF_HWMP_NET_DIAM_TRVS_TIME                = 0xd
	NL80211_MESHCONF_HWMP_PATH_TO_ROOT_TIMEOUT              = 0x17
	NL80211_MESHCONF_HWMP_PERR_MIN_INTERVAL                 = 0x12
	NL80211_MESHCONF_HWMP_PREQ_MIN_INTERVAL                 = 0xc
	NL80211_MESHCONF_HWMP_RANN_INTERVAL                     = 0x10
	NL80211_MESHCONF_HWMP_ROOT_INTERVAL                     = 0x18
	NL80211_MESHCONF_HWMP_ROOTMODE                          = 0xe
	NL80211_MESHCONF_MAX_PEER_LINKS                         = 0x4
	NL80211_MESHCONF_MAX_RETRIES                            = 0x5
	NL80211_MESHCONF_MIN_DISCOVERY_TIMEOUT                  = 0xa
	NL80211_MESHCONF_NOLEARN                                = 0x1e
	NL80211_MESHCONF_PATH_REFRESH_TIME                      = 0x9
	NL80211_MESHCONF_PLINK_TIMEOUT                          = 0x1c
	NL80211_MESHCONF_POWER_MODE                             = 0x1a
	NL80211_MESHCONF_RETRY_TIMEOUT                          = 0x1
	NL80211_MESHCONF_RSSI_THRESHOLD                         = 0x14
	NL80211_MESHCONF_SYNC_OFFSET_MAX_NEIGHBOR               = 0x15
	NL80211_MESHCONF_TTL                                    = 0x6
	NL80211_MESH_POWER_ACTIVE                               = 0x1
	NL80211_MESH_POWER_DEEP_SLEEP                           = 0x3
	NL80211_MESH_POWER_LIGHT_SLEEP                          = 0x2
	NL80211_MESH_POWER_MAX                                  = 0x3
	NL80211_MESH_POWER_UNKNOWN                              = 0x0
	NL80211_MESH_SETUP_ATTR_MAX                             = 0x8
	NL80211_MESH_SETUP_AUTH_PROTOCOL                        = 0x8
	NL80211_MESH_SETUP_ENABLE_VENDOR_METRIC                 = 0x2
	NL80211_MESH_SETUP_ENABLE_VENDOR_PATH_SEL               = 0x1
	NL80211_MESH_SETUP_ENABLE_VENDOR_SYNC                   = 0x6
	NL80211_MESH_SETUP_IE                                   = 0x3
	NL80211_MESH_SETUP_USERSPACE_AMPE                       = 0x5
	NL80211_MESH_SETUP_USERSPACE_AUTH                       = 0x4
	NL80211_MESH_SETUP_USERSPACE_MPM                        = 0x7
	NL80211_MESH_SETUP_VENDOR_PATH_SEL_IE                   = 0x3
	NL80211_MFP_NO                                          = 0x0
	NL80211_MFP_OPTIONAL                                    = 0x2
	NL80211_MFP_REQUIRED                                    = 0x1
	NL80211_MIN_REMAIN_ON_CHANNEL_TIME                      = 0xa
	NL80211_MNTR_FLAG_ACTIVE                                = 0x6
	NL80211_MNTR_FLAG_CONTROL                               = 0x3
	NL80211_MNTR_FLAG_COOK_FRAMES                           = 0x5
	NL80211_MNTR_FLAG_FCSFAIL                               = 0x1
	NL80211_MNTR_FLAG_MAX                                   = 0x6
	NL80211_MNTR_FLAG_OTHER_BSS                             = 0x4
	NL80211_MNTR_FLAG_PLCPFAIL                              = 0x2
	NL80211_MPATH_FLAG_ACTIVE                               = 0x1
	NL80211_MPATH_FLAG_FIXED                                = 0x8
	NL80211_MPATH_FLAG_RESOLVED                             = 0x10
	NL80211_MPATH_FLAG_RESOLVING                            = 0x2
	NL80211_MPATH_FLAG_SN_VALID                             = 0x4
	NL80211_MPATH_INFO_DISCOVERY_RETRIES                    = 0x7
	NL80211_MPATH_INFO_DISCOVERY_TIMEOUT                    = 0x6
	NL80211_MPATH_INFO_EXPTIME                              = 0x4
	NL80211_MPATH_INFO_FLAGS                                = 0x5
	NL80211_MPATH_INFO_FRAME_QLEN                           = 0x1
	NL80211_MPATH_INFO_HOP_COUNT                            = 0x8
	NL80211_MPATH_INFO_MAX                                  = 0x9
	NL80211_MPATH_INFO_METRIC                               = 0x3
	NL80211_MPATH_INFO_PATH_CHANGE                          = 0x9
	NL80211_MPATH_INFO_SN                                   = 0x2
	NL80211_MULTICAST_GROUP_CONFIG                          = "config"
	NL80211_MULTICAST_GROUP_MLME                            = "mlme"
	NL80211_MULTICAST_GROUP_NAN                             = "nan"
	NL80211_MULTICAST_GROUP_REG                             = "regulatory"
	NL80211_MULTICAST_GROUP_SCAN                            = "scan"
	NL80211_MULTICAST_GROUP_TESTMODE                        = "testmode"
	NL80211_MULTICAST_GROUP_VENDOR                          = "vendor"
	NL80211_NAN_FUNC_ATTR_MAX                               = 0x10
	NL80211_NAN_FUNC_CLOSE_RANGE                            = 0x9
	NL80211_NAN_FUNC_FOLLOW_UP                              = 0x2
	NL80211_NAN_FUNC_FOLLOW_UP_DEST                         = 0x8
	NL80211_NAN_FUNC_FOLLOW_UP_ID                           = 0x6
	NL80211_NAN_FUNC_FOLLOW_UP_REQ_ID                       = 0x7
	NL80211_NAN_FUNC_INSTANCE_ID                            = 0xf
	NL80211_NAN_FUNC_MAX_TYPE                               = 0x2
	NL80211_NAN_FUNC_PUBLISH_BCAST                          = 0x4
	NL80211_NAN_FUNC_PUBLISH                                = 0x0
	NL80211_NAN_FUNC_PUBLISH_TYPE                           = 0x3
	NL80211_NAN_FUNC_RX_MATCH_FILTER                        = 0xd
	NL80211_NAN_FUNC_SERVICE_ID                             = 0x2
	NL80211_NAN_FUNC_SERVICE_ID_LEN                         = 0x6
	NL80211_NAN_FUNC_SERVICE_INFO                           = 0xb
	NL80211_NAN_FUNC_SERVICE_SPEC_INFO_MAX_LEN              = 0xff
	NL80211_NAN_FUNC_SRF                                    = 0xc
	NL80211_NAN_FUNC_SRF_MAX_LEN                            = 0xff
	NL80211_NAN_FUNC_SUBSCRIBE_ACTIVE                       = 0x5
	NL80211_NAN_FUNC_SUBSCRIBE                              = 0x1
	NL80211_NAN_FUNC_TERM_REASON                            = 0x10
	NL80211_NAN_FUNC_TERM_REASON_ERROR                      = 0x2
	NL80211_NAN_FUNC_TERM_REASON_TTL_EXPIRED                = 0x1
	NL80211_NAN_FUNC_TERM_REASON_USER_REQUEST               = 0x0
	NL80211_NAN_FUNC_TTL                                    = 0xa
	NL80211_NAN_FUNC_TX_MATCH_FILTER                        = 0xe
	NL80211_NAN_FUNC_TYPE                                   = 0x1
	NL80211_NAN_MATCH_ATTR_MAX                              = 0x2
	NL80211_NAN_MATCH_FUNC_LOCAL                            = 0x1
	NL80211_NAN_MATCH_FUNC_PEER                             = 0x2
	NL80211_NAN_SOLICITED_PUBLISH                           = 0x1
	NL80211_NAN_SRF_ATTR_MAX                                = 0x4
	NL80211_NAN_SRF_BF                                      = 0x2
	NL80211_NAN_SRF_BF_IDX                                  = 0x3
	NL80211_NAN_SRF_INCLUDE                                 = 0x1
	NL80211_NAN_SRF_MAC_ADDRS                               = 0x4
	NL80211_NAN_UNSOLICITED_PUBLISH                         = 0x2
	NL80211_NUM_ACS                                         = 0x4
	NL80211_P2P_PS_SUPPORTED                                = 0x1
	NL80211_P2P_PS_UNSUPPORTED                              = 0x0
	NL80211_PKTPAT_MASK                                     = 0x1
	NL80211_PKTPAT_OFFSET                                   = 0x3
	NL80211_PKTPAT_PATTERN                                  = 0x2
	NL80211_PLINK_ACTION_BLOCK                              = 0x2
	NL80211_PLINK_ACTION_NO_ACTION                          = 0x0
	NL80211_PLINK_ACTION_OPEN                               = 0x1
	NL80211_PLINK_BLOCKED                                   = 0x6
	NL80211_PLINK_CNF_RCVD                                  = 0x3
	NL80211_PLINK_ESTAB                                     = 0x4
	NL80211_PLINK_HOLDING                                   = 0x5
	NL80211_PLINK_LISTEN                                    = 0x0
	NL80211_PLINK_OPN_RCVD                                  = 0x2
	NL80211_PLINK_OPN_SNT                                   = 0x1
	NL80211_PMKSA_CANDIDATE_BSSID                           = 0x2
	NL80211_PMKSA_CANDIDATE_INDEX                           = 0x1
	NL80211_PMKSA_CANDIDATE_PREAUTH                         = 0x3
	NL80211_PMSR_ATTR_MAX                                   = 0x5
	NL80211_PMSR_ATTR_MAX_PEERS                             = 0x1
	NL80211_PMSR_ATTR_PEERS                                 = 0x5
	NL80211_PMSR_ATTR_RANDOMIZE_MAC_ADDR                    = 0x3
	NL80211_PMSR_ATTR_REPORT_AP_TSF                         = 0x2
	NL80211_PMSR_ATTR_TYPE_CAPA                             = 0x4
	NL80211_PMSR_FTM_CAPA_ATTR_ASAP                         = 0x1
	NL80211_PMSR_FTM_CAPA_ATTR_BANDWIDTHS                   = 0x6
	NL80211_PMSR_FTM_CAPA_ATTR_MAX_BURSTS_EXPONENT          = 0x7
	NL80211_PMSR_FTM_CAPA_ATTR_MAX                          = 0xa
	NL80211_PMSR_FTM_CAPA_ATTR_MAX_FTMS_PER_BURST           = 0x8
	NL80211_PMSR_FTM_CAPA_ATTR_NON_ASAP                     = 0x2
	NL80211_PMSR_FTM_CAPA_ATTR_NON_TRIGGER_BASED            = 0xa
	NL80211_PMSR_FTM_CAPA_ATTR_PREAMBLES                    = 0x5
	NL80211_PMSR_FTM_CAPA_ATTR_REQ_CIVICLOC                 = 0x4
	NL80211_PMSR_FTM_CAPA_ATTR_REQ_LCI                      = 0x3
	NL80211_PMSR_FTM_CAPA_ATTR_TRIGGER_BASED                = 0x9
	NL80211_PMSR_FTM_FAILURE_BAD_CHANGED_PARAMS             = 0x7
	NL80211_PMSR_FTM_FAILURE_INVALID_TIMESTAMP              = 0x5
	NL80211_PMSR_FTM_FAILURE_NO_RESPONSE                    = 0x1
	NL80211_PMSR_FTM_FAILURE_PEER_BUSY                      = 0x6
	NL80211_PMSR_FTM_FAILURE_PEER_NOT_CAPABLE               = 0x4
	NL80211_PMSR_FTM_FAILURE_REJECTED                       = 0x2
	NL80211_PMSR_FTM_FAILURE_UNSPECIFIED                    = 0x0
	NL80211_PMSR_FTM_FAILURE_WRONG_CHANNEL                  = 0x3
	NL80211_PMSR_FTM_REQ_ATTR_ASAP                          = 0x1
	NL80211_PMSR_FTM_REQ_ATTR_BSS_COLOR                     = 0xd
	NL80211_PMSR_FTM_REQ_ATTR_BURST_DURATION                = 0x5
	NL80211_PMSR_FTM_REQ_ATTR_BURST_PERIOD                  = 0x4
	NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST                = 0x6
	NL80211_PMSR_FTM_REQ_ATTR_LMR_FEEDBACK                  = 0xc
	NL80211_PMSR_FTM_REQ_ATTR_MAX                           = 0xd
	NL80211_PMSR_FTM_REQ_ATTR_NON_TRIGGER_BASED             = 0xb
	NL80211_PMSR_FTM_REQ_ATTR_NUM_BURSTS_EXP                = 0x3
	NL80211_PMSR_FTM_REQ_ATTR_NUM_FTMR_RETRIES              = 0x7
	NL80211_PMSR_FTM_REQ_ATTR_PREAMBLE                      = 0x2
	NL80211_PMSR_FTM_REQ_ATTR_REQUEST_CIVICLOC              = 0x9
	NL80211_PMSR_FTM_REQ_ATTR_REQUEST_LCI                   = 0x8
	NL80211_PMSR_FTM_REQ_ATTR_TRIGGER_BASED                 = 0xa
	NL80211_PMSR_FTM_RESP_ATTR_BURST_DURATION               = 0x7
	NL80211_PMSR_FTM_RESP_ATTR_BURST_INDEX                  = 0x2
	NL80211_PMSR_FTM_RESP_ATTR_BUSY_RETRY_TIME              = 0x5
	NL80211_PMSR_FTM_RESP_ATTR_CIVICLOC                     = 0x14
	NL80211_PMSR_FTM_RESP_ATTR_DIST_AVG                     = 0x10
	NL80211_PMSR_FTM_RESP_ATTR_DIST_SPREAD                  = 0x12
	NL80211_PMSR_FTM_RESP_ATTR_DIST_VARIANCE                = 0x11
	NL80211_PMSR_FTM_RESP_ATTR_FAIL_REASON                  = 0x1
	NL80211_PMSR_FTM_RESP_ATTR_FTMS_PER_BURST               = 0x8
	NL80211_PMSR_FTM_RESP_ATTR_LCI                          = 0x13
	NL80211_PMSR_FTM_RESP_ATTR_MAX                          = 0x15
	NL80211_PMSR_FTM_RESP_ATTR_NUM_BURSTS_EXP               = 0x6
	NL80211_PMSR_FTM_RESP_ATTR_NUM_FTMR_ATTEMPTS            = 0x3
	NL80211_PMSR_FTM_RESP_ATTR_NUM_FTMR_SUCCESSES           = 0x4
	NL80211_PMSR_FTM_RESP_ATTR_PAD                          = 0x15
	NL80211_PMSR_FTM_RESP_ATTR_RSSI_AVG                     = 0x9
	NL80211_PMSR_FTM_RESP_ATTR_RSSI_SPREAD                  = 0xa
	NL80211_PMSR_FTM_RESP_ATTR_RTT_AVG                      = 0xd
	NL80211_PMSR_FTM_RESP_ATTR_RTT_SPREAD                   = 0xf
	NL80211_PMSR_FTM_RESP_ATTR_RTT_VARIANCE                 = 0xe
	NL80211_PMSR_FTM_RESP_ATTR_RX_RATE                      = 0xc
	NL80211_PMSR_FTM_RESP_ATTR_TX_RATE                      = 0xb
	NL80211_PMSR_PEER_ATTR_ADDR                             = 0x1
	NL80211_PMSR_PEER_ATTR_CHAN                             = 0x2
	NL80211_PMSR_PEER_ATTR_MAX                              = 0x4
	NL80211_PMSR_PEER_ATTR_REQ                              = 0x3
	NL80211_PMSR_PEER_ATTR_RESP                             = 0x4
	NL80211_PMSR_REQ_ATTR_DATA                              = 0x1
	NL80211_PMSR_REQ_ATTR_GET_AP_TSF                        = 0x2
	NL80211_PMSR_REQ_ATTR_MAX                               = 0x2
	NL80211_PMSR_RESP_ATTR_AP_TSF                           = 0x4
	NL80211_PMSR_RESP_ATTR_DATA                             = 0x1
	NL80211_PMSR_RESP_ATTR_FINAL                            = 0x5
	NL80211_PMSR_RESP_ATTR_HOST_TIME                        = 0x3
	NL80211_PMSR_RESP_ATTR_MAX                              = 0x6
	NL80211_PMSR_RESP_ATTR_PAD                              = 0x6
	NL80211_PMSR_RESP_ATTR_STATUS                           = 0x2
	NL80211_PMSR_STATUS_FAILURE                             = 0x3
	NL80211_PMSR_STATUS_REFUSED                             = 0x1
	NL80211_PMSR_STATUS_SUCCESS                             = 0x0
	NL80211_PMSR_STATUS_TIMEOUT                             = 0x2
	NL80211_PMSR_TYPE_FTM                                   = 0x1
	NL80211_PMSR_TYPE_INVALID                               = 0x0
	NL80211_PMSR_TYPE_MAX                                   = 0x1
	NL80211_PREAMBLE_DMG                                    = 0x3
	NL80211_PREAMBLE_HE                                     = 0x4
	NL80211_PREAMBLE_HT                                     = 0x1
	NL80211_PREAMBLE_LEGACY                                 = 0x0
	NL80211_PREAMBLE_VHT                                    = 0x2
	NL80211_PROBE_RESP_OFFLOAD_SUPPORT_80211U               = 0x8
	NL80211_PROBE_RESP_OFFLOAD_SUPPORT_P2P                  = 0x4
	NL80211_PROBE_RESP_OFFLOAD_SUPPORT_WPS2                 = 0x2
	NL80211_PROBE_RESP_OFFLOAD_SUPPORT_WPS                  = 0x1
	NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP               = 0x1
	NL80211_PS_DISABLED                                     = 0x0
	NL80211_PS_ENABLED                                      = 0x1
	NL80211_RADAR_CAC_ABORTED                               = 0x2
	NL80211_RADAR_CAC_FINISHED                              = 0x1
	NL80211_RADAR_CAC_STARTED                               = 0x5
	NL80211_RADAR_DETECTED                                  = 0x0
	NL80211_RADAR_NOP_FINISHED                              = 0x3
	NL80211_RADAR_PRE_CAC_EXPIRED                           = 0x4
	NL80211_RATE_INFO_10_MHZ_WIDTH                          = 0xb
	NL80211_RATE_INFO_160_MHZ_WIDTH                         = 0xa
	NL80211_RATE_INFO_320_MHZ_WIDTH                         = 0x12
	NL80211_RATE_INFO_40_MHZ_WIDTH                          = 0x3
	NL80211_RATE_INFO_5_MHZ_WIDTH                           = 0xc
	NL80211_RATE_INFO_80_MHZ_WIDTH                          = 0x8
	NL80211_RATE_INFO_80P80_MHZ_WIDTH                       = 0x9
	NL80211_RATE_INFO_BITRATE32                             = 0x5
	NL80211_RATE_INFO_BITRATE                               = 0x1
	NL80211_RATE_INFO_EHT_GI_0_8                            = 0x0
	NL80211_RATE_INFO_EHT_GI_1_6                            = 0x1
	NL80211_RATE_INFO_EHT_GI_3_2                            = 0x2
	NL80211_RATE_INFO_EHT_GI                                = 0x15
	NL80211_RATE_INFO_EHT_MCS                               = 0x13
	NL80211_RATE_INFO_EHT_NSS                               = 0x14
	NL80211_RATE_INFO_EHT_RU_ALLOC_106                      = 0x3
	NL80211_RATE_INFO_EHT_RU_ALLOC_106P26                   = 0x4
	NL80211_RATE_INFO_EHT_RU_ALLOC_242                      = 0x5
	NL80211_RATE_INFO_EHT_RU_ALLOC_26                       = 0x0
	NL80211_RATE_INFO_EHT_RU_ALLOC_2x996                    = 0xb
	NL80211_RATE_INFO_EHT_RU_ALLOC_2x996P484                = 0xc
	NL80211_RATE_INFO_EHT_RU_ALLOC_3x996                    = 0xd
	NL80211_RATE_INFO_EHT_RU_ALLOC_3x996P484                = 0xe
	NL80211_RATE_INFO_EHT_RU_ALLOC_484                      = 0x6
	NL80211_RATE_INFO_EHT_RU_ALLOC_484P242                  = 0x7
	NL80211_RATE_INFO_EHT_RU_ALLOC_4x996                    = 0xf
	NL80211_RATE_INFO_EHT_RU_ALLOC_52                       = 0x1
	NL80211_RATE_INFO_EHT_RU_ALLOC_52P26                    = 0x2
	NL80211_RATE_INFO_EHT_RU_ALLOC_996                      = 0x8
	NL80211_RATE_INFO_EHT_RU_ALLOC_996P484                  = 0x9
	NL80211_RATE_INFO_EHT_RU_ALLOC_996P484P242              = 0xa
	NL80211_RATE_INFO_EHT_RU_ALLOC                          = 0x16
	NL80211_RATE_INFO_HE_1XLTF                              = 0x0
	NL80211_RATE_INFO_HE_2XLTF                              = 0x1
	NL80211_RATE_INFO_HE_4XLTF                              = 0x2
	NL80211_RATE_INFO_HE_DCM                                = 0x10
	NL80211_RATE_INFO_HE_GI_0_8                             = 0x0
	NL80211_RATE_INFO_HE_GI_1_6                             = 0x1
	NL80211_RATE_INFO_HE_GI_3_2                             = 0x2
	NL80211_RATE_INFO_HE_GI                                 = 0xf
	NL80211_RATE_INFO_HE_MCS                                = 0xd
	NL80211_RATE_INFO_HE_NSS                                = 0xe
	NL80211_RATE_INFO_HE_RU_ALLOC_106                       = 0x2
	NL80211_RATE_INFO_HE_RU_ALLOC_242                       = 0x3
	NL80211_RATE_INFO_HE_RU_ALLOC_26                        = 0x0
	NL80211_RATE_INFO_HE_RU_ALLOC_2x996                     = 0x6
	NL80211_RATE_INFO_HE_RU_ALLOC_484                       = 0x4
	NL80211_RATE_INFO_HE_RU_ALLOC_52                        = 0x1
	NL80211_RATE_INFO_HE_RU_ALLOC_996                       = 0x5
	NL80211_RATE_INFO_HE_RU_ALLOC                           = 0x11
	NL80211_RATE_INFO_MAX                                   = 0x1d
	NL80211_RATE_INFO_MCS                                   = 0x2
	NL80211_RATE_INFO_SHORT_GI                              = 0x4
	NL80211_RATE_INFO_VHT_MCS                               = 0x6
	NL80211_RATE_INFO_VHT_NSS                               = 0x7
	NL80211_REGDOM_SET_BY_CORE                              = 0x0
	NL80211_REGDOM_SET_BY_COUNTRY_IE                        = 0x3
	NL80211_REGDOM_SET_BY_DRIVER                            = 0x2
	NL80211_REGDOM_SET_BY_USER                              = 0x1
	NL80211_REGDOM_TYPE_COUNTRY                             = 0x0
	NL80211_REGDOM_TYPE_CUSTOM_WORLD                        = 0x2
	NL80211_REGDOM_TYPE_INTERSECTION                        = 0x3
	NL80211_REGDOM_TYPE_WORLD                               = 0x1
	NL80211_REG_RULE_ATTR_MAX                               = 0x8
	NL80211_REKEY_DATA_AKM                                  = 0x4
	NL80211_REKEY_DATA_KCK                                  = 0x2
	NL80211_REKEY_DATA_KEK                                  = 0x1
	NL80211_REKEY_DATA_REPLAY_CTR                           = 0x3
	NL80211_REPLAY_CTR_LEN                                  = 0x8
	NL80211_RRF_AUTO_BW                                     = 0x800
	NL80211_RRF_DFS                                         = 0x10
	NL80211_RRF_GO_CONCURRENT                               = 0x1000
	NL80211_RRF_IR_CONCURRENT                               = 0x1000
	NL80211_RRF_NO_160MHZ                                   = 0x10000
	NL80211_RRF_NO_320MHZ                                   = 0x40000
	NL80211_RRF_NO_80MHZ                                    = 0x8000
	NL80211_RRF_NO_CCK                                      = 0x2
	NL80211_RRF_NO_HE                                       = 0x20000
	NL80211_RRF_NO_HT40                                     = 0x6000
	NL80211_RRF_NO_HT40MINUS                                = 0x2000
	NL80211_RRF_NO_HT40PLUS                                 = 0x4000
	NL80211_RRF_NO_IBSS                                     = 0x80
	NL80211_RRF_NO_INDOOR                                   = 0x4
	NL80211_RRF_NO_IR_ALL                                   = 0x180
	NL80211_RRF_NO_IR                                       = 0x80
	NL80211_RRF_NO_OFDM                                     = 0x1
	NL80211_RRF_NO_OUTDOOR                                  = 0x8
	NL80211_RRF_PASSIVE_SCAN                                = 0x80
	NL80211_RRF_PTMP_ONLY                                   = 0x40
	NL80211_RRF_PTP_ONLY                                    = 0x20
	NL80211_RXMGMT_FLAG_ANSWERED                            = 0x1
	NL80211_RXMGMT_FLAG_EXTERNAL_AUTH                       = 0x2
	NL80211_SAE_PWE_BOTH                                    = 0x3
	NL80211_SAE_PWE_HASH_TO_ELEMENT                         = 0x2
	NL80211_SAE_PWE_HUNT_AND_PECK                           = 0x1
	NL80211_SAE_PWE_UNSPECIFIED                             = 0x0
	NL80211_SAR_ATTR_MAX                                    = 0x2
	NL80211_SAR_ATTR_SPECS                                  = 0x2
	NL80211_SAR_ATTR_SPECS_END_FREQ                         = 0x4
	NL80211_SAR_ATTR_SPECS_MAX                              = 0x4
	NL80211_SAR_ATTR_SPECS_POWER                            = 0x1
	NL80211_SAR_ATTR_SPECS_RANGE_INDEX                      = 0x2
	NL80211_SAR_ATTR_SPECS_START_FREQ                       = 0x3
	NL80211_SAR_ATTR_TYPE                                   = 0x1
	NL80211_SAR_TYPE_POWER                                  = 0x0
	NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP               = 0x20
	NL80211_SCAN_FLAG_AP                                    = 0x4
	NL80211_SCAN_FLAG_COLOCATED_6GHZ                        = 0x4000
	NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME                 = 0x10
	NL80211_SCAN_FLAG_FLUSH                                 = 0x2
	NL80211_SCAN_FLAG_FREQ_KHZ                              = 0x2000
	NL80211_SCAN_FLAG_HIGH_ACCURACY                         = 0x400
	NL80211_SCAN_FLAG_LOW_POWER                             = 0x200
	NL80211_SCAN_FLAG_LOW_PRIORITY                          = 0x1
	NL80211_SCAN_FLAG_LOW_SPAN                              = 0x100
	NL80211_SCAN_FLAG_MIN_PREQ_CONTENT                      = 0x1000
	NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION    = 0x80
	NL80211_SCAN_FLAG_OCE_PROBE_REQ_HIGH_TX_RATE            = 0x40
	NL80211_SCAN_FLAG_RANDOM_ADDR                           = 0x8
	NL80211_SCAN_FLAG_RANDOM_SN                             = 0x800
	NL80211_SCAN_RSSI_THOLD_OFF                             = -0x12c
	NL80211_SCHED_SCAN_MATCH_ATTR_BSSID                     = 0x5
	NL80211_SCHED_SCAN_MATCH_ATTR_MAX                       = 0x6
	NL80211_SCHED_SCAN_MATCH_ATTR_RELATIVE_RSSI             = 0x3
	NL80211_SCHED_SCAN_MATCH_ATTR_RSSI_ADJUST               = 0x4
	NL80211_SCHED_SCAN_MATCH_ATTR_RSSI                      = 0x2
	NL80211_SCHED_SCAN_MATCH_ATTR_SSID                      = 0x1
	NL80211_SCHED_SCAN_MATCH_PER_BAND_RSSI                  = 0x6
	NL80211_SCHED_SCAN_PLAN_INTERVAL                        = 0x1
	NL80211_SCHED_SCAN_PLAN_ITERATIONS                      = 0x2
	NL80211_SCHED_SCAN_PLAN_MAX                             = 0x2
	NL80211_SMPS_DYNAMIC                                    = 0x2
	NL80211_SMPS_MAX                                        = 0x2
	NL80211_SMPS_OFF                                        = 0x0
	NL80211_SMPS_STATIC                                     = 0x1
	NL80211_STA_BSS_PARAM_BEACON_INTERVAL                   = 0x5
	NL80211_STA_BSS_PARAM_CTS_PROT                          = 0x1
	NL80211_STA_BSS_PARAM_DTIM_PERIOD                       = 0x4
	NL80211_STA_BSS_PARAM_MAX                               = 0x5
	NL80211_STA_BSS_PARAM_SHORT_PREAMBLE                    = 0x2
	NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME                   = 0x3
	NL80211_STA_FLAG_ASSOCIATED                             = 0x7
	NL80211_STA_FLAG_AUTHENTICATED                          = 0x5
	NL80211_STA_FLAG_AUTHORIZED                             = 0x1
	NL80211_STA_FLAG_MAX                                    = 0x8
	NL80211_STA_FLAG_MAX_OLD_API                            = 0x6
	NL80211_STA_FLAG_MFP                                    = 0x4
	NL80211_STA_FLAG_SHORT_PREAMBLE                         = 0x2
	NL80211_STA_FLAG_TDLS_PEER                              = 0x6
	NL80211_STA_FLAG_WME                                    = 0x3
	NL80211_STA_INFO_ACK_SIGNAL_AVG                         = 0x23
	NL80211_STA_INFO_ACK_SIGNAL                             = 0x22
	NL80211_STA_INFO_AIRTIME_LINK_METRIC                    = 0x29
	NL80211_STA_INFO_AIRTIME_WEIGHT                         = 0x28
	NL80211_STA_INFO_ASSOC_AT_BOOTTIME                      = 0x2a
	NL80211_STA_INFO_BEACON_LOSS                            = 0x12
	NL80211_STA_INFO_BEACON_RX                              = 0x1d
	NL80211_STA_INFO_BEACON_SIGNAL_AVG                      = 0x1e
	NL80211_STA_INFO_BSS_PARAM                              = 0xf
	NL80211_STA_INFO_CHAIN_SIGNAL_AVG                       = 0x1a
	NL80211_STA_INFO_CHAIN_SIGNAL                           = 0x19
	NL80211_STA_INFO_CONNECTED_TIME                         = 0x10
	NL80211_STA_INFO_CONNECTED_TO_AS                        = 0x2b
	NL80211_STA_INFO_CONNECTED_TO_GATE                      = 0x26
	NL80211_STA_INFO_DATA_ACK_SIGNAL_AVG                    = 0x23
	NL80211_STA_INFO_EXPECTED_THROUGHPUT                    = 0x1b
	NL80211_STA_INFO_FCS_ERROR_COUNT                        = 0x25
	NL80211_STA_INFO_INACTIVE_TIME                          = 0x1
	NL80211_STA_INFO_LLID                                   = 0x4
	NL80211_STA_INFO_LOCAL_PM                               = 0x14
	NL80211_STA_INFO_MAX                                    = 0x2b
	NL80211_STA_INFO_NONPEER_PM                             = 0x16
	NL80211_STA_INFO_PAD                                    = 0x21
	NL80211_STA_INFO_PEER_PM                                = 0x15
	NL80211_STA_INFO_PLID                                   = 0x5
	NL80211_STA_INFO_PLINK_STATE                            = 0x6
	NL80211_STA_INFO_RX_BITRATE                             = 0xe
	NL80211_STA_INFO_RX_BYTES64                             = 0x17
	NL80211_STA_INFO_RX_BYTES                               = 0x2
	NL80211_STA_INFO_RX_DROP_MISC                           = 0x1c
	NL80211_STA_INFO_RX_DURATION                            = 0x20
	NL80211_STA_INFO_RX_MPDUS                               = 0x24
	NL80211_STA_INFO_RX_PACKETS                             = 0x9
	NL80211_STA_INFO_SIGNAL_AVG                             = 0xd
	NL80211_STA_INFO_SIGNAL                                 = 0x7
	NL80211_STA_INFO_STA_FLAGS                              = 0x11
	NL80211_STA_INFO_TID_STATS                              = 0x1f
	NL80211_STA_INFO_T_OFFSET                               = 0x13
	NL80211_STA_INFO_TX_BITRATE                             = 0x8
	NL80211_STA_INFO_TX_BYTES64                             = 0x18
	NL80211_STA_INFO_TX_BYTES                               = 0x3
	NL80211_STA_INFO_TX_DURATION                            = 0x27
	NL80211_STA_INFO_TX_FAILED                              = 0xc
	NL80211_STA_INFO_TX_PACKETS                             = 0xa
	NL80211_STA_INFO_TX_RETRIES                             = 0xb
	NL80211_STA_WME_MAX                                     = 0x2
	NL80211_STA_WME_MAX_SP                                  = 0x2
	NL80211_STA_WME_UAPSD_QUEUES                            = 0x1
	NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY                   = 0x5
	NL80211_SURVEY_INFO_CHANNEL_TIME                        = 0x4
	NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY               = 0x6
	NL80211_SURVEY_INFO_CHANNEL_TIME_RX                     = 0x7
	NL80211_SURVEY_INFO_CHANNEL_TIME_TX                     = 0x8
	NL80211_SURVEY_INFO_FREQUENCY                           = 0x1
	NL80211_SURVEY_INFO_FREQUENCY_OFFSET                    = 0xc
	NL80211_SURVEY_INFO_IN_USE                              = 0x3
	NL80211_SURVEY_INFO_MAX                                 = 0xc
	NL80211_SURVEY_INFO_NOISE                               = 0x2
	NL80211_SURVEY_INFO_PAD                                 = 0xa
	NL80211_SURVEY_INFO_TIME_BSS_RX                         = 0xb
	NL80211_SURVEY_INFO_TIME_BUSY                           = 0x5
	NL80211_SURVEY_INFO_TIME                                = 0x4
	NL80211_SURVEY_INFO_TIME_EXT_BUSY                       = 0x6
	NL80211_SURVEY_INFO_TIME_RX                             = 0x7
	NL80211_SURVEY_INFO_TIME_SCAN                           = 0x9
	NL80211_SURVEY_INFO_TIME_TX                             = 0x8
	NL80211_TDLS_DISABLE_LINK                               = 0x4
	NL80211_TDLS_DISCOVERY_REQ                              = 0x0
	NL80211_TDLS_ENABLE_LINK                                = 0x3
	NL80211_TDLS_PEER_HE                                    = 0x8
	NL80211_TDLS_PEER_HT                                    = 0x1
	NL80211_TDLS_PEER_VHT                                   = 0x2
	NL80211_TDLS_PEER_WMM                                   = 0x4
	NL80211_TDLS_SETUP                                      = 0x1
	NL80211_TDLS_TEARDOWN                                   = 0x2
	NL80211_TID_CONFIG_ATTR_AMPDU_CTRL                      = 0x9
	NL80211_TID_CONFIG_ATTR_AMSDU_CTRL                      = 0xb
	NL80211_TID_CONFIG_ATTR_MAX                             = 0xd
	NL80211_TID_CONFIG_ATTR_NOACK                           = 0x6
	NL80211_TID_CONFIG_ATTR_OVERRIDE                        = 0x4
	NL80211_TID_CONFIG_ATTR_PAD                             = 0x1
	NL80211_TID_CONFIG_ATTR_PEER_SUPP                       = 0x3
	NL80211_TID_CONFIG_ATTR_RETRY_LONG                      = 0x8
	NL80211_TID_CONFIG_ATTR_RETRY_SHORT                     = 0x7
	NL80211_TID_CONFIG_ATTR_RTSCTS_CTRL                     = 0xa
	NL80211_TID_CONFIG_ATTR_TIDS                            = 0x5
	NL80211_TID_CONFIG_ATTR_TX_RATE                         = 0xd
	NL80211_TID_CONFIG_ATTR_TX_RATE_TYPE                    = 0xc
	NL80211_TID_CONFIG_ATTR_VIF_SUPP                        = 0x2
	NL80211_TID_CONFIG_DISABLE                              = 0x1
	NL80211_TID_CONFIG_ENABLE                               = 0x0
	NL80211_TID_STATS_MAX                                   = 0x6
	NL80211_TID_STATS_PAD                                   = 0x5
	NL80211_TID_STATS_RX_MSDU                               = 0x1
	NL80211_TID_STATS_TX_MSDU                               = 0x2
	NL80211_TID_STATS_TX_MSDU_FAILED                        = 0x4
	NL80211_TID_STATS_TX_MSDU_RETRIES                       = 0x3
	NL80211_TID_STATS_TXQ_STATS                             = 0x6
	NL80211_TIMEOUT_ASSOC                                   = 0x3
	NL80211_TIMEOUT_AUTH                                    = 0x2
	NL80211_TIMEOUT_SCAN                                    = 0x1
	NL80211_TIMEOUT_UNSPECIFIED                             = 0x0
	NL80211_TKIP_DATA_OFFSET_ENCR_KEY                       = 0x0
	NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY                     = 0x18
	NL80211_TKIP_DATA_OFFSET_TX_MIC_KEY                     = 0x10
	NL80211_TX_POWER_AUTOMATIC                              = 0x0
	NL80211_TX_POWER_FIXED                                  = 0x2
	NL80211_TX_POWER_LIMITED                                = 0x1
	NL80211_TXQ_ATTR_AC                                     = 0x1
	NL80211_TXQ_ATTR_AIFS                                   = 0x5
	NL80211_TXQ_ATTR_CWMAX                                  = 0x4
	NL80211_TXQ_ATTR_CWMIN                                  = 0x3
	NL80211_TXQ_ATTR_MAX                                    = 0x5
	NL80211_TXQ_ATTR_QUEUE                                  = 0x1
	NL80211_TXQ_ATTR_TXOP                                   = 0x2
	NL80211_TXQ_Q_BE                                        = 0x2
	NL80211_TXQ_Q_BK                                        = 0x3
	NL80211_TXQ_Q_VI                                        = 0x1
	NL80211_TXQ_Q_VO                                        = 0x0
	NL80211_TXQ_STATS_BACKLOG_BYTES                         = 0x1
	NL80211_TXQ_STATS_BACKLOG_PACKETS                       = 0x2
	NL80211_TXQ_STATS_COLLISIONS                            = 0x8
	NL80211_TXQ_STATS_DROPS                                 = 0x4
	NL80211_TXQ_STATS_ECN_MARKS                             = 0x5
	NL80211_TXQ_STATS_FLOWS                                 = 0x3
	NL80211_TXQ_STATS_MAX                                   = 0xb
	NL80211_TXQ_STATS_MAX_FLOWS                             = 0xb
	NL80211_TXQ_STATS_OVERLIMIT                             = 0x6
	NL80211_TXQ_STATS_OVERMEMORY                            = 0x7
	NL80211_TXQ_STATS_TX_BYTES                              = 0x9
	NL80211_TXQ_STATS_TX_PACKETS                            = 0xa
	NL80211_TX_RATE_AUTOMATIC                               = 0x0
	NL80211_TXRATE_DEFAULT_GI                               = 0x0
	NL80211_TX_RATE_FIXED                                   = 0x2
	NL80211_TXRATE_FORCE_LGI                                = 0x2
	NL80211_TXRATE_FORCE_SGI                                = 0x1
	NL80211_TXRATE_GI                                       = 0x4
	NL80211_TXRATE_HE                                       = 0x5
	NL80211_TXRATE_HE_GI                                    = 0x6
	NL80211_TXRATE_HE_LTF                                   = 0x7
	NL80211_TXRATE_HT                                       = 0x2
	NL80211_TXRATE_LEGACY                                   = 0x1
	NL80211_TX_RATE_LIMITED                                 = 0x1
	NL80211_TXRATE_MAX                                      = 0x7
	NL80211_TXRATE_MCS                                      = 0x2
	NL80211_TXRATE_VHT                                      = 0x3
	NL80211_UNSOL_BCAST_PROBE_RESP_ATTR_INT                 = 0x1
	NL80211_UNSOL_BCAST_PROBE_RESP_ATTR_MAX                 = 0x2
	NL80211_UNSOL_BCAST_PROBE_RESP_ATTR_TMPL                = 0x2
	NL80211_USER_REG_HINT_CELL_BASE                         = 0x1
	NL80211_USER_REG_HINT_INDOOR                            = 0x2
	NL80211_USER_REG_HINT_USER                              = 0x0
	NL80211_VENDOR_ID_IS_LINUX                              = 0x80000000
	NL80211_VHT_CAPABILITY_LEN                              = 0xc
	NL80211_VHT_NSS_MAX                                     = 0x8
	NL80211_WIPHY_NAME_MAXLEN                               = 0x40
	NL80211_WMMR_AIFSN                                      = 0x3
	NL80211_WMMR_CW_MAX                                     = 0x2
	NL80211_WMMR_CW_MIN                                     = 0x1
	NL80211_WMMR_MAX                                        = 0x4
	NL80211_WMMR_TXOP                                       = 0x4
	NL80211_WOWLAN_PKTPAT_MASK                              = 0x1
	NL80211_WOWLAN_PKTPAT_OFFSET                            = 0x3
	NL80211_WOWLAN_PKTPAT_PATTERN                           = 0x2
	NL80211_WOWLAN_TCP_DATA_INTERVAL                        = 0x9
	NL80211_WOWLAN_TCP_DATA_PAYLOAD                         = 0x6
	NL80211_WOWLAN_TCP_DATA_PAYLOAD_SEQ                     = 0x7
	NL80211_WOWLAN_TCP_DATA_PAYLOAD_TOKEN                   = 0x8
	NL80211_WOWLAN_TCP_DST_IPV4                             = 0x2
	NL80211_WOWLAN_TCP_DST_MAC                              = 0x3
	NL80211_WOWLAN_TCP_DST_PORT                             = 0x5
	NL80211_WOWLAN_TCP_SRC_IPV4                             = 0x1
	NL80211_WOWLAN_TCP_SRC_PORT                             = 0x4
	NL80211_WOWLAN_TCP_WAKE_MASK                            = 0xb
	NL80211_WOWLAN_TCP_WAKE_PAYLOAD                         = 0xa
	NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE                      = 0x8
	NL80211_WOWLAN_TRIG_ANY                                 = 0x1
	NL80211_WOWLAN_TRIG_DISCONNECT                          = 0x2
	NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST                   = 0x7
	NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE                   = 0x6
	NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED                 = 0x5
	NL80211_WOWLAN_TRIG_MAGIC_PKT                           = 0x3
	NL80211_WOWLAN_TRIG_NET_DETECT                          = 0x12
	NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS                  = 0x13
	NL80211_WOWLAN_TRIG_PKT_PATTERN                         = 0x4
	NL80211_WOWLAN_TRIG_RFKILL_RELEASE                      = 0x9
	NL80211_WOWLAN_TRIG_TCP_CONNECTION                      = 0xe
	NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211                    = 0xa
	NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN                = 0xb
	NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023                     = 0xc
	NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN                 = 0xd
	NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST                 = 0x10
	NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH                    = 0xf
	NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS             = 0x11
	NL80211_WPA_VERSION_1                                   = 0x1
	NL80211_WPA_VERSION_2                                   = 0x2
	NL80211_WPA_VERSION_3                                   = 0x4
)

const (
	FRA_UNSPEC             = 0x0
	FRA_DST                = 0x1
	FRA_SRC                = 0x2
	FRA_IIFNAME            = 0x3
	FRA_GOTO               = 0x4
	FRA_UNUSED2            = 0x5
	FRA_PRIORITY           = 0x6
	FRA_UNUSED3            = 0x7
	FRA_UNUSED4            = 0x8
	FRA_UNUSED5            = 0x9
	FRA_FWMARK             = 0xa
	FRA_FLOW               = 0xb
	FRA_TUN_ID             = 0xc
	FRA_SUPPRESS_IFGROUP   = 0xd
	FRA_SUPPRESS_PREFIXLEN = 0xe
	FRA_TABLE              = 0xf
	FRA_FWMASK             = 0x10
	FRA_OIFNAME            = 0x11
	FRA_PAD                = 0x12
	FRA_L3MDEV             = 0x13
	FRA_UID_RANGE          = 0x14
	FRA_PROTOCOL           = 0x15
	FRA_IP_PROTO           = 0x16
	FRA_SPORT_RANGE        = 0x17
	FRA_DPORT_RANGE        = 0x18
	FR_ACT_UNSPEC          = 0x0
	FR_ACT_TO_TBL          = 0x1
	FR_ACT_GOTO            = 0x2
	FR_ACT_NOP             = 0x3
	FR_ACT_RES3            = 0x4
	FR_ACT_RES4            = 0x5
	FR_ACT_BLACKHOLE       = 0x6
	FR_ACT_UNREACHABLE     = 0x7
	FR_ACT_PROHIBIT        = 0x8
)

const (
	AUDIT_NLGRP_NONE    = 0x0
	AUDIT_NLGRP_READLOG = 0x1
)

const (
	TUN_F_CSUM    = 0x1
	TUN_F_TSO4    = 0x2
	TUN_F_TSO6    = 0x4
	TUN_F_TSO_ECN = 0x8
	TUN_F_UFO     = 0x10
	TUN_F_USO4    = 0x20
	TUN_F_USO6    = 0x40
)

const (
	VIRTIO_NET_HDR_F_NEEDS_CSUM = 0x1
	VIRTIO_NET_HDR_F_DATA_VALID = 0x2
	VIRTIO_NET_HDR_F_RSC_INFO   = 0x4
)

const (
	VIRTIO_NET_HDR_GSO_NONE   = 0x0
	VIRTIO_NET_HDR_GSO_TCPV4  = 0x1
	VIRTIO_NET_HDR_GSO_UDP    = 0x3
	VIRTIO_NET_HDR_GSO_TCPV6  = 0x4
	VIRTIO_NET_HDR_GSO_UDP_L4 = 0x5
	VIRTIO_NET_HDR_GSO_ECN    = 0x80
)

type SchedAttr struct {
	Size     uint32
	Policy   uint32
	Flags    uint64
	Nice     int32
	Priority uint32
	Runtime  uint64
	Deadline uint64
	Period   uint64
	Util_min uint32
	Util_max uint32
}

const SizeofSchedAttr = 0x38

type Cachestat_t struct {
	Cache            uint64
	Dirty            uint64
	Writeback        uint64
	Evicted          uint64
	Recently_evicted uint64
}
type CachestatRange struct {
	Off uint64
	Len uint64
}

const (
	SK_MEMINFO_RMEM_ALLOC          = 0x0
	SK_MEMINFO_RCVBUF              = 0x1
	SK_MEMINFO_WMEM_ALLOC          = 0x2
	SK_MEMINFO_SNDBUF              = 0x3
	SK_MEMINFO_FWD_ALLOC           = 0x4
	SK_MEMINFO_WMEM_QUEUED         = 0x5
	SK_MEMINFO_OPTMEM              = 0x6
	SK_MEMINFO_BACKLOG             = 0x7
	SK_MEMINFO_DROPS               = 0x8
	SK_MEMINFO_VARS                = 0x9
	SKNLGRP_NONE                   = 0x0
	SKNLGRP_INET_TCP_DESTROY       = 0x1
	SKNLGRP_INET_UDP_DESTROY       = 0x2
	SKNLGRP_INET6_TCP_DESTROY      = 0x3
	SKNLGRP_INET6_UDP_DESTROY      = 0x4
	SK_DIAG_BPF_STORAGE_REQ_NONE   = 0x0
	SK_DIAG_BPF_STORAGE_REQ_MAP_FD = 0x1
	SK_DIAG_BPF_STORAGE_REP_NONE   = 0x0
	SK_DIAG_BPF_STORAGE            = 0x1
	SK_DIAG_BPF_STORAGE_NONE       = 0x0
	SK_DIAG_BPF_STORAGE_PAD        = 0x1
	SK_DIAG_BPF_STORAGE_MAP_ID     = 0x2
	SK_DIAG_BPF_STORAGE_MAP_VALUE  = 0x3
)

type SockDiagReq struct {
	Family   uint8
	Protocol uint8
}
```