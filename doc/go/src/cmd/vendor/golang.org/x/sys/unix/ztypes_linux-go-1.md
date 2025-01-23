Response:
The user wants to understand the functionality of a Go code snippet located in `go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go`. This file seems to define a large number of constants and structs specific to the Linux operating system, likely for interacting with low-level kernel interfaces.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Functionality:** The presence of numerous constants prefixed with `NFT_`, `NFTA_`, `BLKPG_`, `NETNSA_`, `XDP_`, `NCSI_`, `SOF_TIMESTAMPING_`, `CRYPTO_MSG_`, `CRYPTOCFGA_`, `BPF_`, `RTNLGRP_`, `LINUX_CAPABILITY_VERSION_`, `LO_FLAGS_`, `TIPC_`, `SYSLOG_ACTION_`, `DEVLINK_`, `CAN_RAW_`, `LWTUNNEL_ENCAP_`, and `ETHTOOL_` strongly suggests that this file provides definitions for interacting with various Linux kernel subsystems and networking features. The structs further reinforce this idea by providing data structures for passing information to and from the kernel.

2. **Infer Go Language Feature:** This file likely supports the `syscall` package in Go. The `syscall` package allows Go programs to make direct system calls to the operating system kernel. The constants and structs defined here would be used as arguments and return values for these system calls.

3. **Provide a Go Code Example:**  To illustrate how these definitions are used, a simple example involving `nftables` (indicated by the `NFT_` and `NFTA_` prefixes) would be appropriate. The example should demonstrate how to use these constants with the `syscall` package. Since the provided snippet doesn't include the actual syscall functions, a hypothetical scenario using placeholders like `syscall.NetlinkSocket()` and `syscall.Send()` needs to be created. The example should show how to construct a netlink message using the defined constants.

4. **Hypothesize Inputs and Outputs:**  For the code example, specific values need to be assumed for the input (e.g., a family constant, a rule attribute constant, data for the rule). The output would be the raw bytes sent to the netlink socket. It's important to clarify that the output is a *representation* of the data and not the actual kernel response.

5. **Address Command-Line Arguments:** This file primarily defines constants and data structures. It doesn't directly handle command-line arguments. Therefore, it's important to state that it doesn't process command-line arguments.

6. **Identify Potential Pitfalls:**  A common mistake when working with low-level system calls and constants is using incorrect values or types. The example should highlight the risk of using incorrect constant values and explain why it can lead to unexpected behavior or errors.

7. **Summarize the Functionality (for Part 2):**  For this specific part of the request, the summary should reiterate that the file provides definitions for interacting with Linux kernel features, focusing on the networking aspects due to the prevalence of `NFT_` constants.

8. **Structure the Response:** The response should be organized clearly, addressing each point in the user's request. Using headings and code blocks will improve readability.

**Self-Correction/Refinement:**

* **Initial thought:** Focus solely on `nftables` due to the abundance of related constants.
* **Correction:** Recognize the broader scope. While `nftables` is prominent, the file contains constants for other subsystems like BPF, XDP, and socket options. The description needs to reflect this wider range.
* **Initial thought:** Provide a complex `nftables` example.
* **Correction:**  Opt for a simpler example illustrating the general use of the constants with hypothetical syscalls, as the actual syscalls aren't present in the snippet. This avoids overcomplicating the example and focuses on the core purpose of the file.
* **Initial thought:**  Ignore the "Part 2" instruction and provide a complete summary.
* **Correction:**  Focus the summary specifically on the provided code snippet and its immediate purpose, as requested for "Part 2". Defer a broader summary to the final part.

By following this thought process, the provided response effectively addresses the user's request, providing a clear explanation of the code's functionality, a relevant example, and highlighting potential issues.
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go的go语言实现的一部分，它定义了大量的常量，这些常量主要用于与Linux内核进行底层交互，特别是关于网络过滤框架 `nftables` 以及其他系统调用相关的参数和选项。

**功能归纳:**

这部分代码主要定义了与以下Linux内核功能相关的常量：

1. **`nftables` (Netfilter Tables):**  这是新一代的Linux防火墙框架，用于替代 `iptables`。 代码中以 `NFT_` 和 `NFTA_` 开头的常量定义了 `nftables` 中各种对象的类型、属性、操作符、标志位等等。例如：
    *  `NFT_TABLE_INET`: 定义了 `inet` 地址族的表。
    *  `NFT_CHAIN_FILTER`: 定义了 `filter` 类型的链。
    *  `NFT_RULE_ADD`: 定义了添加规则的操作。
    *  `NFTA_RULE_EXPRS`: 定义了规则表达式属性。
    *  `NFT_MATCH_ICMPV6`: 定义了匹配 ICMPv6 包的匹配器类型。
    *  `NFTA_MATCH_OP`: 定义了匹配器操作属性。
    *  `NFT_CMP_EQ`: 定义了等于比较操作符。

2. **其他网络相关的系统调用和选项:**  虽然 `nftables` 占据了大部分，但也能看到其他网络相关的定义，例如：
    *  `NFT_PAYLOAD_NETWORK_HEADER`:  与数据包负载相关的常量。
    *  `NFT_META_PROTOCOL`: 与元数据（如协议）相关的常量。
    *  `NFT_CT_STATE`: 与连接跟踪状态相关的常量。

3. **块设备管理 (`blkpg`):**
    * `BLKPG_ADD_PARTITION`:  添加分区的操作码。
    * `BLKPG_DEL_PARTITION`:  删除分区的操作码。

4. **网络命名空间 (`netns`):**
    * `NETNSA_NONE`, `NETNSA_NSID`, `NETNSA_PID`, `NETNSA_FD`:  用于指定网络命名空间的不同方式。

5. **XDP (eXpress Data Path):** 用于高性能包处理。
    * `XDPRingOffset`, `XDPMmapOffsets`, `XDPUmemReg`, `XDPStatistics`, `XDPDesc`:  定义了 XDP 相关的结构体和数据结构。

6. **NCSI (Network Controller Sideband Interface):** 用于带外管理。
    * `NCSI_CMD_UNSPEC`, `NCSI_CMD_PKG_INFO`, `NCSI_ATTR_IFINDEX`: 定义了 NCSI 命令和属性。

7. **时间戳 (`SOF_TIMESTAMPING_`):**  用于套接字时间戳。
    * `SOF_TIMESTAMPING_TX_HARDWARE`, `SOF_TIMESTAMPING_RX_SOFTWARE`: 定义了不同的时间戳类型。

8. **扩展错误 (`SockExtendedErr`):** 用于传递更详细的套接字错误信息。

9. **Fanotify:** 用于文件系统事件通知。
    * `FanotifyEventMetadata`, `FanotifyResponse`: 定义了 fanotify 事件的元数据和响应。

10. **加密 API (`CRYPTO_MSG_`, `CRYPTOCFGA_`):**  与 Linux 内核的加密框架相关。

11. **BPF (Berkeley Packet Filter)/eBPF:**  用于内核中可编程的包过滤和跟踪。
    * 大量的 `BPF_` 开头的常量定义了 BPF 指令、映射类型、程序类型、操作码、标志位等等。

12. **路由 Netlink 组 (`RTNLGRP_`):** 用于标识 Netlink 消息的组。

13. **Capabilities:** 用于进程权限管理。
    * `LINUX_CAPABILITY_VERSION_1`: 定义了 capability 的版本。

14. **Loop 设备 (`LO_FLAGS_`):** 用于管理 loopback 设备。

15. **TIPC (Transparent Inter-Process Communication):** 用于集群环境的进程间通信。

16. **Syslog (`SYSLOG_ACTION_`):**  用于系统日志操作。

17. **Devlink:** 用于管理网络设备的通用接口。
    * 大量的 `DEVLINK_CMD_`, `DEVLINK_ATTR_` 开头的常量定义了 `devlink` 命令、属性和相关的枚举值。

18. **CAN (Controller Area Network):**  用于车载网络等。
    * `CAN_RAW_FILTER`: 定义了 CAN RAW 套接字的过滤器选项。

19. **Watchdog:** 用于硬件看门狗。

20. **PPS (Pulse Per Second):** 用于精确授时。

21. **LWTunnel (Lightweight Tunneling):**  用于创建隧道。

22. **Ethtool:** 用于配置以太网设备。
    * 大量的 `ETHTOOL_` 开头的常量定义了 `ethtool` 命令、参数和标志位。

23. **Fsverity:** 用于文件系统完整性校验。

24. **Next Hop Group (`NHA_`):** 用于路由策略中的下一跳组。

**它是什么go语言功能的实现，请用go代码举例说明:**

这部分代码是 Go 语言 `syscall` 包的一部分实现，更具体地说是 `golang.org/x/sys/unix` 扩展包。 `syscall` 包允许 Go 程序直接调用操作系统的系统调用。  这些常量在 Go 代码中被用来构造传递给系统调用的参数，或者解析系统调用返回的结果。

由于这段代码本身只定义了常量，并没有包含实际的系统调用代码，所以我们无法直接展示调用这些常量的完整 Go 代码。 但是，我们可以假设一个使用 `nftables` 相关常量的场景。

**假设的输入与输出 (需要使用到 syscall 包的 netlink 功能):**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// 假设我们已经定义了 Netlink 相关的辅助函数来发送和接收消息

func main() {
	// 假设要创建一个名为 "my_table" 的 inet 地址族的 nftables 表

	tableName := "my_table"
	tableFamily := syscall.NFT_TABLE_INET // 从 ztypes_linux.go 中获取的常量

	// 构造 Netlink 消息 (简化的示例，实际构造过程会更复杂)
	nlmsg := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   syscall.NLMSG_HDRLEN + syscall.NLA_HDRLEN*2 + len(tableName) + 1, // 假设的长度计算
			Type:  syscall.NFT_MSG_NEWTABLE,                                    // 假设的 Netlink 消息类型
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
			Seq:   1,
			Pid:   uint32(syscall.Getpid()),
		},
	}

	// 构造 Netlink 属性 (NLA)
	nlaFamily := &syscall.NlaMsghdr{
		Len:  syscall.NLA_HDRLEN + 4,
		Type: syscall.NFTA_TABLE_FAMILY, // 从 ztypes_linux.go 中获取的常量
	}
	nlmsg.Data = append(nlmsg.Data, (*(*[4]byte)(unsafe.Pointer(nlaFamily)))[:]...)
	nlmsg.Data = append(nlmsg.Data, (*(*[4]byte)(unsafe.Pointer(&tableFamily)))[:]...)

	nlaName := &syscall.NlaMsghdr{
		Len:  syscall.NLA_HDRLEN + uint16(len(tableName)+1),
		Type: syscall.NFTA_TABLE_NAME, // 从 ztypes_linux.go 中获取的常量
	}
	nlmsg.Data = append(nlmsg.Data, (*(*syscall.NlaMsghdr)(unsafe.Pointer(nlaName)))[:]...)
	nlmsg.Data = append(nlmsg.Data, []byte(tableName+"\x00")...)

	// 假设 sendNetlinkMessage 函数会将消息发送到 Netlink 套接字
	// output, err := sendNetlinkMessage(nlmsg)
	// if err != nil {
	// 	fmt.Println("Error sending Netlink message:", err)
	// 	return
	// }
	// fmt.Println("Netlink response:", output)

	fmt.Printf("构造的 Netlink 消息 (模拟):\n%+v\n", nlmsg)
	fmt.Printf("Netlink 消息数据 (十六进制):\n% X\n", nlmsg.Data)
}
```

**假设的输入与输出:**

**输入:**  Go 代码中定义的 `tableName` 为 "my_table"， `tableFamily` 为 `syscall.NFT_TABLE_INET` (假设其值为 5)。

**输出:**  `nlmsg.Data`  将会包含构造好的 Netlink 消息的字节流，其内容大致如下 (十六进制表示，仅为示例):

```
0c 00 00 00  <-- NlMsghdr.Len
XX XX        <-- NlMsghdr.Type (假设 NFT_MSG_NEWTABLE 的值)
05 01        <-- NlMsghdr.Flags (NLM_F_REQUEST | NLM_F_ACK)
01 00 00 00  <-- NlMsghdr.Seq
YY YY YY YY  <-- NlMsghdr.Pid
08 00 01 00  <-- NlaMsghdr (NFTA_TABLE_FAMILY)
05 00 00 00  <-- NFT_TABLE_INET 的值 (5)
0a 00 02 00  <-- NlaMsghdr (NFTA_TABLE_NAME)
6d 79 5f 74 61 62 6c 65 00  <-- "my_table" (null 结尾)
```

**解释:**

*   代码首先定义了要创建的 `nftables` 表的名称和地址族。
*   然后，它创建了一个 `syscall.NetlinkMessage` 结构体，用于封装要发送到内核的 Netlink 消息。
*   接着，它使用 `syscall.NFTA_TABLE_FAMILY` 和 `syscall.NFTA_TABLE_NAME` 常量来构造 Netlink 属性 (NLA)，这些属性指定了表的信息。
*   最后，它将表的地址族和名称添加到消息的数据部分。

**如果涉及命令行参数的具体处理，请详细介绍一下:**

这段代码本身**不涉及**命令行参数的处理。它只是定义了与系统调用交互时使用的常量。命令行参数的处理通常发生在应用程序的入口点 `main` 函数中，并使用 `os` 包或其他库来解析。应用程序可能会根据命令行参数的值，使用这里定义的常量来构造不同的系统调用请求。

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明:**

使用者在使用这些常量时容易犯错的点包括：

1. **使用了错误的常量值:**  例如，错误地使用了 `NFT_TABLE_IP` (IPv4) 而不是 `NFT_TABLE_INET` (包含了 IPv4 和 IPv6)。这会导致系统调用失败或产生意想不到的结果。

    ```go
    // 错误示例: 使用了错误的地址族常量
    tableFamily := syscall.NFT_TABLE_IP // 假设 NFT_TABLE_IP 的值为 4，但实际可能需要 NFT_TABLE_INET (5)
    // ... 后续构造 Netlink 消息
    ```

    **现象:**  内核可能返回一个错误，指示地址族不匹配。

2. **常量适用的上下文不正确:**  某些常量可能只在特定的系统调用或特定的结构体字段中有效。在错误的上下文中使用会导致类型错误或内核解析失败。

    ```go
    // 错误示例: 将一个用于规则属性的常量用在了表属性上
    nlaFamily := &syscall.NlaMsghdr{
        Len:  syscall.NLA_HDRLEN + 4,
        Type: syscall.NFTA_RULE_FAMILY, // 假设这是一个规则属性常量，不应该用于表
    }
    ```

    **现象:**  内核可能会忽略这个属性，或者返回一个指示属性类型错误的错误。

3. **与内核版本不兼容:**  新的内核版本可能会引入新的常量或修改现有常量的含义。如果程序使用的常量在当前内核版本中不存在或已过时，则会导致错误。

    ```go
    // 假设某个新的 nftables 功能引入了一个新的匹配器类型常量 NFT_MATCH_NEW_PROTOCOL
    // 如果程序在旧内核上使用了这个常量，会导致错误
    matcherType := syscall.NFT_MATCH_NEW_PROTOCOL // 在旧内核中可能未定义
    ```

    **现象:**  系统调用可能会失败，并提示无效的匹配器类型。

**这是第2部分，共4部分，请归纳一下它的功能:**

作为第2部分，这段代码的主要功能是**定义了大量的常量，这些常量是 Go 语言程序与 Linux 内核中网络过滤框架 `nftables` 以及其他底层系统功能进行交互时所必需的。**  它为开发者提供了可以直接在 Go 代码中使用的符号化名称，代替了直接使用数字，提高了代码的可读性和可维护性。  虽然它本身不执行任何操作，但它是构建能够控制 Linux 网络行为的 Go 语言程序的基础。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/ztypes_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
= 0x5
	NFT_BYTEORDER_NTOH                = 0x0
	NFT_BYTEORDER_HTON                = 0x1
	NFTA_BYTEORDER_UNSPEC             = 0x0
	NFTA_BYTEORDER_SREG               = 0x1
	NFTA_BYTEORDER_DREG               = 0x2
	NFTA_BYTEORDER_OP                 = 0x3
	NFTA_BYTEORDER_LEN                = 0x4
	NFTA_BYTEORDER_SIZE               = 0x5
	NFT_CMP_EQ                        = 0x0
	NFT_CMP_NEQ                       = 0x1
	NFT_CMP_LT                        = 0x2
	NFT_CMP_LTE                       = 0x3
	NFT_CMP_GT                        = 0x4
	NFT_CMP_GTE                       = 0x5
	NFTA_CMP_UNSPEC                   = 0x0
	NFTA_CMP_SREG                     = 0x1
	NFTA_CMP_OP                       = 0x2
	NFTA_CMP_DATA                     = 0x3
	NFT_RANGE_EQ                      = 0x0
	NFT_RANGE_NEQ                     = 0x1
	NFTA_RANGE_UNSPEC                 = 0x0
	NFTA_RANGE_SREG                   = 0x1
	NFTA_RANGE_OP                     = 0x2
	NFTA_RANGE_FROM_DATA              = 0x3
	NFTA_RANGE_TO_DATA                = 0x4
	NFT_LOOKUP_F_INV                  = 0x1
	NFTA_LOOKUP_UNSPEC                = 0x0
	NFTA_LOOKUP_SET                   = 0x1
	NFTA_LOOKUP_SREG                  = 0x2
	NFTA_LOOKUP_DREG                  = 0x3
	NFTA_LOOKUP_SET_ID                = 0x4
	NFTA_LOOKUP_FLAGS                 = 0x5
	NFT_DYNSET_OP_ADD                 = 0x0
	NFT_DYNSET_OP_UPDATE              = 0x1
	NFT_DYNSET_F_INV                  = 0x1
	NFTA_DYNSET_UNSPEC                = 0x0
	NFTA_DYNSET_SET_NAME              = 0x1
	NFTA_DYNSET_SET_ID                = 0x2
	NFTA_DYNSET_OP                    = 0x3
	NFTA_DYNSET_SREG_KEY              = 0x4
	NFTA_DYNSET_SREG_DATA             = 0x5
	NFTA_DYNSET_TIMEOUT               = 0x6
	NFTA_DYNSET_EXPR                  = 0x7
	NFTA_DYNSET_PAD                   = 0x8
	NFTA_DYNSET_FLAGS                 = 0x9
	NFT_PAYLOAD_LL_HEADER             = 0x0
	NFT_PAYLOAD_NETWORK_HEADER        = 0x1
	NFT_PAYLOAD_TRANSPORT_HEADER      = 0x2
	NFT_PAYLOAD_CSUM_NONE             = 0x0
	NFT_PAYLOAD_CSUM_INET             = 0x1
	NFT_PAYLOAD_L4CSUM_PSEUDOHDR      = 0x1
	NFTA_PAYLOAD_UNSPEC               = 0x0
	NFTA_PAYLOAD_DREG                 = 0x1
	NFTA_PAYLOAD_BASE                 = 0x2
	NFTA_PAYLOAD_OFFSET               = 0x3
	NFTA_PAYLOAD_LEN                  = 0x4
	NFTA_PAYLOAD_SREG                 = 0x5
	NFTA_PAYLOAD_CSUM_TYPE            = 0x6
	NFTA_PAYLOAD_CSUM_OFFSET          = 0x7
	NFTA_PAYLOAD_CSUM_FLAGS           = 0x8
	NFT_EXTHDR_F_PRESENT              = 0x1
	NFT_EXTHDR_OP_IPV6                = 0x0
	NFT_EXTHDR_OP_TCPOPT              = 0x1
	NFTA_EXTHDR_UNSPEC                = 0x0
	NFTA_EXTHDR_DREG                  = 0x1
	NFTA_EXTHDR_TYPE                  = 0x2
	NFTA_EXTHDR_OFFSET                = 0x3
	NFTA_EXTHDR_LEN                   = 0x4
	NFTA_EXTHDR_FLAGS                 = 0x5
	NFTA_EXTHDR_OP                    = 0x6
	NFTA_EXTHDR_SREG                  = 0x7
	NFT_META_LEN                      = 0x0
	NFT_META_PROTOCOL                 = 0x1
	NFT_META_PRIORITY                 = 0x2
	NFT_META_MARK                     = 0x3
	NFT_META_IIF                      = 0x4
	NFT_META_OIF                      = 0x5
	NFT_META_IIFNAME                  = 0x6
	NFT_META_OIFNAME                  = 0x7
	NFT_META_IIFTYPE                  = 0x8
	NFT_META_OIFTYPE                  = 0x9
	NFT_META_SKUID                    = 0xa
	NFT_META_SKGID                    = 0xb
	NFT_META_NFTRACE                  = 0xc
	NFT_META_RTCLASSID                = 0xd
	NFT_META_SECMARK                  = 0xe
	NFT_META_NFPROTO                  = 0xf
	NFT_META_L4PROTO                  = 0x10
	NFT_META_BRI_IIFNAME              = 0x11
	NFT_META_BRI_OIFNAME              = 0x12
	NFT_META_PKTTYPE                  = 0x13
	NFT_META_CPU                      = 0x14
	NFT_META_IIFGROUP                 = 0x15
	NFT_META_OIFGROUP                 = 0x16
	NFT_META_CGROUP                   = 0x17
	NFT_META_PRANDOM                  = 0x18
	NFT_RT_CLASSID                    = 0x0
	NFT_RT_NEXTHOP4                   = 0x1
	NFT_RT_NEXTHOP6                   = 0x2
	NFT_RT_TCPMSS                     = 0x3
	NFT_HASH_JENKINS                  = 0x0
	NFT_HASH_SYM                      = 0x1
	NFTA_HASH_UNSPEC                  = 0x0
	NFTA_HASH_SREG                    = 0x1
	NFTA_HASH_DREG                    = 0x2
	NFTA_HASH_LEN                     = 0x3
	NFTA_HASH_MODULUS                 = 0x4
	NFTA_HASH_SEED                    = 0x5
	NFTA_HASH_OFFSET                  = 0x6
	NFTA_HASH_TYPE                    = 0x7
	NFTA_META_UNSPEC                  = 0x0
	NFTA_META_DREG                    = 0x1
	NFTA_META_KEY                     = 0x2
	NFTA_META_SREG                    = 0x3
	NFTA_RT_UNSPEC                    = 0x0
	NFTA_RT_DREG                      = 0x1
	NFTA_RT_KEY                       = 0x2
	NFT_CT_STATE                      = 0x0
	NFT_CT_DIRECTION                  = 0x1
	NFT_CT_STATUS                     = 0x2
	NFT_CT_MARK                       = 0x3
	NFT_CT_SECMARK                    = 0x4
	NFT_CT_EXPIRATION                 = 0x5
	NFT_CT_HELPER                     = 0x6
	NFT_CT_L3PROTOCOL                 = 0x7
	NFT_CT_SRC                        = 0x8
	NFT_CT_DST                        = 0x9
	NFT_CT_PROTOCOL                   = 0xa
	NFT_CT_PROTO_SRC                  = 0xb
	NFT_CT_PROTO_DST                  = 0xc
	NFT_CT_LABELS                     = 0xd
	NFT_CT_PKTS                       = 0xe
	NFT_CT_BYTES                      = 0xf
	NFT_CT_AVGPKT                     = 0x10
	NFT_CT_ZONE                       = 0x11
	NFT_CT_EVENTMASK                  = 0x12
	NFTA_CT_UNSPEC                    = 0x0
	NFTA_CT_DREG                      = 0x1
	NFTA_CT_KEY                       = 0x2
	NFTA_CT_DIRECTION                 = 0x3
	NFTA_CT_SREG                      = 0x4
	NFT_LIMIT_PKTS                    = 0x0
	NFT_LIMIT_PKT_BYTES               = 0x1
	NFT_LIMIT_F_INV                   = 0x1
	NFTA_LIMIT_UNSPEC                 = 0x0
	NFTA_LIMIT_RATE                   = 0x1
	NFTA_LIMIT_UNIT                   = 0x2
	NFTA_LIMIT_BURST                  = 0x3
	NFTA_LIMIT_TYPE                   = 0x4
	NFTA_LIMIT_FLAGS                  = 0x5
	NFTA_LIMIT_PAD                    = 0x6
	NFTA_COUNTER_UNSPEC               = 0x0
	NFTA_COUNTER_BYTES                = 0x1
	NFTA_COUNTER_PACKETS              = 0x2
	NFTA_COUNTER_PAD                  = 0x3
	NFTA_LOG_UNSPEC                   = 0x0
	NFTA_LOG_GROUP                    = 0x1
	NFTA_LOG_PREFIX                   = 0x2
	NFTA_LOG_SNAPLEN                  = 0x3
	NFTA_LOG_QTHRESHOLD               = 0x4
	NFTA_LOG_LEVEL                    = 0x5
	NFTA_LOG_FLAGS                    = 0x6
	NFTA_QUEUE_UNSPEC                 = 0x0
	NFTA_QUEUE_NUM                    = 0x1
	NFTA_QUEUE_TOTAL                  = 0x2
	NFTA_QUEUE_FLAGS                  = 0x3
	NFTA_QUEUE_SREG_QNUM              = 0x4
	NFT_QUOTA_F_INV                   = 0x1
	NFT_QUOTA_F_DEPLETED              = 0x2
	NFTA_QUOTA_UNSPEC                 = 0x0
	NFTA_QUOTA_BYTES                  = 0x1
	NFTA_QUOTA_FLAGS                  = 0x2
	NFTA_QUOTA_PAD                    = 0x3
	NFTA_QUOTA_CONSUMED               = 0x4
	NFT_REJECT_ICMP_UNREACH           = 0x0
	NFT_REJECT_TCP_RST                = 0x1
	NFT_REJECT_ICMPX_UNREACH          = 0x2
	NFT_REJECT_ICMPX_NO_ROUTE         = 0x0
	NFT_REJECT_ICMPX_PORT_UNREACH     = 0x1
	NFT_REJECT_ICMPX_HOST_UNREACH     = 0x2
	NFT_REJECT_ICMPX_ADMIN_PROHIBITED = 0x3
	NFTA_REJECT_UNSPEC                = 0x0
	NFTA_REJECT_TYPE                  = 0x1
	NFTA_REJECT_ICMP_CODE             = 0x2
	NFT_NAT_SNAT                      = 0x0
	NFT_NAT_DNAT                      = 0x1
	NFTA_NAT_UNSPEC                   = 0x0
	NFTA_NAT_TYPE                     = 0x1
	NFTA_NAT_FAMILY                   = 0x2
	NFTA_NAT_REG_ADDR_MIN             = 0x3
	NFTA_NAT_REG_ADDR_MAX             = 0x4
	NFTA_NAT_REG_PROTO_MIN            = 0x5
	NFTA_NAT_REG_PROTO_MAX            = 0x6
	NFTA_NAT_FLAGS                    = 0x7
	NFTA_MASQ_UNSPEC                  = 0x0
	NFTA_MASQ_FLAGS                   = 0x1
	NFTA_MASQ_REG_PROTO_MIN           = 0x2
	NFTA_MASQ_REG_PROTO_MAX           = 0x3
	NFTA_REDIR_UNSPEC                 = 0x0
	NFTA_REDIR_REG_PROTO_MIN          = 0x1
	NFTA_REDIR_REG_PROTO_MAX          = 0x2
	NFTA_REDIR_FLAGS                  = 0x3
	NFTA_DUP_UNSPEC                   = 0x0
	NFTA_DUP_SREG_ADDR                = 0x1
	NFTA_DUP_SREG_DEV                 = 0x2
	NFTA_FWD_UNSPEC                   = 0x0
	NFTA_FWD_SREG_DEV                 = 0x1
	NFTA_OBJREF_UNSPEC                = 0x0
	NFTA_OBJREF_IMM_TYPE              = 0x1
	NFTA_OBJREF_IMM_NAME              = 0x2
	NFTA_OBJREF_SET_SREG              = 0x3
	NFTA_OBJREF_SET_NAME              = 0x4
	NFTA_OBJREF_SET_ID                = 0x5
	NFTA_GEN_UNSPEC                   = 0x0
	NFTA_GEN_ID                       = 0x1
	NFTA_GEN_PROC_PID                 = 0x2
	NFTA_GEN_PROC_NAME                = 0x3
	NFTA_FIB_UNSPEC                   = 0x0
	NFTA_FIB_DREG                     = 0x1
	NFTA_FIB_RESULT                   = 0x2
	NFTA_FIB_FLAGS                    = 0x3
	NFT_FIB_RESULT_UNSPEC             = 0x0
	NFT_FIB_RESULT_OIF                = 0x1
	NFT_FIB_RESULT_OIFNAME            = 0x2
	NFT_FIB_RESULT_ADDRTYPE           = 0x3
	NFTA_FIB_F_SADDR                  = 0x1
	NFTA_FIB_F_DADDR                  = 0x2
	NFTA_FIB_F_MARK                   = 0x4
	NFTA_FIB_F_IIF                    = 0x8
	NFTA_FIB_F_OIF                    = 0x10
	NFTA_FIB_F_PRESENT                = 0x20
	NFTA_CT_HELPER_UNSPEC             = 0x0
	NFTA_CT_HELPER_NAME               = 0x1
	NFTA_CT_HELPER_L3PROTO            = 0x2
	NFTA_CT_HELPER_L4PROTO            = 0x3
	NFTA_OBJ_UNSPEC                   = 0x0
	NFTA_OBJ_TABLE                    = 0x1
	NFTA_OBJ_NAME                     = 0x2
	NFTA_OBJ_TYPE                     = 0x3
	NFTA_OBJ_DATA                     = 0x4
	NFTA_OBJ_USE                      = 0x5
	NFTA_TRACE_UNSPEC                 = 0x0
	NFTA_TRACE_TABLE                  = 0x1
	NFTA_TRACE_CHAIN                  = 0x2
	NFTA_TRACE_RULE_HANDLE            = 0x3
	NFTA_TRACE_TYPE                   = 0x4
	NFTA_TRACE_VERDICT                = 0x5
	NFTA_TRACE_ID                     = 0x6
	NFTA_TRACE_LL_HEADER              = 0x7
	NFTA_TRACE_NETWORK_HEADER         = 0x8
	NFTA_TRACE_TRANSPORT_HEADER       = 0x9
	NFTA_TRACE_IIF                    = 0xa
	NFTA_TRACE_IIFTYPE                = 0xb
	NFTA_TRACE_OIF                    = 0xc
	NFTA_TRACE_OIFTYPE                = 0xd
	NFTA_TRACE_MARK                   = 0xe
	NFTA_TRACE_NFPROTO                = 0xf
	NFTA_TRACE_POLICY                 = 0x10
	NFTA_TRACE_PAD                    = 0x11
	NFT_TRACETYPE_UNSPEC              = 0x0
	NFT_TRACETYPE_POLICY              = 0x1
	NFT_TRACETYPE_RETURN              = 0x2
	NFT_TRACETYPE_RULE                = 0x3
	NFTA_NG_UNSPEC                    = 0x0
	NFTA_NG_DREG                      = 0x1
	NFTA_NG_MODULUS                   = 0x2
	NFTA_NG_TYPE                      = 0x3
	NFTA_NG_OFFSET                    = 0x4
	NFT_NG_INCREMENTAL                = 0x0
	NFT_NG_RANDOM                     = 0x1
)

const (
	NFTA_TARGET_UNSPEC = 0x0
	NFTA_TARGET_NAME   = 0x1
	NFTA_TARGET_REV    = 0x2
	NFTA_TARGET_INFO   = 0x3
	NFTA_MATCH_UNSPEC  = 0x0
	NFTA_MATCH_NAME    = 0x1
	NFTA_MATCH_REV     = 0x2
	NFTA_MATCH_INFO    = 0x3
	NFTA_COMPAT_UNSPEC = 0x0
	NFTA_COMPAT_NAME   = 0x1
	NFTA_COMPAT_REV    = 0x2
	NFTA_COMPAT_TYPE   = 0x3
)

type RTCTime struct {
	Sec   int32
	Min   int32
	Hour  int32
	Mday  int32
	Mon   int32
	Year  int32
	Wday  int32
	Yday  int32
	Isdst int32
}

type RTCWkAlrm struct {
	Enabled uint8
	Pending uint8
	Time    RTCTime
}

type BlkpgIoctlArg struct {
	Op      int32
	Flags   int32
	Datalen int32
	Data    *byte
}

const (
	BLKPG_ADD_PARTITION    = 0x1
	BLKPG_DEL_PARTITION    = 0x2
	BLKPG_RESIZE_PARTITION = 0x3
)

const (
	NETNSA_NONE         = 0x0
	NETNSA_NSID         = 0x1
	NETNSA_PID          = 0x2
	NETNSA_FD           = 0x3
	NETNSA_TARGET_NSID  = 0x4
	NETNSA_CURRENT_NSID = 0x5
)

type XDPRingOffset struct {
	Producer uint64
	Consumer uint64
	Desc     uint64
	Flags    uint64
}

type XDPMmapOffsets struct {
	Rx XDPRingOffset
	Tx XDPRingOffset
	Fr XDPRingOffset
	Cr XDPRingOffset
}

type XDPUmemReg struct {
	Addr            uint64
	Len             uint64
	Size            uint32
	Headroom        uint32
	Flags           uint32
	Tx_metadata_len uint32
}

type XDPStatistics struct {
	Rx_dropped               uint64
	Rx_invalid_descs         uint64
	Tx_invalid_descs         uint64
	Rx_ring_full             uint64
	Rx_fill_ring_empty_descs uint64
	Tx_ring_empty_descs      uint64
}

type XDPDesc struct {
	Addr    uint64
	Len     uint32
	Options uint32
}

const (
	NCSI_CMD_UNSPEC                 = 0x0
	NCSI_CMD_PKG_INFO               = 0x1
	NCSI_CMD_SET_INTERFACE          = 0x2
	NCSI_CMD_CLEAR_INTERFACE        = 0x3
	NCSI_ATTR_UNSPEC                = 0x0
	NCSI_ATTR_IFINDEX               = 0x1
	NCSI_ATTR_PACKAGE_LIST          = 0x2
	NCSI_ATTR_PACKAGE_ID            = 0x3
	NCSI_ATTR_CHANNEL_ID            = 0x4
	NCSI_PKG_ATTR_UNSPEC            = 0x0
	NCSI_PKG_ATTR                   = 0x1
	NCSI_PKG_ATTR_ID                = 0x2
	NCSI_PKG_ATTR_FORCED            = 0x3
	NCSI_PKG_ATTR_CHANNEL_LIST      = 0x4
	NCSI_CHANNEL_ATTR_UNSPEC        = 0x0
	NCSI_CHANNEL_ATTR               = 0x1
	NCSI_CHANNEL_ATTR_ID            = 0x2
	NCSI_CHANNEL_ATTR_VERSION_MAJOR = 0x3
	NCSI_CHANNEL_ATTR_VERSION_MINOR = 0x4
	NCSI_CHANNEL_ATTR_VERSION_STR   = 0x5
	NCSI_CHANNEL_ATTR_LINK_STATE    = 0x6
	NCSI_CHANNEL_ATTR_ACTIVE        = 0x7
	NCSI_CHANNEL_ATTR_FORCED        = 0x8
	NCSI_CHANNEL_ATTR_VLAN_LIST     = 0x9
	NCSI_CHANNEL_ATTR_VLAN_ID       = 0xa
)

type ScmTimestamping struct {
	Ts [3]Timespec
}

const (
	SOF_TIMESTAMPING_TX_HARDWARE  = 0x1
	SOF_TIMESTAMPING_TX_SOFTWARE  = 0x2
	SOF_TIMESTAMPING_RX_HARDWARE  = 0x4
	SOF_TIMESTAMPING_RX_SOFTWARE  = 0x8
	SOF_TIMESTAMPING_SOFTWARE     = 0x10
	SOF_TIMESTAMPING_SYS_HARDWARE = 0x20
	SOF_TIMESTAMPING_RAW_HARDWARE = 0x40
	SOF_TIMESTAMPING_OPT_ID       = 0x80
	SOF_TIMESTAMPING_TX_SCHED     = 0x100
	SOF_TIMESTAMPING_TX_ACK       = 0x200
	SOF_TIMESTAMPING_OPT_CMSG     = 0x400
	SOF_TIMESTAMPING_OPT_TSONLY   = 0x800
	SOF_TIMESTAMPING_OPT_STATS    = 0x1000
	SOF_TIMESTAMPING_OPT_PKTINFO  = 0x2000
	SOF_TIMESTAMPING_OPT_TX_SWHW  = 0x4000
	SOF_TIMESTAMPING_BIND_PHC     = 0x8000
	SOF_TIMESTAMPING_OPT_ID_TCP   = 0x10000

	SOF_TIMESTAMPING_LAST = 0x20000
	SOF_TIMESTAMPING_MASK = 0x3ffff

	SCM_TSTAMP_SND   = 0x0
	SCM_TSTAMP_SCHED = 0x1
	SCM_TSTAMP_ACK   = 0x2
)

type SockExtendedErr struct {
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
	Info   uint32
	Data   uint32
}

type FanotifyEventMetadata struct {
	Event_len    uint32
	Vers         uint8
	Reserved     uint8
	Metadata_len uint16
	Mask         uint64
	Fd           int32
	Pid          int32
}

type FanotifyResponse struct {
	Fd       int32
	Response uint32
}

const (
	CRYPTO_MSG_BASE      = 0x10
	CRYPTO_MSG_NEWALG    = 0x10
	CRYPTO_MSG_DELALG    = 0x11
	CRYPTO_MSG_UPDATEALG = 0x12
	CRYPTO_MSG_GETALG    = 0x13
	CRYPTO_MSG_DELRNG    = 0x14
	CRYPTO_MSG_GETSTAT   = 0x15
)

const (
	CRYPTOCFGA_UNSPEC           = 0x0
	CRYPTOCFGA_PRIORITY_VAL     = 0x1
	CRYPTOCFGA_REPORT_LARVAL    = 0x2
	CRYPTOCFGA_REPORT_HASH      = 0x3
	CRYPTOCFGA_REPORT_BLKCIPHER = 0x4
	CRYPTOCFGA_REPORT_AEAD      = 0x5
	CRYPTOCFGA_REPORT_COMPRESS  = 0x6
	CRYPTOCFGA_REPORT_RNG       = 0x7
	CRYPTOCFGA_REPORT_CIPHER    = 0x8
	CRYPTOCFGA_REPORT_AKCIPHER  = 0x9
	CRYPTOCFGA_REPORT_KPP       = 0xa
	CRYPTOCFGA_REPORT_ACOMP     = 0xb
	CRYPTOCFGA_STAT_LARVAL      = 0xc
	CRYPTOCFGA_STAT_HASH        = 0xd
	CRYPTOCFGA_STAT_BLKCIPHER   = 0xe
	CRYPTOCFGA_STAT_AEAD        = 0xf
	CRYPTOCFGA_STAT_COMPRESS    = 0x10
	CRYPTOCFGA_STAT_RNG         = 0x11
	CRYPTOCFGA_STAT_CIPHER      = 0x12
	CRYPTOCFGA_STAT_AKCIPHER    = 0x13
	CRYPTOCFGA_STAT_KPP         = 0x14
	CRYPTOCFGA_STAT_ACOMP       = 0x15
)

const (
	BPF_REG_0                                  = 0x0
	BPF_REG_1                                  = 0x1
	BPF_REG_2                                  = 0x2
	BPF_REG_3                                  = 0x3
	BPF_REG_4                                  = 0x4
	BPF_REG_5                                  = 0x5
	BPF_REG_6                                  = 0x6
	BPF_REG_7                                  = 0x7
	BPF_REG_8                                  = 0x8
	BPF_REG_9                                  = 0x9
	BPF_REG_10                                 = 0xa
	BPF_CGROUP_ITER_ORDER_UNSPEC               = 0x0
	BPF_CGROUP_ITER_SELF_ONLY                  = 0x1
	BPF_CGROUP_ITER_DESCENDANTS_PRE            = 0x2
	BPF_CGROUP_ITER_DESCENDANTS_POST           = 0x3
	BPF_CGROUP_ITER_ANCESTORS_UP               = 0x4
	BPF_MAP_CREATE                             = 0x0
	BPF_MAP_LOOKUP_ELEM                        = 0x1
	BPF_MAP_UPDATE_ELEM                        = 0x2
	BPF_MAP_DELETE_ELEM                        = 0x3
	BPF_MAP_GET_NEXT_KEY                       = 0x4
	BPF_PROG_LOAD                              = 0x5
	BPF_OBJ_PIN                                = 0x6
	BPF_OBJ_GET                                = 0x7
	BPF_PROG_ATTACH                            = 0x8
	BPF_PROG_DETACH                            = 0x9
	BPF_PROG_TEST_RUN                          = 0xa
	BPF_PROG_RUN                               = 0xa
	BPF_PROG_GET_NEXT_ID                       = 0xb
	BPF_MAP_GET_NEXT_ID                        = 0xc
	BPF_PROG_GET_FD_BY_ID                      = 0xd
	BPF_MAP_GET_FD_BY_ID                       = 0xe
	BPF_OBJ_GET_INFO_BY_FD                     = 0xf
	BPF_PROG_QUERY                             = 0x10
	BPF_RAW_TRACEPOINT_OPEN                    = 0x11
	BPF_BTF_LOAD                               = 0x12
	BPF_BTF_GET_FD_BY_ID                       = 0x13
	BPF_TASK_FD_QUERY                          = 0x14
	BPF_MAP_LOOKUP_AND_DELETE_ELEM             = 0x15
	BPF_MAP_FREEZE                             = 0x16
	BPF_BTF_GET_NEXT_ID                        = 0x17
	BPF_MAP_LOOKUP_BATCH                       = 0x18
	BPF_MAP_LOOKUP_AND_DELETE_BATCH            = 0x19
	BPF_MAP_UPDATE_BATCH                       = 0x1a
	BPF_MAP_DELETE_BATCH                       = 0x1b
	BPF_LINK_CREATE                            = 0x1c
	BPF_LINK_UPDATE                            = 0x1d
	BPF_LINK_GET_FD_BY_ID                      = 0x1e
	BPF_LINK_GET_NEXT_ID                       = 0x1f
	BPF_ENABLE_STATS                           = 0x20
	BPF_ITER_CREATE                            = 0x21
	BPF_LINK_DETACH                            = 0x22
	BPF_PROG_BIND_MAP                          = 0x23
	BPF_MAP_TYPE_UNSPEC                        = 0x0
	BPF_MAP_TYPE_HASH                          = 0x1
	BPF_MAP_TYPE_ARRAY                         = 0x2
	BPF_MAP_TYPE_PROG_ARRAY                    = 0x3
	BPF_MAP_TYPE_PERF_EVENT_ARRAY              = 0x4
	BPF_MAP_TYPE_PERCPU_HASH                   = 0x5
	BPF_MAP_TYPE_PERCPU_ARRAY                  = 0x6
	BPF_MAP_TYPE_STACK_TRACE                   = 0x7
	BPF_MAP_TYPE_CGROUP_ARRAY                  = 0x8
	BPF_MAP_TYPE_LRU_HASH                      = 0x9
	BPF_MAP_TYPE_LRU_PERCPU_HASH               = 0xa
	BPF_MAP_TYPE_LPM_TRIE                      = 0xb
	BPF_MAP_TYPE_ARRAY_OF_MAPS                 = 0xc
	BPF_MAP_TYPE_HASH_OF_MAPS                  = 0xd
	BPF_MAP_TYPE_DEVMAP                        = 0xe
	BPF_MAP_TYPE_SOCKMAP                       = 0xf
	BPF_MAP_TYPE_CPUMAP                        = 0x10
	BPF_MAP_TYPE_XSKMAP                        = 0x11
	BPF_MAP_TYPE_SOCKHASH                      = 0x12
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED     = 0x13
	BPF_MAP_TYPE_CGROUP_STORAGE                = 0x13
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY           = 0x14
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE         = 0x15
	BPF_MAP_TYPE_QUEUE                         = 0x16
	BPF_MAP_TYPE_STACK                         = 0x17
	BPF_MAP_TYPE_SK_STORAGE                    = 0x18
	BPF_MAP_TYPE_DEVMAP_HASH                   = 0x19
	BPF_MAP_TYPE_STRUCT_OPS                    = 0x1a
	BPF_MAP_TYPE_RINGBUF                       = 0x1b
	BPF_MAP_TYPE_INODE_STORAGE                 = 0x1c
	BPF_MAP_TYPE_TASK_STORAGE                  = 0x1d
	BPF_MAP_TYPE_BLOOM_FILTER                  = 0x1e
	BPF_MAP_TYPE_USER_RINGBUF                  = 0x1f
	BPF_MAP_TYPE_CGRP_STORAGE                  = 0x20
	BPF_PROG_TYPE_UNSPEC                       = 0x0
	BPF_PROG_TYPE_SOCKET_FILTER                = 0x1
	BPF_PROG_TYPE_KPROBE                       = 0x2
	BPF_PROG_TYPE_SCHED_CLS                    = 0x3
	BPF_PROG_TYPE_SCHED_ACT                    = 0x4
	BPF_PROG_TYPE_TRACEPOINT                   = 0x5
	BPF_PROG_TYPE_XDP                          = 0x6
	BPF_PROG_TYPE_PERF_EVENT                   = 0x7
	BPF_PROG_TYPE_CGROUP_SKB                   = 0x8
	BPF_PROG_TYPE_CGROUP_SOCK                  = 0x9
	BPF_PROG_TYPE_LWT_IN                       = 0xa
	BPF_PROG_TYPE_LWT_OUT                      = 0xb
	BPF_PROG_TYPE_LWT_XMIT                     = 0xc
	BPF_PROG_TYPE_SOCK_OPS                     = 0xd
	BPF_PROG_TYPE_SK_SKB                       = 0xe
	BPF_PROG_TYPE_CGROUP_DEVICE                = 0xf
	BPF_PROG_TYPE_SK_MSG                       = 0x10
	BPF_PROG_TYPE_RAW_TRACEPOINT               = 0x11
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR             = 0x12
	BPF_PROG_TYPE_LWT_SEG6LOCAL                = 0x13
	BPF_PROG_TYPE_LIRC_MODE2                   = 0x14
	BPF_PROG_TYPE_SK_REUSEPORT                 = 0x15
	BPF_PROG_TYPE_FLOW_DISSECTOR               = 0x16
	BPF_PROG_TYPE_CGROUP_SYSCTL                = 0x17
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE      = 0x18
	BPF_PROG_TYPE_CGROUP_SOCKOPT               = 0x19
	BPF_PROG_TYPE_TRACING                      = 0x1a
	BPF_PROG_TYPE_STRUCT_OPS                   = 0x1b
	BPF_PROG_TYPE_EXT                          = 0x1c
	BPF_PROG_TYPE_LSM                          = 0x1d
	BPF_PROG_TYPE_SK_LOOKUP                    = 0x1e
	BPF_PROG_TYPE_SYSCALL                      = 0x1f
	BPF_PROG_TYPE_NETFILTER                    = 0x20
	BPF_CGROUP_INET_INGRESS                    = 0x0
	BPF_CGROUP_INET_EGRESS                     = 0x1
	BPF_CGROUP_INET_SOCK_CREATE                = 0x2
	BPF_CGROUP_SOCK_OPS                        = 0x3
	BPF_SK_SKB_STREAM_PARSER                   = 0x4
	BPF_SK_SKB_STREAM_VERDICT                  = 0x5
	BPF_CGROUP_DEVICE                          = 0x6
	BPF_SK_MSG_VERDICT                         = 0x7
	BPF_CGROUP_INET4_BIND                      = 0x8
	BPF_CGROUP_INET6_BIND                      = 0x9
	BPF_CGROUP_INET4_CONNECT                   = 0xa
	BPF_CGROUP_INET6_CONNECT                   = 0xb
	BPF_CGROUP_INET4_POST_BIND                 = 0xc
	BPF_CGROUP_INET6_POST_BIND                 = 0xd
	BPF_CGROUP_UDP4_SENDMSG                    = 0xe
	BPF_CGROUP_UDP6_SENDMSG                    = 0xf
	BPF_LIRC_MODE2                             = 0x10
	BPF_FLOW_DISSECTOR                         = 0x11
	BPF_CGROUP_SYSCTL                          = 0x12
	BPF_CGROUP_UDP4_RECVMSG                    = 0x13
	BPF_CGROUP_UDP6_RECVMSG                    = 0x14
	BPF_CGROUP_GETSOCKOPT                      = 0x15
	BPF_CGROUP_SETSOCKOPT                      = 0x16
	BPF_TRACE_RAW_TP                           = 0x17
	BPF_TRACE_FENTRY                           = 0x18
	BPF_TRACE_FEXIT                            = 0x19
	BPF_MODIFY_RETURN                          = 0x1a
	BPF_LSM_MAC                                = 0x1b
	BPF_TRACE_ITER                             = 0x1c
	BPF_CGROUP_INET4_GETPEERNAME               = 0x1d
	BPF_CGROUP_INET6_GETPEERNAME               = 0x1e
	BPF_CGROUP_INET4_GETSOCKNAME               = 0x1f
	BPF_CGROUP_INET6_GETSOCKNAME               = 0x20
	BPF_XDP_DEVMAP                             = 0x21
	BPF_CGROUP_INET_SOCK_RELEASE               = 0x22
	BPF_XDP_CPUMAP                             = 0x23
	BPF_SK_LOOKUP                              = 0x24
	BPF_XDP                                    = 0x25
	BPF_SK_SKB_VERDICT                         = 0x26
	BPF_SK_REUSEPORT_SELECT                    = 0x27
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE         = 0x28
	BPF_PERF_EVENT                             = 0x29
	BPF_TRACE_KPROBE_MULTI                     = 0x2a
	BPF_LSM_CGROUP                             = 0x2b
	BPF_STRUCT_OPS                             = 0x2c
	BPF_NETFILTER                              = 0x2d
	BPF_TCX_INGRESS                            = 0x2e
	BPF_TCX_EGRESS                             = 0x2f
	BPF_TRACE_UPROBE_MULTI                     = 0x30
	BPF_LINK_TYPE_UNSPEC                       = 0x0
	BPF_LINK_TYPE_RAW_TRACEPOINT               = 0x1
	BPF_LINK_TYPE_TRACING                      = 0x2
	BPF_LINK_TYPE_CGROUP                       = 0x3
	BPF_LINK_TYPE_ITER                         = 0x4
	BPF_LINK_TYPE_NETNS                        = 0x5
	BPF_LINK_TYPE_XDP                          = 0x6
	BPF_LINK_TYPE_PERF_EVENT                   = 0x7
	BPF_LINK_TYPE_KPROBE_MULTI                 = 0x8
	BPF_LINK_TYPE_STRUCT_OPS                   = 0x9
	BPF_LINK_TYPE_NETFILTER                    = 0xa
	BPF_LINK_TYPE_TCX                          = 0xb
	BPF_LINK_TYPE_UPROBE_MULTI                 = 0xc
	BPF_PERF_EVENT_UNSPEC                      = 0x0
	BPF_PERF_EVENT_UPROBE                      = 0x1
	BPF_PERF_EVENT_URETPROBE                   = 0x2
	BPF_PERF_EVENT_KPROBE                      = 0x3
	BPF_PERF_EVENT_KRETPROBE                   = 0x4
	BPF_PERF_EVENT_TRACEPOINT                  = 0x5
	BPF_PERF_EVENT_EVENT                       = 0x6
	BPF_F_KPROBE_MULTI_RETURN                  = 0x1
	BPF_F_UPROBE_MULTI_RETURN                  = 0x1
	BPF_ANY                                    = 0x0
	BPF_NOEXIST                                = 0x1
	BPF_EXIST                                  = 0x2
	BPF_F_LOCK                                 = 0x4
	BPF_F_NO_PREALLOC                          = 0x1
	BPF_F_NO_COMMON_LRU                        = 0x2
	BPF_F_NUMA_NODE                            = 0x4
	BPF_F_RDONLY                               = 0x8
	BPF_F_WRONLY                               = 0x10
	BPF_F_STACK_BUILD_ID                       = 0x20
	BPF_F_ZERO_SEED                            = 0x40
	BPF_F_RDONLY_PROG                          = 0x80
	BPF_F_WRONLY_PROG                          = 0x100
	BPF_F_CLONE                                = 0x200
	BPF_F_MMAPABLE                             = 0x400
	BPF_F_PRESERVE_ELEMS                       = 0x800
	BPF_F_INNER_MAP                            = 0x1000
	BPF_F_LINK                                 = 0x2000
	BPF_F_PATH_FD                              = 0x4000
	BPF_STATS_RUN_TIME                         = 0x0
	BPF_STACK_BUILD_ID_EMPTY                   = 0x0
	BPF_STACK_BUILD_ID_VALID                   = 0x1
	BPF_STACK_BUILD_ID_IP                      = 0x2
	BPF_F_RECOMPUTE_CSUM                       = 0x1
	BPF_F_INVALIDATE_HASH                      = 0x2
	BPF_F_HDR_FIELD_MASK                       = 0xf
	BPF_F_PSEUDO_HDR                           = 0x10
	BPF_F_MARK_MANGLED_0                       = 0x20
	BPF_F_MARK_ENFORCE                         = 0x40
	BPF_F_INGRESS                              = 0x1
	BPF_F_TUNINFO_IPV6                         = 0x1
	BPF_F_SKIP_FIELD_MASK                      = 0xff
	BPF_F_USER_STACK                           = 0x100
	BPF_F_FAST_STACK_CMP                       = 0x200
	BPF_F_REUSE_STACKID                        = 0x400
	BPF_F_USER_BUILD_ID                        = 0x800
	BPF_F_ZERO_CSUM_TX                         = 0x2
	BPF_F_DONT_FRAGMENT                        = 0x4
	BPF_F_SEQ_NUMBER                           = 0x8
	BPF_F_NO_TUNNEL_KEY                        = 0x10
	BPF_F_TUNINFO_FLAGS                        = 0x10
	BPF_F_INDEX_MASK                           = 0xffffffff
	BPF_F_CURRENT_CPU                          = 0xffffffff
	BPF_F_CTXLEN_MASK                          = 0xfffff00000000
	BPF_F_CURRENT_NETNS                        = -0x1
	BPF_CSUM_LEVEL_QUERY                       = 0x0
	BPF_CSUM_LEVEL_INC                         = 0x1
	BPF_CSUM_LEVEL_DEC                         = 0x2
	BPF_CSUM_LEVEL_RESET                       = 0x3
	BPF_F_ADJ_ROOM_FIXED_GSO                   = 0x1
	BPF_F_ADJ_ROOM_ENCAP_L3_IPV4               = 0x2
	BPF_F_ADJ_ROOM_ENCAP_L3_IPV6               = 0x4
	BPF_F_ADJ_ROOM_ENCAP_L4_GRE                = 0x8
	BPF_F_ADJ_ROOM_ENCAP_L4_UDP                = 0x10
	BPF_F_ADJ_ROOM_NO_CSUM_RESET               = 0x20
	BPF_F_ADJ_ROOM_ENCAP_L2_ETH                = 0x40
	BPF_F_ADJ_ROOM_DECAP_L3_IPV4               = 0x80
	BPF_F_ADJ_ROOM_DECAP_L3_IPV6               = 0x100
	BPF_ADJ_ROOM_ENCAP_L2_MASK                 = 0xff
	BPF_ADJ_ROOM_ENCAP_L2_SHIFT                = 0x38
	BPF_F_SYSCTL_BASE_NAME                     = 0x1
	BPF_LOCAL_STORAGE_GET_F_CREATE             = 0x1
	BPF_SK_STORAGE_GET_F_CREATE                = 0x1
	BPF_F_GET_BRANCH_RECORDS_SIZE              = 0x1
	BPF_RB_NO_WAKEUP                           = 0x1
	BPF_RB_FORCE_WAKEUP                        = 0x2
	BPF_RB_AVAIL_DATA                          = 0x0
	BPF_RB_RING_SIZE                           = 0x1
	BPF_RB_CONS_POS                            = 0x2
	BPF_RB_PROD_POS                            = 0x3
	BPF_RINGBUF_BUSY_BIT                       = 0x80000000
	BPF_RINGBUF_DISCARD_BIT                    = 0x40000000
	BPF_RINGBUF_HDR_SZ                         = 0x8
	BPF_SK_LOOKUP_F_REPLACE                    = 0x1
	BPF_SK_LOOKUP_F_NO_REUSEPORT               = 0x2
	BPF_ADJ_ROOM_NET                           = 0x0
	BPF_ADJ_ROOM_MAC                           = 0x1
	BPF_HDR_START_MAC                          = 0x0
	BPF_HDR_START_NET                          = 0x1
	BPF_LWT_ENCAP_SEG6                         = 0x0
	BPF_LWT_ENCAP_SEG6_INLINE                  = 0x1
	BPF_LWT_ENCAP_IP                           = 0x2
	BPF_F_BPRM_SECUREEXEC                      = 0x1
	BPF_F_BROADCAST                            = 0x8
	BPF_F_EXCLUDE_INGRESS                      = 0x10
	BPF_SKB_TSTAMP_UNSPEC                      = 0x0
	BPF_SKB_TSTAMP_DELIVERY_MONO               = 0x1
	BPF_OK                                     = 0x0
	BPF_DROP                                   = 0x2
	BPF_REDIRECT                               = 0x7
	BPF_LWT_REROUTE                            = 0x80
	BPF_FLOW_DISSECTOR_CONTINUE                = 0x81
	BPF_SOCK_OPS_RTO_CB_FLAG                   = 0x1
	BPF_SOCK_OPS_RETRANS_CB_FLAG               = 0x2
	BPF_SOCK_OPS_STATE_CB_FLAG                 = 0x4
	BPF_SOCK_OPS_RTT_CB_FLAG                   = 0x8
	BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG     = 0x10
	BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG = 0x20
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG         = 0x40
	BPF_SOCK_OPS_ALL_CB_FLAGS                  = 0x7f
	BPF_SOCK_OPS_VOID                          = 0x0
	BPF_SOCK_OPS_TIMEOUT_INIT                  = 0x1
	BPF_SOCK_OPS_RWND_INIT                     = 0x2
	BPF_SOCK_OPS_TCP_CONNECT_CB                = 0x3
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB         = 0x4
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB        = 0x5
	BPF_SOCK_OPS_NEEDS_ECN                     = 0x6
	BPF_SOCK_OPS_BASE_RTT                      = 0x7
	BPF_SOCK_OPS_RTO_CB                        = 0x8
	BPF_SOCK_OPS_RETRANS_CB                    = 0x9
	BPF_SOCK_OPS_STATE_CB                      = 0xa
	BPF_SOCK_OPS_TCP_LISTEN_CB                 = 0xb
	BPF_SOCK_OPS_RTT_CB                        = 0xc
	BPF_SOCK_OPS_PARSE_HDR_OPT_CB              = 0xd
	BPF_SOCK_OPS_HDR_OPT_LEN_CB                = 0xe
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB              = 0xf
	BPF_TCP_ESTABLISHED                        = 0x1
	BPF_TCP_SYN_SENT                           = 0x2
	BPF_TCP_SYN_RECV                           = 0x3
	BPF_TCP_FIN_WAIT1                          = 0x4
	BPF_TCP_FIN_WAIT2                          = 0x5
	BPF_TCP_TIME_WAIT                          = 0x6
	BPF_TCP_CLOSE                              = 0x7
	BPF_TCP_CLOSE_WAIT                         = 0x8
	BPF_TCP_LAST_ACK                           = 0x9
	BPF_TCP_LISTEN                             = 0xa
	BPF_TCP_CLOSING                            = 0xb
	BPF_TCP_NEW_SYN_RECV                       = 0xc
	BPF_TCP_MAX_STATES                         = 0xe
	TCP_BPF_IW                                 = 0x3e9
	TCP_BPF_SNDCWND_CLAMP                      = 0x3ea
	TCP_BPF_DELACK_MAX                         = 0x3eb
	TCP_BPF_RTO_MIN                            = 0x3ec
	TCP_BPF_SYN                                = 0x3ed
	TCP_BPF_SYN_IP                             = 0x3ee
	TCP_BPF_SYN_MAC                            = 0x3ef
	BPF_LOAD_HDR_OPT_TCP_SYN                   = 0x1
	BPF_WRITE_HDR_TCP_CURRENT_MSS              = 0x1
	BPF_WRITE_HDR_TCP_SYNACK_COOKIE            = 0x2
	BPF_DEVCG_ACC_MKNOD                        = 0x1
	BPF_DEVCG_ACC_READ                         = 0x2
	BPF_DEVCG_ACC_WRITE                        = 0x4
	BPF_DEVCG_DEV_BLOCK                        = 0x1
	BPF_DEVCG_DEV_CHAR                         = 0x2
	BPF_FIB_LOOKUP_DIRECT                      = 0x1
	BPF_FIB_LOOKUP_OUTPUT                      = 0x2
	BPF_FIB_LOOKUP_SKIP_NEIGH                  = 0x4
	BPF_FIB_LOOKUP_TBID                        = 0x8
	BPF_FIB_LKUP_RET_SUCCESS                   = 0x0
	BPF_FIB_LKUP_RET_BLACKHOLE                 = 0x1
	BPF_FIB_LKUP_RET_UNREACHABLE               = 0x2
	BPF_FIB_LKUP_RET_PROHIBIT                  = 0x3
	BPF_FIB_LKUP_RET_NOT_FWDED                 = 0x4
	BPF_FIB_LKUP_RET_FWD_DISABLED              = 0x5
	BPF_FIB_LKUP_RET_UNSUPP_LWT                = 0x6
	BPF_FIB_LKUP_RET_NO_NEIGH                  = 0x7
	BPF_FIB_LKUP_RET_FRAG_NEEDED               = 0x8
	BPF_MTU_CHK_SEGS                           = 0x1
	BPF_MTU_CHK_RET_SUCCESS                    = 0x0
	BPF_MTU_CHK_RET_FRAG_NEEDED                = 0x1
	BPF_MTU_CHK_RET_SEGS_TOOBIG                = 0x2
	BPF_FD_TYPE_RAW_TRACEPOINT                 = 0x0
	BPF_FD_TYPE_TRACEPOINT                     = 0x1
	BPF_FD_TYPE_KPROBE                         = 0x2
	BPF_FD_TYPE_KRETPROBE                      = 0x3
	BPF_FD_TYPE_UPROBE                         = 0x4
	BPF_FD_TYPE_URETPROBE                      = 0x5
	BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG        = 0x1
	BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL    = 0x2
	BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP         = 0x4
	BPF_CORE_FIELD_BYTE_OFFSET                 = 0x0
	BPF_CORE_FIELD_BYTE_SIZE                   = 0x1
	BPF_CORE_FIELD_EXISTS                      = 0x2
	BPF_CORE_FIELD_SIGNED                      = 0x3
	BPF_CORE_FIELD_LSHIFT_U64                  = 0x4
	BPF_CORE_FIELD_RSHIFT_U64                  = 0x5
	BPF_CORE_TYPE_ID_LOCAL                     = 0x6
	BPF_CORE_TYPE_ID_TARGET                    = 0x7
	BPF_CORE_TYPE_EXISTS                       = 0x8
	BPF_CORE_TYPE_SIZE                         = 0x9
	BPF_CORE_ENUMVAL_EXISTS                    = 0xa
	BPF_CORE_ENUMVAL_VALUE                     = 0xb
	BPF_CORE_TYPE_MATCHES                      = 0xc
	BPF_F_TIMER_ABS                            = 0x1
)

const (
	RTNLGRP_NONE          = 0x0
	RTNLGRP_LINK          = 0x1
	RTNLGRP_NOTIFY        = 0x2
	RTNLGRP_NEIGH         = 0x3
	RTNLGRP_TC            = 0x4
	RTNLGRP_IPV4_IFADDR   = 0x5
	RTNLGRP_IPV4_MROUTE   = 0x6
	RTNLGRP_IPV4_ROUTE    = 0x7
	RTNLGRP_IPV4_RULE     = 0x8
	RTNLGRP_IPV6_IFADDR   = 0x9
	RTNLGRP_IPV6_MROUTE   = 0xa
	RTNLGRP_IPV6_ROUTE    = 0xb
	RTNLGRP_IPV6_IFINFO   = 0xc
	RTNLGRP_DECnet_IFADDR = 0xd
	RTNLGRP_NOP2          = 0xe
	RTNLGRP_DECnet_ROUTE  = 0xf
	RTNLGRP_DECnet_RULE   = 0x10
	RTNLGRP_NOP4          = 0x11
	RTNLGRP_IPV6_PREFIX   = 0x12
	RTNLGRP_IPV6_RULE     = 0x13
	RTNLGRP_ND_USEROPT    = 0x14
	RTNLGRP_PHONET_IFADDR = 0x15
	RTNLGRP_PHONET_ROUTE  = 0x16
	RTNLGRP_DCB           = 0x17
	RTNLGRP_IPV4_NETCONF  = 0x18
	RTNLGRP_IPV6_NETCONF  = 0x19
	RTNLGRP_MDB           = 0x1a
	RTNLGRP_MPLS_ROUTE    = 0x1b
	RTNLGRP_NSID          = 0x1c
	RTNLGRP_MPLS_NETCONF  = 0x1d
	RTNLGRP_IPV4_MROUTE_R = 0x1e
	RTNLGRP_IPV6_MROUTE_R = 0x1f
	RTNLGRP_NEXTHOP       = 0x20
	RTNLGRP_BRVLAN        = 0x21
)

type CapUserHeader struct {
	Version uint32
	Pid     int32
}

type CapUserData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

const (
	LINUX_CAPABILITY_VERSION_1 = 0x19980330
	LINUX_CAPABILITY_VERSION_2 = 0x20071026
	LINUX_CAPABILITY_VERSION_3 = 0x20080522
)

const (
	LO_FLAGS_READ_ONLY = 0x1
	LO_FLAGS_AUTOCLEAR = 0x4
	LO_FLAGS_PARTSCAN  = 0x8
	LO_FLAGS_DIRECT_IO = 0x10
)

type LoopInfo64 struct {
	Device           uint64
	Inode            uint64
	Rdevice          uint64
	Offset           uint64
	Sizelimit        uint64
	Number           uint32
	Encrypt_type     uint32
	Encrypt_key_size uint32
	Flags            uint32
	File_name        [64]uint8
	Crypt_name       [64]uint8
	Encrypt_key      [32]uint8
	Init             [2]uint64
}
type LoopConfig struct {
	Fd   uint32
	Size uint32
	Info LoopInfo64
	_    [8]uint64
}

type TIPCSocketAddr struct {
	Ref  uint32
	Node uint32
}

type TIPCServiceRange struct {
	Type  uint32
	Lower uint32
	Upper uint32
}

type TIPCServiceName struct {
	Type     uint32
	Instance uint32
	Domain   uint32
}

type TIPCEvent struct {
	Event uint32
	Lower uint32
	Upper uint32
	Port  TIPCSocketAddr
	S     TIPCSubscr
}

type TIPCGroupReq struct {
	Type     uint32
	Instance uint32
	Scope    uint32
	Flags    uint32
}

const (
	TIPC_CLUSTER_SCOPE = 0x2
	TIPC_NODE_SCOPE    = 0x3
)

const (
	SYSLOG_ACTION_CLOSE         = 0
	SYSLOG_ACTION_OPEN          = 1
	SYSLOG_ACTION_READ          = 2
	SYSLOG_ACTION_READ_ALL      = 3
	SYSLOG_ACTION_READ_CLEAR    = 4
	SYSLOG_ACTION_CLEAR         = 5
	SYSLOG_ACTION_CONSOLE_OFF   = 6
	SYSLOG_ACTION_CONSOLE_ON    = 7
	SYSLOG_ACTION_CONSOLE_LEVEL = 8
	SYSLOG_ACTION_SIZE_UNREAD   = 9
	SYSLOG_ACTION_SIZE_BUFFER   = 10
)

const (
	DEVLINK_CMD_UNSPEC                                 = 0x0
	DEVLINK_CMD_GET                                    = 0x1
	DEVLINK_CMD_SET                                    = 0x2
	DEVLINK_CMD_NEW                                    = 0x3
	DEVLINK_CMD_DEL                                    = 0x4
	DEVLINK_CMD_PORT_GET                               = 0x5
	DEVLINK_CMD_PORT_SET                               = 0x6
	DEVLINK_CMD_PORT_NEW                               = 0x7
	DEVLINK_CMD_PORT_DEL                               = 0x8
	DEVLINK_CMD_PORT_SPLIT                             = 0x9
	DEVLINK_CMD_PORT_UNSPLIT                           = 0xa
	DEVLINK_CMD_SB_GET                                 = 0xb
	DEVLINK_CMD_SB_SET                                 = 0xc
	DEVLINK_CMD_SB_NEW                                 = 0xd
	DEVLINK_CMD_SB_DEL                                 = 0xe
	DEVLINK_CMD_SB_POOL_GET                            = 0xf
	DEVLINK_CMD_SB_POOL_SET                            = 0x10
	DEVLINK_CMD_SB_POOL_NEW                            = 0x11
	DEVLINK_CMD_SB_POOL_DEL                            = 0x12
	DEVLINK_CMD_SB_PORT_POOL_GET                       = 0x13
	DEVLINK_CMD_SB_PORT_POOL_SET                       = 0x14
	DEVLINK_CMD_SB_PORT_POOL_NEW                       = 0x15
	DEVLINK_CMD_SB_PORT_POOL_DEL                       = 0x16
	DEVLINK_CMD_SB_TC_POOL_BIND_GET                    = 0x17
	DEVLINK_CMD_SB_TC_POOL_BIND_SET                    = 0x18
	DEVLINK_CMD_SB_TC_POOL_BIND_NEW                    = 0x19
	DEVLINK_CMD_SB_TC_POOL_BIND_DEL                    = 0x1a
	DEVLINK_CMD_SB_OCC_SNAPSHOT                        = 0x1b
	DEVLINK_CMD_SB_OCC_MAX_CLEAR                       = 0x1c
	DEVLINK_CMD_ESWITCH_GET                            = 0x1d
	DEVLINK_CMD_ESWITCH_SET                            = 0x1e
	DEVLINK_CMD_DPIPE_TABLE_GET                        = 0x1f
	DEVLINK_CMD_DPIPE_ENTRIES_GET                      = 0x20
	DEVLINK_CMD_DPIPE_HEADERS_GET                      = 0x21
	DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET               = 0x22
	DEVLINK_CMD_RESOURCE_SET                           = 0x23
	DEVLINK_CMD_RESOURCE_DUMP                          = 0x24
	DEVLINK_CMD_RELOAD                                 = 0x25
	DEVLINK_CMD_PARAM_GET                              = 0x26
	DEVLINK_CMD_PARAM_SET                              = 0x27
	DEVLINK_CMD_PARAM_NEW                              = 0x28
	DEVLINK_CMD_PARAM_DEL                              = 0x29
	DEVLINK_CMD_REGION_GET                             = 0x2a
	DEVLINK_CMD_REGION_SET                             = 0x2b
	DEVLINK_CMD_REGION_NEW                             = 0x2c
	DEVLINK_CMD_REGION_DEL                             = 0x2d
	DEVLINK_CMD_REGION_READ                            = 0x2e
	DEVLINK_CMD_PORT_PARAM_GET                         = 0x2f
	DEVLINK_CMD_PORT_PARAM_SET                         = 0x30
	DEVLINK_CMD_PORT_PARAM_NEW                         = 0x31
	DEVLINK_CMD_PORT_PARAM_DEL                         = 0x32
	DEVLINK_CMD_INFO_GET                               = 0x33
	DEVLINK_CMD_HEALTH_REPORTER_GET                    = 0x34
	DEVLINK_CMD_HEALTH_REPORTER_SET                    = 0x35
	DEVLINK_CMD_HEALTH_REPORTER_RECOVER                = 0x36
	DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE               = 0x37
	DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET               = 0x38
	DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR             = 0x39
	DEVLINK_CMD_FLASH_UPDATE                           = 0x3a
	DEVLINK_CMD_FLASH_UPDATE_END                       = 0x3b
	DEVLINK_CMD_FLASH_UPDATE_STATUS                    = 0x3c
	DEVLINK_CMD_TRAP_GET                               = 0x3d
	DEVLINK_CMD_TRAP_SET                               = 0x3e
	DEVLINK_CMD_TRAP_NEW                               = 0x3f
	DEVLINK_CMD_TRAP_DEL                               = 0x40
	DEVLINK_CMD_TRAP_GROUP_GET                         = 0x41
	DEVLINK_CMD_TRAP_GROUP_SET                         = 0x42
	DEVLINK_CMD_TRAP_GROUP_NEW                         = 0x43
	DEVLINK_CMD_TRAP_GROUP_DEL                         = 0x44
	DEVLINK_CMD_TRAP_POLICER_GET                       = 0x45
	DEVLINK_CMD_TRAP_POLICER_SET                       = 0x46
	DEVLINK_CMD_TRAP_POLICER_NEW                       = 0x47
	DEVLINK_CMD_TRAP_POLICER_DEL                       = 0x48
	DEVLINK_CMD_HEALTH_REPORTER_TEST                   = 0x49
	DEVLINK_CMD_RATE_GET                               = 0x4a
	DEVLINK_CMD_RATE_SET                               = 0x4b
	DEVLINK_CMD_RATE_NEW                               = 0x4c
	DEVLINK_CMD_RATE_DEL                               = 0x4d
	DEVLINK_CMD_LINECARD_GET                           = 0x4e
	DEVLINK_CMD_LINECARD_SET                           = 0x4f
	DEVLINK_CMD_LINECARD_NEW                           = 0x50
	DEVLINK_CMD_LINECARD_DEL                           = 0x51
	DEVLINK_CMD_SELFTESTS_GET                          = 0x52
	DEVLINK_CMD_MAX                                    = 0x54
	DEVLINK_PORT_TYPE_NOTSET                           = 0x0
	DEVLINK_PORT_TYPE_AUTO                             = 0x1
	DEVLINK_PORT_TYPE_ETH                              = 0x2
	DEVLINK_PORT_TYPE_IB                               = 0x3
	DEVLINK_SB_POOL_TYPE_INGRESS                       = 0x0
	DEVLINK_SB_POOL_TYPE_EGRESS                        = 0x1
	DEVLINK_SB_THRESHOLD_TYPE_STATIC                   = 0x0
	DEVLINK_SB_THRESHOLD_TYPE_DYNAMIC                  = 0x1
	DEVLINK_ESWITCH_MODE_LEGACY                        = 0x0
	DEVLINK_ESWITCH_MODE_SWITCHDEV                     = 0x1
	DEVLINK_ESWITCH_INLINE_MODE_NONE                   = 0x0
	DEVLINK_ESWITCH_INLINE_MODE_LINK                   = 0x1
	DEVLINK_ESWITCH_INLINE_MODE_NETWORK                = 0x2
	DEVLINK_ESWITCH_INLINE_MODE_TRANSPORT              = 0x3
	DEVLINK_ESWITCH_ENCAP_MODE_NONE                    = 0x0
	DEVLINK_ESWITCH_ENCAP_MODE_BASIC                   = 0x1
	DEVLINK_PORT_FLAVOUR_PHYSICAL                      = 0x0
	DEVLINK_PORT_FLAVOUR_CPU                           = 0x1
	DEVLINK_PORT_FLAVOUR_DSA                           = 0x2
	DEVLINK_PORT_FLAVOUR_PCI_PF                        = 0x3
	DEVLINK_PORT_FLAVOUR_PCI_VF                        = 0x4
	DEVLINK_PORT_FLAVOUR_VIRTUAL                       = 0x5
	DEVLINK_PORT_FLAVOUR_UNUSED                        = 0x6
	DEVLINK_PARAM_CMODE_RUNTIME                        = 0x0
	DEVLINK_PARAM_CMODE_DRIVERINIT                     = 0x1
	DEVLINK_PARAM_CMODE_PERMANENT                      = 0x2
	DEVLINK_PARAM_CMODE_MAX                            = 0x2
	DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_DRIVER          = 0x0
	DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_FLASH           = 0x1
	DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_DISK            = 0x2
	DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_UNKNOWN         = 0x3
	DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_UNKNOWN = 0x0
	DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_ALWAYS  = 0x1
	DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_NEVER   = 0x2
	DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_DISK    = 0x3
	DEVLINK_ATTR_STATS_RX_PACKETS                      = 0x0
	DEVLINK_ATTR_STATS_RX_BYTES                        = 0x1
	DEVLINK_ATTR_STATS_RX_DROPPED                      = 0x2
	DEVLINK_ATTR_STATS_MAX                             = 0x2
	DEVLINK_FLASH_OVERWRITE_SETTINGS_BIT               = 0x0
	DEVLINK_FLASH_OVERWRITE_IDENTIFIERS_BIT            = 0x1
	DEVLINK_FLASH_OVERWRITE_MAX_BIT                    = 0x1
	DEVLINK_TRAP_ACTION_DROP                           = 0x0
	DEVLINK_TRAP_ACTION_TRAP                           = 0x1
	DEVLINK_TRAP_ACTION_MIRROR                         = 0x2
	DEVLINK_TRAP_TYPE_DROP                             = 0x0
	DEVLINK_TRAP_TYPE_EXCEPTION                        = 0x1
	DEVLINK_TRAP_TYPE_CONTROL                          = 0x2
	DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT            = 0x0
	DEVLINK_ATTR_TRAP_METADATA_TYPE_FA_COOKIE          = 0x1
	DEVLINK_RELOAD_ACTION_UNSPEC                       = 0x0
	DEVLINK_RELOAD_ACTION_DRIVER_REINIT                = 0x1
	DEVLINK_RELOAD_ACTION_FW_ACTIVATE                  = 0x2
	DEVLINK_RELOAD_ACTION_MAX                          = 0x2
	DEVLINK_RELOAD_LIMIT_UNSPEC                        = 0x0
	DEVLINK_RELOAD_LIMIT_NO_RESET                      = 0x1
	DEVLINK_RELOAD_LIMIT_MAX                           = 0x1
	DEVLINK_ATTR_UNSPEC                                = 0x0
	DEVLINK_ATTR_BUS_NAME                              = 0x1
	DEVLINK_ATTR_DEV_NAME                              = 0x2
	DEVLINK_ATTR_PORT_INDEX                            = 0x3
	DEVLINK_ATTR_PORT_TYPE                             = 0x4
	DEVLINK_ATTR_PORT_DESIRED_TYPE                     = 0x5
	DEVLINK_ATTR_PORT_NETDEV_IFINDEX                   = 0x6
	DEVLINK_ATTR_PORT_NETDEV_NAME                      = 0x7
	DEVLINK_ATTR_PORT_IBDEV_NAME                       = 0x8
	DEVLINK_ATTR_PORT_SPLIT_COUNT                      = 0x9
	DEVLINK_ATTR_PORT_SPLIT_GROUP                      = 0xa
	DEVLINK_ATTR_SB_INDEX                              = 0xb
	DEVLINK_ATTR_SB_SIZE                               = 0xc
	DEVLINK_ATTR_SB_INGRESS_POOL_COUNT                 = 0xd
	DEVLINK_ATTR_SB_EGRESS_POOL_COUNT                  = 0xe
	DEVLINK_ATTR_SB_INGRESS_TC_COUNT                   = 0xf
	DEVLINK_ATTR_SB_EGRESS_TC_COUNT                    = 0x10
	DEVLINK_ATTR_SB_POOL_INDEX                         = 0x11
	DEVLINK_ATTR_SB_POOL_TYPE                          = 0x12
	DEVLINK_ATTR_SB_POOL_SIZE                          = 0x13
	DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE                = 0x14
	DEVLINK_ATTR_SB_THRESHOLD                          = 0x15
	DEVLINK_ATTR_SB_TC_INDEX                           = 0x16
	DEVLINK_ATTR_SB_OCC_CUR                            = 0x17
	DEVLINK_ATTR_SB_OCC_MAX                            = 0x18
	DEVLINK_ATTR_ESWITCH_MODE                          = 0x19
	DEVLINK_ATTR_ESWITCH_INLINE_MODE                   = 0x1a
	DEVLINK_ATTR_DPIPE_TABLES                          = 0x1b
	DEVLINK_ATTR_DPIPE_TABLE                           = 0x1c
	DEVLINK_ATTR_DPIPE_TABLE_NAME                      = 0x1d
	DEVLINK_ATTR_DPIPE_TABLE_SIZE                      = 0x1e
	DEVLINK_ATTR_DPIPE_TABLE_MATCHES                   = 0x1f
	DEVLINK_ATTR_DPIPE_TABLE_ACTIONS                   = 0x20
	DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED          = 0x21
	DEVLINK_ATTR_DPIPE_ENTRIES                         = 0x22
	DEVLINK_ATTR_DPIPE_ENTRY                           = 0x23
	DEVLINK_ATTR_DPIPE_ENTRY_INDEX                     = 0x24
	DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES              = 0x25
	DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES             = 0x26
	DEVLINK_ATTR_DPIPE_ENTRY_COUNTER                   = 0x27
	DEVLINK_ATTR_DPIPE_MATCH                           = 0x28
	DEVLINK_ATTR_DPIPE_MATCH_VALUE                     = 0x29
	DEVLINK_ATTR_DPIPE_MATCH_TYPE                      = 0x2a
	DEVLINK_ATTR_DPIPE_ACTION                          = 0x2b
	DEVLINK_ATTR_DPIPE_ACTION_VALUE                    = 0x2c
	DEVLINK_ATTR_DPIPE_ACTION_TYPE                     = 0x2d
	DEVLINK_ATTR_DPIPE_VALUE                           = 0x2e
	DEVLINK_ATTR_DPIPE_VALUE_MASK                      = 0x2f
	DEVLINK_ATTR_DPIPE_VALUE_MAPPING                   = 0x30
	DEVLINK_ATTR_DPIPE_HEADERS                         = 0x31
	DEVLINK_ATTR_DPIPE_HEADER                          = 0x32
	DEVLINK_ATTR_DPIPE_HEADER_NAME                     = 0x33
	DEVLINK_ATTR_DPIPE_HEADER_ID                       = 0x34
	DEVLINK_ATTR_DPIPE_HEADER_FIELDS                   = 0x35
	DEVLINK_ATTR_DPIPE_HEADER_GLOBAL                   = 0x36
	DEVLINK_ATTR_DPIPE_HEADER_INDEX                    = 0x37
	DEVLINK_ATTR_DPIPE_FIELD                           = 0x38
	DEVLINK_ATTR_DPIPE_FIELD_NAME                      = 0x39
	DEVLINK_ATTR_DPIPE_FIELD_ID                        = 0x3a
	DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH                  = 0x3b
	DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE              = 0x3c
	DEVLINK_ATTR_PAD                                   = 0x3d
	DEVLINK_ATTR_ESWITCH_ENCAP_MODE                    = 0x3e
	DEVLINK_ATTR_RESOURCE_LIST                         = 0x3f
	DEVLINK_ATTR_RESOURCE                              = 0x40
	DEVLINK_ATTR_RESOURCE_NAME                         = 0x41
	DEVLINK_ATTR_RESOURCE_ID                           = 0x42
	DEVLINK_ATTR_RESOURCE_SIZE                         = 0x43
	DEVLINK_ATTR_RESOURCE_SIZE_NEW                     = 0x44
	DEVLINK_ATTR_RESOURCE_SIZE_VALID                   = 0x45
	DEVLINK_ATTR_RESOURCE_SIZE_MIN                     = 0x46
	DEVLINK_ATTR_RESOURCE_SIZE_MAX                     = 0x47
	DEVLINK_ATTR_RESOURCE_SIZE_GRAN                    = 0x48
	DEVLINK_ATTR_RESOURCE_UNIT                         = 0x49
	DEVLINK_ATTR_RESOURCE_OCC                          = 0x4a
	DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID               = 0x4b
	DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS            = 0x4c
	DEVLINK_ATTR_PORT_FLAVOUR                          = 0x4d
	DEVLINK_ATTR_PORT_NUMBER                           = 0x4e
	DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER             = 0x4f
	DEVLINK_ATTR_PARAM                                 = 0x50
	DEVLINK_ATTR_PARAM_NAME                            = 0x51
	DEVLINK_ATTR_PARAM_GENERIC                         = 0x52
	DEVLINK_ATTR_PARAM_TYPE                            = 0x53
	DEVLINK_ATTR_PARAM_VALUES_LIST                     = 0x54
	DEVLINK_ATTR_PARAM_VALUE                           = 0x55
	DEVLINK_ATTR_PARAM_VALUE_DATA                      = 0x56
	DEVLINK_ATTR_PARAM_VALUE_CMODE                     = 0x57
	DEVLINK_ATTR_REGION_NAME                           = 0x58
	DEVLINK_ATTR_REGION_SIZE                           = 0x59
	DEVLINK_ATTR_REGION_SNAPSHOTS                      = 0x5a
	DEVLINK_ATTR_REGION_SNAPSHOT                       = 0x5b
	DEVLINK_ATTR_REGION_SNAPSHOT_ID                    = 0x5c
	DEVLINK_ATTR_REGION_CHUNKS                         = 0x5d
	DEVLINK_ATTR_REGION_CHUNK                          = 0x5e
	DEVLINK_ATTR_REGION_CHUNK_DATA                     = 0x5f
	DEVLINK_ATTR_REGION_CHUNK_ADDR                     = 0x60
	DEVLINK_ATTR_REGION_CHUNK_LEN                      = 0x61
	DEVLINK_ATTR_INFO_DRIVER_NAME                      = 0x62
	DEVLINK_ATTR_INFO_SERIAL_NUMBER                    = 0x63
	DEVLINK_ATTR_INFO_VERSION_FIXED                    = 0x64
	DEVLINK_ATTR_INFO_VERSION_RUNNING                  = 0x65
	DEVLINK_ATTR_INFO_VERSION_STORED                   = 0x66
	DEVLINK_ATTR_INFO_VERSION_NAME                     = 0x67
	DEVLINK_ATTR_INFO_VERSION_VALUE                    = 0x68
	DEVLINK_ATTR_SB_POOL_CELL_SIZE                     = 0x69
	DEVLINK_ATTR_FMSG                                  = 0x6a
	DEVLINK_ATTR_FMSG_OBJ_NEST_START                   = 0x6b
	DEVLINK_ATTR_FMSG_PAIR_NEST_START                  = 0x6c
	DEVLINK_ATTR_FMSG_ARR_NEST_START                   = 0x6d
	DEVLINK_ATTR_FMSG_NEST_END                         = 0x6e
	DEVLINK_ATTR_FMSG_OBJ_NAME                         = 0x6f
	DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE                   = 0x70
	DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA                   = 0x71
	DEVLINK_ATTR_HEALTH_REPORTER                       = 0x72
	DEVLINK_ATTR_HEALTH_REPORTER_NAME                  = 0x73
	DEVLINK_ATTR_HEALTH_REPORTER_STATE                 = 0x74
	DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT             = 0x75
	DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT         = 0x76
	DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS               = 0x77
	DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD       = 0x78
	DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER          = 0x79
	DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME                = 0x7a
	DEVLINK_ATTR_FLASH_UPDATE_COMPONENT                = 0x7b
	DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG               = 0x7c
	DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE              = 0x7d
	DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL             = 0x7e
	DEVLINK_ATTR_PORT_PCI_PF_NUMBER                    = 0x7f
	DEVLINK_ATTR_PORT_PCI_VF_NUMBER                    = 0x80
	DEVLINK_ATTR_STATS                                 = 0x81
	DEVLINK_ATTR_TRAP_NAME                             = 0x82
	DEVLINK_ATTR_TRAP_ACTION                           = 0x83
	DEVLINK_ATTR_TRAP_TYPE                             = 0x84
	DEVLINK_ATTR_TRAP_GENERIC                          = 0x85
	DEVLINK_ATTR_TRAP_METADATA                         = 0x86
	DEVLINK_ATTR_TRAP_GROUP_NAME                       = 0x87
	DEVLINK_ATTR_RELOAD_FAILED                         = 0x88
	DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS            = 0x89
	DEVLINK_ATTR_NETNS_FD                              = 0x8a
	DEVLINK_ATTR_NETNS_PID                             = 0x8b
	DEVLINK_ATTR_NETNS_ID                              = 0x8c
	DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP             = 0x8d
	DEVLINK_ATTR_TRAP_POLICER_ID                       = 0x8e
	DEVLINK_ATTR_TRAP_POLICER_RATE                     = 0x8f
	DEVLINK_ATTR_TRAP_POLICER_BURST                    = 0x90
	DEVLINK_ATTR_PORT_FUNCTION                         = 0x91
	DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER              = 0x92
	DEVLINK_ATTR_PORT_LANES                            = 0x93
	DEVLINK_ATTR_PORT_SPLITTABLE                       = 0x94
	DEVLINK_ATTR_PORT_EXTERNAL                         = 0x95
	DEVLINK_ATTR_PORT_CONTROLLER_NUMBER                = 0x96
	DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT           = 0x97
	DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK           = 0x98
	DEVLINK_ATTR_RELOAD_ACTION                         = 0x99
	DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED              = 0x9a
	DEVLINK_ATTR_RELOAD_LIMITS                         = 0x9b
	DEVLINK_ATTR_DEV_STATS                             = 0x9c
	DEVLINK_ATTR_RELOAD_STATS                          = 0x9d
	DEVLINK_ATTR_RELOAD_STATS_ENTRY                    = 0x9e
	DEVLINK_ATTR_RELOAD_STATS_LIMIT                    = 0x9f
	DEVLINK_ATTR_RELOAD_STATS_VALUE                    = 0xa0
	DEVLINK_ATTR_REMOTE_RELOAD_STATS                   = 0xa1
	DEVLINK_ATTR_RELOAD_ACTION_INFO                    = 0xa2
	DEVLINK_ATTR_RELOAD_ACTION_STATS                   = 0xa3
	DEVLINK_ATTR_PORT_PCI_SF_NUMBER                    = 0xa4
	DEVLINK_ATTR_RATE_TYPE                             = 0xa5
	DEVLINK_ATTR_RATE_TX_SHARE                         = 0xa6
	DEVLINK_ATTR_RATE_TX_MAX                           = 0xa7
	DEVLINK_ATTR_RATE_NODE_NAME                        = 0xa8
	DEVLINK_ATTR_RATE_PARENT_NODE_NAME                 = 0xa9
	DEVLINK_ATTR_REGION_MAX_SNAPSHOTS                  = 0xaa
	DEVLINK_ATTR_LINECARD_INDEX                        = 0xab
	DEVLINK_ATTR_LINECARD_STATE                        = 0xac
	DEVLINK_ATTR_LINECARD_TYPE                         = 0xad
	DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES              = 0xae
	DEVLINK_ATTR_NESTED_DEVLINK                        = 0xaf
	DEVLINK_ATTR_SELFTESTS                             = 0xb0
	DEVLINK_ATTR_MAX                                   = 0xb3
	DEVLINK_DPIPE_FIELD_MAPPING_TYPE_NONE              = 0x0
	DEVLINK_DPIPE_FIELD_MAPPING_TYPE_IFINDEX           = 0x1
	DEVLINK_DPIPE_MATCH_TYPE_FIELD_EXACT               = 0x0
	DEVLINK_DPIPE_ACTION_TYPE_FIELD_MODIFY             = 0x0
	DEVLINK_DPIPE_FIELD_ETHERNET_DST_MAC               = 0x0
	DEVLINK_DPIPE_FIELD_IPV4_DST_IP                    = 0x0
	DEVLINK_DPIPE_FIELD_IPV6_DST_IP                    = 0x0
	DEVLINK_DPIPE_HEADER_ETHERNET                      = 0x0
	DEVLINK_DPIPE_HEADER_IPV4                          = 0x1
	DEVLINK_DPIPE_HEADER_IPV6                          = 0x2
	DEVLINK_RESOURCE_UNIT_ENTRY                        = 0x0
	DEVLINK_PORT_FUNCTION_ATTR_UNSPEC                  = 0x0
	DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR                 = 0x1
	DEVLINK_PORT_FN_ATTR_STATE                         = 0x2
	DEVLINK_PORT_FN_ATTR_OPSTATE                       = 0x3
	DEVLINK_PORT_FN_ATTR_CAPS                          = 0x4
	DEVLINK_PORT_FUNCTION_ATTR_MAX                     = 0x6
)

type FsverityDigest struct {
	Algorithm uint16
	Size      uint16
}

type FsverityEnableArg struct {
	Version        uint32
	Hash_algorithm uint32
	Block_size     uint32
	Salt_size      uint32
	Salt_ptr       uint64
	Sig_size       uint32
	_              uint32
	Sig_ptr        uint64
	_              [11]uint64
}

type Nhmsg struct {
	Family   uint8
	Scope    uint8
	Protocol uint8
	Resvd    uint8
	Flags    uint32
}

type NexthopGrp struct {
	Id     uint32
	Weight uint8
	High   uint8
	Resvd2 uint16
}

const (
	NHA_UNSPEC     = 0x0
	NHA_ID         = 0x1
	NHA_GROUP      = 0x2
	NHA_GROUP_TYPE = 0x3
	NHA_BLACKHOLE  = 0x4
	NHA_OIF        = 0x5
	NHA_GATEWAY    = 0x6
	NHA_ENCAP_TYPE = 0x7
	NHA_ENCAP      = 0x8
	NHA_GROUPS     = 0x9
	NHA_MASTER     = 0xa
)

const (
	CAN_RAW_FILTER        = 0x1
	CAN_RAW_ERR_FILTER    = 0x2
	CAN_RAW_LOOPBACK      = 0x3
	CAN_RAW_RECV_OWN_MSGS = 0x4
	CAN_RAW_FD_FRAMES     = 0x5
	CAN_RAW_JOIN_FILTERS  = 0x6
)

type WatchdogInfo struct {
	Options  uint32
	Version  uint32
	Identity [32]uint8
}

type PPSFData struct {
	Info    PPSKInfo
	Timeout PPSKTime
}

type PPSKParams struct {
	Api_version   int32
	Mode          int32
	Assert_off_tu PPSKTime
	Clear_off_tu  PPSKTime
}

type PPSKTime struct {
	Sec   int64
	Nsec  int32
	Flags uint32
}

const (
	LWTUNNEL_ENCAP_NONE       = 0x0
	LWTUNNEL_ENCAP_MPLS       = 0x1
	LWTUNNEL_ENCAP_IP         = 0x2
	LWTUNNEL_ENCAP_ILA        = 0x3
	LWTUNNEL_ENCAP_IP6        = 0x4
	LWTUNNEL_ENCAP_SEG6       = 0x5
	LWTUNNEL_ENCAP_BPF        = 0x6
	LWTUNNEL_ENCAP_SEG6_LOCAL = 0x7
	LWTUNNEL_ENCAP_RPL        = 0x8
	LWTUNNEL_ENCAP_IOAM6      = 0x9
	LWTUNNEL_ENCAP_XFRM       = 0xa
	LWTUNNEL_ENCAP_MAX        = 0xa

	MPLS_IPTUNNEL_UNSPEC = 0x0
	MPLS_IPTUNNEL_DST    = 0x1
	MPLS_IPTUNNEL_TTL    = 0x2
	MPLS_IPTUNNEL_MAX    = 0x2
)

const (
	ETHTOOL_ID_UNSPEC                                                       = 0x0
	ETHTOOL_RX_COPYBREAK                                                    = 0x1
	ETHTOOL_TX_COPYBREAK                                                    = 0x2
	ETHTOOL_PFC_PREVENTION_TOUT                                             = 0x3
	ETHTOOL_TUNABLE_UNSPEC                                                  = 0x0
	ETHTOOL_TUNABLE_U8                                                      = 0x1
	ETHTOOL_TUNABLE_U16                                                     = 0x2
	ETHTOOL_TUNABLE_U32                                                     = 0x3
	ETHTOOL_TUNABLE_U64                                                     = 0x4
	ETHTOOL_TUNABLE_STRING                                                  = 0x5
	ETHTOOL_TUNABLE_S8                                                      = 0x6
	ETHTOOL_TUNABLE_S16                                                     = 0x7
	ETHTOOL_TUNABLE_S32                                                     = 0x8
	ETHTOOL_TUNABLE_S64                                                     = 0x9
	ETHTOOL_PHY_ID_UNSPEC                                                   = 0x0
	ETHTOOL_PHY_DOWNSHIFT                                                   = 0x1
	ETHTOOL_PHY_FAST_LINK_DOWN                                              = 0x2
	ETHTOOL_PHY_EDPD                                                        = 0x3
	ETHTOOL_LINK_EXT_STATE_AUTONEG                                          = 0x0
	ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE                            = 0x1
	ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH                            = 0x2
	ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY                             = 0x3
	ETHTOOL_LINK_EXT_STATE_NO_CABLE                                         = 0x4
	ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE                                      = 0x5
	ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE                                     = 0x6
	ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE                              = 0x7
	ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED                            = 0x8
	ETHTOOL_LINK_EXT_STATE_OVERHEAT                                         = 0x9
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED                        = 0x1
	ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED                           = 0x2
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED                  = 0x3
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE             = 0x4
	ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE               = 0x5
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD                                     = 0x6
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED                 = 0x1
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT                    = 0x2
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY = 0x3
	ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT                               = 0x4
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK            = 0x1
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK               = 0x2
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS              = 0x3
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED                      = 0x4
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED                      = 0x5
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS           = 0x1
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE                          = 0x2
	ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE                          = 0x1
	ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE                         = 0x2
	ETHTOOL_FLASH_ALL_REGIONS                                               = 0x0
	ETHTOOL_F_UNSUPPORTED__BIT                                              = 0x0
	ETHTOOL_F_WISH__BIT                                                     = 0x1
	ETHTOOL_F_COMPAT__BIT                                                   = 0x2
	ETHTOOL_FEC_NONE_BIT                                                    = 0x0
	ETHTOOL_FEC_AUTO_BIT                                                    = 0x1
	ETHTOOL_FEC_OFF_BIT                                                     = 0x2
	ETHTOOL_FEC_RS_BIT                                                      = 0x3
	ETHTOOL_FEC_BASER_BIT                                                   = 0x4
	ETHTOOL_FEC_LLRS_BIT                                                    = 0x5
	ETHTOOL_LINK_MODE_10baseT_Half_BIT                                      = 0x0
	ETHTOOL_LINK_MODE_10baseT_Full_BIT                                      = 0x1
	ETHTOOL_LINK_MODE_100baseT_Half_BIT                                     = 0x2
	ETHTOOL_LINK_MODE_100baseT_Full_BIT                                     = 0x3
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT                                    = 0x4
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT                                    = 0x5
	ETHTOOL_LINK_MODE_Autoneg_BIT                                           = 0x6
	ETHTOOL_LINK_MODE_TP_BIT                                                = 0x7
	ETHTOOL_LINK_MODE_AUI_BIT                                               = 0x8
	ETHTOOL_LINK_MODE_MII_BIT                                               = 0x9
	ETHTOOL_LINK_MODE_FIBRE_BIT                                             = 0xa
	ETHTOOL_LINK_MODE_BNC_BIT                                               = 0xb
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT                                   = 0xc
	ETHTOOL_LINK_MODE_Pause_BIT                                             = 0xd
	ETHTOOL_LINK_MODE_Asym_Pause_BIT                                        = 0xe
	ETHTOOL_LINK_MODE_2500baseX_Full_BIT                                    = 0xf
	ETHTOOL_LINK_MODE_Backplane_BIT                                         = 0x10
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT                                   = 0x11
	ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT                                 = 0x12
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT                                  = 0x13
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT                                    = 0x14
	ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT                                = 0x15
	ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT                                 = 0x16
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT                                 = 0x17
```