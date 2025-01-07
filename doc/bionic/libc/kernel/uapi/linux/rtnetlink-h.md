Response:
Let's break down the thought process for analyzing this C header file and generating the comprehensive response.

**1. Understanding the Context:**

The first step is recognizing the context. The prompt clearly states:

* **File Location:** `bionic/libc/kernel/uapi/linux/rtnetlink.h`
* **Bionic:**  Android's C library, math library, and dynamic linker. This is crucial. It means this header defines *kernel* interfaces used by Android's *user-space* networking components. It's not *part* of bionic's core implementation, but rather a definition of kernel structures it interacts with.
* **`uapi`:**  Indicates "user-space API". This reinforces the idea that this header is for user-space programs interacting with the kernel.
* **`rtnetlink`:** The name itself is a strong clue. "rt" likely refers to routing, and "netlink" is a Linux mechanism for communication between the kernel and user-space. So, this file is about routing-related communication with the kernel.

**2. Initial Scan for Major Components:**

A quick skim reveals several important patterns:

* **`#define` macros:**  Lots of constants are defined. These likely represent various options, flags, and message types.
* **`enum` definitions:** Enumerated types are present, further defining sets of related constants.
* **`struct` definitions:** Several structures are defined. These likely represent the data exchanged between user-space and the kernel via netlink. Key examples are `rtattr`, `rtmsg`, `ifinfomsg`, etc.

**3. Deeper Dive into Functionality (Based on Scanned Components):**

Now, let's connect the scanned components to potential functionality:

* **Macros and Enums Related to Message Types (e.g., `RTM_NEWLINK`, `RTM_GETADDR`):** These strongly suggest the file defines the *types of messages* that can be exchanged via the rtnetlink socket. The `RTM_` prefix clearly indicates "Routing Table Message". The specific names hint at operations like creating, deleting, and getting information about links, addresses, routes, neighbors, etc.

* **`struct rtattr` and Related Macros (`RTA_ALIGN`, `RTA_DATA`):** The `rtattr` structure with `rta_len` and `rta_type` suggests a generic attribute mechanism. The `RTA_` macros are for manipulating these attributes (alignment, accessing data, etc.). This is a common pattern in Linux networking for providing extensible information within netlink messages.

* **`struct rtmsg`:** This looks like the core routing message header. Fields like `rtm_family`, `rtm_dst_len`, `rtm_type`, and `rtm_flags` indicate fundamental routing information.

* **Other Structures (`ifinfomsg`, `prefixmsg`, `tcmsg`, etc.):** These seem to represent specific categories of networking information. `ifinfomsg` likely deals with network interface information, `prefixmsg` with network prefixes, `tcmsg` with traffic control, and so on.

* **`RTMGRP_*` and `RTNLGRP_*` macros/enums:** These are likely related to netlink multicast groups, allowing user-space applications to subscribe to specific types of rtnetlink events.

**4. Connecting to Android:**

Knowing this is used by Android, we can start making connections:

* **Network Configuration:**  Android needs to manage network interfaces, IP addresses, and routes. The `RTM_NEWLINK`, `RTM_NEWADDR`, `RTM_NEWROUTE` message types directly relate to these functions.
* **Connectivity Monitoring:** Android needs to know about changes in network connectivity. Netlink notifications (through the defined groups) are a natural fit for this.
* **VPN and Tethering:**  These features involve manipulating network interfaces and routes, making rtnetlink a likely underlying mechanism.
* **Firewalling and Traffic Shaping:**  The presence of `tcmsg` and related structures suggests rtnetlink is involved in Android's traffic control and firewalling functionalities.

**5. Addressing Specific Prompt Questions:**

Now, let's systematically address the prompt's questions:

* **Functionality:**  Summarize the identified message types and data structures, explaining the overall purpose of rtnetlink (managing and monitoring networking configuration).
* **Android Relevance:** Provide concrete examples of Android features that rely on rtnetlink, like setting IP addresses or monitoring network status changes.
* **libc Function Implementation:**  Acknowledge that this file *defines* structures, not *implements* functions. The *usage* of these definitions is within libc functions like `socket()`, `bind()`, `sendto()`, `recvfrom()` when interacting with netlink sockets. Explain the general process of creating a netlink socket, constructing messages, sending, and receiving.
* **Dynamic Linker:** Explain that this header is used by *applications* that need to interact with the kernel's networking subsystem. The dynamic linker's role is to load these applications and resolve their dependencies, including libc. Provide a simple SO layout example and explain the linking process conceptually.
* **Logical Reasoning (Assumptions/Inputs/Outputs):**  Give an example scenario, like adding an IP address, and show how the rtnetlink message would be constructed with specific data.
* **User/Programming Errors:**  Highlight common pitfalls, such as incorrect message construction, missing permissions, or not handling errors properly.
* **Android Framework/NDK Path and Frida Hook:** Explain the high-level flow from Android framework (e.g., ConnectivityService) down to NDK and then the system call interaction with netlink. Provide a basic Frida hook example targeting the `sendto` system call to intercept rtnetlink messages.

**6. Refinement and Structuring:**

Finally, organize the information logically using headings and bullet points for clarity. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. Double-check that all aspects of the prompt have been addressed. For instance, initially, I might have focused too heavily on the message types and less on the actual *usage* in libc functions. Reviewing the prompt ensures these connections are made explicit.
这是一个定义 Linux 内核与用户空间之间进行路由和链路信息交互的头文件。它定义了用于 Netlink 套接字的常量、数据结构和枚举，这些用于用户空间程序与内核路由模块进行通信。由于它位于 `bionic/libc/kernel/uapi` 路径下，这意味着它是 Android 中用于定义内核接口的一部分，用户空间的库函数会使用这些定义来与内核进行交互。

**它的功能：**

1. **定义了 Netlink 协议族常量:**  例如 `RTNL_FAMILY_IPMR` 和 `RTNL_FAMILY_IP6MR`，用于指定多播路由的协议族。
2. **定义了路由消息类型 (RTM):**  例如 `RTM_NEWLINK`，`RTM_DELLINK`，`RTM_NEWADDR`，`RTM_NEWROUTE` 等，这些定义了用户空间可以请求内核执行的各种路由和链路管理操作，例如创建、删除或获取网络接口、IP 地址、路由信息等。
3. **定义了路由属性 (RTA):**  `struct rtattr` 结构定义了用于携带路由消息附加信息的属性结构，例如目标地址、网关、接口索引等。相关的宏如 `RTA_ALIGN`、`RTA_DATA` 用于处理这些属性的对齐和数据访问。
4. **定义了路由消息体 (rtmsg):** `struct rtmsg` 结构定义了基本的路由消息头，包含协议族、目标/源地址长度、TOS、路由表、协议、作用域、类型和标志等信息。
5. **定义了路由类型 (RTN):**  例如 `RTN_UNICAST`，`RTN_BROADCAST`，`RTN_MULTICAST` 等，用于指示路由的类型。
6. **定义了路由协议 (RTPROT):** 例如 `RTPROT_KERNEL`，`RTPROT_STATIC`，`RTPROT_DHCP` 等，用于标识路由的来源协议。
7. **定义了路由作用域 (rt_scope_t):** 例如 `RT_SCOPE_UNIVERSE`，`RT_SCOPE_LINK`，`RT_SCOPE_HOST` 等，用于指示路由的影响范围。
8. **定义了路由消息标志 (RTM_F_*) 和路由表 ID (rt_class_t):**  用于控制路由操作的行为和指定路由表。
9. **定义了各种具体的路由属性类型 (rtattr_type_t):** 例如 `RTA_DST`，`RTA_GATEWAY`，`RTA_OIF` 等，对应 `struct rtattr` 中的 `rta_type` 字段，用于标识属性的具体含义。
10. **定义了下一跳信息 (rtnexthop):** `struct rtnexthop` 用于描述路由的下一跳信息，用于支持多路径路由。
11. **定义了缓存信息 (rta_cacheinfo):** `struct rta_cacheinfo` 用于传递路由缓存的相关信息。
12. **定义了接口信息消息 (ifinfomsg):** `struct ifinfomsg` 用于传递网络接口的信息，例如接口索引、标志等。
13. **定义了邻居信息消息 (prefixmsg):** `struct prefixmsg` 用于传递网络前缀的信息。
14. **定义了流量控制消息 (tcmsg):** `struct tcmsg` 用于传递流量控制的相关信息。
15. **定义了 Netlink 组播组 (RTMGRP_* 和 RTNLGRP_*):**  用于用户空间程序订阅特定类型的 Netlink 事件。

**与 Android 功能的关系及举例说明：**

这个头文件定义的接口是 Android 系统网络功能的基础。Android 框架和 Native 层需要通过这些接口与 Linux 内核的网络协议栈进行交互，以实现各种网络功能。

**举例说明：**

* **配置网络接口 (IP 地址、掩码、MTU 等):**  Android 系统在连接 Wi-Fi 或移动网络时，需要配置网络接口的 IP 地址、子网掩码、MTU 等。这会涉及到使用 `RTM_NEWADDR` 和 `RTM_SETLINK` 消息类型，并填充相应的 `rtattr` 属性，例如 `IFA_LOCAL` (IP 地址)、`IFA_ADDRESS` (广播地址)、`IFLA_MTU` (MTU 值) 等。
* **添加/删除路由:**  当 Android 设备需要访问外部网络时，需要配置路由信息。例如，设置默认网关。这会使用 `RTM_NEWROUTE` 和 `RTM_DELROUTE` 消息类型，并填充 `RTA_DST` (目标网络)、`RTA_GATEWAY` (网关地址)、`RTA_OIF` (出接口) 等属性。VPN 应用也需要使用这些接口来添加 VPN 路由。
* **监控网络状态变化:**  Android 系统需要监控网络接口的状态变化（例如，接口 UP/DOWN，IP 地址变更）。用户空间的程序可以通过加入相应的 Netlink 组播组（例如 `RTNLGRP_LINK`，`RTNLGRP_IPV4_IFADDR`，`RTNLGRP_IPV6_IFADDR`）来接收内核发送的 `RTM_NEWLINK` 和 `RTM_NEWADDR` 消息，从而感知网络状态的变化。例如，`ConnectivityService` 会监听这些事件来判断网络连接状态。
* **管理 ARP 表:** Android 需要管理 ARP 表来将 IP 地址映射到 MAC 地址。可以使用 `RTM_NEWNEIGH` 和 `RTM_DELNEIGH` 消息来添加或删除 ARP 表项。
* **流量控制 (Traffic Shaping):** Android 可以使用 Linux 的流量控制功能来限制特定应用的带宽或优先级。这会涉及到使用 `RTM_NEWQDISC`，`RTM_NEWTCLASS`，`RTM_NEWTFILTER` 等消息类型，并配合 `tcmsg` 结构和相关的属性。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身 **不包含 libc 函数的实现代码**，它只是定义了内核接口的数据结构和常量。libc 中的网络相关函数会使用这些定义来构造与内核通信的 Netlink 消息。

例如，`libc` 中的 `getifaddrs()` 函数会使用 Netlink 套接字发送 `RTM_GETADDR` 消息到内核，内核收到请求后会返回包含所有接口地址信息的 `RTM_NEWADDR` 消息。`libc` 的 `getifaddrs()` 函数会解析这些消息，并将结果填充到 `ifaddrs` 结构体中返回给用户程序。

**以下是一些涉及 Netlink 通信的 libc 函数及其简要说明:**

* **`socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`:**  创建一个 Netlink 套接字，用于与内核的路由模块通信。`AF_NETLINK` 指定地址族为 Netlink，`SOCK_RAW` 指定原始套接字类型，`NETLINK_ROUTE` 指定 Netlink 协议族为路由。
* **`bind(sockfd, (struct sockaddr *)&addr, sizeof(addr))`:** 将 Netlink 套接字绑定到一个本地地址。对于路由 Netlink 套接字，通常需要指定进程 ID 或加入特定的组播组。
* **`sendto(sockfd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa))`:**  通过 Netlink 套接字向内核发送消息。`buf` 包含根据 `rtnetlink.h` 中定义的结构体构造的 Netlink 消息。
* **`recvfrom(sockfd, buf, len, 0, (struct sockaddr *)&sa, &salen))`:** 通过 Netlink 套接字接收来自内核的消息。接收到的消息结构也由 `rtnetlink.h` 定义。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`rtnetlink.h` 本身不直接涉及 dynamic linker 的功能。但是，使用这个头文件的程序（例如，Android 系统服务或 Native 应用）会链接到 `libc.so`，而 `libc.so` 中包含了操作 Netlink 套接字的相关函数实现。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text          # 包含代码段 (例如 socket, bind, sendto, recvfrom 的实现)
    .rodata        # 包含只读数据 (可能包含一些内部常量)
    .data          # 包含初始化数据
    .bss           # 包含未初始化数据
    .dynsym        # 动态符号表 (包含导出的函数和变量)
    .dynstr        # 动态字符串表 (符号名称)
    .plt           # 程序链接表 (用于延迟绑定)
    .got.plt       # 全局偏移表 (用于存储动态链接的函数地址)
    ...
```

**链接的处理过程：**

1. **编译时：** 当编译一个使用 Netlink 功能的程序时，编译器会找到程序中调用的 `libc` 函数（例如 `socket`）。
2. **链接时：** 链接器（在 Android 上通常是 `lld`）会将程序的目标文件与 `libc.so` 链接在一起。链接器会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `socket` 等函数的定义。
3. **生成可执行文件或共享库：** 链接器会在生成的可执行文件或共享库中创建 `.plt` 和 `.got.plt` 条目，用于存储动态链接的信息。
4. **运行时 (Dynamic Linker 的工作)：** 当 Android 系统加载这个可执行文件或共享库时，`linker` (Android 的动态链接器) 会执行以下操作：
    * 加载所有依赖的共享库，包括 `libc.so`。
    * 解析可执行文件或共享库的动态链接信息。
    * **符号解析：** 对于程序中调用的 `socket` 函数，`linker` 会在 `libc.so` 的地址空间中找到 `socket` 函数的实际地址。
    * **重定位：** `linker` 会将 `socket` 函数的实际地址写入到可执行文件或共享库的 `.got.plt` 表的相应条目中。
    * **延迟绑定 (Lazy Binding)：** 默认情况下，函数的解析和重定位是延迟发生的。第一次调用 `socket` 函数时，会先跳转到 `.plt` 表中的一个桩代码，该桩代码会调用 `linker` 来解析 `socket` 的地址并更新 `.got.plt` 表。后续的调用会直接通过 `.got.plt` 表跳转到 `socket` 的实际地址，避免重复解析。

**假设输入与输出 (逻辑推理)：**

假设一个用户空间程序想要获取所有网络接口的列表。

**假设输入:**

* 程序创建一个 `AF_NETLINK`, `SOCK_RAW`, `NETLINK_ROUTE` 类型的套接字。
* 程序构造一个 Netlink 消息，消息类型为 `RTM_GETLINK`，`rtm_family` 设置为 `AF_UNSPEC` (获取所有协议族的接口)。消息头 `nlmsghdr` 中的 `nlmsg_type` 设置为 `RTM_GETLINK`，`nlmsg_flags` 设置为 `NLM_F_REQUEST | NLM_F_DUMP` (请求并转储所有结果)。消息体可能为空，或者包含一些过滤条件 (在这个例子中为空)。

**预期输出:**

* 内核会返回一系列 Netlink 消息，每个消息对应一个网络接口。
* 每个消息的 `nlmsghdr` 中的 `nlmsg_type` 为 `RTM_NEWLINK`。
* 每个 `RTM_NEWLINK` 消息的负载包含一个 `ifinfomsg` 结构，描述了接口的基本信息（索引、标志等）。
* 消息负载还包含一系列 `rtattr` 属性，例如 `IFLA_IFNAME` (接口名称)、`IFLA_ADDRESS` (MAC 地址)、`IFLA_MTU` (MTU 值) 等。

**用户或编程常见的使用错误，请举例说明：**

1. **未正确设置 Netlink 消息头:** 例如，`nlmsg_len` 未正确计算，导致消息截断或无法解析。`nlmsg_type` 设置错误，导致内核无法识别请求类型。
2. **未正确填充路由属性 (rtattr):** 例如，`rta_len` 或 `rta_type` 设置错误，或者属性数据的格式不正确，导致内核解析错误。
3. **忘记对齐属性数据:** Netlink 属性需要按照 `RTA_ALIGNTO` (通常是 4 字节) 对齐，否则可能导致数据损坏或解析错误。
4. **权限不足:** 某些 Netlink 操作需要特定的权限（例如 `CAP_NET_ADMIN`），如果程序没有相应的权限，内核会拒绝请求。
5. **未处理 Netlink 错误消息:** 内核可能会返回错误类型的 Netlink 消息 (例如 `NLMSG_ERROR`)，程序需要检查并处理这些错误。
6. **阻塞在 `recvfrom` 上:** 如果没有数据到达，`recvfrom` 可能会一直阻塞。程序需要设置合适的超时机制或使用非阻塞 I/O。
7. **错误地假设消息的顺序或数量:** 在 `NLM_F_DUMP` 请求中，内核会发送一系列消息，程序需要循环接收直到接收到 `NLMSG_DONE` 消息，并且不能假设消息的顺序。
8. **内存泄漏:** 在处理接收到的 Netlink 消息时，如果动态分配了内存，需要确保在使用完毕后释放，否则可能导致内存泄漏。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `rtnetlink.h` 的路径：**

1. **Android Framework (Java 层):** 例如，`ConnectivityService` 或 `NetworkManagementService` 等系统服务，它们负责管理网络连接和配置。
2. **AIDL 接口:** Framework 服务通常会通过 AIDL 接口与 Native 层进行通信。
3. **Native 服务 (C++ 层):** 例如，`netd` (Network Daemon) 是一个核心的 Native 服务，负责执行网络相关的操作。Framework 服务会通过 Binder IPC 调用 `netd` 提供的接口。
4. **`libnetd_client.so`:** Framework 服务通常会链接到 `libnetd_client.so`，该库封装了与 `netd` 通信的逻辑。
5. **`netd` 后台进程:** `netd` 进程接收来自 Framework 的请求。
6. **Netlink 套接字操作:** `netd` 中会创建 Netlink 套接字，并使用 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等 `libc` 函数与内核的路由模块进行通信。在构造 Netlink 消息时，会使用 `rtnetlink.h` 中定义的结构体和常量。
7. **Linux Kernel:** 内核接收到 Netlink 消息后，会根据消息类型执行相应的操作，并将结果通过 Netlink 套接字返回给 `netd`。

**NDK 到 `rtnetlink.h` 的路径：**

1. **NDK 应用 (C/C++ 代码):**  开发者可以使用 NDK 编写 Native 代码。
2. **直接使用 `libc` 函数:** NDK 代码可以直接调用 `libc` 提供的 Netlink 相关函数，例如 `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`。
3. **构造 Netlink 消息:** NDK 代码需要根据 `rtnetlink.h` 中定义的结构体和常量手动构造 Netlink 消息。
4. **系统调用:** `libc` 函数最终会通过系统调用 (例如 `sendto`, `recvfrom`) 将 Netlink 消息发送到内核，或从内核接收消息。

**Frida Hook 示例调试步骤：**

可以使用 Frida Hook `sendto` 系统调用来观察 Android 应用或服务发送的 Netlink 消息。

**Frida Hook 脚本 (Python):**

```python
import frida
import struct

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] sendto called")
        # 解析 sockaddr_nl 结构
        family = struct.unpack("<h", data[0:2])[0]
        if family == 18:  # AF_NETLINK
            portid = struct.unpack("<i", data[4:8])[0]
            groups = struct.unpack("<i", data[8:12])[0]
            print(f"    family: AF_NETLINK")
            print(f"    portid: {portid}")
            print(f"    groups: {groups}")

            # 假设我们想解析 rtmsg 结构
            # 注意：需要根据实际发送的数据进行偏移和长度调整
            if len(data) > 12 + 4: # 至少包含 nlmsghdr 和 rtmsg 的一部分
                nlmsghdr_len = struct.unpack("<I", data[12:16])[0]
                nlmsghdr_type = struct.unpack("<H", data[16:18])[0]
                nlmsghdr_flags = struct.unpack("<H", data[18:20])[0]
                nlmsghdr_seq = struct.unpack("<I", data[20:24])[0]
                nlmsghdr_pid = struct.unpack("<I", data[24:28])[0]

                print(f"    Netlink Header:")
                print(f"        nlmsg_len: {nlmsghdr_len}")
                print(f"        nlmsg_type: {nlmsghdr_type}")
                print(f"        nlmsg_flags: {nlmsghdr_flags}")
                print(f"        nlmsg_seq: {nlmsghdr_seq}")
                print(f"        nlmsg_pid: {nlmsghdr_pid}")

                if nlmsghdr_type >= 16 and nlmsghdr_type <= 120: # 假设是 RTM 消息
                    rtmsg_family = struct.unpack("<B", data[28:29])[0]
                    rtmsg_type = struct.unpack("<B", data[35:36])[0]
                    print(f"    Routing Message (RTM):")
                    print(f"        rtm_family: {rtmsg_family}")
                    print(f"        rtm_type: {rtmsg_type}")

def main():
    device = frida.get_usb_device()
    pid = int(input("Enter target PID: "))
    session = device.attach(pid)

    script = session.create_script("""
        Interceptor.attach(Module.findExportByName(null, "sendto"), {
            onEnter: function(args) {
                var sockfd = args[0].toInt32();
                var buf = ptr(args[1]);
                var len = args[2].toInt32();
                var flags = args[3].toInt32();
                var dest_addr = ptr(args[4]);
                var addrlen = args[5].toInt32();

                if (addrlen > 0) {
                    var destAddrData = dest_addr.readByteArray(addrlen);
                    send({type: 'send', addrlen: addrlen, data: Array.from(destAddrData)});
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    input("[!] Press <Enter> to detach from the process...\n")
    session.detach()

if __name__ == '__main__':
    main()
```

**使用步骤：**

1. **准备 Frida 环境:** 确保已安装 Frida 和 Frida-server 在 Android 设备上。
2. **运行目标应用/服务:** 启动你想要监控其 Netlink 通信的 Android 应用或服务。
3. **获取目标进程 PID:**  使用 `adb shell ps | grep <进程名>` 获取目标进程的 PID。
4. **运行 Frida Hook 脚本:** 运行上述 Python 脚本，并输入目标进程的 PID。
5. **观察输出:** 当目标进程调用 `sendto` 发送数据时，Frida 脚本会拦截调用，并尝试解析 `sockaddr_nl` 结构和部分 Netlink 消息头 (`nlmsghdr` 和 `rtmsg`)，并打印相关信息。

**注意:**

* 这个 Frida 脚本只是一个基本示例，用于演示如何 Hook `sendto` 并初步解析 Netlink 消息。实际解析 Netlink 消息需要更详细的逻辑，根据不同的消息类型和属性进行解析。
* 需要根据实际情况调整脚本中的偏移量和长度，以正确解析 Netlink 消息的各个部分。
* 确保你的 Android 设备已 root，并且 Frida-server 正在运行。

通过 Frida Hook，你可以动态地观察 Android 系统或应用是如何使用 `rtnetlink.h` 中定义的接口与内核进行通信的，从而深入理解 Android 网络功能的实现细节。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/rtnetlink.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI__LINUX_RTNETLINK_H
#define _UAPI__LINUX_RTNETLINK_H
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#define RTNL_FAMILY_IPMR 128
#define RTNL_FAMILY_IP6MR 129
#define RTNL_FAMILY_MAX 129
enum {
  RTM_BASE = 16,
#define RTM_BASE RTM_BASE
  RTM_NEWLINK = 16,
#define RTM_NEWLINK RTM_NEWLINK
  RTM_DELLINK,
#define RTM_DELLINK RTM_DELLINK
  RTM_GETLINK,
#define RTM_GETLINK RTM_GETLINK
  RTM_SETLINK,
#define RTM_SETLINK RTM_SETLINK
  RTM_NEWADDR = 20,
#define RTM_NEWADDR RTM_NEWADDR
  RTM_DELADDR,
#define RTM_DELADDR RTM_DELADDR
  RTM_GETADDR,
#define RTM_GETADDR RTM_GETADDR
  RTM_NEWROUTE = 24,
#define RTM_NEWROUTE RTM_NEWROUTE
  RTM_DELROUTE,
#define RTM_DELROUTE RTM_DELROUTE
  RTM_GETROUTE,
#define RTM_GETROUTE RTM_GETROUTE
  RTM_NEWNEIGH = 28,
#define RTM_NEWNEIGH RTM_NEWNEIGH
  RTM_DELNEIGH,
#define RTM_DELNEIGH RTM_DELNEIGH
  RTM_GETNEIGH,
#define RTM_GETNEIGH RTM_GETNEIGH
  RTM_NEWRULE = 32,
#define RTM_NEWRULE RTM_NEWRULE
  RTM_DELRULE,
#define RTM_DELRULE RTM_DELRULE
  RTM_GETRULE,
#define RTM_GETRULE RTM_GETRULE
  RTM_NEWQDISC = 36,
#define RTM_NEWQDISC RTM_NEWQDISC
  RTM_DELQDISC,
#define RTM_DELQDISC RTM_DELQDISC
  RTM_GETQDISC,
#define RTM_GETQDISC RTM_GETQDISC
  RTM_NEWTCLASS = 40,
#define RTM_NEWTCLASS RTM_NEWTCLASS
  RTM_DELTCLASS,
#define RTM_DELTCLASS RTM_DELTCLASS
  RTM_GETTCLASS,
#define RTM_GETTCLASS RTM_GETTCLASS
  RTM_NEWTFILTER = 44,
#define RTM_NEWTFILTER RTM_NEWTFILTER
  RTM_DELTFILTER,
#define RTM_DELTFILTER RTM_DELTFILTER
  RTM_GETTFILTER,
#define RTM_GETTFILTER RTM_GETTFILTER
  RTM_NEWACTION = 48,
#define RTM_NEWACTION RTM_NEWACTION
  RTM_DELACTION,
#define RTM_DELACTION RTM_DELACTION
  RTM_GETACTION,
#define RTM_GETACTION RTM_GETACTION
  RTM_NEWPREFIX = 52,
#define RTM_NEWPREFIX RTM_NEWPREFIX
  RTM_GETMULTICAST = 58,
#define RTM_GETMULTICAST RTM_GETMULTICAST
  RTM_GETANYCAST = 62,
#define RTM_GETANYCAST RTM_GETANYCAST
  RTM_NEWNEIGHTBL = 64,
#define RTM_NEWNEIGHTBL RTM_NEWNEIGHTBL
  RTM_GETNEIGHTBL = 66,
#define RTM_GETNEIGHTBL RTM_GETNEIGHTBL
  RTM_SETNEIGHTBL,
#define RTM_SETNEIGHTBL RTM_SETNEIGHTBL
  RTM_NEWNDUSEROPT = 68,
#define RTM_NEWNDUSEROPT RTM_NEWNDUSEROPT
  RTM_NEWADDRLABEL = 72,
#define RTM_NEWADDRLABEL RTM_NEWADDRLABEL
  RTM_DELADDRLABEL,
#define RTM_DELADDRLABEL RTM_DELADDRLABEL
  RTM_GETADDRLABEL,
#define RTM_GETADDRLABEL RTM_GETADDRLABEL
  RTM_GETDCB = 78,
#define RTM_GETDCB RTM_GETDCB
  RTM_SETDCB,
#define RTM_SETDCB RTM_SETDCB
  RTM_NEWNETCONF = 80,
#define RTM_NEWNETCONF RTM_NEWNETCONF
  RTM_DELNETCONF,
#define RTM_DELNETCONF RTM_DELNETCONF
  RTM_GETNETCONF = 82,
#define RTM_GETNETCONF RTM_GETNETCONF
  RTM_NEWMDB = 84,
#define RTM_NEWMDB RTM_NEWMDB
  RTM_DELMDB = 85,
#define RTM_DELMDB RTM_DELMDB
  RTM_GETMDB = 86,
#define RTM_GETMDB RTM_GETMDB
  RTM_NEWNSID = 88,
#define RTM_NEWNSID RTM_NEWNSID
  RTM_DELNSID = 89,
#define RTM_DELNSID RTM_DELNSID
  RTM_GETNSID = 90,
#define RTM_GETNSID RTM_GETNSID
  RTM_NEWSTATS = 92,
#define RTM_NEWSTATS RTM_NEWSTATS
  RTM_GETSTATS = 94,
#define RTM_GETSTATS RTM_GETSTATS
  RTM_SETSTATS,
#define RTM_SETSTATS RTM_SETSTATS
  RTM_NEWCACHEREPORT = 96,
#define RTM_NEWCACHEREPORT RTM_NEWCACHEREPORT
  RTM_NEWCHAIN = 100,
#define RTM_NEWCHAIN RTM_NEWCHAIN
  RTM_DELCHAIN,
#define RTM_DELCHAIN RTM_DELCHAIN
  RTM_GETCHAIN,
#define RTM_GETCHAIN RTM_GETCHAIN
  RTM_NEWNEXTHOP = 104,
#define RTM_NEWNEXTHOP RTM_NEWNEXTHOP
  RTM_DELNEXTHOP,
#define RTM_DELNEXTHOP RTM_DELNEXTHOP
  RTM_GETNEXTHOP,
#define RTM_GETNEXTHOP RTM_GETNEXTHOP
  RTM_NEWLINKPROP = 108,
#define RTM_NEWLINKPROP RTM_NEWLINKPROP
  RTM_DELLINKPROP,
#define RTM_DELLINKPROP RTM_DELLINKPROP
  RTM_GETLINKPROP,
#define RTM_GETLINKPROP RTM_GETLINKPROP
  RTM_NEWVLAN = 112,
#define RTM_NEWNVLAN RTM_NEWVLAN
  RTM_DELVLAN,
#define RTM_DELVLAN RTM_DELVLAN
  RTM_GETVLAN,
#define RTM_GETVLAN RTM_GETVLAN
  RTM_NEWNEXTHOPBUCKET = 116,
#define RTM_NEWNEXTHOPBUCKET RTM_NEWNEXTHOPBUCKET
  RTM_DELNEXTHOPBUCKET,
#define RTM_DELNEXTHOPBUCKET RTM_DELNEXTHOPBUCKET
  RTM_GETNEXTHOPBUCKET,
#define RTM_GETNEXTHOPBUCKET RTM_GETNEXTHOPBUCKET
  RTM_NEWTUNNEL = 120,
#define RTM_NEWTUNNEL RTM_NEWTUNNEL
  RTM_DELTUNNEL,
#define RTM_DELTUNNEL RTM_DELTUNNEL
  RTM_GETTUNNEL,
#define RTM_GETTUNNEL RTM_GETTUNNEL
  __RTM_MAX,
#define RTM_MAX (((__RTM_MAX + 3) & ~3) - 1)
};
#define RTM_NR_MSGTYPES (RTM_MAX + 1 - RTM_BASE)
#define RTM_NR_FAMILIES (RTM_NR_MSGTYPES >> 2)
#define RTM_FAM(cmd) (((cmd) - RTM_BASE) >> 2)
struct rtattr {
  unsigned short rta_len;
  unsigned short rta_type;
};
#define RTA_ALIGNTO 4U
#define RTA_ALIGN(len) (((len) + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1))
#define RTA_OK(rta,len) ((len) >= (int) sizeof(struct rtattr) && (rta)->rta_len >= sizeof(struct rtattr) && (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen) ((attrlen) -= RTA_ALIGN((rta)->rta_len), (struct rtattr *) (((char *) (rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_LENGTH(len) (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_SPACE(len) RTA_ALIGN(RTA_LENGTH(len))
#define RTA_DATA(rta) ((void *) (((char *) (rta)) + RTA_LENGTH(0)))
#define RTA_PAYLOAD(rta) ((int) ((rta)->rta_len) - RTA_LENGTH(0))
struct rtmsg {
  unsigned char rtm_family;
  unsigned char rtm_dst_len;
  unsigned char rtm_src_len;
  unsigned char rtm_tos;
  unsigned char rtm_table;
  unsigned char rtm_protocol;
  unsigned char rtm_scope;
  unsigned char rtm_type;
  unsigned rtm_flags;
};
enum {
  RTN_UNSPEC,
  RTN_UNICAST,
  RTN_LOCAL,
  RTN_BROADCAST,
  RTN_ANYCAST,
  RTN_MULTICAST,
  RTN_BLACKHOLE,
  RTN_UNREACHABLE,
  RTN_PROHIBIT,
  RTN_THROW,
  RTN_NAT,
  RTN_XRESOLVE,
  __RTN_MAX
};
#define RTN_MAX (__RTN_MAX - 1)
#define RTPROT_UNSPEC 0
#define RTPROT_REDIRECT 1
#define RTPROT_KERNEL 2
#define RTPROT_BOOT 3
#define RTPROT_STATIC 4
#define RTPROT_GATED 8
#define RTPROT_RA 9
#define RTPROT_MRT 10
#define RTPROT_ZEBRA 11
#define RTPROT_BIRD 12
#define RTPROT_DNROUTED 13
#define RTPROT_XORP 14
#define RTPROT_NTK 15
#define RTPROT_DHCP 16
#define RTPROT_MROUTED 17
#define RTPROT_KEEPALIVED 18
#define RTPROT_BABEL 42
#define RTPROT_OPENR 99
#define RTPROT_BGP 186
#define RTPROT_ISIS 187
#define RTPROT_OSPF 188
#define RTPROT_RIP 189
#define RTPROT_EIGRP 192
enum rt_scope_t {
  RT_SCOPE_UNIVERSE = 0,
  RT_SCOPE_SITE = 200,
  RT_SCOPE_LINK = 253,
  RT_SCOPE_HOST = 254,
  RT_SCOPE_NOWHERE = 255
};
#define RTM_F_NOTIFY 0x100
#define RTM_F_CLONED 0x200
#define RTM_F_EQUALIZE 0x400
#define RTM_F_PREFIX 0x800
#define RTM_F_LOOKUP_TABLE 0x1000
#define RTM_F_FIB_MATCH 0x2000
#define RTM_F_OFFLOAD 0x4000
#define RTM_F_TRAP 0x8000
#define RTM_F_OFFLOAD_FAILED 0x20000000
enum rt_class_t {
  RT_TABLE_UNSPEC = 0,
  RT_TABLE_COMPAT = 252,
  RT_TABLE_DEFAULT = 253,
  RT_TABLE_MAIN = 254,
  RT_TABLE_LOCAL = 255,
  RT_TABLE_MAX = 0xFFFFFFFF
};
enum rtattr_type_t {
  RTA_UNSPEC,
  RTA_DST,
  RTA_SRC,
  RTA_IIF,
  RTA_OIF,
  RTA_GATEWAY,
  RTA_PRIORITY,
  RTA_PREFSRC,
  RTA_METRICS,
  RTA_MULTIPATH,
  RTA_PROTOINFO,
  RTA_FLOW,
  RTA_CACHEINFO,
  RTA_SESSION,
  RTA_MP_ALGO,
  RTA_TABLE,
  RTA_MARK,
  RTA_MFC_STATS,
  RTA_VIA,
  RTA_NEWDST,
  RTA_PREF,
  RTA_ENCAP_TYPE,
  RTA_ENCAP,
  RTA_EXPIRES,
  RTA_PAD,
  RTA_UID,
  RTA_TTL_PROPAGATE,
  RTA_IP_PROTO,
  RTA_SPORT,
  RTA_DPORT,
  RTA_NH_ID,
  __RTA_MAX
};
#define RTA_MAX (__RTA_MAX - 1)
#define RTM_RTA(r) ((struct rtattr *) (((char *) (r)) + NLMSG_ALIGN(sizeof(struct rtmsg))))
#define RTM_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct rtmsg))
struct rtnexthop {
  unsigned short rtnh_len;
  unsigned char rtnh_flags;
  unsigned char rtnh_hops;
  int rtnh_ifindex;
};
#define RTNH_F_DEAD 1
#define RTNH_F_PERVASIVE 2
#define RTNH_F_ONLINK 4
#define RTNH_F_OFFLOAD 8
#define RTNH_F_LINKDOWN 16
#define RTNH_F_UNRESOLVED 32
#define RTNH_F_TRAP 64
#define RTNH_COMPARE_MASK (RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_OFFLOAD | RTNH_F_TRAP)
#define RTNH_ALIGNTO 4
#define RTNH_ALIGN(len) (((len) + RTNH_ALIGNTO - 1) & ~(RTNH_ALIGNTO - 1))
#define RTNH_OK(rtnh,len) ((rtnh)->rtnh_len >= sizeof(struct rtnexthop) && ((int) (rtnh)->rtnh_len) <= (len))
#define RTNH_NEXT(rtnh) ((struct rtnexthop *) (((char *) (rtnh)) + RTNH_ALIGN((rtnh)->rtnh_len)))
#define RTNH_LENGTH(len) (RTNH_ALIGN(sizeof(struct rtnexthop)) + (len))
#define RTNH_SPACE(len) RTNH_ALIGN(RTNH_LENGTH(len))
#define RTNH_DATA(rtnh) ((struct rtattr *) (((char *) (rtnh)) + RTNH_LENGTH(0)))
struct rtvia {
  __kernel_sa_family_t rtvia_family;
  __u8 rtvia_addr[];
};
struct rta_cacheinfo {
  __u32 rta_clntref;
  __u32 rta_lastuse;
  __s32 rta_expires;
  __u32 rta_error;
  __u32 rta_used;
#define RTNETLINK_HAVE_PEERINFO 1
  __u32 rta_id;
  __u32 rta_ts;
  __u32 rta_tsage;
};
enum {
  RTAX_UNSPEC,
#define RTAX_UNSPEC RTAX_UNSPEC
  RTAX_LOCK,
#define RTAX_LOCK RTAX_LOCK
  RTAX_MTU,
#define RTAX_MTU RTAX_MTU
  RTAX_WINDOW,
#define RTAX_WINDOW RTAX_WINDOW
  RTAX_RTT,
#define RTAX_RTT RTAX_RTT
  RTAX_RTTVAR,
#define RTAX_RTTVAR RTAX_RTTVAR
  RTAX_SSTHRESH,
#define RTAX_SSTHRESH RTAX_SSTHRESH
  RTAX_CWND,
#define RTAX_CWND RTAX_CWND
  RTAX_ADVMSS,
#define RTAX_ADVMSS RTAX_ADVMSS
  RTAX_REORDERING,
#define RTAX_REORDERING RTAX_REORDERING
  RTAX_HOPLIMIT,
#define RTAX_HOPLIMIT RTAX_HOPLIMIT
  RTAX_INITCWND,
#define RTAX_INITCWND RTAX_INITCWND
  RTAX_FEATURES,
#define RTAX_FEATURES RTAX_FEATURES
  RTAX_RTO_MIN,
#define RTAX_RTO_MIN RTAX_RTO_MIN
  RTAX_INITRWND,
#define RTAX_INITRWND RTAX_INITRWND
  RTAX_QUICKACK,
#define RTAX_QUICKACK RTAX_QUICKACK
  RTAX_CC_ALGO,
#define RTAX_CC_ALGO RTAX_CC_ALGO
  RTAX_FASTOPEN_NO_COOKIE,
#define RTAX_FASTOPEN_NO_COOKIE RTAX_FASTOPEN_NO_COOKIE
  __RTAX_MAX
};
#define RTAX_MAX (__RTAX_MAX - 1)
#define RTAX_FEATURE_ECN (1 << 0)
#define RTAX_FEATURE_SACK (1 << 1)
#define RTAX_FEATURE_TIMESTAMP (1 << 2)
#define RTAX_FEATURE_ALLFRAG (1 << 3)
#define RTAX_FEATURE_TCP_USEC_TS (1 << 4)
#define RTAX_FEATURE_MASK (RTAX_FEATURE_ECN | RTAX_FEATURE_SACK | RTAX_FEATURE_TIMESTAMP | RTAX_FEATURE_ALLFRAG | RTAX_FEATURE_TCP_USEC_TS)
struct rta_session {
  __u8 proto;
  __u8 pad1;
  __u16 pad2;
  union {
    struct {
      __u16 sport;
      __u16 dport;
    } ports;
    struct {
      __u8 type;
      __u8 code;
      __u16 ident;
    } icmpt;
    __u32 spi;
  } u;
};
struct rta_mfc_stats {
  __u64 mfcs_packets;
  __u64 mfcs_bytes;
  __u64 mfcs_wrong_if;
};
struct rtgenmsg {
  unsigned char rtgen_family;
};
struct ifinfomsg {
  unsigned char ifi_family;
  unsigned char __ifi_pad;
  unsigned short ifi_type;
  int ifi_index;
  unsigned ifi_flags;
  unsigned ifi_change;
};
struct prefixmsg {
  unsigned char prefix_family;
  unsigned char prefix_pad1;
  unsigned short prefix_pad2;
  int prefix_ifindex;
  unsigned char prefix_type;
  unsigned char prefix_len;
  unsigned char prefix_flags;
  unsigned char prefix_pad3;
};
enum {
  PREFIX_UNSPEC,
  PREFIX_ADDRESS,
  PREFIX_CACHEINFO,
  __PREFIX_MAX
};
#define PREFIX_MAX (__PREFIX_MAX - 1)
struct prefix_cacheinfo {
  __u32 preferred_time;
  __u32 valid_time;
};
struct tcmsg {
  unsigned char tcm_family;
  unsigned char tcm__pad1;
  unsigned short tcm__pad2;
  int tcm_ifindex;
  __u32 tcm_handle;
  __u32 tcm_parent;
#define tcm_block_index tcm_parent
  __u32 tcm_info;
};
#define TCM_IFINDEX_MAGIC_BLOCK (0xFFFFFFFFU)
enum {
  TCA_UNSPEC,
  TCA_KIND,
  TCA_OPTIONS,
  TCA_STATS,
  TCA_XSTATS,
  TCA_RATE,
  TCA_FCNT,
  TCA_STATS2,
  TCA_STAB,
  TCA_PAD,
  TCA_DUMP_INVISIBLE,
  TCA_CHAIN,
  TCA_HW_OFFLOAD,
  TCA_INGRESS_BLOCK,
  TCA_EGRESS_BLOCK,
  TCA_DUMP_FLAGS,
  TCA_EXT_WARN_MSG,
  __TCA_MAX
};
#define TCA_MAX (__TCA_MAX - 1)
#define TCA_DUMP_FLAGS_TERSE (1 << 0)
#define TCA_RTA(r) ((struct rtattr *) (((char *) (r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))
#define TCA_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct tcmsg))
struct nduseroptmsg {
  unsigned char nduseropt_family;
  unsigned char nduseropt_pad1;
  unsigned short nduseropt_opts_len;
  int nduseropt_ifindex;
  __u8 nduseropt_icmp_type;
  __u8 nduseropt_icmp_code;
  unsigned short nduseropt_pad2;
  unsigned int nduseropt_pad3;
};
enum {
  NDUSEROPT_UNSPEC,
  NDUSEROPT_SRCADDR,
  __NDUSEROPT_MAX
};
#define NDUSEROPT_MAX (__NDUSEROPT_MAX - 1)
#define RTMGRP_LINK 1
#define RTMGRP_NOTIFY 2
#define RTMGRP_NEIGH 4
#define RTMGRP_TC 8
#define RTMGRP_IPV4_IFADDR 0x10
#define RTMGRP_IPV4_MROUTE 0x20
#define RTMGRP_IPV4_ROUTE 0x40
#define RTMGRP_IPV4_RULE 0x80
#define RTMGRP_IPV6_IFADDR 0x100
#define RTMGRP_IPV6_MROUTE 0x200
#define RTMGRP_IPV6_ROUTE 0x400
#define RTMGRP_IPV6_IFINFO 0x800
#define RTMGRP_DECnet_IFADDR 0x1000
#define RTMGRP_DECnet_ROUTE 0x4000
#define RTMGRP_IPV6_PREFIX 0x20000
enum rtnetlink_groups {
  RTNLGRP_NONE,
#define RTNLGRP_NONE RTNLGRP_NONE
  RTNLGRP_LINK,
#define RTNLGRP_LINK RTNLGRP_LINK
  RTNLGRP_NOTIFY,
#define RTNLGRP_NOTIFY RTNLGRP_NOTIFY
  RTNLGRP_NEIGH,
#define RTNLGRP_NEIGH RTNLGRP_NEIGH
  RTNLGRP_TC,
#define RTNLGRP_TC RTNLGRP_TC
  RTNLGRP_IPV4_IFADDR,
#define RTNLGRP_IPV4_IFADDR RTNLGRP_IPV4_IFADDR
  RTNLGRP_IPV4_MROUTE,
#define RTNLGRP_IPV4_MROUTE RTNLGRP_IPV4_MROUTE
  RTNLGRP_IPV4_ROUTE,
#define RTNLGRP_IPV4_ROUTE RTNLGRP_IPV4_ROUTE
  RTNLGRP_IPV4_RULE,
#define RTNLGRP_IPV4_RULE RTNLGRP_IPV4_RULE
  RTNLGRP_IPV6_IFADDR,
#define RTNLGRP_IPV6_IFADDR RTNLGRP_IPV6_IFADDR
  RTNLGRP_IPV6_MROUTE,
#define RTNLGRP_IPV6_MROUTE RTNLGRP_IPV6_MROUTE
  RTNLGRP_IPV6_ROUTE,
#define RTNLGRP_IPV6_ROUTE RTNLGRP_IPV6_ROUTE
  RTNLGRP_IPV6_IFINFO,
#define RTNLGRP_IPV6_IFINFO RTNLGRP_IPV6_IFINFO
  RTNLGRP_DECnet_IFADDR,
#define RTNLGRP_DECnet_IFADDR RTNLGRP_DECnet_IFADDR
  RTNLGRP_NOP2,
  RTNLGRP_DECnet_ROUTE,
#define RTNLGRP_DECnet_ROUTE RTNLGRP_DECnet_ROUTE
  RTNLGRP_DECnet_RULE,
#define RTNLGRP_DECnet_RULE RTNLGRP_DECnet_RULE
  RTNLGRP_NOP4,
  RTNLGRP_IPV6_PREFIX,
#define RTNLGRP_IPV6_PREFIX RTNLGRP_IPV6_PREFIX
  RTNLGRP_IPV6_RULE,
#define RTNLGRP_IPV6_RULE RTNLGRP_IPV6_RULE
  RTNLGRP_ND_USEROPT,
#define RTNLGRP_ND_USEROPT RTNLGRP_ND_USEROPT
  RTNLGRP_PHONET_IFADDR,
#define RTNLGRP_PHONET_IFADDR RTNLGRP_PHONET_IFADDR
  RTNLGRP_PHONET_ROUTE,
#define RTNLGRP_PHONET_ROUTE RTNLGRP_PHONET_ROUTE
  RTNLGRP_DCB,
#define RTNLGRP_DCB RTNLGRP_DCB
  RTNLGRP_IPV4_NETCONF,
#define RTNLGRP_IPV4_NETCONF RTNLGRP_IPV4_NETCONF
  RTNLGRP_IPV6_NETCONF,
#define RTNLGRP_IPV6_NETCONF RTNLGRP_IPV6_NETCONF
  RTNLGRP_MDB,
#define RTNLGRP_MDB RTNLGRP_MDB
  RTNLGRP_MPLS_ROUTE,
#define RTNLGRP_MPLS_ROUTE RTNLGRP_MPLS_ROUTE
  RTNLGRP_NSID,
#define RTNLGRP_NSID RTNLGRP_NSID
  RTNLGRP_MPLS_NETCONF,
#define RTNLGRP_MPLS_NETCONF RTNLGRP_MPLS_NETCONF
  RTNLGRP_IPV4_MROUTE_R,
#define RTNLGRP_IPV4_MROUTE_R RTNLGRP_IPV4_MROUTE_R
  RTNLGRP_IPV6_MROUTE_R,
#define RTNLGRP_IPV6_MROUTE_R RTNLGRP_IPV6_MROUTE_R
  RTNLGRP_NEXTHOP,
#define RTNLGRP_NEXTHOP RTNLGRP_NEXTHOP
  RTNLGRP_BRVLAN,
#define RTNLGRP_BRVLAN RTNLGRP_BRVLAN
  RTNLGRP_MCTP_IFADDR,
#define RTNLGRP_MCTP_IFADDR RTNLGRP_MCTP_IFADDR
  RTNLGRP_TUNNEL,
#define RTNLGRP_TUNNEL RTNLGRP_TUNNEL
  RTNLGRP_STATS,
#define RTNLGRP_STATS RTNLGRP_STATS
  __RTNLGRP_MAX
};
#define RTNLGRP_MAX (__RTNLGRP_MAX - 1)
struct tcamsg {
  unsigned char tca_family;
  unsigned char tca__pad1;
  unsigned short tca__pad2;
};
enum {
  TCA_ROOT_UNSPEC,
  TCA_ROOT_TAB,
#define TCA_ACT_TAB TCA_ROOT_TAB
#define TCAA_MAX TCA_ROOT_TAB
  TCA_ROOT_FLAGS,
  TCA_ROOT_COUNT,
  TCA_ROOT_TIME_DELTA,
  TCA_ROOT_EXT_WARN_MSG,
  __TCA_ROOT_MAX,
#define TCA_ROOT_MAX (__TCA_ROOT_MAX - 1)
};
#define TA_RTA(r) ((struct rtattr *) (((char *) (r)) + NLMSG_ALIGN(sizeof(struct tcamsg))))
#define TA_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct tcamsg))
#define TCA_FLAG_LARGE_DUMP_ON (1 << 0)
#define TCA_ACT_FLAG_LARGE_DUMP_ON TCA_FLAG_LARGE_DUMP_ON
#define TCA_ACT_FLAG_TERSE_DUMP (1 << 1)
#define RTEXT_FILTER_VF (1 << 0)
#define RTEXT_FILTER_BRVLAN (1 << 1)
#define RTEXT_FILTER_BRVLAN_COMPRESSED (1 << 2)
#define RTEXT_FILTER_SKIP_STATS (1 << 3)
#define RTEXT_FILTER_MRP (1 << 4)
#define RTEXT_FILTER_CFM_CONFIG (1 << 5)
#define RTEXT_FILTER_CFM_STATUS (1 << 6)
#define RTEXT_FILTER_MST (1 << 7)
#endif

"""

```