Response:
Let's break down the thought process for generating the detailed explanation of the `nfnetlink_conntrack.h` header file.

**1. Understanding the Request:**

The core request is to explain the functionality of a specific header file within the Android Bionic library. Key aspects to cover include:

* **Functionality:** What does this file define and what purpose does it serve?
* **Android Relevance:** How does it connect to Android's features?
* **libc Function Details:**  A trick question – this file *doesn't* define libc functions directly, but rather *structures* used by them. The focus should be on the *meaning* of the definitions.
* **Dynamic Linker:**  Another slightly misleading point. Header files don't inherently involve the dynamic linker in their *definition*. The linker comes into play when code *using* these definitions is linked. However, the request prompts for related information, so discussing the role of shared libraries and how this header might be used by them is relevant.
* **Logic/Assumptions:**  For a header file, this translates to understanding the intended use cases and the relationships between the defined enums and macros.
* **Common Errors:**  Focus on incorrect usage of the defined constants or misunderstandings about their meaning.
* **Android Framework/NDK Path:**  Tracing how this low-level header is ultimately used in higher levels of Android.
* **Frida Hooking:**  Demonstrating how to inspect the usage of these definitions at runtime.

**2. Initial Analysis of the Header File:**

The header file `nfnetlink_conntrack.h` immediately reveals itself as defining constants (enums and macros) related to **netfilter's connection tracking (conntrack) subsystem** within the Linux kernel. The "nfnetlink" part indicates it uses the netlink protocol for communication between user space and the kernel's netfilter module. The auto-generated notice reinforces that direct modification is discouraged, implying these definitions are tied to kernel versions.

**3. Deconstructing the Enums and Macros:**

The next step is to go through each defined enum and macro, understanding its purpose:

* **`cntl_msg_types` and `ctnl_exp_msg_types`:**  These define the types of messages exchanged via netlink related to connection tracking and expectation tracking. Keywords like "NEW," "GET," "DELETE," and "STATS" are strong indicators of the operations involved.
* **`ctattr_type`:**  This is a crucial enum, defining the *attributes* that can be associated with a connection tracking entry. Terms like "TUPLE," "STATUS," "PROTOINFO," "NAT," "TIMEOUT," etc., provide insight into the information tracked. The `#define CTA_NAT CTA_NAT_SRC` shows macro aliasing.
* **Nested Enums (e.g., `ctattr_tuple`, `ctattr_ip`, `ctattr_l4proto`):** These further refine the structure of the attributes, providing a hierarchical representation of connection details (IP addresses, ports, protocol information). The `CTA_TUPLE_IP`, `CTA_TUPLE_PROTO` within `ctattr_tuple` are good examples.
* **`ctattr_counters`, `ctattr_tstamp`, `ctattr_nat`, etc.:** These define attributes related to specific aspects of connection tracking, like packet/byte counts, timestamps, NAT details, and more.
* **`ctattr_stats_*` Enums:**  These cover statistics related to connection tracking operations.

**4. Connecting to Android Functionality:**

With an understanding of the definitions, the next step is to relate them to Android. The key connection is Android's network stack, which relies on the Linux kernel. Specifically:

* **Firewall (iptables/nftables):**  Conntrack is fundamental to stateful firewalls. Android uses iptables (historically) and nftables. These tools use conntrack to track connections and make informed decisions about allowing or blocking traffic.
* **Network Address Translation (NAT):**  Android devices often act as gateways or hotspots, performing NAT. Conntrack is essential for managing NAT mappings.
* **Connection Tracking for Applications:**  While not directly exposed, the underlying conntrack mechanism affects how network connections behave for Android apps.

**5. Addressing Specific Parts of the Request:**

* **libc Functions:** Explicitly state that the file *defines constants*, not implements libc functions. Explain the constants' *purpose*.
* **Dynamic Linker:** Explain that this header is used by libraries that are dynamically linked. Provide a simplified SO layout and illustrate the linking process (symbol resolution).
* **Logic/Assumptions:**  Show examples of how the enums and macros are likely used to construct and interpret netlink messages related to connection tracking.
* **Common Errors:**  Focus on misusing the constants (e.g., providing an invalid attribute type).
* **Android Framework/NDK Path:** Trace from high-level Java APIs (e.g., `NetworkPolicyManager`) down through native code and system calls that ultimately interact with netfilter and conntrack.
* **Frida Hooking:** Provide concrete examples of how to use Frida to intercept calls and inspect the values of these constants.

**6. Structuring the Response:**

Organize the information logically with clear headings and subheadings, as in the provided example answer. Use bullet points and code blocks to enhance readability.

**7. Language and Tone:**

Use clear and concise language. Explain technical terms. Maintain a helpful and informative tone. Since the request was in Chinese, the response should also be in Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file defines functions related to network configuration.
* **Correction:** The "nfnetlink" part strongly suggests interaction with the netfilter subsystem, and the enum names clearly relate to connection tracking.
* **Initial thought:** Explain how `open()`, `read()`, `write()` work in the context of this file.
* **Correction:**  This file is a header, not a source file with function implementations. Focus on how *other* code uses these definitions with system calls related to netlink sockets.
* **Initial thought:** Provide a highly detailed SO layout with every section.
* **Correction:** A simplified layout highlighting the relevant sections (e.g., `.symtab`, `.strtab`, `.rel.dyn`) is sufficient for illustrating the linking process.

By following this thought process, systematically analyzing the header file, and connecting its definitions to relevant Android concepts, we can arrive at a comprehensive and accurate explanation.
这是一个定义 Linux 内核中 netfilter 连接跟踪 (conntrack) 子系统与用户空间通信接口的头文件。它定义了一系列常量（枚举类型和宏），用于构建和解析通过 netlink 套接字发送的消息。这些消息允许用户空间的程序查询、创建、修改和删除连接跟踪条目以及相关的期望（expectations）。

**它的功能：**

1. **定义 Netlink 消息类型 (Message Types):**  定义了用于 conntrack 和 expectation 管理的不同类型的 netlink 消息，例如：
   - `IPCTNL_MSG_CT_NEW`: 创建新的连接跟踪条目。
   - `IPCTNL_MSG_CT_GET`: 获取现有的连接跟踪条目信息。
   - `IPCTNL_MSG_CT_DELETE`: 删除连接跟踪条目。
   - `IPCTNL_MSG_EXP_NEW`: 创建新的连接跟踪期望。
   - `IPCTNL_MSG_EXP_GET`: 获取现有的连接跟踪期望信息。
   - `IPCTNL_MSG_EXP_DELETE`: 删除连接跟踪期望。

2. **定义连接跟踪属性类型 (Connection Tracking Attribute Types):** 定义了连接跟踪条目和期望可以包含的各种属性，例如：
   - `CTA_TUPLE_ORIG`: 原始方向的连接五元组信息（源IP、目的IP、源端口、目的端口、协议）。
   - `CTA_TUPLE_REPLY`: 回复方向的连接五元组信息。
   - `CTA_STATUS`: 连接的状态信息（例如，ESTABLISHED, NEW, RELATED）。
   - `CTA_PROTOINFO`: 协议相关的附加信息（例如，TCP 状态，窗口缩放）。
   - `CTA_NAT_SRC`, `CTA_NAT_DST`: 网络地址转换 (NAT) 相关信息。
   - `CTA_TIMEOUT`: 连接的超时时间。
   - `CTA_MARK`, `CTA_MARK_MASK`: 连接的防火墙标记。
   - `CTA_COUNTERS_ORIG`, `CTA_COUNTERS_REPLY`: 原始和回复方向的数据包和字节计数。

3. **定义嵌套属性类型 (Nested Attribute Types):**  定义了更精细的属性结构，例如：
   - `ctattr_tuple`: 定义了五元组的组成部分（IP地址、协议）。
   - `ctattr_ip`: 定义了 IP 地址的类型（IPv4 源/目的，IPv6 源/目的）。
   - `ctattr_l4proto`: 定义了四层协议的细节（端口号，ICMP 类型/代码）。
   - `ctattr_protoinfo_tcp`, `ctattr_protoinfo_dccp`, `ctattr_protoinfo_sctp`: 定义了特定传输层协议的附加信息。

**与 Android 功能的关系及举例说明：**

连接跟踪是 Android 网络功能的核心组成部分，尤其是在以下方面：

* **防火墙 (Firewall):** Android 系统使用 `iptables` (或者更新版本的 `nftables`) 作为防火墙。连接跟踪允许防火墙实现**状态防火墙 (Stateful Firewall)** 的功能。状态防火墙能够根据连接的状态（例如，是否是已建立连接的回复包）来决定是否允许数据包通过。例如，当 Android 设备发起一个 HTTP 请求时，连接跟踪会记录这个连接，并且允许服务器返回的响应数据包通过防火墙，即使防火墙规则可能只允许从内部到外部的连接。

* **网络地址转换 (NAT):**  当 Android 设备作为热点或者进行网络共享时，它会执行 NAT。连接跟踪对于 NAT 的正常工作至关重要。它维护了内部网络地址和外部网络地址之间的映射关系，确保响应数据包能够正确地路由到内部设备。例如，当连接到 Android 热点的手机访问互联网时，Android 设备会使用其自身的 IP 地址作为源地址，并且记录下这个连接的信息，以便将互联网返回的数据包正确地转发给手机。

* **网络连接管理:**  Android 框架和服务使用连接跟踪信息来监控和管理网络连接。例如，`ConnectivityService` 可以使用连接跟踪信息来判断网络连接是否活跃，或者是否存在异常连接。

**libc 函数的功能及其实现：**

这个头文件本身**不包含任何 libc 函数的实现**。它只是定义了一些常量。这些常量会被其他的 C/C++ 代码使用，这些代码可能会链接到 libc 中的函数，例如：

* **`socket()`**: 创建一个 netlink 套接字，用于与内核的 netfilter 子系统通信。
* **`bind()`**: 将 netlink 套接字绑定到一个特定的协议族和地址。对于 conntrack，通常会绑定到 `NETLINK_NETFILTER` 协议族。
* **`sendto()`**: 通过 netlink 套接字向内核发送消息，例如创建、查询或删除连接跟踪条目的消息。
* **`recvfrom()`**: 通过 netlink 套接字接收来自内核的消息，例如连接跟踪条目的信息或操作结果。
* **`malloc()`, `free()`**: 用于分配和释放构建和解析 netlink 消息所需的内存。
* **`memcpy()`**: 用于复制 netlink 消息的数据。
* **字节序转换函数 (`htonl`, `ntohl`, `htons`, `ntohs`)**: 由于网络传输中使用大端字节序，而主机可能使用小端字节序，因此需要进行字节序转换。

**这些 libc 函数的实现细节非常复杂，涉及操作系统内核的底层操作和网络协议栈的实现。**  例如，`sendto()` 系统调用会触发内核的网络协议栈处理，将数据包封装成网络协议格式并发送到目标地址。 `recvfrom()` 系统调用则会等待接收来自网络的数据包，并将其传递给用户空间程序。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身不直接涉及 dynamic linker。然而，当包含这个头文件的 C/C++ 代码被编译成共享库 (`.so` 文件) 时，dynamic linker 会参与到链接过程中。

**SO 布局样本 (简化)：**

```
.so 文件名: libnetfilter_conntrack.so

Sections:
  .text:  // 包含可执行代码
    - 使用了 nfnetlink_conntrack.h 中定义的常量的函数
  .data:  // 包含已初始化的全局变量和静态变量
  .rodata: // 包含只读数据，例如字符串常量
  .bss:   // 包含未初始化的全局变量和静态变量
  .symtab: // 符号表，包含导出的和导入的符号
    - 例如: nfnl_open, nfnl_close, ... (可能是从 libnfnetlink.so 导入的函数)
  .strtab: // 字符串表，包含符号表中使用的字符串
  .rel.dyn: // 动态重定位表，指示需要在加载时进行重定位的符号
    - 例如: 指示需要从 libnfnetlink.so 中找到 nfnl_open 的地址
  .init:   // 初始化代码
  .fini:   // 终结代码
```

**链接的处理过程：**

1. **编译时链接:** 当编译链接器 (ld) 创建 `libnetfilter_conntrack.so` 时，如果代码中使用了与 netfilter conntrack 相关的函数（这些函数可能在另一个共享库，例如 `libnfnetlink.so` 中），链接器会在 `.symtab` 中记录对这些函数的引用，并在 `.rel.dyn` 中生成重定位条目。

2. **加载时链接 (Dynamic Linking):** 当 Android 系统加载一个依赖于 `libnetfilter_conntrack.so` 的进程或库时，dynamic linker (例如 `linker64` 或 `linker`) 会执行以下操作：
   - 加载 `libnetfilter_conntrack.so` 到内存中。
   - 解析 `libnetfilter_conntrack.so` 的 `.rel.dyn` 表。
   - 对于每个需要重定位的符号（例如 `nfnl_open`），dynamic linker 会查找提供该符号的共享库 (例如 `libnfnetlink.so`)。这通常通过查找其他已加载的共享库的符号表来完成。
   - 一旦找到符号的地址，dynamic linker 会更新 `libnetfilter_conntrack.so` 内存中的相应位置，将符号引用替换为实际的内存地址。这个过程称为符号解析 (Symbol Resolution)。

**逻辑推理 (假设输入与输出):**

假设有一个用户空间程序想要获取一个 TCP 连接的详细信息，其源 IP 为 192.168.1.100，目的 IP 为 8.8.8.8，源端口为 12345，目的端口为 80。

**假设输入:**

用户空间程序会构建一个 netlink 消息，其类型为 `IPCTNL_MSG_CT_GET`，并包含以下属性：

* `CTA_TUPLE_ORIG`:
    * `CTA_IP_V4_SRC`: 192.168.1.100
    * `CTA_IP_V4_DST`: 8.8.8.8
    * `CTA_PROTO_NUM`: IPPROTO_TCP
    * `CTA_PROTO_SRC_PORT`: 12345 (网络字节序)
    * `CTA_PROTO_DST_PORT`: 80 (网络字节序)

**预期输出:**

内核会回复一个 netlink 消息，包含类型为 `IPCTNL_MSG_CT_NEW` (如果连接存在) 或者错误消息。如果连接存在，消息会包含各种属性，例如：

* `CTA_TUPLE_ORIG`: (与输入相同)
* `CTA_TUPLE_REPLY`: 连接回复方向的五元组。
* `CTA_STATUS`: 连接状态 (例如 `CTA_STATUS_ESTABLISHED`).
* `CTA_TIMEOUT`: 连接的剩余超时时间。
* `CTA_COUNTERS_ORIG`: 原始方向的数据包和字节计数。
* `CTA_COUNTERS_REPLY`: 回复方向的数据包和字节计数。
* ... 其他可能的属性 ...

**用户或编程常见的使用错误：**

1. **字节序错误:**  Netlink 消息中的多字节字段（例如 IP 地址、端口号）需要使用网络字节序（大端）。用户程序如果使用主机字节序发送数据，内核可能无法正确解析。

   ```c
   // 错误示例：直接使用主机字节序
   struct nlmsghdr nlh;
   // ... 设置 nlh ...
   struct ctattr attr;
   attr.cta_type = CTA_PROTO_DST_PORT;
   uint16_t port = 80;
   memcpy(CTA_DATA(&attr), &port, sizeof(port)); // 潜在的字节序问题
   ```

   **正确做法：** 使用 `htons()` 函数将主机字节序转换为网络字节序。

   ```c
   uint16_t port = htons(80);
   memcpy(CTA_DATA(&attr), &port, sizeof(port));
   ```

2. **属性类型错误:**  使用了错误的属性类型代码。例如，尝试使用 `CTA_IP_V6_SRC` 来表示 IPv4 地址。

3. **消息结构错误:**  构建的 netlink 消息结构不正确，例如缺少必要的头部或属性，或者属性的长度字段不正确。

4. **权限不足:**  某些 conntrack 操作可能需要 root 权限。非特权进程可能无法执行这些操作。

5. **内核版本不兼容:**  这个头文件中定义的常量可能与特定内核版本相关。在不同的内核版本上使用可能导致不兼容问题。

**Android Framework 或 NDK 是如何一步步的到达这里的：**

1. **Android Framework (Java 层):**  Android Framework 中的某些网络管理功能可能会通过 JNI 调用到 Native 层代码。例如，`NetworkPolicyManager` 或 `ConnectivityService` 可能需要获取网络连接的状态信息。

2. **Native 代码 (C/C++):**  Native 代码 (通常是系统服务或库) 会使用标准的 Linux 网络 API，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()`，来与内核进行通信。

3. **Netlink 套接字:**  Native 代码会创建一个 `AF_NETLINK` 类型的套接字，并将其绑定到 `NETLINK_NETFILTER` 协议族。

4. **构建 Netlink 消息:**  Native 代码会根据需要构建符合 netfilter conntrack 协议的 netlink 消息。这涉及到使用 `nfnetlink_conntrack.h` 中定义的常量来设置消息类型和属性。例如，如果需要获取连接信息，会创建一个 `IPCTNL_MSG_CT_GET` 类型的消息，并填充相应的属性。

5. **发送 Netlink 消息:**  使用 `sendto()` 系统调用将构建好的 netlink 消息发送到内核。

6. **内核处理:**  内核的 netfilter 子系统会接收到 netlink 消息，并根据消息类型执行相应的操作，例如查找连接跟踪条目。

7. **内核回复:**  内核会将操作结果或请求的数据封装成一个 netlink 消息，并通过相同的 netlink 套接字发送回用户空间。

8. **接收 Netlink 消息:**  Native 代码使用 `recvfrom()` 系统调用接收来自内核的 netlink 消息。

9. **解析 Netlink 消息:**  Native 代码会解析接收到的 netlink 消息，提取出所需的信息，例如连接的状态、计数器等。这同样会用到 `nfnetlink_conntrack.h` 中定义的常量来识别不同的属性。

10. **传递回 Framework:**  Native 代码将获取到的信息通过 JNI 调用传递回 Android Framework 的 Java 层。

**Frida Hook 示例调试这些步骤：**

以下是一个使用 Frida Hook 示例来观察 Native 代码如何使用 `nfnetlink_conntrack.h` 中定义的常量的过程。假设我们想要观察一个进程发送 `IPCTNL_MSG_CT_GET` 消息到内核。

```javascript
// frida hook 脚本

const soName = "your_target_process"; // 替换为目标进程的名称或加载的库
const sendtoSymbol = "sendto"; // sendto 系统调用的符号

Interceptor.attach(Module.getExportByName(null, sendtoSymbol), {
  onEnter: function (args) {
    const sockfd = args[0].toInt32();
    const buf = args[1];
    const len = args[2].toInt32();
    const flags = args[3].toInt32();
    const dest_addr = args[4];
    const addrlen = args[5] ? args[5].toInt32() : 0;

    // 检查是否是 NETLINK 套接字
    const sockaddr_nl = dest_addr.readStructure('sockaddr_nl', 16);
    if (sockaddr_nl.nl_family == 18) { // AF_NETLINK = 18
      console.log("sendto called on NETLINK socket:", sockfd);
      console.log("Message Length:", len);

      // 尝试解析 Netlink 消息头部
      if (len >= 4) {
        const nlmsg_len = buf.readU32();
        const nlmsg_type = buf.add(4).readU16();
        const nlmsg_flags = buf.add(6).readU16();
        const nlmsg_seq = buf.add(8).readU32();
        const nlmsg_pid = buf.add(12).readU32();

        console.log("  Netlink Header:");
        console.log("    Length:", nlmsg_len);

        // 检查是否是 IPCTNL_MSG_CT_GET
        const IPCTNL_MSG_CT_GET = 1; // 从头文件中获取或定义
        if (nlmsg_type == IPCTNL_MSG_CT_GET) {
          console.log("    Type: IPCTNL_MSG_CT_GET (", nlmsg_type, ")");
          // 可以进一步解析消息体中的属性
          // ...
        } else {
          console.log("    Type:", nlmsg_type);
        }
        console.log("    Flags:", nlmsg_flags);
        console.log("    Sequence:", nlmsg_seq);
        console.log("    PID:", nlmsg_pid);
      }
    }
  },
});

// 定义 sockaddr_nl 结构体，Frida 需要知道结构体布局
const sockaddr_nl_layout = {
  nl_family: 'u16',
  nl_pad: 'u16',
  nl_pid: 'u32',
  nl_groups: 'u32'
};
Structure.add('sockaddr_nl', sockaddr_nl_layout);
```

**解释:**

1. **`Interceptor.attach`:**  Hook 了 `sendto` 系统调用。
2. **`onEnter`:**  在 `sendto` 调用之前执行。
3. **检查 `AF_NETLINK`:**  检查 `sendto` 的目标地址是否是 `AF_NETLINK` 套接字。
4. **解析 Netlink 头部:**  尝试读取和打印 Netlink 消息的头部信息，包括消息类型。
5. **检查 `IPCTNL_MSG_CT_GET`:**  如果消息类型是 `IPCTNL_MSG_CT_GET`，则进行相应的记录。
6. **`Structure.add`:**  定义了 `sockaddr_nl` 结构体的布局，以便 Frida 正确解析内存。

通过运行这个 Frida 脚本，你可以观察目标进程是否发送了类型为 `IPCTNL_MSG_CT_GET` 的 Netlink 消息，从而验证 Android Framework 或 NDK 如何使用这个头文件中定义的常量与内核进行交互。你可以根据需要扩展这个脚本来解析消息体中的具体属性，以了解传递的具体连接信息。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter/nfnetlink_conntrack.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _IPCONNTRACK_NETLINK_H
#define _IPCONNTRACK_NETLINK_H
#include <linux/netfilter/nfnetlink.h>
enum cntl_msg_types {
  IPCTNL_MSG_CT_NEW,
  IPCTNL_MSG_CT_GET,
  IPCTNL_MSG_CT_DELETE,
  IPCTNL_MSG_CT_GET_CTRZERO,
  IPCTNL_MSG_CT_GET_STATS_CPU,
  IPCTNL_MSG_CT_GET_STATS,
  IPCTNL_MSG_CT_GET_DYING,
  IPCTNL_MSG_CT_GET_UNCONFIRMED,
  IPCTNL_MSG_MAX
};
enum ctnl_exp_msg_types {
  IPCTNL_MSG_EXP_NEW,
  IPCTNL_MSG_EXP_GET,
  IPCTNL_MSG_EXP_DELETE,
  IPCTNL_MSG_EXP_GET_STATS_CPU,
  IPCTNL_MSG_EXP_MAX
};
enum ctattr_type {
  CTA_UNSPEC,
  CTA_TUPLE_ORIG,
  CTA_TUPLE_REPLY,
  CTA_STATUS,
  CTA_PROTOINFO,
  CTA_HELP,
  CTA_NAT_SRC,
#define CTA_NAT CTA_NAT_SRC
  CTA_TIMEOUT,
  CTA_MARK,
  CTA_COUNTERS_ORIG,
  CTA_COUNTERS_REPLY,
  CTA_USE,
  CTA_ID,
  CTA_NAT_DST,
  CTA_TUPLE_MASTER,
  CTA_SEQ_ADJ_ORIG,
  CTA_NAT_SEQ_ADJ_ORIG = CTA_SEQ_ADJ_ORIG,
  CTA_SEQ_ADJ_REPLY,
  CTA_NAT_SEQ_ADJ_REPLY = CTA_SEQ_ADJ_REPLY,
  CTA_SECMARK,
  CTA_ZONE,
  CTA_SECCTX,
  CTA_TIMESTAMP,
  CTA_MARK_MASK,
  CTA_LABELS,
  CTA_LABELS_MASK,
  CTA_SYNPROXY,
  CTA_FILTER,
  CTA_STATUS_MASK,
  __CTA_MAX
};
#define CTA_MAX (__CTA_MAX - 1)
enum ctattr_tuple {
  CTA_TUPLE_UNSPEC,
  CTA_TUPLE_IP,
  CTA_TUPLE_PROTO,
  CTA_TUPLE_ZONE,
  __CTA_TUPLE_MAX
};
#define CTA_TUPLE_MAX (__CTA_TUPLE_MAX - 1)
enum ctattr_ip {
  CTA_IP_UNSPEC,
  CTA_IP_V4_SRC,
  CTA_IP_V4_DST,
  CTA_IP_V6_SRC,
  CTA_IP_V6_DST,
  __CTA_IP_MAX
};
#define CTA_IP_MAX (__CTA_IP_MAX - 1)
enum ctattr_l4proto {
  CTA_PROTO_UNSPEC,
  CTA_PROTO_NUM,
  CTA_PROTO_SRC_PORT,
  CTA_PROTO_DST_PORT,
  CTA_PROTO_ICMP_ID,
  CTA_PROTO_ICMP_TYPE,
  CTA_PROTO_ICMP_CODE,
  CTA_PROTO_ICMPV6_ID,
  CTA_PROTO_ICMPV6_TYPE,
  CTA_PROTO_ICMPV6_CODE,
  __CTA_PROTO_MAX
};
#define CTA_PROTO_MAX (__CTA_PROTO_MAX - 1)
enum ctattr_protoinfo {
  CTA_PROTOINFO_UNSPEC,
  CTA_PROTOINFO_TCP,
  CTA_PROTOINFO_DCCP,
  CTA_PROTOINFO_SCTP,
  __CTA_PROTOINFO_MAX
};
#define CTA_PROTOINFO_MAX (__CTA_PROTOINFO_MAX - 1)
enum ctattr_protoinfo_tcp {
  CTA_PROTOINFO_TCP_UNSPEC,
  CTA_PROTOINFO_TCP_STATE,
  CTA_PROTOINFO_TCP_WSCALE_ORIGINAL,
  CTA_PROTOINFO_TCP_WSCALE_REPLY,
  CTA_PROTOINFO_TCP_FLAGS_ORIGINAL,
  CTA_PROTOINFO_TCP_FLAGS_REPLY,
  __CTA_PROTOINFO_TCP_MAX
};
#define CTA_PROTOINFO_TCP_MAX (__CTA_PROTOINFO_TCP_MAX - 1)
enum ctattr_protoinfo_dccp {
  CTA_PROTOINFO_DCCP_UNSPEC,
  CTA_PROTOINFO_DCCP_STATE,
  CTA_PROTOINFO_DCCP_ROLE,
  CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ,
  CTA_PROTOINFO_DCCP_PAD,
  __CTA_PROTOINFO_DCCP_MAX,
};
#define CTA_PROTOINFO_DCCP_MAX (__CTA_PROTOINFO_DCCP_MAX - 1)
enum ctattr_protoinfo_sctp {
  CTA_PROTOINFO_SCTP_UNSPEC,
  CTA_PROTOINFO_SCTP_STATE,
  CTA_PROTOINFO_SCTP_VTAG_ORIGINAL,
  CTA_PROTOINFO_SCTP_VTAG_REPLY,
  __CTA_PROTOINFO_SCTP_MAX
};
#define CTA_PROTOINFO_SCTP_MAX (__CTA_PROTOINFO_SCTP_MAX - 1)
enum ctattr_counters {
  CTA_COUNTERS_UNSPEC,
  CTA_COUNTERS_PACKETS,
  CTA_COUNTERS_BYTES,
  CTA_COUNTERS32_PACKETS,
  CTA_COUNTERS32_BYTES,
  CTA_COUNTERS_PAD,
  __CTA_COUNTERS_MAX
};
#define CTA_COUNTERS_MAX (__CTA_COUNTERS_MAX - 1)
enum ctattr_tstamp {
  CTA_TIMESTAMP_UNSPEC,
  CTA_TIMESTAMP_START,
  CTA_TIMESTAMP_STOP,
  CTA_TIMESTAMP_PAD,
  __CTA_TIMESTAMP_MAX
};
#define CTA_TIMESTAMP_MAX (__CTA_TIMESTAMP_MAX - 1)
enum ctattr_nat {
  CTA_NAT_UNSPEC,
  CTA_NAT_V4_MINIP,
#define CTA_NAT_MINIP CTA_NAT_V4_MINIP
  CTA_NAT_V4_MAXIP,
#define CTA_NAT_MAXIP CTA_NAT_V4_MAXIP
  CTA_NAT_PROTO,
  CTA_NAT_V6_MINIP,
  CTA_NAT_V6_MAXIP,
  __CTA_NAT_MAX
};
#define CTA_NAT_MAX (__CTA_NAT_MAX - 1)
enum ctattr_protonat {
  CTA_PROTONAT_UNSPEC,
  CTA_PROTONAT_PORT_MIN,
  CTA_PROTONAT_PORT_MAX,
  __CTA_PROTONAT_MAX
};
#define CTA_PROTONAT_MAX (__CTA_PROTONAT_MAX - 1)
enum ctattr_seqadj {
  CTA_SEQADJ_UNSPEC,
  CTA_SEQADJ_CORRECTION_POS,
  CTA_SEQADJ_OFFSET_BEFORE,
  CTA_SEQADJ_OFFSET_AFTER,
  __CTA_SEQADJ_MAX
};
#define CTA_SEQADJ_MAX (__CTA_SEQADJ_MAX - 1)
enum ctattr_natseq {
  CTA_NAT_SEQ_UNSPEC,
  CTA_NAT_SEQ_CORRECTION_POS,
  CTA_NAT_SEQ_OFFSET_BEFORE,
  CTA_NAT_SEQ_OFFSET_AFTER,
  __CTA_NAT_SEQ_MAX
};
#define CTA_NAT_SEQ_MAX (__CTA_NAT_SEQ_MAX - 1)
enum ctattr_synproxy {
  CTA_SYNPROXY_UNSPEC,
  CTA_SYNPROXY_ISN,
  CTA_SYNPROXY_ITS,
  CTA_SYNPROXY_TSOFF,
  __CTA_SYNPROXY_MAX,
};
#define CTA_SYNPROXY_MAX (__CTA_SYNPROXY_MAX - 1)
enum ctattr_expect {
  CTA_EXPECT_UNSPEC,
  CTA_EXPECT_MASTER,
  CTA_EXPECT_TUPLE,
  CTA_EXPECT_MASK,
  CTA_EXPECT_TIMEOUT,
  CTA_EXPECT_ID,
  CTA_EXPECT_HELP_NAME,
  CTA_EXPECT_ZONE,
  CTA_EXPECT_FLAGS,
  CTA_EXPECT_CLASS,
  CTA_EXPECT_NAT,
  CTA_EXPECT_FN,
  __CTA_EXPECT_MAX
};
#define CTA_EXPECT_MAX (__CTA_EXPECT_MAX - 1)
enum ctattr_expect_nat {
  CTA_EXPECT_NAT_UNSPEC,
  CTA_EXPECT_NAT_DIR,
  CTA_EXPECT_NAT_TUPLE,
  __CTA_EXPECT_NAT_MAX
};
#define CTA_EXPECT_NAT_MAX (__CTA_EXPECT_NAT_MAX - 1)
enum ctattr_help {
  CTA_HELP_UNSPEC,
  CTA_HELP_NAME,
  CTA_HELP_INFO,
  __CTA_HELP_MAX
};
#define CTA_HELP_MAX (__CTA_HELP_MAX - 1)
enum ctattr_secctx {
  CTA_SECCTX_UNSPEC,
  CTA_SECCTX_NAME,
  __CTA_SECCTX_MAX
};
#define CTA_SECCTX_MAX (__CTA_SECCTX_MAX - 1)
enum ctattr_stats_cpu {
  CTA_STATS_UNSPEC,
  CTA_STATS_SEARCHED,
  CTA_STATS_FOUND,
  CTA_STATS_NEW,
  CTA_STATS_INVALID,
  CTA_STATS_IGNORE,
  CTA_STATS_DELETE,
  CTA_STATS_DELETE_LIST,
  CTA_STATS_INSERT,
  CTA_STATS_INSERT_FAILED,
  CTA_STATS_DROP,
  CTA_STATS_EARLY_DROP,
  CTA_STATS_ERROR,
  CTA_STATS_SEARCH_RESTART,
  CTA_STATS_CLASH_RESOLVE,
  CTA_STATS_CHAIN_TOOLONG,
  __CTA_STATS_MAX,
};
#define CTA_STATS_MAX (__CTA_STATS_MAX - 1)
enum ctattr_stats_global {
  CTA_STATS_GLOBAL_UNSPEC,
  CTA_STATS_GLOBAL_ENTRIES,
  CTA_STATS_GLOBAL_MAX_ENTRIES,
  __CTA_STATS_GLOBAL_MAX,
};
#define CTA_STATS_GLOBAL_MAX (__CTA_STATS_GLOBAL_MAX - 1)
enum ctattr_expect_stats {
  CTA_STATS_EXP_UNSPEC,
  CTA_STATS_EXP_NEW,
  CTA_STATS_EXP_CREATE,
  CTA_STATS_EXP_DELETE,
  __CTA_STATS_EXP_MAX,
};
#define CTA_STATS_EXP_MAX (__CTA_STATS_EXP_MAX - 1)
enum ctattr_filter {
  CTA_FILTER_UNSPEC,
  CTA_FILTER_ORIG_FLAGS,
  CTA_FILTER_REPLY_FLAGS,
  __CTA_FILTER_MAX
};
#define CTA_FILTER_MAX (__CTA_FILTER_MAX - 1)
#endif

"""

```