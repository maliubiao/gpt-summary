Response:
Let's break down the thought process for analyzing the provided C header file.

**1. Initial Understanding & Context:**

* **Identify the language:**  It's a C header file (`.h`).
* **Locate the directory:**  `bionic/libc/kernel/uapi/linux/netfilter/nfnetlink_log.h` points to a Linux kernel userspace API (uapi) related to network filtering (`netfilter`) and logging (`nfnetlink_log`). The `bionic` prefix indicates it's used within Android's libc.
* **Purpose of header files:** Header files define data structures, enums, and macros. They act as interfaces for accessing kernel functionality from user space.
* **Keywords:** `netfilter`, `nfnetlink`, `log` are the crucial terms suggesting this relates to how network packets are processed and logged by the Linux kernel's firewall.

**2. Deconstructing the Code (Top-Down):**

* **Include Guard:** `#ifndef _NFNETLINK_LOG_H ... #define _NFNETLINK_LOG_H ... #endif`  This is standard practice to prevent multiple inclusions of the header file, which can cause compilation errors. No specific functionality to explain here, but important to recognize.
* **Include:** `#include <linux/types.h>` and `#include <linux/netfilter/nfnetlink.h>`: These lines indicate dependencies on other kernel header files. This tells us that the current file builds upon the foundation provided by these included headers. We don't need to analyze their contents here unless explicitly asked, but we acknowledge their importance.
* **Enums:**  These define sets of named integer constants. They are key to understanding the different message types, attributes, and configuration commands. For each enum:
    * **Name:** Understand what the name suggests (e.g., `nfulnl_msg_types` clearly relates to message types).
    * **Members:** Analyze each member and its potential meaning. For instance, `NFULNL_MSG_PACKET` likely represents a log message about a network packet. `NFULNL_CFG_CMD_BIND` suggests binding to a logging facility.
    * **`_MAX` and `#define ... MAX`:**  This pattern is a common way in C to define the upper bound for an enum, often used for array sizing or validation.
* **Structs:** These define data structures for organizing related data. For each struct:
    * **Name:** Understand the purpose indicated by the name (e.g., `nfulnl_msg_packet_hdr` is likely the header for a packet log message).
    * **Members:** Analyze each member's type and name to infer its role. For example, `__be16 hw_protocol` suggests the hardware protocol (likely in network byte order), `__u8 hook` probably indicates the Netfilter hook point where the packet was intercepted. Note the `__be` prefix often signifies "big-endian."
    * **`__attribute__((packed))`:** This attribute tells the compiler to avoid padding within the struct, ensuring the layout matches the on-the-wire representation of the data. This is crucial for network protocols.
* **Macros:**  `#define` creates symbolic constants.
    * **Purpose:**  Understand what the macro represents. For example, `NFULNL_COPY_NONE` indicates no data copying, while `NFULNL_CFG_F_SEQ` represents a flag for sequence numbering.

**3. Connecting to Android and Functionality:**

* **Android's Network Stack:**  Realize that Android's network stack relies on the Linux kernel's networking capabilities, including Netfilter. This header file is directly relevant to how Android interacts with Netfilter's logging mechanism.
* **Logging of Network Events:** The file clearly defines structures and enums related to logging network packets. This implies Android can use these structures to receive information about network traffic that matches certain firewall rules.
* **Configuration:** The `nfulnl_msg_config_*` structures and `NFULNL_CFG_*` enums suggest that Android (or applications running on Android with appropriate permissions) can configure the Netfilter logging behavior.

**4. Addressing Specific Requirements of the Prompt:**

* **Functionality Listing:**  Summarize the identified functionalities (logging packet information, configuring logging).
* **Android Relevance & Examples:** Connect the concepts to concrete Android scenarios like firewall apps, VPNs, network monitoring tools, and potentially even the core Android system's network management.
* **libc Function Implementation:**  Crucially, *this header file doesn't define libc functions*. It defines *kernel data structures and constants*. This is a key distinction. The *usage* of these structures might involve libc functions (like `socket`, `sendto`, `recvfrom`), but this file itself is purely declarative. It's important to point this out.
* **Dynamic Linker:** This header file has *no direct relation* to the dynamic linker. Dynamic linking happens at the user-space level to load shared libraries. This header defines kernel structures. Again, it's important to clarify this.
* **Logical Deduction:**  The deduction is primarily based on understanding the names and types within the structures and enums. The assumptions are based on general knowledge of networking and kernel APIs.
* **Common Errors:**  Focus on the potential for misinterpreting the bit flags or incorrect handling of network byte order.
* **Android Framework/NDK Path:** Explain the general flow: an Android app uses Java APIs, which might call native code (NDK), which in turn uses system calls that interact with the kernel's Netfilter subsystem.
* **Frida Hooking:** Provide examples of how Frida could be used to intercept and examine the data structures defined in this header file as they are exchanged between user space and the kernel.

**5. Structuring the Output:**

* Use clear headings and bullet points for readability.
* Explain technical terms.
* Provide concrete examples.
* Be precise about what the header file *does* and *doesn't* do. Avoid overreaching in the analysis.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file defines some specific libc wrappers for Netfilter logging.
* **Correction:**  Looking closer, it's pure kernel uAPI. The libc functions would be in other parts of the bionic library, potentially wrapping the `netlink` socket interface. Focus on what's actually in the file.
* **Initial thought:** Detail every bit and byte of the structures.
* **Refinement:**  Focus on the high-level purpose and meaning of the members. Detailed bit-level analysis is only needed if specifically requested or if there's a particularly subtle aspect.
* **Ensure accurate terminology:**  Use "kernel space," "user space," "system call," "Netlink socket" correctly.

By following these steps, the detailed and accurate analysis provided in the initial example can be constructed. The key is to systematically break down the code, understand the context, and address each part of the prompt explicitly.
这个C头文件 `bionic/libc/kernel/uapi/linux/netfilter/nfnetlink_log.h` 定义了与 Linux 内核 Netfilter 日志功能（通过 Netlink 接口）相关的用户空间 API。它描述了用于在用户空间程序和内核 Netfilter 日志模块之间通信的数据结构和常量。

**功能列举:**

1. **定义 Netlink 消息类型 (enum `nfulnl_msg_types`):**
   - `NFULNL_MSG_PACKET`:  表示一个关于网络数据包的日志消息。
   - `NFULNL_MSG_CONFIG`: 表示一个配置 Netfilter 日志的消息。

2. **定义数据包日志消息结构体 (`struct nfulnl_msg_packet_hdr`, `struct nfulnl_msg_packet_hw`, `struct nfulnl_msg_packet_timestamp`):**
   - `nfulnl_msg_packet_hdr`: 包含数据包的基本信息，如硬件协议类型和 Netfilter hook 点。
   - `nfulnl_msg_packet_hw`:  包含硬件地址信息。
   - `nfulnl_msg_packet_timestamp`: 包含数据包捕获的时间戳。

3. **定义 VLAN 属性枚举 (enum `nfulnl_vlan_attr`):** 用于描述 VLAN 相关的属性。

4. **定义数据包日志消息的属性类型枚举 (enum `nfulnl_attr_type`):**  列出了可以包含在数据包日志消息中的各种属性，例如：
   - `NFULA_PACKET_HDR`: 数据包头信息。
   - `NFULA_MARK`:  与数据包关联的 iptables MARK 值。
   - `NFULA_TIMESTAMP`:  时间戳。
   - `NFULA_IFINDEX_INDEV`:  入接口索引。
   - `NFULA_IFINDEX_OUTDEV`: 出接口索引。
   - `NFULA_HWADDR`:  硬件地址。
   - `NFULA_PAYLOAD`:  数据包负载。
   - `NFULA_UID`:  发起数据包的进程的用户 ID。
   - `NFULA_GID`:  发起数据包的进程的组 ID。
   - `NFULA_CT`:  连接跟踪信息。

5. **定义配置消息命令枚举 (enum `nfulnl_msg_config_cmds`):**  定义了可以发送给 Netfilter 日志模块的配置命令，例如：
   - `NFULNL_CFG_CMD_BIND`: 绑定到特定的协议族进行日志记录。
   - `NFULNL_CFG_CMD_UNBIND`: 解绑。

6. **定义配置消息命令结构体 (`struct nfulnl_msg_config_cmd`):** 包含配置命令。

7. **定义配置模式结构体 (`struct nfulnl_msg_config_mode`):**  定义了日志记录的模式，例如复制的数据范围和模式。

8. **定义配置属性枚举 (enum `nfulnl_attr_config`):** 列出了可以包含在配置消息中的各种属性，例如：
   - `NFULA_CFG_CMD`: 配置命令。
   - `NFULA_CFG_MODE`: 配置模式。
   - `NFULA_CFG_NLBUFSIZ`:  Netlink 缓冲区大小。
   - `NFULA_CFG_TIMEOUT`:  超时时间。
   - `NFULA_CFG_FLAGS`:  配置标志。

9. **定义配置标志宏 (`NFULNL_CFG_F_SEQ`, `NFULNL_CFG_F_SEQ_GLOBAL`, `NFULNL_CFG_F_CONNTRACK`):**  用于设置配置标志，例如启用序列号、全局序列号或连接跟踪信息。

**与 Android 功能的关系及举例:**

这个头文件对于 Android 的网络功能至关重要，因为它定义了用户空间程序如何与内核的防火墙（Netfilter）日志系统交互。Android 使用 Netfilter 作为其核心防火墙机制。

**举例说明:**

* **防火墙应用 (e.g., NoRoot Firewall):**  这类应用可能需要监听网络连接尝试并记录日志。它们会使用 Netlink 套接字，并使用这里定义的结构体来接收内核发出的日志消息。例如，当一个应用尝试建立新的 TCP 连接时，内核的 Netfilter 模块可能会生成一个 `NFULNL_MSG_PACKET` 类型的消息，包含源 IP、目标 IP、端口号等信息，防火墙应用解析这些信息并根据用户的规则进行处理。
* **VPN 应用:** VPN 应用在建立连接或路由数据包时，可能会涉及到 Netfilter 规则的配置。 它们可以使用 Netlink 套接字发送 `NFULNL_MSG_CONFIG` 类型的消息来配置 Netfilter 日志，以便监控特定的网络流量。
* **网络监控工具:**  Android 系统或开发者可能使用网络监控工具来分析网络流量。这些工具会使用 Netlink 接口接收 Netfilter 的日志，了解哪些数据包被允许、拒绝或修改。

**详细解释 libc 函数的功能是如何实现的:**

**这个头文件本身并没有定义任何 libc 函数。** 它定义的是内核数据结构和常量。  用户空间的程序（包括 Android 上的应用和系统服务）会使用标准的 libc 函数，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等，来与内核的 Netfilter 日志模块进行通信。

具体来说，与 Netfilter 日志交互通常涉及以下步骤和 libc 函数：

1. **创建 Netlink 套接字:** 使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` 创建一个用于与 Netfilter 通信的套接字。 `AF_NETLINK` 表明是 Netlink 协议族，`NETLINK_NETFILTER` 表明是用于 Netfilter 子系统的 Netlink 协议。

2. **绑定套接字:** 使用 `bind()` 将套接字绑定到特定的 Netlink 地址。Netlink 地址结构体 `struct sockaddr_nl` 需要设置 `nl_family` 为 `AF_NETLINK`，`nl_pid` 通常设置为当前进程的 PID，`nl_groups` 可以用来订阅特定的 Netfilter 日志组。

3. **发送配置消息:** 如果需要配置 Netfilter 日志，程序会构建一个包含 `nfulnl_msg_config_cmd` 和 `nfulnl_msg_config_mode` 结构体的 Netlink 消息，并使用 `sendto()` 发送到内核。消息的头部需要包含 Netlink 消息头 (`struct nlmsghdr`)。

4. **接收日志消息:** 内核 Netfilter 模块会将匹配日志规则的数据包信息封装成包含 `nfulnl_msg_packet_hdr` 和各种 `NFULA_*` 属性的 Netlink 消息，并通过 Netlink 套接字发送到用户空间程序。程序使用 `recvfrom()` 接收这些消息。

5. **解析日志消息:** 接收到的 Netlink 消息需要根据其头部信息进行解析，提取出 `nfulnl_msg_packet_hdr` 和后续的属性信息。开发者需要根据 `nfulnl_attr_type` 来解析不同类型的属性数据。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件与 dynamic linker 没有直接关系。** Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 负责在程序运行时加载和链接共享库 (`.so` 文件)。这个头文件定义的是内核 API，用户空间的程序会通过系统调用与内核交互，而不是通过动态链接到包含这些定义的共享库。

虽然如此，如果一个用户空间的共享库 (例如，一个实现了网络监控功能的库) 使用了与 Netfilter 日志相关的系统调用，那么这个库本身会被 dynamic linker 加载。

**so 布局样本 (假设一个名为 `libnetfilter_monitor.so` 的库):**

```
libnetfilter_monitor.so:
    .text      # 代码段，包含实现网络监控逻辑的函数
    .data      # 初始化数据
    .bss       # 未初始化数据
    .rodata    # 只读数据
    .dynamic   # 动态链接信息
    .dynsym    # 动态符号表
    .dynstr    # 动态字符串表
    .rel.dyn   # 动态重定位表
    .rel.plt   # PLT 重定位表
```

**链接的处理过程:**

1. **加载:** 当一个 Android 应用或进程加载 `libnetfilter_monitor.so` 时，dynamic linker 会将其加载到内存中的合适位置。

2. **符号查找:**  如果 `libnetfilter_monitor.so` 调用了需要内核支持的函数（例如，通过 `syscall()` 直接调用 `socket()`），那么这些符号不需要在其他共享库中查找，因为它们是内核提供的。

3. **重定位:** Dynamic linker 会根据 `.rel.dyn` 和 `.rel.plt` 中的信息，调整 `libnetfilter_monitor.so` 中需要重定位的地址，例如全局变量的地址或函数地址。

**逻辑推理与假设输入输出:**

**假设输入:**  一个用户空间程序（例如一个网络监控应用）想要监听所有进入的网络数据包的日志。

**操作步骤:**

1. **创建 Netlink 套接字:** 使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)`.
2. **绑定套接字:** 绑定到 Netfilter 的日志组 (例如，可以绑定到所有组，或者特定的组)。
3. **发送配置消息 (可选):**  可以发送 `NFULNL_CFG_CMD_BIND` 消息来绑定到特定的协议族 (例如 `AF_INET` 或 `AF_INET6`)。可以设置 `NFULA_CFG_MODE` 为 `NFULNL_COPY_PACKET` 来获取完整的数据包负载。
4. **接收消息:**  循环使用 `recvfrom()` 接收来自内核的 Netlink 消息。

**假设输出 (接收到的一个日志消息):**

接收到的 Netlink 消息的有效载荷可能包含以下结构（简化）：

```
struct nlmsghdr {
    __u32         nlmsg_len;    // 消息总长度
    __u16         nlmsg_type;   // 消息类型 (NFULNL_MSG_PACKET)
    __u16         nlmsg_flags;
    __u32         nlmsg_seq;
    __u32         nlmsg_pid;
};

struct nfgenmsg {
    __u8          nfgen_family; // 例如 AF_INET
    __u8          version;      // NFNETLINK_V0
    __be16        res_id;
};

struct nfulnl_msg_packet_hdr {
    __be16        hw_protocol;  // 例如 htons(ETH_P_IP)
    __u8          hook;         // Netfilter hook 点 (例如 NF_INET_PRE_ROUTING)
    __u8          _pad;
};

// 可能包含的属性 (根据配置):
struct nlattr {
    __u16         nla_len;      // 属性长度
    __u16         nla_type;     // 属性类型 (例如 NFULA_PAYLOAD)
};
// ... 属性数据 ... (例如，原始数据包数据)

struct nlattr {
    __u16         nla_len;
    __u16         nla_type;     // 例如 NFULA_IFINDEX_INDEV
};
__s32           ifindex_in;   // 入接口索引
```

**用户或编程常见的使用错误:**

1. **未正确处理网络字节序:**  像 `hw_protocol` 这样的字段是网络字节序 (`__be16`)，用户空间程序需要使用 `ntohs()` 等函数将其转换为主机字节序。
2. **错误解析 Netlink 消息:**  Netlink 消息的格式比较复杂，需要正确解析 `nlmsghdr` 和 `nlattr` 结构体才能提取出有用的信息。容易出现长度计算错误或类型判断错误。
3. **权限问题:**  监听 Netfilter 日志通常需要 root 权限或具有 `CAP_NET_ADMIN` 能力。普通应用可能无法成功创建或绑定 Netlink 套接字。
4. **缓冲区溢出:**  在接收 Netlink 消息时，需要分配足够的缓冲区来存储可能到来的数据，否则可能导致缓冲区溢出。
5. **忘记处理错误:**  与内核交互可能会失败，例如 `socket()` 或 `bind()` 调用可能返回错误，程序需要检查并处理这些错误。
6. **不正确的配置:** 发送错误的配置消息可能导致 Netfilter 日志无法正常工作或产生意想不到的结果。例如，设置了错误的复制模式或标志。

**Android framework or ndk 是如何一步步的到达这里:**

1. **Android Framework (Java):**  Android Framework 层的网络功能通常通过 Java API 提供，例如 `ConnectivityManager`, `NetworkPolicyManager`, `VpnService` 等。

2. **Native Code (NDK):**  这些 Java API 的底层实现通常会调用 Native 代码（C/C++），这些 Native 代码可能会使用 NDK 提供的接口与 Linux 内核进行交互。

3. **System Calls:**  NDK 代码最终会通过系统调用与内核通信。对于 Netfilter 日志，相关的系统调用是 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等，用于操作 Netlink 套接字。

4. **内核 Netfilter 子系统:**  当用户空间的程序通过 Netlink 套接字发送或接收消息时，内核的 Netfilter 子系统会处理这些消息。内核会根据配置的规则，将匹配的数据包信息发送到通过 Netlink 监听的套接字。

**Frida Hook 示例调试这些步骤:**

以下是一个使用 Frida Hook 拦截 `recvfrom` 系统调用，查看 Netfilter 日志消息的示例：

```javascript
// attach 到目标进程
const targetProcess = "com.example.firewallapp"; // 替换为目标应用的进程名
const session = Frida.attach(targetProcess);

// 获取 recvfrom 的地址
const recvfromPtr = Module.findExportByName(null, "recvfrom");

if (recvfromPtr) {
  Interceptor.attach(recvfromPtr, {
    onEnter: function (args) {
      // args[0] 是 socket fd
      // args[1] 是接收缓冲区的指针
      // args[2] 是缓冲区的大小
      this.bufPtr = ptr(args[1]);
      this.bufSize = args[2].toInt();
      console.log("recvfrom called, fd:", args[0], "bufSize:", this.bufSize);
    },
    onLeave: function (retval) {
      const bytesReceived = retval.toInt();
      if (bytesReceived > 0) {
        console.log("recvfrom returned:", bytesReceived, "bytes");
        const receivedData = this.bufPtr.readByteArray(bytesReceived);
        console.log("Received data (hex):", hexdump(receivedData, { ansi: true }));

        // 尝试解析 Netlink 消息头
        const nlmsghdrSize = 16; // sizeof(struct nlmsghdr)
        if (bytesReceived >= nlmsghdrSize) {
          const nlmsg_len = this.bufPtr.readU32();
          const nlmsg_type = this.bufPtr.add(4).readU16();

          console.log("  nlmsg_len:", nlmsg_len);
          console.log("  nlmsg_type:", nlmsg_type);

          // 如果是 NFULNL_MSG_PACKET，可以进一步解析
          const NFULNL_MSG_PACKET = 0; // 假设 NFULNL_MSG_PACKET 的值为 0
          if (nlmsg_type === NFULNL_MSG_PACKET) {
            console.log("  Detected NFULNL_MSG_PACKET");
            // 可以继续解析 nfgenmsg, nfulnl_msg_packet_hdr 和后续的属性
          }
        }
      }
    },
  });
} else {
  console.error("Failed to find recvfrom");
}
```

**解释 Frida Hook 示例:**

1. **`Frida.attach(targetProcess)`:**  将 Frida 连接到目标 Android 应用的进程。
2. **`Module.findExportByName(null, "recvfrom")`:**  查找 `recvfrom` 函数在内存中的地址。`null` 表示在所有已加载的模块中搜索。
3. **`Interceptor.attach(...)`:**  拦截 `recvfrom` 函数的调用。
4. **`onEnter`:** 在 `recvfrom` 函数执行之前调用。这里记录了文件描述符和缓冲区大小。
5. **`onLeave`:** 在 `recvfrom` 函数执行之后调用。这里获取了接收到的字节数，读取缓冲区的内容，并尝试解析 Netlink 消息头。
6. **解析 Netlink 消息头:**  读取消息长度和类型，并判断是否为 `NFULNL_MSG_PACKET` 类型的日志消息。

通过这个 Frida Hook 示例，你可以观察到 Android 应用在接收 Netfilter 日志消息时，`recvfrom` 系统调用的参数和返回值，以及接收到的原始数据，从而帮助调试和理解 Netfilter 日志的交互过程。 你需要根据实际情况调整 `NFULNL_MSG_PACKET` 的值，可以通过查看内核头文件或者实际运行中观察到。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter/nfnetlink_log.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _NFNETLINK_LOG_H
#define _NFNETLINK_LOG_H
#include <linux/types.h>
#include <linux/netfilter/nfnetlink.h>
enum nfulnl_msg_types {
  NFULNL_MSG_PACKET,
  NFULNL_MSG_CONFIG,
  NFULNL_MSG_MAX
};
struct nfulnl_msg_packet_hdr {
  __be16 hw_protocol;
  __u8 hook;
  __u8 _pad;
};
struct nfulnl_msg_packet_hw {
  __be16 hw_addrlen;
  __u16 _pad;
  __u8 hw_addr[8];
};
struct nfulnl_msg_packet_timestamp {
  __aligned_be64 sec;
  __aligned_be64 usec;
};
enum nfulnl_vlan_attr {
  NFULA_VLAN_UNSPEC,
  NFULA_VLAN_PROTO,
  NFULA_VLAN_TCI,
  __NFULA_VLAN_MAX,
};
#define NFULA_VLAN_MAX (__NFULA_VLAN_MAX + 1)
enum nfulnl_attr_type {
  NFULA_UNSPEC,
  NFULA_PACKET_HDR,
  NFULA_MARK,
  NFULA_TIMESTAMP,
  NFULA_IFINDEX_INDEV,
  NFULA_IFINDEX_OUTDEV,
  NFULA_IFINDEX_PHYSINDEV,
  NFULA_IFINDEX_PHYSOUTDEV,
  NFULA_HWADDR,
  NFULA_PAYLOAD,
  NFULA_PREFIX,
  NFULA_UID,
  NFULA_SEQ,
  NFULA_SEQ_GLOBAL,
  NFULA_GID,
  NFULA_HWTYPE,
  NFULA_HWHEADER,
  NFULA_HWLEN,
  NFULA_CT,
  NFULA_CT_INFO,
  NFULA_VLAN,
  NFULA_L2HDR,
  __NFULA_MAX
};
#define NFULA_MAX (__NFULA_MAX - 1)
enum nfulnl_msg_config_cmds {
  NFULNL_CFG_CMD_NONE,
  NFULNL_CFG_CMD_BIND,
  NFULNL_CFG_CMD_UNBIND,
  NFULNL_CFG_CMD_PF_BIND,
  NFULNL_CFG_CMD_PF_UNBIND,
};
struct nfulnl_msg_config_cmd {
  __u8 command;
} __attribute__((packed));
struct nfulnl_msg_config_mode {
  __be32 copy_range;
  __u8 copy_mode;
  __u8 _pad;
} __attribute__((packed));
enum nfulnl_attr_config {
  NFULA_CFG_UNSPEC,
  NFULA_CFG_CMD,
  NFULA_CFG_MODE,
  NFULA_CFG_NLBUFSIZ,
  NFULA_CFG_TIMEOUT,
  NFULA_CFG_QTHRESH,
  NFULA_CFG_FLAGS,
  __NFULA_CFG_MAX
};
#define NFULA_CFG_MAX (__NFULA_CFG_MAX - 1)
#define NFULNL_COPY_NONE 0x00
#define NFULNL_COPY_META 0x01
#define NFULNL_COPY_PACKET 0x02
#define NFULNL_CFG_F_SEQ 0x0001
#define NFULNL_CFG_F_SEQ_GLOBAL 0x0002
#define NFULNL_CFG_F_CONNTRACK 0x0004
#endif

"""

```