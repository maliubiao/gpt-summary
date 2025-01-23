Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The central task is to analyze the provided C header file (`nf_tables.h`) and explain its function, relevance to Android, and technical details, specifically within the context of Bionic. The prompt also asks for examples, error scenarios, tracing mechanisms (Frida), and considerations for the dynamic linker.

**2. Initial Assessment of the Header File:**

Scanning the file immediately reveals it's about `netfilter` and `nftables`. Key observations:

* **Auto-generated:**  This means the file is likely derived from a more abstract specification, and manual changes will be lost. It points to a close relationship with the Linux kernel.
* **`#ifndef _LINUX_NF_TABLES_H`:**  Standard header guard, indicating this file defines structures and enums related to netfilter tables.
* **`#define NFT_NAME_MAXLEN 256` and similar:** Defines constants related to the maximum lengths of various nftables objects (tables, chains, etc.).
* **`enum nft_registers`:** Defines an enumeration of registers used in nftables, hinting at a virtual machine or rule execution environment.
* **`enum nft_verdicts`:**  Defines possible outcomes of rule evaluation (CONTINUE, BREAK, JUMP, etc.).
* **`enum nf_tables_msg_types`:**  Defines message types for communication with the netfilter subsystem, likely through netlink sockets. This is a strong indicator of the file's role in controlling nftables.
* **Numerous `enum nft_*_attributes`:**  These enumerations define attributes associated with different nftables objects. This structure is typical for systems that use a type-length-value (TLV) encoding for communication.
* **Specific types like `nft_payload_bases`, `nft_meta_keys`, `nft_ct_keys`:** These highlight the ability of nftables to inspect and manipulate various parts of network packets.

**3. Structuring the Answer:**

Given the multi-faceted nature of the request, a structured approach is essential:

* **功能 (Functionality):**  Start with a high-level summary of what the file does. Emphasize its role as a user-space interface to the Linux kernel's nftables subsystem.
* **与 Android 的关系 (Relationship with Android):** Explain how nftables is used within Android for network security and policy enforcement. Give concrete examples like firewall, VPN, and traffic shaping.
* **Libc 函数详解 (Detailed Explanation of Libc Functions):**  Acknowledge that *this specific file doesn't define libc functions*. Instead, it defines *data structures* used by libc functions that interact with the kernel. Clarify the role of system calls in this interaction.
* **Dynamic Linker 功能 (Dynamic Linker Functionality):**  Similarly, explain that *this file itself is not directly involved in dynamic linking*. However, applications using nftables *will* be linked against libraries (potentially including Bionic's libc) that facilitate communication with the kernel. Describe the general process of linking and provide a sample SO layout.
* **逻辑推理 (Logical Inference):** Create a hypothetical scenario to illustrate how the data structures defined in the file are used in practice. This helps solidify understanding.
* **用户或编程常见的使用错误 (Common User/Programming Errors):** Think about typical mistakes developers might make when working with netfilter/nftables, such as incorrect attribute usage or invalid message construction.
* **Android Framework/NDK 到达这里 (How Android Framework/NDK Reaches Here):** Trace the path from high-level Android APIs down to the kernel level, mentioning relevant layers like `NetworkStack`, `system/netd`, and system calls.
* **Frida Hook 示例 (Frida Hook Example):**  Provide practical examples of using Frida to intercept and inspect interactions with the nftables subsystem. Focus on system calls related to netlink and ioctl.

**4. Populating Each Section (Iterative Refinement):**

* **Functionality:**  Focus on the core purpose: defining the API for controlling nftables. Mention the message types and attribute enumerations.
* **Android Relationship:**  Brainstorm specific Android features that rely on network filtering. Consider scenarios where traffic needs to be blocked, routed differently, or analyzed.
* **Libc Functions:**  Initially, one might think of `socket()`, `bind()`, `sendto()`, `recvfrom()`. However, these are generic network functions. The key is to realize that *no specific libc functions are defined in this header file itself*. The interaction is through system calls. Emphasize the role of libraries that *use* these structures.
* **Dynamic Linker:** The important point is that while this header isn't directly linked, applications that *use* it will be. Describe the SO structure and the linker's job of resolving symbols.
* **Logical Inference:**  Design a simple example, like creating a table and adding a rule. Show how the constants and enums from the header file would be used to construct the necessary data structures.
* **Common Errors:**  Think about the complexity of nftables configuration. Incorrectly specifying attributes, using the wrong message types, or forgetting to handle errors are all potential pitfalls.
* **Android Framework/NDK Path:** Start from high-level APIs (e.g., `ConnectivityManager`, `NetworkPolicyManager`) and work down to the lower levels, identifying the key components involved in network management.
* **Frida Hook:**  Focus on system calls directly related to interacting with netfilter/nftables, such as `sendto` (for sending netlink messages) and potentially `ioctl` (although less common for nftables). Provide concrete Frida script snippets.

**5. Language and Detail:**

Throughout the process, maintain clear and concise language. Explain technical terms appropriately. Use examples to illustrate abstract concepts. Pay attention to the level of detail requested in the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file defines libc functions for nftables."  **Correction:** Realize that this is a *header file* defining *data structures*. The actual functions reside in libc and the kernel.
* **Initial thought:** Focus heavily on specific libc functions. **Correction:** Shift focus to the *purpose* of the header file and how it's *used* by libc functions that interact with the kernel.
* **Consider the audience:**  The prompt doesn't specify the technical level of the reader. Aim for clarity and provide enough context for someone with a basic understanding of networking and C programming.

By following this structured and iterative approach, and by constantly refining understanding based on the content of the header file and the specific requirements of the prompt, a comprehensive and accurate answer can be generated.
这个头文件 `bionic/libc/kernel/uapi/linux/netfilter/nf_tables.h` 定义了 Linux 内核中 `nftables` 子系统的用户空间 API。`nftables` 是 Linux 内核防火墙框架 `netfilter` 的一个组件，用于对网络数据包进行过滤、修改和路由。由于它位于 `bionic/libc/kernel/uapi` 目录下，这表示它是 Android Bionic C 库中与 Linux 内核 API 相关的部分。

**它的功能：**

该头文件定义了用于与 `nftables` 内核模块交互的数据结构、枚举和常量。具体来说，它涵盖了以下功能：

1. **定义了 `nftables` 中各种对象的结构和属性：**
   - **表 (Tables):**  用于组织链的容器。定义了表名、标志（如持久性）等。
   - **链 (Chains):**  包含规则的执行路径。定义了链名、挂钩点（如 `PREROUTING`、`FORWARD`）、策略（如 `accept`、`drop`）等。
   - **规则 (Rules):**  定义了对数据包执行的操作和匹配条件。定义了规则所属的表和链、表达式（用于匹配和操作数据包）等。
   - **集合 (Sets):**  用于存储一组元素的容器，例如 IP 地址、端口号。定义了集合名、键类型、数据类型、标志（如匿名、常量）等。
   - **元素 (Elements):**  集合中包含的实际数据。定义了键值、数据值、超时时间等。
   - **对象 (Objects):**  可重用的配置单元，如计数器、配额等。
   - **流表 (Flow Tables):** 用于硬件加速的数据包处理。

2. **定义了与 `nftables` 交互的消息类型：**
   - `NFT_MSG_NEWTABLE`、`NFT_MSG_GETTABLE`、`NFT_MSG_DELTABLE` 等，用于创建、获取和删除表。
   - `NFT_MSG_NEWCHAIN`、`NFT_MSG_GETCHAIN`、`NFT_MSG_DELCHAIN` 等，用于创建、获取和删除链。
   - `NFT_MSG_NEWRULE`、`NFT_MSG_GETRULE`、`NFT_MSG_DELRULE` 等，用于创建、获取和删除规则。
   - `NFT_MSG_NEWSET`、`NFT_MSG_GETSET`、`NFT_MSG_DELSET` 等，用于创建、获取和删除集合。
   - 其他消息类型用于管理集合元素、生成器、对象、流表等。

3. **定义了用于构建 `nftables` 规则的各种表达式和操作：**
   - **元数据 (Metadata):**  访问数据包的元信息，如接口、协议、标记等。 (`NFTA_META_*`)
   - **负载 (Payload):**  访问数据包的实际内容。 (`NFTA_PAYLOAD_*`)
   - **连接跟踪 (Conntrack):**  访问连接跟踪信息。 (`NFTA_CT_*`)
   - **比较 (Compare):**  比较寄存器或数据。 (`NFTA_CMP_*`)
   - **范围 (Range):**  检查值是否在指定范围内。 (`NFTA_RANGE_*`)
   - **查找 (Lookup):**  在集合中查找元素。 (`NFTA_LOOKUP_*`)
   - **立即数 (Immediate):**  设置寄存器的值。 (`NFTA_IMMEDIATE_*`)
   - **位运算 (Bitwise):**  执行位操作。 (`NFTA_BITWISE_*`)
   - **字节序 (Byteorder):**  转换字节序。 (`NFTA_BYTEORDER_*`)
   - **跳转/返回 (Jump/Return):**  控制规则执行流程。 (`NFT_VERDICT_*`)
   - **日志 (Log):**  记录数据包信息。 (`NFTA_LOG_*`)
   - **队列 (Queue):**  将数据包放入用户空间队列。 (`NFTA_QUEUE_*`)
   - **NAT/MASQ/REDIRECT/TPROXY:**  网络地址转换和端口转发相关操作。
   - 以及其他高级操作，如配额、限制、连接限制等。

4. **定义了用于描述 `nftables` 对象的各种属性的枚举：**
   - 例如，`nft_table_attributes` 定义了表的属性，`nft_chain_attributes` 定义了链的属性，以此类推。

**与 Android 功能的关系及举例说明：**

`nftables` 在 Android 系统中扮演着至关重要的角色，主要负责网络安全和策略执行。Android 使用 `nftables` 来实现：

* **防火墙 (Firewall):**  Android 的防火墙功能（例如，允许或阻止特定应用的联网）底层就是通过配置 `nftables` 规则来实现的。
    * **举例：** 当你在 Android 设置中禁止某个应用使用移动数据时，Android 系统会通过 `netd` 守护进程向内核发送消息，添加相应的 `nftables` 规则来阻止该应用的网络连接。这些规则可能会检查应用的 UID，并根据 UID 阻止其发送或接收数据包。

* **VPN (Virtual Private Network):**  VPN 连接建立后，Android 系统会使用 `nftables` 来路由通过 VPN 接口的网络流量，并可能添加规则来阻止泄漏 VPN 之外的流量。
    * **举例：** 当你连接到 VPN 时，`VpnService` 会与 `netd` 交互，设置 `nftables` 规则，将所有目标 IP 为 `0.0.0.0/0` 的流量路由到 VPN 接口。

* **热点 (Tethering):**  当启用移动热点时，Android 会使用 `nftables` 来转发设备之间的网络流量，并可能进行网络地址转换 (NAT)。
    * **举例：** 当其他设备连接到你的 Android 热点时，`netd` 会配置 `nftables` 规则，将连接到热点的设备的私有 IP 地址转换为 Android 设备的公共 IP 地址，以便这些设备可以访问互联网。

* **流量整形 (Traffic Shaping):**  某些 Android 系统或应用可能会使用 `nftables` 来限制特定连接或应用的带宽使用。
    * **举例：**  一个下载管理器应用可能会使用 `nftables` 的 `limit` 模块来限制其下载速度，避免占用过多网络资源。

* **网络策略 (Network Policies):**  Android 系统使用 `nftables` 来执行各种网络策略，例如 Doze 模式下的网络访问限制。
    * **举例：**  在 Doze 模式下，Android 系统可能会添加 `nftables` 规则，暂时阻止后台应用的网络活动，以节省电量。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身**不包含任何 libc 函数的实现代码**。它只是定义了常量、枚举和结构体，这些是用户空间程序与内核中的 `nftables` 子系统进行交互时使用的数据类型。

用户空间程序（包括 Android 的系统服务和应用）通常会使用 **libmnl (minimalistic netlink library)** 或其他封装了 netlink 协议的库来构建和发送与 `nftables` 相关的 netlink 消息。

**netlink 通信的基本流程如下：**

1. **创建 Netlink 套接字：** 使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` 创建一个用于与 netfilter 子系统通信的 netlink 套接字。

2. **构建 Netlink 消息：**  使用该头文件中定义的结构体和常量，构建包含特定 `nftables` 操作请求的 netlink 消息。例如，要创建一个新的表，你需要创建一个包含 `NFT_MSG_NEWTABLE` 类型和相关属性（如表名、标志）的 netlink 消息。

3. **发送 Netlink 消息：** 使用 `sendto()` 系统调用将构建好的 netlink 消息发送到内核。

4. **内核处理：**  内核中的 `nftables` 模块接收到 netlink 消息后，会解析消息内容，执行相应的操作（例如，创建表、添加规则）。

5. **接收 Netlink 消息 (可选)：** 内核可能会通过 netlink 套接字发送响应消息，指示操作是否成功或包含请求的数据。用户空间程序使用 `recvfrom()` 系统调用接收这些响应。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

此头文件本身不涉及 dynamic linker 的直接功能。但是，使用 `nftables` 的应用程序或库（例如 `libnetfilter_conntrack.so`, `libnftables.so` 等）会被动态链接到 Android 系统中。

**SO 布局样本 (假设一个名为 `libmynftapp.so` 的库使用了 `nf_tables.h` 中定义的结构):**

```
libmynftapp.so:
    .text         # 包含代码段
    .rodata       # 包含只读数据
    .data         # 包含已初始化的可写数据
    .bss          # 包含未初始化的可写数据
    .dynsym       # 动态符号表
    .dynstr       # 动态字符串表
    .rel.dyn      # 动态重定位表
    .rel.plt      # PLT (Procedure Linkage Table) 重定位表
    ...
```

**链接的处理过程：**

1. **编译时链接：** 当编译 `libmynftapp.so` 时，编译器会识别出对 `nf_tables.h` 中定义的常量、枚举和结构体的引用。这些符号会被记录在 `.symtab` (符号表) 和 `.strtab` (字符串表) 中。

2. **生成动态链接信息：**  链接器会生成动态链接所需的信息，包括 `.dynsym` (动态符号表) 和 `.dynstr` (动态字符串表)。这些表列出了库中需要从其他共享库导入或导出的符号。

3. **运行时链接：** 当 Android 系统加载使用 `libmynftapp.so` 的应用程序时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
   - **加载依赖库：**  dynamic linker 会加载 `libmynftapp.so` 依赖的其他共享库，例如 `libc.so`（其中可能包含 netlink 相关的函数）。
   - **符号解析：** dynamic linker 会遍历 `libmynftapp.so` 的 `.rel.dyn` 和 `.rel.plt` 表，找到需要重定位的符号。
   - **查找符号定义：**  对于每个需要重定位的符号，dynamic linker 会在已加载的共享库的动态符号表中查找其定义。例如，如果 `libmynftapp.so` 使用了 `socket()` 函数，dynamic linker 会在 `libc.so` 中查找 `socket()` 的地址。
   - **重定位：**  找到符号的地址后，dynamic linker 会更新 `libmynftapp.so` 中对该符号的引用，将其指向正确的内存地址。
   - **PLT (Procedure Linkage Table)：** 对于外部函数调用，通常会使用 PLT。第一次调用外部函数时，PLT 中的代码会调用 dynamic linker 来解析符号并更新 PLT 表项。后续调用将直接跳转到已解析的地址，提高效率。

**如果做了逻辑推理，请给出假设输入与输出：**

假设我们想创建一个名为 "my_table" 的 IPv4 表。

**假设输入 (使用 libmnl 构建 Netlink 消息，简化表示):**

```c
struct nlmsghdr nlh;
struct nfgenmsg nfmsg;
struct nlattr nla;

// 设置 Netlink 消息头
nlh.nlmsg_len = NLMSG_LENGTH(sizeof(nfmsg) + NLA_HDRLEN + strlen("my_table") + 1);
nlh.nlmsg_type = NFT_MSG_NEWTABLE;
nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

// 设置 Netfilter 通用消息头
nfmsg.nfgen_family = AF_INET;
nfmsg.version = NFNETLINK_V0;
nfmsg.res_id = htons(0);

// 设置表名属性
nla.nla_len = NLA_HDRLEN + strlen("my_table") + 1;
nla.nla_type = NFTA_TABLE_NAME;
strcpy((char *)NLA_DATA(&nla), "my_table");

// ... 将这些结构体组合成完整的 Netlink 消息缓冲区 ...
```

**假设输出 (内核成功创建表后的 Netlink ACK 消息，简化表示):**

```c
struct nlmsghdr nlh_ack;
struct nlmsgerr err;

// Netlink 消息头
nlh_ack.nlmsg_type = NLMSG_ERROR;

// Netlink 错误消息
err.error = 0; // 0 表示成功

// ... 其他信息 ...
```

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **属性类型错误：**  使用错误的属性类型 (`nla_type`) 来表示特定的信息。例如，尝试使用 `NFTA_CHAIN_NAME` 来设置表名，这会导致内核解析错误。

2. **属性长度错误：**  设置的属性长度 (`nla_len`) 与实际数据长度不匹配。如果长度太小，数据会被截断；如果长度太大，可能会导致越界读取。

3. **消息类型错误：**  发送了错误的消息类型 (`nlmsg_type`) 来执行某个操作。例如，尝试使用 `NFT_MSG_NEWRULE` 来创建表。

4. **缺少必要的属性：**  创建 `nftables` 对象时缺少必要的属性。例如，创建一个链时，必须指定其所属的表。

5. **使用错误的协议族：**  在 `nfgenmsg` 中指定了错误的协议族 (`nfgen_family`)。例如，尝试使用 `AF_INET6` 来创建一个 IPv4 表。

6. **并发修改冲突：**  多个进程或线程同时尝试修改 `nftables` 配置可能会导致冲突和意外结果。

7. **权限不足：**  尝试执行需要 root 权限的 `nftables` 操作时，如果当前用户权限不足，会导致操作失败。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `nf_tables.h` 的步骤：**

1. **高层 API 调用：** Android Framework 中的某些服务（例如 `NetworkPolicyManagerService`, `FirewallController`) 或应用会调用高层的 Android API 来管理网络策略或防火墙规则。

2. **System Server 组件：** 这些高层 API 调用通常会转发到 System Server 中的组件，例如 `netd` (network daemon)。

3. **`netd` 守护进程：** `netd` 是 Android 系统中负责网络配置的核心守护进程。它接收来自 Framework 的请求，并将其转换为对内核网络子系统的操作。

4. **`libnetd_client` 库：**  `netd` 内部会使用 `libnetd_client` 库来与内核进行通信。

5. **Netlink 通信：** `libnetd_client` 库使用 netlink 套接字与内核的 `netfilter` 子系统进行交互。在与 `nftables` 交互时，它会构建包含 `nf_tables.h` 中定义的结构和常量的 netlink 消息。

6. **内核 `nftables` 模块：** 内核中的 `nftables` 模块接收来自 netlink 套接字的请求，解析消息，并执行相应的防火墙规则管理操作。

**NDK 到达 `nf_tables.h` 的步骤：**

1. **NDK 应用调用：**  使用 NDK 开发的应用可以直接使用 C/C++ 代码调用 Linux 系统调用或使用封装了 netlink 的库（如 `libmnl` 或 `libnftables`）。

2. **直接 Netlink 通信或库调用：**  NDK 应用可以直接创建 netlink 套接字并构建与 `nftables` 交互的 netlink 消息，或者使用 `libnftables` 等库，这些库内部会使用 `nf_tables.h` 中定义的结构体。

3. **系统调用：**  无论是直接使用 netlink 还是使用库，最终都会涉及到使用系统调用（如 `socket`, `bind`, `sendto`, `recvfrom`) 与内核进行通信。

**Frida Hook 示例调试步骤：**

我们可以使用 Frida hook `sendto` 系统调用，来观察 Android 系统或应用发送到内核的与 `nftables` 相关的 netlink 消息。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message}")
        if data:
            print(f"[*] Data: {data.hex()}")

def main():
    package_name = "com.android.shell"  # 或者你想要监控的进程
    try:
        session = frida.attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Process '{package_name}' not found. Please run the application first.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "sendto"), {
        onEnter: function(args) {
            const sockfd = args[0];
            const buf = args[1];
            const len = args[2];
            const flags = args[3];
            const dest_addr = args[4];
            const addrlen = args[5];

            // 检查是否是 AF_NETLINK 套接字 (通常用于 netfilter)
            const sockaddr_nl = new NativePointer(dest_addr);
            const family = sockaddr_nl.readU16();
            if (family === 16) { // AF_NETLINK = 16
                console.log("[*] sendto called");
                console.log("    sockfd:", sockfd);
                console.log("    len:", len);
                this.buf = buf;
                this.len = len;
            }
        },
        onLeave: function(retval) {
            if (this.buf && this.len > 0) {
                const data = Memory.readByteArray(this.buf, this.len.toInt());
                send({"type": "send", "retval": retval.toInt()}, data);
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Waiting for messages...")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**使用方法：**

1. **保存代码：** 将上面的 Python 代码保存为 `frida_hook_nftables.py`。
2. **安装 Frida：** 确保你的电脑上安装了 Frida 和 frida-tools (`pip install frida frida-tools`).
3. **运行 Android 设备/模拟器：** 确保你的 Android 设备或模拟器已连接并可以被 adb 访问。
4. **运行 Frida 服务：** 将 `frida-server` 推送到 Android 设备并运行。
5. **运行 Hook 脚本：** 在你的电脑上运行 `python frida_hook_nftables.py`。
6. **执行网络操作：** 在 Android 设备上执行一些可能触发 `nftables` 规则的操作，例如连接 VPN、开启热点、更改应用的网络权限等。
7. **观察输出：** Frida 脚本会拦截 `sendto` 调用，并打印发送到内核的数据（如果是 AF_NETLINK 套接字）。你可以分析这些数据，查看是否包含了与 `nf_tables.h` 中定义的结构和常量相关的模式。

**分析 Frida 输出：**

当你看到 `sendto` 被调用且 `family` 为 `16` (AF_NETLINK) 时，输出的 `Data` 部分会是发送到内核的 netlink 消息的十六进制表示。你需要了解 netlink 消息的结构，才能解析这些数据并理解具体的 `nftables` 操作。通常，你会看到消息头 (`nlmsghdr`)，通用 netfilter 头 (`nfgenmsg`)，以及各种 netlink 属性 (`nlattr`)，这些属性的类型和数据对应于 `nf_tables.h` 中定义的枚举和结构体。

例如，你可能会看到 `nlmsg_type` 为 `0` (NFT_MSG_NEWTABLE)，然后会有一个 `nlattr`，其 `nla_type` 为 `1` (NFTA_TABLE_NAME)，并且 `nla_data` 包含了表的名字。通过分析这些数据，你可以了解 Android 系统或应用是如何使用 `nftables` 来管理网络流量的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter/nf_tables.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _LINUX_NF_TABLES_H
#define _LINUX_NF_TABLES_H
#define NFT_NAME_MAXLEN 256
#define NFT_TABLE_MAXNAMELEN NFT_NAME_MAXLEN
#define NFT_CHAIN_MAXNAMELEN NFT_NAME_MAXLEN
#define NFT_SET_MAXNAMELEN NFT_NAME_MAXLEN
#define NFT_OBJ_MAXNAMELEN NFT_NAME_MAXLEN
#define NFT_USERDATA_MAXLEN 256
#define NFT_OSF_MAXGENRELEN 16
enum nft_registers {
  NFT_REG_VERDICT,
  NFT_REG_1,
  NFT_REG_2,
  NFT_REG_3,
  NFT_REG_4,
  __NFT_REG_MAX,
  NFT_REG32_00 = 8,
  NFT_REG32_01,
  NFT_REG32_02,
  NFT_REG32_03,
  NFT_REG32_04,
  NFT_REG32_05,
  NFT_REG32_06,
  NFT_REG32_07,
  NFT_REG32_08,
  NFT_REG32_09,
  NFT_REG32_10,
  NFT_REG32_11,
  NFT_REG32_12,
  NFT_REG32_13,
  NFT_REG32_14,
  NFT_REG32_15,
};
#define NFT_REG_MAX (__NFT_REG_MAX - 1)
#define NFT_REG_SIZE 16
#define NFT_REG32_SIZE 4
#define NFT_REG32_COUNT (NFT_REG32_15 - NFT_REG32_00 + 1)
enum nft_verdicts {
  NFT_CONTINUE = - 1,
  NFT_BREAK = - 2,
  NFT_JUMP = - 3,
  NFT_GOTO = - 4,
  NFT_RETURN = - 5,
};
enum nf_tables_msg_types {
  NFT_MSG_NEWTABLE,
  NFT_MSG_GETTABLE,
  NFT_MSG_DELTABLE,
  NFT_MSG_NEWCHAIN,
  NFT_MSG_GETCHAIN,
  NFT_MSG_DELCHAIN,
  NFT_MSG_NEWRULE,
  NFT_MSG_GETRULE,
  NFT_MSG_DELRULE,
  NFT_MSG_NEWSET,
  NFT_MSG_GETSET,
  NFT_MSG_DELSET,
  NFT_MSG_NEWSETELEM,
  NFT_MSG_GETSETELEM,
  NFT_MSG_DELSETELEM,
  NFT_MSG_NEWGEN,
  NFT_MSG_GETGEN,
  NFT_MSG_TRACE,
  NFT_MSG_NEWOBJ,
  NFT_MSG_GETOBJ,
  NFT_MSG_DELOBJ,
  NFT_MSG_GETOBJ_RESET,
  NFT_MSG_NEWFLOWTABLE,
  NFT_MSG_GETFLOWTABLE,
  NFT_MSG_DELFLOWTABLE,
  NFT_MSG_GETRULE_RESET,
  NFT_MSG_DESTROYTABLE,
  NFT_MSG_DESTROYCHAIN,
  NFT_MSG_DESTROYRULE,
  NFT_MSG_DESTROYSET,
  NFT_MSG_DESTROYSETELEM,
  NFT_MSG_DESTROYOBJ,
  NFT_MSG_DESTROYFLOWTABLE,
  NFT_MSG_GETSETELEM_RESET,
  NFT_MSG_MAX,
};
enum nft_list_attributes {
  NFTA_LIST_UNSPEC,
  NFTA_LIST_ELEM,
  __NFTA_LIST_MAX
};
#define NFTA_LIST_MAX (__NFTA_LIST_MAX - 1)
enum nft_hook_attributes {
  NFTA_HOOK_UNSPEC,
  NFTA_HOOK_HOOKNUM,
  NFTA_HOOK_PRIORITY,
  NFTA_HOOK_DEV,
  NFTA_HOOK_DEVS,
  __NFTA_HOOK_MAX
};
#define NFTA_HOOK_MAX (__NFTA_HOOK_MAX - 1)
enum nft_table_flags {
  NFT_TABLE_F_DORMANT = 0x1,
  NFT_TABLE_F_OWNER = 0x2,
  NFT_TABLE_F_PERSIST = 0x4,
};
#define NFT_TABLE_F_MASK (NFT_TABLE_F_DORMANT | NFT_TABLE_F_OWNER | NFT_TABLE_F_PERSIST)
enum nft_table_attributes {
  NFTA_TABLE_UNSPEC,
  NFTA_TABLE_NAME,
  NFTA_TABLE_FLAGS,
  NFTA_TABLE_USE,
  NFTA_TABLE_HANDLE,
  NFTA_TABLE_PAD,
  NFTA_TABLE_USERDATA,
  NFTA_TABLE_OWNER,
  __NFTA_TABLE_MAX
};
#define NFTA_TABLE_MAX (__NFTA_TABLE_MAX - 1)
enum nft_chain_flags {
  NFT_CHAIN_BASE = (1 << 0),
  NFT_CHAIN_HW_OFFLOAD = (1 << 1),
  NFT_CHAIN_BINDING = (1 << 2),
};
#define NFT_CHAIN_FLAGS (NFT_CHAIN_BASE | NFT_CHAIN_HW_OFFLOAD | NFT_CHAIN_BINDING)
enum nft_chain_attributes {
  NFTA_CHAIN_UNSPEC,
  NFTA_CHAIN_TABLE,
  NFTA_CHAIN_HANDLE,
  NFTA_CHAIN_NAME,
  NFTA_CHAIN_HOOK,
  NFTA_CHAIN_POLICY,
  NFTA_CHAIN_USE,
  NFTA_CHAIN_TYPE,
  NFTA_CHAIN_COUNTERS,
  NFTA_CHAIN_PAD,
  NFTA_CHAIN_FLAGS,
  NFTA_CHAIN_ID,
  NFTA_CHAIN_USERDATA,
  __NFTA_CHAIN_MAX
};
#define NFTA_CHAIN_MAX (__NFTA_CHAIN_MAX - 1)
enum nft_rule_attributes {
  NFTA_RULE_UNSPEC,
  NFTA_RULE_TABLE,
  NFTA_RULE_CHAIN,
  NFTA_RULE_HANDLE,
  NFTA_RULE_EXPRESSIONS,
  NFTA_RULE_COMPAT,
  NFTA_RULE_POSITION,
  NFTA_RULE_USERDATA,
  NFTA_RULE_PAD,
  NFTA_RULE_ID,
  NFTA_RULE_POSITION_ID,
  NFTA_RULE_CHAIN_ID,
  __NFTA_RULE_MAX
};
#define NFTA_RULE_MAX (__NFTA_RULE_MAX - 1)
enum nft_rule_compat_flags {
  NFT_RULE_COMPAT_F_UNUSED = (1 << 0),
  NFT_RULE_COMPAT_F_INV = (1 << 1),
  NFT_RULE_COMPAT_F_MASK = NFT_RULE_COMPAT_F_INV,
};
enum nft_rule_compat_attributes {
  NFTA_RULE_COMPAT_UNSPEC,
  NFTA_RULE_COMPAT_PROTO,
  NFTA_RULE_COMPAT_FLAGS,
  __NFTA_RULE_COMPAT_MAX
};
#define NFTA_RULE_COMPAT_MAX (__NFTA_RULE_COMPAT_MAX - 1)
enum nft_set_flags {
  NFT_SET_ANONYMOUS = 0x1,
  NFT_SET_CONSTANT = 0x2,
  NFT_SET_INTERVAL = 0x4,
  NFT_SET_MAP = 0x8,
  NFT_SET_TIMEOUT = 0x10,
  NFT_SET_EVAL = 0x20,
  NFT_SET_OBJECT = 0x40,
  NFT_SET_CONCAT = 0x80,
  NFT_SET_EXPR = 0x100,
};
enum nft_set_policies {
  NFT_SET_POL_PERFORMANCE,
  NFT_SET_POL_MEMORY,
};
enum nft_set_desc_attributes {
  NFTA_SET_DESC_UNSPEC,
  NFTA_SET_DESC_SIZE,
  NFTA_SET_DESC_CONCAT,
  __NFTA_SET_DESC_MAX
};
#define NFTA_SET_DESC_MAX (__NFTA_SET_DESC_MAX - 1)
enum nft_set_field_attributes {
  NFTA_SET_FIELD_UNSPEC,
  NFTA_SET_FIELD_LEN,
  __NFTA_SET_FIELD_MAX
};
#define NFTA_SET_FIELD_MAX (__NFTA_SET_FIELD_MAX - 1)
enum nft_set_attributes {
  NFTA_SET_UNSPEC,
  NFTA_SET_TABLE,
  NFTA_SET_NAME,
  NFTA_SET_FLAGS,
  NFTA_SET_KEY_TYPE,
  NFTA_SET_KEY_LEN,
  NFTA_SET_DATA_TYPE,
  NFTA_SET_DATA_LEN,
  NFTA_SET_POLICY,
  NFTA_SET_DESC,
  NFTA_SET_ID,
  NFTA_SET_TIMEOUT,
  NFTA_SET_GC_INTERVAL,
  NFTA_SET_USERDATA,
  NFTA_SET_PAD,
  NFTA_SET_OBJ_TYPE,
  NFTA_SET_HANDLE,
  NFTA_SET_EXPR,
  NFTA_SET_EXPRESSIONS,
  __NFTA_SET_MAX
};
#define NFTA_SET_MAX (__NFTA_SET_MAX - 1)
enum nft_set_elem_flags {
  NFT_SET_ELEM_INTERVAL_END = 0x1,
  NFT_SET_ELEM_CATCHALL = 0x2,
};
enum nft_set_elem_attributes {
  NFTA_SET_ELEM_UNSPEC,
  NFTA_SET_ELEM_KEY,
  NFTA_SET_ELEM_DATA,
  NFTA_SET_ELEM_FLAGS,
  NFTA_SET_ELEM_TIMEOUT,
  NFTA_SET_ELEM_EXPIRATION,
  NFTA_SET_ELEM_USERDATA,
  NFTA_SET_ELEM_EXPR,
  NFTA_SET_ELEM_PAD,
  NFTA_SET_ELEM_OBJREF,
  NFTA_SET_ELEM_KEY_END,
  NFTA_SET_ELEM_EXPRESSIONS,
  __NFTA_SET_ELEM_MAX
};
#define NFTA_SET_ELEM_MAX (__NFTA_SET_ELEM_MAX - 1)
enum nft_set_elem_list_attributes {
  NFTA_SET_ELEM_LIST_UNSPEC,
  NFTA_SET_ELEM_LIST_TABLE,
  NFTA_SET_ELEM_LIST_SET,
  NFTA_SET_ELEM_LIST_ELEMENTS,
  NFTA_SET_ELEM_LIST_SET_ID,
  __NFTA_SET_ELEM_LIST_MAX
};
#define NFTA_SET_ELEM_LIST_MAX (__NFTA_SET_ELEM_LIST_MAX - 1)
enum nft_data_types {
  NFT_DATA_VALUE,
  NFT_DATA_VERDICT = 0xffffff00U,
};
#define NFT_DATA_RESERVED_MASK 0xffffff00U
enum nft_data_attributes {
  NFTA_DATA_UNSPEC,
  NFTA_DATA_VALUE,
  NFTA_DATA_VERDICT,
  __NFTA_DATA_MAX
};
#define NFTA_DATA_MAX (__NFTA_DATA_MAX - 1)
#define NFT_DATA_VALUE_MAXLEN 64
enum nft_verdict_attributes {
  NFTA_VERDICT_UNSPEC,
  NFTA_VERDICT_CODE,
  NFTA_VERDICT_CHAIN,
  NFTA_VERDICT_CHAIN_ID,
  __NFTA_VERDICT_MAX
};
#define NFTA_VERDICT_MAX (__NFTA_VERDICT_MAX - 1)
enum nft_expr_attributes {
  NFTA_EXPR_UNSPEC,
  NFTA_EXPR_NAME,
  NFTA_EXPR_DATA,
  __NFTA_EXPR_MAX
};
#define NFTA_EXPR_MAX (__NFTA_EXPR_MAX - 1)
enum nft_immediate_attributes {
  NFTA_IMMEDIATE_UNSPEC,
  NFTA_IMMEDIATE_DREG,
  NFTA_IMMEDIATE_DATA,
  __NFTA_IMMEDIATE_MAX
};
#define NFTA_IMMEDIATE_MAX (__NFTA_IMMEDIATE_MAX - 1)
enum nft_bitwise_ops {
  NFT_BITWISE_BOOL,
  NFT_BITWISE_LSHIFT,
  NFT_BITWISE_RSHIFT,
};
enum nft_bitwise_attributes {
  NFTA_BITWISE_UNSPEC,
  NFTA_BITWISE_SREG,
  NFTA_BITWISE_DREG,
  NFTA_BITWISE_LEN,
  NFTA_BITWISE_MASK,
  NFTA_BITWISE_XOR,
  NFTA_BITWISE_OP,
  NFTA_BITWISE_DATA,
  __NFTA_BITWISE_MAX
};
#define NFTA_BITWISE_MAX (__NFTA_BITWISE_MAX - 1)
enum nft_byteorder_ops {
  NFT_BYTEORDER_NTOH,
  NFT_BYTEORDER_HTON,
};
enum nft_byteorder_attributes {
  NFTA_BYTEORDER_UNSPEC,
  NFTA_BYTEORDER_SREG,
  NFTA_BYTEORDER_DREG,
  NFTA_BYTEORDER_OP,
  NFTA_BYTEORDER_LEN,
  NFTA_BYTEORDER_SIZE,
  __NFTA_BYTEORDER_MAX
};
#define NFTA_BYTEORDER_MAX (__NFTA_BYTEORDER_MAX - 1)
enum nft_cmp_ops {
  NFT_CMP_EQ,
  NFT_CMP_NEQ,
  NFT_CMP_LT,
  NFT_CMP_LTE,
  NFT_CMP_GT,
  NFT_CMP_GTE,
};
enum nft_cmp_attributes {
  NFTA_CMP_UNSPEC,
  NFTA_CMP_SREG,
  NFTA_CMP_OP,
  NFTA_CMP_DATA,
  __NFTA_CMP_MAX
};
#define NFTA_CMP_MAX (__NFTA_CMP_MAX - 1)
enum nft_range_ops {
  NFT_RANGE_EQ,
  NFT_RANGE_NEQ,
};
enum nft_range_attributes {
  NFTA_RANGE_UNSPEC,
  NFTA_RANGE_SREG,
  NFTA_RANGE_OP,
  NFTA_RANGE_FROM_DATA,
  NFTA_RANGE_TO_DATA,
  __NFTA_RANGE_MAX
};
#define NFTA_RANGE_MAX (__NFTA_RANGE_MAX - 1)
enum nft_lookup_flags {
  NFT_LOOKUP_F_INV = (1 << 0),
};
enum nft_lookup_attributes {
  NFTA_LOOKUP_UNSPEC,
  NFTA_LOOKUP_SET,
  NFTA_LOOKUP_SREG,
  NFTA_LOOKUP_DREG,
  NFTA_LOOKUP_SET_ID,
  NFTA_LOOKUP_FLAGS,
  __NFTA_LOOKUP_MAX
};
#define NFTA_LOOKUP_MAX (__NFTA_LOOKUP_MAX - 1)
enum nft_dynset_ops {
  NFT_DYNSET_OP_ADD,
  NFT_DYNSET_OP_UPDATE,
  NFT_DYNSET_OP_DELETE,
};
enum nft_dynset_flags {
  NFT_DYNSET_F_INV = (1 << 0),
  NFT_DYNSET_F_EXPR = (1 << 1),
};
enum nft_dynset_attributes {
  NFTA_DYNSET_UNSPEC,
  NFTA_DYNSET_SET_NAME,
  NFTA_DYNSET_SET_ID,
  NFTA_DYNSET_OP,
  NFTA_DYNSET_SREG_KEY,
  NFTA_DYNSET_SREG_DATA,
  NFTA_DYNSET_TIMEOUT,
  NFTA_DYNSET_EXPR,
  NFTA_DYNSET_PAD,
  NFTA_DYNSET_FLAGS,
  NFTA_DYNSET_EXPRESSIONS,
  __NFTA_DYNSET_MAX,
};
#define NFTA_DYNSET_MAX (__NFTA_DYNSET_MAX - 1)
enum nft_payload_bases {
  NFT_PAYLOAD_LL_HEADER,
  NFT_PAYLOAD_NETWORK_HEADER,
  NFT_PAYLOAD_TRANSPORT_HEADER,
  NFT_PAYLOAD_INNER_HEADER,
  NFT_PAYLOAD_TUN_HEADER,
};
enum nft_payload_csum_types {
  NFT_PAYLOAD_CSUM_NONE,
  NFT_PAYLOAD_CSUM_INET,
  NFT_PAYLOAD_CSUM_SCTP,
};
enum nft_payload_csum_flags {
  NFT_PAYLOAD_L4CSUM_PSEUDOHDR = (1 << 0),
};
enum nft_inner_type {
  NFT_INNER_UNSPEC = 0,
  NFT_INNER_VXLAN,
  NFT_INNER_GENEVE,
};
enum nft_inner_flags {
  NFT_INNER_HDRSIZE = (1 << 0),
  NFT_INNER_LL = (1 << 1),
  NFT_INNER_NH = (1 << 2),
  NFT_INNER_TH = (1 << 3),
};
#define NFT_INNER_MASK (NFT_INNER_HDRSIZE | NFT_INNER_LL | NFT_INNER_NH | NFT_INNER_TH)
enum nft_inner_attributes {
  NFTA_INNER_UNSPEC,
  NFTA_INNER_NUM,
  NFTA_INNER_TYPE,
  NFTA_INNER_FLAGS,
  NFTA_INNER_HDRSIZE,
  NFTA_INNER_EXPR,
  __NFTA_INNER_MAX
};
#define NFTA_INNER_MAX (__NFTA_INNER_MAX - 1)
enum nft_payload_attributes {
  NFTA_PAYLOAD_UNSPEC,
  NFTA_PAYLOAD_DREG,
  NFTA_PAYLOAD_BASE,
  NFTA_PAYLOAD_OFFSET,
  NFTA_PAYLOAD_LEN,
  NFTA_PAYLOAD_SREG,
  NFTA_PAYLOAD_CSUM_TYPE,
  NFTA_PAYLOAD_CSUM_OFFSET,
  NFTA_PAYLOAD_CSUM_FLAGS,
  __NFTA_PAYLOAD_MAX
};
#define NFTA_PAYLOAD_MAX (__NFTA_PAYLOAD_MAX - 1)
enum nft_exthdr_flags {
  NFT_EXTHDR_F_PRESENT = (1 << 0),
};
enum nft_exthdr_op {
  NFT_EXTHDR_OP_IPV6,
  NFT_EXTHDR_OP_TCPOPT,
  NFT_EXTHDR_OP_IPV4,
  NFT_EXTHDR_OP_SCTP,
  NFT_EXTHDR_OP_DCCP,
  __NFT_EXTHDR_OP_MAX
};
#define NFT_EXTHDR_OP_MAX (__NFT_EXTHDR_OP_MAX - 1)
enum nft_exthdr_attributes {
  NFTA_EXTHDR_UNSPEC,
  NFTA_EXTHDR_DREG,
  NFTA_EXTHDR_TYPE,
  NFTA_EXTHDR_OFFSET,
  NFTA_EXTHDR_LEN,
  NFTA_EXTHDR_FLAGS,
  NFTA_EXTHDR_OP,
  NFTA_EXTHDR_SREG,
  __NFTA_EXTHDR_MAX
};
#define NFTA_EXTHDR_MAX (__NFTA_EXTHDR_MAX - 1)
enum nft_meta_keys {
  NFT_META_LEN,
  NFT_META_PROTOCOL,
  NFT_META_PRIORITY,
  NFT_META_MARK,
  NFT_META_IIF,
  NFT_META_OIF,
  NFT_META_IIFNAME,
  NFT_META_OIFNAME,
  NFT_META_IFTYPE,
#define NFT_META_IIFTYPE NFT_META_IFTYPE
  NFT_META_OIFTYPE,
  NFT_META_SKUID,
  NFT_META_SKGID,
  NFT_META_NFTRACE,
  NFT_META_RTCLASSID,
  NFT_META_SECMARK,
  NFT_META_NFPROTO,
  NFT_META_L4PROTO,
  NFT_META_BRI_IIFNAME,
  NFT_META_BRI_OIFNAME,
  NFT_META_PKTTYPE,
  NFT_META_CPU,
  NFT_META_IIFGROUP,
  NFT_META_OIFGROUP,
  NFT_META_CGROUP,
  NFT_META_PRANDOM,
  NFT_META_SECPATH,
  NFT_META_IIFKIND,
  NFT_META_OIFKIND,
  NFT_META_BRI_IIFPVID,
  NFT_META_BRI_IIFVPROTO,
  NFT_META_TIME_NS,
  NFT_META_TIME_DAY,
  NFT_META_TIME_HOUR,
  NFT_META_SDIF,
  NFT_META_SDIFNAME,
  NFT_META_BRI_BROUTE,
  __NFT_META_IIFTYPE,
};
enum nft_rt_keys {
  NFT_RT_CLASSID,
  NFT_RT_NEXTHOP4,
  NFT_RT_NEXTHOP6,
  NFT_RT_TCPMSS,
  NFT_RT_XFRM,
  __NFT_RT_MAX
};
#define NFT_RT_MAX (__NFT_RT_MAX - 1)
enum nft_hash_types {
  NFT_HASH_JENKINS,
  NFT_HASH_SYM,
};
enum nft_hash_attributes {
  NFTA_HASH_UNSPEC,
  NFTA_HASH_SREG,
  NFTA_HASH_DREG,
  NFTA_HASH_LEN,
  NFTA_HASH_MODULUS,
  NFTA_HASH_SEED,
  NFTA_HASH_OFFSET,
  NFTA_HASH_TYPE,
  NFTA_HASH_SET_NAME,
  NFTA_HASH_SET_ID,
  __NFTA_HASH_MAX,
};
#define NFTA_HASH_MAX (__NFTA_HASH_MAX - 1)
enum nft_meta_attributes {
  NFTA_META_UNSPEC,
  NFTA_META_DREG,
  NFTA_META_KEY,
  NFTA_META_SREG,
  __NFTA_META_MAX
};
#define NFTA_META_MAX (__NFTA_META_MAX - 1)
enum nft_rt_attributes {
  NFTA_RT_UNSPEC,
  NFTA_RT_DREG,
  NFTA_RT_KEY,
  __NFTA_RT_MAX
};
#define NFTA_RT_MAX (__NFTA_RT_MAX - 1)
enum nft_socket_attributes {
  NFTA_SOCKET_UNSPEC,
  NFTA_SOCKET_KEY,
  NFTA_SOCKET_DREG,
  NFTA_SOCKET_LEVEL,
  __NFTA_SOCKET_MAX
};
#define NFTA_SOCKET_MAX (__NFTA_SOCKET_MAX - 1)
enum nft_socket_keys {
  NFT_SOCKET_TRANSPARENT,
  NFT_SOCKET_MARK,
  NFT_SOCKET_WILDCARD,
  NFT_SOCKET_CGROUPV2,
  __NFT_SOCKET_MAX
};
#define NFT_SOCKET_MAX (__NFT_SOCKET_MAX - 1)
enum nft_ct_keys {
  NFT_CT_STATE,
  NFT_CT_DIRECTION,
  NFT_CT_STATUS,
  NFT_CT_MARK,
  NFT_CT_SECMARK,
  NFT_CT_EXPIRATION,
  NFT_CT_HELPER,
  NFT_CT_L3PROTOCOL,
  NFT_CT_SRC,
  NFT_CT_DST,
  NFT_CT_PROTOCOL,
  NFT_CT_PROTO_SRC,
  NFT_CT_PROTO_DST,
  NFT_CT_LABELS,
  NFT_CT_PKTS,
  NFT_CT_BYTES,
  NFT_CT_AVGPKT,
  NFT_CT_ZONE,
  NFT_CT_EVENTMASK,
  NFT_CT_SRC_IP,
  NFT_CT_DST_IP,
  NFT_CT_SRC_IP6,
  NFT_CT_DST_IP6,
  NFT_CT_ID,
  __NFT_CT_MAX
};
#define NFT_CT_MAX (__NFT_CT_MAX - 1)
enum nft_ct_attributes {
  NFTA_CT_UNSPEC,
  NFTA_CT_DREG,
  NFTA_CT_KEY,
  NFTA_CT_DIRECTION,
  NFTA_CT_SREG,
  __NFTA_CT_MAX
};
#define NFTA_CT_MAX (__NFTA_CT_MAX - 1)
enum nft_offload_attributes {
  NFTA_FLOW_UNSPEC,
  NFTA_FLOW_TABLE_NAME,
  __NFTA_FLOW_MAX,
};
#define NFTA_FLOW_MAX (__NFTA_FLOW_MAX - 1)
enum nft_limit_type {
  NFT_LIMIT_PKTS,
  NFT_LIMIT_PKT_BYTES
};
enum nft_limit_flags {
  NFT_LIMIT_F_INV = (1 << 0),
};
enum nft_limit_attributes {
  NFTA_LIMIT_UNSPEC,
  NFTA_LIMIT_RATE,
  NFTA_LIMIT_UNIT,
  NFTA_LIMIT_BURST,
  NFTA_LIMIT_TYPE,
  NFTA_LIMIT_FLAGS,
  NFTA_LIMIT_PAD,
  __NFTA_LIMIT_MAX
};
#define NFTA_LIMIT_MAX (__NFTA_LIMIT_MAX - 1)
enum nft_connlimit_flags {
  NFT_CONNLIMIT_F_INV = (1 << 0),
};
enum nft_connlimit_attributes {
  NFTA_CONNLIMIT_UNSPEC,
  NFTA_CONNLIMIT_COUNT,
  NFTA_CONNLIMIT_FLAGS,
  __NFTA_CONNLIMIT_MAX
};
#define NFTA_CONNLIMIT_MAX (__NFTA_CONNLIMIT_MAX - 1)
enum nft_counter_attributes {
  NFTA_COUNTER_UNSPEC,
  NFTA_COUNTER_BYTES,
  NFTA_COUNTER_PACKETS,
  NFTA_COUNTER_PAD,
  __NFTA_COUNTER_MAX
};
#define NFTA_COUNTER_MAX (__NFTA_COUNTER_MAX - 1)
enum nft_last_attributes {
  NFTA_LAST_UNSPEC,
  NFTA_LAST_SET,
  NFTA_LAST_MSECS,
  NFTA_LAST_PAD,
  __NFTA_LAST_MAX
};
#define NFTA_LAST_MAX (__NFTA_LAST_MAX - 1)
enum nft_log_attributes {
  NFTA_LOG_UNSPEC,
  NFTA_LOG_GROUP,
  NFTA_LOG_PREFIX,
  NFTA_LOG_SNAPLEN,
  NFTA_LOG_QTHRESHOLD,
  NFTA_LOG_LEVEL,
  NFTA_LOG_FLAGS,
  __NFTA_LOG_MAX
};
#define NFTA_LOG_MAX (__NFTA_LOG_MAX - 1)
enum nft_log_level {
  NFT_LOGLEVEL_EMERG,
  NFT_LOGLEVEL_ALERT,
  NFT_LOGLEVEL_CRIT,
  NFT_LOGLEVEL_ERR,
  NFT_LOGLEVEL_WARNING,
  NFT_LOGLEVEL_NOTICE,
  NFT_LOGLEVEL_INFO,
  NFT_LOGLEVEL_DEBUG,
  NFT_LOGLEVEL_AUDIT,
  __NFT_LOGLEVEL_MAX
};
#define NFT_LOGLEVEL_MAX (__NFT_LOGLEVEL_MAX - 1)
enum nft_queue_attributes {
  NFTA_QUEUE_UNSPEC,
  NFTA_QUEUE_NUM,
  NFTA_QUEUE_TOTAL,
  NFTA_QUEUE_FLAGS,
  NFTA_QUEUE_SREG_QNUM,
  __NFTA_QUEUE_MAX
};
#define NFTA_QUEUE_MAX (__NFTA_QUEUE_MAX - 1)
#define NFT_QUEUE_FLAG_BYPASS 0x01
#define NFT_QUEUE_FLAG_CPU_FANOUT 0x02
#define NFT_QUEUE_FLAG_MASK 0x03
enum nft_quota_flags {
  NFT_QUOTA_F_INV = (1 << 0),
  NFT_QUOTA_F_DEPLETED = (1 << 1),
};
enum nft_quota_attributes {
  NFTA_QUOTA_UNSPEC,
  NFTA_QUOTA_BYTES,
  NFTA_QUOTA_FLAGS,
  NFTA_QUOTA_PAD,
  NFTA_QUOTA_CONSUMED,
  __NFTA_QUOTA_MAX
};
#define NFTA_QUOTA_MAX (__NFTA_QUOTA_MAX - 1)
enum nft_secmark_attributes {
  NFTA_SECMARK_UNSPEC,
  NFTA_SECMARK_CTX,
  __NFTA_SECMARK_MAX,
};
#define NFTA_SECMARK_MAX (__NFTA_SECMARK_MAX - 1)
#define NFT_SECMARK_CTX_MAXLEN 4096
enum nft_reject_types {
  NFT_REJECT_ICMP_UNREACH,
  NFT_REJECT_TCP_RST,
  NFT_REJECT_ICMPX_UNREACH,
};
enum nft_reject_inet_code {
  NFT_REJECT_ICMPX_NO_ROUTE = 0,
  NFT_REJECT_ICMPX_PORT_UNREACH,
  NFT_REJECT_ICMPX_HOST_UNREACH,
  NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
  __NFT_REJECT_ICMPX_MAX
};
#define NFT_REJECT_ICMPX_MAX (__NFT_REJECT_ICMPX_MAX - 1)
enum nft_reject_attributes {
  NFTA_REJECT_UNSPEC,
  NFTA_REJECT_TYPE,
  NFTA_REJECT_ICMP_CODE,
  __NFTA_REJECT_MAX
};
#define NFTA_REJECT_MAX (__NFTA_REJECT_MAX - 1)
enum nft_nat_types {
  NFT_NAT_SNAT,
  NFT_NAT_DNAT,
};
enum nft_nat_attributes {
  NFTA_NAT_UNSPEC,
  NFTA_NAT_TYPE,
  NFTA_NAT_FAMILY,
  NFTA_NAT_REG_ADDR_MIN,
  NFTA_NAT_REG_ADDR_MAX,
  NFTA_NAT_REG_PROTO_MIN,
  NFTA_NAT_REG_PROTO_MAX,
  NFTA_NAT_FLAGS,
  __NFTA_NAT_MAX
};
#define NFTA_NAT_MAX (__NFTA_NAT_MAX - 1)
enum nft_tproxy_attributes {
  NFTA_TPROXY_UNSPEC,
  NFTA_TPROXY_FAMILY,
  NFTA_TPROXY_REG_ADDR,
  NFTA_TPROXY_REG_PORT,
  __NFTA_TPROXY_MAX
};
#define NFTA_TPROXY_MAX (__NFTA_TPROXY_MAX - 1)
enum nft_masq_attributes {
  NFTA_MASQ_UNSPEC,
  NFTA_MASQ_FLAGS,
  NFTA_MASQ_REG_PROTO_MIN,
  NFTA_MASQ_REG_PROTO_MAX,
  __NFTA_MASQ_MAX
};
#define NFTA_MASQ_MAX (__NFTA_MASQ_MAX - 1)
enum nft_redir_attributes {
  NFTA_REDIR_UNSPEC,
  NFTA_REDIR_REG_PROTO_MIN,
  NFTA_REDIR_REG_PROTO_MAX,
  NFTA_REDIR_FLAGS,
  __NFTA_REDIR_MAX
};
#define NFTA_REDIR_MAX (__NFTA_REDIR_MAX - 1)
enum nft_dup_attributes {
  NFTA_DUP_UNSPEC,
  NFTA_DUP_SREG_ADDR,
  NFTA_DUP_SREG_DEV,
  __NFTA_DUP_MAX
};
#define NFTA_DUP_MAX (__NFTA_DUP_MAX - 1)
enum nft_fwd_attributes {
  NFTA_FWD_UNSPEC,
  NFTA_FWD_SREG_DEV,
  NFTA_FWD_SREG_ADDR,
  NFTA_FWD_NFPROTO,
  __NFTA_FWD_MAX
};
#define NFTA_FWD_MAX (__NFTA_FWD_MAX - 1)
enum nft_objref_attributes {
  NFTA_OBJREF_UNSPEC,
  NFTA_OBJREF_IMM_TYPE,
  NFTA_OBJREF_IMM_NAME,
  NFTA_OBJREF_SET_SREG,
  NFTA_OBJREF_SET_NAME,
  NFTA_OBJREF_SET_ID,
  __NFTA_OBJREF_MAX
};
#define NFTA_OBJREF_MAX (__NFTA_OBJREF_MAX - 1)
enum nft_gen_attributes {
  NFTA_GEN_UNSPEC,
  NFTA_GEN_ID,
  NFTA_GEN_PROC_PID,
  NFTA_GEN_PROC_NAME,
  __NFTA_GEN_MAX
};
#define NFTA_GEN_MAX (__NFTA_GEN_MAX - 1)
enum nft_fib_attributes {
  NFTA_FIB_UNSPEC,
  NFTA_FIB_DREG,
  NFTA_FIB_RESULT,
  NFTA_FIB_FLAGS,
  __NFTA_FIB_MAX
};
#define NFTA_FIB_MAX (__NFTA_FIB_MAX - 1)
enum nft_fib_result {
  NFT_FIB_RESULT_UNSPEC,
  NFT_FIB_RESULT_OIF,
  NFT_FIB_RESULT_OIFNAME,
  NFT_FIB_RESULT_ADDRTYPE,
  __NFT_FIB_RESULT_MAX
};
#define NFT_FIB_RESULT_MAX (__NFT_FIB_RESULT_MAX - 1)
enum nft_fib_flags {
  NFTA_FIB_F_SADDR = 1 << 0,
  NFTA_FIB_F_DADDR = 1 << 1,
  NFTA_FIB_F_MARK = 1 << 2,
  NFTA_FIB_F_IIF = 1 << 3,
  NFTA_FIB_F_OIF = 1 << 4,
  NFTA_FIB_F_PRESENT = 1 << 5,
};
enum nft_ct_helper_attributes {
  NFTA_CT_HELPER_UNSPEC,
  NFTA_CT_HELPER_NAME,
  NFTA_CT_HELPER_L3PROTO,
  NFTA_CT_HELPER_L4PROTO,
  __NFTA_CT_HELPER_MAX,
};
#define NFTA_CT_HELPER_MAX (__NFTA_CT_HELPER_MAX - 1)
enum nft_ct_timeout_timeout_attributes {
  NFTA_CT_TIMEOUT_UNSPEC,
  NFTA_CT_TIMEOUT_L3PROTO,
  NFTA_CT_TIMEOUT_L4PROTO,
  NFTA_CT_TIMEOUT_DATA,
  __NFTA_CT_TIMEOUT_MAX,
};
#define NFTA_CT_TIMEOUT_MAX (__NFTA_CT_TIMEOUT_MAX - 1)
enum nft_ct_expectation_attributes {
  NFTA_CT_EXPECT_UNSPEC,
  NFTA_CT_EXPECT_L3PROTO,
  NFTA_CT_EXPECT_L4PROTO,
  NFTA_CT_EXPECT_DPORT,
  NFTA_CT_EXPECT_TIMEOUT,
  NFTA_CT_EXPECT_SIZE,
  __NFTA_CT_EXPECT_MAX,
};
#define NFTA_CT_EXPECT_MAX (__NFTA_CT_EXPECT_MAX - 1)
#define NFT_OBJECT_UNSPEC 0
#define NFT_OBJECT_COUNTER 1
#define NFT_OBJECT_QUOTA 2
#define NFT_OBJECT_CT_HELPER 3
#define NFT_OBJECT_LIMIT 4
#define NFT_OBJECT_CONNLIMIT 5
#define NFT_OBJECT_TUNNEL 6
#define NFT_OBJECT_CT_TIMEOUT 7
#define NFT_OBJECT_SECMARK 8
#define NFT_OBJECT_CT_EXPECT 9
#define NFT_OBJECT_SYNPROXY 10
#define __NFT_OBJECT_MAX 11
#define NFT_OBJECT_MAX (__NFT_OBJECT_MAX - 1)
enum nft_object_attributes {
  NFTA_OBJ_UNSPEC,
  NFTA_OBJ_TABLE,
  NFTA_OBJ_NAME,
  NFTA_OBJ_TYPE,
  NFTA_OBJ_DATA,
  NFTA_OBJ_USE,
  NFTA_OBJ_HANDLE,
  NFTA_OBJ_PAD,
  NFTA_OBJ_USERDATA,
  __NFTA_OBJ_MAX
};
#define NFTA_OBJ_MAX (__NFTA_OBJ_MAX - 1)
enum nft_flowtable_flags {
  NFT_FLOWTABLE_HW_OFFLOAD = 0x1,
  NFT_FLOWTABLE_COUNTER = 0x2,
  NFT_FLOWTABLE_MASK = (NFT_FLOWTABLE_HW_OFFLOAD | NFT_FLOWTABLE_COUNTER)
};
enum nft_flowtable_attributes {
  NFTA_FLOWTABLE_UNSPEC,
  NFTA_FLOWTABLE_TABLE,
  NFTA_FLOWTABLE_NAME,
  NFTA_FLOWTABLE_HOOK,
  NFTA_FLOWTABLE_USE,
  NFTA_FLOWTABLE_HANDLE,
  NFTA_FLOWTABLE_PAD,
  NFTA_FLOWTABLE_FLAGS,
  __NFTA_FLOWTABLE_MAX
};
#define NFTA_FLOWTABLE_MAX (__NFTA_FLOWTABLE_MAX - 1)
enum nft_flowtable_hook_attributes {
  NFTA_FLOWTABLE_HOOK_UNSPEC,
  NFTA_FLOWTABLE_HOOK_NUM,
  NFTA_FLOWTABLE_HOOK_PRIORITY,
  NFTA_FLOWTABLE_HOOK_DEVS,
  __NFTA_FLOWTABLE_HOOK_MAX
};
#define NFTA_FLOWTABLE_HOOK_MAX (__NFTA_FLOWTABLE_HOOK_MAX - 1)
enum nft_osf_attributes {
  NFTA_OSF_UNSPEC,
  NFTA_OSF_DREG,
  NFTA_OSF_TTL,
  NFTA_OSF_FLAGS,
  __NFTA_OSF_MAX,
};
#define NFTA_OSF_MAX (__NFTA_OSF_MAX - 1)
enum nft_osf_flags {
  NFT_OSF_F_VERSION = (1 << 0),
};
enum nft_synproxy_attributes {
  NFTA_SYNPROXY_UNSPEC,
  NFTA_SYNPROXY_MSS,
  NFTA_SYNPROXY_WSCALE,
  NFTA_SYNPROXY_FLAGS,
  __NFTA_SYNPROXY_MAX,
};
#define NFTA_SYNPROXY_MAX (__NFTA_SYNPROXY_MAX - 1)
enum nft_devices_attributes {
  NFTA_DEVICE_UNSPEC,
  NFTA_DEVICE_NAME,
  __NFTA_DEVICE_MAX
};
#define NFTA_DEVICE_MAX (__NFTA_DEVICE_MAX - 1)
enum nft_xfrm_attributes {
  NFTA_XFRM_UNSPEC,
  NFTA_XFRM_DREG,
  NFTA_XFRM_KEY,
  NFTA_XFRM_DIR,
  NFTA_XFRM_SPNUM,
  __NFTA_XFRM_MAX
};
#define NFTA_XFRM_MAX (__NFTA_XFRM_MAX - 1)
enum nft_xfrm_keys {
  NFT_XFRM_KEY_UNSPEC,
  NFT_XFRM_KEY_DADDR_IP4,
  NFT_XFRM_KEY_DADDR_IP6,
  NFT_XFRM_KEY_SADDR_IP4,
  NFT_XFRM_KEY_SADDR_IP6,
  NFT_XFRM_KEY_REQID,
  NFT_XFRM_KEY_SPI,
  __NFT_XFRM_KEY_MAX,
};
#define NFT_XFRM_KEY_MAX (__NFT_XFRM_KEY_MAX - 1)
enum nft_trace_attributes {
  NFTA_TRACE_UNSPEC,
  NFTA_TRACE_TABLE,
  NFTA_TRACE_CHAIN,
  NFTA_TRACE_RULE_HANDLE,
  NFTA_TRACE_TYPE,
  NFTA_TRACE_VERDICT,
  NFTA_TRACE_ID,
  NFTA_TRACE_LL_HEADER,
  NFTA_TRACE_NETWORK_HEADER,
  NFTA_TRACE_TRANSPORT_HEADER,
  NFTA_TRACE_IIF,
  NFTA_TRACE_IIFTYPE,
  NFTA_TRACE_OIF,
  NFTA_TRACE_OIFTYPE,
  NFTA_TRACE_MARK,
  NFTA_TRACE_NFPROTO,
  NFTA_TRACE_POLICY,
  NFTA_TRACE_PAD,
  __NFTA_TRACE_MAX
};
#define NFTA_TRACE_MAX (__NFTA_TRACE_MAX - 1)
enum nft_trace_types {
  NFT_TRACETYPE_UNSPEC,
  NFT_TRACETYPE_POLICY,
  NFT_TRACETYPE_RETURN,
  NFT_TRACETYPE_RULE,
  __NFT_TRACETYPE_MAX
};
#define NFT_TRACETYPE_MAX (__NFT_TRACETYPE_MAX - 1)
enum nft_ng_attributes {
  NFTA_NG_UNSPEC,
  NFTA_NG_DREG,
  NFTA_NG_MODULUS,
  NFTA_NG_TYPE,
  NFTA_NG_OFFSET,
  NFTA_NG_SET_NAME,
  NFTA_NG_SET_ID,
  __NFTA_NG_MAX
};
#define NFTA_NG_MAX (__NFTA_NG_MAX - 1)
enum nft_ng_types {
  NFT_NG_INCREMENTAL,
  NFT_NG_RANDOM,
  __NFT_NG_MAX
};
#define NFT_NG_MAX (__NFT_NG_MAX - 1)
enum nft_tunnel_key_ip_attributes {
  NFTA_TUNNEL_KEY_IP_UNSPEC,
  NFTA_TUNNEL_KEY_IP_SRC,
  NFTA_TUNNEL_KEY_IP_DST,
  __NFTA_TUNNEL_KEY_IP_MAX
};
#define NFTA_TUNNEL_KEY_IP_MAX (__NFTA_TUNNEL_KEY_IP_MAX - 1)
enum nft_tunnel_ip6_attributes {
  NFTA_TUNNEL_KEY_IP6_UNSPEC,
  NFTA_TUNNEL_KEY_IP6_SRC,
  NFTA_TUNNEL_KEY_IP6_DST,
  NFTA_TUNNEL_KEY_IP6_FLOWLABEL,
  __NFTA_TUNNEL_KEY_IP6_MAX
};
#define NFTA_TUNNEL_KEY_IP6_MAX (__NFTA_TUNNEL_KEY_IP6_MAX - 1)
enum nft_tunnel_opts_attributes {
  NFTA_TUNNEL_KEY_OPTS_UNSPEC,
  NFTA_TUNNEL_KEY_OPTS_VXLAN,
  NFTA_TUNNEL_KEY_OPTS_ERSPAN,
  NFTA_TUNNEL_KEY_OPTS_GENEVE,
  __NFTA_TUNNEL_KEY_OPTS_MAX
};
#define NFTA_TUNNEL_KEY_OPTS_MAX (__NFTA_TUNNEL_KEY_OPTS_MAX - 1)
enum nft_tunnel_opts_vxlan_attributes {
  NFTA_TUNNEL_KEY_VXLAN_UNSPEC,
  NFTA_TUNNEL_KEY_VXLAN_GBP,
  __NFTA_TUNNEL_KEY_VXLAN_MAX
};
#define NFTA_TUNNEL_KEY_VXLAN_MAX (__NFTA_TUNNEL_KEY_VXLAN_MAX - 1)
enum nft_tunnel_opts_erspan_attributes {
  NFTA_TUNNEL_KEY_ERSPAN_UNSPEC,
  NFTA_TUNNEL_KEY_ERSPAN_VERSION,
  NFTA_TUNNEL_KEY_ERSPAN_V1_INDEX,
  NFTA_TUNNEL_KEY_ERSPAN_V2_HWID,
  NFTA_TUNNEL_KEY_ERSPAN_V2_DIR,
  __NFTA_TUNNEL_KEY_ERSPAN_MAX
};
#define NFTA_TUNNEL_KEY_ERSPAN_MAX (__NFTA_TUNNEL_KEY_ERSPAN_MAX - 1)
enum nft_tunnel_opts_geneve_attributes {
  NFTA_TUNNEL_KEY_GENEVE_UNSPEC,
  NFTA_TUNNEL_KEY_GENEVE_CLASS,
  NFTA_TUNNEL_KEY_GENEVE_TYPE,
  NFTA_TUNNEL_KEY_GENEVE_DATA,
  __NFTA_TUNNEL_KEY_GENEVE_MAX
};
#define NFTA_TUNNEL_KEY_GENEVE_MAX (__NFTA_TUNNEL_KEY_GENEVE_MAX - 1)
enum nft_tunnel_flags {
  NFT_TUNNEL_F_ZERO_CSUM_TX = (1 << 0),
  NFT_TUNNEL_F_DONT_FRAGMENT = (1 << 1),
  NFT_TUNNEL_F_SEQ_NUMBER = (1 << 2),
};
#define NFT_TUNNEL_F_MASK (NFT_TUNNEL_F_ZERO_CSUM_TX | NFT_TUNNEL_F_DONT_FRAGMENT | NFT_TUNNEL_F_SEQ_NUMBER)
enum nft_tunnel_key_attributes {
  NFTA_TUNNEL_KEY_UNSPEC,
  NFTA_TUNNEL_KEY_ID,
  NFTA_TUNNEL_KEY_IP,
  NFTA_TUNNEL_KEY_IP6,
  NFTA_TUNNEL_KEY_FLAGS,
  NFTA_TUNNEL_KEY_TOS,
  NFTA_TUNNEL_KEY_TTL,
  NFTA_TUNNEL_KEY_SPORT,
  NFTA_TUNNEL_KEY_DPORT,
  NFTA_TUNNEL_KEY_OPTS,
  __NFTA_TUNNEL_KEY_MAX
};
#define NFTA_TUNNEL_KEY_MAX (__NFTA_TUNNEL_KEY_MAX - 1)
enum nft_tunnel_keys {
  NFT_TUNNEL_PATH,
  NFT_TUNNEL_ID,
  __NFT_TUNNEL_MAX
};
#define NFT_TUNNEL_MAX (__NFT_TUNNEL_MAX - 1)
enum nft_tunnel_mode {
  NFT_TUNNEL_MODE_NONE,
  NFT_TUNNEL_MODE_RX,
  NFT_TUNNEL_MODE_TX,
  __NFT_TUNNEL_MODE_MAX
};
#define NFT_TUNNEL_MODE_MAX (__NFT_TUNNEL_MODE_MAX - 1)
enum nft_tunnel_attributes {
  NFTA_TUNNEL_UNSPEC,
  NFTA_TUNNEL_KEY,
  NFTA_TUNNEL_DREG,
  NFTA_TUNNEL_MODE,
  __NFTA_TUNNEL_MAX
};
#define NFTA_TUNNEL_MAX (__NFTA_TUNNEL_MAX - 1)
#endif
```