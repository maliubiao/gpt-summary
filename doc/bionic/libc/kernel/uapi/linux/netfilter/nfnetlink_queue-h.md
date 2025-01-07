Response:
Let's break down the thought process for answering this complex request about the `nfnetlink_queue.h` header file.

**1. Understanding the Core Request:**

The central goal is to analyze the provided C header file and explain its functionality within the context of Android's Bionic library. The request also asks for specific details like how libc functions work, dynamic linker aspects, potential errors, and how Android frameworks interact with this code.

**2. Initial Analysis of the Header File:**

* **`auto-generated`:** This immediately tells me this isn't code a developer typically writes directly. It's likely generated from some other definition (like a kernel header). This is important because the focus should be on the *meaning* of the definitions, not low-level implementation details within *this specific file*.
* **`#ifndef _NFNETLINK_QUEUE_H`:** This is a standard include guard, preventing multiple inclusions.
* **Includes:**  `linux/types.h` and `linux/netfilter/nfnetlink.h` indicate this file deals with low-level network operations within the Linux kernel. Specifically, Netfilter and its Netlink interface.
* **Enums and Structs:**  The file defines various enums (`nfqnl_msg_types`, `nfqnl_vlan_attr`, `nfqnl_attr_type`, etc.) and structs (`nfqnl_msg_packet_hdr`, `nfqnl_msg_packet_hw`, etc.). These represent data structures and message types used in the Netfilter queueing system. The names clearly suggest their purpose (e.g., `nfqnl_msg_packet_hdr` likely holds the header information of a queued packet).
* **`__attribute__((packed))` and `__aligned_be64`:** These indicate specific memory layout requirements, often used in low-level communication and data structures passed between the kernel and user space. `packed` means no padding between members, and `aligned_be64` suggests big-endian 64-bit alignment.
* **Macros:**  `NFQA_VLAN_MAX`, `NFQA_MAX`, etc., define maximum values for the enums, a common practice. `NFQA_CFG_F_*` and `NFQA_SKB_*` look like bit flags.

**3. Connecting to Android and Bionic:**

* **Bionic's Role:**  Bionic is Android's C library, providing essential system calls and low-level functionalities. Kernel headers within Bionic's `libc/kernel/uapi` expose the kernel's interface to user-space applications. This header file allows Android processes to interact with Netfilter's queueing mechanism.
* **Android Functionality:** Netfilter is a core component of Linux's networking stack, used for packet filtering, NAT, and more. In Android, it's crucial for implementing firewalls, VPNs, traffic shaping, and network monitoring tools. The queueing mechanism (`nfnetlink_queue`) allows user-space applications to intercept and manipulate network packets.

**4. Addressing Specific Request Points:**

* **Functionality Listing:** Based on the enums and structs, the core functionality is about defining data structures and message types for:
    * Packet information (header, hardware address, timestamp, payload).
    * Verdicts (actions to take on packets).
    * Configuration of the queueing mechanism.
* **Android Relationship and Examples:**  Focus on concrete use cases within Android:
    * **Firewall Apps:**  Interception and blocking of malicious traffic.
    * **VPN Apps:**  Forwarding traffic through a tunnel.
    * **Network Monitoring Apps:**  Analyzing network traffic.
* **libc Function Explanation:** This is where careful wording is crucial. This *header file* doesn't *implement* libc functions. It defines data structures used by *other* code that *uses* libc functions. So, explain the *types* of libc functions likely involved (socket creation, sending/receiving data, memory management) and how they'd be used in the context of Netlink communication.
* **Dynamic Linker:** Again, this header doesn't directly involve the dynamic linker. Focus on *where* the code using these structures would reside (likely in shared libraries like `libnetfilter_queue.so`) and how the dynamic linker would load them. Provide a simplified SO layout and the linking process.
* **Logical Reasoning:**  For the example, choose a simple scenario like a packet being queued and then a verdict being sent. Map the input and output to the defined structs.
* **User Errors:** Think about common mistakes developers might make when interacting with Netlink and Netfilter, such as incorrect data structure packing, missing attributes, or improper error handling.
* **Android Framework/NDK Path:** Trace the likely path:
    * **NDK:** Direct use of Netlink libraries.
    * **Framework:**  Higher-level APIs wrapping the NDK or even interacting with system services that use Netfilter.
* **Frida Hook:** Provide a basic Frida example targeting a function that likely interacts with the Netfilter queue (e.g., sending a verdict).

**5. Structuring the Answer:**

Organize the information logically, following the order of the request. Use clear headings and bullet points to improve readability.

**6. Refinement and Language:**

* **Accuracy:** Ensure technical correctness. Double-check the meaning of the structs and enums.
* **Clarity:** Explain concepts in a way that is easy to understand, even for someone not deeply familiar with Netfilter.
* **Conciseness:** Avoid unnecessary jargon or overly verbose explanations.
* **Chinese Language:**  Ensure proper and natural-sounding Chinese translation.

**Self-Correction/Improvements during the thought process:**

* **Initial thought:**  Perhaps I should explain the bitwise operations on the flag macros. **Correction:** While important, it might be too much detail for the general request. Focus on the *purpose* of the flags.
* **Initial thought:**  Should I provide a detailed code example of using the structures? **Correction:** The request is about the header file itself. A high-level example of how it's used is sufficient. Focus on concepts rather than extensive code.
* **Initial thought:**  Explain the intricacies of Netlink socket programming. **Correction:** Keep it high-level. Mention socket creation and sending/receiving, but don't delve into the details of Netlink message headers.

By following these steps and continually refining the approach, we can generate a comprehensive and accurate answer to the user's request.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/netfilter/nfnetlink_queue.h` 这个头文件。

**功能列举:**

这个头文件定义了 Linux 内核中 Netfilter 队列 (nfnetlink_queue) 子系统的用户空间 API 的数据结构和常量。它的主要功能是：

1. **定义了与 Netfilter 队列交互的消息类型:**  `enum nfqnl_msg_types` 定义了用户空间程序与内核通信的不同消息类型，例如发送数据包、发送裁决（允许/丢弃数据包）、配置队列等。

2. **定义了数据包相关信息的结构体:**
   - `struct nfqnl_msg_packet_hdr`: 描述了队列中数据包的基本头部信息，如数据包 ID、硬件协议类型、Netfilter 钩子点。
   - `struct nfqnl_msg_packet_hw`: 描述了数据包的硬件地址信息。
   - `struct nfqnl_msg_packet_timestamp`: 描述了数据包到达的时间戳。

3. **定义了 VLAN 相关的属性:** `enum nfqnl_vlan_attr` 定义了与 VLAN (Virtual LAN) 相关的属性类型，用于描述数据包的 VLAN 信息。

4. **定义了 Netfilter 队列消息的属性类型:** `enum nfqnl_attr_type` 定义了 Netfilter 队列消息中可以包含的各种属性类型，例如数据包头部、裁决头部、标记、时间戳、接口索引、硬件地址、数据包载荷等等。这允许在 Netlink 消息中携带各种类型的信息。

5. **定义了裁决 (Verdict) 相关的结构体:** `struct nfqnl_msg_verdict_hdr` 定义了用户空间发送给内核的裁决信息，包含对数据包的处理决定 (例如 `ACCEPT` 或 `DROP`) 和对应的数据包 ID。

6. **定义了配置队列相关的结构体和枚举:**
   - `enum nfqnl_msg_config_cmds`: 定义了用于配置 Netfilter 队列的命令类型，如绑定协议族、解绑协议族等。
   - `struct nfqnl_msg_config_cmd`: 描述了配置命令的具体内容，如命令类型和协议族。
   - `enum nfqnl_config_mode`: 定义了拷贝数据包的方式，例如不拷贝、只拷贝元数据、拷贝整个数据包。
   - `struct nfqnl_msg_config_params`: 描述了配置参数，如拷贝范围和拷贝模式。
   - `enum nfqnl_attr_config`: 定义了配置消息中可以包含的属性类型，如命令、参数、队列最大长度等。
   - 定义了配置标志位，如 `NFQA_CFG_F_FAIL_OPEN` (失败打开)、`NFQA_CFG_F_CONNTRACK` (连接跟踪) 等。

7. **定义了 SKB (Socket Buffer) 相关的标志位:** 例如 `NFQA_SKB_CSUMNOTREADY` (校验和未就绪) 和 `NFQA_SKB_GSO` (通用分段卸载)。

**与 Android 功能的关系及举例说明:**

Netfilter 是 Linux 内核的网络防火墙框架，Android 作为基于 Linux 内核的操作系统，自然也使用了 Netfilter。 `nfnetlink_queue` 允许用户空间的应用程序注册一个队列，并将满足特定规则的网络数据包转发到该队列进行处理。

**Android 中的应用场景举例:**

* **防火墙应用 (Firewall Apps):**  Android 上的防火墙应用可以使用 `nfnetlink_queue` 来拦截网络数据包，并根据用户设定的规则决定是否允许或阻止这些数据包的传输。例如，一个防火墙应用可以注册一个队列来接收所有发往特定端口的数据包，然后根据应用白名单或黑名单来决定是否将数据包放行。

* **VPN 应用 (VPN Apps):** VPN 应用可以使用 `nfnetlink_queue` 来拦截所有出站或入站的网络流量，并在将其发送到 VPN 服务器之前对其进行加密。

* **网络监控应用 (Network Monitoring Apps):** 网络监控应用可以利用 `nfnetlink_queue` 来捕获网络数据包，并进行流量分析、统计等操作。

* **数据包修改或注入:**  虽然不常见于普通应用，但一些高级的网络工具可能会使用 `nfnetlink_queue` 来修改或甚至注入新的网络数据包。

**libc 函数功能实现详细解释:**

这个头文件本身 **没有实现任何 libc 函数**。它只是定义了数据结构和常量。实际使用这些定义的代码，通常会调用以下类型的 libc 函数：

* **Socket 函数:**
    * `socket()`: 创建 Netlink 套接字，用于与内核的 Netfilter 队列子系统通信。
    * `bind()`: 将套接字绑定到特定的 Netlink 协议族和组播组。
    * `send()`/`sendto()`: 向内核发送 Netlink 消息，例如发送裁决或配置命令。
    * `recv()`/`recvfrom()`: 从内核接收 Netlink 消息，例如接收被队列的数据包。
    * `close()`: 关闭 Netlink 套接字。

* **内存管理函数:**
    * `malloc()`/`calloc()`:  分配内存来存储接收到的数据包或构建要发送的消息。
    * `free()`: 释放已分配的内存。
    * `memcpy()`: 复制数据，例如复制接收到的数据包内容。

* **字节序转换函数 (如果需要跨平台兼容):**
    * `htonl()`/`htons()`: 将主机字节序转换为网络字节序 (大端)。
    * `ntohl()`/`ntohs()`: 将网络字节序转换为主机字节序。  但请注意，这里很多字段已经是 `__be32` 或 `__be16`，表明它们已经是大端序，可能不需要显式转换，或者是在内核层面处理的。

* **错误处理函数:**
    * `perror()`: 打印错误信息。
    * `strerror()`: 获取错误码对应的错误字符串。

**对于涉及 dynamic linker 的功能，对应的 so 布局样本以及链接的处理过程:**

这个头文件本身 **不直接涉及 dynamic linker** 的功能。它只是定义了内核 API 的数据结构。 然而，使用这些定义的代码通常会存在于共享库 (`.so`) 中。

**so 布局样本 (假设一个名为 `libnetfilter_queue.so` 的库使用了这些定义):**

```
libnetfilter_queue.so:
    .init             # 初始化代码段
    .plt              # 程序链接表
    .text             # 代码段，包含使用上面定义的结构体的函数
        - 函数A: 创建并绑定 Netlink 套接字
        - 函数B: 发送裁决消息
        - 函数C: 接收队列中的数据包
        - ...
    .rodata           # 只读数据段，可能包含一些常量
    .data             # 可读写数据段，可能包含全局变量
    .bss              # 未初始化数据段
    .dynamic          # 动态链接信息
    .symtab           # 符号表
    .strtab           # 字符串表
    ... 其他段
```

**链接的处理过程:**

1. **编译时:**  当开发者编写使用 Netfilter 队列 API 的代码时，编译器会包含 `nfnetlink_queue.h` 头文件，以便了解相关的数据结构定义。

2. **链接时:**
   - 如果代码直接调用了与 Netfilter 队列交互的系统调用（例如 `socket`，尽管通常会使用封装好的库），则链接器会将代码与 Bionic 提供的 libc 链接。
   - 更常见的情况是，开发者会使用一个专门的库，例如 `libnetfilter_queue.so`。 在链接时，链接器会将应用程序与 `libnetfilter_queue.so` 链接。  这需要在编译或链接命令中指定 `-lnetfilter_queue`。

3. **运行时:**
   - 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有需要的共享库，包括 `libnetfilter_queue.so`。
   - Dynamic linker 会解析 `libnetfilter_queue.so` 的 `.dynamic` 段，找到其依赖的其他库（例如 libc）。
   - Dynamic linker 会将 `libnetfilter_queue.so` 加载到内存中的合适地址。
   - Dynamic linker 会解析应用程序的 `.plt` (Procedure Linkage Table) 和 `libnetfilter_queue.so` 的 `.got.plt` (Global Offset Table)，来解决函数调用的地址。当应用程序调用 `libnetfilter_queue.so` 中的函数时，实际上是通过 PLT 跳转到 GOT 表中的地址，而 GOT 表中的地址在首次调用时会被 dynamic linker 更新为函数的实际地址。

**逻辑推理，假设输入与输出:**

**假设输入:**

* 用户空间程序创建了一个 Netfilter 队列，并设置了规则，将所有发往 80 端口的 TCP 数据包都转发到该队列。
* 内核接收到一个发往目标地址 `192.168.1.100:80` 的 TCP 数据包。

**处理过程:**

1. 由于设置了规则，内核会将该数据包的信息封装到一个 `nfqnl_msg_packet` 消息中。
2. 该消息会包含一个 `nfqnl_msg_packet_hdr` 结构体，其中：
   - `packet_id`: 例如 `12345` (内核分配的唯一 ID)。
   - `hw_protocol`:  表示以太网协议，例如 `htons(ETH_P_IP)`。
   - `hook`:  表示数据包被捕获的 Netfilter 钩子点，例如 `NF_INET_LOCAL_IN`。
3. 消息还会包含其他属性，例如 `NFQA_PAYLOAD` 包含原始数据包的内容， `NFQA_IFINDEX_INDEV` 包含接收数据包的接口索引等。
4. 内核通过 Netlink 套接字将这个消息发送给注册了该队列的用户空间程序。

**用户空间程序的处理 (假设要丢弃该数据包):**

1. 用户空间程序接收到包含 `nfqnl_msg_packet` 消息的 Netlink 数据包。
2. 程序解析消息，提取 `packet_id` (例如 `12345`)。
3. 程序创建一个 `nfqnl_msg_verdict` 消息。
4. 该消息包含一个 `nfqnl_msg_verdict_hdr` 结构体，其中：
   - `verdict`: 设置为表示丢弃数据包的值，例如 `htonl(NF_DROP)`。
   - `id`: 设置为接收到的数据包 ID，即 `htonl(12345)`。
5. 用户空间程序通过 Netlink 套接字将该裁决消息发送回内核。

**输出:**

* 内核收到裁决消息后，会根据 `packet_id` 找到对应的数据包，并执行 `NF_DROP` 操作，即丢弃该数据包，不会将其发送到目标地址。

**用户或编程常见的使用错误:**

1. **未正确处理字节序:** Netlink 消息中的某些字段使用网络字节序 (大端)，如果用户空间程序没有正确进行字节序转换，会导致解析错误或内核行为异常。

2. **消息结构体打包问题:**  `__attribute__((packed))` 指示编译器不要在结构体成员之间添加填充字节。如果用户空间程序构建消息时假设存在填充，或者使用错误的结构体定义，会导致数据错位。

3. **遗漏必要的属性:** 某些操作可能需要特定的属性才能成功。例如，发送裁决时必须包含正确的 `packet_id`。

4. **不正确的 Netlink 套接字设置:**  创建和绑定 Netlink 套接字时需要指定正确的协议族 (`NETLINK_NETFILTER`) 和组播组 (`NF_NETLINK_QUEUE`)。

5. **忘记处理错误:**  与内核通信可能会失败，例如由于权限问题或队列已满。用户空间程序需要检查 `send()` 和 `recv()` 等函数的返回值，并进行适当的错误处理。

6. **资源泄漏:**  如果用户空间程序没有正确关闭 Netlink 套接字或释放分配的内存，可能会导致资源泄漏。

7. **竞争条件:**  在多线程或多进程环境中，访问共享的 Netlink 套接字或队列资源时需要进行适当的同步，以避免竞争条件。

**Frida Hook 示例调试步骤:**

假设我们要 hook 一个 Android 应用中用于发送 Netfilter 队列裁决的函数。通常，这个应用可能会使用一个封装了 Netlink 通信的库，例如 `libnetfilter_queue.so`。

**假设目标函数:** `nfq_set_verdict` (这是一个虚构的函数名，实际库的函数名可能不同)。

**Frida Hook 脚本示例:**

```javascript
// 假设 libnetfilter_queue.so 被加载到内存中
const libnetfilter_queue = Process.getModuleByName("libnetfilter_queue.so");

// 假设 nfq_set_verdict 函数的地址已知或可以通过符号找到
const nfqSetVerdictPtr = libnetfilter_queue.findExportByName("nfq_set_verdict");

if (nfqSetVerdictPtr) {
  Interceptor.attach(nfqSetVerdictPtr, {
    onEnter: function (args) {
      // 打印函数参数
      console.log("nfq_set_verdict called!");
      console.log("  queue_num:", args[0]); // 第一个参数
      console.log("  id:", args[1]);      // 第二个参数
      console.log("  verdict:", args[2]);  // 第三个参数

      // 你可以在这里修改参数，例如强制放行数据包
      // args[2] = ptr(0x...). // 假设 0x... 是 NF_ACCEPT 的值

      // 读取 verdict 的值 (假设 verdict 是一个 32 位整数)
      const verdict = args[2].toInt();
      if (verdict === /* 代表丢弃的值 */) {
        console.log("  Detected a DROP verdict!");
      }
    },
    onLeave: function (retval) {
      console.log("nfq_set_verdict returned:", retval);
    },
  });
} else {
  console.log("nfq_set_verdict function not found.");
}
```

**调试步骤:**

1. **找到目标进程:** 使用 `frida-ps -U` 或 `frida-ps -D <device_id>` 找到目标 Android 应用的进程 ID。

2. **运行 Frida 脚本:** 使用 `frida -U -f <package_name> -l your_script.js` 或 `frida -U <process_id> -l your_script.js` 来注入并运行 Frida 脚本。

3. **触发网络事件:**  在 Android 设备上执行一些操作，以触发目标应用发送网络数据包，并被 Netfilter 队列捕获。

4. **观察 Frida 输出:**  Frida 脚本会在 `nfq_set_verdict` 函数被调用时打印相关信息，包括函数参数。你可以根据这些信息来分析应用的行为，例如它对哪些数据包发送了什么样的裁决。

5. **修改参数 (可选):**  在 `onEnter` 中，你可以尝试修改函数的参数，例如强制将裁决结果改为 `ACCEPT`，来观察修改后的效果。

6. **定位关键代码:** 通过 Frida 的 hook 输出，你可以更准确地定位到应用中负责处理 Netfilter 队列和发送裁决的代码位置，从而进行更深入的分析和调试。

**说明 Android Framework 或 NDK 是如何一步步到达这里的:**

**NDK (Native Development Kit) 路径:**

1. **应用程序代码:**  开发者使用 NDK 编写 C/C++ 代码，这些代码需要与 Netfilter 队列交互。
2. **使用 Netfilter 队列库:**  开发者可能会链接到像 `libnetfilter_queue.so` 这样的库，该库封装了与内核 Netfilter 队列通信的细节。
3. **系统调用或库函数:** `libnetfilter_queue.so` 内部会使用 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等 libc 函数来创建 Netlink 套接字并与内核通信。
4. **Netlink 协议:** 这些 libc 函数会将数据封装成 Netlink 消息，消息的格式由 `nfnetlink_queue.h` 中定义的结构体来描述。
5. **内核 Netfilter 队列子系统:**  Netlink 消息被发送到内核，内核的 Netfilter 队列子系统会解析这些消息，并执行相应的操作（例如接收数据包、发送裁决、配置队列）。

**Android Framework 路径:**

1. **Java Framework API:**  Android Framework 提供了一些 Java API，例如 `VpnService` 或 `NetworkStatsManager`，这些 API 在底层可能需要与网络层进行交互。
2. **System Services:**  Framework API 的实现通常会调用底层的 System Services (例如 `NetworkManagementService`).
3. **Native 代码 (C/C++):**  System Services 往往由 C/C++ 代码实现。这些 native 代码可能会直接使用 NDK 提供的 Netlink 接口，或者使用更高级的抽象层。
4. **AIDL 接口:**  Framework 和 System Services 之间可能通过 AIDL (Android Interface Definition Language) 定义的接口进行通信。
5. **Netlink 或其他 IPC 机制:**  System Services 的 native 代码最终会使用 Netlink 套接字（或者其他进程间通信机制）与内核的 Netfilter 队列子系统通信。  使用的 Netlink 消息格式仍然遵循 `nfnetlink_queue.h` 的定义。

**总结:**

无论是通过 NDK 还是 Android Framework，与 Netfilter 队列的交互最终都会涉及使用 Netlink 协议，而 `nfnetlink_queue.h` 定义了用户空间和内核空间之间通信所使用的核心数据结构。  NDK 路径通常更直接，开发者可以更底层地控制 Netlink 通信。 Framework 路径则提供了更高级的抽象，隐藏了底层的 Netlink 细节，但最终的实现仍然依赖于这些底层的机制。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter/nfnetlink_queue.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _NFNETLINK_QUEUE_H
#define _NFNETLINK_QUEUE_H
#include <linux/types.h>
#include <linux/netfilter/nfnetlink.h>
enum nfqnl_msg_types {
  NFQNL_MSG_PACKET,
  NFQNL_MSG_VERDICT,
  NFQNL_MSG_CONFIG,
  NFQNL_MSG_VERDICT_BATCH,
  NFQNL_MSG_MAX
};
struct nfqnl_msg_packet_hdr {
  __be32 packet_id;
  __be16 hw_protocol;
  __u8 hook;
} __attribute__((packed));
struct nfqnl_msg_packet_hw {
  __be16 hw_addrlen;
  __u16 _pad;
  __u8 hw_addr[8];
};
struct nfqnl_msg_packet_timestamp {
  __aligned_be64 sec;
  __aligned_be64 usec;
};
enum nfqnl_vlan_attr {
  NFQA_VLAN_UNSPEC,
  NFQA_VLAN_PROTO,
  NFQA_VLAN_TCI,
  __NFQA_VLAN_MAX,
};
#define NFQA_VLAN_MAX (__NFQA_VLAN_MAX - 1)
enum nfqnl_attr_type {
  NFQA_UNSPEC,
  NFQA_PACKET_HDR,
  NFQA_VERDICT_HDR,
  NFQA_MARK,
  NFQA_TIMESTAMP,
  NFQA_IFINDEX_INDEV,
  NFQA_IFINDEX_OUTDEV,
  NFQA_IFINDEX_PHYSINDEV,
  NFQA_IFINDEX_PHYSOUTDEV,
  NFQA_HWADDR,
  NFQA_PAYLOAD,
  NFQA_CT,
  NFQA_CT_INFO,
  NFQA_CAP_LEN,
  NFQA_SKB_INFO,
  NFQA_EXP,
  NFQA_UID,
  NFQA_GID,
  NFQA_SECCTX,
  NFQA_VLAN,
  NFQA_L2HDR,
  NFQA_PRIORITY,
  NFQA_CGROUP_CLASSID,
  __NFQA_MAX
};
#define NFQA_MAX (__NFQA_MAX - 1)
struct nfqnl_msg_verdict_hdr {
  __be32 verdict;
  __be32 id;
};
enum nfqnl_msg_config_cmds {
  NFQNL_CFG_CMD_NONE,
  NFQNL_CFG_CMD_BIND,
  NFQNL_CFG_CMD_UNBIND,
  NFQNL_CFG_CMD_PF_BIND,
  NFQNL_CFG_CMD_PF_UNBIND,
};
struct nfqnl_msg_config_cmd {
  __u8 command;
  __u8 _pad;
  __be16 pf;
};
enum nfqnl_config_mode {
  NFQNL_COPY_NONE,
  NFQNL_COPY_META,
  NFQNL_COPY_PACKET,
};
struct nfqnl_msg_config_params {
  __be32 copy_range;
  __u8 copy_mode;
} __attribute__((packed));
enum nfqnl_attr_config {
  NFQA_CFG_UNSPEC,
  NFQA_CFG_CMD,
  NFQA_CFG_PARAMS,
  NFQA_CFG_QUEUE_MAXLEN,
  NFQA_CFG_MASK,
  NFQA_CFG_FLAGS,
  __NFQA_CFG_MAX
};
#define NFQA_CFG_MAX (__NFQA_CFG_MAX - 1)
#define NFQA_CFG_F_FAIL_OPEN (1 << 0)
#define NFQA_CFG_F_CONNTRACK (1 << 1)
#define NFQA_CFG_F_GSO (1 << 2)
#define NFQA_CFG_F_UID_GID (1 << 3)
#define NFQA_CFG_F_SECCTX (1 << 4)
#define NFQA_CFG_F_MAX (1 << 5)
#define NFQA_SKB_CSUMNOTREADY (1 << 0)
#define NFQA_SKB_GSO (1 << 1)
#define NFQA_SKB_CSUM_NOTVERIFIED (1 << 2)
#endif

"""

```