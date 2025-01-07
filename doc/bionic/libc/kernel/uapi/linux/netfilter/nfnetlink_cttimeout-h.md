Response:
Let's break down the thought process for answering this complex request.

**1. Deconstructing the Request:**

The request asks for a comprehensive analysis of a C header file (`nfnetlink_cttimeout.h`). Key elements to address are:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it tie into Android's workings?
* **libc Functions:**  Explain the implementation of *any* libc functions present (spoiler: there aren't any *directly* in this header).
* **Dynamic Linker:** Discuss its relevance (again, not directly used here, but the context of `/bionic` suggests it's important).
* **Logic/Assumptions:**  If making inferences, state them and provide examples.
* **Common Errors:**  Identify potential pitfalls in using related concepts.
* **Android Framework/NDK Path:**  Trace how this header gets used in Android development.
* **Frida Hooking:** Provide examples for debugging related functionalities.

**2. Initial Analysis of the Header File:**

The first step is to understand the *content* of the header file. It primarily defines:

* **Enums:**  `ctnl_timeout_msg_types`, `ctattr_timeout`, and various `ctattr_timeout_*` enums. These strongly suggest it's about managing timeouts for network connection tracking.
* **Macros:**  `CTA_TIMEOUT_MAX`, etc., which define the maximum values of the enums.
* **`#ifndef` guards:** Standard practice to prevent multiple inclusions.
* **Include:** `#include <linux/netfilter/nfnetlink.h>` which signals interaction with Linux's Netfilter framework.

**3. Connecting to Core Concepts:**

* **Netfilter:**  The `#include` immediately flags this as related to Netfilter, the Linux kernel's firewalling and network address translation (NAT) subsystem. Connection tracking is a core part of Netfilter.
* **Netlink:** The `nfnetlink` in the included header and the `ctnl_timeout_msg_types` strongly indicate the use of Netlink, a socket-based mechanism for communication between the kernel and userspace.
* **Timeouts:** The name of the file and the enum names clearly point to managing timeouts for different aspects of network connections.

**4. Addressing Each Point of the Request (Iterative Process):**

* **Functionality:** Based on the enums, the file defines message types (NEW, GET, DELETE, SET) for manipulating connection tracking timeouts. It also defines attributes for specifying the type of timeout (generic, TCP, UDP, ICMP, etc.) and specific states within those protocols.

* **Android Relevance:** This requires connecting the kernel-level functionality to Android. Key points:
    * Android uses the Linux kernel.
    * Android's networking stack relies on Netfilter for firewalling, NAT, and connection tracking.
    * Applications or system services might need to adjust connection timeout behavior. Examples: Mobile data connections, Wi-Fi connections, VPNs, background services.

* **libc Functions:**  The crucial realization is that this *header file itself* doesn't *implement* libc functions. It *defines* constants and types used by code that *does* use libc functions. It's important to clarify this distinction. However, the *context* of `/bionic` means code using this header likely interacts with other parts of Bionic (like socket functions).

* **Dynamic Linker:** Similar to libc, the header doesn't directly involve the dynamic linker. However, applications interacting with Netfilter will be linked against Bionic libraries. Providing a generic example of shared library layout and the linking process is relevant contextual information.

* **Logic/Assumptions:**  To illustrate the use, it's helpful to create hypothetical examples. The examples provided in the answer focus on constructing Netlink messages based on the defined enums. This demonstrates how the constants would be used in practice. It's important to state the assumptions (like having a Netlink socket).

* **Common Errors:**  These often relate to the complexity of Netlink itself: incorrect message structure, wrong attribute types, failure to handle errors, and not understanding the kernel's state.

* **Android Framework/NDK Path:** This requires tracing how a high-level Android action might lead to the use of these definitions. The path involves:
    * Application (Java/Kotlin) making a network request.
    * Framework handling the request, potentially using `ConnectivityService`, `NetworkStack`.
    * System services interacting with the kernel via Netlink sockets.
    * The kernel using the definitions from this header to manage connection timeouts.

* **Frida Hooking:** The examples should focus on the key points where interaction with this header's concepts is likely: sending Netlink messages related to connection tracking timeouts or inspecting the kernel's connection tracking table. Hooking `sendto` or relevant Netfilter kernel functions are good examples.

**5. Refining and Structuring the Answer:**

The final step involves organizing the information logically, using clear language, and providing sufficient detail for each point. Using headings and bullet points improves readability. It's also crucial to emphasize the relationship between the header file and the underlying kernel functionality. Addressing the "auto-generated" nature of the file provides important context. The explanation of Bionic's role in Android is also crucial.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** Maybe there are implicit libc calls within the macros?  **Correction:**  The macros are just constant definitions. No actual function calls.
* **Initial Thought:** Focus heavily on the *content* of the header. **Correction:**  Expand to explain the *purpose* and *context* of the header within the larger Android/Linux ecosystem.
* **Initial Thought:**  Provide very specific Frida hooks. **Correction:**  Generalize the hook examples to illustrate the *type* of interaction that would be relevant.

By following this structured approach, considering the different facets of the request, and iteratively refining the explanation, we arrive at a comprehensive and accurate answer.
这是一个定义 Linux 内核中网络连接跟踪 (Connection Tracking, conntrack 或 ct) 超时属性的头文件。它定义了用于与内核中连接跟踪模块进行 Netlink 通信的消息类型和属性，以管理连接的超时时间。由于它位于 `bionic/libc/kernel/uapi/linux/netfilter/` 路径下，这意味着它被 Android 的 Bionic 库所包含，用于在用户空间程序中与内核的网络功能进行交互。

**功能列举:**

这个头文件主要定义了以下内容，用于控制网络连接跟踪的超时行为：

1. **消息类型 (enum `ctnl_timeout_msg_types`)**: 定义了用户空间程序可以通过 Netlink 发送给内核的关于连接跟踪超时的消息类型，例如：
   - `IPCTNL_MSG_TIMEOUT_NEW`:  创建新的超时策略。
   - `IPCTNL_MSG_TIMEOUT_GET`:  获取现有的超时策略。
   - `IPCTNL_MSG_TIMEOUT_DELETE`: 删除现有的超时策略。
   - `IPCTNL_MSG_TIMEOUT_DEFAULT_SET`: 设置默认的超时时间。
   - `IPCTNL_MSG_TIMEOUT_DEFAULT_GET`: 获取默认的超时时间。

2. **通用属性 (enum `ctattr_timeout`)**: 定义了与所有协议相关的通用超时属性，例如：
   - `CTA_TIMEOUT_NAME`: 超时策略的名称。
   - `CTA_TIMEOUT_L3PROTO`:  网络层协议 (例如 IPv4, IPv6)。
   - `CTA_TIMEOUT_L4PROTO`:  传输层协议 (例如 TCP, UDP, ICMP)。
   - `CTA_TIMEOUT_DATA`:  与协议相关的具体超时数据。
   - `CTA_TIMEOUT_USE`:  表示该超时策略是否正在使用。

3. **各协议的特定属性 (enum `ctattr_timeout_协议名`)**:  针对不同传输层协议 (TCP, UDP, ICMP 等) 定义了更细粒度的超时属性，反映了连接的不同状态。例如：
   - **TCP (`ctattr_timeout_tcp`)**:  `CTA_TIMEOUT_TCP_SYN_SENT`, `CTA_TIMEOUT_TCP_ESTABLISHED`, `CTA_TIMEOUT_TCP_FIN_WAIT` 等，分别对应 TCP 连接的不同状态。
   - **UDP (`ctattr_timeout_udp`)**: `CTA_TIMEOUT_UDP_UNREPLIED`, `CTA_TIMEOUT_UDP_REPLIED`，表示 UDP 数据包是否已回复。
   - **ICMP (`ctattr_timeout_icmp`)**: `CTA_TIMEOUT_ICMP_TIMEOUT`，表示 ICMP 超时。
   - 其他协议 (DCCP, SCTP, GRE 等) 也类似地定义了各自的超时属性。

4. **最大属性值宏定义 (`CTA_TIMEOUT_MAX`, `CTA_TIMEOUT_TCP_MAX` 等)**:  方便程序确定属性的最大值，用于数组或循环的边界检查。

**与 Android 功能的关系及举例说明:**

这个文件定义的接口直接影响着 Android 设备的网络连接管理和防火墙行为。连接跟踪是 Netfilter 的核心功能，用于跟踪网络连接的状态，以便防火墙能够做出有状态的过滤决策。通过修改连接的超时时间，可以影响以下 Android 功能：

* **移动数据连接和 Wi-Fi 连接的保持:**  Android 系统可以调整连接超时时间，以优化电池消耗，例如在后台活动较少时缩短空闲连接的超时时间，断开不活跃的连接。
* **网络共享 (Tethering):**  当手机作为热点时，需要管理连接到手机的其他设备的网络连接，包括设置超时时间。
* **VPN 连接:**  VPN 客户端需要与 VPN 服务器保持连接，连接跟踪超时设置会影响 VPN 连接的稳定性。
* **应用的网络请求:**  应用程序的网络请求依赖于底层的网络连接。如果连接超时时间设置不当，可能会导致应用的网络请求失败。
* **防火墙规则和 NAT (网络地址转换):**  连接跟踪是防火墙和 NAT 的基础，超时设置直接影响防火墙规则的匹配和 NAT 会话的维持。

**举例说明:**

假设一个 Android 应用发起了一个 TCP 连接到远程服务器。内核的连接跟踪模块会记录这个连接的状态，并为其设置一个默认的超时时间（例如，`CTA_TIMEOUT_TCP_ESTABLISHED` 的默认值）。如果应用在一段时间内没有进行数据交互，并且超过了设定的超时时间，内核就会认为这个连接已经过期，将其从连接跟踪表中移除。这可能会导致后续的应用数据发送失败，需要重新建立连接。

Android 系统或应用可以使用 Netlink socket 与内核通信，发送包含此头文件中定义的消息和属性的消息，来修改特定连接或特定类型的连接的超时时间。例如，一个 VPN 应用可能会在建立 VPN 连接后，通过 Netlink 设置更长的超时时间，以确保连接的持久性。

**详细解释 libc 函数的功能是如何实现的:**

这个头文件本身并不包含任何 libc 函数的实现。它只是定义了一些常量和枚举类型，用于用户空间程序构建与内核通信的 Netlink 消息。

实际使用这些定义的程序会调用 libc 提供的网络相关的系统调用，例如：

* **`socket()`**: 创建一个 Netlink socket，用于与内核进行通信。
* **`bind()`**: 将 Netlink socket 绑定到特定的协议族和端口。
* **`sendto()` / `recvfrom()`**:  通过 Netlink socket 发送和接收消息。

这些 libc 函数的实现位于 Bionic 库中，它们是对内核系统调用的封装。例如，`sendto()` 函数最终会调用内核的 `sys_sendto()` 系统调用，将数据包发送到指定的网络地址。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。它是一个头文件，在编译时会被包含到用户空间的 C/C++ 代码中。

然而，如果用户空间的程序使用了 Netlink 与内核进行交互，并且这些功能被封装在共享库 (Shared Object, `.so`) 中，那么 dynamic linker 就发挥作用了。

**so 布局样本:**

假设有一个名为 `libnetfilter_control.so` 的共享库，它封装了与 Netfilter (包括连接跟踪超时管理) 交互的功能。这个库的布局可能如下：

```
libnetfilter_control.so:
    .init       # 初始化代码段
    .plt        # 程序链接表 (Procedure Linkage Table)
    .text       # 代码段 (包含使用此头文件中定义的常量和枚举的代码)
        - netlink_connect()
        - set_ct_timeout()  # 可能包含使用 CTA_TIMEOUT_* 常量的代码
        - get_ct_timeout()
        - ...
    .rodata     # 只读数据段 (可能包含一些字符串常量)
    .data       # 可读写数据段
    .bss        # 未初始化数据段
    .dynamic    # 动态链接信息
    .symtab     # 符号表
    .strtab     # 字符串表
    .rel.dyn    # 动态重定位表
    .rel.plt    # PLT 重定位表
```

**链接的处理过程:**

1. **编译时链接:** 当开发者编译使用 `libnetfilter_control.so` 的应用程序时，编译器会将对该库中函数的调用记录下来，并在生成的可执行文件中创建一个 `.plt` (Procedure Linkage Table) 条目。

2. **加载时链接:** 当 Android 系统启动应用程序时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序依赖的共享库。

3. **符号解析:** Dynamic linker 会遍历应用程序和其依赖的共享库的符号表 (`.symtab`)，找到被引用的符号的地址。例如，如果应用程序调用了 `libnetfilter_control.so` 中的 `set_ct_timeout()` 函数，dynamic linker 会在 `libnetfilter_control.so` 的符号表中找到 `set_ct_timeout()` 的地址。

4. **重定位:** Dynamic linker 会根据重定位表 (`.rel.dyn`, `.rel.plt`) 修改程序代码和数据中的地址引用，将对共享库中符号的引用指向其在内存中的实际地址。对于 PLT 条目，第一次调用时会触发 lazy binding，dynamic linker 会解析符号并更新 PLT 条目。

5. **执行:** 一旦链接完成，应用程序就可以成功调用 `libnetfilter_control.so` 中定义的函数，这些函数可能会使用此头文件中定义的常量和枚举来构建 Netlink 消息，与内核进行连接跟踪超时相关的操作。

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个用户空间的程序想要获取 TCP 连接已建立状态 (ESTABLISHED) 的默认超时时间。

**假设输入:**

* 程序创建了一个 Netlink socket，并已连接到 `NETLINK_NETFILTER` 协议族。
* 程序构造了一个 Netlink 消息，消息类型为 `IPCTNL_MSG_TIMEOUT_DEFAULT_GET`。
* 消息的属性部分包含：
    * `CTA_TIMEOUT_L3PROTO` 设置为 `AF_INET` (IPv4)。
    * `CTA_TIMEOUT_L4PROTO` 设置为 `IPPROTO_TCP`。
    * `CTA_TIMEOUT_TCP` 属性，其嵌套属性设置为 `CTA_TIMEOUT_TCP_ESTABLISHED`。

**预期输出 (从内核接收到的 Netlink 消息):**

* 消息类型仍然是与请求对应的响应类型 (通常会有一个标志指示这是响应)。
* 消息的属性部分包含：
    * `CTA_TIMEOUT_L3PROTO` 设置为 `AF_INET`。
    * `CTA_TIMEOUT_L4PROTO` 设置为 `IPPROTO_TCP`。
    * `CTA_TIMEOUT_TCP` 属性，其嵌套属性包含：
        * `CTA_TIMEOUT_TCP_ESTABLISHED` 属性，其值表示 TCP ESTABLISHED 状态的默认超时时间 (以秒或 jiffies 为单位)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用了错误的属性类型或值:**  例如，尝试将一个字符串值赋给一个期望整数的属性，或者使用了内核不支持的属性值。这会导致内核解析 Netlink 消息失败。

2. **Netlink 消息结构不正确:**  Netlink 消息有特定的头部结构和属性编码方式。如果消息头部字段设置错误，或者属性的长度、类型等信息不正确，内核将无法正确解析消息。

3. **没有正确处理 Netlink 消息的回复:**  内核在收到 Netlink 请求后通常会发送回复。用户空间程序需要正确接收和解析这些回复，以了解操作是否成功以及获取返回的数据。忽略回复可能导致程序行为异常。

4. **权限不足:**  修改连接跟踪超时可能需要 root 权限或特定的网络 capabilities。如果程序没有足够的权限，内核会拒绝操作。

5. **混淆了不同协议的超时属性:**  例如，尝试在 UDP 连接的超时设置中使用 TCP 相关的属性，会导致内核返回错误。

6. **假设默认超时时间固定不变:**  默认的连接跟踪超时时间可以通过内核参数进行配置。程序不应硬编码这些值，而应该通过 Netlink 查询来获取。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达此处的路径 (概念性描述):**

1. **应用程序发起网络请求:**  一个 Android 应用程序 (Java/Kotlin 代码) 发起一个网络连接请求 (例如，使用 `HttpURLConnection`, `OkHttp`, 或 `Socket`)。

2. **Framework 处理请求:** Android Framework (例如 `ConnectivityService`, `NetworkStack`) 接收到请求，并负责建立底层的网络连接。

3. **Kernel 网络协议栈处理:** Linux 内核的网络协议栈处理连接的建立过程，包括 TCP 三次握手等。

4. **连接跟踪模块介入:** 当连接建立成功后，Netfilter 的连接跟踪模块会记录这个连接的信息，并为其设置初始的超时时间。

5. **Framework 或系统服务可能调整超时:** 在某些情况下，Android Framework 或系统服务 (例如负责省电策略的服务) 可能会根据需要调整连接的超时时间。这通常涉及到通过 Netlink 与内核的连接跟踪模块进行通信。

6. **NDK 代码直接操作:**  使用 NDK 开发的应用程序可以直接使用 socket API 和 Netlink API 与内核交互，包括设置连接跟踪超时。

**Frida Hook 示例:**

以下是一些使用 Frida hook 调试与连接跟踪超时相关的步骤的示例：

**1. Hook `sendto` 系统调用，查看发送的 Netlink 消息:**

```javascript
function hook_sendto() {
    const sendtoPtr = Module.findExportByName(null, 'sendto');
    if (sendtoPtr) {
        Interceptor.attach(sendtoPtr, {
            onEnter: function (args) {
                const sockfd = args[0].toInt32();
                const bufPtr = args[1];
                const len = args[2].toInt32();
                const flags = args[3].toInt32();
                const destAddrPtr = args[4];
                const addrlen = args[5].toInt32();

                // 检查是否是 Netlink socket
                const sockaddrFamily = destAddrPtr.readU16();
                if (sockaddrFamily === 16) { // AF_NETLINK
                    console.log("sendto() called on Netlink socket, fd:", sockfd, "len:", len);
                    if (len > 0) {
                        console.log("Netlink message:", hexdump(bufPtr, { length: len }));
                        // 可以进一步解析 Netlink 消息头部和属性，判断是否与连接跟踪超时相关
                    }
                }
            },
            onLeave: function (retval) {
                // ...
            }
        });
    } else {
        console.error("Failed to find sendto");
    }
}

setImmediate(hook_sendto);
```

**2. Hook 系统服务中可能发送 Netlink 消息的函数 (需要找到具体的服务和函数名，例如 `netd` 守护进程):**

```javascript
// 假设 netd 守护进程中有一个函数负责设置连接跟踪超时
const libnetd = Process.getModuleByName("netd");
const setConntrackTimeoutFunc = libnetd.findExportByName("some_netd_function_related_to_ct_timeout"); // 替换为实际函数名

if (setConntrackTimeoutFunc) {
    Interceptor.attach(setConntrackTimeoutFunc, {
        onEnter: function (args) {
            console.log("Entering setConntrackTimeoutFunc, args:", args);
            // 打印参数，分析如何构建 Netlink 消息
        },
        onLeave: function (retval) {
            console.log("Leaving setConntrackTimeoutFunc, retval:", retval);
        }
    });
} else {
    console.error("Failed to find setConntrackTimeoutFunc");
}
```

**3. Hook 内核中处理 Netlink 消息的函数 (需要内核符号，通常用于系统级调试):**

这需要更高级的 Frida 用法，并且需要 root 权限和内核符号信息。例如，可以 hook `netlink_rcv_skb` 函数来查看接收到的 Netlink 消息。

**调试步骤:**

1. **确定目标进程:** 找到负责网络连接管理或需要调试的应用程序或系统服务进程。
2. **编写 Frida 脚本:** 使用 JavaScript 编写 Frida hook 脚本，hook 相关的 libc 函数 (如 `sendto`) 或目标进程中的特定函数。
3. **运行 Frida:** 使用 Frida CLI 或 API 将脚本注入到目标进程。
4. **分析输出:** 查看 Frida 的输出，分析发送的 Netlink 消息的内容，特别是消息类型和属性，以确定是否与连接跟踪超时相关，以及如何使用此头文件中定义的常量。
5. **进一步分析:** 如果需要更深入的分析，可以结合反汇编工具 (如 IDA Pro, Ghidra) 分析目标进程的代码，找到构建 Netlink 消息的具体逻辑。

通过以上步骤，可以逐步追踪 Android Framework 或 NDK 如何使用此头文件中定义的常量和枚举，与内核的连接跟踪模块进行交互，从而管理网络连接的超时行为。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter/nfnetlink_cttimeout.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _CTTIMEOUT_NETLINK_H
#define _CTTIMEOUT_NETLINK_H
#include <linux/netfilter/nfnetlink.h>
enum ctnl_timeout_msg_types {
  IPCTNL_MSG_TIMEOUT_NEW,
  IPCTNL_MSG_TIMEOUT_GET,
  IPCTNL_MSG_TIMEOUT_DELETE,
  IPCTNL_MSG_TIMEOUT_DEFAULT_SET,
  IPCTNL_MSG_TIMEOUT_DEFAULT_GET,
  IPCTNL_MSG_TIMEOUT_MAX
};
enum ctattr_timeout {
  CTA_TIMEOUT_UNSPEC,
  CTA_TIMEOUT_NAME,
  CTA_TIMEOUT_L3PROTO,
  CTA_TIMEOUT_L4PROTO,
  CTA_TIMEOUT_DATA,
  CTA_TIMEOUT_USE,
  __CTA_TIMEOUT_MAX
};
#define CTA_TIMEOUT_MAX (__CTA_TIMEOUT_MAX - 1)
enum ctattr_timeout_generic {
  CTA_TIMEOUT_GENERIC_UNSPEC,
  CTA_TIMEOUT_GENERIC_TIMEOUT,
  __CTA_TIMEOUT_GENERIC_MAX
};
#define CTA_TIMEOUT_GENERIC_MAX (__CTA_TIMEOUT_GENERIC_MAX - 1)
enum ctattr_timeout_tcp {
  CTA_TIMEOUT_TCP_UNSPEC,
  CTA_TIMEOUT_TCP_SYN_SENT,
  CTA_TIMEOUT_TCP_SYN_RECV,
  CTA_TIMEOUT_TCP_ESTABLISHED,
  CTA_TIMEOUT_TCP_FIN_WAIT,
  CTA_TIMEOUT_TCP_CLOSE_WAIT,
  CTA_TIMEOUT_TCP_LAST_ACK,
  CTA_TIMEOUT_TCP_TIME_WAIT,
  CTA_TIMEOUT_TCP_CLOSE,
  CTA_TIMEOUT_TCP_SYN_SENT2,
  CTA_TIMEOUT_TCP_RETRANS,
  CTA_TIMEOUT_TCP_UNACK,
  __CTA_TIMEOUT_TCP_MAX
};
#define CTA_TIMEOUT_TCP_MAX (__CTA_TIMEOUT_TCP_MAX - 1)
enum ctattr_timeout_udp {
  CTA_TIMEOUT_UDP_UNSPEC,
  CTA_TIMEOUT_UDP_UNREPLIED,
  CTA_TIMEOUT_UDP_REPLIED,
  __CTA_TIMEOUT_UDP_MAX
};
#define CTA_TIMEOUT_UDP_MAX (__CTA_TIMEOUT_UDP_MAX - 1)
enum ctattr_timeout_udplite {
  CTA_TIMEOUT_UDPLITE_UNSPEC,
  CTA_TIMEOUT_UDPLITE_UNREPLIED,
  CTA_TIMEOUT_UDPLITE_REPLIED,
  __CTA_TIMEOUT_UDPLITE_MAX
};
#define CTA_TIMEOUT_UDPLITE_MAX (__CTA_TIMEOUT_UDPLITE_MAX - 1)
enum ctattr_timeout_icmp {
  CTA_TIMEOUT_ICMP_UNSPEC,
  CTA_TIMEOUT_ICMP_TIMEOUT,
  __CTA_TIMEOUT_ICMP_MAX
};
#define CTA_TIMEOUT_ICMP_MAX (__CTA_TIMEOUT_ICMP_MAX - 1)
enum ctattr_timeout_dccp {
  CTA_TIMEOUT_DCCP_UNSPEC,
  CTA_TIMEOUT_DCCP_REQUEST,
  CTA_TIMEOUT_DCCP_RESPOND,
  CTA_TIMEOUT_DCCP_PARTOPEN,
  CTA_TIMEOUT_DCCP_OPEN,
  CTA_TIMEOUT_DCCP_CLOSEREQ,
  CTA_TIMEOUT_DCCP_CLOSING,
  CTA_TIMEOUT_DCCP_TIMEWAIT,
  __CTA_TIMEOUT_DCCP_MAX
};
#define CTA_TIMEOUT_DCCP_MAX (__CTA_TIMEOUT_DCCP_MAX - 1)
enum ctattr_timeout_sctp {
  CTA_TIMEOUT_SCTP_UNSPEC,
  CTA_TIMEOUT_SCTP_CLOSED,
  CTA_TIMEOUT_SCTP_COOKIE_WAIT,
  CTA_TIMEOUT_SCTP_COOKIE_ECHOED,
  CTA_TIMEOUT_SCTP_ESTABLISHED,
  CTA_TIMEOUT_SCTP_SHUTDOWN_SENT,
  CTA_TIMEOUT_SCTP_SHUTDOWN_RECD,
  CTA_TIMEOUT_SCTP_SHUTDOWN_ACK_SENT,
  CTA_TIMEOUT_SCTP_HEARTBEAT_SENT,
  CTA_TIMEOUT_SCTP_HEARTBEAT_ACKED,
  __CTA_TIMEOUT_SCTP_MAX
};
#define CTA_TIMEOUT_SCTP_MAX (__CTA_TIMEOUT_SCTP_MAX - 1)
enum ctattr_timeout_icmpv6 {
  CTA_TIMEOUT_ICMPV6_UNSPEC,
  CTA_TIMEOUT_ICMPV6_TIMEOUT,
  __CTA_TIMEOUT_ICMPV6_MAX
};
#define CTA_TIMEOUT_ICMPV6_MAX (__CTA_TIMEOUT_ICMPV6_MAX - 1)
enum ctattr_timeout_gre {
  CTA_TIMEOUT_GRE_UNSPEC,
  CTA_TIMEOUT_GRE_UNREPLIED,
  CTA_TIMEOUT_GRE_REPLIED,
  __CTA_TIMEOUT_GRE_MAX
};
#define CTA_TIMEOUT_GRE_MAX (__CTA_TIMEOUT_GRE_MAX - 1)
#define CTNL_TIMEOUT_NAME_MAX 32
#endif

"""

```