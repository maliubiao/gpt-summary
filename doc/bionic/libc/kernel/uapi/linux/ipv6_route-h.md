Response:
Let's break down the thought process for analyzing the provided C header file `ipv6_route.h`.

**1. Initial Understanding - Context and Goal:**

The first step is to understand the context. The file is located in the Android bionic library's kernel headers, specifically related to IPv6 routing. The goal is to analyze its functionality, its relationship to Android, the implementation details of related functions (even though the header itself *doesn't* contain implementations), its role in dynamic linking (again, not directly present), common usage errors, and how Android frameworks reach this level.

**2. Deconstructing the Header File - Identifying Key Elements:**

Next, systematically examine the contents of the header file:

* **Header Guards:** `#ifndef _UAPI_LINUX_IPV6_ROUTE_H` and `#define _UAPI_LINUX_IPV6_ROUTE_H` are standard header guards to prevent multiple inclusions. This is a fundamental C/C++ concept.

* **Includes:** `#include <linux/types.h>` and `#include <linux/in6.h>` indicate dependencies on other kernel headers for basic types and IPv6 address structures.

* **Macros (RTF Flags):**  A series of `#define` statements starting with `RTF_`. These clearly represent routing flags. Recognize the pattern and understand they are bitmasks used to represent different routing attributes. Note the `RTF_PREF` macro which uses bit shifting.

* **Structure (`in6_rtmsg`):**  This is the core data structure defined in this header. Carefully analyze its members:
    * `rtmsg_dst`, `rtmsg_src`, `rtmsg_gateway`: IPv6 addresses, likely destination, source, and gateway.
    * `rtmsg_type`: An integer, probably representing the message type.
    * `rtmsg_dst_len`, `rtmsg_src_len`: Lengths, likely prefix lengths for the destination and source addresses.
    * `rtmsg_metric`: A metric value, often used for route selection.
    * `rtmsg_info`: A generic information field.
    * `rtmsg_flags`:  This clearly connects back to the `RTF_` macros.
    * `rtmsg_ifindex`: Network interface index.

* **Macros (RTMSG Types):**  `RTMSG_NEWDEVICE`, `RTMSG_DELDEVICE`, `RTMSG_NEWROUTE`, `RTMSG_DELROUTE`. These appear to be message types related to device and route management.

* **Macros (Priority Levels):** `IP6_RT_PRIO_USER`, `IP6_RT_PRIO_ADDRCONF`. These seem to define different priority levels for routes.

**3. Analyzing Functionality and Relationship to Android:**

* **Core Functionality:** Based on the structure and definitions, the header defines the data structures and constants used for communicating IPv6 routing information within the Linux kernel.

* **Android's Usage:**  Android, being built on the Linux kernel, directly uses these kernel-level interfaces for its networking stack. Examples: network configuration tools, VPN implementations, application networking.

**4. Addressing Implementation Details (Even Though Not in Header):**

The prompt asks about `libc` function implementations. The header *doesn't* contain function implementations. The key realization is that this header defines the *interface* or *structure* of the data exchanged with the kernel. The actual *implementation* of functions that use this structure (like `sendto`, `recvfrom`, `ioctl` with routing commands) resides within the kernel itself or in `libc` wrappers that make system calls to the kernel. It's important to distinguish between the interface definition and the implementation.

**5. Dynamic Linking:**

The header itself doesn't directly involve dynamic linking. However,  `libc` functions that *use* these structures (e.g., functions that interact with the networking stack) are part of `libc.so`. The explanation should focus on how applications link against `libc.so` and indirectly utilize these kernel structures via system calls. A simple `libc.so` layout example with function symbols is sufficient.

**6. Logical Reasoning and Examples:**

Think of concrete scenarios:

* **Route Addition/Deletion:**  Imagine an Android app setting up a VPN. This would involve adding a new route. The `in6_rtmsg` structure would be used to communicate this to the kernel.
* **Network Configuration:**  When Android configures an interface with an IPv6 address and gateway, it uses similar mechanisms.

**7. Common Usage Errors:**

Focus on errors related to incorrect usage of the structures or related system calls:

* Incorrectly setting flags.
* Providing invalid address or prefix lengths.
* Using incorrect system call numbers.

**8. Android Framework and NDK Path:**

Trace the journey from a high-level Android component to the kernel:

* **Android Framework:**  `ConnectivityManager`, `NetworkCapabilities`.
* **System Services:**  `netd`.
* **NDK:**  Socket programming APIs.
* **System Calls:**  `socket`, `ioctl`, `sendto`.
* **Kernel:**  The networking subsystem processes the system calls and uses the structures defined in the header.

**9. Frida Hooking:**

Consider where to place Frida hooks to observe this in action. Good points are:

* System call entry points (`socket`, `ioctl`, `sendto`).
* Functions within `netd` or relevant `libc` functions.

**10. Structuring the Response:**

Organize the information logically using headings and bullet points to make it clear and easy to understand. Address each part of the prompt directly.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe there are `libc` functions defined in this header related to routing.
* **Correction:**  Realize this is a *kernel* header, exposed to userspace. `libc` functions would likely *use* these structures, but the implementations are elsewhere.
* **Initial thought:** Focus heavily on the bitwise operations of the flags.
* **Refinement:** While important, also emphasize the meaning of each flag and how they're used in route configuration.
* **Initial thought:** Provide a complex dynamic linking explanation.
* **Refinement:** Keep it concise, focusing on the relevant aspect: `libc.so` providing the interface for system calls.

By following these steps, breaking down the problem, and refining the analysis, we can generate a comprehensive and accurate response to the prompt.
这是一个描述Linux内核中IPv6路由相关数据结构和常量的头文件 (`ipv6_route.h`)。它定义了用户空间程序与内核网络协议栈交互，进行IPv6路由管理所需的数据结构和宏。这个头文件属于用户空间 API (UAPI)，意味着它是内核提供给用户空间程序使用的接口的一部分。

**功能列举:**

1. **定义 IPv6 路由标志 (RTF_*)**:  这些宏定义了各种 IPv6 路由的属性，例如：
    * `RTF_DEFAULT`: 默认路由。
    * `RTF_ALLONLINK`: 目标网络链路是本地的。
    * `RTF_ADDRCONF`: 通过地址自动配置学习到的路由。
    * `RTF_PREFIX_RT`: 前缀路由。
    * `RTF_ANYCAST`: 任意播路由。
    * `RTF_NONEXTHOP`:  没有下一跳地址（通常用于本地连接）。
    * `RTF_EXPIRES`:  路由会过期。
    * `RTF_ROUTEINFO`:  路由信息。
    * `RTF_CACHE`:  缓存路由。
    * `RTF_FLOW`:  与流相关的路由。
    * `RTF_POLICY`:  基于策略的路由。
    * `RTF_PREF(pref)` 和 `RTF_PREF_MASK`:  路由优先级。
    * `RTF_PCPU`:  每个 CPU 的路由。
    * `RTF_LOCAL`:  本地路由。

2. **定义 `in6_rtmsg` 结构体**:  这个结构体用于在用户空间和内核之间传递 IPv6 路由消息。它包含了以下字段：
    * `rtmsg_dst`:  目标 IPv6 地址。
    * `rtmsg_src`:  源 IPv6 地址（通常为零）。
    * `rtmsg_gateway`:  下一跳 IPv6 地址。
    * `rtmsg_type`:  路由消息类型（例如，新建或删除路由）。
    * `rtmsg_dst_len`:  目标网络前缀长度。
    * `rtmsg_src_len`:  源网络前缀长度。
    * `rtmsg_metric`:  路由度量值（用于路由选择）。
    * `rtmsg_info`:  路由信息（通常未使用或保留）。
    * `rtmsg_flags`:  路由标志（使用上面定义的 `RTF_` 宏）。
    * `rtmsg_ifindex`:  网络接口索引。

3. **定义路由消息类型 (RTMSG_*)**: 这些宏定义了可以传递的路由消息类型：
    * `RTMSG_NEWDEVICE`:  新网络设备。
    * `RTMSG_DELDEVICE`:  删除网络设备。
    * `RTMSG_NEWROUTE`:  添加新路由。
    * `RTMSG_DELROUTE`:  删除路由。

4. **定义路由优先级 (IP6_RT_PRIO_*)**:  定义了不同的路由优先级：
    * `IP6_RT_PRIO_USER`:  用户配置的路由。
    * `IP6_RT_PRIO_ADDRCONF`:  通过地址自动配置学习到的路由。

**与 Android 功能的关系及举例说明:**

这个头文件直接关系到 Android 设备的 IPv6 网络功能。Android 设备需要管理其 IPv6 路由表以实现网络连接。

* **网络配置 (Network Configuration):** 当 Android 设备连接到 IPv6 网络时，例如通过 Wi-Fi 或移动数据网络，系统会配置 IP 地址、网关和路由。这些操作最终会涉及到向内核添加或修改路由表项。例如，当设备获取到一个 IPv6 地址和一个默认网关时，系统会使用类似于 `RTMSG_NEWROUTE` 的消息，填充 `in6_rtmsg` 结构体，并通过特定的系统调用（如 `netlink` 套接字）传递给内核。
* **VPN 连接 (VPN Connection):** 当用户连接到 VPN 服务时，VPN 客户端需要在本地路由表中添加路由，将特定目标网络的流量导向 VPN 服务器。这也会涉及到使用 `RTMSG_NEWROUTE` 消息和 `in6_rtmsg` 结构体。
* **热点功能 (Tethering):** 当 Android 设备作为热点时，它需要管理连接到它的设备的路由。这可能涉及到添加和删除路由项。
* **网络监控工具 (Network Monitoring Tools):** 一些网络监控工具可能会读取或解析路由表信息，而这些信息的结构就由这个头文件定义。

**libc 函数的功能及其实现:**

这个头文件本身并没有定义 `libc` 函数。它定义的是内核数据结构和常量。用户空间的 `libc` 函数，例如用于网络编程的 `socket()`, `bind()`, `sendto()`, `recvfrom()`, 以及更底层的 `syscall()` 等，可能会间接地使用这些定义。

例如，当一个 Android 应用程序想要添加或删除 IPv6 路由时，它通常不会直接操作这个头文件中定义的结构体。相反，它会使用 Android 提供的更高层次的 API，例如 Java 中的 `ConnectivityManager` 或 NDK 中的 socket 函数。

在 NDK 中，应用程序可能会使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` 创建一个 Netlink 套接字，然后构造包含 `in6_rtmsg` 结构体的 Netlink 消息，并通过 `sendto()` 系统调用发送给内核。

**详细解释 `libc` 函数的实现 (以间接使用为例):**

假设一个 Android 应用使用 NDK 创建一个 Netlink 套接字并尝试添加一个 IPv6 路由：

1. **`socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`:**  这个 `libc` 函数会调用相应的内核 `sys_socket()` 系统调用，创建一个用于 Netlink 通信的套接字。`AF_NETLINK` 指定地址族为 Netlink，`NETLINK_ROUTE` 指定 Netlink 协议族为路由管理。

2. **构造 Netlink 消息:**  应用需要构造一个符合 Netlink 协议格式的消息，其中包含一个 `nlmsghdr` 结构体（定义了消息头），以及一个或多个 Netlink 消息属性 (NLA)。对于添加 IPv6 路由，消息的类型会是 `RTM_NEWROUTE`，并且会包含一个 `ifaddrmsg` 或类似的结构体，以及包含 `in6_rtmsg` 结构体数据的 NLA 属性。

3. **`sendto(sockfd, message, len, flags, dest_addr, addrlen)`:** 这个 `libc` 函数会将构造好的 Netlink 消息发送到内核。
    * `sockfd`:  前面创建的 Netlink 套接字的文件描述符。
    * `message`: 指向构造好的 Netlink 消息的指针。
    * `len`:  消息的长度。
    * `flags`:  通常为 0。
    * `dest_addr`:  指向目标地址的指针，对于 Netlink 通常是内核的 Netlink 地址。
    * `addrlen`:  目标地址的长度。

   `sendto()` 内部会调用内核的 `sys_sendto()` 系统调用，将数据包发送到内核的网络协议栈。内核接收到 Netlink 消息后，会解析消息头和属性，提取出路由信息（例如，`in6_rtmsg` 中的数据），并根据消息类型（`RTM_NEWROUTE`）执行相应的路由添加操作。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 到进程的地址空间，并解析和重定位符号引用。

虽然这个头文件定义的是内核数据结构，但使用这些数据结构的 `libc` 函数是位于 `libc.so` 中的。当一个应用程序链接到 `libc` 时，dynamic linker 会负责加载 `libc.so`，并将应用程序中对 `libc` 函数的调用链接到 `libc.so` 中对应的函数实现。

**`libc.so` 布局样本 (简化):**

```
libc.so:
  .text:  // 代码段
    [ ... 其他函数的代码 ... ]
    socket:  // socket 函数的代码
      ...
    sendto:  // sendto 函数的代码
      ...
    [ ... 其他函数代码 ... ]
  .data:  // 数据段
    [ ... 全局变量 ... ]
  .rodata: // 只读数据段
    [ ... 常量 ... ]
  .dynsym: // 动态符号表
    socket  (地址)
    sendto  (地址)
    [ ... 其他符号 ... ]
  .dynstr: // 动态字符串表
    socket
    sendto
    [ ... 其他字符串 ... ]
  .rel.dyn: // 动态重定位表
    [ ... 重定位信息 ... ]
```

**链接的处理过程:**

1. **编译时:** 编译器在编译应用程序的代码时，遇到对 `libc` 函数（如 `socket`, `sendto`）的调用，会生成对这些符号的未解析引用。

2. **链接时:** 链接器（通常是 `ld`）会将应用程序的目标文件和所需的共享库（如 `libc.so`）链接在一起。它会创建一个可执行文件，其中包含一个动态链接表，记录了应用程序依赖的共享库。

3. **运行时:** 当操作系统加载应用程序时，dynamic linker 会被调用。
    * **加载共享库:** Dynamic linker 根据可执行文件的动态链接表，加载 `libc.so` 到进程的地址空间。
    * **解析符号:** Dynamic linker 查找应用程序中未解析的符号（如 `socket`, `sendto`）在 `libc.so` 的动态符号表 (`.dynsym`) 中的地址。
    * **重定位:** Dynamic linker 根据重定位表 (`.rel.dyn`) 中的信息，修改应用程序代码中的未解析引用，使其指向 `libc.so` 中对应函数的实际地址。

这样，当应用程序调用 `socket()` 或 `sendto()` 时，实际上会执行 `libc.so` 中实现的这些函数。这些 `libc` 函数在实现其功能时，可能会使用到这个头文件中定义的内核数据结构，通过系统调用与内核进行交互。

**假设输入与输出 (逻辑推理，针对使用 `in6_rtmsg` 的场景):**

**假设输入 (用户空间程序尝试添加一个到 `2001:db8::/32` 的路由，通过接口 `eth0`):**

* `rtmsg_dst`: `2001:db8::`
* `rtmsg_src`: `::` (通常为零)
* `rtmsg_gateway`:  假设没有下一跳，可以直接连接，则可以为 `::` 或目标网络接口的链路本地地址。
* `rtmsg_type`: `RTPROT_USER` (表示用户添加的路由，可以通过其他方式设置，不直接在 `in6_rtmsg` 中)
* `rtmsg_dst_len`: `32`
* `rtmsg_src_len`: `0`
* `rtmsg_metric`:  例如 `10`
* `rtmsg_info`: `0`
* `rtmsg_flags`:  可能包含 `RTF_UP` (路由启用)
* `rtmsg_ifindex`:  `eth0` 对应的接口索引 (可以通过 `if_nametoindex("eth0")` 获取)

**预期输出 (内核行为):**

内核接收到包含上述 `in6_rtmsg` 信息的 Netlink 消息后，会：

1. **验证消息:** 检查消息的有效性，例如目标地址和前缀长度是否合法。
2. **查找接口:**  根据 `rtmsg_ifindex` 找到对应的网络接口 `eth0`。
3. **创建路由项:** 在 IPv6 路由表中创建一个新的路由项，目标网络为 `2001:db8::/32`，通过接口 `eth0` 到达，度量值为 `10`。
4. **返回确认:**  如果操作成功，内核会通过 Netlink 套接字返回一个确认消息给用户空间程序。如果失败，则返回错误信息。

**用户或编程常见的使用错误:**

1. **错误的地址和前缀长度:**  `rtmsg_dst` 和 `rtmsg_dst_len` 不匹配，例如目标地址不是网络地址，或者前缀长度超出范围 (0-128)。
2. **错误的接口索引:** `rtmsg_ifindex` 指定的接口不存在或者不适合添加该路由。
3. **权限不足:**  普通用户可能没有权限修改路由表，需要 root 权限或相应的 capabilities。
4. **构造错误的 Netlink 消息:**  忘记设置 Netlink 消息头，或者消息属性格式错误，导致内核无法解析。
5. **混淆源地址和目标地址:**  错误地填充 `rtmsg_src` 和 `rtmsg_dst` 字段。
6. **忘记设置必要的路由标志:**  例如，没有设置 `RTF_UP` 导致路由添加后未启用。
7. **假设 `rtmsg_type` 直接控制路由类型:**  `rtmsg_type` 在 `in6_rtmsg` 中通常与 Netlink 消息类型结合使用，例如 `RTM_NEWROUTE`。 路由的具体属性由 `rtmsg_flags` 控制。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤:**

**Android Framework 到内核的路径 (以添加路由为例):**

1. **Android 应用 (Java/Kotlin):**  应用程序可能通过 `ConnectivityManager` 或 `NetworkPolicyManager` 等 API 发起网络配置请求，例如设置 VPN 连接。

2. **System Services (Java):**  这些请求会被传递给系统服务，例如 `ConnectivityService` 或 `NetworkPolicyService`.

3. **Native Daemon (`netd`):**  系统服务通常会通过 Binder IPC 与 native daemon `netd` 进行通信。`netd` 负责执行底层的网络配置操作。

4. **`netd` actions (C++):** `netd` 中会执行相应的操作，例如调用 `ioctl` 系统调用操作网络接口，或者使用 Netlink 套接字与内核通信以管理路由。

5. **`libc` 函数 (C):** `netd` 在与内核交互时，会使用 `libc` 提供的网络编程函数，例如 `socket()`, `bind()`, `sendto()`. 当使用 Netlink 时，会构造包含 `in6_rtmsg` 结构体的 Netlink 消息。

6. **系统调用 (Kernel Entry):** `libc` 函数会触发相应的系统调用，例如 `sendto()`.

7. **内核网络协议栈 (Linux Kernel):** 内核接收到系统调用后，网络协议栈会处理 Netlink 消息，解析 `in6_rtmsg` 结构体中的信息，并更新 IPv6 路由表。

**NDK 到内核的路径:**

1. **NDK 应用 (C/C++):**  NDK 应用程序可以直接使用 socket API 创建 Netlink 套接字。

2. **`libc` 函数 (C):**  NDK 应用调用 `libc` 提供的网络编程函数，例如 `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`, `sendto()`.

3. **系统调用 (Kernel Entry):**  `libc` 函数触发系统调用。

4. **内核网络协议栈 (Linux Kernel):** 内核处理系统调用和 Netlink 消息。

**Frida Hook 示例:**

以下是一些使用 Frida Hook 调试这些步骤的示例：

**Hook `sendto` 系统调用 (观察发送到内核的 Netlink 消息):**

```javascript
if (Process.arch === 'arm64') {
    // ARM64
    const sendtoPtr = Module.findExportByName(null, 'sendto');
    if (sendtoPtr) {
        Interceptor.attach(sendtoPtr, {
            onEnter: function (args) {
                const sockfd = args[0].toInt32();
                const buf = args[1];
                const len = args[2].toInt32();
                const flags = args[3].toInt32();
                const dest_addr = args[4];
                const addrlen = args[5].toInt32();

                // 检查是否是 Netlink 套接字
                const sockaddr_nl = dest_addr.readByteArray(addrlen);
                if (sockaddr_nl[0] === 0x10 && sockaddr_nl[1] === 0x00) { // AF_NETLINK
                    console.log("sendto called with Netlink socket:", sockfd);
                    console.log("Length:", len);
                    // 尝试解析 Netlink 消息头和 in6_rtmsg 结构体
                    try {
                        const nlmsghdrSize = 16; // sizeof(struct nlmsghdr)
                        if (len >= nlmsghdrSize) {
                            const nlmsg_type = buf.readU16();
                            const nlmsg_flags = buf.readU16({ offset: 2 });
                            const nlmsg_seq = buf.readU32({ offset: 4 });
                            const nlmsg_pid = buf.readU32({ offset: 8 });
                            const rtm_message = buf.readByteArray(len - nlmsghdrSize, { offset: nlmsghdrSize });
                            console.log("Netlink Message Type:", nlmsg_type);
                            console.log("Netlink Flags:", nlmsg_flags);
                            // 进一步解析 rtmsg 或 in6_rtmsg (需要知道具体的消息结构)
                            // ...
                        }
                    } catch (e) {
                        console.error("Error parsing Netlink message:", e);
                    }
                }
            }
        });
    }
}
```

**Hook `netd` 中处理路由的函数 (更高级别的观察):**

你需要找到 `netd` 中负责处理路由相关操作的函数，这可能需要一些逆向工程。例如，可能会有函数接收来自 `ConnectivityService` 的请求并执行路由添加操作。

```javascript
// 假设找到了 netd 中添加 IPv6 路由的函数
const addIpv6RouteFunction = Module.findExportByName("netd", "_ZN4android4netdL20addIpv6RouteInternalERKNS_Ipv6AddressEjjj"); // 示例函数名，可能需要调整

if (addIpv6RouteFunction) {
    Interceptor.attach(addIpv6RouteFunction, {
        onEnter: function (args) {
            console.log("addIpv6RouteInternal called");
            // 解析参数，例如目标地址、前缀长度、接口索引等
            const destAddress = args[0];
            const prefixLength = args[1].toInt32();
            const ifIndex = args[2].toInt32();
            // ...
            console.log("Destination Address:", destAddress.toString());
            console.log("Prefix Length:", prefixLength);
            console.log("Interface Index:", ifIndex);
        }
    });
}
```

这些 Frida Hook 示例可以帮助你观察 Android Framework 或 NDK 如何一步步地调用底层的 `libc` 函数，最终通过系统调用与内核交互，涉及到 `ipv6_route.h` 中定义的数据结构。你需要根据具体的场景和目标进程调整 Hook 的位置和解析逻辑。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/ipv6_route.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_IPV6_ROUTE_H
#define _UAPI_LINUX_IPV6_ROUTE_H
#include <linux/types.h>
#include <linux/in6.h>
#define RTF_DEFAULT 0x00010000
#define RTF_ALLONLINK 0x00020000
#define RTF_ADDRCONF 0x00040000
#define RTF_PREFIX_RT 0x00080000
#define RTF_ANYCAST 0x00100000
#define RTF_NONEXTHOP 0x00200000
#define RTF_EXPIRES 0x00400000
#define RTF_ROUTEINFO 0x00800000
#define RTF_CACHE 0x01000000
#define RTF_FLOW 0x02000000
#define RTF_POLICY 0x04000000
#define RTF_PREF(pref) ((pref) << 27)
#define RTF_PREF_MASK 0x18000000
#define RTF_PCPU 0x40000000
#define RTF_LOCAL 0x80000000
struct in6_rtmsg {
  struct in6_addr rtmsg_dst;
  struct in6_addr rtmsg_src;
  struct in6_addr rtmsg_gateway;
  __u32 rtmsg_type;
  __u16 rtmsg_dst_len;
  __u16 rtmsg_src_len;
  __u32 rtmsg_metric;
  unsigned long rtmsg_info;
  __u32 rtmsg_flags;
  int rtmsg_ifindex;
};
#define RTMSG_NEWDEVICE 0x11
#define RTMSG_DELDEVICE 0x12
#define RTMSG_NEWROUTE 0x21
#define RTMSG_DELROUTE 0x22
#define IP6_RT_PRIO_USER 1024
#define IP6_RT_PRIO_ADDRCONF 256
#endif
```