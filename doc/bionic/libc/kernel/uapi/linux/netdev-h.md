Response:
Let's break down the thought process for analyzing this kernel header file.

**1. Initial Understanding & Context:**

* **File Location:** `bionic/libc/kernel/uapi/linux/netdev.handroid` - This tells us it's part of Android's Bionic library, specifically the user-space API for interacting with the Linux kernel's networking subsystem. The `uapi` part is crucial; it signifies the interface between user-space programs and the kernel. The `.handroid` likely indicates Android-specific extensions or configurations.
* **Auto-generated:** The comment at the top is important. Modifications here are likely overwritten. This suggests the file is generated from a source of truth (like a kernel config or a more abstract description).
* **Purpose:**  The filename `netdev.h` strongly suggests it deals with network devices. The `NETDEV_` prefixes reinforce this.

**2. Identifying Key Components:**

* **Macros (`#define`):**  Look for constants and string literals.
    * `_UAPI_LINUX_NETDEV_H`, `NETDEV_FAMILY_NAME`, `NETDEV_FAMILY_VERSION`: These define the header's identity and a version for the "netdev" family.
* **Enums (`enum`):** These define sets of named constants, likely representing different states, types, or features. This is the core of the file's information.
    * `netdev_xdp_act`: Actions related to XDP (eXpress Data Path), a high-performance networking framework.
    * `netdev_xdp_rx_metadata`: Metadata associated with received XDP packets.
    * `netdev_xsk_flags`: Flags related to XDP sockets.
    * `netdev_queue_type`: Types of network queues (receive or transmit).
    * `netdev_qstats_scope`: Scope for queue statistics.
    * `NETDEV_A_*`:  These enums with the `NETDEV_A_` prefix and names like `DEV`, `PAGE_POOL`, `NAPI`, `QUEUE`, `QSTATS`, `DMABUF`  strongly hint at different attributes or data structures associated with various network device components. The `_MAX` members are often used to determine the size of arrays or data structures based on these enums.
    * `NETDEV_CMD_*`: These likely represent commands that can be issued to the kernel related to network devices.
* **Guards (`#ifndef`, `#define`, `#endif`):** The standard header guard pattern to prevent multiple inclusions.

**3. Analyzing Each Component Type:**

* **Macros:**  Straightforward - identify the name and value. Consider their purpose (e.g., `NETDEV_FAMILY_NAME` is likely used in some system calls or data structures for identification).
* **Enums:**  This requires more interpretation.
    * **Group by Prefix:** Notice the common prefixes like `NETDEV_XDP_`, `NETDEV_A_`, `NETDEV_CMD_`. This helps organize the information.
    * **Infer Meaning from Names:**  Try to understand what each enum member represents. For example, `NETDEV_XDP_ACT_REDIRECT` clearly indicates an action to redirect an XDP packet. `NETDEV_A_QUEUE_TYPE` obviously specifies whether a queue is for RX or TX.
    * **Look for Bitmasks:**  Values like powers of 2 (1, 2, 4, 8, 16...) in enums like `netdev_xdp_act` suggest they might be used as bitmasks, allowing multiple options to be combined.
    * **Identify Relationships:** Observe how different enums might relate to each other. For example, `NETDEV_A_QUEUE_NAPI_ID` suggests a link between queues and NAPI (New API) structures.
    * **Consider the Context of "uapi":** Remember these enums define the interface visible to user-space programs. This means these are the constants and types that user-space code will use to interact with the kernel's networking features.

**4. Connecting to Android:**

* **Bionic Context:**  Since this file is in Bionic, it's a fundamental part of the Android system. Any functionality defined here is potentially used by Android's networking stack.
* **High-Performance Networking:** The presence of XDP-related definitions immediately points to support for high-performance networking, which is relevant for modern Android use cases (e.g., high bandwidth applications, network function virtualization).
* **Framework/NDK Interaction:**  Consider how Android applications using the NDK (Native Development Kit) might leverage these definitions to interact with the kernel's networking.

**5. Addressing Specific Questions in the Prompt:**

* **Functions:** This file doesn't define *functions* in the traditional C sense (like `int foo(int a)`). It defines *constants* and *types*. Therefore, the explanation will focus on the *meaning* and *usage* of these definitions, not their implementation within Bionic itself. The *implementation* lives in the Linux kernel.
* **Dynamic Linker:** This file is a header file. Header files are used *during compilation*, not at runtime by the dynamic linker. Therefore, dynamic linker specifics aren't directly relevant here. The *constants* defined here might be used by libraries that are dynamically linked, but this header itself isn't involved in the linking process.
* **Logic Inference/Assumptions:** This is where you need to make educated guesses about how these constants are used. For example, assuming `NETDEV_CMD_DEV_GET` is used to retrieve information about a network device.
* **Common Errors:** Think about how a programmer might misuse these constants. Incorrectly setting bitmasks, using the wrong enum value, etc.
* **Android Framework/NDK Path:**  Trace how network operations in the Android framework eventually lead to system calls that utilize these definitions. This involves understanding the Android networking stack's architecture.
* **Frida Hook Example:**  Illustrate how Frida can be used to intercept system calls or function calls that use these constants to observe their values.

**6. Structuring the Response:**

Organize the information logically:

* **Introduction:** Briefly state the file's purpose and context.
* **Functionality:** List the key functional areas based on the enums (XDP, queue management, statistics, etc.).
* **Android Relevance:**  Provide concrete examples of how these features relate to Android (e.g., high-performance networking for apps).
* **Detailed Explanation of Enums:**  Go through each enum, explaining the meaning of its members.
* **Dynamic Linker (Explain why it's not directly relevant):** Clarify that this is a header file.
* **Logic Inference:** Present plausible scenarios of how these constants might be used.
* **Common Errors:** Give examples of programming mistakes.
* **Android Framework/NDK Path:** Describe the layers of the Android networking stack and how they connect to these definitions.
* **Frida Hook Example:** Provide a code snippet demonstrating how to hook relevant system calls.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  "This file defines functions for network devices."  **Correction:**  Realize it's a header file defining *constants* and *types*, not function implementations. The functions that *use* these definitions are elsewhere (in the kernel and possibly in some Bionic libraries).
* **Initial thought:** "The dynamic linker directly uses this file." **Correction:** Understand that header files are for compilation, not runtime linking. The linker uses compiled code, not header files directly.
* **Focus on the "uapi":** Constantly remind yourself that this is the *user-space* interface to the kernel. The implementations are in the kernel.

By following this structured approach, combining technical knowledge with careful reading and logical deduction, you can effectively analyze and explain the purpose and functionality of a kernel header file like `netdev.handroid`.
这是一个定义Linux网络设备相关常量和枚举类型的头文件，用于Android Bionic C库中，作为用户空间程序与Linux内核进行网络设备交互的接口。

**功能列举：**

这个头文件主要定义了以下功能相关的常量和枚举：

1. **XDP (eXpress Data Path) 相关:**
   - `enum netdev_xdp_act`: 定义了XDP程序可以执行的动作，例如：
     - `NETDEV_XDP_ACT_BASIC`:  基本的XDP处理。
     - `NETDEV_XDP_ACT_REDIRECT`: 将数据包重定向到另一个网络接口。
     - `NETDEV_XDP_ACT_NDO_XMIT`:  通过网络设备驱动的 `ndo_transmit` 函数发送数据包。
     - `NETDEV_XDP_ACT_XSK_ZEROCOPY`:  使用零拷贝方式通过XDP socket发送/接收数据。
     - `NETDEV_XDP_ACT_HW_OFFLOAD`:  将XDP处理卸载到硬件。
     - `NETDEV_XDP_ACT_RX_SG`:  接收分散/聚集 (scatter-gather) 的数据包。
     - `NETDEV_XDP_ACT_NDO_XMIT_SG`:  发送分散/聚集的数据包。
   - `enum netdev_xdp_rx_metadata`: 定义了XDP接收时可以获取的元数据，例如：
     - `NETDEV_XDP_RX_METADATA_TIMESTAMP`:  接收时间戳。
     - `NETDEV_XDP_RX_METADATA_HASH`:  数据包的哈希值。
     - `NETDEV_XDP_RX_METADATA_VLAN_TAG`: VLAN标签。
   - `enum netdev_xsk_flags`: 定义了XDP socket的标志，例如：
     - `NETDEV_XSK_FLAGS_TX_TIMESTAMP`:  请求发送时间戳。
     - `NETDEV_XSK_FLAGS_TX_CHECKSUM`:  请求硬件计算校验和。

2. **网络队列相关:**
   - `enum netdev_queue_type`: 定义了网络队列的类型：
     - `NETDEV_QUEUE_TYPE_RX`: 接收队列。
     - `NETDEV_QUEUE_TYPE_TX`: 发送队列。

3. **队列统计信息作用域:**
   - `enum netdev_qstats_scope`: 定义了队列统计信息的范围：
     - `NETDEV_QSTATS_SCOPE_QUEUE`: 针对特定队列的统计信息。

4. **Netlink属性 (Netlink Attributes):**
   - 定义了用于通过 Netlink 套接字与内核通信时使用的属性 ID，用于获取和设置网络设备的不同方面的信息。这些 `enum` 类型以 `NETDEV_A_` 开头，分别对应不同的对象：
     - `enum { NETDEV_A_DEV_* }`:  网络设备本身的属性，例如接口索引 (`NETDEV_A_DEV_IFINDEX`)，XDP特性 (`NETDEV_A_DEV_XDP_FEATURES`) 等。
     - `enum { NETDEV_A_PAGE_POOL_* }`:  页面池 (page pool) 的属性，用于 XDP 零拷贝。
     - `enum { NETDEV_A_PAGE_POOL_STATS_* }`:  页面池的统计信息。
     - `enum { NETDEV_A_NAPI_* }`:  NAPI (New API) 轮询的属性。
     - `enum { NETDEV_A_QUEUE_* }`:  网络队列的属性。
     - `enum { NETDEV_A_QSTATS_* }`:  网络队列的统计信息，例如收发包数量、错误等。
     - `enum { NETDEV_A_DMABUF_* }`:  DMA buffer 的属性，用于跨进程共享网络数据。

5. **Netlink命令 (Netlink Commands):**
   - `enum { NETDEV_CMD_* }`: 定义了可以通过 Netlink 发送给内核的命令，用于管理网络设备，例如：
     - `NETDEV_CMD_DEV_GET`: 获取网络设备信息。
     - `NETDEV_CMD_DEV_ADD_NTF`, `NETDEV_CMD_DEV_DEL_NTF`, `NETDEV_CMD_DEV_CHANGE_NTF`:  添加、删除、更改网络设备通知。
     - `NETDEV_CMD_PAGE_POOL_GET`: 获取页面池信息。
     - `NETDEV_CMD_QUEUE_GET`: 获取队列信息。
     - `NETDEV_CMD_NAPI_GET`: 获取 NAPI 信息。
     - `NETDEV_CMD_QSTATS_GET`: 获取队列统计信息。
     - `NETDEV_CMD_BIND_RX`: 绑定接收操作。

6. **Netlink多播组 (Netlink Multicast Groups):**
   - `#define NETDEV_MCGRP_MGMT "mgmt"`: 定义了用于管理操作的多播组名称。
   - `#define NETDEV_MCGRP_PAGE_POOL "page-pool"`: 定义了用于页面池操作的多播组名称。

**与Android功能的关联及举例说明：**

这个头文件是 Android 底层网络功能的重要组成部分。Android 应用程序或系统服务需要与内核进行网络设备相关的交互时，会使用到这里定义的常量和枚举。

* **XDP 和高性能网络:** Android 设备上的一些高性能网络应用，例如虚拟化、容器化相关的网络，可能会使用 XDP 来实现高速数据包处理。例如，一个虚拟网卡驱动可能使用 XDP 将数据包直接转发到虚拟机，绕过传统的内核网络协议栈，从而提高性能。
* **网络监控和统计:** Android 系统服务可以使用 Netlink 接口和这里定义的 `NETDEV_A_QSTATS_*` 属性以及 `NETDEV_CMD_QSTATS_GET` 命令来获取网络接口的统计信息，例如收发包数量、错误等。这些信息可以用于网络状态监控、流量统计、性能分析等。例如，Android 的 `ConnectivityService` 或一些网络监控 App 可能会使用这些接口。
* **DMA Buffer 和零拷贝:**  `NETDEV_A_DMABUF_*` 相关的定义表明 Android 支持使用 DMA buffer 来在用户空间和内核空间之间共享网络数据，以及在不同的进程之间共享。这对于实现零拷贝的网络数据传输非常重要，可以显著提高网络性能。例如，一个 VPN 应用可能会使用 DMA buffer 来高效地处理网络数据包。
* **网络设备管理:**  `NETDEV_CMD_DEV_GET` 等命令允许用户空间程序查询和管理网络设备的信息。Android 系统中的 `ip` 命令或其他网络配置工具底层可能会使用这些 Netlink 命令来获取和配置网络接口。

**libc 函数的实现 (此头文件不包含 libc 函数的实现，只定义常量):**

这个头文件本身**不包含任何 libc 函数的实现**。它仅仅定义了常量和枚举类型，这些类型会被 Bionic 中的其他 C 库函数以及内核网络子系统使用。

举例来说，如果你要使用 Netlink 与内核通信来获取网络设备的接口索引，你可能会在你的 C 代码中包含这个头文件，并使用 `NETDEV_A_DEV_IFINDEX` 常量来构造 Netlink 消息。实际发送和接收 Netlink 消息的函数，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等，是 libc 提供的 socket API 的一部分，它们的实现位于 Bionic 的其他源文件中。

**Dynamic Linker 功能 (此头文件与 Dynamic Linker 无直接关系):**

这个头文件是编译时使用的，用于声明常量。它与动态链接器 (Dynamic Linker) **没有直接关系**。动态链接器负责在程序运行时加载和链接共享库。

虽然如此，定义在这个头文件中的常量可能会被 Android 系统中的共享库使用。例如，一个负责处理网络配置的共享库可能会使用 `NETDEV_CMD_DEV_GET` 常量来构建 Netlink 消息。

**SO 布局样本及链接处理过程 (与此头文件无关):**

由于这个头文件不涉及动态链接，所以没有对应的 SO 布局样本或链接处理过程。SO 布局和链接处理是动态链接器的职责，与源代码的组织和编译过程有关。

**逻辑推理、假设输入与输出 (与此头文件定义的常量用法相关):**

假设我们要通过 Netlink 获取网络接口的索引。

* **假设输入:**
    * Netlink 套接字的文件描述符。
    * 目标网络接口的名称 (例如 "wlan0")。
* **逻辑推理:**
    1. 创建一个 Netlink 套接字。
    2. 构建一个 Netlink 消息，设置消息头，包含 `NETDEV_CMD_DEV_GET` 命令。
    3. 添加一个 Netlink 属性，类型为 `IFLA_IFNAME`，值为目标接口名称 "wlan0"。
    4. 将 Netlink 消息发送到内核。
    5. 从内核接收 Netlink 响应消息。
    6. 解析响应消息，查找类型为 `NETDEV_A_DEV_IFINDEX` 的属性，其值即为接口索引。
* **预期输出:**
    * 目标网络接口的索引值 (一个整数)。

**用户或编程常见的使用错误举例：**

1. **使用错误的 Netlink 属性 ID:**  例如，错误地使用了 `NETDEV_A_QUEUE_ID` 来获取设备接口索引，导致内核无法识别请求。
2. **构建错误的 Netlink 消息格式:**  例如，消息头中的协议族或消息类型不正确，导致内核无法解析。
3. **忘记处理 Netlink 消息的错误码:**  内核可能会返回错误消息，如果程序没有正确处理，可能会导致程序行为异常。
4. **假设所有设备都支持某个 XDP 特性:**  在没有检查 `NETDEV_A_DEV_XDP_FEATURES` 的情况下，就尝试使用某个特定的 XDP 功能，可能导致操作失败。
5. **在不适当的上下文中使用了某些常量:**  例如，在不应该使用页面池的场景下，错误地使用了与页面池相关的常量。

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例：**

1. **NDK 应用:**  一个使用 NDK 开发的 C/C++ 应用如果需要直接与 Linux 网络设备交互 (例如，实现一个自定义的网络协议栈或进行高性能网络处理)，可能会包含这个头文件，并使用其中的常量来构建 Netlink 消息或进行其他系统调用。

2. **Android Framework:** Android Framework 中与网络相关的服务，例如 `ConnectivityService`, `NetworkStack`, `VpnService` 等，在底层与内核进行交互时，最终会通过系统调用 (syscall) 来实现。这些系统调用可能涉及到操作网络设备，而内核中处理这些系统调用的代码会使用到这里定义的常量。

   * **例如，`ConnectivityService` 需要获取网络接口的状态信息：**
      1. `ConnectivityService` 调用 Java 层 Network Management API。
      2. Java 层 API 通过 JNI 调用到 native 代码。
      3. Native 代码可能会使用 `libnetutils` 或其他 Bionic 库。
      4. 这些库可能会使用 socket API 和 Netlink 协议与内核通信。
      5. 在构建 Netlink 消息时，会使用到 `bionic/libc/kernel/uapi/linux/netdev.handroid` 中定义的常量，例如 `NETDEV_CMD_DEV_GET` 和 `NETDEV_A_DEV_IFINDEX`。
      6. 内核接收到 Netlink 消息后，会根据消息中的命令和属性进行处理，并将结果返回给用户空间。

**Frida Hook 示例调试步骤：**

假设你想观察 Android 系统中哪个进程在获取网络接口的索引，你可以使用 Frida Hook `recvfrom` 系统调用，并检查接收到的 Netlink 消息。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.android.systemui"]) # 以 SystemUI 进程为例
    session = device.attach(pid)
except Exception as e:
    print(f"Error attaching to device or spawning process: {e}")
    sys.exit(1)

script_code = """
const recvfromPtr = Module.getExportByName(null, "recvfrom");

Interceptor.attach(recvfromPtr, {
    onEnter: function(args) {
        // args[0] 是 socket fd
        // args[1] 是接收缓冲区的地址
        // args[2] 是接收缓冲区的大小
        this.buf = args[1];
        this.len = args[2].toInt();
    },
    onLeave: function(retval) {
        if (retval.toInt() > 0) {
            const receivedData = Memory.readByteArray(this.buf, retval.toInt());
            // 这里可以解析 Netlink 消息，判断是否是与 NETDEV 相关的命令
            // 并检查是否使用了 NETDEV_CMD_DEV_GET 和 NETDEV_A_DEV_IFINDEX

            // 简单的打印接收到的数据
            send({
                type: 'recvfrom',
                data: hexdump(receivedData, { offset: 0, length: retval.toInt(), header: true, ansi: true })
            });
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

try:
    sys.stdin.read()
except KeyboardInterrupt:
    session.detach()
```

**解释 Frida Hook 示例：**

1. **Attach to Process:**  首先，我们使用 Frida 连接到目标 Android 设备，并附加到 `com.android.systemui` 进程 (你可以根据需要替换为其他进程)。
2. **Get `recvfrom` Address:**  我们获取 `recvfrom` 系统调用在内存中的地址。
3. **Intercept `recvfrom`:**  使用 `Interceptor.attach` 拦截 `recvfrom` 函数的调用。
4. **`onEnter`:**  在 `recvfrom` 函数调用之前，我们记录接收缓冲区的地址和大小。
5. **`onLeave`:**  在 `recvfrom` 函数返回之后，如果返回值大于 0 (表示成功接收到数据)，我们读取接收到的数据。
6. **Analyze Data:**  在 `onLeave` 中，你可以进一步解析接收到的数据，判断它是否是一个 Netlink 消息，以及是否使用了 `NETDEV_CMD_DEV_GET` 命令和 `NETDEV_A_DEV_IFINDEX` 属性。这需要对 Netlink 协议有一定的了解。
7. **Send Message:**  我们将接收到的数据以十六进制形式打印出来，方便查看。

通过运行这个 Frida 脚本，你可以观察到 `com.android.systemui` 进程接收到的网络数据，并分析其中是否包含与获取网络接口索引相关的 Netlink 消息，从而验证 Android Framework 是如何一步步到达这个内核头文件中定义的常量的。

请注意，实际的 Android 网络交互可能非常复杂，涉及到多个系统服务和库，你需要根据具体的场景选择合适的 Hook 点和分析方法。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/netdev.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_NETDEV_H
#define _UAPI_LINUX_NETDEV_H
#define NETDEV_FAMILY_NAME "netdev"
#define NETDEV_FAMILY_VERSION 1
enum netdev_xdp_act {
  NETDEV_XDP_ACT_BASIC = 1,
  NETDEV_XDP_ACT_REDIRECT = 2,
  NETDEV_XDP_ACT_NDO_XMIT = 4,
  NETDEV_XDP_ACT_XSK_ZEROCOPY = 8,
  NETDEV_XDP_ACT_HW_OFFLOAD = 16,
  NETDEV_XDP_ACT_RX_SG = 32,
  NETDEV_XDP_ACT_NDO_XMIT_SG = 64,
  NETDEV_XDP_ACT_MASK = 127,
};
enum netdev_xdp_rx_metadata {
  NETDEV_XDP_RX_METADATA_TIMESTAMP = 1,
  NETDEV_XDP_RX_METADATA_HASH = 2,
  NETDEV_XDP_RX_METADATA_VLAN_TAG = 4,
};
enum netdev_xsk_flags {
  NETDEV_XSK_FLAGS_TX_TIMESTAMP = 1,
  NETDEV_XSK_FLAGS_TX_CHECKSUM = 2,
};
enum netdev_queue_type {
  NETDEV_QUEUE_TYPE_RX,
  NETDEV_QUEUE_TYPE_TX,
};
enum netdev_qstats_scope {
  NETDEV_QSTATS_SCOPE_QUEUE = 1,
};
enum {
  NETDEV_A_DEV_IFINDEX = 1,
  NETDEV_A_DEV_PAD,
  NETDEV_A_DEV_XDP_FEATURES,
  NETDEV_A_DEV_XDP_ZC_MAX_SEGS,
  NETDEV_A_DEV_XDP_RX_METADATA_FEATURES,
  NETDEV_A_DEV_XSK_FEATURES,
  __NETDEV_A_DEV_MAX,
  NETDEV_A_DEV_MAX = (__NETDEV_A_DEV_MAX - 1)
};
enum {
  NETDEV_A_PAGE_POOL_ID = 1,
  NETDEV_A_PAGE_POOL_IFINDEX,
  NETDEV_A_PAGE_POOL_NAPI_ID,
  NETDEV_A_PAGE_POOL_INFLIGHT,
  NETDEV_A_PAGE_POOL_INFLIGHT_MEM,
  NETDEV_A_PAGE_POOL_DETACH_TIME,
  NETDEV_A_PAGE_POOL_DMABUF,
  __NETDEV_A_PAGE_POOL_MAX,
  NETDEV_A_PAGE_POOL_MAX = (__NETDEV_A_PAGE_POOL_MAX - 1)
};
enum {
  NETDEV_A_PAGE_POOL_STATS_INFO = 1,
  NETDEV_A_PAGE_POOL_STATS_ALLOC_FAST = 8,
  NETDEV_A_PAGE_POOL_STATS_ALLOC_SLOW,
  NETDEV_A_PAGE_POOL_STATS_ALLOC_SLOW_HIGH_ORDER,
  NETDEV_A_PAGE_POOL_STATS_ALLOC_EMPTY,
  NETDEV_A_PAGE_POOL_STATS_ALLOC_REFILL,
  NETDEV_A_PAGE_POOL_STATS_ALLOC_WAIVE,
  NETDEV_A_PAGE_POOL_STATS_RECYCLE_CACHED,
  NETDEV_A_PAGE_POOL_STATS_RECYCLE_CACHE_FULL,
  NETDEV_A_PAGE_POOL_STATS_RECYCLE_RING,
  NETDEV_A_PAGE_POOL_STATS_RECYCLE_RING_FULL,
  NETDEV_A_PAGE_POOL_STATS_RECYCLE_RELEASED_REFCNT,
  __NETDEV_A_PAGE_POOL_STATS_MAX,
  NETDEV_A_PAGE_POOL_STATS_MAX = (__NETDEV_A_PAGE_POOL_STATS_MAX - 1)
};
enum {
  NETDEV_A_NAPI_IFINDEX = 1,
  NETDEV_A_NAPI_ID,
  NETDEV_A_NAPI_IRQ,
  NETDEV_A_NAPI_PID,
  __NETDEV_A_NAPI_MAX,
  NETDEV_A_NAPI_MAX = (__NETDEV_A_NAPI_MAX - 1)
};
enum {
  NETDEV_A_QUEUE_ID = 1,
  NETDEV_A_QUEUE_IFINDEX,
  NETDEV_A_QUEUE_TYPE,
  NETDEV_A_QUEUE_NAPI_ID,
  NETDEV_A_QUEUE_DMABUF,
  __NETDEV_A_QUEUE_MAX,
  NETDEV_A_QUEUE_MAX = (__NETDEV_A_QUEUE_MAX - 1)
};
enum {
  NETDEV_A_QSTATS_IFINDEX = 1,
  NETDEV_A_QSTATS_QUEUE_TYPE,
  NETDEV_A_QSTATS_QUEUE_ID,
  NETDEV_A_QSTATS_SCOPE,
  NETDEV_A_QSTATS_RX_PACKETS = 8,
  NETDEV_A_QSTATS_RX_BYTES,
  NETDEV_A_QSTATS_TX_PACKETS,
  NETDEV_A_QSTATS_TX_BYTES,
  NETDEV_A_QSTATS_RX_ALLOC_FAIL,
  NETDEV_A_QSTATS_RX_HW_DROPS,
  NETDEV_A_QSTATS_RX_HW_DROP_OVERRUNS,
  NETDEV_A_QSTATS_RX_CSUM_COMPLETE,
  NETDEV_A_QSTATS_RX_CSUM_UNNECESSARY,
  NETDEV_A_QSTATS_RX_CSUM_NONE,
  NETDEV_A_QSTATS_RX_CSUM_BAD,
  NETDEV_A_QSTATS_RX_HW_GRO_PACKETS,
  NETDEV_A_QSTATS_RX_HW_GRO_BYTES,
  NETDEV_A_QSTATS_RX_HW_GRO_WIRE_PACKETS,
  NETDEV_A_QSTATS_RX_HW_GRO_WIRE_BYTES,
  NETDEV_A_QSTATS_RX_HW_DROP_RATELIMITS,
  NETDEV_A_QSTATS_TX_HW_DROPS,
  NETDEV_A_QSTATS_TX_HW_DROP_ERRORS,
  NETDEV_A_QSTATS_TX_CSUM_NONE,
  NETDEV_A_QSTATS_TX_NEEDS_CSUM,
  NETDEV_A_QSTATS_TX_HW_GSO_PACKETS,
  NETDEV_A_QSTATS_TX_HW_GSO_BYTES,
  NETDEV_A_QSTATS_TX_HW_GSO_WIRE_PACKETS,
  NETDEV_A_QSTATS_TX_HW_GSO_WIRE_BYTES,
  NETDEV_A_QSTATS_TX_HW_DROP_RATELIMITS,
  NETDEV_A_QSTATS_TX_STOP,
  NETDEV_A_QSTATS_TX_WAKE,
  __NETDEV_A_QSTATS_MAX,
  NETDEV_A_QSTATS_MAX = (__NETDEV_A_QSTATS_MAX - 1)
};
enum {
  NETDEV_A_DMABUF_IFINDEX = 1,
  NETDEV_A_DMABUF_QUEUES,
  NETDEV_A_DMABUF_FD,
  NETDEV_A_DMABUF_ID,
  __NETDEV_A_DMABUF_MAX,
  NETDEV_A_DMABUF_MAX = (__NETDEV_A_DMABUF_MAX - 1)
};
enum {
  NETDEV_CMD_DEV_GET = 1,
  NETDEV_CMD_DEV_ADD_NTF,
  NETDEV_CMD_DEV_DEL_NTF,
  NETDEV_CMD_DEV_CHANGE_NTF,
  NETDEV_CMD_PAGE_POOL_GET,
  NETDEV_CMD_PAGE_POOL_ADD_NTF,
  NETDEV_CMD_PAGE_POOL_DEL_NTF,
  NETDEV_CMD_PAGE_POOL_CHANGE_NTF,
  NETDEV_CMD_PAGE_POOL_STATS_GET,
  NETDEV_CMD_QUEUE_GET,
  NETDEV_CMD_NAPI_GET,
  NETDEV_CMD_QSTATS_GET,
  NETDEV_CMD_BIND_RX,
  __NETDEV_CMD_MAX,
  NETDEV_CMD_MAX = (__NETDEV_CMD_MAX - 1)
};
#define NETDEV_MCGRP_MGMT "mgmt"
#define NETDEV_MCGRP_PAGE_POOL "page-pool"
#endif

"""

```