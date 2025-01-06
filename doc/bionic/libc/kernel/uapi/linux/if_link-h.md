Response:
Let's break down the thought process for answering the request about `if_link.h`.

**1. Understanding the Core Request:**

The central request is to analyze the provided C header file (`if_link.h`) from the Android Bionic library and explain its purpose, relation to Android, implementation details (if any are directly present), dynamic linker aspects, usage errors, and its path from Android Framework/NDK. Crucially, the request emphasizes explaining functions and dynamic linker involvement.

**2. Initial Assessment of the File:**

The first thing to notice is that this is a *header file* (`.h`). Header files primarily define data structures, constants, and function *declarations*. They don't contain the actual *implementation* of functions. This is a critical point.

**3. Identifying Key Elements within the Header:**

Scanning the file reveals these key components:

* **Include Directives:** `#include <linux/types.h>` and `#include <linux/netlink.h>`. This immediately suggests that this header bridges user-space (Android's Bionic) with Linux kernel networking concepts.
* **Structures:** `rtnl_link_stats`, `rtnl_link_stats64`, `rtnl_hw_stats64`, `rtnl_link_ifmap`, `ifla_bridge_id`, `ifla_cacheinfo`, `ifla_vlan_flags`, etc. These structures clearly represent network interface link information and configurations. The names themselves are quite descriptive (e.g., "rtnl_link_stats" likely holds link statistics for routing netlink).
* **Enums:** A large number of `enum` declarations like `IFLA_UNSPEC`, `IFLA_INET_UNSPEC`, `IFLA_BR_UNSPEC`, etc. The pattern "IFLA_" strongly suggests these are attributes related to network interfaces. The descriptive names within each enum provide further clues about their purpose (e.g., `IFLA_MTU`, `IFLA_ADDRESS`).
* **Macros:** `#define IFLA_COST IFLA_COST`, `#define IFLA_RTA(r)`, `#define IFLA_PAYLOAD(n)`, and various `#define` constants. These are used for convenience, code clarity, and potentially for calculating sizes or offsets. The `IFLA_RTA` and `IFLA_PAYLOAD` macros point towards working with netlink messages, as `rtattr` and payload sizes are common netlink concepts.

**4. Addressing Each Part of the Request Systematically:**

* **Functionality:** Based on the identified elements, the primary function is clearly to define data structures and constants for interacting with the Linux kernel's networking subsystem, specifically related to network interface link information. This includes statistics, attributes, and configuration options.

* **Relationship to Android:**  Android's networking stack relies heavily on the underlying Linux kernel. This header provides the necessary definitions for Android (through Bionic) to communicate with the kernel to manage network interfaces. Examples include getting interface statistics (data usage), configuring IP addresses, setting MTU, and managing bridge interfaces (like for Wi-Fi tethering or VPNs).

* **libc Function Implementation:**  This is a crucial point where understanding header files is key. *Header files do not contain function implementations.* They declare structures and constants. Therefore, the answer must explicitly state this. The *implementation* of functions that *use* these definitions resides in other `.c` files within Bionic or potentially within the kernel itself.

* **Dynamic Linker:**  This header file itself has *no direct interaction* with the dynamic linker. The dynamic linker's job is to resolve symbols and load shared libraries (`.so` files). Header files are used during compilation, not at runtime by the dynamic linker. The answer should clearly state this lack of direct involvement. The request to provide `.so` layout and linking process is not applicable *to this specific header file*.

* **Logical Reasoning (Assumptions):** Since there are no functions to analyze, there's no direct logical reasoning with input/output. However, one could *infer* the *purpose* of certain fields. For example, assuming a function receives a `rtnl_link_stats` structure, the `rx_packets` field would logically represent the number of received packets. This kind of inference is valid but should be stated as an assumption.

* **Common Usage Errors:**  Without functions, direct programming errors related to this *specific file* are limited. However, *using* the defined structures incorrectly (e.g., misinterpreting the units of a statistic, using incorrect attribute IDs) are potential errors. Also, forgetting to include the header file is a basic error.

* **Android Framework/NDK to this Point:**  This requires tracing the path. User-space applications (including those using the NDK) interact with the kernel through system calls. The `netlink` mechanism is a common way for user-space processes to communicate with the kernel's networking subsystem. The Android Framework (e.g., `ConnectivityService`) uses these mechanisms (often indirectly) to manage network connections. The NDK allows developers to directly use lower-level networking APIs, which might involve structures defined in this header. A Frida hook example should demonstrate hooking a system call related to network interface management or a function within Bionic that utilizes these structures.

**5. Structuring the Answer:**

Organize the answer clearly, addressing each part of the request. Use headings and bullet points for better readability.

**6. Language and Tone:**

Use clear and concise Chinese. Explain technical terms where necessary. Be precise in stating what the header file *does* and *does not* do. Avoid over-speculation or inventing information.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Might have initially considered if any inline functions were present. A closer look confirms it's just declarations and definitions.
* **Realization:** The request heavily emphasizes "libc function implementation" and "dynamic linker". Recognizing that this is a *header file* and doesn't contain those is crucial for a correct answer. Don't try to force an explanation where it's not applicable. Instead, clearly state the limitations of the file.
* **Focus Shift:**  Since there are no direct function implementations, shift the focus to how these definitions are *used* by other parts of Bionic and the kernel.
* **Frida Example:**  The Frida example needs to target an actual function call or system call that *uses* the structures defined in this header, rather than just hooking something random. Focus on netlink interaction.

By following this systematic approach and constantly evaluating the information within the file, a comprehensive and accurate answer can be constructed.
这是一个关于Linux网络接口链接层（Link Layer）信息的头文件，定义了一些用于与内核通信的结构体和枚举常量。由于它位于 `bionic/libc/kernel/uapi/linux` 目录下，说明它是用户空间（Userspace）程序可以直接使用的，用于访问内核提供的关于网络接口链接层的信息。Bionic是Android的基础C库，所以这个头文件是Android系统网络功能的基础组成部分。

**功能列举:**

1. **定义网络接口统计信息结构体:**
   - `rtnl_link_stats`:  包含32位整型的网络接口收发包、字节、错误、丢包等统计信息。
   - `rtnl_link_stats64`: 包含64位整型的网络接口收发包、字节、错误、丢包等统计信息，用于计数更大的数据量。
   - `rtnl_hw_stats64`: 包含64位整型的硬件层面网络接口收发包、字节、错误、丢包等统计信息。

2. **定义网络接口硬件映射信息结构体:**
   - `rtnl_link_ifmap`: 描述网络接口的内存起始地址、结束地址、基地址、中断号、DMA通道和端口号等硬件映射信息。

3. **定义网络接口属性（Attribute）的枚举常量:**
   - 以 `IFLA_` 开头的枚举常量，用于在与内核进行 Netlink 通信时标识不同的网络接口属性，例如接口名称 (`IFLA_IFNAME`)、MTU值 (`IFLA_MTU`)、MAC地址 (`IFLA_ADDRESS`)、统计信息 (`IFLA_STATS`, `IFLA_STATS64`) 等等。 这些常量在配置和查询网络接口信息时被广泛使用。

4. **定义与桥接（Bridging）、VLAN、MACVLAN、VXLAN 等网络虚拟化技术相关的属性枚举常量:**
   - 以 `IFLA_BR_`、`IFLA_VLAN_`、`IFLA_MACVLAN_`、`IFLA_VXLAN_` 等开头的枚举常量，用于配置和查询这些虚拟网络接口的特定属性。

5. **定义与XDP (eXpress Data Path) 相关的属性枚举常量:**
   - 以 `IFLA_XDP_` 开头的枚举常量，用于管理网络接口的 XDP 程序。

6. **定义其他网络接口类型（例如Bonding, Tunnel, VLAN等）相关的属性枚举常量:**
   - 涵盖了各种常见的Linux网络接口类型，允许用户空间程序配置和查询这些接口的特定参数。

**与Android功能的关联及举例说明:**

这个头文件中的定义直接关系到Android系统的网络功能，因为它提供了与Linux内核网络接口层交互的基础数据结构和常量。Android Framework 和 Native 层需要通过这些定义来获取和设置网络接口的状态。

**举例说明:**

* **获取网络接口统计信息:** Android系统需要监控网络使用情况，例如流量统计。`ConnectivityService` 或者一些流量监控的应用会使用 Netlink Socket 与内核通信，请求 `IFLA_STATS64` 属性，内核会返回包含 `rtnl_link_stats64` 结构体的数据，其中包含了接口的收发字节数，用于计算流量。
* **配置IP地址和MTU:** 当Android设备连接到Wi-Fi或者移动网络时，系统需要配置IP地址、子网掩码、网关、DNS等信息，同时可能需要设置MTU值。 这会涉及到使用 Netlink Socket 发送包含 `IFLA_ADDRESS` 和 `IFLA_MTU` 属性的消息给内核。
* **管理Wi-Fi热点 (软AP):**  Wi-Fi热点功能通常会在内部创建一个桥接接口。Android系统会使用与桥接相关的属性 (例如 `IFLA_BR_FORWARD_DELAY`, `IFLA_BR_HELLO_TIME`) 来配置这个桥接接口。
* **VPN连接:** VPN 连接的建立通常会创建虚拟网络接口（例如TUN或TAP设备）。Android的VPN客户端会使用与这些接口类型相关的属性 (例如 `IFLA_TUN_OWNER`, `IFLA_TUN_TYPE`) 来配置这些接口。

**详细解释每一个libc函数的功能是如何实现的:**

**这个头文件本身并不包含 libc 函数的实现。** 它只是定义了数据结构和常量。这些结构体会被 libc 中的网络相关函数（例如 socket、ioctl 等）以及直接使用 Netlink Socket 的函数所使用。

举例来说，如果你想获取网络接口的统计信息，你可能会在用户空间程序中使用类似下面的流程：

1. **创建 Netlink Socket:** 使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` 创建一个 Netlink Socket。
2. **构造 Netlink 消息:**  构造一个请求网络接口信息的 Netlink 消息，其中消息头部的 `nlmsg_type` 通常是 `RTM_GETLINK`，消息内容部分包含一个 `ifinfomsg` 结构体，并使用 `rtattr` 结构体添加属性，例如 `IFLA_IFNAME` 来指定要查询的接口名称，或者 `IFLA_EXT_MASK` 来请求扩展信息，包括统计数据。
3. **发送消息到内核:** 使用 `send()` 或 `sendto()` 将 Netlink 消息发送到内核。
4. **接收内核的响应:** 使用 `recv()` 或 `recvfrom()` 接收来自内核的 Netlink 响应消息。
5. **解析响应消息:** 解析接收到的 Netlink 消息，提取出包含网络接口信息的 `ifinfomsg` 结构体，以及使用 `RTA_DATA()` 等宏提取出 `IFLA_STATS` 或 `IFLA_STATS64` 属性对应的数据，这些数据就是 `rtnl_link_stats` 或 `rtnl_link_stats64` 结构体。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件本身与 dynamic linker 没有直接的功能关系。** dynamic linker (在Android中主要是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库 (`.so` 文件)，并解析和重定位符号。

这个头文件中定义的结构体和常量会被编译到使用它们的程序中，最终链接到 Bionic 的 libc.so 或者其他相关的共享库中。

**so 布局样本 (libc.so 的部分布局):**

```
libc.so:
    .text          # 包含 libc 函数的机器码
    .rodata        # 只读数据，例如字符串常量
    .data          # 已初始化的全局变量和静态变量
    .bss           # 未初始化的全局变量和静态变量
    .dynsym        # 动态符号表，包含导出的符号
    .dynstr        # 动态字符串表，包含符号名称
    .plt           # 程序链接表，用于延迟绑定
    .got           # 全局偏移表，用于访问全局数据

    # ... 其他段 ...

    # 在 .rodata 或其他数据段中，可能会包含一些辅助数据结构或常量，
    # 但 if_link.h 中定义的结构体通常是在栈上或堆上分配的，而不是静态存储在 .so 文件中。
```

**链接的处理过程:**

1. **编译阶段:** 当编译一个使用了 `if_link.h` 中定义的结构体的程序时，编译器会根据头文件中的定义来确定这些结构体的大小和成员偏移。
2. **链接阶段:** 链接器会将程序的目标文件与所需的共享库（例如 libc.so）链接在一起。如果程序中使用了与网络相关的 libc 函数（这些函数可能会操作 `if_link.h` 中定义的结构体），链接器会确保这些函数调用能够正确地找到 libc.so 中的实现。
3. **动态链接阶段 (程序启动时):** 当程序启动时，dynamic linker 会加载 libc.so 到内存中，并解析程序中对 libc 函数的引用。如果程序需要使用 `if_link.h` 中定义的结构体与内核通信（通常是通过 Netlink Socket 系统调用），那么在程序运行期间，这些结构体会在用户空间被创建和填充，然后作为参数传递给系统调用。

**由于 `if_link.h` 定义的是数据结构，而不是函数，所以它本身不会被 dynamic linker 直接加载或链接。 它的作用是在编译时提供类型信息。**

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个程序想要获取名为 "eth0" 的网络接口的接收包数：

**假设输入:**

* 网络接口名称: "eth0"

**逻辑推理:**

1. 程序创建一个 Netlink Socket。
2. 程序构造一个 `RTM_GETLINK` 类型的 Netlink 消息。
3. 在消息的属性中，设置 `IFLA_IFNAME` 为 "eth0"，并设置 `IFLA_EXT_MASK` 来请求统计信息。
4. 程序将消息发送给内核。
5. 内核接收到消息后，查找名为 "eth0" 的网络接口。
6. 内核提取该接口的统计信息，填充 `rtnl_link_stats` 或 `rtnl_link_stats64` 结构体。
7. 内核构造一个 Netlink 响应消息，其中包含 `IFLA_STATS64` 属性，属性的值是 `rtnl_link_stats64` 结构体的数据。

**假设输出 (Netlink 响应消息中 `IFLA_STATS64` 的部分内容):**

```
struct rtnl_link_stats64 {
  __u64 rx_packets; // 假设为 12345
  __u64 tx_packets;
  __u64 rx_bytes;
  __u64 tx_bytes;
  // ... 其他统计信息 ...
};
```

程序解析响应消息后，会得到 `rx_packets` 的值为 12345。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记包含头文件:** 如果程序中使用了 `if_link.h` 中定义的结构体或常量，但忘记 `#include <linux/if_link.h>`，会导致编译错误，因为编译器无法识别这些类型和常量。

2. **结构体大小不匹配:**  如果用户尝试手动构建 Netlink 消息，可能会因为对结构体的大小或对齐方式理解错误，导致发送给内核的数据不正确，内核可能无法解析或者解析错误。

3. **使用了错误的属性常量:**  在构造 Netlink 消息时，如果使用了错误的 `IFLA_` 常量，可能会导致内核返回错误信息或者返回不期望的数据。例如，错误地使用 `IFLA_STATS` (32位) 来请求需要 64 位统计信息的接口。

4. **没有正确处理 Netlink 消息的边界和对齐:** Netlink 消息的构造需要注意消息头的长度以及属性的对齐方式 (通常是 4 字节对齐)。如果处理不当，会导致消息格式错误。

5. **错误地解释统计信息的含义:**  例如，将 `rx_errors` 误解为丢包数，或者对不同类型的错误计数没有区分。

**说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。**

**Android Framework 到达 `if_link.h` 的路径 (示例：获取网络接口统计信息):**

1. **Android Framework (Java层):** 例如，`ConnectivityService` 或 `NetworkStatsService` 需要获取网络接口的统计信息。
2. **JNI 调用:** Java层会通过 JNI (Java Native Interface) 调用到 Native 层 (C/C++ 代码)。
3. **Native 层 (C/C++):**
   - 可能直接使用 Bionic 提供的网络相关函数，这些函数内部会使用 `if_link.h` 中定义的结构体。
   - 或者，Native 层代码会直接创建 Netlink Socket 并构造 Netlink 消息。
4. **系统调用:** Native 层代码最终会调用 `socket()` 创建 Netlink Socket，并使用 `sendto()` 发送 Netlink 消息到内核。
5. **内核处理:** Linux 内核的网络子系统接收到 Netlink 消息，解析消息内容，根据请求类型 (例如 `RTM_GETLINK`) 和属性 (例如 `IFLA_STATS64`) 执行相应的操作，并构建 Netlink 响应消息。
6. **内核返回:** 内核通过 Netlink Socket 将响应消息发送回用户空间。
7. **Native 层接收和解析:** Native 层代码接收到 Netlink 响应消息，并解析出包含统计信息的 `rtnl_link_stats` 或 `rtnl_link_stats64` 结构体。
8. **JNI 返回:** Native 层将获取到的信息通过 JNI 传递回 Java 层。
9. **Android Framework 使用:** Java 层使用接收到的网络接口统计信息。

**NDK 到达 `if_link.h` 的路径:**

1. **NDK 应用 (C/C++):** 使用 NDK 开发的应用程序可以直接包含 `<linux/if_link.h>` 头文件。
2. **直接使用 Netlink API:** NDK 应用可以创建 Netlink Socket，构造 Netlink 消息，并使用系统调用与内核通信，其过程与上述 Native 层类似。

**Frida Hook 示例 (Hook `sendto` 系统调用，查看发送的 Netlink 消息):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
    session = device.attach(pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName(null, "sendto"), {
            onEnter: function(args) {
                var sockfd = args[0].toInt32();
                var buf = args[1];
                var len = args[2].toInt32();
                var flags = args[3].toInt32();
                var dest_addr = args[4];
                var addrlen = args[5].toInt32();

                // 判断是否是 Netlink Socket (需要根据实际情况判断)
                // 这里简单假设 sockfd 大于某个值可能是 Netlink Socket
                if (sockfd > 3) {
                    console.log("[Sendto] Socket FD: " + sockfd);
                    console.log("[Sendto] Length: " + len);

                    // 读取发送的数据 (Netlink 消息)
                    var message = Memory.readByteArray(buf, len);
                    send({type: "send", payload: hexdump(message, { offset: 0, length: len, header: true, ansi: true })});
                }
            },
            onLeave: function(retval) {
                // console.log("sendto returned: " + retval);
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
except frida.TimedOutError:
    print("Error: Could not find USB device.")
except frida.ProcessNotFoundError:
    print("Error: Process not found.")
except Exception as e:
    print(f"An error occurred: {e}")
```

**解释 Frida Hook 代码:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **`on_message` 函数:**  定义一个消息处理函数，用于接收来自 Frida Hook 的消息。
3. **获取设备和附加进程:** 使用 `frida.get_usb_device()` 获取 USB 设备，并使用 `device.spawn()` 启动目标应用（替换 `com.example.myapp` 为实际应用包名），然后使用 `device.attach()` 附加到进程。
4. **创建 Frida Script:** 使用 `session.create_script()` 创建 Frida 脚本。
5. **Hook `sendto`:** 使用 `Interceptor.attach()` Hook `sendto` 系统调用。
6. **`onEnter` 函数:** 在 `sendto` 调用之前执行：
   - 获取 `sendto` 的参数，例如 Socket 文件描述符 (`sockfd`)、发送缓冲区 (`buf`)、数据长度 (`len`) 等。
   - **判断是否是 Netlink Socket:**  这里使用一个简单的假设 `sockfd > 3` 来判断是否可能是 Netlink Socket。**更严谨的判断需要检查 Socket 的协议族。**
   - 读取发送的数据：使用 `Memory.readByteArray()` 读取发送缓冲区的内容。
   - 发送消息回 Python：使用 `send()` 函数将读取到的数据以十六进制形式发送回 Python 脚本，方便查看 Netlink 消息的内容。
7. **`onLeave` 函数:** 在 `sendto` 调用之后执行（此处注释掉了，可以用来查看返回值）。
8. **加载和运行脚本:** 使用 `script.on('message', on_message)` 注册消息处理函数，`script.load()` 加载脚本，`device.resume(pid)` 恢复进程执行。
9. **保持脚本运行:** `sys.stdin.read()` 用于让 Python 脚本保持运行状态，以便持续监听 Hook 的消息。

**运行此 Frida 脚本后，当目标应用尝试发送 Netlink 消息时，你可以在终端看到 `sendto` 系统调用的相关信息，包括发送的 Netlink 消息的十六进制内容。 通过分析这些内容，你可以看到 `if_link.h` 中定义的结构体和常量是如何被用来构造 Netlink 消息的。**

**请注意:**  Hook 系统调用可能需要 root 权限或者在某些受限环境下无法工作。 此外，判断是否是 Netlink Socket 的方式需要根据实际情况进行调整，更可靠的方法是检查 Socket 的协议族。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/if_link.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_IF_LINK_H
#define _UAPI_LINUX_IF_LINK_H
#include <linux/types.h>
#include <linux/netlink.h>
struct rtnl_link_stats {
  __u32 rx_packets;
  __u32 tx_packets;
  __u32 rx_bytes;
  __u32 tx_bytes;
  __u32 rx_errors;
  __u32 tx_errors;
  __u32 rx_dropped;
  __u32 tx_dropped;
  __u32 multicast;
  __u32 collisions;
  __u32 rx_length_errors;
  __u32 rx_over_errors;
  __u32 rx_crc_errors;
  __u32 rx_frame_errors;
  __u32 rx_fifo_errors;
  __u32 rx_missed_errors;
  __u32 tx_aborted_errors;
  __u32 tx_carrier_errors;
  __u32 tx_fifo_errors;
  __u32 tx_heartbeat_errors;
  __u32 tx_window_errors;
  __u32 rx_compressed;
  __u32 tx_compressed;
  __u32 rx_nohandler;
};
struct rtnl_link_stats64 {
  __u64 rx_packets;
  __u64 tx_packets;
  __u64 rx_bytes;
  __u64 tx_bytes;
  __u64 rx_errors;
  __u64 tx_errors;
  __u64 rx_dropped;
  __u64 tx_dropped;
  __u64 multicast;
  __u64 collisions;
  __u64 rx_length_errors;
  __u64 rx_over_errors;
  __u64 rx_crc_errors;
  __u64 rx_frame_errors;
  __u64 rx_fifo_errors;
  __u64 rx_missed_errors;
  __u64 tx_aborted_errors;
  __u64 tx_carrier_errors;
  __u64 tx_fifo_errors;
  __u64 tx_heartbeat_errors;
  __u64 tx_window_errors;
  __u64 rx_compressed;
  __u64 tx_compressed;
  __u64 rx_nohandler;
  __u64 rx_otherhost_dropped;
};
struct rtnl_hw_stats64 {
  __u64 rx_packets;
  __u64 tx_packets;
  __u64 rx_bytes;
  __u64 tx_bytes;
  __u64 rx_errors;
  __u64 tx_errors;
  __u64 rx_dropped;
  __u64 tx_dropped;
  __u64 multicast;
};
struct rtnl_link_ifmap {
  __u64 mem_start;
  __u64 mem_end;
  __u64 base_addr;
  __u16 irq;
  __u8 dma;
  __u8 port;
};
enum {
  IFLA_UNSPEC,
  IFLA_ADDRESS,
  IFLA_BROADCAST,
  IFLA_IFNAME,
  IFLA_MTU,
  IFLA_LINK,
  IFLA_QDISC,
  IFLA_STATS,
  IFLA_COST,
#define IFLA_COST IFLA_COST
  IFLA_PRIORITY,
#define IFLA_PRIORITY IFLA_PRIORITY
  IFLA_MASTER,
#define IFLA_MASTER IFLA_MASTER
  IFLA_WIRELESS,
#define IFLA_WIRELESS IFLA_WIRELESS
  IFLA_PROTINFO,
#define IFLA_PROTINFO IFLA_PROTINFO
  IFLA_TXQLEN,
#define IFLA_TXQLEN IFLA_TXQLEN
  IFLA_MAP,
#define IFLA_MAP IFLA_MAP
  IFLA_WEIGHT,
#define IFLA_WEIGHT IFLA_WEIGHT
  IFLA_OPERSTATE,
  IFLA_LINKMODE,
  IFLA_LINKINFO,
#define IFLA_LINKINFO IFLA_LINKINFO
  IFLA_NET_NS_PID,
  IFLA_IFALIAS,
  IFLA_NUM_VF,
  IFLA_VFINFO_LIST,
  IFLA_STATS64,
  IFLA_VF_PORTS,
  IFLA_PORT_SELF,
  IFLA_AF_SPEC,
  IFLA_GROUP,
  IFLA_NET_NS_FD,
  IFLA_EXT_MASK,
  IFLA_PROMISCUITY,
#define IFLA_PROMISCUITY IFLA_PROMISCUITY
  IFLA_NUM_TX_QUEUES,
  IFLA_NUM_RX_QUEUES,
  IFLA_CARRIER,
  IFLA_PHYS_PORT_ID,
  IFLA_CARRIER_CHANGES,
  IFLA_PHYS_SWITCH_ID,
  IFLA_LINK_NETNSID,
  IFLA_PHYS_PORT_NAME,
  IFLA_PROTO_DOWN,
  IFLA_GSO_MAX_SEGS,
  IFLA_GSO_MAX_SIZE,
  IFLA_PAD,
  IFLA_XDP,
  IFLA_EVENT,
  IFLA_NEW_NETNSID,
  IFLA_IF_NETNSID,
  IFLA_TARGET_NETNSID = IFLA_IF_NETNSID,
  IFLA_CARRIER_UP_COUNT,
  IFLA_CARRIER_DOWN_COUNT,
  IFLA_NEW_IFINDEX,
  IFLA_MIN_MTU,
  IFLA_MAX_MTU,
  IFLA_PROP_LIST,
  IFLA_ALT_IFNAME,
  IFLA_PERM_ADDRESS,
  IFLA_PROTO_DOWN_REASON,
  IFLA_PARENT_DEV_NAME,
  IFLA_PARENT_DEV_BUS_NAME,
  IFLA_GRO_MAX_SIZE,
  IFLA_TSO_MAX_SIZE,
  IFLA_TSO_MAX_SEGS,
  IFLA_ALLMULTI,
  IFLA_DEVLINK_PORT,
  IFLA_GSO_IPV4_MAX_SIZE,
  IFLA_GRO_IPV4_MAX_SIZE,
  IFLA_DPLL_PIN,
  __IFLA_MAX
};
#define IFLA_MAX (__IFLA_MAX - 1)
enum {
  IFLA_PROTO_DOWN_REASON_UNSPEC,
  IFLA_PROTO_DOWN_REASON_MASK,
  IFLA_PROTO_DOWN_REASON_VALUE,
  __IFLA_PROTO_DOWN_REASON_CNT,
  IFLA_PROTO_DOWN_REASON_MAX = __IFLA_PROTO_DOWN_REASON_CNT - 1
};
#define IFLA_RTA(r) ((struct rtattr *) (((char *) (r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct ifinfomsg))
enum {
  IFLA_INET_UNSPEC,
  IFLA_INET_CONF,
  __IFLA_INET_MAX,
};
#define IFLA_INET_MAX (__IFLA_INET_MAX - 1)
enum {
  IFLA_INET6_UNSPEC,
  IFLA_INET6_FLAGS,
  IFLA_INET6_CONF,
  IFLA_INET6_STATS,
  IFLA_INET6_MCAST,
  IFLA_INET6_CACHEINFO,
  IFLA_INET6_ICMP6STATS,
  IFLA_INET6_TOKEN,
  IFLA_INET6_ADDR_GEN_MODE,
  IFLA_INET6_RA_MTU,
  __IFLA_INET6_MAX
};
#define IFLA_INET6_MAX (__IFLA_INET6_MAX - 1)
enum in6_addr_gen_mode {
  IN6_ADDR_GEN_MODE_EUI64,
  IN6_ADDR_GEN_MODE_NONE,
  IN6_ADDR_GEN_MODE_STABLE_PRIVACY,
  IN6_ADDR_GEN_MODE_RANDOM,
};
enum {
  IFLA_BR_UNSPEC,
  IFLA_BR_FORWARD_DELAY,
  IFLA_BR_HELLO_TIME,
  IFLA_BR_MAX_AGE,
  IFLA_BR_AGEING_TIME,
  IFLA_BR_STP_STATE,
  IFLA_BR_PRIORITY,
  IFLA_BR_VLAN_FILTERING,
  IFLA_BR_VLAN_PROTOCOL,
  IFLA_BR_GROUP_FWD_MASK,
  IFLA_BR_ROOT_ID,
  IFLA_BR_BRIDGE_ID,
  IFLA_BR_ROOT_PORT,
  IFLA_BR_ROOT_PATH_COST,
  IFLA_BR_TOPOLOGY_CHANGE,
  IFLA_BR_TOPOLOGY_CHANGE_DETECTED,
  IFLA_BR_HELLO_TIMER,
  IFLA_BR_TCN_TIMER,
  IFLA_BR_TOPOLOGY_CHANGE_TIMER,
  IFLA_BR_GC_TIMER,
  IFLA_BR_GROUP_ADDR,
  IFLA_BR_FDB_FLUSH,
  IFLA_BR_MCAST_ROUTER,
  IFLA_BR_MCAST_SNOOPING,
  IFLA_BR_MCAST_QUERY_USE_IFADDR,
  IFLA_BR_MCAST_QUERIER,
  IFLA_BR_MCAST_HASH_ELASTICITY,
  IFLA_BR_MCAST_HASH_MAX,
  IFLA_BR_MCAST_LAST_MEMBER_CNT,
  IFLA_BR_MCAST_STARTUP_QUERY_CNT,
  IFLA_BR_MCAST_LAST_MEMBER_INTVL,
  IFLA_BR_MCAST_MEMBERSHIP_INTVL,
  IFLA_BR_MCAST_QUERIER_INTVL,
  IFLA_BR_MCAST_QUERY_INTVL,
  IFLA_BR_MCAST_QUERY_RESPONSE_INTVL,
  IFLA_BR_MCAST_STARTUP_QUERY_INTVL,
  IFLA_BR_NF_CALL_IPTABLES,
  IFLA_BR_NF_CALL_IP6TABLES,
  IFLA_BR_NF_CALL_ARPTABLES,
  IFLA_BR_VLAN_DEFAULT_PVID,
  IFLA_BR_PAD,
  IFLA_BR_VLAN_STATS_ENABLED,
  IFLA_BR_MCAST_STATS_ENABLED,
  IFLA_BR_MCAST_IGMP_VERSION,
  IFLA_BR_MCAST_MLD_VERSION,
  IFLA_BR_VLAN_STATS_PER_PORT,
  IFLA_BR_MULTI_BOOLOPT,
  IFLA_BR_MCAST_QUERIER_STATE,
  IFLA_BR_FDB_N_LEARNED,
  IFLA_BR_FDB_MAX_LEARNED,
  __IFLA_BR_MAX,
};
#define IFLA_BR_MAX (__IFLA_BR_MAX - 1)
struct ifla_bridge_id {
  __u8 prio[2];
  __u8 addr[6];
};
enum {
  BRIDGE_MODE_UNSPEC,
  BRIDGE_MODE_HAIRPIN,
};
enum {
  IFLA_BRPORT_UNSPEC,
  IFLA_BRPORT_STATE,
  IFLA_BRPORT_PRIORITY,
  IFLA_BRPORT_COST,
  IFLA_BRPORT_MODE,
  IFLA_BRPORT_GUARD,
  IFLA_BRPORT_PROTECT,
  IFLA_BRPORT_FAST_LEAVE,
  IFLA_BRPORT_LEARNING,
  IFLA_BRPORT_UNICAST_FLOOD,
  IFLA_BRPORT_PROXYARP,
  IFLA_BRPORT_LEARNING_SYNC,
  IFLA_BRPORT_PROXYARP_WIFI,
  IFLA_BRPORT_ROOT_ID,
  IFLA_BRPORT_BRIDGE_ID,
  IFLA_BRPORT_DESIGNATED_PORT,
  IFLA_BRPORT_DESIGNATED_COST,
  IFLA_BRPORT_ID,
  IFLA_BRPORT_NO,
  IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
  IFLA_BRPORT_CONFIG_PENDING,
  IFLA_BRPORT_MESSAGE_AGE_TIMER,
  IFLA_BRPORT_FORWARD_DELAY_TIMER,
  IFLA_BRPORT_HOLD_TIMER,
  IFLA_BRPORT_FLUSH,
  IFLA_BRPORT_MULTICAST_ROUTER,
  IFLA_BRPORT_PAD,
  IFLA_BRPORT_MCAST_FLOOD,
  IFLA_BRPORT_MCAST_TO_UCAST,
  IFLA_BRPORT_VLAN_TUNNEL,
  IFLA_BRPORT_BCAST_FLOOD,
  IFLA_BRPORT_GROUP_FWD_MASK,
  IFLA_BRPORT_NEIGH_SUPPRESS,
  IFLA_BRPORT_ISOLATED,
  IFLA_BRPORT_BACKUP_PORT,
  IFLA_BRPORT_MRP_RING_OPEN,
  IFLA_BRPORT_MRP_IN_OPEN,
  IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT,
  IFLA_BRPORT_MCAST_EHT_HOSTS_CNT,
  IFLA_BRPORT_LOCKED,
  IFLA_BRPORT_MAB,
  IFLA_BRPORT_MCAST_N_GROUPS,
  IFLA_BRPORT_MCAST_MAX_GROUPS,
  IFLA_BRPORT_NEIGH_VLAN_SUPPRESS,
  IFLA_BRPORT_BACKUP_NHID,
  __IFLA_BRPORT_MAX
};
#define IFLA_BRPORT_MAX (__IFLA_BRPORT_MAX - 1)
struct ifla_cacheinfo {
  __u32 max_reasm_len;
  __u32 tstamp;
  __u32 reachable_time;
  __u32 retrans_time;
};
enum {
  IFLA_INFO_UNSPEC,
  IFLA_INFO_KIND,
  IFLA_INFO_DATA,
  IFLA_INFO_XSTATS,
  IFLA_INFO_SLAVE_KIND,
  IFLA_INFO_SLAVE_DATA,
  __IFLA_INFO_MAX,
};
#define IFLA_INFO_MAX (__IFLA_INFO_MAX - 1)
enum {
  IFLA_VLAN_UNSPEC,
  IFLA_VLAN_ID,
  IFLA_VLAN_FLAGS,
  IFLA_VLAN_EGRESS_QOS,
  IFLA_VLAN_INGRESS_QOS,
  IFLA_VLAN_PROTOCOL,
  __IFLA_VLAN_MAX,
};
#define IFLA_VLAN_MAX (__IFLA_VLAN_MAX - 1)
struct ifla_vlan_flags {
  __u32 flags;
  __u32 mask;
};
enum {
  IFLA_VLAN_QOS_UNSPEC,
  IFLA_VLAN_QOS_MAPPING,
  __IFLA_VLAN_QOS_MAX
};
#define IFLA_VLAN_QOS_MAX (__IFLA_VLAN_QOS_MAX - 1)
struct ifla_vlan_qos_mapping {
  __u32 from;
  __u32 to;
};
enum {
  IFLA_MACVLAN_UNSPEC,
  IFLA_MACVLAN_MODE,
  IFLA_MACVLAN_FLAGS,
  IFLA_MACVLAN_MACADDR_MODE,
  IFLA_MACVLAN_MACADDR,
  IFLA_MACVLAN_MACADDR_DATA,
  IFLA_MACVLAN_MACADDR_COUNT,
  IFLA_MACVLAN_BC_QUEUE_LEN,
  IFLA_MACVLAN_BC_QUEUE_LEN_USED,
  IFLA_MACVLAN_BC_CUTOFF,
  __IFLA_MACVLAN_MAX,
};
#define IFLA_MACVLAN_MAX (__IFLA_MACVLAN_MAX - 1)
enum macvlan_mode {
  MACVLAN_MODE_PRIVATE = 1,
  MACVLAN_MODE_VEPA = 2,
  MACVLAN_MODE_BRIDGE = 4,
  MACVLAN_MODE_PASSTHRU = 8,
  MACVLAN_MODE_SOURCE = 16,
};
enum macvlan_macaddr_mode {
  MACVLAN_MACADDR_ADD,
  MACVLAN_MACADDR_DEL,
  MACVLAN_MACADDR_FLUSH,
  MACVLAN_MACADDR_SET,
};
#define MACVLAN_FLAG_NOPROMISC 1
#define MACVLAN_FLAG_NODST 2
enum {
  IFLA_VRF_UNSPEC,
  IFLA_VRF_TABLE,
  __IFLA_VRF_MAX
};
#define IFLA_VRF_MAX (__IFLA_VRF_MAX - 1)
enum {
  IFLA_VRF_PORT_UNSPEC,
  IFLA_VRF_PORT_TABLE,
  __IFLA_VRF_PORT_MAX
};
#define IFLA_VRF_PORT_MAX (__IFLA_VRF_PORT_MAX - 1)
enum {
  IFLA_MACSEC_UNSPEC,
  IFLA_MACSEC_SCI,
  IFLA_MACSEC_PORT,
  IFLA_MACSEC_ICV_LEN,
  IFLA_MACSEC_CIPHER_SUITE,
  IFLA_MACSEC_WINDOW,
  IFLA_MACSEC_ENCODING_SA,
  IFLA_MACSEC_ENCRYPT,
  IFLA_MACSEC_PROTECT,
  IFLA_MACSEC_INC_SCI,
  IFLA_MACSEC_ES,
  IFLA_MACSEC_SCB,
  IFLA_MACSEC_REPLAY_PROTECT,
  IFLA_MACSEC_VALIDATION,
  IFLA_MACSEC_PAD,
  IFLA_MACSEC_OFFLOAD,
  __IFLA_MACSEC_MAX,
};
#define IFLA_MACSEC_MAX (__IFLA_MACSEC_MAX - 1)
enum {
  IFLA_XFRM_UNSPEC,
  IFLA_XFRM_LINK,
  IFLA_XFRM_IF_ID,
  IFLA_XFRM_COLLECT_METADATA,
  __IFLA_XFRM_MAX
};
#define IFLA_XFRM_MAX (__IFLA_XFRM_MAX - 1)
enum macsec_validation_type {
  MACSEC_VALIDATE_DISABLED = 0,
  MACSEC_VALIDATE_CHECK = 1,
  MACSEC_VALIDATE_STRICT = 2,
  __MACSEC_VALIDATE_END,
  MACSEC_VALIDATE_MAX = __MACSEC_VALIDATE_END - 1,
};
enum macsec_offload {
  MACSEC_OFFLOAD_OFF = 0,
  MACSEC_OFFLOAD_PHY = 1,
  MACSEC_OFFLOAD_MAC = 2,
  __MACSEC_OFFLOAD_END,
  MACSEC_OFFLOAD_MAX = __MACSEC_OFFLOAD_END - 1,
};
enum {
  IFLA_IPVLAN_UNSPEC,
  IFLA_IPVLAN_MODE,
  IFLA_IPVLAN_FLAGS,
  __IFLA_IPVLAN_MAX
};
#define IFLA_IPVLAN_MAX (__IFLA_IPVLAN_MAX - 1)
enum ipvlan_mode {
  IPVLAN_MODE_L2 = 0,
  IPVLAN_MODE_L3,
  IPVLAN_MODE_L3S,
  IPVLAN_MODE_MAX
};
#define IPVLAN_F_PRIVATE 0x01
#define IPVLAN_F_VEPA 0x02
struct tunnel_msg {
  __u8 family;
  __u8 flags;
  __u16 reserved2;
  __u32 ifindex;
};
enum netkit_action {
  NETKIT_NEXT = - 1,
  NETKIT_PASS = 0,
  NETKIT_DROP = 2,
  NETKIT_REDIRECT = 7,
};
enum netkit_mode {
  NETKIT_L2,
  NETKIT_L3,
};
enum {
  IFLA_NETKIT_UNSPEC,
  IFLA_NETKIT_PEER_INFO,
  IFLA_NETKIT_PRIMARY,
  IFLA_NETKIT_POLICY,
  IFLA_NETKIT_PEER_POLICY,
  IFLA_NETKIT_MODE,
  __IFLA_NETKIT_MAX,
};
#define IFLA_NETKIT_MAX (__IFLA_NETKIT_MAX - 1)
#define TUNNEL_MSG_FLAG_STATS 0x01
#define TUNNEL_MSG_VALID_USER_FLAGS TUNNEL_MSG_FLAG_STATS
enum {
  VNIFILTER_ENTRY_STATS_UNSPEC,
  VNIFILTER_ENTRY_STATS_RX_BYTES,
  VNIFILTER_ENTRY_STATS_RX_PKTS,
  VNIFILTER_ENTRY_STATS_RX_DROPS,
  VNIFILTER_ENTRY_STATS_RX_ERRORS,
  VNIFILTER_ENTRY_STATS_TX_BYTES,
  VNIFILTER_ENTRY_STATS_TX_PKTS,
  VNIFILTER_ENTRY_STATS_TX_DROPS,
  VNIFILTER_ENTRY_STATS_TX_ERRORS,
  VNIFILTER_ENTRY_STATS_PAD,
  __VNIFILTER_ENTRY_STATS_MAX
};
#define VNIFILTER_ENTRY_STATS_MAX (__VNIFILTER_ENTRY_STATS_MAX - 1)
enum {
  VXLAN_VNIFILTER_ENTRY_UNSPEC,
  VXLAN_VNIFILTER_ENTRY_START,
  VXLAN_VNIFILTER_ENTRY_END,
  VXLAN_VNIFILTER_ENTRY_GROUP,
  VXLAN_VNIFILTER_ENTRY_GROUP6,
  VXLAN_VNIFILTER_ENTRY_STATS,
  __VXLAN_VNIFILTER_ENTRY_MAX
};
#define VXLAN_VNIFILTER_ENTRY_MAX (__VXLAN_VNIFILTER_ENTRY_MAX - 1)
enum {
  VXLAN_VNIFILTER_UNSPEC,
  VXLAN_VNIFILTER_ENTRY,
  __VXLAN_VNIFILTER_MAX
};
#define VXLAN_VNIFILTER_MAX (__VXLAN_VNIFILTER_MAX - 1)
enum {
  IFLA_VXLAN_UNSPEC,
  IFLA_VXLAN_ID,
  IFLA_VXLAN_GROUP,
  IFLA_VXLAN_LINK,
  IFLA_VXLAN_LOCAL,
  IFLA_VXLAN_TTL,
  IFLA_VXLAN_TOS,
  IFLA_VXLAN_LEARNING,
  IFLA_VXLAN_AGEING,
  IFLA_VXLAN_LIMIT,
  IFLA_VXLAN_PORT_RANGE,
  IFLA_VXLAN_PROXY,
  IFLA_VXLAN_RSC,
  IFLA_VXLAN_L2MISS,
  IFLA_VXLAN_L3MISS,
  IFLA_VXLAN_PORT,
  IFLA_VXLAN_GROUP6,
  IFLA_VXLAN_LOCAL6,
  IFLA_VXLAN_UDP_CSUM,
  IFLA_VXLAN_UDP_ZERO_CSUM6_TX,
  IFLA_VXLAN_UDP_ZERO_CSUM6_RX,
  IFLA_VXLAN_REMCSUM_TX,
  IFLA_VXLAN_REMCSUM_RX,
  IFLA_VXLAN_GBP,
  IFLA_VXLAN_REMCSUM_NOPARTIAL,
  IFLA_VXLAN_COLLECT_METADATA,
  IFLA_VXLAN_LABEL,
  IFLA_VXLAN_GPE,
  IFLA_VXLAN_TTL_INHERIT,
  IFLA_VXLAN_DF,
  IFLA_VXLAN_VNIFILTER,
  IFLA_VXLAN_LOCALBYPASS,
  IFLA_VXLAN_LABEL_POLICY,
  __IFLA_VXLAN_MAX
};
#define IFLA_VXLAN_MAX (__IFLA_VXLAN_MAX - 1)
struct ifla_vxlan_port_range {
  __be16 low;
  __be16 high;
};
enum ifla_vxlan_df {
  VXLAN_DF_UNSET = 0,
  VXLAN_DF_SET,
  VXLAN_DF_INHERIT,
  __VXLAN_DF_END,
  VXLAN_DF_MAX = __VXLAN_DF_END - 1,
};
enum ifla_vxlan_label_policy {
  VXLAN_LABEL_FIXED = 0,
  VXLAN_LABEL_INHERIT = 1,
  __VXLAN_LABEL_END,
  VXLAN_LABEL_MAX = __VXLAN_LABEL_END - 1,
};
enum {
  IFLA_GENEVE_UNSPEC,
  IFLA_GENEVE_ID,
  IFLA_GENEVE_REMOTE,
  IFLA_GENEVE_TTL,
  IFLA_GENEVE_TOS,
  IFLA_GENEVE_PORT,
  IFLA_GENEVE_COLLECT_METADATA,
  IFLA_GENEVE_REMOTE6,
  IFLA_GENEVE_UDP_CSUM,
  IFLA_GENEVE_UDP_ZERO_CSUM6_TX,
  IFLA_GENEVE_UDP_ZERO_CSUM6_RX,
  IFLA_GENEVE_LABEL,
  IFLA_GENEVE_TTL_INHERIT,
  IFLA_GENEVE_DF,
  IFLA_GENEVE_INNER_PROTO_INHERIT,
  __IFLA_GENEVE_MAX
};
#define IFLA_GENEVE_MAX (__IFLA_GENEVE_MAX - 1)
enum ifla_geneve_df {
  GENEVE_DF_UNSET = 0,
  GENEVE_DF_SET,
  GENEVE_DF_INHERIT,
  __GENEVE_DF_END,
  GENEVE_DF_MAX = __GENEVE_DF_END - 1,
};
enum {
  IFLA_BAREUDP_UNSPEC,
  IFLA_BAREUDP_PORT,
  IFLA_BAREUDP_ETHERTYPE,
  IFLA_BAREUDP_SRCPORT_MIN,
  IFLA_BAREUDP_MULTIPROTO_MODE,
  __IFLA_BAREUDP_MAX
};
#define IFLA_BAREUDP_MAX (__IFLA_BAREUDP_MAX - 1)
enum {
  IFLA_PPP_UNSPEC,
  IFLA_PPP_DEV_FD,
  __IFLA_PPP_MAX
};
#define IFLA_PPP_MAX (__IFLA_PPP_MAX - 1)
enum ifla_gtp_role {
  GTP_ROLE_GGSN = 0,
  GTP_ROLE_SGSN,
};
enum {
  IFLA_GTP_UNSPEC,
  IFLA_GTP_FD0,
  IFLA_GTP_FD1,
  IFLA_GTP_PDP_HASHSIZE,
  IFLA_GTP_ROLE,
  IFLA_GTP_CREATE_SOCKETS,
  IFLA_GTP_RESTART_COUNT,
  IFLA_GTP_LOCAL,
  IFLA_GTP_LOCAL6,
  __IFLA_GTP_MAX,
};
#define IFLA_GTP_MAX (__IFLA_GTP_MAX - 1)
enum {
  IFLA_BOND_UNSPEC,
  IFLA_BOND_MODE,
  IFLA_BOND_ACTIVE_SLAVE,
  IFLA_BOND_MIIMON,
  IFLA_BOND_UPDELAY,
  IFLA_BOND_DOWNDELAY,
  IFLA_BOND_USE_CARRIER,
  IFLA_BOND_ARP_INTERVAL,
  IFLA_BOND_ARP_IP_TARGET,
  IFLA_BOND_ARP_VALIDATE,
  IFLA_BOND_ARP_ALL_TARGETS,
  IFLA_BOND_PRIMARY,
  IFLA_BOND_PRIMARY_RESELECT,
  IFLA_BOND_FAIL_OVER_MAC,
  IFLA_BOND_XMIT_HASH_POLICY,
  IFLA_BOND_RESEND_IGMP,
  IFLA_BOND_NUM_PEER_NOTIF,
  IFLA_BOND_ALL_SLAVES_ACTIVE,
  IFLA_BOND_MIN_LINKS,
  IFLA_BOND_LP_INTERVAL,
  IFLA_BOND_PACKETS_PER_SLAVE,
  IFLA_BOND_AD_LACP_RATE,
  IFLA_BOND_AD_SELECT,
  IFLA_BOND_AD_INFO,
  IFLA_BOND_AD_ACTOR_SYS_PRIO,
  IFLA_BOND_AD_USER_PORT_KEY,
  IFLA_BOND_AD_ACTOR_SYSTEM,
  IFLA_BOND_TLB_DYNAMIC_LB,
  IFLA_BOND_PEER_NOTIF_DELAY,
  IFLA_BOND_AD_LACP_ACTIVE,
  IFLA_BOND_MISSED_MAX,
  IFLA_BOND_NS_IP6_TARGET,
  IFLA_BOND_COUPLED_CONTROL,
  __IFLA_BOND_MAX,
};
#define IFLA_BOND_MAX (__IFLA_BOND_MAX - 1)
enum {
  IFLA_BOND_AD_INFO_UNSPEC,
  IFLA_BOND_AD_INFO_AGGREGATOR,
  IFLA_BOND_AD_INFO_NUM_PORTS,
  IFLA_BOND_AD_INFO_ACTOR_KEY,
  IFLA_BOND_AD_INFO_PARTNER_KEY,
  IFLA_BOND_AD_INFO_PARTNER_MAC,
  __IFLA_BOND_AD_INFO_MAX,
};
#define IFLA_BOND_AD_INFO_MAX (__IFLA_BOND_AD_INFO_MAX - 1)
enum {
  IFLA_BOND_SLAVE_UNSPEC,
  IFLA_BOND_SLAVE_STATE,
  IFLA_BOND_SLAVE_MII_STATUS,
  IFLA_BOND_SLAVE_LINK_FAILURE_COUNT,
  IFLA_BOND_SLAVE_PERM_HWADDR,
  IFLA_BOND_SLAVE_QUEUE_ID,
  IFLA_BOND_SLAVE_AD_AGGREGATOR_ID,
  IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE,
  IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE,
  IFLA_BOND_SLAVE_PRIO,
  __IFLA_BOND_SLAVE_MAX,
};
#define IFLA_BOND_SLAVE_MAX (__IFLA_BOND_SLAVE_MAX - 1)
enum {
  IFLA_VF_INFO_UNSPEC,
  IFLA_VF_INFO,
  __IFLA_VF_INFO_MAX,
};
#define IFLA_VF_INFO_MAX (__IFLA_VF_INFO_MAX - 1)
enum {
  IFLA_VF_UNSPEC,
  IFLA_VF_MAC,
  IFLA_VF_VLAN,
  IFLA_VF_TX_RATE,
  IFLA_VF_SPOOFCHK,
  IFLA_VF_LINK_STATE,
  IFLA_VF_RATE,
  IFLA_VF_RSS_QUERY_EN,
  IFLA_VF_STATS,
  IFLA_VF_TRUST,
  IFLA_VF_IB_NODE_GUID,
  IFLA_VF_IB_PORT_GUID,
  IFLA_VF_VLAN_LIST,
  IFLA_VF_BROADCAST,
  __IFLA_VF_MAX,
};
#define IFLA_VF_MAX (__IFLA_VF_MAX - 1)
struct ifla_vf_mac {
  __u32 vf;
  __u8 mac[32];
};
struct ifla_vf_broadcast {
  __u8 broadcast[32];
};
struct ifla_vf_vlan {
  __u32 vf;
  __u32 vlan;
  __u32 qos;
};
enum {
  IFLA_VF_VLAN_INFO_UNSPEC,
  IFLA_VF_VLAN_INFO,
  __IFLA_VF_VLAN_INFO_MAX,
};
#define IFLA_VF_VLAN_INFO_MAX (__IFLA_VF_VLAN_INFO_MAX - 1)
#define MAX_VLAN_LIST_LEN 1
struct ifla_vf_vlan_info {
  __u32 vf;
  __u32 vlan;
  __u32 qos;
  __be16 vlan_proto;
};
struct ifla_vf_tx_rate {
  __u32 vf;
  __u32 rate;
};
struct ifla_vf_rate {
  __u32 vf;
  __u32 min_tx_rate;
  __u32 max_tx_rate;
};
struct ifla_vf_spoofchk {
  __u32 vf;
  __u32 setting;
};
struct ifla_vf_guid {
  __u32 vf;
  __u64 guid;
};
enum {
  IFLA_VF_LINK_STATE_AUTO,
  IFLA_VF_LINK_STATE_ENABLE,
  IFLA_VF_LINK_STATE_DISABLE,
  __IFLA_VF_LINK_STATE_MAX,
};
struct ifla_vf_link_state {
  __u32 vf;
  __u32 link_state;
};
struct ifla_vf_rss_query_en {
  __u32 vf;
  __u32 setting;
};
enum {
  IFLA_VF_STATS_RX_PACKETS,
  IFLA_VF_STATS_TX_PACKETS,
  IFLA_VF_STATS_RX_BYTES,
  IFLA_VF_STATS_TX_BYTES,
  IFLA_VF_STATS_BROADCAST,
  IFLA_VF_STATS_MULTICAST,
  IFLA_VF_STATS_PAD,
  IFLA_VF_STATS_RX_DROPPED,
  IFLA_VF_STATS_TX_DROPPED,
  __IFLA_VF_STATS_MAX,
};
#define IFLA_VF_STATS_MAX (__IFLA_VF_STATS_MAX - 1)
struct ifla_vf_trust {
  __u32 vf;
  __u32 setting;
};
enum {
  IFLA_VF_PORT_UNSPEC,
  IFLA_VF_PORT,
  __IFLA_VF_PORT_MAX,
};
#define IFLA_VF_PORT_MAX (__IFLA_VF_PORT_MAX - 1)
enum {
  IFLA_PORT_UNSPEC,
  IFLA_PORT_VF,
  IFLA_PORT_PROFILE,
  IFLA_PORT_VSI_TYPE,
  IFLA_PORT_INSTANCE_UUID,
  IFLA_PORT_HOST_UUID,
  IFLA_PORT_REQUEST,
  IFLA_PORT_RESPONSE,
  __IFLA_PORT_MAX,
};
#define IFLA_PORT_MAX (__IFLA_PORT_MAX - 1)
#define PORT_PROFILE_MAX 40
#define PORT_UUID_MAX 16
#define PORT_SELF_VF - 1
enum {
  PORT_REQUEST_PREASSOCIATE = 0,
  PORT_REQUEST_PREASSOCIATE_RR,
  PORT_REQUEST_ASSOCIATE,
  PORT_REQUEST_DISASSOCIATE,
};
enum {
  PORT_VDP_RESPONSE_SUCCESS = 0,
  PORT_VDP_RESPONSE_INVALID_FORMAT,
  PORT_VDP_RESPONSE_INSUFFICIENT_RESOURCES,
  PORT_VDP_RESPONSE_UNUSED_VTID,
  PORT_VDP_RESPONSE_VTID_VIOLATION,
  PORT_VDP_RESPONSE_VTID_VERSION_VIOALTION,
  PORT_VDP_RESPONSE_OUT_OF_SYNC,
  PORT_PROFILE_RESPONSE_SUCCESS = 0x100,
  PORT_PROFILE_RESPONSE_INPROGRESS,
  PORT_PROFILE_RESPONSE_INVALID,
  PORT_PROFILE_RESPONSE_BADSTATE,
  PORT_PROFILE_RESPONSE_INSUFFICIENT_RESOURCES,
  PORT_PROFILE_RESPONSE_ERROR,
};
struct ifla_port_vsi {
  __u8 vsi_mgr_id;
  __u8 vsi_type_id[3];
  __u8 vsi_type_version;
  __u8 pad[3];
};
enum {
  IFLA_IPOIB_UNSPEC,
  IFLA_IPOIB_PKEY,
  IFLA_IPOIB_MODE,
  IFLA_IPOIB_UMCAST,
  __IFLA_IPOIB_MAX
};
enum {
  IPOIB_MODE_DATAGRAM = 0,
  IPOIB_MODE_CONNECTED = 1,
};
#define IFLA_IPOIB_MAX (__IFLA_IPOIB_MAX - 1)
enum {
  HSR_PROTOCOL_HSR,
  HSR_PROTOCOL_PRP,
  HSR_PROTOCOL_MAX,
};
enum {
  IFLA_HSR_UNSPEC,
  IFLA_HSR_SLAVE1,
  IFLA_HSR_SLAVE2,
  IFLA_HSR_MULTICAST_SPEC,
  IFLA_HSR_SUPERVISION_ADDR,
  IFLA_HSR_SEQ_NR,
  IFLA_HSR_VERSION,
  IFLA_HSR_PROTOCOL,
  IFLA_HSR_INTERLINK,
  __IFLA_HSR_MAX,
};
#define IFLA_HSR_MAX (__IFLA_HSR_MAX - 1)
struct if_stats_msg {
  __u8 family;
  __u8 pad1;
  __u16 pad2;
  __u32 ifindex;
  __u32 filter_mask;
};
enum {
  IFLA_STATS_UNSPEC,
  IFLA_STATS_LINK_64,
  IFLA_STATS_LINK_XSTATS,
  IFLA_STATS_LINK_XSTATS_SLAVE,
  IFLA_STATS_LINK_OFFLOAD_XSTATS,
  IFLA_STATS_AF_SPEC,
  __IFLA_STATS_MAX,
};
#define IFLA_STATS_MAX (__IFLA_STATS_MAX - 1)
#define IFLA_STATS_FILTER_BIT(ATTR) (1 << (ATTR - 1))
enum {
  IFLA_STATS_GETSET_UNSPEC,
  IFLA_STATS_GET_FILTERS,
  IFLA_STATS_SET_OFFLOAD_XSTATS_L3_STATS,
  __IFLA_STATS_GETSET_MAX,
};
#define IFLA_STATS_GETSET_MAX (__IFLA_STATS_GETSET_MAX - 1)
enum {
  LINK_XSTATS_TYPE_UNSPEC,
  LINK_XSTATS_TYPE_BRIDGE,
  LINK_XSTATS_TYPE_BOND,
  __LINK_XSTATS_TYPE_MAX
};
#define LINK_XSTATS_TYPE_MAX (__LINK_XSTATS_TYPE_MAX - 1)
enum {
  IFLA_OFFLOAD_XSTATS_UNSPEC,
  IFLA_OFFLOAD_XSTATS_CPU_HIT,
  IFLA_OFFLOAD_XSTATS_HW_S_INFO,
  IFLA_OFFLOAD_XSTATS_L3_STATS,
  __IFLA_OFFLOAD_XSTATS_MAX
};
#define IFLA_OFFLOAD_XSTATS_MAX (__IFLA_OFFLOAD_XSTATS_MAX - 1)
enum {
  IFLA_OFFLOAD_XSTATS_HW_S_INFO_UNSPEC,
  IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST,
  IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED,
  __IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX,
};
#define IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX (__IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX - 1)
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#define XDP_FLAGS_SKB_MODE (1U << 1)
#define XDP_FLAGS_DRV_MODE (1U << 2)
#define XDP_FLAGS_HW_MODE (1U << 3)
#define XDP_FLAGS_REPLACE (1U << 4)
#define XDP_FLAGS_MODES (XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE)
#define XDP_FLAGS_MASK (XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES | XDP_FLAGS_REPLACE)
enum {
  XDP_ATTACHED_NONE = 0,
  XDP_ATTACHED_DRV,
  XDP_ATTACHED_SKB,
  XDP_ATTACHED_HW,
  XDP_ATTACHED_MULTI,
};
enum {
  IFLA_XDP_UNSPEC,
  IFLA_XDP_FD,
  IFLA_XDP_ATTACHED,
  IFLA_XDP_FLAGS,
  IFLA_XDP_PROG_ID,
  IFLA_XDP_DRV_PROG_ID,
  IFLA_XDP_SKB_PROG_ID,
  IFLA_XDP_HW_PROG_ID,
  IFLA_XDP_EXPECTED_FD,
  __IFLA_XDP_MAX,
};
#define IFLA_XDP_MAX (__IFLA_XDP_MAX - 1)
enum {
  IFLA_EVENT_NONE,
  IFLA_EVENT_REBOOT,
  IFLA_EVENT_FEATURES,
  IFLA_EVENT_BONDING_FAILOVER,
  IFLA_EVENT_NOTIFY_PEERS,
  IFLA_EVENT_IGMP_RESEND,
  IFLA_EVENT_BONDING_OPTIONS,
};
enum {
  IFLA_TUN_UNSPEC,
  IFLA_TUN_OWNER,
  IFLA_TUN_GROUP,
  IFLA_TUN_TYPE,
  IFLA_TUN_PI,
  IFLA_TUN_VNET_HDR,
  IFLA_TUN_PERSIST,
  IFLA_TUN_MULTI_QUEUE,
  IFLA_TUN_NUM_QUEUES,
  IFLA_TUN_NUM_DISABLED_QUEUES,
  __IFLA_TUN_MAX,
};
#define IFLA_TUN_MAX (__IFLA_TUN_MAX - 1)
#define RMNET_FLAGS_INGRESS_DEAGGREGATION (1U << 0)
#define RMNET_FLAGS_INGRESS_MAP_COMMANDS (1U << 1)
#define RMNET_FLAGS_INGRESS_MAP_CKSUMV4 (1U << 2)
#define RMNET_FLAGS_EGRESS_MAP_CKSUMV4 (1U << 3)
#define RMNET_FLAGS_INGRESS_MAP_CKSUMV5 (1U << 4)
#define RMNET_FLAGS_EGRESS_MAP_CKSUMV5 (1U << 5)
enum {
  IFLA_RMNET_UNSPEC,
  IFLA_RMNET_MUX_ID,
  IFLA_RMNET_FLAGS,
  __IFLA_RMNET_MAX,
};
#define IFLA_RMNET_MAX (__IFLA_RMNET_MAX - 1)
struct ifla_rmnet_flags {
  __u32 flags;
  __u32 mask;
};
enum {
  IFLA_MCTP_UNSPEC,
  IFLA_MCTP_NET,
  __IFLA_MCTP_MAX,
};
#define IFLA_MCTP_MAX (__IFLA_MCTP_MAX - 1)
enum {
  IFLA_DSA_UNSPEC,
  IFLA_DSA_CONDUIT,
  IFLA_DSA_MASTER = IFLA_DSA_CONDUIT,
  __IFLA_DSA_MAX,
};
#define IFLA_DSA_MAX (__IFLA_DSA_MAX - 1)
#endif

"""

```