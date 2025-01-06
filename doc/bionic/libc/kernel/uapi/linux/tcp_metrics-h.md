Response:
Let's break down the thought process for answering this complex request about `tcp_metrics.h`.

**1. Understanding the Core Request:**

The central task is to analyze the provided C header file (`tcp_metrics.h`) and explain its functionality within the context of Android's Bionic library. The request has several specific constraints:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does this relate to Android? Give examples.
* **libc Function Details:**  Explain the implementation of *each* libc function. (This is a trick question, as there are *no* actual libc function definitions in this header).
* **Dynamic Linker:** Address any dynamic linker aspects. (Another trick, as this is a header file, not a compiled object).
* **Logic & Examples:** Provide examples with input/output.
* **Common Errors:** Highlight potential usage mistakes.
* **Android Framework/NDK Path:** Trace how Android reaches this code.
* **Frida Hooking:** Provide a Frida example.
* **Chinese Response:**  The output language.

**2. Initial Analysis of the Header File:**

The first step is to examine the header file itself. Key observations:

* **`auto-generated`:**  This immediately suggests the file isn't manually written and is likely generated from some other specification or definition. This implies a systematic and possibly kernel-driven origin.
* **`#ifndef _UAPI_LINUX_TCP_METRICS_H`:** Standard header guard to prevent multiple inclusions.
* **`#include <linux/types.h>`:**  This header depends on basic Linux types, indicating it's related to the Linux kernel. The `uapi` path reinforces this, suggesting it's part of the userspace API for kernel features.
* **`#define TCP_METRICS_GENL_NAME "tcp_metrics"` and `#define TCP_METRICS_GENL_VERSION 0x1`:** These define the name and version of a "tcp_metrics" family. The presence of "GENL" strongly hints at the use of Generic Netlink, a Linux kernel mechanism for communication between kernel and userspace.
* **`enum tcp_metric_index`:**  Defines constants representing different TCP metrics (RTT, RTTVAR, CWND, etc.). The `_US` variants suggest microseconds.
* **`enum TCP_METRICS_A_METRICS_*`:** These seem redundant to `tcp_metric_index`. The "A" might stand for "Attribute," but it's not immediately clear how they are used. (Further investigation or context would be needed for complete understanding).
* **`enum TCP_METRICS_ATTR_*`:** Defines attributes associated with TCP metrics, such as IP addresses (v4 and v6), age, timestamps, etc. This confirms the context of network connections.
* **`enum TCP_METRICS_CMD_*`:** Defines commands related to TCP metrics, like "GET" and "DEL," strongly pointing towards an interface for retrieving and deleting metric data.

**3. Connecting to Android:**

Knowing this is a kernel userspace API header, the connection to Android is through system calls and network stack interaction. Android's networking stack relies on the underlying Linux kernel. Applications and system services on Android need a way to access and manage TCP connection information. This header file provides the *definitions* for interacting with that kernel functionality.

**4. Addressing the "Trick" Questions:**

* **libc functions:** The header file *declares* constants and enums, not actual function implementations. The answer must reflect this. The underlying functionality is implemented in the Linux kernel.
* **Dynamic Linker:** Similarly, a header file is not directly linked. It provides definitions used during compilation and linking. The answer should focus on how these definitions enable communication between userspace (Android apps/services) and the kernel, but not directly involving `ld.so`.

**5. Building Examples and Explanations:**

* **Functionality:** Summarize the file's role in defining the interface for accessing TCP metrics via Generic Netlink.
* **Android Relevance:** Provide concrete examples of how Android components (like `ConnectivityService`, network monitoring apps) might utilize these metrics.
* **Implementation:** Clearly state that the *implementation* resides in the Linux kernel, and this header provides the *interface*.
* **Dynamic Linker:** Explain that while not directly linked, the definitions are crucial for compiling applications that interact with this kernel feature.
* **Logic & Examples:**  Construct hypothetical scenarios where a userspace program uses the defined constants to request specific TCP metrics. Illustrate the structure of such a request (even if simplified).
* **Common Errors:** Focus on potential errors related to using the wrong constants, interpreting data incorrectly, or lacking the necessary permissions to access the kernel interface.
* **Android Framework/NDK Path:**  Trace a simplified path: Android App -> Java Network API -> Native Code (using NDK) -> System Call (interacting with the kernel's Netlink interface, guided by these header definitions).
* **Frida Hooking:**  Focus on hooking the system calls or potentially higher-level Java APIs that eventually lead to interaction described by this header. Since the direct interactions are likely in the kernel, hooking at the system call level or the Java/native bridge would be more effective than directly hooking something in Bionic related to this *header*.

**6. Structuring the Response:**

Organize the answer logically, addressing each point of the request. Use clear headings and explanations. Use code blocks for the Frida example.

**7. Refining and Reviewing:**

Read through the generated answer to ensure accuracy, clarity, and completeness. Check that all constraints of the original request have been addressed. Pay attention to the Chinese language requirement.

**Self-Correction/Refinement Example during the process:**

Initially, I might have focused too much on the *idea* of libc functions. Realizing there are *no actual function definitions* in the header is crucial. The refinement would be to shift the focus to the *definitions* of constants and enums, and their role in structuring communication with the kernel. Similarly, for the dynamic linker, the initial thought might be about linking libraries. The correction is to emphasize the *compile-time* use of these definitions for interacting with kernel interfaces, rather than dynamic linking of code *related to this specific header*. The Frida example needs to reflect that direct hooking of something defined in a `uapi` header is unlikely; the focus needs to be on the layers that *use* these definitions to interact with the kernel.
这是一个关于Linux内核TCP度量（metrics）的用户空间API头文件 (`tcp_metrics.h`)。它定义了用于与内核通信以获取和管理TCP连接性能相关信息的常量、枚举和宏。由于它位于 `bionic/libc/kernel/uapi/linux/` 目录下，这意味着它是Android Bionic库的一部分，直接对应于Linux内核提供的接口。

**它的功能:**

这个头文件的主要功能是定义了用户空间程序与Linux内核之间关于TCP连接度量信息交换的接口。具体来说，它定义了：

1. **通用Netlink接口名称和版本:** `TCP_METRICS_GENL_NAME` 和 `TCP_METRICS_GENL_VERSION` 定义了用于访问TCP度量信息的通用Netlink家族的名称和版本。通用Netlink是一种Linux内核提供的机制，允许用户空间程序通过套接字与内核模块进行通信。

2. **TCP度量索引:** `enum tcp_metric_index` 定义了可以查询的各种TCP度量的索引，例如：
   * `TCP_METRIC_RTT`:  往返时间（Round-Trip Time）。
   * `TCP_METRIC_RTTVAR`: 往返时间方差（Round-Trip Time Variation）。
   * `TCP_METRIC_SSTHRESH`: 慢启动阈值（Slow Start Threshold）。
   * `TCP_METRIC_CWND`: 拥塞窗口大小（Congestion Window）。
   * `TCP_METRIC_REORDERING`:  报文重排序计数。
   * `TCP_METRIC_RTT_US`: 微秒级的往返时间。
   * `TCP_METRIC_RTTVAR_US`: 微秒级的往返时间方差。

3. **TCP度量属性索引:** `enum TCP_METRICS_A_METRICS_*` 定义了用于指定要获取的具体度量的属性索引。这些常量似乎与 `tcp_metric_index` 中的值相对应，可能在Netlink消息中使用以标识请求的度量。

4. **TCP度量属性类型:** `enum TCP_METRICS_ATTR_*` 定义了与TCP度量信息相关的属性类型，例如：
   * `TCP_METRICS_ATTR_ADDR_IPV4`: IPv4地址。
   * `TCP_METRICS_ATTR_ADDR_IPV6`: IPv6地址。
   * `TCP_METRICS_ATTR_AGE`: 连接存在的时间。
   * `TCP_METRICS_ATTR_TW_TSVAL`, `TCP_METRICS_ATTR_TW_TS_STAMP`:  TIME_WAIT状态下的时间戳值和时间戳回显值，用于保护序列号回绕 (PAWS)。
   * `TCP_METRICS_ATTR_VALS`: 度量值的数组。
   * 其他与快速打开 (Fast Open) 相关的属性，例如 `TCP_METRICS_ATTR_FOPEN_MSS`, `TCP_METRICS_ATTR_FOPEN_SYN_DROPS` 等。
   * `TCP_METRICS_ATTR_SADDR_IPV4`, `TCP_METRICS_ATTR_SADDR_IPV6`: 源IPv4和IPv6地址。

5. **TCP度量命令类型:** `enum TCP_METRICS_CMD_*` 定义了可以执行的命令类型，例如：
   * `TCP_METRICS_CMD_GET`: 获取TCP度量信息。
   * `TCP_METRICS_CMD_DEL`: 删除TCP度量信息（可能用于清理缓存）。

**它与Android的功能的关系以及举例说明:**

这个头文件定义的功能与Android的网络监控、性能优化以及网络诊断密切相关。Android系统和应用程序可以使用这些接口来获取TCP连接的实时性能数据，用于：

* **网络监控应用:** Android的网络监控应用可以使用这些接口来展示当前活动的TCP连接的RTT、拥塞窗口等信息，帮助用户了解网络状况。例如，一个网络监控App可能使用这些信息来绘制RTT随时间变化的图表。
* **性能优化:** Android系统可以利用这些信息来动态调整网络参数，例如拥塞控制算法的参数，以提高网络性能。例如，如果发现某个连接的RTT过高且RTTVAR也很大，系统可能会采取更保守的拥塞控制策略。
* **网络诊断工具:** 开发人员可以使用这些接口来诊断网络问题。例如，如果一个应用程序连接到服务器速度很慢，可以使用这些接口查看连接的拥塞窗口大小，判断是否是拥塞导致的问题。
* **连接管理服务:** Android的连接管理服务 (ConnectivityService) 可能会在内部使用这些接口来监控和管理网络连接的状态和性能。

**详细解释每一个libc函数的功能是如何实现的:**

**这个头文件本身并没有定义任何libc函数。** 它只是定义了一些常量和枚举类型。实际与内核交互以获取TCP度量信息的功能是由底层的网络编程API（例如 `socket`, `sendto`, `recvfrom` 等）以及内核中的通用Netlink实现提供的。

用户空间程序需要使用标准的socket API创建一个Generic Netlink套接字，并构造符合内核期望的Netlink消息格式，才能与内核进行通信并获取这些TCP度量信息。这个头文件提供了构建这些Netlink消息所需的常量和结构定义。

**对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程:**

**这个头文件与动态链接器没有直接关系。** 动态链接器（在Android上主要是 `linker64` 或 `linker`）负责在程序启动时加载共享库 (`.so` 文件) 并解析符号。这个头文件是用于编译时的，它定义了常量，这些常量会被编译到使用它的程序中。

假设有一个使用这个头文件的程序 `my_network_app`，它会链接到 `libc.so`。 `libc.so` 提供了底层的网络编程 API。

**so布局样本 (my_network_app 和 libc.so 的简化示意):**

```
# my_network_app 可执行文件
.text       # 程序代码，包含使用 TCP_METRICS_* 常量的代码
.rodata     # 只读数据，可能包含 TCP_METRICS_GENL_NAME 字符串
.data       # 可变数据

# libc.so 共享库
.text       # socket, sendto, recvfrom 等函数的代码
.rodata     # 常量
.data       # 可变数据
.symtab     # 符号表，包含 socket 等函数的符号
.dynsym     # 动态符号表
.rel.dyn    # 动态重定位表
.plt        # 程序链接表 (Procedure Linkage Table)
.got        # 全局偏移表 (Global Offset Table)
```

**链接的处理过程:**

1. **编译时:** 当 `my_network_app` 编译时，编译器会读取 `tcp_metrics.h` 头文件，并将其中定义的常量（例如 `TCP_METRICS_GENL_NAME`, `TCP_METRICS_CMD_GET` 等）的值嵌入到 `my_network_app` 的代码段或只读数据段中。

2. **链接时:** 链接器会将 `my_network_app` 与 `libc.so` 链接在一起。 `my_network_app` 中调用 `socket`, `sendto` 等函数的指令需要被解析为 `libc.so` 中对应函数的地址。这通过查找 `libc.so` 的符号表来实现。

3. **运行时:** 当 `my_network_app` 启动时，动态链接器 `linker64` 会：
   * 加载 `my_network_app` 到内存。
   * 加载 `libc.so` 到内存。
   * 解析 `my_network_app` 对 `libc.so` 中函数的引用，更新全局偏移表 (GOT) 和程序链接表 (PLT)，使得程序能够正确调用 `libc.so` 中的函数。

在这个过程中，`tcp_metrics.h` 定义的常量直接被编译到 `my_network_app` 中，用于构造与内核通信的Netlink消息，而与动态链接器加载共享库的过程没有直接的关联。

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个Android应用程序想要获取一个特定TCP连接的RTT。

**假设输入:**

* **目标连接信息:** 应用程序需要知道目标连接的源IP地址、源端口、目的IP地址、目的端口（或者至少能够通过某种方式唯一标识这个连接，例如通过连接的套接字描述符）。为了简化，我们假设我们知道连接的本地和远程 IPv4 地址。
* **请求的度量:** 应用程序想要获取 `TCP_METRIC_RTT`。

**逻辑推理过程:**

1. **创建Generic Netlink套接字:** 应用程序使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)` 创建一个通用Netlink套接字。
2. **解析通用Netlink家族ID:** 应用程序需要向内核查询 `TCP_METRICS_GENL_NAME` 对应的家族ID。这通常通过发送一个 `CTRL_CMD_GETFAMILY` 命令的Netlink消息来实现。
3. **构造Get请求消息:** 应用程序构造一个 Netlink 消息，其头部包含获取到的家族ID，命令设置为 `TCP_METRICS_CMD_GET`。消息的有效负载包含需要查询的连接信息和需要获取的度量类型。这涉及到使用 `TCP_METRICS_ATTR_*` 定义的属性类型，例如：
   * `TCP_METRICS_ATTR_ADDR_IPV4`: 目标IP地址。
   * `TCP_METRICS_ATTR_SADDR_IPV4`: 源IP地址。
   * `TCP_METRICS_ATTR_VALS`: 包含请求的度量索引 `TCP_METRIC_RTT`。
4. **发送请求:** 应用程序使用 `sendto` 将构造的Netlink消息发送到内核。
5. **接收响应:** 应用程序使用 `recvfrom` 接收来自内核的Netlink响应消息。
6. **解析响应:** 应用程序解析接收到的消息。如果请求成功，消息的有效负载会包含请求的TCP度量值，通常会使用 `TCP_METRICS_ATTR_VALS` 属性来返回。

**假设输出:**

假设目标连接的 RTT 为 50 毫秒。内核返回的 Netlink 消息的有效负载可能包含类似以下结构的数据（这是一个简化的示意，实际的Netlink消息结构更复杂）：

```
[
  {
    "attr_type": TCP_METRICS_ATTR_VALS,
    "data": [
      {
        "metric_index": TCP_METRIC_RTT,
        "value": 50000  // 单位可能是微秒，所以是 50000 微秒
      }
    ]
  }
]
```

应用程序解析这个响应，提取出 `TCP_METRIC_RTT` 对应的值 `50000`，并将其转换为毫秒（除以 1000）。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记包含头文件:** 如果程序中使用了 `TCP_METRICS_*` 常量但没有包含 `tcp_metrics.h` 头文件，会导致编译错误，提示常量未定义。

2. **使用错误的Netlink家族ID:** 如果在创建Netlink套接字或构造Netlink消息时使用了错误的家族ID，将无法与内核的TCP度量模块正确通信。

3. **构造错误的Netlink消息格式:** 通用Netlink消息有特定的格式要求。如果消息的头部、属性类型、长度等字段设置不正确，内核可能无法解析消息，导致请求失败。例如，忘记添加必要的连接标识属性（如IP地址和端口）。

4. **权限不足:** 访问某些内核信息可能需要特定的权限。如果应用程序没有足够的权限来访问TCP度量信息，内核可能会拒绝请求。

5. **错误地解释返回值:**  内核返回的度量值的单位可能不是直接期望的单位（例如，RTT可能以微秒为单位）。开发者需要查阅文档并正确解释返回值。

6. **没有处理错误:** 与内核通信可能会失败。应用程序需要检查Netlink操作的返回值，并妥善处理可能出现的错误，例如连接超时、找不到连接等。

**说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。**

**Android Framework 到达这里的路径（简化）：**

1. **Android Framework 应用 (Java层):**  例如，一个网络监控 App 可能使用 `ConnectivityManager` 或 `NetworkStatsManager` 等 Java API 来获取网络连接信息。

2. **System Services (Java/Native层):**  `ConnectivityService` 和 `NetworkStatsService` 等系统服务负责管理网络连接和统计信息。这些服务通常会调用底层的 native 代码来实现功能。

3. **NDK (Native层):**  系统服务或者直接使用 NDK 开发的应用可能会使用标准的 socket API（例如 `socket`, `sendto`, `recvfrom`）与内核进行交互。

4. **Bionic Libc:** NDK 提供的 socket API 最终会调用 Bionic libc 中的实现。

5. **System Calls:** Bionic libc 中的 socket 函数会通过系统调用 (syscall) 进入 Linux 内核。

6. **Linux Kernel (Netlink):** 在内核中，当收到一个针对 `NETLINK_GENERIC` 并且家族名称为 `tcp_metrics` 的消息时，内核的网络子系统会处理这个请求，并返回相应的 TCP 度量信息。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 监控应用程序尝试获取 TCP 度量的简化示例。我们将 Hook `sendto` 系统调用，因为这是用户空间程序向内核发送Netlink消息的关键步骤。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received message: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error message: {message['error']}")

def main():
    package_name = "your.target.app"  # 替换为你要监控的应用程序的包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Error: Process '{package_name}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "sendto"), {
        onEnter: function(args) {
            var sockfd = args[0].toInt32();
            var buf = ptr(args[1]);
            var len = args[2].toInt32();
            var dest_addr = ptr(args[4]);

            // 检查是否是 Netlink 套接字
            var sockaddr_family = dest_addr.readU16();
            if (sockaddr_family == 18) { // AF_NETLINK = 18
                console.log("[*] sendto called on Netlink socket. File descriptor: " + sockfd);
                console.log("[*] Length of data: " + len);

                // 尝试读取 Netlink 头部 (假设标准 Generic Netlink 头部)
                var nlmsg_len = buf.readU32();
                var nlmsg_type = buf.readU16();
                var nlmsg_flags = buf.readU16();
                var nlmsg_seq = buf.readU32();
                var nlmsg_pid = buf.readU32();

                console.log("[*] Netlink Header:");
                console.log("    Length: " + nlmsg_len);
                console.log("    Type: " + nlmsg_type);
                console.log("    Flags: " + nlmsg_flags);
                console.log("    Sequence: " + nlmsg_seq);
                console.log("    PID: " + nlmsg_pid);

                // 你可以进一步解析 Netlink 消息的有效负载，查找 TCP_METRICS_GENL_NAME 等
            }
        },
        onLeave: function(retval) {
            // console.log("[*] sendto returned: " + retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to exit.")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**Frida Hook 示例说明:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到目标 Android 应用程序。
2. **`Interceptor.attach(Module.findExportByName(null, "sendto"), ...)`:**  Hook `sendto` 函数。`Module.findExportByName(null, "sendto")` 会在所有已加载的模块中查找 `sendto` 函数的地址，这通常位于 `libc.so` 中。
3. **`onEnter`:** 在 `sendto` 函数被调用时执行。
4. **`args`:**  包含了 `sendto` 函数的参数。`args[0]` 是套接字文件描述符，`args[1]` 是发送缓冲区的指针，`args[2]` 是发送数据的长度，`args[4]` 是目标地址的指针。
5. **检查 `AF_NETLINK`:** 代码检查目标地址的地址族是否为 `AF_NETLINK` (18)，以判断是否是在向 Netlink 套接字发送数据。
6. **读取 Netlink 头部:**  尝试读取 Netlink 消息的头部信息，例如长度、类型、标志、序列号和 PID。
7. **进一步解析:**  在 `onEnter` 函数中，你可以根据 Netlink 消息的类型和属性进一步解析消息的有效负载，查找是否包含了与 TCP 度量相关的请求。你需要了解 Netlink 消息的详细结构才能进行准确的解析。

这个 Frida 示例提供了一个监控应用程序与内核进行 Netlink 通信的基本方法。要更精确地监控 TCP 度量相关的通信，你需要深入了解通用 Netlink 的协议细节以及 `tcp_metrics` 家族定义的具体消息格式。你可以 Hook 更多的函数，例如 `recvfrom` 来查看内核返回的响应。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/tcp_metrics.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_TCP_METRICS_H
#define _UAPI_LINUX_TCP_METRICS_H
#include <linux/types.h>
#define TCP_METRICS_GENL_NAME "tcp_metrics"
#define TCP_METRICS_GENL_VERSION 0x1
enum tcp_metric_index {
  TCP_METRIC_RTT,
  TCP_METRIC_RTTVAR,
  TCP_METRIC_SSTHRESH,
  TCP_METRIC_CWND,
  TCP_METRIC_REORDERING,
  TCP_METRIC_RTT_US,
  TCP_METRIC_RTTVAR_US,
  __TCP_METRIC_MAX,
};
#define TCP_METRIC_MAX (__TCP_METRIC_MAX - 1)
enum {
  TCP_METRICS_A_METRICS_RTT = 1,
  TCP_METRICS_A_METRICS_RTTVAR,
  TCP_METRICS_A_METRICS_SSTHRESH,
  TCP_METRICS_A_METRICS_CWND,
  TCP_METRICS_A_METRICS_REODERING,
  TCP_METRICS_A_METRICS_RTT_US,
  TCP_METRICS_A_METRICS_RTTVAR_US,
  __TCP_METRICS_A_METRICS_MAX
};
#define TCP_METRICS_A_METRICS_MAX (__TCP_METRICS_A_METRICS_MAX - 1)
enum {
  TCP_METRICS_ATTR_UNSPEC,
  TCP_METRICS_ATTR_ADDR_IPV4,
  TCP_METRICS_ATTR_ADDR_IPV6,
  TCP_METRICS_ATTR_AGE,
  TCP_METRICS_ATTR_TW_TSVAL,
  TCP_METRICS_ATTR_TW_TS_STAMP,
  TCP_METRICS_ATTR_VALS,
  TCP_METRICS_ATTR_FOPEN_MSS,
  TCP_METRICS_ATTR_FOPEN_SYN_DROPS,
  TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS,
  TCP_METRICS_ATTR_FOPEN_COOKIE,
  TCP_METRICS_ATTR_SADDR_IPV4,
  TCP_METRICS_ATTR_SADDR_IPV6,
  TCP_METRICS_ATTR_PAD,
  __TCP_METRICS_ATTR_MAX,
};
#define TCP_METRICS_ATTR_MAX (__TCP_METRICS_ATTR_MAX - 1)
enum {
  TCP_METRICS_CMD_UNSPEC,
  TCP_METRICS_CMD_GET,
  TCP_METRICS_CMD_DEL,
  __TCP_METRICS_CMD_MAX,
};
#define TCP_METRICS_CMD_MAX (__TCP_METRICS_CMD_MAX - 1)
#endif

"""

```