Response:
Let's break down the thought process to answer the user's request about the `rds.h` header file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `rds.h` file within the context of Android (bionic). Key questions are about its purpose, relationship to Android, implementation details (especially for libc functions), dynamic linking aspects, potential usage errors, and how it's reached from the Android framework/NDK. They also requested Frida hook examples.

**2. Initial Analysis of the Header File:**

* **`#ifndef _LINUX_RDS_H` / `#define _LINUX_RDS_H`:**  This is a standard include guard, indicating this file defines an interface that should only be included once per compilation unit.
* **`#include <linux/types.h>` / `#include <linux/socket.h>` / `#include <linux/in6.h>`:**  These includes strongly suggest this header file defines Linux kernel-level interfaces related to networking, specifically sockets and IP addressing (both IPv4 and IPv6). The `rds` likely stands for "Reliable Datagram Sockets" or something similar.
* **Constants (`RDS_IB_ABI_VERSION`, `SOL_RDS`, `RDS_CANCEL_SENT_TO`, etc.):**  These are symbolic names for numerical values. They act as flags, options, or identifiers within the RDS protocol. The `SOL_RDS` suggests a specific socket protocol level. The prefixes like `RDS_` and `SO_RDS_` further reinforce this.
* **Typedefs (`typedef __u8 rds_tos_t;`):** Defines aliases for basic data types, making the code more readable and potentially platform-independent within the Linux kernel context.
* **Structures (`struct rds_info_counter`, `struct rds_info_connection`, etc.):** These define data structures used to represent various aspects of the RDS protocol, such as connection information, message details, and socket statistics. The `__attribute__((packed))` suggests an effort to minimize structure size, likely for performance reasons in kernel space.
* **Enums (`enum rds_message_rxpath_latency`):**  Defines a set of named constants related to the latency measurements in the RDS receive path.
* **Macros (`RDS_CONG_MONITOR_SIZE`, `RDS_CONG_MONITOR_BIT`, etc.):** These are preprocessor directives that perform text substitution. The congestion monitor macros suggest some form of flow control within RDS.
* **More Structures (`struct rds_iovec`, `struct rds_get_mr_args`, etc.):**  These structures appear to define the arguments for specific RDS operations, such as getting memory regions for RDMA (Remote Direct Memory Access). The `mr` likely stands for Memory Region.
* **RDMA Related Constants (`RDS_RDMA_SUCCESS`, `RDS_RDMA_READWRITE`, etc.):** These constants are specifically related to Remote Direct Memory Access, a high-performance networking technique.

**3. Connecting to Android (bionic):**

* **Location (`bionic/libc/kernel/uapi/linux/rds.handroid`):** The key is the path. `bionic` is Android's C library. `libc/kernel/uapi` strongly indicates that this is a *user-space* view of kernel interfaces. `uapi` stands for "user-space API". The `handroid` likely denotes Android-specific modifications or organization.
* **Functionality:** RDS is a Linux kernel feature. Android, being built upon the Linux kernel, can potentially utilize RDS. However, it's less common in typical Android application development compared to TCP/IP. Its use is more likely in specific scenarios like high-performance inter-process communication or potentially within system services.

**4. Addressing Specific Questions:**

* **Functionality Listing:** Summarize the identified areas: Network communication (sockets), RDMA support, Quality of Service (TOS), Congestion control, and gathering statistics.
* **Relationship to Android:**  Emphasize the kernel-level nature. Give potential examples (inter-process communication in specific daemons) while acknowledging it's not a mainstream Android feature.
* **libc Function Explanation:** The critical realization here is that *this header file itself doesn't contain libc function implementations*. It *defines* the structures and constants that *might be used* by libc functions. The focus should be on *what* these definitions represent, not *how* a libc function implements them. Example: `socket()` in libc might use `SOL_RDS` when creating an RDS socket.
* **Dynamic Linker:**  This header is used at compile time. It doesn't directly involve the dynamic linker during runtime linking of shared objects. Therefore, the SO layout and linking process are not directly relevant to this specific header. State this clearly.
* **Logic Reasoning:**  The "reasoning" is mostly about interpreting the definitions. Provide examples of how a flag or structure field might be used.
* **Usage Errors:** Focus on misinterpreting constants, incorrect structure usage, and the general complexity of kernel-level networking.
* **Android Framework/NDK Path:** Explain that direct usage from typical app development is unlikely. Focus on potential kernel-level or system service usage.
* **Frida Hook:**  The challenge is that these are kernel-level definitions. Frida hooks are typically applied in user space. Demonstrate hooking a related system call (like `socket`) and filtering by the protocol family to show how one might *indirectly* observe RDS activity.

**5. Structuring the Response:**

Organize the answer logically, addressing each part of the user's request. Use clear headings and formatting. Provide code examples where appropriate (even if they are conceptual for libc implementation).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe I should try to find the libc source code for functions that use these definitions. **Correction:** Realized that's going too deep for this request. The focus is on what the header *represents*, not the full implementation.
* **Initial thought:** Provide a complex SO layout example. **Correction:** Recognized that this header doesn't directly trigger dynamic linking behavior. Focus on explaining why it's not applicable.
* **Initial thought:**  Give very specific Android framework examples. **Correction:**  Keep the Android examples more general, as direct RDS usage is not common in the app framework. Highlight potential system service use.

By following these steps, including the critical analysis of the file's content and its location within the bionic tree,  a comprehensive and accurate answer can be constructed that addresses all aspects of the user's query.
这个头文件 `bionic/libc/kernel/uapi/linux/rds.handroid` 定义了 Linux 内核中 Reliable Datagram Sockets (RDS) 协议的用户空间 API。它属于 Android 的 Bionic 库，因此是 Android 系统与 Linux 内核中 RDS 功能进行交互的桥梁。

**功能列举:**

该头文件主要定义了以下内容，从而提供了访问 RDS 功能的接口：

1. **常量定义 (Macros & Defines):**
   - `RDS_IB_ABI_VERSION`: 定义了 RDS over InfiniBand 的 ABI 版本。
   - `SOL_RDS`: 定义了 `getsockopt` 和 `setsockopt` 函数中用于 RDS 选项的协议级别。
   - `RDS_CANCEL_SENT_TO`, `RDS_GET_MR`, `RDS_FREE_MR`, `RDS_RECVERR`, `RDS_CONG_MONITOR`, `RDS_GET_MR_FOR_DEST`: 定义了用于 RDS 特定 `setsockopt` 和 `getsockopt` 操作的选项。这些选项允许用户空间程序控制 RDS 的行为，例如取消发送、获取/释放内存区域 (Memory Region，用于 RDMA)。
   - `SO_RDS_TRANSPORT`, `SO_RDS_MSG_RXPATH_LATENCY`:  定义了用于 `getsockopt` 和 `setsockopt` 获取/设置 RDS 传输层和消息接收路径延迟的选项。
   - `RDS_TRANS_IB`, `RDS_TRANS_GAP`, `RDS_TRANS_TCP`, `RDS_TRANS_COUNT`, `RDS_TRANS_NONE`, `RDS_TRANS_IWARP`: 定义了 RDS 支持的传输层类型 (InfiniBand, iWARP, TCP)。
   - `SIOCRDSSETTOS`, `SIOCRDSGETTOS`:  定义了用于设置和获取 RDS 服务类型 (Type of Service, TOS) 的 ioctl 命令。
   - `RDS_CMSG_RDMA_ARGS`, `RDS_CMSG_RDMA_DEST`, `RDS_CMSG_RDMA_MAP`, `RDS_CMSG_RDMA_STATUS`, `RDS_CMSG_CONG_UPDATE`, `RDS_CMSG_ATOMIC_FADD`, `RDS_CMSG_ATOMIC_CSWP`, `RDS_CMSG_MASKED_ATOMIC_FADD`, `RDS_CMSG_MASKED_ATOMIC_CSWP`, `RDS_CMSG_RXPATH_LATENCY`, `RDS_CMSG_ZCOPY_COOKIE`, `RDS_CMSG_ZCOPY_COMPLETION`: 定义了与 RDS 控制消息 (Control Message) 相关的常量，这些控制消息通常通过 `sendmsg` 和 `recvmsg` 函数传递，用于 RDMA 操作、拥塞控制更新、原子操作、接收路径延迟信息以及零拷贝操作。
   - `RDS_INFO_FIRST` 到 `RDS6_INFO_IB_CONNECTIONS`: 定义了用于获取 RDS 统计信息的常量，可以通过 `getsockopt` 与 `SOL_RDS` 结合使用，获取连接、消息、套接字等信息。

2. **类型定义 (Typedefs):**
   - `rds_tos_t`: 定义了 RDS 服务类型的别名。

3. **结构体定义 (Structs):**
   - `rds_info_counter`: 定义了用于表示 RDS 计数器信息的结构体，包含名称和值。
   - `rds_info_connection`, `rds6_info_connection`: 定义了用于表示 RDS 连接信息的结构体，包括序列号、本地/远端地址、传输层类型和标志。IPv6 版本有单独的结构体。
   - `rds_info_message`, `rds6_info_message`: 定义了用于表示 RDS 消息信息的结构体，包括序列号、长度、本地/远端地址/端口和标志。IPv6 版本有单独的结构体。
   - `rds_info_socket`, `rds6_info_socket`: 定义了用于表示 RDS 套接字信息的结构体，包括发送/接收缓冲区大小、绑定/连接地址/端口和 inode 号。IPv6 版本有单独的结构体。
   - `rds_info_tcp_socket`, `rds6_info_tcp_socket`: 定义了用于表示基于 TCP 传输的 RDS 连接信息的结构体，包含本地/远端地址/端口、剩余数据量和 TCP 状态信息。IPv6 版本有单独的结构体。
   - `rds_info_rdma_connection`, `rds6_info_rdma_connection`: 定义了用于表示 RDS over RDMA 连接信息的结构体，包含地址、GID (Global Identifier)、最大发送/接收工作请求、最大 Scatter/Gather Entry 和 RDMA 内存区域限制。IPv6 版本有单独的结构体。
   - `rds_rx_trace_so`, `rds_cmsg_rx_trace`: 定义了用于追踪 RDS 消息接收路径延迟的结构体。
   - `rds_iovec`: 定义了用于表示内存块的结构体，包含地址和长度，常用于 RDMA 操作。
   - `rds_get_mr_args`, `rds_get_mr_for_dest_args`, `rds_free_mr_args`: 定义了用于获取和释放 RDMA 内存区域的参数结构体。
   - `rds_rdma_args`: 定义了执行 RDMA 读写操作的参数结构体。
   - `rds_atomic_args`: 定义了执行 RDMA 原子操作（例如，原子加、比较并交换）的参数结构体。
   - `rds_rdma_notify`: 定义了 RDMA 操作完成通知的结构体。
   - `rds_zcopy_cookies`: 定义了用于零拷贝操作的 cookie 数组结构体。

4. **枚举类型 (Enums):**
   - `rds_message_rxpath_latency`: 定义了 RDS 消息接收路径中各个阶段的枚举值，用于延迟追踪。

**与 Android 功能的关系及举例说明:**

RDS 是一种高性能的网络协议，主要用于集群环境和高性能计算。在 Android 中，直接使用 RDS 的场景相对较少，因为它不是通用的应用程序通信方式。然而，在某些特定的 Android 系统服务或定制化的 Android 设备中，可能会使用 RDS 来实现高性能的内部通信。

**举例说明:**

- **系统服务间通信:** 某些需要极低延迟和高吞吐量的 Android 系统服务，如果运行在支持 RDS 的硬件上，可能会使用 RDS 进行内部通信，例如在多媒体处理、传感器数据聚合等场景。
- **高性能 IPC (Inter-Process Communication):**  在特定的 Android 环境下，例如嵌入式系统或服务器化的 Android，可能会使用 RDS 作为进程间通信的一种方式，尤其是在需要利用 RDMA 能力的场景下。

**详细解释 libc 函数的功能是如何实现的:**

这个头文件本身**不包含 libc 函数的实现**，它只是定义了 Linux 内核中 RDS 功能的接口。libc 中的网络相关函数（如 `socket`, `bind`, `connect`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `ioctl`）会使用这里定义的常量、结构体和类型与内核中的 RDS 模块进行交互。

**例如 `socket()` 函数的实现可能涉及以下步骤（简化描述）：**

1. 用户空间的程序调用 `socket(AF_RDS, SOCK_DGRAM, 0)` 或其他与 RDS 相关的参数。
2. libc 中的 `socket()` 函数会将这些参数打包，并通过系统调用（例如 `sys_socket`）传递给 Linux 内核。
3. 内核中的 `sys_socket` 函数会根据 `AF_RDS` 参数，创建与 RDS 协议族相关的套接字数据结构。这个过程中会使用到 `SOL_RDS` 等常量来标识协议类型。

**例如 `setsockopt()` 函数的实现可能涉及以下步骤（简化描述）：**

1. 用户空间的程序调用 `setsockopt(sockfd, SOL_RDS, RDS_CONG_MONITOR, ...)` 来设置 RDS 的拥塞监控选项。
2. libc 中的 `setsockopt()` 函数会将这些参数打包，并通过系统调用（例如 `sys_setsockopt`）传递给 Linux 内核。
3. 内核中的 `sys_setsockopt` 函数会根据 `SOL_RDS` 和 `RDS_CONG_MONITOR` 参数，找到对应的 RDS 套接字选项处理函数，并根据用户提供的数据进行设置。

**对于涉及 dynamic linker 的功能:**

这个头文件本身**不直接涉及 dynamic linker 的功能**。它是在编译时被包含到程序中，用于声明 RDS 相关的接口。dynamic linker 的主要作用是在程序运行时加载和链接共享库。

**SO 布局样本和链接的处理过程（不适用此头文件）：**

由于此头文件定义的是内核接口，它不会导致新的共享库的生成或链接。如果用户空间的程序需要使用 RDS 功能，它会链接到标准的 libc 库，而 libc 库内部会通过系统调用与内核中的 RDS 模块进行交互。

**逻辑推理和假设输入与输出:**

假设一个用户空间的程序想要获取 RDS 连接的统计信息：

**假设输入:**

- 一个已经创建并连接的 RDS 套接字的文件描述符 `sockfd`。
- 想要获取的统计信息类型：`RDS_INFO_CONNECTIONS`。
- 一个用于存储 `rds_info_connection` 结构体数组的缓冲区 `buf`。
- 缓冲区的大小 `len`。

**代码片段:**

```c
#include <sys/socket.h>
#include <linux/rds.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int sockfd = socket(AF_RDS, SOCK_SEQPACKET, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    // ... (建立 RDS 连接的代码) ...

    struct rds_info_connection conns[10]; // 假设最多有 10 个连接
    socklen_t len = sizeof(conns);

    if (getsockopt(sockfd, SOL_RDS, RDS_INFO_CONNECTIONS, conns, &len) == -1) {
        perror("getsockopt");
        close(sockfd);
        return 1;
    }

    int num_connections = len / sizeof(struct rds_info_connection);
    printf("Number of RDS connections: %d\n", num_connections);
    for (int i = 0; i < num_connections; i++) {
        printf("Connection %d: Local Address: %u, Remote Address: %u\n",
               i, conns[i].laddr, conns[i].faddr);
    }

    close(sockfd);
    return 0;
}
```

**预期输出:**

程序会打印当前 RDS 连接的数量，以及每个连接的本地和远端 IP 地址（以无符号整数形式）。具体的输出取决于系统上实际的 RDS 连接状态。

**涉及用户或者编程常见的使用错误:**

1. **未启用 RDS 内核模块:** 如果 Linux 内核没有加载 RDS 模块，尝试创建 `AF_RDS` 套接字将会失败。
2. **权限不足:**  执行某些 RDS 操作可能需要 root 权限。
3. **错误的 `getsockopt` 或 `setsockopt` 参数:**  传递错误的协议级别 (`SOL_RDS`) 或选项名称 (`RDS_INFO_CONNECTIONS`) 会导致调用失败。
4. **缓冲区大小不足:** 在使用 `getsockopt` 获取统计信息时，提供的缓冲区可能不足以容纳所有的数据，导致数据截断或错误。
5. **错误地理解 RDMA 操作:**  RDMA 操作涉及复杂的内存管理和同步，错误地使用 `rds_get_mr_args`、`rds_rdma_args` 等结构体可能导致程序崩溃或数据损坏。例如，忘记注册内存区域或在操作完成前释放内存。
6. **不正确的地址和端口:** 在连接 RDS 套接字时，需要提供正确的本地和远端地址和端口。

**Android Framework 或 NDK 如何一步步的到达这里:**

在典型的 Android 应用开发中，开发者通常不会直接使用 `AF_RDS` 套接字。Android Framework 提供了更高级的网络抽象，例如 Java 中的 `Socket` 类或 NDK 中的 POSIX socket API。

**到达这里的路径通常发生在 Android 系统服务或底层库中:**

1. **Android 系统服务 (Java 层):** 某些系统服务如果需要使用 RDS 进行高性能通信，可能会通过 JNI 调用到 Native 层。
2. **Native 层 (C/C++):** 在 Native 层，可能会直接使用 POSIX socket API 创建 `AF_RDS` 套接字，并使用 `setsockopt`、`getsockopt` 等函数，这些函数最终会包含 `<linux/rds.h>` 中定义的常量和结构体。
3. **Bionic libc:** Native 层的 socket 相关函数调用会链接到 Bionic libc 库。
4. **系统调用:** Bionic libc 中的 socket 函数会将操作转换为系统调用，传递给 Linux 内核。
5. **Linux 内核:** 内核接收到与 `AF_RDS` 相关的系统调用后，会调用 RDS 模块中的相应处理函数，这些函数会根据 `<linux/rds.h>` 中定义的接口进行操作。

**Frida Hook 示例调试这些步骤:**

由于 `rds.h` 定义的是内核接口，直接在用户空间 hook 这些常量和结构体意义不大。更有效的方法是 hook 与 RDS 相关的系统调用，例如 `socket`、`setsockopt` 和 `getsockopt`，并过滤 `domain` 参数为 `AF_RDS` 的调用。

**Frida Hook 示例:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach('com.example.myapp') # 替换为你的目标进程
except frida.ProcessNotFoundError:
    print("目标进程未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName(null, "socket"), {
    onEnter: function(args) {
        var domain = args[0].toInt32();
        var type = args[1].toInt32();
        var protocol = args[2].toInt32();
        if (domain === 28) { // AF_RDS 的值，可能因系统而异，可以通过头文件确认
            send({event: "socket", args: [domain, type, protocol]});
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "setsockopt"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var level = args[1].toInt32();
        var optname = args[2].toInt32();
        if (level === 276) { // SOL_RDS 的值
            send({event: "setsockopt", args: [sockfd, level, optname]});
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "getsockopt"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var level = args[1].toInt32();
        var optname = args[2].toInt32();
        if (level === 276) { // SOL_RDS 的值
            send({event: "getsockopt", args: [sockfd, level, optname]});
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
print("[*] Frida 脚本已加载，正在监听 RDS 相关系统调用...")
sys.stdin.read()
session.detach()
```

**使用说明:**

1. 将 `com.example.myapp` 替换为你的目标 Android 应用程序的进程名。
2. 确保你的 Android 设备已连接并通过 USB 调试启用。
3. 运行此 Frida 脚本。当目标应用调用 `socket`、`setsockopt` 或 `getsockopt` 且与 RDS 相关时，脚本会打印相关信息。

这个 Frida 脚本可以帮助你观察 Android 应用程序或系统服务是否以及如何使用 RDS 功能。请注意，`AF_RDS` 和 `SOL_RDS` 的实际数值可能因 Android 版本和内核配置而异，你需要根据目标环境进行确认。 你可以通过在目标设备的 shell 中查看 `/usr/include/linux/socket.h` 和 `/usr/include/linux/rds.h` 来获取确切的数值。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/rds.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_RDS_H
#define _LINUX_RDS_H
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in6.h>
#define RDS_IB_ABI_VERSION 0x301
#define SOL_RDS 276
#define RDS_CANCEL_SENT_TO 1
#define RDS_GET_MR 2
#define RDS_FREE_MR 3
#define RDS_RECVERR 5
#define RDS_CONG_MONITOR 6
#define RDS_GET_MR_FOR_DEST 7
#define SO_RDS_TRANSPORT 8
#define SO_RDS_MSG_RXPATH_LATENCY 10
#define RDS_TRANS_IB 0
#define RDS_TRANS_GAP 1
#define RDS_TRANS_TCP 2
#define RDS_TRANS_COUNT 3
#define RDS_TRANS_NONE (~0)
#define RDS_TRANS_IWARP RDS_TRANS_GAP
#define SIOCRDSSETTOS (SIOCPROTOPRIVATE)
#define SIOCRDSGETTOS (SIOCPROTOPRIVATE + 1)
typedef __u8 rds_tos_t;
#define RDS_CMSG_RDMA_ARGS 1
#define RDS_CMSG_RDMA_DEST 2
#define RDS_CMSG_RDMA_MAP 3
#define RDS_CMSG_RDMA_STATUS 4
#define RDS_CMSG_CONG_UPDATE 5
#define RDS_CMSG_ATOMIC_FADD 6
#define RDS_CMSG_ATOMIC_CSWP 7
#define RDS_CMSG_MASKED_ATOMIC_FADD 8
#define RDS_CMSG_MASKED_ATOMIC_CSWP 9
#define RDS_CMSG_RXPATH_LATENCY 11
#define RDS_CMSG_ZCOPY_COOKIE 12
#define RDS_CMSG_ZCOPY_COMPLETION 13
#define RDS_INFO_FIRST 10000
#define RDS_INFO_COUNTERS 10000
#define RDS_INFO_CONNECTIONS 10001
#define RDS_INFO_SEND_MESSAGES 10003
#define RDS_INFO_RETRANS_MESSAGES 10004
#define RDS_INFO_RECV_MESSAGES 10005
#define RDS_INFO_SOCKETS 10006
#define RDS_INFO_TCP_SOCKETS 10007
#define RDS_INFO_IB_CONNECTIONS 10008
#define RDS_INFO_CONNECTION_STATS 10009
#define RDS_INFO_IWARP_CONNECTIONS 10010
#define RDS6_INFO_CONNECTIONS 10011
#define RDS6_INFO_SEND_MESSAGES 10012
#define RDS6_INFO_RETRANS_MESSAGES 10013
#define RDS6_INFO_RECV_MESSAGES 10014
#define RDS6_INFO_SOCKETS 10015
#define RDS6_INFO_TCP_SOCKETS 10016
#define RDS6_INFO_IB_CONNECTIONS 10017
#define RDS_INFO_LAST 10017
struct rds_info_counter {
  __u8 name[32];
  __u64 value;
} __attribute__((packed));
#define RDS_INFO_CONNECTION_FLAG_SENDING 0x01
#define RDS_INFO_CONNECTION_FLAG_CONNECTING 0x02
#define RDS_INFO_CONNECTION_FLAG_CONNECTED 0x04
#define TRANSNAMSIZ 16
struct rds_info_connection {
  __u64 next_tx_seq;
  __u64 next_rx_seq;
  __be32 laddr;
  __be32 faddr;
  __u8 transport[TRANSNAMSIZ];
  __u8 flags;
  __u8 tos;
} __attribute__((packed));
struct rds6_info_connection {
  __u64 next_tx_seq;
  __u64 next_rx_seq;
  struct in6_addr laddr;
  struct in6_addr faddr;
  __u8 transport[TRANSNAMSIZ];
  __u8 flags;
} __attribute__((packed));
#define RDS_INFO_MESSAGE_FLAG_ACK 0x01
#define RDS_INFO_MESSAGE_FLAG_FAST_ACK 0x02
struct rds_info_message {
  __u64 seq;
  __u32 len;
  __be32 laddr;
  __be32 faddr;
  __be16 lport;
  __be16 fport;
  __u8 flags;
  __u8 tos;
} __attribute__((packed));
struct rds6_info_message {
  __u64 seq;
  __u32 len;
  struct in6_addr laddr;
  struct in6_addr faddr;
  __be16 lport;
  __be16 fport;
  __u8 flags;
  __u8 tos;
} __attribute__((packed));
struct rds_info_socket {
  __u32 sndbuf;
  __be32 bound_addr;
  __be32 connected_addr;
  __be16 bound_port;
  __be16 connected_port;
  __u32 rcvbuf;
  __u64 inum;
} __attribute__((packed));
struct rds6_info_socket {
  __u32 sndbuf;
  struct in6_addr bound_addr;
  struct in6_addr connected_addr;
  __be16 bound_port;
  __be16 connected_port;
  __u32 rcvbuf;
  __u64 inum;
} __attribute__((packed));
struct rds_info_tcp_socket {
  __be32 local_addr;
  __be16 local_port;
  __be32 peer_addr;
  __be16 peer_port;
  __u64 hdr_rem;
  __u64 data_rem;
  __u32 last_sent_nxt;
  __u32 last_expected_una;
  __u32 last_seen_una;
  __u8 tos;
} __attribute__((packed));
struct rds6_info_tcp_socket {
  struct in6_addr local_addr;
  __be16 local_port;
  struct in6_addr peer_addr;
  __be16 peer_port;
  __u64 hdr_rem;
  __u64 data_rem;
  __u32 last_sent_nxt;
  __u32 last_expected_una;
  __u32 last_seen_una;
} __attribute__((packed));
#define RDS_IB_GID_LEN 16
struct rds_info_rdma_connection {
  __be32 src_addr;
  __be32 dst_addr;
  __u8 src_gid[RDS_IB_GID_LEN];
  __u8 dst_gid[RDS_IB_GID_LEN];
  __u32 max_send_wr;
  __u32 max_recv_wr;
  __u32 max_send_sge;
  __u32 rdma_mr_max;
  __u32 rdma_mr_size;
  __u8 tos;
  __u8 sl;
  __u32 cache_allocs;
};
struct rds6_info_rdma_connection {
  struct in6_addr src_addr;
  struct in6_addr dst_addr;
  __u8 src_gid[RDS_IB_GID_LEN];
  __u8 dst_gid[RDS_IB_GID_LEN];
  __u32 max_send_wr;
  __u32 max_recv_wr;
  __u32 max_send_sge;
  __u32 rdma_mr_max;
  __u32 rdma_mr_size;
  __u8 tos;
  __u8 sl;
  __u32 cache_allocs;
};
enum rds_message_rxpath_latency {
  RDS_MSG_RX_HDR_TO_DGRAM_START = 0,
  RDS_MSG_RX_DGRAM_REASSEMBLE,
  RDS_MSG_RX_DGRAM_DELIVERED,
  RDS_MSG_RX_DGRAM_TRACE_MAX
};
struct rds_rx_trace_so {
  __u8 rx_traces;
  __u8 rx_trace_pos[RDS_MSG_RX_DGRAM_TRACE_MAX];
};
struct rds_cmsg_rx_trace {
  __u8 rx_traces;
  __u8 rx_trace_pos[RDS_MSG_RX_DGRAM_TRACE_MAX];
  __u64 rx_trace[RDS_MSG_RX_DGRAM_TRACE_MAX];
};
#define RDS_CONG_MONITOR_SIZE 64
#define RDS_CONG_MONITOR_BIT(port) (((unsigned int) port) % RDS_CONG_MONITOR_SIZE)
#define RDS_CONG_MONITOR_MASK(port) (1ULL << RDS_CONG_MONITOR_BIT(port))
typedef __u64 rds_rdma_cookie_t;
struct rds_iovec {
  __u64 addr;
  __u64 bytes;
};
struct rds_get_mr_args {
  struct rds_iovec vec;
  __u64 cookie_addr;
  __u64 flags;
};
struct rds_get_mr_for_dest_args {
  struct sockaddr_storage dest_addr;
  struct rds_iovec vec;
  __u64 cookie_addr;
  __u64 flags;
};
struct rds_free_mr_args {
  rds_rdma_cookie_t cookie;
  __u64 flags;
};
struct rds_rdma_args {
  rds_rdma_cookie_t cookie;
  struct rds_iovec remote_vec;
  __u64 local_vec_addr;
  __u64 nr_local;
  __u64 flags;
  __u64 user_token;
};
struct rds_atomic_args {
  rds_rdma_cookie_t cookie;
  __u64 local_addr;
  __u64 remote_addr;
  union {
    struct {
      __u64 compare;
      __u64 swap;
    } cswp;
    struct {
      __u64 add;
    } fadd;
    struct {
      __u64 compare;
      __u64 swap;
      __u64 compare_mask;
      __u64 swap_mask;
    } m_cswp;
    struct {
      __u64 add;
      __u64 nocarry_mask;
    } m_fadd;
  };
  __u64 flags;
  __u64 user_token;
};
struct rds_rdma_notify {
  __u64 user_token;
  __s32 status;
};
#define RDS_RDMA_SUCCESS 0
#define RDS_RDMA_REMOTE_ERROR 1
#define RDS_RDMA_CANCELED 2
#define RDS_RDMA_DROPPED 3
#define RDS_RDMA_OTHER_ERROR 4
#define RDS_MAX_ZCOOKIES 8
struct rds_zcopy_cookies {
  __u32 num;
  __u32 cookies[RDS_MAX_ZCOOKIES];
};
#define RDS_RDMA_READWRITE 0x0001
#define RDS_RDMA_FENCE 0x0002
#define RDS_RDMA_INVALIDATE 0x0004
#define RDS_RDMA_USE_ONCE 0x0008
#define RDS_RDMA_DONTWAIT 0x0010
#define RDS_RDMA_NOTIFY_ME 0x0020
#define RDS_RDMA_SILENT 0x0040
#endif
```