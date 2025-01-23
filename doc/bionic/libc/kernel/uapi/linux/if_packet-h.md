Response:
Let's break down the thought process for answering this request. The goal is to analyze a C header file related to packet sockets in Linux, specifically within the Android bionic library, and provide a comprehensive explanation.

**1. Understanding the Core Request:**

The primary request is to understand the *functionality* of `if_packet.h`. This means identifying the data structures, constants, and overall purpose of the header file. The request also specifically asks about the relationship to Android, explanations of libc functions (though this file doesn't define any), dynamic linker involvement, usage errors, and how Android framework/NDK reaches this code. Finally, a Frida hook example is requested.

**2. Initial Examination of the Header File:**

The first step is to scan the header file itself. Key observations:

* **`#ifndef __LINUX_IF_PACKET_H` and `#define __LINUX_IF_PACKET_H`:**  This is a standard include guard, preventing multiple inclusions.
* **`#include <asm/byteorder.h>` and `#include <linux/types.h>`:**  This indicates dependencies on other kernel header files for byte ordering and basic type definitions. This is a strong clue that this file deals with low-level kernel interactions.
* **`struct sockaddr_pkt` and `struct sockaddr_ll`:** These look like socket address structures. The `ll` likely stands for "link layer," suggesting raw network access. The fields within these structures (like `spkt_family`, `spkt_device`, `sll_ifindex`, `sll_addr`) reinforce this idea.
* **`#define PACKET_...` constants:** A large number of `#define` directives are present. These likely define flags, options, and values related to packet socket operations. Keywords like `HOST`, `BROADCAST`, `MULTICAST`, `RING`, `FANOUT` provide strong hints about the functionality.
* **`struct tpacket_...` structures:** Several structures prefixed with `tpacket_` appear. This strongly suggests features related to "packet ring buffers" for high-performance packet capture or sending. Fields like `tp_packets`, `tp_drops`, `tp_status`, `tp_len` are typical of such structures.
* **`enum tpacket_versions`:**  This indicates different versions of the packet ring buffer API.
* **`struct packet_mreq`:**  This structure seems related to "membership requests," likely for joining multicast groups.
* **`struct fanout_args`:** This hints at packet fanout mechanisms for distributing packets to multiple processes or threads.

**3. Inferring Functionality:**

Based on the structures and constants, the primary functionality of this header file is to define the interface for interacting with **packet sockets** in Linux. Packet sockets provide a way for applications to send and receive raw link-layer packets, bypassing the normal network protocol stack. This allows for low-level network operations like:

* **Packet sniffing/capture:** Reading all packets on a network interface.
* **Raw packet injection:** Sending custom-crafted Ethernet frames.
* **Link-layer protocol implementation:** Implementing protocols that operate directly on the Ethernet layer.

The presence of `tpacket_*` structures suggests support for **TPacket ring buffers**, which are a more efficient way to handle high volumes of packets compared to traditional `recvfrom()` calls.

**4. Connecting to Android:**

The file is located within the `bionic` directory, which is Android's C library. This means these definitions are available for use by Android applications and system services.

* **NDK Usage:**  Applications built with the Android NDK can directly use these structures and constants when working with socket programming.
* **Android Framework:**  While the Android framework typically uses higher-level APIs for networking, some low-level system services or HAL (Hardware Abstraction Layer) implementations might interact with packet sockets for specific tasks like network monitoring, VPN implementation, or network diagnostics.

**5. Explaining libc Functions:**

The crucial realization here is that **this header file does *not* define libc functions.** It defines *data structures and constants* used by system calls related to packet sockets. The actual functions (like `socket()`, `bind()`, `sendto()`, `recvfrom()`, `setsockopt()`, `getsockopt()`) are defined elsewhere in the C library and kernel. The explanations should focus on how these *system calls* would use the data structures defined in this header.

**6. Dynamic Linker and SO Layout:**

This header file itself doesn't directly involve the dynamic linker. However, the *use* of packet sockets in Android applications will involve the dynamic linker. The application will link against `libc.so`, which contains the implementations of the socket-related system call wrappers. The explanation should illustrate a typical SO layout where `libc.so` is loaded and how system calls are invoked.

**7. Logical Reasoning and Examples:**

For logical reasoning, consider how the different structures and constants relate to each other. For instance, how `sockaddr_ll` is used with `bind()` on a packet socket, or how the `PACKET_FANOUT` options affect packet delivery. The examples should be concrete and illustrate typical usage scenarios.

**8. Common Usage Errors:**

Think about common mistakes developers might make when working with raw sockets, such as incorrect address family, missing privileges, buffer overflows, or improper use of `setsockopt()`.

**9. Android Framework/NDK Path and Frida Hook:**

Trace the path from a high-level Android networking operation down to the packet socket level. This will involve system calls. The Frida hook example should target a system call related to packet sockets, demonstrating how to intercept and inspect the arguments.

**10. Structuring the Response:**

Organize the response logically, addressing each part of the request. Use clear headings and bullet points for readability. Provide code examples for illustration.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This file defines functions for packet sockets."  **Correction:** Realize it primarily defines *data structures* used by system calls.
* **Initial thought:** "Explain the implementation of `socket()`." **Correction:** Focus on how `socket()` would use the `AF_PACKET` family and how other system calls would use the structures defined here.
* **Ensure clarity on the separation of concerns:** Header file definitions vs. function implementations vs. system calls.

By following these steps and iteratively refining the understanding, a comprehensive and accurate answer can be constructed.
这是目录 `bionic/libc/kernel/uapi/linux/if_packet.h` 的源代码文件，它定义了与 Linux **packet sockets** 相关的用户空间 API。Packet sockets 是一种允许程序在链路层（L2）直接发送和接收数据包的强大机制，绕过了通常的网络协议栈处理。

**功能列举:**

这个头文件主要定义了以下内容：

1. **数据结构:**
   - `struct sockaddr_pkt`:  用于指定特定网络设备的包套接字地址。
   - `struct sockaddr_ll`:  更通用的链路层套接字地址，包含接口索引、硬件类型、协议类型和 MAC 地址等信息。
   - `struct tpacket_stats` 和 `struct tpacket_stats_v3`: 用于获取通过 TPacket 环形缓冲区收发数据包的统计信息，例如收发的包数量和丢弃的包数量。
   - `struct tpacket_rollover_stats`:  用于 TPacket 环形缓冲区回滚时的统计信息。
   - `union tpacket_stats_u`:  包含不同版本的 `tpacket_stats` 结构。
   - `struct tpacket_auxdata`:  包含关于接收到数据包的辅助信息，例如状态、长度、快照长度、MAC 层偏移、网络层偏移、VLAN 标签等。
   - `struct tpacket_hdr`:  用于 TPacket 版本 1 和 2 的数据包头信息。
   - `struct tpacket2_hdr`: 用于 TPacket 版本 2 的数据包头信息，包含 VLAN 信息。
   - `struct tpacket_hdr_variant1`:  用于 TPacket 版本 3 的数据包头变体。
   - `struct tpacket3_hdr`: 用于 TPacket 版本 3 的数据包头信息，更加灵活。
   - `struct tpacket_bd_ts`: 用于 TPacket 块描述符的时间戳信息。
   - `struct tpacket_hdr_v1`: 用于 TPacket 版本 1 的块描述符头信息。
   - `union tpacket_bd_header_u`:  包含不同版本的块描述符头。
   - `struct tpacket_block_desc`:  描述 TPacket 环形缓冲区中的一个块。
   - `struct tpacket_req`:  用于创建 TPacket 环形缓冲区的请求参数（版本 1 和 2）。
   - `struct tpacket_req3`: 用于创建 TPacket 环形缓冲区的请求参数（版本 3），支持更多特性。
   - `union tpacket_req_u`: 包含不同版本的 `tpacket_req` 结构。
   - `struct packet_mreq`:  用于加入或离开多播组的请求。
   - `struct fanout_args`: 用于配置数据包扇出（fanout）功能的参数。

2. **宏定义 (Constants):**
   - `PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_MULTICAST`, 等：定义了 `sockaddr_ll` 结构中 `sll_pkttype` 字段的取值，用于指定接收的数据包类型。
   - `PACKET_ADD_MEMBERSHIP`, `PACKET_DROP_MEMBERSHIP`, 等：定义了 `setsockopt` 函数中用于配置 packet socket 选项的常量。例如，用于添加或删除多播组成员、启用/禁用接收输出数据包等。
   - `TP_STATUS_KERNEL`, `TP_STATUS_USER`, 等：定义了 `tpacket_auxdata` 和 `tpacket_hdr` 结构中 `tp_status` 字段的取值，用于表示数据包的状态。
   - `TPACKET_ALIGNMENT`, `TPACKET_HDRLEN`, `TPACKET2_HDRLEN`, `TPACKET3_HDRLEN`: 定义了 TPacket 相关的对齐和头部长度常量。
   - `TPACKET_V1`, `TPACKET_V2`, `TPACKET_V3`:  定义了 TPacket 的版本号。
   - `PACKET_MR_MULTICAST`, `PACKET_MR_PROMISC`, 等：定义了 `packet_mreq` 结构中 `mr_type` 字段的取值，用于指定多播请求的类型，例如加入多播组、开启混杂模式等。
   - `PACKET_FANOUT_HASH`, `PACKET_FANOUT_LB`, 等：定义了数据包扇出功能的类型。
   - `PACKET_FANOUT_FLAG_ROLLOVER`, `PACKET_FANOUT_FLAG_UNIQUEID`, 等：定义了数据包扇出功能的标志位。

**与 Android 功能的关系及举例说明:**

虽然 `if_packet.h` 本身是 Linux 内核的 API，但作为 Android 的 C 库 `bionic` 的一部分，它使得 Android 应用程序（特别是通过 NDK 开发的应用）能够利用 packet socket 的功能。

**例子:**

* **网络监控和分析工具:**  Android 应用可以使用 packet socket 来捕获网络接口上的原始数据包，用于网络监控、协议分析或安全审计。例如，一个 Wi-Fi 分析应用可以使用 packet socket 来监听 Wi-Fi 数据帧。
* **VPN 应用:** VPN 应用的底层实现可能需要直接操作网络数据包，packet socket 提供了一种机制来实现自定义的网络协议栈。
* **数据包注入:** 一些特定的应用场景，例如网络测试或安全工具，可能需要构造并发送自定义的链路层数据包。
* **性能优化:** 通过使用 TPacket 环形缓冲区，可以高效地处理高吞吐量的网络数据包，这对于需要实时处理网络数据的应用非常有用。

**详细解释 libc 函数的功能是如何实现的:**

**重要说明:** `if_packet.h` **本身并不定义任何 libc 函数**。它定义的是数据结构和常量，这些数据结构和常量会被 libc 中与网络编程相关的函数使用，例如：

* **`socket(AF_PACKET, int socket_type, int protocol)`:**  `AF_PACKET` 地址族表示创建的是一个 packet socket。`socket_type` 可以是 `SOCK_RAW` (原始套接字，可以发送和接收任何链路层协议的数据包) 或 `SOCK_DGRAM` (链路层数据报套接字，通常用于特定的链路层协议)。`protocol` 可以指定特定的以太网协议类型（例如 `htons(ETH_P_IP)` 表示只接收 IP 数据包）。在创建 packet socket 时，系统会分配一个与该套接字关联的内核数据结构。
* **`bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`:**  对于 packet socket，`bind` 函数通常用于将套接字绑定到特定的网络接口。`addr` 参数通常是 `struct sockaddr_ll` 类型的指针，其中 `sll_ifindex` 字段指定了要绑定的接口索引。
* **`sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)` 和 `send(int sockfd, const void *buf, size_t len, int flags)`:** 用于通过 packet socket 发送数据包。可以直接构造包含链路层头部的数据包并发送出去。目标地址可以由 `struct sockaddr_ll` 指定。
* **`recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)` 和 `recv(int sockfd, void *buf, size_t len, int flags)`:** 用于从 packet socket 接收数据包。接收到的数据包通常包含链路层头部。如果提供了 `src_addr`，则会填充数据包的源地址信息（通常是 `struct sockaddr_ll`）。
* **`setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)` 和 `getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)`:**  packet socket 提供了许多特定的选项，可以通过 `setsockopt` 和 `getsockopt` 进行配置和获取。例如：
    - `PACKET_ADD_MEMBERSHIP` 和 `PACKET_DROP_MEMBERSHIP`: 用于加入和离开多播组。
    - `PACKET_RX_RING` 和 `PACKET_TX_RING`: 用于配置 TPacket 环形缓冲区。
    - `PACKET_FANOUT`: 用于配置数据包扇出功能。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`if_packet.h` 本身不涉及 dynamic linker 的功能。dynamic linker 的作用是在程序启动时加载所需的共享库（.so 文件）并解析符号。

当 Android 应用使用 packet socket 相关的 libc 函数时，它们会链接到 `libc.so`。

**SO 布局样本 (简化):**

```
libc.so:
    .text:  <libc 函数的代码，包括 socket, bind, sendto, recvfrom, setsockopt 等的实现>
    .data:  <全局变量>
    .bss:   <未初始化的全局变量>
    .symtab: <符号表，包含导出的函数和变量>
    .dynsym: <动态符号表>
    .rel.dyn: <动态重定位表>
    .rel.plt: <PLT (Procedure Linkage Table) 重定位表>
```

**链接的处理过程:**

1. **编译时:** 编译器遇到对 `socket` 等函数的调用时，会生成对这些函数的未解析引用。
2. **链接时:** 链接器会将应用程序的目标文件与所需的共享库（例如 `libc.so`）链接在一起。链接器会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `socket` 等函数的定义，并在应用程序的可执行文件中记录重定位信息。
3. **运行时:** 当程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
   - 加载程序所需的共享库 (`libc.so`) 到内存中。
   - 解析应用程序中的动态符号引用。对于通过 PLT 调用的外部函数，dynamic linker 会在第一次调用时解析目标函数的地址，并更新 PLT 表项，后续调用将直接跳转到已解析的地址。
   - 例如，当调用 `socket(AF_PACKET, ...)` 时，实际执行的是 `libc.so` 中 `socket` 函数的实现。这个实现会调用相应的 Linux 内核系统调用，并使用 `if_packet.h` 中定义的数据结构和常量与内核进行交互。

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个程序想要创建一个接收所有以太网帧的 packet socket 并绑定到名为 "eth0" 的接口：

**假设输入:**

* `socket()` 函数调用参数: `AF_PACKET`, `SOCK_RAW`, `htons(ETH_P_ALL)`
* `bind()` 函数调用参数:
    * `sockfd`: `socket()` 返回的套接字文件描述符
    * `addr`: 指向一个填充了 `struct sockaddr_ll` 结构的指针，其中：
        * `sll_family`: `AF_PACKET`
        * `sll_protocol`: `htons(ETH_P_ALL)`
        * `sll_ifindex`:  通过 `if_nametoindex("eth0")` 获取的接口索引
        * 其他字段设置为 0 或适当的值。
    * `addrlen`: `sizeof(struct sockaddr_ll)`

**逻辑推理:**

1. `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` 会创建一个能够接收所有以太网协议类型数据包的原始 packet socket。
2. `bind()` 函数会将这个套接字与指定的接口 "eth0" 关联起来，这意味着该套接字将只接收通过 "eth0" 接口传入的数据包。

**假设输出:**

* `socket()` 调用成功时返回一个非负的套接字文件描述符。失败时返回 -1 并设置 `errno`。
* `bind()` 调用成功时返回 0。失败时返回 -1 并设置 `errno`，例如 `errno` 可能被设置为 `EPERM` (没有足够的权限) 或 `ENODEV` (指定的接口不存在)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **权限不足:** 创建和操作 packet socket 通常需要 root 权限或 `CAP_NET_RAW` 能力。普通用户尝试创建 packet socket 可能会失败并返回 `EPERM` 错误。
   ```c
   int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   if (sockfd == -1) {
       perror("socket"); // 可能输出: socket: Operation not permitted
   }
   ```

2. **未正确设置 `sockaddr_ll` 结构:**  在 `bind` 或 `sendto` 时，如果 `struct sockaddr_ll` 结构中的字段（如 `sll_family`，`sll_protocol`，`sll_ifindex`) 设置不正确，会导致绑定失败或无法正确发送/接收数据包。
   ```c
   struct sockaddr_ll sll;
   memset(&sll, 0, sizeof(sll));
   sll.sll_family = AF_PACKET;
   // 忘记设置 sll_protocol 或 sll_ifindex
   if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
       perror("bind"); // 可能输出: bind: Invalid argument
   }
   ```

3. **缓冲区溢出:**  在接收数据包时，如果没有为接收缓冲区分配足够的空间，可能会导致缓冲区溢出。
   ```c
   char buffer[100]; // 缓冲区太小
   struct sockaddr_ll src_addr;
   socklen_t addrlen = sizeof(src_addr);
   ssize_t bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addrlen);
   if (bytes_received == -1) {
       perror("recvfrom");
   } else {
       // 如果接收到的数据包大于 100 字节，就会发生溢出
   }
   ```

4. **混淆 `sockaddr_pkt` 和 `sockaddr_ll`:**  `sockaddr_pkt` 结构已经过时，推荐使用 `sockaddr_ll`。混淆使用可能导致程序无法正常工作。

5. **不正确的协议类型:**  在 `socket` 函数中指定的协议类型 (`protocol`) 必须与期望接收或发送的数据包类型匹配。例如，如果只想接收 IP 数据包，应该使用 `htons(ETH_P_IP)`。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

Android Framework 通常不会直接使用 packet socket API。Framework 更倾向于使用更高层次的网络抽象，例如 `java.net.Socket` 或 `android.net.ConnectivityManager`。

**NDK 路径:**

1. **NDK 应用开发:**  开发者使用 Android NDK 开发 C/C++ 代码，这些代码可以直接调用 `bionic` 提供的 libc 函数，包括与 packet socket 相关的函数。
2. **`socket()` 系统调用:** NDK 代码调用 `socket(AF_PACKET, ...)` 函数。
3. **libc 封装:**  `bionic` 中的 `socket` 函数实现会调用相应的 Linux 内核系统调用 `__NR_socket`.
4. **内核处理:** Linux 内核接收到 `__NR_socket` 系统调用后，会创建并初始化一个 packet socket 的内核数据结构。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `socket` 系统调用，特别是当 `domain` 参数为 `AF_PACKET` 时的示例：

```javascript
if (Process.platform === 'linux') {
  const SYSCALL_NUMBER_SOCKET = 283; // 在 ARM64 上 __NR_socket 的系统调用号，可能需要根据架构调整

  Interceptor.attach(Module.getExportByName(null, 'syscall'), {
    onEnter: function (args) {
      const syscallNumber = args[0].toInt32();
      if (syscallNumber === SYSCALL_NUMBER_SOCKET) {
        const domain = args[1].toInt32();
        const type = args[2].toInt32();
        const protocol = args[3].toInt32();

        if (domain === 17) { // AF_PACKET 的值
          console.log("Detected socket(AF_PACKET, ...)");
          console.log("  Type:", type);
          console.log("  Protocol:", protocol);
          // 可以进一步检查 type 和 protocol 的值，例如 SOCK_RAW 等

          // 可以修改参数，例如阻止创建 packet socket
          // args[0] = -1;
        }
      }
    },
    onLeave: function (retval) {
      // console.log("syscall returned with:", retval);
    }
  });
} else {
  console.log("This script is designed for Linux.");
}
```

**使用 Frida 调试步骤:**

1. **安装 Frida:** 确保你的开发机器和 Android 设备上都安装了 Frida。
2. **运行 Frida Server:** 在 Android 设备上运行 Frida Server。
3. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存为一个 `.js` 文件（例如 `hook_packet_socket.js`）。
4. **运行 Frida 脚本:** 使用 Frida CLI 连接到目标 Android 进程并加载脚本。你需要知道目标进程的名称或 PID。

   ```bash
   frida -U -f <your_app_package_name> -l hook_packet_socket.js --no-pause
   # 或者连接到已经运行的进程
   frida -U <process_name_or_pid> -l hook_packet_socket.js
   ```

当你运行使用 packet socket 的 Android 应用时，Frida 脚本会在 `socket` 系统调用被调用时拦截，并打印出相关的参数信息。这可以帮助你理解 Android 应用（尤其是 NDK 开发的应用）是如何使用 packet socket API 的。

请注意，直接在 Android Framework 中使用 packet socket 是比较底层的操作，通常在系统服务或硬件抽象层 (HAL) 中可能见到。普通应用通常使用更高层次的网络 API。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/if_packet.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_IF_PACKET_H
#define __LINUX_IF_PACKET_H
#include <asm/byteorder.h>
#include <linux/types.h>
struct sockaddr_pkt {
  unsigned short spkt_family;
  unsigned char spkt_device[14];
  __be16 spkt_protocol;
};
struct sockaddr_ll {
  unsigned short sll_family;
  __be16 sll_protocol;
  int sll_ifindex;
  unsigned short sll_hatype;
  unsigned char sll_pkttype;
  unsigned char sll_halen;
  unsigned char sll_addr[8];
};
#define PACKET_HOST 0
#define PACKET_BROADCAST 1
#define PACKET_MULTICAST 2
#define PACKET_OTHERHOST 3
#define PACKET_OUTGOING 4
#define PACKET_LOOPBACK 5
#define PACKET_USER 6
#define PACKET_KERNEL 7
#define PACKET_FASTROUTE 6
#define PACKET_ADD_MEMBERSHIP 1
#define PACKET_DROP_MEMBERSHIP 2
#define PACKET_RECV_OUTPUT 3
#define PACKET_RX_RING 5
#define PACKET_STATISTICS 6
#define PACKET_COPY_THRESH 7
#define PACKET_AUXDATA 8
#define PACKET_ORIGDEV 9
#define PACKET_VERSION 10
#define PACKET_HDRLEN 11
#define PACKET_RESERVE 12
#define PACKET_TX_RING 13
#define PACKET_LOSS 14
#define PACKET_VNET_HDR 15
#define PACKET_TX_TIMESTAMP 16
#define PACKET_TIMESTAMP 17
#define PACKET_FANOUT 18
#define PACKET_TX_HAS_OFF 19
#define PACKET_QDISC_BYPASS 20
#define PACKET_ROLLOVER_STATS 21
#define PACKET_FANOUT_DATA 22
#define PACKET_IGNORE_OUTGOING 23
#define PACKET_VNET_HDR_SZ 24
#define PACKET_FANOUT_HASH 0
#define PACKET_FANOUT_LB 1
#define PACKET_FANOUT_CPU 2
#define PACKET_FANOUT_ROLLOVER 3
#define PACKET_FANOUT_RND 4
#define PACKET_FANOUT_QM 5
#define PACKET_FANOUT_CBPF 6
#define PACKET_FANOUT_EBPF 7
#define PACKET_FANOUT_FLAG_ROLLOVER 0x1000
#define PACKET_FANOUT_FLAG_UNIQUEID 0x2000
#define PACKET_FANOUT_FLAG_IGNORE_OUTGOING 0x4000
#define PACKET_FANOUT_FLAG_DEFRAG 0x8000
struct tpacket_stats {
  unsigned int tp_packets;
  unsigned int tp_drops;
};
struct tpacket_stats_v3 {
  unsigned int tp_packets;
  unsigned int tp_drops;
  unsigned int tp_freeze_q_cnt;
};
struct tpacket_rollover_stats {
  __aligned_u64 tp_all;
  __aligned_u64 tp_huge;
  __aligned_u64 tp_failed;
};
union tpacket_stats_u {
  struct tpacket_stats stats1;
  struct tpacket_stats_v3 stats3;
};
struct tpacket_auxdata {
  __u32 tp_status;
  __u32 tp_len;
  __u32 tp_snaplen;
  __u16 tp_mac;
  __u16 tp_net;
  __u16 tp_vlan_tci;
  __u16 tp_vlan_tpid;
};
#define TP_STATUS_KERNEL 0
#define TP_STATUS_USER (1 << 0)
#define TP_STATUS_COPY (1 << 1)
#define TP_STATUS_LOSING (1 << 2)
#define TP_STATUS_CSUMNOTREADY (1 << 3)
#define TP_STATUS_VLAN_VALID (1 << 4)
#define TP_STATUS_BLK_TMO (1 << 5)
#define TP_STATUS_VLAN_TPID_VALID (1 << 6)
#define TP_STATUS_CSUM_VALID (1 << 7)
#define TP_STATUS_GSO_TCP (1 << 8)
#define TP_STATUS_AVAILABLE 0
#define TP_STATUS_SEND_REQUEST (1 << 0)
#define TP_STATUS_SENDING (1 << 1)
#define TP_STATUS_WRONG_FORMAT (1 << 2)
#define TP_STATUS_TS_SOFTWARE (1 << 29)
#define TP_STATUS_TS_SYS_HARDWARE (1 << 30)
#define TP_STATUS_TS_RAW_HARDWARE (1U << 31)
#define TP_FT_REQ_FILL_RXHASH 0x1
struct tpacket_hdr {
  unsigned long tp_status;
  unsigned int tp_len;
  unsigned int tp_snaplen;
  unsigned short tp_mac;
  unsigned short tp_net;
  unsigned int tp_sec;
  unsigned int tp_usec;
};
#define TPACKET_ALIGNMENT 16
#define TPACKET_ALIGN(x) (((x) + TPACKET_ALIGNMENT - 1) & ~(TPACKET_ALIGNMENT - 1))
#define TPACKET_HDRLEN (TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + sizeof(struct sockaddr_ll))
struct tpacket2_hdr {
  __u32 tp_status;
  __u32 tp_len;
  __u32 tp_snaplen;
  __u16 tp_mac;
  __u16 tp_net;
  __u32 tp_sec;
  __u32 tp_nsec;
  __u16 tp_vlan_tci;
  __u16 tp_vlan_tpid;
  __u8 tp_padding[4];
};
struct tpacket_hdr_variant1 {
  __u32 tp_rxhash;
  __u32 tp_vlan_tci;
  __u16 tp_vlan_tpid;
  __u16 tp_padding;
};
struct tpacket3_hdr {
  __u32 tp_next_offset;
  __u32 tp_sec;
  __u32 tp_nsec;
  __u32 tp_snaplen;
  __u32 tp_len;
  __u32 tp_status;
  __u16 tp_mac;
  __u16 tp_net;
  union {
    struct tpacket_hdr_variant1 hv1;
  };
  __u8 tp_padding[8];
};
struct tpacket_bd_ts {
  unsigned int ts_sec;
  union {
    unsigned int ts_usec;
    unsigned int ts_nsec;
  };
};
struct tpacket_hdr_v1 {
  __u32 block_status;
  __u32 num_pkts;
  __u32 offset_to_first_pkt;
  __u32 blk_len;
  __aligned_u64 seq_num;
  struct tpacket_bd_ts ts_first_pkt, ts_last_pkt;
};
union tpacket_bd_header_u {
  struct tpacket_hdr_v1 bh1;
};
struct tpacket_block_desc {
  __u32 version;
  __u32 offset_to_priv;
  union tpacket_bd_header_u hdr;
};
#define TPACKET2_HDRLEN (TPACKET_ALIGN(sizeof(struct tpacket2_hdr)) + sizeof(struct sockaddr_ll))
#define TPACKET3_HDRLEN (TPACKET_ALIGN(sizeof(struct tpacket3_hdr)) + sizeof(struct sockaddr_ll))
enum tpacket_versions {
  TPACKET_V1,
  TPACKET_V2,
  TPACKET_V3
};
struct tpacket_req {
  unsigned int tp_block_size;
  unsigned int tp_block_nr;
  unsigned int tp_frame_size;
  unsigned int tp_frame_nr;
};
struct tpacket_req3 {
  unsigned int tp_block_size;
  unsigned int tp_block_nr;
  unsigned int tp_frame_size;
  unsigned int tp_frame_nr;
  unsigned int tp_retire_blk_tov;
  unsigned int tp_sizeof_priv;
  unsigned int tp_feature_req_word;
};
union tpacket_req_u {
  struct tpacket_req req;
  struct tpacket_req3 req3;
};
struct packet_mreq {
  int mr_ifindex;
  unsigned short mr_type;
  unsigned short mr_alen;
  unsigned char mr_address[8];
};
struct fanout_args {
#ifdef __LITTLE_ENDIAN_BITFIELD
  __u16 id;
  __u16 type_flags;
#else
  __u16 type_flags;
  __u16 id;
#endif
  __u32 max_num_members;
};
#define PACKET_MR_MULTICAST 0
#define PACKET_MR_PROMISC 1
#define PACKET_MR_ALLMULTI 2
#define PACKET_MR_UNICAST 3
#endif
```