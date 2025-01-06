Response:
My thought process to answer the request goes like this:

1. **Understand the Core Subject:** The file `inet_diag.h` defines data structures and constants for the "INET Diagnostics" interface in the Linux kernel. This immediately tells me it's about network socket information retrieval and manipulation at a low level. The "uapi" in the path confirms it's part of the user-space API, meaning it's what applications use to interact with kernel network functionalities.

2. **Break Down the Request:** I identify the key components of the request:
    * **Functionality:** What does this file *do*?
    * **Android Relation:** How does this relate to Android? Give examples.
    * **libc Function Details:**  Explain individual libc functions related to this (though the file itself *defines* structures, it doesn't *implement* functions). I need to infer relevant libc functions that *use* these structures.
    * **Dynamic Linker:** How does this connect to the dynamic linker?  What's the SO layout? Linking process?
    * **Logic Reasoning:**  Any specific logic or filtering defined by these structures?  Give examples.
    * **Common Errors:**  What mistakes might developers make using these structures?
    * **Android Framework/NDK Path:** How does a request reach this kernel interface?
    * **Frida Hooking:**  How can this be observed/modified with Frida?

3. **Analyze the File Content:** I go through the file structure by structure and constant by constant:
    * **Includes:** `#include <linux/types.h>` - Basic data types.
    * **Defines:** `TCPDIAG_GETSOCK`, `DCCPDIAG_GETSOCK`, `INET_DIAG_GETSOCK_MAX` -  Constants, likely for specifying diagnostic operations related to TCP and DCCP. The "GETSOCK" suggests retrieving socket information.
    * **`inet_diag_sockid`:**  Key structure representing a socket's identity (ports, addresses, interface, cookie). Important for matching sockets.
    * **`inet_diag_req` family:** Structures defining different types of requests for diagnostic information (`_req`, `_req_v2`, `_req_raw`). They contain the `inet_diag_sockid` for identifying the target socket and flags for filtering (states).
    * **Enums for Request Types:** `INET_DIAG_REQ_NONE`, `INET_DIAG_REQ_BYTECODE`, etc. - Indicate different ways to filter or request information. Bytecode suggests powerful filtering capabilities.
    * **`inet_diag_bc_op` and related:** Structures for defining bytecode filters. This is advanced filtering.
    * **`inet_diag_hostcond`, `inet_diag_markcond`:** More specialized filtering conditions (by host, by packet mark).
    * **`inet_diag_msg`:** The main structure containing the diagnostic information returned about a socket.
    * **Enums for Message Types:** `INET_DIAG_NONE`, `INET_DIAG_MEMINFO`, etc. - Flags indicating what kind of extra information is included in the `inet_diag_msg`.
    * **`inet_diag_meminfo`, `inet_diag_sockopt`, `tcpvegas_info`, `tcp_dctcp_info`, `tcp_bbr_info`:** Structures for holding specific socket details (memory usage, options, TCP congestion control info).
    * **`union tcp_cc_info`:** A union to hold different TCP congestion control information.

4. **Connect to the Request Points:**  Now I connect my understanding of the file to the specific points in the request:

    * **Functionality:** I summarize that it defines structures for querying and retrieving information about network sockets in the Linux kernel. This is used for debugging, monitoring, and network management.

    * **Android Relation:** I think about how Android uses networking. Apps use sockets. The system needs to manage these. I come up with examples like `dumpsys netstats`, `lsof`, and VPN apps, explaining how they might use this information.

    * **libc Function Details:**  Although the file doesn't define functions, I know it's used by system calls. The key system call is likely `socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)`. I explain how this system call works in general terms (sending a request and receiving a response). Since the request involves filtering, I mention `bind()` and `sendto()`.

    * **Dynamic Linker:** This is a header file. It doesn't contain executable code. Therefore, it's not directly linked by the dynamic linker. I explain this and clarify the role of header files in compilation. I emphasize that the *code* using these structures (in libc or elsewhere) *is* linked.

    * **Logic Reasoning:** I consider how the filtering works. The request structures allow specifying criteria like source/destination addresses, ports, and states. The bytecode option allows complex filtering logic. I create an example of filtering for TCP connections on a specific port.

    * **Common Errors:** I think about mistakes developers might make: incorrect structure initialization, byte order issues (due to `__be16` and `__be32`), incorrect protocol family, and not handling the variable size of some structures correctly.

    * **Android Framework/NDK Path:** I trace a potential path: an app makes a network request -> framework interacts with the network stack (possibly via `NetworkStatsService` or `ConnectivityService`) -> this eventually leads to kernel calls using the `NETLINK_INET_DIAG` interface and these structures. I also mention the NDK and how native apps can directly use socket APIs.

    * **Frida Hooking:** I demonstrate how to hook a system call like `sendto` and inspect the data being sent, focusing on the `inet_diag_req` structure. This shows how to observe the parameters being passed to the kernel.

5. **Structure the Output:** I organize the information logically, using headings and bullet points for clarity. I provide clear explanations for each part of the request and ensure the language is accessible. I use code blocks for the Frida example to make it easier to read. I double-check that I've addressed all the points in the original request.

By following these steps, I can provide a comprehensive and informative answer that addresses all aspects of the user's request. The key is to understand the core functionality of the file and then connect that understanding to the specifics of the Android environment and the request's individual components.
## 对 bionic/libc/kernel/uapi/linux/inet_diag.h 的功能分析

这个头文件 `inet_diag.h` 定义了用户空间程序与 Linux 内核中关于 INET（互联网协议族）套接字诊断接口交互所需的数据结构和常量。 它的主要功能是**提供一种机制，允许用户空间的程序查询和获取关于网络套接字的详细信息**。

**具体功能列举：**

1. **定义请求结构 (Request Structures):**
   - `inet_diag_req`, `inet_diag_req_v2`, `inet_diag_req_raw`: 这些结构体定义了用户空间程序向内核发送请求，以获取特定套接字信息时需要填充的数据。它们包含了套接字标识信息（如源/目的端口、地址）、状态过滤条件等。
   - 这些结构体允许用户按协议族、状态等条件过滤要查询的套接字。

2. **定义套接字标识结构 (Socket Identification Structure):**
   - `inet_diag_sockid`:  这是标识一个特定网络套接字的关键结构。它包含了源端口 (`idiag_sport`)、目的端口 (`idiag_dport`)、源地址 (`idiag_src`)、目的地址 (`idiag_dst`)、网络接口索引 (`idiag_if`) 和一个用于匹配的 Cookie (`idiag_cookie`)。
   -  `INET_DIAG_NOCOOKIE`: 定义了一个特殊值，表示不使用 Cookie 进行匹配。

3. **定义请求扩展 (Request Extensions):**
   - `idiag_ext` 字段用于指示请求中是否包含额外的过滤或控制信息，例如字节码过滤器。
   - `INET_DIAG_REQ_NONE`, `INET_DIAG_REQ_BYTECODE`, `INET_DIAG_REQ_SK_BPF_STORAGES`, `INET_DIAG_REQ_PROTOCOL`:  枚举类型定义了不同的请求扩展类型，允许更精细的查询控制。

4. **定义字节码过滤结构 (Bytecode Filtering Structures):**
   - `inet_diag_bc_op`:  定义了用于套接字过滤的字节码操作。这允许用户编写更复杂的过滤逻辑，而不仅仅依赖于简单的状态匹配。
   - 一系列 `INET_DIAG_BC_*` 常量定义了可用的字节码操作码，例如跳转、比较（大于等于、小于等于、等于）等。
   - `inet_diag_hostcond`, `inet_diag_markcond`:  定义了更具体的基于主机和数据包标记的过滤条件。

5. **定义消息结构 (Message Structure):**
   - `inet_diag_msg`: 这是内核返回给用户空间程序的主要数据结构，包含了关于匹配到的套接字的详细信息。
   - 它包括套接字的基本信息（协议族、状态）、定时器信息、重传次数、套接字标识 (`id`)、过期时间、接收/发送队列长度、用户ID (`idiag_uid`) 和 inode 号 (`idiag_inode`)。

6. **定义消息属性 (Message Attributes):**
   - 一系列 `INET_DIAG_*` 常量定义了可以在返回的 `inet_diag_msg` 中包含的额外属性信息。
   - 例如：`INET_DIAG_MEMINFO`（内存信息）、`INET_DIAG_INFO`（通用信息）、`INET_DIAG_VEGASINFO`（TCP Vegas 信息）、`INET_DIAG_CONG`（拥塞控制算法）、`INET_DIAG_MARK`（数据包标记）等等。
   - 这些常量允许用户请求更详细的套接字状态和性能数据。

7. **定义附加信息结构 (Additional Information Structures):**
   - `inet_diag_meminfo`: 包含套接字的内存使用情况。
   - `inet_diag_sockopt`:  指示套接字选项的设置。
   - `tcpvegas_info`, `tcp_dctcp_info`, `tcp_bbr_info`:  包含特定 TCP 拥塞控制算法的参数。
   - `union tcp_cc_info`:  一个联合体，用于存储不同 TCP 拥塞控制算法的信息。

8. **定义用户层协议信息 (ULP Information):**
   - `INET_ULP_INFO_*` 常量和相关的可能结构体（虽然在这个文件中没有明确定义结构体）用于请求关于套接字上层协议（如 TLS、MPTCP）的信息。

**与 Android 功能的关系及举例说明：**

这个头文件是 Android 系统底层网络功能的重要组成部分。Android 依赖于 Linux 内核的网络栈，因此需要通过这些接口来监控和管理网络连接。

**举例说明：**

* **`dumpsys netstats` 命令:**  Android 的 `dumpsys` 工具可以用来查看网络统计信息。 `dumpsys netstats` 内部很可能使用了 `NETLINK_INET_DIAG` 接口来获取系统中活跃的网络连接信息，包括 TCP 和 UDP 连接，并统计其流量数据。它会利用这里定义的结构体来构造请求和解析内核返回的数据。

* **`lsof` 命令的 Android 版本:**  类似于 Linux 的 `lsof` 命令，Android 上也有类似的工具或者系统组件可以列出打开的文件描述符，包括网络套接字。它也可能使用 `NETLINK_INET_DIAG` 接口来获取套接字信息，并将其关联到进程。

* **VPN 应用:**  VPN 应用需要监控和管理网络连接，并可能需要获取连接的状态信息。它们可以使用 `NETLINK_INET_DIAG` 接口来获取当前活动的网络连接，以便确定哪些连接需要通过 VPN 隧道传输。

* **网络监控工具:**  Android 平台上的网络监控应用，例如查看网络速度、连接列表的应用，很可能在底层使用了这个接口来获取实时的网络连接信息。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身 **不包含任何 libc 函数的实现**。它仅仅定义了数据结构和常量。 用户空间的程序需要使用 Linux 提供的 **Netlink 套接字**机制，通过系统调用与内核进行通信，才能利用这些定义。

以下是一些 **可能涉及的 libc 函数** 以及它们如何与这些数据结构交互：

1. **`socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)`:**
   - 功能：创建一个 Netlink 套接字，用于与内核的 INET 诊断模块通信。
   - 实现：`socket` 系统调用会请求内核创建一个新的套接字文件描述符，并将其关联到指定的协议族 (`AF_NETLINK`) 和 Netlink 协议号 (`NETLINK_INET_DIAG`)。

2. **`bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr))`:**
   - 功能：将 Netlink 套接字绑定到一个本地地址（通常是进程 ID）。
   - 实现：对于 Netlink 套接字，`bind` 通常用于指定接收消息的进程 ID。内核会根据绑定的 ID 将消息路由到相应的用户空间进程。

3. **`sendto(sockfd, (const void *)&req, sizeof(req), 0, (const struct sockaddr *)&kernel_addr, sizeof(kernel_addr))`:**
   - 功能：向内核发送请求消息，请求套接字诊断信息。
   - 实现：`sendto` 系统调用会将用户空间程序填充的 `inet_diag_req` 或其变体结构体，通过 Netlink 套接字发送到内核的 INET 诊断模块。`kernel_addr` 通常指向一个通用的内核 Netlink 地址。

4. **`recvfrom(sockfd, (void *)&msg, sizeof(msg), 0, (struct sockaddr *)&peer_addr, &peer_addr_len)`:**
   - 功能：接收内核返回的包含套接字诊断信息的消息。
   - 实现：内核的 INET 诊断模块在处理完请求后，会将包含 `inet_diag_msg` 结构体的消息通过 Netlink 套接字发送回用户空间程序。`recvfrom` 系统调用用于接收这些消息。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件定义的是内核 UAPI (User-space API)，它在编译时会被包含到用户空间程序的代码中。 **它本身不涉及动态链接器 (dynamic linker)**。

动态链接器负责加载和链接共享库 (`.so` 文件)。  `inet_diag.h` 中定义的数据结构会被编译到使用了它的用户空间程序中，例如 `libc.so` 或其他与网络相关的库。

**SO 布局样本 (假设某个使用到这些结构的库 `libnetutil.so`)：**

```
libnetutil.so:
    .text          # 代码段
        ... 使用 inet_diag_req 和 inet_diag_msg 的函数 ...
    .rodata        # 只读数据段
        ... 可能包含与网络诊断相关的常量 ...
    .data          # 可读写数据段
        ... 可能包含一些全局变量 ...
    .bss           # 未初始化数据段
        ...
    .dynamic       # 动态链接信息
        NEEDED      libc.so.6
        ...
    .symtab        # 符号表
        ... 定义和引用的符号 ...
    .strtab        # 字符串表
        ... 符号名称等字符串 ...
```

**链接的处理过程：**

1. **编译时：** 当编译 `libnetutil.so` 的源文件时，如果包含了 `inet_diag.h`，编译器会使用这些结构体的定义来生成代码。
2. **链接时：** 静态链接器会将编译后的目标文件链接成共享库。此时，`inet_diag.h` 的内容已经融入到 `libnetutil.so` 的代码和数据段中。
3. **运行时：** 当一个应用程序（例如，一个使用网络功能的 Android 应用）需要使用 `libnetutil.so` 中的功能时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责将 `libnetutil.so` 加载到进程的地址空间，并解析其依赖关系，例如 `libc.so.6`。
4. **符号解析：** 如果 `libnetutil.so` 中有函数使用了 `inet_diag_req` 等结构体，并且这些结构体的定义来自于 `libc.so` 提供的头文件，那么动态链接器需要确保这些符号的引用能够正确地指向 `libc.so` 中对应的定义（虽然实际上 `inet_diag.h` 是直接包含的，通常不会作为独立的符号链接）。

**逻辑推理的假设输入与输出：**

**假设输入：**  用户空间程序想要获取所有 TCP 状态为 `ESTABLISHED` 的连接信息。

1. **构建 `inet_diag_req` 结构体：**
   - `idiag_family` = `AF_INET` (或 `AF_INET6`，取决于想要查询的协议族)
   - `idiag_protocol` = `IPPROTO_TCP`
   - `idiag_states` = `TCP_ESTABLISHED` (这是一个内核定义的常量，表示 TCP 连接已建立状态)
   - `id` 中的其他字段可以设置为 0 或通配符，表示不针对特定的 IP 地址或端口进行过滤。
   - `idiag_ext` 可以设置为 0，表示不需要额外的扩展。

2. **发送 Netlink 消息：**  使用 `sendto` 将填充好的 `inet_diag_req` 结构体发送给内核的 INET 诊断模块。

**预期输出：**

内核会返回一系列 Netlink 消息，每个消息包含一个 `inet_diag_msg` 结构体，对应一个满足条件的 TCP 连接。 每个 `inet_diag_msg` 结构体将包含：

- `idiag_family`: `AF_INET` 或 `AF_INET6`
- `idiag_state`:  `TCP_ESTABLISHED`
- `id`:  包含该连接的源/目的 IP 地址、端口等信息。
- 其他字段，例如队列长度、UID、inode 等。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **字节序错误：**  `inet_diag_sockid` 中的端口和地址字段使用网络字节序 (`__be16`, `__be32`)。 用户空间程序需要使用 `htons()` 和 `htonl()` 函数将本地字节序转换为网络字节序，反之使用 `ntohs()` 和 `ntohl()`。  如果字节序处理错误，内核可能无法正确匹配套接字。

   ```c
   struct inet_diag_req req;
   memset(&req, 0, sizeof(req));
   req.idiag_family = AF_INET;
   req.id.idiag_sport = 80; // 错误：应该使用 htons(80)
   ```

2. **未正确初始化结构体：**  忘记将结构体清零，导致包含垃圾数据，可能导致内核返回意外的结果或错误。

   ```c
   struct inet_diag_req req; // 未初始化
   req.idiag_family = AF_INET;
   // ... 其他字段可能包含随机值 ...
   ```

3. **使用错误的协议族或协议号：**  如果想要查询 TCP 连接，但设置了错误的 `idiag_family` 或未设置 `idiag_protocol` 为 `IPPROTO_TCP`，将无法获取到预期的结果。

4. **内核版本兼容性问题：**  某些 `INET_DIAG_*` 常量或结构体字段可能只在特定的内核版本中存在。  用户空间程序需要注意兼容性问题。

5. **权限问题：**  访问某些套接字信息可能需要特定的权限（例如，root 权限）。

6. **错误地假设返回的消息数量：**  一个请求可能会返回多个 `inet_diag_msg` 消息。用户空间程序需要循环接收，直到没有更多消息为止。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `inet_diag.h` 的路径示例：**

1. **应用层:**  一个 Android 应用可能需要获取网络连接信息（例如，一个网络监控应用）。
2. **Framework API:** 应用调用 Android Framework 提供的 API，例如 `ConnectivityManager` 或 `NetworkStatsManager`。
3. **System Services:** Framework API 的实现通常会调用相应的系统服务，例如 `ConnectivityService` 或 `NetworkStatsService`。
4. **Native Code:** 这些系统服务通常会涉及到 Native 代码的调用（通过 JNI）。
5. **Netlink Socket Interaction:** Native 代码可能会创建 Netlink 套接字，并使用 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等系统调用与内核的 `NETLINK_INET_DIAG` 接口通信。
6. **Kernel Interaction:** 内核接收到 Netlink 消息后，INET 诊断模块会根据请求中的信息查找匹配的套接字，并返回包含 `inet_diag_msg` 结构体的响应。

**NDK 到达 `inet_diag.h` 的路径示例：**

1. **NDK 应用:** 一个使用 NDK 开发的 Native 应用可以直接调用 Linux 系统调用。
2. **System Calls:**  NDK 应用可以直接使用 `socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)` 创建 Netlink 套接字，并使用 `sendto()` 发送填充好的 `inet_diag_req` 结构体。
3. **Kernel Interaction:**  与 Framework 路径类似，内核的 INET 诊断模块处理请求并返回响应。

**Frida Hook 示例：**

以下是一个使用 Frida Hook `sendto` 系统调用的示例，用于观察发送给内核的 `inet_diag_req` 结构体的内容：

```javascript
// frida hook 脚本

Interceptor.attach(Module.findExportByName(null, "sendto"), {
  onEnter: function (args) {
    const sockfd = args[0].toInt32();
    const buf = args[1];
    const len = args[2].toInt32();
    const flags = args[3].toInt32();
    const dest_addr = args[4];
    const addrlen = args[5].toInt32();

    // 检查是否是 Netlink 套接字
    const sockaddr_nl = dest_addr.readByteArray(addrlen);
    const family = sockaddr_nl.charCodeAt(0); // 假设 sockaddr_nl 结构体第一个字节是协议族

    if (family === 16) { // AF_NETLINK 的值通常是 16
      console.log("sendto called for AF_NETLINK socket:", sockfd);

      // 尝试解析 inet_diag_req 结构体
      if (len >= 8) { // 假设 inet_diag_req 至少有 8 字节
        const idiag_family = buf.readU8();
        const idiag_src_len = buf.readU8();
        const idiag_dst_len = buf.readU8();
        const idiag_ext = buf.readU8();

        console.log("  idiag_family:", idiag_family);
        console.log("  idiag_src_len:", idiag_src_len);
        console.log("  idiag_dst_len:", idiag_dst_len);
        console.log("  idiag_ext:", idiag_ext);

        // 可以继续解析后续的字段，例如 inet_diag_sockid
        if (len >= 24) { // 假设 inet_diag_req 至少有 24 字节包含 inet_diag_sockid
          const idiag_sport = buf.add(4).readU16();
          const idiag_dport = buf.add(6).readU16();
          console.log("  idiag_sport:", idiag_sport);
          console.log("  idiag_dport:", idiag_dport);
          // ... 继续解析其他字段 ...
        }
      }
    }
  },
});
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_inet_diag.js`）。
2. 使用 Frida 连接到目标 Android 进程：`frida -U -f <package_name> -l hook_inet_diag.js --no-pause` (替换 `<package_name>` 为目标应用的包名)。
3. 当目标应用尝试通过 Netlink 套接字发送消息时，Frida 会拦截 `sendto` 调用，并打印出相关的信息，包括 `inet_diag_req` 结构体的部分内容。

这个 Frida 示例可以帮助开发者理解 Android Framework 或 NDK 应用是如何构建和发送 Netlink 消息，从而与内核的 INET 诊断接口交互的。通过观察 `inet_diag_req` 结构体的内容，可以了解应用请求了哪些信息，以及使用了哪些过滤条件。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/inet_diag.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_INET_DIAG_H_
#define _UAPI_INET_DIAG_H_
#include <linux/types.h>
#define TCPDIAG_GETSOCK 18
#define DCCPDIAG_GETSOCK 19
#define INET_DIAG_GETSOCK_MAX 24
struct inet_diag_sockid {
  __be16 idiag_sport;
  __be16 idiag_dport;
  __be32 idiag_src[4];
  __be32 idiag_dst[4];
  __u32 idiag_if;
  __u32 idiag_cookie[2];
#define INET_DIAG_NOCOOKIE (~0U)
};
struct inet_diag_req {
  __u8 idiag_family;
  __u8 idiag_src_len;
  __u8 idiag_dst_len;
  __u8 idiag_ext;
  struct inet_diag_sockid id;
  __u32 idiag_states;
  __u32 idiag_dbs;
};
struct inet_diag_req_v2 {
  __u8 sdiag_family;
  __u8 sdiag_protocol;
  __u8 idiag_ext;
  __u8 pad;
  __u32 idiag_states;
  struct inet_diag_sockid id;
};
struct inet_diag_req_raw {
  __u8 sdiag_family;
  __u8 sdiag_protocol;
  __u8 idiag_ext;
  __u8 sdiag_raw_protocol;
  __u32 idiag_states;
  struct inet_diag_sockid id;
};
enum {
  INET_DIAG_REQ_NONE,
  INET_DIAG_REQ_BYTECODE,
  INET_DIAG_REQ_SK_BPF_STORAGES,
  INET_DIAG_REQ_PROTOCOL,
  __INET_DIAG_REQ_MAX,
};
#define INET_DIAG_REQ_MAX (__INET_DIAG_REQ_MAX - 1)
struct inet_diag_bc_op {
  unsigned char code;
  unsigned char yes;
  unsigned short no;
};
enum {
  INET_DIAG_BC_NOP,
  INET_DIAG_BC_JMP,
  INET_DIAG_BC_S_GE,
  INET_DIAG_BC_S_LE,
  INET_DIAG_BC_D_GE,
  INET_DIAG_BC_D_LE,
  INET_DIAG_BC_AUTO,
  INET_DIAG_BC_S_COND,
  INET_DIAG_BC_D_COND,
  INET_DIAG_BC_DEV_COND,
  INET_DIAG_BC_MARK_COND,
  INET_DIAG_BC_S_EQ,
  INET_DIAG_BC_D_EQ,
  INET_DIAG_BC_CGROUP_COND,
};
struct inet_diag_hostcond {
  __u8 family;
  __u8 prefix_len;
  int port;
  __be32 addr[];
};
struct inet_diag_markcond {
  __u32 mark;
  __u32 mask;
};
struct inet_diag_msg {
  __u8 idiag_family;
  __u8 idiag_state;
  __u8 idiag_timer;
  __u8 idiag_retrans;
  struct inet_diag_sockid id;
  __u32 idiag_expires;
  __u32 idiag_rqueue;
  __u32 idiag_wqueue;
  __u32 idiag_uid;
  __u32 idiag_inode;
};
enum {
  INET_DIAG_NONE,
  INET_DIAG_MEMINFO,
  INET_DIAG_INFO,
  INET_DIAG_VEGASINFO,
  INET_DIAG_CONG,
  INET_DIAG_TOS,
  INET_DIAG_TCLASS,
  INET_DIAG_SKMEMINFO,
  INET_DIAG_SHUTDOWN,
  INET_DIAG_DCTCPINFO,
  INET_DIAG_PROTOCOL,
  INET_DIAG_SKV6ONLY,
  INET_DIAG_LOCALS,
  INET_DIAG_PEERS,
  INET_DIAG_PAD,
  INET_DIAG_MARK,
  INET_DIAG_BBRINFO,
  INET_DIAG_CLASS_ID,
  INET_DIAG_MD5SIG,
  INET_DIAG_ULP_INFO,
  INET_DIAG_SK_BPF_STORAGES,
  INET_DIAG_CGROUP_ID,
  INET_DIAG_SOCKOPT,
  __INET_DIAG_MAX,
};
#define INET_DIAG_MAX (__INET_DIAG_MAX - 1)
enum {
  INET_ULP_INFO_UNSPEC,
  INET_ULP_INFO_NAME,
  INET_ULP_INFO_TLS,
  INET_ULP_INFO_MPTCP,
  __INET_ULP_INFO_MAX,
};
#define INET_ULP_INFO_MAX (__INET_ULP_INFO_MAX - 1)
struct inet_diag_meminfo {
  __u32 idiag_rmem;
  __u32 idiag_wmem;
  __u32 idiag_fmem;
  __u32 idiag_tmem;
};
struct inet_diag_sockopt {
  __u8 recverr : 1, is_icsk : 1, freebind : 1, hdrincl : 1, mc_loop : 1, transparent : 1, mc_all : 1, nodefrag : 1;
  __u8 bind_address_no_port : 1, recverr_rfc4884 : 1, defer_connect : 1, unused : 5;
};
struct tcpvegas_info {
  __u32 tcpv_enabled;
  __u32 tcpv_rttcnt;
  __u32 tcpv_rtt;
  __u32 tcpv_minrtt;
};
struct tcp_dctcp_info {
  __u16 dctcp_enabled;
  __u16 dctcp_ce_state;
  __u32 dctcp_alpha;
  __u32 dctcp_ab_ecn;
  __u32 dctcp_ab_tot;
};
struct tcp_bbr_info {
  __u32 bbr_bw_lo;
  __u32 bbr_bw_hi;
  __u32 bbr_min_rtt;
  __u32 bbr_pacing_gain;
  __u32 bbr_cwnd_gain;
};
union tcp_cc_info {
  struct tcpvegas_info vegas;
  struct tcp_dctcp_info dctcp;
  struct tcp_bbr_info bbr;
};
#endif

"""

```