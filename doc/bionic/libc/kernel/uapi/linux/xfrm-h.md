Response:
Let's break down the thought process for analyzing the provided C header file (`xfrm.h`) within the context of Android's Bionic library.

**1. Initial Understanding and Context:**

* **File Location:** The path `bionic/libc/kernel/uapi/linux/xfrm.handroid` immediately tells us this is a header file related to the Linux kernel's XFRM subsystem, specifically tailored for Android (hence the `.handroid` suffix). The `uapi` part signifies it's intended for user-space programs.
* **Bionic's Role:** Bionic is Android's C library, providing the standard C library functions and system call wrappers. This file defines data structures and constants used when interacting with the kernel's XFRM functionality.
* **Auto-generated:** The comment at the top is crucial. It means we shouldn't try to *understand the implementation details* within this file itself. This file is a *definition* of the interface to the kernel. The *implementation* resides within the Linux kernel.

**2. Identifying Core Functionality (Based on Struct Names and Definitions):**

* **`xfrm_address_t`:**  Represents an IP address (IPv4 or IPv6). This is fundamental for networking.
* **`xfrm_id`:**  Identifies a Security Association (SA), the core concept in IPsec. It includes destination address, Security Parameter Index (SPI), and protocol.
* **`xfrm_sec_ctx`:**  Security context information, likely used for Mandatory Access Control (MAC) like SELinux.
* **`xfrm_selector`:**  Defines the traffic that an IPsec policy applies to (source/destination addresses, ports, protocol, etc.).
* **`xfrm_lifetime_cfg` and `xfrm_lifetime_cur`:**  Manage the lifetime of SAs (e.g., expiration times, byte/packet limits).
* **`xfrm_replay_state` and `xfrm_replay_state_esn`:**  Mechanisms to prevent replay attacks in IPsec.
* **`xfrm_algo`, `xfrm_algo_auth`, `xfrm_algo_aead`:**  Define the cryptographic algorithms used for encryption, authentication, and authenticated encryption.
* **`xfrm_stats`:**  Keeps track of SA statistics (replay failures, integrity failures, etc.).
* **`XFRM_POLICY_TYPE_*`, `XFRM_POLICY_IN/OUT/FWD`:**  Relate to IPsec policies, defining what security actions to take for specific traffic.
* **`xfrm_sa_dir`:**  Indicates the direction of the Security Association (inbound or outbound).
* **`XFRM_MODE_*`:**  Specifies the IPsec mode (transport, tunnel, etc.).
* **`XFRM_MSG_*`:**  Defines the Netlink message types used to communicate with the XFRM kernel module from user space. This is the primary interface for configuring and managing IPsec.
* **`xfrm_user_*` structures:**  These are user-space representations of kernel data structures, often used in Netlink messages.

**3. Connecting to Android Functionality:**

* **IPsec VPN:**  The most direct connection. Android's VPN capabilities often rely on IPsec, and XFRM is the underlying kernel subsystem.
* **Enterprise Security:**  Features like managed profiles and work profiles might leverage IPsec for securing corporate data.
* **Network Security:**  Even if not directly user-configurable, Android's internal network stack might use IPsec in certain scenarios.
* **SELinux Integration:** The `xfrm_sec_ctx` and associated constants (`XFRM_SC_DOI_LSM`, `XFRM_SC_ALG_SELINUX`) strongly suggest integration with Android's SELinux implementation for finer-grained security policies on IPsec.

**4. Addressing Specific Questions in the Prompt:**

* **Function Listing:**  Simply list the identified structures, enums, and defines with a brief description of their purpose.
* **Android Relationship & Examples:**  Focus on the IPsec VPN use case as it's the most visible. Explain how these structures are used to configure VPN connections (addresses, encryption, authentication, policies).
* **libc Function Implementation:** Emphasize that *this header file doesn't contain implementation*. It's a declaration. The actual libc functions interacting with XFRM will use system calls (like `socket`, `bind`, `sendto`, `recvfrom` with the `AF_NETLINK` family) to communicate with the kernel. *No specific libc functions are defined here.*
* **Dynamic Linker:**  This header file doesn't directly involve the dynamic linker. It defines data structures. The dynamic linker is responsible for loading shared libraries (`.so` files). However, libraries that *use* the XFRM functionality will be linked. Provide a sample `.so` layout and explain the linking process (symbol resolution).
* **Logical Reasoning (Assumptions/Outputs):** For example, if you assume a user is setting up an IPsec tunnel, you can illustrate how the `xfrm_userpolicy_info`, `xfrm_usersa_info`, and algorithm structures would be populated with relevant data.
* **User Errors:**  Common mistakes involve incorrect IP addresses, mismatched keys, wrong protocol selections, or misconfigured policies. Give concrete examples.
* **Framework/NDK to XFRM:** Trace the path from a VPN app (using Java APIs in the framework or C/C++ APIs in the NDK) down to the system calls that ultimately interact with the XFRM kernel module.
* **Frida Hooking:** Provide examples of hooking system calls related to Netlink sockets or functions within libraries that use XFRM (if identifiable).

**5. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use bullet points for lists of functions and concepts. Provide code snippets (even if just illustrative for Frida) to make the explanation more concrete.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on individual function implementations.
* **Correction:** Realize this is a header file, so shift focus to the *definitions* and how they relate to the larger system.
* **Initial thought:** Try to detail every single structure member.
* **Correction:**  Focus on the most important members and the overall purpose of each structure.
* **Initial thought:**  Overcomplicate the dynamic linker explanation.
* **Correction:** Keep it concise, explaining the basic concept of linking and how libraries using XFRM would be involved.

By following this structured approach and continually refining the understanding based on the context of the file, we can arrive at a comprehensive and accurate answer to the prompt.
这是一个位于 `bionic/libc/kernel/uapi/linux/xfrm.handroid` 的源代码文件，是 Android Bionic C 库中关于 Linux 内核 XFRM (IPsec 转换框架) 子系统的用户空间 API 头文件。这个头文件定义了用于与内核 XFRM 模块交互的数据结构和常量。

**它的功能：**

这个头文件定义了用户空间程序与 Linux 内核中 XFRM 子系统进行交互的接口。XFRM 子系统主要负责 IPsec (Internet Protocol Security) 协议的实现，包括安全策略 (Security Policy, SP) 和安全关联 (Security Association, SA) 的管理。

具体来说，它定义了：

1. **数据结构：**
   - `xfrm_address_t`: 表示 IPv4 或 IPv6 地址。
   - `xfrm_id`: 用于唯一标识一个安全关联 (SA)，包含目标地址、SPI (安全参数索引) 和协议。
   - `xfrm_sec_ctx`: 用于表示安全上下文，与 SELinux 等安全机制集成。
   - `xfrm_selector`: 定义了 IPsec 策略作用的网络流量的选择器，包括源地址、目标地址、端口、协议等。
   - `xfrm_lifetime_cfg` 和 `xfrm_lifetime_cur`: 用于配置和表示 SA 的生命周期限制（字节数、包数、时间）。
   - `xfrm_replay_state` 和 `xfrm_replay_state_esn`: 用于防止重放攻击的状态信息。
   - `xfrm_algo`, `xfrm_algo_auth`, `xfrm_algo_aead`: 定义了加密、认证和认证加密算法的相关信息。
   - `xfrm_stats`: 记录 SA 的统计信息，如重放攻击次数、完整性校验失败次数等。
   - `xfrm_user_*` 系列结构体：用于用户空间程序通过 Netlink 套接字与内核交换 XFRM 信息的结构体，例如创建、删除、查询 SA 和策略。

2. **枚举类型：**
   - `XFRM_POLICY_TYPE_*`: 定义了策略的类型（主策略、子策略）。
   - `XFRM_POLICY_IN/OUT/FWD`: 定义了策略的应用方向（入站、出站、转发）。
   - `xfrm_sa_dir`: 定义了 SA 的方向（入站、出站）。
   - `XFRM_MODE_*`: 定义了 IPsec 的模式（传输模式、隧道模式等）。
   - `XFRM_MSG_*`: 定义了用户空间与内核通信的 Netlink 消息类型，用于执行各种 XFRM 操作。
   - `xfrm_attr_type_t`: 定义了 Netlink 消息中属性的类型。

3. **宏定义：**
   - 定义了一些常量，例如生命周期的最大值 `XFRM_INF`，以及一些标志位。

**与 Android 功能的关系及举例：**

这个头文件直接关联到 Android 系统中 IPsec VPN 的实现。Android 系统可以使用 IPsec 协议来建立安全的 VPN 连接。

**举例说明：**

当 Android 设备连接到 IPsec VPN 时，Android 的 VPN 客户端（通常是 framework 层或一个 VPN 应用）会使用这个头文件中定义的数据结构，通过 Netlink 接口与内核的 XFRM 模块进行通信，完成以下操作：

1. **创建安全策略 (Security Policy, SP):** 使用 `xfrm_userpolicy_info` 结构体定义哪些流量需要受到 IPsec 的保护，例如指定源地址、目标地址、端口和协议。通过 `XFRM_MSG_NEWPOLICY` 消息发送给内核。
2. **创建安全关联 (Security Association, SA):** 使用 `xfrm_usersa_info` 结构体定义加密和认证算法 (`xfrm_algo` 等结构体)，以及密钥、SPI 等信息。通过 `XFRM_MSG_NEWSA` 消息发送给内核。
3. **查询 SA 和策略状态：** 使用 `XFRM_MSG_GETSA` 和 `XFRM_MSG_GETPOLICY` 消息获取当前的 SA 和策略信息。

**详细解释每一个 libc 函数的功能是如何实现的：**

**重要提示：** 这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了数据结构和常量。实际与内核 XFRM 交互的 libc 函数通常是网络相关的系统调用，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()`，配合 `AF_NETLINK` 地址族使用。

**例如：**

* **创建 Netlink 套接字：**
  ```c
  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
  ```
  这里 `NETLINK_XFRM` 是一个宏，通常定义在 `<linux/netlink.h>` 中，用于指定 Netlink 套接字的目标是 XFRM 模块。

* **发送 Netlink 消息：**
  ```c
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  // ... 填充 Netlink 消息头和 XFRM 相关的结构体 (例如 xfrm_userpolicy_info)

  sendto(sock, nl_msg, nl_msg_len, 0, (struct sockaddr*)&sa, sizeof(sa));
  ```

* **接收 Netlink 消息：**
  ```c
  recvfrom(sock, buffer, buffer_size, 0, (struct sockaddr*)&sa, &addr_len);
  // ... 解析接收到的 Netlink 消息
  ```

这些系统调用的实现位于 Bionic 库内部，它们会最终调用内核提供的系统调用接口，将请求传递给内核的 XFRM 模块。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身也不直接涉及 dynamic linker。Dynamic linker 的作用是加载共享库 (`.so` 文件) 并解析符号。

**假设有一个用户空间的 VPN 客户端程序 `vpn_client`，它使用了依赖于 XFRM 功能的库 `libipsec.so`。**

**`libipsec.so` 布局样本：**

```
libipsec.so:
    .text         # 代码段，包含实现 IPsec 相关逻辑的函数
    .data         # 数据段，包含全局变量
    .rodata       # 只读数据段
    .bss          # 未初始化数据段
    .dynamic      # 动态链接信息
    .symtab       # 符号表
    .strtab       # 字符串表
    .rel.dyn      # 动态重定位表
    .rel.plt      # PLT (Procedure Linkage Table) 重定位表
```

**链接的处理过程：**

1. **编译时链接：** 当编译 `vpn_client` 时，编译器会记录它需要使用 `libipsec.so` 中提供的符号（函数或变量）。这些符号可能对应于封装了与 XFRM 交互逻辑的函数。
2. **运行时加载：** 当 `vpn_client` 启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载 `vpn_client` 及其依赖的共享库 `libipsec.so`。
3. **符号解析：** Dynamic linker 会解析 `vpn_client` 中对 `libipsec.so` 中符号的引用，将 `vpn_client` 中的调用地址指向 `libipsec.so` 中对应符号的实际地址。
4. **调用 XFRM 功能：** `libipsec.so` 内部的函数会使用前面提到的 `socket()`, `sendto()`, `recvfrom()` 等系统调用，并包含这个头文件中定义的数据结构，来与内核的 XFRM 模块进行通信。

**如果做了逻辑推理，请给出假设输入与输出：**

假设用户空间程序想要创建一个出站的 ESP (Encapsulating Security Payload) 安全关联。

**假设输入（用户空间程序构建的数据结构）：**

```c
struct xfrm_usersa_info sa_info;
memset(&sa_info, 0, sizeof(sa_info));

// 设置 SA 的基本信息
sa_info.family = AF_INET; // IPv4
sa_info.mode = XFRM_MODE_TRANSPORT;
sa_info.id.proto = IPPROTO_ESP;
sa_info.id.spi = htonl(0x12345678); // 假设的 SPI
inet_pton(AF_INET, "203.0.113.10", &sa_info.id.daddr); // 目标地址
inet_pton(AF_INET, "192.0.2.10", &sa_info.saddr);   // 源地址

// 设置加密算法
struct xfrm_algo_auth auth_algo;
strcpy(auth_algo.alg_name, "hmac(sha256)");
auth_algo.alg_key_len = 32;
unsigned char auth_key[32] = { /* ... 密钥数据 ... */ };
memcpy(auth_algo.alg_key, auth_key, 32);

// 设置其他参数，例如生命周期等...

// 构建 Netlink 消息
struct nlmsghdr nlh;
// ... 填充 Netlink 消息头
// ... 将 sa_info 和 auth_algo 等数据添加到 Netlink 消息的 payload 中
```

**假设输出（内核的响应，通过 Netlink 接收）：**

* **成功：** 内核会返回一个类型为 `NLMSG_DONE` 的 Netlink 消息，表示 SA 创建成功。
* **失败：** 内核会返回一个错误类型的 Netlink 消息，并可能包含错误代码，例如 `ENOENT` (没有找到匹配的策略)，`EINVAL` (参数无效) 等。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **地址族不匹配：** 在设置 `xfrm_usersa_info.family` 时，与地址结构 (`xfrm_address_t`) 中使用的地址类型不一致。例如，`family` 设置为 `AF_INET`，但 `daddr` 却使用了 IPv6 地址。
2. **SPI 冲突：** 尝试创建一个 SPI 已经存在的 SA，内核会拒绝。
3. **密钥长度错误：** 为加密或认证算法提供的密钥长度与算法要求的长度不符。
4. **算法名称拼写错误：** 在 `xfrm_algo` 等结构体中填写了内核不支持或识别错误的算法名称。
5. **缺少必要的策略：** 尝试创建 SA，但没有相应的安全策略允许这样的 SA 存在。
6. **权限不足：** 用户空间程序没有足够的权限创建或修改 XFRM 策略和 SA。通常需要 root 权限或具有 `CAP_NET_ADMIN` 能力。
7. **Netlink 消息格式错误：** 构建的 Netlink 消息头或 payload 格式不正确，导致内核无法解析。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 XFRM 的路径：**

1. **VPN 应用 (Java/Kotlin):** 用户通过 VPN 应用发起 VPN 连接请求。
2. **VpnService (Framework API):**  VPN 应用通常会使用 `VpnService` 这个 Framework API 来建立 VPN 连接。
3. **底层 VPN 实现 (Java/Native):** `VpnService` 的具体实现可能会调用底层的 Java 或 Native 代码。对于 IPsec VPN，可能会使用 `android.net.ipsec.ike` 或相关的 Native 库。
4. **Native 库 (C/C++):** 这些 Native 库会使用 POSIX 网络 API (例如 `socket()`, `sendto()`, `recvfrom()`) 和 Netlink 协议与内核的 XFRM 模块进行通信。
5. **系统调用 (Kernel Boundary):** Native 代码通过系统调用进入 Linux 内核。
6. **Netlink 子系统 (Kernel):** 内核的 Netlink 子系统接收到用户空间的 Netlink 消息。
7. **XFRM 模块 (Kernel):** Netlink 消息被路由到 XFRM 模块，XFRM 模块解析消息内容，执行相应的操作（创建/删除 SA/策略等）。

**NDK 到 XFRM 的路径：**

1. **NDK 应用 (C/C++):**  开发者使用 NDK 直接编写 C/C++ 代码。
2. **POSIX 网络 API:** NDK 应用可以直接使用 `socket(AF_NETLINK, ...)` 等 POSIX 网络 API 创建 Netlink 套接字。
3. **构建 Netlink 消息:** NDK 应用需要手动构建符合 Netlink 协议和 XFRM 消息格式的消息，包含这个头文件中定义的结构体。
4. **系统调用和内核交互:**  与 Framework 类似，通过系统调用和 Netlink 子系统与内核 XFRM 模块交互。

**Frida Hook 示例：**

以下是一个使用 Frida Hook `sendto` 系统调用的示例，用于观察 VPN 应用与 XFRM 模块的通信：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] sendto called")
        payload = message['payload']
        print(f"[*] Payload: {payload.hex()}")
        # 可以尝试解析 payload，查看是否包含 XFRM 相关的数据结构

def main():
    package_name = "com.example.vpnapp" # 替换为你的 VPN 应用包名
    try:
        device = frida.get_usb_device(timeout=10)
        session = device.attach(package_name)
    except frida.TimedOutError:
        print(f"Error: Could not find or connect to the device.")
        sys.exit(1)
    except frida.ProcessNotFoundError:
        print(f"Error: Process '{package_name}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "sendto"), {
        onEnter: function(args) {
            const sockfd = args[0].toInt32();
            const buf = args[1];
            const len = args[2].toInt32();
            const flags = args[3].toInt32();
            const dest_addr = args[4];
            const addrlen = args[5].toInt32();

            // 检查是否是 AF_NETLINK 套接字
            const sockaddr_family = Memory.readU16(dest_addr);
            if (sockaddr_family === 18) { // AF_NETLINK 的值
                console.log("[*] sendto called with AF_NETLINK");
                // 读取 payload 数据
                const payload = Memory.readByteArray(buf, len);
                send({ 'type': 'send', 'payload': payload });
            }
        },
        onLeave: function(retval) {
            //console.log("[*] sendto returned:", retval);
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

**使用说明：**

1. 将 `com.example.vpnapp` 替换为你想要调试的 VPN 应用的包名。
2. 确保你的 Android 设备已连接并通过 USB 调试授权。
3. 运行 Frida 脚本。当 VPN 应用尝试发送 Netlink 消息与 XFRM 模块通信时，脚本会拦截 `sendto` 调用，并打印出 payload 的十六进制数据。
4. 你需要根据 Netlink 协议和 XFRM 消息的结构来解析 payload 数据，才能理解具体发送了哪些 XFRM 命令和参数。

**进一步调试：**

* **Hook `recvfrom`:**  类似地，可以 Hook `recvfrom` 系统调用来查看内核 XFRM 模块返回的响应。
* **Hook 关键的 Native 库函数：** 如果知道 VPN 应用使用了特定的 Native 库来处理 IPsec，可以尝试 Hook 该库中负责构建和发送 Netlink 消息的函数。
* **结合 logcat:**  查看系统日志 (logcat) 中与 IPsec 和 XFRM 相关的日志信息，有助于理解程序的执行流程。

通过结合对源代码结构的理解和动态调试工具，可以深入分析 Android 系统中 IPsec VPN 功能的实现细节。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/xfrm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_XFRM_H
#define _LINUX_XFRM_H
#include <linux/in6.h>
#include <linux/types.h>
#include <linux/stddef.h>
typedef union {
  __be32 a4;
  __be32 a6[4];
  struct in6_addr in6;
} xfrm_address_t;
struct xfrm_id {
  xfrm_address_t daddr;
  __be32 spi;
  __u8 proto;
};
struct xfrm_sec_ctx {
  __u8 ctx_doi;
  __u8 ctx_alg;
  __u16 ctx_len;
  __u32 ctx_sid;
  char ctx_str[] __counted_by(ctx_len);
};
#define XFRM_SC_DOI_RESERVED 0
#define XFRM_SC_DOI_LSM 1
#define XFRM_SC_ALG_RESERVED 0
#define XFRM_SC_ALG_SELINUX 1
struct xfrm_selector {
  xfrm_address_t daddr;
  xfrm_address_t saddr;
  __be16 dport;
  __be16 dport_mask;
  __be16 sport;
  __be16 sport_mask;
  __u16 family;
  __u8 prefixlen_d;
  __u8 prefixlen_s;
  __u8 proto;
  int ifindex;
  __kernel_uid32_t user;
};
#define XFRM_INF (~(__u64) 0)
struct xfrm_lifetime_cfg {
  __u64 soft_byte_limit;
  __u64 hard_byte_limit;
  __u64 soft_packet_limit;
  __u64 hard_packet_limit;
  __u64 soft_add_expires_seconds;
  __u64 hard_add_expires_seconds;
  __u64 soft_use_expires_seconds;
  __u64 hard_use_expires_seconds;
};
struct xfrm_lifetime_cur {
  __u64 bytes;
  __u64 packets;
  __u64 add_time;
  __u64 use_time;
};
struct xfrm_replay_state {
  __u32 oseq;
  __u32 seq;
  __u32 bitmap;
};
#define XFRMA_REPLAY_ESN_MAX 4096
struct xfrm_replay_state_esn {
  unsigned int bmp_len;
  __u32 oseq;
  __u32 seq;
  __u32 oseq_hi;
  __u32 seq_hi;
  __u32 replay_window;
  __u32 bmp[];
};
struct xfrm_algo {
  char alg_name[64];
  unsigned int alg_key_len;
  char alg_key[];
};
struct xfrm_algo_auth {
  char alg_name[64];
  unsigned int alg_key_len;
  unsigned int alg_trunc_len;
  char alg_key[];
};
struct xfrm_algo_aead {
  char alg_name[64];
  unsigned int alg_key_len;
  unsigned int alg_icv_len;
  char alg_key[];
};
struct xfrm_stats {
  __u32 replay_window;
  __u32 replay;
  __u32 integrity_failed;
};
enum {
  XFRM_POLICY_TYPE_MAIN = 0,
  XFRM_POLICY_TYPE_SUB = 1,
  XFRM_POLICY_TYPE_MAX = 2,
  XFRM_POLICY_TYPE_ANY = 255
};
enum {
  XFRM_POLICY_IN = 0,
  XFRM_POLICY_OUT = 1,
  XFRM_POLICY_FWD = 2,
  XFRM_POLICY_MASK = 3,
  XFRM_POLICY_MAX = 3
};
enum xfrm_sa_dir {
  XFRM_SA_DIR_IN = 1,
  XFRM_SA_DIR_OUT = 2
};
enum {
  XFRM_SHARE_ANY,
  XFRM_SHARE_SESSION,
  XFRM_SHARE_USER,
  XFRM_SHARE_UNIQUE
};
#define XFRM_MODE_TRANSPORT 0
#define XFRM_MODE_TUNNEL 1
#define XFRM_MODE_ROUTEOPTIMIZATION 2
#define XFRM_MODE_IN_TRIGGER 3
#define XFRM_MODE_BEET 4
#define XFRM_MODE_MAX 5
enum {
  XFRM_MSG_BASE = 0x10,
  XFRM_MSG_NEWSA = 0x10,
#define XFRM_MSG_NEWSA XFRM_MSG_NEWSA
  XFRM_MSG_DELSA,
#define XFRM_MSG_DELSA XFRM_MSG_DELSA
  XFRM_MSG_GETSA,
#define XFRM_MSG_GETSA XFRM_MSG_GETSA
  XFRM_MSG_NEWPOLICY,
#define XFRM_MSG_NEWPOLICY XFRM_MSG_NEWPOLICY
  XFRM_MSG_DELPOLICY,
#define XFRM_MSG_DELPOLICY XFRM_MSG_DELPOLICY
  XFRM_MSG_GETPOLICY,
#define XFRM_MSG_GETPOLICY XFRM_MSG_GETPOLICY
  XFRM_MSG_ALLOCSPI,
#define XFRM_MSG_ALLOCSPI XFRM_MSG_ALLOCSPI
  XFRM_MSG_ACQUIRE,
#define XFRM_MSG_ACQUIRE XFRM_MSG_ACQUIRE
  XFRM_MSG_EXPIRE,
#define XFRM_MSG_EXPIRE XFRM_MSG_EXPIRE
  XFRM_MSG_UPDPOLICY,
#define XFRM_MSG_UPDPOLICY XFRM_MSG_UPDPOLICY
  XFRM_MSG_UPDSA,
#define XFRM_MSG_UPDSA XFRM_MSG_UPDSA
  XFRM_MSG_POLEXPIRE,
#define XFRM_MSG_POLEXPIRE XFRM_MSG_POLEXPIRE
  XFRM_MSG_FLUSHSA,
#define XFRM_MSG_FLUSHSA XFRM_MSG_FLUSHSA
  XFRM_MSG_FLUSHPOLICY,
#define XFRM_MSG_FLUSHPOLICY XFRM_MSG_FLUSHPOLICY
  XFRM_MSG_NEWAE,
#define XFRM_MSG_NEWAE XFRM_MSG_NEWAE
  XFRM_MSG_GETAE,
#define XFRM_MSG_GETAE XFRM_MSG_GETAE
  XFRM_MSG_REPORT,
#define XFRM_MSG_REPORT XFRM_MSG_REPORT
  XFRM_MSG_MIGRATE,
#define XFRM_MSG_MIGRATE XFRM_MSG_MIGRATE
  XFRM_MSG_NEWSADINFO,
#define XFRM_MSG_NEWSADINFO XFRM_MSG_NEWSADINFO
  XFRM_MSG_GETSADINFO,
#define XFRM_MSG_GETSADINFO XFRM_MSG_GETSADINFO
  XFRM_MSG_NEWSPDINFO,
#define XFRM_MSG_NEWSPDINFO XFRM_MSG_NEWSPDINFO
  XFRM_MSG_GETSPDINFO,
#define XFRM_MSG_GETSPDINFO XFRM_MSG_GETSPDINFO
  XFRM_MSG_MAPPING,
#define XFRM_MSG_MAPPING XFRM_MSG_MAPPING
  XFRM_MSG_SETDEFAULT,
#define XFRM_MSG_SETDEFAULT XFRM_MSG_SETDEFAULT
  XFRM_MSG_GETDEFAULT,
#define XFRM_MSG_GETDEFAULT XFRM_MSG_GETDEFAULT
  __XFRM_MSG_MAX
};
#define XFRM_MSG_MAX (__XFRM_MSG_MAX - 1)
#define XFRM_NR_MSGTYPES (XFRM_MSG_MAX + 1 - XFRM_MSG_BASE)
struct xfrm_user_sec_ctx {
  __u16 len;
  __u16 exttype;
  __u8 ctx_alg;
  __u8 ctx_doi;
  __u16 ctx_len;
};
struct xfrm_user_tmpl {
  struct xfrm_id id;
  __u16 family;
  xfrm_address_t saddr;
  __u32 reqid;
  __u8 mode;
  __u8 share;
  __u8 optional;
  __u32 aalgos;
  __u32 ealgos;
  __u32 calgos;
};
struct xfrm_encap_tmpl {
  __u16 encap_type;
  __be16 encap_sport;
  __be16 encap_dport;
  xfrm_address_t encap_oa;
};
enum xfrm_ae_ftype_t {
  XFRM_AE_UNSPEC,
  XFRM_AE_RTHR = 1,
  XFRM_AE_RVAL = 2,
  XFRM_AE_LVAL = 4,
  XFRM_AE_ETHR = 8,
  XFRM_AE_CR = 16,
  XFRM_AE_CE = 32,
  XFRM_AE_CU = 64,
  __XFRM_AE_MAX
#define XFRM_AE_MAX (__XFRM_AE_MAX - 1)
};
struct xfrm_userpolicy_type {
  __u8 type;
  __u16 reserved1;
  __u8 reserved2;
};
enum xfrm_attr_type_t {
  XFRMA_UNSPEC,
  XFRMA_ALG_AUTH,
  XFRMA_ALG_CRYPT,
  XFRMA_ALG_COMP,
  XFRMA_ENCAP,
  XFRMA_TMPL,
  XFRMA_SA,
  XFRMA_POLICY,
  XFRMA_SEC_CTX,
  XFRMA_LTIME_VAL,
  XFRMA_REPLAY_VAL,
  XFRMA_REPLAY_THRESH,
  XFRMA_ETIMER_THRESH,
  XFRMA_SRCADDR,
  XFRMA_COADDR,
  XFRMA_LASTUSED,
  XFRMA_POLICY_TYPE,
  XFRMA_MIGRATE,
  XFRMA_ALG_AEAD,
  XFRMA_KMADDRESS,
  XFRMA_ALG_AUTH_TRUNC,
  XFRMA_MARK,
  XFRMA_TFCPAD,
  XFRMA_REPLAY_ESN_VAL,
  XFRMA_SA_EXTRA_FLAGS,
  XFRMA_PROTO,
  XFRMA_ADDRESS_FILTER,
  XFRMA_PAD,
  XFRMA_OFFLOAD_DEV,
  XFRMA_SET_MARK,
  XFRMA_SET_MARK_MASK,
  XFRMA_IF_ID,
  XFRMA_MTIMER_THRESH,
  XFRMA_SA_DIR,
  XFRMA_NAT_KEEPALIVE_INTERVAL,
  __XFRMA_MAX
#define XFRMA_OUTPUT_MARK XFRMA_SET_MARK
#define XFRMA_MAX (__XFRMA_MAX - 1)
};
struct xfrm_mark {
  __u32 v;
  __u32 m;
};
enum xfrm_sadattr_type_t {
  XFRMA_SAD_UNSPEC,
  XFRMA_SAD_CNT,
  XFRMA_SAD_HINFO,
  __XFRMA_SAD_MAX
#define XFRMA_SAD_MAX (__XFRMA_SAD_MAX - 1)
};
struct xfrmu_sadhinfo {
  __u32 sadhcnt;
  __u32 sadhmcnt;
};
enum xfrm_spdattr_type_t {
  XFRMA_SPD_UNSPEC,
  XFRMA_SPD_INFO,
  XFRMA_SPD_HINFO,
  XFRMA_SPD_IPV4_HTHRESH,
  XFRMA_SPD_IPV6_HTHRESH,
  __XFRMA_SPD_MAX
#define XFRMA_SPD_MAX (__XFRMA_SPD_MAX - 1)
};
struct xfrmu_spdinfo {
  __u32 incnt;
  __u32 outcnt;
  __u32 fwdcnt;
  __u32 inscnt;
  __u32 outscnt;
  __u32 fwdscnt;
};
struct xfrmu_spdhinfo {
  __u32 spdhcnt;
  __u32 spdhmcnt;
};
struct xfrmu_spdhthresh {
  __u8 lbits;
  __u8 rbits;
};
struct xfrm_usersa_info {
  struct xfrm_selector sel;
  struct xfrm_id id;
  xfrm_address_t saddr;
  struct xfrm_lifetime_cfg lft;
  struct xfrm_lifetime_cur curlft;
  struct xfrm_stats stats;
  __u32 seq;
  __u32 reqid;
  __u16 family;
  __u8 mode;
  __u8 replay_window;
  __u8 flags;
#define XFRM_STATE_NOECN 1
#define XFRM_STATE_DECAP_DSCP 2
#define XFRM_STATE_NOPMTUDISC 4
#define XFRM_STATE_WILDRECV 8
#define XFRM_STATE_ICMP 16
#define XFRM_STATE_AF_UNSPEC 32
#define XFRM_STATE_ALIGN4 64
#define XFRM_STATE_ESN 128
};
#define XFRM_SA_XFLAG_DONT_ENCAP_DSCP 1
#define XFRM_SA_XFLAG_OSEQ_MAY_WRAP 2
struct xfrm_usersa_id {
  xfrm_address_t daddr;
  __be32 spi;
  __u16 family;
  __u8 proto;
};
struct xfrm_aevent_id {
  struct xfrm_usersa_id sa_id;
  xfrm_address_t saddr;
  __u32 flags;
  __u32 reqid;
};
struct xfrm_userspi_info {
  struct xfrm_usersa_info info;
  __u32 min;
  __u32 max;
};
struct xfrm_userpolicy_info {
  struct xfrm_selector sel;
  struct xfrm_lifetime_cfg lft;
  struct xfrm_lifetime_cur curlft;
  __u32 priority;
  __u32 index;
  __u8 dir;
  __u8 action;
#define XFRM_POLICY_ALLOW 0
#define XFRM_POLICY_BLOCK 1
  __u8 flags;
#define XFRM_POLICY_LOCALOK 1
#define XFRM_POLICY_ICMP 2
  __u8 share;
};
struct xfrm_userpolicy_id {
  struct xfrm_selector sel;
  __u32 index;
  __u8 dir;
};
struct xfrm_user_acquire {
  struct xfrm_id id;
  xfrm_address_t saddr;
  struct xfrm_selector sel;
  struct xfrm_userpolicy_info policy;
  __u32 aalgos;
  __u32 ealgos;
  __u32 calgos;
  __u32 seq;
};
struct xfrm_user_expire {
  struct xfrm_usersa_info state;
  __u8 hard;
};
struct xfrm_user_polexpire {
  struct xfrm_userpolicy_info pol;
  __u8 hard;
};
struct xfrm_usersa_flush {
  __u8 proto;
};
struct xfrm_user_report {
  __u8 proto;
  struct xfrm_selector sel;
};
struct xfrm_user_kmaddress {
  xfrm_address_t local;
  xfrm_address_t remote;
  __u32 reserved;
  __u16 family;
};
struct xfrm_user_migrate {
  xfrm_address_t old_daddr;
  xfrm_address_t old_saddr;
  xfrm_address_t new_daddr;
  xfrm_address_t new_saddr;
  __u8 proto;
  __u8 mode;
  __u16 reserved;
  __u32 reqid;
  __u16 old_family;
  __u16 new_family;
};
struct xfrm_user_mapping {
  struct xfrm_usersa_id id;
  __u32 reqid;
  xfrm_address_t old_saddr;
  xfrm_address_t new_saddr;
  __be16 old_sport;
  __be16 new_sport;
};
struct xfrm_address_filter {
  xfrm_address_t saddr;
  xfrm_address_t daddr;
  __u16 family;
  __u8 splen;
  __u8 dplen;
};
struct xfrm_user_offload {
  int ifindex;
  __u8 flags;
};
#define XFRM_OFFLOAD_IPV6 1
#define XFRM_OFFLOAD_INBOUND 2
#define XFRM_OFFLOAD_PACKET 4
struct xfrm_userpolicy_default {
#define XFRM_USERPOLICY_UNSPEC 0
#define XFRM_USERPOLICY_BLOCK 1
#define XFRM_USERPOLICY_ACCEPT 2
  __u8 in;
  __u8 fwd;
  __u8 out;
};
#define XFRMGRP_ACQUIRE 1
#define XFRMGRP_EXPIRE 2
#define XFRMGRP_SA 4
#define XFRMGRP_POLICY 8
#define XFRMGRP_REPORT 0x20
enum xfrm_nlgroups {
  XFRMNLGRP_NONE,
#define XFRMNLGRP_NONE XFRMNLGRP_NONE
  XFRMNLGRP_ACQUIRE,
#define XFRMNLGRP_ACQUIRE XFRMNLGRP_ACQUIRE
  XFRMNLGRP_EXPIRE,
#define XFRMNLGRP_EXPIRE XFRMNLGRP_EXPIRE
  XFRMNLGRP_SA,
#define XFRMNLGRP_SA XFRMNLGRP_SA
  XFRMNLGRP_POLICY,
#define XFRMNLGRP_POLICY XFRMNLGRP_POLICY
  XFRMNLGRP_AEVENTS,
#define XFRMNLGRP_AEVENTS XFRMNLGRP_AEVENTS
  XFRMNLGRP_REPORT,
#define XFRMNLGRP_REPORT XFRMNLGRP_REPORT
  XFRMNLGRP_MIGRATE,
#define XFRMNLGRP_MIGRATE XFRMNLGRP_MIGRATE
  XFRMNLGRP_MAPPING,
#define XFRMNLGRP_MAPPING XFRMNLGRP_MAPPING
  __XFRMNLGRP_MAX
};
#define XFRMNLGRP_MAX (__XFRMNLGRP_MAX - 1)
#endif

"""

```