Response:
Let's break down the thought process for answering the request about `nfnetlink_hook.h`.

**1. Understanding the Core Request:**

The central task is to analyze the provided C header file (`nfnetlink_hook.h`) and explain its purpose, relationship to Android, underlying mechanisms, and usage. The request is quite detailed, covering functionality, Android relevance, libc/linker details, error handling, and how to reach this point from Android's higher layers.

**2. Initial Analysis of the Header File:**

* **`#ifndef _NFNL_HOOK_H_ ... #endif`:** This is a standard include guard to prevent multiple inclusions.
* **`enum nfnl_hook_msg_types`:** Defines message types for communication, specifically `NFNL_MSG_HOOK_GET`. This immediately suggests this header is related to a communication protocol. The `MAX` suggests it can potentially be extended.
* **`enum nfnl_hook_attributes`:**  Defines attributes related to a "hook."  Keywords like `HOOKNUM`, `PRIORITY`, `DEV`, `FUNCTION_NAME`, `MODULE_NAME` strongly indicate this is about network filtering hooks.
* **`enum nfnl_hook_chain_info_attributes`:**  Provides further information about the "chain" associated with a hook, including a description and type.
* **`enum nfnl_hook_chain_desc_attributes`:** Describes the "chain" itself, with `TABLE`, `FAMILY`, and `NAME`. This reinforces the network filtering context (e.g., iptables).
* **`enum nfnl_hook_chaintype`:** Specifies different types of chains, `NFTABLES` and `BPF`, confirming involvement with modern Linux network filtering mechanisms.
* **`enum nfnl_hook_bpf_attributes`:**  Specifically for BPF chain types, includes an `ID`.

**3. Connecting to "nfnetlink":**

The filename `nfnetlink_hook.h` and the enum names (like `nfnl_hook_msg_types`) immediately point to the Netfilter Netlink interface. Netlink is a Linux kernel mechanism for communication between the kernel and user-space processes, particularly for network configuration and monitoring. Netfilter is the in-kernel firewalling framework.

**4. Identifying the Functionality:**

Based on the enums, the primary functionality is to:

* **Get information about existing Netfilter hooks:**  `NFNL_MSG_HOOK_GET`.
* **Describe the characteristics of these hooks:**  `HOOKNUM`, `PRIORITY`, `DEV`, `FUNCTION_NAME`, `MODULE_NAME`.
* **Detail the chain associated with the hook:** `DESC`, `TYPE`, `TABLE`, `FAMILY`, `NAME`.
* **Specify the type of chain:** `NFTABLES`, `BPF`.
* **Provide BPF-specific information:** `ID`.

**5. Relating to Android:**

Since this is in `bionic/libc/kernel/uapi/linux/netfilter/`, it's part of Android's system interface to the Linux kernel. This means Android processes can use these definitions to interact with the kernel's Netfilter subsystem. Crucially, Android leverages Netfilter for features like:

* **Firewalling:** Controlling network traffic in and out of the device.
* **Traffic Shaping/QoS:** Managing network bandwidth usage.
* **Network Address Translation (NAT):**  Sharing a single public IP address for multiple devices.
* **VPN:** Establishing secure network connections.

**6. Addressing the libc and Dynamic Linker Questions:**

* **libc Functions:** The header itself *doesn't* define or implement libc functions. It defines *constants* and *data structures* used by programs that *will* use libc functions. The key libc functions involved would be related to socket programming and Netlink communication (e.g., `socket()`, `bind()`, `sendto()`, `recvfrom()`, and potentially functions for parsing Netlink messages).
* **Dynamic Linker:** The header doesn't directly interact with the dynamic linker. However, programs using this header will need to link against libraries that implement the Netlink communication logic. The example SO layout and linking process were provided to illustrate a typical scenario where a library (`libnetfilter_conntrack.so`) might use these definitions.

**7. Logical Reasoning (Hypothetical Input/Output):**

The example of requesting information about hook number 3 demonstrates how a user-space application could use these constants to construct a Netlink request and how the kernel might respond with information about that hook.

**8. Common Usage Errors:**

The potential errors listed focus on the complexities of Netlink communication: incorrect protocol family, message type, attribute handling, and missing error checking.

**9. Tracing from Android Framework/NDK:**

This required some knowledge of Android's network stack. The explanation starts with higher-level Android APIs (like `NetworkPolicyManager`) that might trigger network configuration changes. These APIs eventually lead to system services (like `NetworkManagementService`), which use lower-level tools (like `iptables` or `nft`) that communicate with the kernel via Netlink. The NDK part highlights that developers can directly use Netlink sockets if needed.

**10. Frida Hook Example:**

The Frida example targets the `sendto` system call, which is the fundamental mechanism for sending Netlink messages. This allows inspection of the raw Netlink data being sent and received, which is crucial for debugging Netfilter interactions.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the header defines functions. **Correction:** Realized it only defines constants and structures. The actual implementation of Netlink communication is in other libraries and the kernel.
* **Overly focused on direct libc interaction:**  Shifted focus to how programs using this header would *indirectly* use libc functions for networking.
* **Simplifying the SO layout:**  Provided a basic example rather than an exhaustive listing of dependencies.
* **Ensuring the Frida example was practical:** Focused on a key system call involved in Netlink communication.

By following these steps, breaking down the request into smaller parts, and using knowledge of Linux networking and Android's architecture, it's possible to construct a comprehensive and accurate answer.
这个头文件 `nfnetlink_hook.h` 定义了用于与 Linux 内核的 Netfilter 框架中的 hook 功能进行通信的常量和数据结构。它使用了 Netlink 协议，这是一种用于内核和用户空间进程之间通信的套接字接口。

**功能列举:**

1. **定义 Netlink 消息类型:** `enum nfnl_hook_msg_types` 定义了可以发送给内核的关于 hook 的消息类型，目前只有一个 `NFNL_MSG_HOOK_GET`，表示获取 hook 的信息。
2. **定义 Netlink 属性类型 (Hook):** `enum nfnl_hook_attributes` 定义了用于描述 hook 的各种属性，例如：
   - `NFNLA_HOOK_HOOKNUM`:  hook 点的编号（例如，`NF_INET_PRE_ROUTING`）。
   - `NFNLA_HOOK_PRIORITY`: hook 的优先级。
   - `NFNLA_HOOK_DEV`:  与 hook 关联的网络设备。
   - `NFNLA_HOOK_FUNCTION_NAME`: 处理该 hook 的函数的名称。
   - `NFNLA_HOOK_MODULE_NAME`: 包含处理该 hook 的函数的内核模块的名称。
   - `NFNLA_HOOK_CHAIN_INFO`:  关联的链的信息。
3. **定义 Netlink 属性类型 (Chain 信息):** `enum nfnl_hook_chain_info_attributes` 定义了与 hook 关联的链的详细信息，例如：
   - `NFNLA_HOOK_INFO_DESC`: 链的描述。
   - `NFNLA_HOOK_INFO_TYPE`: 链的类型。
4. **定义 Netlink 属性类型 (Chain 描述):** `enum nfnl_hook_chain_desc_attributes` 定义了链本身的属性，例如：
   - `NFNLA_CHAIN_TABLE`: 链所属的表（例如，`filter`, `nat`）。
   - `NFNLA_CHAIN_FAMILY`:  协议族（例如，`AF_INET`, `AF_INET6`）。
   - `NFNLA_CHAIN_NAME`: 链的名称（例如，`INPUT`, `FORWARD`）。
5. **定义 Hook 链类型:** `enum nfnl_hook_chaintype` 定义了 hook 可以关联的链的类型，例如：
   - `NFNL_HOOK_TYPE_NFTABLES`: 表示使用 `nftables` 框架的链。
   - `NFNL_HOOK_TYPE_BPF`: 表示使用 BPF (Berkeley Packet Filter) 程序的链。
6. **定义 Netlink 属性类型 (BPF):** `enum nfnl_hook_bpf_attributes` 定义了与 BPF 链相关的属性，例如：
   - `NFNLA_HOOK_BPF_ID`:  BPF 程序的 ID。

**与 Android 功能的关系及举例说明:**

这个头文件对于 Android 的网络功能至关重要，因为它定义了与 Linux 内核 Netfilter 框架交互的接口。Android 使用 Netfilter 来实现各种网络功能，包括：

* **防火墙:** Android 的防火墙功能依赖于 Netfilter 来阻止或允许特定的网络连接。例如，应用程序可以通过 `iptables` (一个用户空间的 Netfilter 配置工具，虽然 Android 更倾向于使用 `ndc` 或 `netd`) 来配置规则，这些规则最终会转化为 Netfilter hook 的配置。
* **网络地址转换 (NAT):**  当 Android 设备作为热点时，它会使用 Netfilter 进行 NAT，允许连接到它的设备共享其互联网连接。
* **流量整形 (Traffic Shaping):** Android 可以使用 Netfilter 的 `tc` 工具来限制特定应用程序的网络带宽使用。
* **VPN:** VPN 连接通常会涉及到配置 Netfilter 规则来路由和加密流量。
* **数据包过滤:**  Android 系统服务可能需要监控或修改网络数据包，这可以通过注册 Netfilter hook 来实现。

**举例说明:**

假设一个 Android 系统服务想要获取当前系统中所有已注册的 Netfilter hook 的信息。它会执行以下步骤：

1. 创建一个 Netlink 套接字，指定协议族为 `AF_NETLINK`，协议为 `NETLINK_NETFILTER`。
2. 构建一个 Netlink 消息，消息类型设置为 `NFNL_MSG_HOOK_GET`。
3. (可选) 在消息中添加属性，以过滤要获取的 hook 信息 (当前消息类型似乎只支持获取所有 hook)。
4. 使用 `sendto()` 系统调用将消息发送到内核。
5. 内核接收到消息后，会查找并构建包含 hook 信息的 Netlink 响应消息。
6. 用户空间服务使用 `recvfrom()` 系统调用接收来自内核的响应消息。
7. 解析响应消息中的属性，获取每个 hook 的详细信息，例如 hook 点编号、优先级、关联的函数名等。

**libc 函数的功能实现:**

这个头文件本身并不包含 libc 函数的实现。它只是定义了常量和枚举类型，供使用 Netlink 与内核 Netfilter 模块通信的程序使用。实际的 Netlink 通信涉及以下 libc 函数：

* **`socket()`:** 创建一个 Netlink 套接字。例如：
  ```c
  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
  if (sock < 0) {
      perror("socket");
      // 处理错误
  }
  ```
* **`bind()`:** 将套接字绑定到 Netlink 地址。Netlink 地址包括进程 ID 和组播组 ID。通常，用户空间进程的 PID 会被设置为 0，表示由内核分配。
  ```c
  struct sockaddr_nl addr;
  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  // addr.nl_pid = getpid(); // 也可以使用进程的 PID
  addr.nl_groups = 0; // 不监听组播
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      perror("bind");
      // 处理错误
  }
  ```
* **`sendto()`:** 向内核发送 Netlink 消息。消息需要按照 Netlink 协议的格式进行构造，包括消息头和属性。
  ```c
  struct nlmsghdr nlh;
  // ... 填充 nlh 的字段，如长度、类型等 ...
  struct iovec iov = { .iov_base = &nlh, .iov_len = nlh.nlmsg_len };
  struct sockaddr_nl dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.nl_family = AF_NETLINK;
  // dest_addr.nl_pid = 0; // 发送给内核
  struct msghdr msg = { .msg_name = &dest_addr, .msg_namelen = sizeof(dest_addr), .msg_iov = &iov, .msg_iovlen = 1 };
  if (sendmsg(sock, &msg, 0) < 0) {
      perror("sendmsg");
      // 处理错误
  }
  ```
* **`recvfrom()` 或 `recvmsg()`:** 从内核接收 Netlink 消息。接收到的消息需要进行解析以提取有用的信息。
  ```c
  char buf[4096];
  struct sockaddr_nl from_addr;
  socklen_t from_len = sizeof(from_addr);
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  struct msghdr msg = { .msg_name = &from_addr, .msg_namelen = from_len, .msg_iov = &iov, .msg_iovlen = 1 };
  ssize_t recv_len = recvmsg(sock, &msg, 0);
  if (recv_len < 0) {
      perror("recvmsg");
      // 处理错误
  }
  ```
* **内存管理函数 (`malloc()`, `free()`, 等):** 用于构建和解析 Netlink 消息时动态分配内存。
* **字符串处理函数 (`memcpy()`, `memset()`, 等):** 用于操作 Netlink 消息的缓冲区。

**Dynamic Linker 的功能及 SO 布局样本和链接处理过程:**

这个头文件本身不涉及 dynamic linker 的功能，因为它只是一个头文件，定义了常量和枚举。然而，任何使用这些定义的程序都需要链接到提供 Netlink 通信功能的库。在 Android 中，与 Netfilter 相关的操作通常通过系统服务（如 `netd`）或使用 `libnetfilter_conntrack.so` 等库来完成。

**SO 布局样本:**

假设一个名为 `libmynetfilter.so` 的共享库使用了 `nfnetlink_hook.h` 中的定义：

```
libmynetfilter.so:
    / (根目录)
    /system
        /lib64 (对于 64 位架构) 或 /system/lib (对于 32 位架构)
            libmynetfilter.so
```

**链接处理过程:**

1. **编译时:**  当编译使用 `libmynetfilter.so` 的程序时，编译器会处理 `#include <linux/netfilter/nfnetlink_hook.h>` 指令，并记录需要链接的符号。
2. **链接时:**  链接器会查找所需的库文件 (`libmynetfilter.so`)。链接器会解析库的符号表，并将程序中对 `nfnetlink_hook.h` 中定义的常量的引用与库中的代码关联起来。由于 `nfnetlink_hook.h` 只是定义常量，实际的 Netlink 通信逻辑会在 `libmynetfilter.so` 或其他相关的库（如 `libc.so` 中的 `socket` 等）中实现。
3. **运行时:** 当程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载程序所需的共享库，包括 `libmynetfilter.so` 和其依赖的其他库（例如 `libc.so`）。dynamic linker 会解析这些库的依赖关系，并将程序中的函数调用重定向到加载的库中的相应函数地址。

**假设输入与输出 (逻辑推理):**

假设有一个用户空间程序想要获取 hook 点编号为 0 的 hook 信息。

**假设输入:**

* Netlink 套接字已创建并绑定。
* 构建的 Netlink 消息类型为 `NFNL_MSG_HOOK_GET`。
* 构建的 Netlink 消息包含一个属性 `NFNLA_HOOK_HOOKNUM`，其值为 0。

**预期输出:**

* 内核返回一个 Netlink 消息。
* 该消息包含一个或多个 `NFNETLINK_V0` 类型的消息。
* 每个消息包含以下属性：
    * `NFNLA_HOOK_HOOKNUM`: 值为 0。
    * `NFNLA_HOOK_PRIORITY`:  hook 的优先级，例如 0。
    * `NFNLA_HOOK_DEV`:  关联的设备名，例如 "" (表示所有设备)。
    * `NFNLA_HOOK_FUNCTION_NAME`: 处理该 hook 的内核函数名，例如 `ip_rcv_finish`。
    * `NFNLA_HOOK_MODULE_NAME`:  包含该函数的内核模块名，例如 "" (表示内置)。
    * `NFNLA_HOOK_CHAIN_INFO`:  可能包含关联的链的信息。

**用户或编程常见的使用错误:**

1. **Netlink 套接字未正确创建或绑定:**  如果套接字创建失败或绑定到错误的地址，则无法与内核通信。
2. **Netlink 消息格式错误:**  Netlink 消息需要按照特定的格式进行构造，包括消息头和属性。如果格式错误，内核可能无法解析或处理消息。例如：
   ```c
   // 错误示例：消息长度计算错误
   struct nlmsghdr nlh;
   nlh.nlmsg_len = sizeof(struct nlmsghdr) + sizeof(struct my_attribute); // 忘记包含属性头的长度
   ```
3. **属性类型或值错误:**  使用了错误的属性类型或设置了无效的属性值，会导致内核拒绝请求或返回错误信息。
4. **权限不足:** 某些 Netfilter 操作需要 root 权限。非特权进程可能无法执行某些操作。
5. **内存管理错误:**  在构建和解析 Netlink 消息时，如果没有正确管理内存（例如，忘记 `free()` 分配的内存），会导致内存泄漏。
6. **错误处理不足:**  没有检查 `sendto()` 和 `recvfrom()` 等函数的返回值，可能导致程序在发生错误时继续执行，从而产生不可预测的行为。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 层):**
   - 应用程序可能通过 `ConnectivityManager`、`NetworkPolicyManager` 等系统服务请求进行网络配置或获取网络状态。
   - 这些系统服务会调用底层的 native 代码。

2. **Android Native 代码 (C/C++ 层):**
   - 系统服务（例如 `NetworkManagementService`，通常运行在 `system_server` 进程中）或守护进程（例如 `netd`）会使用 C/C++ 代码来与内核交互。
   - 这些代码会使用标准 Linux 系统调用（如 `socket()`, `bind()`, `sendto()`, `recvfrom()`）来创建和管理 Netlink 套接字。
   - 代码会构建符合 Netlink 协议规范的消息，其中会使用到 `nfnetlink_hook.h` 中定义的常量来指定消息类型和属性。
   - 例如，`netd` 守护进程会处理来自 framework 的网络配置请求，并使用 Netlink 与内核的 Netfilter 模块通信，来配置防火墙规则、NAT 规则等。

3. **NDK:**
   - 使用 NDK 开发的应用程序可以直接使用 Linux 系统调用和相关的头文件，包括 `linux/netfilter/nfnetlink_hook.h`。
   - 开发者可以使用 NDK 直接编写代码来创建 Netlink 套接字，构建和发送 Netlink 消息，与内核的 Netfilter 模块进行交互。这通常用于实现底层的网络功能或监控。

**Frida Hook 示例调试步骤:**

假设我们要 hook 一个使用 Netlink 发送获取 hook 信息的函数，例如 `sendto` 系统调用，以观察发送的 Netlink 消息。

**Frida Hook 脚本示例:**

```javascript
if (Process.platform === 'linux') {
  const sendtoPtr = Module.getExportByName(null, 'sendto');

  if (sendtoPtr) {
    Interceptor.attach(sendtoPtr, {
      onEnter: function (args) {
        const sockfd = args[0].toInt32();
        const bufPtr = args[1];
        const len = args[2].toInt32();
        const flags = args[3].toInt32();
        const destAddrPtr = args[4];
        const addrlen = args[5] ? args[5].toInt32() : 0;

        // 检查是否是 AF_NETLINK 套接字
        const sockType = Socket.type(sockfd);
        if (sockType && sockType.family === 'af_netlink') {
          console.log('[sendto] Called from:', Thread.backtrace(this.context, Backtracer.ACCURATE).map(function(b) { return b.toString(); }).join('\n'));
          console.log('[sendto] sockfd:', sockfd);
          console.log('[sendto] len:', len);
          console.log('[sendto] flags:', flags);

          // 读取 Netlink 消息头
          const nlmsghdrSize = 16; // sizeof(struct nlmsghdr)
          if (len >= nlmsghdrSize) {
            const nlmsg_len = bufPtr.readU32();
            const nlmsg_type = bufPtr.readU16();
            const nlmsg_flags = bufPtr.readU16();
            const nlmsg_seq = bufPtr.readU32();
            const nlmsg_pid = bufPtr.readU32();

            console.log('[sendto] Netlink Header:');
            console.log('  nlmsg_len:', nlmsg_len);
            console.log('  nlmsg_type:', nlmsg_type);
            console.log('  nlmsg_flags:', nlmsg_flags);
            console.log('  nlmsg_seq:', nlmsg_seq);
            console.log('  nlmsg_pid:', nlmsg_pid);

            // 如果是 NFNL_MSG_HOOK_GET 消息，进一步解析属性
            const NFNL_MSG_HOOK_GET = 0;
            if (nlmsg_type === NFNL_MSG_HOOK_GET) {
              console.log('[sendto] Detected NFNL_MSG_HOOK_GET message');
              let currentOffset = nlmsghdrSize;
              while (currentOffset < nlmsg_len) {
                const nla_len = bufPtr.add(currentOffset).readU16();
                const nla_type = bufPtr.add(currentOffset + 2).readU16();
                console.log(`[sendto]   Attribute: type=${nla_type}, len=${nla_len}`);
                currentOffset += nla_len;
              }
            }
          }
        }
      }
    });
  } else {
    console.error('Failed to find sendto symbol');
  }
} else {
  console.warn('This script is designed for Linux.');
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并安装了 Frida 服务。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_nfnetlink.js`。
3. **确定目标进程:** 确定哪个进程可能发送与 Netfilter hook 相关的 Netlink 消息。这可能是 `system_server` 或 `netd`。
4. **运行 Frida:** 使用 Frida 连接到目标进程并加载脚本。例如：
   ```bash
   frida -U -f com.android.systemui -l hook_nfnetlink.js --no-pause
   # 或者
   frida -U -n system_server -l hook_nfnetlink.js --no-pause
   # 或者
   frida -U -n netd -l hook_nfnetlink.js --no-pause
   ```
5. **触发操作:** 在 Android 设备上执行可能触发 Netfilter hook 操作的操作。例如，连接或断开 Wi-Fi，更改网络策略等。
6. **查看 Frida 输出:** Frida 会在控制台上打印出 `sendto` 系统调用的相关信息，包括发送的 Netlink 消息头和属性，帮助你理解用户空间程序是如何与内核 Netfilter 模块交互的。

通过这种方式，你可以观察到哪些进程在与 Netfilter 交互，发送了哪些类型的 Netlink 消息，以及包含了哪些属性，从而深入理解 Android 的网络功能实现。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter/nfnetlink_hook.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _NFNL_HOOK_H_
#define _NFNL_HOOK_H_
enum nfnl_hook_msg_types {
  NFNL_MSG_HOOK_GET,
  NFNL_MSG_HOOK_MAX,
};
enum nfnl_hook_attributes {
  NFNLA_HOOK_UNSPEC,
  NFNLA_HOOK_HOOKNUM,
  NFNLA_HOOK_PRIORITY,
  NFNLA_HOOK_DEV,
  NFNLA_HOOK_FUNCTION_NAME,
  NFNLA_HOOK_MODULE_NAME,
  NFNLA_HOOK_CHAIN_INFO,
  __NFNLA_HOOK_MAX
};
#define NFNLA_HOOK_MAX (__NFNLA_HOOK_MAX - 1)
enum nfnl_hook_chain_info_attributes {
  NFNLA_HOOK_INFO_UNSPEC,
  NFNLA_HOOK_INFO_DESC,
  NFNLA_HOOK_INFO_TYPE,
  __NFNLA_HOOK_INFO_MAX,
};
#define NFNLA_HOOK_INFO_MAX (__NFNLA_HOOK_INFO_MAX - 1)
enum nfnl_hook_chain_desc_attributes {
  NFNLA_CHAIN_UNSPEC,
  NFNLA_CHAIN_TABLE,
  NFNLA_CHAIN_FAMILY,
  NFNLA_CHAIN_NAME,
  __NFNLA_CHAIN_MAX,
};
#define NFNLA_CHAIN_MAX (__NFNLA_CHAIN_MAX - 1)
enum nfnl_hook_chaintype {
  NFNL_HOOK_TYPE_NFTABLES = 0x1,
  NFNL_HOOK_TYPE_BPF,
};
enum nfnl_hook_bpf_attributes {
  NFNLA_HOOK_BPF_UNSPEC,
  NFNLA_HOOK_BPF_ID,
  __NFNLA_HOOK_BPF_MAX,
};
#define NFNLA_HOOK_BPF_MAX (__NFNLA_HOOK_BPF_MAX - 1)
#endif

"""

```