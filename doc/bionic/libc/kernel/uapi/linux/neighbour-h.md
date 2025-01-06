Response:
Let's break down the thought process for answering this request about `neighbour.h`.

**1. Understanding the Core Request:**

The request asks for an analysis of the `neighbour.h` header file within the Android bionic library. The key aspects to cover are:

* **Functionality:** What does this file define?
* **Android Relevance:** How does it relate to Android's functioning?
* **Libc Function Details:**  Explanation of the *libc functions* within the file (a potential trap!).
* **Dynamic Linker:** How does it interact with the dynamic linker (another potential trap!).
* **Logical Reasoning:** Hypothetical input/output examples.
* **Common Errors:** Pitfalls for users/programmers.
* **Android Framework/NDK Path:** How is it accessed?
* **Frida Hooking:**  Examples for debugging.

**2. Initial Analysis of the Header File:**

The first step is to carefully examine the content of `neighbour.h`. The most obvious things are:

* **`#ifndef __LINUX_NEIGHBOUR_H`:**  Include guard, standard practice in C/C++ headers.
* **`#include <linux/types.h>` and `#include <linux/netlink.h>`:**  Dependencies on other Linux kernel headers. This immediately tells us this file is about low-level networking.
* **`struct ndmsg`:** A structure likely related to "neighbor discovery messages."
* **`enum` blocks:**  Define constants and flags related to neighbor discovery (NDA_*, NTF_*, NUD_*, etc.). These strongly suggest this file defines data structures and enumerations for interacting with the kernel's neighbor discovery protocol.
* **`struct nda_cacheinfo`, `struct ndt_stats`, `struct ndtmsg`, `struct ndt_config`:** More structures related to neighbor discovery information and configuration.
* **`enum` blocks (NDTPA_*, NDTA_*, NFEA_*):**  More constants related to different aspects of neighbor discovery.

**3. Addressing the "Libc Function" and "Dynamic Linker" Questions (Critical Thinking):**

This is where careful analysis is crucial. Looking through the header, we see *no actual C functions* being defined. It only defines data structures and constants. This is a *kernel UAPI* header.

* **Libc Functions:** The file *doesn't contain any libc functions*. It defines *data structures used by libc functions* that interact with the kernel's networking subsystem. The answer needs to reflect this distinction.
* **Dynamic Linker:**  Similarly, this header file isn't directly involved in the dynamic linking process. Dynamic linking deals with resolving symbols between shared libraries. This header defines data structures used when a program *communicates with the kernel*, which is a different layer. The answer needs to clarify this.

**4. Focusing on the Actual Functionality:**

The file defines the interface for interacting with the Linux kernel's *neighbor discovery (ND) protocol*. This protocol is crucial for IPv6 networking (and also exists in IPv4 as ARP). It's used to discover the link-layer addresses (like MAC addresses) of other devices on the same network segment.

**5. Connecting to Android:**

How is this relevant to Android? Android devices participate in networks. They need to resolve IP addresses to MAC addresses to send and receive data. Therefore, the kernel's ND implementation, which this header describes, is fundamental to Android's networking capabilities. Examples include:

* Connecting to Wi-Fi networks.
* Communicating with other devices on a local network.
* Using IPv6.

**6. Developing Examples (Logical Reasoning and Common Errors):**

Since it's a header file defining data structures, direct input/output examples aren't applicable in the same way as for a function. Instead, think about how these structures are *used*.

* **Hypothetical Input/Output:**  Consider how a user-space program might interact with the kernel using these structures via `netlink` sockets. The program sends a message to request neighbor information, and the kernel responds with a message containing data formatted according to these structures.
* **Common Errors:**  Think about typical programming errors when dealing with networking and kernel interfaces:
    * Incorrectly setting the flags or state values.
    * Mismatched sizes or alignments when packing/unpacking data.
    * Not handling errors from `socket()` or `sendto()`/`recvfrom()`.

**7. Tracing the Android Framework/NDK Path:**

How does an Android app eventually interact with these structures? The path is generally:

* **Android Application (Java/Kotlin):**  Makes high-level networking requests (e.g., opening a socket).
* **Android Framework (Java):**  Handles the request and uses system calls.
* **Native Code (C/C++ in Android Runtime/NDK):**  Uses system calls like `socket()`, `sendto()`, `recvfrom()`, and interacts with netlink sockets.
* **Linux Kernel:**  The networking subsystem in the kernel uses the definitions in `neighbour.h` to process neighbor discovery messages.

**8. Frida Hooking:**

Focus on where these structures are *used*. Since it's about kernel interaction, hooking system calls related to networking (especially netlink) is the way to go. Examples: `sendto`, `recvfrom`, `socket`. Hooking functions in `libc` that deal with socket options or network address manipulation could also be relevant.

**9. Structuring the Answer:**

Organize the information logically, addressing each point in the request. Use clear and concise language. Emphasize the distinction between the header file's definitions and actual function implementations.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Maybe there are some inline functions in the header?"  *Correction:*  Scan the file again carefully. No inline functions. It's purely data structure definitions.
* **Initial thought:** "Focus on how the dynamic linker resolves symbols related to neighbor discovery." *Correction:* This header isn't about symbol resolution. It's about the *data format* for kernel communication. The dynamic linker's role is in linking libraries, not defining kernel data structures.
* **Initial thought:** "Give very specific examples of system calls using these structures." *Refinement:*  Provide general examples of system calls like `sendto` and `recvfrom` which are the typical entry points for interacting with sockets and thus potentially involving neighbor discovery indirectly. Directly showing how `ndmsg` or `nda_cacheinfo` are used within a specific system call implementation is too low-level for this request and would require kernel source code analysis.

By following these steps of analysis, understanding the core concepts, and carefully distinguishing between definitions and implementations, a comprehensive and accurate answer can be constructed.
这是一个定义 Linux 内核用户空间 API (UAPI) 的头文件，专门用于邻居子系统（Neighbour Subsystem）。邻居子系统是 Linux 内核网络栈的关键部分，负责管理网络层地址（例如 IPv4 或 IPv6 地址）到链路层地址（例如以太网 MAC 地址）的映射关系，也就是我们常说的 ARP (Address Resolution Protocol) 和 NDP (Neighbor Discovery Protocol)。

**它的功能:**

这个头文件主要定义了用于与 Linux 内核邻居子系统交互的数据结构和常量。具体来说，它定义了：

1. **消息结构体 (Structures):**
   - `struct ndmsg`:  表示邻居缓存条目的信息。用于查询或修改邻居缓存。
   - `struct nda_cacheinfo`: 包含邻居缓存条目的缓存信息，例如确认时间、使用时间等。
   - `struct ndt_stats`:  包含邻居表（neighbor table）的统计信息，例如分配次数、销毁次数、查找次数等。
   - `struct ndtmsg`: 用于操作邻居表参数的消息结构体。
   - `struct ndt_config`:  包含邻居表的配置信息，例如表大小、刷新间隔等。

2. **枚举常量 (Enums):**
   - 用于标识邻居属性类型 (NDA_*)，例如目标地址 (NDA_DST)、链路层地址 (NDA_LLADDR) 等。
   - 用于定义邻居条目的标志 (NTF_*)，例如是否正在使用 (NTF_USE)、是否是本机地址 (NTF_SELF) 等。
   - 用于定义邻居条目的状态 (NUD_*)，例如不完整 (NUD_INCOMPLETE)、可达 (NUD_REACHABLE) 等。
   - 用于标识邻居表参数属性类型 (NDTPA_*)，例如接口索引 (NDTPA_IFINDEX)、可达时间 (NDTPA_REACHABLE_TIME) 等。
   - 用于标识邻居表配置属性类型 (NDTA_*)，例如表名 (NDTA_NAME)、阈值 (NDTA_THRESH1) 等。
   - 用于定义转发数据库通知标志 (FDB_NOTIFY_BIT)。
   - 用于定义邻居转发条目属性类型 (NFEA_*)。

3. **宏定义 (Macros):**
   - `NDA_MAX`: 表示邻居属性类型的最大值。
   - `NTF_*`: 定义邻居标志的位掩码。
   - `NUD_*`: 定义邻居状态的位掩码。
   - `NDTPA_MAX`: 表示邻居表参数属性类型的最大值。
   - `NDTA_MAX`: 表示邻居表配置属性类型的最大值。
   - `FDB_NOTIFY_BIT`, `FDB_NOTIFY_INACTIVE_BIT`: 定义转发数据库通知的标志位。
   - `NFEA_MAX`: 表示邻居转发条目属性类型的最大值。

**它与 Android 功能的关系以及举例说明:**

这个头文件直接关系到 Android 设备的网络功能。Android 系统底层使用 Linux 内核，因此需要通过这些定义与内核的邻居子系统进行交互，以实现网络通信。

**举例说明:**

* **IP 地址解析:** 当 Android 设备需要向同一局域网内的另一个 IP 地址发送数据时，它需要知道目标 IP 地址对应的 MAC 地址。内核会使用邻居子系统来查找或发起 ARP/NDP 过程来获取目标 MAC 地址。这个过程中，Android 的网络组件可能会通过 Netlink 套接字与内核通信，而 `neighbour.h` 中定义的 `ndmsg` 结构体就用于封装这些通信消息，例如查询特定 IP 地址的邻居信息。
* **网络状态管理:** Android 系统需要监控网络连接的状态。例如，判断一个邻居是否仍然可达。内核会更新邻居缓存的状态（例如从 `NUD_REACHABLE` 变为 `NUD_STALE`），Android 的网络守护进程可以通过 Netlink 消息获取这些状态变化，并做出相应的处理，例如重新发起 ARP/NDP 请求。
* **Wi-Fi 连接:**  当 Android 设备连接到 Wi-Fi 网络时，它需要与路由器进行通信。路由器会通告其 IPv6 地址和链路层地址。Android 设备会使用 NDP 协议来发现路由器，并将路由器的信息存储在邻居缓存中。`neighbour.h` 中定义的结构体和常量就用于处理这些 NDP 消息。

**详细解释每一个 libc 函数的功能是如何实现的:**

**关键点:** 这个头文件本身**不包含任何 libc 函数的实现**。 它仅仅定义了数据结构和常量，作为用户空间程序与 Linux 内核邻居子系统交互的接口规范。

用户空间程序（例如 Android 的网络守护进程 `netd`）会使用标准的 socket API（如 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等）结合 Netlink 协议与内核的邻居子系统通信。Netlink 是一种特殊的 socket 族，用于在内核和用户空间进程之间传递信息。

当用户空间程序需要查询或修改邻居信息时，它会构造一个符合 `neighbour.h` 中定义的 `ndmsg` 结构的消息，并通过 Netlink socket 发送给内核。内核接收到消息后，会根据消息内容执行相应的操作，并将结果通过 Netlink socket 返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**关键点:**  `neighbour.h` **不直接涉及 dynamic linker 的功能**。

Dynamic linker (例如 Android 的 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并解析符号依赖关系。 `neighbour.h` 定义的是内核 UAPI，用于与内核交互，而 dynamic linker 处理的是用户空间库的链接和加载。

虽然用户空间程序可能会使用依赖于网络功能的共享库，但这些共享库本身不会直接包含 `neighbour.h` 中定义的结构体的实现（因为这些结构体是内核定义的）。共享库可能会调用 libc 的网络相关函数（例如 `getaddrinfo()`, `socket()` 等），而 libc 最终会通过系统调用与内核的网络子系统交互。

**因此，没有直接的 `.so` 布局样本或链接处理过程与 `neighbour.h` 直接相关。**

**如果做了逻辑推理，请给出假设输入与输出:**

由于 `neighbour.h` 定义的是数据结构，我们无法像函数那样给出直接的输入输出。但可以假设一个场景，并描述数据结构的内容：

**假设场景:** 用户空间程序（例如 `ip` 命令）想要查询接口索引为 `eth0` 的、IP 地址为 `192.168.1.100` 的邻居信息。

**假设输入 (构造的 `ndmsg` 结构体):**

```c
struct ndmsg req;
memset(&req, 0, sizeof(req));
req.ndm_family = AF_INET; // 地址族为 IPv4
req.ndm_ifindex = if_nametoindex("eth0"); // 获取 "eth0" 的接口索引
// 其他字段根据需要设置，例如 ndm_state_mask, ndm_flags
```

**假设输出 (内核返回的包含 `ndmsg` 和邻居属性的消息):**

```c
struct nlmsghdr *nlh; // Netlink 消息头
struct ndmsg *resp_ndm;
struct rtattr *rta;
int len;
// ... 接收 Netlink 消息 ...

resp_ndm = NLMSG_DATA(nlh); // 获取 ndmsg 结构体

if (resp_ndm->ndm_family == AF_INET && resp_ndm->ndm_ifindex == if_nametoindex("eth0")) {
    rta = IFLA_RTA(NLMSG_NEXT(nlh, sizeof(struct ndmsg))); // 获取第一个邻居属性

    while (rta && RTA_OK(rta, len)) {
        switch (rta->rta_type) {
            case NDA_DST: {
                // 目标 IP 地址
                struct in_addr *dst_addr = RTA_DATA(rta);
                // 如果 dst_addr 是 192.168.1.100，则找到了目标邻居
                break;
            }
            case NDA_LLADDR: {
                // 链路层地址 (MAC 地址)
                unsigned char *mac_addr = RTA_DATA(rta);
                // 获取到 192.168.1.100 的 MAC 地址
                break;
            }
            case NDA_STATE: {
                // 邻居状态
                __u16 state = *(__u16 *)RTA_DATA(rta);
                // 例如 state 可能为 NUD_REACHABLE
                break;
            }
            // ... 处理其他邻居属性 ...
        }
        rta = RTA_NEXT(rta, len);
    }
}
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **不正确的地址族:** 在构造 `ndmsg` 结构体时，`ndm_family` 字段需要设置为正确的地址族（例如 `AF_INET` for IPv4, `AF_INET6` for IPv6）。如果设置错误，内核可能无法正确处理请求。

   ```c
   struct ndmsg req;
   memset(&req, 0, sizeof(req));
   req.ndm_family = AF_INET6; // 错误地设置为 IPv6
   req.ndm_ifindex = if_nametoindex("eth0");
   // ... 发送请求 ...
   ```

2. **错误的接口索引:** `ndm_ifindex` 字段需要设置为目标接口的正确索引。可以使用 `if_nametoindex()` 函数根据接口名称获取索引。如果索引错误，内核可能找不到对应的邻居信息。

   ```c
   struct ndmsg req;
   memset(&req, 0, sizeof(req));
   req.ndm_family = AF_INET;
   req.ndm_ifindex = 999; // 错误的接口索引
   // ... 发送请求 ...
   ```

3. **不正确的 Netlink 消息构造:**  与邻居子系统通信需要使用 Netlink 协议。用户程序需要正确构造 Netlink 消息头 (`struct nlmsghdr`) 和邻居消息体 (`struct ndmsg`)，以及可能的邻居属性 (`struct rtattr`)。如果消息格式不正确，内核可能无法解析或处理。

4. **忘记处理错误:**  与内核交互可能会失败。用户程序应该检查 Netlink 消息的返回状态，并处理可能出现的错误，例如权限不足、找不到邻居等。

5. **不正确的状态和标志位使用:** 修改邻居缓存时，需要正确设置 `ndm_state` 和 `ndm_flags` 字段。错误地设置这些字段可能会导致网络行为异常。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

Android Framework 和 NDK 通常不会直接操作 `neighbour.h` 中定义的数据结构。它们会使用更高级的网络 API，例如 Java 中的 `java.net` 包或 NDK 中的 socket API。

**路径:**

1. **Android 应用 (Java/Kotlin):**  应用发起网络请求，例如通过 `HttpURLConnection` 或 `Socket` 类。
2. **Android Framework (Java):** Framework 将请求转换为底层的系统调用。例如，`Socket` 的操作最终会调用到 native 代码。
3. **NDK (C/C++):**  在 Android Runtime (ART) 或 Native 代码中，会使用标准的 socket API (例如 `socket()`, `connect()`, `sendto()`, `recvfrom()`).
4. **libc (bionic):** bionic 库实现了这些 socket API，并最终通过系统调用与 Linux 内核进行交互。
5. **Linux Kernel:** 内核的网络子系统接收到系统调用后，如果涉及到邻居解析，就会使用 `neighbour.h` 中定义的数据结构来管理邻居缓存和处理 ARP/NDP 协议。

**Frida Hook 示例:**

要观察 Android 是如何与邻居子系统交互的，可以 Hook 与网络相关的系统调用，或者 Hook Android Framework 中负责网络操作的 Java 方法。

**Hook 系统调用示例 (使用 Frida 的 Native 钩子):**

```javascript
// Hook sendto 系统调用，这可能涉及到需要进行邻居解析的情况
Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
  onEnter: function (args) {
    console.log("sendto called");
    var sockfd = args[0];
    var buf = args[1];
    var len = args[2].toInt32();
    var flags = args[3];
    var dest_addr = args[4];
    var addrlen = args[5].toInt32();

    console.log("  sockfd:", sockfd);
    console.log("  len:", len);
    console.log("  flags:", flags);

    // 可以进一步解析 dest_addr 来查看目标地址信息
    if (dest_addr.isNull() == 0) {
      var family = Memory.readU16(dest_addr);
      console.log("  dest_addr->sa_family:", family);
      if (family === 2) { // AF_INET
        var port = Memory.readU16(dest_addr.add(2));
        var ip = Memory.readU32(dest_addr.add(4));
        console.log("  dest_addr->sin_port:", port);
        console.log("  dest_addr->sin_addr:", inet_ntoa(ip));
      } else if (family === 10) { // AF_INET6
        // 解析 IPv6 地址
      }
    }
  },
  onLeave: function (retval) {
    console.log("sendto returned:", retval);
  },
});

function inet_ntoa(ip) {
  var a = (ip & 0xff);
  var b = (ip >> 8) & 0xff;
  var c = (ip >> 16) & 0xff;
  var d = (ip >> 24) & 0xff;
  return a + "." + b + "." + c + "." + d;
}
```

**Hook Android Framework 方法示例 (使用 Frida 的 Java 钩子):**

```javascript
Java.perform(function() {
  var socketClass = Java.use("java.net.Socket");
  socketClass.connect.overload("java.net.SocketAddress", "int").implementation = function(remoteAddr, timeout) {
    console.log("Socket.connect called to: " + remoteAddr);
    this.connect.overload("java.net.SocketAddress", "int").call(this, remoteAddr, timeout);
  };
});
```

通过这些 Frida Hook，你可以观察到 Android 应用在进行网络通信时，底层是如何调用系统调用，以及系统调用中涉及到的目标地址信息，从而间接地了解邻居子系统的工作过程。虽然不能直接 Hook 到使用 `neighbour.h` 数据结构的内核代码，但可以观察到用户空间与内核交互的入口点。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/neighbour.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_NEIGHBOUR_H
#define __LINUX_NEIGHBOUR_H
#include <linux/types.h>
#include <linux/netlink.h>
struct ndmsg {
  __u8 ndm_family;
  __u8 ndm_pad1;
  __u16 ndm_pad2;
  __s32 ndm_ifindex;
  __u16 ndm_state;
  __u8 ndm_flags;
  __u8 ndm_type;
};
enum {
  NDA_UNSPEC,
  NDA_DST,
  NDA_LLADDR,
  NDA_CACHEINFO,
  NDA_PROBES,
  NDA_VLAN,
  NDA_PORT,
  NDA_VNI,
  NDA_IFINDEX,
  NDA_MASTER,
  NDA_LINK_NETNSID,
  NDA_SRC_VNI,
  NDA_PROTOCOL,
  NDA_NH_ID,
  NDA_FDB_EXT_ATTRS,
  NDA_FLAGS_EXT,
  NDA_NDM_STATE_MASK,
  NDA_NDM_FLAGS_MASK,
  __NDA_MAX
};
#define NDA_MAX (__NDA_MAX - 1)
#define NTF_USE (1 << 0)
#define NTF_SELF (1 << 1)
#define NTF_MASTER (1 << 2)
#define NTF_PROXY (1 << 3)
#define NTF_EXT_LEARNED (1 << 4)
#define NTF_OFFLOADED (1 << 5)
#define NTF_STICKY (1 << 6)
#define NTF_ROUTER (1 << 7)
#define NTF_EXT_MANAGED (1 << 0)
#define NTF_EXT_LOCKED (1 << 1)
#define NUD_INCOMPLETE 0x01
#define NUD_REACHABLE 0x02
#define NUD_STALE 0x04
#define NUD_DELAY 0x08
#define NUD_PROBE 0x10
#define NUD_FAILED 0x20
#define NUD_NOARP 0x40
#define NUD_PERMANENT 0x80
#define NUD_NONE 0x00
struct nda_cacheinfo {
  __u32 ndm_confirmed;
  __u32 ndm_used;
  __u32 ndm_updated;
  __u32 ndm_refcnt;
};
struct ndt_stats {
  __u64 ndts_allocs;
  __u64 ndts_destroys;
  __u64 ndts_hash_grows;
  __u64 ndts_res_failed;
  __u64 ndts_lookups;
  __u64 ndts_hits;
  __u64 ndts_rcv_probes_mcast;
  __u64 ndts_rcv_probes_ucast;
  __u64 ndts_periodic_gc_runs;
  __u64 ndts_forced_gc_runs;
  __u64 ndts_table_fulls;
};
enum {
  NDTPA_UNSPEC,
  NDTPA_IFINDEX,
  NDTPA_REFCNT,
  NDTPA_REACHABLE_TIME,
  NDTPA_BASE_REACHABLE_TIME,
  NDTPA_RETRANS_TIME,
  NDTPA_GC_STALETIME,
  NDTPA_DELAY_PROBE_TIME,
  NDTPA_QUEUE_LEN,
  NDTPA_APP_PROBES,
  NDTPA_UCAST_PROBES,
  NDTPA_MCAST_PROBES,
  NDTPA_ANYCAST_DELAY,
  NDTPA_PROXY_DELAY,
  NDTPA_PROXY_QLEN,
  NDTPA_LOCKTIME,
  NDTPA_QUEUE_LENBYTES,
  NDTPA_MCAST_REPROBES,
  NDTPA_PAD,
  NDTPA_INTERVAL_PROBE_TIME_MS,
  __NDTPA_MAX
};
#define NDTPA_MAX (__NDTPA_MAX - 1)
struct ndtmsg {
  __u8 ndtm_family;
  __u8 ndtm_pad1;
  __u16 ndtm_pad2;
};
struct ndt_config {
  __u16 ndtc_key_len;
  __u16 ndtc_entry_size;
  __u32 ndtc_entries;
  __u32 ndtc_last_flush;
  __u32 ndtc_last_rand;
  __u32 ndtc_hash_rnd;
  __u32 ndtc_hash_mask;
  __u32 ndtc_hash_chain_gc;
  __u32 ndtc_proxy_qlen;
};
enum {
  NDTA_UNSPEC,
  NDTA_NAME,
  NDTA_THRESH1,
  NDTA_THRESH2,
  NDTA_THRESH3,
  NDTA_CONFIG,
  NDTA_PARMS,
  NDTA_STATS,
  NDTA_GC_INTERVAL,
  NDTA_PAD,
  __NDTA_MAX
};
#define NDTA_MAX (__NDTA_MAX - 1)
enum {
  FDB_NOTIFY_BIT = (1 << 0),
  FDB_NOTIFY_INACTIVE_BIT = (1 << 1)
};
enum {
  NFEA_UNSPEC,
  NFEA_ACTIVITY_NOTIFY,
  NFEA_DONT_REFRESH,
  __NFEA_MAX
};
#define NFEA_MAX (__NFEA_MAX - 1)
#endif

"""

```