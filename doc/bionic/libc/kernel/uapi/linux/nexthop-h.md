Response:
Let's break down the thought process for analyzing the provided C header file `nexthop.h`.

**1. Initial Understanding and Context:**

* **Filename and Path:** `bionic/libc/kernel/uapi/linux/nexthop.handroid`. This immediately tells us it's a kernel header file (part of the `uapi` - user-space API) related to networking (`nexthop`) within the Android Bionic library. The `.handroid` suffix is likely a convention for Android-specific kernel headers.
* **Auto-generated:** The comment `/* This file is auto-generated. Modifications will be lost. */` is crucial. It means we shouldn't try to understand the implementation details within this *header* file itself. The actual logic resides in the kernel. This file serves as the *interface* for user-space programs to interact with the kernel's nexthop functionality.
* **Purpose of `uapi`:**  `uapi` headers provide the necessary data structures and definitions for user-space applications to interact with kernel functionalities. This means we're looking for definitions related to how user-space programs might configure or query routing information.

**2. Analyzing the Structure and Content:**

* **Header Guards:** `#ifndef _UAPI_LINUX_NEXTHOP_H` and `#define _UAPI_LINUX_NEXTHOP_H` are standard header guards to prevent multiple inclusions. This is a basic but important structural element.
* **Includes:** `#include <linux/types.h>` means this header relies on standard Linux type definitions (`__u32`, `__u8`, etc.).
* **`struct nhmsg`:** This structure likely represents a generic nexthop message. The fields (`nh_family`, `nh_scope`, `nh_protocol`, `nh_flags`) strongly suggest it's related to network routing configurations.
* **`struct nexthop_grp`:** The name suggests this defines a "nexthop group."  The fields `id`, `weight`, `weight_high` hint at load balancing or multi-path routing scenarios.
* **`enum` and `#define` for Group Types:**  `NEXTHOP_GRP_TYPE_MPATH` and `NEXTHOP_GRP_TYPE_RES` define the possible types of nexthop groups. `MPATH` likely stands for "multi-path," reinforcing the load balancing idea. `RES` is less clear without more context, but could be "reserved" or related to resource allocation.
* **`#define NHA_OP_FLAG_*`:** These are bit flags for "nexthop attribute operations." They indicate different actions or options when interacting with nexthop attributes, like dumping statistics.
* **`enum NHA_*`:** This is a crucial section. The `NHA_` prefix likely stands for "nexthop attribute."  These enumerations define the different *attributes* that can be associated with a nexthop entry or group. Examples include:
    * `NHA_ID`:  A unique identifier.
    * `NHA_GROUP`:  A reference to a nexthop group.
    * `NHA_GROUP_TYPE`: The type of the group (using the earlier `NEXTHOP_GRP_TYPE_*` enums).
    * `NHA_BLACKHOLE`:  Indicates traffic should be dropped.
    * `NHA_OIF`:  Output interface.
    * `NHA_GATEWAY`:  The next hop IP address.
    * `NHA_ENCAP_TYPE`, `NHA_ENCAP`: Related to encapsulation protocols (like tunnels).
    * `NHA_GROUPS`:  Potentially a list of groups.
    * `NHA_MASTER`:  Related to interface bonding or aggregation.
    * `NHA_FDB`: Forwarding Database (typically for bridging).
    * `NHA_RES_GROUP`, `NHA_RES_BUCKET`:  Likely related to the `NEXTHOP_GRP_TYPE_RES` and some form of resource management within the group.
    * `NHA_OP_FLAGS`:  Using the previously defined operation flags.
    * `NHA_GROUP_STATS`, `NHA_HW_STATS_ENABLE`, `NHA_HW_STATS_USED`: For retrieving statistics.
* **Nested `enum NHA_RES_GROUP_*` and `enum NHA_RES_BUCKET_*`:** These further specify attributes related to resource groups and their "buckets," hinting at a more granular management within those groups (like timers and indices).
* **`enum NHA_GROUP_STATS_*` and `enum NHA_GROUP_STATS_ENTRY_*`:**  Define the structure of statistics information related to nexthop groups, including packet counts.

**3. Connecting to Android:**

* **Networking Stack:** The presence of "nexthop" strongly suggests involvement in Android's networking stack. This header likely provides the interface for Android's routing and network management components to configure how network traffic is forwarded.
* **`libc` and Kernel Interaction:** This file is part of `bionic/libc`, indicating it's used by user-space processes. These definitions are used when making system calls (likely using the Netlink socket interface) to interact with the kernel's routing subsystem.
* **Examples:** Setting up multi-path routing for better performance or redundancy, configuring specific gateways for certain traffic, implementing network namespaces, and retrieving network statistics are all plausible uses.

**4. Predicting Functionality and Potential Issues:**

* **Functionality:**  The core function is to allow user-space to configure and query the kernel's nexthop forwarding behavior. This includes defining routes, grouping routes, setting weights for load balancing, and monitoring statistics.
* **Common Errors:**  Incorrectly setting attribute values (e.g., invalid interface indices), trying to configure conflicting routes, not handling errors from system calls, and misinterpreting the statistics data are all potential user errors.

**5. Considering Dynamic Linking (and realizing its limited relevance here):**

While the header is within `bionic`, the *definitions* themselves don't directly involve the dynamic linker. The linker is responsible for resolving symbols at runtime. The *use* of these definitions in system calls would be handled by `libc` functions, but the *header file itself* is primarily about data structures. Therefore, a detailed dynamic linking analysis is not directly applicable to this *header* file. The *functions* that use these structures (which are *not* in this header) would be subject to dynamic linking.

**6. Frida Hooking (Conceptual):**

To hook the usage of these structures, one would need to find the `libc` functions that interact with the kernel using these definitions. Likely candidates are functions related to Netlink socket communication (e.g., functions in `libnetlink.so`). Frida could be used to intercept calls to these functions, examine the arguments containing the `nhmsg` and `nexthop_grp` structures, and observe the flow of information.

**7. Structuring the Response:**

Finally, the information needs to be organized logically, starting with the core functionality, then explaining the details, providing examples, and addressing the specific points requested in the prompt (dynamic linking, errors, Frida). Using clear headings and bullet points makes the explanation easier to understand.

By following this thought process, breaking down the file into its components, and connecting those components to the broader context of Android networking and the `libc`, a comprehensive understanding of the header file's purpose and usage can be achieved. The key is to recognize that this is an *interface definition* and not the *implementation* itself.
这个文件 `bionic/libc/kernel/uapi/linux/nexthop.handroid` 是 Android Bionic 库中的一个头文件，它定义了与 Linux 内核中 "nexthop" 功能相关的用户空间 API (UAPI)。 `nexthop` 机制是 Linux 内核路由子系统的一部分，用于更灵活和高效地管理网络路由的下一跳信息，尤其是在策略路由、多路径路由等高级场景中。

**功能列举:**

该头文件定义了以下关键结构体、枚举和宏，用于与内核的 nexthop 功能进行交互：

1. **`struct nhmsg`**: 定义了通用的 nexthop 消息头部，包含：
   - `nh_family`:  地址族 (例如，AF_INET, AF_INET6)。
   - `nh_scope`:  路由的 scope (例如，链路本地、站点本地、全局)。
   - `nh_protocol`: 路由协议 (例如，RTPROT_STATIC, RTPROT_GATED)。
   - `resvd`:  保留字段。
   - `nh_flags`:  nexthop 的标志位。

2. **`struct nexthop_grp`**: 定义了 nexthop 组的信息，用于实现多路径路由或者链路聚合等功能。包含：
   - `id`:  组的唯一标识符。
   - `weight`:  此下一跳在组中的权重，用于负载均衡。
   - `weight_high`:  高位的权重，可能用于扩展权重范围。
   - `resvd2`: 保留字段。

3. **`enum` (匿名) 用于定义 nexthop 组的类型**:
   - `NEXTHOP_GRP_TYPE_MPATH`:  多路径组。
   - `NEXTHOP_GRP_TYPE_RES`:  资源预留组 (具体含义可能需要参考内核文档)。
   - `__NEXTHOP_GRP_TYPE_MAX`:  最大值。
   - `NEXTHOP_GRP_TYPE_MAX`:  实际最大值。

4. **`#define NHA_OP_FLAG_*`**: 定义了 nexthop 属性操作的标志位，例如：
   - `NHA_OP_FLAG_DUMP_STATS`:  用于请求转储统计信息。
   - `NHA_OP_FLAG_DUMP_HW_STATS`: 用于请求转储硬件统计信息。
   - `NHA_OP_FLAG_RESP_GRP_RESVD_0`:  响应组保留标志。

5. **`enum NHA_*`**: 定义了 nexthop 属性的类型，用于在与内核通信时指定要操作或查询的具体信息。这些属性可以附加到 nexthop 或 nexthop 组上。例如：
   - `NHA_UNSPEC`: 未指定。
   - `NHA_ID`:  nexthop 的 ID。
   - `NHA_GROUP`:  nexthop 所属的组。
   - `NHA_GROUP_TYPE`:  nexthop 组的类型。
   - `NHA_BLACKHOLE`:  表示这是一个黑洞路由（丢弃所有流量）。
   - `NHA_OIF`:  输出接口索引。
   - `NHA_GATEWAY`:  下一跳网关地址。
   - `NHA_ENCAP_TYPE`:  封装类型 (例如，GRE, IPIP)。
   - `NHA_ENCAP`:  封装信息。
   - `NHA_GROUPS`:  相关的 nexthop 组列表。
   - `NHA_MASTER`:  主设备 (例如，用于 bonding)。
   - `NHA_FDB`:  转发数据库 (通常用于 bridge)。
   - `NHA_RES_GROUP`:  资源预留组相关属性。
   - `NHA_RES_BUCKET`:  资源预留桶相关属性。
   - `NHA_OP_FLAGS`:  操作标志。
   - `NHA_GROUP_STATS`:  nexthop 组的统计信息。
   - `NHA_HW_STATS_ENABLE`:  启用硬件统计。
   - `NHA_HW_STATS_USED`:  是否使用硬件统计。

6. **`enum NHA_RES_GROUP_*`**: 定义了资源预留组的属性。

7. **`enum NHA_RES_BUCKET_*`**: 定义了资源预留桶的属性。

8. **`enum NHA_GROUP_STATS_*`**: 定义了 nexthop 组统计信息的属性。

9. **`enum NHA_GROUP_STATS_ENTRY_*`**: 定义了 nexthop 组统计信息条目的属性。

**与 Android 功能的关系及举例说明:**

`nexthop` 功能直接关系到 Android 设备的网络路由管理，尤其是在以下方面：

* **策略路由 (Policy-Based Routing, PBR):** Android 可以使用 `nexthop` 来实现更精细的路由策略，根据源/目标地址、端口等信息将流量路由到不同的下一跳。例如，可以将特定应用的流量路由到特定的 VPN 接口。
* **多路径 TCP (MPTCP):**  虽然这个头文件本身不直接定义 MPTCP，但 `nexthop` 的多路径组功能可以作为 MPTCP 的底层支持，允许数据包通过多个路径发送和接收，提高带宽和可靠性。
* **网络命名空间 (Network Namespaces):** Android 使用网络命名空间隔离不同的网络环境。`nexthop` 配置可能需要在不同的命名空间中进行，以实现不同命名空间之间的路由隔离。
* **VPN 和网络接口管理:** 当 Android 设备连接到 VPN 或有多个网络接口时，`nexthop` 可以用于配置复杂的路由规则，确保流量通过正确的接口和网关。
* **流量工程 (Traffic Engineering):** 通过 `nexthop` 组的权重设置，可以实现简单的流量负载均衡，将流量分配到多个可用的下一跳。

**举例说明:**

假设一个 Android 应用需要通过特定的 VPN 连接发送数据。Android 的网络服务可以使用 `nexthop` 功能配置一条路由规则：

1. 使用 `struct nhmsg` 指定匹配的流量特征（例如，源应用 UID）。
2. 使用 `NHA_OIF` 指定 VPN 接口作为输出接口。
3. 使用 `NHA_GATEWAY` 指定 VPN 服务器的 IP 地址作为下一跳网关。

对于多路径路由的例子，可以创建一个 `NEXTHOP_GRP_TYPE_MPATH` 类型的 nexthop 组，包含多个可用的下一跳 (例如，通过不同的网络接口)。每个下一跳都有一个权重，内核会根据权重将流量分配到不同的路径。

**libc 函数功能实现解释:**

这个头文件本身定义的是数据结构和常量，**不是 libc 函数的实现**。  libc 中与 `nexthop` 功能交互的函数通常是封装了与内核 Netlink 接口通信的系统调用。  这些函数会构建包含 `struct nhmsg` 和各种 `NHA_*` 属性的消息，通过 Netlink 套接字发送给内核，并解析内核返回的响应。

常见的 libc 函数可能包括：

* **`socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`:**  创建一个 Netlink 套接字，用于与内核的路由子系统通信。
* **`sendto()`/`recvfrom()`:**  通过 Netlink 套接字发送和接收消息。
* **封装 Netlink 消息的辅助函数:**  这些函数会根据用户的配置构建符合 Netlink 协议格式的消息，包括 `nlmsghdr`、`rtattr` 等结构，并将 `struct nhmsg` 和各种 `NHA_*` 属性打包到消息中。

**详细解释 libc 函数的实现需要查看 Bionic 的源代码，而不是这个头文件。**  Bionic 的网络相关的代码会使用这些头文件中定义的结构体来构造和解析与内核通信的消息。

**涉及 dynamic linker 的功能，so 布局样本，以及链接的处理过程:**

这个头文件定义的是内核 UAPI，主要用于定义内核与用户空间程序之间交互的数据结构。它本身**不直接涉及 dynamic linker 的功能**。

Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是：

1. **加载共享库 (SO 文件):**  当程序启动时，加载器会加载程序依赖的共享库到内存中。
2. **符号解析:**  解析程序和共享库之间的符号引用，将函数调用等绑定到实际的内存地址。
3. **重定位:**  调整共享库中与地址相关的代码和数据，使其在内存中的实际加载地址生效。

虽然这个头文件中的定义会被 Bionic 的网络相关的共享库（例如，`libc.so` 或其他与网络相关的 SO 文件）使用，但 **这个头文件本身不是一个 SO 文件，也不需要被动态链接**。

**SO 布局样本 (以 `libc.so` 为例):**

```
libc.so:
  .text         # 可执行代码段
  .rodata       # 只读数据段 (可能包含字符串常量等)
  .data         # 已初始化数据段
  .bss          # 未初始化数据段
  .dynamic      # 动态链接信息段
  .dynsym       # 动态符号表
  .dynstr       # 动态字符串表
  .plt          # 程序链接表 (Procedure Linkage Table)
  .got.plt      # 全局偏移量表 (Global Offset Table)
  ...
```

**链接的处理过程 (以 `libc.so` 中使用 `nexthop.h` 定义的函数为例):**

1. **编译时:**  当编译使用 `nexthop.h` 中定义的结构体的代码时，编译器会根据这些定义生成相应的机器码。如果代码中调用了与 `nexthop` 交互的 libc 函数（例如，封装了 Netlink 通信的函数），编译器会生成对这些函数的未解析引用。

2. **链接时:**  静态链接器会将编译后的目标文件链接成可执行文件或共享库。对于对 libc 函数的引用，静态链接器通常会将它们标记为需要动态链接。

3. **运行时 (动态链接):**
   - 当程序启动时，动态链接器会加载程序依赖的 `libc.so`。
   - 动态链接器会解析程序中对 libc 函数的未解析引用。它会查找 `libc.so` 的 `.dynsym` 段中的符号表，找到对应函数的地址。
   - 动态链接器会将找到的函数地址填入程序的 `.got.plt` 表中，这样程序在调用这些函数时，实际上会通过 `.got.plt` 跳转到 `libc.so` 中函数的实际地址。

**逻辑推理，假设输入与输出:**

由于这个文件是头文件，不包含实际的逻辑执行代码，因此很难进行逻辑推理并给出假设输入和输出。其作用是定义数据结构，供其他程序使用。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **内存管理错误:**  在使用涉及 `nexthop` 属性的函数时，如果需要分配内存来存储属性数据，用户可能会忘记释放内存，导致内存泄漏。

   ```c
   // 假设有这样一个函数来设置 nexthop 的 gateway
   int set_nexthop_gateway(int nh_id, const struct sockaddr *gateway);

   // 错误示例：忘记释放 sockaddr 结构体的内存
   struct sockaddr_in *gw = malloc(sizeof(struct sockaddr_in));
   // ... 初始化 gw ...
   set_nexthop_gateway(123, (struct sockaddr *)gw);
   // 缺少 free(gw);
   ```

2. **属性类型和大小错误:**  在构建 Netlink 消息时，如果传递了错误的属性类型或大小，内核可能会拒绝该消息，或者导致未定义的行为。

   ```c
   // 假设有函数用于添加 nexthop 属性
   int add_nexthop_attr(struct nlmsghdr *nlh, int attr_type, const void *data, int data_len);

   // 错误示例：attr_type 错误
   uint32_t group_id = 10;
   add_nexthop_attr(nlh, NHA_OIF, &group_id, sizeof(group_id)); // 应该使用 NHA_GROUP
   ```

3. **权限问题:**  配置网络路由通常需要 root 权限。如果程序没有足够的权限，相关的系统调用将会失败。

4. **Netlink 消息构建错误:**  Netlink 消息的结构比较复杂，如果构建消息时出现错误（例如，头部信息不正确，属性嵌套错误），内核将无法正确解析。

5. **错误处理不足:**  与内核交互的系统调用可能会失败，用户程序需要检查返回值并进行适当的错误处理。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

Android Framework 或 NDK 应用要使用 `nexthop` 功能，通常需要经过以下步骤：

1. **NDK 应用 (C/C++):**
   - NDK 应用可以直接包含 `<linux/nexthop.h>` 头文件（该文件可能被复制到 NDK 的 sysroot 中）。
   - 应用会使用标准的 Linux 网络编程接口，例如 `socket(AF_NETLINK, ...)` 创建 Netlink 套接字。
   - 应用会使用 Bionic 库中提供的函数（或者自己实现）来构建和发送 Netlink 消息，其中会使用 `struct nhmsg` 和 `NHA_*` 等定义。

2. **Android Framework (Java/Kotlin):**
   - Android Framework 通常不会直接使用这些底层的内核头文件。
   - Framework 会通过 System Services (例如，`ConnectivityService`) 间接与内核交互。
   - Framework 的 Java/Kotlin 代码会调用 JNI (Java Native Interface) 方法，这些 JNI 方法会调用 Native 代码 (C/C++)，最终调用到 Bionic 库中与 Netlink 交互的函数。

**Frida Hook 示例调试步骤:**

假设我们要 hook 一个 NDK 应用中设置 nexthop gateway 的操作。我们可以 hook Bionic 库中可能被使用的底层函数，例如 `sendto` 系统调用，或者更具体的封装了 Netlink 消息发送的函数（需要通过逆向工程确定）。

**Frida Hook 代码示例 (Hook `sendto`):**

```python
import frida
import sys

package_name = "your.ndk.app.package"

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please launch the app.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
    onEnter: function (args) {
        const sockfd = args[0].toInt32();
        const buf = args[1];
        const len = args[2].toInt32();
        const flags = args[3].toInt32();
        const dest_addr = args[4];
        const addrlen = args[5].toInt32();

        // 检查是否是 Netlink 套接字 (需要根据实际情况判断)
        // 例如，检查 dest_addr 的 sa_family 是否是 AF_NETLINK
        const sa_family = dest_addr.readU16();
        if (sa_family === 18) { // AF_NETLINK
            console.log("[*] sendto called with Netlink socket");
            console.log("    sockfd:", sockfd);
            console.log("    len:", len);

            // 可以进一步解析 buf 中的 Netlink 消息，查看是否包含 nexthop 相关信息
            // 这需要了解 Netlink 消息的结构
            const nlmsghdr = buf.readByteArray(16); // 假设 nlmsghdr 至少 16 字节
            console.log("    Netlink Header:", hexdump(nlmsghdr));
        }
    },
    onLeave: function (retval) {
        console.log("[*] sendto returned:", retval.toInt32());
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

1. **`frida.attach(package_name)`:** 连接到目标 NDK 应用进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "sendto"), ...)`:**  Hook `libc.so` 中的 `sendto` 函数。
3. **`onEnter`:** 在 `sendto` 函数被调用时执行。
4. **参数解析:**  获取 `sendto` 函数的参数，例如套接字描述符、发送缓冲区、长度等。
5. **Netlink 检查:**  尝试判断是否是 Netlink 套接字，例如检查目标地址的地址族。
6. **消息解析 (进阶):**  读取发送缓冲区的内容，并尝试解析 Netlink 消息头部，查看是否包含与 `nexthop` 相关的属性。这需要对 Netlink 消息的结构有深入的了解。
7. **`onLeave`:** 在 `sendto` 函数返回时执行。

**更精细的 Hook:**

要 hook 更具体的 `nexthop` 配置过程，可能需要：

1. **逆向工程:**  分析 NDK 应用或 Android Framework 中负责网络配置的代码，找到它们调用的 Bionic 库函数。
2. **Hook 特定函数:**  Hook 封装了 Netlink 消息构建和发送的特定函数，而不是通用的 `sendto`。
3. **解析 Netlink 消息:**  编写更复杂的 Frida 脚本来解析 Netlink 消息的结构，提取 `struct nhmsg` 和 `NHA_*` 属性的值。

通过 Frida hook，可以动态地观察 Android 系统如何使用这些内核数据结构进行网络配置，帮助理解其工作原理和调试相关问题。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/nexthop.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_NEXTHOP_H
#define _UAPI_LINUX_NEXTHOP_H
#include <linux/types.h>
struct nhmsg {
  unsigned char nh_family;
  unsigned char nh_scope;
  unsigned char nh_protocol;
  unsigned char resvd;
  unsigned int nh_flags;
};
struct nexthop_grp {
  __u32 id;
  __u8 weight;
  __u8 weight_high;
  __u16 resvd2;
};
enum {
  NEXTHOP_GRP_TYPE_MPATH,
  NEXTHOP_GRP_TYPE_RES,
  __NEXTHOP_GRP_TYPE_MAX,
};
#define NEXTHOP_GRP_TYPE_MAX (__NEXTHOP_GRP_TYPE_MAX - 1)
#define NHA_OP_FLAG_DUMP_STATS BIT(0)
#define NHA_OP_FLAG_DUMP_HW_STATS BIT(1)
#define NHA_OP_FLAG_RESP_GRP_RESVD_0 BIT(31)
enum {
  NHA_UNSPEC,
  NHA_ID,
  NHA_GROUP,
  NHA_GROUP_TYPE,
  NHA_BLACKHOLE,
  NHA_OIF,
  NHA_GATEWAY,
  NHA_ENCAP_TYPE,
  NHA_ENCAP,
  NHA_GROUPS,
  NHA_MASTER,
  NHA_FDB,
  NHA_RES_GROUP,
  NHA_RES_BUCKET,
  NHA_OP_FLAGS,
  NHA_GROUP_STATS,
  NHA_HW_STATS_ENABLE,
  NHA_HW_STATS_USED,
  __NHA_MAX,
};
#define NHA_MAX (__NHA_MAX - 1)
enum {
  NHA_RES_GROUP_UNSPEC,
  NHA_RES_GROUP_PAD = NHA_RES_GROUP_UNSPEC,
  NHA_RES_GROUP_BUCKETS,
  NHA_RES_GROUP_IDLE_TIMER,
  NHA_RES_GROUP_UNBALANCED_TIMER,
  NHA_RES_GROUP_UNBALANCED_TIME,
  __NHA_RES_GROUP_MAX,
};
#define NHA_RES_GROUP_MAX (__NHA_RES_GROUP_MAX - 1)
enum {
  NHA_RES_BUCKET_UNSPEC,
  NHA_RES_BUCKET_PAD = NHA_RES_BUCKET_UNSPEC,
  NHA_RES_BUCKET_INDEX,
  NHA_RES_BUCKET_IDLE_TIME,
  NHA_RES_BUCKET_NH_ID,
  __NHA_RES_BUCKET_MAX,
};
#define NHA_RES_BUCKET_MAX (__NHA_RES_BUCKET_MAX - 1)
enum {
  NHA_GROUP_STATS_UNSPEC,
  NHA_GROUP_STATS_ENTRY,
  __NHA_GROUP_STATS_MAX,
};
#define NHA_GROUP_STATS_MAX (__NHA_GROUP_STATS_MAX - 1)
enum {
  NHA_GROUP_STATS_ENTRY_UNSPEC,
  NHA_GROUP_STATS_ENTRY_ID,
  NHA_GROUP_STATS_ENTRY_PACKETS,
  NHA_GROUP_STATS_ENTRY_PACKETS_HW,
  __NHA_GROUP_STATS_ENTRY_MAX,
};
#define NHA_GROUP_STATS_ENTRY_MAX (__NHA_GROUP_STATS_ENTRY_MAX - 1)
#endif
```