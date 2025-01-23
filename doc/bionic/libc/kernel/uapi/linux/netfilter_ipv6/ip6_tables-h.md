Response:
Let's break down the thought process for analyzing this C header file.

1. **Identify the Purpose:** The first and most crucial step is understanding the file's context. The prompt explicitly states it's from `bionic/libc/kernel/uapi/linux/netfilter_ipv6/ip6_tables.handroid`. This immediately tells us several things:
    * **Bionic:** It's part of Android's core C library.
    * **libc/kernel/uapi:** It's an interface between user-space (Android apps/framework) and the Linux kernel. The `uapi` directory is key here – it signifies user-space visible definitions.
    * **linux/netfilter_ipv6/ip6_tables:**  It relates to IPv6 network filtering within the Linux kernel. Netfilter is Linux's firewall framework, and `ip6_tables` is its IPv6 component. The `.handroid` suffix likely indicates Android-specific modifications or arrangements of standard kernel headers.

2. **High-Level Overview:** Before diving into details, form a general idea of what this file is about. Based on the path, it's about defining structures and constants for interacting with the IPv6 firewall from user space. This interaction likely involves setting up rules, querying information, and potentially managing the firewall.

3. **Scan for Key Components:**  Quickly scan the code for common C constructs that reveal functionality:
    * **`#define` macros:** These define constants, which are often used for flags, sizes, and control commands. Notice the prevalence of `XT_` prefixes, indicating a relationship with the `x_tables` framework (a generic table structure within Netfilter).
    * **`struct` definitions:** These represent data structures used to exchange information between user space and the kernel. Pay attention to the member names, as they often hint at their purpose (e.g., `src`, `dst`, `iniface`, `outiface`).
    * **`typedef` (though absent here):**  Would be another indicator of data types.
    * **Function-like macros (e.g., `IP6T_ENTRY_INIT`):** These are shortcuts for initializing structures.
    * **`static __inline__` functions:** These are small helper functions that are usually inlined for performance.

4. **Categorize Functionality (Implicit):** Although the file doesn't define functions directly (it's a header), the *structures* and *macros* implicitly define the functionality that can be performed. Think in terms of the actions a firewall administrator or a network application might need to take:
    * **Defining Rules:** The structures like `ip6t_ip6`, `ip6t_entry`, and related macros seem to be used for specifying matching criteria and actions for network packets.
    * **Managing Tables:** Structures like `ip6t_getinfo` and `ip6t_replace` suggest operations for retrieving information about and modifying the firewall rule tables.
    * **Counters:** The `xt_counters` structure indicates the ability to track packet and byte counts for rules.
    * **Error Handling:** `ip6t_error_target` suggests a mechanism for handling packets that match certain criteria by generating errors.

5. **Analyze Individual Components:** Now, go through each significant block of code more carefully:
    * **Includes:** Note the included headers (`linux/types.h`, `linux/compiler.h`, etc.). These provide fundamental data types and compiler directives. The `linux/netfilter_ipv6.h` and `linux/netfilter/x_tables.h` are particularly important, confirming the Netfilter context.
    * **Macro Mappings:**  Observe how `IP6T_` macros are often aliases for `XT_` macros. This shows the layering of `ip6_tables` on top of the more generic `x_tables` framework.
    * **Core Structures:**  Examine the `ip6t_ip6`, `ip6t_entry`, `ip6t_standard`, `ip6t_error`, `ip6t_icmp`, `ip6t_getinfo`, `ip6t_replace`, and `ip6t_get_entries` structures in detail. Understand the meaning of each member. For example, in `ip6t_ip6`, `src` and `dst` are source and destination IPv6 addresses, `iniface` and `outiface` are interface names, and `proto` is the protocol number.
    * **Flag Macros:** Understand the purpose of macros like `IP6T_F_PROTO`, `IP6T_INV_VIA_IN`, etc. These define the bits within the `flags` and `invflags` members of the structures, allowing for specific matching conditions.
    * **Control Commands:** The `IP6T_SO_SET_*` and `IP6T_SO_GET_*` macros represent socket options used to interact with the `ip6_tables` module.

6. **Relate to Android:** Consider how this kernel-level functionality relates to Android. Android uses the Linux kernel, so these Netfilter features are directly available. Think about scenarios where Android would need to interact with the firewall:
    * **Firewall Apps:** Applications that manage firewall rules for the user.
    * **VPN Clients:**  Setting up rules to route traffic through the VPN interface.
    * **Network Management:**  System services that might configure firewall rules for specific network configurations.
    * **Tethering:** Setting up forwarding rules for shared internet connections.

7. **Address Specific Prompts:**  Go back to the original request and ensure each point is addressed:
    * **Functionality Listing:** Summarize the identified capabilities.
    * **Android Examples:** Provide concrete scenarios of Android usage.
    * **`libc` Function Explanation:**  Recognize that this header *defines* interfaces but doesn't *implement* `libc` functions. The interaction happens through system calls, and the header provides the data structures for those calls.
    * **Dynamic Linker:** Note the absence of direct dynamic linker involvement in *this header file*. The actual `ip6tables` user-space utility and other network tools *will* be linked, but this header just provides the definitions for interacting with the kernel module.
    * **Logical Reasoning:**  Consider how different parts of the structures and macros interact to define a firewall rule.
    * **Common Errors:** Think about potential mistakes developers might make when using these structures (e.g., incorrect size calculations, flag manipulation).
    * **Android Framework/NDK Path:** Trace how a user-space request might reach this kernel header (via `ioctl` system calls initiated by Android framework components or NDK libraries).
    * **Frida Hooking:** Suggest points where hooking could be useful (system calls related to `ip6tables`).

8. **Structure and Refine:** Organize the findings into a clear and coherent answer, using headings and bullet points for readability. Explain technical terms where necessary. Ensure the language is precise and avoids jargon where possible.

Self-Correction/Refinement During the Process:

* **Initial thought:** "This file *implements* firewall functions."  **Correction:** This is a *header* file. It *defines* the interface, but the actual implementation is in the Linux kernel.
* **Initial thought:** "Let me explain how `malloc` works, since it's part of `libc`." **Correction:** This header doesn't directly involve standard `libc` functions like `malloc`. The memory allocation for these structures likely happens within the kernel or in user-space tools using these definitions.
* **Realization about Dynamic Linking:**  Initially, one might think this file has direct dynamic linking aspects. **Correction:** The dynamic linking happens at a higher level (user-space tools). This header just defines the data structures used in the system calls that those tools will make.

By following this systematic approach, you can effectively analyze complex C header files and understand their role within a larger system like Android.
这个C头文件 `bionic/libc/kernel/uapi/linux/netfilter_ipv6/ip6_tables.handroid` 定义了用户空间程序与Linux内核中IPv6网络过滤模块 (`ip6tables`) 交互时使用的数据结构和常量。它属于Android Bionic库的一部分，目的是为Android系统提供访问底层内核功能的接口。

**功能列举:**

1. **定义了与IPv6网络过滤规则相关的结构体:**
   - `ip6t_ip6`: 描述了IPv6报文的头部信息，用于规则匹配，包括源地址、目的地址、接口、协议等。
   - `ip6t_entry`: 代表一个独立的防火墙规则条目，包含了匹配条件 (`ip6t_ip6`)、计数器、目标动作等。
   - `ip6t_standard`: 代表一个标准的规则目标，例如 `ACCEPT`、`DROP`。
   - `ip6t_error`: 代表一个错误处理目标。
   - `ip6t_icmp`:  用于匹配ICMPv6报文的类型和代码。
   - `ip6t_getinfo`:  用于获取`ip6tables`表的信息。
   - `ip6t_replace`: 用于替换整个`ip6tables`表的内容。
   - `ip6t_get_entries`: 用于获取`ip6tables`表的所有规则条目。

2. **定义了与规则匹配和目标相关的结构体 (来自 `x_tables.h`):**
   - `xt_match`:  定义了规则的匹配器。
   - `xt_target`: 定义了规则的目标动作。
   - `xt_standard_target`:  定义了标准的目标动作 (如 ACCEPT, DROP)。
   - `xt_error_target`: 定义了错误目标动作。
   - `xt_counters`: 定义了规则的计数器 (包数和字节数)。
   - `xt_tcp`:  用于匹配TCP协议的特定字段 (端口、标志位等)。
   - `xt_udp`:  用于匹配UDP协议的特定字段 (端口)。
   - `xt_counters_info`:  包含计数器信息的结构体。

3. **定义了各种宏常量:**
   - `IP6T_FUNCTION_MAXNAMELEN`, `IP6T_TABLE_MAXNAMELEN`: 定义了函数名和表名的最大长度。
   - `IP6T_CONTINUE`, `IP6T_RETURN`:  定义了规则目标动作的返回值。
   - `IP6T_F_*`, `IP6T_INV_*`: 定义了 `ip6t_ip6` 结构体中 `flags` 和 `invflags` 字段的标志位，用于指定要匹配的字段以及是否取反。
   - `IP6T_SO_SET_*`, `IP6T_SO_GET_*`: 定义了用于与内核模块交互的socket选项。
   - `IP6T_BASE_CTL`:  定义了 `ip6tables` 相关 socket 选项的基础值。

4. **定义了用于遍历规则条目的宏:**
   - `IP6T_MATCH_ITERATE`: 遍历规则条目中的匹配器。
   - `IP6T_ENTRY_ITERATE`: 遍历规则表中的所有规则条目。

5. **定义了初始化宏:**
   - `IP6T_ENTRY_INIT`: 初始化 `ip6t_entry` 结构体。
   - `IP6T_STANDARD_INIT`: 初始化 `ip6t_standard` 结构体。
   - `IP6T_ERROR_INIT`: 初始化 `ip6t_error` 结构体。

6. **定义了内联函数:**
   - `ip6t_get_target`:  根据 `ip6t_entry` 结构体获取其目标动作的指针。

**与Android功能的关联及举例说明:**

这个头文件是Android网络功能的基础组成部分，因为它允许用户空间程序配置和管理Android设备的IPv6防火墙。

* **Android防火墙应用:**  像NetGuard这样的Android防火墙应用，会使用这些结构体和常量，通过系统调用与内核中的 `ip6tables` 模块通信，从而实现对应用网络访问的控制。例如，NetGuard可能创建一个 `ip6t_entry` 结构体来阻止特定应用访问特定的IPv6地址或端口。

* **VPN客户端:** VPN客户端在连接时，可能需要添加或修改 `ip6tables` 规则来路由特定的网络流量通过VPN隧道。它们会使用这里的结构体来定义这些规则。

* **网络共享 (Tethering):**  当Android设备作为热点共享网络时，系统会配置 `ip6tables` 来转发数据包。相关的配置会使用到这里定义的结构体。

* **系统服务:** Android的系统服务，例如负责网络管理的 `netd` 守护进程，会使用这些接口来配置设备的网络策略，包括防火墙规则。

**libc函数的功能实现:**

这个头文件本身并没有实现任何 `libc` 函数。它只是定义了数据结构和常量。用户空间程序使用这些定义构建数据，然后通过系统调用（例如 `socket` 创建套接字，`setsockopt` 设置 socket 选项， `ioctl` 进行更底层的控制）与内核中的 `ip6tables` 模块进行交互。

例如，要添加一条防火墙规则，用户空间程序会：

1. 填充一个 `ip6t_replace` 结构体，其中包含要添加的规则的 `ip6t_entry` 结构体。
2. 调用 `socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)` 或类似的函数创建一个套接字。
3. 使用 `setsockopt(sockfd, SOL_IP6, IP6T_SO_SET_REPLACE, ...)` 系统调用，将填充好的 `ip6t_replace` 结构体传递给内核。

内核中的 `ip6tables` 模块会解析这些数据结构，并将其转化为内核中防火墙规则的表示。

**涉及dynamic linker的功能:**

这个头文件本身并不直接涉及动态链接器。然而，使用这些定义的应用程序或库 *会* 被动态链接器处理。

**so布局样本:**

假设有一个名为 `libnetfilter_ipv6.so` 的共享库，它封装了与 `ip6tables` 交互的功能。它的布局可能如下：

```
libnetfilter_ipv6.so:
    .text          # 代码段，包含函数实现
    .rodata        # 只读数据段，可能包含常量字符串
    .data          # 可读写数据段，可能包含全局变量
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .rel.dyn       # 动态重定位表
    .rel.plt       # PLT (Procedure Linkage Table) 重定位表
```

**链接的处理过程:**

1. **编译时:** 应用程序在编译时，编译器会识别出对 `libnetfilter_ipv6.so` 中函数的调用，并在其目标文件中生成对这些符号的未解析引用。

2. **链接时:** 链接器（通常是 `ld`）会将应用程序的目标文件与 `libnetfilter_ipv6.so` 链接在一起。动态链接的情况下，链接器不会将库的代码完全复制到应用程序中，而是在应用程序的可执行文件中记录下对共享库的依赖关系和需要解析的符号。

3. **运行时:** 当应用程序启动时，Android的动态链接器 (`linker64` 或 `linker`) 会：
   - 加载应用程序的可执行文件。
   - 检查应用程序依赖的共享库列表。
   - 加载 `libnetfilter_ipv6.so` 到内存中。
   - 解析应用程序中对 `libnetfilter_ipv6.so` 中符号的引用，将这些引用指向库中相应的函数地址。这通常通过PLT和GOT (Global Offset Table) 完成。

**假设输入与输出 (逻辑推理):**

假设用户空间程序要添加一条规则，允许来自 `2001:db8::1` 的所有TCP流量到达目标地址 `2001:db8::2` 的端口 `80`。

**假设输入 (构建 `ip6t_replace` 结构体):**

```c
struct ip6t_replace replace = {
    .name = "filter", // 表名
    .valid_hooks = (1 << 0), // 关联到 INPUT hook
    .num_entries = 1,
    .size = sizeof(struct ip6t_standard),
    .hook_entry = { 0 }, // 从表的起始位置开始
    .underflow = { 0 },
    .num_counters = 0,
    .counters = NULL,
    .entries = { // 规则条目
        {
            .entry = {
                .ipv6 = {
                    .src = { { { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }, // 2001:db8::1
                    .dst = { { { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } } }, // 2001:db8::2
                    .smsk = { 0 },
                    .dmsk = { 0 },
                    .proto = IPPROTO_TCP,
                    .flags = IP6T_F_PROTO,
                    .invflags = 0,
                },
                .target_offset = sizeof(struct ip6t_entry),
                .next_offset = sizeof(struct ip6t_standard),
                .comefrom = 0,
                .counters = { 0, 0 },
                .elems = { 0 } // 后续添加匹配器和目标
            },
            .target = {
                .u = {
                    .user = {
                        .name = "ACCEPT",
                        .revision = 0,
                    }
                },
                .target_size = sizeof(struct xt_standard_target),
            }
        }
    }
};
// 需要进一步填充 TCP 匹配器到 elems 数组中，这里简化
```

**假设输出 (内核操作):**

内核中的 `ip6tables` 模块会解析这个 `replace` 结构体，并在 `filter` 表的 `INPUT` 链上添加一条新的规则：当接收到的IPv6数据包的源地址为 `2001:db8::1`，目的地址为 `2001:db8::2`，且协议为TCP时，执行 `ACCEPT` 动作。如果成功，系统调用会返回 `0`。

**用户或编程常见的使用错误:**

1. **结构体大小计算错误:** 在填充 `ip6t_replace` 或其他结构体时，如果 `size` 字段计算错误，可能会导致内核解析数据失败或崩溃。
2. **标志位设置错误:** `flags` 和 `invflags` 的设置不当会导致规则匹配逻辑错误。例如，忘记设置 `IP6T_F_PROTO` 标志可能导致协议匹配失效。
3. **内存管理错误:**  在使用涉及到内存分配的 socket 选项时（例如 `IP6T_SO_GET_ENTRIES`），如果用户空间程序没有正确分配和释放内存，可能导致内存泄漏或程序崩溃。
4. **权限不足:**  修改 `ip6tables` 需要 root 权限。普通应用尝试设置这些选项会失败。
5. **Netfilter模块未加载:** 如果内核中没有加载 `ip6_tables` 模块，相关的 socket 选项调用会失败。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework:**
   - Android Framework 中的网络管理服务（例如 `NetworkManagementService`）或 Connectivity 服务可能需要配置防火墙规则。
   - 这些服务通常会调用底层的 JNI (Java Native Interface) 代码。
   - JNI 代码会调用 NDK 提供的 C/C++ 接口。

2. **NDK (Native Development Kit):**
   - NDK 提供了访问 Linux 系统调用的接口。
   - 一些底层的网络库（例如 `libcutils` 或自定义的库）可能会封装与 `ip6tables` 交互的逻辑。
   - 这些库会使用 `socket` 创建套接字，然后使用 `setsockopt` 或 `ioctl` 系统调用，并传入用这个头文件中定义的结构体填充的数据。

**Frida Hook 示例调试步骤:**

可以使用 Frida Hook 来观察 Android 进程如何与 `ip6tables` 交互。以下是一个示例，hook `setsockopt` 系统调用，并筛选与 `IP6T_SO_SET_REPLACE` 相关的调用：

```python
import frida
import sys

package_name = "your.target.package"  # 替换为目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "setsockopt"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var level = args[1].toInt32();
        var optname = args[2].toInt32();

        if (level == 119 /* SOL_IP */ || level == 41 /* SOL_IPV6 */) {
            if (optname == 64 /* IP6T_SO_SET_REPLACE */) {
                console.log("[*] setsockopt called with IP6T_SO_SET_REPLACE");
                console.log("    sockfd:", sockfd);
                console.log("    level:", level);
                console.log("    optname:", optname);

                // 可以进一步读取 optval 的内容，解析 ip6t_replace 结构体
                var optval = args[3];
                var optlen = args[4].toInt32();
                console.log("    optlen:", optlen);

                // 读取 ip6t_replace 结构体的内容 (需要根据结构体定义来解析)
                // 例如读取表名:
                var namePtr = optval.readPointer();
                if (namePtr.isNull() === false) {
                    var name = namePtr.readCString();
                    console.log("    Table Name:", name);
                }
            }
        }
    },
    onLeave: function(retval) {
        console.log("[*] setsockopt returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤说明:**

1. **导入 Frida 库:**  在 Python 脚本中导入 Frida 库。
2. **连接到目标进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到要监控的 Android 进程。
3. **编写 Frida 脚本:**
   - 使用 `Interceptor.attach` hook `libc.so` 中的 `setsockopt` 函数。
   - 在 `onEnter` 中，检查 `level` 是否为 `SOL_IP` 或 `SOL_IPV6`，并且 `optname` 是否为 `IP6T_SO_SET_REPLACE`。
   - 如果条件满足，打印相关信息，例如 socket 文件描述符、选项名称等。
   - 可以进一步读取 `optval` 指向的内存，解析 `ip6t_replace` 结构体的内容。这需要你了解结构体的布局。
   - 在 `onLeave` 中，打印 `setsockopt` 的返回值。
4. **加载和运行脚本:** 使用 `session.create_script` 创建脚本，设置消息处理回调，加载脚本，并保持脚本运行。

通过这个 Frida Hook 示例，你可以观察到目标应用在尝试设置 `ip6tables` 规则时，传递给 `setsockopt` 的参数，从而了解它是如何使用这些数据结构和常量的。你可以根据需要 hook 其他相关的 socket 选项或系统调用，以更全面地了解其交互过程。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter_ipv6/ip6_tables.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_IP6_TABLES_H
#define _UAPI_IP6_TABLES_H
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/if.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#define IP6T_FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define IP6T_TABLE_MAXNAMELEN XT_TABLE_MAXNAMELEN
#define ip6t_match xt_match
#define ip6t_target xt_target
#define ip6t_table xt_table
#define ip6t_get_revision xt_get_revision
#define ip6t_entry_match xt_entry_match
#define ip6t_entry_target xt_entry_target
#define ip6t_standard_target xt_standard_target
#define ip6t_error_target xt_error_target
#define ip6t_counters xt_counters
#define IP6T_CONTINUE XT_CONTINUE
#define IP6T_RETURN XT_RETURN
#include <linux/netfilter/xt_tcpudp.h>
#define ip6t_tcp xt_tcp
#define ip6t_udp xt_udp
#define IP6T_TCP_INV_SRCPT XT_TCP_INV_SRCPT
#define IP6T_TCP_INV_DSTPT XT_TCP_INV_DSTPT
#define IP6T_TCP_INV_FLAGS XT_TCP_INV_FLAGS
#define IP6T_TCP_INV_OPTION XT_TCP_INV_OPTION
#define IP6T_TCP_INV_MASK XT_TCP_INV_MASK
#define IP6T_UDP_INV_SRCPT XT_UDP_INV_SRCPT
#define IP6T_UDP_INV_DSTPT XT_UDP_INV_DSTPT
#define IP6T_UDP_INV_MASK XT_UDP_INV_MASK
#define ip6t_counters_info xt_counters_info
#define IP6T_STANDARD_TARGET XT_STANDARD_TARGET
#define IP6T_ERROR_TARGET XT_ERROR_TARGET
#define IP6T_MATCH_ITERATE(e,fn,args...) XT_MATCH_ITERATE(struct ip6t_entry, e, fn, ##args)
#define IP6T_ENTRY_ITERATE(entries,size,fn,args...) XT_ENTRY_ITERATE(struct ip6t_entry, entries, size, fn, ##args)
struct ip6t_ip6 {
  struct in6_addr src, dst;
  struct in6_addr smsk, dmsk;
  char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
  unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];
  __u16 proto;
  __u8 tos;
  __u8 flags;
  __u8 invflags;
};
#define IP6T_F_PROTO 0x01
#define IP6T_F_TOS 0x02
#define IP6T_F_GOTO 0x04
#define IP6T_F_MASK 0x07
#define IP6T_INV_VIA_IN 0x01
#define IP6T_INV_VIA_OUT 0x02
#define IP6T_INV_TOS 0x04
#define IP6T_INV_SRCIP 0x08
#define IP6T_INV_DSTIP 0x10
#define IP6T_INV_FRAG 0x20
#define IP6T_INV_PROTO XT_INV_PROTO
#define IP6T_INV_MASK 0x7F
struct ip6t_entry {
  struct ip6t_ip6 ipv6;
  unsigned int nfcache;
  __u16 target_offset;
  __u16 next_offset;
  unsigned int comefrom;
  struct xt_counters counters;
  unsigned char elems[0];
};
struct ip6t_standard {
  struct ip6t_entry entry;
  struct xt_standard_target target;
};
struct ip6t_error {
  struct ip6t_entry entry;
  struct xt_error_target target;
};
#define IP6T_ENTRY_INIT(__size) \
{.target_offset = sizeof(struct ip6t_entry),.next_offset = (__size), \
}
#define IP6T_STANDARD_INIT(__verdict) \
{.entry = IP6T_ENTRY_INIT(sizeof(struct ip6t_standard)),.target = XT_TARGET_INIT(XT_STANDARD_TARGET, sizeof(struct xt_standard_target)),.target.verdict = - (__verdict) - 1, \
}
#define IP6T_ERROR_INIT \
{.entry = IP6T_ENTRY_INIT(sizeof(struct ip6t_error)),.target = XT_TARGET_INIT(XT_ERROR_TARGET, sizeof(struct xt_error_target)),.target.errorname = "ERROR", \
}
#define IP6T_BASE_CTL 64
#define IP6T_SO_SET_REPLACE (IP6T_BASE_CTL)
#define IP6T_SO_SET_ADD_COUNTERS (IP6T_BASE_CTL + 1)
#define IP6T_SO_SET_MAX IP6T_SO_SET_ADD_COUNTERS
#define IP6T_SO_GET_INFO (IP6T_BASE_CTL)
#define IP6T_SO_GET_ENTRIES (IP6T_BASE_CTL + 1)
#define IP6T_SO_GET_REVISION_MATCH (IP6T_BASE_CTL + 4)
#define IP6T_SO_GET_REVISION_TARGET (IP6T_BASE_CTL + 5)
#define IP6T_SO_GET_MAX IP6T_SO_GET_REVISION_TARGET
#define IP6T_SO_ORIGINAL_DST 80
struct ip6t_icmp {
  __u8 type;
  __u8 code[2];
  __u8 invflags;
};
#define IP6T_ICMP_INV 0x01
struct ip6t_getinfo {
  char name[XT_TABLE_MAXNAMELEN];
  unsigned int valid_hooks;
  unsigned int hook_entry[NF_INET_NUMHOOKS];
  unsigned int underflow[NF_INET_NUMHOOKS];
  unsigned int num_entries;
  unsigned int size;
};
struct ip6t_replace {
  char name[XT_TABLE_MAXNAMELEN];
  unsigned int valid_hooks;
  unsigned int num_entries;
  unsigned int size;
  unsigned int hook_entry[NF_INET_NUMHOOKS];
  unsigned int underflow[NF_INET_NUMHOOKS];
  unsigned int num_counters;
  struct xt_counters  * counters;
  struct ip6t_entry entries[];
};
struct ip6t_get_entries {
  char name[XT_TABLE_MAXNAMELEN];
  unsigned int size;
  struct ip6t_entry entrytable[];
};
static __inline__ struct xt_entry_target * ip6t_get_target(struct ip6t_entry * e) {
  return(struct xt_entry_target *) ((char *) e + e->target_offset);
}
#endif
```