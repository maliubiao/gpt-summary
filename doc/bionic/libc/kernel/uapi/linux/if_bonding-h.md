Response:
Let's break down the thought process for analyzing this C header file.

**1. Understanding the Request:**

The core request is to analyze the provided C header file (`if_bonding.h`) within the context of Android's Bionic library. The specific points to address are:

* **Functionality:** What does this code *do*? What concepts does it define?
* **Android Relevance:** How does this relate to Android features?
* **`libc` Function Explanation:**  Detail any standard C library functions used (though in this case, it's mostly definitions, not function implementations).
* **Dynamic Linker:** Analyze if and how dynamic linking is involved.
* **Logical Reasoning:**  Infer input/output based on the definitions.
* **Common Usage Errors:**  Identify potential pitfalls when using these definitions.
* **Android Framework/NDK Integration:** Explain how Android code might reach this header.
* **Frida Hooking:** Provide examples of using Frida to inspect this area.

**2. Initial Scan and Keyword Identification:**

My first step is to quickly read through the code and identify key terms and concepts. I look for:

* `#define`: These define constants and macros, hinting at configuration options and operations. Keywords like `BOND_MODE`, `BOND_LINK`, `LACP_STATE` stand out.
* `typedef struct`: These define data structures, revealing how information is organized. `ifbond` and `ifslave` are important.
* `enum`: These define sets of named constants, often representing states or types.
* `SIOCDEVPRIVATE`: This indicates interaction with network devices, likely through ioctl calls.
* `ETH_ALEN`:  Suggests network MAC addresses are involved.

**3. Deciphering the Functionality - Bonding:**

Based on the filename `if_bonding.h` and the prevalence of `BOND_` prefixes, it becomes clear that this header file defines structures and constants related to **network bonding** (also known as link aggregation or NIC teaming). This is the core functionality.

**4. Connecting to Android:**

Now, I consider how network bonding might be relevant to Android. While typical Android phone users might not directly configure bonding, it's important for:

* **Android-based network appliances:**  If someone builds a router or firewall using Android, bonding could be a feature.
* **Server applications on Android:**  If an Android device acts as a server, bonding could improve network throughput and resilience.
* **Advanced network configuration:**  Developers working on low-level network features might need this.

**5. Analyzing Individual Definitions:**

I go through each `#define`, `typedef`, and `enum` and try to understand its purpose:

* **`BOND_ABI_VERSION`:**  Indicates a version for compatibility.
* **`BOND_*_OLD` defines:**  These look like ioctl command codes for interacting with the bonding driver. The `_OLD` suffix suggests they might be deprecated or older versions.
* **`BOND_MODE_*` defines:** These are the different bonding algorithms (Round Robin, Active Backup, etc.). This is a central concept.
* **`BOND_LINK_*` defines:** States related to the link status of individual network interfaces within the bond.
* **`LACP_STATE_*` defines:** Flags related to the Link Aggregation Control Protocol (LACP), a more advanced bonding method.
* **`ifbond` struct:**  Represents the overall bonding interface configuration (mode, number of slaves, monitoring interval).
* **`ifslave` struct:** Represents the status and information of an individual network interface participating in the bond.
* **`ad_info` struct:**  Contains information relevant to LACP.
* **`BOND_XSTATS_*` enums:** Define indices for extended statistics related to bonding, specifically LACP.

**6. `libc` Functions:**

The crucial observation here is that *this header file doesn't contain function implementations*. It's just declarations and definitions. Therefore, the detailed explanation of `libc` function implementations isn't directly applicable *to this file*. However, I *can* mention that the *use* of these definitions in other parts of the Android system will involve standard `libc` functions like `socket()`, `ioctl()`, etc.

**7. Dynamic Linker:**

Again, this header file itself doesn't directly involve the dynamic linker. However,  the *code that uses these definitions* might be in dynamically linked libraries. So, I provide a conceptual `so` layout and explain how the linker resolves symbols when a program uses bonding functionality.

**8. Logical Reasoning (Input/Output):**

I consider how these structures might be used. For example, when querying the status of a bonding interface using an `ioctl` call:

* **Input:**  An `ifreq` structure (common for network interface ioctls) containing a command like `BOND_INFO_QUERY_OLD`.
* **Output:** The `ifreq` structure's data portion would be filled with an `ifbond` structure containing the current bonding configuration, and potentially an array of `ifslave` structures.

**9. Common Usage Errors:**

I think about potential mistakes developers might make:

* **Incorrect `ioctl` calls:**  Using the wrong command codes or not setting up the `ifreq` structure correctly.
* **Misinterpreting bonding modes:** Not understanding the differences between the various `BOND_MODE_*` options.
* **Incorrectly handling link state changes:** Not reacting appropriately to `BOND_LINK_UP`, `BOND_LINK_FAIL`, etc.

**10. Android Framework/NDK Path:**

I trace the potential path from the Android application layer down to this header:

* **Android Framework:**  Higher-level Java APIs related to networking might eventually interact with the kernel through system calls.
* **NDK:**  Native code developed using the NDK can directly use system calls and interact with network devices.
* **`ioctl` system call:** This is the likely mechanism to interact with the bonding driver in the kernel.
* **Kernel:** The Linux kernel's bonding driver processes the `ioctl` requests and uses the definitions from `if_bonding.h`.

**11. Frida Hooking:**

I provide Frida examples targeting the `ioctl` system call. This is the most relevant point to intercept the interaction with the bonding driver. I show how to hook `ioctl` and filter for calls related to bonding by checking the `cmd` parameter.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on specific `libc` *function implementations*. I then realized that this header file primarily deals with *definitions*, not code. The focus shifted to how these definitions are *used* with `libc` functions like `socket` and `ioctl`.
* I made sure to clearly distinguish between the header file itself and the underlying kernel driver and how they interact.
* I refined the Android framework/NDK path to be more specific about the role of `ioctl`.

By following these steps, I could systematically analyze the header file and generate a comprehensive and informative response addressing all aspects of the request.
这个头文件 `bionic/libc/kernel/uapi/linux/if_bonding.h` 定义了 Linux 内核中网络 bonding（也称为链路聚合或 NIC teaming）的相关数据结构和常量。它不是一个可以直接执行的源代码文件，而是定义了用户空间程序与内核网络 bonding 驱动程序交互的接口。

以下是它的功能及其与 Android 关系的详细解释：

**1. 功能列表:**

* **定义 Bonding 设备的各种模式 (Modes):**
    * `BOND_MODE_ROUNDROBIN`: 轮询模式，数据包在所有活动的 slave 设备之间循环发送。
    * `BOND_MODE_ACTIVEBACKUP`: 主备模式，只有一个 slave 设备是活动的，当活动设备失效时，备用设备接管。
    * `BOND_MODE_XOR`: XOR 模式，根据源/目标 MAC 地址或 IP 地址的哈希值选择 slave 设备。
    * `BOND_MODE_BROADCAST`: 广播模式，所有数据包发送到所有 slave 设备。
    * `BOND_MODE_8023AD`: IEEE 802.3ad 动态链路聚合模式，使用 LACP (Link Aggregation Control Protocol) 协商聚合链路。
    * `BOND_MODE_TLB`: 自适应发送负载均衡模式，根据 slave 设备的负载动态分配发送流量。
    * `BOND_MODE_ALB`: 自适应负载均衡模式，除了发送负载均衡外，还进行接收负载均衡 (需要驱动程序支持 ARP 监控)。
* **定义 Bonding 设备的链路状态 (Link States):**
    * `BOND_LINK_UP`: 链路正常。
    * `BOND_LINK_FAIL`: 链路故障。
    * `BOND_LINK_DOWN`: 链路断开。
    * `BOND_LINK_BACK`: 链路恢复。
* **定义 Bonding 设备的成员设备 (Slave) 的状态 (Slave States):**
    * `BOND_STATE_ACTIVE`: Slave 设备处于活动状态。
    * `BOND_STATE_BACKUP`: Slave 设备处于备份状态。
* **定义 Bonding 设备的默认配置:**
    * `BOND_DEFAULT_MAX_BONDS`: 默认最大 bonding 设备数量。
    * `BOND_DEFAULT_TX_QUEUES`: 默认发送队列数量。
    * `BOND_DEFAULT_RESEND_IGMP`: 默认是否重发 IGMP 报文。
* **定义 数据包发送策略 (Transmit Policy):**
    * `BOND_XMIT_POLICY_LAYER2`: 基于二层信息（MAC 地址）进行负载均衡。
    * `BOND_XMIT_POLICY_LAYER34`: 基于三层和四层信息（IP 地址和端口）进行负载均衡。
    * `BOND_XMIT_POLICY_LAYER23`: 基于二层和三层信息进行负载均衡。
    * `BOND_XMIT_POLICY_ENCAP23`:  隧道封装后的二层和三层信息。
    * `BOND_XMIT_POLICY_ENCAP34`:  隧道封装后的三层和四层信息。
    * `BOND_XMIT_POLICY_VLAN_SRCMAC`: 基于 VLAN 标签和源 MAC 地址。
* **定义 LACP 状态标志 (LACP States):** 用于描述 802.3ad 模式下的链路聚合状态，例如活动性、超时、聚合、同步等。
* **定义 用于与 Bonding 设备交互的 ioctl 命令:**
    * `BOND_ENSLAVE_OLD`:  将网络接口添加为 bonding 设备的 slave。
    * `BOND_RELEASE_OLD`:  将网络接口从 bonding 设备中移除。
    * `BOND_SETHWADDR_OLD`: 设置 bonding 设备的硬件地址。
    * `BOND_SLAVE_INFO_QUERY_OLD`: 查询 bonding 设备中某个 slave 的信息。
    * `BOND_INFO_QUERY_OLD`: 查询 bonding 设备的信息。
    * `BOND_CHANGE_ACTIVE_OLD`: 手动切换活动的 slave 设备。
    * `BOND_CHECK_MII_STATUS`: 检查 slave 设备的 MII 状态（用于判断链路状态）。
* **定义 用于扩展统计信息的枚举 (Extended Statistics):** 特别是针对 802.3ad 模式下的 LACP 协议统计信息，例如收发的 LACPDU 报文数量。
* **定义 相关的数据结构:**
    * `ifbond`:  表示 bonding 设备的配置信息，包括模式、slave 数量、MII 监控间隔等。
    * `ifslave`:  表示 bonding 设备中一个 slave 接口的信息，包括 slave ID、名称、链路状态、状态、链路故障计数等。
    * `ad_info`:  表示 802.3ad 模式下的聚合器信息，例如聚合器 ID、端口数量、Actor/Partner Key 和 System ID。

**2. 与 Android 功能的关系及举例说明:**

虽然普通 Android 手机用户可能不会直接接触到网络 bonding 的配置，但在某些 Android 应用场景中可能会用到，特别是在以下情况：

* **Android 作为网络基础设施组件:**  如果 Android 设备被用作路由器、网关或服务器，可能需要使用 bonding 来提高网络吞吐量、冗余性和负载均衡能力。例如，一个基于 Android 构建的家庭服务器，可能会使用 bonding 将多个以太网接口聚合在一起，以提供更高的网络带宽。
* **企业级 Android 应用:**  某些企业级应用可能需要更高级的网络配置，例如连接到使用链路聚合的服务器。
* **Android 系统开发和测试:**  进行底层网络驱动开发或测试时，可能需要配置和管理 bonding 设备。

**举例说明:**

假设你正在开发一个 Android 应用，需要从一个使用链路聚合技术的服务器下载大量数据。虽然你的应用本身不需要直接配置 bonding，但 Android 系统底层的网络栈需要能够理解和处理来自 bonding 接口的网络流量。

在 Android 系统中，可以使用 `ip` 命令或其他网络管理工具来配置 bonding 设备。这些工具最终会通过 `ioctl` 系统调用与内核的 bonding 驱动程序进行交互，而 `if_bonding.h` 中定义的常量和结构体就是这些交互的基础。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **没有包含任何 libc 函数的实现**。它只是定义了常量、宏和数据结构。这些定义被用户空间的程序（通常是用 C/C++ 编写）使用，以便通过系统调用（例如 `ioctl`）与 Linux 内核的 bonding 驱动程序进行通信。

用户空间程序会使用标准 C 库中的函数，例如：

* **`socket()`:** 创建一个网络套接字，用于与内核进行通信。
* **`ioctl()`:**  一个通用的设备控制系统调用，用于向设备驱动程序发送控制命令和获取设备状态。在这个上下文中，`ioctl` 会使用 `if_bonding.h` 中定义的 `BOND_*` 宏作为命令参数，并传递包含 `ifbond` 或 `ifslave` 结构体的指针作为数据。
* **`strcpy()`, `strncpy()`:**  用于复制字符串，例如复制网络接口名称。
* **内存分配函数 (如 `malloc()`, `free()`):**  可能用于动态分配存储 `ifbond` 或 `ifslave` 结构体的内存。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的功能。它只是定义了内核接口。然而，使用这些定义的代码可能位于动态链接的共享库 (`.so`) 中。

**so 布局样本:**

假设有一个名为 `libnetutils.so` 的共享库，它包含了配置和管理网络 bonding 的功能。其布局可能如下：

```
libnetutils.so:
    .text          # 包含代码段
        configure_bonding()  # 一个配置 bonding 设备的函数
        get_bonding_info()   # 一个获取 bonding 设备信息的函数
        ...
    .data          # 包含已初始化的数据段
        ...
    .bss           # 包含未初始化的数据段
        ...
    .dynsym        # 动态符号表
        configure_bonding
        get_bonding_info
        ...
    .dynstr        # 动态字符串表
        ...
    .plt           # 程序链接表
        ...
    .got.plt       # 全局偏移量表
        ...
    ...
```

**链接的处理过程:**

1. **编译时:** 当编译使用 `libnetutils.so` 的程序时，编译器会记录程序需要链接到 `libnetutils.so`，并在可执行文件中添加相应的依赖信息。
2. **加载时:** Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 在程序启动时被调用。
3. **依赖解析:** linker 读取可执行文件的头部信息，识别其依赖的共享库 (`libnetutils.so`)。
4. **加载共享库:** linker 在文件系统中查找并加载 `libnetutils.so` 到内存中。
5. **符号解析:** linker 遍历可执行文件和共享库的动态符号表 (`.dynsym`)，将可执行文件中对 `configure_bonding()` 和 `get_bonding_info()` 等函数的未定义引用，解析到 `libnetutils.so` 中对应的函数地址。这通常通过程序链接表 (`.plt`) 和全局偏移量表 (`.got.plt`) 来实现。

当 `libnetutils.so` 中的代码需要与内核 bonding 驱动程序交互时，它会包含 `if_bonding.h` 头文件，并使用其中定义的常量和结构体来构建 `ioctl` 调用。这些常量和结构体在编译时被硬编码到 `libnetutils.so` 中。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

假设一个用户空间程序想要查询名为 "bond0" 的 bonding 设备的信息。

**假设输入:**

* **`ioctl` 的第一个参数:**  一个打开的网络套接字的文件描述符。
* **`ioctl` 的第二个参数 (`request`):**  `BOND_INFO_QUERY_OLD`。
* **`ioctl` 的第三个参数 (`argp`):**  一个指向 `ifreq` 结构体的指针。该结构体包含：
    * `ifr_name`:  设置为 "bond0" 的字符串。
    * `ifr_data`:  指向一个 `ifbond` 结构体的指针（用于接收内核返回的信息）。

**假设输出:**

`ioctl` 调用成功返回 0，并且 `ifreq` 结构体指向的 `ifbond` 结构体被内核填充了 "bond0" 设备的当前信息，例如：

```c
struct ifbond bond_info;
strcpy(ifr.ifr_name, "bond0");
ifr.ifr_data = (void *)&bond_info;

if (ioctl(sockfd, BOND_INFO_QUERY_OLD, &ifr) == 0) {
    printf("Bonding Mode: %d\n", bond_info.bond_mode);
    printf("Number of Slaves: %d\n", bond_info.num_slaves);
    printf("MII Monitor Interval: %d\n", bond_info.miimon);
}
```

输出可能类似于：

```
Bonding Mode: 1  // BOND_MODE_ACTIVEBACKUP
Number of Slaves: 2
MII Monitor Interval: 100
```

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **错误的 `ioctl` 命令:**  使用了错误的 `BOND_*` 宏值，导致内核无法识别请求。例如，想要查询 bonding 信息却使用了 `BOND_ENSLAVE_OLD`。
* **未正确初始化 `ifreq` 结构体:** 例如，忘记设置 `ifr_name` 或者 `ifr_data` 指向的内存空间不足。
* **传递了错误大小的数据结构:**  `ioctl` 调用需要传递正确大小的数据结构。如果用户空间程序传递的 `ifbond` 或 `ifslave` 结构体大小与内核期望的不一致，可能会导致数据错乱或程序崩溃。
* **在不支持 bonding 的内核上尝试使用 bonding 特性:** 如果 Android 设备的内核没有编译 bonding 驱动程序，尝试使用 bonding 相关的 `ioctl` 调用将会失败。
* **权限问题:** 配置 bonding 设备通常需要 root 权限。非 root 权限的应用尝试执行相关的 `ioctl` 调用将会失败。
* **并发访问冲突:**  多个进程或线程同时尝试修改 bonding 设备的配置可能会导致冲突。需要适当的同步机制来避免这种情况。
* **混淆了旧的和新的 ioctl 命令:**  头文件中包含了一些带有 `_OLD` 后缀的宏，表明它们可能是旧版本，应该使用更新的接口（如果存在）。混用新旧接口可能导致兼容性问题。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到 `if_bonding.h` 的路径:**

1. **Android Framework (Java):**  Android Framework 中处理网络配置的部分（例如 `ConnectivityManager`）最终可能会调用底层的 native 代码来执行实际的网络操作。
2. **NDK (Native Code):**  开发者可以使用 NDK 编写 C/C++ 代码，这些代码可以直接调用 Linux 系统调用。
3. **System Calls:**  要配置或查询 bonding 设备，native 代码会使用 `socket()` 创建套接字，然后使用 `ioctl()` 系统调用与内核进行通信.
4. **Kernel:** Linux 内核接收到 `ioctl()` 调用后，会根据 `ioctl` 的命令参数（例如 `BOND_INFO_QUERY_OLD`）以及传递的数据（`ifreq` 结构体），调用相应的 bonding 驱动程序中的处理函数。
5. **`if_bonding.h`:** 在内核 bonding 驱动程序的代码中，会包含 `if_bonding.h` 头文件，以便使用其中定义的常量和结构体来解析和处理用户空间的请求，以及返回相应的信息。

**Frida Hook 示例:**

可以使用 Frida 来 hook `ioctl` 系统调用，并过滤出与 bonding 相关的调用。以下是一个简单的 Frida 脚本示例：

```javascript
// hook_bonding_ioctl.js

// 获取 ioctl 的符号地址
const ioctlPtr = Module.getExportByName(null, "ioctl");

Interceptor.attach(ioctlPtr, {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();
    const argp = args[2];

    // 检查是否是 bonding 相关的 ioctl 命令
    const bondingCommands = {
      [0x89f0]: "BOND_ENSLAVE_OLD",
      [0x89f1]: "BOND_RELEASE_OLD",
      [0x89f2]: "BOND_SETHWADDR_OLD",
      [0x89fb]: "BOND_SLAVE_INFO_QUERY_OLD",
      [0x89fc]: "BOND_INFO_QUERY_OLD",
      [0x89fd]: "BOND_CHANGE_ACTIVE_OLD",
      [0x89e2]: "BOND_CHECK_MII_STATUS",
    };

    if (bondingCommands[request]) {
      console.log("ioctl called with bonding command:", bondingCommands[request]);
      console.log("File Descriptor:", fd);
      console.log("Request Code:", request);
      console.log("argp:", argp);

      // 可以进一步解析 argp 指向的 ifreq 结构体
      // 需要根据目标架构和 ifreq 结构体的定义进行解析
      // 例如，读取 ifr_name:
      // const ifr_name = argp.readUtf8String();
      // console.log("Interface Name:", ifr_name);
    }
  },
  onLeave: function (retval) {
    // console.log("ioctl returned:", retval);
  },
});

console.log("Frida script attached. Hooking ioctl for bonding commands.");
```

**使用方法:**

1. 将以上代码保存为 `hook_bonding_ioctl.js`。
2. 使用 Frida 连接到目标 Android 进程（例如，一个负责网络配置的系统进程）：
   ```bash
   frida -U -f com.android.systemui -l hook_bonding_ioctl.js --no-pause
   ```
   或者连接到一个正在运行的进程：
   ```bash
   frida -U com.android.shell -l hook_bonding_ioctl.js
   ```
   将 `com.android.systemui` 或 `com.android.shell` 替换为目标进程的包名或进程名。
3. 当目标进程执行与 bonding 相关的 `ioctl` 调用时，Frida 脚本将在控制台上打印出相关信息，例如调用的 `ioctl` 命令、文件描述符、请求代码和 `argp` 指针。你可以进一步解析 `argp` 指向的数据来查看传递的具体参数。

通过这种方式，你可以观察 Android Framework 或 NDK 代码如何一步步地调用 `ioctl`，并使用 `if_bonding.h` 中定义的常量和结构体与内核 bonding 驱动程序进行交互。

请注意，hook 系统调用可能需要 root 权限，并且需要对目标进程的网络配置逻辑和 `ifreq` 结构体的布局有一定的了解才能进行更深入的分析。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/if_bonding.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_IF_BONDING_H
#define _LINUX_IF_BONDING_H
#include <linux/if.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#define BOND_ABI_VERSION 2
#define BOND_ENSLAVE_OLD (SIOCDEVPRIVATE)
#define BOND_RELEASE_OLD (SIOCDEVPRIVATE + 1)
#define BOND_SETHWADDR_OLD (SIOCDEVPRIVATE + 2)
#define BOND_SLAVE_INFO_QUERY_OLD (SIOCDEVPRIVATE + 11)
#define BOND_INFO_QUERY_OLD (SIOCDEVPRIVATE + 12)
#define BOND_CHANGE_ACTIVE_OLD (SIOCDEVPRIVATE + 13)
#define BOND_CHECK_MII_STATUS (SIOCGMIIPHY)
#define BOND_MODE_ROUNDROBIN 0
#define BOND_MODE_ACTIVEBACKUP 1
#define BOND_MODE_XOR 2
#define BOND_MODE_BROADCAST 3
#define BOND_MODE_8023AD 4
#define BOND_MODE_TLB 5
#define BOND_MODE_ALB 6
#define BOND_LINK_UP 0
#define BOND_LINK_FAIL 1
#define BOND_LINK_DOWN 2
#define BOND_LINK_BACK 3
#define BOND_STATE_ACTIVE 0
#define BOND_STATE_BACKUP 1
#define BOND_DEFAULT_MAX_BONDS 1
#define BOND_DEFAULT_TX_QUEUES 16
#define BOND_DEFAULT_RESEND_IGMP 1
#define BOND_XMIT_POLICY_LAYER2 0
#define BOND_XMIT_POLICY_LAYER34 1
#define BOND_XMIT_POLICY_LAYER23 2
#define BOND_XMIT_POLICY_ENCAP23 3
#define BOND_XMIT_POLICY_ENCAP34 4
#define BOND_XMIT_POLICY_VLAN_SRCMAC 5
#define LACP_STATE_LACP_ACTIVITY 0x1
#define LACP_STATE_LACP_TIMEOUT 0x2
#define LACP_STATE_AGGREGATION 0x4
#define LACP_STATE_SYNCHRONIZATION 0x8
#define LACP_STATE_COLLECTING 0x10
#define LACP_STATE_DISTRIBUTING 0x20
#define LACP_STATE_DEFAULTED 0x40
#define LACP_STATE_EXPIRED 0x80
typedef struct ifbond {
  __s32 bond_mode;
  __s32 num_slaves;
  __s32 miimon;
} ifbond;
typedef struct ifslave {
  __s32 slave_id;
  char slave_name[IFNAMSIZ];
  __s8 link;
  __s8 state;
  __u32 link_failure_count;
} ifslave;
struct ad_info {
  __u16 aggregator_id;
  __u16 ports;
  __u16 actor_key;
  __u16 partner_key;
  __u8 partner_system[ETH_ALEN];
};
enum {
  BOND_XSTATS_UNSPEC,
  BOND_XSTATS_3AD,
  __BOND_XSTATS_MAX
};
#define BOND_XSTATS_MAX (__BOND_XSTATS_MAX - 1)
enum {
  BOND_3AD_STAT_LACPDU_RX,
  BOND_3AD_STAT_LACPDU_TX,
  BOND_3AD_STAT_LACPDU_UNKNOWN_RX,
  BOND_3AD_STAT_LACPDU_ILLEGAL_RX,
  BOND_3AD_STAT_MARKER_RX,
  BOND_3AD_STAT_MARKER_TX,
  BOND_3AD_STAT_MARKER_RESP_RX,
  BOND_3AD_STAT_MARKER_RESP_TX,
  BOND_3AD_STAT_MARKER_UNKNOWN_RX,
  BOND_3AD_STAT_PAD,
  __BOND_3AD_STAT_MAX
};
#define BOND_3AD_STAT_MAX (__BOND_3AD_STAT_MAX - 1)
#endif

"""

```