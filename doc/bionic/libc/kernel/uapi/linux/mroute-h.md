Response:
Let's break down the thought process for analyzing the provided C header file (`mroute.h`).

**1. Understanding the Context:**

The first step is to acknowledge the information provided about the file's origin: "bionic/libc/kernel/uapi/linux/mroute.handroid". This immediately tells us several crucial things:

* **bionic:** This indicates it's part of Android's core C library. This implies the file deals with low-level system functionality relevant to Android.
* **libc:**  Confirms it's part of the C standard library implementation.
* **kernel/uapi/linux:**  This is a key indicator. "uapi" stands for "user-space API."  This means the definitions in this header are meant to be used by applications running in user space to interact with the Linux kernel. The "linux" part clarifies that it's related to Linux kernel features.
* **mroute:** This strongly suggests the file is related to IP multicast routing. The "m" likely stands for "multicast."

**2. Initial Code Scan and Keyword Recognition:**

Next, I would quickly scan the code for recognizable patterns and keywords. This helps form initial hypotheses about the file's purpose.

* **`#ifndef _UAPI__LINUX_MROUTE_H` and `#define _UAPI__LINUX_MROUTE_H`:**  Standard header guard to prevent multiple inclusions.
* **`#include <linux/sockios.h>`, `#include <linux/types.h>`, `#include <linux/in.h>`:**  These includes point to core Linux networking and type definitions, reinforcing the networking/kernel interaction idea.
* **`MRT_BASE`, `MRT_INIT`, `MRT_DONE`, `MRT_ADD_VIF`, etc.:** The `MRT_` prefix and the names suggest a set of constants likely used as commands or options for a multicast routing related system call or ioctl. "VIF" probably stands for "Virtual Interface."  "MFC" likely stands for "Multicast Forwarding Cache."
* **`SIOCGETVIFCNT`, `SIOCGETSGCNT`, `SIOCGETRPF`:**  The `SIOC` prefix strongly suggests these are `ioctl` (socket ioctl) commands. These commands likely retrieve information about virtual interfaces, source-group counts, and Reverse Path Forwarding (RPF) status.
* **`MAXVIFS 32`:** A constant defining the maximum number of virtual interfaces.
* **`typedef unsigned long vifbitmap_t;`, `typedef unsigned short vifi_t;`:** Type definitions related to virtual interfaces. The bitmap suggests a way to track or manage multiple VIFs.
* **`struct vifctl`:** A structure likely containing control information for a virtual interface (flags, threshold, addresses).
* **`struct mfcctl`:** A structure likely holding information about a multicast forwarding cache entry (origin, group, TTLs, counters).
* **`struct sioc_sg_req`, `struct sioc_vif_req`:** Structures likely used as arguments for the `ioctl` commands identified earlier.
* **`struct igmpmsg`:**  A structure related to IGMP (Internet Group Management Protocol) messages, which is crucial for multicast group management.
* **`enum { IPMRA_... }`:** Enumerations with `IPMRA_` prefixes likely define attributes or options for a multicast routing attribute system. The nested structure (`IPMRA_TABLE_*`, `IPMRA_VIF_*`, `IPMRA_VIFA_*`, `IPMRA_CREPORT_*`) hints at a more complex attribute management system, potentially using a nested structure to represent different aspects of multicast routing.
* **`MFC_ASSERT_THRESH`, `IGMPMSG_NOCACHE`, etc.:**  More constants likely related to specific aspects of multicast routing and IGMP.

**3. Deduction and Hypothesis Formation:**

Based on the keywords and structures, I started forming hypotheses about the file's purpose:

* **Core Functionality:**  This file defines the user-space interface for controlling and monitoring IP multicast routing within the Linux kernel on Android.
* **Key Concepts:**  Virtual Interfaces (VIFs), Multicast Forwarding Cache (MFC), ioctl commands for control and status retrieval, and interaction with IGMP.
* **Android Relevance:** Since it's in bionic, these functions are used by Android components that need to perform multicast routing operations.

**4. Addressing Specific Requirements of the Prompt:**

Now, I started systematically addressing each part of the prompt:

* **功能列表 (Functionality):** I listed the core functionalities based on the identified constants, structures, and ioctl commands (VIF management, MFC management, querying status, etc.).
* **与 Android 功能的关系 (Relationship with Android):** I considered where multicast might be used in Android. Examples like media streaming (though not very common for end-user apps on mobile), network discovery protocols, and potentially internal system communication came to mind. I focused on more concrete examples where multicast is known to be used.
* **libc 函数的实现 (libc function implementation):** This part required careful consideration. The header file itself *doesn't* contain libc function implementations. It *defines* the interface. The actual implementation resides in the kernel. Therefore, I explained that this file defines the *interface*, and the libc functions (like `ioctl`) act as wrappers to interact with the kernel. I focused on explaining *how* `ioctl` works in this context.
* **dynamic linker 的功能 (Dynamic linker functionality):** This header file doesn't directly involve the dynamic linker. It's about kernel interfaces. I clarified this and explained that dynamic linking is a separate process. I provided a general example of shared library loading as context, but emphasized the lack of direct linkage here.
* **逻辑推理 (Logical Inference):** I picked a simple example like adding a VIF and explained the hypothetical input and output of using the relevant structures and ioctl.
* **用户或编程常见的使用错误 (Common User/Programming Errors):**  I considered typical errors when working with low-level networking APIs, such as incorrect parameter passing, permission issues, and not handling errors.
* **Android Framework/NDK 到达这里的步骤 (Path from Android Framework/NDK):** I outlined the typical path, starting from Java APIs, going through the NDK, and eventually reaching the system call layer where `ioctl` is used with the defined constants.
* **Frida Hook 示例 (Frida Hook Example):** I provided a basic Frida hook example targeting the `ioctl` system call and filtering for the relevant `SIOC` commands to demonstrate how one could intercept and inspect these low-level interactions.

**5. Refinement and Clarity:**

Finally, I reviewed my response for clarity, accuracy, and completeness. I ensured that the language was precise and easy to understand, and that all parts of the prompt were addressed. I added disclaimers where necessary (e.g., about the lack of direct dynamic linker involvement).

This iterative process of understanding the context, scanning the code, forming hypotheses, and addressing the specific requirements of the prompt allowed me to generate a comprehensive and accurate answer.
这个头文件 `bionic/libc/kernel/uapi/linux/mroute.h` 定义了 Linux 内核中与 **IP 组播路由 (Multicast Routing)** 相关的用户空间 API。它为用户空间的应用程序提供了与内核组播路由功能交互的接口。

**功能列表:**

该头文件主要定义了以下功能相关的常量、结构体和宏：

1. **Multicast Routing 操作码 (MRT_*):** 定义了一系列用于控制组播路由的 `ioctl` 命令的常量，例如：
    * `MRT_INIT`: 初始化组播路由。
    * `MRT_DONE`: 停止组播路由。
    * `MRT_ADD_VIF`: 添加一个虚拟接口 (Virtual Interface) 用于组播。
    * `MRT_DEL_VIF`: 删除一个虚拟接口。
    * `MRT_ADD_MFC`: 添加一个组播转发缓存条目 (Multicast Forwarding Cache entry)。
    * `MRT_DEL_MFC`: 删除一个组播转发缓存条目。
    * `MRT_VERSION`: 获取组播路由协议版本。
    * `MRT_ASSERT`: 发送组播路由断言消息。
    * `MRT_PIM`: 启用/禁用协议无关组播 (Protocol Independent Multicast)。
    * `MRT_TABLE`: 操作组播路由表。
    * `MRT_ADD_MFC_PROXY`, `MRT_DEL_MFC_PROXY`: 添加/删除组播转发缓存代理条目。
    * `MRT_FLUSH`: 清空组播路由状态。

2. **Socket IO 控制命令 (SIOCGETVIFCNT, SIOCGETSGCNT, SIOCGETRPF):**  定义了用于获取组播路由状态的 `ioctl` 命令常量：
    * `SIOCGETVIFCNT`: 获取虚拟接口计数。
    * `SIOCGETSGCNT`: 获取源组对计数。
    * `SIOCGETRPF`: 获取反向路径转发 (Reverse Path Forwarding) 信息。

3. **标志位 (MRT_FLUSH_*, VIFF_*):** 定义了用于控制特定行为的标志位，例如：
    * `MRT_FLUSH_MFC`, `MRT_FLUSH_MFC_STATIC`, `MRT_FLUSH_VIFS`, `MRT_FLUSH_VIFS_STATIC`:  用于控制 `MRT_FLUSH` 命令的行为。
    * `VIFF_TUNNEL`, `VIFF_SRCRT`, `VIFF_REGISTER`, `VIFF_USE_IFINDEX`: 用于配置虚拟接口的标志位。

4. **数据结构体 (vifctl, mfcctl, sioc_sg_req, sioc_vif_req, igmpmsg):**  定义了用于在用户空间和内核空间之间传递数据的结构体：
    * `vifctl`:  用于控制和配置虚拟接口的信息，如接口索引、本地/远程地址、标志位等。
    * `mfcctl`: 用于控制和管理组播转发缓存条目的信息，如源地址、组地址、TTL 值、包/字节计数等。
    * `sioc_sg_req`:  用于 `SIOCGETSGCNT` 命令，包含源地址、组地址和相应的计数信息。
    * `sioc_vif_req`: 用于获取单个虚拟接口的统计信息。
    * `igmpmsg`:  用于表示 IGMP (Internet Group Management Protocol) 消息。

5. **枚举类型 (IPMRA_TABLE_*, IPMRA_VIF_*, IPMRA_VIFA_*, IPMRA_CREPORT_*)**: 定义了用于更细粒度控制组播路由属性的枚举值，通常与网络配置接口 (`netlink`) 一起使用。

6. **辅助宏 (VIFM_SET, VIFM_CLR, 等等):**  提供了一些用于操作虚拟接口位图的宏。

**与 Android 功能的关系及举例说明:**

IP 组播在 Android 中相对较少直接用于最终用户应用，但它在一些底层网络功能和系统服务中可能被使用。

* **媒体流传输 (有限场景):** 某些特定的局域网环境下的媒体流传输可能会使用组播，例如 IPTV。Android 设备作为接收端可能需要处理这些组播数据。
* **网络发现协议:**  一些网络发现协议，例如 Bonjour (mDNS)，在某些情况下可能使用组播来广播服务。Android 设备需要能够处理这些组播消息以发现局域网内的服务。
* **内部系统服务:**  Android 系统内部的某些服务，为了效率和减少网络负载，可能会使用组播进行通信。

**举例说明:** 假设一个 Android 应用需要接收来自局域网内特定组播地址的视频流。该应用可能会使用底层的 socket API，并可能间接地通过 Android Framework 的某些网络管理服务，最终调用到操作这些内核组播路由功能的系统调用。例如，添加一个虚拟接口以便接收该组播流。

**libc 函数的功能及实现:**

这个头文件本身**不包含 libc 函数的实现**，它只是定义了用户空间和内核空间交互的接口。用户空间的程序需要使用 libc 提供的 socket 相关的函数，例如 `socket()`, `ioctl()` 等，来与内核的组播路由功能进行交互。

* **`ioctl()` 函数:**  这是与此头文件关系最密切的 libc 函数。 `ioctl()` (input/output control) 是一个系统调用，允许用户空间的程序向设备驱动程序（在这里是网络设备驱动和 IP 组播路由模块）发送控制命令并获取信息。

   **`ioctl()` 的实现原理 (简化版):**
   1. 用户空间程序调用 `ioctl(fd, request, argp)`，其中 `fd` 是一个打开的文件描述符（通常是 socket），`request` 是一个与驱动程序约定的命令码（例如 `MRT_ADD_VIF`），`argp` 是指向包含参数的内存区域的指针（例如 `struct vifctl` 的指针）。
   2. `ioctl()` 系统调用陷入内核。
   3. 内核根据文件描述符找到对应的设备驱动程序的 `ioctl` 处理函数。
   4. 网络设备驱动程序或 IP 组播路由模块的 `ioctl` 处理函数被调用。
   5. 该处理函数根据 `request` 命令码执行相应的操作，例如添加或删除虚拟接口，修改组播路由表等。它会解析 `argp` 指向的数据。
   6. 处理函数将执行结果返回给内核。
   7. 内核将结果返回给用户空间程序。

**涉及 dynamic linker 的功能:**

这个头文件本身**不直接涉及 dynamic linker 的功能**。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (SO 文件) 并解析库之间的依赖关系。

然而，如果用户空间的程序使用了依赖于网络功能的共享库，那么这些共享库在运行时会被 dynamic linker 加载。这些共享库可能会间接地使用到与组播路由相关的系统调用。

**so 布局样本 (假设一个使用了组播路由的共享库):**

```
/system/lib64/my_multicast_lib.so

Sections:
  .text         # 代码段
  .rodata       # 只读数据段
  .data         # 可写数据段
  .bss          # 未初始化数据段
  .dynsym       # 动态符号表
  .dynstr       # 动态字符串表
  .rel.dyn      # 动态重定位表
  .rel.plt      # PLT 重定位表

Dependencies (通过 readelf -d 查看):
  libc.so
  libnetd_client.so  # 假设这个库封装了网络相关的操作

Symbol Table (.dynsym 中可能包含):
  socket
  ioctl

```

**链接的处理过程:**

1. **编译时:**  编译器和链接器会将 `my_multicast_lib.so` 标记为依赖 `libc.so` 和 `libnetd_client.so`。
2. **加载时:** 当应用程序加载 `my_multicast_lib.so` 时，dynamic linker 会首先加载其依赖的共享库 (`libc.so`, `libnetd_client.so`)。
3. **符号解析:**  Dynamic linker 会解析 `my_multicast_lib.so` 中引用的外部符号，例如 `socket` 和 `ioctl`，将它们链接到 `libc.so` 中对应的实现。

**逻辑推理 (假设输入与输出):**

**假设:**  一个程序想要添加一个虚拟接口来接收组播数据。

**输入:**

* `fd`: 一个已创建的 `AF_INET` 或 `AF_INET6` 类型的 UDP socket 的文件描述符。
* `request`: `MRT_ADD_VIF` 常量。
* `argp`: 指向一个 `struct vifctl` 结构体的指针，该结构体包含了要添加的虚拟接口的配置信息，例如：
    * `vifc_vifi`: 要分配的 VIF 索引 (例如 0)。
    * `vifc_flags`:  例如 `0`。
    * `vifc_threshold`:  例如 `1`。
    * `vifc_lcl_addr`: 本地接口地址 (例如 `inet_addr("192.168.1.100")`)。
    * `vifc_rmt_addr`: 远程接口地址 (如果需要，例如隧道模式)。

**输出:**

* **成功:** `ioctl()` 返回 0。
* **失败:** `ioctl()` 返回 -1，并设置 `errno` 以指示错误原因 (例如 `EPERM` 表示权限不足，`EINVAL` 表示参数无效)。

**用户或编程常见的使用错误:**

1. **权限不足:**  执行组播路由相关的操作通常需要 root 权限或特定的网络能力。普通应用可能无法直接调用这些 `ioctl` 命令。
   ```c
   // 错误示例：在没有足够权限的情况下尝试添加 VIF
   int sock = socket(AF_INET, SOCK_DGRAM, 0);
   struct vifctl vif;
   vif.vifc_vifi = 0;
   // ... 初始化其他字段 ...
   if (ioctl(sock, MRT_ADD_VIF, &vif) == -1) {
       perror("ioctl MRT_ADD_VIF failed"); // 可能会输出 "Operation not permitted"
   }
   close(sock);
   ```

2. **参数错误:**  传递给 `ioctl()` 的结构体中的字段值可能不正确，例如无效的 IP 地址、超出范围的 VIF 索引等。
   ```c
   // 错误示例：传递了无效的 IP 地址
   int sock = socket(AF_INET, SOCK_DGRAM, 0);
   struct vifctl vif;
   vif.vifc_vifi = 0;
   vif.vifc_lcl_addr.s_addr = INADDR_NONE; // 无效地址
   // ...
   if (ioctl(sock, MRT_ADD_VIF, &vif) == -1) {
       perror("ioctl MRT_ADD_VIF failed"); // 可能会输出 "Invalid argument"
   }
   close(sock);
   ```

3. **未正确处理错误:**  忽略 `ioctl()` 的返回值和 `errno`，导致程序在操作失败时行为异常。

4. **在错误的 socket 上调用:**  `ioctl()` 命令必须在与组播路由相关的 socket 上调用。

**Android Framework 或 NDK 如何到达这里:**

1. **Java Framework (高层):**  Android 应用通常通过 Java Framework 提供的 API 进行网络操作，例如 `MulticastSocket`。
2. **Native Code (NDK):**  如果需要更底层的控制，开发者可以使用 NDK (Native Development Kit) 编写 C/C++ 代码。
3. **System Services:**  Android Framework 中的网络管理服务 (例如 `ConnectivityService`) 和底层网络守护进程 (`netd`) 负责处理网络配置和路由。这些服务可能会使用 native 代码。
4. **`libnetd_client.so`:**  这是一个 Android 系统库，提供了一种与 `netd` 守护进程通信的方式。`netd` 负责执行实际的网络配置操作。
5. **`netd` 守护进程:**  `netd` 是一个运行在 root 权限下的 native 守护进程，它会接收来自 Framework 或其他进程的命令，并调用底层的 Linux 网络 API (包括 `ioctl`) 来配置网络。
6. **System Calls:**  最终，`netd` 或直接使用 NDK 的应用会调用 `socket()` 创建 socket，并使用 `ioctl()` 系统调用，并传入 `mroute.h` 中定义的常量和结构体，来与内核的组播路由模块进行交互。

**Frida Hook 示例调试步骤:**

假设我们要监控 `netd` 守护进程中添加虚拟接口的操作。

```python
import frida
import sys

package_name = "android" # 实际上 netd 不是一个应用包，但我们可以 attach 到它的进程

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"找不到进程 '{package_name}'，请尝试 attach 到 netd 的进程 ID。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        if (request >= 200 && request <= 212) { // MRT_BASE 到 MRT_MAX 的范围
            console.log("ioctl called with request:", request);
            if (request == 202) { // MRT_ADD_VIF
                console.log("  MRT_ADD_VIF detected!");
                const vifctlPtr = ptr(argp);
                const vifc_vifi = vifctlPtr.readU16();
                const vifc_flags = vifctlPtr.add(2).readU8();
                const vifc_threshold = vifctlPtr.add(3).readU8();
                // ... 读取更多 vifctl 结构体的字段 ...
                console.log("  vifc_vifi:", vifc_vifi);
                console.log("  vifc_flags:", vifc_flags);
                console.log("  vifc_threshold:", vifc_threshold);
                // 可以进一步读取 IP 地址等信息
            }
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **找到 `netd` 进程的 PID:**  可以使用 `adb shell ps | grep netd` 命令。
2. **修改 Frida 脚本:** 将 `frida.attach(package_name)` 中的 `package_name` 替换为 `frida.attach(pid)`，其中 `pid` 是 `netd` 的进程 ID。
3. **运行 Frida 脚本:**  `python your_frida_script.py`。
4. **触发添加虚拟接口的操作:**  在 Android 设备上执行某些网络操作，可能会触发 `netd` 调用 `ioctl` 来添加组播虚拟接口。
5. **查看 Frida 输出:** Frida 脚本会拦截 `ioctl` 系统调用，并打印出相关的请求码和参数信息，帮助你调试和理解组播路由的配置过程。

这个 Frida 示例只是一个基本的框架，你可以根据需要扩展它来捕获更多的 `ioctl` 命令和参数，以便更深入地分析 Android 中组播路由的使用情况。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/mroute.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_MROUTE_H
#define _UAPI__LINUX_MROUTE_H
#include <linux/sockios.h>
#include <linux/types.h>
#include <linux/in.h>
#define MRT_BASE 200
#define MRT_INIT (MRT_BASE)
#define MRT_DONE (MRT_BASE + 1)
#define MRT_ADD_VIF (MRT_BASE + 2)
#define MRT_DEL_VIF (MRT_BASE + 3)
#define MRT_ADD_MFC (MRT_BASE + 4)
#define MRT_DEL_MFC (MRT_BASE + 5)
#define MRT_VERSION (MRT_BASE + 6)
#define MRT_ASSERT (MRT_BASE + 7)
#define MRT_PIM (MRT_BASE + 8)
#define MRT_TABLE (MRT_BASE + 9)
#define MRT_ADD_MFC_PROXY (MRT_BASE + 10)
#define MRT_DEL_MFC_PROXY (MRT_BASE + 11)
#define MRT_FLUSH (MRT_BASE + 12)
#define MRT_MAX (MRT_BASE + 12)
#define SIOCGETVIFCNT SIOCPROTOPRIVATE
#define SIOCGETSGCNT (SIOCPROTOPRIVATE + 1)
#define SIOCGETRPF (SIOCPROTOPRIVATE + 2)
#define MRT_FLUSH_MFC 1
#define MRT_FLUSH_MFC_STATIC 2
#define MRT_FLUSH_VIFS 4
#define MRT_FLUSH_VIFS_STATIC 8
#define MAXVIFS 32
typedef unsigned long vifbitmap_t;
typedef unsigned short vifi_t;
#define ALL_VIFS ((vifi_t) (- 1))
#define VIFM_SET(n,m) ((m) |= (1 << (n)))
#define VIFM_CLR(n,m) ((m) &= ~(1 << (n)))
#define VIFM_ISSET(n,m) ((m) & (1 << (n)))
#define VIFM_CLRALL(m) ((m) = 0)
#define VIFM_COPY(mfrom,mto) ((mto) = (mfrom))
#define VIFM_SAME(m1,m2) ((m1) == (m2))
struct vifctl {
  vifi_t vifc_vifi;
  unsigned char vifc_flags;
  unsigned char vifc_threshold;
  unsigned int vifc_rate_limit;
  union {
    struct in_addr vifc_lcl_addr;
    int vifc_lcl_ifindex;
  };
  struct in_addr vifc_rmt_addr;
};
#define VIFF_TUNNEL 0x1
#define VIFF_SRCRT 0x2
#define VIFF_REGISTER 0x4
#define VIFF_USE_IFINDEX 0x8
struct mfcctl {
  struct in_addr mfcc_origin;
  struct in_addr mfcc_mcastgrp;
  vifi_t mfcc_parent;
  unsigned char mfcc_ttls[MAXVIFS];
  unsigned int mfcc_pkt_cnt;
  unsigned int mfcc_byte_cnt;
  unsigned int mfcc_wrong_if;
  int mfcc_expire;
};
struct sioc_sg_req {
  struct in_addr src;
  struct in_addr grp;
  unsigned long pktcnt;
  unsigned long bytecnt;
  unsigned long wrong_if;
};
struct sioc_vif_req {
  vifi_t vifi;
  unsigned long icount;
  unsigned long ocount;
  unsigned long ibytes;
  unsigned long obytes;
};
struct igmpmsg {
  __u32 unused1, unused2;
  unsigned char im_msgtype;
  unsigned char im_mbz;
  unsigned char im_vif;
  unsigned char im_vif_hi;
  struct in_addr im_src, im_dst;
};
enum {
  IPMRA_TABLE_UNSPEC,
  IPMRA_TABLE_ID,
  IPMRA_TABLE_CACHE_RES_QUEUE_LEN,
  IPMRA_TABLE_MROUTE_REG_VIF_NUM,
  IPMRA_TABLE_MROUTE_DO_ASSERT,
  IPMRA_TABLE_MROUTE_DO_PIM,
  IPMRA_TABLE_VIFS,
  IPMRA_TABLE_MROUTE_DO_WRVIFWHOLE,
  __IPMRA_TABLE_MAX
};
#define IPMRA_TABLE_MAX (__IPMRA_TABLE_MAX - 1)
enum {
  IPMRA_VIF_UNSPEC,
  IPMRA_VIF,
  __IPMRA_VIF_MAX
};
#define IPMRA_VIF_MAX (__IPMRA_VIF_MAX - 1)
enum {
  IPMRA_VIFA_UNSPEC,
  IPMRA_VIFA_IFINDEX,
  IPMRA_VIFA_VIF_ID,
  IPMRA_VIFA_FLAGS,
  IPMRA_VIFA_BYTES_IN,
  IPMRA_VIFA_BYTES_OUT,
  IPMRA_VIFA_PACKETS_IN,
  IPMRA_VIFA_PACKETS_OUT,
  IPMRA_VIFA_LOCAL_ADDR,
  IPMRA_VIFA_REMOTE_ADDR,
  IPMRA_VIFA_PAD,
  __IPMRA_VIFA_MAX
};
#define IPMRA_VIFA_MAX (__IPMRA_VIFA_MAX - 1)
enum {
  IPMRA_CREPORT_UNSPEC,
  IPMRA_CREPORT_MSGTYPE,
  IPMRA_CREPORT_VIF_ID,
  IPMRA_CREPORT_SRC_ADDR,
  IPMRA_CREPORT_DST_ADDR,
  IPMRA_CREPORT_PKT,
  IPMRA_CREPORT_TABLE,
  __IPMRA_CREPORT_MAX
};
#define IPMRA_CREPORT_MAX (__IPMRA_CREPORT_MAX - 1)
#define MFC_ASSERT_THRESH (3 * HZ)
#define IGMPMSG_NOCACHE 1
#define IGMPMSG_WRONGVIF 2
#define IGMPMSG_WHOLEPKT 3
#define IGMPMSG_WRVIFWHOLE 4
#endif
```