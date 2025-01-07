Response:
My thought process for analyzing the `if_tunnel.h` header file went something like this:

1. **Understand the Context:** The prompt clearly states this file is part of Android's Bionic library, specifically within the kernel UAPI (User Application Programming Interface) for Linux networking, focusing on tunnel interfaces. This immediately tells me the file defines structures and constants used for interacting with the Linux kernel's tunnel device drivers *from user space*.

2. **High-Level Overview - What does it *do*?**  Scanning the file, I see a lot of `#define` statements starting with `SIOC`, `GRE_`, `TUNNEL_`, and `IFLA_`. These are strong indicators of:
    * **ioctl commands:** `SIOC` suggests ioctl (input/output control) calls, which are the primary mechanism for user-space programs to configure and control kernel devices. The suffixes like `GETTUNNEL`, `ADDTUNNEL`, `DELTUNNEL` are self-explanatory.
    * **GRE flags:** `GRE_` prefixes point to flags specific to Generic Routing Encapsulation (GRE) tunnels.
    * **Generic tunnel flags:** `TUNNEL_` prefixes appear to be broader flags applicable to various types of tunnels.
    * **Netlink attributes:** `IFLA_` indicates Netlink attributes, which are used in more modern networking configurations via the `rtnetlink` socket. These attributes are used to pass configuration information for tunnel interfaces.
    * **Data structures:** The `struct ip_tunnel_parm`, `struct ip_tunnel_prl`, and `struct ip_tunnel_6rd` define how tunnel parameters are structured in memory.

3. **Break Down by Section:**  To organize the analysis, I mentally divided the file into logical sections:

    * **File Header & Includes:** Basic boilerplate to prevent multiple inclusions and standard Linux header files related to types, network interfaces (`if.h`), IP (`ip.h`), and IPv6 (`in6.h`). The `asm/byteorder.h` is important for handling endianness when communicating with the kernel.
    * **ioctl Definitions (`SIOC...`):**  These are the primary commands for interacting with tunnel devices. I'd note their purpose (get, add, delete, change tunnel configurations, Peer Route List (PRL), and 6to4 Relay Daemon (6RD) settings). I'd also emphasize their relationship to `SIOCDEVPRIVATE`, indicating they are custom ioctls for tunnel devices.
    * **GRE-Specific Definitions (`GRE_...`):**  These define bit flags within the GRE header (checksum, routing, key, sequence number, strict source route, recursion control, acknowledgment). Understanding these helps in dissecting how GRE encapsulation works.
    * **`ip_tunnel_parm` Structure:**  This structure seems crucial for creating and modifying basic IP tunnels. I'd list its members and their likely purposes (interface name, link index, flags, keys, and the inner IP header).
    * **Netlink Attributes for Generic IP Tunnels (`IFLA_IPTUN_...`):** This section indicates a more modern way to configure IP tunnels, allowing setting parameters like local/remote addresses, TTL, TOS, encapsulation settings, etc. The `enum tunnel_encap_types` is also relevant here, defining the different encapsulation methods supported.
    * **`ip_tunnel_prl` Structure:**  This seems related to Peer Route Lists, likely used to define specific routes associated with a tunnel.
    * **`ip_tunnel_6rd` Structure:** This structure is specifically for configuring 6RD tunnels, facilitating IPv6 over IPv4 networks.
    * **Netlink Attributes for GRE Tunnels (`IFLA_GRE_...`):**  Similar to the generic IP tunnel attributes, but specific to GRE. This includes GRE flags and encapsulation settings. The ERSPAN attributes indicate support for Encapsulated Remote SPAN.
    * **Netlink Attributes for VTI Tunnels (`IFLA_VTI_...`):**  These are for configuring Virtual Tunnel Interfaces (VTIs), often used in IPsec scenarios.
    * **Generic Tunnel Flags (`TUNNEL_...`):** These flags seem to provide more general options for various tunnel types.
    * **Bit Definitions for Generic Tunnel Flags (`IP_TUNNEL_..._BIT`):** These provide a way to access the individual bits within the generic tunnel flags, likely used for more fine-grained control.

4. **Connect to Android:**  The prompt specifically asks about Android relevance. Tunnels are used in Android for:
    * **VPN:**  This is the most obvious connection. VPNs heavily rely on tunneling technologies (like IPsec, which might use VTIs, or other custom VPN protocols).
    * **Tethering/Hotspot:**  While less direct, network sharing features might involve some form of local tunneling.
    * **Network Namespaces:**  Android uses network namespaces for process isolation, and tunnels are fundamental for setting up communication between namespaces.

5. **Focus on Libc Functions and Dynamic Linking (as requested):** While this header file *defines* structures and constants, it doesn't *implement* libc functions. The *usage* of these definitions occurs within libc functions like `ioctl`. Therefore, I'd explain how `ioctl` works in general. Regarding dynamic linking, the definitions here are just data. The dynamic linker's role would be in loading the libc that *uses* these definitions, but there's no direct dynamic linking action within *this* file itself. I would provide a general example of how an Android app using VPN might link against libc.

6. **Usage Errors:** Common mistakes would involve incorrect usage of the ioctl commands (wrong arguments, incorrect structure sizes), misunderstanding the bit flags, or misconfiguring the tunnel parameters.

7. **Android Framework/NDK Path:** I'd trace a hypothetical scenario:  An Android app uses the VPN API ->  the Framework calls down to native code (likely in `system/netd`) -> `netd` uses socket calls and ioctl (or Netlink) with these definitions to configure the kernel tunnel interface. For the NDK, developers might directly use socket/ioctl calls, needing to include this header file.

8. **Frida Hook Example:**  A Frida example would focus on intercepting the `ioctl` system call when a tunnel-related `SIOC` command is being used, or perhaps hooking functions within `netd` that handle tunnel configuration.

9. **Structure and Language:**  Finally, I'd organize the information clearly with headings and bullet points, using precise technical language while explaining concepts in an accessible way in Chinese, as requested.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the *details* of each flag without first explaining the overall purpose. I would then step back and provide a broader context.
* I would ensure I clearly differentiate between the *definitions* in the header file and the *implementation* within libc and the kernel.
* I would double-check my understanding of how ioctl and Netlink work and their relationship to this file.
* I would ensure the Frida example is concrete and illustrates how to observe the use of these definitions in a running Android system.

By following these steps, I can systematically analyze the header file and address all aspects of the prompt.
这是一个定义 Linux 内核用户空间 API 的头文件，用于配置和管理网络隧道接口。它位于 Android Bionic 库中，这表明 Android 系统在底层网络配置中使用了这些定义。

**文件功能概览:**

这个头文件主要定义了以下内容，用于用户空间程序与内核中的隧道设备驱动进行交互：

1. **ioctl 命令 (`SIOCGETTUNNEL`, `SIOCADDTUNNEL`, 等等):**  定义了一系列用于获取、添加、删除和修改隧道配置的 ioctl (输入/输出控制) 命令。这些命令允许用户空间的程序控制内核中隧道接口的行为。

2. **GRE 隧道选项 (`GRE_CSUM`, `GRE_KEY`, 等等):** 定义了用于配置 GRE (Generic Routing Encapsulation) 隧道头的各种标志位，例如是否启用校验和、密钥、序列号等。

3. **隧道参数结构体 (`ip_tunnel_parm`):** 定义了一个结构体，用于传递创建和修改基本 IP 隧道所需的参数，如接口名称、链路索引、输入/输出标志、密钥以及内部 IP 报头。

4. **Netlink 属性 (`IFLA_IPTUN_UNSPEC`, `IFLA_GRE_LINK`, 等等):** 定义了用于通过 Netlink 协议配置隧道接口的属性。Netlink 是一种更现代的内核与用户空间通信机制，用于替代传统的 ioctl。这些属性允许更细粒度的控制隧道参数，例如本地/远程地址、TTL、TOS、封装类型等。

5. **隧道封装类型 (`tunnel_encap_types`):** 定义了不同的隧道封装类型，例如无封装、FOU (Foo-Over-UDP)、GUE (Generic UDP Encapsulation)、MPLS。

6. **隧道封装标志 (`TUNNEL_ENCAP_FLAG_CSUM`, 等等):**  定义了与隧道封装相关的标志位，例如是否启用校验和。

7. **Peer Route List (PRL) 相关结构体和宏 (`ip_tunnel_prl`, `PRL_DEFAULT`):** 定义了用于配置 Peer Route List 的结构体和宏，PRL 允许为特定的隧道指定额外的路由信息。

8. **6RD (IPv6 Rapid Deployment) 相关结构体 (`ip_tunnel_6rd`):** 定义了用于配置 6RD 隧道的结构体，用于在 IPv4 网络上部署 IPv6。

9. **VTI (Virtual Tunnel Interface) 相关 Netlink 属性 (`IFLA_VTI_UNSPEC`, 等等):** 定义了用于配置 VTI 隧道的 Netlink 属性，VTI 隧道通常用于 IPsec VPN。

10. **通用隧道选项 (`TUNNEL_CSUM`, `TUNNEL_KEY`, 等等):** 定义了适用于多种隧道类型的通用选项标志位。

**与 Android 功能的关系及举例:**

这个头文件中的定义与 Android 系统的网络功能息息相关，主要体现在以下几个方面：

* **VPN (虚拟私人网络):** Android 设备连接 VPN 时，需要在本地和 VPN 服务器之间建立隧道。这个头文件中定义的 ioctl 命令 (例如 `SIOCADDTUNNEL`, `SIOCDELTUNNEL`, `SIOCCHGTUNNEL`) 和相关的结构体 (例如 `ip_tunnel_parm`) 就被用于创建、配置和管理这些 VPN 隧道。例如，当用户在 Android 设置中配置并连接一个 IPsec 或 L2TP 类型的 VPN 时，Android 系统会使用这些底层的接口来创建相应的隧道。

* **网络共享 (Tethering/Hotspot):**  虽然不太直接，但在某些情况下，Android 的网络共享功能可能涉及到内部的隧道技术，以隔离共享网络和设备本身的网络。

* **容器化和虚拟化:** 如果 Android 系统运行在容器化或虚拟化的环境中，这些隧道相关的接口可能被用于构建虚拟网络环境。

* **网络命名空间 (Network Namespaces):** Android 使用网络命名空间来实现网络隔离。隧道技术是连接不同网络命名空间的关键。这个头文件中的定义会被用于在不同的网络命名空间之间创建虚拟链路。

**libc 函数的功能及其实现:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是一个定义了常量、宏和数据结构的头文件。实际使用这些定义的 libc 函数主要集中在网络相关的系统调用封装中，例如 `ioctl` 函数。

**`ioctl` 函数:**

* **功能:** `ioctl` 是一个通用的设备控制操作函数，允许用户空间的程序向设备驱动程序发送控制命令并传递数据。

* **实现:** `ioctl` 是一个系统调用，其实现位于 Linux 内核中。当用户空间程序调用 `ioctl` 时，会陷入内核态。内核根据传递的文件描述符找到对应的设备驱动程序，然后调用该驱动程序中与 `ioctl` 操作码 (本文件中定义的 `SIOCGETTUNNEL` 等常量) 对应的处理函数。驱动程序会根据传递的参数执行相应的操作，例如创建隧道接口、设置隧道参数等。

**动态链接器功能及 SO 布局样本和链接处理过程:**

这个头文件本身与动态链接器的功能没有直接关系。动态链接器 (在 Android 中是 `linker64` 或 `linker`) 的主要职责是加载动态链接库 (SO 文件) 并解析库之间的依赖关系和符号引用。

**SO 布局样本 (以使用隧道功能的网络库为例):**

假设有一个名为 `libnetwork.so` 的 Android 网络库，它使用了本头文件中定义的接口来管理隧道：

```
libnetwork.so:
    NEEDED libnetd_client.so  // 依赖于 netd 客户端库
    NEEDED libc.so          // 依赖于 C 标准库

符号表:
    ...
    ioctl@LIBC             // 引用 libc.so 中的 ioctl 函数
    SIOCADDTUNNEL          // 使用了本头文件中定义的宏
    ip_tunnel_parm         // 使用了本头文件中定义的结构体
    ...
```

**链接处理过程:**

1. **编译时链接:**  当 `libnetwork.so` 被编译时，编译器会识别出对 `ioctl` 函数的调用以及对 `SIOCADDTUNNEL` 宏和 `ip_tunnel_parm` 结构体的引用。由于 `ioctl` 是 libc 的一部分，编译器会将对 `ioctl` 的调用标记为需要动态链接。`SIOCADDTUNNEL` 和 `ip_tunnel_parm` 的定义会直接包含在 `libnetwork.so` 的代码中（因为它们来自头文件）。

2. **运行时链接:** 当一个 Android 应用加载 `libnetwork.so` 时，动态链接器会执行以下步骤：
    * **加载依赖库:** 加载 `libnetd_client.so` 和 `libc.so` 到内存中。
    * **符号解析:** 找到 `libnetwork.so` 中对 `ioctl` 的未定义符号，并在已加载的 `libc.so` 中查找该符号的地址。
    * **重定位:** 将 `libnetwork.so` 中调用 `ioctl` 的指令修改为指向 `libc.so` 中 `ioctl` 函数的实际地址。
    * **宏和结构体:** 对于 `SIOCADDTUNNEL` 宏，其值在编译时就已经确定，直接嵌入到代码中。对于 `ip_tunnel_parm` 结构体，动态链接器不需要做特殊处理，因为它只是一个数据结构定义。

**假设输入与输出 (逻辑推理):**

假设我们使用 `ioctl` 系统调用来创建一个新的 GRE 隧道接口。

**假设输入:**

* 文件描述符: 指向一个网络设备套接字的有效文件描述符。
* `request`: `SIOCADDTUNNEL` 常量。
* `argp`: 指向 `ip_tunnel_parm` 结构体的指针，该结构体包含了创建隧道所需的参数，例如：
    * `name`:  希望创建的隧道接口名称，例如 "gre0"。
    * `link`:  底层网络接口的索引。
    * `i_flags`:  输入标志，例如 `GRE_CSUM` 表示启用校验和。
    * `o_flags`:  输出标志，例如 `GRE_KEY` 表示使用密钥。
    * `i_key`:  输入密钥。
    * `o_key`:  输出密钥。
    * `iph`:  内部 IP 报头的相关信息。

**预期输出:**

* **成功:**  如果 `ioctl` 调用成功，返回 0。内核会创建一个名为 "gre0" 的新的 GRE 隧道接口，并按照 `ip_tunnel_parm` 中指定的参数进行配置。可以通过 `ip addr` 命令查看到新创建的接口。
* **失败:** 如果 `ioctl` 调用失败，返回 -1，并设置 `errno` 变量来指示错误原因 (例如，权限不足、接口名称已存在、参数错误等)。

**用户或编程常见的使用错误:**

1. **权限不足:**  调用这些 ioctl 命令通常需要 root 权限或 `CAP_NET_ADMIN` 能力。普通应用直接调用可能会因为权限不足而失败。

   ```c
   #include <sys/ioctl.h>
   #include <linux/if_tunnel.h>
   #include <sys/socket.h>
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include <errno.h>

   int main() {
       int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
       if (sockfd < 0) {
           perror("socket");
           return 1;
       }

       struct ifreq ifr;
       memset(&ifr, 0, sizeof(ifr));
       strncpy(ifr.ifr_name, "gre0", IFNAMSIZ - 1);

       struct ip_tunnel_parm parm;
       memset(&parm, 0, sizeof(parm));
       strncpy(parm.name, "gre0", IFNAMSIZ - 1);
       // ... 设置其他隧道参数 ...

       if (ioctl(sockfd, SIOCADDTUNNEL, &parm) < 0) {
           perror("ioctl SIOCADDTUNNEL"); // 可能会输出 "Operation not permitted"
           close(sockfd);
           return 1;
       }

       printf("GRE tunnel created successfully.\n");
       close(sockfd);
       return 0;
   }
   ```

2. **参数错误:**  `ip_tunnel_parm` 结构体中的参数配置不正确，例如，指定的底层链路索引不存在，或者提供的 IP 地址格式错误。

3. **接口名称冲突:**  尝试创建的隧道接口名称已经存在。

4. **忘记包含必要的头文件:**  如果代码中使用了 `SIOCADDTUNNEL` 等宏或 `ip_tunnel_parm` 结构体，但没有包含 `<linux/if_tunnel.h>`，会导致编译错误。

5. **不正确的 ioctl 命令使用:**  例如，使用 `SIOCGETTUNNEL` 尝试获取一个不存在的隧道接口的信息。

**Android Framework 或 NDK 如何到达这里:**

**Android Framework 路径:**

1. **用户操作:** 用户在 Android 设置界面配置 VPN 连接。
2. **VpnService:** Framework 层的 `android.net.VpnService` 类处理 VPN 连接的生命周期。
3. **ConnectivityService:** `VpnService` 会与 `ConnectivityService` 进行交互，请求建立 VPN 连接。
4. **Netd:** `ConnectivityService` 通过 Binder IPC 调用到 native 守护进程 `netd` (`/system/bin/netd`)。
5. **Netlink/ioctl 调用:** `netd` 进程会根据 VPN 配置，使用 Netlink 消息或 `ioctl` 系统调用来配置内核中的隧道接口。例如，`netd` 可能会调用 `ioctl` 并传递 `SIOCADDTUNNEL` 命令和填充好的 `ip_tunnel_parm` 结构体来创建隧道接口。

**Android NDK 路径:**

1. **NDK 应用开发:** 开发者使用 NDK 编写 C/C++ 代码，需要进行底层的网络隧道操作。
2. **系统调用:** NDK 应用可以直接调用 Linux 系统调用，例如 `socket` 和 `ioctl`。
3. **包含头文件:**  NDK 应用需要包含 `<linux/if_tunnel.h>` 头文件才能使用其中定义的宏和结构体。
4. **ioctl 调用:** NDK 应用通过 `ioctl` 系统调用，并传递相应的命令 (如 `SIOCADDTUNNEL`) 和参数结构体来配置隧道接口。

**Frida Hook 示例调试步骤:**

假设我们想要观察 Android 系统在创建 VPN 连接时如何使用 `SIOCADDTUNNEL` ioctl 命令。

**Frida Hook 代码 (JavaScript):**

```javascript
function hook_ioctl() {
  const ioctlPtr = Module.getExportByName(null, "ioctl");
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        if (request === 0x8952) { // SIOCADDTUNNEL 的值 (需要根据实际系统确定)
          console.log("ioctl called with SIOCADDTUNNEL");
          console.log("File Descriptor:", fd);
          console.log("Request:", request);

          // 读取 ip_tunnel_parm 结构体的内容
          const ifr_name = Memory.readUtf8String(argp);
          const link = Memory.readS32(argp.add(16));
          const i_flags = Memory.readU16(argp.add(20));
          const o_flags = Memory.readU16(argp.add(22));
          // ... 读取其他字段 ...

          console.log("ip_tunnel_parm:");
          console.log("  name:", ifr_name);
          console.log("  link:", link);
          console.log("  i_flags:", i_flags);
          console.log("  o_flags:", o_flags);
          // ... 打印其他字段 ...
        }
      },
      onLeave: function (retval) {
        // console.log("ioctl returned:", retval);
      },
    });
    console.log("Hooked ioctl");
  } else {
    console.log("Failed to find ioctl");
  }
}

setImmediate(hook_ioctl);
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 Frida Server。
2. **找到目标进程:**  通常 VPN 连接的创建和管理涉及到 `system_server` 进程或 `netd` 进程。可以使用 `frida-ps -U` 命令找到目标进程的 PID。
3. **运行 Frida Hook:**  使用 Frida 连接到目标进程并运行上面的 Hook 脚本：
   ```bash
   frida -U -f <目标进程名称或 PID> -l your_hook_script.js --no-pause
   ```
4. **触发 VPN 连接:** 在 Android 设备上配置并尝试连接 VPN。
5. **观察 Frida 输出:**  当系统调用 `ioctl` 且 `request` 参数为 `SIOCADDTUNNEL` 的值时，Frida 会打印出相关的日志信息，包括文件描述符以及 `ip_tunnel_parm` 结构体中的参数，从而可以观察到 Android 系统是如何配置隧道接口的。

**注意:** `SIOCADDTUNNEL` 的实际数值可能会因 Android 版本和内核配置而异。你需要根据你的目标系统来确定其具体值。可以通过查看内核源码或在目标系统上运行 `strace` 命令来找到。

这个头文件是 Android 系统网络功能的重要组成部分，它定义了用户空间程序与内核交互，进行隧道配置的基础接口。理解其内容有助于深入了解 Android 的 VPN、网络共享等功能的实现机制。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/if_tunnel.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_IF_TUNNEL_H_
#define _UAPI_IF_TUNNEL_H_
#include <linux/types.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <asm/byteorder.h>
#define SIOCGETTUNNEL (SIOCDEVPRIVATE + 0)
#define SIOCADDTUNNEL (SIOCDEVPRIVATE + 1)
#define SIOCDELTUNNEL (SIOCDEVPRIVATE + 2)
#define SIOCCHGTUNNEL (SIOCDEVPRIVATE + 3)
#define SIOCGETPRL (SIOCDEVPRIVATE + 4)
#define SIOCADDPRL (SIOCDEVPRIVATE + 5)
#define SIOCDELPRL (SIOCDEVPRIVATE + 6)
#define SIOCCHGPRL (SIOCDEVPRIVATE + 7)
#define SIOCGET6RD (SIOCDEVPRIVATE + 8)
#define SIOCADD6RD (SIOCDEVPRIVATE + 9)
#define SIOCDEL6RD (SIOCDEVPRIVATE + 10)
#define SIOCCHG6RD (SIOCDEVPRIVATE + 11)
#define GRE_CSUM __cpu_to_be16(0x8000)
#define GRE_ROUTING __cpu_to_be16(0x4000)
#define GRE_KEY __cpu_to_be16(0x2000)
#define GRE_SEQ __cpu_to_be16(0x1000)
#define GRE_STRICT __cpu_to_be16(0x0800)
#define GRE_REC __cpu_to_be16(0x0700)
#define GRE_ACK __cpu_to_be16(0x0080)
#define GRE_FLAGS __cpu_to_be16(0x0078)
#define GRE_VERSION __cpu_to_be16(0x0007)
#define GRE_IS_CSUM(f) ((f) & GRE_CSUM)
#define GRE_IS_ROUTING(f) ((f) & GRE_ROUTING)
#define GRE_IS_KEY(f) ((f) & GRE_KEY)
#define GRE_IS_SEQ(f) ((f) & GRE_SEQ)
#define GRE_IS_STRICT(f) ((f) & GRE_STRICT)
#define GRE_IS_REC(f) ((f) & GRE_REC)
#define GRE_IS_ACK(f) ((f) & GRE_ACK)
#define GRE_VERSION_0 __cpu_to_be16(0x0000)
#define GRE_VERSION_1 __cpu_to_be16(0x0001)
#define GRE_PROTO_PPP __cpu_to_be16(0x880b)
#define GRE_PPTP_KEY_MASK __cpu_to_be32(0xffff)
struct ip_tunnel_parm {
  char name[IFNAMSIZ];
  int link;
  __be16 i_flags;
  __be16 o_flags;
  __be32 i_key;
  __be32 o_key;
  struct iphdr iph;
};
enum {
  IFLA_IPTUN_UNSPEC,
  IFLA_IPTUN_LINK,
  IFLA_IPTUN_LOCAL,
  IFLA_IPTUN_REMOTE,
  IFLA_IPTUN_TTL,
  IFLA_IPTUN_TOS,
  IFLA_IPTUN_ENCAP_LIMIT,
  IFLA_IPTUN_FLOWINFO,
  IFLA_IPTUN_FLAGS,
  IFLA_IPTUN_PROTO,
  IFLA_IPTUN_PMTUDISC,
  IFLA_IPTUN_6RD_PREFIX,
  IFLA_IPTUN_6RD_RELAY_PREFIX,
  IFLA_IPTUN_6RD_PREFIXLEN,
  IFLA_IPTUN_6RD_RELAY_PREFIXLEN,
  IFLA_IPTUN_ENCAP_TYPE,
  IFLA_IPTUN_ENCAP_FLAGS,
  IFLA_IPTUN_ENCAP_SPORT,
  IFLA_IPTUN_ENCAP_DPORT,
  IFLA_IPTUN_COLLECT_METADATA,
  IFLA_IPTUN_FWMARK,
  __IFLA_IPTUN_MAX,
};
#define IFLA_IPTUN_MAX (__IFLA_IPTUN_MAX - 1)
enum tunnel_encap_types {
  TUNNEL_ENCAP_NONE,
  TUNNEL_ENCAP_FOU,
  TUNNEL_ENCAP_GUE,
  TUNNEL_ENCAP_MPLS,
};
#define TUNNEL_ENCAP_FLAG_CSUM (1 << 0)
#define TUNNEL_ENCAP_FLAG_CSUM6 (1 << 1)
#define TUNNEL_ENCAP_FLAG_REMCSUM (1 << 2)
#define SIT_ISATAP 0x0001
struct ip_tunnel_prl {
  __be32 addr;
  __u16 flags;
  __u16 __reserved;
  __u32 datalen;
  __u32 __reserved2;
};
#define PRL_DEFAULT 0x0001
struct ip_tunnel_6rd {
  struct in6_addr prefix;
  __be32 relay_prefix;
  __u16 prefixlen;
  __u16 relay_prefixlen;
};
enum {
  IFLA_GRE_UNSPEC,
  IFLA_GRE_LINK,
  IFLA_GRE_IFLAGS,
  IFLA_GRE_OFLAGS,
  IFLA_GRE_IKEY,
  IFLA_GRE_OKEY,
  IFLA_GRE_LOCAL,
  IFLA_GRE_REMOTE,
  IFLA_GRE_TTL,
  IFLA_GRE_TOS,
  IFLA_GRE_PMTUDISC,
  IFLA_GRE_ENCAP_LIMIT,
  IFLA_GRE_FLOWINFO,
  IFLA_GRE_FLAGS,
  IFLA_GRE_ENCAP_TYPE,
  IFLA_GRE_ENCAP_FLAGS,
  IFLA_GRE_ENCAP_SPORT,
  IFLA_GRE_ENCAP_DPORT,
  IFLA_GRE_COLLECT_METADATA,
  IFLA_GRE_IGNORE_DF,
  IFLA_GRE_FWMARK,
  IFLA_GRE_ERSPAN_INDEX,
  IFLA_GRE_ERSPAN_VER,
  IFLA_GRE_ERSPAN_DIR,
  IFLA_GRE_ERSPAN_HWID,
  __IFLA_GRE_MAX,
};
#define IFLA_GRE_MAX (__IFLA_GRE_MAX - 1)
#define VTI_ISVTI (( __be16) 0x0001)
enum {
  IFLA_VTI_UNSPEC,
  IFLA_VTI_LINK,
  IFLA_VTI_IKEY,
  IFLA_VTI_OKEY,
  IFLA_VTI_LOCAL,
  IFLA_VTI_REMOTE,
  IFLA_VTI_FWMARK,
  __IFLA_VTI_MAX,
};
#define IFLA_VTI_MAX (__IFLA_VTI_MAX - 1)
#define TUNNEL_CSUM __cpu_to_be16(0x01)
#define TUNNEL_ROUTING __cpu_to_be16(0x02)
#define TUNNEL_KEY __cpu_to_be16(0x04)
#define TUNNEL_SEQ __cpu_to_be16(0x08)
#define TUNNEL_STRICT __cpu_to_be16(0x10)
#define TUNNEL_REC __cpu_to_be16(0x20)
#define TUNNEL_VERSION __cpu_to_be16(0x40)
#define TUNNEL_NO_KEY __cpu_to_be16(0x80)
#define TUNNEL_DONT_FRAGMENT __cpu_to_be16(0x0100)
#define TUNNEL_OAM __cpu_to_be16(0x0200)
#define TUNNEL_CRIT_OPT __cpu_to_be16(0x0400)
#define TUNNEL_GENEVE_OPT __cpu_to_be16(0x0800)
#define TUNNEL_VXLAN_OPT __cpu_to_be16(0x1000)
#define TUNNEL_NOCACHE __cpu_to_be16(0x2000)
#define TUNNEL_ERSPAN_OPT __cpu_to_be16(0x4000)
#define TUNNEL_GTP_OPT __cpu_to_be16(0x8000)
#define TUNNEL_OPTIONS_PRESENT (TUNNEL_GENEVE_OPT | TUNNEL_VXLAN_OPT | TUNNEL_ERSPAN_OPT | TUNNEL_GTP_OPT)
enum {
  IP_TUNNEL_CSUM_BIT = 0U,
  IP_TUNNEL_ROUTING_BIT,
  IP_TUNNEL_KEY_BIT,
  IP_TUNNEL_SEQ_BIT,
  IP_TUNNEL_STRICT_BIT,
  IP_TUNNEL_REC_BIT,
  IP_TUNNEL_VERSION_BIT,
  IP_TUNNEL_NO_KEY_BIT,
  IP_TUNNEL_DONT_FRAGMENT_BIT,
  IP_TUNNEL_OAM_BIT,
  IP_TUNNEL_CRIT_OPT_BIT,
  IP_TUNNEL_GENEVE_OPT_BIT,
  IP_TUNNEL_VXLAN_OPT_BIT,
  IP_TUNNEL_NOCACHE_BIT,
  IP_TUNNEL_ERSPAN_OPT_BIT,
  IP_TUNNEL_GTP_OPT_BIT,
  IP_TUNNEL_VTI_BIT,
  IP_TUNNEL_SIT_ISATAP_BIT = IP_TUNNEL_VTI_BIT,
  IP_TUNNEL_PFCP_OPT_BIT,
  __IP_TUNNEL_FLAG_NUM,
};
#endif

"""

```