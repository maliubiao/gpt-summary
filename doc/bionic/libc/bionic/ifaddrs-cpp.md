Response:
Let's break down the thought process for generating the detailed analysis of `ifaddrs.cpp`.

**1. Understanding the Core Request:**

The initial request asks for a comprehensive analysis of the `ifaddrs.cpp` file. Key aspects to cover are:

* **Functionality:** What does this code do?
* **Android Relevance:** How does it tie into Android's workings?
* **Detailed Implementation:**  Explain the internal workings of each libc function.
* **Dynamic Linking:**  Explain any dynamic linker interaction.
* **Logic & Assumptions:** Identify assumptions, inputs, and outputs.
* **Common Errors:** Point out potential user/programmer mistakes.
* **Android Integration:** Explain how Android frameworks/NDK use this.
* **Debugging:** Provide Frida hook examples.

**2. Initial Code Examination and Keyword Identification:**

The first step is to read through the code and identify key functions, data structures, and concepts. Keywords and structures that immediately stand out are:

* `getifaddrs`, `freeifaddrs`: These are the primary exported functions, indicating the purpose is to retrieve and release interface addresses.
* `ifaddrs`: The core data structure being manipulated.
* `sockaddr`, `sockaddr_in`, `sockaddr_in6`, `sockaddr_ll`: Network address structures.
* `netlink`:  A clear indication of using the netlink socket interface.
* `RTM_NEWLINK`, `RTM_NEWADDR`:  Netlink message types related to network interfaces and addresses.
* `ioctl`, `SIOCGIFFLAGS`:  A fallback mechanism using ioctl.
* `ifreq`:  Structure used with ioctl to get interface flags.
* `FIRST_APPLICATION_UID`: Indicates special handling for system processes.
* `async_safe_log`: Logging within the bionic library.

**3. Deconstructing the Functionality - High Level:**

From the keywords, the central function `getifaddrs` seems to:

* Retrieve information about network interfaces and their associated addresses.
* Use netlink as the primary mechanism.
* Potentially fall back to `ioctl` for certain information.
* Allocate memory to store the results in a linked list of `ifaddrs` structures.
* `freeifaddrs` is responsible for releasing this allocated memory.

**4. Detailed Function Analysis - `getifaddrs`:**

Now, delve deeper into `getifaddrs`:

* **Initialization:** Sets `*out` to `nullptr` to initialize the list.
* **Netlink Setup:** Creates a `NetlinkConnection`. This suggests interaction with the kernel's network subsystem.
* **Conditional `RTM_GETLINK`:**  Notices the `getuid() < FIRST_APPLICATION_UID` check, suggesting different behavior for system and user apps. Hypothesizes that system apps can get more detailed link information.
* **`RTM_GETADDR`:**  This seems to be the primary way to get address information.
* **Callback Function `__getifaddrs_callback`:** Realizes this is where the actual processing of netlink messages occurs.
* **Error Handling:**  Checks for `getaddr_success` and frees memory if it fails.
* **Fallback Mechanisms:**  If `getlink_success` is false, it uses `resolve_or_remove_nameless_interfaces` and `get_interface_flags_via_ioctl`. This indicates handling cases where link information isn't available via netlink.

**5. Detailed Function Analysis - `__getifaddrs_callback`:**

This is the most complex part. Break it down by message type:

* **`RTM_NEWLINK`:**  Handles information about network interfaces themselves (name, flags, hardware address). Focus on how it populates the `ifaddrs_storage` structure.
* **`RTM_NEWADDR`:** Handles information about addresses assigned to interfaces (IP addresses, netmasks, broadcast addresses). Note how it tries to correlate with existing `RTM_NEWLINK` information.

**6. Detailed Function Analysis - Helper Functions:**

Analyze functions like `resolve_or_remove_nameless_interfaces`, `get_interface_flags_via_ioctl`, and the methods within `ifaddrs_storage`. Understand their purpose in filling the `ifaddrs` structure.

**7. Android Relevance:**

Think about where this information is used in Android:

* **Network Settings:**  Displaying IP addresses, interface status.
* **Connectivity Services:**  Managing network connections.
* **VPN Apps:**  Inspecting network interfaces.
* **NDK Networking:**  Apps using sockets directly need this information.

**8. Dynamic Linking:**

Recognize that `getifaddrs` is part of `libc.so`. Explain the basic dynamic linking process – finding the library, resolving symbols. Create a simple example `so` layout.

**9. Assumptions, Inputs, Outputs:**

Consider what `getifaddrs` assumes about the system state and what kind of output it produces (a linked list of `ifaddrs` structures).

**10. Common Errors:**

Think about typical mistakes when using `getifaddrs` and `freeifaddrs`, like memory leaks.

**11. Android Framework/NDK Usage:**

Trace how the Android framework or NDK might call `getifaddrs`. Consider a high-level example like `ConnectivityManager`.

**12. Frida Hooking:**

Identify key functions to hook (like `getifaddrs` itself or potentially the callback). Construct simple Frida scripts to demonstrate intercepting calls and examining arguments/return values.

**13. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use examples and code snippets where appropriate. Maintain a coherent flow and address all parts of the initial request.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the individual `Set...` methods in `ifaddrs_storage`. **Correction:** Realize the netlink message processing in `__getifaddrs_callback` is the core logic that drives these methods.
* **Initial thought:**  Assume `ioctl` is always used. **Correction:**  Understand that `ioctl` is a fallback if `RTM_GETLINK` fails, highlighting the importance of the conditional logic.
* **Initial thought:** Overcomplicate the dynamic linking explanation. **Correction:** Keep the dynamic linking explanation relatively concise and focus on the core concepts relevant to this specific context.

By following this detailed and iterative process, breaking down the problem into smaller, manageable parts, and continuously refining the understanding, one can generate a comprehensive and accurate analysis of the given source code.
好的，让我们深入分析 `bionic/libc/bionic/ifaddrs.cpp` 这个文件。

**文件功能概述**

`ifaddrs.cpp` 文件实现了获取网络接口地址信息的标准 POSIX 函数 `getifaddrs()` 和释放该函数分配内存的 `freeifaddrs()`。 它的主要功能是：

1. **获取网络接口信息:**  `getifaddrs()` 函数负责收集系统中所有网络接口的详细信息，包括接口名称、IP 地址、子网掩码、广播地址、点对点链路的目标地址、接口标志（如是否启动、是否支持广播等）。
2. **数据结构组织:** 它将获取到的信息组织成一个链表，链表的每个节点都是一个 `ifaddrs` 结构体。
3. **内存管理:**  `freeifaddrs()` 函数负责释放 `getifaddrs()` 分配的用于存储接口信息的内存，防止内存泄漏。

**与 Android 功能的关系及举例说明**

这个文件是 Android 基础 C 库 (bionic) 的一部分，因此它提供的网络接口信息功能是 Android 系统网络功能的基础。Android 的很多上层组件和服务依赖于这些信息来执行各种网络操作。

**举例说明:**

* **网络设置应用:** Android 的网络设置应用需要显示当前设备的 IP 地址、连接状态、Wi-Fi 或移动网络的接口信息。这些信息正是通过调用 `getifaddrs()` 获取的。
* **ConnectivityManager 服务:** Android 的 `ConnectivityManager` 服务负责管理设备的网络连接。它需要获取接口信息来判断网络状态、选择合适的网络路由等。
* **VPN 应用:** VPN 应用需要获取当前网络接口的信息，以便建立 VPN 连接和路由网络流量。
* **NDK 网络编程:** 使用 NDK 进行网络编程的开发者可以直接调用 `getifaddrs()` 来获取网络接口信息，进行更底层的网络操作。例如，一个网络监控应用可以使用它来列出所有活跃的网络接口及其属性。

**libc 函数的详细实现**

下面详细解释 `ifaddrs.cpp` 中关键 libc 函数的实现：

**1. `getifaddrs(ifaddrs** out)`**

* **初始化:** 首先将 `*out` 指针设置为 `nullptr`，表示链表的起始为空。
* **使用 Netlink 获取信息:**  这是获取接口信息的主要方式。
    * 创建一个 `NetlinkConnection` 对象，用于与内核的网络子系统通信。
    * **区分系统应用和普通应用:**  `getifaddrs` 会检查当前进程的 UID。如果 UID 小于 `FIRST_APPLICATION_UID` (通常表示系统应用)，则会尝试发送 `RTM_GETLINK` 消息。`RTM_GETLINK` 用于获取更详细的接口链路层信息，例如接口名称和硬件地址。普通应用由于 SELinux 策略的限制，可能无法发送此消息。
    * 发送 `RTM_GETADDR` 消息：无论是否发送 `RTM_GETLINK`，都会发送 `RTM_GETADDR` 消息，用于获取接口的地址信息（IP 地址、掩码等）。
    * 调用 `nc.ReadResponses(__getifaddrs_callback, out)`：接收来自内核的 Netlink 响应，并将每个响应传递给回调函数 `__getifaddrs_callback` 进行处理。 `out` 指针作为上下文传递给回调函数，用于构建接口信息链表。
* **处理获取失败的情况:** 如果 `RTM_GETADDR` 请求失败，则释放已分配的内存，并将 `*out` 设置为 `nullptr` 并返回 -1，指示出错。
* **后处理 (当 `RTM_GETLINK` 失败时):** 如果 `RTM_GETLINK` 失败（通常是普通应用的情况），则需要进行额外的处理：
    * **`resolve_or_remove_nameless_interfaces(out)`:**  遍历已获取的接口信息，对于那些没有名称的接口（可能是因为没有收到 `RTM_GETLINK` 消息），尝试使用 `if_indextoname()` 函数通过接口索引获取接口名称。如果仍然无法获取名称，则将该接口信息从链表中移除。
    * **`get_interface_flags_via_ioctl(out)`:**  由于没有 `RTM_GETLINK` 信息，接口的标志（如 IFF_UP, IFF_BROADCAST）可能没有设置。此函数创建一个 socket，并使用 `ioctl(SIOCGIFFLAGS)` 系统调用来获取每个接口的标志信息。
* **返回结果:**  如果一切顺利，函数返回 0，`*out` 指向包含所有接口信息的 `ifaddrs` 链表的头部。

**2. `freeifaddrs(ifaddrs* list)`**

* **遍历链表:**  函数遍历 `getifaddrs()` 创建的 `ifaddrs` 链表。
* **释放内存:** 对于链表中的每个 `ifaddrs` 结构体，使用 `free(current)` 释放其占用的内存。

**涉及 dynamic linker 的功能**

`ifaddrs.cpp` 本身的代码并没有直接涉及动态链接器的操作。但是，`getifaddrs` 和 `freeifaddrs` 这两个函数是 `libc.so` 共享库的一部分。当应用程序调用这些函数时，动态链接器负责将应用程序的调用链接到 `libc.so` 中对应的函数实现。

**so 布局样本 (简化版):**

假设 `libc.so` 的部分布局如下：

```
libc.so:
    .text:
        ...
        [getifaddrs 函数的机器码]  <-- getifaddrs 的入口地址
        ...
        [freeifaddrs 函数的机器码] <-- freeifaddrs 的入口地址
        ...
    .data:
        ...
    .symtab:
        ...
        getifaddrs (address: 0xXXXXXXXX)
        freeifaddrs (address: 0xYYYYYYYY)
        ...
```

**链接的处理过程:**

1. **编译时:** 当应用程序代码中调用 `getifaddrs()` 时，编译器会生成一个对外部符号 `getifaddrs` 的引用。
2. **链接时:**  静态链接器会将这些未解析的符号信息记录在生成的可执行文件中。
3. **运行时:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载程序依赖的共享库，例如 `libc.so`。
4. **符号解析:** 动态链接器会解析应用程序中对 `getifaddrs` 和 `freeifaddrs` 等符号的引用。它会在已加载的 `libc.so` 的符号表 (`.symtab`) 中查找这些符号的地址。
5. **重定位:** 找到符号的地址后，动态链接器会更新应用程序代码中对这些符号的引用，将其指向 `libc.so` 中实际的函数地址。
6. **调用:** 当应用程序执行到调用 `getifaddrs()` 的指令时，程序会跳转到动态链接器解析出的 `libc.so` 中 `getifaddrs` 函数的地址执行。

**逻辑推理，假设输入与输出**

**假设输入:**

一个 Android 设备具有以下网络接口：

* **wlan0:**  已连接 Wi-Fi，IP 地址为 192.168.1.100，子网掩码 255.255.255.0。
* **eth0:**  未连接网线，没有 IP 地址。
* **lo:**  本地回环接口，IP 地址为 127.0.0.1，子网掩码 255.0.0.0。

**预期输出 (简化版):**

`getifaddrs()` 返回的链表 `ifaddrs` 结构可能包含以下信息（顺序可能不同，细节可能更多）：

```
ifaddrs 1:
    ifa_name: "wlan0"
    ifa_addr: { sa_family: AF_INET, sin_addr: 192.168.1.100 }
    ifa_netmask: { sa_family: AF_INET, sin_addr: 255.255.255.0 }
    ifa_broadaddr: { sa_family: AF_INET, sin_addr: 192.168.1.255 }  (可能存在)
    ifa_flags: ... (IFF_UP | IFF_BROADCAST | ...)

ifaddrs 2:
    ifa_name: "wlan0" (可能存在多个 ifaddr 结构对应同一个接口，例如 IPv6 地址)
    ifa_addr: { sa_family: AF_INET6, sin6_addr: ... }
    ifa_netmask: { sa_family: AF_INET6, sin6_addr: ... }
    ifa_flags: ...

ifaddrs 3:
    ifa_name: "eth0"
    ifa_addr: null
    ifa_netmask: null
    ifa_flags: ... (IFF_DOWN | ...)

ifaddrs 4:
    ifa_name: "lo"
    ifa_addr: { sa_family: AF_INET, sin_addr: 127.0.0.1 }
    ifa_netmask: { sa_family: AF_INET, sin_addr: 255.0.0.0 }
    ifa_flags: ... (IFF_UP | IFF_LOOPBACK | ...)

ifaddrs 5:
    ifa_name: "lo" (可能存在 IPv6 地址)
    ifa_addr: { sa_family: AF_INET6, sin6_addr: ::1 }
    ifa_netmask: ...
    ifa_flags: ...
```

**用户或编程常见的使用错误**

1. **忘记调用 `freeifaddrs()` 释放内存:** 这是最常见的错误。如果 `getifaddrs()` 返回的链表没有被 `freeifaddrs()` 释放，会导致内存泄漏。

   ```c
   #include <ifaddrs.h>
   #include <stdio.h>
   #include <stdlib.h>

   int main() {
       struct ifaddrs *ifap;
       if (getifaddrs(&ifap) == 0) {
           // 处理 ifap 指向的接口信息
           // 错误：忘记调用 freeifaddrs(ifap);
           return 0;
       } else {
           perror("getifaddrs");
           return 1;
       }
   }
   ```

2. **错误地访问 `ifaddrs` 结构体中的指针:** `ifaddrs` 结构体包含指向 `sockaddr` 结构的指针 (`ifa_addr`, `ifa_netmask`, `ifa_broadaddr`, `ifa_dstaddr`). 用户需要检查这些指针是否为 `NULL`，然后再访问其指向的内容，特别是对于没有配置地址的接口。

   ```c
   #include <ifaddrs.h>
   #include <stdio.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>

   int main() {
       struct ifaddrs *ifap, *ifa;
       if (getifaddrs(&ifap) == 0) {
           for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
               if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET) {
                   struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
                   printf("Interface: %s, Address: %s\n", ifa->ifa_name, inet_ntoa(sa->sin_addr));
               } else {
                   printf("Interface: %s, No IPv4 address\n", ifa->ifa_name);
               }
           }
           freeifaddrs(ifap);
           return 0;
       } else {
           perror("getifaddrs");
           return 1;
       }
   }
   ```

3. **假设接口信息的顺序:** `getifaddrs()` 返回的接口信息顺序是不确定的，不应该依赖于特定的顺序。

**Android framework 或 NDK 如何一步步到达这里**

**Android Framework 示例 (Java):**

1. **应用层 (Java):** 应用程序可能需要获取网络接口信息，例如获取设备 IP 地址。
2. **`java.net.NetworkInterface`:**  Java SDK 提供了 `NetworkInterface` 类来获取网络接口信息。
3. **JNI 调用:** `NetworkInterface` 的某些方法，例如 `getNetworkInterfaces()`，最终会通过 JNI (Java Native Interface) 调用到底层的 native 代码。
4. **`android_net_utils.cpp` 或相关 native 代码:** 在 Android 的 framework 中，会有相应的 native 代码来处理 `NetworkInterface` 的 JNI 调用。
5. **系统调用 `getifaddrs`:**  这些 native 代码最终会调用 bionic 库中的 `getifaddrs()` 函数来获取网络接口信息。

**NDK 示例 (C/C++):**

1. **NDK 应用代码 (C/C++):**  NDK 应用可以直接包含 `<ifaddrs.h>` 并调用 `getifaddrs()` 函数。
2. **动态链接:**  编译后的 NDK 应用在运行时会链接到 `libc.so`，动态链接器会将 `getifaddrs()` 的调用链接到 bionic 库中的实现。

**Frida Hook 示例调试步骤**

假设我们要 hook `getifaddrs` 函数，查看其返回值和输出的接口信息。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, 'libc.so');
  if (libc) {
    const getifaddrsPtr = Module.findExportByName(libc.name, 'getifaddrs');
    if (getifaddrsPtr) {
      Interceptor.attach(getifaddrsPtr, {
        onEnter: function (args) {
          console.log('[+] getifaddrs called');
        },
        onLeave: function (retval) {
          console.log('[+] getifaddrs returned:', retval);
          const ifapPtr = Memory.readPointer(this.context.r0); // 假设 Android 32 位架构，返回值通常在 r0
          if (ifapPtr.isNull()) {
            console.log('[-] getifaddrs returned NULL');
            return;
          }

          console.log('[+] Network Interfaces:');
          let current = ifapPtr;
          while (!current.isNull()) {
            const ifa_name = current.readPointer().readCString();
            const ifa_addr_ptr = current.add(Process.pointerSize).readPointer(); // 假设 ifa_addr 是第二个字段
            let ipAddress = 'N/A';
            if (!ifa_addr_ptr.isNull()) {
              const sa_family = ifa_addr_ptr.readU16();
              if (sa_family === 2) { // AF_INET
                const sin_addr_ptr = ifa_addr_ptr.add(4); // sockaddr_in 的 sin_addr 偏移
                ipAddress = inet_ntoa(sin_addr_ptr.readU32());
              } else if (sa_family === 10) { // AF_INET6
                ipAddress = 'IPv6 Address'; // 简化处理 IPv6
              }
            }
            console.log(`  Interface: ${ifa_name}, Address: ${ipAddress}`);
            current = current.add(Process.pointerSize * 2).readPointer(); // 假设 ifa_next 是最后一个字段
          }
        }
      });
    } else {
      console.log('[-] Could not find getifaddrs');
    }
  } else {
    console.log('[-] Could not find libc.so');
  }
}

function inet_ntoa(ip) {
  const a = (ip & 0xff) >>> 0;
  const b = (ip >>> 8) & 0xff;
  const c = (ip >>> 16) & 0xff;
  const d = (ip >>> 24) & 0xff;
  return `${a}.${b}.${c}.${d}`;
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **运行目标应用:** 运行你想要监控其网络接口信息获取的应用。
3. **执行 Frida 命令:** 使用 Frida 连接到目标应用并加载 hook 脚本。例如：

   ```bash
   frida -U -f <package_name> -l getifaddrs_hook.js --no-pause
   ```

   或者，如果应用已经在运行：

   ```bash
   frida -U <package_name> -l getifaddrs_hook.js
   ```

4. **观察输出:** 当目标应用调用 `getifaddrs` 时，Frida 脚本会拦截调用，打印进入和退出信息，并尝试解析和显示获取到的网络接口信息。你需要根据你的 Android 版本和架构调整结构体字段的偏移量。

**注意事项:**

* Hook 系统函数需要 root 权限。
* 上面的 Frida 脚本是一个简化的示例，可能需要根据具体的 Android 版本和架构进行调整，特别是 `ifaddrs` 结构体的布局和返回值的位置。
* 错误处理和更全面的接口信息解析需要进一步完善。

希望这个详细的分析对你有所帮助！

Prompt: 
```
这是目录为bionic/libc/bionic/ifaddrs.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ifaddrs.h>

#include <async_safe/log.h>
#include <cutils/misc.h>           // FIRST_APPLICATION_UID
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "private/ErrnoRestorer.h"

#include "bionic_netlink.h"

// The public ifaddrs struct is full of pointers. Rather than track several
// different allocations, we use a maximally-sized structure with the public
// part at offset 0, and pointers into its hidden tail.
struct ifaddrs_storage {
  // Must come first, so that `ifaddrs_storage` is-a `ifaddrs`.
  ifaddrs ifa;

  // The interface index, so we can match RTM_NEWADDR messages with
  // earlier RTM_NEWLINK messages (to copy the interface flags).
  int interface_index;

  // Storage for the pointers in `ifa`.
  sockaddr_storage addr;
  sockaddr_storage netmask;
  sockaddr_storage ifa_ifu;
  char name[IFNAMSIZ + 1];

  explicit ifaddrs_storage(ifaddrs** list) {
    memset(this, 0, sizeof(*this));

    // push_front onto `list`.
    ifa.ifa_next = *list;
    *list = reinterpret_cast<ifaddrs*>(this);
  }

  void SetAddress(int family, const void* data, size_t byteCount) {
    // The kernel currently uses the order IFA_ADDRESS, IFA_LOCAL, IFA_BROADCAST
    // in inet_fill_ifaddr, but let's not assume that will always be true...
    if (ifa.ifa_addr == nullptr) {
      // This is an IFA_ADDRESS and haven't seen an IFA_LOCAL yet, so assume this is the
      // local address. SetLocalAddress will fix things if we later see an IFA_LOCAL.
      ifa.ifa_addr = CopyAddress(family, data, byteCount, &addr);
    } else {
      // We already saw an IFA_LOCAL, which implies this is a destination address.
      ifa.ifa_dstaddr = CopyAddress(family, data, byteCount, &ifa_ifu);
    }
  }

  void SetBroadcastAddress(int family, const void* data, size_t byteCount) {
    // ifa_broadaddr and ifa_dstaddr overlap in a union. Unfortunately, it's possible
    // to have an interface with both. Keeping the last thing the kernel gives us seems
    // to be glibc 2.19's behavior too, so our choice is being source compatible with
    // badly-written code that assumes ifa_broadaddr and ifa_dstaddr are interchangeable
    // or supporting interfaces with both addresses configured. My assumption is that
    // bad code is more common than weird network interfaces...
    ifa.ifa_broadaddr = CopyAddress(family, data, byteCount, &ifa_ifu);
  }

  void SetLocalAddress(int family, const void* data, size_t byteCount) {
    // The kernel source says "for point-to-point IFA_ADDRESS is DESTINATION address,
    // local address is supplied in IFA_LOCAL attribute".
    //   -- http://lxr.free-electrons.com/source/include/uapi/linux/if_addr.h#L17

    // So copy any existing IFA_ADDRESS into ifa_dstaddr...
    if (ifa.ifa_addr != nullptr) {
      ifa.ifa_dstaddr = reinterpret_cast<sockaddr*>(memcpy(&ifa_ifu, &addr, sizeof(addr)));
    }
    // ...and then put this IFA_LOCAL into ifa_addr.
    ifa.ifa_addr = CopyAddress(family, data, byteCount, &addr);
  }

  // Netlink gives us the prefix length as a bit count. We need to turn
  // that into a BSD-compatible netmask represented by a sockaddr*.
  void SetNetmask(int family, size_t prefix_length) {
    // ...and work out the netmask from the prefix length.
    netmask.ss_family = family;
    uint8_t* dst = SockaddrBytes(family, &netmask);
    memset(dst, 0xff, prefix_length / 8);
    if ((prefix_length % 8) != 0) {
      dst[prefix_length/8] = (0xff << (8 - (prefix_length % 8)));
    }
    ifa.ifa_netmask = reinterpret_cast<sockaddr*>(&netmask);
  }

  void SetPacketAttributes(int ifindex, unsigned short hatype, unsigned char halen) {
    sockaddr_ll* sll = reinterpret_cast<sockaddr_ll*>(&addr);
    sll->sll_ifindex = ifindex;
    sll->sll_hatype = hatype;
    sll->sll_halen = halen;
  }

 private:
  sockaddr* CopyAddress(int family, const void* data, size_t byteCount, sockaddr_storage* ss) {
    // Netlink gives us the address family in the header, and the
    // sockaddr_in or sockaddr_in6 bytes as the payload. We need to
    // stitch the two bits together into the sockaddr that's part of
    // our portable interface.
    ss->ss_family = family;
    memcpy(SockaddrBytes(family, ss), data, byteCount);

    // For IPv6 we might also have to set the scope id.
    if (family == AF_INET6 && (IN6_IS_ADDR_LINKLOCAL(data) || IN6_IS_ADDR_MC_LINKLOCAL(data))) {
      reinterpret_cast<sockaddr_in6*>(ss)->sin6_scope_id = interface_index;
    }

    return reinterpret_cast<sockaddr*>(ss);
  }

  // Returns a pointer to the first byte in the address data (which is
  // stored in network byte order).
  uint8_t* SockaddrBytes(int family, sockaddr_storage* ss) {
    if (family == AF_INET) {
      sockaddr_in* ss4 = reinterpret_cast<sockaddr_in*>(ss);
      return reinterpret_cast<uint8_t*>(&ss4->sin_addr);
    } else if (family == AF_INET6) {
      sockaddr_in6* ss6 = reinterpret_cast<sockaddr_in6*>(ss);
      return reinterpret_cast<uint8_t*>(&ss6->sin6_addr);
    } else if (family == AF_PACKET) {
      sockaddr_ll* sll = reinterpret_cast<sockaddr_ll*>(ss);
      return reinterpret_cast<uint8_t*>(&sll->sll_addr);
    }
    return nullptr;
  }
};

static void __getifaddrs_callback(void* context, nlmsghdr* hdr) {
  ifaddrs** out = reinterpret_cast<ifaddrs**>(context);

  if (hdr->nlmsg_type == RTM_NEWLINK) {
    ifinfomsg* ifi = reinterpret_cast<ifinfomsg*>(NLMSG_DATA(hdr));

    // Create a new ifaddr entry, and set the interface index and flags.
    ifaddrs_storage* new_addr = new ifaddrs_storage(out);
    new_addr->interface_index = ifi->ifi_index;
    new_addr->ifa.ifa_flags = ifi->ifi_flags;

    // Go through the various bits of information and find the name.
    rtattr* rta = IFLA_RTA(ifi);
    size_t rta_len = IFLA_PAYLOAD(hdr);
    while (RTA_OK(rta, rta_len)) {
      if (rta->rta_type == IFLA_ADDRESS) {
          if (RTA_PAYLOAD(rta) < sizeof(new_addr->addr)) {
            new_addr->SetAddress(AF_PACKET, RTA_DATA(rta), RTA_PAYLOAD(rta));
            new_addr->SetPacketAttributes(ifi->ifi_index, ifi->ifi_type, RTA_PAYLOAD(rta));
          }
      } else if (rta->rta_type == IFLA_BROADCAST) {
          if (RTA_PAYLOAD(rta) < sizeof(new_addr->ifa_ifu)) {
            new_addr->SetBroadcastAddress(AF_PACKET, RTA_DATA(rta), RTA_PAYLOAD(rta));
            new_addr->SetPacketAttributes(ifi->ifi_index, ifi->ifi_type, RTA_PAYLOAD(rta));
          }
      } else if (rta->rta_type == IFLA_IFNAME) {
          if (RTA_PAYLOAD(rta) < sizeof(new_addr->name)) {
            memcpy(new_addr->name, RTA_DATA(rta), RTA_PAYLOAD(rta));
            new_addr->ifa.ifa_name = new_addr->name;
          }
      }
      rta = RTA_NEXT(rta, rta_len);
    }
  } else if (hdr->nlmsg_type == RTM_NEWADDR) {
    ifaddrmsg* msg = reinterpret_cast<ifaddrmsg*>(NLMSG_DATA(hdr));

    // We might already know about this interface from an RTM_NEWLINK message.
    const ifaddrs_storage* known_addr = reinterpret_cast<const ifaddrs_storage*>(*out);
    while (known_addr != nullptr && known_addr->interface_index != static_cast<int>(msg->ifa_index)) {
      known_addr = reinterpret_cast<const ifaddrs_storage*>(known_addr->ifa.ifa_next);
    }

    // Create a new ifaddr entry, and set the interface index.
    ifaddrs_storage* new_addr = new ifaddrs_storage(out);
    new_addr->interface_index = static_cast<int>(msg->ifa_index);

    // If this is a known interface, copy what we already know.
    // If we don't know about this interface yet, we try to resolve the name and flags using ioctl
    // calls during postprocessing.
    if (known_addr != nullptr) {
      strcpy(new_addr->name, known_addr->name);
      new_addr->ifa.ifa_name = new_addr->name;
      new_addr->ifa.ifa_flags = known_addr->ifa.ifa_flags;
    }

    // Go through the various bits of information and find the name, address
    // and any broadcast/destination address.
    rtattr* rta = IFA_RTA(msg);
    size_t rta_len = IFA_PAYLOAD(hdr);
    while (RTA_OK(rta, rta_len)) {
      if (rta->rta_type == IFA_ADDRESS) {
        if (msg->ifa_family == AF_INET || msg->ifa_family == AF_INET6) {
          new_addr->SetAddress(msg->ifa_family, RTA_DATA(rta), RTA_PAYLOAD(rta));
          new_addr->SetNetmask(msg->ifa_family, msg->ifa_prefixlen);
        }
      } else if (rta->rta_type == IFA_BROADCAST) {
        if (msg->ifa_family == AF_INET) {
          new_addr->SetBroadcastAddress(msg->ifa_family, RTA_DATA(rta), RTA_PAYLOAD(rta));
          if (known_addr == nullptr) {
            // We did not read the broadcast flag from an RTM_NEWLINK message.
            // Ensure that it is set.
            new_addr->ifa.ifa_flags |= IFF_BROADCAST;
          }
        }
      } else if (rta->rta_type == IFA_LOCAL) {
        if (msg->ifa_family == AF_INET || msg->ifa_family == AF_INET6) {
          new_addr->SetLocalAddress(msg->ifa_family, RTA_DATA(rta), RTA_PAYLOAD(rta));
        }
      } else if (rta->rta_type == IFA_LABEL) {
        if (RTA_PAYLOAD(rta) < sizeof(new_addr->name)) {
          memcpy(new_addr->name, RTA_DATA(rta), RTA_PAYLOAD(rta));
          new_addr->ifa.ifa_name = new_addr->name;
        }
      }
      rta = RTA_NEXT(rta, rta_len);
    }
  }
}

static void resolve_or_remove_nameless_interfaces(ifaddrs** list) {
  ifaddrs_storage* addr = reinterpret_cast<ifaddrs_storage*>(*list);
  ifaddrs_storage* prev_addr = nullptr;
  while (addr != nullptr) {
    ifaddrs* next_addr = addr->ifa.ifa_next;

    // Try resolving interfaces without a name first.
    if (strlen(addr->name) == 0) {
      if (if_indextoname(addr->interface_index, addr->name) != nullptr) {
        addr->ifa.ifa_name = addr->name;
      }
    }

    // If the interface could not be resolved, remove it.
    if (strlen(addr->name) == 0) {
      if (prev_addr == nullptr) {
        *list = next_addr;
      } else {
        prev_addr->ifa.ifa_next = next_addr;
      }
      free(addr);
    } else {
      prev_addr = addr;
    }

    addr = reinterpret_cast<ifaddrs_storage*>(next_addr);
  }
}

static void get_interface_flags_via_ioctl(ifaddrs** list) {
  ScopedFd s(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (s.get() == -1) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC) failed in ifaddrs: %m");
    return;
  }

  for (ifaddrs_storage* addr = reinterpret_cast<ifaddrs_storage*>(*list); addr != nullptr;
       addr = reinterpret_cast<ifaddrs_storage*>(addr->ifa.ifa_next)) {
    ifreq ifr = {};
    strlcpy(ifr.ifr_name, addr->ifa.ifa_name, sizeof(ifr.ifr_name));
    if (ioctl(s.get(), SIOCGIFFLAGS, &ifr) != -1) {
      addr->ifa.ifa_flags = ifr.ifr_flags;
    } else {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                            "ioctl(SIOCGIFFLAGS) for \"%s\" failed in ifaddrs: %m",
                            addr->ifa.ifa_name);
    }
  }
}

int getifaddrs(ifaddrs** out) {
  // We construct the result directly into `out`, so terminate the list.
  *out = nullptr;

  // Open the netlink socket and ask for all the links and addresses.
  NetlinkConnection nc;
  // SELinux policy only allows RTM_GETLINK messages to be sent by system apps.
  bool getlink_success = false;
  if (getuid() < FIRST_APPLICATION_UID) {
    getlink_success = nc.SendRequest(RTM_GETLINK) && nc.ReadResponses(__getifaddrs_callback, out);
  }
  bool getaddr_success =
    nc.SendRequest(RTM_GETADDR) && nc.ReadResponses(__getifaddrs_callback, out);

  if (!getaddr_success) {
    freeifaddrs(*out);
    // Ensure that callers crash if they forget to check for success.
    *out = nullptr;
    return -1;
  }

  if (!getlink_success) {
    // If we weren't able to depend on GETLINK messages, it's possible some
    // interfaces never got their name set. Resolve them using if_indextoname or remove them.
    resolve_or_remove_nameless_interfaces(out);
    // Similarly, without GETLINK messages, interfaces will not have their flags set.
    // Resolve them using the SIOCGIFFLAGS ioctl call.
    get_interface_flags_via_ioctl(out);
  }

  return 0;
}

void freeifaddrs(ifaddrs* list) {
  while (list != nullptr) {
    ifaddrs* current = list;
    list = list->ifa_next;
    free(current);
  }
}

"""

```