Response:
Let's break down the thought process for analyzing the `getnameinfo.c` source code.

**1. Understanding the Request:**

The core request is to understand the functionality of this specific C file within the Android Bionic library. This involves:

* **Identifying the primary function:** `getnameinfo`.
* **Explaining its purpose:** Translating socket addresses to host and service names.
* **Relating it to Android:** How does Android use this?
* **Analyzing individual libc functions:**  How are the supporting functions implemented?
* **Addressing dynamic linking:** How does it interact with the dynamic linker (although this file doesn't directly involve complex dynamic linking scenarios)?
* **Providing examples:** Illustrating usage, potential errors, and debugging.
* **Tracing the execution path:**  How does a call from Android Framework/NDK reach this code?
* **Offering a Frida hook:**  Demonstrating runtime inspection.

**2. Initial Code Scan and Keyword Spotting:**

First, a quick scan of the code reveals key elements:

* **Copyright and License:** Standard open-source licensing information.
* **Includes:**  `<sys/socket.h>`, `<netdb.h>`, `<arpa/inet.h>`, etc. These headers indicate network-related functionality.
* **`getnameinfo` function definition:** This is the main function.
* **`android_getnameinfofornet`:** An Android-specific variant taking a network ID. This is a crucial hint for understanding Android integration.
* **`getnameinfo_inet` and `getnameinfo_local`:** Helper functions for different address families (Internet and Unix domain sockets).
* **`getservbyport`:**  Looking up service names by port number.
* **`gethostbyaddr` (via the proxy):** Looking up hostnames by IP address.
* **`inet_ntop`:** Converting network address structures to strings.
* **IPv6 specific functions:** `ip6_parsenumeric`, `ip6_sa2str`.
* **Error codes:** `EAI_*` constants from `<netdb.h>`.
* **Flags:** `NI_NUMERICHOST`, `NI_NAMEREQD`, etc., controlling the behavior.

**3. Deconstructing `getnameinfo` and `android_getnameinfofornet`:**

* **`getnameinfo`:**  The weak symbol suggests it might be overridden or customized in specific contexts, though in this standard Bionic libc, it likely just calls `android_getnameinfofornet`.
* **`android_getnameinfofornet`:** This function acts as a dispatcher, selecting the appropriate handler based on the socket address family (`sa->sa_family`). This is a common pattern for handling different protocol families.

**4. Analyzing `getnameinfo_inet`:**

This is the core logic for handling Internet addresses. The breakdown looks like this:

* **Address Family Handling:** Iterates through `afdl` (address family data list) to find the correct structure based on the socket address family.
* **Port Handling:** Extracts the port number from the socket address.
* **Service Name Lookup:** If `NI_NUMERICSERV` is not set, it uses `getservbyport` to find the service name. If successful, it copies the name; otherwise, it converts the port number to a string.
* **Host Name Lookup:**
    * **`NI_NUMERICHOST`:** Directly converts the IP address to a string using `inet_ntop`. For IPv6, it uses `ip6_parsenumeric` which also handles scope IDs.
    * **No `NI_NUMERICHOST`:**  Attempts to resolve the hostname using `android_gethostbyaddrfornetcontext_proxy`. The `_proxy` suffix suggests this is an Android-specific abstraction, likely interacting with `netd`. If the lookup fails and `NI_NAMEREQD` is set, it returns an error; otherwise, it falls back to numeric representation.
* **IPv6 Specifics:**  `ip6_parsenumeric` formats the IPv6 address and potentially appends the scope ID. `ip6_sa2str` formats the scope ID, attempting to use the interface name if possible.

**5. Analyzing `getnameinfo_local`:**

This is simpler, handling Unix domain sockets. It extracts the path from the `sockaddr_un` structure.

**6. Addressing Dynamic Linking (Self-Correction):**

Initially, I might have overemphasized the dynamic linker aspects. However, a closer look reveals this file *uses* functions that *are* part of libc and thus are dynamically linked, but it doesn't perform complex dynamic linking operations itself. The key connection is that `getnameinfo` is part of libc.so, which is loaded by the dynamic linker.

**7. Crafting Examples:**

* **Usage:** Provide a simple C code snippet demonstrating how to call `getnameinfo`.
* **Common Errors:** Focus on buffer overflow issues (`hostlen`, `servlen` too small), incorrect flags, and name resolution failures.

**8. Tracing the Execution Path:**

Think about a typical Android network operation:

* **Java code uses `java.net.InetAddress` or similar.**
* **This calls into native code in the Android Framework (e.g., in `libjavacore.so`).**
* **The Framework code eventually calls a Bionic libc function, in this case, likely `getaddrinfo` (which internally might call `getnameinfo` in some scenarios or be a peer function for reverse lookups).**
* **The system call or library function call eventually lands in `bionic/libc/dns/net/getnameinfo.c`.**

**9. Frida Hook:**

Choose a strategic point to hook. Hooking the entry point of `getnameinfo` or `android_getnameinfofornet` is a good start to observe the parameters.

**10. Structuring the Response:**

Organize the information logically with clear headings and explanations for each part of the request. Use code formatting for code examples.

**Self-Correction Example During the Process:**

While initially thinking about dynamic linking, I might have started describing the loading of libc.so in detail. However, I'd realize that `getnameinfo.c` itself doesn't *initiate* dynamic linking. It *relies* on it because it uses other libc functions. Therefore, the explanation should focus on where `getnameinfo` fits within the loaded libc.so and how the dynamic linker resolves the symbols it uses. The SO layout becomes relevant for illustrating where `getnameinfo` resides within `libc.so`.

By following this structured approach, combining code analysis with a high-level understanding of Android architecture, and performing self-correction along the way, I can generate a comprehensive and accurate explanation of the `getnameinfo.c` file.
好的，我们来详细分析一下 `bionic/libc/dns/net/getnameinfo.c` 这个文件。

**功能概述:**

`getnameinfo.c` 文件实现了 `getnameinfo()` 函数，该函数的主要功能是将套接字地址结构 (socket address structure) 转换为主机名和服务名字符串。 简单来说，它实现了 **逆向域名解析** 和 **逆向服务名查找**。

**与 Android 功能的关系及举例说明:**

`getnameinfo()` 是一个标准的 POSIX 函数，在网络编程中非常常用。Android 作为基于 Linux 内核的操作系统，其 C 库 (Bionic) 自然需要提供这个功能。

**Android 中的应用场景：**

1. **网络监控工具:**  例如 `netstat` 命令，它需要将连接的 IP 地址和端口号转换为可读的主机名和服务名。`getnameinfo()` 就被用于实现这个转换过程。
2. **网络调试工具:**  当开发者需要查看网络连接信息时，例如通过 `adb shell` 连接到设备并使用网络工具，这些工具内部可能会调用 `getnameinfo()` 来显示更友好的信息。
3. **应用程序的网络操作:**  应用程序在进行网络通信时，有时需要将接收到的连接信息中的 IP 地址转换为域名，或者将端口号转换为服务名。例如，一个 HTTP 服务器可能会使用 `getnameinfo()` 来记录客户端的域名。
4. **系统服务:**  Android 系统的一些底层服务，例如负责网络连接管理的 `netd`，在处理网络事件时也可能需要使用 `getnameinfo()`。

**举例说明:**

假设一个 Android 应用接收到一个来自 IP 地址 `192.168.1.100` 和端口 `80` 的连接。应用程序可能调用 `getnameinfo()` 来获取这些信息的字符串表示：

```c
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>

int main() {
    struct sockaddr_in sa;
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    int result;

    // 假设已经填充了 sa 结构体，例如：
    sa.sin_family = AF_INET;
    sa.sin_port = htons(80);
    inet_pton(AF_INET, "192.168.1.100", &sa.sin_addr);

    result = getnameinfo((const struct sockaddr *)&sa, sizeof(sa),
                         host, NI_MAXHOST, serv, NI_MAXSERV, 0);

    if (result == 0) {
        printf("主机名: %s, 服务名: %s\n", host, serv, 0);
    } else {
        fprintf(stderr, "getnameinfo 错误: %s\n", gai_strerror(result));
    }

    return 0;
}
```

在这个例子中，`getnameinfo()` 可能会将 `192.168.1.100` 解析为该 IP 地址对应的域名 (如果存在)，并将端口 `80` 解析为服务名 "http"。

**libc 函数的实现细节:**

`getnameinfo.c` 文件内部调用了多个其他的 libc 函数来实现其功能，下面逐一解释：

1. **`android_getnameinfofornet()`:**
   - 这是 Android Bionic 对 `getnameinfo()` 的扩展，它额外接收 `netid` 和 `mark` 参数，用于指定网络命名空间和防火墙标记。
   - 它的主要作用是根据传入的套接字地址族的类型 (`sa->sa_family`)，调用不同的处理函数：
     - `getnameinfo_inet()` 处理 `AF_INET` (IPv4) 和 `AF_INET6` (IPv6) 地址。
     - `getnameinfo_local()` 处理 `AF_LOCAL` (Unix 域套接字) 地址。

2. **`getnameinfo_inet()`:**
   - 这是处理 IPv4 和 IPv6 地址的核心函数。
   - **查找地址族信息:** 它首先遍历 `afdl` 数组，找到与传入地址族匹配的 `afd` 结构体，该结构体包含了地址长度、套接字长度以及地址偏移量等信息。
   - **处理服务名:**
     - 如果 `flags` 中设置了 `NI_NUMERICSERV`，则直接将端口号转换为字符串。
     - 否则，调用 `getservbyport()` 函数，根据端口号和协议 (TCP 或 UDP) 查找对应的服务名。
     - 如果找到服务名，则复制到 `serv` 缓冲区；否则，将端口号转换为字符串。
   - **处理主机名:**
     - 如果 `flags` 中设置了 `NI_NUMERICHOST`，则直接将 IP 地址转换为数字字符串，使用 `inet_ntop()` (对于 IPv4) 或 `ip6_parsenumeric()` (对于 IPv6)。
     - 否则，调用 `android_gethostbyaddrfornetcontext_proxy()` 函数进行逆向域名解析。
       - `android_gethostbyaddrfornetcontext_proxy()` 是 Android Bionic 提供的，它考虑了网络命名空间，并将请求代理到 `netd` 守护进程进行实际的 DNS 查询。
       - 如果解析成功，则将主机名复制到 `host` 缓冲区。
       - 如果解析失败且设置了 `NI_NAMEREQD`，则返回错误 `EAI_NONAME`。
       - 如果解析失败但没有设置 `NI_NAMEREQD`，则将 IP 地址转换为数字字符串。

3. **`getnameinfo_local()`:**
   - 用于处理 Unix 域套接字地址。
   - 它直接将 `sockaddr_un` 结构体中的 `sun_path` (套接字文件路径) 复制到 `host` 缓冲区。服务名部分通常为空。

4. **`getservbyport()`:**
   - 这是标准的 libc 函数，用于根据端口号和协议查找服务名。
   - 它通常会读取 `/etc/services` 文件 (或者通过其他机制，例如 NIS) 来查找服务名。

5. **`android_gethostbyaddrfornetcontext_proxy()`:**
   - 这是 Android Bionic 特有的函数，用于根据 IP 地址执行逆向域名解析，并考虑了网络命名空间。
   - 它会将请求发送到 `netd` 守护进程，由 `netd` 负责执行实际的 DNS 查询。

6. **`inet_ntop()`:**
   - 这是标准的网络编程函数，用于将网络地址结构 (例如 `struct in_addr` 或 `struct in6_addr`) 转换为点分十进制或冒号分隔的字符串表示。

7. **`ip6_parsenumeric()`:**
   - Bionic 中用于处理 IPv6 地址的辅助函数。
   - 它调用 `inet_ntop()` 将 IPv6 地址转换为字符串，并处理 IPv6 的 scope ID (区域 ID)。

8. **`ip6_sa2str()`:**
   - Bionic 中用于将 IPv6 的 scope ID 转换为字符串表示的辅助函数。
   - 它尝试使用 `if_indextoname()` 获取与 scope ID 对应的网络接口名。如果失败，则将 scope ID 转换为数字字符串。

**涉及 dynamic linker 的功能:**

`getnameinfo.c` 本身的代码并不直接涉及 dynamic linker 的操作。然而，它所实现的 `getnameinfo` 函数是 libc 的一部分，而 libc 本身是通过 dynamic linker 加载到进程空间的。

**so 布局样本 (libc.so 的一部分):**

```
libc.so:
    ...
    .text:
        ...
        [getnameinfo 函数的代码]
        [android_getnameinfofornet 函数的代码]
        [getnameinfo_inet 函数的代码]
        [getnameinfo_local 函数的代码]
        [getservbyport 函数的代码]
        [android_gethostbyaddrfornetcontext_proxy 函数的代码]
        [inet_ntop 函数的代码]
        [ip6_parsenumeric 函数的代码]
        [ip6_sa2str 函数的代码]
        ...
    .rodata:
        ...
        [字符串常量等]
        ...
    .data:
        ...
        [全局变量等]
        ...
    .dynamic:
        ...
        [动态链接信息，例如依赖的库，符号表等]
        ...
    .symtab:
        ...
        [符号表，包含 getnameinfo 等函数的符号信息]
        ...
    .strtab:
        ...
        [字符串表，包含符号名等]
        ...
```

**链接的处理过程:**

1. **编译时:** 当程序调用 `getnameinfo` 时，编译器会在目标文件中生成一个对 `getnameinfo` 符号的未解析引用。
2. **链接时:** 链接器 (例如 `ld`) 会将程序的目标文件与所需的共享库 (libc.so) 链接在一起。链接器会查找 libc.so 的符号表，找到 `getnameinfo` 的定义，并将程序中对 `getnameinfo` 的未解析引用指向 libc.so 中 `getnameinfo` 的代码地址。
3. **运行时:** 当程序启动时，dynamic linker (在 Android 上通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，包括 libc.so。dynamic linker 会解析程序中对共享库函数的引用，并将它们绑定到共享库中实际的函数地址。这样，当程序调用 `getnameinfo` 时，实际上执行的是 libc.so 中 `getnameinfo` 的代码。

**逻辑推理、假设输入与输出:**

**假设输入:**

- `sa`: 一个指向 `sockaddr_in` 结构体的指针，表示 IPv4 地址 `192.168.1.100` 和端口 `80`。
- `salen`: `sizeof(struct sockaddr_in)`。
- `host`: 一个大小为 `NI_MAXHOST` 的字符数组。
- `hostlen`: `NI_MAXHOST`。
- `serv`: 一个大小为 `NI_MAXSERV` 的字符数组。
- `servlen`: `NI_MAXSERV`。
- `flags`: 0 (默认标志)。

**预期输出:**

- 如果 `192.168.1.100` 在 DNS 中有对应的域名，且 DNS 解析成功，则 `host` 数组可能包含 "example.com" (假设)。
- `serv` 数组将包含 "http"。
- 函数返回值为 0 (成功)。

**假设输入 (带有 `NI_NUMERICHOST` 标志):**

- `flags`: `NI_NUMERICHOST`。
- 其他输入同上。

**预期输出:**

- `host` 数组将包含 "192.168.1.100"。
- `serv` 数组将包含 "http"。
- 函数返回值为 0 (成功)。

**用户或编程常见的使用错误:**

1. **缓冲区溢出:**  `host` 或 `serv` 缓冲区太小，无法容纳转换后的主机名或服务名，导致 `getnameinfo` 返回 `EAI_OVERFLOW` 错误。
   ```c
   char host[10]; // 缓冲区太小
   char serv[10]; // 缓冲区太小
   getnameinfo((const struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), serv, sizeof(serv), 0);
   // 可能会导致 EAI_OVERFLOW
   ```

2. **`salen` 参数错误:**  `salen` 参数应该等于实际的套接字地址结构的大小。如果传入的 `salen` 过小，`getnameinfo` 可能会返回 `EAI_FAMILY` 或访问越界内存。

3. **错误的 flags 使用:**
   - `NI_NAMEREQD` 和 `NI_NUMERICHOST` 标志冲突，同时设置会导致 `getnameinfo` 返回 `EAI_NONAME`。
   - 没有理解各个 flag 的含义，导致未能获取期望的输出格式。

4. **DNS 解析问题:** 如果网络配置不正确或 DNS 服务器无法访问，逆向域名解析可能会失败，导致 `getnameinfo` 返回 `EAI_NONAME` (如果设置了 `NI_NAMEREQD`) 或返回 IP 地址字符串。

5. **在错误的网络命名空间中执行:** 在 Android 中，如果应用程序在没有网络权限或者在错误的网络命名空间中运行，DNS 解析可能会失败。

**Android Framework 或 NDK 如何到达这里:**

1. **Java 代码:** Android 应用通常使用 Java API 进行网络操作，例如 `java.net.InetAddress` 和 `java.net.Socket` 等类。
2. **Framework Native 代码:** Java 网络 API 的底层实现通常会调用 Android Framework 的 Native 代码 (通常是 C/C++)，例如在 `libjavacore.so` 或 `libnativehelper.so` 中。
3. **Bionic libc 调用:** Framework Native 代码最终会调用 Bionic libc 提供的网络相关函数，例如 `getaddrinfo` (用于正向域名解析) 或 `getnameinfo` (用于逆向域名解析)。
4. **系统调用 (间接):**  `getnameinfo` 内部可能会间接地触发系统调用，例如在进行 DNS 查询时，它会与 `netd` 守护进程进行通信，而 `netd` 可能会执行 `socket`, `sendto`, `recvfrom` 等系统调用。

**Frida Hook 示例:**

可以使用 Frida Hook `getnameinfo` 函数来观察其输入参数和返回值，从而调试网络相关的代码。

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    const getnameinfoPtr = Module.findExportByName("libc.so", "getnameinfo");

    if (getnameinfoPtr) {
        Interceptor.attach(getnameinfoPtr, {
            onEnter: function (args) {
                const saPtr = args[0];
                const salen = args[1].toInt();
                const hostPtr = args[2];
                const hostlen = args[3].toInt();
                const servPtr = args[4];
                const servlen = args[5].toInt();
                const flags = args[6].toInt();

                console.log("getnameinfo called!");
                console.log("  sa:", hexdump(Memory.readByteArray(saPtr, salen), { ansi: true }));
                console.log("  salen:", salen);
                console.log("  hostPtr:", hostPtr);
                console.log("  hostlen:", hostlen);
                console.log("  servPtr:", servPtr);
                console.log("  servlen:", servlen);
                console.log("  flags:", flags);
            },
            onLeave: function (retval) {
                console.log("getnameinfo returned:", retval);
                if (this.context.r2 !== 0 && this.context.r2 !== undefined) { // 假设 r2 寄存器存储 host 缓冲区地址
                    const host = Memory.readCString(ptr(this.context.r2));
                    console.log("  Host:", host);
                }
                if (this.context.r4 !== 0 && this.context.r4 !== undefined) { // 假设 r4 寄存器存储 serv 缓冲区地址
                    const serv = Memory.readCString(ptr(this.context.r4));
                    console.log("  Service:", serv);
                }
            }
        });
    } else {
        console.log("Could not find getnameinfo in libc.so");
    }
}
```

**代码解释:**

- 此 Frida 脚本查找 `libc.so` 中的 `getnameinfo` 函数。
- `onEnter` 函数在 `getnameinfo` 被调用时执行，它打印出函数的参数，包括套接字地址、缓冲区指针和长度、以及标志。
- `onLeave` 函数在 `getnameinfo` 返回后执行，它打印返回值，并尝试读取 `host` 和 `serv` 缓冲区的内容。

通过这个 Frida Hook，你可以观察 Android 系统或应用在进行逆向域名解析和服务名查找时传递给 `getnameinfo` 的具体参数，以及它返回的结果，从而帮助你理解网络操作的底层行为。

希望这个详细的分析对你有所帮助！

Prompt: 
```
这是目录为bionic/libc/dns/net/getnameinfo.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: getnameinfo.c,v 1.53 2012/09/26 23:13:00 christos Exp $	*/
/*	$KAME: getnameinfo.c,v 1.45 2000/09/25 22:43:56 itojun Exp $	*/

/*
 * Copyright (c) 2000 Ben Harris.
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Issues to be discussed:
 * - Thread safe-ness must be checked
 * - RFC2553 says that we should raise error on short buffer.  X/Open says
 *   we need to truncate the result.  We obey RFC2553 (and X/Open should be
 *   modified).  ipngwg rough consensus seems to follow RFC2553.
 * - What is "local" in NI_FQDN?
 * - NI_NAMEREQD and NI_NUMERICHOST conflict with each other.
 * - (KAME extension) always attach textual scopeid (fe80::1%lo0), if
 *   sin6_scope_id is filled - standardization status?
 *   XXX breaks backward compat for code that expects no scopeid.
 *   beware on merge.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: getnameinfo.c,v 1.53 2012/09/26 23:13:00 christos Exp $");
#endif /* LIBC_SCCS and not lint */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include "resolv_netid.h"
#include "resolv_private.h"
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "private/bionic_defs.h"

/* This macro is modelled after the ones in <netinet/in6.h>. */
/* RFC 6052, section 2.1 */
#define IN6_IS_ADDR_WKP(a) \
  ((((a)->s6_addr32[0]) == ntohl(0x0064ff9b)) && \
   (((a)->s6_addr32[1]) == 0) && \
   (((a)->s6_addr32[2]) == 0))

static const struct afd {
	int		a_af;
	socklen_t	a_addrlen;
	socklen_t	a_socklen;
	int		a_off;
} afdl [] = {
#ifdef INET6
	{PF_INET6, sizeof(struct in6_addr), sizeof(struct sockaddr_in6),
		offsetof(struct sockaddr_in6, sin6_addr)},
#endif
	{PF_INET, sizeof(struct in_addr), sizeof(struct sockaddr_in),
		offsetof(struct sockaddr_in, sin_addr)},
	{0, 0, 0, 0},
};

struct sockinet {
	u_char	si_len;
	u_char	si_family;
	u_short	si_port;
};

static int getnameinfo_inet(const struct sockaddr *, socklen_t, char *,
    socklen_t, char *, socklen_t, int, unsigned, unsigned);
#ifdef INET6
static int ip6_parsenumeric(const struct sockaddr *, const char *, char *,
				 socklen_t, int);
static int ip6_sa2str(const struct sockaddr_in6 *, char *, size_t, int);
#endif
static int getnameinfo_local(const struct sockaddr *, socklen_t, char *,
    socklen_t, char *, socklen_t, int);

/*
 * Top-level getnameinfo() code.  Look at the address family, and pick an
 * appropriate function to call.
 */
__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int getnameinfo(const struct sockaddr* sa, socklen_t salen, char* host, size_t hostlen,
		char* serv, size_t servlen, int flags)
{
	return android_getnameinfofornet(sa, salen, host, hostlen, serv, servlen, flags,
			NETID_UNSET, MARK_UNSET);
}

int android_getnameinfofornet(const struct sockaddr* sa, socklen_t salen, char* host,
		size_t hostlen, char* serv, size_t servlen, int flags, unsigned netid,
		unsigned mark)
{
	switch (sa->sa_family) {
	case AF_INET:
	case AF_INET6:
		return getnameinfo_inet(sa, salen, host, hostlen,
				serv, servlen, flags, netid, mark);
	case AF_LOCAL:
		return getnameinfo_local(sa, salen, host, hostlen,
		    serv, servlen, flags);
	default:
		return EAI_FAMILY;
	}
}

/*
 * getnameinfo_local():
 * Format an local address into a printable format.
 */
/* ARGSUSED */
static int
getnameinfo_local(const struct sockaddr *sa, socklen_t salen,
    char *host, socklen_t hostlen, char *serv, socklen_t servlen,
    int flags __attribute__((unused)))
{
       const struct sockaddr_un *sun =
           (const struct sockaddr_un *)(const void *)sa;

       if (salen < (socklen_t) offsetof(struct sockaddr_un, sun_path)) {
           return EAI_FAMILY;
       }

       if (serv != NULL && servlen > 0)
               serv[0] = '\0';

       if (host && hostlen > 0)
               strlcpy(host, sun->sun_path,
                   MIN((socklen_t) sizeof(sun->sun_path) + 1, hostlen));

       return 0;
}

/*
 * getnameinfo_inet():
 * Format an IPv4 or IPv6 sockaddr into a printable string.
 */
static int
getnameinfo_inet(const struct sockaddr* sa, socklen_t salen,
       char *host, socklen_t hostlen,
       char *serv, socklen_t servlen,
       int flags, unsigned netid, unsigned mark)
{
	const struct afd *afd;
	struct servent *sp;
	struct hostent *hp;
	u_short port;
	int family, i;
	const char *addr;
	uint32_t v4a;
	char numserv[512];
	char numaddr[512];

	/* sa is checked below */
	/* host may be NULL */
	/* serv may be NULL */

	if (sa == NULL)
		return EAI_FAIL;

	family = sa->sa_family;
	for (i = 0; afdl[i].a_af; i++)
		if (afdl[i].a_af == family) {
			afd = &afdl[i];
			goto found;
		}
	return EAI_FAMILY;

 found:
	// http://b/1889275: callers should be allowed to provide too much
	// space, but not too little.
	if (salen < afd->a_socklen) {
		return EAI_FAMILY;
	}

	/* network byte order */
	port = ((const struct sockinet *)(const void *)sa)->si_port;
	addr = (const char *)(const void *)sa + afd->a_off;

	if (serv == NULL || servlen == 0) {
		/*
		 * do nothing in this case.
		 * in case you are wondering if "&&" is more correct than
		 * "||" here: rfc2553bis-03 says that serv == NULL OR
		 * servlen == 0 means that the caller does not want the result.
		 */
	} else {
		if (flags & NI_NUMERICSERV)
			sp = NULL;
		else {
			sp = getservbyport(port,
				(flags & NI_DGRAM) ? "udp" : "tcp");
		}
		if (sp) {
			if (strlen(sp->s_name) + 1 > (size_t)servlen)
				return EAI_MEMORY;
			strlcpy(serv, sp->s_name, servlen);
		} else {
			snprintf(numserv, sizeof(numserv), "%u", ntohs(port));
			if (strlen(numserv) + 1 > (size_t)servlen)
				return EAI_MEMORY;
			strlcpy(serv, numserv, servlen);
		}
	}

	switch (sa->sa_family) {
	case AF_INET:
		v4a = (uint32_t)
		    ntohl(((const struct sockaddr_in *)
		    (const void *)sa)->sin_addr.s_addr);
		if (IN_MULTICAST(v4a) || IN_EXPERIMENTAL(v4a))
			flags |= NI_NUMERICHOST;
		v4a >>= IN_CLASSA_NSHIFT;
		if (v4a == 0)
			flags |= NI_NUMERICHOST;
		break;
#ifdef INET6
	case AF_INET6:
	    {
		const struct sockaddr_in6 *sin6;
		sin6 = (const struct sockaddr_in6 *)(const void *)sa;
		switch (sin6->sin6_addr.s6_addr[0]) {
		case 0x00:
			if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
				;
			else if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
				;
			else if (IN6_IS_ADDR_WKP(&sin6->sin6_addr))
				;
			else
				flags |= NI_NUMERICHOST;
			break;
		default:
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
				flags |= NI_NUMERICHOST;
			}
			else if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
				flags |= NI_NUMERICHOST;
			break;
		}
	    }
		break;
#endif
	}
	if (host == NULL || hostlen == 0) {
		/*
		 * do nothing in this case.
		 * in case you are wondering if "&&" is more correct than
		 * "||" here: rfc2553bis-03 says that host == NULL or
		 * hostlen == 0 means that the caller does not want the result.
		 */
	} else if (flags & NI_NUMERICHOST) {
		size_t numaddrlen;

		/* NUMERICHOST and NAMEREQD conflicts with each other */
		if (flags & NI_NAMEREQD)
			return EAI_NONAME;

		switch(afd->a_af) {
#ifdef INET6
		case AF_INET6:
		{
			int error;

			if ((error = ip6_parsenumeric(sa, addr, host,
						      hostlen, flags)) != 0)
				return(error);
			break;
		}
#endif
		default:
			if (inet_ntop(afd->a_af, addr, numaddr, sizeof(numaddr))
			    == NULL)
				return EAI_SYSTEM;
			numaddrlen = strlen(numaddr);
			if (numaddrlen + 1 > (size_t)hostlen) /* don't forget terminator */
				return EAI_MEMORY;
			strlcpy(host, numaddr, hostlen);
			break;
		}
	} else {
		// This code should only run in the app context, not inside netd, so netid is
		// the app's netid.  netd doesn't use getnameinfo for network requests.
		const struct android_net_context netcontext = { .app_netid = netid, .app_mark = mark };
		hp = android_gethostbyaddrfornetcontext_proxy(addr, afd->a_addrlen, afd->a_af, &netcontext);
		if (hp) {
#if 0
			/*
			 * commented out, since "for local host" is not
			 * implemented here - see RFC2553 p30
			 */
			if (flags & NI_NOFQDN) {
				char *p;
				p = strchr(hp->h_name, '.');
				if (p)
					TODO: Before uncommenting rewrite to avoid modifying hp.
					*p = '\0';
			}
#endif
			if (strlen(hp->h_name) + 1 > (size_t)hostlen) {
				return EAI_MEMORY;
			}
			strlcpy(host, hp->h_name, hostlen);
		} else {
			if (flags & NI_NAMEREQD)
				return EAI_NONAME;
			switch(afd->a_af) {
#ifdef INET6
			case AF_INET6:
			{
				int error;

				if ((error = ip6_parsenumeric(sa, addr, host,
							      hostlen,
							      flags)) != 0)
					return(error);
				break;
			}
#endif
			default:
				if (inet_ntop(afd->a_af, addr, host,
				    hostlen) == NULL)
					return EAI_SYSTEM;
				break;
			}
		}
	}
	return(0);
}

#ifdef INET6
static int
ip6_parsenumeric(const struct sockaddr *sa, const char *addr, char *host,
       socklen_t hostlen, int flags)
{
	size_t numaddrlen;
	char numaddr[512];

	assert(sa != NULL);
	assert(addr != NULL);
	assert(host != NULL);

	if (inet_ntop(AF_INET6, addr, numaddr, sizeof(numaddr)) == NULL)
		return EAI_SYSTEM;

	numaddrlen = strlen(numaddr);
	if (numaddrlen + 1 > (size_t)hostlen) /* don't forget terminator */
		return EAI_OVERFLOW;
	strlcpy(host, numaddr, hostlen);

	if (((const struct sockaddr_in6 *)(const void *)sa)->sin6_scope_id) {
		char zonebuf[MAXHOSTNAMELEN];
		int zonelen;

		zonelen = ip6_sa2str(
		    (const struct sockaddr_in6 *)(const void *)sa,
		    zonebuf, sizeof(zonebuf), flags);
		if (zonelen < 0)
			return EAI_OVERFLOW;
		if ((size_t) zonelen + 1 + numaddrlen + 1 > (size_t)hostlen)
			return EAI_OVERFLOW;
		/* construct <numeric-addr><delim><zoneid> */
		memcpy(host + numaddrlen + 1, zonebuf,
		    (size_t)zonelen);
		host[numaddrlen] = SCOPE_DELIMITER;
		host[numaddrlen + 1 + zonelen] = '\0';
	}

	return 0;
}

/* ARGSUSED */
static int
ip6_sa2str(const struct sockaddr_in6 *sa6, char *buf, size_t bufsiz, int flags)
{
	unsigned int ifindex;
	const struct in6_addr *a6;
	int n;

	assert(sa6 != NULL);
	assert(buf != NULL);

	ifindex = (unsigned int)sa6->sin6_scope_id;
	a6 = &sa6->sin6_addr;

#ifdef NI_NUMERICSCOPE
	if ((flags & NI_NUMERICSCOPE) != 0) {
		n = snprintf(buf, bufsiz, "%u", sa6->sin6_scope_id);
		if (n < 0 || n >= bufsiz)
			return -1;
		else
			return n;
	}
#endif

	/* if_indextoname() does not take buffer size.  not a good api... */
	if ((IN6_IS_ADDR_LINKLOCAL(a6) || IN6_IS_ADDR_MC_LINKLOCAL(a6)) &&
	    bufsiz >= IF_NAMESIZE) {
		char *p = if_indextoname(ifindex, buf);
		if (p) {
			return(strlen(p));
		}
	}

	/* last resort */
	n = snprintf(buf, bufsiz, "%u", sa6->sin6_scope_id);
	if (n < 0 || (size_t) n >= bufsiz)
		return -1;
	else
		return n;
}
#endif /* INET6 */

"""

```