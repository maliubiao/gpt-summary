Response:
Let's break down the thought process for answering the request about the `ip6.h` header file.

**1. Understanding the Core Request:**

The user has provided a C header file (`ip6.h`) from Android's Bionic library and wants to know its purpose, relationship to Android, details about libc functions (if any), dynamic linker aspects, examples, common errors, and how Android components use it, along with Frida hooking.

**2. Initial Assessment of the Header File:**

The first thing to notice is that this is a header file, not a source code file with function implementations. Header files primarily define data structures, constants, and function prototypes. Therefore, the request to "详细解释每一个libc函数的功能是如何实现的" is immediately problematic since there *are no* libc function implementations in this file. This needs to be addressed directly in the answer.

**3. Identifying the Primary Function:**

The filename and the content clearly indicate this header file is related to IPv6. The presence of `struct ip6_hdr`, extension header definitions, and constants like `IPV6_VERSION` confirm this. The core function is to define the structure and constants needed to work with IPv6 packets at a low level.

**4. Relating to Android:**

Since it's part of Bionic, the standard C library for Android, it's integral to networking on Android devices. Any network communication using IPv6 on Android will directly or indirectly rely on these definitions. Examples include:

* **Sockets:** The `socket()` system call with the `AF_INET6` address family will use these structures.
* **Network Daemons:**  Android system services handling network configuration and communication will utilize these definitions.
* **NDK Applications:**  Native applications developed using the NDK can directly include this header to interact with IPv6.

**5. Addressing the "libc Function Implementation" Question:**

This is a crucial point. The answer needs to explicitly state that header files don't contain function implementations. It should clarify that `ip6.h` defines *data structures* that libc functions (like `sendto`, `recvfrom`, etc.) *use*. It's important to distinguish between definition and implementation.

**6. Dynamic Linker Aspects:**

Header files themselves don't directly involve the dynamic linker. However, the *structures defined in the header* are used by code that *is* linked. The dynamic linker plays a role in resolving the symbols (like the structures and constants) when a program using these definitions is loaded. A simple SO layout and linking example can illustrate how a hypothetical `libnet.so` might use these definitions, and how the dynamic linker resolves those references for an application.

**7. Examples and Common Errors:**

* **Example:** Creating an IPv6 socket is a straightforward example of how these definitions are used in code.
* **Common Errors:** Focus on errors related to *using* the defined structures and constants incorrectly, like:
    * Incorrectly filling the `ip6_hdr` structure.
    * Misinterpreting the meaning of fields like `ip6_plen`.
    * Network byte order issues when working with multi-byte fields.

**8. Android Framework/NDK Pathway:**

Trace the path from high-level Android APIs down to the native layer:

* **Java Layer:** `java.net.Inet6Address`, `java.net.Socket`.
* **Framework (Binder Calls):**  Network management services interacting with the kernel.
* **NDK:** Direct use of socket APIs and inclusion of `ip6.h`.

**9. Frida Hooking:**

Demonstrate how Frida can be used to inspect the `ip6_hdr` structure or related system calls to understand how IPv6 communication is happening. Hooking a `sendto` call with `AF_INET6` is a good example.

**10. Structuring the Answer:**

Organize the answer logically, addressing each part of the user's request. Use clear headings and bullet points for readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe I should try to find the source code for functions that *use* these structures.
* **Correction:** The request is specifically about *this header file*. While knowing the functions that use it is helpful, the focus should remain on the header itself and the definitions it provides. Mentioning the relevant libc functions is sufficient.
* **Initial thought:** Go into deep detail about each field in the `ip6_hdr` structure.
* **Correction:**  While explaining the purpose is important, a detailed bit-by-bit breakdown of every field might be too much. Focus on the key fields and their significance.
* **Initial thought:**  The dynamic linker section should be very technical.
* **Correction:** Keep the dynamic linker explanation relatively high-level and focus on how it connects the definitions in the header to the actual code using them. A simple example is more effective than a complex technical explanation.

By following this process of understanding the request, assessing the provided information, identifying key aspects, and refining the approach, a comprehensive and accurate answer can be constructed. The key is to address the core questions while being mindful of the limitations of the provided input (a header file, not source code).
这是一个定义 IPv6 协议头和相关常量、数据结构的 C 头文件 (`ip6.h`)。它属于 Android Bionic 库的一部分，用于进行底层的网络编程，特别是与 IPv6 协议相关的操作。

**功能列举:**

1. **定义 IPv6 协议头结构体 (`struct ip6_hdr`):**  描述了 IPv6 数据包头的组成部分，包括版本号、流量类别、流标签、有效载荷长度、下一个报头、跳数限制、源地址和目标地址。
2. **定义 IPv6 扩展头结构体 (`struct ip6_ext`, `struct ip6_hbh`, `struct ip6_dest`, `struct ip6_rthdr`, `struct ip6_frag`):**  定义了 IPv6 的各种扩展头部，例如逐跳选项头、目标选项头、路由头和分片头。这些扩展头提供了额外的功能，例如服务质量、安全性和路由选择。
3. **定义 IPv6 选项相关结构体 (`struct ip6_opt`, `struct ip6_opt_jumbo`, `struct ip6_opt_nsap`, `struct ip6_opt_tunnel`, `struct ip6_opt_router`):** 定义了 IPv6 选项的通用结构和特定选项的结构，例如填充选项、巨型净荷选项、NSAP 地址选项、隧道限制选项和路由器告警选项。
4. **定义与 IPv6 相关的常量和宏:**  例如 `IPV6_VERSION` (IPv6 版本号), `IPV6_MAXHLIM` (最大跳数限制), `IPV6_DEFHLIM` (默认跳数限制), `IPV6_MMTU` (最小 MTU) 等。这些常量用于在程序中操作和检查 IPv6 数据包。
5. **包含其他必要的头文件:**  例如 `<sys/cdefs.h>`, `<sys/types.h>`, `<endian.h>`, `<linux/in6.h>`，提供了类型定义、字节序处理以及 Linux 特定的 IPv6 地址结构定义。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 系统底层网络功能的基础。任何在 Android 上使用 IPv6 协议的网络通信都离不开这些定义。

* **网络连接:** 当 Android 设备尝试建立 IPv6 连接时，例如访问一个 IPv6 网站或与一个 IPv6 服务器通信，底层的网络协议栈会构建和解析 IPv6 数据包，而 `ip6.h` 中定义的结构体正是这些数据包的蓝图。
* **网络配置:** Android 系统在配置 IPv6 地址、路由等信息时，可能会使用到这个头文件中定义的结构体和常量。
* **VPN 和隧道:** 当 Android 设备建立 VPN 连接或者使用其他隧道技术时，可能会涉及到 IPv6 数据包的封装和解封装，这时就需要使用到 `ip6.h` 中定义的头部结构。
* **NDK 开发:** 使用 Android NDK 进行原生网络编程的开发者可以直接包含这个头文件，以便在 C/C++ 代码中操作 IPv6 数据包。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个 `ip6.h` 文件本身是一个头文件，它只包含结构体定义、宏定义和常量定义，并不包含任何 C 标准库 (libc) 函数的实现代码。**  它描述了 IPv6 数据包的格式，供其他函数（包括 libc 中的网络相关函数，以及 Android 系统内核中的网络协议栈）使用。

libc 中与网络相关的函数，例如 `socket()`, `bind()`, `connect()`, `sendto()`, `recvfrom()` 等，在处理 IPv6 地址和数据包时，会使用到 `ip6.h` 中定义的 `struct ip6_hdr` 和其他相关的结构体。这些函数的实现通常在 Bionic 库的其他源文件中，并且会调用 Android 内核提供的系统调用来完成实际的网络操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`ip6.h` 本身不直接涉及动态链接器的功能。但是，当一个共享库 (`.so`) 或可执行文件需要使用 `ip6.h` 中定义的结构体和常量时，动态链接器会参与链接过程。

**so 布局样本:**

假设我们有一个名为 `libnetutil.so` 的共享库，它使用了 `ip6.h` 中的定义：

```
libnetutil.so:
  .text         # 代码段
    ...
    # 某个函数可能使用 struct ip6_hdr * 来处理 IPv6 数据包
    ...
  .data         # 数据段
    ...
  .rodata       # 只读数据段
    ...
  .bss          # 未初始化数据段
    ...
  .dynsym       # 动态符号表 (包含 struct ip6_hdr 等符号)
  .dynstr       # 动态字符串表
  .rel.dyn      # 动态重定位表
  ...
```

**链接的处理过程:**

1. **编译时:** 当编译 `libnetutil.so` 的源代码时，编译器会识别出对 `struct ip6_hdr` 等类型的引用。这些类型定义来自 `ip6.h`。
2. **链接时:** 静态链接器会将目标文件链接成共享库。虽然 `struct ip6_hdr` 的定义在 `ip6.h` 中，但实际的结构体定义是由编译器处理的，链接器主要关注符号的引用和定义。
3. **运行时 (动态链接):** 当一个应用程序（例如一个使用 NDK 开发的程序）加载 `libnetutil.so` 时，动态链接器 (在 Android 上通常是 `linker64` 或 `linker`) 会执行以下操作：
    * **加载共享库:** 将 `libnetutil.so` 加载到进程的内存空间。
    * **符号解析:** 扫描 `libnetutil.so` 的 `.dynsym` (动态符号表) 和 `.dynstr` (动态字符串表)，找到 `struct ip6_hdr` 等符号。由于 `struct ip6_hdr` 的定义在 Bionic 的头文件中，它实际上并不作为一个需要动态链接的“符号”存在于 Bionic 的共享库中。编译器已经将结构体的大小和布局信息编译到了使用它的代码中。
    * **重定位:** 如果 `libnetutil.so` 中有全局变量使用了 `struct ip6_hdr` 类型，动态链接器会更新这些变量的地址。对于结构体本身，由于它只是一个数据结构定义，动态链接器主要处理的是使用该结构体的变量和函数的地址。

**假设输入与输出 (逻辑推理):**

这里不太适合直接用假设输入输出的方式来描述头文件的功能。头文件是定义，而不是执行逻辑。我们可以假设一个使用该头文件的场景：

**假设输入:** 一个要发送的 IPv6 数据包的各个字段值。

**处理过程:**  一个网络编程函数 (例如在 Android 系统网络协议栈中) 会使用 `ip6.h` 中定义的 `struct ip6_hdr` 结构体，将这些字段值填充到结构体的对应成员中。

**输出:**  一个格式正确的 IPv6 数据包头部的内存表示。

**例如:**

假设要发送一个源地址为 `2001:db8::1`, 目标地址为 `2001:db8::2`, 负载长度为 100 字节的 IPv6 数据包。

```c
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int main() {
    struct ip6_hdr ip6h;

    // 填充 IPv6 头部
    ip6h.ip6_vfc = 0x60; // 版本号 (6)
    ip6h.ip6_flow = 0;    // 流标签
    ip6h.ip6_plen = htons(100); // 负载长度 (网络字节序)
    ip6h.ip6_nxt = 17;   // 下一个头部 (UDP)
    ip6h.ip6_hlim = 64;  // 跳数限制

    inet_pton(AF_INET6, "2001:db8::1", &ip6h.ip6_src);
    inet_pton(AF_INET6, "2001:db8::2", &ip6h.ip6_dst);

    // 打印头部信息 (仅作演示)
    unsigned char *p = (unsigned char *)&ip6h;
    for (int i = 0; i < sizeof(ip6h); i++) {
        printf("%02x ", p[i]);
    }
    printf("\n");

    return 0;
}
```

这个例子展示了如何使用 `ip6.h` 中定义的 `struct ip6_hdr` 来构建 IPv6 头部。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **字节序错误:**  IPv6 头部中的某些字段（如负载长度）是多字节的，需要使用网络字节序 (大端序)。如果开发者不注意进行字节序转换 (`htons`, `ntohs`)，会导致数据包解析错误。

   ```c
   // 错误示例：未进行字节序转换
   ip6h.ip6_plen = 100; // 应该使用 htons(100)
   ```

2. **头部字段填充错误:** 错误地设置头部字段的值，例如版本号错误、跳数限制设置为 0 等，会导致数据包无法正确发送或被网络设备丢弃。

   ```c
   // 错误示例：错误的版本号
   ip6h.ip6_vfc = 0x40; // IPv4 的版本号
   ```

3. **扩展头处理不当:** 如果数据包包含扩展头，开发者需要正确地解析和处理这些扩展头。忽略或错误地解析扩展头会导致通信失败或安全问题。

4. **地址结构体使用错误:**  错误地使用 `struct in6_addr` 结构体，例如没有正确地将字符串形式的 IPv6 地址转换为二进制形式，会导致地址错误。

   ```c
   // 错误示例：直接赋值字符串
   // strcpy((char *)ip6h.ip6_src.s6_addr, "2001:db8::1"); // 错误的做法
   inet_pton(AF_INET6, "2001:db8::1", &ip6h.ip6_src); // 正确的做法
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `ip6.h` 的路径:**

1. **Java 代码 (Android Framework):**  高层的 Android Framework 代码，例如 `java.net.Inet6Address` 或 `java.net.Socket` 等类，用于处理网络连接和地址信息。
2. **JNI (Java Native Interface):**  当 Java 代码需要进行底层的网络操作时，会通过 JNI 调用 Native 代码 (通常是 C/C++ 代码)。
3. **Native 代码 (Bionic/NDK):** 这些 Native 代码会使用 Bionic 库提供的网络相关的函数，例如 `socket()`, `connect()`, `sendto()` 等。
4. **系统调用:** Bionic 库中的网络函数会进一步调用 Linux 内核提供的系统调用，例如 `socket(AF_INET6, ...)` 或 `sendto(..., (const struct sockaddr *)&addr6, sizeof(addr6))`.
5. **内核网络协议栈:**  内核接收到系统调用后，网络协议栈会根据指定的地址族 (例如 `AF_INET6`) 和协议类型来处理数据包。在处理 IPv6 数据包时，内核代码会使用到 `ip6.h` 中定义的结构体来解析和构建 IPv6 头部。

**NDK 到 `ip6.h` 的路径:**

1. **NDK 应用代码:** 使用 NDK 开发的 C/C++ 应用可以直接包含 `<netinet/ip6.h>` 头文件。
2. **使用 Socket API:** NDK 应用可以使用标准的 Socket API (例如 `socket()`, `bind()`, `sendto()`) 来进行网络编程。
3. **Bionic 库:** NDK 应用调用的 Socket API 函数实际上是 Bionic 库提供的实现。
4. **系统调用和内核:**  Bionic 库的 Socket 函数最终会调用 Linux 内核的系统调用，与 Framework 的路径相同。

**Frida Hook 示例:**

可以使用 Frida Hook 系统调用或者 Bionic 库中的函数来观察 `ip6.h` 中定义的结构体的使用情况。

**示例 1: Hook `sendto` 系统调用 (观察 IPv6 数据包的发送)**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received message")
        print(message['payload'])
    elif message['type'] == 'error':
        print("[!] Error:")
        print(message['stack'])

def main():
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    if pid is None:
        session = device.attach('com.example.myapp') # 替换为你的应用包名
    else:
        session = device.attach(pid)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "sendto"), {
        onEnter: function(args) {
            var sockfd = args[0].toInt32();
            var buf = args[1];
            var len = args[2].toInt32();
            var flags = args[3].toInt32();
            var addr = args[4];
            var addrlen = args[5].toInt32();

            // 判断是否是 IPv6 地址族
            const AF_INET6 = 10;
            var sa_family = Memory.readU16(addr);
            if (sa_family == AF_INET6) {
                console.log("[sendto] IPv6 packet detected!");
                console.log("sockfd:", sockfd);
                console.log("len:", len);

                // 读取 sockaddr_in6 结构体
                var sin6_family = Memory.readU16(addr);
                var sin6_port = Memory.readU16(addr.add(2));
                var sin6_flowinfo = Memory.readU32(addr.add(4));
                var sin6_addr = addr.add(8);
                var sin6_scope_id = Memory.readU32(addr.add(24));

                console.log("sin6_family:", sin6_family);
                console.log("sin6_port:", sin6_port);
                console.log("sin6_flowinfo:", sin6_flowinfo);
                console.log("sin6_addr:", sin6_addr.readByteArray(16));
                console.log("sin6_scope_id:", sin6_scope_id);

                // 读取 ip6_hdr 结构体 (假设数据包头部紧跟着 sockaddr_in6)
                var ip6_hdr_ptr = buf;
                var ip6_vfc = Memory.readU8(ip6_hdr_ptr);
                var ip6_flow_high = Memory.readU24(ip6_hdr_ptr.add(1));
                var ip6_plen = Memory.readU16(ip6_hdr_ptr.add(4));
                var ip6_nxt = Memory.readU8(ip6_hdr_ptr.add(6));
                var ip6_hlim = Memory.readU8(ip6_hdr_ptr.add(7));
                var ip6_src = ip6_hdr_ptr.add(8).readByteArray(16);
                var ip6_dst = ip6_hdr_ptr.add(24).readByteArray(16);

                console.log("ip6_vfc:", ip6_vfc.toString(16));
                console.log("ip6_flow:", ip6_flow_high.toString(16));
                console.log("ip6_plen:", ip6_plen);
                console.log("ip6_nxt:", ip6_nxt);
                console.log("ip6_hlim:", ip6_hlim);
                console.log("ip6_src:", hexdump(ip6_src));
                console.log("ip6_dst:", hexdump(ip6_dst));
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print('[*] Script loaded, press Ctrl+C to exit')
    sys.stdin.read()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将上面的 Python 代码保存为 `frida_hook_ip6.py`。
2. 找到你想要监控的 Android 应用程序的进程 ID (PID) 或者直接使用包名。
3. 运行 Frida 脚本: `frida -U -f com.example.myapp frida_hook_ip6.py` (如果使用包名) 或者 `frida -U PID frida_hook_ip6.py` (如果使用 PID)。

这个 Frida 脚本会 Hook `sendto` 系统调用，并在检测到 IPv6 数据包发送时，打印出相关的头部信息，包括 `ip6_hdr` 结构体的各个字段值。你可以根据需要修改脚本来 Hook 其他相关的函数或系统调用，以观察 `ip6.h` 中定义的结构体在 Android 系统中的使用情况。

**请注意:** Frida Hook 需要 root 权限或者在允许调试的设备上运行。你需要安装 Frida 工具和相应的 Python 库。

通过这些方法，你可以理解 `bionic/libc/include/netinet/ip6.h` 在 Android 系统中的作用，以及 Android Framework 和 NDK 如何一步步地使用到它。

### 提示词
```
这是目录为bionic/libc/include/netinet/ip6.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: ip6.h,v 1.23 2007/12/25 18:33:46 perry Exp $	*/
/*	$KAME: ip6.h,v 1.45 2003/06/05 04:46:38 keiichi Exp $	*/

/*
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
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ip.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_IP6_H_
#define _NETINET_IP6_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <endian.h>

#include <linux/in6.h>

/*
 * Definition for internet protocol version 6.
 * RFC 2460
 */

struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			u_int32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			u_int16_t ip6_un1_plen;	/* payload length */
			u_int8_t  ip6_un1_nxt;	/* next header */
			u_int8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		u_int8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
} __packed;

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

#define IPV6_VERSION		0x60
#define IPV6_VERSION_MASK	0xf0

#define IPV6_FLOWINFO_MASK	0xffffff0f	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0xffff0f00	/* flow label (20 bits) */

#if 1
/* ECN bits proposed by Sally Floyd */
#define IP6TOS_CE		0x01	/* congestion experienced */
#define IP6TOS_ECT		0x02	/* ECN-capable transport */
#endif

/*
 * Extension Headers
 */

struct	ip6_ext {
	u_int8_t ip6e_nxt;
	u_int8_t ip6e_len;
} __packed;

/* Hop-by-Hop options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_hbh {
	u_int8_t ip6h_nxt;	/* next header */
	u_int8_t ip6h_len;	/* length in units of 8 octets */
	/* followed by options */
} __packed;

/* Destination options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_dest {
	u_int8_t ip6d_nxt;	/* next header */
	u_int8_t ip6d_len;	/* length in units of 8 octets */
	/* followed by options */
} __packed;

/* Option types and related macros */
#define IP6OPT_PAD1		0x00	/* 00 0 00000 */
#define IP6OPT_PADN		0x01	/* 00 0 00001 */
#define IP6OPT_JUMBO		0xC2	/* 11 0 00010 = 194 */
#define IP6OPT_NSAP_ADDR	0xC3	/* 11 0 00011 */
#define IP6OPT_TUNNEL_LIMIT	0x04	/* 00 0 00100 */
#define IP6OPT_RTALERT		0x05	/* 00 0 00101 (KAME definition) */
#define IP6OPT_ROUTER_ALERT	0x05	/* (RFC3542 def, recommended) */

#define IP6OPT_RTALERT_LEN	4
#define IP6OPT_RTALERT_MLD	0	/* Datagram contains an MLD message */
#define IP6OPT_RTALERT_RSVP	1	/* Datagram contains an RSVP message */
#define IP6OPT_RTALERT_ACTNET	2 	/* contains an Active Networks msg */
#define IP6OPT_MINLEN		2

#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6OPT_TYPE_SKIP	0x00
#define IP6OPT_TYPE_DISCARD	0x40
#define IP6OPT_TYPE_FORCEICMP	0x80
#define IP6OPT_TYPE_ICMP	0xC0

#define IP6OPT_MUTABLE		0x20

/* IPv6 options: common part */
struct ip6_opt {
	u_int8_t ip6o_type;
	u_int8_t ip6o_len;
} __packed;

/* Jumbo Payload Option */
struct ip6_opt_jumbo {
	u_int8_t ip6oj_type;
	u_int8_t ip6oj_len;
	u_int8_t ip6oj_jumbo_len[4];
} __packed;
#define IP6OPT_JUMBO_LEN 6

/* NSAP Address Option */
struct ip6_opt_nsap {
	u_int8_t ip6on_type;
	u_int8_t ip6on_len;
	u_int8_t ip6on_src_nsap_len;
	u_int8_t ip6on_dst_nsap_len;
	/* followed by source NSAP */
	/* followed by destination NSAP */
} __packed;

/* Tunnel Limit Option */
struct ip6_opt_tunnel {
	u_int8_t ip6ot_type;
	u_int8_t ip6ot_len;
	u_int8_t ip6ot_encap_limit;
} __packed;

/* Router Alert Option */
struct ip6_opt_router {
	u_int8_t ip6or_type;
	u_int8_t ip6or_len;
	u_int8_t ip6or_value[2];
} __packed;
/* Router alert values (in network byte order) */
#define IP6_ALERT_MLD	0x0000
#define IP6_ALERT_RSVP	0x0100
#define IP6_ALERT_AN	0x0200

/* Routing header */
struct ip6_rthdr {
	u_int8_t  ip6r_nxt;	/* next header */
	u_int8_t  ip6r_len;	/* length in units of 8 octets */
	u_int8_t  ip6r_type;	/* routing type */
	u_int8_t  ip6r_segleft;	/* segments left */
	/* followed by routing type specific data */
} __packed;

/* Type 0 Routing header */
struct ip6_rthdr0 {
	u_int8_t  ip6r0_nxt;		/* next header */
	u_int8_t  ip6r0_len;		/* length in units of 8 octets */
	u_int8_t  ip6r0_type;		/* always zero */
	u_int8_t  ip6r0_segleft;	/* segments left */
	u_int32_t ip6r0_reserved;	/* reserved field */
} __packed;

/* Fragment header */
struct ip6_frag {
	u_int8_t  ip6f_nxt;		/* next header */
	u_int8_t  ip6f_reserved;	/* reserved field */
	u_int16_t ip6f_offlg;		/* offset, reserved, and flag */
	u_int32_t ip6f_ident;		/* identification */
} __packed;

#define IP6F_OFF_MASK		0xf8ff	/* mask out offset from _offlg */
#define IP6F_RESERVED_MASK	0x0600	/* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0100	/* more-fragments flag */

/*
 * Internet implementation parameters.
 */
#define IPV6_MAXHLIM	255	/* maximum hoplimit */
#define IPV6_DEFHLIM	64	/* default hlim */
#define IPV6_FRAGTTL	120	/* ttl for fragment packets, in slowtimo tick */
#define IPV6_HLIMDEC	1	/* subtracted when forwarding */

#define IPV6_MMTU	1280	/* minimal MTU and reassembly. 1024 + 256 */
#define IPV6_MAXPACKET	65535	/* ip6 max packet size without Jumbo payload*/

#endif /* !_NETINET_IP6_H_ */
```