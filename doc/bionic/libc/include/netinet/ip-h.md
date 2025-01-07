Response:
Let's break down the thought process for analyzing this `ip.h` header file.

**1. Initial Understanding of the Request:**

The request asks for a comprehensive analysis of the provided C header file (`ip.h`) located within the Android Bionic library. It specifically requests:

* **Functionality:** What does this file define?
* **Android Relevance:** How does this relate to Android?
* **libc Function Implementation:**  Detailed explanation of each libc function (though a header file doesn't *implement* functions). This needs clarification.
* **Dynamic Linker Relevance:** Any connection to the dynamic linker.
* **Logic/Assumptions:**  Any deductions made based on the content.
* **Common Errors:** Potential usage mistakes.
* **Android Framework/NDK Path:** How code reaches this header.
* **Frida Hooking:** Example of debugging with Frida.

**2. Analyzing the Header File Content:**

* **Copyright and License:**  Recognize the BSD-style license and the origins from BSD/NetBSD/OpenBSD. This immediately tells us it's a standard networking header.
* **Include Guards (`#ifndef _NETINET_IP_H_`, `#define _NETINET_IP_H_`, `#endif`):**  Understand their purpose: preventing multiple inclusions and potential compilation errors.
* **Standard Includes:** Identify the included headers (`sys/cdefs.h`, `sys/types.h`, `endian.h`, `netinet/in.h`, `netinet/in_systm.h`). Recognize that these provide foundational definitions for C, data types, byte order handling, and other internet protocol related structures. This reinforces the idea that this file deals with networking.
* **`__BEGIN_DECLS` and `__END_DECLS`:** Recognize these as compiler directives for C++ compatibility.
* **Key Definition: `struct ip`:** This is the core of the file. Carefully examine the members of this structure:
    * **Bitfields:**  `ip_hl:4`, `ip_v:4`. Understand that these pack data into fewer bits. Realize `ip_hl` (header length) and `ip_v` (version) are fundamental IP header fields.
    * **Standard Types:**  `u_int8_t`, `u_int16_t`, `u_int32_t`. Know these are unsigned integer types of different sizes.
    * **Flags:**  `IP_RF`, `IP_DF`, `IP_MF`, `IP_OFFMASK`. Recognize these as flags related to IP fragmentation.
    * **Addresses:** `struct in_addr ip_src, ip_dst`. Understand these represent IP addresses (defined in `netinet/in.h`).
* **Macros and Definitions:** Go through each `#define`:
    * **`IPVERSION`:**  Clearly defines the IP version (4).
    * **`IP_MAXPACKET`:**  Maximum IP packet size.
    * **`IPTOS_*`:** Definitions related to the Type of Service (TOS) field, including low delay, throughput, reliability, cost, and ECN.
    * **`IPOPT_*`:** Definitions for IP options, including control, debugging, routing, timestamping, security, etc. Notice the structure for `ip_timestamp`.
    * **`MAXTTL`, `IPDEFTTL`, `IPFRAGTTL`, `IPTTLDEC`:** Time-to-live related constants.
    * **`IP_MSS`:** Maximum Segment Size.
    * **`ippseudo`:**  The IP pseudo-header used for TCP/UDP checksum calculation.
* **Bionic Additions:** Notice the section labeled "BIONIC addition" which includes definitions like `struct iphdr`, `struct ip_auth_hdr`, `struct ip_esp_hdr`, `struct ip_comp_hdr`. Recognize these as structures related to different IP header formats and IPsec (Authentication Header and Encapsulating Security Payload). The `iphdr` is particularly important as it's commonly used and avoids bitfield issues in some implementations.

**3. Answering the Specific Questions (Iterative Process):**

* **Functionality:** Summarize the purpose of the header file – defining the structure of IP headers and related constants.
* **Android Relevance:**  Explain that this is essential for network communication on Android devices. Provide examples like network sockets, VPNs, etc.
* **libc Function Implementation:**  Realize the initial interpretation was incorrect. Header files *declare* structures and constants, not *implement* functions. Correct the understanding and explain the role of the header in providing type definitions for functions implemented elsewhere in the libc.
* **Dynamic Linker Relevance:**  Initially, there seems to be no direct connection to the dynamic linker. State this but keep an open mind. The linker deals with loading shared libraries, not the low-level structure of IP packets. *Self-correction:  While not directly *used* by the linker, the *data structures defined here are used by code that gets linked.*
* **Logic/Assumptions:** Point out the assumptions made in defining the structures (e.g., byte order).
* **Common Errors:** Think about how developers might misuse these definitions (incorrectly sizing buffers, endianness issues).
* **Android Framework/NDK Path:**  Start from the application level and trace down. App -> Framework (using Java network APIs) -> Native code (using NDK network APIs) -> Bionic libc (where this header is used). Focus on the `socket()` system call.
* **Frida Hooking:**  Devise a simple Frida script to inspect the `ip` structure within a running process, targeting a relevant system call like `sendto`.

**4. Structuring the Response:**

Organize the information logically, addressing each part of the request. Use clear headings and bullet points for readability. Provide code examples for Frida and clarify any technical terms.

**5. Refinement and Review:**

Read through the generated response. Check for accuracy, completeness, and clarity. Ensure the language is precise and avoids jargon where possible. For example, initially, I might have just said "defines IP headers," but refining it to include "data structures for representing IPv4 headers, options, and related constants" is more accurate. Double-check the Frida example for correctness.

This iterative process of analysis, answering, structuring, and refining helps produce a comprehensive and accurate response to the request. The key is to break down the complex request into smaller, manageable parts and to leverage existing knowledge of networking and C programming.
好的，让我们详细分析一下 `bionic/libc/include/netinet/ip.h` 这个头文件。

**功能列举:**

这个头文件定义了互联网协议版本 4 (IPv4) 的数据结构和相关的常量。它主要包含了：

1. **`struct ip` 结构体:** 定义了 IPv4 报文头的基本格式，包括版本号、头部长度、服务类型、总长度、标识符、分片偏移、生存时间、协议类型、校验和以及源 IP 地址和目标 IP 地址。
2. **宏定义:**  定义了与 IPv4 协议相关的各种常量，例如：
    * `IPVERSION`: IP 协议版本号 (4)。
    * `IP_MAXPACKET`: 最大 IP 数据包大小。
    * `IPTOS_*`:  服务类型 (Type of Service, TOS) 字段的各种标志位，用于区分不同的服务质量需求，例如低延迟、高吞吐量、高可靠性等。
    * `IPOPT_*`: IP 选项相关的定义，例如记录路由、时间戳、安全选项、源站选路等。
    * `MAXTTL`, `IPDEFTTL`: 生存时间 (Time to Live, TTL) 的最大值和默认值。
    * `IP_MSS`:  最大报文段长度 (Maximum Segment Size)。
3. **`struct ippseudo` 结构体:** 定义了用于计算 TCP 和 UDP 校验和的伪头部 (pseudo header)。
4. **Bionic 特有的结构体 (`struct iphdr`, `struct ip_auth_hdr`, `struct ip_esp_hdr`, `struct ip_comp_hdr`):**  这些结构体是为了兼容 Linux 内核而添加的，在一些程序中可能会被用到。它们提供了另一种形式的 IP 头部定义，以及与 IPsec 相关的头部结构。

**与 Android 功能的关系及举例说明:**

`ip.h` 中定义的结构体和常量是 Android 系统网络通信的基础。任何涉及 IP 协议的网络操作都会直接或间接地使用到这些定义。

**举例说明:**

* **网络套接字编程 (Sockets):** 当 Android 应用程序使用 Java 或 NDK 中的套接字 API 进行网络通信时，底层实现会用到 `ip.h` 中定义的 `struct ip` 来构建和解析 IP 数据包。例如，当创建一个 `SOCK_STREAM` 或 `SOCK_DGRAM` 套接字并通过 `sendto` 或 `send` 发送数据时，操作系统内核会构造包含 IP 头的网络包。
* **VPN (Virtual Private Network):** VPN 应用在 Android 上建立安全隧道时，需要处理 IP 数据包的封装和解封装。这涉及到读取和修改 IP 头部的信息，例如源地址、目标地址等，而这些信息的格式就是由 `ip.h` 定义的。
* **网络诊断工具 (如 ping, traceroute):** 这些工具发送和接收 IP 数据包，并解析 IP 头部的信息来诊断网络连接问题。例如，`ping` 工具会检查收到的 ICMP 回应报文中的 IP 头部，以确定目标主机是否可达。
* **数据包捕获 (如 tcpdump):**  Android 上的数据包捕获工具会捕获网络接口上的原始数据包，并按照 `ip.h` 中定义的格式来解析 IP 头部，显示源地址、目标地址、协议类型等信息。

**详细解释每一个 libc 函数的功能是如何实现的:**

**重要提示:** `ip.h` 是一个 **头文件**，它只包含 **数据结构的定义和宏定义**，**不包含任何 C 库函数的实现代码**。  C 库函数的实现代码通常位于 `.c` 源文件中，编译后会链接到 libc 库中。

`ip.h` 中定义的结构体和常量会被其他 C 库函数使用，例如：

* **套接字相关的函数 (`socket`, `bind`, `connect`, `sendto`, `recvfrom` 等):**  这些函数在进行网络通信时，会使用 `struct ip` 来构造或解析 IP 数据包。例如，`sendto` 函数在发送 UDP 数据报时，内核会创建一个包含 `struct ip` 结构的 IP 头部，并将应用程序提供的数据封装在 IP 数据包中。
* **网络地址转换函数 (`inet_addr`, `inet_ntoa` 等):** 这些函数用于在点分十进制的 IP 地址字符串和 `struct in_addr` 结构体之间进行转换，而 `struct in_addr` 是 `struct ip` 的成员。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`ip.h` 本身与 dynamic linker 没有直接的功能关联。dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载和链接共享库 (`.so` 文件)。

虽然 `ip.h` 中定义的结构体会被 libc 库中的网络相关函数使用，而 libc 库本身会被 dynamic linker 加载，但 `ip.h` 的内容并不直接影响 dynamic linker 的行为。

**SO 布局样本 (以 libc.so 为例):**

```
libc.so:
    .text          # 存放可执行代码
    .rodata        # 存放只读数据，例如字符串常量
    .data          # 存放已初始化的全局变量和静态变量
    .bss           # 存放未初始化的全局变量和静态变量
    .plt           # Procedure Linkage Table，用于延迟绑定
    .got           # Global Offset Table，用于访问全局变量和函数地址

    # ... 其他段 ...

    # 包含网络相关函数的实现代码 (例如 sendto, recvfrom 等)
    # 这些函数的实现会使用 ip.h 中定义的结构体
```

**链接的处理过程:**

1. **编译时:** 当编译一个使用网络功能的 Android 应用或库时，编译器会包含 `ip.h` 头文件，以便正确解析 IP 相关的结构体和常量。
2. **链接时:** 链接器会将应用程序或库的目标文件与所需的共享库 (例如 `libc.so`) 链接在一起。如果应用程序调用了 `sendto` 等网络函数，链接器会在 `libc.so` 的 `.plt` 和 `.got` 段中创建相应的条目。
3. **运行时:** 当应用程序启动时，dynamic linker 会加载 `libc.so` 到内存中。
4. **延迟绑定:** 当第一次调用 `sendto` 函数时，dynamic linker 会解析 `sendto` 函数在 `libc.so` 中的实际地址，并更新 `.got` 表中的对应条目。后续对 `sendto` 的调用将直接通过 `.got` 表跳转到实际的函数地址，而无需再次进行地址解析。
5. **libc 函数执行:** `sendto` 函数的实现代码会使用 `ip.h` 中定义的 `struct ip` 结构体来构造 IP 数据包。

**逻辑推理，给出假设输入与输出:**

假设一个 C 程序需要构造一个基本的 IP 头部。

**假设输入:**

* 源 IP 地址: `192.168.1.100`
* 目标 IP 地址: `8.8.8.8`
* 协议类型: `IPPROTO_TCP` (假设定义在其他头文件中)
* 数据部分长度: `100` 字节

**代码示例 (简化):**

```c
#include <netinet/ip.h>
#include <arpa/inet.h> // for inet_pton

int main() {
    struct ip ip_header;

    ip_header.ip_v = IPVERSION;
    ip_header.ip_hl = 5; // 假设没有 IP 选项
    ip_header.ip_tos = 0;
    ip_header.ip_len = htons(sizeof(struct ip) + 100); // 总长度
    ip_header.ip_id = htons(12345);
    ip_header.ip_off = 0;
    ip_header.ip_ttl = 64;
    ip_header.ip_p = IPPROTO_TCP;
    ip_header.ip_sum = 0; // 稍后计算校验和
    inet_pton(AF_INET, "192.168.1.100", &ip_header.ip_src);
    inet_pton(AF_INET, "8.8.8.8", &ip_header.ip_dst);

    // ... 计算校验和 ...

    // ... 将 ip_header 和数据发送出去 ...

    return 0;
}
```

**假设输出 (`ip_header` 结构体的内存表示，字节顺序可能因系统而异):**

```
(假设大端字节序)
ip_v: 4
ip_hl: 5
ip_tos: 0
ip_len: 0x0069  (105，包括 IP 头部 20 字节 + 数据 100 字节)
ip_id: 0x3039  (12345)
ip_off: 0x0000
ip_ttl: 64
ip_p:  6     (TCP 协议号)
ip_sum: ... (校验和)
ip_src: 0xC0A80164 (192.168.1.100)
ip_dst: 0x08080808 (8.8.8.8)
```

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **字节序错误:** IP 头部中的某些字段 (如长度、ID) 是网络字节序 (大端序)，而主机字节序可能不同。开发者需要使用 `htons()` (host to network short) 和 `ntohs()` (network to host short) 等函数进行转换。

   **错误示例:**

   ```c
   ip_header.ip_len = sizeof(struct ip) + data_length; // 缺少 htons()
   ```

2. **IP 头部长度计算错误:**  `ip_hl` 字段表示头部长度，单位是 4 字节。如果错误地计算或设置该字段，会导致解析错误。

   **错误示例:**

   ```c
   ip_header.ip_hl = sizeof(struct ip); // 应该除以 4
   ```

3. **校验和计算错误:** IP 头部包含一个校验和字段，用于验证头部数据的完整性。如果校验和计算不正确，数据包可能会被网络设备丢弃。

   **错误示例:**  忘记计算校验和或使用了错误的计算方法。

4. **分片标志和偏移量使用不当:**  错误地设置 `IP_DF`, `IP_MF` 标志或 `ip_off` 字段可能导致数据包无法正确分片和重组。

5. **直接修改只读的宏定义:** 尝试修改 `ip.h` 中定义的宏常量 (例如 `IPVERSION`) 是错误的，因为这些宏在编译时会被替换，修改源文件不会改变已编译代码的行为。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 Bionic 的路径:**

1. **Android Application (Java/Kotlin):**  应用程序通过 Java SDK 提供的网络 API (例如 `java.net.Socket`, `java.net.DatagramSocket`) 发起网络请求。
2. **Android Framework (Java):**  Java 网络 API 的底层实现会调用 Android 系统的 native 方法 (JNI)。
3. **NDK (Native Development Kit) (C/C++):** 如果应用程序使用 NDK 进行网络编程，可以直接调用 C 库函数 (如 `socket`, `sendto`, `recvfrom`)。
4. **Bionic libc (C Library):** NDK 中使用的 C 库函数由 Bionic 提供。这些函数会使用 `ip.h` 中定义的结构体和常量来处理网络数据包。
5. **Linux Kernel:** Bionic libc 中的网络相关函数最终会调用 Linux 内核提供的系统调用 (如 `sendto`, `recvfrom`)，内核负责实际的网络数据包的发送和接收。

**Frida Hook 示例:**

假设我们想在应用程序发送 UDP 数据包时，查看 Bionic libc 中 `sendto` 函数接收到的 IP 头部信息。

```python
import frida
import struct

# 连接到目标进程
process_name = "目标应用程序的进程名"  # 替换为实际进程名
session = frida.attach(process_name)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
    onEnter: function(args) {
        // args[0] 是 socket 文件描述符
        // args[1] 是指向要发送数据的缓冲区的指针
        // args[2] 是要发送的数据的长度
        // args[3] 是目标地址结构体的指针 (struct sockaddr_in 或 sockaddr_in6)
        // args[4] 是地址结构体的长度

        var len = parseInt(args[2]);
        if (len > 20) { // 假设数据包长度大于 IP 头部长度
            var ip_header_ptr = ptr(args[1]);
            var version_ihl = ip_header_ptr.readU8();
            var version = version_ihl >> 4;
            var ihl = version_ihl & 0x0F;
            var header_len = ihl * 4;

            if (version == 4 && header_len >= 20) {
                console.log("sendto called!");
                console.log("Socket FD:", args[0]);
                console.log("Buffer Pointer:", args[1]);
                console.log("Length:", len);
                console.log("To:", Memory.readCString(args[3]));

                // 读取 IP 头部
                var ip_header_data = ip_header_ptr.readByteArray(header_len);
                console.log("IP Header (hex):", hexdump(ip_header_data, { ansi: true }));

                // 解析 IP 头部
                var ip_header = struct.unpack('!BBH HHH BBH II', ip_header_data);
                console.log("IP Header (parsed):", ip_header);
                console.log("  Version:", ip_header[0] >> 4);
                console.log("  Header Length:", (ip_header[0] & 0x0F) * 4);
                console.log("  Total Length:", ip_header[2]);
                // ... 解析其他字段 ...
            }
        }
    }
});
"""

script = session.create_script_from_string(script_code)
script.load()
input("Press Enter to detach...")
session.detach()
```

**代码解释:**

1. **`frida.attach(process_name)`:** 连接到目标 Android 应用程序的进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "sendto"), ...)`:**  Hook Bionic libc 中的 `sendto` 函数。
3. **`onEnter: function(args)`:**  在 `sendto` 函数执行前被调用。
4. **`args`:**  包含 `sendto` 函数的参数。
5. **读取和解析 IP 头部:**  从 `args[1]` 指向的缓冲区读取 IP 头部数据，并使用 `struct.unpack` 解析 IP 头部字段 (注意网络字节序 `!`)。
6. **打印信息:**  将捕获到的信息 (包括原始 IP 头部和解析后的字段) 打印到 Frida 控制台。

**调试步骤:**

1. **准备环境:**  安装 Frida 和 Python 环境，确保可以 adb 连接到 Android 设备或模拟器。
2. **运行目标应用:**  启动需要监控网络活动的 Android 应用程序。
3. **运行 Frida 脚本:**  执行上面的 Python Frida 脚本，替换 `"目标应用程序的进程名"` 为实际进程名。
4. **触发网络操作:**  在目标应用程序中执行会发送 UDP 数据包的操作。
5. **查看 Frida 输出:**  Frida 控制台会打印出 `sendto` 函数被调用时的 IP 头部信息。

通过这个 Frida Hook 示例，你可以实时监控应用程序发送的网络数据包，并深入了解 Bionic libc 是如何处理 IP 头部数据的。

希望以上分析能够帮助你理解 `bionic/libc/include/netinet/ip.h` 文件以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/include/netinet/ip.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: ip.h,v 1.12 2006/04/27 02:19:32 tedu Exp $	*/
/*	$NetBSD: ip.h,v 1.9 1995/05/15 01:22:44 cgd Exp $	*/

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

#ifndef _NETINET_IP_H_
#define _NETINET_IP_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <endian.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

__BEGIN_DECLS

/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */
#define	IPVERSION	4

/*
 * Structure of an internet header, naked of options.
 */
struct ip {
	u_int32_t ip_hl:4,		/* header length */
		  ip_v:4;		/* version */
	u_int8_t  ip_tos;		/* type of service */
	u_int16_t ip_len;		/* total length */
	u_int16_t ip_id;		/* identification */
	u_int16_t ip_off;		/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t  ip_ttl;		/* time to live */
	u_int8_t  ip_p;			/* protocol */
	u_int16_t ip_sum;		/* checksum */
	struct	  in_addr ip_src, ip_dst; /* source and dest address */
};

#define	IP_MAXPACKET	65535		/* maximum packet size */

/*
 * Definitions for IP type of service (ip_tos)
 */
#define	IPTOS_LOWDELAY		0x10
#define	IPTOS_THROUGHPUT	0x08
#define	IPTOS_RELIABILITY	0x04
#define	IPTOS_MINCOST		0x02
#if 1
/* ECN RFC3168 obsoletes RFC2481, and these will be deprecated soon. */
#define IPTOS_CE		0x01	/* congestion experienced */
#define IPTOS_ECT		0x02	/* ECN-capable transport */
#endif

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
#define	IPTOS_PREC_NETCONTROL		0xe0
#define	IPTOS_PREC_INTERNETCONTROL	0xc0
#define	IPTOS_PREC_CRITIC_ECP		0xa0
#define	IPTOS_PREC_FLASHOVERRIDE	0x80
#define	IPTOS_PREC_FLASH		0x60
#define	IPTOS_PREC_IMMEDIATE		0x40
#define	IPTOS_PREC_PRIORITY		0x20
#define	IPTOS_PREC_ROUTINE		0x00

/*
 * ECN (Explicit Congestion Notification) codepoints in RFC3168
 * mapped to the lower 2 bits of the TOS field.
 */
#define	IPTOS_ECN_NOTECT	0x00	/* not-ECT */
#define	IPTOS_ECN_ECT1		0x01	/* ECN-capable transport (1) */
#define	IPTOS_ECN_ECT0		0x02	/* ECN-capable transport (0) */
#define	IPTOS_ECN_CE		0x03	/* congestion experienced */
#define	IPTOS_ECN_MASK		0x03	/* ECN field mask */

/*
 * Definitions for options.
 */
#define	IPOPT_COPIED(o)		((o)&0x80)
#define	IPOPT_CLASS(o)		((o)&0x60)
#define	IPOPT_NUMBER(o)		((o)&0x1f)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_DEBMEAS		0x40
#define	IPOPT_RESERVED2		0x60

#define	IPOPT_EOL		0		/* end of option list */
#define	IPOPT_NOP		1		/* no operation */

#define	IPOPT_RR		7		/* record packet route */
#define	IPOPT_TS		68		/* timestamp */
#define	IPOPT_SECURITY		130		/* provide s,c,h,tcc */
#define	IPOPT_LSRR		131		/* loose source route */
#define	IPOPT_SATID		136		/* satnet id */
#define	IPOPT_SSRR		137		/* strict source route */

/*
 * Offsets to fields in options other than EOL and NOP.
 */
#define	IPOPT_OPTVAL		0		/* option ID */
#define	IPOPT_OLEN		1		/* option length */
#define	IPOPT_OFFSET		2		/* offset within option */
#define	IPOPT_MINOFF		4		/* min value of above */

/*
 * Time stamp option structure.
 */
struct	ip_timestamp {
	u_int8_t ipt_code;		/* IPOPT_TS */
	u_int8_t ipt_len;		/* size of structure (variable) */
	u_int8_t ipt_ptr;		/* index of current entry */
	u_int32_t ipt_flg:4,		/* flags, see below */
		  ipt_oflw:4;		/* overflow counter */
	union ipt_timestamp {
	n_time	ipt_time[1];
	struct	ipt_ta {
		struct in_addr ipt_addr;
		n_time ipt_time;
	} ipt_ta[1];
	} ipt_timestamp;
};

/* flag bits for ipt_flg */
#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3		/* specified modules only */

/* bits for security (not byte swapped) */
#define	IPOPT_SECUR_UNCLASS	0x0000
#define	IPOPT_SECUR_CONFID	0xf135
#define	IPOPT_SECUR_EFTO	0x789a
#define	IPOPT_SECUR_MMMM	0xbc4d
#define	IPOPT_SECUR_RESTR	0xaf13
#define	IPOPT_SECUR_SECRET	0xd788
#define	IPOPT_SECUR_TOPSECRET	0x6bc5

/*
 * Internet implementation parameters.
 */
#define	MAXTTL		255		/* maximum time to live (seconds) */
#define	IPDEFTTL	64		/* default ttl, from RFC 1340 */
#define	IPFRAGTTL	60		/* time to live for frags, slowhz */
#define	IPTTLDEC	1		/* subtracted when forwarding */

#define	IP_MSS		576		/* default maximum segment size */

/*
 * This is the real IPv4 pseudo header, used for computing the TCP and UDP
 * checksums. For the Internet checksum, struct ipovly can be used instead.
 * For stronger checksums, the real thing must be used.
 */
struct ippseudo {
	struct    in_addr ippseudo_src;	/* source internet address */
	struct    in_addr ippseudo_dst;	/* destination internet address */
	u_int8_t  ippseudo_pad;		/* pad, must be zero */
	u_int8_t  ippseudo_p;		/* protocol */
	u_int16_t ippseudo_len;		/* protocol length */
};

/* BIONIC addition: declarations matching the Linux kernel */
/*                  some programs expect these...          */

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4
#define MAX_IPOPTLEN 40

#define IPOPT_COPY		0x80
#define IPOPT_CLASS_MASK	0x60
#define IPOPT_NUMBER_MASK	0x1f

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_MEASUREMENT	0x40
#define	IPOPT_RESERVED2		0x60

#define IPOPT_END	(0 |IPOPT_CONTROL)
#define IPOPT_NOOP	(1 |IPOPT_CONTROL)
#define IPOPT_SEC	(2 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_TIMESTAMP	(4 |IPOPT_MEASUREMENT)
#define IPOPT_SID	(8 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t  ihl    :4,
		 version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t  version:4,
  		 ihl    :4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	uint8_t	  tos;
	uint16_t  tot_len;
	uint16_t  id;
	uint16_t  frag_off;
	uint8_t   ttl;
	uint8_t   protocol;
	uint16_t  check;
	int32_t   saddr;
	int32_t   daddr;
};

struct ip_auth_hdr {
	uint8_t  nexthdr;
	uint8_t  hdrlen;
	uint16_t reserved;
	uint32_t spi;
	uint32_t seq_no;
	uint8_t  auth_data[0];
};

struct ip_esp_hdr {
	uint32_t spi;
	uint32_t seq_no;
	uint8_t  enc_data[0];
};

struct ip_comp_hdr {
	uint8_t  nexthdr;
	uint8_t  flags;
	uint16_t cpi;
};

__END_DECLS

#endif /* _NETINET_IP_H_ */

"""

```