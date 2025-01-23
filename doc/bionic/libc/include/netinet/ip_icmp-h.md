Response:
Let's break down the thought process for answering the user's request. The request is comprehensive and requires understanding of a header file's purpose, its relation to the operating system, and low-level networking concepts.

**1. Understanding the Core Request:**

The user provided a header file (`ip_icmp.h`) and wants to know its functionalities, especially within the context of Android's Bionic library. They are also interested in the implementation details of related C library functions, dynamic linking aspects, potential errors, and how this file is reached from higher layers of Android.

**2. Initial Analysis of the Header File:**

* **Filename and Location:** `bionic/libc/include/netinet/ip_icmp.h`. This immediately tells us it's part of the network stack definitions in Android's C library. The `netinet` directory strongly suggests it's related to the TCP/IP protocol suite. The `ip_icmp.h` filename clearly points to the ICMP protocol.
* **Copyright and History:** The copyright notice indicates it's derived from BSD Unix (OpenBSD/NetBSD), a common source for networking code. This implies the core functionality is likely standard and well-established.
* **Includes:** The header includes `<sys/cdefs.h>`, `<linux/icmp.h>`, and `<netinet/ip.h>`. This is crucial information:
    * `<sys/cdefs.h>`: Provides compiler-specific definitions and macros for portability.
    * `<linux/icmp.h>`:  This is a key hint. It suggests that Bionic, while being Android's libc, reuses or adapts definitions from the Linux kernel's ICMP structures. This is a common practice.
    * `<netinet/ip.h>`: Defines the structure of IP headers, essential for working with ICMP, as ICMP messages are encapsulated within IP packets.
* **`__BEGIN_DECLS` and `__END_DECLS`:** These are Bionic-specific macros for managing C++ name mangling and ensuring proper linking.
* **Comments about RFCs:**  The comments explicitly mention relevant RFCs (792, 950, etc.). This is a vital clue about the standards this header file implements. It tells us the definitions are not arbitrary but follow established network protocols.
* **`struct icmp`:** This is the central structure definition. It defines the layout of an ICMP header, containing fields for type, code, checksum, and various unions for different ICMP message types. The nested unions are a bit complex but are designed to save space, as not all fields are used for every ICMP type.
* **Macros:** The header defines many macros (e.g., `ICMP_ECHOREPLY`, `ICMP_UNREACH_HOST`). These are symbolic constants representing different ICMP message types and codes. They improve code readability and maintainability.
* **Length Constants:**  Macros like `ICMP_MINLEN`, `ICMP_TSLEN`, etc., define minimum lengths for different ICMP message types, useful for validation.
* **`ICMP_INFOTYPE` Macro:** This macro checks if an ICMP type is considered an "information" type.

**3. Answering the User's Questions -  A Step-by-Step Approach:**

* **Functionality:** Based on the analysis, the primary function is to define the structure and constants related to the ICMP protocol. This involves listing the ICMP message types, codes, and the format of the ICMP header.
* **Relationship to Android:** ICMP is fundamental for network diagnostics (ping), error reporting (destination unreachable), and router discovery. Android, as a networking-capable OS, heavily relies on these functionalities. Examples like `ping` command and network connection failure notifications are good illustrations.
* **libc Function Implementation:** This is a trick question! Header files don't *implement* functions; they define data structures and constants. The *implementation* of ICMP processing happens in the kernel. It's crucial to clarify this distinction. Focus on the *usage* of these definitions by libc functions. `socket()`, `sendto()`, `recvfrom()` are good examples of syscalls used by libc that eventually interact with the kernel's ICMP handling. Explain that the *kernel* is where the actual logic resides.
* **Dynamic Linker:** Header files themselves don't directly involve the dynamic linker. However, the `__BEGIN_DECLS` and `__END_DECLS` macros are relevant. Explain their purpose in managing symbol visibility and name mangling in C++ for shared libraries. Provide a basic example of an SO structure and how the linker resolves symbols.
* **Logical Inference (Assumptions, Input/Output):**  This question needs a bit of interpretation. Since it's a header file,  focus on how the definitions are *used*. For example, if a program receives an ICMP packet with `icmp_type == ICMP_ECHOREPLY`, it knows it's a response to a ping. The "input" is an ICMP packet (conceptually), and the "output" is the interpretation of its type and code.
* **User Errors:** Common errors include incorrect usage of ICMP types/codes when crafting packets, not handling ICMP errors properly when receiving, and buffer overflows if not validating packet sizes based on the defined length constants.
* **Android Framework/NDK Flow:** Start from a high-level action (e.g., the user using the `ping` command or an app checking network connectivity). Trace the path down through the framework (Java/Kotlin), the NDK (C/C++), libc (using socket APIs), and eventually the kernel's network stack where the ICMP processing happens.
* **Frida Hook Example:** Provide a concrete example of how to use Frida to intercept ICMP messages at the system call level (`sendto` or `recvfrom`). Highlight what information can be observed (arguments, return values).

**4. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Address each part of the user's request systematically. Start with the general functionalities, then move to specific aspects like libc, dynamic linking, and finally the Android framework integration and debugging.

**5. Language and Tone:**

Use clear and concise Chinese. Explain technical terms without being overly academic. Assume the user has some programming background but might not be a networking expert.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Focus solely on the header file's content.
* **Correction:** Realize that the user wants to understand its *role* in the broader Android system, so expanding beyond the header file itself is crucial.
* **Initial thought:**  Deeply explain the checksum calculation.
* **Correction:**  While important, it's not explicitly requested and might be too detailed for this general overview. Mention its existence and purpose is sufficient.
* **Initial thought:** Provide complex code examples for everything.
* **Correction:** Keep code examples concise and focused on illustrating specific points (like the Frida hook).

By following this structured thought process, breaking down the complex request into smaller parts, and constantly relating the header file's content to the Android ecosystem, a comprehensive and helpful answer can be generated.
这个目录 `bionic/libc/include/netinet/ip_icmp.h` 中的 `ip_icmp.h` 文件是 Android Bionic C 库中关于互联网控制消息协议（ICMP）的头文件。它定义了 ICMP 协议中使用的数据结构和常量。

**文件功能:**

1. **定义 ICMP 头部结构 (`struct icmp`)**:  这是该文件最核心的功能。它定义了 ICMP 报文的头部结构，包括消息类型、代码、校验和以及根据消息类型变化的联合体字段。

2. **定义 ICMP 消息类型和代码的常量**: 文件中定义了各种 ICMP 消息类型（例如，回显请求 `ICMP_ECHO`，回显应答 `ICMP_ECHOREPLY`，目标不可达 `ICMP_UNREACH` 等）以及每种类型对应的代码。这些常量用于标识 ICMP 报文的具体含义。

3. **定义与特定 ICMP 类型相关的结构**:  例如，`struct icmp_ra_addr` 用于路由器通告消息，联合体 `icmp_hun` 和 `icmp_dun` 包含不同 ICMP 消息类型所需的额外数据。

4. **定义与 ICMP 报文长度相关的常量**:  例如，`ICMP_MINLEN` 定义了 ICMP 报文的最小长度。

**与 Android 功能的关系及举例说明:**

ICMP 协议是互联网协议族中一个基础协议，用于在 IP 主机和路由器之间传递控制消息，例如报告错误、诊断网络问题等。Android 作为基于 Linux 内核的操作系统，自然也需要支持 ICMP 协议以实现网络功能。

* **`ping` 命令**: 最直接的例子就是 `ping` 命令。当你使用 `ping` 命令测试网络连通性时，它会发送 ICMP 回显请求报文 (`ICMP_ECHO`)，并等待目标主机返回 ICMP 回显应答报文 (`ICMP_ECHOREPLY`). `ip_icmp.h` 中定义的常量 `ICMP_ECHO` 和 `ICMP_ECHOREPLY` 就被网络相关的系统调用和库函数使用，以构造和解析这些报文。

* **网络诊断工具**:  Android 系统或应用可能会使用 ICMP 协议进行网络诊断，例如检测路由是否可达、主机是否存活等。

* **错误报告**: 当网络出现问题时，例如目标主机不可达，网络设备会发送 ICMP 目标不可达报文 (`ICMP_UNREACH`)。Android 系统需要能够解析这些 ICMP 报文，并将错误信息反馈给应用程序或用户。

* **路由器发现**:  路由器可以使用 ICMP 路由器通告报文 (`ICMP_ROUTERADVERT`) 来告知网络中的主机它们的路由信息。Android 设备可以接收和处理这些报文来自动配置路由。

**详细解释每一个 libc 函数的功能是如何实现的:**

需要明确的是，`ip_icmp.h` 是一个**头文件**，它定义了数据结构和常量，但**不包含任何 C 库函数的具体实现**。 ICMP 协议的处理主要在 Linux 内核的网络栈中完成。

Android 的 Bionic libc 提供了网络相关的系统调用接口（例如 `socket()`, `sendto()`, `recvfrom()` 等），应用程序可以使用这些接口与内核的网络栈交互，从而发送和接收 ICMP 报文。

例如，当你在 Android 上执行 `ping` 命令时，它会：

1. 使用 `socket()` 系统调用创建一个 RAW socket，指定协议为 `IPPROTO_ICMP`。
2. 构造一个 ICMP 回显请求报文，其中报文的类型字段被设置为 `ICMP_ECHO`（这个常量定义在 `ip_icmp.h` 中）。
3. 使用 `sendto()` 系统调用将构造好的 ICMP 报文发送到目标 IP 地址。
4. 使用 `recvfrom()` 系统调用等待接收来自目标主机的 ICMP 回显应答报文。
5. 解析接收到的报文，检查其类型是否为 `ICMP_ECHOREPLY`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`ip_icmp.h` 本身不直接涉及 dynamic linker 的功能。它只是定义了数据结构和常量，这些定义会被编译到使用它的共享库或可执行文件中。

然而，定义在 `ip_icmp.h` 中的常量和结构体会被网络相关的共享库（例如 `libcutils.so`, `libnetd_client.so` 等）使用。这些共享库在加载时会通过 dynamic linker 进行链接。

**SO 布局样本 (简化):**

```
libnetd_client.so:
    .text:
        ... // 使用了 ICMP 相关常量的代码
        call function_using_icmp_constants
        ...
    .data:
        ...
    .rodata:
        icmp_echo_type: .word ICMP_ECHO  // 常量会被放入只读数据段
        ...
    .dynamic:
        NEEDED libc.so
        ...
    .symtab:
        ...
        _ZN12SomeClassUsingICMP ... // 使用 ICMP 的类的符号
        ...
```

**链接的处理过程:**

1. 当一个应用程序启动并需要使用 `libnetd_client.so` 中的功能时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载这个 SO 文件。
2. Linker 会解析 SO 文件的 `.dynamic` 段，找到它依赖的其他共享库（例如 `libc.so`）。
3. Linker 会加载 `libc.so` (如果尚未加载)。
4. Linker 会解析 `libnetd_client.so` 的符号表 (`.symtab`) 和重定位表 (`.rel.dyn`, `.rel.plt`)。
5. 如果 `libnetd_client.so` 中的代码使用了在 `libc.so` 中定义的符号（尽管这里 `ip_icmp.h` 中的内容更多是常量而非函数），linker 会将这些符号引用解析到 `libc.so` 中对应的地址。
6. 对于定义在 `ip_icmp.h` 中的常量（例如 `ICMP_ECHO`），它们在编译时就已经被替换为具体的数值，并存储在 `libnetd_client.so` 的只读数据段中。 Dynamic linker 不需要对这些常量进行额外的链接处理。

**逻辑推理，假设输入与输出:**

虽然 `ip_icmp.h` 不涉及逻辑推理的代码，但我们可以考虑一个使用它的场景：

**假设输入:**  一个程序接收到一个 IP 数据包，内核判断这是一个 ICMP 报文。内核会将报文头部的类型字段传递给处理 ICMP 报文的函数。

**处理过程 (简化):**  ICMP 处理函数会读取报文的 `icmp_type` 字段，并将其与 `ip_icmp.h` 中定义的常量进行比较：

```c
#include <netinet/ip_icmp.h>

void handle_icmp_packet(struct icmp *icmp_header) {
    switch (icmp_header->icmp_type) {
        case ICMP_ECHOREPLY:
            // 处理回显应答报文
            printf("Received ICMP Echo Reply\n");
            break;
        case ICMP_UNREACH:
            // 处理目标不可达报文
            printf("Received ICMP Unreachable, code: %d\n", icmp_header->icmp_code);
            break;
        // ... 其他 ICMP 类型
        default:
            printf("Received unknown ICMP type: %d\n", icmp_header->icmp_type);
            break;
    }
}
```

**假设输出:**  根据 `icmp_type` 的值，程序会执行相应的处理逻辑，例如打印不同的消息。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误地构造 ICMP 报文**:  程序员可能会错误地设置 `icmp_type` 或 `icmp_code` 的值，导致接收方无法正确解析报文。例如，将回显请求的类型设置为目标不可达的类型。

2. **校验和计算错误**: ICMP 头部包含一个校验和字段。如果程序员在构造报文时没有正确计算校验和，接收方会丢弃该报文。

3. **缓冲区溢出**: 在解析接收到的 ICMP 报文时，如果没有正确检查报文长度，可能会发生缓冲区溢出。例如，假设收到的报文类型是需要特定长度额外数据的类型，但实际收到的报文长度不足，导致读取越界。

4. **没有正确处理 ICMP 错误**: 应用程序在发送网络数据时可能会收到 ICMP 错误报文（例如目标不可达）。如果应用程序没有正确处理这些错误，可能会导致程序行为异常。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 发起网络请求 (Java/Kotlin):**
   - 用户在应用中执行某些操作，触发网络请求，例如使用 `HttpURLConnection` 或 `OkHttp` 发起 HTTP 请求。
   - Framework 可能会使用更高层的 API，例如 `ConnectivityManager` 来检查网络状态。

2. **进入 Native 层 (NDK):**
   - 如果应用需要执行底层的网络操作，例如发送 ICMP 报文，它可以使用 NDK 提供的 Socket API。
   - 例如，一个使用 NDK 编写的 `ping` 工具会直接调用 `socket()`, `sendto()`, `recvfrom()` 等系统调用。

3. **Bionic libc (C 库):**
   - NDK 提供的 Socket API 实际上是 Bionic libc 对 Linux 系统调用的封装。
   - 当调用 `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` 时，Bionic libc 会调用内核的 `socket` 系统调用。
   - 当调用 `sendto()` 发送 ICMP 报文时，Bionic libc 会将构造好的 ICMP 报文传递给内核的 `sendto` 系统调用。

4. **Linux Kernel 网络栈:**
   - 内核接收到 `sendto` 系统调用后，会根据指定的协议 (`IPPROTO_ICMP`) 和目标地址，构造 IP 头部，并将 ICMP 报文数据封装到 IP 数据包中。
   - 当接收到 ICMP 报文时，内核会解析 IP 头部，识别出是 ICMP 协议，然后解析 ICMP 头部，根据 `icmp_type` 和 `icmp_code` 进行相应的处理或将报文传递给相应的进程。

**Frida Hook 示例:**

我们可以使用 Frida hook `sendto` 系统调用，来观察何时发送了 ICMP 报文，并查看 `ip_icmp.h` 中定义的常量是如何被使用的。

```javascript
// hook sendto 系统调用
Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
  onEnter: function (args) {
    const sockfd = args[0].toInt32();
    const buf = args[1];
    const len = args[2].toInt32();
    const flags = args[3].toInt32();
    const dest_addr = args[4];
    const addrlen = args[5].toInt32();

    // 检查 socket 类型是否为 RAW socket 且协议为 ICMP
    const SOL_SOCKET = 1;
    const SO_PROTOCOL = 6;
    const protocol = Memory.alloc(Process.pointerSize);
    var result = recvfrom(sockfd, NULL, 0, MSG_PEEK, NULL, NULL); // 获取 socket 信息，但并不接收数据
    if (result >= 0) {
      const getsockoptPtr = Module.findExportByName("libc.so", "getsockopt");
      const getsockopt = new NativeFunction(getsockoptPtr, 'int', ['int', 'int', 'int', 'pointer', 'pointer']);
      const lenPtr = Memory.alloc(Process.pointerSize);
      lenPtr.writeU32(Process.pointerSize);
      getsockopt(sockfd, SOL_SOCKET, SO_PROTOCOL, protocol, lenPtr);
      if (protocol.readS32() === 1) { // IPPROTO_ICMP 的值通常为 1
        console.log("发送 ICMP 报文:");
        console.log("  Socket FD:", sockfd);
        console.log("  Length:", len);

        // 读取 ICMP 头部
        if (len >= 8) {
          const icmp_type = buf.readU8();
          const icmp_code = buf.add(1).readU8();
          console.log("  ICMP Type:", icmp_type);
          console.log("  ICMP Code:", icmp_code);

          // 可以根据 icmp_type 的值来判断具体的 ICMP 消息类型
          if (icmp_type === 8) { // ICMP_ECHO
            console.log("  这是一个 ICMP 回显请求");
          } else if (icmp_type === 0) { // ICMP_ECHOREPLY
            console.log("  这是一个 ICMP 回显应答");
          } else if (icmp_type === 3) { // ICMP_UNREACH
            console.log("  这是一个 ICMP 目标不可达报文");
          }
          // ... 其他 ICMP 类型
        }
      }
    }
  },
});
```

**解释 Frida Hook 示例:**

1. **`Interceptor.attach`**:  我们 hook 了 `libc.so` 中的 `sendto` 函数。
2. **`onEnter`**:  在 `sendto` 函数被调用时执行。
3. **获取参数**:  我们获取了 `sendto` 函数的各个参数，包括 socket 文件描述符、发送缓冲区、数据长度等。
4. **检查协议**:  我们尝试获取 socket 的协议类型，判断是否为 `IPPROTO_ICMP` (通常值为 1)。
5. **读取 ICMP 头部**: 如果是 ICMP 报文，我们读取缓冲区的前 8 个字节，分别对应 `icmp_type` 和 `icmp_code` 字段。
6. **打印信息**:  我们将读取到的 ICMP 类型和代码打印出来，可以观察到程序发送了哪种类型的 ICMP 报文。

通过这个 Frida hook，我们可以在 Android 设备上运行时动态地观察到哪些程序正在发送 ICMP 报文，以及发送的具体类型，从而验证 `ip_icmp.h` 中定义的常量是如何被实际使用的。

请注意，这个 Frida 示例需要运行在 root 权限的 Android 设备上，并且需要安装 Frida 工具。

### 提示词
```
这是目录为bionic/libc/include/netinet/ip_icmp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: ip_icmp.h,v 1.21 2005/07/31 03:30:55 pascoe Exp $	*/
/*	$NetBSD: ip_icmp.h,v 1.10 1996/02/13 23:42:28 christos Exp $	*/

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
 *	@(#)ip_icmp.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_IP_ICMP_H_
#define _NETINET_IP_ICMP_H_

#include <sys/cdefs.h>

#include <linux/icmp.h>
#include <netinet/ip.h>

__BEGIN_DECLS

/*
 * Interface Control Message Protocol Definitions.
 * Per RFC 792, September 1981.
 * RFC 950, August 1985. (Address Mask Request / Reply)
 * RFC 1256, September 1991. (Router Advertisement and Solicitation)
 * RFC 1108, November 1991. (Param Problem, Missing Req. Option)
 * RFC 1393, January 1993. (Traceroute)
 * RFC 1475, June 1993. (Datagram Conversion Error)
 * RFC 1812, June 1995. (adm prohib, host precedence, precedence cutoff)
 * RFC 2002, October 1996. (Mobility changes to Router Advertisement)
 */

/*
 * ICMP Router Advertisement data
 */
struct icmp_ra_addr {
	uint32_t  ira_addr;
	uint32_t  ira_preference;
};

/*
 * Structure of an icmp header.
 */
struct icmp {
	uint8_t  icmp_type;		/* type of message, see below */
	uint8_t  icmp_code;		/* type sub code */
	uint16_t icmp_cksum;		/* ones complement cksum of struct */
	union {
		uint8_t   ih_pptr;		/* ICMP_PARAMPROB */
		struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
		struct ih_idseq {
			  uint16_t  icd_id;
			  uint16_t  icd_seq;
		} ih_idseq;
		int32_t   ih_void;

		/* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
		struct ih_pmtu {
			  uint16_t  ipm_void;
			  uint16_t  ipm_nextmtu;
		} ih_pmtu;

		struct ih_rtradv {
			uint8_t   irt_num_addrs;
			uint8_t   irt_wpa;
			uint16_t  irt_lifetime;
		} ih_rtradv;
	} icmp_hun;
#define	icmp_pptr	  icmp_hun.ih_pptr
#define	icmp_gwaddr	  icmp_hun.ih_gwaddr
#define	icmp_id		  icmp_hun.ih_idseq.icd_id
#define	icmp_seq	  icmp_hun.ih_idseq.icd_seq
#define	icmp_void	  icmp_hun.ih_void
#define	icmp_pmvoid	  icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	  icmp_hun.ih_pmtu.ipm_nextmtu
#define	icmp_num_addrs	  icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	  icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	  icmp_hun.ih_rtradv.irt_lifetime
	union {
		struct id_ts {
			  uint32_t  its_otime;
			  uint32_t  its_rtime;
			  uint32_t  its_ttime;
		} id_ts;
		struct id_ip  {
			  struct ip idi_ip;
			  /* options and then 64 bits of data */
		} id_ip;
		uint32_t  id_mask;
		int8_t	  id_data[1];
	} icmp_dun;
#define	icmp_otime	  icmp_dun.id_ts.its_otime
#define	icmp_rtime	  icmp_dun.id_ts.its_rtime
#define	icmp_ttime	  icmp_dun.id_ts.its_ttime
#define	icmp_ip		  icmp_dun.id_ip.idi_ip
#define	icmp_mask	  icmp_dun.id_mask
#define	icmp_data	  icmp_dun.id_data
};

/*
 * For IPv6 transition related ICMP errors.
 */
#define	ICMP_V6ADVLENMIN	(8 + sizeof(struct ip) + 40)
#define	ICMP_V6ADVLEN(p)	(8 + ((p)->icmp_ip.ip_hl << 2) + 40)

/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enough to contain the returned ip header.
 * Only then can we do the check to see if 64 bits of packet
 * data have been returned, since we need to check the returned
 * ip header length.
 */
#define	ICMP_MINLEN	8				/* abs minimum */
#define	ICMP_TSLEN	(8 + 3 * sizeof (n_time))	/* timestamp */
#define	ICMP_MASKLEN	12				/* address mask */
#define	ICMP_ADVLENMIN	(8 + sizeof (struct ip) + 8)	/* min */
#define	ICMP_ADVLEN(p)	(8 + ((p)->icmp_ip.ip_hl << 2) + 8)
	/* N.B.: must separately check that ip_hl >= 5 */

/*
 * Definition of type and code field values.
 *	http://www.iana.org/assignments/icmp-parameters
 */
#define	ICMP_ECHOREPLY		0		/* echo reply */
#define	ICMP_UNREACH		3		/* dest unreachable, codes: */
#define	ICMP_UNREACH_NET		0	/* bad net */
#define	ICMP_UNREACH_HOST		1	/* bad host */
#define	ICMP_UNREACH_PROTOCOL		2	/* bad protocol */
#define	ICMP_UNREACH_PORT		3	/* bad port */
#define	ICMP_UNREACH_NEEDFRAG		4	/* IP_DF caused drop */
#define	ICMP_UNREACH_SRCFAIL		5	/* src route failed */
#define	ICMP_UNREACH_NET_UNKNOWN	6	/* unknown net */
#define	ICMP_UNREACH_HOST_UNKNOWN	7	/* unknown host */
#define	ICMP_UNREACH_ISOLATED		8	/* src host isolated */
#define	ICMP_UNREACH_NET_PROHIB		9	/* for crypto devs */
#define	ICMP_UNREACH_HOST_PROHIB	10	/* ditto */
#define	ICMP_UNREACH_TOSNET		11	/* bad tos for net */
#define	ICMP_UNREACH_TOSHOST		12	/* bad tos for host */
#define	ICMP_UNREACH_FILTER_PROHIB	13	/* prohibited access */
#define	ICMP_UNREACH_HOST_PRECEDENCE	14	/* precedence violat'n*/
#define	ICMP_UNREACH_PRECEDENCE_CUTOFF	15	/* precedence cutoff */
#define	ICMP_SOURCEQUENCH	4		/* packet lost, slow down */
#define	ICMP_REDIRECT		5		/* shorter route, codes: */
#define	ICMP_REDIRECT_NET	0		/* for network */
#define	ICMP_REDIRECT_HOST	1		/* for host */
#define	ICMP_REDIRECT_TOSNET	2		/* for tos and net */
#define	ICMP_REDIRECT_TOSHOST	3		/* for tos and host */
#define	ICMP_ALTHOSTADDR	6		/* alternate host address */
#define	ICMP_ECHO		8		/* echo service */
#define	ICMP_ROUTERADVERT	9		/* router advertisement */
#define	ICMP_ROUTERADVERT_NORMAL		0	/* normal advertisement */
#define	ICMP_ROUTERADVERT_NOROUTE_COMMON	16	/* selective routing */
#define	ICMP_ROUTERSOLICIT	10		/* router solicitation */
#define	ICMP_TIMXCEED		11		/* time exceeded, code: */
#define	ICMP_TIMXCEED_INTRANS	0		/* ttl==0 in transit */
#define	ICMP_TIMXCEED_REASS	1		/* ttl==0 in reass */
#define	ICMP_PARAMPROB		12		/* ip header bad */
#define	ICMP_PARAMPROB_ERRATPTR 0		/* req. opt. absent */
#define	ICMP_PARAMPROB_OPTABSENT 1		/* req. opt. absent */
#define	ICMP_PARAMPROB_LENGTH	2		/* bad length */
#define	ICMP_TSTAMP		13		/* timestamp request */
#define	ICMP_TSTAMPREPLY	14		/* timestamp reply */
#define	ICMP_IREQ		15		/* information request */
#define	ICMP_IREQREPLY		16		/* information reply */
#define	ICMP_MASKREQ		17		/* address mask request */
#define	ICMP_MASKREPLY		18		/* address mask reply */
#define	ICMP_TRACEROUTE		30		/* traceroute */
#define	ICMP_DATACONVERR	31		/* data conversion error */
#define	ICMP_MOBILE_REDIRECT	32		/* mobile host redirect */
#define	ICMP_IPV6_WHEREAREYOU	33		/* IPv6 where-are-you */
#define	ICMP_IPV6_IAMHERE	34		/* IPv6 i-am-here */
#define	ICMP_MOBILE_REGREQUEST	35		/* mobile registration req */
#define	ICMP_MOBILE_REGREPLY	36		/* mobile registration reply */
#define	ICMP_SKIP		39		/* SKIP */
#define	ICMP_PHOTURIS		40		/* Photuris */
#define	ICMP_PHOTURIS_UNKNOWN_INDEX	1	/* unknown sec index */
#define	ICMP_PHOTURIS_AUTH_FAILED	2	/* auth failed */
#define	ICMP_PHOTURIS_DECRYPT_FAILED	3	/* decrypt failed */

#define	ICMP_MAXTYPE		40

#define	ICMP_INFOTYPE(type) \
	((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO || \
	(type) == ICMP_ROUTERADVERT || (type) == ICMP_ROUTERSOLICIT || \
	(type) == ICMP_TSTAMP || (type) == ICMP_TSTAMPREPLY || \
	(type) == ICMP_IREQ || (type) == ICMP_IREQREPLY || \
	(type) == ICMP_MASKREQ || (type) == ICMP_MASKREPLY)

__END_DECLS

#endif /* _NETINET_IP_ICMP_H_ */
```