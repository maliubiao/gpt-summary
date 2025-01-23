Response:
Let's break down the thought process for analyzing this C header file.

1. **Understanding the Request:** The core request is to analyze `nameser_compat.h` within the Android Bionic library. The analysis needs to cover its functionality, relationship to Android, libc function details (though it's primarily definitions), dynamic linker aspects, common usage errors, and how Android Framework/NDK reach this code, along with a Frida hook example.

2. **Initial Scan and Identifying Key Areas:**  A quick read reveals the file's purpose: compatibility with an older DNS library (`nameser.h`). It primarily defines structures, constants, and macros. The header comments mention "Berkeley," suggesting a connection to BSD-derived networking code. Keywords like "HEADER," "PACKETSZ," "T_A," "C_IN" immediately point to DNS-related concepts.

3. **Functionality Listing (Broad Strokes):** Based on the initial scan, the file's main functions are:
    * Defining the structure of DNS query headers (`HEADER`).
    * Defining constants related to DNS packet sizes, name lengths, and header sizes.
    * Defining symbolic names for DNS message opcodes (QUERY, UPDATE), response codes (NOERROR, NXDOMAIN), record types (A, NS, MX), and classes (IN).
    * Providing macros for reading and writing short and long integers in network byte order.

4. **Relationship to Android:**  The file resides within Bionic, Android's core C library. This immediately establishes a direct connection. Android apps using networking, especially DNS resolution, will indirectly rely on these definitions. The `getaddrinfo()` function is a prime example of an Android system call that internally utilizes DNS.

5. **Libc Function Details:**  Here's where it's important to be precise. This header file *doesn't define libc functions*. It defines *structures, constants, and macros* that are used *by* libc functions related to DNS. The focus should be on *how these definitions are used*. For instance, `HEADER` is used to interpret the raw bytes of a DNS packet, and constants like `T_A` specify the type of DNS record being requested or received.

6. **Dynamic Linker Aspects:**  This header file itself doesn't directly interact with the dynamic linker. However, *code that uses these definitions* will be part of shared libraries (`.so` files). When an Android app or system service uses DNS-related functions (like those using the definitions in this header), the dynamic linker is responsible for loading the necessary shared libraries (like `libc.so`) into the process's memory. The `so` layout example should reflect a typical `libc.so` structure and how it's linked. The linking process involves resolving symbols – the functions and data defined in these headers are part of that symbol resolution.

7. **Logical Reasoning (Assumptions and Outputs):**  Since the file is mostly definitions, logical reasoning revolves around how these definitions are used. For example, if you have a DNS packet and you access the `qdcount` field of the `HEADER` structure, you're assuming the packet is well-formed according to the DNS protocol and the `HEADER` structure definition. The output would be the number of questions in the DNS query.

8. **Common Usage Errors:**  Mistakes often arise when directly manipulating DNS packets. Incorrectly setting the header fields, using the wrong constants for record types, or misinterpreting the byte order are common pitfalls. Examples should be concrete and illustrate potential problems.

9. **Android Framework/NDK Path and Frida Hook:**  This requires tracing the call stack. Start with a high-level Android API (e.g., `InetAddress.getByName()`). Show how this leads down through Java native methods, then into the NDK, and finally into Bionic's networking functions that would utilize these DNS definitions. A Frida hook example should target a relevant function within Bionic's DNS resolution process (e.g., a function that parses the DNS header or constructs a DNS query) and demonstrate how to inspect the values defined in this header.

10. **Refinement and Structure:**  Organize the information logically with clear headings. Use precise language. For example, instead of saying "the file does DNS," say "the file provides definitions and constants used in DNS operations."  Ensure the examples are illustrative and easy to understand. Use code blocks for the Frida hook example and `so` layout.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file *implements* DNS functionality." **Correction:** This file *defines structures and constants* used in DNS implementation. The actual implementation is in other C files within Bionic.
* **Initial thought:** Focus heavily on individual libc function implementation. **Correction:** The file doesn't define functions. Shift focus to how the *definitions* are used by libc functions.
* **Initial thought:**  Overcomplicate the dynamic linker section. **Correction:** Keep it focused on the basics: the role of the dynamic linker in loading `libc.so` and resolving symbols related to these definitions.
* **Ensure clarity in examples:**  Make sure the Frida hook targets a concrete function and the `so` layout is representative.

By following this structured approach and engaging in self-correction, we can produce a comprehensive and accurate analysis of the provided header file.
这个文件 `bionic/libc/include/arpa/nameser_compat.h` 是 Android Bionic 库中的一个头文件，其主要目的是为了提供与早期 DNS (Domain Name System) 库 `nameser.h` 的兼容性。  它定义了一些结构体、常量和宏，这些结构体、常量和宏用于处理 DNS 协议中的数据包和消息。

**功能列举:**

1. **定义 DNS 消息头结构体 `HEADER`:** 描述了 DNS 查询和响应消息头的格式，包括各种标志位（如递归期望、截断标志、权威应答等）、操作码、返回码以及各个数据段的计数（问题数、答案数、权威记录数、附加记录数）。
2. **定义与 DNS 数据包大小相关的常量:**  例如 `PACKETSZ` (最大数据包大小), `MAXDNAME` (最大域名长度) 等。
3. **定义 DNS 消息头和各个部分的固定大小常量:** 例如 `HFIXEDSZ` (头部固定大小), `QFIXEDSZ` (问题部分固定大小), `RRFIXEDSZ` (资源记录部分固定大小)。
4. **定义与数据类型大小相关的常量:** 例如 `INT32SZ`, `INT16SZ`, `INT8SZ`，用于处理 DNS 数据包中的不同大小的数据。
5. **定义 IP 地址大小常量:** 例如 `INADDRSZ` (IPv4 地址大小), `IN6ADDRSZ` (IPv6 地址大小)。
6. **定义 DNS 操作码常量:**  例如 `QUERY` (查询), `IQUERY` (反向查询), `STATUS` (状态查询), `NS_UPDATE_OP` (更新操作) 等。
7. **定义 DNS 返回码常量:** 例如 `NOERROR` (无错误), `FORMERR` (格式错误), `SERVFAIL` (服务器失败), `NXDOMAIN` (域名不存在) 等。
8. **定义 DNS 更新操作码常量:** 例如 `DELETE` (删除), `ADD` (添加)。
9. **定义 DNS 记录类型常量:**  例如 `T_A` (IPv4 地址记录), `T_NS` (域名服务器记录), `T_MX` (邮件交换记录), `T_CNAME` (别名记录) 等，涵盖了常见的 DNS 记录类型。
10. **定义 DNS 类常量:** 例如 `C_IN` (Internet 类), `C_CHAOS`, `C_HS` 等。
11. **定义字节序转换宏:** 例如 `GETSHORT`, `GETLONG`, `PUTSHORT`, `PUTLONG`，用于在主机字节序和网络字节序之间转换 16 位和 32 位整数。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 系统进行网络域名解析的基础。Android 应用程序需要将域名转换为 IP 地址才能建立网络连接。Bionic 库中的网络相关函数（例如 `getaddrinfo`）会使用这里定义的结构体和常量来构建和解析 DNS 查询和响应。

**举例说明:**

当一个 Android 应用尝试连接到 `www.google.com` 时，系统会调用 `getaddrinfo` 函数。`getaddrinfo` 函数内部会构建一个 DNS 查询数据包，这个数据包的头部结构就由 `HEADER` 结构体定义。例如，设置 `rd` 标志位表示期望进行递归查询，设置 `qdcount` 表示查询的问题数量，设置相应的查询类型（例如 `T_A` 获取 IPv4 地址）。接收到 DNS 服务器的响应后，同样会使用 `HEADER` 结构体来解析响应头，获取返回码 (`rcode`)，答案数量 (`ancount`) 等信息，并进一步解析答案部分获取 IP 地址。

**libc 函数的功能实现 (本文件主要是定义，实际实现位于其他源文件):**

这个头文件本身并不包含 libc 函数的实现代码，它只是定义了数据结构和常量。使用这些定义来实现 DNS 相关功能的 libc 函数通常位于 Bionic 库的 `libc.so` 中，例如：

* **`res_send()` / `__res_send()`:**  发送 DNS 查询数据包。这个函数会使用 `HEADER` 结构体构建查询头，并根据查询类型和域名构建查询部分。`PACKETSZ` 等常量会限制数据包的大小。
* **`res_query()` / `__res_query()`:** 执行 DNS 查询的更高级接口，内部会调用 `res_send()` 并处理响应。
* **`dn_expand()`:**  用于解压缩 DNS 数据包中的域名，域名可能以压缩格式存储。
* **`ns_initparse()` / `ns_parserr()`:** 用于解析 DNS 响应数据包。这些函数会读取数据包并根据 `HEADER` 中的信息定位到答案、权威记录和附加记录部分，然后根据记录类型解析记录的具体内容（例如，对于 `T_A` 记录，解析出 IPv4 地址）。
* **字节序转换函数 (例如 `htons`, `htonl`, `ntohs`, `ntohl`)：** 虽然这里定义了 `GETSHORT`/`PUTSHORT` 等宏，但实际的字节序转换通常由 `<netinet/in.h>` 或 `<sys/socket.h>` 中定义的函数完成。这些宏是对这些底层函数的封装或别名，确保跨平台兼容性。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`nameser_compat.h` 本身不直接涉及 dynamic linker 的功能，但它定义的结构体和常量会被编译到使用 DNS 功能的共享库中，例如 `libc.so`。

**`libc.so` 布局样本 (简化):**

```
libc.so:
  .text:  (代码段，包含 res_send, res_query 等函数的指令)
    res_send:
      ; ... 使用 HEADER 结构体和相关常量 ...
      ; ... 调用系统调用发送数据包 ...
    res_query:
      ; ... 调用 res_send ...
      ; ... 处理接收到的数据 ...
  .rodata: (只读数据段，可能包含一些 DNS 相关的常量字符串)
    _dns_server_address:  "8.8.8.8"  ; 示例 DNS 服务器地址
  .data:   (可读写数据段，可能包含一些全局变量)
    _res:  ; res_state 结构体实例，用于 DNS 配置
  .dynsym: (动态符号表，包含导出的函数和变量)
    res_send
    res_query
    ; ... 其他导出的符号 ...
  .dynstr: (动态字符串表，包含符号名)
    res_send
    res_query
    ; ... 其他符号名 ...
  .rel.dyn: (动态重定位表，用于在加载时修正地址)
    ; ... 可能包含对其他库的引用的重定位信息 ...
```

**链接的处理过程:**

1. **编译时:**  当编译使用 DNS 相关函数的代码时，编译器会查找 `nameser_compat.h` 中定义的结构体和常量。
2. **链接时:**  链接器会将编译后的目标文件链接成共享库 (`libc.so`) 或可执行文件。如果代码中使用了 `res_send` 等函数，链接器会在 `libc.so` 的动态符号表中找到这些符号的定义。
3. **运行时 (Dynamic Linker):**
   * 当一个应用程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序依赖的共享库，例如 `libc.so`。
   * Dynamic linker 会解析 `libc.so` 的动态段信息，包括 `.dynsym`, `.dynstr`, 和 `.rel.dyn`。
   * 如果应用程序调用了 `res_send` 函数，dynamic linker 会在 `libc.so` 的符号表中找到 `res_send` 的地址，并将其填入应用程序的 GOT (Global Offset Table) 或 PLT (Procedure Linkage Table) 中。
   * 当应用程序第一次调用 `res_send` 时，会通过 PLT 跳转到 dynamic linker 提供的桩代码，dynamic linker 会完成符号解析，将 `res_send` 的实际地址写入 GOT 表项，后续的调用将直接通过 GOT 表跳转到 `res_send` 的实现代码。
   * 在 `res_send` 的实现中，会使用 `nameser_compat.h` 中定义的 `HEADER` 结构体和常量来构建 DNS 数据包。

**假设输入与输出 (逻辑推理):**

假设有一个程序想要查询 `www.example.com` 的 A 记录。

**假设输入:**

* 目标域名: `www.example.com`
* 查询类型: `T_A` (IPv4 地址)
* 使用 `res_query()` 函数发起查询。

**逻辑推理过程 (简化):**

1. `res_query()` 内部调用 `res_send()` 构建 DNS 查询数据包。
2. `res_send()` 使用 `HEADER` 结构体构建包头：
   * 设置 `qr` 为 0 (表示查询)。
   * 设置 `opcode` 为 `QUERY`。
   * 设置 `rd` 为 1 (期望递归)。
   * 设置 `qdcount` 为 1 (一个问题)。
   * 其他字段根据需要设置。
3. `res_send()` 构建查询部分，包含 `www.example.com` 和 `T_A` 类型，以及 `C_IN` 类。
4. 数据包通过网络发送到配置的 DNS 服务器。
5. 接收到 DNS 服务器的响应数据包。
6. `res_query()` 或其内部调用的函数使用 `HEADER` 结构体解析响应头，检查 `rcode` 判断是否成功。
7. 如果 `rcode` 为 `NOERROR`，则解析答案部分，根据 `T_A` 类型解析出 IPv4 地址。

**假设输出:**

* 如果查询成功，则输出 `www.example.com` 的 IPv4 地址 (例如: `93.184.216.34`)。
* 如果查询失败 (例如，域名不存在)，则输出相应的错误码 (例如，`NXDOMAIN`)。

**用户或编程常见的使用错误:**

1. **字节序错误:**  在手动构建或解析 DNS 数据包时，如果没有正确使用 `htons`, `htonl`, `ntohs`, `ntohl` 等函数进行字节序转换，会导致数据包格式错误，无法被 DNS 服务器正确解析，或者解析出的结果不正确。

   ```c
   // 错误示例：直接赋值，没有考虑字节序
   HEADER header;
   header.id = 0x1234; // 应该使用 htons(0x1234)
   ```

2. **常量使用错误:**  使用错误的 DNS 类型或类常量，导致查询或解析错误。

   ```c
   // 错误示例：错误地使用 TXT 记录类型查询 A 记录
   res_query(hostname, C_IN, T_TXT, buffer, sizeof(buffer));
   ```

3. **缓冲区溢出:**  在处理 DNS 响应时，如果没有正确检查数据包长度和缓冲区大小，可能会发生缓冲区溢出。

   ```c
   // 危险示例：假设 name 指向 DNS 响应中的域名，没有检查长度
   char name_buffer[64];
   strcpy(name_buffer, name); // 如果域名长度超过 63，会发生溢出
   ```

4. **错误处理不足:**  没有充分检查 DNS 查询的返回值和错误码，可能导致程序在 DNS 查询失败时出现未预期的行为。

   ```c
   int result = res_query(hostname, C_IN, T_A, buffer, sizeof(buffer));
   // 应该检查 result 的值，判断查询是否成功
   if (result < 0) {
       perror("DNS query failed");
   }
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework:** 当一个 Java 应用需要解析域名时，它通常会使用 `java.net.InetAddress` 类的方法，例如 `getByName()`。

   ```java
   InetAddress address = InetAddress.getByName("www.google.com");
   ```

2. **Java Native Interface (JNI):** `InetAddress.getByName()` 是一个 native 方法，其实现位于 Android 平台的本地代码中。

3. **NDK (Native Development Kit):**  在 Android 平台的本地代码中，会调用 Bionic 库提供的网络相关函数。`libnativehelper.so` 和 `libnetd_client.so` 等库会参与域名解析过程。

4. **Bionic libc:** 最终，会调用 Bionic 库中的 DNS 解析函数，例如 `android_getaddrinfo()`（Android 特定的 `getaddrinfo` 实现）或底层的 `res_query()` / `res_send()`。这些函数会使用 `arpa/nameser_compat.h` 中定义的结构体和常量。

**Frida Hook 示例:**

可以使用 Frida hook Bionic 库中的 `res_send` 函数，查看 DNS 查询数据包的头部信息。

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__res_send"), {
    onEnter: function(args) {
        // args[0] 是 res_state 结构体指针
        // args[1] 是要发送的 DNS 数据包的指针
        // args[2] 是数据包的长度

        var packetPtr = ptr(args[1]);
        var packetLength = args[2].toInt();

        if (packetLength >= 12) { // 至少是 HEADER 的大小
            var headerBuf = packetPtr.readByteArray(12);
            var header = {
                id: headerBuf.readU16(),
                rd: (headerBuf[2] >> 0) & 1,
                tc: (headerBuf[2] >> 1) & 1,
                aa: (headerBuf[2] >> 2) & 1,
                opcode: (headerBuf[2] >> 3) & 0xF,
                qr: (headerBuf[2] >> 7) & 1,
                rcode: headerBuf[3] & 0xF,
                // ... 其他字段 ...
            };
            send({type: "send", payload: "DNS Query Header: " + JSON.stringify(header)});
        } else {
            send({type: "send", payload: "DNS Packet too short"});
        }
    },
    onLeave: function(retval) {
        // console.log("res_send returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 调试步骤:**

1. **准备环境:**  确保安装了 Frida 和 Python，并且 Android 设备或模拟器已连接并启用了 USB 调试。
2. **找到目标进程:**  将 `your.app.package.name` 替换为你要调试的应用程序的包名。运行该应用程序。
3. **运行 Frida 脚本:**  运行上面的 Python 脚本。
4. **触发 DNS 查询:**  在目标应用程序中触发一个需要进行域名解析的操作，例如访问一个网页或连接到服务器。
5. **查看 Frida 输出:**  Frida 脚本会 hook `__res_send` 函数，并在每次发送 DNS 查询时打印出解析出的 DNS 头部信息，例如 ID、标志位、操作码等。这可以帮助你理解 Android 系统是如何构建 DNS 查询数据包的。

这个 `nameser_compat.h` 文件虽然本身不包含复杂的逻辑，但它是 Android 系统进行域名解析的关键基础，为上层网络功能的实现提供了必要的数据结构和常量定义。理解它的内容有助于深入了解 Android 的网络层工作原理。

### 提示词
```
这是目录为bionic/libc/include/arpa/nameser_compat.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: nameser_compat.h,v 1.1.1.2 2004/11/07 01:28:27 christos Exp $	*/

/* Copyright (c) 1983, 1989
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 */

/*
 *      from nameser.h	8.1 (Berkeley) 6/2/93
 *	Id: nameser_compat.h,v 1.8 2006/05/19 02:33:40 marka Exp
 */

#ifndef _ARPA_NAMESER_COMPAT_
#define	_ARPA_NAMESER_COMPAT_

#include <sys/cdefs.h>

#include <endian.h>

#define	__BIND		19950621	/* (DEAD) interface version stamp. */

/*
 * Structure for query header.  The order of the fields is machine- and
 * compiler-dependent, depending on the byte/bit order and the layout
 * of bit fields.  We use bit fields only in int variables, as this
 * is all ANSI requires.  This requires a somewhat confusing rearrangement.
 */

typedef struct {
	unsigned	id :16;		/* query identification number */
			/* fields in third byte */
	unsigned	rd :1;		/* recursion desired */
	unsigned	tc :1;		/* truncated message */
	unsigned	aa :1;		/* authoritive answer */
	unsigned	opcode :4;	/* purpose of message */
	unsigned	qr :1;		/* response flag */
			/* fields in fourth byte */
	unsigned	rcode :4;	/* response code */
	unsigned	cd: 1;		/* checking disabled by resolver */
	unsigned	ad: 1;		/* authentic data from named */
	unsigned	unused :1;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	ra :1;		/* recursion available */
			/* remaining bytes */
	unsigned	qdcount :16;	/* number of question entries */
	unsigned	ancount :16;	/* number of answer entries */
	unsigned	nscount :16;	/* number of authority entries */
	unsigned	arcount :16;	/* number of resource entries */
} HEADER;

#define PACKETSZ	NS_PACKETSZ
#define MAXDNAME	NS_MAXDNAME
#define MAXCDNAME	NS_MAXCDNAME
#define MAXLABEL	NS_MAXLABEL
#define	HFIXEDSZ	NS_HFIXEDSZ
#define QFIXEDSZ	NS_QFIXEDSZ
#define RRFIXEDSZ	NS_RRFIXEDSZ
#define	INT32SZ		NS_INT32SZ
#define	INT16SZ		NS_INT16SZ
#define	INT8SZ		NS_INT8SZ
#define	INADDRSZ	NS_INADDRSZ
#define	IN6ADDRSZ	NS_IN6ADDRSZ
#define	INDIR_MASK	NS_CMPRSFLGS
#define NAMESERVER_PORT	NS_DEFAULTPORT

#define S_ZONE		ns_s_zn
#define S_PREREQ	ns_s_pr
#define S_UPDATE	ns_s_ud
#define S_ADDT		ns_s_ar

#define QUERY		ns_o_query
#define IQUERY		ns_o_iquery
#define STATUS		ns_o_status
#define	NS_NOTIFY_OP	ns_o_notify
#define	NS_UPDATE_OP	ns_o_update

#define NOERROR		ns_r_noerror
#define FORMERR		ns_r_formerr
#define SERVFAIL	ns_r_servfail
#define NXDOMAIN	ns_r_nxdomain
#define NOTIMP		ns_r_notimpl
#define REFUSED		ns_r_refused
#define YXDOMAIN	ns_r_yxdomain
#define YXRRSET		ns_r_yxrrset
#define NXRRSET		ns_r_nxrrset
#define NOTAUTH		ns_r_notauth
#define NOTZONE		ns_r_notzone
/*#define BADSIG		ns_r_badsig*/
/*#define BADKEY		ns_r_badkey*/
/*#define BADTIME		ns_r_badtime*/


#define DELETE		ns_uop_delete
#define ADD		ns_uop_add

#define T_A		ns_t_a
#define T_NS		ns_t_ns
#define T_MD		ns_t_md
#define T_MF		ns_t_mf
#define T_CNAME		ns_t_cname
#define T_SOA		ns_t_soa
#define T_MB		ns_t_mb
#define T_MG		ns_t_mg
#define T_MR		ns_t_mr
#define T_NULL		ns_t_null
#define T_WKS		ns_t_wks
#define T_PTR		ns_t_ptr
#define T_HINFO		ns_t_hinfo
#define T_MINFO		ns_t_minfo
#define T_MX		ns_t_mx
#define T_TXT		ns_t_txt
#define	T_RP		ns_t_rp
#define T_AFSDB		ns_t_afsdb
#define T_X25		ns_t_x25
#define T_ISDN		ns_t_isdn
#define T_RT		ns_t_rt
#define T_NSAP		ns_t_nsap
#define T_NSAP_PTR	ns_t_nsap_ptr
#define	T_SIG		ns_t_sig
#define	T_KEY		ns_t_key
#define	T_PX		ns_t_px
#define	T_GPOS		ns_t_gpos
#define	T_AAAA		ns_t_aaaa
#define	T_LOC		ns_t_loc
#define	T_NXT		ns_t_nxt
#define	T_EID		ns_t_eid
#define	T_NIMLOC	ns_t_nimloc
#define	T_SRV		ns_t_srv
#define T_ATMA		ns_t_atma
#define T_NAPTR		ns_t_naptr
#define T_A6		ns_t_a6
#define	T_TSIG		ns_t_tsig
#define	T_IXFR		ns_t_ixfr
#define T_AXFR		ns_t_axfr
#define T_MAILB		ns_t_mailb
#define T_MAILA		ns_t_maila
#define T_ANY		ns_t_any

#define C_IN		ns_c_in
#define C_CHAOS		ns_c_chaos
#define C_HS		ns_c_hs
/* BIND_UPDATE */
#define C_NONE		ns_c_none
#define C_ANY		ns_c_any

#define	GETSHORT		NS_GET16
#define	GETLONG			NS_GET32
#define	PUTSHORT		NS_PUT16
#define	PUTLONG			NS_PUT32

#endif /* _ARPA_NAMESER_COMPAT_ */
```