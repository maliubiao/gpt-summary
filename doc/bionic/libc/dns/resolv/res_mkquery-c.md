Response:
Let's break down the thought process for analyzing the `res_mkquery.c` file.

1. **Understand the Goal:** The request asks for a comprehensive explanation of the `res_mkquery.c` file in Android's Bionic library. This includes functionality, Android relevance, libc function details, dynamic linking aspects, example usage, error scenarios, and how the code is reached from higher layers.

2. **Initial Scan and Keyword Identification:**  First, I'd quickly scan the code and identify key function names (`res_nmkquery`, `res_nopt`), included headers (`sys/types.h`, `netinet/in.h`, `arpa/nameser.h`, `netdb.h`, `resolv.h`, `stdio.h`, `string.h`), and prominent concepts (DNS queries, opcodes, classes, types, resource records, EDNS0). The copyright notices also give context about its origins (Berkeley, Digital Equipment, ISC).

3. **Identify the Core Function: `res_nmkquery`:**  The name itself suggests "make query." The function signature confirms this: it takes information needed to construct a DNS query (opcode, domain name, class, type, data) and populates a buffer.

4. **Deconstruct `res_nmkquery`:**  Go through the function step-by-step:
    * **Purpose:** Creates a DNS query message.
    * **Input Parameters:**  Understand the role of each parameter (`res_state`, `op`, `dname`, `class`, `type`, `data`, `datalen`, `newrr_in`, `buf`, `buflen`). Pay attention to the `res_state` which likely holds resolver configuration.
    * **Header Initialization:**  Note how the DNS header is constructed (`HEADER` struct, setting `id`, `opcode`, `rd`, `ad`, `rcode`). Realize this is the standard DNS header format.
    * **Opcode Handling (Switch Statement):** This is crucial. Focus on the `QUERY` and `IQUERY` cases as these are the most common. Understand how the question section (domain name, type, class) is constructed using `dn_comp` and `ns_put16`. For `IQUERY`, note the different structure for inverse queries. The `NS_NOTIFY_OP` is less common but still present.
    * **Return Value:**  The function returns the size of the generated query or -1 on error.

5. **Identify the Secondary Function: `res_nopt`:** The name suggests "network options" or "OPT record."  The code and comments clearly indicate this is for adding the EDNS0 OPT record to a DNS query, as defined in RFC 2671.

6. **Deconstruct `res_nopt`:**
    * **Purpose:** Adds an EDNS0 OPT record.
    * **Input Parameters:**  Understand the role of `statp`, `n0` (current offset), `buf`, `buflen`, and `anslen` (intended answer size).
    * **OPT Record Construction:**  Note the hardcoded `T_OPT` type, the setting of the UDP payload size (`anslen`), the handling of DNSSEC-OK, and the optional padding.
    * **Header Update:** The `arcount` (additional record count) in the DNS header is incremented.

7. **Connect to Android:**
    * **Bionic Library:** Emphasize that this code is part of Android's standard C library, making it fundamental to networking on Android.
    * **DNS Resolution:** Explain how `res_mkquery` is a key component in the process of resolving domain names to IP addresses. Higher-level Android APIs use this indirectly.
    * **Examples:**  Provide concrete examples like a browser resolving a website or an app connecting to a server.

8. **Explain Libc Functions:**  Focus on the non-obvious functions:
    * **`dn_comp`:**  Crucial for compressing domain names, saving space in DNS packets. Explain the pointer compression mechanism.
    * **`ns_put16`, `ns_put32`:**  Simple functions for writing network byte order integers. Explain why network byte order is important.
    * **`htons`:** Host-to-network short (for the header fields).
    * **`memset`, `memcpy`:** Standard memory manipulation.
    * **`res_randomid`:** Explain its role in associating requests and responses.

9. **Address Dynamic Linking (Less Directly Involved):** While `res_mkquery.c` itself doesn't *directly* perform dynamic linking, it's part of `libc.so`, which *is* dynamically linked.
    * **SO Layout Example:** Provide a simplified example of how `libc.so` might be structured.
    * **Linking Process:** Explain the basic linking steps (symbol resolution, relocation).

10. **Provide Logic Examples (Hypothetical):** Create simple input scenarios and predict the output DNS query structure (header, question section). This helps illustrate the function's behavior.

11. **Illustrate Common Errors:**  Think about what could go wrong: buffer overflow (`buflen` too small), invalid input (`dname`), etc.

12. **Trace the Call Path (Android Framework/NDK):** This requires understanding Android's networking stack.
    * **High-Level APIs:** Start with user-facing APIs like `InetAddress.getByName()` in Java or `getaddrinfo()` in native code.
    * **System Services:** Mention `netd` (the network daemon) as a key intermediary.
    * **Bionic Resolver:** Explain how `netd` ultimately calls functions within `libc.so`, including `res_mkquery`.

13. **Frida Hook Example:**  Provide a practical Frida script to intercept `res_nmkquery` calls and log the arguments. This demonstrates how to debug and observe this code in action.

14. **Structure and Language:** Organize the information logically with clear headings. Use precise language and avoid jargon where possible, but explain technical terms when necessary. Use Chinese as requested.

15. **Review and Refine:** After drafting the response, review it for accuracy, completeness, and clarity. Ensure all parts of the original request have been addressed. For instance, double-check that libc function explanations are accurate and the Frida example is functional.

By following this systematic approach, we can construct a comprehensive and informative answer to the request. The key is to break down the problem, understand the core functionality, connect it to the broader Android context, and provide concrete examples and debugging techniques.
好的，让我们详细分析一下 `bionic/libc/dns/resolv/res_mkquery.c` 这个文件。

**功能概述**

`res_mkquery.c` 文件包含了用于构造 DNS 查询报文的核心函数 `res_nmkquery` 以及相关的辅助函数（如 `res_nopt`，用于添加 EDNS0 选项）。其主要功能是：

1. **构建 DNS 查询消息：**  根据传入的参数（如域名、查询类型、查询类等），创建一个符合 DNS 协议格式的查询报文，以便发送给 DNS 服务器。
2. **处理不同类型的查询：** 支持标准的 `QUERY` 查询，也支持逆向查询 `IQUERY` 以及 DNS NOTIFY 操作。
3. **添加 EDNS0 支持：**  通过 `res_nopt` 函数，可以向 DNS 查询报文中添加 EDNS0 (Extension Mechanisms for DNS) 选项，用于支持更大的 UDP 报文、DNSSEC 等扩展功能。

**与 Android 功能的关系及举例**

`res_mkquery.c` 是 Android Bionic C 库的一部分，因此它直接关系到 Android 设备上的网络功能，特别是域名解析。

**举例说明：**

* **应用程序访问网络：** 当 Android 应用程序需要访问一个网站，例如 `www.google.com`，它会使用底层的网络 API。这些 API 最终会调用 Bionic 库中的域名解析函数。`res_mkquery` 就是在这个过程中被调用的关键函数之一，它负责生成向 DNS 服务器查询 `www.google.com` IP 地址的 DNS 查询报文。
* **网络连接建立：**  在建立 TCP 或 UDP 连接时，如果目标地址是域名而不是 IP 地址，系统需要先进行域名解析。`res_mkquery` 在此过程中生成 DNS 查询报文，以便获取目标域名对应的 IP 地址。
* **系统服务：** Android 系统的一些核心服务，如 `netd` (网络守护进程)，也依赖 Bionic 库进行域名解析。`res_mkquery` 在这些服务执行域名解析任务时扮演着重要角色。

**Libc 函数功能详解**

以下是 `res_mkquery.c` 中使用到的一些关键 libc 函数的解释：

1. **`memset(void *s, int c, size_t n)`:**
   * **功能：** 将 `s` 指向的内存块的前 `n` 个字节设置为 `c` 的值。
   * **实现：**  通常是通过一个优化的循环来实现，逐字节或者以更大的单位（如字、双字）填充内存。
   * **在 `res_mkquery.c` 中的应用：**  在 `res_nmkquery` 函数开始时，用于初始化 DNS 查询报文头部 `buf` 的前 `HFIXEDSZ` (DNS 头部固定大小) 个字节为 0。

2. **`htons(uint16_t hostshort)`:**
   * **功能：** 将主机字节序的 16 位无符号整数转换为网络字节序。网络字节序通常是大端字节序。
   * **实现：**  检查当前系统的字节序，如果与网络字节序不同，则交换高低字节。
   * **在 `res_mkquery.c` 中的应用：**  用于设置 DNS 报文头部中的 `id`、`qdcount` 和 `arcount` 等字段，确保它们在网络传输中以正确的字节顺序被解析。

3. **`memcpy(void *dest, const void *src, size_t n)`:**
   * **功能：** 将 `src` 指向的内存块的前 `n` 个字节复制到 `dest` 指向的内存块。
   * **实现：**  通常是通过一个优化的循环来实现，逐字节或者以更大的单位复制内存。需要注意源地址和目标地址不能重叠。
   * **在 `res_mkquery.c` 中的应用：**  在 `IQUERY` 查询类型中，如果提供了数据 `data`，则使用 `memcpy` 将数据复制到查询报文中。

4. **`dn_comp(const char *exp, u_char *comp_dn, int size, u_char **dnptrs, u_char **lastdnptr)`:**
   * **功能：** 将域名 `exp` 压缩成 DNS 报文所使用的压缩格式。域名压缩通过使用指针指向之前出现过的相同域名部分来节省空间。
   * **实现：**
      * 它会遍历域名 `exp` 的各个部分（由点分隔）。
      * 对于每个部分，它会在 `dnptrs` 指向的指针数组中查找是否已经存在相同的域名部分。
      * 如果找到，就在 `comp_dn` 中写入一个指向已存在部分的指针（以 `0xc0` 开头的两个字节）。
      * 如果找不到，就将当前域名部分写入 `comp_dn`，并在 `dnptrs` 中记录当前位置，以便后续的域名部分可以引用。
      * `size` 参数限制了写入 `comp_dn` 的最大长度。
      * `dnptrs` 和 `lastdnptr` 用于维护已压缩域名的指针列表，以便进行回溯和压缩。
   * **在 `res_mkquery.c` 中的应用：**  在 `QUERY` 和 `NS_NOTIFY_OP` 查询类型中，用于将要查询的域名 `dname` 压缩后写入 DNS 查询报文。

5. **`ns_put16(uint16_t s, u_char *cp)` 和 `ns_put32(uint32_t l, u_char *cp)`:**
   * **功能：** 将 16 位或 32 位的主机字节序整数转换为网络字节序，并将结果写入到 `cp` 指向的内存位置。
   * **实现：**  这两个函数通常会调用 `htons` 和 `htonl` 来进行字节序转换，然后将转换后的值写入内存。
   * **在 `res_mkquery.c` 中的应用：** 用于将查询类型 (`type`)、查询类 (`class`)、资源记录的 TTL 和数据长度等字段以网络字节序写入 DNS 查询报文。

6. **`res_randomid()`:**
   * **功能：** 生成一个随机的 16 位 ID，用于标识 DNS 查询。
   * **实现：**  可能使用伪随机数生成器，并需要保证在短时间内生成的 ID 不重复，以避免响应混淆。
   * **在 `res_mkquery.c` 中的应用：**  生成的 ID 被设置到 DNS 报文头部的 `id` 字段中，用于将 DNS 响应与发出的查询进行匹配。

**涉及 Dynamic Linker 的功能**

`res_mkquery.c` 的代码本身并不直接涉及 dynamic linker 的操作。但是，作为 `libc.so` 的一部分，`res_mkquery` 函数的加载和链接是由 dynamic linker 完成的。

**SO 布局样本：**

```
libc.so:
    ...
    .text:  # 代码段
        ...
        res_nmkquery:  # res_mkquery 函数的代码
            ...
        dn_comp:      # dn_comp 函数的代码
            ...
        ...
    .data:  # 初始化数据段
        ...
        _res_opcodes: # 存储操作码字符串的数组
            ...
    .bss:   # 未初始化数据段
        ...
    .dynsym: # 动态符号表
        res_nmkquery
        dn_comp
        ...
    .dynstr: # 动态字符串表
        res_nmkquery
        dn_comp
        ...
    .plt:   # 程序链接表（Procedure Linkage Table）
        ...
    .got:   # 全局偏移表（Global Offset Table）
        ...
    ...
```

**链接的处理过程：**

1. **加载 `libc.so`：** 当一个应用程序启动时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会根据应用程序的依赖关系加载所需的共享库，包括 `libc.so`。
2. **符号解析：** dynamic linker 会解析 `libc.so` 的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)，找到 `res_nmkquery` 等函数的地址。
3. **重定位：** 由于共享库的加载地址在运行时才能确定，dynamic linker 需要修改代码和数据段中涉及绝对地址引用的部分，使其指向正确的运行时地址。这涉及到使用全局偏移表 (`.got`) 和程序链接表 (`.plt`)。
4. **调用 `res_nmkquery`：** 当应用程序中的代码需要进行 DNS 查询时，它会调用 Bionic 库提供的域名解析函数（例如 `getaddrinfo`）。这些高层函数最终会调用到 `res_nmkquery`。由于 `res_nmkquery` 已经通过 dynamic linker 加载并链接，程序可以直接跳转到其在内存中的实际地址执行。

**逻辑推理：假设输入与输出**

假设输入：

* `op`: `QUERY` (标准查询)
* `dname`: `www.example.com`
* `class`: `C_IN` (Internet 类)
* `type`: `T_A` (A 记录，即 IPv4 地址)
* `buf`: 指向一个足够大的缓冲区
* `buflen`: 缓冲区大小

输出（假设缓冲区足够大）：

`buf` 中会填充一个 DNS 查询报文，其结构如下：

```
Header:
  ID: 随机值 (例如 0x1234)
  Flags: 0x0100 (标准查询，期望递归)
  QDCOUNT: 0x0001 (一个问题)
  ANCOUNT: 0x0000
  NSCOUNT: 0x0000
  ARCOUNT: 0x0000

Question Section:
  QNAME: \x03www\x07example\x03com\x00  (压缩后的域名)
  QTYPE: 0x0001 (A 记录)
  QCLASS: 0x0001 (Internet 类)
```

**用户或编程常见的使用错误**

1. **缓冲区溢出：**  `buflen` 参数太小，无法容纳生成的 DNS 查询报文，导致内存溢出。
   * **示例：**  如果 `dname` 非常长，生成的压缩域名也会很长，如果 `buflen` 设置得过小，`dn_comp` 可能会写入超出缓冲区边界的数据。

2. **错误的参数：**  传递了无效的 `op`、`class` 或 `type` 值。
   * **示例：** 使用了未定义的查询类型或类。

3. **未初始化的 `res_state` 结构体：**  `res_nmkquery` 的第一个参数 `statp` 是一个指向 `res_state` 结构体的指针，该结构体包含了解析器的状态信息。如果该结构体未正确初始化，可能会导致不可预测的行为。

4. **在多线程环境中使用未加锁的 `res_state`：** `res_state` 结构体可能包含一些全局状态，在多线程环境下不加锁地访问和修改可能会导致竞争条件。

**Android Framework 或 NDK 如何一步步到达这里**

1. **应用程序发起网络请求：**  无论是 Java 代码 (Android Framework) 还是 C/C++ 代码 (NDK)，应用程序都会通过高层 API 发起网络请求，例如：
   * **Java (Android Framework):** `java.net.InetAddress.getByName("www.example.com")`, `android.webkit.WebView` 加载网页, `OkHttp` 或 `URLConnection` 进行网络请求。
   * **NDK:** `getaddrinfo("www.example.com", "80", hints, &result)`。

2. **系统服务处理域名解析：**  这些高层 API 通常会将域名解析的任务委托给系统服务，最常见的是 `netd` (网络守护进程)。

3. **`netd` 调用 Bionic 库函数：** `netd` 进程会调用 Bionic 库提供的域名解析函数，例如 `android_getaddrinfo` 或底层的 `res_query` 等。

4. **`res_query` 或类似函数调用 `res_nmkquery`：**  `res_query` 函数负责执行 DNS 查询的整个流程，包括构造查询报文、发送报文、接收响应等。在构造查询报文阶段，`res_query` 会调用 `res_nmkquery` 来生成实际的 DNS 查询数据。

**Frida Hook 示例调试步骤**

可以使用 Frida Hook 来拦截 `res_nmkquery` 函数的调用，查看其参数和返回值，从而调试域名解析过程。

**Frida Hook 脚本示例 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const res_nmkquery = Module.findExportByName("libc.so", "res_nmkquery");
  if (res_nmkquery) {
    Interceptor.attach(res_nmkquery, {
      onEnter: function (args) {
        const op = args[1].toInt32();
        const dname = Memory.readCString(args[2]);
        const qclass = args[3].toInt32();
        const qtype = args[4].toInt32();

        console.log("res_nmkquery called with:");
        console.log("  Opcode:", op);
        console.log("  Domain Name:", dname);
        console.log("  Class:", qclass);
        console.log("  Type:", qtype);
      },
      onLeave: function (retval) {
        console.log("res_nmkquery returned:", retval.toInt32());
      }
    });
  } else {
    console.error("res_nmkquery not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**使用步骤：**

1. **准备环境：** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **运行 Frida 脚本：** 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_res_mkquery.js`)，然后使用 Frida 命令行工具运行：
   ```bash
   frida -U -f <your_app_package_name> -l hook_res_mkquery.js
   ```
   或者，如果想附加到一个正在运行的进程：
   ```bash
   frida -U <process_name_or_pid> -l hook_res_mkquery.js
   ```
3. **触发域名解析：** 在你的 Android 应用程序中执行会导致域名解析的操作，例如访问一个网站。
4. **查看输出：** Frida 会在控制台输出 `res_nmkquery` 函数被调用时的参数和返回值，你可以从中了解正在进行的 DNS 查询。

通过 Frida Hook，你可以深入了解 Android 系统在进行域名解析时 `res_mkquery` 函数的具体行为，这对于调试网络问题或理解系统底层机制非常有帮助。

希望以上分析对您有所帮助！

Prompt: 
```
这是目录为bionic/libc/dns/resolv/res_mkquery.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: res_mkquery.c,v 1.6 2006/01/24 17:40:32 christos Exp $	*/

/*
 * Copyright (c) 1985, 1993
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
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#ifdef notdef
static const char sccsid[] = "@(#)res_mkquery.c	8.1 (Berkeley) 6/4/93";
static const char rcsid[] = "Id: res_mkquery.c,v 1.1.2.2.4.2 2004/03/16 12:34:18 marka Exp";
#else
__RCSID("$NetBSD: res_mkquery.c,v 1.6 2006/01/24 17:40:32 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */



#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netdb.h>
#ifdef ANDROID_CHANGES
#include "resolv_private.h"
#else
#include <resolv.h>
#endif
#include <stdio.h>
#include <string.h>

/* Options.  Leave them on. */
#ifndef DEBUG
#define DEBUG
#endif

#ifndef lint
#define UNUSED(a)	(void)&a
#else
#define UNUSED(a)	a = a
#endif

extern const char *_res_opcodes[];

/*
 * Form all types of queries.
 * Returns the size of the result or -1.
 */
int
res_nmkquery(res_state statp,
	     int op,			/* opcode of query */
	     const char *dname,		/* domain name */
	     int class, int type,	/* class and type of query */
	     const u_char *data,	/* resource record data */
	     int datalen,		/* length of data */
	     const u_char *newrr_in,	/* new rr for modify or append */
	     u_char *buf,		/* buffer to put query */
	     int buflen)		/* size of buffer */
{
	register HEADER *hp;
	register u_char *cp, *ep;
	register int n;
	u_char *dnptrs[20], **dpp, **lastdnptr;

	UNUSED(newrr_in);

#ifdef DEBUG
	if (statp->options & RES_DEBUG)
		printf(";; res_nmkquery(%s, %s, %s, %s)\n",
		       _res_opcodes[op], dname, p_class(class), p_type(type));
#endif
	/*
	 * Initialize header fields.
	 */
	if ((buf == NULL) || (buflen < HFIXEDSZ))
		return (-1);
	memset(buf, 0, HFIXEDSZ);
	hp = (HEADER *)(void *)buf;
	hp->id = htons(res_randomid());
	hp->opcode = op;
	hp->rd = (statp->options & RES_RECURSE) != 0U;
	hp->ad = (statp->options & RES_USE_DNSSEC) != 0U;
	hp->rcode = NOERROR;
	cp = buf + HFIXEDSZ;
	ep = buf + buflen;
	dpp = dnptrs;
	*dpp++ = buf;
	*dpp++ = NULL;
	lastdnptr = dnptrs + sizeof dnptrs / sizeof dnptrs[0];
	/*
	 * perform opcode specific processing
	 */
	switch (op) {
	case QUERY:	/*FALLTHROUGH*/
	case NS_NOTIFY_OP:
		if (ep - cp < QFIXEDSZ)
			return (-1);
		if ((n = dn_comp(dname, cp, ep - cp - QFIXEDSZ, dnptrs,
		    lastdnptr)) < 0)
			return (-1);
		cp += n;
		ns_put16(type, cp);
		cp += INT16SZ;
		ns_put16(class, cp);
		cp += INT16SZ;
		hp->qdcount = htons(1);
		if (op == QUERY || data == NULL)
			break;
		/*
		 * Make an additional record for completion domain.
		 */
		if ((ep - cp) < RRFIXEDSZ)
			return (-1);
		n = dn_comp((const char *)data, cp, ep - cp - RRFIXEDSZ,
			    dnptrs, lastdnptr);
		if (n < 0)
			return (-1);
		cp += n;
		ns_put16(T_NULL, cp);
		cp += INT16SZ;
		ns_put16(class, cp);
		cp += INT16SZ;
		ns_put32(0, cp);
		cp += INT32SZ;
		ns_put16(0, cp);
		cp += INT16SZ;
		hp->arcount = htons(1);
		break;

	case IQUERY:
		/*
		 * Initialize answer section
		 */
		if (ep - cp < 1 + RRFIXEDSZ + datalen)
			return (-1);
		*cp++ = '\0';	/* no domain name */
		ns_put16(type, cp);
		cp += INT16SZ;
		ns_put16(class, cp);
		cp += INT16SZ;
		ns_put32(0, cp);
		cp += INT32SZ;
		ns_put16(datalen, cp);
		cp += INT16SZ;
		if (datalen) {
			memcpy(cp, data, (size_t)datalen);
			cp += datalen;
		}
		hp->ancount = htons(1);
		break;

	default:
		return (-1);
	}
	return (cp - buf);
}

#ifdef RES_USE_EDNS0
/* attach OPT pseudo-RR, as documented in RFC2671 (EDNS0). */
#ifndef T_OPT
#define T_OPT	41
#endif

int
res_nopt(res_state statp,
	 int n0,		/* current offset in buffer */
	 u_char *buf,		/* buffer to put query */
	 int buflen,		/* size of buffer */
	 int anslen)		/* UDP answer buffer size */
{
	register HEADER *hp;
	register u_char *cp, *ep;
	u_int16_t flags = 0;

#ifdef DEBUG
	if ((statp->options & RES_DEBUG) != 0U)
		printf(";; res_nopt()\n");
#endif

	hp = (HEADER *)(void *)buf;
	cp = buf + n0;
	ep = buf + buflen;

	if ((ep - cp) < 1 + RRFIXEDSZ)
		return (-1);

	*cp++ = 0;	/* "." */

	ns_put16(T_OPT, cp);	/* TYPE */
	cp += INT16SZ;
	if (anslen > 0xffff)
		anslen = 0xffff;
	ns_put16(anslen, cp);			/* CLASS = UDP payload size */
	cp += INT16SZ;
	*cp++ = NOERROR;	/* extended RCODE */
	*cp++ = 0;		/* EDNS version */
	if (statp->options & RES_USE_DNSSEC) {
#ifdef DEBUG
		if (statp->options & RES_DEBUG)
			printf(";; res_opt()... ENDS0 DNSSEC\n");
#endif
		flags |= NS_OPT_DNSSEC_OK;
	}
	ns_put16(flags, cp);
	cp += INT16SZ;
#ifdef EDNS0_PADDING
	{
		u_int16_t minlen = (cp - buf) + 3 * INT16SZ;
		u_int16_t extra = minlen % EDNS0_PADDING;
		u_int16_t padlen = (EDNS0_PADDING - extra) % EDNS0_PADDING;
		if (minlen > buflen) {
			return (-1);
		}
		padlen = MIN(padlen, buflen - minlen);
		ns_put16(padlen + 2 * INT16SZ, cp);	/* RDLEN */
		cp += INT16SZ;
		ns_put16(NS_OPT_PADDING, cp);	/* OPTION-CODE */
		cp += INT16SZ;
		ns_put16(padlen, cp);	/* OPTION-LENGTH */
		cp += INT16SZ;
		memset(cp, 0, padlen);
		cp += padlen;
	}
#else
	ns_put16(0, cp);	/* RDLEN */
	cp += INT16SZ;
#endif
	hp->arcount = htons(ntohs(hp->arcount) + 1);

	return (cp - buf);
}
#endif

"""

```