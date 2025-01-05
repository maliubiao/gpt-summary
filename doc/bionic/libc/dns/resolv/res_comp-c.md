Response:
Let's break down the thought process for answering the request about `res_comp.c`.

**1. Understanding the Core Request:**

The fundamental request is to understand the functionality of `res_comp.c` within the Android Bionic context. This means not just describing the functions, but also their role in the larger Android system, potential usage, and debugging.

**2. Initial Analysis of the Code:**

The first step is to quickly scan the provided source code. Key observations:

* **DNS Related:** The file name (`res_comp.c`), the include of `<arpa/nameser.h>` and `<resolv.h>` (or `<resolv_private.h>` for Android), and function names like `dn_expand`, `dn_comp`, `dn_skipname` immediately indicate this file deals with DNS name compression and manipulation.
* **License Information:** The copyright headers reveal its origin in BSD and ISC, highlighting its pedigree and common usage in networking.
* **Function Breakdown:**  A quick glance identifies the core functions:
    * `dn_expand`:  Expanding compressed DNS names.
    * `dn_comp`: Compressing DNS names.
    * `dn_skipname`: Skipping over compressed DNS names.
    * `res_hnok`, `res_ownok`, `res_mailok`, `res_dnok`: Functions validating DNS name formats.
    * (Conditionally defined) `__putlong`, `__putshort`, `_getlong`, `_getshort`: Byte order manipulation (likely legacy compatibility).

**3. Deconstructing the Request - Addressing Each Point:**

Now, systematically address each part of the request:

* **Functionality Listing:**  This is straightforward. List each exported function and its primary purpose based on its name and the provided comments.

* **Relationship to Android Functionality:**  Think about where DNS resolution is used in Android. The most obvious connection is networking – apps need to resolve domain names to IP addresses. Mention the `getaddrinfo` family of functions as a high-level API that likely utilizes these lower-level DNS functions. Emphasize that this is a *fundamental* part of the Android networking stack.

* **Detailed Explanation of `libc` Functions:**  For each function, describe:
    * **Purpose:**  What the function does.
    * **How it Works (High-Level):**  The general algorithm or approach. Avoid getting *too* deep into bit manipulation without examining the `ns_*.h` includes. Focus on the conceptual steps (e.g., iterating through labels, checking for pointers, writing length octets).
    * **Parameters and Return Values:**  Briefly explain the key inputs and outputs.

* **Dynamic Linker Involvement:** This requires understanding *where* `libc` resides in the Android system.
    * **SO Layout:**  Describe that `libc.so` is a core system library loaded at a well-known address. Mention that applications link against it. Provide a simplified example `libc.so` layout, showing sections like `.text`, `.data`, `.bss`, and the symbol table.
    * **Linking Process:** Explain that the dynamic linker (`linker64` or `linker`) resolves symbols at runtime. When an app calls `dn_expand`, the linker finds its address in `libc.so`'s symbol table. Mention the role of GOT and PLT.

* **Logical Reasoning (Hypothetical Input/Output):** Create simple, concrete examples to illustrate the core compression and expansion functions. This makes the abstract concepts more tangible.

* **Common Usage Errors:**  Think about typical mistakes programmers make when dealing with buffers and strings in C, especially related to DNS: buffer overflows, incorrect buffer sizes, passing `NULL` pointers.

* **Android Framework/NDK Path:**  Trace the call chain from a user-level action (e.g., opening a URL in a browser) down to these `libc` functions. Illustrate how framework components (like `ConnectivityManager`), system services, and finally, native code using `getaddrinfo` lead to `res_comp.c`.

* **Frida Hook Example:**  Provide a practical Frida script that demonstrates how to intercept calls to `dn_expand`. This helps in debugging and understanding the function's behavior in a real Android environment. Keep the script simple and focused on demonstrating the hook.

**4. Language and Tone:**

Maintain a clear, concise, and informative tone. Use Chinese as requested. Explain technical terms clearly.

**5. Review and Refine:**

After drafting the answer, review it for accuracy, completeness, and clarity. Ensure all parts of the original request have been addressed. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might not have explicitly mentioned GOT/PLT but realized it's important for explaining dynamic linking. Similarly, ensuring the Frida script is basic and easy to understand is crucial.

By following this structured thought process, we can generate a comprehensive and helpful response that addresses all aspects of the user's request about the `res_comp.c` file in Android Bionic.
好的，让我们详细分析一下 `bionic/libc/dns/resolv/res_comp.c` 这个文件。

**功能概述**

`res_comp.c` 文件是 Android Bionic C 库中负责域名系统 (DNS) 消息压缩和解压缩以及域名格式验证的关键组成部分。它提供了一系列函数，用于将人类可读的域名转换为 DNS 消息中使用的压缩格式，以及将压缩格式还原为可读格式。此外，它还包含用于验证域名是否符合特定格式（如主机名、邮件地址等）的函数。

**与 Android 功能的关系及举例**

DNS 解析是 Android 系统网络功能的基础。每当 Android 设备需要连接到互联网上的某个域名时（例如访问网站、发送电子邮件、连接到服务器），都需要将域名转换为 IP 地址。`res_comp.c` 中的函数在这一过程中扮演着至关重要的角色。

**举例说明：**

* **网络请求:** 当 Android 应用程序（例如浏览器、电子邮件客户端）尝试连接到 `www.google.com` 时，系统会调用底层的网络库进行 DNS 解析。
* **`getaddrinfo()`:**  Android NDK 中提供的 `getaddrinfo()` 函数用于将主机名和服务名转换为地址。在 `getaddrinfo()` 的实现内部，会调用 `res_comp.c` 中的函数来处理域名。
* **VPN 连接:**  某些 VPN 连接可能需要在本地网络中解析特定的域名，`res_comp.c` 的功能确保这些域名能够被正确处理。

**libc 函数的详细实现解释**

以下是 `res_comp.c` 中主要函数的详细解释：

1. **`dn_expand(const u_char *msg, const u_char *eom, const u_char *src, char *dst, int dstsiz)`**

   * **功能:** 将 DNS 消息中压缩的域名 (`src`) 展开为人类可读的完整域名，存储在 `dst` 缓冲区中。
   * **实现:**
     * DNS 消息为了节省空间，采用了域名压缩技术。如果域名的一部分之前在消息中出现过，后续的域名部分可以通过一个指向之前出现位置的指针来表示。
     * `dn_expand` 函数遍历压缩的域名，检查是否遇到了压缩指针。
     * 如果遇到指针，它会跳转到消息中指针指向的位置，并从那里继续读取域名部分。
     * 它将解压后的域名部分复制到 `dst` 缓冲区，并用点号分隔不同的标签（label）。
     * `eom` 指向消息的末尾，用于边界检查，防止读取超出消息范围。
     * `dstsiz` 指定了 `dst` 缓冲区的大小，用于防止缓冲区溢出。
     * 如果解压成功，返回压缩域名的长度；如果发生错误（例如，指针指向消息外部），则返回 -1。
   * **假设输入与输出:**
     * **假设输入:**
       * `msg`: 指向完整 DNS 消息的起始位置。
       * `eom`: 指向 DNS 消息末尾的下一个字节。
       * `src`: 指向消息中压缩域名的起始位置。假设压缩域名表示 "www.example.com"，并且使用了压缩。
       * `dst`: 指向一个足够大的字符缓冲区。
       * `dstsiz`: `dst` 缓冲区的大小。
     * **输出:**
       * `dst` 中的内容将是 "www.example.com"。
       * 函数返回值是压缩域名的长度。
   * **用户或编程常见错误:**
     * `dstsiz` 太小，导致缓冲区溢出。
     * `msg`、`eom` 或 `src` 指针无效。

2. **`dn_comp(const char *src, u_char *dst, int dstsiz, u_char **dnptrs, u_char **lastdnptr)`**

   * **功能:** 将人类可读的域名 (`src`) 压缩后存储到 DNS 消息缓冲区 (`dst`) 中。
   * **实现:**
     * `dn_comp` 函数将域名分解为多个标签（由点号分隔）。
     * 它尝试在 `dnptrs` 到 `lastdnptr` 指向的指针数组中查找之前是否已经压缩过相同的域名部分。这个指针数组用于记录之前压缩过的域名部分的起始位置，以便后续的域名部分可以使用指针进行压缩。
     * 如果找到匹配的域名部分，它会将一个指向之前位置的压缩指针写入 `dst`。
     * 如果没有找到匹配，它会将当前标签的长度和标签内容写入 `dst`，并更新指针数组。
     * `dstsiz` 指定了 `dst` 缓冲区的大小，用于防止缓冲区溢出。
     * 如果压缩成功，返回压缩后的域名长度；如果发生错误（例如，`dstsiz` 不足），则返回 -1。
   * **假设输入与输出:**
     * **假设输入:**
       * `src`: 字符串 "www.example.com"。
       * `dst`: 指向一个足够大的无符号字符缓冲区。
       * `dstsiz`: `dst` 缓冲区的大小。
       * `dnptrs`: 指向一个指针数组，用于存储之前压缩过的域名部分的指针。
       * `lastdnptr`: 指向 `dnptrs` 数组的末尾。
     * **输出:**
       * `dst` 中的内容将是 "www.example.com" 的压缩表示。
       * 函数返回值是压缩后的域名长度。
   * **用户或编程常见错误:**
     * `dstsiz` 太小，无法容纳压缩后的域名。
     * `dnptrs` 和 `lastdnptr` 管理不当，导致压缩效率低下或错误。

3. **`dn_skipname(const u_char *ptr, const u_char *eom)`**

   * **功能:** 跳过 DNS 消息中的一个压缩域名，返回该压缩域名的长度。
   * **实现:**
     * `dn_skipname` 函数读取 `ptr` 指向的字节。
     * 如果该字节的高两位是 11 (表示压缩指针)，则跳过 2 个字节（指针本身）。
     * 否则，该字节表示当前标签的长度，跳过该长度加 1 个字节（包括长度字节）。
     * 重复此过程直到遇到 0 长度的标签（域名的末尾）。
     * `eom` 用于边界检查。
     * 如果成功跳过，返回压缩域名的长度；如果遇到错误（例如，指针指向消息外部），则返回 -1。

4. **`res_hnok(const char *dn)`**

   * **功能:** 验证域名 (`dn`) 是否符合主机名格式的要求。
   * **实现:**
     * 主机名标签只能包含字母、数字和连字符（但不能在开头或结尾）。
     * `res_hnok` 遍历域名，检查每个字符是否符合这些规则。
     * 它还检查标签的开头和结尾字符。
     * Android Bionic 版本还允许在标签中间使用下划线。

5. **`res_ownok(const char *dn)`**

   * **功能:** 验证域名 (`dn`) 是否符合资源记录所有者名称的格式要求 (用于 A, MX, WKS 记录)。
   * **实现:**
     * 与 `res_hnok` 类似，但允许第一个标签是通配符 "*"。

6. **`res_mailok(const char *dn)`**

   * **功能:** 验证域名 (`dn`) 是否符合 SOA 或 RP 记录中 RNAME 的格式要求（例如，邮件地址）。
   * **实现:**
     * 第一个标签可以包含任何可打印字符，可以使用反斜杠进行转义。
     * 其余部分必须符合主机名格式。

7. **`res_dnok(const char *dn)`**

   * **功能:** 验证域名 (`dn`) 是否包含可接受的字符（基本是可打印字符）。
   * **实现:**
     * 允许域名包含除控制字符外的所有 ASCII 字符。

**dynamic linker 的功能以及 SO 布局样本和链接处理过程**

`res_comp.c` 编译后的代码会包含在 `libc.so` 动态链接库中。当 Android 应用程序调用这些函数时，动态链接器负责将函数调用重定向到 `libc.so` 中相应的函数实现。

**SO 布局样本 (简化):**

```
libc.so:
  .text:  // 代码段，包含 dn_expand, dn_comp 等函数的机器码
    ... (dn_expand 的机器码) ...
    ... (dn_comp 的机器码) ...
    ...
  .data:  // 已初始化数据段，可能包含一些全局变量
    ...
  .bss:   // 未初始化数据段
    ...
  .dynsym: // 动态符号表，包含导出的符号 (如 dn_expand, dn_comp)
    dn_expand (address)
    dn_comp (address)
    ...
  .dynstr: // 动态字符串表，包含符号名称的字符串
    "dn_expand"
    "dn_comp"
    ...
  .plt:    // Procedure Linkage Table，用于延迟绑定
    dn_expand:
      jmp *GOT[index_for_dn_expand]
    dn_comp:
      jmp *GOT[index_for_dn_comp]
    ...
  .got:    // Global Offset Table，在程序运行时被动态链接器填充
    index_for_dn_expand: 0x0  // 初始为 0，动态链接后指向 dn_expand 的实际地址
    index_for_dn_comp: 0x0    // 初始为 0，动态链接后指向 dn_comp 的实际地址
    ...
```

**链接处理过程:**

1. **编译时:** 当应用程序的代码调用 `dn_expand` 时，编译器会生成一个对该符号的引用。由于 `dn_expand` 在 `libc.so` 中，编译器并不知道其确切地址，因此会生成一个对 PLT 中对应条目的调用。
2. **加载时:** Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 在加载应用程序时，也会加载其依赖的动态链接库 `libc.so`。
3. **符号解析:** 动态链接器会解析应用程序中对 `libc.so` 中符号的引用。对于 `dn_expand`，动态链接器会在 `libc.so` 的 `.dynsym` 表中找到 `dn_expand` 的定义及其在 `libc.so` 内部的地址。
4. **GOT/PLT 重写 (延迟绑定):** 默认情况下，Android 使用延迟绑定。当第一次调用 `dn_expand` 时，PLT 中的指令会跳转到动态链接器的一个特殊例程。该例程会查找 `dn_expand` 的实际地址，并将其写入 GOT 中对应的条目 (`GOT[index_for_dn_expand]`)。然后，动态链接器会将控制权转移到 `dn_expand` 的实际地址。后续对 `dn_expand` 的调用会直接通过 PLT 跳转到 GOT 中已填充的地址，从而避免了重复的符号查找和重定位。

**Android Framework 或 NDK 如何到达这里**

以下是一个简化的调用链，展示了 Android Framework 或 NDK 如何最终调用 `res_comp.c` 中的函数：

1. **Android 应用发起网络请求:** 例如，一个浏览器应用想要访问 `www.example.com`。
2. **Java Framework 层:**
   * 应用调用 `java.net.URL` 或 `android.net.http.HttpsURLConnection` 等类。
   * 这些类最终会调用到 `android.net.ConnectivityManager` 或类似的系统服务来处理网络连接。
3. **System Server 进程:** `ConnectivityManager` 等服务运行在 System Server 进程中。
4. **Native 代码 (通过 JNI 调用):** System Server 的网络相关功能会调用到底层的 Native 代码，通常通过 JNI (Java Native Interface) 进行。
5. **`getaddrinfo()` 或相关函数:** Native 代码可能会调用 `libc.so` 中提供的 `getaddrinfo()` 函数来执行 DNS 解析。
6. **`resolv` 库:** `getaddrinfo()` 内部会使用 `resolv` 库 (包含在 `libc.so` 中) 来处理 DNS 查询。
7. **`res_query()` 或类似函数:** `resolv` 库会调用 `res_query()` 或类似的函数来构建 DNS 查询消息并发送到 DNS 服务器。
8. **消息构建:** 在构建 DNS 查询消息的过程中，需要将域名压缩。`res_comp.c` 中的 `dn_comp()` 函数会被调用来完成这个任务。
9. **接收 DNS 响应:** 当收到 DNS 服务器的响应后，需要解析响应消息。
10. **消息解析:**  `res_comp.c` 中的 `dn_expand()` 函数会被调用来解压缩响应消息中的域名。

**Frida Hook 示例调试步骤**

可以使用 Frida 来 hook `dn_expand` 函数，以观察其输入和输出：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用程序的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 '{package_name}' 未运行")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "dn_expand"), {
    onEnter: function(args) {
        console.log("[*] dn_expand called");
        console.log("    msg: " + args[0]);
        console.log("    eom: " + args[1]);
        console.log("    src: " + args[2]);
        console.log("    dst: " + args[3]);
        console.log("    dstsiz: " + args[4]);
        // 可以读取 src 指向的压缩域名数据
        // 以及在 onLeave 中查看 dst 的内容
    },
    onLeave: function(retval) {
        console.log("[*] dn_expand returned: " + retval);
        if (retval > 0) {
            console.log("    Expanded domain: " + Memory.readUtf8String(this.context.r2)); // 假设 dst 对应 r2 寄存器，可能需要根据架构调整
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida 和 Python 环境。**
2. **将上面的 Python 代码保存为 `hook_dn_expand.py`，并将 `你的应用包名` 替换为你要调试的应用程序的实际包名。**
3. **确保你的 Android 设备已连接并通过 USB 调试。**
4. **运行你要调试的应用程序。**
5. **在终端中运行 `python hook_dn_expand.py`。**
6. **在应用程序中触发网络请求，例如访问一个网站。**
7. **Frida 会拦截对 `dn_expand` 的调用，并打印出相关的参数和返回值，包括解压后的域名。**

**总结**

`res_comp.c` 文件是 Android Bionic 中 DNS 解析的关键组成部分，负责域名的压缩、解压缩和格式验证。理解其功能和实现对于理解 Android 的网络工作原理至关重要。通过 Frida 等工具，我们可以深入调试这些底层函数，更好地理解系统的运作方式。

Prompt: 
```
这是目录为bionic/libc/dns/resolv/res_comp.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: res_comp.c,v 1.6 2004/05/22 23:47:09 christos Exp $	*/

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
static const char sccsid[] = "@(#)res_comp.c	8.1 (Berkeley) 6/4/93";
static const char rcsid[] = "Id: res_comp.c,v 1.1.2.1.4.1 2004/03/09 08:33:54 marka Exp";
#else
__RCSID("$NetBSD: res_comp.c,v 1.6 2004/05/22 23:47:09 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <ctype.h>
#ifdef ANDROID_CHANGES
#include "resolv_private.h"
#else
#include <resolv.h>
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * Expand compressed domain name 'src' to full domain name.
 * 'msg' is a pointer to the begining of the message,
 * 'eom' points to the first location after the message,
 * 'dst' is a pointer to a buffer of size 'dstsiz' for the result.
 * Return size of compressed name or -1 if there was an error.
 */
int
dn_expand(const u_char *msg, const u_char *eom, const u_char *src,
	  char *dst, int dstsiz)
{
	int n = ns_name_uncompress(msg, eom, src, dst, (size_t)dstsiz);

	if (n > 0 && dst[0] == '.')
		dst[0] = '\0';
	return (n);
}

/*
 * Pack domain name 'exp_dn' in presentation form into 'comp_dn'.
 * Return the size of the compressed name or -1.
 * 'length' is the size of the array pointed to by 'comp_dn'.
 */
int
dn_comp(const char *src, u_char *dst, int dstsiz,
	u_char **dnptrs, u_char **lastdnptr)
{
	return (ns_name_compress(src, dst, (size_t)dstsiz,
				 (const u_char **)dnptrs,
				 (const u_char **)lastdnptr));
}

/*
 * Skip over a compressed domain name. Return the size or -1.
 */
int
dn_skipname(const u_char *ptr, const u_char *eom) {
	const u_char *saveptr = ptr;

	if (ns_name_skip(&ptr, eom) == -1)
		return (-1);
	return (ptr - saveptr);
}

/*
 * Verify that a domain name uses an acceptable character set.
 */

/*
 * Note the conspicuous absence of ctype macros in these definitions.  On
 * non-ASCII hosts, we can't depend on string literals or ctype macros to
 * tell us anything about network-format data.  The rest of the BIND system
 * is not careful about this, but for some reason, we're doing it right here.
 */

/* BIONIC: We also accept underscores in the middle of labels.
 *         This extension is needed to make resolution on some VPN networks
 *         work properly.
 */

#define PERIOD 0x2e
#define	hyphenchar(c) ((c) == 0x2d)
#define bslashchar(c) ((c) == 0x5c)
#define periodchar(c) ((c) == PERIOD)
#define asterchar(c) ((c) == 0x2a)
#define alphachar(c) (((c) >= 0x41 && (c) <= 0x5a) \
		   || ((c) >= 0x61 && (c) <= 0x7a))
#define digitchar(c) ((c) >= 0x30 && (c) <= 0x39)
#define underscorechar(c)  ((c) == 0x5f)

#define borderchar(c) (alphachar(c) || digitchar(c))
#define middlechar(c) (borderchar(c) || hyphenchar(c) || underscorechar(c))
#define	domainchar(c) ((c) > 0x20 && (c) < 0x7f)

int
res_hnok(const char *dn) {
	int pch = PERIOD, ch = *dn++;

	while (ch != '\0') {
		int nch = *dn++;

		if (periodchar(ch)) {
			;
		} else if (periodchar(pch)) {
			if (!borderchar(ch))
				return (0);
		} else if (periodchar(nch) || nch == '\0') {
			if (!borderchar(ch))
				return (0);
		} else {
			if (!middlechar(ch))
				return (0);
		}
		pch = ch, ch = nch;
	}
	return (1);
}

/*
 * hostname-like (A, MX, WKS) owners can have "*" as their first label
 * but must otherwise be as a host name.
 */
int
res_ownok(const char *dn) {
	if (asterchar(dn[0])) {
		if (periodchar(dn[1]))
			return (res_hnok(dn+2));
		if (dn[1] == '\0')
			return (1);
	}
	return (res_hnok(dn));
}

/*
 * SOA RNAMEs and RP RNAMEs can have any printable character in their first
 * label, but the rest of the name has to look like a host name.
 */
int
res_mailok(const char *dn) {
	int ch, escaped = 0;

	/* "." is a valid missing representation */
	if (*dn == '\0')
		return (1);

	/* otherwise <label>.<hostname> */
	while ((ch = *dn++) != '\0') {
		if (!domainchar(ch))
			return (0);
		if (!escaped && periodchar(ch))
			break;
		if (escaped)
			escaped = 0;
		else if (bslashchar(ch))
			escaped = 1;
	}
	if (periodchar(ch))
		return (res_hnok(dn));
	return (0);
}

/*
 * This function is quite liberal, since RFC 1034's character sets are only
 * recommendations.
 */
int
res_dnok(const char *dn) {
	int ch;

	while ((ch = *dn++) != '\0')
		if (!domainchar(ch))
			return (0);
	return (1);
}

#ifdef BIND_4_COMPAT
/*
 * This module must export the following externally-visible symbols:
 *	___putlong
 *	___putshort
 *	__getlong
 *	__getshort
 * Note that one _ comes from C and the others come from us.
 */
void __putlong(u_int32_t src, u_char *dst) { ns_put32(src, dst); }
void __putshort(u_int16_t src, u_char *dst) { ns_put16(src, dst); }
#ifndef __ultrix__
u_int32_t _getlong(const u_char *src) { return (ns_get32(src)); }
u_int16_t _getshort(const u_char *src) { return (ns_get16(src)); }
#endif /*__ultrix__*/
#endif /*BIND_4_COMPAT*/

"""

```