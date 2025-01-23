Response:
Let's break down the thought process for analyzing the C code and generating the detailed response.

**1. Initial Understanding and Goal:**

The request asks for a comprehensive analysis of the `ns_print.c` file from Android's Bionic libc. The key aspects are:

* **Functionality:** What does this code do?
* **Android Relevance:** How does it fit into the Android ecosystem?
* **Libc Function Implementation:** How are the core libc functions within this file implemented?
* **Dynamic Linking:** If relevant, how does it interact with the dynamic linker?
* **Logic/Assumptions:** Any internal reasoning or assumptions made by the code.
* **Common Errors:**  Pitfalls programmers might encounter.
* **Android Framework/NDK Integration:** How does the execution reach this code from higher levels?
* **Debugging (Frida):**  How can we inspect this code in action?

**2. High-Level Overview of the Code:**

The immediate clue is the filename and the comment mentioning DNS. The `#include` directives confirm this, bringing in headers related to networking (`sys/socket.h`, `netinet/in.h`), DNS (`arpa/nameser.h`), and standard C libraries (`stddef.h`, `string.h`, `ctype.h`). The presence of `resolv.h` (or the Android-specific `resolv_private.h`) is also a strong indicator.

The core function `ns_sprintrrf` stands out. The name suggests "name server print resource record formatted." This points to the primary function: formatting DNS resource records into a human-readable string representation.

**3. Dissecting Key Functions:**

* **`ns_sprintrr` and `ns_sprintrrf`:** These are the entry points for formatting. They take DNS message and resource record data and format it. The `f` in `ns_sprintrrf` likely means "formatted," allowing more direct control over the input.
* **`prune_origin`:**  This function aims to shorten domain names by removing a common "origin" suffix. This is common in DNS zone files.
* **`charstr`:** Handles the formatting of "character-string" data within DNS records, respecting the length prefix and escaping special characters.
* **`addname`:** This is crucial. It handles the expansion of compressed domain names (using pointers) within the DNS message and then applies `prune_origin`. This is a core part of DNS parsing.
* **`addlen`, `addstr`, `addtab`:**  These are utility functions for managing the output buffer (`buf` and `buflen`). They handle string appending and formatting (like adding tabs for alignment).

**4. Identifying Android Relevance:**

The comment `#ifdef ANDROID_CHANGES` and the inclusion of `"resolv_private.h"` are direct indicators of Android-specific modifications. This suggests that Android might have customized aspects of the DNS resolution process. The `resolv` library is a fundamental part of how Android devices resolve domain names.

**5. Analyzing Libc Function Implementations (within this file):**

The focus here is *how* the functions in `ns_print.c` use standard libc functions, not re-implementing them. Examples include:

* `strlen`: Calculating string lengths.
* `memcpy`: Copying data.
* `snprintf`: Formatting strings into a buffer.
* `inet_ntop`: Converting IP addresses to string format.
* `isascii`, `isprint`: Character classification.
* `strchr`: Searching for characters within a string.

The code *doesn't* reimplement these; it leverages them. The explanation should highlight *how* they are used in the context of formatting DNS data.

**6. Dynamic Linking Considerations:**

The code uses functions like `dn_expand` and likely relies on the overall DNS resolver infrastructure within Bionic. While `ns_print.c` itself doesn't directly interact with the dynamic linker (like calling `dlopen`), it is part of a larger shared library (`libc.so`). Therefore, its functions are called via function pointers resolved by the dynamic linker at runtime. The explanation needs to describe this indirect relationship and provide a basic `libc.so` structure.

**7. Logical Inference and Assumptions:**

The code makes assumptions about the structure of DNS messages and resource records, as defined by the DNS RFCs. For instance, it expects specific data layouts for different record types (A, CNAME, MX, etc.). The `prune_origin` function assumes a common suffix for domain names in certain contexts.

**8. Common User/Programming Errors:**

Buffer overflows are a classic C problem. Incorrectly sizing the output buffer (`buf`, `buflen`) or miscalculating the required space could lead to crashes. Providing a buffer that's too small for a complex DNS record is a likely error. Also, misunderstanding the expected input format (e.g., providing malformed DNS data) can lead to incorrect output.

**9. Android Framework/NDK Call Chain:**

This requires tracing the execution flow. A simplified path would be:

* **Application:** Makes a network request (e.g., opening a URL).
* **Android Framework:**  Uses system services to handle the request.
* **DNS Resolver:** The framework initiates a DNS lookup.
* **Bionic `libc.so`:** The DNS resolver within `libc.so` is involved. The `ns_print` functions are likely used for logging or debugging purposes within the resolver, or when providing formatted DNS information to applications.
* **NDK:**  Applications using the NDK can directly interact with networking functions, which will eventually involve the Bionic DNS resolver.

**10. Frida Hooking:**

The Frida examples should target the core formatting functions (`ns_sprintrr`, `ns_sprintrrf`). Hooking these functions allows interception of the arguments (DNS data, buffers) and the return value (formatted string). This is a powerful way to observe the function in action.

**11. Structuring the Response:**

Organize the information logically using headings and subheadings. Use clear and concise language. Provide code examples and explanations where necessary. Address all parts of the original request.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on low-level memory manipulation. **Correction:**  Shift focus to the higher-level purpose of formatting DNS data and how libc functions are *used* for this.
* **Initial thought:**  Try to explain the entire DNS resolution process. **Correction:** Keep the focus on the `ns_print.c` file and its specific role. Briefly mention the broader context, but don't delve too deep into the resolver implementation itself.
* **Initial thought:** Provide overly technical details about dynamic linking. **Correction:**  Explain the core concept of shared libraries and function resolution without getting bogged down in linker specifics. Focus on the *impact* on this code.
* **Initial thought:**  Provide very generic examples of common errors. **Correction:**  Make the examples specific to the context of DNS record formatting and buffer management.

By following this structured approach, combining code analysis with contextual knowledge about Android and DNS, and iteratively refining the understanding, we can generate a comprehensive and accurate response to the complex request.
好的，让我们详细分析一下 `bionic/libc/dns/nameser/ns_print.c` 这个文件。

**功能概述**

`ns_print.c` 文件的主要功能是将 DNS 资源记录（Resource Records, RR）转换成人类可读的文本格式。这对于调试 DNS 问题、查看 DNS 响应以及生成 DNS 区域文件等场景非常有用。

具体来说，它包含以下几个核心功能：

1. **`ns_sprintrr` 和 `ns_sprintrrf`:** 这两个函数是入口点，用于将 `ns_rr` 结构体（表示一个 DNS 资源记录）的内容格式化到一个字符串缓冲区中。`ns_sprintrr` 接收一个 `ns_msg` 结构体（代表整个 DNS 消息）和一个 `ns_rr` 结构体作为输入，而 `ns_sprintrrf` 则接收更细粒度的参数，例如资源记录的名称、类型、类、TTL 和数据等。
2. **针对不同 RR 类型的格式化逻辑:** 文件中包含一个大的 `switch` 语句，根据资源记录的类型（例如 A 记录、CNAME 记录、MX 记录等）采取不同的格式化方式。它会调用不同的函数来处理特定类型的数据。
3. **域名压缩处理:**  `addname` 函数负责处理 DNS 消息中可能存在的域名压缩。DNS 协议为了节省空间，允许在消息中用指针指向之前出现过的域名，`addname` 能够展开这些压缩的域名。
4. **Origin 处理:** `prune_origin` 函数用于移除域名中与 "origin" 相关的部分。在 DNS 区域文件中，经常会有一个共同的 "origin"，为了简洁，可以省略域名中与 origin 相同的部分。
5. **字符数据处理:** `charstr` 函数用于格式化资源记录数据中出现的 "character-string" 类型的数据，它会将字符串用双引号包围，并处理特殊字符的转义。
6. **辅助格式化函数:**  `addlen`, `addstr`, `addtab` 等函数是一些辅助工具，用于向输出缓冲区添加字符串、添加制表符以进行对齐等。

**与 Android 功能的关系及举例**

`ns_print.c` 是 Android 系统 DNS 解析库的一部分，因此它直接参与了 Android 设备进行域名解析的过程。虽然用户或应用程序通常不会直接调用这个文件中的函数，但它们被底层的 DNS 解析器使用。

**举例说明:**

* **`getaddrinfo()` 系统调用:**  当 Android 应用程序（例如浏览器、社交应用）需要将域名（如 `www.google.com`）解析为 IP 地址时，它会调用 `getaddrinfo()` 系统调用。
* **Bionic 的 DNS 解析器:** `getaddrinfo()` 最终会调用 Bionic libc 中的 DNS 解析器实现。
* **DNS 查询和响应:**  DNS 解析器会构建 DNS 查询报文，发送给 DNS 服务器，并接收 DNS 响应报文。
* **`ns_print.c` 的作用:**  在 DNS 响应报文被解析后，如果需要将响应中的资源记录以文本形式展示（例如在调试信息中），那么 `ns_sprintrr` 或 `ns_sprintrrf` 函数就会被调用。例如，Android 可能会在内部日志中打印 DNS 查询的结果，这时就可能用到这些格式化函数。

**详细解释每一个 libc 函数的功能是如何实现的**

需要注意的是，`ns_print.c` 文件本身**并没有实现** `libc` 的核心函数，而是**使用**了 `libc` 提供的函数。

我们来解释一下 `ns_print.c` 中使用的一些关键 `libc` 函数：

1. **`strlen(const char *s)`:**  计算字符串 `s` 的长度（不包括终止符 `\0`）。
   * **实现原理:** 通常通过循环遍历字符串，直到遇到 `\0` 字符为止，并返回遍历的字符数。

2. **`memcpy(void *dest, const void *src, size_t n)`:** 将 `src` 指向的内存块的 `n` 个字节复制到 `dest` 指向的内存块。
   * **实现原理:** 通常是逐字节地从源地址读取数据并写入目标地址。为了提高效率，可能会进行字或块级别的复制。需要注意内存区域可能重叠的情况。

3. **`snprintf(char *str, size_t size, const char *format, ...)`:**  类似于 `sprintf`，但增加了缓冲区大小限制 `size`，防止缓冲区溢出。它根据 `format` 字符串将后续的参数格式化输出到 `str` 指向的缓冲区，最多写入 `size-1` 个字符，并在末尾添加 `\0`。
   * **实现原理:**  解析 `format` 字符串中的格式化指示符（如 `%d`, `%s`, `%x` 等），并将相应的参数转换为字符串并写入缓冲区。它会检查写入的字符数是否超过 `size-1`。

4. **`inet_ntop(int af, const void *src, char *dst, socklen_t size)`:** 将网络地址结构体（例如 `struct in_addr` 或 `struct in6_addr`）中的二进制 IP 地址转换为点分十进制或冒号分隔的十六进制字符串，存储到 `dst` 中。`af` 指定地址族（`AF_INET` 或 `AF_INET6`），`size` 是目标缓冲区的大小。
   * **实现原理:**  根据地址族，从 `src` 指向的内存中提取 IP 地址的字节，并按照相应的格式转换为字符串。例如，对于 IPv4，将 4 个字节分别转换为十进制数，并用点号分隔。

5. **`isascii(int c)`:** 检查字符 `c` 是否是 ASCII 字符（0 到 127）。
   * **实现原理:**  通常是一个简单的范围检查。

6. **`isprint(int c)`:** 检查字符 `c` 是否是可打印字符（包括空格）。
   * **实现原理:**  通常也是一个范围检查，不同的字符编码集可能有不同的可打印字符范围。

7. **`strchr(const char *s, int c)`:** 在字符串 `s` 中查找第一次出现字符 `c` 的位置，如果找到则返回指向该位置的指针，否则返回 `NULL`。
   * **实现原理:** 逐个遍历字符串 `s` 的字符，直到找到与 `c` 相等的字符或遇到字符串结尾。

8. **`dn_expand(const unsigned char *msg, const unsigned char *eomorig, const unsigned char *comp_dn, char *exp_dn, int length)`:**  展开 DNS 消息中的压缩域名。`msg` 是 DNS 消息的起始地址，`eomorig` 是消息的结束地址，`comp_dn` 是指向压缩域名的指针，`exp_dn` 是用于存储展开后域名的缓冲区，`length` 是缓冲区的大小。
   * **实现原理:**  检查 `comp_dn` 指向的数据是否是压缩指针（高两位为 1）。如果是，则从消息的指定偏移量处读取域名部分并进行递归展开。如果不是压缩指针，则直接复制域名部分。

9. **`b64_ntop(const unsigned char *src, size_t srclength, char *target, size_t targsize)`:** 将二进制数据 `src` 编码为 Base64 字符串，存储到 `target` 中。
    * **实现原理:** 将每 3 个字节的二进制数据转换为 4 个 Base64 字符。需要处理输入数据长度不是 3 的倍数的情况，并添加 padding 字符 `=`。

**涉及 dynamic linker 的功能及处理过程**

`ns_print.c` 文件中的代码会被编译成 `libc.so` 这个共享库的一部分。当程序运行时，dynamic linker (在 Android 上是 `linker64` 或 `linker`) 负责加载 `libc.so` 并解析其中的符号。

**so 布局样本 (简化):**

```
libc.so:
    .text:
        ns_sprintrr: ... (代码)
        ns_sprintrrf: ... (代码)
        prune_origin: ... (代码)
        ... (其他 libc 函数)
    .data:
        ... (全局变量)
    .dynsym:
        ns_sprintrr  (符号表项)
        ns_sprintrrf (符号表项)
        prune_origin (符号表项)
        ... (其他导出符号)
    .dynstr:
        "ns_sprintrr" (字符串表项)
        "ns_sprintrrf" (字符串表项)
        "prune_origin" (字符串表项)
        ...
```

**链接的处理过程:**

1. **程序启动:** 当一个 Android 应用程序启动时，操作系统会加载程序的可执行文件。
2. **依赖项加载:**  可执行文件会声明它依赖的共享库，例如 `libc.so`。dynamic linker 会负责找到并加载这些库到内存中。
3. **符号解析 (Symbol Resolution):**  如果程序中调用了 `libc.so` 中的函数（例如通过 `getaddrinfo` 间接调用了 `ns_sprintrr`），dynamic linker 需要将程序中的函数调用地址与 `libc.so` 中对应函数的实际地址关联起来。
4. **重定位 (Relocation):**  由于共享库被加载到内存的哪个地址是不确定的（地址空间布局随机化 ASLR），dynamic linker 需要修改程序和共享库中的某些地址引用，使其指向正确的内存位置。
5. **函数调用:** 一旦符号解析和重定位完成，程序就可以成功调用 `libc.so` 中的函数。例如，当 DNS 解析器需要格式化资源记录时，它会通过函数指针调用 `ns_sprintrr`。

**假设输入与输出 (逻辑推理)**

假设我们有一个简单的 A 记录，表示 `example.com` 的 IP 地址是 `192.0.2.1`。

**假设输入:**

* **`name`:** "example.com"
* **`class`:** `ns_c_in` (Internet 类)
* **`type`:** `ns_t_a` (A 记录类型)
* **`ttl`:** 3600
* **`rdata`:**  包含 `192.0.2.1` 的二进制表示（4个字节：`\xC0\x00\x02\x01`）
* **`rdlen`:** 4

**可能的输出 (调用 `ns_sprintrrf` 后):**

```
example.com. 3600 IN A 192.0.2.1
```

**解释:**

* `example.com.`：域名，尾部的点表示根域。
* `3600`：TTL 值。
* `IN`：资源记录的类 (Internet)。
* `A`：资源记录的类型 (A 记录)。
* `192.0.2.1`：A 记录的数据，即 IP 地址。

**用户或编程常见的使用错误**

1. **缓冲区溢出:**  如果传递给 `ns_sprintrr` 或 `ns_sprintrrf` 的缓冲区 `buf` 太小，无法容纳格式化后的字符串，就会发生缓冲区溢出，可能导致程序崩溃或安全漏洞。

   ```c
   char buf[32]; // 缓冲区太小
   ns_sprintrrf(..., buf, sizeof(buf)); // 可能溢出
   ```

2. **传递错误的参数:**  例如，传递了错误的资源记录类型或类，可能导致格式化输出不正确或程序错误。

3. **没有正确处理域名压缩:**  如果手动解析 DNS 消息并尝试格式化资源记录，需要正确处理域名压缩，否则 `addname` 函数可能会出错。

4. **对 `origin` 参数理解不当:**  `origin` 参数用于简化域名显示，如果不理解其含义，可能会得到意外的输出结果。

**Android framework 或 NDK 如何一步步的到达这里**

1. **应用发起网络请求:**  Android 应用可能通过 `java.net.URL`, `OkHttp`, `HttpURLConnection` 等 Java API 发起网络请求。
2. **Framework 处理:**  这些 Java API 底层会调用 Android Framework 中的网络相关服务，例如 `ConnectivityService` 或 `NetworkStack`.
3. **Native DNS 解析:** Framework 层最终会调用 Native 代码进行 DNS 解析，这通常涉及到 Bionic libc 中的 `getaddrinfo` 函数。
4. **`res_nsearch` 等函数:** `getaddrinfo` 内部会使用 `res_nsearch` 或类似的函数来执行 DNS 查询。
5. **接收 DNS 响应:** DNS 查询的结果（DNS 响应报文）会被接收。
6. **调试或日志输出:**  在某些情况下，Android 系统或网络库可能需要将 DNS 响应中的资源记录以文本形式打印出来，用于调试或日志记录。这时，就会调用 `ns_sprintrr` 或 `ns_sprintrrf`。

**NDK 的路径:**

使用 NDK 开发的 Native 应用可以直接调用 Bionic libc 中的网络函数，例如 `getaddrinfo`。因此，如果 NDK 应用需要进行 DNS 解析，其路径与 Framework 类似，最终也会涉及到 `ns_print.c` 中的函数，尤其是在需要将 DNS 记录格式化为字符串的时候。

**Frida hook 示例调试步骤**

可以使用 Frida hook `ns_sprintrrf` 函数来观察其输入和输出。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

# 要 hook 的进程名称或 PID
package_name = "com.example.myapp" # 替换为你的应用包名

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ns_sprintrrf"), {
    onEnter: function(args) {
        this.msg = args[0];
        this.msglen = args[1].toInt();
        this.name = Memory.readUtf8String(args[2]);
        this.class = args[3].toInt();
        this.type = args[4].toInt();
        this.ttl = args[5].toInt();
        this.rdata = args[6];
        this.rdlen = args[7].toInt();
        this.name_ctx = args[8];
        this.origin = args[9];
        this.buf = args[10];
        this.buflen = args[11].toInt();

        console.log("---------- ns_sprintrrf 调用 ----------");
        console.log("msg:", this.msg);
        console.log("msglen:", this.msglen);
        console.log("name:", this.name);
        console.log("class:", this.class);
        console.log("type:", this.type);
        console.log("ttl:", this.ttl);
        console.log("rdata:", this.rdata);
        console.log("rdlen:", this.rdlen);
        console.log("name_ctx:", this.name_ctx ? Memory.readUtf8String(this.name_ctx) : null);
        console.log("origin:", this.origin ? Memory.readUtf8String(this.origin) : null);
        console.log("buflen:", this.buflen);
    },
    onLeave: function(retval) {
        if (retval.toInt() > 0) {
            console.log("格式化后的字符串:", Memory.readUtf8String(this.buf));
        } else {
            console.log("格式化失败，返回值:", retval);
        }
        console.log("---------------------------------------");
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida hook 示例解释:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 连接的设备，并附加到目标应用程序进程。
2. **`Module.findExportByName("libc.so", "ns_sprintrrf")`:**  在 `libc.so` 库中查找 `ns_sprintrrf` 函数的地址。
3. **`Interceptor.attach(...)`:**  拦截 `ns_sprintrrf` 函数的调用。
4. **`onEnter`:**  在函数执行前调用，可以读取函数的参数。
   * `args` 数组包含了函数的参数。我们读取了 DNS 消息指针、长度、域名、类型、类、TTL、RDATA 指针和长度、上下文名称、Origin 和缓冲区信息。
   * 使用 `Memory.readUtf8String()` 读取字符串参数。
5. **`onLeave`:** 在函数执行后调用，可以读取函数的返回值。
   * 读取格式化后的字符串缓冲区 `this.buf`。
6. **`script.load()`:** 加载并运行 Frida 脚本。

**调试步骤:**

1. 确保你的 Android 设备已连接并通过 USB 调试授权。
2. 安装 Frida 和 Python 的 Frida 模块 (`pip install frida-tools`).
3. 将上面的 Python 脚本保存为一个文件（例如 `hook_ns_print.py`）。
4. 将 `package_name` 替换为你想要调试的应用程序的包名。
5. 运行你的 Android 应用程序。
6. 在终端中运行 Frida 脚本： `python hook_ns_print.py`。
7. 当应用程序执行涉及 DNS 记录格式化的操作时，Frida 会拦截 `ns_sprintrrf` 的调用，并打印出其输入参数和格式化后的输出字符串。

通过这个 Frida 脚本，你可以观察到 `ns_sprintrrf` 何时被调用，以及它处理的具体 DNS 资源记录数据，这对于理解 DNS 解析过程和调试相关问题非常有帮助。

### 提示词
```
这是目录为bionic/libc/dns/nameser/ns_print.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: ns_print.c,v 1.11 2012/03/13 21:13:39 christos Exp $	*/

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium.
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
#ifndef lint
#ifdef notdef
static const char rcsid[] = "Id: ns_print.c,v 1.12 2009/03/03 05:29:58 each Exp";
#else
__RCSID("$NetBSD: ns_print.c,v 1.11 2012/03/13 21:13:39 christos Exp $");
#endif
#endif

/* Import. */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>

#include <isc/assertions.h>
#include <isc/dst.h>
#include <assert.h>
#include <errno.h>
#ifdef ANDROID_CHANGES
#include "resolv_private.h"
#else
#include <resolv.h>
#endif
#include <stddef.h>
#include <string.h>
#include <ctype.h>

#ifndef MIN
#define	MIN(x,y)	((x)<(y)?(x):(y))
#endif

/* Forward. */

static size_t	prune_origin(const char *name, const char *origin);
static int	charstr(const u_char *rdata, const u_char *edata,
			char **buf, size_t *buflen);
static int	addname(const u_char *msg, size_t msglen,
			const u_char **p, const char *origin,
			char **buf, size_t *buflen);
static void	addlen(size_t len, char **buf, size_t *buflen);
static int	addstr(const char *src, size_t len,
		       char **buf, size_t *buflen);
static int	addtab(size_t len, size_t target, int spaced,
		       char **buf, size_t *buflen);

/* Macros. */

#define	T(x) \
	do { \
		if ((x) < 0) \
			return (-1); \
	} while (/*CONSTCOND*/0)

static const char base32hex[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUV=0123456789abcdefghijklmnopqrstuv";
/* Public. */

/*
 *	Convert an RR to presentation format.
 *
 * return:
 *	Number of characters written to buf, or -1 (check errno).
 */
int
ns_sprintrr(const ns_msg *handle, const ns_rr *rr,
	    const char *name_ctx, const char *origin,
	    char *buf, size_t buflen)
{
	int n;

	n = ns_sprintrrf(ns_msg_base(*handle), ns_msg_size(*handle),
			 ns_rr_name(*rr), ns_rr_class(*rr), ns_rr_type(*rr),
			 ns_rr_ttl(*rr), ns_rr_rdata(*rr), ns_rr_rdlen(*rr),
			 name_ctx, origin, buf, buflen);
	return (n);
}

/*
 *	Convert the fields of an RR into presentation format.
 *
 * return:
 *	Number of characters written to buf, or -1 (check errno).
 */
int
ns_sprintrrf(const u_char *msg, size_t msglen,
	    const char *name, ns_class class, ns_type type,
	    u_long ttl, const u_char *rdata, size_t rdlen,
	    const char *name_ctx, const char *origin,
	    char *buf, size_t buflen)
{
	const char *obuf = buf;
	const u_char *edata = rdata + rdlen;
	int spaced = 0;

	const char *comment;
	char tmp[100];
	int len, x;

	/*
	 * Owner.
	 */
	if (name_ctx != NULL && ns_samename(name_ctx, name) == 1) {
		T(addstr("\t\t\t", (size_t)3, &buf, &buflen));
	} else {
		len = (int)prune_origin(name, origin);
		if (*name == '\0') {
			goto root;
		} else if (len == 0) {
			T(addstr("@\t\t\t", (size_t)4, &buf, &buflen));
		} else {
			T(addstr(name, (size_t)len, &buf, &buflen));
			/* Origin not used or not root, and no trailing dot? */
			if (((origin == NULL || origin[0] == '\0') ||
			    (origin[0] != '.' && origin[1] != '\0' &&
			    name[len] == '\0')) && name[len - 1] != '.') {
 root:
				T(addstr(".", (size_t)1, &buf, &buflen));
				len++;
			}
			T(spaced = addtab((size_t)len, 24, spaced, &buf, &buflen));
		}
	}

	/*
	 * TTL, Class, Type.
	 */
	T(x = ns_format_ttl(ttl, buf, buflen));
	addlen((size_t)x, &buf, &buflen);
	len = snprintf(tmp, sizeof(tmp), " %s %s", p_class(class), p_type(type));
	T(addstr(tmp, (size_t)len, &buf, &buflen));
	T(spaced = addtab((size_t)(x + len), (size_t)16, spaced, &buf, &buflen));

	/*
	 * RData.
	 */
	switch (type) {
	case ns_t_a:
		if (rdlen != (size_t)NS_INADDRSZ)
			goto formerr;
		(void) inet_ntop(AF_INET, rdata, buf, (socklen_t)buflen);
		addlen(strlen(buf), &buf, &buflen);
		break;

	case ns_t_cname:
	case ns_t_mb:
	case ns_t_mg:
	case ns_t_mr:
	case ns_t_ns:
	case ns_t_ptr:
	case ns_t_dname:
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
		break;

	case ns_t_hinfo:
	case ns_t_isdn:
		/* First word. */
		T(len = charstr(rdata, edata, &buf, &buflen));
		if (len == 0)
			goto formerr;
		rdata += len;
		T(addstr(" ", (size_t)1, &buf, &buflen));


		/* Second word, optional in ISDN records. */
		if (type == ns_t_isdn && rdata == edata)
			break;

		T(len = charstr(rdata, edata, &buf, &buflen));
		if (len == 0)
			goto formerr;
		rdata += len;
		break;

	case ns_t_soa: {
		u_long t;

		/* Server name. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
		T(addstr(" ", (size_t)1, &buf, &buflen));

		/* Administrator name. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
		T(addstr(" (\n", (size_t)3, &buf, &buflen));
		spaced = 0;

		if ((edata - rdata) != 5*NS_INT32SZ)
			goto formerr;

		/* Serial number. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		T(addstr("\t\t\t\t\t", (size_t)5, &buf, &buflen));
		len = snprintf(tmp, sizeof(tmp), "%lu", t);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		T(spaced = addtab((size_t)len, (size_t)16, spaced, &buf, &buflen));
		T(addstr("; serial\n", (size_t)9, &buf, &buflen));
		spaced = 0;

		/* Refresh interval. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		T(addstr("\t\t\t\t\t", (size_t)5, &buf, &buflen));
		T(len = ns_format_ttl(t, buf, buflen));
		addlen((size_t)len, &buf, &buflen);
		T(spaced = addtab((size_t)len, (size_t)16, spaced, &buf, &buflen));
		T(addstr("; refresh\n", (size_t)10, &buf, &buflen));
		spaced = 0;

		/* Retry interval. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		T(addstr("\t\t\t\t\t", (size_t)5, &buf, &buflen));
		T(len = ns_format_ttl(t, buf, buflen));
		addlen((size_t)len, &buf, &buflen);
		T(spaced = addtab((size_t)len, (size_t)16, spaced, &buf, &buflen));
		T(addstr("; retry\n", (size_t)8, &buf, &buflen));
		spaced = 0;

		/* Expiry. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		T(addstr("\t\t\t\t\t", (size_t)5, &buf, &buflen));
		T(len = ns_format_ttl(t, buf, buflen));
		addlen((size_t)len, &buf, &buflen);
		T(spaced = addtab((size_t)len, (size_t)16, spaced, &buf, &buflen));
		T(addstr("; expiry\n", (size_t)9, &buf, &buflen));
		spaced = 0;

		/* Minimum TTL. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		T(addstr("\t\t\t\t\t", (size_t)5, &buf, &buflen));
		T(len = ns_format_ttl(t, buf, buflen));
		addlen((size_t)len, &buf, &buflen);
		T(addstr(" )", (size_t)2, &buf, &buflen));
		T(spaced = addtab((size_t)len, (size_t)16, spaced, &buf, &buflen));
		T(addstr("; minimum\n", (size_t)10, &buf, &buflen));

		break;
	    }

	case ns_t_mx:
	case ns_t_afsdb:
	case ns_t_rt:
	case ns_t_kx: {
		u_int t;

		if (rdlen < (size_t)NS_INT16SZ)
			goto formerr;

		/* Priority. */
		t = ns_get16(rdata);
		rdata += NS_INT16SZ;
		len = snprintf(tmp, sizeof(tmp), "%u ", t);
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* Target. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

		break;
	    }

	case ns_t_px: {
		u_int t;

		if (rdlen < (size_t)NS_INT16SZ)
			goto formerr;

		/* Priority. */
		t = ns_get16(rdata);
		rdata += NS_INT16SZ;
		len = snprintf(tmp, sizeof(tmp), "%u ", t);
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* Name1. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
		T(addstr(" ", (size_t)1, &buf, &buflen));

		/* Name2. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

		break;
	    }

	case ns_t_x25:
		T(len = charstr(rdata, edata, &buf, &buflen));
		if (len == 0)
			goto formerr;
		rdata += len;
		break;

	case ns_t_txt:
	case ns_t_spf:
		while (rdata < edata) {
			T(len = charstr(rdata, edata, &buf, &buflen));
			if (len == 0)
				goto formerr;
			rdata += len;
			if (rdata < edata)
				T(addstr(" ", (size_t)1, &buf, &buflen));
		}
		break;

	case ns_t_nsap: {
		char t[2+255*3];

		(void) inet_nsap_ntoa((int)rdlen, rdata, t);
		T(addstr(t, strlen(t), &buf, &buflen));
		break;
	    }

	case ns_t_aaaa:
		if (rdlen != (size_t)NS_IN6ADDRSZ)
			goto formerr;
		(void) inet_ntop(AF_INET6, rdata, buf, (socklen_t)buflen);
		addlen(strlen(buf), &buf, &buflen);
		break;

	case ns_t_loc: {
		char t[255];

		/* XXX protocol format checking? */
		(void) loc_ntoa(rdata, t, sizeof(t));
		T(addstr(t, strlen(t), &buf, &buflen));
		break;
	    }

	case ns_t_naptr: {
		u_int order, preference;
		char t[50];

		if (rdlen < 2U*NS_INT16SZ)
			goto formerr;

		/* Order, Precedence. */
		order = ns_get16(rdata);	rdata += NS_INT16SZ;
		preference = ns_get16(rdata);	rdata += NS_INT16SZ;
		len = snprintf(t, sizeof(t), "%u %u ", order, preference);
		T(addstr(t, (size_t)len, &buf, &buflen));

		/* Flags. */
		T(len = charstr(rdata, edata, &buf, &buflen));
		if (len == 0)
			goto formerr;
		rdata += len;
		T(addstr(" ", (size_t)1, &buf, &buflen));

		/* Service. */
		T(len = charstr(rdata, edata, &buf, &buflen));
		if (len == 0)
			goto formerr;
		rdata += len;
		T(addstr(" ", (size_t)1, &buf, &buflen));

		/* Regexp. */
		T(len = charstr(rdata, edata, &buf, &buflen));
		if (len < 0)
			return (-1);
		if (len == 0)
			goto formerr;
		rdata += len;
		T(addstr(" ", (size_t)1, &buf, &buflen));

		/* Server. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
		break;
	    }

	case ns_t_srv: {
		u_int priority, weight, port;
		char t[50];

		if (rdlen < 3U*NS_INT16SZ)
			goto formerr;

		/* Priority, Weight, Port. */
		priority = ns_get16(rdata);  rdata += NS_INT16SZ;
		weight   = ns_get16(rdata);  rdata += NS_INT16SZ;
		port     = ns_get16(rdata);  rdata += NS_INT16SZ;
		len = snprintf(t, sizeof(t), "%u %u %u ", priority, weight, port);
		T(addstr(t, (size_t)len, &buf, &buflen));

		/* Server. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
		break;
	    }

	case ns_t_minfo:
	case ns_t_rp:
		/* Name1. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
		T(addstr(" ", (size_t)1, &buf, &buflen));

		/* Name2. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

		break;

	case ns_t_wks: {
		int n, lcnt;

		if (rdlen < 1U + NS_INT32SZ)
			goto formerr;

		/* Address. */
		(void) inet_ntop(AF_INET, rdata, buf, (socklen_t)buflen);
		addlen(strlen(buf), &buf, &buflen);
		rdata += NS_INADDRSZ;

		/* Protocol. */
		len = snprintf(tmp, sizeof(tmp), " %u ( ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		rdata += NS_INT8SZ;

		/* Bit map. */
		n = 0;
		lcnt = 0;
		while (rdata < edata) {
			u_int c = *rdata++;
			do {
				if (c & 0200) {
					if (lcnt == 0) {
						T(addstr("\n\t\t\t\t", (size_t)5,
							 &buf, &buflen));
						lcnt = 10;
						spaced = 0;
					}
					len = snprintf(tmp, sizeof(tmp), "%d ", n);
					T(addstr(tmp, (size_t)len, &buf, &buflen));
					lcnt--;
				}
				c <<= 1;
			} while (++n & 07);
		}
		T(addstr(")", (size_t)1, &buf, &buflen));

		break;
	    }

	case ns_t_key:
	case ns_t_dnskey: {
		char base64_key[NS_MD5RSA_MAX_BASE64];
		u_int keyflags, protocol, algorithm, key_id;
		const char *leader;
		int n;

		if (rdlen < 0U + NS_INT16SZ + NS_INT8SZ + NS_INT8SZ)
			goto formerr;

		/* Key flags, Protocol, Algorithm. */
#ifndef _LIBC
		key_id = dst_s_dns_key_id(rdata, edata-rdata);
#else
		key_id = 0;
#endif
		keyflags = ns_get16(rdata);  rdata += NS_INT16SZ;
		protocol = *rdata++;
		algorithm = *rdata++;
		len = snprintf(tmp, sizeof(tmp), "0x%04x %u %u",
			       keyflags, protocol, algorithm);
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* Public key data. */
		len = b64_ntop(rdata, (size_t)(edata - rdata),
			       base64_key, sizeof base64_key);
		if (len < 0)
			goto formerr;
		if (len > 15) {
			T(addstr(" (", (size_t)2, &buf, &buflen));
			leader = "\n\t\t";
			spaced = 0;
		} else
			leader = " ";
		for (n = 0; n < len; n += 48) {
			T(addstr(leader, strlen(leader), &buf, &buflen));
			T(addstr(base64_key + n, (size_t)MIN(len - n, 48),
				 &buf, &buflen));
		}
		if (len > 15)
			T(addstr(" )", (size_t)2, &buf, &buflen));
		n = snprintf(tmp, sizeof(tmp), " ; key_tag= %u", key_id);
		T(addstr(tmp, (size_t)n, &buf, &buflen));

		break;
	    }

	case ns_t_sig:
	case ns_t_rrsig: {
		char base64_key[NS_MD5RSA_MAX_BASE64];
		u_int typ, algorithm, labels, footprint;
		const char *leader;
		u_long t;
		int n;

		if (rdlen < 22U)
			goto formerr;

		/* Type covered, Algorithm, Label count, Original TTL. */
	        typ = ns_get16(rdata);  rdata += NS_INT16SZ;
		algorithm = *rdata++;
		labels = *rdata++;
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		len = snprintf(tmp, sizeof(tmp), "%s %d %d %lu ",
			       p_type((int)typ), algorithm, labels, t);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		if (labels > (u_int)dn_count_labels(name))
			goto formerr;

		/* Signature expiry. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		len = snprintf(tmp, sizeof(tmp), "%s ", p_secstodate(t));
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* Time signed. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		len = snprintf(tmp, sizeof(tmp), "%s ", p_secstodate(t));
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* Signature Footprint. */
		footprint = ns_get16(rdata);  rdata += NS_INT16SZ;
		len = snprintf(tmp, sizeof(tmp), "%u ", footprint);
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* Signer's name. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

		/* Signature. */
		len = b64_ntop(rdata, (size_t)(edata - rdata),
			       base64_key, sizeof base64_key);
		if (len > 15) {
			T(addstr(" (", (size_t)2, &buf, &buflen));
			leader = "\n\t\t";
			spaced = 0;
		} else
			leader = " ";
		if (len < 0)
			goto formerr;
		for (n = 0; n < len; n += 48) {
			T(addstr(leader, strlen(leader), &buf, &buflen));
			T(addstr(base64_key + n, (size_t)MIN(len - n, 48),
				 &buf, &buflen));
		}
		if (len > 15)
			T(addstr(" )", (size_t)2, &buf, &buflen));
		break;
	    }

	case ns_t_nxt: {
		ptrdiff_t n, c;

		/* Next domain name. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

		/* Type bit map. */
		n = edata - rdata;
		for (c = 0; c < n*8; c++)
			if (NS_NXT_BIT_ISSET(c, rdata)) {
				len = snprintf(tmp, sizeof(tmp), " %s", p_type((int)c));
				T(addstr(tmp, (size_t)len, &buf, &buflen));
			}
		break;
	    }

	case ns_t_cert: {
		u_int c_type, key_tag, alg;
		int n;
		size_t siz;
		char base64_cert[8192], tmp1[40];
		const char *leader;

		c_type  = ns_get16(rdata); rdata += NS_INT16SZ;
		key_tag = ns_get16(rdata); rdata += NS_INT16SZ;
		alg = (u_int) *rdata++;

		len = snprintf(tmp1, sizeof(tmp1), "%d %d %d ", c_type, key_tag, alg);
		T(addstr(tmp1, (size_t)len, &buf, &buflen));
		siz = (edata-rdata)*4/3 + 4; /* "+4" accounts for trailing \0 */
		if (siz > sizeof(base64_cert) * 3/4) {
			const char *str = "record too long to print";
			T(addstr(str, strlen(str), &buf, &buflen));
		}
		else {
			len = b64_ntop(rdata, (size_t)(edata-rdata),
			    base64_cert, siz);

			if (len < 0)
				goto formerr;
			else if (len > 15) {
				T(addstr(" (", (size_t)2, &buf, &buflen));
				leader = "\n\t\t";
				spaced = 0;
			}
			else
				leader = " ";

			for (n = 0; n < len; n += 48) {
				T(addstr(leader, strlen(leader),
					 &buf, &buflen));
				T(addstr(base64_cert + n, (size_t)MIN(len - n, 48),
					 &buf, &buflen));
			}
			if (len > 15)
				T(addstr(" )", (size_t)2, &buf, &buflen));
		}
		break;
	    }

	case ns_t_tkey: {
		/* KJD - need to complete this */
		u_long t;
		int mode, err, keysize;

		/* Algorithm name. */
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
		T(addstr(" ", (size_t)1, &buf, &buflen));

		/* Inception. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		len = snprintf(tmp, sizeof(tmp), "%s ", p_secstodate(t));
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* Experation. */
		t = ns_get32(rdata);  rdata += NS_INT32SZ;
		len = snprintf(tmp, sizeof(tmp), "%s ", p_secstodate(t));
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* Mode , Error, Key Size. */
		/* Priority, Weight, Port. */
		mode = ns_get16(rdata);  rdata += NS_INT16SZ;
		err  = ns_get16(rdata);  rdata += NS_INT16SZ;
		keysize  = ns_get16(rdata);  rdata += NS_INT16SZ;
		len = snprintf(tmp, sizeof(tmp), "%u %u %u ", mode, err, keysize);
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		/* XXX need to dump key, print otherdata length & other data */
		break;
	    }

	case ns_t_tsig: {
		/* BEW - need to complete this */
		int n;

		T(len = addname(msg, msglen, &rdata, origin, &buf, &buflen));
		T(addstr(" ", (size_t)1, &buf, &buflen));
		rdata += 8; /* time */
		n = ns_get16(rdata); rdata += INT16SZ;
		rdata += n; /* sig */
		n = ns_get16(rdata); rdata += INT16SZ; /* original id */
		snprintf(buf, buflen, "%d", ns_get16(rdata));
		rdata += INT16SZ;
		addlen(strlen(buf), &buf, &buflen);
		break;
	    }

	case ns_t_a6: {
		struct in6_addr a;
		int pbyte, pbit;

		/* prefix length */
		if (rdlen == 0U) goto formerr;
		len = snprintf(tmp, sizeof(tmp), "%d ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		pbit = *rdata;
		if (pbit > 128) goto formerr;
		pbyte = (pbit & ~7) / 8;
		rdata++;

		/* address suffix: provided only when prefix len != 128 */
		if (pbit < 128) {
			if (rdata + pbyte >= edata) goto formerr;
			memset(&a, 0, sizeof(a));
			memcpy(&a.s6_addr[pbyte], rdata, sizeof(a) - pbyte);
			(void) inet_ntop(AF_INET6, &a, buf, (socklen_t)buflen);
			addlen(strlen(buf), &buf, &buflen);
			rdata += sizeof(a) - pbyte;
		}

		/* prefix name: provided only when prefix len > 0 */
		if (pbit == 0)
			break;
		if (rdata >= edata) goto formerr;
		T(addstr(" ", (size_t)1, &buf, &buflen));
		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

		break;
	    }

	case ns_t_opt: {
		len = snprintf(tmp, sizeof(tmp), "%u bytes", class);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		break;
	    }

	case ns_t_ds:
	case ns_t_dlv:
	case ns_t_sshfp: {
		u_int t;

		if (type == ns_t_ds || type == ns_t_dlv) {
			if (rdlen < 4U) goto formerr;
			t = ns_get16(rdata);
			rdata += NS_INT16SZ;
			len = snprintf(tmp, sizeof(tmp), "%u ", t);
			T(addstr(tmp, (size_t)len, &buf, &buflen));
		} else
			if (rdlen < 2U) goto formerr;

		len = snprintf(tmp, sizeof(tmp), "%u ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		rdata++;

		len = snprintf(tmp, sizeof(tmp), "%u ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		rdata++;

		while (rdata < edata) {
			len = snprintf(tmp, sizeof(tmp), "%02X", *rdata);
			T(addstr(tmp, (size_t)len, &buf, &buflen));
			rdata++;
		}
		break;
	    }

	case ns_t_nsec3:
	case ns_t_nsec3param: {
		u_int t, w, l, j, k, c;

		len = snprintf(tmp, sizeof(tmp), "%u ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		rdata++;

		len = snprintf(tmp, sizeof(tmp), "%u ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		rdata++;

		t = ns_get16(rdata);
		rdata += NS_INT16SZ;
		len = snprintf(tmp, sizeof(tmp), "%u ", t);
		T(addstr(tmp, (size_t)len, &buf, &buflen));

		t = *rdata++;
		if (t == 0) {
			T(addstr("-", 1, &buf, &buflen));
		} else {
			while (t-- > 0) {
				len = snprintf(tmp, sizeof(tmp), "%02X", *rdata);
				T(addstr(tmp, (size_t)len, &buf, &buflen));
				rdata++;
			}
		}
		if (type == ns_t_nsec3param)
			break;
		T(addstr(" ", 1, &buf, &buflen));

		t = *rdata++;
		while (t > 0) {
			switch (t) {
			case 1:
				tmp[0] = base32hex[(((uint32_t)rdata[0]>>3)&0x1f)];
				tmp[1] = base32hex[(((uint32_t)rdata[0]<<2)&0x1c)];
				tmp[2] = tmp[3] = tmp[4] = '=';
				tmp[5] = tmp[6] = tmp[7] = '=';
				break;
			case 2:
				tmp[0] = base32hex[(((uint32_t)rdata[0]>>3)&0x1f)];
				tmp[1] = base32hex[(((uint32_t)rdata[0]<<2)&0x1c)|
						   (((uint32_t)rdata[1]>>6)&0x03)];
				tmp[2] = base32hex[(((uint32_t)rdata[1]>>1)&0x1f)];
				tmp[3] = base32hex[(((uint32_t)rdata[1]<<4)&0x10)];
				tmp[4] = tmp[5] = tmp[6] = tmp[7] = '=';
				break;
			case 3:
				tmp[0] = base32hex[(((uint32_t)rdata[0]>>3)&0x1f)];
				tmp[1] = base32hex[(((uint32_t)rdata[0]<<2)&0x1c)|
						   (((uint32_t)rdata[1]>>6)&0x03)];
				tmp[2] = base32hex[(((uint32_t)rdata[1]>>1)&0x1f)];
				tmp[3] = base32hex[(((uint32_t)rdata[1]<<4)&0x10)|
						   (((uint32_t)rdata[2]>>4)&0x0f)];
				tmp[4] = base32hex[(((uint32_t)rdata[2]<<1)&0x1e)];
				tmp[5] = tmp[6] = tmp[7] = '=';
				break;
			case 4:
				tmp[0] = base32hex[(((uint32_t)rdata[0]>>3)&0x1f)];
				tmp[1] = base32hex[(((uint32_t)rdata[0]<<2)&0x1c)|
						   (((uint32_t)rdata[1]>>6)&0x03)];
				tmp[2] = base32hex[(((uint32_t)rdata[1]>>1)&0x1f)];
				tmp[3] = base32hex[(((uint32_t)rdata[1]<<4)&0x10)|
						   (((uint32_t)rdata[2]>>4)&0x0f)];
				tmp[4] = base32hex[(((uint32_t)rdata[2]<<1)&0x1e)|
						   (((uint32_t)rdata[3]>>7)&0x01)];
				tmp[5] = base32hex[(((uint32_t)rdata[3]>>2)&0x1f)];
				tmp[6] = base32hex[((uint32_t)rdata[3]<<3)&0x18];
				tmp[7] = '=';
				break;
			default:
				tmp[0] = base32hex[(((uint32_t)rdata[0]>>3)&0x1f)];
				tmp[1] = base32hex[(((uint32_t)rdata[0]<<2)&0x1c)|
						   (((uint32_t)rdata[1]>>6)&0x03)];
				tmp[2] = base32hex[(((uint32_t)rdata[1]>>1)&0x1f)];
				tmp[3] = base32hex[(((uint32_t)rdata[1]<<4)&0x10)|
						   (((uint32_t)rdata[2]>>4)&0x0f)];
				tmp[4] = base32hex[(((uint32_t)rdata[2]<<1)&0x1e)|
						   (((uint32_t)rdata[3]>>7)&0x01)];
				tmp[5] = base32hex[(((uint32_t)rdata[3]>>2)&0x1f)];
				tmp[6] = base32hex[(((uint32_t)rdata[3]<<3)&0x18)|
						   (((uint32_t)rdata[4]>>5)&0x07)];
				tmp[7] = base32hex[(rdata[4]&0x1f)];
				break;
			}
			T(addstr(tmp, 8, &buf, &buflen));
			if (t >= 5) {
				rdata += 5;
				t -= 5;
			} else {
				rdata += t;
				t -= t;
			}
		}

		while (rdata < edata) {
			w = *rdata++;
			l = *rdata++;
			for (j = 0; j < l; j++) {
				if (rdata[j] == 0)
					continue;
				for (k = 0; k < 8; k++) {
					if ((rdata[j] & (0x80 >> k)) == 0)
						continue;
					c = w * 256 + j * 8 + k;
					len = snprintf(tmp, sizeof(tmp), " %s", p_type((ns_type)c));
					T(addstr(tmp, (size_t)len, &buf, &buflen));
				}
			}
			rdata += l;
		}
		break;
	    }

	case ns_t_nsec: {
		u_int w, l, j, k, c;

		T(addname(msg, msglen, &rdata, origin, &buf, &buflen));

		while (rdata < edata) {
			w = *rdata++;
			l = *rdata++;
			for (j = 0; j < l; j++) {
				if (rdata[j] == 0)
					continue;
				for (k = 0; k < 8; k++) {
					if ((rdata[j] & (0x80 >> k)) == 0)
						continue;
					c = w * 256 + j * 8 + k;
					len = snprintf(tmp, sizeof(tmp), " %s", p_type((ns_type)c));
					T(addstr(tmp, (size_t)len, &buf, &buflen));
				}
			}
			rdata += l;
		}
		break;
	    }

	case ns_t_dhcid: {
		int n;
		unsigned int siz;
		char base64_dhcid[8192];
		const char *leader;

		siz = (int)(edata-rdata)*4/3 + 4; /* "+4" accounts for trailing \0 */
		if (siz > sizeof(base64_dhcid) * 3/4) {
			const char *str = "record too long to print";
			T(addstr(str, strlen(str), &buf, &buflen));
		} else {
			len = b64_ntop(rdata, (size_t)(edata-rdata),
			    base64_dhcid, siz);

			if (len < 0)
				goto formerr;

			else if (len > 15) {
				T(addstr(" (", 2, &buf, &buflen));
				leader = "\n\t\t";
				spaced = 0;
			}
			else
				leader = " ";

			for (n = 0; n < len; n += 48) {
				T(addstr(leader, strlen(leader),
					 &buf, &buflen));
				T(addstr(base64_dhcid + n,
				    (size_t)MIN(len - n, 48), &buf, &buflen));
			}
			if (len > 15)
				T(addstr(" )", 2, &buf, &buflen));
		}
		break;
	}

	case ns_t_ipseckey: {
		int n;
		unsigned int siz;
		char base64_key[8192];
		const char *leader;

		if (rdlen < 2)
			goto formerr;

		switch (rdata[1]) {
		case 0:
		case 3:
			if (rdlen < 3)
				goto formerr;
			break;
		case 1:
			if (rdlen < 7)
				goto formerr;
			break;
		case 2:
			if (rdlen < 19)
				goto formerr;
			break;
		default:
			comment = "unknown IPSECKEY gateway type";
			goto hexify;
		}

		len = snprintf(tmp, sizeof(tmp), "%u ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		rdata++;

		len = snprintf(tmp, sizeof(tmp), "%u ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		rdata++;

		len = snprintf(tmp, sizeof(tmp), "%u ", *rdata);
		T(addstr(tmp, (size_t)len, &buf, &buflen));
		rdata++;

		switch (rdata[-2]) {
		case 0:
			T(addstr(".", 1, &buf, &buflen));
			break;
		case 1:
			(void) inet_ntop(AF_INET, rdata, buf, (socklen_t)buflen);
			addlen(strlen(buf), &buf, &buflen);
			rdata += 4;
			break;
		case 2:
			(void) inet_ntop(AF_INET6, rdata, buf, (socklen_t)buflen);
			addlen(strlen(buf), &buf, &buflen);
			rdata += 16;
			break;
		case 3:
			T(addname(msg, msglen, &rdata, origin, &buf, &buflen));
			break;
		}

		if (rdata >= edata)
			break;

		siz = (int)(edata-rdata)*4/3 + 4; /* "+4" accounts for trailing \0 */
		if (siz > sizeof(base64_key) * 3/4) {
			const char *str = "record too long to print";
			T(addstr(str, strlen(str), &buf, &buflen));
		} else {
			len = b64_ntop(rdata, (size_t)(edata-rdata),
			    base64_key, siz);

			if (len < 0)
				goto formerr;

			else if (len > 15) {
				T(addstr(" (", 2, &buf, &buflen));
				leader = "\n\t\t";
				spaced = 0;
			}
			else
				leader = " ";

			for (n = 0; n < len; n += 48) {
				T(addstr(leader, strlen(leader),
					 &buf, &buflen));
				T(addstr(base64_key + n,
				    (size_t)MIN(len - n, 48), &buf, &buflen));
			}
			if (len > 15)
				T(addstr(" )", 2, &buf, &buflen));
		}
		break;
	}

	case ns_t_hip: {
		unsigned int i, hip_len, algorithm, key_len;
		char base64_key[NS_MD5RSA_MAX_BASE64];
		unsigned int siz;
		const char *leader = "\n\t\t\t\t\t";

		hip_len = *rdata++;
		algorithm = *rdata++;
		key_len = ns_get16(rdata);
		rdata += NS_INT16SZ;

		siz = key_len*4/3 + 4; /* "+4" accounts for trailing \0 */
		if (siz > sizeof(base64_key) * 3/4) {
			const char *str = "record too long to print";
			T(addstr(str, strlen(str), &buf, &buflen));
		} else {
			len = snprintf(tmp, sizeof(tmp), "( %u ", algorithm);
			T(addstr(tmp, (size_t)len, &buf, &buflen));

			for (i = 0; i < hip_len; i++) {
				len = snprintf(tmp, sizeof(tmp), "%02X", *rdata);
				T(addstr(tmp, (size_t)len, &buf, &buflen));
				rdata++;
			}
			T(addstr(leader, strlen(leader), &buf, &buflen));

			len = b64_ntop(rdata, key_len, base64_key, siz);
			if (len < 0)
				goto formerr;

			T(addstr(base64_key, (size_t)len, &buf, &buflen));

			rdata += key_len;
			while (rdata < edata) {
				T(addstr(leader, strlen(leader), &buf, &buflen));
				T(addname(msg, msglen, &rdata, origin,
					  &buf, &buflen));
			}
			T(addstr(" )", 2, &buf, &buflen));
		}
		break;
	    }

	default:
		comment = "unknown RR type";
		goto hexify;
	}
	_DIAGASSERT(__type_fit(int, buf - obuf));
	return (int)(buf - obuf);
 formerr:
	comment = "RR format error";
 hexify: {
	int n, m;
	char *p;

	len = snprintf(tmp, sizeof(tmp), "\\# %u%s\t; %s", (unsigned)(edata - rdata),
		       rdlen != 0U ? " (" : "", comment);
	T(addstr(tmp, (size_t)len, &buf, &buflen));
	while (rdata < edata) {
		p = tmp;
		p += snprintf(p, sizeof(tmp), "\n\t");
		spaced = 0;
		n = MIN(16, (int)(edata - rdata));
		for (m = 0; m < n; m++)
			p += snprintf(p, sizeof(tmp) - (p - tmp), "%02x ", rdata[m]);
		T(addstr(tmp, (size_t)(p - tmp), &buf, &buflen));
		if (n < 16) {
			T(addstr(")", (size_t)1, &buf, &buflen));
			T(addtab((size_t)(p - tmp + 1), (size_t)48, spaced, &buf, &buflen));
		}
		p = tmp;
		p += snprintf(p, sizeof(tmp), "; ");
		for (m = 0; m < n; m++)
			*p++ = (isascii(rdata[m]) && isprint(rdata[m]))
				? rdata[m]
				: '.';
		T(addstr(tmp, (size_t)(p - tmp), &buf, &buflen));
		rdata += n;
	}
	_DIAGASSERT(__type_fit(int, buf - obuf));
	return (int)(buf - obuf);
    }
}

/* Private. */

/*
 * size_t
 * prune_origin(name, origin)
 *	Find out if the name is at or under the current origin.
 * return:
 *	Number of characters in name before start of origin,
 *	or length of name if origin does not match.
 * notes:
 *	This function should share code with samedomain().
 */
static size_t
prune_origin(const char *name, const char *origin) {
	const char *oname = name;

	while (*name != '\0') {
		if (origin != NULL && ns_samename(name, origin) == 1)
			return (name - oname - (name > oname));
		while (*name != '\0') {
			if (*name == '\\') {
				name++;
				/* XXX need to handle \nnn form. */
				if (*name == '\0')
					break;
			} else if (*name == '.') {
				name++;
				break;
			}
			name++;
		}
	}
	return (name - oname);
}

/*
 * int
 * charstr(rdata, edata, buf, buflen)
 *	Format a <character-string> into the presentation buffer.
 * return:
 *	Number of rdata octets consumed
 *	0 for protocol format error
 *	-1 for output buffer error
 * side effects:
 *	buffer is advanced on success.
 */
static int
charstr(const u_char *rdata, const u_char *edata, char **buf, size_t *buflen) {
	const u_char *odata = rdata;
	size_t save_buflen = *buflen;
	char *save_buf = *buf;

	if (addstr("\"", (size_t)1, buf, buflen) < 0)
		goto enospc;
	if (rdata < edata) {
		int n = *rdata;

		if (rdata + 1 + n <= edata) {
			rdata++;
			while (n-- > 0) {
				if (strchr("\n\"\\", *rdata) != NULL)
					if (addstr("\\", (size_t)1, buf, buflen) < 0)
						goto enospc;
				if (addstr((const char *)rdata, (size_t)1,
					   buf, buflen) < 0)
					goto enospc;
				rdata++;
			}
		}
	}
	if (addstr("\"", (size_t)1, buf, buflen) < 0)
		goto enospc;
	_DIAGASSERT(__type_fit(int, rdata - odata));
	return (int)(rdata - odata);
 enospc:
	errno = ENOSPC;
	*buf = save_buf;
	*buflen = save_buflen;
	return (-1);
}

static int
addname(const u_char *msg, size_t msglen,
	const u_char **pp, const char *origin,
	char **buf, size_t *buflen)
{
	size_t newlen, save_buflen = *buflen;
	char *save_buf = *buf;
	int n;

	n = dn_expand(msg, msg + msglen, *pp, *buf, (int)*buflen);
	if (n < 0)
		goto enospc;	/* Guess. */
	newlen = prune_origin(*buf, origin);
	if (**buf == '\0') {
		goto root;
	} else if (newlen == 0U) {
		/* Use "@" instead of name. */
		if (newlen + 2 > *buflen)
			goto enospc;        /* No room for "@\0". */
		(*buf)[newlen++] = '@';
		(*buf)[newlen] = '\0';
	} else {
		if (((origin == NULL || origin[0] == '\0') ||
		    (origin[0] != '.' && origin[1] != '\0' &&
		    (*buf)[newlen] == '\0')) && (*buf)[newlen - 1] != '.') {
			/* No trailing dot. */
 root:
			if (newlen + 2 > *buflen)
				goto enospc;	/* No room for ".\0". */
			(*buf)[newlen++] = '.';
			(*buf)[newlen] = '\0';
		}
	}
	*pp += n;
	addlen(newlen, buf, buflen);
	**buf = '\0';
	_DIAGASSERT(__type_fit(int, newlen));
	return (int)newlen;
 enospc:
	errno = ENOSPC;
	*buf = save_buf;
	*buflen = save_buflen;
	return (-1);
}

static void
addlen(size_t len, char **buf, size_t *buflen) {
	assert(len <= *buflen);
	*buf += len;
	*buflen -= len;
}

static int
addstr(const char *src, size_t len, char **buf, size_t *buflen) {
	if (len >= *buflen) {
		errno = ENOSPC;
		return (-1);
	}
	memcpy(*buf, src, len);
	addlen(len, buf, buflen);
	**buf = '\0';
	return (0);
}

static int
addtab(size_t len, size_t target, int spaced, char **buf, size_t *buflen) {
	size_t save_buflen = *buflen;
	char *save_buf = *buf;
	ptrdiff_t t;

	if (spaced || len >= target - 1) {
		T(addstr("  ", (size_t)2, buf, buflen));
		spaced = 1;
	} else {
		for (t = (target - len - 1) / 8; t >= 0; t--)
			if (addstr("\t", (size_t)1, buf, buflen) < 0) {
				*buflen = save_buflen;
				*buf = save_buf;
				return (-1);
			}
		spaced = 0;
	}
	return (spaced);
}
```