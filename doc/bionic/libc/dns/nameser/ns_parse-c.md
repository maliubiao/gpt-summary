Response:
Let's break down the thought process for analyzing the `ns_parse.c` file.

1. **Understanding the Request:** The core request is to analyze the functionality of this C file, considering its role in Android's Bionic library. This means identifying its purpose, how it interacts with the Android ecosystem, and any potential developer pitfalls. Specific areas of interest are libc functions, dynamic linking, error handling, and its place within the Android framework.

2. **Initial Skim and High-Level Understanding:**  The file starts with copyright information related to ISC (Internet Systems Consortium) and mentions NetBSD. This suggests it's likely based on or derived from standard DNS parsing code. The `#include` directives immediately give clues: `<sys/types.h>`, `<netinet/in.h>`, `<arpa/nameser.h>`, `<resolv.h>`, and the conditional `#include "resolv_private.h"` (for Android). These headers strongly indicate this file deals with parsing DNS messages.

3. **Identifying Key Data Structures:** The `ns_msg` and `ns_rr` (and `ns_rr2`) structures are central. The comments and the code using them reveal their purpose: `ns_msg` represents a parsed DNS message, and `ns_rr` represents a resource record within that message. The `_ns_flagdata` array is clearly used for accessing individual flags in the DNS message header.

4. **Analyzing Public Functions:** The function names provide significant insight:
    * `ns_msg_getflag`:  Extracts a specific flag from the DNS message header.
    * `ns_skiprr`: Skips over a specified number of resource records. This is useful for navigating the different sections of a DNS message.
    * `ns_initparse`:  Initializes an `ns_msg` structure by parsing the header and identifying the starting points of each section (question, answer, authority, additional).
    * `ns_parserr`: Parses a single resource record from a specified section.
    * `ns_parserr2`: Similar to `ns_parserr`, but it uses `ns_name_unpack2`, implying it handles uncompressed domain names differently.

5. **Analyzing Private Functions:** The `setsection` function is clearly an internal helper function. Its purpose is to move the parsing context within the `ns_msg` structure to a specific section of the DNS message.

6. **Understanding the Role of Macros:** The `RETERR` macro simplifies error handling by setting `errno` and returning -1.

7. **Connecting to Android:** The `#ifdef ANDROID_CHANGES` block is a key indicator of Android-specific modifications. The inclusion of `"resolv_private.h"` suggests Android's DNS resolver implementation might have internal details not present in standard `resolv.h`.

8. **Explaining Libc Functions:** The request specifically asks for explanations of libc functions. This requires examining how functions like `dn_skipname`, `dn_expand`, `NS_GET16`, `NS_GET32`, and `memcpy` (implicitly used within `ns_name_unpack2`) are used and what they achieve in the context of DNS parsing.

9. **Addressing Dynamic Linking:** Since this is part of Bionic, the dynamic linker is relevant. The thought process here is to consider how this code might be used within a larger Android process. It would likely be part of a shared library (like `libc.so`) that other parts of Android link against. The example SO layout and linking process illustrate this.

10. **Considering User Errors:**  Thinking about how a developer might misuse these functions is crucial. Incorrectly providing message lengths, trying to access out-of-bounds data, or misunderstanding the section structure are potential pitfalls. The examples of `ns_initparse` and `ns_parserr` illustrate these.

11. **Tracing the Call Stack (Android Framework/NDK):**  This requires knowledge of the Android networking stack. Starting from a high level (an app making a network request), one can trace down to the system calls related to DNS resolution. This involves thinking about `getaddrinfo`, the `netd` daemon, and eventually the libc resolver functions.

12. **Frida Hooking:**  To debug this code, Frida is a natural choice. The examples demonstrate how to hook the key functions and inspect their arguments and return values. This allows for observing the actual DNS message being processed.

13. **Structuring the Answer:**  Organizing the information logically is essential for a clear and comprehensive answer. Using headings and bullet points helps to break down the different aspects of the analysis.

14. **Refinement and Detail:**  After the initial draft, it's important to review and add details. For example, explaining the endianness considerations with `NS_GET16` and `NS_GET32`, or providing more specific examples of user errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the NetBSD origins might be a distraction. While it's important background, the focus should be on its role within *Android*.
* **Realization:**  The `ns_name_unpack2` function is significant and needs proper explanation, especially its handling of uncompressed names.
* **Adding clarity:** The explanation of `setsection` needs to highlight its role in managing the internal parsing state.
* **Improving examples:**  The user error examples could be more concrete and illustrate the consequences of the error.
* **Strengthening the Android integration:**  Explicitly mentioning `getaddrinfo` and `netd` helps connect the file to the broader Android system.

By following these steps, iteratively refining the understanding, and focusing on the specific requirements of the prompt, the comprehensive analysis provided earlier can be generated.
好的，让我们详细分析一下 `bionic/libc/dns/nameser/ns_parse.c` 这个文件。

**功能概述:**

`ns_parse.c` 文件是 Android Bionic 库中用于解析 DNS 消息的核心组件。它提供了一系列函数，用于将接收到的 DNS 响应消息（通常是二进制数据流）解析成结构化的数据，方便应用程序访问和处理其中的信息。

具体来说，它的主要功能包括：

1. **初始化解析器:** `ns_initparse()` 函数用于初始化一个 `ns_msg` 结构体，该结构体代表一个待解析的 DNS 消息。它会解析消息头部，提取消息 ID、标志位和各个节（Section）的记录数，并记录各个节的起始位置。
2. **解析标志位:** `ns_msg_getflag()` 函数用于从 `ns_msg` 结构体中提取特定的 DNS 标志位（如 QR, Opcode, AA, TC, RD, RA 等）。
3. **跳过资源记录:** `ns_skiprr()` 函数用于跳过指定节中的若干个资源记录（Resource Record）。这在只需要解析特定 RR 时非常有用，可以避免解析不关心的部分。
4. **解析资源记录:** `ns_parserr()` 和 `ns_parserr2()` 函数用于解析指定节中的单个资源记录，并将解析结果存储到 `ns_rr` 或 `ns_rr2` 结构体中。`ns_parserr` 使用压缩域名格式，而 `ns_parserr2` 使用非压缩域名格式。

**与 Android 功能的关系及举例说明:**

这个文件是 Android 网络功能的重要组成部分，直接影响到 DNS 解析的效率和正确性。Android 应用程序在进行网络通信时，经常需要将域名解析为 IP 地址。这个过程涉及到向 DNS 服务器发送查询请求，并接收服务器返回的响应消息。`ns_parse.c` 中的函数就是用来解析这些响应消息的。

**举例说明:**

当一个 Android 应用尝试访问 `www.google.com` 时，系统会进行以下（简化的）步骤：

1. **发起 DNS 查询:** Android 系统会构造一个 DNS 查询消息，包含要查询的域名 `www.google.com` 和请求的记录类型（如 A 记录）。
2. **发送查询请求:** 这个请求会通过网络发送到配置的 DNS 服务器。
3. **接收 DNS 响应:** DNS 服务器返回一个包含 `www.google.com` 对应 IP 地址的响应消息。这个消息是以二进制数据流的形式存在的。
4. **解析响应消息:** Android 的 DNS 解析器会调用 `ns_initparse()` 初始化解析器，然后调用 `ns_parserr()` 或 `ns_parserr2()` 来解析响应消息中的各个资源记录，提取出 `www.google.com` 对应的 IP 地址。
5. **建立连接:** 应用程序使用解析得到的 IP 地址与 `www.google.com` 的服务器建立连接。

**详细解释每一个 libc 函数的功能是如何实现的:**

这里列举 `ns_parse.c` 中使用的一些关键 libc 函数，并解释其功能：

* **`dn_skipname(const u_char *ptr, const u_char *eom)`:**  这个函数用于跳过 DNS 消息中的一个域名。DNS 域名可以采用压缩格式，其中一部分域名可以通过指针指向消息中之前出现过的相同域名来节省空间。`dn_skipname` 会处理这种压缩格式，返回跳过的域名所占的字节数。如果遇到格式错误或超出消息末尾，则返回 -1。
    * **实现原理:** 它会遍历域名标签，每个标签以一个字节表示长度，后面跟着对应长度的字符。如果遇到压缩指针（以 `0xC0` 开头的两个字节），则跳到指针指向的位置继续解析。
* **`dn_expand(const u_char *msg, const u_char *eom, const u_char *comp_dn, char *exp_dn, int length)`:** 这个函数用于展开 DNS 消息中压缩的域名。它将 `comp_dn` 指向的压缩域名展开成可读的字符串格式，并存储到 `exp_dn` 缓冲区中，最大长度为 `length`。
    * **实现原理:** 它会检查 `comp_dn` 指向的数据是否为压缩指针。如果是，则跳转到指针指向的位置继续解析。否则，它会读取域名标签的长度和字符，并将字符复制到 `exp_dn` 中，直到遇到空标签或错误。
* **`memcpy(void *dest, const void *src, size_t n)` (隐式使用):**  `ns_name_unpack2` 函数内部会使用 `memcpy` 或类似的内存复制操作，将域名数据从 DNS 消息缓冲区复制到目标缓冲区。
    * **实现原理:** `memcpy` 是一个基本的内存复制函数，它将 `src` 指向的 `n` 个字节复制到 `dest` 指向的内存区域。
* **`NS_GET16(u_int16_t value, const u_char *p)` 和 `NS_GET32(u_int32_t value, const u_char *p)`:** 这不是标准的 libc 函数，而是 `arpa/nameser.h` 中定义的宏，用于从网络字节序的缓冲区中读取 16 位和 32 位整数，并将其转换为本地字节序。
    * **实现原理:** 这些宏通常会调用底层的字节序转换函数，例如 `ntohs()` (network to host short) 和 `ntohl()` (network to host long)。这些函数会将网络字节序（大端序）的整数转换为主机字节序。

**涉及 dynamic linker 的功能及 so 布局样本和链接处理过程:**

`ns_parse.c` 编译后会成为 `libc.so` 动态链接库的一部分。当 Android 应用程序需要解析 DNS 消息时，它会调用 `libc.so` 中提供的 DNS 解析相关函数，这些函数最终会调用 `ns_parse.c` 中的函数。

**so 布局样本 (简化):**

```
libc.so:
    ...
    .text:  // 代码段
        ns_initparse:
            ...
        ns_msg_getflag:
            ...
        ns_skiprr:
            ...
        ns_parserr:
            ...
        ns_parserr2:
            ...
    .rodata: // 只读数据段
        _ns_flagdata:
            ...
    ...
```

**链接处理过程:**

1. **编译时链接:** 当应用程序使用 NDK 或 SDK 编译时，链接器会将应用程序代码与所需的系统库（如 `libc.so`）链接起来。这会在应用程序的可执行文件中记录下对 `libc.so` 中特定符号（函数）的依赖。
2. **运行时链接:** 当应用程序启动时，Android 的动态链接器 (`linker64` 或 `linker`) 会加载应用程序及其依赖的共享库。
3. **符号查找:** 当应用程序调用 `ns_initparse` 等函数时，动态链接器会根据应用程序中的符号引用，在已加载的共享库 (`libc.so`) 中查找对应的函数地址。
4. **重定位:**  由于共享库在内存中的加载地址可能每次都不同，动态链接器需要对代码中的某些地址进行调整，使其指向正确的内存位置。
5. **执行:** 找到函数地址后，程序控制流会跳转到 `libc.so` 中 `ns_initparse` 函数的代码开始执行。

**逻辑推理、假设输入与输出:**

**假设输入:**  一个包含 DNS A 记录响应的二进制数据流。

```
// 假设的 DNS 响应消息 (简化，网络字节序)
unsigned char response[] = {
    0x12, 0x34, // Transaction ID
    0x81, 0x80, // Flags (Response, Authoritative Answer, Recursion Desired, Recursion Available)
    0x00, 0x01, // Questions Count: 1
    0x00, 0x01, // Answer RRs Count: 1
    0x00, 0x00, // Authority RRs Count: 0
    0x00, 0x00, // Additional RRs Count: 0
    // Question Section
    0x03, 'w', 'w', 'w', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, // Name: www.google.com
    0x00, 0x01, // Type: A (Address)
    0x00, 0x01, // Class: IN (Internet)
    // Answer Section
    0xc0, 0x0c, // Name: Pointer to Question Name (压缩)
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
    0x00, 0x00, 0x0e, 0x10, // TTL: 3600 秒
    0x00, 0x04, // RDLength: 4
    0xac, 0xd9, 0x01, 0x0a  // RData: 172.217.1.10 (IP 地址)
};
```

**逻辑推理和输出:**

1. **`ns_initparse(response, sizeof(response), &msg)`:** 初始化 `ns_msg` 结构体 `msg`。
   * `msg._id` 将被设置为 `0x1234`。
   * `msg._flags` 将被设置为 `0x8180`。
   * `msg._counts[ns_s_qd]` (Question Count) 将被设置为 1。
   * `msg._counts[ns_s_an]` (Answer Count) 将被设置为 1。
   * `msg._sections[ns_s_qd]` 将指向 Question Section 的起始位置。
   * `msg._sections[ns_s_an]` 将指向 Answer Section 的起始位置。

2. **`ns_parserr(&msg, ns_s_an, 0, &rr)`:** 解析 Answer Section 的第一个 RR。
   * `rr.name` 将被设置为 `"www.google.com"` (通过展开压缩域名得到)。
   * `rr.type` 将被设置为 `1` (A 记录)。
   * `rr.rr_class` 将被设置为 `1` (IN 类)。
   * `rr.ttl` 将被设置为 `3600`。
   * `rr.rdlength` 将被设置为 `4`。
   * `rr.rdata` 将指向包含 IP 地址 `172.217.1.10` 的 4 字节数据。

**用户或编程常见的使用错误:**

1. **提供的消息长度不正确:** 如果传递给 `ns_initparse` 的 `msglen` 参数小于实际消息的长度，会导致解析过程中读取超出缓冲区范围的数据，引发崩溃或安全漏洞。
   ```c
   unsigned char response[100]; // 假设实际长度大于 100
   int response_len = actual_length;
   ns_msg msg;
   if (ns_initparse(response, 100, &msg) == -1) { // 错误：使用了固定长度 100
       perror("ns_initparse failed");
   }
   ```
2. **尝试访问不存在的 RR:** 在解析特定节的 RR 时，如果指定的 `rrnum` 超出该节的 RR 数量，`ns_parserr` 会返回错误。
   ```c
   ns_msg msg;
   // ... 初始化 msg ...
   if (msg._counts[ns_s_an] > 0) {
       ns_rr rr;
       if (ns_parserr(&msg, ns_s_an, msg._counts[ns_s_an], &rr) == -1) { // 错误：尝试访问索引超出范围的 RR
           perror("ns_parserr failed");
       }
   }
   ```
3. **未正确处理返回值:**  `ns_initparse` 和 `ns_parserr` 等函数在失败时会返回 `-1` 并设置 `errno`。程序员应该检查返回值并根据 `errno` 进行错误处理。
   ```c
   ns_msg msg;
   if (ns_initparse(response, response_len, &msg) == -1) {
       perror("ns_initparse failed");
       // 进一步处理错误，例如记录日志或退出程序
   }
   ```
4. **假设固定的消息结构:** DNS 消息的结构可能会因为不同的查询类型或服务器实现而有所不同。程序员应该根据 `ns_msg` 中的计数信息动态地解析各个节，而不是假设固定的结构。

**说明 Android framework 或 NDK 是如何一步步到达这里的，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 发起 DNS 查询:**
   - 当应用程序需要进行网络通信时，例如使用 `java.net.InetAddress.getByName()` 或 OkHttp 等网络库，Android Framework 会调用底层的网络组件。
   - Framework 会通过 Socket 连接到 `netd` 守护进程。
   - `netd` 负责处理网络相关的操作，包括 DNS 解析。

2. **`netd` 进程处理 DNS 查询:**
   - `netd` 接收到来自 Framework 的 DNS 查询请求。
   - `netd` 内部的 DNS 解析器会构造 DNS 查询消息。
   - `netd` 将查询消息发送到配置的 DNS 服务器。
   - `netd` 接收 DNS 服务器返回的响应消息。

3. **Bionic libc 的 DNS 解析函数被调用:**
   - `netd` 接收到 DNS 响应后，会将响应数据传递给 Bionic libc 提供的 DNS 解析函数，例如 `res_nparserr` 或类似的函数（这些函数最终会调用 `ns_parse.c` 中的函数）。
   - 这些函数会调用 `ns_initparse` 初始化解析器，然后根据响应消息的结构调用 `ns_parserr` 或 `ns_parserr2` 来解析各个资源记录。

4. **解析结果返回:**
   - 解析完成后，libc 的 DNS 解析函数会将解析结果返回给 `netd`。
   - `netd` 再将解析结果返回给 Android Framework。
   - Framework 最终将 IP 地址返回给应用程序。

**Frida Hook 示例:**

可以使用 Frida Hook `ns_initparse` 和 `ns_parserr` 函数，来观察 DNS 消息的解析过程。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    package_name = "your.target.app"  # 替换为你的目标应用包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
        sys.exit(1)

    script_source = """
        Interceptor.attach(Module.findExportByName("libc.so", "ns_initparse"), {
            onEnter: function(args) {
                console.log("[+] ns_initparse called");
                this.msg = args[0];
                this.msglen = args[1].toInt();
                console.log("    Message Length:", this.msglen);
                // 可以打印消息内容 (注意：可能会很大)
                // var buffer = Memory.readByteArray(this.msg, this.msglen);
                // console.log("    Message:", hexdump(buffer, { ansi: true }));
            },
            onLeave: function(retval) {
                console.log("[+] ns_initparse returned:", retval);
            }
        });

        Interceptor.attach(Module.findExportByName("libc.so", "ns_parserr"), {
            onEnter: function(args) {
                console.log("[+] ns_parserr called");
                this.handle = args[0];
                this.section = args[1].toInt();
                this.rrnum = args[2].toInt();
                console.log("    Section:", this.section);
                console.log("    RR Number:", this.rrnum);
            },
            onLeave: function(retval) {
                console.log("[+] ns_parserr returned:", retval);
                if (retval == 0) {
                    var rr = ptr(this.args[3]);
                    var namePtr = rr.readPointer();
                    var type = rr.add(Process.pointerSize).readU16();
                    var klass = rr.add(Process.pointerSize + 2).readU16();
                    var ttl = rr.add(Process.pointerSize + 4).readU32();
                    var rdlength = rr.add(Process.pointerSize + 8).readU16();
                    // 注意：rdata 是一个指针，需要进一步读取
                    console.log("    Parsed RR:");
                    console.log("        Name:", Memory.readCString(namePtr));
                    console.log("        Type:", type);
                    console.log("        Class:", klass);
                    console.log("        TTL:", ttl);
                    console.log("        RDLength:", rdlength);
                }
            }
        });
    """

    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()
    print("[*] 脚本已加载，等待 DNS 解析操作...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `hook_dns.py`。
2. 确保你的 Android 设备已连接并可以使用 `adb` 命令访问。
3. 安装 Frida 和 frida-tools：`pip install frida frida-tools`。
4. 运行你要监控的网络请求的 Android 应用程序。
5. 运行 Frida hook 脚本：`python hook_dns.py`。

当应用程序进行 DNS 解析时，Frida 脚本会拦截 `ns_initparse` 和 `ns_parserr` 的调用，并打印出相关的信息，例如消息长度、节号、RR 编号以及解析出的 RR 内容。

通过 Frida Hook，你可以深入了解 Android 系统如何使用 `ns_parse.c` 中的函数来解析 DNS 消息，从而更好地理解其工作原理。

### 提示词
```
这是目录为bionic/libc/dns/nameser/ns_parse.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: ns_parse.c,v 1.9 2012/03/13 21:13:39 christos Exp $	*/

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996,1999 by Internet Software Consortium.
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
static const char rcsid[] = "Id: ns_parse.c,v 1.10 2009/01/23 19:59:16 each Exp";
#else
__RCSID("$NetBSD: ns_parse.c,v 1.9 2012/03/13 21:13:39 christos Exp $");
#endif
#endif

/* Import. */

#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/nameser.h>

#include <assert.h>
#include <errno.h>
#ifdef ANDROID_CHANGES
#include "resolv_private.h"
#else
#include <resolv.h>
#endif
#include <string.h>

/* Forward. */

static void	setsection(ns_msg *msg, ns_sect sect);

/* Macros. */

#define RETERR(err) do { errno = (err); return (-1); } while (/*NOTREACHED*//*CONSTCOND*/0)

/* Public. */

struct _ns_flagdata {  int mask, shift;  };

/* These need to be in the same order as the nres.h:ns_flag enum. */
const struct _ns_flagdata _ns_flagdata[16] = {
	{ 0x8000, 15 },		/* qr. */
	{ 0x7800, 11 },		/* opcode. */
	{ 0x0400, 10 },		/* aa. */
	{ 0x0200, 9 },		/* tc. */
	{ 0x0100, 8 },		/* rd. */
	{ 0x0080, 7 },		/* ra. */
	{ 0x0040, 6 },		/* z. */
	{ 0x0020, 5 },		/* ad. */
	{ 0x0010, 4 },		/* cd. */
	{ 0x000f, 0 },		/* rcode. */
	{ 0x0000, 0 },		/* expansion (1/6). */
	{ 0x0000, 0 },		/* expansion (2/6). */
	{ 0x0000, 0 },		/* expansion (3/6). */
	{ 0x0000, 0 },		/* expansion (4/6). */
	{ 0x0000, 0 },		/* expansion (5/6). */
	{ 0x0000, 0 },		/* expansion (6/6). */
};

int ns_msg_getflag(ns_msg handle, int flag) {
	return((u_int32_t)((handle)._flags & _ns_flagdata[flag].mask) >> _ns_flagdata[flag].shift);
}

int
ns_skiprr(const u_char *ptr, const u_char *eom, ns_sect section, int count) {
	const u_char *optr = ptr;

	for (; count > 0; count--) {
		int b, rdlength;

		b = dn_skipname(ptr, eom);
		if (b < 0)
			RETERR(EMSGSIZE);
		ptr += b/*Name*/ + NS_INT16SZ/*Type*/ + NS_INT16SZ/*Class*/;
		if (section != ns_s_qd) {
			if (ptr + NS_INT32SZ + NS_INT16SZ > eom)
				RETERR(EMSGSIZE);
			ptr += NS_INT32SZ/*TTL*/;
			NS_GET16(rdlength, ptr);
			ptr += rdlength/*RData*/;
		}
	}
	if (ptr > eom)
		RETERR(EMSGSIZE);
	_DIAGASSERT(__type_fit(int, ptr - optr));
	return (int)(ptr - optr);
}

int
ns_initparse(const u_char *msg, int msglen, ns_msg *handle) {
	const u_char *eom = msg + msglen;
	int i;

	handle->_msg = msg;
	handle->_eom = eom;
	if (msg + NS_INT16SZ > eom)
		RETERR(EMSGSIZE);
	NS_GET16(handle->_id, msg);
	if (msg + NS_INT16SZ > eom)
		RETERR(EMSGSIZE);
	NS_GET16(handle->_flags, msg);
	for (i = 0; i < ns_s_max; i++) {
		if (msg + NS_INT16SZ > eom)
			RETERR(EMSGSIZE);
		NS_GET16(handle->_counts[i], msg);
	}
	for (i = 0; i < ns_s_max; i++)
		if (handle->_counts[i] == 0)
			handle->_sections[i] = NULL;
		else {
			int b = ns_skiprr(msg, eom, (ns_sect)i,
					  handle->_counts[i]);

			if (b < 0)
				return (-1);
			handle->_sections[i] = msg;
			msg += b;
		}
	if (msg != eom)
		RETERR(EMSGSIZE);
	setsection(handle, ns_s_max);
	return (0);
}

int
ns_parserr(ns_msg *handle, ns_sect section, int rrnum, ns_rr *rr) {
	int b;
	int tmp;

	/* Make section right. */
	tmp = section;
	if (tmp < 0 || section >= ns_s_max)
		RETERR(ENODEV);
	if (section != handle->_sect)
		setsection(handle, section);

	/* Make rrnum right. */
	if (rrnum == -1)
		rrnum = handle->_rrnum;
	if (rrnum < 0 || rrnum >= handle->_counts[(int)section])
		RETERR(ENODEV);
	if (rrnum < handle->_rrnum)
		setsection(handle, section);
	if (rrnum > handle->_rrnum) {
		b = ns_skiprr(handle->_msg_ptr, handle->_eom, section,
			      rrnum - handle->_rrnum);

		if (b < 0)
			return (-1);
		handle->_msg_ptr += b;
		handle->_rrnum = rrnum;
	}

	/* Do the parse. */
	b = dn_expand(handle->_msg, handle->_eom,
		      handle->_msg_ptr, rr->name, NS_MAXDNAME);
	if (b < 0)
		return (-1);
	handle->_msg_ptr += b;
	if (handle->_msg_ptr + NS_INT16SZ + NS_INT16SZ > handle->_eom)
		RETERR(EMSGSIZE);
	NS_GET16(rr->type, handle->_msg_ptr);
	NS_GET16(rr->rr_class, handle->_msg_ptr);
	if (section == ns_s_qd) {
		rr->ttl = 0;
		rr->rdlength = 0;
		rr->rdata = NULL;
	} else {
		if (handle->_msg_ptr + NS_INT32SZ + NS_INT16SZ > handle->_eom)
			RETERR(EMSGSIZE);
		NS_GET32(rr->ttl, handle->_msg_ptr);
		NS_GET16(rr->rdlength, handle->_msg_ptr);
		if (handle->_msg_ptr + rr->rdlength > handle->_eom)
			RETERR(EMSGSIZE);
		rr->rdata = handle->_msg_ptr;
		handle->_msg_ptr += rr->rdlength;
	}
	if (++handle->_rrnum > handle->_counts[(int)section])
		setsection(handle, (ns_sect)((int)section + 1));

	/* All done. */
	return (0);
}

/*
 * This is identical to the above but uses network-format (uncompressed) names.
 */
int
ns_parserr2(ns_msg *handle, ns_sect section, int rrnum, ns_rr2 *rr) {
	int b;
	int tmp;

	/* Make section right. */
	tmp = section;
	if (tmp < 0 || section >= ns_s_max)
		RETERR(ENODEV);
	if (section != handle->_sect)
		setsection(handle, section);

	/* Make rrnum right. */
	if (rrnum == -1)
		rrnum = handle->_rrnum;
	if (rrnum < 0 || rrnum >= handle->_counts[(int)section])
		RETERR(ENODEV);
	if (rrnum < handle->_rrnum)
		setsection(handle, section);
	if (rrnum > handle->_rrnum) {
		b = ns_skiprr(handle->_msg_ptr, handle->_eom, section,
			      rrnum - handle->_rrnum);

		if (b < 0)
			return (-1);
		handle->_msg_ptr += b;
		handle->_rrnum = rrnum;
	}

	/* Do the parse. */
	b = ns_name_unpack2(handle->_msg, handle->_eom, handle->_msg_ptr,
			    rr->nname, NS_MAXNNAME, &rr->nnamel);
	if (b < 0)
		return (-1);
	handle->_msg_ptr += b;
	if (handle->_msg_ptr + NS_INT16SZ + NS_INT16SZ > handle->_eom)
		RETERR(EMSGSIZE);
	NS_GET16(rr->type, handle->_msg_ptr);
	NS_GET16(rr->rr_class, handle->_msg_ptr);
	if (section == ns_s_qd) {
		rr->ttl = 0;
		rr->rdlength = 0;
		rr->rdata = NULL;
	} else {
		if (handle->_msg_ptr + NS_INT32SZ + NS_INT16SZ > handle->_eom)
			RETERR(EMSGSIZE);
		NS_GET32(rr->ttl, handle->_msg_ptr);
		NS_GET16(rr->rdlength, handle->_msg_ptr);
		if (handle->_msg_ptr + rr->rdlength > handle->_eom)
			RETERR(EMSGSIZE);
		rr->rdata = handle->_msg_ptr;
		handle->_msg_ptr += rr->rdlength;
	}
	if (++handle->_rrnum > handle->_counts[(int)section])
		setsection(handle, (ns_sect)((int)section + 1));

	/* All done. */
	return (0);
}

/* Private. */

static void
setsection(ns_msg *msg, ns_sect sect) {
	msg->_sect = sect;
	if (sect == ns_s_max) {
		msg->_rrnum = -1;
		msg->_msg_ptr = NULL;
	} else {
		msg->_rrnum = 0;
		msg->_msg_ptr = msg->_sections[(int)sect];
	}
}
```