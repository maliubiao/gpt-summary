Response:
Let's break down the thought process for analyzing this C code. The goal is to understand its functionality, its relation to Android, and how it's used.

**1. Initial Code Scan & High-Level Understanding:**

* **Copyright Notice:**  The header clearly indicates this code originates from ISC (Internet Systems Consortium), with contributions from NetBSD. This immediately suggests it's related to networking and likely DNS.
* **Includes:**  The `#include` directives confirm this. `sys/types.h`, `netinet/in.h`, `arpa/nameser.h`, `string.h`, `ctype.h`, `stdlib.h`, `limits.h` are standard C headers. The presence of `#ifdef ANDROID_CHANGES` and the inclusion of `"resolv_private.h"` *or* `<resolv.h>` signals Android-specific modifications to a standard DNS resolution library.
* **Macros:** `NS_TYPE_ELT` and `DNS_LABELTYPE_BITSTRING` suggest this code handles extended DNS label types, specifically bit strings.
* **Static Data:** `digits` and `digitvalue` are lookup tables for converting between ASCII digits and their numeric values. This is a strong hint towards ASCII-to-numeric and numeric-to-ASCII conversions, likely related to domain name encoding/decoding.
* **Function Prototypes:**  The `static` keyword indicates these functions are internal to the file. The names (`special`, `printable`, `dn_find`, `encode_bitsring`, `labellen`, `decode_bitstring`) provide clues about their purpose.

**2. Deeper Dive into Public Functions (API):**

The code exposes several functions with the `ns_name_` prefix. These are the primary interface of this module:

* `ns_name_ntop`: "Name to Presentation" - likely converts a network-format domain name to a human-readable string.
* `ns_name_pton`: "Presentation to Name" - likely converts a human-readable domain name string into the network format.
* `ns_name_pton2`:  A variation of `ns_name_pton`, possibly providing additional information or options.
* `ns_name_ntol`: "Name to Lowercase" - likely converts a network-format domain name to lowercase.
* `ns_name_unpack`:  Likely unpacks a domain name from a network message, handling potential compression.
* `ns_name_unpack2`: A variation of `ns_name_unpack`.
* `ns_name_pack`: Likely packs (and potentially compresses) a domain name into network format.
* `ns_name_uncompress`: Likely uncompresses a domain name from a network message.
* `ns_name_compress`: Likely compresses a human-readable domain name into network format.
* `ns_name_rollback`:  Seems to manage an array of pointers related to compression.
* `ns_name_skip`:  Skips over a compressed domain name in a network message.
* `ns_name_length`:  Calculates the length of a domain name in network format.
* `ns_name_eq`:  Compares two domain names for equality.
* `ns_name_owned`: Checks if one domain is a subdomain of another.
* `ns_name_map`:  Breaks down a domain name into its component labels.
* `ns_name_labels`: Counts the number of labels in a domain name.

**3. Analyzing Internal Functions:**

These helper functions support the public API:

* `special`: Checks if a character needs quoting in a domain name.
* `printable`: Checks if a character is printable.
* `mklower`: Converts an uppercase character to lowercase.
* `dn_find`:  Finds a compressed domain name within a buffer of compressed names (used for compression).
* `encode_bitsring`: Encodes a bit string label into the network format.
* `decode_bitstring`: Decodes a bit string label from the network format.
* `labellen`:  Determines the length of a label in network format.

**4. Connecting to Android:**

* **`#ifdef ANDROID_CHANGES`:** This is a crucial indicator. The code behaves slightly differently in Android. The inclusion of `"resolv_private.h"` suggests Android has its own internal implementation details for DNS resolution.
* **`bionic/libc`:** The file path itself confirms this is part of Android's C library. This means these functions are fundamental to how Android handles networking and DNS.

**5. Dynamic Linker Considerations:**

* **No Explicit Dynamic Linking in this file:** A close reading reveals no direct calls to dynamic linker functions (like `dlopen`, `dlsym`, etc.). However, because this code is *part* of `libc`, it's inherently linked into almost every Android process.
* **Indirect Dependency:**  Other parts of `libc` (like `getaddrinfo`, which uses these `ns_name_` functions) *do* interact with the dynamic linker to load shared libraries for different network protocols.

**6. Logical Reasoning and Examples:**

At this stage, it's useful to mentally walk through the functions with example inputs:

* **`ns_name_ntop`:** Input: `\x03www\x06google\x03com\x00`. Output: `www.google.com`.
* **`ns_name_pton`:** Input: `www.google.com`. Output: `\x03www\x06google\x03com\x00`. Input: `[x01/1]`. Output: `\x41\x01\x80`.

**7. Common Usage Errors:**

Thinking about how developers might misuse these functions is important:

* **Buffer Overflow:** Incorrectly sizing the `dst` buffer in `ntop`, `pton`, `unpack`, or `pack` can lead to buffer overflows.
* **Invalid Input:**  Providing malformed domain names to `pton` or corrupted network data to `unpack`.
* **Incorrect Compression Pointer Management:** Misusing `dnptrs` in `pack` can lead to incorrect compression or errors.

**8. Tracing from Android Framework/NDK:**

This requires understanding the Android networking stack. The process involves:

1. **Application making a network request:**  Using Java APIs like `InetAddress.getByName()`.
2. **Framework calling native code:** The Java method calls into native code, likely within the `libnativehelper.so` or `libjavacrypto.so` libraries.
3. **Native code using `getaddrinfo`:**  These libraries will eventually call the standard C library function `getaddrinfo`.
4. **`getaddrinfo` using resolver functions:** `getaddrinfo` relies on resolver functions (like `res_query`) which internally use the functions in `ns_name.c` to process domain names.

**9. Frida Hooking:**

Based on the understanding of the call flow,  Frida hooks can be placed at various points:

* **Java Level:** Hooking `InetAddress.getByName()`.
* **Native Level:** Hooking `getaddrinfo` or even specific functions within `ns_name.c` like `ns_name_ntop` or `ns_name_pton`.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  "This file directly handles DNS queries."  **Correction:**  While it's *part* of the DNS resolution process, it primarily deals with the *format* of domain names, not the network communication itself. Functions like `res_query` handle the actual DNS lookups.
* **Initial thought:**  "The dynamic linker is heavily involved here." **Correction:**  While `libc` is a shared library, this specific file doesn't have explicit dynamic linking calls. Its connection is more about being a fundamental part of the linked `libc`.
* **Focusing on the data structures:** Pay attention to `u_char *` and the ways labels and compression are represented. This helps understand the internal logic of the functions.

By following this structured approach, combining code analysis with knowledge of Android internals and networking concepts, we can arrive at a comprehensive understanding of the provided C source code.
好的，让我们来详细分析一下 `bionic/libc/dns/nameser/ns_name.c` 这个文件。

**文件功能概览**

`ns_name.c` 文件是 Android Bionic C 库中负责域名处理的关键部分。它实现了一系列函数，用于将域名在不同的表示形式之间进行转换和操作，这些形式包括：

* **表示格式 (Presentation Format):**  人类可读的 ASCII 字符串形式，例如 "www.google.com"。
* **网络格式 (Network Format):**  用于在网络上传输的编码形式，符合 RFC 1035 等 DNS 规范。这种格式通常包含长度前缀和可能的压缩。

该文件主要提供以下功能：

1. **域名到表示格式的转换 (`ns_name_ntop`, `ns_name_uncompress`)**: 将网络格式的域名转换为人类可读的 ASCII 字符串。
2. **表示格式到域名的转换 (`ns_name_pton`, `ns_name_compress`)**: 将人类可读的 ASCII 字符串转换为网络格式的域名。
3. **域名格式操作 (`ns_name_ntol`)**: 将网络格式的域名转换为全小写形式。
4. **域名解包与打包 (`ns_name_unpack`, `ns_name_pack`)**: 从网络消息中提取域名或将域名打包到网络消息中，并处理 DNS 压缩。
5. **域名长度计算和跳过 (`ns_name_length`, `ns_name_skip`)**: 计算网络格式域名的长度，或在网络消息中跳过一个域名。
6. **域名比较 (`ns_name_eq`, `ns_name_owned`)**: 比较两个域名是否相等，或判断一个域名是否是另一个域名的子域名。
7. **域名标签映射 (`ns_name_map`, `ns_name_labels`)**: 将域名分解成标签，或计算域名的标签数量。
8. **DNS 压缩管理 (`ns_name_rollback`)**:  管理 DNS 压缩指针。

**与 Android 功能的关系及举例说明**

`ns_name.c` 是 Android 网络功能的基础组成部分。几乎所有需要解析域名的 Android 功能都间接地或直接地依赖于这些函数。以下是一些例子：

* **网络连接:** 当 Android 应用需要连接到某个网站或服务器时，例如通过浏览器访问网页、发送 HTTP 请求等，都需要将域名解析为 IP 地址。`ns_name.c` 中的函数负责处理域名字符串的格式转换，为后续的 DNS 查询做好准备。例如，`getaddrinfo` 系统调用最终会使用到这里的函数来处理主机名。

* **应用安装和更新:**  应用商店在下载和安装应用时，需要连接到 Google Play 服务器或其他应用分发服务器，这些服务器通常使用域名。

* **系统服务:** Android 系统内部的许多服务，例如网络时间同步 (NTP)、定位服务等，也可能需要解析域名。

* **VPN 连接:**  建立 VPN 连接时，客户端可能需要解析 VPN 服务器的域名。

**举例说明:** 假设一个 Android 应用需要连接到 `www.example.com`。

1. 应用发起网络请求，例如使用 `java.net.URL` 或 OkHttp 库。
2. Java 代码会调用 Android Framework 层的相关网络 API。
3. Android Framework 会调用底层的 Native 代码，最终会调用到 Bionic C 库中的 `getaddrinfo` 函数。
4. `getaddrinfo` 函数内部会使用 `ns_name_pton` 将 "www.example.com" 转换为网络格式的域名。
5. 然后，系统会进行 DNS 查询，将网络格式的域名发送到 DNS 服务器。
6. DNS 服务器返回 IP 地址，系统再使用 `ns_name_ntop` (虽然不一定直接用于显示，但可能在调试或日志中使用) 将响应中的域名部分转换回可读格式。

**libc 函数的实现细节**

下面详细解释一些关键 libc 函数的功能是如何实现的：

* **`ns_name_ntop(const u_char *src, char *dst, size_t dstsiz)` (网络格式转表示格式)**

   1. **遍历标签:**  从 `src` 指向的网络格式域名开始，逐个读取标签的长度和内容。网络格式中，每个标签的第一个字节表示标签的长度。
   2. **处理压缩:**  如果遇到压缩指针 (长度字节的高两位为 11)，则根据指针跳转到消息的其他位置继续解析。**这是 dynamic linker 可能涉及的地方，虽然 `ns_name_ntop` 本身不直接调用 dynamic linker，但压缩机制需要理解消息的布局。**
   3. **转义特殊字符:**  如果标签中包含特殊字符 (如 '.', '\', ';') 或不可打印字符，则进行转义，例如将 '.' 转换为 "\.", 不可打印字符转换为 "\DDD" (DDD 是三位八进制数)。
   4. **拼接标签:**  将解析出的标签用 "." 连接起来，形成最终的表示格式字符串，并写入 `dst` 缓冲区。
   5. **处理根域名:** 如果是根域名 (长度为 0)，则输出 "."。
   6. **错误处理:**  检查缓冲区溢出等错误，如果超出 `dstsiz` 则返回 -1 并设置 `errno` 为 `EMSGSIZE`。

* **`ns_name_pton(const char *src, u_char *dst, size_t dstsiz)` (表示格式转网络格式)**

   1. **分割标签:**  将 `src` 指向的表示格式字符串按照 "." 分割成多个标签。
   2. **检查标签长度:**  确保每个标签的长度不超过 63 字节。
   3. **处理转义字符:**  如果标签中包含转义字符 (如 "\.", "\\", "\DDD")，则进行反转义。
   4. **编码标签:**  将每个标签的长度作为第一个字节，后跟标签的内容，写入 `dst` 缓冲区。
   5. **添加终止符:**  在所有标签编码完成后，添加一个长度为 0 的字节作为域名结束符。
   6. **错误处理:** 检查标签长度、域名总长度是否超出限制，如果超出 `dstsiz` 或其他限制则返回 -1 并设置 `errno`。

* **`ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src, u_char *dst, size_t dstsiz)` (解包域名)**

   1. **处理压缩:**  这是 `ns_name_unpack` 的核心。它会检查当前字节是否是压缩指针。如果是，则根据指针的值跳转到 `msg` 中的其他位置继续读取域名。
   2. **复制标签:**  如果不是压缩指针，则读取标签的长度和内容，并复制到 `dst` 缓冲区。
   3. **循环处理:**  重复步骤 1 和 2，直到遇到长度为 0 的标签结束符。
   4. **防止循环:**  在处理压缩时，会检查是否出现了循环引用的情况，如果发现循环则返回错误。
   5. **错误处理:**  检查越界、缓冲区溢出等错误。

* **`ns_name_pack(const u_char *src, u_char *dst, int dstsiz, const u_char **dnptrs, const u_char **lastdnptr)` (打包域名)**

   1. **查找可压缩部分:**  遍历 `src` 指向的域名中的每个标签，并在 `dnptrs` 指向的已压缩域名列表中查找是否已经存在相同的部分。`dnptrs` 是一个指向先前已压缩域名的指针数组，用于实现 DNS 压缩。
   2. **使用压缩指针:**  如果找到匹配的部分，则将一个压缩指针写入 `dst` 缓冲区，指向已存在的部分，从而节省空间。压缩指针的格式是高两位为 11，后 14 位表示偏移量。
   3. **复制未压缩部分:**  如果没有找到匹配的部分，则将当前标签的长度和内容复制到 `dst` 缓冲区。
   4. **更新压缩指针列表:**  如果成功压缩了新的标签，并且 `lastdnptr` 不为 NULL，则将当前压缩后的位置添加到 `dnptrs` 列表中，以便后续的压缩可以使用。
   5. **错误处理:**  检查缓冲区溢出等错误。

**涉及 dynamic linker 的功能及处理过程**

虽然 `ns_name.c` 本身不直接调用 `dlopen`、`dlsym` 等 dynamic linker 的函数，但它与 dynamic linker 有间接的关系，特别是在处理 DNS 压缩时。

**so 布局样本 (简化)**

假设一个简单的 Android 进程加载了 `libc.so`：

```
内存地址范围       |  内容
-------------------|--------------------
0x...0000         |  ELF header of libc.so
0x...1000         |  .text section (代码段，包含 ns_name.c 的代码)
0x...A000         |  .rodata section (只读数据段，例如 digits, digitvalue)
0x...C000         |  .data section (可读写数据段)
0x...D000         |  .bss section (未初始化数据段)
...
```

当 `ns_name_unpack` 或 `ns_name_pack` 处理压缩时，它们需要理解网络消息的内存布局。压缩指针实际上是一个相对于消息起始地址的偏移量。

**链接的处理过程**

1. **编译时链接:** `ns_name.c` 被编译成目标文件，然后链接到 `libc.so` 共享库中。链接器会解析符号引用，确保函数调用能够找到正确的地址。
2. **运行时链接:** 当 Android 进程加载 `libc.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会将 `libc.so` 加载到内存中的某个地址空间，并解析其中的符号引用，包括 `ns_name.c` 中的函数。
3. **DNS 压缩的间接关系:**  虽然 `ns_name.c` 不直接调用 dynamic linker 的接口，但其操作依赖于内存地址的概念，而内存地址的管理和共享库的加载正是 dynamic linker 的职责。当 `ns_name_unpack` 遇到压缩指针时，它假设消息的起始地址是已知的，并且可以通过偏移量计算出压缩部分的地址。这个消息的内存布局是由加载器（包括 dynamic linker）在运行时决定的。

**假设输入与输出 (逻辑推理)**

* **`ns_name_ntop` 输入:** `\x03www\x06google\x03com\x00` (网络格式的 "www.google.com")
   **`ns_name_ntop` 输出:** `"www.google.com"`

* **`ns_name_pton` 输入:** `"mail.example.net"`
   **`ns_name_pton` 输出:** `\x04mail\x07example\x03net\x00`

* **`ns_name_unpack` 输入 (假设 `msg` 指向 `\x03abc\xc0\x04\x00`，`src` 指向 `\x03abc\xc0\x04`)**:  `\xc0\x04` 是一个压缩指针，指向偏移量 4 的位置 (即 `google`)。
   **`ns_name_unpack` 输出 (解压后的域名):**  取决于 `msg` 的内容，假设 `msg` 的偏移量 4 开始是 `\x06google`，则解压后的部分会包含 "google"。

* **`ns_name_pack` 输入 (假设 `dnptrs` 指向已经包含 "example.com" 的压缩表示):**  要打包的域名是 "www.example.com"。
   **`ns_name_pack` 输出:**  可能会将 "example.com" 部分压缩，输出类似 `\x03www\xc0<offset>` 的格式，其中 `<offset>` 是指向已压缩的 "example.com" 的偏移量。

**用户或编程常见的使用错误**

1. **缓冲区溢出:**  在调用 `ns_name_ntop` 或 `ns_name_pton` 时，如果提供的 `dst` 缓冲区太小，会导致缓冲区溢出。
   ```c
   char buf[10];
   u_char src[] = "\x03www\x06google\x03com\x00";
   if (ns_name_ntop(src, buf, sizeof(buf)) == -1) {
       perror("ns_name_ntop failed"); // 可能发生缓冲区溢出
   }
   ```

2. **未正确处理返回值:**  `ns_name_ntop` 和 `ns_name_pton` 等函数返回 -1 表示失败，但开发者可能没有检查返回值。
   ```c
   u_char dst[256];
   ns_name_pton("invalid.domain...", dst, sizeof(dst)); // 如果域名过长，应该检查返回值
   ```

3. **错误理解域名格式:**  开发者可能不理解网络格式域名的结构，导致手动构建或解析时出错。

4. **在多线程环境中使用静态变量:**  虽然在这个代码片段中没有明显的静态可写变量，但在其他 DNS 解析相关的代码中，如果存在未正确同步的静态变量，可能导致线程安全问题。

**Android Framework 或 NDK 如何到达这里**

以下是一个简化的调用链，说明 Android Framework 或 NDK 如何最终调用到 `ns_name.c` 中的函数：

1. **Java 代码:** Android 应用通过 Java API 发起网络请求，例如使用 `java.net.InetAddress.getByName("www.google.com")`。

2. **Framework 层:**  Java 代码的调用会传递到 Android Framework 层的网络相关服务，例如 `ConnectivityService` 或 `NetworkManagementService`。

3. **Native 代码 (NDK 或 Framework 内部):** Framework 层会调用底层的 Native 代码，这可能涉及到 NDK 库 (如果应用使用了 NDK) 或者 Framework 内部的 Native 库。

4. **`getaddrinfo` 调用:**  底层的 Native 代码最终会调用 Bionic C 库中的 `getaddrinfo` 函数。`getaddrinfo` 是一个用于将主机名和服务名解析为地址的 POSIX 标准函数。

5. **Resolver 函数:** `getaddrinfo` 内部会使用 resolver 相关的函数，这些函数负责执行 DNS 查询。例如，可能会调用 `res_query` 或 `gethostbyname` 等。

6. **`ns_name.c` 中的函数:**  resolver 函数在处理域名时，会调用 `ns_name.c` 中定义的函数进行域名格式的转换、压缩、解压等操作。例如，`res_query` 在构建 DNS 查询报文时会使用 `ns_name_pack`，在解析 DNS 响应报文时会使用 `ns_name_unpack`。

**Frida Hook 示例**

可以使用 Frida Hook 来观察这些步骤，例如 Hook `ns_name_pton` 函数，查看传入的域名字符串和生成的网络格式数据：

```python
import frida
import sys

package_name = "your.target.app" # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_source = """
Interceptor.attach(Module.findExportByName("libc.so", "ns_name_pton"), {
    onEnter: function(args) {
        var src = Memory.readUtf8String(args[0]);
        var dst = args[1];
        var dstsiz = args[2].toInt();
        console.log("[+] ns_name_pton called");
        console.log("    src: " + src);
        console.log("    dst: " + dst);
        console.log("    dstsiz: " + dstsiz);
        this.dstPtr = dst;
        this.dstSize = dstsiz;
    },
    onLeave: function(retval) {
        if (retval == 0 || retval == 1) {
            var packedName = Memory.readByteArray(this.dstPtr, Math.min(64, this.dstSize)); // 读取部分输出
            console.log("    Packed name (first 64 bytes): " + hexdump(packedName, { ansi: true }));
        } else {
            console.log("    ns_name_pton failed");
        }
    }
});
"""

script = session.create_script(script_source)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个 Frida 脚本会 Hook `libc.so` 中的 `ns_name_pton` 函数，并在函数调用前后打印出相关信息，包括输入的域名字符串和输出的网络格式数据。你可以根据需要 Hook 其他函数来观察不同的处理步骤。

希望这个详细的分析能够帮助你理解 `bionic/libc/dns/nameser/ns_name.c` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/dns/nameser/ns_name.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: ns_name.c,v 1.9 2012/03/13 21:13:39 christos Exp $	*/

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
static const char rcsid[] = "Id: ns_name.c,v 1.11 2009/01/23 19:59:16 each Exp";
#else
__RCSID("$NetBSD: ns_name.c,v 1.9 2012/03/13 21:13:39 christos Exp $");
#endif
#endif

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
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>

#define NS_TYPE_ELT			0x40 /* EDNS0 extended label type */
#define DNS_LABELTYPE_BITSTRING		0x41

/* Data. */

static const char	digits[] = "0123456789";

static const char digitvalue[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/*16*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*32*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*48*/
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, /*64*/
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*80*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*96*/
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*112*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*256*/
};

/* Forward. */

static int		special(int);
static int		printable(int);
static int		dn_find(const u_char *, const u_char *,
				const u_char * const *,
				const u_char * const *);
static int		encode_bitsring(const char **, const char *,
					unsigned char **, unsigned char **,
					unsigned const char *);
static int		labellen(const u_char *);
static int		decode_bitstring(const unsigned char **,
					 char *, const char *);

/* Public. */

/*
 *	Convert an encoded domain name to printable ascii as per RFC1035.
 * return:
 *	Number of bytes written to buffer, or -1 (with errno set)
 *
 * notes:
 *	The root is returned as "."
 *	All other domains are returned in non absolute form
 */
int
ns_name_ntop(const u_char *src, char *dst, size_t dstsiz)
{
	const u_char *cp;
	char *dn, *eom;
	u_char c;
	u_int n;
	int l;

	cp = src;
	dn = dst;
	eom = dst + dstsiz;

	while ((n = *cp++) != 0) {
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			/* Some kind of compression pointer. */
			errno = EMSGSIZE;
			return (-1);
		}
		if (dn != dst) {
			if (dn >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			*dn++ = '.';
		}
		if ((l = labellen(cp - 1)) < 0) {
			errno = EMSGSIZE; /* XXX */
			return(-1);
		}
		if (dn + l >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		if ((n & NS_CMPRSFLGS) == NS_TYPE_ELT) {
			int m;

			if (n != DNS_LABELTYPE_BITSTRING) {
				/* XXX: labellen should reject this case */
				errno = EINVAL;
				return(-1);
			}
			if ((m = decode_bitstring(&cp, dn, eom)) < 0)
			{
				errno = EMSGSIZE;
				return(-1);
			}
			dn += m;
			continue;
		}
		for (; l > 0; l--) {
			c = *cp++;
			if (special(c)) {
				if (dn + 1 >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = (char)c;
			} else if (!printable(c)) {
				if (dn + 3 >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = digits[c / 100];
				*dn++ = digits[(c % 100) / 10];
				*dn++ = digits[c % 10];
			} else {
				if (dn >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = (char)c;
			}
		}
	}
	if (dn == dst) {
		if (dn >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		*dn++ = '.';
	}
	if (dn >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	*dn++ = '\0';
	_DIAGASSERT(__type_fit(int, dn - dst));
	return (int)(dn - dst);
}

/*
 *	Convert a ascii string into an encoded domain name as per RFC1035.
 *
 * return:
 *
 *	-1 if it fails
 *	1 if string was fully qualified
 *	0 is string was not fully qualified
 *
 * notes:
 *	Enforces label and domain length limits.
 */
int
ns_name_pton(const char *src, u_char *dst, size_t dstsiz) {
	return (ns_name_pton2(src, dst, dstsiz, NULL));
}

/*
 * ns_name_pton2(src, dst, dstsiz, *dstlen)
 *	Convert a ascii string into an encoded domain name as per RFC1035.
 * return:
 *	-1 if it fails
 *	1 if string was fully qualified
 *	0 is string was not fully qualified
 * side effects:
 *	fills in *dstlen (if non-NULL)
 * notes:
 *	Enforces label and domain length limits.
 */

int
ns_name_pton2(const char *src, u_char *dst, size_t dstsiz, size_t *dstlen) {
	u_char *label, *bp, *eom;
	int c, n, escaped, e = 0;
	char *cp;

	escaped = 0;
	bp = dst;
	eom = dst + dstsiz;
	label = bp++;

	while ((c = *src++) != 0) {
		if (escaped) {
			if (c == '[') { /* start a bit string label */
				if ((cp = strchr(src, ']')) == NULL) {
					errno = EINVAL; /* ??? */
					return(-1);
				}
				if ((e = encode_bitsring(&src, cp + 2,
							 &label, &bp, eom))
				    != 0) {
					errno = e;
					return(-1);
				}
				escaped = 0;
				label = bp++;
				if ((c = *src++) == 0)
					goto done;
				else if (c != '.') {
					errno = EINVAL;
					return(-1);
				}
				continue;
			}
			else if ((cp = strchr(digits, c)) != NULL) {
				n = (int)(cp - digits) * 100;
				if ((c = *src++) == 0 ||
				    (cp = strchr(digits, c)) == NULL) {
					errno = EMSGSIZE;
					return (-1);
				}
				n += (int)(cp - digits) * 10;
				if ((c = *src++) == 0 ||
				    (cp = strchr(digits, c)) == NULL) {
					errno = EMSGSIZE;
					return (-1);
				}
				n += (int)(cp - digits);
				if (n > 255) {
					errno = EMSGSIZE;
					return (-1);
				}
				c = n;
			}
			escaped = 0;
		} else if (c == '\\') {
			escaped = 1;
			continue;
		} else if (c == '.') {
			c = (int)(bp - label - 1);
			if ((c & NS_CMPRSFLGS) != 0) {	/* Label too big. */
				errno = EMSGSIZE;
				return (-1);
			}
			if (label >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			*label = c;
			/* Fully qualified ? */
			if (*src == '\0') {
				if (c != 0) {
					if (bp >= eom) {
						errno = EMSGSIZE;
						return (-1);
					}
					*bp++ = '\0';
				}
				if ((bp - dst) > MAXCDNAME) {
					errno = EMSGSIZE;
					return (-1);
				}
				if (dstlen != NULL)
					*dstlen = (bp - dst);
				return (1);
			}
			if (c == 0 || *src == '.') {
				errno = EMSGSIZE;
				return (-1);
			}
			label = bp++;
			continue;
		}
		if (bp >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		*bp++ = (u_char)c;
	}
	c = (int)(bp - label - 1);
	if ((c & NS_CMPRSFLGS) != 0) {		/* Label too big. */
		errno = EMSGSIZE;
		return (-1);
	}
  done:
	if (label >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	*label = c;
	if (c != 0) {
		if (bp >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		*bp++ = 0;
	}
	if ((bp - dst) > MAXCDNAME) {	/* src too big */
		errno = EMSGSIZE;
		return (-1);
	}
	if (dstlen != NULL)
		*dstlen = (bp - dst);
	return (0);
}

/*
 *	Convert a network strings labels into all lowercase.
 *
 * return:
 *	Number of bytes written to buffer, or -1 (with errno set)
 *
 * notes:
 *	Enforces label and domain length limits.
 */

int
ns_name_ntol(const u_char *src, u_char *dst, size_t dstsiz)
{
	const u_char *cp;
	u_char *dn, *eom;
	u_char c;
	u_int n;
	int l;

	cp = src;
	dn = dst;
	eom = dst + dstsiz;

	if (dn >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	while ((n = *cp++) != 0) {
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			/* Some kind of compression pointer. */
			errno = EMSGSIZE;
			return (-1);
		}
		*dn++ = n;
		if ((l = labellen(cp - 1)) < 0) {
			errno = EMSGSIZE;
			return (-1);
		}
		if (dn + l >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		for (; l > 0; l--) {
			c = *cp++;
			if (isascii(c) && isupper(c))
				*dn++ = tolower(c);
			else
				*dn++ = c;
		}
	}
	*dn++ = '\0';
	_DIAGASSERT(__type_fit(int, dn - dst));
	return (int)(dn - dst);
}

/*
 *	Unpack a domain name from a message, source may be compressed.
 *
 * return:
 *	-1 if it fails, or consumed octets if it succeeds.
 */
int
ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src,
	       u_char *dst, size_t dstsiz)
{
	return (ns_name_unpack2(msg, eom, src, dst, dstsiz, NULL));
}

/*
 * ns_name_unpack2(msg, eom, src, dst, dstsiz, *dstlen)
 *	Unpack a domain name from a message, source may be compressed.
 * return:
 *	-1 if it fails, or consumed octets if it succeeds.
 * side effect:
 *	fills in *dstlen (if non-NULL).
 */
int
ns_name_unpack2(const u_char *msg, const u_char *eom, const u_char *src,
		u_char *dst, size_t dstsiz, size_t *dstlen)
{
	const u_char *srcp, *dstlim;
	u_char *dstp;
	int n, len, checked, l;

	len = -1;
	checked = 0;
	dstp = dst;
	srcp = src;
	dstlim = dst + dstsiz;
	if (srcp < msg || srcp >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	/* Fetch next label in domain name. */
	while ((n = *srcp++) != 0) {
		/* Check for indirection. */
		switch (n & NS_CMPRSFLGS) {
		case 0:
		case NS_TYPE_ELT:
			/* Limit checks. */
			if ((l = labellen(srcp - 1)) < 0) {
				errno = EMSGSIZE;
				return(-1);
			}
			if (dstp + l + 1 >= dstlim || srcp + l >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			checked += l + 1;
			*dstp++ = n;
			memcpy(dstp, srcp, (size_t)l);
			dstp += l;
			srcp += l;
			break;

		case NS_CMPRSFLGS:
			if (srcp >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			if (len < 0) {
				_DIAGASSERT(__type_fit(int, srcp - src + 1));
				len = (int)(srcp - src + 1);
			}
			// BEGIN android-changed: safer pointer overflow check
			l = (((n & 0x3f) << 8) | (*srcp & 0xff));
			if (l >= eom - msg) {  /* Out of range. */
				errno = EMSGSIZE;
				return (-1);
			}
			srcp = msg + l;
			// END android-changed
			checked += 2;
			/*
			 * Check for loops in the compressed name;
			 * if we've looked at the whole message,
			 * there must be a loop.
			 */
			if (checked >= eom - msg) {
				errno = EMSGSIZE;
				return (-1);
			}
			break;

		default:
			errno = EMSGSIZE;
			return (-1);			/* flag error */
		}
	}
	*dstp++ = 0;
	if (dstlen != NULL)
		*dstlen = dstp - dst;
	if (len < 0) {
		_DIAGASSERT(__type_fit(int, srcp - src));
		len = (int)(srcp - src);
	}
	return len;
}

/*
 *	Pack domain name 'domain' into 'comp_dn'.
 *
 * return:
 *	Size of the compressed name, or -1.
 *
 * notes:
 *	'dnptrs' is an array of pointers to previous compressed names.
 *	dnptrs[0] is a pointer to the beginning of the message. The array
 *	ends with NULL.
 *	'lastdnptr' is a pointer to the end of the array pointed to
 *	by 'dnptrs'.
 *
 * Side effects:
 *	The list of pointers in dnptrs is updated for labels inserted into
 *	the message as we compress the name.  If 'dnptr' is NULL, we don't
 *	try to compress names. If 'lastdnptr' is NULL, we don't update the
 *	list.
 */
int
ns_name_pack(const u_char *src, u_char *dst, int dstsiz,
	     const u_char **dnptrs, const u_char **lastdnptr)
{
	u_char *dstp;
	const u_char **cpp, **lpp, *eob, *msg;
	const u_char *srcp;
	int n, l, first = 1;

	srcp = src;
	dstp = dst;
	eob = dstp + dstsiz;
	lpp = cpp = NULL;
	if (dnptrs != NULL) {
		if ((msg = *dnptrs++) != NULL) {
			for (cpp = dnptrs; *cpp != NULL; cpp++)
				continue;
			lpp = cpp;	/* end of list to search */
		}
	} else
		msg = NULL;

	/* make sure the domain we are about to add is legal */
	l = 0;
	do {
		int l0;

		n = *srcp;
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			errno = EMSGSIZE;
			return (-1);
		}
		if ((l0 = labellen(srcp)) < 0) {
			errno = EINVAL;
			return(-1);
		}
		l += l0 + 1;
		if (l > MAXCDNAME) {
			errno = EMSGSIZE;
			return (-1);
		}
		srcp += l0 + 1;
	} while (n != 0);

	/* from here on we need to reset compression pointer array on error */
	srcp = src;
	do {
		/* Look to see if we can use pointers. */
		n = *srcp;
		if (n != 0 && msg != NULL) {
			l = dn_find(srcp, msg, (const u_char * const *)dnptrs,
				    (const u_char * const *)lpp);
			if (l >= 0) {
				if (dstp + 1 >= eob) {
					goto cleanup;
				}
				*dstp++ = ((u_int32_t)l >> 8) | NS_CMPRSFLGS;
				*dstp++ = l % 256;
				_DIAGASSERT(__type_fit(int, dstp - dst));
				return (int)(dstp - dst);
			}
			/* Not found, save it. */
			if (lastdnptr != NULL && cpp < lastdnptr - 1 &&
			    (dstp - msg) < 0x4000 && first) {
				*cpp++ = dstp;
				*cpp = NULL;
				first = 0;
			}
		}
		/* copy label to buffer */
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			/* Should not happen. */
			goto cleanup;
		}
		n = labellen(srcp);
		if (dstp + 1 + n >= eob) {
			goto cleanup;
		}
		memcpy(dstp, srcp, (size_t)(n + 1));
		srcp += n + 1;
		dstp += n + 1;
	} while (n != 0);

	if (dstp > eob) {
cleanup:
		if (msg != NULL)
			*lpp = NULL;
		errno = EMSGSIZE;
		return (-1);
	}
	_DIAGASSERT(__type_fit(int, dstp - dst));
	return (int)(dstp - dst);
}

/*
 *	Expand compressed domain name to presentation format.
 *
 * return:
 *	Number of bytes read out of `src', or -1 (with errno set).
 *
 * note:
 *	Root domain returns as "." not "".
 */
int
ns_name_uncompress(const u_char *msg, const u_char *eom, const u_char *src,
		   char *dst, size_t dstsiz)
{
	u_char tmp[NS_MAXCDNAME];
	int n;

	if ((n = ns_name_unpack(msg, eom, src, tmp, sizeof tmp)) == -1)
		return (-1);
	if (ns_name_ntop(tmp, dst, dstsiz) == -1)
		return (-1);
	return (n);
}

/*
 *	Compress a domain name into wire format, using compression pointers.
 *
 * return:
 *	Number of bytes consumed in `dst' or -1 (with errno set).
 *
 * notes:
 *	'dnptrs' is an array of pointers to previous compressed names.
 *	dnptrs[0] is a pointer to the beginning of the message.
 *	The list ends with NULL.  'lastdnptr' is a pointer to the end of the
 *	array pointed to by 'dnptrs'. Side effect is to update the list of
 *	pointers for labels inserted into the message as we compress the name.
 *	If 'dnptr' is NULL, we don't try to compress names. If 'lastdnptr'
 *	is NULL, we don't update the list.
 */
int
ns_name_compress(const char *src, u_char *dst, size_t dstsiz,
		 const u_char **dnptrs, const u_char **lastdnptr)
{
	u_char tmp[NS_MAXCDNAME];

	if (ns_name_pton(src, tmp, sizeof tmp) == -1)
		return (-1);
	return (ns_name_pack(tmp, dst, (int)dstsiz, dnptrs, lastdnptr));
}

/*
 * Reset dnptrs so that there are no active references to pointers at or
 * after src.
 */
void
ns_name_rollback(const u_char *src, const u_char **dnptrs,
		 const u_char **lastdnptr)
{
	while (dnptrs < lastdnptr && *dnptrs != NULL) {
		if (*dnptrs >= src) {
			*dnptrs = NULL;
			break;
		}
		dnptrs++;
	}
}

/*
 *	Advance *ptrptr to skip over the compressed name it points at.
 *
 * return:
 *	0 on success, -1 (with errno set) on failure.
 */
int
ns_name_skip(const u_char **ptrptr, const u_char *eom)
{
	const u_char *cp;
	u_int n;
	int l=0;

	cp = *ptrptr;
	while (cp < eom && (n = *cp++) != 0) {
		/* Check for indirection. */
		switch (n & NS_CMPRSFLGS) {
		case 0:			/* normal case, n == len */
			cp += n;
			continue;
		case NS_TYPE_ELT: /* EDNS0 extended label */
			if (cp < eom && (l = labellen(cp - 1)) < 0) {
				errno = EMSGSIZE; /* XXX */
				return(-1);
			}
			cp += l;
			continue;
		case NS_CMPRSFLGS:	/* indirection */
			cp++;
			break;
		default:		/* illegal type */
			errno = EMSGSIZE;
			return (-1);
		}
		break;
	}
	if (cp > eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	*ptrptr = cp;
	return (0);
}

/* Find the number of octets an nname takes up, including the root label.
 * (This is basically ns_name_skip() without compression-pointer support.)
 * ((NOTE: can only return zero if passed-in namesiz argument is zero.))
 */
ssize_t
ns_name_length(ns_nname_ct nname, size_t namesiz) {
	ns_nname_ct orig = nname;
	u_int n;

	while (namesiz-- > 0 && (n = *nname++) != 0) {
		if ((n & NS_CMPRSFLGS) != 0) {
			errno = EISDIR;
			return (-1);
		}
		if (n > namesiz) {
			errno = EMSGSIZE;
			return (-1);
		}
		nname += n;
		namesiz -= n;
	}
	return (nname - orig);
}

/* Compare two nname's for equality.  Return -1 on error (setting errno).
 */
int
ns_name_eq(ns_nname_ct a, size_t as, ns_nname_ct b, size_t bs) {
	ns_nname_ct ae = a + as, be = b + bs;
	int ac, bc;

	while (ac = *a, bc = *b, ac != 0 && bc != 0) {
		if ((ac & NS_CMPRSFLGS) != 0 || (bc & NS_CMPRSFLGS) != 0) {
			errno = EISDIR;
			return (-1);
		}
		if (a + ac >= ae || b + bc >= be) {
			errno = EMSGSIZE;
			return (-1);
		}
		if (ac != bc || strncasecmp((const char *) ++a,
					    (const char *) ++b,
					    (size_t)ac) != 0)
			return (0);
		a += ac, b += bc;
	}
	return (ac == 0 && bc == 0);
}

/* Is domain "A" owned by (at or below) domain "B"?
 */
int
ns_name_owned(ns_namemap_ct a, int an, ns_namemap_ct b, int bn) {
	/* If A is shorter, it cannot be owned by B. */
	if (an < bn)
		return (0);

	/* If they are unequal before the length of the shorter, A cannot... */
	while (bn > 0) {
		if (a->len != b->len ||
		    strncasecmp((const char *) a->base,
				(const char *) b->base, (size_t)a->len) != 0)
			return (0);
		a++, an--;
		b++, bn--;
	}

	/* A might be longer or not, but either way, B owns it. */
	return (1);
}

/* Build an array of <base,len> tuples from an nname, top-down order.
 * Return the number of tuples (labels) thus discovered.
 */
int
ns_name_map(ns_nname_ct nname, size_t namelen, ns_namemap_t map, int mapsize) {
	u_int n;
	int l;

	n = *nname++;
	namelen--;

	/* Root zone? */
	if (n == 0) {
		/* Extra data follows name? */
		if (namelen > 0) {
			errno = EMSGSIZE;
			return (-1);
		}
		return (0);
	}

	/* Compression pointer? */
	if ((n & NS_CMPRSFLGS) != 0) {
		errno = EISDIR;
		return (-1);
	}

	/* Label too long? */
	if (n > namelen) {
		errno = EMSGSIZE;
		return (-1);
	}

	/* Recurse to get rest of name done first. */
	l = ns_name_map(nname + n, namelen - n, map, mapsize);
	if (l < 0)
		return (-1);

	/* Too many labels? */
	if (l >= mapsize) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	/* We're on our way back up-stack, store current map data. */
	map[l].base = nname;
	map[l].len = n;
	return (l + 1);
}

/* Count the labels in a domain name.  Root counts, so COM. has two.  This
 * is to make the result comparable to the result of ns_name_map().
 */
int
ns_name_labels(ns_nname_ct nname, size_t namesiz) {
	int ret = 0;
	u_int n;

	while (namesiz-- > 0 && (n = *nname++) != 0) {
		if ((n & NS_CMPRSFLGS) != 0) {
			errno = EISDIR;
			return (-1);
		}
		if (n > namesiz) {
			errno = EMSGSIZE;
			return (-1);
		}
		nname += n;
		namesiz -= n;
		ret++;
	}
	return (ret + 1);
}
/* Private. */

/*
 *	Thinking in noninternationalized USASCII (per the DNS spec),
 *	is this characted special ("in need of quoting") ?
 *
 * return:
 *	boolean.
 */
static int
special(int ch) {
	switch (ch) {
	case 0x22: /* '"' */
	case 0x2E: /* '.' */
	case 0x3B: /* ';' */
	case 0x5C: /* '\\' */
	case 0x28: /* '(' */
	case 0x29: /* ')' */
	/* Special modifiers in zone files. */
	case 0x40: /* '@' */
	case 0x24: /* '$' */
		return (1);
	default:
		return (0);
	}
}

/*
 *	Thinking in noninternationalized USASCII (per the DNS spec),
 *	is this character visible and not a space when printed ?
 *
 * return:
 *	boolean.
 */
static int
printable(int ch) {
	return (ch > 0x20 && ch < 0x7f);
}

/*
 *	Thinking in noninternationalized USASCII (per the DNS spec),
 *	convert this character to lower case if it's upper case.
 */
static int
mklower(int ch) {
	if (ch >= 0x41 && ch <= 0x5A)
		return (ch + 0x20);
	return (ch);
}

/*
 *	Search for the counted-label name in an array of compressed names.
 *
 * return:
 *	offset from msg if found, or -1.
 *
 * notes:
 *	dnptrs is the pointer to the first name on the list,
 *	not the pointer to the start of the message.
 */
static int
dn_find(const u_char *domain, const u_char *msg,
	const u_char * const *dnptrs,
	const u_char * const *lastdnptr)
{
	const u_char *dn, *cp, *sp;
	const u_char * const *cpp;
	u_int n;

	for (cpp = dnptrs; cpp < lastdnptr; cpp++) {
		sp = *cpp;
		/*
		 * terminate search on:
		 * root label
		 * compression pointer
		 * unusable offset
		 */
		while (*sp != 0 && (*sp & NS_CMPRSFLGS) == 0 &&
		       (sp - msg) < 0x4000) {
			dn = domain;
			cp = sp;
			while ((n = *cp++) != 0) {
				/*
				 * check for indirection
				 */
				switch (n & NS_CMPRSFLGS) {
				case 0:		/* normal case, n == len */
					n = labellen(cp - 1); /* XXX */

					if (n != *dn++)
						goto next;

					for (; n > 0; n--)
						if (mklower(*dn++) !=
						    mklower(*cp++))
							goto next;
					/* Is next root for both ? */
					if (*dn == '\0' && *cp == '\0') {
						_DIAGASSERT(__type_fit(int,
						    sp - msg));
						return (int)(sp - msg);
					}
					if (*dn)
						continue;
					goto next;
				case NS_CMPRSFLGS:	/* indirection */
					cp = msg + (((n & 0x3f) << 8) | *cp);
					break;

				default:	/* illegal type */
					errno = EMSGSIZE;
					return (-1);
				}
			}
 next: ;
			sp += *sp + 1;
		}
	}
	errno = ENOENT;
	return (-1);
}

static int
decode_bitstring(const unsigned char **cpp, char *dn, const char *eom)
{
	const unsigned char *cp = *cpp;
	char *beg = dn, tc;
	int b, blen, plen, i;

	if ((blen = (*cp & 0xff)) == 0)
		blen = 256;
	plen = (blen + 3) / 4;
	plen += (int)sizeof("\\[x/]") + (blen > 99 ? 3 : (blen > 9) ? 2 : 1);
	if (dn + plen >= eom)
		return(-1);

	cp++;
	i = snprintf(dn, eom - dn, "\\[x");
	if (i < 0)
		return (-1);
	dn += i;
	for (b = blen; b > 7; b -= 8, cp++) {
		i = snprintf(dn, eom - dn, "%02x", *cp & 0xff);
		if (i < 0)
			return (-1);
		dn += i;
	}
	if (b > 4) {
		tc = *cp++;
		i = snprintf(dn, eom - dn, "%02x", tc & (0xff << (8 - b)));
		if (i < 0)
			return (-1);
		dn += i;
	} else if (b > 0) {
		tc = *cp++;
		i = snprintf(dn, eom - dn, "%1x",
			       (((u_int32_t)tc >> 4) & 0x0f) & (0x0f << (4 - b)));
		if (i < 0)
			return (-1);
		dn += i;
	}
	i = snprintf(dn, eom - dn, "/%d]", blen);
	if (i < 0)
		return (-1);
	dn += i;

	*cpp = cp;
	_DIAGASSERT(__type_fit(int, dn - beg));
	return (int)(dn - beg);
}

static int
encode_bitsring(const char **bp, const char *end, unsigned char **labelp,
	        unsigned char ** dst, unsigned const char *eom)
{
	int afterslash = 0;
	const char *cp = *bp;
	unsigned char *tp;
	char c;
	const char *beg_blen;
	char *end_blen = NULL;
	int value = 0, count = 0, tbcount = 0, blen = 0;

	beg_blen = end_blen = NULL;

	/* a bitstring must contain at least 2 characters */
	if (end - cp < 2)
		return(EINVAL);

	/* XXX: currently, only hex strings are supported */
	if (*cp++ != 'x')
		return(EINVAL);
	if (!isxdigit((*cp) & 0xff)) /* reject '\[x/BLEN]' */
		return(EINVAL);

	for (tp = *dst + 1; cp < end && tp < eom; cp++) {
		switch((c = *cp)) {
		case ']':	/* end of the bitstring */
			if (afterslash) {
				if (beg_blen == NULL)
					return(EINVAL);
				blen = (int)strtol(beg_blen, &end_blen, 10);
				if (*end_blen != ']')
					return(EINVAL);
			}
			if (count)
				*tp++ = ((value << 4) & 0xff);
			cp++;	/* skip ']' */
			goto done;
		case '/':
			afterslash = 1;
			break;
		default:
			if (afterslash) {
				if (!isdigit(c&0xff))
					return(EINVAL);
				if (beg_blen == NULL) {

					if (c == '0') {
						/* blen never begings with 0 */
						return(EINVAL);
					}
					beg_blen = cp;
				}
			} else {
				if (!isxdigit(c&0xff))
					return(EINVAL);
				value <<= 4;
				value += digitvalue[(int)c];
				count += 4;
				tbcount += 4;
				if (tbcount > 256)
					return(EINVAL);
				if (count == 8) {
					*tp++ = value;
					count = 0;
				}
			}
			break;
		}
	}
  done:
	if (cp >= end || tp >= eom)
		return(EMSGSIZE);

	/*
	 * bit length validation:
	 * If a <length> is present, the number of digits in the <bit-data>
	 * MUST be just sufficient to contain the number of bits specified
	 * by the <length>. If there are insignificant bits in a final
	 * hexadecimal or octal digit, they MUST be zero.
	 * RFC 2673, Section 3.2.
	 */
	if (blen > 0) {
		int traillen;

		if (((blen + 3) & ~3) != tbcount)
			return(EINVAL);
		traillen = tbcount - blen; /* between 0 and 3 */
		if (((value << (8 - traillen)) & 0xff) != 0)
			return(EINVAL);
	}
	else
		blen = tbcount;
	if (blen == 256)
		blen = 0;

	/* encode the type and the significant bit fields */
	**labelp = DNS_LABELTYPE_BITSTRING;
	**dst = blen;

	*bp = cp;
	*dst = tp;

	return(0);
}

static int
labellen(const u_char *lp)
{
	int bitlen;
	u_char l = *lp;

	if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
		/* should be avoided by the caller */
		return(-1);
	}

	if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT) {
		if (l == DNS_LABELTYPE_BITSTRING) {
			if ((bitlen = *(lp + 1)) == 0)
				bitlen = 256;
			return((bitlen + 7 ) / 8 + 1);
		}
		return(-1);	/* unknwon ELT */
	}
	return(l);
}

"""

```