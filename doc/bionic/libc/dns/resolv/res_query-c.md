Response:
Let's break down the thought process for answering the user's request about `res_query.c`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of `res_query.c`. The key aspects are:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it fit into the Android ecosystem?
* **Libc Function Details:** How are the individual functions within the file implemented?
* **Dynamic Linking:** If dynamic linking is involved, provide examples and explain the process.
* **Logic and Assumptions:**  Explain any assumptions made about inputs and outputs.
* **Common Errors:**  Highlight potential user or programming mistakes.
* **Android Framework/NDK Integration:** Trace how this code is reached from higher levels.
* **Debugging with Frida:** Give practical Frida hooking examples.

**2. Initial Analysis of the Source Code:**

* **Copyright Notices:** The initial copyright notices tell us this code has roots in Berkeley (BSD), Digital Equipment Corporation, and Internet Systems Consortium (ISC). This immediately suggests it's a well-established and widely used piece of network code.
* **Includes:** The `#include` directives provide crucial clues about the file's purpose:
    * `<sys/types.h>`, `<sys/param.h>`: Basic system types and parameters.
    * `<netinet/in.h>`, `<arpa/inet.h>`, `<arpa/nameser.h>`: Core network and DNS structures and definitions.
    * `<ctype.h>`: Character type checking.
    * `<errno.h>`: Error handling.
    * `<netdb.h>`: Network database operations (like `gethostbyname`).
    * `"resolv_cache.h"`, `"resolv_private.h"` (Android Specific):  Indicates caching and internal resolution details specific to Android. The alternative `<resolv.h>` is the standard library header.
    * `<stdio.h>`, `<stdlib.h>`, `<unistd.h>`, `<string.h>`: Standard C library functions.
* **Function Declarations:** The presence of `res_nquery`, `res_nsearch`, `res_nquerydomain`, and `res_hostalias` suggests a focus on performing DNS queries with different search strategies.
* **`res_state`:** The repeated use of `res_state statp` points to a structure that holds the resolver's state information (like DNS servers, search domains, options, etc.).
* **`HEADER`:**  The cast `(HEADER *)(void *)answer` suggests the code directly manipulates the DNS message header.
* **Error Handling:** The use of `RES_SET_H_ERRNO` indicates a custom error reporting mechanism specific to DNS resolution within `libresolv`.

**3. Deconstructing Each Function:**

* **`res_nquery`:** This looks like the fundamental query function. It constructs a DNS query, sends it, and waits for a response. The "n" likely signifies "new" or "network" version. The code includes retry logic for EDNS0 errors.
* **`res_nsearch`:** This function implements the search list logic. It tries different domain suffixes based on the `res_state` configuration and the number of dots in the hostname. It handles various DNS error codes (`NXDOMAIN`, `SERVFAIL`, `NO_DATA`).
* **`res_nquerydomain`:** This seems like a helper function for `res_nsearch`, combining a hostname with a domain suffix before performing the actual query.
* **`res_hostalias`:** This function is currently a stub (`return (NULL);`). The comment suggests it *could* handle local host aliases, but it's disabled in this version.

**4. Connecting to Android:**

* **`bionic` and `libc`:** The file path clearly places it within Android's C library. This means it's a core component used by almost all Android applications and system services that need to resolve hostnames.
* **`resolv`:** The directory name indicates its role in DNS resolution.
* **Android-Specific Includes:** The presence of `"resolv_cache.h"` and `"resolv_private.h"` confirms Android customizations. These likely involve caching DNS results to improve performance and possibly internal implementation details.
* **Framework/NDK Usage:**  Think about how an Android app resolves a hostname:  Java code uses `InetAddress.getByName()`, which eventually calls native code within the Android runtime, which then interfaces with `libc` functions like these. The NDK allows direct use of C/C++ code, making this even more direct.

**5. Addressing Dynamic Linking:**

* **`libc.so`:**  This code resides within `libc.so`, the standard C library. Applications link against this library.
* **Linkage:** When a program calls `res_nquery`, the dynamic linker (`linker64` or `linker`) resolves the symbol and ensures the correct function in `libc.so` is called.

**6. Constructing Examples and Explanations:**

* **Libc Function Details:** Explain the steps within each function, focusing on the DNS message format and the different parts of the query process.
* **Android Examples:** Give concrete examples like opening a URL in a browser or using `adb`.
* **Dynamic Linking Example:**  Show a simplified `libc.so` layout and illustrate how the dynamic linker resolves symbols.
* **Assumptions:**  Explicitly state assumptions, such as the DNS server being reachable and correctly configured.
* **Common Errors:**  Think about typical mistakes like incorrect DNS server settings or malformed hostnames.

**7. Frida Hooking:**

* **Identify Target Functions:** The key functions to hook are `res_nquery`, `res_nsearch`, and `res_nquerydomain`.
* **Basic Hook Structure:** Show the fundamental Frida `Interceptor.attach` syntax.
* **Log Arguments and Return Values:** Demonstrate how to access and log the input arguments and return value of the hooked functions.

**8. Structuring the Response:**

Organize the information logically:

* Start with a summary of the file's overall functionality.
* Discuss Android relevance with examples.
* Detail each function's implementation.
* Explain dynamic linking with a sample layout.
* Provide assumptions and common errors.
* Trace the call flow from the Android framework/NDK.
* Give practical Frida hooking examples.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe focus too much on the low-level packet details.
* **Correction:** Realize the user needs a broader understanding, including Android context and higher-level usage. Balance low-level details with high-level explanation.
* **Initial Thought:**  Forget to mention the disabled `res_hostalias`.
* **Correction:** Include it, noting its current state and potential purpose.
* **Initial Thought:**  Provide a highly technical dynamic linking explanation.
* **Correction:** Simplify it for clarity, focusing on the core concepts of symbol resolution and shared libraries.
* **Initial Thought:**  Overcomplicate the Frida examples.
* **Correction:** Provide simple, illustrative examples that demonstrate the basic hooking mechanism.

By following this thought process, breaking down the problem, analyzing the code, and connecting it to the broader Android environment, a comprehensive and helpful answer can be constructed.
好的，让我们详细分析一下 `bionic/libc/dns/resolv/res_query.c` 这个文件。

**功能概述**

`res_query.c` 文件是 Android Bionic C 库中负责执行 DNS 查询的核心代码。它的主要功能是：

1. **构建 DNS 查询报文:**  根据给定的域名、查询类型（例如 A 记录、AAAA 记录）、查询类（通常是 INternet）等信息，构建符合 DNS 协议规范的查询报文。
2. **发送 DNS 查询报文:**  将构建好的查询报文发送到一个或多个配置的 DNS 服务器。
3. **接收 DNS 响应报文:**  等待并接收来自 DNS 服务器的响应报文。
4. **初步检查响应报文:**  检查响应报文的状态码，判断查询是否成功，例如是否找到域名、服务器是否出错等。
5. **实现域名搜索规则:**  如果配置了搜索域（search domain），并且查询的域名不包含足够的点号，或者配置了 `RES_DNSRCH` 选项，则会尝试将域名与搜索域组合后进行多次查询。
6. **处理主机别名 (host alias):**  虽然代码中 `res_hostalias` 函数目前返回 `NULL`，但其目的是处理本地主机别名。在其他 DNS 库的实现中，这个函数会查找本地配置文件（如 `/etc/hosts`）来查找别名。

**与 Android 功能的关系及举例说明**

`res_query.c` 在 Android 系统中扮演着至关重要的角色，几乎所有需要解析域名的地方都会间接或直接地使用到这里的代码。

**举例说明:**

* **网络连接:** 当 Android 应用需要连接到一个使用域名而不是 IP 地址的服务器时（例如访问一个网站），系统会使用 DNS 解析将域名转换为 IP 地址。`res_query.c` 就是完成这个转换的关键部分。
    * 例如，当你在 Chrome 浏览器中输入 `www.google.com` 并按下回车时，浏览器会发起网络请求。Android 系统会使用 `res_query.c` 中的函数来查询 `www.google.com` 的 IP 地址。
* **ADB 连接:**  当你使用 `adb connect <hostname>` 命令连接到 Android 设备时，`adb` 客户端需要解析 `<hostname>` 为 IP 地址，这个过程也依赖于 `res_query.c`。
* **应用内的网络请求:**  任何 Android 应用，无论是使用 Java 的 `InetAddress.getByName()` 还是 Native 代码中的 `getaddrinfo()`，最终都会调用到 Bionic C 库的 DNS 解析函数，其中就包括 `res_query.c` 里的逻辑。
* **系统服务:** Android 系统的一些核心服务，例如网络管理服务、定位服务等，也可能需要在内部进行域名解析，从而使用到这里的代码。

**libc 函数的实现细节**

我们来详细解释一下 `res_query.c` 中主要的 libc 函数的功能和实现：

1. **`res_nquery(res_state statp, const char *name, int class, int type, u_char *answer, int anslen)`**

   * **功能:** 这是执行单次 DNS 查询的核心函数。它构建 DNS 查询报文并发送，然后接收并初步检查响应。
   * **实现细节:**
     * **`res_nmkquery()`:**  调用 `res_nmkquery` 函数（可能在其他源文件中）根据 `name`（域名）、`class`（查询类）、`type`（查询类型）等信息构建 DNS 查询报文，并将报文放入 `buf` 缓冲区。
     * **可选的 EDNS0 处理:** 如果启用了 EDNS0（Extension Mechanisms for DNS），并且之前的查询因为 EDNS0 失败，会尝试重新构建带有 EDNS0 的查询。`res_nopt()` 函数负责添加 EDNS0 选项。
     * **`res_nsend()`:** 调用 `res_nsend` 函数（可能在其他源文件中）将构建好的 DNS 查询报文从 `buf` 发送到配置的 DNS 服务器，并将接收到的响应报文放入 `answer` 缓冲区。
     * **错误处理:** 如果 `res_nsend` 返回错误，会根据情况设置 `H_ERRNO` 为 `TRY_AGAIN`。
     * **响应检查:** 检查响应报文头部的 `rcode` 字段（返回码）和 `ancount` 字段（应答记录数）。
       * 如果 `rcode` 不是 `NOERROR` 或 `ancount` 为 0，则表示查询失败或没有找到结果，根据不同的 `rcode` 设置相应的 `H_ERRNO`（例如 `HOST_NOT_FOUND`、`TRY_AGAIN`、`NO_DATA` 等）。

2. **`res_nsearch(res_state statp, const char *name, int class, int type, u_char *answer, int anslen)`**

   * **功能:**  实现带搜索域的 DNS 查询。它会根据配置的搜索域列表，尝试将给定的域名与搜索域组合后进行多次查询，直到找到结果或所有可能性都尝试完毕。
   * **实现细节:**
     * **主机别名处理:** 首先调用 `res_hostalias` 查找本地主机别名（当前实现为空）。
     * **点号检查:** 检查域名中点号的数量，以及是否以点号结尾。
     * **直接查询:** 如果域名中的点号数量大于等于 `ndots` 配置，或者域名以点号结尾，则会先尝试直接查询该域名。
     * **搜索域迭代:** 如果满足搜索条件（例如 `RES_DEFNAMES` 或 `RES_DNSRCH` 启用），则遍历 `statp->dnsrch` 中的搜索域列表。
       * **`res_nquerydomain()`:**  对于每个搜索域，调用 `res_nquerydomain` 函数将域名与搜索域组合，并执行查询。
       * **错误处理:**  根据 `res_nquerydomain` 返回的结果和 `statp->res_h_errno` 的值，决定是否继续尝试下一个搜索域。例如，如果遇到 `NO_DATA` 或 `HOST_NOT_FOUND`，会继续尝试；如果遇到 `SERVFAIL`，可能会停止搜索。
     * **最终查询:**  如果在所有搜索域中都没有找到结果，并且之前没有直接查询过，则会尝试直接查询原始域名。
     * **设置 H_ERRNO:**  根据最终的查询结果设置 `H_ERRNO`。

3. **`res_nquerydomain(res_state statp, const char *name, const char *domain, int class, int type, u_char *answer, int anslen)`**

   * **功能:**  将给定的域名 `name` 和 `domain` 拼接在一起，然后调用 `res_nquery` 执行查询。
   * **实现细节:**
     * **处理结尾的点号:** 如果 `domain` 为 `NULL`，则检查 `name` 是否以点号结尾，如果是，则去掉点号再进行查询。
     * **拼接域名:** 如果 `domain` 不为 `NULL`，则将 `name` 和 `domain` 用点号拼接成完整的域名。
     * **调用 `res_nquery`:** 调用 `res_nquery` 函数执行实际的 DNS 查询。

4. **`res_hostalias(const res_state statp, const char *name, char *dst, size_t siz)`**

   * **功能:**  查找本地主机别名。
   * **实现细节:**  在当前提供的代码中，这个函数直接返回 `NULL`，表示主机别名功能被禁用 (`#define DISABLE_HOST_ALIAS 1`)。在其他 DNS 库的实现中，这个函数通常会读取 `/etc/hosts` 文件，查找与 `name` 匹配的别名，并将别名复制到 `dst` 缓冲区。

**涉及 dynamic linker 的功能、so 布局样本以及链接的处理过程**

`res_query.c` 本身的代码并没有直接涉及到动态链接器的操作。它的功能是提供 DNS 查询的实现，会被其他需要进行域名解析的程序或库使用。

**so 布局样本:**

`res_query.c` 编译后会成为 `libc.so` 动态链接库的一部分。一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
    .text:  // 代码段
        res_nquery:  // res_query.c 中的 res_nquery 函数的机器码
        res_nsearch: // res_query.c 中的 res_nsearch 函数的机器码
        res_nquerydomain: // ...
        // 其他 libc 函数 ...
    .data:  // 数据段
        // 全局变量 ...
    .bss:   // 未初始化数据段
        // 未初始化的全局变量 ...
    .dynsym: // 动态符号表
        res_nquery
        res_nsearch
        res_nquerydomain
        // 其他导出的符号 ...
    .dynstr: // 动态字符串表
        "res_nquery"
        "res_nsearch"
        "res_nquerydomain"
        // 其他导出的符号的名称 ...
    // 其他段 ...
```

**链接的处理过程:**

1. **编译时链接:** 当一个程序（例如 Chrome 浏览器进程）需要使用 `res_nquery` 函数时，编译器会在链接阶段记录下对 `res_nquery` 符号的引用。
2. **运行时链接:**  当程序启动时，Android 的动态链接器（`linker` 或 `linker64`）会负责加载程序依赖的动态链接库，包括 `libc.so`。
3. **符号解析:** 动态链接器会根据程序的符号引用，在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `res_nquery` 符号的地址。
4. **重定位:** 找到符号地址后，动态链接器会更新程序中对 `res_nquery` 的调用地址，使其指向 `libc.so` 中 `res_nquery` 函数的实际地址。

**假设输入与输出的逻辑推理**

**假设输入:**

* **`res_nquery`:**
    * `name`: "www.example.com"
    * `class`: `C_IN` (Internet)
    * `type`: `T_A` (IPv4 地址)
    * DNS 服务器已正确配置且 `www.example.com` 有对应的 A 记录。

* **`res_nsearch`:**
    * `name`: "example"
    * `class`: `C_IN`
    * `type`: `T_A`
    * `statp->dnsrch` 配置了搜索域：`{"example.com", "corp.local"}`
    * `example.com` 域下存在 `example` 的 A 记录。

**输出:**

* **`res_nquery`:**
    * 如果查询成功，`answer` 缓冲区将包含 `www.example.com` 的 IPv4 地址，函数返回响应报文的大小。
    * 如果查询失败（例如域名不存在），函数返回 -1，并且 `statp->res_h_errno` 会被设置为相应的错误代码（例如 `HOST_NOT_FOUND`）。

* **`res_nsearch`:**
    * 会首先尝试直接查询 "example"，如果失败，则会尝试查询 "example.example.com"。
    * 如果在 "example.example.com" 中找到 A 记录，`answer` 缓冲区将包含其 IPv4 地址，函数返回响应报文的大小。
    * 如果所有搜索域都尝试完毕且未找到结果，函数返回 -1，并且 `statp->res_h_errno` 会被设置为相应的错误代码。

**用户或编程常见的使用错误**

1. **DNS 服务器配置错误:**  如果设备的 DNS 服务器配置不正确或无法访问，DNS 查询将失败。这通常会导致 `res_nquery` 或 `res_nsearch` 返回 -1，并且 `H_ERRNO` 设置为 `TRY_AGAIN` 或其他网络相关的错误。
    * **示例:** 用户在 Wi-Fi 设置中手动配置了一个无效的 DNS 服务器地址。
2. **域名拼写错误:**  查询一个不存在的域名会导致 `res_nquery` 或 `res_nsearch` 返回 -1，并且 `H_ERRNO` 设置为 `HOST_NOT_FOUND`。
    * **示例:**  程序中错误地将 "www.example.com" 写成了 "ww.example.com"。
3. **查询类型错误:**  请求了错误的查询类型（例如，请求一个没有 A 记录但有 AAAA 记录的域名的 A 记录）会导致 `res_nquery` 返回 -1，并且 `H_ERRNO` 设置为 `NO_DATA`。
4. **缓冲区溢出:**  传递给 `res_nquery` 或 `res_nsearch` 的 `answer` 缓冲区太小，无法容纳完整的 DNS 响应报文，可能导致内存溢出或其他不可预测的行为。虽然代码中有 `anslen` 参数进行大小检查，但调用者需要确保 `anslen` 的值正确。
5. **不恰当的搜索域配置:**  如果搜索域配置不当，可能会导致不必要的 DNS 查询，影响性能。

**Android Framework 或 NDK 如何到达这里**

从 Android Framework 或 NDK 到 `res_query.c` 的调用路径通常如下：

**Android Framework (Java):**

1. **`java.net.InetAddress.getByName(String host)`:**  这是 Java 中进行域名解析的常用方法。
2. **`libcore.io.GaiResolver.resolve(String host, int netId)`:**  `InetAddress` 的实现通常委托给 `GaiResolver`。
3. **Native 方法调用:** `GaiResolver` 会调用 Native 方法（JNI）。
4. **`android_net_getaddrinfo` (在 `libnativehelper.so` 或 `libnetd_client.so` 中):**  这个 Native 方法是 `getaddrinfo` 系统调用的 Android 特殊实现。
5. **`getaddrinfo` (Bionic libc):**  Android 的 `getaddrinfo` 函数会使用 `res_nsearch` 或类似的函数来执行 DNS 查询。

**Android NDK (C/C++):**

1. **`getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)`:**  这是标准的 POSIX 函数，用于将主机名或服务名解析为地址。
2. **Bionic libc 实现:**  NDK 中使用的 `getaddrinfo` 函数是 Bionic C 库提供的实现，它会调用 `res_nsearch` 或类似的函数。

**Frida Hook 示例调试步骤**

可以使用 Frida 来 hook `res_nquery` 函数，查看其参数和返回值，从而了解 DNS 查询的过程。

**Frida Hook 脚本示例:**

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到应用: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "res_nquery"), {
    onEnter: function(args) {
        console.log("[+] res_nquery called");
        console.log("    statp:", args[0]);
        console.log("    name:", Memory.readUtf8String(args[1]));
        console.log("    class:", args[2]);
        console.log("    type:", args[3]);
        // 注意：打印 answer 缓冲区可能很大，这里省略
        console.log("    anslen:", args[5]);
    },
    onLeave: function(retval) {
        console.log("[+] res_nquery returned:", retval);
        if (retval > 0) {
            // 读取部分响应数据 (假设是 IPv4 地址)
            // let answer_ptr = this.context.r2; // 根据架构调整寄存器
            // let ip_address = Memory.readByteArray(answer_ptr + 12, 4); // 偏移可能需要调整
            // console.log("    Answer (first 4 bytes):", ip_address);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **准备环境:** 确保已安装 Frida 和 adb，并且你的 Android 设备已连接到电脑。
2. **找到目标应用包名:**  替换脚本中的 `package_name` 为你要调试的应用的实际包名。
3. **运行 Frida 脚本:** 运行上述 Python 脚本。
4. **在应用中触发 DNS 查询:**  在你的 Android 应用中执行会导致 DNS 查询的操作，例如访问一个网页、连接到一个服务器等。
5. **查看 Frida 输出:**  Frida 会拦截对 `res_nquery` 的调用，并打印出函数的参数和返回值，你可以从中看到正在查询的域名、查询类型等信息。

**更进一步的调试:**

* 你可以 hook `res_nsearch` 或 `res_nquerydomain` 来观察搜索域的处理过程。
* 在 `onLeave` 中，你可以尝试读取 `answer` 缓冲区的内容，以查看 DNS 响应的具体数据。注意，需要根据 DNS 报文的格式来解析这些数据。

希望以上详细的解释能够帮助你理解 `bionic/libc/dns/resolv/res_query.c` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/dns/resolv/res_query.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: res_query.c,v 1.7 2006/01/24 17:41:25 christos Exp $	*/

/*
 * Copyright (c) 1988, 1993
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
static const char sccsid[] = "@(#)res_query.c	8.1 (Berkeley) 6/4/93";
static const char rcsid[] = "Id: res_query.c,v 1.2.2.3.4.2 2004/03/16 12:34:19 marka Exp";
#else
__RCSID("$NetBSD: res_query.c,v 1.7 2006/01/24 17:41:25 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */



#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#ifdef ANDROID_CHANGES
#include "resolv_cache.h"
#include "resolv_private.h"
#else
#include <resolv.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define DISABLE_HOST_ALIAS 1

/* Options.  Leave them on. */
#ifndef DEBUG
#define DEBUG
#endif

#if PACKETSZ > 1024
#define MAXPACKET	PACKETSZ
#else
#define MAXPACKET	1024
#endif

/*
 * Formulate a normal query, send, and await answer.
 * Returned answer is placed in supplied buffer "answer".
 * Perform preliminary check of answer, returning success only
 * if no error is indicated and the answer count is nonzero.
 * Return the size of the response on success, -1 on error.
 * Error number is left in H_ERRNO.
 *
 * Caller must parse answer and determine whether it answers the question.
 */
int
res_nquery(res_state statp,
	   const char *name,	/* domain name */
	   int class, int type,	/* class and type of query */
	   u_char *answer,	/* buffer to put answer */
	   int anslen)		/* size of answer buffer */
{
	u_char buf[MAXPACKET];
	HEADER *hp = (HEADER *)(void *)answer;
	int n;
	u_int oflags;

	oflags = statp->_flags;

again:
	hp->rcode = NOERROR;	/* default */

#ifdef DEBUG
	if (statp->options & RES_DEBUG)
		printf(";; res_query(%s, %d, %d)\n", name, class, type);
#endif

	n = res_nmkquery(statp, QUERY, name, class, type, NULL, 0, NULL,
			 buf, sizeof(buf));
#ifdef RES_USE_EDNS0
	if (n > 0 && (statp->_flags & RES_F_EDNS0ERR) == 0 &&
	    (statp->options & (RES_USE_EDNS0|RES_USE_DNSSEC)) != 0U)
		n = res_nopt(statp, n, buf, sizeof(buf), anslen);
#endif
	if (n <= 0) {
#ifdef DEBUG
		if (statp->options & RES_DEBUG)
			printf(";; res_query: mkquery failed\n");
#endif
		RES_SET_H_ERRNO(statp, NO_RECOVERY);
		return (n);
	}
	n = res_nsend(statp, buf, n, answer, anslen);
	if (n < 0) {
#ifdef RES_USE_EDNS0
		/* if the query choked with EDNS0, retry without EDNS0 */
		if ((statp->options & (RES_USE_EDNS0|RES_USE_DNSSEC)) != 0U &&
		    ((oflags ^ statp->_flags) & RES_F_EDNS0ERR) != 0) {
			statp->_flags |= RES_F_EDNS0ERR;
			if (statp->options & RES_DEBUG)
				printf(";; res_nquery: retry without EDNS0\n");
			goto again;
		}
#endif
#ifdef DEBUG
		if (statp->options & RES_DEBUG)
			printf(";; res_query: send error\n");
#endif
		RES_SET_H_ERRNO(statp, TRY_AGAIN);
		return (n);
	}

	if (hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
#ifdef DEBUG
		if (statp->options & RES_DEBUG)
			printf(";; rcode = (%s), counts = an:%d ns:%d ar:%d\n",
			       p_rcode(hp->rcode),
			       ntohs(hp->ancount),
			       ntohs(hp->nscount),
			       ntohs(hp->arcount));
#endif
		switch (hp->rcode) {
		case NXDOMAIN:
			RES_SET_H_ERRNO(statp, HOST_NOT_FOUND);
			break;
		case SERVFAIL:
			RES_SET_H_ERRNO(statp, TRY_AGAIN);
			break;
		case NOERROR:
			RES_SET_H_ERRNO(statp, NO_DATA);
			break;
		case FORMERR:
		case NOTIMP:
		case REFUSED:
		default:
			RES_SET_H_ERRNO(statp, NO_RECOVERY);
			break;
		}
		return (-1);
	}
	return (n);
}

/*
 * Formulate a normal query, send, and retrieve answer in supplied buffer.
 * Return the size of the response on success, -1 on error.
 * If enabled, implement search rules until answer or unrecoverable failure
 * is detected.  Error code, if any, is left in H_ERRNO.
 */
int
res_nsearch(res_state statp,
	    const char *name,	/* domain name */
	    int class, int type,	/* class and type of query */
	    u_char *answer,	/* buffer to put answer */
	    int anslen)		/* size of answer */
{
	const char *cp, * const *domain;
	HEADER *hp = (HEADER *)(void *)answer;
	char tmp[NS_MAXDNAME];
	u_int dots;
	int trailing_dot, ret, saved_herrno;
	int got_nodata = 0, got_servfail = 0, root_on_list = 0;
	int tried_as_is = 0;
	int searched = 0;

	errno = 0;
	RES_SET_H_ERRNO(statp, HOST_NOT_FOUND);  /* True if we never query. */

	dots = 0;
	for (cp = name; *cp != '\0'; cp++)
		dots += (*cp == '.');
	trailing_dot = 0;
	if (cp > name && *--cp == '.')
		trailing_dot++;

	/* If there aren't any dots, it could be a user-level alias. */
	if (!dots && (cp = res_hostalias(statp, name, tmp, sizeof tmp))!= NULL)
		return (res_nquery(statp, cp, class, type, answer, anslen));

	/*
	 * If there are enough dots in the name, let's just give it a
	 * try 'as is'. The threshold can be set with the "ndots" option.
	 * Also, query 'as is', if there is a trailing dot in the name.
	 */
	saved_herrno = -1;
	if (dots >= statp->ndots || trailing_dot) {
		ret = res_nquerydomain(statp, name, NULL, class, type,
					 answer, anslen);
		if (ret > 0 || trailing_dot)
			return (ret);
		saved_herrno = statp->res_h_errno;
		tried_as_is++;
	}

	/*
	 * We do at least one level of search if
	 *	- there is no dot and RES_DEFNAME is set, or
	 *	- there is at least one dot, there is no trailing dot,
	 *	  and RES_DNSRCH is set.
	 */
	if ((!dots && (statp->options & RES_DEFNAMES) != 0U) ||
	    (dots && !trailing_dot && (statp->options & RES_DNSRCH) != 0U)) {
		int done = 0;

		/* Unfortunately we need to load network-specific info
		 * (dns servers, search domains) before
		 * the domain stuff is tried.  Will have a better
		 * fix after thread pools are used as this will
		 * be loaded once for the thread instead of each
		 * time a query is tried.
		 */
		_resolv_populate_res_for_net(statp);

		for (domain = (const char * const *)statp->dnsrch;
		     *domain && !done;
		     domain++) {
			searched = 1;

			if (domain[0][0] == '\0' ||
			    (domain[0][0] == '.' && domain[0][1] == '\0'))
				root_on_list++;

			ret = res_nquerydomain(statp, name, *domain,
					       class, type,
					       answer, anslen);
			if (ret > 0)
				return (ret);

			/*
			 * If no server present, give up.
			 * If name isn't found in this domain,
			 * keep trying higher domains in the search list
			 * (if that's enabled).
			 * On a NO_DATA error, keep trying, otherwise
			 * a wildcard entry of another type could keep us
			 * from finding this entry higher in the domain.
			 * If we get some other error (negative answer or
			 * server failure), then stop searching up,
			 * but try the input name below in case it's
			 * fully-qualified.
			 */
			if (errno == ECONNREFUSED) {
				RES_SET_H_ERRNO(statp, TRY_AGAIN);
				return (-1);
			}

			switch (statp->res_h_errno) {
			case NO_DATA:
				got_nodata++;
				/* FALLTHROUGH */
			case HOST_NOT_FOUND:
				/* keep trying */
				break;
			case TRY_AGAIN:
				if (hp->rcode == SERVFAIL) {
					/* try next search element, if any */
					got_servfail++;
					break;
				}
				/* FALLTHROUGH */
			default:
				/* anything else implies that we're done */
				done++;
			}

			/* if we got here for some reason other than DNSRCH,
			 * we only wanted one iteration of the loop, so stop.
			 */
			if ((statp->options & RES_DNSRCH) == 0U)
				done++;
		}
	}

	/*
	 * If the query has not already been tried as is then try it
	 * unless RES_NOTLDQUERY is set and there were no dots.
	 */
	if ((dots || !searched || (statp->options & RES_NOTLDQUERY) == 0U) &&
	    !(tried_as_is || root_on_list)) {
		ret = res_nquerydomain(statp, name, NULL, class, type,
				       answer, anslen);
		if (ret > 0)
			return (ret);
	}

	/* if we got here, we didn't satisfy the search.
	 * if we did an initial full query, return that query's H_ERRNO
	 * (note that we wouldn't be here if that query had succeeded).
	 * else if we ever got a nodata, send that back as the reason.
	 * else send back meaningless H_ERRNO, that being the one from
	 * the last DNSRCH we did.
	 */
	if (saved_herrno != -1)
		RES_SET_H_ERRNO(statp, saved_herrno);
	else if (got_nodata)
		RES_SET_H_ERRNO(statp, NO_DATA);
	else if (got_servfail)
		RES_SET_H_ERRNO(statp, TRY_AGAIN);
	return (-1);
}

/*
 * Perform a call on res_query on the concatenation of name and domain,
 * removing a trailing dot from name if domain is NULL.
 */
int
res_nquerydomain(res_state statp,
	    const char *name,
	    const char *domain,
	    int class, int type,	/* class and type of query */
	    u_char *answer,		/* buffer to put answer */
	    int anslen)		/* size of answer */
{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	int n, d;

#ifdef DEBUG
	if (statp->options & RES_DEBUG)
		printf(";; res_nquerydomain(%s, %s, %d, %d)\n",
		       name, domain?domain:"<Nil>", class, type);
#endif
	if (domain == NULL) {
		/*
		 * Check for trailing '.';
		 * copy without '.' if present.
		 */
		n = strlen(name);
		if (n >= MAXDNAME) {
			RES_SET_H_ERRNO(statp, NO_RECOVERY);
			return (-1);
		}
		n--;
		if (n >= 0 && name[n] == '.') {
			strncpy(nbuf, name, (size_t)n);
			nbuf[n] = '\0';
		} else
			longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + d + 1 >= MAXDNAME) {
			RES_SET_H_ERRNO(statp, NO_RECOVERY);
			return (-1);
		}
		snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
	}
	return (res_nquery(statp, longname, class, type, answer, anslen));
}

const char *
res_hostalias(const res_state statp, const char *name, char *dst, size_t siz) {
	return (NULL);
}

"""

```