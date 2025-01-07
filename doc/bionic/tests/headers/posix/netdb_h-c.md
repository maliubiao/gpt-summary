Response:
Let's break down the thought process for analyzing the `netdb_h.c` file and generating the comprehensive response.

**1. Understanding the Purpose of the File:**

The first step is to recognize that `netdb_h.c` under `bionic/tests/headers/posix/` is a *header test file*. It's not implementing networking functionality directly. Instead, it's checking for the presence and correct definition of elements within the `netdb.h` header file. This is crucial for ensuring API compatibility and correctness.

**2. Identifying Key Elements within the Code:**

The code uses several helper macros (`TYPE`, `STRUCT_MEMBER`, `MACRO`, `FUNCTION`). These make the structure of the test clear. I need to identify what each of these categories represents:

*   `TYPE(...)`: Checks if a given type (like `struct hostent`) is defined.
*   `STRUCT_MEMBER(..., ...)`: Checks if a specific member exists within a structure.
*   `MACRO(...)`: Checks if a macro is defined.
*   `FUNCTION(..., ...)`: Checks if a function with a specific signature exists.

**3. Categorizing the Checked Elements:**

As I go through the code, I should mentally group the checked elements:

*   **Structures:**  `hostent`, `netent`, `protoent`, `servent`, `addrinfo`. These are data structures used to represent network information.
*   **Structure Members:**  The fields within the above structures (e.g., `h_name` in `hostent`).
*   **Macros:**  Constants and flags related to network operations (e.g., `AI_PASSIVE`, `EAI_AGAIN`).
*   **Functions:**  Functions for network address and service lookups and manipulation (e.g., `getaddrinfo`, `gethostent`).

**4. Determining the Functionality Being Tested:**

Based on the elements being checked, I can infer the overall functionality covered by `netdb.h`:

*   **Host Name Resolution:**  Looking up IP addresses given a hostname (and vice-versa). Relates to `hostent`, `gethostent`, `getnameinfo`.
*   **Network Information:**  Retrieving information about networks (less commonly used now). Relates to `netent`, `getnetbyaddr`, `getnetbyname`.
*   **Protocol Information:**  Getting details about network protocols (like TCP, UDP). Relates to `protoent`, `getprotobyname`, `getprotobynumber`.
*   **Service Information:**  Finding port numbers and protocol for named services (like HTTP, SSH). Relates to `servent`, `getservbyname`, `getservbyport`.
*   **Address Information:**  A more modern and flexible way to handle network address resolution, supporting IPv4 and IPv6. Relates to `addrinfo`, `getaddrinfo`, `freeaddrinfo`.
*   **Error Handling:**  Constants representing errors from address/name resolution. Relates to the `EAI_` macros and `gai_strerror`.

**5. Relating to Android:**

Since `bionic` is Android's C library, any functionality covered by `netdb.h` is directly relevant to Android. Examples:

*   Apps need to resolve hostnames to connect to servers.
*   Networking components in the Android system use these functions.

**6. Explaining Libc Function Implementation:**

This requires some general knowledge about how these functions are typically implemented. Key considerations:

*   **Platform Differences:**  Implementations vary between operating systems. The answer should acknowledge this.
*   **DNS Lookups:**  `getaddrinfo` and related functions often involve DNS queries.
*   **Local Files:**  `/etc/hosts`, `/etc/networks`, `/etc/protocols`, `/etc/services` are traditional sources of information.
*   **NSS (Name Service Switch):**  Modern systems use NSS for a pluggable mechanism to resolve names and addresses. Bionic likely uses its own implementation or a simplified version.

**7. Addressing Dynamic Linking (If Applicable):**

The provided code *doesn't directly demonstrate dynamic linking*. It's just checking header definitions. Therefore, the answer should state that the file itself doesn't involve dynamic linking and explain *why* (it's a header test). However, it's good to mention where the actual implementation of these functions *would* reside (likely in `libc.so`). If the test *were* about a function that was dynamically linked from another library, then a SO layout example and linking process explanation would be needed.

**8. Providing Examples (Input/Output, Usage Errors):**

*   **Input/Output:**  Simple examples for `getaddrinfo` are good to illustrate how the functions are used.
*   **Usage Errors:**  Common mistakes like not freeing memory returned by `getaddrinfo` or passing invalid arguments should be highlighted.

**9. Tracing from Android Framework/NDK:**

This requires understanding the Android architecture. The general flow is:

*   An app (Java/Kotlin) makes a network request (e.g., using `HttpURLConnection`, `OkHttp`).
*   The Android framework (Java code) uses native methods (JNI).
*   The native methods call standard C library functions like `getaddrinfo`.

A Frida hook example demonstrating interception at the `getaddrinfo` level is a good way to illustrate this.

**10. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use bullet points and code blocks to improve readability. Address each part of the prompt thoroughly.

**Self-Correction/Refinement during the thought process:**

*   **Initial Thought:** "This file implements network functions."  **Correction:** "No, it *tests* the definitions of network-related elements in a header file."
*   **Concern:**  "I need to explain the *exact* implementation of `getaddrinfo` in Bionic." **Refinement:** "Focus on the general principles and acknowledge platform variations. I don't have the internal Bionic source code here."
*   **Realization:** "The dynamic linking part of the prompt doesn't directly apply to *this specific file*." **Clarification:** Explain why and where dynamic linking would be relevant in the broader context of these functions.

By following this structured approach and constantly evaluating my understanding, I can generate a comprehensive and accurate answer to the prompt.
这个文件 `bionic/tests/headers/posix/netdb_h.c` 的主要功能是**测试 `netdb.h` 头文件的正确性**。它并不实现任何实际的网络功能。  在 Android Bionic 的构建过程中，这类测试文件用于确保头文件定义了预期的结构体、宏和函数原型。这对于保证 API 的兼容性和正确性至关重要。

**具体功能列表:**

该测试文件通过一系列的 `TYPE`, `STRUCT_MEMBER`, `MACRO`, 和 `FUNCTION` 宏来检查 `netdb.h` 中定义的：

*   **结构体 (Structures):**
    *   `struct hostent`: 用于存储主机信息的结构体（例如，主机名、别名、地址类型、地址长度、地址列表）。
    *   `struct netent`: 用于存储网络信息的结构体（例如，网络名、别名、地址类型、网络号）。
    *   `struct protoent`: 用于存储协议信息的结构体（例如，协议名、别名、协议号）。
    *   `struct servent`: 用于存储服务信息的结构体（例如，服务名、别名、端口号、协议名）。
    *   `struct addrinfo`: 用于存储地址信息的结构体，是比 `hostent` 更现代且通用的结构体，支持 IPv4 和 IPv6。

*   **结构体成员 (Structure Members):** 检查上述每个结构体是否包含预期的成员变量及其类型。例如，`STRUCT_MEMBER(struct hostent, char*, h_name)` 检查 `struct hostent` 是否有名为 `h_name` 的 `char*` 类型成员。

*   **宏定义 (Macros):**
    *   `IPPORT_RESERVED`:  定义了保留端口的起始值。
    *   `AI_PASSIVE`, `AI_CANONNAME`, `AI_NUMERICHOST`, `AI_NUMERICSERV`, `AI_V4MAPPED`, `AI_ALL`, `AI_ADDRCONFIG`:  `getaddrinfo` 函数的标志位。
    *   `NI_NOFQDN`, `NI_NUMERICHOST`, `NI_NAMEREQD`, `NI_NUMERICSERV`, `NI_DGRAM`: `getnameinfo` 函数的标志位。
    *   `EAI_AGAIN`, `EAI_BADFLAGS`, `EAI_FAIL`, `EAI_FAMILY`, `EAI_MEMORY`, `EAI_NONAME`, `EAI_SERVICE`, `EAI_SOCKTYPE`, `EAI_SYSTEM`, `EAI_OVERFLOW`: `getaddrinfo` 和 `getnameinfo` 函数可能返回的错误码。

*   **函数原型 (Function Prototypes):** 检查 `netdb.h` 中声明的函数的存在及其签名（参数和返回值类型）。例如，`FUNCTION(getaddrinfo, int (*f)(const char*, const char*, const struct addrinfo*, struct addrinfo**))` 检查是否存在名为 `getaddrinfo` 的函数，并且其签名是否匹配。  列出的函数都是用于网络地址和主机名解析、服务和协议信息查询的 POSIX 标准函数。

**与 Android 功能的关系及举例说明:**

`netdb.h` 中定义的元素是 Android 系统进行网络编程的基础。Android 的应用程序和系统服务在进行网络通信时，会直接或间接地使用这些结构体和函数。

*   **域名解析:** 当 Android 应用需要连接到一个使用域名标识的服务器时（例如，访问 `www.google.com`），系统会使用 `getaddrinfo` 或 `gethostent` 函数将域名解析为 IP 地址。
    *   **示例:**  一个浏览器应用 (Chrome) 通过 URL `https://www.example.com` 发起请求。Android 系统内部会调用 `getaddrinfo("www.example.com", "https", ...)` 来获取 `www.example.com` 的 IP 地址，以便建立 TCP 连接。

*   **获取网络信息:** 虽然不太常用，但一些网络工具或系统级应用可能会使用 `getnetbyname` 或 `getnetbyaddr` 来查询网络信息。

*   **获取协议信息:**  网络编程中，有时需要根据协议名（如 "tcp" 或 "udp"）获取协议号，或者反之。`getprotobyname` 和 `getprotobynumber` 就用于此目的。

*   **获取服务信息:**  在进行端口绑定或连接时，可以使用 `getservbyname` 和 `getservbyport` 来查找特定服务的端口号和协议。
    *   **示例:**  一个 FTP 服务器程序可能会调用 `getservbyname("ftp", "tcp")` 来确定 FTP 服务的标准端口号 (21) 和协议 (tcp)。

**libc 函数的实现细节:**

这些 `netdb.h` 中声明的函数的具体实现位于 Android Bionic 的 `libc.so` 库中。  这些函数的实现通常涉及以下步骤：

*   **`getaddrinfo`:**  这是一个现代的地址解析函数，它尝试将主机名和服务名转换为套接字地址结构列表。其实现通常包括：
    1. **参数解析和验证:** 检查传入的参数是否有效。
    2. **查找缓存:**  检查本地是否有缓存的地址信息。
    3. **DNS 查询:** 如果主机名是域名，则会发起 DNS 查询请求到配置的 DNS 服务器。这可能涉及多个 DNS 查询（例如，先查 IPv6 的 AAAA 记录，再查 IPv4 的 A 记录）。
    4. **本地主机文件 (`/etc/hosts`) 查询:** 检查本地的 `/etc/hosts` 文件中是否有匹配的条目。
    5. **名称服务切换 (NSS):**  Bionic 使用自己的 NSS 实现，允许通过不同的源（例如，DNS, files）来解析主机名和服务名。
    6. **结果构建:** 将查询到的地址信息填充到 `addrinfo` 结构体链表中。
    7. **错误处理:**  处理各种可能发生的错误，例如 DNS 查询失败、内存分配失败等。

*   **`gethostent`:**  这是一个较老的地址解析函数，主要用于 IPv4。它的实现方式与 `getaddrinfo` 类似，但功能较少，不支持更灵活的查询选项。它通常依赖于 `/etc/hosts` 文件和 DNS 查询。

*   **`getnameinfo`:**  这个函数的功能与 `getaddrinfo` 相反，它将套接字地址结构转换为主机名和服务名。其实现通常包括：
    1. **反向 DNS 查询:** 对于 IP 地址，尝试进行反向 DNS 查询 (PTR 记录) 以获取主机名。
    2. **查找本地服务数据库:**  根据端口号和协议查找对应的服务名。

*   **`getnetbyaddr` 和 `getnetbyname`:**  这些函数用于查找网络信息。在现代网络环境中，这些函数的使用较少，其实现可能依赖于本地配置文件（如 `/etc/networks`，尽管这个文件现在通常为空）。

*   **`getprotobyname` 和 `getprotobynumber`:**  这些函数用于查找协议信息。其实现通常依赖于本地配置文件 `/etc/protocols`。

*   **`getservbyname` 和 `getservbyport`:**  这些函数用于查找服务信息。其实现通常依赖于本地配置文件 `/etc/services`。

*   **`sethostent`, `setnetent`, `setprotoent`, `setservent`, `endhostent`, `endnetent`, `endprotoent`, `endservent`:**  这些函数用于控制遍历本地网络数据库文件（如 `/etc/hosts` 等）。例如，`sethostent(0)` 会打开 `/etc/hosts` 文件以便顺序读取主机信息，`gethostent()` 会读取下一条记录，`endhostent()` 会关闭文件。

**涉及 dynamic linker 的功能及 SO 布局样本和链接处理过程:**

`netdb_h.c` 本身是一个头文件测试，并不涉及动态链接。  实际实现 `netdb.h` 中声明的函数的代码位于 `libc.so` 中。

**SO 布局样本 (`libc.so`)：**

```
libc.so:
    .text           # 包含可执行代码
        getaddrinfo:  # getaddrinfo 函数的实现代码
            ...
        gethostent:   # gethostent 函数的实现代码
            ...
        ...          # 其他 netdb.h 中函数的实现
    .data           # 包含已初始化的全局变量
        ...
    .bss            # 包含未初始化的全局变量
        ...
    .dynsym         # 动态符号表，列出导出的符号 (函数和变量)
        getaddrinfo
        gethostent
        ...
    .dynstr         # 动态字符串表，存储符号名称
        ...
    .plt            # 程序链接表，用于延迟绑定
        getaddrinfo@LIBC
        gethostent@LIBC
        ...
    .got.plt        # 全局偏移表，存储外部符号的地址 (初始时指向 PLT 条目)
        ...
```

**链接处理过程：**

1. **编译时：** 当一个应用程序或库使用了 `netdb.h` 中的函数时，编译器会找到这些函数的声明，但并不会包含它们的具体实现代码。编译器会将这些函数调用标记为需要外部链接。

2. **链接时：** 链接器（在 Android 上通常是 `lld`）会将应用程序或库的目标文件与所需的共享库（如 `libc.so`）链接在一起。
    *   链接器会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `getaddrinfo`, `gethostent` 等函数的符号。
    *   链接器会在应用程序或库的可执行文件中创建 `.plt` (Procedure Linkage Table) 和 `.got.plt` (Global Offset Table)。
    *   对于每个需要动态链接的外部函数，链接器会在 `.plt` 中创建一个条目，并在 `.got.plt` 中分配一个条目来存储该函数的最终地址。初始时，`.got.plt` 中的条目指向对应的 `.plt` 条目。

3. **运行时（首次调用动态链接函数时）：**
    *   当程序首次调用 `getaddrinfo` 时，控制流会跳转到 `.plt` 中 `getaddrinfo` 对应的条目。
    *   `.plt` 条目中的代码会将控制权交给动态链接器 (linker，通常是 `/system/bin/linker64` 或 `/system/bin/linker`)。
    *   动态链接器会查找 `libc.so` 中 `getaddrinfo` 函数的实际地址。
    *   动态链接器会将 `getaddrinfo` 的实际地址写入 `.got.plt` 中对应的条目。
    *   动态链接器将控制权返回给程序，程序会通过更新后的 `.got.plt` 条目跳转到 `getaddrinfo` 的实际代码。

4. **运行时（后续调用）：**
    *   当程序后续再次调用 `getaddrinfo` 时，控制流仍然会跳转到 `.plt` 条目。
    *   但是，由于 `.got.plt` 中的地址已经被动态链接器更新为 `getaddrinfo` 的实际地址，程序会直接跳转到该函数的代码，而无需再次调用动态链接器。这称为**延迟绑定**。

**逻辑推理 (假设输入与输出):**

虽然 `netdb_h.c` 本身不涉及逻辑推理，但我们可以假设一个使用 `getaddrinfo` 的场景：

**假设输入:**

*   `hostname`: "www.example.com"
*   `service`: "http"
*   `hints`:  `NULL` (使用默认设置)

**预期输出:**

`getaddrinfo` 可能会返回一个 `addrinfo` 结构体链表，其中包含以下信息（具体内容取决于 DNS 解析结果）：

*   一个或多个 `addrinfo` 结构体。
*   每个 `addrinfo` 结构体的 `ai_family` 可能是 `AF_INET` (IPv4) 或 `AF_INET6` (IPv6)。
*   每个 `addrinfo` 结构体的 `ai_socktype` 可能是 `SOCK_STREAM` (TCP)。
*   每个 `addrinfo` 结构体的 `ai_protocol` 可能是 `IPPROTO_TCP`.
*   每个 `addrinfo` 结构体的 `ai_addr` 指向一个 `sockaddr_in` 或 `sockaddr_in6` 结构体，其中包含 `www.example.com` 的 IP 地址 (例如, `192.0.2.1` 或 `2001:db8::1`) 和端口号 (80)。

**用户或编程常见的使用错误:**

*   **忘记检查返回值:** `getaddrinfo` 等函数在出错时会返回非零值。不检查返回值可能导致程序在遇到网络问题时崩溃或行为异常。
*   **内存泄漏:** `getaddrinfo` 成功时会分配内存来存储 `addrinfo` 结构体链表。使用完毕后，必须调用 `freeaddrinfo` 来释放这些内存，否则会导致内存泄漏。
    ```c
    struct addrinfo *res;
    int error = getaddrinfo("www.example.com", "http", NULL, &res);
    if (error) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(error));
        // 忘记释放 res 指向的内存！
        return 1;
    }
    // ... 使用 res ...
    freeaddrinfo(res); // 正确的做法
    ```
*   **错误地使用 `hints` 参数:**  `hints` 参数可以用来指定期望的地址族、套接字类型等。如果使用不当，可能会导致 `getaddrinfo` 返回空结果或不期望的结果。
*   **混淆 `gethostbyname` 和 `getaddrinfo`:** `gethostbyname` 是一个较老的函数，只支持 IPv4。推荐使用 `getaddrinfo`，因为它更灵活，支持 IPv6。
*   **在多线程程序中不正确地使用 `gethostbyname`:**  `gethostbyname` 不是线程安全的，在多线程程序中应避免使用或采取适当的同步措施。 `getaddrinfo` 是线程安全的。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

1. **Android Framework (Java/Kotlin):**  Android 应用通常通过 Java 或 Kotlin 代码进行网络操作，例如使用 `java.net.URL`, `HttpURLConnection`, `OkHttp` 等。

2. **Framework Native 代码:** 这些 Java/Kotlin 网络 API 的底层实现会调用 Android Framework 的 Native 代码（通常是用 C++ 编写），这些 Native 代码会使用 Bionic 提供的网络库函数。

3. **NDK:**  使用 NDK 开发的 C/C++ 应用可以直接调用 Bionic 提供的 `netdb.h` 中的函数。

**Frida Hook 示例调试 `getaddrinfo`:**

以下是一个使用 Frida Hook 拦截 `getaddrinfo` 函数调用的示例：

```javascript
if (Process.platform === 'android') {
  const getaddrinfoPtr = Module.findExportByName("libc.so", "getaddrinfo");

  if (getaddrinfoPtr) {
    Interceptor.attach(getaddrinfoPtr, {
      onEnter: function (args) {
        const hostname = Memory.readCString(args[0]);
        const service = Memory.readCString(args[1]);
        console.log(`[getaddrinfo] Hostname: ${hostname}, Service: ${service}`);
        // 可以修改参数，例如强制使用 IPv4
        // const hints = ptr(args[2]);
        // if (hints.isNull() === false) {
        //   Memory.writeU32(hints.add(4), 2); // AF_INET = 2
        // }
      },
      onLeave: function (retval) {
        console.log(`[getaddrinfo] Returned: ${retval}`);
        if (retval === 0) {
          const resPtr = Memory.readPointer(this.context.sp.add(Process.pointerSize * 3)); // 根据架构调整栈偏移
          if (!resPtr.isNull()) {
            const ai_family = Memory.readU32(resPtr);
            const ai_socktype = Memory.readU32(resPtr.add(4));
            const ai_protocol = Memory.readU32(resPtr.add(8));
            console.log(`[getaddrinfo] Result: ai_family=${ai_family}, ai_socktype=${ai_socktype}, ai_protocol=${ai_protocol}`);
            // 进一步解析 addrinfo 结构体
          }
        }
      }
    });
    console.log("Hooked getaddrinfo");
  } else {
    console.error("Failed to find getaddrinfo in libc.so");
  }
} else {
  console.log("Not running on Android");
}
```

**使用步骤:**

1. 将上述 JavaScript 代码保存为 `hook_getaddrinfo.js`。
2. 使用 Frida 连接到目标 Android 应用进程：
    ```bash
    frida -U -f <package_name> -l hook_getaddrinfo.js --no-pause
    ```
    或者，如果应用已经在运行：
    ```bash
    frida -U <package_name> -l hook_getaddrinfo.js
    ```
3. 当目标应用进行网络请求，调用 `getaddrinfo` 时，Frida 会拦截该调用，并在控制台上打印出主机名、服务名、返回值以及一些结果信息。

通过 Frida Hook，你可以动态地观察 `getaddrinfo` 的调用参数、返回值以及内部行为，从而调试 Android Framework 或 NDK 中涉及地址解析的步骤。你可以根据需要扩展 Hook 代码来检查更多的细节，例如 `addrinfo` 结构体中的 IP 地址等。

Prompt: 
```
这是目录为bionic/tests/headers/posix/netdb_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2017 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <netdb.h>

#include "header_checks.h"

static void netdb_h() {
  TYPE(struct hostent);
  STRUCT_MEMBER(struct hostent, char*, h_name);
  STRUCT_MEMBER(struct hostent, char**, h_aliases);
  STRUCT_MEMBER(struct hostent, int, h_addrtype);
  STRUCT_MEMBER(struct hostent, int, h_length);
  STRUCT_MEMBER(struct hostent, char**, h_addr_list);

  TYPE(struct netent);
  STRUCT_MEMBER(struct netent, char*, n_name);
  STRUCT_MEMBER(struct netent, char**, n_aliases);
  STRUCT_MEMBER(struct netent, int, n_addrtype);
  STRUCT_MEMBER(struct netent, uint32_t, n_net);

  TYPE(uint32_t);

  TYPE(struct protoent);
  STRUCT_MEMBER(struct protoent, char*, p_name);
  STRUCT_MEMBER(struct protoent, char**, p_aliases);
  STRUCT_MEMBER(struct protoent, int, p_proto);


  TYPE(struct servent);
  STRUCT_MEMBER(struct servent, char*, s_name);
  STRUCT_MEMBER(struct servent, char**, s_aliases);
  STRUCT_MEMBER(struct servent, int, s_port);
  STRUCT_MEMBER(struct servent, char*, s_proto);

  MACRO(IPPORT_RESERVED);

  TYPE(struct addrinfo);
  STRUCT_MEMBER(struct addrinfo, int, ai_flags);
  STRUCT_MEMBER(struct addrinfo, int, ai_family);
  STRUCT_MEMBER(struct addrinfo, int, ai_socktype);
  STRUCT_MEMBER(struct addrinfo, int, ai_protocol);
  STRUCT_MEMBER(struct addrinfo, socklen_t, ai_addrlen);
  STRUCT_MEMBER(struct addrinfo, struct sockaddr*, ai_addr);
  STRUCT_MEMBER(struct addrinfo, char*, ai_canonname);
  STRUCT_MEMBER(struct addrinfo, struct addrinfo*, ai_next);

  MACRO(AI_PASSIVE);
  MACRO(AI_CANONNAME);
  MACRO(AI_NUMERICHOST);
  MACRO(AI_NUMERICSERV);
  MACRO(AI_V4MAPPED);
  MACRO(AI_ALL);
  MACRO(AI_ADDRCONFIG);

  MACRO(NI_NOFQDN);
  MACRO(NI_NUMERICHOST);
  MACRO(NI_NAMEREQD);
  MACRO(NI_NUMERICSERV);
#if !defined(__BIONIC__) && !defined(__GLIBC__)
  MACRO(NI_NUMERICSCOPE);
#endif
  MACRO(NI_DGRAM);

  MACRO(EAI_AGAIN);
  MACRO(EAI_BADFLAGS);
  MACRO(EAI_FAIL);
  MACRO(EAI_FAMILY);
  MACRO(EAI_MEMORY);
  MACRO(EAI_NONAME);
  MACRO(EAI_SERVICE);
  MACRO(EAI_SOCKTYPE);
  MACRO(EAI_SYSTEM);
  MACRO(EAI_OVERFLOW);

  FUNCTION(endhostent, void (*f)(void));
  FUNCTION(endnetent, void (*f)(void));
  FUNCTION(endprotoent, void (*f)(void));
  FUNCTION(endservent, void (*f)(void));
  FUNCTION(freeaddrinfo, void (*f)(struct addrinfo*));
  FUNCTION(gai_strerror, const char* (*f)(int));
  FUNCTION(getaddrinfo, int (*f)(const char*, const char*, const struct addrinfo*, struct addrinfo**));
  FUNCTION(gethostent, struct hostent* (*f)(void));
#if defined(__BIONIC__) // Historical ABI accident.
  FUNCTION(getnameinfo, int (*f)(const struct sockaddr*, socklen_t, char*, size_t, char*, size_t, int));
#else
  FUNCTION(getnameinfo, int (*f)(const struct sockaddr*, socklen_t, char*, socklen_t, char*, socklen_t, int));
#endif
  FUNCTION(getnetbyaddr, struct netent* (*f)(uint32_t, int));
  FUNCTION(getnetbyname, struct netent* (*f)(const char*));
  FUNCTION(getnetent, struct netent* (*f)(void));
  FUNCTION(getprotobyname, struct protoent* (*f)(const char*));
  FUNCTION(getprotobynumber, struct protoent* (*f)(int));
  FUNCTION(getprotoent, struct protoent* (*f)(void));
  FUNCTION(getservbyname, struct servent* (*f)(const char*, const char*));
  FUNCTION(getservbyport, struct servent* (*f)(int, const char*));
  FUNCTION(getservent, struct servent* (*f)(void));
  FUNCTION(sethostent, void (*f)(int));
  FUNCTION(setnetent, void (*f)(int));
  FUNCTION(setprotoent, void (*f)(int));
  FUNCTION(setservent, void (*f)(int));

  TYPE(socklen_t);
}

"""

```