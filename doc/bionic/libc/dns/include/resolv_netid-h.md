Response:
Let's break down the thought process for analyzing this header file.

1. **Understanding the Context:** The first step is to recognize the file's location: `bionic/libc/dns/include/resolv_netid.handroid`. This immediately tells us it's part of Android's C library (`bionic`), specifically dealing with DNS resolution, and likely related to network IDs. The `.handroid` suffix suggests it's an internal header for Android and not part of the public NDK.

2. **Identifying the Core Purpose:**  The comments at the beginning are crucial. They state that this header deals with "per-network DNS server selection" and is used by `system/netd/`. This highlights the key function: managing DNS resolution differently based on the network the application is using.

3. **Analyzing Key Definitions:**  Next, go through the `#define` statements:
    * `NETID_UNSET`: Signals that the system should automatically determine the appropriate network.
    * `MARK_UNSET`: Represents the default socket mark. These hints about how network traffic is tagged.

4. **Examining the `android_net_context` Structure:** This is a central element. Deconstruct its members:
    * `app_netid`, `app_mark`:  Relate to the application's network context.
    * `dns_netid`, `dns_mark`: Relate to the DNS resolution's network context. The comment about VPNs highlights the distinction.
    * `uid`:  Introduces the concept of per-UID routing for DNS.
    * `flags`:  Indicates optional behavior.
    * `qhook`:  Suggests a mechanism for intercepting or modifying DNS queries.

5. **Analyzing the Function Declarations:** This is where the functionality becomes more concrete. Look for patterns and common elements:
    * **Naming Convention:** Functions starting with `android_` and ending with `fornet` or `fornetcontext` clearly relate to network-specific DNS resolution.
    * **`fornet` vs. `fornetcontext`:** The presence of both suggests that sometimes you provide individual `netid` and `mark`, and other times you pass the entire `android_net_context` structure. The latter likely offers more comprehensive context.
    * **Function Types:**  `gethostbyaddr`, `gethostbyname`, `getaddrinfo` are standard DNS resolution functions. The `android_` versions adapt them for network awareness.
    * **`_resolv_set_nameservers_for_net`, `_resolv_flush_cache_for_net`, `_resolv_delete_cache_for_net`:** These clearly indicate administrative functions for managing per-network DNS settings and caching.
    * **`__used_in_netd` and `__LIBC_HIDDEN__`:** These visibility attributes are essential for understanding the intended scope of the functions. `__used_in_netd` means it's meant for use by the `netd` daemon, while `__LIBC_HIDDEN__` means it's an internal implementation detail of `libc`.

6. **Connecting to Android Concepts:**  Now, tie the pieces together with Android features:
    * **Network Isolation:**  The concept of network IDs directly relates to how Android isolates network traffic for different apps, users, and VPNs.
    * **VPNs:** The comment within `android_net_context` explicitly mentions VPNs as a key use case.
    * **`netd`:**  The header's explicit connection to `system/netd/` is vital. Understand that `netd` is the network management daemon in Android.
    * **UID-based routing:** The `uid` field ties into Android's user and application management.

7. **Inferring Implementation and Usage:** Based on the function signatures and names, infer the general implementation strategies. For example, `android_getaddrinfofornetcontext` likely takes the context, extracts the relevant `netid` and potentially `mark`, and then uses lower-level networking APIs (possibly within `netd`) to perform the DNS lookup on the correct network.

8. **Considering Edge Cases and Errors:** Think about how these functions might be misused or encounter errors. Passing invalid network IDs or incorrect buffer sizes are common programming mistakes.

9. **Sketching the Flow:**  Imagine the steps involved when an Android app makes a network request. How does the request eventually reach these functions? This involves the Android Framework, potentially the NDK, and eventually down to `libc`.

10. **Crafting the Frida Hook:** Based on the identified functions and their purpose, design Frida hooks to intercept these calls, observe their arguments (like `netid` and the hostname), and potentially modify their behavior.

11. **Structuring the Output:** Organize the analysis logically, starting with a high-level overview, then diving into details of the functions, linking them to Android concepts, and finally providing practical examples like Frida hooks.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is just about setting DNS servers.
* **Correction:** The `android_net_context` structure and the distinction between app and DNS netids show it's more about *routing* DNS requests to the correct network.
* **Initial thought:** How are these functions called directly by apps?
* **Correction:** They're likely used internally by Android system services and potentially exposed through higher-level APIs or indirectly through standard socket calls handled by `netd`. The `__used_in_netd` attribute reinforces this.
* **Initial thought:** The `qhook` is unclear.
* **Refinement:** It's likely a hook for intercepting and potentially modifying DNS queries before they are sent, potentially used for implementing features like local DNS resolution or VPN-specific DNS handling.

By following this systematic approach, combining careful reading of the code and comments with knowledge of Android architecture, it's possible to generate a comprehensive and accurate analysis of the header file.
这个头文件 `bionic/libc/dns/include/resolv_netid.handroid` 是 Android Bionic C 库中关于 **基于网络 ID 的 DNS 解析** 的内部头文件。它定义了一些结构体和函数，用于支持 Android 系统根据不同的网络环境进行 DNS 查询。由于它带有 `.handroid` 后缀，表明它不是 Android NDK 的公共 API，而是 Android 内部使用的。

以下是它的功能分解：

**主要功能：**

1. **支持基于网络 ID 的 DNS 解析：**  Android 设备可以同时连接到多个网络（例如，移动数据、Wi-Fi、VPN）。这个头文件提供的函数允许系统指定 DNS 查询应该在哪个网络上进行。这对于确保应用程序的网络流量按照预期路由非常重要。

2. **管理 per-network 的 DNS 服务器配置：**  不同的网络可能使用不同的 DNS 服务器。这个头文件中的函数允许为特定的网络设置、刷新和删除 DNS 服务器配置。

3. **处理 VPN 场景：**  当设备连接到 VPN 时，VPN 可以有自己的 DNS 服务器。这个头文件中的机制允许应用程序的流量使用 VPN 提供的 DNS 服务器，即使应用程序本身可能运行在不同的网络上下文中。

4. **支持 UID 隔离的 DNS 解析：**  Android 引入了 per-UID 路由，这意味着可以根据发出请求的应用程序的用户 ID (UID) 来路由网络流量。这个头文件中的结构体和函数考虑了 UID，允许更精细的 DNS 解析控制。

**与 Android 功能的关系及举例说明：**

* **网络隔离 (Network Isolation)：** Android 使用网络 ID (netId) 来隔离不同的网络。例如，一个应用的网络流量可能被标记为一个特定的 netId，而另一个应用的流量可能被标记为另一个 netId。这个头文件中的函数允许 DNS 查询指定 `netId`，从而确保查询在正确的网络上进行。
    * **例子：** 当一个 VPN 应用连接后，它会创建一个新的网络接口和对应的 `netId`。使用 `android_getaddrinfofornetcontext` 等函数时，可以传入 VPN 的 `netId`，确保 DNS 查询通过 VPN 连接发送，解析到的地址也是 VPN 网络可访问的。

* **`netd` 守护进程：**  `system/netd/` (Network Daemon) 是 Android 系统中负责网络管理的关键组件。这个头文件中的函数主要被 `netd` 使用。`netd` 负责处理网络连接的建立、路由配置、防火墙规则以及 DNS 解析策略等。
    * **例子：**  当系统需要为一个特定的网络配置 DNS 服务器时，`netd` 会调用 `_resolv_set_nameservers_for_net` 函数。

* **Android Framework 的网络请求：** 当一个 Android 应用发起网络请求时，Android Framework 会根据应用的配置和当前的网络状态，选择合适的网络接口。这个过程会涉及到网络 ID 的确定。最终，底层的 DNS 解析操作会调用到 `bionic` 库中的函数。
    * **例子：**  当一个应用使用 `java.net.URL` 或 `android.net.ConnectivityManager` 发起网络请求时，Android Framework 会在底层调用 `getaddrinfo` 等系统调用。Bionic 中的 `android_getaddrinfofornetcontext` 等函数会被间接调用，根据当前的网络上下文（包括 `netId`）进行 DNS 解析。

**详细解释每个 libc 函数的功能是如何实现的：**

由于这是头文件，它只包含函数声明，没有具体实现。这些函数的实现在 `bionic/libc/dns/` 目录下对应的源文件中。以下是对声明的函数的功能进行推测性的解释：

* **`struct hostent *android_gethostbyaddrfornet(const void *addr, socklen_t len, int type, unsigned netid, unsigned mark)`:**
    * **功能：**  根据 IP 地址反向查找主机名，并在指定的网络上进行查询。
    * **实现推测：** 该函数可能会创建一个 DNS 查询包，并设置相关的网络绑定信息（例如，通过 socket 的 `SO_BINDTODEVICE` 选项或 `setsockopt` 设置 socket mark）。然后，它会将查询发送到与指定 `netid` 关联的 DNS 服务器。

* **`struct hostent *android_gethostbynamefornet(const char *name, int af, unsigned netid, unsigned mark)`:**
    * **功能：**  根据主机名查找 IP 地址，并在指定的网络上进行查询。
    * **实现推测：**  类似于 `android_gethostbyaddrfornet`，它会构建一个 DNS 查询包，包含要查询的主机名，并绑定到指定的网络进行发送。

* **`int android_getaddrinfofornet(const char *node, const char *service, const struct addrinfo *hints, unsigned netid, unsigned mark, struct addrinfo **res)`:**
    * **功能：**  将主机名和服务名转换为地址信息，并允许指定网络。
    * **实现推测：**  这是更现代的地址解析函数，支持 IPv4 和 IPv6。它会根据 `hints` 参数进行更灵活的查询，并返回一个链表的地址信息。实现上会考虑 `netid` 和 `mark` 来选择合适的网络接口和 DNS 服务器。

* **`struct hostent *android_gethostbyaddrfornetcontext(const void *addr, socklen_t len, int type, const struct android_net_context *context)`:**
* **`struct hostent *android_gethostbynamefornetcontext(const char *name, int af, const struct android_net_context *context)`:**
* **`int android_getaddrinfofornetcontext(const char *node, const char *service, const struct addrinfo *hints, const struct android_net_context *context, struct addrinfo **res)`:**
    * **功能：**  这些函数与上面的 `fornet` 版本类似，但它们接受一个 `android_net_context` 结构体作为参数，其中包含了更丰富的网络上下文信息（包括应用和 DNS 的 `netid`、`mark`、`uid` 等）。
    * **实现推测：**  这些函数会从 `android_net_context` 结构体中提取必要的网络信息，例如 `dns_netid` 和 `dns_mark`，并使用这些信息来执行 DNS 查询。对于 VPN 场景，`app_netid` 可能与 `dns_netid` 不同。

* **`extern int _resolv_set_nameservers_for_net(unsigned netid, const char** servers, unsigned numservers, const char *domains, const struct __res_params* params)`:**
    * **功能：**  为指定的网络 ID 设置 DNS 服务器。
    * **实现推测：**  该函数可能会更新一个全局的数据结构，该结构存储了每个网络的 DNS 服务器配置。这个数据结构会被 DNS 解析函数使用。

* **`extern void _resolv_flush_cache_for_net(unsigned netid)`:**
    * **功能：**  刷新与特定网络 ID 关联的 DNS 缓存。
    * **实现推测：**  DNS 解析结果通常会被缓存以提高性能。此函数会清除指定网络的缓存条目。

* **`extern void _resolv_delete_cache_for_net(unsigned netid)`:**
    * **功能：**  删除与特定网络 ID 关联的 DNS 缓存。
    * **实现推测：**  与刷新缓存不同，删除缓存可能会释放相关的资源。

* **`struct hostent *android_gethostbyaddrfornetcontext_proxy(const void *addr, socklen_t len, int type, const struct android_net_context *context)`:**
    * **功能：**  很可能是一个内部的代理函数，用于处理某些特殊情况下的反向 DNS 查询。`__LIBC_HIDDEN__` 表明它是内部使用的。

* **`int android_getnameinfofornet(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags, unsigned netid, unsigned mark)`:**
    * **功能：**  将套接字地址转换为主机名和服务名，并允许指定网络。
    * **实现推测：**  它是 `getnameinfo` 的网络感知版本，会考虑 `netid` 和 `mark` 来执行反向 DNS 查询。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身不直接涉及 dynamic linker 的功能。它定义的是 DNS 解析相关的函数接口。这些函数的实现位于 `libc.so` 中，它是由 dynamic linker 加载和链接的。

**`libc.so` 布局样本 (简化)：**

```
libc.so:
    .text          # 代码段
        android_gethostbyaddrfornet:
            # ... 实现代码 ...
        android_gethostbynamefornet:
            # ... 实现代码 ...
        # ... 其他 DNS 相关函数 ...
        _resolv_set_nameservers_for_net:
            # ... 实现代码 ...
    .data          # 数据段 (可能包含全局变量和 DNS 配置信息)
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息
        SONAME      libc.so
        NEEDED      libnetd_client.so  # 可能依赖于 netd 客户端库
        # ... 其他依赖和符号信息 ...
    .symtab        # 符号表 (包含导出的函数和变量)
        android_gethostbyaddrfornet
        android_gethostbynamefornet
        # ...
        _resolv_set_nameservers_for_net
    .strtab        # 字符串表
```

**链接的处理过程：**

1. **编译时：** 当编译一个需要使用这些 DNS 函数的程序时，编译器会找到对应的头文件，并记录下对这些函数的引用。

2. **链接时：** 链接器会将编译后的目标文件与 `libc.so` 链接起来。它会查找 `libc.so` 的符号表，找到 `android_gethostbyaddrfornet` 等函数的地址，并将这些地址填入程序的可执行文件中。

3. **运行时：** 当程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，包括 `libc.so`。

4. **符号解析 (Dynamic Linking)：** dynamic linker 会解析程序中对 `libc.so` 中函数的引用，并将它们绑定到 `libc.so` 中实际的函数地址。这个过程通常是延迟绑定的，即在函数第一次被调用时才解析。

5. **`netd` 的使用：** `netd` 守护进程在运行时也会加载 `libc.so`，并调用 `_resolv_set_nameservers_for_net` 等函数来管理 DNS 配置。

**如果做了逻辑推理，请给出假设输入与输出：**

**假设输入：**

* 调用 `android_gethostbynamefornet`，传入主机名 "www.google.com"，地址族 `AF_INET`，`netid` 为 `100`，`mark` 为 `0`。
* 假设网络 ID `100` 关联的网络配置了 DNS 服务器 `8.8.8.8` 和 `8.8.4.4`。

**逻辑推理：**

1. 函数会创建一个 DNS 查询包，目标主机为 "www.google.com"，查询类型为 A 记录 (IPv4 地址)。
2. 查询包会被发送到与 `netid` `100` 关联的 DNS 服务器 `8.8.8.8` 或 `8.8.4.4`。
3. DNS 服务器会返回 "www.google.com" 的 IPv4 地址。

**输出：**

* 如果查询成功，函数会返回一个指向 `hostent` 结构体的指针，其中包含了 "www.google.com" 的标准主机名、别名列表以及 IPv4 地址列表。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **传递错误的 `netid`：**  如果传递了一个不存在或不正确的 `netid`，DNS 查询可能无法到达预期的网络，导致解析失败或返回错误的结果。

2. **在错误的上下文中使用：**  这些函数是 Android 内部使用的，直接在应用代码中调用可能会导致不可预测的行为，因为它们依赖于 Android 系统的网络管理机制。开发者应该使用 Android Framework 提供的网络 API。

3. **内存管理错误：**  `gethostbyname` 和 `gethostbyaddr` 返回的 `hostent` 结构体通常是静态分配的，后续的调用可能会覆盖之前的结果。程序员需要注意拷贝数据。 `getaddrinfo` 返回的 `addrinfo` 链表需要手动 `freeaddrinfo` 释放内存。

4. **阻塞操作：**  这些 DNS 解析函数是阻塞的。在主线程中直接调用可能会导致应用无响应 (ANR)。应该在后台线程中执行 DNS 查询。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 Bionic DNS 函数的路径 (简化)：**

1. **应用发起网络请求：** 例如，使用 `java.net.URL` 创建一个 URL 对象并调用 `openConnection()`。
2. **URLConnection 处理：**  Android Framework 中的 `URLConnection` 实现（例如 `HttpURLConnection` 或 `HttpsURLConnection`) 会处理底层的网络连接。
3. **InetAddress 解析：** 当需要建立连接时，`URLConnection` 会调用 `InetAddress.getByName()` 或 `InetAddress.getAllByName()` 来解析主机名。
4. **Network Layer：**  `InetAddress` 的实现会调用到 Android Framework 的网络层，例如 `android.net.ConnectivityManager` 和 `android.net.Network`。
5. **System Services：**  Framework 会通过 Binder IPC 调用到系统服务，例如 `netd`。
6. **`netd` 处理：**  `netd` 接收到 DNS 解析请求，可能会调用 Bionic 库中的 `android_getaddrinfofornetcontext` 等函数。
7. **Bionic DNS 解析：**  Bionic 库的 DNS 解析函数执行实际的 DNS 查询，并返回结果。

**NDK 到 Bionic DNS 函数的路径：**

1. **NDK 应用调用 Socket API：**  NDK 应用可以使用标准的 Socket API (例如 `getaddrinfo`)。
2. **C 库封装：**  NDK 提供的 C 库头文件 (例如 `<netdb.h>`) 声明了 `getaddrinfo` 等函数。
3. **Bionic 实现：**  NDK 中的 `getaddrinfo` 函数实际上是 Bionic 库中的实现，可能会内部调用到 `android_getaddrinfofornetcontext` 等带 `netid` 的版本，以处理网络上下文。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `android_getaddrinfofornetcontext` 函数并打印其参数的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const android_getaddrinfofornetcontext = Module.findExportByName("libc.so", "android_getaddrinfofornetcontext");
  if (android_getaddrinfofornetcontext) {
    Interceptor.attach(android_getaddrinfofornetcontext, {
      onEnter: function (args) {
        const node = args[0];
        const service = args[1];
        const hints = args[2];
        const context = args[3];

        const nodeStr = node ? Memory.readUtf8String(node) : null;
        const serviceStr = service ? Memory.readUtf8String(service) : null;

        console.log("android_getaddrinfofornetcontext called:");
        console.log("  node:", nodeStr);
        console.log("  service:", serviceStr);
        // 解析 struct android_net_context
        if (context) {
          console.log("  context->app_netid:", context.readU32());
          console.log("  context->app_mark:", context.add(4).readU32());
          console.log("  context->dns_netid:", context.add(8).readU32());
          console.log("  context->dns_mark:", context.add(12).readU32());
          console.log("  context->uid:", context.add(16).readU32());
          console.log("  context->flags:", context.add(20).readU32());
        }
      },
      onLeave: function (retval) {
        console.log("android_getaddrinfofornetcontext returned:", retval);
      }
    });
  } else {
    console.log("Failed to find android_getaddrinfofornetcontext");
  }
}
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_dns.js`)。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_dns.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_dns.js
   ```
3. 当应用发起网络请求时，Frida 会拦截 `android_getaddrinfofornetcontext` 函数的调用，并在控制台输出相关的参数信息，包括主机名、服务名以及 `android_net_context` 结构体的成员。

通过 Frida Hook，可以深入了解 Android Framework 或 NDK 如何调用底层的 Bionic DNS 函数，以及传递了哪些网络上下文信息，这对于调试网络相关问题非常有帮助。

### 提示词
```
这是目录为bionic/libc/dns/include/resolv_netid.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * Copyright (C) 2014 The Android Open Source Project
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
#ifndef _RESOLV_NETID_H
#define _RESOLV_NETID_H

/* This header contains declarations related to per-network DNS
 * server selection. They are used by system/netd/ and should not be
 * exposed by the C library's public NDK headers.
 */
#include <sys/cdefs.h>
#include <netinet/in.h>
#include "resolv_params.h"
#include <stdio.h>

/*
 * Passing NETID_UNSET as the netId causes system/netd/server/DnsProxyListener.cpp to
 * fill in the appropriate default netId for the query.
 */
#define NETID_UNSET 0u

/*
 * MARK_UNSET represents the default (i.e. unset) value for a socket mark.
 */
#define MARK_UNSET 0u

__BEGIN_DECLS

struct __res_params;
struct addrinfo;

#define __used_in_netd __attribute__((visibility ("default")))

/*
 * A struct to capture context relevant to network operations.
 *
 * Application and DNS netids/marks can differ from one another under certain
 * circumstances, notably when a VPN applies to the given uid's traffic but the
 * VPN network does not have its own DNS servers explicitly provisioned.
 *
 * The introduction of per-UID routing means the uid is also an essential part
 * of the evaluation context. Its proper uninitialized value is
 * NET_CONTEXT_INVALID_UID.
 */
struct android_net_context {
    unsigned app_netid;
    unsigned app_mark;
    unsigned dns_netid;
    unsigned dns_mark;
    uid_t uid;
    unsigned flags;
    res_send_qhook qhook;
};

#define NET_CONTEXT_INVALID_UID ((uid_t)-1)

#define NET_CONTEXT_FLAG_USE_LOCAL_NAMESERVERS  0x00000001
#define NET_CONTEXT_FLAG_USE_EDNS               0x00000002

struct hostent *android_gethostbyaddrfornet(const void *, socklen_t, int, unsigned, unsigned) __used_in_netd;
struct hostent *android_gethostbynamefornet(const char *, int, unsigned, unsigned) __used_in_netd;
int android_getaddrinfofornet(const char *, const char *, const struct addrinfo *, unsigned,
    unsigned, struct addrinfo **) __used_in_netd;
/*
 * TODO: consider refactoring android_getaddrinfo_proxy() to serve as an
 * explore_fqdn() dispatch table method, with the below function only making DNS calls.
 */
struct hostent *android_gethostbyaddrfornetcontext(const void *, socklen_t, int, const struct android_net_context *) __used_in_netd;
struct hostent *android_gethostbynamefornetcontext(const char *, int, const struct android_net_context *) __used_in_netd;
int android_getaddrinfofornetcontext(const char *, const char *, const struct addrinfo *,
    const struct android_net_context *, struct addrinfo **) __used_in_netd;

/* set name servers for a network */
extern int _resolv_set_nameservers_for_net(unsigned netid, const char** servers,
        unsigned numservers, const char *domains, const struct __res_params* params) __used_in_netd;

/* flush the cache associated with a certain network */
extern void _resolv_flush_cache_for_net(unsigned netid) __used_in_netd;

/* delete the cache associated with a certain network */
extern void _resolv_delete_cache_for_net(unsigned netid) __used_in_netd;

/* Internal use only. */
struct hostent *android_gethostbyaddrfornetcontext_proxy(const void *, socklen_t, int , const struct android_net_context *) __LIBC_HIDDEN__;
int android_getnameinfofornet(const struct sockaddr *, socklen_t, char *, size_t, char *, size_t, int, unsigned, unsigned) __LIBC_HIDDEN__;

__END_DECLS

#endif /* _RESOLV_NETID_H */
```