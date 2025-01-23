Response:
Let's break down the thought process for answering this request.

1. **Understanding the Core Request:** The user wants to understand the functionality of the `resolv_private.handroid` header file within Android's Bionic libc. They are particularly interested in its DNS resolution capabilities, interaction with Android, libc function implementations, dynamic linker involvement, potential errors, and how Android frameworks access this code. Frida hooking examples are also requested.

2. **Initial File Analysis (Header File):** The first step is to recognize that this is a *header file*. Header files primarily contain:
    * **Declarations:**  Function prototypes, structure definitions, macro definitions, and extern variable declarations.
    * **Inlines (rare in this specific file):**  Small, often performance-critical functions.
    * **No Actual Implementations:**  The *how* of a function is generally in a `.c` file, not a `.h` file.

3. **Categorizing Functionality Based on Declarations:**  Scan the header file and group related declarations. This involves identifying:
    * **Data Structures:**  `struct __res_state`, `union res_sockaddr_union`, `struct res_sym`. These define the data used by the resolver.
    * **Macros:** `MAXHOSTNAMELEN`, `RES_INIT`, `RES_DEBUG`, etc. These are compile-time constants and flags.
    * **Function Declarations:**  `res_init`, `res_query`, `res_send`, `dn_expand`, etc. These are the public interfaces to the resolver library.
    * **Hidden/Internal Declarations:**  Functions prefixed with `__LIBC_HIDDEN__`. These are for internal use within Bionic.
    * **Type Definitions:** `typedef struct __res_state *res_state;`. Creates aliases for data types.

4. **Inferring Functionality from Declarations (and existing knowledge):**  Based on the names and common DNS concepts, deduce the purpose of the declared entities:
    * **`struct __res_state`:**  Likely holds the resolver's state information (server addresses, timeouts, options, etc.).
    * **`res_query`, `res_search`, `res_send`:**  Core DNS resolution functions.
    * **`dn_expand`, `dn_comp`:** Functions for manipulating DNS names.
    * **`RES_INIT`, `RES_DEBUG`:** Configuration options for the resolver.

5. **Addressing Specific Questions:** Now tackle the individual parts of the user's request:

    * **Functionality Listing:** Summarize the categories of functionalities identified in step 3 (DNS resolution, configuration, internal utilities, etc.).

    * **Android Relevance and Examples:** Connect the functionalities to Android's needs. DNS resolution is crucial for network access. Examples:
        * Apps using hostnames.
        * System services needing network resources.
        * Connectivity checks.

    * **Detailed libc Function Implementation:**  **Crucially, recognize that the header file *doesn't* contain implementations.** Explain that the implementations are in `.c` files and provide examples of likely source files (like `res_query.c`, `res_send.c`). Give a high-level overview of what these implementations *might* involve (e.g., `res_query` building a query, sending it, and parsing the response). *Avoid making up details without looking at the actual source.*

    * **Dynamic Linker Functionality:** Scan for elements that suggest dynamic linking. The presence of `__BEGIN_DECLS` and `__END_DECLS` (common in C for managing visibility) is a hint. Also, consider the purpose of a shared library like `libc`. Explain the role of the dynamic linker in resolving symbols. Provide a *simplified* SO layout example, focusing on the essential components (text, data, symbol table, relocation table). Explain the linking process at a high level (symbol resolution, relocation).

    * **Logical Reasoning (Assumptions and Outputs):** Choose a simple function like `res_init`. Assume default settings. Describe the likely output: initialization of the `__res_state` structure with default values. For more complex functions, acknowledge the difficulty without the full source code.

    * **Common Usage Errors:** Think about typical mistakes developers make when using DNS resolution:
        * Not checking return values.
        * Blocking the main thread.
        * Misconfiguring `resolv.conf`.

    * **Android Framework/NDK Path:** Describe the typical layers involved in a network request: application code -> Android Framework (Java) -> Native code (NDK) -> Bionic libc. Mention relevant framework classes (e.g., `java.net.InetAddress`).

    * **Frida Hooking:**  Provide concrete Frida examples for hooking key functions like `res_query` and `res_send`. Explain what information can be logged using these hooks.

6. **Review and Refine:** Read through the entire answer to ensure clarity, accuracy (within the limits of not having the `.c` files), and completeness. Ensure all parts of the user's request have been addressed. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe I should try to guess the exact implementation details of each libc function.
* **Correction:** Realized that's impossible and potentially misleading without the actual `.c` files. Focus on the general purpose and likely steps involved.

* **Initial thought:** Get bogged down in the details of the SO layout.
* **Correction:**  Keep the SO layout example simple and focused on the key concepts relevant to dynamic linking.

* **Initial thought:**  Provide overly complex Frida examples.
* **Correction:**  Start with basic examples that demonstrate the core concept of hooking and logging function calls and arguments.

By following this structured approach, combining file analysis with domain knowledge and addressing each part of the user's request systematically, a comprehensive and informative answer can be generated.
这是一个位于 Android Bionic C 库中 DNS 解析器私有头文件。虽然它本身不包含可执行代码，但它定义了供 DNS 解析器内部使用的各种数据结构、宏和函数声明。理解它的功能需要结合 `resolv.h` 以及相关的 `.c` 源文件。

**主要功能列表：**

1. **定义 DNS 解析器状态结构体 (`struct __res_state`)：**  这是核心结构，存储了 DNS 解析器的各种状态信息，例如：
    * **`nsaddr_list`**:  要查询的 DNS 服务器的 IP 地址列表。
    * **`retrans`, `retry`**:  重新传输的间隔时间和重试次数。
    * **`options`**:  控制解析器行为的各种选项标志（例如，是否使用 TCP、是否开启调试等）。
    * **`dnsrch`**:  域名搜索列表。
    * **`id`**:  当前 DNS 查询消息的 ID。
    * **Hook 函数 (`qhook`, `rhook`)**:  允许用户自定义查询和响应处理逻辑（尽管通常不直接在应用中使用）。
    * **统计信息**:  与 DNS 服务器性能相关的统计数据。

2. **定义和声明各种宏：**  提供了一些常量和标志，用于配置和控制 DNS 解析过程，例如：
    * **`MAXHOSTNAMELEN`**:  主机名的最大长度。
    * **`_PATH_RESCONF`**:  `resolv.conf` 配置文件的默认路径。
    * **`RES_TIMEOUT`, `MAXRESOLVSORT`, `RES_MAXNDOTS` 等**:  各种超时和限制参数。
    * **`RES_INIT`, `RES_DEBUG`, `RES_USEVC` 等**:  解析器选项标志。

3. **声明内部使用的函数 (使用 `__LIBC_HIDDEN__`)：** 这些函数是 Bionic DNS 解析器内部使用的，通常不暴露给应用程序开发者。它们实现了 DNS 解析的各个环节，例如：
    * **缓存管理**: `_resolv_cache_get_resolver_stats`, `_resolv_cache_add_resolver_stats_sample` 等，用于管理 DNS 查询结果的缓存。
    * **状态管理**: `__res_get_state`, `__res_put_state`，用于获取和释放全局或线程局部的解析器状态。
    * **底层操作**: `res_send`, `res_mkquery` 等的内部版本。
    * **名字操作**: `dn_comp`, `dn_expand` 等。
    * **错误处理**: `RES_SET_H_ERRNO` 相关的宏。

4. **定义联合体 (`union res_sockaddr_union`)：**  用于存储 IPv4 和 IPv6 地址信息，方便在不同地址族之间进行操作。

5. **定义符号表结构 (`struct res_sym`)：**  用于将 DNS 记录类型、类等数值表示映射到其字符串表示，方便调试和日志输出。

**与 Android 功能的关系及举例说明：**

这个头文件是 Android 系统网络功能的基础组成部分。所有需要进行域名解析的操作，最终都会涉及到这里定义的结构和函数。

* **应用程序访问互联网**: 当 Android 应用需要连接到某个域名（例如 `www.google.com`）时，系统会使用 DNS 解析器将该域名解析为 IP 地址。`struct __res_state` 中存储的 DNS 服务器地址就来源于系统配置或网络连接信息。
* **系统服务**: Android 的各种系统服务，例如 `netd` (网络守护进程)，也需要进行 DNS 解析以执行网络相关的任务。
* **Connectivity Service (连接性服务)**:  Android 的连接性服务会使用 DNS 解析来判断网络是否可用，以及探测门户网站。
* **NDK 开发**: 使用 NDK 进行网络编程的开发者，可以通过 libc 提供的 DNS 解析函数（例如 `getaddrinfo`，它最终会调用这里声明的内部函数）来实现域名解析。

**libc 函数的功能实现 (基于头文件推断，具体实现位于 `.c` 文件中)：**

由于这是一个头文件，我们只能看到函数的声明，无法看到具体的实现代码。但是，基于函数名和常见的 DNS 解析流程，我们可以推断其功能：

* **`res_init()`**:  （尽管这里声明的是 `__res_init`，实际应用中常使用 `res_init`）初始化 DNS 解析器状态。它会读取 `/etc/resolv.conf` 文件（或 Android 上的 `/etc/ppp/resolv.conf`）来获取 DNS 服务器地址、域名搜索列表等信息，并填充到 `struct __res_state` 结构体中。
* **`res_query()`**:  执行一个标准的 DNS 查询。它会构建 DNS 查询报文，并发送到配置的 DNS 服务器。然后等待服务器响应，并解析响应报文，将结果返回给调用者。
* **`res_send()`**:  底层的发送 DNS 查询报文的函数。它接收构建好的查询报文，并使用 UDP 或 TCP 协议将其发送到指定的 DNS 服务器。
* **`dn_comp()`**:  将一个可读的域名压缩成 DNS 报文格式。DNS 报文中为了节省空间，会使用指针来表示重复出现的域名部分。
* **`dn_expand()`**:  将 DNS 报文中压缩的域名展开成可读的字符串。
* **`res_mkquery()`**:  构建一个 DNS 查询报文。它接收查询类型、域名等参数，并按照 DNS 协议的格式生成查询报文的字节流。

**涉及 dynamic linker 的功能和处理过程：**

这个头文件属于 Bionic libc，它本身就是一个动态链接库 (`.so` 文件)。当一个应用程序或系统服务调用 libc 提供的 DNS 解析函数时，动态链接器负责将这些函数调用链接到 libc.so 中对应的实现代码。

**SO 布局样本 (简化版)：**

```
libc.so:
    .text:  # 存放可执行代码，包括 res_init, res_query 等函数的实现
        res_init:
            ... (res_init 的机器码) ...
        res_query:
            ... (res_query 的机器码) ...
        ...

    .data:  # 存放已初始化的全局变量和静态变量，例如 __res_state 的全局实例 (如果存在)
        __res_state_global:
            ... (全局 __res_state 结构体的数据) ...
        ...

    .bss:   # 存放未初始化的全局变量和静态变量

    .dynsym: # 动态符号表，列出了可以被其他 SO 共享的符号 (函数名、变量名)
        res_init
        res_query
        ...

    .dynstr: # 动态符号字符串表，存储 .dynsym 中符号的名字

    .plt:    # 程序链接表，用于延迟绑定动态链接的函数

    .got:    # 全局偏移表，用于存储动态链接函数的实际地址

    ... 其他段 ...
```

**链接的处理过程：**

1. **编译时：** 当应用程序或系统服务编译时，编译器遇到对 `res_init` 或 `res_query` 等函数的调用，会在生成的目标文件中记录下这些符号的引用，并标记为需要动态链接。

2. **加载时：** 当 Android 系统加载应用程序或系统服务时，动态链接器 (linker) 会负责加载所有依赖的共享库，包括 `libc.so`。

3. **符号解析：** 动态链接器会扫描 `libc.so` 的 `.dynsym` 段，找到应用程序引用的符号（例如 `res_init`）。

4. **重定位：** 动态链接器会修改应用程序的 `.got` (全局偏移表) 或 `.plt` (程序链接表) 中的条目，使其指向 `libc.so` 中对应函数的实际地址。  对于延迟绑定的情况，首次调用函数时才会进行地址解析和重定位。

5. **执行：** 当应用程序执行到调用 `res_init` 或 `res_query` 的代码时，程序会通过 `.got` 或 `.plt` 表跳转到 `libc.so` 中对应的函数实现。

**假设输入与输出 (针对 `res_init` 函数)：**

**假设输入：** 系统启动，网络配置中 DNS 服务器地址为 `8.8.8.8` 和 `8.8.4.4`，域名搜索列表为空。

**输出：**  `res_init` 函数执行后，全局或线程局部的 `struct __res_state` 结构体中的关键字段会被设置为：

* `nscount = 2`
* `nsaddr_list[0].sin_addr` 包含 `8.8.8.8` 的二进制表示
* `nsaddr_list[1].sin_addr` 包含 `8.8.4.4` 的二进制表示
* `dnsrch` 列表为空或包含默认的本地搜索域 (如果配置了)。
* 其他选项根据默认值或系统配置进行设置。

**用户或编程常见的使用错误：**

1. **未调用 `res_init` 就使用 DNS 解析函数**: 虽然 Bionic libc 可能会在第一次使用时自动进行初始化，但显式调用 `res_init` 可以确保在多线程环境下状态的正确性，并且可以提前处理配置文件读取失败的情况。

   ```c
   #include <netdb.h>
   #include <stdio.h>
   #include <resolv.h> // 需要包含 resolv.h 或相关头文件

   int main() {
       struct hostent *host = gethostbyname("www.example.com"); // 可能在 res_init 之前调用

       if (host == NULL) {
           herror("gethostbyname");
           return 1;
       }
       // ...
       return 0;
   }
   ```

   **修正：**

   ```c
   #include <netdb.h>
   #include <stdio.h>
   #include <resolv.h>

   int main() {
       if (res_init() == -1) {
           perror("res_init");
           return 1;
       }

       struct hostent *host = gethostbyname("www.example.com");
       if (host == NULL) {
           herror("gethostbyname");
           return 1;
       }
       // ...
       return 0;
   }
   ```

2. **阻塞主线程进行 DNS 解析**: DNS 解析可能需要一段时间，特别是在网络状况不佳的情况下。在主线程中直接调用 DNS 解析函数会导致 UI 卡顿。应该在后台线程中执行 DNS 解析操作。

3. **错误地假设 DNS 解析总是成功**: 网络是不可靠的，DNS 服务器可能不可用，或者域名不存在。必须检查 DNS 解析函数的返回值，并妥善处理错误情况。

4. **滥用或误解 `resolv.conf` 的配置**:  手动修改 `/etc/resolv.conf` 可能导致 DNS 解析问题，特别是权限不正确或格式错误时。在 Android 上，通常应该通过系统设置或网络管理工具来配置 DNS 服务器。

**Android Framework 或 NDK 如何到达这里：**

1. **Android Framework (Java 代码)**: 当一个 Android 应用的 Java 代码需要进行网络操作，例如使用 `java.net.InetAddress.getByName("www.example.com")` 解析域名时。

2. **Native Method 调用**:  `java.net.InetAddress.getByName()` 是一个 native 方法，它会通过 JNI (Java Native Interface) 调用到 Android 运行时 (ART) 或 Dalvik 虚拟机中的 native 代码。

3. **`libjavacrypto.so` 或 `libnetd_client.so` 等**:  在 native 层，可能会涉及到 `libjavacrypto.so` 或 `libnetd_client.so` 等库，这些库提供了更底层的网络功能接口。

4. **`getaddrinfo()` 或 `gethostbyname()`**: 这些库最终会调用 Bionic libc 提供的标准 C 库函数 `getaddrinfo()` 或 `gethostbyname()`。

5. **Bionic libc (`libc.so`)**: `getaddrinfo()` 和 `gethostbyname()` 函数内部会调用 DNS 解析相关的函数，例如 `res_init()`, `res_query()`, `res_send()` 等，这些函数的声明就在 `resolv_private.handroid` 和 `resolv.h` 中。

**Frida Hook 示例调试步骤：**

假设我们想监控 `res_query` 函数的调用，查看它查询的域名和返回结果。

```python
import frida
import sys

package_name = "你的应用包名" # 例如 "com.example.myapp"

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__res_query"), {
    onEnter: function(args) {
        const domainPtr = Memory.readCString(args[0]);
        const type = ptr(args[1]).readU16();
        const klass = ptr(args[2]).readU16();
        console.log("[*] __res_query called with domain:", domainPtr, "type:", type, "class:", klass);
        this.domain = domainPtr;
    },
    onLeave: function(retval) {
        console.log("[*] __res_query returned:", retval);
        if (retval === 0) {
            // 查询成功，可以尝试解析返回的 buffer
            // 这里只是一个示例，实际解析需要更复杂的逻辑
            // console.log("[*] Response buffer:", hexdump(ptr(arguments[3]).readByteArray(64)));
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 步骤解释：**

1. **导入 Frida 库**: 导入 `frida` 和 `sys` 库。
2. **指定目标应用**: 设置要 Hook 的应用程序的包名。
3. **定义消息处理函数**: `on_message` 函数用于处理 Frida 发送的消息，例如 `console.log` 的输出。
4. **连接到目标进程**: 使用 `frida.get_usb_device().attach(package_name)` 连接到正在运行的目标 Android 应用进程。
5. **编写 Frida Hook 脚本**:
   * **`Interceptor.attach()`**:  用于 Hook 指定的函数。
   * **`Module.findExportByName("libc.so", "__res_query")`**:  在 `libc.so` 库中查找 `__res_query` 函数的地址。
   * **`onEnter`**:  在 `__res_query` 函数被调用之前执行。
     * `args` 数组包含了函数的参数。
     * `Memory.readCString(args[0])` 读取第一个参数（域名）的字符串。
     * 读取查询类型和类。
     * 打印 `__res_query` 被调用的信息。
     * 将域名保存在 `this.domain` 中，以便在 `onLeave` 中使用。
   * **`onLeave`**: 在 `__res_query` 函数执行完毕之后执行。
     * `retval` 是函数的返回值。
     * 打印返回值。
     * 如果返回值是 0（表示成功），可以尝试解析返回的 DNS 响应 buffer（这里只是一个示例，实际解析需要更复杂的代码）。
6. **创建和加载 Frida 脚本**: 使用 `session.create_script()` 创建脚本，并使用 `script.load()` 加载到目标进程。
7. **保持脚本运行**: `sys.stdin.read()` 保持脚本运行，直到手动停止。

**运行这个 Frida 脚本，当目标应用进行 DNS 查询时，你将在控制台中看到 `__res_query` 函数被调用的信息，包括查询的域名、类型和类，以及函数的返回值。**

请注意，这只是一个基本的 Hook 示例。实际调试中可能需要更复杂的 Hook 逻辑来解析 DNS 响应报文，或者 Hook 其他相关的 DNS 解析函数。此外，某些应用可能会使用反 Hook 技术，需要采取相应的绕过措施。

### 提示词
```
这是目录为bionic/libc/dns/include/resolv_private.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: resolv.h,v 1.31 2005/12/26 19:01:47 perry Exp $	*/

/*
 * Copyright (c) 1983, 1987, 1989
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

/*
 *	@(#)resolv.h	8.1 (Berkeley) 6/2/93
 *	Id: resolv.h,v 1.7.2.11.4.2 2004/06/25 00:41:05 marka Exp
 */

#pragma once

#include <sys/cdefs.h>

#include <resolv.h>
#include "resolv_static.h"
#include "resolv_params.h"
#include "resolv_stats.h"
#include <net/if.h>
#include <time.h>

__BEGIN_DECLS

// Linux defines MAXHOSTNAMELEN as 64, while the domain name limit in
// RFC 1034 and RFC 1035 is 255 octets.
#ifdef MAXHOSTNAMELEN
#undef MAXHOSTNAMELEN
#endif
#define MAXHOSTNAMELEN 256

/*
 * Revision information.  This is the release date in YYYYMMDD format.
 * It can change every day so the right thing to do with it is use it
 * in preprocessor commands such as "#if (__RES > 19931104)".  Do not
 * compare for equality; rather, use it to determine whether your resolver
 * is new enough to contain a certain feature.
 */

#define	__RES	20030124

/*
 * This used to be defined in res_query.c, now it's in herror.c.
 * [XXX no it's not.  It's in irs/irs_data.c]
 * It was
 * never extern'd by any *.h file before it was placed here.  For thread
 * aware programs, the last h_errno value set is stored in res->h_errno.
 *
 * XXX:	There doesn't seem to be a good reason for exposing RES_SET_H_ERRNO
 *	(and __h_errno_set) to the public via <resolv.h>.
 * XXX:	__h_errno_set is really part of IRS, not part of the resolver.
 *	If somebody wants to build and use a resolver that doesn't use IRS,
 *	what do they do?  Perhaps something like
 *		#ifdef WANT_IRS
 *		# define RES_SET_H_ERRNO(r,x) __h_errno_set(r,x)
 *		#else
 *		# define RES_SET_H_ERRNO(r,x) (h_errno = (r)->res_h_errno = (x))
 *		#endif
 */

#define RES_SET_H_ERRNO(r,x) (h_errno = (r)->res_h_errno = (x))
struct __res_state; /* forward */

/*
 * Resolver configuration file.
 * Normally not present, but may contain the address of the
 * initial name server(s) to query and the domain search list.
 */

#ifndef _PATH_RESCONF
#ifdef ANDROID_CHANGES
#define _PATH_RESCONF        "/etc/ppp/resolv.conf"
#else
#define _PATH_RESCONF        "/etc/resolv.conf"
#endif
#endif

struct res_sym {
	int		number;	   /* Identifying number, like T_MX */
	const char *	name;	   /* Its symbolic name, like "MX" */
	const char *	humanname; /* Its fun name, like "mail exchanger" */
};

/*
 * Global defines and variables for resolver stub.
 */
#define	MAXDFLSRCH		3	/* # default domain levels to try */
#define	LOCALDOMAINPARTS	2	/* min levels in name that is "local" */

#define	RES_TIMEOUT		5	/* min. seconds between retries */
#define	MAXRESOLVSORT		10	/* number of net to sort on */
#define	RES_MAXNDOTS		15	/* should reflect bit field size */
#define	RES_MAXRETRANS		30	/* only for resolv.conf/RES_OPTIONS */
#define	RES_MAXRETRY		5	/* only for resolv.conf/RES_OPTIONS */
#define	RES_DFLRETRY		2	/* Default #/tries. */
#define	RES_MAXTIME		65535	/* Infinity, in milliseconds. */

struct __res_state_ext;

struct __res_state {
	unsigned	netid;			/* NetId: cache key and socket mark */
	int	retrans;	 	/* retransmission time interval */
	int	retry;			/* number of times to retransmit */
#ifdef sun
	u_int	options;		/* option flags - see below. */
#else
	u_long	options;		/* option flags - see below. */
#endif
	int	nscount;		/* number of name servers */
	struct sockaddr_in
		nsaddr_list[MAXNS];	/* address of name server */
#define	nsaddr	nsaddr_list[0]		/* for backward compatibility */
	u_short	id;			/* current message id */
	char	*dnsrch[MAXDNSRCH+1];	/* components of domain to search */
	char	defdname[256];		/* default domain (deprecated) */
#ifdef sun
	u_int	pfcode;			/* RES_PRF_ flags - see below. */
#else
	u_long	pfcode;			/* RES_PRF_ flags - see below. */
#endif
	unsigned ndots:4;		/* threshold for initial abs. query */
	unsigned nsort:4;		/* number of elements in sort_list[] */
	char	unused[3];
	struct {
		struct in_addr	addr;
		uint32_t	mask;
	} sort_list[MAXRESOLVSORT];
#ifdef __OLD_RES_STATE
	char lookups[4];
#else
	res_send_qhook qhook;		/* query hook */
	res_send_rhook rhook;		/* response hook */
	int	res_h_errno;		/* last one set for this context */
	unsigned _mark;			/* If non-0 SET_MARK to _mark on all request sockets */
	int	_vcsock;		/* PRIVATE: for res_send VC i/o */
	u_int	_flags;			/* PRIVATE: see below */
	u_int	_pad;			/* make _u 64 bit aligned */
	union {
		/* On an 32-bit arch this means 512b total. */
		char	pad[72 - 4*sizeof (int) - 2*sizeof (void *)];
		struct {
			uint16_t		nscount;
			uint16_t		nstimes[MAXNS];	/* ms. */
			int			nssocks[MAXNS];
			struct __res_state_ext *ext;	/* extention for IPv6 */
		} _ext;
	} _u;
#endif
        struct res_static   rstatic[1];
};

typedef struct __res_state *res_state;

/* Retrieve a local copy of the stats for the given netid. The buffer must have space for
 * MAXNS __resolver_stats. Returns the revision id of the resolvers used.
 */
__LIBC_HIDDEN__
extern int
_resolv_cache_get_resolver_stats( unsigned netid, struct __res_params* params,
        struct __res_stats stats[MAXNS]);

/* Add a sample to the shared struct for the given netid and server, provided that the
 * revision_id of the stored servers has not changed.
 */
__LIBC_HIDDEN__
extern void
_resolv_cache_add_resolver_stats_sample( unsigned netid, int revision_id, int ns,
        const struct __res_sample* sample, int max_samples);

/* End of stats related definitions */

union res_sockaddr_union {
	struct sockaddr_in	sin;
#ifdef IN6ADDR_ANY_INIT
	struct sockaddr_in6	sin6;
#endif
#ifdef ISC_ALIGN64
	int64_t			__align64;	/* 64bit alignment */
#else
	int32_t			__align32;	/* 32bit alignment */
#endif
	char			__space[128];   /* max size */
};

/*
 * Resolver flags (used to be discrete per-module statics ints).
 */
#define	RES_F_VC	0x00000001	/* socket is TCP */
#define	RES_F_CONN	0x00000002	/* socket is connected */
#define	RES_F_EDNS0ERR	0x00000004	/* EDNS0 caused errors */
#define	RES_F__UNUSED	0x00000008	/* (unused) */
#define	RES_F_LASTMASK	0x000000F0	/* ordinal server of last res_nsend */
#define	RES_F_LASTSHIFT	4		/* bit position of LASTMASK "flag" */
#define	RES_GETLAST(res) (((res)._flags & RES_F_LASTMASK) >> RES_F_LASTSHIFT)

/* res_findzonecut2() options */
#define	RES_EXHAUSTIVE	0x00000001	/* always do all queries */
#define	RES_IPV4ONLY	0x00000002	/* IPv4 only */
#define	RES_IPV6ONLY	0x00000004	/* IPv6 only */

/*
 * Resolver options (keep these in synch with res_debug.c, please)
 */
#define RES_INIT	0x00000001	/* address initialized */
#define RES_DEBUG	0x00000002	/* print debug messages */
#define RES_AAONLY	0x00000004	/* authoritative answers only (!IMPL)*/
#define RES_USEVC	0x00000008	/* use virtual circuit */
#define RES_PRIMARY	0x00000010	/* query primary server only (!IMPL) */
#define RES_IGNTC	0x00000020	/* ignore trucation errors */
#define RES_RECURSE	0x00000040	/* recursion desired */
#define RES_DEFNAMES	0x00000080	/* use default domain name */
#define RES_STAYOPEN	0x00000100	/* Keep TCP socket open */
#define RES_DNSRCH	0x00000200	/* search up local domain tree */
#define	RES_INSECURE1	0x00000400	/* type 1 security disabled */
#define	RES_INSECURE2	0x00000800	/* type 2 security disabled */
#define	RES_NOALIASES	0x00001000	/* shuts off HOSTALIASES feature */
#define	RES_USE_INET6	0x00002000	/* use/map IPv6 in gethostbyname() */
#define RES_ROTATE	0x00004000	/* rotate ns list after each query */
#define	RES_NOCHECKNAME	0x00008000	/* do not check names for sanity. */
#define	RES_KEEPTSIG	0x00010000	/* do not strip TSIG records */
#define	RES_BLAST	0x00020000	/* blast all recursive servers */
#define RES_NOTLDQUERY	0x00100000	/* don't unqualified name as a tld */
#define RES_USE_DNSSEC	0x00200000	/* use DNSSEC using OK bit in OPT */
/* #define RES_DEBUG2	0x00400000 */	/* nslookup internal */
/* KAME extensions: use higher bit to avoid conflict with ISC use */
#define RES_USE_DNAME	0x10000000	/* use DNAME */
#define RES_USE_EDNS0	0x40000000	/* use EDNS0 if configured */
#define RES_NO_NIBBLE2	0x80000000	/* disable alternate nibble lookup */

#define RES_DEFAULT	(RES_RECURSE | RES_DEFNAMES | \
			 RES_DNSRCH | RES_NO_NIBBLE2)

/*
 * Resolver "pfcode" values.  Used by dig.
 */
#define RES_PRF_STATS	0x00000001
#define RES_PRF_UPDATE	0x00000002
#define RES_PRF_CLASS   0x00000004
#define RES_PRF_CMD	0x00000008
#define RES_PRF_QUES	0x00000010
#define RES_PRF_ANS	0x00000020
#define RES_PRF_AUTH	0x00000040
#define RES_PRF_ADD	0x00000080
#define RES_PRF_HEAD1	0x00000100
#define RES_PRF_HEAD2	0x00000200
#define RES_PRF_TTLID	0x00000400
#define RES_PRF_HEADX	0x00000800
#define RES_PRF_QUERY	0x00001000
#define RES_PRF_REPLY	0x00002000
#define RES_PRF_INIT	0x00004000
#define RES_PRF_TRUNC	0x00008000
/*			0x00010000	*/

/* Things involving an internal (static) resolver context. */
__LIBC_HIDDEN__ extern struct __res_state *__res_get_state(void);
__LIBC_HIDDEN__ extern void __res_put_state(struct __res_state *);

#ifndef ANDROID_CHANGES
/*
 * Source and Binary compatibility; _res will not work properly
 * with multi-threaded programs.
 */
extern struct __res_state *__res_state(void);
#define _res (*__res_state())
#endif

#ifndef __BIND_NOSTATIC
#define fp_nquery		__fp_nquery
#define fp_query		__fp_query
#define hostalias		__hostalias
#define p_query			__p_query
#define res_close		__res_close
#define res_opt			__res_opt
#define res_isourserver		__res_isourserver
#define	res_querydomain		__res_querydomain
#define res_send		__res_send

#ifdef BIND_RES_POSIX3
#define	dn_expand	__dn_expand
#define	res_init	__res_init
#define	res_query	__res_query
#define	res_search	__res_search
#define	res_mkquery	__res_mkquery
#endif

void		fp_nquery(const u_char *, int, FILE *);
void		fp_query(const u_char *, FILE *);
const char *	hostalias(const char *);
void		p_query(const u_char *);
void		res_close(void);
int		res_init(void);
__LIBC_HIDDEN__ int		res_opt(int, u_char *, int, int);
int		res_isourserver(const struct sockaddr_in *);
int		res_mkquery(int, const char *, int, int, const u_char *, int, const u_char *, u_char *, int);
int		res_query(const char *, int, int, u_char *, int);
int		res_querydomain(const char *, const char *, int, int, u_char *, int);
int		res_search(const char *, int, int, u_char *, int);
int		res_send(const u_char *, int, u_char *, int);
#endif

#if !defined(SHARED_LIBBIND) || defined(LIB)
/*
 * If libbind is a shared object (well, DLL anyway)
 * these externs break the linker when resolv.h is
 * included by a lib client (like named)
 * Make them go away if a client is including this
 *
 */
__LIBC_HIDDEN__ extern const struct res_sym __p_key_syms[];
__LIBC_HIDDEN__ extern const struct res_sym __p_cert_syms[];
extern const struct res_sym __p_class_syms[];
extern const struct res_sym __p_type_syms[];
__LIBC_HIDDEN__ extern const struct res_sym __p_rcode_syms[];
#endif /* SHARED_LIBBIND */

#ifndef ANDROID_CHANGES
#define dn_comp			__dn_comp
#endif
#define dn_count_labels		__dn_count_labels
#define dn_skipname		__dn_skipname
#define fp_resstat		__fp_resstat
#define loc_aton		__loc_aton
#define loc_ntoa		__loc_ntoa
#define p_cdname		__p_cdname
#define p_cdnname		__p_cdnname
#define p_class			__p_class
#define p_fqname		__p_fqname
#define p_fqnname		__p_fqnname
#define p_option		__p_option
#define p_secstodate		__p_secstodate
#define p_section		__p_section
#define p_time			__p_time
#define p_type			__p_type
#define p_rcode			__p_rcode
#define p_sockun		__p_sockun
#define putlong			__putlong
#define putshort		__putshort
#define res_dnok		__res_dnok
#define res_findzonecut		__res_findzonecut
#define res_findzonecut2	__res_findzonecut2
#define res_hnok		__res_hnok
#define res_hostalias		__res_hostalias
#define res_mailok		__res_mailok
#define res_nameinquery		__res_nameinquery
#define res_nclose		__res_nclose
#define res_ninit		__res_ninit
#define res_nmkquery		__res_nmkquery
#define res_pquery		__res_pquery
#define res_nquery		__res_nquery
#define res_nquerydomain	__res_nquerydomain
#define res_nsearch		__res_nsearch
#define res_nsend		__res_nsend
#define res_nsendsigned		__res_nsendsigned
#define res_nisourserver	__res_nisourserver
#define res_ownok		__res_ownok
#define res_queriesmatch	__res_queriesmatch
#define sym_ntop		__sym_ntop
#define sym_ntos		__sym_ntos
#define sym_ston		__sym_ston
#define res_nopt		__res_nopt
#define res_ndestroy		__res_ndestroy
#define	res_nametoclass		__res_nametoclass
#define	res_nametotype		__res_nametotype
#define	res_setservers		__res_setservers
#define	res_getservers		__res_getservers
#define	res_buildprotolist	__res_buildprotolist
#define	res_destroyprotolist	__res_destroyprotolist
#define	res_destroyservicelist	__res_destroyservicelist
#define	res_get_nibblesuffix	__res_get_nibblesuffix
#define	res_get_nibblesuffix2	__res_get_nibblesuffix2
#define	res_ourserver_p		__res_ourserver_p
#define	res_protocolname	__res_protocolname
#define	res_protocolnumber	__res_protocolnumber
#define	res_send_setqhook	__res_send_setqhook
#define	res_send_setrhook	__res_send_setrhook
#define	res_servicename		__res_servicename
#define	res_servicenumber	__res_servicenumber
int		res_hnok(const char *);
int		res_ownok(const char *);
int		res_mailok(const char *);
int		res_dnok(const char *);
int		sym_ston(const struct res_sym *, const char *, int *);
const char *	sym_ntos(const struct res_sym *, int, int *);
const char *	sym_ntop(const struct res_sym *, int, int *);
#ifndef ANDROID_CHANGES
int		b64_ntop(u_char const *, size_t, char *, size_t);
int		b64_pton(char const *, u_char *, size_t);
#endif
int		loc_aton(const char *, u_char *);
const char *	loc_ntoa(const u_char *, char *, size_t);
int		dn_skipname(const u_char *, const u_char *);
void		putlong(uint32_t, u_char *);
void		putshort(uint16_t, u_char *);
#ifndef __ultrix__
uint16_t	_getshort(const u_char *);
uint32_t	_getlong(const u_char *);
#endif
const char *	p_class(int);
const char *	p_time(uint32_t);
const char *	p_type(int);
const char *	p_rcode(int);
__LIBC_HIDDEN__ const char *	p_sockun(union res_sockaddr_union, char *, size_t);
const u_char *	p_cdnname(const u_char *, const u_char *, int, FILE *);
const u_char *	p_cdname(const u_char *, const u_char *, FILE *);
const u_char *	p_fqnname(const u_char *, const u_char *,
			       int, char *, int);
const u_char *	p_fqname(const u_char *, const u_char *, FILE *);
const char *	p_option(u_long);
char *		p_secstodate(u_long);
int		dn_count_labels(const char *);
int		res_nameinquery(const char *, int, int, const u_char *,
				     const u_char *);
int		res_queriesmatch(const u_char *, const u_char *,
				      const u_char *, const u_char *);
__LIBC_HIDDEN__ const char *	p_section(int, int);
/* Things involving a resolver context. */
int		res_ninit(res_state);
int		res_nisourserver(const res_state, const struct sockaddr_in *);
void		fp_resstat(const res_state, FILE *);
__LIBC_HIDDEN__ void		res_pquery(const res_state, const u_char *, int, FILE *);
const char *	res_hostalias(const res_state, const char *, char *, size_t);
int		res_nquery(res_state, const char *, int, int, u_char *, int);
int		res_nsearch(res_state, const char *, int, int, u_char *, int);
int		res_nquerydomain(res_state, const char *, const char *,
				      int, int, u_char *, int);
int		res_nmkquery(res_state, int, const char *, int, int,
				  const u_char *, int, const u_char *,
				  u_char *, int);
int		res_nsend(res_state, const u_char *, int, u_char *, int);
int		res_nsendsigned(res_state, const u_char *, int,
				     ns_tsig_key *, u_char *, int);
int		res_findzonecut(res_state, const char *, ns_class, int,
				     char *, size_t, struct in_addr *, int);
int		res_findzonecut2(res_state, const char *, ns_class, int,
				      char *, size_t,
				      union res_sockaddr_union *, int);
void		res_nclose(res_state);
__LIBC_HIDDEN__ int		res_nopt(res_state, int, u_char *, int, int);
void		res_send_setqhook(res_send_qhook);
void		res_send_setrhook(res_send_rhook);
__LIBC_HIDDEN__ int		__res_vinit(res_state, int);
void		res_destroyservicelist(void);
const char *	res_servicename(uint16_t, const char *);
const char *	res_protocolname(int);
void		res_destroyprotolist(void);
void		res_buildprotolist(void);
__LIBC_HIDDEN__ const char *	res_get_nibblesuffix(res_state);
__LIBC_HIDDEN__ const char *	res_get_nibblesuffix2(res_state);
__LIBC_HIDDEN__ void		res_ndestroy(res_state);
__LIBC_HIDDEN__ uint16_t	res_nametoclass(const char *, int *);
__LIBC_HIDDEN__ uint16_t	res_nametotype(const char *, int *);
__LIBC_HIDDEN__ void		res_setservers(res_state,
				    const union res_sockaddr_union *, int);
__LIBC_HIDDEN__ int		res_getservers(res_state,
				    union res_sockaddr_union *, int);

struct android_net_context; /* forward */
__LIBC_HIDDEN__ void res_setnetcontext(res_state, const struct android_net_context *);

// We use the OpenBSD __res_randomid...
u_int __res_randomid(void);
// ...but NetBSD calls it res_randomid.
#define res_randomid __res_randomid

int __connect(int, const struct sockaddr*, socklen_t);

// Symbols that are supposed to be in resolv.h, but that we aren't exporting.
int ns_parserr2(ns_msg*, ns_sect, int, ns_rr2*);
int ns_name_pton2(const char*, u_char*, size_t, size_t*);
int ns_name_unpack2(const u_char*, const u_char*, const u_char*, u_char*, size_t, size_t*);
int ns_name_eq(ns_nname_ct, size_t, ns_nname_ct, size_t);
int ns_name_owned(ns_namemap_ct, int, ns_namemap_ct, int);
int ns_name_map(ns_nname_ct, size_t, ns_namemap_t, int);
int ns_name_labels(ns_nname_ct, size_t);

__END_DECLS
```