Response:
Let's break down the thought process for analyzing the `nsdispatch.c` code and generating the detailed response.

**1. Understanding the Core Functionality:**

* **Initial Reading:** The first step is to read through the code to get a general idea of what it does. The function names (`nsdispatch`, `_nsmethod`), the data structures (`ns_dtab`, `ns_src`), and the comments (especially the copyright and purpose statement) provide initial clues.
* **Identifying Key Data Structures:** Pay close attention to the `ns_dtab` and `ns_src` structures. The `ns_dtab` seems to map "sources" to callback functions, and `ns_src` provides a list of sources to try.
* **Tracing the Execution Flow:** Follow the logic within the `nsdispatch` function. It iterates through a list of sources (`defaults`), tries to find a matching entry in `disp_tab` using `_nsmethod`, and then calls the associated callback function.
* **Recognizing the Purpose:**  The code is clearly involved in dispatching requests to different "sources" based on a configuration. This strongly suggests a name service switching (NSS) mechanism.

**2. Deeper Analysis and Answering Specific Questions:**

* **Functionality Listing:** Based on the initial understanding, list the core functionalities: Dispatching requests, using a configuration table, iterating through sources, and calling callbacks.
* **Relationship to Android:**  Connect the functionality to Android's need to resolve hostnames, usernames, etc. Mention the role of libc in providing these fundamental services. The `bionic/libc/dns` path strongly indicates its relevance to DNS resolution.
* **Detailed Explanation of `libc` Functions:**  Focus on the standard C library functions used in the code:
    * `strcasecmp`: Explain its case-insensitive string comparison.
    * `assert`: Explain its purpose in debugging and its behavior.
    * `va_list`, `va_start`, `va_arg`, `va_end`: Describe how they handle variable argument lists. This is crucial for understanding how arguments are passed to the callback functions.
* **Dynamic Linker Aspects:** This requires a deeper understanding of how Android loads shared libraries.
    * **Identifying Potential Links:** Recognize that `nsdispatch` itself is part of `libc`, which is loaded by the dynamic linker. However, the code doesn't directly *use* dynamic linking features like `dlopen` or `dlsym`.
    * **Focusing on the `libc.so` Layout:**  Describe the general structure of a shared object in Android (including `.text`, `.data`, `.bss`, `.dynsym`, `.plt`, `.got`). Explain how symbols are resolved.
    * **Linkage Process (Indirect):** Explain that while `nsdispatch` doesn't *perform* dynamic linking, it relies on `libc` being correctly linked. The callback functions pointed to in `disp_tab` could reside in other shared libraries. Illustrate with a hypothetical scenario.
* **Logical Reasoning (Hypothetical Input/Output):** Create a simple scenario with `disp_tab` and `defaults`. Trace the execution flow for a specific input (`"files"`) and predict the output based on the code's logic.
* **Common Usage Errors:** Think about how developers might misuse or misunderstand this functionality. Examples include incorrect configuration, missing sources, and problems with callback functions.
* **Android Framework/NDK Path and Frida Hook:** This requires knowing the higher-level Android architecture.
    * **Tracing the Path:** Start with a high-level API call (e.g., `InetAddress.getByName()`) and follow it down through the Android framework (Java), native code, and finally to `libc` functions like `getaddrinfo`. Explain how NSS plays a role in this.
    * **Frida Hooking:**  Provide a practical Frida script to intercept the `nsdispatch` function, log its arguments, and potentially modify its behavior. Highlight the importance of finding the correct memory address.

**3. Structuring the Response:**

* **Organize by Question:**  Address each part of the original prompt systematically.
* **Use Clear Headings:** Make it easy to read and navigate the information.
* **Provide Code Examples:** Illustrate concepts with snippets of code where appropriate (e.g., Frida script, hypothetical `so` layout).
* **Explain Technical Terms:**  Define any potentially unfamiliar terms (e.g., NSS, dynamic linker, GOT).
* **Be Concise and Accurate:** Provide accurate information without unnecessary jargon.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** Maybe focus too much on the dynamic linking of the callback functions themselves.
* **Correction:** Realize that `nsdispatch`'s primary role is dispatching, not direct dynamic linking. Shift the focus to how `libc` is linked and how the callbacks *could* reside in other `so` files.
* **Initial Thought:**  Provide a very complex Frida script.
* **Correction:** Simplify the Frida script to demonstrate the basic concept of hooking the function and logging arguments. Emphasize clarity.
* **Review and Refine:**  Read through the entire response to ensure accuracy, completeness, and clarity. Check for any logical inconsistencies or areas that could be explained better.

By following this thought process, breaking down the problem into smaller parts, and iteratively refining the analysis, we can arrive at a comprehensive and accurate explanation of the `nsdispatch.c` code.
好的，让我们详细分析一下 `bionic/libc/dns/net/nsdispatch.c` 这个文件。

**功能列举：**

`nsdispatch.c` 文件实现了动态地将命名服务请求分发到不同的来源（sources），例如本地文件、DNS 服务器等。它提供了一种灵活的机制，允许系统管理员或应用程序配置在哪些来源中查找特定的信息。其核心功能可以概括为：

1. **请求分发 (Request Dispatching):**  根据配置（`disp_tab` 和 `defaults`），将命名服务请求路由到合适的处理方法。
2. **配置驱动 (Configuration Driven):**  行为由外部配置数据驱动，而不是硬编码在代码中。这使得系统更容易配置和扩展。
3. **可扩展性 (Extensibility):**  通过添加新的数据源和相应的处理回调函数，可以轻松地扩展支持的命名服务来源。
4. **错误处理 (Error Handling):**  处理来自不同数据源的错误，并根据配置决定是否继续尝试其他来源。
5. **NSS (Name Service Switch) 机制的基础:** 这是 Android 和其他类 Unix 系统中实现 NSS 的关键组件之一。

**与 Android 功能的关系及举例：**

`nsdispatch.c` 在 Android 系统中扮演着至关重要的角色，它是 Android NSS 机制的核心。NSS 允许 Android 系统以统一的方式访问各种命名和配置数据库。以下是一些例子：

* **域名解析 (Domain Name Resolution):** 当 Android 应用需要将域名（例如 `www.google.com`) 解析为 IP 地址时，会调用 `getaddrinfo` 等函数。`nsdispatch` 会被用于决定先从哪个数据源查找，例如本地的 `hosts` 文件，还是 DNS 服务器。
* **用户和组信息查找 (User and Group Information Lookup):**  当系统需要查找用户名对应的用户 ID，或者用户所属的组时，也会使用 NSS。`nsdispatch` 可以配置为先查找本地文件 (`/etc/passwd`, `/etc/group`)，然后再尝试其他来源（例如 LDAP 服务器，尽管 Android 默认不常用 LDAP）。
* **主机名查找 (Hostname Lookup):**  查找与 IP 地址对应的主机名，或者获取本地主机名。

**举例说明域名解析流程：**

1. Android 应用调用 `getaddrinfo("www.example.com", NULL, ...)`。
2. `getaddrinfo` 内部会调用 NSS 相关的函数。
3. NSS 配置（通常在 `/system/etc/nsswitch.conf` 中定义）指定了如何查找主机名。 例如，它可能包含类似 `hosts: files dns` 的配置。
4. `nsdispatch` 函数会被调用，其 `database` 参数可能是 "hosts"，`method` 参数可能是 "lookup"。
5. `nsdispatch` 根据 `disp_tab` 查找与 "files" 和 "dns" 对应的回调函数。
6. 首先，会尝试调用处理 "files" 的回调函数，它会读取 `/etc/hosts` 文件查找 "www.example.com"。
7. 如果在 `/etc/hosts` 中没有找到，并且配置允许继续查找，`nsdispatch` 会调用处理 "dns" 的回调函数。
8. 处理 "dns" 的回调函数会发起 DNS 查询请求，最终从 DNS 服务器获取 "www.example.com" 的 IP 地址。

**详细解释每个 libc 函数的功能是如何实现的：**

* **`strcasecmp(const char *s1, const char *s2)`:**
    * **功能:**  不区分大小写地比较两个字符串 `s1` 和 `s2`。
    * **实现:**  通常会逐个字符比较两个字符串，直到遇到不相同的字符或者字符串的结尾。在比较字符时，会将其转换为相同的大小写形式（通常是小写或大写）再进行比较。
    * **返回值:**
        * 如果 `s1` 小于 `s2`（忽略大小写），返回一个负整数。
        * 如果 `s1` 等于 `s2`（忽略大小写），返回 0。
        * 如果 `s1` 大于 `s2`（忽略大小写），返回一个正整数。

* **`assert(expression)`:**
    * **功能:**  一个调试宏，用于在程序运行时检查 `expression` 的真假。
    * **实现:**  如果 `expression` 的值为假（0），`assert` 会打印一条包含错误信息（包括文件名、行号和表达式）的消息到标准错误输出，并调用 `abort()` 函数终止程序。在发布版本中，可以通过定义 `NDEBUG` 宏来禁用 `assert`，从而避免额外的运行时开销。

* **`va_list ap;`， `va_start(ap, defaults);`， `va_arg(ap, type);`， `va_end(ap);`:**
    * **功能:**  用于处理可变参数列表（variadic arguments）。这些宏允许函数接受数量和类型可变的参数。
    * **实现:**
        * `va_list ap;`: 声明一个 `va_list` 类型的变量 `ap`，用于存储可变参数的信息。
        * `va_start(ap, defaults);`: 初始化 `ap`，使其指向 `defaults` 参数之后的第一个可变参数。`defaults` 是最后一个命名的固定参数。
        * `va_arg(ap, type);`:  从 `ap` 指向的位置获取一个参数，并将其解释为 `type` 类型。每次调用 `va_arg`，`ap` 都会移动到下一个参数的位置。
        * `va_end(ap);`: 清理 `va_list` 使用的资源，通常将 `ap` 设置为无效状态。这是为了防止在 `va_start` 之后没有 `va_end` 的情况下出现问题。
    * **在 `nsdispatch` 中的使用:**  可变参数列表用于将额外的参数传递给实际处理请求的回调函数 (`*cb`)。这些参数的具体含义取决于正在处理的命名服务类型和方法。

**涉及 dynamic linker 的功能：**

`nsdispatch.c` 本身的代码并没有直接使用动态链接器 (`linker`) 的功能，例如 `dlopen` 或 `dlsym`。 然而，它作为 `libc.so` 的一部分，其运行依赖于动态链接器。

**`libc.so` 布局样本：**

一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
    .text         # 包含可执行代码，例如 nsdispatch 的代码
    .rodata       # 只读数据，例如字符串常量
    .data         # 已初始化的全局变量和静态变量
    .bss          # 未初始化的全局变量和静态变量
    .dynsym       # 动态符号表，包含导出的和导入的符号
    .dynstr       # 动态字符串表，存储符号名称
    .plt          # 程序链接表，用于延迟绑定外部函数
    .got          # 全局偏移表，存储外部函数的地址
```

**链接的处理过程：**

1. **编译时链接:** 当编译链接包含 `nsdispatch.c` 的 `libc` 库时，编译器和链接器会生成包含符号信息的 `libc.so` 文件。`nsdispatch` 函数的符号会被添加到 `.dynsym` 表中，以便其他共享库或可执行文件可以找到它。
2. **运行时链接 (动态链接):** 当 Android 进程启动时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，包括 `libc.so`。
3. **符号解析:**
    * 如果 `nsdispatch` 函数内部调用了其他 `libc` 内部的函数（例如 `strcasecmp`），这些调用在编译时会被标记为需要链接。动态链接器会在 `libc.so` 内部找到这些函数的地址，并更新 `nsdispatch` 函数代码中的相应调用。
    * 如果其他共享库（例如实现特定 NSS 模块的 `.so` 文件）需要调用 `nsdispatch`，动态链接器会在加载这些库时，通过 `libc.so` 的 `.dynsym` 表找到 `nsdispatch` 的地址，并建立链接。
4. **延迟绑定 (Lazy Binding):**  为了提高启动速度，动态链接器通常使用延迟绑定。这意味着外部函数的地址直到第一次被调用时才会被解析和绑定。程序链接表 (`.plt`) 和全局偏移表 (`.got`) 用于实现延迟绑定。当第一次调用外部函数时，会跳转到 `.plt` 中的一段代码，该代码会调用动态链接器来解析符号地址，并将地址更新到 `.got` 表中。后续的调用将直接通过 `.got` 表跳转到目标函数。

**逻辑推理，假设输入与输出：**

假设有以下简单的 `disp_tab` 和 `defaults`：

```c
static const struct ns_dispatchtab my_dispatchtab[] = {
    { "myfiles",  myfiles_lookup, NULL },
    { "mydns",    mydns_lookup,   NULL },
    { NULL, NULL, NULL }
};

static const struct ns_src my_defaults[] = {
    { "myfiles", NS_AUTHORITATIVE|NS_SUCCESS },
    { "mydns",   NS_SUCCESS },
    { NULL, 0 }
};
```

并且 `nsdispatch` 被这样调用：

```c
char buffer[256];
int result = nsdispatch(buffer, my_dispatchtab, "myhosts", "gethostbyname", my_defaults, "example.com");
```

**假设输入：**

* `disp_tab`: 指向 `my_dispatchtab`，定义了 "myfiles" 和 "mydns" 两个数据源及其回调函数。
* `database`: "myhosts"
* `method`: "gethostbyname"
* `defaults`: 指向 `my_defaults`，指定了查找顺序为 "myfiles" 然后是 "mydns"。
* 可变参数: "example.com" (假设 `gethostbyname` 回调函数需要主机名作为参数)

**逻辑推理：**

1. `nsdispatch` 开始执行。
2. 循环遍历 `my_defaults` 中的数据源。
3. 第一次迭代，`source` 是 "myfiles"。
4. `_nsmethod` 函数会在 `my_dispatchtab` 中查找 "myfiles"，找到对应的回调函数 `myfiles_lookup`。
5. 调用 `myfiles_lookup(buffer, NULL, ap)`，其中 `ap` 指向 "example.com"。
6. **假设 `myfiles_lookup` 的实现:**
    * 如果 `myfiles_lookup` 在其配置的文件中找到了 "example.com" 的信息，它可能会将结果写入 `buffer`，并返回 `NS_SUCCESS`。
    * 如果没有找到，它可能会返回 `NS_NOTFOUND`。
7. 如果 `myfiles_lookup` 返回 `NS_SUCCESS`，由于 `my_defaults` 中 "myfiles" 的 flags 包含 `NS_SUCCESS`，`nsdispatch` 将停止并返回 `NS_SUCCESS`。
8. 如果 `myfiles_lookup` 返回 `NS_NOTFOUND`，`nsdispatch` 将继续到下一个数据源 "mydns"。
9. `_nsmethod` 找到 "mydns" 对应的回调函数 `mydns_lookup`。
10. 调用 `mydns_lookup(buffer, NULL, ap)`。
11. **假设 `mydns_lookup` 的实现:**
    * `mydns_lookup` 可能会发起 DNS 查询以查找 "example.com"。
    * 如果找到，将结果写入 `buffer` 并返回 `NS_SUCCESS`。
    * 如果未找到，返回 `NS_NOTFOUND` 或其他错误代码。
12. `nsdispatch` 根据 `mydns_lookup` 的返回值以及 `my_defaults` 中 "mydns" 的 flags 决定是否继续或停止。

**假设输出：**

* 如果 `myfiles_lookup` 找到了 "example.com"，输出可能是 `NS_SUCCESS`，并且 `buffer` 中包含了从 "myfiles" 获取的信息。
* 如果 `myfiles_lookup` 没找到，但 `mydns_lookup` 找到了，输出可能是 `NS_SUCCESS`，并且 `buffer` 中包含了从 DNS 获取的信息。
* 如果两个都找不到，输出可能是 `NS_NOTFOUND`.

**用户或编程常见的使用错误：**

1. **配置错误:**  `disp_tab` 或 `defaults` 配置不正确，导致请求无法路由到正确的处理函数。例如，数据源名称拼写错误，或者回调函数指针为空。
2. **回调函数实现错误:** 回调函数 (`*cb`) 的实现可能存在 bug，导致崩溃、返回错误的结果或者内存泄漏。
3. **忘记处理所有可能的返回值:** 调用 `nsdispatch` 的代码可能没有正确处理所有可能的返回值（例如 `NS_SUCCESS`, `NS_NOTFOUND`, `NS_UNAVAIL`, `NS_TRYAGAIN`），导致程序行为不符合预期。
4. **可变参数传递错误:**  传递给 `nsdispatch` 的可变参数与回调函数期望的参数类型或数量不匹配，可能导致未定义行为。
5. **线程安全问题:**  如果 `disp_tab` 或回调函数内部的状态不是线程安全的，在多线程环境下使用 `nsdispatch` 可能会导致数据竞争或其他并发问题。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤：**

**路径示例 (域名解析):**

1. **Java Framework:** Android 应用调用 Java 网络 API，例如 `InetAddress.getByName("www.example.com")`.
2. **Native Code (libnativehelper.so):** Java Framework 会通过 JNI (Java Native Interface) 调用到 C/C++ 代码，例如 `libnativehelper.so` 中的函数。
3. **Bionic libc (libc.so):** `libnativehelper.so` 最终会调用 Bionic libc 提供的网络函数，例如 `getaddrinfo("www.example.com", NULL, ...)`。
4. **NSS Implementation (libc.so):** `getaddrinfo` 内部会使用 NSS 机制来查找主机名。这涉及到读取 `/system/etc/nsswitch.conf` 等配置文件，并调用 `nsdispatch` 函数来分发请求。
5. **Data Source Modules (可能在其他 .so 中):** `nsdispatch` 根据配置调用相应的回调函数，这些回调函数可能在 `libc.so` 内部，也可能在其他共享库中（例如用于 DNS 解析的模块）。

**Frida Hook 示例：**

假设我们要 hook `nsdispatch` 函数，查看其参数：

```python
import frida
import sys

package_name = "your.target.package"  # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "nsdispatch"), {
    onEnter: function(args) {
        console.log("[*] Called nsdispatch");
        console.log("    retval:", args[0]);
        console.log("    disp_tab:", args[1]);
        console.log("    database:", Memory.readUtf8String(args[2]));
        console.log("    method:", Memory.readUtf8String(args[3]));
        console.log("    defaults:", args[4]);
        // 可以进一步读取可变参数，但这需要知道回调函数的参数类型
    },
    onLeave: function(retval) {
        console.log("[*] nsdispatch returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**使用方法：**

1. 确保你的 Android 设备已连接并通过 USB 调试授权。
2. 安装 Frida 和 frida-tools (`pip install frida-tools`).
3. 将 `your.target.package` 替换为你要调试的应用的包名。
4. 运行 Python 脚本。
5. 在你的 Android 设备上执行触发网络请求或其他需要 NSS 的操作的应用功能。
6. Frida 会拦截对 `nsdispatch` 的调用，并打印出其参数，包括 `database` 和 `method`，你可以从中了解 NSS 正在尝试查找什么信息。

通过 Frida hook，你可以动态地观察 `nsdispatch` 的行为，了解 Android Framework 或 NDK 如何一步步地调用到这个函数，以及传递了哪些参数，这对于理解 Android 的底层命名服务机制非常有帮助。

Prompt: 
```
这是目录为bionic/libc/dns/net/nsdispatch.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: nsdispatch.c,v 1.30 2005/11/29 03:11:59 christos Exp $	*/

/*-
 * Copyright (c) 1997, 1998, 1999, 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Luke Mewburn; and by Jason R. Thorpe.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 * Copyright (c) 2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * Portions of this software were developed for the FreeBSD Project by
 * Jacques A. Vidrine, Safeport Network Services, and Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <assert.h>
#include <errno.h>
#include <nsswitch.h>
#include <stdarg.h>
#include <strings.h>

static nss_method
_nsmethod(const char *source, const char *database __unused, const char *method __unused,
    const ns_dtab disp_tab[], void **cb_data)
{
	int	curdisp;

	if (disp_tab != NULL) {
		for (curdisp = 0; disp_tab[curdisp].src != NULL; curdisp++) {
			if (strcasecmp(source, disp_tab[curdisp].src) == 0) {
				*cb_data = disp_tab[curdisp].cb_data;
				return (disp_tab[curdisp].callback);
			}
		}
	}

	*cb_data = NULL;
	return (NULL);
}

int
/*ARGSUSED*/
nsdispatch(void *retval, const ns_dtab disp_tab[], const char *database,
	    const char *method, const ns_src defaults[], ...)
{
	va_list		 ap;
	int		 i, result;
	const ns_src	*srclist;
	int		 srclistsize;
	nss_method	 cb;
	void		*cb_data;

	/* retval may be NULL */
	/* disp_tab may be NULL */
	assert(database != NULL);
	assert(method != NULL);
	assert(defaults != NULL);
	if (database == NULL || method == NULL || defaults == NULL)
		return (NS_UNAVAIL);

        srclist = defaults;
        srclistsize = 0;
        while (srclist[srclistsize].name != NULL)
                srclistsize++;

	result = 0;

	for (i = 0; i < srclistsize; i++) {
		cb = _nsmethod(srclist[i].name, database, method,
		    disp_tab, &cb_data);
		result = 0;
		if (cb != NULL) {
			va_start(ap, defaults);
			result = (*cb)(retval, cb_data, ap);
			va_end(ap);
			if (defaults[0].flags & NS_FORCEALL)
				continue;
			if (result & srclist[i].flags)
				break;
			/* Stop trying next resolver when there is a memory space fatal error. */
			if ((result & NS_UNAVAIL) != 0 && errno == ENOSPC) {
			  break;
			}
		}
	}
	result &= NS_STATUSMASK;	/* clear private flags in result */

	return (result ? result : NS_NOTFOUND);
}

"""

```