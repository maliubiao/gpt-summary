Response:
Let's break down the thought process to analyze the provided C header file (`nsswitch.h`) and address all the questions.

**1. Understanding the Core Purpose:**

The first step is to recognize that this header file is about "Name Service Switch" (NSS). The filename `nsswitch.h` and the comments within confirm this. NSS is a mechanism to configure how a system resolves names (like hostnames, usernames, etc.) by specifying different sources and their order.

**2. Identifying Key Data Structures:**

Next, carefully examine the `typedef struct` definitions. These are the building blocks of the NSS implementation:

*   `ns_src`: Represents a source (e.g., "files", "dns"). It stores the source name and flags indicating success/failure, etc.
*   `ns_dtab`:  The "dispatch table". It maps a source to a specific function (`nss_method`) and associated data. Think of it as "for this source, use this function."
*   `ns_mtab`: The "method table". Similar to `ns_dtab` but intended for dynamically loaded modules. It maps (database, method) to a function.
*   `ns_dbt`: The "database table". It represents an entry in `nsswitch.conf`, linking a database name (e.g., "hosts") to a list of `ns_src` entries.
*   `ns_mod`: Represents a dynamically loaded NSS module.

**3. Deconstructing the Macros and Constants:**

Pay attention to the `#define` statements. These define important constants and macros:

*   Paths: `_PATH_NS_CONF` points to the configuration file.
*   Return Codes: `NS_CONTINUE`, `NS_RETURN`, `NS_SUCCESS`, `NS_UNAVAIL`, etc., define the possible outcomes of a name resolution attempt.
*   Flags: `NS_FORCEALL` and the status flags.
*   Source and Database Names: `NSSRC_FILES`, `NSSRC_DNS`, `NSDB_HOSTS`, `NSDB_PASSWD`, etc. These are the keywords used in `nsswitch.conf`.
*   Callback Macros: `NS_FILES_CB`, `NS_DNS_CB`, etc. These help create entries in the `ns_dtab`.

**4. Analyzing Function Declarations:**

Look at the function prototypes declared:

*   `nsdispatch`: This is the central function for querying name services. It takes the database, dispatch table, and other arguments.
*   `nss_module_register_fn`, `nss_module_unregister_fn`: Function pointer types for registering and unregistering dynamically loaded modules.
*   The `_nsdbt...` functions (prefixed with `_NS_PRIVATE`): These are internal helper functions for managing the database table.

**5. Connecting to Android:**

Now, relate these concepts to Android. Since the file is in `bionic/libc/dns`, it's clear that this NSS implementation is part of Android's standard C library and is used for resolving network-related names.

**6. Addressing Specific Questions (Mental Check-List):**

Go through each point in the prompt and see how the header file relates:

*   **功能 (Functionality):**  The core function is to provide a configurable mechanism for name resolution. List the data structures and their roles.
*   **与 Android 功能的关系 (Relationship to Android):** Explain how it's used for network operations (hostname lookup, etc.). Mention that Bionic is Android's libc.
*   **libc 函数功能 (libc Function Details):** Focus on `nsdispatch`. Explain its purpose (querying sources) and the meaning of its parameters (dispatch table, sources). Since the header doesn't provide *implementation* details, emphasize the high-level function.
*   **dynamic linker 功能 (Dynamic Linker Functionality):** Explain the purpose of `ns_mtab`, `ns_mod`, `nss_module_register_fn`, and `nss_module_unregister_fn`. Describe the scenario where modules are loaded (e.g., for custom name resolution). Sketch a basic SO layout with the registration function. Describe the linking process.
*   **逻辑推理 (Logical Deduction):**  Think of a simple example: looking up a hostname. Show how `nsswitch.conf` directs the lookup to "files" then "dns."  Trace the flow through `nsdispatch`.
*   **用户或编程常见错误 (Common Errors):**  Think about mistakes in `nsswitch.conf` (syntax, ordering), and missing dependencies for dynamic modules.
*   **Android Framework/NDK 到达这里 (Path from Framework/NDK):** Start from a high-level Android API call (e.g., `InetAddress.getByName()`) and trace it down through the NDK, libc, and ultimately to the NSS functions. Consider the role of `getaddrinfo`.
*   **Frida Hook 示例 (Frida Hook Example):** Identify key functions to hook (e.g., `nsdispatch`, module registration functions). Provide a basic Frida script demonstrating hooking and logging.

**7. Structuring the Response:**

Organize the information logically, addressing each point in the prompt clearly. Use headings and bullet points for readability. Provide code examples (SO layout, Frida script) where requested.

**Self-Correction/Refinement During the Process:**

*   **Initial thought:** Maybe focus too much on low-level bit manipulation of the flags. **Correction:**  Keep the explanation at a higher level, focusing on the purpose and usage of the flags.
*   **Initial thought:** Try to explain the exact implementation of `nsdispatch`. **Correction:**  Recognize that the header file only *declares* the function. Describe its role and parameters instead.
*   **Initial thought:**  Make the Frida example too complex. **Correction:** Simplify the example to focus on the basic principle of hooking a function and logging its arguments.

By following these steps, focusing on understanding the purpose and key components of the header file, and systematically addressing each question in the prompt, a comprehensive and accurate answer can be constructed.
这个头文件 `bionic/libc/dns/include/nsswitch.handroid` 定义了 Android Bionic C 库中用于名称服务切换 (Name Service Switch, NSS) 的接口和数据结构。NSS 是一个用于配置系统如何查找各种类型信息的机制，例如主机名、用户名、组名等。它允许管理员指定不同的信息源 (例如本地文件、DNS、NIS) 及其查询顺序。

**功能列表:**

1. **定义 NSS 架构:** 定义了用于描述 NSS 配置的关键数据结构，例如源 (source)、数据库 (database)、方法 (method) 和模块 (module)。
2. **定义标准常量:** 提供了表示 NSS 操作结果、标志和已知源/数据库的常量，例如 `NS_SUCCESS`、`NS_UNAVAIL`、`NSSRC_FILES`、`NSDB_HOSTS` 等。
3. **定义回调函数类型:** 定义了 NSS 模块中用于实际执行查找操作的函数指针类型 `nss_method`。
4. **定义调度表 (Dispatch Table):** 定义了 `ns_dtab` 结构，用于静态地将源与对应的回调函数关联起来。
5. **定义模块表 (Method Table):** 定义了 `ns_mtab` 结构，用于动态加载的 NSS 模块，将数据库和方法名映射到实际的函数。
6. **定义模块注册/反注册函数类型:**  定义了 `nss_module_register_fn` 和 `nss_module_unregister_fn`，用于动态加载和卸载 NSS 模块。
7. **声明核心调度函数:** 声明了 `nsdispatch` 函数，它是 NSS 的核心，用于根据配置执行查找操作。
8. **声明私有辅助函数 (ifdef _NS_PRIVATE):** 声明了一些内部使用的辅助函数，用于解析和管理 NSS 配置。

**与 Android 功能的关系及举例说明:**

NSS 在 Android 中扮演着至关重要的角色，它决定了应用程序如何解析主机名、查找用户信息等。

*   **主机名解析:** 当应用程序需要将主机名 (例如 `www.google.com`) 转换为 IP 地址时，Bionic 的网络库会使用 NSS 来完成这个任务。`nsswitch.conf` 文件 (位于 `/etc/nsswitch.conf`) 中 `hosts:` 行的配置决定了查找顺序，例如先查本地 `/etc/hosts` 文件，再查 DNS 服务器。
    ```
    # /etc/nsswitch.conf
    hosts: files dns
    ```
    这意味着当调用 `getaddrinfo("www.google.com", ...)` 时，Bionic 会首先使用 `files` 源 (对应 `/etc/hosts`) 进行查找，如果找不到，则会使用 `dns` 源进行查找。

*   **用户信息查找:**  当应用程序需要获取用户信息 (例如用户名对应的 UID) 时，NSS 也会被使用。`nsswitch.conf` 中 `passwd:` 行的配置决定了查找顺序，例如先查本地 `/etc/passwd` 文件。
    ```
    # /etc/nsswitch.conf
    passwd: files
    ```
    这意味着当调用 `getpwnam("username")` 时，Bionic 会使用 `files` 源 (对应 `/etc/passwd`) 进行查找。

*   **网络组查找:**  NSS 可以配置如何查找网络组信息。

**详细解释 libc 函数的功能实现:**

这个头文件本身并没有实现 libc 函数的功能，它只是定义了接口和数据结构。具体的实现位于 Bionic 的其他源文件中，例如 `bionic/libc/dns/nss/nss_files.c` (实现 `files` 源) 和 `bionic/libc/dns/nss/nss_dns.c` (实现 `dns` 源)。

**`nsdispatch` 函数:**

`nsdispatch` 是 NSS 的核心函数，它的主要功能是根据给定的数据库和配置，遍历指定的源，并调用与每个源关联的回调函数，直到找到结果或所有源都尝试完毕。

**假设输入与输出 (针对 `nsdispatch`)**

假设我们要查找主机名 `example.com`，并且 `nsswitch.conf` 中 `hosts:` 行配置为 `files dns`。

**输入:**

*   `void *`:  可能包含一些上下文信息，具体取决于调用的上下文。
*   `const ns_dtab []`:  一个调度表，其中包含了每个源 (例如 `files`, `dns`) 及其对应的回调函数。对于 `files` 源，回调函数可能负责读取 `/etc/hosts` 文件；对于 `dns` 源，回调函数可能负责发起 DNS 查询。
*   `const char *`:  数据库名称，例如 `"hosts"`。
*   `const char *`:  要查找的键，例如 `"example.com"`。
*   `const ns_src []`:  从解析 `nsswitch.conf` 得到的源列表，例如 `{ "files", 0 }, { "dns", 0 }`。
*   `...`:  可变参数，传递给回调函数的参数，例如用于存储结果的缓冲区。

**输出:**

*   返回值: `NS_SUCCESS` (找到结果), `NS_NOTFOUND` (未找到结果), `NS_UNAVAIL` (源不可用), `NS_TRYAGAIN` (稍后重试) 等。
*   通过可变参数修改: 将查找结果存储到提供的缓冲区中 (如果找到)。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

NSS 允许动态加载模块来扩展其功能。`ns_mtab`、`ns_mod`、`nss_module_register_fn` 和 `nss_module_unregister_fn` 就是为了支持这个特性。

**so 布局样本 (假设一个名为 `nss_mycustom.so` 的自定义 NSS 模块):**

```
nss_mycustom.so:
    ... 其他代码 ...

    // 实现自定义查找方法的函数
    int my_lookup_hosts(void *cb_data, void *result, va_list ap) {
        // 自定义查找逻辑
        ...
    }

    // 模块注册函数
    ns_mtab *nss_module_register(const char *name, u_int *size, nss_module_unregister_fn *unregister) {
        static ns_mtab my_mtab[] = {
            { "hosts", "mycustom", my_lookup_hosts, NULL },
            { NULL } // 结束标记
        };
        *size = sizeof(my_mtab) / sizeof(my_mtab[0]) - 1;
        *unregister = nss_module_unregister;
        return my_mtab;
    }

    // 模块反注册函数
    void nss_module_unregister(ns_mtab *mtab, u_int size) {
        // 清理资源
        ...
    }

    // 导出注册函数 (用于 dynamic linker)
    .global nss_module_register
```

**链接的处理过程:**

1. **解析 `nsswitch.conf`:** Bionic 的 NSS 实现会解析 `/etc/nsswitch.conf` 文件。
2. **遇到动态模块配置:** 如果在 `nsswitch.conf` 中配置了需要动态加载的模块 (例如 `hosts: files mycustom dns`)。
3. **`dlopen` 加载模块:** Bionic 的 NSS 实现会使用 `dlopen("nss_mycustom.so", RTLD_LAZY)` 加载指定的动态库。
4. **查找注册函数:** dynamic linker (在 Android 上通常是 `linker64` 或 `linker`) 会在加载的 `.so` 文件中查找名为 `nss_module_register` 的符号。
5. **调用注册函数:** Bionic 的 NSS 代码会调用 `nss_module_register` 函数。
6. **返回方法表:** `nss_module_register` 函数会返回一个 `ns_mtab` 数组，描述了该模块提供的查找方法。
7. **添加到模块列表:** Bionic 的 NSS 实现会将这个方法表添加到其内部的模块列表中。
8. **使用自定义方法:** 当需要查找 `hosts` 时，如果配置中指定了 `mycustom` 源，`nsdispatch` 函数会根据 `ns_mtab` 中的信息调用 `my_lookup_hosts` 函数。
9. **`dlclose` 卸载模块:** 在不再需要时，可以使用 `dlclose()` 卸载动态加载的模块，并调用其 `nss_module_unregister` 函数进行清理。

**用户或者编程常见的使用错误举例说明:**

1. **`nsswitch.conf` 配置错误:**
    *   **语法错误:**  在 `nsswitch.conf` 中拼写错误源或数据库名称，导致 NSS 无法正确解析配置文件。
        ```
        # 错误示例
        hotss: files dns
        ```
    *   **源的顺序不当:**  将不可靠或性能差的源放在前面，导致不必要的延迟。例如，如果 DNS 服务器不可用，但 `dns` 放在 `files` 前面，系统会先尝试 DNS 查询，导致启动缓慢。
    *   **缺少必要的源:**  如果应用程序依赖某个源 (例如 `dns`) 但在 `nsswitch.conf` 中没有配置，会导致查找失败。

2. **动态模块加载失败:**
    *   **so 文件不存在或路径错误:** 如果在 `nsswitch.conf` 中配置了动态模块，但对应的 `.so` 文件不存在或路径不正确，`dlopen` 会失败。
    *   **符号未导出:**  如果动态库中的 `nss_module_register` 函数没有正确导出，dynamic linker 无法找到它，导致加载失败。
    *   **依赖项缺失:**  动态库可能依赖其他的共享库，如果这些依赖项没有被加载，加载会失败。

3. **NSS 调用错误:**
    *   **传递错误的参数给 NSS 函数:**  例如，传递空指针或不正确的缓冲区大小。
    *   **假设特定的查找顺序:**  应用程序不应该硬编码假设 NSS 的查找顺序，因为这是可配置的。应该处理各种可能的查找结果。

**Android Framework 或 NDK 如何一步步的到达这里，给出 Frida hook 示例调试这些步骤。**

以下以主机名解析为例，说明 Android Framework 如何最终调用到 NSS 相关代码：

1. **Android Framework API 调用:**  应用程序调用 Android Framework 提供的网络 API，例如 `InetAddress.getByName("www.google.com")`。
2. **Framework 层调用 Native 方法:** Framework 层 (Java 代码) 会通过 JNI (Java Native Interface) 调用到 Android 运行时 (ART) 或 Dalvik 中的 native 方法。
3. **NDK 网络库:**  Framework 调用的 native 方法最终会调用到 NDK 提供的网络库函数，例如 `getaddrinfo("www.google.com", ...)`。`getaddrinfo` 是一个标准的 POSIX 函数，用于进行地址解析。
4. **Bionic libc `getaddrinfo` 实现:** NDK 中的 `getaddrinfo` 函数最终会调用到 Bionic libc 的 `getaddrinfo` 实现 (`bionic/libc/net/getaddrinfo.c`)。
5. **NSS 调用:** Bionic 的 `getaddrinfo` 实现内部会使用 NSS 机制来查找主机名对应的 IP 地址。它会读取 `/etc/nsswitch.conf`，并调用 `nsdispatch` 函数，根据配置的源 (例如 `files`, `dns`) 依次尝试查找。
6. **NSS 模块调用:**  `nsdispatch` 会根据配置调用相应的 NSS 模块的函数，例如 `nss_files.so` 或 `nss_dns.so` 中的函数来执行实际的查找操作。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida Hook `getaddrinfo` 或 `nsdispatch` 函数来观察其调用过程和参数。

**Hook `getaddrinfo`:**

```javascript
Java.perform(function() {
    var InetAddress = Java.use("java.net.InetAddress");
    InetAddress.getByName.overload('java.lang.String').implementation = function(host) {
        console.log("[Frida] Hooking InetAddress.getByName, host: " + host);
        var result = this.getByName(host);
        console.log("[Frida] InetAddress.getByName returned: " + result);
        return result;
    };
});
```

这个 Frida 脚本 Hook 了 Java 层的 `InetAddress.getByName` 方法，可以观察到应用程序发起的域名解析请求。

**Hook `getaddrinfo` (Native 层):**

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "getaddrinfo"), {
    onEnter: function(args) {
        console.log("[Frida] Hooking getaddrinfo");
        console.log("  hostname: " + Memory.readCString(args[0]));
        console.log("  service:  " + Memory.readCString(args[1]));
        // ... 打印其他参数
    },
    onLeave: function(retval) {
        console.log("[Frida] getaddrinfo returned: " + retval);
        // ... 打印返回值
    }
});
```

这个 Frida 脚本 Hook 了 native 层的 `getaddrinfo` 函数，可以观察到传递给 `getaddrinfo` 的主机名和服务名。

**Hook `nsdispatch`:**

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "nsdispatch"), {
    onEnter: function(args) {
        console.log("[Frida] Hooking nsdispatch");
        console.log("  database: " + Memory.readCString(args[2]));
        console.log("  key:      " + Memory.readCString(args[3]));
        // 可以进一步解析 ns_dtab 和 ns_src 结构
    },
    onLeave: function(retval) {
        console.log("[Frida] nsdispatch returned: " + retval);
    }
});
```

这个 Frida 脚本 Hook 了 `nsdispatch` 函数，可以观察到正在查询的数据库和键，以及 NSS 的执行流程。

通过这些 Frida Hook 脚本，可以清晰地观察到 Android Framework 如何一步步地调用到 Bionic libc 的 NSS 相关函数进行名称解析。 可以根据需要 Hook 不同的函数来调试不同阶段的行为。

### 提示词
```
这是目录为bionic/libc/dns/include/nsswitch.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: nsswitch.h,v 1.21 2011/07/17 20:54:34 joerg Exp $	*/

/*-
 * Copyright (c) 1997, 1998, 1999, 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Luke Mewburn.
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

#ifndef _NSSWITCH_H
#define _NSSWITCH_H	1

#include <sys/types.h>
#include <stdarg.h>

#define	NSS_MODULE_INTERFACE_VERSION	0

#ifndef _PATH_NS_CONF
#define _PATH_NS_CONF	"/etc/nsswitch.conf"
#endif

#define	NS_CONTINUE	0
#define	NS_RETURN	1

/*
 * Layout of:
 *	uint32_t ns_src.flags
 */
	/* nsswitch.conf status codes and nsdispatch(3) return values */
#define	NS_SUCCESS	(1<<0)		/* entry was found */
#define	NS_UNAVAIL	(1<<1)		/* source not responding, or corrupt */
#define	NS_NOTFOUND	(1<<2)		/* source responded 'no such entry' */
#define	NS_TRYAGAIN	(1<<3)		/* source busy, may respond to retrys */
#define	NS_STATUSMASK	0x000000ff	/* bitmask to get the status flags */

	/* internal nsdispatch(3) flags; not settable in nsswitch.conf(5)  */
#define	NS_FORCEALL	(1<<8)		/* force all methods to be invoked; */

/*
 * Currently implemented sources.
 */
#define NSSRC_FILES	"files"		/* local files */
#define	NSSRC_DNS	"dns"		/* DNS; IN for hosts, HS for others */
#define	NSSRC_NIS	"nis"		/* YP/NIS */
#define	NSSRC_COMPAT	"compat"	/* passwd,group in YP compat mode */

/*
 * Currently implemented databases.
 */
#define NSDB_HOSTS		"hosts"
#define NSDB_GROUP		"group"
#define NSDB_GROUP_COMPAT	"group_compat"
#define NSDB_NETGROUP		"netgroup"
#define NSDB_NETWORKS		"networks"
#define NSDB_PASSWD		"passwd"
#define NSDB_PASSWD_COMPAT	"passwd_compat"
#define NSDB_SHELLS		"shells"

/*
 * Suggested databases to implement.
 */
#define NSDB_ALIASES		"aliases"
#define NSDB_AUTH		"auth"
#define NSDB_AUTOMOUNT		"automount"
#define NSDB_BOOTPARAMS		"bootparams"
#define NSDB_ETHERS		"ethers"
#define NSDB_EXPORTS		"exports"
#define NSDB_NETMASKS		"netmasks"
#define NSDB_PHONES		"phones"
#define NSDB_PRINTCAP		"printcap"
#define NSDB_PROTOCOLS		"protocols"
#define NSDB_REMOTE		"remote"
#define NSDB_RPC		"rpc"
#define NSDB_SENDMAILVARS	"sendmailvars"
#define NSDB_SERVICES		"services"
#define NSDB_TERMCAP		"termcap"
#define NSDB_TTYS		"ttys"

/*
 * ns_dtab `callback' function signature.
 */
typedef	int (*nss_method)(void *, void *, va_list);

/*
 * ns_dtab - `nsswitch dispatch table'
 * Contains an entry for each source and the appropriate function to call.
 */
typedef struct {
	const char	 *src;
	nss_method	 callback;
	void		 *cb_data;
} ns_dtab;

/*
 * Macros to help build an ns_dtab[]
 */
#define NS_FILES_CB(F,C)	{ NSSRC_FILES,	F,	__UNCONST(C) },
#define NS_COMPAT_CB(F,C)	{ NSSRC_COMPAT,	F,	__UNCONST(C) },

#ifdef HESIOD
#   define NS_DNS_CB(F,C)	{ NSSRC_DNS,	F,	__UNCONST(C) },
#else
#   define NS_DNS_CB(F,C)
#endif

#ifdef YP
#   define NS_NIS_CB(F,C)	{ NSSRC_NIS,	F,	__UNCONST(C) },
#else
#   define NS_NIS_CB(F,C)
#endif
#define	NS_NULL_CB		{ .src = NULL },

/*
 * ns_src - `nsswitch source'
 * Used by the nsparser routines to store a mapping between a source
 * and its dispatch control flags for a given database.
 */
typedef struct {
	const char	*name;
	uint32_t	 flags;
} ns_src;


/*
 * ns_mtab - `nsswitch method table'
 * An nsswitch module provides a mapping from (database name, method name)
 * tuples to the nss_method and associated callback data.  Effectively,
 * ns_dtab, but used for dynamically loaded modules.
 */
typedef struct {
	const char	*database;
	const char	*name;
	nss_method	 method;
	void		*mdata;
} ns_mtab;

/*
 * nss_module_register_fn - module registration function
 *	called at module load
 * nss_module_unregister_fn - module un-registration function
 *	called at module unload
 */
typedef	void (*nss_module_unregister_fn)(ns_mtab *, u_int);
typedef	ns_mtab *(*nss_module_register_fn)(const char *, u_int *,
					   nss_module_unregister_fn *);

#ifdef _NS_PRIVATE

/*
 * Private data structures for back-end nsswitch implementation.
 */

/*
 * ns_dbt - `nsswitch database thang'
 * For each database in /etc/nsswitch.conf there is a ns_dbt, with its
 * name and a list of ns_src's containing the source information.
 */
typedef struct {
	const char	*name;		/* name of database */
	ns_src		*srclist;	/* list of sources */
	u_int		 srclistsize;	/* size of srclist */
} ns_dbt;

/*
 * ns_mod - `nsswitch module'
 */
typedef struct {
	const char	*name;		/* module name */
	void		*handle;	/* handle from dlopen() */
	ns_mtab		*mtab;		/* method table */
	u_int		 mtabsize;	/* size of mtab */
					/* called to unload module */
	nss_module_unregister_fn unregister;
} ns_mod;

#endif /* _NS_PRIVATE */


#include <sys/cdefs.h>

__BEGIN_DECLS
int	nsdispatch(void *, const ns_dtab [], const char *,
			const char *, const ns_src [], ...);

#ifdef _NS_PRIVATE
int		 _nsdbtaddsrc(ns_dbt *, const ns_src *);
void		 _nsdbtdump(const ns_dbt *);
int		 _nsdbtput(const ns_dbt *);
void		 _nsyyerror(const char *);
int		 _nsyylex(void);
#endif /* _NS_PRIVATE */

__END_DECLS

#endif /* !_NSSWITCH_H */
```