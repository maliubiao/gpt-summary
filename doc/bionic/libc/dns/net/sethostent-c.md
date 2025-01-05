Response:
Let's break down the thought process for analyzing the `sethostent.c` file.

**1. Initial Understanding of the File's Purpose:**

The first step is to recognize the file path: `bionic/libc/dns/net/sethostent.c`. This immediately suggests its involvement in:

* **bionic:** Android's core C library. This means it's a low-level component.
* **libc:** Part of the standard C library implementation.
* **dns:** Domain Name System, relating to hostname resolution.
* **net:** Networking functionalities.
* **`sethostent`:**  The filename directly points to the core function being analyzed. A quick mental note or search would confirm that `sethostent`, `endhostent`, etc., are related to iterating through host entries.

**2. High-Level Functionality Identification:**

Read the copyright and header information. Notice the mention of `NetBSD`. This is important context: Android's Bionic libc often borrows/adapts code from BSD.

Skim the function definitions: `sethostent`, `endhostent`, `sethostent_r`, `endhostent_r`, `_hf_gethtbyname`, `_hf_gethtbyname2`, `_hf_gethtbyaddr`. These names clearly indicate their roles in managing host entry data.

**3. Core Functions and Their Actions:**

* **`sethostent(int stayopen)`:**  The `stayopen` argument hints at whether the underlying data source should remain open. The code calls `sethostent_r`. This suggests a reentrant version exists.
* **`endhostent()`:**  This likely closes the data source opened by `sethostent`. It calls `endhostent_r`.
* **`sethostent_r(FILE **hf)`:**  This is the reentrant version. It opens or rewinds the `/etc/hosts` file (indicated by `_PATH_HOSTS`). The `FILE **hf` suggests it manages a file pointer.
* **`endhostent_r(FILE **hf)`:** This closes the file pointed to by `*hf`.
* **`_hf_gethtbyname(void *rv, void *cb_data, va_list ap)`:** This function aims to retrieve a host entry by name. The `va_list` suggests it's used within a larger framework (like NSS). It calls `_hf_gethtbyname2`. The comment about `glibc compatibility` is a key observation.
* **`_hf_gethtbyname2(const char *name, int af, struct getnamaddr *info)`:** This is the core logic for finding a host by name within the `/etc/hosts` file. It reads the file, compares names and aliases, and populates the `hostent` structure. Pay attention to the use of `malloc`, `free`, and the handling of buffer overflows (`nospc` label).
* **`_hf_gethtbyaddr(void *rv, void *cb_data, va_list ap)`:** This function retrieves a host entry by its IP address. It iterates through the `/etc/hosts` file and compares addresses.

**4. Connections to Android:**

* **`/etc/hosts`:** This file is fundamental to local hostname resolution in Linux/Android. The code directly interacts with it.
* **Bionic libc:**  This entire file *is* part of Bionic. Its functions are used by other parts of the Android system.
* **DNS Resolution:** While this file primarily deals with `/etc/hosts`, it's a component of the broader DNS resolution process in Android. Other parts of Bionic handle DNS queries to remote servers.
* **NDK:**  NDK applications can call these libc functions directly.

**5. Dynamic Linker Analysis (Hypothetical/Contextual):**

Since the code is in `libc`, it will be part of `libc.so`. Think about how an application would use these functions.

* **`libc.so` Layout:** Standard layout with exported symbols like `sethostent`, `gethostbyname`, etc., in the `.symtab` and `.dynsym` sections.
* **Linking:**  An application calling `sethostent` will have a dependency on `libc.so`. The dynamic linker resolves this dependency at runtime, loading `libc.so` and resolving the symbol.

**6. Error Handling and Common Mistakes:**

Notice the `*info->he = ...` assignments. This suggests an error reporting mechanism. Think about common mistakes when using host resolution functions:

* Incorrect buffer sizes.
* Not checking return values.
* Assuming network availability.

**7. Tracing with Frida:**

Consider how you would intercept these calls. Frida is a good tool for this. Think about the function signatures and how to hook them.

**8. Structuring the Response:**

Organize the information logically:

* Start with a summary of the file's purpose.
* Detail the functionality of each function.
* Explain the relationship to Android.
* Discuss dynamic linking.
* Provide examples of usage and errors.
* Show how to trace with Frida.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the `/etc/hosts` file.
* **Correction:** Realize that while this file handles `/etc/hosts`, it's part of a larger DNS resolution mechanism. Mention `res_state` and the interaction with `resolv.h`, even if it's not the primary focus of this specific file.
* **Initial thought:**  Overly detailed explanation of `HENT_SCOPY`, etc.
* **Refinement:**  Recognize that these are likely macros for buffer management and summarize their purpose rather than diving into their exact implementation (unless the prompt specifically asks).
* **Initial thought:** Forget to explicitly mention the reentrant nature of the `_r` functions.
* **Correction:**  Emphasize the thread-safety aspect and why reentrant versions are necessary.

By following this breakdown, combining code analysis with general knowledge of networking and the Android ecosystem, and using a structured approach to present the information, we arrive at a comprehensive and accurate answer.
这个文件 `bionic/libc/dns/net/sethostent.c` 是 Android Bionic C 库中处理主机名数据库访问的一部分。它实现了与打开、关闭和重置主机名数据库文件相关的函数。这个文件主要关注本地主机名解析，通常是通过读取 `/etc/hosts` 文件来实现的。

以下是该文件的功能列表，以及与 Android 功能的关系和详细解释：

**1. 功能列表:**

* **`sethostent(int stayopen)`:** 打开主机名数据库文件。如果 `stayopen` 为非零值，则表示在后续的 `gethostbyname` 或 `gethostbyaddr` 调用后，文件描述符应保持打开状态。
* **`endhostent(void)`:** 关闭主机名数据库文件。
* **`sethostent_r(FILE **hf)`:**  `sethostent` 的可重入版本。它打开或重置主机名数据库文件，并将文件指针存储在 `hf` 指向的位置。
* **`endhostent_r(FILE **hf)`:** `endhostent` 的可重入版本。它关闭 `hf` 指向的文件指针，并将其设置为 `NULL`。
* **`_hf_gethtbyname(void *rv, void *cb_data, va_list ap)`:**  通过主机名查找主机信息的内部函数。它从主机名数据库文件中读取记录，并尝试匹配给定的主机名。这个函数通常由 NSS (Name Service Switch) 框架调用。
* **`_hf_gethtbyname2(const char *name, int af, struct getnamaddr *info)`:**  `_hf_gethtbyname` 的核心实现。它打开主机名数据库文件（如果需要），读取每一行，解析主机名、别名和地址，并将结果存储在 `hostent` 结构中。`af` 参数指定地址族 (如 `AF_INET` 或 `AF_INET6`)。
* **`_hf_gethtbyaddr(void *rv, void *cb_data, va_list ap)`:**  通过 IP 地址查找主机信息的内部函数。它从主机名数据库文件中读取记录，并尝试匹配给定的 IP 地址。

**2. 与 Android 功能的关系及举例说明:**

这些函数是 Android 系统中进行本地主机名解析的基础。当 Android 应用或系统组件需要将主机名转换为 IP 地址，或者将 IP 地址转换为主机名时，这些函数会被间接地调用。

**举例说明:**

* **应用发起网络连接:** 当一个 Android 应用尝试连接到一个主机名 (例如 `www.google.com`) 时，系统首先会查找本地的 `/etc/hosts` 文件。`sethostent` (或其可重入版本) 会被调用来打开这个文件，然后 `gethostbyname` (最终会调用 `_hf_gethtbyname` 或 `_hf_gethtbyname2`) 会读取文件内容并查找匹配的主机名。如果找到匹配项，则返回对应的 IP 地址。
* **ADB 连接:** 当你使用 `adb connect <设备IP>` 连接到 Android 设备时，如果提供了主机名而不是 IP 地址，Android 系统也会使用这些函数来解析该主机名。
* **网络配置:**  Android 的网络配置系统可能会使用这些函数来验证或解析本地主机名。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

* **`sethostent(int stayopen)`:**
    * 获取一个指向 `res_static` 结构的指针，该结构包含用于 DNS 解析的静态数据。
    * 调用 `sethostent_r(&rs->hostf)`，将 `res_static` 结构中的主机文件指针传递给可重入版本。

* **`endhostent(void)`:**
    * 获取 `res_static` 结构指针。
    * 调用 `endhostent_r(&rs->hostf)`，关闭 `res_static` 结构中保存的主机文件。

* **`sethostent_r(FILE **hf)`:**
    * 检查 `*hf` 是否为空。
    * 如果为空，则使用 `fopen(_PATH_HOSTS, "re")` 以只读方式打开 `/etc/hosts` 文件，并将返回的文件指针赋值给 `*hf`。`_PATH_HOSTS` 通常在 `<paths.h>` 中定义为 `/etc/hosts`。
    * 如果 `*hf` 非空，则使用 `rewind(*hf)` 将文件指针重置到文件开头。

* **`endhostent_r(FILE **hf)`:**
    * 检查 `*hf` 是否非空。
    * 如果非空，则使用 `fclose(*hf)` 关闭文件，并将 `*hf` 设置为 `NULL`。

* **`_hf_gethtbyname(void *rv, void *cb_data, va_list ap)`:**
    * 这是一个被 NSS 框架调用的包装函数。
    * 从 `va_list` 中提取主机名 (`name`) 和地址族 (`af`)。
    * 直接调用 `_hf_gethtbyname2(name, af, info)` 来执行实际的查找操作。
    * 根据 `_hf_gethtbyname2` 的返回值设置相应的错误代码并返回 NSS 状态。

* **`_hf_gethtbyname2(const char *name, int af, struct getnamaddr *info)`:**
    * 初始化局部变量，包括用于存储主机别名和地址的数组。
    * 调用 `sethostent_r(&hf)` 打开或重置主机名数据库文件。
    * 分配一块缓冲区 `buf` 用于存储从文件中读取的数据。
    * 进入一个循环，使用 `netbsd_gethostent_r` 从文件中读取每一行主机记录。`netbsd_gethostent_r` 是一个用于解析主机文件行的函数，它将数据填充到 `hostent` 结构中。
    * 对于每一条读取到的主机记录，首先比较主机名是否与目标 `name` 匹配（忽略大小写）。
    * 如果主机名不匹配，则遍历主机别名列表，检查是否有匹配项。
    * 如果找到匹配项：
        * 如果是第一次找到匹配项，则设置 `hent` 结构的基本信息 (地址族、长度、主机名、别名)。
        * 将匹配的 IP 地址复制到 `addr_ptrs` 数组中。
    * 调用 `endhostent_r(&hf)` 关闭主机名数据库文件。
    * 如果找到匹配项，则将结果复制到 `info->hp` 指向的 `hostent` 结构中，包括主机名、别名和地址列表。
    * 释放之前分配的缓冲区 `buf`。
    * 如果没有找到匹配项，则设置错误代码并返回 `NULL`。
    * 如果在处理过程中遇到内存不足 (`ENOSPC`)，则设置相应的错误代码。

* **`_hf_gethtbyaddr(void *rv, void *cb_data, va_list ap)`:**
    * 从 `va_list` 中提取 IP 地址 (`addr`)、地址长度 (`info->hp->h_length`) 和地址族 (`info->hp->h_addrtype`)。
    * 调用 `sethostent_r(&hf)` 打开或重置主机名数据库文件。
    * 进入一个循环，使用 `netbsd_gethostent_r` 从文件中读取每一行主机记录。
    * 对于每一条读取到的主机记录，比较记录中的 IP 地址是否与目标 `addr` 匹配。
    * 如果找到匹配项，则跳出循环。
    * 调用 `endhostent_r(&hf)` 关闭主机名数据库文件。
    * 如果找到匹配项，则返回 `NS_SUCCESS`。否则，设置错误代码并返回 `NS_NOTFOUND`。

**4. 涉及 dynamic linker 的功能:**

这个文件本身的代码并没有直接涉及 dynamic linker 的具体操作。然而，这些函数最终会被链接到 `libc.so` 中，而 dynamic linker 负责在程序运行时加载和链接 `libc.so`。

**so 布局样本 (libc.so 的简化片段):**

```
libc.so:
    .text:
        sethostent:  ... // sethostent 的代码
        endhostent:  ... // endhostent 的代码
        sethostent_r: ... // sethostent_r 的代码
        endhostent_r: ... // endhostent_r 的代码
        _hf_gethtbyname: ... // _hf_gethtbyname 的代码
        _hf_gethtbyname2: ... // _hf_gethtbyname2 的代码
        _hf_gethtbyaddr: ... // _hf_gethtbyaddr 的代码
        ...
    .rodata:
        _PATH_HOSTS: "/etc/hosts"
        ...
    .data:
        ...
    .dynsym:
        sethostent  (GLOBAL, OBJECT, ...)
        endhostent  (GLOBAL, OBJECT, ...)
        gethostbyname (GLOBAL, OBJECT, ...) // 其他相关的 DNS 解析函数
        ...
```

**链接的处理过程:**

1. **编译时:** 当一个应用程序调用 `sethostent` 时，编译器会记录下对该符号的未解析引用。
2. **链接时:** 链接器会将应用程序的目标文件与 `libc.so` 链接在一起。链接器会查找 `libc.so` 的 `.dynsym` 段，找到 `sethostent` 的地址，并将应用程序中对 `sethostent` 的引用指向这个地址。
3. **运行时:** 当应用程序启动时，dynamic linker (如 `linker64` 或 `linker`) 会加载 `libc.so` 到内存中。然后，它会解析应用程序中所有对共享库函数的引用，包括 `sethostent`，确保这些引用指向 `libc.so` 中正确的函数地址。

**5. 逻辑推理 (假设输入与输出):**

假设 `/etc/hosts` 文件包含以下内容:

```
127.0.0.1 localhost
192.168.1.10 myandroid
192.168.1.20 another-host test
```

**假设输入与输出:**

* **输入 `_hf_gethtbyname2("myandroid", AF_INET, ...)`:**
    * **输出:** `hostent` 结构，其中 `h_name` 为 "myandroid"，`h_addr_list[0]` 包含 IP 地址 `192.168.1.10`。

* **输入 `_hf_gethtbyname2("test", AF_INET, ...)`:**
    * **输出:** `hostent` 结构，其中 `h_name` 为 "another-host"，`h_aliases` 包含 "test"，`h_addr_list[0]` 包含 IP 地址 `192.168.1.20`。

* **输入 `_hf_gethtbyaddr(..., {0x0a, 0x00, 0x00, 0x01}, 4, AF_INET)` (对应 IP 地址 10.0.0.1):**
    * **输出:** 如果 `/etc/hosts` 中没有匹配的记录，则返回 `NS_NOTFOUND`。

**6. 用户或编程常见的使用错误:**

* **忘记调用 `endhostent()`:** 如果 `sethostent(1)` 被调用但 `endhostent()` 没有被调用，文件描述符会一直保持打开状态，可能导致资源泄漏。
* **缓冲区溢出:**  虽然代码中使用了 `HENT_SCOPY` 和 `HENT_COPY` 等宏来尝试安全地复制数据，但在手动处理主机名和地址时，不正确的缓冲区大小可能导致溢出。
* **假设 `/etc/hosts` 存在且可读:** 程序应该处理 `/etc/hosts` 文件不存在或无法读取的情况。
* **未处理返回值:** 没有检查 `sethostent` 或 `gethostbyname` 等函数的返回值，可能导致程序在遇到错误时行为不确定。

**7. Android framework 或 ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `sethostent` 的调用路径 (简化):**

1. **Java 代码:** Android 应用的 Java 代码通常不直接调用 `sethostent`。它们会使用 `java.net.InetAddress` 类来进行主机名解析。
2. **Framework (Java/Native):** `InetAddress.getByName(String host)` 等方法会调用到 Android Framework 的 native 代码。
3. **Bionic Libc (JNI):** Framework 的 native 代码会通过 JNI (Java Native Interface) 调用 Bionic Libc 中的 `getaddrinfo` 函数。
4. **NSS (Name Service Switch):** `getaddrinfo` 函数会根据系统配置 (通常通过 `/etc/nsswitch.conf`) 调用不同的解析服务模块。对于本地主机名解析，可能会使用 `files` 模块。
5. **`_nss_files_gethostbyname_r`:** `files` 模块中的函数会打开 `/etc/hosts` 并读取内容。
6. **`sethostent`/`gethostbyname_r`:** 在读取 `/etc/hosts` 的过程中，`sethostent_r` 可能会被调用来打开文件，而 `gethostbyname_r` (或其内部实现，如 `_hf_gethtbyname2`) 会被用来查找主机名。

**NDK 到 `sethostent` 的调用路径:**

1. **C/C++ 代码:** NDK 应用可以直接调用 Bionic Libc 提供的标准 C 库函数，如 `gethostbyname`。
2. **Bionic Libc:** `gethostbyname` 的实现内部会调用 `sethostent` 来打开主机名数据库，然后读取并解析文件内容。

**Frida Hook 示例:**

以下是一个使用 Frida hook `sethostent` 函数的示例：

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName('libc.so');
  const sethostentPtr = libc.getExportByName('sethostent');

  if (sethostentPtr) {
    Interceptor.attach(sethostentPtr, {
      onEnter: function (args) {
        const stayopen = args[0].toInt32();
        console.log('[sethostent] stayopen:', stayopen);
      },
      onLeave: function (retval) {
        console.log('[sethostent] returned');
      }
    });
  } else {
    console.error('Failed to find sethostent in libc.so');
  }
} else {
  console.log('This script is for Android.');
}
```

**解释:**

1. **`if (Process.platform === 'android')`:** 确保脚本只在 Android 环境下运行。
2. **`const libc = Process.getModuleByName('libc.so');`:** 获取 `libc.so` 模块的句柄。
3. **`const sethostentPtr = libc.getExportByName('sethostent');`:** 获取 `sethostent` 函数的地址。
4. **`Interceptor.attach(sethostentPtr, { ... });`:**  使用 Frida 的 `Interceptor` 来拦截对 `sethostent` 函数的调用。
5. **`onEnter: function (args)`:** 在 `sethostent` 函数被调用时执行。`args` 数组包含传递给函数的参数。在这里，`args[0]` 是 `stayopen` 参数。
6. **`onLeave: function (retval)`:** 在 `sethostent` 函数返回时执行。`retval` 包含函数的返回值。

你可以使用类似的 Frida 脚本来 hook 其他函数，如 `endhostent`, `_hf_gethtbyname2` 等，以调试主机名解析过程。要 hook 内部函数（如 `_hf_gethtbyname2`），你可能需要找到其在 `libc.so` 中的地址，这可以通过分析符号表或使用其他 Frida 技术实现。

通过这些分析和示例，你可以更深入地理解 `bionic/libc/dns/net/sethostent.c` 文件在 Android 系统中的作用和实现细节。

Prompt: 
```
这是目录为bionic/libc/dns/net/sethostent.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: sethostent.c,v 1.20 2014/03/17 13:24:23 christos Exp $	*/

/*
 * Copyright (c) 1985, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)sethostent.c	8.1 (Berkeley) 6/4/93";
static char rcsid[] = "Id: sethostent.c,v 8.5 1996/09/28 06:51:07 vixie Exp ";
#else
__RCSID("$NetBSD: sethostent.c,v 1.20 2014/03/17 13:24:23 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <nsswitch.h>
#include <netdb.h>
#include <resolv.h>
#include <errno.h>
#include <stdlib.h>

#include "hostent.h"
#include "resolv_private.h"

#ifndef _REENTRANT
void	res_close(void);
#endif

static struct hostent *_hf_gethtbyname2(const char *, int, struct getnamaddr *);

void
/*ARGSUSED*/
sethostent(int stayopen)
{
	struct res_static* rs = __res_get_static();
	if (rs) sethostent_r(&rs->hostf);
}

void
endhostent(void)
{
	struct res_static* rs = __res_get_static();
	if (rs) endhostent_r(&rs->hostf);
}

void
sethostent_r(FILE **hf)
{
	if (!*hf)
		*hf = fopen(_PATH_HOSTS, "re");
	else
		rewind(*hf);
}

void
endhostent_r(FILE **hf)
{
	if (*hf) {
		(void)fclose(*hf);
		*hf = NULL;
	}
}

/*ARGSUSED*/
int
_hf_gethtbyname(void *rv, void *cb_data, va_list ap)
{
	struct hostent *hp;
	const char *name;
	int af;
	struct getnamaddr *info = rv;

	_DIAGASSERT(rv != NULL);

	name = va_arg(ap, char *);
	/* NOSTRICT skip string len */(void)va_arg(ap, int);
	af = va_arg(ap, int);

#if 0
	{
		res_state res = __res_get_state();
		if (res == NULL)
			return NS_NOTFOUND;
		if (res->options & RES_USE_INET6)
			hp = _hf_gethtbyname2(name, AF_INET6, info);
		else
			hp = NULL;
		if (hp == NULL)
			hp = _hf_gethtbyname2(name, AF_INET, info);
		__res_put_state(res);
	}
#else
	hp = _hf_gethtbyname2(name, af, info);
#endif
	if (hp == NULL) {
		if (*info->he == NETDB_INTERNAL && errno == ENOSPC) {
			return NS_UNAVAIL; // glibc compatibility.
		}
		*info->he = HOST_NOT_FOUND;
		return NS_NOTFOUND;
	}
	return NS_SUCCESS;
}

struct hostent *
_hf_gethtbyname2(const char *name, int af, struct getnamaddr *info)
{
	struct hostent *hp, hent;
	char *buf, *ptr;
	size_t len, anum, num, i;
	FILE *hf;
	char *aliases[MAXALIASES];
	char *addr_ptrs[MAXADDRS];

	_DIAGASSERT(name != NULL);

	hf = NULL;
	sethostent_r(&hf);
	if (hf == NULL) {
		errno = EINVAL;
		*info->he = NETDB_INTERNAL;
		return NULL;
	}

	if ((ptr = buf = malloc(len = info->buflen)) == NULL) {
		*info->he = NETDB_INTERNAL;
		endhostent_r(&hf);
		return NULL;
	}

	anum = 0;		/* XXX: gcc */
	hent.h_name = NULL;	/* XXX: gcc */
	hent.h_addrtype = 0;	/* XXX: gcc */
	hent.h_length = 0;	/* XXX: gcc */

	for (num = 0; num < MAXADDRS;) {
		info->hp->h_addrtype = af;
		info->hp->h_length = 0;

		hp = netbsd_gethostent_r(hf, info->hp, info->buf, info->buflen,
		    info->he);
		if (hp == NULL) {
			if (*info->he == NETDB_INTERNAL && errno == ENOSPC) {
				goto nospc; // glibc compatibility.
			}
			break;
		}

		if (strcasecmp(hp->h_name, name) != 0) {
			char **cp;
			for (cp = hp->h_aliases; *cp != NULL; cp++)
				if (strcasecmp(*cp, name) == 0)
					break;
			if (*cp == NULL) continue;
		}

		if (num == 0) {
			hent.h_addrtype = af = hp->h_addrtype;
			hent.h_length = hp->h_length;

			HENT_SCOPY(hent.h_name, hp->h_name, ptr, len);
			for (anum = 0; hp->h_aliases[anum]; anum++) {
				if (anum >= MAXALIASES)
					goto nospc;
				HENT_SCOPY(aliases[anum], hp->h_aliases[anum],
				    ptr, len);
			}
			ptr = __builtin_align_up(ptr, sizeof(uintptr_t));
			if ((size_t)(ptr - buf) >= info->buflen)
				goto nospc;
		}

		if (num >= MAXADDRS)
			goto nospc;
		HENT_COPY(addr_ptrs[num], hp->h_addr_list[0], hp->h_length, ptr,
		    len);
		num++;
	}
	endhostent_r(&hf);

	if (num == 0) {
		*info->he = HOST_NOT_FOUND;
		free(buf);
		return NULL;
	}

	hp = info->hp;
	ptr = info->buf;
	len = info->buflen;

	hp->h_addrtype = hent.h_addrtype;
	hp->h_length = hent.h_length;

	HENT_ARRAY(hp->h_aliases, anum, ptr, len);
	HENT_ARRAY(hp->h_addr_list, num, ptr, len);

	for (i = 0; i < num; i++)
		HENT_COPY(hp->h_addr_list[i], addr_ptrs[i], hp->h_length, ptr,
		    len);
	hp->h_addr_list[num] = NULL;

	HENT_SCOPY(hp->h_name, hent.h_name, ptr, len);

	for (i = 0; i < anum; i++)
		HENT_SCOPY(hp->h_aliases[i], aliases[i], ptr, len);
	hp->h_aliases[anum] = NULL;

	free(buf);
	return hp;
nospc:
	*info->he = NETDB_INTERNAL;
	endhostent_r(&hf);
	free(buf);
	errno = ENOSPC;
	return NULL;
}

/*ARGSUSED*/
int
_hf_gethtbyaddr(void *rv, void *cb_data, va_list ap)
{
	struct hostent *hp;
	const unsigned char *addr;
	struct getnamaddr *info = rv;
	FILE *hf;

	_DIAGASSERT(rv != NULL);

	addr = va_arg(ap, unsigned char *);
	info->hp->h_length = va_arg(ap, int);
	info->hp->h_addrtype = va_arg(ap, int);

	hf = NULL;
	sethostent_r(&hf);
	if (hf == NULL) {
		*info->he = NETDB_INTERNAL;
		return NS_UNAVAIL;
	}
	while ((hp = netbsd_gethostent_r(hf, info->hp, info->buf, info->buflen,
	    info->he)) != NULL)
		if (!memcmp(hp->h_addr_list[0], addr, (size_t)hp->h_length))
			break;
	endhostent_r(&hf);

	if (hp == NULL) {
		if (errno == ENOSPC) return NS_UNAVAIL; // glibc compatibility.
		*info->he = HOST_NOT_FOUND;
		return NS_NOTFOUND;
	}
	return NS_SUCCESS;
}

"""

```