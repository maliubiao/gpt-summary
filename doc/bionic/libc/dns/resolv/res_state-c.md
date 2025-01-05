Response:
Let's break down the thought process for answering the request about `res_state.c`.

**1. Understanding the Core Request:**

The request is about understanding the functionality of a specific C source file within Android's Bionic library, `bionic/libc/dns/resolv/res_state.c`. The core task is to analyze its purpose, implementation details, interaction with Android, and potential usage scenarios.

**2. Initial Analysis of the Code:**

The first step is to read through the code and identify key components and their roles. I would look for:

* **Includes:** `sys/cdefs.h`, `sys/types.h`, `arpa/inet.h`, `arpa/nameser.h`, `netdb.h`, `resolv_private.h`, `resolv_cache.h`, `pthread.h`, `stdlib.h`, `string.h`. These indicate the code deals with network addresses, DNS, threading, memory management, and string manipulation.
* **Macros:** `DEBUG`. This suggests a debugging feature that can be toggled.
* **Typedefs:**  The definition of the `_res_thread` struct is crucial. It contains `_h_errno`, `_nres` (a `__res_state`), and `_rstatic` (a `res_static`). This strongly suggests this file manages thread-local DNS resolver state.
* **Static Functions:** `_res_thread_alloc`, `_res_static_done`, `_res_thread_free`, `_res_thread_get`. These are internal helper functions for managing the `_res_thread` structure.
* **Global Static Variables:** `_res_key`. This, combined with the use of `pthread_key_create`, points to thread-local storage.
* **Constructor Attribute:** `__attribute__((constructor)) static void __res_key_init()`. This indicates initialization code that runs when the shared library is loaded.
* **Exported Functions:** `__get_h_errno`, `__res_get_state`, `__res_put_state`, `__res_get_static`. These are the functions intended to be used by other parts of the library.

**3. Identifying Core Functionality:**

Based on the code analysis, the primary function of `res_state.c` is to manage thread-local storage for DNS resolver state. This involves:

* **Allocation:** Creating and initializing the `_res_thread` structure.
* **Initialization:** Calling `res_ninit` to initialize the DNS resolver state within the thread-local storage.
* **Access:** Providing functions (`__get_h_errno`, `__res_get_state`, `__res_get_static`) to access the thread-local DNS resolver state.
* **Cleanup:** Freeing the allocated memory when the thread exits or the library is unloaded.

**4. Relating to Android Functionality:**

The DNS resolver is a fundamental part of networking. Android applications rely on it to translate hostnames to IP addresses. This file plays a role in ensuring that each thread performing DNS lookups has its own independent resolver state, preventing race conditions and other threading issues.

**5. Explaining `libc` Functions:**

The request asks for detailed explanations of `libc` functions. This requires understanding what each function does. For instance:

* `calloc`:  Allocate and zero-initialize memory.
* `memset`:  Set a block of memory to a specific value.
* `free`:  Release allocated memory.
* `pthread_key_create`: Create a thread-specific storage key.
* `pthread_getspecific`: Retrieve the value associated with a thread-specific storage key for the current thread.
* `pthread_setspecific`: Set the value associated with a thread-specific storage key for the current thread.
* `res_ninit`: Initialize or reset a DNS resolver state structure.
* `fclose`: Close a file stream.

**6. Addressing Dynamic Linker Aspects:**

The presence of the `__attribute__((constructor))` attribute immediately signals interaction with the dynamic linker. I would explain:

* **`.init_array`:**  Where the linker places constructor functions.
* **SO Layout:**  A basic explanation of how shared libraries are structured, including sections like `.text`, `.data`, `.bss`, and `.init_array`.
* **Linking Process:** A high-level description of how the dynamic linker loads and initializes shared libraries.

**7. Considering Logical Reasoning (Hypothetical Inputs/Outputs):**

For logical reasoning, I would focus on the thread-local storage aspect:

* **Input:** Multiple threads calling functions that trigger DNS lookups (e.g., `getaddrinfo`).
* **Output:** Each thread gets its own `_res_thread` structure with its independent DNS resolver state, ensuring isolation.

**8. Identifying Common Usage Errors:**

The most likely error is incorrect handling of the `res_state` structure if the user were to directly interact with it (which is usually discouraged, as it's an internal detail). However, since the functions provided are more about *getting* the state, a more relevant error is not initializing the resolver properly or misconfiguring DNS settings at the system level, which would affect the underlying `res_ninit` behavior.

**9. Tracing the Call Path (Android Framework/NDK):**

This requires a high-level understanding of how Android applications use networking. The path would involve:

* **Application Code:** Making a network request (e.g., using Java's `java.net` package or NDK's socket APIs).
* **Android Framework:** The framework's networking components (e.g., `ConnectivityManager`, `NetworkCapabilities`) handle network management.
* **System Calls:**  Eventually, the request reaches native code where system calls like `getaddrinfo` are made.
* **Bionic Libc:**  `getaddrinfo` and related functions rely on the DNS resolver implementation within Bionic, which includes `res_state.c`.

**10. Providing a Frida Hook Example:**

A Frida hook needs to target a function that utilizes the resolver state. `getaddrinfo` is a good choice because it's a common entry point for DNS resolution. The hook should demonstrate how to intercept the call and potentially examine the `res_state`.

**11. Structuring the Answer:**

Finally, organize the information logically, using clear headings and bullet points for readability. Start with a high-level overview of the file's purpose and then delve into the details. Ensure all aspects of the original request are addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the individual `libc` functions.
* **Correction:**  Realize the core purpose is managing thread-local state, making the interaction between `pthread` functions and `res_ninit` more central.
* **Initial thought:** Provide complex examples of manual `res_state` manipulation.
* **Correction:**  Focus on more realistic user errors related to DNS configuration, as direct manipulation is less common.
* **Initial thought:** Give a very low-level, system call-focused call path.
* **Correction:**  Start with higher-level Android framework components to provide a more understandable flow.

By following this thought process, and continually refining the understanding and presentation, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析一下 `bionic/libc/dns/resolv/res_state.c` 这个文件。

**功能概述:**

`res_state.c` 的主要功能是管理 DNS 解析器状态的线程本地存储。这意味着每个线程在进行 DNS 查询时都会拥有自己独立的 DNS 解析器状态，从而避免多线程环境下的数据竞争和状态冲突。

具体来说，它负责：

1. **为每个线程分配和初始化 `__res_state` 结构体:**  `__res_state` 是 DNS 解析的核心数据结构，包含了查询选项、服务器列表、超时设置、缓存等信息。
2. **提供访问当前线程 `__res_state` 的接口:**  通过 `__res_get_state()` 函数，其他 DNS 相关代码可以获取到当前线程的 DNS 解析器状态。
3. **管理与 DNS 解析相关的静态数据:**  通过 `_rstatic` 成员，管理一些静态的、但可能需要在每个线程中独立访问的数据，例如 `hosts` 文件相关的缓冲。
4. **在线程退出时清理分配的资源:**  确保在线程结束后，为该线程分配的 DNS 解析器状态被正确释放，避免内存泄漏。

**与 Android 功能的关系及举例说明:**

DNS 解析是 Android 系统中非常基础且重要的功能，几乎所有需要访问网络的应用都依赖于它将域名转换为 IP 地址。 `res_state.c` 在其中扮演着关键角色，确保了 DNS 解析在多线程环境下的稳定性和正确性。

**举例说明:**

* 当一个 Android 应用（例如浏览器、社交应用）需要访问一个网站时，它会调用 `getaddrinfo()` 或类似的函数来进行 DNS 查询。
* `getaddrinfo()` 最终会调用到 Bionic libc 中的 DNS 解析相关代码。
* 这些代码会通过 `__res_get_state()` 获取当前线程的 `__res_state` 结构体，并使用其中的配置信息进行 DNS 查询。
* 由于每个线程都有自己的 `__res_state`，因此不同线程发起的 DNS 查询不会互相干扰，可以独立配置和管理。

**详细解释每个 libc 函数的功能是如何实现的:**

让我们逐个分析 `res_state.c` 中涉及的 `libc` 函数：

1. **`calloc(1, sizeof(*rt))`:**
   - **功能:**  在堆上分配一块大小为 `sizeof(*rt)` 的内存，并将该内存块的所有字节初始化为 0。
   - **实现:**  `calloc` 通常由内存分配器（例如 `dlmalloc` 或 `jemalloc`，取决于 Android 版本）实现。它会从堆中找到一块足够大的空闲内存块，将其标记为已分配，并将内容清零，然后返回指向该内存块的指针。
   - **在本文件中的作用:**  用于为 `_res_thread` 结构体分配内存。

2. **`memset(rt->_rstatic, 0, sizeof rt->_rstatic)`:**
   - **功能:**  将从 `rt->_rstatic` 开始的 `sizeof rt->_rstatic` 个字节设置为 0。
   - **实现:**  `memset` 通常由汇编语言高度优化实现，它可以高效地将指定的值写入内存块。
   - **在本文件中的作用:**  初始化 `_res_thread` 结构体中的 `_rstatic` 成员。

3. **`free(rs->servent.s_aliases)`:**
   - **功能:**  释放之前通过 `malloc` 或 `calloc` 分配的内存块。
   - **实现:**  `free` 会将指定的内存块标记为空闲，并将其归还给内存分配器，以便后续的内存分配请求可以使用这块内存。
   - **在本文件中的作用:**  释放与服务信息相关的别名列表占用的内存。

4. **`fclose(rs->hostf)`:**
   - **功能:**  关闭由 `fopen` 打开的文件流。
   - **实现:**  `fclose` 会刷新缓冲区中的数据到磁盘，释放与文件流相关的资源（例如文件描述符）。
   - **在本文件中的作用:**  关闭用于读取 `hosts` 文件的文件流。

5. **`pthread_key_create(&_res_key, _res_thread_free)`:**
   - **功能:**  创建一个线程特定的数据键。当线程退出时，与该键关联的析构函数（在这里是 `_res_thread_free`）会被调用。
   - **实现:**  操作系统会维护一个全局的线程特定数据键的列表。`pthread_key_create` 会分配一个新的键，并将析构函数与该键关联起来。
   - **在本文件中的作用:**  创建用于存储每个线程的 `_res_thread` 结构体的键。

6. **`pthread_getspecific(_res_key)`:**
   - **功能:**  获取与当前线程和指定键关联的值。
   - **实现:**  操作系统会维护每个线程的键值对。`pthread_getspecific` 会查找当前线程的指定键，并返回与之关联的值。
   - **在本文件中的作用:**  获取当前线程的 `_res_thread` 结构体。

7. **`pthread_setspecific(_res_key, rt)`:**
   - **功能:**  将指定的值与当前线程和指定的键关联起来。
   - **实现:**  操作系统会更新当前线程的键值对，将指定的值与指定的键关联起来。
   - **在本文件中的作用:**  将新创建的 `_res_thread` 结构体与当前线程关联。

8. **`res_ninit(rt->_nres)`:**
   - **功能:**  初始化或重新初始化 `__res_state` 结构体。这包括读取 `/etc/resolv.conf` 文件来获取 DNS 服务器地址、设置默认选项等。
   - **实现:**  `res_ninit` 会执行一系列操作，包括打开并解析 `/etc/resolv.conf` 文件，读取配置信息（例如 `nameserver`, `search`, `options`），初始化 `__res_state` 结构体中的各个字段。
   - **在本文件中的作用:**  为当前线程的 DNS 解析器状态进行初始化配置。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`res_state.c` 中与 dynamic linker 相关的部分是使用了 `__attribute__((constructor))` 声明的 `__res_key_init` 函数。

**SO 布局样本:**

一个典型的 shared object (`.so`) 文件布局包含以下部分：

```
.text        # 存放代码段
.rodata      # 存放只读数据
.data        # 存放已初始化的全局变量和静态变量
.bss         # 存放未初始化的全局变量和静态变量
.dynamic     # 存放动态链接器需要的信息
.dynsym      # 动态符号表
.dynstr      # 动态字符串表
.rel.plt     # PLT 重定位表
.rel.dyn     # 数据段重定位表
.init_array  # 存放初始化函数指针数组
.fini_array  # 存放析构函数指针数组
...
```

**链接的处理过程:**

1. **编译阶段:** 编译器在编译 `res_state.c` 时，会将 `__res_key_init` 函数标记为构造函数。
2. **链接阶段:** 链接器在创建 shared object 文件时，会找到所有标记为构造函数的函数，并将它们的地址放入 `.init_array` 段中。
3. **加载时 (Runtime):** 当 dynamic linker 加载包含 `res_state.c` 的 shared object 文件时，它会执行 `.init_array` 段中所有函数指针指向的函数。
4. **`__res_key_init` 的执行:** 因此，在 shared object 被加载时，`__res_key_init` 函数会被 dynamic linker 自动调用。
5. **`pthread_key_create` 的调用:** `__res_key_init` 函数会调用 `pthread_key_create` 创建线程特定数据键 `_res_key`，并指定 `_res_thread_free` 作为析构函数。

**逻辑推理 (假设输入与输出):**

假设在一个多线程的 Android 应用中，有两个线程 A 和 B 同时发起 DNS 查询：

**线程 A:**

* **假设输入:**  需要查询域名 "www.example.com"
* **输出:**  通过 DNS 解析得到 "www.example.com" 对应的 IP 地址。

**线程 B:**

* **假设输入:** 需要查询域名 "api.example.com"
* **输出:**  通过 DNS 解析得到 "api.example.com" 对应的 IP 地址。

**推理过程:**

1. 当线程 A 首次调用需要 DNS 解析的函数时，`_res_thread_get()` 会被调用。由于线程 A 之前没有分配过 `_res_thread`，因此会分配一个新的 `_res_thread` 结构体，并调用 `res_ninit()` 进行初始化。
2. 线程 A 的 DNS 查询会使用其独立的 `__res_state` 结构体，其中包含了该线程的 DNS 配置信息。
3. 同样地，当线程 B 首次调用需要 DNS 解析的函数时，也会分配并初始化自己的 `_res_thread` 结构体。
4. 线程 B 的 DNS 查询会使用其独立的 `__res_state` 结构体，与线程 A 的状态互不影响。
5. 最终，线程 A 和 B 可以独立地完成 DNS 查询，获得各自域名对应的 IP 地址。

**涉及用户或者编程常见的使用错误，请举例说明:**

由于 `res_state.c` 中的函数主要是内部使用，用户或开发者通常不会直接调用它们。但是，与 DNS 解析相关的常见错误包括：

1. **网络配置错误:**  例如，`/etc/resolv.conf` 文件配置错误，导致无法找到 DNS 服务器或使用了错误的 DNS 服务器。这会影响 `res_ninit()` 的初始化过程。
2. **阻塞 DNS 查询:** 在主线程中进行同步 DNS 查询会导致应用无响应（ANR）。正确的做法是在后台线程执行 DNS 查询。
3. **不当的缓存处理:**  过度依赖 DNS 缓存可能导致无法及时获取最新的 IP 地址。
4. **内存泄漏 (理论上，但不太可能直接与此文件相关):**  虽然 `res_state.c` 负责资源的分配和释放，但如果在其他 DNS 相关代码中没有正确释放与 DNS 查询结果相关的内存，可能会导致内存泄漏。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `res_state.c` 的调用路径:**

1. **Java 代码发起网络请求:**  例如，使用 `java.net.URL`, `OkHttp`, `HttpURLConnection` 等类进行网络请求。
2. **Framework 层处理:**  Android Framework 的网络组件（例如 `ConnectivityManager`, `NetworkCapabilities`）会处理网络连接和地址解析。
3. **Native 代码调用:**  Framework 层最终会调用到 Native 代码，例如 `libnativehelper.so` 中的 JNI 函数。
4. **`getaddrinfo` 调用:**  Native 代码可能会调用 `getaddrinfo` 函数来进行地址解析。
5. **Bionic libc 中的 `getaddrinfo`:**  Android 的 `getaddrinfo` 实现位于 Bionic libc 中。
6. **`__res_get_state` 调用:**  Bionic libc 的 `getaddrinfo` 实现会调用 `__res_get_state()` 来获取当前线程的 DNS 解析器状态。

**NDK 到 `res_state.c` 的调用路径:**

1. **NDK 代码发起网络请求:** 使用 NDK 提供的 Socket API 或其他网络库进行网络请求。
2. **`getaddrinfo` 调用:** NDK 代码可以直接调用 Bionic libc 中的 `getaddrinfo` 函数。
3. **`__res_get_state` 调用:**  与 Framework 类似，`getaddrinfo` 内部会调用 `__res_get_state()`。

**Frida Hook 示例:**

我们可以使用 Frida Hook `__res_get_state` 函数来观察其调用情况：

```javascript
if (Process.platform === 'android') {
  const res_get_state = Module.findExportByName("libc.so", "__res_get_state");
  if (res_get_state) {
    Interceptor.attach(res_get_state, {
      onEnter: function (args) {
        console.log("[+] __res_get_state called");
        console.log("   Thread ID:", Process.getCurrentThreadId());
        // 可以进一步检查调用栈等信息
        // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n"));
      },
      onLeave: function (retval) {
        console.log("[+] __res_get_state returned:", retval);
      }
    });
  } else {
    console.log("[-] __res_get_state not found");
  }
} else {
  console.log("[!] This script is designed for Android.");
}
```

**使用步骤:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_res_state.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_res_state.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_res_state.js
   ```
3. 当目标应用执行需要 DNS 解析的操作时，Frida 会拦截 `__res_get_state` 函数的调用，并在控制台上输出相关信息，包括线程 ID 和返回值。

**Frida Hook 其他相关函数示例:**

你也可以 Hook 其他相关函数，例如 `res_ninit`:

```javascript
if (Process.platform === 'android') {
  const res_ninit = Module.findExportByName("libc.so", "res_ninit");
  if (res_ninit) {
    Interceptor.attach(res_ninit, {
      onEnter: function (args) {
        console.log("[+] res_ninit called");
        console.log("   res_state address:", args[0]);
      },
      onLeave: function (retval) {
        console.log("[+] res_ninit returned:", retval);
      }
    });
  } else {
    console.log("[-] res_ninit not found");
  }
} else {
  console.log("[!] This script is designed for Android.");
}
```

通过这些 Frida Hook 示例，你可以深入了解 Android 系统在进行 DNS 解析时，如何一步步调用到 `res_state.c` 中的相关函数，以及如何管理 DNS 解析器的状态。

希望以上分析能够帮助你理解 `bionic/libc/dns/resolv/res_state.c` 的功能和作用。

Prompt: 
```
这是目录为bionic/libc/dns/resolv/res_state.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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
#include <sys/cdefs.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include "resolv_private.h"
#include "resolv_cache.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>


/* Set to 1 to enable debug traces */
#define DEBUG 0

#if DEBUG
#  include <async_safe/log.h>
#  include <unistd.h>  /* for gettid() */
#  define D(...) async_safe_format_log(ANDROID_LOG_DEBUG,"libc", __VA_ARGS__)
#else
#  define D(...)  do{}while(0)
#endif

typedef struct {
    int                  _h_errno;
    // TODO: Have one __res_state per network so we don't have to repopulate frequently.
    struct __res_state  _nres[1];
    struct res_static   _rstatic[1];
} _res_thread;

static _res_thread*
_res_thread_alloc(void)
{
    _res_thread*  rt = calloc(1, sizeof(*rt));

    if (rt) {
        rt->_h_errno = 0;
        memset(rt->_rstatic, 0, sizeof rt->_rstatic);
    }
    return rt;
}

static void
_res_static_done(struct res_static* rs)
{
    /* fortunately, there is nothing to do here, since the
     * points in h_addr_ptrs and host_aliases should all
     * point to 'hostbuf'
     */
    if (rs->hostf) {  /* should not happen in theory, but just be safe */
        fclose(rs->hostf);
        rs->hostf = NULL;
    }
    free(rs->servent.s_aliases);
}

static void
_res_thread_free( void*  _rt )
{
    _res_thread*  rt = _rt;

    D("%s: rt=%p for thread=%d", __FUNCTION__, rt, gettid());

    _res_static_done(rt->_rstatic);
    res_ndestroy(rt->_nres);
    free(rt);
}

static pthread_key_t _res_key;

__attribute__((constructor)) static void __res_key_init() {
    pthread_key_create(&_res_key, _res_thread_free);
}

static _res_thread*
_res_thread_get(void)
{
    _res_thread*  rt;
    rt = pthread_getspecific( _res_key );

    if (rt != NULL) {
        return rt;
    }

    /* It is the first time this function is called in this thread,
     * we need to create a new thread-specific DNS resolver state. */
    rt = _res_thread_alloc();
    if (rt == NULL) {
        return NULL;
    }
    pthread_setspecific( _res_key, rt );
    D("%s: tid=%d Created new DNS state rt=%p",
      __FUNCTION__, gettid(), rt);

    /* Reset the state, note that res_ninit() can now properly reset
     * an existing state without leaking memory.
     */
    D("%s: tid=%d, rt=%p, setting DNS state (options RES_INIT=%d)",
      __FUNCTION__, gettid(), rt, (rt->_nres->options & RES_INIT) != 0);
    if ( res_ninit( rt->_nres ) < 0 ) {
        /* This should not happen */
        D("%s: tid=%d rt=%p, woot, res_ninit() returned < 0",
          __FUNCTION__, gettid(), rt);
        _res_thread_free(rt);
        pthread_setspecific( _res_key, NULL );
        return NULL;
    }
    return rt;
}

int*
__get_h_errno(void)
{
    _res_thread*  rt    = _res_thread_get();
    static int    panic = NETDB_INTERNAL;

    return rt ? &rt->_h_errno : &panic;
}

res_state
__res_get_state(void)
{
    _res_thread*  rt = _res_thread_get();

    return rt ? rt->_nres : NULL;
}

void
__res_put_state(res_state res __unused)
{
    /* nothing to do */
}

struct res_static* __res_get_static(void) {
    _res_thread*  rt = _res_thread_get();

    return rt ? rt->_rstatic : NULL;
}

"""

```