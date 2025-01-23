Response:
Let's break down the thought process for analyzing this `res_init.c` file. The request is quite comprehensive, so a structured approach is needed.

**1. Understanding the Core Function:**

The filename `res_init.c` immediately suggests that this file deals with the initialization of the resolver library. The comments at the beginning confirm this, mentioning "Resolver state default settings." The primary function is likely to set up the internal state required for DNS lookups.

**2. Identifying Key Functions and Data Structures:**

Scanning the code reveals the main entry point: `res_ninit`. The presence of `__res_vinit` suggests an internal initialization function. Other functions like `res_setoptions`, `res_setservers`, and `res_getservers` hint at configuration and server management. The `res_state` structure is clearly central to holding the resolver's state.

**3. Analyzing `res_ninit` and `__res_vinit`:**

* **`res_ninit`:** The code is simple, calling `__res_vinit`. This indicates `res_ninit` is a public interface that delegates to the internal initialization.

* **`__res_vinit`:**  This function is the workhorse. The comments and code reveal the following steps:
    * **Initialization of `res_state`:** Setting default values for timeouts, retries, options, and a random ID.
    * **Default Nameserver:** Setting a default nameserver (loopback or `INADDR_ANY`). The comment about the historical reasons for this is important.
    * **Reading Configuration:**  The code attempts to read `/etc/resolv.conf` (though this is skipped on Android as noted by `#ifndef ANDROID_CHANGES`). This is crucial for understanding how DNS settings are configured.
    * **Environment Variables:** Checking `LOCALDOMAIN` and `RES_OPTIONS` for further configuration. This shows how users can override defaults.
    * **Default Domain:** Determining the default domain name, either from `LOCALDOMAIN`, `/etc/resolv.conf`, or the system's hostname.
    * **Search List:** Populating the search list for domain name resolution.
    * **Setting Options:** Processing options from `/etc/resolv.conf` and the environment.
    * **Final Initialization:** Setting the `RES_INIT` flag.

**4. Analyzing Supporting Functions:**

* **`res_setoptions`:**  This function parses option strings and updates the `res_state`. Understanding the available options (like `ndots`, `timeout`, `debug`) is important.
* **`res_setservers` and `res_getservers`:**  These functions manage the list of DNS servers. They handle both IPv4 and IPv6 addresses.
* **`res_nclose` and `res_ndestroy`:** These deal with closing sockets and freeing resources associated with the resolver state.

**5. Considering Android-Specific Aspects:**

The `#ifdef ANDROID_CHANGES` blocks are vital. The key takeaways are:

* **Ignoring `/etc/resolv.conf`:** Android doesn't rely on this standard file.
* **`res_setnetcontext`:** This Android-specific function is used to configure the resolver based on network context (like the network ID and DNS mark). This is how Android manages DNS on a per-network basis.

**6. Dynamic Linking Considerations:**

While this specific file doesn't directly perform dynamic linking, it *uses* functions and data structures that are part of `libc`, which *is* dynamically linked. The `res_state` structure and functions like `malloc`, `memset`, `strcpy`, `getenv`, `fopen`, etc., are all part of `libc`. The dynamic linker is responsible for loading `libc.so` and resolving these symbols when a program uses resolver functions.

**7. User Errors and Examples:**

Thinking about common mistakes helps illustrate the practical implications:

* **Incorrect `/etc/resolv.conf`:** Typographical errors in nameserver addresses or domain names.
* **Missing `/etc/resolv.conf`:** On non-Android systems, this can lead to resolution failures.
* **Incorrect environment variables:**  Setting `LOCALDOMAIN` or `RES_OPTIONS` incorrectly.

**8. Frida Hooking Strategy:**

To trace execution, hooking the entry points like `res_ninit` and `__res_vinit` is logical. Also, hooking Android-specific functions like `res_setnetcontext` provides insight into how Android configures the resolver.

**9. Structuring the Response:**

Finally, the information needs to be organized clearly according to the prompt's requirements:

* **Functions:** List the key functions and their purpose.
* **Android Relevance:** Explain how the code relates to Android's DNS configuration, particularly the deviation from standard Linux practices.
* **`libc` Function Details:** Describe the standard `libc` functions used.
* **Dynamic Linking:** Explain the role of the dynamic linker in making `libc` functionality available.
* **Logic and I/O:** Provide simple examples of input and output.
* **User Errors:** Illustrate common mistakes.
* **Android Framework/NDK Integration:** Explain how Android apps and NDK code use these resolver functions.
* **Frida Hooking:** Provide concrete examples of Frida scripts.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Focusing too much on the BSD origins of the code. Realization: The prompt specifically asks about Android, so prioritize the Android-specific changes.
* **Considering dynamic linking:** Initially, not explicitly thinking about *how* the functions are made available. Correction: Emphasize that these are `libc` functions and the dynamic linker's role.
* **Frida examples:**  Initially, thinking too abstractly about hooking. Correction: Provide specific function names and basic hook structure for clarity.
* **User error examples:** Ensuring the examples are practical and relate directly to the functions being discussed.

By following these steps, the comprehensive analysis of `res_init.c` can be constructed, addressing all aspects of the prompt.
好的，让我们来详细分析一下 `bionic/libc/dns/resolv/res_init.c` 这个文件。

**功能概述:**

`res_init.c` 文件的主要功能是初始化 DNS 解析器（resolver）的状态。它负责读取 DNS 相关的配置信息，例如域名服务器的地址、默认搜索域等，并将这些信息存储在一个全局或线程局部的结构体中，供其他 DNS 解析函数使用。具体来说，它的功能包括：

1. **读取 `/etc/resolv.conf` 文件（在非 Android 系统上）：**  解析该文件以获取 DNS 服务器地址、默认域名、搜索域等配置信息。
2. **读取环境变量：**  检查 `LOCALDOMAIN` 和 `RES_OPTIONS` 环境变量，以允许用户覆盖或修改 DNS 设置。
3. **设置默认值：**  如果配置文件或环境变量中没有提供某些信息，则使用默认值。例如，默认的域名服务器地址通常是本地回环地址（127.0.0.1 或 ::1）。
4. **构建搜索域列表：**  根据配置信息，构建一个用于域名补全的搜索域列表。
5. **初始化解析器状态结构体 `res_state`：**  将读取到的配置信息和默认值存储到 `res_state` 结构体中。这个结构体包含了进行 DNS 查询所需的所有状态信息。
6. **Android 特有功能 (通过 `#ifdef ANDROID_CHANGES` 标识)：**
    * **忽略 `/etc/resolv.conf`：** Android 系统通常不依赖传统的 `/etc/resolv.conf` 文件。
    * **使用 `res_setnetcontext` 函数：** 允许根据网络上下文（例如，特定的网络接口或 VPN 连接）配置 DNS 服务器。这使得 Android 可以为不同的网络连接使用不同的 DNS 设置。

**与 Android 功能的关系及举例说明:**

`res_init.c` 是 Android DNS 解析功能的基础。当应用程序需要将域名解析为 IP 地址时，它会使用 `libc` 提供的 DNS 解析函数（例如 `getaddrinfo`、`gethostbyname` 等）。这些函数在内部会使用 `res_state` 中存储的配置信息。

**举例说明:**

假设一个 Android 应用程序尝试连接到 `www.google.com`。

1. 应用程序调用 `getaddrinfo("www.google.com", "80", NULL, &hints, &res)`。
2. `getaddrinfo` 函数内部会检查解析器是否已经初始化。如果未初始化，它会调用 `res_ninit` 或 `__res_vinit`。
3. 在 Android 上，`res_ninit` 或 `__res_vinit` 不会读取 `/etc/resolv.conf`。
4. 相反，Android 系统可能会在应用程序启动时或网络状态改变时调用 `res_setnetcontext` 来配置 DNS 设置。`res_setnetcontext` 会根据当前的活动网络连接（例如，Wi-Fi 或移动数据）设置 DNS 服务器地址和标记等信息。
5. `res_init.c` 中的代码负责处理这些配置，并将服务器地址存储在 `res_state` 结构体中。
6. 之后，`getaddrinfo` 使用 `res_state` 中的 DNS 服务器地址向 DNS 服务器发送查询请求，最终将 `www.google.com` 解析为 IP 地址。

**详细解释 libc 函数的实现:**

以下是 `res_init.c` 中使用的一些关键 `libc` 函数及其实现方式的简要解释：

* **`fopen(const char *pathname, const char *mode)`:**
    * **功能:** 打开由 `pathname` 指定的文件。`mode` 参数指定打开文件的模式（例如 "r" 表示只读）。
    * **实现:**  `fopen` 是一个标准 C 库函数，其实现涉及到系统调用，例如 `open`。它会分配一个 `FILE` 结构体来表示打开的文件，并初始化相关的缓冲区和文件描述符。
* **`fgets(char *s, int size, FILE *stream)`:**
    * **功能:** 从由 `stream` 指定的文件流中读取最多 `size - 1` 个字符到 `s` 指向的缓冲区。读取到换行符或文件结尾时停止。
    * **实现:** `fgets` 内部会调用底层的读取系统调用（例如 `read`）来从文件中读取数据，并将其存储到提供的缓冲区中。它会处理缓冲区溢出，并在字符串末尾添加空字符 `\0`。
* **`strncmp(const char *s1, const char *s2, size_t n)`:**
    * **功能:** 比较字符串 `s1` 的前 `n` 个字符和字符串 `s2` 的前 `n` 个字符。
    * **实现:** `strncmp` 逐个比较两个字符串的字符，直到遇到不同的字符、到达 `n` 个字符或到达字符串的末尾。它返回一个整数，表示两个字符串的比较结果。
* **`strncpy(char *dest, const char *src, size_t n)`:**
    * **功能:** 将字符串 `src` 的前 `n` 个字符复制到 `dest` 指向的缓冲区。
    * **实现:** `strncpy` 逐个字符地将 `src` 的内容复制到 `dest`。如果 `src` 的长度小于 `n`，则 `dest` 的剩余部分会用空字符填充。如果 `src` 的长度大于或等于 `n`，则 `dest` 不会以空字符结尾。
* **`strchr(const char *s, int c)`:**
    * **功能:** 在字符串 `s` 中查找字符 `c` 第一次出现的位置。
    * **实现:** `strchr` 从字符串的开头开始遍历，直到找到匹配的字符或到达字符串的末尾。如果找到，则返回指向该字符的指针；否则返回 `NULL`。
* **`strpbrk(const char *s, const char *accept)`:**
    * **功能:** 在字符串 `s` 中查找 `accept` 中的任何字符第一次出现的位置。
    * **实现:** `strpbrk` 遍历字符串 `s`，并对每个字符检查它是否在字符串 `accept` 中。如果找到匹配的字符，则返回指向该字符的指针；否则返回 `NULL`。
* **`atoi(const char *nptr)`:**
    * **功能:** 将字符串 `nptr` 转换为整数。
    * **实现:** `atoi` 从字符串的开头开始解析数字字符，直到遇到非数字字符或字符串末尾。它将解析到的数字字符转换为整数并返回。
* **`getenv(const char *name)`:**
    * **功能:** 获取名为 `name` 的环境变量的值。
    * **实现:** `getenv` 通常会访问一个存储环境变量的全局数据结构（例如，一个哈希表）。它在数据结构中查找与 `name` 匹配的键，并返回对应的值。
* **`gethostname(char *name, size_t len)`:**
    * **功能:** 获取当前主机名。
    * **实现:** `gethostname` 会调用底层的系统调用（例如 `uname`）来获取主机名，并将其复制到提供的缓冲区中。
* **`malloc(size_t size)`:**
    * **功能:** 分配指定大小的内存块。
    * **实现:** `malloc` 是一个动态内存分配函数。它会从堆中找到一块足够大的空闲内存块，并返回指向该内存块的指针。`malloc` 的实现涉及到维护堆的元数据，以便跟踪已分配和空闲的内存块。
* **`memset(void *s, int c, size_t n)`:**
    * **功能:** 将 `s` 指向的内存块的前 `n` 个字节设置为值 `c`。
    * **实现:** `memset` 会高效地将指定的字节值写入到内存块中。它通常会使用优化的汇编指令来实现。
* **`strcpy(char *dest, const char *src)`:**
    * **功能:** 将字符串 `src` 复制到 `dest` 指向的缓冲区（包括终止的空字符）。
    * **实现:** `strcpy` 逐个字符地将 `src` 的内容复制到 `dest`，直到遇到 `src` 的终止空字符。
* **`close(int fd)`:**
    * **功能:** 关闭一个文件描述符。
    * **实现:** `close` 是一个系统调用，它会释放与文件描述符关联的系统资源（例如，文件表项）。
* **`free(void *ptr)`:**
    * **功能:** 释放由 `malloc` 或相关函数分配的内存块。
    * **实现:** `free` 将指定的内存块标记为空闲，并将其返回到堆中，以便后续的内存分配使用。

**涉及 dynamic linker 的功能:**

`res_init.c` 本身并不直接执行动态链接的操作。但是，它所处的 `libc.so` 库是由 dynamic linker 加载到进程地址空间的。当应用程序调用 `res_ninit` 或其他 `libc` 中的函数时，dynamic linker 负责找到这些函数的实现，并将其链接到应用程序。

**so 布局样本:**

假设一个简化的 Android 进程内存布局，`libc.so` 可能被加载到以下地址范围：

```
...
7000000000 - 70000001000 r-xp    libc.so  (代码段)
70000001000 - 70000001100 r--p    libc.so  (只读数据段)
70000001100 - 70000001200 rw-p    libc.so  (可读写数据段)
...
```

* **代码段 (r-xp):** 包含 `res_ninit`、`__res_vinit` 等函数的机器码指令。
* **只读数据段 (r--p):** 包含字符串常量和其他只读数据。
* **可读写数据段 (rw-p):** 包含全局变量，例如 `res_state` 结构体的实例（如果它是全局的，或者线程局部存储）。

**链接的处理过程:**

1. **应用程序启动:** 当 Android 启动一个应用程序时，zygote 进程会 fork 出一个新的进程。
2. **加载器介入:** 内核会启动 dynamic linker（通常是 `/system/bin/linker64` 或 `/system/bin/linker`）。
3. **加载共享库:** dynamic linker 读取应用程序的可执行文件头，找到依赖的共享库列表，其中包括 `libc.so`。
4. **查找共享库:** dynamic linker 在预定义的路径中查找 `libc.so`。
5. **加载到内存:** dynamic linker 将 `libc.so` 的代码段、数据段等加载到进程的地址空间中的某个区域（如上面的例子）。
6. **符号解析:** dynamic linker 遍历应用程序的“延迟绑定”或“立即绑定”的符号引用。当应用程序第一次调用 `res_ninit` 时，dynamic linker 会在 `libc.so` 的符号表（包含了库中导出的函数和变量的名称和地址）中查找 `res_ninit` 的地址。
7. **重定位:** dynamic linker 使用重定位表来修正代码段和数据段中的地址引用，使其指向正确的内存位置。例如，如果 `res_ninit` 中调用了其他 `libc` 函数，这些调用指令中的目标地址需要被修正。
8. **绑定:** dynamic linker 将应用程序中对 `res_ninit` 的调用指令的目标地址更新为 `libc.so` 中 `res_ninit` 函数的实际地址。
9. **执行:** 现在，当应用程序调用 `res_ninit` 时，控制流会跳转到 `libc.so` 中 `res_ninit` 函数的实现。

**逻辑推理、假设输入与输出:**

假设我们有一个简单的 Android 应用，它调用 `getaddrinfo("example.com", "80", NULL, &hints, &res)`。

**假设输入:**

* 当前网络连接的 DNS 服务器地址由 Android 系统设置为 `8.8.8.8` 和 `8.8.4.4` (通过 `res_setnetcontext`)。
* 应用程序没有设置任何环境变量来覆盖 DNS 设置。
* 系统没有 `/etc/resolv.conf` 文件（或其内容被忽略）。

**逻辑推理:**

1. 当 `getaddrinfo` 首次被调用时，会触发 `res_ninit` 或 `__res_vinit` 的调用。
2. 由于是 Android 系统，`/etc/resolv.conf` 不会被读取。
3. `res_state` 结构体会使用默认值进行初始化，但关键的 DNS 服务器地址会被 `res_setnetcontext` 设置的值覆盖。
4. `res_state->nscount` 将设置为 DNS 服务器的数量 (例如 2)。
5. `res_state->nsaddr_list` 将包含 `8.8.8.8` 和 `8.8.4.4` 的 `sockaddr_in` 结构体。
6. 后续的 DNS 查询将使用这些服务器地址。

**假设输出 (并非函数返回值，而是 `res_state` 的状态):**

* `statp->nscount = 2;`
* `statp->nsaddr_list[0].sin_family = AF_INET;`
* `statp->nsaddr_list[0].sin_addr.s_addr = inet_addr("8.8.8.8");`
* `statp->nsaddr_list[1].sin_family = AF_INET;`
* `statp->nsaddr_list[1].sin_addr.s_addr = inet_addr("8.8.4.4");`
* 其他字段可能包含默认值。

**用户或编程常见的使用错误:**

1. **假设 `/etc/resolv.conf` 起作用 (Android):**  在 Android 开发中，依赖 `/etc/resolv.conf` 来配置 DNS 是错误的。应该使用 Android 提供的 API 或系统设置来管理网络配置。
2. **错误地修改 `res_state` 结构体:**  `res_state` 是内部状态，直接修改它可能会导致不可预测的行为。应该使用 `libc` 提供的 API 函数（例如 `res_setservers`) 来修改 DNS 配置。
3. **忘记处理 `getaddrinfo` 的错误:**  DNS 解析可能失败，应用程序应该检查 `getaddrinfo` 的返回值，并处理可能的错误情况（例如，网络连接问题、域名不存在等）。
4. **在多线程环境中使用全局 `res_state` 而不加锁:**  虽然 `res_state` 可能是线程局部的，但如果存在全局版本，在多线程环境中并发访问和修改它可能会导致数据竞争。

**Android framework 或 NDK 如何到达这里:**

1. **Java Framework:**
   * 当一个 Java 应用程序需要进行网络操作时，例如使用 `java.net.InetAddress.getByName("example.com")`，Java Framework 会调用底层的 Native 代码。
   * `InetAddress` 类的方法最终会调用到 Android Runtime (ART) 中的 JNI (Java Native Interface) 代码。
   * 这些 JNI 代码会调用 Bionic `libc.so` 中的 `getaddrinfo` 函数。
   * `getaddrinfo` 内部会触发 `res_ninit` 或 `__res_vinit` 的调用，从而执行 `res_init.c` 中的代码。

2. **NDK (Native Development Kit):**
   * 如果开发者使用 NDK 编写 C/C++ 代码，他们可以直接调用 `libc.so` 中的 DNS 解析函数，例如 `getaddrinfo` 或 `gethostbyname`。
   * 当这些函数被调用时，它们会按照上述流程初始化解析器状态。

**Frida hook 示例调试步骤:**

可以使用 Frida hook `res_ninit` 或 `__res_vinit` 函数，以观察其执行过程和 `res_state` 结构体的变化。

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__res_vinit"), {
    onEnter: function(args) {
        console.log("[*] __res_vinit called");
        console.log("    statp: " + args[0]);
        console.log("    preinit: " + args[1]);
    },
    onLeave: function(retval) {
        console.log("[*] __res_vinit returned: " + retval);
        // 可以进一步读取 res_state 结构体的内容
        var res_state_ptr = this.context.r0; // 假设返回值在 r0 寄存器
        if (retval == 0 && res_state_ptr != 0) {
            console.log("[*] Reading res_state...");
            // 示例：读取 nscount
            var nscount = Memory.readU32(ptr(res_state_ptr).add(offsetof_res_state_nscount));
            console.log("    nscount: " + nscount);
            // 可以继续读取其他字段
        }
    }
});

// 假设你已经定义了 res_state 结构体的布局
const offsetof_res_state_nscount = 16; // 需要根据实际结构体定义调整

"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida 脚本:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 设备上正在运行的目标应用程序。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "__res_vinit"), ...)`:**  Hook `libc.so` 中的 `__res_vinit` 函数。
3. **`onEnter`:** 在 `__res_vinit` 函数被调用时执行。打印函数的参数。
4. **`onLeave`:** 在 `__res_vinit` 函数返回时执行。打印返回值，并尝试读取 `res_state` 结构体中的 `nscount` 字段。
5. **`offsetof_res_state_nscount`:**  你需要根据 `bionic/libc/include/resolv.h` 或 `bionic/libc/dns/resolv/resolv_private.h` 中 `res_state` 结构体的定义，确定 `nscount` 字段的偏移量。

通过运行这个 Frida 脚本，你可以观察到 `__res_vinit` 何时被调用，查看传入的参数，以及读取初始化后的 `res_state` 结构体的一些关键信息，例如 DNS 服务器的数量。你可以根据需要 hook 其他函数或读取 `res_state` 的其他字段，以更深入地了解 DNS 解析的初始化过程。

希望这个详细的分析对您有所帮助！

### 提示词
```
这是目录为bionic/libc/dns/resolv/res_init.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: res_init.c,v 1.8 2006/03/19 03:10:08 christos Exp $	*/

/*
 * Copyright (c) 1985, 1989, 1993
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
static const char sccsid[] = "@(#)res_init.c	8.1 (Berkeley) 6/7/93";
static const char rcsid[] = "Id: res_init.c,v 1.9.2.5.4.2 2004/03/16 12:34:18 marka Exp";
#else
__RCSID("$NetBSD: res_init.c,v 1.8 2006/03/19 03:10:08 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */



#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#ifdef ANDROID_CHANGES
#include <errno.h>
#include <fcntl.h>
#endif /* ANDROID_CHANGES */

/* ensure that sockaddr_in6 and IN6ADDR_ANY_INIT are declared / defined */
#ifdef ANDROID_CHANGES
#include "resolv_netid.h"
#include "resolv_private.h"
#else
#include <resolv.h>
#endif

#include "res_private.h"

/* Options.  Should all be left alone. */
#ifndef DEBUG
#define DEBUG
#endif

static void res_setoptions __P((res_state, const char *, const char *));

#ifdef RESOLVSORT
static const char sort_mask[] = "/&";
#define ISSORTMASK(ch) (strchr(sort_mask, ch) != NULL)
static uint32_t net_mask(struct in_addr);
#endif

#if !defined(isascii)	/* XXX - could be a function */
# define isascii(c) (!(c & 0200))
#endif

/*
 * Resolver state default settings.
 */

/*
 * Set up default settings.  If the configuration file exist, the values
 * there will have precedence.  Otherwise, the server address is set to
 * INADDR_ANY and the default domain name comes from the gethostname().
 *
 * An interrim version of this code (BIND 4.9, pre-4.4BSD) used 127.0.0.1
 * rather than INADDR_ANY ("0.0.0.0") as the default name server address
 * since it was noted that INADDR_ANY actually meant ``the first interface
 * you "ifconfig"'d at boot time'' and if this was a SLIP or PPP interface,
 * it had to be "up" in order for you to reach your own name server.  It
 * was later decided that since the recommended practice is to always
 * install local static routes through 127.0.0.1 for all your network
 * interfaces, that we could solve this problem without a code change.
 *
 * The configuration file should always be used, since it is the only way
 * to specify a default domain.  If you are running a server on your local
 * machine, you should say "nameserver 0.0.0.0" or "nameserver 127.0.0.1"
 * in the configuration file.
 *
 * Return 0 if completes successfully, -1 on error
 */
int
res_ninit(res_state statp) {
	extern int __res_vinit(res_state, int);

	return (__res_vinit(statp, 0));
}

/* This function has to be reachable by res_data.c but not publicly. */
int
__res_vinit(res_state statp, int preinit) {
#if !defined(__BIONIC__)
	register FILE *fp;
#endif
	register char *cp, **pp;
#if !defined(__BIONIC__)
	register int n;
#endif
	char buf[BUFSIZ];
	int nserv = 0;    /* number of nameserver records read from file */
#if !defined(__BIONIC__)
	int haveenv = 0;
#endif
	int havesearch = 0;
#ifdef RESOLVSORT
	int nsort = 0;
#endif
#if !defined(__BIONIC__)
	char *net;
#endif
	int dots;
	union res_sockaddr_union u[2];

        if ((statp->options & RES_INIT) != 0U)
                res_ndestroy(statp);

	if (!preinit) {
		statp->netid = NETID_UNSET;
		statp->retrans = RES_TIMEOUT;
		statp->retry = RES_DFLRETRY;
		statp->options = RES_DEFAULT;
		statp->id = res_randomid();
		statp->_mark = MARK_UNSET;
	}

	memset(u, 0, sizeof(u));
#ifdef USELOOPBACK
	u[nserv].sin.sin_addr = inet_makeaddr(IN_LOOPBACKNET, 1);
#else
	u[nserv].sin.sin_addr.s_addr = INADDR_ANY;
#endif
	u[nserv].sin.sin_family = AF_INET;
	u[nserv].sin.sin_port = htons(NAMESERVER_PORT);
#ifdef HAVE_SA_LEN
	u[nserv].sin.sin_len = sizeof(struct sockaddr_in);
#endif
	nserv++;
#ifdef HAS_INET6_STRUCTS
#ifdef USELOOPBACK
	u[nserv].sin6.sin6_addr = in6addr_loopback;
#else
	u[nserv].sin6.sin6_addr = in6addr_any;
#endif
	u[nserv].sin6.sin6_family = AF_INET6;
	u[nserv].sin6.sin6_port = htons(NAMESERVER_PORT);
#ifdef HAVE_SA_LEN
	u[nserv].sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	nserv++;
#endif
	statp->nscount = 0;
	statp->ndots = 1;
	statp->pfcode = 0;
	statp->_vcsock = -1;
	statp->_flags = 0;
	statp->qhook = NULL;
	statp->rhook = NULL;
	statp->_u._ext.nscount = 0;
	statp->_u._ext.ext = malloc(sizeof(*statp->_u._ext.ext));
	if (statp->_u._ext.ext != NULL) {
	        memset(statp->_u._ext.ext, 0, sizeof(*statp->_u._ext.ext));
		statp->_u._ext.ext->nsaddrs[0].sin = statp->nsaddr;
		strcpy(statp->_u._ext.ext->nsuffix, "ip6.arpa");
		strcpy(statp->_u._ext.ext->nsuffix2, "ip6.int");
	}
	statp->nsort = 0;
	res_setservers(statp, u, nserv);

#if defined(__BIONIC__)
	/* Ignore the environment. */
#else
	/* Allow user to override the local domain definition */
	if ((cp = getenv("LOCALDOMAIN")) != NULL) {
		(void)strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
		statp->defdname[sizeof(statp->defdname) - 1] = '\0';
		haveenv++;

		/*
		 * Set search list to be blank-separated strings
		 * from rest of env value.  Permits users of LOCALDOMAIN
		 * to still have a search list, and anyone to set the
		 * one that they want to use as an individual (even more
		 * important now that the rfc1535 stuff restricts searches)
		 */
		cp = statp->defdname;
		pp = statp->dnsrch;
		*pp++ = cp;
		for (n = 0; *cp && pp < statp->dnsrch + MAXDNSRCH; cp++) {
			if (*cp == '\n')	/* silly backwards compat */
				break;
			else if (*cp == ' ' || *cp == '\t') {
				*cp = 0;
				n = 1;
			} else if (n) {
				*pp++ = cp;
				n = 0;
				havesearch = 1;
			}
		}
		/* null terminate last domain if there are excess */
		while (*cp != '\0' && *cp != ' ' && *cp != '\t' && *cp != '\n')
			cp++;
		*cp = '\0';
		*pp++ = 0;
	}
	if (nserv > 0)
		statp->nscount = nserv;
#endif

#ifndef ANDROID_CHANGES /* !ANDROID_CHANGES - IGNORE resolv.conf in Android */
#define	MATCH(line, name) \
	(!strncmp(line, name, sizeof(name) - 1) && \
	(line[sizeof(name) - 1] == ' ' || \
	 line[sizeof(name) - 1] == '\t'))

	nserv = 0;
	if ((fp = fopen(_PATH_RESCONF, "re")) != NULL) {
	    /* read the config file */
	    while (fgets(buf, sizeof(buf), fp) != NULL) {
		/* skip comments */
		if (*buf == ';' || *buf == '#')
			continue;
		/* read default domain name */
		if (MATCH(buf, "domain")) {
		    if (haveenv)	/* skip if have from environ */
			    continue;
		    cp = buf + sizeof("domain") - 1;
		    while (*cp == ' ' || *cp == '\t')
			    cp++;
		    if ((*cp == '\0') || (*cp == '\n'))
			    continue;
		    strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
		    statp->defdname[sizeof(statp->defdname) - 1] = '\0';
		    if ((cp = strpbrk(statp->defdname, " \t\n")) != NULL)
			    *cp = '\0';
		    havesearch = 0;
		    continue;
		}
		/* set search list */
		if (MATCH(buf, "search")) {
		    if (haveenv)	/* skip if have from environ */
			    continue;
		    cp = buf + sizeof("search") - 1;
		    while (*cp == ' ' || *cp == '\t')
			    cp++;
		    if ((*cp == '\0') || (*cp == '\n'))
			    continue;
		    strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
		    statp->defdname[sizeof(statp->defdname) - 1] = '\0';
		    if ((cp = strchr(statp->defdname, '\n')) != NULL)
			    *cp = '\0';
		    /*
		     * Set search list to be blank-separated strings
		     * on rest of line.
		     */
		    cp = statp->defdname;
		    pp = statp->dnsrch;
		    *pp++ = cp;
		    for (n = 0; *cp && pp < statp->dnsrch + MAXDNSRCH; cp++) {
			    if (*cp == ' ' || *cp == '\t') {
				    *cp = 0;
				    n = 1;
			    } else if (n) {
				    *pp++ = cp;
				    n = 0;
			    }
		    }
		    /* null terminate last domain if there are excess */
		    while (*cp != '\0' && *cp != ' ' && *cp != '\t')
			    cp++;
		    *cp = '\0';
		    *pp++ = 0;
		    havesearch = 1;
		    continue;
		}
		/* read nameservers to query */
		if (MATCH(buf, "nameserver") && nserv < MAXNS) {
		    struct addrinfo hints, *ai;
		    char sbuf[NI_MAXSERV];
		    const size_t minsiz =
		        sizeof(statp->_u._ext.ext->nsaddrs[0]);

		    cp = buf + sizeof("nameserver") - 1;
		    while (*cp == ' ' || *cp == '\t')
			cp++;
		    cp[strcspn(cp, ";# \t\n")] = '\0';
		    if ((*cp != '\0') && (*cp != '\n')) {
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = PF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
			hints.ai_flags = AI_NUMERICHOST;
			sprintf(sbuf, "%u", NAMESERVER_PORT);
			if (getaddrinfo(cp, sbuf, &hints, &ai) == 0 &&
			    ai->ai_addrlen <= minsiz) {
			    if (statp->_u._ext.ext != NULL) {
				memcpy(&statp->_u._ext.ext->nsaddrs[nserv],
				    ai->ai_addr, ai->ai_addrlen);
			    }
			    if (ai->ai_addrlen <=
			        sizeof(statp->nsaddr_list[nserv])) {
				memcpy(&statp->nsaddr_list[nserv],
				    ai->ai_addr, ai->ai_addrlen);
			    } else
				statp->nsaddr_list[nserv].sin_family = 0;
			    freeaddrinfo(ai);
			    nserv++;
			}
		    }
		    continue;
		}
		if (MATCH(buf, "sortlist")) {
		    struct in_addr a;

		    cp = buf + sizeof("sortlist") - 1;
		    while (nsort < MAXRESOLVSORT) {
			while (*cp == ' ' || *cp == '\t')
			    cp++;
			if (*cp == '\0' || *cp == '\n' || *cp == ';')
			    break;
			net = cp;
			while (*cp && !ISSORTMASK(*cp) && *cp != ';' &&
			       isascii(*cp) && !isspace((unsigned char)*cp))
				cp++;
			n = *cp;
			*cp = 0;
			if (inet_aton(net, &a)) {
			    statp->sort_list[nsort].addr = a;
			    if (ISSORTMASK(n)) {
				*cp++ = n;
				net = cp;
				while (*cp && *cp != ';' &&
					isascii(*cp) &&
					!isspace((unsigned char)*cp))
				    cp++;
				n = *cp;
				*cp = 0;
				if (inet_aton(net, &a)) {
				    statp->sort_list[nsort].mask = a.s_addr;
				} else {
				    statp->sort_list[nsort].mask =
					net_mask(statp->sort_list[nsort].addr);
				}
			    } else {
				statp->sort_list[nsort].mask =
				    net_mask(statp->sort_list[nsort].addr);
			    }
			    nsort++;
			}
			*cp = n;
		    }
		    continue;
		}
		if (MATCH(buf, "options")) {
		    res_setoptions(statp, buf + sizeof("options") - 1, "conf");
		    continue;
		}
	    }
	    if (nserv > 0)
		statp->nscount = nserv;
	    statp->nsort = nsort;
	    (void) fclose(fp);
	}
#endif /* !ANDROID_CHANGES */
/*
 * Last chance to get a nameserver.  This should not normally
 * be necessary
 */
#ifdef NO_RESOLV_CONF
	if(nserv == 0)
		nserv = get_nameservers(statp);
#endif

	if (statp->defdname[0] == 0 &&
	    gethostname(buf, sizeof(statp->defdname) - 1) == 0 &&
	    (cp = strchr(buf, '.')) != NULL)
		strcpy(statp->defdname, cp + 1);

	/* find components of local domain that might be searched */
	if (havesearch == 0) {
		pp = statp->dnsrch;
		*pp++ = statp->defdname;
		*pp = NULL;

		dots = 0;
		for (cp = statp->defdname; *cp; cp++)
			dots += (*cp == '.');

		cp = statp->defdname;
		while (pp < statp->dnsrch + MAXDFLSRCH) {
			if (dots < LOCALDOMAINPARTS)
				break;
			cp = strchr(cp, '.') + 1;    /* we know there is one */
			*pp++ = cp;
			dots--;
		}
		*pp = NULL;
#ifdef DEBUG
		if (statp->options & RES_DEBUG) {
			printf(";; res_init()... default dnsrch list:\n");
			for (pp = statp->dnsrch; *pp; pp++)
				printf(";;\t%s\n", *pp);
			printf(";;\t..END..\n");
		}
#endif
	}

	if ((cp = getenv("RES_OPTIONS")) != NULL)
		res_setoptions(statp, cp, "env");
	if (nserv > 0) {
		statp->nscount = nserv;
		statp->options |= RES_INIT;
	}
	return (0);
}

static void
res_setoptions(res_state statp, const char *options, const char *source)
{
	const char *cp = options;
	int i;
	struct __res_state_ext *ext = statp->_u._ext.ext;

#ifdef DEBUG
	if (statp->options & RES_DEBUG)
		printf(";; res_setoptions(\"%s\", \"%s\")...\n",
		       options, source);
#endif
	while (*cp) {
		/* skip leading and inner runs of spaces */
		while (*cp == ' ' || *cp == '\t')
			cp++;
		/* search for and process individual options */
		if (!strncmp(cp, "ndots:", sizeof("ndots:") - 1)) {
			i = atoi(cp + sizeof("ndots:") - 1);
			if (i <= RES_MAXNDOTS)
				statp->ndots = i;
			else
				statp->ndots = RES_MAXNDOTS;
#ifdef DEBUG
			if (statp->options & RES_DEBUG)
				printf(";;\tndots=%d\n", statp->ndots);
#endif
		} else if (!strncmp(cp, "timeout:", sizeof("timeout:") - 1)) {
			i = atoi(cp + sizeof("timeout:") - 1);
			if (i <= RES_MAXRETRANS)
				statp->retrans = i;
			else
				statp->retrans = RES_MAXRETRANS;
#ifdef DEBUG
			if (statp->options & RES_DEBUG)
				printf(";;\ttimeout=%d\n", statp->retrans);
#endif
		} else if (!strncmp(cp, "attempts:", sizeof("attempts:") - 1)){
			i = atoi(cp + sizeof("attempts:") - 1);
			if (i <= RES_MAXRETRY)
				statp->retry = i;
			else
				statp->retry = RES_MAXRETRY;
#ifdef DEBUG
			if (statp->options & RES_DEBUG)
				printf(";;\tattempts=%d\n", statp->retry);
#endif
		} else if (!strncmp(cp, "debug", sizeof("debug") - 1)) {
#ifdef DEBUG
			if (!(statp->options & RES_DEBUG)) {
				printf(";; res_setoptions(\"%s\", \"%s\")..\n",
				       options, source);
				statp->options |= RES_DEBUG;
			}
			printf(";;\tdebug\n");
#endif
		} else if (!strncmp(cp, "no_tld_query",
				    sizeof("no_tld_query") - 1) ||
			   !strncmp(cp, "no-tld-query",
				    sizeof("no-tld-query") - 1)) {
			statp->options |= RES_NOTLDQUERY;
		} else if (!strncmp(cp, "inet6", sizeof("inet6") - 1)) {
			statp->options |= RES_USE_INET6;
		} else if (!strncmp(cp, "rotate", sizeof("rotate") - 1)) {
			statp->options |= RES_ROTATE;
		} else if (!strncmp(cp, "no-check-names",
				    sizeof("no-check-names") - 1)) {
			statp->options |= RES_NOCHECKNAME;
		}
#ifdef RES_USE_EDNS0
		else if (!strncmp(cp, "edns0", sizeof("edns0") - 1)) {
			statp->options |= RES_USE_EDNS0;
		}
#endif
		else if (!strncmp(cp, "dname", sizeof("dname") - 1)) {
			statp->options |= RES_USE_DNAME;
		}
		else if (!strncmp(cp, "nibble:", sizeof("nibble:") - 1)) {
			if (ext == NULL)
				goto skip;
			cp += sizeof("nibble:") - 1;
			i = MIN(strcspn(cp, " \t"), sizeof(ext->nsuffix) - 1);
			strncpy(ext->nsuffix, cp, (size_t)i);
			ext->nsuffix[i] = '\0';
		}
		else if (!strncmp(cp, "nibble2:", sizeof("nibble2:") - 1)) {
			if (ext == NULL)
				goto skip;
			cp += sizeof("nibble2:") - 1;
			i = MIN(strcspn(cp, " \t"), sizeof(ext->nsuffix2) - 1);
			strncpy(ext->nsuffix2, cp, (size_t)i);
			ext->nsuffix2[i] = '\0';
		}
		else if (!strncmp(cp, "v6revmode:", sizeof("v6revmode:") - 1)) {
			cp += sizeof("v6revmode:") - 1;
			/* "nibble" and "bitstring" used to be valid */
			if (!strncmp(cp, "single", sizeof("single") - 1)) {
				statp->options |= RES_NO_NIBBLE2;
			} else if (!strncmp(cp, "both", sizeof("both") - 1)) {
				statp->options &=
					 ~RES_NO_NIBBLE2;
			}
		}
		else {
			/* XXX - print a warning here? */
		}
   skip:
		/* skip to next run of spaces */
		while (*cp && *cp != ' ' && *cp != '\t')
			cp++;
	}
}

#ifdef RESOLVSORT
/* XXX - should really support CIDR which means explicit masks always. */
static uint32_t
net_mask(struct in_addr in)	/*!< XXX - should really use system's version of this */
{
	register uint32_t i = ntohl(in.s_addr);

	if (IN_CLASSA(i))
		return (htonl(IN_CLASSA_NET));
	else if (IN_CLASSB(i))
		return (htonl(IN_CLASSB_NET));
	return (htonl(IN_CLASSC_NET));
}
#endif

/*%
 * This routine is for closing the socket if a virtual circuit is used and
 * the program wants to close it.  This provides support for endhostent()
 * which expects to close the socket.
 *
 * This routine is not expected to be user visible.
 */
void
res_nclose(res_state statp)
{
	int ns;

	if (statp->_vcsock >= 0) {
		(void) close(statp->_vcsock);
		statp->_vcsock = -1;
		statp->_flags &= ~(RES_F_VC | RES_F_CONN);
	}
	for (ns = 0; ns < statp->_u._ext.nscount; ns++) {
		if (statp->_u._ext.nssocks[ns] != -1) {
			(void) close(statp->_u._ext.nssocks[ns]);
			statp->_u._ext.nssocks[ns] = -1;
		}
	}
}

void
res_ndestroy(res_state statp)
{
	res_nclose(statp);
	if (statp->_u._ext.ext != NULL)
		free(statp->_u._ext.ext);
	statp->options &= ~RES_INIT;
	statp->_u._ext.ext = NULL;
}

const char *
res_get_nibblesuffix(res_state statp)
{
	if (statp->_u._ext.ext)
		return (statp->_u._ext.ext->nsuffix);
	return ("ip6.arpa");
}

const char *
res_get_nibblesuffix2(res_state statp)
{
	if (statp->_u._ext.ext)
		return (statp->_u._ext.ext->nsuffix2);
	return ("ip6.int");
}

void
res_setservers(res_state statp, const union res_sockaddr_union *set, int cnt)
{
	int i, nserv;
	size_t size;

	/* close open servers */
	res_nclose(statp);

	/* cause rtt times to be forgotten */
	statp->_u._ext.nscount = 0;

	nserv = 0;
	for (i = 0; i < cnt && nserv < MAXNS; i++) {
		switch (set->sin.sin_family) {
		case AF_INET:
			size = sizeof(set->sin);
			if (statp->_u._ext.ext)
				memcpy(&statp->_u._ext.ext->nsaddrs[nserv],
					&set->sin, size);
			if (size <= sizeof(statp->nsaddr_list[nserv]))
				memcpy(&statp->nsaddr_list[nserv],
					&set->sin, size);
			else
				statp->nsaddr_list[nserv].sin_family = 0;
			nserv++;
			break;

#ifdef HAS_INET6_STRUCTS
		case AF_INET6:
			size = sizeof(set->sin6);
			if (statp->_u._ext.ext)
				memcpy(&statp->_u._ext.ext->nsaddrs[nserv],
					&set->sin6, size);
			if (size <= sizeof(statp->nsaddr_list[nserv]))
				memcpy(&statp->nsaddr_list[nserv],
					&set->sin6, size);
			else
				statp->nsaddr_list[nserv].sin_family = 0;
			nserv++;
			break;
#endif

		default:
			break;
		}
		set++;
	}
	statp->nscount = nserv;

}

int
res_getservers(res_state statp, union res_sockaddr_union *set, int cnt)
{
	int i;
	size_t size;
	uint16_t family;

	for (i = 0; i < statp->nscount && i < cnt; i++) {
		if (statp->_u._ext.ext)
			family = statp->_u._ext.ext->nsaddrs[i].sin.sin_family;
		else
			family = statp->nsaddr_list[i].sin_family;

		switch (family) {
		case AF_INET:
			size = sizeof(set->sin);
			if (statp->_u._ext.ext)
				memcpy(&set->sin,
				       &statp->_u._ext.ext->nsaddrs[i],
				       size);
			else
				memcpy(&set->sin, &statp->nsaddr_list[i],
				       size);
			break;

#ifdef HAS_INET6_STRUCTS
		case AF_INET6:
			size = sizeof(set->sin6);
			if (statp->_u._ext.ext)
				memcpy(&set->sin6,
				       &statp->_u._ext.ext->nsaddrs[i],
				       size);
			else
				memcpy(&set->sin6, &statp->nsaddr_list[i],
				       size);
			break;
#endif

		default:
			set->sin.sin_family = 0;
			break;
		}
		set++;
	}
	return (statp->nscount);
}

#ifdef ANDROID_CHANGES
void res_setnetcontext(res_state statp, const struct android_net_context *netcontext)
{
	if (statp != NULL) {
		statp->netid = netcontext->dns_netid;
		statp->_mark = netcontext->dns_mark;
		statp->qhook = netcontext->qhook;
		if (netcontext->flags & NET_CONTEXT_FLAG_USE_EDNS) {
			statp->options |= RES_USE_EDNS0 | RES_USE_DNSSEC;
		}
	}
}

#endif /* ANDROID_CHANGES */
```