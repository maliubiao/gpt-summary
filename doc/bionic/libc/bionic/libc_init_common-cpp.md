Response:
Let's break down the thought process for analyzing this C++ source file and generating the detailed response.

**1. Initial Understanding and Goal Identification:**

The first step is to grasp the core purpose of the file: `bionic/libc/bionic/libc_init_common.cpp`. The description explicitly states it's part of Android's C library (bionic) and handles common initialization tasks. The request asks for its functions, their relationship to Android, implementation details, handling of dynamic linking, potential errors, and how Android frameworks interact with it. This signals a need for a multi-faceted analysis covering functionality, implementation, and integration.

**2. Code Structure and Key Areas:**

Scanning the code reveals several distinct sections and areas of concern:

* **Includes:**  These give hints about the functionalities used (e.g., `<fcntl.h>` for file operations, `<sys/auxv.h>` for auxiliary vectors, `<pthread_internal.h>` for thread management).
* **Global Variables:** Look for `__LIBC_HIDDEN__` and `__BIONIC_WEAK_VARIABLE_FOR_NATIVE_BRIDGE` declarations. These often indicate internal state or interfaces with the dynamic linker/other components. `__libc_globals`, `__progname`, and cache size variables stand out.
* **Function Declarations:**  Identify the prominent functions like `__libc_init_globals`, `__libc_init_common`, `__libc_init_AT_SECURE`, `__libc_fini`, and weak symbols like `__libc_init_scudo`, `__libc_init_mte_late`, and `__libc_set_target_sdk_version`.
* **Conditional Compilation (`#if defined(...)`):** Note the use of preprocessor directives, particularly those related to architecture (`__i386__`, `__x86_64__`, `__aarch64__`) and specific features (`USE_SCUDO`, `__has_feature(hwaddress_sanitizer)`). This suggests platform-specific behavior.
* **Specific Function Logic:**  Pay close attention to the implementation details within each function. Look for system calls (`sysconf`, `gettid`, `open`, `fcntl`, `personality`, `getauxval`, `timer_create`, `timer_settime`, `timer_delete`), mutex usage, and interactions with other internal functions.

**3. Function-by-Function Analysis:**

Go through each function and deduce its purpose:

* `__libc_init_globals`:  Initializes core libc globals, likely called early. The mention of "linker and libc" suggests it's run in both contexts.
* `__check_max_thread_id`:  A 32-bit specific check, highlighting an Android-specific constraint.
* `arc4random_fork_handler`:  Related to forking and randomness, important for security.
* `__libc_init_scudo`: Deals with the Scudo memory allocator, an Android-specific component. The conditional logic based on `USE_SCUDO` and `hwaddress_sanitizer` is key.
* `__libc_init_mte_late`:  Handles Memory Tagging Extension (MTE), a hardware-assisted memory safety feature, and its potential downgrade mechanism.
* `__libc_add_main_thread`:  Manages the main thread in the internal thread list.
* `__libc_init_common`:  The main initialization function, calling other initialization routines.
* `__libc_init_fork_handler`: Sets up handlers for fork events.
* `__libc_set_target_sdk_version`:  Configures Scudo based on the target API level, another Android-specific aspect.
* `__early_abort`:  A very early error handling mechanism.
* `__nullify_closed_stdio`: Ensures standard file descriptors are valid, crucial for security.
* `env_match`, `__is_valid_environment_variable`, `__is_unsafe_environment_variable`, `__sanitize_environment_variables`:  Deal with environment variable security, a significant concern in Android's sandboxed environment.
* `__initialize_personality`: Sets the Linux personality, related to system call behavior.
* `__libc_init_AT_SECURE`: Handles the `AT_SECURE` auxiliary vector, a vital part of Android's security model for setuid programs.
* `__libc_fini`:  Handles the execution of destructors at program termination.
* `__libc_init_x86_cache_info`: Architecture-specific optimization based on CPU cache information.

**4. Connecting to Android Features:**

While analyzing each function, actively look for connections to specific Android functionalities:

* **Scudo:**  Directly mentioned and configured.
* **Memory Tagging (MTE):**  Explicitly handled with downgrade logic.
* **System Properties:** `__system_properties_init` is a clear indicator.
* **FDSan/FDTrack:** `__libc_init_fdsan` and `__libc_init_fdtrack` are Android-specific security features.
* **Native Bridge:** The `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` macro signifies interaction with the mechanism for running 32-bit apps on 64-bit devices.
* **Target SDK Version:** `__libc_set_target_sdk_version` directly relates to Android's API level system.
* **Security Sandboxing:** The environment variable sanitization is a crucial part of Android's security model.
* **`AT_SECURE`:** A core mechanism for managing security transitions in Android.

**5. Dynamic Linker Aspects:**

Identify code segments related to the dynamic linker:

* **Global Variables:** `__libc_globals` being initialized in both the linker and libc.
* **Weak Symbols:** Functions marked with `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` can be overridden by the dynamic linker.
* **Initialization Order:** The comments about running twice for linker and libc copies are important.

For the SO layout and linking process, a general understanding of ELF files and dynamic linking is needed. Create a simplified example to illustrate the concept.

**6. Error Handling and Common Mistakes:**

Think about potential issues and how the code addresses them. The `__early_abort` function is a strong signal of critical early-stage errors. The environment variable sanitization highlights potential security vulnerabilities. Consider common programming errors related to environment variables or file descriptor management.

**7. Framework/NDK Interaction:**

Trace how execution might reach this code:

* **App Startup:**  The dynamic linker loads `libc.so`, triggering initialization.
* **`dlopen`:** Loading shared libraries brings in `libc.so`.
* **NDK Usage:**  NDK code directly uses libc functions, indirectly relying on this initialization.

Frida hooks are a practical way to observe this. Identify relevant functions to hook (initialization functions are good candidates).

**8. Structuring the Response:**

Organize the information logically according to the request's components:

* **Functionality:** List the key tasks performed by the file.
* **Android Relevance:** Explain how each function ties into Android features, providing examples.
* **Libc Function Implementation:** Detail the implementation of significant libc functions.
* **Dynamic Linker:** Explain the role of the file in dynamic linking, provide a SO layout, and describe the linking process.
* **Logic and Assumptions:**  Explain any logical deductions or assumptions made.
* **Common Errors:** Provide examples of user or programming errors.
* **Framework/NDK Path:** Describe how the framework and NDK lead to this code.
* **Frida Hook Examples:**  Give practical Frida code snippets.

**9. Refinement and Clarity:**

Review the generated response for accuracy, clarity, and completeness. Ensure that technical terms are explained adequately and that examples are relevant. Use clear and concise language, avoiding jargon where possible. Ensure the Chinese translation is accurate and natural.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on individual libc functions.
* **Correction:** Realize the importance of the initialization *process* and the interplay between different functions. Emphasize the order of execution and dependencies.
* **Initial thought:**  Provide very technical details about dynamic linking.
* **Correction:**  Simplify the SO layout and linking process explanation to be more understandable. Focus on the core concepts.
* **Initial thought:**  Only mention direct NDK calls.
* **Correction:** Include the framework's role in process creation and how that leads to libc loading.

By following these steps and iteratively refining the analysis, a comprehensive and accurate response can be generated, addressing all aspects of the original request.
好的，我们来详细分析 `bionic/libc/bionic/libc_init_common.cpp` 这个文件。

**文件功能概览:**

`libc_init_common.cpp` 文件是 Android Bionic libc 库的核心初始化文件之一。它的主要功能是在程序启动的早期阶段执行各种必要的初始化任务，为后续的 libc 功能以及应用程序的正常运行奠定基础。这些任务包括：

1. **初始化全局变量:** 初始化 libc 内部使用的全局变量，例如 `environ` (环境变量)、`errno` (错误码) 和程序名。
2. **初始化虚拟动态共享对象 (VDSO):**  VDSO 允许程序直接调用某些内核函数，提高性能。
3. **设置 setjmp cookie:** 用于防止栈溢出攻击。
4. **初始化线程相关:** 添加主线程到线程列表。
5. **初始化系统属性:**  允许访问 Android 系统属性。
6. **初始化 FDSan 和 FDTrack:**  用于调试文件描述符泄漏和错误使用。
7. **初始化 CPU 缓存信息 (特定架构):**  在 x86 架构上，获取并存储 CPU 缓存大小信息，用于性能优化。
8. **初始化 Scudo 内存分配器:**  配置 Scudo，Android 的现代内存分配器，例如设置是否填充已分配内存。
9. **处理内存标签扩展 (MTE) (特定架构):**  在 ARM64 架构上，管理 MTE 功能的启用和降级。
10. **处理 `AT_SECURE` 辅助向量:**  处理与安全相关的程序启动，例如 setuid 程序，包括清理不安全的环境变量。
11. **强制打开标准 I/O 文件描述符:** 确保 stdin、stdout 和 stderr 始终指向有效的文件，防止安全问题。
12. **设置进程 "personality":**  影响系统调用的行为 (在 32 位系统上)。
13. **注册 `fork()` 处理函数:**  管理 `arc4random` 相关的锁，确保在 `fork()` 调用后随机数生成器的状态正确。
14. **设置目标 SDK 版本相关配置:**  根据目标 SDK 版本配置 Scudo 的行为。
15. **执行 `.fini_array` 中的析构函数:** 在程序退出时调用，清理全局对象。

**与 Android 功能的关系及举例说明:**

这个文件与 Android 的功能紧密相关，因为它直接负责 libc 的初始化，而 libc 是 Android 系统中所有 native 代码的基础。

* **系统属性 (System Properties):**
    * **功能:** `__system_properties_init()` 函数初始化了访问 Android 系统属性的机制。系统属性是 Android 系统中用于存储配置信息的键值对。
    * **举例:**  `getprop ro.build.version.sdk` 可以获取当前设备的 SDK 版本。`libc_init_common.cpp` 的初始化是 `getprop` 命令能够正常工作的基础。
* **Scudo 内存分配器:**
    * **功能:**  `__libc_init_scudo()` 函数负责配置 Scudo 内存分配器。Scudo 提供了比传统 `dlmalloc` 更安全和高效的内存管理。
    * **举例:**  当 NDK 应用调用 `malloc()` 分配内存时，最终会调用到 Scudo 的实现。`libc_init_common.cpp` 中的配置决定了 Scudo 的一些行为，例如是否用特定模式填充新分配的内存（用于调试）。
* **FDSan (File Descriptor Sanitizer):**
    * **功能:** `__libc_init_fdsan()` 初始化了 FDSan，这是一个用于检测文件描述符泄漏和错误使用的工具。
    * **举例:**  如果一个 NDK 应用打开了一个文件却没有关闭，FDSan 可以在运行时检测到并发出警告，帮助开发者排查问题。FDSan 的初始化依赖于系统属性的配置。
* **FDTrack (File Descriptor Tracking):**
    * **功能:** `__libc_init_fdtrack()` 初始化了 FDTrack，它跟踪文件描述符的创建和关闭，用于调试。
* **内存标签扩展 (MTE):**
    * **功能:**  `__libc_init_mte_late()` 函数在支持 MTE 的 ARM64 设备上处理 MTE 的配置和可能的降级。MTE 是一种硬件辅助的内存安全特性，可以检测内存访问错误。
    * **举例:**  如果启用了 MTE，当程序尝试访问未授权的内存区域时，MTE 可以立即检测到并终止程序，防止潜在的安全漏洞。`libc_init_common.cpp` 中的代码可以在启动后的一段时间将 MTE 的严格模式降级为异步模式，以平衡性能和安全性。
* **安全启动 (`AT_SECURE`):**
    * **功能:** `__libc_init_AT_SECURE()` 函数处理 `AT_SECURE` 辅助向量。当程序以特权身份运行时（例如 setuid），这个向量会被设置，表明需要进行额外的安全措施。
    * **举例:**  对于 setuid 程序，`libc_init_AT_SECURE()` 会清理一些可能被恶意利用的环境变量，例如 `LD_PRELOAD`，防止提权攻击。

**Libc 函数的实现细节:**

由于篇幅限制，我们无法详细解释每一个 libc 函数的实现，但可以挑几个关键的进行说明：

* **`__libc_init_globals()`:**
    * **功能:** 初始化 libc 的全局变量。
    * **实现:**
        * 调用 `__libc_globals.initialize()` 初始化 `libc_globals` 结构体。
        * 调用 `__libc_init_vdso()` 初始化 VDSO 相关的函数指针，使得 libc 可以直接调用内核函数。
        * 调用 `__libc_init_setjmp_cookie()` 设置用于栈保护的 cookie 值。
    * **与 Android 的关系:**  VDSO 的使用是 Android 系统性能优化的重要手段。
* **`__libc_init_common()`:**
    * **功能:**  执行一系列通用的初始化任务。
    * **实现:**
        * 设置全局变量 `environ` 和 `errno`。
        * 设置程序名 (`progname`)。
        * 在 32 位系统上检查最大线程 ID。
        * 调用 `__libc_add_main_thread()` 将主线程添加到线程列表。
        * 调用 `__system_properties_init()`、`__libc_init_fdsan()` 和 `__libc_init_fdtrack()` 初始化相关子系统。
        * 在 x86 架构上调用 `__libc_init_x86_cache_info()` 获取 CPU 缓存信息。
    * **与 Android 的关系:** 这是 libc 启动的关键入口点，许多 Android 特有的功能都在此初始化。
* **`__libc_init_AT_SECURE()`:**
    * **功能:**  处理 `AT_SECURE` 辅助向量，进行安全相关的初始化。
    * **实现:**
        * 通过 `getauxval(AT_SECURE)` 获取 `AT_SECURE` 的值。
        * 调用 `__nullify_closed_stdio()` 确保标准 I/O 文件描述符有效。
        * 如果 `AT_SECURE` 被设置，调用 `__sanitize_environment_variables()` 清理不安全的环境变量。
        * 将经过清理的环境变量赋值给 `environ`。
        * 调用 `__initialize_personality()` 设置进程 "personality"。
    * **与 Android 的关系:**  对于 Android 的安全模型至关重要，特别是对于具有特权的应用。
* **`__nullify_closed_stdio()`:**
    * **功能:**  强制打开 stdin、stdout 和 stderr，即使它们在启动时被关闭。
    * **实现:**
        * 遍历文件描述符 0、1 和 2。
        * 使用 `fcntl(i, F_GETFL)` 检查文件描述符是否已打开。
        * 如果未打开（返回 -1 且 `errno` 为 `EBADF`），则尝试打开 `/dev/null` 或 `/sys/fs/selinux/null` 并将其关联到该文件描述符。
    * **与 Android 的关系:**  防止由于文件描述符管理不当导致的安全漏洞。

**Dynamic Linker 的功能和处理过程:**

`libc_init_common.cpp` 中涉及到 dynamic linker 的主要体现在以下几个方面：

1. **全局变量的初始化:**  `__libc_globals` 的初始化注释说明了它在 dynamic linker 和 libc 自身都会运行。这意味着 dynamic linker 也有自己的一份 `libc_globals` 副本，需要在早期进行初始化。
2. **弱符号 (Weak Symbols):**  像 `__progname` 以及以 `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 修饰的函数，例如 `__libc_init_scudo`，都是弱符号。这意味着如果可执行文件或其依赖的库中定义了同名的强符号，则链接器会使用强符号的定义。这允许 Android 系统在不同的场景下替换 libc 的某些默认行为。

**SO 布局样本和链接处理过程:**

假设我们有一个简单的可执行文件 `my_app`，它链接到 `libc.so`：

```
my_app (可执行文件)
├── .text (代码段)
├── .data (已初始化数据段)
├── .bss (未初始化数据段)
└── .dynamic (动态链接信息)
    ├── ...
    ├── NEEDED   libc.so  // 依赖 libc.so
    ├── SYMTAB   ...
    ├── STRTAB   ...
    └── ...

libc.so (共享库)
├── .text
├── .data
├── .bss
├── .dynamic
    ├── ...
    └── SONAME libc.so
├── .init_array (初始化函数数组)
└── .fini_array (析构函数数组)
```

**链接处理过程:**

1. **加载可执行文件:**  当 Android 系统启动 `my_app` 时，内核会加载可执行文件的头部，并识别出它是一个动态链接的程序。
2. **加载动态链接器:** 内核根据可执行文件头部的信息，加载动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 到内存中。
3. **加载依赖库:** 动态链接器解析可执行文件的 `.dynamic` 段，找到所有依赖的共享库，例如 `libc.so`。
4. **定位和加载共享库:** 动态链接器在预定义的路径（例如 `/system/lib64` 或 `/system/lib`）中查找 `libc.so`，并将其加载到内存中。
5. **符号解析和重定位:** 动态链接器解析 `my_app` 和 `libc.so` 的符号表，将 `my_app` 中对 `libc.so` 中函数的调用地址进行重定位，使其指向 `libc.so` 中函数的实际地址。
6. **执行初始化函数:** 动态链接器会执行 `libc.so` 的 `.init_array` 段中指定的初始化函数。在这个过程中，`libc_init_common.cpp` 中定义的 `__libc_init_common()` 等函数会被调用，完成 libc 的初始化。
7. **启动应用程序:**  初始化完成后，动态链接器将控制权交给应用程序的入口点。

**逻辑推理、假设输入与输出 (示例):**

假设在 ARM64 设备上，`__libc_shared_globals()->heap_tagging_upgrade_timer_sec` 的值为 5。

* **假设输入:** `__libc_shared_globals()->heap_tagging_upgrade_timer_sec = 5;`
* **逻辑推理:**  `__libc_init_mte_late()` 函数会被调用，它会创建一个定时器，在 5 秒后触发。定时器触发时，会调用一个 lambda 函数，将 MTE 的模式从同步降级为异步。
* **预期输出:** 在程序启动 5 秒后，系统日志中会出现一条类似 "Downgrading MTE to async." 的消息。并且后续的内存分配行为会受到异步 MTE 的影响。

**用户或编程常见的使用错误举例:**

* **环境变量问题:**  在安全敏感的上下文中（例如 setuid 程序）错误地依赖或设置了被 `__sanitize_environment_variables()` 清理的环境变量，可能导致程序行为异常或安全漏洞。
    * **错误示例:**  一个 setuid 程序尝试读取 `LD_PRELOAD` 环境变量来加载自定义的库，但这在 `libc_init_AT_SECURE()` 中会被清理，导致加载失败。
* **文件描述符泄漏:**  没有正确关闭打开的文件描述符，FDSan 会检测到这类问题，但这通常不是 `libc_init_common.cpp` 直接导致的，而是应用代码的错误。`libc_init_common.cpp` 的作用是初始化 FDSan 来帮助发现这类错误。
* **在早期依赖未初始化的 libc 功能:**  如果在 libc 初始化完成之前就尝试调用某些 libc 函数，可能会导致程序崩溃或行为未定义。这通常发生在非常早期的启动阶段，例如在动态链接器加载共享库的过程中。

**Android Framework 或 NDK 如何到达这里:**

1. **Android 系统启动:** 当 Android 设备启动时，`init` 进程是第一个启动的用户空间进程。
2. **Zygote 进程启动:** `init` 进程会启动 Zygote 进程。Zygote 是所有 Android 应用进程的父进程。
3. **Zygote 加载共享库:** Zygote 进程在启动时会加载许多共享库，包括 `libc.so`。动态链接器在加载 `libc.so` 时会执行其 `.init_array` 中的初始化函数，从而调用到 `libc_init_common.cpp` 中的 `__libc_init_common()` 等函数。
4. **应用进程 fork:** 当启动一个新的 Android 应用时，Zygote 进程会 `fork()` 出一个新的进程。
5. **应用进程执行:** 新的进程会执行应用的代码。由于应用进程继承了 Zygote 进程加载的共享库，因此 `libc.so` 已经被加载和初始化。
6. **NDK 应用:** 对于使用 NDK 开发的 native 应用，其执行路径类似，只不过它们的入口点是 native 代码，而 native 代码会直接调用 libc 提供的函数。

**Frida Hook 示例调试步骤:**

可以使用 Frida Hook 来观察 `libc_init_common.cpp` 中函数的执行。以下是一个示例，用于 Hook `__libc_init_common()` 函数：

```javascript
if (Process.arch === 'arm64') {
    const libcInitCommon = Module.findExportByName("libc.so", "__libc_init_common");
    if (libcInitCommon) {
        Interceptor.attach(libcInitCommon, {
            onEnter: function (args) {
                console.log("[+] __libc_init_common called!");
                // 可以在这里打印参数或者执行其他操作
            },
            onLeave: function (retval) {
                console.log("[+] __libc_init_common finished.");
            }
        });
    } else {
        console.log("[-] __libc_init_common not found in libc.so");
    }
} else {
    console.log("[-] This script is for ARM64 architecture.");
}
```

**调试步骤:**

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida server。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_libc_init.js`。
3. **连接到目标进程:** 确定你要调试的进程的进程 ID 或进程名称。
4. **运行 Frida 命令:** 使用 Frida 命令行工具将脚本注入到目标进程中。例如，如果目标进程的名称是 `com.example.myapp`，可以运行：
   ```bash
   frida -U -f com.example.myapp -l hook_libc_init.js --no-pause
   ```
   或者，如果已经知道进程 ID：
   ```bash
   frida -U <进程ID> -l hook_libc_init.js
   ```
5. **观察输出:** 当目标进程启动并加载 `libc.so` 时，Frida 会 Hook 到 `__libc_init_common()` 函数，并在终端输出相应的日志信息。

通过这种方式，你可以 Hook 其他 `libc_init_common.cpp` 中的函数，例如 `__libc_init_AT_SECURE()` 或 `__libc_init_scudo()`，以观察它们的执行过程和参数，帮助你理解 libc 的初始化流程。

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/libc_init_common.cpp` 文件的功能和作用。

Prompt: 
```
这是目录为bionic/libc/bionic/libc_init_common.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "libc_init_common.h"

#include <async_safe/log.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/personality.h>
#include <sys/time.h>
#include <unistd.h>

#include "heap_tagging.h"
#include "private/ScopedPthreadMutexLocker.h"
#include "private/WriteProtected.h"
#include "private/bionic_defs.h"
#include "private/bionic_globals.h"
#include "private/bionic_tls.h"
#include "private/thread_private.h"
#include "pthread_internal.h"

extern "C" int __system_properties_init(void);
extern "C" void scudo_malloc_set_zero_contents(int);
extern "C" void scudo_malloc_set_pattern_fill_contents(int);

__LIBC_HIDDEN__ constinit WriteProtected<libc_globals> __libc_globals;
__LIBC_HIDDEN__ constinit _Atomic(bool) __libc_memtag_stack;
__LIBC_HIDDEN__ constinit bool __libc_memtag_stack_abi;

// Not public, but well-known in the BSDs.
__BIONIC_WEAK_VARIABLE_FOR_NATIVE_BRIDGE
const char* __progname;

#if defined(__i386__) || defined(__x86_64__)
// Default sizes based on the old hard-coded values for Atom/Silvermont (x86) and Core 2 (x86-64)...
size_t __x86_data_cache_size = 24 * 1024;
size_t __x86_data_cache_size_half = __x86_data_cache_size / 2;
size_t __x86_shared_cache_size = sizeof(long) == 8 ? 4096 * 1024 : 1024 * 1024;
size_t __x86_shared_cache_size_half = __x86_shared_cache_size / 2;
// ...overwritten at runtime based on the cpu's reported cache sizes.
static void __libc_init_x86_cache_info() {
  // Handle the case where during early boot /sys fs may not yet be ready,
  // resulting in sysconf() returning 0, leading to crashes.
  // In that case (basically just init), we keep the defaults.
  if (sysconf(_SC_LEVEL1_DCACHE_SIZE) != 0) {
    __x86_data_cache_size = sysconf(_SC_LEVEL1_DCACHE_SIZE);
    __x86_data_cache_size_half = __x86_data_cache_size / 2;
  }
  if (sysconf(_SC_LEVEL2_CACHE_SIZE) != 0) {
    __x86_shared_cache_size = sysconf(_SC_LEVEL2_CACHE_SIZE);
    __x86_shared_cache_size_half = __x86_shared_cache_size / 2;
  }
}
#endif

void __libc_init_globals() {
  // Initialize libc globals that are needed in both the linker and in libc.
  // In dynamic binaries, this is run at least twice for different copies of the
  // globals, once for the linker's copy and once for the one in libc.so.
  __libc_globals.initialize();
  __libc_globals.mutate([](libc_globals* globals) {
    __libc_init_vdso(globals);
    __libc_init_setjmp_cookie(globals);
  });
}

#if !defined(__LP64__)
static void __check_max_thread_id() {
  if (gettid() > 65535) {
    async_safe_fatal("32-bit pthread_mutex_t only supports pids <= 65535; "
                     "current pid %d; "
                     "`echo 65535 > /proc/sys/kernel/pid_max` as root",
                     gettid());
  }
}
#endif

static void arc4random_fork_handler() {
  _rs_forked = 1;
  _thread_arc4_lock();
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void __libc_init_scudo() {
  // Heap tagging level *must* be set before interacting with Scudo, otherwise
  // the primary will be mapped with PROT_MTE even if MTE is is not enabled in
  // this process.
  SetDefaultHeapTaggingLevel();

// TODO(b/158870657) make this unconditional when all devices support SCUDO.
#if defined(USE_SCUDO) && !__has_feature(hwaddress_sanitizer)
#if defined(SCUDO_PATTERN_FILL_CONTENTS)
  scudo_malloc_set_pattern_fill_contents(1);
#elif defined(SCUDO_ZERO_CONTENTS)
  scudo_malloc_set_zero_contents(1);
#endif
#endif
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
__attribute__((no_sanitize("hwaddress", "memtag"))) void
__libc_init_mte_late() {
#if defined(__aarch64__)
  if (!__libc_shared_globals()->heap_tagging_upgrade_timer_sec) {
    return;
  }
  struct sigevent event = {};
  static timer_t timer;
  event.sigev_notify = SIGEV_THREAD;
  event.sigev_notify_function = [](union sigval) {
    async_safe_format_log(ANDROID_LOG_INFO, "libc",
                          "Downgrading MTE to async.");
    ScopedPthreadMutexLocker l(&g_heap_tagging_lock);
    SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC);
    timer_delete(timer);
  };

  if (timer_create(CLOCK_REALTIME, &event, &timer) == -1) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "Failed to create MTE downgrade timer: %m");
    // Revert back to ASYNC. If we fail to create or arm the timer, otherwise
    // the process would be indefinitely stuck in SYNC.
    SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC);
    return;
  }

  struct itimerspec timerspec = {};
  timerspec.it_value.tv_sec =
      __libc_shared_globals()->heap_tagging_upgrade_timer_sec;
  if (timer_settime(timer, /* flags= */ 0, &timerspec, nullptr) == -1) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "Failed to arm MTE downgrade timer: %m");
    // Revert back to ASYNC. If we fail to create or arm the timer, otherwise
    // the process would be indefinitely stuck in SYNC.
    SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC);
    timer_delete(timer);
    return;
  }
  async_safe_format_log(
      ANDROID_LOG_INFO, "libc", "Armed MTE downgrade timer for %" PRId64 " s",
      __libc_shared_globals()->heap_tagging_upgrade_timer_sec);
#endif
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void __libc_add_main_thread() {
  // Get the main thread from TLS and add it to the thread list.
  pthread_internal_t* main_thread = __get_thread();
  __pthread_internal_add(main_thread);
}

void __libc_init_common() {
  // Initialize various globals.
  environ = __libc_shared_globals()->init_environ;
  errno = 0;
  setprogname(__libc_shared_globals()->init_progname ?: "<unknown>");

#if !defined(__LP64__)
  __check_max_thread_id();
#endif

  __libc_add_main_thread();

  __system_properties_init(); // Requires 'environ'.
  __libc_init_fdsan(); // Requires system properties (for debug.fdsan).
  __libc_init_fdtrack();

#if defined(__i386__) || defined(__x86_64__)
  __libc_init_x86_cache_info();
#endif
}

void __libc_init_fork_handler() {
  // Register atfork handlers to take and release the arc4random lock.
  pthread_atfork(arc4random_fork_handler, _thread_arc4_unlock, _thread_arc4_unlock);
}

extern "C" void scudo_malloc_set_add_large_allocation_slack(int add_slack);

__BIONIC_WEAK_FOR_NATIVE_BRIDGE void __libc_set_target_sdk_version(int target_api_level __unused) {
#if defined(USE_SCUDO) && !__has_feature(hwaddress_sanitizer)
  scudo_malloc_set_add_large_allocation_slack(target_api_level < 31);
#endif
}

__noreturn static void __early_abort(size_t line) {
  // We can't write to stdout or stderr because we're aborting before we've checked that
  // it's safe for us to use those file descriptors. We probably can't strace either, so
  // we rely on the fact that if we dereference a low address, either debuggerd or the
  // kernel's crash dump will show the fault address.
  *reinterpret_cast<int*>(line) = 0;
  _exit(EXIT_FAILURE);
}

// Force any of the stdin/stdout/stderr file descriptors that aren't
// open to be associated with /dev/null.
static void __nullify_closed_stdio() {
  for (int i = 0; i < 3; i++) {
    if (TEMP_FAILURE_RETRY(fcntl(i, F_GETFL)) == -1) {
      // The only error we allow is that the file descriptor does not exist.
      if (errno != EBADF) __early_abort(__LINE__);

      // This file descriptor wasn't open, so open /dev/null.
      // init won't have /dev/null available, but SELinux provides an equivalent.
      // This takes advantage of the fact that open() will take the lowest free
      // file descriptor, and we're iterating in order from 0, but we'll
      // double-check we got the right fd anyway...
      int fd;
      if (((fd = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR))) == -1 &&
           (fd = TEMP_FAILURE_RETRY(open("/sys/fs/selinux/null", O_RDWR))) == -1) ||
          fd != i) {
        __early_abort(__LINE__);
      }
    }
  }
}

// Check if the environment variable definition at 'envstr'
// starts with '<name>=', and if so return the address of the
// first character after the equal sign. Otherwise return null.
static const char* env_match(const char* envstr, const char* name) {
  size_t i = 0;

  while (envstr[i] == name[i] && name[i] != '\0') {
    ++i;
  }

  if (name[i] == '\0' && envstr[i] == '=') {
    return envstr + i + 1;
  }

  return nullptr;
}

static bool __is_valid_environment_variable(const char* name) {
  // According to the kernel source, by default the kernel uses 32*PAGE_SIZE
  // as the maximum size for an environment variable definition.
  const int MAX_ENV_LEN = 32*4096;

  if (name == nullptr) {
    return false;
  }

  // Parse the string, looking for the first '=' there, and its size.
  int pos = 0;
  int first_equal_pos = -1;
  while (pos < MAX_ENV_LEN) {
    if (name[pos] == '\0') {
      break;
    }
    if (name[pos] == '=' && first_equal_pos < 0) {
      first_equal_pos = pos;
    }
    pos++;
  }

  // Check that it's smaller than MAX_ENV_LEN (to detect non-zero terminated strings).
  if (pos >= MAX_ENV_LEN) {
    return false;
  }

  // Check that it contains at least one equal sign that is not the first character
  if (first_equal_pos < 1) {
    return false;
  }

  return true;
}

static bool __is_unsafe_environment_variable(const char* name) {
  // None of these should be allowed when the AT_SECURE auxv
  // flag is set. This flag is set to inform userspace that a
  // security transition has occurred, for example, as a result
  // of executing a setuid program or the result of an SELinux
  // security transition.
  static constexpr const char* UNSAFE_VARIABLE_NAMES[] = {
      "ANDROID_DNS_MODE",
      "GCONV_PATH",
      "GETCONF_DIR",
      "HOSTALIASES",
      "JE_MALLOC_CONF",
      "LD_AOUT_LIBRARY_PATH",
      "LD_AOUT_PRELOAD",
      "LD_AUDIT",
      "LD_CONFIG_FILE",
      "LD_DEBUG",
      "LD_DEBUG_OUTPUT",
      "LD_DYNAMIC_WEAK",
      "LD_HWASAN",
      "LD_LIBRARY_PATH",
      "LD_ORIGIN_PATH",
      "LD_PRELOAD",
      "LD_PROFILE",
      "LD_SHOW_AUXV",
      "LD_USE_LOAD_BIAS",
      "LIBC_DEBUG_MALLOC_OPTIONS",
      "LIBC_HOOKS_ENABLE",
      "LOCALDOMAIN",
      "LOCPATH",
      "MALLOC_CHECK_",
      "MALLOC_CONF",
      "MALLOC_TRACE",
      "NIS_PATH",
      "NLSPATH",
      "RESOLV_HOST_CONF",
      "RES_OPTIONS",
      "SCUDO_OPTIONS",
      "TMPDIR",
      "TZDIR",
  };
  for (const auto& unsafe_variable_name : UNSAFE_VARIABLE_NAMES) {
    if (env_match(name, unsafe_variable_name) != nullptr) {
      return true;
    }
  }
  return false;
}

static void __sanitize_environment_variables(char** env) {
  char** src = env;
  char** dst = env;
  for (; src[0] != nullptr; ++src) {
    if (!__is_valid_environment_variable(src[0])) {
      continue;
    }
    // Remove various unsafe environment variables if we're loading a setuid program.
    if (__is_unsafe_environment_variable(src[0])) {
      continue;
    }
    dst[0] = src[0];
    ++dst;
  }
  dst[0] = nullptr;
}

static void __initialize_personality() {
#if !defined(__LP64__)
  int old_value = personality(0xffffffff);
  if (old_value == -1) {
    async_safe_fatal("error getting old personality value: %m");
  }

  if (personality((static_cast<unsigned int>(old_value) & ~PER_MASK) | PER_LINUX32) == -1) {
    async_safe_fatal("error setting PER_LINUX32 personality: %m");
  }
#endif
}

void __libc_init_AT_SECURE(char** env) {
  // Check that the kernel provided a value for AT_SECURE.
  errno = 0;
  unsigned long is_AT_SECURE = getauxval(AT_SECURE);
  if (errno != 0) __early_abort(__LINE__);

  // Always ensure that STDIN/STDOUT/STDERR exist. This prevents file
  // descriptor confusion bugs where a parent process closes
  // STD*, the exec()d process calls open() for an unrelated reason,
  // the newly created file descriptor is assigned
  // 0<=FD<=2, and unrelated code attempts to read / write to the STD*
  // FDs.
  // In particular, this can be a security bug for setuid/setgid programs.
  // For example:
  // https://www.freebsd.org/security/advisories/FreeBSD-SA-02:23.stdio.asc
  // However, for robustness reasons, we don't limit these protections to
  // just security critical executables.
  //
  // Init is excluded from these protections unless AT_SECURE is set, as
  // /dev/null and/or /sys/fs/selinux/null will not be available at
  // early boot.
  if ((getpid() != 1) || is_AT_SECURE) {
    __nullify_closed_stdio();
  }

  if (is_AT_SECURE) {
    __sanitize_environment_variables(env);
  }

  // Now the environment has been sanitized, make it available.
  environ = __libc_shared_globals()->init_environ = env;

  __initialize_personality();
}

/* This function will be called during normal program termination
 * to run the destructors that are listed in the .fini_array section
 * of the executable, if any.
 *
 * 'fini_array' points to a list of function addresses. The first
 * entry in the list has value -1, the last one has value 0.
 */
void __libc_fini(void* array) {
  typedef void (*Dtor)();
  Dtor* fini_array = reinterpret_cast<Dtor*>(array);
  const Dtor minus1 = reinterpret_cast<Dtor>(static_cast<uintptr_t>(-1));

  // Validity check: the first entry must be -1.
  if (array == nullptr || fini_array[0] != minus1) return;

  // Skip over it.
  fini_array += 1;

  // Count the number of destructors.
  int count = 0;
  while (fini_array[count] != nullptr) {
    ++count;
  }

  // Now call each destructor in reverse order, ignoring any -1s.
  while (count > 0) {
    Dtor dtor = fini_array[--count];
    if (dtor != minus1) dtor();
  }
}

"""

```