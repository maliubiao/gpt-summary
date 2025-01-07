Response:
Let's break down the thought process for generating the detailed response to the provided C++ header file.

**1. Understanding the Goal:**

The core request is to analyze the `linker_tls.handroid.h` file, explaining its purpose, functionalities, relationships to Android, implementation details, dynamic linking aspects, potential errors, and how Android reaches this code. The response should be in Chinese with illustrative examples and Frida hooking.

**2. Initial Analysis of the Header File:**

The first step is to read through the header file and identify its key elements:

* **Copyright Notice:** Standard boilerplate, indicates ownership and licensing.
* **Includes:** `<stdlib.h>` (standard library) and `"private/bionic_elf_tls.h"` (Android-specific TLS definitions). This immediately signals that the file deals with Thread-Local Storage (TLS).
* **Forward Declarations:** `struct TlsModule;` and `struct soinfo;` indicate dependencies on these structures, hinting at TLS module management and shared library information.
* **Function Declarations:**  These are the core of the file and provide clues about the functionality:
    * `linker_setup_exe_static_tls()`:  Likely sets up TLS for the main executable. "static" suggests initialization at load time.
    * `linker_finalize_static_tls()`:  Likely performs cleanup or finalization of static TLS.
    * `register_soinfo_tls()` and `unregister_soinfo_tls()`:  Clearly related to managing TLS for shared libraries (`soinfo`).
    * `get_tls_module()`:  Retrieves information about a specific TLS module.
    * `TlsDescResolverFunc`:  A function pointer type, suggesting a mechanism for resolving TLS descriptors.
    * `struct TlsDescriptor`:  Holds information related to TLS descriptors. The `#if defined(__arm__)` indicates architecture-specific variations.
    * `struct TlsDynamicResolverArg`:  Arguments for dynamic TLS resolution.
    * `tlsdesc_resolver_static`, `tlsdesc_resolver_dynamic`, `tlsdesc_resolver_unresolved_weak`:  Different resolver functions, hinting at different scenarios for TLS resolution. The `__LIBC_HIDDEN__ extern "C"` indicates internal implementation details of the C library.

**3. Categorizing and Elaborating on Functionalities:**

Based on the initial analysis, I started grouping the functionalities and elaborating on them:

* **Core Functionality:** TLS management is the central theme.
* **Static vs. Dynamic TLS:** The presence of `static` and `dynamic` resolver functions and related setup functions points to these two types of TLS. I explained their differences.
* **Shared Library Integration:**  `register_soinfo_tls` and `unregister_soinfo_tls` are directly linked to the dynamic linker and how it manages TLS for loaded libraries.
* **TLS Descriptor Resolution:** This is a crucial aspect for accessing thread-local variables. I explained the purpose of the `TlsDescriptor` and the resolver functions.

**4. Connecting to Android Functionality:**

Here, the key is to relate the identified functionalities to how Android works:

* **App Startup:** `linker_setup_exe_static_tls` is used when an app starts.
* **Library Loading:** `register_soinfo_tls` is called when a shared library is loaded.
* **Thread Creation:** TLS is fundamental for thread-local data.
* **NDK Usage:**  NDK libraries also rely on TLS.

**5. "Detailed Explanation of libc Functions":**

The prompt specifically asks about `libc` functions. While the *header file itself* doesn't implement the *body* of libc functions, it *declares* functions that are part of the dynamic linker, which is tightly coupled with `libc`. Therefore, I focused on explaining the *purpose* of the declared functions within the context of the dynamic linker and TLS, even though their actual implementation resides elsewhere. I emphasized the concept of resolvers and how they work.

**6. Dynamic Linker Aspects:**

This requires understanding how shared libraries are loaded and linked.

* **SO Layout:** I described a typical memory layout with code, data, and `.tbss` (thread-local storage) sections.
* **Linking Process:** I explained the role of the dynamic linker in resolving symbols and setting up TLS when a library is loaded. I highlighted the use of GOT (Global Offset Table) and TLS-related GOT entries.

**7. Logical Reasoning and Examples:**

For the resolver functions, I provided hypothetical input and output to illustrate how the resolution process might work.

**8. Common Usage Errors:**

I focused on common pitfalls related to thread-local storage, such as incorrect initialization order and assuming thread-safety without proper synchronization.

**9. Android Framework/NDK to This Code:**

This requires tracing the execution flow:

* **App Launch:** The system starts the `zygote` process.
* **Forking:**  New app processes are forked from `zygote`.
* **Dynamic Linker Invocation:** The dynamic linker (`/system/bin/linker64` or `/system/bin/linker`) is invoked to load the application executable and its dependencies.
* **TLS Setup:** The dynamic linker calls functions like `linker_setup_exe_static_tls` and `register_soinfo_tls` as part of the loading process.
* **NDK:** When an NDK library is loaded, the same dynamic linking process applies.

**10. Frida Hooking:**

I provided practical Frida examples to demonstrate how to intercept and inspect the execution of the key functions, which is a valuable debugging technique. I focused on hooking the entry points of the resolver functions and the `register_soinfo_tls` function.

**11. Language and Formatting:**

Throughout the process, I ensured the response was in clear and understandable Chinese, using appropriate terminology and formatting to enhance readability. I used bullet points, code blocks, and explanations to structure the information effectively.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the *implementation* of libc functions.
* **Correction:** Realized the header file only *declares* these functions, and the focus should be on their *purpose* within the dynamic linking context.
* **Initial thought:** Provide very technical details about ELF structures.
* **Correction:**  Simplified the explanation of SO layout and linking process to make it more accessible.
* **Initial thought:**  Overlook the importance of illustrating with examples.
* **Correction:** Added specific scenarios and hypothetical inputs/outputs to clarify the concepts.

By following these steps and constantly refining the approach, I was able to generate a comprehensive and informative answer that addresses all aspects of the user's request.
这是一个关于 Android Bionic 库中动态链接器 (linker) 处理线程本地存储 (Thread-Local Storage, TLS) 的头文件 `linker_tls.handroid.h`。它定义了与 TLS 管理和解析相关的结构体和函数声明。下面我将逐一解释其功能，并根据你的要求进行详细说明。

**功能列表:**

这个头文件主要定义了以下功能，用于动态链接器在 Android 系统中管理和解析 TLS：

1. **静态 TLS 的设置和终结:**
   - `linker_setup_exe_static_tls(const char* progname)`:  为可执行文件设置静态 TLS。
   - `linker_finalize_static_tls()`:  终结静态 TLS。

2. **共享库 TLS 的注册和注销:**
   - `register_soinfo_tls(soinfo* si)`:  当加载一个新的共享库时，注册其 TLS 信息。
   - `unregister_soinfo_tls(soinfo* si)`: 当卸载一个共享库时，注销其 TLS 信息。

3. **获取 TLS 模块信息:**
   - `const TlsModule& get_tls_module(size_t module_id)`: 根据模块 ID 获取对应的 TLS 模块信息。

4. **定义 TLS 描述符和解析函数类型:**
   - `typedef size_t TlsDescResolverFunc(size_t)`: 定义 TLS 描述符解析函数的类型。
   - `struct TlsDescriptor`: 定义 TLS 描述符的结构，包含解析函数指针和参数。

5. **定义动态 TLS 解析参数:**
   - `struct TlsDynamicResolverArg`: 定义动态 TLS 解析器的参数，包含 generation 和 index。

6. **声明内部 TLS 描述符解析函数:**
   - `__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_static(size_t)`:  用于解析静态 TLS 描述符的函数。
   - `__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_dynamic(size_t)`: 用于解析动态 TLS 描述符的函数。
   - `__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_unresolved_weak(size_t)`: 用于解析未解决的弱符号 TLS 描述符的函数。

**与 Android 功能的关系及举例说明:**

这个头文件中的功能是 Android 动态链接器不可或缺的一部分，它负责处理应用程序和共享库的线程本地存储。TLS 允许每个线程拥有自己的全局变量副本，这对于编写多线程程序至关重要。

* **应用程序启动:** 当 Android 系统启动一个新的应用程序进程时，动态链接器会首先加载可执行文件，并调用 `linker_setup_exe_static_tls()` 来设置应用程序的静态 TLS。这使得应用程序可以使用 `__thread` 关键字声明的全局变量。
   * **例子:** 假设一个应用程序定义了一个线程局部变量 `__thread int my_thread_local_var = 0;`。在应用程序启动时，`linker_setup_exe_static_tls()` 会分配必要的空间并初始化该变量。

* **加载共享库:** 当应用程序使用 `dlopen()` 等函数加载一个新的共享库时，动态链接器会调用 `register_soinfo_tls()` 来注册该共享库的 TLS 信息。这使得共享库也可以使用线程局部变量。
   * **例子:**  假设一个共享库 `libmylib.so` 定义了一个线程局部变量 `__thread char* my_lib_thread_local_str = "hello";`。当应用程序加载 `libmylib.so` 时，`register_soinfo_tls()` 会确保为该变量在每个线程中分配独立的存储空间。

* **访问线程局部变量:** 当代码尝试访问一个线程局部变量时，编译器会生成特殊的代码，利用 TLS 描述符来定位该变量在当前线程中的地址。这个过程可能涉及到调用 `tlsdesc_resolver_static()` 或 `tlsdesc_resolver_dynamic()` 等解析函数。

**详细解释每一个 libc 函数的功能是如何实现的:**

需要注意的是，这个头文件本身 **并没有实现** 这些函数的功能，它只是声明了这些函数的接口。这些函数的具体实现位于 Bionic 动态链接器的其他源文件中，例如 `bionic/linker/linker.cpp` 等。

* **`linker_setup_exe_static_tls(const char* progname)`:**
    - **功能:** 为主程序设置静态 TLS 块。静态 TLS 在程序启动时分配，大小在编译时确定。
    - **实现思路:**  动态链接器会根据 ELF 文件的头信息 (例如 `.tbss` 节) 计算静态 TLS 的大小，并分配一块内存区域。每个线程都会被分配到这块区域的一个偏移量，用于访问其线程局部变量。`progname` 可能用于命名或标记 TLS 区域。
* **`linker_finalize_static_tls()`:**
    - **功能:**  清理或释放静态 TLS 相关的资源。
    - **实现思路:**  在进程退出时调用，可能释放为静态 TLS 分配的内存，但通常静态分配的内存在进程结束时由操作系统回收。
* **`register_soinfo_tls(soinfo* si)`:**
    - **功能:** 注册一个新加载的共享库的 TLS 信息。
    - **实现思路:**  `soinfo` 结构体包含了共享库的信息，包括其 TLS 节 (例如 `.tbss`) 的大小和对齐要求。动态链接器会根据这些信息，在全局的 TLS 空间中为该共享库分配一个唯一的 TLS 模块 ID，并记录其 TLS 块的偏移量。
* **`unregister_soinfo_tls(soinfo* si)`:**
    - **功能:** 注销一个卸载的共享库的 TLS 信息。
    - **实现思路:** 当共享库被卸载时，动态链接器需要清理与其 TLS 相关的元数据，例如移除其 TLS 模块 ID 和偏移量的记录。但是，已经分配的 TLS 内存通常不会立即释放，因为其他线程可能仍在访问它。
* **`get_tls_module(size_t module_id)`:**
    - **功能:** 根据模块 ID 获取对应的 TLS 模块信息。
    - **实现思路:** 动态链接器会维护一个数据结构（例如数组或哈希表）来存储所有已加载模块的 TLS 信息。此函数会根据 `module_id` 在该数据结构中查找并返回对应的 `TlsModule` 结构。
* **`tlsdesc_resolver_static(size_t)`:**
    - **功能:** 解析静态 TLS 描述符，返回线程局部变量的地址。
    - **实现思路:** 当代码访问静态 TLS 变量时，编译器会生成一个 TLS 描述符，其中包含了模块 ID 和变量在模块内的偏移量。`tlsdesc_resolver_static` 函数会根据模块 ID 找到对应的 TLS 模块的基地址，然后加上变量的偏移量，得到最终的内存地址。
* **`tlsdesc_resolver_dynamic(size_t)`:**
    - **功能:** 解析动态 TLS 描述符，用于访问在共享库中定义的线程局部变量。
    - **实现思路:** 动态 TLS 的解析过程比静态 TLS 更复杂。它涉及到查找共享库的 `soinfo` 结构，确定其 TLS 块的偏移量，然后再根据变量在模块内的偏移量计算出最终地址。`TlsDynamicResolverArg` 结构可能包含了用于加速查找的信息，例如 `generation` 和 `index`。
* **`tlsdesc_resolver_unresolved_weak(size_t)`:**
    - **功能:** 处理未解决的弱符号 TLS 描述符。
    - **实现思路:**  弱符号允许在没有定义的情况下被引用。如果一个弱符号的 TLS 变量没有被定义，这个解析器可能会返回一个空指针或一个特定的错误值。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**SO 布局样本:**

一个典型的共享库 (SO 文件) 的内存布局中，与 TLS 相关的部分包括：

```
.dynamic       # 动态链接信息
.got           # 全局偏移量表 (Global Offset Table)
.plt           # 过程链接表 (Procedure Linkage Table)
.text          # 代码段
.rodata        # 只读数据段
.data          # 已初始化数据段
.bss           # 未初始化数据段
.tbss          # 线程局部存储未初始化段 (Thread-BSS)
.tdata         # 线程局部存储已初始化段 (Thread-Data)
...
```

* **`.tbss` (Thread-BSS):**  存放未初始化的线程局部变量。动态链接器会根据此节的大小为每个线程分配空间。
* **`.tdata` (Thread-Data):** 存放已初始化的线程局部变量的初始值。当创建新线程时，这部分数据会被复制到线程的 TLS 块中。

**链接的处理过程:**

1. **编译时:** 编译器遇到 `__thread` 关键字声明的全局变量时，会在 `.tbss` 或 `.tdata` 节中为其分配空间，并生成访问这些变量的特殊代码，这些代码会使用 TLS 描述符。

2. **链接时:** 静态链接器 (在构建共享库时) 会将所有的 `.tbss` 和 `.tdata` 节合并，并生成必要的动态链接信息，包括 TLS 描述符的入口。

3. **运行时 (动态链接):** 当动态链接器加载一个包含 TLS 变量的共享库时：
   - 它会解析共享库的 ELF 头，找到 `.tbss` 和 `.tdata` 节的大小和对齐要求。
   - 调用 `register_soinfo_tls()` 注册该共享库的 TLS 信息。
   - 动态链接器会分配一块足够大的 TLS 空间，并为该共享库分配一个唯一的模块 ID 和在该 TLS 空间内的偏移量。
   - 当线程首次访问该共享库的线程局部变量时，可能会触发 TLS 描述符的解析过程。

**TLS 描述符解析过程示例:**

假设一个共享库 `libexample.so` 中定义了 `__thread int my_tls_var = 10;`。当应用程序的某个线程首次访问 `my_tls_var` 时，会发生以下步骤：

1. **代码执行:** 编译器生成的代码会尝试通过 TLS 描述符访问 `my_tls_var`。
2. **TLS 描述符:** TLS 描述符可能包含 `libexample.so` 的模块 ID 和 `my_tls_var` 在 `.tbss` 或 `.tdata` 中的偏移量。
3. **解析器调用:** 系统会调用相应的 TLS 描述符解析函数，通常是 `tlsdesc_resolver_dynamic()`。
4. **查找 `soinfo`:** 解析器根据模块 ID 找到 `libexample.so` 的 `soinfo` 结构。
5. **计算地址:**  `soinfo` 结构包含了 `libexample.so` 的 TLS 块在当前线程 TLS 区域的起始地址。解析器将该起始地址加上 `my_tls_var` 在 `.tbss` 或 `.tdata` 中的偏移量，得到 `my_tls_var` 在当前线程中的实际内存地址。
6. **返回地址:** 解析器返回计算出的地址，程序可以访问该线程局部变量。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们调用 `get_tls_module` 函数：

**假设输入:** `module_id = 2`

**逻辑推理:** 动态链接器维护着一个已加载共享库的列表和它们的 TLS 信息。模块 ID 2 可能对应于加载的某个共享库，例如 `libutils.so`。

**假设输出:**  `get_tls_module(2)` 可能会返回一个 `TlsModule` 结构，其中包含 `libutils.so` 的 TLS 相关信息，例如：

```c++
struct TlsModule {
  size_t base;        // 该模块 TLS 块在全局 TLS 区域的起始地址
  size_t size;        // 该模块 TLS 块的大小
  // ... 其他信息
};
```

`base` 字段会指向为 `libutils.so` 的线程局部变量分配的内存区域的起始地址。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **未初始化线程局部变量:**  声明了 `__thread int my_var;` 但没有初始化。在某些平台或编译器下，这可能导致未定义的行为，因为变量可能包含垃圾值。
   ```c++
   __thread int my_var; // 错误：未初始化

   void* thread_func(void*) {
       printf("my_var: %d\n", my_var); // 可能输出意想不到的值
       return nullptr;
   }
   ```

2. **在静态初始化中使用线程局部变量:**  在全局变量的初始化列表中使用线程局部变量，这是不允许的，因为在程序启动的早期，线程局部存储可能尚未完全初始化。
   ```c++
   __thread int thread_id;
   int global_var = thread_id; // 错误：在静态初始化中使用线程局部变量
   ```

3. **在错误的线程访问线程局部变量:** 虽然 TLS 的目的是让每个线程拥有自己的变量副本，但如果逻辑错误，可能会在一个线程中访问到另一个线程的“副本”（虽然实际上是不同的内存地址）。这通常是多线程同步错误导致的。

4. **假设线程局部变量在所有平台上都可用:**  虽然 `__thread` 是一个常见的扩展，但并非所有 C++ 标准都支持。编写跨平台代码时需要考虑兼容性。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 或 NDK 如何到达这里:**

1. **应用程序启动:** 当 Android 系统启动一个应用程序时，首先会 fork 一个 zygote 进程的副本。
2. **加载应用程序可执行文件:**  系统调用 `execve` 加载应用程序的可执行文件。
3. **动态链接器启动:**  内核会启动动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`)。
4. **加载依赖库:** 动态链接器会解析应用程序依赖的共享库，并逐个加载。
5. **处理 TLS (应用程序):**  在加载应用程序可执行文件时，动态链接器会调用 `linker_setup_exe_static_tls()` 来设置应用程序的静态 TLS 区域。
6. **处理 TLS (共享库):** 当加载一个包含线程局部变量的共享库时，动态链接器会调用 `register_soinfo_tls()` 来注册该库的 TLS 信息。
7. **NDK 代码:**  如果应用程序使用了 NDK 编写的本地代码，并且这些代码中使用了线程局部变量，那么在加载 NDK 库时，也会经历上述的 TLS 处理过程。
8. **访问 TLS 变量:**  当应用程序或 NDK 代码尝试访问一个线程局部变量时，编译器生成的代码会触发 TLS 描述符的解析，最终可能调用 `tlsdesc_resolver_static` 或 `tlsdesc_resolver_dynamic`。

**Frida Hook 示例:**

我们可以使用 Frida 来 hook 这些函数，观察它们的调用和参数。

```javascript
// Hook linker_setup_exe_static_tls
Interceptor.attach(Module.findExportByName(null, "linker_setup_exe_static_tls"), {
  onEnter: function(args) {
    console.log("linker_setup_exe_static_tls called with progname:", args[0].readUtf8String());
  }
});

// Hook register_soinfo_tls
Interceptor.attach(Module.findExportByName(null, "register_soinfo_tls"), {
  onEnter: function(args) {
    var soinfo = ptr(args[0]);
    var pathname = soinfo.add(Process.pointerSize * 5).readPointer().readCString(); // 假设 soinfo 结构体布局
    console.log("register_soinfo_tls called with soinfo:", soinfo, "pathname:", pathname);
  }
});

// Hook tlsdesc_resolver_static
Interceptor.attach(Module.findExportByName(null, "tlsdesc_resolver_static"), {
  onEnter: function(args) {
    console.log("tlsdesc_resolver_static called with arg:", args[0]);
  },
  onLeave: function(retval) {
    console.log("tlsdesc_resolver_static returning:", retval);
  }
});

// Hook tlsdesc_resolver_dynamic
Interceptor.attach(Module.findExportByName(null, "tlsdesc_resolver_dynamic"), {
  onEnter: function(args) {
    console.log("tlsdesc_resolver_dynamic called with arg:", args[0]);
  },
  onLeave: function(retval) {
    console.log("tlsdesc_resolver_dynamic returning:", retval);
  }
});
```

**使用方法:**

1. 将以上 JavaScript 代码保存到一个文件中，例如 `hook_tls.js`。
2. 找到你要调试的 Android 应用程序的进程 ID (PID)。
3. 使用 Frida 连接到目标进程：`frida -U -f <package_name> -l hook_tls.js --no-pause` 或者 `frida -p <pid> -l hook_tls.js`。

**调试步骤:**

1. 运行包含线程局部变量的应用程序。
2. 观察 Frida 的输出，可以看到 `linker_setup_exe_static_tls` 在应用程序启动时被调用。
3. 当加载包含线程局部变量的共享库时，会看到 `register_soinfo_tls` 被调用，并打印出共享库的路径。
4. 当应用程序或 NDK 代码访问线程局部变量时，会触发 `tlsdesc_resolver_static` 或 `tlsdesc_resolver_dynamic` 的调用，你可以观察到它们的输入参数和返回值 (线程局部变量的地址)。

通过 Frida hook，你可以深入了解 Android 动态链接器处理 TLS 的过程，并帮助你调试与线程局部变量相关的问题。请注意，`soinfo` 结构体的具体布局可能因 Android 版本而异，你可能需要根据实际情况调整 hook 代码。

Prompt: 
```
这是目录为bionic/linker/linker_tls.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <stdlib.h>

#include "private/bionic_elf_tls.h"

struct TlsModule;
struct soinfo;

void linker_setup_exe_static_tls(const char* progname);
void linker_finalize_static_tls();

void register_soinfo_tls(soinfo* si);
void unregister_soinfo_tls(soinfo* si);

const TlsModule& get_tls_module(size_t module_id);

typedef size_t TlsDescResolverFunc(size_t);

struct TlsDescriptor {
#if defined(__arm__)
  size_t arg;
  TlsDescResolverFunc* func;
#else
  TlsDescResolverFunc* func;
  size_t arg;
#endif
};

struct TlsDynamicResolverArg {
  size_t generation;
  TlsIndex index;
};

__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_static(size_t);
__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_dynamic(size_t);
__LIBC_HIDDEN__ extern "C" size_t tlsdesc_resolver_unresolved_weak(size_t);

"""

```