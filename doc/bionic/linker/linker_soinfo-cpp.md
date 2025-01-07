Response:
Let's break down the thought process for generating the comprehensive response about `linker_soinfo.cpp`.

**1. Understanding the Core Request:**

The request asks for a detailed explanation of the `linker_soinfo.cpp` file within the Android Bionic linker. Key areas to cover include functionality, relationship to Android, implementation details (especially libc functions), dynamic linking aspects, error scenarios, and how Android components reach this code. A Frida hook example is also requested.

**2. Initial High-Level Analysis of the Code:**

The code itself immediately signals its purpose. The filename "linker_soinfo.cpp" and the included headers (e.g., `dlfcn.h`, `elf.h`, `linker.h`) strongly suggest this file defines the `soinfo` structure and related operations. `soinfo` likely represents information about a shared object (SO) file loaded by the dynamic linker.

**3. Deconstructing the Request into Key Sections:**

To create a structured and comprehensive answer, I broke down the request into these major sections:

*   **File Functionality:** What is the main purpose of this file?
*   **Relationship to Android:** How does this file contribute to the overall Android system?
*   **libc Function Implementation:** Are there any standard C library functions used, and how are they used within this context?
*   **Dynamic Linker Functionality:** This is crucial. What dynamic linking features are implemented here?
*   **Error Scenarios:**  What common programming mistakes might interact with this code?
*   **Android Framework/NDK Path:** How does the system get to this code during normal operation?
*   **Frida Hook Example:**  A practical demonstration of interacting with this code.

**4. In-Depth Code Analysis (Iterative Process):**

I went through the code section by section, focusing on the following:

*   **Class `soinfo`:**  This is the central data structure. I identified its members (e.g., `realpath_`, `base`, `size`, `flags_`, various ELF header pointers, linked lists for dependencies). I deduced that it stores metadata about loaded shared libraries.
*   **Class `SymbolLookupList`:** This class manages the search order for symbols. The logic for global and local symbol lookup, as well as `DT_SYMBOLIC`, is important.
*   **Symbol Lookup Functions (`soinfo_do_lookup`, `gnu_lookup`, `elf_lookup`):** These are core to the dynamic linking process. I focused on the hash table lookups (GNU and ELF) and versioning checks.
*   **Constructor/Destructor Functions (`call_constructors`, `call_destructors`):**  These manage the execution of initialization and finalization code within shared libraries.
*   **Dependency Management (`add_child`, `remove_all_links`):**  These functions handle the relationships between loaded libraries.
*   **Flags and State:**  I paid attention to the various flags within the `soinfo` structure that track the state of the loaded library (e.g., `FLAG_LINKED`, `FLAG_EXE`).
*   **Handle Management:** The generation and use of unique handles for shared libraries are important for `dlopen` and related functions.
*   **Helper Functions:** I noted the utility functions like `calculate_gnu_hash`, `check_symbol_version`, and the tracing macros.

**5. Connecting Code to Concepts:**

As I analyzed the code, I linked it back to fundamental dynamic linking concepts:

*   **Shared Objects:** The entire file revolves around the concept of shared libraries and their metadata.
*   **Symbol Resolution:** The `SymbolLookupList` and the lookup functions directly implement the process of finding symbols.
*   **Relocation:** While this file doesn't perform the relocation *itself*, it provides the context and information needed for the relocation process (handled in `linker_relocate.cpp`).
*   **Initialization and Finalization:**  The constructor/destructor calling mechanisms are vital for proper library loading and unloading.
*   **Dependencies:** The parent-child relationships between `soinfo` objects represent the dependency graph of loaded libraries.
*   **Namespaces:** The involvement of `android_namespace_t` shows how Android isolates libraries.
*   **Versioning:** The versioning checks (`check_symbol_version`) address compatibility issues between libraries.
*   **Handles:** The handles are crucial for the `dlopen`/`dlsym`/`dlclose` API.

**6. Generating Examples and Explanations:**

For each section, I aimed to provide clear explanations and illustrative examples:

*   **Relationship to Android:** I used `dlopen` as a concrete example of how this code gets used.
*   **libc Functions:** I focused on functions like `strcmp`, `memcmp`, `strcpy`, `strlen`, and `dlerror` and explained their role in the linker's operations.
*   **Dynamic Linking:**  I created a simplified SO layout and described the linking process steps.
*   **Error Scenarios:** I focused on common mistakes like missing dependencies and symbol conflicts.
*   **Frida Hook:** I constructed a basic Frida script that demonstrates how to intercept a function within this file.

**7. Structuring the Output:**

I organized the information logically using headings and bullet points to make it easy to read and understand. I also used code formatting for clarity.

**8. Refinement and Review:**

I reviewed the generated response to ensure accuracy, completeness, and clarity. I checked that the examples were relevant and the explanations were easy to follow.

**Self-Correction/Refinement during the Process:**

*   Initially, I might have focused too much on low-level details of the hash functions. I then realized the higher-level concepts of symbol lookup and dependency management were more important for the overall understanding.
*   I made sure to connect the code snippets back to the bigger picture of how Android loads and manages shared libraries.
*   I added explanations of the data structures like `SymbolLookupList` to clarify their purpose.
*   I ensured the Frida example was practical and demonstrated a useful interaction with the code.

By following this iterative process of analysis, understanding, and explanation, I could generate a comprehensive and informative response to the original request.
好的，我们来详细分析 `bionic/linker/linker_soinfo.cpp` 文件的功能和实现细节。

**文件功能总览**

`linker_soinfo.cpp` 文件定义了 `soinfo` 结构体及其相关操作。`soinfo` 是 Android 动态链接器 (linker) 中一个核心的数据结构，用于存储和管理有关已加载共享对象 (Shared Object, SO) 的信息。 它的主要功能包括：

1. **存储共享对象元数据:**  例如共享对象的路径、加载地址、大小、依赖关系、符号表、重定位表等信息。
2. **支持符号查找:**  实现共享对象内部以及跨共享对象的符号查找机制，是动态链接的核心功能。
3. **管理共享对象的生命周期:**  包括加载、初始化、卸载等过程中的状态管理。
4. **处理构造函数和析构函数:**  负责调用共享对象中的初始化和清理函数。
5. **维护共享对象的依赖关系:**  记录共享对象的父子依赖关系。
6. **处理版本信息:**  支持符号版本控制。
7. **提供访问共享对象信息的接口:**  允许 linker 的其他模块访问和修改共享对象的信息。

**与 Android 功能的关系及举例**

`linker_soinfo.cpp` 文件是 Android 动态链接器的关键组成部分，而动态链接器是 Android 平台的核心基础设施之一，负责加载和链接应用程序以及其依赖的共享库。

**举例说明:**

*   **应用程序启动:** 当 Android 系统启动一个应用程序时，zygote 进程 fork 出新的进程。 新进程在执行 `main` 函数之前，需要加载应用程序依赖的共享库（例如 `libc.so`, `libm.so`, `libart.so` 等）。 linker 会为每个加载的共享库创建一个 `soinfo` 对象，用于跟踪其信息。
*   **`dlopen()` 函数:**  当应用程序调用 `dlopen()` 函数动态加载一个共享库时，linker 会创建或查找该共享库的 `soinfo` 对象，并将其加入到进程的地址空间中。
*   **符号解析:**  应用程序或共享库在调用其他共享库中的函数或访问其全局变量时，linker 需要进行符号解析，找到符号对应的地址。 `soinfo` 对象存储了符号表等信息，用于支持高效的符号查找。
*   **版本控制:** Android 系统使用符号版本控制来处理不同版本共享库之间的兼容性问题。 `soinfo` 结构体中包含了版本信息，linker 在进行符号查找时会考虑版本匹配。

**详细解释 libc 函数的功能实现**

`linker_soinfo.cpp` 文件中使用的 libc 函数主要是为了进行字符串操作、内存比较和文件系统操作：

*   **`strcmp(const char* str1, const char* str2)`:**  用于比较两个字符串是否相等。在 `soinfo::gnu_lookup` 和 `soinfo::elf_lookup` 函数中，用于比较目标符号的名称和符号表中找到的符号名称。
    *   **实现:**  逐个字符比较两个字符串，直到遇到不相等的字符或者字符串结尾。如果所有字符都相等且都到达结尾，则返回 0，否则返回非 0 值。
*   **`memcmp(const void* ptr1, const void* ptr2, size_t num)`:**  用于比较两块内存区域的内容是否相等。在 `soinfo::gnu_lookup` 中，用于快速比较符号名称的前 `name_len + 1` 个字节。
    *   **实现:**  逐个字节比较两块内存区域，直到遇到不相等的字节或者比较完指定的字节数。如果所有字节都相等，则返回 0，否则返回非 0 值。
*   **`strcpy(char* dest, const char* src)` (虽然代码中没有直接调用，但 `strlcpy` 类似):** 用于将源字符串复制到目标字符串。在 `soinfo::set_soname` 中，用于复制 soname。
    *   **实现:**  逐个字符将源字符串复制到目标字符串，直到遇到源字符串的空终止符 `\0`。注意 `strcpy` 可能存在缓冲区溢出的风险，因此更安全的做法是使用 `strlcpy` 或 `strncpy`。
*   **`strlen(const char* str)`:**  用于计算字符串的长度（不包括空终止符）。在计算哈希值或者比较字符串长度时可能会用到。
    *   **实现:**  从字符串的起始地址开始遍历，直到遇到空终止符 `\0`，返回遍历的字符数。
*   **`stat(const char* pathname, struct stat* buf)`:**  用于获取文件的状态信息，例如文件大小、修改时间等。 在 `soinfo` 的构造函数中，可以用来获取共享对象的文件信息。
    *   **实现:**  调用内核提供的系统调用，获取指定路径文件的元数据信息，并将结果存储在 `struct stat` 结构体中。
*   **`open(const char* pathname, int flags, ...)` (间接使用):**  用于打开文件。linker 在加载共享库时需要打开文件读取其内容。
    *   **实现:**  调用内核提供的系统调用，根据指定的路径和标志打开文件，返回一个文件描述符。
*   **`read(int fd, void* buf, size_t count)` (间接使用):**  用于从打开的文件中读取数据。linker 读取共享库的 ELF 头、段表、符号表等信息。
    *   **实现:**  调用内核提供的系统调用，从指定的文件描述符读取最多 `count` 个字节的数据到缓冲区 `buf` 中。
*   **`close(int fd)` (间接使用):** 用于关闭打开的文件描述符。
    *   **实现:**  调用内核提供的系统调用，释放与指定文件描述符相关的系统资源。
*   **`unistd.h` 中的其他函数 (例如 `getpid`, `gettid` 等):**  可能用于日志记录或调试。

**涉及 dynamic linker 的功能，so 布局样本以及链接的处理过程**

`linker_soinfo.cpp` 文件是动态链接器实现的核心部分，它直接参与了共享对象的加载、符号解析和初始化过程。

**SO 布局样本:**

一个典型的共享对象 (SO) 文件的布局如下（简化）：

```
.ELF Header
.Program Headers (LOAD segments)
.dynamic section (DT_NEEDED, DT_SYMTAB, DT_STRTAB, DT_HASH/DT_GNU_HASH, DT_REL/DT_RELA, DT_INIT, DT_FINI, etc.)
.hash or .gnu.hash section (符号哈希表)
.dynsym section (动态符号表)
.dynstr section (动态字符串表)
.rel.dyn or .rela.dyn section (数据重定位表)
.rel.plt or .rela.plt section (PLT 重定位表)
.init section (初始化代码)
.fini section (清理代码)
... 其他段 ...
```

**链接的处理过程 (与 `linker_soinfo.cpp` 相关的部分):**

1. **加载共享对象:**
    *   linker 调用 `mmap` 将共享对象的文件内容映射到进程的地址空间。
    *   为该共享对象创建一个 `soinfo` 对象，并填充其成员变量，包括基地址 (`base`)、大小 (`size`)、文件名 (`realpath_`, `soname_`) 等。
    *   解析 ELF header 和 program headers，获取各个段的地址和大小。
    *   读取 `.dynamic` section，从中获取符号表 (`symtab_`, `strtab_`)、哈希表 (`gnu_hash_`, `bucket_`, `chain_`)、重定位表 (`plt_reloc_`, `reloc_`)、初始化/清理函数地址 (`init_func_`, `fini_func_`)、依赖项 (`DT_NEEDED`) 等信息。

2. **处理依赖关系:**
    *   解析 `DT_NEEDED` 条目，确定当前共享对象依赖的其他共享对象。
    *   递归地加载这些依赖的共享对象，并为它们创建 `soinfo` 对象。
    *   维护 `soinfo` 对象之间的父子关系 (`children_`, `parents_`)。

3. **符号解析:**
    *   当需要解析一个符号时（例如，在重定位过程中或者调用 `dlsym`），linker 会根据 `soinfo` 对象中存储的符号表和哈希表进行查找。
    *   `SymbolLookupList` 类用于管理符号查找的顺序，它会考虑全局符号、局部符号以及 `DT_SYMBOLIC` 标志的影响。
    *   `soinfo::gnu_lookup` 和 `soinfo::elf_lookup` 函数实现了基于 GNU hash 和 ELF hash 的符号查找算法。
    *   会进行版本检查，确保找到的符号版本与需求匹配。
    *   如果找到符号，则返回符号的地址；否则，返回错误。

4. **执行初始化函数:**
    *   在所有必要的共享对象都被加载和链接后，linker 会遍历 `soinfo` 列表，并调用每个共享对象的初始化函数（`DT_INIT` 和 `DT_INIT_ARRAY`）。 `soinfo::call_constructors` 函数负责执行此过程。

5. **卸载共享对象:**
    *   当通过 `dlclose` 卸载一个共享对象时，linker 会调用该共享对象的清理函数（`DT_FINI` 和 `DT_FINI_ARRAY`）。 `soinfo::call_destructors` 函数负责执行此过程。
    *   解除该共享对象在进程地址空间的映射。
    *   删除对应的 `soinfo` 对象。

**逻辑推理的假设输入与输出**

假设我们有以下两个共享库 `liba.so` 和 `libb.so`，`liba.so` 依赖于 `libb.so`。

**假设输入:**

*   应用程序尝试加载 `liba.so`。
*   `liba.so` 的 `.dynamic` section 中包含 `DT_NEEDED` 条目，指向 `libb.so`。
*   `liba.so` 中有一个未定义的符号 `symbol_from_b`，该符号在 `libb.so` 中定义。

**逻辑推理过程 (与 `linker_soinfo.cpp` 相关):**

1. linker 首先为 `liba.so` 创建一个 `soinfo` 对象 (`soinfo_a`)，并解析其 ELF 头和段信息。
2. linker 在 `soinfo_a` 的 `.dynamic` section 中找到 `DT_NEEDED` 条目，指向 `libb.so`。
3. linker 查找 `libb.so`，如果尚未加载，则为其创建一个 `soinfo` 对象 (`soinfo_b`)，并加载 `libb.so`。
4. linker 将 `soinfo_b` 添加到 `soinfo_a` 的依赖列表 (`children_`) 中，并将 `soinfo_a` 添加到 `soinfo_b` 的被依赖列表 (`parents_`) 中。
5. 在重定位 `liba.so` 时，linker 遇到未定义的符号 `symbol_from_b`。
6. linker 创建一个 `SymbolLookupList`，其中包含了 `soinfo_a` 和其依赖项 `soinfo_b`。
7. linker 使用 `soinfo::gnu_lookup` 或 `soinfo::elf_lookup` 在 `soinfo_b` 的符号表中查找 `symbol_from_b`。
8. 如果找到 `symbol_from_b`，则获取其地址，并完成 `liba.so` 中对该符号的重定位。

**输出:**

*   成功加载 `liba.so` 和 `libb.so`。
*   `soinfo_a` 和 `soinfo_b` 对象被创建，并包含了各自共享库的信息。
*   `soinfo_a->children_` 包含 `soinfo_b`。
*   `soinfo_b->parents_` 包含 `soinfo_a`。
*   `liba.so` 中 `symbol_from_b` 的引用被正确地解析到 `libb.so` 中定义的地址。

**用户或编程常见的使用错误**

与 `linker_soinfo.cpp` 相关的常见用户或编程错误包括：

1. **缺少依赖库:**  如果应用程序依赖的共享库没有被加载，linker 将无法找到符号，导致加载失败或运行时崩溃。
    *   **错误示例:**  应用程序依赖 `libfoo.so`，但是没有将 `libfoo.so` 打包到 APK 中或者没有将其放在系统库路径下。
2. **符号冲突:**  不同的共享库中定义了相同的全局符号，导致 linker 无法确定使用哪个符号。
    *   **错误示例:**  `libbar.so` 和 `libbaz.so` 都定义了一个名为 `global_var` 的全局变量。
3. **版本不兼容:**  应用程序或共享库依赖特定版本的共享库，但系统中加载的是不兼容的版本。
    *   **错误示例:**  应用程序使用 `libcrypto.so` 的某个新版本提供的 API，但系统中安装的是旧版本的 `libcrypto.so`。
4. **循环依赖:**  两个或多个共享库相互依赖，导致 linker 陷入死循环。
    *   **错误示例:**  `libc.so` 依赖 `libm.so`，而 `libm.so` 又依赖 `libc.so`。虽然 bionic linker 有一定的循环依赖处理机制，但过于复杂的循环依赖仍然可能导致问题。
5. **在构造函数中 `dlopen` 自身或依赖库:**  这可能导致无限递归的构造函数调用，最终导致栈溢出。
    *   **错误示例:**  `libself.so` 的构造函数中调用 `dlopen("libself.so")`。

**Android framework 或 NDK 如何一步步到达这里**

以下是一个简化的调用链，说明 Android framework 或 NDK 如何最终涉及到 `linker_soinfo.cpp` 中的代码：

1. **应用程序启动 (Framework):**
    *   `ActivityManagerService` (AMS) 决定启动一个新的 Activity。
    *   AMS 通过 `Zygote` 进程 fork 出新的应用程序进程。
    *   新进程执行应用程序的 `main` 函数之前，`linker` (位于 `/system/bin/linker64` 或 `/system/bin/linker`) 被内核调用。
    *   `linker` 首先加载自身，并创建自身的 `soinfo` 对象。
    *   `linker` 根据应用程序的配置信息，加载应用程序依赖的共享库（例如 `libc.so`, `libart.so` 等）。
    *   在加载每个共享库时，`linker` 会创建一个 `soinfo` 对象，并调用 `linker_soinfo.cpp` 中的代码来初始化该对象，读取 ELF 头信息，解析符号表等。

2. **NDK 开发，使用 `dlopen` (NDK):**
    *   使用 NDK 开发的应用程序可以通过 `dlopen()` 函数动态加载共享库。
    *   当应用程序调用 `dlopen()` 时，会调用到 bionic 的 `dlopen` 实现。
    *   bionic 的 `dlopen` 实现会调用 `linker` 的相关函数来加载共享库。
    *   `linker` 会为新加载的共享库创建一个 `soinfo` 对象，并调用 `linker_soinfo.cpp` 中的代码来完成相关操作。

**Frida hook 示例调试这些步骤**

可以使用 Frida hook `soinfo` 结构体中的关键函数，例如 `soinfo::call_constructors` 或符号查找函数，来观察共享库的加载和初始化过程。

```javascript
// hook soinfo::call_constructors
Interceptor.attach(Module.findExportByName(null, "_ZN6soinfo16call_constructorsEv"), {
  onEnter: function (args) {
    console.log("[call_constructors] Calling constructors for soinfo:", this.context);
    // 可以进一步访问 this 对象，例如获取 realpath_
    const realpathPtr = this.context.r0.add(Process.pointerSize * 2); // 假设 realpath_ 是 soinfo 的第三个成员
    const realpath = Memory.readUtf8String(realpathPtr.readPointer());
    console.log("[call_constructors] Realpath:", realpath);
  },
  onLeave: function (retval) {
    console.log("[call_constructors] Finished calling constructors.");
  }
});

// hook soinfo::gnu_lookup
Interceptor.attach(Module.findExportByName(null, "_ZN6soinfo9gnu_lookupER10SymbolNamePK12version_info"), {
  onEnter: function (args) {
    const symbolNamePtr = args[1];
    const symbolName = Memory.readCString(Memory.readPointer(symbolNamePtr));
    console.log("[gnu_lookup] Searching for symbol:", symbolName);
    // 可以查看 soinfo 对象的信息
    console.log("[gnu_lookup] in soinfo:", this.context);
  },
  onLeave: function (retval) {
    if (retval.isNull()) {
      console.log("[gnu_lookup] Symbol not found.");
    } else {
      console.log("[gnu_lookup] Symbol found at:", retval);
    }
  }
});
```

**解释 Frida Hook 示例:**

*   **`Interceptor.attach(...)`:** Frida 的核心函数，用于拦截函数调用。
*   **`Module.findExportByName(null, "_ZN6soinfo16call_constructorsEv")`:**  查找名为 `_ZN6soinfo16call_constructorsEv` 的导出函数。这是 `soinfo::call_constructors` 的符号名（需要 demangle）。 `null` 表示在所有已加载的模块中查找。
*   **`onEnter: function (args)`:**  在目标函数执行之前调用。`args` 是传递给目标函数的参数。`this.context` 指向 `soinfo` 对象的指针（根据调用约定）。
*   **`onLeave: function (retval)`:** 在目标函数执行之后调用。`retval` 是目标函数的返回值。
*   **`Memory.readUtf8String(...)` 和 `Memory.readCString(...)`:**  用于读取内存中的字符串。

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_soinfo.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <your_package_name> -l hook_soinfo.js --no-pause
   ```
   或者连接到正在运行的进程：
   ```bash
   frida -U <process_id_or_package_name> -l hook_soinfo.js
   ```
3. 当应用程序加载共享库或进行符号查找时，Frida 会打印出相应的日志信息，帮助你理解 linker 的工作过程。

希望以上详细的解释能够帮助你理解 `bionic/linker/linker_soinfo.cpp` 文件的功能和实现细节。

Prompt: 
```
这是目录为bionic/linker/linker_soinfo.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include "linker_soinfo.h"

#include <dlfcn.h>
#include <elf.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <async_safe/log.h>

#include "linker.h"
#include "linker_config.h"
#include "linker_debug.h"
#include "linker_globals.h"
#include "linker_gnu_hash.h"
#include "linker_logger.h"
#include "linker_relocate.h"
#include "linker_utils.h"
#include "platform/bionic/mte.h"
#include "private/bionic_globals.h"

SymbolLookupList::SymbolLookupList(soinfo* si)
    : sole_lib_(si->get_lookup_lib()), begin_(&sole_lib_), end_(&sole_lib_ + 1) {
  CHECK(si != nullptr);
  slow_path_count_ += !!g_linker_debug_config.lookup;
  slow_path_count_ += sole_lib_.needs_sysv_lookup();
}

SymbolLookupList::SymbolLookupList(const soinfo_list_t& global_group, const soinfo_list_t& local_group) {
  slow_path_count_ += !!g_linker_debug_config.lookup;
  libs_.reserve(1 + global_group.size() + local_group.size());

  // Reserve a space in front for DT_SYMBOLIC lookup.
  libs_.push_back(SymbolLookupLib {});

  global_group.for_each([this](soinfo* si) {
    libs_.push_back(si->get_lookup_lib());
    slow_path_count_ += libs_.back().needs_sysv_lookup();
  });

  local_group.for_each([this](soinfo* si) {
    libs_.push_back(si->get_lookup_lib());
    slow_path_count_ += libs_.back().needs_sysv_lookup();
  });

  begin_ = &libs_[1];
  end_ = &libs_[0] + libs_.size();
}

/* "This element's presence in a shared object library alters the dynamic linker's
 * symbol resolution algorithm for references within the library. Instead of starting
 * a symbol search with the executable file, the dynamic linker starts from the shared
 * object itself. If the shared object fails to supply the referenced symbol, the
 * dynamic linker then searches the executable file and other shared objects as usual."
 *
 * http://www.sco.com/developers/gabi/2012-12-31/ch5.dynamic.html
 *
 * Note that this is unlikely since static linker avoids generating
 * relocations for -Bsymbolic linked dynamic executables.
 */
void SymbolLookupList::set_dt_symbolic_lib(soinfo* lib) {
  CHECK(!libs_.empty());
  slow_path_count_ -= libs_[0].needs_sysv_lookup();
  libs_[0] = lib ? lib->get_lookup_lib() : SymbolLookupLib();
  slow_path_count_ += libs_[0].needs_sysv_lookup();
  begin_ = lib ? &libs_[0] : &libs_[1];
}

// Check whether a requested version matches the version on a symbol definition. There are a few
// special cases:
//  - If the defining DSO has no version info at all, then any version matches.
//  - If no version is requested (vi==nullptr, verneed==kVersymNotNeeded), then any non-hidden
//    version matches.
//  - If the requested version is not defined by the DSO, then verneed is kVersymGlobal, and only
//    global symbol definitions match. (This special case is handled as part of the ordinary case
//    where the version must match exactly.)
static inline bool check_symbol_version(const ElfW(Versym)* ver_table, uint32_t sym_idx,
                                        const ElfW(Versym) verneed) {
  if (ver_table == nullptr) return true;
  const uint32_t verdef = ver_table[sym_idx];
  return (verneed == kVersymNotNeeded) ?
      !(verdef & kVersymHiddenBit) :
      verneed == (verdef & ~kVersymHiddenBit);
}

template <bool IsGeneral>
__attribute__((noinline)) static const ElfW(Sym)*
soinfo_do_lookup_impl(const char* name, const version_info* vi,
                      soinfo** si_found_in, const SymbolLookupList& lookup_list) {
  const auto [ hash, name_len ] = calculate_gnu_hash(name);
  constexpr uint32_t kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
  SymbolName elf_symbol_name(name);

  const SymbolLookupLib* end = lookup_list.end();
  const SymbolLookupLib* it = lookup_list.begin();

  while (true) {
    const SymbolLookupLib* lib;
    uint32_t sym_idx;

    // Iterate over libraries until we find one whose Bloom filter matches the symbol we're
    // searching for.
    while (true) {
      if (it == end) return nullptr;
      lib = it++;

      if (IsGeneral && lib->needs_sysv_lookup()) {
        if (const ElfW(Sym)* sym = lib->si_->find_symbol_by_name(elf_symbol_name, vi)) {
          *si_found_in = lib->si_;
          return sym;
        }
        continue;
      }

      if (IsGeneral) {
        LD_DEBUG(lookup, "SEARCH %s in %s@%p (gnu)",
                 name, lib->si_->get_realpath(), reinterpret_cast<void*>(lib->si_->base));
      }

      const uint32_t word_num = (hash / kBloomMaskBits) & lib->gnu_maskwords_;
      const ElfW(Addr) bloom_word = lib->gnu_bloom_filter_[word_num];
      const uint32_t h1 = hash % kBloomMaskBits;
      const uint32_t h2 = (hash >> lib->gnu_shift2_) % kBloomMaskBits;

      if ((1 & (bloom_word >> h1) & (bloom_word >> h2)) == 1) {
        sym_idx = lib->gnu_bucket_[hash % lib->gnu_nbucket_];
        if (sym_idx != 0) {
          break;
        }
      }
    }

    // Search the library's hash table chain.
    ElfW(Versym) verneed = kVersymNotNeeded;
    bool calculated_verneed = false;

    uint32_t chain_value = 0;
    const ElfW(Sym)* sym = nullptr;

    do {
      sym = lib->symtab_ + sym_idx;
      chain_value = lib->gnu_chain_[sym_idx];
      if ((chain_value >> 1) == (hash >> 1)) {
        if (vi != nullptr && !calculated_verneed) {
          calculated_verneed = true;
          verneed = find_verdef_version_index(lib->si_, vi);
        }
        if (check_symbol_version(lib->versym_, sym_idx, verneed) &&
            static_cast<size_t>(sym->st_name) + name_len + 1 <= lib->strtab_size_ &&
            memcmp(lib->strtab_ + sym->st_name, name, name_len + 1) == 0 &&
            is_symbol_global_and_defined(lib->si_, sym)) {
          *si_found_in = lib->si_;
          return sym;
        }
      }
      ++sym_idx;
    } while ((chain_value & 1) == 0);
  }
}

const ElfW(Sym)* soinfo_do_lookup(const char* name, const version_info* vi,
                                  soinfo** si_found_in, const SymbolLookupList& lookup_list) {
  return lookup_list.needs_slow_path() ?
      soinfo_do_lookup_impl<true>(name, vi, si_found_in, lookup_list) :
      soinfo_do_lookup_impl<false>(name, vi, si_found_in, lookup_list);
}

soinfo::soinfo(android_namespace_t* ns, const char* realpath, const struct stat* file_stat,
               off64_t file_offset, int rtld_flags) {
  if (realpath != nullptr) {
    realpath_ = realpath;
  }

  flags_ = FLAG_NEW_SOINFO;
  version_ = SOINFO_VERSION;

  if (file_stat != nullptr) {
    this->st_dev_ = file_stat->st_dev;
    this->st_ino_ = file_stat->st_ino;
    this->file_offset_ = file_offset;
  }

  this->rtld_flags_ = rtld_flags;
  this->primary_namespace_ = ns;
}

soinfo::~soinfo() {
  g_soinfo_handles_map.erase(handle_);
}

void soinfo::set_dt_runpath(const char* path) {
  if (!has_min_version(3)) {
    return;
  }

  std::vector<std::string> runpaths;

  split_path(path, ":", &runpaths);

  std::string origin = dirname(get_realpath());
  // FIXME: add $PLATFORM.
  std::vector<std::pair<std::string, std::string>> params = {
    {"ORIGIN", origin},
    {"LIB", kLibPath},
  };
  for (auto&& s : runpaths) {
    format_string(&s, params);
  }

  resolve_paths(runpaths, &dt_runpath_);
}

const ElfW(Versym)* soinfo::get_versym(size_t n) const {
  auto table = get_versym_table();
  return table ? table + n : nullptr;
}

ElfW(Addr) soinfo::get_verneed_ptr() const {
  if (has_min_version(2)) {
    return verneed_ptr_;
  }

  return 0;
}

size_t soinfo::get_verneed_cnt() const {
  if (has_min_version(2)) {
    return verneed_cnt_;
  }

  return 0;
}

ElfW(Addr) soinfo::get_verdef_ptr() const {
  if (has_min_version(2)) {
    return verdef_ptr_;
  }

  return 0;
}

size_t soinfo::get_verdef_cnt() const {
  if (has_min_version(2)) {
    return verdef_cnt_;
  }

  return 0;
}

SymbolLookupLib soinfo::get_lookup_lib() {
  SymbolLookupLib result {};
  result.si_ = this;

  // For libs that only have SysV hashes, leave the gnu_bloom_filter_ field NULL to signal that
  // the fallback code path is needed.
  if (!is_gnu_hash()) {
    return result;
  }

  result.gnu_maskwords_ = gnu_maskwords_;
  result.gnu_shift2_ = gnu_shift2_;
  result.gnu_bloom_filter_ = gnu_bloom_filter_;

  result.strtab_ = strtab_;
  result.strtab_size_ = strtab_size_;
  result.symtab_ = symtab_;
  result.versym_ = get_versym_table();

  result.gnu_chain_ = gnu_chain_;
  result.gnu_nbucket_ = gnu_nbucket_;
  result.gnu_bucket_ = gnu_bucket_;

  return result;
}

const ElfW(Sym)* soinfo::find_symbol_by_name(SymbolName& symbol_name,
                                             const version_info* vi) const {
  return is_gnu_hash() ? gnu_lookup(symbol_name, vi) : elf_lookup(symbol_name, vi);
}

ElfW(Addr) soinfo::apply_memtag_if_mte_globals(ElfW(Addr) sym_addr) const {
  if (!should_tag_memtag_globals()) return sym_addr;
  if (sym_addr == 0) return sym_addr;  // Handle undefined weak symbols.
  return reinterpret_cast<ElfW(Addr)>(get_tagged_address(reinterpret_cast<void*>(sym_addr)));
}

const ElfW(Sym)* soinfo::gnu_lookup(SymbolName& symbol_name, const version_info* vi) const {
  const uint32_t hash = symbol_name.gnu_hash();

  constexpr uint32_t kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
  const uint32_t word_num = (hash / kBloomMaskBits) & gnu_maskwords_;
  const ElfW(Addr) bloom_word = gnu_bloom_filter_[word_num];
  const uint32_t h1 = hash % kBloomMaskBits;
  const uint32_t h2 = (hash >> gnu_shift2_) % kBloomMaskBits;

  LD_DEBUG(lookup, "SEARCH %s in %s@%p (gnu)",
           symbol_name.get_name(), get_realpath(), reinterpret_cast<void*>(base));

  // test against bloom filter
  if ((1 & (bloom_word >> h1) & (bloom_word >> h2)) == 0) {
    return nullptr;
  }

  // bloom test says "probably yes"...
  uint32_t n = gnu_bucket_[hash % gnu_nbucket_];

  if (n == 0) {
    return nullptr;
  }

  const ElfW(Versym) verneed = find_verdef_version_index(this, vi);
  const ElfW(Versym)* versym = get_versym_table();

  do {
    ElfW(Sym)* s = symtab_ + n;
    if (((gnu_chain_[n] ^ hash) >> 1) == 0 &&
        check_symbol_version(versym, n, verneed) &&
        strcmp(get_string(s->st_name), symbol_name.get_name()) == 0 &&
        is_symbol_global_and_defined(this, s)) {
      return symtab_ + n;
    }
  } while ((gnu_chain_[n++] & 1) == 0);

  return nullptr;
}

const ElfW(Sym)* soinfo::elf_lookup(SymbolName& symbol_name, const version_info* vi) const {
  uint32_t hash = symbol_name.elf_hash();

  LD_DEBUG(lookup, "SEARCH %s in %s@%p h=%x(elf) %zd",
           symbol_name.get_name(), get_realpath(),
           reinterpret_cast<void*>(base), hash, hash % nbucket_);

  const ElfW(Versym) verneed = find_verdef_version_index(this, vi);
  const ElfW(Versym)* versym = get_versym_table();

  for (uint32_t n = bucket_[hash % nbucket_]; n != 0; n = chain_[n]) {
    ElfW(Sym)* s = symtab_ + n;

    if (check_symbol_version(versym, n, verneed) &&
        strcmp(get_string(s->st_name), symbol_name.get_name()) == 0 &&
        is_symbol_global_and_defined(this, s)) {
      return symtab_ + n;
    }
  }

  return nullptr;
}

ElfW(Sym)* soinfo::find_symbol_by_address(const void* addr) {
  return is_gnu_hash() ? gnu_addr_lookup(addr) : elf_addr_lookup(addr);
}

static bool symbol_matches_soaddr(const ElfW(Sym)* sym, ElfW(Addr) soaddr) {
  // Skip TLS symbols. A TLS symbol's value is relative to the start of the TLS segment rather than
  // to the start of the solib. The solib only reserves space for the initialized part of the TLS
  // segment. (i.e. .tdata is followed by .tbss, and .tbss overlaps other sections.)
  return sym->st_shndx != SHN_UNDEF &&
      ELF_ST_TYPE(sym->st_info) != STT_TLS &&
      soaddr >= sym->st_value &&
      soaddr < sym->st_value + sym->st_size;
}

ElfW(Sym)* soinfo::gnu_addr_lookup(const void* addr) {
  ElfW(Addr) soaddr = reinterpret_cast<ElfW(Addr)>(addr) - load_bias;

  for (size_t i = 0; i < gnu_nbucket_; ++i) {
    uint32_t n = gnu_bucket_[i];

    if (n == 0) {
      continue;
    }

    do {
      ElfW(Sym)* sym = symtab_ + n;
      if (symbol_matches_soaddr(sym, soaddr)) {
        return sym;
      }
    } while ((gnu_chain_[n++] & 1) == 0);
  }

  return nullptr;
}

ElfW(Sym)* soinfo::elf_addr_lookup(const void* addr) {
  ElfW(Addr) soaddr = reinterpret_cast<ElfW(Addr)>(addr) - load_bias;

  // Search the library's symbol table for any defined symbol which
  // contains this address.
  for (size_t i = 0; i < nchain_; ++i) {
    ElfW(Sym)* sym = symtab_ + i;
    if (symbol_matches_soaddr(sym, soaddr)) {
      return sym;
    }
  }

  return nullptr;
}

static void call_function(const char* function_name __unused,
                          linker_ctor_function_t function,
                          const char* realpath __unused) {
  if (function == nullptr || reinterpret_cast<uintptr_t>(function) == static_cast<uintptr_t>(-1)) {
    return;
  }

  LD_DEBUG(calls, "[ Calling c-tor %s @ %p for '%s' ]", function_name, function, realpath);
  function(g_argc, g_argv, g_envp);
  LD_DEBUG(calls, "[ Done calling c-tor %s @ %p for '%s' ]", function_name, function, realpath);
}

static void call_function(const char* function_name __unused,
                          linker_dtor_function_t function,
                          const char* realpath __unused) {
  if (function == nullptr || reinterpret_cast<uintptr_t>(function) == static_cast<uintptr_t>(-1)) {
    return;
  }

  LD_DEBUG(calls, "[ Calling d-tor %s @ %p for '%s' ]", function_name, function, realpath);
  function();
  LD_DEBUG(calls, "[ Done calling d-tor %s @ %p for '%s' ]", function_name, function, realpath);
}

template <typename F>
static inline void call_array(const char* array_name __unused, F* functions, size_t count,
                              bool reverse, const char* realpath) {
  if (functions == nullptr) {
    return;
  }

  LD_DEBUG(calls, "[ Calling %s (size %zd) @ %p for '%s' ]", array_name, count, functions, realpath);

  int begin = reverse ? (count - 1) : 0;
  int end = reverse ? -1 : count;
  int step = reverse ? -1 : 1;

  for (int i = begin; i != end; i += step) {
    LD_DEBUG(calls, "[ %s[%d] == %p ]", array_name, i, functions[i]);
    call_function("function", functions[i], realpath);
  }

  LD_DEBUG(calls, "[ Done calling %s for '%s' ]", array_name, realpath);
}

void soinfo::call_pre_init_constructors() {
  // DT_PREINIT_ARRAY functions are called before any other constructors for executables,
  // but ignored in a shared library.
  call_array("DT_PREINIT_ARRAY", preinit_array_, preinit_array_count_, false, get_realpath());
}

void soinfo::call_constructors() {
  if (constructors_called) {
    return;
  }

  // We set constructors_called before actually calling the constructors, otherwise it doesn't
  // protect against recursive constructor calls. One simple example of constructor recursion
  // is the libc debug malloc, which is implemented in libc_malloc_debug_leak.so:
  // 1. The program depends on libc, so libc's constructor is called here.
  // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
  // 3. dlopen() calls the constructors on the newly created
  //    soinfo for libc_malloc_debug_leak.so.
  // 4. The debug .so depends on libc, so CallConstructors is
  //    called again with the libc soinfo. If it doesn't trigger the early-
  //    out above, the libc constructor will be called again (recursively!).
  constructors_called = true;

  if (!is_main_executable() && preinit_array_ != nullptr) {
    // The GNU dynamic linker silently ignores these, but we warn the developer.
    DL_WARN("\"%s\": ignoring DT_PREINIT_ARRAY in shared library!", get_realpath());
  }

  get_children().for_each([] (soinfo* si) {
    si->call_constructors();
  });

  if (!is_linker()) {
    bionic_trace_begin((std::string("calling constructors: ") + get_realpath()).c_str());
  }

  // DT_INIT should be called before DT_INIT_ARRAY if both are present.
  call_function("DT_INIT", init_func_, get_realpath());
  call_array("DT_INIT_ARRAY", init_array_, init_array_count_, false, get_realpath());

  if (!is_linker()) {
    bionic_trace_end();
  }
}

void soinfo::call_destructors() {
  if (!constructors_called) {
    return;
  }

  ScopedTrace trace((std::string("calling destructors: ") + get_realpath()).c_str());

  // DT_FINI_ARRAY must be parsed in reverse order.
  call_array("DT_FINI_ARRAY", fini_array_, fini_array_count_, true, get_realpath());

  // DT_FINI should be called after DT_FINI_ARRAY if both are present.
  call_function("DT_FINI", fini_func_, get_realpath());
}

void soinfo::add_child(soinfo* child) {
  if (has_min_version(0)) {
    child->parents_.push_back(this);
    this->children_.push_back(child);
  }
}

void soinfo::remove_all_links() {
  if (!has_min_version(0)) {
    return;
  }

  // 1. Untie connected soinfos from 'this'.
  children_.for_each([&] (soinfo* child) {
    child->parents_.remove_if([&] (const soinfo* parent) {
      return parent == this;
    });
  });

  parents_.for_each([&] (soinfo* parent) {
    parent->children_.remove_if([&] (const soinfo* child) {
      return child == this;
    });
  });

  // 2. Remove from the primary namespace
  primary_namespace_->remove_soinfo(this);
  primary_namespace_ = nullptr;

  // 3. Remove from secondary namespaces
  secondary_namespaces_.for_each([&](android_namespace_t* ns) {
    ns->remove_soinfo(this);
  });


  // 4. Once everything untied - clear local lists.
  parents_.clear();
  children_.clear();
  secondary_namespaces_.clear();
}

dev_t soinfo::get_st_dev() const {
  if (has_min_version(0)) {
    return st_dev_;
  }

  return 0;
};

ino_t soinfo::get_st_ino() const {
  if (has_min_version(0)) {
    return st_ino_;
  }

  return 0;
}

off64_t soinfo::get_file_offset() const {
  if (has_min_version(1)) {
    return file_offset_;
  }

  return 0;
}

uint32_t soinfo::get_rtld_flags() const {
  if (has_min_version(1)) {
    return rtld_flags_;
  }

  return 0;
}

uint32_t soinfo::get_dt_flags_1() const {
  if (has_min_version(1)) {
    return dt_flags_1_;
  }

  return 0;
}

void soinfo::set_dt_flags_1(uint32_t dt_flags_1) {
  if (has_min_version(1)) {
    if ((dt_flags_1 & DF_1_GLOBAL) != 0) {
      rtld_flags_ |= RTLD_GLOBAL;
    }

    if ((dt_flags_1 & DF_1_NODELETE) != 0) {
      rtld_flags_ |= RTLD_NODELETE;
    }

    dt_flags_1_ = dt_flags_1;
  }
}

void soinfo::set_nodelete() {
  rtld_flags_ |= RTLD_NODELETE;
}

void soinfo::set_realpath(const char* path) {
#if defined(__work_around_b_24465209__)
  if (has_min_version(2)) {
    realpath_ = path;
  }
#else
  realpath_ = path;
#endif
}

const char* soinfo::get_realpath() const {
#if defined(__work_around_b_24465209__)
  if (has_min_version(2)) {
    return realpath_.c_str();
  } else {
    return old_name_;
  }
#else
  return realpath_.c_str();
#endif
}

void soinfo::set_soname(const char* soname) {
#if defined(__work_around_b_24465209__)
  if (has_min_version(2)) {
    soname_ = soname;
  }
  strlcpy(old_name_, soname_.c_str(), sizeof(old_name_));
#else
  soname_ = soname;
#endif
}

const char* soinfo::get_soname() const {
#if defined(__work_around_b_24465209__)
  if (has_min_version(2)) {
    return soname_.c_str();
  } else {
    return old_name_;
  }
#else
  return soname_.c_str();
#endif
}

// This is a return on get_children()/get_parents() if
// 'this->flags' does not have FLAG_NEW_SOINFO set.
static soinfo_list_t g_empty_list;

soinfo_list_t& soinfo::get_children() {
  if (has_min_version(0)) {
    return children_;
  }

  return g_empty_list;
}

const soinfo_list_t& soinfo::get_children() const {
  if (has_min_version(0)) {
    return children_;
  }

  return g_empty_list;
}

soinfo_list_t& soinfo::get_parents() {
  if (has_min_version(0)) {
    return parents_;
  }

  return g_empty_list;
}

static std::vector<std::string> g_empty_runpath;

const std::vector<std::string>& soinfo::get_dt_runpath() const {
  if (has_min_version(3)) {
    return dt_runpath_;
  }

  return g_empty_runpath;
}

android_namespace_t* soinfo::get_primary_namespace() {
  if (has_min_version(3)) {
    return primary_namespace_;
  }

  return &g_default_namespace;
}

void soinfo::add_secondary_namespace(android_namespace_t* secondary_ns) {
  CHECK(has_min_version(3));
  secondary_namespaces_.push_back(secondary_ns);
}

android_namespace_list_t& soinfo::get_secondary_namespaces() {
  CHECK(has_min_version(3));
  return secondary_namespaces_;
}

const char* soinfo::get_string(ElfW(Word) index) const {
  if (has_min_version(1) && (index >= strtab_size_)) {
    async_safe_fatal("%s: strtab out of bounds error; STRSZ=%zd, name=%d",
        get_realpath(), strtab_size_, index);
  }

  return strtab_ + index;
}

bool soinfo::is_gnu_hash() const {
  return (flags_ & FLAG_GNU_HASH) != 0;
}

bool soinfo::can_unload() const {
  return !is_linked() ||
         (
             (get_rtld_flags() & (RTLD_NODELETE | RTLD_GLOBAL)) == 0
         );
}

bool soinfo::is_linked() const {
  return (flags_ & FLAG_LINKED) != 0;
}

bool soinfo::is_image_linked() const {
  return (flags_ & FLAG_IMAGE_LINKED) != 0;
}

bool soinfo::is_main_executable() const {
  return (flags_ & FLAG_EXE) != 0;
}

bool soinfo::is_linker() const {
  return (flags_ & FLAG_LINKER) != 0;
}

void soinfo::set_linked() {
  flags_ |= FLAG_LINKED;
}

void soinfo::set_image_linked() {
  flags_ |= FLAG_IMAGE_LINKED;
}

void soinfo::set_linker_flag() {
  flags_ |= FLAG_LINKER;
}

void soinfo::set_main_executable() {
  flags_ |= FLAG_EXE;
}

size_t soinfo::increment_ref_count() {
  return ++local_group_root_->ref_count_;
}

size_t soinfo::decrement_ref_count() {
  return --local_group_root_->ref_count_;
}

size_t soinfo::get_ref_count() const {
  return local_group_root_->ref_count_;
}

soinfo* soinfo::get_local_group_root() const {
  return local_group_root_;
}

void soinfo::set_mapped_by_caller(bool mapped_by_caller) {
  if (mapped_by_caller) {
    flags_ |= FLAG_MAPPED_BY_CALLER;
  } else {
    flags_ &= ~FLAG_MAPPED_BY_CALLER;
  }
}

bool soinfo::is_mapped_by_caller() const {
  return (flags_ & FLAG_MAPPED_BY_CALLER) != 0;
}

// This function returns api-level at the time of
// dlopen/load. Note that libraries opened by system
// will always have 'current' api level.
int soinfo::get_target_sdk_version() const {
  if (!has_min_version(2)) {
    return __ANDROID_API__;
  }

  return local_group_root_->target_sdk_version_;
}

uintptr_t soinfo::get_handle() const {
  CHECK(has_min_version(3));
  CHECK(handle_ != 0);
  return handle_;
}

void* soinfo::to_handle() {
  if (get_application_target_sdk_version() < 24 || !has_min_version(3)) {
    return this;
  }

  return reinterpret_cast<void*>(get_handle());
}

void soinfo::generate_handle() {
  CHECK(has_min_version(3));
  CHECK(handle_ == 0); // Make sure this is the first call

  // Make sure the handle is unique and does not collide
  // with special values which are RTLD_DEFAULT and RTLD_NEXT.
  do {
    if (!is_first_stage_init()) {
      arc4random_buf(&handle_, sizeof(handle_));
    } else {
      // arc4random* is not available in init because /dev/urandom hasn't yet been
      // created. So, when running with init, use the monotonically increasing
      // numbers as handles
      handle_ += 2;
    }
    // the least significant bit for the handle is always 1
    // making it easy to test the type of handle passed to
    // dl* functions.
    handle_ = handle_ | 1;
  } while (handle_ == reinterpret_cast<uintptr_t>(RTLD_DEFAULT) ||
           handle_ == reinterpret_cast<uintptr_t>(RTLD_NEXT) ||
           g_soinfo_handles_map.contains(handle_));

  g_soinfo_handles_map[handle_] = this;
}

void soinfo::set_gap_start(ElfW(Addr) gap_start) {
  CHECK(has_min_version(6));
  gap_start_ = gap_start;
}
ElfW(Addr) soinfo::get_gap_start() const {
  CHECK(has_min_version(6));
  return gap_start_;
}

void soinfo::set_gap_size(size_t gap_size) {
  CHECK(has_min_version(6));
  gap_size_ = gap_size;
}
size_t soinfo::get_gap_size() const {
  CHECK(has_min_version(6));
  return gap_size_;
}

// TODO(dimitry): Move SymbolName methods to a separate file.

uint32_t calculate_elf_hash(const char* name) {
  const uint8_t* name_bytes = reinterpret_cast<const uint8_t*>(name);
  uint32_t h = 0, g;

  while (*name_bytes) {
    h = (h << 4) + *name_bytes++;
    g = h & 0xf0000000;
    h ^= g;
    h ^= g >> 24;
  }

  return h;
}

uint32_t SymbolName::elf_hash() {
  if (!has_elf_hash_) {
    elf_hash_ = calculate_elf_hash(name_);
    has_elf_hash_ = true;
  }

  return elf_hash_;
}

uint32_t SymbolName::gnu_hash() {
  if (!has_gnu_hash_) {
    gnu_hash_ = calculate_gnu_hash(name_).first;
    has_gnu_hash_ = true;
  }

  return gnu_hash_;
}

"""

```