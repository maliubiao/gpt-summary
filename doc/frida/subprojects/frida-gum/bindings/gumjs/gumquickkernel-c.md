Response:
Let's break down the thought process for analyzing this C code for Frida.

**1. Understanding the Goal:**

The primary goal is to analyze the `gumquickkernel.c` file and explain its functionality in the context of Frida, reverse engineering, low-level operations, and potential user errors. We also need to trace how a user might reach this code.

**2. Initial Skim and High-Level Understanding:**

The first step is to quickly scan the code for keywords and patterns. Things that immediately jump out:

* **Includes:** `gumquickkernel.h`, `gumquickmacros.h` – suggests it's part of the "gum" library within Frida.
* **Typedefs and Structs:**  `GumMemoryValueType`, `GumQuickMatchContext`, `GumKernelScanContext`, `GumMemoryScanSyncContext` – indicates data structures for managing different operations, particularly related to memory.
* **Enums:** `_GumMemoryValueType` – lists various data types (S8, U8, etc.), hinting at memory reading and writing capabilities.
* **Function Declarations:** Lots of `GUMJS_DECLARE_*` macros. The `GUMJS` prefix strongly suggests an interaction with JavaScript. The function names like `gumjs_kernel_get_available`, `gumjs_kernel_read_S32`, `gumjs_kernel_scan` give clues about their purpose.
* **Static Functions:**  Helper functions like `gum_emit_module`, `gum_parse_range_details`, `gum_append_match` suggest a modular design.
* **`JSContext`:** This confirms the JavaScript bridge.
* **`GumQuickCore`:** Likely a core component of the "gum" library.
* **`gum_kernel_*` functions:**  Functions like `gum_kernel_enumerate_modules`, `gum_kernel_read`, `gum_kernel_alloc`, `gum_kernel_protect`, `gum_kernel_scan` strongly point to interactions with the operating system kernel.
* **Macros for Read/Write:** The `GUMJS_DEFINE_MEMORY_READ_WRITE` and `GUMJS_EXPORT_MEMORY_READ_WRITE` macros are used extensively, indicating a systematic way of exposing memory access functions.
* **Error Handling:**  Checks like `if (!gum_quick_kernel_check_api_available (ctx))` and calls to `_gum_quick_throw_*` suggest error handling mechanisms.

**3. Deeper Dive and Functionality Breakdown:**

Now, let's examine the key functions and their roles:

* **Getters/Setters:** `gumjs_kernel_get_available`, `gumjs_kernel_get_base`, `gumjs_kernel_set_base` are straightforward for checking API availability and getting/setting the kernel base address. This is crucial for interacting with kernel memory.
* **Enumeration Functions:** `gumjs_kernel_enumerate_modules`, `gumjs_kernel_enumerate_ranges`, `gumjs_kernel_enumerate_module_ranges` – these functions allow introspection of the kernel's state by listing loaded modules and memory ranges. The callbacks (`on_match`, `on_complete`) indicate asynchronous operation.
* **Memory Allocation/Protection:** `gumjs_kernel_alloc` and `gumjs_kernel_protect` provide basic memory management within the kernel.
* **Memory Read/Write:**  The numerous `gumjs_kernel_read_*` and `gumjs_kernel_write_*` functions are core to Frida's ability to interact with memory. The different data types in `_GumMemoryValueType` allow for reading and writing various data structures.
* **Memory Scanning:** `gumjs_kernel_scan` and `gumjs_kernel_scan_sync` are powerful features for finding patterns in kernel memory. The synchronous version returns results directly, while the asynchronous version uses callbacks.

**4. Connecting to Reverse Engineering Concepts:**

As each function's purpose becomes clearer, connect it to typical reverse engineering tasks:

* **Enumeration:**  Essential for understanding the target's structure, finding interesting modules or memory regions.
* **Memory Reading:** Fundamental for examining data structures, code, and variables.
* **Memory Writing:**  Used for patching code, modifying data, and injecting payloads.
* **Memory Scanning:**  Used to locate specific code sequences, data patterns, or vulnerabilities.

**5. Considering Low-Level Details:**

Think about the underlying OS interactions:

* **Kernel Modules:**  Understanding how modules are loaded and their structure is relevant for `gumjs_kernel_enumerate_modules`.
* **Memory Management:**  Concepts like page sizes, memory protection (read, write, execute), and virtual addresses are directly related to `gumjs_kernel_alloc` and `gumjs_kernel_protect`.
* **System Calls (Implicit):** While not directly visible, functions like `gum_kernel_read` and `gum_kernel_write` likely involve system calls to interact with the kernel.

**6. Logical Reasoning and Examples:**

For functions like `gumjs_kernel_scan`, consider how the input parameters (`address`, `size`, `pattern`, callbacks) influence the output (matches found). Invent simple scenarios to illustrate this.

**7. User Errors and Debugging:**

Think about common mistakes developers might make when using these APIs:

* **Incorrect Addresses:** Passing invalid memory addresses.
* **Incorrect Sizes:** Specifying the wrong number of bytes to read or write.
* **Type Mismatches:** Trying to read data as the wrong type.
* **Permissions Issues:** Attempting to access protected memory.

**8. Tracing User Actions:**

Imagine a typical Frida workflow:

1. User attaches Frida to a process.
2. User accesses the `Kernel` namespace in the Frida script.
3. User calls functions like `Kernel.enumerateModules()`, `Kernel.read*()`, `Kernel.scanSync()`.

This step-by-step process helps understand how user actions in JavaScript translate to the execution of this C code.

**9. Structuring the Output:**

Organize the analysis logically:

* Start with a summary of the file's purpose.
* List the core functionalities with explanations and examples.
* Address reverse engineering relevance, low-level details, logical reasoning, and user errors in separate sections.
* Conclude with the user interaction trace.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Simplification:**  Realize that simply stating "reads memory" isn't enough. Explain *what* kind of memory, *how*, and *why* it's useful.
* **Missing Connections:**  Ensure that each function is explicitly linked to relevant concepts (e.g., `gumjs_kernel_enumerate_modules` to kernel module structure).
* **Vague Explanations:**  Replace general statements with specific examples. Instead of saying "can modify memory," show how `Kernel.writeS32()` could change a variable.
* **Lack of User Context:**  Emphasize how a user in a Frida script would actually use these functions.

By following these steps, combining code analysis with domain knowledge, and continuously refining the explanation, a comprehensive and accurate analysis of the `gumquickkernel.c` file can be produced.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickkernel.c` 这个文件的功能。

**文件功能概述**

这个 C 文件是 Frida 工具中 `gum` 库的一部分，它主要负责在目标进程（特别是内核）中执行与内存操作和信息获取相关的快速操作。它通过 JavaScript 绑定（`bindings/gumjs`）将内核级别的功能暴露给 Frida 用户，允许用户从 JavaScript 代码中与目标系统的内核进行交互。

**具体功能列表及说明**

1. **内核 API 可用性检查 (`gumjs_kernel_get_available`)**:
   - **功能:**  检查目标系统是否支持 Frida 的内核 API。
   - **逆向关系:** 在进行内核级别的逆向操作之前，这是一个重要的检查步骤，确保 Frida 能够执行相关的内核操作。
   - **二进制底层/内核/框架知识:**  依赖于 Frida 底层与操作系统内核交互的能力，可能涉及到检查特定的内核符号或接口。
   - **逻辑推理:**  假设系统支持内核 API，则返回 `true`，否则返回 `false`。
   - **用户错误:** 用户如果在不支持内核 API 的系统上尝试使用内核相关的 Frida 功能，会收到错误提示。
   - **用户操作如何到达这里:** 当用户在 Frida JavaScript 脚本中访问 `Kernel.available` 属性时，会调用这个 C 函数。

2. **获取/设置内核基地址 (`gumjs_kernel_get_base`, `gumjs_kernel_set_base`)**:
   - **功能:** 获取目标系统内核的基地址，也可以尝试设置（在某些受限场景下）。
   - **逆向关系:**  内核基地址是进行内核级逆向分析的关键信息，许多内核数据结构的偏移量都是相对于这个基地址计算的。
   - **二进制底层/内核/框架知识:**  需要了解不同操作系统获取内核基地址的方法（例如，读取特定的内核变量或通过系统调用）。
   - **逻辑推理:**  `get_base` 返回当前内核的基地址，`set_base` 尝试设置基地址（如果允许）。
   - **用户错误:**  尝试设置错误的基地址可能会导致系统不稳定或崩溃。
   - **用户操作如何到达这里:** 当用户在 Frida JavaScript 脚本中访问 `Kernel.base` 属性（get）或尝试赋值给 `Kernel.base` 属性（set）时。

3. **枚举内核模块 (`gumjs_kernel_enumerate_modules`)**:
   - **功能:**  列出当前加载到内核中的所有模块（例如，驱动程序）。
   - **逆向关系:**  对于理解内核的结构和功能至关重要，可以帮助识别感兴趣的目标模块。
   - **二进制底层/内核/框架知识:**  需要了解操作系统内核模块的管理机制，例如 Linux 的 `/proc/modules` 或 Windows 的驱动程序对象列表。
   - **逻辑推理:**  遍历内核模块列表，对每个模块调用用户提供的 `onMatch` 回调函数，并在完成后调用 `onComplete`。
   - **假设输入/输出:**
     - **输入:** 用户提供的 `onMatch` 函数（处理每个模块的信息）和 `onComplete` 函数（枚举完成时调用）。
     - **输出:**  `onMatch` 函数会被调用多次，每次传递一个包含模块名称、基地址和大小的对象。`onComplete` 函数会在枚举完成后被调用。
   - **用户错误:**  提供的回调函数如果出现错误，可能会导致枚举过程提前终止。
   - **用户操作如何到达这里:** 用户在 Frida JavaScript 脚本中调用 `Kernel._enumerateModules(callbacks)` 函数。

4. **枚举内核内存区域 (`gumjs_kernel_enumerate_ranges`)**:
   - **功能:**  列出内核中具有特定保护属性（例如，可读、可写、可执行）的内存区域。
   - **逆向关系:**  帮助理解内核的内存布局，查找特定的代码段或数据段。
   - **二进制底层/内核/框架知识:**  需要了解操作系统内核的内存管理机制，例如页表和内存保护标志。
   - **逻辑推理:**  遍历内核的内存区域，根据指定的保护属性进行过滤，并对匹配的区域调用 `onMatch` 回调。
   - **假设输入/输出:**
     - **输入:**  内存保护属性 (`prot`)，`onMatch` 和 `onComplete` 回调函数。
     - **输出:**  `onMatch` 函数被调用多次，每次传递一个包含内存区域基地址、大小和保护属性的对象。
   - **用户错误:**  指定的保护属性可能无法匹配到任何内存区域。
   - **用户操作如何到达这里:** 用户在 Frida JavaScript 脚本中调用 `Kernel._enumerateRanges(protection, callbacks)` 函数。

5. **枚举模块内的内存区域 (`gumjs_kernel_enumerate_module_ranges`)**:
   - **功能:**  列出特定内核模块内部具有特定保护属性的内存区域。
   - **逆向关系:**  更精细地了解特定内核模块的内存布局。
   - **二进制底层/内核/框架知识:**  结合了模块枚举和内存区域枚举的知识。
   - **逻辑推理:**  先找到指定的模块，然后在其内部遍历内存区域并根据保护属性过滤。
   - **假设输入/输出:**
     - **输入:**  模块名称 (`module_name`)，内存保护属性 (`prot`)，`onMatch` 和 `onComplete` 回调函数。
     - **输出:**  `onMatch` 函数被调用多次，每次传递一个包含模块名、内存区域基地址、大小和保护属性的对象。
   - **用户错误:**  指定的模块名称不存在，或者模块内没有匹配的内存区域。
   - **用户操作如何到达这里:** 用户在 Frida JavaScript 脚本中调用 `Kernel._enumerateModuleRanges(moduleName, protection, callbacks)` 函数。

6. **分配内核内存 (`gumjs_kernel_alloc`)**:
   - **功能:**  在内核空间分配指定大小的内存。
   - **逆向关系:**  可能用于在内核中注入代码或数据。
   - **二进制底层/内核/框架知识:**  需要了解内核的内存分配机制，例如 `kmalloc` 或类似的函数。
   - **逻辑推理:**  调用内核的内存分配函数，并返回分配的内存地址。
   - **假设输入/输出:**
     - **输入:**  要分配的内存大小 (`size`).
     - **输出:**  分配的内存的基地址。
   - **用户错误:**  请求分配的内存大小过大，或者内核内存不足。
   - **用户操作如何到达这里:** 用户在 Frida JavaScript 脚本中调用 `Kernel.alloc(size)` 函数。

7. **修改内核内存保护属性 (`gumjs_kernel_protect`)**:
   - **功能:**  修改内核中指定内存区域的保护属性（例如，将只读内存变为可写）。
   - **逆向关系:**  允许修改内核代码或数据，是进行内核漏洞利用或动态修改内核行为的关键操作。
   - **二进制底层/内核/框架知识:**  需要了解操作系统内核的内存保护机制和修改方法，例如 `mprotect` 或类似的系统调用。
   - **逻辑推理:**  调用内核的内存保护修改函数，并返回操作是否成功。
   - **假设输入/输出:**
     - **输入:**  要修改的内存地址 (`address`)，大小 (`size`)，新的保护属性 (`prot`)。
     - **输出:**  布尔值，表示操作是否成功。
   - **用户错误:**  尝试修改受保护的或不存在的内存区域的保护属性，或者尝试设置无效的保护属性。
   - **用户操作如何到达这里:** 用户在 Frida JavaScript 脚本中调用 `Kernel.protect(address, size, protection)` 函数。

8. **读取内核内存 (`gumjs_kernel_read_*`)**:
   - **功能:**  从内核空间的指定地址读取不同类型的数据（例如，S8, U8, S32, U64, 字符串等）。
   - **逆向关系:**  用于检查内核数据结构、变量和代码。
   - **二进制底层/内核/框架知识:**  需要理解不同数据类型在内存中的表示方式。
   - **逻辑推理:**  调用内核的内存读取函数，并将读取到的数据转换为相应的 JavaScript 类型。
   - **假设输入/输出:**
     - **输入:**  要读取的内存地址 (`address`)，以及可选的读取长度 (`length`) 对于字节数组和字符串。
     - **输出:**  读取到的数据，类型取决于调用的具体函数（例如，`readS32` 返回 32 位有符号整数）。
   - **用户错误:**  读取无效的内存地址或指定了错误的读取长度。
   - **用户操作如何到达这里:** 用户在 Frida JavaScript 脚本中调用 `Kernel.readS8(address)`, `Kernel.readU64(address)`, `Kernel.readCString(address, length)` 等函数。

9. **写入内核内存 (`gumjs_kernel_write_*`)**:
   - **功能:**  向内核空间的指定地址写入不同类型的数据。
   - **逆向关系:**  用于修改内核数据或代码，例如，修改函数行为或修复漏洞。
   - **二进制底层/内核/框架知识:**  需要理解不同数据类型在内存中的表示方式。
   - **逻辑推理:**  将 JavaScript 数据转换为相应的 C 类型，并调用内核的内存写入函数。
   - **假设输入/输出:**
     - **输入:**  要写入的内存地址 (`address`)，要写入的值 (`value`)。
     - **输出:**  无返回值，操作成功或失败会抛出异常。
   - **用户错误:**  写入无效的内存地址或写入了错误类型的数据。
   - **用户操作如何到达这里:** 用户在 Frida JavaScript 脚本中调用 `Kernel.writeS32(address, value)`, `Kernel.writeU64(address, value)`, `Kernel.writeUtf8String(address, value)` 等函数。

10. **扫描内核内存 (`gumjs_kernel_scan`, `gumjs_kernel_scan_sync`)**:
    - **功能:** 在内核空间的指定内存区域中搜索匹配特定模式的字节序列。`gumjs_kernel_scan` 是异步的，使用回调函数返回结果，而 `gumjs_kernel_scan_sync` 是同步的，直接返回匹配结果数组。
    - **逆向关系:**  用于查找特定的代码片段、数据模式或已知的签名。
    - **二进制底层/内核/框架知识:**  需要理解字节模式匹配的概念。
    - **逻辑推理:**  遍历指定的内存区域，将每个位置的字节序列与提供的模式进行比较。
    - **假设输入/输出 (`gumjs_kernel_scan`):**
        - **输入:**  起始地址 (`address`)，扫描大小 (`size`)，匹配模式 (`pattern`)，`onMatch`, `onError`, `onComplete` 回调函数。
        - **输出:**  每次找到匹配时调用 `onMatch`，传递匹配的地址和大小。
    - **假设输入/输出 (`gumjs_kernel_scan_sync`):**
        - **输入:**  起始地址 (`address`)，扫描大小 (`size`)，匹配模式 (`pattern`)。
        - **输出:**  一个数组，包含所有匹配项的对象，每个对象包含匹配的地址和大小。
    - **用户错误:**  提供的模式不正确，或者扫描的内存区域无效。异步扫描的回调函数如果处理不当可能会导致错误。
    - **用户操作如何到达这里:** 用户在 Frida JavaScript 脚本中调用 `Kernel._scan(address, size, pattern, callbacks)` 或 `Kernel.scanSync(address, size, pattern)` 函数。

**与逆向方法的关联举例**

* **查找特定内核函数:** 使用 `Kernel.scanSync` 扫描内核内存，查找已知内核函数的指令序列（例如，函数序言的特征码）。
* **分析内核数据结构:** 使用 `Kernel.readU64` 读取内核数据结构的成员，例如进程控制块（PCB）中的字段。
* **动态修改内核行为:** 使用 `Kernel.writeU8` 或 `Kernel.writeS32` 修改内核函数的指令，例如，跳过某些安全检查。
* **枚举加载的驱动程序:** 使用 `Kernel._enumerateModules` 获取所有已加载的内核模块的信息。

**涉及的二进制底层、Linux/Android 内核及框架的知识举例**

* **内存地址表示:**  函数参数和返回值中使用了 `GumAddress`，这通常表示一个 64 位或 32 位的内存地址，需要理解不同架构下的地址空间布局。
* **内存保护属性:** `GumPageProtection` 枚举和相关函数涉及到 Linux/Android 内核的内存保护机制（例如，PROT_READ, PROT_WRITE, PROT_EXEC）。
* **内核模块管理:**  枚举模块的功能依赖于操作系统提供的接口，例如 Linux 的 `get_modules()` 系统调用或读取 `/proc/modules` 文件。
* **内存分配函数:**  `gum_kernel_alloc_n_pages` 等函数底层会调用内核的内存分配函数，例如 Linux 的 `__get_free_pages` 或类似的机制。
* **字节序:**  在读取和写入多字节数据时，需要考虑目标系统的字节序（大端或小端）。

**逻辑推理的假设输入与输出**

以 `gumjs_kernel_scan_sync` 为例：

* **假设输入:**
    - `address`:  内核内存起始地址 `0xffffffff81000000` (假设)
    - `size`:  扫描大小 `4096` 字节
    - `pattern`:  一个 `GumMatchPattern` 对象，表示要搜索的字节序列，例如 `[0x55, 0x48, 0x89, 0xe5]` (x86-64 函数序言)。
* **预期输出:**  一个 JavaScript 数组，包含在指定内存区域内找到的所有匹配项。每个匹配项是一个对象，包含 `address` (匹配的起始地址) 和 `size` (匹配的字节数，通常与模式长度相同)。如果未找到匹配项，则返回空数组。

**用户或编程常见的使用错误举例**

* **读取或写入无效地址:**  例如，尝试读取地址 `0` 或一个未映射的内核地址，会导致程序崩溃或抛出异常。
* **指定错误的读取/写入长度:**  例如，尝试使用 `readS64` 读取一个只包含 4 字节数据的地址，会导致读取到不完整或错误的数据。
* **修改关键内核数据结构错误的值:**  例如，错误地修改进程的权限信息可能导致系统不稳定或安全漏洞。
* **在不支持内核 API 的系统上使用内核功能:**  会导致 `Kernel.available` 返回 `false`，并且尝试调用其他内核相关函数会失败。
* **异步扫描 (`gumjs_kernel_scan`) 未正确处理回调:**  例如，`onMatch` 函数中出现错误未捕获，可能导致扫描过程提前终止或结果不完整。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户编写 Frida JavaScript 脚本:**  用户使用 Frida 的 JavaScript API 来与目标进程交互。例如，他们可能想要读取某个内核变量的值。
2. **调用 `Kernel` 对象的方法:**  在脚本中，用户会访问全局 `Kernel` 对象，并调用其提供的方法，例如 `Kernel.readU64(address)`.
3. **JavaScript 引擎执行:**  Frida 的 JavaScript 引擎（通常是 QuickJS）会解析并执行这些 JavaScript 代码。
4. **调用 C++ 绑定代码:**  当执行到 `Kernel.readU64(address)` 时，JavaScript 引擎会调用相应的 C++ 绑定代码（在 Frida Gum 中），这些绑定代码负责将 JavaScript 调用转换为 C++ 函数调用。
5. **调用 `gumjs_kernel_read_U64` 函数:**  在 `gumquickkernel.c` 文件中，`gumjs_kernel_read_U64` 函数会被调用。
6. **参数解析和验证:**  `gumjs_kernel_read_U64` 函数会解析 JavaScript 传递的参数（例如，内存地址），并进行一些基本的验证。
7. **调用底层内核交互函数:**  `gumjs_kernel_read_U64` 函数最终会调用 `gum_kernel_read` 函数（在 Frida Gum 的核心库中），该函数负责执行实际的内核内存读取操作，这可能涉及到系统调用。
8. **数据返回和转换:**  读取到的内核数据会通过 C++ 绑定代码转换回 JavaScript 类型，并返回给用户的脚本。

**调试线索:**

* **JavaScript 脚本中的函数调用:**  用户的 JavaScript 代码是入口点，检查用户调用的 `Kernel` 对象的方法和传递的参数。
* **Frida 的日志输出:**  Frida 通常会输出一些调试信息，可以帮助追踪函数调用和错误。
* **断点调试:**  可以使用 GDB 或 LLDB 等调试器附加到 Frida 的进程，并在 `gumquickkernel.c` 中的关键函数设置断点，以查看参数值和执行流程。
* **Frida Gum 的源代码:**  理解 `gumquickkernel.c` 以及相关的头文件和核心库代码，可以帮助深入理解调用的过程和原理。

希望这个详细的分析能够帮助你理解 `gumquickkernel.c` 文件的功能和作用。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickkernel.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2016-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2018-2019 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickkernel.h"

#include "gumquickmacros.h"

typedef guint GumMemoryValueType;
typedef struct _GumQuickMatchContext GumQuickMatchContext;
typedef struct _GumKernelScanContext GumKernelScanContext;
typedef struct _GumMemoryScanSyncContext GumMemoryScanSyncContext;

enum _GumMemoryValueType
{
  GUM_MEMORY_VALUE_S8,
  GUM_MEMORY_VALUE_U8,
  GUM_MEMORY_VALUE_S16,
  GUM_MEMORY_VALUE_U16,
  GUM_MEMORY_VALUE_S32,
  GUM_MEMORY_VALUE_U32,
  GUM_MEMORY_VALUE_S64,
  GUM_MEMORY_VALUE_U64,
  GUM_MEMORY_VALUE_LONG,
  GUM_MEMORY_VALUE_ULONG,
  GUM_MEMORY_VALUE_FLOAT,
  GUM_MEMORY_VALUE_DOUBLE,
  GUM_MEMORY_VALUE_BYTE_ARRAY,
  GUM_MEMORY_VALUE_C_STRING,
  GUM_MEMORY_VALUE_UTF8_STRING,
  GUM_MEMORY_VALUE_UTF16_STRING
};

struct _GumQuickMatchContext
{
  JSValue on_match;
  JSValue on_complete;
  GumQuickMatchResult result;

  JSContext * ctx;
  GumQuickCore * core;
};

struct _GumKernelScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  JSValue on_match;
  JSValue on_error;
  JSValue on_complete;
  GumQuickMatchResult result;

  JSContext * ctx;
  GumQuickCore * core;
};

struct _GumMemoryScanSyncContext
{
  JSValue matches;
  uint32_t index;

  JSContext * ctx;
  GumQuickCore * core;
};

GUMJS_DECLARE_GETTER (gumjs_kernel_get_available)
GUMJS_DECLARE_GETTER (gumjs_kernel_get_base)
GUMJS_DECLARE_SETTER (gumjs_kernel_set_base)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumQuickMatchContext * mc);
static JSValue gum_parse_module_details (JSContext * ctx,
    const GumModuleDetails * details, GumQuickCore * core);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumQuickMatchContext * mc);
static JSValue gum_parse_range_details (JSContext * ctx,
    const GumRangeDetails * details, GumQuickCore * core);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_module_ranges)
static gboolean gum_emit_module_range (
    const GumKernelModuleRangeDetails * details, GumQuickMatchContext * mc);
static JSValue gum_parse_module_range_details (JSContext * ctx,
    const GumKernelModuleRangeDetails * details, GumQuickCore * core);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_protect)

static JSValue gum_quick_kernel_read (JSContext * ctx, GumMemoryValueType type,
    GumQuickArgs * args, GumQuickCore * core);
static JSValue gum_quick_kernel_write (JSContext * ctx, GumMemoryValueType type,
    GumQuickArgs * args, GumQuickCore * core);

#define GUMJS_DEFINE_MEMORY_READ(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_kernel_read_##T) \
    { \
      return gum_quick_kernel_read (ctx, GUM_MEMORY_VALUE_##T, args, core); \
    }
#define GUMJS_DEFINE_MEMORY_WRITE(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_kernel_write_##T) \
    { \
      return gum_quick_kernel_write (ctx, GUM_MEMORY_VALUE_##T, args, core); \
    }
#define GUMJS_DEFINE_MEMORY_READ_WRITE(T) \
    GUMJS_DEFINE_MEMORY_READ (T); \
    GUMJS_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
    JS_CFUNC_DEF ("read" N, 0, gumjs_kernel_read_##T)
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
    JS_CFUNC_DEF ("write" N, 0, gumjs_kernel_write_##T)
#define GUMJS_EXPORT_MEMORY_READ_WRITE(N, T) \
    GUMJS_EXPORT_MEMORY_READ (N, T), \
    GUMJS_EXPORT_MEMORY_WRITE (N, T)

GUMJS_DEFINE_MEMORY_READ_WRITE (S8)
GUMJS_DEFINE_MEMORY_READ_WRITE (U8)
GUMJS_DEFINE_MEMORY_READ_WRITE (S16)
GUMJS_DEFINE_MEMORY_READ_WRITE (U16)
GUMJS_DEFINE_MEMORY_READ_WRITE (S32)
GUMJS_DEFINE_MEMORY_READ_WRITE (U32)
GUMJS_DEFINE_MEMORY_READ_WRITE (S64)
GUMJS_DEFINE_MEMORY_READ_WRITE (U64)
GUMJS_DEFINE_MEMORY_READ_WRITE (LONG)
GUMJS_DEFINE_MEMORY_READ_WRITE (ULONG)
GUMJS_DEFINE_MEMORY_READ_WRITE (FLOAT)
GUMJS_DEFINE_MEMORY_READ_WRITE (DOUBLE)
GUMJS_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUMJS_DEFINE_MEMORY_READ (C_STRING)
GUMJS_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUMJS_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)

GUMJS_DECLARE_FUNCTION (gumjs_kernel_scan)
static void gum_kernel_scan_context_free (GumKernelScanContext * ctx);
static void gum_kernel_scan_context_run (GumKernelScanContext * self);
static gboolean gum_kernel_scan_context_emit_match (GumAddress address,
    gsize size, GumKernelScanContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_scan_sync)
static gboolean gum_append_match (GumAddress address, gsize size,
    GumMemoryScanSyncContext * sc);

static gboolean gum_quick_kernel_check_api_available (JSContext * ctx);

static const JSCFunctionListEntry gumjs_kernel_entries[] =
{
  JS_CGETSET_DEF ("available", gumjs_kernel_get_available, NULL),
  JS_CGETSET_DEF ("base", gumjs_kernel_get_base, gumjs_kernel_set_base),

  JS_CFUNC_DEF ("_enumerateModules", 0, gumjs_kernel_enumerate_modules),
  JS_CFUNC_DEF ("_enumerateRanges", 0, gumjs_kernel_enumerate_ranges),
  JS_CFUNC_DEF ("_enumerateModuleRanges", 0,
      gumjs_kernel_enumerate_module_ranges),
  JS_CFUNC_DEF ("alloc", 0, gumjs_kernel_alloc),
  JS_CFUNC_DEF ("protect", 0, gumjs_kernel_protect),

  GUMJS_EXPORT_MEMORY_READ_WRITE ("S8", S8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U8", U8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S16", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U16", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S32", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U32", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S64", S64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U64", U64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Short", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("UShort", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Int", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("UInt", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Long", LONG),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ULong", ULONG),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Float", FLOAT),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Double", DOUBLE),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ByteArray", BYTE_ARRAY),
  GUMJS_EXPORT_MEMORY_READ ("CString", C_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf8String", UTF8_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf16String", UTF16_STRING),

  JS_CFUNC_DEF ("_scan", 0, gumjs_kernel_scan),
  JS_CFUNC_DEF ("scanSync", 0, gumjs_kernel_scan_sync),
};

void
_gum_quick_kernel_init (GumQuickKernel * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj;

  self->core = core;

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_kernel_entries,
      G_N_ELEMENTS (gumjs_kernel_entries));
  JS_DefinePropertyValueStr (ctx, obj, "pageSize",
      JS_NewInt32 (ctx, gum_kernel_query_page_size ()), JS_PROP_C_W_E);
  JS_DefinePropertyValueStr (ctx, ns, "Kernel", obj, JS_PROP_C_W_E);
}

void
_gum_quick_kernel_dispose (GumQuickKernel * self)
{
}

void
_gum_quick_kernel_finalize (GumQuickKernel * self)
{
}

GUMJS_DEFINE_GETTER (gumjs_kernel_get_available)
{
  return JS_NewBool (ctx, gum_kernel_api_is_available ());
}

GUMJS_DEFINE_GETTER (gumjs_kernel_get_base)
{
  GumAddress address;

  if (!gum_quick_kernel_check_api_available (ctx))
    return JS_EXCEPTION;

  address = gum_kernel_find_base_address ();

  return _gum_quick_uint64_new (ctx, address, core);
}

GUMJS_DEFINE_SETTER (gumjs_kernel_set_base)
{
  GumAddress address;

  if (!gum_quick_kernel_check_api_available (ctx))
    return JS_EXCEPTION;

  if (!_gum_quick_uint64_get (ctx, val, core, &address))
    return JS_EXCEPTION;

  gum_kernel_set_base_address (address);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_modules)
{
  GumQuickMatchContext mc;

  if (!gum_quick_kernel_check_api_available (ctx))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_kernel_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  JSValue module, result;

  module = gum_parse_module_details (ctx, details, mc->core);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &module);

  JS_FreeValue (ctx, module);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

static JSValue
gum_parse_module_details (JSContext * ctx,
                          const GumModuleDetails * details,
                          GumQuickCore * core)
{
  JSValue m = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, base),
      _gum_quick_uint64_new (ctx, details->range->base_address, core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewInt64 (ctx, details->range->size),
      JS_PROP_C_W_E);

  return m;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_ranges)
{
  GumQuickMatchContext mc;
  GumPageProtection prot;

  if (!gum_quick_kernel_check_api_available (ctx))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "mF{onMatch,onComplete}", &prot,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_kernel_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  JSValue range, result;

  range = gum_parse_range_details (ctx, details, mc->core);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &range);

  JS_FreeValue (ctx, range);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

static JSValue
gum_parse_range_details (JSContext * ctx,
                         const GumRangeDetails * details,
                         GumQuickCore * core)
{
  JSValue r = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, base),
      _gum_quick_uint64_new (ctx, details->range->base_address, core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewInt64 (ctx, details->range->size),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, protection),
      _gum_quick_page_protection_new (ctx, details->protection),
      JS_PROP_C_W_E);

  return r;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_module_ranges)
{
  const gchar * module_name;
  GumPageProtection prot;
  GumQuickMatchContext mc;

  if (!gum_quick_kernel_check_api_available (ctx))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "s?mF{onMatch,onComplete}", &module_name,
      &prot, &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_kernel_enumerate_module_ranges (
      (module_name == NULL) ? "Kernel" : module_name, prot,
      (GumFoundKernelModuleRangeFunc) gum_emit_module_range, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_module_range (const GumKernelModuleRangeDetails * details,
                       GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  JSValue module_range, result;

  module_range = gum_parse_module_range_details (ctx, details, mc->core);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &module_range);

  JS_FreeValue (ctx, module_range);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

static JSValue
gum_parse_module_range_details (JSContext * ctx,
                                const GumKernelModuleRangeDetails * details,
                                GumQuickCore * core)
{
  JSValue r = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, base),
      _gum_quick_uint64_new (ctx, details->address, core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewInt64 (ctx, details->size),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, protection),
      _gum_quick_page_protection_new (ctx, details->protection),
      JS_PROP_C_W_E);

  return r;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_alloc)
{
  GumAddress address;
  gsize size, page_size;
  guint n_pages;

  if (!gum_quick_kernel_check_api_available (ctx))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "Z", &size))
    return JS_EXCEPTION;

  if (size == 0 || size > 0x7fffffff)
    return _gum_quick_throw_literal (ctx, "invalid size");

  page_size = gum_kernel_query_page_size ();
  n_pages = ((size + page_size - 1) & ~(page_size - 1)) / page_size;

  address = gum_kernel_alloc_n_pages (n_pages);

  return _gum_quick_kernel_resource_new (ctx, address, gum_kernel_free_pages,
      core);
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_protect)
{
  GumAddress address;
  gsize size;
  GumPageProtection prot;
  gboolean success;

  if (!gum_quick_kernel_check_api_available (ctx))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "QZm", &address, &size, &prot))
    return JS_EXCEPTION;

  if (size > 0x7fffffff)
    return _gum_quick_throw_literal (ctx, "invalid size");

  if (size != 0)
    success = gum_kernel_try_mprotect (address, size, prot);
  else
    success = TRUE;

  return JS_NewBool (ctx, success);
}

static JSValue
gum_quick_kernel_read (JSContext * ctx,
                       GumMemoryValueType type,
                       GumQuickArgs * args,
                       GumQuickCore * core)
{
  JSValue result = JS_NULL;
  GumAddress address;
  gssize length;
  gpointer data = NULL;
  const gchar * end;

  if (!gum_quick_kernel_check_api_available (ctx))
    goto propagate_exception;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
      if (!_gum_quick_args_parse (args, "QZ", &address, &length))
        goto propagate_exception;
      break;
    default:
      if (!_gum_quick_args_parse (args, "Q", &address))
        goto propagate_exception;
      length = 0;
      break;
  }

  if (address == 0)
    goto beach;

  if (length == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_S8:
      case GUM_MEMORY_VALUE_U8:
        length = 1;
        break;
      case GUM_MEMORY_VALUE_S16:
      case GUM_MEMORY_VALUE_U16:
        length = 2;
        break;
      case GUM_MEMORY_VALUE_S32:
      case GUM_MEMORY_VALUE_U32:
      case GUM_MEMORY_VALUE_FLOAT:
        length = 4;
        break;
      case GUM_MEMORY_VALUE_S64:
      case GUM_MEMORY_VALUE_U64:
      case GUM_MEMORY_VALUE_LONG:
      case GUM_MEMORY_VALUE_ULONG:
      case GUM_MEMORY_VALUE_DOUBLE:
        length = 8;
        break;
      default:
        break;
    }
  }

  if (length > 0)
  {
    gsize n_bytes_read;

    data = gum_kernel_read (address, length, &n_bytes_read);
    if (data == NULL)
      goto invalid_address;

    switch (type)
    {
      case GUM_MEMORY_VALUE_S8:
        result = JS_NewInt32 (ctx, *((gint8 *) data));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = JS_NewInt32 (ctx, *((guint8 *) data));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = JS_NewInt32 (ctx, *((gint16 *) data));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = JS_NewInt32 (ctx, *((guint16 *) data));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = JS_NewInt32 (ctx, *((gint32 *) data));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = JS_NewInt32 (ctx, *((guint32 *) data));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = _gum_quick_int64_new (ctx, *((gint64 *) data), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        result = _gum_quick_uint64_new (ctx, *((guint64 *) data), core);
        break;
      case GUM_MEMORY_VALUE_LONG:
        result = _gum_quick_int64_new (ctx, *((glong *) data), core);
        break;
      case GUM_MEMORY_VALUE_ULONG:
        result = _gum_quick_uint64_new (ctx, *((gulong *) data), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = JS_NewFloat64 (ctx, *((gfloat *) data));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = JS_NewFloat64 (ctx, *((gdouble *) data));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        uint8_t * buf = g_steal_pointer (&data);

        result = JS_NewArrayBuffer (ctx, buf, n_bytes_read,
            _gum_quick_array_buffer_free, buf, FALSE);

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        gchar * str;

        str = g_utf8_make_valid (data, n_bytes_read);
        result = JS_NewString (ctx, str);
        g_free (str);

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gchar * slice;

        if (!g_utf8_validate (data, n_bytes_read, &end))
          goto invalid_utf8;

        slice = g_strndup (data, n_bytes_read);
        result = JS_NewString (ctx, slice);
        g_free (slice);

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gchar * str_utf8;
        glong size;

        str_utf8 = g_utf16_to_utf8 (data, n_bytes_read, NULL, &size, NULL);
        if (str_utf8 == NULL)
          goto invalid_utf16;
        result = JS_NewString (ctx, str_utf8);
        g_free (str_utf8);

        break;
      }
      default:
        g_assert_not_reached ();
    }

  }
  else if (type == GUM_MEMORY_VALUE_BYTE_ARRAY)
  {
    result = JS_NewArrayBufferCopy (ctx, NULL, 0);
  }
  else
  {
    goto invalid_length;
  }

  goto beach;

invalid_address:
  {
    _gum_quick_throw (ctx, "access violation reading 0x%" G_GINT64_MODIFIER "x",
        address);
    goto propagate_exception;
  }
invalid_length:
  {
    _gum_quick_throw_literal (ctx, "expected a length > 0");
    goto propagate_exception;
  }
invalid_utf8:
  {
    _gum_quick_throw (ctx, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - (gchar *) data));
    goto propagate_exception;
  }
invalid_utf16:
  {
    _gum_quick_throw_literal (ctx, "invalid string");
    goto propagate_exception;
  }
propagate_exception:
  {
    result = JS_EXCEPTION;
    goto beach;
  }
beach:
  {
    g_free (data);

    return result;
  }
}

static JSValue
gum_quick_kernel_write (JSContext * ctx,
                        GumMemoryValueType type,
                        GumQuickArgs * args,
                        GumQuickCore * core)
{
  GumAddress address = 0;
  gssize s = 0;
  gsize u = 0;
  gint64 s64 = 0;
  guint64 u64 = 0;
  gdouble number = 0;
  gfloat number32 = 0;
  GBytes * bytes = NULL;
  const gchar * str = NULL;
  gunichar2 * str_utf16 = NULL;
  const guint8 * data = NULL;
  gsize str_length = 0;
  gsize length = 0;
  gboolean success;

  if (!gum_quick_kernel_check_api_available (ctx))
    return JS_EXCEPTION;

  switch (type)
  {
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_S32:
      if (!_gum_quick_args_parse (args, "Qz", &address, &s))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_U32:
      if (!_gum_quick_args_parse (args, "QZ", &address, &u))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_LONG:
      if (!_gum_quick_args_parse (args, "Qq", &address, &s64))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_ULONG:
      if (!_gum_quick_args_parse (args, "QQ", &address, &u64))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      if (!_gum_quick_args_parse (args, "Qn", &address, &number))
        return JS_EXCEPTION;
      number32 = (gfloat) number;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_quick_args_parse (args, "QB", &address, &bytes))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
      if (!_gum_quick_args_parse (args, "Qs", &address, &str))
        return JS_EXCEPTION;

      str_length = g_utf8_strlen (str, -1);
      if (type == GUM_MEMORY_VALUE_UTF16_STRING)
        str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);

      break;
    default:
      g_assert_not_reached ();
  }

  switch (type)
  {
    case GUM_MEMORY_VALUE_S8:
      data = (guint8 *) &s;
      length = 1;
      break;
    case GUM_MEMORY_VALUE_U8:
      data = (guint8 *) &u;
      length = 1;
      break;
    case GUM_MEMORY_VALUE_S16:
      data = (guint8 *) &s;
      length = 2;
      break;
    case GUM_MEMORY_VALUE_U16:
      data = (guint8 *) &u;
      length = 2;
      break;
    case GUM_MEMORY_VALUE_S32:
      data = (guint8 *) &s;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_U32:
      data = (guint8 *) &u;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_LONG:
    case GUM_MEMORY_VALUE_S64:
      data = (guint8 *) &s64;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_ULONG:
    case GUM_MEMORY_VALUE_U64:
      data = (guint8 *) &u64;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
      data = (guint8 *) &number32;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_DOUBLE:
      data = (guint8 *) &number;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      data = g_bytes_get_data (bytes, &length);
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
      data = (guint8 *) str;
      length = g_utf8_offset_to_pointer (str, str_length) - str + 1;
      break;
    case GUM_MEMORY_VALUE_UTF16_STRING:
      data = (guint8 *) str_utf16;
      length = (str_length + 1) * sizeof (gunichar2);
      break;
    default:
      g_assert_not_reached ();
  }

  if (length <= 0)
    goto invalid_length;

  success = gum_kernel_write (address, data, length);

  g_free (str_utf16);

  if (!success)
    goto invalid_address;

  return JS_UNDEFINED;

invalid_address:
  {
    _gum_quick_throw (ctx, "access violation writing to 0x%" G_GINT64_MODIFIER
        "x", address);
    return JS_EXCEPTION;
  }
invalid_length:
  {
    _gum_quick_throw_literal (ctx, "expected a length > 0");
    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_scan)
{
  GumKernelScanContext sc;
  GumAddress address;
  gsize size;

  if (!_gum_quick_args_parse (args, "QZMF{onMatch,onError,onComplete}",
      &address, &size, &sc.pattern, &sc.on_match, &sc.on_error,
      &sc.on_complete))
    return JS_EXCEPTION;

  sc.range.base_address = address;
  sc.range.size = size;

  gum_match_pattern_ref (sc.pattern);

  JS_DupValue (ctx, sc.on_match);
  JS_DupValue (ctx, sc.on_error);
  JS_DupValue (ctx, sc.on_complete);

  sc.result = GUM_QUICK_MATCH_CONTINUE;

  sc.ctx = ctx;
  sc.core = core;

  _gum_quick_core_pin (core);
  _gum_quick_core_push_job (core,
      (GumScriptJobFunc) gum_kernel_scan_context_run,
      g_slice_dup (GumKernelScanContext, &sc),
      (GDestroyNotify) gum_kernel_scan_context_free);

  return JS_UNDEFINED;
}

static void
gum_kernel_scan_context_free (GumKernelScanContext * self)
{
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, core);

  JS_FreeValue (ctx, self->on_match);
  JS_FreeValue (ctx, self->on_error);
  JS_FreeValue (ctx, self->on_complete);

  _gum_quick_core_unpin (core);
  _gum_quick_scope_leave (&scope);

  gum_match_pattern_unref (self->pattern);

  g_slice_free (GumKernelScanContext, self);
}

static void
gum_kernel_scan_context_run (GumKernelScanContext * self)
{
  gum_kernel_scan (&self->range, self->pattern,
      (GumMemoryScanMatchFunc) gum_kernel_scan_context_emit_match, self);

  if (self->result != GUM_QUICK_MATCH_ERROR)
  {
    GumQuickScope script_scope;

    _gum_quick_scope_enter (&script_scope, self->core);

    _gum_quick_scope_call_void (&script_scope, self->on_complete, JS_UNDEFINED,
        0, NULL);

    _gum_quick_scope_leave (&script_scope);
  }
}

static gboolean
gum_kernel_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumKernelScanContext * self)
{
  gboolean proceed;
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  GumQuickScope scope;
  JSValue argv[2];
  JSValue result;

  _gum_quick_scope_enter (&scope, core);

  argv[0] = _gum_quick_uint64_new (ctx, address, core);
  argv[1] = JS_NewUint32 (ctx, size);

  result = _gum_quick_scope_call (&scope, self->on_match, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);

  proceed = _gum_quick_process_match_result (ctx, &result, &self->result);

  _gum_quick_scope_leave (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_scan_sync)
{
  JSValue result;
  GumAddress address;
  gsize size;
  GumMatchPattern * pattern;
  GumMemoryRange range;
  GumMemoryScanSyncContext sc;

  if (!_gum_quick_args_parse (args, "QZM", &address, &size, &pattern))
    return JS_EXCEPTION;

  range.base_address = address;
  range.size = size;

  result = JS_NewArray (ctx);

  sc.matches = result;
  sc.index = 0;

  sc.ctx = ctx;
  sc.core = core;

  gum_kernel_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
      &sc);

  return result;
}

static gboolean
gum_append_match (GumAddress address,
                  gsize size,
                  GumMemoryScanSyncContext * sc)
{
  JSContext * ctx = sc->ctx;
  GumQuickCore * core = sc->core;
  JSValue m;

  m = JS_NewObject (ctx);
  JS_DefinePropertyValue (ctx, m, GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_uint64_new (ctx, address, core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m, GUM_QUICK_CORE_ATOM (core, size),
      JS_NewUint32 (ctx, size),
      JS_PROP_C_W_E);

  JS_DefinePropertyValueUint32 (ctx, sc->matches, sc->index, m, JS_PROP_C_W_E);
  sc->index++;

  return TRUE;
}

static gboolean
gum_quick_kernel_check_api_available (JSContext * ctx)
{
  if (!gum_kernel_api_is_available ())
  {
    _gum_quick_throw_literal (ctx,
        "Kernel API is not available on this system");
    return FALSE;
  }

  return TRUE;
}

"""

```