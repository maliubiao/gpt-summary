Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:** The core task is to analyze the provided C++ source code for `linker_block_allocator_test.cpp` and explain its functionality in the context of Android's Bionic linker. This involves identifying what the tests are doing, how they relate to memory allocation in the linker, and potentially highlighting any relevant Android-specific aspects.

**2. Initial Code Scan - High-Level Overview:**

   * **Includes:**  Immediately notice `<stdlib.h>`, `<string.h>`, `<sys/mman.h>`, `<sys/param.h>`, `<gtest/gtest.h>`, `"linker_block_allocator.h"`, and `<unistd.h>`. These headers suggest the code deals with standard library functions, memory management (especially `mmap`), Google Test framework, the target `linker_block_allocator.h`, and POSIX system calls.
   * **Namespace:** The code is within an anonymous namespace, which is a common C++ practice for hiding internal implementation details within a file.
   * **Struct Definitions:**  See several `struct` definitions (`test_struct_nominal`, `test_struct_small`, `test_struct_max_align`, `test_struct_larger`). These look like test data structures of different sizes and alignments, which is a strong hint about what the allocator is being tested against.
   * **`linker_allocator_test_helper` template function:** This function takes a type `Element` and seems to perform a common sequence of allocation and freeing using `LinkerTypeAllocator`. This suggests a parameterized test strategy.
   * **`TEST` macros:**  These are clearly Google Test macros, indicating the presence of unit tests. The names of the tests (`test_nominal`, `test_small`, etc.) relate to the previously defined structs.
   * **`protect_all` function:** This function allocates memory, applies memory protection (using `PROT_READ` and `PROT_WRITE`), and then deliberately tries to violate the protection to trigger a segmentation fault. This points to testing the memory protection capabilities of the allocator.
   * **`ASSERT_EXIT` macro:** Another Google Test macro used to verify that a function call leads to a specific exit condition (in this case, a `SIGSEGV`).

**3. Deeper Dive - Analyzing Individual Parts:**

   * **`test_struct_*` Structures:** The names and sizes suggest the tests are designed to check allocation behavior for different sizes and alignment requirements. `test_struct_small` is smaller than a likely block size, `test_struct_max_align` has explicit alignment, and `test_struct_larger` is larger, potentially crossing block boundaries.
   * **`linker_allocator_test_helper` Function Breakdown:**
      * `LinkerTypeAllocator<Element> allocator;`:  Creates an instance of the allocator. The template nature means the tests will run with different struct types.
      * `allocator.alloc();`:  Allocates memory. The `ASSERT_TRUE` and `ASSERT_EQ` statements check if the returned pointers are valid and properly aligned (both to `kBlockSizeAlign` and the element's own alignment).
      * The calculation of `dist` (`__BIONIC_ALIGN(MAX(sizeof(Element), kBlockSizeMin), kBlockSizeAlign)`) is crucial. It reveals the allocation strategy: allocate in blocks aligned to `kBlockSizeAlign`, and the minimum allocation size is `kBlockSizeMin`. The `MAX` ensures even small allocations get a minimum chunk.
      * `allocator.free();`:  Releases the allocated memory.
   * **Individual `TEST` Functions:**  Each `TEST` calls `linker_allocator_test_helper` with a specific `test_struct_*` type. This confirms that the allocator is being tested with varying data sizes and alignment needs. The "test_larger" test adds a loop to allocate many objects, likely to test page boundary handling.
   * **`protect_all` Function Breakdown:**
      * Allocates some memory.
      * `allocator.protect_all(PROT_READ);` and `allocator.protect_all(PROT_READ | PROT_WRITE);`: These calls suggest the allocator has a mechanism to change the memory protection attributes of allocated blocks.
      * The code then tries to write to memory that should be read-only after the final `protect_all(PROT_READ);` call, expecting a segmentation fault.
   * **Constants:**  The definition of `kPageSize` using `sysconf(_SC_PAGE_SIZE)` is standard POSIX and confirms interaction with the operating system's memory management.

**4. Connecting to Android and the Dynamic Linker:**

   * **`linker_block_allocator.h`:** This header file is the key. The fact that the test file includes it and uses `LinkerTypeAllocator` directly indicates this is a test specifically for a memory allocator used *within* the dynamic linker.
   * **Purpose of a Linker Allocator:** Dynamic linkers need to allocate memory for various internal data structures (e.g., symbol tables, relocation entries, loaded library information). Using a specialized block allocator can improve performance compared to general-purpose allocators by reducing fragmentation and overhead.
   * **`kBlockSizeAlign` and `kBlockSizeMin`:** These constants (likely defined in `linker_block_allocator.h` or a related header) represent the granularity of memory allocation within the linker's allocator. This is a common technique in allocators to manage memory in chunks.

**5. Addressing the Specific Questions:**

   * **Functionality:** Summarize what the tests are doing (allocating, freeing, checking alignment, testing memory protection).
   * **Android Relevance:** Explain that this allocator is used by the dynamic linker for its internal data structures.
   * **`libc` Functions:** Focus on `sysconf`, `mman.h` functions (even though not directly called in the tests, they are relevant to the underlying implementation of the allocator, especially `mmap` which is likely used to obtain memory blocks), `memcpy` and other string functions (used within the test structs). Explain their general purpose.
   * **Dynamic Linker Features:**  Explain the concept of SO layouts and how the linker uses allocators to manage memory within those layouts. Provide a simple example SO layout.
   * **Logical Reasoning/Assumptions:** Point out the assumptions about `kBlockSizeAlign` and `kBlockSizeMin`.
   * **Common User Errors:**  While this is a *test* file, discuss common memory management errors (double-free, use-after-free) that this type of allocator aims to prevent or manage efficiently within the linker.
   * **Android Framework/NDK Path:** Explain the high-level flow of how an app starts, the role of the zygote, and how the dynamic linker is involved in loading libraries.
   * **Frida Hooking:** Provide concrete Frida examples for hooking `alloc` and `free` methods of `LinkerTypeAllocator`.

**6. Structuring the Output:** Organize the information logically, using headings and bullet points for clarity. Translate technical terms into understandable language where appropriate.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the individual test cases.
* **Correction:** Realize the importance of the `linker_allocator_test_helper` function as it encapsulates the core allocation/free logic being tested.
* **Initial thought:**  Go into deep detail about the implementation of `mmap`.
* **Correction:**  Keep the explanation of `libc` functions concise and focused on their relevance to the *test* context or the likely underlying implementation of the allocator. Avoid getting bogged down in implementation details not directly visible in the test code.
* **Initial thought:**  Assume a high level of technical knowledge from the reader.
* **Correction:** Explain concepts like dynamic linking and SO layouts in a way that is accessible to a broader audience.

By following these steps, iteratively analyzing the code, and focusing on the prompt's requirements, a comprehensive and accurate explanation can be constructed.
好的，让我们来分析一下 `bionic/linker/linker_block_allocator_test.cpp` 这个文件。

**功能概述**

这个 C++ 文件是一个单元测试文件，用于测试 Android Bionic 动态链接器中的 `LinkerBlockAllocator` 类。`LinkerBlockAllocator` 是一种用于在链接器内部高效地分配内存块的自定义分配器。

**具体功能点:**

1. **测试基本分配和释放:**
   - 测试 `LinkerTypeAllocator::alloc()` 方法是否能正确分配内存。
   - 测试分配的内存是否按照预期的对齐方式进行对齐 (`kBlockSizeAlign` 和 `alignof(Element)`）。
   - 测试 `LinkerTypeAllocator::free()` 方法是否能正确释放已分配的内存。
   - 测试连续分配的内存块是否紧邻排列（以优化空间利用率）。

2. **测试不同大小结构的分配:**
   - 测试分配小于最小块大小 (`kBlockSizeMin`) 的结构体。
   - 测试分配具有特定对齐要求的结构体 (`__attribute__((aligned(16)))`)。
   - 测试分配较大尺寸的结构体，验证分配器处理跨越内部管理块的能力。

3. **测试跨页分配:**
   - 验证分配器在内存耗尽当前页时，能够分配新的内存页。

4. **测试内存保护机制:**
   - 测试 `LinkerTypeAllocator::protect_all()` 方法，该方法可以修改所有已分配内存块的内存保护属性（例如，设置为只读）。
   - 通过故意访问被保护的内存页，验证内存保护机制是否生效（应该导致 `SIGSEGV` 信号）。

**与 Android 功能的关系及举例说明**

`LinkerBlockAllocator` 是 Android 动态链接器（`linker` 或 `libdl.so`）的核心组件之一。动态链接器负责加载和链接应用程序依赖的共享库 (`.so` 文件)。在加载和链接过程中，链接器需要动态地分配内存来存储各种内部数据结构，例如：

* **符号表 (Symbol Tables):** 存储共享库中导出的函数和变量的名称和地址。
* **重定位表 (Relocation Tables):** 记录需要在加载时修改的地址信息。
* **共享库信息 (Shared Library Information):**  存储已加载共享库的路径、加载地址、依赖关系等信息。

`LinkerBlockAllocator` 的设计目标是：

* **效率:**  针对链接器内部的分配模式进行优化，减少碎片，提高分配速度。
* **内存控制:**  提供细粒度的内存管理能力，例如可以对分配的内存区域设置保护属性。

**举例说明:**

当一个 Android 应用启动并加载一个 `.so` 库时，动态链接器会执行以下操作，其中可能涉及到 `LinkerBlockAllocator`：

1. **加载共享库:** 链接器使用 `mmap` 系统调用将 `.so` 文件映射到进程的地址空间。
2. **解析 ELF 头:** 链接器读取 `.so` 文件的 ELF 头，获取符号表、重定位表等信息的位置和大小。
3. **分配内存:** 链接器使用 `LinkerBlockAllocator` 分配内存来存储解析到的符号表、重定位表以及其他内部数据结构。例如，可能分配一块内存来存储共享库中所有导出函数的名称和地址。
4. **执行重定位:** 链接器遍历重定位表，根据需要修改代码和数据段中的地址，使其指向正确的内存位置。这可能需要分配临时内存。
5. **调用初始化函数:** 链接器调用共享库中的 `JNI_OnLoad` 或 `__attribute__((constructor))` 修饰的函数。

在这个过程中，每次链接器需要存储一些数据时，它就会调用 `LinkerBlockAllocator::alloc()` 来获取一块内存。

**详细解释每一个 libc 函数的功能是如何实现的**

这个测试文件中直接使用的 libc 函数包括：

* **`stdlib.h`:**
    * **`malloc` 和 `free`:**  虽然测试代码本身没有直接使用 `malloc` 和 `free`，但 `LinkerTypeAllocator` 的底层实现可能会使用这些函数或更底层的内存管理机制（例如 `mmap`）。`malloc` 用于动态分配指定大小的内存块，`free` 用于释放由 `malloc` 分配的内存块。其实现通常涉及维护一个空闲内存块链表，并根据请求的大小查找合适的空闲块。
    * **`sysconf`:**  用于获取系统配置信息。在这里，`sysconf(_SC_PAGE_SIZE)` 用于获取系统的页大小。其实现通常通过系统调用与内核交互来获取配置信息。

* **`string.h`:**
    * **`memcpy`:** 用于将一段内存的内容复制到另一段内存。尽管测试代码中没有显式调用 `memcpy`，但在结构体赋值或内部数据操作时可能会隐式使用。其实现通常是逐字节或逐字地复制数据。

* **`sys/mman.h`:**
    * **`mmap`:** 用于将文件或设备映射到内存。动态链接器在加载共享库时会使用 `mmap` 将 `.so` 文件映射到进程的地址空间。`mmap` 的实现涉及到与内核的交互，在进程的虚拟地址空间中创建一个映射，并将其关联到磁盘上的文件或物理内存。
    * **`munmap`:** 用于解除 `mmap` 创建的映射。
    * **内存保护相关的宏 (例如 `PROT_READ`, `PROT_WRITE`):**  这些宏定义了内存区域的访问权限，例如只读、可读写等。这些宏与 `mprotect` 系统调用一起使用，用于修改内存区域的保护属性。

* **`sys/param.h`:**
    * **`MAX` 宏:**  一个简单的宏，用于返回两个值中的较大值。

* **`unistd.h`:**
    * **`getpid`:** 获取当前进程的 ID。在动态链接器的上下文中，这可能用于日志记录或调试。
    * **`_SC_PAGE_SIZE` 宏:**  用于 `sysconf` 函数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

**SO 布局样本：**

一个典型的 Android `.so` (共享库) 文件布局大致如下：

```
.dynamic   (动态链接信息，例如依赖库、符号表位置等)
.hash      (符号哈希表，用于快速查找符号)
.gnu.version (符号版本信息)
.gnu.version_r (依赖库的版本信息)
.rel.dyn   (数据段重定位表)
.rel.plt   (PLT (Procedure Linkage Table) 重定位表)
.plt       (Procedure Linkage Table，延迟绑定函数调用)
.text      (代码段，包含可执行指令)
.rodata    (只读数据段，包含常量)
.data      (已初始化数据段，包含全局变量)
.bss       (未初始化数据段，全局变量)
...       (其他段，例如调试信息)
```

**链接的处理过程 (简化描述):**

1. **加载 SO:** 当应用程序请求加载一个共享库时（例如通过 `System.loadLibrary()` 或 JNI 调用），Android 运行时 (ART 或 Dalvik) 会请求动态链接器加载该 `.so` 文件。
2. **`mmap` 映射:** 动态链接器使用 `mmap` 将 `.so` 文件映射到进程的地址空间。
3. **解析 ELF 头:** 链接器读取 ELF 头，确定各个段的位置和大小。
4. **分配内存:**  链接器使用 `LinkerBlockAllocator` 分配内存来存储：
   - **共享库的内部表示:**  例如，一个表示该 SO 文件的 `soinfo` 结构体，其中包含加载地址、依赖库列表、符号表指针等信息。
   - **符号表:**  从 `.symtab` 和 `.strtab` 段解析出的符号信息。
   - **重定位表:**  `.rel.dyn` 和 `.rel.plt` 段的内容。
5. **符号查找:** 当程序调用共享库中的函数时，链接器需要找到该函数的实际地址。它会查找符号表，匹配函数名。
6. **重定位:** 链接器遍历重定位表，根据需要修改代码或数据段中的地址。
   - **绝对重定位:** 将代码或数据中的地址修改为符号的绝对地址。
   - **相对重定位:**  将代码或数据中的地址修改为相对于某个基地址的偏移量。
7. **PLT 和延迟绑定:**  对于外部函数的调用，通常使用 PLT (Procedure Linkage Table) 实现延迟绑定。第一次调用时，链接器会解析出函数的实际地址并更新 PLT 条目，后续调用将直接跳转到该地址。
8. **依赖库加载:** 如果被加载的 SO 依赖于其他 SO 文件，链接器会递归地加载这些依赖库。

在整个过程中，`LinkerBlockAllocator` 负责为链接器内部的各种数据结构提供内存，确保高效的内存管理。

**如果做了逻辑推理，请给出假设输入与输出**

在 `linker_block_allocator_test.cpp` 中，主要的逻辑推理体现在以下方面：

* **对齐测试:**  假设 `kBlockSizeAlign` 和结构体的对齐要求已知，测试代码会断言分配的内存地址满足这些对齐要求。
    * **假设输入:** `kBlockSizeAlign = 16`，`alignof(test_struct_max_align) = 16`
    * **预期输出:** `reinterpret_cast<uintptr_t>(ptr)` % 16 == 0

* **连续分配测试:** 假设分配器按顺序分配，且块之间有固定的间隔。
    * **假设输入:**  连续分配两个 `test_struct_nominal` 类型的对象。
    * **预期输出:**  第二个对象的地址比第一个对象的地址偏移 `__BIONIC_ALIGN(MAX(sizeof(test_struct_nominal), kBlockSizeMin), kBlockSizeAlign)` 字节。

* **内存保护测试:** 假设 `protect_all(PROT_READ)` 能成功将内存设置为只读，并且尝试写入只读内存会触发 `SIGSEGV`。
    * **假设输入:** 调用 `protect_all(PROT_READ)` 后尝试写入 `page1_ptr->str[11]`。
    * **预期输出:** 程序因 `SIGSEGV` 信号而终止，并输出 "trying to access protected page"。

**如果涉及用户或者编程常见的使用错误，请举例说明**

虽然 `LinkerBlockAllocator` 是链接器内部使用的，普通用户或开发者不会直接操作它，但理解其背后的原理有助于避免与内存管理相关的常见错误：

1. **内存泄漏:**  如果 `LinkerBlockAllocator` 内部没有正确地管理已分配的内存，可能会导致内存泄漏。虽然这不太可能发生，但理解分配器的作用有助于理解内存泄漏的根本原因。

2. **野指针和悬挂指针:**  尽管 `LinkerBlockAllocator` 不会直接暴露给用户，但如果链接器内部的代码错误地释放了正在使用的内存，就会导致野指针或悬挂指针的问题，从而引发崩溃或其他不可预测的行为。

3. **缓冲区溢出:**  如果链接器在分配内存后，向分配的缓冲区写入超出其大小的数据，就会导致缓冲区溢出，可能覆盖其他重要的数据结构。

4. **双重释放:**  尝试对同一块内存调用两次 `free` 操作会导致未定义行为，通常会导致程序崩溃。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `LinkerBlockAllocator` 的步骤 (简化):**

1. **应用程序启动:**  用户启动一个 Android 应用程序。
2. **Zygote 进程 fork:**  Android 系统通过 Zygote 进程 fork 出新的进程来运行应用程序。
3. **加载 ART/Dalvik 虚拟机:**  新进程加载 ART (Android Runtime，Android 5.0+) 或 Dalvik (旧版本) 虚拟机。
4. **加载应用程序代码和依赖库:**  虚拟机开始加载应用程序的代码 (`.apk` 文件中的 `.dex` 文件) 以及应用程序依赖的 native 库 (`.so` 文件)。
5. **动态链接器介入:**  当需要加载 native 库时，虚拟机调用动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`)。
6. **链接器操作:** 动态链接器执行前面描述的加载、解析、重定位等操作，其中会使用 `LinkerBlockAllocator` 分配内存来存储内部数据结构。

**NDK 到达 `LinkerBlockAllocator` 的步骤:**

1. **NDK 代码编译:**  开发者使用 NDK 编译 C/C++ 代码，生成 `.so` 文件。
2. **应用程序集成:**  将生成的 `.so` 文件集成到 Android 应用程序中。
3. **应用程序加载 NDK 库:**  应用程序通过 `System.loadLibrary()` 或 JNI 调用来加载 NDK 库。
4. **动态链接器加载 NDK 库:**  动态链接器执行与上述相同的加载和链接过程，使用 `LinkerBlockAllocator` 管理内存。

**Frida Hook 示例:**

可以使用 Frida Hook `LinkerTypeAllocator` 的 `alloc` 和 `free` 方法来观察其行为。假设你的 Android 设备上运行着需要调试的应用程序，并且你已经安装了 Frida 和 frida-server。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("linker64", "_ZN19LinkerTypeAllocatorI20test_struct_nominalE5allocEv"), {
    onEnter: function(args) {
        console.log("[LinkerTypeAllocator::alloc] Called");
        this.allocation_size = this.context.r0; // 假设分配大小在 r0 寄存器
    },
    onLeave: function(retval) {
        console.log("[LinkerTypeAllocator::alloc] Returned address:", retval);
    }
});

Interceptor.attach(Module.findExportByName("linker64", "_ZN19LinkerTypeAllocatorI20test_struct_nominalE4freeEPv"), {
    onEnter: function(args) {
        console.log("[LinkerTypeAllocator::free] Called with address:", args[1]);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**说明:**

1. **`package_name`:** 将 `你的应用包名` 替换为你想要调试的应用程序的包名。
2. **`frida.get_usb_device().attach(package_name)`:**  连接到 USB 连接的 Android 设备上的目标进程。
3. **`Module.findExportByName("linker64", ...)`:**  在 `linker64` 模块中查找 `LinkerTypeAllocator::alloc` 和 `LinkerTypeAllocator::free` 方法的符号。你需要根据你想要 Hook 的具体结构体类型和链接器架构（32 位或 64 位）调整符号名称。可以使用 `adb shell cat /proc/进程ID/maps` 来查找 `linker` 或 `linker64` 的加载地址，并使用工具（如 `readelf` 或 `objdump`）查看其导出的符号。
4. **`Interceptor.attach(...)`:**  拦截这两个方法的调用。
5. **`onEnter` 和 `onLeave`:**  在函数调用前后执行 JavaScript 代码。
6. **`args`:**  访问函数参数。
7. **`retval`:**  访问函数返回值。
8. **`console.log`:**  在 Frida 控制台中打印信息。

**运行步骤:**

1. 确保你的 Android 设备已连接并通过 USB 调试模式连接到计算机。
2. 启动 frida-server 在 Android 设备上运行。
3. 运行上面的 Python 脚本。
4. 启动目标 Android 应用程序。

你将在 Frida 控制台中看到 `LinkerTypeAllocator::alloc` 和 `LinkerTypeAllocator::free` 的调用信息，包括分配的地址和释放的地址。你需要根据实际的符号名称和参数传递方式调整 Frida 脚本。

这个测试文件是理解 Android 动态链接器内存管理机制的一个很好的起点。希望这个详细的分析能够帮助你更好地理解其功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/linker/linker_block_allocator_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>

#include <gtest/gtest.h>

#include "linker_block_allocator.h"

#include <unistd.h>

namespace {

struct test_struct_nominal {
  void* pointer;
  ssize_t value;
};

/*
 * this one has size below kBlockSizeAlign
 */
struct test_struct_small {
  char str[3];
};

struct test_struct_max_align {
  char str[16];
} __attribute__((aligned(16)));

/*
 * 1009 byte struct (1009 is prime)
 */
struct test_struct_larger {
  char str[1009];
};

static size_t kPageSize = sysconf(_SC_PAGE_SIZE);

template <typename Element>
void linker_allocator_test_helper() {
  LinkerTypeAllocator<Element> allocator;

  Element* ptr1 = allocator.alloc();
  ASSERT_TRUE(ptr1 != nullptr);
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr1) % kBlockSizeAlign);
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr1) % alignof(Element));
  Element* ptr2 = allocator.alloc();
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr2) % kBlockSizeAlign);
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr2) % alignof(Element));
  ASSERT_TRUE(ptr2 != nullptr);

  // they should be next to each other.
  size_t dist = __BIONIC_ALIGN(MAX(sizeof(Element), kBlockSizeMin), kBlockSizeAlign);
  ASSERT_EQ(reinterpret_cast<uint8_t*>(ptr1) + dist, reinterpret_cast<uint8_t*>(ptr2));

  allocator.free(ptr1);
  allocator.free(ptr2);
}

};  // anonymous namespace

TEST(linker_allocator, test_nominal) {
  linker_allocator_test_helper<test_struct_nominal>();
}

TEST(linker_allocator, test_small) {
  linker_allocator_test_helper<test_struct_small>();
}

TEST(linker_allocator, test_max_align) {
  linker_allocator_test_helper<test_struct_max_align>();
}

TEST(linker_allocator, test_larger) {
  linker_allocator_test_helper<test_struct_larger>();

  LinkerTypeAllocator<test_struct_larger> allocator;

  // lets allocate until we reach next page.
  size_t n = kPageSize / sizeof(test_struct_larger) + 1;

  for (size_t i=0; i<n; ++i) {
    ASSERT_TRUE(allocator.alloc() != nullptr);
  }

  test_struct_larger* ptr_to_free = allocator.alloc();
  ASSERT_TRUE(ptr_to_free != nullptr);
}

static void protect_all() {
  LinkerTypeAllocator<test_struct_larger> allocator;

  // number of allocs to reach the end of first page
  size_t n = kPageSize/sizeof(test_struct_larger) - 1;
  test_struct_larger* page1_ptr = allocator.alloc();

  for (size_t i=0; i<n; ++i) {
    allocator.alloc();
  }

  test_struct_larger* page2_ptr = allocator.alloc();
  allocator.protect_all(PROT_READ);
  allocator.protect_all(PROT_READ | PROT_WRITE);
  // check access
  page2_ptr->str[23] = 27;
  page1_ptr->str[13] = 11;

  allocator.protect_all(PROT_READ);
  fprintf(stderr, "trying to access protected page");

  // this should result in segmentation fault
  page1_ptr->str[11] = 7;
}

TEST(linker_allocator, test_protect) {
  testing::FLAGS_gtest_death_test_style = "threadsafe";
  ASSERT_EXIT(protect_all(), testing::KilledBySignal(SIGSEGV), "trying to access protected page");
}
```