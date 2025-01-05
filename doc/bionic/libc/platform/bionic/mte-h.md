Response:
Let's break down the thought process for analyzing this C header file and generating the detailed response.

**1. Understanding the Goal:**

The core request is to analyze a C header file related to Memory Tagging Extension (MTE) in Android's Bionic library and explain its functionality, connection to Android, implementation details, dynamic linking aspects (if any), potential errors, and how it's used in the Android ecosystem.

**2. Initial Code Scan and Keyword Identification:**

First, I'd scan the code for key terms and concepts:

*   `mte`: This is the central theme – Memory Tagging Extension.
*   `aarch64`:  Indicates architecture-specific code, specifically ARM64. This immediately suggests MTE is primarily an ARM64 feature in this context.
*   `getauxval`, `AT_HWCAP2`, `HWCAP2_MTE`:  These relate to checking hardware capabilities. This tells me the code dynamically detects if MTE is supported.
*   `__asm__ __volatile__`:  Inline assembly, indicating direct interaction with the processor's MTE instructions.
*   `ldg`, `irg`, `stg`:  These are likely MTE-specific assembly instructions (load tagged, insert random tag, store tag).
*   `ScopedDisableMTE`: A class suggesting a mechanism to temporarily disable MTE.
*   `tco`:  Looking this up (or having prior knowledge) reveals it's the Tag Check Override register, crucial for temporarily disabling MTE.
*   `stack_mte_ringbuffer_*`: Functions related to allocating and managing a ring buffer for stack MTE.
*   `munmap`, `mmap`: Standard memory management functions.
*   `prctl`, `PR_SET_VMA`, `PR_SET_VMA_ANON_NAME`:  System calls for process control, specifically naming memory regions.
*   `page.h`, `page_size()`: Hints at page-level memory management.

**3. High-Level Functionality Identification:**

Based on the keywords, I can deduce the file's primary functions:

*   **Detecting MTE Support:**  `mte_supported()`.
*   **Pointer Tagging:**  `get_tagged_address()`, `insert_random_tag()`.
*   **Memory Tagging:** `set_memory_tag()`.
*   **Temporarily Disabling MTE:** `ScopedDisableMTE`.
*   **Stack MTE Management:**  Functions for allocating and freeing a special ring buffer used for stack tagging.

**4. Deeper Dive into Each Function/Section:**

Now, I would go through each function and section in more detail:

*   **`mte_supported()`:**  Clearly checks for the `HWCAP2_MTE` capability flag, indicating hardware MTE support. The `#if defined(__aarch64__)` is critical.

*   **`get_tagged_address()`:**  On ARM64, it uses the `ldg` instruction. I'd research this instruction to understand it *loads* the tagged address. The `const_cast` is a bit odd, suggesting it might be used in scenarios where the constness needs to be temporarily removed.

*   **`insert_random_tag()`:** Uses the `irg` instruction to insert a random tag. The `mask` parameter allows excluding certain tags, although it's marked `unused` in the current implementation, which is worth noting.

*   **`set_memory_tag()`:** Uses the `stg` instruction to store the tag from the pointer into the memory location it points to. This is the operation that actually *tags* the memory.

*   **`ScopedDisableMTE`:**  This is a RAII (Resource Acquisition Is Initialization) pattern. The constructor saves the current `tco` value and disables tagging (sets `tco` to 1). The destructor restores the original value. This is crucial for regions of code where MTE might interfere.

*   **Stack MTE Ring Buffer Functions:** These are more complex. I'd analyze the logic:
    *   `stack_mte_ringbuffer_size()`: Calculates the size based on a size class.
    *   `stack_mte_ringbuffer_size_from_pointer()`: Extracts the size class from the top byte of the pointer (an interesting encoding).
    *   `stack_mte_ringbuffer_size_add_to_pointer()`: Stores the size class in the pointer's top byte.
    *   `stack_mte_free_ringbuffer()`: Uses `munmap` to free the allocated memory.
    *   `stack_mte_ringbuffer_allocate()`: This is the most involved. The comments about alignment and the allocation strategy (allocating extra and then unmapping) are key to understanding the implementation's quirks and why it's done this way (likely for performance reasons related to LLVM code generation). The `prctl` call to name the memory region is also important for debugging.

**5. Connecting to Android and Providing Examples:**

At this stage, I'd start thinking about how this code relates to Android:

*   **Memory Safety:** MTE is a memory safety feature. Android uses it to detect memory errors.
*   **Bionic's Role:** Bionic is the C library, so these functions are low-level primitives for memory management.
*   **Framework/NDK Usage:**  Higher layers of Android (Framework, NDK libraries) would use these primitives indirectly, possibly through custom allocators or runtime checks.
*   **Frida Hooking:** I'd consider which functions would be interesting to hook for debugging (e.g., `insert_random_tag`, `set_memory_tag`, the allocation/free functions).

**6. Dynamic Linking Considerations:**

While this specific header doesn't directly *perform* dynamic linking, the context of Bionic means it's part of a system that relies heavily on it. The memory tagging can affect how libraries are loaded and interact, particularly regarding memory safety within and between shared libraries. I'd explain the concept of shared libraries, the linker's role, and how MTE adds a layer of checking. A simple `so` layout example would illustrate the basic structure of a shared library.

**7. Identifying Potential Errors:**

I would think about common mistakes developers might make:

*   **Incorrect Tag Usage:** Using a tagged pointer with untagged memory, or vice-versa.
*   **Mismatched Tags:** Writing to memory tagged with one tag using a pointer with a different tag.
*   **Disabling MTE Incorrectly:**  Forgetting to re-enable it or disabling it for too long.
*   **Stack Buffer Overflows (MTE's Prevention Target):**  Explain how MTE helps detect these.

**8. Structuring the Response:**

Finally, I'd organize the information logically, using headings and bullet points for clarity:

*   Start with a high-level summary of the file's purpose.
*   Detail the functionality of each function.
*   Explain the connection to Android with examples.
*   Address dynamic linking.
*   Provide examples of user errors.
*   Explain how the code is reached from higher levels (Framework/NDK).
*   Include Frida hook examples.

**Self-Correction/Refinement during the process:**

*   **Initial thought:**  Maybe the `mask` in `insert_random_tag` is used.
*   **Correction:** The `__attribute__((unused))` indicates it's currently not used, so I should mention that.
*   **Initial thought:** Focus heavily on the assembly instructions.
*   **Refinement:** While important, also explain the *purpose* of these instructions in the context of memory tagging.
*   **Initial thought:** Just list the functions.
*   **Refinement:** Group related functions (like the stack MTE ring buffer functions) and explain the overall purpose of each group.

By following this systematic approach, breaking down the code into smaller pieces, and thinking about the broader context, I can generate a comprehensive and accurate explanation like the example provided in the prompt.
这个目录 `bionic/libc/platform/bionic/mte.handroid` 下的源代码文件 `mte.handroid` 主要是为了提供 **内存标记扩展 (Memory Tagging Extension, MTE)** 的支持。MTE 是一种硬件安全特性，旨在帮助检测和防止内存安全漏洞，例如堆溢出和释放后使用。

让我们详细分解一下它的功能和与 Android 的关系：

**文件功能概览:**

这个头文件定义了一些内联函数和结构体，用于在 Android 的 Bionic C 库中利用 ARMv8.5-A 架构引入的 MTE 特性。其核心功能包括：

1. **检测 MTE 支持:** 提供 `mte_supported()` 函数来检查当前硬件和内核是否支持 MTE。
2. **获取带标签的地址:** 提供 `get_tagged_address()` 函数，用于获取指向带有特定标签的内存地址的指针。
3. **插入随机标签:** 提供 `insert_random_tag()` 函数，用于在指针中插入一个随机生成的标签。
4. **设置内存标签:** 提供 `set_memory_tag()` 函数，用于将指针中的标签存储到指针指向的内存中。
5. **临时禁用 MTE:** 提供 `ScopedDisableMTE` 类，用于在特定代码块中临时禁用 MTE 检查。
6. **栈 MTE 环形缓冲区管理:** 提供一组函数 (`stack_mte_ringbuffer_size`, `stack_mte_ringbuffer_size_from_pointer`, `stack_mte_ringbuffer_size_add_to_pointer`, `stack_mte_free_ringbuffer`, `stack_mte_ringbuffer_allocate`) 用于管理用于栈内存标记的环形缓冲区。

**与 Android 功能的关系及举例说明:**

MTE 是 Android 增强内存安全性的重要机制。它通过在内存地址中添加一个小的标签（通常是 4 位），并在访问内存时检查指针的标签是否与内存的标签匹配，从而帮助检测内存错误。

*   **增强应用安全性:** Android 系统应用和第三方应用都可以利用 MTE 来提高自身的安全性，减少因内存错误导致的崩溃或漏洞。例如，一个使用 MTE 的应用可以更早地发现堆溢出，防止恶意代码利用该漏洞。
*   **系统级内存保护:** Android 框架本身也可以利用 MTE 来保护关键系统服务，防止恶意应用或漏洞影响系统稳定性和安全性。
*   **与 Scudo 集成:** 代码注释提到了 Scudo，它是 Android 的用户空间内存分配器。MTE 可以与 Scudo 协同工作，例如，Scudo 使用零标签作为块头部的标记，以防止线性堆溢出/欠溢出。
*   **栈保护:** `stack_mte_ringbuffer_*` 系列函数表明 MTE 也被用于栈内存保护。通过为栈分配特殊的环形缓冲区并标记栈上的变量，可以检测栈溢出等错误。

**libc 函数的功能实现:**

让我们详细解释每个 `libc` 函数的功能是如何实现的：

1. **`mte_supported()`:**
    *   **功能:** 检查当前系统是否支持 MTE。
    *   **实现:**  在 ARM64 架构上，它使用 `getauxval(AT_HWCAP2)` 来获取辅助向量，然后检查 `HWCAP2_MTE` 位是否被设置。`AT_HWCAP2` 包含硬件能力的信息，`HWCAP2_MTE` 是指示 MTE 支持的标志。在非 ARM64 架构上，它直接返回 `false`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 在支持 MTE 的 ARM64 设备上运行。
        *   **输出:** `true`
        *   **假设输入:** 在不支持 MTE 的设备或非 ARM64 设备上运行。
        *   **输出:** `false`

2. **`get_tagged_address(const void* ptr)`:**
    *   **功能:** 获取指向带有特定标签的内存地址的指针。
    *   **实现:**  在 ARM64 架构上且 MTE 支持的情况下，它使用内联汇编指令 `ldg` (load tag)。`ldg %0, [%0]` 的含义是将 `ptr` 指向的内存地址的标签加载到 `ptr` 中。实际上，这里的操作并不会改变内存中的标签，而是将指针本身的标签（如果存在）返回。如果没有启用 MTE，或者在非 ARM64 架构上，它只是简单地返回原始指针。`const_cast` 用于移除 `const` 属性，因为汇编操作可能会修改指针的值（添加标签）。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** `ptr` 指向地址 `0x1000`，并且该地址的标签为 `0xA`。
        *   **输出:** 返回的指针的值可能是 `0x100000000000000A` (高位存储标签)。具体格式取决于 MTE 的实现。
        *   **假设输入:** MTE 不支持。
        *   **输出:** 返回的指针的值为 `0x1000`。

3. **`insert_random_tag(const void* ptr, __attribute__((unused)) uint64_t mask = 0)`:**
    *   **功能:** 在指针中插入一个随机生成的标签。
    *   **实现:** 在 ARM64 架构上且 MTE 支持的情况下，它使用内联汇编指令 `irg` (insert random tag)。`irg %0, %0, %1` 的含义是在 `ptr` 中插入一个随机标签，并受 `mask` 的影响（`mask` 用于排除某些标签）。尽管 `mask` 参数被标记为 `unused`，但其设计意图是允许控制生成的随机标签。如果没有启用 MTE，或者在非 ARM64 架构上，它只是简单地返回原始指针。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** `ptr` 指向地址 `0x2000`。
        *   **输出:** 返回的指针的值可能是 `0x200000000000000B`（插入了一个随机标签，例如 `0xB`）。
        *   **假设输入:** MTE 不支持。
        *   **输出:** 返回的指针的值为 `0x2000`。

4. **`set_memory_tag(__attribute__((unused)) void* ptr)`:**
    *   **功能:** 将指针中的标签存储到指针指向的内存中，从而标记该内存。
    *   **实现:** 在 ARM64 架构上且 MTE 支持的情况下，它使用内联汇编指令 `stg` (store tag)。`stg %0, [%0]` 的含义是将 `ptr` 中的标签存储到 `ptr` 指向的内存地址。这步操作实际地给内存单元打上了标签。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** `ptr` 的值为 `0x300000000000000C` (地址 `0x3000`，标签 `0xC`)。
        *   **输出:** 地址 `0x3000` 处的内存被标记为 `0xC`。
        *   **假设输入:** MTE 不支持。
        *   **输出:** 该函数不执行任何操作。

5. **`ScopedDisableMTE` 类:**
    *   **功能:** 提供一种 RAII (Resource Acquisition Is Initialization) 风格的机制，用于在代码块执行期间临时禁用 MTE。
    *   **实现:**
        *   **构造函数:** 如果 MTE 被支持，构造函数会读取当前 Tag Check Override (TCO) 寄存器的值并将其保存到 `prev_tco_` 成员变量中，然后将 TCO 寄存器设置为 `#1`，从而禁用 MTE 检查。
        *   **析构函数:** 如果 MTE 被支持，析构函数会将 TCO 寄存器的值恢复为之前保存的 `prev_tco_`，从而重新启用 MTE 检查。
    *   **用户或编程常见的使用错误:**
        *   **忘记创建实例:** 如果需要禁用 MTE 的代码块没有创建 `ScopedDisableMTE` 的实例，MTE 将不会被禁用。
        *   **在不必要的地方使用:**  过度使用 `ScopedDisableMTE` 会降低 MTE 的保护效果。应该只在必要的时候禁用 MTE，例如在执行与 MTE 不兼容的旧代码或进行某些特定的底层操作时。

6. **栈 MTE 环形缓冲区管理函数:**
    *   这些函数用于管理用于栈内存标记的环形缓冲区。栈 MTE 使用环形缓冲区来存储最近分配和释放的栈帧的标签信息，以便在发生栈溢出等情况时进行检测。
    *   **`stack_mte_ringbuffer_size(uintptr_t size_cls)`:**
        *   **功能:** 根据给定的 size class 计算环形缓冲区的大小。
        *   **实现:**  缓冲区大小是 `kStackMteRingbufferSizeMultiplier` (硬编码为 4096) 乘以 `2` 的 `size_cls` 次方。
        *   **逻辑推理:** `stack_mte_ringbuffer_size(0)` 返回 4096，`stack_mte_ringbuffer_size(1)` 返回 8192，以此类推。
    *   **`stack_mte_ringbuffer_size_from_pointer(uintptr_t ptr)`:**
        *   **功能:** 从指向环形缓冲区的指针中提取缓冲区的大小。
        *   **实现:**  缓冲区的大小信息存储在指针的最高字节中（位 56-63）。它将指针右移 56 位，得到一个表示 "页" 数的值（这里的 "页" 指的是 `kStackMteRingbufferSizeMultiplier` 大小的块），然后乘以 `kStackMteRingbufferSizeMultiplier`。
    *   **`stack_mte_ringbuffer_size_add_to_pointer(uintptr_t ptr, uintptr_t size_cls)`:**
        *   **功能:** 将 size class 信息添加到指向环形缓冲区的指针的最高字节中。
        *   **实现:** 它使用位运算将 `size_cls` 左移 56 位，然后与 `ptr` 进行按位或运算，将大小信息存储到指针中。
    *   **`stack_mte_free_ringbuffer(uintptr_t stack_mte_tls)`:**
        *   **功能:** 释放栈 MTE 环形缓冲区。
        *   **实现:**  它首先使用 `stack_mte_ringbuffer_size_from_pointer` 从指针中获取缓冲区大小，然后使用 `munmap` 系统调用释放该内存。
    *   **`stack_mte_ringbuffer_allocate(size_t n, const char* name)`:**
        *   **功能:** 分配一个用于栈 MTE 的环形缓冲区。
        *   **实现:**
            *   它首先根据 size class `n` 计算所需的大小。
            *   为了满足 LLVM 代码生成的对齐要求（2 * size），它分配略大的内存 (3 * size - pagesize)，然后使用 `mmap` 系统调用分配匿名私有内存。
            *   它计算对齐到 `2 * size` 的地址，并使用 `munmap` 解除映射不需要的部分，以确保分配的内存块是对齐的。
            *   如果提供了名称，它使用 `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)` 来命名该内存区域，方便调试。
            *   最后，它将 size class 信息添加到返回的指针的最高字节中。
        *   **用户或编程常见的使用错误:**
            *   直接操作返回的指针的最高字节，可能会破坏大小信息。
            *   尝试释放并非由 `stack_mte_ringbuffer_allocate` 分配的内存。

**涉及 dynamic linker 的功能:**

这个头文件本身并不直接涉及 dynamic linker 的核心功能，但 MTE 作为一种系统级特性，会影响 dynamic linker 的行为和内存布局。

**SO 布局样本:**

一个典型的 Android shared object (`.so`) 文件的内存布局可能如下所示（简化）：

```
+-----------------------+  <-- 加载基址
|       ELF Header      |
+-----------------------+
|      Program Headers  |
+-----------------------+
|     Section Headers   |
+-----------------------+
|        .text         |  <-- 代码段
+-----------------------+
|        .rodata       |  <-- 只读数据段
+-----------------------+
|        .data         |  <-- 初始化数据段
+-----------------------+
|        .bss          |  <-- 未初始化数据段
+-----------------------+
|       .dynamic       |  <-- 动态链接信息
+-----------------------+
|    Symbol Table      |
+-----------------------+
|   String Table       |
+-----------------------+
|      ... other ...    |
+-----------------------+
```

**链接的处理过程:**

当 dynamic linker 加载一个 `.so` 文件时，它会将各个段加载到内存中的不同区域。MTE 的影响在于，在支持 MTE 的系统上，linker 和 loader 需要确保分配的内存区域可以被标记。

*   **内存分配:** Linker 会使用 `mmap` 等系统调用分配内存来加载 `.so` 文件的各个段。这些内存分配操作可能会受到 MTE 的影响，例如，确保分配的内存页可以设置标签。
*   **重定位:** Linker 需要修改 `.so` 文件中的某些指令和数据，以便它们指向正确的内存地址。在 MTE 环境下，如果涉及到指针操作，linker 可能会需要考虑标签的影响，但这通常由硬件和编译器透明地处理。
*   **PLT/GOT:** Procedure Linkage Table (PLT) 和 Global Offset Table (GOT) 是动态链接的关键组成部分。当一个 `.so` 文件调用另一个 `.so` 文件中的函数时，会通过 PLT 和 GOT 进行间接调用。MTE 可能会影响 GOT 的内容，因为 GOT 中存储的是函数指针，这些指针可能带有标签。

**由于这个 `mte.handroid` 文件主要关注的是 MTE 的使用接口，而不是 dynamic linker 的内部实现，所以这里只能给出一般性的说明。更深入的 dynamic linker 和 MTE 的交互需要查看 linker 的源代码。**

**Android Framework 或 NDK 如何一步步到达这里:**

1. **应用或 Framework 代码 (Java/Kotlin 或 C/C++):**  应用程序或 Android Framework 中的代码可能需要执行一些内存操作。
2. **NDK 库 (C/C++):** 如果是 NDK 应用，或者 Framework 调用了底层的 NDK 库，这些库可能会直接使用 `libc` 提供的函数。
3. **Bionic libc 函数调用:** NDK 库或 Framework 的 C/C++ 代码可能会调用 `malloc`, `free`, 或其他内存相关的 `libc` 函数。
4. **Scudo 内存分配器:** Android 默认的内存分配器 Scudo 内部可能会使用 MTE 相关的接口，例如在分配或释放内存时设置标签。
5. **`mte.handroid` 中的内联函数:**  Scudo 或其他 `libc` 组件可能会直接调用 `mte.handroid` 中定义的内联函数，例如 `insert_random_tag` 或 `set_memory_tag` 来操作内存标签。
6. **内核交互:** 最终，这些 MTE 相关的操作会通过系统调用（例如 `mmap`, `munmap`, 或其他与内存管理相关的 syscall）与内核进行交互。内核负责实际的内存标记和检查。

**Frida Hook 示例调试步骤:**

可以使用 Frida 来 hook `mte.handroid` 中的函数，以观察 MTE 的行为。以下是一些示例：

```javascript
// Hook mte_supported 函数
Interceptor.attach(Module.findExportByName("libc.so", "mte_supported"), {
  onEnter: function(args) {
    console.log("mte_supported called");
  },
  onLeave: function(retval) {
    console.log("mte_supported returned:", retval);
  }
});

// Hook insert_random_tag 函数
Interceptor.attach(Module.findExportByName("libc.so", "insert_random_tag"), {
  onEnter: function(args) {
    console.log("insert_random_tag called with ptr:", args[0]);
  },
  onLeave: function(retval) {
    console.log("insert_random_tag returned:", retval);
  }
});

// Hook set_memory_tag 函数
Interceptor.attach(Module.findExportByName("libc.so", "set_memory_tag"), {
  onEnter: function(args) {
    console.log("set_memory_tag called with ptr:", args[0]);
  }
});

// Hook stack_mte_ringbuffer_allocate 函数
Interceptor.attach(Module.findExportByName("libc.so", "stack_mte_ringbuffer_allocate"), {
  onEnter: function(args) {
    console.log("stack_mte_ringbuffer_allocate called with size_cls:", args[0], "name:", args[1].readUtf8String());
  },
  onLeave: function(retval) {
    console.log("stack_mte_ringbuffer_allocate returned:", retval);
  }
});
```

**调试步骤:**

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。
2. **编写 Frida 脚本:** 将上述 JavaScript 代码保存到一个文件中（例如 `mte_hook.js`）。
3. **找到目标进程:** 确定你想要调试的进程的名称或 PID。
4. **运行 Frida:** 使用 Frida 命令行工具将脚本注入到目标进程中：
    ```bash
    frida -U -f <package_name> -l mte_hook.js --no-pause
    # 或
    frida -U <process_name_or_pid> -l mte_hook.js
    ```
5. **触发 MTE 相关代码:** 在目标应用中执行可能触发 MTE 相关操作的代码。
6. **查看 Frida 输出:** Frida 会在控制台上打印出你 hook 的函数的调用信息和参数返回值，从而帮助你理解 MTE 的工作方式。

通过 Frida hook，你可以观察到哪些函数被调用，传递了哪些参数，以及 MTE 是否被启用，从而更深入地理解 Android 中 MTE 的使用。

Prompt: 
```
这是目录为bionic/libc/platform/bionic/mte.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2020 The Android Open Source Project
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

#include <stddef.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "page.h"

// Note: Most PR_MTE_* constants come from the upstream kernel. This tag mask
// allows for the hardware to provision any nonzero tag. Zero tags are reserved
// for scudo to use for the chunk headers in order to prevent linear heap
// overflow/underflow.
#define PR_MTE_TAG_SET_NONZERO (0xfffeUL << PR_MTE_TAG_SHIFT)

inline bool mte_supported() {
#if defined(__aarch64__)
  static bool supported = getauxval(AT_HWCAP2) & HWCAP2_MTE;
#else
  static bool supported = false;
#endif
  return supported;
}

inline void* get_tagged_address(const void* ptr) {
#if defined(__aarch64__)
  if (mte_supported()) {
    __asm__ __volatile__(".arch_extension mte; ldg %0, [%0]" : "+r"(ptr));
  }
#endif  // aarch64
  return const_cast<void*>(ptr);
}

// Inserts a random tag tag to `ptr`, using any of the set lower 16 bits in
// `mask` to exclude the corresponding tag from being generated. Note: This does
// not tag memory. This generates a pointer to be used with set_memory_tag.
inline void* insert_random_tag(const void* ptr, __attribute__((unused)) uint64_t mask = 0) {
#if defined(__aarch64__)
  if (mte_supported() && ptr) {
    __asm__ __volatile__(".arch_extension mte; irg %0, %0, %1" : "+r"(ptr) : "r"(mask));
  }
#endif  // aarch64
  return const_cast<void*>(ptr);
}

// Stores the address tag in `ptr` to memory, at `ptr`.
inline void set_memory_tag(__attribute__((unused)) void* ptr) {
#if defined(__aarch64__)
  if (mte_supported()) {
    __asm__ __volatile__(".arch_extension mte; stg %0, [%0]" : "+r"(ptr));
  }
#endif  // aarch64
}

#ifdef __aarch64__
class ScopedDisableMTE {
  size_t prev_tco_;

 public:
  ScopedDisableMTE() {
    if (mte_supported()) {
      __asm__ __volatile__(".arch_extension mte; mrs %0, tco; msr tco, #1" : "=r"(prev_tco_));
    }
  }

  ~ScopedDisableMTE() {
    if (mte_supported()) {
      __asm__ __volatile__(".arch_extension mte; msr tco, %0" : : "r"(prev_tco_));
    }
  }
};

// N.B. that this is NOT the pagesize, but 4096. This is hardcoded in the codegen.
// See
// https://github.com/search?q=repo%3Allvm/llvm-project%20AArch64StackTagging%3A%3AinsertBaseTaggedPointer&type=code
constexpr size_t kStackMteRingbufferSizeMultiplier = 4096;

inline size_t stack_mte_ringbuffer_size(uintptr_t size_cls) {
  return kStackMteRingbufferSizeMultiplier * (1 << size_cls);
}

inline size_t stack_mte_ringbuffer_size_from_pointer(uintptr_t ptr) {
  // The size in the top byte is not the size_cls, but the number of "pages" (not OS pages, but
  // kStackMteRingbufferSizeMultiplier).
  return kStackMteRingbufferSizeMultiplier * (ptr >> 56ULL);
}

inline uintptr_t stack_mte_ringbuffer_size_add_to_pointer(uintptr_t ptr, uintptr_t size_cls) {
  return ptr | ((1ULL << size_cls) << 56ULL);
}

inline void stack_mte_free_ringbuffer(uintptr_t stack_mte_tls) {
  size_t size = stack_mte_ringbuffer_size_from_pointer(stack_mte_tls);
  void* ptr = reinterpret_cast<void*>(stack_mte_tls & ((1ULL << 56ULL) - 1ULL));
  munmap(ptr, size);
}

inline void* stack_mte_ringbuffer_allocate(size_t n, const char* name) {
  if (n > 7) return nullptr;
  // Allocation needs to be aligned to 2*size to make the fancy code-gen work.
  // So we allocate 3*size - pagesz bytes, which will always contain size bytes
  // aligned to 2*size, and unmap the unneeded part.
  // See
  // https://github.com/search?q=repo%3Allvm/llvm-project%20AArch64StackTagging%3A%3AinsertBaseTaggedPointer&type=code
  //
  // In the worst case, we get an allocation that is one page past the properly
  // aligned address, in which case we have to unmap the previous
  // 2*size - pagesz bytes. In that case, we still have size properly aligned
  // bytes left.
  size_t size = stack_mte_ringbuffer_size(n);
  size_t pgsize = page_size();

  size_t alloc_size = __BIONIC_ALIGN(3 * size - pgsize, pgsize);
  void* allocation_ptr =
      mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (allocation_ptr == MAP_FAILED)
    return nullptr;
  uintptr_t allocation = reinterpret_cast<uintptr_t>(allocation_ptr);

  size_t alignment = 2 * size;
  uintptr_t aligned_allocation = __BIONIC_ALIGN(allocation, alignment);
  if (allocation != aligned_allocation) {
    munmap(reinterpret_cast<void*>(allocation), aligned_allocation - allocation);
  }
  if (aligned_allocation + size != allocation + alloc_size) {
    munmap(reinterpret_cast<void*>(aligned_allocation + size),
           (allocation + alloc_size) - (aligned_allocation + size));
  }

  if (name) {
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<void*>(aligned_allocation), size, name);
  }

  // We store the size in the top byte of the pointer (which is ignored)
  return reinterpret_cast<void*>(stack_mte_ringbuffer_size_add_to_pointer(aligned_allocation, n));
}
#else
struct ScopedDisableMTE {
  // Silence unused variable warnings in non-aarch64 builds.
  ScopedDisableMTE() {}
};
#endif

"""

```