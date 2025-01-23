Response:
Let's break down the thought process to analyze the provided C++ code.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of `jemalloc_wrapper.cpp`. Key areas of focus are:

* **Functionality:** What does this code do?
* **Android Relevance:** How does it tie into Android's workings?
* **Detailed Function Explanation:**  Explain the implementation of each function.
* **Dynamic Linker Integration:** If applicable, detail the SO layout and linking process.
* **Logic and Examples:** Provide hypothetical inputs/outputs and common errors.
* **Android Framework/NDK Path:**  Explain how the code is reached from higher levels.
* **Debugging with Frida:**  Give a Frida hook example.

**2. Initial Code Scan and Identification of Key Areas:**

A quick glance reveals the following:

* **Copyright and License:** Standard open-source boilerplate.
* **Includes:**  Standard C library headers (`errno.h`, `inttypes.h`, `malloc.h`, etc.), Android-specific headers (`async_safe/log.h`, `private/MallocXmlElem.h`), and the core jemalloc header (`jemalloc.h`). This immediately tells us it's a wrapper around jemalloc specifically for Android.
* **Forward Declarations:**  Functions prefixed with `je_` are declared. This suggests they are jemalloc's internal functions.
* **Function Definitions:** Several functions are defined (`je_pvalloc`, `je_memalign_round_up_boundary`, `je_aligned_alloc_wrapper`, `je_mallopt`, `je_malloc_info`). These are the core of the wrapper.
* **Conditional Compilation (`#ifdef`):**  Code sections that undefine existing `je_memalign` and `je_aligned_alloc` suggest the wrapper is providing its own implementations.
* **`je_mallctl` Calls:** Frequent calls to `je_mallctl` indicate interaction with jemalloc's control interface for runtime configuration and statistics.
* **Logging:** The use of `async_safe_format_log` shows logging within the Android system.
* **XML Output:** The `MallocXmlElem` class suggests generating XML output, likely for memory profiling or debugging.

**3. Detailed Function Analysis (Iterative Process):**

For each defined function, I'd go through the following steps:

* **Purpose:** What is the intended goal of this function?  (e.g., allocate page-aligned memory, handle `mallopt` calls, provide memory information).
* **Implementation:**  How does the code achieve this?
    * **Break down the logic step by step.**
    * **Identify key function calls** (especially to jemalloc functions).
    * **Understand the conditional logic (if/else statements).**
    * **Look for error handling** (setting `errno`).
* **Relationship to Android:** How does this function fit into Android's memory management?  Does it provide specific behavior required by Android?
* **Potential Issues/Edge Cases:**  What could go wrong? What are the limitations?

**Example: Analyzing `je_pvalloc`**

1. **Purpose:** Allocate memory aligned to page boundaries.
2. **Implementation:**
   * Get page size using `getpagesize()`.
   * Calculate the aligned size using `__BIONIC_ALIGN`.
   * Check for integer overflow (`size < bytes`).
   * Call `je_memalign` with the page size as the alignment.
3. **Android Relevance:** Page-aligned allocations are often needed for memory mapping (`mmap`).
4. **Potential Issues:** Integer overflow during size calculation.

**4. Dynamic Linker Analysis:**

* **Identify Linkage:**  The code itself doesn't directly manipulate the dynamic linker. However, it provides implementations for functions that *will be called* by dynamically linked libraries (e.g., `malloc`, `free`, `memalign`).
* **SO Layout:**  Think about where this code resides. It's part of `libc.so`, a core Android library. Other libraries link against `libc.so`.
* **Linking Process:** When an application or library uses `malloc`, the dynamic linker resolves this symbol to the implementation in `libc.so` (which in this case, is the jemalloc wrapper).

**5. Logic and Examples:**

* **Hypothetical Inputs/Outputs:** For simple functions, this is straightforward (e.g., `je_pvalloc(1000)` might return a pointer to 4096 bytes of memory). For more complex functions (`je_mallopt`), consider the input parameters and the expected effect on jemalloc's internal state.
* **Common Errors:** Think about how a programmer might misuse these functions (e.g., providing a non-power-of-two alignment to `memalign` before the wrapper's fix, or a non-multiple size to `aligned_alloc`).

**6. Android Framework/NDK Path:**

* **Start with the User:** How does a developer trigger memory allocation?  Through Java APIs (which eventually call native code) or directly through the NDK.
* **Trace Down:**  Follow the call stack. A Java `new` might call into native code, which then uses `malloc`. The NDK directly provides `malloc`.
* **Focus on the Entry Point:** The key is that `libc.so` provides the standard C memory allocation functions, and this wrapper is *inside* `libc.so`.

**7. Frida Hook Example:**

* **Choose a Function:** Select a function you want to monitor (e.g., `je_pvalloc`).
* **Basic Hooking:**  Use Frida's `Interceptor.attach` to intercept calls to the function.
* **Log Arguments and Return Value:**  Inside the hook, log the input arguments and the returned pointer.

**8. Structuring the Response:**

Organize the information logically, using clear headings and bullet points. Provide code snippets where relevant. Ensure the language is clear and concise. Address all parts of the original request.

**Self-Correction/Refinement during the process:**

* **Realization:**  Initially, I might have focused too heavily on the specific jemalloc implementation details. The request emphasizes the *wrapper*. I need to shift focus to how the wrapper modifies or enhances jemalloc's behavior within the Android context.
* **Clarification:**  If a function's purpose isn't immediately obvious, I'd reread the code carefully and consult documentation (if available) for the underlying jemalloc functions.
* **Accuracy:** Double-check details, especially when explaining the dynamic linking process or the interaction with Android's internal components.

By following this systematic approach, I can produce a comprehensive and accurate analysis of the provided `jemalloc_wrapper.cpp` code.
好的，让我们深入分析 `bionic/libc/bionic/jemalloc_wrapper.cpp` 这个文件。

**功能概览:**

`jemalloc_wrapper.cpp` 文件是 Android Bionic C 库中用来包装 `jemalloc` 内存分配器的代码。它的主要功能是提供一组与标准 C 库内存管理函数（如 `malloc`, `free`, `memalign` 等）兼容的接口，但底层实现委托给了 `jemalloc`。这个包装层允许 Android 系统使用 `jemalloc` 提供的更高级的内存管理特性，同时保持与现有代码的兼容性。

**与 Android 功能的关系及举例:**

这个文件是 Android 内存管理的核心组成部分。Android 框架和 NDK 开发的应用程序在进行内存分配和释放时，最终会调用到 `libc.so` 中提供的内存管理函数。由于 `jemalloc_wrapper.cpp` 实现了这些函数的包装，它实际上控制着 Android 应用的内存分配行为。

**举例说明:**

1. **性能优化:** `jemalloc` 通常比传统的 `dlmalloc` 或其他简单分配器在多线程环境下具有更好的性能。Android 使用 `jemalloc` 可以提升应用程序的内存分配效率，尤其是在并发量大的场景下。

2. **内存统计和调试:** `jemalloc` 提供了丰富的内存统计信息。`jemalloc_wrapper.cpp` 中的 `je_mallopt` 和 `je_malloc_info` 函数利用了这些特性，使得开发者可以通过标准接口获取更详细的内存使用情况，辅助内存泄漏检测和性能分析。

3. **内存回收策略:** `jemalloc` 允许更精细的内存回收控制。`je_mallopt` 中对 `M_DECAY_TIME` 的处理就体现了这一点，允许调整空闲内存的回收时间，从而平衡内存占用和性能。

**libc 函数的实现细节:**

`jemalloc_wrapper.cpp` 并没有重新实现所有的 `libc` 内存管理函数，而是提供了一些特定函数的包装或扩展。让我们逐个分析：

1. **`je_pvalloc(size_t bytes)`:**
   - **功能:** 分配大小为 `bytes` 且内存页对齐的内存。
   - **实现:**
     - 获取系统的页大小 (`getpagesize()`)。
     - 将请求的字节数向上对齐到页大小 (`__BIONIC_ALIGN`)。
     - 如果对齐后的尺寸小于原始请求大小，说明发生溢出，返回 `nullptr`。
     - 调用 `jemalloc` 提供的 `je_memalign` 函数，以页大小作为对齐边界分配内存。

2. **`je_memalign_round_up_boundary(size_t boundary, size_t size)`:**
   - **功能:** 分配大小为 `size` 且地址是 `boundary` 的倍数的内存。如果 `boundary` 不是 2 的幂，则将其向上舍入到最近的 2 的幂。
   - **实现:**
     - 检查 `boundary` 是否为 0。如果是，则将其设置为 1。
     - 检查 `boundary` 是否是 2 的幂 (`!powerof2(boundary)`)。如果不是，则使用 `BIONIC_ROUND_UP_POWER_OF_2` 宏将其向上舍入到最近的 2 的幂。
     - 调用 `jemalloc` 提供的 `je_memalign` 函数进行实际的内存分配。
   - **与标准 `memalign` 的区别:** 标准 `memalign` 要求 `boundary` 必须是 2 的幂，否则会失败。这里的实现使其更宽容，向上调整了 `boundary`。

3. **`je_aligned_alloc_wrapper(size_t alignment, size_t size)`:**
   - **功能:** 分配大小为 `size` 且地址是 `alignment` 的倍数的内存。
   - **实现:**
     - 检查 `size` 是否是 `alignment` 的倍数 (`(size % alignment) != 0`)。如果不是，设置 `errno` 为 `EINVAL` 并返回 `nullptr`。
     - 调用 `jemalloc` 提供的 `je_aligned_alloc` 函数进行实际分配。
   - **原因:** `jemalloc` 本身可能不强制要求 `size` 是 `alignment` 的倍数，但标准 `aligned_alloc` 有此要求，因此这里添加了额外的校验。

4. **`je_mallopt(int param, int value)`:**
   - **功能:** 提供内存分配器的控制选项。
   - **实现:**
     - **`M_DECAY_TIME`:**  控制空闲内存的回收时间。
       - 将 `value` 转换为毫秒：`< 0` 表示禁用（设置为一个很大的值），`> 0` 表示 1 秒，`0` 表示立即回收。
       - 使用 `je_mallctl` 函数来设置全局和每个 arena 的 `dirty_decay_ms` 和 `muzzy_decay_ms` 参数。Arena 是 `jemalloc` 管理内存的区域。
     - **`M_PURGE` / `M_PURGE_ALL`:**  尝试释放未使用的内存。
       - 调用 `je_mallctl("thread.tcache.flush", ...)` 清空当前线程的缓存。
       - 调用 `je_mallctl` 清理 arena 中的内存。
     - **`M_LOG_STATS`:**  打印内存分配器的统计信息。
       - 遍历所有 arena，使用 `je_mallinfo_arena_info` 获取 arena 级别的统计信息。
       - 使用 `je_stats_arena` 和回调函数打印更细粒度的 size class 统计信息。
   - **与标准 `mallopt` 的区别:**  这里的实现只支持 `M_DECAY_TIME`, `M_PURGE`, 和 `M_LOG_STATS` 这几个选项，其他的 `mallopt` 参数可能被忽略。

5. **`je_malloc_info(int options, FILE* fp)`:**
   - **功能:**  将内存分配器的信息以 XML 格式输出到指定的文件流。
   - **实现:**
     - 检查 `options` 是否为 0，非 0 则返回错误。
     - 使用自定义的 `MallocXmlElem` 类来生成 XML 结构。
     - 遍历所有 arena，获取 arena 和 bin 的统计信息 (`je_mallinfo_arena_info`, `je_mallinfo_bin_info`)。
     - 将分配的 large 块、huge 块和 bins 的信息写入 XML。

**涉及 dynamic linker 的功能及处理过程:**

`jemalloc_wrapper.cpp` 本身并不直接参与 dynamic linker 的工作，但它提供的函数最终会被 dynamic linker 加载和链接到应用程序或共享库中。

**SO 布局样本:**

```
libc.so:
    ...
    符号表:
        ...
        malloc  (指向 jemalloc_wrapper.cpp 中包装的 malloc 实现)
        free    (指向 jemalloc_wrapper.cpp 中包装的 free 实现)
        memalign (指向 jemalloc_wrapper.cpp 中的 je_memalign_round_up_boundary)
        aligned_alloc (指向 jemalloc_wrapper.cpp 中的 je_aligned_alloc_wrapper)
        mallopt (指向 jemalloc_wrapper.cpp 中的 je_mallopt)
        malloc_info (指向 jemalloc_wrapper.cpp 中的 je_malloc_info)
        ...
```

**链接的处理过程:**

1. 当一个应用程序或共享库需要调用 `malloc` 时，编译器会在其目标文件中记录一个对 `malloc` 符号的未解析引用。
2. 在程序或库加载时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责解析这些符号。
3. Dynamic linker 会查找系统中已加载的共享库，例如 `libc.so`，以找到 `malloc` 的定义。
4. 在 `libc.so` 的符号表中，`malloc` 符号被定义为指向 `jemalloc_wrapper.cpp` 中包装的 `malloc` 实现（实际上是 `jemalloc` 提供的 `je_malloc`）。
5. Dynamic linker 将应用程序或共享库中的 `malloc` 调用重定向到 `libc.so` 中 `malloc` 的实际地址。

**逻辑推理、假设输入与输出:**

**例子：`je_memalign_round_up_boundary`**

- **假设输入:** `boundary = 7`, `size = 100`
- **逻辑推理:**
    - `boundary` 不是 2 的幂。
    - `BIONIC_ROUND_UP_POWER_OF_2(7)` 会计算出 8。
    - 调用 `je_memalign(8, 100)`。
- **预期输出:** 返回一个指向大小为 100 字节，且起始地址是 8 的倍数的内存块的指针。

**例子：`je_aligned_alloc_wrapper`**

- **假设输入:** `alignment = 16`, `size = 32`
- **逻辑推理:** `32 % 16 == 0`，条件成立。调用 `je_aligned_alloc(16, 32)`。
- **预期输出:** 返回一个指向大小为 32 字节，且起始地址是 16 的倍数的内存块的指针。

- **假设输入:** `alignment = 16`, `size = 30`
- **逻辑推理:** `30 % 16 != 0`，条件不成立。
- **预期输出:** 返回 `nullptr`，并设置 `errno` 为 `EINVAL`。

**用户或编程常见的使用错误:**

1. **`memalign` 使用非 2 的幂作为边界 (在 wrapper 修复之前):**
   ```c++
   void* ptr = memalign(7, 100); // 在某些系统中会失败
   ```
   `jemalloc_wrapper.cpp` 通过 `je_memalign_round_up_boundary` 修正了这个问题。

2. **`aligned_alloc` 的 `size` 不是 `alignment` 的倍数:**
   ```c++
   void* ptr = aligned_alloc(16, 30); // 错误：size 必须是 alignment 的倍数
   if (ptr == nullptr && errno == EINVAL) {
       // 正确处理错误
   }
   ```
   `je_aligned_alloc_wrapper` 检查并处理了这个错误。

3. **错误地理解 `mallopt` 的行为:**
   ```c++
   mallopt(M_TRIM_THRESHOLD, 128 * 1024); // 在 Android 中可能不会有预期效果
   ```
   由于 `jemalloc_wrapper.cpp` 只实现了部分 `mallopt` 功能，调用未实现的参数可能不会产生任何作用，或者被忽略。

**Android framework 或 ndk 如何到达这里:**

1. **Java 代码 (Android Framework):**
   - 当 Java 代码需要分配内存时，例如创建一个新的 `Bitmap` 对象或者 `byte[]` 数组，JVM 会通过 JNI 调用 Native 代码。
   - 在 Native 代码中，可能会使用 `malloc` 或 `new` 来分配内存。
   - 这些 `malloc` 调用会被链接到 `libc.so` 中 `jemalloc_wrapper.cpp` 提供的实现。

2. **NDK 开发 (C/C++):**
   - 使用 NDK 开发的应用程序可以直接调用标准 C 库的内存分配函数，如 `malloc`, `free`, `memalign`, `aligned_alloc` 等。
   - 这些函数调用会直接链接到 `libc.so` 中 `jemalloc_wrapper.cpp` 提供的实现。

**Frida Hook 示例调试步骤:**

假设我们要 hook `je_pvalloc` 函数，查看其分配的大小和返回的地址。

1. **找到 `je_pvalloc` 在 `libc.so` 中的地址:**
   可以使用 `adb shell` 和 `grep` 命令来查找 `je_pvalloc` 在 `/system/lib64/libc.so` (或 `/system/lib/libc.so` for 32-bit) 中的地址。
   ```bash
   adb shell
   grep " je_pvalloc" /apex/com.android.runtime/lib64/bionic/linker64/exported_symbols/libc.so.txt  # Android 10+
   # 或者
   grep " je_pvalloc" /system/lib64/libc.so # Android 9 及更早版本
   ```
   输出类似：`00000000000xxxxx T je_pvalloc`，其中 `00000000000xxxxx` 是函数的地址。

2. **编写 Frida Hook 脚本 (JavaScript):**
   ```javascript
   if (Process.arch === 'arm64') {
       var je_pvalloc_addr = Module.findExportByName("libc.so", "je_pvalloc"); // 更可靠的方式
   } else if (Process.arch === 'arm') {
       var je_pvalloc_addr = Module.findExportByName("libc.so", "_Z10je_pvallocm"); // 名称可能被 mangled
   } else {
       console.log("Unsupported architecture.");
   }

   if (je_pvalloc_addr) {
       Interceptor.attach(je_pvalloc_addr, {
           onEnter: function (args) {
               var bytes = args[0].toInt();
               console.log("je_pvalloc called with size:", bytes);
           },
           onLeave: function (retval) {
               console.log("je_pvalloc returned:", retval);
           }
       });
       console.log("Hooked je_pvalloc at:", je_pvalloc_addr);
   } else {
       console.error("Could not find je_pvalloc.");
   }
   ```

3. **运行 Frida 脚本:**
   使用 Frida 连接到目标 Android 进程并运行脚本。例如，如果目标进程的进程 ID 是 `12345`：
   ```bash
   frida -U -f <your_package_name> -l your_script.js
   # 或者 attach 到已运行的进程
   frida -U <your_package_name> -l your_script.js
   ```

4. **触发内存分配:**
   在被 Hook 的应用程序中执行会调用 `pvalloc` 的操作。例如，创建一个需要页对齐内存的对象。

5. **查看 Frida 输出:**
   Frida 的控制台会打印出 `je_pvalloc` 被调用的信息，包括请求的字节数和返回的内存地址。

这个例子展示了如何使用 Frida 来动态地观察 `jemalloc_wrapper.cpp` 中函数的行为，这对于理解 Android 的内存管理机制和调试相关问题非常有帮助。

希望这个详细的分析能够帮助你理解 `bionic/libc/bionic/jemalloc_wrapper.cpp` 的功能和作用。

### 提示词
```
这是目录为bionic/libc/bionic/jemalloc_wrapper.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <inttypes.h>
#include <malloc.h>
#include <sys/param.h>
#include <unistd.h>

#include <async_safe/log.h>
#include <private/MallocXmlElem.h>

#include "jemalloc.h"

__BEGIN_DECLS

size_t je_mallinfo_narenas();
size_t je_mallinfo_nbins();
struct mallinfo je_mallinfo_arena_info(size_t);
struct mallinfo je_mallinfo_bin_info(size_t, size_t);
void je_stats_arena(size_t arena_index, void (*callback)(size_t, size_t, size_t));

__END_DECLS

void* je_pvalloc(size_t bytes) {
  size_t pagesize = getpagesize();
  size_t size = __BIONIC_ALIGN(bytes, pagesize);
  if (size < bytes) {
    return nullptr;
  }
  return je_memalign(pagesize, size);
}

#ifdef je_memalign
#undef je_memalign
#endif

// The man page for memalign says it fails if boundary is not a power of 2,
// but this is not true. Both glibc and dlmalloc round up to the next power
// of 2, so we'll do the same.
void* je_memalign_round_up_boundary(size_t boundary, size_t size) {
  if (boundary != 0) {
    if (!powerof2(boundary)) {
      boundary = BIONIC_ROUND_UP_POWER_OF_2(boundary);
    }
  } else {
    boundary = 1;
  }
  return je_memalign(boundary, size);
}

#ifdef je_aligned_alloc
#undef je_aligned_alloc
#endif

// The aligned_alloc function requires that size is a multiple of alignment.
// jemalloc doesn't enforce this, so add enforcement here.
void* je_aligned_alloc_wrapper(size_t alignment, size_t size) {
  if ((size % alignment) != 0) {
    errno = EINVAL;
    return nullptr;
  }
  return je_aligned_alloc(alignment, size);
}

int je_mallopt(int param, int value) {
  // The only parameter we currently understand is M_DECAY_TIME.
  if (param == M_DECAY_TIME) {
    // Only support setting the value to -1 or 0 or 1.
    ssize_t decay_time_ms;
    if (value < 0) {
      // Given that SSIZE_MAX may not be supported in jemalloc, set this to a
      // sufficiently large number that essentially disables the decay timer.
      decay_time_ms = 10000000;
    } else if (value) {
      decay_time_ms = 1000;
    } else {
      decay_time_ms = 0;
    }
    // First get the total number of arenas.
    unsigned narenas;
    size_t sz = sizeof(unsigned);
    if (je_mallctl("arenas.narenas", &narenas, &sz, nullptr, 0) != 0) {
      return 0;
    }

    // Set the decay time for any arenas that will be created in the future.
    if (je_mallctl("arenas.dirty_decay_ms", nullptr, nullptr, &decay_time_ms, sizeof(decay_time_ms)) != 0) {
      return 0;
    }
    if (je_mallctl("arenas.muzzy_decay_ms", nullptr, nullptr, &decay_time_ms, sizeof(decay_time_ms)) != 0) {
      return 0;
    }

    // Change the decay on the already existing arenas.
    char buffer[100];
    for (unsigned i = 0; i < narenas; i++) {
      snprintf(buffer, sizeof(buffer), "arena.%d.dirty_decay_ms", i);
      if (je_mallctl(buffer, nullptr, nullptr, &decay_time_ms, sizeof(decay_time_ms)) != 0) {
        break;
      }
      snprintf(buffer, sizeof(buffer), "arena.%d.muzzy_decay_ms", i);
      if (je_mallctl(buffer, nullptr, nullptr, &decay_time_ms, sizeof(decay_time_ms)) != 0) {
        break;
      }
    }
    return 1;
  } else if (param == M_PURGE || param == M_PURGE_ALL) {
    // Only clear the current thread cache since there is no easy way to
    // clear the caches of other threads.
    // This must be done first so that cleared allocations get purged
    // in the next calls.
    // Ignore the return call since this will fail if the tcache is disabled.
    je_mallctl("thread.tcache.flush", nullptr, nullptr, nullptr, 0);

    unsigned narenas;
    size_t sz = sizeof(unsigned);
    if (je_mallctl("arenas.narenas", &narenas, &sz, nullptr, 0) != 0) {
      return 0;
    }
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "arena.%u.purge", narenas);
    if (je_mallctl(buffer, nullptr, nullptr, nullptr, 0) != 0) {
      return 0;
    }
    return 1;
  } else if (param == M_LOG_STATS) {
    size_t total_bytes = 0;
    for (size_t i = 0; i < je_mallinfo_narenas(); i++) {
      struct mallinfo mi = je_mallinfo_arena_info(i);
      size_t arena_bytes = mi.fsmblks + mi.ordblks + mi.uordblks;
      async_safe_format_log(ANDROID_LOG_INFO, "jemalloc",
                            "Arena %zu: bin bytes=%zu large bytes=%zu total bytes=%zu", i,
                            mi.fsmblks, mi.ordblks, arena_bytes);

      je_stats_arena(i, [](size_t index, size_t size, size_t allocs) {
        if (allocs != 0) {
          async_safe_format_log(ANDROID_LOG_INFO, "jemalloc",
                                "  Size Class %zu(%zu bytes): allocs=%zu total bytes=%zu", index,
                                size, allocs, allocs * size);
        }
      });
      total_bytes += arena_bytes;
    }
    async_safe_format_log(ANDROID_LOG_INFO, "jemalloc", "Total Bytes=%zu", total_bytes);
    return 1;
  }

  return 0;
}

int je_malloc_info(int options, FILE* fp) {
  if (options != 0) {
    errno = EINVAL;
    return -1;
  }

  fflush(fp);
  int fd = fileno(fp);
  MallocXmlElem root(fd, "malloc", "version=\"jemalloc-1\"");

  // Dump all of the large allocations in the arenas.
  for (size_t i = 0; i < je_mallinfo_narenas(); i++) {
    struct mallinfo mi = je_mallinfo_arena_info(i);
    if (mi.hblkhd != 0) {
      MallocXmlElem arena_elem(fd, "heap", "nr=\"%d\"", i);
      {
        MallocXmlElem(fd, "allocated-large").Contents("%zu", mi.ordblks);
        MallocXmlElem(fd, "allocated-huge").Contents("%zu", mi.uordblks);
        MallocXmlElem(fd, "allocated-bins").Contents("%zu", mi.fsmblks);

        size_t total = 0;
        for (size_t j = 0; j < je_mallinfo_nbins(); j++) {
          struct mallinfo mi = je_mallinfo_bin_info(i, j);
          if (mi.ordblks != 0) {
            MallocXmlElem bin_elem(fd, "bin", "nr=\"%d\"", j);
            MallocXmlElem(fd, "allocated").Contents("%zu", mi.ordblks);
            MallocXmlElem(fd, "nmalloc").Contents("%zu", mi.uordblks);
            MallocXmlElem(fd, "ndalloc").Contents("%zu", mi.fordblks);
            total += mi.ordblks;
          }
        }
        MallocXmlElem(fd, "bins-total").Contents("%zu", total);
      }
    }
  }

  return 0;
}
```