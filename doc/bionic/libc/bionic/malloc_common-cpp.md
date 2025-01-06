Response:
Let's break down the thought process to answer the request about `malloc_common.cpp`.

**1. Understanding the Core Purpose:**

The initial comments in the file are crucial. They immediately tell us this file acts as a "thin layer" or intermediary. It doesn't implement the actual memory allocation but *dispatches* calls to the real allocator. The key takeaway is the debug malloc mechanism, which can be activated via a system property. This immediately suggests a conditional execution path.

**2. Identifying Key Functions and Structures:**

Scanning the code reveals the standard C memory allocation functions (`malloc`, `calloc`, `free`, `realloc`, `memalign`, etc.). The presence of `GetDispatchTable()` is a major hint. This likely returns a function pointer table, allowing the choice of the underlying allocator at runtime. The global function pointers `__malloc_hook`, `__realloc_hook`, etc., point towards the possibility of user-defined memory allocation interception.

**3. Analyzing the Dispatch Mechanism:**

The pattern in almost every exported function is the same:
   - Call `GetDispatchTable()`.
   - If the result is not null, call the corresponding function in the dispatch table.
   - Otherwise, call the default `Malloc(...)` function.

This confirms the "thin layer" idea and highlights the importance of `GetDispatchTable()`. It also raises the question of *how* this dispatch table is populated. This is a point where external knowledge about Android's memory management becomes important. We know about the debug malloc and how system properties influence behavior.

**4. Connecting to Android Functionality:**

The comments mentioning the "libc shared library" and the "libc.debug.malloc.options" property are direct links to Android's functionality. The debug malloc feature is a prime example of Android-specific customization. The presence of `heap_tagging.h`, `heap_zero_init.h`, and `malloc_tagged_pointers.h` suggests additional Android-specific memory management features.

**5. Explaining `libc` Functions:**

For each `libc` function, the explanation should cover:
   - Its basic purpose (what it does).
   - How it's implemented in this file (the dispatch mechanism).
   - Potential Android-specific aspects (like tagging).

**6. Addressing Dynamic Linking:**

The file itself doesn't directly *perform* dynamic linking. However, its structure (the dispatch table) is *influenced* by dynamic linking. The debug malloc is a separate shared object (`.so`). The `GetDispatchTable()` function is the key connection point. The explanation needs to cover:
   - The role of the dynamic linker in loading shared libraries.
   - How the debug malloc `.so` would be loaded (when the property is set).
   - How `GetDispatchTable()` would be implemented to return the debug malloc's function pointers.

A sample `.so` layout and the linking process needs to be illustrated conceptually, highlighting the relocation of symbols.

**7. Considering User Errors and Logic:**

Common memory management errors are universal (double-free, use-after-free, memory leaks). Examples should be simple and illustrative. The logic within `malloc_common.cpp` is mainly about dispatching, so the core logic errors reside in the *underlying allocators*.

**8. Tracing the Path from Framework/NDK:**

This requires understanding the layers of Android. Start from a high-level action (e.g., a Java object allocation). Trace down through the VM (if involved), then the JNI bridge to native code, and finally to a `malloc` call in the NDK. The example should be concrete.

**9. Frida Hooking:**

Frida examples should target the key functions. Hooking `malloc`, `free`, and `GetDispatchTable` (if possible and useful for observation) are good starting points. The example should show how to intercept calls, inspect arguments, and potentially modify behavior.

**10. Structuring the Response:**

Organize the information clearly using headings and subheadings. Use bullet points for lists of functionalities and examples. Keep the language precise and avoid jargon where possible, or explain it when used. Address each part of the prompt explicitly.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the code within the file.
* **Correction:** Realize that understanding the *context* (Android's memory management, dynamic linking) is crucial. The file is an *interface* to other components.
* **Initial thought:** Simply list the functions and their direct implementations.
* **Correction:** Explain the dispatch mechanism and its significance.
* **Initial thought:** Provide a very low-level detailed explanation of dynamic linking.
* **Correction:** Focus on the *conceptual* aspects relevant to this file and the debug malloc. A high-level overview is sufficient.
* **Initial thought:** Provide complex Frida examples.
* **Correction:** Keep the Frida examples simple and focused on demonstrating interception.

By following this thought process, which involves understanding the code, its context within Android, and the specific points requested by the prompt, we can generate a comprehensive and accurate answer.
好的，让我们详细分析一下 `bionic/libc/bionic/malloc_common.cpp` 这个文件。

**文件功能概述**

`malloc_common.cpp` 在 Android Bionic 库中扮演着一个核心的中间层角色，它的主要功能是：

1. **作为内存分配函数的统一入口点：**  它定义了 `malloc`、`calloc`、`free`、`realloc` 等标准 C 内存分配函数的接口。应用程序调用这些函数时，实际上首先会进入 `malloc_common.cpp` 中的实现。

2. **内存分配策略的动态切换：**  它允许在运行时选择不同的底层内存分配器实现。默认情况下，它使用 Bionic 内置的内存分配器。但是，通过设置系统属性 `"libc.debug.malloc.options"`，可以加载一个独立的调试 malloc 共享库，从而替换默认的分配器。

3. **内存分配钩子 (Hooks)：** 它定义了全局的函数指针 `__malloc_hook`、`__realloc_hook`、`__free_hook`、`__memalign_hook`。这些钩子允许开发者或调试工具在内存分配的关键时刻插入自定义的代码，例如用于内存泄漏检测、性能分析等。

4. **Android 特有的内存管理功能集成：**  它集成了 Android 特有的内存管理特性，例如：
    * **堆标签 (Heap Tagging)：** 用于在分配的内存块上添加标签，以便更好地进行调试和分析。
    * **堆零初始化 (Heap Zero Initialization)：** 允许在分配内存时将其初始化为零。
    * **Tagged Pointers 支持：**  处理带有标签的指针，用于内存安全检查。

5. **libmemunreachable 集成：**  提供了 `malloc_iterate`、`malloc_disable`、`malloc_enable` 等函数，用于支持 `libmemunreachable` 库进行内存泄漏检测。

**与 Android 功能的关系及举例**

`malloc_common.cpp` 与 Android 的功能紧密相关，它是 Android 系统中所有内存分配操作的基础。

* **应用程序内存分配：** 所有的 Android 应用程序（无论是 Java 代码还是 Native 代码）在需要分配内存时，最终都会调用到这里定义的 `malloc`、`calloc` 等函数。例如，一个 Java `new` 操作，最终会通过 Dalvik/ART 虚拟机的 JNI 调用到 Native 代码的 `malloc`。

* **系统服务内存分配：** Android 的各种系统服务，例如 Activity Manager、PackageManager 等，在运行时也需要分配和管理内存，它们同样会使用这里的内存分配函数。

* **NDK 开发：** 使用 Android NDK 进行 Native 开发的开发者直接使用的就是 `malloc_common.cpp` 提供的内存分配接口。

* **调试功能：**  通过设置 `"libc.debug.malloc.options"` 属性，可以启用调试 malloc，这对于诊断内存相关的错误（例如内存泄漏、野指针访问）至关重要。例如，设置 `libc.debug.malloc.options=guard` 可以启用内存边界保护。

**libc 函数的实现细节**

`malloc_common.cpp` 中的 libc 内存分配函数实现通常遵循以下模式：

1. **获取分发表 (Dispatch Table)：** 调用 `GetDispatchTable()` 函数来获取当前使用的内存分配器的函数指针表。这个分发表包含了实际执行内存分配操作的函数指针。

2. **条件执行：**
   * **如果分发表不为空 (调试 malloc 已启用)：** 调用分发表中对应的函数指针，例如 `dispatch_table->malloc(bytes)`。
   * **如果分发表为空 (使用默认 malloc)：** 调用 `Malloc(函数名)(参数)` 宏。这个宏会将调用转发到 Bionic 默认的内存分配器实现。

3. **Tagged Pointer 处理：**  `MaybeTagPointer()` 和 `MaybeUntagAndCheckPointer()` 函数用于处理带有标签的指针。在分配内存后，`MaybeTagPointer()` 可能会给返回的指针添加标签。在释放内存前，`MaybeUntagAndCheckPointer()` 会移除标签并进行一些安全检查。

**示例：`malloc(size_t bytes)` 的实现**

```c++
extern "C" void* malloc(size_t bytes) {
  auto dispatch_table = GetDispatchTable();
  void *result;
  if (__predict_false(dispatch_table != nullptr)) {
    result = dispatch_table->malloc(bytes);
  } else {
    result = Malloc(malloc)(bytes);
  }
  if (__predict_false(result == nullptr)) {
    warning_log("malloc(%zu) failed: returning null pointer", bytes);
    return nullptr;
  }
  return MaybeTagPointer(result);
}
```

* 当调用 `malloc(size)` 时，首先获取 `dispatch_table`。
* 如果调试 malloc 被激活，则调用调试 malloc 的 `malloc` 实现。
* 否则，调用 Bionic 默认的 `malloc` 实现。
* 如果分配失败，会打印警告日志。
* 最后，使用 `MaybeTagPointer()` 对返回的指针进行可能的标签处理。

**动态链接功能及 SO 布局样本和链接处理过程**

`malloc_common.cpp` 本身并不直接负责动态链接，但它利用了动态链接机制来实现调试 malloc 的加载。

**SO 布局样本：**

* **`libc.so` (主库):** 包含 `malloc_common.cpp` 中的代码以及默认的内存分配器实现。它导出了 `malloc`、`free` 等符号。
* **`libc_debug_malloc.so` (调试库):**  这是一个单独的共享库，包含了用于调试目的的内存分配器实现。它也导出了 `malloc`、`free` 等符号，但这些符号的实现与 `libc.so` 中的不同。

**链接处理过程：**

1. **默认情况：** 当应用程序启动时，动态链接器 (e.g., `linker64`) 会加载 `libc.so`。应用程序调用 `malloc` 时，链接器会将调用解析到 `libc.so` 中 `malloc_common.cpp` 定义的 `malloc` 函数。由于此时 `dispatch_table` 通常为空，实际执行的是 Bionic 默认的内存分配器。

2. **启用调试 malloc：**
   * 当系统属性 `"libc.debug.malloc.options"` 被设置为非零值时，动态链接器会加载 `libc_debug_malloc.so`。
   * `libc_debug_malloc.so` 的加载过程通常会在 `libc.so` 初始化阶段完成。
   * `libc_debug_malloc.so` 中会有一个初始化函数，该函数会获取其内部的内存分配函数指针（例如 `malloc`、`free` 的实现），并将这些指针存储到 `dispatch_table` 中。`GetDispatchTable()` 函数会返回指向这个 `dispatch_table` 的指针。

3. **后续的内存分配：**  当应用程序再次调用 `malloc` 时，`GetDispatchTable()` 将返回指向 `libc_debug_malloc.so` 中函数指针的表。因此，调用会转发到调试 malloc 的实现。

**逻辑推理、假设输入与输出**

假设输入：应用程序调用 `malloc(1024)`。

**情况 1：调试 malloc 未启用**

* `GetDispatchTable()` 返回 `nullptr`。
* `Malloc(malloc)(1024)` 被调用，即调用 Bionic 默认的 `malloc` 实现。
* 输出：返回一个指向至少 1024 字节已分配内存的指针。

**情况 2：调试 malloc 已启用**

* `GetDispatchTable()` 返回指向 `libc_debug_malloc.so` 中函数指针表的指针。
* `dispatch_table->malloc(1024)` 被调用，即调用调试 malloc 的 `malloc` 实现。
* 输出：返回一个指向至少 1024 字节已分配内存的指针，并且可能包含调试 malloc 添加的额外信息（例如 guard 区域）。

**用户或编程常见的使用错误**

1. **忘记检查 `malloc` 的返回值：** 如果 `malloc` 分配失败，会返回 `nullptr`。不检查返回值会导致程序崩溃。
   ```c++
   void* ptr = malloc(1024);
   // 忘记检查 ptr 是否为 nullptr
   memcpy(ptr, data, 1024); // 如果 ptr 是 nullptr，这里会崩溃
   ```

2. **重复释放内存 (`double free`)：**  对同一块内存调用 `free` 多次会导致内存损坏。
   ```c++
   void* ptr = malloc(1024);
   free(ptr);
   free(ptr); // 错误！
   ```

3. **释放未分配的内存：** 尝试释放一个并非由 `malloc`、`calloc` 或 `realloc` 分配的指针。
   ```c++
   int data[10];
   free(data); // 错误！
   ```

4. **内存泄漏：**  分配了内存但忘记释放，导致程序占用的内存持续增长。
   ```c++
   void allocate_memory() {
       void* ptr = malloc(1024);
       // ... 使用 ptr ...
       // 忘记 free(ptr);
   }
   ```

5. **使用已释放的内存 (`use-after-free`)：**  在调用 `free` 之后仍然尝试访问该内存。
   ```c++
   void* ptr = malloc(1024);
   free(ptr);
   * (int*)ptr = 10; // 错误！
   ```

**Android Framework 或 NDK 如何到达这里**

以下是一个简化的流程，说明 Android Framework 或 NDK 如何最终调用到 `malloc_common.cpp` 中的内存分配函数：

1. **Android Framework (Java 代码):**  例如，创建一个 `Bitmap` 对象。
   ```java
   Bitmap bitmap = Bitmap.createBitmap(100, 100, Bitmap.Config.ARGB_8888);
   ```

2. **虚拟机 (ART/Dalvik):**  `Bitmap.createBitmap` 的底层实现会涉及到 Native 代码的调用。虚拟机负责管理 Java 对象的内存，但对于 Native 层的内存分配，它需要通过 JNI (Java Native Interface) 与 Native 代码交互。

3. **JNI 调用:** 虚拟机调用 Native 代码，例如 `android_graphics_Bitmap_nativeCreate` 函数。

4. **Native 代码 (C/C++):** `android_graphics_Bitmap_nativeCreate` 函数内部需要分配 Native 内存来存储位图数据。

5. **调用 `malloc`：** Native 代码中会调用 `malloc` 或其他内存分配函数来分配内存。这个 `malloc` 调用会命中 `bionic/libc/bionic/malloc_common.cpp` 中定义的 `malloc` 函数。

6. **内存分配：** `malloc_common.cpp` 根据当前的配置选择合适的内存分配器，并执行实际的内存分配。

**NDK 开发场景：**

1. **NDK C/C++ 代码：** 开发者直接在 Native 代码中使用 `malloc`、`calloc` 等函数。
   ```c++
   #include <stdlib.h>

   void* allocate_native_memory(size_t size) {
       return malloc(size);
   }
   ```
2. **调用 `malloc`：**  这里的 `malloc` 调用同样会命中 `bionic/libc/bionic/malloc_common.cpp` 中定义的函数。

**Frida Hook 示例调试**

以下是一个使用 Frida Hook 拦截 `malloc` 函数的示例：

```javascript
if (Process.platform === 'android') {
  const mallocPtr = Module.findExportByName('libc.so', 'malloc');
  if (mallocPtr) {
    Interceptor.attach(mallocPtr, {
      onEnter: function (args) {
        const size = args[0].toInt();
        console.log(`malloc called with size: ${size}`);
      },
      onLeave: function (retval) {
        console.log(`malloc returned: ${retval}`);
      }
    });
  } else {
    console.error('Could not find malloc in libc.so');
  }
}
```

**解释：**

1. **`if (Process.platform === 'android')`:**  确保只在 Android 平台上运行。
2. **`Module.findExportByName('libc.so', 'malloc')`:**  在 `libc.so` 中查找 `malloc` 函数的地址。
3. **`Interceptor.attach(mallocPtr, { ... })`:**  使用 Frida 的 `Interceptor` 拦截 `malloc` 函数。
4. **`onEnter`:**  在 `malloc` 函数调用之前执行。`args` 数组包含了传递给 `malloc` 的参数（这里是内存大小）。
5. **`onLeave`:** 在 `malloc` 函数返回之后执行。`retval` 包含了 `malloc` 的返回值（分配的内存地址）。

**使用这个 Frida 脚本：**

1. 将脚本保存为 `.js` 文件（例如 `malloc_hook.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <包名> -l malloc_hook.js --no-pause
   ```
   将 `<包名>` 替换为你要调试的应用程序的包名。
3. 当应用程序执行到调用 `malloc` 的代码时，Frida 会拦截调用，并在控制台上打印出 `malloc` 的参数和返回值。

**其他可以 Hook 的点：**

* **`free`:** 观察内存释放的情况。
* **`calloc`、`realloc`、`memalign`:** 观察其他内存分配函数的调用。
* **`GetDispatchTable`:** 查看当前使用的内存分配器（默认或调试 malloc）。
* **`SetHeapTaggingLevel`:**  观察堆标签功能的启用情况。

通过 Frida Hook，你可以动态地观察和分析应用程序的内存分配行为，这对于调试内存相关的错误非常有帮助。

希望这个详细的解释能够帮助你理解 `bionic/libc/bionic/malloc_common.cpp` 的功能和作用。

Prompt: 
```
这是目录为bionic/libc/bionic/malloc_common.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2009 The Android Open Source Project
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

// Contains a thin layer that calls whatever real native allocator
// has been defined. For the libc shared library, this allows the
// implementation of a debug malloc that can intercept all of the allocation
// calls and add special debugging code to attempt to catch allocation
// errors. All of the debugging code is implemented in a separate shared
// library that is only loaded when the property "libc.debug.malloc.options"
// is set to a non-zero value.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <platform/bionic/malloc.h>
#include <private/ScopedPthreadMutexLocker.h>
#include <private/bionic_config.h>

#include "gwp_asan_wrappers.h"
#include "heap_tagging.h"
#include "heap_zero_init.h"
#include "malloc_common.h"
#include "malloc_limit.h"
#include "malloc_tagged_pointers.h"

// =============================================================================
// Global variables instantations.
// =============================================================================

// Malloc hooks globals.
void* (*volatile __malloc_hook)(size_t, const void*);
void* (*volatile __realloc_hook)(void*, size_t, const void*);
void (*volatile __free_hook)(void*, const void*);
void* (*volatile __memalign_hook)(size_t, size_t, const void*);
// =============================================================================

// =============================================================================
// Allocation functions
// =============================================================================
extern "C" void* calloc(size_t n_elements, size_t elem_size) {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return MaybeTagPointer(dispatch_table->calloc(n_elements, elem_size));
  }
  void* result = Malloc(calloc)(n_elements, elem_size);
  if (__predict_false(result == nullptr)) {
    warning_log("calloc(%zu, %zu) failed: returning null pointer", n_elements, elem_size);
  }
  return MaybeTagPointer(result);
}

extern "C" void free(void* mem) {
  auto dispatch_table = GetDispatchTable();
  mem = MaybeUntagAndCheckPointer(mem);
  if (__predict_false(dispatch_table != nullptr)) {
    dispatch_table->free(mem);
  } else {
    Malloc(free)(mem);
  }
}

extern "C" struct mallinfo mallinfo() {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->mallinfo();
  }
  return Malloc(mallinfo)();
}

extern "C" int malloc_info(int options, FILE* fp) {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->malloc_info(options, fp);
  }
  return Malloc(malloc_info)(options, fp);
}

extern "C" int mallopt(int param, int value) {
  // Some are handled by libc directly rather than by the allocator.
  if (param == M_BIONIC_SET_HEAP_TAGGING_LEVEL) {
    ScopedPthreadMutexLocker locker(&g_heap_tagging_lock);
    return SetHeapTaggingLevel(static_cast<HeapTaggingLevel>(value));
  }
  if (param == M_BIONIC_ZERO_INIT) {
    return SetHeapZeroInitialize(value);
  }

  // The rest we pass on...
  int retval;
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    retval = dispatch_table->mallopt(param, value);
  } else {
    retval = Malloc(mallopt)(param, value);
  }

  // Track the M_DECAY_TIME mallopt calls.
  if (param == M_DECAY_TIME && retval == 1) {
    __libc_globals.mutate([value](libc_globals* globals) {
      if (value <= 0) {
        atomic_store(&globals->decay_time_enabled, false);
      } else {
        atomic_store(&globals->decay_time_enabled, true);
      }
    });
  }
  return retval;
}

extern "C" void* malloc(size_t bytes) {
  auto dispatch_table = GetDispatchTable();
  void *result;
  if (__predict_false(dispatch_table != nullptr)) {
    result = dispatch_table->malloc(bytes);
  } else {
    result = Malloc(malloc)(bytes);
  }
  if (__predict_false(result == nullptr)) {
    warning_log("malloc(%zu) failed: returning null pointer", bytes);
    return nullptr;
  }
  return MaybeTagPointer(result);
}

extern "C" size_t malloc_usable_size(const void* mem) {
  auto dispatch_table = GetDispatchTable();
  mem = MaybeUntagAndCheckPointer(mem);
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->malloc_usable_size(mem);
  }
  return Malloc(malloc_usable_size)(mem);
}

extern "C" void* memalign(size_t alignment, size_t bytes) {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return MaybeTagPointer(dispatch_table->memalign(alignment, bytes));
  }
  void* result = Malloc(memalign)(alignment, bytes);
  if (__predict_false(result == nullptr)) {
    warning_log("memalign(%zu, %zu) failed: returning null pointer", alignment, bytes);
  }
  return MaybeTagPointer(result);
}

extern "C" int posix_memalign(void** memptr, size_t alignment, size_t size) {
  auto dispatch_table = GetDispatchTable();
  int result;
  if (__predict_false(dispatch_table != nullptr)) {
    result = dispatch_table->posix_memalign(memptr, alignment, size);
  } else {
    result = Malloc(posix_memalign)(memptr, alignment, size);
  }
  if (result == 0) {
    *memptr = MaybeTagPointer(*memptr);
  }
  return result;
}

extern "C" void* aligned_alloc(size_t alignment, size_t size) {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return MaybeTagPointer(dispatch_table->aligned_alloc(alignment, size));
  }
  void* result = Malloc(aligned_alloc)(alignment, size);
  if (__predict_false(result == nullptr)) {
    warning_log("aligned_alloc(%zu, %zu) failed: returning null pointer", alignment, size);
  }
  return MaybeTagPointer(result);
}

extern "C" __attribute__((__noinline__)) void* realloc(void* old_mem, size_t bytes) {
  auto dispatch_table = GetDispatchTable();
  old_mem = MaybeUntagAndCheckPointer(old_mem);
  if (__predict_false(dispatch_table != nullptr)) {
    return MaybeTagPointer(dispatch_table->realloc(old_mem, bytes));
  }
  void* result = Malloc(realloc)(old_mem, bytes);
  if (__predict_false(result == nullptr && bytes != 0)) {
    warning_log("realloc(%p, %zu) failed: returning null pointer", old_mem, bytes);
  }
  return MaybeTagPointer(result);
}

extern "C" void* reallocarray(void* old_mem, size_t item_count, size_t item_size) {
  size_t new_size;
  if (__builtin_mul_overflow(item_count, item_size, &new_size)) {
    warning_log("reallocaray(%p, %zu, %zu) failed: returning null pointer",
                old_mem, item_count, item_size);
    errno = ENOMEM;
    return nullptr;
  }
  return realloc(old_mem, new_size);
}

#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
extern "C" void* pvalloc(size_t bytes) {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return MaybeTagPointer(dispatch_table->pvalloc(bytes));
  }
  void* result = Malloc(pvalloc)(bytes);
  if (__predict_false(result == nullptr)) {
    warning_log("pvalloc(%zu) failed: returning null pointer", bytes);
  }
  return MaybeTagPointer(result);
}

extern "C" void* valloc(size_t bytes) {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return MaybeTagPointer(dispatch_table->valloc(bytes));
  }
  void* result = Malloc(valloc)(bytes);
  if (__predict_false(result == nullptr)) {
    warning_log("valloc(%zu) failed: returning null pointer", bytes);
  }
  return MaybeTagPointer(result);
}
#endif
// =============================================================================

struct CallbackWrapperArg {
  void (*callback)(uintptr_t base, size_t size, void* arg);
  void* arg;
};

void CallbackWrapper(uintptr_t base, size_t size, void* arg) {
  CallbackWrapperArg* wrapper_arg = reinterpret_cast<CallbackWrapperArg*>(arg);
  wrapper_arg->callback(
    reinterpret_cast<uintptr_t>(MaybeTagPointer(reinterpret_cast<void*>(base))),
    size, wrapper_arg->arg);
}

// =============================================================================
// Exported for use by libmemunreachable.
// =============================================================================

// Calls callback for every allocation in the anonymous heap mapping
// [base, base+size). Must be called between malloc_disable and malloc_enable.
// `base` in this can take either a tagged or untagged pointer, but we always
// provide a tagged pointer to the `base` argument of `callback` if the kernel
// supports tagged pointers.
extern "C" int malloc_iterate(uintptr_t base, size_t size,
    void (*callback)(uintptr_t base, size_t size, void* arg), void* arg) {
  auto dispatch_table = GetDispatchTable();
  // Wrap the malloc_iterate callback we were provided, in order to provide
  // pointer tagging support.
  CallbackWrapperArg wrapper_arg;
  wrapper_arg.callback = callback;
  wrapper_arg.arg = arg;
  uintptr_t untagged_base =
      reinterpret_cast<uintptr_t>(UntagPointer(reinterpret_cast<void*>(base)));
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->malloc_iterate(
      untagged_base, size, CallbackWrapper, &wrapper_arg);
  }
  return Malloc(malloc_iterate)(
    untagged_base, size, CallbackWrapper, &wrapper_arg);
}

// Disable calls to malloc so malloc_iterate gets a consistent view of
// allocated memory.
extern "C" void malloc_disable() {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->malloc_disable();
  }
  return Malloc(malloc_disable)();
}

// Re-enable calls to malloc after a previous call to malloc_disable.
extern "C" void malloc_enable() {
  auto dispatch_table = GetDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->malloc_enable();
  }
  return Malloc(malloc_enable)();
}

#if defined(LIBC_STATIC)
extern "C" ssize_t malloc_backtrace(void*, uintptr_t*, size_t) {
  return 0;
}
#endif

#if __has_feature(hwaddress_sanitizer)
// FIXME: implement these in HWASan allocator.
extern "C" int __sanitizer_malloc_iterate(uintptr_t base __unused, size_t size __unused,
                                          void (*callback)(uintptr_t base, size_t size, void* arg)
                                              __unused,
                                          void* arg __unused) {
  return 0;
}

extern "C" void __sanitizer_malloc_disable() {
}

extern "C" void __sanitizer_malloc_enable() {
}

extern "C" int __sanitizer_malloc_info(int, FILE*) {
  errno = ENOTSUP;
  return -1;
}
#endif
// =============================================================================

static constexpr MallocDispatch __libc_malloc_default_dispatch __attribute__((unused)) = {
  Malloc(calloc),
  Malloc(free),
  Malloc(mallinfo),
  Malloc(malloc),
  Malloc(malloc_usable_size),
  Malloc(memalign),
  Malloc(posix_memalign),
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  Malloc(pvalloc),
#endif
  Malloc(realloc),
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  Malloc(valloc),
#endif
  Malloc(malloc_iterate),
  Malloc(malloc_disable),
  Malloc(malloc_enable),
  Malloc(mallopt),
  Malloc(aligned_alloc),
  Malloc(malloc_info),
};

const MallocDispatch* NativeAllocatorDispatch() {
  return &__libc_malloc_default_dispatch;
}

"""

```