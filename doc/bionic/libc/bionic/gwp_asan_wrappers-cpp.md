Response:
Let's break down the thought process to analyze the `gwp_asan_wrappers.cpp` file.

1. **Understand the Context:** The initial prompt clearly states that this file is part of `bionic`, Android's C library, specifically for `gwp_asan`. GWP-ASan likely stands for "Guard Page With Address Sanitizer," a memory safety feature. Knowing this context is crucial.

2. **Identify the Core Functionality:**  The filename itself (`gwp_asan_wrappers.cpp`) strongly suggests that this file provides *wrappers* around existing memory allocation functions. Scanning the code confirms this: we see functions like `gwp_asan_malloc`, `gwp_asan_free`, `gwp_asan_calloc`, etc. These shadow standard `libc` allocation functions.

3. **Analyze the Wrappers:**  For each wrapped function, observe the common pattern:
    * A check (`__predict_false(GuardedAlloc.shouldSample())` or `GuardedAlloc.pointerIsMine(mem)`).
    * If the condition is met, call a method on `GuardedAlloc` (e.g., `GuardedAlloc.allocate`, `GuardedAlloc.deallocate`).
    * Otherwise, call the corresponding function from `prev_dispatch`.

4. **Infer the Role of `GuardedAlloc`:** Based on the wrapper logic, `GuardedAlloc` is the central component of GWP-ASan. It seems to manage a special pool of memory and handle allocations that are being "sampled" for memory safety checks.

5. **Infer the Role of `prev_dispatch`:**  The code explicitly initializes `prev_dispatch` with `NativeAllocatorDispatch()`. This strongly suggests that GWP-ASan is hooking into the standard memory allocation mechanism. `prev_dispatch` holds the original (or previous) allocation functions.

6. **Examine the `MallocDispatch` Structure:** The `gwp_asan_dispatch` structure is a key piece. It's an array of function pointers that mirrors the standard `MallocDispatch` structure. This is the mechanism by which GWP-ASan intercepts memory allocation calls. Note the use of the `Malloc()` macro, which seems to pull in the original `libc` implementations for functions GWP-ASan doesn't directly handle.

7. **Analyze the Initialization Logic:** The code has functions like `MaybeInitGwpAsan` and `EnableGwpAsan`. Look for how GWP-ASan is configured:
    * System properties (`libc.debug.gwp_asan.*`).
    * Environment variables (`GWP_ASAN_*`).
    * Program name targeting.
    * Sampling rates and maximum allocation limits.
    * The `android_mallopt_gwp_asan_options_t` structure.

8. **Identify Key Concepts:** Based on the code analysis, the core concepts of GWP-ASan emerge:
    * **Sampling:**  Only a fraction of allocations are managed by GWP-ASan.
    * **Guard Pages:**  (Implicit) The name suggests that GWP-ASan uses guard pages to detect memory errors. While not explicitly implemented in *this* file, the `GuardedPoolAllocator` class likely handles this.
    * **Crash Handling:**  The `GwpAsanPreCrashHandler` and `GwpAsanPostCrashHandler` functions indicate integration with Android's crash reporting mechanism.
    * **Recoverability:** The `Recoverable` option suggests that in some cases, GWP-ASan can prevent immediate crashes.

9. **Connect to Android Functionality:**
    * **Memory Safety:** GWP-ASan is a memory safety feature directly relevant to Android's stability and security.
    * **System Properties and Environment Variables:**  Android's configuration mechanisms are used to control GWP-ASan's behavior.
    * **Crash Reporting:** Integration with `debuggerd` is crucial for reporting memory errors.
    * **Zygote:** The special handling of the Zygote process shows awareness of Android's process model.

10. **Detailed Explanation of `libc` Functions:** For each wrapped `libc` function (`calloc`, `free`, `malloc`, etc.), explain its standard behavior and how GWP-ASan's wrapper modifies it. Emphasize the conditions under which GWP-ASan takes control.

11. **Dynamic Linker Aspects:**  Although this file doesn't directly implement the dynamic linker, it *interfaces* with it. The `MallocDispatch` mechanism is how `libc`'s memory allocation is controlled. Explain how GWP-ASan inserts its own dispatch table. A sample SO layout showing the `MallocDispatch` table in the `.data` section of `libc.so` is helpful. Explain the linking process at a high level: when a program calls `malloc`, the dynamic linker resolves it to the appropriate function in `libc.so`, which now points to the GWP-ASan wrapper if enabled.

12. **Logic and Assumptions:** When explaining the sampling logic, explicitly state the assumptions (e.g., the use of `arc4random_buf` for randomness).

13. **Common Errors:** Think about how developers might misuse memory and how GWP-ASan helps catch those errors (e.g., use-after-free, heap overflows).

14. **Android Framework/NDK Interaction:** Trace the path from a framework/NDK allocation down to the GWP-ASan wrappers. Focus on the `malloc` family of functions.

15. **Frida Hooking:** Provide practical examples of how to use Frida to intercept the GWP-ASan wrapper functions and the underlying `GuardedAlloc` methods.

16. **Structure and Language:** Organize the information logically using clear headings and bullet points. Use precise and accurate language, avoiding jargon where possible or explaining it clearly. Respond in Chinese as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this about *implementing* ASan?"  **Correction:**  No, it's about a *specific* implementation of a guard page mechanism within `bionic`, named GWP-ASan, and how it wraps existing allocators.
* **Initial thought:** "Focus only on the wrappers." **Correction:**  Need to understand the bigger picture: how GWP-ASan is initialized, configured, and integrated into the Android system.
* **Initial thought:** "Go deep into the `GuardedPoolAllocator` implementation." **Correction:**  The prompt asks about *this* file. Mention `GuardedPoolAllocator` as the core component but don't delve into its internal details (unless explicitly asked). Focus on how the wrappers interact with it.
* **Ensuring clarity for each `libc` function:**  Don't just say "it wraps `malloc`". Explain the conditions under which GWP-ASan is involved versus the default allocator.
* **Dynamic linking explanation:** Realized that just mentioning `MallocDispatch` isn't enough. Need to explain *how* the dynamic linker plays a role in directing calls to GWP-ASan.
* **Frida examples:** Made sure the examples were practical and targeted the relevant functions.
好的，让我们来详细分析一下 `bionic/libc/bionic/gwp_asan_wrappers.cpp` 这个文件。

**文件功能概述**

这个文件实现了 GWP-ASan (Guard Pages With Address Sanitizer) 的内存分配器包装器 (wrappers)。GWP-ASan 是一种轻量级的内存错误检测机制，它通过随机选择一些内存分配并将其放置在特殊的受保护的内存池中来工作。这样，当发生堆溢出、使用已释放内存等错误时，更容易被检测到。

**与 Android 功能的关系及举例**

GWP-ASan 是 Android 系统为了提高内存安全性和稳定性而引入的一项技术。它属于 Android Bionic 库的一部分，因此直接影响着所有使用 Bionic 库的 Android 进程，包括 Android Framework、应用程序以及 Native 代码。

**举例说明：**

1. **应用程序崩溃检测:**  如果一个应用程序存在堆溢出漏洞，传统的内存分配器可能不会立即导致程序崩溃，因为溢出的内存可能恰好没有被其他重要数据占用。但是，如果溢出的内存恰好是 GWP-ASan 保护的内存，那么溢出操作会立即触发一个错误，导致程序崩溃，并生成相应的错误报告，帮助开发者快速定位问题。

2. **Framework 稳定性:** Android Framework 的各个组件也是用 C/C++ 编写的，同样面临内存安全问题。GWP-ASan 可以帮助检测 Framework 组件中的内存错误，提高系统的整体稳定性。例如，一个 System Server 进程中的内存错误可能会导致整个系统不稳定甚至重启。

3. **NDK 开发:** 使用 NDK 进行 Native 开发的开发者也会受益于 GWP-ASan。在开发和测试阶段启用 GWP-ASan 可以帮助他们及早发现代码中的内存错误，减少发布后的潜在风险。

**libc 函数的实现细节**

这个文件中的函数是对标准 `libc` 内存分配函数的包装，其核心逻辑是决定是否将当前的内存分配请求交给 GWP-ASan 管理。

* **`gwp_asan_calloc(size_t n_elements, size_t elem_size)`:**
    * **功能:**  分配一块大小为 `n_elements * elem_size` 的内存，并将所有字节初始化为零。
    * **实现:**
        1. 使用 `__predict_false(GuardedAlloc.shouldSample())` 判断当前分配是否应该被 GWP-ASan 采样 (处理)。`GuardedAlloc.shouldSample()` 内部会根据配置的采样率来决定是否返回 true。
        2. 如果返回 true，计算需要的总字节数，并尝试使用 `GuardedAlloc.allocate(bytes)` 从 GWP-ASan 的保护池中分配内存。
        3. 如果 `GuardedAlloc.allocate` 分配成功，则返回分配的内存。
        4. 如果 `GuardedAlloc.shouldSample()` 返回 false，或者 `GuardedAlloc.allocate` 分配失败，则调用原始的 `libc` 的 `calloc` 函数 (`prev_dispatch->calloc(n_elements, elem_size)`) 来分配内存。

* **`gwp_asan_free(void* mem)`:**
    * **功能:**  释放之前分配的内存块。
    * **实现:**
        1. 使用 `__predict_false(GuardedAlloc.pointerIsMine(mem))` 判断要释放的内存是否由 GWP-ASan 管理。`GuardedAlloc.pointerIsMine(mem)` 检查给定的指针是否指向 GWP-ASan 池中的内存。
        2. 如果返回 true，则调用 `GuardedAlloc.deallocate(mem)` 使用 GWP-ASan 的释放逻辑来释放内存。
        3. 如果返回 false，则调用原始的 `libc` 的 `free` 函数 (`prev_dispatch->free(mem)`) 来释放内存。

* **`gwp_asan_malloc(size_t bytes)`:**
    * **功能:** 分配一块指定大小的内存块。
    * **实现:** 逻辑与 `gwp_asan_calloc` 类似，只是不进行内存初始化。

* **`gwp_asan_malloc_usable_size(const void* mem)`:**
    * **功能:** 返回给定指针指向的内存块的实际可用大小。
    * **实现:**
        1. 使用 `__predict_false(GuardedAlloc.pointerIsMine(mem))` 判断内存是否由 GWP-ASan 管理。
        2. 如果是，则调用 `GuardedAlloc.getSize(mem)` 获取 GWP-ASan 管理的内存块大小。
        3. 否则，调用原始的 `libc` 的 `malloc_usable_size`。

* **`gwp_asan_realloc(void* old_mem, size_t bytes)`:**
    * **功能:**  重新分配之前分配的内存块，可以扩大或缩小内存块的大小。
    * **实现:**
        1. 使用 `__predict_false(GuardedAlloc.pointerIsMine(old_mem))` 判断要重新分配的内存是否由 GWP-ASan 管理。
        2. 如果是：
            * 如果 `bytes` 为 0，则相当于 `free(old_mem)`，调用 `GuardedAlloc.deallocate(old_mem)`。
            * 否则，先使用 `gwp_asan_malloc(bytes)` 分配一块新的内存。
            * 如果分配成功，将旧内存中的内容拷贝到新内存中（拷贝大小取两者较小值）。
            * 然后释放旧的内存块 `GuardedAlloc.deallocate(old_mem)`。
            * 返回新分配的内存指针。
        3. 如果旧内存不是由 GWP-ASan 管理，则调用原始的 `libc` 的 `realloc` 函数。

* **`gwp_asan_malloc_iterate(...)`:**
    * **功能:**  遍历指定范围内的内存块，并对每个块执行回调函数。
    * **实现:**  如果指定的基址是由 GWP-ASan 管理的，则调用 `GuardedAlloc.iterate()` 来遍历 GWP-ASan 管理的内存。否则，调用原始的 `libc` 的 `malloc_iterate`。

* **`gwp_asan_malloc_disable()` 和 `gwp_asan_malloc_enable()`:**
    * **功能:**  禁用和启用 GWP-ASan。
    * **实现:** 分别调用 `GuardedAlloc.disable()` 和 `GuardedAlloc.enable()` 来控制 GWP-ASan 的状态，并同时调用原始 `libc` 对应的方法。

**涉及 dynamic linker 的功能**

GWP-ASan 通过替换 `libc` 的默认内存分配器来实现其功能。这涉及到动态链接的过程。

1. **`MallocDispatch` 结构体:**  `gwp_asan_dispatch` 是一个 `MallocDispatch` 类型的结构体，它包含了一组函数指针，指向 GWP-ASan 提供的内存分配函数。

   ```c++
   const MallocDispatch gwp_asan_dispatch __attribute__((unused)) = {
       gwp_asan_calloc,
       gwp_asan_free,
       Malloc(mallinfo),
       gwp_asan_malloc,
       gwp_asan_malloc_usable_size,
       Malloc(memalign),
       Malloc(posix_memalign),
   #if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
       Malloc(pvalloc),
   #endif
       gwp_asan_realloc,
   #if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
       Malloc(valloc),
   #endif
       gwp_asan_malloc_iterate,
       gwp_asan_malloc_disable,
       gwp_asan_malloc_enable,
       Malloc(mallopt),
       Malloc(aligned_alloc),
       Malloc(malloc_info),
   };
   ```

   注意 `Malloc()` 宏，它实际上会获取原始 `libc` 中对应函数的地址。这意味着 GWP-ASan 只包装了它需要监控的函数，其他的函数仍然使用 `libc` 的实现。

2. **SO 布局样本:**

   当 GWP-ASan 被启用时，`libc.so` 的内部数据结构会被修改。一个简化的 `libc.so` 布局可能如下所示（关注与内存分配相关的部分）：

   ```
   .text:00000000B7001000 T calloc         ; Original libc calloc implementation
   .text:00000000B7002000 T free           ; Original libc free implementation
   .data:00000000B7E00000 D __libc_globals  ; Global variables for libc
   .data:00000000B7E00100 D default_dispatch_table ; Pointer to default MallocDispatch
   .data:00000000B7E00108 D current_dispatch_table ; Pointer to current MallocDispatch
   ```

3. **链接的处理过程:**

   * 在程序启动时，动态链接器 (`linker`) 会加载所有依赖的共享库，包括 `libc.so`。
   * `libc` 在初始化时 (通常通过 `libc_init`)，会判断是否需要启用 GWP-ASan (通过系统属性或环境变量等配置)。
   * 如果启用了 GWP-ASan，`libc` 会将 `__libc_globals.current_dispatch_table` 指向 `gwp_asan_dispatch` 结构体。
   * 当应用程序或 Framework 代码调用 `malloc`, `free`, `calloc` 等内存分配函数时，这些调用实际上会通过 `__libc_globals.current_dispatch_table` 中对应的函数指针跳转到 GWP-ASan 提供的包装函数。
   * 如果 GWP-ASan 决定不处理当前的分配，它会调用 `prev_dispatch` 中保存的原始 `libc` 函数的地址。

**逻辑推理：假设输入与输出**

**假设输入:**

* 应用程序分配 100 字节的内存：`malloc(100)`
* GWP-ASan 的采样率被设置为 1/10 (意味着大约 10% 的分配会被 GWP-ASan 处理)。

**输出的可能性 1 (GWP-ASan 采样到):**

1. `gwp_asan_malloc(100)` 被调用。
2. `GuardedAlloc.shouldSample()` 返回 `true` (根据采样率)。
3. `GuardedAlloc.allocate(100)` 被调用，从 GWP-ASan 的保护池中分配内存。
4. 返回指向 GWP-ASan 管理的内存的指针。

**输出的可能性 2 (GWP-ASan 未采样到):**

1. `gwp_asan_malloc(100)` 被调用。
2. `GuardedAlloc.shouldSample()` 返回 `false`.
3. `prev_dispatch->malloc(100)` 被调用，实际调用的是原始 `libc` 的 `malloc`。
4. 返回指向 `libc` 标准堆的内存的指针。

**用户或编程常见的使用错误及举例**

1. **堆溢出 (Heap buffer overflow):**
   * **错误代码:**
     ```c++
     char* buffer = (char*)malloc(10);
     strcpy(buffer, "This is a string longer than 10 bytes"); // 堆溢出
     ```
   * **GWP-ASan 的作用:** 如果 `buffer` 指向的内存是由 GWP-ASan 管理的，`strcpy` 导致的溢出会触碰到 GWP-ASan 设置的保护页，立即导致程序崩溃。

2. **使用已释放的内存 (Use-after-free):**
   * **错误代码:**
     ```c++
     int* ptr = (int*)malloc(sizeof(int));
     *ptr = 10;
     free(ptr);
     *ptr = 20; // 使用已释放的内存
     ```
   * **GWP-ASan 的作用:** 如果 `ptr` 指向的内存是由 GWP-ASan 管理的，`free(ptr)` 后，GWP-ASan 可能会将该内存区域标记为不可访问。后续的 `*ptr = 20` 操作会触发错误。

3. **重复释放内存 (Double free):**
   * **错误代码:**
     ```c++
     int* ptr = (int*)malloc(sizeof(int));
     free(ptr);
     free(ptr); // 重复释放
     ```
   * **GWP-ASan 的作用:**  GWP-ASan 可以检测到重复释放同一块内存，并报告错误。

**Android Framework 或 NDK 如何到达这里**

1. **Framework 或 NDK 代码调用 `malloc`, `free`, `calloc` 等函数。** 例如，在 Java 层创建一个 Bitmap 对象，底层可能会调用 Native 代码分配内存。
2. **这些调用会被动态链接器解析到 `libc.so` 中。**
3. **如果 GWP-ASan 已启用，`libc` 的 `current_dispatch_table` 指向 `gwp_asan_dispatch`。**
4. **因此，实际执行的是 `gwp_asan_calloc`, `gwp_asan_free`, `gwp_asan_malloc` 等包装函数。**
5. **在这些包装函数内部，会根据采样率等条件判断是否将内存分配交给 `GuardedAlloc` 处理。**
6. **如果交给 `GuardedAlloc`，则从 GWP-ASan 的保护池中分配内存。否则，调用原始的 `libc` 分配器。**

**Frida Hook 示例调试步骤**

可以使用 Frida 来 Hook 这些 GWP-ASan 的包装函数，观察其行为和参数。

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你要调试的应用程序的包名

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
Interceptor.attach(Module.findExportByName("libc.so", "gwp_asan_malloc"), {
    onEnter: function(args) {
        var size = args[0].toInt();
        send(`gwp_asan_malloc called with size: ${size}`);
    },
    onLeave: function(retval) {
        send(`gwp_asan_malloc returned: ${retval}`);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "gwp_asan_free"), {
    onEnter: function(args) {
        var ptr = args[0];
        send(`gwp_asan_free called with pointer: ${ptr}`);
    }
});

// 可以添加其他 GWP-ASan 函数的 Hook，例如 gwp_asan_calloc, gwp_asan_realloc 等
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida 和 USB 驱动。**
2. **将你的 Android 设备连接到电脑，并确保 adb 可用。**
3. **将 `package_name` 替换为你要调试的应用程序的包名。**
4. **运行上面的 Python 脚本。**
5. **在你的 Android 设备上操作该应用程序，触发内存分配和释放操作。**
6. **Frida 会打印出 `gwp_asan_malloc` 和 `gwp_asan_free` 函数的调用信息，包括分配的大小和指针地址。**

**进一步的 Hook:**

你可以进一步 Hook `GuardedAlloc` 类的方法，例如 `shouldSample`, `allocate`, `deallocate`, `pointerIsMine` 等，来更深入地了解 GWP-ASan 的内部工作原理。你需要找到 `libgwp_asan.so` 库并找到这些方法的地址。

例如，要 Hook `GuardedAlloc::shouldSample()`:

1. 使用 `frida-ps -U` 找到目标进程的 PID。
2. 使用 `frida -U -n <进程名> --aux-only` 找到 `libgwp_asan.so` 的加载地址。
3. 使用 `readelf -s <libgwp_asan.so>` 或类似工具找到 `GuardedAlloc::shouldSample()` 的符号地址。
4. 在 Frida 脚本中使用 `Module.findBaseAddress("libgwp_asan.so").add(<偏移地址>)` 计算出 `shouldSample` 函数的实际地址，并进行 Hook。

**总结**

`bionic/libc/bionic/gwp_asan_wrappers.cpp` 文件是 Android GWP-ASan 功能的核心组成部分，它通过包装标准的 `libc` 内存分配函数，实现了对部分内存分配的监控和保护，从而帮助开发者检测和预防内存安全问题，提高了 Android 系统的稳定性和安全性。通过 Frida 等工具，我们可以方便地调试和分析 GWP-ASan 的行为。

### 提示词
```
这是目录为bionic/libc/bionic/gwp_asan_wrappers.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <alloca.h>
#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "gwp_asan/crash_handler.h"
#include "gwp_asan/guarded_pool_allocator.h"
#include "gwp_asan/options.h"
#include "gwp_asan_wrappers.h"
#include "malloc_common.h"
#include "platform/bionic/android_unsafe_frame_pointer_chase.h"
#include "platform/bionic/macros.h"
#include "platform/bionic/malloc.h"
#include "private/bionic_arc4random.h"
#include "private/bionic_globals.h"
#include "private/bionic_malloc_dispatch.h"
#include "sys/system_properties.h"
#include "sysprop_helpers.h"

#ifndef LIBC_STATIC
#include "bionic/malloc_common_dynamic.h"
#endif  // LIBC_STATIC

static gwp_asan::GuardedPoolAllocator GuardedAlloc;
static const MallocDispatch* prev_dispatch;

using Mode = android_mallopt_gwp_asan_options_t::Mode;
using Options = gwp_asan::options::Options;

// basename() is a mess, see the manpage. Let's be explicit what handling we
// want (don't touch my string!).
extern "C" const char* __gnu_basename(const char* path);

namespace {

// ============================================================================
// Implementation of GWP-ASan malloc wrappers.
// ============================================================================

void* gwp_asan_calloc(size_t n_elements, size_t elem_size) {
  if (__predict_false(GuardedAlloc.shouldSample())) {
    size_t bytes;
    if (!__builtin_mul_overflow(n_elements, elem_size, &bytes)) {
      if (void* result = GuardedAlloc.allocate(bytes)) {
        return result;
      }
    }
  }
  return prev_dispatch->calloc(n_elements, elem_size);
}

void gwp_asan_free(void* mem) {
  if (__predict_false(GuardedAlloc.pointerIsMine(mem))) {
    GuardedAlloc.deallocate(mem);
    return;
  }
  prev_dispatch->free(mem);
}

void* gwp_asan_malloc(size_t bytes) {
  if (__predict_false(GuardedAlloc.shouldSample())) {
    if (void* result = GuardedAlloc.allocate(bytes)) {
      return result;
    }
  }
  return prev_dispatch->malloc(bytes);
}

size_t gwp_asan_malloc_usable_size(const void* mem) {
  if (__predict_false(GuardedAlloc.pointerIsMine(mem))) {
    return GuardedAlloc.getSize(mem);
  }
  return prev_dispatch->malloc_usable_size(mem);
}

void* gwp_asan_realloc(void* old_mem, size_t bytes) {
  // GPA::pointerIsMine(p) always returns false where `p == nullptr` (and thus
  // malloc(bytes) is requested). We always fall back to the backing allocator,
  // technically missing some coverage, but reducing an extra conditional
  // branch.
  if (__predict_false(GuardedAlloc.pointerIsMine(old_mem))) {
    if (__predict_false(bytes == 0)) {
      GuardedAlloc.deallocate(old_mem);
      return nullptr;
    }
    void* new_ptr = gwp_asan_malloc(bytes);
    // If malloc() fails, then don't destroy the old memory.
    if (__predict_false(new_ptr == nullptr)) return nullptr;

    size_t old_size = GuardedAlloc.getSize(old_mem);
    memcpy(new_ptr, old_mem, (bytes < old_size) ? bytes : old_size);
    GuardedAlloc.deallocate(old_mem);
    return new_ptr;
  }
  return prev_dispatch->realloc(old_mem, bytes);
}

int gwp_asan_malloc_iterate(uintptr_t base, size_t size,
                            void (*callback)(uintptr_t base, size_t size, void* arg), void* arg) {
  if (__predict_false(GuardedAlloc.pointerIsMine(reinterpret_cast<void*>(base)))) {
    // TODO(mitchp): GPA::iterate() returns void, but should return int.
    // TODO(mitchp): GPA::iterate() should take uintptr_t, not void*.
    GuardedAlloc.iterate(reinterpret_cast<void*>(base), size, callback, arg);
    return 0;
  }
  return prev_dispatch->malloc_iterate(base, size, callback, arg);
}

void gwp_asan_malloc_disable() {
  GuardedAlloc.disable();
  prev_dispatch->malloc_disable();
}

void gwp_asan_malloc_enable() {
  GuardedAlloc.enable();
  prev_dispatch->malloc_enable();
}

const MallocDispatch gwp_asan_dispatch __attribute__((unused)) = {
    gwp_asan_calloc,
    gwp_asan_free,
    Malloc(mallinfo),
    gwp_asan_malloc,
    gwp_asan_malloc_usable_size,
    Malloc(memalign),
    Malloc(posix_memalign),
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
    Malloc(pvalloc),
#endif
    gwp_asan_realloc,
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
    Malloc(valloc),
#endif
    gwp_asan_malloc_iterate,
    gwp_asan_malloc_disable,
    gwp_asan_malloc_enable,
    Malloc(mallopt),
    Malloc(aligned_alloc),
    Malloc(malloc_info),
};

bool isPowerOfTwo(uint64_t x) {
  assert(x != 0);
  return (x & (x - 1)) == 0;
}

bool ShouldGwpAsanSampleProcess(unsigned sample_rate) {
  if (!isPowerOfTwo(sample_rate)) {
    warning_log(
        "GWP-ASan process sampling rate of %u is not a power-of-two, and so modulo bias occurs.",
        sample_rate);
  }

  uint8_t random_number;
  __libc_safe_arc4random_buf(&random_number, sizeof(random_number));
  return random_number % sample_rate == 0;
}

bool GwpAsanInitialized = false;
bool GwpAsanRecoverable = false;

// The probability (1 / SampleRate) that an allocation gets chosen to be put
// into the special GWP-ASan pool.
using SampleRate_t = typeof(gwp_asan::options::Options::SampleRate);
constexpr SampleRate_t kDefaultSampleRate = 2500;
static const char* kSampleRateSystemSysprop = "libc.debug.gwp_asan.sample_rate.system_default";
static const char* kSampleRateAppSysprop = "libc.debug.gwp_asan.sample_rate.app_default";
static const char* kSampleRateTargetedSyspropPrefix = "libc.debug.gwp_asan.sample_rate.";
static const char* kSampleRateEnvVar = "GWP_ASAN_SAMPLE_RATE";

// The probability (1 / ProcessSampling) that a process will be randomly
// selected for sampling, for system apps and system processes. The process
// sampling rate should always be a power of two to avoid modulo bias.
constexpr unsigned kDefaultProcessSampling = 128;
static const char* kProcessSamplingSystemSysprop =
    "libc.debug.gwp_asan.process_sampling.system_default";
static const char* kProcessSamplingAppSysprop = "libc.debug.gwp_asan.process_sampling.app_default";
static const char* kProcessSamplingTargetedSyspropPrefix = "libc.debug.gwp_asan.process_sampling.";
static const char* kProcessSamplingEnvVar = "GWP_ASAN_PROCESS_SAMPLING";

// The upper limit of simultaneous allocations supported by GWP-ASan. Any
// allocations in excess of this limit will be passed to the backing allocator
// and can't be sampled. This value, if unspecified, will be automatically
// calculated to keep the same ratio as the default (2500 sampling : 32 allocs).
// So, if you specify GWP_ASAN_SAMPLE_RATE=1250 (i.e. twice as frequent), we'll
// automatically calculate that we need double the slots (64).
using SimultaneousAllocations_t = typeof(gwp_asan::options::Options::MaxSimultaneousAllocations);
constexpr SimultaneousAllocations_t kDefaultMaxAllocs = 32;
static const char* kMaxAllocsSystemSysprop = "libc.debug.gwp_asan.max_allocs.system_default";
static const char* kMaxAllocsAppSysprop = "libc.debug.gwp_asan.max_allocs.app_default";
static const char* kMaxAllocsTargetedSyspropPrefix = "libc.debug.gwp_asan.max_allocs.";
static const char* kMaxAllocsEnvVar = "GWP_ASAN_MAX_ALLOCS";

static const char* kRecoverableSystemSysprop = "libc.debug.gwp_asan.recoverable.system_default";
static const char* kRecoverableAppSysprop = "libc.debug.gwp_asan.recoverable.app_default";
static const char* kRecoverableTargetedSyspropPrefix = "libc.debug.gwp_asan.recoverable.";
static const char* kRecoverableEnvVar = "GWP_ASAN_RECOVERABLE";

static const char kPersistPrefix[] = "persist.";

bool NeedsGwpAsanRecovery(void* fault_ptr) {
  fault_ptr = untag_address(fault_ptr);
  return GwpAsanInitialized && GwpAsanRecoverable &&
         __gwp_asan_error_is_mine(GuardedAlloc.getAllocatorState(),
                                  reinterpret_cast<uintptr_t>(fault_ptr));
}

void GwpAsanPreCrashHandler(void* fault_ptr) {
  fault_ptr = untag_address(fault_ptr);
  if (!NeedsGwpAsanRecovery(fault_ptr)) return;
  GuardedAlloc.preCrashReport(fault_ptr);
}

void GwpAsanPostCrashHandler(void* fault_ptr) {
  fault_ptr = untag_address(fault_ptr);
  if (!NeedsGwpAsanRecovery(fault_ptr)) return;
  GuardedAlloc.postCrashReportRecoverableOnly(fault_ptr);
}

void SetDefaultGwpAsanOptions(Options* options, unsigned* process_sample_rate,
                              const android_mallopt_gwp_asan_options_t& mallopt_options) {
  options->Enabled = true;
  options->InstallSignalHandlers = false;
  options->InstallForkHandlers = true;
  options->Backtrace = android_unsafe_frame_pointer_chase;
  options->SampleRate = kDefaultSampleRate;
  options->MaxSimultaneousAllocations = kDefaultMaxAllocs;
  options->Recoverable = true;
  GwpAsanRecoverable = true;

  if (mallopt_options.mode == Mode::SYSTEM_PROCESS_OR_SYSTEM_APP ||
      mallopt_options.mode == Mode::APP_MANIFEST_DEFAULT) {
    *process_sample_rate = kDefaultProcessSampling;
  } else {
    *process_sample_rate = 1;
  }
}

bool GetGwpAsanOptionImpl(char* value_out,
                          const android_mallopt_gwp_asan_options_t& mallopt_options,
                          const char* system_sysprop, const char* app_sysprop,
                          const char* targeted_sysprop_prefix, const char* env_var) {
  const char* basename = "";
  if (mallopt_options.program_name) basename = __gnu_basename(mallopt_options.program_name);

  constexpr size_t kSyspropMaxLen = 512;
  char program_specific_sysprop[kSyspropMaxLen] = {};
  char persist_program_specific_sysprop[kSyspropMaxLen] = {};
  char persist_default_sysprop[kSyspropMaxLen] = {};
  const char* sysprop_names[4] = {};
  // Tests use a blank program name to specify that system properties should not
  // be used. Tests still continue to use the environment variable though.
  if (*basename != '\0') {
    const char* default_sysprop = system_sysprop;
    if (mallopt_options.mode == Mode::APP_MANIFEST_ALWAYS) {
      default_sysprop = app_sysprop;
    }
    async_safe_format_buffer(&program_specific_sysprop[0], kSyspropMaxLen, "%s%s",
                             targeted_sysprop_prefix, basename);
    async_safe_format_buffer(&persist_program_specific_sysprop[0], kSyspropMaxLen, "%s%s",
                             kPersistPrefix, program_specific_sysprop);
    async_safe_format_buffer(&persist_default_sysprop[0], kSyspropMaxLen, "%s%s", kPersistPrefix,
                             default_sysprop);

    // In order of precedence, always take the program-specific sysprop (e.g.
    // '[persist.]libc.debug.gwp_asan.sample_rate.cameraserver') over the
    // generic sysprop (e.g.
    // '[persist.]libc.debug.gwp_asan.(system_default|app_default)'). In
    // addition, always take the non-persistent option over the persistent
    // option.
    sysprop_names[0] = program_specific_sysprop;
    sysprop_names[1] = persist_program_specific_sysprop;
    sysprop_names[2] = default_sysprop;
    sysprop_names[3] = persist_default_sysprop;
  }

  return get_config_from_env_or_sysprops(env_var, sysprop_names, arraysize(sysprop_names),
                                         value_out, PROP_VALUE_MAX);
}

bool GetGwpAsanIntegerOption(unsigned long long* result,
                             const android_mallopt_gwp_asan_options_t& mallopt_options,
                             const char* system_sysprop, const char* app_sysprop,
                             const char* targeted_sysprop_prefix, const char* env_var,
                             const char* descriptive_name) {
  char buffer[PROP_VALUE_MAX];
  if (!GetGwpAsanOptionImpl(buffer, mallopt_options, system_sysprop, app_sysprop,
                            targeted_sysprop_prefix, env_var)) {
    return false;
  }
  char* end;
  unsigned long long value = strtoull(buffer, &end, 10);
  if (value == ULLONG_MAX || *end != '\0') {
    warning_log("Invalid GWP-ASan %s: \"%s\". Using default value instead.", descriptive_name,
                buffer);
    return false;
  }

  *result = value;
  return true;
}

bool GetGwpAsanBoolOption(bool* result, const android_mallopt_gwp_asan_options_t& mallopt_options,
                          const char* system_sysprop, const char* app_sysprop,
                          const char* targeted_sysprop_prefix, const char* env_var,
                          const char* descriptive_name) {
  char buffer[PROP_VALUE_MAX] = {};
  if (!GetGwpAsanOptionImpl(buffer, mallopt_options, system_sysprop, app_sysprop,
                            targeted_sysprop_prefix, env_var)) {
    return false;
  }

  if (strncasecmp(buffer, "1", PROP_VALUE_MAX) == 0 ||
      strncasecmp(buffer, "true", PROP_VALUE_MAX) == 0) {
    *result = true;
    return true;
  } else if (strncasecmp(buffer, "0", PROP_VALUE_MAX) == 0 ||
             strncasecmp(buffer, "false", PROP_VALUE_MAX) == 0) {
    *result = false;
    return true;
  }

  warning_log(
      "Invalid GWP-ASan %s: \"%s\". Using default value \"%s\" instead. Valid values are \"true\", "
      "\"1\", \"false\", or \"0\".",
      descriptive_name, buffer, *result ? "true" : "false");
  return false;
}

// Initialize the GWP-ASan options structure in *options, taking into account whether someone has
// asked for specific GWP-ASan settings. The order of priority is:
//  1. Environment variables.
//  2. Process-specific system properties.
//  3. Global system properties.
// If any of these overrides are found, we return true. Otherwise, use the default values, and
// return false.
bool GetGwpAsanOptions(Options* options, unsigned* process_sample_rate,
                       const android_mallopt_gwp_asan_options_t& mallopt_options) {
  SetDefaultGwpAsanOptions(options, process_sample_rate, mallopt_options);

  bool had_overrides = false;

  unsigned long long buf;
  if (GetGwpAsanIntegerOption(&buf, mallopt_options, kSampleRateSystemSysprop,
                              kSampleRateAppSysprop, kSampleRateTargetedSyspropPrefix,
                              kSampleRateEnvVar, "sample rate")) {
    options->SampleRate = buf;
    had_overrides = true;
  }

  if (GetGwpAsanIntegerOption(&buf, mallopt_options, kProcessSamplingSystemSysprop,
                              kProcessSamplingAppSysprop, kProcessSamplingTargetedSyspropPrefix,
                              kProcessSamplingEnvVar, "process sampling rate")) {
    *process_sample_rate = buf;
    had_overrides = true;
  }

  if (GetGwpAsanIntegerOption(&buf, mallopt_options, kMaxAllocsSystemSysprop, kMaxAllocsAppSysprop,
                              kMaxAllocsTargetedSyspropPrefix, kMaxAllocsEnvVar,
                              "maximum simultaneous allocations")) {
    options->MaxSimultaneousAllocations = buf;
    had_overrides = true;
  } else if (had_overrides) {
    // Multiply the number of slots available, such that the ratio between
    // sampling rate and slots is kept the same as the default. For example, a
    // sampling rate of 1000 is 2.5x more frequent than default, and so
    // requires 80 slots (32 * 2.5).
    float frequency_multiplier = static_cast<float>(options->SampleRate) / kDefaultSampleRate;
    options->MaxSimultaneousAllocations =
        /* default */ kDefaultMaxAllocs / frequency_multiplier;
  }

  bool recoverable = true;
  if (GetGwpAsanBoolOption(&recoverable, mallopt_options, kRecoverableSystemSysprop,
                           kRecoverableAppSysprop, kRecoverableTargetedSyspropPrefix,
                           kRecoverableEnvVar, "recoverable")) {
    options->Recoverable = recoverable;
    GwpAsanRecoverable = recoverable;
    had_overrides = true;
  }

  return had_overrides;
}

bool MaybeInitGwpAsan(libc_globals* globals,
                      const android_mallopt_gwp_asan_options_t& mallopt_options) {
  if (GwpAsanInitialized) {
    error_log("GWP-ASan was already initialized for this process.");
    return false;
  }

  Options options;
  unsigned process_sample_rate = kDefaultProcessSampling;
  if (!GetGwpAsanOptions(&options, &process_sample_rate, mallopt_options) &&
      mallopt_options.mode == Mode::APP_MANIFEST_NEVER) {
    return false;
  }

  if (options.SampleRate == 0 || process_sample_rate == 0 ||
      options.MaxSimultaneousAllocations == 0) {
    return false;
  }

  if (!ShouldGwpAsanSampleProcess(process_sample_rate)) {
    return false;
  }

  // GWP-ASan is compatible with heapprofd/malloc_debug/malloc_hooks iff
  // GWP-ASan was installed first. If one of these other libraries was already
  // installed, we don't enable GWP-ASan. These libraries are normally enabled
  // in libc_init after GWP-ASan, but if the new process is a zygote child and
  // trying to initialize GWP-ASan through mallopt(), one of these libraries may
  // be installed. It may be possible to change this in future by modifying the
  // internal dispatch pointers of these libraries at this point in time, but
  // given that they're all debug-only, we don't really mind for now.
  if (GetDefaultDispatchTable() != nullptr) {
    // Something else is installed.
    return false;
  }

  // GWP-ASan's initialization is always called in a single-threaded context, so
  // we can initialize lock-free.
  // Set GWP-ASan as the malloc dispatch table.
  globals->malloc_dispatch_table = gwp_asan_dispatch;
  atomic_store(&globals->default_dispatch_table, &gwp_asan_dispatch);

  // If malloc_limit isn't installed, we can skip the default_dispatch_table
  // lookup.
  if (GetDispatchTable() == nullptr) {
    atomic_store(&globals->current_dispatch_table, &gwp_asan_dispatch);
  }

  GwpAsanInitialized = true;

  prev_dispatch = NativeAllocatorDispatch();

  GuardedAlloc.init(options);

  __libc_shared_globals()->gwp_asan_state = GuardedAlloc.getAllocatorState();
  __libc_shared_globals()->gwp_asan_metadata = GuardedAlloc.getMetadataRegion();
  __libc_shared_globals()->debuggerd_needs_gwp_asan_recovery = NeedsGwpAsanRecovery;
  __libc_shared_globals()->debuggerd_gwp_asan_pre_crash_report = GwpAsanPreCrashHandler;
  __libc_shared_globals()->debuggerd_gwp_asan_post_crash_report = GwpAsanPostCrashHandler;

  return true;
}
};  // anonymous namespace

bool MaybeInitGwpAsanFromLibc(libc_globals* globals) {
  // Never initialize the Zygote here. A Zygote chosen for sampling would also
  // have all of its children sampled. Instead, the Zygote child will choose
  // whether it samples or not just after the Zygote forks. Note that the Zygote
  // changes its name after it's started, at this point it's still called
  // "app_process" or "app_process64".
  static const char kAppProcessNamePrefix[] = "app_process";
  const char* progname = getprogname();
  if (strncmp(progname, kAppProcessNamePrefix, sizeof(kAppProcessNamePrefix) - 1) == 0)
    return false;

  android_mallopt_gwp_asan_options_t mallopt_options;
  mallopt_options.program_name = progname;
  mallopt_options.mode = Mode::SYSTEM_PROCESS_OR_SYSTEM_APP;

  return MaybeInitGwpAsan(globals, mallopt_options);
}

bool DispatchIsGwpAsan(const MallocDispatch* dispatch) {
  return dispatch == &gwp_asan_dispatch;
}

bool EnableGwpAsan(const android_mallopt_gwp_asan_options_t& options) {
  if (GwpAsanInitialized) {
    return true;
  }

  bool ret_value;
  __libc_globals.mutate(
      [&](libc_globals* globals) { ret_value = MaybeInitGwpAsan(globals, options); });
  return ret_value;
}
```