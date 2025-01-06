Response:
Let's break down the thought process for analyzing the `malloc_limit.cpp` file and generating the detailed response.

**1. Understanding the Goal:**

The core request is to understand the functionality of `malloc_limit.cpp`, its relationship to Android, how it works internally (especially the libc function implementations), its interaction with the dynamic linker, potential errors, and how to hook into it. Essentially, a deep dive into a specific piece of Android's memory management.

**2. Initial Scan and Identification of Core Functionality:**

The first step is to quickly read through the code to get a high-level understanding. Keywords like "Limit," "gAllocLimit," "gAllocated," and the `MallocDispatch` structure immediately stand out. This suggests the file is about imposing a limit on memory allocations. The presence of function pointers in `MallocDispatch` hints at a mechanism for intercepting or wrapping standard `malloc` family functions.

**3. Deconstructing the `MallocDispatch` Structure:**

The `MallocDispatch` structure is crucial. It lists all the `malloc` family functions that are being intercepted (e.g., `calloc`, `free`, `malloc`, `realloc`). This provides a roadmap for analyzing the individual `Limit...` functions. The fact that it's named `__limit_dispatch` strongly reinforces the "memory limit" purpose.

**4. Analyzing Individual `Limit...` Functions:**

For each `Limit...` function, the pattern is generally the same:

* **Check the Limit:**  The `CheckLimit(bytes)` function is called to see if the requested allocation would exceed the `gAllocLimit`.
* **Early Exit on Failure:** If the limit is exceeded, a warning is logged, and `nullptr` (or `ENOMEM` for `posix_memalign`) is returned.
* **Get the Underlying Dispatch Table:**  `GetDefaultDispatchTable()` is called. This is the key to the interception mechanism. If it's not `nullptr`, it means another memory allocator (like the default Android allocator) is in use.
* **Call the Underlying Function:** If a dispatch table exists, the corresponding function pointer in that table is called (e.g., `dispatch_table->calloc(...)`). Otherwise, the standard `Malloc(...)` macro (which likely resolves to the system `malloc`, `calloc`, etc.) is used.
* **Update `gAllocated`:** For successful allocations, `IncrementLimit()` updates the `gAllocated` counter. For `free` and `realloc`, `DecrementLimit()` or similar logic is used.

This pattern makes the analysis of each `Limit...` function relatively straightforward.

**5. Understanding the Limiting Mechanism:**

The variables `gAllocated` (atomic) and `gAllocLimit` are central. `gAllocated` tracks the currently allocated memory, and `gAllocLimit` is the maximum allowed allocation. The `CheckLimit` function performs the crucial comparison. The atomic nature of `gAllocated` ensures thread safety.

**6. Dynamic Linker Involvement (Important Nuance):**

The code itself doesn't *directly* use dynamic linker functions like `dlopen` or `dlsym`. However, the mechanism for switching the dispatch table (`EnableLimitDispatchTable`) *is* tied to how shared libraries and their symbols are managed by the dynamic linker. The `__libc_globals` structure is a global data structure managed by `libc.so`, and its modification needs careful synchronization, especially in a multi-threaded environment. The code uses mutexes and atomic operations to achieve this. The "so布局样本" (SO layout example) is meant to illustrate how `libc.so` and potentially other allocators coexist in memory. The "链接的处理过程" refers to how the dynamic linker resolves the `malloc` family function calls to either the `Limit...` versions or the underlying allocator's versions, based on the current dispatch table.

**7. Identifying Potential Errors:**

The code itself has some error handling (checking for `nullptr`, logging warnings). The analysis needs to consider common programmer errors when *using* this limiting mechanism. Trying to set the limit multiple times or passing incorrect arguments to `LimitEnable` are obvious examples.

**8. Connecting to Android Framework/NDK:**

This requires thinking about how an application running on Android might interact with this code. The NDK provides C/C++ APIs, which directly use the standard `malloc` family functions. The Android Framework (written in Java/Kotlin) often uses native code under the hood, which also relies on these functions. The key link is understanding that the `malloc` calls from these higher layers eventually reach the `libc` implementation, where the `malloc_limit.cpp` code can intercept them if enabled.

**9. Frida Hooking:**

To demonstrate the interaction, Frida is a natural choice. The examples need to show how to intercept the `LimitEnable` function to set the limit and then hook one of the `Limit...` allocation functions (like `LimitMalloc`) to observe the behavior.

**10. Structuring the Response:**

Finally, the information needs to be organized logically. Starting with the core functionality, explaining the implementation details, addressing the dynamic linker aspects, discussing errors, showing the connection to Android, and providing a practical debugging example makes for a comprehensive and understandable response. Using clear headings and formatting helps readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe `malloc_limit.cpp` directly calls `dlopen`. **Correction:**  It doesn't call dynamic linker functions directly, but its mechanism *relies* on the dynamic linker's symbol resolution and shared library management.
* **Initial thought:** Focus heavily on the specific details of each libc function's underlying implementation (e.g., how `malloc` in `dlmalloc` works). **Correction:** The request asks for the *functionality* of the `Limit...` wrappers. The core implementation of the underlying allocator is a separate topic (though acknowledged by the `Malloc(...)` macro). Focus on the limit-checking and dispatching logic.
* **Thinking about the SO layout:**  Realize it's not just `libc.so`. Other allocators might exist in different shared libraries. The layout example should reflect this potential complexity.

By following this structured thought process, including identifying key components, analyzing individual functions, understanding the overall mechanism, and connecting it to the broader Android ecosystem, a detailed and accurate response can be generated.
好的，让我们深入分析一下 `bionic/libc/bionic/malloc_limit.cpp` 这个文件。

**功能概览**

`malloc_limit.cpp` 的主要功能是**限制应用程序可以分配的最大内存量**。它通过实现一个自定义的 `malloc` 分发器（dispatch table）来拦截标准的内存分配函数（如 `malloc`, `calloc`, `free`, `realloc` 等），并在实际分配内存之前检查是否会超出预设的限制。

**与 Android 功能的关系及举例说明**

这个功能是 Android 安全和资源管理机制的一部分。限制单个进程的内存使用可以防止恶意或错误的应用程序占用过多内存，导致系统不稳定或崩溃。

**举例说明：**

假设一个应用程序尝试分配大量内存，例如一个很大的位图：

```c++
void* huge_memory = malloc(1024 * 1024 * 500); // 尝试分配 500MB
if (huge_memory == nullptr) {
  // 分配失败，可能是因为超过了内存限制
  perror("malloc failed");
}
```

如果没有 `malloc_limit.cpp` 的机制，如果系统内存足够，这次分配可能会成功。但是，如果启用了内存限制，并且设置了较低的限制（例如 256MB），那么 `LimitMalloc` 函数会检测到这次分配请求将超过限制，并返回 `nullptr`，导致分配失败。应用程序可以根据返回值进行相应的错误处理，避免程序崩溃。

**详细解释每一个 libc 函数的功能是如何实现的**

`malloc_limit.cpp` 并没有重新实现 `malloc`, `free` 等底层的内存分配算法。它做的是**包装（wrap）**这些标准的 libc 函数。让我们逐个分析：

* **`LimitCalloc(size_t n_elements, size_t elem_size)`:**
    1. 计算总请求大小：`total = n_elements * elem_size`。
    2. **检查内存限制：** 调用 `CheckLimit(total)`，该函数会将当前已分配的内存 `gAllocated` 加上请求分配的大小，如果超过 `gAllocLimit`，则返回 `false`。
    3. **超出限制处理：** 如果 `CheckLimit` 返回 `false`，则打印警告日志，并返回 `nullptr`。
    4. **获取默认分发器：** 调用 `GetDefaultDispatchTable()` 获取当前生效的 `malloc` 分发器。这允许在不同内存分配器之间切换。
    5. **调用底层 `calloc`：**
        * 如果 `dispatch_table` 不为空，则调用 `dispatch_table->calloc(n_elements, elem_size)`，即调用下一个分发器的 `calloc` 实现。
        * 否则，调用标准的 libc `calloc`，通过 `Malloc(calloc)(n_elements, elem_size)` 实现。 `Malloc` 宏很可能定义为直接调用 libc 函数。
    6. **更新已分配内存计数：** 如果分配成功（返回非空指针），则调用 `IncrementLimit()`，该函数会将新分配的内存大小（通过 `LimitUsableSize` 获取）添加到 `gAllocated` 中。
    7. **返回结果。**

* **`LimitFree(void* mem)`:**
    1. **更新已分配内存计数：** 调用 `atomic_fetch_sub(&gAllocated, LimitUsableSize(mem))`，从 `gAllocated` 中减去要释放的内存大小。
    2. **获取默认分发器。**
    3. **调用底层 `free`：** 类似 `LimitCalloc`，调用 `dispatch_table->free(mem)` 或 `Malloc(free)(mem)`。

* **`LimitMalloc(size_t bytes)`:**
    1. **检查内存限制：** 调用 `CheckLimit(bytes)`。
    2. **超出限制处理。**
    3. **获取默认分发器。**
    4. **调用底层 `malloc`。**
    5. **更新已分配内存计数。**

* **`LimitMemalign(size_t alignment, size_t bytes)` 和 `LimitPosixMemalign(void** memptr, size_t alignment, size_t size)` 和 `LimitAlignedAlloc(size_t alignment, size_t size)`:**
    与 `LimitMalloc` 类似，先检查内存限制，然后调用底层的对齐分配函数。`LimitPosixMemalign` 需要处理返回码。

* **`LimitRealloc(void* old_mem, size_t bytes)`:**
    1. **获取旧内存块的大小：** `old_usable_size = LimitUsableSize(old_mem)`。
    2. **检查内存限制（仅当需要增加大小时）：** 如果 `bytes > old_usable_size`，则调用 `CheckLimit(bytes - old_usable_size)`，因为只需要检查增加的内存量是否会超出限制。
    3. **超出限制处理（同时释放旧内存）：** 如果超出限制，则调用 `LimitFree(old_mem)` 释放旧内存，并返回 `nullptr`。
    4. **获取默认分发器。**
    5. **调用底层 `realloc`。**
    6. **更新已分配内存计数：**
        * 如果 `realloc` 成功，需要计算新旧内存块大小的差异，并更新 `gAllocated`。
        * 如果 `realloc` 失败返回 `nullptr`，则认为旧内存已释放，需要减去旧内存块的大小。

* **`LimitPvalloc(size_t bytes)` 和 `LimitValloc(size_t bytes)`:**  这些是已弃用的分配函数，处理逻辑与 `LimitMalloc` 类似。

* **传递函数（Pass through functions）：**  `LimitUsableSize`, `LimitMallinfo`, `LimitIterate`, `LimitMallocDisable`, `LimitMallocEnable`, `LimitMallocInfo`, `LimitMallopt` 这些函数直接调用底层相应的函数，它们的主要作用是让 `malloc_limit` 分发器能够处理这些操作，即使它本身不改变这些操作的行为。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程**

`malloc_limit.cpp` 本身并没有直接使用 `dlopen`, `dlsym` 等动态链接器 API。但是，它通过修改全局的 `malloc` 分发器表来实现其功能，这与动态链接器有密切关系。

**SO 布局样本：**

假设一个 Android 应用程序 `app_process` 启动，并加载了一些共享库：

```
Memory Map:

00000000 - 00000fff  [init]           # 启动加载器
00001000 - 000fffff  /system/bin/app_process64  # 主程序
...
xxxxxxxx - yyyyyyyy  /system/lib64/libc.so       # bionic C 库
...
aaaaaaaa - bbbbbbbb  /system/lib64/libm.so       # 数学库
...
cccccccc - dddddddd  /system/lib64/libart.so     # Android Runtime
...
eeeeeeee - ffffffff  /data/app/com.example.myapp/lib/arm64/libnative.so  # 应用程序的 native 库
```

* **`libc.so`:**  包含 `malloc`, `free` 等标准 C 库函数的实现，以及 `malloc_limit.cpp` 中的代码。
* **`libnative.so`:**  应用程序的本地代码库，它会调用 `libc.so` 中的内存分配函数。

**链接的处理过程：**

1. **默认状态：** 当应用程序启动时，动态链接器会加载所有需要的共享库。默认情况下，当 `libnative.so` 调用 `malloc` 时，动态链接器会将这个调用链接到 `libc.so` 中标准的 `malloc` 实现。

2. **启用内存限制：** 当调用 `LimitEnable` 函数时，它会尝试将全局的 `malloc` 分发器表切换为 `__limit_dispatch`。这个操作会修改 `libc.so` 中的全局状态。

3. **拦截内存分配：** 一旦 `__limit_dispatch` 生效，当 `libnative.so` 再次调用 `malloc` 时，动态链接器仍然会将其链接到 `libc.so` 中的 `malloc` 符号，但此时该符号已经被 `malloc_limit.cpp` 中的 `LimitMalloc` 函数覆盖（或者说，`malloc` 符号指向了 `LimitMalloc`）。

4. **检查和分发：**  `LimitMalloc` 函数首先检查内存限制。如果未超出限制，它会调用 `GetDefaultDispatchTable()`。如果默认分发器不是空（通常情况下，它会指向底层的实际分配器），则调用默认分发器的 `malloc` 函数。

**总结：** 动态链接器负责符号的解析和链接。`malloc_limit.cpp` 通过修改 `libc.so` 内部的全局分发器表，改变了 `malloc` 等函数的实际执行路径，从而实现了内存限制的功能。

**逻辑推理，给出假设输入与输出**

**假设输入：**

1. 应用程序调用 `LimitEnable(memory_limit)`，其中 `memory_limit` 的值为 10MB (10 * 1024 * 1024)。
2. 应用程序调用 `malloc(5MB)`。
3. 应用程序调用 `malloc(7MB)`。

**输出：**

1. `LimitEnable` 调用成功，全局变量 `gAllocLimit` 被设置为 10MB。
2. 第一个 `malloc(5MB)` 调用：
   - `CheckLimit(5MB)` 返回 `true` (5MB <= 10MB)。
   - 底层的 `malloc` 分配 5MB 内存。
   - `gAllocated` 更新为 5MB。
   - `malloc(5MB)` 返回一个有效的内存地址。
3. 第二个 `malloc(7MB)` 调用：
   - `CheckLimit(7MB)` 返回 `false` (当前已分配 5MB，加上请求的 7MB，总共 12MB，超过了 10MB 的限制)。
   - `LimitMalloc` 打印警告日志。
   - `malloc(7MB)` 返回 `nullptr`。

**涉及用户或者编程常见的使用错误，请举例说明**

1. **多次调用 `LimitEnable`：**  `LimitEnable` 内部有检查，只能被成功调用一次。后续调用会失败并打印错误日志。

   ```c++
   LimitEnable(&limit1, sizeof(limit1)); // 假设 limit1 包含初始限制值
   LimitEnable(&limit2, sizeof(limit2)); // 错误：限制只能设置一次
   ```

2. **传递错误的参数给 `LimitEnable`：** `LimitEnable` 期望的参数是指向 `size_t` 类型的指针。传递其他类型的指针或错误的大小会导致函数返回 `false` 并设置 `errno` 为 `EINVAL`。

   ```c++
   int wrong_limit = 1024;
   LimitEnable(&wrong_limit, sizeof(int)); // 错误：期望 size_t
   ```

3. **假设内存分配总是成功：**  即使在启用内存限制的情况下，程序也应该检查 `malloc`, `calloc`, `realloc` 等函数的返回值，因为即使在限制之内，也可能因为其他原因导致分配失败。

   ```c++
   void* ptr = malloc(some_size);
   // 缺少对 ptr 是否为 nullptr 的检查
   memcpy(ptr, data, some_size); // 如果 ptr 是 nullptr，会导致程序崩溃
   ```

4. **在多线程环境下不当使用：** 虽然 `gAllocated` 是原子类型，保证了更新的线程安全，但是如果多个线程同时尝试启用或修改内存限制，仍然需要适当的同步机制来避免竞争条件。`EnableLimitDispatchTable` 函数内部就使用了互斥锁来保护全局状态的修改。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `malloc_limit.cpp` 的路径：**

1. **Java 代码请求内存：** Android Framework (Java/Kotlin 代码) 中的对象创建、Bitmap 加载等操作最终可能需要在 Native 层分配内存。例如，创建一个大的 Bitmap 对象。

2. **Framework 调用 Native 代码：** Framework 通过 JNI (Java Native Interface) 调用 Android Runtime (ART) 中的 Native 代码，例如与 Bitmap 相关的 Native 方法。

3. **ART 调用 Bionic Libc：** ART 的 Native 代码在需要分配内存时，会调用 Bionic libc 提供的 `malloc`, `calloc` 等函数。

4. **`malloc_limit.cpp` 拦截：** 如果内存限制功能被启用，对 `malloc` 的调用会被 `malloc_limit.cpp` 中的 `LimitMalloc` 函数拦截。

**NDK 到 `malloc_limit.cpp` 的路径：**

1. **NDK 代码请求内存：** 使用 NDK 开发的应用程序，其 C/C++ 代码中直接调用 `malloc`, `calloc` 等标准 C 库函数。

2. **链接到 Bionic Libc：** NDK 应用程序在编译时会链接到 Bionic libc。

3. **`malloc_limit.cpp` 拦截：**  与 Framework 类似，如果内存限制被启用，对 `malloc` 的调用会被 `malloc_limit.cpp` 拦截。

**Frida Hook 示例：**

以下是一个使用 Frida Hook `LimitMalloc` 函数的示例，用于观察内存限制的行为：

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([package_name])
    session = device.attach(pid)
except Exception as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
'use strict';

// 假设已经在目标进程中启用了内存限制

// Hook LimitMalloc 函数
Interceptor.attach(Module.findExportByName("libc.so", "_Z11LimitMallocm"), { // 注意需要 demangle 函数名
    onEnter: function (args) {
        var bytes = args[0].toInt();
        send(`[LimitMalloc] Attempting to allocate ${bytes} bytes`);
    },
    onLeave: function (retval) {
        if (retval.isNull()) {
            send("[LimitMalloc] Allocation failed (limit exceeded?)");
        } else {
            send(`[LimitMalloc] Allocation successful, returned address: ${retval}`);
        }
    }
});

// 可以选择 hook LimitEnable 来观察限制是如何设置的
Interceptor.attach(Module.findExportByName("libc.so", "_Z11LimitEnablePvj"), { // 注意需要 demangle 函数名
    onEnter: function (args) {
        var limitPtr = ptr(args[0]);
        var limit = limitPtr.readU64();
        send(`[LimitEnable] Setting memory limit to ${limit} bytes`);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)

input() # 等待用户输入退出

session.detach()
```

**使用步骤：**

1. **安装 Frida 和 adb。**
2. **在 Android 设备上安装 Frida server。**
3. **将 Python 脚本保存为 `hook_malloc_limit.py`。**
4. **替换 `package_name` 为你的应用程序包名。**
5. **运行脚本：`python hook_malloc_limit.py`。**
6. **在你的应用程序中触发内存分配操作。**

**Frida Hook 说明：**

* **`Interceptor.attach`：**  用于 Hook 指定的函数。
* **`Module.findExportByName("libc.so", "_Z11LimitMallocm")`：**  在 `libc.so` 中查找 `LimitMalloc` 函数的地址。注意，C++ 函数名需要 demangle（可以使用 `c++filt` 命令获取 demangled name）。`_Z11LimitMallocm` 是 `LimitMalloc(size_t)` 的一种可能的 mangled name。
* **`onEnter`：**  在函数入口处执行的代码，可以访问函数参数。
* **`onLeave`：**  在函数返回前执行的代码，可以访问返回值。
* **`send()`：**  将消息发送回 Frida 客户端。

通过这个 Frida 脚本，你可以观察到 `LimitMalloc` 何时被调用，请求分配的内存大小，以及分配是否成功。如果分配失败，可以推测可能是由于超过了内存限制。你也可以 Hook `LimitEnable` 函数来查看内存限制是如何设置的。

希望这个详细的分析能够帮助你理解 `malloc_limit.cpp` 的功能和实现方式。

Prompt: 
```
这是目录为bionic/libc/bionic/malloc_limit.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <private/bionic_malloc_dispatch.h>

#if __has_feature(hwaddress_sanitizer)
#include <sanitizer/allocator_interface.h>
#endif

#include "malloc_common.h"
#include "malloc_common_dynamic.h"
#include "malloc_heapprofd.h"
#include "malloc_limit.h"

__BEGIN_DECLS
static void* LimitCalloc(size_t n_elements, size_t elem_size);
static void LimitFree(void* mem);
static void* LimitMalloc(size_t bytes);
static void* LimitMemalign(size_t alignment, size_t bytes);
static int LimitPosixMemalign(void** memptr, size_t alignment, size_t size);
static void* LimitRealloc(void* old_mem, size_t bytes);
static void* LimitAlignedAlloc(size_t alignment, size_t size);
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
static void* LimitPvalloc(size_t bytes);
static void* LimitValloc(size_t bytes);
#endif

// Pass through functions.
static size_t LimitUsableSize(const void* mem);
static struct mallinfo LimitMallinfo();
static int LimitIterate(uintptr_t base, size_t size, void (*callback)(uintptr_t, size_t, void*), void* arg);
static void LimitMallocDisable();
static void LimitMallocEnable();
static int LimitMallocInfo(int options, FILE* fp);
static int LimitMallopt(int param, int value);
__END_DECLS

static constexpr MallocDispatch __limit_dispatch
  __attribute__((unused)) = {
    LimitCalloc,
    LimitFree,
    LimitMallinfo,
    LimitMalloc,
    LimitUsableSize,
    LimitMemalign,
    LimitPosixMemalign,
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
    LimitPvalloc,
#endif
    LimitRealloc,
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
    LimitValloc,
#endif
    LimitIterate,
    LimitMallocDisable,
    LimitMallocEnable,
    LimitMallopt,
    LimitAlignedAlloc,
    LimitMallocInfo,
  };

static _Atomic uint64_t gAllocated;
static uint64_t gAllocLimit;

static inline bool CheckLimit(size_t bytes) {
  uint64_t total;
  if (__predict_false(__builtin_add_overflow(
                          atomic_load_explicit(&gAllocated, memory_order_relaxed), bytes, &total) ||
                      total > gAllocLimit)) {
    return false;
  }
  return true;
}

static inline void* IncrementLimit(void* mem) {
  if (__predict_false(mem == nullptr)) {
    return nullptr;
  }
  atomic_fetch_add(&gAllocated, LimitUsableSize(mem));
  return mem;
}

void* LimitCalloc(size_t n_elements, size_t elem_size) {
  size_t total;
  if (__builtin_mul_overflow(n_elements, elem_size, &total) || !CheckLimit(total)) {
    warning_log("malloc_limit: calloc(%zu, %zu) exceeds limit %" PRId64, n_elements, elem_size,
                gAllocLimit);
    return nullptr;
  }
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return IncrementLimit(dispatch_table->calloc(n_elements, elem_size));
  }
  return IncrementLimit(Malloc(calloc)(n_elements, elem_size));
}

void LimitFree(void* mem) {
  atomic_fetch_sub(&gAllocated, LimitUsableSize(mem));
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->free(mem);
  }
  return Malloc(free)(mem);
}

void* LimitMalloc(size_t bytes) {
  if (!CheckLimit(bytes)) {
    warning_log("malloc_limit: malloc(%zu) exceeds limit %" PRId64, bytes, gAllocLimit);
    return nullptr;
  }
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return IncrementLimit(dispatch_table->malloc(bytes));
  }
  return IncrementLimit(Malloc(malloc)(bytes));
}

static void* LimitMemalign(size_t alignment, size_t bytes) {
  if (!CheckLimit(bytes)) {
    warning_log("malloc_limit: memalign(%zu, %zu) exceeds limit %" PRId64, alignment, bytes,
                gAllocLimit);
    return nullptr;
  }
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return IncrementLimit(dispatch_table->memalign(alignment, bytes));
  }
  return IncrementLimit(Malloc(memalign)(alignment, bytes));
}

static int LimitPosixMemalign(void** memptr, size_t alignment, size_t size) {
  if (!CheckLimit(size)) {
    warning_log("malloc_limit: posix_memalign(%zu, %zu) exceeds limit %" PRId64, alignment, size,
                gAllocLimit);
    return ENOMEM;
  }
  int retval;
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    retval = dispatch_table->posix_memalign(memptr, alignment, size);
  } else {
    retval = Malloc(posix_memalign)(memptr, alignment, size);
  }
  if (__predict_false(retval != 0)) {
    return retval;
  }
  IncrementLimit(*memptr);
  return 0;
}

static void* LimitAlignedAlloc(size_t alignment, size_t size) {
  if (!CheckLimit(size)) {
    warning_log("malloc_limit: aligned_alloc(%zu, %zu) exceeds limit %" PRId64, alignment, size,
                gAllocLimit);
    return nullptr;
  }
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return IncrementLimit(dispatch_table->aligned_alloc(alignment, size));
  }
  return IncrementLimit(Malloc(aligned_alloc)(alignment, size));
}

static void* LimitRealloc(void* old_mem, size_t bytes) {
  size_t old_usable_size = LimitUsableSize(old_mem);
  void* new_ptr;
  // Need to check the size only if the allocation will increase in size.
  if (bytes > old_usable_size && !CheckLimit(bytes - old_usable_size)) {
    warning_log("malloc_limit: realloc(%p, %zu) exceeds limit %" PRId64, old_mem, bytes,
                gAllocLimit);
    // Free the old pointer.
    LimitFree(old_mem);
    return nullptr;
  }

  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    new_ptr = dispatch_table->realloc(old_mem, bytes);
  } else {
    new_ptr = Malloc(realloc)(old_mem, bytes);
  }

  if (__predict_false(new_ptr == nullptr)) {
    // This acts as if the pointer was freed.
    atomic_fetch_sub(&gAllocated, old_usable_size);
    return nullptr;
  }

  size_t new_usable_size = LimitUsableSize(new_ptr);
  // Assumes that most allocations increase in size, rather than shrink.
  if (__predict_false(old_usable_size > new_usable_size)) {
    atomic_fetch_sub(&gAllocated, old_usable_size - new_usable_size);
  } else {
    atomic_fetch_add(&gAllocated, new_usable_size - old_usable_size);
  }
  return new_ptr;
}

#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
static void* LimitPvalloc(size_t bytes) {
  if (!CheckLimit(bytes)) {
    warning_log("malloc_limit: pvalloc(%zu) exceeds limit %" PRId64, bytes, gAllocLimit);
    return nullptr;
  }
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return IncrementLimit(dispatch_table->pvalloc(bytes));
  }
  return IncrementLimit(Malloc(pvalloc)(bytes));
}

static void* LimitValloc(size_t bytes) {
  if (!CheckLimit(bytes)) {
    warning_log("malloc_limit: valloc(%zu) exceeds limit %" PRId64, bytes, gAllocLimit);
    return nullptr;
  }
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return IncrementLimit(dispatch_table->valloc(bytes));
  }
  return IncrementLimit(Malloc(valloc)(bytes));
}
#endif

bool MallocLimitInstalled() {
  return GetDispatchTable() == &__limit_dispatch;
}

#if defined(LIBC_STATIC)
static bool EnableLimitDispatchTable() {
  // This is the only valid way to modify the dispatch tables for a
  // static executable so no locks are necessary.
  __libc_globals.mutate([](libc_globals* globals) {
    atomic_store(&globals->current_dispatch_table, &__limit_dispatch);
  });
  return true;
}
#else
static bool EnableLimitDispatchTable() {
  pthread_mutex_lock(&gGlobalsMutateLock);
  // All other code that calls mutate will grab the gGlobalsMutateLock.
  // However, there is one case where the lock cannot be acquired, in the
  // signal handler that enables heapprofd. In order to avoid having two
  // threads calling mutate at the same time, use an atomic variable to
  // verify that only this function or the signal handler are calling mutate.
  // If this function is called at the same time as the signal handler is
  // being called, allow a short period for the signal handler to complete
  // before failing.
  bool enabled = false;
  size_t num_tries = 200;
  while (true) {
    if (!atomic_exchange(&gGlobalsMutating, true)) {
      __libc_globals.mutate([](libc_globals* globals) {
        atomic_store(&globals->current_dispatch_table, &__limit_dispatch);
      });
      atomic_store(&gGlobalsMutating, false);
      enabled = true;
      break;
    }
    if (--num_tries == 0) {
      break;
    }
    usleep(1000);
  }
  pthread_mutex_unlock(&gGlobalsMutateLock);
  if (enabled) {
    info_log("malloc_limit: Allocation limit enabled, max size %" PRId64 " bytes\n", gAllocLimit);
  } else {
    error_log("malloc_limit: Failed to enable allocation limit.");
  }
  return enabled;
}
#endif

bool LimitEnable(void* arg, size_t arg_size) {
  if (arg == nullptr || arg_size != sizeof(size_t)) {
    errno = EINVAL;
    return false;
  }

  static _Atomic bool limit_enabled;
  if (atomic_exchange(&limit_enabled, true)) {
    // The limit can only be enabled once.
    error_log("malloc_limit: The allocation limit has already been set, it can only be set once.");
    return false;
  }

  gAllocLimit = *reinterpret_cast<size_t*>(arg);
#if __has_feature(hwaddress_sanitizer)
  size_t current_allocated = __sanitizer_get_current_allocated_bytes();
#else
  size_t current_allocated;
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    current_allocated = dispatch_table->mallinfo().uordblks;
  } else {
    current_allocated = Malloc(mallinfo)().uordblks;
  }
#endif
  // This has to be set before the enable occurs since "gAllocated" is used
  // to compute the limit. If the enable fails, "gAllocated" is never used.
  atomic_store(&gAllocated, current_allocated);

  if (!EnableLimitDispatchTable()) {
    // Failed to enable, reset so a future enable will pass.
    atomic_store(&limit_enabled, false);
    return false;
  }
  return true;
}

static size_t LimitUsableSize(const void* mem) {
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->malloc_usable_size(mem);
  }
  return Malloc(malloc_usable_size)(mem);
}

static struct mallinfo LimitMallinfo() {
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->mallinfo();
  }
  return Malloc(mallinfo)();
}

static int LimitIterate(uintptr_t base, size_t size, void (*callback)(uintptr_t, size_t, void*), void* arg) {
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->malloc_iterate(base, size, callback, arg);
  }
  return Malloc(malloc_iterate)(base, size, callback, arg);
}

static void LimitMallocDisable() {
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    dispatch_table->malloc_disable();
  } else {
    Malloc(malloc_disable)();
  }
}

static void LimitMallocEnable() {
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    dispatch_table->malloc_enable();
  } else {
    Malloc(malloc_enable)();
  }
}

static int LimitMallocInfo(int options, FILE* fp) {
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->malloc_info(options, fp);
  }
  return Malloc(malloc_info)(options, fp);
}

static int LimitMallopt(int param, int value) {
  auto dispatch_table = GetDefaultDispatchTable();
  if (__predict_false(dispatch_table != nullptr)) {
    return dispatch_table->mallopt(param, value);
  }
  return Malloc(mallopt)(param, value);
}

"""

```