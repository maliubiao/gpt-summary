Response:
Let's break down the thought process for analyzing the `malloc_common_dynamic.cpp` file.

**1. Understanding the Core Purpose:**

The initial comments are crucial. They clearly state the file's role: a *thin layer* that dynamically loads the *real* memory allocator implementation. This immediately tells us:

* **Abstraction:** This file isn't doing the heavy lifting of memory management itself.
* **Dynamic Loading:**  Key functionalities will be loaded at runtime.
* **Debugging Focus:** The mention of "debug malloc" and intercepting allocation calls hints at a primary purpose beyond just basic allocation.

**2. Identifying Key Functionalities by Examining Includes and Globals:**

* **Includes:**  Looking at the `#include` directives reveals important areas:
    * `dlfcn.h`:  Dynamic linking functions (like `dlopen`, `dlsym`, `dlclose`). This confirms the dynamic loading aspect.
    * `pthread.h`:  Threading primitives (like mutexes). Suggests thread-safety considerations.
    * `stdatomic.h`: Atomic operations. Another indicator of concurrency control.
    * `<android/dlext.h>`: Android-specific dynamic linking extensions. This is a strong signal that the code is Android-specific.
    * `<platform/bionic/malloc.h>`, `<private/bionic_malloc_dispatch.h>`: Bionic's malloc interface and the dispatch table concept (which is key to the dynamic loading).
    * `<sys/system_properties.h>`: Accessing Android system properties. This is vital for the conditional loading of debug/hook libraries.
    * Headers related to GWP-ASan, heap tagging, zero initialization, heapprofd, and malloc limits: These indicate advanced memory management features being integrated.

* **Global Variables:** Global variables like `gGlobalsMutateLock`, `gGlobalsMutating`, `gZygoteChild`, and `gZygoteChildProfileable` provide insights into the file's context and how it interacts with the Android system (especially the Zygote process). The `gFunctions` array is a crucial pointer to the dynamically loaded allocator's functions.

**3. Deconstructing the `Init` Functions:**

The `InitMallocFunction`, `InitMallocFunctions`, `InitSharedLibrary`, and `LoadSharedLibrary` functions are central to the dynamic loading mechanism. Analyzing their steps is vital:

* **`InitMallocFunction`:**  Constructs the symbol name (e.g., "debug_malloc") and uses `dlsym` to find the function within the loaded library. The error handling (`dlsym` returning `nullptr`) is important.
* **`InitMallocFunctions`:** Iterates through the standard `malloc` family of functions and calls `InitMallocFunction` for each. This shows how the dispatch table is populated.
* **`InitSharedLibrary`:**  Looks for the "initialize", "finalize", and leak info functions, in addition to the core malloc functions. The error handling if any of these aren't found is significant.
* **`LoadSharedLibrary`:** This is the core dynamic loading logic. It attempts to load from the "runtime" namespace first (for APEX compatibility) and falls back to the default namespace. The use of `android_dlopen_ext` is an Android-specific detail.

**4. Understanding the Role of System Properties and Environment Variables:**

The `CheckLoadMallocHooks` and `CheckLoadMallocDebug` functions are critical for understanding how the debugging and hooking mechanisms are activated. They check both system properties (`libc.debug.malloc.options`, etc.) and environment variables (`LIBC_DEBUG_MALLOC_OPTIONS`, etc.), with environment variables taking precedence. The check for specific programs via `libc.debug.malloc.program` is an interesting detail.

**5. Analyzing `MallocInitImpl` and `__libc_init_malloc`:**

These functions orchestrate the entire initialization process. `MallocInitImpl` decides whether to load debug malloc or hooks based on the property checks. `__libc_init_malloc` is the entry point called during the libc initialization. The logic for handling Heapprofd installation if no other hooks are installed is also important.

**6. Examining the Leak Information Functions:**

The `GetMallocLeakInfo`, `FreeMallocLeakInfo`, and `WriteMallocLeakInfo` functions are clearly related to debugging and memory leak detection. The fallback behavior in `WriteMallocLeakInfo` if debug malloc isn't enabled is a practical touch.

**7. Understanding `malloc_backtrace`:**

This function allows retrieving the allocation backtrace, which is essential for debugging memory issues. Its dependency on the dynamically loaded library is clear.

**8. Recognizing the Older `get_malloc_leak_info` and `free_malloc_leak_info`:**

The conditional compilation (`#if !defined(__LP64__) && defined(__arm__)`) and the comment about "old platform only functions" are crucial. This highlights backward compatibility considerations.

**9. Connecting to Android Framework/NDK and Frida:**

At this stage, knowing that this code is part of Bionic (Android's C library) provides the link to the Android Framework and NDK. Framework components and NDK applications ultimately rely on the functions provided by libc, including memory allocation. The request for Frida hooks requires identifying relevant function calls that could be intercepted (e.g., the `dlopen`, `dlsym` calls, the `malloc`, `free` calls within the loaded libraries, or even the `__libc_init_malloc` function).

**10. Structuring the Output:**

The request asks for specific information, so organizing the answer clearly is essential:

* **Functions:** List the functions and their roles concisely.
* **Android Relationship:** Explain how this code relates to Android's overall functionality, especially the role of Bionic.
* **libc Function Details:** Elaborate on the implementation of key libc functions within this file (mainly the initialization and dynamic loading logic).
* **Dynamic Linker Aspects:** Detail the SO layout (libc and the debug/hook libraries) and the linking process.
* **Logic Inference:**  Provide examples of how the conditional loading works based on properties.
* **Common Errors:**  Give examples of misuse, such as forgetting to enable debug malloc.
* **Android Framework/NDK Integration:** Describe the path from the Framework/NDK down to this code.
* **Frida Hooks:** Provide practical Frida examples for intercepting relevant function calls.

**Self-Correction/Refinement During Analysis:**

* **Initial Thought:**  Might initially focus too much on the individual malloc/free functions.
* **Correction:** Realize that this file is *not* the implementation of malloc/free but a *loader* for it. Shift focus to the dynamic loading aspects.
* **Initial Thought:**  Might overlook the significance of the system properties and environment variables.
* **Correction:** Recognize their central role in controlling the debugging and hooking features.
* **Initial Thought:**  Might not immediately connect the older leak info functions to backward compatibility.
* **Correction:**  Pay attention to the conditional compilation and comments indicating the reason for their existence.

By following these steps, focusing on the core purpose, identifying key components, and carefully analyzing the code, we can arrive at a comprehensive and accurate understanding of the `malloc_common_dynamic.cpp` file.
好的，让我们来详细分析 `bionic/libc/bionic/malloc_common_dynamic.cpp` 这个文件。

**文件功能概述**

`malloc_common_dynamic.cpp` 在 Android Bionic 库中扮演着内存分配机制的动态加载和调试桥梁的角色。它本身并不直接实现内存分配的核心逻辑，而是负责：

1. **动态加载实际的内存分配器实现：**  根据系统属性或环境变量，动态加载 `libc_malloc_debug.so` (调试 malloc) 或 `libc_malloc_hooks.so` (malloc hooks)。
2. **提供统一的 malloc 接口：**  通过函数指针 `gFunctions` 数组和 `MallocDispatch` 结构体，将外部的 `malloc`、`free` 等内存管理函数调用转发到动态加载的库中。
3. **支持内存泄漏检测和调试：**  如果加载了调试 malloc 库，则提供获取和写入内存泄漏信息的功能。
4. **提供 malloc hooks 机制：** 允许开发者自定义内存分配和释放的行为。
5. **处理 Zygote 进程的特殊情况：**  区分 Zygote 父进程和子进程，并允许对子进程进行性能分析。
6. **为 Heapprofd 提供集成点：**  当没有加载调试 malloc 或 hooks 时，允许 Heapprofd (一种内存分析工具) 安装其 hooks。

**与 Android 功能的关系及举例说明**

这个文件是 Android 系统内存管理的关键组成部分，直接影响着所有 Native 代码的内存分配行为。

* **核心系统服务：** Android 的核心系统服务（例如 `system_server`）大量使用 C++ 和 Native 代码，其内存分配最终都会通过这里。例如，当 `system_server` 需要分配一块新的内存来存储一个 Activity 的信息时，它会调用 `malloc`，这个调用最终会被转发到 `malloc_common_dynamic.cpp` 加载的实际分配器。
* **应用程序框架 (Android Framework)：**  虽然 Java 代码主要使用 Dalvik/ART 虚拟机的垃圾回收机制，但 Framework 中仍然存在 Native 组件，例如 SurfaceFlinger (负责屏幕合成)。这些组件的内存管理也依赖于此。
* **NDK 应用程序：**  使用 Android NDK 开发的应用程序完全运行在 Native 层，所有的内存分配都通过 Bionic 的 `malloc` 等函数，因此 `malloc_common_dynamic.cpp` 对 NDK 应用至关重要。
* **调试和性能分析：**  通过加载调试 malloc 库，开发者可以方便地进行内存泄漏检测。例如，开发者可以设置 `libc.debug.malloc.options` 系统属性为 `backtrace`，然后运行应用，应用退出时或者调用相关 API 就可以生成内存泄漏的报告。
* **自定义内存管理：**  通过 malloc hooks 机制，开发者可以实现自定义的内存分配策略，例如用于特定的性能优化或者安全监控场景。

**libc 函数的功能实现**

这个文件本身并没有直接实现 `malloc`、`free` 等 libc 函数的核心逻辑。它的主要工作是动态地加载实现了这些函数的共享库。下面解释一下相关的辅助函数：

* **`InitMallocFunction`:**
    * **功能：** 从已加载的共享库 (`malloc_impl_handler`) 中查找特定的 malloc 函数 (例如 "debug_malloc", "hooks_free") 的地址。
    * **实现：** 使用 `dlsym` 函数，该函数是动态链接器提供的 API，用于在已加载的共享库中查找符号 (函数或变量) 的地址。
    * **假设输入与输出：**
        * **假设输入：** `malloc_impl_handler` 指向 `libc_malloc_debug.so` 的句柄，`prefix` 为 "debug"，`suffix` 为 "malloc"。
        * **输出：** 如果 `libc_malloc_debug.so` 中存在名为 `debug_malloc` 的函数，则返回该函数的地址，否则返回 `nullptr`。
* **`InitMallocFunctions`:**
    * **功能：**  批量从已加载的共享库中查找并初始化 `MallocDispatch` 结构体中的所有标准 malloc 函数指针 (如 `malloc`, `free`, `calloc` 等)。
    * **实现：** 循环调用 `InitMallocFunction` 来查找每个 malloc 函数。
* **`LoadSharedLibrary`:**
    * **功能：**  加载指定的共享库 (`shared_lib`)，例如 `libc_malloc_debug.so` 或 `libc_malloc_hooks.so`。
    * **实现：**
        1. **尝试从 "runtime" 命名空间加载：**  首先尝试使用 `android_dlopen_ext` 从名为 "com_android_runtime" 的命名空间加载库。这通常用于加载与运行时 APEX 包裹在一起的库。
        2. **回退到默认命名空间加载：** 如果在 "runtime" 命名空间中找不到，则使用标准的 `dlopen` 函数从默认的命名空间加载。
    * **动态链接器的参与：**  `dlopen` 是动态链接器的核心 API。当调用 `dlopen` 时，动态链接器会：
        1. 查找指定的共享库文件。
        2. 将共享库加载到进程的地址空间。
        3. 解析共享库的符号依赖，并加载其依赖的其他共享库。
        4. 执行共享库的初始化代码 (通常是 `__attribute__((constructor))` 修饰的函数)。
* **`InstallHooks`:**
    * **功能：**  加载指定的共享库，并调用其初始化函数来安装 malloc hooks 或调试 malloc。
    * **实现：**
        1. 调用 `LoadSharedLibrary` 加载共享库。
        2. 调用共享库中的 `initialize` 函数 (通过 `gFunctions[FUNC_INITIALIZE]` 获取)，传递当前的 `MallocDispatch` 表和一些配置信息。
        3. 将新加载的分配器的函数指针更新到全局的 `default_dispatch_table` 和 `current_dispatch_table` 中。
        4. 使用 `__cxa_atexit` 注册一个在进程退出时调用的清理函数 (`MallocFiniImpl`)。

**涉及 Dynamic Linker 的功能**

`malloc_common_dynamic.cpp` 与动态链接器密切相关，因为它依赖动态链接器来加载和链接实际的内存分配器实现。

**SO 布局样本**

假设我们正在运行一个启用了调试 malloc 的应用。进程的内存布局可能如下：

```
[进程地址空间]
+-----------------------+
|       ...           |
+-----------------------+
|       libc.so         |  <-- bionic 库本身
|   (包含 malloc_common_dynamic.cpp) |
+-----------------------+
|  libc_malloc_debug.so |  <-- 动态加载的调试 malloc 库
|   (实现了 malloc, free 等函数) |
+-----------------------+
|       ...           |
+-----------------------+
```

**链接的处理过程**

1. **libc.so 加载：** 当进程启动时，动态链接器会首先加载 `libc.so`。
2. **`__libc_init_malloc` 调用：**  `libc.so` 的初始化代码会调用 `__libc_init_malloc` 函数。
3. **决定加载哪个分配器：** `__libc_init_malloc` 内部的 `MallocInitImpl` 函数会检查系统属性 (`libc.debug.malloc.options`) 或环境变量 (`LIBC_DEBUG_MALLOC_OPTIONS`) 来决定是否加载调试 malloc 库。
4. **`LoadSharedLibrary` 调用：** 如果需要加载调试 malloc，则调用 `LoadSharedLibrary("libc_malloc_debug.so", ...)`。
5. **动态链接：** 动态链接器会找到 `libc_malloc_debug.so` 文件，将其加载到进程地址空间，并解析其符号依赖。
6. **符号查找和链接：** `InitMallocFunctions` 函数使用 `dlsym` 在 `libc_malloc_debug.so` 中查找 `debug_malloc`、`debug_free` 等符号的地址。找到的地址会被赋值给 `globals->malloc_dispatch_table` 中的函数指针。
7. **后续 malloc 调用：** 当应用程序调用 `malloc` 时，实际上会调用 `libc.so` 中定义的 `malloc` (通常是一个内联函数或者宏)，该函数会间接地通过 `globals->current_dispatch_table->malloc` 调用到 `libc_malloc_debug.so` 中实现的 `debug_malloc` 函数。

**逻辑推理、假设输入与输出**

假设系统属性 `libc.debug.malloc.options` 被设置为 `backtrace`。

* **假设输入：**  `__system_property_get("libc.debug.malloc.options", prop)` 返回 "backtrace"。
* **逻辑推理：** `CheckLoadMallocDebug` 函数会判断该属性不为空，并且不会被 `libc.debug.malloc.program` 过滤，从而返回 `true`。
* **输出：** `InstallHooks` 函数会被调用，尝试加载 `libc_malloc_debug.so`。如果加载成功，`gFunctions` 数组和 `globals->malloc_dispatch_table` 会被 `libc_malloc_debug.so` 中的函数地址填充，后续的内存分配操作将由调试 malloc 库处理。

**用户或编程常见的使用错误**

1. **忘记设置系统属性或环境变量：**  开发者希望启用调试 malloc 或 malloc hooks，但忘记设置相应的系统属性或环境变量，导致实际加载的是默认的分配器。
2. **设置了错误的属性值：**  例如，将 `libc.debug.malloc.options` 设置为无效的值，导致加载失败或者行为异常。
3. **在错误的时机设置属性：**  有些属性需要在进程启动前设置才能生效。如果在进程运行过程中修改，可能不会对该进程产生影响。
4. **混淆调试 malloc 和 malloc hooks：**  两者是互斥的，只能加载其中一个。开发者可能错误地尝试同时启用两者。
5. **在生产环境启用调试 malloc：**  调试 malloc 通常会带来性能损耗，不应该在生产环境中使用。
6. **不理解 malloc hooks 的副作用：**  自定义的 malloc hooks 可能会引入新的 bug 或者性能问题，需要谨慎使用和测试。

**Android Framework 或 NDK 如何到达这里**

1. **应用程序启动或 Framework 组件初始化：**  无论是应用程序进程启动还是 Framework 的核心服务启动，动态链接器都会加载必要的共享库，包括 `libc.so`。
2. **`libc.so` 初始化：**  在 `libc.so` 加载完成后，其初始化代码会被执行，其中包括调用 `__libc_init_malloc` 函数。
3. **`MallocInitImpl` 执行：** `__libc_init_malloc` 会调用 `MallocInitImpl`，该函数会根据系统属性或环境变量决定是否加载调试 malloc 或 malloc hooks 库。
4. **加载共享库 (如果需要)：**  如果启用了调试 malloc 或 hooks，`LoadSharedLibrary` 函数会被调用，动态链接器会介入加载相应的 `.so` 文件。
5. **`InstallHooks` 安装钩子：**  加载成功后，`InstallHooks` 函数会调用共享库的初始化函数，将自定义的内存分配函数地址注册到全局的 `malloc_dispatch_table` 中。
6. **应用程序或 Framework 调用 malloc/free：**  当应用程序或 Framework 的 Native 代码调用 `malloc`、`free` 等函数时，这些调用最终会通过 `malloc_dispatch_table` 中注册的函数指针，路由到实际的内存分配器实现 (可能是默认的、调试 malloc 的，或者是自定义 hooks 的)。

**Frida Hook 示例调试**

以下是一些可以使用 Frida 进行 Hook 的关键函数，以观察内存分配过程：

```javascript
// Hook __libc_init_malloc 函数，观察初始化过程
Interceptor.attach(Module.findExportByName("libc.so", "__libc_init_malloc"), {
  onEnter: function (args) {
    console.log("[__libc_init_malloc] called");
  },
  onLeave: function (retval) {
    console.log("[__libc_init_malloc] returned");
  }
});

// Hook LoadSharedLibrary 函数，观察共享库的加载
Interceptor.attach(Module.findExportByName("libc.so", "_Z17LoadSharedLibraryPKcS0_P14MallocDispatch"), { // 函数签名可能因 Android 版本而异，需要调整
  onEnter: function (args) {
    console.log("[LoadSharedLibrary] shared_lib:", args[0].readUtf8String());
  },
  onLeave: function (retval) {
    console.log("[LoadSharedLibrary] returned handle:", retval);
  }
});

// Hook dlopen 函数，观察更底层的动态链接过程
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter: function (args) {
    console.log("[dlopen] path:", args[0].readUtf8String());
  },
  onLeave: function (retval) {
    console.log("[dlopen] returned handle:", retval);
  }
});

// Hook InitMallocFunctions 函数，观察函数指针的初始化
Interceptor.attach(Module.findExportByName("libc.so", "_Z17InitMallocFunctionsPvP14MallocDispatchPKc"), { // 函数签名可能因 Android 版本而异，需要调整
  onEnter: function (args) {
    console.log("[InitMallocFunctions] impl_handler:", args[0]);
    console.log("[InitMallocFunctions] prefix:", args[2].readUtf8String());
  },
  onLeave: function (retval) {
    console.log("[InitMallocFunctions] returned:", retval);
  }
});

// Hook 实际的 malloc 函数调用 (可能在 libc_malloc_debug.so 或 libc_malloc_hooks.so 中)
const mallocPtr = Module.findExportByName(null, "malloc"); // 如果加载了调试 malloc 或 hooks，需要找到对应的库
if (mallocPtr) {
  Interceptor.attach(mallocPtr, {
    onEnter: function (args) {
      console.log("[malloc] size:", args[0]);
    },
    onLeave: function (retval) {
      console.log("[malloc] returned address:", retval);
    }
  });
}
```

**总结**

`malloc_common_dynamic.cpp` 虽然代码量不大，但它在 Android 的内存管理体系中扮演着至关重要的角色。它通过动态加载机制，实现了内存分配器的灵活切换和扩展，为调试、性能分析以及自定义内存管理提供了基础。理解这个文件的工作原理，有助于深入了解 Android Native 内存管理机制。

Prompt: 
```
这是目录为bionic/libc/bionic/malloc_common_dynamic.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#if defined(LIBC_STATIC)
#error This file should not be compiled for static targets.
#endif

// Contains a thin layer that calls whatever real native allocator
// has been defined. For the libc shared library, this allows the
// implementation of a debug malloc that can intercept all of the allocation
// calls and add special debugging code to attempt to catch allocation
// errors. All of the debugging code is implemented in a separate shared
// library that is only loaded when the property "libc.debug.malloc.options"
// is set to a non-zero value. There are three functions exported to
// allow ddms, or other external users to get information from the debug
// allocation.
//   get_malloc_leak_info: Returns information about all of the known native
//                         allocations that are currently in use.
//   free_malloc_leak_info: Frees the data allocated by the call to
//                          get_malloc_leak_info.
//   write_malloc_leak_info: Writes the leak info data to a file.

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <android/dlext.h>

#include <platform/bionic/malloc.h>
#include <private/ScopedPthreadMutexLocker.h>
#include <private/bionic_config.h>
#include <private/bionic_defs.h>
#include <private/bionic_malloc_dispatch.h>

#include <sys/system_properties.h>

#include "gwp_asan_wrappers.h"
#include "heap_tagging.h"
#include "heap_zero_init.h"
#include "malloc_common.h"
#include "malloc_common_dynamic.h"
#include "malloc_heapprofd.h"
#include "malloc_limit.h"

// =============================================================================
// Global variables instantations.
// =============================================================================
pthread_mutex_t gGlobalsMutateLock = PTHREAD_MUTEX_INITIALIZER;

_Atomic bool gGlobalsMutating = false;

bool gZygoteChild = false;

// In a Zygote child process, this is set to true if profiling of this process
// is allowed. Note that this is set at a later time than gZygoteChild. The
// latter is set during the fork (while still in zygote's SELinux domain). While
// this bit is set after the child is specialized (and has transferred SELinux
// domains if applicable). These two flags are read by the
// BIONIC_SIGNAL_PROFILER handler, which does nothing if the process is not
// profileable.
_Atomic bool gZygoteChildProfileable = false;

// =============================================================================

static constexpr char kHooksSharedLib[] = "libc_malloc_hooks.so";
static constexpr char kHooksPrefix[] = "hooks";
static constexpr char kHooksPropertyEnable[] = "libc.debug.hooks.enable";
static constexpr char kHooksEnvEnable[] = "LIBC_HOOKS_ENABLE";

static constexpr char kDebugSharedLib[] = "libc_malloc_debug.so";
static constexpr char kDebugPrefix[] = "debug";
static constexpr char kDebugPropertyOptions[] = "libc.debug.malloc.options";
static constexpr char kDebugPropertyProgram[] = "libc.debug.malloc.program";
static constexpr char kDebugEnvOptions[] = "LIBC_DEBUG_MALLOC_OPTIONS";

typedef void (*finalize_func_t)();
typedef bool (*init_func_t)(const MallocDispatch*, bool*, const char*);
typedef void (*get_malloc_leak_info_func_t)(uint8_t**, size_t*, size_t*, size_t*, size_t*);
typedef void (*free_malloc_leak_info_func_t)(uint8_t*);
typedef bool (*write_malloc_leak_info_func_t)(FILE*);
typedef ssize_t (*malloc_backtrace_func_t)(void*, uintptr_t*, size_t);

enum FunctionEnum : uint8_t {
  FUNC_INITIALIZE,
  FUNC_FINALIZE,
  FUNC_GET_MALLOC_LEAK_INFO,
  FUNC_FREE_MALLOC_LEAK_INFO,
  FUNC_MALLOC_BACKTRACE,
  FUNC_WRITE_LEAK_INFO,
  FUNC_LAST,
};
static void* gFunctions[FUNC_LAST];

extern "C" int __cxa_atexit(void (*func)(void *), void *arg, void *dso);

template<typename FunctionType>
static bool InitMallocFunction(void* malloc_impl_handler, FunctionType* func, const char* prefix, const char* suffix) {
  char symbol[128];
  snprintf(symbol, sizeof(symbol), "%s_%s", prefix, suffix);
  *func = reinterpret_cast<FunctionType>(dlsym(malloc_impl_handler, symbol));
  if (*func == nullptr) {
    error_log("%s: dlsym(\"%s\") failed", getprogname(), symbol);
    return false;
  }
  return true;
}

static bool InitMallocFunctions(void* impl_handler, MallocDispatch* table, const char* prefix) {
  if (!InitMallocFunction<MallocFree>(impl_handler, &table->free, prefix, "free")) {
    return false;
  }
  if (!InitMallocFunction<MallocCalloc>(impl_handler, &table->calloc, prefix, "calloc")) {
    return false;
  }
  if (!InitMallocFunction<MallocMallinfo>(impl_handler, &table->mallinfo, prefix, "mallinfo")) {
    return false;
  }
  if (!InitMallocFunction<MallocMallopt>(impl_handler, &table->mallopt, prefix, "mallopt")) {
    return false;
  }
  if (!InitMallocFunction<MallocMalloc>(impl_handler, &table->malloc, prefix, "malloc")) {
    return false;
  }
  if (!InitMallocFunction<MallocMallocInfo>(impl_handler, &table->malloc_info, prefix,
                                                "malloc_info")) {
    return false;
  }
  if (!InitMallocFunction<MallocMallocUsableSize>(impl_handler, &table->malloc_usable_size, prefix,
                                                  "malloc_usable_size")) {
    return false;
  }
  if (!InitMallocFunction<MallocMemalign>(impl_handler, &table->memalign, prefix, "memalign")) {
    return false;
  }
  if (!InitMallocFunction<MallocPosixMemalign>(impl_handler, &table->posix_memalign, prefix,
                                               "posix_memalign")) {
    return false;
  }
  if (!InitMallocFunction<MallocAlignedAlloc>(impl_handler, &table->aligned_alloc,
                                              prefix, "aligned_alloc")) {
    return false;
  }
  if (!InitMallocFunction<MallocRealloc>(impl_handler, &table->realloc, prefix, "realloc")) {
    return false;
  }
  if (!InitMallocFunction<MallocIterate>(impl_handler, &table->malloc_iterate, prefix,
                                         "malloc_iterate")) {
    return false;
  }
  if (!InitMallocFunction<MallocMallocDisable>(impl_handler, &table->malloc_disable, prefix,
                                               "malloc_disable")) {
    return false;
  }
  if (!InitMallocFunction<MallocMallocEnable>(impl_handler, &table->malloc_enable, prefix,
                                              "malloc_enable")) {
    return false;
  }
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  if (!InitMallocFunction<MallocPvalloc>(impl_handler, &table->pvalloc, prefix, "pvalloc")) {
    return false;
  }
  if (!InitMallocFunction<MallocValloc>(impl_handler, &table->valloc, prefix, "valloc")) {
    return false;
  }
#endif

  return true;
}

static void MallocFiniImpl(void*) {
  // Our BSD stdio implementation doesn't close the standard streams,
  // it only flushes them. Other unclosed FILE*s will show up as
  // malloc leaks, but to avoid the standard streams showing up in
  // leak reports, close them here.
  fclose(stdin);
  fclose(stdout);
  fclose(stderr);

  reinterpret_cast<finalize_func_t>(gFunctions[FUNC_FINALIZE])();
}

static bool CheckLoadMallocHooks(char** options) {
  char* env = getenv(kHooksEnvEnable);
  if ((env == nullptr || env[0] == '\0' || env[0] == '0') &&
    (__system_property_get(kHooksPropertyEnable, *options) == 0 || *options[0] == '\0' || *options[0] == '0')) {
    return false;
  }
  *options = nullptr;
  return true;
}

static bool CheckLoadMallocDebug(char** options) {
  // If kDebugMallocEnvOptions is set then it overrides the system properties.
  char* env = getenv(kDebugEnvOptions);
  if (env == nullptr || env[0] == '\0') {
    if (__system_property_get(kDebugPropertyOptions, *options) == 0 || *options[0] == '\0') {
      return false;
    }

    // Check to see if only a specific program should have debug malloc enabled.
    char program[PROP_VALUE_MAX];
    if (__system_property_get(kDebugPropertyProgram, program) != 0 &&
        strstr(getprogname(), program) == nullptr) {
      return false;
    }
  } else {
    *options = env;
  }
  return true;
}

void SetGlobalFunctions(void* functions[]) {
  for (size_t i = 0; i < FUNC_LAST; i++) {
    gFunctions[i] = functions[i];
  }
}

static void ClearGlobalFunctions() {
  for (size_t i = 0; i < FUNC_LAST; i++) {
    gFunctions[i] = nullptr;
  }
}

bool InitSharedLibrary(void* impl_handle, const char* shared_lib, const char* prefix, MallocDispatch* dispatch_table) {
  static constexpr const char* names[] = {
    "initialize",
    "finalize",
    "get_malloc_leak_info",
    "free_malloc_leak_info",
    "malloc_backtrace",
    "write_malloc_leak_info",
  };
  for (size_t i = 0; i < FUNC_LAST; i++) {
    char symbol[128];
    snprintf(symbol, sizeof(symbol), "%s_%s", prefix, names[i]);
    gFunctions[i] = dlsym(impl_handle, symbol);
    if (gFunctions[i] == nullptr) {
      error_log("%s: %s routine not found in %s", getprogname(), symbol, shared_lib);
      ClearGlobalFunctions();
      return false;
    }
  }

  if (!InitMallocFunctions(impl_handle, dispatch_table, prefix)) {
    ClearGlobalFunctions();
    return false;
  }
  return true;
}

extern "C" struct android_namespace_t* android_get_exported_namespace(const char* name);

void* LoadSharedLibrary(const char* shared_lib, const char* prefix, MallocDispatch* dispatch_table) {
  void* impl_handle = nullptr;
  // Try to load the libc_malloc_* libs from the "runtime" namespace and then
  // fall back to dlopen() to load them from the default namespace.
  //
  // The libraries are packaged in the runtime APEX together with libc.so.
  // However, since the libc.so is searched via the symlink in the system
  // partition (/system/lib/libc.so -> /apex/com.android.runtime/bionic/libc.so)
  // libc.so is loaded into the default namespace. If we just dlopen() here, the
  // linker will load the libs found in /system/lib which might be incompatible
  // with libc.so in the runtime APEX. Use android_dlopen_ext to explicitly load
  // the ones in the runtime APEX.
  struct android_namespace_t* runtime_ns = android_get_exported_namespace("com_android_runtime");
  if (runtime_ns != nullptr) {
    const android_dlextinfo dlextinfo = {
      .flags = ANDROID_DLEXT_USE_NAMESPACE,
      .library_namespace = runtime_ns,
    };
    impl_handle = android_dlopen_ext(shared_lib, RTLD_NOW | RTLD_LOCAL, &dlextinfo);
  }

  if (impl_handle == nullptr) {
    impl_handle = dlopen(shared_lib, RTLD_NOW | RTLD_LOCAL);
  }

  if (impl_handle == nullptr) {
    error_log("%s: Unable to open shared library %s: %s", getprogname(), shared_lib, dlerror());
    return nullptr;
  }

  if (!InitSharedLibrary(impl_handle, shared_lib, prefix, dispatch_table)) {
    dlclose(impl_handle);
    impl_handle = nullptr;
  }

  return impl_handle;
}

bool FinishInstallHooks(libc_globals* globals, const char* options, const char* prefix) {
  init_func_t init_func = reinterpret_cast<init_func_t>(gFunctions[FUNC_INITIALIZE]);

  // If GWP-ASan was initialised, we should use it as the dispatch table for
  // heapprofd/malloc_debug/malloc_debug.
  const MallocDispatch* prev_dispatch = GetDefaultDispatchTable();
  if (prev_dispatch == nullptr) {
    prev_dispatch = NativeAllocatorDispatch();
  }

  if (!init_func(prev_dispatch, &gZygoteChild, options)) {
    error_log("%s: failed to enable malloc %s", getprogname(), prefix);
    ClearGlobalFunctions();
    return false;
  }

  // Do a pointer swap so that all of the functions become valid at once to
  // avoid any initialization order problems.
  atomic_store(&globals->default_dispatch_table, &globals->malloc_dispatch_table);
  if (!MallocLimitInstalled()) {
    atomic_store(&globals->current_dispatch_table, &globals->malloc_dispatch_table);
  }

  // Use atexit to trigger the cleanup function. This avoids a problem
  // where another atexit function is used to cleanup allocated memory,
  // but the finalize function was already called. This particular error
  // seems to be triggered by a zygote spawned process calling exit.
  int ret_value = __cxa_atexit(MallocFiniImpl, nullptr, nullptr);
  if (ret_value != 0) {
    // We don't consider this a fatal error.
    warning_log("failed to set atexit cleanup function: %d", ret_value);
  }
  return true;
}

static bool InstallHooks(libc_globals* globals, const char* options, const char* prefix,
                         const char* shared_lib) {
  void* impl_handle = LoadSharedLibrary(shared_lib, prefix, &globals->malloc_dispatch_table);
  if (impl_handle == nullptr) {
    return false;
  }

  if (!FinishInstallHooks(globals, options, prefix)) {
    dlclose(impl_handle);
    return false;
  }
  return true;
}

extern "C" const char* __scudo_get_stack_depot_addr();
extern "C" const char* __scudo_get_region_info_addr();
extern "C" const char* __scudo_get_ring_buffer_addr();
extern "C" size_t __scudo_get_ring_buffer_size();
extern "C" size_t __scudo_get_stack_depot_size();

// Initializes memory allocation framework once per process.
static void MallocInitImpl(libc_globals* globals) {
  char prop[PROP_VALUE_MAX];
  char* options = prop;

  MaybeInitGwpAsanFromLibc(globals);

#if defined(USE_SCUDO) && !__has_feature(hwaddress_sanitizer)
  __libc_shared_globals()->scudo_stack_depot = __scudo_get_stack_depot_addr();
  __libc_shared_globals()->scudo_region_info = __scudo_get_region_info_addr();
  __libc_shared_globals()->scudo_ring_buffer = __scudo_get_ring_buffer_addr();
  __libc_shared_globals()->scudo_ring_buffer_size = __scudo_get_ring_buffer_size();
  __libc_shared_globals()->scudo_stack_depot_size = __scudo_get_stack_depot_size();
#endif

  // Prefer malloc debug since it existed first and is a more complete
  // malloc interceptor than the hooks.
  bool hook_installed = false;
  if (CheckLoadMallocDebug(&options)) {
    hook_installed = InstallHooks(globals, options, kDebugPrefix, kDebugSharedLib);
  } else if (CheckLoadMallocHooks(&options)) {
    hook_installed = InstallHooks(globals, options, kHooksPrefix, kHooksSharedLib);
  }

  if (!hook_installed) {
    if (HeapprofdShouldLoad()) {
      HeapprofdInstallHooksAtInit(globals);
    }
  } else {
    // Record the fact that incompatible hooks are active, to skip any later
    // heapprofd signal handler invocations.
    HeapprofdRememberHookConflict();
  }
}

// Initializes memory allocation framework.
// This routine is called from __libc_init routines in libc_init_dynamic.cpp.
__BIONIC_WEAK_FOR_NATIVE_BRIDGE
__LIBC_HIDDEN__ void __libc_init_malloc(libc_globals* globals) {
  MallocInitImpl(globals);
}

// =============================================================================
// Functions to support dumping of native heap allocations using malloc debug.
// =============================================================================
bool GetMallocLeakInfo(android_mallopt_leak_info_t* leak_info) {
  void* func = gFunctions[FUNC_GET_MALLOC_LEAK_INFO];
  if (func == nullptr) {
    errno = ENOTSUP;
    return false;
  }
  reinterpret_cast<get_malloc_leak_info_func_t>(func)(
      &leak_info->buffer, &leak_info->overall_size, &leak_info->info_size,
      &leak_info->total_memory, &leak_info->backtrace_size);
  return true;
}

bool FreeMallocLeakInfo(android_mallopt_leak_info_t* leak_info) {
  void* func = gFunctions[FUNC_FREE_MALLOC_LEAK_INFO];
  if (func == nullptr) {
    errno = ENOTSUP;
    return false;
  }
  reinterpret_cast<free_malloc_leak_info_func_t>(func)(leak_info->buffer);
  return true;
}

bool WriteMallocLeakInfo(FILE* fp) {
  void* func = gFunctions[FUNC_WRITE_LEAK_INFO];
  bool written = false;
  if (func != nullptr) {
    written = reinterpret_cast<write_malloc_leak_info_func_t>(func)(fp);
  }

  if (!written) {
    fprintf(fp, "Native heap dump not available. To enable, run these commands (requires root):\n");
    fprintf(fp, "# adb shell stop\n");
    fprintf(fp, "# adb shell setprop libc.debug.malloc.options backtrace\n");
    fprintf(fp, "# adb shell start\n");
    errno = ENOTSUP;
  }
  return written;
}
// =============================================================================

// =============================================================================
// Exported for use by libmemunreachable.
// =============================================================================
extern "C" ssize_t malloc_backtrace(void* pointer, uintptr_t* frames, size_t frame_count) {
  void* func = gFunctions[FUNC_MALLOC_BACKTRACE];
  if (func == nullptr) {
    return 0;
  }
  return reinterpret_cast<malloc_backtrace_func_t>(func)(pointer, frames, frame_count);
}
// =============================================================================

#if !defined(__LP64__) && defined(__arm__)
// =============================================================================
// Old platform only functions that some old 32 bit apps are still using.
// See b/132175052.
// Only compile the functions for 32 bit arm, so that new apps do not use
// these functions.
// =============================================================================
extern "C" void get_malloc_leak_info(uint8_t** info, size_t* overall_size, size_t* info_size,
                                     size_t* total_memory, size_t* backtrace_size) {
  if (info == nullptr || overall_size == nullptr || info_size == nullptr ||
      total_memory == nullptr || backtrace_size == nullptr) {
    return;
  }

  *info = nullptr;
  *overall_size = 0;
  *info_size = 0;
  *total_memory = 0;
  *backtrace_size = 0;

  android_mallopt_leak_info_t leak_info = {};
  if (android_mallopt(M_GET_MALLOC_LEAK_INFO, &leak_info, sizeof(leak_info))) {
    *info = leak_info.buffer;
    *overall_size = leak_info.overall_size;
    *info_size = leak_info.info_size;
    *total_memory = leak_info.total_memory;
    *backtrace_size = leak_info.backtrace_size;
  }
}

extern "C" void free_malloc_leak_info(uint8_t* info) {
  android_mallopt_leak_info_t leak_info = { .buffer = info };
  android_mallopt(M_FREE_MALLOC_LEAK_INFO, &leak_info, sizeof(leak_info));
}
// =============================================================================
#endif

"""

```