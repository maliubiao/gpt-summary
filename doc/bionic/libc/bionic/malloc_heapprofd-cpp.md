Response:
Let's break down the thought process for analyzing the `malloc_heapprofd.cpp` file and generating the detailed response.

**1. Understanding the Core Goal:**

The first step is to grasp the fundamental purpose of this code. The file name itself, "malloc_heapprofd.cpp", strongly suggests it's related to heap profiling (`heapprofd`) integrated with the memory allocation system (`malloc`). The initial comments confirm this, outlining the steps involved in installing heapprofd hooks.

**2. Identifying Key Components and Concepts:**

Next, scan the code for recurring patterns, data structures, and important function names. This involves:

* **State Machine:**  The `MallocHeapprofdState` enum immediately stands out. This suggests a state machine governing the installation and lifecycle of the heapprofd hooks. Understanding the transitions between these states is crucial.
* **Synchronization:** The `MaybeModifyGlobals` template and the `gGlobalsMutateLock` mutex indicate the code deals with concurrency and needs to protect shared global state. The `atomic_` prefixes for variables like `gHeapprofdState` and `gHeapprofdHandle` reinforce this.
* **Dynamic Linking:** The inclusion of `<dlfcn.h>` and the use of `dlopen` and related functions clearly indicate that heapprofd functionality is loaded dynamically from a shared library (`heapprofd_client.so`).
* **Dispatch Tables:** References to `MallocDispatch` and `GetDefaultDispatchTable` point to the hook mechanism used to intercept `malloc` and related calls.
* **Property System:** The interaction with Android's property system (using `__system_property_get`) to determine if heapprofd should be enabled is important.
* **Signal Handling:** The presence of `HandleHeapprofdSignal` and the explanation of its use with signals is a key aspect.
* **Error Handling:**  The frequent use of `error_log` and `warning_log` indicates error reporting and potential issues.

**3. Deconstructing the State Machine:**

The diagram in the comments is extremely helpful. Analyze each state and the transitions between them. Pay attention to the conditions that trigger these transitions (e.g., signals, first `malloc` call). Understand the purpose of the "ephemeral hooks."

**4. Analyzing Functionality:**

Go through each major function and determine its role:

* **`HandleHeapprofdSignal()`:**  Entry point via signal. Its logic for installing ephemeral hooks and managing state transitions is central.
* **`HeapprofdShouldLoad()`:**  Determines whether heapprofd should be enabled based on system properties.
* **`HeapprofdRememberHookConflict()`:** Handles the case where other malloc hooking mechanisms are active.
* **`CommonInstallHooks()`:**  The core logic for loading the `heapprofd_client.so` and installing the actual heapprofd hooks.
* **`HeapprofdInstallHooksAtInit()`:**  Used during early initialization.
* **`InitHeapprofd()`:**  The thread function responsible for the actual heapprofd initialization.
* **`MallocInitHeapprofdHook()`:** The ephemeral hook that triggers the creation of the initialization thread.
* **`HeapprofdInitZygoteChildProfiling()`:** Handles enabling heapprofd in Zygote-forked processes.
* **`DispatchReset()`:**  Allows disabling heapprofd.
* **`HeapprofdMallopt()`:**  Provides a way to interact with heapprofd via `mallopt`.

**5. Relating to Android Functionality:**

Connect the functionality of each function to broader Android concepts:

* **System Properties:** Explain how system properties control system behavior, including enabling debugging features.
* **Zygote:**  Describe the role of Zygote in process creation and how heapprofd can be enabled for newly forked processes.
* **Signal Handling:** Explain how signals are used for inter-process communication and triggering specific actions.
* **Dynamic Linking:** Explain the role of the dynamic linker in loading shared libraries.
* **NDK/Framework Interaction:**  Trace the possible paths from application code to this low-level library.

**6. Detailing `libc` Function Implementations:**

For each `libc` function used:

* **`dlopen()`:** Explain its purpose in loading shared libraries.
* **`dlsym()`:**  (Implicitly used in `LoadSharedLibrary` and `InitSharedLibrary`) Explain its role in finding symbols in loaded libraries.
* **`pthread_create()`:** Explain thread creation.
* **`pthread_setname_np()`:** Explain setting thread names for debugging.
* **`pthread_detach()`:** Explain detaching threads.
* **`open()`/`read()`/`close()`:** Explain basic file operations used to read `/proc/self/cmdline`.
* **`memchr()`/`memrchr()`/`memcpy()`/`strcmp()`:**  Explain basic memory and string manipulation functions.
* **`__system_property_get()`:** Explain accessing Android system properties.
* **Atomic Operations:** Explain the use of `atomic_load`, `atomic_store`, and `atomic_compare_exchange_strong` for thread-safe access to shared variables.
* **Mutex Operations:** Explain the use of `pthread_mutex_lock` and `pthread_mutex_unlock` for mutual exclusion.

**7. Dynamic Linker Analysis:**

* **SO Layout:** Create a simple example of how `heapprofd_client.so` might be laid out in memory, highlighting the expected symbols.
* **Linking Process:** Describe the steps involved in resolving symbols and linking the shared library with `libc`.

**8. Logic Inference and Examples:**

* **Assumptions and Outputs:**  Provide concrete scenarios and predict the behavior of the code, especially regarding state transitions.
* **Common Errors:** Think about how a developer might misuse the system or encounter issues related to heapprofd.

**9. Tracing from Framework/NDK:**

Outline the typical call chain from an Android application or native code to the `malloc` functions in `libc`, demonstrating how the heapprofd hooks get involved.

**10. Frida Hooking:**

Provide practical Frida examples to demonstrate how to intercept key functions and observe the behavior of the heapprofd code.

**11. Structuring the Response:**

Organize the information logically using headings and bullet points to make it easy to read and understand. Use clear and concise language. Ensure all aspects of the prompt are addressed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus solely on the function implementations.
* **Correction:** Realize the importance of the state machine and the dynamic linking aspects.
* **Initial thought:**  Provide generic explanations of `libc` functions.
* **Correction:** Tailor the explanations to their specific use in this file.
* **Initial thought:**  Assume the reader has deep knowledge of Android internals.
* **Correction:** Provide more context and background information where necessary.
* **Initial thought:**  Focus heavily on code details.
* **Correction:** Balance code details with explanations of the overall system behavior and purpose.

By following these steps, iterating on the understanding, and structuring the response effectively, we can generate a comprehensive and informative analysis of the `malloc_heapprofd.cpp` file.
好的，我们来详细分析 `bionic/libc/bionic/malloc_heapprofd.cpp` 这个文件。

**功能概述**

`malloc_heapprofd.cpp` 的主要功能是实现一个名为 "heapprofd" 的堆内存分析工具的集成。Heapprofd 允许在 Android 设备上进行实时的堆内存使用情况分析，帮助开发者识别内存泄漏、过度分配等问题。

具体来说，这个文件负责以下任务：

1. **动态加载 heapprofd 客户端库 (`heapprofd_client.so`)：**  只有在需要进行堆内存分析时，才会加载这个库，避免不必要的性能开销。
2. **拦截 `malloc`、`free` 等内存分配相关的函数：** 通过修改 `libc` 的函数分发表 (`dispatch table`)，将这些函数的调用转发到 `heapprofd_client.so` 中实现的对应函数。
3. **管理 heapprofd 的状态：**  通过一个状态机 (`MallocHeapprofdState`) 来跟踪 heapprofd 的安装、激活和卸载过程。
4. **与 Android 系统属性交互：**  根据特定的系统属性（例如 `heapprofd.enable`）来决定是否启用 heapprofd。
5. **处理触发 heapprofd 的信号：**  当收到特定的信号时，例如由 `am profile` 命令发送的信号，会启动 heapprofd。
6. **支持 Zygote 进程的堆分析：**  在 Zygote fork 子进程时，可以根据配置启动 heapprofd。
7. **处理与其他内存调试工具的冲突：**  例如，如果 `malloc_debug` 或 `malloc hooks` 已经启用，heapprofd 将不会激活。

**与 Android 功能的关系及举例说明**

`malloc_heapprofd.cpp` 与 Android 的核心功能紧密相关，因为它直接影响着应用程序的内存管理。

* **内存分析和调试：**  Heapprofd 是 Android 提供的一种强大的内存分析工具，用于帮助开发者诊断内存问题。例如，开发者可以使用 `am profile proc start --sampling heapprofd <pid>` 命令来启动对特定进程的 heapprofd 分析。
* **性能优化：** 通过分析堆内存的使用情况，开发者可以发现内存分配上的瓶颈，从而进行性能优化。例如，可以识别出频繁分配和释放的小对象，并尝试使用对象池等技术来优化。
* **系统稳定性：**  及时发现和修复内存泄漏等问题可以提高系统的整体稳定性，防止应用程序崩溃或系统资源耗尽。

**libc 函数的实现细节**

这个文件中直接实现的 `libc` 函数不多，但它涉及到修改 `libc` 内部的函数分发表，从而间接地控制了 `malloc` 等函数的行为。

* **`MallocInitHeapprofdHook(size_t bytes)`:**
    * **功能：**  这是一个临时的 `malloc` 钩子函数，在 heapprofd 尚未完全初始化时被安装。当第一次调用 `malloc` 时，会执行这个函数。
    * **实现：**
        1. 使用 `MaybeModifyGlobals` 函数尝试获取全局锁，以确保线程安全地修改全局状态。
        2. 检查当前 heapprofd 的状态是否为 `kEphemeralHookInstalled` (临时钩子已安装)。
        3. 如果是，则将 heapprofd 的状态切换到 `kRemovingEphemeralHook` (正在移除临时钩子)。
        4. 恢复 `libc` 默认的 `malloc` 分发函数。这涉及到从 `gPreviousDefaultDispatchTable` 中恢复之前的分发表，并更新 `__libc_globals` 中的 `default_dispatch_table` 和 `current_dispatch_table`。
        5. 创建一个新的线程 `InitHeapprofd` 来执行真正的 heapprofd 初始化工作。
        6. 如果状态转换失败，则会打印警告日志，表明可能存在并发问题。
        7. 最后，调用之前保存的 `malloc` 函数（来自 `gPreviousDefaultDispatchTable` 或原生分配器）来实际分配内存。

* **`HeapprofdMallopt(int opcode, void* arg, size_t arg_size)`:**
    * **功能：**  响应 `mallopt` 函数的调用，提供与 heapprofd 相关的操作。
    * **实现：**
        1. 检查 `opcode` 是否为 `M_RESET_HOOKS`，这是用于重置 heapprofd 钩子的操作码。
        2. 如果是 `M_RESET_HOOKS`，则调用 `DispatchReset()` 函数来卸载 heapprofd 钩子。
        3. 如果 `opcode` 不是 `M_RESET_HOOKS`，则设置 `errno` 为 `ENOTSUP` (不支持的操作)，并返回 `false`。

**涉及 dynamic linker 的功能**

`malloc_heapprofd.cpp` 依赖 dynamic linker 来加载 `heapprofd_client.so` 库。

**SO 布局样本 (`heapprofd_client.so`)**

```
heapprofd_client.so:
    .init             // 初始化代码段
    .text             // 代码段
        heapprofd_malloc
        heapprofd_free
        heapprofd_calloc
        heapprofd_realloc
        // ... 其他 heapprofd 相关的函数
    .rodata           // 只读数据段
        // ...
    .data             // 数据段
        // ...
```

**链接的处理过程**

1. **`dlopen("heapprofd_client.so", ...)`:**  当需要启动 heapprofd 时，`CommonInstallHooks` 函数会调用 `dlopen` 来加载 `heapprofd_client.so`。Dynamic linker 会执行以下步骤：
   * 查找 `heapprofd_client.so` 库文件（通常在 `/system/lib` 或 `/vendor/lib` 等目录下）。
   * 将库加载到进程的地址空间。
   * 执行库的 `.init` 代码段中的初始化代码。
2. **`LoadSharedLibrary` 或 `InitSharedLibrary` (自定义函数)：** 这些函数内部通常会使用 `dlsym` 来查找 `heapprofd_client.so` 中导出的特定符号（函数地址），例如 `heapprofd_malloc`、`heapprofd_free` 等。
3. **修改 `malloc` 分发表：**  `FinishInstallHooks` 函数会将 `heapprofd_client.so` 中获取到的函数地址更新到 `libc` 的 `malloc` 分发表 (`__libc_globals.default_dispatch_table` 和 `__libc_globals.current_dispatch_table`) 中。这样，后续对 `malloc`、`free` 等函数的调用实际上会跳转到 `heapprofd_client.so` 中对应的 `heapprofd_malloc`、`heapprofd_free` 等函数。

**逻辑推理、假设输入与输出**

**场景 1：通过系统属性启用 heapprofd**

* **假设输入：** 系统属性 `heapprofd.enable` 设置为 "all" 或 `heapprofd.enable.<process_name>` 设置为非零值。
* **输出：**
    1. 当应用程序启动时，`HeapprofdShouldLoad()` 函数会返回 `true`。
    2. 如果是在 Zygote 中，`HeapprofdInitZygoteChildProfiling()` 会调用 `HandleHeapprofdSignal()`。
    3. `HandleHeapprofdSignal()` 会尝试安装 heapprofd 钩子。
    4. 最终，`heapprofd_client.so` 会被加载，并且 `malloc` 等函数的调用会被转发到该库。

**场景 2：通过信号触发 heapprofd**

* **假设输入：**  应用程序正在运行，并且收到了一个特定的信号（由 `am profile` 命令发送），信号的 `si_value` 指示需要启用 heapprofd。
* **输出：**
    1. 信号处理函数 `HandleHeapprofdSignal()` 被调用。
    2. 如果 heapprofd 尚未激活，则会执行加载和钩子安装过程，与场景 1 类似。

**场景 3：与其他内存调试工具冲突**

* **假设输入：**  系统属性 `debug.malloc.hook` 或 `LIBC_HOOKS_ENABLE` 被设置，导致 `malloc_debug` 或 generic hooks 已经启用。
* **输出：**
    1. `HeapprofdRememberHookConflict()` 函数会被调用。
    2. `gHeapprofdState` 会被设置为 `kIncompatibleHooks`。
    3. 后续尝试启用 heapprofd 的操作将会失败，并打印日志 "not enabling heapprofd, malloc_debug/malloc_hooks are enabled."。

**用户或编程常见的使用错误**

1. **忘记启用 heapprofd：** 开发者可能期望 heapprofd 自动运行，但实际上需要通过系统属性或 `am profile` 命令显式启用。
2. **与其他内存调试工具冲突：**  如果开发者同时启用了 `malloc_debug` 或其他内存钩子，heapprofd 将无法工作。需要先禁用其他工具。
3. **性能影响：**  Heapprofd 会带来一定的性能开销，不适合在性能敏感的生产环境长时间运行。开发者应该在分析完成后及时禁用。
4. **错误地假设 heapprofd 捕获所有内存分配：**  在 heapprofd 初始化完成之前发生的内存分配可能不会被捕获。临时钩子的机制是为了处理这个问题，但仍需注意。
5. **在信号处理程序中进行不安全的操作：**  `HandleHeapprofdSignal()` 是在信号处理程序中调用的，因此必须避免执行可能导致死锁或崩溃的不安全操作，例如分配内存或获取锁（除非使用原子操作）。

**Android framework 或 NDK 如何一步步到达这里**

1. **Framework 请求进行堆分析：**
   * 开发者在命令行使用 `am profile proc start --sampling heapprofd <pid>` 命令。
   * `ActivityManagerService` (AMS) 接收到这个请求。
   * AMS 向目标进程发送一个信号（例如 `SIGUSR1` 或 `SIGPROF`），并附带指示 heapprofd 的信息。

2. **进程收到信号并调用信号处理函数：**
   * 目标进程的 `libc` 接收到信号。
   * 注册的信号处理函数（通常在 `bionic/libc/arch-common/bionic/signal_handler.cpp` 中）被调用。
   * 这个信号处理函数会检查信号的类型和附加信息。如果指示需要启用 heapprofd，则会调用 `HandleHeapprofdSignal()` 函数。

3. **`HandleHeapprofdSignal()` 执行 heapprofd 初始化流程：**
   * 检查当前 heapprofd 的状态。
   * 如果需要，加载 `heapprofd_client.so` 库。
   * 修改 `libc` 的 `malloc` 分发表，将内存分配相关的函数调用转发到 `heapprofd_client.so` 中的实现。

4. **NDK 代码调用 `malloc` 等函数：**
   * 当 NDK 代码（例如使用 `new` 或 `malloc`）分配内存时，实际调用的是 `libc` 提供的 `malloc` 函数。
   * 由于 heapprofd 的钩子已经安装，这些调用会被转发到 `heapprofd_client.so` 中的 `heapprofd_malloc` 函数。
   * `heapprofd_malloc` 函数会记录内存分配的信息，并将调用转发回原始的 `malloc` 实现（如果需要）。

**Frida Hook 示例调试这些步骤**

以下是一些使用 Frida 来 hook 和观察 `malloc_heapprofd.cpp` 相关函数的示例：

```javascript
// Hook HandleHeapprofdSignal 函数
Interceptor.attach(Module.findExportByName("libc.so", "HandleHeapprofdSignal"), {
  onEnter: function (args) {
    console.log("HandleHeapprofdSignal called");
  },
  onLeave: function (retval) {
    console.log("HandleHeapprofdSignal returned");
  }
});

// Hook MallocInitHeapprofdHook 函数
Interceptor.attach(Module.findExportByName("libc.so", "MallocInitHeapprofdHook"), {
  onEnter: function (args) {
    console.log("MallocInitHeapprofdHook called, size =", args[0]);
  },
  onLeave: function (retval) {
    console.log("MallocInitHeapprofdHook returned, address =", retval);
  }
});

// Hook dlopen 函数，观察 heapprofd_client.so 的加载
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter: function (args) {
    const filename = args[0].readCString();
    if (filename.includes("heapprofd_client.so")) {
      console.log("dlopen called with:", filename);
    }
  },
  onLeave: function (retval) {
    if (this.context.filename && this.context.filename.includes("heapprofd_client.so")) {
      console.log("dlopen returned handle:", retval);
    }
  }
});

// Hook 修改 malloc 分发表的关键函数 (假设 LoadSharedLibrary 中会调用 __libc_globals.mutate)
const mutate_addr = Module.findExportByName("libc.so", "__libc_globals_mutate");
if (mutate_addr) {
  Interceptor.attach(mutate_addr, {
    onEnter: function (args) {
      console.log("__libc_globals_mutate called");
      // 可以进一步分析传递给 mutate 的 lambda 函数
    },
    onLeave: function (retval) {
      console.log("__libc_globals_mutate returned");
    }
  });
}

// 读取 gHeapprofdState 的值
function getHeapprofdState() {
  const state_addr = Module.findGlobalSymbol("gHeapprofdState").address;
  return Memory.readU8(state_addr);
}

// 每隔一段时间打印 heapprofd 的状态
setInterval(function() {
  console.log("Current gHeapprofdState:", getHeapprofdState());
}, 1000);
```

**使用步骤：**

1. 将以上 JavaScript 代码保存为一个 `.js` 文件（例如 `heapprofd_hook.js`）。
2. 使用 Frida 连接到目标 Android 进程：`frida -U -f <package_name> -l heapprofd_hook.js --no-pause` 或 `frida -U <process_name> -l heapprofd_hook.js`.
3. 执行触发 heapprofd 的操作，例如使用 `am profile` 命令。
4. 观察 Frida 的输出，查看 hook 函数的调用和 `gHeapprofdState` 的变化，从而理解 heapprofd 的初始化过程。

通过这些分析和示例，希望能帮助你更深入地理解 `bionic/libc/bionic/malloc_heapprofd.cpp` 的功能和实现细节。

Prompt: 
```
这是目录为bionic/libc/bionic/malloc_heapprofd.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#if defined(LIBC_STATIC)
#error This file should not be compiled for static targets.
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <platform/bionic/malloc.h>
#include <private/bionic_config.h>
#include <private/bionic_malloc_dispatch.h>
#include <sys/system_properties.h>

#include "gwp_asan_wrappers.h"
#include "malloc_common.h"
#include "malloc_common_dynamic.h"
#include "malloc_heapprofd.h"
#include "malloc_limit.h"

// Installing heapprofd hooks is a multi step process, as outlined below.
//
// The incremental hooking and a dedicated task thread are used since we cannot
// do heavy work within a signal handler, or when blocking a malloc invocation.
//
// +--->+-------------+------------------+
// | +->+kInitialState+----------------+ |  malloc functions are not intercepted in any way.
// | |  +-------+-----+                | |
// | |          | HandleHeapprofd      | |
// | |          v Signal()             | |
// | |  +-------+----------------+     | |  currently installing the ephemeral hooks.
// | |  |kInstallingEphemeralHook|<--+ | |
// | |  +-------+----------------+   | | |
// | |          |                    | | |
// | |          v                    | | |
// | |  +-------+---------------+    | | |  ephemeral hooks are installed. on the first call to
// | |  |kEphemeralHookInstalled|    | | |  malloc these hooks spawn a thread that installs the
// | |  +-------+---------------+    A B C  heapprofd hooks.
// | |          | MallocInit         | | |
// | |          v HeapprofdHook ()   | | |
// | |  +-------+--------------+     | | |  first call to malloc happened. the hooks are reset to
// | +--|kRemovingEphemeralHook|     | | |  kInitialState.
// |    +----------------------+     | | |
// |                                 | | |
// |                                 | | |
// |    +---------------+            | | |  currently installing the heapprofd hook
// |    |kInstallingHook|<-----------|-+ |
// |    +-------+-------+            |   |
// |            |                    |   |
// |            v                    |   |
// |    +-------+------+             |   |  heapprofd hooks are installed. these forward calls to
// |    |kHookInstalled|-------------+   |  malloc / free / etc. to heapprofd_client.so.
// |    +-------+------+                 |
// |            | DispatchReset()        |
// |            v                        |
// |    +-------+---------+              |  currently resetting the hooks to default.
// |----+kUninstallingHook|              |
//      +-----------------+              |
//                                       |
//                                       |
//      +------------------+             |  malloc debug / malloc hooks are active. these take
//      |kIncompatibleHooks+<------------+  precendence over heapprofd, so heapprofd will not get
//      +------------------+                enabled. this is a terminal state.
//
//
// A) HandleHeapprofdSignal()
// B) HeapprofdInstallHooksAtInit() / InitHeapprofd()
// C) HeapprofdRememberHookConflict()
enum MallocHeapprofdState : uint8_t {
  kInitialState,
  kInstallingEphemeralHook,
  kEphemeralHookInstalled,
  kRemovingEphemeralHook,
  kInstallingHook,
  kHookInstalled,
  kUninstallingHook,
  kIncompatibleHooks
};

enum ModifyGlobalsMode {
  kWithLock,   // all calls to MaybeModifyGlobals with kWithLock will serialise. they can fail
               // due to a concurrent call with kWithoutLock.
  kWithoutLock // calls to MaybeModifyGlobals with kWithoutLock do not serialise. they can fail
               // due to concurrent calls with kWithoutLock or kWithLock.
};

// Provide mutual exclusion so no two threads try to modify the globals at the same time.
template <typename Fn>
bool MaybeModifyGlobals(ModifyGlobalsMode mode, Fn f) {
  bool success = false;
  if (mode == kWithLock) {
    pthread_mutex_lock(&gGlobalsMutateLock);
  }
  // As we have grabbed the mutex, the following condition should always hold, except
  // if we are currently running HandleHeapprofdSignal.
  if (!atomic_exchange(&gGlobalsMutating, true)) {
    f();
    success = true;
    atomic_store(&gGlobalsMutating, false);
  } else {
    error_log("%s: heapprofd client: concurrent modification.", getprogname());
  }
  if (mode == kWithLock) {
    pthread_mutex_unlock(&gGlobalsMutateLock);
  }
  return success;
}

extern "C" void* MallocInitHeapprofdHook(size_t);

static constexpr char kHeapprofdSharedLib[] = "heapprofd_client.so";
static constexpr char kHeapprofdPrefix[] = "heapprofd";
static constexpr char kHeapprofdPropertyEnable[] = "heapprofd.enable";

constexpr char kHeapprofdProgramPropertyPrefix[] = "heapprofd.enable.";
constexpr size_t kHeapprofdProgramPropertyPrefixSize = sizeof(kHeapprofdProgramPropertyPrefix) - 1;
constexpr size_t kMaxCmdlineSize = 512;

// The handle returned by dlopen when previously loading the heapprofd
// hooks. nullptr if shared library has not been already been loaded.
static _Atomic (void*) gHeapprofdHandle = nullptr;
static _Atomic MallocHeapprofdState gHeapprofdState = kInitialState;

static bool GetHeapprofdProgramProperty(char* data, size_t size) {
  if (size < kHeapprofdProgramPropertyPrefixSize) {
    error_log("%s: Overflow constructing heapprofd property", getprogname());
    return false;
  }
  memcpy(data, kHeapprofdProgramPropertyPrefix, kHeapprofdProgramPropertyPrefixSize);

  int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    error_log("%s: Failed to open /proc/self/cmdline", getprogname());
    return false;
  }
  char cmdline[kMaxCmdlineSize];
  ssize_t rd = read(fd, cmdline, sizeof(cmdline) - 1);
  close(fd);
  if (rd == -1) {
    error_log("%s: Failed to read /proc/self/cmdline", getprogname());
    return false;
  }
  cmdline[rd] = '\0';
  char* first_arg = static_cast<char*>(memchr(cmdline, '\0', rd));
  if (first_arg == nullptr) {
    error_log("%s: Overflow reading cmdline", getprogname());
    return false;
  }
  // For consistency with what we do with Java app cmdlines, trim everything
  // after the @ sign of the first arg.
  char* first_at = static_cast<char*>(memchr(cmdline, '@', rd));
  if (first_at != nullptr && first_at < first_arg) {
    *first_at = '\0';
    first_arg = first_at;
  }

  char* start = static_cast<char*>(memrchr(cmdline, '/', first_arg - cmdline));
  if (start == first_arg) {
    // The first argument ended in a slash.
    error_log("%s: cmdline ends in /", getprogname());
    return false;
  } else if (start == nullptr) {
    start = cmdline;
  } else {
    // Skip the /.
    start++;
  }

  size_t name_size = static_cast<size_t>(first_arg - start);
  if (name_size >= size - kHeapprofdProgramPropertyPrefixSize) {
    error_log("%s: overflow constructing heapprofd property.", getprogname());
    return false;
  }
  // + 1 to also copy the trailing null byte.
  memcpy(data + kHeapprofdProgramPropertyPrefixSize, start, name_size + 1);
  return true;
}

// Runtime triggering entry-point. Two possible call sites:
// * when receiving a profiling signal with a si_value indicating heapprofd.
// * when a Zygote child is marking itself as profileable, and there's a
//   matching profiling request for this process (in which case heapprofd client
//   is loaded synchronously).
// In both cases, the caller is responsible for verifying that the process is
// considered profileable.

// Previously installed default dispatch table, if it exists. This is used to
// load heapprofd properly when GWP-ASan was already installed. If GWP-ASan was
// already installed, heapprofd will take over the dispatch table, but will use
// GWP-ASan as the backing dispatch. Writes to this variable is atomically
// protected by MaybeModifyGlobals.
// Reads are not protected, so this is atomic. We cannot fail the call in
// MallocInitHeapprofdHook.
static _Atomic (const MallocDispatch*) gPreviousDefaultDispatchTable = nullptr;
static MallocDispatch gEphemeralDispatch;

void HandleHeapprofdSignal() {
  if (atomic_load(&gHeapprofdState) == kIncompatibleHooks) {
    error_log("%s: not enabling heapprofd, malloc_debug/malloc_hooks are enabled.", getprogname());
    return;
  }

  // We cannot grab the mutex here, as this is used in a signal handler.
  MaybeModifyGlobals(kWithoutLock, [] {
    MallocHeapprofdState expected = kInitialState;
    // If hooks are already installed, we still want to install ephemeral hooks to retrigger
    // heapprofd client initialization.
    MallocHeapprofdState expected2 = kHookInstalled;
    if (atomic_compare_exchange_strong(&gHeapprofdState, &expected,
          kInstallingEphemeralHook)) {
      const MallocDispatch* default_dispatch = GetDefaultDispatchTable();

      // Below, we initialize heapprofd lazily by redirecting libc's malloc() to
      // call MallocInitHeapprofdHook, which spawns off a thread and initializes
      // heapprofd. During the short period between now and when heapprofd is
      // initialized, allocations may need to be serviced. There are three
      // possible configurations:

      if (DispatchIsGwpAsan(default_dispatch)) {
        //  1. GWP-ASan was installed. We should use GWP-ASan for everything but
        //  malloc() in the interim period before heapprofd is properly
        //  installed. After heapprofd is finished installing, we will use
        //  GWP-ASan as heapprofd's backing allocator to allow heapprofd and
        //  GWP-ASan to coexist.
        atomic_store(&gPreviousDefaultDispatchTable, default_dispatch);
        gEphemeralDispatch = *default_dispatch;
      } else {
        // Either,
        // 2. No malloc hooking has been done (heapprofd, GWP-ASan, etc.). In
        // this case, everything but malloc() should come from the system
        // allocator.
        //
        // or,
        //
        // 3. It may be possible at this point in time that heapprofd is
        // *already* the default dispatch, and when it was initialized there
        // was no default dispatch installed. As such we don't want to use
        // heapprofd as the backing store for itself (otherwise infinite
        // recursion occurs). We will use the system allocator functions. Note:
        // We've checked that no other malloc interceptors are being used by
        // validating `gHeapprofdIncompatibleHooks` above, so we don't need to
        // worry about that case here.
        atomic_store(&gPreviousDefaultDispatchTable, nullptr);
        gEphemeralDispatch = *NativeAllocatorDispatch();
      }
    } else if (expected == kEphemeralHookInstalled) {
      // Nothing to do here. The ephemeral hook was installed, but
      // MallocInitHeapprofdHook() was never called. Since the ephemeral hook
      // is already there, no need to reinstall it.
      return;
    } else if (atomic_compare_exchange_strong(&gHeapprofdState, &expected2,
                                              kInstallingEphemeralHook)) {
      // if we still have hook installed, we can reuse the previous
      // decision. THIS IS REQUIRED FOR CORRECTNESS, because otherwise the
      // following can happen
      // 1. Assume DispatchIsGwpAsan(default_dispatch)
      // 2. This function is ran, sets gPreviousDefaultDispatchTable to
      //    GWP ASan.
      // 3. The sessions ends, DispatchReset FAILS due to a race. Now
      //    heapprofd hooks are default dispatch.
      // 4. We re-enter this function later. If we did NOT look at the
      //    previously recorded gPreviousDefaultDispatchTable, we would
      //    incorrectly reach case 3. below.
      // 5. The session ends, DispatchReset now resets the hooks to the
      //    system allocator. This is incorrect.
      const MallocDispatch* prev_dispatch =
        atomic_load(&gPreviousDefaultDispatchTable);
      gEphemeralDispatch = prev_dispatch ? *prev_dispatch : *NativeAllocatorDispatch();
    } else {
      error_log("%s: heapprofd: failed to transition kInitialState -> kInstallingEphemeralHook. "
          "current state (possible race): %d", getprogname(), expected2);
      return;
    }
    // Now, replace the malloc function so that the next call to malloc() will
    // initialize heapprofd.
    gEphemeralDispatch.malloc = MallocInitHeapprofdHook;

    // And finally, install these new malloc-family interceptors.
    __libc_globals.mutate([](libc_globals* globals) {
      atomic_store(&globals->default_dispatch_table, &gEphemeralDispatch);
      if (!MallocLimitInstalled()) {
        atomic_store(&globals->current_dispatch_table, &gEphemeralDispatch);
      }
    });
    atomic_store(&gHeapprofdState, kEphemeralHookInstalled);
  });
  // Otherwise, we're racing against malloc_limit's enable logic (at most once
  // per process, and a niche feature). This is highly unlikely, so simply give
  // up if it does happen.
}

bool HeapprofdShouldLoad() {
  // First check for heapprofd.enable. If it is set to "all", enable
  // heapprofd for all processes. Otherwise, check heapprofd.enable.${prog},
  // if it is set and not 0, enable heap profiling for this process.
  char property_value[PROP_VALUE_MAX];
  if (__system_property_get(kHeapprofdPropertyEnable, property_value) == 0) {
    return false;
  }
  if (strcmp(property_value, "all") == 0) {
    return true;
  }

  char program_property[kHeapprofdProgramPropertyPrefixSize + kMaxCmdlineSize];
  if (!GetHeapprofdProgramProperty(program_property,
                                   sizeof(program_property))) {
    return false;
  }
  if (__system_property_get(program_property, property_value) == 0) {
    return false;
  }
  return property_value[0] != '\0';
}

void HeapprofdRememberHookConflict() {
  atomic_store(&gHeapprofdState, kIncompatibleHooks);
}

static void CommonInstallHooks(libc_globals* globals) {
  void* impl_handle = atomic_load(&gHeapprofdHandle);
  if (impl_handle == nullptr) {
    impl_handle = LoadSharedLibrary(kHeapprofdSharedLib, kHeapprofdPrefix, &globals->malloc_dispatch_table);
    if (impl_handle == nullptr) {
      return;
    }
    atomic_store(&gHeapprofdHandle, impl_handle);
  } else if (!InitSharedLibrary(impl_handle, kHeapprofdSharedLib, kHeapprofdPrefix, &globals->malloc_dispatch_table)) {
    return;
  }

  FinishInstallHooks(globals, nullptr, kHeapprofdPrefix);
}

void HeapprofdInstallHooksAtInit(libc_globals *globals) {
  // Before we set the new default_dispatch_table in FinishInstallHooks, save
  // the previous dispatch table. If DispatchReset() gets called later, we want
  // to be able to restore the dispatch. We're still under
  // MaybeModifyGlobals locks at this point.
  atomic_store(&gPreviousDefaultDispatchTable, GetDefaultDispatchTable());
  MaybeModifyGlobals(kWithoutLock, [globals] {
    MallocHeapprofdState expected = kInitialState;
    if (atomic_compare_exchange_strong(&gHeapprofdState, &expected, kInstallingHook)) {
      CommonInstallHooks(globals);
      atomic_store(&gHeapprofdState, kHookInstalled);
    } else {
      error_log("%s: heapprofd: failed to transition kInitialState -> kInstallingHook. "
          "current state (possible race): %d", getprogname(), expected);
    }
  });
}

static void* InitHeapprofd(void*) {
  MaybeModifyGlobals(kWithLock, [] {
    MallocHeapprofdState expected = kInitialState;
    if (atomic_compare_exchange_strong(&gHeapprofdState, &expected, kInstallingHook)) {
      __libc_globals.mutate([](libc_globals* globals) {
        CommonInstallHooks(globals);
      });
      atomic_store(&gHeapprofdState, kHookInstalled);
    } else {
      error_log("%s: heapprofd: failed to transition kInitialState -> kInstallingHook. "
          "current state (possible race): %d", getprogname(), expected);
    }
  });
  return nullptr;
}

extern "C" void* MallocInitHeapprofdHook(size_t bytes) {
  MaybeModifyGlobals(kWithLock, [] {
    MallocHeapprofdState expected = kEphemeralHookInstalled;
    if (atomic_compare_exchange_strong(&gHeapprofdState, &expected, kRemovingEphemeralHook)) {
      __libc_globals.mutate([](libc_globals* globals) {
        const MallocDispatch* previous_dispatch = atomic_load(&gPreviousDefaultDispatchTable);
        atomic_store(&globals->default_dispatch_table, previous_dispatch);
        if (!MallocLimitInstalled()) {
          atomic_store(&globals->current_dispatch_table, previous_dispatch);
        }
      });
      atomic_store(&gHeapprofdState, kInitialState);

      pthread_t thread_id;
      if (pthread_create(&thread_id, nullptr, InitHeapprofd, nullptr) != 0) {
        error_log("%s: heapprofd: failed to pthread_create.", getprogname());
      } else if (pthread_setname_np(thread_id, "heapprofdinit") != 0) {
        error_log("%s: heapprod: failed to pthread_setname_np", getprogname());
      } else if (pthread_detach(thread_id) != 0) {
        error_log("%s: heapprofd: failed to pthread_detach", getprogname());
      }
    } else {
      warning_log("%s: heapprofd: could not transition kEphemeralHookInstalled -> "
          "kRemovingEphemeralHook. current state (possible race): %d. this can be benign "
          "if two threads try this transition at the same time", getprogname(),
          expected);
    }
  });
  // If we had a previous dispatch table, use that to service the allocation,
  // otherwise fall back to the native allocator.
  // This could be modified by a concurrent HandleHeapprofdSignal, but that is
  // benign as we will dispatch to the ephemeral handler, which will then dispatch
  // to the underlying one.
  const MallocDispatch* previous_dispatch = atomic_load(&gPreviousDefaultDispatchTable);
  if (previous_dispatch) {
    return previous_dispatch->malloc(bytes);
  }
  return NativeAllocatorDispatch()->malloc(bytes);
}

bool HeapprofdInitZygoteChildProfiling() {
  // Conditionally start "from startup" profiling.
  if (HeapprofdShouldLoad()) {
    // Directly call the signal handler codepath (properly protects against
    // concurrent invocations).
    HandleHeapprofdSignal();
  }
  return true;
}

static bool DispatchReset() {
  if (atomic_load(&gHeapprofdState) == kInitialState) {
    return true;
  }

  bool success = false;
  MaybeModifyGlobals(kWithLock, [&success] {
    MallocHeapprofdState expected = kHookInstalled;

    if(atomic_compare_exchange_strong(&gHeapprofdState, &expected, kUninstallingHook)){
      __libc_globals.mutate([](libc_globals* globals) {
        const MallocDispatch* previous_dispatch = atomic_load(&gPreviousDefaultDispatchTable);
        atomic_store(&globals->default_dispatch_table, previous_dispatch);
        if (!MallocLimitInstalled()) {
          atomic_store(&globals->current_dispatch_table, previous_dispatch);
        }
      });
      atomic_store(&gHeapprofdState, kInitialState);
      success = true;
    } else {
      error_log("%s: heapprofd: failed to transition kHookInstalled -> kUninstallingHook. "
          "current state (possible race): %d", getprogname(),
          expected);
    }
  });
  if (!success) {
    errno = EAGAIN;
  }
  return success;
}

bool HeapprofdMallopt(int opcode, void* arg, size_t arg_size) {
  if (opcode == M_RESET_HOOKS) {
    if (arg != nullptr || arg_size != 0) {
      errno = EINVAL;
      return false;
    }
    return DispatchReset();
  }
  errno = ENOTSUP;
  return false;
}

"""

```