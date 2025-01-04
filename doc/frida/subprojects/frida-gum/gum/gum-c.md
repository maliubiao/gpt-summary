Response:
Let's break down the thought process for analyzing the `gum.c` file.

1. **Understand the Goal:** The request asks for a functional breakdown of `gum.c`, its relation to reverse engineering, its use of low-level OS features, examples of logical reasoning (including hypothetical input/output), common usage errors, and how a user might reach this code.

2. **Initial Code Scan (Keywords and Structure):**  I'd start by quickly scanning the code for key terms and overall structure. Keywords like `Copyright`, `#include`, `static`, `void`, function names (especially those starting with `gum_`), and conditional compilation (`#ifdef`) give immediate clues. The structure reveals it's a C file with function definitions and some global variables.

3. **Identify Core Functionality (Top-Down and Bottom-Up):**

   * **Top-Down:** Looking at the prominent functions like `gum_init`, `gum_shutdown`, `gum_deinit`, `gum_init_embedded`, `gum_deinit_embedded`, and functions related to forking suggests a lifecycle management component for the Gum library. The presence of `gum_interceptor_obtain` hints at an interception/hooking mechanism, a core feature of dynamic instrumentation.

   * **Bottom-Up:**  The `#include` directives point to dependencies and functionalities. `gum-init.h`, `gumexceptorbackend.h`, `guminterceptor-priv.h`, `gummemory-priv.h`, `gumprintf.h`, and `gumtls-priv.h` indicate modules for initialization, exception handling, interception, memory management, formatted printing, and thread-local storage. Standard C libraries like `stdlib.h`, `string.h`, and platform-specific headers (`windows.h`, `dlfcn.h`, `android/log.h`, etc.) further refine the understanding.

4. **Categorize Functionalities:** Based on the initial scan and deeper dives into specific sections, I would start categorizing the functionalities:

   * **Initialization/Shutdown:** `gum_init`, `gum_shutdown`, `gum_deinit`, `gum_init_embedded`, `gum_deinit_embedded`. These manage the library's lifecycle.
   * **Interception/Hooking:**  Presence of `GumInterceptor`, `gum_interceptor_obtain`, `gum_interceptor_ignore_current_thread`, `gum_interceptor_unignore_current_thread`. This is a major RE-related aspect.
   * **Memory Management:**  References to `gum_malloc`, `gum_free`, `gum_calloc`, potentially the `ffi_mem_callbacks`.
   * **Threading:** Functions related to thread initialization, realization, disposal, and finalization, along with `gum_process_get_current_thread_id`.
   * **Cloaking:** Functions like `gum_cloak_add_range`, `gum_cloak_remove_range`, `gum_cloak_add_thread`, `gum_cloak_remove_thread`, `gum_cloak_add_file_descriptor`, `gum_cloak_remove_file_descriptor`.
   * **Logging:** `gum_on_log_message` and its platform-specific implementations.
   * **CPU Feature Detection:** `gum_query_cpu_features`, `gum_do_query_cpu_features`, and platform-specific implementations using CPUID instructions.
   * **Fork Handling:** `gum_prepare_to_fork`, `gum_recover_from_fork_in_parent`, `gum_recover_from_fork_in_child`.
   * **Error Handling:**  `G_DEFINE_QUARK (gum-error-quark, gum_error)` and `gum_panic`.
   * **Destructors:** `_gum_register_early_destructor`, `_gum_register_destructor`.

5. **Connect to Reverse Engineering:**  Once the core functionalities are identified, the connection to reverse engineering becomes clearer:

   * **Interception:** The most direct connection. Frida's ability to intercept function calls is enabled by this module.
   * **Memory Management Awareness:**  Understanding how Frida allocates and frees memory is crucial for avoiding memory leaks or corruptions during instrumentation.
   * **Thread Awareness:**  Instrumenting multi-threaded applications requires careful handling of thread contexts, which this code seems to manage.
   * **Cloaking:** This feature is designed to hide Frida's presence, a common requirement in certain reverse engineering scenarios.

6. **Identify Low-Level OS Interactions:** Look for platform-specific code and interactions with system APIs:

   * **Linux:** `dlfcn.h` for dynamic linking (`dlopen`), interaction with `/proc/cpuinfo`.
   * **Android:** `android/log.h` for logging.
   * **macOS (Darwin):** `CoreFoundation/CoreFoundation.h` for logging, `dlfcn.h` for dynamic linking, interactions with `mach_task_self()`.
   * **Windows:** `windows.h` for debugging output (`OutputDebugStringW`) and potentially memory management debugging (`_CrtSetBreakAlloc`, etc.).
   * **General:**  Thread management primitives provided by the underlying OS (though often abstracted by GLib).

7. **Logical Reasoning and Examples:** For this, focus on specific functions and their potential behavior:

   * **`gum_init`:**  Input: None. Output: Internal state changes (e.g., `gum_initialized` becomes `TRUE`).
   * **`gum_cloak_add_range` (hypothetical):** Input: A `GumMemoryRange` representing memory to hide. Output: Internal data structures are updated to track the cloaked range. A reverse engineer might use this to hide Frida's own memory regions.
   * **`gum_on_log_message`:** Input: Log domain, log level, message. Output: Platform-specific logging (stdout, stderr, system logs).

8. **Common User Errors:** Think about how a *programmer* using the Frida API (which uses this underlying code) might make mistakes:

   * **Incorrectly managing the Frida environment:**  Forgetting to call `gum_init` or `gum_deinit` at appropriate times.
   * **Memory leaks:**  While `gum.c` manages its own internal memory, a user's instrumentation code might introduce leaks that could be indirectly related to Frida's memory management.
   * **Thread safety issues:**  If instrumentation code isn't thread-safe, it could lead to crashes or unexpected behavior, and `gum.c`'s thread management becomes relevant in the debugging process.

9. **User Journey to `gum.c`:** Consider the steps a user takes to trigger the execution of code within `gum.c`:

   * **Writing a Frida script:**  The user starts by writing JavaScript code using the Frida API.
   * **Attaching to a process:** The script targets a running process (or spawns a new one).
   * **Using Frida API functions:**  The script uses functions like `Interceptor.attach`, `Memory.read*`, `Memory.write*`, etc. These JavaScript API calls are eventually translated into calls to the underlying C/C++ code of Frida, including functions in `gum.c`.
   * **Potential error scenarios:** If the script causes a crash within Frida's core, or if Frida's internal logging is enabled, the execution flow might lead to functions in `gum.c` like `gum_panic` or `gum_on_log_message`.

10. **Refine and Organize:**  Finally, organize the gathered information into a clear and structured answer, addressing each part of the original request. Use headings, bullet points, and code examples (even if hypothetical) to illustrate the points. Double-check for accuracy and completeness. Ensure the language is precise and avoids jargon where possible, or explains it clearly.
好的，让我们详细分析一下 `frida/subprojects/frida-gum/gum/gum.c` 这个文件。从文件名和目录结构来看，`gum.c` 很可能是 Frida 的 Gum 库的核心组件之一。Gum 负责底层的动态 instrumentation功能。

**文件功能概述：**

`gum.c` 文件是 Frida Gum 库的初始化、配置、资源管理和一些核心功能的入口点。它负责以下主要职责：

1. **库的初始化与反初始化:**
   - `gum_init()`: 初始化 Gum 库，包括内存管理、线程局部存储 (TLS)、拦截器等子系统的初始化。
   - `gum_shutdown()`: 执行早期析构函数，进行一些清理工作。
   - `gum_deinit()`: 反初始化 Gum 库，清理 TLS、拦截器等资源。
   - `gum_init_embedded()` 和 `gum_deinit_embedded()`:  用于嵌入式环境的初始化和反初始化，例如在没有完整操作系统支持的环境中。

2. **全局配置与管理:**
   - 管理全局的析构函数列表 (`gum_early_destructors`, `gum_final_destructors`)，在库的生命周期结束时执行清理操作。
   - 提供注册析构函数的接口 (`_gum_register_early_destructor`, `_gum_register_destructor`)。

3. **线程管理集成:**
   - 集成 GLib 的线程管理功能 (如果启用 `HAVE_FRIDA_GLIB`)，例如在线程创建、销毁时执行特定的回调函数 (`gum_on_thread_init`, `gum_on_thread_realize`, `gum_on_thread_dispose`, `gum_on_thread_finalize`)。
   - 使用线程局部存储 (`gum_internal_thread_details_key`) 来存储每个线程特定的信息。
   - 提供忽略/取消忽略特定线程的拦截功能 (`gum_interceptor_ignore_current_thread`, `gum_interceptor_unignore_current_thread`)。

4. **文件描述符管理集成:**
   - 集成 GLib 的文件描述符管理功能 (如果启用 `HAVE_FRIDA_GLIB`)，在文件描述符打开和关闭时执行回调函数 (`gum_on_fd_opened`, `gum_on_fd_closed`)。

5. **日志记录:**
   - 提供默认的日志处理函数 `gum_on_log_message`，根据不同的平台 (Windows, Android, Darwin, Linux) 使用不同的方式输出日志信息。

6. **CPU 特性检测:**
   - `gum_query_cpu_features()`:  检测当前 CPU 支持的特性 (例如 AVX2, CET-SS, ARM 的 NEON 等)。这对于优化代码生成和选择合适的指令集非常重要。

7. **内存管理 (间接):**
   - 虽然 `gum.c` 本身可能不直接分配和释放大量内存，但它配置了底层的内存分配器 (通过 `ffi_set_mem_callbacks` 和 GLib 的内存虚拟表)，并可能引用了内部堆 (`gum_internal_heap_ref`, `gum_internal_heap_unref`)。

8. **进程 Fork 支持:**
   - 提供在进程 `fork()` 前后进行处理的函数 (`gum_prepare_to_fork`, `gum_recover_from_fork_in_parent`, `gum_recover_from_fork_in_child`)，以确保在 `fork()` 之后子进程能够正确地进行 instrumentation。

9. **错误处理:**
   - 定义了 Gum 库的错误域 (`gum-error-quark`)。
   - 提供了 `gum_panic()` 函数用于抛出致命错误。

10. **地址管理:**
    - 定义了 `GumAddress` 类型和相关的复制和释放函数 (`gum_address_copy`, `gum_address_free`)，用于表示内存地址。

11. **"Cloaking" 功能:**
    - 提供了添加和移除内存范围和线程的 "cloaking" 功能，这可能用于隐藏 Frida 的某些操作或数据，防止被目标进程检测到。相关的函数有 `gum_cloak_add_range`, `gum_cloak_remove_range`, `gum_cloak_add_thread`, `gum_cloak_remove_thread`, `gum_cloak_add_file_descriptor`, `gum_cloak_remove_file_descriptor`。

**与逆向方法的关系及举例说明：**

`gum.c` 是 Frida 动态 instrumentation 能力的基础，与逆向方法紧密相关：

* **代码注入与执行:**  Frida 通过 Gum 提供的底层机制，可以将 JavaScript 代码注入到目标进程中执行。`gum.c` 中的初始化过程为后续的代码注入和执行奠定了基础。
* **函数 Hook (拦截):**  `gum.c` 负责初始化和管理拦截器 (`GumInterceptor`)。拦截器是 Frida 最核心的特性之一，允许逆向工程师在目标进程的函数执行前后插入自己的代码，监控函数参数、返回值，甚至修改执行流程。
    * **例子:** 使用 Frida 的 JavaScript API `Interceptor.attach(address, { onEnter: function(args) { ... }, onLeave: function(retval) { ... } })` 时，底层会调用 Gum 库的拦截相关功能，而 `gum.c` 中 `_gum_interceptor_init()` 等函数就是负责这部分初始化的。
* **内存监控与修改:**  通过 Gum 提供的内存管理接口，Frida 可以读取和修改目标进程的内存。这对于分析数据结构、破解校验等逆向任务至关重要。
    * **例子:** 使用 `Memory.read*()` 或 `Memory.write*()` 函数时，虽然这些 API 可能不在 `gum.c` 中直接实现，但 `gum.c` 中的内存管理配置影响着这些操作的可用性和行为。
* **追踪系统调用和 API 调用:**  拦截器可以用于 hook 系统调用或目标应用的内部 API，从而追踪程序的行为。`gum.c` 中拦截器的初始化是实现这一点的关键。
* **隐藏 Instrumentation 代码:**  "Cloaking" 功能可以帮助逆向工程师隐藏 Frida 的 footprint，使其在某些反调试或安全机制较强的环境中能够更隐蔽地工作。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

`gum.c` 涉及大量的底层知识和平台特定的实现：

* **二进制底层:**
    * **CPU 特性检测:** `gum_do_query_cpu_features()` 函数会使用 CPUID 指令 (在 x86 架构上) 或读取 `/proc/cpuinfo` (在 ARM Linux 上) 等方式来获取 CPU 的能力。这些操作直接与底层的硬件指令集相关。
    * **例子:**  在 x86 架构上，`gum_get_cpuid()` 函数直接调用 `__cpuid` (MSVC) 或 `__cpuid_count` (GCC)，这些都是汇编级别的指令。
* **Linux:**
    * **动态链接:**  `gum_libdl_prevent_unload()` 函数尝试阻止 `libdl.so.2` 被卸载，这涉及到 Linux 的动态链接器的工作原理。
    * **`/proc/cpuinfo`:**  在 ARM Linux 上，通过读取 `/proc/cpuinfo` 文件来获取 CPU 特性，这是 Linux 内核暴露硬件信息的机制。
    * **系统调用:** Frida 的拦截机制最终会涉及到对系统调用的处理，虽然 `gum.c` 中没有直接的系统调用代码，但它是拦截器工作的基础。
* **Android 内核及框架:**
    * **Android 日志:** `gum_on_log_message()` 在 Android 平台上使用 `__android_log_write()` 函数来输出日志，这是 Android 系统提供的日志接口。
    * **`fork()` 系统调用:** `gum_prepare_to_fork()` 和相关的函数需要理解 `fork()` 系统调用的语义以及子进程如何继承父进程的状态，并进行相应的处理以保证 instrumentation 的正确性。
* **macOS (Darwin) 内核及框架:**
    * **CoreFoundation:**  `gum_on_log_message()` 在 macOS 上使用 CoreFoundation 框架的 `CFLog` 函数进行日志输出。这需要了解 macOS 的 Foundation 和 CoreFoundation 框架。
    * **动态库加载:**  在 macOS 上，可能需要使用 `dlopen` 和 `dlsym` 来加载和查找 CoreFoundation 的函数。
    * **Mach 接口:**  `gum_darwin_query_all_image_infos()` 使用 `mach_task_self()`，这是 macOS 内核提供的 Mach 接口的一部分，用于获取进程信息。

**逻辑推理及假设输入与输出:**

* **假设输入:**  调用 `gum_init()` 时，假设目标操作系统是 Linux。
* **逻辑推理:**  `gum_init()` 内部会调用 `_gum_interceptor_init()` 来初始化拦截器。在 Linux 平台上，`_gum_interceptor_init()` 可能会涉及到分配内存来存储 hook 信息，并可能设置一些与内核交互的数据结构。
* **输出:**  初始化完成后，全局变量 `gum_cached_interceptor` 将指向一个新创建的 `GumInterceptor` 对象，该对象可以用于后续的函数 hook 操作。

* **假设输入:**  调用 `gum_query_cpu_features()`。
* **逻辑推理:**  如果运行在 x86 架构的 Windows 系统上，`gum_query_cpu_features()` 会调用 `gum_do_query_cpu_features()`，后者会进一步调用 `gum_get_cpuid()`。`gum_get_cpuid()` 会执行 CPUID 指令来查询 CPU 的特性位。
* **输出:**  如果 CPU 支持 AVX2 并且操作系统启用了 XSAVE 特性，则 `gum_query_cpu_features()` 返回的 `GumCpuFeatures` 将包含 `GUM_CPU_AVX2` 标志。

**用户或编程常见的使用错误及举例说明:**

* **未正确初始化/反初始化:**  如果用户编写的 Frida 模块没有正确地调用 `gum_init_embedded()` (或 `gum_init()`) 和 `gum_deinit_embedded()` (或 `gum_deinit()`)，可能会导致资源泄漏或其他未定义的行为。
    * **例子:**  如果只调用了 `gum_init_embedded()` 而没有调用 `gum_deinit_embedded()`，那么在模块卸载时，Gum 库分配的一些内存可能无法被释放。
* **在不安全的时间调用 Gum 函数:**  某些 Gum 库的函数可能不是线程安全的，如果在多线程环境下不加保护地调用，可能会导致数据竞争或崩溃。
    * **例子:**  如果多个线程同时尝试修改全局的析构函数列表，可能会导致程序崩溃。虽然 Gum 库自身会做一些同步处理，但用户编写的 instrumentation 代码也需要注意线程安全。
* **内存管理错误 (间接):** 虽然 Gum 库自身管理内存，但用户在使用 Frida 的 API (例如 `Memory.alloc()`) 分配内存后，如果没有正确释放，也会导致内存泄漏。这虽然不是 `gum.c` 直接的错误，但与 Gum 库提供的内存管理机制有关。
* **不理解 "Cloaking" 的影响:**  用户可能会错误地使用 "Cloaking" 功能，导致 Frida 的某些功能无法正常工作，或者产生意想不到的副作用。
    * **例子:**  如果错误地将 Frida 自身使用的内存区域 "cloaked" 起来，可能会导致 Frida 内部的某些操作失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Frida 尝试 hook 一个 Android 应用的某个函数，并遇到了问题，需要查看 Frida 的日志或进行更底层的调试：

1. **编写 Frida 脚本:** 用户编写 JavaScript 代码，使用 Frida 的 `Interceptor.attach()` API 来 hook 目标函数。
2. **运行 Frida 脚本:** 用户通过 Frida 的命令行工具 (`frida`) 或 Python API 运行该脚本，指定目标进程。
3. **Frida Agent 加载:** Frida 会将一个 Agent (包含 Gum 库) 加载到目标进程中。这时，目标进程会执行 Gum 库的初始化代码，包括 `gum_init_embedded()` (在嵌入式环境中)。
4. **拦截器初始化:** `gum_init_embedded()` 会调用 `_gum_interceptor_init()`，初始化拦截器。
5. **`Interceptor.attach()` 调用:** 当 JavaScript 代码执行到 `Interceptor.attach()` 时，Frida 的 JavaScript 引擎会将这个调用转换为对 Gum 库底层 C/C++ 代码的调用。
6. **查找目标函数地址:** Frida 需要找到目标函数的内存地址。
7. **设置 Hook:** Gum 库的拦截器会在目标函数地址处设置 hook，这通常涉及到修改目标地址的指令。
8. **日志输出 (如果出错或开启了日志):** 如果在上述任何步骤中出现错误，或者用户开启了 Frida 的日志输出，那么 `gum_on_log_message()` 函数会被调用，根据平台的不同，日志信息会被输出到不同的位置 (例如，Android 的 logcat，Linux 的 stdout/stderr)。
9. **崩溃或异常:** 如果 hook 设置不正确，或者在执行 hook 代码时发生错误，可能会导致目标进程崩溃或抛出异常。调试器可能会停在 `gum.c` 中的某个位置，例如 `gum_panic()` 函数如果被调用。

作为调试线索，如果用户遇到 Frida 相关的问题，可以：

* **查看 Frida 的日志输出:**  了解初始化、hook 设置等过程是否正常。
* **使用 Frida 的调试功能:**  例如，在 JavaScript 代码中使用 `console.log()`，这些日志最终会通过 `gum_on_log_message()` 输出。
* **使用 GDB 等调试器attach到目标进程:**  如果问题比较复杂，可以直接调试目标进程，查看 Gum 库的内部状态，例如拦截器的状态、内存分配情况等。
* **阅读 Frida 的源代码:**  理解 Gum 库的实现细节，有助于定位问题的原因。

总而言之，`gum.c` 是 Frida 动态 instrumentation 引擎的核心组成部分，负责库的生命周期管理、核心功能的初始化以及与底层操作系统和硬件的交互。理解 `gum.c` 的功能对于深入理解 Frida 的工作原理和进行高级的逆向工程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gum.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Stefano Moioli <smxdev4@gmail.com>
 * Copyright (C) 2024 Yannis Juglaret <yjuglaret@mozilla.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum.h"

#include "gum-init.h"
#include "gumexceptorbackend.h"
#include "guminterceptor-priv.h"
#include "gummemory-priv.h"
#include "gumprintf.h"
#include "gumtls-priv.h"
#include "valgrind.h"
#ifdef HAVE_I386
# ifdef _MSC_VER
#  include <intrin.h>
# else
#  include <cpuid.h>
# endif
#elif defined (HAVE_ARM64) && defined (HAVE_DARWIN)
# include "gum/gumdarwin.h"
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_WINDOWS
# include <windows.h>
#endif
#if !defined (GUM_USE_SYSTEM_ALLOC) && defined (HAVE_FRIDA_LIBFFI)
# include <ffi.h>
#endif

#define DEBUG_HEAP_LEAKS 0

typedef struct _GumInternalThreadDetails GumInternalThreadDetails;

struct _GumInternalThreadDetails
{
  GumThreadId thread_id;
  guint n_cloaked_ranges;
  GumMemoryRange cloaked_ranges[GUM_MAX_THREAD_RANGES];
};

static void gum_destructor_invoke (GumDestructorFunc destructor);

#if !defined (GUM_USE_SYSTEM_ALLOC) && defined (HAVE_FRIDA_LIBFFI)
static void gum_on_ffi_allocate (void * base_address, size_t size);
static void gum_on_ffi_deallocate (void * base_address, size_t size);
#endif
#ifdef HAVE_FRIDA_GLIB
static void gum_on_thread_init (void);
static void gum_on_thread_realize (void);
static void gum_on_thread_dispose (void);
static void gum_on_thread_finalize (void);
static void gum_internal_thread_details_free (
    GumInternalThreadDetails * details);
static void gum_on_fd_opened (gint fd, const gchar * description);
static void gum_on_fd_closed (gint fd, const gchar * description);
#endif

static void gum_on_log_message (const gchar * log_domain,
    GLogLevelFlags log_level, const gchar * message, gpointer user_data);

#if defined (HAVE_LINUX) && defined (HAVE_GLIBC)
# include <dlfcn.h>
# define GUM_RTLD_DLOPEN 0x80000000
extern void * __libc_dlopen_mode (char * name, int flags)
    __attribute__ ((weak));
static void gum_libdl_prevent_unload (void);
#endif

#ifdef HAVE_ANDROID
# include <android/log.h>
#else
# include <stdio.h>
# ifdef HAVE_DARWIN
#  include <CoreFoundation/CoreFoundation.h>
#  include <dlfcn.h>

typedef struct _GumCFApi GumCFApi;
typedef gint32 CFLogLevel;

enum _CFLogLevel
{
  kCFLogLevelEmergency = 0,
  kCFLogLevelAlert     = 1,
  kCFLogLevelCritical  = 2,
  kCFLogLevelError     = 3,
  kCFLogLevelWarning   = 4,
  kCFLogLevelNotice    = 5,
  kCFLogLevelInfo      = 6,
  kCFLogLevelDebug     = 7
};

struct _GumCFApi
{
  CFStringRef (* CFStringCreateWithCString) (CFAllocatorRef alloc,
      const char * c_str, CFStringEncoding encoding);
  void (* CFRelease) (CFTypeRef cf);
  void (* CFLog) (CFLogLevel level, CFStringRef format, ...);
};

# endif
#endif

static void gum_do_init (void);

#ifndef GUM_DIET
static GumAddress * gum_address_copy (const GumAddress * address);
static void gum_address_free (GumAddress * address);
#endif

static GumCpuFeatures gum_do_query_cpu_features (void);

static gboolean gum_initialized = FALSE;
static GSList * gum_early_destructors = NULL;
static GSList * gum_final_destructors = NULL;

#ifdef HAVE_FRIDA_GLIB
static GPrivate gum_internal_thread_details_key = G_PRIVATE_INIT (
    (GDestroyNotify) gum_internal_thread_details_free);
#endif

static GumInterceptor * gum_cached_interceptor = NULL;

G_DEFINE_QUARK (gum-error-quark, gum_error)

GUM_DEFINE_BOXED_TYPE (GumAddress, gum_address, gum_address_copy,
                       gum_address_free)

void
gum_init (void)
{
  if (gum_initialized)
    return;
  gum_initialized = TRUE;

  gum_internal_heap_ref ();
  gum_do_init ();
}

void
gum_shutdown (void)
{
  g_slist_foreach (gum_early_destructors, (GFunc) gum_destructor_invoke, NULL);
  g_slist_free (gum_early_destructors);
  gum_early_destructors = NULL;
}

void
gum_deinit (void)
{
  g_assert (gum_initialized);

  gum_shutdown ();

  _gum_tls_deinit ();

  g_slist_foreach (gum_final_destructors, (GFunc) gum_destructor_invoke, NULL);
  g_slist_free (gum_final_destructors);
  gum_final_destructors = NULL;

  _gum_interceptor_deinit ();

  gum_initialized = FALSE;
}

static void
gum_do_init (void)
{
#ifndef GUM_USE_SYSTEM_ALLOC
  cs_opt_mem gum_cs_mem_callbacks = {
    gum_internal_malloc,
    gum_internal_calloc,
    gum_internal_realloc,
    gum_internal_free,
    (cs_vsnprintf_t) gum_vsnprintf
  };
#endif

#ifdef HAVE_FRIDA_GLIB
  glib_init ();
# ifndef GUM_DIET
  gobject_init ();
# endif
#endif

#ifndef GUM_USE_SYSTEM_ALLOC
  cs_option (0, CS_OPT_MEM, GPOINTER_TO_SIZE (&gum_cs_mem_callbacks));
#endif

  _gum_tls_init ();
  _gum_interceptor_init ();
  _gum_tls_realize ();
}

void
_gum_register_early_destructor (GumDestructorFunc destructor)
{
  gum_early_destructors = g_slist_prepend (gum_early_destructors,
      GUM_FUNCPTR_TO_POINTER (destructor));
}

void
_gum_register_destructor (GumDestructorFunc destructor)
{
  gum_final_destructors = g_slist_prepend (gum_final_destructors,
      GUM_FUNCPTR_TO_POINTER (destructor));
}

static void
gum_destructor_invoke (GumDestructorFunc destructor)
{
  destructor ();
}

void
gum_init_embedded (void)
{
#if !defined (GUM_USE_SYSTEM_ALLOC) && defined (HAVE_FRIDA_LIBFFI)
  ffi_mem_callbacks ffi_callbacks = {
    (void * (*) (size_t)) gum_malloc,
    (void * (*) (size_t, size_t)) gum_calloc,
    gum_free,
    gum_on_ffi_allocate,
    gum_on_ffi_deallocate
  };
#endif
#ifdef HAVE_FRIDA_GLIB
  GThreadCallbacks thread_callbacks = {
    gum_on_thread_init,
    gum_on_thread_realize,
    gum_on_thread_dispose,
    gum_on_thread_finalize
  };
  GFDCallbacks fd_callbacks = {
    gum_on_fd_opened,
    gum_on_fd_closed
  };
#endif
#if !defined (GUM_USE_SYSTEM_ALLOC) && defined (HAVE_FRIDA_GLIB) && \
    !DEBUG_HEAP_LEAKS && !defined (HAVE_ASAN)
  GMemVTable mem_vtable = {
    gum_malloc,
    gum_realloc,
    gum_memalign,
    gum_free,
    gum_calloc,
    gum_malloc,
    gum_realloc
  };
#endif
#if defined (HAVE_WINDOWS) && DEBUG_HEAP_LEAKS
  int tmp_flag;
#endif

  if (gum_initialized)
    return;
  gum_initialized = TRUE;

#if defined (HAVE_WINDOWS) && DEBUG_HEAP_LEAKS
  /*_CrtSetBreakAlloc (1337);*/

  _CrtSetReportMode (_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile (_CRT_ERROR, _CRTDBG_FILE_STDERR);

  tmp_flag = _CrtSetDbgFlag (_CRTDBG_REPORT_FLAG);

  tmp_flag |= _CRTDBG_ALLOC_MEM_DF;
  tmp_flag |= _CRTDBG_LEAK_CHECK_DF;
  tmp_flag &= ~_CRTDBG_CHECK_CRT_DF;

  _CrtSetDbgFlag (tmp_flag);
#endif

  gum_internal_heap_ref ();
#if !defined (GUM_USE_SYSTEM_ALLOC) && defined (HAVE_FRIDA_LIBFFI)
  ffi_set_mem_callbacks (&ffi_callbacks);
#endif
#ifdef HAVE_FRIDA_GLIB
  g_thread_set_callbacks (&thread_callbacks);
  g_platform_audit_set_fd_callbacks (&fd_callbacks);
#endif
#if !DEBUG_HEAP_LEAKS && !defined (HAVE_ASAN)
  if (RUNNING_ON_VALGRIND)
  {
    g_setenv ("G_SLICE", "always-malloc", TRUE);
  }
  else
  {
#if !defined (GUM_USE_SYSTEM_ALLOC) && defined (HAVE_FRIDA_GLIB)
    g_mem_set_vtable (&mem_vtable);
#endif
  }
#else
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#endif
#ifdef HAVE_FRIDA_GLIB
  glib_init ();
#endif
  g_log_set_default_handler (gum_on_log_message, NULL);
  gum_do_init ();

  g_set_prgname ("frida");

#if defined (HAVE_LINUX) && defined (HAVE_GLIBC)
  gum_libdl_prevent_unload ();
#endif

  gum_cached_interceptor = gum_interceptor_obtain ();
}

void
gum_deinit_embedded (void)
{
  g_assert (gum_initialized);

  gum_shutdown ();
#ifdef HAVE_FRIDA_GLIB
  glib_shutdown ();
#endif

  gum_clear_object (&gum_cached_interceptor);

  gum_deinit ();
#ifdef HAVE_FRIDA_GLIB
  glib_deinit ();
#endif
#if !defined (GUM_USE_SYSTEM_ALLOC) && defined (HAVE_FRIDA_LIBFFI)
  ffi_deinit ();
#endif
  gum_internal_heap_unref ();

  gum_initialized = FALSE;
}

void
gum_prepare_to_fork (void)
{
  _gum_exceptor_backend_prepare_to_fork ();
}

void
gum_recover_from_fork_in_parent (void)
{
  _gum_exceptor_backend_recover_from_fork_in_parent ();
}

void
gum_recover_from_fork_in_child (void)
{
  _gum_exceptor_backend_recover_from_fork_in_child ();
}

#if !defined (GUM_USE_SYSTEM_ALLOC) && defined (HAVE_FRIDA_LIBFFI)

static void
gum_on_ffi_allocate (void * base_address,
                     size_t size)
{
  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (base_address);
  range.size = size;
  gum_cloak_add_range (&range);
}

static void
gum_on_ffi_deallocate (void * base_address,
                       size_t size)
{
  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (base_address);
  range.size = size;
  gum_cloak_remove_range (&range);
}

#endif

#ifdef HAVE_FRIDA_GLIB

static void
gum_on_thread_init (void)
{
}

static void
gum_on_thread_realize (void)
{
  GumInternalThreadDetails * details;
  guint i;

  gum_interceptor_ignore_current_thread (gum_cached_interceptor);

  details = g_slice_new (GumInternalThreadDetails);
  details->thread_id = gum_process_get_current_thread_id ();
  details->n_cloaked_ranges =
      gum_thread_try_get_ranges (details->cloaked_ranges,
          GUM_MAX_THREAD_RANGES);

  gum_cloak_add_thread (details->thread_id);

  for (i = 0; i != details->n_cloaked_ranges; i++)
    gum_cloak_add_range (&details->cloaked_ranges[i]);

  /* This allows us to free the data no matter how the thread exits */
  g_private_set (&gum_internal_thread_details_key, details);
}

static void
gum_on_thread_dispose (void)
{
  if (gum_cached_interceptor != NULL)
    gum_interceptor_ignore_current_thread (gum_cached_interceptor);
}

static void
gum_on_thread_finalize (void)
{
  if (gum_cached_interceptor != NULL)
    gum_interceptor_unignore_current_thread (gum_cached_interceptor);
}

static void
gum_internal_thread_details_free (GumInternalThreadDetails * details)
{
  GumThreadId thread_id;
  guint i;

  thread_id = details->thread_id;

  for (i = 0; i != details->n_cloaked_ranges; i++)
    gum_cloak_remove_range (&details->cloaked_ranges[i]);

  g_slice_free (GumInternalThreadDetails, details);

  gum_cloak_remove_thread (thread_id);
}

static void
gum_on_fd_opened (gint fd,
                  const gchar * description)
{
  gum_cloak_add_file_descriptor (fd);
}

static void
gum_on_fd_closed (gint fd,
                  const gchar * description)
{
  gum_cloak_remove_file_descriptor (fd);
}

#endif

#if defined (HAVE_LINUX) && defined (HAVE_GLIBC)

static void
gum_libdl_prevent_unload (void)
{
  if (__libc_dlopen_mode == NULL)
    return;

  __libc_dlopen_mode ("libdl.so.2", RTLD_LAZY | GUM_RTLD_DLOPEN);
}

#endif

static void
gum_on_log_message (const gchar * log_domain,
                    GLogLevelFlags log_level,
                    const gchar * message,
                    gpointer user_data)
{
#if defined (HAVE_WINDOWS)
  gunichar2 * message_utf16;

  message_utf16 = g_utf8_to_utf16 (message, -1, NULL, NULL, NULL);
  OutputDebugStringW (message_utf16);
  g_free (message_utf16);
#elif defined (HAVE_ANDROID)
  int priority;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
    case G_LOG_LEVEL_CRITICAL:
    case G_LOG_LEVEL_WARNING:
      priority = ANDROID_LOG_FATAL;
      break;
    case G_LOG_LEVEL_MESSAGE:
    case G_LOG_LEVEL_INFO:
      priority = ANDROID_LOG_INFO;
      break;
    case G_LOG_LEVEL_DEBUG:
    default:
      priority = ANDROID_LOG_DEBUG;
      break;
  }

  __android_log_write (priority, log_domain, message);
#else
# ifdef HAVE_DARWIN
  static gsize api_value = 0;
  GumCFApi * api;

  if (g_once_init_enter (&api_value))
  {
    const gchar * cf_path = "/System/Library/Frameworks/"
        "CoreFoundation.framework/CoreFoundation";
    void * cf;

    /*
     * CoreFoundation must be loaded by the main thread, so we should avoid
     * loading it.
     */
    if (gum_module_find_base_address (cf_path) != 0)
    {
      cf = dlopen (cf_path, RTLD_GLOBAL | RTLD_LAZY);
      g_assert (cf != NULL);

      api = g_slice_new (GumCFApi);

      api->CFStringCreateWithCString = dlsym (cf, "CFStringCreateWithCString");
      g_assert (api->CFStringCreateWithCString != NULL);

      api->CFRelease = dlsym (cf, "CFRelease");
      g_assert (api->CFRelease != NULL);

      api->CFLog = dlsym (cf, "CFLog");
      g_assert (api->CFLog != NULL);

      dlclose (cf);

      /*
       * In case Foundation is also loaded, make sure it's initialized
       * so CFLog() doesn't crash if called early.
       */
      gum_module_ensure_initialized ("/System/Library/Frameworks/"
          "Foundation.framework/Foundation");
    }
    else
    {
      api = NULL;
    }

    g_once_init_leave (&api_value, 1 + GPOINTER_TO_SIZE (api));
  }

  api = GSIZE_TO_POINTER (api_value - 1);
  if (api != NULL)
  {
    CFLogLevel cf_log_level;
    CFStringRef message_str, template_str;

    switch (log_level & G_LOG_LEVEL_MASK)
    {
      case G_LOG_LEVEL_ERROR:
        cf_log_level = kCFLogLevelError;
        break;
      case G_LOG_LEVEL_CRITICAL:
        cf_log_level = kCFLogLevelCritical;
        break;
      case G_LOG_LEVEL_WARNING:
        cf_log_level = kCFLogLevelWarning;
        break;
      case G_LOG_LEVEL_MESSAGE:
        cf_log_level = kCFLogLevelNotice;
        break;
      case G_LOG_LEVEL_INFO:
        cf_log_level = kCFLogLevelInfo;
        break;
      case G_LOG_LEVEL_DEBUG:
        cf_log_level = kCFLogLevelDebug;
        break;
      default:
        g_assert_not_reached ();
    }

    message_str = api->CFStringCreateWithCString (NULL, message,
        kCFStringEncodingUTF8);
    if (log_domain != NULL)
    {
      CFStringRef log_domain_str;

      template_str = api->CFStringCreateWithCString (NULL, "%@: %@",
          kCFStringEncodingUTF8);
      log_domain_str = api->CFStringCreateWithCString (NULL, log_domain,
          kCFStringEncodingUTF8);
      api->CFLog (cf_log_level, template_str, log_domain_str, message_str);
      api->CFRelease (log_domain_str);
    }
    else
    {
      template_str = api->CFStringCreateWithCString (NULL, "%@",
          kCFStringEncodingUTF8);
      api->CFLog (cf_log_level, template_str, message_str);
    }
    api->CFRelease (template_str);
    api->CFRelease (message_str);

    return;
  }
  /* else: fall through to stdout/stderr logging */
# endif

  FILE * file = NULL;
  const gchar * severity = NULL;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
      file = stderr;
      severity = "ERROR";
      break;
    case G_LOG_LEVEL_CRITICAL:
      file = stderr;
      severity = "CRITICAL";
      break;
    case G_LOG_LEVEL_WARNING:
      file = stderr;
      severity = "WARNING";
      break;
    case G_LOG_LEVEL_MESSAGE:
      file = stderr;
      severity = "MESSAGE";
      break;
    case G_LOG_LEVEL_INFO:
      file = stdout;
      severity = "INFO";
      break;
    case G_LOG_LEVEL_DEBUG:
      file = stdout;
      severity = "DEBUG";
      break;
    default:
      g_assert_not_reached ();
  }

  fprintf (file, "[%s %s] %s\n", log_domain, severity, message);
  fflush (file);
#endif
}

#ifdef GUM_DIET

gpointer
gum_object_ref (gpointer object)
{
  GumObject * self = object;

  g_atomic_int_inc (&self->ref_count);

  return self;
}

void
gum_object_unref (gpointer object)
{
  GumObject * self = object;

  if (g_atomic_int_dec_and_test (&self->ref_count))
  {
    self->finalize (object);

    g_free (self);
  }
}

#endif

void
gum_panic (const gchar * format,
           ...)
{
#ifndef GUM_DIET
  va_list args;

  va_start (args, format);
  g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, format, args);
  va_end (args);
#endif

  g_abort ();
}

#ifndef GUM_DIET

static GumAddress *
gum_address_copy (const GumAddress * address)
{
  return g_slice_dup (GumAddress, address);
}

static void
gum_address_free (GumAddress * address)
{
  g_slice_free (GumAddress, address);
}

#endif

GumCpuFeatures
gum_query_cpu_features (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    GumCpuFeatures features = gum_do_query_cpu_features ();

    g_once_init_leave (&cached_result, features + 1);
  }

  return cached_result - 1;
}

#if defined (HAVE_I386)

static gboolean gum_get_cpuid (guint level, guint * a, guint * b, guint * c,
    guint * d);

static GumCpuFeatures
gum_do_query_cpu_features (void)
{
  GumCpuFeatures features = 0;
  gboolean cpu_supports_avx2 = FALSE;
  gboolean cpu_supports_cet_ss = FALSE;
  gboolean os_enabled_xsave = FALSE;
  guint a, b, c, d;

  if (gum_get_cpuid (7, &a, &b, &c, &d))
  {
    cpu_supports_avx2 = (b & (1 << 5)) != 0;
    cpu_supports_cet_ss = (c & (1 << 7)) != 0;
  }

  if (gum_get_cpuid (1, &a, &b, &c, &d))
    os_enabled_xsave = (c & (1 << 27)) != 0;

  if (cpu_supports_avx2 && os_enabled_xsave)
    features |= GUM_CPU_AVX2;

  if (cpu_supports_cet_ss)
    features |= GUM_CPU_CET_SS;

  return features;
}

static gboolean
gum_get_cpuid (guint level,
               guint * a,
               guint * b,
               guint * c,
               guint * d)
{
#ifdef _MSC_VER
  gint info[4];
  guint n;

  __cpuid (info, 0);
  n = info[0];
  if (n < level)
    return FALSE;

  __cpuid (info, level);

  *a = info[0];
  *b = info[1];
  *c = info[2];
  *d = info[3];

  return TRUE;
#else
  guint n;

  n = __get_cpuid_max (0, NULL);
  if (n < level)
    return FALSE;

  __cpuid_count (level, 0, *a, *b, *c, *d);

  return TRUE;
#endif
}

#elif defined (HAVE_ARM)

static GumCpuFeatures
gum_do_query_cpu_features (void)
{
  GumCpuFeatures features = 0;

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
# if __ARM_ARCH > 4 || defined (__THUMB_INTERWORK__)
  features |= GUM_CPU_THUMB_INTERWORK;
# endif
#else
  features |= GUM_CPU_THUMB_INTERWORK;
#endif

#ifdef __ARM_VFPV2__
  features |= GUM_CPU_VFP2;
#endif

#ifdef __ARM_VFPV3__
  features |= GUM_CPU_VFP3;
#endif

#ifdef __ARM_NEON__
  features |= GUM_CPU_VFPD32;
#endif

#if defined (HAVE_LINUX) && defined (__ARM_EABI__) && \
    !(defined (__ARM_VFPV2__) && defined (__ARM_VFPV3__) && \
        defined (__ARM_NEON__))
  {
    gchar * info = NULL;
    gchar ** items = NULL;
    gchar * start, * end, * item;
    guint i;

    if (!g_file_get_contents ("/proc/cpuinfo", &info, NULL, NULL))
      goto beach;

    start = strstr (info, "\nFeatures");
    if (start == NULL)
      goto beach;
    start += 9;

    start = strchr (start, ':');
    if (start == NULL)
      goto beach;
    start += 2;

    end = strchr (start, '\n');
    if (end == NULL)
      goto beach;
    *end = '\0';

    items = g_strsplit (start, " ", -1);

    for (i = 0; (item = items[i]) != NULL; i++)
    {
      if (strcmp (item, "vfp") == 0)
      {
        features |= GUM_CPU_VFP2;
      }
      else if (strcmp (item, "vfpv3") == 0)
      {
        features |= GUM_CPU_VFP3;
      }
      else if (strcmp (item, "vfpd32") == 0 || strcmp (item, "neon") == 0)
      {
        features |= GUM_CPU_VFPD32;
      }
      else if (strcmp (item, "asimd") == 0)
      {
        features |= GUM_CPU_VFP2 | GUM_CPU_VFP3 | GUM_CPU_VFPD32;
      }
    }

beach:
    g_strfreev (items);

    g_free (info);
  }
#endif

  return features;
}

#elif defined (HAVE_ARM64) && defined (HAVE_DARWIN)

static GumCpuFeatures
gum_do_query_cpu_features (void)
{
  GumCpuFeatures features = 0;
  GumDarwinAllImageInfos infos;
  GumDarwinCpuSubtype subtype;

  gum_darwin_query_all_image_infos (mach_task_self (), &infos);

  subtype = *((GumDarwinCpuSubtype *) (infos.dyld_image_load_address + 8));
  if ((subtype & GUM_DARWIN_CPU_SUBTYPE_MASK) == GUM_DARWIN_CPU_SUBTYPE_ARM64E)
    features |= GUM_CPU_PTRAUTH;

  return features;
}

#else

static GumCpuFeatures
gum_do_query_cpu_features (void)
{
  return 0;
}

#endif

"""

```