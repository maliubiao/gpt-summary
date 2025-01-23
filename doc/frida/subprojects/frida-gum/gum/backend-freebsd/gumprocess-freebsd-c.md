Response:
Let's break down the thought process for analyzing this C code.

1. **Understand the Goal:** The request asks for the functionality of the `gumprocess-freebsd.c` file, its relation to reverse engineering, its use of low-level concepts, logical reasoning, potential user errors, and how a user might reach this code.

2. **High-Level Overview:**  Recognize that the file name and the surrounding context (`frida/subprojects/frida-gum/gum/backend-freebsd`) strongly suggest this is a platform-specific implementation for Frida's dynamic instrumentation on FreeBSD. The "gumprocess" part hints at process-related operations.

3. **Function-by-Function Analysis (Initial Pass):** Go through each function and briefly note its purpose based on its name and the operations within it. Don't get bogged down in details initially. Keywords and system calls are helpful here:

    * `gum_process_query_libc_name`:  Looks up libc.
    * `gum_try_resolve_dynamic_symbol`: Resolves symbols.
    * `gum_process_is_debugger_attached`: Checks for debugger.
    * `gum_process_get_id`: Gets process ID.
    * `gum_process_get_current_thread_id`: Gets thread ID.
    * `gum_process_has_thread`: Checks for thread existence.
    * `gum_process_modify_thread`: The core function for modifying thread context. Notice the `fork`, `ptrace`, and socket usage.
    * `gum_do_modify_thread`:  The child process part of `gum_process_modify_thread`. Focus on the `ptrace` calls.
    * `gum_read_chunk`, `gum_write_chunk`: Helper functions for reliable data transfer.
    * `gum_wait_for_child_signal`:  Waits for signals during `ptrace`.
    * `_gum_process_enumerate_threads`: Iterates through threads using `sysctl`.
    * `gum_store_cpu_context`: Stores CPU context.
    * `gum_freebsd_query_program_path_for_self`, `gum_freebsd_query_program_path_for_pid`: Gets executable path using `sysctl`.
    * `_gum_process_collect_main_module`: Collects information about the main module.
    * `_gum_process_enumerate_modules`: Iterates through modules using `dl_iterate_phdr`.
    * `gum_emit_module_from_phdr`: Callback for `dl_iterate_phdr`.
    * `_gum_process_enumerate_ranges`, `gum_freebsd_enumerate_ranges`:  Iterates through memory ranges using `sysctl`.
    * `gum_process_enumerate_malloc_ranges`:  Not implemented.
    * `gum_thread_try_get_ranges`: Gets thread stack ranges.
    * `gum_thread_get_system_error`, `gum_thread_set_system_error`:  Manages `errno`.
    * `gum_thread_suspend`, `gum_thread_resume`: Controls thread execution using `thr_kill`.
    * `gum_thread_set_hardware_breakpoint`, `gum_thread_unset_hardware_breakpoint`, `gum_thread_set_hardware_watchpoint`, `gum_thread_unset_hardware_watchpoint`: Hardware breakpoint/watchpoint handling (currently unsupported).
    * `gum_module_load`: Loads modules using `dlopen`.
    * `gum_module_get_handle`: Gets a module handle without loading.
    * `gum_module_ensure_initialized`: Ensures a module is initialized.
    * `gum_module_find_export_by_name`: Finds exported symbols using `dlsym`.
    * `_gum_process_resolve_module_name`: Resolves module names to paths and bases.
    * `gum_store_module_path_and_base_if_name_matches`: Helper for resolving module names.
    * `gum_module_path_matches`:  Compares module paths.
    * `gum_thread_state_from_proc`:  Maps FreeBSD thread status to Gum's enum.
    * `gum_page_protection_from_vmentry`: Maps FreeBSD memory protection to Gum's enum.
    * `gum_freebsd_parse_ucontext`, `gum_freebsd_unparse_ucontext`: Converts between `ucontext_t` and `GumCpuContext`.
    * `gum_freebsd_parse_regs`, `gum_freebsd_unparse_regs`: Converts between `reg` and `GumCpuContext`.

4. **Categorize Functionality:** Group the functions based on their roles:

    * **Process Information:**  Getting PID, checking for debugger, listing threads and modules, getting executable path.
    * **Thread Manipulation:** Modifying thread context, suspending/resuming threads, getting/setting CPU context.
    * **Memory Management:** Enumerating memory ranges.
    * **Module Management:** Loading modules, finding exports, resolving module names.
    * **Error Handling:** Getting/setting system errors.
    * **CPU Context Handling:** Parsing and unparsing CPU state.

5. **Relate to Reverse Engineering:** Think about how each category of functions is crucial for dynamic analysis and reverse engineering. Modifying thread context, inspecting memory, and understanding module loading are all fundamental. `ptrace` is a key technique here.

6. **Identify Low-Level Concepts:**  List the system calls, data structures, and concepts that are inherently low-level:

    * System calls: `ptrace`, `sysctl`, `fork`, `socketpair`, `read`, `write`, `waitpid`, `thr_kill`, `thr_kill2`, `dlopen`, `dlsym`, `dladdr`, `dlinfo`.
    * Data structures: `kinfo_proc`, `dl_phdr_info`, `kinfo_vmentry`, `ucontext_t`, `reg`, `pthread_attr_t`.
    * Concepts: Process IDs, thread IDs, signals, memory protection, virtual memory, ELF format (implied by `dl_iterate_phdr`), CPU registers.

7. **Logical Reasoning (Hypothetical Scenarios):** Consider how the code *could* be used. For example, how `gum_process_modify_thread` uses `fork` and `ptrace` to interact with another thread. What happens in the parent and child processes? What data is exchanged?

8. **User Errors:** Think about common mistakes a programmer using Frida might make that could lead to issues in this code:

    * Incorrect module names.
    * Trying to manipulate threads in ways that are not permitted by the OS.
    * Expecting hardware breakpoints to work when they are not supported.

9. **Debugging Journey:**  Imagine a scenario where a Frida user encounters a problem and how their actions would lead to this specific file. They'd be using Frida's API, which would eventually call into the platform-specific backend.

10. **Structure and Refine:** Organize the findings into the categories requested by the prompt. Provide clear explanations and concrete examples. Use the code snippets to illustrate the points being made. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. For example, explain what `ptrace` does.

11. **Review and Iterate:** Read through the entire analysis to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might just say "modifies thread context," but I need to elaborate on *how* it does that (using `ptrace` in a separate process).

This systematic approach, starting with a high-level understanding and gradually drilling down into the details, is key to effectively analyzing and explaining complex code like this. The decomposition into categories makes it easier to manage the information and address all aspects of the request.
这是一个名为 `gumprocess-freebsd.c` 的 C 源代码文件，它是 Frida 动态 instrumentation 工具在 FreeBSD 操作系统上的一个后端实现。它的主要职责是提供在 FreeBSD 系统上与进程和线程交互的功能，以便 Frida 能够进行代码注入、拦截和修改等操作。

下面列举一下它的主要功能，并结合逆向、底层知识、逻辑推理和常见错误进行说明：

**主要功能:**

1. **查询进程和线程信息:**
   - `gum_process_query_libc_name`:  尝试获取 libc 库的名称。
   - `gum_process_is_debugger_attached`: 检查是否有调试器附加到当前进程。
   - `gum_process_get_id`: 获取当前进程的 PID (进程 ID)。
   - `gum_process_get_current_thread_id`: 获取当前线程的 TID (线程 ID)。
   - `gum_process_has_thread`: 检查指定线程 ID 的线程是否存在于当前进程中。
   - `_gum_process_enumerate_threads`: 枚举进程中的所有线程。
   - `gum_freebsd_query_program_path_for_self`, `gum_freebsd_query_program_path_for_pid`: 获取进程的可执行文件路径。

2. **修改线程上下文 (核心功能):**
   - `gum_process_modify_thread`: 允许修改指定线程的 CPU 上下文 (寄存器值等)。这是 Frida 实现代码注入和 hook 的关键。
   - `gum_do_modify_thread`:  `gum_process_modify_thread` 的实际执行逻辑，通常在一个子进程中通过 `ptrace` 系统调用实现。
   - `gum_freebsd_parse_ucontext`, `gum_freebsd_unparse_ucontext`:  在 `ucontext_t` (FreeBSD 中表示用户态上下文的结构体) 和 Frida 的 `GumCpuContext` 之间转换数据。
   - `gum_freebsd_parse_regs`, `gum_freebsd_unparse_regs`: 在 FreeBSD 的 `reg` 结构体 (通过 `ptrace` 获取的寄存器信息) 和 Frida 的 `GumCpuContext` 之间转换数据。

3. **内存操作:**
   - `_gum_process_enumerate_ranges`, `gum_freebsd_enumerate_ranges`: 枚举进程的内存映射区域，可以指定内存保护属性进行过滤。
   - `gum_thread_try_get_ranges`: 尝试获取线程的栈内存范围。
   - `gum_process_enumerate_malloc_ranges`: (当前未实现)  计划用于枚举进程的堆内存分配情况。

4. **模块 (共享库) 操作:**
   - `_gum_process_collect_main_module`: 收集主模块的信息。
   - `_gum_process_enumerate_modules`: 枚举进程加载的所有模块 (共享库)。
   - `gum_emit_module_from_phdr`:  `dl_iterate_phdr` 的回调函数，用于从程序头信息中提取模块信息。
   - `gum_module_load`: 加载指定的模块 (共享库)。
   - `gum_module_ensure_initialized`: 确保模块已经被初始化。
   - `gum_module_find_export_by_name`: 在指定模块中查找导出的符号 (函数或变量)。
   - `_gum_process_resolve_module_name`: 解析模块名称，获取其路径和基地址。

5. **线程控制:**
   - `gum_thread_suspend`: 暂停指定线程的执行。
   - `gum_thread_resume`: 恢复指定线程的执行。
   - `gum_thread_set_hardware_breakpoint`, `gum_thread_unset_hardware_breakpoint`, `gum_thread_set_hardware_watchpoint`, `gum_thread_unset_hardware_watchpoint`: (当前未实现)  计划用于设置和取消硬件断点和观察点。

6. **错误处理:**
   - `gum_thread_get_system_error`, `gum_thread_set_system_error`: 获取和设置线程的系统错误码 (errno)。

**与逆向方法的关系及举例说明:**

* **动态代码分析和 Hook:** `gum_process_modify_thread` 是 Frida 实现动态代码插桩的核心。逆向工程师可以使用 Frida 脚本来调用这个功能，修改目标进程中函数的入口地址，跳转到自定义的代码，从而实现对函数行为的拦截和修改 (Hook)。
    * **例子:**  假设要 Hook `open` 系统调用，Frida 会使用 `gum_process_modify_thread` 修改 `open` 函数的指令，使其跳转到 Frida 注入的代码。当目标进程调用 `open` 时，会先执行 Frida 的代码，记录参数或修改行为，然后再决定是否调用原始的 `open`。

* **内存分析:** `_gum_process_enumerate_ranges` 允许逆向工程师查看目标进程的内存布局，识别代码段、数据段、堆、栈等，有助于理解程序的内存使用情况，查找敏感数据或漏洞。
    * **例子:**  逆向恶意软件时，可以使用 Frida 获取进程的内存映射，查找可能包含解密后的恶意代码或配置信息的内存区域。

* **模块分析:**  通过 `_gum_process_enumerate_modules` 和 `gum_module_find_export_by_name`，逆向工程师可以了解目标进程加载了哪些动态库，并找到感兴趣的函数地址，方便进行进一步的分析和 Hook。
    * **例子:**  分析一个使用了 OpenSSL 库的程序，可以使用 Frida 列出所有加载的模块，找到 `libssl.so`，然后查找 `SSL_connect` 函数的地址，以便监控 SSL 连接过程。

**涉及到的二进制底层、Linux/Android 内核及框架的知识及举例说明:**

* **FreeBSD 内核接口:**  该文件大量使用了 FreeBSD 特有的系统调用和内核数据结构，如 `ptrace` (用于进程控制和调试)、`sysctl` (用于获取和设置内核参数)、`thr_kill` (用于向线程发送信号)、`kinfo_proc` (包含进程和线程信息的结构体)、`kinfo_vmentry` (包含内存映射信息的结构体) 等。
    * **例子:**  `_gum_process_enumerate_threads` 函数使用 `sysctl` 系统调用，通过 `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID | KERN_PROC_INC_THREAD` 这些参数来获取指定进程的所有线程信息，返回的是 `kinfo_proc` 结构体数组。

* **进程和线程管理:** 文件中的函数涉及到进程的创建 (`fork`)，线程的创建和销毁 (尽管这里没有直接创建，但有枚举和控制)，进程和线程间的通信 (通过 `socketpair`)，以及信号处理 (例如 `SIGSTOP`, `SIGCONT`)。
    * **例子:** `gum_process_modify_thread` 使用 `fork` 创建一个子进程，然后在子进程中使用 `ptrace` 来 attach 到目标线程，进行寄存器操作。父子进程之间通过 socketpair 创建的 socket 进行通信，传递 CPU 上下文数据。

* **内存管理:**  涉及虚拟内存的概念，内存映射 (`mmap` 的底层实现，通过内核数据结构 `kinfo_vmentry` 获取)，内存保护属性 (`KVME_PROT_READ`, `KVME_PROT_WRITE`, `KVME_PROT_EXEC`)。
    * **例子:** `gum_freebsd_enumerate_ranges` 函数通过 `sysctl` 获取 `kinfo_vmentry` 结构体，从中提取内存区域的起始地址、大小和保护属性，并将其转换为 Frida 的 `GumRangeDetails` 结构体。

* **动态链接:**  使用了 `dlfcn.h` 提供的动态链接相关的 API，如 `dlopen` (加载共享库)、`dlsym` (查找符号)、`dladdr` (查找符号的地址信息)、`dl_iterate_phdr` (遍历程序头信息)。
    * **例子:** `gum_process_query_libc_name` 使用 `dlsym` 查找 `exit` 符号的地址，然后使用 `dladdr` 获取该符号所在的库的名称。

* **CPU 上下文:**  需要理解不同架构 (如 x86-64, ARM64) 的 CPU 寄存器结构和上下文切换的原理。`gum_freebsd_parse_ucontext` 和 `gum_freebsd_parse_regs` 等函数负责将 FreeBSD 的 CPU 上下文表示转换为 Frida 统一的 `GumCpuContext` 结构体。
    * **例子:** 在 x86-64 架构下，`gum_freebsd_parse_regs` 函数将 `regs` 结构体中的 `r_rip` 赋值给 `ctx->rip`，表示指令指针寄存器。

**逻辑推理及假设输入与输出:**

* **`gum_process_is_debugger_attached`:**
    * **假设输入:**  当前进程是否被 `gdb` 或其他调试器附加。
    * **输出:**  如果被附加，返回 `TRUE` (非零值)，否则返回 `FALSE` (零值)。
    * **逻辑:**  通过 `sysctl` 获取进程的 `kinfo_proc` 结构体，检查其 `ki_flag` 成员是否包含 `P_TRACED` 标志。

* **`gum_process_modify_thread` (针对不同线程):**
    * **假设输入:**  目标线程的 ID (`thread_id`)，一个修改 CPU 上下文的回调函数 (`func`)，以及用户数据 (`user_data`)。
    * **输出:**  如果成功修改线程上下文，返回 `TRUE`，否则返回 `FALSE`。
    * **逻辑:**
        1. 创建一个 socketpair 用于父子进程通信。
        2. `fork` 创建子进程。
        3. 子进程调用 `gum_do_modify_thread`，使用 `ptrace` attach 到目标进程，暂停目标线程，获取寄存器，发送给父进程。
        4. 父进程调用回调函数 `func` 修改收到的 CPU 上下文。
        5. 父进程将修改后的 CPU 上下文发送回子进程。
        6. 子进程恢复目标线程的寄存器，detach 并退出。

* **`_gum_process_resolve_module_name`:**
    * **假设输入:**  模块名称 (`name`)，例如 `"libc.so.7"` 或 `"/lib/libc.so.7"`。
    * **输出:**  如果找到模块，则通过指针参数 `path` 返回模块的完整路径，`base` 返回模块的加载基地址，函数返回 `TRUE`。否则，`path` 和 `base` 的值不确定，函数返回 `FALSE`。
    * **逻辑:**  尝试使用 `dlopen` 获取模块句柄，如果成功，则通过 `dlinfo` 获取模块信息。如果失败，则遍历已加载的模块列表，查找名称匹配的模块。

**涉及用户或者编程常见的使用错误及举例说明:**

* **在 `gum_process_modify_thread` 中尝试修改自身线程而没有正确处理:** 代码中对修改自身线程做了特殊处理，直接获取和设置 `ucontext_t`。如果用户错误地认为可以像修改其他线程一样修改自身线程，可能会导致逻辑错误或崩溃。
    * **例子:** 用户可能错误地认为可以通过 `gum_process_modify_thread` 和 `ptrace` 的方式修改当前线程的寄存器，而没有意识到需要使用 `getcontext` 和 `setcontext`。

* **在多线程环境中使用全局变量或静态变量不当:**  Frida Agent 通常运行在目标进程中，如果 `gumprocess-freebsd.c` 中的某些静态变量没有进行适当的线程安全保护，可能会导致数据竞争和不可预测的行为。虽然这个文件中看起来没有明显的全局或静态变量直接被多个线程修改，但在其他相关文件中可能存在这类问题。

* **假设硬件断点/观察点可用:**  用户如果尝试使用 `gum_thread_set_hardware_breakpoint` 等函数，会因为 FreeBSD 平台尚未支持而得到 `GUM_ERROR_NOT_SUPPORTED` 错误。
    * **例子:** 用户编写 Frida 脚本尝试设置硬件断点，但脚本在 FreeBSD 上运行时会失败，并显示不支持的错误信息。

* **模块名称解析错误:**  在 `_gum_process_resolve_module_name` 中，如果用户提供的模块名称不正确 (既不是完整路径也不是正确的 soname)，可能导致模块解析失败。
    * **例子:** 用户想找到 `libcrypto.so`，但误写成 `crypto.so`，可能会导致 Frida 无法找到该模块。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户首先会编写 JavaScript 或 Python 脚本，使用 Frida 提供的 API 来进行动态插桩。例如，他们可能会使用 `Interceptor.attach` 来 hook 某个函数。

2. **Frida 核心库处理:** Frida 的核心库 (通常是 Python 模块或 Node.js 模块) 会接收到用户的请求 (例如 attach 到进程、hook 函数)。

3. **Gum (Frida 的底层引擎) 调用:** Frida 核心库会将请求传递给 Gum，这是 Frida 的底层引擎，负责处理跨平台的细节。

4. **平台特定后端的选择:** Gum 会根据目标进程的操作系统 (这里是 FreeBSD) 选择相应的后端实现，也就是 `gum/backend-freebsd` 目录下的代码。

5. **`gumprocess-freebsd.c` 中的函数被调用:**  当用户请求的操作涉及到进程或线程级别的操作时，Gum 会调用 `gumprocess-freebsd.c` 中相应的函数。
   * **例如:** 当用户使用 `Interceptor.attach` hook 一个函数时，Frida 需要获取目标函数的地址，这可能涉及到调用 `_gum_process_resolve_module_name` 和 `gum_module_find_export_by_name`。
   * **例如:** 当 Frida 需要修改目标函数的代码时，会调用 `gum_process_modify_thread` 来修改目标线程的指令指针或注入代码。
   * **例如:** 当用户使用 `Process.enumerateModules()` 时，会调用 `_gum_process_enumerate_modules` 来获取模块列表。

6. **系统调用和内核交互:** `gumprocess-freebsd.c` 中的函数最终会调用 FreeBSD 的系统调用 (如 `ptrace`, `sysctl`, `dlopen` 等) 来完成实际的操作。

**调试线索:** 如果在 Frida 的使用过程中遇到问题，例如无法 hook 函数、内存访问错误等，可以沿着这个调用链进行调试：

* **查看 Frida 脚本的输出和错误信息。**
* **启用 Frida 的调试日志 (例如设置 `FRIDA_DEBUG=1`)，查看 Gum 和后端实现的日志输出。**
* **如果问题怀疑出在平台特定代码，可以尝试阅读 `gumprocess-freebsd.c` 的源代码，理解其实现逻辑。**
* **使用 `gdb` 等调试器附加到 Frida 运行的进程，设置断点在 `gumprocess-freebsd.c` 中的关键函数，例如 `gum_process_modify_thread` 或 `ptrace` 调用处，来跟踪执行流程和查看变量值。**

总而言之，`gumprocess-freebsd.c` 是 Frida 在 FreeBSD 平台上实现动态 instrumentation 功能的关键组件，它提供了与进程、线程、内存和模块交互的底层接口，使得 Frida 能够执行代码注入、hook 和内存分析等强大的逆向工程操作。理解其功能和实现细节对于调试 Frida 相关问题和深入理解 Frida 的工作原理至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-freebsd/gumprocess-freebsd.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2022-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "backend-elf/gumprocess-elf.h"
#include "gum-init.h"
#include "gum/gumfreebsd.h"

#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <pthread_np.h>
#include <stdlib.h>
#include <strings.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/thr.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#define GUM_TEMP_FAILURE_RETRY(expression) \
    ({ \
      gssize __result; \
      \
      do __result = (gssize) (expression); \
      while (__result == -EINTR); \
      \
      __result; \
    })

typedef struct _GumModifyThreadContext GumModifyThreadContext;

typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;
typedef struct _GumResolveModuleNameContext GumResolveModuleNameContext;

struct _GumModifyThreadContext
{
  gint fd[2];
  pid_t pid;
  lwpid_t target_thread;
  lwpid_t interruptible_thread;
};

struct _GumEnumerateModulesContext
{
  GumFoundModuleFunc func;
  gpointer user_data;
};

struct _GumResolveModuleNameContext
{
  const gchar * name;
  gchar * path;
  GumAddress base;
};

static const gchar * gum_try_init_libc_name (void);
static gboolean gum_try_resolve_dynamic_symbol (const gchar * name,
    Dl_info * info);

static void gum_do_modify_thread (GumModifyThreadContext * ctx);
static gboolean gum_read_chunk (gint fd, gpointer buffer, gsize length);
static gboolean gum_write_chunk (gint fd, gconstpointer buffer, gsize length);
static gboolean gum_wait_for_child_signal (pid_t pid, gint expected_signal);

static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static gchar * gum_query_program_path_for_target (int target, GError ** error);

static int gum_emit_module_from_phdr (struct dl_phdr_info * info, size_t size,
    void * user_data);

static gboolean gum_store_module_path_and_base_if_name_matches (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_module_path_matches (const gchar * path,
    const gchar * name_or_path);

static GumThreadState gum_thread_state_from_proc (const struct kinfo_proc * p);
static GumPageProtection gum_page_protection_from_vmentry (int native_prot);

const gchar *
gum_process_query_libc_name (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_libc_name, NULL);

  if (once.retval == NULL)
    gum_panic ("Unable to locate the libc; please file a bug");

  return once.retval;
}

static const gchar *
gum_try_init_libc_name (void)
{
  Dl_info info;

  if (!gum_try_resolve_dynamic_symbol ("exit", &info))
    return NULL;

  return info.dli_fname;
}

static gboolean
gum_try_resolve_dynamic_symbol (const gchar * name,
                                Dl_info * info)
{
  gpointer address;

  address = dlsym (RTLD_NEXT, name);
  if (address == NULL)
    address = dlsym (RTLD_DEFAULT, name);
  if (address == NULL)
    return FALSE;

  return dladdr (address, info) != 0;
}

gboolean
gum_process_is_debugger_attached (void)
{
  int mib[4];
  struct kinfo_proc info;
  size_t size;
  int result G_GNUC_UNUSED;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = getpid ();

  size = sizeof (info);

  result = sysctl (mib, G_N_ELEMENTS (mib), &info, &size, NULL, 0);
  g_assert (result == 0);

  return (info.ki_flag & P_TRACED) != 0;
}

GumProcessId
gum_process_get_id (void)
{
  return getpid ();
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return pthread_getthreadid_np ();
}

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  return thr_kill (thread_id, 0) == 0;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data,
                           GumModifyThreadFlags flags)
{
  gboolean success = FALSE;

  if (thread_id == gum_process_get_current_thread_id ())
  {
    ucontext_t uc;
    volatile gboolean modified = FALSE;

    getcontext (&uc);
    if (!modified)
    {
      GumCpuContext cpu_context;

      gum_freebsd_parse_ucontext (&uc, &cpu_context);
      func (thread_id, &cpu_context, user_data);
      gum_freebsd_unparse_ucontext (&cpu_context, &uc);

      modified = TRUE;
      setcontext (&uc);
    }

    success = TRUE;
  }
  else
  {
    GumModifyThreadContext ctx;
    gint child, fd;
    GumCpuContext cpu_context;
    guint i;
    guint8 close_ack;
    ssize_t n;
    int status;

    if (socketpair (AF_UNIX, SOCK_STREAM, 0, ctx.fd) != 0)
      return FALSE;
    ctx.pid = getpid ();
    ctx.target_thread = thread_id;
    ctx.interruptible_thread = pthread_getthreadid_np ();

    child = fork ();
    if (child == -1)
      goto beach;
    if (child == 0)
    {
      gum_do_modify_thread (&ctx);
      _Exit (0);
    }

    fd = ctx.fd[0];
    close (ctx.fd[1]);
    ctx.fd[1] = -1;

    if (!gum_read_chunk (fd, &cpu_context, sizeof (GumCpuContext)))
      goto beach;

    func (thread_id, &cpu_context, user_data);

    if (!gum_write_chunk (fd, &cpu_context, sizeof (GumCpuContext)))
      goto beach;

    n = GUM_TEMP_FAILURE_RETRY (read (fd, &close_ack, sizeof (close_ack)));
    if (n != 0)
      goto beach;

    waitpid (child, &status, 0);

    success = TRUE;

beach:
    for (i = 0; i != G_N_ELEMENTS (ctx.fd); i++)
    {
      gint sockfd = ctx.fd[i];
      if (sockfd != -1)
        close (sockfd);
    }
  }

  return success;
}

static void
gum_do_modify_thread (GumModifyThreadContext * ctx)
{
  const gint fd = ctx->fd[1];
  gboolean attached;
  struct reg regs;
  GumCpuContext cpu_context;

  attached = FALSE;

  close (ctx->fd[0]);
  ctx->fd[0] = -1;

  if (ptrace (PT_ATTACH, ctx->pid, NULL, 0) != 0)
    goto beach;
  attached = TRUE;
  if (!gum_wait_for_child_signal (ctx->pid, SIGSTOP))
    goto beach;

  if (ptrace (PT_GETREGS, ctx->target_thread, (caddr_t) &regs, 0) != 0)
    goto beach;
  if (ptrace (PT_SUSPEND, ctx->target_thread, NULL, 0) != 0)
    goto beach;
  if (ptrace (PT_CONTINUE, ctx->pid, GSIZE_TO_POINTER (1), 0) != 0)
    goto beach;

  gum_freebsd_parse_regs (&regs, &cpu_context);
  if (!gum_write_chunk (fd, &cpu_context, sizeof (GumCpuContext)))
    goto beach;

  if (!gum_read_chunk (fd, &cpu_context, sizeof (GumCpuContext)))
    goto beach;
  gum_freebsd_unparse_regs (&cpu_context, &regs);

  if (thr_kill2 (ctx->pid, ctx->interruptible_thread, SIGSTOP) != 0)
    goto beach;
  if (!gum_wait_for_child_signal (ctx->pid, SIGSTOP))
    goto beach;
  if (ptrace (PT_SETREGS, ctx->target_thread, (caddr_t) &regs, 0) != 0)
    goto beach;

  goto beach;

beach:
  {
    if (attached)
      ptrace (PT_DETACH, ctx->pid, NULL, 0);

    close (fd);

    return;
  }
}

static gboolean
gum_read_chunk (gint fd,
                gpointer buffer,
                gsize length)
{
  gpointer cursor = buffer;
  gsize remaining = length;

  while (remaining != 0)
  {
    ssize_t n;

    n = GUM_TEMP_FAILURE_RETRY (read (fd, cursor, remaining));
    if (n <= 0)
      return FALSE;

    cursor += n;
    remaining -= n;
  }

  return TRUE;
}

static gboolean
gum_write_chunk (gint fd,
                 gconstpointer buffer,
                 gsize length)
{
  gconstpointer cursor = buffer;
  gsize remaining = length;

  while (remaining != 0)
  {
    ssize_t n;

    n = GUM_TEMP_FAILURE_RETRY (write (fd, cursor, remaining));
    if (n <= 0)
      return FALSE;

    cursor += n;
    remaining -= n;
  }

  return TRUE;
}

static gboolean
gum_wait_for_child_signal (pid_t pid,
                           gint expected_signal)
{
  int status;

  if (waitpid (pid, &status, 0) == -1)
    return FALSE;

  if (!WIFSTOPPED (status))
    return FALSE;

  return WSTOPSIG (status) == expected_signal;
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  int mib[4];
  struct kinfo_proc * threads = NULL;
  size_t size;
  guint n, i;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID | KERN_PROC_INC_THREAD;
  mib[3] = getpid ();

  size = 0;
  if (sysctl (mib, G_N_ELEMENTS (mib), NULL, &size, NULL, 0) != 0)
    goto beach;

  while (TRUE)
  {
    size_t previous_size;
    gboolean still_too_small;

    threads = g_realloc (threads, size);

    previous_size = size;
    if (sysctl (mib, G_N_ELEMENTS (mib), threads, &size, NULL, 0) == 0)
      break;

    still_too_small = errno == ENOMEM && size == previous_size;
    if (!still_too_small)
      goto beach;

    size += size / 10;
  }

  n = size / sizeof (struct kinfo_proc);
  for (i = 0; i != n; i++)
  {
    struct kinfo_proc * p = &threads[i];
    GumThreadDetails details;

    details.id = p->ki_tid;
    details.name = (p->ki_tdname[0] != '\0') ? p->ki_tdname : NULL;
    details.state = gum_thread_state_from_proc (p);
    if (!gum_process_modify_thread (details.id, gum_store_cpu_context,
          &details.cpu_context, GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY))
    {
      bzero (&details.cpu_context, sizeof (details.cpu_context));
    }

    if (!func (&details, user_data))
      break;
  }

beach:
  g_free (threads);
}

static void
gum_store_cpu_context (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  memcpy (user_data, cpu_context, sizeof (GumCpuContext));
}

gchar *
gum_freebsd_query_program_path_for_self (GError ** error)
{
  return gum_query_program_path_for_target (-1, error);
}

gchar *
gum_freebsd_query_program_path_for_pid (pid_t pid,
                                        GError ** error)
{
  return gum_query_program_path_for_target (pid, error);
}

static gchar *
gum_query_program_path_for_target (int target,
                                   GError ** error)
{
  gchar * path;
  size_t size;
  int mib[4];

  size = PATH_MAX;
  path = g_malloc (size);

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = target;

  if (sysctl (mib, G_N_ELEMENTS (mib), path, &size, NULL, 0) != 0)
    goto failure;

  if (size == 0)
    path[0] = '\0';

  return path;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    g_free (path);
    return NULL;
  }
}

gboolean
_gum_process_collect_main_module (const GumModuleDetails * details,
                                  gpointer user_data)
{
  GumModuleDetails ** out = user_data;

  *out = gum_module_details_copy (details);

  return FALSE;
}

void
_gum_process_enumerate_modules (GumFoundModuleFunc func,
                                gpointer user_data)
{
  GumEnumerateModulesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  dl_iterate_phdr (gum_emit_module_from_phdr, &ctx);
}

static int
gum_emit_module_from_phdr (struct dl_phdr_info * info,
                           size_t size,
                           void * user_data)
{
  GumEnumerateModulesContext * ctx = user_data;
  gchar * name;
  GumModuleDetails details;
  GumMemoryRange range;
  gboolean is_program_itself, carry_on;
  Elf_Half i;

  name = g_path_get_basename (info->dlpi_name);

  details.name = name;
  details.range = &range;
  details.path = info->dlpi_name;

  is_program_itself = info->dlpi_addr == 0;

  if (is_program_itself)
  {
    gsize page_size_mask = ~((gsize) gum_query_page_size () - 1);
    range.base_address = GPOINTER_TO_SIZE (info->dlpi_phdr) & page_size_mask;
  }
  else
  {
    range.base_address = info->dlpi_addr;
  }

  range.size = 0;
  for (i = 0; i != info->dlpi_phnum; i++)
  {
    const Elf_Phdr * h = &info->dlpi_phdr[i];
    if (h->p_type == PT_LOAD)
      range.size += h->p_memsz;
  }

  carry_on = ctx->func (&details, ctx->user_data);

  g_free (name);

  return carry_on ? 0 : 1;
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
  gum_freebsd_enumerate_ranges (getpid (), prot, func, user_data);
}

void
gum_freebsd_enumerate_ranges (pid_t pid,
                              GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  int mib[4];
  gpointer entries = NULL;
  gpointer cursor, end;
  size_t size;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_VMMAP;
  mib[3] = pid;

  size = 0;
  if (sysctl (mib, G_N_ELEMENTS (mib), NULL, &size, NULL, 0) != 0)
    goto beach;

  while (TRUE)
  {
    size_t previous_size;
    gboolean still_too_small;

    entries = g_realloc (entries, size);

    previous_size = size;
    if (sysctl (mib, G_N_ELEMENTS (mib), entries, &size, NULL, 0) == 0)
      break;

    still_too_small = errno == ENOMEM && size == previous_size;
    if (!still_too_small)
      goto beach;

    size = size * 4 / 3;
  }

  cursor = entries;
  end = entries + size;

  while (cursor != end)
  {
    struct kinfo_vmentry * e = cursor;
    GumRangeDetails details;
    GumMemoryRange range;
    GumFileMapping file;

    if (e->kve_structsize == 0)
      break;

    range.base_address = e->kve_start;
    range.size = e->kve_end - e->kve_start;

    details.range = &range;
    details.protection = gum_page_protection_from_vmentry (e->kve_protection);
    if (e->kve_type == KVME_TYPE_VNODE)
    {
      file.path = e->kve_path;
      file.offset = e->kve_offset;
      file.size = e->kve_vn_size;

      details.file = &file;
    }
    else
    {
      details.file = NULL;
    }

    if ((details.protection & prot) == prot)
    {
      if (!func (&details, user_data))
        goto beach;
    }

    cursor += e->kve_structsize;
  }

beach:
  g_free (entries);
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  /* Not implemented */
}

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
  guint n = 0;
  pthread_attr_t attr;
  void * stack_addr;
  size_t stack_size;
  GumMemoryRange * range;

  pthread_attr_init (&attr);

  if (pthread_attr_get_np (pthread_self (), &attr) != 0)
    goto beach;

  if (pthread_attr_getstack (&attr, &stack_addr, &stack_size) != 0)
    goto beach;

  range = &ranges[0];
  range->base_address = GUM_ADDRESS (stack_addr);
  range->size = stack_size;

  n = 1;

beach:
  pthread_attr_destroy (&attr);

  return n;
}

gint
gum_thread_get_system_error (void)
{
  return errno;
}

void
gum_thread_set_system_error (gint value)
{
  errno = value;
}

gboolean
gum_thread_suspend (GumThreadId thread_id,
                    GError ** error)
{
  if (thr_kill (thread_id, SIGSTOP) != 0)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    return FALSE;
  }
}

gboolean
gum_thread_resume (GumThreadId thread_id,
                   GError ** error)
{
  if (thr_kill (thread_id, SIGCONT) != 0)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    return FALSE;
  }
}

gboolean
gum_thread_set_hardware_breakpoint (GumThreadId thread_id,
                                    guint breakpoint_id,
                                    GumAddress address,
                                    GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Hardware breakpoints are not yet supported on this platform");
  return FALSE;
}

gboolean
gum_thread_unset_hardware_breakpoint (GumThreadId thread_id,
                                      guint breakpoint_id,
                                      GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Hardware breakpoints are not yet supported on this platform");
  return FALSE;
}

gboolean
gum_thread_set_hardware_watchpoint (GumThreadId thread_id,
                                    guint watchpoint_id,
                                    GumAddress address,
                                    gsize size,
                                    GumWatchConditions wc,
                                    GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Hardware watchpoints are not yet supported on this platform");
  return FALSE;
}

gboolean
gum_thread_unset_hardware_watchpoint (GumThreadId thread_id,
                                      guint watchpoint_id,
                                      GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Hardware watchpoints are not yet supported on this platform");
  return FALSE;
}

gboolean
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  if (dlopen (module_name, RTLD_LAZY) == NULL)
    goto not_found;

  return TRUE;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

static void *
gum_module_get_handle (const gchar * module_name)
{
  return dlopen (module_name, RTLD_LAZY | RTLD_NOLOAD);
}

gboolean
gum_module_ensure_initialized (const gchar * module_name)
{
  void * module;

  module = gum_module_get_handle (module_name);
  if (module == NULL)
    return FALSE;
  dlclose (module);

  module = dlopen (module_name, RTLD_LAZY);
  if (module == NULL)
    return FALSE;
  dlclose (module);

  return TRUE;
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumAddress result;
  void * module;

  if (module_name != NULL)
  {
    module = gum_module_get_handle (module_name);
    if (module == NULL)
      return 0;
  }
  else
  {
    module = RTLD_DEFAULT;
  }

  result = GUM_ADDRESS (dlsym (module, symbol_name));

  if (module != RTLD_DEFAULT)
    dlclose (module);

  return result;
}

gboolean
_gum_process_resolve_module_name (const gchar * name,
                                  gchar ** path,
                                  GumAddress * base)
{
  gboolean success = FALSE;
  void * handle = NULL;
  GumResolveModuleNameContext ctx;

  if (name[0] == '/' && base == NULL)
  {
    success = TRUE;

    if (path != NULL)
      *path = g_strdup (name);

    goto beach;
  }

  handle = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);
  if (handle != NULL)
  {
    Link_map * entry;

    if (dlinfo (handle, RTLD_DI_LINKMAP, &entry) != 0)
      goto beach;

    success = TRUE;

    if (path != NULL)
      *path = g_strdup (entry->l_name);

    if (base != NULL)
      *base = GUM_ADDRESS (entry->l_base);

    goto beach;
  }

  ctx.name = name;
  ctx.path = NULL;
  ctx.base = 0;

  gum_process_enumerate_modules (gum_store_module_path_and_base_if_name_matches,
      &ctx);

  success = ctx.path != NULL;

  if (path != NULL)
    *path = g_steal_pointer (&ctx.path);

  if (base != NULL)
    *base = ctx.base;

  g_free (ctx.path);

beach:
  g_clear_pointer (&handle, dlclose);

  return success;
}

static gboolean
gum_store_module_path_and_base_if_name_matches (
    const GumModuleDetails * details,
    gpointer user_data)
{
  GumResolveModuleNameContext * ctx = user_data;

  if (gum_module_path_matches (details->path, ctx->name))
  {
    ctx->path = g_strdup (details->path);
    ctx->base = details->range->base_address;
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_module_path_matches (const gchar * path,
                         const gchar * name_or_path)
{
  const gchar * s;

  if (name_or_path[0] == '/')
    return strcmp (name_or_path, path) == 0;

  if ((s = strrchr (path, '/')) != NULL)
    return strcmp (name_or_path, s + 1) == 0;

  return strcmp (name_or_path, path) == 0;
}

static GumThreadState
gum_thread_state_from_proc (const struct kinfo_proc * p)
{
  switch (p->ki_stat)
  {
    case SRUN:
      return GUM_THREAD_RUNNING;
    case SSTOP:
      return GUM_THREAD_STOPPED;
    case SIDL:
    case SSLEEP:
    case SWAIT:
    case SLOCK:
      return GUM_THREAD_WAITING;
    case SZOMB:
      return GUM_THREAD_UNINTERRUPTIBLE;
    default:
      g_assert_not_reached ();
  }
}

static GumPageProtection
gum_page_protection_from_vmentry (int native_prot)
{
  GumPageProtection prot = GUM_PAGE_NO_ACCESS;

  if ((native_prot & KVME_PROT_READ) != 0)
    prot |= GUM_PAGE_READ;
  if ((native_prot & KVME_PROT_WRITE) != 0)
    prot |= GUM_PAGE_WRITE;
  if ((native_prot & KVME_PROT_EXEC) != 0)
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}

void
gum_freebsd_parse_ucontext (const ucontext_t * uc,
                            GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  const mcontext_t * mc = &uc->uc_mcontext;

  ctx->rip = mc->mc_rip;

  ctx->r15 = mc->mc_r15;
  ctx->r14 = mc->mc_r14;
  ctx->r13 = mc->mc_r13;
  ctx->r12 = mc->mc_r12;
  ctx->r11 = mc->mc_r11;
  ctx->r10 = mc->mc_r10;
  ctx->r9 = mc->mc_r9;
  ctx->r8 = mc->mc_r8;

  ctx->rdi = mc->mc_rdi;
  ctx->rsi = mc->mc_rsi;
  ctx->rbp = mc->mc_rbp;
  ctx->rsp = mc->mc_rsp;
  ctx->rbx = mc->mc_rbx;
  ctx->rdx = mc->mc_rdx;
  ctx->rcx = mc->mc_rcx;
  ctx->rax = mc->mc_rax;
#elif defined (HAVE_ARM64)
  const struct gpregs * gp = &uc->uc_mcontext.mc_gpregs;
  gsize i;

  ctx->pc = gp->gp_elr;
  ctx->sp = gp->gp_sp;
  ctx->nzcv = 0;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    ctx->x[i] = gp->gp_x[i];
  ctx->fp = gp->gp_x[29];
  ctx->lr = gp->gp_lr;

  if ((uc->uc_mcontext.mc_flags & _MC_FP_VALID) != 0)
    memcpy (ctx->v, uc->uc_mcontext.mc_fpregs.fp_q, sizeof (ctx->v));
  else
    memset (ctx->v, 0, sizeof (ctx->v));
#else
# error FIXME
#endif
}

void
gum_freebsd_unparse_ucontext (const GumCpuContext * ctx,
                              ucontext_t * uc)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  mcontext_t * mc = &uc->uc_mcontext;

  mc->mc_rip = ctx->rip;

  mc->mc_r15 = ctx->r15;
  mc->mc_r14 = ctx->r14;
  mc->mc_r13 = ctx->r13;
  mc->mc_r12 = ctx->r12;
  mc->mc_r11 = ctx->r11;
  mc->mc_r10 = ctx->r10;
  mc->mc_r9 = ctx->r9;
  mc->mc_r8 = ctx->r8;

  mc->mc_rdi = ctx->rdi;
  mc->mc_rsi = ctx->rsi;
  mc->mc_rbp = ctx->rbp;
  mc->mc_rsp = ctx->rsp;
  mc->mc_rbx = ctx->rbx;
  mc->mc_rdx = ctx->rdx;
  mc->mc_rcx = ctx->rcx;
  mc->mc_rax = ctx->rax;
#elif defined (HAVE_ARM64)
  struct gpregs * gp = &uc->uc_mcontext.mc_gpregs;
  gsize i;

  gp->gp_elr = ctx->pc;
  gp->gp_sp = ctx->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    gp->gp_x[i] = ctx->x[i];
  gp->gp_x[29] = ctx->fp;
  gp->gp_lr = ctx->lr;

  uc->uc_mcontext.mc_flags = _MC_FP_VALID;
  memcpy (uc->uc_mcontext.mc_fpregs.fp_q, ctx->v, sizeof (ctx->v));
#else
# error FIXME
#endif
}

void
gum_freebsd_parse_regs (const struct reg * regs,
                        GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  ctx->rip = regs->r_rip;

  ctx->r15 = regs->r_r15;
  ctx->r14 = regs->r_r14;
  ctx->r13 = regs->r_r13;
  ctx->r12 = regs->r_r12;
  ctx->r11 = regs->r_r11;
  ctx->r10 = regs->r_r10;
  ctx->r9 = regs->r_r9;
  ctx->r8 = regs->r_r8;

  ctx->rdi = regs->r_rdi;
  ctx->rsi = regs->r_rsi;
  ctx->rbp = regs->r_rbp;
  ctx->rsp = regs->r_rsp;
  ctx->rbx = regs->r_rbx;
  ctx->rdx = regs->r_rdx;
  ctx->rcx = regs->r_rcx;
  ctx->rax = regs->r_rax;
#elif defined (HAVE_ARM64)
  gsize i;

  ctx->pc = regs->elr;
  ctx->sp = regs->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    ctx->x[i] = regs->x[i];
  ctx->fp = regs->x[29];
  ctx->lr = regs->lr;
#else
# error FIXME
#endif
}

void
gum_freebsd_unparse_regs (const GumCpuContext * ctx,
                          struct reg * regs)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs->r_rip = ctx->rip;

  regs->r_r15 = ctx->r15;
  regs->r_r14 = ctx->r14;
  regs->r_r13 = ctx->r13;
  regs->r_r12 = ctx->r12;
  regs->r_r11 = ctx->r11;
  regs->r_r10 = ctx->r10;
  regs->r_r9 = ctx->r9;
  regs->r_r8 = ctx->r8;

  regs->r_rdi = ctx->rdi;
  regs->r_rsi = ctx->rsi;
  regs->r_rbp = ctx->rbp;
  regs->r_rsp = ctx->rsp;
  regs->r_rbx = ctx->rbx;
  regs->r_rdx = ctx->rdx;
  regs->r_rcx = ctx->rcx;
  regs->r_rax = ctx->rax;
#elif defined (HAVE_ARM64)
  gsize i;

  regs->elr = ctx->pc;
  regs->sp = ctx->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    regs->x[i] = ctx->x[i];
  regs->x[29] = ctx->fp;
  regs->lr = ctx->lr;
#else
# error FIXME
#endif
}
```