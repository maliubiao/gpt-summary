Response:
Let's break down the thought process for analyzing this C source code file.

**1. Initial Understanding and Context:**

* **Identify the Project:** The header comment clearly states it's part of Frida, a dynamic instrumentation toolkit. The path `frida/subprojects/frida-gum/gum/backend-windows/` is crucial for understanding its scope: it's a Windows-specific backend implementation within Frida's "gum" (presumably the core instrumentation engine).
* **Purpose of Frida:**  Frida's primary goal is to allow users to inspect and modify the behavior of running processes *without* needing the source code. This immediately suggests that this file will likely deal with low-level OS interactions related to process and thread management, memory manipulation, and debugging.
* **Target Platform:** The path and the inclusion of Windows headers like `windows.h`, `psapi.h`, `tlhelp32.h`, and `dbghelp.h` confirm this file is specifically for Windows.

**2. Code Structure and Key Components:**

* **Includes:**  Examine the included headers. They reveal the core functionalities being used:
    * `gumprocess-priv.h`: Likely contains private definitions and declarations for this module.
    * `gum/gumdbghelp.h`, `gum/gumwindows.h`: Indicate interaction with Windows debugging APIs and potentially other Frida-specific Windows utilities.
    * Standard Windows headers (`intrin.h`, `psapi.h`, `tchar.h`, `tlhelp32.h`):  Essential for process/thread management, memory information, and debugging.
* **Typedefs and Structs:** These define data structures used throughout the code. Pay close attention to:
    * `GumSetHardwareBreakpointContext`, `GumSetHardwareWatchpointContext`:  Clearly related to setting hardware breakpoints and watchpoints – a core debugging feature.
    * `GumModifyDebugRegistersFunc`:  A function pointer indicating the capability to directly manipulate debug registers, a very low-level operation.
    * Other `typedef`s for function pointers like `GumGetThreadDescriptionFunc`, `GumGetCurrentThreadStackLimitsFunc`, etc.:  Show the file interacts with various Windows APIs for thread information.
    * `GumEnumerateSymbolsContext`, `GumFindExportContext`: Point to symbol and export table enumeration, essential for understanding the structure of loaded modules.
* **Static Functions:** These are helper functions internal to this file. Their names provide hints about their purpose: `gum_windows_get_thread_details`, `gum_process_enumerate_heap_ranges`, `gum_do_set_hardware_breakpoint`, etc.
* **Global Functions (prefixed with `gum_process_` or `gum_thread_`):** These are the public interface of this module, likely called by other parts of Frida. Their names are very descriptive (e.g., `gum_process_get_id`, `gum_thread_suspend`, `gum_module_load`).

**3. Functionality Deduction (High-Level):**

Based on the includes, typedefs, and function names, we can start outlining the functionalities:

* **Process Information:** Getting the current process ID, checking if a debugger is attached.
* **Thread Management:** Enumerating threads, getting thread details (ID, name, state, CPU context), suspending and resuming threads.
* **Module Management:** Enumerating modules, loading modules, enumerating imports and exports, finding module base addresses and export addresses, enumerating symbols.
* **Memory Management:** Enumerating memory ranges (with protection information), enumerating heap allocations, getting thread stack limits.
* **Debugging:** Setting and unsetting hardware breakpoints and watchpoints (involves direct manipulation of debug registers).
* **Error Handling:**  Uses `GError` for reporting errors.
* **CPU Architecture Detection:**  Determining the CPU architecture of the current and other processes.

**4. Connecting to Reverse Engineering Concepts:**

* **Dynamic Analysis:** The entire file is about dynamic analysis. Frida injects into running processes, and this code provides the low-level mechanisms for that.
* **Debugging:** The hardware breakpoint/watchpoint functionality is a direct application of debugging techniques. Understanding how debug registers work is key to reverse engineering malware or understanding program behavior.
* **Memory Layout:** Enumerating memory ranges and heap allocations helps in understanding how a process organizes its memory, crucial for finding vulnerabilities or understanding data structures.
* **Module Structure:** Enumerating imports, exports, and symbols allows reverse engineers to understand the dependencies of a program and the functions it exposes, which is fundamental to static and dynamic analysis.
* **API Hooking:** While not directly implemented in this file, the functionalities provided (like finding function addresses) are building blocks for API hooking, a common reverse engineering technique.

**5. Low-Level Details and OS Concepts:**

* **Windows API:**  The code heavily uses the Windows API (Win32 API), demonstrating a need for understanding concepts like handles, processes, threads, modules, memory management, and debugging in Windows.
* **PE File Format:** Enumerating imports and exports requires knowledge of the Portable Executable (PE) file format, the standard executable format on Windows.
* **Context Switching:**  Suspending and resuming threads involves understanding the concept of context switching and how thread states are managed by the OS.
* **Memory Protection:** Enumerating memory ranges with protection attributes (`PAGE_READONLY`, `PAGE_EXECUTE_READWRITE`, etc.) relates to OS-level memory protection mechanisms.
* **Debug Registers (DR0-DR7):**  Setting hardware breakpoints and watchpoints directly interacts with these CPU registers, requiring knowledge of their purpose and how they trigger debugging exceptions.
* **TEB (Thread Environment Block):** Accessing the thread's last error code using `__readfsdword` or `__readgsqword` indicates familiarity with the TEB and its structure (architecture-dependent).
* **System Calls (indirectly):** While not directly making system calls, the Win32 API functions used often wrap system calls to interact with the kernel.

**6. Logical Reasoning and Examples:**

* **Hardware Breakpoints:**  *Hypothetical Input:* User wants to break when `kernel32.dll`'s `LoadLibraryW` is called. *Output:* Frida (using this code) would set a hardware breakpoint at the address of `LoadLibraryW` in the target process. When that address is reached during execution, a debug exception occurs, and Frida can intercept it.
* **Memory Enumeration:** *Hypothetical Input:* User wants to find all executable memory regions. *Output:* Frida would call `gum_process_enumerate_ranges` with the `GUM_PAGE_EXECUTE` flag. This code would then use `VirtualQuery` to iterate through memory regions and identify those with execute permissions, reporting their base address and size.

**7. User Errors and Debugging:**

* **Invalid Thread ID:**  If the user provides an invalid thread ID to a function like `gum_thread_suspend`, `OpenThread` will fail, and the code will handle the error (setting a `GError`). This illustrates potential misuse.
* **Permissions Issues:** Trying to access information about a process without sufficient privileges will lead to errors (e.g., `OpenProcess` failing with `ERROR_ACCESS_DENIED`). Frida needs to run with appropriate permissions to instrument other processes.
* **Incorrect Module Names:**  Providing an incorrect module name to functions like `gum_module_load` or `gum_module_find_export_by_name` will result in the functions not finding the module (e.g., `GetModuleHandleW` returning NULL).

**8. Tracing User Operations:**

A user might interact with this code through Frida's Python or JavaScript API. For example, a Python script might call `frida.attach(...)` to connect to a process, then use functions like `process.enumerate_modules()` or `thread.suspend()`. These high-level API calls eventually translate into calls to the C functions within this `gumprocess-windows.c` file. Debugging would involve setting breakpoints in the Python/JavaScript code and stepping through to see how the calls propagate down to the C level.

**Self-Correction/Refinement during the process:**

* **Initially, I might have focused too much on a single function.**  Realizing that the file provides a broader set of process and thread interaction tools requires stepping back and looking at the overall structure.
* **I might have overlooked some of the more subtle aspects,** like the use of `g_once_init_enter/leave` for thread-safe initialization of static variables or the details of accessing the TEB. A closer reading and understanding of the Windows API documentation would be necessary to grasp these nuances.
* **Connecting the C code to the high-level Frida API requires some knowledge of Frida's architecture.**  Understanding that the Python/JavaScript bindings are essentially wrappers around these C functions is crucial for tracing user operations.

By following this structured approach, combining code analysis with knowledge of the underlying technologies and the purpose of Frida, we can effectively understand the functionality of this C source code file.
好的，让我们来详细分析 `frida/subprojects/frida-gum/gum/backend-windows/gumprocess-windows.c` 这个文件的功能。

**文件功能归纳**

这个文件是 Frida 工具在 Windows 平台上的一个核心组件，主要负责实现与目标进程的交互，包括：

1. **进程信息获取:**  获取当前进程 ID，判断是否有调试器附加。
2. **线程管理:**  枚举进程中的线程，获取线程的详细信息（ID、名称、状态、CPU 上下文），暂停和恢复线程的执行。
3. **模块管理:**  枚举进程加载的模块（DLL），加载新的模块，枚举模块的导入导出表，查找模块的基址和导出函数的地址，枚举模块中的符号。
4. **内存管理:**  枚举进程的内存区域（带有保护属性），枚举进程的堆内存分配，获取线程的栈内存范围。
5. **硬件断点和观察点:**  在指定的线程上设置和取消硬件断点和硬件观察点。
6. **CPU 类型查询:**  查询当前进程以及指定进程的 CPU 类型（x86, x64, ARM64）。
7. **系统错误处理:**  获取和设置线程的最后错误代码。

**与逆向方法的关系及举例说明**

这个文件提供的功能与逆向工程的方法紧密相关，因为它允许逆向工程师在运行时检查和修改目标进程的行为。

* **动态调试:**
    * **硬件断点 (`gum_thread_set_hardware_breakpoint`, `gum_thread_unset_hardware_breakpoint`):**  逆向工程师可以使用硬件断点在特定的代码地址暂停目标进程的执行，从而检查程序的状态，例如变量的值、寄存器的内容等。
        * **举例:**  你想知道 `kernel32.dll` 中的 `CreateFileW` 函数何时被调用，以及它的参数是什么。你可以在 `CreateFileW` 的入口地址设置一个硬件断点。当程序执行到这个地址时，Frida 会中断程序，你可以查看当时的寄存器状态来获取参数信息。
    * **硬件观察点 (`gum_thread_set_hardware_watchpoint`, `gum_thread_unset_hardware_watchpoint`):**  逆向工程师可以使用硬件观察点来监控特定内存地址的访问情况（读、写、执行），当内存被访问时中断程序。
        * **举例:**  你怀疑一个变量 `g_counter` 的值被意外修改。你可以在 `g_counter` 的内存地址设置一个硬件写入观察点。一旦有代码尝试写入这个地址，程序就会中断，你可以追溯是谁修改了该变量。
    * **线程暂停和恢复 (`gum_thread_suspend`, `gum_thread_resume`):**  在调试过程中，可能需要暂停某个线程的执行来仔细分析其状态，或者在修改内存或寄存器后恢复其执行。
* **代码和数据检查:**
    * **模块枚举 (`_gum_process_enumerate_modules`):**  逆向工程师可以获取目标进程加载的所有 DLL，了解程序的模块组成和依赖关系。
    * **导出表枚举 (`gum_module_enumerate_exports`):**  可以查看目标模块导出了哪些函数，这对于理解模块的功能和寻找可利用的接口非常重要。
    * **导入表枚举 (`gum_module_enumerate_imports`):**  可以查看目标模块导入了哪些其他模块的函数，了解模块的依赖关系，以及可能存在的 hook 点。
    * **符号枚举 (`gum_module_enumerate_symbols`):**  可以获取模块中的符号信息（函数名、变量名等），这有助于理解代码的结构和功能，尤其是在有符号信息的程序中。
    * **内存区域枚举 (`_gum_process_enumerate_ranges`):**  可以查看进程的内存布局，了解代码段、数据段、堆栈的位置和属性。
    * **堆内存枚举 (`gum_process_enumerate_malloc_ranges`):**  可以查看进程的堆内存分配情况，对于分析内存泄漏或者查找动态分配的数据结构很有帮助。
* **代码修改 (虽然此文件未直接实现，但为实现奠定了基础):**  虽然这个文件本身不直接修改代码，但它提供了获取模块基址、函数地址等关键信息的能力，这些是 Frida 进行代码注入、hook 和代码修改的基础。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明**

虽然这个文件是 Windows 平台特定的，但其中涉及的概念和技术在其他操作系统上也有对应。

* **二进制底层知识:**
    * **PE 文件格式 (Portable Executable):**  在 `gum_module_enumerate_imports` 和 `gum_module_enumerate_exports` 中，代码需要解析 PE 文件的结构（DOS 头、NT 头、数据目录、导入表、导出表）来获取模块的导入导出信息。这是理解 Windows 可执行文件格式的基础。
    * **内存管理:**  代码使用 `VirtualQuery` 枚举内存区域，涉及到 Windows 的虚拟内存管理机制，如内存页的保护属性 (`PAGE_READONLY`, `PAGE_EXECUTE_READWRITE` 等)。
    * **线程上下文 (CONTEXT):**  在设置和取消硬件断点/观察点以及暂停/恢复线程时，需要操作线程的上下文结构 (`CONTEXT`)，这是一个与 CPU 架构相关的结构，保存了线程的寄存器状态、指令指针等信息。
    * **Debug 寄存器 (DR0-DR7):**  硬件断点和观察点的实现直接操作了 x86/x64 或 ARM64 架构的调试寄存器，这是与 CPU 硬件紧密相关的特性。
* **Linux 内核知识 (对比):**
    * **进程和线程管理:**  Linux 也有类似的进程和线程概念，但 API 不同 (例如，使用 `pthread` 系列函数进行线程管理，读取 `/proc/[pid]/maps` 获取内存映射信息)。
    * **动态链接库 (Shared Objects):**  Linux 下的动态链接库（.so 文件）也有类似的导入导出表概念，但格式不同 (ELF 格式)。
    * **系统调用:**  虽然代码直接调用的是 Windows API，但这些 API 最终会转化为系统调用，与 Linux 内核的系统调用机制类似。
    * **ptrace:**  在 Linux 上，类似于 Frida 的工具通常会使用 `ptrace` 系统调用来进行进程调试和控制。
* **Android 内核及框架知识 (对比):**
    * **进程和线程:** Android 基于 Linux 内核，因此进程和线程的概念类似。
    * **动态链接库 (.so 文件):** Android 也使用 `.so` 文件，格式为 ELF。
    * **ART (Android Runtime):**  在 Android 上进行动态 instrumentation 可能需要考虑 ART 的特性，例如解释执行、JIT 编译等。Frida 在 Android 上的实现会涉及到与 ART 虚拟机的交互。
    * **Binder:**  Android 的进程间通信机制 Binder 在逆向分析 Android 应用时经常需要考虑。

**逻辑推理、假设输入与输出**

代码中包含一些逻辑推理，例如在枚举模块时，会遍历进程的模块句柄列表，然后获取每个模块的详细信息。

* **假设输入:**  Frida 想要枚举目标进程 (PID 1234) 加载的所有模块。
* **输出 (`_gum_process_enumerate_modules` 函数的行为):**
    1. `GetCurrentProcess()` 获取当前 Frida 进程的句柄 (虽然名字叫 GetCurrentProcess，但实际上操作的是目标进程，因为 Frida 通常会attach到目标进程)。
    2. `EnumProcessModules()` 获取目标进程加载的模块句柄列表。
    3. 循环遍历模块句柄列表：
        * `GetModuleInformation()` 获取每个模块的基址、大小等信息。
        * `GetModuleFileNameW()` 获取模块的文件路径。
        * 调用用户提供的回调函数 (`func`)，将模块的详细信息 (`GumModuleDetails`) 传递给它。
        * 如果回调函数返回 `FALSE`，则停止枚举。

* **假设输入:**  Frida 想要查找 `kernel32.dll` 中 `LoadLibraryW` 函数的地址。
* **输出 (`gum_module_find_export_by_name` 函数的行为):**
    1. `get_module_handle_utf8("kernel32.dll")` 获取 `kernel32.dll` 的模块句柄。
    2. `GetProcAddress(module, "LoadLibraryW")` 获取 `LoadLibraryW` 函数的地址。
    3. 返回该地址。

**用户或编程常见的使用错误及举例说明**

* **无效的线程 ID:**  用户可能提供了一个不存在的线程 ID 给 `gum_thread_suspend` 或 `gum_thread_set_hardware_breakpoint`，导致 `OpenThread` 失败。代码中通常会检查 `OpenThread` 的返回值，并返回错误。
    * **举例:**  `gum_thread_suspend(9999, &error)`，如果线程 ID 9999 不存在，`OpenThread` 会返回 `NULL`，函数会设置 `GError` 并返回 `FALSE`。
* **权限不足:**  在尝试操作其他进程的线程或内存时，如果 Frida 进程没有足够的权限，相关的 API 调用 (如 `OpenThread`, `GetThreadContext`) 可能会失败。
    * **举例:**  尝试在以管理员权限运行的进程中设置硬件断点，而 Frida 自身是以普通用户权限运行的，可能会导致 `OpenThread` 失败，并返回 `ERROR_ACCESS_DENIED`。
* **错误的模块名或符号名:**  在使用 `gum_module_find_export_by_name` 等函数时，如果提供了错误的模块名或符号名，函数将无法找到对应的模块或符号，并返回 0。
    * **举例:**  `gum_module_find_export_by_name("krnl32.dll", "LoadLibraryW")` (模块名拼写错误)，`get_module_handle_utf8` 将返回 `NULL`，最终函数返回 0。
* **忘记检查错误:**  编程时，用户可能会忘记检查 Frida 函数的返回值和 `GError`，导致错误被忽略。

**用户操作是如何一步步的到达这里，作为调试线索**

用户通常通过 Frida 的高层 API (如 Python 或 JavaScript API) 与目标进程进行交互。这些高层 API 最终会调用到 `gum` 库的 C 代码。

1. **用户编写 Frida 脚本:**  例如，使用 Python API 来附加到一个进程并设置一个硬件断点：
   ```python
   import frida

   session = frida.attach("target_process")
   # ... 获取要设置断点的线程 ID 和地址 ...
   thread_id = ...
   address = ...
   session.set_hardware_breakpoint(thread_id, address)
   ```

2. **Frida Python 绑定:**  `session.set_hardware_breakpoint`  在 Frida 的 Python 绑定中会调用到相应的 C 代码。

3. **`frida-gum` 库:**  Python 绑定会通过 FFI (Foreign Function Interface) 或类似机制调用到 `frida-gum` 库中的函数，最终会调用到 `gum/backend-windows/gumprocess-windows.c` 中的 `gum_thread_set_hardware_breakpoint` 函数。

4. **系统调用:**  `gum_thread_set_hardware_breakpoint` 函数会调用 Windows API 函数，如 `OpenThread`，`GetThreadContext`，`SetThreadContext`，这些 Windows API 最终会转换为系统调用，与 Windows 内核进行交互，设置硬件断点。

**作为调试线索:**  当你在调试 Frida 脚本时，如果遇到问题，可以按照以下步骤进行排查：

1. **检查 Frida 脚本的逻辑:**  确认你传递给 Frida API 的参数是否正确 (例如，正确的进程名、线程 ID、内存地址)。
2. **查看 Frida 的错误信息:**  Frida 通常会提供详细的错误信息，包括 C 代码中设置的 `GError`。
3. **使用 Frida 的调试功能:**  Frida 提供了一些调试选项，可以输出更详细的日志信息。
4. **如果需要深入调试 `gum` 库:**
    * 你可以尝试编译带有调试符号的 `frida-gum` 库。
    * 使用 C/C++ 调试器 (如 Visual Studio Debugger) 附加到 Frida 运行的进程，然后在 `gumprocess-windows.c` 中设置断点，跟踪代码的执行流程，查看变量的值，以及 Windows API 的返回值。
    * 理解从高层 API 到底层 C 代码的调用链是非常重要的。

**总结 (针对第一部分)**

`gumprocess-windows.c` 文件的主要功能是为 Frida 工具提供了一组用于在 Windows 平台上与目标进程进行交互的底层 API。它实现了诸如进程和线程管理、模块枚举、内存操作以及硬件断点/观察点等核心功能，这些功能是 Frida 进行动态 instrumentation 和逆向工程的基础。该文件大量使用了 Windows API，并涉及到对 PE 文件格式、线程上下文、调试寄存器等底层概念的理解。用户通过 Frida 的高层 API 操作最终会调用到这个文件中的函数。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-windows/gumprocess-windows.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2009-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#define _NO_CVCONST_H
#include "gum/gumdbghelp.h"
#include "gum/gumwindows.h"

#include <intrin.h>
#include <psapi.h>
#include <tchar.h>
#include <tlhelp32.h>

#ifndef _MSC_VER
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Warray-bounds"
#endif

typedef struct _GumSetHardwareBreakpointContext GumSetHardwareBreakpointContext;
typedef struct _GumSetHardwareWatchpointContext GumSetHardwareWatchpointContext;
typedef void (* GumModifyDebugRegistersFunc) (CONTEXT * ctx,
    gpointer user_data);
typedef HRESULT (WINAPI * GumGetThreadDescriptionFunc) (
    HANDLE thread, WCHAR ** description);
typedef void (WINAPI * GumGetCurrentThreadStackLimitsFunc) (
    PULONG_PTR low_limit, PULONG_PTR high_limit);
typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumFindExportContext GumFindExportContext;
typedef BOOL (WINAPI * GumIsWow64ProcessFunc) (HANDLE process, BOOL * is_wow64);
typedef BOOL (WINAPI * GumGetProcessInformationFunc) (HANDLE process,
    PROCESS_INFORMATION_CLASS process_information_class,
    void * process_information, DWORD process_information_size);

struct _GumSetHardwareBreakpointContext
{
  guint breakpoint_id;
  GumAddress address;
};

struct _GumSetHardwareWatchpointContext
{
  guint watchpoint_id;
  GumAddress address;
  gsize size;
  GumWatchConditions conditions;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundSymbolFunc func;
  gpointer user_data;
};

struct _GumFindExportContext
{
  const gchar * symbol_name;
  GumAddress result;
};

static gboolean gum_windows_get_thread_details (DWORD thread_id,
    GumThreadDetails * details);
static gboolean gum_process_enumerate_heap_ranges (HANDLE heap,
    GumFoundMallocRangeFunc func, gpointer user_data);
static void gum_do_set_hardware_breakpoint (CONTEXT * ctx, gpointer user_data);
static void gum_do_unset_hardware_breakpoint (CONTEXT * ctx,
    gpointer user_data);
static void gum_do_set_hardware_watchpoint (CONTEXT * ctx, gpointer user_data);
static void gum_do_unset_hardware_watchpoint (CONTEXT * ctx,
    gpointer user_data);
static gboolean gum_modify_debug_registers (GumThreadId thread_id,
    GumModifyDebugRegistersFunc func, gpointer user_data, GError ** error);
static BOOL CALLBACK gum_emit_symbol (PSYMBOL_INFO info, ULONG symbol_size,
    PVOID user_context);
static gboolean gum_store_address_if_module_has_export (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_store_address_if_export_name_matches (
    const GumExportDetails * details, gpointer user_data);
static HMODULE get_module_handle_utf8 (const gchar * module_name);

const gchar *
gum_process_query_libc_name (void)
{
  return "msvcrt.dll";
}

gboolean
gum_process_is_debugger_attached (void)
{
  return IsDebuggerPresent ();
}

GumProcessId
gum_process_get_id (void)
{
  return GetCurrentProcessId ();
}

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4

GumThreadId
gum_process_get_current_thread_id (void)
{
  return __readfsdword (0x24);
}

#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8

GumThreadId
gum_process_get_current_thread_id (void)
{
  return __readgsdword (0x48);
}

#else

GumThreadId
gum_process_get_current_thread_id (void)
{
  return GetCurrentThreadId ();
}

#endif

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  gboolean found = FALSE;
  HANDLE thread;

  thread = OpenThread (SYNCHRONIZE, FALSE, thread_id);
  if (thread != NULL)
  {
    found = WaitForSingleObject (thread, 0) == WAIT_TIMEOUT;

    CloseHandle (thread);
  }

  return found;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data,
                           GumModifyThreadFlags flags)
{
  gboolean success = FALSE;
  HANDLE thread;
#ifdef _MSC_VER
  __declspec (align (64))
#endif
      CONTEXT context
#ifndef _MSC_VER
        __attribute__ ((aligned (64)))
#endif
        = { 0, };
  GumCpuContext cpu_context;

  thread = OpenThread (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
      THREAD_SUSPEND_RESUME, FALSE, thread_id);
  if (thread == NULL)
    goto beach;

  if (SuspendThread (thread) == (DWORD) -1)
    goto beach;

  context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  if (!GetThreadContext (thread, &context))
    goto beach;

  gum_windows_parse_context (&context, &cpu_context);
  func (thread_id, &cpu_context, user_data);
  gum_windows_unparse_context (&cpu_context, &context);

  if (!SetThreadContext (thread, &context))
  {
    ResumeThread (thread);
    goto beach;
  }

  success = ResumeThread (thread) != (DWORD) -1;

beach:
  if (thread != NULL)
    CloseHandle (thread);

  return success;
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  DWORD this_process_id;
  HANDLE snapshot;
  THREADENTRY32 entry;

  this_process_id = GetCurrentProcessId ();

  snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    goto beach;

  entry.dwSize = sizeof (entry);
  if (!Thread32First (snapshot, &entry))
    goto beach;

  do
  {
    if (RTL_CONTAINS_FIELD (&entry, entry.dwSize, th32OwnerProcessID) &&
        entry.th32OwnerProcessID == this_process_id)
    {
      GumThreadDetails details;

      if (gum_windows_get_thread_details (entry.th32ThreadID, &details))
      {
        if (!func (&details, user_data))
          break;
      }
    }

    entry.dwSize = sizeof (entry);
  }
  while (Thread32Next (snapshot, &entry));

beach:
  if (snapshot != INVALID_HANDLE_VALUE)
    CloseHandle (snapshot);
}

static gboolean
gum_windows_get_thread_details (DWORD thread_id,
                                GumThreadDetails * details)
{
  gboolean success = FALSE;
  static gsize initialized = FALSE;
  static GumGetThreadDescriptionFunc get_thread_description;
  static DWORD desired_access;
  HANDLE thread = NULL;
#ifdef _MSC_VER
  __declspec (align (64))
#endif
      CONTEXT context
#ifndef _MSC_VER
        __attribute__ ((aligned (64)))
#endif
        = { 0, };

  memset (details, 0, sizeof (GumThreadDetails));

  if (g_once_init_enter (&initialized))
  {
    get_thread_description = (GumGetThreadDescriptionFunc) GetProcAddress (
        GetModuleHandle (_T ("kernel32.dll")),
        "GetThreadDescription");

    desired_access = THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME;
    if (get_thread_description != NULL)
      desired_access |= THREAD_QUERY_LIMITED_INFORMATION;

    g_once_init_leave (&initialized, TRUE);
  }

  thread = OpenThread (desired_access, FALSE, thread_id);
  if (thread == NULL)
    goto beach;

  details->id = thread_id;

  if (get_thread_description != NULL)
  {
    WCHAR * name_utf16;

    if (!SUCCEEDED (get_thread_description (thread, &name_utf16)))
      goto beach;

    if (name_utf16[0] != L'\0')
    {
      details->name = g_utf16_to_utf8 ((const gunichar2 *) name_utf16, -1, NULL,
          NULL, NULL);
    }

    LocalFree (name_utf16);
  }

  if (thread_id == GetCurrentThreadId ())
  {
    details->state = GUM_THREAD_RUNNING;

    RtlCaptureContext (&context);
    gum_windows_parse_context (&context, &details->cpu_context);

    success = TRUE;
  }
  else
  {
    DWORD previous_suspend_count;

    previous_suspend_count = SuspendThread (thread);
    if (previous_suspend_count == (DWORD) -1)
      goto beach;

    if (previous_suspend_count == 0)
      details->state = GUM_THREAD_RUNNING;
    else
      details->state = GUM_THREAD_STOPPED;

    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (GetThreadContext (thread, &context))
    {
      gum_windows_parse_context (&context, &details->cpu_context);
      success = TRUE;
    }

    ResumeThread (thread);
  }

beach:
  if (thread != NULL)
    CloseHandle (thread);

  if (!success)
    g_free ((gpointer) details->name);

  return success;
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
  HANDLE this_process;
  HMODULE first_module;
  DWORD modules_size = 0;
  HMODULE * modules = NULL;
  guint mod_idx;

  this_process = GetCurrentProcess ();

  if (!EnumProcessModules (this_process, &first_module, sizeof (first_module),
      &modules_size))
  {
    goto beach;
  }

  modules = (HMODULE *) g_malloc (modules_size);

  if (!EnumProcessModules (this_process, modules, modules_size, &modules_size))
  {
    goto beach;
  }

  for (mod_idx = 0; mod_idx != modules_size / sizeof (HMODULE); mod_idx++)
  {
    MODULEINFO mi;
    WCHAR module_path_utf16[MAX_PATH];
    gchar * module_path, * module_name;
    GumMemoryRange range;
    GumModuleDetails details;
    gboolean carry_on;

    if (!GetModuleInformation (this_process, modules[mod_idx], &mi,
        sizeof (mi)))
    {
      continue;
    }

    GetModuleFileNameW (modules[mod_idx], module_path_utf16, MAX_PATH);
    module_path_utf16[MAX_PATH - 1] = '\0';
    module_path = g_utf16_to_utf8 ((const gunichar2 *) module_path_utf16, -1,
        NULL, NULL, NULL);
    module_name = strrchr (module_path, '\\') + 1;

    range.base_address = GUM_ADDRESS (mi.lpBaseOfDll);
    range.size = mi.SizeOfImage;

    details.name = module_name;
    details.range = &range;
    details.path = module_path;

    carry_on = func (&details, user_data);

    g_free (module_path);

    if (!carry_on)
      break;
  }

beach:
  g_free (modules);
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
  guint8 * cur_base_address;

  cur_base_address = NULL;

  while (TRUE)
  {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret;

    ret = VirtualQuery (cur_base_address, &mbi, sizeof (mbi));
    if (ret == 0)
      break;

    if (mbi.Protect != 0 && (mbi.Protect & PAGE_GUARD) == 0)
    {
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_windows (mbi.Protect);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;
        GumRangeDetails details;

        range.base_address = GUM_ADDRESS (cur_base_address);
        range.size = mbi.RegionSize;

        details.range = &range;
        details.protection = cur_prot;
        details.file = NULL; /* TODO */

        if (!func (&details, user_data))
          return;
      }
    }

    cur_base_address += mbi.RegionSize;
  }
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  HANDLE process_heap;
  DWORD num_heaps;
  HANDLE * heaps;
  DWORD num_heaps_after;
  DWORD i;

  process_heap = GetProcessHeap ();
  if (!gum_process_enumerate_heap_ranges (process_heap, func, user_data))
    return;

  num_heaps = GetProcessHeaps (0, NULL);
  if (num_heaps == 0)
    return;
  heaps = HeapAlloc (process_heap, 0, num_heaps * sizeof (HANDLE));
  if (heaps == NULL)
    return;
  num_heaps_after = GetProcessHeaps (num_heaps, heaps);

  num_heaps = MIN (num_heaps_after, num_heaps);
  for (i = 0; i != num_heaps; i++)
  {
    if (heaps[i] != process_heap)
    {
      if (!gum_process_enumerate_heap_ranges (process_heap, func, user_data))
        break;
    }
  }

  HeapFree (process_heap, 0, heaps);
}

static gboolean
gum_process_enumerate_heap_ranges (HANDLE heap,
                                   GumFoundMallocRangeFunc func,
                                   gpointer user_data)
{
  gboolean carry_on;
  gboolean locked_heap;
  GumMemoryRange range;
  GumMallocRangeDetails details;
  PROCESS_HEAP_ENTRY entry;

  /* HeapLock may fail but it doesn't seem to have any real consequences... */
  locked_heap = HeapLock (heap);

  details.range = &range;
  carry_on = TRUE;
  entry.lpData = NULL;
  while (carry_on && HeapWalk (heap, &entry))
  {
    if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0)
    {
      range.base_address = GUM_ADDRESS (entry.lpData);
      range.size = entry.cbData;
      carry_on = func (&details, user_data);
    }
  }

  if (locked_heap)
    HeapUnlock (heap);

  return carry_on;
}

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
  static gsize initialized = FALSE;
  static GumGetCurrentThreadStackLimitsFunc get_stack_limits = NULL;
  ULONG_PTR low, high;
  GumMemoryRange * range;

  if (g_once_init_enter (&initialized))
  {
    get_stack_limits = (GumGetCurrentThreadStackLimitsFunc) GetProcAddress (
        GetModuleHandle (_T ("kernel32.dll")),
        "GetCurrentThreadStackLimits");

    g_once_init_leave (&initialized, TRUE);
  }

  if (get_stack_limits == NULL)
    return 0;

  get_stack_limits (&low, &high);

  range = &ranges[0];
  range->base_address = low;
  range->size = high - low;

  return 1;
}

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4

gint
gum_thread_get_system_error (void)
{
  gint32 * teb = (gint32 *) __readfsdword (0x18);
  return teb[13];
}

void
gum_thread_set_system_error (gint value)
{
  gint32 * teb = (gint32 *) __readfsdword (0x18);
  if (teb[13] != value)
    teb[13] = value;
}

#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8

gint
gum_thread_get_system_error (void)
{
  gint32 * teb = (gint32 *) __readgsqword (0x30);
  return teb[26];
}

void
gum_thread_set_system_error (gint value)
{
  gint32 * teb = (gint32 *) __readgsqword (0x30);
  if (teb[26] != value)
    teb[26] = value;
}

#else

gint
gum_thread_get_system_error (void)
{
  return (gint) GetLastError ();
}

void
gum_thread_set_system_error (gint value)
{
  SetLastError ((DWORD) value);
}

#endif

gboolean
gum_thread_suspend (GumThreadId thread_id,
                    GError ** error)
{
  gboolean success = FALSE;
  HANDLE thread;

  thread = OpenThread (THREAD_SUSPEND_RESUME, FALSE, thread_id);
  if (thread == NULL)
    goto failure;

  if (SuspendThread (thread) == (DWORD) -1)
    goto failure;

  success = TRUE;
  goto beach;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "Unable to suspend thread: 0x%08lx", GetLastError ());
    goto beach;
  }
beach:
  {
    if (thread != NULL)
      CloseHandle (thread);

    return success;
  }
}

gboolean
gum_thread_resume (GumThreadId thread_id,
                   GError ** error)
{
  gboolean success = FALSE;
  HANDLE thread;

  thread = OpenThread (THREAD_SUSPEND_RESUME, FALSE, thread_id);
  if (thread == NULL)
    goto failure;

  if (ResumeThread (thread) == (DWORD) -1)
    goto failure;

  success = TRUE;
  goto beach;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "Unable to resume thread: 0x%08lx", GetLastError ());
    goto beach;
  }
beach:
  {
    if (thread != NULL)
      CloseHandle (thread);

    return success;
  }
}

gboolean
gum_thread_set_hardware_breakpoint (GumThreadId thread_id,
                                    guint breakpoint_id,
                                    GumAddress address,
                                    GError ** error)
{
  GumSetHardwareBreakpointContext bpc;

  bpc.breakpoint_id = breakpoint_id;
  bpc.address = address;

  return gum_modify_debug_registers (thread_id, gum_do_set_hardware_breakpoint,
      &bpc, error);
}

static void
gum_do_set_hardware_breakpoint (CONTEXT * ctx,
                                gpointer user_data)
{
  GumSetHardwareBreakpointContext * bpc = user_data;

#ifdef HAVE_ARM64
  _gum_arm64_set_breakpoint (ctx->Bcr, ctx->Bvr, bpc->breakpoint_id,
      bpc->address);
#else
  _gum_x86_set_breakpoint (&ctx->Dr7, &ctx->Dr0, bpc->breakpoint_id,
      bpc->address);
#endif
}

gboolean
gum_thread_unset_hardware_breakpoint (GumThreadId thread_id,
                                      guint breakpoint_id,
                                      GError ** error)
{
  return gum_modify_debug_registers (thread_id,
      gum_do_unset_hardware_breakpoint, GUINT_TO_POINTER (breakpoint_id),
      error);
}

static void
gum_do_unset_hardware_breakpoint (CONTEXT * ctx,
                                  gpointer user_data)
{
  guint breakpoint_id = GPOINTER_TO_UINT (user_data);

#ifdef HAVE_ARM64
  _gum_arm64_unset_breakpoint (ctx->Bcr, ctx->Bvr, breakpoint_id);
#else
  _gum_x86_unset_breakpoint (&ctx->Dr7, &ctx->Dr0, breakpoint_id);
#endif
}

gboolean
gum_thread_set_hardware_watchpoint (GumThreadId thread_id,
                                    guint watchpoint_id,
                                    GumAddress address,
                                    gsize size,
                                    GumWatchConditions wc,
                                    GError ** error)
{
  GumSetHardwareWatchpointContext wpc;

  wpc.watchpoint_id = watchpoint_id;
  wpc.address = address;
  wpc.size = size;
  wpc.conditions = wc;

  return gum_modify_debug_registers (thread_id, gum_do_set_hardware_watchpoint,
      &wpc, error);
}

static void
gum_do_set_hardware_watchpoint (CONTEXT * ctx,
                                gpointer user_data)
{
  GumSetHardwareWatchpointContext * wpc = user_data;

#ifdef HAVE_ARM64
  _gum_arm64_set_watchpoint (ctx->Wcr, ctx->Wvr, wpc->watchpoint_id,
      wpc->address, wpc->size, wpc->conditions);
#else
  _gum_x86_set_watchpoint (&ctx->Dr7, &ctx->Dr0, wpc->watchpoint_id,
      wpc->address, wpc->size, wpc->conditions);
#endif
}

gboolean
gum_thread_unset_hardware_watchpoint (GumThreadId thread_id,
                                      guint watchpoint_id,
                                      GError ** error)
{
  return gum_modify_debug_registers (thread_id,
      gum_do_unset_hardware_watchpoint, GUINT_TO_POINTER (watchpoint_id),
      error);
}

static void
gum_do_unset_hardware_watchpoint (CONTEXT * ctx,
                                  gpointer user_data)
{
  guint watchpoint_id = GPOINTER_TO_UINT (user_data);

#ifdef HAVE_ARM64
  _gum_arm64_unset_watchpoint (ctx->Wcr, ctx->Wvr, watchpoint_id);
#else
  _gum_x86_unset_watchpoint (&ctx->Dr7, &ctx->Dr0, watchpoint_id);
#endif
}

static gboolean
gum_modify_debug_registers (GumThreadId thread_id,
                            GumModifyDebugRegistersFunc func,
                            gpointer user_data,
                            GError ** error)
{
  gboolean success = FALSE;
  HANDLE thread = NULL;
  CONTEXT * active_ctx;

  if (thread_id == gum_process_get_current_thread_id () &&
      (active_ctx = gum_windows_get_active_exceptor_context ()) != NULL)
  {
    func (active_ctx, user_data);
  }
  else
  {
    CONTEXT ctx = { 0, };

    thread = OpenThread (
        THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE,
        thread_id);
    if (thread == NULL)
      goto failure;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext (thread, &ctx))
      goto failure;

    func (&ctx, user_data);

    if (!SetThreadContext (thread, &ctx))
      goto failure;
  }

  success = TRUE;
  goto beach;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "Unable to modify debug registers: 0x%08lx", GetLastError ());
    goto beach;
  }
beach:
  {
    if (thread != NULL)
      CloseHandle (thread);

    return success;
  }
}

gboolean
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  gunichar2 * wide_name;
  HMODULE module;

  wide_name = g_utf8_to_utf16 (module_name, -1, NULL, NULL, NULL);
  module = LoadLibraryW ((LPCWSTR) wide_name);
  g_free (wide_name);

  if (module == NULL)
    goto not_found;

  return TRUE;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
        "LoadLibrary failed: 0x%08lx", GetLastError ());
    return FALSE;
  }
}

gboolean
gum_module_ensure_initialized (const gchar * module_name)
{
  HMODULE module;

  module = get_module_handle_utf8 (module_name);

  return module != NULL;
}

void
gum_module_enumerate_imports (const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  gpointer module;
  const guint8 * mod_base;
  const IMAGE_DOS_HEADER * dos_hdr;
  const IMAGE_NT_HEADERS * nt_hdrs;
  const IMAGE_DATA_DIRECTORY * entry;
  const IMAGE_IMPORT_DESCRIPTOR * desc;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  mod_base = (const guint8 *) module;
  dos_hdr = (const IMAGE_DOS_HEADER *) module;
  nt_hdrs = (const IMAGE_NT_HEADERS *) &mod_base[dos_hdr->e_lfanew];
  entry = &nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  desc = (const IMAGE_IMPORT_DESCRIPTOR *) (mod_base + entry->VirtualAddress);

  for (; desc->Characteristics != 0; desc++)
  {
    GumImportDetails details;
    const IMAGE_THUNK_DATA * thunk_data;

    if (desc->OriginalFirstThunk == 0)
      continue;

    details.type = GUM_IMPORT_FUNCTION; /* FIXME: how can we tell? */
    details.name = NULL;
    details.module = (const gchar *) (mod_base + desc->Name);
    details.address = 0;
    details.slot = 0; /* TODO */

    thunk_data = (const IMAGE_THUNK_DATA *)
        (mod_base + desc->OriginalFirstThunk);
    for (; thunk_data->u1.AddressOfData != 0; thunk_data++)
    {
      if ((thunk_data->u1.AddressOfData & IMAGE_ORDINAL_FLAG) != 0)
        continue; /* FIXME: we ignore imports by ordinal */

      details.name = (const gchar *)
          (mod_base + thunk_data->u1.AddressOfData + 2);
      details.address =
          gum_module_find_export_by_name (details.module, details.name);

      if (!func (&details, user_data))
        return;
    }
  }
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  gpointer module;
  const guint8 * mod_base;
  const IMAGE_DOS_HEADER * dos_hdr;
  const IMAGE_NT_HEADERS * nt_hdrs;
  const IMAGE_DATA_DIRECTORY * entry;
  const IMAGE_EXPORT_DIRECTORY * exp;
  const guint8 * exp_start, * exp_end;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  mod_base = (const guint8 *) module;
  dos_hdr = (const IMAGE_DOS_HEADER *) module;
  nt_hdrs = (const IMAGE_NT_HEADERS *) &mod_base[dos_hdr->e_lfanew];
  entry = &nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  exp = (const IMAGE_EXPORT_DIRECTORY *)(mod_base + entry->VirtualAddress);
  exp_start = mod_base + entry->VirtualAddress;
  exp_end = exp_start + entry->Size - 1;

  if (exp->AddressOfNames != 0)
  {
    const DWORD * name_rvas, * func_rvas;
    const WORD * ord_rvas;
    DWORD index;

    name_rvas = (const DWORD *) &mod_base[exp->AddressOfNames];
    ord_rvas = (const WORD *) &mod_base[exp->AddressOfNameOrdinals];
    func_rvas = (const DWORD *) &mod_base[exp->AddressOfFunctions];

    for (index = 0; index < exp->NumberOfNames; index++)
    {
      DWORD func_rva;
      const guint8 * func_address;

      func_rva = func_rvas[ord_rvas[index]];
      func_address = &mod_base[func_rva];
      if (func_address < exp_start || func_address > exp_end)
      {
        GumExportDetails details;

        details.type = GUM_EXPORT_FUNCTION; /* TODO: data exports */
        details.name = (const gchar *) &mod_base[name_rvas[index]];
        details.address = GUM_ADDRESS (func_address);

        if (!func (&details, user_data))
          return;
      }
    }
  }
}

void
gum_module_enumerate_symbols (const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  GumDbghelpImpl * dbghelp;
  HMODULE module;
  GumEnumerateSymbolsContext ctx;

  dbghelp = gum_dbghelp_impl_try_obtain ();
  if (dbghelp == NULL)
    return;

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;
  dbghelp->SymEnumSymbols (GetCurrentProcess (), GPOINTER_TO_SIZE (module),
      NULL, gum_emit_symbol, &ctx);
}

static BOOL CALLBACK
gum_emit_symbol (PSYMBOL_INFO info,
                 ULONG symbol_size,
                 PVOID user_context)
{
  GumEnumerateSymbolsContext * ctx = user_context;
  GumSymbolDetails details;

  details.is_global = info->Tag == SymTagPublicSymbol ||
      (info->Flags & SYMFLAG_EXPORT) != 0;

  if (info->Tag == SymTagPublicSymbol || info->Tag == SymTagFunction)
  {
    details.type = GUM_SYMBOL_FUNCTION;
  }
  else if (info->Tag == SymTagData)
  {
    details.type = ((info->Flags & SYMFLAG_TLSREL) != 0)
        ? GUM_SYMBOL_TLS
        : GUM_SYMBOL_OBJECT;
  }
  else
  {
    return TRUE;
  }

  details.section = NULL;
  details.name = info->Name;
  details.address = info->Address;
  details.size = symbol_size;

  return ctx->func (&details, ctx->user_data);
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  HANDLE this_process;
  HMODULE module;
  MODULEINFO mi;
  guint8 * cur_base_address, * end_address;

  this_process = GetCurrentProcess ();

  module = get_module_handle_utf8 (module_name);
  if (module == NULL)
    return;

  if (!GetModuleInformation (this_process, module, &mi, sizeof (mi)))
    return;

  cur_base_address = (guint8 *) mi.lpBaseOfDll;
  end_address = (guint8 *) mi.lpBaseOfDll + mi.SizeOfImage;

  do
  {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret G_GNUC_UNUSED;

    ret = VirtualQuery (cur_base_address, &mbi, sizeof (mbi));
    g_assert (ret != 0);

    if (mbi.Protect != 0)
    {
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_windows (mbi.Protect);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;
        GumRangeDetails details;

        range.base_address = GUM_ADDRESS (cur_base_address);
        range.size = mbi.RegionSize;

        details.range = &range;
        details.protection = cur_prot;
        details.file = NULL; /* TODO */

        if (!func (&details, user_data))
          return;
      }
    }

    cur_base_address += mbi.RegionSize;
  }
  while (cur_base_address < end_address);
}

void
gum_module_enumerate_sections (const gchar * module_name,
                               GumFoundSectionFunc func,
                               gpointer user_data)
{
}

void
gum_module_enumerate_dependencies (const gchar * module_name,
                                   GumFoundDependencyFunc func,
                                   gpointer user_data)
{
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  return GUM_ADDRESS (get_module_handle_utf8 (module_name));
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  if (module_name == NULL)
  {
    GumFindExportContext ctx;

    ctx.symbol_name = symbol_name;
    ctx.result = 0;

    gum_process_enumerate_modules (gum_store_address_if_module_has_export,
        &ctx);

    return ctx.result;
  }
  else
  {
    HMODULE module;

    module = get_module_handle_utf8 (module_name);
    if (module == NULL)
      return 0;

    return GUM_ADDRESS (GetProcAddress (module, symbol_name));
  }
}

static gboolean
gum_store_address_if_module_has_export (const GumModuleDetails * details,
                                        gpointer user_data)
{
  GumFindExportContext * ctx = user_data;

  gum_module_enumerate_exports (details->path,
      gum_store_address_if_export_name_matches, ctx);

  return ctx->result == 0;
}

static gboolean
gum_store_address_if_export_name_matches (const GumExportDetails * details,
                                          gpointer user_data)
{
  GumFindExportContext * ctx = user_data;

  if (strcmp (details->name, ctx->symbol_name) == 0)
  {
    ctx->result = details->address;
    return FALSE;
  }

  return TRUE;
}

static HMODULE
get_module_handle_utf8 (const gchar * module_name)
{
  HMODULE module;
  gunichar2 * wide_name;

  wide_name = g_utf8_to_utf16 (module_name, -1, NULL, NULL, NULL);
  module = GetModuleHandleW ((LPCWSTR) wide_name);
  g_free (wide_name);

  return module;
}

GumCpuType
gum_windows_query_native_cpu_type (void)
{
  static gsize initialized = FALSE;
  static GumCpuType type;

  if (g_once_init_enter (&initialized))
  {
    SYSTEM_INFO si;

    GetNativeSystemInfo (&si);

    switch (si.wProcessorArchitecture)
    {
      case PROCESSOR_ARCHITECTURE_INTEL:
        type = GUM_CPU_IA32;
        break;
      case PROCESSOR_ARCHITECTURE_AMD64:
        type = GUM_CPU_AMD64;
        break;
      case PROCESSOR_ARCHITECTURE_ARM64:
        type = GUM_CPU_ARM64;
        break;
      default:
        g_assert_not_reached ();
    }

    g_once_init_leave (&initialized, TRUE);
  }

  return type;
}

GumCpuType
gum_windows_cpu_type_from_pid (guint pid,
                               GError ** error)
{
  GumCpuType result = -1;
  HANDLE process;
  static gsize initialized = FALSE;
  static GumIsWow64ProcessFunc is_wow64_process;
  static GumGetProcessInformationFunc get_process_information;

  process = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (process == NULL)
    goto propagate_api_error;

  if (g_once_init_enter (&initialized))
  {
    HMODULE kernel32;

    kernel32 = GetModuleHandle (_T ("kernel32.dll"));

    is_wow64_process = (GumIsWow64ProcessFunc)
        GetProcAddress (kernel32, "IsWow64Process");
    get_process_information = (GumGetProcessInformationFunc)
        GetProcAddress (kernel32, "GetProcessInformation");

    if (get_process_information != NULL)
    {
      NTSTATUS (WINAPI * rtl_get_version) (PRTL_OSVERSIONINFOW info);
      RTL_OSVERSIONINFOW info = { 0, };
      gboolean win11_or_newer;

      rtl_get_version = (NTSTATUS (WINAPI *) (PRTL_OSVERSIONINFOW))
          GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "RtlGetVersion");

      info.dwOSVersionInfoSize = sizeof (info);
      rtl_get_version (&info);

      win11_or_newer =
          info.dwMajorVersion >= 11 ||
          (info.dwMajorVersion == 10 &&
           (info.dwMinorVersion > 0 || info.dwBuildNumber >= 22000));
      if (!win11_or_newer)
        get_process_information = NULL;
    }

    g_once_init_leave (&initialized, TRUE);
  }

  if (get_process_information != NULL)
  {
    PROCESS_MACHINE_INFORMATION info;

    if (!get_process_information (process, ProcessMachineTypeInfo, &info,
          sizeof (info)))
    {
      goto propagate_api_error;
    }

    switch (info.ProcessMachine)
    {
      case IMAGE_FILE_MACHINE_I386:
        result = GUM_CPU_IA32;
        break;
      case IMAGE_FILE_MACHINE_AMD64:
        result = GUM_CPU_AMD64;
        break;
      case IMAGE_FILE_MACHINE_ARM64:
        result = GUM_CPU_ARM64;
        break;
      default:
        g_assert_not_reached ();
    }
  }
  else if (is_wow64_process != NULL)
  {
    BOOL is_wow64;

    if (!is_wow64_process (process, &is_wow64))
      goto propagate_api_error;

    result = is_wow64 ? GUM_CPU_IA32 : gum_windows_query_native_cpu_type ();
  }
  else
  {
    result = gum_windows_query_native_cpu_type ();
  }

  goto beach;

propagate_api_error:
  {
    DWORD code = GetLastError ();

    switch (code)
    {
      case ERROR_INVALID_PARAMETER:
        g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
            "Process not found");
        break;
      case ERROR_ACCESS_DENIED:
        g_set_error (error, GUM_ERROR, GUM_ERROR_PERMISSION_DENIED,
            "Permission denied");
        break;
      default:
        g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
            "Unexpectedly failed with error code: 0x%08x", code);
        break;
    }

    goto beach;
  }
beach:
  {
    if (process != NULL)
      CloseHandle (process);

    return result;
  }
}

void
gum_windows_parse_context (const CONTEXT * context,
                           GumCpuContext * cpu_context)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = context->Eip;

  cpu_context->edi = context->Edi;
  cpu_context->esi = context->Esi;
  cpu_context->ebp = context->Ebp;
  cpu_context->esp = context->Esp;
  cpu_context->ebx = context->Ebx;
  cpu_context->edx = context->Edx;
  cpu_context->ecx = context->Ecx;
  cpu_context->eax = context->Eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOI
```