Response:
Let's break down the thought process for analyzing this C code snippet.

1. **Understand the Goal:** The request asks for a functional overview of the provided C code, specifically within the context of Frida's Stalker component. It also requests connections to reverse engineering, low-level details (Linux, Android, kernel), logical reasoning, potential user errors, and debugging insights. The crucial constraint is to focus *only* on the provided snippet.

2. **Initial Scan for Keywords and Concepts:**  A quick read-through reveals several key terms and concepts related to dynamic instrumentation and low-level system interaction:

    * **`gumstalker.h`:**  This immediately tells us this is the core Stalker implementation.
    * **`frida`:** The context provided confirms this.
    * **`x86`:**  The file path (`backend-x86`) and the presence of `gumx86reader.h`, `gumx86writer.h`, and `gumx86relocator.h` pinpoint the architecture.
    * **Slabs (`GumCodeSlab`, `GumSlowSlab`, `GumDataSlab`):**  These suggest memory management for generated code and data.
    * **Blocks (`GumExecBlock`):**  Likely represent basic blocks of executed code.
    * **Contexts (`GumExecCtx`, `GumInfectContext`):**  Point to the management of execution state and instrumentation settings.
    * **Probes (`GumCallProbe`):** Suggest a mechanism for injecting custom logic at specific points.
    * **Backpatching (`GumBackpatch*`):** Hints at optimization techniques where generated code is modified after initial execution.
    * **Callouts (`GumCalloutEntry`):**  Probably used to invoke user-defined callbacks from the generated code.
    * **`#ifdef` blocks (e.g., `HAVE_WINDOWS`, `HAVE_LINUX`, `HAVE_ANDROID`):** Indicate platform-specific implementations.
    * **System calls (`syscall`, `int 0x80`):**  Highlight interaction with the operating system kernel.
    * **Memory management (`malloc`, `free` implied by slab structures).**
    * **Threading (`GMutex`, `GPrivate`).**
    * **Exception handling (`GumExceptor` for Windows).**

3. **Identify Core Data Structures and Their Roles:**  Focus on the main `struct` definitions:

    * **`GumStalker`:**  The central object, managing global Stalker state (slabs, contexts, probes, etc.).
    * **`GumExecCtx`:**  Per-thread context for Stalker, holding the state of the instrumented execution (code writers, slabs, current block, etc.).
    * **`GumExecBlock`:** Represents a contiguous block of instrumented code.
    * **Slab Structures (`GumCodeSlab`, `GumSlowSlab`, `GumDataSlab`):**  Efficient memory allocators for generated code (fast and slow paths) and data.

4. **Infer Functionality from Data Structures and Definitions:** Based on the identified structures:

    * **Code Instrumentation:** The presence of code slabs, writers, and relocators strongly suggests that Stalker dynamically generates and modifies code.
    * **Tracing/Profiling:** The `GumEventSink` and the various event types within `GumExecBlock`'s writing functions (e.g., `gum_exec_block_write_call_event_code`) suggest the ability to trace execution flow.
    * **Function Hooking/Interception:**  `GumCallProbe` likely allows users to inject code before or after function calls.
    * **Optimization:** Backpatching aims to optimize frequently executed code paths.
    * **Thread Context Management:** `GumExecCtx` manages the instrumentation state for individual threads.

5. **Connect to Reverse Engineering Concepts:**

    * **Dynamic Analysis:** Stalker is a prime example of a dynamic analysis tool, observing program behavior at runtime.
    * **Code Injection:** The "infect" and "disinfect" functions, along with the code generation mechanisms, clearly involve injecting code into the target process.
    * **Hooking:**  `GumCallProbe` is a hooking mechanism.
    * **Tracing:** The event emission capabilities are for tracing execution.

6. **Identify Low-Level Interactions:**

    * **Memory Management:** Slab allocators manage memory regions. The code likely interacts with virtual memory APIs (e.g., `mmap` or `VirtualAlloc` implicitly through GLib).
    * **CPU Architecture (x86):**  The `gumx86*` files and the handling of registers and instructions are directly tied to the x86 architecture.
    * **Operating System (Linux/Android/Windows):** The `#ifdef` blocks indicate platform-specific handling of signals, exceptions, system calls, and memory management. Linux kernel interactions are evident in the syscall handling.
    * **Process Context:** Stalker operates within the context of the target process.

7. **Consider Logical Reasoning (Hypothetical Input/Output):**  Imagine a simple function call. Stalker would:

    * **Input:** The address of the function being called.
    * **Processing:** Allocate a `GumExecBlock`, generate instrumented code (potentially including a call to a probe), and set up backpatching.
    * **Output:** Execution jumps to the generated code, the probe is executed (if present), and eventually, the original function is called (or execution continues as modified).

8. **Think About User Errors:**

    * **Incorrect Configuration:** Misconfiguring exclusions could lead to unexpected behavior.
    * **Resource Exhaustion:**  Although less likely in this snippet, improper use could theoretically lead to excessive memory allocation.
    * **Race Conditions:** Concurrent access to Stalker's data structures (without proper locking) could cause issues.

9. **Trace User Operations (Debugging Clues):** How does a user arrive at this code?

    * **Frida Scripting:**  A user writes a Frida script that uses the `Stalker` API (e.g., `Stalker.follow()`).
    * **API Calls:** The JavaScript/Python Frida bindings interact with the core Frida library, eventually calling functions that lead to the execution of `gumstalker-x86.c`.
    * **Debugging Scenario:** When debugging a Frida script or the Stalker itself, stepping through the code would lead into this file.

10. **Structure the Output:**  Organize the findings into clear categories (Functionality, Reverse Engineering, Low-Level Details, etc.) as requested. Use bullet points for readability.

11. **Refine and Elaborate:** Review the initial analysis and add more detail where necessary. For example, explain *why* slabs are used (memory management efficiency).

By following this structured approach, even without deep prior knowledge of the specific codebase, one can effectively analyze the provided code snippet and address the various aspects of the request. The key is to look for patterns, keywords, and architectural hints within the code.
这是 frida 动态插桩工具中 `frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c` 文件的第一部分源代码。这个文件是针对 x86 架构的 Stalker 组件的实现，Stalker 是 Frida 中用于动态代码跟踪和插桩的核心组件。

**第一部分功能归纳:**

这部分代码主要负责定义 Stalker 组件的数据结构、初始化以及一些核心的底层操作。它建立了 Stalker 运行所需的内存管理框架、上下文环境，并包含了与操作系统交互的一些基本接口。

**详细功能列举:**

1. **头文件包含和宏定义:**
   - 包含了 Stalker 自身需要的头文件 (`gumstalker.h`)，以及各种辅助模块的头文件 (`gummetalhash.h`, `gumx86reader.h`, `gumx86writer.h` 等)，这些模块分别负责哈希表、x86 指令读取、x86 指令写入等功能。
   - 包含了标准库头文件 (`stdlib.h`, `string.h`) 以及平台相关的头文件 (`windows.h`, `psapi.h`, `sys/syscall.h`, `unwind.h` 等)。
   - 定义了大量的宏，例如代码段和数据段的初始大小和动态增长大小 (`GUM_CODE_SLAB_SIZE_INITIAL`, `GUM_CODE_SLAB_SIZE_DYNAMIC` 等)，以及一些与指令大小、寄存器索引、魔数相关的常量。

2. **数据结构定义:**
   - 定义了各种核心的数据结构，例如：
     - `GumStalker`: Stalker 组件的主要结构体，包含了全局状态，如内存 slab 管理、互斥锁、上下文列表、排除范围等。
     - `GumInfectContext`, `GumDisinfectContext`, `GumActivation`, `GumInvalidateContext`:  与 Stalker 的激活、失效相关的上下文结构。
     - `GumCallProbe`: 用于实现函数调用探针（hook）的结构体。
     - `GumExecCtx`: 每个线程的执行上下文，包含了代码生成器、内存 slab、当前执行的 block 等信息。
     - `GumExecBlock`: 代表被 Stalker 跟踪的一段代码块。
     - `GumCodeSlab`, `GumSlowSlab`, `GumDataSlab`: 用于管理 Stalker 生成的代码和数据的内存 slab。
     - `GumGeneratorContext`: 代码生成过程中的上下文信息。
     - `GumCalloutEntry`: 用于存储用户自定义的回调函数信息。
     - `GumInstruction`: 代表一条 x86 指令。
     - `GumBranchTarget`: 代表一个分支目标地址的信息。
     - `GumBackpatch*`:  定义了不同类型的回填信息，用于优化 Stalker 生成的代码。
     - `GumIcEntry`:  用于内联缓存的条目。
   - 这些结构体共同构成了 Stalker 运行的基础框架，用于存储和管理插桩过程中的各种信息。

3. **枚举类型定义:**
   - 定义了各种枚举类型，用于表示不同的状态、模式和类型，例如：
     - `GumExecCtxState`, `GumExecCtxMode`: 执行上下文的状态和模式。
     - `GumExecBlockFlags`: 执行块的标志。
     - `GumPrologType`: 函数 prolog 的类型。
     - `GumCodeContext`: 代码上下文，例如是否可中断。
     - `GumBackpatchType`: 回填的类型。
     - `GumVirtualizationRequirements`:  虚拟化需求。

4. **函数声明:**
   - 声明了大量的内部函数，这些函数实现了 Stalker 的各种核心功能，例如：
     - `_gum_stalker_do_follow_me`: 开始跟踪当前线程。
     - `gum_stalker_infect`, `gum_stalker_disinfect`:  感染和解除感染线程，将 Stalker 的控制流注入到目标线程。
     - `_gum_stalker_do_activate`, `_gum_stalker_do_deactivate`: 激活和停用 Stalker。
     - `gum_stalker_do_invalidate`: 使缓存的插桩代码失效。
     - `gum_stalker_create_exec_ctx`, `gum_stalker_destroy_exec_ctx`: 创建和销毁线程执行上下文。
     - `gum_exec_ctx_new`, `gum_exec_ctx_free`: 分配和释放执行上下文。
     - `gum_code_slab_new`, `gum_slow_slab_new`, `gum_data_slab_new`: 创建不同类型的内存 slab。
     - 大量的 `gum_exec_block_*` 函数：用于操作执行块，例如创建、清除、提交、回填、写入事件代码等。
     - 大量的 `gum_exec_ctx_write_*` 函数：用于向代码生成器写入不同的代码片段，例如 prolog、epilog、helper 函数等。

5. **属性定义:**
   - 使用 GObject 框架定义了 Stalker 对象的属性，例如 `ic_entries` (内联缓存条目数) 和 `adj_blocks` (预取的相邻代码块数)。

6. **全局变量和私有数据:**
   - 定义了全局私有数据 `gum_stalker_exec_ctx_private`，可能用于存储线程本地的执行上下文。
   - 定义了 `_gum_thread_exit_impl`，用于存储线程退出函数的地址。
   - 在 Linux 平台下定义了 `gum_int80_code` 和 `gum_syscall_code`，分别代表 `int 0x80` 和 `syscall` 指令的字节码。

7. **平台特定代码:**
   - 使用 `#ifdef` 预处理指令包含了针对不同操作系统的特定代码，例如 Windows 和 Linux，处理例如异常、系统调用等。

**与逆向方法的关系及举例:**

Stalker 本身就是一个强大的动态逆向工具，它通过动态地修改目标进程的执行流程来实现代码跟踪和插桩。

- **代码跟踪:** Stalker 可以跟踪目标程序执行的每一条指令或代码块，记录执行路径。例如，通过设置 `GumEventType` 为 `GUM_EVENT_EXEC` 或 `GUM_EVENT_BLOCK`，Stalker 可以在程序执行到新的指令或代码块时发出事件，逆向工程师可以监听这些事件来了解程序的执行流程。
- **函数 Hook:** `GumCallProbe` 允许在函数调用前后插入自定义的代码。例如，逆向工程师可以使用它来拦截特定函数的调用，查看函数的参数和返回值，或者修改函数的行为。
- **动态修改代码:** Stalker 可以修改目标程序的代码，例如插入断点、修改函数实现等。虽然这部分代码主要关注 Stalker 的基础设施，但其目标是支持动态代码修改。

**涉及到二进制底层、Linux, Android 内核及框架的知识及举例:**

- **二进制底层:**
    - **指令编码:** 文件中涉及到对 x86 指令的读取 (`gumx86reader.h`) 和写入 (`gumx86writer.h`)，需要理解 x86 指令的编码格式。
    - **寄存器操作:**  代码中使用了 `GumCpuContext` 来保存 CPU 的上下文信息，涉及到对各种 x86 寄存器的操作。例如，`GUM_STATE_PRESERVE_TOPMOST_REGISTER_INDEX` 定义了栈顶寄存器的索引。
    - **内存管理:** Stalker 使用了 Slab 分配器来高效管理内存，这是一种常见的内核内存管理技术。
- **Linux 内核:**
    - **系统调用:** 代码中包含了对 Linux 系统调用的处理，例如 `syscall` 和 `int 0x80` 指令 (`gum_syscall_code`, `gum_int80_code`)。Stalker 需要能够识别和处理这些系统调用，以便在系统调用前后进行插桩。
    - **异常处理 (Unwind):**  在 Linux 上，Stalker 可能会尝试集成异常处理机制 (`unwind.h`)，以便在异常发生时进行处理。
    - **线程创建 (`clone`):** 注释中提到如果遇到 `clone` 系统调用，需要“burn a page”，这涉及到对 Linux 线程创建机制的理解。
- **Android 内核及框架:**
    - 代码中使用了 `#ifndef HAVE_ANDROID` 来区分非 Android 平台的一些特性，例如与 `guminterceptor.h` 相关的代码。这表明 Android 平台的 Stalker 实现可能有所不同，可能需要考虑 Android 特有的进程和线程模型。
- **Windows 操作系统:**
    - **PE 文件格式:**  虽然这部分代码没有直接涉及 PE 文件解析，但理解 Windows 可执行文件的加载和执行过程对于理解 Stalker 的工作原理至关重要。
    - **Windows API:**  代码中使用了 Windows API，例如 `GetModuleHandle`, `GetModuleInformation`, `VirtualQuery` 等，用于获取模块信息和查询内存状态。
    - **异常处理:** 在 Windows 上，Stalker 使用 `GumExceptor` 来处理异常。
    - **WOW64:**  代码中包含了对 WOW64 (Windows 32-bit On Windows 64-bit) 的支持，需要处理 32 位和 64 位代码之间的转换。

**逻辑推理及假设输入与输出:**

假设 Stalker 尝试跟踪一个简单的函数调用：

```c
int add(int a, int b) {
  return a + b;
}

int main() {
  int result = add(1, 2);
  return 0;
}
```

- **假设输入:** `add` 函数的起始地址。
- **Stalker 的处理逻辑:**
    1. 当程序执行到 `add` 函数时，Stalker 会拦截执行流。
    2. Stalker 会在 `code_slab` 中生成一段新的代码，这段代码可能包含：
        - 保存当前 CPU 状态的 prolog。
        - 如果有注册 `GumCallProbe`，则调用 probe 的代码。
        - 跳转到原始 `add` 函数的代码。
        - 从原始 `add` 函数返回后，如果有注册 `GumCallProbe`，则调用 probe 的代码。
        - 恢复 CPU 状态的 epilog。
        - 跳转回调用 `add` 函数的位置。
    3. Stalker 会修改原始的调用指令，使其跳转到生成的这段新代码。
- **假设输出 (事件):**
    - 如果启用了 `GUM_EVENT_CALL`，Stalker 会发出一个 call 事件，包含 `add` 函数的地址和参数 (如果可以获取)。
    - 如果启用了 `GUM_EVENT_EXEC` 或 `GUM_EVENT_BLOCK`，Stalker 会发出多个 exec 或 block 事件，记录执行到生成代码块和原始 `add` 函数的执行过程。
    - 如果有 `GumCallProbe` 注册，probe 的回调函数会被调用，可以访问 `add` 函数的参数和返回值。

**用户或编程常见的使用错误及举例:**

- **未正确处理平台差异:** 用户可能在编写 Frida 脚本时没有考虑到不同平台 (例如 Windows 和 Linux) 的差异，导致 Stalker 的行为不一致或者出错。例如，假设用户直接操作了某些平台特定的寄存器，而没有进行平台判断。
- **过度或不必要的插桩:** 用户可能会对性能敏感的代码进行过多的插桩，导致程序运行速度显著下降。
- **内存管理错误:** 虽然 Stalker 自身管理内存，但如果用户在 `GumCalloutEntry` 中使用了自定义的 `data` 和 `data_destroy`，需要确保正确管理这些内存，避免内存泄漏。
- **竞争条件:** 如果多个 Frida 脚本或操作同时修改 Stalker 的状态，可能会导致竞争条件。

**用户操作如何一步步到达这里作为调试线索:**

1. **编写 Frida 脚本:** 用户首先编写一个 Frida 脚本，使用 `Stalker` API 来跟踪目标进程的执行。例如，使用 `Stalker.follow()` 函数开始跟踪。
2. **连接到目标进程:** 用户使用 Frida 客户端 (例如 Python 脚本或 frida-cli) 连接到目标进程。
3. **Frida 加载 Gum 库:** Frida 客户端会将 Gum 库 (包含 Stalker) 加载到目标进程中。
4. **调用 Stalker API:**  用户在脚本中调用的 `Stalker.follow()` 等 API 会最终调用到 Gum 库中相应的 C 函数。
5. **`gum_stalker_do_follow_me` 等函数被调用:**  例如，`Stalker.follow()` 会触发 `gum_stalker_do_follow_me` 函数的执行，这个函数会创建 `GumExecCtx`，设置跟踪选项等。
6. **代码执行到 `gumstalker-x86.c`:** 当目标进程执行到被 Stalker 插桩的代码时，控制流会跳转到 Stalker 生成的代码中，这些代码的生成和管理逻辑就在 `gumstalker-x86.c` 中实现。
7. **调试线索:**  在调试过程中，如果用户设置了断点或者通过日志输出来查看执行流程，他们可能会发现程序执行到了 `gumstalker-x86.c` 中的某个函数，例如内存分配、代码生成、回填等相关的函数。通过查看这些函数的调用栈、参数和局部变量，可以了解 Stalker 的具体工作过程和状态。

总而言之，`gumstalker-x86.c` 的第一部分为 Frida 的 Stalker 组件在 x86 架构上奠定了基础，定义了核心的数据结构和接口，并处理了与操作系统交互的一些基本操作。它是理解 Stalker 工作原理的关键入口。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2009-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 * Copyright (C) 2020      Duy Phan Thanh <phanthanhduypr@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumstalker.h"

#include "gummetalhash.h"
#include "gumx86reader.h"
#include "gumx86writer.h"
#include "gummemory.h"
#include "gumx86relocator.h"
#include "gumspinlock.h"
#include "gumstalker-priv.h"
#ifdef HAVE_WINDOWS
# include "gumexceptor.h"
#endif
#ifdef HAVE_LINUX
# include "gum-init.h"
# include "gumelfmodule.h"
#endif
#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
# include "guminterceptor.h"
#endif

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_WINDOWS
# define VC_EXTRALEAN
# include <windows.h>
# include <psapi.h>
# include <tchar.h>
#endif
#ifdef HAVE_LINUX
# include <sys/syscall.h>
# ifndef HAVE_ANDROID
#  include <unwind.h>
# endif
# ifndef __NR_clone3
#  define __NR_clone3 435
# endif
#endif

#define GUM_CODE_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_CODE_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_SLOW_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_SLOW_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_DATA_SLAB_SIZE_INITIAL  (GUM_CODE_SLAB_SIZE_INITIAL / 5)
#define GUM_DATA_SLAB_SIZE_DYNAMIC  (GUM_CODE_SLAB_SIZE_DYNAMIC / 5)
#define GUM_SCRATCH_SLAB_SIZE       16384
/*
 * If we encounter the `clone` syscall, then we have to burn a page to prevent
 * issues with both threads running in the same page.
 */
#define GUM_EXEC_BLOCK_MIN_CAPACITY (1024 + 8192)
#define GUM_DATA_BLOCK_MIN_CAPACITY (sizeof (GumExecBlock) + 1024)

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_INVALIDATE_TRAMPOLINE_SIZE            16
# define GUM_STATE_PRESERVE_TOPMOST_REGISTER_INDEX 3
# define GUM_IC_MAGIC_EMPTY                        0xdeadface
# define GUM_IC_MAGIC_SCRATCH                      0xcafef00d
#else
# define GUM_INVALIDATE_TRAMPOLINE_SIZE            17
# define GUM_STATE_PRESERVE_TOPMOST_REGISTER_INDEX 9
# define GUM_IC_MAGIC_EMPTY                        0xbaadd00ddeadface
# define GUM_IC_MAGIC_SCRATCH                      0xbaadd00dcafef00d
#endif
#define GUM_MINIMAL_PROLOG_RETURN_OFFSET \
    ((GUM_STATE_PRESERVE_TOPMOST_REGISTER_INDEX + 2) * sizeof (gpointer))
#define GUM_FULL_PROLOG_RETURN_OFFSET \
    (sizeof (GumCpuContext) + sizeof (gpointer))
#define GUM_X86_THUNK_ARGLIST_STACK_RESERVE 64 /* x64 ABI compatibility */

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;
typedef struct _GumActivation GumActivation;
typedef struct _GumInvalidateContext GumInvalidateContext;
typedef struct _GumCallProbe GumCallProbe;

typedef struct _GumExecCtx GumExecCtx;
typedef guint GumExecCtxMode;
typedef void (* GumExecHelperWriteFunc) (GumExecCtx * ctx, GumX86Writer * cw);
typedef struct _GumExecBlock GumExecBlock;
typedef guint GumExecBlockFlags;
typedef gpointer (* GumExecCtxReplaceCurrentBlockFunc) (GumExecBlock * block,
    gpointer start_address, gpointer from_insn);

typedef struct _GumCodeSlab GumCodeSlab;
typedef struct _GumSlowSlab GumSlowSlab;
typedef struct _GumDataSlab GumDataSlab;
typedef struct _GumSlab GumSlab;

typedef guint GumPrologType;
typedef guint GumCodeContext;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;
typedef guint GumBackpatchType;
typedef struct _GumBackpatchCall GumBackpatchCall;
typedef struct _GumBackpatchRet GumBackpatchRet;
typedef struct _GumBackpatchJmp GumBackpatchJmp;
typedef struct _GumBackpatchInlineCache GumBackpatchInlineCache;
typedef struct _GumIcEntry GumIcEntry;

typedef guint GumVirtualizationRequirements;

#ifdef HAVE_WINDOWS
# if GLIB_SIZEOF_VOID_P == 8
typedef DWORD64 GumNativeRegisterValue;
# else
typedef DWORD GumNativeRegisterValue;
# endif
#endif

#ifdef HAVE_LINUX
typedef struct _GumCheckElfSection GumCheckElfSection;
#endif

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
typedef struct _Unwind_Exception _Unwind_Exception;
typedef struct _Unwind_Context _Unwind_Context;
struct dwarf_eh_bases;
#endif

enum
{
  PROP_0,
  PROP_IC_ENTRIES,
  PROP_ADJACENT_BLOCKS,
};

struct _GumStalker
{
  GObject parent;

  guint ic_entries;
  /*
   * Stalker compiles each block on demand. However, when we reach the end of a
   * given block, we may encounter an instruction (e.g. a Jcc or a CALL) which
   * means whilst we have reached the end of the block, another block of code
   * will immediately follow it. In the event of a Jcc, we know that if the
   * branch is not taken, then control flow will continue immediately to that
   * adjacent block.
   *
   * By fetching these adjacent blocks ahead of time, before they are needed to
   * be executed, we can ensure that they will also occur adjacently in their
   * instrumented form in the code_slab. Therefore when we come to backpatch
   * between such adjacent blocks, we can instead replace the usual JMP
   * statement with a NOP slide and gain a bit of performance.
   */
  guint adj_blocks;

  gsize ctx_size;
  gsize ctx_header_size;

  goffset thunks_offset;
  gsize thunks_size;

  goffset code_slab_offset;
  gsize code_slab_size_initial;
  gsize code_slab_size_dynamic;

  /*
   * The instrumented code which Stalker generates is split into two parts.
   * There is the part which is always run (the fast path) and the part which
   * is run only when attempting to find the next block and call the backpatcher
   * (the slow path). Backpatching is applied to the fast path so that
   * subsequent executions no longer need to transit the slow path.
   *
   * By separating the code in this way, we can improve the locality of the code
   * executing in the fast path. This has a performance benefit as well as
   * making the backpatched code much easier to read when working in the
   * debugger.
   *
   * The slow path makes use of its own slab and its own code writer.
   */
  goffset slow_slab_offset;
  gsize slow_slab_size_initial;
  gsize slow_slab_size_dynamic;

  goffset data_slab_offset;
  gsize data_slab_size_initial;
  gsize data_slab_size_dynamic;

  goffset scratch_slab_offset;
  gsize scratch_slab_size;

  gsize page_size;
  GumCpuFeatures cpu_features;
  gboolean is_rwx_supported;

  GMutex mutex;
  GSList * contexts;

  GArray * exclusions;
  gint trust_threshold;
  volatile gboolean any_probes_attached;
  volatile gint last_probe_id;
  GumSpinlock probe_lock;
  GHashTable * probe_target_by_id;
  GHashTable * probe_array_by_address;

#ifdef HAVE_WINDOWS
  GumExceptor * exceptor;
# if GLIB_SIZEOF_VOID_P == 4
  gpointer user32_start, user32_end;
  gpointer ki_user_callback_dispatcher_impl;
  GArray * wow_transition_impls;
# endif
#endif
};

struct _GumInfectContext
{
  GumStalker * stalker;
  GumStalkerTransformer * transformer;
  GumEventSink * sink;
};

struct _GumDisinfectContext
{
  GumExecCtx * exec_ctx;
  gboolean success;
};

struct _GumActivation
{
  GumExecCtx * ctx;
  gboolean pending;
  gconstpointer target;
};

struct _GumInvalidateContext
{
  GumExecBlock * block;
  gboolean is_executing_target_block;
};

struct _GumCallProbe
{
  gint ref_count;
  GumProbeId id;
  GumCallProbeCallback callback;
  gpointer user_data;
  GDestroyNotify user_notify;
};

struct _GumExecCtx
{
  volatile gint state;
  GumExecCtxMode mode;
  gint64 destroy_pending_since;

  GumStalker * stalker;
  GumThreadId thread_id;
#ifdef HAVE_WINDOWS
  GumNativeRegisterValue previous_pc;
  GumNativeRegisterValue previous_dr0;
  GumNativeRegisterValue previous_dr1;
  GumNativeRegisterValue previous_dr2;
  GumNativeRegisterValue previous_dr7;
#endif

  GumX86Writer code_writer;
  GumX86Writer slow_writer;
  GumX86Relocator relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerOutput * output);
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * event,
      GumCpuContext * cpu_context);
  GumStalkerObserver * observer;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gpointer pending_return_location;
  guint pending_calls;

  gpointer resume_at;
  gpointer return_at;
  gpointer app_stack;
  gconstpointer activation_target;

  gpointer thunks;
  gpointer infect_thunk;
  GumAddress infect_body;

  GumSpinlock code_lock;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumDataSlab * data_slab;
  GumCodeSlab * scratch_slab;
  GumMetalHashTable * mappings;
  gpointer last_prolog_minimal;
  gpointer last_epilog_minimal;
  gpointer last_prolog_full;
  gpointer last_epilog_full;
  gpointer last_invalidator;

  /*
   * GumExecBlocks are attached to a singly linked list when they are generated,
   * this allows us to store other data in the data slab (rather than relying on
   * them being found in there in sequential order).
   */
  GumExecBlock * block_list;

  /*
   * Stalker for x86 no longer makes use of a shadow stack for handling CALL/RET
   * instructions, so we instead keep a count of the depth of the stack here
   * when GUM_CALL or GUM_RET events are enabled.
   */
  gint depth;

#ifdef HAVE_LINUX
  gpointer last_int80;
  gpointer last_syscall;
  GumAddress syscall_end;
# ifndef HAVE_ANDROID
  GumMetalHashTable * excluded_calls;
# endif
#endif
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

enum _GumExecCtxMode
{
  GUM_EXEC_CTX_NORMAL,
  GUM_EXEC_CTX_SINGLE_STEPPING_ON_CALL,
  GUM_EXEC_CTX_SINGLE_STEPPING_THROUGH_CALL
};

struct _GumExecBlock
{
  GumExecBlock * next;
  GumExecCtx * ctx;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumExecBlock * storage_block;

  guint8 * real_start;
  guint8 * code_start;
  guint8 * slow_start;
  guint real_size;
  guint code_size;
  guint slow_size;
  guint capacity;
  guint last_callout_offset;

  GumExecBlockFlags flags;
  gint recycle_count;

  GumIcEntry * ic_entries;
};

enum _GumExecBlockFlags
{
  GUM_EXEC_BLOCK_ACTIVATION_TARGET = 1 << 0,
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  GumSlab * next;
};

struct _GumCodeSlab
{
  GumSlab slab;

  gpointer invalidator;
};

struct _GumSlowSlab
{
  GumSlab slab;

  gpointer invalidator;
};

struct _GumDataSlab
{
  GumSlab slab;
};

enum _GumPrologType
{
  GUM_PROLOG_NONE,
  GUM_PROLOG_IC,
  GUM_PROLOG_MINIMAL,
  GUM_PROLOG_FULL
};

enum _GumCodeContext
{
  GUM_CODE_INTERRUPTIBLE,
  GUM_CODE_UNINTERRUPTIBLE
};

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  GumX86Relocator * relocator;
  GumX86Writer * code_writer;
  GumX86Writer * slow_writer;
  gpointer continuation_real_address;
  GumPrologType opened_prolog;
};

struct _GumInstruction
{
  const cs_insn * ci;
  guint8 * start;
  guint8 * end;
};

struct _GumStalkerIterator
{
  GumExecCtx * exec_context;
  GumExecBlock * exec_block;
  GumGeneratorContext * generator_context;

  GumInstruction instruction;
  GumVirtualizationRequirements requirements;
};

struct _GumCalloutEntry
{
  GumStalkerCallout callout;
  gpointer data;
  GDestroyNotify data_destroy;

  gpointer pc;

  GumExecCtx * exec_context;

  GumCalloutEntry * next;
};

struct _GumBranchTarget
{
  gpointer origin_ip;

  gpointer absolute_address;
  gssize relative_offset;

  gboolean is_indirect;
  uint8_t pfx_seg;
  x86_reg base;
  x86_reg index;
  guint8 scale;
};

enum _GumBackpatchType
{
  GUM_BACKPATCH_CALL,
  GUM_BACKPATCH_JMP,
  GUM_BACKPATCH_INLINE_CACHE,
};

struct _GumBackpatchCall
{
  gsize code_offset;
  GumPrologType opened_prolog;
  gpointer ret_real_address;
  gsize ret_code_offset;
};

struct _GumBackpatchRet
{
  gsize code_offset;
};

struct _GumBackpatchJmp
{
  guint id;
  gsize code_offset;
  GumPrologType opened_prolog;
};

struct _GumBackpatchInlineCache
{
  guint8 dummy;
};

struct _GumBackpatch
{
  GumBackpatchType type;
  gpointer to;
  gpointer from;
  gpointer from_insn;

  union
  {
    GumBackpatchCall call;
    GumBackpatchRet ret;
    GumBackpatchJmp jmp;
    GumBackpatchInlineCache inline_cache;
  };
};

struct _GumIcEntry
{
  gpointer real_start;
  gpointer code_start;
};

enum _GumVirtualizationRequirements
{
  GUM_REQUIRE_NOTHING         = 0,

  GUM_REQUIRE_RELOCATION      = 1 << 0,
  GUM_REQUIRE_SINGLE_STEP     = 1 << 1
};

#ifdef HAVE_LINUX

struct _GumCheckElfSection
{
  gchar name[PATH_MAX];
  GumBranchTarget * target;
  gboolean found;
};

#endif

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)

extern _Unwind_Reason_Code __gxx_personality_v0 (int version,
    _Unwind_Action actions, uint64_t exception_class,
    _Unwind_Exception * unwind_exception, _Unwind_Context * context)
    __attribute__ ((weak));
extern const void * _Unwind_Find_FDE (const void * pc, struct dwarf_eh_bases *);

static void gum_stalker_ensure_unwind_apis_instrumented (void);
static void gum_stalker_deinit_unwind_apis_instrumentation (void);
static _Unwind_Reason_Code gum_stalker_exception_personality (int version,
    _Unwind_Action actions, uint64_t exception_class,
    _Unwind_Exception * unwind_exception, _Unwind_Context * context);
static const void * gum_stalker_exception_find_fde (const void * pc,
    struct dwarf_eh_bases * bases);

#endif

static void gum_stalker_dispose (GObject * object);
static void gum_stalker_finalize (GObject * object);
static void gum_stalker_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_stalker_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);

G_GNUC_INTERNAL void _gum_stalker_do_follow_me (GumStalker * self,
    GumStalkerTransformer * transformer, GumEventSink * sink,
    gpointer * ret_addr_ptr);
static void gum_stalker_infect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_stalker_disinfect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
G_GNUC_INTERNAL void _gum_stalker_do_activate (GumStalker * self,
    gconstpointer target, gpointer * ret_addr_ptr);
G_GNUC_INTERNAL void _gum_stalker_do_deactivate (GumStalker * self,
    gpointer * ret_addr_ptr);
static gboolean gum_stalker_do_invalidate (GumExecCtx * ctx,
    gconstpointer address, GumActivation * activation);
static void gum_stalker_try_invalidate_block_owned_by_thread (
    GumThreadId thread_id, GumCpuContext * cpu_context, gpointer user_data);

static GumCallProbe * gum_call_probe_ref (GumCallProbe * probe);
static void gum_call_probe_unref (GumCallProbe * probe);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumStalkerTransformer * transformer,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (void);
static GumExecCtx * gum_stalker_find_exec_ctx_by_thread_id (GumStalker * self,
    GumThreadId thread_id);

static gsize gum_stalker_snapshot_space_needed_for (GumStalker * self,
    gsize real_size);
static gsize gum_stalker_get_ic_entry_size (GumStalker * stalker);

static void gum_stalker_thaw (GumStalker * self, gpointer code, gsize size);
static void gum_stalker_freeze (GumStalker * self, gpointer code, gsize size);

static GumExecCtx * gum_exec_ctx_new (GumStalker * self, GumThreadId thread_id,
    GumStalkerTransformer * transformer, GumEventSink * sink);
static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_dispose (GumExecCtx * ctx);
static GumCodeSlab * gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
    GumCodeSlab * code_slab);
static GumSlowSlab * gum_exec_ctx_add_slow_slab (GumExecCtx * ctx,
    GumSlowSlab * code_slab);
static GumDataSlab * gum_exec_ctx_add_data_slab (GumExecCtx * ctx,
    GumDataSlab * data_slab);
static void gum_exec_ctx_compute_code_address_spec (GumExecCtx * ctx,
    gsize slab_size, GumAddressSpec * spec);
static void gum_exec_ctx_compute_data_address_spec (GumExecCtx * ctx,
    gsize slab_size, GumAddressSpec * spec);
static gboolean gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
    gpointer resume_at);
static void gum_exec_ctx_unfollow (GumExecCtx * ctx, gpointer resume_at);
static gboolean gum_exec_ctx_has_executed (GumExecCtx * ctx);
static gboolean gum_exec_ctx_contains (GumExecCtx * ctx, gconstpointer address);
static gpointer gum_exec_ctx_switch_block (GumExecCtx * ctx,
    GumExecBlock * block, gpointer start_address, gpointer from_insn);
static void gum_exec_ctx_query_block_switch_callback (GumExecCtx * ctx,
    GumExecBlock * block, gpointer start_address, gpointer from_insn,
    gpointer * target);

static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address);
static GumExecBlock * gum_exec_ctx_build_block (GumExecCtx * ctx,
    gpointer real_address);
static void gum_exec_ctx_recompile_block (GumExecCtx * ctx,
    GumExecBlock * block);
static void gum_exec_ctx_compile_block (GumExecCtx * ctx, GumExecBlock * block,
    gconstpointer input_code, gpointer output_code, GumAddress output_pc,
    guint * input_size, guint * output_size, guint * slow_size);
static void gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
    GumExecBlock * block);

static gboolean gum_stalker_iterator_is_out_of_space (
    GumStalkerIterator * self);

static void gum_stalker_invoke_callout (GumCalloutEntry * entry,
    GumCpuContext * cpu_context);

static void gum_exec_ctx_write_prolog (GumExecCtx * ctx, GumPrologType type,
    GumX86Writer * cw);
static void gum_exec_ctx_write_epilog (GumExecCtx * ctx, GumPrologType type,
    GumX86Writer * cw);

static void gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx);
static void gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
    GumPrologType type, GumX86Writer * cw);
static void gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
    GumPrologType type, GumX86Writer * cw);
static void gum_exec_ctx_write_invalidator (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr, GumExecHelperWriteFunc write);
static gboolean gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr);

static void gum_exec_ctx_get_branch_target_address (GumExecCtx * ctx,
    const GumBranchTarget * target, GumGeneratorContext * gc,
    GumX86Writer * cw);
static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
    GumX86Reg target_register, GumX86Reg source_register,
    gpointer ip, GumGeneratorContext * gc, GumX86Writer * cw);
static void gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx, GumX86Reg target_register, GumX86Reg source_register,
    gpointer ip, GumGeneratorContext * gc, GumX86Writer * cw);
static void gum_exec_ctx_load_real_register_from_full_frame_into (
    GumExecCtx * ctx, GumX86Reg target_register, GumX86Reg source_register,
    gpointer ip, GumGeneratorContext * gc, GumX86Writer * cw);
static void gum_exec_ctx_load_real_register_from_ic_frame_into (
    GumExecCtx * ctx, GumX86Reg target_register, GumX86Reg source_register,
    gpointer ip, GumGeneratorContext * gc, GumX86Writer * cw);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_clear (GumExecBlock * block);
static void gum_exec_block_commit (GumExecBlock * block);
static void gum_exec_block_invalidate (GumExecBlock * block);
static gpointer gum_exec_block_get_snapshot_start (GumExecBlock * block);
static GumCalloutEntry * gum_exec_block_get_last_callout_entry (
    const GumExecBlock * block);
static void gum_exec_block_set_last_callout_entry (GumExecBlock * block,
    GumCalloutEntry * entry);

static void gum_exec_block_backpatch_call (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, gsize code_offset,
    GumPrologType opened_prolog, gpointer ret_real_address,
    gsize ret_code_offset);
static void gum_exec_block_backpatch_jmp (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, guint id, gsize code_offset,
    GumPrologType opened_prolog);
static gboolean gum_exec_block_get_eob (gpointer from_insn, guint id);
static void gum_exec_block_backpatch_conditional_jmp (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, guint id, gsize jcc_code_offset,
    GumPrologType opened_prolog);
static GumExecBlock * gum_exec_block_get_adjacent (GumExecBlock * from);
static void gum_exec_block_backpatch_unconditional_jmp (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, gboolean is_eob, gsize code_offset,
    GumPrologType opened_prolog);
static gboolean gum_exec_block_is_adjacent (gpointer target,
    GumExecBlock * from);
static void gum_exec_block_backpatch_inline_cache (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn);

static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static gboolean gum_exec_block_is_direct_jmp_to_plt_got (GumExecBlock * block,
    GumGeneratorContext * gc, GumBranchTarget * target);
#ifdef HAVE_LINUX
static GArray * gum_exec_ctx_get_plt_got_ranges (void);
static void gum_exec_ctx_deinit_plt_got_ranges (void);
static gboolean gum_exec_ctx_find_plt_got (const GumModuleDetails * details,
    gpointer user_data);
static gboolean gum_exec_check_elf_section (
    const GumElfSectionDetails * details, gpointer user_data);
#endif
static void gum_exec_block_handle_direct_jmp_to_plt_got (GumExecBlock * block,
    GumGeneratorContext * gc, GumBranchTarget * target);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static void gum_exec_block_write_adjust_depth (GumExecBlock * block,
    GumX86Writer * cw, gssize adj);
static GumVirtualizationRequirements gum_exec_block_virtualize_sysenter_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_syscall_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_int_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
#ifdef HAVE_LINUX
static GumVirtualizationRequirements gum_exec_block_virtualize_linux_syscall (
    GumExecBlock * block, GumGeneratorContext * gc);
static void gum_exec_ctx_write_int80_helper (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_syscall_helper (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_aligned_syscall (GumExecCtx * ctx,
    GumX86Writer * cw, const guint8 * syscall_insn, gsize syscall_size);
#endif
#if GLIB_SIZEOF_VOID_P == 4 && defined (HAVE_WINDOWS)
static GumVirtualizationRequirements
    gum_exec_block_virtualize_wow64_transition (GumExecBlock * block,
    GumGeneratorContext * gc, gpointer impl);
#endif

static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    const GumBranchTarget * target, GumExecCtxReplaceCurrentBlockFunc func,
    GumGeneratorContext * gc, guint id, GumAddress jcc_address);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_chaining_return_code (GumExecBlock * block,
    GumGeneratorContext * gc, guint16 npop);
static gpointer * gum_exec_block_write_inline_cache_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumX86Writer * cw, GumX86Writer * cws);
static void gum_exec_block_backpatch_slab (GumExecBlock * block,
    gpointer target);
static void gum_exec_block_write_single_step_transfer_code (
    GumExecBlock * block, GumGeneratorContext * gc);
#if GLIB_SIZEOF_VOID_P == 4 && !defined (HAVE_QNX)
static void gum_exec_block_write_sysenter_continuation_code (
    GumExecBlock * block, GumGeneratorContext * gc, gpointer saved_ret_addr);
#endif

static void gum_exec_block_write_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc,
    GumCodeContext cc);
static void gum_exec_block_write_ret_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);

static void gum_exec_block_maybe_write_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_invoke_call_probes (GumExecBlock * block,
    GumCpuContext * cpu_context);

static gpointer gum_exec_block_write_inline_data (GumX86Writer * cw,
    gconstpointer data, gsize size, GumAddress * address);

static void gum_exec_block_open_prolog (GumExecBlock * block,
    GumPrologType type, GumGeneratorContext * gc, GumX86Writer * cw);
static void gum_exec_block_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc, GumX86Writer * cw);

static GumCodeSlab * gum_code_slab_new (GumExecCtx * ctx);
static GumSlowSlab * gum_slow_slab_new (GumExecCtx * ctx);
static void gum_code_slab_free (GumCodeSlab * code_slab);
static void gum_code_slab_init (GumCodeSlab * code_slab, gsize slab_size,
    gsize page_size);
static void gum_slow_slab_init (GumSlowSlab * slow_slab, gsize slab_size,
    gsize page_size);

static GumDataSlab * gum_data_slab_new (GumExecCtx * ctx);
static void gum_data_slab_free (GumDataSlab * data_slab);
static void gum_data_slab_init (GumDataSlab * data_slab, gsize slab_size);

static void gum_scratch_slab_init (GumCodeSlab * scratch_slab, gsize slab_size);

static void gum_slab_free (GumSlab * slab);
static void gum_slab_init (GumSlab * slab, gsize slab_size, gsize header_size);
static gsize gum_slab_available (GumSlab * self);
static gpointer gum_slab_start (GumSlab * self);
static gpointer gum_slab_end (GumSlab * self);
static gpointer gum_slab_cursor (GumSlab * self);
static gpointer gum_slab_reserve (GumSlab * self, gsize size);
static gpointer gum_slab_try_reserve (GumSlab * self, gsize size);

static void gum_write_segment_prefix (uint8_t segment, GumX86Writer * cw);

static GumX86Reg gum_x86_meta_reg_from_real_reg (GumX86Reg reg);
static GumX86Reg gum_x86_reg_from_capstone (x86_reg reg);

#ifdef HAVE_WINDOWS
static gboolean gum_stalker_on_exception (GumExceptionDetails * details,
    gpointer user_data);
static void gum_enable_hardware_breakpoint (GumNativeRegisterValue * dr7_reg,
    guint index);
# if GLIB_SIZEOF_VOID_P == 4
static void gum_collect_export (GArray * impls, const TCHAR * module_name,
    const gchar * export_name);
static void gum_collect_export_by_handle (GArray * impls,
    HMODULE module_handle, const gchar * export_name);
static gpointer gum_find_system_call_above_us (GumStalker * stalker,
    gpointer * start_esp);
# endif
#endif

static gpointer gum_find_thread_exit_implementation (void);
#ifdef HAVE_DARWIN
static gboolean gum_store_thread_exit_match (GumAddress address, gsize size,
    gpointer user_data);
#endif

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)

static GPrivate gum_stalker_exec_ctx_private;

static gpointer _gum_thread_exit_impl;

#ifdef HAVE_LINUX
static const guint8 gum_int80_code[] = { 0xcd, 0x80 };
static const guint8 gum_syscall_code[] = { 0x0f, 0x05 };

# ifndef HAVE_ANDROID
static GumInterceptor * gum_exec_ctx_interceptor = NULL;
# endif
#endif

gboolean
gum_stalker_is_supported (void)
{
  return TRUE;
}

void
gum_stalker_activate_experimental_unwind_support (void)
{
#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  gum_stalker_ensure_unwind_apis_instrumented ();
#endif
}

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_stalker_dispose;
  object_class->finalize = gum_stalker_finalize;
  object_class->get_property = gum_stalker_get_property;
  object_class->set_property = gum_stalker_set_property;

  g_object_class_install_property (object_class, PROP_IC_ENTRIES,
      g_param_spec_uint ("ic-entries", "IC Entries", "Inline Cache Entries",
      2, 32, 2,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (object_class, PROP_ADJACENT_BLOCKS,
      g_param_spec_uint ("adjacent-blocks", "Adjacent Blocks",
      "Prefetch Adjacent Blocks", 0, 32, 0,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

  _gum_thread_exit_impl = gum_find_thread_exit_implementation ();
}

static void
gum_stalker_init (GumStalker * self)
{
  gsize page_size;

  self->exclusions = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->trust_threshold = 1;

  gum_spinlock_init (&self->probe_lock);
  self->probe_target_by_id = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  self->probe_array_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) g_ptr_array_unref);

  page_size = gum_query_page_size ();

  self->thunks_size = page_size;
  self->code_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_SIZE_INITIAL, page_size);
  self->slow_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_SLOW_SLAB_SIZE_INITIAL, page_size);
  self->data_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_DATA_SLAB_SIZE_INITIAL, page_size);
  self->code_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_SIZE_DYNAMIC, page_size);
  self->slow_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_SLOW_SLAB_SIZE_DYNAMIC, page_size);
  self->data_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_DATA_SLAB_SIZE_DYNAMIC, page_size);
  self->scratch_slab_size = GUM_ALIGN_SIZE (GUM_SCRATCH_SLAB_SIZE, page_size);
  self->ctx_header_size = GUM_ALIGN_SIZE (sizeof (GumExecCtx), page_size);
  self->ctx_size =
      self->ctx_header_size +
      self->thunks_size +
      self->code_slab_size_initial +
      self->slow_slab_size_initial +
      self->data_slab_size_initial +
      self->scratch_slab_size +
      0;

  self->thunks_offset = self->ctx_header_size;
  self->code_slab_offset = self->thunks_offset + self->thunks_size;
  self->slow_slab_offset =
      self->code_slab_offset + self->code_slab_size_initial;
  self->data_slab_offset =
      self->slow_slab_offset + self->slow_slab_size_initial;
  self->scratch_slab_offset =
      self->data_slab_offset + self->data_slab_size_initial;

  self->page_size = page_size;
  self->cpu_features = gum_query_cpu_features ();
  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;

  g_mutex_init (&self->mutex);
  self->contexts = NULL;

#ifdef HAVE_WINDOWS
  self->exceptor = gum_exceptor_obtain ();
  gum_exceptor_add (self->exceptor, gum_stalker_on_exception, self);

# if GLIB_SIZEOF_VOID_P == 4
  {
    HMODULE ntmod, usermod;
    MODULEINFO mi;
    BOOL success G_GNUC_UNUSED;
    gboolean found_user32_code G_GNUC_UNUSED;
    guint8 * p;
    GArray * impls;

    ntmod = GetModuleHandle (_T ("ntdll.dll"));
    usermod = GetModuleHandle (_T ("user32.dll"));
    g_assert (ntmod != NULL && usermod != NULL);

    success = GetModuleInformation (GetCurrentProcess (), usermod,
        &mi, sizeof (mi));
    g_assert (success);
    self->user32_start = mi.lpBaseOfDll;
    self->user32_end = (guint8 *) mi.lpBaseOfDll + mi.SizeOfImage;

    found_user32_code = FALSE;
    for (p = self->user32_start; p < (guint8 *) self->user32_end;)
    {
      MEMORY_BASIC_INFORMATION mbi;

      success = VirtualQuery (p, &mbi, sizeof (mbi)) == sizeof (mbi);
      g_assert (success);

      if (mbi.Protect == PAGE_EXECUTE_READ ||
          mbi.Protect == PAGE_EXECUTE_READWRITE ||
          mbi.Protect == PAGE_EXECUTE_WRITECOPY
"""


```