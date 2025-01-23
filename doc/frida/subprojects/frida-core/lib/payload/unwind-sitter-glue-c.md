Response:
Let's break down the thought process for analyzing this C code snippet.

1. **Understand the Goal:** The request asks for a functional breakdown of `unwind-sitter-glue.c`, its relation to reverse engineering, low-level details, logical reasoning, potential errors, and how a user might reach this code.

2. **High-Level Overview (Skimming):**  Quickly read through the code, paying attention to includes, defines, structs, and function names. This provides initial clues about the file's purpose. Keywords like "unwind," "libunwind," "cursor," "vtable," "hook," "replace," and architecture-specific `#ifdef`s stand out. The includes `<capstone.h>` and `<gum/...>` immediately suggest interaction with a disassembler and the Frida framework.

3. **Identify Key Data Structures:** Focus on the `struct` definitions: `FridaFillInfoContext`, `FridaDyldUnwindSections`, `FridaCreateArgs`, and `FridaUnwindHookState`. Understanding these structures is crucial for grasping the data flow and purpose of the functions. Note what each structure holds (e.g., unwind info, module headers, hook state).

4. **Analyze Function by Function (Core Logic):**  Go through each function, trying to determine its role:
    * `_frida_unwind_sitter_fill_unwind_sections`: Seems to copy cached unwind information. The caching suggests performance optimization.
    * `_frida_unwind_sitter_hook_libunwind`: The "hook" keyword is a strong indicator of dynamic instrumentation. It interacts with `libunwind`, modifies a vtable, and uses `gum_interceptor`. This is a key function for Frida's operation.
    * `_frida_unwind_sitter_unhook_libunwind`:  The opposite of the previous function, reverting the hook.
    * `frida_get_cached_sections` and `frida_create_cached_sections`:  Deal with caching unwind information, likely based on memory ranges.
    * `frida_fill_info`:  Used as a callback during section enumeration, extracting DWARF and compact unwind data.
    * `frida_unwind_cursor_set_info_replacement`:  This is the replacement function injected via the hook. It's modifying the return address based on Frida's stack translation. This is central to Frida's ability to intercept and modify execution flow. The architecture-specific code for signing/unsigning pointers is important.
    * `frida_find_vtable`:  Locates the vtable of `libunwind`'s cursor object by disassembling code. This is a fragile but necessary step when relying on internal implementation details.
    * `frida_compute_vtable_shift`:  Calculates an offset within the vtable, likely due to different `libunwind` versions. Architecture-specific implementations exist.
    * Helper functions like `frida_find_bss_range`, `frida_is_empty_function`, and `frida_has_first_match`: Support the main logic, like finding specific memory regions or identifying patterns.

5. **Connect to Reverse Engineering:**  Think about how the identified functionalities relate to reverse engineering techniques. The code directly interacts with program execution by:
    * **Code Injection:** Hooking `libunwind` and replacing a function.
    * **Dynamic Analysis:** Observing and modifying program behavior at runtime.
    * **Stack Unwinding:**  Manipulating the stack unwinding process to gain control or information.
    * **Code Analysis:** Using Capstone to disassemble and understand `libunwind`'s internal structure.

6. **Identify Low-Level Details:**  Focus on aspects that touch the operating system and hardware:
    * **Memory Management:**  Using `gum_memory_query_protection`, `gum_query_page_size`.
    * **Process Memory:** Interacting with `mach_task_self()` on macOS.
    * **Executable Formats:**  Parsing Mach-O headers (`FRIDA_MH_MAGIC_64`).
    * **CPU Architectures:**  Handling ARM64 and x86-64 differences.
    * **Calling Conventions:** Implicitly dealing with stack frames and register usage (e.g., RBP, X29).
    * **Code Signing:**  Addressing pointer authentication on ARM64.
    * **Dynamic Linking:**  Finding exports from `libunwind.dylib`.

7. **Infer Logical Reasoning:**  Look for conditional statements and how data is processed. The caching mechanism is a clear example of optimization. The logic for finding the vtable involves assumptions about `libunwind`'s implementation. The pointer signing/unsigning logic is based on security features of the ARM64 architecture.

8. **Consider User Errors:** Think about common mistakes a user might make that could relate to this code:
    * Targeting the wrong process.
    * Incorrect Frida setup or version.
    * Issues with code signing or permissions.
    * Trying to hook functions that are called very early or very late in the process lifecycle.

9. **Trace User Actions:** Imagine the steps a developer would take to reach this code:
    * **Goal:** Intercept function calls or modify program behavior during stack unwinding.
    * **Frida Usage:** Write a Frida script.
    * **API Call:** The script would likely use Frida's `Interceptor` API or similar mechanisms to hook functions.
    * **Internal Mechanism:** Frida's core would then use the code in `unwind-sitter-glue.c` to implement the hooking, especially when stack unwinding is involved.

10. **Refine and Structure:** Organize the findings into the requested categories (functionality, reverse engineering, low-level details, logic, errors, user actions). Use clear and concise language, providing examples where relevant. Be sure to explain the *why* behind the code's actions.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This code just deals with stack unwinding."  **Correction:** Realized it's not just about unwinding but *intercepting and modifying* the unwinding process.
* **Unclear about vtable:** Initially might not fully grasp the significance of the vtable. **Correction:**  Recognized that it's about hooking a specific function pointer within an object's structure, a common technique in C++ and related approaches.
* **Pointer signing complexity:** Could have glossed over the pointer signing. **Correction:** Realized its importance for security on ARM64 and that Frida needs to handle it correctly.
* **Too technical:**  Might have focused too much on specific code lines. **Correction:** Shifted to explaining the *purpose* and *implications* of the code.

By following this structured approach, combining code analysis with an understanding of Frida's goals and underlying principles, a comprehensive and accurate explanation of the `unwind-sitter-glue.c` file can be produced.
好的，让我们来详细分析一下 `frida/subprojects/frida-core/lib/payload/unwind-sitter-glue.c` 这个文件。

**文件功能概述**

这个 C 文件是 Frida 动态 instrumentation 工具的核心组成部分，其主要功能是**在目标进程进行栈回溯（unwinding）时，介入并修改栈帧信息，从而实现对程序执行流程的控制和干预**。 具体来说，它做了以下几件事：

1. **拦截 `libunwind` 库的关键函数：**  `libunwind` 是一个用于在运行时进行栈回溯的库。该文件通过 Hook 技术，拦截 `libunwind` 库中负责设置栈帧信息的函数（通常是与 `unw_cursor_t` 相关的操作）。
2. **缓存 unwind 信息：**  为了提高效率，它会缓存目标模块的 DWARF 和 compact unwind 信息，这些信息用于描述栈帧结构。
3. **在栈回溯过程中修改返回地址：** 当目标程序进行栈回溯时，被拦截的函数会被调用。在这个过程中，Frida 可以获取到当前的栈帧信息，并根据需要修改栈帧中存储的返回地址。
4. **处理代码签名：** 在 ARM64 架构上，为了安全，返回地址可能被签名。该文件会处理这些签名，确保修改后的返回地址仍然有效。

**与逆向方法的关系及举例说明**

这个文件是 Frida 实现动态逆向的核心组件之一。它通过在运行时修改程序的执行流程，使得逆向工程师可以：

* **追踪函数调用路径：** 通过修改返回地址，可以强制程序跳转到指定的代码位置，从而观察特定的函数调用序列。
    * **举例：** 假设你想知道函数 `A` 调用完后，程序接下来会执行哪个函数。你可以使用 Frida hook 住 `A` 函数，并在其返回时，通过 `unwind-sitter-glue.c` 修改其返回地址，让程序跳转到一个自定义的 hook 函数，在该 hook 函数中记录下原始的返回地址。
* **绕过安全检查或实现特定功能：** 通过修改返回地址，可以跳过某些安全检查逻辑，或者在程序执行到特定点时插入自定义的代码。
    * **举例：** 某些恶意软件会进行完整性校验。你可以使用 Frida hook 住校验函数，并通过修改返回地址，直接跳过校验成功的逻辑，即使校验失败也让程序继续运行。
* **动态修改函数行为：**  虽然这个文件主要关注栈回溯，但它为 Frida 提供了修改程序执行流程的基础能力，可以与其他 Frida 功能结合，实现更复杂的动态修改。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明**

这个文件的实现涉及多个底层的概念：

* **二进制文件结构 (Mach-O)：** 在 macOS 上，它需要解析 Mach-O 文件头，查找 DWARF 和 compact unwind 信息段 (`__eh_frame`, `__unwind_info`)。这些段包含了描述函数栈帧布局的数据。
    * **代码示例：** `(*(guint32 *) header != FRIDA_MH_MAGIC_64)`  这行代码检查内存中的数据是否是 Mach-O 文件的魔数，用于判断是否找到了有效的 Mach-O 文件头。
* **栈帧结构：**  理解函数调用时栈帧的布局是至关重要的。它需要知道返回地址通常存储在栈帧的哪个位置（例如，相对于帧指针 FP）。
    * **代码示例：** `#define FRIDA_FP_TO_SP(fp) (fp + 0x10)`  这行代码定义了根据帧指针 (FP) 计算栈指针 (SP) 的方式，这与具体的架构和调用约定有关。
* **`libunwind` 库：** 需要了解 `libunwind` 的内部工作原理，特别是 `unw_cursor_t` 结构以及与其相关的函数，例如用于设置栈帧信息的函数。
    * **代码示例：**  查找 `unw_init_local` 或 `_Unwind_RaiseException` 的导出符号，以定位 `libunwind` 库并进一步查找关键的虚函数表。
* **Hook 技术：**  Frida 使用 Gum 库来实现 Hook。该文件使用 `gum_interceptor_replace` 函数来替换 `libunwind` 中的函数。
    * **代码示例：** `gum_interceptor_replace (interceptor, state->set_info_original, frida_unwind_cursor_set_info_replacement, NULL, NULL)`  这行代码将原始的设置栈帧信息的函数替换为 Frida 提供的 `frida_unwind_cursor_set_info_replacement` 函数。
* **虚拟内存管理：**  需要了解进程的内存布局，例如代码段 (`__TEXT`) 的位置。
    * **代码示例：** `gum_darwin_module_enumerate_sections (module, (GumFoundDarwinSectionFunc) frida_fill_info, &ctx);`  这行代码枚举模块的节区，以便找到包含 unwind 信息的节区。
* **CPU 架构特定指令 (ARM64/x86-64)：**  代码中存在大量的条件编译，针对不同的 CPU 架构（主要是 ARM64 和 x86-64）采取不同的处理方式。例如，查找 vtable 的方式，以及处理代码签名的方式都不同。
    * **代码示例：** 使用 Capstone 反汇编引擎 (`<capstone.h>`) 来分析 `libunwind` 的代码，根据不同的指令（例如 `LEA` 在 x86-64 上，`ADRP`/`ADD` 在 ARM64 上）来定位虚函数表。
* **代码签名 (ARM64)：** 在 ARM64 上，为了防止恶意代码修改返回地址，引入了 Pointer Authentication Code (PAC)。Frida 需要处理这些签名，确保修改后的返回地址仍然有效。
    * **代码示例：**  `ptrauth.h` 头文件和相关的宏 (`FRIDA_RESIGN_PTR`) 以及内联汇编用于签名和剥离指针认证码。

**逻辑推理、假设输入与输出**

让我们分析一下 `frida_unwind_cursor_set_info_replacement` 这个关键函数的逻辑：

**假设输入：**

* `self`: 指向 `libunwind` 中 `unw_cursor_t` 结构的指针。这个结构体包含了当前栈帧的信息。
* `is_return_address`: 一个布尔值，指示当前正在处理的是否是返回地址。

**逻辑推理：**

1. **调用原始的 `set_info` 函数：**  首先，它会调用 `libunwind` 原始的设置栈帧信息的函数 (`state->set_info`)，以确保基本的栈回溯操作能够正常进行。
2. **获取帧指针 (FP)：**  根据 CPU 架构，从 `unw_cursor_t` 结构中获取当前的帧指针寄存器的值（RBP 或 X29）。
3. **获取存储的返回地址：**  根据帧指针，计算出存储返回地址的内存地址，并读取其值。
4. **检查是否需要翻译地址：** 调用 `gum_invocation_stack_translate` 函数，尝试将当前的返回地址翻译成 Frida 注入的代码的地址空间中的地址。如果地址发生了变化，说明当前的返回地址指向的是原始代码，需要进行修改。
5. **修改返回地址并处理代码签名：** 如果需要修改返回地址，则将栈上的返回地址值更新为翻译后的地址。在 ARM64 架构上，还需要根据原始返回地址是否签名来重新签名新的返回地址，以保证其有效性。

**假设输出：**

* **正常情况：** 函数执行完毕，`unw_cursor_t` 结构体中与当前栈帧相关的返回地址信息可能被修改为 Frida 注入的代码的地址。
* **如果 `fp` 为 0 或 -1：**  说明栈帧信息不完整或出现了错误，函数会直接返回，不做任何修改。
* **如果没有 `missing_info`：**  表示已经有 unwind 信息，可能会尝试进行地址翻译和修改。

**用户或编程常见的使用错误及举例说明**

* **Hook 错误的函数：**  如果用户尝试 Hook 的不是 `libunwind` 中负责设置栈帧信息的函数，那么 `unwind-sitter-glue.c` 的逻辑可能不会被触发，或者无法正确地修改返回地址。
* **不正确的 Frida 脚本逻辑：**  用户可能在 Frida 脚本中编写了错误的逻辑，导致 `gum_invocation_stack_translate` 函数返回了错误的翻译地址，从而导致程序崩溃或行为异常。
* **目标进程使用了非标准的栈回溯方式：** 如果目标进程不使用 `libunwind` 进行栈回溯，或者使用了高度定制化的栈管理方式，那么 `unwind-sitter-glue.c` 的 Hook 可能无法生效。
* **与其他的 Frida 模块或脚本冲突：**  如果其他 Frida 模块或脚本也尝试 Hook `libunwind` 的相关函数，可能会导致冲突。
* **权限问题：**  Frida 需要足够的权限才能在目标进程中进行 Hook 和内存修改。如果权限不足，操作可能会失败。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户编写 Frida 脚本：** 用户首先会编写一个 Frida 脚本，目标是修改目标进程的函数执行流程。
2. **使用 Frida API 进行 Hook：**  在脚本中，用户会使用 Frida 提供的 `Interceptor` API 或类似的机制来 Hook 目标函数。例如，他们可能会使用 `Interceptor.replace()` 来替换目标函数的实现。
3. **Frida 内部处理 Hook 请求：** 当 Frida 接收到 Hook 请求后，它会在目标进程中注入 Frida 的 Agent 代码。
4. **涉及到栈回溯的场景：**  如果被 Hook 的函数在执行过程中触发了栈回溯（例如，抛出异常、调用 `backtrace` 等），或者 Frida 脚本本身需要在某些时刻获取调用栈信息，那么 `libunwind` 库会被调用。
5. **`_frida_unwind_sitter_hook_libunwind` 被调用：** 为了能够干预栈回溯过程，Frida 的 Agent 代码会调用 `_frida_unwind_sitter_hook_libunwind` 函数，该函数会 Hook `libunwind` 中关键的设置栈帧信息的函数。
6. **栈回溯发生，Hook 生效：** 当目标进程进行栈回溯，并调用到被 Hook 的 `libunwind` 函数时，`frida_unwind_cursor_set_info_replacement` 函数会被执行。
7. **修改返回地址（如果需要）：** 在 `frida_unwind_cursor_set_info_replacement` 函数中，Frida 会根据当前的上下文和脚本的逻辑，判断是否需要修改栈帧中的返回地址。

**调试线索：**

* **检查 Frida 脚本的 Hook 设置：** 确认用户是否正确地 Hook 了目标函数。
* **查看 Frida 的日志输出：** Frida 通常会输出一些调试信息，可以帮助了解 Hook 是否成功，以及 `unwind-sitter-glue.c` 的代码是否被执行。
* **使用 Frida 的 `console.log` 或其他调试功能：**  在 Frida 脚本中添加日志输出，可以跟踪程序的执行流程，观察 `gum_invocation_stack_translate` 的返回值，以及返回地址是否被修改。
* **分析目标进程的调用栈：**  可以使用 Frida 的 `Thread.backtrace()` 或类似的 API 来获取目标进程的调用栈信息，从而了解栈回溯的过程。
* **使用更底层的调试工具：**  在某些情况下，可能需要使用像 LLDB 或 GDB 这样的底层调试器来更详细地分析目标进程的内存和寄存器状态。

总而言之，`frida/subprojects/frida-core/lib/payload/unwind-sitter-glue.c` 是 Frida 实现动态代码修改和程序流程控制的关键组成部分，它通过 Hook `libunwind` 库，介入栈回溯过程，并能够修改栈帧信息，从而为逆向工程师提供了强大的动态分析能力。理解其工作原理对于深入使用 Frida 进行逆向工程至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-core/lib/payload/unwind-sitter-glue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#include "frida-payload.h"

#ifdef HAVE_DARWIN

#include <capstone.h>
#include <gum/gumdarwin.h>
#include <gum/gummemory.h>
#include <ptrauth.h>

#define FRIDA_MH_MAGIC_64 0xfeedfacf
#define FRIDA_LIBUNWIND_PATH "/usr/lib/system/libunwind.dylib"
#define FRIDA_UNWIND_CURSOR_VTABLE_OFFSET_SET_INFO 0x68
#define FRIDA_UNWIND_CURSOR_VTABLE_OFFSET_GET_REG 0x18
#define FRIDA_FP_TO_SP(fp) (fp + 0x10)
#ifdef HAVE_ARM64
# define FRIDA_UNWIND_CURSOR_unwindInfoMissing 0x268
# define FRIDA_UNWAARCH64_X29 29
# define FRIDA_STRIP_MASK 0x0000007fffffffffULL
#else
# define FRIDA_UNWIND_CURSOR_unwindInfoMissing 0x100
# define FRIDA_UNWX86_64_RBP 6
#endif

typedef struct _FridaFillInfoContext FridaFillInfoContext;
typedef struct _FridaDyldUnwindSections FridaDyldUnwindSections;
typedef struct _FridaCreateArgs FridaCreateArgs;
typedef struct _FridaUnwindHookState FridaUnwindHookState;

struct _FridaFillInfoContext
{
  FridaDyldUnwindSections * info;
  guint missing_info;
};

struct _FridaDyldUnwindSections
{
  const void * mh;
  const void * dwarf_section;
  uintptr_t dwarf_section_length;
  const void * compact_unwind_section;
  uintptr_t compact_unwind_section_length;
};

struct _FridaCreateArgs
{
  GumAddress range_start;
  GumAddress range_end;
};

struct _FridaUnwindHookState
{
  gpointer vtable;
  gssize shift;
  gpointer * set_info_slot;
  gpointer set_info_original;
  void (* set_info) (gpointer cursor, gint is_return_address);
  gpointer (* get_reg) (gpointer cursor, gint reg);
};

#if __has_feature (ptrauth_calls)
# define FRIDA_RESIGN_PTR(x) GSIZE_TO_POINTER (gum_sign_code_address (gum_strip_code_address (GUM_ADDRESS (x))))
#else
# define FRIDA_RESIGN_PTR(x) (x)
#endif

static FridaDyldUnwindSections * frida_get_cached_sections (GumAddress range_start, GumAddress range_end);
static FridaDyldUnwindSections * frida_create_cached_sections (FridaCreateArgs * args);
static gboolean frida_fill_info (const GumDarwinSectionDetails * details, FridaFillInfoContext * ctx);
static void frida_unwind_cursor_set_info_replacement (gpointer cursor, gint is_return_address);
static gpointer frida_find_vtable (void);
static gboolean frida_compute_vtable_shift (gpointer vtable, gssize * shift);
#ifdef HAVE_ARM64
static gboolean frida_find_bss_range (const GumSectionDetails * details, GumMemoryRange * range);
#else
static gboolean frida_is_empty_function (GumAddress address);
static gboolean frida_has_first_match (GumAddress address, gsize size, gboolean * matches);
#endif

static FridaUnwindHookState * state = NULL;

void
_frida_unwind_sitter_fill_unwind_sections (GumAddress invader_start, GumAddress invader_end, void * info)
{
  FridaDyldUnwindSections * unwind_sections = info;
  FridaDyldUnwindSections * cached;

  cached = frida_get_cached_sections (invader_start, invader_end);
  if (cached == NULL)
    return;

  memcpy (unwind_sections, cached, sizeof (FridaDyldUnwindSections));
}

void
_frida_unwind_sitter_hook_libunwind (void)
{
#if GLIB_SIZEOF_VOID_P == 8
  gpointer * set_info_slot;
  gpointer get_reg_impl;
  GumInterceptor * interceptor;

  if (state != NULL)
    return;

  state = g_slice_new0 (FridaUnwindHookState);
  if (state == NULL)
    return;

  state->vtable = frida_find_vtable ();
  if (state->vtable == NULL)
    goto unsupported_version;

  if (!frida_compute_vtable_shift (state->vtable, &state->shift))
    goto unsupported_version;

  set_info_slot = (gpointer *) (GUM_ADDRESS (state->vtable) + FRIDA_UNWIND_CURSOR_VTABLE_OFFSET_SET_INFO + state->shift);
  get_reg_impl = *(gpointer *) (GUM_ADDRESS (state->vtable) + FRIDA_UNWIND_CURSOR_VTABLE_OFFSET_GET_REG + state->shift);

  state->set_info_slot = set_info_slot;
  state->set_info_original = *set_info_slot;
  state->set_info = FRIDA_RESIGN_PTR (state->set_info_original);
  state->get_reg = FRIDA_RESIGN_PTR (get_reg_impl);

  interceptor = gum_interceptor_obtain ();
  if (gum_interceptor_replace (interceptor, state->set_info_original, frida_unwind_cursor_set_info_replacement, NULL, NULL)
      != GUM_REPLACE_OK)
    goto unsupported_version;

  return;

unsupported_version:
  g_slice_free (FridaUnwindHookState, state);
  state = NULL;
#endif
}

void
_frida_unwind_sitter_unhook_libunwind (void)
{
  GumInterceptor * interceptor;

  if (state == NULL)
    return;

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_revert (interceptor, state->set_info_original);

  g_slice_free (FridaUnwindHookState, state);
  state = NULL;
}

static FridaDyldUnwindSections *
frida_get_cached_sections (GumAddress range_start, GumAddress range_end)
{
  static GOnce get_sections_once = G_ONCE_INIT;
  FridaCreateArgs args;

  args.range_start = range_start;
  args.range_end = range_end;

  g_once (&get_sections_once, (GThreadFunc) frida_create_cached_sections, &args);

  return (FridaDyldUnwindSections *) get_sections_once.retval;
}

static FridaDyldUnwindSections *
frida_create_cached_sections (FridaCreateArgs * args)
{
  FridaDyldUnwindSections * cached_sections;
  gsize page_size;
  gpointer header;
  GumPageProtection prot;
  GumDarwinModule * module;
  FridaFillInfoContext ctx;

  page_size = gum_query_page_size ();
  header = GSIZE_TO_POINTER (args->range_start);

  while ((gum_memory_query_protection (header, &prot) && (prot & GUM_PAGE_READ) == 0) ||
      (*(guint32 *) header != FRIDA_MH_MAGIC_64 && header + 4 <= GSIZE_TO_POINTER (args->range_end)))
  {
    header += page_size;
  }
  if (*(guint32 *) header != FRIDA_MH_MAGIC_64)
    return NULL;

  cached_sections = g_slice_new0 (FridaDyldUnwindSections);
  cached_sections->mh = header;

  module = gum_darwin_module_new_from_memory ("Frida", mach_task_self (), GPOINTER_TO_SIZE (header), GUM_DARWIN_MODULE_FLAGS_NONE, NULL);
  if (module == NULL)
    return cached_sections;

  ctx.info = cached_sections;
  ctx.missing_info = 2;
  gum_darwin_module_enumerate_sections (module, (GumFoundDarwinSectionFunc) frida_fill_info, &ctx);

  g_object_unref (module);

  return cached_sections;
}

static gboolean
frida_fill_info (const GumDarwinSectionDetails * details, FridaFillInfoContext * ctx)
{
  if (strcmp ("__TEXT", details->segment_name) != 0)
    return TRUE;

  if (strcmp ("__eh_frame", details->section_name) == 0)
  {
    ctx->missing_info--;
    ctx->info->dwarf_section = GSIZE_TO_POINTER (details->vm_address);
    ctx->info->dwarf_section_length = details->size;
  }
  else if (strcmp ("__unwind_info", details->section_name) == 0)
  {
    ctx->missing_info--;
    ctx->info->compact_unwind_section = GSIZE_TO_POINTER (details->vm_address);
    ctx->info->compact_unwind_section_length = details->size;
  }

  return ctx->missing_info > 0;
}

static void
frida_unwind_cursor_set_info_replacement (gpointer self, gint is_return_address)
{
  gboolean missing_info;
  GumAddress fp, stored_pc;
  gpointer * stored_pc_slot;
#if defined (HAVE_ARM64) && !__has_feature (ptrauth_calls)
  gboolean was_signed = FALSE;
#endif

  if (state == NULL)
    return;

  state->set_info (self, is_return_address);

#ifdef HAVE_ARM64
  fp = GUM_ADDRESS (state->get_reg (self, FRIDA_UNWAARCH64_X29));
#else
  fp = GUM_ADDRESS (state->get_reg (self, FRIDA_UNWX86_64_RBP));
#endif
  if (fp == 0 || fp == -1)
    return;

  missing_info = *((guint8 *) self + FRIDA_UNWIND_CURSOR_unwindInfoMissing);

  stored_pc_slot = GSIZE_TO_POINTER (fp + GLIB_SIZEOF_VOID_P);
  stored_pc = GUM_ADDRESS (*stored_pc_slot);
#if __has_feature (ptrauth_calls)
  stored_pc = gum_strip_code_address (stored_pc);
#elif defined (HAVE_ARM64)
  was_signed = (stored_pc & ~FRIDA_STRIP_MASK) != 0ULL;
  if (was_signed)
    stored_pc &= FRIDA_STRIP_MASK;
#endif

  if (!missing_info)
  {
    GumAddress translated;

    translated = GUM_ADDRESS (gum_invocation_stack_translate (gum_interceptor_get_current_stack (), GSIZE_TO_POINTER (stored_pc)));
    if (translated != stored_pc)
    {
#if __has_feature (ptrauth_calls)
      *stored_pc_slot = ptrauth_sign_unauthenticated (
          ptrauth_strip (GSIZE_TO_POINTER (translated), ptrauth_key_asia), ptrauth_key_asib, FRIDA_FP_TO_SP (fp));
#elif defined (HAVE_ARM64)
      if (was_signed)
      {
        GumAddress resigned;

        asm volatile (
            "mov x17, %1\n\t"
            "mov x16, %2\n\t"
            ".byte 0x5f, 0x21, 0x03, 0xd5\n\t" /* pacib1716 */
            "mov %0, x17\n\t"
            : "=r" (resigned)
            : "r" (translated & FRIDA_STRIP_MASK),
              "r" (FRIDA_FP_TO_SP (fp))
            : "x16", "x17"
        );

        *stored_pc_slot = GSIZE_TO_POINTER (resigned);
      }
      else
      {
        *stored_pc_slot = GSIZE_TO_POINTER (translated);
      }
#else
      *stored_pc_slot = GSIZE_TO_POINTER (translated);
#endif
    }
  }
}

static gpointer
frida_find_vtable (void)
{
  GumAddress result = 0;
  GumAddress export;
  uint64_t address;
  G_GNUC_UNUSED cs_err err;
  csh capstone;
  cs_insn * insn = NULL;
  const uint8_t * code;
  size_t size;
  const size_t max_size = 2048;

  export = gum_module_find_export_by_name (FRIDA_LIBUNWIND_PATH, "unw_init_local");
  if (export == 0)
    export = gum_module_find_export_by_name (FRIDA_LIBUNWIND_PATH, "_Unwind_RaiseException");
  if (export == 0)
    return NULL;
  export = gum_strip_code_address (export);
  address = export;

#ifdef HAVE_ARM64
  cs_arch_register_arm64 ();
  err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
#else
  cs_arch_register_x86 ();
  err = cs_open (CS_ARCH_X86, CS_MODE_64, &capstone);
#endif
  g_assert (err == CS_ERR_OK);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert (err == CS_ERR_OK);

  insn = cs_malloc (capstone);
  code = GSIZE_TO_POINTER (export);
  size = max_size;

#ifdef HAVE_ARM64
  {
    GumAddress last_adrp;
    guint last_adrp_reg;
    GumMemoryRange bss_range;

    bss_range.base_address = 0;
    gum_module_enumerate_sections (FRIDA_LIBUNWIND_PATH, (GumFoundSectionFunc) frida_find_bss_range, &bss_range);

    while (cs_disasm_iter (capstone, &code, &size, &address, insn))
    {
      if (insn->id == ARM64_INS_RET || insn->id == ARM64_INS_RETAA || insn->id == ARM64_INS_RETAB)
        break;
      if (insn->id == ARM64_INS_ADRP)
      {
        if (result != 0)
          break;
        last_adrp = (GumAddress) insn->detail->arm64.operands[1].imm;
        last_adrp_reg = insn->detail->arm64.operands[0].reg;
      }
      else if (insn->id == ARM64_INS_ADD && insn->detail->arm64.operands[0].reg == last_adrp_reg)
      {
        GumAddress candidate;
        gboolean is_bss;

        candidate = last_adrp + (GumAddress) insn->detail->arm64.operands[2].imm;

        is_bss = bss_range.base_address != 0 &&
            bss_range.base_address <= candidate &&
            candidate < bss_range.base_address + bss_range.size;
        if (!is_bss)
        {
          if (result == 0)
          {
            result = candidate;
            last_adrp = candidate;
          }
          else
          {
            result = candidate;
            break;
          }
        }
      }
      else if (result != 0)
      {
        break;
      }
    }
  }
#else
  while (cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    if (insn->id == X86_INS_RET)
      break;
    if (insn->id == X86_INS_LEA)
    {
      const cs_x86_op * op = &insn->detail->x86.operands[1];
      if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP)
      {
        result = address + op->mem.disp * op->mem.scale;
        break;
      }
    }
  }
#endif

  if (insn != NULL)
    cs_free (insn, 1);
  cs_close (&capstone);

  return GSIZE_TO_POINTER (result);
}

#ifdef HAVE_ARM64

static gboolean
frida_find_bss_range (const GumSectionDetails * details, GumMemoryRange * range)
{
  if (strcmp (details->name, "__bss") == 0)
  {
    range->base_address = details->address;
    range->size = details->size;
    return FALSE;
  }

  return TRUE;
}

static gboolean
frida_compute_vtable_shift (gpointer vtable, gssize * shift)
{
  gboolean result = FALSE;
  G_GNUC_UNUSED cs_err err;
  csh capstone;
  cs_insn * insn = NULL;
  const uint8_t * code;
  uint64_t address;
  size_t size = 4;

  cs_arch_register_arm64 ();
  err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
  g_assert (err == CS_ERR_OK);

  insn = cs_malloc (capstone);
  code = gum_strip_code_pointer (*(gpointer *) vtable);
  address = GPOINTER_TO_SIZE (code);

  if (cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    if (insn->id == ARM64_INS_RET || insn->id == ARM64_INS_RETAA || insn->id == ARM64_INS_RETAB)
      *shift = 0;
    else
      *shift = -2 * GLIB_SIZEOF_VOID_P;

    result = TRUE;
  }

  if (insn != NULL)
    cs_free (insn, 1);
  cs_close (&capstone);

  return result;
}

#else

static gboolean
frida_compute_vtable_shift (gpointer vtable, gssize * shift)
{
  GumAddress cursor = GPOINTER_TO_SIZE (vtable);
  GumAddress error = cursor + 16 * GLIB_SIZEOF_VOID_P;

  while (cursor < error && *(gpointer *) GSIZE_TO_POINTER (cursor) == NULL)
    cursor += GLIB_SIZEOF_VOID_P;
  if (cursor == error)
    return FALSE;

  if (frida_is_empty_function (GUM_ADDRESS (*(gpointer *) GSIZE_TO_POINTER (cursor))) &&
      frida_is_empty_function (GUM_ADDRESS (*(gpointer *) GSIZE_TO_POINTER (cursor + GLIB_SIZEOF_VOID_P))))
  {
    *shift = cursor - GPOINTER_TO_SIZE (vtable);
  }
  else
  {
    *shift = cursor - GPOINTER_TO_SIZE (vtable) - 2 * GLIB_SIZEOF_VOID_P;
  }

  return TRUE;
}

static gboolean
frida_is_empty_function (GumAddress address)
{
  gboolean matches = FALSE;
  GumMemoryRange range;
  GumMatchPattern * pattern;

  range.base_address = address;
  range.size = 6;

  /*
   * 55      push rbp
   * 4889e5  mov rbp, rsp
   * 5d      pop rbp
   * c3      ret
   */
  pattern = gum_match_pattern_new_from_string ("55 48 89 e5 5d c3");

  gum_memory_scan (&range, pattern, (GumMemoryScanMatchFunc) frida_has_first_match, &matches);

  gum_match_pattern_unref (pattern);

  return matches;
}

static gboolean
frida_has_first_match (GumAddress address, gsize size, gboolean * matches)
{
  *matches = TRUE;
  return FALSE;
}

#endif

#endif
```