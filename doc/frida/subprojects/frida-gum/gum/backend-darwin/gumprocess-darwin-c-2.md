Response:
Let's break down the thought process for analyzing this C code snippet.

**1. Initial Understanding and Goal:**

The first step is to recognize the language (C) and the context (part of Frida, a dynamic instrumentation toolkit, specifically for Darwin/macOS). The prompt asks for the functionality of the code and how it relates to reverse engineering, low-level concepts, debugging, and common errors. The fact that it's the *third* part of a larger file suggests it focuses on more specialized aspects.

**2. Function-by-Function Analysis:**

The most straightforward approach is to examine each function individually. For each function, ask:

* **What does it do?**  What are its inputs and outputs? What are the key operations?
* **Why is this necessary in the context of dynamic instrumentation on Darwin?**
* **How does this relate to reverse engineering?**
* **Does this touch upon low-level details (memory, architecture, OS APIs)?**
* **Are there any logical steps that can be expressed as input/output examples?**
* **What could go wrong (user errors, assumptions)?**

**Applying this to each function:**

* **`gum_darwin_module_enumerate_dependencies_sync`:**  The name suggests it finds and iterates over module dependencies. It uses `GumDarwinModuleResolver`, indicating it interacts with the dynamic linker. This is crucial for understanding how libraries are loaded and interconnected, a key part of reverse engineering.

* **`gum_darwin_find_slide`:** The function signature and variable names (`module_address`, `module`, `slide`) strongly suggest it's calculating the ASLR slide for a given module. It parses the Mach-O header (`mach_header`, `load_command`, `segment_command`). This is fundamental to overcoming address space randomization in reverse engineering.

* **`gum_darwin_find_command`:** Similar to the previous function, it parses the Mach-O header to locate a specific load command by its ID. This is important for analyzing the structure and loading process of executables.

* **`find_image_address_and_slide`:**  This function uses `_dyld_image_count` and `_dyld_get_image_name`/`_dyld_get_image_header`/`_dyld_get_image_vmaddr_slide`. These are direct calls to the dynamic linker's API, used to retrieve information about loaded images. The alias handling for system libraries is interesting.

* **`gum_canonicalize_module_name`:**  This function aims to get the full path of a module, even if only the name is given. It uses `gum_process_enumerate_modules`, indicating it iterates through the process's loaded modules.

* **`gum_store_module_path_if_module_name_matches`:** This is a helper function for the previous one, used as a callback to find a matching module name.

* **`gum_module_path_equals`:**  This utility function checks if a given path matches either the full path or just the name of a module.

* **`gum_thread_state_from_darwin`:** This function maps Darwin thread states to Frida's internal representation. This is necessary for a cross-platform instrumentation tool to have a consistent view of thread states.

* **`gum_darwin_parse_unified_thread_state``gum_darwin_parse_native_thread_state`:** These functions extract CPU register values from Darwin's thread state structures. They handle different architectures (x86, ARM). This is crucial for inspecting and manipulating the execution state.

* **`gum_darwin_unparse_unified_thread_state``/`gum_darwin_unparse_native_thread_state`:** These are the reverse of the previous functions, allowing Frida to *set* CPU register values.

* **`gum_symbol_name_from_darwin`:** This simple function removes the leading underscore from Darwin symbol names, a common convention.

**3. Identifying Connections and Themes:**

After analyzing individual functions, look for overarching themes and connections between them. In this case, several key themes emerge:

* **Mach-O Parsing:**  Multiple functions deal with reading and interpreting the Mach-O executable format.
* **Dynamic Linking (dyld):** Several functions directly interact with the dynamic linker to get information about loaded modules.
* **Thread State Manipulation:** A significant portion of the code focuses on getting and setting CPU registers.
* **Architecture Awareness:** The code uses preprocessor directives (`#ifdef`) to handle different CPU architectures.
* **Module Management:**  Functions for finding, enumerating, and getting information about modules.

**4. Addressing Specific Prompt Questions:**

Go back through the prompt and explicitly address each part:

* **Functionality Listing:**  Summarize the purpose of each function.
* **Relationship to Reverse Engineering:**  Connect the functions to common reverse engineering tasks (understanding program structure, bypassing ASLR, inspecting execution state, etc.).
* **Binary/Kernel/Framework Knowledge:**  Point out where the code interacts with Mach-O, dyld, kernel thread states, and platform-specific APIs.
* **Logical Reasoning (Input/Output):**  Create simple scenarios to illustrate the behavior of functions like `gum_darwin_find_slide` or `gum_canonicalize_module_name`.
* **User/Programming Errors:**  Consider what could go wrong (invalid module names, incorrect assumptions about memory layouts, etc.).
* **User Steps to Reach Here (Debugging):** Explain how a Frida user might trigger these functions (e.g., attaching to a process, listing modules, setting breakpoints).
* **Overall Functionality (Part 3):**  Synthesize the individual functionalities into a broader description of this code segment's role within Frida. Emphasize the low-level interaction with the Darwin operating system.

**5. Refinement and Organization:**

Organize the findings logically. Start with a high-level summary, then detail each function, addressing the specific prompt points for each. Use clear and concise language. Group related functionalities together.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about modules."  **Correction:** While modules are central, thread state manipulation is also a significant part.
* **Initial thought:** "Just list what each function does." **Correction:** The prompt asks for *how* it relates to other areas (reverse engineering, etc.), so simply listing isn't enough.
* **Realization:** The `#ifdef` blocks are crucial for understanding the code's adaptability to different architectures.

By following these steps, we can systematically analyze the code snippet and provide a comprehensive and informative answer that addresses all aspects of the prompt.
这是 `gumprocess-darwin.c` 文件的第三部分，主要包含了与 Darwin (macOS 和 iOS) 操作系统相关的进程和模块操作的底层实现。结合前两部分，我们可以归纳一下它的功能：

**总体功能归纳 (基于三部分):**

`gumprocess-darwin.c` 文件的核心目标是提供 Frida Gum 框架在 Darwin 系统上进行进程内动态 instrumentation 所需的底层能力。它负责：

1. **进程和线程管理:** 获取进程信息 (ID、名称)、枚举进程中的线程、获取和设置线程状态 (寄存器值)。
2. **模块管理:** 枚举进程中加载的模块 (动态库、可执行文件)、查找特定模块、解析模块信息 (基址、大小、路径)、解析 Mach-O 文件头信息 (load commands, segments)。
3. **内存管理:** 读取和写入目标进程的内存。
4. **系统调用:** 执行系统调用 (这部分可能在其他相关文件中，但进程操作离不开系统调用)。
5. **异常处理:** 可能会涉及处理目标进程的异常 (例如，断点触发)。
6. **CPU 上下文管理:**  在 Frida 的通用 CPU 上下文和 Darwin 特有的线程状态结构之间进行转换。
7. **地址空间布局:**  理解和操作目标进程的地址空间布局，例如查找 ASLR 的偏移量 (slide)。

**第三部分功能详细分析：**

这第三部分的代码主要关注以下几个方面：

1. **模块依赖枚举:** `gum_darwin_module_enumerate_dependencies_sync` 函数用于同步地枚举给定模块的依赖项。它使用 `GumDarwinModuleResolver` 来查找模块，并递归地枚举其依赖。

2. **查找 ASLR Slide:** `gum_darwin_find_slide` 函数用于查找给定模块的地址滑动值 (Address Space Layout Randomization slide)。它解析 Mach-O 文件头，查找 `__TEXT` 段，并计算模块加载基址与 `__TEXT` 段的虚拟地址之间的差值。

3. **查找 Load Command:** `gum_darwin_find_command` 函数用于在给定模块中查找特定 ID 的 Mach-O Load Command。它遍历 Mach-O 文件头中的 load commands 并进行匹配。

4. **查找镜像地址和 Slide (通过 dyld):** `find_image_address_and_slide` 函数尝试通过 `dyld` (dynamic loader) 的 API 获取给定镜像 (模块) 的加载地址和 ASLR slide 值。它会检查 `/usr/lib/system/introspection/` 路径下的别名。

5. **规范化模块名称:** `gum_canonicalize_module_name` 函数用于将模块名规范化为完整的路径。如果输入的是简单的模块名，它会遍历已加载的模块列表来查找匹配的路径。

6. **模块路径比较:** `gum_module_path_equals` 函数用于比较给定的路径是否与模块的路径或名称匹配。

7. **Darwin 线程状态到 Frida 线程状态的转换:** `gum_thread_state_from_darwin` 函数将 Darwin 的线程运行状态常量转换为 Frida 的通用线程状态枚举。

8. **解析和反解析 Darwin 线程状态:**
   - `gum_darwin_parse_unified_thread_state` 和 `gum_darwin_parse_native_thread_state` 函数将 Darwin 的线程状态结构 (包含 CPU 寄存器信息) 解析到 Frida 的 `GumCpuContext` 结构中。  这些函数针对不同的 CPU 架构 (x86, ARM, ARM64) 进行了适配。
   - `gum_darwin_unparse_unified_thread_state` 和 `gum_darwin_unparse_native_thread_state` 函数执行相反的操作，将 Frida 的 `GumCpuContext` 中的值写回到 Darwin 的线程状态结构中。

9. **从 Darwin 符号名中提取标准符号名:** `gum_symbol_name_from_darwin` 函数用于移除 Darwin 符号名前的前导下划线。

**与逆向方法的关联和举例说明：**

* **模块依赖分析:**  `gum_darwin_module_enumerate_dependencies_sync` 可以帮助逆向工程师理解目标程序依赖了哪些动态库。这对于分析程序的架构和功能至关重要。
    * **举例:**  通过这个函数，Frida 可以列出一个应用的 `UIKit.framework` 依赖，从而让逆向工程师知道该应用使用了 UIKit 相关的 UI 组件。

* **绕过 ASLR:** `gum_darwin_find_slide` 允许 Frida 动态地计算模块的加载偏移，从而在 hook 函数或读取内存时能够定位到正确的地址。在静态分析中，ASLR 是一个障碍，但在动态分析中，Frida 可以克服它。
    * **举例:**  假设一个函数 `+[NSString stringWithUTF8String:]` 在内存中的实际地址是基址加上 slide 值。Frida 通过 `gum_darwin_find_slide` 获得 `Foundation` 框架的 slide，然后可以计算出该函数的运行时地址并进行 hook。

* **分析 Mach-O 结构:** `gum_darwin_find_command` 使得 Frida 能够检查 Mach-O 文件头的 load commands，例如 `LC_LOAD_DYLIB` (加载动态库)、`LC_SEGMENT_64` (段信息) 等。这对于理解程序的加载过程和内存布局很有帮助。
    * **举例:**  逆向工程师可以使用 Frida 脚本，结合这个函数，检查目标程序是否使用了 `__DATA_CONST` 段来存储常量字符串。

* **获取模块加载信息:** `find_image_address_and_slide` 利用 dyld 的 API 获取模块信息，这为动态分析提供了便利，无需手动解析 Mach-O 文件。

* **CPU 寄存器操作:** `gum_darwin_parse_unified_thread_state` 和 `gum_darwin_unparse_unified_thread_state` 是 Frida 实现 hook 和修改程序行为的核心部分。逆向工程师可以通过修改寄存器值来改变程序的执行流程。
    * **举例:**  在一个函数调用前，可以将返回值寄存器 (例如 x0 或 rax) 设置为特定的值，从而欺骗程序的后续逻辑。或者，在函数执行过程中，修改条件码寄存器来改变分支走向。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层 (Mach-O):** 代码中直接操作 `mach_header`、`load_command`、`segment_command` 等 Mach-O 文件格式的结构体，这是 Darwin 系统上可执行文件和动态库的格式。
* **Darwin 内核:**  虽然代码本身不是内核代码，但它使用了与内核相关的概念，如线程状态 (定义在内核头文件中)。获取和设置线程状态通常需要通过系统调用与内核交互。
* **动态链接器 (dyld):**  `find_image_address_and_slide` 直接使用了 dyld 的 API (`_dyld_image_count`, `_dyld_get_image_name` 等)。理解 dyld 的工作原理对于理解模块加载和依赖关系至关重要。
* **CPU 架构:**  代码中使用了大量的 `#ifdef` 预处理指令来处理不同 CPU 架构 (x86, ARM, ARM64) 的差异，特别是线程状态结构和寄存器名称。
* **内存布局:**  理解虚拟内存、地址空间、ASLR 等概念是理解 `gum_darwin_find_slide` 等函数的关键。

**逻辑推理、假设输入与输出：**

* **`gum_darwin_find_slide`:**
    * **假设输入:** `module_address` 为 0x100000000, `module` 指向一个有效的 Mach-O 文件的内存起始位置，该文件 `__TEXT` 段的 `vmaddr` 为 0x1000。
    * **输出:** `slide` 将被设置为 0x100000000 - 0x1000 = 0xFFFFFFFF000。函数返回 `TRUE`.

* **`gum_canonicalize_module_name`:**
    * **假设输入:** `name` 为 "libSystem.B.dylib"。假设系统中加载了 `/usr/lib/libSystem.B.dylib`。
    * **输出:** 函数将返回指向字符串 `/usr/lib/libSystem.B.dylib` 的指针。

* **`gum_thread_state_from_darwin`:**
    * **假设输入:** `run_state` 为 `TH_STATE_RUNNING`。
    * **输出:** 函数返回 `GUM_THREAD_RUNNING`。

* **`gum_darwin_parse_native_thread_state` (x86_64):**
    * **假设输入:** `ts->__rip` 为 0x7fff00001000。
    * **输出:** `ctx->rip` 将被设置为 0x7fff00001000。

**涉及用户或编程常见的使用错误：**

* **错误的模块名:**  在 `gum_darwin_module_enumerate_dependencies_sync` 或 `find_image_address_and_slide` 中传递不存在或错误的模块名会导致函数找不到模块并返回错误或 NULL。
* **不兼容的 CPU 上下文操作:**  尝试在不匹配目标架构的环境下使用线程状态解析/反解析函数会导致数据错乱或崩溃。Frida 应该处理这些差异，但如果用户直接操作这些底层函数，就需要注意架构匹配。
* **假设固定的内存地址:**  由于 ASLR 的存在，假设模块或函数的地址是固定的会导致 hook 或内存读写失败。应该使用类似 `gum_darwin_find_slide` 的函数来动态计算地址。
* **在不正确的时机操作线程状态:**  在线程正在执行关键代码时修改其状态可能会导致程序崩溃或行为异常。Frida 内部会对线程进行同步和暂停，但如果用户绕过 Frida 的 API 直接操作，可能会出错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户启动一个 Frida 会话并附加到一个 Darwin 进程。**  例如，使用 `frida -p <pid>` 或 `frida -n <process_name>`.
2. **用户尝试 hook 目标进程中的某个函数。**  例如，使用 `Interceptor.attach(Module.findExportByName("libSystem.B.dylib", "open"), { ... })`.
3. **Frida 内部需要解析 "libSystem.B.dylib" 模块的信息。**  这可能触发 `gum_canonicalize_module_name` 来获取完整的模块路径。
4. **Frida 需要获取 `open` 函数的运行时地址。** 这会涉及到查找模块的基址和 ASLR slide，可能会调用 `find_image_address_and_slide` 或相关的模块查找函数。
5. **在 hook 点被命中时，Frida 需要获取当前线程的 CPU 上下文。** 这会调用 `gum_darwin_parse_unified_thread_state` 或 `gum_darwin_parse_native_thread_state` 来读取寄存器值。
6. **用户可能想要修改函数的参数或返回值。**  这会调用 `gum_darwin_unparse_unified_thread_state` 或 `gum_darwin_unparse_native_thread_state` 来修改寄存器值。
7. **如果用户尝试枚举目标进程加载的模块，** Frida 会使用类似的机制，调用内部的模块枚举函数，可能会涉及到 `gum_darwin_module_enumerate_dependencies_sync` 等。

**总结:**

这部分代码是 Frida 在 Darwin 系统上进行动态 instrumentation 的重要组成部分，它提供了访问和操作目标进程的模块信息、内存布局以及线程状态的底层能力。理解这些代码有助于深入了解 Frida 的工作原理，并在进行更复杂的逆向分析和动态 instrumentation 时提供帮助。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumprocess-darwin.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
,
                                   gpointer user_data)
{
  GumDarwinModuleResolver * resolver;
  GumDarwinModule * module;

  resolver = gum_darwin_module_resolver_new (task, NULL);
  if (resolver == NULL)
    return;

  module = gum_darwin_module_resolver_find_module (resolver, module_name);
  if (module != NULL)
    gum_darwin_module_enumerate_dependencies (module, func, user_data);

  gum_object_unref (resolver);
}

gboolean
gum_darwin_find_slide (GumAddress module_address,
                       const guint8 * module,
                       gsize module_size,
                       gint64 * slide)
{
  struct mach_header * header;
  const guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      struct segment_command * sc = (struct segment_command *) lc;
      struct segment_command_64 * sc64 = (struct segment_command_64 *) lc;
      if (strcmp (sc->segname, "__TEXT") == 0)
      {
        if (header->magic == MH_MAGIC)
          *slide = module_address - sc->vmaddr;
        else
          *slide = module_address - sc64->vmaddr;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

gboolean
gum_darwin_find_command (guint id,
                         const guint8 * module,
                         gsize module_size,
                         gpointer * command)
{
  struct mach_header * header;
  const guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == id)
    {
      *command = lc;
      return TRUE;
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
find_image_address_and_slide (const gchar * image_name,
                              gpointer * address,
                              gpointer * slide)
{
  gboolean found = FALSE;
  const gchar * sysroot;
  guint sysroot_size;
  gchar * image_alias;
  guint count, i;

  sysroot = gum_darwin_query_sysroot ();
  sysroot_size = (sysroot != NULL) ? strlen (sysroot) : 0;

  image_alias = g_str_has_prefix (image_name, "/usr/lib/system/")
      ? g_strconcat ("/usr/lib/system/introspection/", image_name + 16, NULL)
      : NULL;

  count = _dyld_image_count ();

  for (i = 0; i != count; i++)
  {
    const gchar * candidate_name;

    candidate_name = _dyld_get_image_name (i);
    if (sysroot != NULL && g_str_has_prefix (candidate_name, sysroot))
      candidate_name += sysroot_size;

    if (gum_module_path_equals (candidate_name, image_name) ||
        ((image_alias != NULL) &&
         gum_module_path_equals (candidate_name, image_alias)))
    {
      *address = (gpointer) _dyld_get_image_header (i);
      *slide = (gpointer) _dyld_get_image_vmaddr_slide (i);
      found = TRUE;
      break;
    }
  }

  g_free (image_alias);

  return found;
}

static gchar *
gum_canonicalize_module_name (const gchar * name)
{
  GumCanonicalizeNameContext ctx;

  if (name[0] == '/')
    return g_strdup (name);

  ctx.module_name = name;
  ctx.module_path = NULL;
  gum_process_enumerate_modules (gum_store_module_path_if_module_name_matches,
      &ctx);
  return ctx.module_path;
}

static gboolean
gum_store_module_path_if_module_name_matches (const GumModuleDetails * details,
                                              gpointer user_data)
{
  GumCanonicalizeNameContext * ctx = user_data;

  if (strcmp (details->name, ctx->module_name) == 0)
  {
    ctx->module_path = g_strdup (details->path);
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_module_path_equals (const gchar * path,
                        const gchar * name_or_path)
{
  gchar * s;

  if (name_or_path[0] == '/')
    return strcmp (name_or_path, path) == 0;

  if ((s = strrchr (path, '/')) != NULL)
    return strcmp (name_or_path, s + 1) == 0;

  return strcmp (name_or_path, path) == 0;
}

static GumThreadState
gum_thread_state_from_darwin (integer_t run_state)
{
  switch (run_state)
  {
    case TH_STATE_RUNNING: return GUM_THREAD_RUNNING;
    case TH_STATE_STOPPED: return GUM_THREAD_STOPPED;
    case TH_STATE_WAITING: return GUM_THREAD_WAITING;
    case TH_STATE_UNINTERRUPTIBLE: return GUM_THREAD_UNINTERRUPTIBLE;
    case TH_STATE_HALTED:
    default:
      return GUM_THREAD_HALTED;
  }
}

void
gum_darwin_parse_unified_thread_state (const GumDarwinUnifiedThreadState * ts,
                                       GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  gum_darwin_parse_native_thread_state (&ts->uts.ts32, ctx);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  gum_darwin_parse_native_thread_state (&ts->uts.ts64, ctx);
#elif defined (HAVE_ARM)
  gum_darwin_parse_native_thread_state (&ts->ts_32, ctx);
#elif defined (HAVE_ARM64)
  gum_darwin_parse_native_thread_state (&ts->ts_64, ctx);
#endif
}

void
gum_darwin_parse_native_thread_state (const GumDarwinNativeThreadState * ts,
                                      GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  ctx->eip = ts->__eip;

  ctx->edi = ts->__edi;
  ctx->esi = ts->__esi;
  ctx->ebp = ts->__ebp;
  ctx->esp = ts->__esp;
  ctx->ebx = ts->__ebx;
  ctx->edx = ts->__edx;
  ctx->ecx = ts->__ecx;
  ctx->eax = ts->__eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  ctx->rip = ts->__rip;

  ctx->r15 = ts->__r15;
  ctx->r14 = ts->__r14;
  ctx->r13 = ts->__r13;
  ctx->r12 = ts->__r12;
  ctx->r11 = ts->__r11;
  ctx->r10 = ts->__r10;
  ctx->r9 = ts->__r9;
  ctx->r8 = ts->__r8;

  ctx->rdi = ts->__rdi;
  ctx->rsi = ts->__rsi;
  ctx->rbp = ts->__rbp;
  ctx->rsp = ts->__rsp;
  ctx->rbx = ts->__rbx;
  ctx->rdx = ts->__rdx;
  ctx->rcx = ts->__rcx;
  ctx->rax = ts->__rax;
#elif defined (HAVE_ARM)
  guint n;

  ctx->pc = ts->__pc;
  ctx->sp = ts->__sp;
  ctx->cpsr = ts->__cpsr;

  ctx->r8 = ts->__r[8];
  ctx->r9 = ts->__r[9];
  ctx->r10 = ts->__r[10];
  ctx->r11 = ts->__r[11];
  ctx->r12 = ts->__r[12];

  memset (ctx->v, 0, sizeof (ctx->v));

  for (n = 0; n != G_N_ELEMENTS (ctx->r); n++)
    ctx->r[n] = ts->__r[n];
  ctx->lr = ts->__lr;
#elif defined (HAVE_ARM64)
  guint n;

# ifdef HAVE_PTRAUTH
  ctx->pc = GPOINTER_TO_SIZE (ts->__opaque_pc);
  ctx->sp = GPOINTER_TO_SIZE (ts->__opaque_sp);

  ctx->fp = GPOINTER_TO_SIZE (ts->__opaque_fp);
  ctx->lr = GPOINTER_TO_SIZE (ts->__opaque_lr);
# else
  ctx->pc = GPOINTER_TO_SIZE (__darwin_arm_thread_state64_get_pc_fptr (*ts));
  ctx->sp = __darwin_arm_thread_state64_get_sp (*ts);

  ctx->fp = __darwin_arm_thread_state64_get_fp (*ts);
  ctx->lr = GPOINTER_TO_SIZE (__darwin_arm_thread_state64_get_lr_fptr (*ts));
# endif

  for (n = 0; n != G_N_ELEMENTS (ctx->x); n++)
    ctx->x[n] = ts->__x[n];

  memset (ctx->v, 0, sizeof (ctx->v));
#endif
}

void
gum_darwin_unparse_unified_thread_state (const GumCpuContext * ctx,
                                         GumDarwinUnifiedThreadState * ts)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  x86_state_hdr_t * header = &ts->tsh;

  header->flavor = x86_THREAD_STATE32;
  header->count = x86_THREAD_STATE32_COUNT;

  gum_darwin_unparse_native_thread_state (ctx, &ts->uts.ts32);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  x86_state_hdr_t * header = &ts->tsh;

  header->flavor = x86_THREAD_STATE64;
  header->count = x86_THREAD_STATE64_COUNT;

  gum_darwin_unparse_native_thread_state (ctx, &ts->uts.ts64);
#elif defined (HAVE_ARM)
  arm_state_hdr_t * header = &ts->ash;

  header->flavor = ARM_THREAD_STATE;
  header->count = ARM_THREAD_STATE_COUNT;

  gum_darwin_unparse_native_thread_state (ctx, &ts->ts_32);
#elif defined (HAVE_ARM64)
  arm_state_hdr_t * header = &ts->ash;

  header->flavor = ARM_THREAD_STATE64;
  header->count = ARM_THREAD_STATE64_COUNT;

  gum_darwin_unparse_native_thread_state (ctx, &ts->ts_64);
#endif
}

void
gum_darwin_unparse_native_thread_state (const GumCpuContext * ctx,
                                        GumDarwinNativeThreadState * ts)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  ts->__eip = ctx->eip;

  ts->__edi = ctx->edi;
  ts->__esi = ctx->esi;
  ts->__ebp = ctx->ebp;
  ts->__esp = ctx->esp;
  ts->__ebx = ctx->ebx;
  ts->__edx = ctx->edx;
  ts->__ecx = ctx->ecx;
  ts->__eax = ctx->eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  ts->__rip = ctx->rip;

  ts->__r15 = ctx->r15;
  ts->__r14 = ctx->r14;
  ts->__r13 = ctx->r13;
  ts->__r12 = ctx->r12;
  ts->__r11 = ctx->r11;
  ts->__r10 = ctx->r10;
  ts->__r9 = ctx->r9;
  ts->__r8 = ctx->r8;

  ts->__rdi = ctx->rdi;
  ts->__rsi = ctx->rsi;
  ts->__rbp = ctx->rbp;
  ts->__rsp = ctx->rsp;
  ts->__rbx = ctx->rbx;
  ts->__rdx = ctx->rdx;
  ts->__rcx = ctx->rcx;
  ts->__rax = ctx->rax;
#elif defined (HAVE_ARM)
  guint n;

  ts->__pc = ctx->pc;
  ts->__sp = ctx->sp;
  ts->__cpsr = ctx->cpsr;

  ts->__r[8] = ctx->r8;
  ts->__r[9] = ctx->r9;
  ts->__r[10] = ctx->r10;
  ts->__r[11] = ctx->r11;
  ts->__r[12] = ctx->r12;

  for (n = 0; n != G_N_ELEMENTS (ctx->r); n++)
    ts->__r[n] = ctx->r[n];
  ts->__lr = ctx->lr;
#elif defined (HAVE_ARM64)
  guint n;

# ifdef HAVE_PTRAUTH
  ts->__opaque_pc = GSIZE_TO_POINTER (ctx->pc);
  ts->__opaque_sp = GSIZE_TO_POINTER (ctx->sp);

  ts->__opaque_fp = GSIZE_TO_POINTER (ctx->fp);
  ts->__opaque_lr = GSIZE_TO_POINTER (ctx->lr);
# else
  __darwin_arm_thread_state64_set_pc_fptr (*ts, GSIZE_TO_POINTER (ctx->pc));
  __darwin_arm_thread_state64_set_sp (*ts, ctx->sp);

  __darwin_arm_thread_state64_set_fp (*ts, ctx->fp);
  __darwin_arm_thread_state64_set_lr_fptr (*ts, GSIZE_TO_POINTER (ctx->lr));
# endif

  for (n = 0; n != G_N_ELEMENTS (ctx->x); n++)
    ts->__x[n] = ctx->x[n];
#endif
}

const char *
gum_symbol_name_from_darwin (const char * s)
{
  return (s[0] == '_') ? s + 1 : s;
}

"""


```