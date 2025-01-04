Response:
Let's break down the thought process to generate the summary of `gumelfmodule.c`.

1. **Understand the Goal:** The core request is to summarize the *functionality* of the provided C code for `gumelfmodule.c`, specifically within the context of Frida, dynamic instrumentation, and reverse engineering. It also asks for connections to binary internals, OS concepts, examples of use and errors, and how a user might reach this code.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for keywords and function names that suggest its purpose. Notice repeated terms like "Elf," "module," "enumerate," "section," "segment," "relocation," "symbol," "dynamic," "import," "export," "dependency." This immediately points to the code's involvement with parsing and analyzing ELF (Executable and Linkable Format) files, the standard binary format on Linux and Android.

3. **Function Grouping and Abstraction:**  Start grouping related functions. For instance, functions starting with `gum_elf_module_enumerate_` clearly deal with iterating over different parts of the ELF file. Functions with `gum_elf_module_find_` are for searching. Functions like `gum_elf_module_read_` handle low-level data reading. This grouping helps to create higher-level functional categories.

4. **Identify Core Functionality:** Based on the grouped functions and keywords, start formulating the main functions of the module. The enumeration functions suggest the ability to list segments, sections, relocations, symbols, dynamic entries, imports, exports, and dependencies. The "find" functions suggest the ability to locate specific elements within the ELF structure. The "read" functions imply parsing and interpretation of the ELF data.

5. **Connect to Reverse Engineering:**  Consider *why* someone would want to do these things in a reverse engineering context. Enumerating symbols and imports/exports is crucial for understanding a program's API and how it interacts with other libraries. Relocations are essential for understanding how code and data are adjusted when a library is loaded at runtime. Sections and segments provide the basic structure of the executable.

6. **Relate to Binary Internals and OS Concepts:** Think about the underlying concepts involved. ELF is a binary format, so byte-level operations and understanding of data structures are relevant. Relocations are a direct consequence of dynamic linking in operating systems like Linux and Android. Segments and sections relate to memory management and loading processes. Dynamic entries are part of the dynamic linking process. The mention of Android linker confirms its relevance in that ecosystem.

7. **Consider User Interaction and Debugging:**  How does a Frida user end up using this code?  Frida's core functionality is about inspecting and modifying running processes. When Frida targets a process, it needs to understand the structure of the loaded modules (executables and libraries). This module is likely involved in that initial parsing and analysis. Debugging scenarios might involve inspecting module structures, understanding relocation issues, or examining symbol tables.

8. **Hypothesize Inputs and Outputs (Logical Reasoning):**  Think about specific functions and what their inputs and outputs would be. For `gum_elf_module_enumerate_symbols`, the input is a `GumElfModule` object, and the output is a series of calls to a callback function (`GumFoundElfSymbolFunc`) with `GumElfSymbolDetails` for each symbol. For `gum_elf_module_find_section_header_by_name`, the input is the module and a section name, and the output is a pointer to the section header or NULL.

9. **Identify Potential User Errors:**  What could go wrong from a user's perspective?  Providing an invalid path to a module would be a common error. Trying to access non-existent symbols or sections could also lead to issues. Misinterpreting the data returned by these functions is another possibility.

10. **Structure the Summary:** Organize the information logically. Start with a high-level overview of the module's purpose. Then, detail the specific functionalities, linking them to reverse engineering concepts. Address the binary/OS aspects, provide input/output examples, discuss user errors, and finally explain how the user reaches this code.

11. **Refine and Iterate:** Read through the generated summary and refine it for clarity and accuracy. Ensure that the language is precise and avoids jargon where possible (or explains it when necessary). Check if all aspects of the prompt have been addressed. For instance, the prompt explicitly asks to "归纳一下它的功能" (summarize its functionality), which encourages a concise overview.

By following these steps, moving from a broad understanding to specific details and considering the context of Frida and reverse engineering, one can effectively summarize the functionality of a complex piece of code like `gumelfmodule.c`.
这是对Frida动态插桩工具源代码文件 `frida/subprojects/frida-gum/gum/gumelfmodule.c` 第二部分的分析归纳。结合之前的第一部分，我们可以对这个文件的整体功能进行总结。

**整体功能归纳 (结合第一部分和第二部分):**

`gumelfmodule.c` 文件的核心功能是**解析和表示 ELF (Executable and Linkable Format) 模块的信息，以便于Frida进行动态插桩和分析。**  它提供了一系列函数，用于读取、解析和遍历 ELF 文件的各种结构，例如：

1. **模块加载和初始化:**
   - 读取 ELF 文件的头部信息 (Ehdr)。
   - 读取程序头部 (Phdr) 和节头部 (Shdr) 表。
   - 解析动态节 (Dynamic Section)，获取动态链接信息。
   - 确定模块在内存中的基址。
   - 处理 APK 文件中的模块提取（Android 特定）。

2. **ELF 结构遍历和信息提取:**
   - **段 (Segments):**  枚举和获取程序段的详细信息 (内存地址、大小、文件偏移、权限等)。
   - **节 (Sections):** 枚举和获取节的详细信息 (名称、地址、大小等)。
   - **重定位 (Relocations):** 枚举和获取重定位条目的详细信息，包括地址、类型、符号索引、附加值等。这对于理解动态链接过程至关重要。
   - **动态条目 (Dynamic Entries):** 枚举和获取动态链接段的条目，例如 `NEEDED` (依赖库)、`SYMTAB` (符号表)、`STRTAB` (字符串表) 等。
   - **符号 (Symbols):** 枚举和获取符号表中的符号信息，包括名称、地址、大小、类型、绑定属性等。它可以区分动态符号和普通符号。
   - **导入 (Imports):**  枚举模块导入的外部符号，包括函数和变量。它会尝试通过重定位信息和动态符号信息来识别导入。
   - **导出 (Exports):** 枚举模块导出的符号，包括函数和变量。
   - **依赖 (Dependencies):** 枚举模块依赖的其他共享库。

3. **数据读取和转换:**
   - 提供了一系列函数用于从 ELF 文件或内存中读取不同大小的整数 (uint8, uint16, uint32, uint64)。
   - 考虑了字节序 (大端和小端) 的问题。
   - 提供了在线地址和离线地址之间的转换函数，这在动态插桩中非常重要，因为模块在文件中的地址和加载到内存后的地址可能不同。

4. **辅助功能:**
   - 查找特定类型或索引的程序头和节头。
   - 计算模块的首选加载地址和映射大小。
   - 检查内存边界，避免读取越界。
   - 处理符号名称的边界检查。

**与逆向方法的关联和举例:**

- **理解程序结构:**  通过枚举段和节，逆向工程师可以了解程序的内存布局，代码、数据、只读数据等分别存储在哪些区域。
    - **例子:** 逆向一个恶意软件时，可以通过查看 `.text` 节来定位代码入口点，查看 `.rodata` 节来寻找硬编码的字符串。
- **分析动态链接:**  枚举重定位条目可以帮助理解程序如何解析对外部库函数的调用。
    - **例子:**  当逆向一个使用了 `libc` 库的程序时，可以查看 `JUMP_SLOT` 类型的重定位，了解程序如何通过 GOT (Global Offset Table) 调用 `printf` 或 `malloc` 等函数。
- **识别函数和变量:** 枚举符号表可以列出程序中定义的所有函数和全局变量。
    - **例子:**  在逆向一个加壳的程序时，可能需要找到原始的 `main` 函数，可以通过符号表中的 `main` 符号来定位。
- **了解模块依赖关系:** 枚举依赖项可以帮助理解程序依赖哪些外部库，这对于环境搭建和行为分析很重要。
    - **例子:**  在分析一个使用了 `libssl` 的程序时，可以通过依赖项列表确认该程序可能涉及加密操作。
- **动态跟踪和Hook:**  Frida 的核心功能是 Hook 函数。`gumelfmodule.c` 提供的符号信息 (名称和地址) 是进行 Hook 的基础。
    - **例子:** 使用 Frida Hook `fopen` 函数，需要先通过符号表找到 `fopen` 的地址。

**涉及的二进制底层、Linux/Android 内核及框架知识:**

- **ELF 文件格式:**  `gumelfmodule.c` 深入操作 ELF 文件的各种头部和表结构，需要对 ELF 格式有深入的理解，包括 Ehdr, Phdr, Shdr, Dynamic Section, Symbol Table, Relocation Table 等。
- **动态链接:**  代码中处理了重定位、动态符号、GOT、PLT 等概念，这些都是动态链接的核心组成部分，是 Linux 和 Android 系统中共享库工作的基础。
- **内存管理:**  涉及到程序段的加载地址、大小、权限等，这些都与操作系统的内存管理机制紧密相关。
- **进程加载:**  理解程序加载器如何将 ELF 文件加载到内存中，并进行地址重定位，是理解 `gumelfmodule.c` 功能的背景知识。
- **Linux 系统调用接口:**  虽然代码本身没有直接调用系统调用，但其解析的信息最终与系统调用的执行息息相关。
- **Android Framework (特定情况):**  处理 APK 提取和 linker 模块的特殊导出，涉及到 Android 平台的特定知识。

**逻辑推理、假设输入与输出:**

假设我们有一个简单的共享库 `libtest.so`，它导出一个函数 `test_function` 和一个全局变量 `test_variable`，并依赖于 `libc.so`。

- **假设输入:** 指向 `libtest.so` 内存映射的指针 (`GumElfModule *self`)。
- **输出示例:**
    - `gum_elf_module_enumerate_exports` 会回调 `GumFoundExportFunc`，并提供 `test_function` (类型为 `GUM_EXPORT_FUNCTION`) 和 `test_variable` (类型为 `GUM_EXPORT_VARIABLE`) 的名称和地址。
    - `gum_elf_module_enumerate_imports` 可能会回调 `GumFoundImportFunc`，提供来自 `libc.so` 的导入函数，例如 `printf` 的名称。
    - `gum_elf_module_enumerate_dependencies` 会回调 `GumFoundDependencyFunc`，提供 `libc.so` 的名称。
    - `gum_elf_module_enumerate_sections` 会列出 `.text`, `.data`, `.bss`, `.dynsym`, `.dynstr`, `.rel.dyn` 等节的详细信息。
    - `gum_elf_module_enumerate_relocations` 会列出针对外部符号的重定位条目，例如将 `printf` 的调用地址指向 GOT 表中的条目。

**涉及用户或编程常见的使用错误:**

- **传递无效的模块指针:** 如果 `GumElfModule *self` 是空指针或者指向无效的内存区域，会导致程序崩溃或未定义的行为。
- **假设符号一定存在:** 用户在尝试通过名称查找符号时，如果没有进行错误处理，当符号不存在时可能会导致问题。
- **错误地理解地址:**  混淆在线地址和离线地址，可能导致 Hook 到错误的内存位置。
- **在不适用的平台上使用特定功能:** 例如，在非 Android 平台上尝试使用 APK 提取相关的功能。
- **内存越界访问 (理论上):** 虽然 `gumelfmodule.c` 内部有边界检查，但如果 Frida 的其他部分提供的模块信息不准确，仍然可能导致越界访问。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 启动并附加到目标进程:** 用户使用 Frida CLI 或 Python API 附加到一个正在运行的进程。
2. **脚本执行，需要访问模块信息:**  Frida 脚本中，用户可能需要获取目标进程中加载的某个模块的信息，例如基址、导出函数等。
3. **Frida 调用 Gum API 获取模块信息:**  Frida 的 JavaScript 引擎会调用 Gum 库的 C API 来执行相应的操作。
4. **Gum 调用 `gum_elf_module_find_by_address` 或其他相关函数:** Gum 库会根据模块的加载地址或其他标识符找到对应的 `GumElfModule` 结构。
5. **调用 `gumelfmodule.c` 中的函数进行解析:**  例如，用户调用 `Module.getExportByName()`，最终会调用 `gum_elf_module_enumerate_exports` 和相关的符号查找函数。
6. **调试线索:** 如果在上述步骤中出现错误，例如找不到模块、找不到符号，或者访问了无效的内存地址，那么调试器可能会停在 `gumelfmodule.c` 的某个函数中，例如在边界检查失败时。查看函数调用栈，可以追溯到用户脚本的哪个操作触发了对 `gumelfmodule.c` 的调用。

总而言之，`gumelfmodule.c` 是 Frida 工具中一个至关重要的组成部分，它负责将底层的 ELF 二进制数据转化为高层次的、易于理解和操作的信息，为 Frida 的动态插桩功能提供了坚实的基础。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gumelfmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
                      gpointer user_data)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * h = &g_array_index (self->phdrs, GumElfPhdr, i);
    GumElfSegmentDetails d;

    if (h->type != GUM_ELF_PHDR_LOAD)
      continue;

    d.vm_address = h->vaddr;
    d.vm_size = h->memsz;
    d.file_offset = h->offset;
    d.file_size = h->filesz;
    d.protection = gum_parse_phdr_protection (h);

    if (!func (&d, user_data))
      return;
  }
}

void
gum_elf_module_enumerate_sections (GumElfModule * self,
                                   GumFoundElfSectionFunc func,
                                   gpointer user_data)
{
  guint i;

  for (i = 0; i != self->shdrs->len; i++)
  {
    const GumElfSectionDetails * d =
        &g_array_index (self->sections, GumElfSectionDetails, i);

    if (!func (d, user_data))
      return;
  }
}

void
gum_elf_module_enumerate_relocations (GumElfModule * self,
                                      GumFoundElfRelocationFunc func,
                                      gpointer user_data)
{
  gconstpointer data;
  gsize size;
  guint i;
  GumElfRelocationGroup g = { 0, };

  data = gum_elf_module_get_file_data (self, &size);

  for (i = 0; i != self->shdrs->len; i++)
  {
    const GumElfShdr * shdr = &g_array_index (self->shdrs, GumElfShdr, i);

    switch (shdr->type)
    {
      case GUM_ELF_SECTION_REL:
      case GUM_ELF_SECTION_RELA:
      {
        const GumElfShdr * symtab_shdr;

        memset (&g, 0, sizeof (g));

        g.offset = shdr->offset;
        g.size = shdr->size;
        g.entsize = shdr->entsize;
        g.relocs_have_addend = shdr->type == GUM_ELF_SECTION_RELA;

        symtab_shdr =
            gum_elf_module_find_section_header_by_index (self, shdr->link);
        if (symtab_shdr != NULL)
        {
          const GumElfShdr * strings_shdr;

          g.symtab_offset = symtab_shdr->offset;
          g.symtab_entsize = symtab_shdr->entsize;

          strings_shdr = gum_elf_module_find_section_header_by_index (self,
              symtab_shdr->link);
          if (strings_shdr != NULL)
          {
            g.strings = (const gchar *) data + strings_shdr->offset;
            g.strings_base = data;
            g.strings_size = size;
          }
        }

        g.parent = &g_array_index (self->sections, GumElfSectionDetails, i);

        if (!gum_elf_module_emit_relocations (self, &g, func, user_data))
          return;

        break;
      }
      default:
        break;
    }
  }

  if (g.offset != 0)
    return;

  for (i = 0; i != self->dyns->len; i++)
  {
    const GumElfDyn * dyn = &g_array_index (self->dyns, GumElfDyn, i);

    switch (dyn->tag)
    {
      case GUM_ELF_DYNAMIC_REL:
      case GUM_ELF_DYNAMIC_RELA:
        g.offset = dyn->val;
        g.relocs_have_addend = dyn->tag == GUM_ELF_DYNAMIC_RELA;
        break;
      case GUM_ELF_DYNAMIC_RELSZ:
      case GUM_ELF_DYNAMIC_RELASZ:
        g.size = dyn->val;
        break;
      case GUM_ELF_DYNAMIC_RELENT:
      case GUM_ELF_DYNAMIC_RELAENT:
        g.entsize = dyn->val;
        break;
      case GUM_ELF_DYNAMIC_SYMTAB:
        g.symtab_offset = dyn->val;
        break;
      case GUM_ELF_DYNAMIC_SYMENT:
        g.symtab_entsize = dyn->val;
        break;
      default:
        break;
    }
  }

  g.strings = self->dynamic_strings;
  g.strings_base = gum_elf_module_get_live_data (self, &g.strings_size);

  gum_elf_module_emit_relocations (self, &g, func, user_data);
}

static gboolean
gum_elf_module_emit_relocations (GumElfModule * self,
                                 const GumElfRelocationGroup * g,
                                 GumFoundElfRelocationFunc func,
                                 gpointer user_data)
{
  guint64 minimum_entsize;
  gconstpointer data;
  gsize size;
  guint n, i;
  gconstpointer start, end, cursor;

  GError ** error = NULL;

  if (g->offset == 0 || g->size == 0 || g->entsize == 0)
    goto invalid_group;
  if (g->symtab_offset == 0 || g->symtab_entsize == 0)
    goto invalid_group;
  if (g->strings == NULL)
    goto invalid_group;

  switch (self->ehdr.identity.klass)
  {
    case GUM_ELF_CLASS_64:
      minimum_entsize = g->relocs_have_addend ? 24 : 16;
      break;
    case GUM_ELF_CLASS_32:
      minimum_entsize = g->relocs_have_addend ? 12 : 8;
      break;
    default:
      g_assert_not_reached ();
  }
  if (g->entsize < minimum_entsize)
    goto invalid_group;

  data = gum_elf_module_get_file_data (self, &size);

  n = g->size / g->entsize;

  start = (const guint8 *) data + g->offset;
  end = (const guint8 *) start + g->size;
  GUM_CHECK_BOUNDS (start, end, "relocations");

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfRelocationDetails d;
    guint32 sym_index;
    GumElfSymbolDetails sym_details;

    d.addend = 0;

    switch (self->ehdr.identity.klass)
    {
      case GUM_ELF_CLASS_64:
      {
        guint64 info;

        d.address = gum_elf_module_read_uint64 (self, cursor);

        info = gum_elf_module_read_uint64 (self,
            (const guint64 *) ((const guint8 *) cursor + 8));
        d.type = info & GUM_INT32_MASK;
        sym_index = info >> 32;

        if (g->relocs_have_addend)
        {
          d.addend = gum_elf_module_read_int64 (self,
              (const gint64 *) ((const guint8 *) cursor + 16));
        }

        break;
      }
      case GUM_ELF_CLASS_32:
      {
        guint32 info;

        d.address = gum_elf_module_read_uint32 (self, cursor);

        info = gum_elf_module_read_uint32 (self,
            (const guint32 *) ((const guint8 *) cursor + 4));
        d.type = info & GUM_INT8_MASK;
        sym_index = info >> 8;

        if (g->relocs_have_addend)
        {
          d.addend = gum_elf_module_read_int32 (self,
              (const gint32 *) ((const guint8 *) cursor + 8));
        }

        break;
      }
      default:
        g_assert_not_reached ();
    }

    d.address = gum_elf_module_translate_to_online (self, d.address);

    if (sym_index != GUM_STN_UNDEF)
    {
      gconstpointer sym_start, sym_end;
      GumElfSym sym_val;

      sym_start = (const guint8 *) data + g->symtab_offset +
          (sym_index * g->symtab_entsize);
      sym_end = (const guint8 *) sym_start + g->symtab_entsize;
      GUM_CHECK_BOUNDS (sym_start, sym_end, "relocation symbol");

      gum_elf_module_read_symbol (self, sym_start, &sym_val);

      gum_elf_module_parse_symbol (self, &sym_val, g->strings, &sym_details);
      if (sym_details.name != NULL)
      {
        if (!gum_elf_module_check_str_bounds (self, sym_details.name,
              g->strings_base, g->strings_size, "relocation symbol name", NULL))
          goto invalid_group;
      }
      else
      {
        sym_details.name = "";
      }

      d.symbol = &sym_details;
    }
    else
    {
      d.symbol = NULL;
    }

    d.parent = g->parent;

    if (!func (&d, user_data))
      return FALSE;

    cursor = (const guint8 *) cursor + g->entsize;
  }

  return TRUE;

invalid_group:
propagate_error:
  return TRUE;
}

void
gum_elf_module_enumerate_dynamic_entries (GumElfModule * self,
                                          GumFoundElfDynamicEntryFunc func,
                                          gpointer user_data)
{
  guint i;

  for (i = 0; i != self->dyns->len; i++)
  {
    const GumElfDyn * dyn = &g_array_index (self->dyns, GumElfDyn, i);
    GumElfDynamicEntryDetails d;

    d.tag = dyn->tag;
    d.val = dyn->val;

    if (!func (&d, user_data))
      return;
  }
}

void
gum_elf_module_enumerate_imports (GumElfModule * self,
                                  GumFoundImportFunc func,
                                  gpointer user_data)
{
  GumElfEnumerateImportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.slots = g_hash_table_new (g_str_hash, g_str_equal);
  if (gum_try_get_jump_slot_relocation_type_for_machine (self->ehdr.machine,
        &ctx.jump_slot_type))
  {
    gum_elf_module_enumerate_relocations (self,
        gum_maybe_collect_import_slot_from_relocation, &ctx);
  }

  gum_elf_module_enumerate_dynamic_symbols (self, gum_emit_elf_import, &ctx);

  g_hash_table_unref (ctx.slots);
}

static gboolean
gum_emit_elf_import (const GumElfSymbolDetails * details,
                     gpointer user_data)
{
  GumElfEnumerateImportsContext * ctx = user_data;

  if (details->shdr_index == GUM_ELF_SHDR_INDEX_UNDEF &&
      (details->type == GUM_ELF_SYMBOL_FUNC ||
       details->type == GUM_ELF_SYMBOL_OBJECT))
  {
    GumImportDetails d;

    d.type = (details->type == GUM_ELF_SYMBOL_FUNC)
        ? GUM_EXPORT_FUNCTION
        : GUM_EXPORT_VARIABLE;
    d.name = details->name;
    d.module = NULL;
    d.address = 0;
    d.slot = GUM_ADDRESS (g_hash_table_lookup (ctx->slots, details->name));

    if (!ctx->func (&d, ctx->user_data))
      return FALSE;
  }

  return TRUE;
}

static gboolean
gum_try_get_jump_slot_relocation_type_for_machine (GumElfMachine machine,
                                                   guint32 * type)
{
  switch (machine)
  {
    case GUM_ELF_MACHINE_386:
      *type = GUM_ELF_IA32_JMP_SLOT;
      break;
    case GUM_ELF_MACHINE_X86_64:
      *type = GUM_ELF_X64_JUMP_SLOT;
      break;
    case GUM_ELF_MACHINE_ARM:
      *type = GUM_ELF_ARM_JUMP_SLOT;
      break;
    case GUM_ELF_MACHINE_AARCH64:
      *type = GUM_ELF_ARM64_JUMP_SLOT;
      break;
    case GUM_ELF_MACHINE_MIPS:
    case GUM_ELF_MACHINE_MIPS_RS3_LE:
    case GUM_ELF_MACHINE_MIPS_X:
      *type = GUM_ELF_MIPS_JUMP_SLOT;
      break;
    default:
      *type = G_MAXUINT32;
      return FALSE;
  }

  return TRUE;
}

static gboolean
gum_maybe_collect_import_slot_from_relocation (
    const GumElfRelocationDetails * details,
    gpointer user_data)
{
  GumElfEnumerateImportsContext * ctx = user_data;

  if (details->type == ctx->jump_slot_type && details->symbol != NULL)
  {
    g_hash_table_insert (ctx->slots, (gpointer) details->symbol->name,
        GSIZE_TO_POINTER (details->address));
  }

  return TRUE;
}

void
gum_elf_module_enumerate_exports (GumElfModule * self,
                                  GumFoundExportFunc func,
                                  gpointer user_data)
{
  GumElfEnumerateExportsContext ctx;

#ifdef HAVE_ANDROID
  if (self->source_path != NULL &&
      gum_android_is_linker_module_name (self->source_path))
  {
    const gchar ** magic_exports;
    guint i;

    magic_exports = gum_android_get_magic_linker_export_names ();

    for (i = 0; magic_exports[i] != NULL; i++)
    {
      const gchar * name = magic_exports[i];
      GumExportDetails d;

      d.type = GUM_EXPORT_FUNCTION;
      d.name = name;
      d.address = gum_module_find_export_by_name (self->source_path, name);
      g_assert (d.address != 0);

      if (!func (&d, user_data))
        return;
    }
  }
#endif

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_dynamic_symbols (self, gum_emit_elf_export, &ctx);
}

static gboolean
gum_emit_elf_export (const GumElfSymbolDetails * details,
                     gpointer user_data)
{
  GumElfEnumerateExportsContext * ctx = user_data;

  if (details->shdr_index != GUM_ELF_SHDR_INDEX_UNDEF &&
      (details->type == GUM_ELF_SYMBOL_FUNC ||
       details->type == GUM_ELF_SYMBOL_OBJECT) &&
      (details->bind == GUM_ELF_BIND_GLOBAL ||
       details->bind == GUM_ELF_BIND_WEAK))
  {
    GumExportDetails d;

    d.type = (details->type == GUM_ELF_SYMBOL_FUNC)
        ? GUM_EXPORT_FUNCTION
        : GUM_EXPORT_VARIABLE;
    d.name = details->name;
    d.address = details->address;

    if (!ctx->func (&d, ctx->user_data))
      return FALSE;
  }

  return TRUE;
}

void
gum_elf_module_enumerate_dynamic_symbols (GumElfModule * self,
                                          GumFoundElfSymbolFunc func,
                                          gpointer user_data)
{
  GumElfStoreSymtabParamsContext ctx;
  gsize i;
  gconstpointer data;
  gsize size;
  GError ** error = NULL;

  ctx.pending = 3;
  ctx.found_hash = FALSE;

  ctx.entries = NULL;
  ctx.entry_size = 0;
  ctx.entry_count = 0;

  ctx.module = self;

  gum_elf_module_enumerate_dynamic_entries (self, gum_store_symtab_params,
      &ctx);
  if (ctx.pending != 0 || ctx.entry_count == 0)
    return;

  gum_elf_module_enumerate_sections (self, gum_adjust_symtab_params, &ctx);

  data = gum_elf_module_get_live_data (self, &size);

  for (i = 1; i != ctx.entry_count; i++)
  {
    gconstpointer entry = (const guint8 *) ctx.entries + (i * ctx.entry_size);
    GumElfSym sym;
    GumElfSymbolDetails details;

    gum_elf_module_read_symbol (self, entry, &sym);

    gum_elf_module_parse_symbol (self, &sym, self->dynamic_strings, &details);
    if (details.name != NULL)
      GUM_CHECK_STR_BOUNDS (details.name, "symbol name");
    else
      details.name = "";

    if (!func (&details, user_data))
      return;
  }

propagate_error:
  return;
}

static void
gum_elf_module_parse_symbol (GumElfModule * self,
                             const GumElfSym * sym,
                             const gchar * strings,
                             GumElfSymbolDetails * d)
{
  GumElfSymbolType type = GUM_ELF_ST_TYPE (sym->info);
  const GumElfSectionDetails * section;

  section = gum_elf_module_find_section_details_by_index (self, sym->shndx);

  if (type == GUM_ELF_SYMBOL_SECTION)
  {
    d->name = (section != NULL) ? section->name : NULL;
    d->address = self->base_address + sym->value;
  }
  else
  {
    d->name = strings + sym->name;
    d->address = (sym->value != 0)
        ? gum_elf_module_translate_to_online (self, sym->value)
        : 0;
  }

  d->size = sym->size;
  d->type = type;
  d->bind = GUM_ELF_ST_BIND (sym->info);
  d->shdr_index = sym->shndx;
  d->section = section;
}

static void
gum_elf_module_read_symbol (GumElfModule * self,
                            gconstpointer raw_sym,
                            GumElfSym * sym)
{
#define GUM_READ_SYM_FIELD(name, type) \
    GUM_READ (sym->name, src->name, type)
#define GUM_READ_SYM() \
    G_STMT_START \
    { \
      GUM_READ_SYM_FIELD (name,  uint32); \
      GUM_READ_SYM_FIELD (info,  uint8); \
      GUM_READ_SYM_FIELD (other, uint8); \
      GUM_READ_SYM_FIELD (shndx, uint16); \
      GUM_READ_SYM_FIELD (value, uint64); \
      GUM_READ_SYM_FIELD (size,  uint64); \
    } \
    G_STMT_END
#define GUM_READ_SYM32() \
    G_STMT_START \
    { \
      GUM_READ_SYM_FIELD (name,  uint32); \
      GUM_READ_SYM_FIELD (value, uint32); \
      GUM_READ_SYM_FIELD (size,  uint32); \
      GUM_READ_SYM_FIELD (info,  uint8); \
      GUM_READ_SYM_FIELD (other, uint8); \
      GUM_READ_SYM_FIELD (shndx, uint16); \
    } \
    G_STMT_END

  switch (self->ehdr.identity.klass)
  {
    case GUM_ELF_CLASS_64:
    {
      const GumElfSym * src = raw_sym;
      GUM_READ_SYM ();
      break;
    }
    case GUM_ELF_CLASS_32:
    {
      const GumElfSym32 * src = raw_sym;
      GUM_READ_SYM32 ();
      break;
    }
    default:
      g_assert_not_reached ();
  }

#undef GUM_READ_SYM_FIELD
#undef GUM_READ_SYM
#undef GUM_READ_SYM32
}

static gboolean
gum_store_symtab_params (const GumElfDynamicEntryDetails * details,
                         gpointer user_data)
{
  GumElfStoreSymtabParamsContext * ctx = user_data;

  switch (details->tag)
  {
    case GUM_ELF_DYNAMIC_SYMTAB:
      ctx->entries = gum_elf_module_resolve_dynamic_virtual_location (
          ctx->module, details->val);
      ctx->pending--;
      break;
    case GUM_ELF_DYNAMIC_SYMENT:
      ctx->entry_size = details->val;
      ctx->pending--;
      break;
    case GUM_ELF_DYNAMIC_HASH:
    {
      const guint32 * hash_params;
      guint32 nchain;

      if (ctx->found_hash)
        break;
      ctx->found_hash = TRUE;

      hash_params = gum_elf_module_resolve_dynamic_virtual_location (
          ctx->module, details->val);
      nchain = hash_params[1];

      ctx->entry_count = nchain;
      ctx->pending--;

      break;
    }
    case GUM_ELF_DYNAMIC_GNU_HASH:
    {
      const guint32 * hash_params;
      guint32 nbuckets;
      guint32 symoffset;
      guint32 bloom_size;
      const gsize * bloom;
      const guint32 * buckets;
      const guint32 * chain;
      guint32 highest_index, bucket_index;

      if (ctx->found_hash)
        break;
      ctx->found_hash = TRUE;

      hash_params = gum_elf_module_resolve_dynamic_virtual_location (
          ctx->module, details->val);
      nbuckets = hash_params[0];
      symoffset = hash_params[1];
      bloom_size = hash_params[2];
      bloom = (gsize *) (hash_params + 4);
      buckets = (const guint32 *) (bloom + bloom_size);
      chain = buckets + nbuckets;

      highest_index = 0;
      for (bucket_index = 0; bucket_index != nbuckets; bucket_index++)
      {
        highest_index = MAX (buckets[bucket_index], highest_index);
      }

      if (highest_index >= symoffset)
      {
        while (TRUE)
        {
          guint32 hash = chain[highest_index - symoffset];

          if ((hash & 1) != 0)
            break;

          highest_index++;
        }
      }

      ctx->entry_count = highest_index + 1;
      ctx->pending--;

      break;
    }
    default:
      break;
  }

  return ctx->pending != 0;
}

static gboolean
gum_adjust_symtab_params (const GumElfSectionDetails * details,
                          gpointer user_data)
{
  GumElfStoreSymtabParamsContext * ctx = user_data;

  if (details->address == GUM_ADDRESS (ctx->entries))
  {
    ctx->entry_count = details->size / ctx->entry_size;
    return FALSE;
  }

  return TRUE;
}

void
gum_elf_module_enumerate_symbols (GumElfModule * self,
                                  GumFoundElfSymbolFunc func,
                                  gpointer user_data)
{
  gum_elf_module_enumerate_symbols_in_section (self, GUM_ELF_SECTION_SYMTAB,
      func, user_data);
}

static void
gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
                                             GumElfSectionType section,
                                             GumFoundElfSymbolFunc func,
                                             gpointer user_data)
{
  const GumElfShdr * shdr, * strings_shdr;
  gconstpointer data;
  gsize size;
  guint64 n, i;
  gconstpointer start, end;
  const gchar * strings;
  gconstpointer cursor;
  GError ** error = NULL;

  shdr = gum_elf_module_find_section_header_by_type (self, section);
  if (shdr == NULL)
    return;

  strings_shdr =
      gum_elf_module_find_section_header_by_index (self, shdr->link);
  if (strings_shdr == NULL)
    return;

  data = gum_elf_module_get_file_data (self, &size);

  n = shdr->size / shdr->entsize;

  start = (const guint8 *) data + shdr->offset;
  end = (const guint8 *) start + (n * shdr->entsize);
  GUM_CHECK_BOUNDS (start, end, "symbols");

  strings = (const gchar *) data + strings_shdr->offset;

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfSym sym;
    GumElfSymbolDetails details;

    gum_elf_module_read_symbol (self, cursor, &sym);

    gum_elf_module_parse_symbol (self, &sym, strings, &details);
    if (details.name != NULL)
      GUM_CHECK_STR_BOUNDS (details.name, "symbol name");
    else
      details.name = "";

    if (!func (&details, user_data))
      return;

    cursor = (const guint8 *) cursor + shdr->entsize;
  }

propagate_error:
  return;
}

void
gum_elf_module_enumerate_dependencies (GumElfModule * self,
                                       GumFoundDependencyFunc func,
                                       gpointer user_data)
{
  GumElfEnumerateDepsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.module = self;

  gum_elf_module_enumerate_dynamic_entries (self, gum_emit_each_needed, &ctx);
}

static gboolean
gum_emit_each_needed (const GumElfDynamicEntryDetails * details,
                      gpointer user_data)
{
  GumElfEnumerateDepsContext * ctx = user_data;
  gconstpointer data;
  gsize size;
  GumDependencyDetails d;

  if (details->tag != GUM_ELF_DYNAMIC_NEEDED)
    return TRUE;

  data = gum_elf_module_get_live_data (ctx->module, &size);

  d.name = ctx->module->dynamic_strings + details->val;
  if (!gum_elf_module_check_str_bounds (ctx->module, d.name, data, size,
        "dependencies", NULL))
  {
    return TRUE;
  }
  d.type = GUM_DEPENDENCY_REGULAR;

  return ctx->func (&d, ctx->user_data);
}

static gboolean
gum_elf_module_find_address_file_offset (GumElfModule * self,
                                         GumAddress address,
                                         guint64 * offset)
{
  const GumElfPhdr * phdr;
  gsize delta;

  phdr = gum_elf_module_find_load_phdr_by_address (self, address);
  if (phdr == NULL)
    return FALSE;

  delta = address - phdr->vaddr;
  if (delta >= phdr->filesz)
    return FALSE;

  *offset = phdr->offset + delta;

  return TRUE;
}

static gboolean
gum_elf_module_find_address_protection (GumElfModule * self,
                                        GumAddress address,
                                        GumPageProtection * prot)
{
  const GumElfPhdr * phdr;

  phdr = gum_elf_module_find_load_phdr_by_address (self, address);
  if (phdr == NULL)
    return FALSE;

  *prot = gum_parse_phdr_protection (phdr);

  return TRUE;
}

static GumPageProtection
gum_parse_phdr_protection (const GumElfPhdr * phdr)
{
  GumPageProtection p;

  p = GUM_PAGE_NO_ACCESS;
  if ((phdr->flags & GUM_ELF_PHDR_R) != 0)
    p |= GUM_PAGE_READ;
  if ((phdr->flags & GUM_ELF_PHDR_W) != 0)
    p |= GUM_PAGE_WRITE;
  if ((phdr->flags & GUM_ELF_PHDR_X) != 0)
    p |= GUM_PAGE_EXECUTE;

  return p;
}

static const GumElfPhdr *
gum_elf_module_find_phdr_by_type (GumElfModule * self,
                                  guint32 type)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * h = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (h->type == type)
      return h;
  }

  return NULL;
}

static const GumElfPhdr *
gum_elf_module_find_load_phdr_by_address (GumElfModule * self,
                                          GumAddress address)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * h = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (h->type == GUM_ELF_PHDR_LOAD &&
        address >= h->vaddr &&
        address < h->vaddr + h->memsz)
    {
      return h;
    }
  }

  return NULL;
}

static const GumElfShdr *
gum_elf_module_find_section_header_by_index (GumElfModule * self,
                                             guint i)
{
  if (i == GUM_ELF_SHDR_INDEX_UNDEF)
    return NULL;

  if (i >= self->shdrs->len)
    return NULL;

  return &g_array_index (self->shdrs, GumElfShdr, i);
}

static const GumElfShdr *
gum_elf_module_find_section_header_by_type (GumElfModule * self,
                                            GumElfSectionType type)
{
  guint i;

  for (i = 0; i != self->shdrs->len; i++)
  {
    const GumElfShdr * shdr = &g_array_index (self->shdrs, GumElfShdr, i);

    if ((GumElfSectionType) shdr->type == type)
      return shdr;
  }

  return NULL;
}

static const GumElfSectionDetails *
gum_elf_module_find_section_details_by_index (GumElfModule * self,
                                              guint i)
{
  if (i == GUM_ELF_SHDR_INDEX_UNDEF)
    return NULL;

  if (i >= self->sections->len)
    return NULL;

  return &g_array_index (self->sections, GumElfSectionDetails, i);
}

static GumAddress
gum_elf_module_compute_preferred_address (GumElfModule * self)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * phdr = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (phdr->type == GUM_ELF_PHDR_LOAD && phdr->offset == 0)
      return phdr->vaddr;
  }

  return 0;
}

static guint64
gum_elf_module_compute_mapped_size (GumElfModule * self)
{
  guint64 lowest, highest, page_size;
  guint i;

  lowest = ~G_GUINT64_CONSTANT (0);
  highest = 0;

  page_size = gum_query_page_size ();

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * phdr = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (phdr->type == GUM_ELF_PHDR_LOAD)
    {
      lowest = MIN (GUM_ELF_PAGE_START (phdr->vaddr, page_size), lowest);
      highest = MAX (phdr->vaddr + phdr->memsz, highest);
    }
  }

  return highest - lowest;
}

static GumElfDynamicAddressState
gum_elf_module_detect_dynamic_address_state (GumElfModule * self)
{
  guint i;

  if (self->source_mode == GUM_ELF_SOURCE_MODE_OFFLINE)
    return GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;

  for (i = 0; i != self->dyns->len; i++)
  {
    const GumElfDyn * dyn = &g_array_index (self->dyns, GumElfDyn, i);

    switch (dyn->tag)
    {
      case GUM_ELF_DYNAMIC_SYMTAB:
      case GUM_ELF_DYNAMIC_STRTAB:
        if (dyn->val > self->base_address)
          return GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED;
        break;
    }
  }

  return GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;
}

GumAddress
gum_elf_module_translate_to_offline (GumElfModule * self,
                                     GumAddress online_address)
{
  return self->preferred_address + (online_address - self->base_address);
}

GumAddress
gum_elf_module_translate_to_online (GumElfModule * self,
                                    GumAddress offline_address)
{
  return self->base_address + (offline_address - self->preferred_address);
}

static gpointer
gum_elf_module_resolve_dynamic_virtual_location (GumElfModule * self,
                                                 GumAddress address)
{
  if (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE)
  {
    switch (self->dynamic_address_state)
    {
      case GUM_ELF_DYNAMIC_ADDRESS_PRISTINE:
        return GSIZE_TO_POINTER (
            gum_elf_module_translate_to_online (self, address));
      case GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED:
        return GSIZE_TO_POINTER (address);
      default:
        g_assert_not_reached ();
    }

    return NULL;
  }
  else
  {
    guint64 offset;

    if (!gum_elf_module_find_address_file_offset (self, address, &offset))
      return NULL;

    return (guint8 *) self->file_data + offset;
  }
}

static gboolean
gum_store_dynamic_string_table (const GumElfDynamicEntryDetails * details,
                                gpointer user_data)
{
  GumElfModule * self = user_data;

  if (details->tag != GUM_ELF_DYNAMIC_STRTAB)
    return TRUE;

  self->dynamic_strings = gum_elf_module_resolve_dynamic_virtual_location (self,
      details->val);
  return FALSE;
}

static gboolean
gum_elf_module_check_bounds (GumElfModule * self,
                             gconstpointer left,
                             gconstpointer right,
                             gconstpointer base,
                             gsize size,
                             const gchar * name,
                             GError ** error)
{
  const guint8 * l = left;
  const guint8 * r = right;

  if (r < l)
    goto oob;

  if (l < (const guint8 *) base)
    goto oob;

  if (r > (const guint8 *) base + size)
    goto oob;

  return TRUE;

oob:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Missing data while reading %s", name);
    return FALSE;
  }
}

static gboolean
gum_elf_module_check_str_bounds (GumElfModule * self,
                                 const gchar * str,
                                 gconstpointer base,
                                 gsize size,
                                 const gchar * name,
                                 GError ** error)
{
  const gchar * end, * cursor;

  if (str < (const gchar *) base)
    goto consider_file_data;

  end = (const gchar *) base + size;
  if (str >= end)
    goto consider_file_data;

  cursor = str;
  do
  {
    if (cursor >= end)
      goto oob;
  }
  while (*cursor++ != '\0');

  return TRUE;

consider_file_data:
  {
    if (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE &&
        GUM_ADDRESS (base) == self->base_address)
    {
      return gum_elf_module_check_str_bounds (self, str, self->file_data,
          self->file_size, name, error);
    }

    goto oob;
  }
oob:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Missing data while reading %s", name);
    return FALSE;
  }
}

static guint8
gum_elf_module_read_uint8 (GumElfModule * self,
                           const guint8 * v)
{
  return *v;
}

static guint16
gum_elf_module_read_uint16 (GumElfModule * self,
                            const guint16 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GUINT16_FROM_LE (*v)
      : GUINT16_FROM_BE (*v);
}

static gint32
gum_elf_module_read_int32 (GumElfModule * self,
                           const gint32 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GINT32_FROM_LE (*v)
      : GINT32_FROM_BE (*v);
}

static guint32
gum_elf_module_read_uint32 (GumElfModule * self,
                            const guint32 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GUINT32_FROM_LE (*v)
      : GUINT32_FROM_BE (*v);
}

static gint64
gum_elf_module_read_int64 (GumElfModule * self,
                           const gint64 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GINT64_FROM_LE (*v)
      : GINT64_FROM_BE (*v);
}

static guint64
gum_elf_module_read_uint64 (GumElfModule * self,
                            const guint64 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GUINT64_FROM_LE (*v)
      : GUINT64_FROM_BE (*v);
}

static gboolean
gum_maybe_extract_from_apk (const gchar * path,
                            GBytes ** file_bytes)
{
#if defined (HAVE_ANDROID) && defined (HAVE_MINIZIP)
  gboolean success = FALSE;
  gchar ** tokens;
  const gchar * apk_path, * file_path, * bare_file_path;
  void * zip_stream = NULL;
  void * zip_reader = NULL;
  gsize size;
  gpointer buffer = NULL;

  tokens = g_strsplit (path, "!", 2);
  if (g_strv_length (tokens) != 2 || !g_str_has_suffix (tokens[0], ".apk"))
    goto beach;
  apk_path = tokens[0];
  file_path = tokens[1];
  bare_file_path = file_path + 1;

  mz_stream_os_create (&zip_stream);
  if (mz_stream_os_open (zip_stream, apk_path, MZ_OPEN_MODE_READ) != MZ_OK)
    goto beach;

  mz_zip_reader_create (&zip_reader);
  if (mz_zip_reader_open (zip_reader, zip_stream) != MZ_OK)
    goto beach;

  if (mz_zip_reader_locate_entry (zip_reader, bare_file_path, TRUE) != MZ_OK)
    goto beach;

  size = mz_zip_reader_entry_save_buffer_length (zip_reader);
  buffer = g_malloc (size);
  if (mz_zip_reader_entry_save_buffer (zip_reader, buffer, size) != MZ_OK)
    goto beach;

  success = TRUE;

  *file_bytes = g_bytes_new_take (g_steal_pointer (&buffer), size);

beach:
  g_free (buffer);
  mz_zip_reader_delete (&zip_reader);
  mz_stream_os_delete (&zip_stream);
  g_strfreev (tokens);

  return success;
#else
  return FALSE;
#endif
}

#endif

"""


```