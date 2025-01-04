Response:
The user wants to understand the functionality of the provided C code snippet from Frida, specifically the `gumdarwinmodule.c` file. I need to analyze the code and identify its purpose, relating it to reverse engineering, low-level concepts, and potential user errors. The request emphasizes providing concrete examples and explaining how a user might reach this code. Since this is the third part of a series, I also need to summarize the overall function of this specific file.

Here's a breakdown of how I'll approach this:

1. **Overall Function:** Determine the primary goal of `gumdarwinmodule.c`. It seems to be related to processing Mach-O binary files on Darwin-based systems (macOS, iOS).

2. **Feature Listing:**  Go through the functions and identify their individual roles. Key functions seem to involve:
    - Checking CPU and pointer authentication compatibility.
    - Parsing Mach-O headers and load commands.
    - Extracting information like module name, UUID, segments, dependencies, and export symbols.
    - Reading data from memory.
    - Handling export symbol trie structures.

3. **Reverse Engineering Relevance:** Identify how these functionalities are used in reverse engineering. Examples could include:
    - Inspecting module metadata to understand its purpose.
    - Finding exported functions to hook or analyze.
    - Understanding memory layout based on segments.
    - Identifying dependencies to understand the module's ecosystem.

4. **Binary/Kernel/Framework Concepts:** Point out the connections to low-level aspects:
    - Mach-O file format understanding.
    - CPU architectures (x86, ARM) and their variants.
    - Pointer authentication concepts.
    - Memory management (segments, virtual addresses).
    - Dynamic linking concepts (dylibs).

5. **Logical Reasoning (Input/Output):** For some functions, describe hypothetical inputs and their expected outputs. For example, `gum_exports_trie_find` could take an export name and return details about that export.

6. **User Errors:** Consider common mistakes developers or users might make when using Frida or interacting with these concepts. This could include:
    - Specifying the wrong CPU architecture for hooking.
    - Misinterpreting module information.

7. **User Journey (Debugging):**  Explain how a Frida user's actions might lead to the execution of this code. This often involves Frida's module enumeration and analysis features.

8. **Part 3 Summary:** Concisely summarize the functions within this specific code snippet, building upon the understanding from the previous parts (although the previous parts weren't provided, I can infer the broader context of Frida's module handling).

**Mental Sandbox Simulation:**

- Imagine Frida trying to hook a function in a specific Mach-O module on macOS.
- Frida would need to load and parse the module's header using functions like `gum_darwin_module_take_image`.
- It would use functions like `gum_exports_trie_find` to locate the target function's symbol.
- Compatibility checks using functions like `gum_darwin_module_can_handle` would be performed.

**Key Code Areas to Focus On:**

- `gum_darwin_module_can_handle`: CPU and ptrauth compatibility.
- `gum_darwin_module_take_image`: Mach-O parsing and information extraction.
- `gum_exports_trie_find`/`gum_exports_trie_foreach`: Export symbol handling.
- `gum_darwin_module_read_and_assign`: Memory reading.

By following these steps and focusing on the key aspects of the code, I can generate a comprehensive answer that addresses all parts of the user's request.
这是 `frida/subprojects/frida-gum/gum/gumdarwinmodule.c` 文件的第三部分代码，主要关注的是 Mach-O 文件（Darwin 系统如 macOS 和 iOS 的可执行文件格式）的进一步解析，特别是关于导出符号表 (exports trie) 的处理以及一些辅助功能。

**功能列举：**

1. **导出符号表 (Exports Trie) 的查找 (`gum_exports_trie_find`):**
   - 功能：在一个已经解析的 Mach-O 模块的导出符号表中查找特定的符号名称。
   - 输入：指向导出符号表起始和结束位置的指针，要查找的符号名称字符串，以及一个用于存储找到的符号详细信息的结构体指针。
   - 输出：如果找到符号则返回 `TRUE`，否则返回 `FALSE`。找到的符号信息会填充到提供的结构体中。

2. **导出符号表 (Exports Trie) 的遍历 (`gum_exports_trie_foreach`):**
   - 功能：遍历一个 Mach-O 模块的所有导出符号。
   - 输入：指向导出符号表起始和结束位置的指针，一个回调函数指针，以及用户自定义的数据指针。
   - 输出：遍历过程中如果回调函数始终返回 `TRUE`，则最终返回 `TRUE`，如果回调函数返回 `FALSE`，则遍历提前终止并返回 `FALSE`.
   - 作用：允许用户对模块的每个导出符号执行自定义操作。

3. **导出符号表 (Exports Trie) 的递归遍历 (`gum_exports_trie_traverse`):**
   - 功能：作为 `gum_exports_trie_foreach` 的辅助函数，负责实际的导出符号表的树形结构遍历。
   - 输入：当前遍历到的节点指针，以及一个包含遍历上下文信息的结构体指针。
   - 输出：同 `gum_exports_trie_foreach`。

4. **从导出符号表节点初始化符号详情 (`gum_darwin_export_details_init_from_node`):**
   - 功能：根据导出符号表中的一个节点信息，初始化一个 `GumDarwinExportDetails` 结构体，包含符号的名称、标志、偏移地址或其他相关信息（如重导出信息）。
   - 输入：符号详情结构体指针，符号名称字符串，当前节点指针，导出符号表结束指针。
   - 输出：无返回值，但会修改传入的符号详情结构体。

5. **从 Darwin CPU 类型获取 Gum CPU 类型 (`gum_cpu_type_from_darwin`):**
   - 功能：将 Darwin 系统定义的 CPU 类型（如 `GUM_DARWIN_CPU_X86`）转换为 Frida 内部使用的 `GumCpuType` 枚举值（如 `GUM_CPU_IA32`）。
   - 输入：Darwin 的 CPU 类型枚举值。
   - 输出：对应的 Frida CPU 类型枚举值。

6. **从 Darwin CPU 类型和子类型获取 Ptrauth 支持 (`gum_ptrauth_support_from_darwin`):**
   - 功能：确定给定 CPU 类型和子类型是否支持指针认证 (Pointer Authentication, ptrauth)，这是 ARM64e 架构引入的安全特性。
   - 输入：Darwin 的 CPU 类型和子类型枚举值。
   - 输出：一个 `GumPtrauthSupport` 枚举值，表示是否支持 ptrauth。

7. **从 CPU 类型获取指针大小 (`gum_pointer_size_from_cpu_type`):**
   - 功能：根据 CPU 类型确定指针的大小（例如，x86 和 ARM 是 4 字节，x86_64 和 ARM64 是 8 字节）。
   - 输入：Darwin 的 CPU 类型枚举值。
   - 输出：指针大小（以字节为单位）。

**与逆向方法的关联及举例说明：**

这些功能与逆向工程密切相关，特别是动态分析。

* **查找导出符号 (`gum_exports_trie_find`)**:  在逆向过程中，经常需要找到目标模块导出的特定函数或变量。例如，你想 hook 系统库 `libsystem_c.dylib` 中的 `open` 函数。你可以通过模块名和函数名调用 Frida 的 API，Frida 内部就会使用类似 `gum_exports_trie_find` 的机制来定位 `open` 函数在内存中的地址。

   ```c
   // 假设已经获取了模块的 GumDarwinModule 结构体指针 'module'
   GumDarwinExportDetails details;
   if (gum_exports_trie_find(module->exports, module->exports_end, "open", &details)) {
       // 找到了 "open" 符号，details 结构体包含了其信息
       g_print("Found export: %s at offset %lu\n", details.name, details.offset);
   } else {
       g_print("Export 'open' not found.\n");
   }
   ```

* **遍历导出符号 (`gum_exports_trie_foreach`)**: 当你需要分析一个模块的所有导出函数时，可以使用此功能。例如，你想找到某个库导出的所有以 "hook_" 开头的函数，以便进行自动化分析或 hook。

   ```c
   typedef struct {
       const gchar *prefix;
   } FindExportsContext;

   static gboolean find_hook_exports(GumDarwinExportDetails *details, gpointer user_data) {
       FindExportsContext *ctx = (FindExportsContext *)user_data;
       if (g_str_has_prefix(details->name, ctx->prefix)) {
           g_print("Found hook export: %s\n", details->name);
       }
       return TRUE; // 继续遍历
   }

   // 假设已经获取了模块的 GumDarwinModule 结构体指针 'module'
   FindExportsContext ctx = {"hook_"};
   gum_exports_trie_foreach(module->exports, module->exports_end, find_hook_exports, &ctx);
   ```

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

虽然这段代码专注于 Darwin 系统，但其概念与 Linux 和 Android 中的动态链接库 (shared libraries) 和符号表处理类似。

* **二进制底层 (Mach-O 格式):** 这段代码直接操作 Mach-O 文件的结构，如导出符号表的 trie 结构。理解 ULEB128 编码（用于存储符号表中的长度和偏移量）是必要的。
* **CPU 架构 (x86, ARM):**  代码需要区分不同的 CPU 架构，因为它们的指令集、寄存器和指针大小可能不同。`gum_cpu_type_from_darwin` 和 `gum_pointer_size_from_cpu_type` 就是处理这种差异的。
* **指针认证 (PtrAuth):** `gum_ptrauth_support_from_darwin` 涉及 ARM64e 引入的硬件安全特性，Frida 需要识别目标设备是否支持 ptrauth，以便进行正确的 hook 操作。

**逻辑推理，假设输入与输出：**

* **假设输入到 `gum_exports_trie_find`:**
    - `exports`: 指向一个有效的 Mach-O 模块的导出符号表起始位置的指针。
    - `exports_end`: 指向导出符号表结束位置的指针。
    - `name`: 字符串 "malloc"。
    - `details`: 一个未初始化的 `GumDarwinExportDetails` 结构体指针。
* **预期输出:**
    - 如果模块导出了 `malloc` 函数，则函数返回 `TRUE`，并且 `details` 结构体会被填充，例如 `details.name` 为 "malloc"，`details.offset` 为 `malloc` 函数的相对偏移地址。
    - 如果模块未导出 `malloc` 函数，则函数返回 `FALSE`，`details` 结构体内容不确定。

**涉及用户或编程常见的使用错误及举例说明：**

* **传递错误的符号名称给 `gum_exports_trie_find`:** 如果用户传递的符号名称在目标模块中不存在，`gum_exports_trie_find` 将返回 `FALSE`。这可能是因为用户拼写错误，或者误以为某个符号是导出的。
* **在未加载模块的情况下尝试访问导出符号表:** 如果在 `GumDarwinModule` 结构体尚未正确初始化或 `exports` 指针为空的情况下调用 `gum_exports_trie_find` 或 `gum_exports_trie_foreach`，会导致程序崩溃或产生未定义的行为。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

当 Frida 用户尝试在 Darwin 系统上 hook 函数时，Frida 内部会经历以下步骤，可能会到达这段代码：

1. **Frida 脚本执行:** 用户编写 JavaScript 代码，使用 Frida 的 API 来 attach 到一个进程或加载一个库，并尝试 hook 一个特定的函数，例如 `Interceptor.attach(Module.getExportByName("libsystem_c.dylib", "open"), ...)`。
2. **模块加载和解析:** Frida 的 Gum 引擎会加载目标模块（`libsystem_c.dylib`）。在加载过程中，会解析 Mach-O 文件头和 load commands，这涉及到之前部分的代码。
3. **查找导出符号:** 当调用 `Module.getExportByName` 时，Frida 内部会调用相应的 C 代码，最终会使用类似于 `gum_exports_trie_find` 的函数，传入模块的导出符号表指针和要查找的函数名 "open"。
4. **`gumdarwinmodule.c` 执行:**  `gum_exports_trie_find` 函数会在 `gumdarwinmodule.c` 文件中执行，遍历导出符号表，查找匹配的符号。
5. **Hook 设置:** 如果找到符号，Frida 会获取其地址，并在该地址设置 hook。

作为调试线索，如果用户在 hook 过程中遇到问题，例如 hook 不生效或找不到符号，可以检查以下几点：

* **模块名称是否正确？**
* **符号名称是否正确？** 注意大小写和命名规范。
* **目标模块是否真的导出了该符号？** 可以使用 `frida-ps -D <device_id> --show-module-exports <process_name>` 或类似工具查看模块的导出符号。
* **Frida 版本是否与目标系统兼容？**

**归纳一下它的功能 (第 3 部分):**

这部分代码主要负责 **解析和操作 Mach-O 文件的导出符号表 (exports trie)**。它提供了查找特定导出符号和遍历所有导出符号的功能，这对于 Frida 实现动态 instrumentation 至关重要，因为它允许 Frida 找到需要在运行时进行拦截和修改的函数地址。此外，它还包含了一些辅助函数，用于处理 CPU 类型和指针大小等架构相关的信息，确保 Frida 能够在不同的 Darwin 设备上正确运行。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gumdarwinmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
if (allow_any_cpu)
  {
    gboolean is_supported = canonical_cpu_type != GUM_CPU_INVALID;
    if (!is_supported)
      return FALSE;
  }
  else
  {
    gboolean matches_selected_cpu = canonical_cpu_type == self->cpu_type;
    if (!matches_selected_cpu)
      return FALSE;
  }

  allow_any_ptrauth = self->ptrauth_support == GUM_PTRAUTH_INVALID;
  if (!allow_any_ptrauth)
  {
    gboolean matches_selected_ptrauth =
        gum_ptrauth_support_from_darwin (cpu_type, cpu_subtype)
        == self->ptrauth_support;
    if (!matches_selected_ptrauth)
      return FALSE;
  }

  return TRUE;
}

static gboolean
gum_darwin_module_take_image (GumDarwinModule * self,
                              GumDarwinModuleImage * image,
                              GError ** error)
{
  gboolean success = FALSE;
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;
  const GumLinkeditDataCommand * exports_trie = NULL;

  g_assert (self->image == NULL);
  self->image = image;

  header = (GumMachHeader32 *) image->data;

  self->filetype = header->filetype;

  if (self->cpu_type == GUM_CPU_INVALID)
    self->cpu_type = gum_cpu_type_from_darwin (header->cputype);

  if (self->ptrauth_support == GUM_PTRAUTH_INVALID)
  {
    self->ptrauth_support =
        gum_ptrauth_support_from_darwin (header->cputype, header->cpusubtype);
  }

  self->pointer_size = gum_pointer_size_from_cpu_type (header->cputype);

  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) image->data + 1;
  else
    command = (GumMachHeader64 *) image->data + 1;
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = (GumLoadCommand *) command;

    switch (lc->cmd)
    {
      case GUM_LC_ID_DYLIB:
      {
        if (self->name == NULL)
        {
          const GumDylib * dl = &((GumDylibCommand *) lc)->dylib;
          const gchar * raw_path;
          guint raw_path_len;

          raw_path = (const gchar *) command + dl->name.offset;
          raw_path_len = lc->cmdsize - sizeof (GumDylibCommand);

          self->name = g_strndup (raw_path, raw_path_len);
        }

        break;
      }
      case GUM_LC_ID_DYLINKER:
      {
        if (self->name == NULL)
        {
          const GumDylinkerCommand * dl = (const GumDylinkerCommand *) lc;
          const gchar * raw_path;
          guint raw_path_len;

          raw_path = (const gchar *) command + dl->name.offset;
          raw_path_len = lc->cmdsize - sizeof (GumDylinkerCommand);

          self->name = g_strndup (raw_path, raw_path_len);
        }

        break;
      }
      case GUM_LC_UUID:
      {
        if (self->uuid == NULL)
        {
          const GumUUIDCommand * uc = command;
          const uint8_t * u = uc->uuid;

          self->uuid = g_strdup_printf ("%02X%02X%02X%02X-%02X%02X-%02X%02X-"
              "%02X%02X-%02X%02X%02X%02X%02X%02X", u[0], u[1], u[2], u[3],
              u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
              u[14], u[15]);
        }

        break;
      }
      case GUM_LC_SEGMENT_32:
      case GUM_LC_SEGMENT_64:
      {
        GumDarwinSegment segment;

        if (lc->cmd == GUM_LC_SEGMENT_32)
        {
          const GumSegmentCommand32 * sc = command;

          g_strlcpy (segment.name, sc->segname, sizeof (segment.name));
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }
        else
        {
          const GumSegmentCommand64 * sc = command;

          g_strlcpy (segment.name, sc->segname, sizeof (segment.name));
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }

        g_array_append_val (self->segments, segment);

        if (strcmp (segment.name, "__TEXT") == 0)
        {
          self->preferred_address = segment.vm_address;
        }

        break;
      }
      case GUM_LC_LOAD_DYLIB:
      case GUM_LC_LOAD_WEAK_DYLIB:
      case GUM_LC_REEXPORT_DYLIB:
      case GUM_LC_LOAD_UPWARD_DYLIB:
      {
        const GumDylibCommand * dc = command;
        GumDependencyDetails dep;

        dep.name = (const gchar *) command + dc->dylib.name.offset;
        switch (lc->cmd)
        {
          case GUM_LC_LOAD_DYLIB:
            dep.type = GUM_DEPENDENCY_REGULAR;
            break;
          case GUM_LC_LOAD_WEAK_DYLIB:
            dep.type = GUM_DEPENDENCY_WEAK;
            break;
          case GUM_LC_REEXPORT_DYLIB:
            dep.type = GUM_DEPENDENCY_REEXPORT;
            break;
          case GUM_LC_LOAD_UPWARD_DYLIB:
            dep.type = GUM_DEPENDENCY_UPWARD;
            break;
          default:
            g_assert_not_reached ();
        }
        g_array_append_val (self->dependencies, dep);

        if (lc->cmd == GUM_LC_REEXPORT_DYLIB)
          g_ptr_array_add (self->reexports, (gpointer) dep.name);

        break;
      }
      case GUM_LC_DYLD_INFO_ONLY:
        self->info = command;
        break;
      case GUM_LC_DYLD_EXPORTS_TRIE:
        exports_trie = command;
        break;
      case GUM_LC_SYMTAB:
        self->symtab = command;
        break;
      case GUM_LC_DYSYMTAB:
        self->dysymtab = command;
        break;
      default:
        break;
    }

    command = (const guint8 *) command + lc->cmdsize;
  }

  gum_darwin_module_enumerate_sections (self,
      gum_add_text_range_if_text_section, self->text_ranges);

  if (self->info == NULL)
  {
    if (exports_trie != NULL)
    {
      if (image->linkedit != NULL)
      {
        self->exports =
            (const guint8 *) image->linkedit + exports_trie->dataoff;
        self->exports_end = self->exports + exports_trie->datasize;
        self->exports_malloc_data = NULL;
      }
      else
      {
        GumAddress linkedit;

        if (!gum_find_linkedit (image->data, image->size, &linkedit))
          goto beach;
        linkedit += gum_darwin_module_get_slide (self);

        gum_darwin_module_read_and_assign (self,
            linkedit + exports_trie->dataoff,
            exports_trie->datasize,
            &self->exports,
            &self->exports_end,
            &self->exports_malloc_data);
      }
    }
  }
  else if (image->linkedit != NULL)
  {
    self->rebases = (const guint8 *) image->linkedit + self->info->rebase_off;
    self->rebases_end = self->rebases + self->info->rebase_size;
    self->rebases_malloc_data = NULL;

    self->binds = (const guint8 *) image->linkedit + self->info->bind_off;
    self->binds_end = self->binds + self->info->bind_size;
    self->binds_malloc_data = NULL;

    self->lazy_binds =
        (const guint8 *) image->linkedit + self->info->lazy_bind_off;
    self->lazy_binds_end = self->lazy_binds + self->info->lazy_bind_size;
    self->lazy_binds_malloc_data = NULL;

    self->exports = (const guint8 *) image->linkedit + self->info->export_off;
    self->exports_end = self->exports + self->info->export_size;
    self->exports_malloc_data = NULL;
  }
  else
  {
    GumAddress linkedit;

    if (!gum_find_linkedit (image->data, image->size, &linkedit))
      goto beach;
    linkedit += gum_darwin_module_get_slide (self);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->rebase_off,
        self->info->rebase_size,
        &self->rebases,
        &self->rebases_end,
        &self->rebases_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->bind_off,
        self->info->bind_size,
        &self->binds,
        &self->binds_end,
        &self->binds_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->lazy_bind_off,
        self->info->lazy_bind_size,
        &self->lazy_binds,
        &self->lazy_binds_end,
        &self->lazy_binds_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->export_off,
        self->info->export_size,
        &self->exports,
        &self->exports_end,
        &self->exports_malloc_data);
  }

  success = self->segments->len != 0;

beach:
  if (!success)
  {
    self->image = NULL;
    gum_darwin_module_image_free (image);

    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
  }

  return success;
}

static void
gum_darwin_module_read_and_assign (GumDarwinModule * self,
                                   GumAddress address,
                                   gsize size,
                                   const guint8 ** start,
                                   const guint8 ** end,
                                   gpointer * malloc_data)
{
  guint8 * data;

  if (size == 0)
    goto empty_read;

  if (self->is_local)
  {
    *start = GSIZE_TO_POINTER (address);
    if (end != NULL)
      *end = GSIZE_TO_POINTER (address + size);

    *malloc_data = NULL;
  }
  else
  {
    gsize n_bytes_read;

    n_bytes_read = 0;
    data = gum_darwin_module_read_from_task (self, address, size,
        &n_bytes_read);

    *start = data;
    if (end != NULL)
      *end = (data != NULL) ? data + n_bytes_read : NULL;
    else if (n_bytes_read != size)
      goto short_read;

    *malloc_data = data;
  }

  return;

empty_read:
  {
    *start = NULL;
    if (end != NULL)
      *end = NULL;

    *malloc_data = NULL;

    return;
  }
short_read:
  {
    g_free (data);
    *start = NULL;

    *malloc_data = NULL;

    return;
  }
}

static gboolean
gum_find_linkedit (const guint8 * module,
                   gsize module_size,
                   GumAddress * linkedit)
{
  GumMachHeader32 * header;
  const guint8 * p;
  guint cmd_index;

  header = (GumMachHeader32 *) module;
  if (header->magic == GUM_MH_MAGIC_32)
    p = module + sizeof (GumMachHeader32);
  else
    p = module + sizeof (GumMachHeader64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    GumLoadCommand * lc = (GumLoadCommand *) p;

    if (lc->cmd == GUM_LC_SEGMENT_32 || lc->cmd == GUM_LC_SEGMENT_64)
    {
      GumSegmentCommand32 * sc32 = (GumSegmentCommand32 *) lc;
      GumSegmentCommand64 * sc64 = (GumSegmentCommand64 *) lc;
      if (strncmp (sc32->segname, "__LINKEDIT", 10) == 0)
      {
        if (header->magic == GUM_MH_MAGIC_32)
          *linkedit = sc32->vmaddr - sc32->fileoff;
        else
          *linkedit = sc64->vmaddr - sc64->fileoff;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
gum_add_text_range_if_text_section (const GumDarwinSectionDetails * details,
                                    gpointer user_data)
{
  GArray * ranges = user_data;

  if (gum_section_flags_indicate_text_section (details->flags))
  {
    GumMemoryRange r;
    r.base_address = details->vm_address;
    r.size = details->size;
    g_array_append_val (ranges, r);
  }

  return TRUE;
}

static gboolean
gum_section_flags_indicate_text_section (guint32 flags)
{
  return (flags & (GUM_S_ATTR_PURE_INSTRUCTIONS | GUM_S_ATTR_SOME_INSTRUCTIONS))
      != 0;
}

GumDarwinModuleImage *
gum_darwin_module_image_new (void)
{
  GumDarwinModuleImage * image;

  image = g_slice_new0 (GumDarwinModuleImage);
  image->shared_segments = g_array_new (FALSE, FALSE,
      sizeof (GumDarwinModuleImageSegment));

  return image;
}

GumDarwinModuleImage *
gum_darwin_module_image_dup (const GumDarwinModuleImage * other)
{
  GumDarwinModuleImage * image;

  image = g_slice_new0 (GumDarwinModuleImage);

  image->size = other->size;

  image->source_offset = other->source_offset;
  image->source_size = other->source_size;
  image->shared_offset = other->shared_offset;
  image->shared_size = other->shared_size;
  image->shared_segments = g_array_ref (other->shared_segments);

  if (other->bytes != NULL)
    image->bytes = g_bytes_ref (other->bytes);

  if (other->shared_segments->len > 0)
  {
    guint i;

    image->malloc_data = g_malloc (other->size);
    image->data = image->malloc_data;

    g_assert (other->source_size != 0);
    memcpy (image->data, other->data, other->source_size);

    for (i = 0; i != other->shared_segments->len; i++)
    {
      GumDarwinModuleImageSegment * s = &g_array_index (other->shared_segments,
          GumDarwinModuleImageSegment, i);
      memcpy ((guint8 *) image->data + s->offset,
          (const guint8 *) other->data + s->offset, s->size);
    }
  }
  else
  {
    image->malloc_data = g_memdup2 (other->data, other->size);
    image->data = image->malloc_data;
  }

  if (other->bytes != NULL)
  {
    gconstpointer data;
    gsize size;

    data = g_bytes_get_data (other->bytes, &size);
    if (other->linkedit >= data &&
        other->linkedit < (gconstpointer) ((const guint8 *) data + size))
    {
      image->linkedit = other->linkedit;
    }
  }

  if (image->linkedit == NULL && other->linkedit != NULL)
  {
    g_assert (other->linkedit >= other->data && other->linkedit <
        (gconstpointer) ((guint8 *) other->data + other->size));
    image->linkedit = (guint8 *) image->data +
        ((guint8 *) other->linkedit - (guint8 *) other->data);
  }

  return image;
}

void
gum_darwin_module_image_free (GumDarwinModuleImage * image)
{
  g_free (image->malloc_data);
  g_bytes_unref (image->bytes);

  g_array_unref (image->shared_segments);

  g_slice_free (GumDarwinModuleImage, image);
}

static gboolean
gum_exports_trie_find (const guint8 * exports,
                       const guint8 * exports_end,
                       const gchar * name,
                       GumDarwinExportDetails * details)
{
  const gchar * s;
  const guint8 * p;

  if (exports == exports_end)
    return FALSE;

  s = name;
  p = exports;
  while (p != NULL)
  {
    gint64 terminal_size;
    const guint8 * children;
    guint8 child_count, i;
    guint64 node_offset;

    terminal_size = gum_read_uleb128 (&p, exports_end);

    if (*s == '\0' && terminal_size != 0)
    {
      gum_darwin_export_details_init_from_node (details, name, p, exports_end);
      return TRUE;
    }

    children = p + terminal_size;
    child_count = *children++;
    p = children;
    node_offset = 0;
    for (i = 0; i != child_count; i++)
    {
      const gchar * symbol_cur;
      gboolean matching_edge;

      symbol_cur = s;
      matching_edge = TRUE;
      while (*p != '\0')
      {
        if (matching_edge)
        {
          if (*p != *symbol_cur)
            matching_edge = FALSE;
          symbol_cur++;
        }
        p++;
      }
      p++;

      if (matching_edge)
      {
        node_offset = gum_read_uleb128 (&p, exports_end);
        s = symbol_cur;
        break;
      }
      else
      {
        gum_skip_leb128 (&p, exports_end);
      }
    }

    if (node_offset != 0)
      p = exports + node_offset;
    else
      p = NULL;
  }

  return FALSE;
}

static gboolean
gum_exports_trie_foreach (const guint8 * exports,
                          const guint8 * exports_end,
                          GumFoundDarwinExportFunc func,
                          gpointer user_data)
{
  GumExportsTrieForeachContext ctx;
  gboolean carry_on;

  if (exports == exports_end)
    return TRUE;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.prefix = g_string_sized_new (1024);
  ctx.exports = exports;
  ctx.exports_end = exports_end;

  carry_on = gum_exports_trie_traverse (exports, &ctx);

  g_string_free (ctx.prefix, TRUE);

  return carry_on;
}

static gboolean
gum_exports_trie_traverse (const guint8 * p,
                           GumExportsTrieForeachContext * ctx)
{
  GString * prefix = ctx->prefix;
  const guint8 * exports = ctx->exports;
  const guint8 * exports_end = ctx->exports_end;
  gboolean carry_on;
  guint64 terminal_size;
  guint8 child_count, i;

  terminal_size = gum_read_uleb128 (&p, exports_end);
  if (terminal_size != 0)
  {
    GumDarwinExportDetails details;

    gum_darwin_export_details_init_from_node (&details, prefix->str, p,
        exports_end);

    carry_on = ctx->func (&details, ctx->user_data);
    if (!carry_on)
      return FALSE;
  }

  p += terminal_size;
  child_count = *p++;
  for (i = 0; i != child_count; i++)
  {
    gsize length = 0;

    while (*p != '\0')
    {
      g_string_append_c (prefix, *p++);
      length++;
    }
    p++;

    carry_on = gum_exports_trie_traverse (
        exports + gum_read_uleb128 (&p, exports_end),
        ctx);
    if (!carry_on)
      return FALSE;

    g_string_truncate (prefix, prefix->len - length);
  }

  return TRUE;
}

static void
gum_darwin_export_details_init_from_node (GumDarwinExportDetails * details,
                                          const gchar * name,
                                          const guint8 * node,
                                          const guint8 * exports_end)
{
  const guint8 * p = node;

  details->name = name;
  details->flags = gum_read_uleb128 (&p, exports_end);
  if ((details->flags & GUM_EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    details->reexport_library_ordinal = gum_read_uleb128 (&p, exports_end);
    details->reexport_symbol = (*p != '\0') ? (gchar *) p : name;
  }
  else if ((details->flags & GUM_EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
  {
    details->stub = gum_read_uleb128 (&p, exports_end);
    details->resolver = gum_read_uleb128 (&p, exports_end);
  }
  else
  {
    details->offset = gum_read_uleb128 (&p, exports_end);
  }
}

static GumCpuType
gum_cpu_type_from_darwin (GumDarwinCpuType cpu_type)
{
  switch (cpu_type)
  {
    case GUM_DARWIN_CPU_X86:
      return GUM_CPU_IA32;
    case GUM_DARWIN_CPU_X86_64:
      return GUM_CPU_AMD64;
    case GUM_DARWIN_CPU_ARM:
      return GUM_CPU_ARM;
    case GUM_DARWIN_CPU_ARM64:
      return GUM_CPU_ARM64;
    default:
      return GUM_CPU_INVALID;
  }
}

static GumPtrauthSupport
gum_ptrauth_support_from_darwin (GumDarwinCpuType cpu_type,
                                 GumDarwinCpuSubtype cpu_subtype)
{
  if (cpu_type == GUM_DARWIN_CPU_ARM64)
  {
    return ((cpu_subtype & GUM_DARWIN_CPU_SUBTYPE_MASK) ==
            GUM_DARWIN_CPU_SUBTYPE_ARM64E)
        ? GUM_PTRAUTH_SUPPORTED
        : GUM_PTRAUTH_UNSUPPORTED;
  }

  return GUM_PTRAUTH_UNSUPPORTED;
}

static guint
gum_pointer_size_from_cpu_type (GumDarwinCpuType cpu_type)
{
  switch (cpu_type)
  {
    case GUM_DARWIN_CPU_X86:
    case GUM_DARWIN_CPU_ARM:
      return 4;
    case GUM_DARWIN_CPU_X86_64:
    case GUM_DARWIN_CPU_ARM64:
      return 8;
    default:
      return 0;
  }
}

#endif

"""


```