Response:
The user wants a summary of the functionality of the provided C code snippet from `gumdarwinmodule.c`. This file is part of Frida, a dynamic instrumentation toolkit, and specifically deals with Darwin (macOS, iOS) modules.

I need to analyze the code and identify the main functionalities it implements. These seem to revolve around parsing and iterating through different sections and structures within a Mach-O binary (the executable format on Darwin).

Here's a breakdown of the code's apparent functions:

1. **Enumerating Rebase Operations:** The `gum_darwin_module_enumerate_rebases` function iterates through the rebase information of a loaded module. This is used to adjust addresses when a module is loaded at a different address than its preferred base.

2. **Enumerating Bind Operations:** The `gum_darwin_module_enumerate_binds` function iterates through the standard binding information. Binding is the process of linking against external symbols (functions, variables) provided by other libraries.

3. **Enumerating Lazy Bind Operations:** The `gum_darwin_module_enumerate_lazy_binds` function focuses on bindings that are resolved only when they are first used.

4. **Enumerating Chained Binds:** The `gum_darwin_module_enumerate_chained_binds` and `gum_emit_chained_imports` functions deal with a newer binding mechanism introduced by Apple, aimed at improving security and performance.

5. **Querying TLV (Thread Local Variables) Parameters:** The `gum_darwin_module_query_tlv_parameters` and `gum_collect_tlv_params` functions extract information about thread-local storage.

6. **Enumerating TLV Descriptors:** The `gum_darwin_module_enumerate_tlv_descriptors` function iterates through the descriptors for thread-local variables.

7. **Enumerating Initialization and Termination Pointers/Offsets:** The functions like `gum_darwin_module_enumerate_init_pointers`, `gum_darwin_module_enumerate_init_offsets`, and `gum_darwin_module_enumerate_term_pointers`, along with their helper functions, iterate through functions that need to be called during module initialization and termination.

8. **Enumerating Dependencies:** The `gum_darwin_module_enumerate_dependencies` function lists the dynamic libraries that the current module depends on.

9. **Enumerating Function Starts:** The `gum_darwin_module_enumerate_function_starts` function provides information about the starting addresses of functions within the module.

10. **Getting Dependency by Ordinal:** The `gum_darwin_module_get_dependency_by_ordinal` function retrieves the name of a dependency based on its ordinal number.

11. **Ensuring Image is Loaded:** The `gum_darwin_module_ensure_image_loaded` function makes sure the Mach-O image of the module is loaded into memory before processing.

12. **Parsing Threaded Items:** The `gum_darwin_threaded_item_parse` function decodes the data structure used in chained fixups.

13. **Loading Image from Filesystem/Memory:** The functions like `gum_darwin_module_load_image_from_filesystem`, `gum_darwin_module_load_image_header_from_filesystem`, and `gum_darwin_module_load_image_from_memory` handle the process of loading the Mach-O image either from a file or from memory.

14. **Checking CPU Compatibility:** The `gum_darwin_module_can_load` function determines if the module's architecture is compatible with the current process.

Now, I need to synthesize this information into a concise summary.
This code snippet from `gumdarwinmodule.c` is responsible for **analyzing and enumerating various aspects of a loaded Darwin (macOS, iOS) Mach-O module**. It provides functionalities to inspect the module's internal structure and dependencies.

Here's a breakdown of its key functionalities:

**1. Enumerating Relocation Information (Rebases):**

* **Function:** `gum_darwin_module_enumerate_rebases`
* **Functionality:** This function iterates through the rebase information of a Mach-O module. Rebasing is the process of adjusting addresses within the module when it's loaded at a different base address than originally intended. This is a core concept in dynamic linking.
* **Relation to Reverse Engineering:**  Understanding rebases is crucial for reverse engineering as it helps map the loaded module's memory layout to its original structure. By enumerating rebases, Frida can identify where address adjustments have been made, allowing hooks and modifications to be placed correctly.
* **Binary/Low-Level:** This directly interacts with the Mach-O header's `__LINKEDIT` segment and the rebase information stored within it. It parses opcodes like `GUM_REBASE_OPCODE_DO_REBASE_IMM_TIMES`, `GUM_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB`, etc., which are specific to the Mach-O rebase format.
* **Example:** Imagine a function originally located at address `0x1000`. If the module is loaded at `0x4000`, a rebase entry would instruct the loader to add `0x3000` to this address. This function would then reside at `0x4000 + 0x3000 = 0x7000` in memory. This function helps Frida identify this transformation.

**2. Enumerating Binding Information (Binds):**

* **Function:** `gum_darwin_module_enumerate_binds`
* **Functionality:** This function iterates through the standard binding information. Binding resolves symbolic references (like function calls to external libraries) by associating them with actual memory addresses.
* **Relation to Reverse Engineering:** Binding information is fundamental for understanding a module's dependencies and how it interacts with other libraries. It reveals which external functions and variables the module uses.
* **Binary/Low-Level:**  It parses the bind information from the `__LINKEDIT` segment, interpreting opcodes like `GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM`, `GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM`, `GUM_BIND_OPCODE_DO_BIND`, etc., which are specific to the Mach-O bind format. These opcodes describe the binding process, including the library ordinal, symbol name, and the location to be patched.
* **Example:** A module might call a function `printf` from the `libc` library. The bind information would contain an entry indicating that a specific memory location within the module needs to be patched with the actual address of `printf` in `libc` when the module is loaded.

**3. Enumerating Lazy Binding Information:**

* **Function:** `gum_darwin_module_enumerate_lazy_binds`
* **Functionality:** This function focuses on "lazy" bindings. Lazy binding delays the resolution of symbols until they are first used, potentially improving startup performance.
* **Relation to Reverse Engineering:**  Understanding lazy binding can be important when analyzing a module's initialization process and identifying which dependencies are resolved immediately and which are delayed.
* **Binary/Low-Level:** Similar to standard binds, it parses the bind information, but specifically targets the lazy binding table in the `__LINKEDIT` segment.

**4. Enumerating Chained Fixups (Modern Binding):**

* **Functions:** `gum_darwin_module_enumerate_chained_binds`, `gum_emit_chained_imports`
* **Functionality:** These functions handle a newer, more efficient, and secure binding mechanism introduced by Apple. Chained fixups involve a more compact representation of binding information.
* **Relation to Reverse Engineering:** Reverse engineering modern macOS/iOS binaries increasingly requires understanding chained fixups. Frida needs to be able to parse this format to hook functions resolved through this mechanism.
* **Binary/Low-Level:** This involves parsing the `__LINKEDIT` segment for chained fixup information, including headers like `GumChainedFixupsHeader` and structures like `GumChainedImport`. It involves bitwise operations to extract information from the packed data.
* **Logic/Assumption:** The code assumes the existence of a `GumEmitImportContext` structure containing a resolver function (`ctx->resolver`). It iterates through fixup pages, identifies potential import slots based on chained pointer values, and resolves the actual import address using the resolver. The output depends on the behavior of the provided resolver function.
* **User/Programming Error:** If the provided `ctx->resolver` function is incorrect or does not properly resolve symbol names to addresses, the chained fixup enumeration will not correctly identify the bound functions.

**5. Querying Thread Local Variable (TLV) Parameters and Descriptors:**

* **Functions:** `gum_darwin_module_query_tlv_parameters`, `gum_collect_tlv_params`, `gum_darwin_module_enumerate_tlv_descriptors`
* **Functionality:** These functions extract information about thread-local storage (TLS). TLS provides each thread with its own private copy of certain variables.
* **Relation to Reverse Engineering:** Understanding TLS is crucial for analyzing multi-threaded applications and how data is managed within each thread's context.
* **Binary/Low-Level:**  This involves examining the Mach-O header flags (`GUM_MH_HAS_TLV_DESCRIPTORS`) and specific sections like `__thread_vars`, `__thread_data`, and `__thread_bss` to determine the layout and size of thread-local storage. It parses structures like `GumTlvThunk32` and `GumTlvThunk64`.

**6. Enumerating Initialization and Termination Functions:**

* **Functions:** `gum_darwin_module_enumerate_init_pointers`, `gum_darwin_module_enumerate_init_offsets`, `gum_darwin_module_enumerate_term_pointers`, `gum_emit_section_init_pointers`, `gum_emit_section_init_offsets`, `gum_emit_section_term_pointers`
* **Functionality:** These functions identify and enumerate functions that are executed when the module is loaded (initialization) and unloaded (termination).
* **Relation to Reverse Engineering:**  Understanding initialization and termination routines is essential for analyzing a module's setup and cleanup processes. Hooking these functions can be useful for intercepting module loading/unloading.
* **Binary/Low-Level:** It looks for specific sections like `__mod_init_func`, `__init_offsets`, and `__mod_term_func` in the Mach-O segments.

**7. Enumerating Dependencies:**

* **Function:** `gum_darwin_module_enumerate_dependencies`
* **Functionality:** This function lists the dynamic libraries that the current module depends on.
* **Relation to Reverse Engineering:**  Knowing the dependencies is fundamental for understanding a module's functionality and the external code it relies on.
* **Binary/Low-Level:** It parses the load commands in the Mach-O header, specifically looking for `LC_LOAD_DYLIB` commands, which specify the paths to dependent libraries.

**8. Enumerating Function Starts:**

* **Function:** `gum_darwin_module_enumerate_function_starts`
* **Functionality:** This function provides information about the starting addresses of functions within the module. This information is often stored in the `__DATA,__la_symbol_ptr` or similar sections.
* **Relation to Reverse Engineering:** This is crucial for identifying function boundaries and setting breakpoints or hooks at the beginning of functions.
* **Binary/Low-Level:** It searches for the `LC_FUNCTION_STARTS` load command in the Mach-O header and extracts the function start addresses from the associated data.

**9. Getting Dependency by Ordinal:**

* **Function:** `gum_darwin_module_get_dependency_by_ordinal`
* **Functionality:** Given an ordinal number, this function returns the name of the corresponding dependency. Ordinals are used in the binding process to refer to dependencies.

**10. Ensuring Image is Loaded:**

* **Function:** `gum_darwin_module_ensure_image_loaded`
* **Functionality:** This utility function ensures that the Mach-O image of the module is loaded into memory before any analysis is performed.

**11. Parsing Threaded Items:**

* **Function:** `gum_darwin_threaded_item_parse`
* **Functionality:** This function parses the data structures used in chained fixups for rebasing and binding. It decodes the packed information within a `guint64` value.
* **Binary/Low-Level:** It performs bitwise operations and shifts to extract different fields from the `guint64` representing a threaded item, distinguishing between bind and rebase types and their associated data.

**12. Loading Module Image:**

* **Functions:** `gum_darwin_module_load_image_from_filesystem`, `gum_darwin_module_load_image_header_from_filesystem`, `gum_darwin_module_load_image_from_memory`, `gum_darwin_module_get_header_offset_size`, `gum_darwin_module_load_image_from_blob`
* **Functionality:** These functions handle the process of loading the Mach-O image into memory, either from a file path or from an existing memory region. They also handle parsing fat binaries (which contain code for multiple architectures).
* **Operating System/Kernel:** These functions interact with the operating system to read file contents or access memory regions. They utilize functions like `g_mapped_file_new` and potentially lower-level memory management APIs.

**13. Checking CPU Compatibility:**

* **Function:** `gum_darwin_module_can_load`
* **Functionality:** This function checks if the module's target architecture (CPU type and subtype) is compatible with the current process's architecture.

**User Operation to Reach This Code (Debugging Context):**

A user would typically not interact with this C code directly. Instead, they would use the Frida API (often in Python or JavaScript) to perform actions like:

1. **Attaching to a process:** `frida.attach("process_name")`
2. **Getting a module:** `session.get_module_by_name("module_name")`
3. **Enumerating exports, imports, or other module details:**  Frida's API provides methods like `module.enumerate_exports()`, `module.enumerate_imports()`, etc.

When these high-level API calls are made, Frida internally uses the logic in files like `gumdarwinmodule.c` to parse the module's structure and retrieve the requested information.

**Example of User Error:**

A common user error related to these functionalities is attempting to enumerate module information *before* the module is fully loaded. Frida usually handles this, but if a user is interacting with Frida at a very low level or during the early stages of process startup, they might encounter errors if they try to access module data that hasn't been fully initialized yet.

**Summary of Functionality (Part 2):**

This part of `gumdarwinmodule.c` focuses on **enumerating binding information**, both standard and lazy, and the more modern **chained fixups**. It also handles **querying and enumerating thread-local variable (TLV) information**. These functionalities are crucial for Frida to understand how a Darwin module links against external code and manages thread-specific data, enabling powerful dynamic instrumentation capabilities.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gumdarwinmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
       {
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size;
        }

        break;
      }
      case GUM_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + gum_read_uleb128 (&p, end);
        break;
      case GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
      {
        gsize count, skip, i;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size + skip;
        }

        break;
      }
      default:
        return;
    }
  }
}

void
gum_darwin_module_enumerate_binds (GumDarwinModule * self,
                                   GumFoundDarwinBindFunc func,
                                   gpointer user_data)
{
  const guint8 * start, * end, * p;
  gboolean done;
  GumDarwinBindDetails details;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->binds;
  end = self->binds_end;
  p = start;
  done = FALSE;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = 0;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;
  details.threaded_table_size = 0;

  while (!done && p != end)
  {
    guint8 opcode = *p & GUM_BIND_OPCODE_MASK;
    guint8 immediate = *p & GUM_BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_BIND_OPCODE_DONE:
        done = TRUE;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = GUM_BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case GUM_BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = gum_read_sleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        if (details.segment == NULL)
          return;
        details.offset = gum_read_uleb128 (&p, end);
        break;
      }
      case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size;
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + (immediate * self->pointer_size);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        guint64 count, skip, i;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size + skip;
        }

        break;
      }
      case GUM_BIND_OPCODE_THREADED:
      {
        switch (immediate)
        {
          case GUM_BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
          {
            guint64 size;

            size = gum_read_uleb128 (&p, end);
            if (size > G_MAXUINT16)
              return;

            details.type = GUM_DARWIN_BIND_THREADED_TABLE;
            details.threaded_table_size = size;

            if (!func (&details, user_data))
              return;

            break;
          }
          case GUM_BIND_SUBOPCODE_THREADED_APPLY:
          {
            details.type = GUM_DARWIN_BIND_THREADED_ITEMS;

            if (!func (&details, user_data))
              return;

            break;
          }
          default:
            return;
        }

        break;
      }
      default:
        return;
    }
  }
}

void
gum_darwin_module_enumerate_lazy_binds (GumDarwinModule * self,
                                        GumFoundDarwinBindFunc func,
                                        gpointer user_data)
{
  const guint8 * start, * end, * p;
  GumDarwinBindDetails details;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->lazy_binds;
  end = self->lazy_binds_end;
  p = start;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = GUM_DARWIN_BIND_POINTER;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  while (p != end)
  {
    guint8 opcode = *p & GUM_BIND_OPCODE_MASK;
    guint8 immediate = *p & GUM_BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_BIND_OPCODE_DONE:
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = GUM_BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case GUM_BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = gum_read_sleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        if (details.segment == NULL)
          return;
        details.offset = gum_read_uleb128 (&p, end);
        break;
      }
      case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size;
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
      case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      default:
        return;
    }
  }
}

static void
gum_darwin_module_enumerate_chained_binds (GumDarwinModule * self,
                                           GumFoundDarwinBindFunc func,
                                           gpointer user_data)
{
  GumEmitImportContext * ctx = user_data;

  g_assert (ctx->resolver != NULL);

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self))
    return;

  gum_darwin_module_enumerate_chained_fixups (self,
      (GumFoundDarwinChainedFixupsFunc) gum_emit_chained_imports,
      ctx);
}

static gboolean
gum_emit_chained_imports (const GumDarwinChainedFixupsDetails * details,
                          GumEmitImportContext * ctx)
{
  GumDarwinModule * self = ctx->module;
  const guint8 * fixups_start, * fixups_end;
  gpointer malloc_data;
  const GumChainedFixupsHeader * fixups_header;
  const gchar * symbols;
  GHashTable * targets;
  guint imp_index;
  const GumChainedStartsInImage * image_starts;
  gsize slide;
  guint seg_index;

  gum_darwin_module_read_and_assign (self, details->vm_address, details->size,
      &fixups_start, &fixups_end, &malloc_data);
  if (fixups_start == NULL)
    return ctx->carry_on;

  fixups_header = (const GumChainedFixupsHeader *) fixups_start;

  symbols = (const gchar *) fixups_start + fixups_header->symbols_offset;
  targets = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);

  for (imp_index = 0; imp_index != fixups_header->imports_count; imp_index++)
  {
    guint name_offset;
    gint8 lib_ordinal;
    GumImportDetails * d;
    gpointer key;

    switch (fixups_header->imports_format)
    {
      case GUM_CHAINED_IMPORT:
      {
        const GumChainedImport * imports = (const GumChainedImport *)
            (fixups_start + fixups_header->imports_offset);
        const GumChainedImport * import = &imports[imp_index];

        name_offset = import->name_offset;
        lib_ordinal = import->lib_ordinal;

        break;
      }
      case GUM_CHAINED_IMPORT_ADDEND:
      {
        const GumChainedImportAddend * imports =
            (const GumChainedImportAddend *) (fixups_start +
                fixups_header->imports_offset);
        const GumChainedImportAddend * import = &imports[imp_index];

        name_offset = import->name_offset;
        lib_ordinal = import->lib_ordinal;

        break;
      }
      case GUM_CHAINED_IMPORT_ADDEND64:
      {
        const GumChainedImportAddend64 * imports =
            (const GumChainedImportAddend64 *) (fixups_start +
                fixups_header->imports_offset);
        const GumChainedImportAddend64 * import = &imports[imp_index];

        name_offset = import->name_offset;
        lib_ordinal = import->lib_ordinal;

        break;
      }
      default:
        goto skip;
    }

    d = g_new (GumImportDetails, 1);
    d->type = GUM_IMPORT_UNKNOWN;
    d->name = symbols + name_offset;
    d->module = gum_darwin_module_get_dependency_by_ordinal (self, lib_ordinal);
    d->address = ctx->resolver (d->module, d->name, ctx->user_data);
    d->slot = 0;

    key = GSIZE_TO_POINTER (gum_strip_code_address (d->address));

    g_hash_table_replace (targets, key, d);
  }

  image_starts = (const GumChainedStartsInImage *) (fixups_start +
      fixups_header->starts_offset);

  slide = gum_darwin_module_get_slide (self);

  for (seg_index = 0; seg_index != image_starts->seg_count; seg_index++)
  {
    const guint seg_offset = image_starts->seg_info_offset[seg_index];
    const GumChainedStartsInSegment * seg_starts;
    const GumDarwinSegment * current_seg;
    guint16 page_index;

    if (seg_offset == 0)
      continue;

    seg_starts = (const GumChainedStartsInSegment *)
        ((const guint8 *) image_starts + seg_offset);

    current_seg = gum_darwin_module_get_nth_segment (self, seg_index);

    for (page_index = 0; page_index != seg_starts->page_count; page_index++)
    {
      guint16 start;
      GumAddress page_address;
      const guint8 * page_start, * page_end, * cursor;
      gpointer page_malloc_data;

      start = seg_starts->page_start[page_index];
      if (start == GUM_CHAINED_PTR_START_NONE)
        continue;

      page_address = current_seg->vm_address +
          (page_index * seg_starts->page_size) + start + slide;

      gum_darwin_module_read_and_assign (self, page_address,
          seg_starts->page_size - start, &page_start, &page_end,
          &page_malloc_data);
      if (page_start == NULL)
        continue;

      cursor = page_start;

      for (; cursor != page_end; cursor += GLIB_SIZEOF_VOID_P)
      {
        GumAddress candidate = *(guint64 *) cursor;
        gpointer key;
        GumImportDetails * d;

        if (candidate == 0)
          continue;

        key = GSIZE_TO_POINTER (gum_strip_code_address (candidate));

        d = g_hash_table_lookup (targets, key);
        if (d == NULL)
          continue;

        d->slot = page_address + (cursor - page_start);

        ctx->carry_on = ctx->func (d, ctx->user_data);
        if (!ctx->carry_on)
          break;
      }

      g_free (page_malloc_data);

      if (!ctx->carry_on)
        break;
    }

    if (!ctx->carry_on)
      break;
  }

skip:
  g_hash_table_unref (targets);
  g_free (malloc_data);

  return ctx->carry_on;
}

void
gum_darwin_module_query_tlv_parameters (GumDarwinModule * self,
                                        GumDarwinTlvParameters * params)
{
  GumMachHeader32 * header;
  guint32 flags;
  GumQueryTlvParamsContext ctx;

  params->num_descriptors = 0;
  params->descriptors_offset = 0;
  params->data_offset = 0;
  params->data_size = 0;
  params->bss_size = 0;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  header = self->image->data;

  if (header->magic == GUM_MH_MAGIC_32)
    flags = header->flags;
  else
    flags = ((GumMachHeader64 *) header)->flags;
  if ((flags & GUM_MH_HAS_TLV_DESCRIPTORS) == 0)
    return;

  ctx.header = header;
  ctx.params = params;
  gum_darwin_module_enumerate_sections (self, gum_collect_tlv_params, &ctx);
}

static gboolean
gum_collect_tlv_params (const GumDarwinSectionDetails * section,
                        gpointer user_data)
{
  GumQueryTlvParamsContext * ctx = user_data;
  GumDarwinTlvParameters * params = ctx->params;

  switch (section->flags & GUM_SECTION_TYPE_MASK)
  {
    case GUM_S_THREAD_LOCAL_VARIABLES:
    {
      gsize descriptor_size = (ctx->header->magic == GUM_MH_MAGIC_64)
          ? sizeof (GumTlvThunk64)
          : sizeof (GumTlvThunk32);
      params->num_descriptors = section->size / descriptor_size;
      params->descriptors_offset = section->file_offset;
      break;
    }
    case GUM_S_THREAD_LOCAL_REGULAR:
      params->data_offset = section->file_offset;
      params->data_size = section->size;
      break;
    case GUM_S_THREAD_LOCAL_ZEROFILL:
      params->bss_size = section->size;
      break;
    default:
      break;
  }

  return TRUE;
}

void
gum_darwin_module_enumerate_tlv_descriptors (
    GumDarwinModule * self,
    GumFoundDarwinTlvDescriptorFunc func,
    gpointer user_data)
{
  GumDarwinTlvParameters tlv;
  gconstpointer descriptors;
  gsize i;
  guint32 format;

  gum_darwin_module_query_tlv_parameters (self, &tlv);
  if (tlv.num_descriptors == 0)
    return;

  descriptors =
      (const guint8 *) self->image->data + tlv.descriptors_offset;
  format = ((GumMachHeader32 *) self->image->data)->magic;

  for (i = 0; i != tlv.num_descriptors; i++)
  {
    GumDarwinTlvDescriptorDetails details;

    if (format == GUM_MH_MAGIC_32)
    {
      const GumTlvThunk32 * d = &((const GumTlvThunk32 *) descriptors)[i];
      details.file_offset =
          tlv.descriptors_offset + (i * sizeof (GumTlvThunk32));
      details.thunk = d->thunk;
      details.key = d->key;
      details.offset = d->offset;
    }
    else
    {
      const GumTlvThunk64 * d = &((const GumTlvThunk64 *) descriptors)[i];
      details.file_offset =
          tlv.descriptors_offset + (i * sizeof (GumTlvThunk64));
      details.thunk = d->thunk;
      details.key = d->key;
      details.offset = d->offset;
    }

    if (!func (&details, user_data))
      return;
  }
}

void
gum_darwin_module_enumerate_init_pointers (GumDarwinModule * self,
                                           GumFoundDarwinInitPointersFunc func,
                                           gpointer user_data)
{
  GumEmitInitPointersContext ctx;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  ctx.func = func;
  ctx.user_data = user_data;
  ctx.pointer_size = self->pointer_size;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_init_pointers,
      &ctx);
}

void
gum_darwin_module_enumerate_init_offsets (GumDarwinModule * self,
                                          GumFoundDarwinInitOffsetsFunc func,
                                          gpointer user_data)
{
  GumEmitInitOffsetsContext ctx;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  ctx.func = func;
  ctx.user_data = user_data;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_init_offsets,
      &ctx);
}

void
gum_darwin_module_enumerate_term_pointers (GumDarwinModule * self,
                                           GumFoundDarwinTermPointersFunc func,
                                           gpointer user_data)
{
  GumEmitTermPointersContext ctx;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  ctx.func = func;
  ctx.user_data = user_data;
  ctx.pointer_size = self->pointer_size;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_term_pointers,
      &ctx);
}

static gboolean
gum_emit_section_init_pointers (const GumDarwinSectionDetails * details,
                                gpointer user_data)
{
  if ((details->flags & GUM_SECTION_TYPE_MASK) == GUM_S_MOD_INIT_FUNC_POINTERS)
  {
    GumEmitInitPointersContext * ctx = user_data;
    GumDarwinInitPointersDetails d;

    d.address = details->vm_address;
    d.count = details->size / ctx->pointer_size;

    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

static gboolean
gum_emit_section_init_offsets (const GumDarwinSectionDetails * details,
                               gpointer user_data)
{
  if ((details->flags & GUM_SECTION_TYPE_MASK) == GUM_S_INIT_FUNC_OFFSETS)
  {
    GumEmitInitOffsetsContext * ctx = user_data;
    GumDarwinInitOffsetsDetails d;

    d.address = details->vm_address;
    d.count = details->size / sizeof (guint32);

    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

static gboolean
gum_emit_section_term_pointers (const GumDarwinSectionDetails * details,
                                gpointer user_data)
{
  if ((details->flags & GUM_SECTION_TYPE_MASK) == GUM_S_MOD_TERM_FUNC_POINTERS)
  {
    GumEmitTermPointersContext * ctx = user_data;
    GumDarwinTermPointersDetails d;

    d.address = details->vm_address;
    d.count = details->size / ctx->pointer_size;

    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

void
gum_darwin_module_enumerate_dependencies (GumDarwinModule * self,
                                          GumFoundDependencyFunc func,
                                          gpointer user_data)
{
  guint i;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  for (i = 0; i != self->dependencies->len; i++)
  {
    const GumDependencyDetails * d =
        &g_array_index (self->dependencies, GumDependencyDetails, i);

    if (!func (d, user_data))
      return;
  }
}

void
gum_darwin_module_enumerate_function_starts (
    GumDarwinModule * self,
    GumFoundDarwinFunctionStartsFunc func,
    gpointer user_data)
{
  GumDarwinModuleImage * image;
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  image = self->image;

  header = (GumMachHeader32 *) image->data;
  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) image->data + 1;
  else
    command = (GumMachHeader64 *) image->data + 1;
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = command;

    if (lc->cmd == GUM_LC_FUNCTION_STARTS)
    {
      const GumLinkeditDataCommand * starts = command;
      GumAddress linkedit;
      GumDarwinFunctionStartsDetails details;

      if (!gum_find_linkedit (image->data, image->size, &linkedit))
        return;

      linkedit += gum_darwin_module_get_slide (self);

      details.vm_address = linkedit + starts->dataoff;
      details.file_offset = starts->dataoff;
      details.size = starts->datasize;

      if (!func (&details, user_data))
        return;
    }

    command = (const guint8 *) command + lc->cmdsize;
  }
}

const gchar *
gum_darwin_module_get_dependency_by_ordinal (GumDarwinModule * self,
                                             gint ordinal)
{
  gint i;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return NULL;

  switch (ordinal)
  {
    case GUM_BIND_SPECIAL_DYLIB_SELF:
      return self->name;
    case GUM_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
    case GUM_BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
    case GUM_BIND_SPECIAL_DYLIB_WEAK_LOOKUP:
      return NULL;
  }

  i = ordinal - 1;

  if (i < 0 || i >= (gint) self->dependencies->len)
    return NULL;

  return g_array_index (self->dependencies, GumDependencyDetails, i).name;
}

gboolean
gum_darwin_module_ensure_image_loaded (GumDarwinModule * self,
                                       GError ** error)
{
  if (self->image != NULL)
    return TRUE;

  return gum_darwin_module_load_image_from_memory (self, error);
}

void
gum_darwin_threaded_item_parse (guint64 value,
                                GumDarwinThreadedItem * result)
{
  result->is_authenticated      = (value >> 63) & 1;
  result->type                  = (value >> 62) & 1;
  result->delta                 = (value >> 51) & GUM_INT11_MASK;
  result->key                   = (value >> 49) & GUM_INT2_MASK;
  result->has_address_diversity = (value >> 48) & 1;
  result->diversity             = (value >> 32) & GUM_INT16_MASK;

  if (result->type == GUM_DARWIN_THREADED_BIND)
  {
    result->bind_ordinal = value & GUM_INT16_MASK;
  }
  else if (result->type == GUM_DARWIN_THREADED_REBASE)
  {
    if (result->is_authenticated)
    {
      result->rebase_address = value & GUM_INT32_MASK;
    }
    else
    {
      guint64 top_8_bits, bottom_43_bits, sign_bits;
      gboolean sign_bit_set;

      top_8_bits = (value << 13) & G_GUINT64_CONSTANT (0xff00000000000000);
      bottom_43_bits = value     & G_GUINT64_CONSTANT (0x000007ffffffffff);

      sign_bit_set = (value >> 42) & 1;
      if (sign_bit_set)
        sign_bits = G_GUINT64_CONSTANT (0x00fff80000000000);
      else
        sign_bits = 0;

      result->rebase_address = top_8_bits | sign_bits | bottom_43_bits;
    }
  }
}

static gboolean
gum_darwin_module_load_image_from_filesystem (GumDarwinModule * self,
                                              const gchar * path,
                                              GError ** error)
{
  gboolean success;
  GMappedFile * file;
  gsize size, size_in_pages, page_size;
  gpointer data;
  GBytes * blob;

  file = g_mapped_file_new (path, FALSE, NULL);
  if (file == NULL)
    goto not_found;

  size = g_mapped_file_get_length (file);
  page_size = gum_query_page_size ();
  size_in_pages = size / page_size;
  if (size % page_size != 0)
    size_in_pages++;

  data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  memcpy (data, g_mapped_file_get_contents (file), size);

  g_clear_pointer (&file, g_mapped_file_unref);

  blob = g_bytes_new_with_free_func (data, size, gum_free_pages, data);

  success = gum_darwin_module_load_image_from_blob (self, blob, error);

  g_bytes_unref (blob);

  return success;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
        "Module not found at \"%s\"", path);
    return FALSE;
  }
}

static gboolean
gum_darwin_module_load_image_header_from_filesystem (GumDarwinModule * self,
                                                     const gchar * path,
                                                     GError ** error)
{
  gboolean success;
  GMappedFile * file;
  gsize page_size, size, size_in_pages;
  gpointer data;
  GBytes * blob;
  gsize header_size, cursor;
  gboolean is_fat;

  file = g_mapped_file_new (path, FALSE, NULL);
  if (file == NULL)
    goto not_found;

  page_size = gum_query_page_size ();
  data = gum_alloc_n_pages (1, GUM_PAGE_RW);
  size = page_size;

  header_size = 0;
  cursor = 0;
  do
  {
    gsize header_offset = 0;

    memcpy (data, g_mapped_file_get_contents (file) + cursor, size);
    if (!gum_darwin_module_get_header_offset_size (self, data, size,
        &header_offset, &header_size, error))
    {
      gum_free_pages (data);
      g_clear_pointer (&file, g_mapped_file_unref);
      return FALSE;
    }

    cursor += header_offset;
    is_fat = header_offset > 0;
  }
  while (is_fat);

  size_in_pages = header_size / page_size;
  if (header_size % page_size != 0)
    size_in_pages++;

  if (size_in_pages != 1)
  {
    gum_free_pages (data);
    data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  }

  memcpy (data, g_mapped_file_get_contents (file) + cursor, header_size);

  g_clear_pointer (&file, g_mapped_file_unref);

  blob = g_bytes_new_with_free_func (data, header_size, gum_free_pages, data);

  success = gum_darwin_module_load_image_from_blob (self, blob, error);

  g_bytes_unref (blob);

  return success;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
        "Module not found at \"%s\"", path);
    return FALSE;
  }
}

static gboolean
gum_darwin_module_get_header_offset_size (GumDarwinModule * self,
                                          gpointer data,
                                          gsize data_size,
                                          gsize * out_offset,
                                          gsize * out_size,
                                          GError ** error)
{
  GumFatHeader * fat_header;
  gpointer data_end;
  gboolean found;

  fat_header = data;
  data_end = (guint8 *) data + data_size;

  found = FALSE;
  switch (fat_header->magic)
  {
    case GUM_FAT_CIGAM_32:
    {
      guint32 count, i;

      count = GUINT32_FROM_BE (fat_header->nfat_arch);
      for (i = 0; i != count && !found; i++)
      {
        GumFatArch32 * fat_arch;
        guint32 offset;
        GumDarwinCpuType cpu_type;
        GumDarwinCpuSubtype cpu_subtype;

        fat_arch = ((GumFatArch32 *) (fat_header + 1)) + i;
        if ((gpointer) (fat_arch + 1) > data_end)
          goto invalid_blob;

        offset = GUINT32_FROM_BE (fat_arch->offset);
        cpu_type = GUINT32_FROM_BE (fat_arch->cputype);
        cpu_subtype = GUINT32_FROM_BE (fat_arch->cpusubtype);

        found = gum_darwin_module_can_load (self, cpu_type, cpu_subtype);
        if (found)
        {
          *out_offset = offset;
          *out_size = (gum_pointer_size_from_cpu_type (cpu_type) == 8)
              ? sizeof (GumMachHeader64)
              : sizeof (GumMachHeader32);
        }
      }

      break;
    }
    case GUM_MH_MAGIC_32:
    {
      GumMachHeader32 * header = data;

      if ((gpointer) (header + 1) > data_end)
        goto invalid_blob;

      found = gum_darwin_module_can_load (self, header->cputype,
          header->cpusubtype);
      if (found)
      {
        *out_offset = 0;
        *out_size = sizeof (GumMachHeader32) + header->sizeofcmds;
      }

      break;
    }
    case GUM_MH_MAGIC_64:
    {
      GumMachHeader64 * header = data;

      if ((gpointer) (header + 1) > data_end)
        goto invalid_blob;

      found = gum_darwin_module_can_load (self, header->cputype,
          header->cpusubtype);
      if (found)
      {
        *out_offset = 0;
        *out_size = sizeof (GumMachHeader64) + header->sizeofcmds;
      }

      break;
    }
    default:
      goto invalid_blob;
  }

  if (!found)
    goto incompatible_image;

  return TRUE;

invalid_blob:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
    return FALSE;
  }
incompatible_image:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Incompatible Mach-O image");
    return FALSE;
  }
}

static gboolean
gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
                                        GBytes * blob,
                                        GError ** error)
{
  GumDarwinModuleImage * image;
  guint8 * blob_start, * blob_end;
  gsize blob_size;
  gsize page_size;
  gboolean is_page_aligned;
  gpointer data;
  gsize size;
  guint32 magic;

  image = gum_darwin_module_image_new ();
  image->bytes = g_bytes_ref (blob);

  blob_start = (guint8 *) g_bytes_get_data (blob, &blob_size);
  blob_end = blob_start + blob_size;

  page_size = gum_query_page_size ();
  is_page_aligned = (GPOINTER_TO_SIZE (blob_start) % page_size) == 0;
  if (!is_page_aligned)
  {
    gsize size_in_pages;
    gpointer copy;

    size_in_pages = blob_size / page_size;
    if (blob_size % page_size != 0)
      size_in_pages++;

    copy = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
    memcpy (copy, blob_start, blob_size);

    blob = g_bytes_new_with_free_func (copy, blob_size, gum_free_pages, copy);
    blob_start = copy;
    blob_end = blob_start + blob_size;

    g_bytes_unref (image->bytes);
    image->bytes = blob;
  }

  data = blob_start;
  size = blob_size;

  if (blob_size < 4)
    goto invalid_blob;
  magic = *((guint32 *) data);

  if (magic == GUM_FAT_CIGAM_32)
  {
    GumFatHeader * fat_header;
    guint32 count, i;
    gboolean found;

    fat_header = (GumFatHeader *) blob_start;

    count = GUINT32_FROM_BE (fat_header->nfat_arch);
    found = FALSE;
    for (i = 0; i != count && !found; i++)
    {
      GumFatArch32 * fat_arch;
      GumDarwinCpuType cpu_type;
      GumDarwinCpuSubtype cpu_subtype;

      fat_arch = ((GumFatArch32 *) (fat_header + 1)) + i;
      if ((guint8 *) (fat_arch + 1) > blob_end)
        goto invalid_blob;

      cpu_type = GUINT32_FROM_BE (fat_arch->cputype);
      cpu_subtype = GUINT32_FROM_BE (fat_arch->cpusubtype);

      found = gum_darwin_module_can_load (self, cpu_type, cpu_subtype);
      if (found)
      {
        data = blob_start + GUINT32_FROM_BE (fat_arch->offset);
        size = GUINT32_FROM_BE (fat_arch->size);
      }
    }

    if (!found)
      goto incompatible_image;

    if ((guint8 *) data + 4 > blob_end)
      goto invalid_blob;
    magic = *((guint32 *) data);
  }

  switch (magic)
  {
    case GUM_MH_MAGIC_32:
    {
      GumMachHeader32 * header = data;

      if ((guint8 *) (header + 1) > blob_end)
        goto invalid_blob;

      if (!gum_darwin_module_can_load (self, header->cputype,
          header->cpusubtype))
      {
        goto incompatible_image;
      }

      break;
    }
    case GUM_MH_MAGIC_64:
    {
      GumMachHeader64 * header = data;

      if ((guint8 *) (header + 1) > blob_end)
        goto invalid_blob;

      if (!gum_darwin_module_can_load (self, header->cputype,
          header->cpusubtype))
      {
        goto incompatible_image;
      }

      break;
    }
    default:
      goto invalid_blob;
  }

  image->data = data;
  image->size = size;
  image->linkedit = data;

  return gum_darwin_module_take_image (self, image, error);

invalid_blob:
  {
    gum_darwin_module_image_free (image);

    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
    return FALSE;
  }
incompatible_image:
  {
    gum_darwin_module_image_free (image);

    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Incompatible Mach-O image");
    return FALSE;
  }
}

static gboolean
gum_darwin_module_load_image_from_memory (GumDarwinModule * self,
                                          GError ** error)
{
  guint8 * start, * end;
  gpointer malloc_data;
  GumDarwinModuleImage * image;

  g_assert (self->base_address != 0);

  gum_darwin_module_read_and_assign (self, self->base_address,
      GUM_MAX_MACHO_METADATA_SIZE, (const guint8 **) &start,
      (const guint8 **) &end, &malloc_data);
  if (start == NULL)
    goto invalid_task;

  image = gum_darwin_module_image_new ();

  image->data = start;
  image->size = end - start;

  image->malloc_data = malloc_data;

  return gum_darwin_module_take_image (self, image, error);

invalid_task:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Process is dead");
    return FALSE;
  }
}

static gboolean
gum_darwin_module_can_load (GumDarwinModule * self,
                            GumDarwinCpuType cpu_type,
                            GumDarwinCpuSubtype cpu_subtype)
{
  GumCpuType canonical_cpu_type;
  gboolean allow_any_cpu, allow_any_ptrauth;

  canonical_cpu_type = gum_cpu_type_from_darwin (cpu_type);

  allow_any_cpu = self->cpu_type == GUM_CPU_INVALID;
  
"""


```