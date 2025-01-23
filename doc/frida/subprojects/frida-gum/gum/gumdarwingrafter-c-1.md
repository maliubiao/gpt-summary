Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Scan and Keyword Identification:**

The first step is to quickly read through the code, looking for recognizable patterns and keywords. Things that immediately jump out are:

* **`frida` and file path:**  This confirms the context of the code and the specific file within the Frida project.
* **`gumdarwingrafter.c`:**  The "darwin" suggests macOS, and "grafter" implies modifying or inserting something into existing structures.
* **`Gum...` prefixes:**  This indicates Frida's internal data structures and functions. Examples: `GumGraftedLayout`, `GumDyldInfoCommand`, `GumArm64Writer`.
* **`LC_...` constants:** These are Mach-O load commands, specific to macOS and iOS executables. This reinforces the "darwin" part.
* **`bind`, `lazy_bind`, `rebase`, `export`:**  These terms relate to dynamic linking and symbol resolution in Mach-O.
* **`emit_segments`:** This function seems to be generating or writing data into memory segments.
* **`hook`, `trampoline`, `import`:** These are key concepts in dynamic instrumentation – intercepting function calls.
* **`gum_arm64_writer`:**  Code generation for the ARM64 architecture.
* **`merge_lazy_binds_into_binds` and `replay_bind_state_transitions`:**  Manipulation of the binding information.
* **`_gum_grafted_hook_activate` and `_gum_grafted_hook_deactivate`:** Functions to control the activation of hooks.

**2. Understanding the Core Functionality:**

Based on the keywords, the central goal appears to be *dynamically modifying a Mach-O binary at runtime* to insert hooks and redirect function calls. The "grafter" name is very fitting.

**3. Analyzing Key Functions and Data Structures:**

Now, dive deeper into the crucial parts:

* **`gum_darwin_grafter_apply`:**  This seems to be the main entry point. It iterates through Mach-O load commands, shifting addresses within them (`GUM_SHIFT`, `GUM_MAYBE_SHIFT`). The logic around `LC_DYLD_INFO_ONLY` is about handling binding information.
* **Load Command Handling (`case GUM_LC_...`):**  Each case handles a specific type of load command. The code adjusts offsets within these commands, preparing them for the inserted code and data. The special handling of `LC_DYLD_INFO_ONLY` and merging lazy bindings is critical.
* **`gum_darwin_grafter_emit_segments`:** This function *generates* the code and data for the hooks and trampolines. It uses `gum_arm64_writer` to write ARM64 assembly instructions. The structure of the grafted code (trampolines, headers, hook/import entries) becomes evident here.
* **`gum_merge_lazy_binds_into_binds`:** This is about resolving symbols that are initially resolved lazily by the dynamic linker. Frida needs these resolved upfront for its interception mechanism. It parses the binding opcodes.
* **`gum_replay_bind_state_transitions`:**  This function helps understand the state changes during the binding process, necessary for correctly merging lazy bindings.

**4. Connecting to Reverse Engineering Concepts:**

Think about how this code relates to standard reverse engineering tasks:

* **Analyzing Mach-O structure:** Understanding load commands, symbol tables, binding information is fundamental to reverse engineering macOS/iOS binaries. This code directly interacts with these structures.
* **Dynamic analysis:** Frida is a dynamic analysis tool. This code enables *modifying* the behavior of a running process, which is a key aspect of dynamic analysis.
* **Hooking/Interception:** The code explicitly implements hooking by inserting trampolines to redirect execution flow.
* **Code injection:**  While not explicitly injecting *new* code segments, it modifies existing segments and adds data.

**5. Considering Binary/Kernel/Framework Aspects:**

* **Binary format (Mach-O):** The entire code revolves around the Mach-O executable format.
* **Dynamic linking:** The handling of binding information is directly related to how the dynamic linker resolves symbols.
* **ARM64 architecture:** The `gum_arm64_writer` indicates interaction with the ARM64 instruction set.
* **Operating System (macOS/iOS):**  The use of Mach-O load commands and the dynamic linker are OS-specific.

**6. Logical Reasoning and Assumptions:**

* **Assumption:** The input is a valid Mach-O binary.
* **Assumption:** Frida has allocated memory for the grafted code and data.
* **Reasoning (in `emit_segments`):** The code carefully calculates offsets and writes instructions to redirect execution. The logic ensures that when the original code is executed, it jumps to Frida's trampoline, allowing Frida to execute its own code before returning to the original flow.

**7. Identifying Potential User Errors:**

* **Incorrect Frida API usage:**  Users might not correctly configure Frida to use this grafting mechanism.
* **Conflicting hooks:** If multiple Frida scripts try to hook the same function in incompatible ways, it could lead to crashes or unexpected behavior.
* **Resource exhaustion:**  Excessive hooking could potentially impact performance.

**8. Tracing User Operations:**

Consider how a user ends up triggering this code:

1. **Write a Frida script:** The user uses the Frida API to specify functions they want to intercept.
2. **Target a process:** The script targets a running process on macOS/iOS.
3. **Frida's core:** Frida's core components analyze the target process.
4. **Grafting mechanism:** Frida determines that the "grafting" technique is appropriate for the requested hooks (likely for system libraries or other performance-critical scenarios where inline hooking is preferred).
5. **`gumdarwingrafter.c` execution:**  The functions in this file are called to modify the target process's memory, inserting the necessary trampolines and data structures.

**9. Structuring the Output:**

Finally, organize the findings into clear categories (functionality, relation to reverse engineering, binary/kernel aspects, etc.) as requested by the prompt. Provide specific examples from the code to illustrate each point.

This detailed thought process, moving from a general understanding to specific code analysis and connecting it to broader concepts, is crucial for effectively analyzing and explaining complex code like this.
This is part 2 of the analysis of the `gumdarwingrafter.c` file, focusing on the remaining code and summarizing its functionality.

Let's break down the functionality of the provided code snippet:

**1. Handling Mach-O Load Commands (Continuation from Part 1):**

The code continues processing different Mach-O load commands (`LC_...`). It focuses on adjusting offsets within these commands, specifically shifting them to accommodate the injected Frida code and data.

* **`GUM_LC_SYMTAB` and `GUM_LC_DYSYMTAB`:** These deal with the symbol table and dynamic symbol table information. The code shifts the offsets of these tables (`symoff`, `stroff`, `tocoff`, etc.). This is essential because Frida is inserting new data and potentially needs to adjust the locations where the system looks for symbols.
* **`GUM_LC_CODE_SIGNATURE`, `GUM_LC_SEGMENT_SPLIT_INFO`, etc.:** These are various linkedit data commands related to code signing, segment splitting, function starts, etc. The code shifts the `dataoff` in these commands. This is critical to maintain the integrity of the binary's structure after modification, especially for code signing verification.
* **`default` case:**  For any unrecognized load commands, it does nothing, ensuring the code doesn't break if new load command types are introduced in the future.

**2. `gum_darwin_grafter_emit_segments` Function:**

This function is responsible for generating and writing the actual grafted code and data into the target process's memory. It sets up the trampolines and data structures needed for Frida's hooks.

* **Iterating through Segment Pairs:** It iterates through descriptors that define where the grafted code and data should be placed.
* **Memory Allocation and Initialization:** It obtains pointers to the code and data segments and initializes them with zeros.
* **Setting up Trampolines:** It writes ARM64 assembly instructions into the `hook_trampolines` and `import_trampolines`. These trampolines are small pieces of code that redirect execution flow when a hooked function is called.
    * **`hook_trampolines`:**  These are placed at the original function's entry point. They save registers, check if the hook is active, call Frida's runtime, and then either execute the original instruction or jump to the user-defined callback.
    * **`import_trampolines`:** These are used for hooking imported functions (functions from other libraries). They similarly redirect execution.
* **Setting up Headers and Entries:** It populates the `GumGraftedHeader`, `GumGraftedHook`, and `GumGraftedImport` structures with information about the hooks, including offsets, flags, and user data pointers.
* **ARM64 Assembly Generation:** It uses `gum_arm64_writer` to generate the ARM64 instructions for the trampolines. This involves instructions like `b` (branch), `push`, `ldr` (load register), `tbz` (test bit and branch if zero), and `br` (branch register).
* **Error Handling:**  It includes a basic error check (`goto ldr_error`) if a `ldr` instruction's target is too far away, which could happen with large memory layouts.

**3. `gum_merge_lazy_binds_into_binds` Function:**

This crucial function deals with resolving "lazy" bindings in the Mach-O binary.

* **Lazy Binding:**  In macOS/iOS, some symbols are not resolved until they are actually called (lazy binding). This function forces these bindings to be resolved upfront.
* **Merging Data:** It merges the data from the lazy binding section (`ic->lazy_bind_off`, `ic->lazy_bind_size`) into the regular binding section (`ic->bind_off`, `ic->bind_size`).
* **Parsing Bind Opcodes:** It iterates through the lazy binding opcodes, interpreting their meaning (setting library ordinal, symbol name, type, addend, segment and offset).
* **State Tracking:** It uses a `GumBindState` structure to track the current state of the binding process.
* **Avoiding Redundancy:** It only appends binding opcodes to the merged section if they represent a change in the binding state compared to the regular binding section. This avoids unnecessary data.
* **Terminator:** It adds a `GUM_BIND_OPCODE_DONE` terminator to the end of the merged binding section.

**4. `gum_replay_bind_state_transitions` Function:**

This helper function is used by `gum_merge_lazy_binds_into_binds` to simulate the state changes that occur during the dynamic linking process.

* **Replaying Opcodes:** It iterates through a sequence of bind opcodes and updates the `GumBindState` accordingly.
* **Tracking Binding Information:** It tracks information like the segment index, offset, type, library ordinal, and addend for each binding entry.

**5. `_gum_grafted_hook_activate` and `_gum_grafted_hook_deactivate` Functions:**

These simple functions control the activation state of a grafted hook.

* **Flags Manipulation:** They modify a flag within the `GumGraftedHook` structure to enable or disable the hook. This allows Frida to dynamically turn hooks on and off without needing to rewrite the grafted code.

**Functionality Summary:**

In essence, `gumdarwingrafter.c` is responsible for:

* **Modifying the Mach-O binary structure in memory:** It adjusts offsets in load commands to make space for Frida's injected code and data.
* **Generating and injecting hook trampolines:** It creates small pieces of code that intercept function calls, redirecting execution to Frida's runtime.
* **Managing binding information:** It resolves lazy bindings to ensure that Frida can intercept calls to dynamically linked libraries.
* **Providing a mechanism to activate and deactivate hooks:**  It allows Frida to control whether a hook is currently active.

**Relationship to Reverse Engineering:**

* **Dynamic Instrumentation:** This file is a core component of Frida, a dynamic instrumentation toolkit. Dynamic instrumentation is a powerful reverse engineering technique that allows you to observe and modify the behavior of a running program.
* **Code Injection:** The process of injecting trampolines into the target process's code is a form of code injection, a common technique in reverse engineering for modifying program behavior.
* **Understanding Binary Formats:** The code demonstrates a deep understanding of the Mach-O executable format used on macOS and iOS. This is a fundamental skill in reverse engineering these platforms.
* **Hooking Techniques:** The implementation of trampolines is a classic hooking technique used in reverse engineering to intercept function calls.
* **Analyzing Dynamic Linking:** The handling of binding information is crucial for understanding how programs interact with shared libraries, a key aspect of reverse engineering.

**Example of Relationship to Reverse Engineering:**

Imagine a reverse engineer wants to analyze how a specific API function in a macOS application works. They can use Frida, which utilizes `gumdarwingrafter.c`, to:

1. **Hook the API function:** Frida will use the code in this file to insert a trampoline at the beginning of the API function.
2. **Intercept the call:** When the application calls the API function, the execution will be redirected to Frida's runtime via the trampoline.
3. **Analyze the arguments and behavior:** The reverse engineer can then use Frida to inspect the arguments passed to the function, the return value, and the internal state of the application during the function's execution.
4. **Modify behavior (optional):** The reverse engineer could even use Frida to modify the arguments or the return value of the function, altering the application's behavior.

**Binary/Kernel/Framework Knowledge:**

* **Binary 底层 (Binary Low-Level):** The code directly manipulates the binary structure of Mach-O files, including load commands, sections, and symbol tables. It works with raw memory addresses and sizes.
* **Linux (Although the file name indicates "darwin"):** While the file is specific to Darwin (macOS/iOS), the concepts of dynamic linking, code injection, and hooking are also relevant in the Linux environment, although the specific implementations and binary formats (like ELF) differ.
* **Android Kernel/Framework (Indirectly):** While this specific file targets Darwin, Frida also supports Android. The underlying principles of dynamic instrumentation and code injection are similar across platforms, even though the implementation details for hooking and binary manipulation will be different on Android (using the ELF format and the Android runtime environment).
* **ARM64 Architecture:** The use of `gum_arm64_writer` indicates knowledge of the ARM64 instruction set, which is prevalent on modern Apple devices and Android devices.

**Logical Reasoning, Assumptions, and Input/Output:**

**Assumption:** The input to these functions is a valid Mach-O binary loaded into memory.

**`gum_darwin_grafter_apply`:**

* **Input:** A pointer to the start of the Mach-O header in memory (`header_data`), the size of the header, a `GumGraftedLayout` structure describing where to inject code, and a pointer to store the merged bind information.
* **Output:** Modifies the Mach-O header in memory by shifting offsets in load commands. Optionally returns the merged bind information.

**`gum_darwin_grafter_emit_segments`:**

* **Input:** A pointer to the memory where the grafted segments should be written (`output`), a `GumGraftedLayout` structure, arrays of code offsets and import information.
* **Output:** Writes the grafted code (trampolines) and data structures into the specified memory locations. Returns `TRUE` on success, `FALSE` on failure.

**`gum_merge_lazy_binds_into_binds`:**

* **Input:** A `GumDyldInfoCommand` structure describing the bind and lazy bind sections, and a pointer to the linkedit segment in memory.
* **Output:** Returns a `GByteArray` containing the merged bind information.

**`gum_replay_bind_state_transitions`:**

* **Input:** Pointers to the start and end of a sequence of bind opcodes, and a pointer to a `GumBindState` structure.
* **Output:** Modifies the `GumBindState` structure to reflect the state transitions caused by the opcodes.

**`_gum_grafted_hook_activate` / `_gum_grafted_hook_deactivate`:**

* **Input:** A pointer to a `GumGraftedHook` structure.
* **Output:** Modifies the flags within the `GumGraftedHook` structure.

**User or Programming Common Usage Errors:**

* **Incorrect Frida API Usage:** Users might misuse the Frida API, leading to incorrect offsets or sizes being passed to these functions, causing crashes or unexpected behavior.
* **Memory Corruption:** If the `GumGraftedLayout` is not correctly calculated, the grafting process could overwrite critical parts of the target process's memory.
* **Conflicting Hooks:**  If multiple Frida scripts try to hook the same function in incompatible ways, it could lead to undefined behavior.
* **Incorrect Permissions:** Frida needs sufficient permissions to access and modify the target process's memory. If permissions are insufficient, the grafting process will fail.
* **Target Process Instability:**  Heavy or incorrect instrumentation can sometimes destabilize the target process, leading to crashes.

**User Operation Steps to Reach This Code (Debugging Clue):**

1. **User writes a Frida script:** The script uses Frida's API (e.g., `Interceptor.attach`, `Module.getExportByName`) to specify functions they want to intercept.
2. **User runs the Frida script against a target process on macOS or iOS.**
3. **Frida's core logic:** Frida analyzes the target process and determines the best way to implement the requested hooks. For certain scenarios, especially when hooking functions in system libraries or when inline hooking is preferred for performance reasons, Frida will utilize the "grafting" mechanism.
4. **`gum/gumdarwingrafter.c` is invoked:**
    * Frida will first call functions in this file (like `gum_darwin_grafter_apply`) to prepare the target process by adjusting load command offsets.
    * Then, `gum_darwin_grafter_emit_segments` will be called to write the actual hook trampolines and data structures into the process's memory.
    * If lazy binding is involved, `gum_merge_lazy_binds_into_binds` might be called to resolve those bindings.
5. **Hooks are active:** Once the grafting is complete, when the target process calls a hooked function, the execution flow will be redirected through the injected trampolines.

**In summary, this code file is a crucial part of Frida's dynamic instrumentation engine on macOS and iOS. It handles the low-level details of modifying the target process's memory to insert hooks, allowing Frida to intercept function calls and enable powerful dynamic analysis and modification capabilities.**

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/gumdarwingrafter.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
bind_off + ic->weak_bind_size ==
                ic->lazy_bind_off)
              ic->weak_bind_size += ic->lazy_bind_size;
            else if (ic->export_off + ic->export_size == ic->lazy_bind_off)
              ic->export_size += ic->lazy_bind_size;
          }

          /*
           * Get rid of lazy binds so Interceptor can index them. This could
           * also be achieved at runtime by calling dlopen() with RTLD_NOW, but
           * we don't know if the library was loaded RTLD_GLOBAL vs RTLD_LOCAL.
           */
          binds = gum_merge_lazy_binds_into_binds (ic, linkedit);
          *merged_binds = binds;
          ic->bind_off =
              layout->rewritten_binds_offset + layout->linkedit_shift;

          /*
           * Adjust the size of binds so that everything is contiguous.
           * Not doing so results in a bug in codesign for which the resulting
           * signed binary turns out corrupted.
           */
          ic->bind_size = layout->rewritten_binds_capacity;

          g_assert (binds->len <= ic->bind_size);

          ic->lazy_bind_off = 0;
          ic->lazy_bind_size = 0;
        }
        else
        {
          GUM_MAYBE_SHIFT (ic->bind_off);
          GUM_MAYBE_SHIFT (ic->lazy_bind_off);
        }

        GUM_MAYBE_SHIFT (ic->rebase_off);
        GUM_MAYBE_SHIFT (ic->weak_bind_off);
        GUM_MAYBE_SHIFT (ic->export_off);

        break;
      }
      case GUM_LC_SYMTAB:
      {
        GumSymtabCommand * sc = command_out;

        GUM_SHIFT (sc->symoff);
        GUM_SHIFT (sc->stroff);

        break;
      }
      case GUM_LC_DYSYMTAB:
      {
        GumDysymtabCommand * dc = command_out;

        GUM_MAYBE_SHIFT (dc->tocoff);
        GUM_MAYBE_SHIFT (dc->modtaboff);
        GUM_MAYBE_SHIFT (dc->extrefsymoff);
        GUM_SHIFT (dc->indirectsymoff); /* XXX: is it always specified? */
        GUM_MAYBE_SHIFT (dc->extreloff);
        GUM_MAYBE_SHIFT (dc->locreloff);

        break;
      }
      case GUM_LC_CODE_SIGNATURE:
      case GUM_LC_SEGMENT_SPLIT_INFO:
      case GUM_LC_FUNCTION_STARTS:
      case GUM_LC_DATA_IN_CODE:
      case GUM_LC_DYLIB_CODE_SIGN_DRS:
      case GUM_LC_LINKER_OPTIMIZATION_HINT:
      case GUM_LC_DYLD_CHAINED_FIXUPS:
      case GUM_LC_DYLD_EXPORTS_TRIE:
      {
        GumLinkeditDataCommand * dc = command_out;

        GUM_SHIFT (dc->dataoff);

        break;
      }
      default:
        break;
    }

    command_in = (const guint8 *) command_in + lc->cmdsize;
  }

  *num_commands_out = n;

  return commands_out;
}

static gboolean
gum_darwin_grafter_emit_segments (gpointer output,
                                  const GumGraftedLayout * layout,
                                  GArray * code_offsets,
                                  GArray * imports,
                                  GError ** error)
{
  gboolean success = FALSE;
  GumArm64Writer cw;
  guint i, j;

  gum_arm64_writer_init (&cw, NULL);

  for (j = 0; j != layout->segment_pair_descriptors->len; j++)
  {
    const GumSegmentPairDescriptor * descriptor;
    gpointer code, data;
    GumGraftedHookTrampoline * hook_trampolines;
    GumGraftedImportTrampoline * import_trampolines;
    GumGraftedHeader * header;
    GumGraftedHook * hook_entries;
    GumGraftedImport * import_entries;
    GumAddress hook_trampolines_addr, import_trampolines_addr;
    GumAddress runtime_addr, do_begin_invocation_addr, do_end_invocation_addr;
    GumAddress header_addr, begin_invocation_addr, end_invocation_addr;
    GumAddress hook_entries_addr, import_entries_addr;

    descriptor = &g_array_index (layout->segment_pair_descriptors,
        GumSegmentPairDescriptor, j);

    code = (guint8 *) output + descriptor->code_offset;
    data = (guint8 *) output + descriptor->data_offset;

    memset (code, 0, descriptor->code_size);
    memset (data, 0, descriptor->data_size);

    hook_trampolines = code;
    import_trampolines =
        (GumGraftedImportTrampoline *) (hook_trampolines +
            descriptor->num_code_offsets);

    header = data;
    hook_entries = (GumGraftedHook *) (header + 1);
    import_entries = (GumGraftedImport *) (hook_entries +
        descriptor->num_code_offsets);

    header->abi_version = GUM_DARWIN_GRAFTER_ABI_VERSION;
    header->num_hooks = descriptor->num_code_offsets;
    header->num_imports = descriptor->num_imports;

    hook_trampolines_addr = descriptor->code_address;
    import_trampolines_addr = hook_trampolines_addr +
        descriptor->num_code_offsets * sizeof (GumGraftedHookTrampoline);

    runtime_addr = import_trampolines_addr +
        descriptor->num_imports * sizeof (GumGraftedImportTrampoline);
    do_begin_invocation_addr = runtime_addr +
        G_STRUCT_OFFSET (GumGraftedRuntime, do_begin_invocation);
    do_end_invocation_addr = runtime_addr +
        G_STRUCT_OFFSET (GumGraftedRuntime, do_end_invocation);

    header_addr = descriptor->data_address;
    begin_invocation_addr = header_addr +
        G_STRUCT_OFFSET (GumGraftedHeader, begin_invocation);
    end_invocation_addr = header_addr +
        G_STRUCT_OFFSET (GumGraftedHeader, end_invocation);

    hook_entries_addr = header_addr + sizeof (GumGraftedHeader);
    import_entries_addr = hook_entries_addr +
        descriptor->num_code_offsets * sizeof (GumGraftedHook);

    for (i = 0; i != descriptor->num_code_offsets; i++)
    {
      guint32 code_offset, * code_instructions, overwritten_insn;
      GumAddress code_addr;
      GumGraftedHookTrampoline * trampoline = &hook_trampolines[i];
      GumAddress trampoline_addr, on_enter_addr;
      GumGraftedHook * entry = &hook_entries[i];
      GumAddress entry_addr, flags_addr, user_data_addr;
      gconstpointer not_active = trampoline;

      code_offset = g_array_index (code_offsets, guint32,
          i + descriptor->code_offsets_start);
      code_addr = layout->text_address + code_offset;
      code_instructions = (guint32 *) ((guint8 *) output + code_offset);

      overwritten_insn = code_instructions[0];

      trampoline_addr =
          hook_trampolines_addr + i * sizeof (GumGraftedHookTrampoline);
      on_enter_addr = trampoline_addr +
          G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_enter);

      entry_addr = hook_entries_addr + i * sizeof (GumGraftedHook);
      flags_addr = entry_addr + G_STRUCT_OFFSET (GumGraftedHook, flags);
      user_data_addr = entry_addr + G_STRUCT_OFFSET (GumGraftedHook, user_data);

      gum_arm64_writer_reset (&cw, code_instructions);
      cw.pc = code_addr;
      gum_arm64_writer_put_b_imm (&cw, on_enter_addr);
      gum_arm64_writer_flush (&cw);

      gum_arm64_writer_reset (&cw, trampoline->on_enter);
      cw.pc = on_enter_addr;
      gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);
      gum_arm64_writer_put_ldr_reg_u32_ptr (&cw, ARM64_REG_W16, flags_addr);
      gum_arm64_writer_put_tbz_reg_imm_label (&cw,
          ARM64_REG_W16, 0, not_active);
      if (!gum_arm64_writer_put_ldr_reg_u64_ptr (&cw,
          ARM64_REG_X17, user_data_addr))
      {
        goto ldr_error;
      }
      gum_arm64_writer_put_b_imm (&cw, do_begin_invocation_addr);

      g_assert (cw.pc == trampoline_addr +
          G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_leave));
      gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);
      if (!gum_arm64_writer_put_ldr_reg_u64_ptr (&cw,
          ARM64_REG_X17, user_data_addr))
      {
        goto ldr_error;
      }
      gum_arm64_writer_put_b_imm (&cw, do_end_invocation_addr);

      g_assert (cw.pc == trampoline_addr +
          G_STRUCT_OFFSET (GumGraftedHookTrampoline, not_active));
      gum_arm64_writer_put_label (&cw, not_active);
      gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);

      g_assert (cw.pc == trampoline_addr +
          G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_invoke));
      /* TODO: use Arm64Relocator */
      gum_arm64_writer_put_instruction (&cw, overwritten_insn);
      gum_arm64_writer_put_b_imm (&cw, code_addr + sizeof (overwritten_insn));

      gum_arm64_writer_flush (&cw);
      g_assert (
          gum_arm64_writer_offset (&cw) == sizeof (GumGraftedHookTrampoline));

      entry->code_offset = code_offset;
      entry->trampoline_offset = trampoline_addr - layout->text_address;
      entry->flags =
          sizeof (GumGraftedHookTrampoline)                     << 24 |
          G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_enter)  << 17 |
          G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_leave)  << 10 |
          G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_invoke) <<  3 |
          0x0;
    }

    for (i = 0; i != descriptor->num_imports; i++)
    {
      const GumImport * import;
      GumGraftedImportTrampoline * trampoline = &import_trampolines[i];
      GumAddress trampoline_addr;
      GumGraftedImport * entry = &import_entries[i];
      GumAddress entry_addr, user_data_addr;

      import = &g_array_index (imports, GumImport,
          i + descriptor->imports_start);

      trampoline_addr =
          import_trampolines_addr + i * sizeof (GumGraftedImportTrampoline);

      entry_addr = import_entries_addr + i * sizeof (GumGraftedImport);
      user_data_addr =
          entry_addr + G_STRUCT_OFFSET (GumGraftedImport, user_data);

      gum_arm64_writer_reset (&cw, trampoline->on_enter);
      cw.pc = trampoline_addr +
          G_STRUCT_OFFSET (GumGraftedImportTrampoline, on_enter);
      gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);
      if (!gum_arm64_writer_put_ldr_reg_u64_ptr (&cw,
          ARM64_REG_X17, user_data_addr))
      {
        goto ldr_error;
      }
      gum_arm64_writer_put_b_imm (&cw, do_begin_invocation_addr);

      g_assert (cw.pc == trampoline_addr +
          G_STRUCT_OFFSET (GumGraftedImportTrampoline, on_leave));
      gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);
      if (!gum_arm64_writer_put_ldr_reg_u64_ptr (&cw,
          ARM64_REG_X17, user_data_addr))
      {
        goto ldr_error;
      }
      gum_arm64_writer_put_b_imm (&cw, do_end_invocation_addr);

      gum_arm64_writer_flush (&cw);
      g_assert (
          gum_arm64_writer_offset (&cw) == sizeof (GumGraftedImportTrampoline));

      entry->slot_offset = import->slot_offset;
      entry->trampoline_offset = trampoline_addr - layout->text_address;
      entry->flags =
          sizeof (GumGraftedImportTrampoline)                     << 24 |
          G_STRUCT_OFFSET (GumGraftedImportTrampoline, on_enter)  << 17 |
          G_STRUCT_OFFSET (GumGraftedImportTrampoline, on_leave)  << 10 |
          0x0;
    }

    gum_arm64_writer_reset (&cw, import_trampolines + descriptor->num_imports);

    cw.pc = do_begin_invocation_addr;
    if (!gum_arm64_writer_put_ldr_reg_u64_ptr (&cw,
        ARM64_REG_X16, begin_invocation_addr))
    {
      goto ldr_error;
    }
    gum_arm64_writer_put_br_reg (&cw, ARM64_REG_X16);

    g_assert (cw.pc == do_end_invocation_addr);
    if (!gum_arm64_writer_put_ldr_reg_u64_ptr (&cw,
        ARM64_REG_X16, end_invocation_addr))
    {
      goto ldr_error;
    }
    gum_arm64_writer_put_br_reg (&cw, ARM64_REG_X16);
  }

  success = TRUE;
  goto beach;

ldr_error:
  g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
      "LDR target too far away; please file a bug");

beach:
  gum_arm64_writer_clear (&cw);

  return success;
}

static GByteArray *
gum_merge_lazy_binds_into_binds (const GumDyldInfoCommand * ic,
                                 gconstpointer linkedit)
{
  GByteArray * binds;
  guint8 terminator;

  binds = g_byte_array_sized_new (ic->bind_size + ic->lazy_bind_size);

  g_byte_array_append (binds, (const guint8 *) linkedit + ic->bind_off,
      ic->bind_size);

  while (binds->len > 0 && (binds->data[binds->len - 1] & GUM_BIND_OPCODE_MASK)
      == GUM_BIND_OPCODE_DONE)
  {
    g_byte_array_set_size (binds, binds->len - 1);
  }

  if (ic->lazy_bind_size != 0)
  {
    GumBindState state;
    const guint8 * start, * end, * p;
    const gsize pointer_size = sizeof (guint64);

    gum_replay_bind_state_transitions (binds->data, binds->data + binds->len,
        &state);

    start = (const guint8 *) linkedit + ic->lazy_bind_off;
    end = start + ic->lazy_bind_size;
    p = start;

    if (state.addend != 0)
    {
      guint8 reset_state[GUM_BIND_STATE_RESET_SIZE] = {
        GUM_BIND_OPCODE_SET_ADDEND_SLEB,
        0
      };

      /*
       * Prevent some of the previous state from bleeding into the converted
       * lazy bindings, which state must be treated as a different "context".
       */
      g_byte_array_append (binds, reset_state, sizeof (reset_state));

      state.addend = 0;
    }

    while (p != end)
    {
      const guint8 * opcode_start;
      guint8 opcode, immediate;
      gboolean keep;
      GumDarwinBindOrdinal new_library_ordinal;
      gint64 new_addend;
      guint new_segment_index;
      guint64 new_offset;

      opcode_start = p;

      opcode = *p & GUM_BIND_OPCODE_MASK;
      immediate = *p & GUM_BIND_IMMEDIATE_MASK;
      p++;

      keep = FALSE;
      switch (opcode)
      {
        case GUM_BIND_OPCODE_DONE:
          break;
        case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
          switch (opcode)
          {
            case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
              new_library_ordinal = immediate;
              break;
            case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
              new_library_ordinal = gum_read_uleb128 (&p, end);
              break;
            case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
              if (immediate == 0)
              {
                new_library_ordinal = 0;
              }
              else
              {
                gint8 value = GUM_BIND_OPCODE_MASK | immediate;
                new_library_ordinal = value;
              }
              break;
            default:
              g_assert_not_reached ();
          }

          if (new_library_ordinal != state.library_ordinal)
          {
            state.library_ordinal = new_library_ordinal;
            keep = TRUE;
          }

          break;
        case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
          while (*p != '\0')
            p++;
          p++;
          keep = TRUE;
          break;
        case GUM_BIND_OPCODE_SET_TYPE_IMM:
          if (immediate != state.type)
          {
            state.type = immediate;
            keep = TRUE;
          }
          break;
        case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
          new_addend = gum_read_sleb128 (&p, end);
          if (new_addend != state.addend)
          {
            state.addend = new_addend;
            keep = TRUE;
          }
          break;
        case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
          new_segment_index = immediate;
          new_offset = gum_read_uleb128 (&p, end);
          if (new_segment_index != state.segment_index ||
              new_offset != state.offset)
          {
            state.segment_index = new_segment_index;
            state.offset = new_offset;
            keep = TRUE;
          }
          break;
        case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
          new_offset = state.offset + gum_read_uleb128 (&p, end);
          if (new_offset != state.offset)
          {
            state.offset = new_offset;
            keep = TRUE;
          }
          break;
        case GUM_BIND_OPCODE_DO_BIND:
          state.offset += pointer_size;
          keep = TRUE;
          break;
        case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        default:
          goto malformed_lazy_bind;
      }

      if (keep)
        g_byte_array_append (binds, opcode_start, p - opcode_start);
    }
  }

malformed_lazy_bind:
  terminator = GUM_BIND_OPCODE_DONE;
  g_byte_array_append (binds, &terminator, sizeof (terminator));

  return binds;
}

static void
gum_replay_bind_state_transitions (const guint8 * start,
                                   const guint8 * end,
                                   GumBindState * state)
{
  const gsize pointer_size = sizeof (guint64);
  const guint8 * p;
  gboolean done;

  p = start;
  done = FALSE;

  state->segment_index = 0;
  state->offset = 0;
  state->type = 0;
  state->library_ordinal = 0;
  state->addend = 0;
  state->threaded_table_size = 0;

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
        state->library_ordinal = immediate;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        state->library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          state->library_ordinal = 0;
        }
        else
        {
          gint8 value = GUM_BIND_OPCODE_MASK | immediate;
          state->library_ordinal = value;
        }
        break;
      case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        while (*p != '\0')
          p++;
        p++;
        break;
      case GUM_BIND_OPCODE_SET_TYPE_IMM:
        state->type = immediate;
        break;
      case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
        state->addend = gum_read_sleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        state->segment_index = immediate;
        state->offset = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
        state->offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND:
        state->offset += pointer_size;
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        state->offset += pointer_size + gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        state->offset += pointer_size + (immediate * pointer_size);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        guint64 count, skip;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        state->offset += count * (pointer_size + skip);

        break;
      }
      case GUM_BIND_OPCODE_THREADED:
      {
        switch (immediate)
        {
          case GUM_BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
            state->type = GUM_DARWIN_BIND_THREADED_TABLE;
            state->threaded_table_size = gum_read_uleb128 (&p, end);
            break;
          case GUM_BIND_SUBOPCODE_THREADED_APPLY:
            state->type = GUM_DARWIN_BIND_THREADED_ITEMS;
            break;
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

#endif

void
_gum_grafted_hook_activate (GumGraftedHook * self)
{
  self->flags |= 1;
}

void
_gum_grafted_hook_deactivate (GumGraftedHook * self)
{
  self->flags &= ~1;
}
```