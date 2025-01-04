Response:
The user wants a summary of the functionality of the provided C code snippet from `gumdarwinmapper.c`. This is the third part of a three-part request. The request also asks for connections to reverse engineering, low-level details (Linux, Android kernel/framework), logical reasoning (with examples), common user errors, and debugging.

Here's a plan:

1. **Identify Core Functionality:** Scan the code for function definitions and their purposes. Focus on what these functions do in the context of dynamic instrumentation.
2. **Reverse Engineering Connections:** Look for functions that manipulate code, memory, or program execution flow, which are central to reverse engineering.
3. **Low-Level Details:**  Identify interactions with OS-specific concepts, especially related to Darwin (macOS/iOS), and consider how they might relate to Linux or Android (though direct connections might be less prevalent in this specific Darwin-focused file).
4. **Logical Reasoning:** Find examples of conditional execution and data manipulation that involve assumptions and generate specific outputs based on inputs.
5. **User/Programming Errors:** Think about how incorrect usage of the Frida API or misunderstandings of the underlying platform could lead to errors related to these functions.
6. **User Operations/Debugging:** Trace back how a user interacting with Frida might trigger the execution of these functions. Consider the instrumentation workflow.
7. **Synthesize Summary:** Combine the identified functionalities into a concise overview, given this is the final part of the multi-part request.

**Pre-computation/Analysis of the Code:**

* **Code Emission (ARM64):** Functions like `gum_emit_arm64_init_calls`, `gum_emit_arm64_term_calls`, and `gum_emit_arm64_tlv_init_code` are clearly involved in generating ARM64 assembly instructions. This relates to the "dynamic" aspect of dynamic instrumentation.
* **Chained Fixups and Binding:** Functions with "chained_fixups" and "bind" in their names (`gum_accumulate_chained_fixups_size`, `gum_darwin_mapper_resolve_chained_imports`, `gum_darwin_mapper_bind`, etc.) deal with resolving and applying fixups and bindings, which are crucial for loading and linking dynamic libraries.
* **Symbol Resolution:** Functions like `gum_darwin_mapper_resolve_import` and `gum_darwin_mapper_resolve_symbol` are responsible for finding the addresses of symbols (functions, variables) in loaded modules.
* **Memory Management:** `gum_darwin_mapper_data_from_offset` handles accessing data within the mapped module.
* **Dependency Management:** Functions like `gum_darwin_mapper_get_dependency_by_ordinal` and `gum_darwin_mapper_get_dependency_by_name` manage the dependencies between loaded modules.
* **Footprint Calculation:** Functions with "accumulate_footprint_size" determine the memory required for Frida's instrumentation.
* **Rebasing:** `gum_darwin_mapper_rebase` deals with adjusting addresses when a library is loaded at a different address than its preferred base.
* **Thread Local Storage (TLS):**  The `gum_emit_arm64_tlv_init_code` function interacts with thread-local variables.

Now, let's structure the response according to the user's requirements.
这是 `gumdarwinmapper.c` 文件的第三部分，主要延续了前两部分的功能，继续负责在 Darwin (macOS, iOS 等) 系统上对二进制文件进行动态映射和修改，以便进行 Frida 的插桩。

**归纳一下它的功能:**

这部分代码主要集中在以下几个方面：

1. **代码生成 (Code Emission):**  生成用于在目标进程中执行的 ARM64 代码片段，例如：
    * `gum_emit_arm64_init_calls`:  生成调用初始化函数的代码。
    * `gum_emit_arm64_term_calls`: 生成调用终止函数的代码。
    * `gum_emit_arm64_tlv_init_code`: 生成初始化线程局部变量 (Thread Local Variable, TLV) 的代码。
2. **大小计算 (Footprint Calculation):**  计算插桩所需的额外内存空间，用于存储 Frida 生成的代码和数据，包括：
    * 各种类型的绑定修正 (bind fixups)。
    * 初始化和终止函数调用。
    * 链接修复 (chained fixups)。
3. **数据访问 (Data Access):** 提供从模块文件中特定偏移量读取数据的函数 `gum_darwin_mapper_data_from_offset`。
4. **依赖管理 (Dependency Management):**  管理模块之间的依赖关系，包括通过序号 (`gum_darwin_mapper_get_dependency_by_ordinal`) 和名称 (`gum_darwin_mapper_get_dependency_by_name`) 获取依赖模块的信息。
5. **符号解析 (Symbol Resolution):**  解析模块中的符号 (函数、变量)，找到它们的地址，用于后续的绑定和代码生成，包括处理重导出符号。
6. **链接修复处理 (Chained Imports):** 处理 Mach-O 文件中的链接修复信息 (chained fixups)，解析需要导入的符号并将其地址存储起来。
7. **重定位处理 (Rebasing):** 处理模块加载时的重定位信息，根据加载地址的偏移量调整内存中的指针。
8. **绑定处理 (Binding):** 处理模块的绑定信息，将导入的符号地址写入到相应的内存位置，包括处理普通绑定、线程局部存储绑定。
9. **线程局部变量处理 (Thread Local Variables):**  查找和处理与线程局部变量相关的 `__dyld4` section 信息。

**与逆向的方法的关系，并举例说明:**

这部分代码是 Frida 动态插桩的核心，与逆向分析紧密相关。通过理解和操作目标进程的内存、代码和符号，可以实现各种逆向分析目标。

* **动态代码注入和执行:** `gum_emit_arm64_init_calls` 和 `gum_emit_arm64_term_calls` 生成的代码会在目标进程启动和退出时执行，这允许逆向工程师在这些关键时刻插入自己的代码，例如记录日志、修改行为等。
    * **举例:** 逆向工程师可以使用 Frida 脚本来 hook 一个应用程序的 `viewDidLoad` 方法 (iOS) 或 `onCreate` 方法 (Android)，并在这些方法执行之前或之后插入自己的代码，以分析应用程序的初始化流程或修改某些配置。
* **动态符号解析和替换:**  `gum_darwin_mapper_resolve_import` 和 `gum_darwin_mapper_bind` 使得 Frida 能够找到目标进程中函数的地址，并可以将其替换为自定义的函数。
    * **举例:** 逆向工程师可以 hook `NSString` 的 `stringWithString:` 方法，并替换其实现，从而监控或修改应用程序中创建的所有字符串。
* **理解程序加载和链接过程:** 通过分析处理重定位 (`gum_darwin_mapper_rebase`) 和绑定 (`gum_darwin_mapper_bind`) 的代码，逆向工程师可以更深入地理解 Mach-O 文件的加载和动态链接过程，这对于理解代码的执行流程和依赖关系至关重要。

**涉及到的二进制底层，linux, android内核及框架的知识，并举例说明:**

* **二进制底层知识:**
    * **Mach-O 文件格式:**  代码处理了 Mach-O 文件的各个 section (如 `__DATA_CONST`, `__LINKEDIT`)，以及 rebase 和 bind 信息，这些都是 Mach-O 文件格式的关键组成部分。
    * **ARM64 汇编:**  `gum_emit_arm64_*` 系列函数直接生成 ARM64 汇编指令，需要对 ARM64 指令集有深入的了解。
    * **动态链接器 (dyld):** 代码中涉及到与动态链接器相关的概念，如绑定、重定位、线程局部变量等。
* **Linux 内核知识 (间接相关):** 虽然这份代码是针对 Darwin 的，但动态链接、符号解析等概念在 Linux 中也有对应的实现 (例如使用 ELF 文件格式和 `ld-linux.so`)。理解 Darwin 的实现有助于理解这些通用概念在不同操作系统上的变体。
* **Android 内核及框架知识 (间接相关):** 类似地，Android 系统也有其动态链接机制 (使用 ELF 文件格式和 `linker`)。Frida 在 Android 上的实现也会涉及到类似的操作，尽管具体的代码实现会有所不同。这部分 Darwin 代码可以作为理解动态 instrumentation 原理的基础。
* **线程局部变量 (TLS):** `gum_emit_arm64_tlv_init_code` 涉及到了线程局部变量的初始化，这是操作系统提供的一种机制，允许每个线程拥有自己的变量副本。

**做了逻辑推理，并给出假设输入与输出:**

* **`gum_darwin_mapper_get_dependency_by_ordinal`:**
    * **假设输入:** `self` 指向一个 `GumDarwinMapper` 结构体，`ordinal` 为一个正整数 (例如 1)，`error` 为一个 `GError**` 指针。
    * **逻辑推理:** 函数会根据 `ordinal` 的值在 `self->dependencies` 数组中查找对应的依赖模块。如果 `ordinal` 为 1，则返回数组的第一个元素。
    * **假设输出:** 如果找到了对应的依赖模块，则返回指向 `GumDarwinMapping` 结构体的指针；如果 `ordinal` 超出范围，则设置 `error` 并返回 `NULL`。
* **`gum_darwin_mapper_resolve_import`:**
    * **假设输入:** `self` 指向一个 `GumDarwinMapper` 结构体，`library_ordinal` 为一个依赖库的序号，`symbol_name` 为需要解析的符号名称 (例如 "_malloc")，`is_weak` 为 FALSE，`value` 指向一个 `GumDarwinSymbolValue` 结构体，`error` 为一个 `GError**` 指针。
    * **逻辑推理:** 函数会根据 `library_ordinal` 找到对应的依赖模块，然后在该模块中查找名为 `symbol_name` 的符号的地址。
    * **假设输出:** 如果找到了符号，则将符号的地址存储在 `value->address` 中，并返回 `TRUE`；如果找不到符号，则设置 `error` 并返回 `FALSE`。

**涉及用户或者编程常见的使用错误，并举例说明:**

这部分代码是 Frida 内部实现，用户通常不会直接操作这些函数，但一些用户操作或编程错误可能会导致相关代码被执行，并可能产生错误。

* **错误的模块或符号名称:** 如果 Frida 脚本中指定的模块或符号名称不正确，那么在符号解析阶段 (`gum_darwin_mapper_resolve_import`) 可能会失败，导致插桩失败。
    * **举例:**  用户尝试 hook 一个名为 "MyLib" 的库中的 "myFunction" 函数，但实际库的名称是 "mylib.dylib" 或者符号名是 "_myFunction"，则会导致符号解析失败。
* **尝试 hook 不存在的符号:**  如果用户尝试 hook 一个目标进程中不存在的符号，也会导致符号解析失败。
* **依赖关系错误:**  如果一个模块的依赖关系没有正确加载或解析，可能会导致在绑定阶段无法找到所需的符号。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户使用 Python 或 JavaScript 编写 Frida 脚本，指定要 hook 的函数、要修改的内存等。
2. **用户运行 Frida:** 用户通过 Frida CLI 工具 (如 `frida`, `frida-trace`) 或 Frida API 将脚本注入到目标进程。
3. **Frida 加载和初始化:** Frida Agent 被加载到目标进程中，并进行初始化。这会涉及到 `gumdarwinmapper.c` 中与模块加载和映射相关的代码。
4. **Frida 解析目标模块:** 当用户指定要 hook 某个模块的函数时，Frida 会使用 `gum_darwin_mapper_get_dependency_by_name` 等函数查找并加载目标模块的信息。
5. **Frida 解析符号:** 使用 `gum_darwin_mapper_resolve_import` 和 `gum_darwin_mapper_resolve_symbol` 函数查找目标函数或变量的地址。
6. **Frida 生成插桩代码:**  根据用户的 hook 操作，Frida 会使用 `gum_emit_arm64_*` 系列函数生成 ARM64 汇编代码，用于在目标函数执行前后执行用户的自定义代码。
7. **Frida 应用插桩:**  Frida 将生成的代码注入到目标进程的内存中，并修改目标函数的指令，使其跳转到 Frida 注入的代码。
8. **目标代码执行:** 当目标进程执行到被 hook 的函数时，会先执行 Frida 注入的代码，然后可以选择执行原始函数或跳过。

**调试线索:**

如果在 Frida 插桩过程中遇到问题，例如无法 hook 到指定的函数，可以从以下几个方面进行调试，这些都与 `gumdarwinmapper.c` 的功能相关：

* **检查模块名称是否正确:**  确认 Frida 脚本中使用的模块名称与目标进程中加载的模块名称完全一致。
* **检查符号名称是否正确:** 确认 Frida 脚本中使用的符号名称 (包括前导下划线) 与目标模块中的符号名称一致。可以使用 `frida-ps -U` 或 `frida <process_name>` 并查看模块导出符号来确认。
* **查看 Frida 的日志输出:**  Frida 提供了详细的日志输出，可以查看在模块加载、符号解析等阶段是否出现错误。
* **使用 Frida 的 `Module.enumerateExports()` 方法:**  在 Frida 脚本中可以使用 `Module.enumerateExports()` 来列出指定模块的所有导出符号，帮助确认符号是否存在以及名称是否正确。
* **分析目标进程的内存布局:**  使用 Frida 的 `Process.enumerateModules()` 和 `Module.getBaseAddress()` 可以查看目标进程的内存布局，帮助理解模块的加载地址。

总而言之，`gumdarwinmapper.c` 的这部分代码是 Frida 在 Darwin 系统上实现动态插桩的关键组成部分，它负责理解和操作目标进程的二进制结构，以便在运行时修改其行为。理解这部分代码的功能有助于深入理解 Frida 的工作原理，并能更好地进行逆向分析和调试。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumdarwinmapper.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
lr_reg_no_auth (aw, ARM64_REG_X5);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19, 4);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X20, next_label);

  return TRUE;
}

static gboolean
gum_emit_arm64_term_calls (const GumDarwinTermPointersDetails * details,
                           GumEmitArm64Context * ctx)
{
  GumArm64Writer * aw = ctx->aw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, details->address +
      ((details->count - 1) * 8));
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X20, details->count);

  gum_arm64_writer_put_label (aw, next_label);

  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_X0,
      ARM64_REG_X19, 0);
  gum_arm64_writer_put_blr_reg_no_auth (aw, ARM64_REG_X0);

  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19, 8);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X20, next_label);

  return TRUE;
}

static void
gum_emit_arm64_tlv_init_code (GumEmitArm64Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumDarwinModule * module = self->module;
  gsize pointer_size = module->pointer_size;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  GumAddress tlv_section = module->base_address + tlv->descriptors_offset;
  GumArm64Writer * aw = ctx->aw;
  gconstpointer next_label = GSIZE_TO_POINTER (aw->code + 1);
  gconstpointer has_key_label = GSIZE_TO_POINTER (aw->code + 2);

  gum_arm64_writer_put_call_address_with_arguments (aw,
      self->pthread_key_create, 2,
      GUM_ARG_ADDRESS, self->pthread_key,
      GUM_ARG_ADDRESS, GUM_ADDRESS (0) /* destructor */);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, self->pthread_key);
  gum_arm64_writer_put_ldr_reg_reg (aw, ARM64_REG_X19, ARM64_REG_X19);
  gum_arm64_writer_put_lsl_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19,
      (pointer_size == 8) ? 3 : 2);
  gum_arm64_writer_put_mrs (aw, ARM64_REG_X20, GUM_ARM64_SYSREG_TPIDRRO_EL0);
  gum_arm64_writer_put_and_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20,
      (guint64) -8);
  gum_arm64_writer_put_add_reg_reg_reg (aw, ARM64_REG_X19, ARM64_REG_X19,
      ARM64_REG_X20);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X20, self->tlv_area);
  gum_arm64_writer_put_str_reg_reg (aw, ARM64_REG_X20, ARM64_REG_X19);

  gum_arm64_writer_put_ldr_reg_u64 (aw, ARM64_REG_X20, tlv_section);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X21,
      tlv->num_descriptors);

  gum_arm64_writer_put_label (aw, next_label);

  gum_arm64_writer_put_ldr_reg_u64 (aw, ARM64_REG_X19,
      gum_strip_code_address (self->tlv_get_addr_addr));
  gum_arm64_writer_put_str_reg_reg (aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20,
      pointer_size);

  gum_arm64_writer_put_ldr_reg_reg (aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X19, has_key_label);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, self->pthread_key);
  gum_arm64_writer_put_ldr_reg_reg (aw, ARM64_REG_X19, ARM64_REG_X19);
  gum_arm64_writer_put_str_reg_reg (aw, ARM64_REG_X19, ARM64_REG_X20);

  gum_arm64_writer_put_label (aw, has_key_label);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20,
      2 * pointer_size);

  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X21, ARM64_REG_X21, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X21, next_label);
}

#endif

static gboolean
gum_accumulate_chained_fixups_size (
    const GumDarwinChainedFixupsDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;
  gsize pointer_size = self->module->pointer_size;
  const GumChainedFixupsHeader * fixups_header;

  fixups_header = gum_darwin_mapper_data_from_offset (self,
      details->file_offset, pointer_size);
  if (fixups_header == NULL)
    return TRUE;

  ctx->chained_fixups_count++;
  ctx->chained_imports_count += fixups_header->imports_count;

  ctx->total += GUM_MAPPER_CHAINED_FIXUP_CALL_SIZE;

  return TRUE;
}

static gboolean
gum_accumulate_bind_footprint_size (const GumDarwinBindDetails * details,
                                    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  switch (details->type)
  {
    case GUM_DARWIN_BIND_POINTER:
      gum_accumulate_bind_pointer_footprint_size (ctx, details);
      break;
    case GUM_DARWIN_BIND_THREADED_TABLE:
      gum_accumulate_bind_threaded_table_footprint_size (ctx, details);
      break;
    case GUM_DARWIN_BIND_THREADED_ITEMS:
      gum_accumulate_bind_threaded_items_footprint_size (ctx, details);
      break;
    default:
      break;
  }

  return TRUE;
}

static void
gum_accumulate_bind_pointer_footprint_size (
    GumAccumulateFootprintContext * ctx,
    const GumDarwinBindDetails * details)
{
  GumDarwinMapper * self = ctx->mapper;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return;

  if (gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value))
  {
    if (value.resolver != 0)
      ctx->total += GUM_MAPPER_RESOLVER_SIZE;
  }
}

static void
gum_accumulate_bind_threaded_table_footprint_size (
    GumAccumulateFootprintContext * ctx,
    const GumDarwinBindDetails * details)
{
#if defined (HAVE_ARM) || defined (HAVE_ARM64)
  ctx->total += sizeof (gum_threaded_bind_processor_code);
  ctx->total += details->threaded_table_size * sizeof (GumAddress);
#endif
}

static void
gum_accumulate_bind_threaded_items_footprint_size (
    GumAccumulateFootprintContext * ctx,
    const GumDarwinBindDetails * details)
{
  ctx->threaded_regions_count++;

  ctx->total += sizeof (GumAddress);
}

static gboolean
gum_accumulate_init_pointers_footprint_size (
    const GumDarwinInitPointersDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  ctx->total += GUM_MAPPER_INIT_SIZE;

  return TRUE;
}

static gboolean
gum_accumulate_init_offsets_footprint_size (
    const GumDarwinInitOffsetsDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  ctx->total += GUM_MAPPER_INIT_SIZE;

  return TRUE;
}

static gboolean
gum_accumulate_term_footprint_size (
    const GumDarwinTermPointersDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  ctx->total += GUM_MAPPER_TERM_SIZE;

  return TRUE;
}

static gpointer
gum_darwin_mapper_data_from_offset (GumDarwinMapper * self,
                                    guint64 offset,
                                    guint size)
{
  GumDarwinModuleImage * image = self->image;
  guint64 source_offset = image->source_offset;

  if (source_offset != 0)
  {
    if (offset < source_offset)
      return NULL;
    if (offset + size > source_offset + image->shared_offset +
        image->shared_size)
      return NULL;
  }
  else
  {
    if (offset + size > image->size)
      return NULL;
  }

  return image->data + (offset - source_offset);
}

static GumDarwinMapping *
gum_darwin_mapper_get_dependency_by_ordinal (GumDarwinMapper * self,
                                             gint ordinal,
                                             GError ** error)
{
  GumDarwinMapping * result;

  switch (ordinal)
  {
    case GUM_DARWIN_BIND_SELF:
      result = gum_darwin_mapper_get_dependency_by_name (self,
          self->module->name, error);
      break;
    case GUM_DARWIN_BIND_MAIN_EXECUTABLE:
    case GUM_DARWIN_BIND_FLAT_LOOKUP:
    case GUM_DARWIN_BIND_WEAK_LOOKUP:
      goto invalid_ordinal;
    default:
    {
      gint i = ordinal - 1;

      if (i >= 0 && i < self->dependencies->len)
        result = g_ptr_array_index (self->dependencies, i);
      else
        goto invalid_ordinal;

      break;
    }
  }

  return result;

invalid_ordinal:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed dependency ordinal");
    return NULL;
  }
}

static GumDarwinMapping *
gum_darwin_mapper_get_dependency_by_name (GumDarwinMapper * self,
                                          const gchar * name,
                                          GError ** error)
{
  GumDarwinModuleResolver * resolver = self->resolver;
  GumDarwinMapping * mapping;

  if (self->parent != NULL)
    return gum_darwin_mapper_get_dependency_by_name (self->parent, name, error);

  mapping = g_hash_table_lookup (self->mappings, name);

  if (mapping == NULL)
  {
    GumDarwinModule * module =
        gum_darwin_module_resolver_find_module (resolver, name);
    if (module != NULL)
      mapping = gum_darwin_mapper_add_existing_mapping (self, module);
  }

  if (mapping == NULL)
  {
    gchar * full_name;
    GumDarwinMapper * mapper;

    if (resolver->sysroot != NULL)
      full_name = g_strconcat (resolver->sysroot, name, NULL);
    else
      full_name = g_strdup (name);

    mapper = gum_darwin_mapper_new_from_file_with_parent (self, full_name,
        self->resolver, error);
    if (mapper != NULL)
    {
      mapping = g_hash_table_lookup (self->mappings, full_name);
      g_assert (mapping != NULL);

      if (resolver->sysroot != NULL)
        gum_darwin_mapper_add_alias_mapping (self, name, mapping);
    }

    g_free (full_name);
  }

  return mapping;
}

static gboolean
gum_darwin_mapper_resolve_import (GumDarwinMapper * self,
                                  gint library_ordinal,
                                  const gchar * symbol_name,
                                  gboolean is_weak,
                                  GumDarwinSymbolValue * value,
                                  GError ** error)
{
  gboolean success;
  GumDarwinMapping * dependency;

  if (library_ordinal == GUM_DARWIN_BIND_FLAT_LOOKUP)
  {
    dependency = NULL;

    value->address = gum_strip_code_address (
        gum_darwin_module_resolver_find_dynamic_address (self->resolver,
          gum_symbol_name_from_darwin (symbol_name)));
    value->resolver = 0;

    success = value->address != 0;
  }
  else
  {
    dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
        library_ordinal, error);
    if (dependency == NULL)
      goto module_not_found;

    success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
        symbol_name, value);
    if (!success && !is_weak && self->resolver->sysroot != NULL &&
        g_str_has_suffix (symbol_name, "$INODE64"))
    {
      gchar * plain_name;

      plain_name = g_strndup (symbol_name, strlen (symbol_name) - 8);
      success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
          plain_name, value);
      g_free (plain_name);
    }
  }

  if (!success && !is_weak)
    goto symbol_not_found;

  return TRUE;

module_not_found:
  {
    return FALSE;
  }
symbol_not_found:
  {
    if (dependency != NULL)
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
          "Unable to bind, “%s” not found in “%s”",
          gum_symbol_name_from_darwin (symbol_name),
          dependency->module->name);
    }
    else
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
          "Unable to bind, “%s” cannot be resolved through flat lookup",
          gum_symbol_name_from_darwin (symbol_name));
    }
    return FALSE;
  }
}

static gboolean
gum_darwin_mapper_resolve_symbol (GumDarwinMapper * self,
                                  GumDarwinModule * module,
                                  const gchar * name,
                                  GumDarwinSymbolValue * value)
{
  GumDarwinExportDetails details;

  if (self->parent != NULL)
  {
    return gum_darwin_mapper_resolve_symbol (self->parent, module, name, value);
  }

  if (strcmp (name, "_atexit") == 0 ||
      strcmp (name, "_atexit_b") == 0 ||
      strcmp (name, "___cxa_atexit") == 0 ||
      strcmp (name, "___cxa_thread_atexit") == 0 ||
      strcmp (name, "__tlv_atexit") == 0)
  {
    /*
     * We pretend we install the handler by resolving to a dummy function that
     * does nothing. Memory for handlers isn't released, so we shouldn't let
     * our libraries register them. In our case atexit is only for debugging
     * purposes anyway (GLib installs a handler to print statistics when
     * debugging is enabled).
     */
    if (self->runtime_address != 0)
    {
      value->address = self->runtime_address + self->runtime_header_size;
      if (self->module->cpu_type == GUM_CPU_ARM)
        value->address |= 1;
    }
    else
    {
      /* Resolving before mapped; we will handle it later. */
      value->address = 0xdeadbeef;
    }
    value->resolver = 0;
    return TRUE;
  }

  if (GUM_MEMORY_RANGE_INCLUDES (&self->shared_cache_range,
        module->base_address))
  {
    const gchar * unmangled_name = name + 1;

    value->address = gum_module_find_export_by_name (module->name, unmangled_name);
#ifdef HAVE_ARM64
    if (value->address != 0)
    {
      /*
       * XXX: Symbols with a resolver, such as strcmp() on macOS Sequoia, have
       *      an invalid signature. Asking the CPU to strip the ptrauth bits
       *      in such a case thus results in more junk being added.
       */
      if (value->address >> 47 == 0x100)
        value->address &= 0x7fffffffffffff;
      else
        value->address = gum_strip_code_address (value->address);
    }
#endif
    value->resolver = 0;

    if (value->address != 0)
      return TRUE;
  }

  if (!gum_darwin_module_resolve_export (module, name, &details))
  {
    if (gum_darwin_module_get_lacks_exports_for_reexports (module))
    {
      GPtrArray * reexports = module->reexports;
      guint i;

      for (i = 0; i != reexports->len; i++)
      {
        GumDarwinMapping * target;

        target = gum_darwin_mapper_get_dependency_by_name (self,
            g_ptr_array_index (reexports, i), NULL);
        if (target == NULL)
          continue;

        if (gum_darwin_mapper_resolve_symbol (self, target->module, name,
            value))
        {
          return TRUE;
        }
      }
    }

    return FALSE;
  }

  if ((details.flags & GUM_DARWIN_EXPORT_REEXPORT) != 0)
  {
    const gchar * target_name;
    GumDarwinMapping * target;

    target_name = gum_darwin_module_get_dependency_by_ordinal (module,
        details.reexport_library_ordinal);

    target = gum_darwin_mapper_get_dependency_by_name (self, target_name, NULL);
    if (target == NULL)
      return FALSE;

    return gum_darwin_mapper_resolve_symbol (self, target->module,
        details.reexport_symbol, value);
  }

  switch (details.flags & GUM_DARWIN_EXPORT_KIND_MASK)
  {
    case GUM_DARWIN_EXPORT_REGULAR:
      if ((details.flags & GUM_DARWIN_EXPORT_STUB_AND_RESOLVER) != 0)
      {
        /* XXX: we ignore interposing */
        value->address = module->base_address + details.stub;
        value->resolver = module->base_address + details.resolver;
        return TRUE;
      }
      value->address = module->base_address + details.offset;
      value->resolver = 0;
      return TRUE;
    case GUM_DARWIN_EXPORT_THREAD_LOCAL:
      value->address = module->base_address + details.offset;
      value->resolver = 0;
      return TRUE;
    case GUM_DARWIN_EXPORT_ABSOLUTE:
      value->address = details.offset;
      value->resolver = 0;
      return TRUE;
    default:
      return FALSE;
  }
}

static GumDarwinMapping *
gum_darwin_mapper_add_existing_mapping (GumDarwinMapper * self,
                                        GumDarwinModule * module)
{
  GumDarwinMapping * mapping;

  mapping = g_slice_new (GumDarwinMapping);
  mapping->module = g_object_ref (module);
  mapping->mapper = NULL;

  g_hash_table_insert (self->mappings, g_strdup (module->name), mapping);

  return mapping;
}

static GumDarwinMapping *
gum_darwin_mapper_add_pending_mapping (GumDarwinMapper * self,
                                       const gchar * name,
                                       GumDarwinMapper * mapper)
{
  GumDarwinMapping * mapping;

  mapping = g_slice_new (GumDarwinMapping);
  mapping->module = g_object_ref (mapper->module);
  mapping->mapper = mapper;

  g_hash_table_insert (self->mappings, g_strdup (name), mapping);

  return mapping;
}

static GumDarwinMapping *
gum_darwin_mapper_add_alias_mapping (GumDarwinMapper * self,
                                     const gchar * name,
                                     const GumDarwinMapping * to)
{
  GumDarwinMapping * mapping;

  mapping = g_slice_dup (GumDarwinMapping, to);
  g_object_ref (mapping->module);

  g_hash_table_insert (self->mappings, g_strdup (name), mapping);

  return mapping;
}

static gboolean
gum_darwin_mapper_resolve_chained_imports (
    const GumDarwinChainedFixupsDetails * details,
    gpointer user_data)
{
  GumMapContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;
  gsize pointer_size = self->module->pointer_size;
  const GumChainedFixupsHeader * fixups_header;
  const gchar * symbols;
  uint32_t count, i;

  fixups_header = gum_darwin_mapper_data_from_offset (self,
      details->file_offset, pointer_size);
  if (fixups_header == NULL)
    goto invalid_data;

  symbols = (const gchar *) fixups_header + fixups_header->symbols_offset;
  count = fixups_header->imports_count;

  g_clear_pointer (&self->chained_symbols, g_array_unref);
  self->chained_symbols = g_array_sized_new (FALSE, FALSE, pointer_size, count);

  switch (fixups_header->imports_format)
  {
    case GUM_CHAINED_IMPORT:
    {
      const GumChainedImport * imports =
          ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != count; i++)
      {
        const GumChainedImport * import = &imports[i];
        gint library_ordinal = (gint8) import->lib_ordinal;

        if (!gum_darwin_mapper_append_chained_symbol (self, library_ordinal,
              symbols + import->name_offset, import->weak_import, 0,
              ctx->error))
        {
          goto propagate_error;
        }
      }

      break;
    }
    case GUM_CHAINED_IMPORT_ADDEND:
    {
      const GumChainedImportAddend * imports =
          ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != count; i++)
      {
        const GumChainedImportAddend * import = &imports[i];
        gint library_ordinal = (gint8) import->lib_ordinal;

        if (!gum_darwin_mapper_append_chained_symbol (self, library_ordinal,
              symbols + import->name_offset, import->weak_import,
              import->addend, ctx->error))
        {
          goto propagate_error;
        }
      }

      break;
    }
    case GUM_CHAINED_IMPORT_ADDEND64:
    {
      const GumChainedImportAddend64 * imports =
          ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != count; i++)
      {
        const GumChainedImportAddend64 * import = &imports[i];
        gint library_ordinal = (gint16) import->lib_ordinal;

        if (!gum_darwin_mapper_append_chained_symbol (self, library_ordinal,
              symbols + import->name_offset, import->weak_import,
              import->addend, ctx->error))
        {
          goto propagate_error;
        }
      }

      break;
    }
  }

  return TRUE;

invalid_data:
  {
    ctx->success = FALSE;
    g_set_error (ctx->error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed chained fixups");
    return FALSE;
  }
propagate_error:
  {
    ctx->success = FALSE;
    return FALSE;
  }
}

static gboolean
gum_darwin_mapper_append_chained_symbol (GumDarwinMapper * self,
                                         gint library_ordinal,
                                         const gchar * symbol_name,
                                         gboolean is_weak,
                                         gint64 addend,
                                         GError ** error)
{
  GumDarwinSymbolValue value;

  if (!gum_darwin_mapper_resolve_import (self, library_ordinal, symbol_name,
        is_weak, &value, error))
  {
    return FALSE;
  }

  if (value.address != 0)
    value.address += addend;

  g_array_append_val (self->chained_symbols, value.address);

  return TRUE;
}

static gboolean
gum_darwin_mapper_rebase (const GumDarwinRebaseDetails * details,
                          gpointer user_data)
{
  GumMapContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;
  gsize pointer_size = self->module->pointer_size;
  gpointer entry;

  if (details->offset >= details->segment->file_size)
    goto invalid_data;

  entry = gum_darwin_mapper_data_from_offset (self,
      details->segment->file_offset + details->offset, pointer_size);
  if (entry == NULL)
    goto invalid_data;

  switch (details->type)
  {
    case GUM_DARWIN_REBASE_POINTER:
    case GUM_DARWIN_REBASE_TEXT_ABSOLUTE32:
      if (pointer_size == 4)
        *((guint32 *) entry) += (guint32) details->slide;
      else
        *((guint64 *) entry) += (guint64) details->slide;
      break;
    case GUM_DARWIN_REBASE_TEXT_PCREL32:
    default:
      goto invalid_data;
  }

  return TRUE;

invalid_data:
  {
    ctx->success = FALSE;
    g_set_error (ctx->error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed rebase entry");
    return FALSE;
  }
}

static gboolean
gum_darwin_mapper_bind (const GumDarwinBindDetails * details,
                        gpointer user_data)
{
  GumMapContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;

  switch (details->type)
  {
    case GUM_DARWIN_BIND_POINTER:
      ctx->success = gum_darwin_mapper_bind_pointer (self, details, ctx->error);
      break;
    case GUM_DARWIN_BIND_THREADED_TABLE:
      ctx->success = gum_darwin_mapper_bind_table (self, details, ctx->error);
      break;
    case GUM_DARWIN_BIND_THREADED_ITEMS:
      ctx->success = gum_darwin_mapper_bind_items (self, details, ctx->error);
      break;
    default:
      goto invalid_data;
  }

  return ctx->success;

invalid_data:
  {
    ctx->success = FALSE;
    g_set_error (ctx->error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed bind entry");
    return FALSE;
  }
}

static gboolean
gum_darwin_mapper_bind_pointer (GumDarwinMapper * self,
                                const GumDarwinBindDetails * bind,
                                GError ** error)
{
  GumDarwinSymbolValue value;

  if (!gum_darwin_mapper_resolve_import (self, bind->library_ordinal,
        bind->symbol_name,
        (bind->symbol_flags & GUM_DARWIN_BIND_WEAK_IMPORT) != 0,
        &value, error))
  {
    return FALSE;
  }

  if (value.address != 0)
    value.address += bind->addend;

  if (self->threaded_symbols != NULL)
  {
    g_array_append_val (self->threaded_symbols, value.address);
  }
  else
  {
    gsize pointer_size = self->module->pointer_size;
    gpointer entry;

    entry = gum_darwin_mapper_data_from_offset (self,
        bind->segment->file_offset + bind->offset, pointer_size);
    if (entry == NULL)
      goto invalid_data;

    if (pointer_size == 4)
      *((guint32 *) entry) = value.address;
    else
      *((guint64 *) entry) = value.address;
  }

  return TRUE;

invalid_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed bind entry");
    return FALSE;
  }
}

static gboolean
gum_darwin_mapper_bind_table (GumDarwinMapper * self,
                              const GumDarwinBindDetails * bind,
                              GError ** error)
{
  g_clear_pointer (&self->threaded_symbols, g_array_unref);
  g_clear_pointer (&self->threaded_regions, g_array_unref);
  self->threaded_symbols = g_array_sized_new (FALSE, FALSE, sizeof (GumAddress),
      bind->threaded_table_size);
  self->threaded_regions = g_array_sized_new (FALSE, FALSE, sizeof (GumAddress),
      256);

  return TRUE;
}

static gboolean
gum_darwin_mapper_bind_items (GumDarwinMapper * self,
                              const GumDarwinBindDetails * bind,
                              GError ** error)
{
  GArray * threaded_regions = self->threaded_regions;
  GumAddress region_start;

  if (threaded_regions == NULL)
    goto invalid_data;

  region_start =
      self->module->base_address + bind->segment->vm_address + bind->offset;

  g_array_append_val (threaded_regions, region_start);

  return TRUE;

invalid_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed bind items");
    return FALSE;
  }
}

static void
gum_darwin_mapping_free (GumDarwinMapping * self)
{
  g_object_unref (self->module);
  g_slice_free (GumDarwinMapping, self);
}

static gboolean
gum_find_tlv_get_addr (const GumDarwinSectionDetails * details,
                       gpointer user_data)
{
  GumMapContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;

  if (strcmp (details->section_name, "__dyld4") != 0)
    return TRUE;

  if (self->module->pointer_size == 4)
  {
    self->tlv_get_addr_addr =
        ((GumLibdyldDyld4Section32 *) GSIZE_TO_POINTER (details->vm_address))
        ->tlv_get_addr_addr;
  }
  else
  {
    self->tlv_get_addr_addr =
        ((GumLibdyldDyld4Section64 *) GSIZE_TO_POINTER (details->vm_address))
        ->tlv_get_addr_addr;
  }

  ctx->success = TRUE;

  return FALSE;
}

#endif

"""


```