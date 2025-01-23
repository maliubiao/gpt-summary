Response:
The user wants me to analyze a C++ header file snippet from the V8 JavaScript engine.
The request is broken down into several parts, focusing on understanding the functionality of the code.

Here's a plan:
1. **Identify the main purpose of the code:**  Look for keywords and patterns that indicate the code's role. The function names like `DecodeFunctionSection`, `DecodeTableSection`, etc., strongly suggest this code is responsible for parsing and interpreting the structure of a WebAssembly module.
2. **List the functionalities:**  Go through each method and describe what it does in the context of WebAssembly module decoding.
3. **Check for Torque usage:** Examine the file extension. If it were `.tq`, it would be a Torque file. In this case, it's `.h`, so it's a regular C++ header file.
4. **Relate to JavaScript:** Explain how the decoded information is used in the JavaScript environment (though the code itself is C++).
5. **Provide code logic reasoning:** Select a method (e.g., `DecodeFunctionSection`) and explain the expected input (raw byte stream) and output (updated module data structures).
6. **Illustrate common programming errors:**  Think about potential issues when writing WebAssembly modules that this decoder might catch (e.g., exceeding limits, invalid types).
7. **Summarize the functionality (for Part 2):**  Provide a concise overview of what the code does, based on the analysis of the provided snippet.
这是V8源代码文件 `v8/src/wasm/module-decoder-impl.h` 的一部分，它负责 WebAssembly 模块的解码过程。从提供的代码片段来看，它专注于解码模块的特定部分，例如函数、表、内存、全局变量、导出项等。

以下是其功能的详细列表：

1. **解码函数段 (`DecodeFunctionSection`)**:
   - 读取函数计数。
   - 调整模块的 `functions` 向量大小以容纳导入的函数和当前声明的函数。
   - 初始化 `validated_functions` 位集，用于跟踪哪些函数已验证。
   - 如果是 asm.js 模块，则默认将所有函数标记为有效。
   - 遍历每个声明的函数，读取其签名索引，并将其与函数关联起来。

2. **解码表段 (`DecodeTableSection`)**:
   - 读取表计数。
   - 遍历每个表：
     - 检查是否存在初始化表达式。
     - 读取表的类型，并验证其是否为对象引用类型。
     - 验证表类型是否需要初始值。
     - 读取表的标志（是否共享）。
     - 读取表的大小限制（初始大小和最大大小）。
     - 如果有初始化表达式，则解码它。

3. **解码内存段 (`DecodeMemorySection`)**:
   - 读取内存计数。
   - 调整模块的 `memories` 向量大小以容纳导入的内存和当前声明的内存。
   - 遍历每个内存：
     - 读取内存的标志。
     - 读取内存的大小限制（初始页数和最大页数）。
   - 如果有多个内存，则记录 `multi_memory` 特性。
   - 更新计算后的内存信息。

4. **解码全局变量段 (`DecodeGlobalSection`)**:
   - 读取全局变量计数。
   - 为新的全局变量预留空间。
   - 遍历每个全局变量：
     - 读取全局变量的类型。
     - 读取全局变量的标志（可变性和是否共享）。
     - 解码全局变量的初始化表达式。
     - 将新的全局变量添加到模块的 `globals` 向量中。

5. **解码导出段 (`DecodeExportSection`)**:
   - 读取导出项计数。
   - 为导出项预留空间。
   - 遍历每个导出项：
     - 读取导出名称。
     - 读取导出项的类型（函数、表、内存、全局变量、标签）。
     - 根据导出类型读取相应的索引，并将其与导出的实体关联起来。
     - 检查重复的导出名称（非 asm.js 模块）。

6. **解码起始段 (`DecodeStartSection`)**:
   - 读取起始函数的索引。
   - 验证起始函数是否具有零参数和零返回值。

7. **解码元素段 (`DecodeElementSection`)**:
   - 读取元素段计数。
   - 遍历每个元素段：
     - 读取元素段的头部信息。
     - 遍历元素，验证其类型。
     - 将元素段添加到模块的 `elem_segments` 向量中。

8. **解码代码段 (`DecodeCodeSection`)**:
   - 在访问全局变量偏移量之前先进行计算。
   - 读取函数体计数。
   - 遍历每个函数体：
     - 读取函数体的大小。
     - 读取函数体的字节。
     - 调用 `DecodeFunctionBody` 处理函数体。
     - 处理指令跟踪信息。

9. **开始代码段 (`StartCodeSection`)**:
   - 检查段的顺序。
   - 在访问全局变量偏移量之前先进行计算。
   - 记录代码段的字节范围。

10. **检查函数计数 (`CheckFunctionsCount`)**:
    - 验证代码段中声明的函数体数量是否与之前声明的函数数量一致。

11. **解码函数体 (`DecodeFunctionBody`)**:
    - 记录函数体的偏移量和长度。
    - 对于小函数进行计数。

12. **检查数据段计数 (`CheckDataSegmentsCount`)**:
    - 验证数据段的数量是否与之前声明的数量一致（如果存在数据计数段）。

13. **解码数据段 (`DecodeDataSection`)**:
    - 读取数据段计数。
    - 遍历每个数据段：
      - 读取数据段的头部信息。
      - 读取数据源的大小。
      - 读取数据源的字节。
      - 将数据段信息添加到模块的 `data_segments` 向量中。

14. **解码名称段 (`DecodeNameSection`)**:
    - 解析模块名称（忽略其他名称子段）。

15. **解码源映射 URL 段 (`DecodeSourceMappingURLSection`)**:
    - 解析源映射文件的 URL。

16. **解码外部调试信息段 (`DecodeExternalDebugInfoSection`)**:
    - 解析外部调试信息文件的 URL。

17. **解码指令跟踪段 (`DecodeInstTraceSection`)**:
    - 解析指令跟踪信息，用于调试和性能分析。

18. **解码编译提示段 (`DecodeCompilationHintsSection`)**:
    - 解析编译提示信息，用于指导编译器的优化策略。

19. **解码分支提示段 (`DecodeBranchHintsSection`)**:
    - 解析分支预测提示信息，用于改进代码执行效率。

20. **解码数据计数段 (`DecodeDataCountSection`)**:
    - 读取声明的数据段数量。

21. **解码标签段 (`DecodeTagSection`)**:
    - 读取标签（异常）计数。
    - 遍历每个标签，读取其签名索引。

22. **解码字符串引用段 (`DecodeStringRefSection`)**:
    - 读取字符串字面量计数。
    - 遍历每个字符串字面量，读取其内容。

23. **检查不匹配的计数 (`CheckMismatchedCounts`)**:
    - 检查声明的函数数量与提供的函数体数量是否一致。
    - 检查声明的数据段数量与提供的数据段数量是否一致。

24. **完成解码 (`FinishDecoding`)**:
    - 如果解码成功，并且计数匹配，则进行全局变量偏移量计算等最终处理。

**关于 Torque:**

`v8/src/wasm/module-decoder-impl.h` 文件以 `.h` 结尾，**不是** v8 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系:**

虽然这段代码是 C++，但它直接关系到 JavaScript 中 WebAssembly 的功能。当 JavaScript 代码尝试加载和实例化一个 WebAssembly 模块时，V8 引擎会使用这段代码来解析 WebAssembly 字节码，并将其转换为 V8 内部可以理解和执行的数据结构。

**JavaScript 示例:**

```javascript
// 假设我们有一个 WebAssembly 模块的字节数组 wasmBytes
WebAssembly.instantiate(wasmBytes)
  .then(result => {
    // result.instance 是 WebAssembly 模块的实例
    console.log("WebAssembly 模块已成功实例化", result.instance);
    // 可以调用导出的函数
    // result.instance.exports.exported_function();
  })
  .catch(error => {
    console.error("实例化 WebAssembly 模块失败:", error);
  });
```

在这个过程中，`v8/src/wasm/module-decoder-impl.h` 中的代码会被 V8 调用，来理解 `wasmBytes` 的结构，提取函数、表、内存等信息，并验证模块的有效性。

**代码逻辑推理 (以 `DecodeFunctionSection` 为例):**

**假设输入:**

- `module_->functions.size()` 的初始值为 `module_->num_imported_functions` (假设为 2)。
- `v8_flags.max_wasm_functions` 的值为 1000。
- 输入的 WebAssembly 字节码中声明的函数数量 `functions_count` 为 3。

**输出:**

- `module_->functions.size()` 将变为 `2 + 3 = 5`。
- `module_->num_declared_functions` 将变为 `3`。
- `module_->validated_functions` 将被分配一个大小为 `(3 + 7) / 8 = 1` 的 `std::atomic<uint8_t>[]` 数组。
- 如果是 asm.js 模块，`module_->validated_functions` 的第一个字节将被填充为 `0xff`。
- `module_->functions` 向量的索引 2、3 和 4 的元素将被初始化：
    - `function->func_index` 分别为 2、3 和 4。
    - `function->sig_index` 将从字节码中读取。
    - `function->sig` 指向的函数签名将被解码。

**用户常见的编程错误示例:**

1. **函数索引超出范围:** 在导出段中引用了一个不存在的函数索引。解码器会检查并报错。
   ```c++
   // 假设模块只有 2 个函数（索引 0 和 1）
   // 字节码中尝试导出索引为 2 的函数
   errorf(kind_pos, "invalid export index %u", exp->index);
   ```

2. **表类型不正确:** 尝试创建一个非引用类型的表。解码器会检查并报错。
   ```c++
   if (!table_type.is_object_reference()) {
     error(type_position, "Only reference types can be used as table types");
     break;
   }
   ```

**功能归纳 (针对第 2 部分):**

这段代码是 WebAssembly 模块解码器实现的一部分，专注于**解析和提取模块中定义的函数、表、内存、全局变量、导出项、起始函数、元素段**等核心结构信息。它负责读取 WebAssembly 字节码中这些部分的描述，并将其转换为 V8 引擎内部表示，以便后续的验证、编译和执行。此外，它还处理了名称段、源映射 URL 段、外部调试信息段以及一些性能优化相关的提示信息段。这段代码的核心目标是理解 WebAssembly 模块的静态结构。

### 提示词
```
这是目录为v8/src/wasm/module-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
t("functions count", v8_flags.max_wasm_functions);
    DCHECK_EQ(module_->functions.size(), module_->num_imported_functions);
    uint32_t total_function_count =
        module_->num_imported_functions + functions_count;
    module_->functions.resize(total_function_count);
    module_->num_declared_functions = functions_count;
    // Also initialize the {validated_functions} bitset here, now that we know
    // the number of declared functions.
    DCHECK_NULL(module_->validated_functions);
    module_->validated_functions =
        std::make_unique<std::atomic<uint8_t>[]>((functions_count + 7) / 8);
    if (is_asmjs_module(module_.get())) {
      // Mark all asm.js functions as valid by design (it's faster to do this
      // here than to check this in {WasmModule::function_was_validated}).
      std::fill_n(module_->validated_functions.get(), (functions_count + 7) / 8,
                  0xff);
    }

    for (uint32_t func_index = module_->num_imported_functions;
         func_index < total_function_count; ++func_index) {
      WasmFunction* function = &module_->functions[func_index];
      function->func_index = func_index;
      if (tracer_) tracer_->FunctionName(func_index);
      function->sig_index = consume_sig_index(module_.get(), &function->sig);
      if (!ok()) return;
    }
  }

  void DecodeTableSection() {
    static_assert(kV8MaxWasmTables <= kMaxUInt32);
    uint32_t table_count = consume_count("table count", kV8MaxWasmTables);

    for (uint32_t i = 0; ok() && i < table_count; i++) {
      if (tracer_) tracer_->TableOffset(pc_offset());
      module_->tables.emplace_back();
      WasmTable* table = &module_->tables.back();
      const uint8_t* type_position = pc();

      bool has_initializer = false;
      if (read_u8<Decoder::FullValidationTag>(
              pc(), "table-with-initializer byte") == 0x40) {
        consume_bytes(1, "with-initializer ", tracer_);
        has_initializer = true;
        type_position++;
        uint8_t reserved = consume_u8("reserved-byte", tracer_);
        if (reserved != 0) {
          error(type_position, "Reserved byte must be 0x00");
          break;
        }
        type_position++;
      }

      ValueType table_type = consume_value_type();
      if (!table_type.is_object_reference()) {
        error(type_position, "Only reference types can be used as table types");
        break;
      }
      if (!has_initializer && !table_type.is_defaultable()) {
        errorf(type_position,
               "Table of non-defaultable table %s needs initial value",
               table_type.name().c_str());
        break;
      }
      table->type = table_type;

      consume_table_flags(table);
      if (table->shared) module_->has_shared_part = true;
      // Note that we should not throw an error if the declared maximum size is
      // oob. We will instead fail when growing at runtime.
      uint64_t kNoMaximum = kMaxUInt64;
      consume_resizable_limits(
          "table", "elements", v8_flags.wasm_max_table_size,
          &table->initial_size, table->has_maximum_size, kNoMaximum,
          &table->maximum_size,
          table->is_table64() ? k64BitLimits : k32BitLimits);

      if (has_initializer) {
        table->initial_value =
            consume_init_expr(module_.get(), table_type, table->shared);
      }
    }
  }

  void DecodeMemorySection() {
    const uint8_t* mem_count_pc = pc();
    static_assert(kV8MaxWasmMemories <= kMaxUInt32);
    // Use {kV8MaxWasmMemories} here, but only allow for >1 memory if
    // multi-memory is enabled (checked below). This allows for better error
    // messages.
    uint32_t memory_count = consume_count("memory count", kV8MaxWasmMemories);
    size_t imported_memories = module_->memories.size();
    DCHECK_GE(kV8MaxWasmMemories, imported_memories);
    if (memory_count > kV8MaxWasmMemories - imported_memories) {
      errorf(mem_count_pc,
             "Exceeding maximum number of memories (%u; declared %u, "
             "imported %zu)",
             kV8MaxWasmMemories, memory_count, imported_memories);
    }
    module_->memories.resize(imported_memories + memory_count);

    for (uint32_t i = 0; ok() && i < memory_count; i++) {
      WasmMemory* memory = module_->memories.data() + imported_memories + i;
      memory->index = static_cast<uint32_t>(imported_memories + i);
      if (tracer_) tracer_->MemoryOffset(pc_offset());
      consume_memory_flags(memory);
      uint32_t max_pages =
          memory->is_memory64() ? kSpecMaxMemory64Pages : kSpecMaxMemory32Pages;
      consume_resizable_limits(
          "memory", "pages", max_pages, &memory->initial_pages,
          memory->has_maximum_pages, max_pages, &memory->maximum_pages,
          memory->is_memory64() ? k64BitLimits : k32BitLimits);
    }
    if (module_->memories.size() > 1) detected_features_->add_multi_memory();
    UpdateComputedMemoryInformation();
  }

  void UpdateComputedMemoryInformation() {
    for (WasmMemory& memory : module_->memories) {
      UpdateComputedInformation(&memory, module_->origin);
    }
  }

  void DecodeGlobalSection() {
    uint32_t globals_count = consume_count("globals count", kV8MaxWasmGlobals);
    uint32_t imported_globals = static_cast<uint32_t>(module_->globals.size());
    // It is important to not resize the globals vector from the beginning,
    // because we use its current size when decoding the initializer.
    module_->globals.reserve(imported_globals + globals_count);
    for (uint32_t i = 0; ok() && i < globals_count; ++i) {
      TRACE("DecodeGlobal[%d] module+%d\n", i, static_cast<int>(pc_ - start_));
      if (tracer_) tracer_->GlobalOffset(pc_offset());
      ValueType type = consume_value_type();
      auto [mutability, shared] = consume_global_flags();
      if (failed()) break;
      // Validation that {type} and {shared} are compatible will happen in
      // {consume_init_expr}.
      ConstantExpression init = consume_init_expr(module_.get(), type, shared);
      module_->globals.push_back(
          WasmGlobal{.type = type,
                     .mutability = mutability,
                     .init = init,
                     .index = 0,  // set later in CalculateGlobalOffsets
                     .shared = shared});
      if (shared) module_->has_shared_part = true;
    }
  }

  void DecodeExportSection() {
    uint32_t export_table_count =
        consume_count("exports count", kV8MaxWasmExports);
    module_->export_table.reserve(export_table_count);
    for (uint32_t i = 0; ok() && i < export_table_count; ++i) {
      TRACE("DecodeExportTable[%d] module+%d\n", i,
            static_cast<int>(pc_ - start_));
      if (tracer_) {
        tracer_->Description("export #");
        tracer_->Description(i);
        tracer_->NextLine();
      }

      WireBytesRef name = consume_utf8_string(this, "field name", tracer_);

      const uint8_t* kind_pos = pc();
      ImportExportKindCode kind =
          static_cast<ImportExportKindCode>(consume_u8("kind", tracer_));

      module_->export_table.push_back(WasmExport{.name = name, .kind = kind});
      WasmExport* exp = &module_->export_table.back();

      if (tracer_) {
        tracer_->Description(": ");
        tracer_->Description(ExternalKindName(exp->kind));
        tracer_->Description(" ");
      }
      switch (kind) {
        case kExternalFunction: {
          WasmFunction* func = nullptr;
          exp->index = consume_func_index(module_.get(), &func);

          if (failed()) break;
          DCHECK_NOT_NULL(func);

          module_->num_exported_functions++;
          func->exported = true;
          // Exported functions are considered "declared".
          func->declared = true;
          break;
        }
        case kExternalTable: {
          WasmTable* table = nullptr;
          exp->index = consume_table_index(module_.get(), &table);
          if (table) table->exported = true;
          break;
        }
        case kExternalMemory: {
          const uint8_t* index_pos = pc();
          exp->index = consume_u32v("memory index", tracer_);
          size_t num_memories = module_->memories.size();
          if (exp->index >= module_->memories.size()) {
            errorf(index_pos,
                   "invalid exported memory index %u (having %zu memor%s)",
                   exp->index, num_memories, num_memories == 1 ? "y" : "ies");
            break;
          }
          module_->memories[exp->index].exported = true;
          break;
        }
        case kExternalGlobal: {
          WasmGlobal* global = nullptr;
          exp->index = consume_global_index(module_.get(), &global);
          if (global) {
            global->exported = true;
          }
          break;
        }
        case kExternalTag: {
          WasmTag* tag = nullptr;
          exp->index = consume_tag_index(module_.get(), &tag);
          break;
        }
        default:
          errorf(kind_pos, "invalid export kind 0x%02x", exp->kind);
          break;
      }
      if (tracer_) tracer_->NextLine();
    }
    // Check for duplicate exports (except for asm.js).
    if (ok() && module_->origin == kWasmOrigin &&
        module_->export_table.size() > 1) {
      std::vector<WasmExport> sorted_exports(module_->export_table);

      auto cmp_less = [this](const WasmExport& a, const WasmExport& b) {
        // Return true if a < b.
        if (a.name.length() != b.name.length()) {
          return a.name.length() < b.name.length();
        }
        const uint8_t* left =
            start() + GetBufferRelativeOffset(a.name.offset());
        const uint8_t* right =
            start() + GetBufferRelativeOffset(b.name.offset());
        return memcmp(left, right, a.name.length()) < 0;
      };
      std::stable_sort(sorted_exports.begin(), sorted_exports.end(), cmp_less);

      auto it = sorted_exports.begin();
      WasmExport* last = &*it++;
      for (auto end = sorted_exports.end(); it != end; last = &*it++) {
        DCHECK(!cmp_less(*it, *last));  // Vector must be sorted.
        if (!cmp_less(*last, *it)) {
          const uint8_t* pc =
              start() + GetBufferRelativeOffset(it->name.offset());
          TruncatedUserString<> name(pc, it->name.length());
          errorf(pc, "Duplicate export name '%.*s' for %s %d and %s %d",
                 name.length(), name.start(), ExternalKindName(last->kind),
                 last->index, ExternalKindName(it->kind), it->index);
          break;
        }
      }
    }
  }

  void DecodeStartSection() {
    if (tracer_) tracer_->StartOffset(pc_offset());
    WasmFunction* func;
    const uint8_t* pos = pc_;
    module_->start_function_index = consume_func_index(module_.get(), &func);
    if (tracer_) tracer_->NextLine();
    if (func &&
        (func->sig->parameter_count() > 0 || func->sig->return_count() > 0)) {
      error(pos, "invalid start function: non-zero parameter or return count");
    }
  }

  void DecodeElementSection() {
    uint32_t segment_count =
        consume_count("segment count", v8_flags.wasm_max_table_size);

    for (uint32_t i = 0; i < segment_count; ++i) {
      if (tracer_) tracer_->ElementOffset(pc_offset());
      WasmElemSegment segment = consume_element_segment_header();
      if (tracer_) tracer_->NextLineIfNonEmpty();
      if (failed()) return;
      DCHECK_NE(segment.type, kWasmBottom);

      for (uint32_t j = 0; j < segment.element_count; j++) {
        // Just run validation on elements; do not store them anywhere. We will
        // decode them again from wire bytes as needed.
        consume_element_segment_entry(module_.get(), segment);
        if (failed()) return;
      }
      module_->elem_segments.push_back(std::move(segment));
    }
  }

  void DecodeCodeSection() {
    // Make sure global offset were calculated before they get accessed during
    // function compilation.
    CalculateGlobalOffsets(module_.get());
    uint32_t code_section_start = pc_offset();
    uint32_t functions_count = consume_u32v("functions count", tracer_);
    if (tracer_) {
      tracer_->Description(functions_count);
      tracer_->NextLine();
    }
    CheckFunctionsCount(functions_count, code_section_start);

    auto inst_traces_it = this->inst_traces_.begin();
    std::vector<std::pair<uint32_t, uint32_t>> inst_traces;

    for (uint32_t i = 0; ok() && i < functions_count; ++i) {
      int function_index = module_->num_imported_functions + i;
      if (tracer_) {
        tracer_->Description("function #");
        tracer_->FunctionName(function_index);
        tracer_->NextLine();
      }
      const uint8_t* pos = pc();
      uint32_t size = consume_u32v("body size", tracer_);
      if (tracer_) {
        tracer_->Description(size);
        tracer_->NextLine();
      }
      if (size > kV8MaxWasmFunctionSize) {
        errorf(pos, "size %u > maximum function size %zu", size,
               kV8MaxWasmFunctionSize);
        return;
      }
      uint32_t offset = pc_offset();
      consume_bytes(size, "function body");
      if (failed()) break;
      DecodeFunctionBody(function_index, size, offset);

      // Now that the function has been decoded, we can compute module offsets.
      for (; inst_traces_it != this->inst_traces_.end() &&
             std::get<0>(*inst_traces_it) == i;
           ++inst_traces_it) {
        uint32_t trace_offset = offset + std::get<1>(*inst_traces_it);
        uint32_t mark_id = std::get<2>(*inst_traces_it);
        std::pair<uint32_t, uint32_t> trace_mark = {trace_offset, mark_id};
        inst_traces.push_back(trace_mark);
      }
    }
    // If we have actually decoded traces and they were all decoded without
    // error, then we can move them to the module. If any errors are found, it
    // is safe to throw away all traces.
    if (V8_UNLIKELY(!inst_traces.empty() &&
                    inst_traces_it == this->inst_traces_.end())) {
      // This adds an invalid entry at the end of the traces. An invalid entry
      // is defined as having an module offset of 0 and a markid of 0.
      inst_traces.push_back({0, 0});
      this->module_->inst_traces = std::move(inst_traces);
    }
    DCHECK_GE(pc_offset(), code_section_start);
    module_->code = {code_section_start, pc_offset() - code_section_start};
  }

  void StartCodeSection(WireBytesRef section_bytes) {
    CheckSectionOrder(kCodeSectionCode);
    // Make sure global offset were calculated before they get accessed during
    // function compilation.
    CalculateGlobalOffsets(module_.get());
    module_->code = section_bytes;
  }

  bool CheckFunctionsCount(uint32_t functions_count, uint32_t error_offset) {
    if (functions_count != module_->num_declared_functions) {
      errorf(error_offset, "function body count %u mismatch (%u expected)",
             functions_count, module_->num_declared_functions);
      return false;
    }
    return true;
  }

  void DecodeFunctionBody(uint32_t func_index, uint32_t length,
                          uint32_t offset) {
    WasmFunction* function = &module_->functions[func_index];
    function->code = {offset, length};
    constexpr uint32_t kSmallFunctionThreshold = 50;
    if (length < kSmallFunctionThreshold) {
      ++module_->num_small_functions;
    }
    if (tracer_) {
      tracer_->FunctionBody(function, pc_ - (pc_offset() - offset));
    }
  }

  bool CheckDataSegmentsCount(uint32_t data_segments_count) {
    if (has_seen_unordered_section(kDataCountSectionCode) &&
        data_segments_count != module_->num_declared_data_segments) {
      errorf(pc(), "data segments count %u mismatch (%u expected)",
             data_segments_count, module_->num_declared_data_segments);
      return false;
    }
    return true;
  }

  struct DataSegmentHeader {
    bool is_active;
    bool is_shared;
    uint32_t memory_index;
    ConstantExpression dest_addr;
  };

  void DecodeDataSection() {
    uint32_t data_segments_count =
        consume_count("data segments count", kV8MaxWasmDataSegments);
    if (!CheckDataSegmentsCount(data_segments_count)) return;

    module_->data_segments.reserve(data_segments_count);
    for (uint32_t i = 0; i < data_segments_count; ++i) {
      TRACE("DecodeDataSegment[%d] module+%d\n", i,
            static_cast<int>(pc_ - start_));
      if (tracer_) tracer_->DataOffset(pc_offset());

      DataSegmentHeader header = consume_data_segment_header();

      uint32_t source_length = consume_u32v("source size", tracer_);
      if (tracer_) {
        tracer_->Description(source_length);
        tracer_->NextLine();
      }
      uint32_t source_offset = pc_offset();

      if (tracer_) {
        tracer_->Bytes(pc_, source_length);
        tracer_->Description("segment data");
        tracer_->NextLine();
      }
      consume_bytes(source_length, "segment data");

      if (failed()) break;
      module_->data_segments.emplace_back(
          header.is_active, header.is_shared, header.memory_index,
          header.dest_addr, WireBytesRef{source_offset, source_length});
    }
  }

  void DecodeNameSection() {
    if (tracer_) {
      tracer_->NameSection(
          pc_, end_, buffer_offset_ + static_cast<uint32_t>(pc_ - start_));
    }
    // TODO(titzer): find a way to report name errors as warnings.
    // Ignore all but the first occurrence of name section.
    if (!has_seen_unordered_section(kNameSectionCode)) {
      set_seen_unordered_section(kNameSectionCode);
      module_->name_section = {buffer_offset_,
                               static_cast<uint32_t>(end_ - start_)};
      // Use an inner decoder so that errors don't fail the outer decoder.
      Decoder inner(start_, pc_, end_, buffer_offset_);
      // Decode all name subsections.
      // Be lenient with their order.
      while (inner.ok() && inner.more()) {
        uint8_t name_type = inner.consume_u8("name type");
        if (name_type & 0x80) inner.error("name type if not varuint7");

        uint32_t name_payload_len = inner.consume_u32v("name payload length");
        if (!inner.checkAvailable(name_payload_len)) break;

        // Decode module name, ignore the rest.
        // Function and local names will be decoded when needed.
        if (name_type == NameSectionKindCode::kModuleCode) {
          WireBytesRef name =
              consume_string(&inner, unibrow::Utf8Variant::kLossyUtf8,
                             "module name", ITracer::NoTrace);
          if (inner.ok() && validate_utf8(&inner, name)) {
            module_->name = name;
          }
        } else {
          inner.consume_bytes(name_payload_len, "name subsection payload");
        }
      }
    }
    // Skip the whole names section in the outer decoder.
    consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
  }

  void DecodeSourceMappingURLSection() {
    Decoder inner(start_, pc_, end_, buffer_offset_);
    WireBytesRef url =
        wasm::consume_utf8_string(&inner, "module name", tracer_);
    if (inner.ok() &&
        module_->debug_symbols[WasmDebugSymbols::Type::SourceMap].type ==
            WasmDebugSymbols::None) {
      module_->debug_symbols[WasmDebugSymbols::Type::SourceMap] = {
          WasmDebugSymbols::Type::SourceMap, url};
    }
    set_seen_unordered_section(kSourceMappingURLSectionCode);
    consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
  }

  void DecodeExternalDebugInfoSection() {
    Decoder inner(start_, pc_, end_, buffer_offset_);
    WireBytesRef url =
        wasm::consume_utf8_string(&inner, "external symbol file", tracer_);
    if (inner.ok()) {
      module_->debug_symbols[WasmDebugSymbols::Type::ExternalDWARF] = {
          WasmDebugSymbols::Type::ExternalDWARF, url};
      set_seen_unordered_section(kExternalDebugInfoSectionCode);
    }
    consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
  }

  void DecodeInstTraceSection() {
    TRACE("DecodeInstTrace module+%d\n", static_cast<int>(pc_ - start_));
    if (!has_seen_unordered_section(kInstTraceSectionCode)) {
      set_seen_unordered_section(kInstTraceSectionCode);

      // Use an inner decoder so that errors don't fail the outer decoder.
      Decoder inner(start_, pc_, end_, buffer_offset_);

      std::vector<std::tuple<uint32_t, uint32_t, uint32_t>> inst_traces;

      uint32_t func_count = inner.consume_u32v("number of functions");
      // Keep track of the previous function index to validate the ordering.
      int64_t last_func_idx = -1;
      for (uint32_t i = 0; i < func_count; i++) {
        uint32_t func_idx = inner.consume_u32v("function index");
        if (int64_t{func_idx} <= last_func_idx) {
          inner.errorf("Invalid function index: %d", func_idx);
          break;
        }
        last_func_idx = func_idx;

        uint32_t num_traces = inner.consume_u32v("number of trace marks");
        TRACE("DecodeInstTrace[%d] module+%d\n", func_idx,
              static_cast<int>(inner.pc() - inner.start()));
        // Keep track of the previous offset to validate the ordering.
        int64_t last_func_off = -1;
        for (uint32_t j = 0; j < num_traces; ++j) {
          uint32_t func_off = inner.consume_u32v("function offset");

          uint32_t mark_size = inner.consume_u32v("mark size");
          uint32_t trace_mark_id = 0;
          // Build the mark id from the individual bytes.
          for (uint32_t k = 0; k < mark_size; k++) {
            trace_mark_id |= inner.consume_u8("trace mark id") << k * 8;
          }
          if (int64_t{func_off} <= last_func_off) {
            inner.errorf("Invalid branch offset: %d", func_off);
            break;
          }
          last_func_off = func_off;
          TRACE("DecodeInstTrace[%d][%d] module+%d\n", func_idx, func_off,
                static_cast<int>(inner.pc() - inner.start()));
          // Store the function index, function offset, and mark id into a
          // temporary 3-tuple. This will later be translated to a module
          // offset and  mark id.
          std::tuple<uint32_t, uint32_t, uint32_t> mark_tuple = {
              func_idx, func_off, trace_mark_id};
          inst_traces.push_back(mark_tuple);
        }
      }
      // Extra unexpected bytes are an error.
      if (inner.more()) {
        inner.errorf("Unexpected extra bytes: %d\n",
                     static_cast<int>(inner.pc() - inner.start()));
      }
      // If everything went well, accept the traces for the module.
      if (inner.ok()) {
        this->inst_traces_ = std::move(inst_traces);
      }
    }

    // Skip the whole instruction trace section in the outer decoder.
    consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
  }

  void DecodeCompilationHintsSection() {
    TRACE("DecodeCompilationHints module+%d\n", static_cast<int>(pc_ - start_));

    // TODO(frgossen): Find a way to report compilation hint errors as warnings.
    // All except first occurrence after function section and before code
    // section are ignored.
    const bool before_function_section =
        next_ordered_section_ <= kFunctionSectionCode;
    const bool after_code_section = next_ordered_section_ > kCodeSectionCode;
    if (before_function_section || after_code_section ||
        has_seen_unordered_section(kCompilationHintsSectionCode)) {
      return;
    }
    set_seen_unordered_section(kCompilationHintsSectionCode);

    // TODO(frgossen) Propagate errors to outer decoder in experimental phase.
    // We should use an inner decoder later and propagate its errors as
    // warnings.
    Decoder& decoder = *this;
    // Decoder decoder(start_, pc_, end_, buffer_offset_);

    // Ensure exactly one compilation hint per function.
    uint32_t hint_count = decoder.consume_u32v("compilation hint count");
    if (hint_count != module_->num_declared_functions) {
      decoder.errorf(decoder.pc(), "Expected %u compilation hints (%u found)",
                     module_->num_declared_functions, hint_count);
    }

    // Decode sequence of compilation hints.
    if (decoder.ok()) {
      module_->compilation_hints.reserve(hint_count);
    }
    for (uint32_t i = 0; decoder.ok() && i < hint_count; i++) {
      TRACE("DecodeCompilationHints[%d] module+%d\n", i,
            static_cast<int>(pc_ - start_));

      // Compilation hints are encoded in one byte each.
      // +-------+----------+---------------+----------+
      // | 2 bit | 2 bit    | 2 bit         | 2 bit    |
      // | ...   | Top tier | Baseline tier | Strategy |
      // +-------+----------+---------------+----------+
      uint8_t hint_byte = decoder.consume_u8("compilation hint");
      if (!decoder.ok()) break;

      // Validate the hint_byte.
      // For the compilation strategy, all 2-bit values are valid. For the tier,
      // only 0x0, 0x1, and 0x2 are allowed.
      static_assert(
          static_cast<int>(WasmCompilationHintTier::kDefault) == 0 &&
              static_cast<int>(WasmCompilationHintTier::kBaseline) == 1 &&
              static_cast<int>(WasmCompilationHintTier::kOptimized) == 2,
          "The check below assumes that 0x03 is the only invalid 2-bit number "
          "for a compilation tier");
      if (((hint_byte >> 2) & 0x03) == 0x03 ||
          ((hint_byte >> 4) & 0x03) == 0x03) {
        decoder.errorf(decoder.pc(),
                       "Invalid compilation hint %#04x (invalid tier 0x03)",
                       hint_byte);
        break;
      }

      // Decode compilation hint.
      WasmCompilationHint hint;
      hint.strategy =
          static_cast<WasmCompilationHintStrategy>(hint_byte & 0x03);
      hint.baseline_tier =
          static_cast<WasmCompilationHintTier>((hint_byte >> 2) & 0x03);
      hint.top_tier =
          static_cast<WasmCompilationHintTier>((hint_byte >> 4) & 0x03);

      // Ensure that the top tier never downgrades a compilation result. If
      // baseline and top tier are the same compilation will be invoked only
      // once.
      if (hint.top_tier < hint.baseline_tier &&
          hint.top_tier != WasmCompilationHintTier::kDefault) {
        decoder.errorf(decoder.pc(),
                       "Invalid compilation hint %#04x (forbidden downgrade)",
                       hint_byte);
      }

      // Happily accept compilation hint.
      if (decoder.ok()) {
        module_->compilation_hints.push_back(std::move(hint));
      }
    }

    // If section was invalid reset compilation hints.
    if (decoder.failed()) {
      module_->compilation_hints.clear();
    }

    // @TODO(frgossen) Skip the whole compilation hints section in the outer
    // decoder if inner decoder was used.
    // consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
  }

  void DecodeBranchHintsSection() {
    TRACE("DecodeBranchHints module+%d\n", static_cast<int>(pc_ - start_));
    if (!has_seen_unordered_section(kBranchHintsSectionCode)) {
      set_seen_unordered_section(kBranchHintsSectionCode);
      // Use an inner decoder so that errors don't fail the outer decoder.
      Decoder inner(start_, pc_, end_, buffer_offset_);
      BranchHintInfo branch_hints;

      uint32_t func_count = inner.consume_u32v("number of functions");
      // Keep track of the previous function index to validate the ordering
      int64_t last_func_idx = -1;
      for (uint32_t i = 0; i < func_count; i++) {
        uint32_t func_idx = inner.consume_u32v("function index");
        if (int64_t{func_idx} <= last_func_idx) {
          inner.errorf("Invalid function index: %d", func_idx);
          break;
        }
        last_func_idx = func_idx;
        uint32_t num_hints = inner.consume_u32v("number of hints");
        BranchHintMap func_branch_hints;
        TRACE("DecodeBranchHints[%d] module+%d\n", func_idx,
              static_cast<int>(inner.pc() - inner.start()));
        // Keep track of the previous branch offset to validate the ordering
        int64_t last_br_off = -1;
        for (uint32_t j = 0; j < num_hints; ++j) {
          uint32_t br_off = inner.consume_u32v("branch instruction offset");
          if (int64_t{br_off} <= last_br_off) {
            inner.errorf("Invalid branch offset: %d", br_off);
            break;
          }
          last_br_off = br_off;
          uint32_t data_size = inner.consume_u32v("data size");
          if (data_size != 1) {
            inner.errorf("Invalid data size: %#x. Expected 1.", data_size);
            break;
          }
          uint32_t br_dir = inner.consume_u8("branch direction");
          TRACE("DecodeBranchHints[%d][%d] module+%d\n", func_idx, br_off,
                static_cast<int>(inner.pc() - inner.start()));
          WasmBranchHint hint;
          switch (br_dir) {
            case 0:
              hint = WasmBranchHint::kUnlikely;
              break;
            case 1:
              hint = WasmBranchHint::kLikely;
              break;
            default:
              hint = WasmBranchHint::kNoHint;
              inner.errorf(inner.pc(), "Invalid branch hint %#x", br_dir);
              break;
          }
          if (!inner.ok()) {
            break;
          }
          func_branch_hints.insert(br_off, hint);
        }
        if (!inner.ok()) {
          break;
        }
        branch_hints.emplace(func_idx, std::move(func_branch_hints));
      }
      // Extra unexpected bytes are an error.
      if (inner.more()) {
        inner.errorf("Unexpected extra bytes: %d\n",
                     static_cast<int>(inner.pc() - inner.start()));
      }
      // If everything went well, accept the hints for the module.
      if (inner.ok()) {
        module_->branch_hints = std::move(branch_hints);
      }
    }
    // Skip the whole branch hints section in the outer decoder.
    consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
  }

  void DecodeDataCountSection() {
    module_->num_declared_data_segments =
        consume_count("data segments count", kV8MaxWasmDataSegments);
    if (tracer_) tracer_->NextLineIfNonEmpty();
  }

  void DecodeTagSection() {
    uint32_t tag_count = consume_count("tag count", kV8MaxWasmTags);
    for (uint32_t i = 0; ok() && i < tag_count; ++i) {
      TRACE("DecodeTag[%d] module+%d\n", i, static_cast<int>(pc_ - start_));
      if (tracer_) tracer_->TagOffset(pc_offset());
      const WasmTagSig* tag_sig = nullptr;
      consume_exception_attribute();  // Attribute ignored for now.
      ModuleTypeIndex sig_index =
          consume_tag_sig_index(module_.get(), &tag_sig);
      module_->tags.emplace_back(tag_sig, sig_index);
    }
  }

  void DecodeStringRefSection() {
    uint32_t deferred = consume_count("deferred string literal count",
                                      kV8MaxWasmStringLiterals);
    if (deferred) {
      errorf(pc(), "Invalid deferred string literal count %u (expected 0)",
             deferred);
    }
    uint32_t immediate = consume_count("string literal count",
                                       kV8MaxWasmStringLiterals - deferred);
    for (uint32_t i = 0; ok() && i < immediate; ++i) {
      TRACE("DecodeStringLiteral[%d] module+%d\n", i,
            static_cast<int>(pc_ - start_));
      if (tracer_) tracer_->StringOffset(pc_offset());
      // TODO(12868): Throw if the string's utf-16 length > String::kMaxLength.
      WireBytesRef pos = wasm::consume_string(this, unibrow::Utf8Variant::kWtf8,
                                              "string literal", tracer_);
      module_->stringref_literals.emplace_back(pos);
    }
  }

  bool CheckMismatchedCounts() {
    // The declared vs. defined function count is normally checked when
    // decoding the code section, but we have to check it here too in case the
    // code section is absent.
    if (module_->num_declared_functions != 0) {
      DCHECK_LT(module_->num_imported_functions, module_->functions.size());
      // We know that the code section has been decoded if the first
      // non-imported function has its code set.
      if (!module_->functions[module_->num_imported_functions].code.is_set()) {
        errorf(pc(), "function count is %u, but code section is absent",
               module_->num_declared_functions);
        return false;
      }
    }
    // Perform a similar check for the DataCount and Data sections, where data
    // segments are declared but the Data section is absent.
    if (!CheckDataSegmentsCount(
            static_cast<uint32_t>(module_->data_segments.size()))) {
      return false;
    }
    return true;
  }

  ModuleResult FinishDecoding() {
    if (ok() && CheckMismatchedCounts()) {
      // We calculate the global offsets here, because there may not be a
      // global section and code section that would have triggered the
      // calculation before. Even without the globals section the calculation
      // is needed because globals can also be defined in the import section.
      Calcul
```