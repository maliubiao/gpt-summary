Response:
The user wants a summary of the functionality of the provided C++ header file, `v8/src/wasm/module-decoder-impl.h`.

Here's a breakdown of the thinking process to generate the answer:

1. **Identify the core purpose:** The name "module-decoder-impl.h" strongly suggests this file is responsible for decoding WebAssembly modules. The code confirms this by having methods like `DecodeModule`, `DecodeSection`, `DecodeFunctionSignature`, etc.

2. **Examine key methods and data structures:**
    * `DecodeModule`: This is the main entry point for decoding an entire module. It handles the overall structure, including the header and sections.
    * `DecodeSection`:  Processes individual sections within the WebAssembly module.
    * `DecodeSingleFunctionForTesting`, `DecodeFunctionSignature`:  Handle decoding of specific parts like functions and signatures, likely for testing or specific use cases.
    * `consume_*`:  A large number of `consume_*` methods indicate the file handles parsing various WebAssembly constructs like value types, limits, indices, expressions, etc. These are the building blocks of the decoding process.
    * `ModuleResult`, `FunctionResult`: These likely represent the outcome of decoding operations, indicating success or failure and potentially carrying the decoded data or error information.
    * `WasmModule`: This is the core data structure that holds the decoded representation of the WebAssembly module.
    * `WasmSectionIterator`:  Helps iterate through the sections of the module.

3. **Look for features and specific handling:**
    * **Validation:**  The `ValidateFunctions` call indicates that the decoder performs validation of the WebAssembly code.
    * **Error Handling:** The presence of `failed()`, `errorf()`, and `toResult()` points to robust error handling during the decoding process.
    * **Experimental Features:**  Checks for `v8_flags.experimental_wasm_shared` and `enabled_features_.has_memory64()` show the decoder handles experimental WebAssembly features.
    * **Constant Expressions:**  The `consume_init_expr` and related logic indicate support for decoding constant expressions used in globals and element/data segments.
    * **Shared Memory/Tables:**  Specific logic related to shared memories and tables is present.
    * **Memory64:**  Handling for 64-bit memories is apparent.
    * **Element and Data Segments:**  Dedicated `consume_element_segment_header` and `consume_data_segment_header` functions show support for these features.

4. **Infer Relationships with JavaScript (if any):** While this is a C++ file, the context is V8, the JavaScript engine. WebAssembly is executed within JavaScript environments. Therefore, this decoder is crucial for enabling JavaScript to load and execute WebAssembly code. The decoded `WasmModule` will be used by other parts of V8 to compile and run the WebAssembly.

5. **Consider potential user errors:**  WebAssembly has specific structural requirements. The decoder's error handling suggests common mistakes would involve:
    * Incorrect module structure (e.g., out-of-order sections).
    * Invalid indices (referencing non-existent functions, globals, etc.).
    * Type mismatches in constant expressions or segment initializers.
    * Exceeding size limits for various components.
    * Using features not supported by the engine (or without the necessary flags).

6. **Structure the answer according to the prompt's requests:** Address each point in the prompt:
    * List of functionalities.
    * Torque source identification (not applicable in this case).
    * Relationship with JavaScript and example.
    * Code logic and examples (provide plausible input/output for a function signature).
    * Common user errors.
    * Overall summary (the current task).

7. **Refine and elaborate:**  Provide more details and explanations for each point. For instance, instead of just saying "decodes sections," mention the types of sections handled. For the JavaScript example, show how the decoded module would be used. For user errors, give specific examples related to WebAssembly syntax.

8. **Focus on the provided code snippet for the final summary:**  The last part of the prompt asks for a summary of the *provided snippet*. This snippet mainly focuses on the `DecodeModule` method and the loop that iterates through sections. It also touches on validation and calculating global offsets. The summary should emphasize these aspects.
## v8/src/wasm/module-decoder-impl.h 代码功能归纳 (第 3 部分)

这是 `v8/src/wasm/module-decoder-impl.h` 源代码的第三部分，主要集中在以下功能：

**核心功能：模块和函数解码**

* **`DecodeModule(bool validate_functions)`:**  这是解码整个 WebAssembly 模块的主要入口点。
    * 它首先检查模块大小是否超过限制。
    * 然后调用 `DecodeModuleHeader` 解码模块头。
    * 接下来，它使用 `WasmSectionIterator` 遍历模块的各个 section。
    * 对于每个 section，调用 `DecodeSection` 进行具体解码。
    * 在 section 遍历完成后，调用 `FinishDecoding` 进行最后的处理。
    * 如果 `validate_functions` 为 true，则调用 `ValidateFunctions` 对函数体进行验证。
    * 最后，如果开启了 `v8_flags.dump_wasm_module`，则会转储模块信息。
* **`DecodeSingleFunctionForTesting(Zone* zone, ModuleWireBytes wire_bytes, const WasmModule* module)`:**  用于测试目的，解码单个匿名函数。
    * 它期望以 `kWasmFunctionTypeCode` 开头。
    * 调用 `consume_sig` 解析函数签名。
    * 使用 `ValidateFunctionBody` 验证函数体。
* **`DecodeFunctionSignature(Zone* zone, const uint8_t* start)`:**  解码单个函数签名。
    * 期望以 `kWasmFunctionTypeCode` 开头。
    * 调用 `consume_sig` 解析签名。
* **`DecodeInitExprForTesting(ValueType expected)`:**  用于测试目的，解码一个初始化表达式。
    * 调用 `consume_init_expr` 进行解码。
* **`consume_element_segment_entry(WasmModule* module, const WasmElemSegment& segment)`:** 解码元素段的条目，根据元素类型选择解码方式（常量表达式或函数索引）。

**辅助功能和工具方法：**

* **`shared_module() const`:** 返回共享的 `WasmModule` 指针。
* **`has_seen_unordered_section(SectionCode section_code)` 和 `set_seen_unordered_section(SectionCode section_code)`:**  用于跟踪是否已经遇到过无序的 section。
* **`off(const uint8_t* ptr)`:** 计算给定指针相对于模块起始地址的偏移量。
* **`CalculateGlobalOffsets(WasmModule* module)`:** 计算全局变量的偏移量和全局变量表的总大小。这个方法会被多次调用，确保在访问全局变量偏移量之前完成计算。
* **`consume_sig_index(WasmModule* module, const FunctionSig** sig)`:** 消费并验证函数签名的索引。
* **`consume_tag_sig_index(WasmModule* module, const FunctionSig** sig)`:** 消费并验证异常标签的签名索引，并确保其返回类型为空。
* **`consume_count(const char* name, size_t maximum)`:** 消费一个计数器，并检查其是否超过最大值。
* **`consume_func_index`, `consume_global_index`, `consume_table_index`, `consume_tag_index`:** 消费并验证各种索引。
* **`consume_limits_byte<LimitsByteType limits_type>()`:** 消费并解析内存或表的 limits 字节。
* **`consume_table_flags(WasmTable* table)` 和 `consume_memory_flags(WasmMemory* memory)`:**  根据 limits 字节设置表和内存的属性。
* **`consume_global_flags()`:** 消费并解析全局变量的标志（可变性和共享性）。
* **`consume_resizable_limits(...)`:** 消费并解析可调整大小的限制（用于内存和表）。
* **`expect_u8(const char* name, uint8_t expected)`:** 消费一个字节，如果与期望值不符则报错。
* **`consume_init_expr(WasmModule* module, ValueType expected, bool is_shared)`:** 解码一个初始化表达式，并进行类型检查。
* **`consume_mutability()`:** 消费并解析可变性标志。
* **`consume_value_type()`:** 消费并解析一个值类型。
* **`consume_storage_type()`:** 消费并解析一个存储类型（可能是打包类型）。
* **`consume_sig(Zone* zone)`:** 消费并解析一个函数签名。
* **`consume_struct(Zone* zone)`:** 消费并解析一个结构体类型定义。
* **`consume_array(Zone* zone)`:** 消费并解析一个数组类型定义。
* **`consume_exception_attribute()`:** 消费异常的属性字段。
* **`consume_element_segment_header()`:** 消费并解析元素段的头部信息。
* **`consume_data_segment_header()`:** 消费并解析数据段的头部信息。
* **`consume_element_func_index(WasmModule* module, ValueType expected)`:** 消费并验证元素段中的函数索引。

**JavaScript 关系示例:**

虽然 `module-decoder-impl.h` 是 C++ 代码，但它负责解析 WebAssembly 模块，这直接关系到 JavaScript 如何加载和执行 WebAssembly 代码。

```javascript
// 假设我们有一个 WebAssembly 模块的字节数组
const wasmBytes = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, // Magic number: \0asm
  0x01, 0x00, 0x00, 0x00, // Version: 1
  // ... 模块的其他 section 数据
]);

// 在 JavaScript 中，我们可以使用 WebAssembly API 加载这些字节
WebAssembly.instantiate(wasmBytes)
  .then(result => {
    const instance = result.instance;
    // 现在我们可以调用 WebAssembly 模块导出的函数
    // 例如，如果模块导出了一个名为 "add" 的函数
    // const sum = instance.exports.add(5, 3);
    // console.log(sum); // 输出 8
  });
```

**`v8/src/wasm/module-decoder-impl.h` 的作用就是解析 `wasmBytes` 中的内容，将其转化为 V8 可以理解和执行的内部表示形式 (`WasmModule`)。**  `DecodeModule` 方法会读取 `wasmBytes` 中的各个 section，例如类型 section、函数 section、代码 section 等，并构建出 `WasmModule` 对象，其中包含了模块的函数、全局变量、内存、表等信息。

**代码逻辑推理示例:**

**假设输入:**  正在解码一个包含类型 section 和函数 section 的 WebAssembly 模块。类型 section 定义了一个接受两个 i32 参数并返回一个 i32 结果的函数签名。函数 section 引用了这个签名。

**`DecodeModule` 方法的执行流程 (简化):**

1. 读取模块头。
2. `WasmSectionIterator` 定位到类型 section。
3. `DecodeSection` 调用类型 section 的解码逻辑（未在提供的代码中）。
4. 类型 section 的解码逻辑会调用类似 `consume_count` 读取参数和返回值数量，然后调用 `consume_value_type` 读取每个参数和返回值的类型，最终构建 `FunctionSig` 对象并添加到 `module_->types` 中。
5. `WasmSectionIterator` 定位到函数 section。
6. `DecodeSection` 调用函数 section 的解码逻辑（当前代码片段中部分涉及）。
7. 函数 section 的解码逻辑会调用 `consume_count` 读取函数数量，然后对于每个函数，调用 `consume_sig_index` 读取其签名索引。
8. `consume_sig_index` 会根据读取的索引在 `module_->types` 中查找对应的 `FunctionSig` 对象。

**假设输出:** `module_->types` 包含了正确解析的函数签名，函数 section 中的每个函数都关联了正确的签名索引。

**用户常见的编程错误示例:**

1. **无效的模块结构:** WebAssembly 模块的 section 顺序是特定的。例如，类型 section 必须在函数 section 之前。如果用户手动构建 WebAssembly 字节码时，将 section 顺序搞错，`DecodeModule` 在遍历 section 时可能会出错。

2. **索引超出范围:**  如果在函数 section 中引用了一个不存在的类型索引，`consume_sig_index` 会检测到索引超出 `module_->types` 的范围并报错。

3. **类型不匹配:** 在初始化全局变量或元素段时，提供的初始值类型与声明的类型不符。例如，尝试使用浮点数初始化一个 i32 类型的全局变量，`consume_init_expr` 中的类型检查会失败。

4. **超出限制:**  定义过多的函数参数或返回值，超过了 `kV8MaxWasmFunctionParams` 或 `kV8MaxWasmFunctionReturns` 的限制，`consume_count` 会报错。

**总结 `v8/src/wasm/module-decoder-impl.h` 的功能 (基于提供的第 3 部分代码):**

这部分代码主要负责 **解码 WebAssembly 模块的结构和内容**。 核心的 `DecodeModule` 方法驱动整个解码过程，遍历模块的各个 section 并调用相应的解码逻辑。 此外，它还提供了用于解码单个函数、函数签名和初始化表达式的方法，以及一系列辅助的 `consume_*` 方法来解析 WebAssembly 的各种基本构成元素（如类型、索引、标志等）。  这部分代码还涉及到模块的验证，尤其是在函数体验证方面。 总体而言，这部分代码是 V8 理解和处理 WebAssembly 模块的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/module-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
ateGlobalOffsets(module_.get());
    }

    return toResult(std::move(module_));
  }

  // Decodes an entire module.
  ModuleResult DecodeModule(bool validate_functions) {
    // Keep a reference to the wire bytes, in case this decoder gets reset on
    // error.
    base::Vector<const uint8_t> wire_bytes(start_, end_ - start_);
    size_t max_size = max_module_size();
    if (wire_bytes.size() > max_size) {
      return ModuleResult{WasmError{0, "size > maximum module size (%zu): %zu",
                                    max_size, wire_bytes.size()}};
    }

    DecodeModuleHeader(wire_bytes);
    if (failed()) return toResult(nullptr);

    static constexpr uint32_t kWasmHeaderSize = 8;
    Decoder section_iterator_decoder(start_ + kWasmHeaderSize, end_,
                                     kWasmHeaderSize);
    WasmSectionIterator section_iter(&section_iterator_decoder, tracer_);

    while (ok()) {
      if (section_iter.section_code() != SectionCode::kUnknownSectionCode) {
        uint32_t offset = static_cast<uint32_t>(section_iter.payload().begin() -
                                                wire_bytes.begin());
        DecodeSection(section_iter.section_code(), section_iter.payload(),
                      offset);
        if (!ok()) break;
      }
      if (!section_iter.more()) break;
      section_iter.advance(true);
    }

    // Check for module structure errors before validating function bodies, to
    // produce consistent error message independent of whether validation
    // happens here or later.
    if (section_iterator_decoder.failed()) {
      return section_iterator_decoder.toResult(nullptr);
    }

    ModuleResult result = FinishDecoding();
    if (!result.failed() && validate_functions) {
      std::function<bool(int)> kNoFilter;
      if (WasmError validation_error =
              ValidateFunctions(module_.get(), enabled_features_, wire_bytes,
                                kNoFilter, detected_features_)) {
        result = ModuleResult{validation_error};
      }
    }

    if (v8_flags.dump_wasm_module) DumpModule(wire_bytes, result.ok());

    return result;
  }

  // Decodes a single anonymous function starting at {start_}.
  FunctionResult DecodeSingleFunctionForTesting(Zone* zone,
                                                ModuleWireBytes wire_bytes,
                                                const WasmModule* module) {
    DCHECK(ok());
    pc_ = start_;
    expect_u8("type form", kWasmFunctionTypeCode);
    WasmFunction function;
    function.sig = consume_sig(zone);
    function.code = {off(pc_), static_cast<uint32_t>(end_ - pc_)};

    if (!ok()) return FunctionResult{std::move(error_)};

    constexpr bool kShared = false;
    FunctionBody body{function.sig, off(pc_), pc_, end_, kShared};

    WasmDetectedFeatures unused_detected_features;
    DecodeResult result = ValidateFunctionBody(zone, enabled_features_, module,
                                               &unused_detected_features, body);

    if (result.failed()) return FunctionResult{std::move(result).error()};

    return FunctionResult{std::make_unique<WasmFunction>(function)};
  }

  // Decodes a single function signature at {start}.
  const FunctionSig* DecodeFunctionSignature(Zone* zone, const uint8_t* start) {
    pc_ = start;
    if (!expect_u8("type form", kWasmFunctionTypeCode)) return nullptr;
    const FunctionSig* result = consume_sig(zone);
    return ok() ? result : nullptr;
  }

  ConstantExpression DecodeInitExprForTesting(ValueType expected) {
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    return consume_init_expr(module_.get(), expected, kIsShared);
  }

  // Takes a module as parameter so that wasm-disassembler.cc can pass its own
  // module.
  ConstantExpression consume_element_segment_entry(
      WasmModule* module, const WasmElemSegment& segment) {
    if (segment.element_type == WasmElemSegment::kExpressionElements) {
      return consume_init_expr(module, segment.type, segment.shared);
    } else {
      return ConstantExpression::RefFunc(
          consume_element_func_index(module, segment.type));
    }
  }

  const std::shared_ptr<WasmModule>& shared_module() const { return module_; }

 private:
  bool has_seen_unordered_section(SectionCode section_code) {
    return seen_unordered_sections_ & (1 << section_code);
  }

  void set_seen_unordered_section(SectionCode section_code) {
    seen_unordered_sections_ |= 1 << section_code;
  }

  uint32_t off(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr - start_) + buffer_offset_;
  }

  // Calculate individual global offsets and total size of globals table. This
  // function should be called after all globals have been defined, which is
  // after the import section and the global section, but before the global
  // offsets are accessed, e.g. by the function compilers. The moment when this
  // function should be called is not well-defined, as the global section may
  // not exist. Therefore this function is called multiple times.
  void CalculateGlobalOffsets(WasmModule* module) {
    if (module->globals.empty() || module->untagged_globals_buffer_size != 0 ||
        module->tagged_globals_buffer_size != 0) {
      // This function has already been executed before, so we don't have to
      // execute it again.
      return;
    }
    uint32_t untagged_offset = 0;
    uint32_t tagged_offset = 0;
    uint32_t num_imported_mutable_globals = 0;
    for (WasmGlobal& global : module->globals) {
      if (global.mutability && global.imported) {
        global.index = num_imported_mutable_globals++;
      } else if (global.type.is_reference()) {
        global.offset = tagged_offset;
        // All entries in the tagged_globals_buffer have size 1.
        tagged_offset++;
      } else {
        int size = global.type.value_kind_size();
        untagged_offset = (untagged_offset + size - 1) & ~(size - 1);  // align
        global.offset = untagged_offset;
        untagged_offset += size;
      }
    }
    module->untagged_globals_buffer_size = untagged_offset;
    module->tagged_globals_buffer_size = tagged_offset;
  }

  ModuleTypeIndex consume_sig_index(WasmModule* module,
                                    const FunctionSig** sig) {
    const uint8_t* pos = pc_;
    ModuleTypeIndex sig_index{consume_u32v("signature index")};
    if (tracer_) tracer_->Bytes(pos, static_cast<uint32_t>(pc_ - pos));
    if (!module->has_signature(sig_index)) {
      errorf(pos, "no signature at index %u (%d types)", sig_index,
             static_cast<int>(module->types.size()));
      *sig = nullptr;
      return {};
    }
    *sig = module->signature(sig_index);
    if (tracer_) {
      tracer_->Description(*sig);
      tracer_->NextLine();
    }
    return sig_index;
  }

  ModuleTypeIndex consume_tag_sig_index(WasmModule* module,
                                        const FunctionSig** sig) {
    const uint8_t* pos = pc_;
    ModuleTypeIndex sig_index = consume_sig_index(module, sig);
    if (*sig && (*sig)->return_count() != 0) {
      errorf(pos, "tag signature %u has non-void return", sig_index);
      *sig = nullptr;
      return {};
    }
    return sig_index;
  }

  uint32_t consume_count(const char* name, size_t maximum) {
    const uint8_t* p = pc_;
    uint32_t count = consume_u32v(name, tracer_);
    if (tracer_) {
      tracer_->Description(count);
      if (count == 1) {
        tracer_->Description(": ");
      } else {
        tracer_->NextLine();
      }
    }
    if (count > maximum) {
      errorf(p, "%s of %u exceeds internal limit of %zu", name, count, maximum);
      return 0;
    }
    return count;
  }

  uint32_t consume_func_index(WasmModule* module, WasmFunction** func) {
    return consume_index("function", &module->functions, func);
  }

  uint32_t consume_global_index(WasmModule* module, WasmGlobal** global) {
    return consume_index("global", &module->globals, global);
  }

  uint32_t consume_table_index(WasmModule* module, WasmTable** table) {
    return consume_index("table", &module->tables, table);
  }

  uint32_t consume_tag_index(WasmModule* module, WasmTag** tag) {
    return consume_index("tag", &module->tags, tag);
  }

  template <typename T>
  uint32_t consume_index(const char* name, std::vector<T>* vector, T** ptr) {
    const uint8_t* pos = pc_;
    uint32_t index = consume_u32v("index", tracer_);
    if (tracer_) {
      tracer_->Description(": ");
      tracer_->Description(index);
    }
    if (index >= vector->size()) {
      errorf(pos, "%s index %u out of bounds (%d entr%s)", name, index,
             static_cast<int>(vector->size()),
             vector->size() == 1 ? "y" : "ies");
      *ptr = nullptr;
      return 0;
    }
    *ptr = &(*vector)[index];
    return index;
  }

  // The limits byte structure is used for memories and tables.
  struct LimitsByte {
    uint8_t flags;

    // Flags 0..7 are valid (3 bits).
    bool is_valid() const { return (flags & ~0x7) == 0; }
    bool has_maximum() const { return flags & 0x1; }
    bool is_shared() const { return flags & 0x2; }
    bool is_64bit() const { return flags & 0x4; }
    AddressType address_type() const {
      return is_64bit() ? AddressType::kI64 : AddressType::kI32;
    }
  };

  enum LimitsByteType { kMemory, kTable };

  template <LimitsByteType limits_type>
  LimitsByte consume_limits_byte() {
    if (tracer_) tracer_->Bytes(pc_, 1);
    LimitsByte limits{consume_u8(
        limits_type == kMemory ? "memory limits flags" : "table limits flags")};
    if (!limits.is_valid()) {
      errorf(pc() - 1, "invalid %s limits flags 0x%x",
             limits_type == kMemory ? "memory" : "table", limits.flags);
    }

    if (limits.is_shared()) {
      if constexpr (limits_type == kMemory) {
        // V8 does not support shared memory without a maximum.
        if (!limits.has_maximum()) {
          error(pc() - 1, "shared memory must have a maximum defined");
        }
        if (v8_flags.experimental_wasm_shared) {
          error(pc() - 1,
                "shared memories are not supported with "
                "--experimental-wasm-shared yet.");
        }
      } else if (!v8_flags.experimental_wasm_shared) {  // table
        error(pc() - 1,
              "invalid table limits flags, enable with "
              "--experimental-wasm-shared");
      }
    }

    if (limits.is_64bit() && !enabled_features_.has_memory64()) {
      errorf(pc() - 1,
             "invalid %s limits flags 0x%x (enable with "
             "--experimental-wasm-memory64)",
             limits_type == kMemory ? "memory" : "table", limits.flags);
    }

    if (tracer_) {
      if (limits.is_shared()) tracer_->Description(" shared");
      if (limits.is_64bit()) {
        tracer_->Description(limits_type == kMemory ? " mem64" : " table64");
      }
      tracer_->Description(limits.has_maximum() ? " with maximum"
                                                : " no maximum");
      tracer_->NextLine();
    }

    return limits;
  }

  void consume_table_flags(WasmTable* table) {
    LimitsByte limits = consume_limits_byte<kTable>();
    table->has_maximum_size = limits.has_maximum();
    table->shared = limits.is_shared();
    table->address_type = limits.address_type();

    if (table->is_table64()) detected_features_->add_memory64();
  }

  void consume_memory_flags(WasmMemory* memory) {
    LimitsByte limits = consume_limits_byte<kMemory>();
    memory->has_maximum_pages = limits.has_maximum();
    memory->is_shared = limits.is_shared();
    memory->address_type = limits.address_type();

    if (memory->is_shared) detected_features_->add_shared_memory();
    if (memory->is_memory64()) detected_features_->add_memory64();
  }

  std::pair<bool, bool> consume_global_flags() {
    uint8_t flags = consume_u8("global flags");
    if (flags & ~0b11) {
      errorf(pc() - 1, "invalid global flags 0x%x", flags);
      return {false, false};
    }
    bool mutability = flags & 0b1;
    bool shared = flags & 0b10;
    if (tracer_) {
      tracer_->Bytes(pc_, 1);  // The flags byte.
      if (shared) tracer_->Description(" shared");
      tracer_->Description(mutability ? " mutable" : " immutable");
    }
    if (shared && !v8_flags.experimental_wasm_shared) {
      errorf(
          pc() - 1,
          "invalid global flags 0x%x (enable via --experimental-wasm-shared)",
          flags);
      return {false, false};
    }
    return {mutability, shared};
  }

  enum ResizableLimitsType : bool { k32BitLimits, k64BitLimits };
  void consume_resizable_limits(
      const char* name, const char* units,
      // Not: both memories and tables have a 32-bit limit on the initial size.
      uint32_t max_initial, uint32_t* initial, bool has_maximum,
      uint64_t max_maximum, uint64_t* maximum, ResizableLimitsType type) {
    const uint8_t* pos = pc();
    // Note that even if we read the values as 64-bit value, all V8 limits are
    // still within uint32_t range.
    uint64_t initial_64 = type == k64BitLimits
                              ? consume_u64v("initial size", tracer_)
                              : consume_u32v("initial size", tracer_);
    if (initial_64 > max_initial) {
      errorf(pos,
             "initial %s size (%" PRIu64
             " %s) is larger than implementation limit (%u %s)",
             name, initial_64, units, max_initial, units);
    }
    *initial = static_cast<uint32_t>(initial_64);
    if (tracer_) {
      tracer_->Description(*initial);
      tracer_->NextLine();
    }
    if (has_maximum) {
      pos = pc();
      uint64_t maximum_64 = type == k64BitLimits
                                ? consume_u64v("maximum size", tracer_)
                                : consume_u32v("maximum size", tracer_);
      if (maximum_64 > max_maximum) {
        errorf(pos,
               "maximum %s size (%" PRIu64
               " %s) is larger than implementation limit (%" PRIu64 " %s)",
               name, maximum_64, units, max_maximum, units);
      }
      if (maximum_64 < *initial) {
        errorf(pos,
               "maximum %s size (%" PRIu64 " %s) is less than initial (%u %s)",
               name, maximum_64, units, *initial, units);
      }
      *maximum = maximum_64;
      if (tracer_) {
        tracer_->Description(*maximum);
        tracer_->NextLine();
      }
    } else {
      *maximum = max_initial;
    }
  }

  // Consumes a byte, and emits an error if it does not equal {expected}.
  bool expect_u8(const char* name, uint8_t expected) {
    const uint8_t* pos = pc();
    uint8_t value = consume_u8(name);
    if (value != expected) {
      errorf(pos, "expected %s 0x%02x, got 0x%02x", name, expected, value);
      return false;
    }
    return true;
  }

  ConstantExpression consume_init_expr(WasmModule* module, ValueType expected,
                                       bool is_shared) {
    // The error message mimics the one generated by the {WasmFullDecoder}.
#define TYPE_CHECK(found)                                                \
  if (V8_UNLIKELY(!IsSubtypeOf(found, expected, module))) {              \
    errorf(pc() + 1,                                                     \
           "type error in constant expression[0] (expected %s, got %s)", \
           expected.name().c_str(), found.name().c_str());               \
    return {};                                                           \
  }

    if (tracer_) tracer_->NextLineIfNonEmpty();
    // To avoid initializing a {WasmFullDecoder} for the most common
    // expressions, we replicate their decoding and validation here. The
    // manually handled cases correspond to {ConstantExpression}'s kinds.
    // We need to make sure to check that the expression ends in {kExprEnd};
    // otherwise, it is just the first operand of a composite expression, and we
    // fall back to the default case.
    if (!more()) {
      error("Beyond end of code");
      return {};
    }
    switch (static_cast<WasmOpcode>(*pc())) {
      case kExprI32Const: {
        auto [value, length] =
            read_i32v<FullValidationTag>(pc() + 1, "i32.const");
        if (V8_UNLIKELY(failed())) return {};
        if (V8_LIKELY(lookahead(1 + length, kExprEnd))) {
          TYPE_CHECK(kWasmI32)
          if (tracer_) {
            tracer_->InitializerExpression(pc_, pc_ + length + 2, kWasmI32);
          }
          consume_bytes(length + 2);
          return ConstantExpression::I32Const(value);
        }
        break;
      }
      case kExprRefFunc: {
        auto [index, length] =
            read_u32v<FullValidationTag>(pc() + 1, "ref.func");
        if (V8_UNLIKELY(failed())) return {};
        if (V8_LIKELY(lookahead(1 + length, kExprEnd))) {
          if (V8_UNLIKELY(index >= module->functions.size())) {
            errorf(pc() + 1, "function index %u out of bounds", index);
            return {};
          }
          ValueType type = ValueType::Ref(module->functions[index].sig_index);
          TYPE_CHECK(type)
          if (V8_UNLIKELY(is_shared && !IsShared(type, module))) {
            error(pc(), "ref.func does not have a shared type");
            return {};
          }
          module->functions[index].declared = true;
          if (tracer_) {
            tracer_->InitializerExpression(pc_, pc_ + length + 2, type);
          }
          consume_bytes(length + 2);
          return ConstantExpression::RefFunc(index);
        }
        break;
      }
      case kExprRefNull: {
        auto [type, length] =
            value_type_reader::read_heap_type<FullValidationTag>(
                this, pc() + 1, enabled_features_);
        value_type_reader::ValidateHeapType<FullValidationTag>(this, pc_,
                                                               module, type);
        if (V8_UNLIKELY(failed())) return {};
        if (V8_LIKELY(lookahead(1 + length, kExprEnd))) {
          TYPE_CHECK(ValueType::RefNull(type))
          if (V8_UNLIKELY(is_shared &&
                          !IsShared(ValueType::RefNull(type), module))) {
            error(pc(), "ref.null does not have a shared type");
            return {};
          }
          if (tracer_) {
            tracer_->InitializerExpression(pc_, pc_ + length + 2,
                                           ValueType::RefNull(type));
          }
          consume_bytes(length + 2);
          return ConstantExpression::RefNull(type.representation());
        }
        break;
      }
      default:
        break;
    }
#undef TYPE_CHECK

    auto sig = FixedSizeSignature<ValueType>::Returns(expected);
    FunctionBody body(&sig, this->pc_offset(), pc_, end_, is_shared);
    WasmDetectedFeatures detected;
    ConstantExpression result;
    {
      // We need a scope for the decoder because its destructor resets some Zone
      // elements, which has to be done before we reset the Zone afterwards.
      WasmFullDecoder<Decoder::FullValidationTag, ConstantExpressionInterface,
                      kConstantExpression>
          decoder(&init_expr_zone_, module, enabled_features_, &detected, body,
                  module);

      uint32_t offset = this->pc_offset();

      decoder.DecodeFunctionBody();

      if (tracer_) {
        // In case of error, decoder.end() is set to the position right before
        // the byte(s) that caused the error. For debugging purposes, we should
        // print these bytes, but we don't know how many of them there are, so
        // for now we have to guess. For more accurate behavior, we'd have to
        // pass {num_invalid_bytes} to every {decoder->DecodeError()} call.
        static constexpr size_t kInvalidBytesGuess = 4;
        const uint8_t* end =
            decoder.ok() ? decoder.end()
                         : std::min(decoder.end() + kInvalidBytesGuess, end_);
        tracer_->InitializerExpression(pc_, end, expected);
      }
      this->pc_ = decoder.end();

      if (decoder.failed()) {
        error(decoder.error().offset(), decoder.error().message().c_str());
        return {};
      }

      if (!decoder.interface().end_found()) {
        error("constant expression is missing 'end'");
        return {};
      }

      result = ConstantExpression::WireBytes(
          offset, static_cast<uint32_t>(decoder.end() - decoder.start()));
    }

    // We reset the zone here; its memory is not used anymore, and we do not
    // want memory from all constant expressions to add up.
    init_expr_zone_.Reset();

    return result;
  }

  // Read a mutability flag
  bool consume_mutability() {
    if (tracer_) tracer_->Bytes(pc_, 1);
    uint8_t val = consume_u8("mutability");
    if (tracer_) {
      tracer_->Description(val == 0   ? " immutable"
                           : val == 1 ? " mutable"
                                      : " invalid");
    }
    if (val > 1) error(pc_ - 1, "invalid mutability");
    return val != 0;
  }

  ValueType consume_value_type() {
    auto [result, length] =
        value_type_reader::read_value_type<FullValidationTag>(
            this, pc_,
            module_->origin == kWasmOrigin ? enabled_features_
                                           : WasmEnabledFeatures::None());
    value_type_reader::ValidateValueType<FullValidationTag>(
        this, pc_, module_.get(), result);
    if (tracer_) {
      tracer_->Bytes(pc_, length);
      tracer_->Description(result);
    }
    consume_bytes(length, "value type");
    return result;
  }

  ValueType consume_storage_type() {
    uint8_t opcode = read_u8<FullValidationTag>(this->pc());
    switch (opcode) {
      case kI8Code:
        consume_bytes(1, " i8", tracer_);
        return kWasmI8;
      case kI16Code:
        consume_bytes(1, " i16", tracer_);
        return kWasmI16;
      default:
        // It is not a packed type, so it has to be a value type.
        return consume_value_type();
    }
  }

  const FunctionSig* consume_sig(Zone* zone) {
    if (tracer_) tracer_->NextLine();
    // Parse parameter types.
    uint32_t param_count =
        consume_count("param count", kV8MaxWasmFunctionParams);
    // We don't know the return count yet, so decode the parameters into a
    // temporary SmallVector. This needs to be copied over into the permanent
    // storage later.
    base::SmallVector<ValueType, 8> params{param_count};
    for (uint32_t i = 0; i < param_count; ++i) {
      params[i] = consume_value_type();
      if (tracer_) tracer_->NextLineIfFull();
    }
    if (tracer_) tracer_->NextLineIfNonEmpty();

    // Parse return types.
    uint32_t return_count =
        consume_count("return count", kV8MaxWasmFunctionReturns);
    // Now that we know the param count and the return count, we can allocate
    // the permanent storage.
    ValueType* sig_storage =
        zone->AllocateArray<ValueType>(param_count + return_count);
    // Note: Returns come first in the signature storage.
    std::copy_n(params.begin(), param_count, sig_storage + return_count);
    for (uint32_t i = 0; i < return_count; ++i) {
      sig_storage[i] = consume_value_type();
      if (tracer_) tracer_->NextLineIfFull();
    }
    if (tracer_) tracer_->NextLineIfNonEmpty();

    return zone->New<FunctionSig>(return_count, param_count, sig_storage);
  }

  const StructType* consume_struct(Zone* zone) {
    uint32_t field_count =
        consume_count(", field count", kV8MaxWasmStructFields);
    if (failed()) return nullptr;
    ValueType* fields = zone->AllocateArray<ValueType>(field_count);
    bool* mutabilities = zone->AllocateArray<bool>(field_count);
    for (uint32_t i = 0; ok() && i < field_count; ++i) {
      fields[i] = consume_storage_type();
      mutabilities[i] = consume_mutability();
      if (tracer_) tracer_->NextLine();
    }
    if (failed()) return nullptr;
    uint32_t* offsets = zone->AllocateArray<uint32_t>(field_count);
    StructType* result =
        zone->New<StructType>(field_count, offsets, fields, mutabilities);
    result->InitializeOffsets();
    return result;
  }

  const ArrayType* consume_array(Zone* zone) {
    ValueType element_type = consume_storage_type();
    bool mutability = consume_mutability();
    if (tracer_) tracer_->NextLine();
    if (failed()) return nullptr;
    return zone->New<ArrayType>(element_type, mutability);
  }

  // Consume the attribute field of an exception.
  uint32_t consume_exception_attribute() {
    const uint8_t* pos = pc_;
    uint32_t attribute = consume_u32v("exception attribute");
    if (tracer_) tracer_->Bytes(pos, static_cast<uint32_t>(pc_ - pos));
    if (attribute != kExceptionAttribute) {
      errorf(pos, "exception attribute %u not supported", attribute);
      return 0;
    }
    return attribute;
  }

  WasmElemSegment consume_element_segment_header() {
    const uint8_t* pos = pc();

    // The mask for the bit in the flag which indicates if the segment is
    // active or not (0 is active).
    constexpr uint8_t kNonActiveMask = 1 << 0;
    // The mask for the bit in the flag which indicates:
    // - for active tables, if the segment has an explicit table index field.
    // - for non-active tables, whether the table is declarative (vs. passive).
    constexpr uint8_t kHasTableIndexOrIsDeclarativeMask = 1 << 1;
    // The mask for the bit in the flag which indicates if the functions of this
    // segment are defined as function indices (0) or constant expressions (1).
    constexpr uint8_t kExpressionsAsElementsMask = 1 << 2;
    // The mask for the bit which denotes whether this segment is shared.
    constexpr uint8_t kSharedFlag = 1 << 3;
    constexpr uint8_t kFullMask = kNonActiveMask |
                                  kHasTableIndexOrIsDeclarativeMask |
                                  kExpressionsAsElementsMask | kSharedFlag;

    uint32_t flag = consume_u32v("flag", tracer_);
    if ((flag & kFullMask) != flag) {
      errorf(pos, "illegal flag value %u", flag);
      return {};
    }

    bool is_shared = flag & kSharedFlag;
    if (is_shared && !v8_flags.experimental_wasm_shared) {
      errorf(pos,
             "illegal flag value %u, enable with --experimental-wasm-shared",
             flag);
      return {};
    }
    if (is_shared) module_->has_shared_part = true;

    const WasmElemSegment::Status status =
        (flag & kNonActiveMask) ? (flag & kHasTableIndexOrIsDeclarativeMask)
                                      ? WasmElemSegment::kStatusDeclarative
                                      : WasmElemSegment::kStatusPassive
                                : WasmElemSegment::kStatusActive;
    const bool is_active = status == WasmElemSegment::kStatusActive;
    if (tracer_) {
      tracer_->Description(": ");
      tracer_->Description(status == WasmElemSegment::kStatusActive ? "active"
                           : status == WasmElemSegment::kStatusPassive
                               ? "passive,"
                               : "declarative,");
    }

    WasmElemSegment::ElementType element_type =
        flag & kExpressionsAsElementsMask
            ? WasmElemSegment::kExpressionElements
            : WasmElemSegment::kFunctionIndexElements;

    const bool has_table_index =
        is_active && (flag & kHasTableIndexOrIsDeclarativeMask);
    uint32_t table_index = 0;
    if (has_table_index) {
      table_index = consume_u32v(", table index", tracer_);
      if (tracer_) tracer_->Description(table_index);
    }
    if (V8_UNLIKELY(is_active && table_index >= module_->tables.size())) {
      // If `has_table_index`, we have an explicit table index. Otherwise, we
      // always have the implicit table index 0.
      errorf(pos, "out of bounds%s table index %u",
             has_table_index ? "" : " implicit", table_index);
      return {};
    }

    ValueType table_type =
        is_active ? module_->tables[table_index].type : kWasmBottom;

    ConstantExpression offset;
    if (is_active) {
      if (tracer_) {
        tracer_->Description(", offset:");
        tracer_->NextLine();
      }
      offset = consume_init_expr(
          module_.get(),
          module_->tables[table_index].is_table64() ? kWasmI64 : kWasmI32,
          is_shared);
      // Failed to parse offset initializer, return early.
      if (failed()) return {};
    }

    // Denotes an active segment without table index, type, or element kind.
    const bool backwards_compatible_mode =
        is_active && !(flag & kHasTableIndexOrIsDeclarativeMask);
    ValueType type;
    if (element_type == WasmElemSegment::kExpressionElements) {
      if (backwards_compatible_mode) {
        type = kWasmFuncRef;
      } else {
        if (tracer_) tracer_->Description(" element type:");
        type = consume_value_type();
        if (failed()) return {};
      }
    } else {
      if (!backwards_compatible_mode) {
        // We have to check that there is an element kind of type Function. All
        // other element kinds are not valid yet.
        if (tracer_) tracer_->Description(" ");
        uint8_t val = consume_u8("element type: function", tracer_);
        if (V8_UNLIKELY(static_cast<ImportExportKindCode>(val) !=
                        kExternalFunction)) {
          errorf(pos, "illegal element kind 0x%x. Must be 0x%x", val,
                 kExternalFunction);
          return {};
        }
      }
      type = kWasmFuncRef.AsNonNull();
    }

    if (V8_UNLIKELY(is_active &&
                    !IsSubtypeOf(type, table_type, this->module_.get()))) {
      errorf(pos,
             "Element segment of type %s is not a subtype of referenced "
             "table %u (of type %s)",
             type.name().c_str(), table_index, table_type.name().c_str());
      return {};
    }

    // TODO(14616): Is this too restrictive?
    if (V8_UNLIKELY(is_active &&
                    (is_shared != module_->tables[table_index].shared))) {
      error(pos,
            "Shared (resp. non-shared) element segments must refer to shared "
            "(resp. non-shared) tables");
      return {};
    }

    uint32_t num_elem =
        consume_count(" number of elements", max_table_init_entries());

    if (is_active) {
      return {is_shared,    type,     table_index, std::move(offset),
              element_type, num_elem, pc_offset()};
    } else {
      return {status, is_shared, type, element_type, num_elem, pc_offset()};
    }
  }

  DataSegmentHeader consume_data_segment_header() {
    const uint8_t* pos = pc();
    uint32_t flag = consume_u32v("flag", tracer_);

    if (flag & ~0b1011) {
      errorf(pos, "illegal flag value %u", flag);
      return {};
    }

    uint32_t status_flag = flag & 0b11;

    if (tracer_) {
      tracer_->Description(": ");
      tracer_->Description(
          status_flag == SegmentFlags::kActiveNoIndex     ? "active no index"
          : status_flag == SegmentFlags::kPassive         ? "passive"
          : status_flag == SegmentFlags::kActiveWithIndex ? "active with index"
                                                          : "unknown");
    }

    if (status_flag != SegmentFlags::kActiveNoIndex &&
        status_flag != SegmentFlags::kPassive &&
        status_flag != SegmentFlags::kActiveWithIndex) {
      errorf(pos, "illegal flag value %u", flag);
      return {};
    }

    bool is_shared = flag & 0b1000;

    if (V8_UNLIKELY(is_shared && !v8_flags.experimental_wasm_shared)) {
      errorf(pos,
             "illegal flag value %u. Enable with --experimental-wasm-shared",
             flag);
      return {};
    }

    if (is_shared) module_->has_shared_part = true;

    if (tracer_) {
      if (is_shared) tracer_->Description(" shared");
      tracer_->NextLine();
    }

    bool is_active = status_flag == SegmentFlags::kActiveNoIndex ||
                     status_flag == SegmentFlags::kActiveWithIndex;
    uint32_t mem_index = status_flag == SegmentFlags::kActiveWithIndex
                             ? consume_u32v("memory index", tracer_)
                             : 0;
    ConstantExpression offset;

    if (is_active) {
      size_t num_memories = module_->memories.size();
      if (mem_index >= num_memories) {
        errorf(pos,
               "invalid memory index %u for data section (having %zu memor%s)",
               mem_index, num_memories, num_memories == 1 ? "y" : "ies");
        return {};
      }
      ValueType expected_type =
          module_->memories[mem_index].is_memory64() ? kWasmI64 : kWasmI32;
      offset = consume_init_expr(module_.get(), expected_type, is_shared);
    }

    return {is_active, is_shared, mem_index, offset};
  }

  uint32_t consume_element_func_index(WasmModule* module, ValueType expected) {
    WasmFunction* func = nullptr;
    const uint8_t* initial_pc = pc();
    uint32_t index = consume_func_index(module, &func);
    if (tracer_) trace
```