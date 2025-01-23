Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/wasm/wasm-serialization.cc`. This is the second part of a multi-part code snippet.

Here's a breakdown of the thinking process to answer the user's request:

1. **Identify the Core Purpose:** The filename `wasm-serialization.cc` strongly suggests that the code is responsible for serializing and deserializing WebAssembly modules. Given this is "part 2", the current snippet is likely focused on *deserialization*.

2. **Examine the Classes and Methods:**
    * `NativeModuleDeserializer`: This class is central to the provided code. Its methods like `ReadHeader`, `ReadCode`, `CopyAndRelocate`, `ReadTieringBudget`, and `Publish` clearly relate to the process of reconstructing a WebAssembly module from a serialized representation.
    * `DeserializeNativeModule`: This function appears to be the entry point for the deserialization process. It takes the serialized data and other related information as input and attempts to create a `WasmModuleObject`.

3. **Analyze Key Functionalities within `NativeModuleDeserializer`:**
    * **`ReadHeader`:** This reads initial information like detected features, code size, import details, and constant pool data.
    * **`ReadCode`:** This is crucial. It reads the bytecode and metadata for individual functions. It distinguishes between `kLazyFunction` and `kEagerFunction`, indicating support for different compilation strategies. It also handles allocating memory for the code (`current_code_space_`).
    * **`CopyAndRelocate`:**  This function takes the raw code bytes and relocates addresses within the code, resolving references to functions, builtins, and external resources. This is a critical step in making the deserialized code executable.
    * **`ReadTieringBudget`:** This reads data related to dynamic tiering (optimization) of WebAssembly code.
    * **`Publish`:** This appears to finalize the deserialization of a batch of functions, making the `WasmCode` objects available.

4. **Analyze `DeserializeNativeModule`:**
    * **Version Check:** It verifies the compatibility of the serialized data with the current V8 version.
    * **Decoding:** It decodes the WebAssembly module's wire format using `DecodeWasmModule`.
    * **Native Module Management:** It checks if a native module for the given wire bytes already exists in the cache and reuses it if possible. Otherwise, it creates a new one.
    * **Deserialization Invocation:** It instantiates `NativeModuleDeserializer` and calls its `Read` method.
    * **Module Object Creation:** Finally, it creates a `WasmModuleObject` which represents the deserialized module in the V8 runtime.

5. **Address Specific Questions from the Prompt:**

    * **Functionality:** Summarize the core purpose identified in steps 1-4.
    * **`.tq` Extension:**  The code is C++, so it's not a Torque file.
    * **JavaScript Relationship:** Deserialization is essential for loading and running WebAssembly code in JavaScript. Provide an example using `WebAssembly.instantiate`.
    * **Code Logic Inference (Input/Output):**  Focus on the `ReadCode` method. Hypothesize an input (data for a function) and the corresponding output (`DeserializationUnit`).
    * **Common Programming Errors:**  Think about potential issues during serialization or deserialization, like version mismatches or corrupted data.
    * **Overall Functionality (Part 2):** Summarize the actions described in this specific code snippet, emphasizing the deserialization aspect. Since this is part 2, acknowledge that part 1 likely handled serialization.

6. **Structure the Answer:** Organize the information logically, addressing each point from the user's prompt. Use clear and concise language. Provide code examples where requested.

7. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might just say it handles relocation, but it's better to explain *what* is being relocated (function calls, builtins, etc.).
这是v8源代码文件 `v8/src/wasm/wasm-serialization.cc` 的第二部分，延续了第一部分的功能，主要负责**反序列化 (deserialization) WebAssembly 模块**。

以下是该部分代码的功能归纳：

**核心功能：将序列化的 WebAssembly 模块数据还原为可执行的 V8 内部表示。**

具体来说，该部分代码主要实现了 `NativeModuleDeserializer` 类和 `DeserializeNativeModule` 函数，用于执行以下操作：

1. **读取序列化头信息 (`ReadHeader`)**:
   - 读取 WebAssembly 检测到的特性 (detected features)。
   - 读取剩余的代码大小。
   - 读取所有函数是否已验证的标志。
   - 读取编译时导入信息 (compile-time imports)。
   - 读取 well-known imports 信息。

2. **读取函数代码 (`ReadCode`)**:
   - 逐个读取序列化后的 WebAssembly 函数的代码和元数据。
   - 根据 `code_kind` ( `kLazyFunction` 或 `kEagerFunction`) 区分延迟编译和立即编译的函数。
   - 读取常量池、安全点表、异常处理表、代码注释、未填充的二进制大小、栈槽数量、溢出槽数量、参数槽数量、代码大小、重定位信息大小、源码位置信息大小、内联位置信息大小、去优化数据大小、保护指令大小、代码种类和执行层级等信息。
   - 从预先分配的代码空间中分配内存来存储函数代码。

3. **复制和重定位代码 (`CopyAndRelocate`)**:
   - 将读取到的代码复制到分配的内存中。
   - 遍历代码的重定位信息，根据不同的重定位类型 (例如 WASM_CALL, WASM_STUB_CALL, WASM_CANONICAL_SIG_ID, EXTERNAL_REFERENCE, INTERNAL_REFERENCE)  修复代码中的地址引用，使其指向正确的函数、内置函数、全局变量等。
   - 清理指令缓存 (flush the icache)。

4. **读取分层编译预算 (`ReadTieringBudget`)**:
   - 读取用于 WebAssembly 分层编译的预算信息。

5. **发布代码 (`Publish`)**:
   - 将反序列化后的 `WasmCode` 对象发布到 `NativeModule` 中，使其可以被执行。

6. **顶层反序列化函数 (`DeserializeNativeModule`)**:
   - 接收序列化的数据、原始的 WebAssembly 字节码、编译时导入信息和源码 URL。
   - 检查序列化数据的版本是否支持。
   - 解码 WebAssembly 模块的原始字节码 (`DecodeWasmModule`)。
   - 尝试从缓存中获取已存在的 `NativeModule`，如果不存在则创建一个新的。
   - 创建 `NativeModuleDeserializer` 对象并调用 `Read` 方法来执行反序列化过程。
   - 在反序列化完成后，初始化 `NativeModule` 的状态。
   - 创建 `WasmModuleObject`，它是 JavaScript 中 `WebAssembly.Module` 的实例。
   - 将编译后的脚本信息通知调试器。
   - 记录 WebAssembly 代码信息用于性能分析。

**关于问题：**

* **`.tq` 结尾:**  `v8/src/wasm/wasm-serialization.cc` 以 `.cc` 结尾，这是一个 C++ 源代码文件，不是 Torque 源代码。Torque 文件的扩展名是 `.tq`。

* **与 JavaScript 的关系:**  `v8/src/wasm/wasm-serialization.cc` 中的反序列化功能直接关系到 JavaScript 如何加载和运行 WebAssembly 代码。当 JavaScript 代码调用 `WebAssembly.Module` 或 `WebAssembly.instantiate` 加载一个已经编译过的 WebAssembly 模块时，V8 引擎会使用这里的反序列化逻辑来恢复模块的内部表示。

   **JavaScript 示例:**

   ```javascript
   // 假设 wasmModuleBytes 是一个包含序列化 WebAssembly 模块数据的 Uint8Array
   const wasmModuleBytes = new Uint8Array(/* ... 序列化的模块数据 ... */);

   // 加载已经编译过的 WebAssembly 模块 (这里假设 V8 内部有缓存)
   WebAssembly.instantiate(wasmModuleBytes)
     .then(result => {
       console.log("WebAssembly 模块加载成功", result.instance);
     })
     .catch(error => {
       console.error("加载 WebAssembly 模块失败", error);
     });
   ```

   在这个例子中，虽然我们传递的是字节码，但如果 V8 内部存在该模块的序列化版本，它就会使用反序列化来加载，而不是重新编译。

* **代码逻辑推理 (假设输入与输出):**

   假设我们正在反序列化一个简单的 WebAssembly 函数，它的代码大小为 `100` 字节，包含一些重定位信息。

   **假设输入 (在 `ReadCode` 方法中):**

   - `reader` 当前指向函数代码的起始位置。
   - `reader` 读取到的信息如下 (示例值):
     - `code_kind`: `kEagerFunction` (假设是立即编译的函数)
     - `constant_pool_offset`: 10
     - `safepoint_table_offset`: 50
     - ... (其他元数据的大小和偏移量)
     - `code_size`: 100
     - `reloc_size`: 20
     - ... (其他元数据的大小)
     - `src_code_buffer` (从 reader 中读取的 100 字节代码) : `[0xFA, 0x1B, 0xCC, ...]`
     - `reloc_info` (从 reader 中读取的 20 字节重定位信息): `[0x01, 0x02, 0x03, ...]`

   **预期输出 (在 `ReadCode` 方法中):**

   - `unit` (一个 `DeserializationUnit` 对象) 包含以下信息:
     - `src_code_buffer`:  `base::Vector<uint8_t>`，包含读取到的 100 字节代码 `[0xFA, 0x1B, 0xCC, ...]`。
     - `code`: 指向新创建的 `WasmCode` 对象的指针，该对象包含了函数的元数据 (大小、偏移量等) 和指向代码内存的指针。
     - `jump_tables`: 当前的代码跳转表。
   - `current_code_space_` 指针会前进 `100` 字节。
   - `remaining_code_size_` 会减少 `100`。

   **假设输入 (在 `CopyAndRelocate` 方法中):**

   - `unit` 是 `ReadCode` 方法的输出。
   - `unit.code->reloc_info()` 包含需要重定位的信息，例如一个 `WASM_CALL` 类型的重定位项，指向模块中的另一个函数。

   **预期输出 (在 `CopyAndRelocate` 方法中):**

   - `unit.code->instructions()` 指向的内存区域中，`WASM_CALL` 指令的操作数会被修改，指向目标函数的实际内存地址。
   - 指令缓存会被清理，确保 CPU 执行到最新的代码。

* **用户常见的编程错误:**

   虽然这个文件是 V8 内部的实现，但与用户编程相关的错误通常发生在**序列化和反序列化的数据不一致**或**版本不兼容**时。

   **示例:**

   1. **使用旧版本的 V8 序列化了 WebAssembly 模块，然后尝试在新版本的 V8 中反序列化:** 新版本的 V8 可能添加了新的特性或修改了数据结构，导致反序列化失败或产生不可预测的行为。错误消息可能类似于 "Unsupported serialized data version"。

   2. **手动修改了序列化后的 WebAssembly 模块数据:**  任何对序列化数据的修改都可能破坏其结构，导致反序列化时出现校验错误、内存访问错误或其他崩溃。

   3. **在不同的编译配置下序列化和反序列化:** 例如，在一个启用了某些实验性 WebAssembly 特性的 V8 版本中序列化，然后在未启用这些特性的版本中反序列化，可能会导致错误。

**归纳一下 `v8/src/wasm/wasm-serialization.cc` 的功能 (第 2 部分):**

该文件的第二部分专注于 **反序列化已经序列化过的 WebAssembly 模块**。它定义了 `NativeModuleDeserializer` 类及其相关方法，负责从二进制数据中读取模块的各种组件（头信息、函数代码、元数据、重定位信息等），并将这些信息恢复成 V8 引擎可以理解和执行的内部表示。`DeserializeNativeModule` 函数是反序列化的入口点，它负责协调整个反序列化过程，并最终创建可以在 JavaScript 中使用的 `WebAssembly.Module` 对象。这部分代码是 V8 引擎支持快速加载编译后的 WebAssembly 模块的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/wasm-serialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-serialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
_limit) {
      reloc_queue.Add(std::move(batch));
      DCHECK(batch.empty());
      batch_size = 0;
      job_handle->NotifyConcurrencyIncrease();
    }
  }

  // We should have read the expected amount of code now, and should have fully
  // utilized the allocated code space.
  DCHECK_EQ(0, remaining_code_size_);
  DCHECK_EQ(0, current_code_space_.size());

  if (!batch.empty()) {
    reloc_queue.Add(std::move(batch));
    job_handle->NotifyConcurrencyIncrease();
  }

  // Wait for all tasks to finish, while participating in their work.
  job_handle->Join();

  ReadTieringBudget(reader);
  return reader->current_size() == 0;
}

void NativeModuleDeserializer::ReadHeader(Reader* reader) {
  WasmDetectedFeatures detected_features = WasmDetectedFeatures::FromIntegral(
      reader->Read<WasmDetectedFeatures::StorageType>());
  // Ignore the return value of UpdateDetectedFeatures; all features will be
  // published after deserialization anyway.
  USE(native_module_->compilation_state()->UpdateDetectedFeatures(
      detected_features));

  remaining_code_size_ = reader->Read<size_t>();

  all_functions_validated_ = reader->Read<bool>();

  auto compile_imports_flags =
      reader->Read<CompileTimeImportFlags::StorageType>();
  uint32_t constants_module_size = reader->Read<uint32_t>();
  base::Vector<const char> constants_module_data =
      reader->ReadVector<char>(constants_module_size);
  compile_imports_ = CompileTimeImports::FromSerialized(compile_imports_flags,
                                                        constants_module_data);

  uint32_t imported = native_module_->module()->num_imported_functions;
  if (imported > 0) {
    base::Vector<const WellKnownImport> well_known_imports =
        reader->ReadVector<WellKnownImport>(imported);
    native_module_->module()->type_feedback.well_known_imports.Initialize(
        well_known_imports);
  }
}

DeserializationUnit NativeModuleDeserializer::ReadCode(int fn_index,
                                                       Reader* reader) {
  uint8_t code_kind = reader->Read<uint8_t>();
  if (code_kind == kLazyFunction) {
    lazy_functions_.push_back(fn_index);
    return {};
  }
  if (code_kind == kEagerFunction) {
    eager_functions_.push_back(fn_index);
    return {};
  }

  int constant_pool_offset = reader->Read<int>();
  int safepoint_table_offset = reader->Read<int>();
  int handler_table_offset = reader->Read<int>();
  int code_comment_offset = reader->Read<int>();
  int unpadded_binary_size = reader->Read<int>();
  int stack_slot_count = reader->Read<int>();
  int ool_spill_count = reader->Read<int>();
  uint32_t tagged_parameter_slots = reader->Read<uint32_t>();
  int code_size = reader->Read<int>();
  int reloc_size = reader->Read<int>();
  int source_position_size = reader->Read<int>();
  int inlining_position_size = reader->Read<int>();
  int deopt_data_size = reader->Read<int>();
  // TODO(mliedtke): protected_instructions_data is the first part of the
  // meta_data_ array. Ideally the sizes would be in the same order...
  int protected_instructions_size = reader->Read<int>();
  WasmCode::Kind kind = reader->Read<WasmCode::Kind>();
  ExecutionTier tier = reader->Read<ExecutionTier>();

  DCHECK(IsAligned(code_size, kCodeAlignment));
  DCHECK_GE(remaining_code_size_, code_size);
  if (current_code_space_.size() < static_cast<size_t>(code_size)) {
    // Allocate the next code space. Don't allocate more than 90% of
    // {kMaxCodeSpaceSize}, to leave some space for jump tables.
    size_t max_reservation = RoundUp<kCodeAlignment>(
        v8_flags.wasm_max_code_space_size_mb * MB * 9 / 10);
    size_t code_space_size = std::min(max_reservation, remaining_code_size_);
    std::tie(current_code_space_, current_jump_tables_) =
        native_module_->AllocateForDeserializedCode(code_space_size);
    DCHECK_EQ(current_code_space_.size(), code_space_size);
    CHECK(current_jump_tables_.is_valid());
  }

  DeserializationUnit unit;
  unit.src_code_buffer = reader->ReadVector<uint8_t>(code_size);
  auto reloc_info = reader->ReadVector<uint8_t>(reloc_size);
  auto source_pos = reader->ReadVector<uint8_t>(source_position_size);
  auto inlining_pos = reader->ReadVector<uint8_t>(inlining_position_size);
  auto deopt_data = reader->ReadVector<uint8_t>(deopt_data_size);
  auto protected_instructions =
      reader->ReadVector<uint8_t>(protected_instructions_size);

  base::Vector<uint8_t> instructions =
      current_code_space_.SubVector(0, code_size);
  current_code_space_ += code_size;
  remaining_code_size_ -= code_size;

  unit.code = native_module_->AddDeserializedCode(
      fn_index, instructions, stack_slot_count, ool_spill_count,
      tagged_parameter_slots, safepoint_table_offset, handler_table_offset,
      constant_pool_offset, code_comment_offset, unpadded_binary_size,
      protected_instructions, reloc_info, source_pos, inlining_pos, deopt_data,
      kind, tier);
  unit.jump_tables = current_jump_tables_;
  return unit;
}

void NativeModuleDeserializer::CopyAndRelocate(
    const DeserializationUnit& unit) {
  WritableJitAllocation jit_allocation = ThreadIsolation::RegisterJitAllocation(
      reinterpret_cast<Address>(unit.code->instructions().begin()),
      unit.code->instructions().size(),
      ThreadIsolation::JitAllocationType::kWasmCode, false);

  jit_allocation.CopyCode(0, unit.src_code_buffer.begin(),
                          unit.src_code_buffer.size());

  // Relocate the code.
  int kMask = RelocInfo::ModeMask(RelocInfo::WASM_CALL) |
              RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL) |
              RelocInfo::ModeMask(RelocInfo::WASM_CANONICAL_SIG_ID) |
              RelocInfo::ModeMask(RelocInfo::WASM_INDIRECT_CALL_TARGET) |
              RelocInfo::ModeMask(RelocInfo::EXTERNAL_REFERENCE) |
              RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
              RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE_ENCODED);
  for (WritableRelocIterator iter(jit_allocation, unit.code->instructions(),
                                  unit.code->reloc_info(),
                                  unit.code->constant_pool(), kMask);
       !iter.done(); iter.next()) {
    RelocInfo::Mode mode = iter.rinfo()->rmode();
    switch (mode) {
      case RelocInfo::WASM_CALL: {
        uint32_t tag = GetWasmCalleeTag(iter.rinfo());
        Address target =
            native_module_->GetNearCallTargetForFunction(tag, unit.jump_tables);
        iter.rinfo()->set_wasm_call_address(target);
        break;
      }
      case RelocInfo::WASM_STUB_CALL: {
        uint32_t tag = GetWasmCalleeTag(iter.rinfo());
        Address target = native_module_->GetJumpTableEntryForBuiltin(
            static_cast<Builtin>(tag), unit.jump_tables);
        iter.rinfo()->set_wasm_stub_call_address(target);
        break;
      }
      case RelocInfo::WASM_CANONICAL_SIG_ID: {
        // This is intentional: in serialized code, we patched embedded
        // canonical signature IDs with their module-specific equivalents,
        // so although the accessor is called "wasm_canonical_sig_id()", what
        // we get back is actually a module-specific signature ID, which we
        // now need to translate back to a canonical ID.
        ModuleTypeIndex module_local_sig_id{
            iter.rinfo()->wasm_canonical_sig_id()};
        CanonicalTypeIndex canonical_sig_id =
            native_module_->module()->canonical_sig_id(module_local_sig_id);
        iter.rinfo()->set_wasm_canonical_sig_id(canonical_sig_id.index);
      } break;
      case RelocInfo::WASM_INDIRECT_CALL_TARGET: {
        Address function_index = iter.rinfo()->wasm_indirect_call_target();
        WasmCodePointer target = native_module_->GetIndirectCallTarget(
            base::checked_cast<uint32_t>(function_index));
        iter.rinfo()->set_wasm_indirect_call_target(target, SKIP_ICACHE_FLUSH);
      } break;
      case RelocInfo::EXTERNAL_REFERENCE: {
        uint32_t tag = GetWasmCalleeTag(iter.rinfo());
        Address address = ExternalReferenceList::Get().address_from_tag(tag);
        iter.rinfo()->set_target_external_reference(address, SKIP_ICACHE_FLUSH);
        break;
      }
      case RelocInfo::INTERNAL_REFERENCE:
      case RelocInfo::INTERNAL_REFERENCE_ENCODED: {
        Address offset = iter.rinfo()->target_internal_reference();
        Address target = unit.code->instruction_start() + offset;
        Assembler::deserialization_set_target_internal_reference_at(
            iter.rinfo()->pc(), target, mode);
        break;
      }
      default:
        UNREACHABLE();
    }
  }

  // Finally, flush the icache for that code.
  FlushInstructionCache(unit.code->instructions().begin(),
                        unit.code->instructions().size());
}

void NativeModuleDeserializer::ReadTieringBudget(Reader* reader) {
  size_t size_of_tiering_budget =
      native_module_->module()->num_declared_functions * sizeof(uint32_t);
  if (size_of_tiering_budget > reader->current_size()) {
    return;
  }
  base::Vector<const uint8_t> serialized_budget =
      reader->ReadVector<const uint8_t>(size_of_tiering_budget);

  memcpy(native_module_->tiering_budget_array(), serialized_budget.begin(),
         size_of_tiering_budget);
}

void NativeModuleDeserializer::Publish(std::vector<DeserializationUnit> batch) {
  DCHECK(!batch.empty());
  std::vector<std::unique_ptr<WasmCode>> codes;
  codes.reserve(batch.size());
  for (auto& unit : batch) {
    codes.emplace_back(std::move(unit).code);
  }
  auto published_codes = native_module_->PublishCode(base::VectorOf(codes));
  for (auto* wasm_code : published_codes) {
    wasm_code->MaybePrint();
    wasm_code->Validate();
  }
}

bool IsSupportedVersion(base::Vector<const uint8_t> header,
                        WasmEnabledFeatures enabled_features) {
  if (header.size() < WasmSerializer::kHeaderSize) return false;
  uint8_t current_version[WasmSerializer::kHeaderSize];
  Writer writer({current_version, WasmSerializer::kHeaderSize});
  WriteHeader(&writer, enabled_features);
  return memcmp(header.begin(), current_version, WasmSerializer::kHeaderSize) ==
         0;
}

MaybeHandle<WasmModuleObject> DeserializeNativeModule(
    Isolate* isolate, base::Vector<const uint8_t> data,
    base::Vector<const uint8_t> wire_bytes_vec,
    const CompileTimeImports& compile_imports,
    base::Vector<const char> source_url) {
  WasmEnabledFeatures enabled_features =
      WasmEnabledFeatures::FromIsolate(isolate);
  if (!IsWasmCodegenAllowed(isolate, isolate->native_context())) return {};
  if (!IsSupportedVersion(data, enabled_features)) return {};

  // Make the copy of the wire bytes early, so we use the same memory for
  // decoding, lookup in the native module cache, and insertion into the cache.
  auto owned_wire_bytes = base::OwnedVector<uint8_t>::Of(wire_bytes_vec);

  WasmDetectedFeatures detected_features;
  ModuleResult decode_result = DecodeWasmModule(
      enabled_features, owned_wire_bytes.as_vector(), false,
      i::wasm::kWasmOrigin, isolate->counters(), isolate->metrics_recorder(),
      isolate->GetOrRegisterRecorderContextId(isolate->native_context()),
      DecodingMethod::kDeserialize, &detected_features);
  if (decode_result.failed()) return {};
  std::shared_ptr<WasmModule> module = std::move(decode_result).value();
  CHECK_NOT_NULL(module);

  WasmEngine* wasm_engine = GetWasmEngine();
  auto shared_native_module = wasm_engine->MaybeGetNativeModule(
      module->origin, owned_wire_bytes.as_vector(), compile_imports, isolate);
  if (shared_native_module == nullptr) {
    const bool dynamic_tiering = v8_flags.wasm_dynamic_tiering;
    const bool include_liftoff = !dynamic_tiering;
    size_t code_size_estimate =
        wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
            module.get(), include_liftoff, DynamicTiering{dynamic_tiering});
    shared_native_module = wasm_engine->NewNativeModule(
        isolate, enabled_features, detected_features, compile_imports,
        std::move(module), code_size_estimate);
    // We have to assign a compilation ID here, as it is required for a
    // potential re-compilation, e.g. triggered by
    // {EnterDebuggingForIsolate}. The value is -2 so that it is different
    // than the compilation ID of actual compilations, and also different than
    // the sentinel value of the CompilationState.
    shared_native_module->compilation_state()->set_compilation_id(-2);
    shared_native_module->SetWireBytes(std::move(owned_wire_bytes));

    NativeModuleDeserializer deserializer(shared_native_module.get());
    Reader reader(data + WasmSerializer::kHeaderSize);
    bool error = !deserializer.Read(&reader);
    if (error) {
      wasm_engine->UpdateNativeModuleCache(
          error, std::move(shared_native_module), isolate);
      return {};
    }
    shared_native_module->compilation_state()->InitializeAfterDeserialization(
        deserializer.lazy_functions(), deserializer.eager_functions());
    wasm_engine->UpdateNativeModuleCache(error, shared_native_module, isolate);
    // Now publish the full set of detected features (read during
    // deserialization, so potentially more than from DecodeWasmModule above).
    detected_features =
        shared_native_module->compilation_state()->detected_features();
    PublishDetectedFeatures(detected_features, isolate, true);
  }

  DirectHandle<Script> script =
      wasm_engine->GetOrCreateScript(isolate, shared_native_module, source_url);
  Handle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate, shared_native_module, script);

  // Finish the Wasm script now and make it public to the debugger.
  isolate->debug()->OnAfterCompile(script);

  // Log the code within the generated module for profiling.
  shared_native_module->LogWasmCodes(isolate, *script);

  return module_object;
}

}  // namespace v8::internal::wasm
```