Response:
The user wants a summary of the functionality of the provided C++ source code file `v8/src/wasm/wasm-code-manager.cc`. I need to identify the key responsibilities of this file within the V8 WebAssembly implementation. The user also has specific conditions to address:

1. **List functionalities:**  I need to enumerate the core tasks this code performs.
2. **Torque check:** Confirm if the file name ends with `.tq`. It doesn't.
3. **JavaScript relation:**  Determine if the code relates to JavaScript functionality and provide a JavaScript example if it does.
4. **Code logic reasoning:** If there are logical deductions or computations, I should provide example inputs and outputs.
5. **Common programming errors:** Identify potential mistakes programmers might make related to the functionality in this file.
6. **Final summary:**  A concise overview of the file's purpose.

Let's break down the code section by section to understand its roles:

- **Memory Management for Wasm Code:**  The code deals with allocating and managing memory for compiled WebAssembly code. This includes initial reservations, committing memory, and potentially freeing unused code. Key functions like `NewNativeModule`, `TryAllocate`, `FreeNativeModule`, and the `code_allocator_` member point to this.
- **Native Modules:**  It seems to manage "NativeModule" objects, which encapsulate a compiled WebAssembly module and its associated metadata.
- **Code Objects:** The code manages individual `WasmCode` objects, representing compiled functions. Functions like `AddCompiledCode` and `RemoveCompiledCode` are relevant here.
- **Code Lookup:** The `LookupCode` functions are responsible for finding the `WasmCode` object corresponding to a given program counter (PC) value. The `WasmCodeLookupCache` is used for optimization.
- **Tiering:** The code mentions "tiering," referring to different optimization levels for WebAssembly code (e.g., Liftoff, Turbofan).
- **Jump Tables:** It handles the creation and management of jump tables for efficient function calls.
- **Debug Information:** The code interacts with `DebugInfo` for debugging WebAssembly.
- **Memory Protection:** Features related to memory protection keys are present.
- **Statistics and Counters:**  The code updates counters related to code size and memory usage.
- **Code References:** The `WasmCodeRefScope` appears to manage the lifetime of `WasmCode` objects.

**JavaScript Relation:** WebAssembly is closely tied to JavaScript. When JavaScript calls a WebAssembly function, or vice-versa, the mechanisms managed by this code are involved.

**Code Logic Reasoning:**  The `EstimateLazyCompileTableSize`, `EstimateNativeModuleMetaDataSize`, and the allocation logic in `NewNativeModule` involve calculations.

**Common Programming Errors:** While the file itself is internal V8 code, understanding its function can help avoid errors like running out of memory for Wasm code, or issues with debugging optimized code.

**Final Summary:** This file is central to managing the compiled WebAssembly code within V8, handling memory allocation, code object lifecycle, and efficient code lookup.

Now, let's structure the answer according to the user's requirements.
这是v8/src/wasm/wasm-code-manager.cc的源代码，它在 V8 的 WebAssembly 实现中扮演着核心角色，主要负责管理已编译的 WebAssembly 代码。以下是其功能的详细列举：

**主要功能:**

1. **WebAssembly 代码内存管理:**
   - **分配代码空间:** 负责为已编译的 WebAssembly 代码分配虚拟内存空间。这包括初始的较大预留空间以及在需要时提交更多内存。
   - **释放代码空间:**  当不再需要时，释放已分配的 WebAssembly 代码内存。
   - **跟踪已提交的代码空间:** 维护当前已提交的代码空间大小，并设置阈值以触发内存压力通知。
   - **代码空间分配策略:**  实现了代码空间的分配策略，例如，避免一次分配超过一半的代码空间，以留出空间给跳转表等开销。

2. **NativeModule 管理:**
   - **创建 NativeModule:**  负责创建 `NativeModule` 对象，该对象封装了一个已编译的 WebAssembly 模块及其相关的元数据和代码。
   - **存储和查找 NativeModule:**  维护一个映射，用于根据代码地址查找对应的 `NativeModule`。

3. **WasmCode 对象管理:**
   - **添加已编译的代码:**  接收编译结果（`WasmCompilationResult`），为编译后的代码分配实际的内存，并将代码复制到分配的空间中。
   - **创建 WasmCode 对象:**  创建 `WasmCode` 对象，该对象表示一个已编译的 WebAssembly 函数，并包含有关该函数的元数据，例如指令地址、大小、调试信息等。
   - **移除已编译的代码:**  根据不同的过滤条件（例如，调试代码、Liftoff 代码、Turbofan 代码）移除不再需要的已编译代码。
   - **跟踪和存储 WasmCode 对象:**  在一个表中存储模块中每个函数的 `WasmCode` 对象。

4. **代码查找 (Code Lookup):**
   - **根据地址查找 WasmCode:**  提供根据程序计数器 (PC) 值查找对应 `WasmCode` 对象的功能，这对于执行 WebAssembly 代码和调试至关重要。
   - **WasmCodeLookupCache:**  使用缓存来加速代码查找过程。

5. **代码分层优化 (Tiering):**
   - 涉及到 Liftoff 和 Turbofan 两种编译层级，并管理它们的代码。
   - 可以刷新 Liftoff 代码以释放内存。

6. **跳转表 (Jump Tables) 管理:**
   - 为 WebAssembly 函数调用分配和管理跳转表。

7. **调试信息 (Debug Info) 管理:**
   -  可以创建和管理 `DebugInfo` 对象，用于存储 WebAssembly 模块的调试信息。

8. **内存保护 (Memory Protection):**
   -  检查系统是否支持内存保护密钥 (Memory Protection Keys, PKU)，并确定是否启用以及当前是否可写。

9. **统计和监控:**
   - 记录已编译的 WebAssembly 代码的大小和元数据大小，用于性能分析和监控。
   - 提供方法来采样代码大小和元数据大小。

10. **代码引用计数 (Code Reference Counting):**
    - 使用 `WasmCodeRefScope` 来管理 `WasmCode` 对象的生命周期，防止在被使用时被意外释放。

**关于文件类型:**

`v8/src/wasm/wasm-code-manager.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系:**

`wasm-code-manager.cc` 直接服务于 JavaScript 中 WebAssembly 的功能。当 JavaScript 代码加载和执行 WebAssembly 模块时，`wasm-code-manager.cc` 中实现的机制负责管理编译后的 WebAssembly 代码，并使其能够被 V8 的 JavaScript 引擎执行。

**JavaScript 示例:**

```javascript
// 加载一个 WebAssembly 模块
WebAssembly.instantiateStreaming(fetch('my_module.wasm'))
  .then(result => {
    const wasmModule = result.instance;

    // 调用 WebAssembly 模块导出的函数
    const resultFromWasm = wasmModule.exports.add(5, 10);
    console.log(resultFromWasm); // 输出 15
  });
```

在这个例子中，当 `WebAssembly.instantiateStreaming` 加载并编译 `my_module.wasm` 时，`wasm-code-manager.cc` 中的代码负责分配内存来存储编译后的机器码，创建 `NativeModule` 和 `WasmCode` 对象来表示这个模块和它的函数。当 JavaScript 调用 `wasmModule.exports.add(5, 10)` 时，V8 需要查找 `add` 函数对应的已编译代码的地址，这个查找过程就可能涉及到 `wasm-code-manager.cc` 中的 `LookupCode` 功能。

**代码逻辑推理 (假设输入与输出):**

假设有一个 WebAssembly 模块包含一个简单的加法函数，编译后其机器码大小为 100 字节。

**假设输入:**

- 一个 `WasmCompilationResult` 对象，描述了加法函数的编译结果，其中 `code_desc.instr_size` 为 100。
- `NativeModule` 对象 `nm`。

**代码逻辑 (在 `NativeModule::AddCompiledCode` 中):**

1. `RoundUp<kCodeAlignment>(result.code_desc.instr_size)` 计算向上对齐后的代码大小，假设 `kCodeAlignment` 为 8，则结果为 104。
2. `code_allocator_.AllocateForCode(this, total_code_space)` 会尝试从 `nm` 的代码空间中分配 104 字节的内存。
3. 如果分配成功，返回一个指向已分配内存的指针 `code_space`。
4. 代码会将编译后的机器码从 `result.code_desc.buffer` 复制到 `code_space` 指向的内存区域。
5. 创建一个 `WasmCode` 对象，其 `instruction_start()` 将指向 `code_space` 的起始地址，`instructions_size()` 为 100。

**假设输出:**

- 在 `nm` 的代码空间中分配了 104 字节的连续内存。
- 创建了一个 `WasmCode` 对象，指向新分配的代码内存。

**用户常见的编程错误 (与此文件功能相关的):**

虽然用户通常不会直接与 `wasm-code-manager.cc` 交互，但理解其功能可以帮助理解与 WebAssembly 相关的错误：

1. **内存溢出:** 如果加载非常大的 WebAssembly 模块，或者动态生成大量的 WebAssembly 代码，可能会导致代码空间耗尽。错误信息可能与内存分配失败有关。
2. **尝试调用未导出的 WebAssembly 函数:** 这与代码查找过程有关。如果 JavaScript 尝试调用一个在 WebAssembly 模块中不存在或者未导出的函数，V8 将无法找到对应的 `WasmCode` 对象。
3. **在调试过程中遇到问题:**  理解代码管理器如何处理调试信息可以帮助理解调试器的行为，例如单步执行、断点等。如果移除了调试代码，可能无法进行调试。

**归纳其功能 (第 4 部分，共 4 部分):**

`v8/src/wasm/wasm-code-manager.cc` 是 V8 中负责 **管理已编译的 WebAssembly 代码的核心组件**。它处理代码的内存分配、生命周期管理、查找以及与代码分层优化和调试相关的任务。它确保了 WebAssembly 代码能够高效安全地在 V8 引擎中执行。 它的主要职责是 **作为已编译 WebAssembly 代码的中央管理中心**，为 V8 引擎的其余部分提供必要的服务。

### 提示词
```
这是目录为v8/src/wasm/wasm-code-manager.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-code-manager.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
tiering) size_of_turbofan /= 4;

  return lazy_compile_table_size + size_of_imports + size_of_liftoff +
         size_of_turbofan;
}

// static
size_t WasmCodeManager::EstimateNativeModuleMetaDataSize(
    const WasmModule* module) {
  size_t wasm_module_estimate = module->EstimateStoredSize();

  uint32_t num_wasm_functions = module->num_declared_functions;

  // TODO(wasm): Include wire bytes size.
  size_t native_module_estimate =
      sizeof(NativeModule) +                      // NativeModule struct
      (sizeof(WasmCode*) * num_wasm_functions) +  // code table size
      (sizeof(WasmCode) * num_wasm_functions);    // code object size

  size_t jump_table_size = RoundUp<kCodeAlignment>(
      JumpTableAssembler::SizeForNumberOfSlots(num_wasm_functions));
  size_t far_jump_table_size =
      RoundUp<kCodeAlignment>(JumpTableAssembler::SizeForNumberOfFarJumpSlots(
          BuiltinLookup::BuiltinCount(),
          NumWasmFunctionsInFarJumpTable(num_wasm_functions)));

  return wasm_module_estimate + native_module_estimate + jump_table_size +
         far_jump_table_size;
}

// static
bool WasmCodeManager::HasMemoryProtectionKeySupport() {
#if V8_HAS_PKU_JIT_WRITE_PROTECT
  return RwxMemoryWriteScope::IsSupported();
#else
  return false;
#endif  // V8_HAS_PKU_JIT_WRITE_PROTECT
}

// static
bool WasmCodeManager::MemoryProtectionKeysEnabled() {
  return HasMemoryProtectionKeySupport();
}

// static
bool WasmCodeManager::MemoryProtectionKeyWritable() {
#if V8_HAS_PKU_JIT_WRITE_PROTECT
  return RwxMemoryWriteScope::IsPKUWritable();
#else
  return false;
#endif  // V8_HAS_PKU_JIT_WRITE_PROTECT
}

std::shared_ptr<NativeModule> WasmCodeManager::NewNativeModule(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    WasmDetectedFeatures detected_features, CompileTimeImports compile_imports,
    size_t code_size_estimate, std::shared_ptr<const WasmModule> module) {
#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    VirtualMemory code_space;
    std::shared_ptr<NativeModule> ret;
    new NativeModule(enabled_features, detected_features, compile_imports,
                     DynamicTiering{v8_flags.wasm_dynamic_tiering.value()},
                     std::move(code_space), std::move(module),
                     isolate->async_counters(), &ret);
    // The constructor initialized the shared_ptr.
    DCHECK_NOT_NULL(ret);
    TRACE_HEAP("New NativeModule (wasm-jitless) %p\n", ret.get());
    return ret;
  }
#endif  // V8_ENABLE_DRUMBRAKE

  if (total_committed_code_space_.load() >
      critical_committed_code_space_.load()) {
    // Flush Liftoff code and record the flushed code size.
    if (v8_flags.flush_liftoff_code) {
      auto [code_size, metadata_size] =
          wasm::GetWasmEngine()->FlushLiftoffCode();
      isolate->counters()->wasm_flushed_liftoff_code_size_bytes()->AddSample(
          static_cast<int>(code_size));
      isolate->counters()
          ->wasm_flushed_liftoff_metadata_size_bytes()
          ->AddSample(static_cast<int>(metadata_size));
    }
    (reinterpret_cast<v8::Isolate*>(isolate))
        ->MemoryPressureNotification(MemoryPressureLevel::kCritical);
    size_t committed = total_committed_code_space_.load();
    DCHECK_GE(max_committed_code_space_, committed);
    critical_committed_code_space_.store(
        committed + (max_committed_code_space_ - committed) / 2);
  }

  size_t code_vmem_size =
      ReservationSize(code_size_estimate, module->num_declared_functions, 0);

  // The '--wasm-max-initial-code-space-reservation' testing flag can be used to
  // reduce the maximum size of the initial code space reservation (in MB).
  if (v8_flags.wasm_max_initial_code_space_reservation > 0) {
    size_t flag_max_bytes =
        static_cast<size_t>(v8_flags.wasm_max_initial_code_space_reservation) *
        MB;
    if (flag_max_bytes < code_vmem_size) code_vmem_size = flag_max_bytes;
  }

  // Try up to two times; getting rid of dead JSArrayBuffer allocations might
  // require two GCs because the first GC maybe incremental and may have
  // floating garbage.
  static constexpr int kAllocationRetries = 2;
  VirtualMemory code_space;
  for (int retries = 0;; ++retries) {
    code_space = TryAllocate(code_vmem_size);
    if (code_space.IsReserved()) break;
    if (retries == kAllocationRetries) {
      auto oom_detail = base::FormattedString{}
                        << "NewNativeModule cannot allocate code space of "
                        << code_vmem_size << " bytes";
      V8::FatalProcessOutOfMemory(isolate, "Allocate initial wasm code space",
                                  oom_detail.PrintToArray().data());
      UNREACHABLE();
    }
    // Run one GC, then try the allocation again.
    isolate->heap()->MemoryPressureNotification(MemoryPressureLevel::kCritical,
                                                true);
  }

  Address start = code_space.address();
  size_t size = code_space.size();
  Address end = code_space.end();
  std::shared_ptr<NativeModule> ret;
  new NativeModule(enabled_features, detected_features,
                   std::move(compile_imports),
                   DynamicTiering{v8_flags.wasm_dynamic_tiering.value()},
                   std::move(code_space), std::move(module),
                   isolate->async_counters(), &ret);
  // The constructor initialized the shared_ptr.
  DCHECK_NOT_NULL(ret);
  TRACE_HEAP("New NativeModule %p: Mem: 0x%" PRIxPTR ",+%zu\n", ret.get(),
             start, size);

  base::MutexGuard lock(&native_modules_mutex_);
  lookup_map_.insert(std::make_pair(start, std::make_pair(end, ret.get())));
  return ret;
}

void NativeModule::SampleCodeSize(Counters* counters) const {
  size_t code_size = code_allocator_.committed_code_space();
  int code_size_mb = static_cast<int>(code_size / MB);
#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    base::MutexGuard lock(&module_->interpreter_mutex_);
    if (auto interpreter = module_->interpreter_.lock()) {
      code_size_mb = static_cast<int>(interpreter->TotalBytecodeSize() / MB);
    }
  }
#endif  // V8_ENABLE_DRUMBRAKE
  counters->wasm_module_code_size_mb()->AddSample(code_size_mb);
  int code_size_kb = static_cast<int>(code_size / KB);
  counters->wasm_module_code_size_kb()->AddSample(code_size_kb);
  // Record the size of metadata.
  Histogram* metadata_histogram = counters->wasm_module_metadata_size_kb();
  if (metadata_histogram->Enabled()) {
    // TODO(349610478): EstimateCurrentMemoryConsumption() acquires a large
    // amount of locks per NativeModule. This estimation is run on every
    // mark-compact GC. Reconsider whether this should be run less frequently.
    // (Probably incomplete) list of locks acquired:
    // - TypeFeedbackStorage::mutex
    // - LazilyGeneratedNames::mutex_
    // - CompilationStateImpl::mutex_
    // - CompilationUnitQueues::queues_mutex_
    //   - per queue: QueueImpl::mutex
    // - BigUnitsQueue::mutex
    // - WasmImportWrapperCache::mutex_
    // - NativeModule::allocation_mutex_
    // - LazilyGeneratedNames::mutex_
    // - DebugInfoImpl::debug_side_tables_mutex_
    // - DebugInfoImpl::mutex_
    int metadata_size_kb =
        static_cast<int>(EstimateCurrentMemoryConsumption() / KB);
    metadata_histogram->AddSample(metadata_size_kb);
  }
  // If this is a wasm module of >= 2MB, also sample the freed code size,
  // absolute and relative. Code GC does not happen on asm.js
  // modules, and small modules will never trigger GC anyway.
  size_t generated_size = code_allocator_.generated_code_size();
  if (generated_size >= 2 * MB && module()->origin == kWasmOrigin) {
    size_t freed_size = code_allocator_.freed_code_size();
    DCHECK_LE(freed_size, generated_size);
    int freed_percent = static_cast<int>(100 * freed_size / generated_size);
    counters->wasm_module_freed_code_size_percent()->AddSample(freed_percent);
  }
}

std::unique_ptr<WasmCode> NativeModule::AddCompiledCode(
    const WasmCompilationResult& result) {
  std::vector<std::unique_ptr<WasmCode>> code = AddCompiledCode({&result, 1});
  return std::move(code[0]);
}

std::vector<std::unique_ptr<WasmCode>> NativeModule::AddCompiledCode(
    base::Vector<const WasmCompilationResult> results) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.AddCompiledCode", "num", results.size());
  DCHECK(!results.empty());
  std::vector<std::unique_ptr<WasmCode>> generated_code;
  generated_code.reserve(results.size());

  // First, allocate code space for all the results.
  // Never add more than half of a code space at once. This leaves some space
  // for jump tables and other overhead. We could use {OverheadPerCodeSpace},
  // but that's only an approximation, so we are conservative here and never use
  // more than half a code space.
  size_t max_code_batch_size = v8_flags.wasm_max_code_space_size_mb * MB / 2;
  size_t total_code_space = 0;
  for (auto& result : results) {
    DCHECK(result.succeeded());
    size_t new_code_space =
        RoundUp<kCodeAlignment>(result.code_desc.instr_size);
    if (total_code_space + new_code_space > max_code_batch_size) {
      // Split off the first part of the {results} vector and process it
      // separately. This method then continues with the rest.
      size_t split_point = &result - results.begin();
      if (split_point == 0) {
        // Fuzzers sometimes hit this by reducing --wasm-max-code-sapce-size-mb
        // to an unreasonably small value. Make this an OOM to avoid getting a
        // CHECK failure in this case.
        if (v8_flags.wasm_max_code_space_size_mb <
            kDefaultMaxWasmCodeSpaceSizeMb / 10) {
          auto oom_detail = base::FormattedString{}
                            << "--wasm-max-code-space-size="
                            << v8_flags.wasm_max_code_space_size_mb.value();
          V8::FatalProcessOutOfMemory(nullptr,
                                      "A single code object needs more than "
                                      "half of the code space size",
                                      oom_detail.PrintToArray().data());
        } else {
          // Otherwise make this a CHECK failure so we see if this is happening
          // in the wild or in tests.
          FATAL(
              "A single code object needs more than half of the code space "
              "size");
        }
      }
      auto first_results = AddCompiledCode(results.SubVector(0, split_point));
      generated_code.insert(generated_code.end(),
                            std::make_move_iterator(first_results.begin()),
                            std::make_move_iterator(first_results.end()));
      // Continue processing the rest of the vector. This change to the
      // {results} vector does not invalidate iterators (which are just
      // pointers). In particular, the end pointer stays the same.
      results += split_point;
      total_code_space = 0;
    }
    total_code_space += new_code_space;
  }
  base::Vector<uint8_t> code_space;
  NativeModule::JumpTablesRef jump_tables;
  {
    base::RecursiveMutexGuard guard{&allocation_mutex_};
    code_space = code_allocator_.AllocateForCode(this, total_code_space);
    // Lookup the jump tables to use once, then use for all code objects.
    jump_tables =
        FindJumpTablesForRegionLocked(base::AddressRegionOf(code_space));
  }
  // If we happen to have a {total_code_space} which is bigger than
  // {kMaxCodeSpaceSize}, we would not find valid jump tables for the whole
  // region. If this ever happens, we need to handle this case (by splitting the
  // {results} vector in smaller chunks).
  CHECK(jump_tables.is_valid());

  std::vector<size_t> sizes;
  for (const auto& result : results) {
    sizes.emplace_back(RoundUp<kCodeAlignment>(result.code_desc.instr_size));
  }
  ThreadIsolation::RegisterJitAllocations(
      reinterpret_cast<Address>(code_space.begin()), sizes,
      ThreadIsolation::JitAllocationType::kWasmCode);

  // Now copy the generated code into the code space and relocate it.
  for (auto& result : results) {
    DCHECK_EQ(result.code_desc.buffer, result.instr_buffer->start());
    size_t code_size = RoundUp<kCodeAlignment>(result.code_desc.instr_size);
    base::Vector<uint8_t> this_code_space = code_space.SubVector(0, code_size);
    code_space += code_size;
    generated_code.emplace_back(AddCodeWithCodeSpace(
        result.func_index, result.code_desc, result.frame_slot_count,
        result.ool_spill_count, result.tagged_parameter_slots,
        result.protected_instructions_data.as_vector(),
        result.source_positions.as_vector(),
        result.inlining_positions.as_vector(), result.deopt_data.as_vector(),
        GetCodeKind(result), result.result_tier, result.for_debugging,
        result.frame_has_feedback_slot, this_code_space, jump_tables));
  }
  DCHECK_EQ(0, code_space.size());

  // Check that we added the expected amount of code objects, even if we split
  // the {results} vector.
  DCHECK_EQ(generated_code.capacity(), generated_code.size());

  return generated_code;
}

void NativeModule::SetDebugState(DebugState new_debug_state) {
  // Do not tier down asm.js (just never change the tiering state).
  if (module()->origin != kWasmOrigin) return;

  base::RecursiveMutexGuard lock(&allocation_mutex_);
  debug_state_ = new_debug_state;
}

namespace {
bool ShouldRemoveCode(WasmCode* code, NativeModule::RemoveFilter filter) {
  if (filter == NativeModule::RemoveFilter::kRemoveDebugCode &&
      !code->for_debugging()) {
    return false;
  }
  if (filter == NativeModule::RemoveFilter::kRemoveNonDebugCode &&
      code->for_debugging()) {
    return false;
  }
  if (filter == NativeModule::RemoveFilter::kRemoveLiftoffCode &&
      !code->is_liftoff()) {
    return false;
  }
  if (filter == NativeModule::RemoveFilter::kRemoveTurbofanCode &&
      !code->is_turbofan()) {
    return false;
  }
  return true;
}
}  // namespace

std::pair<size_t, size_t> NativeModule::RemoveCompiledCode(
    RemoveFilter filter) {
  const uint32_t num_imports = module_->num_imported_functions;
  const uint32_t num_functions = module_->num_declared_functions;
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  size_t removed_codesize = 0;
  size_t removed_metadatasize = 0;
  for (uint32_t i = 0; i < num_functions; i++) {
    WasmCode* code = code_table_[i];
    if (code && ShouldRemoveCode(code, filter)) {
      removed_codesize += code->instructions_size();
      removed_metadatasize += code->EstimateCurrentMemoryConsumption();
      code_table_[i] = nullptr;
      // Add the code to the {WasmCodeRefScope}, so the ref count cannot drop to
      // zero here. It might in the {WasmCodeRefScope} destructor, though.
      WasmCodeRefScope::AddRef(code);
      code->DecRefOnLiveCode();
      uint32_t func_index = i + num_imports;
      UseLazyStubLocked(func_index);
    }
  }
  // When resuming optimized execution after a debugging session ends, or when
  // discarding optimized code that made outdated assumptions, allow another
  // tier-up task to get scheduled.
  if (filter == RemoveFilter::kRemoveDebugCode ||
      filter == RemoveFilter::kRemoveTurbofanCode) {
    compilation_state_->AllowAnotherTopTierJobForAllFunctions();
  }
  return std::make_pair(removed_codesize, removed_metadatasize);
}

size_t NativeModule::SumLiftoffCodeSizeForTesting() const {
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  const uint32_t num_functions = module_->num_declared_functions;
  size_t codesize_liftoff = 0;
  for (uint32_t i = 0; i < num_functions; i++) {
    WasmCode* code = code_table_[i];
    if (code && code->is_liftoff()) {
      codesize_liftoff += code->instructions_size();
    }
  }
  return codesize_liftoff;
}

void NativeModule::FreeCode(base::Vector<WasmCode* const> codes) {
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  // Free the code space.
  code_allocator_.FreeCode(codes);

  if (!new_owned_code_.empty()) TransferNewOwnedCodeLocked();
  DebugInfo* debug_info = debug_info_.get();
  // Free the {WasmCode} objects. This will also unregister trap handler data.
  for (WasmCode* code : codes) {
    DCHECK_EQ(1, owned_code_.count(code->instruction_start()));
    owned_code_.erase(code->instruction_start());
  }
  // Remove debug side tables for all removed code objects, after releasing our
  // lock. This is to avoid lock order inversion.
  if (debug_info) debug_info->RemoveDebugSideTables(codes);
}

size_t NativeModule::GetNumberOfCodeSpacesForTesting() const {
  base::RecursiveMutexGuard guard{&allocation_mutex_};
  return code_allocator_.GetNumCodeSpaces();
}

bool NativeModule::HasDebugInfo() const {
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  return debug_info_ != nullptr;
}

DebugInfo* NativeModule::GetDebugInfo() {
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  if (!debug_info_) debug_info_ = std::make_unique<DebugInfo>(this);
  return debug_info_.get();
}

NamesProvider* NativeModule::GetNamesProvider() {
  DCHECK(HasWireBytes());
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  if (!names_provider_) {
    names_provider_ =
        std::make_unique<NamesProvider>(module_.get(), wire_bytes());
  }
  return names_provider_.get();
}

size_t NativeModule::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(NativeModule, 480);
  size_t result = sizeof(NativeModule);
  result += module_->EstimateCurrentMemoryConsumption();

  std::shared_ptr<base::OwnedVector<const uint8_t>> wire_bytes =
      std::atomic_load(&wire_bytes_);
  size_t wire_bytes_size = wire_bytes ? wire_bytes->size() : 0;
  result += wire_bytes_size;

  if (source_map_) {
    result += source_map_->EstimateCurrentMemoryConsumption();
  }
  result += compilation_state_->EstimateCurrentMemoryConsumption();
  // For {tiering_budgets_}.
  result += module_->num_declared_functions * sizeof(uint32_t);

  size_t external_storage = compile_imports_.constants_module().capacity();
  // This is an approximation: the actual number of inline-stored characters
  // is a little less than the result of `sizeof`.
  if (external_storage > sizeof(std::string)) {
    result += external_storage;
  }

  // For fast api call targets.
  result += module_->num_imported_functions *
            (sizeof(std::atomic<Address>) + sizeof(CFunctionInfo*));
  // We cannot hold the `allocation_mutex_` while calling
  // `debug_info_->EstimateCurrentMemoryConsumption`, as we would run into a
  // lock-order-inversion when acquiring the `mutex_`. The reverse order happens
  // when calling `WasmScript::SetBreakPointForFunction`.
  DebugInfo* debug_info;
  {
    base::RecursiveMutexGuard lock(&allocation_mutex_);
    result += ContentSize(owned_code_);
    for (auto& [address, unique_code_ptr] : owned_code_) {
      result += unique_code_ptr->EstimateCurrentMemoryConsumption();
    }
    result += ContentSize(new_owned_code_);
    for (std::unique_ptr<WasmCode>& code : new_owned_code_) {
      result += code->EstimateCurrentMemoryConsumption();
    }
    // For {code_table_}.
    result += module_->num_declared_functions * sizeof(void*);
    result += ContentSize(code_space_data_);
    debug_info = debug_info_.get();
    if (names_provider_) {
      result += names_provider_->EstimateCurrentMemoryConsumption();
    }
  }
  if (debug_info) {
    result += debug_info->EstimateCurrentMemoryConsumption();
  }

  if (v8_flags.trace_wasm_offheap_memory) {
    PrintF("NativeModule wire bytes: %zu\n", wire_bytes_size);
    PrintF("NativeModule: %zu\n", result);
  }
  return result;
}

void WasmCodeManager::FreeNativeModule(
    base::Vector<VirtualMemory> owned_code_space, size_t committed_size) {
  base::MutexGuard lock(&native_modules_mutex_);
  for (auto& code_space : owned_code_space) {
    DCHECK(code_space.IsReserved());
    TRACE_HEAP("VMem Release: 0x%" PRIxPTR ":0x%" PRIxPTR " (%zu)\n",
               code_space.address(), code_space.end(), code_space.size());

#if defined(V8_OS_WIN64)
    if (CanRegisterUnwindInfoForNonABICompliantCodeRange()) {
      win64_unwindinfo::UnregisterNonABICompliantCodeRange(
          reinterpret_cast<void*>(code_space.address()));
    }
#endif  // V8_OS_WIN64

    lookup_map_.erase(code_space.address());
    ThreadIsolation::UnregisterJitPage(code_space.address(), code_space.size());
    code_space.Free();
    DCHECK(!code_space.IsReserved());
  }

  DCHECK(IsAligned(committed_size, CommitPageSize()));
  [[maybe_unused]] size_t old_committed =
      total_committed_code_space_.fetch_sub(committed_size);
  DCHECK_LE(committed_size, old_committed);
}

NativeModule* WasmCodeManager::LookupNativeModule(Address pc) const {
  base::MutexGuard lock(&native_modules_mutex_);
  if (lookup_map_.empty()) return nullptr;

  auto iter = lookup_map_.upper_bound(pc);
  if (iter == lookup_map_.begin()) return nullptr;
  --iter;
  Address region_start = iter->first;
  Address region_end = iter->second.first;
  NativeModule* candidate = iter->second.second;

  DCHECK_NOT_NULL(candidate);
  return region_start <= pc && pc < region_end ? candidate : nullptr;
}

WasmCode* WasmCodeManager::LookupCode(Address pc) const {
  NativeModule* candidate = LookupNativeModule(pc);
  if (candidate) return candidate->Lookup(pc);
  return GetWasmImportWrapperCache()->Lookup(pc);
}

WasmCode* WasmCodeManager::LookupCode(Isolate* isolate, Address pc) const {
  // Since kNullAddress is used as a sentinel value, we should not try
  // to look it up in the cache
  if (pc == kNullAddress) return nullptr;
  // If 'isolate' is nullptr, do not use a cache. This can happen when
  // called from function V8NameConverter::NameOfAddress
  if (isolate) {
    return isolate->wasm_code_look_up_cache()->GetCacheEntry(pc)->code;
  } else {
    wasm::WasmCodeRefScope code_ref_scope;
    return LookupCode(pc);
  }
}

std::pair<WasmCode*, SafepointEntry> WasmCodeManager::LookupCodeAndSafepoint(
    Isolate* isolate, Address pc) {
  auto* entry = isolate->wasm_code_look_up_cache()->GetCacheEntry(pc);
  WasmCode* code = entry->code;
  DCHECK_NOT_NULL(code);
  // For protected instructions we usually do not emit a safepoint because the
  // frame will be unwound anyway. The exception is debugging code, where the
  // frame might be inspected if "pause on exception" is set.
  // For those instructions, we thus need to explicitly return an empty
  // safepoint; using any previously registered safepoint can lead to crashes
  // when we try to visit spill slots that do not hold tagged values at this
  // point.
  // Evaluate this condition only on demand (the fast path does not need it).
  auto expect_safepoint = [code, pc]() {
    const bool is_protected_instruction = code->IsProtectedInstruction(
        pc - WasmFrameConstants::kProtectedInstructionReturnAddressOffset);
    return !is_protected_instruction || code->for_debugging();
  };
  if (!entry->safepoint_entry.is_initialized() && expect_safepoint()) {
    entry->safepoint_entry = SafepointTable{code}.TryFindEntry(pc);
    CHECK(entry->safepoint_entry.is_initialized());
  } else if (expect_safepoint()) {
    DCHECK_EQ(entry->safepoint_entry, SafepointTable{code}.TryFindEntry(pc));
  } else {
    DCHECK(!entry->safepoint_entry.is_initialized());
  }
  return std::make_pair(code, entry->safepoint_entry);
}

void WasmCodeManager::FlushCodeLookupCache(Isolate* isolate) {
  return isolate->wasm_code_look_up_cache()->Flush();
}

namespace {
thread_local WasmCodeRefScope* current_code_refs_scope = nullptr;
}  // namespace

WasmCodeRefScope::WasmCodeRefScope()
    : previous_scope_(current_code_refs_scope) {
  current_code_refs_scope = this;
}

WasmCodeRefScope::~WasmCodeRefScope() {
  DCHECK_EQ(this, current_code_refs_scope);
  current_code_refs_scope = previous_scope_;
  WasmCode::DecrementRefCount(base::VectorOf(code_ptrs_));
}

// static
void WasmCodeRefScope::AddRef(WasmCode* code) {
  DCHECK_NOT_NULL(code);
  WasmCodeRefScope* current_scope = current_code_refs_scope;
  DCHECK_NOT_NULL(current_scope);
  current_scope->code_ptrs_.push_back(code);
  code->IncRef();
}

void WasmCodeLookupCache::Flush() {
  for (int i = 0; i < kWasmCodeLookupCacheSize; i++)
    cache_[i].pc.store(kNullAddress, std::memory_order_release);
}

WasmCodeLookupCache::CacheEntry* WasmCodeLookupCache::GetCacheEntry(
    Address pc) {
  static_assert(base::bits::IsPowerOfTwo(kWasmCodeLookupCacheSize));
  DCHECK(pc != kNullAddress);
  uint32_t hash = ComputeAddressHash(pc);
  uint32_t index = hash & (kWasmCodeLookupCacheSize - 1);
  CacheEntry* entry = &cache_[index];
  if (entry->pc.load(std::memory_order_acquire) == pc) {
    // Code can be deallocated at two points:
    // - when the NativeModule that references it is garbage-
    //   collected;
    // - when it is no longer referenced by its NativeModule, nor from
    //   any stack.
    // The cache is cleared when a NativeModule is destroyed, and when
    // the isolate reports the set of code referenced from its stacks.
    // So, if the code is the cache, it is because it was live at some
    // point (when inserted in the cache), its native module is still
    // considered live, and it has not yet been reported as no longer
    // referenced from any stack. It thus cannot have been released
    // yet.
#ifdef DEBUG
    wasm::WasmCodeRefScope code_ref_scope;
    DCHECK_EQ(entry->code, wasm::GetWasmCodeManager()->LookupCode(pc));
#endif  // DEBUG
  } else {
    // For WebAssembly frames we perform a lookup in the handler table.
    // This code ref scope is here to avoid a check failure when looking up
    // the code. It's not actually necessary to keep the code alive as it's
    // currently being executed.
    wasm::WasmCodeRefScope code_ref_scope;
    entry->pc.store(pc, std::memory_order_release);
    entry->code = wasm::GetWasmCodeManager()->LookupCode(pc);
    entry->safepoint_entry.Reset();
  }
  return entry;
}

Address WasmCodePointerAddress(WasmCodePointer pointer) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  return wasm::GetProcessWideWasmCodePointerTable()->GetEntrypoint(pointer);
#else
  return pointer;
#endif
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8
#undef TRACE_HEAP
```