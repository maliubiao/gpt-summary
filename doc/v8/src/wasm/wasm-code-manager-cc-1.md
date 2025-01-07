Response:
The user wants me to analyze a C++ source code file related to V8's WebAssembly implementation. I need to extract its functionalities, consider its potential relationship with JavaScript, provide example usage if related, reason about the code logic with hypothetical inputs and outputs, point out common programming errors it might prevent, and finally, summarize its function based on the provided snippet.

**Functionality Breakdown:**

1. **Code Allocation and Management:** The code snippet heavily focuses on memory management for WebAssembly code. It involves allocating, committing, decommitting, and freeing memory regions specifically for storing compiled Wasm code.
2. **Native Module Management:** It deals with `NativeModule` objects, which represent compiled Wasm modules. This includes initializing code spaces, managing jump tables, and associating compiled code with its module.
3. **Code Publishing and Tiering:** The code handles the process of publishing compiled Wasm code and managing different tiers of compilation (e.g., Liftoff, Turbofan). It includes logic for deciding when to update the active code for a function based on tier and debugging status.
4. **Jump Table Management:**  The code manages jump tables used for efficient function calls, including lazy compilation stubs.
5. **Relocation:** The code applies relocation information to the allocated code, adjusting addresses based on the final memory location.
6. **Debugging Support:**  It considers debugging states and the installation of debug code.
7. **Code Pointer Table:** The code interacts with a process-wide `WasmCodePointerTable` to manage pointers to compiled Wasm functions.
8. **Well-Known Imports:** It handles the management and updates of well-known imports for type feedback.

**Relationship with JavaScript:**

WebAssembly code interacts closely with JavaScript. When JavaScript calls a Wasm function, or vice-versa, the `wasm-code-manager.cc` is involved in ensuring the correct code is executed.

**Hypothetical Input and Output (Code Allocation):**

*   **Input:** `WasmCodeAllocator::AllocateForCode(native_module, 1024)` - request to allocate 1024 bytes of code.
*   **Output:** A `base::Vector<uint8_t>` representing a memory region of at least 1024 bytes, aligned to code alignment, ready for code to be written into. The internal state of `free_code_space_` would be updated.

**Common Programming Errors:**

*   **Memory Corruption:** If memory allocation and deallocation are not handled correctly, it can lead to memory corruption. The code in the snippet uses `DisjointAllocationPool` to manage free memory regions, likely to prevent overlaps and ensure efficient allocation.
*   **Incorrect Relocation:** Failing to apply relocations correctly would result in the generated code jumping to the wrong addresses or accessing incorrect data. The code iterates through relocation entries and adjusts addresses based on the difference between the original and allocated memory.
*   **Cache Incoherence:** If the instruction cache is not flushed after writing or modifying code, the processor might execute stale instructions. The `FlushInstructionCache` call after relocation is crucial.

**Summary of Functionality (based on provided snippet):**

This section of `v8/src/wasm/wasm-code-manager.cc` primarily focuses on **managing the lifecycle and memory allocation of compiled WebAssembly code within a `NativeModule`**. It handles the allocation of code spaces, commits memory pages as needed, and integrates newly compiled code into the module's jump tables and code pointer table. It also incorporates logic for tiered compilation and debugging, ensuring the correct version of code is active based on the module's state.

这是 `v8/src/wasm/wasm-code-manager.cc` 的一部分源代码，主要负责 WebAssembly 代码的**发布和管理**，以及相关的**内存分配**。

以下是根据提供的代码片段归纳的功能点：

1. **代码分配 (Code Allocation):**
    *   `AllocateForCode`:  负责为 WebAssembly 代码分配内存空间。它会检查是否有足够的空闲空间，如果没有，则会分配新的代码空间。
    *   管理已分配的代码空间 (`owned_code_space_`) 和空闲的代码空间 (`free_code_space_`)。
    *   支持按需提交内存页 (`Commit`) 以减少内存占用。
    *   记录已提交的代码空间大小 (`committed_code_space_`) 和生成的代码大小 (`generated_code_size_`).

2. **代码释放 (Code Freeing):**
    *   `FreeCode`: 释放不再使用的 WebAssembly 代码占用的内存。
    *   将释放的内存区域合并回空闲空间 (`freed_code_space_`)。
    *   按页取消提交不再使用的内存 (`Decommit`)。
    *   记录已释放的代码大小 (`freed_code_size_`).

3. **NativeModule 管理:**
    *   `NativeModule` 对象的创建和初始化，包括分配初始代码空间。
    *   `ReserveCodeTableForTesting`:  在测试中预留代码表空间。
    *   `LogWasmCodes`:  记录 WebAssembly 代码信息 (用于调试或分析)。

4. **代码发布 (Code Publishing):**
    *   `AddCodeForTesting`:  为测试目的添加代码。
    *   `AddCode`:  添加编译后的 WebAssembly 代码。它会分配内存，注册 JIT 分配，并进行必要的重定位。
    *   `PublishCodeLocked`:  将编译好的 `WasmCode` 对象发布到 `NativeModule` 中，使其可以被执行。
    *   `PublishCode`:  发布单个或多个 `WasmCode` 对象，考虑了类型反馈的假设。
    *   根据代码的执行层级 (`ExecutionTier`) 和调试状态 (`ForDebugging`) 决定是否更新代码表 (`code_table_`) 中的代码。

5. **跳转表 (Jump Table) 管理:**
    *   创建和初始化跳转表 (`main_jump_table_`, `main_far_jump_table_`, `lazy_compile_table_`)，用于高效的函数调用。
    *   `InitializeJumpTableForLazyCompilation`: 初始化用于懒编译的跳转表。
    *   `UseLazyStubLocked`:  将指定函数的跳转目标设置为懒编译桩。
    *   `PatchJumpTablesLocked`: 更新跳转表中的条目，指向新发布的代码。

6. **代码指针表 (Code Pointer Table) 管理:**
    *   `InitializeCodePointerTableHandles`:  为 WebAssembly 函数分配全局的代码指针表句柄。
    *   `FreeCodePointerTableHandles`:  释放代码指针表句柄。

7. **调试支持 (Debugging Support):**
    *   根据调试状态 (`debug_state_`) 决定是否安装调试代码。
    *   `ReinstallDebugCode`:  重新安装调试代码。

8. **反序列化支持 (Deserialization Support):**
    *   `AllocateForDeserializedCode`: 为反序列化的代码分配内存。
    *   `AddDeserializedCode`: 添加反序列化后的 WebAssembly 代码。

9. **快照 (Snapshot) 功能:**
    *   `SnapshotCodeTable`:  创建当前代码表的快照。

**与 JavaScript 的关系:**

`v8/src/wasm/wasm-code-manager.cc` 中管理的代码是 WebAssembly 代码，当 JavaScript 调用 WebAssembly 函数时，或者 WebAssembly 调用 JavaScript 函数时，都需要通过这里管理的代码入口。

**JavaScript 示例 (假设的):**

虽然 `wasm-code-manager.cc` 是 C++ 代码，但其功能直接影响 JavaScript 如何执行 WebAssembly 代码。例如，当 JavaScript 执行以下代码时：

```javascript
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
instance.exports.myFunction();
```

幕后，V8 会调用 `wasm-code-manager.cc` 中的代码来分配内存给 `module.wasm` 中的编译后的代码，并将 `myFunction` 的入口地址写入相应的跳转表或代码指针表中，以便 JavaScript 可以正确地跳转到 WebAssembly 代码执行。

**代码逻辑推理 (假设输入与输出):**

假设：

*   `free_code_space_` 当前有一个大小为 2MB 的空闲代码块。
*   `CommitPageSize()` 返回 4KB。

输入：`WasmCodeAllocator::AllocateForCode(nullptr, 10KB)`

输出：

*   `code_space` 将是一个包含 10KB 空闲内存的 `base::AddressRegion`。
*   `free_code_space_` 将减少 10KB，剩余一个 2MB - 10KB 的空闲代码块。
*   由于 10KB 需要跨越多个 4KB 的提交页，因此会调用 `Commit` 函数，实际提交的内存可能会略大于 10KB (向上对齐到 4KB 的倍数)。
*   `committed_code_space_` 的值会增加。

**用户常见的编程错误 (避免):**

*   **内存泄漏:**  如果分配的 WebAssembly 代码内存没有被正确释放，会导致内存泄漏。`FreeCode` 函数的作用就是防止这种情况发生。
*   **悬挂指针:**  如果在代码被释放后仍然持有指向该代码的指针，就会出现悬挂指针。`WasmCodeRefScope` 和引用计数机制可以帮助管理 `WasmCode` 对象的生命周期，减少悬挂指针的风险。
*   **缓冲区溢出:**  在将编译后的代码写入分配的内存时，如果写入的大小超过了分配的大小，会导致缓冲区溢出。`AllocateForCode` 负责分配足够的空间来避免这种情况。
*   **指令缓存一致性问题:**  在修改了代码段之后，如果没有刷新指令缓存，处理器可能会执行旧的代码。`FlushInstructionCache` 用于确保指令缓存与内存中的代码一致。

**总结 (基于提供的代码片段的功能):**

这段 `v8/src/wasm/wasm-code-manager.cc` 的代码片段主要负责 **WebAssembly 代码的内存分配、释放和管理，以及将编译后的代码发布到 `NativeModule` 中并维护代码的活性**。它涉及到代码空间的管理、内存页的提交和取消提交、跳转表的维护、代码指针表的管理，以及对不同执行层级和调试状态的支持。其核心目标是确保 WebAssembly 代码能够被安全有效地加载、执行和卸载。

Prompt: 
```
这是目录为v8/src/wasm/wasm-code-manager.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-code-manager.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
         oom_detail.PrintToArray().data());
      UNREACHABLE();
    }

    base::AddressRegion new_region = new_mem.region();
    free_code_space_.Merge(new_region);
    owned_code_space_.emplace_back(std::move(new_mem));
    InitializeCodeRange(native_module, new_region);
    if (native_module) {
      code_manager->AssignRange(new_region, native_module);
      native_module->AddCodeSpaceLocked(new_region);

      async_counters_->wasm_module_num_code_spaces()->AddSample(
          static_cast<int>(owned_code_space_.size()));
    }

    code_space = free_code_space_.Allocate(size);
    CHECK(!code_space.is_empty());
  }
  const Address commit_page_size = CommitPageSize();
  Address commit_start = RoundUp(code_space.begin(), commit_page_size);
  Address commit_end = RoundUp(code_space.end(), commit_page_size);
  // {commit_start} will be either code_space.start or the start of the next
  // page. {commit_end} will be the start of the page after the one in which
  // the allocation ends.
  // We start from an aligned start, and we know we allocated vmem in
  // page multiples.
  // We just need to commit what's not committed. The page in which we
  // start is already committed (or we start at the beginning of a page).
  // The end needs to be committed all through the end of the page.
  if (commit_start < commit_end) {
    for (base::AddressRegion split_range : SplitRangeByReservationsIfNeeded(
             {commit_start, commit_end - commit_start}, owned_code_space_)) {
      code_manager->Commit(split_range);
    }
    committed_code_space_.fetch_add(commit_end - commit_start);
    // Committed code cannot grow bigger than maximum code space size.
    DCHECK_LE(committed_code_space_.load(),
              v8_flags.wasm_max_committed_code_mb * MB);
  }
  DCHECK(IsAligned(code_space.begin(), kCodeAlignment));
  generated_code_size_.fetch_add(code_space.size(), std::memory_order_relaxed);

  TRACE_HEAP("Code alloc for %p: 0x%" PRIxPTR ",+%zu\n", this,
             code_space.begin(), size);
  return {reinterpret_cast<uint8_t*>(code_space.begin()), code_space.size()};
}

void WasmCodeAllocator::FreeCode(base::Vector<WasmCode* const> codes) {
  // Zap code area and collect freed code regions.
  DisjointAllocationPool freed_regions;
  size_t code_size = 0;
  for (WasmCode* code : codes) {
    code_size += code->instructions().size();
    freed_regions.Merge(base::AddressRegion{code->instruction_start(),
                                            code->instructions().size()});
    ThreadIsolation::UnregisterWasmAllocation(code->instruction_start(),
                                              code->instructions().size());
  }
  freed_code_size_.fetch_add(code_size);

  // Merge {freed_regions} into {freed_code_space_} and put all ranges of full
  // pages to decommit into {regions_to_decommit} (decommitting is expensive,
  // so try to merge regions before decommitting).
  DisjointAllocationPool regions_to_decommit;
  size_t commit_page_size = CommitPageSize();
  for (auto region : freed_regions.regions()) {
    auto merged_region = freed_code_space_.Merge(region);
    Address discard_start =
        std::max(RoundUp(merged_region.begin(), commit_page_size),
                 RoundDown(region.begin(), commit_page_size));
    Address discard_end =
        std::min(RoundDown(merged_region.end(), commit_page_size),
                 RoundUp(region.end(), commit_page_size));
    if (discard_start >= discard_end) continue;
    regions_to_decommit.Merge({discard_start, discard_end - discard_start});
  }

  auto* code_manager = GetWasmCodeManager();
  for (auto region : regions_to_decommit.regions()) {
    [[maybe_unused]] size_t old_committed =
        committed_code_space_.fetch_sub(region.size());
    DCHECK_GE(old_committed, region.size());
    for (base::AddressRegion split_range :
         SplitRangeByReservationsIfNeeded(region, owned_code_space_)) {
      code_manager->Decommit(split_range);
    }
  }
}

size_t WasmCodeAllocator::GetNumCodeSpaces() const {
  return owned_code_space_.size();
}

NativeModule::NativeModule(WasmEnabledFeatures enabled_features,
                           WasmDetectedFeatures detected_features,
                           CompileTimeImports compile_imports,
                           DynamicTiering dynamic_tiering,
                           VirtualMemory code_space,
                           std::shared_ptr<const WasmModule> module,
                           std::shared_ptr<Counters> async_counters,
                           std::shared_ptr<NativeModule>* shared_this)
    : engine_scope_(
          GetWasmEngine()->GetBarrierForBackgroundCompile()->TryLock()),
      code_allocator_(async_counters),
      enabled_features_(enabled_features),
      compile_imports_(std::move(compile_imports)),
      module_(std::move(module)),
      fast_api_targets_(
          new std::atomic<Address>[module_->num_imported_functions]()),
      fast_api_signatures_(
          new std::atomic<
              const MachineSignature*>[module_->num_imported_functions]()) {
  DCHECK(engine_scope_);
  // We receive a pointer to an empty {std::shared_ptr}, and install ourselve
  // there.
  DCHECK_NOT_NULL(shared_this);
  DCHECK_NULL(*shared_this);
  shared_this->reset(this);
  compilation_state_ =
      CompilationState::New(*shared_this, std::move(async_counters),
                            dynamic_tiering, detected_features);
  compilation_state_->InitCompileJob();
  DCHECK_NOT_NULL(module_);
  if (module_->num_declared_functions > 0) {
    code_table_ =
        std::make_unique<WasmCode*[]>(module_->num_declared_functions);
    InitializeCodePointerTableHandles(module_->num_declared_functions);
    tiering_budgets_ = std::make_unique<std::atomic<uint32_t>[]>(
        module_->num_declared_functions);
    // The tiering budget is accessed directly from generated code.
    static_assert(sizeof(*tiering_budgets_.get()) == sizeof(uint32_t));

    std::fill_n(tiering_budgets_.get(), module_->num_declared_functions,
                v8_flags.wasm_tiering_budget);
  }

  if (v8_flags.wasm_jitless) return;

  // Even though there cannot be another thread using this object (since we
  // are just constructing it), we need to hold the mutex to fulfill the
  // precondition of {WasmCodeAllocator::Init}, which calls
  // {NativeModule::AddCodeSpaceLocked}.
  base::RecursiveMutexGuard guard{&allocation_mutex_};
  auto initial_region = code_space.region();
  code_allocator_.Init(std::move(code_space));
  code_allocator_.InitializeCodeRange(this, initial_region);
  AddCodeSpaceLocked(initial_region);
}

void NativeModule::ReserveCodeTableForTesting(uint32_t max_functions) {
  if (v8_flags.wasm_jitless) return;

  WasmCodeRefScope code_ref_scope;
  CHECK_LE(module_->num_declared_functions, max_functions);
  auto new_table = std::make_unique<WasmCode*[]>(max_functions);
  if (module_->num_declared_functions > 0) {
    memcpy(new_table.get(), code_table_.get(),
           module_->num_declared_functions * sizeof(WasmCode*));
  }
  code_table_ = std::move(new_table);
  InitializeCodePointerTableHandles(max_functions);

  base::RecursiveMutexGuard guard(&allocation_mutex_);
  CHECK_EQ(1, code_space_data_.size());
  base::AddressRegion single_code_space_region = code_space_data_[0].region;
  // Re-allocate the near and far jump tables.
  main_jump_table_ = CreateEmptyJumpTableInRegionLocked(
      JumpTableAssembler::SizeForNumberOfSlots(max_functions),
      single_code_space_region, JumpTableType::kJumpTable);
  CHECK(
      single_code_space_region.contains(main_jump_table_->instruction_start()));
  main_far_jump_table_ = CreateEmptyJumpTableInRegionLocked(
      JumpTableAssembler::SizeForNumberOfFarJumpSlots(
          BuiltinLookup::BuiltinCount(),
          NumWasmFunctionsInFarJumpTable(max_functions)),
      single_code_space_region, JumpTableType::kFarJumpTable);
  CHECK(single_code_space_region.contains(
      main_far_jump_table_->instruction_start()));
  code_space_data_[0].jump_table = main_jump_table_;
  InitializeJumpTableForLazyCompilation(max_functions);
}

void NativeModule::LogWasmCodes(Isolate* isolate, Tagged<Script> script) {
  DisallowGarbageCollection no_gc;
  if (!WasmCode::ShouldBeLogged(isolate)) return;

  TRACE_EVENT1("v8.wasm", "wasm.LogWasmCodes", "functions",
               module_->num_declared_functions);

  Tagged<Object> url_obj = script->name();
  DCHECK(IsString(url_obj) || IsUndefined(url_obj));
  std::unique_ptr<char[]> source_url =
      IsString(url_obj) ? Cast<String>(url_obj)->ToCString()
                        : std::unique_ptr<char[]>(new char[1]{'\0'});

  // Log all owned code, not just the current entries in the code table. This
  // will also include import wrappers.
  WasmCodeRefScope code_ref_scope;
  for (auto& code : SnapshotAllOwnedCode()) {
    code->LogCode(isolate, source_url.get(), script->id());
  }
}

WasmCode* NativeModule::AddCodeForTesting(DirectHandle<Code> code) {
  const size_t relocation_size = code->relocation_size();
  base::OwnedVector<uint8_t> reloc_info;
  if (relocation_size > 0) {
    reloc_info = base::OwnedVector<uint8_t>::Of(
        base::Vector<uint8_t>{code->relocation_start(), relocation_size});
  }
  DirectHandle<TrustedByteArray> source_pos_table(
      code->source_position_table(), code->instruction_stream()->GetIsolate());
  int source_pos_len = source_pos_table->length();
  auto source_pos = base::OwnedVector<uint8_t>::NewForOverwrite(source_pos_len);
  if (source_pos_len > 0) {
    MemCopy(source_pos.begin(), source_pos_table->begin(), source_pos_len);
  }

  static_assert(InstructionStream::kOnHeapBodyIsContiguous);
  base::Vector<const uint8_t> instructions(
      reinterpret_cast<uint8_t*>(code->body_start()),
      static_cast<size_t>(code->body_size()));
  const int stack_slots = code->stack_slots();

  // Metadata offsets in InstructionStream objects are relative to the start of
  // the metadata section, whereas WasmCode expects offsets relative to
  // instruction_start.
  const int base_offset = code->instruction_size();
  // TODO(jgruber,v8:8758): Remove this translation. It exists only because
  // InstructionStream objects contains real offsets but WasmCode expects an
  // offset of 0 to mean 'empty'.
  const int safepoint_table_offset =
      code->has_safepoint_table() ? base_offset + code->safepoint_table_offset()
                                  : 0;
  const int handler_table_offset = base_offset + code->handler_table_offset();
  const int constant_pool_offset = base_offset + code->constant_pool_offset();
  const int code_comments_offset = base_offset + code->code_comments_offset();

  base::RecursiveMutexGuard guard{&allocation_mutex_};
  base::Vector<uint8_t> dst_code_bytes =
      code_allocator_.AllocateForCode(this, instructions.size());
  {
    WritableJitAllocation jit_allocation =
        ThreadIsolation::RegisterJitAllocation(
            reinterpret_cast<Address>(dst_code_bytes.begin()),
            dst_code_bytes.size(),
            ThreadIsolation::JitAllocationType::kWasmCode, true);
    jit_allocation.CopyCode(0, instructions.begin(), instructions.size());

    // Apply the relocation delta by iterating over the RelocInfo.
    intptr_t delta = reinterpret_cast<Address>(dst_code_bytes.begin()) -
                     code->instruction_start();
    int mode_mask = RelocInfo::kApplyMask |
                    RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL) |
                    RelocInfo::ModeMask(RelocInfo::WASM_INDIRECT_CALL_TARGET);
    auto jump_tables_ref =
        FindJumpTablesForRegionLocked(base::AddressRegionOf(dst_code_bytes));
    Address dst_code_addr = reinterpret_cast<Address>(dst_code_bytes.begin());
    Address constant_pool_start = dst_code_addr + constant_pool_offset;
    RelocIterator orig_it(*code, mode_mask);
    for (WritableRelocIterator it(jit_allocation, dst_code_bytes,
                                  reloc_info.as_vector(), constant_pool_start,
                                  mode_mask);
         !it.done(); it.next(), orig_it.next()) {
      RelocInfo::Mode mode = it.rinfo()->rmode();
      if (RelocInfo::IsWasmStubCall(mode)) {
        uint32_t stub_call_tag = orig_it.rinfo()->wasm_call_tag();
        DCHECK_LT(stub_call_tag,
                  static_cast<uint32_t>(Builtin::kFirstBytecodeHandler));
        Builtin builtin = static_cast<Builtin>(stub_call_tag);
        Address entry = GetJumpTableEntryForBuiltin(builtin, jump_tables_ref);
        it.rinfo()->set_wasm_stub_call_address(entry);
      } else if (RelocInfo::IsWasmIndirectCallTarget(mode)) {
        Address function_index = it.rinfo()->wasm_indirect_call_target();
        WasmCodePointer target =
            GetIndirectCallTarget(base::checked_cast<uint32_t>(function_index));
        it.rinfo()->set_wasm_indirect_call_target(target, SKIP_ICACHE_FLUSH);
      } else {
        it.rinfo()->apply(delta);
      }
    }
  }

  // Flush the i-cache after relocation.
  FlushInstructionCache(dst_code_bytes.begin(), dst_code_bytes.size());

  std::unique_ptr<WasmCode> new_code{
      new WasmCode{this,                     // native_module
                   kAnonymousFuncIndex,      // index
                   dst_code_bytes,           // instructions
                   stack_slots,              // stack_slots
                   0,                        // ool_spills
                   0,                        // tagged_parameter_slots
                   safepoint_table_offset,   // safepoint_table_offset
                   handler_table_offset,     // handler_table_offset
                   constant_pool_offset,     // constant_pool_offset
                   code_comments_offset,     // code_comments_offset
                   instructions.length(),    // unpadded_binary_size
                   {},                       // protected_instructions
                   reloc_info.as_vector(),   // reloc_info
                   source_pos.as_vector(),   // source positions
                   {},                       // inlining positions
                   {},                       // deopt data
                   WasmCode::kWasmFunction,  // kind
                   ExecutionTier::kNone,     // tier
                   kNotForDebugging}};       // for_debugging
  new_code->MaybePrint();
  new_code->Validate();

  return PublishCodeLocked(std::move(new_code));
}

void NativeModule::InitializeJumpTableForLazyCompilation(
    uint32_t num_wasm_functions) {
  if (!num_wasm_functions) return;
  allocation_mutex_.AssertHeld();

  DCHECK_NULL(lazy_compile_table_);
  lazy_compile_table_ = CreateEmptyJumpTableLocked(
      JumpTableAssembler::SizeForNumberOfLazyFunctions(num_wasm_functions),
      JumpTableType::kLazyCompileTable);

  CHECK_EQ(1, code_space_data_.size());
  const CodeSpaceData& code_space_data = code_space_data_[0];
  DCHECK_NOT_NULL(code_space_data.jump_table);
  DCHECK_NOT_NULL(code_space_data.far_jump_table);

  Address compile_lazy_address =
      code_space_data.far_jump_table->instruction_start() +
      JumpTableAssembler::FarJumpSlotIndexToOffset(
          BuiltinLookup::JumptableIndexForBuiltin(Builtin::kWasmCompileLazy));

  JumpTableAssembler::GenerateLazyCompileTable(
      lazy_compile_table_->instruction_start(), num_wasm_functions,
      module_->num_imported_functions, compile_lazy_address);

  JumpTableAssembler::InitializeJumpsToLazyCompileTable(
      code_space_data.jump_table->instruction_start(), num_wasm_functions,
      lazy_compile_table_->instruction_start());

  WasmCodePointerTable* code_pointer_table =
      GetProcessWideWasmCodePointerTable();
  WasmCodePointerTable::WriteScope write_scope(
      "Initialize WasmCodePointerTable");
  DCHECK_LE(num_wasm_functions, code_pointer_handles_size_);
  for (uint32_t i = 0; i < num_wasm_functions; i++) {
    code_pointer_table->SetEntrypointWithWriteScope(
        code_pointer_handles_[i],
        lazy_compile_table_->instruction_start() +
            JumpTableAssembler::LazyCompileSlotIndexToOffset(i),
        write_scope);
  }
}

void NativeModule::UseLazyStubLocked(uint32_t func_index) {
  allocation_mutex_.AssertHeld();
  DCHECK_LE(module_->num_imported_functions, func_index);
  DCHECK_LT(func_index,
            module_->num_imported_functions + module_->num_declared_functions);
  // Avoid opening a new write scope per function. The caller should hold the
  // scope instead.

  DCHECK_NOT_NULL(lazy_compile_table_);

  // Add jump table entry for jump to the lazy compile stub.
  uint32_t slot_index = declared_function_index(module(), func_index);
  DCHECK_NULL(code_table_[slot_index]);
  Address lazy_compile_target =
      lazy_compile_table_->instruction_start() +
      JumpTableAssembler::LazyCompileSlotIndexToOffset(slot_index);
  PatchJumpTablesLocked(slot_index, lazy_compile_target);
}

std::unique_ptr<WasmCode> NativeModule::AddCode(
    int index, const CodeDesc& desc, int stack_slots, int ool_spill_count,
    uint32_t tagged_parameter_slots,
    base::Vector<const uint8_t> protected_instructions_data,
    base::Vector<const uint8_t> source_position_table,
    base::Vector<const uint8_t> inlining_positions,
    base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
    ExecutionTier tier, ForDebugging for_debugging) {
  base::Vector<uint8_t> code_space;
  NativeModule::JumpTablesRef jump_table_ref;
  {
    base::RecursiveMutexGuard guard{&allocation_mutex_};
    code_space = code_allocator_.AllocateForCode(this, desc.instr_size);
    jump_table_ref =
        FindJumpTablesForRegionLocked(base::AddressRegionOf(code_space));
  }
  // Only Liftoff code can have the {frame_has_feedback_slot} bit set.
  DCHECK_NE(tier, ExecutionTier::kLiftoff);
  bool frame_has_feedback_slot = false;
  ThreadIsolation::RegisterJitAllocation(
      reinterpret_cast<Address>(code_space.begin()), code_space.size(),
      ThreadIsolation::JitAllocationType::kWasmCode);
  return AddCodeWithCodeSpace(
      index, desc, stack_slots, ool_spill_count, tagged_parameter_slots,
      protected_instructions_data, source_position_table, inlining_positions,
      deopt_data, kind, tier, for_debugging, frame_has_feedback_slot,
      code_space, jump_table_ref);
}

void NativeModule::FreeCodePointerTableHandles() {
  WasmCodePointerTable* code_pointer_table =
      GetProcessWideWasmCodePointerTable();
  for (uint32_t i = 0; i < code_pointer_handles_size_; i++) {
    code_pointer_table->FreeEntry(code_pointer_handles_[i]);
  }

  code_pointer_handles_.reset();
  code_pointer_handles_size_ = 0;
}

void NativeModule::InitializeCodePointerTableHandles(
    uint32_t num_wasm_functions) {
  if (code_pointer_handles_size_ != 0) {
    // During testing, we might already have code pointer handles allocated.
    FreeCodePointerTableHandles();
  }
  code_pointer_handles_ =
      std::make_unique<WasmCodePointerTable::Handle[]>(num_wasm_functions);
  code_pointer_handles_size_ = num_wasm_functions;

  WasmCodePointerTable* code_pointer_table =
      GetProcessWideWasmCodePointerTable();
  for (uint32_t i = 0; i < num_wasm_functions; i++) {
    code_pointer_handles_[i] = code_pointer_table->AllocateUninitializedEntry();
  }
}

std::unique_ptr<WasmCode> NativeModule::AddCodeWithCodeSpace(
    int index, const CodeDesc& desc, int stack_slots, int ool_spill_count,
    uint32_t tagged_parameter_slots,
    base::Vector<const uint8_t> protected_instructions_data,
    base::Vector<const uint8_t> source_position_table,
    base::Vector<const uint8_t> inlining_positions,
    base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
    ExecutionTier tier, ForDebugging for_debugging,
    bool frame_has_feedback_slot, base::Vector<uint8_t> dst_code_bytes,
    const JumpTablesRef& jump_tables) {
  base::Vector<uint8_t> reloc_info{
      desc.buffer + desc.buffer_size - desc.reloc_size,
      static_cast<size_t>(desc.reloc_size)};
  UpdateCodeSize(desc.instr_size, tier, for_debugging);

  // TODO(jgruber,v8:8758): Remove this translation. It exists only because
  // CodeDesc contains real offsets but WasmCode expects an offset of 0 to mean
  // 'empty'.
  const int safepoint_table_offset =
      desc.safepoint_table_size == 0 ? 0 : desc.safepoint_table_offset;
  const int handler_table_offset = desc.handler_table_offset;
  const int constant_pool_offset = desc.constant_pool_offset;
  const int code_comments_offset = desc.code_comments_offset;
  const int instr_size = desc.instr_size;

  {
    WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
        reinterpret_cast<Address>(dst_code_bytes.begin()),
        dst_code_bytes.size(), ThreadIsolation::JitAllocationType::kWasmCode,
        true);
    jit_allocation.CopyCode(0, desc.buffer, desc.instr_size);

    // Apply the relocation delta by iterating over the RelocInfo.
    intptr_t delta = dst_code_bytes.begin() - desc.buffer;
    int mode_mask = RelocInfo::kApplyMask |
                    RelocInfo::ModeMask(RelocInfo::WASM_CALL) |
                    RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL) |
                    RelocInfo::ModeMask(RelocInfo::WASM_INDIRECT_CALL_TARGET);
    Address code_start = reinterpret_cast<Address>(dst_code_bytes.begin());
    Address constant_pool_start = code_start + constant_pool_offset;

    for (WritableRelocIterator it(jit_allocation, dst_code_bytes, reloc_info,
                                  constant_pool_start, mode_mask);
         !it.done(); it.next()) {
      RelocInfo::Mode mode = it.rinfo()->rmode();
      if (RelocInfo::IsWasmCall(mode)) {
        uint32_t call_tag = it.rinfo()->wasm_call_tag();
        Address target = GetNearCallTargetForFunction(call_tag, jump_tables);
        it.rinfo()->set_wasm_call_address(target);
      } else if (RelocInfo::IsWasmStubCall(mode)) {
        uint32_t stub_call_tag = it.rinfo()->wasm_call_tag();
        DCHECK_LT(stub_call_tag,
                  static_cast<uint32_t>(Builtin::kFirstBytecodeHandler));
        Builtin builtin = static_cast<Builtin>(stub_call_tag);
        Address entry = GetJumpTableEntryForBuiltin(builtin, jump_tables);
        it.rinfo()->set_wasm_stub_call_address(entry);
      } else if (RelocInfo::IsWasmIndirectCallTarget(mode)) {
        Address function_index = it.rinfo()->wasm_indirect_call_target();
        WasmCodePointer target =
            GetIndirectCallTarget(base::checked_cast<uint32_t>(function_index));
        it.rinfo()->set_wasm_indirect_call_target(target, SKIP_ICACHE_FLUSH);
      } else {
        it.rinfo()->apply(delta);
      }
    }
  }

  // Flush the i-cache after relocation.
  FlushInstructionCache(dst_code_bytes.begin(), dst_code_bytes.size());

  // Liftoff code will not be relocated or serialized, thus do not store any
  // relocation information.
  if (tier == ExecutionTier::kLiftoff) reloc_info = {};

  std::unique_ptr<WasmCode> code{new WasmCode{this,
                                              index,
                                              dst_code_bytes,
                                              stack_slots,
                                              ool_spill_count,
                                              tagged_parameter_slots,
                                              safepoint_table_offset,
                                              handler_table_offset,
                                              constant_pool_offset,
                                              code_comments_offset,
                                              instr_size,
                                              protected_instructions_data,
                                              reloc_info,
                                              source_position_table,
                                              inlining_positions,
                                              deopt_data,
                                              kind,
                                              tier,
                                              for_debugging,
                                              frame_has_feedback_slot}};

  code->MaybePrint();
  code->Validate();

  return code;
}

WasmCode* NativeModule::PublishCode(std::unique_ptr<WasmCode> code,
                                    AssumptionsJournal* assumptions) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.PublishCode");
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  if (assumptions != nullptr) {
    // Acquiring the lock is expensive, so callers should only pass non-empty
    // assumptions journals.
    DCHECK(!assumptions->empty());
    // Only Turbofan makes assumptions.
    DCHECK_EQ(ExecutionTier::kTurbofan, code->tier());
    WellKnownImportsList& current = module_->type_feedback.well_known_imports;
    for (auto [import_index, status] : assumptions->import_statuses()) {
      if (current.get(import_index) != status) {
        compilation_state_->AllowAnotherTopTierJob(code->index());
        return nullptr;
      }
    }
  }
  return PublishCodeLocked(std::move(code));
}

std::vector<WasmCode*> NativeModule::PublishCode(
    base::Vector<std::unique_ptr<WasmCode>> codes) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.PublishCode", "number", codes.size());
  std::vector<WasmCode*> published_code;
  published_code.reserve(codes.size());
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  // The published code is put into the top-most surrounding {WasmCodeRefScope}.
  for (auto& code : codes) {
    published_code.push_back(PublishCodeLocked(std::move(code)));
  }
  return published_code;
}

void NativeModule::UpdateWellKnownImports(
    base::Vector<WellKnownImport> entries) {
  // The {~WasmCodeRefScope} destructor must run after releasing the {lock},
  // to avoid lock order inversion.
  WasmCodeRefScope ref_scope;
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  WellKnownImportsList::UpdateResult result =
      module_->type_feedback.well_known_imports.Update(entries);
  if (result == WellKnownImportsList::UpdateResult::kFoundIncompatibility) {
    RemoveCompiledCode(NativeModule::RemoveFilter::kRemoveTurbofanCode);
  }
}

WasmCode::Kind GetCodeKind(const WasmCompilationResult& result) {
  switch (result.kind) {
    case WasmCompilationResult::kWasmToJsWrapper:
      return WasmCode::Kind::kWasmToJsWrapper;
#if V8_ENABLE_DRUMBRAKE
    case WasmCompilationResult::kInterpreterEntry:
      return WasmCode::Kind::kInterpreterEntry;
#endif  // V8_ENABLE_DRUMBRAKE
    case WasmCompilationResult::kFunction:
      return WasmCode::Kind::kWasmFunction;
    default:
      UNREACHABLE();
  }
}

WasmCode* NativeModule::PublishCodeLocked(
    std::unique_ptr<WasmCode> owned_code) {
  allocation_mutex_.AssertHeld();

  WasmCode* code = owned_code.get();
  new_owned_code_.emplace_back(std::move(owned_code));

  // Add the code to the surrounding code ref scope, so the returned pointer is
  // guaranteed to be valid.
  WasmCodeRefScope::AddRef(code);

  if (code->index() < static_cast<int>(module_->num_imported_functions)) {
    return code;
  }

  DCHECK_LT(code->index(), num_functions());

  code->RegisterTrapHandlerData();

  // Assume an order of execution tiers that represents the quality of their
  // generated code.
  static_assert(ExecutionTier::kNone < ExecutionTier::kLiftoff &&
                    ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                "Assume an order on execution tiers");

  uint32_t slot_idx = declared_function_index(module(), code->index());
  WasmCode* prior_code = code_table_[slot_idx];
  // If we are tiered down, install all debugging code (except for stepping
  // code, which is only used for a single frame and never installed in the
  // code table of jump table). Otherwise, install code if it was compiled
  // with a higher tier.
  static_assert(
      kForDebugging > kNotForDebugging && kWithBreakpoints > kForDebugging,
      "for_debugging is ordered");

  if (should_update_code_table(code, prior_code)) {
    code_table_[slot_idx] = code;
    if (prior_code) {
      WasmCodeRefScope::AddRef(prior_code);
      // The code is added to the current {WasmCodeRefScope}, hence the ref
      // count cannot drop to zero here.
      prior_code->DecRefOnLiveCode();
    }

    PatchJumpTablesLocked(slot_idx, code->instruction_start());
  } else {
    // The code tables does not hold a reference to the code, hence decrement
    // the initial ref count of 1. The code was added to the
    // {WasmCodeRefScope} though, so it cannot die here.
    code->DecRefOnLiveCode();
  }

  return code;
}

bool NativeModule::should_update_code_table(WasmCode* new_code,
                                            WasmCode* prior_code) const {
  if (new_code->for_debugging() == kForStepping) {
    // Never install stepping code.
    return false;
  }
  if (debug_state_ == kDebugging) {
    if (new_code->for_debugging() == kNotForDebugging) {
      // In debug state, only install debug code.
      return false;
    }
    if (prior_code && prior_code->for_debugging() > new_code->for_debugging()) {
      // In debug state, install breakpoints over normal debug code.
      return false;
    }
  }
  // In kNoDebugging:
  // Install if the tier is higher than before or we replace debugging code with
  // non-debugging code.
  // Also allow installing a lower tier if deopt support is enabled and the
  // prior code has deopt data. (The check for deopt_data is needed as with
  // compilation hints, both baseline and top tier compilation run concurrently
  // in the background and can finish in any order.)
  if (prior_code && !prior_code->for_debugging() &&
      prior_code->tier() > new_code->tier() &&
      (!v8_flags.wasm_deopt || prior_code->deopt_data().empty())) {
    return false;
  }
  return true;
}

void NativeModule::ReinstallDebugCode(WasmCode* code) {
  base::RecursiveMutexGuard lock(&allocation_mutex_);

  DCHECK_EQ(this, code->native_module());
  DCHECK_EQ(kWithBreakpoints, code->for_debugging());
  DCHECK(!code->IsAnonymous());
  DCHECK_LE(module_->num_imported_functions, code->index());
  DCHECK_LT(code->index(), num_functions());

  // If the module is tiered up by now, do not reinstall debug code.
  if (debug_state_ != kDebugging) return;

  uint32_t slot_idx = declared_function_index(module(), code->index());
  if (WasmCode* prior_code = code_table_[slot_idx]) {
    WasmCodeRefScope::AddRef(prior_code);
    // The code is added to the current {WasmCodeRefScope}, hence the ref
    // count cannot drop to zero here.
    prior_code->DecRefOnLiveCode();
  }
  code_table_[slot_idx] = code;
  code->IncRef();

  PatchJumpTablesLocked(slot_idx, code->instruction_start());
}

std::pair<base::Vector<uint8_t>, NativeModule::JumpTablesRef>
NativeModule::AllocateForDeserializedCode(size_t total_code_size) {
  base::RecursiveMutexGuard guard{&allocation_mutex_};
  base::Vector<uint8_t> code_space =
      code_allocator_.AllocateForCode(this, total_code_size);
  auto jump_tables =
      FindJumpTablesForRegionLocked(base::AddressRegionOf(code_space));
  return {code_space, jump_tables};
}

std::unique_ptr<WasmCode> NativeModule::AddDeserializedCode(
    int index, base::Vector<uint8_t> instructions, int stack_slots,
    int ool_spills, uint32_t tagged_parameter_slots, int safepoint_table_offset,
    int handler_table_offset, int constant_pool_offset,
    int code_comments_offset, int unpadded_binary_size,
    base::Vector<const uint8_t> protected_instructions_data,
    base::Vector<const uint8_t> reloc_info,
    base::Vector<const uint8_t> source_position_table,
    base::Vector<const uint8_t> inlining_positions,
    base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
    ExecutionTier tier) {
  UpdateCodeSize(instructions.size(), tier, kNotForDebugging);

  return std::unique_ptr<WasmCode>{new WasmCode{
      this, index, instructions, stack_slots, ool_spills,
      tagged_parameter_slots, safepoint_table_offset, handler_table_offset,
      constant_pool_offset, code_comments_offset, unpadded_binary_size,
      protected_instructions_data, reloc_info, source_position_table,
      inlining_positions, deopt_data, kind, tier, kNotForDebugging}};
}

std::pair<std::vector<WasmCode*>, std::vector<WellKnownImport>>
NativeModule::SnapshotCodeTable() const {
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  WasmCode** start = code_table_.get();
  WasmCode** end = start + module_->num_declared_functions;
  for (WasmCode* code : base::VectorOf(start, end - start)) {
    if (code) WasmCodeRefScope::AddRef(code);
  }
  std::vector<WellKnownImport> import_statuses(module_->num_imported_functions);
  for (uint32_t i = 0; i < module_->num
"""


```