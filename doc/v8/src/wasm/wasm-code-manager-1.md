Response: The user wants to understand the functionality of the C++ code provided in the `v8/src/wasm/wasm-code-manager.cc` file. This is the second part of the file.

**Plan:**

1. Read through the provided code snippets, paying attention to the class methods and their operations.
2. Summarize the functionality of the `NativeModule` class, as this part of the code heavily relies on it.
3. Identify relationships with JavaScript functionality and provide JavaScript examples where relevant.
4. Focus on the parts of the `NativeModule` class that were not covered in the first part.
This C++ code snippet is part of the `v8/src/wasm/wasm-code-manager.cc` file and focuses on the functionalities of the `NativeModule` class related to managing compiled WebAssembly code. Specifically, this part deals with:

*   **Code Lookup and Management:**  It provides methods for finding `WasmCode` objects by program counter (PC) address (`Lookup`), retrieving specific code based on its index (`GetCode`), and checking if code exists for a function (`HasCode`, `HasCodeWithTier`).
*   **Jump Table Management:**  It handles the creation, patching, and management of jump tables (`CreateEmptyJumpTableLocked`, `CreateEmptyJumpTableInRegionLocked`, `PatchJumpTablesLocked`, `PatchJumpTableLocked`). Jump tables are crucial for efficient indirect calls and function calls in WebAssembly.
*   **Code Space Allocation:**  It manages adding new memory regions for storing compiled code (`AddCodeSpaceLocked`).
*   **Wire Bytes Storage:** It handles storing and accessing the original WebAssembly bytecode (`SetWireBytes`).
*   **Lazy Compilation Statistics:** It tracks the number and duration of lazy compilations (`AddLazyCompilationTimeSample`).
*   **Owned Code Tracking:** It maintains a sorted list of all allocated `WasmCode` objects (`owned_code_`, `new_owned_code_`) and provides methods to access and manage them (`SnapshotAllOwnedCode`, `TransferNewOwnedCodeLocked`).
*   **Finding Jump Tables in Regions:** It allows locating suitable jump tables for a given memory region (`FindJumpTablesForRegionLocked`).
*   **Retrieving Call Targets:** It provides functions to get the target address for direct calls (`GetNearCallTargetForFunction`) and indirect calls (`GetIndirectCallTarget`), as well as for built-in functions (`GetJumpTableEntryForBuiltin`).
*   **Reverse Lookup from Jump Table:** It allows finding the function index associated with a given jump table slot address (`GetFunctionIndexFromJumpTableSlot`).
*   **Creating Indirect Call Target Maps:** It generates a map of indirect call targets to their corresponding function indices (`CreateIndirectCallTargetToFunctionIndexMap`).
*   **Identifying Built-in Functions in Jump Tables:** It can determine the built-in function associated with a specific address within a far jump table (`GetBuiltinInJumptableSlot`).
*   **Code Pointer Handles:** It manages handles for accessing function entry points, especially when the code pointer table is enabled (`GetCodePointerHandle`).
*   **Destructor:** The `NativeModule` destructor handles cleanup, including canceling background compilations and freeing the module's resources.

**Relationship with JavaScript Functionality and Examples:**

The functionality described in this code is deeply intertwined with how JavaScript executes WebAssembly code. While the C++ code manages the low-level details of code storage and execution, these actions are triggered and utilized when JavaScript interacts with WebAssembly modules.

Here are some examples illustrating the connection:

1. **Instantiation of a WebAssembly Module:** When you instantiate a WebAssembly module in JavaScript, the V8 engine (which includes this C++ code) allocates memory for the compiled code and metadata. The `NativeModule` class is central to this process.

    ```javascript
    const wasmCode = new Uint8Array([
      0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 0, 1, 127, 3, 2, 1, 0, 5, 3, 1, 0,
      11, 10, 1, 6, 0, 65, 0, 16, 0, 11
    ]);
    const wasmModule = new WebAssembly.Module(wasmCode);
    const wasmInstance = new WebAssembly.Instance(wasmModule, {});
    ```

    Internally, the `WebAssembly.Module` constructor will lead to the creation of a `NativeModule` object, and the `WebAssembly.Instance` constructor will trigger the allocation of code space and potentially the compilation of functions.

2. **Calling a WebAssembly Function:** When you call a WebAssembly function from JavaScript, the engine uses the jump tables managed by `NativeModule` to efficiently jump to the correct entry point of the compiled function.

    ```javascript
    // Assuming wasmInstance from the previous example has an exported function 'add'
    const result = wasmInstance.exports.add(5, 10);
    console.log(result); // Output: 15
    ```

    The call to `wasmInstance.exports.add` will involve looking up the function's entry point in the jump table. The `GetCode` and jump table management methods in `NativeModule` are crucial for this.

3. **Lazy Compilation:**  The `AddLazyCompilationTimeSample` method suggests support for lazy compilation. When a WebAssembly function is called for the first time, it might not be fully compiled. The engine can use a "lazy stub" initially and then compile the function in the background. The `NativeModule` keeps track of the code and updates the jump table when the fully compiled code is ready.

4. **Debugging WebAssembly:** The code mentions `ForDebugging`. When you debug WebAssembly code in a JavaScript environment, the engine might need to load different versions of the compiled code (with debugging information). The `NativeModule` helps manage these different versions and switch between them.

5. **Indirect Calls:** WebAssembly's `call_indirect` instruction relies heavily on jump tables. The `CreateEmptyJumpTableLocked` and related methods are used to create and populate these tables, enabling the efficient execution of indirect calls.

In summary, this part of the `wasm-code-manager.cc` file is fundamental to the efficient and correct execution of WebAssembly code within the V8 JavaScript engine. It handles the core tasks of managing compiled code, function entry points, and the memory regions where the code resides, all of which are essential for the seamless integration of WebAssembly into the JavaScript ecosystem.

Prompt: 
```
这是目录为v8/src/wasm/wasm-code-manager.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
_imported_functions; i++) {
    import_statuses[i] = module_->type_feedback.well_known_imports.get(i);
  }
  return {std::vector<WasmCode*>{start, end}, std::move(import_statuses)};
}

std::vector<WasmCode*> NativeModule::SnapshotAllOwnedCode() const {
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  if (!new_owned_code_.empty()) TransferNewOwnedCodeLocked();

  std::vector<WasmCode*> all_code(owned_code_.size());
  std::transform(owned_code_.begin(), owned_code_.end(), all_code.begin(),
                 [](auto& entry) { return entry.second.get(); });
  std::for_each(all_code.begin(), all_code.end(), WasmCodeRefScope::AddRef);
  return all_code;
}

WasmCode* NativeModule::GetCode(uint32_t index) const {
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  WasmCode* code = code_table_[declared_function_index(module(), index)];
  if (code) WasmCodeRefScope::AddRef(code);
  return code;
}

bool NativeModule::HasCode(uint32_t index) const {
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  return code_table_[declared_function_index(module(), index)] != nullptr;
}

bool NativeModule::HasCodeWithTier(uint32_t index, ExecutionTier tier) const {
  base::RecursiveMutexGuard guard(&allocation_mutex_);
  return code_table_[declared_function_index(module(), index)] != nullptr &&
         code_table_[declared_function_index(module(), index)]->tier() == tier;
}

void NativeModule::SetWasmSourceMap(
    std::unique_ptr<WasmModuleSourceMap> source_map) {
  source_map_ = std::move(source_map);
}

WasmModuleSourceMap* NativeModule::GetWasmSourceMap() const {
  return source_map_.get();
}

WasmCode* NativeModule::CreateEmptyJumpTableLocked(int jump_table_size,
                                                   JumpTableType type) {
  return CreateEmptyJumpTableInRegionLocked(jump_table_size,
                                            kUnrestrictedRegion, type);
}

namespace {

ThreadIsolation::JitAllocationType ToAllocationType(
    v8::internal::wasm::NativeModule::JumpTableType type) {
  switch (type) {
    case NativeModule::JumpTableType::kJumpTable:
      return ThreadIsolation::JitAllocationType::kWasmJumpTable;
    case NativeModule::JumpTableType::kFarJumpTable:
      return ThreadIsolation::JitAllocationType::kWasmFarJumpTable;
    case NativeModule::JumpTableType::kLazyCompileTable:
      return ThreadIsolation::JitAllocationType::kWasmLazyCompileTable;
  }
}

}  // namespace

WasmCode* NativeModule::CreateEmptyJumpTableInRegionLocked(
    int jump_table_size, base::AddressRegion region, JumpTableType type) {
  allocation_mutex_.AssertHeld();
  // Only call this if we really need a jump table.
  DCHECK_LT(0, jump_table_size);
  base::Vector<uint8_t> code_space =
      code_allocator_.AllocateForCodeInRegion(this, jump_table_size, region);
  DCHECK(!code_space.empty());
  UpdateCodeSize(jump_table_size, ExecutionTier::kNone, kNotForDebugging);
  {
    WritableJitAllocation jit_allocation =
        ThreadIsolation::RegisterJitAllocation(
            reinterpret_cast<Address>(code_space.begin()), code_space.size(),
            ToAllocationType(type));
    jit_allocation.ClearBytes(0, code_space.size());
  }
  std::unique_ptr<WasmCode> code{
      new WasmCode{this,                  // native_module
                   kAnonymousFuncIndex,   // index
                   code_space,            // instructions
                   0,                     // stack_slots
                   0,                     // ool_spills
                   0,                     // tagged_parameter_slots
                   0,                     // safepoint_table_offset
                   jump_table_size,       // handler_table_offset
                   jump_table_size,       // constant_pool_offset
                   jump_table_size,       // code_comments_offset
                   jump_table_size,       // unpadded_binary_size
                   {},                    // protected_instructions
                   {},                    // reloc_info
                   {},                    // source_pos
                   {},                    // inlining pos
                   {},                    // deopt data
                   WasmCode::kJumpTable,  // kind
                   ExecutionTier::kNone,  // tier
                   kNotForDebugging}};    // for_debugging
  return PublishCodeLocked(std::move(code));
}

void NativeModule::UpdateCodeSize(size_t size, ExecutionTier tier,
                                  ForDebugging for_debugging) {
  if (for_debugging != kNotForDebugging) return;
  // Count jump tables (ExecutionTier::kNone) for both Liftoff and TurboFan as
  // this is shared code.
  if (tier != ExecutionTier::kTurbofan) liftoff_code_size_.fetch_add(size);
  if (tier != ExecutionTier::kLiftoff) turbofan_code_size_.fetch_add(size);
}

void NativeModule::PatchJumpTablesLocked(uint32_t slot_index, Address target) {
  allocation_mutex_.AssertHeld();

  GetProcessWideWasmCodePointerTable()->SetEntrypoint(
      code_pointer_handles_[slot_index], target);

  for (auto& code_space_data : code_space_data_) {
    // TODO(sroettger): need to unlock both jump tables together
    DCHECK_IMPLIES(code_space_data.jump_table, code_space_data.far_jump_table);
    if (!code_space_data.jump_table) continue;
    WritableJumpTablePair writable_jump_tables =
        ThreadIsolation::LookupJumpTableAllocations(
            code_space_data.jump_table->instruction_start(),
            code_space_data.jump_table->instructions_size_,
            code_space_data.far_jump_table->instruction_start(),
            code_space_data.far_jump_table->instructions_size_);
    PatchJumpTableLocked(writable_jump_tables, code_space_data, slot_index,
                         target);
  }
}

void NativeModule::PatchJumpTableLocked(WritableJumpTablePair& jump_table_pair,
                                        const CodeSpaceData& code_space_data,
                                        uint32_t slot_index, Address target) {
  allocation_mutex_.AssertHeld();

  DCHECK_NOT_NULL(code_space_data.jump_table);
  DCHECK_NOT_NULL(code_space_data.far_jump_table);

  DCHECK_LT(slot_index, module_->num_declared_functions);
  Address jump_table_slot =
      code_space_data.jump_table->instruction_start() +
      JumpTableAssembler::JumpSlotIndexToOffset(slot_index);
  uint32_t far_jump_table_offset = JumpTableAssembler::FarJumpSlotIndexToOffset(
      BuiltinLookup::BuiltinCount() + slot_index);
  // Only pass the far jump table start if the far jump table actually has a
  // slot for this function index (i.e. does not only contain runtime stubs).
  bool has_far_jump_slot =
      far_jump_table_offset <
      code_space_data.far_jump_table->instructions().size();
  Address far_jump_table_start =
      code_space_data.far_jump_table->instruction_start();
  Address far_jump_table_slot =
      has_far_jump_slot ? far_jump_table_start + far_jump_table_offset
                        : kNullAddress;
  JumpTableAssembler::PatchJumpTableSlot(jump_table_pair, jump_table_slot,
                                         far_jump_table_slot, target);
  DCHECK_LT(slot_index, code_pointer_handles_size_);
  GetProcessWideWasmCodePointerTable()->SetEntrypointWithRwxWriteScope(
      code_pointer_handles_[slot_index], target, jump_table_pair.write_scope());
}

void NativeModule::AddCodeSpaceLocked(base::AddressRegion region) {
  allocation_mutex_.AssertHeld();

  // Each code space must be at least twice as large as the overhead per code
  // space. Otherwise, we are wasting too much memory.
  DCHECK_GE(region.size(),
            2 * OverheadPerCodeSpace(module()->num_declared_functions));

  WasmCodeRefScope code_ref_scope;
  WasmCode* jump_table = nullptr;
  WasmCode* far_jump_table = nullptr;
  const uint32_t num_wasm_functions = module_->num_declared_functions;
  const bool is_first_code_space = code_space_data_.empty();
  // We always need a far jump table, because it contains the runtime stubs.
  const bool needs_far_jump_table =
      !FindJumpTablesForRegionLocked(region).is_valid();
  const bool needs_jump_table = num_wasm_functions > 0 && needs_far_jump_table;

  if (needs_jump_table) {
    // Allocate additional jump tables just as big as the first one.
    // This is in particular needed in cctests which add functions to the module
    // after the jump tables are already created (see https://crbug.com/v8/14213
    // and {NativeModule::ReserveCodeTableForTesting}.
    int jump_table_size =
        is_first_code_space
            ? JumpTableAssembler::SizeForNumberOfSlots(num_wasm_functions)
            : main_jump_table_->instructions_size_;
    jump_table = CreateEmptyJumpTableInRegionLocked(jump_table_size, region,
                                                    JumpTableType::kJumpTable);
    CHECK(region.contains(jump_table->instruction_start()));
  }

  if (needs_far_jump_table) {
    int num_function_slots = NumWasmFunctionsInFarJumpTable(num_wasm_functions);
    // See comment above for the size computation.
    int far_jump_table_size =
        is_first_code_space
            ? JumpTableAssembler::SizeForNumberOfFarJumpSlots(
                  BuiltinLookup::BuiltinCount(), num_function_slots)
            : main_far_jump_table_->instructions_size_;
    far_jump_table = CreateEmptyJumpTableInRegionLocked(
        far_jump_table_size, region, JumpTableType::kFarJumpTable);
    CHECK(region.contains(far_jump_table->instruction_start()));
    EmbeddedData embedded_data = EmbeddedData::FromBlob();
    static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
    Address builtin_addresses[BuiltinLookup::BuiltinCount()];
    for (int i = 0; i < BuiltinLookup::BuiltinCount(); ++i) {
      builtin_addresses[i] = embedded_data.InstructionStartOf(
          BuiltinLookup::BuiltinForJumptableIndex(i));
    }
    WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
        far_jump_table->instruction_start(), far_jump_table->instructions_size_,
        ThreadIsolation::JitAllocationType::kWasmFarJumpTable);

    JumpTableAssembler::GenerateFarJumpTable(
        jit_allocation, far_jump_table->instruction_start(), builtin_addresses,
        BuiltinLookup::BuiltinCount(), num_function_slots);
  }

  if (is_first_code_space) {
    // This can be updated and accessed without locks, since the addition of the
    // first code space happens during initialization of the {NativeModule},
    // where no concurrent accesses are possible.
    main_jump_table_ = jump_table;
    main_far_jump_table_ = far_jump_table;
  }

  code_space_data_.push_back(CodeSpaceData{region, jump_table, far_jump_table});

  if (is_first_code_space) {
    InitializeJumpTableForLazyCompilation(num_wasm_functions);
  }

  if (jump_table && !is_first_code_space) {
    // Patch the new jump table(s) with existing functions. If this is the first
    // code space, there cannot be any functions that have been compiled yet.
    const CodeSpaceData& new_code_space_data = code_space_data_.back();
    // TODO(sroettger): need to create two write scopes? Or have a write scope
    // for multiple allocations.
    WritableJumpTablePair writable_jump_tables =
        ThreadIsolation::LookupJumpTableAllocations(
            new_code_space_data.jump_table->instruction_start(),

            new_code_space_data.jump_table->instructions_size_,
            new_code_space_data.far_jump_table->instruction_start(),

            new_code_space_data.far_jump_table->instructions_size_);
    for (uint32_t slot_index = 0; slot_index < num_wasm_functions;
         ++slot_index) {
      if (code_table_[slot_index]) {
        PatchJumpTableLocked(writable_jump_tables, new_code_space_data,
                             slot_index,
                             code_table_[slot_index]->instruction_start());
      } else if (lazy_compile_table_) {
        // Use the main jump table as the target so that we don't have to add a
        // landing pad instruction to the lazy compile table entries.
        Address main_jump_table_target =
            main_jump_table_->instruction_start() +
            JumpTableAssembler::JumpSlotIndexToOffset(slot_index);
        PatchJumpTableLocked(writable_jump_tables, new_code_space_data,
                             slot_index, main_jump_table_target);
      }
    }
  }
}

namespace {
class NativeModuleWireBytesStorage final : public WireBytesStorage {
 public:
  explicit NativeModuleWireBytesStorage(
      std::shared_ptr<base::OwnedVector<const uint8_t>> wire_bytes)
      : wire_bytes_(std::move(wire_bytes)) {}

  base::Vector<const uint8_t> GetCode(WireBytesRef ref) const final {
    return std::atomic_load(&wire_bytes_)
        ->as_vector()
        .SubVector(ref.offset(), ref.end_offset());
  }

  std::optional<ModuleWireBytes> GetModuleBytes() const final {
    return std::optional<ModuleWireBytes>(
        std::atomic_load(&wire_bytes_)->as_vector());
  }

 private:
  const std::shared_ptr<base::OwnedVector<const uint8_t>> wire_bytes_;
};
}  // namespace

void NativeModule::SetWireBytes(base::OwnedVector<const uint8_t> wire_bytes) {
  auto shared_wire_bytes =
      std::make_shared<base::OwnedVector<const uint8_t>>(std::move(wire_bytes));
  std::atomic_store(&wire_bytes_, shared_wire_bytes);
  if (!shared_wire_bytes->empty()) {
    compilation_state_->SetWireBytesStorage(
        std::make_shared<NativeModuleWireBytesStorage>(
            std::move(shared_wire_bytes)));
  }
}

void NativeModule::AddLazyCompilationTimeSample(int64_t sample_in_micro_sec) {
  num_lazy_compilations_.fetch_add(1, std::memory_order_relaxed);
  sum_lazy_compilation_time_in_micro_sec_.fetch_add(sample_in_micro_sec,
                                                    std::memory_order_relaxed);
  int64_t max =
      max_lazy_compilation_time_in_micro_sec_.load(std::memory_order_relaxed);
  while (sample_in_micro_sec > max &&
         !max_lazy_compilation_time_in_micro_sec_.compare_exchange_weak(
             max, sample_in_micro_sec, std::memory_order_relaxed,
             std::memory_order_relaxed)) {
    // Repeat until we set the new maximum sucessfully.
  }
}

void NativeModule::TransferNewOwnedCodeLocked() const {
  allocation_mutex_.AssertHeld();
  DCHECK(!new_owned_code_.empty());
  // Sort the {new_owned_code_} vector reversed, such that the position of the
  // previously inserted element can be used as a hint for the next element. If
  // elements in {new_owned_code_} are adjacent, this will guarantee
  // constant-time insertion into the map.
  std::sort(new_owned_code_.begin(), new_owned_code_.end(),
            [](const std::unique_ptr<WasmCode>& a,
               const std::unique_ptr<WasmCode>& b) {
              return a->instruction_start() > b->instruction_start();
            });
  auto insertion_hint = owned_code_.end();
  for (auto& code : new_owned_code_) {
    DCHECK_EQ(0, owned_code_.count(code->instruction_start()));
    // Check plausibility of the insertion hint.
    DCHECK(insertion_hint == owned_code_.end() ||
           insertion_hint->first > code->instruction_start());
    insertion_hint = owned_code_.emplace_hint(
        insertion_hint, code->instruction_start(), std::move(code));
  }
  new_owned_code_.clear();
}

WasmCode* NativeModule::Lookup(Address pc) const {
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  if (!new_owned_code_.empty()) TransferNewOwnedCodeLocked();
  auto iter = owned_code_.upper_bound(pc);
  if (iter == owned_code_.begin()) return nullptr;
  --iter;
  WasmCode* candidate = iter->second.get();
  DCHECK_EQ(candidate->instruction_start(), iter->first);
  if (!candidate->contains(pc)) return nullptr;
  WasmCodeRefScope::AddRef(candidate);
  return candidate;
}

NativeModule::JumpTablesRef NativeModule::FindJumpTablesForRegionLocked(
    base::AddressRegion code_region) const {
  allocation_mutex_.AssertHeld();
  auto jump_table_usable = [code_region](const WasmCode* jump_table) {
    // We only ever need to check for suitable jump tables if
    // {kNeedsFarJumpsBetweenCodeSpaces} is true.
    if constexpr (!kNeedsFarJumpsBetweenCodeSpaces) UNREACHABLE();
    Address table_start = jump_table->instruction_start();
    Address table_end = table_start + jump_table->instructions().size();
    // Compute the maximum distance from anywhere in the code region to anywhere
    // in the jump table, avoiding any underflow.
    size_t max_distance = std::max(
        code_region.end() > table_start ? code_region.end() - table_start : 0,
        table_end > code_region.begin() ? table_end - code_region.begin() : 0);
    // kDefaultMaxWasmCodeSpaceSizeMb is <= the maximum near call distance on
    // the current platform.
    // We can allow a max_distance that is equal to
    // kDefaultMaxWasmCodeSpaceSizeMb, because every call or jump will target an
    // address *within* the region, but never exactly the end of the region. So
    // all occuring offsets are actually smaller than max_distance.
    return max_distance <= kDefaultMaxWasmCodeSpaceSizeMb * MB;
  };

  for (auto& code_space_data : code_space_data_) {
    DCHECK_IMPLIES(code_space_data.jump_table, code_space_data.far_jump_table);
    if (!code_space_data.far_jump_table) continue;
    // Only return these jump tables if they are reachable from the whole
    // {code_region}.
    if (kNeedsFarJumpsBetweenCodeSpaces &&
        (!jump_table_usable(code_space_data.far_jump_table) ||
         (code_space_data.jump_table &&
          !jump_table_usable(code_space_data.jump_table)))) {
      continue;
    }
    return {code_space_data.jump_table
                ? code_space_data.jump_table->instruction_start()
                : kNullAddress,
            code_space_data.far_jump_table->instruction_start()};
  }
  return {};
}

Address NativeModule::GetNearCallTargetForFunction(
    uint32_t func_index, const JumpTablesRef& jump_tables) const {
  DCHECK(jump_tables.is_valid());
  uint32_t slot_offset = JumpTableOffset(module(), func_index);
  return jump_tables.jump_table_start + slot_offset;
}

Address NativeModule::GetJumpTableEntryForBuiltin(
    Builtin builtin, const JumpTablesRef& jump_tables) const {
  DCHECK(jump_tables.is_valid());
  int index = BuiltinLookup::JumptableIndexForBuiltin(builtin);

  auto offset = JumpTableAssembler::FarJumpSlotIndexToOffset(index);
  return jump_tables.far_jump_table_start + offset;
}

uint32_t NativeModule::GetFunctionIndexFromJumpTableSlot(
    Address slot_address) const {
  WasmCodeRefScope code_refs;
  WasmCode* code = Lookup(slot_address);
  DCHECK_NOT_NULL(code);
  DCHECK_EQ(WasmCode::kJumpTable, code->kind());
  uint32_t slot_offset =
      static_cast<uint32_t>(slot_address - code->instruction_start());
  uint32_t slot_idx = JumpTableAssembler::SlotOffsetToIndex(slot_offset);
  DCHECK_LT(slot_idx, module_->num_declared_functions);
  DCHECK_EQ(slot_address,
            code->instruction_start() +
                JumpTableAssembler::JumpSlotIndexToOffset(slot_idx));
  return module_->num_imported_functions + slot_idx;
}

NativeModule::CallIndirectTargetMap
NativeModule::CreateIndirectCallTargetToFunctionIndexMap() const {
  absl::flat_hash_map<WasmCodePointer, uint32_t> lookup_map;
  for (uint32_t func_index = num_imported_functions();
       func_index < num_functions(); func_index++) {
    lookup_map.emplace(GetIndirectCallTarget(func_index), func_index);
  }
  return lookup_map;
}

Builtin NativeModule::GetBuiltinInJumptableSlot(Address target) const {
  base::RecursiveMutexGuard guard(&allocation_mutex_);

  for (auto& code_space_data : code_space_data_) {
    if (code_space_data.far_jump_table != nullptr &&
        code_space_data.far_jump_table->contains(target)) {
      uint32_t offset = static_cast<uint32_t>(
          target - code_space_data.far_jump_table->instruction_start());
      uint32_t index = JumpTableAssembler::FarJumpSlotOffsetToIndex(offset);
      if (index >= BuiltinLookup::BuiltinCount()) continue;
      if (JumpTableAssembler::FarJumpSlotIndexToOffset(index) != offset) {
        continue;
      }
      return BuiltinLookup::BuiltinForJumptableIndex(index);
    }
  }

  // Invalid address.
  return Builtin::kNoBuiltinId;
}

WasmCodePointerTable::Handle NativeModule::GetCodePointerHandle(
    int index) const {
  DCHECK_IMPLIES(index != kAnonymousFuncIndex, index >= 0);
  if (index == kAnonymousFuncIndex ||
      static_cast<uint32_t>(index) < module_->num_imported_functions) {
    // TODO(sroettger): do ImportWrappers need a code pointer handle?
    return WasmCodePointerTable::kInvalidHandle;
  }
  return code_pointer_handles_[declared_function_index(module_.get(), index)];
}

WasmCodePointer NativeModule::GetIndirectCallTarget(int func_index) const {
  DCHECK_GE(func_index, num_imported_functions());
  DCHECK_LT(func_index, num_functions());

#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  return GetCodePointerHandle(func_index);
#else
  return jump_table_start() + JumpTableOffset(module(), func_index);
#endif
}

NativeModule::~NativeModule() {
  TRACE_HEAP("Deleting native module: %p\n", this);
  // Cancel all background compilation before resetting any field of the
  // NativeModule or freeing anything.
  compilation_state_->CancelCompilation();

  GetWasmEngine()->FreeNativeModule(this);

  // If experimental PGO support is enabled, serialize the PGO data now.
  if (V8_UNLIKELY(v8_flags.experimental_wasm_pgo_to_file)) {
    DumpProfileToFile(module_.get(), wire_bytes(), tiering_budgets_.get());
  }

  FreeCodePointerTableHandles();
}

WasmCodeManager::WasmCodeManager()
    : max_committed_code_space_(v8_flags.wasm_max_committed_code_mb * MB),
      critical_committed_code_space_(max_committed_code_space_ / 2),
      next_code_space_hint_(reinterpret_cast<Address>(
          GetPlatformPageAllocator()->GetRandomMmapAddr())) {
  // Check that --wasm-max-code-space-size-mb is not set bigger than the default
  // value. Otherwise we run into DCHECKs or other crashes later.
  CHECK_GE(kDefaultMaxWasmCodeSpaceSizeMb,
           v8_flags.wasm_max_code_space_size_mb);
}

WasmCodeManager::~WasmCodeManager() {
  // No more committed code space.
  DCHECK_EQ(0, total_committed_code_space_.load());
}

#if defined(V8_OS_WIN64)
// static
bool WasmCodeManager::CanRegisterUnwindInfoForNonABICompliantCodeRange() {
  return win64_unwindinfo::CanRegisterUnwindInfoForNonABICompliantCodeRange() &&
         v8_flags.win64_unwinding_info;
}
#endif  // V8_OS_WIN64

void WasmCodeManager::Commit(base::AddressRegion region) {
  DCHECK(IsAligned(region.begin(), CommitPageSize()));
  DCHECK(IsAligned(region.size(), CommitPageSize()));
  // Reserve the size. Use CAS loop to avoid overflow on
  // {total_committed_code_space_}.
  size_t old_value = total_committed_code_space_.load();
  while (true) {
    DCHECK_GE(max_committed_code_space_, old_value);
    if (region.size() > max_committed_code_space_ - old_value) {
      auto oom_detail = base::FormattedString{}
                        << "trying to commit " << region.size()
                        << ", already committed " << old_value;
      V8::FatalProcessOutOfMemory(nullptr,
                                  "Exceeding maximum wasm committed code space",
                                  oom_detail.PrintToArray().data());
      UNREACHABLE();
    }
    if (total_committed_code_space_.compare_exchange_weak(
            old_value, old_value + region.size())) {
      break;
    }
  }

  TRACE_HEAP("Setting rwx permissions for 0x%" PRIxPTR ":0x%" PRIxPTR "\n",
             region.begin(), region.end());
  bool success = GetPlatformPageAllocator()->RecommitPages(
      reinterpret_cast<void*>(region.begin()), region.size(),
      PageAllocator::kReadWriteExecute);

  if (V8_UNLIKELY(!success)) {
    auto oom_detail = base::FormattedString{} << "region size: "
                                              << region.size();
    V8::FatalProcessOutOfMemory(nullptr, "Commit wasm code space",
                                oom_detail.PrintToArray().data());
    UNREACHABLE();
  }
}

void WasmCodeManager::Decommit(base::AddressRegion region) {
  PageAllocator* allocator = GetPlatformPageAllocator();
  DCHECK(IsAligned(region.begin(), allocator->CommitPageSize()));
  DCHECK(IsAligned(region.size(), allocator->CommitPageSize()));
  [[maybe_unused]] size_t old_committed =
      total_committed_code_space_.fetch_sub(region.size());
  DCHECK_LE(region.size(), old_committed);
  TRACE_HEAP("Decommitting system pages 0x%" PRIxPTR ":0x%" PRIxPTR "\n",
             region.begin(), region.end());
  if (V8_UNLIKELY(!allocator->DecommitPages(
          reinterpret_cast<void*>(region.begin()), region.size()))) {
    // Decommit can fail in near-OOM situations.
    auto oom_detail = base::FormattedString{} << "region size: "
                                              << region.size();
    V8::FatalProcessOutOfMemory(nullptr, "Decommit Wasm code space",
                                oom_detail.PrintToArray().data());
  }
}

void WasmCodeManager::AssignRange(base::AddressRegion region,
                                  NativeModule* native_module) {
  base::MutexGuard lock(&native_modules_mutex_);
  lookup_map_.insert(std::make_pair(
      region.begin(), std::make_pair(region.end(), native_module)));
}

VirtualMemory WasmCodeManager::TryAllocate(size_t size) {
  v8::PageAllocator* page_allocator = GetPlatformPageAllocator();
  DCHECK_GT(size, 0);
  size_t allocate_page_size = page_allocator->AllocatePageSize();
  size = RoundUp(size, allocate_page_size);
  Address hint =
      next_code_space_hint_.fetch_add(size, std::memory_order_relaxed);

  // When we start exposing Wasm in jitless mode, then the jitless flag
  // will have to determine whether we set kMapAsJittable or not.
  DCHECK(!v8_flags.jitless);
  VirtualMemory mem(page_allocator, size, reinterpret_cast<void*>(hint),
                    allocate_page_size,
                    PageAllocator::Permission::kNoAccessWillJitLater);
  if (!mem.IsReserved()) {
    // Try resetting {next_code_space_hint_}, which might fail if another thread
    // bumped it in the meantime.
    Address bumped_hint = hint + size;
    next_code_space_hint_.compare_exchange_weak(bumped_hint, hint,
                                                std::memory_order_relaxed);
    return {};
  }
  TRACE_HEAP("VMem alloc: 0x%" PRIxPTR ":0x%" PRIxPTR " (%zu)\n", mem.address(),
             mem.end(), mem.size());

  if (mem.address() != hint) {
    // If the hint was ignored, just store the end of the new vmem area
    // unconditionally, potentially racing with other concurrent allocations (it
    // does not really matter which end pointer we keep in that case).
    next_code_space_hint_.store(mem.end(), std::memory_order_relaxed);
  }

  // Don't pre-commit the code cage on Windows since it uses memory and it's not
  // required for recommit.
#if !defined(V8_OS_WIN)
  if (MemoryProtectionKeysEnabled()) {
#if V8_HAS_PKU_JIT_WRITE_PROTECT
    if (ThreadIsolation::Enabled()) {
      CHECK(ThreadIsolation::MakeExecutable(mem.address(), mem.size()));
    } else {
      CHECK(base::MemoryProtectionKey::SetPermissionsAndKey(
          mem.region(), PageAllocator::kReadWriteExecute,
          RwxMemoryWriteScope::memory_protection_key()));
    }
#else
    UNREACHABLE();
#endif
  } else {
    CHECK(SetPermissions(GetPlatformPageAllocator(), mem.address(), mem.size(),
                         PageAllocator::kReadWriteExecute));
  }
  page_allocator->DiscardSystemPages(reinterpret_cast<void*>(mem.address()),
                                     mem.size());
#endif  // !defined(V8_OS_WIN)

  ThreadIsolation::RegisterJitPage(mem.address(), mem.size());

  return mem;
}

namespace {
// The numbers here are rough estimates, used to calculate the size of the
// initial code reservation and for estimating the amount of external memory
// reported to the GC.
// They do not need to be accurate. Choosing them too small will result in
// separate code spaces being allocated (compile time and runtime overhead),
// choosing them too large results in over-reservation (virtual address space
// only).
// In doubt, choose the numbers slightly too large on 64-bit systems (where
// {kNeedsFarJumpsBetweenCodeSpaces} is {true}). Over-reservation is less
// critical in a 64-bit address space, but separate code spaces cause overhead.
// On 32-bit systems (where {kNeedsFarJumpsBetweenCodeSpaces} is {false}), the
// opposite is true: Multiple code spaces are cheaper, and address space is
// scarce, hence choose numbers slightly too small.
//
// Numbers can be determined by running benchmarks with
// --trace-wasm-compilation-times, and piping the output through
// tools/wasm/code-size-factors.py.
#if V8_TARGET_ARCH_X64
constexpr size_t kTurbofanFunctionOverhead = 24;
constexpr size_t kTurbofanCodeSizeMultiplier = 3;
constexpr size_t kLiftoffFunctionOverhead = 56;
constexpr size_t kLiftoffCodeSizeMultiplier = 4;
constexpr size_t kImportSize = 640;
#elif V8_TARGET_ARCH_IA32
constexpr size_t kTurbofanFunctionOverhead = 20;
constexpr size_t kTurbofanCodeSizeMultiplier = 3;
constexpr size_t kLiftoffFunctionOverhead = 48;
constexpr size_t kLiftoffCodeSizeMultiplier = 3;
constexpr size_t kImportSize = 600;
#elif V8_TARGET_ARCH_ARM
constexpr size_t kTurbofanFunctionOverhead = 44;
constexpr size_t kTurbofanCodeSizeMultiplier = 3;
constexpr size_t kLiftoffFunctionOverhead = 96;
constexpr size_t kLiftoffCodeSizeMultiplier = 5;
constexpr size_t kImportSize = 550;
#elif V8_TARGET_ARCH_ARM64
constexpr size_t kTurbofanFunctionOverhead = 40;
constexpr size_t kTurbofanCodeSizeMultiplier = 3;
constexpr size_t kLiftoffFunctionOverhead = 68;
constexpr size_t kLiftoffCodeSizeMultiplier = 4;
constexpr size_t kImportSize = 750;
#else
// Other platforms should add their own estimates for best performance. Numbers
// below are the maximum of other architectures.
constexpr size_t kTurbofanFunctionOverhead = 44;
constexpr size_t kTurbofanCodeSizeMultiplier = 4;
constexpr size_t kLiftoffFunctionOverhead = 96;
constexpr size_t kLiftoffCodeSizeMultiplier = 5;
constexpr size_t kImportSize = 750;
#endif
}  // namespace

// static
size_t WasmCodeManager::EstimateLiftoffCodeSize(int body_size) {
  return kLiftoffFunctionOverhead + kCodeAlignment / 2 +
         body_size * kLiftoffCodeSizeMultiplier;
}

// static
size_t WasmCodeManager::EstimateNativeModuleCodeSize(
    const WasmModule* module, bool include_liftoff,
    DynamicTiering dynamic_tiering) {
  int num_functions = static_cast<int>(module->num_declared_functions);
  int num_imported_functions = static_cast<int>(module->num_imported_functions);
  int code_section_length = 0;
  if (num_functions > 0) {
    DCHECK_EQ(module->functions.size(), num_imported_functions + num_functions);
    auto* first_fn = &module->functions[module->num_imported_functions];
    auto* last_fn = &module->functions.back();
    code_section_length =
        static_cast<int>(last_fn->code.end_offset() - first_fn->code.offset());
  }
  return EstimateNativeModuleCodeSize(num_functions, num_imported_functions,
                                      code_section_length, include_liftoff,
                                      dynamic_tiering);
}

// static
size_t WasmCodeManager::EstimateNativeModuleCodeSize(
    int num_functions, int num_imported_functions, int code_section_length,
    bool include_liftoff, DynamicTiering dynamic_tiering) {
  // The size for the jump table and far jump table is added later, per code
  // space (see {OverheadPerCodeSpace}). We still need to add the overhead for
  // the lazy compile table once, though. There are configurations where we do
  // not need it (non-asm.js, no dynamic tiering and no lazy compilation), but
  // we ignore this here as most of the time we will need it.
  const size_t lazy_compile_table_size =
      JumpTableAssembler::SizeForNumberOfLazyFunctions(num_functions);

  const size_t size_of_imports = kImportSize * num_imported_functions;

  const size_t overhead_per_function_turbofan =
      kTurbofanFunctionOverhead + kCodeAlignment / 2;
  size_t size_of_turbofan = overhead_per_function_turbofan * num_functions +
                            kTurbofanCodeSizeMultiplier * code_section_length;

  const size_t overhead_per_function_liftoff =
      kLiftoffFunctionOverhead + kCodeAlignment / 2;
  const size_t size_of_liftoff =
      include_liftoff ? overhead_per_function_liftoff * num_functions +
                            kLiftoffCodeSizeMultiplier * code_section_length
                      : 0;

  // With dynamic tiering we don't expect to compile more than 25% with
  // TurboFan. If there is no liftoff though then all code will get generated
  // by TurboFan.
  if (include_liftoff && dynamic_tiering) size_of_turbofan /= 4;

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

"""


```