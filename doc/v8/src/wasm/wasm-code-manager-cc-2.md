Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `v8/src/wasm/wasm-code-manager.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The file name `wasm-code-manager.cc` strongly suggests this code is responsible for managing the code generated for WebAssembly modules within V8. This includes allocation, storage, and access to the generated machine code.

2. **Analyze Key Classes and Methods:** Look for prominent classes and their methods to understand the main actions. The `NativeModule` class seems central, with methods like `GetCode`, `SnapshotAllOwnedCode`, `CreateEmptyJumpTableLocked`, `PatchJumpTablesLocked`, `AddCodeSpaceLocked`, `Lookup`, etc. The `WasmCodeManager` class also appears significant with methods like `TryAllocate`, `Commit`, and `Decommit`.

3. **Group Functionalities:** Categorize the identified methods into logical groups based on their apparent purpose. Some initial groupings could be:
    * Code retrieval (`GetCode`, `SnapshotAllOwnedCode`, `Lookup`)
    * Code allocation (`CreateEmptyJumpTableLocked`, `AddCodeSpaceLocked`, `TryAllocate`)
    * Code modification (`PatchJumpTablesLocked`)
    * Metadata management (`SetWasmSourceMap`, `GetWasmSourceMap`, `SetWireBytes`)
    * Performance tracking (`AddLazyCompilationTimeSample`)
    * Memory management (`Commit`, `Decommit`)
    * Jump table handling (related to many `NativeModule` methods)
    * Indirect call handling (`GetIndirectCallTarget`, `CreateIndirectCallTargetToFunctionIndexMap`)

4. **Infer Functionality Details:** For each group, analyze the method names and the surrounding code to infer the specific actions. For example:
    * "Code retrieval" involves getting specific code by index or finding code by program counter.
    * "Code allocation" manages memory regions for storing the generated code, including jump tables.
    * "Code modification" specifically deals with patching jump tables, which are crucial for function calls in WebAssembly.
    * "Metadata management" links the generated code with source maps and the original bytecode.
    * "Performance tracking" collects metrics about lazy compilation.
    * "Memory management" handles the commitment and decommitment of memory pages for the generated code.
    * "Jump table handling" is a core mechanism for efficient function calls and involves creating, patching, and looking up entries.
    * "Indirect call handling" focuses on how indirect calls are resolved.

5. **Address Specific Prompts:**
    * **`.tq` check:** The code is `.cc`, so it's not Torque.
    * **JavaScript relationship:**  Think about how these low-level operations manifest in JavaScript. Compiling and running WebAssembly involves these steps behind the scenes. The example should show a simple WebAssembly instantiation and function call.
    * **Logic inference:**  Choose a simple scenario, like retrieving code by index, and describe the input (an index) and the expected output (a `WasmCode` pointer).
    * **Common errors:** Consider what mistakes developers might make when dealing with WebAssembly, such as incorrect imports or table sizes.

6. **Synthesize the Summary:** Combine the grouped functionalities into a concise summary, highlighting the main responsibilities of the code. Emphasize the core role of managing WebAssembly code within V8.

7. **Refine and Organize:** Ensure the response is well-structured, easy to understand, and addresses all aspects of the user's request. Use clear language and avoid overly technical jargon where possible. Specifically for this "part 3" request, focus on summarizing the features already discussed in the provided code.

**Self-Correction/Refinement during the process:**

* Initially, I might have just listed all the methods. Realizing this is not a good summary, I would then group them by functionality.
* I might have overlooked the importance of jump tables. Further analysis of the code would reveal their central role in function calls.
* The JavaScript example needs to be concrete and easy to understand. Starting with a simple example and then mentioning more complex interactions (like imports) is a good approach.
* For the logic inference, choosing a straightforward case is better than trying to explain a complex jump table patching scenario.
* When thinking about common errors, it's important to relate them back to the functionalities of the code. For instance, issues with imports are relevant because the code manages information about imported functions.

By following these steps, the comprehensive and informative answer provided earlier can be generated.
这是 v8 源代码文件 `v8/src/wasm/wasm-code-manager.cc` 的第三部分，延续了之前代码的功能，主要关注于 **`NativeModule` 类中与代码管理相关的操作**。

**归纳一下它的功能：**

这部分代码主要负责以下 `NativeModule` 类的功能：

1. **获取代码快照:**  `SnapshotAllOwnedCode()`  用于获取当前模块拥有的所有编译后的 WebAssembly 代码块 (WasmCode) 的快照，这在某些需要检查或持久化代码状态的场景下很有用。

2. **获取特定索引的代码:** `GetCode(uint32_t index)`  根据函数索引获取对应的已编译的 WebAssembly 代码块。它会增加代码块的引用计数。`HasCode(uint32_t index)` 和 `HasCodeWithTier(uint32_t index, ExecutionTier tier)`  用于检查特定索引的函数是否已编译，以及是否以特定的优化层级编译。

3. **设置和获取源码映射:** `SetWasmSourceMap()` 和 `GetWasmSourceMap()`  用于设置和获取 WebAssembly 模块的源码映射信息，这对于调试 WebAssembly 代码至关重要。

4. **创建空的跳转表:** `CreateEmptyJumpTableLocked()` 和 `CreateEmptyJumpTableInRegionLocked()`  用于在指定的内存区域创建空的跳转表。跳转表是 WebAssembly 中实现函数调用的关键数据结构。它分为普通跳转表 (`kJumpTable`) 和远跳转表 (`kFarJumpTable`)，以及用于延迟编译的表 (`kLazyCompileTable`)。

5. **更新代码大小统计:** `UpdateCodeSize()`  用于记录已编译代码的大小，并根据优化层级（Liftoff 或 TurboFan）进行分别统计。

6. **修补跳转表:** `PatchJumpTablesLocked()` 和 `PatchJumpTableLocked()`  用于更新跳转表中的条目，将函数索引对应的槽位指向实际的函数代码地址。这在函数编译完成后动态更新调用目标时使用。

7. **添加代码空间:** `AddCodeSpaceLocked()`  用于为 WebAssembly 模块分配新的代码内存区域。当现有代码空间不足时，会分配新的空间并初始化其中的跳转表。这部分代码还负责初始化用于延迟编译的跳转表。

8. **设置 Wire Bytes:** `SetWireBytes()`  用于存储 WebAssembly 模块的原始字节码。

9. **记录延迟编译时间:** `AddLazyCompilationTimeSample()`  用于收集关于延迟编译的性能数据。

10. **转移新的代码:** `TransferNewOwnedCodeLocked()`  将新创建的代码块从一个临时容器转移到主要的 `owned_code_` 容器中，并进行排序以方便查找。

11. **查找代码块:** `Lookup(Address pc)`  根据给定的程序计数器 (PC) 地址，查找包含该地址的已编译 WebAssembly 代码块。

12. **查找指定区域的跳转表:** `FindJumpTablesForRegionLocked()`  在给定的代码区域内查找可用的跳转表。这在支持跨代码空间跳转的架构中非常重要。

13. **获取近调用目标和跳转表入口:** `GetNearCallTargetForFunction()` 和 `GetJumpTableEntryForBuiltin()`  用于根据函数索引或内置函数的类型，获取跳转表中的目标地址。

14. **从跳转表槽位获取函数索引:** `GetFunctionIndexFromJumpTableSlot()`  根据跳转表槽位的地址反向查找对应的函数索引。

15. **创建间接调用目标到函数索引的映射:** `CreateIndirectCallTargetToFunctionIndexMap()`  创建一个映射，将间接调用的目标地址与对应的函数索引关联起来。

16. **获取跳转表槽位中的内置函数:** `GetBuiltinInJumptableSlot()`  根据跳转表槽位的地址判断其指向的是哪个内置函数。

17. **获取代码指针句柄:** `GetCodePointerHandle()`  用于获取与特定函数关联的代码指针表中的句柄。

18. **获取间接调用目标地址:** `GetIndirectCallTarget()`  获取用于间接调用的目标地址。

19. **析构函数:** `~NativeModule()`  负责释放与 `NativeModule` 相关的资源，包括取消后台编译任务和释放代码指针表句柄。

**与 JavaScript 的关系：**

所有这些底层代码管理操作都是在 V8 引擎执行 JavaScript 代码加载和运行 WebAssembly 模块时发生的。当你实例化一个 WebAssembly 模块并在 JavaScript 中调用其导出的函数时，V8 内部会调用这里的函数来管理编译后的代码。

**JavaScript 示例：**

```javascript
async function runWasm() {
  const response = await fetch('your_wasm_module.wasm');
  const bytes = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(bytes);

  // 当你调用 module.instance.exports.exported_function 时，
  // V8 内部会使用 wasm-code-manager.cc 中的函数来查找并执行
  // `exported_function` 对应的编译后的机器码。
  const result = module.instance.exports.exported_function(42);
  console.log(result);
}

runWasm();
```

在这个例子中，`WebAssembly.instantiate(bytes)` 会触发 V8 对 WebAssembly 字节码的编译和代码管理过程，其中就包括 `wasm-code-manager.cc` 中的代码。当你调用 `module.instance.exports.exported_function(42)` 时，V8 会使用 `NativeModule::GetCode()` 等函数来找到 `exported_function` 编译后的代码，并通过跳转表跳转到该代码执行。

**代码逻辑推理（假设输入与输出）：**

**假设输入：**

* 一个 `NativeModule` 对象 `native_module`.
* 一个函数索引 `index = 5`.
* 假设索引 5 的函数已经被编译。

**代码逻辑：**

当我们调用 `native_module->GetCode(5)` 时：

1. `GetCode` 函数获取 `allocation_mutex_` 的锁。
2. 它通过 `declared_function_index(module(), index)` 计算出在内部代码表中的真实索引（考虑到导入函数）。
3. 它访问 `code_table_` 数组中对应的元素 `code_table_[calculated_index]`。
4. 假设 `code_table_[calculated_index]` 指向一个有效的 `WasmCode` 对象。
5. `WasmCodeRefScope::AddRef(code)` 会增加该 `WasmCode` 对象的引用计数。
6. 函数返回该 `WasmCode` 对象的指针。

**输出：**

一个指向索引为 5 的 WebAssembly 函数的 `WasmCode` 对象的指针。

**用户常见的编程错误（与 WebAssembly 相关）：**

1. **导入函数或全局变量与 WebAssembly 模块定义不匹配：**  如果 JavaScript 提供的导入与 WebAssembly 模块的声明不一致（例如，类型不匹配，数量不匹配），会导致实例化失败。`wasm-code-manager.cc` 管理模块的结构，但在实例化时会进行校验。

   ```javascript
   // 假设 wasm 模块导入了一个名为 "imported_func" 的函数，接收一个 i32 参数并返回 i32
   const importObject = {
     env: {
       // 错误：提供的导入函数没有参数
       imported_func: () => { console.log("Hello"); return 0; }
     }
   };

   WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject)
     .catch(error => console.error("Instantiation error:", error));
   ```

2. **尝试调用未导出的 WebAssembly 函数：** 如果 JavaScript 代码尝试调用 WebAssembly 模块中未通过 `export` 声明的函数，会导致运行时错误。`wasm-code-manager.cc` 负责管理导出的代码，但调用未导出的函数会找不到对应的入口点。

   ```javascript
   async function run() {
     const module = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
     const instance = module.instance;

     // 假设 module.wasm 中没有导出名为 "internal_function" 的函数
     if (instance.exports.internal_function) {
       instance.exports.internal_function(); // 运行时错误：找不到该导出
     } else {
       console.log("internal_function is not exported.");
     }
   }
   run();
   ```

3. **间接调用时类型签名不匹配：**  在 WebAssembly 中使用 `call_indirect` 进行间接调用时，如果提供的函数索引对应的函数签名与 `call_indirect` 指令指定的签名不匹配，会导致运行时错误。`wasm-code-manager.cc` 管理函数类型信息，但类型不匹配会在执行时被检测到。

总而言之，这部分 `wasm-code-manager.cc` 代码是 V8 引擎中管理 WebAssembly 模块编译后代码的核心组件，负责代码的分配、存储、查找、更新以及与调试信息和性能数据的关联。它为 JavaScript 执行 WebAssembly 代码提供了底层的支持。

### 提示词
```
这是目录为v8/src/wasm/wasm-code-manager.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-code-manager.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  if (include_liftoff && dynamic_
```