Response:
The user wants a summary of the functionality of the provided C++ header file `v8/src/wasm/wasm-code-manager.h`. I need to go through each method and member variable and synthesize a description of its purpose. Since this is part 2 of 2, I also need to summarize the functionality across both parts.

Here's a breakdown of the functionalities in this second part:

1. **Code Freeing:** `FreeCode` allows the `WasmEngine` to free up dead Wasm code.
2. **Code Space Information:** `GetNumberOfCodeSpacesForTesting` reveals the number of reserved code spaces (likely for testing purposes).
3. **Debugging Support:** `HasDebugInfo`, `GetDebugInfo`, and `GetNamesProvider` deal with retrieving debugging information and symbol names for the Wasm module.
4. **Tiering Budget:**  `tiering_budget_array` provides access to the function call counters used in dynamic tiering.
5. **Counters:** `counters` exposes the internal counters of the `WasmCodeAllocator`.
6. **Memory Consumption:** `EstimateCurrentMemoryConsumption` gives an estimate of the memory used by the module.
7. **Code Logging:** `log_code`, `EnableCodeLogging`, and `DisableCodeLogging` control logging of generated Wasm code.
8. **Jump Tables:** The `JumpTableType` enum and related methods (`CreateEmptyJumpTableLocked`, `CreateEmptyJumpTableInRegionLocked`, `FindJumpTablesForRegionLocked`) manage different types of jump tables used for indirect calls and lazy compilation.
9. **Fast API Calls:**  `TrySetFastApiCallTarget`, `fast_api_targets`, `set_fast_api_signature`, and `fast_api_signatures` handle optimizations for calling imported Web APIs directly from Wasm, including managing call targets and signatures.
10. **Code Pointer Table:** `GetCodePointerHandle` and `GetIndirectCallTarget` are used to obtain stable entry points for Wasm functions, particularly for indirect calls.
11. **Internal Data Structures:**  The `CodeSpaceData` struct and several private methods (`AddCodeWithCodeSpace`, `PatchJumpTablesLocked`, `PatchJumpTableLocked`, `AddCodeSpaceLocked`, `PublishCodeLocked`, `TransferNewOwnedCodeLocked`, `should_update_code_table`) deal with the internal management of code spaces and patching of jump tables.
12. **NativeModule Constructor:** The private `NativeModule` constructor handles the initial setup of a native Wasm module.
13. **Member Variables:**  The numerous member variables store information like enabled features, the Wasm module, source maps, wire bytes, jump tables, compilation state, tiering budgets, mutexes for thread safety, collections of owned code, code tables, debug information, and metrics.
14. **WasmCodeManager Class:** This class is responsible for managing all `NativeModule` instances and their associated code. It includes methods for looking up native modules and code by address, estimating code size, managing memory allocation and deallocation for Wasm code, and handling memory protection keys.
15. **WasmCodeRefScope Class:**  This class seems to be a mechanism for tracking the lifetime of `WasmCode` objects within a specific scope.
16. **WasmCodeLookupCache Class:** This class provides a cache to speed up lookups of `WasmCode` objects by address.

Now I can generate the detailed explanation and the final summary.
这是目录为v8/src/wasm/wasm-code-manager.h的一个v8源代码， 请列举一下它的功能,
如果v8/src/wasm/wasm-code-manager.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

基于提供的代码片段，以下是 `v8/src/wasm/wasm-code-manager.h` 的功能列表（第二部分）：

1. **释放不再使用的代码 (`FreeCode`)**:
    -   允许 `WasmEngine` 释放已经不再使用的 WebAssembly 代码。这涉及到内部的资源管理和统计。

2. **获取代码空间数量 (测试用) (`GetNumberOfCodeSpacesForTesting`)**:
    -   提供一个方法来获取为此模块单独保留的代码空间的数量。这主要是用于测试目的。

3. **检查和获取调试信息 (`HasDebugInfo`, `GetDebugInfo`, `GetNamesProvider`)**:
    -   `HasDebugInfo`: 检查当前 `NativeModule` 是否包含调试信息。
    -   `GetDebugInfo`: 获取或创建当前 `NativeModule` 的调试信息对象 (`DebugInfo`)，用于支持调试器。
    -   `GetNamesProvider`: 获取或创建名称提供器 (`NamesProvider`)，它依赖于模块的 wire bytes，用于提供函数名等符号信息。

4. **访问分层编译预算数组 (`tiering_budget_array`)**:
    -   返回一个指向原子 `uint32_t` 数组的指针，该数组用于存储函数调用的计数，用于分层编译的决策。

5. **访问内部计数器 (`counters`)**:
    -   返回 `WasmCodeAllocator` 的计数器对象，用于跟踪代码分配等操作。

6. **估计当前内存消耗 (`EstimateCurrentMemoryConsumption`)**:
    -   提供一个方法来估算当前 `NativeModule` 占用的内存大小。

7. **控制代码日志记录 (`log_code`, `EnableCodeLogging`, `DisableCodeLogging`)**:
    -   `log_code`: 返回一个布尔值，指示是否启用了代码日志记录。
    -   `EnableCodeLogging`: 启用代码日志记录。
    -   `DisableCodeLogging`: 禁用代码日志记录。

8. **定义跳转表类型 (`JumpTableType`)**:
    -   定义了不同类型的跳转表，包括普通跳转表 (`kJumpTable`)，远跳转表 (`kFarJumpTable`) 和惰性编译表 (`kLazyCompileTable`)。

9. **尝试设置快速 API 调用目标 (`TrySetFastApiCallTarget`)**:
    -   尝试设置指定导入函数 (`index`) 的快速 API 调用目标地址。
    -   如果之前已经设置了不同的目标，则返回 `false`，并且该导入函数将被标记为不适合使用预知的导入优化，已编译的代码将被刷新，未来的调用将不会使用快速 API 调用。
    -   **代码逻辑推理：**
        -   **假设输入：** `func_index = 0`, `target = 0x12345678`，且 `fast_api_targets_[0]` 当前为 `kNullAddress`。
        -   **输出：** 返回 `true`，并且 `fast_api_targets_[0]` 的值被设置为 `0x12345678`。
        -   **假设输入：** `func_index = 0`, `target = 0x87654321`，且 `fast_api_targets_[0]` 当前为 `0x12345678`。
        -   **输出：** 返回 `false`。

10. **访问快速 API 调用目标数组 (`fast_api_targets`)**:
    -   返回指向存储快速 API 调用目标地址的原子指针数组的指针。

11. **设置快速 API 签名 (`set_fast_api_signature`)**:
    -   存储导入的 Web API 函数的 C++ 调用目标的签名 (`MachineSignature`)。签名从 `FunctionTemplateInfo` 对象复制到 `WasmModule` 的 `signature_zone` 中，以确保其生命周期与 `WasmModule` 一致。

12. **检查是否存在快速 API 签名 (`has_fast_api_signature`)**:
    -   检查指定索引的函数是否存在已设置的快速 API 签名。

13. **访问快速 API 签名数组 (`fast_api_signatures`)**:
    -   返回指向存储快速 API 签名的原子指针数组的指针。

14. **获取代码指针句柄 (`GetCodePointerHandle`)**:
    -   获取指定索引函数的代码指针表句柄 (`WasmCodePointerTable::Handle`)。

15. **获取间接调用目标 (`GetIndirectCallTarget`)**:
    -   获取指定索引函数的稳定入口点，用于间接调用。

16. **内部类和方法 (`CodeSpaceData`, `AddCodeWithCodeSpace`, `CreateEmptyJumpTableLocked` 等)**:
    -   定义了用于管理代码空间的内部数据结构 (`CodeSpaceData`)，包括代码区域和跳转表。
    -   提供了在指定代码空间中添加代码 (`AddCodeWithCodeSpace`) 和创建空跳转表 (`CreateEmptyJumpTableLocked`, `CreateEmptyJumpTableInRegionLocked`) 的方法。
    -   `FindJumpTablesForRegionLocked` 用于查找给定代码区域应使用的跳转表。
    -   `UpdateCodeSize` 用于更新代码大小的统计信息。
    -   `PatchJumpTablesLocked`, `PatchJumpTableLocked` 用于修补跳转表，将条目指向实际的目标地址。
    -   `AddCodeSpaceLocked` 由 `WasmCodeAllocator` 调用，用于注册新的代码空间。
    -   `PublishCodeLocked` 用于发布新创建的 `WasmCode` 对象。
    -   `TransferNewOwnedCodeLocked` 用于将新拥有的代码从一个临时容器转移到主容器。
    -   `should_update_code_table` 确定是否应该更新代码表。

17. **`NativeModule` 构造函数**:
    -   私有构造函数，通过 `WasmCodeManager::NewNativeModule()` 调用，用于初始化 `NativeModule` 对象。

18. **成员变量**:
    -   包括 `engine_scope_` (用于保持引擎的生命周期)，`code_allocator_` (代码分配器)，`enabled_features_` (启用的特性)，`compile_imports_` (编译时导入)，`module_` (Wasm 模块)，`source_map_` (源码映射)，`wire_bytes_` (原始字节码)，各种跳转表指针，`compilation_state_` (编译状态)，`tiering_budgets_` (分层编译预算)，互斥锁 (`allocation_mutex_`)，存储已分配代码的容器 (`owned_code_`, `new_owned_code_`)，代码表 (`code_table_`)，代码指针句柄数组 (`code_pointer_handles_`)，代码空间数据 (`code_space_data_`)，调试信息 (`debug_info_`)，名称提供器 (`names_provider_`)，调试状态 (`debug_state_`)，惰性编译相关的标志和计数器，以及快速 API 调用目标和签名的数组。

19. **`WasmCodeManager` 类**:
    -   负责管理所有的 `NativeModule` 实例。
    -   提供了查找包含给定程序计数器 (`pc`) 的 `NativeModule` 和 `WasmCode` 的方法 (`LookupNativeModule`, `LookupCode`, `LookupCodeAndSafepoint`)。
    -   提供了刷新代码查找缓存的方法 (`FlushCodeLookupCache`)。
    -   跟踪已提交的代码空间大小 (`committed_code_space_`).
    -   提供了估计 Liftoff 函数代码大小 (`EstimateLiftoffCodeSize`) 和整个 NativeModule 代码大小的方法 (`EstimateNativeModuleCodeSize`, 两个重载版本)。
    -   提供了估计 NativeModule 元数据大小的方法 (`EstimateNativeModuleMetaDataSize`).
    -   提供了检查硬件和软件是否支持内存保护密钥 (PKU) 的方法 (`HasMemoryProtectionKeySupport`, `MemoryProtectionKeysEnabled`, `MemoryProtectionKeyWritable`)。
    -   提供了创建新的 `NativeModule` 的方法 (`NewNativeModule`)。
    -   提供了分配和提交/取消提交虚拟内存的方法 (`TryAllocate`, `Commit`, `Decommit`).
    -   提供了释放 `NativeModule` 的方法 (`FreeNativeModule`).
    -   提供了分配代码区域的方法 (`AssignRange`).
    -   内部维护了一个查找表 (`lookup_map_`) 来根据地址查找 `NativeModule`。

20. **`WasmCodeRefScope` 类**:
    -   似乎用于管理 `WasmCode` 对象的生命周期，可能用于确保在特定作用域内创建的 `WasmCode` 对象在作用域结束时被正确处理。它维护了一个栈结构来跟踪当前的作用域。

21. **`WasmCodeLookupCache` 类**:
    -   提供了一个缓存机制，用于加速通过程序计数器 (`pc`) 查找 `WasmCode` 对象的过程。这可以提高性能，因为代码查找是一个频繁的操作。

**如果 `v8/src/wasm/wasm-code-manager.h` 以 `.tq` 结尾**：

那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 特有的类型化中间语言，用于生成高效的运行时代码。如果该文件是 `.tq` 文件，它将包含用 Torque 编写的逻辑，而不是 C++ 声明。

**与 JavaScript 的关系 (示例)**：

`WasmCodeManager` 管理的 WebAssembly 代码最终会被 JavaScript 调用或与 JavaScript 互操作。例如，当 JavaScript 调用一个导出的 WebAssembly 函数时，V8 需要查找该函数的入口点，而 `WasmCodeManager` 就负责管理这些入口点。

```javascript
// 假设我们有一个编译好的 WebAssembly 模块实例 'wasmInstance'
const add = wasmInstance.exports.add; // 获取导出的 'add' 函数

const result = add(5, 3); // JavaScript 调用 WebAssembly 函数

console.log(result); // 输出 8
```

在这个例子中，当 `add(5, 3)` 被调用时，V8 内部会使用 `WasmCodeManager` 来找到 `add` 函数的实际机器码地址并执行它。`GetIndirectCallTarget` 或类似的机制可能被用于获取这个入口点。

**用户常见的编程错误 (涉及到的部分)**：

虽然 `wasm-code-manager.h` 是 V8 内部的，用户一般不会直接操作它，但其功能间接关联到一些常见的 WebAssembly 编程错误：

1. **调用未导出的函数**：如果 JavaScript 尝试调用一个 WebAssembly 模块中不存在或未导出的函数，V8 在查找入口点时会失败，这与 `WasmCodeManager` 管理的代码有关。
2. **类型不匹配的互操作**：当 JavaScript 和 WebAssembly 之间进行函数调用时，参数和返回值的类型必须匹配。如果类型不匹配，可能会导致执行错误，这与 `TrySetFastApiCallTarget` 和 `set_fast_api_signature` 尝试建立的快速调用路径有关。不正确的签名会导致调用失败。

**第2部分功能归纳**：

`v8/src/wasm/wasm-code-manager.h` 的第二部分主要关注以下功能：

*   **代码生命周期管理**：包括释放不再使用的代码。
*   **调试支持**：提供访问和管理 WebAssembly 模块调试信息的功能。
*   **性能优化**：通过快速 API 调用目标和签名来优化 JavaScript 与 WebAssembly 之间的互操作。
*   **内部代码管理**：管理不同类型的代码空间、跳转表以及代码的分配、修补和发布。
*   **内存管理**：跟踪和估计 WebAssembly 代码的内存消耗。
*   **监控与诊断**：提供代码日志记录和访问内部计数器的功能。
*   **分层编译支持**：通过分层编译预算数组来辅助动态优化决策。
*   **管理 `NativeModule` 实例**：`WasmCodeManager` 负责创建、查找和管理 `NativeModule` 对象及其关联的代码。
*   **代码查找缓存**：通过 `WasmCodeLookupCache` 提高代码查找效率。
*   **代码引用作用域管理**：通过 `WasmCodeRefScope` 管理 `WasmCode` 对象的生命周期。

总的来说，这部分代码更深入地涉及了 V8 内部如何管理和优化 WebAssembly 代码的执行，包括底层的内存管理、代码组织和与其他 V8 组件的交互。

### 提示词
```
这是目录为v8/src/wasm/wasm-code-manager.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-code-manager.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Should only be called via {WasmEngine::FreeDeadCode}, so the engine can do
  // its accounting.
  void FreeCode(base::Vector<WasmCode* const>);

  // Retrieve the number of separately reserved code spaces for this module.
  size_t GetNumberOfCodeSpacesForTesting() const;

  // Check whether there is DebugInfo for this NativeModule.
  bool HasDebugInfo() const;

  // Get or create the debug info for this NativeModule.
  DebugInfo* GetDebugInfo();

  // Get or create the NamesProvider. Requires {HasWireBytes()}.
  NamesProvider* GetNamesProvider();

  std::atomic<uint32_t>* tiering_budget_array() const {
    return tiering_budgets_.get();
  }

  Counters* counters() const { return code_allocator_.counters(); }

  size_t EstimateCurrentMemoryConsumption() const;

  bool log_code() const { return log_code_.load(std::memory_order_relaxed); }

  void EnableCodeLogging() { log_code_.store(true, std::memory_order_relaxed); }

  void DisableCodeLogging() {
    log_code_.store(false, std::memory_order_relaxed);
  }

  enum class JumpTableType {
    kJumpTable,
    kFarJumpTable,
    kLazyCompileTable,
  };

  // This function tries to set the fast API call target of function import
  // `index`. If the call target has been set before with a different value,
  // then this function returns false, and this import will be marked as not
  // suitable for wellknown imports, i.e. all existing compiled code of the
  // module gets flushed, and future calls to this import will not use fast API
  // calls.
  bool TrySetFastApiCallTarget(int func_index, Address target) {
    Address old_val =
        fast_api_targets_[func_index].load(std::memory_order_relaxed);
    if (old_val == target) {
      return true;
    }
    if (old_val != kNullAddress) {
      // If already a different target is stored, then there are conflicting
      // targets and fast api calls are not possible. In that case the import
      // will be marked as not suitable for wellknown imports, and the
      // `fast_api_target` of this import will never be used anymore in the
      // future.
      return false;
    }
    if (fast_api_targets_[func_index].compare_exchange_strong(
            old_val, target, std::memory_order_relaxed)) {
      return true;
    }
    // If a concurrent call to `TrySetFastAPICallTarget` set the call target to
    // the same value as this call, we consider also this call successful.
    return old_val == target;
  }

  std::atomic<Address>* fast_api_targets() const {
    return fast_api_targets_.get();
  }

  // Stores the signature of the C++ call target of an imported web API
  // function. The signature got copied from the `FunctionTemplateInfo` object
  // of the web API function into the `signature_zone` of the `WasmModule` so
  // that it stays alive as long as the `WasmModule` exists.
  void set_fast_api_signature(int func_index, const MachineSignature* sig) {
    fast_api_signatures_[func_index] = sig;
  }

  bool has_fast_api_signature(int index) {
    return fast_api_signatures_[index] != nullptr;
  }

  std::atomic<const MachineSignature*>* fast_api_signatures() const {
    return fast_api_signatures_.get();
  }

  WasmCodePointerTable::Handle GetCodePointerHandle(int index) const;
  // Get a stable entry point for function at `function_index` that can be used
  // for indirect calls.
  WasmCodePointer GetIndirectCallTarget(int func_index) const;

 private:
  friend class WasmCode;
  friend class WasmCodeAllocator;
  friend class WasmCodeManager;
  friend class CodeSpaceWriteScope;

  struct CodeSpaceData {
    base::AddressRegion region;
    WasmCode* jump_table;
    WasmCode* far_jump_table;
  };

  // Private constructor, called via {WasmCodeManager::NewNativeModule()}.
  NativeModule(WasmEnabledFeatures enabled_features,
               WasmDetectedFeatures detected_features,
               CompileTimeImports compile_imports,
               DynamicTiering dynamic_tiering, VirtualMemory code_space,
               std::shared_ptr<const WasmModule> module,
               std::shared_ptr<Counters> async_counters,
               std::shared_ptr<NativeModule>* shared_this);

  std::unique_ptr<WasmCode> AddCodeWithCodeSpace(
      int index, const CodeDesc& desc, int stack_slots, int ool_spill_count,
      uint32_t tagged_parameter_slots,
      base::Vector<const uint8_t> protected_instructions_data,
      base::Vector<const uint8_t> source_position_table,
      base::Vector<const uint8_t> inlining_positions,
      base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
      ExecutionTier tier, ForDebugging for_debugging,
      bool frame_has_feedback_slot, base::Vector<uint8_t> code_space,
      const JumpTablesRef& jump_tables_ref);

  WasmCode* CreateEmptyJumpTableLocked(int jump_table_size, JumpTableType type);

  WasmCode* CreateEmptyJumpTableInRegionLocked(int jump_table_size,
                                               base::AddressRegion,
                                               JumpTableType type);

  // Finds the jump tables that should be used for given code region. This
  // information is then passed to {GetNearCallTargetForFunction} and
  // {GetNearRuntimeStubEntry} to avoid the overhead of looking this information
  // up there. Return an empty struct if no suitable jump tables exist.
  JumpTablesRef FindJumpTablesForRegionLocked(base::AddressRegion) const;

  void UpdateCodeSize(size_t, ExecutionTier, ForDebugging);

  // Hold the {allocation_mutex_} when calling one of these methods.
  // {slot_index} is the index in the declared functions, i.e. function index
  // minus the number of imported functions.
  void PatchJumpTablesLocked(uint32_t slot_index, Address target);
  void PatchJumpTableLocked(WritableJumpTablePair& jump_table_pair,
                            const CodeSpaceData&, uint32_t slot_index,
                            Address target);

  // Called by the {WasmCodeAllocator} to register a new code space.
  void AddCodeSpaceLocked(base::AddressRegion);

  // Hold the {allocation_mutex_} when calling {PublishCodeLocked}.
  WasmCode* PublishCodeLocked(std::unique_ptr<WasmCode>);

  // Transfer owned code from {new_owned_code_} to {owned_code_}.
  void TransferNewOwnedCodeLocked() const;

  bool should_update_code_table(WasmCode* new_code, WasmCode* prior_code) const;

  // -- Fields of {NativeModule} start here.

  // Keep the engine alive as long as this NativeModule is alive. In its
  // destructor, the NativeModule still communicates with the WasmCodeManager,
  // owned by the engine. This fields comes before other fields which also still
  // access the engine (like the code allocator), so that it's destructor runs
  // last.
  OperationsBarrier::Token engine_scope_;

  // {WasmCodeAllocator} manages all code reservations and allocations for this
  // {NativeModule}.
  WasmCodeAllocator code_allocator_;

  // Features enabled for this module. We keep a copy of the features that
  // were enabled at the time of the creation of this native module,
  // to be consistent across asynchronous compilations later.
  const WasmEnabledFeatures enabled_features_;

  // Compile-time imports requested for this module.
  const CompileTimeImports compile_imports_;

  // The decoded module, stored in a shared_ptr such that background compile
  // tasks can keep this alive.
  std::shared_ptr<const WasmModule> module_;

  std::unique_ptr<WasmModuleSourceMap> source_map_;

  // Wire bytes, held in a shared_ptr so they can be kept alive by the
  // {WireBytesStorage}, held by background compile tasks.
  std::shared_ptr<base::OwnedVector<const uint8_t>> wire_bytes_;

  // The first allocated jump table. Always used by external calls (from JS).
  // Wasm calls might use one of the other jump tables stored in
  // {code_space_data_}.
  WasmCode* main_jump_table_ = nullptr;

  // The first allocated far jump table.
  WasmCode* main_far_jump_table_ = nullptr;

  // Lazy compile stub table, containing entries to jump to the
  // {WasmCompileLazy} builtin, passing the function index.
  WasmCode* lazy_compile_table_ = nullptr;

  // The compilation state keeps track of compilation tasks for this module.
  // Note that its destructor blocks until all tasks are finished/aborted and
  // hence needs to be destructed first when this native module dies.
  std::unique_ptr<CompilationState> compilation_state_;

  // Array to handle number of function calls.
  std::unique_ptr<std::atomic<uint32_t>[]> tiering_budgets_;

  // This mutex protects concurrent calls to {AddCode} and friends.
  // TODO(dlehmann): Revert this to a regular {Mutex} again.
  // This needs to be a {RecursiveMutex} only because of {CodeSpaceWriteScope}
  // usages, which are (1) either at places that already hold the
  // {allocation_mutex_} or (2) because of multiple open {CodeSpaceWriteScope}s
  // in the call hierarchy. Both are fixable.
  mutable base::RecursiveMutex allocation_mutex_;

  //////////////////////////////////////////////////////////////////////////////
  // Protected by {allocation_mutex_}:

  // Holds allocated code objects for fast lookup and deletion. For lookup based
  // on pc, the key is the instruction start address of the value. Filled lazily
  // from {new_owned_code_} (below).
  mutable std::map<Address, std::unique_ptr<WasmCode>> owned_code_;

  // Holds owned code which is not inserted into {owned_code_} yet. It will be
  // inserted on demand. This has much better performance than inserting
  // individual code objects.
  mutable std::vector<std::unique_ptr<WasmCode>> new_owned_code_;

  // Table of the latest code object per function, updated on initial
  // compilation and tier up. The number of entries is
  // {WasmModule::num_declared_functions}, i.e. there are no entries for
  // imported functions.
  std::unique_ptr<WasmCode*[]> code_table_;

  // CodePointerTable handles for all declared functions. The entries are
  // initialized to point to the lazy compile table and will later be updated to
  // point to the compiled code.
  std::unique_ptr<WasmCodePointerTable::Handle[]> code_pointer_handles_;
  // The size will usually be num_declared_functions, except that we sometimes
  // allocate larger arrays for testing.
  size_t code_pointer_handles_size_ = 0;

  // Data (especially jump table) per code space.
  std::vector<CodeSpaceData> code_space_data_;

  // Debug information for this module. You only need to hold the allocation
  // mutex while getting the {DebugInfo} pointer, or initializing this field.
  // Further accesses to the {DebugInfo} do not need to be protected by the
  // mutex.
  std::unique_ptr<DebugInfo> debug_info_;

  std::unique_ptr<NamesProvider> names_provider_;

  DebugState debug_state_ = kNotDebugging;

  // End of fields protected by {allocation_mutex_}.
  //////////////////////////////////////////////////////////////////////////////

  bool lazy_compile_frozen_ = false;
  std::atomic<size_t> liftoff_bailout_count_{0};
  std::atomic<size_t> liftoff_code_size_{0};
  std::atomic<size_t> turbofan_code_size_{0};

  // Metrics for lazy compilation.
  std::atomic<int> num_lazy_compilations_{0};
  std::atomic<int64_t> sum_lazy_compilation_time_in_micro_sec_{0};
  std::atomic<int64_t> max_lazy_compilation_time_in_micro_sec_{0};
  std::atomic<bool> should_metrics_be_reported_{true};

  // Whether the next instantiation should trigger repeated output of PGO data
  // (if --experimental-wasm-pgo-to-file is enabled).
  std::atomic<bool> should_pgo_data_be_written_{true};

  // A lock-free quick-access flag to indicate whether code for this
  // NativeModule might need to be logged in any isolate. This is updated by the
  // {WasmEngine}, which keeps the source of truth. After checking this flag,
  // you would typically call into {WasmEngine::LogCode} which then checks
  // (under a mutex) which isolate needs logging.
  std::atomic<bool> log_code_{false};

  std::unique_ptr<std::atomic<Address>[]> fast_api_targets_;
  std::unique_ptr<std::atomic<const MachineSignature*>[]> fast_api_signatures_;
};

class V8_EXPORT_PRIVATE WasmCodeManager final {
 public:
  WasmCodeManager();
  WasmCodeManager(const WasmCodeManager&) = delete;
  WasmCodeManager& operator=(const WasmCodeManager&) = delete;

  ~WasmCodeManager();

#if defined(V8_OS_WIN64)
  static bool CanRegisterUnwindInfoForNonABICompliantCodeRange();
#endif  // V8_OS_WIN64

  NativeModule* LookupNativeModule(Address pc) const;
  // Returns the Wasm code that contains the given address. The result
  // is cached. There is one cache per isolate for performance reasons
  // (to avoid locking and reference counting). Note that the returned
  // value is not reference counted. This should not be an issue since
  // we expect that the code is currently being executed. If 'isolate'
  // is nullptr, no caching occurs.
  WasmCode* LookupCode(Isolate* isolate, Address pc) const;
  std::pair<WasmCode*, SafepointEntry> LookupCodeAndSafepoint(Isolate* isolate,
                                                              Address pc);
  void FlushCodeLookupCache(Isolate* isolate);
  size_t committed_code_space() const {
    return total_committed_code_space_.load();
  }

  // Estimate the needed code space for a Liftoff function based on the size of
  // the function body (wasm byte code).
  static size_t EstimateLiftoffCodeSize(int body_size);
  // Estimate the needed code space from a completely decoded module.
  static size_t EstimateNativeModuleCodeSize(const WasmModule* module,
                                             bool include_liftoff,
                                             DynamicTiering dynamic_tiering);
  // Estimate the needed code space from the number of functions and total code
  // section length.
  static size_t EstimateNativeModuleCodeSize(int num_functions,
                                             int num_imported_functions,
                                             int code_section_length,
                                             bool include_liftoff,
                                             DynamicTiering dynamic_tiering);
  // Estimate the size of metadata needed for the NativeModule, excluding
  // generated code. This data is stored on the C++ heap.
  static size_t EstimateNativeModuleMetaDataSize(const WasmModule* module);

  // Returns true if there is hardware support for PKU. Use
  // {MemoryProtectionKeysEnabled} to also check if PKU usage is enabled via
  // flags.
  static bool HasMemoryProtectionKeySupport();

  // Returns true if PKU should be used.
  static bool MemoryProtectionKeysEnabled();

  // Returns {true} if the memory protection key is write-enabled for the
  // current thread.
  // Can only be called if {HasMemoryProtectionKeySupport()} is {true}.
  static bool MemoryProtectionKeyWritable();

 private:
  friend class WasmCodeAllocator;
  friend class WasmCodeLookupCache;
  friend class WasmEngine;
  friend class WasmImportWrapperCache;

  std::shared_ptr<NativeModule> NewNativeModule(
      Isolate* isolate, WasmEnabledFeatures enabled_features,
      WasmDetectedFeatures detected_features,
      CompileTimeImports compile_imports, size_t code_size_estimate,
      std::shared_ptr<const WasmModule> module);

  V8_WARN_UNUSED_RESULT VirtualMemory TryAllocate(size_t size);
  void Commit(base::AddressRegion);
  void Decommit(base::AddressRegion);

  void FreeNativeModule(base::Vector<VirtualMemory> owned_code,
                        size_t committed_size);

  void AssignRange(base::AddressRegion, NativeModule*);

  WasmCode* LookupCode(Address pc) const;

  const size_t max_committed_code_space_;

  std::atomic<size_t> total_committed_code_space_{0};
  // If the committed code space exceeds {critical_committed_code_space_}, then
  // we trigger a GC before creating the next module. This value is set to the
  // currently committed space plus 50% of the available code space on creation
  // and updated after each GC.
  std::atomic<size_t> critical_committed_code_space_;

  mutable base::Mutex native_modules_mutex_;

  //////////////////////////////////////////////////////////////////////////////
  // Protected by {native_modules_mutex_}:

  std::map<Address, std::pair<Address, NativeModule*>> lookup_map_;

  // End of fields protected by {native_modules_mutex_}.
  //////////////////////////////////////////////////////////////////////////////

  // We remember the end address of the last allocated code space and use that
  // as a hint for the next code space. As the WasmCodeManager is shared by the
  // whole process this ensures that Wasm code spaces are allocated next to each
  // other with a high likelyhood. This improves the performance of cross-module
  // calls as the branch predictor can only predict indirect call targets within
  // a certain range around the call instruction.
  std::atomic<Address> next_code_space_hint_;
};

// {WasmCodeRefScope}s form a perfect stack. New {WasmCode} pointers generated
// by e.g. creating new code or looking up code by its address are added to the
// top-most {WasmCodeRefScope}.
class V8_EXPORT_PRIVATE V8_NODISCARD WasmCodeRefScope {
 public:
  WasmCodeRefScope();
  WasmCodeRefScope(const WasmCodeRefScope&) = delete;
  WasmCodeRefScope& operator=(const WasmCodeRefScope&) = delete;
  ~WasmCodeRefScope();

  // Register a {WasmCode} reference in the current {WasmCodeRefScope}. Fails if
  // there is no current scope.
  static void AddRef(WasmCode*);

 private:
  WasmCodeRefScope* const previous_scope_;
  std::vector<WasmCode*> code_ptrs_;
};

class WasmCodeLookupCache final {
  friend WasmCodeManager;

 public:
  WasmCodeLookupCache() { Flush(); }

  WasmCodeLookupCache(const WasmCodeLookupCache&) = delete;
  WasmCodeLookupCache& operator=(const WasmCodeLookupCache&) = delete;

 private:
  struct CacheEntry {
    std::atomic<Address> pc;
    wasm::WasmCode* code;
    SafepointEntry safepoint_entry;
    CacheEntry() : safepoint_entry() {}
  };

  void Flush();
  CacheEntry* GetCacheEntry(Address pc);

  static const int kWasmCodeLookupCacheSize = 1024;
  CacheEntry cache_[kWasmCodeLookupCacheSize];
};

}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_WASM_CODE_MANAGER_H_
```