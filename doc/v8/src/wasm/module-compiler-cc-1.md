Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/module-compiler.cc`. The snippet focuses on the `CompilationState` class and lazy compilation, including tier-up mechanisms and type feedback processing.

Here's a breakdown of the code's functions and features:

1. **`CompilationState` PIMPL Implementation:** The code defines the interface of the `CompilationState` class and uses the PIMPL (Pointer to Implementation) idiom to hide implementation details in `CompilationStateImpl`. This includes methods for:
    *   Initializing and cancelling compilation jobs.
    *   Setting error states.
    *   Managing wire bytes storage.
    *   Adding compilation event callbacks.
    *   Triggering tier-up for functions.
    *   Managing top-tier compilation jobs.
    *   Handling initialization after deserialization.
    *   Querying compilation status (failed, baseline finished).
    *   Setting the compilation ID.
    *   Getting the dynamic tiering setting.
    *   Estimating memory consumption.
    *   Publishing compiled code.
    *   Creating new `CompilationState` instances.
    *   Getting and updating detected WebAssembly features.

2. **Compilation Hints and Strategies:** The code defines functions to retrieve and apply compilation hints (e.g., compile eagerly or lazily) from the WebAssembly module. It also defines a `GetCompileStrategy` function to determine the compilation strategy for a given function based on these hints and other factors like whether the module is being lazily compiled.

3. **Execution Tiering:** The code manages different execution tiers for WebAssembly code (e.g., Liftoff, Turbofan). It includes functions like `GetDefaultTiersPerModule` and `GetLazyCompilationTiers` to determine the appropriate tiers based on factors such as debug mode, compilation hints, and dynamic tiering settings.

4. **Lazy Compilation:** The code implements lazy compilation for WebAssembly functions. The `CompileLazy` function compiles a single function on demand. It handles compilation errors, publishes the compiled code, and potentially triggers tier-up to a higher optimization level.

5. **Lazy Compilation Errors:** The `ThrowLazyCompilationError` function is responsible for validating a function that failed to compile lazily and throwing a JavaScript error with details about the compilation failure.

6. **Transitive Type Feedback Processing:** The `TransitiveTypeFeedbackProcessor` class gathers type feedback from JavaScript execution and propagates it to called functions. This feedback is used to guide optimizations like inlining. It processes call site feedback, including direct calls, `call_ref`, and `call_indirect`.

7. **Feedback Maker:**  The `FeedbackMaker` class helps in collecting and organizing type feedback for a specific function. It handles different types of calls (direct, `call_ref`, `call_indirect`), manages a cache of call targets, and creates `CallSiteFeedback` objects.

8. **Tier-Up Triggering:** The `TriggerTierUp` function initiates the compilation of a function to a higher optimization tier (Turbofan) based on feedback indicating that the function is frequently executed (hot).

Now, let's structure the response according to the user's requirements.
这是v8源代码文件 `v8/src/wasm/module-compiler.cc` 的第二部分，主要关注以下功能：

**1. `CompilationState` 类的 PIMPL 实现:**

这部分代码展示了 `CompilationState` 类的 PIMPL（Pointer to Implementation）模式的实现。这意味着 `CompilationState` 类本身只声明了接口，而真正的实现细节放在了 `CompilationStateImpl` 类中。

*   **功能:**
    *   **生命周期管理:**  `~CompilationState()` 调用 `CompilationStateImpl` 的析构函数进行清理。
    *   **编译任务管理:** 提供 `InitCompileJob()`, `CancelCompilation()`, `CancelInitialCompilation()` 方法来管理编译任务的生命周期。
    *   **错误处理:** `SetError()` 方法用于设置编译错误状态。
    *   **存储管理:**  `SetWireBytesStorage()` 和 `GetWireBytesStorage()` 用于管理 WebAssembly 模块的原始字节码（wire bytes）。
    *   **回调机制:** `AddCallback()` 允许添加编译事件的回调函数。
    *   **分层编译控制:**  `TierUpAllFunctions()`, `AllowAnotherTopTierJob()`, `AllowAnotherTopTierJobForAllFunctions()` 用于控制 WebAssembly 函数的优化编译（tier-up）过程。
    *   **反序列化支持:** `InitializeAfterDeserialization()` 用于在模块反序列化后初始化编译进度。
    *   **状态查询:**  `failed()` 和 `baseline_compilation_finished()` 用于查询编译状态。
    *   **编译 ID 管理:** `set_compilation_id()` 用于设置编译 ID。
    *   **动态分层信息:** `dynamic_tiering()` 返回动态分层编译的设置。
    *   **内存估算:** `EstimateCurrentMemoryConsumption()` 用于估算当前的内存消耗。
    *   **代码发布:** `PublishCode()` 用于发布编译完成的 WebAssembly 代码。
    *   **创建实例:** `New()` 是一个静态方法，用于创建 `CompilationState` 实例。
    *   **特性检测:** `detected_features()` 和 `UpdateDetectedFeatures()` 用于获取和更新检测到的 WebAssembly 特性。

**2. 编译策略和执行层级 (Execution Tier) 的选择:**

*   **功能:**
    *   定义了 `ApplyHintToExecutionTier()` 函数，用于将编译提示转换为具体的执行层级（例如：Baseline, Optimized）。
    *   `GetCompilationHint()` 函数用于获取 WebAssembly 模块中指定函数的编译提示。
    *   `GetCompileStrategy()` 函数根据模块配置、编译特性和编译提示，决定函数的编译策略（例如：延迟编译、立即编译）。
    *   定义了 `ExecutionTierPair` 结构体，用于表示 Baseline 和 Top Tier 两个执行层级。
    *   `GetDefaultTiersPerModule()` 函数根据模块类型（普通 wasm 或 asm.js）、debug 状态和动态分层设置，确定模块的默认执行层级。
    *   `GetLazyCompilationTiers()` 函数在延迟编译场景下，根据编译提示和调试状态，确定函数的执行层级。

**3. 延迟编译 (Lazy Compilation):**

*   **功能:**
    *   `CompileLazy()` 函数实现了 WebAssembly 函数的延迟编译。当第一次调用一个尚未编译的延迟编译函数时，会触发此函数进行编译。
    *   它会获取函数的执行层级，执行编译，发布编译后的代码，并根据策略决定是否启动更高层级的优化编译。
    *   它还包含了性能统计的代码，用于记录延迟编译的时间。

**4. 延迟编译错误处理:**

*   **功能:**
    *   `ThrowLazyCompilationError()` 函数用于处理延迟编译失败的情况。它会对函数代码进行验证，并抛出一个包含详细错误信息的 JavaScript 异常。

**5. 传递类型反馈处理 (Transitive Type Feedback Processing):**

*   **功能:**
    *   `TransitiveTypeFeedbackProcessor` 类用于处理 WebAssembly 函数的类型反馈信息。
    *   当一个 WebAssembly 函数被执行时，V8 会收集关于其调用目标的信息（类型反馈）。这个类负责将这些信息传递给被调用的函数，以便进行更深入的优化（例如内联）。
    *   它会遍历调用链，收集并处理每个函数的调用点信息，包括直接调用、`call_ref` 和 `call_indirect`。
    *   `FeedbackMaker` 类是 `TransitiveTypeFeedbackProcessor` 的辅助类，用于构建和管理单个函数的调用点反馈信息。

**6. 触发优化编译 (Tier-Up):**

*   **功能:**
    *   `TriggerTierUp()` 函数用于触发将 WebAssembly 函数编译到更高优化层级（通常是 Turbofan）的操作。
    *   这通常发生在 V8 检测到某个函数执行频率很高，值得进行更积极的优化时。
    *   它会更新函数的优先级信息，并创建相应的编译任务。

**如果 v8/src/wasm/module-compiler.cc 以 .tq 结尾:**

如果 `v8/src/wasm/module-compiler.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种 V8 使用的类型化的中间语言，用于编写高效的内置函数和运行时代码。

**与 JavaScript 的功能关系及示例:**

这部分代码直接影响 WebAssembly 在 JavaScript 中的执行性能。延迟编译、分层编译和类型反馈优化都是为了提高 WebAssembly 代码的执行效率。

**JavaScript 示例:**

```javascript
// 假设有一个 WebAssembly 模块
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60,
  0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0a, 0x01,
  0x07, 0x61, 0x64, 0x64, 0x5f, 0x69, 0x33, 0x32, 0x00, 0x00, 0x0a, 0x09,
  0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
]);

WebAssembly.instantiate(wasmCode)
  .then(module => {
    const instance = module.instance;
    // 第一次调用 add_i32 函数时，可能会触发 CompileLazy
    console.log(instance.exports.add_i32(5, 3)); // 输出 8

    // 多次调用后，V8 可能会根据类型反馈触发 TriggerTierUp 进行优化
    for (let i = 0; i < 10000; i++) {
      instance.exports.add_i32(i, i + 1);
    }

    // 再次调用，可能执行的是优化后的代码
    console.log(instance.exports.add_i32(10, 20)); // 输出 30
  });
```

在这个例子中：

*   首次调用 `instance.exports.add_i32` 时，如果该函数是延迟编译的，`CompileLazy` 可能会被调用来编译该函数。
*   多次调用后，V8 的类型反馈机制会记录 `add_i32` 的调用情况。如果 V8 判断该函数很“热”，可能会调用 `TriggerTierUp` 将其编译到更优化的层级（例如 Turbofan）。

**代码逻辑推理 (假设输入与输出):**

假设我们正在处理一个简单的 WebAssembly 模块，其中包含一个未编译的函数 `funcA`。

**假设输入 (在 `CompileLazy` 函数中):**

*   `isolate`: 当前 V8 隔离区。
*   `trusted_instance_data`: 包含 WebAssembly 实例信息的对象。
*   `func_index`:  `funcA` 的索引。

**可能的输出:**

*   **成功编译:** `CompileLazy` 函数成功编译 `funcA`，并将编译后的代码添加到 `native_module` 中。函数返回 `true`。后续对 `funcA` 的调用将执行编译后的代码。
*   **编译失败:** 如果编译过程中出现错误（例如，代码验证失败），`CompileLazy` 函数可能会返回 `false`。如果启用了 `--wasm-lazy-validation`，可能会调用 `ThrowLazyCompilationError` 抛出异常。

**用户常见的编程错误:**

虽然这段代码是 V8 内部的实现，但用户在使用 WebAssembly 时可能会遇到与之相关的错误，例如：

*   **WebAssembly 代码格式错误:**  如果提供的 WebAssembly 字节码不符合规范，V8 在编译时会报错。这可能在 `CompileLazy` 或更早的阶段被检测到。
*   **类型不匹配:** 在 JavaScript 调用 WebAssembly 函数时，如果提供的参数类型与 WebAssembly 函数签名不匹配，可能会导致错误。虽然这段代码不直接处理这种情况，但类型反馈机制会记录这些调用信息，并可能影响未来的优化决策。

**总结 (归纳功能):**

这部分 `v8/src/wasm/module-compiler.cc` 代码的核心功能是 **管理 WebAssembly 模块的编译过程，包括延迟编译、分层编译、类型反馈优化以及错误处理**。它定义了 `CompilationState` 类来维护编译状态，并实现了延迟编译和类型反馈机制，以提高 WebAssembly 代码的执行效率。 这些机制使得 V8 能够根据实际的执行情况动态地优化 WebAssembly 代码。

### 提示词
```
这是目录为v8/src/wasm/module-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ancelled();
}

}  // namespace

//////////////////////////////////////////////////////
// PIMPL implementation of {CompilationState}.

CompilationState::~CompilationState() { Impl(this)->~CompilationStateImpl(); }

void CompilationState::InitCompileJob() { Impl(this)->InitCompileJob(); }

void CompilationState::CancelCompilation() {
  Impl(this)->CancelCompilation(CompilationStateImpl::kCancelUnconditionally);
}

void CompilationState::CancelInitialCompilation() {
  Impl(this)->CancelCompilation(
      CompilationStateImpl::kCancelInitialCompilation);
}

void CompilationState::SetError() { Impl(this)->SetError(); }

void CompilationState::SetWireBytesStorage(
    std::shared_ptr<WireBytesStorage> wire_bytes_storage) {
  Impl(this)->SetWireBytesStorage(std::move(wire_bytes_storage));
}

std::shared_ptr<WireBytesStorage> CompilationState::GetWireBytesStorage()
    const {
  return Impl(this)->GetWireBytesStorage();
}

void CompilationState::AddCallback(
    std::unique_ptr<CompilationEventCallback> callback) {
  return Impl(this)->AddCallback(std::move(callback));
}

void CompilationState::TierUpAllFunctions() {
  Impl(this)->TierUpAllFunctions();
}

void CompilationState::AllowAnotherTopTierJob(uint32_t func_index) {
  Impl(this)->AllowAnotherTopTierJob(func_index);
}

void CompilationState::AllowAnotherTopTierJobForAllFunctions() {
  Impl(this)->AllowAnotherTopTierJobForAllFunctions();
}

void CompilationState::InitializeAfterDeserialization(
    base::Vector<const int> lazy_functions,
    base::Vector<const int> eager_functions) {
  Impl(this)->InitializeCompilationProgressAfterDeserialization(
      lazy_functions, eager_functions);
}

bool CompilationState::failed() const { return Impl(this)->failed(); }

bool CompilationState::baseline_compilation_finished() const {
  return Impl(this)->baseline_compilation_finished();
}

void CompilationState::set_compilation_id(int compilation_id) {
  Impl(this)->set_compilation_id(compilation_id);
}

DynamicTiering CompilationState::dynamic_tiering() const {
  return Impl(this)->dynamic_tiering();
}

size_t CompilationState::EstimateCurrentMemoryConsumption() const {
  return Impl(this)->EstimateCurrentMemoryConsumption();
}

std::vector<WasmCode*> CompilationState::PublishCode(
    base::Vector<std::unique_ptr<WasmCode>> unpublished_code) {
  return Impl(this)->PublishCode(unpublished_code);
}

// static
std::unique_ptr<CompilationState> CompilationState::New(
    const std::shared_ptr<NativeModule>& native_module,
    std::shared_ptr<Counters> async_counters, DynamicTiering dynamic_tiering,
    WasmDetectedFeatures detected_features) {
  return std::unique_ptr<CompilationState>(
      reinterpret_cast<CompilationState*>(new CompilationStateImpl(
          std::move(native_module), std::move(async_counters), dynamic_tiering,
          detected_features)));
}

WasmDetectedFeatures CompilationState::detected_features() const {
  return Impl(this)->detected_features();
}

WasmDetectedFeatures CompilationState::UpdateDetectedFeatures(
    WasmDetectedFeatures detected_features) {
  return Impl(this)->UpdateDetectedFeatures(detected_features);
}

// End of PIMPL implementation of {CompilationState}.
//////////////////////////////////////////////////////

namespace {

ExecutionTier ApplyHintToExecutionTier(WasmCompilationHintTier hint,
                                       ExecutionTier default_tier) {
  switch (hint) {
    case WasmCompilationHintTier::kDefault:
      return default_tier;
    case WasmCompilationHintTier::kBaseline:
      return ExecutionTier::kLiftoff;
    case WasmCompilationHintTier::kOptimized:
      return ExecutionTier::kTurbofan;
  }
  UNREACHABLE();
}

const WasmCompilationHint* GetCompilationHint(const WasmModule* module,
                                              uint32_t func_index) {
  DCHECK_LE(module->num_imported_functions, func_index);
  uint32_t hint_index = declared_function_index(module, func_index);
  const std::vector<WasmCompilationHint>& compilation_hints =
      module->compilation_hints;
  if (hint_index < compilation_hints.size()) {
    return &compilation_hints[hint_index];
  }
  return nullptr;
}

CompileStrategy GetCompileStrategy(const WasmModule* module,
                                   WasmEnabledFeatures enabled_features,
                                   uint32_t func_index, bool lazy_module) {
  if (lazy_module) return CompileStrategy::kLazy;
  if (!enabled_features.has_compilation_hints()) {
    return CompileStrategy::kDefault;
  }
  auto* hint = GetCompilationHint(module, func_index);
  if (hint == nullptr) return CompileStrategy::kDefault;
  switch (hint->strategy) {
    case WasmCompilationHintStrategy::kLazy:
      return CompileStrategy::kLazy;
    case WasmCompilationHintStrategy::kEager:
      return CompileStrategy::kEager;
    case WasmCompilationHintStrategy::kLazyBaselineEagerTopTier:
      return CompileStrategy::kLazyBaselineEagerTopTier;
    case WasmCompilationHintStrategy::kDefault:
      return CompileStrategy::kDefault;
  }
}

struct ExecutionTierPair {
  ExecutionTier baseline_tier;
  ExecutionTier top_tier;
};

// Pass the debug state as a separate parameter to avoid data races: the debug
// state may change between its use here and its use at the call site. To have
// a consistent view on the debug state, the caller reads the debug state once
// and then passes it to this function.
ExecutionTierPair GetDefaultTiersPerModule(NativeModule* native_module,
                                           DynamicTiering dynamic_tiering,
                                           DebugState is_in_debug_state,
                                           bool lazy_module) {
  const WasmModule* module = native_module->module();
  if (lazy_module) {
    return {ExecutionTier::kNone, ExecutionTier::kNone};
  }
  if (is_asmjs_module(module)) {
    DCHECK(!is_in_debug_state);
    return {ExecutionTier::kTurbofan, ExecutionTier::kTurbofan};
  }
  if (is_in_debug_state) {
    return {ExecutionTier::kLiftoff, ExecutionTier::kLiftoff};
  }
  ExecutionTier baseline_tier =
      v8_flags.liftoff ? ExecutionTier::kLiftoff : ExecutionTier::kTurbofan;
  bool eager_tier_up = !dynamic_tiering && v8_flags.wasm_tier_up;
  ExecutionTier top_tier =
      eager_tier_up ? ExecutionTier::kTurbofan : baseline_tier;
  return {baseline_tier, top_tier};
}

ExecutionTierPair GetLazyCompilationTiers(NativeModule* native_module,
                                          uint32_t func_index,
                                          DebugState is_in_debug_state) {
  DynamicTiering dynamic_tiering =
      Impl(native_module->compilation_state())->dynamic_tiering();
  // For lazy compilation, get the tiers we would use if lazy compilation is
  // disabled.
  constexpr bool kNotLazy = false;
  ExecutionTierPair tiers = GetDefaultTiersPerModule(
      native_module, dynamic_tiering, is_in_debug_state, kNotLazy);
  // If we are in debug mode, we ignore compilation hints.
  if (is_in_debug_state) return tiers;

  // Check if compilation hints override default tiering behaviour.
  if (native_module->enabled_features().has_compilation_hints()) {
    if (auto* hint = GetCompilationHint(native_module->module(), func_index)) {
      tiers.baseline_tier =
          ApplyHintToExecutionTier(hint->baseline_tier, tiers.baseline_tier);
      tiers.top_tier = ApplyHintToExecutionTier(hint->top_tier, tiers.top_tier);
    }
  }

  if (V8_UNLIKELY(v8_flags.wasm_tier_up_filter >= 0 &&
                  func_index !=
                      static_cast<uint32_t>(v8_flags.wasm_tier_up_filter))) {
    tiers.top_tier = tiers.baseline_tier;
  }

  // Correct top tier if necessary.
  static_assert(ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                "Assume an order on execution tiers");
  if (tiers.baseline_tier > tiers.top_tier) {
    tiers.top_tier = tiers.baseline_tier;
  }
  return tiers;
}

// The {CompilationUnitBuilder} builds compilation units and stores them in an
// internal buffer. The buffer is moved into the working queue of the
// {CompilationStateImpl} when {Commit} is called.
class CompilationUnitBuilder {
 public:
  explicit CompilationUnitBuilder(NativeModule* native_module)
      : native_module_(native_module) {}

  void AddBaselineUnit(int func_index, ExecutionTier tier) {
    baseline_units_.emplace_back(func_index, tier, kNotForDebugging);
  }

  void AddTopTierUnit(int func_index, ExecutionTier tier) {
    tiering_units_.emplace_back(func_index, tier, kNotForDebugging);
  }

  void Commit() {
    if (baseline_units_.empty() && tiering_units_.empty()) return;
    compilation_state()->CommitCompilationUnits(base::VectorOf(baseline_units_),
                                                base::VectorOf(tiering_units_));
    Clear();
  }

  void Clear() {
    baseline_units_.clear();
    tiering_units_.clear();
  }

  const WasmModule* module() { return native_module_->module(); }

 private:
  CompilationStateImpl* compilation_state() const {
    return Impl(native_module_->compilation_state());
  }

  NativeModule* const native_module_;
  std::vector<WasmCompilationUnit> baseline_units_;
  std::vector<WasmCompilationUnit> tiering_units_;
};

DecodeResult ValidateSingleFunction(Zone* zone, const WasmModule* module,
                                    int func_index,
                                    base::Vector<const uint8_t> code,
                                    WasmEnabledFeatures enabled_features,
                                    WasmDetectedFeatures* detected_features) {
  // Sometimes functions get validated unpredictably in the background, for
  // debugging or when inlining one function into another. We check here if that
  // is the case, and exit early if so.
  if (module->function_was_validated(func_index)) return {};
  const WasmFunction* func = &module->functions[func_index];
  bool is_shared = module->type(func->sig_index).is_shared;
  FunctionBody body{func->sig, func->code.offset(), code.begin(), code.end(),
                    is_shared};
  DecodeResult result = ValidateFunctionBody(zone, enabled_features, module,
                                             detected_features, body);
  if (result.ok()) module->set_function_validated(func_index);
  return result;
}

enum OnlyLazyFunctions : bool {
  kAllFunctions = false,
  kOnlyLazyFunctions = true,
};

bool IsLazyModule(const WasmModule* module) {
  return v8_flags.wasm_lazy_compilation ||
         (v8_flags.asm_wasm_lazy_compilation && is_asmjs_module(module));
}

class CompileLazyTimingScope {
 public:
  CompileLazyTimingScope(Counters* counters, NativeModule* native_module)
      : counters_(counters), native_module_(native_module) {
    timer_.Start();
  }

  ~CompileLazyTimingScope() {
    base::TimeDelta elapsed = timer_.Elapsed();
    native_module_->AddLazyCompilationTimeSample(elapsed.InMicroseconds());
    counters_->wasm_lazy_compile_time()->AddTimedSample(elapsed);
  }

 private:
  Counters* counters_;
  NativeModule* native_module_;
  base::ElapsedTimer timer_;
};

}  // namespace

bool CompileLazy(Isolate* isolate,
                 Tagged<WasmTrustedInstanceData> trusted_instance_data,
                 int func_index) {
  DisallowGarbageCollection no_gc;
  NativeModule* native_module = trusted_instance_data->native_module();
  Counters* counters = isolate->counters();

  // Put the timer scope around everything, including the {CodeSpaceWriteScope}
  // and its destruction, to measure complete overhead (apart from the runtime
  // function itself, which has constant overhead).
  std::optional<CompileLazyTimingScope> lazy_compile_time_scope;
  if (base::TimeTicks::IsHighResolution()) {
    lazy_compile_time_scope.emplace(counters, native_module);
  }

  DCHECK(!native_module->lazy_compile_frozen());

  TRACE_LAZY("Compiling wasm-function#%d.\n", func_index);

  CompilationStateImpl* compilation_state =
      Impl(native_module->compilation_state());
  DebugState is_in_debug_state = native_module->IsInDebugState();
  ExecutionTierPair tiers =
      GetLazyCompilationTiers(native_module, func_index, is_in_debug_state);

  DCHECK_LE(native_module->num_imported_functions(), func_index);
  DCHECK_LT(func_index, native_module->num_functions());
  WasmCompilationUnit baseline_unit{
      func_index, tiers.baseline_tier,
      is_in_debug_state ? kForDebugging : kNotForDebugging};
  CompilationEnv env = CompilationEnv::ForModule(native_module);
  WasmDetectedFeatures detected_features;
  WasmCompilationResult result = baseline_unit.ExecuteCompilation(
      &env, compilation_state->GetWireBytesStorage().get(), counters,
      &detected_features);
  compilation_state->OnCompilationStopped(detected_features);

  // During lazy compilation, we can only get compilation errors when
  // {--wasm-lazy-validation} is enabled. Otherwise, the module was fully
  // verified before starting its execution.
  CHECK_IMPLIES(result.failed(), v8_flags.wasm_lazy_validation);
  if (result.failed()) {
    return false;
  }

  WasmCodeRefScope code_ref_scope;
  WasmCode* code =
      native_module->PublishCode(native_module->AddCompiledCode(result));
  DCHECK_EQ(func_index, code->index());

  if (V8_UNLIKELY(native_module->log_code())) {
    GetWasmEngine()->LogCode(base::VectorOf(&code, 1));
    // Log the code immediately in the current isolate.
    GetWasmEngine()->LogOutstandingCodesForIsolate(isolate);
  }

  counters->wasm_lazily_compiled_functions()->Increment();

  const WasmModule* module = native_module->module();
  const bool lazy_module = IsLazyModule(module);
  if (GetCompileStrategy(module, native_module->enabled_features(), func_index,
                         lazy_module) == CompileStrategy::kLazy &&
      tiers.baseline_tier < tiers.top_tier) {
    WasmCompilationUnit tiering_unit{func_index, tiers.top_tier,
                                     kNotForDebugging};
    compilation_state->CommitTopTierCompilationUnit(tiering_unit);
  }
  return true;
}

void ThrowLazyCompilationError(Isolate* isolate,
                               const NativeModule* native_module,
                               int func_index) {
  const WasmModule* module = native_module->module();

  CompilationStateImpl* compilation_state =
      Impl(native_module->compilation_state());
  const WasmFunction* func = &module->functions[func_index];
  base::Vector<const uint8_t> code =
      compilation_state->GetWireBytesStorage()->GetCode(func->code);

  auto enabled_features = native_module->enabled_features();
  // This path is unlikely, so the overhead for creating an extra Zone is
  // not important.
  Zone validation_zone{GetWasmEngine()->allocator(), ZONE_NAME};
  WasmDetectedFeatures unused_detected_features;
  DecodeResult decode_result =
      ValidateSingleFunction(&validation_zone, module, func_index, code,
                             enabled_features, &unused_detected_features);

  CHECK(decode_result.failed());
  wasm::ErrorThrower thrower(isolate, nullptr);
  thrower.CompileFailed(GetWasmErrorWithName(native_module->wire_bytes(),
                                             func_index, module,
                                             std::move(decode_result).error()));
}

// The main purpose of this class is to copy the feedback vectors that live in
// `FixedArray`s on the JavaScript heap to a C++ datastructure on the `module`
// that is accessible to the background compilation threads.
// While we are at it, we also do some light processing here, e.g., mapping the
// feedback to functions, identified by their function index, and filtering out
// feedback for calls to imported functions (which we currently don't inline).
class TransitiveTypeFeedbackProcessor {
 public:
  static void Process(Isolate* isolate,
                      Tagged<WasmTrustedInstanceData> trusted_instance_data,
                      int func_index) {
    TransitiveTypeFeedbackProcessor{isolate, trusted_instance_data, func_index}
        .ProcessQueue();
  }

 private:
  TransitiveTypeFeedbackProcessor(
      Isolate* isolate, Tagged<WasmTrustedInstanceData> trusted_instance_data,
      int func_index)
      : isolate_(isolate),
        instance_data_(trusted_instance_data),
        module_(trusted_instance_data->module()),
        mutex_guard(&module_->type_feedback.mutex),
        feedback_for_function_(module_->type_feedback.feedback_for_function) {
    queue_.insert(func_index);
  }

  ~TransitiveTypeFeedbackProcessor() { DCHECK(queue_.empty()); }

  void ProcessQueue() {
    while (!queue_.empty()) {
      auto next = queue_.cbegin();
      ProcessFunction(*next);
      queue_.erase(next);
    }
  }

  void ProcessFunction(int func_index);

  void EnqueueCallees(const std::vector<CallSiteFeedback>& feedback) {
    for (size_t i = 0; i < feedback.size(); i++) {
      const CallSiteFeedback& csf = feedback[i];
      for (int j = 0; j < csf.num_cases(); j++) {
        int func = csf.function_index(j);
        // Don't spend time on calls that have never been executed.
        if (csf.call_count(j) == 0) continue;
        // Don't recompute feedback that has already been processed.
        auto existing = feedback_for_function_.find(func);
        if (existing != feedback_for_function_.end() &&
            !existing->second.feedback_vector.empty()) {
          if (!existing->second.needs_reprocessing_after_deopt) {
            continue;
          }
          DCHECK(v8_flags.wasm_deopt);
          existing->second.needs_reprocessing_after_deopt = false;
        }
        queue_.insert(func);
      }
    }
  }

  DisallowGarbageCollection no_gc_scope_;
  Isolate* const isolate_;
  const Tagged<WasmTrustedInstanceData> instance_data_;
  const WasmModule* const module_;
  // TODO(jkummerow): Check if it makes a difference to apply any updates
  // as a single batch at the end.
  base::SharedMutexGuard<base::kExclusive> mutex_guard;
  std::unordered_map<uint32_t, FunctionTypeFeedback>& feedback_for_function_;
  std::set<int> queue_;
};

bool IsCrossInstanceCall(Tagged<Object> obj, Isolate* const isolate) {
  return obj == ReadOnlyRoots{isolate}.wasm_cross_instance_call_symbol();
}

class FeedbackMaker {
 public:
  FeedbackMaker(Isolate* const isolate,
                Tagged<WasmTrustedInstanceData> trusted_instance_data,
                int func_index, int num_calls)
      : isolate_(isolate),
        instance_data_(trusted_instance_data),
        num_imported_functions_(static_cast<int>(
            trusted_instance_data->module()->num_imported_functions)),
        func_index_(func_index) {
    result_.reserve(num_calls);
  }

  void AddCallRefCandidate(Tagged<WasmFuncRef> funcref, int count) {
    Tagged<WasmInternalFunction> internal_function =
        Cast<WasmFuncRef>(funcref)->internal(isolate_);
    // Discard cross-instance calls, as we can only inline same-instance code.
    if (internal_function->implicit_arg() != instance_data_) {
      has_non_inlineable_targets_ = true;
      return;
    }
    // Discard imports for now.
    if (internal_function->function_index() < num_imported_functions_) {
      has_non_inlineable_targets_ = true;
      return;
    }
    AddCall(internal_function->function_index(), count);
  }

  void AddCallIndirectCandidate(Tagged<Object> target_truncated_obj,
                                int count) {
    // Discard cross-instance calls, as we can only inline same-instance code.
    if (IsCrossInstanceCall(target_truncated_obj, isolate_)) {
      has_non_inlineable_targets_ = true;
      return;
    }
    Tagged<Smi> target_truncated_smi = Cast<Smi>(target_truncated_obj);

    // We need to map a truncated call target back to a function index.
    // Generally there may be multiple jump tables if code spaces are far apart
    // (to ensure that direct calls can always use a near call to the closest
    // jump table).
    // However, here we are always handling call targets that are originally
    // from the `WasmDispatchTable`, whose entries are always targets pointing
    // into the main jump table, so we only need to check against that.

#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
    WasmCodePointerTable::Handle handle = target_truncated_smi.value();
    Address entry = GetProcessWideWasmCodePointerTable()->GetEntrypoint(handle);
    wasm::WasmCode* code =
        wasm::GetWasmCodeManager()->LookupCode(nullptr, entry);
    if (!code || code->native_module() != instance_data_->native_module() ||
        code->IsAnonymous()) {
      // Was not in the main table (e.g., because it's an imported function).
      has_non_inlineable_targets_ = true;
      return;
    }
    DCHECK_EQ(code->kind(), WasmCode::Kind::kWasmFunction);
    uint32_t func_idx = code->index();
#else
    Address jt_start = instance_data_->native_module()->jump_table_start();
    uint32_t jt_size = JumpTableAssembler::SizeForNumberOfSlots(
        instance_data_->module()->num_declared_functions);
    Address jt_end = jt_start + jt_size;

    uint32_t jt_start_truncated = jt_start & kSmiMaxValue;
    uint32_t jt_end_truncated = jt_end & kSmiMaxValue;
    uint32_t target_truncated = target_truncated_smi.value();

    if (target_truncated < jt_start_truncated ||
        target_truncated >= jt_end_truncated) {
      // Was not in the main table (e.g., because it's an imported function).
      has_non_inlineable_targets_ = true;
      return;
    }

    uint32_t jt_offset = target_truncated - jt_start_truncated;
    uint32_t jt_slot_idx = JumpTableAssembler::SlotOffsetToIndex(jt_offset);
    uint32_t func_idx =
        instance_data_->module()->num_imported_functions + jt_slot_idx;
#endif
    AddCall(func_idx, count);
  }

  void AddCall(int target, int count) {
    // Keep the cache sorted (using insertion-sort), highest count first.
    int insertion_index = 0;
    while (insertion_index < cache_usage_ &&
           counts_cache_[insertion_index] >= count) {
      insertion_index++;
    }
    for (int shifted_index = cache_usage_ - 1; shifted_index >= insertion_index;
         shifted_index--) {
      targets_cache_[shifted_index + 1] = targets_cache_[shifted_index];
      counts_cache_[shifted_index + 1] = counts_cache_[shifted_index];
    }
    targets_cache_[insertion_index] = target;
    counts_cache_[insertion_index] = count;
    cache_usage_++;
  }

  bool HasTargetCached(int target) {
    auto end = targets_cache_ + cache_usage_;
    return std::find(targets_cache_, end, target) != end;
  }

  void FinalizeCall() {
    if (cache_usage_ == 0) {
      result_.emplace_back();
    } else if (cache_usage_ == 1) {
      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%zu inlineable (monomorphic)]\n",
               func_index_, result_.size());
      }
      result_.emplace_back(targets_cache_[0], counts_cache_[0]);
    } else {
      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%zu inlineable (polymorphic %d)]\n",
               func_index_, result_.size(), cache_usage_);
      }
      CallSiteFeedback::PolymorphicCase* polymorphic =
          new CallSiteFeedback::PolymorphicCase[cache_usage_];
      for (int i = 0; i < cache_usage_; i++) {
        polymorphic[i].function_index = targets_cache_[i];
        polymorphic[i].absolute_call_frequency = counts_cache_[i];
      }
      result_.emplace_back(polymorphic, cache_usage_);
    }
    result_.back().set_has_non_inlineable_targets(has_non_inlineable_targets_);
    has_non_inlineable_targets_ = false;
    cache_usage_ = 0;
  }

  void set_has_non_inlineable_targets() { has_non_inlineable_targets_ = true; }

  // {GetResult} can only be called on a r-value reference to make it more
  // obvious at call sites that {this} should not be used after this operation.
  std::vector<CallSiteFeedback>&& GetResult() && { return std::move(result_); }

 private:
  Isolate* const isolate_;
  const Tagged<WasmTrustedInstanceData> instance_data_;
  std::vector<CallSiteFeedback> result_;
  const int num_imported_functions_;
  const int func_index_;
  int cache_usage_{0};
  int targets_cache_[kMaxPolymorphism];
  int counts_cache_[kMaxPolymorphism];
  bool has_non_inlineable_targets_ = false;
};

void TransitiveTypeFeedbackProcessor::ProcessFunction(int func_index) {
  int which_vector = declared_function_index(module_, func_index);
  Tagged<Object> maybe_feedback =
      instance_data_->feedback_vectors()->get(which_vector);
  if (!IsFixedArray(maybe_feedback)) return;
  Tagged<FixedArray> feedback = Cast<FixedArray>(maybe_feedback);
  base::Vector<uint32_t> call_targets =
      module_->type_feedback.feedback_for_function[func_index]
          .call_targets.as_vector();

  // For each entry in {call_targets}, there are two {Object} slots in the
  // {feedback} vector:
  // +--------------------------+-----------------------------+----------------+
  // |        Call Type         |      Feedback: Entry 1      |    Entry 2     |
  // +-------------------------+------------------------------+----------------+
  // | direct                   | Smi(count)                  | Smi(0), unused |
  // +--------------------------+-----------------------------+----------------+
  // | ref, uninitialized       | Smi(0)                      | Smi(0)         |
  // | ref, monomorphic         | WasmFuncRef(target)         | Smi(count>0)   |
  // | ref, polymorphic         | FixedArray                  | Undefined      |
  // | ref, megamorphic         | MegamorphicSymbol           | Undefined      |
  // +--------------------------+-----------------------------+----------------+
  // | indirect, uninitialized  | Smi(0)                      | Smi(0)         |
  // | indirect, monomorphic    | Smi(truncated_target)       | Smi(count>0)   |
  // | indirect, wrong instance | WasmCrossInstanceCallSymbol | Smi(count>0)   |
  // | indirect, polymorphic    | FixedArray                  | Undefined      |
  // | indirect, megamorphic    | MegamorphicSymbol           | Undefined      |
  // +--------------------------+-----------------------------+----------------+
  // The FixedArray entries for the polymorphic cases look like the monomorphic
  // entries in the feedback vector itself, i.e., they can a (truncated) target,
  // or the wrong instance sentinel (for cross-instance call_indirect).
  // See {UpdateCallRefOrIndirectIC} in {wasm.tq} for how this is written.
  // Since this is combining untrusted data ({feedback} vector on the JS heap)
  // with trusted data ({call_targets}), make sure to avoid an OOB access.
  int checked_feedback_length = feedback->length();
  SBXCHECK_EQ(checked_feedback_length, call_targets.size() * 2);
  FeedbackMaker fm(isolate_, instance_data_, func_index,
                   checked_feedback_length / 2);
  for (int i = 0; i < checked_feedback_length; i += 2) {
    uint32_t sentinel_or_target = call_targets[i / 2];
    Tagged<Object> first_slot = feedback->get(i);
    Tagged<Object> second_slot = feedback->get(i + 1);

    if (sentinel_or_target != FunctionTypeFeedback::kCallRef &&
        sentinel_or_target != FunctionTypeFeedback::kCallIndirect) {
      // Direct call counts.
      int count = Smi::ToInt(first_slot);
      DCHECK_EQ(Smi::ToInt(second_slot), 0);
      // TODO(dlehmann): Currently, TurboFan assumes that we add feedback even
      // if the call count is zero. Once TurboFan is gone, revisit if we can
      // avoid this (similar to how we do for call_ref/call_indirect today).
      fm.AddCall(static_cast<int>(sentinel_or_target), count);
    } else if (IsSmi(second_slot) && Smi::ToInt(second_slot) == 0) {
      // Uninitialized call_ref or call_indirect.
      DCHECK_EQ(Smi::ToInt(first_slot), 0);
      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%d: uninitialized]\n", func_index, i / 2);
      }
    } else if (IsWasmFuncRef(first_slot)) {
      // Monomorphic call_ref.
      DCHECK_EQ(sentinel_or_target, FunctionTypeFeedback::kCallRef);
      int count = Smi::ToInt(second_slot);
      fm.AddCallRefCandidate(Cast<WasmFuncRef>(first_slot), count);
    } else if (IsSmi(first_slot) || IsCrossInstanceCall(first_slot, isolate_)) {
      // Monomorphic call_indirect.
      DCHECK_EQ(sentinel_or_target, FunctionTypeFeedback::kCallIndirect);
      int count = Smi::ToInt(second_slot);
      fm.AddCallIndirectCandidate(first_slot, count);
    } else if (IsFixedArray(first_slot)) {
      // Polymorphic call_ref or call_indirect.
      Tagged<FixedArray> polymorphic = Cast<FixedArray>(first_slot);
      DCHECK(IsUndefined(second_slot));
      int checked_polymorphic_length = polymorphic->length();
      SBXCHECK_LE(checked_polymorphic_length, 2 * kMaxPolymorphism);
      if (sentinel_or_target == FunctionTypeFeedback::kCallRef) {
        for (int j = 0; j < checked_polymorphic_length; j += 2) {
          Tagged<WasmFuncRef> target = Cast<WasmFuncRef>(polymorphic->get(j));
          int count = Smi::ToInt(polymorphic->get(j + 1));
          fm.AddCallRefCandidate(target, count);
        }
      } else {
        DCHECK_EQ(sentinel_or_target, FunctionTypeFeedback::kCallIndirect);
        for (int j = 0; j < checked_polymorphic_length; j += 2) {
          Tagged<Object> target = polymorphic->get(j);
          int count = Smi::ToInt(polymorphic->get(j + 1));
          fm.AddCallIndirectCandidate(target, count);
        }
      }
    } else if (first_slot == ReadOnlyRoots{isolate_}.megamorphic_symbol()) {
      DCHECK(IsUndefined(second_slot));
      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%d: megamorphic]\n", func_index, i / 2);
      }
    } else {
      UNREACHABLE();
    }

    if (v8_flags.wasm_deopt &&
        first_slot != ReadOnlyRoots{isolate_}.megamorphic_symbol()) {
      // If we already had feedback for this call, also add the already existing
      // feedback to prevent deopt loops where two different instantiations
      // (which have their own on-heap feedback vector) to "flip-flop" between
      // their inlining decisions potentially causing deopt loops.
      const std::vector<CallSiteFeedback>& existing =
          feedback_for_function_[func_index].feedback_vector;
      size_t feedback_index = i / 2;
      if (feedback_index < existing.size()) {
        const CallSiteFeedback& old_feedback = existing[feedback_index];
        if (old_feedback.has_non_inlineable_targets()) {
          fm.set_has_non_inlineable_targets();
        }
        for (int i = 0; i < old_feedback.num_cases(); ++i) {
          int old_target_function_index = old_feedback.function_index(i);
          // If the new feedback already contains the target, we do not touch
          // the call count.
          if (!fm.HasTargetCached(old_target_function_index)) {
            fm.AddCall(old_target_function_index, old_feedback.call_count(i));
            // There shouldn't be any imported functions in there as they can't
            // be inlined. If this DCHECK is invalidated,
            // has_non_inlineable_targets_ would need to be updated here to
            // reflect that.
            DCHECK_GE(static_cast<uint32_t>(old_target_function_index),
                      instance_data_->module()->num_imported_functions);
          }
        }
      }
    }

    fm.FinalizeCall();
  }
  std::vector<CallSiteFeedback> result = std::move(fm).GetResult();
  EnqueueCallees(result);
  feedback_for_function_[func_index].feedback_vector = std::move(result);
}

void TriggerTierUp(Isolate* isolate,
                   Tagged<WasmTrustedInstanceData> trusted_instance_data,
                   int func_index) {
  NativeModule* native_module = trusted_instance_data->native_module();
  CompilationStateImpl* compilation_state =
      Impl(native_module->compilation_state());
  WasmCompilationUnit tiering_unit{func_index, ExecutionTier::kTurbofan,
                                   kNotForDebugging};

  const WasmModule* module = native_module->module();
  int priority;
  {
    base::SharedMutexGuard<base::kExclusive> mutex_guard(
        &module->type_feedback.mutex);
    int array_index = wasm::declared_function_index(module, func_index);
    trusted_instance_data->tiering_budget_array()[array_index].store(
        v8_flags.wasm_tiering_budget, std::memory_order_relaxed);
    int& stored_priority =
        module->type_feedback.feedback_for_function[func_index].tierup_priority;
    if (stored_priority < kMaxInt) ++stored_priority;
    priority = stored_priority;
  }
  // Only create a compilation unit if this is the first time we detect this
  // function as hot (priority == 1), or if the priority increased
  // significantly. The latter is assumed to be the case if the priority
  // increased at least to four, and is a power of two.
  if (priority == 2 || !base::bits::IsPowerOfTwo(priority)) return;
```