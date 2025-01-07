Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the `module-compiler.cc` file's functionality, considering specific conditions (like `.tq` extension, JavaScript relation), logic inference, common errors, and finally a concise summary. The "part 6 of 6" indicates a cumulative summarization is needed.

2. **Initial Scan for Core Functionality:** I'll quickly read through the code, focusing on class names, key methods, and overall structure. I see `CompilationStateImpl`, `CompilationUnitQueues`, `WasmCompilationUnit`, `WasmCode`, and methods related to adding, committing, getting, and finishing compilation units. This immediately suggests the file manages the compilation process of WebAssembly modules.

3. **Break Down by Class/Structure:**  The code is centered around `CompilationStateImpl`. I'll analyze its purpose and the roles of its member variables and methods.

    * **`CompilationStateImpl`:** This seems to be the main orchestrator. It holds compilation units, manages different compilation tiers (baseline, top-tier), handles callbacks, tracks progress, and deals with errors. The mutexes (`mutex_`, `callbacks_mutex_`) indicate thread safety and management of concurrent compilation.

    * **`CompilationUnitQueues`:** This likely manages the queue of work items for the compilation process, separated by tiers and priorities.

    * **`WasmCompilationUnit`:** Represents a single unit of work for compilation (likely a function).

    * **`WasmCode`:** Represents the compiled code for a function.

4. **Identify Key Operations:**  Based on the methods, I can identify core functionalities:

    * **Adding compilation units:** `AddBaselineCompilationUnit`, `AddTopTierCompilationUnit`, `AddTopTierPriorityCompilationUnit`.
    * **Committing units:** `CommitCompilationUnits`, `CommitTopTierCompilationUnit`.
    * **Retrieving units:** `GetNextCompilationUnit`, `GetQueueForCompileTask`.
    * **Handling finished units:** `OnFinishedUnits`. This is crucial for tracking progress and triggering callbacks.
    * **Error handling:** `SetError`.
    * **Managing compilation tiers:**  References to "baseline" and "top-tier" compilation, often associated with Liftoff and Turbofan.
    * **Callbacks:**  The `callbacks_` vector and `TriggerCallbacks` method suggest a mechanism to notify when certain compilation events occur.
    * **Code publishing:** `PublishCompilationResults`, `PublishCode`, `SchedulePublishCompilationResults`.
    * **Dynamic tiering and caching:** The logic around `wasm_caching_threshold`, `wasm_caching_timeout_ms`, and the `TriggerCodeCachingAfterTimeoutTask`.
    * **Import wrapper compilation:** `CompileImportWrapperForTest`.

5. **Address Specific Requirements:** Now, I'll go through the specific points raised in the request:

    * **`.tq` extension:** The code is `.cc`, so it's C++, not Torque.
    * **JavaScript relation:** The code directly deals with compiling WebAssembly, which is tightly integrated with JavaScript. The compiled WASM code can be called from JS and vice versa. I'll provide a simple JS example of calling a WASM function.
    * **Logic Inference:** The `OnFinishedUnits` method has complex logic for updating compilation progress based on the tier of the finished code. I'll create a hypothetical scenario with input (current progress, finished code tier) and output (updated progress).
    * **Common Programming Errors:**  The locking mechanism with mutexes suggests potential deadlocks if not handled correctly. I'll illustrate a potential deadlock scenario.
    * **Part 6 of 6 and Overall Summary:**  Since this is the last part, I'll synthesize the functionalities identified so far into a comprehensive summary. I'll emphasize its role in the broader WASM compilation pipeline within V8.

6. **Refine and Structure the Output:** I will organize the findings clearly, using bullet points for functionalities, code blocks for examples, and clear explanations for logic inference and potential errors. I'll ensure the language is precise and avoids jargon where possible. The final summary will tie everything together.

7. **Self-Critique and Review:**  Before submitting, I'll re-read my answer and compare it to the code to ensure accuracy and completeness. I'll check if I've addressed all aspects of the request. For instance, I'll confirm that the logic inference example makes sense and the deadlock scenario is plausible. I'll also make sure the final summary is indeed a good representation of all the described functionalities.
好的，让我们来分析一下 `v8/src/wasm/module-compiler.cc` 这个文件的功能。

**文件功能概览:**

从提供的代码片段来看，`v8/src/wasm/module-compiler.cc` 的主要功能是**管理 WebAssembly 模块的编译过程**。它负责协调不同阶段的编译工作，跟踪编译进度，处理编译完成的回调，以及处理编译过程中可能出现的错误。

**具体功能点:**

1. **管理编译状态 (`CompilationStateImpl`):**
   - 维护模块的编译状态，包括已完成的编译层级、待编译的单元、以及编译过程中的错误状态。
   - 使用互斥锁 (`mutex_`, `callbacks_mutex_`) 保护共享的编译状态，确保线程安全。
   - 跟踪尚未完成基线编译的单元数量 (`outstanding_baseline_units_`)。
   - 记录编译过程中检测到的特性 (`detected_features_`)。
   - 管理编译回调 (`callbacks_`)，在特定编译事件发生时触发。
   - 记录编译 ID (`compilation_id_`) 用于跟踪。
   - 负责触发代码缓存 (`TriggerCachingAfterTimeout`, `TriggerOutstandingCallbacks`)，以优化性能。

2. **管理编译单元队列 (`CompilationUnitQueues`):**
   - 维护不同编译层级（例如基线编译和优化编译）的编译单元队列。
   - 允许添加带有优先级的编译单元 (`AddTopTierPriorityCompilationUnit`)。
   - 提供方法获取指定任务的队列 (`GetQueueForCompileTask`) 和下一个待编译的单元 (`GetNextCompilationUnit`)。

3. **处理编译单元的提交 (`CommitCompilationUnits`):**
   - 接收并添加基线编译和优化编译的单元到相应的队列。
   - 通知编译任务有新的工作单元，可以增加并发度。

4. **处理已完成的编译单元 (`OnFinishedUnits`):**
   - 接收已完成编译的代码对象 (`WasmCode`) 向量。
   - 更新函数的编译进度 (`compilation_progress_`)，记录已达到的编译层级。
   - 触发相应的编译完成回调。
   - 如果启用了 deopt，并且当前安装的代码是 Liftoff 代码，则允许再次进行优化编译。
   - 记录自上次触发代码缓存以来的字节数 (`bytes_since_last_chunk_`)，用于动态分层编译。

5. **触发编译事件回调 (`TriggerCallbacks`):**
   - 根据发生的编译事件（例如基线编译完成、编译失败、编译块完成）调用注册的回调函数。
   - 使用 `TRACE_EVENT` 记录编译事件。

6. **处理编译错误 (`SetError`):**
   - 设置编译失败标志 (`compile_failed_`)。
   - 清除回调列表。

7. **发布编译结果 (`PublishCompilationResults`, `PublishCode`, `SchedulePublishCompilationResults`):**
   - 将编译好的 `WasmCode` 对象发布到 `NativeModule` 中，使其可以被执行。
   - 提供同步和异步的发布机制。

8. **等待特定编译事件 (`WaitForCompilationEvent`):**
   - 允许等待特定的编译事件发生，例如基线编译完成。

9. **强制所有函数进行优化编译 (`TierUpAllFunctions`):**
   - 将所有尚未进行优化编译的函数添加到优化编译队列。
   - 直接编译尚未完成优化的函数。

10. **编译导入包装器 (`CompileImportWrapperForTest`):**
    - 为 WebAssembly 导入的函数编译包装器代码。

**关于文件扩展名和 Torque:**

`v8/src/wasm/module-compiler.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果文件以 `.tq` 结尾，那才是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部函数的领域特定语言。

**与 JavaScript 的关系及示例:**

`v8/src/wasm/module-compiler.cc` 的功能与 JavaScript 的执行密切相关。WebAssembly 模块通常由 JavaScript 加载和实例化，并且 JavaScript 代码可以调用 WebAssembly 模块中导出的函数。

**JavaScript 示例:**

```javascript
// 假设 'module.wasm' 是一个 WebAssembly 模块
fetch('module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;
    // 调用 WebAssembly 模块中导出的名为 'add' 的函数
    const result = instance.exports.add(5, 3);
    console.log(result); // 输出 8
  });
```

在这个例子中，`WebAssembly.instantiate` 内部会调用 V8 的 WebAssembly 编译流程，其中就包括 `v8/src/wasm/module-compiler.cc` 中实现的功能。该文件负责将 WebAssembly 字节码编译成可执行的机器码，使得 JavaScript 可以调用这些代码。

**代码逻辑推理及假设输入输出:**

**假设输入:**

- 存在一个 WebAssembly 模块，其中包含一个名为 `my_function` 的函数。
- 调用 `AddTopTierCompilationUnit` 将 `my_function` 添加到优化编译队列。
- 之后，编译线程完成了 `my_function` 的优化编译，并生成了 `WasmCode` 对象。

**输出（`OnFinishedUnits` 方法的执行结果）:**

- `code_vector` 参数包含指向 `my_function` 的 `WasmCode` 对象的指针，且 `code->tier()` 为 `ExecutionTier::kTurbofan`。
- `compilation_progress_` 中对应 `my_function` 的条目会被更新，其 `ReachedTierField` 会被设置为 `kTurbofan`。
- 如果满足动态分层编译的条件，可能会触发代码缓存相关的操作。
- 之前注册的、监听优化编译完成事件的回调函数会被调用。

**用户常见的编程错误:**

与这个文件直接相关的用户编程错误相对较少，因为它主要处理 V8 内部的编译逻辑。然而，用户在与 WebAssembly 交互时可能会遇到以下错误，这些错误可能与这个文件处理的编译过程有关：

1. **WebAssembly 模块加载或实例化失败:**  例如，如果 WebAssembly 模块的字节码无效，V8 的编译过程会失败，导致 JavaScript 中的 `WebAssembly.instantiate` 抛出错误。

   ```javascript
   fetch('invalid.wasm') // 假设这是一个无效的 wasm 文件
     .then(response => response.arrayBuffer())
     .then(bytes => WebAssembly.instantiate(bytes))
     .catch(error => {
       console.error("WebAssembly instantiation failed:", error);
     });
   ```

2. **调用未导出的 WebAssembly 函数:** 如果 JavaScript 尝试调用 WebAssembly 模块中没有导出的函数，会导致运行时错误。这与编译过程有关，因为编译器会确定哪些函数可以被导出。

   ```javascript
   fetch('module.wasm')
     .then(response => response.arrayBuffer())
     .then(bytes => WebAssembly.instantiate(bytes))
     .then(results => {
       const instance = results.instance;
       // 假设 'nonExistentFunction' 没有被导出
       instance.exports.nonExistentFunction(); // TypeError: ... is not a function
     });
   ```

3. **WebAssembly 函数调用时参数类型不匹配:** 如果传递给 WebAssembly 函数的参数类型与函数签名不符，可能会导致运行时错误或未定义的行为。

**归纳总结 (第 6 部分，共 6 部分):**

作为系列文章的最后一部分，可以归纳出 `v8/src/wasm/module-compiler.cc` 在 V8 的 WebAssembly 支持中扮演着至关重要的角色。它负责将 WebAssembly 字节码高效地编译成可执行的机器码，并管理整个编译生命周期。其核心功能包括：

- **状态管理:** 维护模块的编译状态和进度。
- **任务调度:** 管理不同编译层级的编译单元队列。
- **编译执行:** 触发实际的代码生成过程（虽然代码生成本身可能在其他文件中）。
- **结果处理:** 处理编译完成的代码，更新状态，并触发回调。
- **错误处理:** 捕获和处理编译过程中出现的错误。
- **性能优化:** 通过动态分层编译和代码缓存等机制提高性能。

该文件是 V8 执行 WebAssembly 代码的基础，确保了 JavaScript 环境能够有效地加载、实例化和执行 WebAssembly 模块。它通过精心设计的并发机制和状态管理，实现了高效且可靠的 WebAssembly 编译流程。

Prompt: 
```
这是目录为v8/src/wasm/module-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
lEvents)) {
    callbacks_.emplace_back(std::move(callback));
  }
}

void CompilationStateImpl::CommitCompilationUnits(
    base::Vector<WasmCompilationUnit> baseline_units,
    base::Vector<WasmCompilationUnit> top_tier_units) {
  base::MutexGuard guard{&mutex_};
  if (!baseline_units.empty() || !top_tier_units.empty()) {
    compilation_unit_queues_.AddUnits(baseline_units, top_tier_units,
                                      native_module_->module());
  }
  if (!baseline_units.empty()) {
    DCHECK(baseline_compile_job_->IsValid());
    baseline_compile_job_->NotifyConcurrencyIncrease();
  }
  if (!top_tier_units.empty()) {
    DCHECK(top_tier_compile_job_->IsValid());
    top_tier_compile_job_->NotifyConcurrencyIncrease();
  }
}

void CompilationStateImpl::CommitTopTierCompilationUnit(
    WasmCompilationUnit unit) {
  CommitCompilationUnits({}, {&unit, 1});
}

void CompilationStateImpl::AddTopTierPriorityCompilationUnit(
    WasmCompilationUnit unit, size_t priority) {
  compilation_unit_queues_.AddTopTierPriorityUnit(unit, priority);
  // We should not have a {CodeSpaceWriteScope} open at this point, as
  // {NotifyConcurrencyIncrease} can spawn new threads which could inherit PKU
  // permissions (which would be a security issue).
  top_tier_compile_job_->NotifyConcurrencyIncrease();
}

CompilationUnitQueues::Queue* CompilationStateImpl::GetQueueForCompileTask(
    int task_id) {
  return compilation_unit_queues_.GetQueueForTask(task_id);
}

std::optional<WasmCompilationUnit> CompilationStateImpl::GetNextCompilationUnit(
    CompilationUnitQueues::Queue* queue, CompilationTier tier) {
  return compilation_unit_queues_.GetNextUnit(queue, tier);
}

void CompilationStateImpl::OnFinishedUnits(
    base::Vector<WasmCode*> code_vector) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.OnFinishedUnits", "units", code_vector.size());

  base::MutexGuard guard(&callbacks_mutex_);

  // Assume an order of execution tiers that represents the quality of their
  // generated code.
  static_assert(ExecutionTier::kNone < ExecutionTier::kLiftoff &&
                    ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                "Assume an order on execution tiers");

  if (!v8_flags.wasm_jitless) {
    DCHECK_EQ(compilation_progress_.size(),
              native_module_->module()->num_declared_functions);
  }

  bool has_top_tier_code = false;

  for (size_t i = 0; i < code_vector.size(); i++) {
    WasmCode* code = code_vector[i];
    DCHECK_NOT_NULL(code);
    DCHECK_LT(code->index(), native_module_->num_functions());

    has_top_tier_code |= code->tier() == ExecutionTier::kTurbofan;

    if (code->index() <
        static_cast<int>(native_module_->num_imported_functions())) {
      // Import wrapper.
      DCHECK_EQ(code->tier(), ExecutionTier::kTurbofan);
      outstanding_baseline_units_--;
    } else {
      // Function.
      DCHECK_NE(code->tier(), ExecutionTier::kNone);

      // Read function's compilation progress.
      // This view on the compilation progress may differ from the actually
      // compiled code. Any lazily compiled function does not contribute to the
      // compilation progress but may publish code to the code manager.
      int slot_index =
          declared_function_index(native_module_->module(), code->index());
      uint8_t function_progress = compilation_progress_[slot_index];
      ExecutionTier required_baseline_tier =
          RequiredBaselineTierField::decode(function_progress);
      ExecutionTier reached_tier = ReachedTierField::decode(function_progress);

      // Check whether required baseline or top tier are reached.
      if (reached_tier < required_baseline_tier &&
          required_baseline_tier <= code->tier()) {
        DCHECK_GT(outstanding_baseline_units_, 0);
        outstanding_baseline_units_--;
      }
      if (code->tier() == ExecutionTier::kTurbofan) {
        bytes_since_last_chunk_ += code->instructions().size();
      }

      // Update function's compilation progress.
      if (code->tier() > reached_tier) {
        compilation_progress_[slot_index] = ReachedTierField::update(
            compilation_progress_[slot_index], code->tier());
      }
      // Allow another top tier compilation if deopts are enabled and the
      // currently installed code object is a liftoff object.
      // Ideally, this would be done only if the code->tier() ==
      // ExeuctionTier::Liftoff as the code object for which we run this
      // function should be the same as the one installed on the native_module.
      // This is unfortunately not the case as installing a code object on the
      // native module and updating the compilation_progress_ and the
      // CompilationUnitQueues::top_tier_compiled_ are not synchronized.
      // Note: GetCode() acquires the NativeModule::allocation_mutex_, so this
      // could cause deadlocks if any other place acquires
      // NativeModule::allocation_mutex_ first and then
      // CompilationStateImpl::callbacks_mutex_!
      const bool is_liftoff = code->tier() == ExecutionTier::kLiftoff;
      auto published_code_is_liftoff = [this](int index) {
        WasmCode* code = native_module_->GetCode(index);
        if (code == nullptr) return false;
        return code->is_liftoff();
      };
      if (v8_flags.wasm_deopt &&
          (is_liftoff || published_code_is_liftoff(code->index()))) {
        compilation_progress_[slot_index] = ReachedTierField::update(
            compilation_progress_[slot_index], ExecutionTier::kLiftoff);
        compilation_unit_queues_.AllowAnotherTopTierJob(code->index());
      }
      DCHECK_LE(0, outstanding_baseline_units_);
    }
  }

  // Update the {last_top_tier_compilation_timestamp_} if it is set (i.e. a
  // delayed task has already been spawned).
  if (has_top_tier_code && !last_top_tier_compilation_timestamp_.IsNull()) {
    last_top_tier_compilation_timestamp_ = base::TimeTicks::Now();
  }

  TriggerOutstandingCallbacks();
}

namespace {
class TriggerCodeCachingAfterTimeoutTask : public v8::Task {
 public:
  explicit TriggerCodeCachingAfterTimeoutTask(
      std::weak_ptr<NativeModule> native_module)
      : native_module_(std::move(native_module)) {}

  void Run() override {
    if (std::shared_ptr<NativeModule> native_module = native_module_.lock()) {
      Impl(native_module->compilation_state())->TriggerCachingAfterTimeout();
    }
  }

 private:
  const std::weak_ptr<NativeModule> native_module_;
};
}  // namespace

void CompilationStateImpl::TriggerOutstandingCallbacks() {
  callbacks_mutex_.AssertHeld();

  base::EnumSet<CompilationEvent> triggered_events;
  if (outstanding_baseline_units_ == 0) {
    triggered_events.Add(CompilationEvent::kFinishedBaselineCompilation);
  }

  // For dynamic tiering, trigger "compilation chunk finished" after a new chunk
  // of size {v8_flags.wasm_caching_threshold}.
  if (dynamic_tiering_ &&
      static_cast<size_t>(v8_flags.wasm_caching_threshold) <=
          bytes_since_last_chunk_) {
    // Trigger caching immediately if there is no timeout or the hard threshold
    // was reached.
    if (v8_flags.wasm_caching_timeout_ms <= 0 ||
        static_cast<size_t>(v8_flags.wasm_caching_hard_threshold) <=
            bytes_since_last_chunk_) {
      triggered_events.Add(CompilationEvent::kFinishedCompilationChunk);
      bytes_since_last_chunk_ = 0;
    } else if (last_top_tier_compilation_timestamp_.IsNull()) {
      // Trigger a task after the given timeout; that task will only trigger
      // caching if no new code was added until then. Otherwise, it will
      // re-schedule itself.
      V8::GetCurrentPlatform()->CallDelayedOnWorkerThread(
          std::make_unique<TriggerCodeCachingAfterTimeoutTask>(
              native_module_weak_),
          1e-3 * v8_flags.wasm_caching_timeout_ms);

      // Set the timestamp (will be updated by {OnFinishedUnits} if more
      // top-tier compilation finished before the delayed task is being run).
      last_top_tier_compilation_timestamp_ = base::TimeTicks::Now();
    }
  }

  if (compile_failed_.load(std::memory_order_relaxed)) {
    // *Only* trigger the "failed" event.
    triggered_events =
        base::EnumSet<CompilationEvent>({CompilationEvent::kFailedCompilation});
  }

  TriggerCallbacks(triggered_events);
}

void CompilationStateImpl::TriggerCallbacks(
    base::EnumSet<CompilationEvent> events) {
  if (events.empty()) return;

  // Don't trigger past events again.
  events -= finished_events_;
  // There can be multiple compilation chunks, thus do not store this.
  finished_events_ |= events - CompilationEvent::kFinishedCompilationChunk;

  for (auto event :
       {std::make_pair(CompilationEvent::kFailedCompilation,
                       "wasm.CompilationFailed"),
        std::make_pair(CompilationEvent::kFinishedBaselineCompilation,
                       "wasm.BaselineFinished"),
        std::make_pair(CompilationEvent::kFinishedCompilationChunk,
                       "wasm.CompilationChunkFinished")}) {
    if (!events.contains(event.first)) continue;
    DCHECK_NE(compilation_id_, kInvalidCompilationID);
    TRACE_EVENT1("v8.wasm", event.second, "id", compilation_id_);
    for (auto& callback : callbacks_) {
      callback->call(event.first);
    }
  }

  if (outstanding_baseline_units_ == 0) {
    auto new_end = std::remove_if(
        callbacks_.begin(), callbacks_.end(), [](const auto& callback) {
          return callback->release_after_final_event();
        });
    callbacks_.erase(new_end, callbacks_.end());
  }
}

void CompilationStateImpl::TriggerCachingAfterTimeout() {
  base::MutexGuard guard{&callbacks_mutex_};

  // It can happen that we reached the hard threshold while waiting for the
  // timeout to expire. In that case, {bytes_since_last_chunk_} might be zero
  // and there is nothing new to cache.
  if (bytes_since_last_chunk_ == 0) return;

  DCHECK(!last_top_tier_compilation_timestamp_.IsNull());
  base::TimeTicks caching_time =
      last_top_tier_compilation_timestamp_ +
      base::TimeDelta::FromMilliseconds(v8_flags.wasm_caching_timeout_ms);
  base::TimeDelta time_until_caching = caching_time - base::TimeTicks::Now();
  // If we are still half a millisecond or more away from the timeout,
  // reschedule the task. Otherwise, call the caching callback.
  if (time_until_caching >= base::TimeDelta::FromMicroseconds(500)) {
    int ms_remaining =
        static_cast<int>(time_until_caching.InMillisecondsRoundedUp());
    DCHECK_LE(1, ms_remaining);
    V8::GetCurrentPlatform()->CallDelayedOnWorkerThread(
        std::make_unique<TriggerCodeCachingAfterTimeoutTask>(
            native_module_weak_),
        ms_remaining);
    return;
  }

  TriggerCallbacks({CompilationEvent::kFinishedCompilationChunk});
  last_top_tier_compilation_timestamp_ = {};
  bytes_since_last_chunk_ = 0;
}

void CompilationStateImpl::OnCompilationStopped(
    WasmDetectedFeatures detected_features) {
  WasmDetectedFeatures new_detected_features =
      UpdateDetectedFeatures(detected_features);
  if (new_detected_features.empty()) return;

  // New detected features can only happen during eager compilation or if lazy
  // validation is enabled.
  // The exceptions are currently stringref and imported strings, which are only
  // detected on top-tier compilation.
  DCHECK(!v8_flags.wasm_lazy_compilation || v8_flags.wasm_lazy_validation ||
         (new_detected_features -
          WasmDetectedFeatures{{WasmDetectedFeature::stringref,
                                WasmDetectedFeature::imported_strings_utf8,
                                WasmDetectedFeature::imported_strings}})
             .empty());
  // TODO(clemensb): Fix reporting of late detected features (relevant for lazy
  // validation and for stringref).
}

WasmDetectedFeatures CompilationStateImpl::UpdateDetectedFeatures(
    WasmDetectedFeatures detected_features) {
  WasmDetectedFeatures old_features =
      detected_features_.load(std::memory_order_relaxed);
  while (!detected_features_.compare_exchange_weak(
      old_features, old_features | detected_features,
      std::memory_order_relaxed)) {
    // Retry with updated {old_features}.
  }
  return detected_features - old_features;
}

void CompilationStateImpl::PublishCompilationResults(
    std::vector<std::unique_ptr<WasmCode>> unpublished_code) {
  if (unpublished_code.empty()) return;

#if DEBUG
  // We don't compile import wrappers eagerly.
  for (const auto& code : unpublished_code) {
    int func_index = code->index();
    DCHECK_LE(native_module_->num_imported_functions(), func_index);
    DCHECK_LT(func_index, native_module_->num_functions());
  }
#endif
  PublishCode(base::VectorOf(unpublished_code));
}

std::vector<WasmCode*> CompilationStateImpl::PublishCode(
    base::Vector<std::unique_ptr<WasmCode>> code) {
  WasmCodeRefScope code_ref_scope;
  std::vector<WasmCode*> published_code =
      native_module_->PublishCode(std::move(code));
  // Defer logging code in case wire bytes were not fully received yet.
  if (native_module_->log_code() && native_module_->HasWireBytes()) {
    GetWasmEngine()->LogCode(base::VectorOf(published_code));
  }

  OnFinishedUnits(base::VectorOf(published_code));
  return published_code;
}

void CompilationStateImpl::SchedulePublishCompilationResults(
    std::vector<std::unique_ptr<WasmCode>> unpublished_code,
    CompilationTier tier) {
  PublishState& state = publish_state_[tier];
  {
    base::MutexGuard guard(&state.mutex_);
    if (state.publisher_running_) {
      // Add new code to the queue and return.
      state.publish_queue_.reserve(state.publish_queue_.size() +
                                   unpublished_code.size());
      for (auto& c : unpublished_code) {
        state.publish_queue_.emplace_back(std::move(c));
      }
      return;
    }
    state.publisher_running_ = true;
  }
  while (true) {
    PublishCompilationResults(std::move(unpublished_code));
    unpublished_code.clear();

    // Keep publishing new code that came in.
    base::MutexGuard guard(&state.mutex_);
    DCHECK(state.publisher_running_);
    if (state.publish_queue_.empty()) {
      state.publisher_running_ = false;
      return;
    }
    unpublished_code.swap(state.publish_queue_);
  }
}

size_t CompilationStateImpl::NumOutstandingCompilations(
    CompilationTier tier) const {
  return compilation_unit_queues_.GetSizeForTier(tier);
}

void CompilationStateImpl::SetError() {
  compile_cancelled_.store(true, std::memory_order_relaxed);
  if (compile_failed_.exchange(true, std::memory_order_relaxed)) {
    return;  // Already failed before.
  }

  base::MutexGuard callbacks_guard(&callbacks_mutex_);
  TriggerOutstandingCallbacks();
  callbacks_.clear();
}

void CompilationStateImpl::WaitForCompilationEvent(
    CompilationEvent expect_event) {
  switch (expect_event) {
    case CompilationEvent::kFinishedBaselineCompilation:
      if (baseline_compile_job_->IsValid()) baseline_compile_job_->Join();
      break;
    default:
      // Waiting on other CompilationEvent doesn't make sense.
      UNREACHABLE();
  }
#ifdef DEBUG
  base::EnumSet<CompilationEvent> events{expect_event,
                                         CompilationEvent::kFailedCompilation};
  base::MutexGuard guard(&callbacks_mutex_);
  DCHECK(finished_events_.contains_any(events));
#endif
}

void CompilationStateImpl::TierUpAllFunctions() {
  const WasmModule* module = native_module_->module();
  uint32_t num_wasm_functions = module->num_declared_functions;
  WasmCodeRefScope code_ref_scope;
  CompilationUnitBuilder builder(native_module_);
  for (uint32_t i = 0; i < num_wasm_functions; ++i) {
    int func_index = module->num_imported_functions + i;
    WasmCode* code = native_module_->GetCode(func_index);
    if (!code || !code->is_turbofan()) {
      builder.AddTopTierUnit(func_index, ExecutionTier::kTurbofan);
    }
  }
  builder.Commit();

  // Join the compilation, until no compilation units are left anymore.
  class DummyDelegate final : public JobDelegate {
    bool ShouldYield() override { return false; }
    bool IsJoiningThread() const override { return true; }
    void NotifyConcurrencyIncrease() override { UNIMPLEMENTED(); }
    uint8_t GetTaskId() override { return kMainTaskId; }
  };

  DummyDelegate delegate;
  ExecuteCompilationUnits(native_module_weak_, async_counters_.get(), &delegate,
                          CompilationTier::kTopTier);

  // We cannot wait for other compilation threads to finish, so we explicitly
  // compile all functions which are not yet available as TurboFan code.
  for (uint32_t i = 0; i < num_wasm_functions; ++i) {
    uint32_t func_index = module->num_imported_functions + i;
    WasmCode* code = native_module_->GetCode(func_index);
    if (!code || !code->is_turbofan()) {
      wasm::GetWasmEngine()->CompileFunction(async_counters_.get(),
                                             native_module_, func_index,
                                             wasm::ExecutionTier::kTurbofan);
    }
  }
}

WasmCode* CompileImportWrapperForTest(Isolate* isolate,
                                      NativeModule* native_module,
                                      ImportCallKind kind,
                                      const CanonicalSig* sig,
                                      CanonicalTypeIndex type_index,
                                      int expected_arity, Suspend suspend) {
  bool source_positions = is_asmjs_module(native_module->module());
  if (v8_flags.wasm_jitless) {
    WasmImportWrapperCache::ModificationScope cache_scope(
        GetWasmImportWrapperCache());
    WasmImportWrapperCache::CacheKey key(kind, type_index, expected_arity,
                                         suspend);
    DCHECK_NULL(cache_scope[key]);
    return nullptr;
  }

  return GetWasmImportWrapperCache()->CompileWasmImportCallWrapper(
      isolate, kind, sig, type_index, source_positions, expected_arity,
      suspend);
}

}  // namespace v8::internal::wasm

#undef TRACE_COMPILE
#undef TRACE_STREAMING
#undef TRACE_LAZY

"""


```