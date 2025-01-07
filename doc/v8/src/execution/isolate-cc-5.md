Response:
Let's break down the thought process for analyzing this C++ code snippet from `v8/src/execution/isolate.cc`.

**1. Understanding the Goal:**

The request asks for a functional overview of the provided code, specifically focusing on its relationship to V8's Isolate concept. It also mentions Torque (irrelevant here), JavaScript connections, code logic (input/output), common programming errors, and finally a summary as part 6 of 9.

**2. Initial Scan and Keyword Recognition:**

Immediately, words like `Isolate`, `OFFSET_OF`, `CHECK_EQ`, `static_assert`, `IsolateData`, `kIsolate...Offset`, `kCacheLineSize`, `RoundDown`, `ClearSerializerData`, `UpdateLogObjectRelocation`, `Deinit`, etc., jump out. These are strong indicators of the code's purpose.

* `Isolate`: This is the central concept. The file name confirms this.
* `OFFSET_OF`:  This macro is crucial for understanding memory layout. It calculates the offset of a member within a struct or class.
* `CHECK_EQ`, `static_assert`: These are assertion mechanisms, used to verify assumptions at runtime and compile time, respectively. They are used here to ensure the calculated offsets match predefined constants.
* `IsolateData`:  Likely a nested structure within `Isolate` holding per-isolate data.
* `kIsolate...Offset`: These constants suggest a defined memory layout for the `Isolate` object.
* `kCacheLineSize`, `RoundDown`: These hints relate to performance optimization, specifically ensuring data used together resides within the same CPU cache line.
* `ClearSerializerData`, `UpdateLogObjectRelocation`, `Deinit`: These are clearly functions related to the Isolate's lifecycle – cleanup, settings adjustments, and shutdown.

**3. Deduction of Primary Functionality (Based on First Block):**

The first large block of `CHECK_EQ` and `static_assert` statements is clearly verifying the memory layout of the `Isolate` class and its `isolate_data_` member. It ensures that specific members are at the expected offsets. The `static_assert`s about `kStackGuardSize`, `kBuiltinTier0TableSize`, and `kBuiltinTier0EntryTableSize` confirm the code is also checking the sizes of related data structures.

The cache line assertions further refine this understanding. They show that V8 developers are carefully arranging members of `IsolateData` to improve performance by minimizing cache misses during critical operations like CEntry/CallApiCallback.

**4. Analysis of Subsequent Functions:**

* **`ClearSerializerData()`:**  This suggests functionality related to serialization/deserialization of the Isolate state. The deletion of `external_reference_map_` confirms this.
* **`UpdateLogObjectRelocation()`:** This function is about updating a boolean flag based on various logging and profiling settings. This flag likely controls whether object relocation needs to be logged, potentially for debugging or performance analysis.
* **`Deinit()`:** This is the most complex function. The name clearly indicates it's responsible for the tear-down of the Isolate. Scanning through the code reveals a systematic process of:
    * Unregistering from Perfetto (profiling).
    * Detaching from shared heaps.
    * Tearing down the heap.
    * Disabling garbage collection during tear-down.
    * Notifying various subsystems about disposal (Wasm, metrics, etc.).
    * Stopping background tasks and compilers.
    * Detaching from shared resources.
    * Releasing shared pointers.
    * Tearing down core components (builtins, bootstrapper, etc.).
    * Freeing memory.

**5. Addressing Specific Requirements:**

* **Torque:** The code doesn't end in `.tq`, so it's not Torque.
* **JavaScript Relationship:** The code deals with the internal structure and lifecycle of the V8 Isolate, which *directly* enables JavaScript execution. The interaction is not direct JavaScript code but rather the underlying C++ infrastructure. The thought is to provide an example of how the Isolate is *used* in a JavaScript context, hence the `v8::Isolate::New()` example.
* **Code Logic Reasoning (Input/Output):** The offset checks are deterministic. Given the definition of the `Isolate` class, the `OFFSET_OF` macro will always produce the same results. The assertions either pass or fail. The `UpdateLogObjectRelocation` function takes no input and changes an internal boolean based on global flags and the state of other components.
* **Common Programming Errors:**  The offset assertions protect against a common error: changes to the `Isolate` class structure without updating the internal offset constants. This would lead to crashes or incorrect behavior.
* **归纳功能 (Summarization):** The goal is to synthesize the findings into a concise summary, highlighting the core responsibilities of the code.

**6. Structuring the Output:**

The final step involves organizing the gathered information into the requested format, using clear headings and examples. This includes:

* Listing the functionality clearly.
* Explaining the offset checks and their purpose.
* Providing a JavaScript example (even though the C++ doesn't directly *contain* JavaScript).
* Giving concrete input/output for the logical deductions.
* Illustrating the potential programming errors.
* Crafting a concise summary for part 6.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on individual `CHECK_EQ` lines. Realizing the pattern of memory layout verification is key.
* Recognizing the performance implications of the cache line assertions adds a deeper understanding.
*  While `Deinit()` is long, identifying the major steps (heap tear-down, thread management, component disposal, memory freeing) provides a better high-level view.
*  The connection to JavaScript needs to be articulated correctly – it's the underlying engine, not directly manipulatable JavaScript.

By following this thought process, combining code analysis with an understanding of the V8 architecture, and addressing each part of the request, a comprehensive and accurate answer can be generated.
这是一个V8源代码文件，路径为 `v8/src/execution/isolate.cc`。 从文件扩展名 `.cc` 可以看出，这是一个 C++ 源代码文件。

**功能列举：**

这个文件的主要功能是定义和实现 `v8::Isolate` 类。`Isolate` 是 V8 引擎中最重要的概念之一，它代表了一个独立的 JavaScript 执行环境。 我们可以从代码中推断出以下功能：

1. **Isolate 结构定义和内存布局验证:** 代码中大量的 `CHECK_EQ` 和 `static_assert` 用于严格验证 `Isolate` 及其内部数据结构 `IsolateData` 的内存布局。这确保了 V8 内部访问这些数据成员时使用的是正确的偏移量。例如，`CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.stack_guard_)), Internals::kIsolateStackGuardOffset);` 验证了 `Isolate` 对象中 `isolate_data_.stack_guard_` 成员的偏移量是否与预定义的常量 `Internals::kIsolateStackGuardOffset` 相符。这对于跨平台和版本维护至关重要。

2. **Isolate 的初始化和清理:**  `Deinit()` 函数负责 `Isolate` 对象的清理工作，包括释放各种资源，例如堆内存、后台线程、编译器相关的对象、日志文件等。 这确保了在 `Isolate` 不再使用时，系统资源能够被正确回收。

3. **序列化数据的清理:** `ClearSerializerData()` 函数用于清理与序列化相关的数据，例如 `external_reference_map_`。这在 `Isolate` 的状态需要被序列化或反序列化时使用。

4. **日志对象重定位更新:** `UpdateLogObjectRelocation()` 函数根据不同的配置选项（例如是否开启可预测模式、代码创建日志、堆分析等）更新 `log_object_relocation_` 标志。这个标志可能用于控制是否需要记录对象的重定位信息，用于调试或性能分析。

5. **处理异常传播回调:** `NotifyExceptionPropagationCallback()`, `ReportExceptionFunctionCallback()`, `ReportExceptionPropertyCallback()`, 和 `SetExceptionPropagationCallback()` 这些函数用于处理和报告 JavaScript 异常如何传播到外部的 C++ 代码中。这允许嵌入器（例如 Node.js 或 Chrome）捕获和处理 V8 引擎中发生的 JavaScript 异常。

6. **计数器初始化:** `InitializeCounters()` 和 `InitializeLoggingAndCounters()` 负责初始化与性能监控和日志记录相关的计数器。

7. **嵌入式 Blob 的处理:**  `InitializeDefaultEmbeddedBlob()`, `CreateAndSetEmbeddedBlob()`, `MaybeRemapEmbeddedBuiltinsIntoCodeRange()` 等函数涉及 V8 引擎中预编译代码（称为 "embedded blob"）的处理。这些 blob 包含了内置的 JavaScript 函数和对象，可以加快启动速度。代码负责加载、创建和管理这些 blob。

8. **短内置调用优化:** `InitializeIsShortBuiltinCallsEnabled()` 和 `MaybeRemapEmbeddedBuiltinsIntoCodeRange()` 涉及到一种优化技术，即如果条件允许（例如内存充足），将内置函数的代码映射到代码段的附近，从而可以使用更短、更快的调用指令。

9. **线程局部数据的管理:** `SetIsolateThreadLocals()` 用于设置与特定线程相关的 `Isolate` 数据。

10. **析构函数:** `~Isolate()` 是 `Isolate` 类的析构函数，负责在对象销毁时进行必要的清理工作，例如删除各种缓存、句柄作用域实现器等。

11. **初始化线程局部变量:** `InitializeThreadLocal()` 用于初始化与当前线程相关的 `Isolate` 变量。

12. **设置外部 TryCatch 的终止状态:** `SetTerminationOnExternalTryCatch()` 用于当 JavaScript 异常被外部的 C++ `TryCatch` 捕获时，设置终止执行的状态。

13. **将异常传播到外部 TryCatch:** `PropagateExceptionToExternalTryCatch()`  负责将 V8 引擎内部的 JavaScript 异常信息传递给外部的 C++ `TryCatch` 结构。

**关于 Torque：**

由于文件扩展名是 `.cc`，而不是 `.tq`，因此 `v8/src/execution/isolate.cc` **不是**一个 V8 Torque 源代码文件。 Torque 文件通常用于定义内置函数的实现。

**与 JavaScript 的关系及示例：**

`v8::Isolate` 是 V8 执行 JavaScript 代码的核心。 你创建的每一个独立的 JavaScript 执行环境都对应着一个 `Isolate` 实例。

**JavaScript 示例：**

```javascript
// Node.js 环境
const v8 = require('v8');

// 创建一个新的 Isolate (在 Node.js 中通常由运行时环境管理)
// const isolate = new v8.Isolate(); // 你不能直接这样创建，通常由运行时环境管理

// 在 Isolate 中执行 JavaScript 代码
// isolate.runInContext(() => {
//   console.log('Hello from the Isolate!');
// });

// 获取当前 Isolate 的堆统计信息
const heapStatistics = v8.getHeapStatistics();
console.log(heapStatistics.total_available_size);

// 创建一个沙箱环境 (Context) 在 Isolate 中运行代码
// const context = v8.Context.New(isolate);
// const result = context.eval('2 + 2');
// console.log(result);
```

在浏览器环境中，每个 tab 页或 web worker 通常都有自己的 `Isolate` 实例。虽然你不能直接操作 `v8::Isolate` 对象，但你的 JavaScript 代码的执行完全依赖于它。

**代码逻辑推理（假设输入与输出）：**

考虑 `UpdateLogObjectRelocation()` 函数：

**假设输入：**

* `v8_flags.verify_predictable` 为 `true`
* `IsLoggingCodeCreation()` 返回 `false`
* `v8_file_logger()->is_logging()` 返回 `false`
* `heap_profiler()` 返回一个非空指针，且 `heap_profiler()->is_tracking_object_moves()` 返回 `false`
* `heap()->has_heap_object_allocation_tracker()` 返回 `false`

**预期输出：**

`log_object_relocation_` 将被设置为 `true`，因为 `v8_flags.verify_predictable` 为真。

**假设输入：**

* `v8_flags.verify_predictable` 为 `false`
* `IsLoggingCodeCreation()` 返回 `true`

**预期输出：**

`log_object_relocation_` 将被设置为 `true`。

**涉及用户常见的编程错误：**

虽然用户无法直接修改 `v8/src/execution/isolate.cc` 的代码，但了解 `Isolate` 的生命周期和资源管理对于嵌入 V8 的开发者至关重要。

**常见的错误包括：**

1. **资源泄漏：** 如果嵌入器没有正确地清理 `Isolate` 对象（通过调用 `Platform::TearDownIsolate` 或类似的方法），可能会导致内存泄漏和其他资源泄漏。

2. **在错误的线程上访问 Isolate：**  `Isolate` 对象通常不是线程安全的，必须在创建它的线程上进行主要操作。在不同的线程上直接访问 `Isolate` 的成员可能会导致崩溃或其他不可预测的行为。V8 提供了机制（例如 `Locker` 和 `Unlocker`）来安全地在不同线程上与 `Isolate` 交互。

3. **假设 `Isolate` 是全局唯一的：**  在多线程或多进程环境中，可能会存在多个 `Isolate` 实例。错误地假设只有一个 `Isolate` 可能会导致数据竞争和错误。

4. **不理解 `Context` 的作用：** `Isolate` 提供了一个独立的执行环境，而 `Context` 则提供了在 `Isolate` 中运行 JavaScript 代码的沙箱。 混淆这两个概念可能导致代码在预期的作用域之外执行。

**第 6 部分的功能归纳：**

作为第 6 部分，`v8/src/execution/isolate.cc` 的主要功能是 **定义和实现了 V8 引擎中核心的 `v8::Isolate` 类，负责创建、管理和清理独立的 JavaScript 执行环境。**  这包括了 `Isolate` 的内存布局定义、生命周期管理（初始化和清理）、资源管理、与外部 C++ 代码的交互（例如异常传播）、性能优化（如短内置调用）以及与嵌入式代码 blob 的处理。  它确保了 V8 能够提供隔离且高效的 JavaScript 执行环境。

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共9部分，请归纳一下它的功能

"""
:kIsolateCageBaseOffset);
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.long_task_stats_counter_)),
           Internals::kIsolateLongTaskStatsCounterOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.stack_guard_)),
           Internals::kIsolateStackGuardOffset);

  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.thread_local_top_)),
      Internals::kIsolateThreadLocalTopOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.handle_scope_data_)),
      Internals::kIsolateHandleScopeDataOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.embedder_data_)),
           Internals::kIsolateEmbedderDataOffset);
#ifdef V8_COMPRESS_POINTERS
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.external_pointer_table_)),
           Internals::kIsolateExternalPointerTableOffset);

  CHECK_EQ(static_cast<int>(OFFSET_OF(
               Isolate, isolate_data_.shared_external_pointer_table_)),
           Internals::kIsolateSharedExternalPointerTableAddressOffset);
#endif
#ifdef V8_ENABLE_SANDBOX
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.trusted_cage_base_)),
      Internals::kIsolateTrustedCageBaseOffset);

  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.trusted_pointer_table_)),
           Internals::kIsolateTrustedPointerTableOffset);

  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.shared_trusted_pointer_table_)),
           Internals::kIsolateSharedTrustedPointerTableAddressOffset);
#endif
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.api_callback_thunk_argument_)),
           Internals::kIsolateApiCallbackThunkArgumentOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(
               Isolate, isolate_data_.continuation_preserved_embedder_data_)),
           Internals::kContinuationPreservedEmbedderDataOffset);

  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.roots_table_)),
           Internals::kIsolateRootsOffset);

  CHECK(IsAligned(reinterpret_cast<Address>(&isolate_data_),
                  kIsolateDataAlignment));

  static_assert(Internals::kStackGuardSize == sizeof(StackGuard));
  static_assert(Internals::kBuiltinTier0TableSize ==
                Builtins::kBuiltinTier0Count * kSystemPointerSize);
  static_assert(Internals::kBuiltinTier0EntryTableSize ==
                Builtins::kBuiltinTier0Count * kSystemPointerSize);

  // Ensure that certain hot IsolateData fields fall into the same CPU cache
  // line.
  constexpr size_t kCacheLineSize = 64;
  static_assert(OFFSET_OF(Isolate, isolate_data_) == 0);

  // Fields written on every CEntry/CallApiCallback/CallApiGetter call.
  // See MacroAssembler::EnterExitFrame/LeaveExitFrame.
  constexpr size_t kCEntryFPCacheLine = RoundDown<kCacheLineSize>(
      OFFSET_OF(IsolateData, thread_local_top_.c_entry_fp_));
  static_assert(kCEntryFPCacheLine ==
                RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, thread_local_top_.c_function_)));
  static_assert(kCEntryFPCacheLine ==
                RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, thread_local_top_.context_)));
  static_assert(
      kCEntryFPCacheLine ==
      RoundDown<kCacheLineSize>(OFFSET_OF(
          IsolateData, thread_local_top_.topmost_script_having_context_)));
  static_assert(kCEntryFPCacheLine ==
                RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, thread_local_top_.last_api_entry_)));

  // Fields written on every MacroAssembler::CallCFunction call.
  static_assert(RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, fast_c_call_caller_fp_)) ==
                RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, fast_c_call_caller_pc_)));

  // LinearAllocationArea objects must not cross cache line boundary.
  static_assert(
      RoundDown<kCacheLineSize>(OFFSET_OF(IsolateData, new_allocation_info_)) ==
      RoundDown<kCacheLineSize>(OFFSET_OF(IsolateData, new_allocation_info_) +
                                sizeof(LinearAllocationArea) - 1));
  static_assert(
      RoundDown<kCacheLineSize>(OFFSET_OF(IsolateData, old_allocation_info_)) ==
      RoundDown<kCacheLineSize>(OFFSET_OF(IsolateData, old_allocation_info_) +
                                sizeof(LinearAllocationArea) - 1));
}

void Isolate::ClearSerializerData() {
  delete external_reference_map_;
  external_reference_map_ = nullptr;
}

// When profiling status changes, call this function to update the single bool
// cache.
void Isolate::UpdateLogObjectRelocation() {
  log_object_relocation_ = v8_flags.verify_predictable ||
                           IsLoggingCodeCreation() ||
                           v8_file_logger()->is_logging() ||
                           (heap_profiler() != nullptr &&
                            heap_profiler()->is_tracking_object_moves()) ||
                           heap()->has_heap_object_allocation_tracker();
}

void Isolate::Deinit() {
  TRACE_ISOLATE(deinit);

#if defined(V8_USE_PERFETTO)
  PerfettoLogger::UnregisterIsolate(this);
#endif  // defined(V8_USE_PERFETTO)

  // All client isolates should already be detached when the shared heap isolate
  // tears down.
  if (is_shared_space_isolate()) {
    global_safepoint()->AssertNoClientsOnTearDown();
  }

  if (has_shared_space() && !is_shared_space_isolate()) {
    IgnoreLocalGCRequests ignore_gc_requests(heap());
    main_thread_local_heap()->ExecuteMainThreadWhileParked([this]() {
      shared_space_isolate()->global_safepoint()->clients_mutex_.Lock();
    });
  }

  // We start with the heap tear down so that releasing managed objects does
  // not cause a GC.
  heap_.StartTearDown();

  DisallowGarbageCollection no_gc;
  IgnoreLocalGCRequests ignore_gc_requests(heap());

#if V8_ENABLE_WEBASSEMBLY && V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    wasm::WasmInterpreter::NotifyIsolateDisposal(this);
  } else if (v8_flags.wasm_enable_exec_time_histograms &&
             v8_flags.slow_histograms) {
    wasm_execution_timer_->Terminate();
  }
#endif  // V8_ENABLE_WEBASSEMBLY && V8_ENABLE_DRUMBRAKE

  tracing_cpu_profiler_.reset();
  if (v8_flags.stress_sampling_allocation_profiler > 0) {
    heap_profiler()->StopSamplingHeapProfiler();
  }

  metrics_recorder_->NotifyIsolateDisposal();
  recorder_context_id_map_.clear();

  FutexEmulation::IsolateDeinit(this);
  if (v8_flags.harmony_struct) {
    JSSynchronizationPrimitive::IsolateDeinit(this);
  } else {
    DCHECK(async_waiter_queue_nodes_.empty());
  }

  debug()->Unload();

#if V8_ENABLE_WEBASSEMBLY
  wasm::GetWasmEngine()->DeleteCompileJobsOnIsolate(this);

  BackingStore::RemoveSharedWasmMemoryObjects(this);
#endif  // V8_ENABLE_WEBASSEMBLY

  if (concurrent_recompilation_enabled()) {
    optimizing_compile_dispatcher_->Stop();
    delete optimizing_compile_dispatcher_;
    optimizing_compile_dispatcher_ = nullptr;
  }

  if (v8_flags.print_deopt_stress) {
    PrintF(stdout, "=== Stress deopt counter: %u\n", stress_deopt_count_);
  }

  // We must stop the logger before we tear down other components.
  sampler::Sampler* sampler = v8_file_logger_->sampler();
  if (sampler && sampler->IsActive()) sampler->Stop();
  v8_file_logger_->StopProfilerThread();

  FreeThreadResources();

  // Stop concurrent tasks before destroying resources since they might still
  // use those.
  cancelable_task_manager()->CancelAndWait();

  // Cancel all compiler tasks.
#ifdef V8_ENABLE_SPARKPLUG
  delete baseline_batch_compiler_;
  baseline_batch_compiler_ = nullptr;
#endif  // V8_ENABLE_SPARKPLUG

#ifdef V8_ENABLE_MAGLEV
  delete maglev_concurrent_dispatcher_;
  maglev_concurrent_dispatcher_ = nullptr;
#endif  // V8_ENABLE_MAGLEV

  if (lazy_compile_dispatcher_) {
    lazy_compile_dispatcher_->AbortAll();
    lazy_compile_dispatcher_.reset();
  }

  // At this point there are no more background threads left in this isolate.
  heap_.safepoint()->AssertMainThreadIsOnlyThread();

  // Tear down data that requires the shared heap before detaching.
  heap_.TearDownWithSharedHeap();
  DumpAndResetBuiltinsProfileData();

  // Detach from the shared heap isolate and then unlock the mutex.
  if (has_shared_space() && !is_shared_space_isolate()) {
    GlobalSafepoint* global_safepoint =
        this->shared_space_isolate()->global_safepoint();
    global_safepoint->RemoveClient(this);
    global_safepoint->clients_mutex_.Unlock();
  }

  shared_space_isolate_.reset();

  // Since there are no other threads left, we can lock this mutex without any
  // ceremony. This signals to the tear down code that we are in a safepoint.
  base::RecursiveMutexGuard safepoint(&heap_.safepoint()->local_heaps_mutex_);

  ReleaseSharedPtrs();

  builtins_.TearDown();
  bootstrapper_->TearDown();

  if (tiering_manager_ != nullptr) {
    delete tiering_manager_;
    tiering_manager_ = nullptr;
  }

  delete heap_profiler_;
  heap_profiler_ = nullptr;

#if USE_SIMULATOR
  delete simulator_data_;
  simulator_data_ = nullptr;
#endif

  // After all concurrent tasks are stopped, we know for sure that stats aren't
  // updated anymore.
  DumpAndResetStats();

  heap_.TearDown();
  ReadOnlyHeap::TearDown(this);

  delete inner_pointer_to_code_cache_;
  inner_pointer_to_code_cache_ = nullptr;

  main_thread_local_isolate_.reset();

  FILE* logfile = v8_file_logger_->TearDownAndGetLogFile();
  if (logfile != nullptr) base::Fclose(logfile);

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
  if (v8_flags.enable_etw_stack_walking) {
    ETWJITInterface::RemoveIsolate(this);
  }
#endif  // defined(V8_OS_WIN)

#if V8_ENABLE_WEBASSEMBLY
  wasm::GetWasmEngine()->RemoveIsolate(this);

  delete wasm_code_look_up_cache_;
  wasm_code_look_up_cache_ = nullptr;
#endif  // V8_ENABLE_WEBASSEMBLY

  TearDownEmbeddedBlob();

  delete interpreter_;
  interpreter_ = nullptr;

  delete ast_string_constants_;
  ast_string_constants_ = nullptr;

  delete logger_;
  logger_ = nullptr;

  delete root_index_map_;
  root_index_map_ = nullptr;

  delete compiler_zone_;
  compiler_zone_ = nullptr;
  compiler_cache_ = nullptr;

  SetCodePages(nullptr);

  ClearSerializerData();

  if (OwnsStringTables()) {
    string_forwarding_table()->TearDown();
  } else {
    DCHECK_NULL(string_table_.get());
    DCHECK_NULL(string_forwarding_table_.get());
  }

  if (!is_shared_space_isolate()) {
    DCHECK_NULL(shared_struct_type_registry_.get());
  }

#ifdef V8_COMPRESS_POINTERS
  external_pointer_table().TearDownSpace(
      heap()->young_external_pointer_space());
  external_pointer_table().TearDownSpace(heap()->old_external_pointer_space());
  external_pointer_table().DetachSpaceFromReadOnlySegment(
      heap()->read_only_external_pointer_space());
  external_pointer_table().TearDownSpace(
      heap()->read_only_external_pointer_space());
  external_pointer_table().TearDown();
  if (owns_shareable_data()) {
    shared_external_pointer_table().TearDownSpace(
        shared_external_pointer_space());
    shared_external_pointer_table().TearDown();
    delete isolate_data_.shared_external_pointer_table_;
    isolate_data_.shared_external_pointer_table_ = nullptr;
    delete shared_external_pointer_space_;
    shared_external_pointer_space_ = nullptr;
  }
  cpp_heap_pointer_table().TearDownSpace(heap()->cpp_heap_pointer_space());
  cpp_heap_pointer_table().TearDown();
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  trusted_pointer_table().TearDownSpace(heap()->trusted_pointer_space());
  trusted_pointer_table().TearDown();
  if (owns_shareable_data()) {
    shared_trusted_pointer_table().TearDownSpace(
        shared_trusted_pointer_space());
    shared_trusted_pointer_table().TearDown();
    delete isolate_data_.shared_trusted_pointer_table_;
    isolate_data_.shared_trusted_pointer_table_ = nullptr;
    delete shared_trusted_pointer_space_;
    shared_trusted_pointer_space_ = nullptr;
  }

  IsolateGroup::current()->code_pointer_table()->TearDownSpace(
      heap()->code_pointer_space());
#endif  // V8_ENABLE_SANDBOX
#ifdef V8_ENABLE_LEAPTIERING
  GetProcessWideJSDispatchTable()->TearDownSpace(
      heap()->js_dispatch_table_space());
#endif  // V8_ENABLE_LEAPTIERING

  {
    base::MutexGuard lock_guard(&thread_data_table_mutex_);
    thread_data_table_.RemoveAllThreads();
  }
}

void Isolate::SetIsolateThreadLocals(Isolate* isolate,
                                     PerIsolateThreadData* data) {
  Isolate::SetCurrent(isolate);
  g_current_per_isolate_thread_data_ = data;

#ifdef V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES
  V8HeapCompressionScheme::InitBase(isolate ? isolate->cage_base()
                                            : kNullAddress);
  IsolateGroup::set_current(isolate ? isolate->isolate_group() : nullptr);
#ifdef V8_EXTERNAL_CODE_SPACE
  ExternalCodeCompressionScheme::InitBase(isolate ? isolate->code_cage_base()
                                                  : kNullAddress);
#endif
#endif  // V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES

  if (isolate && isolate->main_thread_local_isolate()) {
    WriteBarrier::SetForThread(
        isolate->main_thread_local_heap()->marking_barrier());
  } else {
    WriteBarrier::SetForThread(nullptr);
  }
}

Isolate::~Isolate() {
  TRACE_ISOLATE(destructor);
  DCHECK_NULL(current_deoptimizer_);

  // The entry stack must be empty when we get here.
  DCHECK(entry_stack_ == nullptr ||
         entry_stack_.load()->previous_item == nullptr);

  delete entry_stack_;
  entry_stack_ = nullptr;

  delete date_cache_;
  date_cache_ = nullptr;

  delete regexp_stack_;
  regexp_stack_ = nullptr;

  delete descriptor_lookup_cache_;
  descriptor_lookup_cache_ = nullptr;

  delete load_stub_cache_;
  load_stub_cache_ = nullptr;
  delete store_stub_cache_;
  store_stub_cache_ = nullptr;
  delete define_own_stub_cache_;
  define_own_stub_cache_ = nullptr;

  delete materialized_object_store_;
  materialized_object_store_ = nullptr;

  delete v8_file_logger_;
  v8_file_logger_ = nullptr;

  delete handle_scope_implementer_;
  handle_scope_implementer_ = nullptr;

  delete code_tracer();
  set_code_tracer(nullptr);

  delete compilation_cache_;
  compilation_cache_ = nullptr;
  delete bootstrapper_;
  bootstrapper_ = nullptr;

  delete thread_manager_;
  thread_manager_ = nullptr;

  bigint_processor_->Destroy();

  delete global_handles_;
  global_handles_ = nullptr;
  delete eternal_handles_;
  eternal_handles_ = nullptr;

#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmEngine::FreeAllOrphanedGlobalHandles(wasm_orphaned_handle_);
#endif

  delete string_stream_debug_object_cache_;
  string_stream_debug_object_cache_ = nullptr;

  delete random_number_generator_;
  random_number_generator_ = nullptr;

  delete fuzzer_rng_;
  fuzzer_rng_ = nullptr;

  delete debug_;
  debug_ = nullptr;

  delete cancelable_task_manager_;
  cancelable_task_manager_ = nullptr;

  delete allocator_;
  allocator_ = nullptr;

  // Assert that |default_microtask_queue_| is the last MicrotaskQueue instance.
  DCHECK_IMPLIES(default_microtask_queue_,
                 default_microtask_queue_ == default_microtask_queue_->next());
  delete default_microtask_queue_;
  default_microtask_queue_ = nullptr;

#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmCodePointerTable* wasm_code_pointer_table =
      wasm::GetProcessWideWasmCodePointerTable();
  for (size_t i = 0; i < Builtins::kNumWasmIndirectlyCallableBuiltins; i++) {
    wasm_code_pointer_table->FreeEntry(wasm_builtin_code_handles_[i]);
  }
#endif

  // isolate_group_ released in caller, to ensure that all member destructors
  // run before potentially unmapping the isolate's VirtualMemoryArea.
}

void Isolate::InitializeThreadLocal() {
  thread_local_top()->Initialize(this);
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  i::PtrComprCageAccessScope ptr_compr_cage_access_scope(this);
#endif  // DEBUG
  clear_exception();
  clear_pending_message();
}

void Isolate::SetTerminationOnExternalTryCatch() {
  DCHECK_IMPLIES(v8_flags.strict_termination_checks,
                 is_execution_terminating());
  if (try_catch_handler() == nullptr) return;
  try_catch_handler()->can_continue_ = false;
  try_catch_handler()->exception_ = reinterpret_cast<void*>(
      ReadOnlyRoots(heap()).termination_exception().ptr());
}

bool Isolate::PropagateExceptionToExternalTryCatch(
    ExceptionHandlerType top_handler) {
  Tagged<Object> exception = this->exception();

  if (top_handler == ExceptionHandlerType::kJavaScriptHandler) return false;
  if (top_handler == ExceptionHandlerType::kNone) return true;

  DCHECK_EQ(ExceptionHandlerType::kExternalTryCatch, top_handler);
  if (!is_catchable_by_javascript(exception)) {
    SetTerminationOnExternalTryCatch();
  } else {
    v8::TryCatch* handler = try_catch_handler();
    DCHECK(IsJSMessageObject(pending_message()) ||
           IsTheHole(pending_message(), this));
    handler->can_continue_ = true;
    handler->exception_ = reinterpret_cast<void*>(exception.ptr());
    // Propagate to the external try-catch only if we got an actual message.
    if (!has_pending_message()) return true;
    handler->message_obj_ = reinterpret_cast<void*>(pending_message().ptr());
  }
  return true;
}

namespace {

inline Tagged<FunctionTemplateInfo> GetTargetFunctionTemplateInfo(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  Tagged<Object> target = FunctionCallbackArguments::GetTarget(info);
  if (IsFunctionTemplateInfo(target)) {
    return Cast<FunctionTemplateInfo>(target);
  }
  CHECK(Is<JSFunction>(target));
  Tagged<SharedFunctionInfo> shared_info = Cast<JSFunction>(target)->shared();
  return shared_info->api_func_data();
}

}  // namespace

void Isolate::NotifyExceptionPropagationCallback() {
  DCHECK_NOT_NULL(exception_propagation_callback_);

  // Try to figure out whether the exception was thrown directly from an
  // Api callback and if it's the case then call the
  // |exception_propagation_callback_| with relevant data.

  ExternalCallbackScope* ext_callback_scope = external_callback_scope();
  StackFrameIterator it(this);

  if (it.done() && !ext_callback_scope) {
    // The exception was thrown directly by embedder code without crossing
    // "C++ -> JS" or "C++ -> Api callback" boundary.
    return;
  }
  if (it.done() ||
      (ext_callback_scope &&
       ext_callback_scope->JSStackComparableAddress() < it.frame()->fp())) {
    // There were no crossings of "C++ -> JS" boundary at all or they happened
    // earlier than the last crossing of the  "C++ -> Api callback" boundary.
    // In this case all the data about Api callback is available in the
    // |ext_callback_scope| object.
    DCHECK_NOT_NULL(ext_callback_scope);
    v8::ExceptionContext kind = ext_callback_scope->exception_context();
    switch (kind) {
      case v8::ExceptionContext::kConstructor:
      case v8::ExceptionContext::kOperation: {
        DCHECK_NOT_NULL(ext_callback_scope->callback_info());
        auto callback_info =
            reinterpret_cast<const v8::FunctionCallbackInfo<v8::Value>*>(
                ext_callback_scope->callback_info());

        DirectHandle<JSReceiver> receiver =
            Utils::OpenDirectHandle(*callback_info->This());
        DirectHandle<FunctionTemplateInfo> function_template_info(
            GetTargetFunctionTemplateInfo(*callback_info), this);
        ReportExceptionFunctionCallback(receiver, function_template_info, kind);
        return;
      }
      case v8::ExceptionContext::kAttributeGet:
      case v8::ExceptionContext::kAttributeSet:
      case v8::ExceptionContext::kIndexedQuery:
      case v8::ExceptionContext::kIndexedGetter:
      case v8::ExceptionContext::kIndexedDescriptor:
      case v8::ExceptionContext::kIndexedSetter:
      case v8::ExceptionContext::kIndexedDefiner:
      case v8::ExceptionContext::kIndexedDeleter:
      case v8::ExceptionContext::kNamedQuery:
      case v8::ExceptionContext::kNamedGetter:
      case v8::ExceptionContext::kNamedDescriptor:
      case v8::ExceptionContext::kNamedSetter:
      case v8::ExceptionContext::kNamedDefiner:
      case v8::ExceptionContext::kNamedDeleter:
      case v8::ExceptionContext::kNamedEnumerator: {
        DCHECK_NOT_NULL(ext_callback_scope->callback_info());
        auto callback_info =
            reinterpret_cast<const v8::PropertyCallbackInfo<v8::Value>*>(
                ext_callback_scope->callback_info());

        // Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
        // TODO(https://crbug.com/333672197): remove.
        START_ALLOW_USE_DEPRECATED()

        Handle<Object> holder = Utils::OpenHandle(*callback_info->Holder());
        Handle<Object> maybe_name =
            PropertyCallbackArguments::GetPropertyKeyHandle(*callback_info);
        Handle<Name> name =
            IsSmi(*maybe_name)
                ? factory()->SizeToString(
                      PropertyCallbackArguments::GetPropertyIndex(
                          *callback_info))
                : Cast<Name>(maybe_name);
        DCHECK(IsJSReceiver(*holder));

        // Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
        // TODO(https://crbug.com/333672197): remove.
        END_ALLOW_USE_DEPRECATED()

        // Currently we call only ApiGetters from JS code.
        ReportExceptionPropertyCallback(Cast<JSReceiver>(holder), name, kind);
        return;
      }

      case v8::ExceptionContext::kUnknown:
        DCHECK_WITH_MSG(kind != v8::ExceptionContext::kUnknown,
                        "ExternalCallbackScope should not use "
                        "v8::ExceptionContext::kUnknown exception context");
        return;
    }
    UNREACHABLE();
  }

  // There were no crossings of "C++ -> Api callback" bondary or they
  // happened before crossing the "C++ -> JS" boundary.
  // In this case all the data about Api callback is available in the
  // topmost "JS -> Api callback" frame (ApiCallbackExitFrame or
  // ApiAccessorExitFrame).
  DCHECK(!it.done());
  StackFrame::Type frame_type = it.frame()->type();
  switch (frame_type) {
    case StackFrame::API_CALLBACK_EXIT: {
      ApiCallbackExitFrame* frame = ApiCallbackExitFrame::cast(it.frame());
      DirectHandle<JSReceiver> receiver(Cast<JSReceiver>(frame->receiver()),
                                        this);
      DirectHandle<FunctionTemplateInfo> function_template_info =
          frame->GetFunctionTemplateInfo();

      v8::ExceptionContext callback_kind =
          frame->IsConstructor() ? v8::ExceptionContext::kConstructor
                                 : v8::ExceptionContext::kOperation;
      ReportExceptionFunctionCallback(receiver, function_template_info,
                                      callback_kind);
      return;
    }
    case StackFrame::API_ACCESSOR_EXIT: {
      ApiAccessorExitFrame* frame = ApiAccessorExitFrame::cast(it.frame());

      Handle<Object> holder(frame->holder(), this);
      Handle<Name> name(frame->property_name(), this);
      DCHECK(IsJSReceiver(*holder));

      // Currently we call only ApiGetters from JS code.
      ReportExceptionPropertyCallback(Cast<JSReceiver>(holder), name,
                                      v8::ExceptionContext::kAttributeGet);
      return;
    }
    case StackFrame::TURBOFAN_JS:
      // This must be a fast Api call.
      CHECK(it.frame()->InFastCCall());
      // TODO(ishell): support fast Api calls.
      return;
    case StackFrame::EXIT:
    case StackFrame::BUILTIN_EXIT:
      // This is a regular runtime function or C++ builtin.
      return;
#if V8_ENABLE_WEBASSEMBLY
    case StackFrame::WASM:
    case StackFrame::WASM_SEGMENT_START:
      // No more info.
      return;
#endif  // V8_ENABLE_WEBASSEMBLY
    default:
      // Other types are not expected, so just hard-crash.
      CHECK_NE(frame_type, frame_type);
  }
}

void Isolate::ReportExceptionFunctionCallback(
    DirectHandle<JSReceiver> receiver,
    DirectHandle<FunctionTemplateInfo> function,
    v8::ExceptionContext exception_context) {
  DCHECK(exception_context == v8::ExceptionContext::kConstructor ||
         exception_context == v8::ExceptionContext::kOperation);
  DCHECK_NOT_NULL(exception_propagation_callback_);

  // Ignore exceptions that we can't extend.
  if (!IsJSReceiver(this->exception())) return;
  Handle<JSReceiver> exception(Cast<JSReceiver>(this->exception()), this);

  DirectHandle<Object> maybe_message(pending_message(), this);

  Handle<String> property_name =
      IsUndefined(function->class_name(), this)
          ? factory()->empty_string()
          : Handle<String>(Cast<String>(function->class_name()), this);
  Handle<String> interface_name =
      IsUndefined(function->interface_name(), this)
          ? factory()->empty_string()
          : Handle<String>(Cast<String>(function->interface_name()), this);
  if (exception_context != ExceptionContext::kConstructor) {
    exception_context =
        static_cast<ExceptionContext>(function->exception_context());
  }

  {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(this);
    // Ignore any exceptions thrown inside the callback and rethrow the
    // original exception/message.
    TryCatch try_catch(v8_isolate);

    exception_propagation_callback_(v8::ExceptionPropagationMessage(
        v8_isolate, v8::Utils::ToLocal(exception),
        v8::Utils::ToLocal(interface_name), v8::Utils::ToLocal(property_name),
        exception_context));

    try_catch.Reset();
  }
  ReThrow(*exception, *maybe_message);
}

void Isolate::ReportExceptionPropertyCallback(
    Handle<JSReceiver> holder, Handle<Name> name,
    v8::ExceptionContext exception_context) {
  DCHECK_NOT_NULL(exception_propagation_callback_);

  if (!IsJSReceiver(this->exception())) return;
  Handle<JSReceiver> exception(Cast<JSReceiver>(this->exception()), this);

  DirectHandle<Object> maybe_message(pending_message(), this);

  Handle<String> property_name;
  std::ignore = Name::ToFunctionName(this, name).ToHandle(&property_name);
  Handle<String> interface_name = JSReceiver::GetConstructorName(this, holder);

  {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(this);
    // Ignore any exceptions thrown inside the callback and rethrow the
    // original exception/message.
    TryCatch try_catch(v8_isolate);

    exception_propagation_callback_(v8::ExceptionPropagationMessage(
        v8_isolate, v8::Utils::ToLocal(exception),
        v8::Utils::ToLocal(interface_name), v8::Utils::ToLocal(property_name),
        exception_context));

    try_catch.Reset();
  }
  ReThrow(*exception, *maybe_message);
}

void Isolate::SetExceptionPropagationCallback(
    ExceptionPropagationCallback callback) {
  exception_propagation_callback_ = callback;
}

bool Isolate::InitializeCounters() {
  if (async_counters_) return false;
  async_counters_ = std::make_shared<Counters>(this);
  return true;
}

void Isolate::InitializeLoggingAndCounters() {
  if (v8_file_logger_ == nullptr) {
    v8_file_logger_ = new V8FileLogger(this);
  }
  InitializeCounters();
}

namespace {

void FinalizeBuiltinCodeObjects(Isolate* isolate) {
  DCHECK_NOT_NULL(isolate->embedded_blob_code());
  DCHECK_NE(0, isolate->embedded_blob_code_size());
  DCHECK_NOT_NULL(isolate->embedded_blob_data());
  DCHECK_NE(0, isolate->embedded_blob_data_size());

  EmbeddedData d = EmbeddedData::FromBlob(isolate);
  HandleScope scope(isolate);
  static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    DirectHandle<Code> old_code = isolate->builtins()->code_handle(builtin);
    // Note that `old_code.instruction_start` might point to `old_code`'s
    // InstructionStream which might be GCed once we replace the old code
    // with the new code.
    Address instruction_start = d.InstructionStartOf(builtin);
    DirectHandle<Code> new_code =
        isolate->factory()->NewCodeObjectForEmbeddedBuiltin(old_code,
                                                            instruction_start);

    // From this point onwards, the old builtin code object is unreachable and
    // will be collected by the next GC.
    isolate->builtins()->set_code(builtin, *new_code);
  }
}

#ifdef DEBUG
bool IsolateIsCompatibleWithEmbeddedBlob(Isolate* isolate) {
  EmbeddedData d = EmbeddedData::FromBlob(isolate);
  return (d.IsolateHash() == isolate->HashIsolateForEmbeddedBlob());
}
#endif  // DEBUG

}  // namespace

void Isolate::InitializeDefaultEmbeddedBlob() {
  const uint8_t* code = DefaultEmbeddedBlobCode();
  uint32_t code_size = DefaultEmbeddedBlobCodeSize();
  const uint8_t* data = DefaultEmbeddedBlobData();
  uint32_t data_size = DefaultEmbeddedBlobDataSize();

  if (StickyEmbeddedBlobCode() != nullptr) {
    base::MutexGuard guard(current_embedded_blob_refcount_mutex_.Pointer());
    // Check again now that we hold the lock.
    if (StickyEmbeddedBlobCode() != nullptr) {
      code = StickyEmbeddedBlobCode();
      code_size = StickyEmbeddedBlobCodeSize();
      data = StickyEmbeddedBlobData();
      data_size = StickyEmbeddedBlobDataSize();
      current_embedded_blob_refs_++;
    }
  }

  if (code_size == 0) {
    CHECK_EQ(0, data_size);
  } else {
    SetEmbeddedBlob(code, code_size, data, data_size);
  }
}

void Isolate::CreateAndSetEmbeddedBlob() {
  base::MutexGuard guard(current_embedded_blob_refcount_mutex_.Pointer());

  PrepareBuiltinSourcePositionMap();

  // If a sticky blob has been set, we reuse it.
  if (StickyEmbeddedBlobCode() != nullptr) {
    CHECK_EQ(embedded_blob_code(), StickyEmbeddedBlobCode());
    CHECK_EQ(embedded_blob_data(), StickyEmbeddedBlobData());
    CHECK_EQ(CurrentEmbeddedBlobCode(), StickyEmbeddedBlobCode());
    CHECK_EQ(CurrentEmbeddedBlobData(), StickyEmbeddedBlobData());
  } else {
    // Create and set a new embedded blob.
    uint8_t* code;
    uint32_t code_size;
    uint8_t* data;
    uint32_t data_size;
    OffHeapInstructionStream::CreateOffHeapOffHeapInstructionStream(
        this, &code, &code_size, &data, &data_size);

    CHECK_EQ(0, current_embedded_blob_refs_);
    const uint8_t* const_code = const_cast<const uint8_t*>(code);
    const uint8_t* const_data = const_cast<const uint8_t*>(data);
    SetEmbeddedBlob(const_code, code_size, const_data, data_size);
    current_embedded_blob_refs_++;

    SetStickyEmbeddedBlob(code, code_size, data, data_size);
  }

  MaybeRemapEmbeddedBuiltinsIntoCodeRange();
  FinalizeBuiltinCodeObjects(this);
}

void Isolate::InitializeIsShortBuiltinCallsEnabled() {
  if (V8_SHORT_BUILTIN_CALLS_BOOL && v8_flags.short_builtin_calls) {
#if defined(V8_OS_ANDROID)
    // On Android, the check is not operative to detect memory, and re-embedded
    // builtins don't have a memory cost.
    is_short_builtin_calls_enabled_ = true;
#else
    // Check if the system has more than 4GB of physical memory by comparing the
    // old space size with respective threshold value.
    is_short_builtin_calls_enabled_ = (heap_.MaxOldGenerationSize() >=
                                       kShortBuiltinCallsOldSpaceSizeThreshold);
#endif  // defined(V8_OS_ANDROID)
    // Additionally, enable if there is already a process-wide CodeRange that
    // has re-embedded builtins.
    if (COMPRESS_POINTERS_BOOL) {
      CodeRange* code_range = isolate_group()->GetCodeRange();
      if (code_range && code_range->embedded_blob_code_copy() != nullptr) {
        is_short_builtin_calls_enabled_ = true;
      }
    }
    if (V8_ENABLE_NEAR_CODE_RANGE_BOOL) {
      // The short builtin calls could still be enabled if allocated code range
      // is close enough to embedded builtins so that the latter could be
      // reached using pc-relative (short) calls/jumps.
      is_short_builtin_calls_enabled_ |=
          GetShortBuiltinsCallRegion().contains(heap_.code_region());
    }
  }
}

void Isolate::MaybeRemapEmbeddedBuiltinsIntoCodeRange() {
  if (!is_short_builtin_calls_enabled() || !RequiresCodeRange()) {
    return;
  }
  if (V8_ENABLE_NEAR_CODE_RANGE_BOOL &&
      GetShortBuiltinsCallRegion().contains(heap_.code_region())) {
    // The embedded builtins are within the pc-relative reach from the code
    // range, so there's no need to remap embedded builtins.
    return;
  }

  CHECK_NOT_NULL(embedded_blob_code_);
  CHECK_NE(embedded_blob_code_size_, 0);

  DCHECK_NOT_NULL(heap_.code_range_);
  embedded_blob_code_ = 
"""


```