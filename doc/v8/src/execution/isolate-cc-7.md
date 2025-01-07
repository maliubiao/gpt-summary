Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/isolate.cc`. They also have specific requirements based on file extension, relationship to JavaScript, code logic, and common programming errors. Since this is part 8 of 9, a general summary of the isolate's responsibilities might be useful.

Here's a breakdown of the code's functionality:

1. **WebAssembly Statistics:** Handles dumping and resetting WebAssembly engine statistics.
2. **Runtime Call Statistics:**  Collects and prints statistics about runtime calls.
3. **Builtins Profiling:** Manages profiling data for built-in functions, including logging and resetting counts.
4. **Concurrent Optimization:** Controls the priority and abortion of concurrent JavaScript optimization.
5. **Compilation Statistics:**  Provides access to statistics for TurboFan and potentially Maglev compilations.
6. **Code Tracing:**  Manages a code tracer for debugging and profiling.
7. **Optimizer Usage:** Determines if the JavaScript optimizer should be used.
8. **RegExp Code Size:** Tracks the total amount of code generated for regular expressions.
9. **Source Position Information:** Determines if detailed source position information is needed for debugging and profiling.
10. **Code Creation Logging:** Checks if code creation events are being logged.
11. **Code Compaction:** Checks if code compaction is allowed.
12. **Source Position Requirements:** Determines if source positions are required based on various flags and debugging states.
13. **Feedback Vectors for Profiling:**  Manages and initializes feedback vectors used by profiling tools.
14. **Date Cache:** Manages a date cache.
15. **Prototype Checking:**  Identifies if a given object is one of the fundamental prototypes (Object, Array, String).
16. **Creation Context Check:**  Determines if an object belongs to a specific creation context.
17. **Protector Updates:** Updates various "protectors" when certain actions occur (like setting elements or prototypes) to invalidate assumptions made by the compiler. These include protectors related to:
    - No elements on prototypes
    - Typed array species lookup chain
    - Number/String not being regexp-like
    - String wrapper to primitive conversion
18. **Random Number Generation:** Provides access to random number generators, including a fuzzer-specific one.
19. **Identity Hash Generation:** Generates unique identity hashes.
20. **Symbol Management:**  Manages the creation and retrieval of symbols (both public and API-specific).
21. **Call Completion Callbacks:**  Manages lists of callbacks to be executed before and after function calls.
22. **WebAssembly Continuation:** Initializes the WebAssembly continuation object.
23. **Promise Hook Management:** Manages a promise hook for observing promise lifecycle events.
24. **Dynamic Import Callback:** Handles the dynamic import of modules.
25. **Import Attributes:** Extracts import attributes from the import() options.
26. **Kept Objects:** Provides a way to clear kept objects.
27. **Host Callbacks for Modules:** Sets callbacks for host-specific module operations (dynamic import, meta object initialization, shadow realm context creation).
28. **Stack Trace Preparation Callback:** Handles custom stack trace formatting.
29. **Externally Compiled Files:**  Manages a list of externally compiled files.
30. **Builtin Unwind Data:** Sets unwind information for built-in functions (Windows specific).
31. **ETW Session Filtering (Windows):**  Allows filtering ETW sessions based on URL.
32. **Crash Key Callbacks:** Manages callbacks for adding crash keys.
33. **Atomics Wait Callback:**  Manages a callback for `Atomics.wait`.
34. **Promise Hook Execution:**  Runs promise hooks at various stages of a promise's lifecycle.
35. **Async Function Suspension:** Handles events when async functions are suspended.
36. **Promise Then/Catch/Finally Hooks:** Triggers asynchronous debugging events for `then`, `catch`, and `finally`.
37. **Promise Before/After Hooks:** Triggers promise hooks before and after promise resolution/rejection.

Considering the provided code snippet, it focuses on:

- **Statistics and Profiling:** Gathering and reporting on the performance of different V8 components (Wasm, runtime calls, builtins, compiler).
- **Concurrent Optimization Control:** Managing background compilation processes.
- **Protectors:** Ensuring the correctness of compiler optimizations by invalidating assumptions when necessary.
- **Module Loading Integration:** Providing hooks for host environments to customize module loading behavior.
- **Promise Hook Mechanism:** Enabling observation of promise lifecycle events for debugging and other purposes.
这个`v8/src/execution/isolate.cc`代码片段主要负责以下功能：

1. **处理 WebAssembly 引擎统计信息:** 如果启用了 WebAssembly 且 `turbo_stats_wasm` 标志为真，则会调用 `wasm::GetWasmEngine()->DumpAndResetTurboStatistics()` 来导出并重置 WebAssembly 引擎的统计数据。这对于分析 WebAssembly 代码的性能很有用。

2. **收集和打印运行时调用统计信息:** 如果启用了 `V8_RUNTIME_CALL_STATS` 并且相应的追踪标志被激活，代码会将 worker 线程的运行时调用统计信息添加到主线程的统计表中，然后打印并重置这些统计信息。这有助于了解 V8 运行时的行为和性能瓶颈。

3. **导出和重置内置函数的性能分析数据:**  `DumpAndResetBuiltinsProfileData()` 函数负责处理内置函数的性能分析数据。如果启用了内置函数性能分析 (`v8_enable_builtins_profiling=true`) 并且存在分析数据，它会将数据输出到文件（如果指定了 `v8_flags.turbo_profiling_output`）或标准输出。之后，它会重置这些计数器。

4. **调整并发优化的优先级:** `IncreaseConcurrentOptimizationPriority()` 函数允许提高特定函数的并发优化优先级，特别是针对 TurboFan 编译的 JavaScript 函数。

5. **中止并发优化:** `AbortConcurrentOptimization()` 函数可以中止正在进行的并发优化，可以选择阻塞行为。这会刷新 TurboFan 和 Maglev 的并发调度器。

6. **获取编译统计信息:**  `GetTurboStatistics()` 和 `GetMaglevStatistics()` 函数分别返回 TurboFan 和 Maglev 编译器的统计信息对象。如果统计信息对象尚未创建，则会先创建它。

7. **获取代码追踪器:** `GetCodeTracer()` 函数返回与当前 Isolate 关联的 `CodeTracer` 对象，如果尚未创建，则会创建一个新的。

8. **判断是否使用优化器:** `use_optimizer()` 函数判断当前 Isolate 是否应该使用优化器 (TurboFan 或 Maglev)。这取决于各种标志、CPU 特性以及是否启用了序列化或精确的代码覆盖率。

9. **记录正则表达式生成的代码大小:** `IncreaseTotalRegexpCodeGenerated()` 函数用于累加生成的正则表达式代码的大小。

10. **判断是否需要详细的优化代码行信息:** `NeedsDetailedOptimizedCodeLineInfo()` 函数根据是否需要源码位置信息来判断是否需要更详细的优化代码行信息。

11. **判断是否正在记录代码创建:** `IsLoggingCodeCreation()` 函数检查是否正在监听代码创建事件，这可能由文件日志记录器、性能分析器或其他标志触发。

12. **判断是否允许代码压缩:** `AllowsCodeCompaction()` 函数检查是否启用了代码空间压缩以及日志记录器是否允许压缩。

13. **判断是否需要源码位置信息:** `NeedsSourcePositions()` 函数检查各种标志和调试状态，以确定是否需要收集源码位置信息。这对于调试、性能分析和代码追踪至关重要。

14. **设置用于性能分析工具的反馈向量:** `SetFeedbackVectorsForProfilingTools()` 函数允许设置用于性能分析工具的反馈向量列表。

15. **初始化反馈向量列表:** `MaybeInitializeVectorListFromHeap()` 函数用于从堆中收集现有的反馈向量，并将其添加到根列表中，以便在垃圾回收期间保留它们。

16. **管理日期缓存:** `set_date_cache()` 函数用于设置 Isolate 的日期缓存。

17. **判断对象是否为特定的原型对象:** `IsArrayOrObjectOrStringPrototype()` 函数检查给定的 JSObject 是否是 Array、Object 或 String 的初始原型对象。

18. **判断对象是否在创建上下文中:** `IsInCreationContext()` 函数判断给定的 JSObject 是否属于特定的 NativeContext 的某个预定义槽位。

19. **更新保护器 (Protectors):**  多个 `Update...ProtectorOnSetElement` 和 `Update...ProtectorOnSetPrototype` 函数用于在设置对象元素或原型时更新各种 "保护器"。这些保护器是 V8 优化器所依赖的假设，当这些假设可能失效时，需要使相应的保护器失效，以防止错误的优化。这些保护器包括：
    - `UpdateNoElementsProtectorOnSetElement`:  当在原型链上设置元素时，使 "no elements" 保护器失效。
    - `UpdateProtectorsOnSetPrototype`:  当设置对象的原型时，更新多个相关的保护器。
    - `UpdateTypedArraySpeciesLookupChainProtectorOnSetPrototype`: 当设置 TypedArray 构造函数的原型时，使 TypedArray 的 `@@species` 查找链保护器失效。
    - `UpdateNumberStringNotRegexpLikeProtectorOnSetPrototype`: 当设置 `Number.prototype` 或 `String.prototype` 的原型时，使数字和字符串不是正则表达式的保护器失效。
    - `UpdateStringWrapperToPrimitiveProtectorOnSetPrototype`: 当设置字符串包装对象的原型时，使字符串包装对象到原始值的转换保护器失效。

20. **生成随机数:**  `random_number_generator()` 和 `fuzzer_rng()` 函数提供访问 Isolate 的随机数生成器的接口。

21. **生成唯一标识哈希:** `GenerateIdentityHash()` 函数用于生成唯一的标识哈希值。

22. **管理符号 (Symbols):** `SymbolFor()` 函数用于在全局符号表中查找或添加符号。

23. **管理回调函数:**  `AddBeforeCallEnteredCallback()`, `RemoveBeforeCallEnteredCallback()`, `AddCallCompletedCallback()`, `RemoveCallCompletedCallback()`, 和 `FireCallCompletedCallbackInternal()` 函数用于管理在函数调用前后执行的回调函数。

24. **初始化 WebAssembly JSPI 功能:** `WasmInitJSPIFeature()` 用于初始化 WebAssembly 的 JSPI (JavaScript Promise Integration) 功能，例如设置活动的 Continuation 对象。

25. **更新 Promise Hook 保护器:** `UpdatePromiseHookProtector()` 函数用于使 Promise Hook 保护器失效。

26. **更新 Promise Hook 状态:** `PromiseHookStateUpdated()` 函数根据 Promise Hook 和异步事件代理的状态更新内部标志。

27. **处理 HostImportModuleDynamicallyCallback:** `RunHostImportModuleDynamicallyCallback()` 函数负责执行主机提供的动态导入模块的回调函数。

28. **获取导入属性:** `GetImportAttributesFromArgument()` 函数从动态导入的选项参数中提取导入属性。

29. **清理保留的对象:** `ClearKeptObjects()` 函数用于清理堆中被显式保留的对象。

30. **设置主机回调函数:** `SetHostImportModuleDynamicallyCallback()`, `SetHostImportModuleWithPhaseDynamicallyCallback()`, `SetHostInitializeImportMetaObjectCallback()`, 和 `SetHostCreateShadowRealmContextCallback()` 函数用于设置主机提供的各种回调函数，用于定制模块加载和执行的行为。

31. **执行 HostInitializeImportMetaObjectCallback:** `RunHostInitializeImportMetaObjectCallback()` 执行主机提供的初始化 import.meta 对象的回调函数。

32. **执行 HostCreateShadowRealmContextCallback:** `RunHostCreateShadowRealmContextCallback()` 执行主机提供的创建 ShadowRealm 上下文的回调函数。

33. **执行 PrepareStackTraceCallback:** `RunPrepareStackTraceCallback()` 函数负责执行用户提供的自定义堆栈跟踪格式化回调函数。

34. **管理外部编译的文件名:** `LookupOrAddExternallyCompiledFilename()`, `GetExternallyCompiledFilename()`, 和 `GetExternallyCompiledFilenameCount()` 函数用于管理外部编译文件的文件名列表。

35. **准备内置函数的源码位置映射:** `PrepareBuiltinSourcePositionMap()` 函数用于准备内置函数的源码位置映射。

36. **设置内置函数的展开数据 (Windows):** `SetBuiltinUnwindData()` 函数用于设置内置函数在 Windows x64 上的展开信息。

37. **设置 PrepareStackTraceCallback:** `SetPrepareStackTraceCallback()` 函数用于设置自定义堆栈跟踪格式化的回调函数。

38. **判断是否存在 PrepareStackTraceCallback:** `HasPrepareStackTraceCallback()` 函数检查是否设置了自定义堆栈跟踪格式化回调函数。

39. **设置和运行 ETW 会话过滤回调 (Windows):** `SetFilterETWSessionByURLCallback()` 和 `RunFilterETWSessionByURLCallback()` 函数用于设置和执行基于 URL 过滤 ETW (Event Tracing for Windows) 会话的回调。

40. **设置崩溃键回调:** `SetAddCrashKeyCallback()` 函数用于设置添加崩溃键的回调函数。

41. **设置 Atomics.wait 回调:** `SetAtomicsWaitCallback()` 函数用于设置 `Atomics.wait` 操作的回调函数。

42. **运行 Atomics.wait 回调:** `RunAtomicsWaitCallback()` 函数在 `Atomics.wait` 事件发生时执行回调函数。

43. **设置 Promise Hook:** `SetPromiseHook()` 函数用于设置 Promise Hook 回调函数。

44. **运行所有 Promise Hook:** `RunAllPromiseHooks()` 函数在 Promise 生命周期中的不同阶段运行已注册的 Promise Hook，包括上下文相关的 Hook 和 Isolate 级别的 Hook。

45. **运行 Promise Hook:** `RunPromiseHook()` 函数执行 Isolate 级别的 Promise Hook 回调。

46. **处理异步函数挂起事件:** `OnAsyncFunctionSuspended()` 函数在异步函数挂起时触发 Promise Hook 并通知异步事件代理。

47. **处理 Promise.then/catch/finally 事件:** `OnPromiseThen()` 函数检测 Promise 的 `then`、`catch` 和 `finally` 调用，并通知异步事件代理。

48. **处理 Promise before 事件:** `OnPromiseBefore()` 函数在 Promise 执行之前运行 Promise Hook 并通知异步事件代理。

49. **处理 Promise after 事件:** `OnPromiseAfter()` 函数在 Promise 执行之后运行 Promise Hook。

**关于你的问题：**

* **文件扩展名:** 该代码是以 `.cc` 结尾，因此不是 v8 torque 源代码。
* **与 JavaScript 的关系:**  该文件中的许多功能都直接关系到 JavaScript 的执行和优化，例如：
    ```javascript
    // JavaScript 示例，展示了与部分 C++ 代码功能的关联
    async function fetchData() {
      try {
        const result = await fetch('api/data'); // 触发 Promise 生命周期事件
        return result.json();
      } catch (error) {
        console.error(error); // 可能会触发自定义堆栈跟踪
        throw error;
      }
    }

    // 动态导入
    import('./module.js').then(module => {
      module.doSomething();
    });
    ```
* **代码逻辑推理:**
    * **假设输入:** `v8_flags.turbo_stats_wasm` 为 true，且启用了 WebAssembly。
    * **输出:**  调用 `wasm::GetWasmEngine()->DumpAndResetTurboStatistics()` 将 WebAssembly 引擎的统计信息输出到某个地方（通常是日志或控制台），并重置这些统计信息。
* **用户常见的编程错误:**
    * **忘记处理 Promise 拒绝:**  如果 JavaScript 代码中创建了一个 Promise 但没有提供 `.catch()` 处理拒绝的情况，V8 的 Promise Hook 机制可以用来监控这些未处理的拒绝，虽然这段 C++ 代码本身不直接处理这种错误，但它是 Promise Hook 机制的一部分。
    * **过度依赖原型修改:**  在 JavaScript 中过度修改内置对象的原型可能会导致性能问题，甚至破坏 V8 的优化假设。这段 C++ 代码中的 `Update...ProtectorOnSetPrototype` 系列函数就是为了应对这种情况，当原型被修改时，V8 会使相关的优化失效，确保代码的正确性，但也可能降低性能。

**归纳其功能 (作为第 8 部分，共 9 部分):**

考虑到这是 Isolate 相关的代码的第 8 部分，这个代码片段主要关注 **Isolate 实例在运行时对性能监控、优化控制、与外部环境交互 (如主机环境和 WebAssembly 引擎) 以及提供调试支持的能力。** 它处理了统计信息的收集、并发优化的管理、各种保护器的更新以确保优化的正确性、与主机环境的回调交互、以及 Promise Hook 和其他调试工具的集成。 这部分代码更侧重于运行时行为的监控和调整，以及与外部环境的集成，而不是 Isolate 的核心创建和初始化。

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共9部分，请归纳一下它的功能

"""
c API for the {WasmEngine} yet. So for now we
  // just dump and reset the engines statistics together with the Isolate.
  if (v8_flags.turbo_stats_wasm) {
    wasm::GetWasmEngine()->DumpAndResetTurboStatistics();
  }
#endif  // V8_ENABLE_WEBASSEMBLY
#if V8_RUNTIME_CALL_STATS
  if (V8_UNLIKELY(TracingFlags::runtime_stats.load(std::memory_order_relaxed) ==
                  v8::tracing::TracingCategoryObserver::ENABLED_BY_NATIVE)) {
    counters()->worker_thread_runtime_call_stats()->AddToMainTable(
        counters()->runtime_call_stats());
    counters()->runtime_call_stats()->Print();
    counters()->runtime_call_stats()->Reset();
  }
#endif  // V8_RUNTIME_CALL_STATS
}

void Isolate::DumpAndResetBuiltinsProfileData() {
  if (BasicBlockProfiler::Get()->HasData(this)) {
    if (v8_flags.turbo_profiling_output) {
      FILE* f = std::fopen(v8_flags.turbo_profiling_output, "w");
      if (f == nullptr) {
        FATAL("Unable to open file \"%s\" for writing.\n",
              v8_flags.turbo_profiling_output.value());
      }
      OFStream pgo_stream(f);
      BasicBlockProfiler::Get()->Log(this, pgo_stream);
    } else {
      StdoutStream out;
      BasicBlockProfiler::Get()->Print(this, out);
    }
    BasicBlockProfiler::Get()->ResetCounts(this);
  } else {
    // Only log builtins PGO data if v8 was built with
    // v8_enable_builtins_profiling=true
    CHECK_NULL(v8_flags.turbo_profiling_output);
  }
}

void Isolate::IncreaseConcurrentOptimizationPriority(
    CodeKind kind, Tagged<SharedFunctionInfo> function) {
  DCHECK_EQ(kind, CodeKind::TURBOFAN_JS);
  optimizing_compile_dispatcher()->Prioritize(function);
}

void Isolate::AbortConcurrentOptimization(BlockingBehavior behavior) {
  if (concurrent_recompilation_enabled()) {
    DisallowGarbageCollection no_recursive_gc;
    optimizing_compile_dispatcher()->Flush(behavior);
  }
#ifdef V8_ENABLE_MAGLEV
  if (maglev_concurrent_dispatcher()->is_enabled()) {
    DisallowGarbageCollection no_recursive_gc;
    maglev_concurrent_dispatcher()->Flush(behavior);
  }
#endif
}

std::shared_ptr<CompilationStatistics> Isolate::GetTurboStatistics() {
  if (turbo_statistics_ == nullptr) {
    turbo_statistics_.reset(new CompilationStatistics());
  }
  return turbo_statistics_;
}

#ifdef V8_ENABLE_MAGLEV

std::shared_ptr<CompilationStatistics> Isolate::GetMaglevStatistics() {
  if (maglev_statistics_ == nullptr) {
    maglev_statistics_.reset(new CompilationStatistics());
  }
  return maglev_statistics_;
}

#endif  // V8_ENABLE_MAGLEV

CodeTracer* Isolate::GetCodeTracer() {
  if (code_tracer() == nullptr) set_code_tracer(new CodeTracer(id()));
  return code_tracer();
}

bool Isolate::use_optimizer() {
  // TODO(v8:7700): Update this predicate for a world with multiple tiers.
  return (v8_flags.turbofan || v8_flags.maglev) && !serializer_enabled_ &&
         CpuFeatures::SupportsOptimizer() && !is_precise_count_code_coverage();
}

void Isolate::IncreaseTotalRegexpCodeGenerated(DirectHandle<HeapObject> code) {
  PtrComprCageBase cage_base(this);
  DCHECK(IsCode(*code, cage_base) || IsTrustedByteArray(*code, cage_base));
  total_regexp_code_generated_ += code->Size(cage_base);
}

bool Isolate::NeedsDetailedOptimizedCodeLineInfo() const {
  return NeedsSourcePositions() || detailed_source_positions_for_profiling();
}

bool Isolate::IsLoggingCodeCreation() const {
  return v8_file_logger()->is_listening_to_code_events() || is_profiling() ||
         v8_flags.log_function_events ||
         logger()->is_listening_to_code_events();
}

bool Isolate::AllowsCodeCompaction() const {
  return v8_flags.compact_code_space && logger()->allows_code_compaction();
}

bool Isolate::NeedsSourcePositions() const {
  return
      // Static conditions.
      v8_flags.trace_deopt || v8_flags.trace_turbo ||
      v8_flags.trace_turbo_graph || v8_flags.turbo_profiling ||
      v8_flags.print_maglev_code || v8_flags.perf_prof || v8_flags.log_maps ||
      v8_flags.log_ic || v8_flags.log_function_events ||
      v8_flags.heap_snapshot_on_oom ||
      // Dynamic conditions; changing any of these conditions triggers source
      // position collection for the entire heap
      // (CollectSourcePositionsForAllBytecodeArrays).
      is_profiling() || debug_->is_active() || v8_file_logger_->is_logging();
}

void Isolate::SetFeedbackVectorsForProfilingTools(Tagged<Object> value) {
  DCHECK(IsUndefined(value, this) || IsArrayList(value));
  heap()->set_feedback_vectors_for_profiling_tools(value);
}

void Isolate::MaybeInitializeVectorListFromHeap() {
  if (!IsUndefined(heap()->feedback_vectors_for_profiling_tools(), this)) {
    // Already initialized, return early.
    DCHECK(IsArrayList(heap()->feedback_vectors_for_profiling_tools()));
    return;
  }

  // Collect existing feedback vectors.
  DirectHandleVector<FeedbackVector> vectors(this);

  {
    HeapObjectIterator heap_iterator(heap());
    for (Tagged<HeapObject> current_obj = heap_iterator.Next();
         !current_obj.is_null(); current_obj = heap_iterator.Next()) {
      if (!IsFeedbackVector(current_obj)) continue;

      Tagged<FeedbackVector> vector = Cast<FeedbackVector>(current_obj);
      Tagged<SharedFunctionInfo> shared = vector->shared_function_info();

      // No need to preserve the feedback vector for non-user-visible functions.
      if (!shared->IsSubjectToDebugging()) continue;

      vectors.emplace_back(vector, this);
    }
  }

  // Add collected feedback vectors to the root list lest we lose them to GC.
  Handle<ArrayList> list =
      ArrayList::New(this, static_cast<int>(vectors.size()));
  for (const auto& vector : vectors) list = ArrayList::Add(this, list, vector);
  SetFeedbackVectorsForProfilingTools(*list);
}

void Isolate::set_date_cache(DateCache* date_cache) {
  if (date_cache != date_cache_) {
    delete date_cache_;
  }
  date_cache_ = date_cache;
}

Isolate::KnownPrototype Isolate::IsArrayOrObjectOrStringPrototype(
    Tagged<JSObject> object) {
  Tagged<Map> metamap = object->map(this)->map(this);
  Tagged<NativeContext> native_context = metamap->native_context();
  if (native_context->initial_object_prototype() == object) {
    return KnownPrototype::kObject;
  } else if (native_context->initial_array_prototype() == object) {
    return KnownPrototype::kArray;
  } else if (native_context->initial_string_prototype() == object) {
    return KnownPrototype::kString;
  }
  return KnownPrototype::kNone;
}

bool Isolate::IsInCreationContext(Tagged<JSObject> object, uint32_t index) {
  DisallowGarbageCollection no_gc;
  Tagged<Map> metamap = object->map(this)->map(this);
  // Filter out native-context independent objects.
  if (metamap == ReadOnlyRoots(this).meta_map()) return false;
  Tagged<NativeContext> native_context = metamap->native_context();
  return native_context->get(index) == object;
}

void Isolate::UpdateNoElementsProtectorOnSetElement(
    DirectHandle<JSObject> object) {
  DisallowGarbageCollection no_gc;
  if (!object->map()->is_prototype_map()) return;
  if (!Protectors::IsNoElementsIntact(this)) return;
  KnownPrototype obj_type = IsArrayOrObjectOrStringPrototype(*object);
  if (obj_type == KnownPrototype::kNone) return;
  if (obj_type == KnownPrototype::kObject) {
    this->CountUsage(v8::Isolate::kObjectPrototypeHasElements);
  } else if (obj_type == KnownPrototype::kArray) {
    this->CountUsage(v8::Isolate::kArrayPrototypeHasElements);
  }
  Protectors::InvalidateNoElements(this);
}

void Isolate::UpdateProtectorsOnSetPrototype(
    DirectHandle<JSObject> object, DirectHandle<Object> new_prototype) {
  UpdateNoElementsProtectorOnSetPrototype(object);
  UpdateTypedArraySpeciesLookupChainProtectorOnSetPrototype(object);
  UpdateNumberStringNotRegexpLikeProtectorOnSetPrototype(object);
  UpdateStringWrapperToPrimitiveProtectorOnSetPrototype(object, new_prototype);
}

void Isolate::UpdateTypedArraySpeciesLookupChainProtectorOnSetPrototype(
    DirectHandle<JSObject> object) {
  // Setting the __proto__ of TypedArray constructor could change TypedArray's
  // @@species. So we need to invalidate the @@species protector.
  if (IsTypedArrayConstructor(*object) &&
      Protectors::IsTypedArraySpeciesLookupChainIntact(this)) {
    Protectors::InvalidateTypedArraySpeciesLookupChain(this);
  }
}

void Isolate::UpdateNumberStringNotRegexpLikeProtectorOnSetPrototype(
    DirectHandle<JSObject> object) {
  if (!Protectors::IsNumberStringNotRegexpLikeIntact(this)) {
    return;
  }
  // We need to protect the prototype chain of `Number.prototype` and
  // `String.prototype`.
  // Since `Object.prototype.__proto__` is not writable, we can assume it
  // doesn't occur here. We detect `Number.prototype` and `String.prototype` by
  // checking for a prototype that is a JSPrimitiveWrapper. This is a safe
  // approximation. Using JSPrimitiveWrapper as prototype should be
  // sufficiently rare.
  DCHECK(!IsJSObjectPrototype(*object));
  if (object->map()->is_prototype_map() && (IsJSPrimitiveWrapper(*object))) {
    Protectors::InvalidateNumberStringNotRegexpLike(this);
  }
}

void Isolate::UpdateStringWrapperToPrimitiveProtectorOnSetPrototype(
    DirectHandle<JSObject> object, DirectHandle<Object> new_prototype) {
  if (!Protectors::IsStringWrapperToPrimitiveIntact(this)) {
    return;
  }

  // We can have a custom @@toPrimitive on a string wrapper also if we subclass
  // String and the subclass (or one of its subclasses) defines its own
  // @@toPrimive. Thus we invalidate the protector whenever we detect
  // subclassing String - it should be reasonably rare.
  if (IsStringWrapper(*object) || IsStringWrapper(*new_prototype)) {
    Protectors::InvalidateStringWrapperToPrimitive(this);
  }
}

static base::RandomNumberGenerator* ensure_rng_exists(
    base::RandomNumberGenerator** rng, int seed) {
  if (*rng == nullptr) {
    if (seed != 0) {
      *rng = new base::RandomNumberGenerator(seed);
    } else {
      *rng = new base::RandomNumberGenerator();
    }
  }
  return *rng;
}

base::RandomNumberGenerator* Isolate::random_number_generator() {
  // TODO(bmeurer) Initialized lazily because it depends on flags; can
  // be fixed once the default isolate cleanup is done.
  return ensure_rng_exists(&random_number_generator_, v8_flags.random_seed);
}

base::RandomNumberGenerator* Isolate::fuzzer_rng() {
  if (fuzzer_rng_ == nullptr) {
    int64_t seed = v8_flags.fuzzer_random_seed;
    if (seed == 0) {
      seed = random_number_generator()->initial_seed();
    }

    fuzzer_rng_ = new base::RandomNumberGenerator(seed);
  }

  return fuzzer_rng_;
}

int Isolate::GenerateIdentityHash(uint32_t mask) {
  int hash;
  int attempts = 0;
  do {
    hash = random_number_generator()->NextInt() & mask;
  } while (hash == 0 && attempts++ < 30);
  return hash != 0 ? hash : 1;
}

#ifdef DEBUG
#define ISOLATE_FIELD_OFFSET(type, name, ignored) \
  const intptr_t Isolate::name##_debug_offset_ = OFFSET_OF(Isolate, name##_);
ISOLATE_INIT_LIST(ISOLATE_FIELD_OFFSET)
ISOLATE_INIT_ARRAY_LIST(ISOLATE_FIELD_OFFSET)
#undef ISOLATE_FIELD_OFFSET
#endif

Handle<Symbol> Isolate::SymbolFor(RootIndex dictionary_index,
                                  Handle<String> name, bool private_symbol) {
  Handle<String> key = factory()->InternalizeString(name);
  Handle<RegisteredSymbolTable> dictionary =
      Cast<RegisteredSymbolTable>(root_handle(dictionary_index));
  InternalIndex entry = dictionary->FindEntry(this, key);
  Handle<Symbol> symbol;
  if (entry.is_not_found()) {
    symbol =
        private_symbol ? factory()->NewPrivateSymbol() : factory()->NewSymbol();
    symbol->set_description(*key);
    dictionary = RegisteredSymbolTable::Add(this, dictionary, key, symbol);

    switch (dictionary_index) {
      case RootIndex::kPublicSymbolTable:
        symbol->set_is_in_public_symbol_table(true);
        heap()->set_public_symbol_table(*dictionary);
        break;
      case RootIndex::kApiSymbolTable:
        heap()->set_api_symbol_table(*dictionary);
        break;
      case RootIndex::kApiPrivateSymbolTable:
        heap()->set_api_private_symbol_table(*dictionary);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    symbol = Handle<Symbol>(Cast<Symbol>(dictionary->ValueAt(entry)), this);
  }
  return symbol;
}

void Isolate::AddBeforeCallEnteredCallback(BeforeCallEnteredCallback callback) {
  auto pos = std::find(before_call_entered_callbacks_.begin(),
                       before_call_entered_callbacks_.end(), callback);
  if (pos != before_call_entered_callbacks_.end()) return;
  before_call_entered_callbacks_.push_back(callback);
}

void Isolate::RemoveBeforeCallEnteredCallback(
    BeforeCallEnteredCallback callback) {
  auto pos = std::find(before_call_entered_callbacks_.begin(),
                       before_call_entered_callbacks_.end(), callback);
  if (pos == before_call_entered_callbacks_.end()) return;
  before_call_entered_callbacks_.erase(pos);
}

void Isolate::AddCallCompletedCallback(CallCompletedCallback callback) {
  auto pos = std::find(call_completed_callbacks_.begin(),
                       call_completed_callbacks_.end(), callback);
  if (pos != call_completed_callbacks_.end()) return;
  call_completed_callbacks_.push_back(callback);
}

void Isolate::RemoveCallCompletedCallback(CallCompletedCallback callback) {
  auto pos = std::find(call_completed_callbacks_.begin(),
                       call_completed_callbacks_.end(), callback);
  if (pos == call_completed_callbacks_.end()) return;
  call_completed_callbacks_.erase(pos);
}

void Isolate::FireCallCompletedCallbackInternal(
    MicrotaskQueue* microtask_queue) {
  DCHECK(thread_local_top()->CallDepthIsZero());

  bool perform_checkpoint =
      microtask_queue &&
      microtask_queue->microtasks_policy() == v8::MicrotasksPolicy::kAuto &&
      !is_execution_terminating();

  v8::Isolate* isolate = reinterpret_cast<v8::Isolate*>(this);
  if (perform_checkpoint) microtask_queue->PerformCheckpoint(isolate);

  if (call_completed_callbacks_.empty()) return;
  // Fire callbacks.  Increase call depth to prevent recursive callbacks.
  v8::Isolate::SuppressMicrotaskExecutionScope suppress(isolate);
  std::vector<CallCompletedCallback> callbacks(call_completed_callbacks_);
  for (auto& callback : callbacks) {
    callback(reinterpret_cast<v8::Isolate*>(this));
  }
}

#ifdef V8_ENABLE_WEBASSEMBLY
void Isolate::WasmInitJSPIFeature() {
  if (IsUndefined(root(RootIndex::kActiveContinuation))) {
    wasm::StackMemory* stack(wasm::StackMemory::GetCentralStackView(this));
    this->wasm_stacks().emplace_back(stack);
    stack->set_index(0);
    if (v8_flags.trace_wasm_stack_switching) {
      PrintF("Set up native stack object (limit: %p, base: %p)\n",
             stack->jslimit(), reinterpret_cast<void*>(stack->base()));
    }
    HandleScope scope(this);
    DirectHandle<WasmContinuationObject> continuation =
        WasmContinuationObject::New(this, stack, wasm::JumpBuffer::Active,
                                    AllocationType::kOld);
    heap()
        ->roots_table()
        .slot(RootIndex::kActiveContinuation)
        .store(*continuation);
  }
}
#endif

void Isolate::UpdatePromiseHookProtector() {
  if (Protectors::IsPromiseHookIntact(this)) {
    HandleScope scope(this);
    Protectors::InvalidatePromiseHook(this);
  }
}

void Isolate::PromiseHookStateUpdated() {
  promise_hook_flags_ =
      (promise_hook_flags_ & PromiseHookFields::HasContextPromiseHook::kMask) |
      PromiseHookFields::HasIsolatePromiseHook::encode(promise_hook_) |
      PromiseHookFields::HasAsyncEventDelegate::encode(async_event_delegate_) |
      PromiseHookFields::IsDebugActive::encode(debug()->is_active());

  if (promise_hook_flags_ != 0) {
    UpdatePromiseHookProtector();
  }
}

namespace {

MaybeHandle<JSPromise> NewRejectedPromise(Isolate* isolate,
                                          v8::Local<v8::Context> api_context,
                                          Handle<Object> exception) {
  v8::Local<v8::Promise::Resolver> resolver;
  API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, resolver,
                                       v8::Promise::Resolver::New(api_context),
                                       MaybeHandle<JSPromise>());

  MAYBE_RETURN_ON_EXCEPTION_VALUE(
      isolate, resolver->Reject(api_context, v8::Utils::ToLocal(exception)),
      MaybeHandle<JSPromise>());

  v8::Local<v8::Promise> promise = resolver->GetPromise();
  return v8::Utils::OpenHandle(*promise);
}

}  // namespace

MaybeHandle<JSPromise> Isolate::RunHostImportModuleDynamicallyCallback(
    MaybeHandle<Script> maybe_referrer, Handle<Object> specifier,
    ModuleImportPhase phase,
    MaybeHandle<Object> maybe_import_options_argument) {
  DCHECK(!is_execution_terminating());
  v8::Local<v8::Context> api_context = v8::Utils::ToLocal(native_context());
  if (host_import_module_dynamically_callback_ == nullptr) {
    Handle<Object> exception =
        factory()->NewError(error_function(), MessageTemplate::kUnsupported);
    return NewRejectedPromise(this, api_context, exception);
  }

  Handle<String> specifier_str;
  MaybeHandle<String> maybe_specifier = Object::ToString(this, specifier);
  if (!maybe_specifier.ToHandle(&specifier_str)) {
    if (is_execution_terminating()) {
      return MaybeHandle<JSPromise>();
    }
    Handle<Object> exception(this->exception(), this);
    clear_exception();
    return NewRejectedPromise(this, api_context, exception);
  }
  DCHECK(!has_exception());

  v8::Local<v8::Promise> promise;
  Handle<FixedArray> import_attributes_array;
  if (!GetImportAttributesFromArgument(maybe_import_options_argument)
           .ToHandle(&import_attributes_array)) {
    if (is_execution_terminating()) {
      return MaybeHandle<JSPromise>();
    }
    Handle<Object> exception(this->exception(), this);
    clear_exception();
    return NewRejectedPromise(this, api_context, exception);
  }
  Handle<FixedArray> host_defined_options;
  Handle<Object> resource_name;
  if (maybe_referrer.is_null()) {
    host_defined_options = factory()->empty_fixed_array();
    resource_name = factory()->null_value();
  } else {
    DirectHandle<Script> referrer = maybe_referrer.ToHandleChecked();
    host_defined_options = handle(referrer->host_defined_options(), this);
    resource_name = handle(referrer->name(), this);
  }

  switch (phase) {
    case ModuleImportPhase::kEvaluation:
      // TODO(42204365): Deprecate HostImportModuleDynamicallyCallback once
      // HostImportModuleWithPhaseDynamicallyCallback is stable.
      API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          this, promise,
          host_import_module_dynamically_callback_(
              api_context, v8::Utils::ToLocal(host_defined_options),
              v8::Utils::ToLocal(resource_name),
              v8::Utils::ToLocal(specifier_str),
              ToApiHandle<v8::FixedArray>(import_attributes_array)),
          MaybeHandle<JSPromise>());
      break;
    case ModuleImportPhase::kSource:
      CHECK(v8_flags.js_source_phase_imports);
      CHECK_NOT_NULL(host_import_module_with_phase_dynamically_callback_);
      API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          this, promise,
          host_import_module_with_phase_dynamically_callback_(
              api_context, v8::Utils::ToLocal(host_defined_options),
              v8::Utils::ToLocal(resource_name),
              v8::Utils::ToLocal(specifier_str), phase,
              ToApiHandle<v8::FixedArray>(import_attributes_array)),
          MaybeHandle<JSPromise>());
      break;
    default:
      UNREACHABLE();
  }

  return v8::Utils::OpenHandle(*promise);
}

MaybeHandle<FixedArray> Isolate::GetImportAttributesFromArgument(
    MaybeHandle<Object> maybe_import_options_argument) {
  Handle<FixedArray> import_attributes_array = factory()->empty_fixed_array();
  Handle<Object> import_options_argument;
  if (!maybe_import_options_argument.ToHandle(&import_options_argument) ||
      IsUndefined(*import_options_argument)) {
    return import_attributes_array;
  }

  // The parser shouldn't have allowed the second argument to import() if
  // the flag wasn't enabled.
  DCHECK(v8_flags.harmony_import_attributes);

  if (!IsJSReceiver(*import_options_argument)) {
    this->Throw(
        *factory()->NewTypeError(MessageTemplate::kNonObjectImportArgument));
    return MaybeHandle<FixedArray>();
  }

  Handle<JSReceiver> import_options_argument_receiver =
      Cast<JSReceiver>(import_options_argument);

  Handle<Object> import_attributes_object;

  if (v8_flags.harmony_import_attributes) {
    Handle<Name> with_key = factory()->with_string();
    if (!JSReceiver::GetProperty(this, import_options_argument_receiver,
                                 with_key)
             .ToHandle(&import_attributes_object)) {
      // This can happen if the property has a getter function that throws
      // an error.
      return MaybeHandle<FixedArray>();
    }
  }

  // If there is no 'with' option in the options bag, it's not an error. Just do
  // the import() as if no attributes were provided.
  if (IsUndefined(*import_attributes_object)) return import_attributes_array;

  if (!IsJSReceiver(*import_attributes_object)) {
    this->Throw(
        *factory()->NewTypeError(MessageTemplate::kNonObjectAttributesOption));
    return MaybeHandle<FixedArray>();
  }

  Handle<JSReceiver> import_attributes_object_receiver =
      Cast<JSReceiver>(import_attributes_object);

  Handle<FixedArray> attribute_keys;
  if (!KeyAccumulator::GetKeys(this, import_attributes_object_receiver,
                               KeyCollectionMode::kOwnOnly, ENUMERABLE_STRINGS,
                               GetKeysConversion::kConvertToString)
           .ToHandle(&attribute_keys)) {
    // This happens if the attributes object is a Proxy whose ownKeys() or
    // getOwnPropertyDescriptor() trap throws.
    return MaybeHandle<FixedArray>();
  }

  bool has_non_string_attribute = false;

  // The attributes will be passed to the host in the form: [key1,
  // value1, key2, value2, ...].
  constexpr size_t kAttributeEntrySizeForDynamicImport = 2;
  import_attributes_array = factory()->NewFixedArray(static_cast<int>(
      attribute_keys->length() * kAttributeEntrySizeForDynamicImport));
  for (int i = 0; i < attribute_keys->length(); i++) {
    Handle<String> attribute_key(Cast<String>(attribute_keys->get(i)), this);
    Handle<Object> attribute_value;
    if (!Object::GetPropertyOrElement(this, import_attributes_object_receiver,
                                      attribute_key)
             .ToHandle(&attribute_value)) {
      // This can happen if the property has a getter function that throws
      // an error.
      return MaybeHandle<FixedArray>();
    }

    if (!IsString(*attribute_value)) {
      has_non_string_attribute = true;
    }

    import_attributes_array->set((i * kAttributeEntrySizeForDynamicImport),
                                 *attribute_key);
    import_attributes_array->set((i * kAttributeEntrySizeForDynamicImport) + 1,
                                 *attribute_value);
  }

  if (has_non_string_attribute) {
    this->Throw(*factory()->NewTypeError(
        MessageTemplate::kNonStringImportAttributeValue));
    return MaybeHandle<FixedArray>();
  }

  return import_attributes_array;
}

void Isolate::ClearKeptObjects() { heap()->ClearKeptObjects(); }

void Isolate::SetHostImportModuleDynamicallyCallback(
    HostImportModuleDynamicallyCallback callback) {
  host_import_module_dynamically_callback_ = callback;
}

void Isolate::SetHostImportModuleWithPhaseDynamicallyCallback(
    HostImportModuleWithPhaseDynamicallyCallback callback) {
  host_import_module_with_phase_dynamically_callback_ = callback;
}

MaybeHandle<JSObject> Isolate::RunHostInitializeImportMetaObjectCallback(
    Handle<SourceTextModule> module) {
  CHECK(IsTheHole(module->import_meta(kAcquireLoad), this));
  Handle<JSObject> import_meta = factory()->NewJSObjectWithNullProto();
  if (host_initialize_import_meta_object_callback_ != nullptr) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(native_context());
    host_initialize_import_meta_object_callback_(
        api_context, Utils::ToLocal(Cast<Module>(module)),
        v8::Local<v8::Object>::Cast(v8::Utils::ToLocal(import_meta)));
    if (has_exception()) return {};
  }
  return import_meta;
}

void Isolate::SetHostInitializeImportMetaObjectCallback(
    HostInitializeImportMetaObjectCallback callback) {
  host_initialize_import_meta_object_callback_ = callback;
}

void Isolate::SetHostCreateShadowRealmContextCallback(
    HostCreateShadowRealmContextCallback callback) {
  host_create_shadow_realm_context_callback_ = callback;
}

MaybeHandle<NativeContext> Isolate::RunHostCreateShadowRealmContextCallback() {
  if (host_create_shadow_realm_context_callback_ == nullptr) {
    DirectHandle<Object> exception =
        factory()->NewError(error_function(), MessageTemplate::kUnsupported);
    Throw(*exception);
    return kNullMaybeHandle;
  }

  v8::Local<v8::Context> api_context = v8::Utils::ToLocal(native_context());
  v8::Local<v8::Context> shadow_realm_context;
  API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      this, shadow_realm_context,
      host_create_shadow_realm_context_callback_(api_context),
      MaybeHandle<NativeContext>());
  Handle<Context> shadow_realm_context_handle =
      v8::Utils::OpenHandle(*shadow_realm_context);
  DCHECK(IsNativeContext(*shadow_realm_context_handle));
  shadow_realm_context_handle->set_scope_info(
      ReadOnlyRoots(this).shadow_realm_scope_info());
  return Cast<NativeContext>(shadow_realm_context_handle);
}

MaybeHandle<Object> Isolate::RunPrepareStackTraceCallback(
    Handle<NativeContext> context, Handle<JSObject> error,
    Handle<JSArray> sites) {
  v8::Local<v8::Context> api_context = Utils::ToLocal(context);

  v8::Local<v8::Value> stack;
  API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      this, stack,
      prepare_stack_trace_callback_(api_context, Utils::ToLocal(error),
                                    Utils::ToLocal(sites)),
      MaybeHandle<Object>());
  return Utils::OpenHandle(*stack);
}

int Isolate::LookupOrAddExternallyCompiledFilename(const char* filename) {
  if (embedded_file_writer_ != nullptr) {
    return embedded_file_writer_->LookupOrAddExternallyCompiledFilename(
        filename);
  }
  return 0;
}

const char* Isolate::GetExternallyCompiledFilename(int index) const {
  if (embedded_file_writer_ != nullptr) {
    return embedded_file_writer_->GetExternallyCompiledFilename(index);
  }
  return "";
}

int Isolate::GetExternallyCompiledFilenameCount() const {
  if (embedded_file_writer_ != nullptr) {
    return embedded_file_writer_->GetExternallyCompiledFilenameCount();
  }
  return 0;
}

void Isolate::PrepareBuiltinSourcePositionMap() {
  if (embedded_file_writer_ != nullptr) {
    return embedded_file_writer_->PrepareBuiltinSourcePositionMap(
        this->builtins());
  }
}

#if defined(V8_OS_WIN64)
void Isolate::SetBuiltinUnwindData(
    Builtin builtin,
    const win64_unwindinfo::BuiltinUnwindInfo& unwinding_info) {
  if (embedded_file_writer_ != nullptr) {
    embedded_file_writer_->SetBuiltinUnwindData(builtin, unwinding_info);
  }
}
#endif  // V8_OS_WIN64

void Isolate::SetPrepareStackTraceCallback(PrepareStackTraceCallback callback) {
  prepare_stack_trace_callback_ = callback;
}

bool Isolate::HasPrepareStackTraceCallback() const {
  return prepare_stack_trace_callback_ != nullptr;
}

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
void Isolate::SetFilterETWSessionByURLCallback(
    FilterETWSessionByURLCallback callback) {
  filter_etw_session_by_url_callback_ = callback;
}

bool Isolate::RunFilterETWSessionByURLCallback(
    const std::string& etw_filter_payload) {
  if (!filter_etw_session_by_url_callback_) return true;
  v8::Local<v8::Context> context = Utils::ToLocal(native_context());
  return filter_etw_session_by_url_callback_(context, etw_filter_payload);
}
#endif  // V8_OS_WIN && V8_ENABLE_ETW_STACK_WALKING

void Isolate::SetAddCrashKeyCallback(AddCrashKeyCallback callback) {
  add_crash_key_callback_ = callback;

  // Log the initial set of data.
  AddCrashKeysForIsolateAndHeapPointers();
}

void Isolate::SetAtomicsWaitCallback(v8::Isolate::AtomicsWaitCallback callback,
                                     void* data) {
  atomics_wait_callback_ = callback;
  atomics_wait_callback_data_ = data;
}

void Isolate::RunAtomicsWaitCallback(v8::Isolate::AtomicsWaitEvent event,
                                     Handle<JSArrayBuffer> array_buffer,
                                     size_t offset_in_bytes, int64_t value,
                                     double timeout_in_ms,
                                     AtomicsWaitWakeHandle* stop_handle) {
  DCHECK(array_buffer->is_shared());
  if (atomics_wait_callback_ == nullptr) return;
  HandleScope handle_scope(this);
  atomics_wait_callback_(
      event, v8::Utils::ToLocalShared(array_buffer), offset_in_bytes, value,
      timeout_in_ms,
      reinterpret_cast<v8::Isolate::AtomicsWaitWakeHandle*>(stop_handle),
      atomics_wait_callback_data_);
}

void Isolate::SetPromiseHook(PromiseHook hook) {
  promise_hook_ = hook;
  PromiseHookStateUpdated();
}

void Isolate::RunAllPromiseHooks(PromiseHookType type,
                                 Handle<JSPromise> promise,
                                 Handle<Object> parent) {
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  if (HasContextPromiseHooks()) {
    native_context()->RunPromiseHook(type, promise, parent);
  }
#endif
  if (HasIsolatePromiseHooks() || HasAsyncEventDelegate()) {
    RunPromiseHook(type, promise, parent);
  }
}

void Isolate::RunPromiseHook(PromiseHookType type, Handle<JSPromise> promise,
                             Handle<Object> parent) {
  if (!HasIsolatePromiseHooks()) return;
  DCHECK(promise_hook_ != nullptr);
  promise_hook_(type, v8::Utils::PromiseToLocal(promise),
                v8::Utils::ToLocal(parent));
}

void Isolate::OnAsyncFunctionSuspended(Handle<JSPromise> promise,
                                       Handle<JSPromise> parent) {
  DCHECK(!promise->has_async_task_id());
  RunAllPromiseHooks(PromiseHookType::kInit, promise, parent);
  if (HasAsyncEventDelegate()) {
    DCHECK_NE(nullptr, async_event_delegate_);
    current_async_task_id_ =
        JSPromise::GetNextAsyncTaskId(current_async_task_id_);
    promise->set_async_task_id(current_async_task_id_);
    async_event_delegate_->AsyncEventOccurred(debug::kDebugAwait,
                                              promise->async_task_id(), false);
  }
}

void Isolate::OnPromiseThen(DirectHandle<JSPromise> promise) {
  if (!HasAsyncEventDelegate()) return;
  Maybe<debug::DebugAsyncActionType> action_type =
      Nothing<debug::DebugAsyncActionType>();
  for (JavaScriptStackFrameIterator it(this); !it.done(); it.Advance()) {
    std::vector<Handle<SharedFunctionInfo>> infos;
    it.frame()->GetFunctions(&infos);
    for (auto it = infos.rbegin(); it != infos.rend(); ++it) {
      DirectHandle<SharedFunctionInfo> info = *it;
      if (info->HasBuiltinId()) {
        // We should not report PromiseThen and PromiseCatch which is called
        // indirectly, e.g. Promise.all calls Promise.then internally.
        switch (info->builtin_id()) {
          case Builtin::kPromisePrototypeCatch:
            action_type = Just(debug::kDebugPromiseCatch);
            continue;
          case Builtin::kPromisePrototypeFinally:
            action_type = Just(debug::kDebugPromiseFinally);
            continue;
          case Builtin::kPromisePrototypeThen:
            action_type = Just(debug::kDebugPromiseThen);
            continue;
          default:
            return;
        }
      }
      if (info->IsUserJavaScript() && action_type.IsJust()) {
        DCHECK(!promise->has_async_task_id());
        current_async_task_id_ =
            JSPromise::GetNextAsyncTaskId(current_async_task_id_);
        promise->set_async_task_id(current_async_task_id_);
        async_event_delegate_->AsyncEventOccurred(action_type.FromJust(),
                                                  promise->async_task_id(),
                                                  debug()->IsBlackboxed(info));
      }
      return;
    }
  }
}

void Isolate::OnPromiseBefore(Handle<JSPromise> promise) {
  RunPromiseHook(PromiseHookType::kBefore, promise,
                 factory()->undefined_value());
  if (HasAsyncEventDelegate()) {
    if (promise->has_async_task_id()) {
      async_event_delegate_->AsyncEventOccurred(
          debug::kDebugWillHandle, promise->async_task_id(), false);
    }
  }
}

void Isolate::OnPromiseAfter(Handle<JSPromise> promise) {
  RunPromiseHook(PromiseHookType::kAfter, promise,
                 factory()->undefined_
"""


```