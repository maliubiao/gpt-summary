Response:
Let's break down the thought process to analyze the provided C++ header file and answer the user's questions.

1. **Understand the Core Purpose:** The first thing to notice is the file name: `counters-definitions.h` and the presence of macros like `HISTOGRAM_RANGE_LIST`, `NESTED_TIMED_HISTOGRAM_LIST`, etc. The `#ifndef` and `#define` guards confirm it's a header file. The initial comment mentioning "logging" reinforces the idea that this file is about defining and managing performance metrics or events within the V8 engine.

2. **Identify the Main Mechanisms:** The `#define` statements with macros like `HISTOGRAM_RANGE_LIST(HR)` are key. This indicates a pattern for defining different types of counters or metrics. The `HR` parameter suggests these macros are meant to be expanded with specific counter definitions.

3. **Categorize the Counters:**  Scan through the different macros:
    * `HISTOGRAM_RANGE_LIST`:  Defines histograms with a range of values. Each entry seems to represent a specific performance aspect, like "code_cache_reject_reason" or "errors_thrown_per_context." The parameters (`name`, `caption`, `min`, `max`, `num_buckets`) are clearly defining the histogram's properties.
    * `NESTED_TIMED_HISTOGRAM_LIST` and `TIMED_HISTOGRAM_LIST`:  These are for time-based measurements. The `max` and `unit` parameters confirm this. The "Nested" version likely implies it can be used within a scope to measure durations of specific code blocks.
    * `AGGREGATABLE_HISTOGRAM_TIMER_LIST`:  Another timer-related macro, perhaps designed for aggregating timer values.
    * `HISTOGRAM_PERCENTAGE_LIST`:  Deals with percentage-based metrics.
    * `HISTOGRAM_LEGACY_MEMORY_LIST`:  Appears to be for memory-related samples, possibly with a fixed range.
    * `STATS_COUNTER_LIST`:  Simple counters for events or quantities.
    * `STATS_COUNTER_NATIVE_CODE_LIST`: Similar to the previous one, but specifically for counters incremented from native code.

4. **Infer Functionality:** Based on the counter categories and their names, we can infer the overall functionality of the file:
    * **Performance Monitoring:**  The majority of the counters relate to garbage collection, compilation times (including JIT and WebAssembly), memory usage, and other internal V8 operations.
    * **Debugging and Profiling:** The counters can be used to understand the behavior of the engine, identify bottlenecks, and track resource consumption.
    * **Code Caching Analysis:**  Counters related to code cache hits, misses, and reasons for rejection provide insights into the effectiveness of the caching mechanisms.
    * **WebAssembly Specific Metrics:** A significant number of counters are dedicated to WebAssembly, indicating a focus on monitoring its performance and resource usage.

5. **Address Specific Questions:**

    * **Is it Torque?** The file ends with `.h`, not `.tq`. So, it's a standard C++ header file, not a Torque source file.

    * **Relationship to JavaScript:**  Although the file is C++, the counters directly reflect the execution of JavaScript code. For example, `errors_thrown_per_context` directly relates to JavaScript exceptions. The performance of compilation and garbage collection directly impacts JavaScript execution speed. WebAssembly, while not strictly JavaScript, is often executed within a JavaScript environment in browsers.

    * **JavaScript Example:**  To illustrate the connection, think about `errors_thrown_per_context`. A simple JavaScript `try...catch` block can trigger this counter.

    * **Code Logic Inference (with Assumptions):**  Choose a relatively straightforward counter like `errors_thrown_per_context`. Assume the V8 engine has a mechanism to increment this counter whenever a JavaScript exception is caught or propagates to the top level. Provide example JavaScript code that would cause an exception and hypothesize how the counter would change.

    * **Common Programming Errors:** Focus on errors that would directly lead to an increase in specific counters. For instance, excessive string concatenation or creating many small objects could trigger garbage collection more frequently, affecting the GC-related counters. Errors in regular expressions could lead to excessive backtracking, affecting `regexp_backtracks`.

6. **Structure the Answer:** Organize the findings logically:

    * Start with a general summary of the file's purpose.
    * Explain the core mechanism (macros).
    * List the categories of counters and provide examples for each.
    * Address the specific questions about Torque, JavaScript relation, code logic, and common errors.
    * Provide JavaScript code examples and hypothetical inputs/outputs for the code logic inference.
    * Clearly illustrate common programming errors and link them to the relevant counters.

7. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas where more detail might be helpful. For instance, initially, I might not have explicitly stated *why* these counters are useful (performance analysis, debugging), and I would add that during the review. I might also initially forget to mention the `#ifndef` guard and would add that detail.
## 功能列举

`v8/src/logging/counters-definitions.h` 是 V8 引擎中一个非常重要的头文件，它的主要功能是 **定义各种性能计数器和直方图**。这些计数器和直方图用于 **监控 V8 引擎的运行时行为和性能指标**。

具体来说，这个文件定义了以下几种类型的统计数据：

* **范围直方图 (Range Histograms):**  用于记录特定事件发生的频率分布在不同的数值范围内。例如，`errors_thrown_per_context` 记录了每个上下文中抛出的错误数量的分布。
* **嵌套定时直方图 (Nested Timed Histograms):** 用于记录特定操作花费的时间，并允许在嵌套的执行流程中进行计时。
* **定时直方图 (Timed Histograms):**  用于记录特定事件或操作所花费的时间，例如垃圾回收的各个阶段、代码编译的时间等。
* **可聚合的直方图定时器列表 (Aggregatable Histogram Timer List):**  类似于定时直方图，但可能具有特殊的聚合特性。
* **百分比直方图 (Percentage Histograms):**  用于记录百分比相关的指标，例如堆内存的碎片率。
* **旧式的内存直方图 (Histogram Legacy Memory List):** 用于记录旧式的内存采样数据。
* **状态计数器 (Stats Counters):**  用于记录一些简单的计数，例如全局句柄的数量、编译缓存的命中率等。
* **原生代码状态计数器 (Stats Counter Native Code List):**  专门用于记录从 V8 的原生 C++ 代码中递增的计数器。

**总结来说，这个文件的核心作用是为 V8 引擎的性能监控和分析提供了一套预定义的指标框架。** 这些指标可以帮助开发者了解 V8 的运行状态，定位性能瓶颈，并进行优化。

## 关于文件后缀

如果 `v8/src/logging/counters-definitions.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 自研的领域特定语言 (DSL)，用于生成高效的 V8 内建函数和运行时代码。

当前的文件名是 `.h`，表明它是一个标准的 C++ 头文件。

## 与 JavaScript 功能的关系

`v8/src/logging/counters-definitions.h` 中定义的计数器和直方图 **与 JavaScript 的执行密切相关**。 这些指标反映了 V8 引擎在执行 JavaScript 代码时发生的各种事件和性能数据。

**JavaScript 示例：**

以下 JavaScript 代码的执行可能会影响 `counters-definitions.h` 中定义的某些计数器：

```javascript
// 可能会增加 errors_thrown_per_context 计数器
try {
  throw new Error("Something went wrong!");
} catch (e) {
  console.error(e);
}

// 可能会影响 gc_* 相关的定时直方图和状态计数器
let largeArray = new Array(1000000).fill(0);

// 可能会影响 compile_* 相关的定时直方图
function add(a, b) {
  return a + b;
}
add(1, 2); // 首次调用可能触发编译

// 可能影响 wasm_* 相关的计数器和直方图
// 前提是代码中使用了 WebAssembly
// 例如：
// fetch('module.wasm')
//   .then(response => response.arrayBuffer())
//   .then(bytes => WebAssembly.instantiate(bytes))
//   .then(results => {
//     results.instance.exports.exported_function();
//   });

// 可能影响 regexp_backtracks 计数器
const regex = /a*b/;
regex.test("aaaaaaaaaaaaaaaaaaaaaaaaac");
```

**解释：**

* **`errors_thrown_per_context`:** 当 JavaScript 代码抛出错误并被 `try...catch` 捕获时，或者未被捕获导致程序终止时，这个计数器可能会增加。
* **`gc_*` 相关的计数器和直方图:** 当 JavaScript 代码创建大量对象，导致内存压力增加时，会触发垃圾回收。垃圾回收的各个阶段（标记、清除、压缩等）的耗时会被记录在相应的定时直方图中。
* **`compile_*` 相关的直方图:**  V8 引擎在执行 JavaScript 代码时，会将代码编译成机器码以提高执行效率。编译的过程，包括解析、优化等阶段的耗时会被记录。
* **`wasm_*` 相关的计数器和直方图:** 如果 JavaScript 代码使用了 WebAssembly，那么加载、编译、实例化 WebAssembly 模块以及执行 WebAssembly 代码的相关信息会被记录。
* **`regexp_backtracks`:** 当执行复杂的正则表达式时，如果发生大量的回溯，这个计数器会增加。

## 代码逻辑推理

假设我们关注 `errors_thrown_per_context` 计数器。

**假设输入：**  一段 JavaScript 代码在一个 V8 上下文中执行，并抛出了 3 个未被捕获的错误。

**代码逻辑推断：**  V8 引擎内部会有一个机制来捕获 JavaScript 抛出的错误。当一个错误未被 `try...catch` 捕获并冒泡到事件循环时，V8 会递增与当前上下文关联的 `errors_thrown_per_context` 计数器的值。

**预期输出：**  `errors_thrown_per_context` 计数器对于该上下文的值会增加 3。

**更具体的代码逻辑（简化）：**

```c++
// 假设 V8 内部有这样的结构
struct ContextCounters {
  int errors_thrown;
  // ... 其他计数器
};

// 当 JavaScript 抛出未捕获的错误时调用的函数
void OnUncaughtException(ContextCounters* counters) {
  counters->errors_thrown++;
}

// 假设 JavaScript 执行过程中抛出了一个错误
// ...
OnUncaughtException(currentContext->counters);
// ...
```

## 用户常见的编程错误

一些常见的 JavaScript 编程错误可能会直接或间接地影响 `counters-definitions.h` 中定义的计数器：

1. **内存泄漏：**  持续创建对象但不释放，会导致堆内存持续增长，最终触发更频繁的垃圾回收（影响 `gc_*` 相关的计数器和直方图），甚至可能导致内存溢出错误。

   ```javascript
   // 错误的示例：持续创建对象但不清理
   let leakedObjects = [];
   setInterval(() => {
     leakedObjects.push(new Object()); // 对象不断增加
   }, 10);
   ```

2. **同步阻塞：**  执行耗时的同步操作会阻塞 JavaScript 主线程，可能导致 V8 引擎的调度延迟或其他性能问题。虽然这个文件里没有直接对应“阻塞”的计数器，但可能会间接影响例如编译时间等。

   ```javascript
   // 错误的示例：耗时的同步操作
   function sleep(ms) {
     const start = Date.now();
     while (Date.now() - start < ms);
   }
   sleep(5000); // 阻塞 5 秒
   ```

3. **低效的字符串操作：**  在循环中频繁使用 `+` 或 `concat` 连接字符串会创建大量临时字符串对象，增加垃圾回收的压力。

   ```javascript
   // 错误的示例：低效的字符串拼接
   let result = "";
   for (let i = 0; i < 10000; i++) {
     result += "some string"; // 每次都创建新的字符串
   }
   ```

4. **复杂的正则表达式：**  编写回溯严重的正则表达式会导致 `regexp_backtracks` 计数器急剧增加，并可能导致性能问题甚至拒绝服务攻击 (ReDoS)。

   ```javascript
   // 错误的示例：回溯严重的正则表达式
   const regex = /^(a+)+b$/;
   regex.test("aaaaaaaaaaaaaaaaaaaaaaaaac"); // 可能会花费很长时间
   ```

5. **频繁的错误抛出和捕获：**  在性能敏感的代码中频繁地抛出和捕获异常会带来额外的开销，可能增加 `errors_thrown_per_context` 计数器，并影响整体性能。虽然错误处理是必要的，但不应该被用于正常的控制流。

总而言之，`v8/src/logging/counters-definitions.h` 提供了一个观察 V8 引擎内部运行状态的窗口。理解这些计数器的含义可以帮助开发者更好地理解 JavaScript 代码的执行过程，并避免一些常见的性能陷阱。

Prompt: 
```
这是目录为v8/src/logging/counters-definitions.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/logging/counters-definitions.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_LOGGING_COUNTERS_DEFINITIONS_H_
#define V8_LOGGING_COUNTERS_DEFINITIONS_H_

#include "include/v8-internal.h"

namespace v8 {
namespace internal {

// Generic range histograms.
// HR(name, caption, min, max, num_buckets)
#define HISTOGRAM_RANGE_LIST(HR)                                               \
  HR(code_cache_reject_reason, V8.CodeCacheRejectReason, 1, 9, 9)              \
  HR(errors_thrown_per_context, V8.ErrorsThrownPerContext, 0, 200, 20)         \
  HR(incremental_marking_reason, V8.GCIncrementalMarkingReason, 0,             \
     kGarbageCollectionReasonMaxValue, kGarbageCollectionReasonMaxValue + 1)   \
  HR(incremental_marking_sum, V8.GCIncrementalMarkingSum, 0, 10000, 101)       \
  HR(mark_compact_reason, V8.GCMarkCompactReason, 0,                           \
     kGarbageCollectionReasonMaxValue, kGarbageCollectionReasonMaxValue + 1)   \
  HR(gc_finalize_clear, V8.GCFinalizeMC.Clear, 0, 10000, 101)                  \
  HR(gc_finalize_epilogue, V8.GCFinalizeMC.Epilogue, 0, 10000, 101)            \
  HR(gc_finalize_evacuate, V8.GCFinalizeMC.Evacuate, 0, 10000, 101)            \
  HR(gc_finalize_finish, V8.GCFinalizeMC.Finish, 0, 10000, 101)                \
  HR(gc_finalize_mark, V8.GCFinalizeMC.Mark, 0, 10000, 101)                    \
  HR(gc_finalize_prologue, V8.GCFinalizeMC.Prologue, 0, 10000, 101)            \
  HR(gc_finalize_sweep, V8.GCFinalizeMC.Sweep, 0, 10000, 101)                  \
  HR(gc_scavenger_scavenge_main, V8.GCScavenger.ScavengeMain, 0, 10000, 101)   \
  HR(gc_scavenger_scavenge_roots, V8.GCScavenger.ScavengeRoots, 0, 10000, 101) \
  /* Asm/Wasm. */                                                              \
  HR(wasm_functions_per_asm_module, V8.WasmFunctionsPerModule.asm, 1, 1000000, \
     51)                                                                       \
  HR(wasm_functions_per_wasm_module, V8.WasmFunctionsPerModule.wasm, 1,        \
     1000000, 51)                                                              \
  HR(array_buffer_big_allocations, V8.ArrayBufferLargeAllocations, 0, 4096,    \
     13)                                                                       \
  HR(array_buffer_new_size_failures, V8.ArrayBufferNewSizeFailures, 0, 4096,   \
     13)                                                                       \
  HR(shared_array_allocations, V8.SharedArrayAllocationSizes, 0, 4096, 13)     \
  HR(wasm_asm_huge_function_size_bytes, V8.WasmHugeFunctionSizeBytes.asm,      \
     100 * KB, GB, 51)                                                         \
  HR(wasm_wasm_huge_function_size_bytes, V8.WasmHugeFunctionSizeBytes.wasm,    \
     100 * KB, GB, 51)                                                         \
  HR(wasm_asm_module_size_bytes, V8.WasmModuleSizeBytes.asm, 1, GB, 51)        \
  HR(wasm_wasm_module_size_bytes, V8.WasmModuleSizeBytes.wasm, 1, GB, 51)      \
  HR(wasm_compile_huge_function_peak_memory_bytes,                             \
     V8.WasmCompileHugeFunctionPeakMemoryBytes, 1, GB, 51)                     \
  HR(asm_module_size_bytes, V8.AsmModuleSizeBytes, 1, GB, 51)                  \
  HR(compile_script_cache_behaviour, V8.CompileScript.CacheBehaviour, 0, 20,   \
     21)                                                                       \
  HR(wasm_memory_allocation_result, V8.WasmMemoryAllocationResult, 0, 3, 4)    \
  /* Committed code size per module, collected on GC. */                       \
  /* Older histogram, in MiB (0..1024MB). */                                   \
  HR(wasm_module_code_size_mb, V8.WasmModuleCodeSizeMiB, 0, 1024, 64)          \
  /* Newer histogram, in KiB (0..100MB). */                                    \
  HR(wasm_module_code_size_kb, V8.WasmModuleCodeSizeKiB, 0, 1024 * 100, 101)   \
  /* Metadata size per module, collected on GC. */                             \
  HR(wasm_module_metadata_size_kb, V8.WasmModuleMetadataSizeKiB, 0,            \
     1024 * 100, 101)                                                          \
  /* Metadata of the whole Wasm engine, collected on GC. */                    \
  HR(wasm_engine_metadata_size_kb, V8.WasmEngineMetadataSizeKiB, 0,            \
     1024 * 100, 101)                                                          \
  /* Percent of freed code size per module, collected on GC. */                \
  HR(wasm_module_freed_code_size_percent, V8.WasmModuleCodeSizePercentFreed,   \
     0, 100, 32)                                                               \
  /* Number of code GCs triggered per native module, collected on code GC. */  \
  HR(wasm_module_num_triggered_code_gcs,                                       \
     V8.WasmModuleNumberOfCodeGCsTriggered, 1, 128, 20)                        \
  /* The amount of executable Liftoff code flushed on emergency GCs for */     \
  /* allocations and on memory pressure. */                                    \
  HR(wasm_flushed_liftoff_code_size_bytes, V8.WasmFlushedLiftoffCodeSizeBytes, \
     0, GB, 101)                                                               \
  /* The size of flushed Liftoff meta data on emergency GCs for allocations */ \
  /* and on memory pressure. */                                                \
  HR(wasm_flushed_liftoff_metadata_size_bytes,                                 \
     V8.WasmFlushedLiftoffMetadataSizeBytes, 0, GB, 101)                       \
  /* Number of code spaces reserved per wasm module. */                        \
  HR(wasm_module_num_code_spaces, V8.WasmModuleNumberOfCodeSpaces, 1, 128, 20) \
  /* Number of deopts triggered in webassembly code. */                        \
  HR(wasm_deopts_executed, V8.WasmDeoptsExecutedCount, 0, 10000, 51)           \
  HR(wasm_deopts_per_function, V8.WasmDeoptsPerFunction, 0, 500, 21)           \
  /* Number of live modules per isolate. */                                    \
  HR(wasm_modules_per_isolate, V8.WasmModulesPerIsolate, 1, 1024, 30)          \
  /* Number of live modules per engine (i.e. whole process). */                \
  HR(wasm_modules_per_engine, V8.WasmModulesPerEngine, 1, 1024, 30)            \
  /* Bailout reason if Liftoff failed, or {kSuccess} (per function). */        \
  HR(liftoff_bailout_reasons, V8.LiftoffBailoutReasons, 0, 20, 21)             \
  /* Support for PKEYs/PKU by testing result of pkey_alloc(). */               \
  HR(wasm_memory_protection_keys_support, V8.WasmMemoryProtectionKeysSupport,  \
     0, 1, 2)                                                                  \
  /* Ticks observed in a single Turbofan compilation, in 1K. */                \
  HR(turbofan_ticks, V8.TurboFan1KTicks, 0, 100000, 200)                       \
  /* Backtracks observed in a single regexp interpreter execution. */          \
  /* The maximum of 100M backtracks takes roughly 2 seconds on my machine. */  \
  HR(regexp_backtracks, V8.RegExpBacktracks, 1, 100000000, 50)                 \
  /* Number of times a cache event is triggered for a wasm module. */          \
  HR(wasm_cache_count, V8.WasmCacheCount, 0, 100, 101)                         \
  /* Number of in-use external pointers in the external pointer table. */      \
  /* Counted after sweeping the table at the end of mark-compact GC. */        \
  HR(external_pointers_count, V8.SandboxedExternalPointersCount, 0,            \
     kMaxExternalPointers, 101)                                                \
  HR(code_pointers_count, V8.SandboxedCodePointersCount, 0, kMaxCodePointers,  \
     101)                                                                      \
  HR(trusted_pointers_count, V8.SandboxedTrustedPointersCount, 0,              \
     kMaxTrustedPointers, 101)                                                 \
  HR(cppheap_pointers_count, V8.SandboxedCppHeapPointersCount, 0,              \
     kMaxCppHeapPointers, 101)                                                 \
  HR(js_dispatch_table_entries_count, V8.JSDispatchTableEntriesCount, 0,       \
     kMaxJSDispatchEntries, 101)                                               \
  /* Outcome of external pointer table compaction: kSuccess, */                \
  /* kPartialSuccessor kAbortedDuringSweeping. See */                          \
  /* ExternalPointerTable::TableCompactionOutcome enum for more details. */    \
  HR(external_pointer_table_compaction_outcome,                                \
     V8.ExternalPointerTableCompactionOutcome, 0, 2, 3)                        \
  HR(wasm_compilation_method, V8.WasmCompilationMethod, 0, 4, 5)               \
  HR(asmjs_instantiate_result, V8.AsmjsInstantiateResult, 0, 1, 2)

#if V8_ENABLE_DRUMBRAKE
#define HISTOGRAM_RANGE_LIST_SLOW(HR)                                         \
  /* Percentage (*1000) of time spent running Wasm jitted code. */            \
  HR(wasm_jit_execution_ratio, V8.JitWasmExecutionPercentage, 0, 100000, 101) \
  HR(wasm_jit_execution_too_slow, V8.JitWasmExecutionTooSlow, 0, 100000, 101) \
  /* Percentage (*1000) of time spent running in the Wasm interpreter. */     \
  HR(wasm_jitless_execution_ratio, V8.JitlessWasmExecutionPercentage, 0,      \
     100000, 101)                                                             \
  HR(wasm_jitless_execution_too_slow, V8.JitlessWasmExecutionTooSlow, 0,      \
     100000, 101)
#endif  // V8_ENABLE_DRUMBRAKE

// Like TIMED_HISTOGRAM_LIST, but allows the use of NestedTimedHistogramScope.
// HT(name, caption, max, unit)
#define NESTED_TIMED_HISTOGRAM_LIST(HT)                                       \
  /* Garbage collection timers. */                                            \
  HT(gc_incremental_marking, V8.GCIncrementalMarking, 10000, MILLISECOND)     \
  HT(gc_incremental_marking_start, V8.GCIncrementalMarkingStart, 10000,       \
     MILLISECOND)                                                             \
  HT(gc_minor_incremental_marking_start, V8.GCMinorIncrementalMarkingStart,   \
     10000, MILLISECOND)                                                      \
  HT(gc_low_memory_notification, V8.GCLowMemoryNotification, 10000,           \
     MILLISECOND)                                                             \
  /* Compilation times. */                                                    \
  HT(collect_source_positions, V8.CollectSourcePositions, 1000000,            \
     MICROSECOND)                                                             \
  HT(compile, V8.CompileMicroSeconds, 1000000, MICROSECOND)                   \
  HT(compile_eval, V8.CompileEvalMicroSeconds, 1000000, MICROSECOND)          \
  /* Serialization as part of compilation (code caching). */                  \
  HT(compile_serialize, V8.CompileSerializeMicroSeconds, 100000, MICROSECOND) \
  HT(compile_deserialize, V8.CompileDeserializeMicroSeconds, 1000000,         \
     MICROSECOND)                                                             \
  /* Snapshot. */                                                             \
  HT(snapshot_decompress, V8.SnapshotDecompressMicroSeconds, 1000000,         \
     MICROSECOND)                                                             \
  HT(snapshot_deserialize_rospace, V8.SnapshotDeserializeRoSpaceMicroSeconds, \
     1000000, MICROSECOND)                                                    \
  HT(snapshot_deserialize_isolate, V8.SnapshotDeserializeIsolateMicroSeconds, \
     1000000, MICROSECOND)                                                    \
  HT(snapshot_deserialize_context, V8.SnapshotDeserializeContextMicroSeconds, \
     1000000, MICROSECOND)                                                    \
  /* ... and also see compile_deserialize above. */                           \
  /* Total compilation time incl. caching/parsing. */                         \
  HT(compile_script, V8.CompileScriptMicroSeconds, 1000000, MICROSECOND)

#define NESTED_TIMED_HISTOGRAM_LIST_SLOW(HT)                                \
  /* Total V8 time (including JS and runtime calls, exluding callbacks). */ \
  HT(execute, V8.ExecuteMicroSeconds, 1000000, MICROSECOND)

// Timer histograms, thread safe: HT(name, caption, max, unit)
#define TIMED_HISTOGRAM_LIST(HT)                                               \
  /* Garbage collection timers. */                                             \
  HT(gc_finalize_incremental_regular,                                          \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.Regular, 10000,          \
     MILLISECOND)                                                              \
  HT(gc_finalize_incremental_regular_foreground,                               \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.Regular.Foreground,      \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_incremental_regular_background,                               \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.Regular.Background,      \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_incremental_memory_reducing,                                  \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.ReduceMemory, 10000,     \
     MILLISECOND)                                                              \
  HT(gc_finalize_incremental_memory_reducing_foreground,                       \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.ReduceMemory.Foreground, \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_incremental_memory_reducing_background,                       \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.ReduceMemory.Background, \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_incremental_memory_measure,                                   \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.MeasureMemory, 10000,    \
     MILLISECOND)                                                              \
  HT(gc_finalize_incremental_memory_measure_foreground,                        \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.MeasureMemory            \
         .Foreground,                                                          \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_incremental_memory_measure_background,                        \
     V8.GC.Event.MainThread.Full.Finalize.Incremental.MeasureMemory            \
         .Background,                                                          \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_non_incremental_regular,                                      \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.Regular, 10000,       \
     MILLISECOND)                                                              \
  HT(gc_finalize_non_incremental_regular_foreground,                           \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.Regular.Foreground,   \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_non_incremental_regular_background,                           \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.Regular.Background,   \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_non_incremental_memory_reducing,                              \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.ReduceMemory, 10000,  \
     MILLISECOND)                                                              \
  HT(gc_finalize_non_incremental_memory_reducing_foreground,                   \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.ReduceMemory          \
         .Foreground,                                                          \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_non_incremental_memory_reducing_background,                   \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.ReduceMemory          \
         .Background,                                                          \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_non_incremental_memory_measure,                               \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.MeasureMemory, 10000, \
     MILLISECOND)                                                              \
  HT(gc_finalize_non_incremental_memory_measure_foreground,                    \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.MeasureMemory         \
         .Foreground,                                                          \
     10000, MILLISECOND)                                                       \
  HT(gc_finalize_non_incremental_memory_measure_background,                    \
     V8.GC.Event.MainThread.Full.Finalize.NonIncremental.MeasureMemory         \
         .Background,                                                          \
     10000, MILLISECOND)                                                       \
  HT(measure_memory_delay_ms, V8.MeasureMemoryDelayMilliseconds, 100000,       \
     MILLISECOND)                                                              \
  HT(gc_time_to_global_safepoint, V8.GC.TimeToGlobalSafepoint, 10000000,       \
     MICROSECOND)                                                              \
  HT(gc_time_to_safepoint, V8.GC.TimeToSafepoint, 10000000, MICROSECOND)       \
  HT(gc_time_to_collection_on_background, V8.GC.TimeToCollectionOnBackground,  \
     10000000, MICROSECOND)                                                    \
  /* Maglev timers. */                                                         \
  HT(maglev_optimize_prepare, V8.MaglevOptimizePrepare, 100000, MICROSECOND)   \
  HT(maglev_optimize_execute, V8.MaglevOptimizeExecute, 100000, MICROSECOND)   \
  HT(maglev_optimize_finalize, V8.MaglevOptimizeFinalize, 100000, MICROSECOND) \
  HT(maglev_optimize_total_time, V8.MaglevOptimizeTotalTime, 1000000,          \
     MICROSECOND)                                                              \
  /* TurboFan timers. */                                                       \
  HT(turbofan_optimize_prepare, V8.TurboFanOptimizePrepare, 1000000,           \
     MICROSECOND)                                                              \
  HT(turbofan_optimize_execute, V8.TurboFanOptimizeExecute, 1000000,           \
     MICROSECOND)                                                              \
  HT(turbofan_optimize_finalize, V8.TurboFanOptimizeFinalize, 1000000,         \
     MICROSECOND)                                                              \
  HT(turbofan_optimize_total_foreground, V8.TurboFanOptimizeTotalForeground,   \
     10000000, MICROSECOND)                                                    \
  HT(turbofan_optimize_total_background, V8.TurboFanOptimizeTotalBackground,   \
     10000000, MICROSECOND)                                                    \
  HT(turbofan_optimize_total_time, V8.TurboFanOptimizeTotalTime, 10000000,     \
     MICROSECOND)                                                              \
  HT(turbofan_optimize_non_concurrent_total_time,                              \
     V8.TurboFanOptimizeNonConcurrentTotalTime, 10000000, MICROSECOND)         \
  HT(turbofan_optimize_concurrent_total_time,                                  \
     V8.TurboFanOptimizeConcurrentTotalTime, 10000000, MICROSECOND)            \
  HT(turbofan_osr_prepare, V8.TurboFanOptimizeForOnStackReplacementPrepare,    \
     1000000, MICROSECOND)                                                     \
  HT(turbofan_osr_execute, V8.TurboFanOptimizeForOnStackReplacementExecute,    \
     1000000, MICROSECOND)                                                     \
  HT(turbofan_osr_finalize, V8.TurboFanOptimizeForOnStackReplacementFinalize,  \
     1000000, MICROSECOND)                                                     \
  HT(turbofan_osr_total_time,                                                  \
     V8.TurboFanOptimizeForOnStackReplacementTotalTime, 10000000, MICROSECOND) \
  /* Wasm timers. */                                                           \
  HT(wasm_compile_asm_module_time, V8.WasmCompileModuleMicroSeconds.asm,       \
     10000000, MICROSECOND)                                                    \
  HT(wasm_compile_wasm_module_time, V8.WasmCompileModuleMicroSeconds.wasm,     \
     10000000, MICROSECOND)                                                    \
  HT(wasm_async_compile_wasm_module_time,                                      \
     V8.WasmCompileModuleAsyncMicroSeconds, 100000000, MICROSECOND)            \
  HT(wasm_streaming_compile_wasm_module_time,                                  \
     V8.WasmCompileModuleStreamingMicroSeconds, 100000000, MICROSECOND)        \
  HT(wasm_streaming_finish_wasm_module_time,                                   \
     V8.WasmFinishModuleStreamingMicroSeconds, 100000000, MICROSECOND)         \
  HT(wasm_deserialization_time, V8.WasmDeserializationTimeMilliSeconds, 10000, \
     MILLISECOND)                                                              \
  HT(wasm_compile_asm_function_time, V8.WasmCompileFunctionMicroSeconds.asm,   \
     1000000, MICROSECOND)                                                     \
  HT(wasm_compile_wasm_function_time, V8.WasmCompileFunctionMicroSeconds.wasm, \
     1000000, MICROSECOND)                                                     \
  HT(wasm_compile_huge_function_time, V8.WasmCompileHugeFunctionMilliSeconds,  \
     100000, MILLISECOND)                                                      \
  HT(wasm_instantiate_wasm_module_time,                                        \
     V8.WasmInstantiateModuleMicroSeconds.wasm, 10000000, MICROSECOND)         \
  HT(wasm_instantiate_asm_module_time,                                         \
     V8.WasmInstantiateModuleMicroSeconds.asm, 10000000, MICROSECOND)          \
  HT(wasm_lazy_compile_time, V8.WasmLazyCompileTimeMicroSeconds, 100000000,    \
     MICROSECOND)                                                              \
  HT(wasm_compile_after_deserialize,                                           \
     V8.WasmCompileAfterDeserializeMilliSeconds, 1000000, MILLISECOND)         \
  /* Total compilation time incl. caching/parsing for various cache states. */ \
  HT(compile_script_with_produce_cache,                                        \
     V8.CompileScriptMicroSeconds.ProduceCache, 1000000, MICROSECOND)          \
  HT(compile_script_with_isolate_cache_hit,                                    \
     V8.CompileScriptMicroSeconds.IsolateCacheHit, 1000000, MICROSECOND)       \
  HT(compile_script_with_consume_cache,                                        \
     V8.CompileScriptMicroSeconds.ConsumeCache, 1000000, MICROSECOND)          \
  HT(compile_script_consume_failed,                                            \
     V8.CompileScriptMicroSeconds.ConsumeCache.Failed, 1000000, MICROSECOND)   \
  HT(compile_script_no_cache_other,                                            \
     V8.CompileScriptMicroSeconds.NoCache.Other, 1000000, MICROSECOND)         \
  HT(compile_script_no_cache_because_inline_script,                            \
     V8.CompileScriptMicroSeconds.NoCache.InlineScript, 1000000, MICROSECOND)  \
  HT(compile_script_no_cache_because_script_too_small,                         \
     V8.CompileScriptMicroSeconds.NoCache.ScriptTooSmall, 1000000,             \
     MICROSECOND)                                                              \
  HT(compile_script_no_cache_because_cache_too_cold,                           \
     V8.CompileScriptMicroSeconds.NoCache.CacheTooCold, 1000000, MICROSECOND)  \
  HT(compile_script_streaming_finalization,                                    \
     V8.CompileScriptMicroSeconds.StreamingFinalization, 1000000, MICROSECOND) \
  HT(compile_script_on_background,                                             \
     V8.CompileScriptMicroSeconds.BackgroundThread, 1000000, MICROSECOND)      \
  HT(compile_function_on_background,                                           \
     V8.CompileFunctionMicroSeconds.BackgroundThread, 1000000, MICROSECOND)    \
  HT(deserialize_script_on_background,                                         \
     V8.CompileScriptMicroSeconds.ConsumeCache.BackgroundThread, 1000000,      \
     MICROSECOND)                                                              \
  /* Debugger timers. */                                                       \
  HT(debug_pause_to_paused_event, V8.DebugPauseToPausedEventMilliSeconds,      \
     1000000, MILLISECOND)

#define AGGREGATABLE_HISTOGRAM_TIMER_LIST(AHT) \
  AHT(compile_lazy, V8.CompileLazyMicroSeconds)

#define HISTOGRAM_PERCENTAGE_LIST(HP)                                          \
  /* Heap fragmentation. */                                                    \
  HP(external_fragmentation_total, V8.MemoryExternalFragmentationTotal)        \
  HP(external_fragmentation_old_space, V8.MemoryExternalFragmentationOldSpace) \
  HP(external_fragmentation_code_space,                                        \
     V8.MemoryExternalFragmentationCodeSpace)                                  \
  HP(external_fragmentation_map_space, V8.MemoryExternalFragmentationMapSpace) \
  HP(external_fragmentation_lo_space, V8.MemoryExternalFragmentationLoSpace)

// Note: These use Histogram with options (min=1000, max=500000, buckets=50).
#define HISTOGRAM_LEGACY_MEMORY_LIST(HM)                                      \
  HM(heap_sample_total_committed, V8.MemoryHeapSampleTotalCommitted)          \
  HM(heap_sample_total_used, V8.MemoryHeapSampleTotalUsed)                    \
  HM(heap_sample_map_space_committed, V8.MemoryHeapSampleMapSpaceCommitted)   \
  HM(heap_sample_code_space_committed, V8.MemoryHeapSampleCodeSpaceCommitted) \
  HM(heap_sample_maximum_committed, V8.MemoryHeapSampleMaximumCommitted)

#define STATS_COUNTER_LIST(SC)                                                 \
  /* Global handle count. */                                                   \
  SC(global_handles, V8.GlobalHandles)                                         \
  SC(alive_after_last_gc, V8.AliveAfterLastGC)                                 \
  SC(compilation_cache_hits, V8.CompilationCacheHits)                          \
  SC(compilation_cache_misses, V8.CompilationCacheMisses)                      \
  /* Number of times the cache contained a reusable Script but not */          \
  /* the root SharedFunctionInfo. */                                           \
  SC(compilation_cache_partial_hits, V8.CompilationCachePartialHits)           \
  SC(objs_since_last_young, V8.ObjsSinceLastYoung)                             \
  SC(objs_since_last_full, V8.ObjsSinceLastFull)                               \
  SC(gc_compactor_caused_by_request, V8.GCCompactorCausedByRequest)            \
  SC(gc_compactor_caused_by_promoted_data, V8.GCCompactorCausedByPromotedData) \
  SC(gc_compactor_caused_by_oldspace_exhaustion,                               \
     V8.GCCompactorCausedByOldspaceExhaustion)                                 \
  SC(enum_cache_hits, V8.EnumCacheHits)                                        \
  SC(enum_cache_misses, V8.EnumCacheMisses)                                    \
  SC(maps_created, V8.MapsCreated)                                             \
  SC(megamorphic_stub_cache_updates, V8.MegamorphicStubCacheUpdates)           \
  SC(regexp_entry_runtime, V8.RegExpEntryRuntime)                              \
  SC(stack_interrupts, V8.StackInterrupts)                                     \
  SC(new_space_bytes_available, V8.MemoryNewSpaceBytesAvailable)               \
  SC(new_space_bytes_committed, V8.MemoryNewSpaceBytesCommitted)               \
  SC(new_space_bytes_used, V8.MemoryNewSpaceBytesUsed)                         \
  SC(old_space_bytes_available, V8.MemoryOldSpaceBytesAvailable)               \
  SC(old_space_bytes_committed, V8.MemoryOldSpaceBytesCommitted)               \
  SC(old_space_bytes_used, V8.MemoryOldSpaceBytesUsed)                         \
  SC(code_space_bytes_available, V8.MemoryCodeSpaceBytesAvailable)             \
  SC(code_space_bytes_committed, V8.MemoryCodeSpaceBytesCommitted)             \
  SC(code_space_bytes_used, V8.MemoryCodeSpaceBytesUsed)                       \
  SC(map_space_bytes_available, V8.MemoryMapSpaceBytesAvailable)               \
  SC(map_space_bytes_committed, V8.MemoryMapSpaceBytesCommitted)               \
  SC(map_space_bytes_used, V8.MemoryMapSpaceBytesUsed)                         \
  SC(lo_space_bytes_available, V8.MemoryLoSpaceBytesAvailable)                 \
  SC(lo_space_bytes_committed, V8.MemoryLoSpaceBytesCommitted)                 \
  SC(lo_space_bytes_used, V8.MemoryLoSpaceBytesUsed)                           \
  SC(wasm_generated_code_size, V8.WasmGeneratedCodeBytes)                      \
  SC(wasm_reloc_size, V8.WasmRelocBytes)                                       \
  SC(wasm_deopt_data_size, V8.WasmDeoptDataBytes)                              \
  SC(wasm_lazily_compiled_functions, V8.WasmLazilyCompiledFunctions)           \
  SC(wasm_compiled_export_wrapper, V8.WasmCompiledExportWrappers)

// List of counters that can be incremented from generated code. We need them in
// a separate list to be able to relocate them.
#define STATS_COUNTER_NATIVE_CODE_LIST(SC)                         \
  /* Number of write barriers executed at runtime. */              \
  SC(write_barriers, V8.WriteBarriers)                             \
  SC(regexp_entry_native, V8.RegExpEntryNative)                    \
  SC(megamorphic_stub_cache_probes, V8.MegamorphicStubCacheProbes) \
  SC(megamorphic_stub_cache_misses, V8.MegamorphicStubCacheMisses)

}  // namespace internal
}  // namespace v8

#endif  // V8_LOGGING_COUNTERS_DEFINITIONS_H_

"""

```