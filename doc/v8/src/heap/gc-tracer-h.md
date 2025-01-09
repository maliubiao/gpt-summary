Response:
Let's break down the thought process for analyzing the `gc-tracer.h` file.

1. **Initial Understanding of the File Name and Path:**  The path `v8/src/heap/gc-tracer.h` immediately suggests this file is related to garbage collection (`gc`) and performance monitoring (`tracer`) within the V8 JavaScript engine's heap management system. The `.h` extension confirms it's a C++ header file, likely defining a class or set of related structures and functions.

2. **Skimming the Copyright and Includes:** The copyright notice indicates it's part of the V8 project. The `#include` directives reveal dependencies on other V8 components (`include/v8-metrics.h`, `src/base/...`, `src/common/...`, `src/heap/...`, `src/logging/...`) and external testing frameworks (`testing/gtest/...`). This reinforces the idea that this is a core part of V8's internal workings.

3. **Identifying Key Structures and Enums:**  A quick scan reveals several important elements:
    * **Enums:** `YoungGenerationSpeedMode`, `GCTracer::Scope::ScopeId`, `GCTracer::Event::Type`, `GCTracer::Event::State`, `GCTracer::RecordGCPhasesInfo::Mode`. These suggest different modes of operation, specific events being tracked, and states within a garbage collection cycle.
    * **Classes:** `GCTracer::IncrementalInfos`, `GCTracer::Scope`, `GCTracer::Event`, `GCTracer::RecordGCPhasesInfo`. The `GCTracer` class itself is clearly the central component. The nested classes represent related data or functionality.
    * **Macros:** `TRACE_GC_CATEGORIES`, `TRACE_GC`, `TRACE_GC_ARG1`, etc. These likely provide a mechanism for logging and performance tracing during garbage collection.

4. **Focusing on the `GCTracer` Class:** This is the core of the file. I'd then go through its members:
    * **Public Methods:**  Methods like `StartCycle`, `StopCycle`, `StartAtomicPause`, `StopAtomicPause`, `SampleAllocation`,  `AddIncrementalMarkingStep`, and the various `...SpeedInBytesPerMillisecond` functions immediately suggest the core responsibilities of the `GCTracer`:  tracking GC events, timing them, and calculating performance metrics. The `Notify...Completed` methods indicate interaction with different stages of the GC process.
    * **Public Nested Classes:** The nested classes provide further details:
        * `IncrementalInfos`:  Tracks details about incremental GC steps.
        * `Scope`: Represents a timed block of code within the GC process. The `ScopeId` enum is crucial for understanding the different phases being tracked.
        * `Event`:  Holds detailed information about a single GC cycle. The `Type` and `State` enums here are critical.
        * `RecordGCPhasesInfo`:  Deals with recording GC phase timings for histograms.
    * **Private Members:**  These hint at the internal state of the tracer: `current_`, `previous_`, `epoch_young_`, `epoch_full_`, various speed and timing variables, and buffers for storing historical data.

5. **Connecting the Dots - Understanding the Workflow:** By examining the public methods and the structure of the `Event` class, a general picture of how the tracer works starts to emerge:
    * A GC cycle begins with `StartCycle`.
    * Different phases of the GC are marked using `Scope` objects (created using the `TRACE_GC` macros).
    * Atomic pauses are marked by `StartAtomicPause` and `StopAtomicPause`.
    * Allocation events are captured by `SampleAllocation`.
    * Incremental marking steps are recorded via `AddIncrementalMarkingStep`.
    * The cycle ends with `StopCycle`.
    * The `Event` object accumulates information about the cycle, and this information is likely used for logging and performance analysis.

6. **Analyzing the Macros:** The `TRACE_GC` family of macros is clearly used for instrumenting the code. They likely create `Scope` objects and use some underlying tracing mechanism (potentially the `TRACE_EVENT0`, `TRACE_EVENT1`, `TRACE_EVENT_WITH_FLOW0` functions) to record the start and end of these scopes, along with associated data. The `UNIQUE_IDENTIFIER` part is a common C++ trick to avoid naming conflicts.

7. **Considering the "If .tq" Clause:**  The statement about `.tq` files being Torque source code requires knowledge about V8's build system. Recognizing Torque's role in V8's implementation details is important here. If the file *were* a `.tq` file, the analysis would shift towards understanding the more low-level, type-safe implementation details of the GC.

8. **Relating to JavaScript Functionality:**  This requires understanding *why* V8 needs a GC tracer. The GC is fundamental to JavaScript's memory management. Therefore, any JavaScript code that allocates objects (which is almost all of it) will be indirectly affected by the GC and hence, the `GCTracer`. Simple examples involving object creation and long-running scripts are relevant here.

9. **Code Logic Reasoning and Examples:**  This involves picking specific methods and imagining how they would work. For instance, `SampleAllocation` likely calculates the difference in allocation counters since the last call. The `...SpeedInBytesPerMillisecond` methods would involve dividing the amount of work done (bytes processed, objects collected) by the time taken. Hypothetical inputs and outputs help illustrate these calculations.

10. **Identifying Common Programming Errors:**  This involves thinking about how developers might misunderstand or cause issues related to garbage collection. Memory leaks (holding onto objects unnecessarily) and performance issues due to excessive object creation are prime examples.

11. **Structuring the Answer:** Finally, organizing the gathered information into a clear and structured answer is crucial. Using headings like "Functionality," "Torque Source Code," "Relationship with JavaScript," etc., makes the information easier to understand. Providing code examples and clear explanations enhances the value of the analysis.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the tracer directly *controls* the GC.
* **Correction:**  The name "tracer" suggests it's primarily for *observing* and *recording* what the GC is doing, rather than actively managing it.
* **Initial thought:** The macros are just simple logging.
* **Refinement:** The `TRACE_EVENT_WITH_FLOW` macros indicate the ability to track asynchronous operations or related events across different parts of the system.
* **Initial thought:** The JavaScript examples should be complex.
* **Refinement:** Simple examples effectively demonstrate the core concept of the GC being triggered by JavaScript actions.

By following this thought process, moving from general understanding to specific details, and constantly connecting the pieces, a comprehensive analysis of the `gc-tracer.h` file can be achieved.
这是一个V8源代码文件，位于 `v8/src/heap/gc-tracer.h`，它定义了 `GCTracer` 类及其相关的结构体和枚举。`GCTracer` 的主要功能是 **追踪和记录垃圾回收（Garbage Collection，GC）过程中的各种事件和性能数据**。

以下是 `gc-tracer.h` 中定义的功能的详细列表：

**1. 追踪 GC 事件和状态:**

* **`GCTracer::Event` 类:**  定义了用于存储单个 GC 事件信息的结构体，包括：
    * **`Type` 枚举:**  标识 GC 的类型 (Scavenger, Mark Compactor, Incremental Mark Compactor, Minor Mark Sweeper 等)。
    * **`State` 枚举:**  表示 GC 周期中的状态 (NOT_RUNNING, MARKING, ATOMIC, SWEEPING)。
    * GC 的原因 (`gc_reason`) 和收集器的原因 (`collector_reason`)。
    * GC 期间的优先级 (`priority`).
    * GC 开始和结束的时间戳 (`start_time`, `end_time`).
    * 内存使用情况 (开始和结束时的对象大小、内存大小、空洞大小等)。
    * 年轻代对象的大小和存活对象的大小。
    * 增量标记的字节数和持续时间。
    * 原子暂停的开始和结束时间戳。
    * 在不同 GC 阶段花费的时间 (`scopes` 数组)。
    * 增量 GC 阶段的详细信息 (`incremental_scopes` 数组)。
* **`StartCycle()`, `StopCycle()` 方法:**  用于标记一个 GC 周期的开始和结束，并创建和填充 `GCTracer::Event` 对象。
* **`StartAtomicPause()`, `StopAtomicPause()` 方法:**  用于标记 GC 周期中原子暂停的开始和结束。

**2. 记录 GC 阶段的耗时:**

* **`GCTracer::Scope` 类:**  用于创建一个作用域对象，在对象创建时记录开始时间，在对象销毁时记录结束时间，并计算该作用域内的耗时。
* **`TRACE_GC`, `TRACE_GC_ARG1`, `TRACE_GC_EPOCH` 等宏:**  简化了在代码中创建 `GCTracer::Scope` 对象的过程，并同时发出 tracing 事件，方便性能分析工具进行可视化。这些宏允许开发者在代码的关键 GC 阶段添加计时点。
* **`AddScopeSample()` 方法:**  用于手动添加特定 GC 作用域的耗时。
* **`RecordGCPhasesHistograms()` 方法:**  用于记录 GC 各个阶段的耗时到直方图中，方便进行性能统计分析。

**3. 记录和计算 GC 相关的性能指标:**

* **吞吐量计算:**
    * `NewSpaceAllocationThroughputInBytesPerMillisecond()`: 新生代分配吞吐量。
    * `OldGenerationAllocationThroughputInBytesPerMillisecond()`: 老年代分配吞吐量。
    * `EmbedderAllocationThroughputInBytesPerMillisecond()`:  嵌入器（例如，使用 V8 的应用程序）分配的吞吐量。
    * `AllocationThroughputInBytesPerMillisecond()`:  总的分配吞吐量。
* **GC 速度计算:**
    * `IncrementalMarkingSpeedInBytesPerMillisecond()`:  增量标记的速度。
    * `EmbedderSpeedInBytesPerMillisecond()`:  嵌入器辅助标记的速度。
    * `YoungGenerationSpeedInBytesPerMillisecond()`:  年轻代 GC 的速度。
    * `CompactionSpeedInBytesPerMillisecond()`:  压缩的速度。
    * `MarkCompactSpeedInBytesPerMillisecond()`:  标记-压缩 GC 的速度。
    * `FinalIncrementalMarkCompactSpeedInBytesPerMillisecond()`:  增量标记-压缩 GC 完成阶段的速度。
    * `OldGenerationSpeedInBytesPerMillisecond()`:  老年代 GC 的整体速度。
* **存活率计算:**
    * `AverageSurvivalRatio()`:  计算平均存活率。
    * `SurvivalEventsRecorded()`:  检查是否记录了存活事件。
    * `AddSurvivalRatio()`:  添加存活率数据点。
* **并发性估计:**
    * `SampleConcurrencyEsimate()`:  记录并发线程的估计数量。
* **增量标记步骤记录:**
    * `AddIncrementalMarkingStep()`:  记录增量标记的步骤信息（持续时间和标记的字节数）。
    * `AddIncrementalSweepingStep()`: 记录增量清理的步骤信息。
* **代码刷新增加:**
    * `CodeFlushingIncrease()`:  返回当前周期的代码刷新增加量。
* **Mutator 利用率:**
    * `AverageMarkCompactMutatorUtilization()`:  计算标记-压缩 GC 的平均 Mutator 利用率。
    * `CurrentMarkCompactMutatorUtilization()`: 计算当前的标记-压缩 GC 的 Mutator 利用率。
* **记录嵌入器标记速度:**
    * `RecordEmbedderMarkingSpeed()`: 记录嵌入器辅助标记的速度。
* **记录调度到执行增量标记任务的时间:**
    * `AverageTimeToIncrementalMarkingTask()`: 计算平均时间。
    * `RecordTimeToIncrementalMarkingTask()`: 记录时间。

**4. 与外部系统集成:**

* **`v8::metrics::GarbageCollectionFullMainThreadBatchedIncrementalMark/Sweep`:**  用于将增量标记和清理事件批量报告给 V8 的指标系统。
* **`TRACE_EVENT0`, `TRACE_EVENT1`, `TRACE_EVENT_WITH_FLOW0` 等宏:**  利用 Chromium 的 tracing 机制，将 GC 事件记录下来，可以用于 Chrome DevTools 的性能分析。

**5. 其他辅助功能:**

* **`CurrentEpoch()`:**  获取当前的 GC 轮次。
* **`UpdateCurrentEvent()`:**  更新当前 GC 事件的信息。
* **`ResetSurvivalEvents()`:**  重置存活事件记录。
* **`NotifyFullSweepingCompleted()`, `NotifyYoungSweepingCompleted()`, `NotifyFullCppGCCompleted()`, `NotifyYoungCppGCRunning()`, `NotifyYoungCppGCCompleted()`:**  用于在 GC 的不同阶段发出通知，特别是在涉及 CppGC 的情况下。
* **`IsInObservablePause()`, `IsInAtomicPause()`, `IsConsistentWithCollector()`, `IsSweepingInProgress()` (DEBUG only):**  提供调试期间的断言和状态检查。
* **`PrintNVP()`, `Print()`, `Output()`:**  用于输出 GC 追踪信息到日志或控制台。

**如果 `v8/src/heap/gc-tracer.h` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现 V8 的内置函数和运行时。在这种情况下，该文件将包含使用 Torque 语法编写的 `GCTracer` 或相关功能的实现逻辑。Torque 代码会被编译成 C++ 代码，然后与 V8 的其他部分一起编译。

**与 JavaScript 功能的关系 (举例说明):**

`GCTracer` 直接关联着 JavaScript 的内存管理。当 JavaScript 代码创建对象、调用函数、执行各种操作时，V8 的垃圾回收器会在后台定期运行，回收不再使用的内存。`GCTracer` 负责记录这些 GC 行为的各种细节，帮助 V8 团队和开发者理解 GC 的性能，找出瓶颈，并进行优化。

**JavaScript 示例:**

```javascript
// 创建大量对象
let objects = [];
for (let i = 0; i < 1000000; i++) {
  objects.push({ value: i });
}

// 执行一些操作
for (let i = 0; i < objects.length; i++) {
  objects[i].value += 1;
}

// 清空引用，使对象可以被垃圾回收
objects = null;

// 此时，V8 的垃圾回收器可能会开始工作，回收之前创建的对象占用的内存。
// GCTracer 会记录这次 GC 的类型、耗时、回收的内存大小等信息。
```

在这个例子中，当 `objects = null` 后，之前 `objects` 数组引用的那些对象就变得不可达了。V8 的 GC 会识别出这些不再使用的对象，并将它们占用的内存回收。`GCTracer` 会记录这个回收过程的各种细节，例如是 Scavenger 还是 Mark Compactor 进行了回收，回收花费了多少时间，回收了多少内存等等。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `AddIncrementalMarkingStep(5.2, 10240)`，其中 `5.2` 是增量标记步骤的持续时间（毫秒），`10240` 是标记的字节数。

**假设输入:**

* `duration` (double): 5.2
* `bytes` (size_t): 10240

**代码逻辑 (推测):**

在 `AddIncrementalMarkingStep` 方法内部，可能会进行以下操作：

1. 记录本次增量标记的持续时间和字节数到 `current_` 事件的 `incremental_marking_duration` 和 `incremental_marking_bytes` 字段。
2. 更新 `incremental_scopes_` 数组中对应增量标记阶段的统计信息（例如，总耗时、最长步骤耗时、步骤数）。
3. 将这些信息记录到 tracing 系统，以便在性能分析工具中查看。

**可能的输出 (记录在 `current_` 事件中):**

* `current_.incremental_marking_duration` 增加 5.2 毫秒。
* `current_.incremental_marking_bytes` 增加 10240 字节。
* `current_.incremental_scopes_[MC_INCREMENTAL].duration` 增加 5.2 毫秒。
* `current_.incremental_scopes_[MC_INCREMENTAL].steps` 增加 1。
* 如果本次步骤的持续时间大于之前记录的最长步骤，则更新 `current_.incremental_scopes_[MC_INCREMENTAL].longest_step`。

**用户常见的编程错误 (举例说明):**

一个与 GC 追踪相关的常见编程错误是 **创建大量的临时对象而没有及时释放引用**。这会导致 GC 频繁触发，并且每次 GC 可能需要处理大量的对象，从而影响性能。

**JavaScript 示例 (造成大量临时对象):**

```javascript
function processData(data) {
  let result = [];
  for (let i = 0; i < data.length; i++) {
    // 每次循环都创建一个新的临时对象
    let temp = { index: i, value: data[i] * 2 };
    result.push(temp);
  }
  return result;
}

let largeData = Array(100000).fill(1);
let processedData = processData(largeData);
```

在这个例子中，`processData` 函数在每次循环迭代时都会创建一个新的对象 `temp`。如果 `largeData` 非常大，这将导致创建大量的临时对象。虽然这些对象在函数执行结束后会变成垃圾，但过多的短期对象会增加 GC 的压力，`GCTracer` 会记录下这种频繁的 GC 行为，提示开发者可能需要优化代码，例如避免在循环中过度创建临时对象。

另一个例子是 **意外地保持对不再需要的对象的引用**，导致内存泄漏，使得 GC 无法回收这些内存。`GCTracer` 可以帮助分析内存使用情况，从而发现潜在的内存泄漏问题。

总而言之，`v8/src/heap/gc-tracer.h` 定义的 `GCTracer` 类是 V8 垃圾回收机制的重要组成部分，它负责监控和记录 GC 的行为，为性能分析和优化提供关键的数据支持。

Prompt: 
```
这是目录为v8/src/heap/gc-tracer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/gc-tracer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_GC_TRACER_H_
#define V8_HEAP_GC_TRACER_H_

#include <optional>

#include "include/v8-metrics.h"
#include "src/base/compiler-specific.h"
#include "src/base/macros.h"
#include "src/base/ring-buffer.h"
#include "src/common/globals.h"
#include "src/heap/base/bytes.h"
#include "src/init/heap-symbols.h"
#include "src/logging/counters.h"
#include "testing/gtest/include/gtest/gtest_prod.h"  // nogncheck

namespace v8 {
namespace internal {

enum YoungGenerationSpeedMode {
  kUpToAndIncludingAtomicPause,
  kOnlyAtomicPause
};

#define TRACE_GC_CATEGORIES \
  "devtools.timeline," TRACE_DISABLED_BY_DEFAULT("v8.gc")

// Sweeping for full GC may be interleaved with sweeping for minor
// gc. The below scopes should use TRACE_GC_EPOCH to associate them
// with the right cycle.
#define TRACE_GC(tracer, scope_id)                                    \
  DCHECK_NE(GCTracer::Scope::MC_SWEEP, scope_id);                     \
  DCHECK_NE(GCTracer::Scope::MC_BACKGROUND_SWEEPING, scope_id);       \
  GCTracer::Scope UNIQUE_IDENTIFIER(gc_tracer_scope)(                 \
      tracer, GCTracer::Scope::ScopeId(scope_id), ThreadKind::kMain); \
  TRACE_EVENT0(TRACE_GC_CATEGORIES,                                   \
               GCTracer::Scope::Name(GCTracer::Scope::ScopeId(scope_id)))

#define TRACE_GC_ARG1(tracer, scope_id, arg0_name, arg0_value)            \
  DCHECK_NE(GCTracer::Scope::MC_SWEEP, scope_id);                         \
  DCHECK_NE(GCTracer::Scope::MC_BACKGROUND_SWEEPING, scope_id);           \
  GCTracer::Scope UNIQUE_IDENTIFIER(gc_tracer_scope)(                     \
      tracer, GCTracer::Scope::ScopeId(scope_id), ThreadKind::kMain);     \
  TRACE_EVENT1(TRACE_GC_CATEGORIES,                                       \
               GCTracer::Scope::Name(GCTracer::Scope::ScopeId(scope_id)), \
               arg0_name, arg0_value)

#define TRACE_GC_WITH_FLOW(tracer, scope_id, bind_id, flow_flags)         \
  DCHECK_NE(GCTracer::Scope::MC_SWEEP, scope_id);                         \
  DCHECK_NE(GCTracer::Scope::MC_BACKGROUND_SWEEPING, scope_id);           \
  GCTracer::Scope UNIQUE_IDENTIFIER(gc_tracer_scope)(                     \
      tracer, GCTracer::Scope::ScopeId(scope_id), ThreadKind::kMain);     \
  TRACE_EVENT_WITH_FLOW0(                                                 \
      TRACE_GC_CATEGORIES,                                                \
      GCTracer::Scope::Name(GCTracer::Scope::ScopeId(scope_id)), bind_id, \
      flow_flags)

#define TRACE_GC1(tracer, scope_id, thread_kind)                \
  GCTracer::Scope UNIQUE_IDENTIFIER(gc_tracer_scope)(           \
      tracer, GCTracer::Scope::ScopeId(scope_id), thread_kind); \
  TRACE_EVENT0(TRACE_GC_CATEGORIES,                             \
               GCTracer::Scope::Name(GCTracer::Scope::ScopeId(scope_id)))

#define TRACE_GC1_WITH_FLOW(tracer, scope_id, thread_kind, bind_id,       \
                            flow_flags)                                   \
  GCTracer::Scope UNIQUE_IDENTIFIER(gc_tracer_scope)(                     \
      tracer, GCTracer::Scope::ScopeId(scope_id), thread_kind);           \
  TRACE_EVENT_WITH_FLOW0(                                                 \
      TRACE_GC_CATEGORIES,                                                \
      GCTracer::Scope::Name(GCTracer::Scope::ScopeId(scope_id)), bind_id, \
      flow_flags)

#define TRACE_GC_EPOCH(tracer, scope_id, thread_kind)                     \
  GCTracer::Scope UNIQUE_IDENTIFIER(gc_tracer_scope)(                     \
      tracer, GCTracer::Scope::ScopeId(scope_id), thread_kind);           \
  TRACE_EVENT1(TRACE_GC_CATEGORIES,                                       \
               GCTracer::Scope::Name(GCTracer::Scope::ScopeId(scope_id)), \
               "epoch", tracer->CurrentEpoch(scope_id))

#define TRACE_GC_EPOCH_WITH_FLOW(tracer, scope_id, thread_kind, bind_id,  \
                                 flow_flags)                              \
  GCTracer::Scope UNIQUE_IDENTIFIER(gc_tracer_scope)(                     \
      tracer, GCTracer::Scope::ScopeId(scope_id), thread_kind);           \
  TRACE_EVENT_WITH_FLOW1(                                                 \
      TRACE_GC_CATEGORIES,                                                \
      GCTracer::Scope::Name(GCTracer::Scope::ScopeId(scope_id)), bind_id, \
      flow_flags, "epoch", tracer->CurrentEpoch(scope_id))

#define TRACE_GC_NOTE(note)                  \
  do {                                       \
    TRACE_EVENT0(TRACE_GC_CATEGORIES, note); \
  } while (0)

#define TRACE_GC_NOTE_WITH_FLOW(note, bind_id, flow_flags)                  \
  do {                                                                      \
    TRACE_EVENT_WITH_FLOW0(TRACE_GC_CATEGORIES, note, bind_id, flow_flags); \
  } while (0)

using CollectionEpoch = uint32_t;

// GCTracer collects and prints ONE line after each garbage collector
// invocation IFF --trace_gc is used.
class V8_EXPORT_PRIVATE GCTracer {
  using Priority = v8::Isolate::Priority;

 public:
  struct IncrementalInfos final {
    constexpr V8_INLINE IncrementalInfos& operator+=(base::TimeDelta delta);

    base::TimeDelta duration;
    base::TimeDelta longest_step;
    int steps = 0;
  };

  class V8_EXPORT_PRIVATE V8_NODISCARD Scope {
   public:
    enum ScopeId {
#define DEFINE_SCOPE(scope) scope,
      TRACER_SCOPES(DEFINE_SCOPE) TRACER_BACKGROUND_SCOPES(DEFINE_SCOPE)
#undef DEFINE_SCOPE
          NUMBER_OF_SCOPES,

      FIRST_INCREMENTAL_SCOPE = MC_INCREMENTAL,
      LAST_INCREMENTAL_SCOPE = MC_INCREMENTAL_SWEEPING,
      FIRST_SCOPE = MC_INCREMENTAL,
      NUMBER_OF_INCREMENTAL_SCOPES =
          LAST_INCREMENTAL_SCOPE - FIRST_INCREMENTAL_SCOPE + 1,
      FIRST_TOP_MC_SCOPE = MC_CLEAR,
      LAST_TOP_MC_SCOPE = MC_SWEEP,
      FIRST_BACKGROUND_SCOPE = BACKGROUND_YOUNG_ARRAY_BUFFER_SWEEP,
      LAST_BACKGROUND_SCOPE = SCAVENGER_BACKGROUND_SCAVENGE_PARALLEL
    };

    V8_INLINE Scope(GCTracer* tracer, ScopeId scope, ThreadKind thread_kind);
    V8_INLINE ~Scope();
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;
    static constexpr const char* Name(ScopeId id);
    static constexpr bool NeedsYoungEpoch(ScopeId id);
    static constexpr int IncrementalOffset(ScopeId id);

   private:
    GCTracer* const tracer_;
    const ScopeId scope_;
    const ThreadKind thread_kind_;
    const base::TimeTicks start_time_;
#ifdef V8_RUNTIME_CALL_STATS
    RuntimeCallTimer timer_;
    RuntimeCallStats* runtime_stats_ = nullptr;
    std::optional<WorkerThreadRuntimeCallStatsScope> runtime_call_stats_scope_;
#endif  // defined(V8_RUNTIME_CALL_STATS)
  };

  class Event {
   public:
    enum class Type {
      SCAVENGER = 0,
      MARK_COMPACTOR = 1,
      INCREMENTAL_MARK_COMPACTOR = 2,
      MINOR_MARK_SWEEPER = 3,
      INCREMENTAL_MINOR_MARK_SWEEPER = 4,
      START = 5,
    };

    // Returns true if the event corresponds to a young generation GC.
    V8_INLINE static constexpr bool IsYoungGenerationEvent(Type type);

    // The state diagram for a GC cycle:
    //   (NOT_RUNNING) -----(StartCycle)----->
    //   MARKING       --(StartAtomicPause)-->
    //   ATOMIC        ---(StopAtomicPause)-->
    //   SWEEPING      ------(StopCycle)-----> NOT_RUNNING
    enum class State { NOT_RUNNING, MARKING, ATOMIC, SWEEPING };

    Event(Type type, State state, GarbageCollectionReason gc_reason,
          const char* collector_reason, Priority priority);

    // Type of the event.
    Type type;

    // State of the cycle corresponding to the event.
    State state;

    GarbageCollectionReason gc_reason;
    const char* collector_reason;

    // The Isolate's priority during the current GC cycle. The priority is set
    // when the cycle starts. If the priority changes before the cycle is
    // finished, the priority will be reset to denote a mixed priority.
    std::optional<Priority> priority;

    // Timestamp set in the constructor.
    base::TimeTicks start_time;

    // Timestamp set in the destructor.
    base::TimeTicks end_time;

    // Memory reduction flag set.
    bool reduce_memory = false;

    // Size of objects in heap set in constructor.
    size_t start_object_size = 0;

    // Size of objects in heap set in destructor.
    size_t end_object_size = 0;

    // Size of memory allocated from OS set in constructor.
    size_t start_memory_size = 0;

    // Size of memory allocated from OS set in destructor.
    size_t end_memory_size = 0;

    // Total amount of space either wasted or contained in one of free lists
    // before the current GC.
    size_t start_holes_size = 0;

    // Total amount of space either wasted or contained in one of free lists
    // after the current GC.
    size_t end_holes_size = 0;

    // Size of young objects in constructor.
    size_t young_object_size = 0;

    // Size of survived young objects in destructor.
    size_t survived_young_object_size = 0;

    // Bytes marked incrementally for INCREMENTAL_MARK_COMPACTOR
    size_t incremental_marking_bytes = 0;

    // Approximate number of threads that contributed in garbage collection.
    size_t concurrency_estimate = 1;

    // Duration (in ms) of incremental marking steps for
    // INCREMENTAL_MARK_COMPACTOR.
    base::TimeDelta incremental_marking_duration;

    base::TimeTicks incremental_marking_start_time;

    // Start/end of atomic/safepoint pause.
    base::TimeTicks start_atomic_pause_time;
    base::TimeTicks end_atomic_pause_time;

    // Amounts of time spent in different scopes during GC.
    base::TimeDelta scopes[Scope::NUMBER_OF_SCOPES];

    // Holds details for incremental marking scopes.
    IncrementalInfos incremental_scopes[Scope::NUMBER_OF_INCREMENTAL_SCOPES];
  };

  class RecordGCPhasesInfo final {
   public:
    RecordGCPhasesInfo(Heap* heap, GarbageCollector collector,
                       GarbageCollectionReason reason);

    enum class Mode { None, Scavenger, Finalize };

    Mode mode() const { return mode_; }
    const char* trace_event_name() const { return trace_event_name_; }

    // The timers are based on Gc types and the kinds of GC being invoked.
    TimedHistogram* type_timer() const { return type_timer_; }
    TimedHistogram* type_priority_timer() const { return type_priority_timer_; }

   private:
    Mode mode_;
    const char* trace_event_name_;
    TimedHistogram* type_timer_;
    TimedHistogram* type_priority_timer_;
  };

  static constexpr base::TimeDelta kThroughputTimeFrame =
      base::TimeDelta::FromSeconds(5);
  static constexpr double kConservativeSpeedInBytesPerMillisecond = 128 * KB;

#ifdef V8_RUNTIME_CALL_STATS
  V8_INLINE static RuntimeCallCounterId RCSCounterFromScope(Scope::ScopeId id);
#endif  // defined(V8_RUNTIME_CALL_STATS)

  GCTracer(Heap* heap, base::TimeTicks startup_time,
           GarbageCollectionReason initial_gc_reason =
               GarbageCollectionReason::kUnknown);

  GCTracer(const GCTracer&) = delete;
  GCTracer& operator=(const GCTracer&) = delete;

  V8_INLINE CollectionEpoch CurrentEpoch(Scope::ScopeId id) const;

  // Start and stop an observable pause.
  void StartObservablePause(base::TimeTicks time);
  void StopObservablePause(GarbageCollector collector, base::TimeTicks time);

  // Update the current event if it precedes the start of the observable pause.
  void UpdateCurrentEvent(GarbageCollectionReason gc_reason,
                          const char* collector_reason);

  enum class MarkingType { kAtomic, kIncremental };

  // Start and stop a GC cycle (collecting data and reporting results).
  void StartCycle(GarbageCollector collector, GarbageCollectionReason gc_reason,
                  const char* collector_reason, MarkingType marking);
  void StopYoungCycleIfNeeded();
  void StopFullCycleIfNeeded();

  void UpdateMemoryBalancerGCSpeed();

  // Start and stop a cycle's atomic pause.
  void StartAtomicPause();
  void StopAtomicPause();

  void StartInSafepoint(base::TimeTicks time);
  void StopInSafepoint(base::TimeTicks time);

  void NotifyFullSweepingCompleted();
  void NotifyYoungSweepingCompleted();

  void NotifyFullCppGCCompleted();
  void NotifyYoungCppGCRunning();
  void NotifyYoungCppGCCompleted();

#ifdef DEBUG
  bool IsInObservablePause() const;
  bool IsInAtomicPause() const;

  // Checks if the current event is consistent with a collector.
  bool IsConsistentWithCollector(GarbageCollector collector) const;

  // Checks if the current event corresponds to a full GC cycle whose sweeping
  // has not finalized yet.
  bool IsSweepingInProgress() const;
#endif

  // Sample and accumulate bytes allocated since the last GC.
  void SampleAllocation(base::TimeTicks current, size_t new_space_counter_bytes,
                        size_t old_generation_counter_bytes,
                        size_t embedder_counter_bytes);

  void AddCompactionEvent(double duration, size_t live_bytes_compacted);

  void AddSurvivalRatio(double survival_ratio);

  void SampleConcurrencyEsimate(size_t concurrency);

  // Log an incremental marking step.
  void AddIncrementalMarkingStep(double duration, size_t bytes);

  // Log an incremental marking step.
  void AddIncrementalSweepingStep(double duration);

  // Compute the average incremental marking speed in bytes/millisecond.
  // Returns a conservative value if no events have been recorded.
  double IncrementalMarkingSpeedInBytesPerMillisecond() const;

  // Compute the average embedder speed in bytes/millisecond.
  // Returns a conservative value if no events have been recorded.
  double EmbedderSpeedInBytesPerMillisecond() const;

  // Average estimaged young generation speed in bytes/millisecond. This factors
  // in concurrency and assumes that the level of concurrency provided by the
  // embedder is stable. E.g., receiving lower concurrency than previously
  // recorded events will yield in lower current speed.
  //
  // Returns 0 if no events have been recorded.
  double YoungGenerationSpeedInBytesPerMillisecond(
      YoungGenerationSpeedMode mode) const;

  // Compute the average compaction speed in bytes/millisecond.
  // Returns 0 if not enough events have been recorded.
  double CompactionSpeedInBytesPerMillisecond() const;

  // Compute the average mark-sweep speed in bytes/millisecond.
  // Returns 0 if no events have been recorded.
  double MarkCompactSpeedInBytesPerMillisecond() const;

  // Compute the average incremental mark-sweep finalize speed in
  // bytes/millisecond.
  // Returns 0 if no events have been recorded.
  double FinalIncrementalMarkCompactSpeedInBytesPerMillisecond() const;

  // Compute the overall old generation mark compact speed including incremental
  // steps and the final mark-compact step.
  double OldGenerationSpeedInBytesPerMillisecond();

  // Allocation throughput in the new space in bytes/millisecond.
  // Returns 0 if no allocation events have been recorded.
  double NewSpaceAllocationThroughputInBytesPerMillisecond() const;

  // Allocation throughput in the old generation in bytes/millisecond in the
  // last time_ms milliseconds.
  // Returns 0 if no allocation events have been recorded.
  double OldGenerationAllocationThroughputInBytesPerMillisecond() const;

  // Allocation throughput in the embedder in bytes/millisecond in the
  // last time_ms milliseconds.
  // Returns 0 if no allocation events have been recorded.
  double EmbedderAllocationThroughputInBytesPerMillisecond() const;

  // Allocation throughput in heap in bytes/millisecond in the last time_ms
  // milliseconds.
  // Returns 0 if no allocation events have been recorded.
  double AllocationThroughputInBytesPerMillisecond() const;

  // Computes the average survival ratio based on the last recorded survival
  // events.
  // Returns 0 if no events have been recorded.
  double AverageSurvivalRatio() const;

  // Returns true if at least one survival event was recorded.
  bool SurvivalEventsRecorded() const;

  // Discard all recorded survival events.
  void ResetSurvivalEvents();

  void NotifyIncrementalMarkingStart();

  // Invoked when starting marking - either incremental or as part of the atomic
  // pause. Used for computing/updating code flushing increase.
  void NotifyMarkingStart();

  // Returns the current cycle's code flushing increase in seconds.
  uint16_t CodeFlushingIncrease() const;

  // Returns average mutator utilization with respect to mark-compact
  // garbage collections. This ignores scavenger.
  double AverageMarkCompactMutatorUtilization() const;
  double CurrentMarkCompactMutatorUtilization() const;

  V8_INLINE void AddScopeSample(Scope::ScopeId id, base::TimeDelta duration);

  void RecordGCPhasesHistograms(RecordGCPhasesInfo::Mode mode);

  void RecordEmbedderMarkingSpeed(size_t bytes, base::TimeDelta duration);

  // Returns the average time between scheduling and invocation of an
  // incremental marking task.
  std::optional<base::TimeDelta> AverageTimeToIncrementalMarkingTask() const;
  void RecordTimeToIncrementalMarkingTask(base::TimeDelta time_to_task);

#ifdef V8_RUNTIME_CALL_STATS
  V8_INLINE WorkerThreadRuntimeCallStats* worker_thread_runtime_call_stats();
#endif  // defined(V8_RUNTIME_CALL_STATS)

  GarbageCollector GetCurrentCollector() const;

  void UpdateCurrentEventPriority(Priority priority);

 private:
  using BytesAndDurationBuffer = ::heap::base::BytesAndDurationBuffer;
  using SmoothedBytesAndDuration = ::heap::base::SmoothedBytesAndDuration;

  struct BackgroundCounter {
    double total_duration_ms;
  };

  void StopCycle(GarbageCollector collector);

  // Statistics for background scopes are kept out of the current event and only
  // copied there via FetchBackgroundCounters(). This method here is thread-safe
  // but may return out-of-date numbers as it only considers data from the
  // current Event.
  V8_INLINE double current_scope(Scope::ScopeId id) const;

  V8_INLINE constexpr const IncrementalInfos& incremental_scope(
      Scope::ScopeId id) const;

  void ResetForTesting();
  void RecordIncrementalMarkingSpeed(size_t bytes, base::TimeDelta duration);
  void RecordMutatorUtilization(base::TimeTicks mark_compactor_end_time,
                                base::TimeDelta mark_compactor_duration);

  // Update counters for an entire full GC cycle. Exact accounting of events
  // within a GC is not necessary which is why the recording takes place at the
  // end of the atomic pause.
  void RecordGCSumCounters();

  // Print one detailed trace line in name=value format.
  // TODO(ernstm): Move to Heap.
  void PrintNVP() const;

  // Print one trace line.
  // TODO(ernstm): Move to Heap.
  void Print() const;

  // Prints a line and also adds it to the heap's ring buffer so that
  // it can be included in later crash dumps.
  void PRINTF_FORMAT(2, 3) Output(const char* format, ...) const;

  void FetchBackgroundCounters();

  void ReportFullCycleToRecorder();
  void ReportIncrementalMarkingStepToRecorder(double v8_duration);
  void ReportIncrementalSweepingStepToRecorder(double v8_duration);
  void ReportYoungCycleToRecorder();

  // Pointer to the heap that owns this tracer.
  Heap* heap_;

  // Current tracer event. Populated during Start/Stop cycle. Valid after Stop()
  // has returned.
  Event current_;

  // Previous tracer event.
  Event previous_;

  // The starting time of the observable pause if set.
  std::optional<base::TimeTicks> start_of_observable_pause_;

  // We need two epochs, since there can be scavenges during incremental
  // marking.
  CollectionEpoch epoch_young_ = 0;
  CollectionEpoch epoch_full_ = 0;

  // Incremental marking speed for major GCs. Marking for minor GCs is ignored.
  double recorded_major_incremental_marking_speed_ = 0.0;

  std::optional<base::TimeDelta> average_time_to_incremental_marking_task_;

  // This is not the general last marking start time as it's only updated when
  // we reach the minimum threshold for code flushing which is 1 sec.
  std::optional<base::TimeTicks> last_marking_start_time_for_code_flushing_;
  uint16_t code_flushing_increase_s_ = 0;

  // Incremental scopes carry more information than just the duration. The infos
  // here are merged back upon starting/stopping the GC tracer.
  IncrementalInfos incremental_scopes_[Scope::NUMBER_OF_INCREMENTAL_SCOPES];

  // Timestamp and allocation counter at the last sampled allocation event.
  base::TimeTicks allocation_time_;
  size_t new_space_allocation_counter_bytes_ = 0;
  size_t old_generation_allocation_counter_bytes_ = 0;
  size_t embedder_allocation_counter_bytes_ = 0;

  double combined_mark_compact_speed_cache_ = 0.0;

  // Used for computing average mutator utilization.
  double average_mutator_duration_ = 0.0;
  double average_mark_compact_duration_ = 0.0;
  double current_mark_compact_mutator_utilization_ = 1.0;

  // The end of the last mark-compact GC. Is set to isolate/heap setup time
  // before the first one.
  base::TimeTicks previous_mark_compact_end_time_;
  base::TimeDelta total_duration_since_last_mark_compact_;

  BytesAndDurationBuffer recorded_compactions_;
  BytesAndDurationBuffer recorded_incremental_mark_compacts_;
  BytesAndDurationBuffer recorded_mark_compacts_;
  BytesAndDurationBuffer recorded_major_totals_;
  BytesAndDurationBuffer recorded_embedder_marking_;

  static constexpr base::TimeDelta kSmoothedAllocationSpeedDecayRate =
      v8::base::TimeDelta::FromMilliseconds(100);

  SmoothedBytesAndDuration new_generation_allocations_{
      kSmoothedAllocationSpeedDecayRate};
  SmoothedBytesAndDuration old_generation_allocations_{
      kSmoothedAllocationSpeedDecayRate};
  SmoothedBytesAndDuration embedder_generation_allocations_{
      kSmoothedAllocationSpeedDecayRate};

  // Estimate for young generation speed. Based on walltime and concurrency
  // estimates.
  BytesAndDurationBuffer recorded_minor_gc_per_thread_;
  BytesAndDurationBuffer recorded_minor_gc_atomic_pause_;
  base::RingBuffer<double> recorded_survival_ratios_;

  // A full GC cycle stops only when both v8 and cppgc (if available) GCs have
  // finished sweeping.
  bool notified_full_sweeping_completed_ = false;
  bool notified_full_cppgc_completed_ = false;
  bool full_cppgc_completed_during_minor_gc_ = false;

  bool notified_young_sweeping_completed_ = false;
  // Similar to full GCs, a young GC cycle stops only when both v8 and cppgc GCs
  // have finished sweeping.
  bool notified_young_cppgc_completed_ = false;
  // Keep track whether the young cppgc GC was scheduled (as opposed to full
  // cycles, for young cycles cppgc is not always scheduled).
  bool notified_young_cppgc_running_ = false;

  // When a full GC cycle is interrupted by a young generation GC cycle, the
  // |previous_| event is used as temporary storage for the |current_| event
  // that corresponded to the full GC cycle, and this field is set to true.
  bool young_gc_while_full_gc_ = false;

  v8::metrics::GarbageCollectionFullMainThreadBatchedIncrementalMark
      incremental_mark_batched_events_;
  v8::metrics::GarbageCollectionFullMainThreadBatchedIncrementalSweep
      incremental_sweep_batched_events_;

  mutable base::Mutex background_scopes_mutex_;
  base::TimeDelta background_scopes_[Scope::NUMBER_OF_SCOPES];

  FRIEND_TEST(GCTracerTest, AllocationThroughput);
  FRIEND_TEST(GCTracerTest, BackgroundScavengerScope);
  FRIEND_TEST(GCTracerTest, BackgroundMinorMSScope);
  FRIEND_TEST(GCTracerTest, BackgroundMajorMCScope);
  FRIEND_TEST(GCTracerTest, CyclePriorities);
  FRIEND_TEST(GCTracerTest, EmbedderAllocationThroughput);
  FRIEND_TEST(GCTracerTest, MultithreadedBackgroundScope);
  FRIEND_TEST(GCTracerTest, NewSpaceAllocationThroughput);
  FRIEND_TEST(GCTracerTest, PerGenerationAllocationThroughput);
  FRIEND_TEST(GCTracerTest, PerGenerationAllocationThroughputWithProvidedTime);
  FRIEND_TEST(GCTracerTest, RegularScope);
  FRIEND_TEST(GCTracerTest, IncrementalMarkingDetails);
  FRIEND_TEST(GCTracerTest, IncrementalScope);
  FRIEND_TEST(GCTracerTest, IncrementalMarkingSpeed);
  FRIEND_TEST(GCTracerTest, MutatorUtilization);
  FRIEND_TEST(GCTracerTest, RecordMarkCompactHistograms);
  FRIEND_TEST(GCTracerTest, RecordScavengerHistograms);
};

const char* ToString(GCTracer::Event::Type type, bool short_name);

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_GC_TRACER_H_

"""

```