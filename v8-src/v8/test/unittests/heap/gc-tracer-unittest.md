Response: The user wants a summary of the C++ source code file `v8/test/unittests/heap/gc-tracer-unittest.cc`. I need to identify the main functionalities tested in this file. It seems to be testing the `GCTracer` class.

Key areas likely covered:

1. **Allocation Throughput:** How the `GCTracer` measures and calculates the rate of memory allocation.
2. **Scope Measurement:**  Testing how the `GCTracer` tracks the time spent in different phases of garbage collection (GC). This includes both regular and incremental GC.
3. **Incremental Marking Details:** Specifically testing the tracking of incremental marking progress, like duration, steps, and the longest step.
4. **Incremental Marking Speed:** Testing the calculation of the speed of incremental marking.
5. **Mutator Utilization:**  How the `GCTracer` calculates the percentage of time the application (mutator) is running versus the time spent in GC.
6. **Background GC Scopes:** Testing the tracking of time spent in background GC tasks for different GC types (Scavenger, Minor MS, Major MC).
7. **Multithreaded Scopes:** Checking that the `GCTracer` can handle background GC scopes from multiple threads.
8. **Histogram Recording:** Testing the functionality for recording GC phase durations into histograms.
9. **Cycle Priorities:** Testing how the `GCTracer` handles and tracks the priority of the current GC cycle.

Regarding the relationship with JavaScript, the `GCTracer` is an internal component of the V8 engine, which executes JavaScript. The metrics tracked by the `GCTracer` are directly related to the performance of JavaScript applications. Specifically, things like allocation rate and GC times impact how smoothly a JavaScript application runs.

I can illustrate this by showing how memory allocation in JavaScript can be linked to the allocation throughput measured by the `GCTracer`. Similarly, how different JavaScript operations might trigger different GC phases whose timing is tracked.
这个C++源代码文件 `v8/test/unittests/heap/gc-tracer-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 `GCTracer` 类的功能。 `GCTracer` 类负责跟踪和记录垃圾回收（Garbage Collection，GC）相关的各种指标，例如：

**主要功能测试点归纳:**

1. **内存分配吞吐量 (Allocation Throughput):**  测试 `GCTracer` 如何计算不同内存空间（例如新生代、老生代）的内存分配速度。它模拟内存分配事件，并验证计算出的吞吐量是否符合预期。

2. **GC 作用域 (GC Scopes) 测量:**  测试 `GCTracer` 如何记录 GC 过程中不同阶段所花费的时间。 这包括原子 GC 和增量 GC 的各个阶段。

3. **增量标记细节 (Incremental Marking Details):**  测试 `GCTracer` 如何跟踪增量标记的进度，例如记录每次增量标记步骤的时间、最长步骤的时间以及总的增量标记持续时间。

4. **增量标记速度 (Incremental Marking Speed):** 测试 `GCTracer` 如何计算增量标记的速度，即每毫秒标记的字节数。

5. **Mutator 利用率 (Mutator Utilization):**  测试 `GCTracer` 如何计算 Mutator（即 JavaScript 代码的执行）的利用率，即在 GC 周期中，Mutator 实际运行的时间占比。

6. **后台 GC 作用域 (Background GC Scopes):**  测试 `GCTracer` 如何记录后台 GC 任务所花费的时间，这些任务在独立的线程中运行，例如后台 Scavenger、后台 Minor Mark-Sweep 和后台 Major Mark-Compact。

7. **多线程后台作用域 (Multithreaded Background Scope):**  测试 `GCTracer` 是否能正确处理来自多个后台线程的 GC 作用域信息。

8. **记录 GC 直方图 (Record GC Histograms):**  测试 `GCTracer` 如何将 GC 各个阶段的持续时间记录到直方图中，以便进行性能分析和监控。

9. **GC 周期优先级 (Cycle Priorities):**  测试 `GCTracer` 如何跟踪和管理 GC 周期的优先级，这与 V8 引擎的执行优先级相关。

**与 JavaScript 的关系及 JavaScript 示例:**

`GCTracer` 是 V8 引擎内部的核心组件，负责监控 JavaScript 程序的内存管理行为。JavaScript 程序的性能直接受到垃圾回收效率的影响。 `GCTracer` 收集的指标可以帮助 V8 团队优化垃圾回收算法，从而提高 JavaScript 代码的执行效率。

以下是一些 JavaScript 代码示例，它们的操作可能会直接影响 `GCTracer` 记录的指标：

**1. 内存分配 (影响内存分配吞吐量):**

```javascript
let myArray = [];
for (let i = 0; i < 1000000; i++) {
  myArray.push(i); // 持续向数组添加元素，导致内存分配
}
```

这段代码会大量分配内存，`GCTracer` 会记录这些分配事件，并计算出内存分配的吞吐量。

**2. 创建大量临时对象 (可能触发 GC，影响 GC 作用域):**

```javascript
function createTemporaryObjects() {
  for (let i = 0; i < 10000; i++) {
    let temp = { x: i, y: i * 2 }; // 创建大量的临时对象
  }
}

createTemporaryObjects(); // 执行后，这些临时对象可能会被垃圾回收
```

这段代码创建了大量的临时对象，这些对象在函数执行完毕后不再被引用，可能会触发垃圾回收。`GCTracer` 会记录这次垃圾回收过程中各个阶段的耗时。

**3. 执行耗时操作与 GC 的交替 (影响 Mutator 利用率):**

```javascript
function longRunningTask() {
  let result = 0;
  for (let i = 0; i < 1000000000; i++) {
    result += i;
  }
  return result;
}

console.log("开始耗时任务");
longRunningTask();
console.log("耗时任务结束");

let myObject = { data: new Array(1000000) }; // 分配一些内存，可能触发 GC
```

这段代码展示了一个长时间运行的任务，之后进行了一次内存分配。  `GCTracer` 会记录 Mutator (执行 `longRunningTask` 和内存分配代码) 的运行时间和 GC 的运行时间，从而计算出 Mutator 的利用率。如果 GC 频繁发生，Mutator 的利用率会降低。

**总结:**

`v8/test/unittests/heap/gc-tracer-unittest.cc` 文件通过单元测试确保 `GCTracer` 类能够准确地跟踪和记录 V8 引擎中垃圾回收相关的关键性能指标。这些指标对于理解和优化 JavaScript 程序的性能至关重要。 JavaScript 代码的行为，例如内存分配和对象创建，会直接影响 `GCTracer` 记录的数据，从而反映出垃圾回收的效率和对 JavaScript 执行的影响。

Prompt: 
```
这是目录为v8/test/unittests/heap/gc-tracer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/gc-tracer.h"

#include <cmath>
#include <limits>
#include <optional>

#include "src/base/platform/platform.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/heap/gc-tracer-inl.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8::internal {

using GCTracerTest = TestWithContext;

namespace {

void SampleAllocation(GCTracer* tracer, base::TimeTicks time,
                      size_t per_space_counter_bytes) {
  // Increment counters of all spaces.
  tracer->SampleAllocation(time, per_space_counter_bytes,
                           per_space_counter_bytes, per_space_counter_bytes);
}

enum class StartTracingMode {
  kAtomic,
  kIncremental,
  kIncrementalStart,
  kIncrementalEnterPause,
};

void StartTracing(GCTracer* tracer, GarbageCollector collector,
                  StartTracingMode mode,
                  std::optional<base::TimeTicks> time = {}) {
  DCHECK_IMPLIES(mode != StartTracingMode::kAtomic,
                 !Heap::IsYoungGenerationCollector(collector));
  // Start the cycle for incremental marking.
  if (mode == StartTracingMode::kIncremental ||
      mode == StartTracingMode::kIncrementalStart) {
    tracer->StartCycle(collector, GarbageCollectionReason::kTesting,
                       "collector unittest",
                       GCTracer::MarkingType::kIncremental);
  }
  // If just that was requested, no more to be done.
  if (mode == StartTracingMode::kIncrementalStart) return;
  // Else, we enter the observable pause.
  tracer->StartObservablePause(time.value_or(base::TimeTicks::Now()));
  // Start an atomic GC cycle.
  if (mode == StartTracingMode::kAtomic) {
    tracer->StartCycle(collector, GarbageCollectionReason::kTesting,
                       "collector unittest", GCTracer::MarkingType::kAtomic);
  }
  // We enter the atomic pause.
  tracer->StartAtomicPause();
  // Update the current event for an incremental GC cycle.
  if (mode != StartTracingMode::kAtomic) {
    tracer->UpdateCurrentEvent(GarbageCollectionReason::kTesting,
                               "collector unittest");
  }
}

void StopTracing(GCTracer* tracer, GarbageCollector collector,
                 std::optional<base::TimeTicks> time = {}) {
  tracer->StopAtomicPause();
  tracer->StopObservablePause(collector, time.value_or(base::TimeTicks::Now()));
  switch (collector) {
    case GarbageCollector::SCAVENGER:
      tracer->StopYoungCycleIfNeeded();
      break;
    case GarbageCollector::MINOR_MARK_SWEEPER:
      tracer->NotifyYoungSweepingCompleted();
      break;
    case GarbageCollector::MARK_COMPACTOR:
      tracer->NotifyFullSweepingCompleted();
      break;
  }
}

}  // namespace

TEST_F(GCTracerTest, PerGenerationAllocationThroughput) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();
  tracer->allocation_time_ = base::TimeTicks();

  const int time1 = 100;
  const size_t counter1 = 1000;
  SampleAllocation(tracer, base::TimeTicks::FromMsTicksForTesting(time1),
                   counter1);
  const int time2 = 200;
  const size_t counter2 = 2000;
  SampleAllocation(tracer, base::TimeTicks::FromMsTicksForTesting(time2),
                   counter2);
  const size_t expected_throughput1 = counter2 / time2 * (1.0 - exp2(-2.0));
  EXPECT_EQ(expected_throughput1,
            static_cast<size_t>(
                tracer->NewSpaceAllocationThroughputInBytesPerMillisecond()));
  EXPECT_EQ(
      expected_throughput1,
      static_cast<size_t>(
          tracer->OldGenerationAllocationThroughputInBytesPerMillisecond()));
  EXPECT_EQ(expected_throughput1,
            static_cast<size_t>(
                tracer->EmbedderAllocationThroughputInBytesPerMillisecond()));
  const int time3 = 1000;
  const size_t counter3 = 30000;
  SampleAllocation(tracer, base::TimeTicks::FromMsTicksForTesting(time3),
                   counter3);
  const size_t expected_throughput2 =
      (counter3 - counter2) / (time3 - time2) * (1.0 - exp2(-8.0)) +
      exp2(-8.0) * expected_throughput1;
  EXPECT_GE(expected_throughput2, expected_throughput1);
  EXPECT_LE(expected_throughput2, (counter3 - counter2) / (time3 - time2));
  EXPECT_EQ(expected_throughput2,
            static_cast<size_t>(
                tracer->NewSpaceAllocationThroughputInBytesPerMillisecond()));
  EXPECT_EQ(
      expected_throughput2,
      static_cast<size_t>(
          tracer->OldGenerationAllocationThroughputInBytesPerMillisecond()));
  EXPECT_EQ(expected_throughput2,
            static_cast<size_t>(
                tracer->EmbedderAllocationThroughputInBytesPerMillisecond()));
}

TEST_F(GCTracerTest, RegularScope) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();

  EXPECT_EQ(base::TimeDelta(),
            tracer->current_.scopes[GCTracer::Scope::MC_MARK]);
  // Sample not added because the cycle has not started.
  tracer->AddScopeSample(GCTracer::Scope::MC_MARK,
                         base::TimeDelta::FromMilliseconds(10));
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kAtomic);
  tracer->AddScopeSample(GCTracer::Scope::MC_MARK,
                         base::TimeDelta::FromMilliseconds(100));
  StopTracing(tracer, GarbageCollector::MARK_COMPACTOR);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(100),
            tracer->current_.scopes[GCTracer::Scope::MC_MARK]);
}

TEST_F(GCTracerTest, IncrementalScope) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();

  EXPECT_EQ(base::TimeDelta(),
            tracer->current_.scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]);
  // Sample is added because its ScopeId is listed as incremental sample.
  tracer->AddScopeSample(GCTracer::Scope::MC_INCREMENTAL_FINALIZE,
                         base::TimeDelta::FromMilliseconds(100));
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncremental);
  tracer->AddScopeSample(GCTracer::Scope::MC_INCREMENTAL_FINALIZE,
                         base::TimeDelta::FromMilliseconds(100));
  StopTracing(tracer, GarbageCollector::MARK_COMPACTOR);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(200),
            tracer->current_.scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]);
}

TEST_F(GCTracerTest, IncrementalMarkingDetails) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();

  // Round 1.
  tracer->AddScopeSample(GCTracer::Scope::MC_INCREMENTAL_FINALIZE,
                         base::TimeDelta::FromMilliseconds(50));
  // Scavenger has no impact on incremental marking details.
  StartTracing(tracer, GarbageCollector::SCAVENGER, StartTracingMode::kAtomic);
  StopTracing(tracer, GarbageCollector::SCAVENGER);
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncremental);
  tracer->AddScopeSample(GCTracer::Scope::MC_INCREMENTAL_FINALIZE,
                         base::TimeDelta::FromMilliseconds(100));
  StopTracing(tracer, GarbageCollector::MARK_COMPACTOR);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(100),
            tracer->current_
                .incremental_scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]
                .longest_step);
  EXPECT_EQ(2, tracer->current_
                   .incremental_scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]
                   .steps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(150),
            tracer->current_
                .incremental_scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]
                .duration);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(150),
            tracer->current_.scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]);

  // Round 2. Numbers should be reset.
  tracer->AddScopeSample(GCTracer::Scope::MC_INCREMENTAL_FINALIZE,
                         base::TimeDelta::FromMilliseconds(13));
  tracer->AddScopeSample(GCTracer::Scope::MC_INCREMENTAL_FINALIZE,
                         base::TimeDelta::FromMilliseconds(15));
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncremental);
  tracer->AddScopeSample(GCTracer::Scope::MC_INCREMENTAL_FINALIZE,
                         base::TimeDelta::FromMilliseconds(122));
  StopTracing(tracer, GarbageCollector::MARK_COMPACTOR);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(122),
            tracer->current_
                .incremental_scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]
                .longest_step);
  EXPECT_EQ(3, tracer->current_
                   .incremental_scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]
                   .steps);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(150),
            tracer->current_
                .incremental_scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]
                .duration);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(150),
            tracer->current_.scopes[GCTracer::Scope::MC_INCREMENTAL_FINALIZE]);
}

TEST_F(GCTracerTest, IncrementalMarkingSpeed) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();
  tracer->previous_mark_compact_end_time_ = base::TimeTicks();

  // Round 1.
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncrementalStart,
               base::TimeTicks::FromMsTicksForTesting(0));
  // 1000000 bytes in 100ms.
  tracer->AddIncrementalMarkingStep(100, 1000000);
  EXPECT_EQ(1000000 / 100,
            tracer->IncrementalMarkingSpeedInBytesPerMillisecond());
  // 1000000 bytes in 100ms.
  tracer->AddIncrementalMarkingStep(100, 1000000);
  EXPECT_EQ(1000000 / 100,
            tracer->IncrementalMarkingSpeedInBytesPerMillisecond());
  if (!v8_flags.separate_gc_phases) {
    // Scavenger has no impact on incremental marking details.
    StartTracing(tracer, GarbageCollector::SCAVENGER,
                 StartTracingMode::kAtomic);
    StopTracing(tracer, GarbageCollector::SCAVENGER);
  }
  // 1000000 bytes in 100ms.
  tracer->AddIncrementalMarkingStep(100, 1000000);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(300),
            tracer->current_.incremental_marking_duration);
  EXPECT_EQ(3000000u, tracer->current_.incremental_marking_bytes);
  EXPECT_EQ(1000000 / 100,
            tracer->IncrementalMarkingSpeedInBytesPerMillisecond());
  // 1000000 bytes in 100ms.
  tracer->AddIncrementalMarkingStep(100, 1000000);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(400),
            tracer->current_.incremental_marking_duration);
  EXPECT_EQ(4000000u, tracer->current_.incremental_marking_bytes);
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncrementalEnterPause,
               base::TimeTicks::FromMsTicksForTesting(500));
  StopTracing(tracer, GarbageCollector::MARK_COMPACTOR,
              base::TimeTicks::FromMsTicksForTesting(600));
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(400),
            tracer->current_.incremental_marking_duration);
  EXPECT_EQ(4000000u, tracer->current_.incremental_marking_bytes);
  EXPECT_EQ(1000000 / 100,
            tracer->IncrementalMarkingSpeedInBytesPerMillisecond());

  // Round 2.
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncrementalStart,
               base::TimeTicks::FromMsTicksForTesting(700));
  tracer->AddIncrementalMarkingStep(2000, 1000);
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncrementalEnterPause,
               base::TimeTicks::FromMsTicksForTesting(3000));
  StopTracing(tracer, GarbageCollector::MARK_COMPACTOR,
              base::TimeTicks::FromMsTicksForTesting(3100));
  EXPECT_DOUBLE_EQ((4000000.0 / 400 + 1000.0 / 2000) / 2,
                   static_cast<double>(
                       tracer->IncrementalMarkingSpeedInBytesPerMillisecond()));
}

TEST_F(GCTracerTest, MutatorUtilization) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();
  tracer->previous_mark_compact_end_time_ = base::TimeTicks();

  // Mark-compact #1 ended at 200ms and took 100ms.
  tracer->RecordMutatorUtilization(base::TimeTicks::FromMsTicksForTesting(200),
                                   base::TimeDelta::FromMilliseconds(100));
  // Average mark-compact time = 100ms.
  // Average mutator time = 100ms.
  EXPECT_DOUBLE_EQ(0.5, tracer->CurrentMarkCompactMutatorUtilization());
  EXPECT_DOUBLE_EQ(0.5, tracer->AverageMarkCompactMutatorUtilization());

  // Mark-compact #2 ended at 400ms and took 100ms.
  tracer->RecordMutatorUtilization(base::TimeTicks::FromMsTicksForTesting(400),
                                   base::TimeDelta::FromMilliseconds(100));
  // Average mark-compact time = 100ms * 0.5 + 100ms * 0.5.
  // Average mutator time = 100ms * 0.5 + 100ms * 0.5.
  EXPECT_DOUBLE_EQ(0.5, tracer->CurrentMarkCompactMutatorUtilization());
  EXPECT_DOUBLE_EQ(0.5, tracer->AverageMarkCompactMutatorUtilization());

  // Mark-compact #3 ended at 600ms and took 200ms.
  tracer->RecordMutatorUtilization(base::TimeTicks::FromMsTicksForTesting(600),
                                   base::TimeDelta::FromMilliseconds(200));
  // Average mark-compact time = 100ms * 0.5 + 200ms * 0.5.
  // Average mutator time = 100ms * 0.5 + 0ms * 0.5.
  EXPECT_DOUBLE_EQ(0.0, tracer->CurrentMarkCompactMutatorUtilization());
  EXPECT_DOUBLE_EQ(50.0 / 200.0,
                   tracer->AverageMarkCompactMutatorUtilization());

  // Mark-compact #4 ended at 800ms and took 0ms.
  tracer->RecordMutatorUtilization(base::TimeTicks::FromMsTicksForTesting(800),
                                   base::TimeDelta());
  // Average mark-compact time = 150ms * 0.5 + 0ms * 0.5.
  // Average mutator time = 50ms * 0.5 + 200ms * 0.5.
  EXPECT_DOUBLE_EQ(1.0, tracer->CurrentMarkCompactMutatorUtilization());
  EXPECT_DOUBLE_EQ(125.0 / 200.0,
                   tracer->AverageMarkCompactMutatorUtilization());
}

TEST_F(GCTracerTest, BackgroundScavengerScope) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();
  StartTracing(tracer, GarbageCollector::SCAVENGER, StartTracingMode::kAtomic);
  tracer->AddScopeSample(
      GCTracer::Scope::SCAVENGER_BACKGROUND_SCAVENGE_PARALLEL,
      base::TimeDelta::FromMilliseconds(10));
  tracer->AddScopeSample(
      GCTracer::Scope::SCAVENGER_BACKGROUND_SCAVENGE_PARALLEL,
      base::TimeDelta::FromMilliseconds(1));
  StopTracing(tracer, GarbageCollector::SCAVENGER);
  EXPECT_EQ(
      base::TimeDelta::FromMilliseconds(11),
      tracer->current_
          .scopes[GCTracer::Scope::SCAVENGER_BACKGROUND_SCAVENGE_PARALLEL]);
}

TEST_F(GCTracerTest, BackgroundMinorMSScope) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();
  StartTracing(tracer, GarbageCollector::MINOR_MARK_SWEEPER,
               StartTracingMode::kAtomic);
  tracer->AddScopeSample(GCTracer::Scope::MINOR_MS_BACKGROUND_MARKING,
                         base::TimeDelta::FromMilliseconds(10));
  tracer->AddScopeSample(GCTracer::Scope::MINOR_MS_BACKGROUND_MARKING,
                         base::TimeDelta::FromMilliseconds(1));
  StopTracing(tracer, GarbageCollector::MINOR_MARK_SWEEPER);
  EXPECT_EQ(
      base::TimeDelta::FromMilliseconds(11),
      tracer->current_.scopes[GCTracer::Scope::MINOR_MS_BACKGROUND_MARKING]);
}

TEST_F(GCTracerTest, BackgroundMajorMCScope) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncrementalStart);
  tracer->AddScopeSample(GCTracer::Scope::MC_BACKGROUND_MARKING,
                         base::TimeDelta::FromMilliseconds(100));
  tracer->AddScopeSample(GCTracer::Scope::MC_BACKGROUND_SWEEPING,
                         base::TimeDelta::FromMilliseconds(200));
  tracer->AddScopeSample(GCTracer::Scope::MC_BACKGROUND_MARKING,
                         base::TimeDelta::FromMilliseconds(10));
  if (!v8_flags.separate_gc_phases) {
    // Scavenger should not affect the major mark-compact scopes.
    StartTracing(tracer, GarbageCollector::SCAVENGER,
                 StartTracingMode::kAtomic);
    StopTracing(tracer, GarbageCollector::SCAVENGER);
  }
  tracer->AddScopeSample(GCTracer::Scope::MC_BACKGROUND_SWEEPING,
                         base::TimeDelta::FromMilliseconds(20));
  tracer->AddScopeSample(GCTracer::Scope::MC_BACKGROUND_MARKING,
                         base::TimeDelta::FromMilliseconds(1));
  tracer->AddScopeSample(GCTracer::Scope::MC_BACKGROUND_SWEEPING,
                         base::TimeDelta::FromMilliseconds(2));
  StartTracing(tracer, GarbageCollector::MARK_COMPACTOR,
               StartTracingMode::kIncrementalEnterPause);
  tracer->AddScopeSample(GCTracer::Scope::MC_BACKGROUND_EVACUATE_COPY,
                         base::TimeDelta::FromMilliseconds(30));
  tracer->AddScopeSample(GCTracer::Scope::MC_BACKGROUND_EVACUATE_COPY,
                         base::TimeDelta::FromMilliseconds(3));
  tracer->AddScopeSample(
      GCTracer::Scope::MC_BACKGROUND_EVACUATE_UPDATE_POINTERS,
      base::TimeDelta::FromMilliseconds(40));
  tracer->AddScopeSample(
      GCTracer::Scope::MC_BACKGROUND_EVACUATE_UPDATE_POINTERS,
      base::TimeDelta::FromMilliseconds(4));
  StopTracing(tracer, GarbageCollector::MARK_COMPACTOR);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(111),
            tracer->current_.scopes[GCTracer::Scope::MC_BACKGROUND_MARKING]);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(222),
            tracer->current_.scopes[GCTracer::Scope::MC_BACKGROUND_SWEEPING]);
  EXPECT_EQ(
      base::TimeDelta::FromMilliseconds(33),
      tracer->current_.scopes[GCTracer::Scope::MC_BACKGROUND_EVACUATE_COPY]);
  EXPECT_EQ(
      base::TimeDelta::FromMilliseconds(44),
      tracer->current_
          .scopes[GCTracer::Scope::MC_BACKGROUND_EVACUATE_UPDATE_POINTERS]);
}

class ThreadWithBackgroundScope final : public base::Thread {
 public:
  explicit ThreadWithBackgroundScope(GCTracer* tracer)
      : Thread(Options("ThreadWithBackgroundScope")), tracer_(tracer) {}
  void Run() override {
    GCTracer::Scope scope(tracer_, GCTracer::Scope::MC_BACKGROUND_MARKING,
                          ThreadKind::kBackground);
  }

 private:
  GCTracer* tracer_;
};

TEST_F(GCTracerTest, MultithreadedBackgroundScope) {
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  ThreadWithBackgroundScope thread1(tracer);
  ThreadWithBackgroundScope thread2(tracer);
  tracer->ResetForTesting();
  CHECK(thread1.Start());
  CHECK(thread2.Start());
  tracer->FetchBackgroundCounters();

  thread1.Join();
  thread2.Join();
  tracer->FetchBackgroundCounters();

  EXPECT_LE(base::TimeDelta(),
            tracer->current_.scopes[GCTracer::Scope::MC_BACKGROUND_MARKING]);
}

class GcHistogram {
 public:
  static void* CreateHistogram(const char* name, int min, int max,
                               size_t buckets) {
    histograms_[name] = std::unique_ptr<GcHistogram>(new GcHistogram());
    return histograms_[name].get();
  }

  static void AddHistogramSample(void* histogram, int sample) {
    if (histograms_.empty()) return;
    static_cast<GcHistogram*>(histogram)->samples_.push_back(sample);
  }

  static GcHistogram* Get(const char* name) { return histograms_[name].get(); }

  static void CleanUp() { histograms_.clear(); }

  int Total() const {
    int result = 0;
    for (int i : samples_) {
      result += i;
    }
    return result;
  }

  int Count() const { return static_cast<int>(samples_.size()); }

 private:
  std::vector<int> samples_;
  static std::map<std::string, std::unique_ptr<GcHistogram>> histograms_;
};

std::map<std::string, std::unique_ptr<GcHistogram>> GcHistogram::histograms_ =
    std::map<std::string, std::unique_ptr<GcHistogram>>();

TEST_F(GCTracerTest, RecordMarkCompactHistograms) {
  if (v8_flags.stress_incremental_marking) return;
  isolate()->SetCreateHistogramFunction(&GcHistogram::CreateHistogram);
  isolate()->SetAddHistogramSampleFunction(&GcHistogram::AddHistogramSample);
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();
  tracer->current_.scopes[GCTracer::Scope::MC_CLEAR] =
      base::TimeDelta::FromMilliseconds(1);
  tracer->current_.scopes[GCTracer::Scope::MC_EPILOGUE] =
      base::TimeDelta::FromMilliseconds(2);
  tracer->current_.scopes[GCTracer::Scope::MC_EVACUATE] =
      base::TimeDelta::FromMilliseconds(3);
  tracer->current_.scopes[GCTracer::Scope::MC_FINISH] =
      base::TimeDelta::FromMilliseconds(4);
  tracer->current_.scopes[GCTracer::Scope::MC_MARK] =
      base::TimeDelta::FromMilliseconds(5);
  tracer->current_.scopes[GCTracer::Scope::MC_PROLOGUE] =
      base::TimeDelta::FromMilliseconds(6);
  tracer->current_.scopes[GCTracer::Scope::MC_SWEEP] =
      base::TimeDelta::FromMilliseconds(7);
  tracer->RecordGCPhasesHistograms(
      GCTracer::RecordGCPhasesInfo::Mode::Finalize);
  EXPECT_EQ(1, GcHistogram::Get("V8.GCFinalizeMC.Clear")->Total());
  EXPECT_EQ(2, GcHistogram::Get("V8.GCFinalizeMC.Epilogue")->Total());
  EXPECT_EQ(3, GcHistogram::Get("V8.GCFinalizeMC.Evacuate")->Total());
  EXPECT_EQ(4, GcHistogram::Get("V8.GCFinalizeMC.Finish")->Total());
  EXPECT_EQ(5, GcHistogram::Get("V8.GCFinalizeMC.Mark")->Total());
  EXPECT_EQ(6, GcHistogram::Get("V8.GCFinalizeMC.Prologue")->Total());
  EXPECT_EQ(7, GcHistogram::Get("V8.GCFinalizeMC.Sweep")->Total());
  GcHistogram::CleanUp();
}

TEST_F(GCTracerTest, RecordScavengerHistograms) {
  if (v8_flags.stress_incremental_marking) return;
  isolate()->SetCreateHistogramFunction(&GcHistogram::CreateHistogram);
  isolate()->SetAddHistogramSampleFunction(&GcHistogram::AddHistogramSample);
  GCTracer* tracer = i_isolate()->heap()->tracer();
  tracer->ResetForTesting();
  tracer->current_.scopes[GCTracer::Scope::SCAVENGER_SCAVENGE_ROOTS] =
      base::TimeDelta::FromMilliseconds(1);
  tracer->current_.scopes[GCTracer::Scope::SCAVENGER_SCAVENGE_PARALLEL] =
      base::TimeDelta::FromMilliseconds(2);
  tracer->RecordGCPhasesHistograms(
      GCTracer::RecordGCPhasesInfo::Mode::Scavenger);
  EXPECT_EQ(1, GcHistogram::Get("V8.GCScavenger.ScavengeRoots")->Total());
  EXPECT_EQ(2, GcHistogram::Get("V8.GCScavenger.ScavengeMain")->Total());
  GcHistogram::CleanUp();
}

TEST_F(GCTracerTest, CyclePriorities) {
  using Priority = v8::Isolate::Priority;
  if (v8_flags.stress_incremental_marking) return;
  GCTracer* tracer = i_isolate()->heap()->tracer();
  CHECK_EQ(i_isolate()->priority(), Priority::kUserBlocking);
  tracer->ResetForTesting();
  EXPECT_TRUE(tracer->current_.priority.has_value());
  EXPECT_EQ(tracer->current_.priority, Priority::kUserBlocking);
  // Setting the same priority again doesn't change the cycle priority.
  i_isolate()->SetPriority(Priority::kUserBlocking);
  EXPECT_TRUE(tracer->current_.priority.has_value());
  EXPECT_EQ(tracer->current_.priority, Priority::kUserBlocking);
  // Setting a different priority resets the cycle priority.
  i_isolate()->SetPriority(Priority::kUserVisible);
  EXPECT_FALSE(tracer->current_.priority.has_value());
  tracer->ResetForTesting();
  // Initial cycle priority is the same as the isolate priority.
  EXPECT_TRUE(tracer->current_.priority.has_value());
  EXPECT_EQ(tracer->current_.priority, Priority::kUserVisible);
  // Undoing a priority change doesn't restore a cycle priority.
  i_isolate()->SetPriority(Priority::kUserBlocking);
  i_isolate()->SetPriority(Priority::kUserVisible);
  EXPECT_FALSE(tracer->current_.priority.has_value());
}

}  // namespace v8::internal

"""

```