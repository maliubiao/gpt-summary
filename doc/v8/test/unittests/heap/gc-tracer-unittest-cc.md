Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The file name `gc-tracer-unittest.cc` immediately suggests its primary function: to test the `GCTracer` class. The "unittest" part confirms this. The `v8/test/unittests/heap/` path further clarifies that it's part of the V8 JavaScript engine's testing framework, specifically for the heap management subsystem.

2. **Scan for Key Class:** Look for the class being tested. In this case, it's clearly `GCTracer`.

3. **Understand the Test Structure:**  Unit tests in C++ often use a framework like Google Test (`testing/gtest/include/gtest/gtest.h`). The `TEST_F` macro is a strong indicator of this. Each `TEST_F` defines an individual test case. The `GCTracerTest` before the comma in `TEST_F` indicates a test fixture (a class inheriting from `TestWithContext`, likely providing common setup/teardown).

4. **Analyze Individual Test Cases (Functional Breakdown):** Go through each `TEST_F` function and try to understand what specific aspect of `GCTracer` it's testing. Look for:
    * **Setup:** What are the initial conditions?  Is `tracer->ResetForTesting()` called? This suggests a clean state for each test.
    * **Actions:** What methods of `GCTracer` are being called?  Are there helper functions like `SampleAllocation`, `StartTracing`, `StopTracing`?
    * **Assertions:** What are the `EXPECT_EQ`, `EXPECT_GE`, `EXPECT_LE`, `EXPECT_DOUBLE_EQ` calls checking? These are the core of the test, verifying the expected behavior.

5. **Identify Helper Functions:** Notice the functions defined within the anonymous namespace (`namespace { ... }`): `SampleAllocation`, `StartTracing`, `StopTracing`. These encapsulate common operations related to interacting with the `GCTracer`, making the tests more readable. Analyze what each of these helpers does.

6. **Look for Conditional Logic:** Observe the `if (v8_flags.stress_incremental_marking) return;` statements. This indicates that some tests might be skipped based on V8's internal flags. It's important to note this, as it means the tests aren't *always* run.

7. **Identify Key Concepts:** As you go through the tests, you'll encounter terms related to garbage collection: "allocation throughput," "scopes," "incremental marking," "mutator utilization," "background scavenging/marking," "histograms," "cycle priorities."  These terms provide clues about the responsibilities of the `GCTracer`.

8. **Connect to JavaScript (If Applicable):**  Consider how the functionality being tested in `GCTracer` relates to JavaScript. Garbage collection is a fundamental part of JavaScript's memory management. Think about how allocation, tracing, and different GC strategies manifest in JavaScript execution.

9. **Look for Potential User Errors:**  Consider scenarios where a developer might misuse or misunderstand the concepts related to garbage collection or performance monitoring. This can help in formulating examples of common programming errors.

10. **Code Logic Inference (Input/Output):** For tests that involve calculations (like `PerGenerationAllocationThroughput` or `IncrementalMarkingSpeed`), try to mentally trace the execution with the provided sample data. What inputs lead to what outputs?  This helps in understanding the logic being tested.

11. **Structure the Answer:** Organize your findings logically:
    * Start with a high-level summary of the file's purpose.
    * List the key functionalities based on the individual test cases.
    * Explain the helper functions.
    * Address the `.tq` question.
    * Provide JavaScript examples (if applicable).
    * Give input/output examples for relevant tests.
    * Mention common programming errors.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This file tests how GC works."  **Refinement:** Be more specific. It tests the *instrumentation and tracking* of GC events by the `GCTracer`, not the actual GC algorithms themselves.
* **Initial thought:** "The helper functions are just for setup." **Refinement:**  They encapsulate core actions related to simulating GC cycles, not just basic setup.
* **Stuck on a test:** If a particular test is unclear, re-read the surrounding code, the `EXPECT` statements, and the comments (if any). Try to relate it to other tests or concepts you've already understood.
* **JavaScript connection unclear:**  Think about *why* V8 needs a `GCTracer`. It's for performance monitoring and understanding GC behavior, which directly impacts JavaScript execution. Focus on the *observable effects* of GC.

By following this structured approach, you can effectively analyze C++ unittest files like this and extract the relevant information to answer the user's questions.
这个C++源代码文件 `v8/test/unittests/heap/gc-tracer-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 `GCTracer` 类的功能。`GCTracer` 的主要职责是**追踪和记录垃圾回收 (GC) 过程中的各种事件和性能指标**。

以下是该文件列举的功能：

1. **追踪不同代的内存分配吞吐量 (PerGenerationAllocationThroughput):**
   - 测试 `GCTracer` 如何计算新空间、老年代和嵌入器空间的内存分配速度。
   - 通过模拟多次内存分配，并断言计算出的吞吐量是否符合预期。
   - 使用了指数平滑来计算吞吐量，以减少噪声。

2. **记录和聚合不同 GC 阶段的耗时 (RegularScope, IncrementalScope, IncrementalMarkingDetails):**
   - 测试 `GCTracer` 如何记录原子 GC 和增量 GC 中不同阶段（例如，标记、清除、压缩等）的耗时。
   - `RegularScope` 测试原子 GC 阶段的耗时记录。
   - `IncrementalScope` 测试增量 GC 中特定阶段的耗时记录。
   - `IncrementalMarkingDetails` 测试增量标记的详细信息，例如最长步骤、步骤数和总持续时间。

3. **追踪增量标记的速度 (IncrementalMarkingSpeed):**
   - 测试 `GCTracer` 如何计算增量标记的速度，单位是每毫秒标记的字节数。
   - 通过模拟增量标记步骤，并断言计算出的速度是否正确。

4. **计算 Mutator 利用率 (MutatorUtilization):**
   - 测试 `GCTracer` 如何计算 Mutator（即执行 JavaScript 代码的线程）的利用率，即 Mutator 运行时间占总时间的比例。
   - 通过模拟多次 GC，并断言计算出的当前和平均 Mutator 利用率是否符合预期。

5. **记录后台 GC 阶段的耗时 (BackgroundScavengerScope, BackgroundMinorMSScope, BackgroundMajorMCScope):**
   - 测试 `GCTracer` 如何记录后台垃圾回收阶段（例如，后台清除、后台标记、后台扫描等）的耗时。
   - 分别测试了 Scavenger（新生代 GC）、Minor MS（小标记清除）和 Major MC（老年代标记压缩）的后台阶段。

6. **处理多线程后台 GC 作用域 (MultithreadedBackgroundScope):**
   - 测试 `GCTracer` 如何处理在不同后台线程中记录的 GC 阶段耗时。
   - 创建多个线程模拟后台 GC 操作，并确保 `GCTracer` 能正确聚合这些信息。

7. **记录 GC 阶段的直方图数据 (RecordMarkCompactHistograms, RecordScavengerHistograms):**
   - 测试 `GCTracer` 如何将不同 GC 阶段的耗时记录到直方图中，用于性能分析和监控。
   - 使用了模拟的直方图类 `GcHistogram` 来验证数据是否被正确记录。

8. **管理 GC 循环的优先级 (CyclePriorities):**
   - 测试 `GCTracer` 如何跟踪和管理当前 GC 循环的优先级，这与 V8 的 Isolate 优先级相关。
   - 验证了当 Isolate 优先级改变时，GC 循环的优先级是否会相应更新。

**关于文件扩展名和 Torque:**

如果 `v8/test/unittests/heap/gc-tracer-unittest.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码文件**。Torque 是 V8 用于定义运行时函数的领域特定语言。 然而，根据你提供的文件名，它以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**。

**与 JavaScript 的关系和示例:**

`GCTracer` 的功能直接关系到 JavaScript 的性能。JavaScript 开发者虽然不能直接操作 `GCTracer`，但 `GCTracer` 收集的数据对于理解和优化 JavaScript 代码的性能至关重要。例如，通过 `GCTracer` 的数据，可以分析：

- **GC 的频率和耗时:**  频繁且耗时长的 GC 会导致 JavaScript 执行卡顿。
- **不同 GC 阶段的瓶颈:**  了解哪个 GC 阶段耗时最多，有助于 V8 团队优化 GC 算法。
- **内存分配模式:**  高分配率可能导致更频繁的 GC。

**JavaScript 示例 (虽然无法直接访问 `GCTracer`，但其影响是可见的):**

```javascript
// 例子：创建一个导致大量内存分配的对象
let largeArray = [];
for (let i = 0; i < 1000000; i++) {
  largeArray.push({ index: i, data: 'some data' });
}

// 执行一些操作
for (let i = 0; i < largeArray.length; i++) {
  largeArray[i].data += ' updated';
}

// 清空数组，让 GC 回收内存
largeArray = null;
```

在这个例子中，创建 `largeArray` 会导致大量的内存分配。当 `largeArray` 不再被引用时（`largeArray = null;`），垃圾回收器会回收这部分内存。`GCTracer` 会记录这个过程中的分配量和 GC 时间。

**代码逻辑推理 (假设输入与输出):**

以 `PerGenerationAllocationThroughput` 测试为例：

**假设输入:**

1. **时间点 1:** 100 毫秒，分配量 1000 字节
2. **时间点 2:** 200 毫秒，分配量 2000 字节
3. **时间点 3:** 1000 毫秒，分配量 30000 字节

**预期输出:**

- 在时间点 2 之后，计算出的吞吐量 `expected_throughput1` 应该接近 `(2000 / 200) * (1.0 - exp2(-2.0))`。
- 在时间点 3 之后，计算出的吞吐量 `expected_throughput2` 应该是一个加权平均值，更接近 `(30000 - 2000) / (1000 - 200)`，并受到之前的吞吐量影响。

**用户常见的编程错误 (导致 GC 压力):**

1. **意外地持有大量对象的引用:**
   ```javascript
   let globalArray = [];

   function createAndStoreObject() {
     let obj = { data: new Array(1000000) };
     globalArray.push(obj); // 错误：持续向全局数组添加对象，阻止 GC 回收
   }

   for (let i = 0; i < 100; i++) {
     createAndStoreObject();
   }
   ```
   在这个例子中，`globalArray` 会不断增长，导致内存泄漏和频繁的 GC。

2. **创建大量临时对象:**
   ```javascript
   function processData(data) {
     let result = [];
     for (let item of data) {
       result.push(item.toString().toUpperCase().split(',')); // 错误：创建大量的临时字符串和数组
     }
     return result;
   }

   let largeDataSet = [...];
   processData(largeDataSet);
   ```
   在 `processData` 函数中，每次循环都会创建新的字符串和数组，这些临时对象会增加 GC 的压力。

3. **闭包导致的内存泄漏:**
   ```javascript
   function createCounter() {
     let count = 0;
     return function() { // 错误：闭包引用了外部作用域的变量，如果闭包长期存在，可能导致内存泄漏
       count++;
       console.log(count);
     };
   }

   let counter = createCounter();
   // 如果 counter 长期存在，它会一直持有 count 变量的引用。
   ```
   如果闭包长期存在，并且引用了较大的外部变量，可能导致内存无法被回收。

总而言之，`v8/test/unittests/heap/gc-tracer-unittest.cc` 通过各种单元测试，确保 `GCTracer` 能够准确地追踪和记录 V8 垃圾回收过程中的关键信息，这对于 V8 团队进行性能分析、优化和调试至关重要。虽然 JavaScript 开发者不能直接操作 `GCTracer`，但理解其背后的原理有助于编写更高效、更少触发 GC 的 JavaScript 代码。

### 提示词
```
这是目录为v8/test/unittests/heap/gc-tracer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/gc-tracer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```