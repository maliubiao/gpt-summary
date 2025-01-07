Response:
Let's break down the thought process for analyzing the provided C++ unittest code.

1. **Understanding the Goal:** The request is to understand the *functionality* of the provided C++ code. Specifically, we need to identify what it tests and what aspects of the `StatsCollector` class it covers.

2. **Initial Scan for Key Information:**  The first step is to quickly scan the code for obvious clues:
    * **File Name:** `stats-collector-unittest.cc` immediately tells us this is a test file specifically for the `StatsCollector` class.
    * **Includes:** The includes reveal dependencies:
        * `"src/heap/cppgc/stats-collector.h"`: This is the header file for the class being tested. This will be the primary source of truth about what `StatsCollector` *does*.
        * `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`:  These are Google Test and Google Mock frameworks, indicating that this is a unit test suite. We can expect `TEST_F` and `EXPECT_EQ` macros.
    * **Namespaces:** `cppgc::internal` suggests this is an internal implementation detail within the `cppgc` garbage collection system.

3. **Identifying the Class Under Test:** The code defines a `StatsCollectorTest` class that inherits from `::testing::Test`. This is a standard pattern in Google Test for grouping related tests. The `stats` member of type `StatsCollector` within this test fixture confirms that `StatsCollector` is the target of the tests.

4. **Analyzing Individual Test Cases (The Heart of Understanding Functionality):**  The bulk of the work involves examining each `TEST_F` block. Each test case focuses on a specific aspect of `StatsCollector`'s behavior. Here's how to analyze them:

    * **Test Name:** The test name usually provides a good indication of what's being tested. For example, `NoMarkedBytes`, `EventPrevGCMarkedObjectSize`, `AllocationNoReportBelowAllocationThresholdBytes`, etc.
    * **Setup:** Look for any setup code within the test. In this case, the `FakeAllocate` and `FakeFree` helper functions are important. They simulate allocation and freeing of memory, allowing the tests to manipulate the internal state of the `StatsCollector`.
    * **Actions:**  Identify the calls made to the `StatsCollector`'s methods. For instance, `stats.NotifyMarkingStarted()`, `stats.NotifyMarkingCompleted()`, `stats.NotifyAllocation()`, `stats.NotifyExplicitFree()`, `stats.NotifyAllocatedMemory()`, `stats.NotifyFreedMemory()`, etc.
    * **Assertions:**  Focus on the `EXPECT_EQ` and `EXPECT_LT`/`EXPECT_GE` calls. These are the verifications of the expected behavior. They tell us what the test expects the `StatsCollector` to track and report.
    * **Mock Objects:** The tests using `MockAllocationObserver` introduce the concept of observers. The `EXPECT_CALL` macros set up expectations for how the mock object's methods will be called, revealing how `StatsCollector` notifies observers about changes.

5. **Synthesizing Functionality from Test Cases:** After analyzing each test, we can start to summarize the overall functionality being tested:
    * Tracking marked bytes during garbage collection.
    * Tracking allocated object size, with a threshold for reporting.
    * Tracking total allocated and freed memory.
    * Tracking discarded memory.
    * Calculating resident memory (allocated - discarded).
    * Notifying observers about changes in allocated object size and total allocated memory.
    * Allowing observers to trigger actions (like GC) based on allocation events.

6. **Addressing Specific Questions in the Prompt:**

    * **Listing Functionality:** This is a direct result of the synthesis in step 5.
    * **`.tq` Extension:**  A quick lookup (or prior knowledge) would confirm that `.tq` usually refers to Torque in V8. The code provided is clearly C++, so this condition is false.
    * **Relationship to JavaScript:** `StatsCollector` is part of V8's garbage collection system. Garbage collection is fundamental to JavaScript's memory management. We can illustrate this with a simple JavaScript example where creating and discarding objects triggers the GC and thus involves the `StatsCollector` internally.
    * **Code Logic Inference (Input/Output):**  Choose a simple test case, like `EventPrevGCMarkedObjectSize`, and demonstrate the flow and expected output based on the input values.
    * **Common Programming Errors:**  Think about how developers might misuse or misunderstand statistics related to memory. A common error is prematurely optimizing based on incomplete or misinterpreted statistics, leading to more complex code without actual performance gains.

7. **Structuring the Answer:** Organize the findings into a clear and logical structure, addressing each part of the original prompt. Use bullet points and clear language. Provide the JavaScript example and the input/output scenario as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus solely on the methods of `StatsCollector`.
* **Correction:** Realize that the *tests* are the primary source of information about what the class *does*. Focus on the test cases and the assertions.
* **Initial thought:**  Just list the methods being called.
* **Refinement:** Explain *what* each test is verifying about the behavior of those methods. Connect the method calls to the state changes and the assertions.
* **Consideration:**  Should I explain the details of Google Test and Google Mock?
* **Decision:** Briefly mention their role but focus on the specifics of the `StatsCollector` tests. Avoid getting bogged down in the testing framework details.

By following this structured approach, combining code analysis with an understanding of testing methodologies, we can effectively extract the functionality of the given C++ unittest code.
这个C++源代码文件 `v8/test/unittests/heap/cppgc/stats-collector-unittest.cc` 是 V8 JavaScript 引擎中 `cppgc` 组件的 `StatsCollector` 类的单元测试。

以下是它主要的功能：

**1. 测试 `StatsCollector` 类跟踪和报告垃圾回收统计信息的能力:**

   - **标记阶段统计:**  测试 `StatsCollector` 能否正确记录垃圾回收标记阶段标记的字节数 (`marked_bytes`)。例如，`TEST_F(StatsCollectorTest, NoMarkedBytes)` 和 `TEST_F(StatsCollectorTest, EventPrevGCMarkedObjectSize)` 就验证了这一点。

   - **分配对象大小统计:** 测试 `StatsCollector` 能否跟踪已分配的对象的大小 (`allocated_object_size`)。 这包括：
     -  验证当分配的对象大小小于阈值 (`kAllocationThresholdBytes`) 时不报告。 (`TEST_F(StatsCollectorTest, AllocationNoReportBelowAllocationThresholdBytes)`)
     -  验证当分配的对象大小大于等于阈值时正确报告。 (`TEST_F(StatsCollectorTest, AlllocationReportAboveAllocationThresholdBytes)`)
     -  验证在垃圾回收的不同阶段，`allocated_object_size` 的变化。 (`TEST_F(StatsCollectorTest, InitialAllocatedObjectSize)`, `TEST_F(StatsCollectorTest, AllocatedObjectSize)`, `TEST_F(StatsCollectorTest, AllocatedObjectSizeNoMarkedBytes)`, `TEST_F(StatsCollectorTest, AllocatedObjectSizeAllocateAfterMarking)`)

   - **总分配和释放内存统计:** 测试 `StatsCollector` 能否跟踪总的分配内存 (`allocated_memory_size`) 和释放内存。 (`TEST_F(StatsCollectorTest, AllocatedMemorySize)`)

   - **丢弃内存统计:** 测试 `StatsCollector` 能否跟踪被丢弃的内存 (`discarded_memory_size`)。 (`TEST_F(StatsCollectorTest, DiscardedMemorySize)`)

   - **常驻内存统计:** 测试 `StatsCollector` 能否计算常驻内存大小 (`resident_memory_size`)，这通常是已分配内存减去丢弃的内存。 (`TEST_F(StatsCollectorTest, ResidentMemorySizeWithoutDiscarded)`, `TEST_F(StatsCollectorTest, ResidentMemorySizeWithDiscarded)`)

**2. 测试 `StatsCollector` 的观察者模式:**

   - **注册和注销观察者:** 测试可以注册和注销 `AllocationObserver`。 (`TEST_F(StatsCollectorTest, RegisterUnregisterObserver)`)

   - **观察者接收通知:** 测试当分配对象大小增加或减少时，注册的观察者 (`MockAllocationObserver`) 会收到相应的通知 (`AllocatedObjectSizeIncreased`, `AllocatedObjectSizeDecreased`)。 (`TEST_F(StatsCollectorTest, ObserveAllocatedObjectSizeIncreaseAndDecrease)`)

   - **观察者接收重置通知:** 测试当垃圾回收发生时，观察者会收到 `ResetAllocatedObjectSize` 通知。 (`TEST_F(StatsCollectorTest, ObserveResetAllocatedObjectSize)`)

   - **观察者接收分配/释放内存通知:** 测试观察者可以接收到总分配和释放内存的通知 (`AllocatedSizeIncreased`, `AllocatedSizeDecreased`)。 (`TEST_F(StatsCollectorTest, ObserveAllocatedMemoryIncreaseAndDecrease)`)

   - **观察者触发垃圾回收:** 测试观察者可以在接收到分配通知后触发垃圾回收。 (`TEST_F(StatsCollectorTest, ObserverTriggersGC)`) 这展示了观察者模式的灵活性，可以根据统计信息执行自定义操作。

**关于文件扩展名和 JavaScript 关系:**

-  `v8/test/unittests/heap/cppgc/stats-collector-unittest.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。
-  如果文件以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。
-  `StatsCollector` 负责收集 V8 的 `cppgc` 组件（一个 C++ 编写的垃圾回收器）的统计信息。 虽然它本身不是 JavaScript 代码，但它 **直接关联到 JavaScript 的功能**，因为垃圾回收是 JavaScript 引擎管理内存的关键部分。

**JavaScript 例子说明:**

当 JavaScript 代码创建对象并最终不再使用它们时，V8 的垃圾回收器（包括 `cppgc`）会回收这些对象占用的内存。 `StatsCollector` 就在这个过程中收集相关的统计信息，例如有多少对象被标记为可回收，回收了多少内存等等。

```javascript
// JavaScript 例子

let myObject = { data: new Array(10000).fill(0) }; // 创建一个占用一定内存的对象

// ... 一段时间后，myObject 不再被使用

myObject = null; //  让 myObject 变为垃圾回收的候选者

// 在 V8 的垃圾回收过程中，StatsCollector 会记录与 myObject 回收相关的统计信息。
```

**代码逻辑推理 (假设输入与输出):**

**测试用例:** `TEST_F(StatsCollectorTest, EventPrevGCMarkedObjectSize)`

**假设输入:**

1. 调用 `stats.NotifyMarkingStarted(CollectionType::kMajor, GCConfig::MarkingType::kAtomic, GCConfig::IsForcedGC::kNotForced);`  表示开始一次 Major GC 的原子标记阶段。
2. 调用 `stats.NotifyMarkingCompleted(1024);` 表示标记阶段完成，标记了 1024 字节。
3. 调用 `stats.NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);` 表示清理阶段完成。

**预期输出:**

-   调用 `stats.GetPreviousEventForTesting()` 应该返回一个 `GCEvent` 对象，其中 `event.marked_bytes` 的值为 `1024u`。
-   `EXPECT_EQ(1024u, event.marked_bytes);` 断言会成功。

**用户常见的编程错误 (与垃圾回收统计相关的潜在错误):**

1. **过早优化基于不准确的统计信息:**  开发者可能会查看垃圾回收统计信息，并基于这些信息进行优化，但如果没有充分理解统计信息的含义或者统计信息本身存在偏差，可能会导致错误的优化方向，甚至引入性能问题。 例如，仅仅因为看到某个时间段 Full GC 频率较高就盲目增加堆大小，而没有分析根本原因。

2. **内存泄漏的诊断延迟:**  如果开发者没有有效地利用垃圾回收统计信息，可能无法及时发现内存泄漏。 持续增长的堆大小和频繁的 Full GC 可能预示着内存泄漏，但如果开发者没有监控这些指标，问题可能会被忽视直到造成严重影响。

3. **不理解对象生命周期对垃圾回收的影响:** 开发者可能不理解 JavaScript 对象的生命周期和作用域如何影响垃圾回收。 创建大量临时对象或者持有对不再需要的对象的引用会导致不必要的垃圾回收开销，而 `StatsCollector` 的信息可以帮助理解这些开销的来源。

4. **过度依赖手动内存管理 (在不必要的情况下):**  虽然 V8 提供了自动垃圾回收，但在某些情况下，开发者可能会尝试进行手动内存管理（例如，错误地认为手动释放某些资源可以显著提升性能）。 然而，这种做法往往是复杂且容易出错的，而且可能与垃圾回收器的机制冲突，反而导致问题。 理解 `StatsCollector` 提供的统计信息可以帮助开发者评估手动内存管理的必要性和效果。

总而言之， `v8/test/unittests/heap/cppgc/stats-collector-unittest.cc`  全面测试了 `StatsCollector` 类的功能，确保它能够准确地收集和报告 `cppgc` 垃圾回收器的各种统计信息，并通过观察者模式将这些信息传递出去，这对于 V8 引擎的性能监控和调优至关重要。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/stats-collector-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/stats-collector-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/stats-collector.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

constexpr size_t kNoMarkedBytes = 0;

constexpr size_t kMinReportedSize = StatsCollector::kAllocationThresholdBytes;

class StatsCollectorTest : public ::testing::Test {
 public:
  static constexpr Platform* kNoPlatform = nullptr;

  StatsCollectorTest() : stats(kNoPlatform) {}

  void FakeAllocate(size_t bytes) {
    stats.NotifyAllocation(bytes);
    stats.NotifySafePointForConservativeCollection();
  }

  void FakeFree(size_t bytes) {
    stats.NotifyExplicitFree(bytes);
    stats.NotifySafePointForConservativeCollection();
  }

  StatsCollector stats;
};

}  // namespace

TEST_F(StatsCollectorTest, NoMarkedBytes) {
  stats.NotifyMarkingStarted(CollectionType::kMajor,
                             GCConfig::MarkingType::kAtomic,
                             GCConfig::IsForcedGC::kNotForced);
  stats.NotifyMarkingCompleted(kNoMarkedBytes);
  stats.NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
  auto event = stats.GetPreviousEventForTesting();
  EXPECT_EQ(0u, event.marked_bytes);
}

TEST_F(StatsCollectorTest, EventPrevGCMarkedObjectSize) {
  stats.NotifyMarkingStarted(CollectionType::kMajor,
                             GCConfig::MarkingType::kAtomic,
                             GCConfig::IsForcedGC::kNotForced);
  stats.NotifyMarkingCompleted(1024);
  stats.NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
  auto event = stats.GetPreviousEventForTesting();
  EXPECT_EQ(1024u, event.marked_bytes);
}

TEST_F(StatsCollectorTest, AllocationNoReportBelowAllocationThresholdBytes) {
  constexpr size_t kObjectSize = 17;
  EXPECT_LT(kObjectSize, StatsCollector::kAllocationThresholdBytes);
  FakeAllocate(kObjectSize);
  EXPECT_EQ(0u, stats.allocated_object_size());
}

TEST_F(StatsCollectorTest, AlllocationReportAboveAllocationThresholdBytes) {
  constexpr size_t kObjectSize = StatsCollector::kAllocationThresholdBytes;
  EXPECT_GE(kObjectSize, StatsCollector::kAllocationThresholdBytes);
  FakeAllocate(kObjectSize);
  EXPECT_EQ(kObjectSize, stats.allocated_object_size());
}

TEST_F(StatsCollectorTest, InitialAllocatedObjectSize) {
  stats.NotifyMarkingStarted(CollectionType::kMajor,
                             GCConfig::MarkingType::kAtomic,
                             GCConfig::IsForcedGC::kNotForced);
  EXPECT_EQ(0u, stats.allocated_object_size());
  stats.NotifyMarkingCompleted(kNoMarkedBytes);
  EXPECT_EQ(0u, stats.allocated_object_size());
  stats.NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
  EXPECT_EQ(0u, stats.allocated_object_size());
}

TEST_F(StatsCollectorTest, AllocatedObjectSize) {
  stats.NotifyMarkingStarted(CollectionType::kMajor,
                             GCConfig::MarkingType::kAtomic,
                             GCConfig::IsForcedGC::kNotForced);
  FakeAllocate(kMinReportedSize);
  EXPECT_EQ(kMinReportedSize, stats.allocated_object_size());
  stats.NotifyMarkingCompleted(kMinReportedSize);
  EXPECT_EQ(kMinReportedSize, stats.allocated_object_size());
  stats.NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
  EXPECT_EQ(kMinReportedSize, stats.allocated_object_size());
}

TEST_F(StatsCollectorTest, AllocatedObjectSizeNoMarkedBytes) {
  stats.NotifyMarkingStarted(CollectionType::kMajor,
                             GCConfig::MarkingType::kAtomic,
                             GCConfig::IsForcedGC::kNotForced);
  FakeAllocate(kMinReportedSize);
  EXPECT_EQ(kMinReportedSize, stats.allocated_object_size());
  stats.NotifyMarkingCompleted(kNoMarkedBytes);
  EXPECT_EQ(0u, stats.allocated_object_size());
  stats.NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
  EXPECT_EQ(0u, stats.allocated_object_size());
}

TEST_F(StatsCollectorTest, AllocatedObjectSizeAllocateAfterMarking) {
  stats.NotifyMarkingStarted(CollectionType::kMajor,
                             GCConfig::MarkingType::kAtomic,
                             GCConfig::IsForcedGC::kNotForced);
  FakeAllocate(kMinReportedSize);
  EXPECT_EQ(kMinReportedSize, stats.allocated_object_size());
  stats.NotifyMarkingCompleted(kMinReportedSize);
  FakeAllocate(kMinReportedSize);
  EXPECT_EQ(2 * kMinReportedSize, stats.allocated_object_size());
  stats.NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
  EXPECT_EQ(2 * kMinReportedSize, stats.allocated_object_size());
}

class MockAllocationObserver : public StatsCollector::AllocationObserver {
 public:
  MOCK_METHOD(void, AllocatedObjectSizeIncreased, (size_t), (override));
  MOCK_METHOD(void, AllocatedObjectSizeDecreased, (size_t), (override));
  MOCK_METHOD(void, ResetAllocatedObjectSize, (size_t), (override));
  MOCK_METHOD(void, AllocatedSizeIncreased, (size_t), (override));
  MOCK_METHOD(void, AllocatedSizeDecreased, (size_t), (override));
};

TEST_F(StatsCollectorTest, RegisterUnregisterObserver) {
  MockAllocationObserver observer;
  stats.RegisterObserver(&observer);
  stats.UnregisterObserver(&observer);
}

TEST_F(StatsCollectorTest, ObserveAllocatedObjectSizeIncreaseAndDecrease) {
  MockAllocationObserver observer;
  stats.RegisterObserver(&observer);
  EXPECT_CALL(observer, AllocatedObjectSizeIncreased(kMinReportedSize));
  FakeAllocate(kMinReportedSize);
  EXPECT_CALL(observer, AllocatedObjectSizeDecreased(kMinReportedSize));
  FakeFree(kMinReportedSize);
  stats.UnregisterObserver(&observer);
}

namespace {

void FakeGC(StatsCollector* stats, size_t marked_bytes) {
  stats->NotifyMarkingStarted(CollectionType::kMajor,
                              GCConfig::MarkingType::kAtomic,
                              GCConfig::IsForcedGC::kNotForced);
  stats->NotifyMarkingCompleted(marked_bytes);
  stats->NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
}

}  // namespace

TEST_F(StatsCollectorTest, ObserveResetAllocatedObjectSize) {
  MockAllocationObserver observer;
  stats.RegisterObserver(&observer);
  EXPECT_CALL(observer, AllocatedObjectSizeIncreased(kMinReportedSize));
  FakeAllocate(kMinReportedSize);
  EXPECT_CALL(observer, ResetAllocatedObjectSize(64));
  FakeGC(&stats, 64);
  stats.UnregisterObserver(&observer);
}

TEST_F(StatsCollectorTest, ObserveAllocatedMemoryIncreaseAndDecrease) {
  MockAllocationObserver observer;
  stats.RegisterObserver(&observer);
  static constexpr size_t kAllocatedMemorySize = 4096;
  EXPECT_CALL(observer, AllocatedSizeIncreased(kAllocatedMemorySize));
  stats.NotifyAllocatedMemory(kAllocatedMemorySize);
  static constexpr size_t kFreedMemorySize = 2048;
  EXPECT_CALL(observer, AllocatedSizeDecreased(kFreedMemorySize));
  stats.NotifyFreedMemory(kFreedMemorySize);
  stats.UnregisterObserver(&observer);
}

namespace {

class AllocationObserverTriggeringGC final
    : public StatsCollector::AllocationObserver {
 public:
  AllocationObserverTriggeringGC(StatsCollector* stats, double survival_ratio)
      : stats(stats), survival_ratio_(survival_ratio) {}

  void AllocatedObjectSizeIncreased(size_t bytes) final {
    increase_call_count++;
    increased_size_bytes += bytes;
    if (increase_call_count == 1) {
      FakeGC(stats, bytes * survival_ratio_);
    }
  }

  // // Mock out the rest to trigger warnings if used.
  MOCK_METHOD(void, AllocatedObjectSizeDecreased, (size_t), (override));
  MOCK_METHOD(void, ResetAllocatedObjectSize, (size_t), (override));

  size_t increase_call_count = 0;
  size_t increased_size_bytes = 0;
  StatsCollector* stats;
  double survival_ratio_;
};

}  // namespace

TEST_F(StatsCollectorTest, ObserverTriggersGC) {
  constexpr double kSurvivalRatio = 0.5;
  AllocationObserverTriggeringGC gc_observer(&stats, kSurvivalRatio);
  MockAllocationObserver mock_observer;
  // Internal detail: First registered observer is also notified first.
  stats.RegisterObserver(&gc_observer);
  stats.RegisterObserver(&mock_observer);

  // Both observers see the exact allocated object size byte count.
  EXPECT_CALL(mock_observer,
              ResetAllocatedObjectSize(kMinReportedSize * kSurvivalRatio));
  EXPECT_CALL(gc_observer,
              ResetAllocatedObjectSize(kMinReportedSize * kSurvivalRatio));

  // Since the GC clears counters, mock_observer should see an increase call
  // with a delta of zero bytes. This expectation makes use of the internal
  // detail that first registered observer triggers GC.
  EXPECT_CALL(mock_observer, AllocatedObjectSizeIncreased(0));

  // Trigger scenario.
  FakeAllocate(kMinReportedSize);

  EXPECT_EQ(1u, gc_observer.increase_call_count);
  EXPECT_EQ(kMinReportedSize, gc_observer.increased_size_bytes);

  stats.UnregisterObserver(&gc_observer);
  stats.UnregisterObserver(&mock_observer);
}

TEST_F(StatsCollectorTest, AllocatedMemorySize) {
  EXPECT_EQ(0u, stats.allocated_memory_size());
  stats.NotifyAllocatedMemory(1024);
  EXPECT_EQ(1024u, stats.allocated_memory_size());
  stats.NotifyFreedMemory(1024);
  EXPECT_EQ(0u, stats.allocated_memory_size());
}

TEST_F(StatsCollectorTest, DiscardedMemorySize) {
  EXPECT_EQ(0u, stats.discarded_memory_size());
  stats.IncrementDiscardedMemory(1024);
  EXPECT_EQ(1024u, stats.discarded_memory_size());
  stats.DecrementDiscardedMemory(1024);
  EXPECT_EQ(0u, stats.discarded_memory_size());
}

TEST_F(StatsCollectorTest, ResidentMemorySizeWithoutDiscarded) {
  EXPECT_EQ(0u, stats.resident_memory_size());
  stats.NotifyAllocatedMemory(1024);
  EXPECT_EQ(1024u, stats.resident_memory_size());
  stats.NotifyFreedMemory(1024);
  EXPECT_EQ(0u, stats.resident_memory_size());
}

TEST_F(StatsCollectorTest, ResidentMemorySizeWithDiscarded) {
  EXPECT_EQ(0u, stats.resident_memory_size());
  stats.NotifyAllocatedMemory(8192);
  EXPECT_EQ(8192u, stats.resident_memory_size());
  stats.IncrementDiscardedMemory(4096);
  EXPECT_EQ(4096u, stats.resident_memory_size());
  stats.DecrementDiscardedMemory(4096);
  EXPECT_EQ(8192u, stats.resident_memory_size());
  stats.NotifyFreedMemory(8192);
  EXPECT_EQ(0u, stats.resident_memory_size());
}

}  // namespace internal
}  // namespace cppgc

"""

```