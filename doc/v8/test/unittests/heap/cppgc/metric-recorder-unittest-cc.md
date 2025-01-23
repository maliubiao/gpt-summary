Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for the functionalities of the provided C++ code, specifically focusing on a unit test file for `MetricRecorder`. It also has conditional requests about Torque, JavaScript, logic, and common errors.

2. **Identify the Main Subject:** The code clearly defines and tests a class called `MetricRecorderImpl` and its base class `MetricRecorder`. The tests are within a class `MetricRecorderTest`. This immediately tells me the core functionality revolves around recording and tracking metrics related to garbage collection (GC).

3. **Analyze `MetricRecorderImpl`:**  This class *implements* the `MetricRecorder` interface. It has methods `AddMainThreadEvent` that take different event types related to GC cycles (full GC, incremental marking, incremental sweeping). Crucially, it *stores* these events and counts how many times each event type is recorded using static member variables. This suggests it's a mock or simplified implementation used for testing purposes.

4. **Analyze `MetricRecorderTest`:** This class sets up the testing environment.
    * It inherits from `testing::TestWithHeap`, implying it's testing code that interacts with a heap (likely the V8 heap).
    * It instantiates `MetricRecorderImpl` and sets it as the active recorder in the `StatsCollector`.
    * It has helper functions `StartGC` and `EndGC` that simulate the beginning and end of garbage collection cycles by interacting with the `StatsCollector`.
    * The `TEST_F` macros define individual test cases.

5. **Break Down the Test Cases:** I go through each `TEST_F` and analyze what it's verifying:
    * `IncrementalScopesReportedImmediately`: Checks that incremental mark and sweep events are recorded *immediately* when their corresponding `EnabledScope` goes out of scope.
    * `NonIncrementalScopesNotReportedImmediately`: Checks that non-incremental (atomic, concurrent) events are *not* reported immediately.
    * `CycleEndMetricsReportedOnGcEnd`: Checks that a full GC cycle event is recorded when `EndGC` is called.
    * `CycleEndHistogramReportsCorrectValues`: This is a more complex test. It simulates a GC cycle, creates various `EnabledScope` and `EnabledConcurrentScope` objects with simulated durations, and then verifies that the durations recorded in the `GCCycle` event are correct. It also checks collection rate and efficiency.
    * `ObjectSizeMetricsNoAllocations`: Tests the recording of object sizes before and after GC when there are no allocations during the cycle.
    * `ObjectSizeMetricsWithAllocations`: Tests the recording of object and memory sizes before and after GC, including simulating allocations and frees during the cycle.

6. **Synthesize the Functionality:** Based on the analysis, I formulate the main functionalities:
    * Records metrics for different phases of garbage collection (incremental mark/sweep, full GC, atomic phases, concurrent phases).
    * Differentiates between incremental and non-incremental GC phases in terms of when metrics are recorded.
    * Calculates and records duration, collection rate, and efficiency of GC cycles.
    * Tracks object and memory usage before and after GC.

7. **Address Conditional Requests:**
    * **`.tq` extension:**  I check the file extension. It's `.cc`, so it's C++, *not* Torque.
    * **JavaScript Relationship:**  The code is part of V8, the JavaScript engine. Therefore, it directly relates to JavaScript's garbage collection mechanism. I provide a JavaScript example to illustrate how GC affects object lifecycle and memory management.
    * **Logic and Assumptions:** I identify the key assumption: the `StatsCollector` is the component that triggers the `MetricRecorder` to record events. I then create a hypothetical scenario with inputs to `StartGC` and `EndGC` and predict the output based on the code's behavior.
    * **Common Programming Errors:** I think about how developers might misuse or misunderstand concepts related to garbage collection and memory management in JavaScript, such as creating memory leaks through circular references or holding onto objects unnecessarily.

8. **Structure the Answer:** I organize the information logically, starting with the main functionalities, then addressing the conditional requests in order, and finally summarizing with potential programming errors. I use clear headings and formatting to improve readability.

9. **Refine and Review:** I reread my answer and the original code to ensure accuracy and completeness. I check for any inconsistencies or areas that could be clearer. For example, I explicitly mention that `MetricRecorderImpl` is a test implementation.
Based on the provided C++ code, `v8/test/unittests/heap/cppgc/metric-recorder-unittest.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This file contains unit tests for the `MetricRecorder` class within the `cppgc` (C++ garbage collection) component of V8. The primary goal of these tests is to verify that the `MetricRecorder` correctly records and reports metrics related to garbage collection cycles and their sub-phases.

Specifically, the tests focus on:

1. **Recording GC Events:**  The tests check that the `MetricRecorder` records events for different stages of garbage collection, including:
   - **Incremental Marking:**  A phase where the heap is marked incrementally over time.
   - **Incremental Sweeping:** A phase where garbage is reclaimed incrementally.
   - **Full GC Cycles:**  A complete garbage collection cycle.
   - **Atomic Phases:**  Non-incremental phases like atomic marking, sweeping, and compaction.
   - **Concurrent Phases:** Phases that can run in parallel with the main thread.

2. **Immediate Reporting of Incremental Events:** The tests verify that events for incremental marking and sweeping are reported immediately when the corresponding scope (managed by `StatsCollector::EnabledScope`) ends.

3. **Delayed Reporting of Non-Incremental Events:** The tests ensure that events for non-incremental GC phases are not reported immediately but are aggregated and reported at the end of the GC cycle.

4. **Reporting of Cycle-End Metrics:**  The tests confirm that metrics summarizing the entire GC cycle (durations of different phases, total duration, collection rate, efficiency, object and memory usage) are recorded and available when the GC cycle completes.

5. **Correctness of Reported Values:**  A significant part of the tests involves checking the accuracy of the recorded metrics, especially the durations of different GC phases. They simulate time spent in different phases and verify that the `MetricRecorder` captures these durations correctly. The tests also verify collection rate and efficiency calculations.

6. **Tracking Object and Memory Sizes:** The tests check if the `MetricRecorder` correctly records the number of objects and the amount of memory before and after a garbage collection cycle, as well as the amount of memory freed.

**Analysis of the Code:**

- **`MetricRecorderImpl`:** This is a test implementation (mock) of the `MetricRecorder` interface. It provides simple methods to record GC events by storing the event details and incrementing a counter. This allows the tests to easily inspect what events were recorded and their values.

- **`MetricRecorderTest`:** This class sets up the testing environment. It:
    - Inherits from `testing::TestWithHeap`, providing access to a V8 heap for testing.
    - Sets up the `MetricRecorderImpl` to be used by the `StatsCollector`.
    - Provides helper methods `StartGC` and `EndGC` to simulate the beginning and end of garbage collection cycles, triggering notifications to the `StatsCollector`.

- **Test Cases (`TEST_F`):** Each `TEST_F` macro defines an individual test that focuses on a specific aspect of the `MetricRecorder`'s functionality.

**Conditional Checks:**

* **`.tq` Extension:** The filename ends with `.cc`, not `.tq`. Therefore, it is **not** a V8 Torque source file. It's a standard C++ source file.

* **Relationship with JavaScript:** Yes, this code has a direct relationship with JavaScript functionality. Garbage collection is a fundamental part of JavaScript's memory management. V8, the JavaScript engine used in Chrome and Node.js, uses `cppgc` for managing the heap of C++ objects within the engine. The metrics recorded by `MetricRecorder` are crucial for understanding and optimizing the performance of JavaScript garbage collection.

**JavaScript Example:**

While this C++ code doesn't directly execute JavaScript, it measures aspects of the underlying engine that supports JavaScript. Here's how the concepts relate to JavaScript:

```javascript
// Example demonstrating potential GC impact

let myObject = { data: new Array(1000000) }; // Allocate a large object

// ... some code that uses myObject ...

myObject = null; // Make the object eligible for garbage collection

// At some point, V8's garbage collector will run and potentially reclaim the
// memory occupied by the object's data. The MetricRecorder would record
// information about this GC cycle, such as the duration and the amount of
// memory freed.

// In a more complex scenario with many object allocations and deallocations,
// the MetricRecorder would provide insights into the efficiency and performance
// of the garbage collector.
```

**Code Logic Reasoning (with Assumptions):**

**Assumption:** The `StatsCollector` is the component that triggers the `MetricRecorder` to record events based on notifications about GC state changes and the opening/closing of `EnabledScope` objects.

**Scenario 1: Incremental Marking**

* **Input:**
    1. `StartGC()` is called.
    2. An `EnabledScope` for `StatsCollector::kIncrementalMark` is created.
    3. The scope is closed.
    4. `EndGC()` is called.
* **Output:**
    - `MetricRecorderImpl::MainThreadIncrementalMark_callcount` will be 1.
    - `MetricRecorderImpl::MainThreadIncrementalMark_event.duration_us` will be greater than 0 (assuming some time passed within the scope).
    - `MetricRecorderImpl::GCCycle_callcount` will be 1.

**Scenario 2: Atomic Marking**

* **Input:**
    1. `StartGC()` is called.
    2. An `EnabledScope` for `StatsCollector::kAtomicMark` is created and closed.
    3. `EndGC()` is called.
* **Output:**
    - `MetricRecorderImpl::MainThreadIncrementalMark_callcount` will be 0 (atomic events are not reported immediately).
    - `MetricRecorderImpl::GCCycle_callcount` will be 1.
    - `MetricRecorderImpl::GCCycle_event.main_thread_atomic.mark_duration_us` will be greater than 0.

**User Common Programming Errors (Related to GC and Metrics):**

1. **Memory Leaks:**  In JavaScript (and C++), unintentionally holding onto references to objects can prevent the garbage collector from reclaiming their memory. This will be reflected in the metrics as increased memory usage and potentially longer GC durations.

   ```javascript
   // Example of a potential memory leak in JavaScript
   let leakedObjects = [];
   function createLeakyObject() {
     let obj = { data: new Array(1000) };
     leakedObjects.push(obj); // Holding onto the object unnecessarily
   }

   for (let i = 0; i < 1000; i++) {
     createLeakyObject();
   }
   // The 'leakedObjects' array keeps references to all the created objects,
   // preventing them from being garbage collected even if they are no longer
   // needed by the rest of the application.
   ```

2. **Premature Optimization based on Misinterpreted Metrics:**  Developers might try to optimize garbage collection based on metrics without fully understanding the underlying causes. For example, seeing a high GC duration might lead to premature or incorrect optimizations if the root cause is not properly identified (e.g., excessive object creation or inefficient data structures).

3. **Ignoring GC Impact:**  Developers might write code without considering the impact on garbage collection. Creating many temporary objects in performance-critical sections can lead to frequent and potentially long GC pauses, impacting application responsiveness. The metrics provided by `MetricRecorder` help identify such issues.

4. **Circular References (in JavaScript):**  While modern garbage collectors can often handle simple circular references, complex ones can still cause issues in some cases. These would show up as higher memory usage and potentially less efficient garbage collection.

   ```javascript
   // Example of circular reference in JavaScript
   let objectA = {};
   let objectB = {};

   objectA.reference = objectB;
   objectB.reference = objectA;

   // If there are no other references to objectA and objectB, they become
   // eligible for garbage collection. However, the circular reference
   // between them might make it take longer for the garbage collector to
   // identify and reclaim their memory.
   ```

In summary, `v8/test/unittests/heap/cppgc/metric-recorder-unittest.cc` is a crucial part of ensuring the correctness and reliability of the garbage collection metrics within V8's `cppgc` component. These metrics are vital for understanding and optimizing the performance of JavaScript applications.

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/metric-recorder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/metric-recorder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/metric-recorder.h"

#include "src/heap/cppgc/stats-collector.h"
#include "test/unittests/heap/cppgc/tests.h"

namespace cppgc {
namespace internal {

namespace {
class MetricRecorderImpl final : public MetricRecorder {
 public:
  void AddMainThreadEvent(const GCCycle& event) final {
    GCCycle_event = event;
    GCCycle_callcount++;
  }
  void AddMainThreadEvent(const MainThreadIncrementalMark& event) final {
    MainThreadIncrementalMark_event = event;
    MainThreadIncrementalMark_callcount++;
  }
  void AddMainThreadEvent(const MainThreadIncrementalSweep& event) final {
    MainThreadIncrementalSweep_event = event;
    MainThreadIncrementalSweep_callcount++;
  }

  static size_t GCCycle_callcount;
  static GCCycle GCCycle_event;
  static size_t MainThreadIncrementalMark_callcount;
  static MainThreadIncrementalMark MainThreadIncrementalMark_event;
  static size_t MainThreadIncrementalSweep_callcount;
  static MainThreadIncrementalSweep MainThreadIncrementalSweep_event;
};

// static
size_t MetricRecorderImpl::GCCycle_callcount = 0u;
MetricRecorderImpl::GCCycle MetricRecorderImpl::GCCycle_event;
size_t MetricRecorderImpl::MainThreadIncrementalMark_callcount = 0u;
MetricRecorderImpl::MainThreadIncrementalMark
    MetricRecorderImpl::MainThreadIncrementalMark_event;
size_t MetricRecorderImpl::MainThreadIncrementalSweep_callcount = 0u;
MetricRecorderImpl::MainThreadIncrementalSweep
    MetricRecorderImpl::MainThreadIncrementalSweep_event;

class MetricRecorderTest : public testing::TestWithHeap {
 public:
  MetricRecorderTest() : stats(Heap::From(GetHeap())->stats_collector()) {
    stats->SetMetricRecorder(std::make_unique<MetricRecorderImpl>());
  }

  void StartGC() {
    stats->NotifyMarkingStarted(CollectionType::kMajor,
                                GCConfig::MarkingType::kIncremental,
                                GCConfig::IsForcedGC::kNotForced);
  }
  void EndGC(size_t marked_bytes) {
    stats->NotifyMarkingCompleted(marked_bytes);
    stats->NotifySweepingCompleted(GCConfig::SweepingType::kIncremental);
  }

  StatsCollector* stats;
};
}  // namespace

TEST_F(MetricRecorderTest, IncrementalScopesReportedImmediately) {
  MetricRecorderImpl::GCCycle_callcount = 0u;
  MetricRecorderImpl::MainThreadIncrementalMark_callcount = 0u;
  MetricRecorderImpl::MainThreadIncrementalSweep_callcount = 0u;
  StartGC();
  {
    EXPECT_EQ(0u, MetricRecorderImpl::MainThreadIncrementalMark_callcount);
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kIncrementalMark);
      scope.DecreaseStartTimeForTesting(
          v8::base::TimeDelta::FromMilliseconds(1));
    }
    EXPECT_EQ(1u, MetricRecorderImpl::MainThreadIncrementalMark_callcount);
    EXPECT_LT(0u,
              MetricRecorderImpl::MainThreadIncrementalMark_event.duration_us);
  }
  {
    EXPECT_EQ(0u, MetricRecorderImpl::MainThreadIncrementalSweep_callcount);
    {
      StatsCollector::EnabledScope scope(
          Heap::From(GetHeap())->stats_collector(),
          StatsCollector::kIncrementalSweep);
      scope.DecreaseStartTimeForTesting(
          v8::base::TimeDelta::FromMilliseconds(1));
    }
    EXPECT_EQ(1u, MetricRecorderImpl::MainThreadIncrementalSweep_callcount);
    EXPECT_LT(0u,
              MetricRecorderImpl::MainThreadIncrementalSweep_event.duration_us);
  }
  EXPECT_EQ(0u, MetricRecorderImpl::GCCycle_callcount);
  EndGC(0);
}

TEST_F(MetricRecorderTest, NonIncrementalScopesNotReportedImmediately) {
  MetricRecorderImpl::GCCycle_callcount = 0u;
  MetricRecorderImpl::MainThreadIncrementalMark_callcount = 0u;
  MetricRecorderImpl::MainThreadIncrementalSweep_callcount = 0u;
  StartGC();
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kAtomicMark);
  }
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kAtomicWeak);
  }
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kAtomicCompact);
  }
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kAtomicSweep);
  }
  {
    StatsCollector::EnabledConcurrentScope scope(
        Heap::From(GetHeap())->stats_collector(),
        StatsCollector::kConcurrentMark);
  }
  {
    StatsCollector::EnabledConcurrentScope scope(
        Heap::From(GetHeap())->stats_collector(),
        StatsCollector::kConcurrentSweep);
  }
  EXPECT_EQ(0u, MetricRecorderImpl::MainThreadIncrementalMark_callcount);
  EXPECT_EQ(0u, MetricRecorderImpl::MainThreadIncrementalSweep_callcount);
  EXPECT_EQ(0u, MetricRecorderImpl::GCCycle_callcount);
  EndGC(0);
}

TEST_F(MetricRecorderTest, CycleEndMetricsReportedOnGcEnd) {
  MetricRecorderImpl::GCCycle_callcount = 0u;
  MetricRecorderImpl::MainThreadIncrementalMark_callcount = 0u;
  MetricRecorderImpl::MainThreadIncrementalSweep_callcount = 0u;
  StartGC();
  EndGC(0);
  EXPECT_EQ(0u, MetricRecorderImpl::MainThreadIncrementalMark_callcount);
  EXPECT_EQ(0u, MetricRecorderImpl::MainThreadIncrementalSweep_callcount);
  EXPECT_EQ(1u, MetricRecorderImpl::GCCycle_callcount);
}

TEST_F(MetricRecorderTest, CycleEndHistogramReportsCorrectValues) {
  StartGC();
  {
    // Warmup scope to make sure everything is loaded in memory and reduce noise
    // in timing measurements.
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kIncrementalMark);
  }
  EndGC(1000);
  StartGC();
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kIncrementalMark);
    scope.DecreaseStartTimeForTesting(
        v8::base::TimeDelta::FromMilliseconds(10));
  }
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kIncrementalSweep);
    scope.DecreaseStartTimeForTesting(
        v8::base::TimeDelta::FromMilliseconds(20));
  }
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kAtomicMark);
    scope.DecreaseStartTimeForTesting(
        v8::base::TimeDelta::FromMilliseconds(30));
  }
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kAtomicWeak);
    scope.DecreaseStartTimeForTesting(
        v8::base::TimeDelta::FromMilliseconds(50));
  }
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kAtomicCompact);
    scope.DecreaseStartTimeForTesting(
        v8::base::TimeDelta::FromMilliseconds(60));
  }
  {
    StatsCollector::EnabledScope scope(Heap::From(GetHeap())->stats_collector(),
                                       StatsCollector::kAtomicSweep);
    scope.DecreaseStartTimeForTesting(
        v8::base::TimeDelta::FromMilliseconds(70));
  }
  {
    StatsCollector::EnabledConcurrentScope scope(
        Heap::From(GetHeap())->stats_collector(),
        StatsCollector::kConcurrentMark);
    scope.DecreaseStartTimeForTesting(
        v8::base::TimeDelta::FromMilliseconds(80));
  }
  {
    StatsCollector::EnabledConcurrentScope scope(
        Heap::From(GetHeap())->stats_collector(),
        StatsCollector::kConcurrentSweep);
    scope.DecreaseStartTimeForTesting(
        v8::base::TimeDelta::FromMilliseconds(100));
  }
  EndGC(300);
  // Check durations.
  static constexpr int64_t kDurationComparisonTolerance = 5000;
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.main_thread_incremental
                         .mark_duration_us -
                     10000),
            kDurationComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.main_thread_incremental
                         .sweep_duration_us -
                     20000),
            kDurationComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.main_thread_atomic
                         .mark_duration_us -
                     30000),
            kDurationComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.main_thread_atomic
                         .weak_duration_us -
                     50000),
            kDurationComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.main_thread_atomic
                         .compact_duration_us -
                     60000),
            kDurationComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.main_thread_atomic
                         .sweep_duration_us -
                     70000),
            kDurationComparisonTolerance);
  EXPECT_LT(
      std::abs(MetricRecorderImpl::GCCycle_event.main_thread.mark_duration_us -
               40000),
      kDurationComparisonTolerance);
  EXPECT_LT(
      std::abs(MetricRecorderImpl::GCCycle_event.main_thread.weak_duration_us -
               50000),
      kDurationComparisonTolerance);
  EXPECT_LT(
      std::abs(
          MetricRecorderImpl::GCCycle_event.main_thread.compact_duration_us -
          60000),
      kDurationComparisonTolerance);
  EXPECT_LT(
      std::abs(MetricRecorderImpl::GCCycle_event.main_thread.sweep_duration_us -
               90000),
      kDurationComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.total.mark_duration_us -
                     120000),
            kDurationComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.total.weak_duration_us -
                     50000),
            kDurationComparisonTolerance);
  EXPECT_LT(
      std::abs(MetricRecorderImpl::GCCycle_event.total.compact_duration_us -
               60000),
      kDurationComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event.total.sweep_duration_us -
                     190000),
            kDurationComparisonTolerance);
  // Check collection rate and efficiency.
  EXPECT_DOUBLE_EQ(
      0.7, MetricRecorderImpl::GCCycle_event.collection_rate_in_percent);
  static constexpr double kEfficiencyComparisonTolerance = 0.0005;
  EXPECT_LT(
      std::abs(MetricRecorderImpl::GCCycle_event.efficiency_in_bytes_per_us -
               (700.0 / (120000 + 50000 + 60000 + 190000))),
      kEfficiencyComparisonTolerance);
  EXPECT_LT(std::abs(MetricRecorderImpl::GCCycle_event
                         .main_thread_efficiency_in_bytes_per_us -
                     (700.0 / (40000 + 50000 + 60000 + 90000))),
            kEfficiencyComparisonTolerance);
}

TEST_F(MetricRecorderTest, ObjectSizeMetricsNoAllocations) {
  // Populate previous event.
  StartGC();
  EndGC(1000);
  // Populate current event.
  StartGC();
  EndGC(800);
  EXPECT_EQ(1000u, MetricRecorderImpl::GCCycle_event.objects.before_bytes);
  EXPECT_EQ(800u, MetricRecorderImpl::GCCycle_event.objects.after_bytes);
  EXPECT_EQ(200u, MetricRecorderImpl::GCCycle_event.objects.freed_bytes);
  EXPECT_EQ(0u, MetricRecorderImpl::GCCycle_event.memory.before_bytes);
  EXPECT_EQ(0u, MetricRecorderImpl::GCCycle_event.memory.after_bytes);
  EXPECT_EQ(0u, MetricRecorderImpl::GCCycle_event.memory.freed_bytes);
}

TEST_F(MetricRecorderTest, ObjectSizeMetricsWithAllocations) {
  // Populate previous event.
  StartGC();
  EndGC(1000);
  // Populate current event.
  StartGC();
  stats->NotifyAllocation(300);
  stats->NotifyAllocatedMemory(1400);
  stats->NotifyFreedMemory(700);
  stats->NotifyMarkingCompleted(800);
  stats->NotifyAllocation(150);
  stats->NotifyAllocatedMemory(1000);
  stats->NotifyFreedMemory(400);
  stats->NotifySweepingCompleted(GCConfig::SweepingType::kAtomic);
  EXPECT_EQ(1300u, MetricRecorderImpl::GCCycle_event.objects.before_bytes);
  EXPECT_EQ(800, MetricRecorderImpl::GCCycle_event.objects.after_bytes);
  EXPECT_EQ(500u, MetricRecorderImpl::GCCycle_event.objects.freed_bytes);
  EXPECT_EQ(700u, MetricRecorderImpl::GCCycle_event.memory.before_bytes);
  EXPECT_EQ(300u, MetricRecorderImpl::GCCycle_event.memory.after_bytes);
  EXPECT_EQ(400u, MetricRecorderImpl::GCCycle_event.memory.freed_bytes);
}

}  // namespace internal
}  // namespace cppgc
```