Response:
Let's break down the thought process for analyzing the `v8/src/logging/counters.h` file.

1. **Understand the Goal:** The request asks for the functionality of this C++ header file within the V8 JavaScript engine. It also has specific sub-questions about Torque, JavaScript relevance, code logic, and common errors.

2. **Initial Skim and Keyword Identification:**  Read through the header file, looking for recurring keywords and class names. Keywords like `StatsCounter`, `Histogram`, `TimedHistogram`, `Counters`, `Isolate`, `Callback`, `atomic`, `Mutex`, and `#define` jump out. These provide initial clues about the file's purpose.

3. **High-Level Purpose Deduction:** Based on the keywords, it's clear the file deals with collecting and managing statistics and performance metrics within V8. The "logging" directory also reinforces this idea. The different histogram types suggest capturing distributions of events or timings. The `StatsCounter` suggests simple value tracking.

4. **Deconstructing Key Classes:**  Analyze the purpose of each major class:

    * **`StatsTable`:**  This seems to be a central registry. The `SetCounterFunction`, `SetCreateHistogramFunction`, and `SetAddHistogramSampleFunction` strongly indicate it's the interface for external systems to plug into V8's internal counters. The `FindLocation` suggests a way to get a memory location for a specific counter.

    * **`StatsCounter`:**  This represents a single, thread-safe counter. The methods `Set`, `Get`, `Increment`, and `Decrement` are standard counter operations. The `Enabled()` method suggests some counters might be conditionally active. The interaction with `StatsTable` during initialization (`Initialize`) is important.

    * **`Histogram`:** This is an abstract base for different histogram types. The `AddSample` method is key. The `Enabled()` method and the connection to `Counters` in `Initialize` are noted. The lazy creation logic (`EnsureCreated`) is also observed.

    * **`TimedHistogram`:** Inherits from `Histogram`, suggesting it's for measuring time durations. `AddTimedSample` is the specialized method.

    * **`NestedTimedHistogram`:** Extends `TimedHistogram` and introduces the concept of nested timers, which is interesting and requires careful time accounting. The `Enter` and `Leave` methods point to managing a stack-like structure for nested scopes.

    * **`AggregatableHistogramTimer`:**  Focuses on aggregating timings from potentially multiple "inner" scopes. The `Start`, `Stop`, and `Add` methods are crucial.

    * **`AggregatedMemoryHistogram`:**  More complex. It seems to smooth out memory usage samples over time, sending averaged values to a backing histogram. The linear interpolation logic is a key detail.

    * **`Counters`:** The central manager for all these counters and histograms. It holds instances of all the specific counters and histograms. The `ResetCounterFunction` and `ResetCreateHistogramFunction` methods suggest runtime reconfiguration. The macros (like `HISTOGRAM_RANGE_LIST`) are a concise way to define many similar counters. The `Id` enum helps identify specific counters.

    * **`CountersVisitor` and Initializer/Resetter classes:** These implement the Visitor pattern to perform operations on all registered counters/histograms.

5. **Answering Specific Questions:**

    * **Torque:** The file extension is `.h`, not `.tq`, so it's C++ not Torque.

    * **JavaScript Relation:**  While this is a C++ file, the *purpose* is directly related to JavaScript performance. These counters and histograms track things like compilation times, garbage collection behavior, and execution statistics, all of which influence JavaScript execution. The example provided focuses on observable JavaScript behavior that these counters would track (e.g., function calls, memory usage).

    * **Code Logic/Input-Output:** Focus on the non-trivial logic. The `AggregatedMemoryHistogram`'s smoothing logic is a good example. Hypothesize inputs (timestamps and values) and trace how the `Aggregate` and `AddSample` methods would process them, showing how it generates smoothed samples.

    * **Common Errors:** Think about how developers might misuse these classes. Since they're internal V8 components, direct user errors are unlikely. However, errors in the *instrumentation* (how V8 uses these counters) are possible. For example, forgetting to stop a timer, leading to incorrect measurements. Or using the wrong histogram type for the data being collected.

6. **Structure and Refine:** Organize the findings logically. Start with a high-level summary, then detail the functionality of each major component. Address the specific questions clearly. Use code snippets (even if simplified) to illustrate points. Ensure the language is clear and avoids overly technical jargon where possible.

7. **Self-Correction/Review:** Read through the analysis. Does it accurately reflect the header file's purpose? Are the explanations clear and concise?  Are the examples relevant?  Are there any inconsistencies or areas that need more clarification?  For example, initially, I might not have fully grasped the purpose of the `CountersVisitor` pattern. Reviewing the code helps to identify such patterns and their role. Similarly, double-checking the file extension confirms it's not a Torque file.

This iterative process of skimming, analyzing, deducing, and refining helps to create a comprehensive understanding of the code and address all aspects of the request.
好的， 让我们来分析一下 `v8/src/logging/counters.h` 这个 V8 源代码文件的功能。

**主要功能概览:**

`v8/src/logging/counters.h` 文件定义了一套用于在 V8 JavaScript 引擎内部收集和监控各种性能指标的机制。它提供了一组类，用于创建和管理不同类型的计数器和直方图，这些工具可以帮助 V8 开发者了解引擎的运行时行为，识别性能瓶颈，并进行性能优化。

**具体功能分解:**

1. **`StatsTable` 类:**
   - 充当一个中央注册表，用于存储和管理计数器和直方图。
   - 允许外部应用程序通过回调函数（`CounterLookupCallback`, `CreateHistogramCallback`, `AddHistogramSampleCallback`）接入 V8 的计数器系统。这意味着外部工具或监控系统可以自定义如何存储和处理这些统计数据。
   - 提供 `FindLocation` 方法，根据名称查找计数器的存储位置。这个位置可能是线程特定的。
   - 提供 `CreateHistogram` 和 `AddHistogramSample` 方法，用于创建和向直方图添加样本。

2. **`StatsCounter` 类:**
   - 代表一个可以原子操作的 32 位整数计数器。
   - 提供 `Set`, `Get`, `Increment`, `Decrement` 等方法来操作计数器的值。
   - `Enabled()` 方法指示计数器是否已启用（即，是否已成功找到存储位置）。
   - `GetInternalPointer()` 方法返回计数器的内部指针，这主要供代码生成器使用，以便直接操作计数器，避免调用运行时系统。
   - 每个 `StatsCounter` 实例都与一个 `Counters` 对象关联。

3. **`Histogram` 类:**
   - 作为所有直方图类型的基类。
   - 提供 `AddSample` 方法向直方图添加数据点。
   - `Enabled()` 方法指示直方图是否已启用。
   - 存储直方图的名称、最小值、最大值和桶的数量等元数据。
   - 使用互斥锁 (`mutex_`) 来保证线程安全。
   - `EnsureCreated()` 方法用于延迟创建直方图，只有在需要时才真正创建。

4. **`TimedHistogram` 类:**
   - 继承自 `Histogram`，专门用于记录时间间隔。
   - 提供 `AddTimedSample` 方法，接收 `base::TimeDelta` 类型的样本。
   - 可以记录放弃事件 (`RecordAbandon`)。
   - 可以设置时间分辨率 (`TimedHistogramResolution`)，例如毫秒或微秒。

5. **`NestedTimedHistogram` 类:**
   - 继承自 `TimedHistogram`，用于处理嵌套的时间测量场景。例如，当一个定时器在另一个定时器运行时启动和停止时，它可以正确地计算时间。
   - 使用 `NestedTimedHistogramScope` 来管理嵌套的计时器。

6. **`AggregatableHistogramTimer` 类:**
   - 用于聚合在某个范围内的事件的持续时间。它允许定义一个外部范围和一个内部范围，内部范围的计时会被累加到外部范围。

7. **`AggregatedMemoryHistogram` 类模板:**
   - 用于平滑内存使用情况的样本数据。它接收时间戳和内存值的样本对，并将其转换为时间均匀的样本，然后发送到后端的直方图。这有助于消除由于采样频率不一致导致的偏差。

8. **`Counters` 类:**
   - 负责管理所有类型的计数器和直方图实例。
   - 包含各种宏定义（例如 `HISTOGRAM_RANGE_LIST`, `STATS_COUNTER_LIST`），用于声明不同类型的计数器和直方图。这些宏通常在 `v8/src/logging/counters-definitions.h` 中定义。
   - 提供访问器方法（例如 `name()`）来获取特定计数器或直方图的实例。
   - 包含一个 `StatsTable` 实例来管理底层的存储和查找。
   - 可以注册外部的回调函数来处理计数器和直方图数据。

9. **`CountersVisitor` 类及其子类 (`CountersInitializer`, `StatsCounterResetter`, `HistogramResetter`):**
   - 使用访问者模式来遍历和操作 `Counters` 对象中包含的所有计数器和直方图。
   - `CountersInitializer` 用于初始化计数器和直方图。
   - `StatsCounterResetter` 和 `HistogramResetter` 用于重置特定类型的计数器或直方图。

**关于 `.tq` 结尾的文件:**

如果 `v8/src/logging/counters.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是 V8 使用的一种领域特定语言（DSL），用于生成高效的 C++ 代码，特别是用于实现 V8 的内置函数和运行时代码。  然而，根据你提供的文件名，它是 `.h` 结尾，所以它是一个标准的 C++ 头文件。

**与 JavaScript 的关系:**

`v8/src/logging/counters.h` 中定义的计数器和直方图直接关系到 V8 引擎执行 JavaScript 代码时的性能监控。它们跟踪各种事件和指标，例如：

- **代码编译时间:**  记录将 JavaScript 代码编译成机器码所需的时间。
- **垃圾回收 (GC) 活动:**  记录 GC 的次数、持续时间、回收的内存量等。
- **内置函数调用:**  记录调用各种内置 JavaScript 函数的次数和耗时。
- **内存分配:**  记录内存的分配和使用情况。
- **执行统计信息:**  记录执行特定操作的次数，例如访问对象属性、调用函数等。

这些信息对于理解 JavaScript 代码的性能特征至关重要。当开发者遇到性能问题时，V8 团队可以使用这些计数器和直方图来诊断问题所在。

**JavaScript 示例 (概念性):**

虽然我们不能直接在 JavaScript 中访问这些 C++ 计数器，但我们可以观察到 JavaScript 代码执行时受到这些内部指标影响的行为。

```javascript
// 假设 V8 内部有一个名为 "compileTime" 的计数器，记录编译时间
console.time('compilation');
function add(a, b) {
  return a + b;
}
console.timeEnd('compilation');

// 假设 V8 内部有一个名为 "gcCount" 的计数器，记录 GC 次数
let largeArray = [];
for (let i = 0; i < 1000000; i++) {
  largeArray.push({ data: new Array(1000).fill(i) });
}
largeArray = null; // 触发垃圾回收

// 假设 V8 内部有一个名为 "functionCallCount_add" 的计数器
add(5, 3);
add(10, 2);
```

在这个例子中，`console.time` 和 `console.timeEnd` 可以粗略地测量编译时间（尽管它们测量的是更广泛的时间范围）。创建并丢弃 `largeArray` 可能会触发垃圾回收，这会影响 V8 内部的 `gcCount` 计数器。调用 `add` 函数会影响 V8 内部跟踪函数调用次数的计数器。

**代码逻辑推理和假设输入/输出:**

让我们以 `AggregatedMemoryHistogram` 为例进行代码逻辑推理。

**假设输入:**

我们有一个 `AggregatedMemoryHistogram` 实例，它关联到一个名为 `memoryUsageHistogram` 的后端 `Histogram`。 `v8_flags.histogram_interval` 设置为 10 毫秒。

我们依次添加以下样本 (时间戳单位：毫秒，内存使用单位：MB):

1. `AddSample(0, 100)`
2. `AddSample(5, 110)`
3. `AddSample(12, 125)`
4. `AddSample(25, 130)`

**代码逻辑推理:**

1. **样本 1 (0, 100):**  `AggregatedMemoryHistogram` 初始化。 `start_ms_ = 0`, `last_ms_ = 0`, `aggregate_value_ = 100`, `last_value_ = 100`。

2. **样本 2 (5, 110):**
   - `current_ms = 5`, `current_value = 110`.
   - `end_ms = 0 + 10 = 10`.
   - 由于 `end_ms > current_ms`, 不会立即发送聚合样本。
   - `aggregate_value_` 更新为基于线性插值的平均值。

3. **样本 3 (12, 125):**
   - `current_ms = 12`, `current_value = 125`.
   - `end_ms = 10`. 由于 `end_ms <= current_ms`, 需要发送聚合样本。
   - 计算时间间隔 [0, 10) 的平均值。 假设线性插值，在 t=10 时的值约为 `100 + (110 - 100) / (5 - 0) * (10 - 0) = 120`。
   - 发送一个样本到 `memoryUsageHistogram`，值大约为 `(100 + 120) / 2 = 110` (可能需要更精确的计算)。
   - 更新 `start_ms_`, `last_ms_`, `aggregate_value_` 等。
   - 检查下一个时间间隔。

4. **样本 4 (25, 130):**
   - 类似地，计算并发送时间间隔 [10, 20) 和 [20, 25) 的聚合样本。

**假设输出 (发送到 `memoryUsageHistogram` 的样本):**

- 大约在时间 10ms 时，发送一个值在 110 到 120 之间的样本。
- 大约在时间 20ms 时，发送一个值在 120 到 127.5 之间的样本。

**涉及用户常见的编程错误 (V8 开发者角度):**

由于 `v8/src/logging/counters.h` 是 V8 内部使用的，普通 JavaScript 开发者不会直接与其交互。然而，V8 开发者在使用这些计数器时可能会犯以下错误：

1. **不正确的计数器名称或 ID:**  在代码中引用不存在或错误的计数器名称或 ID，导致无法正确记录或检索数据。
2. **忘记启用计数器或直方图:**  即使定义了计数器，如果没有正确地初始化或启用，将不会收集任何数据。
3. **在多线程环境中使用非线程安全的计数器 (如果存在):** 虽然 `StatsCounter` 本身是线程安全的，但在某些复杂的场景下，可能需要额外的同步措施。
4. **直方图的范围或桶数设置不当:**  如果直方图的最小值、最大值或桶数设置不合理，可能会导致数据分布不准确或信息丢失。例如，如果最大值设置得太小，超出范围的样本将不会被记录。
5. **过度使用或不当使用直方图:**  记录过多的数据到直方图可能会消耗大量内存和性能。需要根据实际需求选择合适的指标进行监控。
6. **忘记停止计时器:**  对于 `TimedHistogram` 和相关类，如果在计时完成后忘记停止计时器，会导致记录的时间过长。

例如，一个常见的错误可能是：

```c++
// 错误示例：忘记初始化 Counters 对象或注册回调函数
void MyV8Embedder::SomeFunction() {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::internal::Isolate* i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);
  v8::internal::Counters* counters = i_isolate->counters();

  // 假设 kMyCustomCounter 是在 counters-definitions.h 中定义的计数器
  // 如果 Counters 对象没有正确初始化，或者外部的 CounterLookupCallback 没有注册，
  // 那么 Increment 操作可能不会生效，或者会写入无效的内存位置。
  counters->kMyCustomCounter.Increment();
}
```

总结来说，`v8/src/logging/counters.h` 是 V8 引擎中一个核心的性能监控模块，它定义了用于收集各种运行时统计信息的工具。这些信息对于理解和优化 V8 引擎以及其执行的 JavaScript 代码的性能至关重要。

Prompt: 
```
这是目录为v8/src/logging/counters.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/logging/counters.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_LOGGING_COUNTERS_H_
#define V8_LOGGING_COUNTERS_H_

#include <memory>

#include "include/v8-callbacks.h"
#include "src/base/atomic-utils.h"
#include "src/base/platform/elapsed-timer.h"
#include "src/base/platform/time.h"
#include "src/common/globals.h"
#include "src/logging/counters-definitions.h"
#include "src/logging/runtime-call-stats.h"
#include "src/objects/code-kind.h"
#include "src/objects/objects.h"
#include "src/utils/allocation.h"

namespace v8 {
namespace internal {

// StatsCounters is an interface for plugging into external
// counters for monitoring.  Counters can be looked up and
// manipulated by name.

class Counters;
class Isolate;

class StatsTable {
 public:
  StatsTable(const StatsTable&) = delete;
  StatsTable& operator=(const StatsTable&) = delete;

  // Register an application-defined function for recording
  // subsequent counter statistics.
  void SetCounterFunction(CounterLookupCallback f);

  // Register an application-defined function to create histograms for
  // recording subsequent histogram samples.
  void SetCreateHistogramFunction(CreateHistogramCallback f) {
    create_histogram_function_ = f;
  }

  // Register an application-defined function to add a sample
  // to a histogram created with CreateHistogram function.
  void SetAddHistogramSampleFunction(AddHistogramSampleCallback f) {
    add_histogram_sample_function_ = f;
  }

  bool HasCounterFunction() const { return lookup_function_ != nullptr; }

  // Lookup the location of a counter by name.  If the lookup
  // is successful, returns a non-nullptr pointer for writing the
  // value of the counter.  Each thread calling this function
  // may receive a different location to store it's counter.
  // The return value must not be cached and re-used across
  // threads, although a single thread is free to cache it.
  int* FindLocation(const char* name) {
    if (!lookup_function_) return nullptr;
    return lookup_function_(name);
  }

  // Create a histogram by name. If the create is successful,
  // returns a non-nullptr pointer for use with AddHistogramSample
  // function. min and max define the expected minimum and maximum
  // sample values. buckets is the maximum number of buckets
  // that the samples will be grouped into.
  void* CreateHistogram(const char* name, int min, int max, size_t buckets) {
    if (!create_histogram_function_) return nullptr;
    return create_histogram_function_(name, min, max, buckets);
  }

  // Add a sample to a histogram created with the CreateHistogram
  // function.
  void AddHistogramSample(void* histogram, int sample) {
    if (!add_histogram_sample_function_) return;
    return add_histogram_sample_function_(histogram, sample);
  }

 private:
  friend class Counters;

  explicit StatsTable(Counters* counters);

  CounterLookupCallback lookup_function_;
  CreateHistogramCallback create_histogram_function_;
  AddHistogramSampleCallback add_histogram_sample_function_;
};

// StatsCounters are dynamically created values which can be tracked in the
// StatsTable. They are designed to be lightweight to create and easy to use.
//
// Internally, a counter represents a value in a row of a StatsTable.
// The row has a 32bit value for each process/thread in the table and also
// a name (stored in the table metadata). Since the storage location can be
// thread-specific, this class cannot be shared across threads.
// This class is thread-safe.
class StatsCounter {
 public:
  void Set(int value) { GetPtr()->store(value, std::memory_order_relaxed); }
  int Get() { return GetPtr()->load(); }

  void Increment(int value = 1) {
    GetPtr()->fetch_add(value, std::memory_order_relaxed);
  }

  void Decrement(int value = 1) {
    GetPtr()->fetch_sub(value, std::memory_order_relaxed);
  }

  // Returns true if this counter is enabled (a lookup function was provided and
  // it returned a non-null pointer).
  V8_EXPORT_PRIVATE bool Enabled();

  // Get the internal pointer to the counter. This is used
  // by the code generator to emit code that manipulates a
  // given counter without calling the runtime system.
  std::atomic<int>* GetInternalPointer() { return GetPtr(); }

 private:
  friend class Counters;
  friend class CountersInitializer;
  friend class StatsCounterResetter;

  void Initialize(const char* name, Counters* counters) {
    DCHECK_NULL(counters_);
    DCHECK_NOT_NULL(counters);
    // Counter names always start with "c:V8.".
    DCHECK_EQ(0, memcmp(name, "c:V8.", 5));
    counters_ = counters;
    name_ = name;
  }

  V8_NOINLINE V8_EXPORT_PRIVATE std::atomic<int>* SetupPtrFromStatsTable();

  // Reset the cached internal pointer.
  void Reset() { ptr_.store(nullptr, std::memory_order_relaxed); }

  // Returns the cached address of this counter location.
  std::atomic<int>* GetPtr() {
    auto* ptr = ptr_.load(std::memory_order_acquire);
    if (V8_LIKELY(ptr)) return ptr;
    return SetupPtrFromStatsTable();
  }

  Counters* counters_ = nullptr;
  const char* name_ = nullptr;
  // A pointer to an atomic, set atomically in {GetPtr}.
  std::atomic<std::atomic<int>*> ptr_{nullptr};
};

// A Histogram represents a dynamically created histogram in the
// StatsTable.  Note: This class is thread safe.
class Histogram {
 public:
  // Add a single sample to this histogram.
  V8_EXPORT_PRIVATE void AddSample(int sample);

  // Returns true if this histogram is enabled.
  bool Enabled() { return histogram_ != nullptr; }

  const char* name() const { return name_; }

  int min() const { return min_; }
  int max() const { return max_; }
  int num_buckets() const { return num_buckets_; }

  // Asserts that |expected_counters| are the same as the Counters this
  // Histogram reports to.
  void AssertReportsToCounters(Counters* expected_counters) {
    DCHECK_EQ(counters_, expected_counters);
  }

 protected:
  Histogram() = default;
  Histogram(const Histogram&) = delete;
  Histogram& operator=(const Histogram&) = delete;

  void Initialize(const char* name, int min, int max, int num_buckets,
                  Counters* counters) {
    name_ = name;
    min_ = min;
    max_ = max;
    num_buckets_ = num_buckets;
    histogram_ = nullptr;
    counters_ = counters;
    DCHECK_NOT_NULL(counters_);
  }

  Counters* counters() const { return counters_; }

  // Reset the cached internal pointer to nullptr; the histogram will be
  // created lazily, the first time it is needed.
  void Reset() { histogram_ = nullptr; }

  // Lazily create the histogram, if it has not been created yet.
  void EnsureCreated(bool create_new = true) {
    if (create_new && histogram_.load(std::memory_order_acquire) == nullptr) {
      base::MutexGuard Guard(&mutex_);
      if (histogram_.load(std::memory_order_relaxed) == nullptr)
        histogram_.store(CreateHistogram(), std::memory_order_release);
    }
  }

 private:
  friend class Counters;
  friend class CountersInitializer;
  friend class HistogramResetter;

  V8_EXPORT_PRIVATE void* CreateHistogram() const;

  const char* name_;
  int min_;
  int max_;
  int num_buckets_;
  std::atomic<void*> histogram_;
  Counters* counters_;
  base::Mutex mutex_;
};

// Dummy classes for better visiting.

class PercentageHistogram : public Histogram {};
class LegacyMemoryHistogram : public Histogram {};

enum class TimedHistogramResolution { MILLISECOND, MICROSECOND };

// A thread safe histogram timer.
class TimedHistogram : public Histogram {
 public:
  // Records a TimeDelta::Max() result. Useful to record percentage of tasks
  // that never got to run in a given scenario. Log if isolate non-null.
  void RecordAbandon(base::ElapsedTimer* timer, Isolate* isolate);

  // Add a single sample to this histogram.
  V8_EXPORT_PRIVATE void AddTimedSample(base::TimeDelta sample);

#ifdef DEBUG
  // Ensures that we don't have nested timers for TimedHistogram per thread, use
  // NestedTimedHistogram which correctly pause and resume timers.
  // This method assumes that each timer is alternating between stopped and
  // started on a single thread. Multiple timers can be active on different
  // threads.
  bool ToggleRunningState(bool expected_is_running) const;
#endif  // DEBUG

 protected:
  void Stop(base::ElapsedTimer* timer);
  void LogStart(Isolate* isolate);
  void LogEnd(Isolate* isolate);

  friend class Counters;
  friend class CountersInitializer;

  TimedHistogramResolution resolution_;

  TimedHistogram() = default;
  TimedHistogram(const TimedHistogram&) = delete;
  TimedHistogram& operator=(const TimedHistogram&) = delete;

  void Initialize(const char* name, int min, int max,
                  TimedHistogramResolution resolution, int num_buckets,
                  Counters* counters) {
    Histogram::Initialize(name, min, max, num_buckets, counters);
    resolution_ = resolution;
  }
};

class NestedTimedHistogramScope;
class PauseNestedTimedHistogramScope;

// For use with the NestedTimedHistogramScope. 'Nested' here means that scopes
// may have nested lifetimes while still correctly accounting for time, e.g.:
//
// void f() {
//   NestedTimedHistogramScope timer(...);
//   ...
//   f();  // Recursive call.
// }
class NestedTimedHistogram : public TimedHistogram {
 public:
  // Note: public for testing purposes only.
  NestedTimedHistogram(const char* name, int min, int max,
                       TimedHistogramResolution resolution, int num_buckets,
                       Counters* counters)
      : NestedTimedHistogram() {
    Initialize(name, min, max, resolution, num_buckets, counters);
  }

 private:
  friend class Counters;
  friend class NestedTimedHistogramScope;
  friend class PauseNestedTimedHistogramScope;

  inline NestedTimedHistogramScope* Enter(NestedTimedHistogramScope* next) {
    NestedTimedHistogramScope* previous = current_;
    current_ = next;
    return previous;
  }

  inline void Leave(NestedTimedHistogramScope* previous) {
    current_ = previous;
  }

  NestedTimedHistogramScope* current_ = nullptr;

  NestedTimedHistogram() = default;
  NestedTimedHistogram(const NestedTimedHistogram&) = delete;
  NestedTimedHistogram& operator=(const NestedTimedHistogram&) = delete;
};

// A histogram timer that can aggregate events within a larger scope.
//
// Intended use of this timer is to have an outer (aggregating) and an inner
// (to be aggregated) scope, where the inner scope measure the time of events,
// and all those inner scope measurements will be summed up by the outer scope.
// An example use might be to aggregate the time spent in lazy compilation
// while running a script.
//
// Helpers:
// - AggregatingHistogramTimerScope, the "outer" scope within which
//     times will be summed up.
// - AggregatedHistogramTimerScope, the "inner" scope which defines the
//     events to be timed.
class AggregatableHistogramTimer : public Histogram {
 public:
  // Start/stop the "outer" scope.
  void Start() { time_ = base::TimeDelta(); }
  void Stop() {
    if (time_ != base::TimeDelta()) {
      // Only add non-zero samples, since zero samples represent situations
      // where there were no aggregated samples added.
      AddSample(static_cast<int>(time_.InMicroseconds()));
    }
  }

  // Add a time value ("inner" scope).
  void Add(base::TimeDelta other) { time_ += other; }

 private:
  friend class Counters;

  AggregatableHistogramTimer() = default;
  AggregatableHistogramTimer(const AggregatableHistogramTimer&) = delete;
  AggregatableHistogramTimer& operator=(const AggregatableHistogramTimer&) =
      delete;

  base::TimeDelta time_;
};

// A helper class for use with AggregatableHistogramTimer. This is the
// // outer-most timer scope used with an AggregatableHistogramTimer. It will
// // aggregate the information from the inner AggregatedHistogramTimerScope.
class V8_NODISCARD AggregatingHistogramTimerScope {
 public:
  explicit AggregatingHistogramTimerScope(AggregatableHistogramTimer* histogram)
      : histogram_(histogram) {
    histogram_->Start();
  }
  ~AggregatingHistogramTimerScope() { histogram_->Stop(); }

 private:
  AggregatableHistogramTimer* histogram_;
};

// A helper class for use with AggregatableHistogramTimer, the "inner" scope
// // which defines the events to be timed.
class V8_NODISCARD AggregatedHistogramTimerScope {
 public:
  explicit AggregatedHistogramTimerScope(AggregatableHistogramTimer* histogram)
      : histogram_(histogram) {
    timer_.Start();
  }
  ~AggregatedHistogramTimerScope() { histogram_->Add(timer_.Elapsed()); }

 private:
  base::ElapsedTimer timer_;
  AggregatableHistogramTimer* histogram_;
};

// AggretatedMemoryHistogram collects (time, value) sample pairs and turns
// them into time-uniform samples for the backing historgram, such that the
// backing histogram receives one sample every T ms, where the T is controlled
// by the v8_flags.histogram_interval.
//
// More formally: let F be a real-valued function that maps time to sample
// values. We define F as a linear interpolation between adjacent samples. For
// each time interval [x; x + T) the backing histogram gets one sample value
// that is the average of F(t) in the interval.
template <typename Histogram>
class AggregatedMemoryHistogram {
 public:
  // Note: public for testing purposes only.
  explicit AggregatedMemoryHistogram(Histogram* backing_histogram)
      : AggregatedMemoryHistogram() {
    backing_histogram_ = backing_histogram;
  }

  // Invariants that hold before and after AddSample if
  // is_initialized_ is true:
  //
  // 1) For we processed samples that came in before start_ms_ and sent the
  // corresponding aggregated samples to backing histogram.
  // 2) (last_ms_, last_value_) is the last received sample.
  // 3) last_ms_ < start_ms_ + v8_flags.histogram_interval.
  // 4) aggregate_value_ is the average of the function that is constructed by
  // linearly interpolating samples received between start_ms_ and last_ms_.
  void AddSample(double current_ms, double current_value);

 private:
  friend class Counters;

  AggregatedMemoryHistogram()
      : is_initialized_(false),
        start_ms_(0.0),
        last_ms_(0.0),
        aggregate_value_(0.0),
        last_value_(0.0),
        backing_histogram_(nullptr) {}
  double Aggregate(double current_ms, double current_value);

  bool is_initialized_;
  double start_ms_;
  double last_ms_;
  double aggregate_value_;
  double last_value_;
  Histogram* backing_histogram_;
};

template <typename Histogram>
void AggregatedMemoryHistogram<Histogram>::AddSample(double current_ms,
                                                     double current_value) {
  if (!is_initialized_) {
    aggregate_value_ = current_value;
    start_ms_ = current_ms;
    last_value_ = current_value;
    last_ms_ = current_ms;
    is_initialized_ = true;
  } else {
    const double kEpsilon = 1e-6;
    const int kMaxSamples = 1000;
    if (current_ms < last_ms_ + kEpsilon) {
      // Two samples have the same time, remember the last one.
      last_value_ = current_value;
    } else {
      double sample_interval_ms = v8_flags.histogram_interval;
      double end_ms = start_ms_ + sample_interval_ms;
      if (end_ms <= current_ms + kEpsilon) {
        // Linearly interpolate between the last_ms_ and the current_ms.
        double slope = (current_value - last_value_) / (current_ms - last_ms_);
        int i;
        // Send aggregated samples to the backing histogram from the start_ms
        // to the current_ms.
        for (i = 0; i < kMaxSamples && end_ms <= current_ms + kEpsilon; i++) {
          double end_value = last_value_ + (end_ms - last_ms_) * slope;
          double sample_value;
          if (i == 0) {
            // Take aggregate_value_ into account.
            sample_value = Aggregate(end_ms, end_value);
          } else {
            // There is no aggregate_value_ for i > 0.
            sample_value = (last_value_ + end_value) / 2;
          }
          backing_histogram_->AddSample(static_cast<int>(sample_value + 0.5));
          last_value_ = end_value;
          last_ms_ = end_ms;
          end_ms += sample_interval_ms;
        }
        if (i == kMaxSamples) {
          // We hit the sample limit, ignore the remaining samples.
          aggregate_value_ = current_value;
          start_ms_ = current_ms;
        } else {
          aggregate_value_ = last_value_;
          start_ms_ = last_ms_;
        }
      }
      aggregate_value_ = current_ms > start_ms_ + kEpsilon
                             ? Aggregate(current_ms, current_value)
                             : aggregate_value_;
      last_value_ = current_value;
      last_ms_ = current_ms;
    }
  }
}

template <typename Histogram>
double AggregatedMemoryHistogram<Histogram>::Aggregate(double current_ms,
                                                       double current_value) {
  double interval_ms = current_ms - start_ms_;
  double value = (current_value + last_value_) / 2;
  // The aggregate_value_ is the average for [start_ms_; last_ms_].
  // The value is the average for [last_ms_; current_ms].
  // Return the weighted average of the aggregate_value_ and the value.
  return aggregate_value_ * ((last_ms_ - start_ms_) / interval_ms) +
         value * ((current_ms - last_ms_) / interval_ms);
}

// This file contains all the v8 counters that are in use.
class Counters : public std::enable_shared_from_this<Counters> {
 public:
  explicit Counters(Isolate* isolate);

  // Register an application-defined function for recording
  // subsequent counter statistics. Note: Must be called on the main
  // thread.
  void ResetCounterFunction(CounterLookupCallback f);

  // Register an application-defined function to create histograms for
  // recording subsequent histogram samples. Note: Must be called on
  // the main thread.
  void ResetCreateHistogramFunction(CreateHistogramCallback f);

  // Register an application-defined function to add a sample
  // to a histogram. Will be used in all subsequent sample additions.
  // Note: Must be called on the main thread.
  void SetAddHistogramSampleFunction(AddHistogramSampleCallback f) {
    stats_table_.SetAddHistogramSampleFunction(f);
  }

#define HR(name, caption, min, max, num_buckets) \
  Histogram* name() {                            \
    name##_.EnsureCreated();                     \
    return &name##_;                             \
  }
  HISTOGRAM_RANGE_LIST(HR)
#undef HR

#if V8_ENABLE_DRUMBRAKE
#define HR(name, caption, min, max, num_buckets)     \
  Histogram* name() {                                \
    name##_.EnsureCreated(v8_flags.slow_histograms); \
    return &name##_;                                 \
  }
  HISTOGRAM_RANGE_LIST_SLOW(HR)
#undef HR
#endif  // V8_ENABLE_DRUMBRAKE

#define HT(name, caption, max, res) \
  NestedTimedHistogram* name() {    \
    name##_.EnsureCreated();        \
    return &name##_;                \
  }
  NESTED_TIMED_HISTOGRAM_LIST(HT)
#undef HT

#define HT(name, caption, max, res)                  \
  NestedTimedHistogram* name() {                     \
    name##_.EnsureCreated(v8_flags.slow_histograms); \
    return &name##_;                                 \
  }
  NESTED_TIMED_HISTOGRAM_LIST_SLOW(HT)
#undef HT

#define HT(name, caption, max, res) \
  TimedHistogram* name() {          \
    name##_.EnsureCreated();        \
    return &name##_;                \
  }
  TIMED_HISTOGRAM_LIST(HT)
#undef HT

#define AHT(name, caption)             \
  AggregatableHistogramTimer* name() { \
    name##_.EnsureCreated();           \
    return &name##_;                   \
  }
  AGGREGATABLE_HISTOGRAM_TIMER_LIST(AHT)
#undef AHT

#define HP(name, caption)       \
  PercentageHistogram* name() { \
    name##_.EnsureCreated();    \
    return &name##_;            \
  }
  HISTOGRAM_PERCENTAGE_LIST(HP)
#undef HP

#define HM(name, caption)         \
  LegacyMemoryHistogram* name() { \
    name##_.EnsureCreated();      \
    return &name##_;              \
  }
  HISTOGRAM_LEGACY_MEMORY_LIST(HM)
#undef HM

#define SC(name, caption) \
  StatsCounter* name() { return &name##_; }
  STATS_COUNTER_LIST(SC)
  STATS_COUNTER_NATIVE_CODE_LIST(SC)
#undef SC

  // clang-format off
  enum Id {
#define RATE_ID(name, caption, max, res) k_##name,
    NESTED_TIMED_HISTOGRAM_LIST(RATE_ID)
    NESTED_TIMED_HISTOGRAM_LIST_SLOW(RATE_ID)
    TIMED_HISTOGRAM_LIST(RATE_ID)
#undef RATE_ID
#define AGGREGATABLE_ID(name, caption) k_##name,
    AGGREGATABLE_HISTOGRAM_TIMER_LIST(AGGREGATABLE_ID)
#undef AGGREGATABLE_ID
#define PERCENTAGE_ID(name, caption) k_##name,
    HISTOGRAM_PERCENTAGE_LIST(PERCENTAGE_ID)
#undef PERCENTAGE_ID
#define MEMORY_ID(name, caption) k_##name,
    HISTOGRAM_LEGACY_MEMORY_LIST(MEMORY_ID)
#undef MEMORY_ID
#define COUNTER_ID(name, caption) k_##name,
    STATS_COUNTER_LIST(COUNTER_ID)
    STATS_COUNTER_NATIVE_CODE_LIST(COUNTER_ID)
#undef COUNTER_ID
#define COUNTER_ID(name) kCountOf##name, kSizeOf##name,
    INSTANCE_TYPE_LIST(COUNTER_ID)
#undef COUNTER_ID
#define COUNTER_ID(name) kCountOfCODE_TYPE_##name, \
    kSizeOfCODE_TYPE_##name,
    CODE_KIND_LIST(COUNTER_ID)
#undef COUNTER_ID
    stats_counter_count
  };
  // clang-format on

#ifdef V8_RUNTIME_CALL_STATS
  RuntimeCallStats* runtime_call_stats() { return &runtime_call_stats_; }

  WorkerThreadRuntimeCallStats* worker_thread_runtime_call_stats() {
    return &worker_thread_runtime_call_stats_;
  }
#else   // V8_RUNTIME_CALL_STATS
  RuntimeCallStats* runtime_call_stats() { return nullptr; }

  WorkerThreadRuntimeCallStats* worker_thread_runtime_call_stats() {
    return nullptr;
  }
#endif  // V8_RUNTIME_CALL_STATS

 private:
  friend class CountersVisitor;
  friend class Histogram;
  friend class NestedTimedHistogramScope;
  friend class StatsCounter;
  friend class StatsTable;

  int* FindLocation(const char* name) {
    return stats_table_.FindLocation(name);
  }

  void* CreateHistogram(const char* name, int min, int max, size_t buckets) {
    return stats_table_.CreateHistogram(name, min, max, buckets);
  }

  void AddHistogramSample(void* histogram, int sample) {
    stats_table_.AddHistogramSample(histogram, sample);
  }

  Isolate* isolate() { return isolate_; }

#define HR(name, caption, min, max, num_buckets) Histogram name##_;
  HISTOGRAM_RANGE_LIST(HR)
#if V8_ENABLE_DRUMBRAKE
  HISTOGRAM_RANGE_LIST_SLOW(HR)
#endif  // V8_ENABLE_DRUMBRAKE
#undef HR

#define HT(name, caption, max, res) NestedTimedHistogram name##_;
  NESTED_TIMED_HISTOGRAM_LIST(HT)
  NESTED_TIMED_HISTOGRAM_LIST_SLOW(HT)
#undef HT

#define HT(name, caption, max, res) TimedHistogram name##_;
  TIMED_HISTOGRAM_LIST(HT)
#undef HT

#define AHT(name, caption) AggregatableHistogramTimer name##_;
  AGGREGATABLE_HISTOGRAM_TIMER_LIST(AHT)
#undef AHT

#define HP(name, caption) PercentageHistogram name##_;
  HISTOGRAM_PERCENTAGE_LIST(HP)
#undef HP

#define HM(name, caption) LegacyMemoryHistogram name##_;
  HISTOGRAM_LEGACY_MEMORY_LIST(HM)
#undef HM

#define SC(name, caption) StatsCounter name##_;
  STATS_COUNTER_LIST(SC)
  STATS_COUNTER_NATIVE_CODE_LIST(SC)
#undef SC

#ifdef V8_RUNTIME_CALL_STATS
  RuntimeCallStats runtime_call_stats_;
  WorkerThreadRuntimeCallStats worker_thread_runtime_call_stats_;
#endif
  Isolate* isolate_;
  StatsTable stats_table_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(Counters);
};

class CountersVisitor {
 public:
  explicit CountersVisitor(Counters* counters) : counters_(counters) {}

  void Start();
  Counters* counters() { return counters_; }

 protected:
  virtual void VisitHistograms();
  virtual void VisitStatsCounters();

  virtual void VisitHistogram(Histogram* histogram, const char* caption) {}
  virtual void VisitStatsCounter(StatsCounter* counter, const char* caption) {}

  virtual void Visit(Histogram* histogram, const char* caption, int min,
                     int max, int num_buckets);
  virtual void Visit(TimedHistogram* histogram, const char* caption, int max,
                     TimedHistogramResolution res);
  virtual void Visit(NestedTimedHistogram* histogram, const char* caption,
                     int max, TimedHistogramResolution res);
  virtual void Visit(AggregatableHistogramTimer* histogram,
                     const char* caption);
  virtual void Visit(PercentageHistogram* histogram, const char* caption);
  virtual void Visit(LegacyMemoryHistogram* histogram, const char* caption);
  virtual void Visit(StatsCounter* counter, const char* caption);

 private:
  Counters* counters_;
};

class CountersInitializer : public CountersVisitor {
 public:
  using CountersVisitor::CountersVisitor;

 protected:
  void Visit(Histogram* histogram, const char* caption, int min, int max,
             int num_buckets) final;
  void Visit(TimedHistogram* histogram, const char* caption, int max,
             TimedHistogramResolution res) final;
  void Visit(NestedTimedHistogram* histogram, const char* caption, int max,
             TimedHistogramResolution res) final;
  void Visit(AggregatableHistogramTimer* histogram, const char* caption) final;
  void Visit(PercentageHistogram* histogram, const char* caption) final;
  void Visit(LegacyMemoryHistogram* histogram, const char* caption) final;
  void Visit(StatsCounter* counter, const char* caption) final;
};

class StatsCounterResetter : public CountersVisitor {
 public:
  using CountersVisitor::CountersVisitor;

 protected:
  void VisitHistograms() final {}
  void VisitStatsCounter(StatsCounter* counter, const char* caption) final;
};

class HistogramResetter : public CountersVisitor {
 public:
  using CountersVisitor::CountersVisitor;

 protected:
  void VisitStatsCounters() final {}
  void VisitHistogram(Histogram* histogram, const char* caption) final;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_LOGGING_COUNTERS_H_

"""

```