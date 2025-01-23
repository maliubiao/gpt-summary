Response:
Let's break down the thought process for analyzing the `runtime-call-stats.cc` file.

1. **Initial Scan for Keywords and Structure:**  The first step is to quickly skim the code, looking for familiar C++ constructs and keywords related to the task:

    * `#ifdef V8_RUNTIME_CALL_STATS`:  This immediately tells me that the code is conditionally compiled, hinting that it's an optional feature.
    * `#include`: Standard C++ includes and V8-specific includes suggest a mix of general utility and engine-specific functionality.
    * `namespace v8 { namespace internal {`: This confirms it's part of V8's internal implementation.
    * Class names like `RuntimeCallTimer`, `RuntimeCallCounter`, `RuntimeCallStats`, `RuntimeCallStatEntries`, `WorkerThreadRuntimeCallStats`: These are the core components, suggesting the file is about tracking and managing runtime call statistics.
    * Method names like `Print`, `Add`, `Reset`, `Dump`, `Enter`, `Leave`, `Snapshot`: These are actions performed on these components.
    * Macros like `FOR_EACH_GC_COUNTER`, `FOR_EACH_MANUAL_COUNTER`, etc.:  These indicate a systematic way of defining or iterating over different types of counters.
    * `base::TimeTicks`, `base::TimeDelta`, `base::ThreadTicks`:  These suggest time and performance measurement is involved.
    * `v8::tracing::TracedValue`, `TRACE_EVENT_INSTANT1`: This points to integration with V8's tracing system.

2. **Identify Core Functionality (The "What"):** Based on the class names and methods, I can infer the main purpose:

    * **Tracking:** The code seems to track how many times certain runtime functions or C++ builtins are called and how much time is spent in them.
    * **Organization:**  The different classes (`RuntimeCallCounter`, `RuntimeCallTimer`, `RuntimeCallStats`) likely represent a hierarchy or different aspects of the tracking.
    * **Reporting:** The `Print` method and the tracing integration suggest the collected data can be outputted and analyzed.
    * **Thread-Specific Handling:** The `WorkerThreadRuntimeCallStats` class hints at handling statistics from worker threads.

3. **Analyze Key Classes and Their Interactions (The "How"):**  Now, let's delve deeper into the classes:

    * **`RuntimeCallCounter`:**  Seems to store the name of a function/builtin, the number of times it's called (`count_`), and the total time spent in it (`time_`). The `Add` method allows merging counters. The `Dump` method suggests outputting data for tracing. `Reset` clears the counts.
    * **`RuntimeCallTimer`:** Appears to be responsible for measuring the duration of calls. It has `Start`, `Stop`, `Pause`, `Resume`, and `Snapshot` methods. The `parent()` method suggests a stack-like structure for nested calls. It accumulates time into an associated `RuntimeCallCounter`.
    * **`RuntimeCallStatEntries`:**  This class seems to be responsible for formatting and printing the collected statistics. It sorts the entries by time and then count.
    * **`RuntimeCallStats`:** This is the main orchestrator. It holds an array of `RuntimeCallCounter` objects. `Enter` and `Leave` manage the timer stack and update counters when entering and exiting functions. `Add` merges statistics from another `RuntimeCallStats` object. `Print` outputs the statistics. `Reset` clears the counters. It also handles thread-specific counters.
    * **`WorkerThreadRuntimeCallStats`:** Manages `RuntimeCallStats` for worker threads and aggregates them into the main thread's statistics. The `WorkerThreadRuntimeCallStatsScope` is likely a RAII helper to manage the active `RuntimeCallStats` for a given worker thread.

4. **Address Specific Questions from the Prompt:** Now, armed with a good understanding of the code, let's address the specific points:

    * **File Extension:** The prompt asks about `.tq`. Based on the code content (C++), it's clearly *not* a Torque file. Torque files are for a specific V8 language.
    * **Relationship to JavaScript:** Since this tracks runtime function calls and builtins, it directly relates to the execution of JavaScript code. Many of the tracked functions are likely called by the V8 engine when running JavaScript.
    * **JavaScript Example:** To illustrate the connection, I thought about a common JavaScript operation and what V8 runtime functions it might involve. `Array.push()` is a good example, as it internally calls V8 runtime functions to manage the array's memory.
    * **Code Logic Inference (Hypothetical Input/Output):**  I considered a scenario with a few function calls and how the counters would be updated and the output would look. This involves understanding the accumulation of time and counts.
    * **Common Programming Errors:**  I thought about scenarios where users might misunderstand or misuse V8 features related to performance or debugging, such as relying solely on wall-clock time instead of CPU time, or not understanding the overhead of certain operations.

5. **Refine and Organize:** Finally, I organized the findings into a clear and structured response, addressing each point in the prompt. I used clear headings and formatting to make it easy to read and understand. I also added cautionary notes where appropriate (e.g., about the conditional compilation).

This systematic approach, starting with a high-level overview and gradually drilling down into details, helps in understanding complex code like this. The key is to identify the main components, their responsibilities, and how they interact. Relating the code back to the problem domain (in this case, V8's runtime execution) is also crucial.
This C++ source file, `v8/src/logging/runtime-call-stats.cc`, is responsible for **collecting and reporting statistics about the calls to runtime functions and C++ builtins within the V8 JavaScript engine.**  It provides a mechanism to measure how often these internal functions are executed and the time spent in them.

Here's a breakdown of its functionalities:

**Core Functionality:**

* **Tracking Call Counts and Time:** The file defines classes like `RuntimeCallCounter` and `RuntimeCallTimer` to track the number of times a specific runtime function or builtin is called and the cumulative time spent executing it.
* **Categorization of Counters:** It uses macros like `FOR_EACH_GC_COUNTER`, `FOR_EACH_MANUAL_COUNTER`, `FOR_EACH_INTRINSIC`, etc., to define and categorize different types of runtime calls (e.g., garbage collection related, manually triggered, intrinsic functions).
* **Thread-Specific Statistics:** It includes mechanisms to handle statistics collected from different threads, particularly worker threads (`WorkerThreadRuntimeCallStats`).
* **Output and Reporting:** It provides methods to print the collected statistics to an output stream (`Print`) and to dump them in a format suitable for tracing (`Dump`).
* **Enabling/Disabling:** The functionality is controlled by the `V8_RUNTIME_CALL_STATS` preprocessor definition, allowing it to be enabled or disabled during compilation. It also interacts with tracing flags.
* **Time Measurement:** It uses `base::TimeTicks` and `base::TimeDelta` for time measurements, and allows switching between wall-clock time and CPU time based on a flag (`v8_flags.rcs_cpu_time`).
* **Nested Call Tracking:** The `RuntimeCallTimer` and its stack-like structure (`current_timer_`) allow tracking the time spent in nested function calls.

**Answering your specific questions:**

**1. File Extension and Torque:**

> 如果v8/src/logging/runtime-call-stats.cc以.tq结尾，那它是个v8 torque源代码

No, `v8/src/logging/runtime-call-stats.cc` is a **C++ source file**. Files ending in `.tq` in the V8 project are indeed **Torque files**. Torque is a domain-specific language used within V8 to generate optimized code for runtime functions and builtins. This file is about the *instrumentation* of those functions, not their definition in Torque.

**2. Relationship with JavaScript and Example:**

> 如果它与javascript的功能有关系，请用javascript举例说明

Yes, `v8/src/logging/runtime-call-stats.cc` is directly related to the execution of JavaScript code. When JavaScript code is executed, it often involves calls to internal V8 runtime functions and C++ builtins. This file tracks those internal calls.

**JavaScript Example:**

```javascript
// Example JavaScript code
function myFunction(arr) {
  arr.push(10); // This will likely trigger a V8 runtime call for array manipulation
  arr.sort();   // This might trigger a V8 builtin for sorting
  return arr.length;
}

const myArray = [3, 1, 2];
myFunction(myArray);
```

When this JavaScript code runs, the V8 engine will internally call various runtime functions and builtins. `runtime-call-stats.cc` would track calls to functions like:

* **`ArrayPush` (Runtime Function):** Called when `arr.push(10)` is executed.
* **`ArraySort` (Builtin):** Called when `arr.sort()` is executed.
* Potentially other functions related to memory management, object creation, etc.

The statistics collected would include the number of times `ArrayPush` and `ArraySort` were called and the time spent in those calls.

**3. Code Logic Inference (Hypothetical Input and Output):**

Let's assume `V8_RUNTIME_CALL_STATS` is enabled, and we have the following simplified scenario:

**Hypothetical Input:**

* JavaScript code calls a runtime function named "StringAdd" twice.
* The first call to "StringAdd" takes 0.01 milliseconds.
* The second call to "StringAdd" takes 0.02 milliseconds.

**Code Logic within `RuntimeCallStats`:**

1. When "StringAdd" is called the first time, `RuntimeCallStats::Enter` is invoked (likely through a macro). This starts a timer for the "StringAdd" counter.
2. When "StringAdd" finishes, `RuntimeCallStats::Leave` is invoked. This stops the timer and adds the elapsed time (0.01ms) to the "StringAdd" counter, incrementing its call count to 1.
3. The same process happens for the second call to "StringAdd", adding 0.02ms to the "StringAdd" counter and incrementing the count to 2.

**Hypothetical Output (when `Print` is called):**

```
                        Runtime Function/C++ Builtin        Time              Count
========================================================================================
                                         StringAdd      0.03ms               2
----------------------------------------------------------------------------------------
                                             Total      0.03ms               2
```

**Explanation:**

* The output shows the name of the runtime function ("StringAdd").
* "Time" displays the total time spent in "StringAdd" (0.01ms + 0.02ms = 0.03ms).
* "Count" shows the number of times "StringAdd" was called (2).
* The "Total" row summarizes the statistics across all tracked functions.

**4. Common Programming Errors:**

This file itself doesn't directly expose APIs that typical JavaScript programmers would use and therefore doesn't directly lead to common JavaScript programming errors. However, the *information* it provides can help diagnose performance issues that might arise from certain coding patterns.

**Example of a performance issue diagnosable with this data:**

* **Excessive String Concatenation:** A common JavaScript mistake is performing string concatenation in a loop using the `+` operator. This can lead to the creation of many intermediate string objects and frequent calls to internal string manipulation functions.

**JavaScript Code with Potential Issue:**

```javascript
let result = "";
for (let i = 0; i < 10000; i++) {
  result += "some text";
}
```

**How `runtime-call-stats.cc` can help diagnose:**

If runtime call statistics are enabled, running this code might show a very high count and significant time spent in a runtime function like `StringAdd` or similar string manipulation functions. This would indicate that this part of the code is a performance bottleneck and suggest using more efficient techniques like array joining or template literals.

**In summary, `v8/src/logging/runtime-call-stats.cc` is a vital piece of V8's internal instrumentation. It helps developers understand the performance characteristics of the engine by tracking the execution of its internal functions, which are directly triggered by the execution of JavaScript code.** It's not Torque code, but it works in conjunction with Torque-generated code by measuring its runtime behavior. While JavaScript developers don't directly interact with this file, the data it provides can be invaluable for performance analysis and optimization.

### 提示词
```
这是目录为v8/src/logging/runtime-call-stats.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/logging/runtime-call-stats.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef V8_RUNTIME_CALL_STATS

#include "src/logging/runtime-call-stats.h"

#include <iomanip>

#include "src/flags/flags.h"
#include "src/tracing/tracing-category-observer.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

base::TimeTicks (*RuntimeCallTimer::Now)() = &base::TimeTicks::Now;

base::TimeTicks RuntimeCallTimer::NowCPUTime() {
  base::ThreadTicks ticks = base::ThreadTicks::Now();
  return base::TimeTicks::FromInternalValue(ticks.ToInternalValue());
}

class RuntimeCallStatEntries {
 public:
  void Print(std::ostream& os) {
    if (total_call_count_ == 0) return;
    std::sort(entries_.rbegin(), entries_.rend());
    os << std::setw(50) << "Runtime Function/C++ Builtin" << std::setw(12)
       << "Time" << std::setw(18) << "Count" << std::endl
       << std::string(88, '=') << std::endl;
    for (Entry& entry : entries_) {
      entry.SetTotal(total_time_, total_call_count_);
      entry.Print(os);
    }
    os << std::string(88, '-') << std::endl;
    Entry("Total", total_time_, total_call_count_).Print(os);
  }

  // By default, the compiler will usually inline this, which results in a large
  // binary size increase: std::vector::push_back expands to a large amount of
  // instructions, and this function is invoked repeatedly by macros.
  V8_NOINLINE void Add(RuntimeCallCounter* counter) {
    if (counter->count() == 0) return;
    entries_.push_back(
        Entry(counter->name(), counter->time(), counter->count()));
    total_time_ += counter->time();
    total_call_count_ += counter->count();
  }

 private:
  class Entry {
   public:
    Entry(const char* name, base::TimeDelta time, uint64_t count)
        : name_(name),
          time_(time.InMicroseconds()),
          count_(count),
          time_percent_(100),
          count_percent_(100) {}

    bool operator<(const Entry& other) const {
      if (time_ < other.time_) return true;
      if (time_ > other.time_) return false;
      return count_ < other.count_;
    }

    V8_NOINLINE void Print(std::ostream& os) {
      os.precision(2);
      os << std::fixed << std::setprecision(2);
      os << std::setw(50) << name_;
      os << std::setw(10) << static_cast<double>(time_) / 1000 << "ms ";
      os << std::setw(6) << time_percent_ << "%";
      os << std::setw(10) << count_ << " ";
      os << std::setw(6) << count_percent_ << "%";
      os << std::endl;
    }

    V8_NOINLINE void SetTotal(base::TimeDelta total_time,
                              uint64_t total_count) {
      if (total_time.InMicroseconds() == 0) {
        time_percent_ = 0;
      } else {
        time_percent_ = 100.0 * time_ / total_time.InMicroseconds();
      }
      count_percent_ = 100.0 * count_ / total_count;
    }

   private:
    const char* name_;
    int64_t time_;
    uint64_t count_;
    double time_percent_;
    double count_percent_;
  };

  uint64_t total_call_count_ = 0;
  base::TimeDelta total_time_;
  std::vector<Entry> entries_;
};

void RuntimeCallCounter::Reset() {
  count_ = 0;
  time_ = 0;
}

void RuntimeCallCounter::Dump(v8::tracing::TracedValue* value) {
  value->BeginArray(name_);
  value->AppendDouble(count_);
  value->AppendDouble(time_);
  value->EndArray();
}

void RuntimeCallCounter::Add(RuntimeCallCounter* other) {
  count_ += other->count();
  time_ += other->time().InMicroseconds();
}

void RuntimeCallTimer::Snapshot() {
  base::TimeTicks now = Now();
  // Pause only / topmost timer in the timer stack.
  Pause(now);
  // Commit all the timer's elapsed time to the counters.
  RuntimeCallTimer* timer = this;
  while (timer != nullptr) {
    timer->CommitTimeToCounter();
    timer = timer->parent();
  }
  Resume(now);
}

RuntimeCallStats::RuntimeCallStats(ThreadType thread_type)
    : in_use_(false), thread_type_(thread_type) {
  static const char* const kNames[] = {
#define CALL_BUILTIN_COUNTER(name) "GC_" #name,
      FOR_EACH_GC_COUNTER(CALL_BUILTIN_COUNTER)  //
#undef CALL_BUILTIN_COUNTER
#define CALL_RUNTIME_COUNTER(name) #name,
      FOR_EACH_MANUAL_COUNTER(CALL_RUNTIME_COUNTER)  //
#undef CALL_RUNTIME_COUNTER
#define CALL_RUNTIME_COUNTER(name, nargs, ressize) #name,
      FOR_EACH_INTRINSIC(CALL_RUNTIME_COUNTER)  //
#undef CALL_RUNTIME_COUNTER
#define CALL_BUILTIN_COUNTER(name, Argc) #name,
      BUILTIN_LIST_C(CALL_BUILTIN_COUNTER)  //
#undef CALL_BUILTIN_COUNTER
#define CALL_BUILTIN_COUNTER(name) "API_" #name,
      FOR_EACH_API_COUNTER(CALL_BUILTIN_COUNTER)  //
#undef CALL_BUILTIN_COUNTER
#define CALL_BUILTIN_COUNTER(name) #name,
      FOR_EACH_HANDLER_COUNTER(CALL_BUILTIN_COUNTER)  //
#undef CALL_BUILTIN_COUNTER
#define THREAD_SPECIFIC_COUNTER(name) #name,
      FOR_EACH_THREAD_SPECIFIC_COUNTER(THREAD_SPECIFIC_COUNTER)  //
#undef THREAD_SPECIFIC_COUNTER
  };
  for (int i = 0; i < kNumberOfCounters; i++) {
    this->counters_[i] = RuntimeCallCounter(kNames[i]);
  }
  if (v8_flags.rcs_cpu_time) {
    CHECK(base::ThreadTicks::IsSupported());
    base::ThreadTicks::WaitUntilInitialized();
    RuntimeCallTimer::Now = &RuntimeCallTimer::NowCPUTime;
  }
}

namespace {
constexpr RuntimeCallCounterId FirstCounter(RuntimeCallCounterId first, ...) {
  return first;
}

#define THREAD_SPECIFIC_COUNTER(name) k##name,
constexpr RuntimeCallCounterId kFirstThreadVariantCounter =
    FirstCounter(FOR_EACH_THREAD_SPECIFIC_COUNTER(THREAD_SPECIFIC_COUNTER) 0);
#undef THREAD_SPECIFIC_COUNTER

#define THREAD_SPECIFIC_COUNTER(name) +1
constexpr int kThreadVariantCounterCount =
    0 FOR_EACH_THREAD_SPECIFIC_COUNTER(THREAD_SPECIFIC_COUNTER);
#undef THREAD_SPECIFIC_COUNTER

constexpr auto kLastThreadVariantCounter = static_cast<RuntimeCallCounterId>(
    kFirstThreadVariantCounter + kThreadVariantCounterCount - 1);
}  // namespace

bool RuntimeCallStats::HasThreadSpecificCounterVariants(
    RuntimeCallCounterId id) {
  // Check that it's in the range of the thread-specific variant counters and
  // also that it's one of the background counters.
  return id >= kFirstThreadVariantCounter && id <= kLastThreadVariantCounter;
}

bool RuntimeCallStats::IsBackgroundThreadSpecificVariant(
    RuntimeCallCounterId id) {
  return HasThreadSpecificCounterVariants(id) &&
         (id - kFirstThreadVariantCounter) % 2 == 1;
}

void RuntimeCallStats::Enter(RuntimeCallTimer* timer,
                             RuntimeCallCounterId counter_id) {
  DCHECK(IsCalledOnTheSameThread());
  RuntimeCallCounter* counter = GetCounter(counter_id);
  DCHECK_NOT_NULL(counter->name());
  timer->Start(counter, current_timer());
  current_timer_.SetValue(timer);
  current_counter_.SetValue(counter);
}

void RuntimeCallStats::Leave(RuntimeCallTimer* timer) {
  DCHECK(IsCalledOnTheSameThread());
  RuntimeCallTimer* stack_top = current_timer();
  if (stack_top == nullptr) return;  // Missing timer is a result of Reset().
  CHECK(stack_top == timer);
  current_timer_.SetValue(timer->Stop());
  RuntimeCallTimer* cur_timer = current_timer();
  current_counter_.SetValue(cur_timer ? cur_timer->counter() : nullptr);
}

void RuntimeCallStats::Add(RuntimeCallStats* other) {
  for (int i = 0; i < kNumberOfCounters; i++) {
    GetCounter(i)->Add(other->GetCounter(i));
  }
}

// static
void RuntimeCallStats::CorrectCurrentCounterId(RuntimeCallCounterId counter_id,
                                               CounterMode mode) {
  DCHECK(IsCalledOnTheSameThread());
  if (mode == RuntimeCallStats::CounterMode::kThreadSpecific) {
    counter_id = CounterIdForThread(counter_id);
  }
  DCHECK(IsCounterAppropriateForThread(counter_id));

  RuntimeCallTimer* timer = current_timer();
  if (timer == nullptr) return;
  RuntimeCallCounter* counter = GetCounter(counter_id);
  timer->set_counter(counter);
  current_counter_.SetValue(counter);
}

bool RuntimeCallStats::IsCalledOnTheSameThread() {
  if (thread_id_.IsValid()) return thread_id_ == ThreadId::Current();
  thread_id_ = ThreadId::Current();
  return true;
}

void RuntimeCallStats::Print() {
  StdoutStream os;
  Print(os);
}

void RuntimeCallStats::Print(std::ostream& os) {
  RuntimeCallStatEntries entries;
  if (current_timer_.Value() != nullptr) {
    current_timer_.Value()->Snapshot();
  }
  for (int i = 0; i < kNumberOfCounters; i++) {
    entries.Add(GetCounter(i));
  }
  entries.Print(os);
}

void RuntimeCallStats::Reset() {
  if (V8_LIKELY(!TracingFlags::is_runtime_stats_enabled())) return;

  // In tracing, we only what to trace the time spent on top level trace events,
  // if runtime counter stack is not empty, we should clear the whole runtime
  // counter stack, and then reset counters so that we can dump counters into
  // top level trace events accurately.
  while (current_timer_.Value()) {
    current_timer_.SetValue(current_timer_.Value()->Stop());
  }

  for (int i = 0; i < kNumberOfCounters; i++) {
    GetCounter(i)->Reset();
  }

  in_use_ = true;
}

void RuntimeCallStats::Dump(v8::tracing::TracedValue* value) {
  for (int i = 0; i < kNumberOfCounters; i++) {
    if (GetCounter(i)->count() > 0) GetCounter(i)->Dump(value);
  }
  in_use_ = false;
}

WorkerThreadRuntimeCallStats::WorkerThreadRuntimeCallStats()
    : isolate_thread_id_(ThreadId::Current()) {}

WorkerThreadRuntimeCallStats::~WorkerThreadRuntimeCallStats() {
  if (tls_key_) base::Thread::DeleteThreadLocalKey(*tls_key_);
}

base::Thread::LocalStorageKey WorkerThreadRuntimeCallStats::GetKey() {
  base::MutexGuard lock(&mutex_);
  if (!tls_key_) tls_key_ = base::Thread::CreateThreadLocalKey();
  return *tls_key_;
}

RuntimeCallStats* WorkerThreadRuntimeCallStats::NewTable() {
  // Never create a new worker table on the isolate's main thread.
  DCHECK_NE(ThreadId::Current(), isolate_thread_id_);
  std::unique_ptr<RuntimeCallStats> new_table =
      std::make_unique<RuntimeCallStats>(RuntimeCallStats::kWorkerThread);
  RuntimeCallStats* result = new_table.get();

  base::MutexGuard lock(&mutex_);
  tables_.push_back(std::move(new_table));
  return result;
}

void WorkerThreadRuntimeCallStats::AddToMainTable(
    RuntimeCallStats* main_call_stats) {
  base::MutexGuard lock(&mutex_);
  for (auto& worker_stats : tables_) {
    DCHECK_NE(main_call_stats, worker_stats.get());
    main_call_stats->Add(worker_stats.get());
    worker_stats->Reset();
  }
}

WorkerThreadRuntimeCallStatsScope::WorkerThreadRuntimeCallStatsScope(
    WorkerThreadRuntimeCallStats* worker_stats) {
  if (V8_LIKELY(!TracingFlags::is_runtime_stats_enabled())) return;

  table_ = reinterpret_cast<RuntimeCallStats*>(
      base::Thread::GetThreadLocal(worker_stats->GetKey()));
  if (table_ == nullptr) {
    if (V8_UNLIKELY(!TracingFlags::is_runtime_stats_enabled())) return;
    table_ = worker_stats->NewTable();
    base::Thread::SetThreadLocal(worker_stats->GetKey(), table_);
  }

  if ((TracingFlags::runtime_stats.load(std::memory_order_relaxed) &
       v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
    table_->Reset();
  }
}

WorkerThreadRuntimeCallStatsScope::~WorkerThreadRuntimeCallStatsScope() {
  if (V8_LIKELY(table_ == nullptr)) return;

  if ((TracingFlags::runtime_stats.load(std::memory_order_relaxed) &
       v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
    auto value = v8::tracing::TracedValue::Create();
    table_->Dump(value.get());
    TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("v8.runtime_stats"),
                         "V8.RuntimeStats", TRACE_EVENT_SCOPE_THREAD,
                         "runtime-call-stats", std::move(value));
  }
}

}  // namespace internal
}  // namespace v8

#endif  // V8_RUNTIME_CALL_STATS
```