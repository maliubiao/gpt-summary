Response: The user wants to understand the functionality of the C++ code in `v8/src/wasm/module-compiler.cc`.
The request is split into three parts, and this is the first part.
I need to summarize the functionality of the code in this first part.
If the code relates to JavaScript functionality, I need to provide an example in JavaScript.

Looking at the includes, the file seems to be responsible for compiling WebAssembly modules within V8. It deals with:
- **Compilation strategies**: eager, lazy, tiered compilation.
- **Background compilation**: managing worker threads and work queues for parallel compilation.
- **Compilation units**: representing a single function to be compiled.
- **Compilation state**: tracking the progress of compilation for a given module.
- **Integration with JavaScript**: the includes for `wasm-js.h` and mentions of `NativeModule` suggest interaction with the JavaScript environment.

The code defines classes like `CompilationStateImpl`, `CompilationUnitQueues`, and `CompilationUnitBuilder`, which are key components in the compilation pipeline.

The connection to JavaScript comes from the fact that WebAssembly modules are loaded and executed within a JavaScript environment. V8, as the JavaScript engine for Chrome and Node.js, handles the compilation and execution of these modules.

**Let's break down the key functionalities in this part:**

1. **Compilation Strategies**: Defines different strategies for when and how to compile WebAssembly functions (lazy, eager, tiered). This directly impacts the startup time and performance characteristics of WebAssembly modules in a JavaScript environment.

2. **Background Compilation Management**:  Sets up mechanisms for managing background threads to compile WebAssembly functions in parallel. This involves work queues (`CompilationUnitQueues`) and tasks. This is crucial for performance, as it allows the main JavaScript thread to remain responsive while compilation happens in the background.

3. **Compilation Units**:  Introduces the concept of `WasmCompilationUnit`, representing a single function to be compiled. This allows for granular control over the compilation process.

4. **Compilation State Management**: The `CompilationStateImpl` class is central to managing the overall compilation process for a WebAssembly module. It tracks which functions are compiled, handles cancellation, and manages callbacks for compilation events. This is the interface through which the JavaScript embedding (V8) interacts with the WebAssembly compilation process.

5. **Callbacks and Events**: The code mentions callbacks for compilation events. This is a mechanism for informing the JavaScript environment about the progress and completion of the WebAssembly compilation.

**JavaScript Example:**

A JavaScript example that directly demonstrates the functionalities within this C++ code is challenging because these are internal implementation details of the V8 engine. However, we can illustrate the *effect* of these functionalities. For instance, the compilation strategy affects when the JavaScript execution might block.

```javascript
// Example demonstrating the effect of compilation strategies (though not directly interacting with the C++ code)

async function loadAndRunWasm() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer); // This triggers the C++ compilation logic

  // Depending on the compilation strategy (lazy, eager),
  // the code below might block or run immediately.

  const instance = await WebAssembly.instantiate(module);
  const result = instance.exports.myFunction();
  console.log(result);
}

loadAndRunWasm();
```

In this example:
- `WebAssembly.compile(buffer)` is the JavaScript API that initiates the WebAssembly compilation process, which in turn uses the C++ code being described.
- The choice of compilation strategy (lazy or eager, which the C++ code manages) will affect when the compilation happens relative to the `WebAssembly.instantiate` call. With lazy compilation, individual functions might only be compiled when they are first called, potentially causing a slight delay then. Eager compilation would compile more upfront.

The C++ code manages these internal processes to make the JavaScript WebAssembly API work efficiently.
This section of the `module-compiler.cc` file in the V8 project is primarily responsible for managing the **compilation process of WebAssembly modules**. Here's a breakdown of its key functionalities:

**Core Responsibilities:**

1. **Defining Compilation Strategies:** It introduces different strategies for compiling WebAssembly functions, such as `kLazy`, `kEager`, and `kLazyBaselineEagerTopTier`. These strategies determine when and how functions are compiled (e.g., on first use or ahead of time).

2. **Managing Background Compilation:** It sets up infrastructure for parallel compilation of WebAssembly functions using worker threads and work-stealing queues (`CompilationUnitQueues`). This is crucial for improving performance by utilizing multi-core processors.

3. **Representing Compilation Units:** It defines the concept of a `WasmCompilationUnit`, which represents a single function to be compiled. These units are the items of work distributed among the background compilation threads.

4. **Tracking Compilation State:** The `CompilationStateImpl` class is central to managing the compilation process for a specific WebAssembly module. It keeps track of which functions are still to be compiled, handles cancellation of compilation, and manages callbacks for compilation events.

5. **Handling Compilation Hints:** The code considers compilation hints provided in the WebAssembly module to guide the compilation strategy for individual functions.

6. **Integrating with the V8 Engine:** It interacts with other parts of the V8 engine, including the compiler (`src/compiler/wasm-compiler.h`), code space management (`src/wasm/code-space-access.h`), and the overall WebAssembly engine (`src/wasm/wasm-engine.h`).

**Relationship to JavaScript:**

While this C++ code is an internal part of the V8 engine, it directly supports the functionality of the `WebAssembly` JavaScript API. When you load and compile a WebAssembly module in JavaScript, this C++ code is the engine that performs the actual compilation.

**JavaScript Example Illustrating the Effect (not direct interaction):**

The C++ code manages the *internal* process of compiling the WebAssembly module. From a JavaScript perspective, we don't directly interact with these classes. However, the *effect* of the compilation strategies can be observed.

```javascript
async function loadAndRunWasm() {
  const response = await fetch('my_module.wasm');
  const buffer = await response.arrayBuffer();

  console.time('WebAssembly.compile');
  const module = await WebAssembly.compile(buffer);
  console.timeEnd('WebAssembly.compile');

  console.time('WebAssembly.instantiate');
  const instance = await WebAssembly.instantiate(module);
  console.timeEnd('WebAssembly.instantiate');

  const result = instance.exports.myFunction();
  console.log(result);
}

loadAndRunWasm();
```

**Explanation of the JavaScript Example's Connection:**

- **`WebAssembly.compile(buffer)`:** This JavaScript function call is the entry point that triggers the WebAssembly compilation process within V8. The C++ code in `module-compiler.cc` is responsible for the work done during this call.
- **Compilation Strategies' Impact:**
    - If the C++ code uses the **eager compilation strategy**, the `WebAssembly.compile` call might take longer initially, as more (or all) of the module's functions are compiled upfront.
    - If the C++ code uses the **lazy compilation strategy**, the `WebAssembly.compile` call might be faster, but the first time a specific exported function is called (`instance.exports.myFunction()`), there might be a slight delay as that function is compiled on-demand.
    - **Tiered compilation** (like `kLazyBaselineEagerTopTier`) aims to balance these by quickly compiling a baseline version for immediate execution and then optimizing in the background.

**In essence, this part of the C++ code is the "brain" behind the WebAssembly compilation process within V8. It orchestrates the different stages of compilation, manages background threads for efficiency, and respects compilation hints to optimize the process.**

### 提示词
```
这是目录为v8/src/wasm/module-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/module-compiler.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <queue>

#include "src/api/api-inl.h"
#include "src/base/enum-set.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/semaphore.h"
#include "src/base/platform/time.h"
#include "src/codegen/compiler.h"
#include "src/compiler/wasm-compiler.h"
#include "src/debug/debug.h"
#include "src/handles/global-handles-inl.h"
#include "src/logging/counters-scopes.h"
#include "src/logging/metrics.h"
#include "src/tracing/trace-event.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/jump-table-assembler.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/pgo.h"
#include "src/wasm/std-object-sizes.h"
#include "src/wasm/streaming-decoder.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-code-pointer-table-inl.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-feature-flags.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-js.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/wasm-serialization.h"

#define TRACE_COMPILE(...)                                 \
  do {                                                     \
    if (v8_flags.trace_wasm_compiler) PrintF(__VA_ARGS__); \
  } while (false)

#define TRACE_STREAMING(...)                                \
  do {                                                      \
    if (v8_flags.trace_wasm_streaming) PrintF(__VA_ARGS__); \
  } while (false)

#define TRACE_LAZY(...)                                            \
  do {                                                             \
    if (v8_flags.trace_wasm_lazy_compilation) PrintF(__VA_ARGS__); \
  } while (false)

namespace v8::internal::wasm {

namespace {

enum class CompileStrategy : uint8_t {
  // Compiles functions on first use. In this case, execution will block until
  // the function's baseline is reached and top tier compilation starts in
  // background (if applicable).
  // Lazy compilation can help to reduce startup time and code size at the risk
  // of blocking execution.
  kLazy,
  // Compiles baseline ahead of execution and starts top tier compilation in
  // background (if applicable).
  kEager,
  // Triggers baseline compilation on first use (just like {kLazy}) with the
  // difference that top tier compilation is started eagerly.
  // This strategy can help to reduce startup time at the risk of blocking
  // execution, but only in its early phase (until top tier compilation
  // finishes).
  kLazyBaselineEagerTopTier,
  // Marker for default strategy.
  kDefault = kEager,
};

class CompilationStateImpl;
class CompilationUnitBuilder;

class V8_NODISCARD BackgroundCompileScope {
 public:
  explicit BackgroundCompileScope(std::weak_ptr<NativeModule> native_module)
      : native_module_(native_module.lock()) {}

  NativeModule* native_module() const {
    DCHECK(native_module_);
    return native_module_.get();
  }
  inline CompilationStateImpl* compilation_state() const;

  bool cancelled() const;

 private:
  // Keep the native module alive while in this scope.
  std::shared_ptr<NativeModule> native_module_;
};

enum CompilationTier { kBaseline = 0, kTopTier = 1, kNumTiers = kTopTier + 1 };

// A set of work-stealing queues (vectors of units). Each background compile
// task owns one of the queues and steals from all others once its own queue
// runs empty.
class CompilationUnitQueues {
 public:
  // Public API for QueueImpl.
  struct Queue {
    bool ShouldPublish(int num_processed_units) const;
  };

  explicit CompilationUnitQueues(int num_declared_functions)
      : num_declared_functions_(num_declared_functions) {
    // Add one first queue, to add units to.
    queues_.emplace_back(std::make_unique<QueueImpl>(0));

#if !defined(__cpp_lib_atomic_value_initialization) || \
    __cpp_lib_atomic_value_initialization < 201911L
    for (auto& atomic_counter : num_units_) {
      std::atomic_init(&atomic_counter, size_t{0});
    }
#endif

    top_tier_compiled_ =
        std::make_unique<std::atomic<bool>[]>(num_declared_functions);

#if !defined(__cpp_lib_atomic_value_initialization) || \
    __cpp_lib_atomic_value_initialization < 201911L
    for (int i = 0; i < num_declared_functions; i++) {
      std::atomic_init(&top_tier_compiled_.get()[i], false);
    }
#endif
  }

  Queue* GetQueueForTask(int task_id) {
    int required_queues = task_id + 1;
    {
      base::SharedMutexGuard<base::kShared> queues_guard{&queues_mutex_};
      if (V8_LIKELY(static_cast<int>(queues_.size()) >= required_queues)) {
        return queues_[task_id].get();
      }
    }

    // Otherwise increase the number of queues.
    base::SharedMutexGuard<base::kExclusive> queues_guard{&queues_mutex_};
    int num_queues = static_cast<int>(queues_.size());
    while (num_queues < required_queues) {
      int steal_from = num_queues + 1;
      queues_.emplace_back(std::make_unique<QueueImpl>(steal_from));
      ++num_queues;
    }

    // Update the {publish_limit}s of all queues.

    // We want background threads to publish regularly (to avoid contention when
    // they are all publishing at the end). On the other side, each publishing
    // has some overhead (part of it for synchronizing between threads), so it
    // should not happen *too* often. Thus aim for 4-8 publishes per thread, but
    // distribute it such that publishing is likely to happen at different
    // times.
    int units_per_thread = num_declared_functions_ / num_queues;
    int min = std::max(10, units_per_thread / 8);
    int queue_id = 0;
    for (auto& queue : queues_) {
      // Set a limit between {min} and {2*min}, but not smaller than {10}.
      int limit = min + (min * queue_id / num_queues);
      queue->publish_limit.store(limit, std::memory_order_relaxed);
      ++queue_id;
    }

    return queues_[task_id].get();
  }

  std::optional<WasmCompilationUnit> GetNextUnit(Queue* queue,
                                                 CompilationTier tier) {
    DCHECK_LT(tier, CompilationTier::kNumTiers);
    if (auto unit = GetNextUnitOfTier(queue, tier)) {
      [[maybe_unused]] size_t old_units_count =
          num_units_[tier].fetch_sub(1, std::memory_order_relaxed);
      DCHECK_LE(1, old_units_count);
      return unit;
    }
    return {};
  }

  void AddUnits(base::Vector<WasmCompilationUnit> baseline_units,
                base::Vector<WasmCompilationUnit> top_tier_units,
                const WasmModule* module) {
    DCHECK_LT(0, baseline_units.size() + top_tier_units.size());
    // Add to the individual queues in a round-robin fashion. No special care is
    // taken to balance them; they will be balanced by work stealing.
    QueueImpl* queue;
    {
      int queue_to_add = next_queue_to_add.load(std::memory_order_relaxed);
      base::SharedMutexGuard<base::kShared> queues_guard{&queues_mutex_};
      while (!next_queue_to_add.compare_exchange_weak(
          queue_to_add, next_task_id(queue_to_add, queues_.size()),
          std::memory_order_relaxed)) {
        // Retry with updated {queue_to_add}.
      }
      queue = queues_[queue_to_add].get();
    }

    base::MutexGuard guard(&queue->mutex);
    std::optional<base::MutexGuard> big_units_guard;
    for (auto pair :
         {std::make_pair(CompilationTier::kBaseline, baseline_units),
          std::make_pair(CompilationTier::kTopTier, top_tier_units)}) {
      int tier = pair.first;
      base::Vector<WasmCompilationUnit> units = pair.second;
      if (units.empty()) continue;
      num_units_[tier].fetch_add(units.size(), std::memory_order_relaxed);
      for (WasmCompilationUnit unit : units) {
        size_t func_size = module->functions[unit.func_index()].code.length();
        if (func_size <= kBigUnitsLimit) {
          queue->units[tier].push_back(unit);
        } else {
          if (!big_units_guard) {
            big_units_guard.emplace(&big_units_queue_.mutex);
          }
          big_units_queue_.has_units[tier].store(true,
                                                 std::memory_order_relaxed);
          big_units_queue_.units[tier].emplace(func_size, unit);
        }
      }
    }
  }

  void AddTopTierPriorityUnit(WasmCompilationUnit unit, size_t priority) {
    base::SharedMutexGuard<base::kShared> queues_guard{&queues_mutex_};
    // Add to the individual queues in a round-robin fashion. No special care is
    // taken to balance them; they will be balanced by work stealing.
    // Priorities should only be seen as a hint here; without balancing, we
    // might pop a unit with lower priority from one queue while other queues
    // still hold higher-priority units.
    // Since updating priorities in a std::priority_queue is difficult, we just
    // add new units with higher priorities, and use the
    // {CompilationUnitQueues::top_tier_compiled_} array to discard units for
    // functions which are already being compiled.
    int queue_to_add = next_queue_to_add.load(std::memory_order_relaxed);
    while (!next_queue_to_add.compare_exchange_weak(
        queue_to_add, next_task_id(queue_to_add, queues_.size()),
        std::memory_order_relaxed)) {
      // Retry with updated {queue_to_add}.
    }

    {
      auto* queue = queues_[queue_to_add].get();
      base::MutexGuard guard(&queue->mutex);
      queue->top_tier_priority_units.emplace(priority, unit);
      num_priority_units_.fetch_add(1, std::memory_order_relaxed);
      num_units_[CompilationTier::kTopTier].fetch_add(
          1, std::memory_order_relaxed);
    }
  }

  // Get the current number of units in the queue for |tier|. This is only a
  // momentary snapshot, it's not guaranteed that {GetNextUnit} returns a unit
  // if this method returns non-zero.
  size_t GetSizeForTier(CompilationTier tier) const {
    DCHECK_LT(tier, CompilationTier::kNumTiers);
    return num_units_[tier].load(std::memory_order_relaxed);
  }

  void AllowAnotherTopTierJob(uint32_t func_index) {
    top_tier_compiled_[func_index].store(false, std::memory_order_relaxed);
  }

  void AllowAnotherTopTierJobForAllFunctions() {
    for (int i = 0; i < num_declared_functions_; i++) {
      AllowAnotherTopTierJob(i);
    }
  }

  size_t EstimateCurrentMemoryConsumption() const;

 private:
  // Functions bigger than {kBigUnitsLimit} will be compiled first, in ascending
  // order of their function body size.
  static constexpr size_t kBigUnitsLimit = 4096;

  struct BigUnit {
    BigUnit(size_t func_size, WasmCompilationUnit unit)
        : func_size{func_size}, unit(unit) {}

    size_t func_size;
    WasmCompilationUnit unit;

    bool operator<(const BigUnit& other) const {
      return func_size < other.func_size;
    }
  };

  struct TopTierPriorityUnit {
    TopTierPriorityUnit(int priority, WasmCompilationUnit unit)
        : priority(priority), unit(unit) {}

    size_t priority;
    WasmCompilationUnit unit;

    bool operator<(const TopTierPriorityUnit& other) const {
      return priority < other.priority;
    }
  };

  struct BigUnitsQueue {
    BigUnitsQueue() {
#if !defined(__cpp_lib_atomic_value_initialization) || \
    __cpp_lib_atomic_value_initialization < 201911L
      for (auto& atomic : has_units) std::atomic_init(&atomic, false);
#endif
    }

    mutable base::Mutex mutex;

    // Can be read concurrently to check whether any elements are in the queue.
    std::atomic<bool> has_units[CompilationTier::kNumTiers];

    // Protected by {mutex}:
    std::priority_queue<BigUnit> units[CompilationTier::kNumTiers];
  };

  struct QueueImpl : public Queue {
    explicit QueueImpl(int next_steal_task_id)
        : next_steal_task_id(next_steal_task_id) {}

    // Number of units after which the task processing this queue should publish
    // compilation results. Updated (reduced, using relaxed ordering) when new
    // queues are allocated. If there is only one thread running, we can delay
    // publishing arbitrarily.
    std::atomic<int> publish_limit{kMaxInt};

    base::Mutex mutex;

    // All fields below are protected by {mutex}.
    std::vector<WasmCompilationUnit> units[CompilationTier::kNumTiers];
    std::priority_queue<TopTierPriorityUnit> top_tier_priority_units;
    int next_steal_task_id;
  };

  int next_task_id(int task_id, size_t num_queues) const {
    int next = task_id + 1;
    return next == static_cast<int>(num_queues) ? 0 : next;
  }

  std::optional<WasmCompilationUnit> GetNextUnitOfTier(Queue* public_queue,
                                                       int tier) {
    QueueImpl* queue = static_cast<QueueImpl*>(public_queue);

    // First check whether there is a priority unit. Execute that first.
    if (tier == CompilationTier::kTopTier) {
      if (auto unit = GetTopTierPriorityUnit(queue)) {
        return unit;
      }
    }

    // Then check whether there is a big unit of that tier.
    if (auto unit = GetBigUnitOfTier(tier)) return unit;

    // Finally check whether our own queue has a unit of the wanted tier. If
    // so, return it, otherwise get the task id to steal from.
    int steal_task_id;
    {
      base::MutexGuard mutex_guard(&queue->mutex);
      if (!queue->units[tier].empty()) {
        auto unit = queue->units[tier].back();
        queue->units[tier].pop_back();
        return unit;
      }
      steal_task_id = queue->next_steal_task_id;
    }

    // Try to steal from all other queues. If this succeeds, return one of the
    // stolen units.
    {
      base::SharedMutexGuard<base::kShared> guard{&queues_mutex_};
      for (size_t steal_trials = 0; steal_trials < queues_.size();
           ++steal_trials, ++steal_task_id) {
        if (steal_task_id >= static_cast<int>(queues_.size())) {
          steal_task_id = 0;
        }
        if (auto unit = StealUnitsAndGetFirst(queue, steal_task_id, tier)) {
          return unit;
        }
      }
    }

    // If we reach here, we didn't find any unit of the requested tier.
    return {};
  }

  std::optional<WasmCompilationUnit> GetBigUnitOfTier(int tier) {
    // Fast path without locking.
    if (!big_units_queue_.has_units[tier].load(std::memory_order_relaxed)) {
      return {};
    }
    base::MutexGuard guard(&big_units_queue_.mutex);
    if (big_units_queue_.units[tier].empty()) return {};
    WasmCompilationUnit unit = big_units_queue_.units[tier].top().unit;
    big_units_queue_.units[tier].pop();
    if (big_units_queue_.units[tier].empty()) {
      big_units_queue_.has_units[tier].store(false, std::memory_order_relaxed);
    }
    return unit;
  }

  std::optional<WasmCompilationUnit> GetTopTierPriorityUnit(QueueImpl* queue) {
    // Fast path without locking.
    if (num_priority_units_.load(std::memory_order_relaxed) == 0) {
      return {};
    }

    int steal_task_id;
    {
      base::MutexGuard mutex_guard(&queue->mutex);
      while (!queue->top_tier_priority_units.empty()) {
        auto unit = queue->top_tier_priority_units.top().unit;
        queue->top_tier_priority_units.pop();
        num_priority_units_.fetch_sub(1, std::memory_order_relaxed);

        if (!top_tier_compiled_[unit.func_index()].exchange(
                true, std::memory_order_relaxed)) {
          return unit;
        }
        num_units_[CompilationTier::kTopTier].fetch_sub(
            1, std::memory_order_relaxed);
      }
      steal_task_id = queue->next_steal_task_id;
    }

    // Try to steal from all other queues. If this succeeds, return one of the
    // stolen units.
    {
      base::SharedMutexGuard<base::kShared> guard{&queues_mutex_};
      for (size_t steal_trials = 0; steal_trials < queues_.size();
           ++steal_trials, ++steal_task_id) {
        if (steal_task_id >= static_cast<int>(queues_.size())) {
          steal_task_id = 0;
        }
        if (auto unit = StealTopTierPriorityUnit(queue, steal_task_id)) {
          return unit;
        }
      }
    }

    return {};
  }

  // Steal units of {wanted_tier} from {steal_from_task_id} to {queue}. Return
  // first stolen unit (rest put in queue of {task_id}), or {nullopt} if
  // {steal_from_task_id} had no units of {wanted_tier}.
  // Hold a shared lock on {queues_mutex_} when calling this method.
  std::optional<WasmCompilationUnit> StealUnitsAndGetFirst(
      QueueImpl* queue, int steal_from_task_id, int wanted_tier) {
    auto* steal_queue = queues_[steal_from_task_id].get();
    // Cannot steal from own queue.
    if (steal_queue == queue) return {};
    std::vector<WasmCompilationUnit> stolen;
    std::optional<WasmCompilationUnit> returned_unit;
    {
      base::MutexGuard guard(&steal_queue->mutex);
      auto* steal_from_vector = &steal_queue->units[wanted_tier];
      if (steal_from_vector->empty()) return {};
      size_t remaining = steal_from_vector->size() / 2;
      auto steal_begin = steal_from_vector->begin() + remaining;
      returned_unit = *steal_begin;
      stolen.assign(steal_begin + 1, steal_from_vector->end());
      steal_from_vector->erase(steal_begin, steal_from_vector->end());
    }
    base::MutexGuard guard(&queue->mutex);
    auto* target_queue = &queue->units[wanted_tier];
    target_queue->insert(target_queue->end(), stolen.begin(), stolen.end());
    queue->next_steal_task_id = steal_from_task_id + 1;
    return returned_unit;
  }

  // Steal one priority unit from {steal_from_task_id} to {task_id}. Return
  // stolen unit, or {nullopt} if {steal_from_task_id} had no priority units.
  // Hold a shared lock on {queues_mutex_} when calling this method.
  std::optional<WasmCompilationUnit> StealTopTierPriorityUnit(
      QueueImpl* queue, int steal_from_task_id) {
    auto* steal_queue = queues_[steal_from_task_id].get();
    // Cannot steal from own queue.
    if (steal_queue == queue) return {};
    std::optional<WasmCompilationUnit> returned_unit;
    {
      base::MutexGuard guard(&steal_queue->mutex);
      while (true) {
        if (steal_queue->top_tier_priority_units.empty()) return {};

        auto unit = steal_queue->top_tier_priority_units.top().unit;
        steal_queue->top_tier_priority_units.pop();
        num_priority_units_.fetch_sub(1, std::memory_order_relaxed);

        if (!top_tier_compiled_[unit.func_index()].exchange(
                true, std::memory_order_relaxed)) {
          returned_unit = unit;
          break;
        }
        num_units_[CompilationTier::kTopTier].fetch_sub(
            1, std::memory_order_relaxed);
      }
    }
    base::MutexGuard guard(&queue->mutex);
    queue->next_steal_task_id = steal_from_task_id + 1;
    return returned_unit;
  }

  // {queues_mutex_} protectes {queues_};
  mutable base::SharedMutex queues_mutex_;
  std::vector<std::unique_ptr<QueueImpl>> queues_;

  const int num_declared_functions_;

  BigUnitsQueue big_units_queue_;

  std::atomic<size_t> num_units_[CompilationTier::kNumTiers];
  std::atomic<size_t> num_priority_units_{0};
  std::unique_ptr<std::atomic<bool>[]> top_tier_compiled_;
  std::atomic<int> next_queue_to_add{0};
};

size_t CompilationUnitQueues::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(CompilationUnitQueues, 248);
  UPDATE_WHEN_CLASS_CHANGES(QueueImpl, 144);
  UPDATE_WHEN_CLASS_CHANGES(BigUnitsQueue, 120);
  // Not including sizeof(CompilationUnitQueues) because that's included in
  // sizeof(CompilationStateImpl).
  size_t result = 0;
  {
    base::SharedMutexGuard<base::kShared> lock(&queues_mutex_);
    result += ContentSize(queues_) + queues_.size() * sizeof(QueueImpl);
    for (const auto& q : queues_) {
      base::MutexGuard guard(&q->mutex);
      result += ContentSize(*q->units);
      result += q->top_tier_priority_units.size() * sizeof(TopTierPriorityUnit);
    }
  }
  {
    base::MutexGuard lock(&big_units_queue_.mutex);
    result += big_units_queue_.units[0].size() * sizeof(BigUnit);
    result += big_units_queue_.units[1].size() * sizeof(BigUnit);
  }
  // For {top_tier_compiled_}.
  result += sizeof(std::atomic<bool>) * num_declared_functions_;
  return result;
}

bool CompilationUnitQueues::Queue::ShouldPublish(
    int num_processed_units) const {
  auto* queue = static_cast<const QueueImpl*>(this);
  return num_processed_units >=
         queue->publish_limit.load(std::memory_order_relaxed);
}

// The {CompilationStateImpl} keeps track of the compilation state of the
// owning NativeModule, i.e. which functions are left to be compiled.
// It contains a task manager to allow parallel and asynchronous background
// compilation of functions.
// Its public interface {CompilationState} lives in compilation-environment.h.
class CompilationStateImpl {
 public:
  CompilationStateImpl(const std::shared_ptr<NativeModule>& native_module,
                       std::shared_ptr<Counters> async_counters,
                       DynamicTiering dynamic_tiering,
                       WasmDetectedFeatures detected_features);
  ~CompilationStateImpl() {
    if (baseline_compile_job_->IsValid()) {
      baseline_compile_job_->CancelAndDetach();
    }
    if (top_tier_compile_job_->IsValid()) {
      top_tier_compile_job_->CancelAndDetach();
    }
  }

  // Call right after the constructor, after the {compilation_state_} field in
  // the {NativeModule} has been initialized.
  void InitCompileJob();

  // {kCancelUnconditionally}: Cancel all compilation.
  // {kCancelInitialCompilation}: Cancel all compilation if initial (baseline)
  // compilation is not finished yet.
  enum CancellationPolicy { kCancelUnconditionally, kCancelInitialCompilation };
  void CancelCompilation(CancellationPolicy);

  bool cancelled() const;

  // Apply a compilation hint to the initial compilation progress, updating all
  // internal fields accordingly.
  void ApplyCompilationHintToInitialProgress(const WasmCompilationHint& hint,
                                             size_t hint_idx);

  // Use PGO information to choose a better initial compilation progress
  // (tiering decisions).
  void ApplyPgoInfoToInitialProgress(ProfileInformation* pgo_info);

  // Apply PGO information to a fully initialized compilation state. Also
  // trigger compilation as needed.
  void ApplyPgoInfoLate(ProfileInformation* pgo_info);

  // Initialize compilation progress. Set compilation tiers to expect for
  // baseline and top tier compilation. Must be set before
  // {CommitCompilationUnits} is invoked which triggers background compilation.
  void InitializeCompilationProgress(ProfileInformation* pgo_info);

  void InitializeCompilationProgressAfterDeserialization(
      base::Vector<const int> lazy_functions,
      base::Vector<const int> eager_functions);

  // Initializes compilation units based on the information encoded in the
  // {compilation_progress_}.
  void InitializeCompilationUnits(
      std::unique_ptr<CompilationUnitBuilder> builder);

  // Adds compilation units for another function to the
  // {CompilationUnitBuilder}. This function is the streaming compilation
  // equivalent to {InitializeCompilationUnits}.
  void AddCompilationUnit(CompilationUnitBuilder* builder, int func_index);

  // Add the callback to be called on compilation events. Needs to be
  // set before {CommitCompilationUnits} is run to ensure that it receives all
  // events. The callback object must support being deleted from any thread.
  void AddCallback(std::unique_ptr<CompilationEventCallback> callback);

  // Inserts new functions to compile and kicks off compilation.
  void CommitCompilationUnits(base::Vector<WasmCompilationUnit> baseline_units,
                              base::Vector<WasmCompilationUnit> top_tier_units);
  void CommitTopTierCompilationUnit(WasmCompilationUnit);
  void AddTopTierPriorityCompilationUnit(WasmCompilationUnit, size_t);

  CompilationUnitQueues::Queue* GetQueueForCompileTask(int task_id);

  std::optional<WasmCompilationUnit> GetNextCompilationUnit(
      CompilationUnitQueues::Queue*, CompilationTier tier);

  void OnFinishedUnits(base::Vector<WasmCode*>);

  void OnCompilationStopped(WasmDetectedFeatures detected);
  void SchedulePublishCompilationResults(
      std::vector<std::unique_ptr<WasmCode>> unpublished_code,
      CompilationTier tier);

  WasmDetectedFeatures detected_features() const {
    return detected_features_.load(std::memory_order_relaxed);
  }

  // Update the set of detected features; returns all features that were not
  // detected before.
  V8_WARN_UNUSED_RESULT WasmDetectedFeatures
      UpdateDetectedFeatures(WasmDetectedFeatures);

  size_t NumOutstandingCompilations(CompilationTier tier) const;

  void SetError();

  void WaitForCompilationEvent(CompilationEvent event);

  void TierUpAllFunctions();

  void AllowAnotherTopTierJob(uint32_t func_index) {
    compilation_unit_queues_.AllowAnotherTopTierJob(func_index);
  }

  void AllowAnotherTopTierJobForAllFunctions() {
    compilation_unit_queues_.AllowAnotherTopTierJobForAllFunctions();
  }

  bool failed() const {
    return compile_failed_.load(std::memory_order_relaxed);
  }

  bool baseline_compilation_finished() const {
    base::MutexGuard guard(&callbacks_mutex_);
    return outstanding_baseline_units_ == 0;
  }

  DynamicTiering dynamic_tiering() const { return dynamic_tiering_; }

  Counters* counters() const { return async_counters_.get(); }

  void SetWireBytesStorage(
      std::shared_ptr<WireBytesStorage> wire_bytes_storage) {
    base::MutexGuard guard(&mutex_);
    wire_bytes_storage_ = std::move(wire_bytes_storage);
  }

  std::shared_ptr<WireBytesStorage> GetWireBytesStorage() const {
    base::MutexGuard guard(&mutex_);
    DCHECK_NOT_NULL(wire_bytes_storage_);
    return wire_bytes_storage_;
  }

  void set_compilation_id(int compilation_id) {
    DCHECK_EQ(compilation_id_, kInvalidCompilationID);
    compilation_id_ = compilation_id;
  }

  size_t EstimateCurrentMemoryConsumption() const;

  // Called from the delayed task to trigger caching if the timeout
  // (--wasm-caching-timeout-ms) has passed since the last top-tier compilation.
  // This either triggers caching or re-schedules the task if more code has
  // been compiled to the top tier in the meantime.
  void TriggerCachingAfterTimeout();

  std::vector<WasmCode*> PublishCode(
      base::Vector<std::unique_ptr<WasmCode>> codes);

 private:
  void AddCompilationUnitInternal(CompilationUnitBuilder* builder,
                                  int function_index,
                                  uint8_t function_progress);

  // Trigger callbacks according to the internal counters below
  // (outstanding_...).
  // Hold the {callbacks_mutex_} when calling this method.
  void TriggerOutstandingCallbacks();
  // Trigger an exact set of callbacks. Hold the {callbacks_mutex_} when calling
  // this method.
  void TriggerCallbacks(base::EnumSet<CompilationEvent>);

  void PublishCompilationResults(
      std::vector<std::unique_ptr<WasmCode>> unpublished_code);

  NativeModule* const native_module_;
  std::weak_ptr<NativeModule> const native_module_weak_;
  const std::shared_ptr<Counters> async_counters_;

  // Compilation error, atomically updated. This flag can be updated and read
  // using relaxed semantics.
  std::atomic<bool> compile_failed_{false};

  // True if compilation was cancelled and worker threads should return. This
  // flag can be updated and read using relaxed semantics.
  std::atomic<bool> compile_cancelled_{false};

  CompilationUnitQueues compilation_unit_queues_;

  // Cache the dynamic tiering configuration to be consistent for the whole
  // compilation.
  const DynamicTiering dynamic_tiering_;

  // This mutex protects all information of this {CompilationStateImpl} which is
  // being accessed concurrently.
  mutable base::Mutex mutex_;

  // The compile job handles, initialized right after construction of
  // {CompilationStateImpl}.
  std::unique_ptr<JobHandle> baseline_compile_job_;
  std::unique_ptr<JobHandle> top_tier_compile_job_;

  // The compilation id to identify trace events linked to this compilation.
  static constexpr int kInvalidCompilationID = -1;
  int compilation_id_ = kInvalidCompilationID;

  // Features detected to be used in this module. Features can be detected
  // as a module is being compiled.
  std::atomic<WasmDetectedFeatures> detected_features_;

  //////////////////////////////////////////////////////////////////////////////
  // Protected by {mutex_}:

  // Abstraction over the storage of the wire bytes. Held in a shared_ptr so
  // that background compilation jobs can keep the storage alive while
  // compiling.
  std::shared_ptr<WireBytesStorage> wire_bytes_storage_;

  // End of fields protected by {mutex_}.
  //////////////////////////////////////////////////////////////////////////////

  // This mutex protects the callbacks vector, and the counters used to
  // determine which callbacks to call. The counters plus the callbacks
  // themselves need to be synchronized to ensure correct order of events.
  mutable base::Mutex callbacks_mutex_;

  //////////////////////////////////////////////////////////////////////////////
  // Protected by {callbacks_mutex_}:

  // Callbacks to be called on compilation events.
  std::vector<std::unique_ptr<CompilationEventCallback>> callbacks_;

  // Events that already happened.
  base::EnumSet<CompilationEvent> finished_events_;

  int outstanding_baseline_units_ = 0;
  // The amount of generated top tier code since the last
  // {kFinishedCompilationChunk} event.
  size_t bytes_since_last_chunk_ = 0;
  std::vector<uint8_t> compilation_progress_;

  // The timestamp of the last top-tier compilation.
  // This field is updated on every publishing of top-tier code, and is reset
  // once caching is triggered. Hence it also informs whether a caching task is
  // currently being scheduled (whenever this is set).
  base::TimeTicks last_top_tier_compilation_timestamp_;

  // End of fields protected by {callbacks_mutex_}.
  //////////////////////////////////////////////////////////////////////////////

  struct PublishState {
    // {mutex_} protects {publish_queue_} and {publisher_running_}.
    base::Mutex mutex_;
    std::vector<std::unique_ptr<WasmCode>> publish_queue_;
    bool publisher_running_ = false;
  };
  PublishState publish_state_[CompilationTier::kNumTiers];

  // Encoding of fields in the {compilation_progress_} vector.
  using RequiredBaselineTierField = base::BitField8<ExecutionTier, 0, 2>;
  using RequiredTopTierField = base::BitField8<ExecutionTier, 2, 2>;
  using ReachedTierField = base::BitField8<ExecutionTier, 4, 2>;
};

CompilationStateImpl* Impl(CompilationState* compilation_state) {
  return reinterpret_cast<CompilationStateImpl*>(compilation_state);
}
const CompilationStateImpl* Impl(const CompilationState* compilation_state) {
  return reinterpret_cast<const CompilationStateImpl*>(compilation_state);
}

CompilationStateImpl* BackgroundCompileScope::compilation_state() const {
  DCHECK(native_module_);
  return Impl(native_module_->compilation_state());
}

size_t CompilationStateImpl::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(CompilationStateImpl, 672);
  size_t result = sizeof(CompilationStateImpl);

  {
    base::MutexGuard guard{&mutex_};
    result += compilation_unit_queues_.EstimateCurrentMemoryConsumption();
  }

  // To read the size of {callbacks_} and {compilation_progress_}, we'd
  // need to acquire the {callbacks_mutex_}, which can cause deadlocks
  // when that mutex is already held elsewhere and another thread calls
  // into this function. So we rely on heuristics and informed guesses
  // instead: {compilation_progress_} contains an entry for every declared
  // function in the module...
  result += sizeof(uint8_t) * native_module_->module()->num_declared_functions;
  // ...and there are typically no more than a handful of {callbacks_}.
  constexpr size_t kAssumedNumberOfCallbacks = 4;
  constexpr size_t size_of_vector =
      kAssumedNumberOfCallbacks *
      sizeof(std::unique_ptr<CompilationEventCallback>);
  // Concrete subclasses of CompilationEventCallback will be bigger, but we
  // can't know that here.
  constexpr size_t size_of_payload =
      kAssumedNumberOfCallbacks * sizeof(CompilationEventCallback);
  result += size_of_vector + size_of_payload;

  if (v8_flags.trace_wasm_offheap_memory) {
    PrintF("CompilationStateImpl: %zu\n", result);
  }
  return result;
}

bool BackgroundCompileScope::cancelled() const {
  return native_module_ == nullptr ||
         Impl(native_module_->compilation_state())->cancelled();
}

}  // namespace

//////////////////////////////////////////////////////
// PIMPL implementation of {CompilationState}.

CompilationState::~CompilationState() { Impl(this)->~CompilationStateImpl(); }

void CompilationState::InitCompileJob() { Impl(this)->InitCompileJob(); }

void CompilationState::CancelCompilation() {
  Impl(this)->CancelCompilation(CompilationStateImpl::kCancelUnconditionally);
}

void CompilationState::CancelInitialCompilation() {
  Impl(this)->CancelCompilation(
      CompilationStateImpl::kCancelInitialCompilation);
}

void CompilationState::SetError() { Impl(this)->SetError(); }

void CompilationState::SetWireBytesStorage(
    std::shared_ptr<WireBytesStorage> wire_bytes_storage) {
  Impl(this)->SetWireBytesStorage(std::move(wire_bytes_storage));
}

std::shared_ptr<WireBytesStorage> CompilationState::GetWireBytesStorage()
    const {
  return Impl(this)->GetWireBytesStorage();
}

void CompilationState::AddCallback(
    std::unique_ptr<CompilationEventCallback> callback) {
  return Impl(this)->AddCallback(std::move(callback));
}

void CompilationState::TierUpAllFunctions() {
  Impl(this)->TierUpAllFunctions();
}

void CompilationState::AllowAnotherTopTierJob(uint32_t func_index) {
  Impl(this)->AllowAnotherTopTierJob(func_index);
}

void CompilationState::AllowAnotherTopTierJobForAllFunctions() {
  Impl(this)->AllowAnotherTopTierJobForAllFunctions();
}

void CompilationState::InitializeAfterDeserialization(
    base::Vector<const int> lazy_functions,
    base::Vector<const int> eager_functions) {
  Impl(this)->InitializeCompilationProgressAfterDeserialization(
      lazy_functions, eager_functions);
}

bool CompilationState::failed() const { return Impl(this)->failed(); }

bool CompilationState::baseline_compilation_finished() const {
  return Impl(this)->baseline_compilation_finished();
}

void CompilationState::set_compilation_id(int compilation_id) {
  Impl(this)->set_compilation_id(compilation_id);
}

DynamicTiering CompilationState::dynamic_tiering() const {
  return Impl(this)->dynamic_tiering();
}

size_t CompilationState::EstimateCurrentMemoryConsumption() const {
  return Impl(this)->EstimateCurrentMemoryConsumption();
}

std::vector<WasmCode*> CompilationState::PublishCode(
    base::Vector<std::unique_ptr<WasmCode>> unpublished_code) {
  return Impl(this)->PublishCode(unpublished_code);
}

// static
std::unique_ptr<CompilationState> CompilationState::New(
    const std::shared_ptr<NativeModule>& native_module,
    std::shared_ptr<Counters> async_counters, DynamicTiering dynamic_tiering,
    WasmDetectedFeatures detected_features) {
  return std::unique_ptr<CompilationState>(
      reinterpret_cast<CompilationState*>(new CompilationStateImpl(
          std::move(native_module), std::move(async_counters), dynamic_tiering,
          detected_features)));
}

WasmDetectedFeatures CompilationState::detected_features() const {
  return Impl(this)->detected_features();
}

WasmDetectedFeatures CompilationState::UpdateDetectedFeatures(
    WasmDetectedFeatures detected_features) {
  return Impl(this)->UpdateDetectedFeatures(detected_features);
}

// End of PIMPL implementation of {CompilationState}.
//////////////////////////////////////////////////////

namespace {

ExecutionTier ApplyHintToExecutionTier(WasmCompilationHintTier hint,
                                       ExecutionTier default_tier) {
  switch (hint) {
    case WasmCompilationHintTier::kDefault:
      return default_tier;
    case WasmCompilationHintTier::kBaseline:
      return ExecutionTier::kLiftoff;
    case WasmCompilationHintTier::kOptimized:
      return ExecutionTier::kTurbofan;
  }
  UNREACHABLE();
}

const WasmCompilationHint* GetCompilationHint(const WasmModule* module,
                                              uint32_t func_index) {
  DCHECK_LE(module->num_imported_functions, func_index);
  uint32_t hint_index = declared_function_index(module, func_index);
  const std::vector<WasmCompilationHint>& compilation_hints =
      module->compilation_hints;
  if (hint_index < compilation_hints.size()) {
    return &compilation_hints[hint_index];
  }
  return nullptr;
}

CompileStrategy GetCompileStrategy(const WasmModule* module,
                                   WasmEnabledFeatures enabled_features,
                                   uint32_t func_index, bool lazy_module) {
  if (lazy_module) return CompileStrategy::kLazy;
  if (!enabled_features.has_compilation_hints()) {
    return CompileStrategy::kDefault;
  }
  auto* hint = GetCompilationHint(module, func_index);
  if (hint == nullptr) return CompileStrategy::kDefault;
  switch (hint->strategy) {
    case WasmCompilationHintStrategy::kLazy:
      return CompileStrategy::kLazy;
    case WasmCompilationHintStrategy::kEager:
      return CompileStrategy::kEager;
    case WasmCompilationHintStrategy::kLazyBaselineEagerTopTier:
      return CompileStrategy::kLazyBaselineEagerTopTier;
    case WasmCompilationHintStrategy::kDefault:
      return CompileStrategy::kDefault;
  }
}

struct ExecutionTierPair {
  ExecutionTier baseline_tier;
  ExecutionTier top_tier;
};

// Pass the debug state as a separate parameter to avoid data races: the debug
// state may change between its use here and its use at the call site. To have
// a consistent view on the debug state, the caller reads the debug state once
// and then passes it to this function.
ExecutionTierPair GetDefaultTiersPerModule(NativeModule* native_module,
                                           DynamicTiering dynamic_tiering,
                                           DebugState is_in_debug_state,
                                           bool lazy_module) {
  const WasmModule* module = native_module->module();
  if (lazy_module) {
    return {ExecutionTier::kNone, ExecutionTier::kNone};
  }
  if (is_asmjs_module(module)) {
    DCHECK(!is_in_debug_state);
    return {ExecutionTier::kTurbofan, ExecutionTier::kTurbofan};
  }
  if (is_in_debug_state) {
    return {ExecutionTier::kLiftoff, ExecutionTier::kLiftoff};
  }
  ExecutionTier baseline_tier =
      v8_flags.liftoff ? ExecutionTier::kLiftoff : ExecutionTier::kTurbofan;
  bool eager_tier_up = !dynamic_tiering && v8_flags.wasm_tier_up;
  ExecutionTier top_tier =
      eager_tier_up ? ExecutionTier::kTurbofan : baseline_tier;
  return {baseline_tier, top_tier};
}

ExecutionTierPair GetLazyCompilationTiers(NativeModule* native_module,
                                          uint32_t func_index,
                                          DebugState is_in_debug_state) {
  DynamicTiering dynamic_tiering =
      Impl(native_module->compilation_state())->dynamic_tiering();
  // For lazy compilation, get the tiers we would use if lazy compilation is
  // disabled.
  constexpr bool kNotLazy = false;
  ExecutionTierPair tiers = GetDefaultTiersPerModule(
      native_module, dynamic_tiering, is_in_debug_state, kNotLazy);
  // If we are in debug mode, we ignore compilation hints.
  if (is_in_debug_state) return tiers;

  // Check if compilation hints override default tiering behaviour.
  if (native_module->enabled_features().has_compilation_hints()) {
    if (auto* hint = GetCompilationHint(native_module->module(), func_index)) {
      tiers.baseline_tier =
          ApplyHintToExecutionTier(hint->baseline_tier, tiers.baseline_tier);
      tiers.top_tier = ApplyHintToExecutionTier(hint->top_tier, tiers.top_tier);
    }
  }

  if (V8_UNLIKELY(v8_flags.wasm_tier_up_filter >= 0 &&
                  func_index !=
                      static_cast<uint32_t>(v8_flags.wasm_tier_up_filter))) {
    tiers.top_tier = tiers.baseline_tier;
  }

  // Correct top tier if necessary.
  static_assert(ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                "Assume an order on execution tiers");
  if (tiers.baseline_tier > tiers.top_tier) {
    tiers.top_tier = tiers.baseline_tier;
  }
  return tiers;
}

// The {CompilationUnitBuilder} builds compilation units and stores them in an
// internal buffer. The buffer is moved into the working queue of the
// {CompilationStateImpl} when {Commit} is called.
class CompilationUnitBuilder {
 public:
  explicit CompilationUnitBuilder(NativeModule* native_module)
      : native_module_(native_module) {}

  void AddBaselineUnit(int func_index, ExecutionTier tier) {
    baseline_units_.emplace_back(func_index, tier, kNotForDebugging);
  }

  void AddTopTierUnit(int func_index, ExecutionTier tier) {
    tiering_units_.emplace_back(func_index, tier, kNotForDebugging);
  }

  void Commit() {
    if (baseline_units_.empty() && tiering_units_.empty()) return;
    compilation_state()->CommitCompilationUnits(base::VectorOf(baseline_units_),
                                                base::VectorOf(tiering_units_));
    Clear();
  }

  void Clear() {
    baseline_units_.clear();
    tiering_units_.clear();
  }

  const WasmModule* module() { return native_module_->module(); }

 private:
  CompilationStateImpl* compilation_state() const {
    return Impl(native_module_->compilation_state());
  }

  NativeModule* const native_module_;
  std::vector<WasmCompilationUnit> baseline_units_;
  std::vector<WasmCompilationUnit> tiering_units_;
};

DecodeResult ValidateSingleFunction(Zone* zone, const WasmModule* module,
                                    int func_index,
                                    base::Vector<const uint8_t> code,
                                    WasmEnabledFeatures enabled_features,
                                    WasmDetectedFeatures* detected_features) {
  // Sometimes functions get validated unpredictably in the background, for
  // debugging or when inlining one function into another. We check here if that
  // is the case, and exit early if so.
  if (module->function_was_validated(func_index)) return {};
  const WasmFunction* func = &module->functions[func_index];
  bool is_shared = module->type(func->sig_index).is_shared;
  FunctionBody body{func->sig, func->code.offset(), code.begin(), code.end(),
                    is_shared};
  DecodeResult result = ValidateFunctionBody(zone, enabled_features, module,
                                             detected_features, body);
  if (result.ok()) module->set_function_validated(func_index);
  return result;
}

enum OnlyLazyFunctions : bool {
  kAllFunctions = false,
  kOnlyLazyFunctions = true,
};

bool IsLazyModule(const WasmModule* module) {
  return v8_flags.wasm_lazy_compilation ||
         (v8_flags.asm_wasm_lazy_compilation && is_asmjs_module(module));
}

class CompileLazyTimingScope {
 public:
  CompileLazyTimingScope(Counters* counters, NativeModule* native_module)
      : counters_(counters), native_module_(native_module) {
    timer_.Start();
  }

  ~CompileLazyTimingScope() {
    base::TimeDelta elapsed = timer_.Elapsed();
    native_module_->AddLazyCompilationTimeSample(elapsed.InMicroseconds());
    counters_->wasm_lazy_compile_time()->AddTimedSample(elapsed);
  }

 private:
  Counters* counters_;
  NativeModule* native_module_;
  base::ElapsedTimer timer_;
};

}  // namespace

bool CompileLazy(Isolate* isolate,
                 Tagged<WasmTrustedInstanceData> trusted_instance_data,
                 int func_index) {
  DisallowGarbageCollection no_gc;
  NativeModule* native_module = trusted_instance_data->native_module();
  Counters* counters = isolate->counters();

  // Put the timer scope around everything, including the {CodeSpaceWriteScope}
  // and its destruction, to measure complete overhead (apart from the runtime
  // function itself, which has constant overhead).
  std::optional<CompileLazyTimingScope> lazy_compile_time_scope;
  if (base::TimeTicks::IsHighResolution()) {
    lazy_compile_time_scope.emplace(counters, native_module);
  }

  DCHECK(!native_module->lazy_compile_frozen());

  TRACE_LAZY("Compiling wasm-function#%d.\n", func_index);

  CompilationStateImpl* compilation_state =
      Impl(native_module->compilation_state());
  DebugState is_in_debug_state = native_module->IsInDebugState();
  ExecutionTierPair tiers =
      GetLazyCompilationTiers(native_module, func_index, is_in_debug_state);

  DCHECK_LE(native_module->num_imported_functions(), func_index);
  DCHECK_LT(func_index, native_module->num_functions());
  WasmCompilationUnit baseline_unit{
      func_index, tiers.baseline_tier,
      is_in_debug_state ? kForDebugging : kNotForDebugging};
  CompilationEnv env = CompilationEnv::ForModule(native_module);
  WasmDetectedFeatures detected_features;
  WasmCompilationResult result = baseline_unit.ExecuteCompilation(
      &env, compilation_state->GetWireBytesStorage().get(), counters,
      &detected_features);
  compilation_state->OnCompilationStopped(detected_features);

  // During lazy compilation, we can only get compilation errors when
  // {--wasm-lazy-validation} is enabled. Otherwise, the module was fully
  // verified before starting its execution.
  CHECK_IMPLIES(result.failed(), v8_flags.wasm_lazy_validation);
  if (result.failed()) {
    return false;
  }

  WasmCodeRefScope code_ref_scope;
  WasmCode* code =
      native_module->PublishCode(native_module->AddCompiledCode(result));
  DCHECK_EQ(func_index, code->index());

  if (V8_UNLIKELY(native_module->log_code())) {
    GetWasmEngine()->LogCode(base::VectorOf(&code, 1));
    // Log the code immediately in the current isolate.
    GetWasmEngine()->LogOutstandingCodesForIsolate(isolate);
  }

  counters->wasm_lazily_compiled_functions()->Increment();

  const WasmModule* module = native_module->module();
  const bool lazy_module = IsLazyModule(module);
  if (GetCompileStrategy(module, native_module->enabled_features(), func_index,
                         lazy_module) == CompileStrategy::kLazy &&
      tiers.baseline_tier < tiers.top_tier) {
    WasmCompilationUnit tiering_unit{func_index, tiers.top_tier,
                                     kNotForDebugging};
    compilation_state->CommitTopTierCompilationUnit(tiering_unit);
  }
  return true;
}

void ThrowLazyCompilationError(Isolate* isolate,
                               const NativeModule* native_module,
                               int func_index) {
  const WasmModule* module = native_module->module();

  CompilationStateImpl* compilation_state =
      Impl(native_module->compilation_state());
  const WasmFunction* func = &module->functions[func_index];
  base::Vector<const uint8_t> code =
      compilation_state->GetWireBytesStorage()->GetCode(func->code);

  auto enabled_features = native_module->enabled_features();
  // This path is unlikely, so the overhead for creating an extra Zone is
  // not important.
  Zone validation_zone{GetWasmEngine()->allocator(), ZONE_NAME};
  WasmDetectedFeatures unused_detected_features;
  DecodeResult decode_result =
      ValidateSingleFunction(&validation_zone, module, func_index, code,
                             enabled_features, &unused_detected_features);

  CHECK(decode_result.failed());
  wasm::ErrorThrower thrower(isolate, nullptr);
  thrower.CompileFailed(GetWasmErrorWithName(native_module->wire_bytes(),
                                             func_index, module,
                                             std::move(decode_result).error()));
}

// The main purpose of this class is to copy the feedback vectors that live in
// `FixedArray`s on the JavaScript heap to a C++ datastructure on the `module`
// that is accessible to the background compilation threads.
// While we are at it, we also do some light processing here, e.g., mapping the
// feedback to functions, identified by their function index, and filtering out
// feedback for calls to imported functions (which we currently don't inline).
class TransitiveTypeFeedbackProcessor {
 public:
  static void Process(Isolate* isolate,
                      Tagged<WasmTrustedInstanceData> trusted_instance_data,
                      int func_index) {
    TransitiveTypeFeedbackProcessor{isolate, trusted_instance_data, func_index}
        .ProcessQueue();
  }

 private:
  TransitiveTypeFeedbackProcessor(
      Isolate* isolate, Tagged<WasmTrustedInstanceData> trusted_instance_data,
      int func_index)
      : isolate_(isolate),
        instance_data_(trusted_instance_data),
        module_(trusted_instance_data->module()),
        mutex_guard(&module_->type_feedback.mutex),
        feedback_for_function_(module_->type_feedback.feedback_for_function) {
    queue_.insert(func_index);
  }

  ~TransitiveTypeFeedbackProcessor() { DCHECK(queue_.empty()); }

  void ProcessQueue() {
    while (!queue_.empty()) {
      auto next = queue_.cbegin();
      ProcessFunction(*next);
      queue_.erase(next);
    }
  }

  void ProcessFunction(int func_index);

  void EnqueueCallees(const std::vector<CallSiteFeedback>& feedback) {
    for (size_t i = 0; i < feedback.size(); i++) {
      const CallSiteFeedback& csf = feedback[i];
      for (int j = 0; j < csf.num_cases(); j++) {
        int func = csf.function_index(j);
        // Don't spend time on calls that have never been executed.
        if (csf.call_count(j) == 0) continue;
        // Don't recompute feedback that has already been processed.
        auto existing = feedback_for_function_.find(func);
        if (existing != feedback_for_function_.end() &&
            !existing->second.feedback_vector.empty()) {
          if (!existing->second.needs_reprocessing_after_deopt) {
            continue;
          }
          DCHECK(v8_flags.wasm_deopt);
          existing->second.needs_reprocessing_after_deopt = false;
        }
        queue_.insert(func);
      }
    }
  }

  DisallowGarbageCollection no_gc_scope_;
  Isolate* const isolate_;
  const Tagged<WasmTrustedInstanceData> instance_data_;
  const WasmModule* const module_;
  // TODO(jkummerow): Check if it makes a difference to apply any updates
  // as a single batch at the end.
  base::SharedMutexGuard<base::kExclusive> mutex_guard;
  std::unordered_map<uint32_t, FunctionTypeFeedback>& feedback_for_function_;
  std::set<int> queue_;
};

bool IsCrossInstanceCall(Tagged<Object> obj, Isolate* const isolate) {
  return obj == ReadOnlyRoots{isolate}.wasm_cross_instance_call_symbol();
}

class FeedbackMaker {
 public:
  FeedbackMaker(Isolate* const isolate,
                Tagged<WasmTrustedInstanceData> trusted_instance_data,
                int func_index, int num_calls)
      : isolate_(isolate),
        instance_data_(trusted_instance_data),
        num_imported_functions_(static_cast<int>(
            trusted_instance_data->module()->num_imported_functions)),
        func_index_(func_index) {
    result_.reserve(num_calls);
  }

  void AddCallRefCandidate(Tagged<WasmFuncRef> funcref, int count) {
    Tagged<WasmInternalFunction> internal_function =
        Cast<WasmFuncRef>(funcref)->internal(isolate_);
    // Discard cross-instance calls, as we can only inline same-instance code.
    if (internal_function->implicit_arg() != instance_data_) {
      has_non_inlineable_targets_ = true;
      return;
    }
    // Discard imports for now.
    if (internal_function->function_index() < num_imported_functions_) {
      has_non_inlineable_targets_ = true;
      return;
    }
    AddCall(internal_function->function_index(), count);
  }

  void AddCallIndirectCandidate(Tagged<Object> target_truncated_obj,
                                int count) {
    // Discard cross-instance calls, as we can only inline same-instance code.
    if (IsCrossInstanceCall(target_truncated_obj, isolate_)) {
      has_non_inlineable_targets_ = true;
      return;
    }
    Tagged<Smi> target_truncated_smi = Cast<Smi>(target_truncated_obj);

    // We need to map a truncated call target back to a function index.
    // Generally there may be multiple jump tables if code spaces are far apart
    // (to ensure that direct calls can always use a near call to the closest
    // jump table).
    // However, here we are always handling call targets that are originally
    // from the `WasmDispatchTable`, whose entries are always targets pointing
    // into the main jump table, so we only need to check against that.

#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
    WasmCodePointerTable::Handle handle = target_truncated_smi.value();
    Address entry = GetProcessWideWasmCodePointerTable()->GetEntrypoint(handle);
    wasm::WasmCode* code =
        wasm::GetWasmCodeManager()->LookupCode(nullptr, entry);
    if (!code || code->native_module() != instance_data_->native_module() ||
        code->IsAnonymous()) {
      // Was not in the main table (e.g., because it's an imported function).
      has_non_inlineable_targets_ = true;
      return;
    }
    DCHECK_EQ(code->kind(), WasmCode::Kind::kWasmFunction);
    uint32_t func_idx = code->index();
#else
    Address jt_start = instance_data_->native_module()->jump_table_start();
    uint32_t jt_size = JumpTableAssembler::SizeForNumberOfSlots(
        instance_data_->module()->num_declared_functions);
    Address jt_end = jt_start + jt_size;

    uint32_t jt_start_truncated = jt_start & kSmiMaxValue;
    uint32_t jt_end_truncated = jt_end & kSmiMaxValue;
    uint32_t target_truncated = target_truncated_smi.value();

    if (target_truncated < jt_start_truncated ||
        target_truncated >= jt_end_truncated) {
      // Was not in the main table (e.g., because it's an imported function).
      has_non_inlineable_targets_ = true;
      return;
    }

    uint32_t jt_offset = target_truncated - jt_start_truncated;
    uint32_t jt_slot_idx = JumpTableAssembler::SlotOffsetToIndex(jt_offset);
    uint32_t func_idx =
        instance_data_->module()->num_imported_functions + jt_slot_idx;
#endif
    AddCall(func_idx, count);
  }

  void AddCall(int target, int count) {
    // Keep the cache sorted (using insertion-sort), highest count first.
    int insertion_index = 0;
    while (insertion_index < cache_usage_ &&
           counts_cache_[insertion_index] >= count) {
      insertion_index++;
    }
    for (int shifted_index = cache_usage_ - 1; shifted_index >= insertion_index;
         shifted_index--) {
      targets_cache_[shifted_index + 1] = targets_cache_[shifted_index];
      counts_cache_[shifted_index + 1] = counts_cache_[shifted_index];
    }
    targets_cache_[insertion_index] = target;
    counts_cache_[insertion_index] = count;
    cache_usage_++;
  }

  bool HasTargetCached(int target) {
    auto end = targets_cache_ + cache_usage_;
    return std::find(targets_cache_, end, target) != end;
  }

  void FinalizeCall() {
    if (cache_usage_ == 0) {
      result_.emplace_back();
    } else if (cache_usage_ == 1) {
      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%zu inlineable (monomorphic)]\n",
               func_index_, result_.size());
      }
      result_.emplace_back(targets_cache_[0], counts_cache_[0]);
    } else {
      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%zu inlineable (polymorphic %d)]\n",
               func_index_, result_.size(), cache_usage_);
      }
      CallSiteFeedback::PolymorphicCase* polymorphic =
          new CallSiteFeedback::PolymorphicCase[cache_usage_];
      for (int i = 0; i < cache_usage_; i++) {
        polymorphic[i].function_index = targets_cache_[i];
        polymorphic[i].absolute_call_frequency = counts_cache_[i];
      }
      result_.emplace_back(polymorphic, cache_usage_);
    }
    result_.back().set_has_non_inlineable_targets(has_non_inlineable_targets_);
    has_non_inlineable_targets_ = false;
    cache_usage_ = 0;
  }

  void set_has_non_inlineable_targets() { has_non_inlineable_targets_ = true; }

  // {GetResult} can only be called on a r-value reference to make it more
  // obvious at call sites that {this} should not be used after this operation.
  std::vector<CallSiteFeedback>&& GetResult() && { return std::move(result_); }

 private:
  Isolate* const isolate_;
  const Tagged<WasmTrustedInstanceData> instance_data_;
  std::vector<CallSiteFeedback> result_;
  const int num_imported_functions_;
  const int func_index_;
  int cache_usage_{0};
  int targets_cache_[kMaxPolymorphism];
  int counts_cache_[kMaxPolymorphism];
  bool has_non_inlineable_targets_ = false;
};

void TransitiveTypeFeedbackProcessor::ProcessFunction(int func_index) {
  int which_vector = declared_function_index(module_, func_index);
  Tagged<Object> maybe_feedback =
      instance_data_->feedback_vectors()->get(which_vector);
  if (!IsFixedArray(maybe_feedback)) return;
  Tagged<FixedArray> feedback = Cast<FixedArray>(maybe_feedback);
  base::Vector<uint32_t> call_targets =
      module_->type_feedback.feedback_for_function[func_index]
          .call_targets.as_vector();

  // For each entry in {call_targets}, there are two {Object} slots in the
  // {feedback} vector:
  // +--------------------------+-----------------------------+----------------+
  // |        Call Type         |      Feedback: Entry 1      |    Entry 2     |
  // +-------------------------+------------------------------+----------------+
  // | direct                   | Smi(count)                  | Smi(0), unused |
  // +--------------------------+-----------------------------+----------------+
  // | ref, uninitialized       | Smi(0)                      | Smi(0)         |
  // | ref, monomorphic         | WasmFuncRef(target)         | Smi(count>0)   |
  // | ref, polymorphic         | FixedArray                  | Undefined      |
  // | ref, megamorphic         | MegamorphicSymbol           | Undefined      |
  // +--------------------------+-----------------------------+----------------+
  // | indirect, uninitialized  | Smi(0)                      | Smi(0)         |
  // | indirect, monomorphic    | Smi(truncated_target)       | Smi(count>0)   |
  // | indirect, wrong instance | WasmCrossInstanceCallSymbol | Smi(count>0)   |
  // | indirect, polymorphic    | FixedArray                  | Undefined      |
  // | indirect, megamorphic    | MegamorphicSymbol           | Undefined      |
  // +--------------------------+-----------------------------+----------------+
  // The FixedArray entries for the polymorphic cases look like the monomorphic
  // entries in the feedback vector itself, i.e., they can a (truncated) target,
  // or the wrong instance sentinel (for cross-instance call_indirect).
  // See {UpdateCallRefOrIndirectIC} in {wasm.tq} for how this is written.
  // Since this is combining untrusted data ({feedback} vector on the JS heap)
  // with trusted data ({call_targets}), make sure to avoid an OOB access.
  int checked_feedback_length = feedback->length();
  SBXCHECK_EQ(checked_feedback_length, call_targets.size() * 2);
  FeedbackMaker fm(isolate_, instance_data_, func_index,
                   checked_feedback_length / 2);
  for (int i = 0; i < checked_feedback_length; i += 2) {
    uint32_t sentinel_or_target = call_targets[i / 2];
    Tagged<Object> first_slot = feedback->get(i);
    Tagged<Object> second_slot = feedback->get(i + 1);

    if (sentinel_or_target != FunctionTypeFeedback::kCallRef &&
        sentinel_or_target != FunctionTypeFeedback::kCallIndirect) {
      // Direct call counts.
      int count = Smi::ToInt(first_slot);
      DCHECK_EQ(Smi::ToInt(second_slot), 0);
      // TODO(dlehmann): Currently, TurboFan assumes that we add feedback even
      // if the call count is zero. Once TurboFan is gone, revisit if we can
      // avoid this (similar to how we do for call_ref/call_indirect today).
      fm.AddCall(static_cast<int>(sentinel_or_target), count);
    } else if (IsSmi(second_slot) && Smi::ToInt(second_slot) == 0) {
      // Uninitialized call_ref or call_indirect.
      DCHECK_EQ(Smi::ToInt(first_slot), 0);
      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%d: uninitialized]\n", func_index, i / 2);
      }
    } else if (IsWasmFuncRef(first_slot)) {
      // Monomorphic call_ref.
      DCHECK_EQ(sentinel_or_target, FunctionTypeFeedback::kCallRef);
      int count = Smi::ToInt(second_slot);
      fm.AddCallRefCandidate(Cast<WasmFuncRef>(first_slot), count);
    } else if (IsSmi(first_slot) || IsCrossInstanceCall(first_slot, isolate_)) {
      // Monomorphic call_indirect.
      DCHECK_EQ(sentinel_or_target, FunctionTypeFeedback::kCallIndirect);
      int count = Smi::ToInt(second_slot);
      fm.AddCallIndirectCandidate(first_slot, count);
    } else if (IsFixedArray(first_slot)) {
      // Polymorphic call_ref or call_indirect.
      Tagged<FixedArray> polymorphic = Cast<FixedArray>(first_slot);
      DCHECK(IsUndefined(second_slot));
      int checked_polymorphic_length = polymorphic->length();
      SBXCHECK_LE(checked_polymorphic_length, 2 * kMaxPolymorphism);
      if (sentinel_or_target == FunctionTypeFeedback::kCallRef) {
        for (int j = 0; j < checked_polymorphic_length; j += 2) {
          Tagged<WasmFuncRef> target = Cast<WasmFuncRef>(polymorphic->get(j));
          int count = Smi::ToInt(polymorphic->get(j + 1));
          fm.AddCallRefCandidate(target, count);
        }
      } else {
        DCHECK_EQ(sentinel_or_target, FunctionTypeFeedback::kCallIndirect);
        for (int j = 0; j < checked_polymorphic_length; j += 2) {
          Tagged<Object> target = polymorphic->get(j);
          int count = Smi::ToInt(polymorphic->get(j + 1));
          fm.AddCallIndirectCandidate(target, count);
        }
      }
    } else if (first_slot == ReadOnlyRoots{isolate_}.megamorphic_symbol()) {
      DCHECK(IsUndefined(second_slot));
      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%d: megamorphic]\n", func_index, i / 2);
      }
    } else {
      UNREACHABLE();
    }

    if (v8_flags.wasm_deopt &&
        first_slot != ReadOnlyRoots{isolate_}.megamorphic_symbol()) {
      // If we already had feedback for this call, also add the already existing
      // feedback to prevent deopt loops where two different instantiations
      // (which have their own on-heap feedback vector) to "flip-flop" between
      // their inlining decisions potentially causing deopt loops.
      const std::vector<CallSiteFeedback>& existing =
          feedback_for_function_[func_index].feedback_vector;
      size_t feedback_index = i / 2;
      if (feedback_index < existing.size()) {
        const CallSiteFeedback& old_feedback = existing[feedback_index];
        if (old_feedback.has_non_inlineable_targets()) {
          fm.set_has_non_inlineable_targets();
        }
        for (int i = 0; i < old_feedback.num_cases(); ++i) {
          int old_target_function_index = old_feedback.function_index(i);
          // If the new feedback already contains the target, we do not touch
          // the call count.
          if (!fm.HasTargetCached(old_target_function_index)) {
            fm.AddCall(old_target_function_index, old_feedback.call_count(i));
            // There shouldn't be any imported functions in there as they can't
            // be inlined. If this DCHECK is invalidated,
            // has_non_inlineable_targets_ would need to be updated here to
            // reflect that.
            DCHECK_GE(static_cast<uint32_t>(old_target_function_index),
                      instance_data_->module()->num_imported_functions);
          }
        }
      }
    }

    fm.FinalizeCall();
  }
  std::vector<CallSiteFeedback> result = std::move(fm).GetResult();
  EnqueueCallees(result);
  feedback_for_function_[func_index].feedback_vector = std::move(result);
}

void TriggerTierUp(Isolate* isolate,
                   Tagged<WasmTrustedInstanceData> trusted_instance_data,
                   int func_index) {
  NativeModule* native_module = trusted_instance_data->native_module();
  CompilationStateImpl* compilation_state =
      Impl(native_module->compilation_state());
  WasmCompilationUnit tiering_unit{func_index, ExecutionTier::kTurbofan,
                                   kNotForDebugging};

  const WasmModule* module = native_module->module();
  int priority;
  {
    base::SharedMutexGuard<base::kExclusive> mutex_guard(
        &module->type_feedback.mutex);
    int array_index = wasm::declared_function_index(module, func_index);
    trusted_instance_data->tiering_budget_array()[array_index].store(
        v8_flags.wasm_tiering_budget, std::memory_order_relaxed);
    int& stored_priority =
        module->type_feedback.feedback_for_function[func_index].tierup_priority;
    if (stored_priority < kMaxInt) ++stored_priority;
    priority = stored_priority;
  }
  // Only create a compilation unit if this is the first time we detect this
  // function as hot (priority == 1), or if the priority increased
  // significantly. The latter is assumed to be the case if the priority
  // increased at least to four, and is a power of two.
  if (priority == 2 || !base::bits::IsPowerOfTwo(priority)) return;
```