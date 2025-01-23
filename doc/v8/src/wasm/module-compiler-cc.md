Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/module-compiler.cc`. The summary should include:
1. A general description of the code's purpose.
2. Information about whether it's a Torque file (which it isn't, as it doesn't end with `.tq`).
3. If the code relates to JavaScript functionality, a JavaScript example illustrating the connection.
4. Examples of code logic with input and output (if applicable).
5. Common user programming errors related to the code (if applicable).
6. A final summary of its function.

Let's break down the code to identify its key responsibilities.

- **Includes:** The included headers suggest this file deals with WebAssembly module compilation within V8. Keywords like "wasm", "compiler", "module", "codegen", "streaming", "pgo" are strong indicators.
- **Macros (`TRACE_COMPILE`, `TRACE_STREAMING`, `TRACE_LAZY`):** These are likely for debugging and logging during the compilation process, specific to different compilation strategies (eager, lazy).
- **Namespace:** The code is within the `v8::internal::wasm` namespace, confirming its role in V8's WebAssembly implementation.
- **Enums (`CompileStrategy`, `CompilationTier`):** These define different ways and phases of compiling WebAssembly modules, such as lazy vs. eager compilation and baseline vs. top-tier optimization.
- **Classes (`BackgroundCompileScope`, `CompilationUnitQueues`, `CompilationStateImpl`):** These are the core components.
    - `BackgroundCompileScope`: Manages the lifetime of the `NativeModule` during background compilation.
    - `CompilationUnitQueues`:  Manages work queues for compilation units (likely individual functions or parts of them), supporting work stealing for parallel compilation.
    - `CompilationStateImpl`:  Tracks the overall compilation state of a WebAssembly module, including which functions are compiled and managing the compilation tasks.
- **Data Structures within `CompilationUnitQueues`:**  The use of priority queues and mutexes suggests a system designed for managing and scheduling compilation tasks efficiently, including handling large functions and prioritising certain compilations.
- **Data Structures within `CompilationStateImpl`:**  The presence of mutexes, job handles, and callbacks indicates management of concurrent compilation processes and notification of compilation events.
- **`CompilationStateImpl::ApplyCompilationHintToInitialProgress` and `ApplyPgoInfo*`:** These methods suggest the integration of compilation hints and Profile-Guided Optimization (PGO) to influence the compilation process.
- **`CompilationStateImpl::CommitCompilationUnits`:** This is a key function that seems to initiate the compilation process by adding units to the work queues.
- **`CompilationStateImpl::PublishCode`:** This method likely handles making the compiled code available.

Based on this analysis, the primary function of `v8/src/wasm/module-compiler.cc` is to manage the compilation process of WebAssembly modules in V8. This includes handling different compilation strategies, managing work queues for parallel compilation, tracking the compilation state, and integrating with features like PGO.

Now, let's address each point of the user's request systematically.```cpp
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
    
### 提示词
```
这是目录为v8/src/wasm/module-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
         Impl(native_module_->compilation_state())->c
```