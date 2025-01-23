Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Understanding of the Request:**

The request asks for the functionalities of the `ArrayBufferSweeper` class based on the provided C++ source code. It also specifies conditions for identifying Torque code, relating it to JavaScript, providing JavaScript examples, explaining code logic with inputs and outputs, and highlighting common programming errors.

**2. Code Structure and Core Components:**

The first step is to identify the main class and its key member variables and methods. Scanning the code, `ArrayBufferSweeper` is clearly the central class. I also notice `ArrayBufferList` and the nested `SweepingState` and `SweepingJob` classes. This suggests a state machine or a worker pattern for the sweeping process.

**3. Deconstructing `ArrayBufferSweeper` Functionalities:**

I'll go through the public methods of `ArrayBufferSweeper` and deduce their purpose:

* **Constructor/Destructor:**  `ArrayBufferSweeper(Heap* heap)` takes a `Heap` pointer, indicating its dependency on the V8 heap. The destructor `~ArrayBufferSweeper()` calls `EnsureFinished()` and `ReleaseAll()`, suggesting cleanup operations.

* **`EnsureFinished()`/`Finish()`/`FinishIfDone()`:** These methods deal with the completion of a sweeping process. The names imply synchronization and finalization.

* **`RequestSweep()`/`Prepare()`/`Finalize()`:** This trio suggests a lifecycle for initiating and managing a sweep operation. `RequestSweep()` seems to trigger it, `Prepare()` sets up the state, and `Finalize()` concludes it. The `SweepingType` enum hints at different kinds of sweeps.

* **`Append()`:** This adds an `ArrayBufferExtension` to the sweeper's management, likely associated with a `JSArrayBuffer`. The code checks for young/old generation, suggesting different lists for different generations.

* **`Resize()`:** This modifies the size accounted for an `ArrayBufferExtension`, adjusting memory usage.

* **`Detach()`:** This removes an `ArrayBufferExtension` from active management, likely when the underlying ArrayBuffer is detached.

* **`IncrementExternalMemoryCounters()`/`DecrementExternalMemoryCounters()`:** These methods clearly manage external memory accounting, a crucial part of V8's memory management.

* **`ReleaseAll()`:** This appears to free all `ArrayBufferExtension`s in a given list.

**4. Analyzing Nested Classes:**

* **`ArrayBufferList`:** This class appears to be a linked list specifically for `ArrayBufferExtension` objects. It manages a head, tail, and byte count. The `Append()` methods add extensions, and there are methods for checking emptiness and calculating byte sizes.

* **`SweepingState`:** This class encapsulates the state of an ongoing sweep. It holds the young and old lists being swept, the type of sweep, and uses a `JobHandle` for background sweeping. The `MergeTo()` method suggests combining the results of a sweep.

* **`SweepingJob`:** This is a `JobTask`, confirming that sweeping can happen in the background. It takes a `SweepingState`, the young and old lists to sweep, and the sweep type. The `Run()` method is the entry point for the background task, and `SweepYoung()` and `SweepFull()` are the core sweeping logic.

**5. Identifying Core Functionalities (Summarization):**

Based on the above analysis, I can now list the core functionalities:

* Tracking ArrayBuffers
* Sweeping (Garbage Collection) of ArrayBuffer's backing stores
* Different Sweeping Types (Young and Full)
* Concurrent Sweeping (using background jobs)
* Memory Accounting (tracking external memory usage)
* Handling ArrayBuffer Resizing and Detachment

**6. Checking for Torque:**

The request specifically asks about `.tq` files. The provided code is `.cc`, so it's C++. I can state that it's not Torque.

**7. Relating to JavaScript:**

JavaScript's `ArrayBuffer` and `SharedArrayBuffer` directly correspond to the functionality being managed here. I can provide JavaScript examples of creating, resizing, and detaching `ArrayBuffer`s to illustrate the connection.

**8. Code Logic Inference (with Input/Output):**

I'll focus on a simple but illustrative method, like `ArrayBufferList::Append()`. I need to consider different scenarios (empty list, non-empty list) and how the `head_`, `tail_`, and `bytes_` are updated.

**9. Common Programming Errors:**

I'll think about potential issues related to manual memory management, concurrency, and incorrect usage of `ArrayBuffer` in JavaScript that might relate to the sweeper's work.

**10. Refinement and Organization:**

Finally, I'll organize my findings clearly, addressing each point in the request. I'll use headings and bullet points for better readability and ensure accurate and concise explanations. I'll double-check for any inconsistencies or missing information. For instance, the role of `ArrayBufferExtension` becomes clearer when understanding it as a wrapper around the actual backing store, containing metadata for the sweeper.

This structured approach helps in systematically analyzing the code and extracting the required information, ensuring all aspects of the request are addressed. It involves understanding the overall architecture, dissecting individual components, and then piecing together the functionalities and their connection to the broader V8 ecosystem and JavaScript.
`v8/src/heap/array-buffer-sweeper.cc` 是 V8 引擎中负责管理和清理 ArrayBuffer 及其关联的外部内存的组件。它的主要功能是作为垃圾回收过程的一部分，识别不再被引用的 ArrayBuffer，并释放它们占用的外部内存。

**功能列表:**

1. **追踪 ArrayBuffer:**  维护着一个或两个列表 (`young_` 和 `old_`)，用于记录所有已分配的 ArrayBuffer 的信息。这些信息存储在 `ArrayBufferExtension` 对象中。`young_` 列表通常包含新生代的 ArrayBuffer，而 `old_` 列表包含老生代的 ArrayBuffer。
2. **执行 ArrayBuffer 的清理 (Sweeping):**  在垃圾回收周期中，`ArrayBufferSweeper` 会遍历这些列表，检查哪些 ArrayBuffer 可以被回收。它根据标记阶段的结果来判断 ArrayBuffer 是否仍然被引用。
3. **释放未引用的 ArrayBuffer 的外部内存:** 对于未被标记的 ArrayBuffer，`ArrayBufferSweeper` 会释放它们持有的外部内存。
4. **管理外部内存计数器:**  `ArrayBufferSweeper` 负责更新 V8 引擎中跟踪外部内存使用情况的计数器，以反映 ArrayBuffer 的分配和释放。
5. **支持并发清理:**  `ArrayBufferSweeper` 可以利用后台线程并发地执行清理操作，以减少主线程的暂停时间。
6. **处理 ArrayBuffer 的调整大小和分离:** 当 ArrayBuffer 的大小发生改变或被分离时，`ArrayBufferSweeper` 会更新其跟踪的信息和外部内存计数器。
7. **区分新生代和老生代 ArrayBuffer 的清理:**  `ArrayBufferSweeper` 可以分别对新生代和老生代的 ArrayBuffer 进行清理，这与 V8 的分代垃圾回收策略相符。

**关于是否是 Torque 源代码:**

根据您提供的信息，`v8/src/heap/array-buffer-sweeper.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 Javascript 的功能关系及示例:**

`ArrayBufferSweeper` 的核心功能是管理 JavaScript 中 `ArrayBuffer` 和 `SharedArrayBuffer` 对象所占用的外部内存。这些 JavaScript 对象允许开发者在 JavaScript 中直接操作原始的二进制数据。

**JavaScript 示例:**

```javascript
// 创建一个 ArrayBuffer
const buffer = new ArrayBuffer(16); // 分配 16 字节的外部内存

// 创建一个类型化数组视图，用于操作 ArrayBuffer 的内容
const view = new Uint8Array(buffer);
view[0] = 1;
view[1] = 2;

// ... 一段时间后，如果 buffer 不再被引用 ...

// 在垃圾回收发生时，ArrayBufferSweeper 会检测到 buffer 不再可达，
// 并释放其占用的 16 字节外部内存。

// 显式将 buffer 设置为 null，使其更容易被垃圾回收
// (这只是一个例子，在实际应用中，通常是由于作用域改变或对象属性被覆盖等原因导致不可达)
// buffer = null;

// 对于 SharedArrayBuffer，即使在多个 Agent 之间共享，
// 只要没有 Agent 持有它的引用，也会被垃圾回收。
const sharedBuffer = new SharedArrayBuffer(32);
```

在这个例子中，`new ArrayBuffer(16)` 在 V8 的堆外分配了 16 字节的内存。`ArrayBufferSweeper` 就负责跟踪这块内存。当 JavaScript 代码中不再有任何对象引用这个 `buffer` 时，垃圾回收器会标记这块内存为可回收，然后 `ArrayBufferSweeper` 负责真正释放这 16 字节的外部内存。

**代码逻辑推理 (假设输入与输出):**

假设在垃圾回收的标记阶段完成后，`ArrayBufferSweeper` 的 `young_` 列表中有以下 `ArrayBufferExtension` 对象（简化表示，只关注是否被标记和占用的字节数）：

**输入:**

`young_` 列表包含以下 `ArrayBufferExtension`:

* `extension1`: 已标记 (IsYoungMarked() 为 true), accounting_length() 为 1024 字节
* `extension2`: 未标记 (IsYoungMarked() 为 false), accounting_length() 为 512 字节
* `extension3`: 已标记 (IsYoungMarked() 为 true), accounting_length() 为 2048 字节

**执行 `SweepYoung` 后的输出:**

* `extension2` 对应的 ArrayBuffer 的外部内存会被释放。
* `extension2` 会被删除。
* `extension1` 和 `extension3` 会被移动到 `new_old_` 或 `new_young_` 列表中，并且它们的 young 标记会被移除 (YoungUnmark())。具体移动到哪个列表取决于是否被晋升 (IsYoungPromoted())，以及 `treat_all_young_as_promoted_` 的设置。
* 全局的外部内存计数器会减少 512 字节。
* `young_.head_` 指向下一个需要被处理的 extension (如果清理过程被中断)。

**用户常见的编程错误:**

1. **内存泄漏 (Indirectly Related):**  虽然 `ArrayBufferSweeper` 负责回收未引用的 ArrayBuffer，但如果用户在 JavaScript 中意外地保持了对 `ArrayBuffer` 或其 `TypedArray` 视图的引用，那么相关的外部内存就不会被释放，导致内存占用持续增加。

   ```javascript
   let leakyBuffer;
   function createLeakyBuffer() {
     leakyBuffer = new ArrayBuffer(1024 * 1024); // 1MB
     return new Uint8Array(leakyBuffer);
   }

   createLeakyBuffer();
   // 即使 createLeakyBuffer 函数执行完毕，
   // 全局变量 leakyBuffer 仍然持有 ArrayBuffer 的引用，
   // 因此其占用的 1MB 内存不会被 ArrayBufferSweeper 回收。
   ```

2. **过早分离 ArrayBuffer 导致访问错误:**  如果在还有活跃的 `TypedArray` 视图指向 `ArrayBuffer` 时就分离了 `ArrayBuffer`，后续对这些视图的访问会导致错误。虽然这不直接是 `ArrayBufferSweeper` 的问题，但理解 `ArrayBuffer` 的生命周期对于避免此类错误至关重要。

   ```javascript
   const buffer = new ArrayBuffer(10);
   const view = new Uint8Array(buffer);
   // ... 使用 view ...

   // 错误：过早分离 buffer
   // buffer.transfer(); // 假设有这样的操作或者其他方式分离

   // 后续访问 view 会导致错误
   // view[0] = 1; // 可能会抛出异常
   ```

3. **不理解 `SharedArrayBuffer` 的共享性导致的并发问题:**  对于 `SharedArrayBuffer`，多个 Agent (例如，Web Workers) 可以同时访问和修改其内容。如果开发者没有正确地使用同步机制 (例如，Atomics)，可能会导致数据竞争和不可预测的结果。这虽然不是 `ArrayBufferSweeper` 直接管理的问题，但与 `SharedArrayBuffer` 的使用息息相关。

总而言之，`v8/src/heap/array-buffer-sweeper.cc` 是 V8 引擎中一个关键的内存管理组件，它专注于清理 JavaScript 中 `ArrayBuffer` 和 `SharedArrayBuffer` 对象所占用的外部内存，确保 V8 引擎能够有效地管理内存资源。

### 提示词
```
这是目录为v8/src/heap/array-buffer-sweeper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/array-buffer-sweeper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/array-buffer-sweeper.h"

#include <atomic>
#include <memory>
#include <utility>

#include "array-buffer-sweeper.h"
#include "src/base/logging.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap.h"
#include "src/objects/js-array-buffer.h"

namespace v8 {
namespace internal {

size_t ArrayBufferList::Append(ArrayBufferExtension* extension) {
  if (head_ == nullptr) {
    DCHECK_NULL(tail_);
    head_ = tail_ = extension;
  } else {
    tail_->set_next(extension);
    tail_ = extension;
  }

  const size_t accounting_length = [&] {
    if (age_ == ArrayBufferExtension::Age::kOld) {
      return extension->SetOld().accounting_length();
    } else {
      return extension->SetYoung().accounting_length();
    }
  }();
  DCHECK_GE(bytes_ + accounting_length, bytes_);
  bytes_ += accounting_length;
  extension->set_next(nullptr);
  return accounting_length;
}

void ArrayBufferList::Append(ArrayBufferList& list) {
  DCHECK_EQ(age_, list.age_);

  if (head_ == nullptr) {
    DCHECK_NULL(tail_);
    head_ = list.head_;
    tail_ = list.tail_;
  } else if (list.head_) {
    DCHECK_NOT_NULL(list.tail_);
    tail_->set_next(list.head_);
    tail_ = list.tail_;
  } else {
    DCHECK_NULL(list.tail_);
  }

  bytes_ += list.ApproximateBytes();
  list = ArrayBufferList(age_);
}

bool ArrayBufferList::ContainsSlow(ArrayBufferExtension* extension) const {
  for (ArrayBufferExtension* current = head_; current;
       current = current->next()) {
    if (current == extension) return true;
  }
  return false;
}

size_t ArrayBufferList::BytesSlow() const {
  ArrayBufferExtension* current = head_;
  size_t sum = 0;
  while (current) {
    sum += current->accounting_length();
    current = current->next();
  }
  DCHECK_GE(sum, ApproximateBytes());
  return sum;
}

bool ArrayBufferList::IsEmpty() const {
  DCHECK_IMPLIES(head_, tail_);
  DCHECK_IMPLIES(!head_, bytes_ == 0);
  return head_ == nullptr;
}

class ArrayBufferSweeper::SweepingState final {
  enum class Status { kInProgress, kDone };

 public:
  SweepingState(Heap* heap, ArrayBufferList young, ArrayBufferList old,
                SweepingType type,
                TreatAllYoungAsPromoted treat_all_young_as_promoted,
                uint64_t trace_id);

  ~SweepingState() { DCHECK(job_handle_ && !job_handle_->IsValid()); }

  void SetDone() { status_.store(Status::kDone, std::memory_order_relaxed); }
  bool IsDone() const {
    return status_.load(std::memory_order_relaxed) == Status::kDone;
  }

  void MergeTo(ArrayBufferSweeper* sweeper) {
    // the worker may see a difference between `young/old_bytes_accounted_` and
    // `initial_young/old_bytes_` due to concurrent main thread adjustments
    // (resizing).
    sweeper->young_bytes_adjustment_while_sweeping_ +=
        initial_young_bytes_ - young_bytes_accounted_;
    sweeper->old_bytes_adjustment_while_sweeping_ +=
        initial_old_bytes_ - old_bytes_accounted_;
    DCHECK_GE(new_young_.bytes_ +
                  sweeper->young_bytes_adjustment_while_sweeping_ +
                  sweeper->young_.bytes_,
              0);
    DCHECK_GE(new_old_.bytes_ + sweeper->old_bytes_adjustment_while_sweeping_ +
                  sweeper->old_.bytes_,
              0);
    sweeper->young_.Append(new_young_);
    sweeper->old_.Append(new_old_);
    // Apply pending adjustments from resizing and detaching.
    sweeper->young_.bytes_ +=
        std::exchange(sweeper->young_bytes_adjustment_while_sweeping_, 0);
    sweeper->old_.bytes_ +=
        std::exchange(sweeper->old_bytes_adjustment_while_sweeping_, 0);
    sweeper->DecrementExternalMemoryCounters(freed_bytes_);
  }

  void StartBackgroundSweeping() { job_handle_->NotifyConcurrencyIncrease(); }
  void FinishSweeping() {
    DCHECK(job_handle_ && job_handle_->IsValid());
    job_handle_->Join();
  }

 private:
  class SweepingJob;

  std::atomic<Status> status_{Status::kInProgress};
  ArrayBufferList new_young_{ArrayBufferList::Age::kYoung};
  ArrayBufferList new_old_{ArrayBufferList::Age::kOld};
  size_t freed_bytes_{0};
  const uint64_t initial_young_bytes_{0};
  const uint64_t initial_old_bytes_{0};
  // Track bytes accounted bytes during sweeping, including freed and promoted
  // bytes. This is used to compute adjustment when sweeping finishes.
  uint64_t young_bytes_accounted_{0};
  uint64_t old_bytes_accounted_{0};
  std::unique_ptr<JobHandle> job_handle_;
};

class ArrayBufferSweeper::SweepingState::SweepingJob final : public JobTask {
 public:
  SweepingJob(Heap* heap, SweepingState& state, ArrayBufferList young,
              ArrayBufferList old, SweepingType type,
              TreatAllYoungAsPromoted treat_all_young_as_promoted,
              uint64_t trace_id)
      : heap_(heap),
        state_(state),
        young_(young),
        old_(old),
        type_(type),
        treat_all_young_as_promoted_(treat_all_young_as_promoted),
        trace_id_(trace_id),
        local_sweeper_(heap_->sweeper()) {}

  ~SweepingJob() override = default;

  SweepingJob(const SweepingJob&) = delete;
  SweepingJob& operator=(const SweepingJob&) = delete;

  void Run(JobDelegate* delegate) final;

  size_t GetMaxConcurrency(size_t worker_count) const override {
    return state_.IsDone() ? 0 : 1;
  }

 private:
  void Sweep(JobDelegate* delegate);
  // Returns true if sweeping finished. Returns false if sweeping yielded while
  // there are still array buffers left to sweep.
  bool SweepYoung(JobDelegate* delegate);
  bool SweepFull(JobDelegate* delegate);
  bool SweepListFull(JobDelegate* delegate, ArrayBufferList& list,
                     ArrayBufferExtension::Age age);

  Heap* const heap_;
  SweepingState& state_;
  ArrayBufferList young_{ArrayBufferList::Age::kYoung};
  ArrayBufferList old_{ArrayBufferList::Age::kOld};
  const SweepingType type_;
  const TreatAllYoungAsPromoted treat_all_young_as_promoted_;
  const uint64_t trace_id_;
  Sweeper::LocalSweeper local_sweeper_;
};

void ArrayBufferSweeper::SweepingState::SweepingJob::Run(
    JobDelegate* delegate) {
  const ThreadKind thread_kind =
      delegate->IsJoiningThread() ? ThreadKind::kMain : ThreadKind::kBackground;
  if (treat_all_young_as_promoted_ == TreatAllYoungAsPromoted::kNo) {
    // Waiting for promoted page iteration is only needed when not all young
    // array buffers are promoted.
    GCTracer::Scope::ScopeId scope_id =
        type_ == SweepingType::kYoung
            ? thread_kind == ThreadKind::kMain
                  ? GCTracer::Scope::MINOR_MS_SWEEP
                  : GCTracer::Scope::MINOR_MS_BACKGROUND_SWEEPING
        : thread_kind == ThreadKind::kMain
            ? GCTracer::Scope::MC_SWEEP
            : GCTracer::Scope::MC_BACKGROUND_SWEEPING;
    TRACE_GC_EPOCH_WITH_FLOW(
        heap_->tracer(), scope_id, thread_kind,
        heap_->sweeper()->GetTraceIdForFlowEvent(scope_id),
        TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
    const bool finished =
        local_sweeper_.ContributeAndWaitForPromotedPagesIteration(delegate);
    DCHECK_IMPLIES(delegate->IsJoiningThread(), finished);
    if (!finished) return;
    DCHECK(!heap_->sweeper()->IsIteratingPromotedPages());
  }
  GCTracer::Scope::ScopeId scope_id =
      type_ == SweepingType::kYoung
          ? thread_kind == ThreadKind::kMain
                ? GCTracer::Scope::YOUNG_ARRAY_BUFFER_SWEEP
                : GCTracer::Scope::BACKGROUND_YOUNG_ARRAY_BUFFER_SWEEP
      : thread_kind == ThreadKind::kMain
          ? GCTracer::Scope::FULL_ARRAY_BUFFER_SWEEP
          : GCTracer::Scope::BACKGROUND_FULL_ARRAY_BUFFER_SWEEP;
  TRACE_GC_EPOCH_WITH_FLOW(heap_->tracer(), scope_id, thread_kind, trace_id_,
                           TRACE_EVENT_FLAG_FLOW_IN);
  Sweep(delegate);
}

ArrayBufferSweeper::SweepingState::SweepingState(
    Heap* heap, ArrayBufferList young, ArrayBufferList old,
    ArrayBufferSweeper::SweepingType type,
    ArrayBufferSweeper::TreatAllYoungAsPromoted treat_all_young_as_promoted,
    uint64_t trace_id)
    : initial_young_bytes_(young.bytes_),
      initial_old_bytes_(old.bytes_),
      job_handle_(V8::GetCurrentPlatform()->CreateJob(
          TaskPriority::kUserVisible,
          std::make_unique<SweepingJob>(
              heap, *this, std::move(young), std::move(old), type,
              treat_all_young_as_promoted, trace_id))) {}

ArrayBufferSweeper::ArrayBufferSweeper(Heap* heap) : heap_(heap) {}

ArrayBufferSweeper::~ArrayBufferSweeper() {
  EnsureFinished();
  ReleaseAll(&old_);
  ReleaseAll(&young_);
}

void ArrayBufferSweeper::EnsureFinished() {
  if (!sweeping_in_progress()) return;

  Finish();
}

void ArrayBufferSweeper::Finish() {
  state_->FinishSweeping();

  Finalize();
  DCHECK_LE(heap_->backing_store_bytes(), SIZE_MAX);
  DCHECK(!sweeping_in_progress());
}

void ArrayBufferSweeper::FinishIfDone() {
  if (sweeping_in_progress()) {
    DCHECK(state_);
    if (state_->IsDone()) {
      Finish();
    }
  }
}

void ArrayBufferSweeper::RequestSweep(
    SweepingType type, TreatAllYoungAsPromoted treat_all_young_as_promoted) {
  DCHECK(!sweeping_in_progress());

  if (young_.IsEmpty() && (old_.IsEmpty() || type == SweepingType::kYoung))
    return;

  GCTracer::Scope::ScopeId scope_id =
      type == SweepingType::kYoung
          ? v8_flags.minor_ms
                ? GCTracer::Scope::MINOR_MS_FINISH_SWEEP_ARRAY_BUFFERS
                : GCTracer::Scope::SCAVENGER_SWEEP_ARRAY_BUFFERS
          : GCTracer::Scope::MC_FINISH_SWEEP_ARRAY_BUFFERS;
  auto trace_id = GetTraceIdForFlowEvent(scope_id);
  TRACE_GC_WITH_FLOW(heap_->tracer(), scope_id, trace_id,
                     TRACE_EVENT_FLAG_FLOW_OUT);
  Prepare(type, treat_all_young_as_promoted, trace_id);
  DCHECK_IMPLIES(v8_flags.minor_ms && type == SweepingType::kYoung,
                 !heap_->ShouldReduceMemory());
  if (!heap_->IsTearingDown() && !heap_->ShouldReduceMemory() &&
      v8_flags.concurrent_array_buffer_sweeping &&
      heap_->ShouldUseBackgroundThreads()) {
    state_->StartBackgroundSweeping();
  } else {
    Finish();
  }
}

void ArrayBufferSweeper::Prepare(
    SweepingType type, TreatAllYoungAsPromoted treat_all_young_as_promoted,
    uint64_t trace_id) {
  DCHECK(!sweeping_in_progress());
  DCHECK_IMPLIES(type == SweepingType::kFull,
                 treat_all_young_as_promoted == TreatAllYoungAsPromoted::kYes);
  switch (type) {
    case SweepingType::kYoung: {
      state_ = std::make_unique<SweepingState>(
          heap_, std::move(young_), ArrayBufferList(ArrayBufferList::Age::kOld),
          type, treat_all_young_as_promoted, trace_id);
      young_ = ArrayBufferList(ArrayBufferList::Age::kYoung);
    } break;
    case SweepingType::kFull: {
      state_ = std::make_unique<SweepingState>(
          heap_, std::move(young_), std::move(old_), type,
          treat_all_young_as_promoted, trace_id);
      young_ = ArrayBufferList(ArrayBufferList::Age::kYoung);
      old_ = ArrayBufferList(ArrayBufferList::Age::kOld);
    } break;
  }
  DCHECK(sweeping_in_progress());
}

void ArrayBufferSweeper::Finalize() {
  DCHECK(sweeping_in_progress());
  CHECK(state_->IsDone());
  state_->MergeTo(this);
  state_.reset();
  DCHECK(!sweeping_in_progress());
}

void ArrayBufferSweeper::ReleaseAll(ArrayBufferList* list) {
  ArrayBufferExtension* current = list->head_;
  while (current) {
    ArrayBufferExtension* next = current->next();
    const size_t bytes = current->ClearAccountingLength().accounting_length();
    DecrementExternalMemoryCounters(bytes);
    FinalizeAndDelete(current);
    current = next;
  }
  *list = ArrayBufferList(list->age_);
}

void ArrayBufferSweeper::Append(Tagged<JSArrayBuffer> object,
                                ArrayBufferExtension* extension) {
  size_t bytes = extension->accounting_length();

  FinishIfDone();

  // `Heap::InYoungGeneration` during full GC with sticky markbits is generally
  // inaccurate. However, a full GC will sweep both lists and promote all to
  // old, so it doesn't matter which list initially holds the extension.
  if (HeapLayout::InYoungGeneration(object)) {
    young_.Append(extension);
  } else {
    old_.Append(extension);
  }

  IncrementExternalMemoryCounters(bytes);
}

void ArrayBufferSweeper::Resize(ArrayBufferExtension* extension,
                                int64_t delta) {
  FinishIfDone();

  ArrayBufferExtension::AccountingState previous_value =
      extension->UpdateAccountingLength(delta);

  UpdateApproximateBytes(delta, previous_value.age());
  if (delta > 0) {
    IncrementExternalMemoryCounters(delta);
  } else {
    DecrementExternalMemoryCounters(-delta);
  }
}

void ArrayBufferSweeper::Detach(ArrayBufferExtension* extension) {
  // Finish sweeping here first such that the code below is guaranteed to
  // observe the same sweeping state.
  FinishIfDone();

  ArrayBufferExtension::AccountingState previous_value =
      extension->ClearAccountingLength();

  // We cannot free the extension eagerly here, since extensions are tracked in
  // a singly linked list. The next GC will remove it automatically.

  UpdateApproximateBytes(-previous_value.accounting_length(),
                         previous_value.age());
  DecrementExternalMemoryCounters(previous_value.accounting_length());
}

void ArrayBufferSweeper::UpdateApproximateBytes(int64_t delta,
                                                ArrayBufferExtension::Age age) {
  switch (age) {
    case ArrayBufferExtension::Age::kYoung:
      if (!sweeping_in_progress()) {
        DCHECK_GE(young_.bytes_, -delta);
        young_.bytes_ += delta;
      } else {
        young_bytes_adjustment_while_sweeping_ += delta;
      }
      break;
    case ArrayBufferExtension::Age::kOld:
      if (!sweeping_in_progress()) {
        DCHECK_GE(old_.bytes_, -delta);
        old_.bytes_ += delta;
      } else {
        old_bytes_adjustment_while_sweeping_ += delta;
      }
  }
}

void ArrayBufferSweeper::IncrementExternalMemoryCounters(size_t bytes) {
  if (bytes == 0) return;
  heap_->IncrementExternalBackingStoreBytes(
      ExternalBackingStoreType::kArrayBuffer, bytes);
  external_memory_accounter_.Increase(heap_->isolate(), bytes);
}

void ArrayBufferSweeper::DecrementExternalMemoryCounters(size_t bytes) {
  if (bytes == 0) return;
  heap_->DecrementExternalBackingStoreBytes(
      ExternalBackingStoreType::kArrayBuffer, bytes);
  external_memory_accounter_.Decrease(heap_->isolate(), bytes);
}

void ArrayBufferSweeper::FinalizeAndDelete(ArrayBufferExtension* extension) {
#ifdef V8_COMPRESS_POINTERS
  extension->ZapExternalPointerTableEntry();
#endif  // V8_COMPRESS_POINTERS
  delete extension;
}

void ArrayBufferSweeper::SweepingState::SweepingJob::Sweep(
    JobDelegate* delegate) {
  CHECK(!state_.IsDone());
  bool is_finished;
  switch (type_) {
    case SweepingType::kYoung:
      is_finished = SweepYoung(delegate);
      break;
    case SweepingType::kFull:
      is_finished = SweepFull(delegate);
      break;
  }
  if (is_finished) {
    state_.SetDone();
  } else {
    TRACE_GC_NOTE("ArrayBufferSweeper Preempted");
  }
}

bool ArrayBufferSweeper::SweepingState::SweepingJob::SweepFull(
    JobDelegate* delegate) {
  DCHECK_EQ(SweepingType::kFull, type_);
  if (!SweepListFull(delegate, young_, ArrayBufferExtension::Age::kYoung))
    return false;
  return SweepListFull(delegate, old_, ArrayBufferExtension::Age::kOld);
}

bool ArrayBufferSweeper::SweepingState::SweepingJob::SweepListFull(
    JobDelegate* delegate, ArrayBufferList& list,
    ArrayBufferExtension::Age age) {
  static constexpr size_t kYieldCheckInterval = 256;
  static_assert(base::bits::IsPowerOfTwo(kYieldCheckInterval),
                "kYieldCheckInterval must be power of 2");

  ArrayBufferExtension* current = list.head_;

  ArrayBufferList& new_old = state_.new_old_;
  size_t freed_bytes = 0;
  size_t accounted_bytes = 0;
  size_t swept_extensions = 0;

  while (current) {
    DCHECK_EQ(list.age_, current->age());
    if ((swept_extensions++ & (kYieldCheckInterval - 1)) == 0) {
      if (delegate->ShouldYield()) break;
    }
    ArrayBufferExtension* next = current->next();

    if (!current->IsMarked()) {
      freed_bytes += current->accounting_length();
      FinalizeAndDelete(current);
    } else {
      current->Unmark();
      accounted_bytes += new_old.Append(current);
    }

    current = next;
  }

  state_.freed_bytes_ += freed_bytes;
  if (age == ArrayBufferExtension::Age::kYoung) {
    state_.young_bytes_accounted_ += (freed_bytes + accounted_bytes);
  } else {
    state_.old_bytes_accounted_ += (freed_bytes + accounted_bytes);
  }

  list.head_ = current;
  return !current;
}

bool ArrayBufferSweeper::SweepingState::SweepingJob::SweepYoung(
    JobDelegate* delegate) {
  static constexpr size_t kYieldCheckInterval = 256;
  static_assert(base::bits::IsPowerOfTwo(kYieldCheckInterval),
                "kYieldCheckInterval must be power of 2");

  DCHECK_EQ(SweepingType::kYoung, type_);
  ArrayBufferExtension* current = young_.head_;

  ArrayBufferList& new_old = state_.new_old_;
  ArrayBufferList& new_young = state_.new_young_;
  size_t freed_bytes = 0;
  size_t accounted_bytes = 0;
  size_t swept_extensions = 0;

  while (current) {
    DCHECK_EQ(ArrayBufferExtension::Age::kYoung, current->age());
    if ((swept_extensions++ & (kYieldCheckInterval - 1)) == 0) {
      if (delegate->ShouldYield()) break;
    }
    ArrayBufferExtension* next = current->next();

    if (!current->IsYoungMarked()) {
      const size_t bytes = current->accounting_length();
      FinalizeAndDelete(current);
      if (bytes) freed_bytes += bytes;
    } else {
      if ((treat_all_young_as_promoted_ == TreatAllYoungAsPromoted::kYes) ||
          current->IsYoungPromoted()) {
        current->YoungUnmark();
        accounted_bytes += new_old.Append(current);
      } else {
        current->YoungUnmark();
        accounted_bytes += new_young.Append(current);
      }
    }

    current = next;
  }

  state_.freed_bytes_ += freed_bytes;
  // Update young/old_bytes_accounted_; the worker may see a difference between
  // this and `initial_young/old_bytes_` due to concurrent main thread
  // adjustments.
  state_.young_bytes_accounted_ += (freed_bytes + accounted_bytes);

  young_.head_ = current;
  return !current;
}

uint64_t ArrayBufferSweeper::GetTraceIdForFlowEvent(
    GCTracer::Scope::ScopeId scope_id) const {
  return reinterpret_cast<uint64_t>(this) ^
         heap_->tracer()->CurrentEpoch(scope_id);
}

}  // namespace internal
}  // namespace v8
```