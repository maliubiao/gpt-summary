Response: Let's break down the thought process to analyze the C++ code and generate the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and a JavaScript example if it relates to JavaScript features. The key here is to identify the core purpose and any direct interaction or impact on the JavaScript runtime.

2. **Initial Scan for Keywords:**  Quickly scan the code for relevant keywords:
    * `ArrayBuffer`: This is a strong indicator of interaction with JavaScript's `ArrayBuffer`.
    * `Sweeper`: Suggests a process for cleaning up or managing resources.
    * `Young`, `Old`:  Likely related to generational garbage collection.
    * `Heap`:  Confirms involvement with memory management.
    * `GC`, `GCTracer`:  Explicitly points to garbage collection.
    * `JSArrayBuffer`:  The C++ representation of JavaScript ArrayBuffers.
    * `Detach`, `Resize`:  Operations that can be performed on ArrayBuffers in JavaScript.

3. **Identify the Core Class:** The class `ArrayBufferSweeper` appears central. Focus on its methods and member variables.

4. **Analyze `ArrayBufferSweeper`'s Methods:**
    * `Append(Tagged<JSArrayBuffer>, ArrayBufferExtension*)`:  Likely adds ArrayBuffers to the sweeper's tracking.
    * `Resize(ArrayBufferExtension*, int64_t)`:  Handles resizing of ArrayBuffers.
    * `Detach(ArrayBufferExtension*)`:  Handles detaching of ArrayBuffers.
    * `RequestSweep(SweepingType, TreatAllYoungAsPromoted)`: Initiates the sweeping process.
    * `Finish()`, `EnsureFinished()`, `FinishIfDone()`: Methods related to completing the sweeping process.
    * `ReleaseAll(ArrayBufferList*)`:  Releases resources associated with ArrayBuffers.

5. **Understand `ArrayBufferList`:** This seems to be a container for `ArrayBufferExtension` objects, likely divided into "young" and "old" generations.

6. **Understand `ArrayBufferExtension` (Implicit):** While the full definition isn't provided in this snippet, its usage suggests it holds metadata about an ArrayBuffer, including its size (`accounting_length()`), mark status (`IsMarked()`, `IsYoungMarked()`, `IsYoungPromoted()`), and links to other extensions (`next()`).

7. **Infer the Sweeping Process:**
    * The sweeper maintains two lists of ArrayBuffers: `young_` and `old_`.
    * The sweeping process is triggered by `RequestSweep`.
    * It can be done concurrently in a background thread using a `SweepingJob`.
    * The sweeping process involves marking live ArrayBuffers and releasing those that are no longer reachable (unmarked).
    * There are different sweeping types (`kYoung`, `kFull`), suggesting different scopes of garbage collection.

8. **Connect to JavaScript:** The key connection is through `JSArrayBuffer`. The sweeper manages the underlying memory associated with JavaScript ArrayBuffer objects. Operations like resizing and detaching in JavaScript directly impact the sweeper's state and actions.

9. **Formulate the Summary:**  Based on the above analysis, construct a concise summary highlighting the main function: managing the lifecycle of memory backing JavaScript `ArrayBuffer` objects during garbage collection. Emphasize the "sweeping" analogy, the generational aspect, and the interactions with `resize` and `detach`.

10. **Create the JavaScript Example:**  Think about JavaScript code that directly uses `ArrayBuffer` and the operations the C++ code handles. `ArrayBuffer`, `Uint8Array` (as a view), `slice()`, and setting elements demonstrate creating, using, and potentially resizing the underlying buffer. The `console.log` statements help illustrate the impact on memory management (though this is an abstraction in JavaScript). Crucially, *detaching* an `ArrayBuffer` is a direct, visible operation in JavaScript that this C++ code handles on the backend. This makes it a perfect example.

11. **Refine and Review:** Ensure the summary is clear, accurate, and avoids overly technical jargon. Check that the JavaScript example is correct and effectively illustrates the connection. Make sure the explanation connecting the C++ and JavaScript is logical and easy to understand.

Self-Correction/Refinement During the Process:

* **Initial thought:** Maybe focus too much on the internal details of the `SweepingJob`. **Correction:** Realize the request is about the *overall function* from a higher level, especially its relationship to JavaScript. The internal threading is a detail, not the core function from a JavaScript perspective.
* **Considering the JS example:**  Initially think about just creating an `ArrayBuffer`. **Correction:**  Recognize that `detach()` is a much more direct and demonstrable link to the sweeper's work. Also consider showing resizing, although detaching is more definitive.
* **Wording of the summary:**  Avoid overly technical C++ terms if possible. Use analogies like "sweeping" to make it more accessible. Ensure the connection to garbage collection is clear.

By following these steps, focusing on the key functionalities, and relating them to JavaScript concepts, we can arrive at a comprehensive and understandable explanation.
这个C++源代码文件 `array-buffer-sweeper.cc` 实现了 V8 引擎中 **ArrayBuffer 的垃圾回收和管理功能**。更具体地说，它的主要职责是：

**核心功能:**

1. **追踪和管理 ArrayBuffer 的内存:**  它维护着两个 `ArrayBufferList`，分别用于跟踪年轻代（young generation）和老年代（old generation）的 `ArrayBufferExtension` 对象。 `ArrayBufferExtension` 可以被认为是 C++ 中对 JavaScript `ArrayBuffer` 的一个描述符或管理结构。

2. **执行 ArrayBuffer 的“清扫”（Sweeping）操作:**  这是垃圾回收过程的一部分。清扫器会遍历已分配的 ArrayBuffer，判断哪些是仍然被引用的（"活着"的），哪些是不再被引用的（可以被回收的）。
    * **年轻代清扫 (Young Generation Sweeping):**  在 Minor GC（Scavenger）期间执行，主要处理新分配的 ArrayBuffer。
    * **老年代清扫 (Old Generation Sweeping):** 在 Major GC（Mark-Sweep 或 Mark-Compact）期间执行，处理经过多次 Minor GC 仍然存活的 ArrayBuffer。

3. **释放不再使用的 ArrayBuffer 的内存:**  对于被标记为不再使用的 ArrayBuffer，清扫器会释放其关联的外部内存（backing store）。

4. **处理 ArrayBuffer 的生命周期事件:**
    * **分配 (Append):** 当 JavaScript 中创建新的 `ArrayBuffer` 时，会在 C++ 层创建一个 `ArrayBufferExtension` 并添加到清扫器的列表中。
    * **调整大小 (Resize):** 当 JavaScript 中调整 `ArrayBuffer` 大小时，清扫器会更新相应的 `ArrayBufferExtension` 的信息。
    * **分离 (Detach):** 当 JavaScript 中分离 `ArrayBuffer` 时，清扫器会标记该 `ArrayBuffer`，以便在后续的清扫过程中回收其内存。

5. **支持并发清扫:** 该代码实现了在后台线程中并发执行 ArrayBuffer 清扫的功能，以减少主线程的停顿时间，提高垃圾回收的效率。

**与 JavaScript 的关系和示例:**

`array-buffer-sweeper.cc` 直接负责管理 JavaScript 中 `ArrayBuffer` 对象的底层内存。JavaScript 中的 `ArrayBuffer` 操作最终会调用到 V8 引擎的 C++ 代码来执行。

**JavaScript 示例:**

```javascript
// 创建一个 ArrayBuffer
let buffer = new ArrayBuffer(16);
console.log(buffer.byteLength); // 输出 16

// 创建一个视图来操作 ArrayBuffer
let view = new Uint8Array(buffer);
view[0] = 42;

// 调整 ArrayBuffer 的大小 (需要通过 SharedArrayBuffer 或其他机制，ArrayBuffer 本身不可直接调整大小)
//  例如，创建一个更大的 ArrayBuffer 并复制内容
let largerBuffer = new ArrayBuffer(32);
let largerView = new Uint8Array(largerBuffer);
for (let i = 0; i < buffer.byteLength; i++) {
  largerView[i] = view[i];
}
buffer = largerBuffer;
console.log(buffer.byteLength); // 输出 32

// 分离 ArrayBuffer
buffer = null; // 使得 buffer 可以被垃圾回收

// 或者显式分离 (某些情况下)
// buffer.detach(); // 某些旧版本的实现可能支持，但现在通常不直接暴露
```

**解释:**

* 当 JavaScript 代码创建 `new ArrayBuffer(16)` 时，V8 引擎会在堆上分配 16 字节的内存，并在 C++ 层创建一个 `ArrayBufferExtension` 对象来跟踪这块内存。`ArrayBufferSweeper` 会负责管理这个 `ArrayBufferExtension`。
* 当我们调整 `ArrayBuffer` 的大小（通过创建新的并复制）时，旧的 `ArrayBuffer` 如果不再被引用，最终会被垃圾回收器（包括 `ArrayBufferSweeper`）识别并释放其关联的内存。
* 当我们将 `buffer = null;` 或调用 `buffer.detach()` (如果支持) 时，我们移除了对 `ArrayBuffer` 的引用，使其成为垃圾回收的候选对象。在下一次垃圾回收周期中，`ArrayBufferSweeper` 会识别到这个 `ArrayBuffer` 不再被引用，并释放其占用的内存。

**总结:**

`array-buffer-sweeper.cc` 是 V8 引擎中负责 `ArrayBuffer` 对象内存管理和垃圾回收的关键组件。它与 JavaScript 的 `ArrayBuffer` 功能紧密相关，确保了 JavaScript 代码能够安全有效地使用和释放内存，避免内存泄漏。它在垃圾回收的不同阶段（年轻代和老年代）进行清扫，并处理 `ArrayBuffer` 的分配、调整大小和分离等生命周期事件。

Prompt: 
```
这是目录为v8/src/heap/array-buffer-sweeper.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```