Response: Let's break down the thought process for analyzing the `local-heap.cc` file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality and its relationship to JavaScript, illustrated with JavaScript examples.

2. **Identify Key Components (Headers):** The `#include` directives provide initial clues about the file's purpose. Looking at them reveals interactions with:
    * Memory management (`<memory>`)
    * Atomic operations (`<atomic>`)
    * Mutexes (`src/base/platform/mutex.h`)
    * Global settings (`src/common/globals.h`)
    * Isolate (V8's execution context) (`src/execution/isolate.h`)
    * Handles (`src/handles/local-handles.h`, `src/handles/persistent-handles.h`)
    * Garbage Collection (GC) related concepts (`src/heap/*`)

3. **Identify the Core Class:** The file defines the `LocalHeap` class. This is the central entity we need to understand.

4. **Analyze the `LocalHeap` Constructor and Destructor:** These methods often reveal the lifecycle and primary responsibilities of a class.
    * **Constructor:** Takes a `Heap*`, `ThreadKind`, and potentially `PersistentHandles`. This suggests a `LocalHeap` is associated with a larger `Heap` and a specific thread. The initialization of `heap_allocator_`, `marking_barrier_`, and the interaction with `heap_->safepoint()` are important. The setting of `LocalHeap::Current()` also points to thread-local storage.
    * **Destructor:**  Focuses on cleanup, including freeing allocation areas, publishing the marking barrier, and resetting the current `LocalHeap`. The call to `EnsureParkedBeforeDestruction()` suggests the `LocalHeap` needs to be in a specific state before destruction.

5. **Examine Key Member Functions and Group Them by Functionality:**  Go through the public methods of `LocalHeap` and try to categorize them. Initial categories might be:
    * **Thread Management:** `Park`, `Unpark`, `IsParked`, `IsRunning`
    * **Allocation:** Implicitly through `heap_allocator_` (though the methods themselves might be in `heap-allocator.h`).
    * **Handles:** `EnsurePersistentHandles`, `AttachPersistentHandles`, `DetachPersistentHandles`, `ContainsLocalHandle`, `ContainsPersistentHandle`
    * **Garbage Collection:**  Many methods related to marking (`SetUpMarkingBarrier`, `SetUpSharedMarking`, `MarkLinearAllocationAreasBlack`, etc.), and callbacks (`AddGCEpilogueCallback`, `RemoveGCEpilogueCallback`). The interaction with `Safepoint` is crucial.
    * **Internal State Management:**  Methods like `VerifyCurrent`, `SetUpMainThread`, and the various `LinearAllocationArea` methods.

6. **Focus on the "Local" Aspect:** The name "LocalHeap" implies something specific to a thread or a limited scope. The thread-local variable `g_current_local_heap_` confirms this. The distinction between the main thread and other threads is also significant.

7. **Connect to JavaScript (the Tricky Part):**  This requires understanding how V8 works internally.
    * **Memory Management:** JavaScript engines need to allocate memory for objects. `LocalHeap` is clearly involved in this process, especially on background threads. Think about how objects are created and managed in JavaScript.
    * **Garbage Collection:**  JavaScript has automatic garbage collection. The GC-related methods in `LocalHeap` directly relate to how V8 reclaims memory. Concepts like marking and sweeping are relevant here.
    * **Handles:** JavaScript values are represented by handles in the V8 engine. The `LocalHandles` and `PersistentHandles` within `LocalHeap` are ways to manage these handles. Think about how variables are stored and accessed in JavaScript.
    * **Concurrency:**  JavaScript can use web workers or asynchronous operations. `LocalHeap` manages memory on different threads, so it's crucial for concurrent JavaScript execution.

8. **Formulate JavaScript Examples:** Once the connections to JavaScript concepts are made, create simple examples that illustrate these concepts. Focus on:
    * **Object creation:** Demonstrates memory allocation.
    * **Garbage collection triggers (indirectly):** Shows when objects might become eligible for collection.
    * **Web Workers (concurrency):** Illustrates how different threads (and thus potentially different `LocalHeap` instances) are involved.
    * **Handles (less directly observable from JavaScript):** Explain that while not directly visible, handles are how V8 manages objects behind the scenes.

9. **Structure the Summary:** Organize the findings into a clear and logical structure. Start with a high-level overview, then delve into specific functionalities, and finally, explain the connection to JavaScript with examples.

10. **Review and Refine:**  Read through the summary and examples. Are they accurate and easy to understand?  Are there any ambiguities?  Can the explanations be improved?  For instance, initially, I might not have explicitly linked `PersistentHandles` to long-lived objects or closures, but further reflection would lead to that connection.

**Self-Correction Example during the process:**

* **Initial Thought:** "The file manages memory allocation."
* **Correction:** "While memory allocation is involved, especially through `heap_allocator_`, the `LocalHeap` seems to be more about managing memory *within a specific thread's context* and coordinating with the global `Heap` and the GC."  This leads to emphasizing the "local" aspect and the thread management functions.

By following this iterative process of examining the code, identifying key components, and connecting them to higher-level concepts (especially JavaScript), a comprehensive understanding of the `local-heap.cc` file can be achieved.
这个文件 `v8/src/heap/local-heap.cc` 的主要功能是**管理和维护 V8 引擎中非主线程的堆内存（Local Heap）以及相关的线程状态和操作。**

更具体地说，它负责：

1. **为非主线程提供独立的堆内存区域:**  V8 为了提高并发性能，允许在非主线程上拥有独立的堆内存。这个文件定义的 `LocalHeap` 类就是用来管理这些局部堆的。
2. **管理线程状态 (Parked/Running):**  `LocalHeap` 跟踪管理与它关联的线程的状态，主要有两种状态：
    * **Parked (休眠):** 线程暂时不执行 JavaScript 代码，通常是为了等待 GC 或进入安全点。
    * **Running (运行):** 线程正在执行 JavaScript 代码。
    它提供了 `Park()` 和 `Unpark()` 方法来控制线程的状态转换。
3. **处理安全点 (Safepoint):** 安全点是 GC 能够安全执行的时刻。`LocalHeap` 参与到安全点机制中，允许线程安全地进入和离开安全点。
4. **管理局部句柄 (Local Handles) 和持久句柄 (Persistent Handles):**
    * **Local Handles:**  用于在当前线程的栈上临时持有 JavaScript 对象的引用，生命周期较短。
    * **Persistent Handles:** 用于在 GC 期间仍然保持对象存活的引用，生命周期较长。
    `LocalHeap` 负责创建、附加和分离这些句柄。
5. **线性分配 (Linear Allocation):**  `LocalHeap` 管理着线程本地的线性分配区域，用于快速分配小对象。
6. **与主堆 (Main Heap) 的交互:**  虽然是局部堆，但它仍然需要与主堆进行交互，例如在 GC 过程中需要同步信息。
7. **支持并发标记 (Concurrent Marking):**  `LocalHeap` 包含了 `MarkingBarrier`，用于在并发标记阶段记录对象的变化，以保证 GC 的正确性。
8. **执行 GC 的 Epilogue 回调:**  在垃圾回收的最后阶段，`LocalHeap` 会调用注册的回调函数。

**与 JavaScript 的关系以及 JavaScript 示例：**

`LocalHeap` 的功能直接影响着 JavaScript 的性能和并发能力。虽然 JavaScript 开发者无法直接操作 `LocalHeap` 对象，但其背后的机制是支撑 JavaScript 代码高效运行的关键。

**以下是一些与 `LocalHeap` 功能相关的 JavaScript 概念和示例：**

1. **Web Workers (多线程):**

   ```javascript
   // 主线程
   const worker = new Worker('worker.js');

   // worker.js (在独立的线程中运行)
   onmessage = function(e) {
     // 在 worker 线程中创建的对象会被分配到 worker 线程的 LocalHeap 中
     const obj = { data: e.data };
     postMessage('收到: ' + obj.data);
   }
   ```

   当使用 Web Workers 时，每个 Worker 都有自己的 JavaScript 执行上下文和独立的堆。V8 会为每个 Worker 线程创建一个 `LocalHeap` 实例来管理其内存。在 `worker.js` 中创建的对象 `obj` 就可能被分配到该 Worker 对应的 `LocalHeap` 中。

2. **异步操作和 Promise (线程状态转换):**

   ```javascript
   async function fetchData() {
     console.log('开始获取数据');
     await new Promise(resolve => setTimeout(resolve, 1000)); // 模拟耗时操作
     console.log('数据获取完成');
     return { data: '来自服务器的数据' };
   }

   fetchData();
   ```

   虽然 JavaScript 是单线程的（在主线程上），但异步操作通常会涉及到事件循环和一些后台任务。在某些 V8 的实现中，Promise 的 `then()` 回调可能在不同的微任务阶段执行，而这些微任务可能与主线程的 `LocalHeap` 交互。虽然这个例子不是直接展示 `LocalHeap` 的操作，但它说明了 V8 如何管理主线程的执行状态，这与 `LocalHeap` 管理其他线程状态的概念是类似的。

3. **闭包 (Persistent Handles):**

   ```javascript
   function createCounter() {
     let count = 0;
     return function() {
       count++;
       return count;
     };
   }

   const counter = createCounter();
   console.log(counter()); // 1
   console.log(counter()); // 2
   ```

   在上面的例子中，`createCounter` 函数返回的匿名函数形成了一个闭包，它捕获了 `count` 变量。即使 `createCounter` 函数执行完毕，`count` 变量仍然存在，因为匿名函数持有着它的引用。在 V8 内部，这种对长期存活对象的引用可能通过 `Persistent Handles` 来实现，而 `LocalHeap` 负责管理这些句柄。

4. **垃圾回收 (Safepoint):**

   JavaScript 的垃圾回收是自动进行的。当 V8 执行垃圾回收时，它需要确保所有的 JavaScript 线程都到达一个安全点，才能安全地进行内存回收。`LocalHeap` 的 `Park()` 和 `Unpark()` 方法以及安全点相关的机制，确保了非主线程在 GC 期间能够安全地暂停和恢复执行。

**总结:**

`v8/src/heap/local-heap.cc` 文件是 V8 引擎中管理非主线程堆内存的关键组件。它负责线程的内存分配、状态管理、安全点处理以及与主堆的协调。虽然 JavaScript 开发者不能直接接触 `LocalHeap`，但理解它的功能有助于理解 V8 如何实现高效的并发和自动内存管理。  Web Workers、异步操作、闭包和垃圾回收等 JavaScript 特性都依赖于 `LocalHeap` 提供的底层机制。

Prompt: 
```
这是目录为v8/src/heap/local-heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/local-heap.h"

#include <atomic>
#include <memory>
#include <optional>

#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/handles/local-handles.h"
#include "src/heap/collection-barrier.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-write-barrier.h"
#include "src/heap/heap.h"
#include "src/heap/local-heap-inl.h"
#include "src/heap/main-allocator.h"
#include "src/heap/marking-barrier.h"
#include "src/heap/parked-scope.h"
#include "src/heap/safepoint.h"

namespace v8 {
namespace internal {

thread_local LocalHeap* g_current_local_heap_ V8_CONSTINIT = nullptr;

V8_TLS_DEFINE_GETTER(LocalHeap::Current, LocalHeap*, g_current_local_heap_)

// static
void LocalHeap::SetCurrent(LocalHeap* local_heap) {
  g_current_local_heap_ = local_heap;
}

#ifdef DEBUG
void LocalHeap::VerifyCurrent() const {
  LocalHeap* current = LocalHeap::Current();

  if (is_main_thread())
    DCHECK_NULL(current);
  else
    DCHECK_EQ(current, this);
}
#endif

LocalHeap::LocalHeap(Heap* heap, ThreadKind kind,
                     std::unique_ptr<PersistentHandles> persistent_handles)
    : heap_(heap),
      ptr_compr_cage_access_scope_(heap->isolate()),
      is_main_thread_(kind == ThreadKind::kMain),
      state_(ThreadState::Parked()),
      allocation_failed_(false),
      nested_parked_scopes_(0),
      prev_(nullptr),
      next_(nullptr),
      handles_(new LocalHandles),
      persistent_handles_(std::move(persistent_handles)),
      heap_allocator_(this) {
  DCHECK_IMPLIES(!is_main_thread(), heap_->deserialization_complete());
  if (!is_main_thread()) {
    heap_allocator_.Setup();
    SetUpMarkingBarrier();
  }

  heap_->safepoint()->AddLocalHeap(this, [this] {
    if (!is_main_thread()) {
      saved_marking_barrier_ =
          WriteBarrier::SetForThread(marking_barrier_.get());
      if (heap_->incremental_marking()->IsMarking()) {
        marking_barrier_->Activate(
            heap_->incremental_marking()->IsCompacting(),
            heap_->incremental_marking()->marking_mode());
      }

      SetUpSharedMarking();
    }
  });

  if (persistent_handles_) {
    persistent_handles_->Attach(this);
  }
  DCHECK_NULL(LocalHeap::Current());
  if (!is_main_thread()) {
    saved_current_isolate_ = Isolate::TryGetCurrent();
    Isolate::SetCurrent(heap_->isolate());
    LocalHeap::SetCurrent(this);
  }
}

LocalHeap::~LocalHeap() {
  // Park thread since removing the local heap could block.
  EnsureParkedBeforeDestruction();

  heap_->safepoint()->RemoveLocalHeap(this, [this] {
    FreeLinearAllocationAreas();

    if (!is_main_thread()) {
      marking_barrier_->PublishIfNeeded();
      marking_barrier_->PublishSharedIfNeeded();
      MarkingBarrier* overwritten =
          WriteBarrier::SetForThread(saved_marking_barrier_);
      DCHECK_EQ(overwritten, marking_barrier_.get());
      USE(overwritten);
    }
  });

  if (!is_main_thread()) {
    DCHECK_EQ(Isolate::Current(), heap_->isolate());
    Isolate::SetCurrent(saved_current_isolate_);
    DCHECK_EQ(LocalHeap::Current(), this);
    LocalHeap::SetCurrent(nullptr);
  }

  DCHECK(gc_epilogue_callbacks_.IsEmpty());
}

void LocalHeap::SetUpMainThreadForTesting() {
  Unpark();
  DCHECK(is_main_thread());
  DCHECK(IsRunning());
  heap_allocator_.Setup();
  SetUpMarkingBarrier();
  SetUpSharedMarking();
}

void LocalHeap::SetUpMainThread(LinearAllocationArea& new_allocation_info,
                                LinearAllocationArea& old_allocation_info) {
  DCHECK(is_main_thread());
  DCHECK(IsRunning());
  heap_allocator_.Setup(&new_allocation_info, &old_allocation_info);
  SetUpMarkingBarrier();
  SetUpSharedMarking();
}

void LocalHeap::SetUpMarkingBarrier() {
  DCHECK_NULL(marking_barrier_);
  marking_barrier_ = std::make_unique<MarkingBarrier>(this);
}

void LocalHeap::SetUpSharedMarking() {
#if DEBUG
  // Ensure the thread is either in the running state or holds the safepoint
  // lock. This guarantees that the state of incremental marking can't change
  // concurrently (this requires a safepoint).
  if (is_main_thread()) {
    DCHECK(IsRunning());
  } else {
    heap()->safepoint()->AssertActive();
  }
#endif  // DEBUG

  Isolate* isolate = heap_->isolate();

  if (isolate->has_shared_space() && !isolate->is_shared_space_isolate()) {
    if (isolate->shared_space_isolate()
            ->heap()
            ->incremental_marking()
            ->IsMajorMarking()) {
      marking_barrier_->ActivateShared();
    }
  }
}

void LocalHeap::EnsurePersistentHandles() {
  if (!persistent_handles_) {
    persistent_handles_ = heap_->isolate()->NewPersistentHandles();
    persistent_handles_->Attach(this);
  }
}

void LocalHeap::AttachPersistentHandles(
    std::unique_ptr<PersistentHandles> persistent_handles) {
  DCHECK_NULL(persistent_handles_);
  persistent_handles_ = std::move(persistent_handles);
  persistent_handles_->Attach(this);
}

std::unique_ptr<PersistentHandles> LocalHeap::DetachPersistentHandles() {
  if (persistent_handles_) persistent_handles_->Detach();
  return std::move(persistent_handles_);
}

#ifdef DEBUG
bool LocalHeap::ContainsPersistentHandle(Address* location) {
  return persistent_handles_ ? persistent_handles_->Contains(location) : false;
}

bool LocalHeap::ContainsLocalHandle(Address* location) {
  return handles_ ? handles_->Contains(location) : false;
}

bool LocalHeap::IsHandleDereferenceAllowed() {
  VerifyCurrent();
  return IsRunning();
}
#endif

bool LocalHeap::IsParked() const {
#ifdef DEBUG
  VerifyCurrent();
#endif
  return state_.load_relaxed().IsParked();
}

bool LocalHeap::IsRunning() const {
#ifdef DEBUG
  VerifyCurrent();
#endif
  return state_.load_relaxed().IsRunning();
}

void LocalHeap::ParkSlowPath() {
  while (true) {
    ThreadState current_state = ThreadState::Running();
    if (state_.CompareExchangeStrong(current_state, ThreadState::Parked()))
      return;

    // CAS above failed, so state is Running with some additional flag.
    DCHECK(current_state.IsRunning());

    if (is_main_thread()) {
      DCHECK(current_state.IsSafepointRequested() ||
             current_state.IsCollectionRequested());

      if (current_state.IsSafepointRequested()) {
        ThreadState old_state = state_.SetParked();
        heap_->safepoint()->NotifyPark();
        if (old_state.IsCollectionRequested())
          heap_->collection_barrier_->CancelCollectionAndResumeThreads();
        return;
      }

      if (current_state.IsCollectionRequested()) {
        if (!heap()->ignore_local_gc_requests()) {
          heap_->CollectGarbageForBackground(this);
          continue;
        }

        DCHECK(!current_state.IsSafepointRequested());

        if (state_.CompareExchangeStrong(current_state,
                                         current_state.SetParked())) {
          heap_->collection_barrier_->CancelCollectionAndResumeThreads();
          return;
        } else {
          continue;
        }
      }
    } else {
      DCHECK(current_state.IsSafepointRequested());
      DCHECK(!current_state.IsCollectionRequested());

      ThreadState old_state = state_.SetParked();
      CHECK(old_state.IsRunning());
      CHECK(old_state.IsSafepointRequested());
      CHECK(!old_state.IsCollectionRequested());

      heap_->safepoint()->NotifyPark();
      return;
    }
  }
}

void LocalHeap::UnparkSlowPath() {
  while (true) {
    ThreadState current_state = ThreadState::Parked();
    if (state_.CompareExchangeStrong(current_state, ThreadState::Running()))
      return;

    // CAS above failed, so state is Parked with some additional flag.
    DCHECK(current_state.IsParked());

    if (is_main_thread()) {
      DCHECK(current_state.IsSafepointRequested() ||
             current_state.IsCollectionRequested());

      if (current_state.IsSafepointRequested()) {
        SleepInUnpark();
        continue;
      }

      if (current_state.IsCollectionRequested()) {
        DCHECK(!current_state.IsSafepointRequested());

        if (!state_.CompareExchangeStrong(current_state,
                                          current_state.SetRunning()))
          continue;

        if (!heap()->ignore_local_gc_requests()) {
          heap_->CollectGarbageForBackground(this);
        }

        return;
      }
    } else {
      DCHECK(current_state.IsSafepointRequested());
      DCHECK(!current_state.IsCollectionRequested());

      SleepInUnpark();
    }
  }
}

void LocalHeap::SleepInUnpark() {
  GCTracer::Scope::ScopeId scope_id;
  ThreadKind thread_kind;

  if (is_main_thread()) {
    scope_id = GCTracer::Scope::UNPARK;
    thread_kind = ThreadKind::kMain;
  } else {
    scope_id = GCTracer::Scope::BACKGROUND_UNPARK;
    thread_kind = ThreadKind::kBackground;
  }

  TRACE_GC1(heap_->tracer(), scope_id, thread_kind);
  heap_->safepoint()->WaitInUnpark();
}

void LocalHeap::EnsureParkedBeforeDestruction() {
  DCHECK_IMPLIES(!is_main_thread(), IsParked());
}

void LocalHeap::SafepointSlowPath() {
  ThreadState current_state = state_.load_relaxed();
  DCHECK(current_state.IsRunning());

  if (is_main_thread()) {
    DCHECK(current_state.IsSafepointRequested() ||
           current_state.IsCollectionRequested());

    if (current_state.IsSafepointRequested()) {
      SleepInSafepoint();
    }

    if (current_state.IsCollectionRequested()) {
      heap_->CollectGarbageForBackground(this);
    }
  } else {
    DCHECK(current_state.IsSafepointRequested());
    DCHECK(!current_state.IsCollectionRequested());

    SleepInSafepoint();
  }
}

void LocalHeap::SleepInSafepoint() {
  GCTracer::Scope::ScopeId scope_id;
  ThreadKind thread_kind;

  if (is_main_thread()) {
    scope_id = GCTracer::Scope::SAFEPOINT;
    thread_kind = ThreadKind::kMain;
  } else {
    scope_id = GCTracer::Scope::BACKGROUND_SAFEPOINT;
    thread_kind = ThreadKind::kBackground;
  }

  TRACE_GC1(heap_->tracer(), scope_id, thread_kind);

  ExecuteWithStackMarker([this]() {
    // Parking the running thread here is an optimization. We do not need to
    // wake this thread up to reach the next safepoint.
    ThreadState old_state = state_.SetParked();
    CHECK(old_state.IsRunning());
    CHECK(old_state.IsSafepointRequested());
    CHECK_IMPLIES(old_state.IsCollectionRequested(), is_main_thread());

    heap_->safepoint()->WaitInSafepoint();

    std::optional<IgnoreLocalGCRequests> ignore_gc_requests;
    if (is_main_thread()) ignore_gc_requests.emplace(heap());
    Unpark();
  });
}

#ifdef DEBUG
bool LocalHeap::IsSafeForConservativeStackScanning() const {
#ifdef V8_ENABLE_DIRECT_HANDLE
  // There must be no direct handles on the stack below the stack marker.
  if (DirectHandleBase::NumberOfHandles() > 0) return false;
#endif
  // Check if we are inside at least one ParkedScope.
  if (nested_parked_scopes_ > 0) {
    // The main thread can avoid the trampoline, if it's not the main thread of
    // a client isolate.
    if (is_main_thread() && (heap()->isolate()->is_shared_space_isolate() ||
                             !heap()->isolate()->has_shared_space()))
      return true;
    // Otherwise, require that we're inside the trampoline.
    return is_in_trampoline();
  }
  // Otherwise, we are reaching the initial parked state and the stack should
  // not be interesting.
  return true;
}
#endif  // DEBUG

void LocalHeap::FreeLinearAllocationAreas() {
  heap_allocator_.FreeLinearAllocationAreas();
}

#if DEBUG
void LocalHeap::VerifyLinearAllocationAreas() const {
  heap_allocator_.VerifyLinearAllocationAreas();
}
#endif  // DEBUG

void LocalHeap::MakeLinearAllocationAreasIterable() {
  heap_allocator_.MakeLinearAllocationAreasIterable();
}

void LocalHeap::MarkLinearAllocationAreasBlack() {
  heap_allocator_.MarkLinearAllocationAreasBlack();
}

void LocalHeap::UnmarkLinearAllocationsArea() {
  heap_allocator_.UnmarkLinearAllocationsArea();
}

void LocalHeap::MarkSharedLinearAllocationAreasBlack() {
  if (heap_allocator_.shared_space_allocator()) {
    heap_allocator_.shared_space_allocator()->MarkLinearAllocationAreaBlack();
  }
}

void LocalHeap::UnmarkSharedLinearAllocationsArea() {
  if (heap_allocator_.shared_space_allocator()) {
    heap_allocator_.shared_space_allocator()->UnmarkLinearAllocationArea();
  }
}

void LocalHeap::FreeLinearAllocationAreasAndResetFreeLists() {
  heap_allocator_.FreeLinearAllocationAreasAndResetFreeLists();
}

void LocalHeap::FreeSharedLinearAllocationAreasAndResetFreeLists() {
  if (heap_allocator_.shared_space_allocator()) {
    heap_allocator_.shared_space_allocator()
        ->FreeLinearAllocationAreaAndResetFreeList();
  }
}

void LocalHeap::AddGCEpilogueCallback(GCEpilogueCallback* callback, void* data,
                                      GCCallbacksInSafepoint::GCType gc_type) {
  DCHECK(IsRunning());
  gc_epilogue_callbacks_.Add(callback, data, gc_type);
}

void LocalHeap::RemoveGCEpilogueCallback(GCEpilogueCallback* callback,
                                         void* data) {
  DCHECK(IsRunning());
  gc_epilogue_callbacks_.Remove(callback, data);
}

void LocalHeap::InvokeGCEpilogueCallbacksInSafepoint(
    GCCallbacksInSafepoint::GCType gc_type) {
  gc_epilogue_callbacks_.Invoke(gc_type);
}

void LocalHeap::NotifyObjectSizeChange(
    Tagged<HeapObject> object, int old_size, int new_size,
    ClearRecordedSlots clear_recorded_slots) {
  heap()->NotifyObjectSizeChange(object, old_size, new_size,
                                 clear_recorded_slots);
}

void LocalHeap::WeakenDescriptorArrays(
    GlobalHandleVector<DescriptorArray> strong_descriptor_arrays) {
  AsHeap()->WeakenDescriptorArrays(std::move(strong_descriptor_arrays));
}

}  // namespace internal
}  // namespace v8

"""

```