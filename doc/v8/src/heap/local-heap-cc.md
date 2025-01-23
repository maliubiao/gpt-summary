Response:
Let's break down the thought process for analyzing the `local-heap.cc` file.

1. **Understanding the Request:** The core request is to understand the functionality of the `local-heap.cc` file within the V8 JavaScript engine. The prompt also provides specific constraints: check for Torque source (`.tq`), relate to JavaScript, provide code logic examples, and identify common programming errors.

2. **Initial Scan and Keyword Identification:**  I'd start by quickly scanning the code for important keywords and class names. This immediately reveals key elements:

    * `LocalHeap`: This is the central class, so its purpose is paramount.
    * `Heap`:  The `LocalHeap` interacts with the main `Heap`. This suggests a relationship related to memory management.
    * `Isolate`:  Another core V8 concept. `LocalHeap` is associated with an `Isolate`.
    * `ThreadKind`: Indicates the `LocalHeap` is associated with a specific type of thread (main or background).
    * `PersistentHandles`, `LocalHandles`:  Handle management, likely for keeping objects alive.
    * `MarkingBarrier`:  Related to garbage collection marking phases.
    * `LinearAllocationArea`:  Allocation strategy hints.
    * `Safepoint`: A crucial concept in concurrent garbage collection.
    * `Park`, `Unpark`:  Thread pausing and resuming.
    * `GCEpilogueCallback`:  Callbacks executed after garbage collection.

3. **Inferring High-Level Functionality:** Based on the keywords, I can start forming a high-level understanding:

    * **Per-Thread Heap Management:** The name "LocalHeap" and the association with `ThreadKind` strongly suggest that it's a heap specifically for individual threads. This likely improves performance by reducing contention on the main heap.
    * **Garbage Collection Support:** The presence of `MarkingBarrier`, `Safepoint`, and `GCEpilogueCallback` clearly indicates involvement in garbage collection.
    * **Handle Management:**  `PersistentHandles` and `LocalHandles` are for managing object references.
    * **Allocation:** `LinearAllocationArea` suggests a fast, linear allocation strategy.
    * **Concurrency Control:** `Park`, `Unpark`, and `Safepoint` point to mechanisms for safely pausing and resuming threads, particularly during garbage collection.

4. **Analyzing Key Methods and Data Members:**  Next, I would examine the key methods and data members in more detail to solidify the understanding:

    * **Constructor (`LocalHeap(...)`) and Destructor (`~LocalHeap()`):** These methods handle initialization (setting up allocators, marking barriers, attaching to the safepoint mechanism) and cleanup (freeing resources, publishing marking information, detaching from the safepoint).
    * **`Park()` and `Unpark()`:** These methods implement the logic for pausing and resuming the thread associated with the `LocalHeap`, taking into account safepoints and potential garbage collection requests. The slow path logic is interesting as it handles different states and thread types.
    * **`Safepoint()`:** This method puts the thread into a safepoint, a state where the garbage collector can safely operate.
    * **`SetUpMarkingBarrier()`, `SetUpSharedMarking()`:** These methods configure the marking barrier, which is used during garbage collection marking phases.
    * **`heap_allocator_`:** This member is responsible for allocating memory within the `LocalHeap`.
    * **`state_`:** Tracks the current state of the thread (running, parked, safepoint requested, etc.).

5. **Relating to JavaScript:** The connection to JavaScript lies in V8's role as the JavaScript engine. The `LocalHeap` is part of V8's memory management system, which directly impacts how JavaScript objects are allocated and garbage collected. While `local-heap.cc` isn't directly manipulating JavaScript syntax, its functionality is *essential* for the execution of JavaScript code. The example of creating and using objects demonstrates this connection.

6. **Code Logic Examples:**  To illustrate the behavior, I would choose key functionalities like `Park()` and `Unpark()`. I'd create scenarios with different initial states and thread types to demonstrate the conditional logic within these methods. For example, showing how a background thread parks when a safepoint is requested is a good illustration.

7. **Common Programming Errors:** I would think about common errors that developers might make when dealing with concurrent programming and memory management, and relate them to the concepts in `local-heap.cc`. Examples include accessing data without proper synchronization (related to the need for safepoints) and memory leaks (although `local-heap.cc` focuses on *internal* memory management within V8, it's a relevant broader concept).

8. **Torque Check:**  The prompt specifically asks about Torque. A quick check of the file extension (`.cc`) confirms it's C++, not Torque.

9. **Structuring the Answer:** Finally, I would structure the answer logically, starting with the overall functionality, then diving into specific aspects like JavaScript relation, code logic, and potential errors. Using headings and bullet points improves readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe `LocalHeap` directly manages JavaScript object allocation.
* **Correction:** While it *contributes* to allocation, the `heap_allocator_` member and interaction with the main `Heap` suggest it's a lower-level abstraction focused on thread-local memory regions.
* **Initial thought:** The JavaScript example should be complex.
* **Correction:** A simple example demonstrating object creation is sufficient to show the connection to JavaScript's fundamental operations.
* **Ensuring Clarity:**  Emphasize the *internal* nature of `local-heap.cc` and how it supports the overall V8 architecture rather than being directly manipulated by JavaScript developers.

By following this structured approach, combining code scanning with conceptual understanding, and addressing the specific constraints of the prompt, I can generate a comprehensive and accurate explanation of the `local-heap.cc` file.
好的，让我们来分析一下 `v8/src/heap/local-heap.cc` 这个文件。

**功能概述:**

`v8/src/heap/local-heap.cc` 文件定义了 `LocalHeap` 类，它是 V8 引擎中用于管理每个线程私有堆内存的关键组件。其主要功能包括：

1. **线程隔离的堆管理:** 为每个非主线程（worker 线程等）提供独立的堆内存区域，减少多线程环境下的锁竞争，提高内存分配和垃圾回收的效率。主线程也有一个 `LocalHeap`，但其行为略有不同。
2. **内存分配:**  `LocalHeap` 内部使用 `heap_allocator_` 来负责在该线程的私有堆上分配内存。
3. **垃圾回收支持:**  `LocalHeap` 与 V8 的垃圾回收机制紧密集成，包括：
    * **标记屏障 (Marking Barrier):**  `marking_barrier_` 用于在增量标记过程中跟踪对象引用，确保垃圾回收的正确性。
    * **安全点 (Safepoint):**  `LocalHeap` 的 `Park` 和 `Unpark` 方法以及 `SafepointSlowPath` 等方法用于实现线程的安全点机制，允许垃圾回收器在安全的状态下暂停和恢复线程。
    * **线性分配区 (Linear Allocation Areas):** `LocalHeap` 管理线性分配区，用于快速分配小对象。
4. **Handle 管理:**  `LocalHeap` 拥有 `LocalHandles` 和 `PersistentHandles`，用于管理在该线程上创建的 JavaScript 对象的引用，防止对象被过早回收。
5. **线程状态管理:**  `state_` 成员变量用于跟踪线程的状态 (运行中、暂停等)，用于同步和协调垃圾回收等操作。
6. **GC 回调:**  `gc_epilogue_callbacks_` 允许在垃圾回收周期的末尾注册和执行回调函数。

**Torque 源代码:**

`v8/src/heap/local-heap.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。如果它是 Torque 源代码，那么它的扩展名将会是 `.tq`。

**与 JavaScript 的关系及示例:**

`LocalHeap` 的功能直接影响 JavaScript 代码的执行，因为它负责 JavaScript 对象的内存分配和垃圾回收。当 JavaScript 代码创建对象时，V8 引擎会在相应的 `LocalHeap` 上分配内存。

**JavaScript 示例:**

```javascript
// 假设这段代码运行在一个 worker 线程中

const myObject = { data: "hello" };
const myArray = [1, 2, 3];

// 当创建 myObject 和 myArray 时，worker 线程的 LocalHeap 会分配相应的内存。

function processData() {
  const tempObject = { value: myObject.data.length };
  // tempObject 也会在 worker 线程的 LocalHeap 上分配。
  return tempObject.value;
}

processData();

// 当这些对象不再被引用时，worker 线程的垃圾回收器会在 LocalHeap 上回收它们的内存。
```

在这个例子中，当 `myObject` 和 `myArray` 在 worker 线程中被创建时，worker 线程的 `LocalHeap` 负责分配存储这些对象的内存。`processData` 函数中创建的 `tempObject` 也会分配在同一个 `LocalHeap` 上。V8 的垃圾回收器会在适当的时候扫描 `LocalHeap`，回收不再使用的对象所占用的内存。

**代码逻辑推理及假设输入/输出:**

让我们来看 `ParkSlowPath` 方法的一个简化逻辑推理：

**假设输入:**

* 一个非主线程的 `LocalHeap` 实例，其 `state_` 当前为 `ThreadState::Running()`，并且 `Safepoint` 被请求 (例如，垃圾回收器需要暂停线程)。

**代码片段 (简化):**

```c++
void LocalHeap::ParkSlowPath() {
  while (true) {
    ThreadState current_state = ThreadState::Running();
    if (state_.CompareExchangeStrong(current_state, ThreadState::Parked()))
      return;

    // CAS above failed, so state is Running with some additional flag.
    DCHECK(current_state.IsRunning());

    if (!is_main_thread()) {
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
```

**推理步骤:**

1. **循环开始:** 进入 `while (true)` 循环，尝试将线程状态从 `Running` 修改为 `Parked`。
2. **CAS 操作:** 使用 `CompareExchangeStrong` 原子操作尝试更新 `state_`。如果当前 `state_` 不是 `Running`，则操作失败，需要重新读取 `state_` 并重试。
3. **非主线程分支:** 由于假设是非主线程，代码进入 `if (!is_main_thread())` 分支。
4. **断言检查:**  断言 `current_state.IsSafepointRequested()` 为真，因为这是触发 `Park` 的条件。
5. **设置 Parked 状态:** 调用 `state_.SetParked()` 将线程状态设置为 `Parked`。
6. **通知 Safepoint:** 调用 `heap_->safepoint()->NotifyPark()` 通知全局的 Safepoint 机制，表明该线程已暂停。
7. **返回:**  方法执行完毕，线程已进入暂停状态。

**预期输出:**

* `LocalHeap` 的 `state_` 变为 `ThreadState::Parked()`。
* 全局的 Safepoint 机制收到该线程暂停的通知。

**涉及用户常见的编程错误:**

虽然用户通常不会直接操作 `LocalHeap`，但 `LocalHeap` 的设计是为了解决多线程编程中常见的内存管理问题。一些相关的用户编程错误包括：

1. **数据竞争 (Data Race):** 在多线程环境下，如果不进行适当的同步，多个线程可能同时访问和修改同一块内存，导致数据不一致。`LocalHeap` 通过为每个线程提供私有堆来减少这种竞争。
   ```javascript
   // 错误示例：在没有同步的情况下，多个 worker 线程修改共享对象
   let counter = 0;

   function incrementCounter() {
     for (let i = 0; i < 10000; i++) {
       counter++; // 多个线程并发执行可能导致数据竞争
     }
   }

   const worker1 = new Worker(...);
   const worker2 = new Worker(...);
   worker1.postMessage('start');
   worker2.postMessage('start');
   ```
2. **内存泄漏 (Memory Leak):**  如果对象不再被使用但仍然被持有引用，垃圾回收器无法回收其内存，导致内存泄漏。虽然 `LocalHeap` 负责管理内存，但 JavaScript 代码中的错误仍然可能导致泄漏。
   ```javascript
   // 错误示例：意外地持有不再需要的对象的引用
   function createLargeObject() {
     const obj = new Array(1000000).fill({});
     return obj;
   }

   let leakedObject;

   function run() {
     leakedObject = createLargeObject(); // leakedObject 持有大对象的引用
     // ... 一些操作
     // 忘记释放 leakedObject 的引用
   }

   run(); // leakedObject 仍然存在，导致内存无法回收
   ```
3. **死锁 (Deadlock):**  在多线程程序中，如果多个线程互相等待对方释放资源，就会发生死锁。`LocalHeap` 的 `Park` 和 `Unpark` 机制是为了安全地暂停和恢复线程，但如果用户代码中存在不当的锁使用，仍然可能导致死锁。

总而言之，`v8/src/heap/local-heap.cc` 是 V8 引擎中一个非常重要的组件，它为每个线程提供了隔离的堆内存管理，并与垃圾回收机制紧密配合，确保 JavaScript 代码能够高效、安全地运行。虽然开发者不会直接操作这个文件中的代码，但理解其功能有助于理解 V8 的内存管理模型和多线程行为。

### 提示词
```
这是目录为v8/src/heap/local-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/local-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```