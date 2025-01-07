Response: Let's break down the thought process to analyze this C++ code and connect it to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of `v8/src/heap/safepoint.cc` and its relation to JavaScript. This means I need to figure out *what* this code does in the V8 engine and *why* it's important for running JavaScript.

2. **Initial Code Scan - Keywords and Structure:** I'll quickly scan the code for prominent keywords and structures:
    * `Safepoint`: This is clearly the central concept.
    * `Isolate`, `Heap`, `LocalHeap`, `GlobalSafepoint`: These suggest memory management and potentially multi-threading within V8. `Isolate` is particularly important as it's the core execution context for JavaScript.
    * `Mutex`, `Lock`, `Barrier`, `atomic`: These strongly indicate synchronization primitives, suggesting the code deals with concurrent execution.
    * `EnterLocalSafepointScope`, `InitiateGlobalSafepointScope`, `Leave...`:  These look like entry and exit points for specific operations.
    * `SetSafepointRequestedFlags`, `ClearSafepointRequestedFlags`: These hint at controlling the state of threads.
    * `WaitInSafepoint`, `WaitUntilRunningThreadsInSafepoint`:  More evidence of thread synchronization.
    * `RootVisitor`, `Iterate`: These are common patterns in garbage collectors for traversing object graphs.

3. **Hypothesize Core Functionality:** Based on the keywords, I can form a hypothesis: This code manages "safepoints," which are likely points in execution where the state of JavaScript execution can be examined or modified safely, especially in a multi-threaded environment. This is crucial for operations like garbage collection.

4. **Drill Down into Key Classes:**

    * **`IsolateSafepoint`:** Seems to manage safepoints within a single V8 isolate. The `EnterLocalSafepointScope` and `LeaveLocalSafepointScope` suggest a localized safepoint, possibly for operations within a specific isolate's thread. The interaction with `LocalHeap` reinforces this.

    * **`GlobalSafepoint`:**  Manages safepoints across multiple isolates. The `AppendClient`, `RemoveClient`, `EnterGlobalSafepointScope`, and `LeaveGlobalSafepointScope` point to coordinating safepoints across different isolates. This is likely necessary for operations that need to affect the entire V8 environment, such as a full garbage collection across multiple isolates.

    * **`Barrier`:** A synchronization primitive used to ensure all relevant threads reach the safepoint before proceeding.

5. **Connect to Garbage Collection:**  The presence of `gc-tracer`, `Heap`, and the need for safepoints strongly suggests a link to garbage collection. Garbage collection needs to pause JavaScript execution momentarily to safely examine and reclaim memory. Safepoints provide these pause points.

6. **Consider Multi-threading:** The mutexes and barriers clearly indicate that this code deals with multiple threads. JavaScript execution, while often appearing single-threaded to the programmer, internally uses multiple threads in V8 for tasks like garbage collection, compilation, and potentially web workers/shared arrays. Safepoints are essential for coordinating these threads.

7. **Formulate a High-Level Summary:**  At this stage, I'd summarize that the code implements a mechanism for safely pausing JavaScript execution across one or more isolates. This mechanism, called a "safepoint," is crucial for operations like garbage collection and potentially other internal V8 tasks that require a consistent view of the heap.

8. **Connect to JavaScript - The "Why":** Now, the crucial step is to explain *why* this matters to JavaScript developers. Although developers don't directly interact with safepoints, they are essential for the correct and efficient execution of JavaScript.

    * **Garbage Collection:** This is the most obvious link. Without safepoints, garbage collection could occur while JavaScript code is modifying objects, leading to data corruption and crashes.

    * **Consistency:** Safepoints ensure that when V8 needs to perform internal operations, it can do so with a consistent view of the JavaScript heap and execution state.

    * **Multi-threading (Internal):**  Even though JavaScript has a single-threaded execution model in the event loop, V8 uses internal threads. Safepoints help coordinate these threads so they don't interfere with each other.

9. **Create JavaScript Examples:** To illustrate the connection, I need examples that demonstrate scenarios where safepoints are implicitly involved:

    * **Simple Garbage Collection:** Create a situation where garbage collection is likely to occur (lots of object creation and dereferencing). The safepoint is what allows the GC to happen safely.

    * **More Complex Scenario (though harder to directly show):**  Mention web workers or shared arrays, even though the code doesn't explicitly detail their safepoint mechanisms. This hints at how safepoints are relevant in more complex concurrent JavaScript environments. *Initially, I might think about demonstrating shared array access, but that gets complex. Sticking to a simpler GC example is better for illustration.*

10. **Refine and Organize:** Finally, I would organize the findings into a clear and concise explanation, starting with the high-level functionality and then providing more details and the JavaScript examples. I'd ensure the language is accessible and avoids overly technical jargon where possible. I would also make sure the examples clearly link back to the concept of safepoints, even if the link is implicit. I might add a concluding statement to reiterate the importance of safepoints.

This step-by-step breakdown allows for a structured approach to understanding the C++ code and its significance in the context of JavaScript, even without being an expert in V8 internals. The key is to identify the core concepts, understand their purpose, and connect them back to the user-facing aspects of JavaScript.
The C++ source code file `v8/src/heap/safepoint.cc` implements the **safepoint mechanism** within the V8 JavaScript engine's heap management.

In essence, **safepoints are specific points in the execution of JavaScript code where all threads (or a relevant subset of threads) can be safely paused**. This is crucial for operations that require a consistent view of the heap and the execution state, primarily **garbage collection (GC)**.

Here's a breakdown of its key functionalities:

**1. Synchronization and Coordination of Threads:**

* **`IsolateSafepoint`:** Manages safepoints within a single V8 isolate (an independent JavaScript execution environment).
* **`GlobalSafepoint`:**  Manages safepoints across multiple isolates, which can occur in scenarios like web workers or shared array buffers.
* **`Barrier`:**  A synchronization primitive used to ensure that all participating threads reach the safepoint before proceeding. It involves:
    * **`Arm()`:**  Sets up the barrier, indicating a safepoint is being initiated.
    * **`WaitUntilRunningThreadsInSafepoint()`:**  Blocks the initiating thread until all other running threads have reached the safepoint.
    * **`NotifyPark()`:**  Called by a thread when it reaches the safepoint.
    * **`WaitInSafepoint()`:**  A thread calls this to wait at the safepoint until it's safe to resume.
    * **`Disarm()`:**  Releases all threads waiting at the safepoint.
* **Mutexes (`local_heaps_mutex_`, `clients_mutex_`):** Used to protect shared data structures and ensure exclusive access during critical operations related to safepoint management.

**2. Initiating and Exiting Safepoints:**

* **`EnterLocalSafepointScope()` / `LeaveLocalSafepointScope()`:** Used to initiate and exit a safepoint within a single isolate. This is typically used for local GC operations.
* **`InitiateGlobalSafepointScope()` / `LeaveGlobalSafepointScope()`:** Used to initiate and exit a safepoint across multiple isolates. This is necessary for global GC operations or other operations that require coordination across isolates.
* **`SetSafepointRequestedFlags()`:**  Flags threads that need to reach a safepoint.
* **`ClearSafepointRequestedFlags()`:** Clears the safepoint request flags when the safepoint is over.

**3. Handling Different Thread States:**

* The code interacts with `LocalHeap` and its `ThreadState` to track whether a thread is running, parked, or has a safepoint requested.

**4. Performance Considerations:**

* The code includes timing mechanisms (using `TimedHistogramScope`) to track the time taken to reach a safepoint, which is important for performance analysis and optimization of garbage collection.

**Relationship with JavaScript Functionality (with JavaScript examples):**

The `safepoint.cc` code is fundamental to the smooth and safe execution of JavaScript. While JavaScript developers don't directly interact with safepoints, they are essential for enabling features like:

**1. Garbage Collection:**

* **How it works:** When V8 needs to perform garbage collection, it initiates a safepoint. This ensures that the JavaScript code is paused at a point where the heap's state is consistent. The garbage collector can then safely traverse the object graph and reclaim unused memory without the risk of data corruption due to ongoing JavaScript execution.

* **JavaScript Example:**

```javascript
function createLotsOfObjects() {
  let objects = [];
  for (let i = 0; i < 100000; i++) {
    objects.push({ data: new Array(1000).fill(i) });
  }
  // At some point, many of these 'objects' will become unreachable and eligible for GC.
  // The safepoint mechanism ensures GC happens safely while this code is potentially running.
}

createLotsOfObjects();
```

In the background, when the V8 garbage collector decides to run, it will trigger a safepoint. All JavaScript execution threads will pause at these safepoints, allowing the GC to do its work.

**2. Managing Web Workers and Shared Array Buffers (Multi-Isolate Scenarios):**

* **How it works:** When JavaScript code in different web workers or isolates using shared array buffers needs to interact or when a global garbage collection is required, the `GlobalSafepoint` mechanism ensures that all relevant isolates are paused at a consistent point. This prevents race conditions and data inconsistencies when accessing shared memory.

* **JavaScript Example (Web Workers):**

```javascript
// main.js
const worker = new Worker('worker.js');
worker.postMessage({ sharedData: sharedArray });

// worker.js
onmessage = function(e) {
  const sharedData = e.data.sharedData;
  // ... access and modify sharedData ...
};
```

When the V8 engine needs to perform a global operation (like a full GC) involving both the main thread and the worker thread, the global safepoint mechanism will ensure both are paused before the operation proceeds.

**3. Debugging and Profiling:**

* Although not the primary purpose, safepoints can also be relevant for debugging and profiling tools. These tools often need to inspect the state of the JavaScript engine, which requires pausing execution safely.

**In summary, `v8/src/heap/safepoint.cc` implements a critical low-level mechanism in V8 that ensures the safety and correctness of operations like garbage collection, especially in multi-threaded or multi-isolate environments. It's a fundamental building block for the robust execution of JavaScript.**

Prompt: 
```
这是目录为v8/src/heap/safepoint.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/safepoint.h"

#include <atomic>

#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/handles/handles.h"
#include "src/handles/local-handles.h"
#include "src/handles/persistent-handles.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap.h"
#include "src/heap/local-heap-inl.h"
#include "src/heap/parked-scope.h"
#include "src/logging/counters-scopes.h"
#include "src/objects/objects.h"

namespace v8 {
namespace internal {

IsolateSafepoint::IsolateSafepoint(Heap* heap) : heap_(heap) {}

void IsolateSafepoint::EnterLocalSafepointScope() {
  // Safepoints need to be initiated on some main thread.
  DCHECK_NULL(LocalHeap::Current());
  DCHECK(AllowGarbageCollection::IsAllowed());

  LockMutex(isolate()->main_thread_local_heap());
  if (++active_safepoint_scopes_ > 1) return;

  // Local safepoint can only be initiated on the isolate's main thread.
  DCHECK_EQ(ThreadId::Current(), isolate()->thread_id());

  TimedHistogramScope timer(isolate()->counters()->gc_time_to_safepoint());
  TRACE_GC(heap_->tracer(), GCTracer::Scope::TIME_TO_SAFEPOINT);

  barrier_.Arm();
  size_t running = SetSafepointRequestedFlags(IncludeMainThread::kNo);
  barrier_.WaitUntilRunningThreadsInSafepoint(running);
}

class PerClientSafepointData final {
 public:
  explicit PerClientSafepointData(Isolate* isolate) : isolate_(isolate) {}

  void set_locked_and_running(size_t running) {
    locked_ = true;
    running_ = running;
  }

  IsolateSafepoint* safepoint() const { return heap()->safepoint(); }
  Heap* heap() const { return isolate_->heap(); }
  Isolate* isolate() const { return isolate_; }

  bool is_locked() const { return locked_; }
  size_t running() const { return running_; }

 private:
  Isolate* const isolate_;
  size_t running_ = 0;
  bool locked_ = false;
};

void IsolateSafepoint::InitiateGlobalSafepointScope(
    Isolate* initiator, PerClientSafepointData* client_data) {
  shared_space_isolate()->global_safepoint()->AssertActive();
  LockMutex(initiator->main_thread_local_heap());
  InitiateGlobalSafepointScopeRaw(initiator, client_data);
}

void IsolateSafepoint::TryInitiateGlobalSafepointScope(
    Isolate* initiator, PerClientSafepointData* client_data) {
  shared_space_isolate()->global_safepoint()->AssertActive();
  if (!local_heaps_mutex_.TryLock()) return;
  InitiateGlobalSafepointScopeRaw(initiator, client_data);
}

class GlobalSafepointInterruptTask : public CancelableTask {
 public:
  explicit GlobalSafepointInterruptTask(Heap* heap)
      : CancelableTask(heap->isolate()), heap_(heap) {}

  ~GlobalSafepointInterruptTask() override = default;
  GlobalSafepointInterruptTask(const GlobalSafepointInterruptTask&) = delete;
  GlobalSafepointInterruptTask& operator=(const GlobalSafepointInterruptTask&) =
      delete;

 private:
  // v8::internal::CancelableTask overrides.
  void RunInternal() override { heap_->main_thread_local_heap()->Safepoint(); }

  Heap* heap_;
};

void IsolateSafepoint::InitiateGlobalSafepointScopeRaw(
    Isolate* initiator, PerClientSafepointData* client_data) {
  CHECK_EQ(++active_safepoint_scopes_, 1);
  barrier_.Arm();

  size_t running =
      SetSafepointRequestedFlags(ShouldIncludeMainThread(initiator));
  client_data->set_locked_and_running(running);

  if (isolate() != initiator) {
    // An isolate might be waiting in the event loop. Post a task in order to
    // wake it up.
    isolate()->heap()->GetForegroundTaskRunner()->PostTask(
        std::make_unique<GlobalSafepointInterruptTask>(heap_));

    // Request an interrupt in case of long-running code.
    isolate()->stack_guard()->RequestGlobalSafepoint();
  }
}

IsolateSafepoint::IncludeMainThread IsolateSafepoint::ShouldIncludeMainThread(
    Isolate* initiator) {
  const bool is_initiator = isolate() == initiator;
  return is_initiator ? IncludeMainThread::kNo : IncludeMainThread::kYes;
}

size_t IsolateSafepoint::SetSafepointRequestedFlags(
    IncludeMainThread include_main_thread) {
  size_t running = 0;

  // There needs to be at least one LocalHeap for the main thread.
  DCHECK_NOT_NULL(local_heaps_head_);

  for (LocalHeap* local_heap = local_heaps_head_; local_heap;
       local_heap = local_heap->next_) {
    if (local_heap->is_main_thread() &&
        include_main_thread == IncludeMainThread::kNo) {
      continue;
    }

    const LocalHeap::ThreadState old_state =
        local_heap->state_.SetSafepointRequested();

    if (old_state.IsRunning()) running++;
    CHECK_IMPLIES(old_state.IsCollectionRequested(),
                  local_heap->is_main_thread());
    CHECK(!old_state.IsSafepointRequested());
  }

  return running;
}

void IsolateSafepoint::LockMutex(LocalHeap* local_heap) {
  if (!local_heaps_mutex_.TryLock()) {
    // Safepoints are only used for GCs, so GC requests should be ignored by
    // default when parking for a safepoint.
    IgnoreLocalGCRequests ignore_gc_requests(local_heap->heap());
    local_heap->ExecuteWhileParked([this]() { local_heaps_mutex_.Lock(); });
  }
}

void IsolateSafepoint::LeaveGlobalSafepointScope(Isolate* initiator) {
  local_heaps_mutex_.AssertHeld();
  CHECK_EQ(--active_safepoint_scopes_, 0);
  ClearSafepointRequestedFlags(ShouldIncludeMainThread(initiator));
  barrier_.Disarm();
  local_heaps_mutex_.Unlock();
}

void IsolateSafepoint::LeaveLocalSafepointScope() {
  local_heaps_mutex_.AssertHeld();
  DCHECK_GT(active_safepoint_scopes_, 0);

  if (--active_safepoint_scopes_ == 0) {
    ClearSafepointRequestedFlags(IncludeMainThread::kNo);
    barrier_.Disarm();
  }

  local_heaps_mutex_.Unlock();
}

void IsolateSafepoint::ClearSafepointRequestedFlags(
    IncludeMainThread include_main_thread) {
  for (LocalHeap* local_heap = local_heaps_head_; local_heap;
       local_heap = local_heap->next_) {
    if (local_heap->is_main_thread() &&
        include_main_thread == IncludeMainThread::kNo) {
      continue;
    }

    const LocalHeap::ThreadState old_state =
        local_heap->state_.ClearSafepointRequested();

    CHECK(old_state.IsParked());
    CHECK(old_state.IsSafepointRequested());
    CHECK_IMPLIES(old_state.IsCollectionRequested(),
                  local_heap->is_main_thread());
  }
}

void IsolateSafepoint::WaitInSafepoint() { barrier_.WaitInSafepoint(); }

void IsolateSafepoint::WaitInUnpark() { barrier_.WaitInUnpark(); }

void IsolateSafepoint::NotifyPark() { barrier_.NotifyPark(); }

void IsolateSafepoint::WaitUntilRunningThreadsInSafepoint(
    const PerClientSafepointData* client_data) {
  barrier_.WaitUntilRunningThreadsInSafepoint(client_data->running());
}

void IsolateSafepoint::Barrier::Arm() {
  base::MutexGuard guard(&mutex_);
  DCHECK(!IsArmed());
  armed_ = true;
  stopped_ = 0;
}

void IsolateSafepoint::Barrier::Disarm() {
  base::MutexGuard guard(&mutex_);
  DCHECK(IsArmed());
  armed_ = false;
  stopped_ = 0;
  cv_resume_.NotifyAll();
}

void IsolateSafepoint::Barrier::WaitUntilRunningThreadsInSafepoint(
    size_t running) {
  base::MutexGuard guard(&mutex_);
  DCHECK(IsArmed());
  while (stopped_ < running) {
    cv_stopped_.Wait(&mutex_);
  }
  DCHECK_EQ(stopped_, running);
}

void IsolateSafepoint::Barrier::NotifyPark() {
  base::MutexGuard guard(&mutex_);
  CHECK(IsArmed());
  stopped_++;
  cv_stopped_.NotifyOne();
}

void IsolateSafepoint::Barrier::WaitInSafepoint() {
  const auto scoped_blocking_call =
      V8::GetCurrentPlatform()->CreateBlockingScope(BlockingType::kWillBlock);
  base::MutexGuard guard(&mutex_);
  CHECK(IsArmed());
  stopped_++;
  cv_stopped_.NotifyOne();

  while (IsArmed()) {
    cv_resume_.Wait(&mutex_);
  }
}

void IsolateSafepoint::Barrier::WaitInUnpark() {
  const auto scoped_blocking_call =
      V8::GetCurrentPlatform()->CreateBlockingScope(BlockingType::kWillBlock);
  base::MutexGuard guard(&mutex_);

  while (IsArmed()) {
    cv_resume_.Wait(&mutex_);
  }
}

void IsolateSafepoint::Iterate(RootVisitor* visitor) {
  AssertActive();
  for (LocalHeap* current = local_heaps_head_; current;
       current = current->next_) {
    current->handles()->Iterate(visitor);
  }
}

void IsolateSafepoint::AssertMainThreadIsOnlyThread() {
  DCHECK_EQ(local_heaps_head_, heap_->main_thread_local_heap());
  DCHECK_NULL(heap_->main_thread_local_heap()->next_);
}

Isolate* IsolateSafepoint::isolate() const { return heap_->isolate(); }

Isolate* IsolateSafepoint::shared_space_isolate() const {
  return isolate()->shared_space_isolate();
}

IsolateSafepointScope::IsolateSafepointScope(Heap* heap)
    : safepoint_(heap->safepoint()) {
  safepoint_->EnterLocalSafepointScope();
}

IsolateSafepointScope::~IsolateSafepointScope() {
  safepoint_->LeaveLocalSafepointScope();
}

GlobalSafepoint::GlobalSafepoint(Isolate* isolate)
    : shared_space_isolate_(isolate) {}

void GlobalSafepoint::AppendClient(Isolate* client) {
  clients_mutex_.AssertHeld();

  DCHECK_NULL(client->global_safepoint_prev_client_isolate_);
  DCHECK_NULL(client->global_safepoint_next_client_isolate_);
  DCHECK_NE(clients_head_, client);

  if (clients_head_) {
    clients_head_->global_safepoint_prev_client_isolate_ = client;
  }

  client->global_safepoint_prev_client_isolate_ = nullptr;
  client->global_safepoint_next_client_isolate_ = clients_head_;

  clients_head_ = client;
}

void GlobalSafepoint::RemoveClient(Isolate* client) {
  DCHECK_EQ(client->heap()->gc_state(), Heap::TEAR_DOWN);
  AssertActive();

  if (client->global_safepoint_next_client_isolate_) {
    client->global_safepoint_next_client_isolate_
        ->global_safepoint_prev_client_isolate_ =
        client->global_safepoint_prev_client_isolate_;
  }

  if (client->global_safepoint_prev_client_isolate_) {
    client->global_safepoint_prev_client_isolate_
        ->global_safepoint_next_client_isolate_ =
        client->global_safepoint_next_client_isolate_;
  } else {
    DCHECK_EQ(clients_head_, client);
    clients_head_ = client->global_safepoint_next_client_isolate_;
  }
}

void GlobalSafepoint::AssertNoClientsOnTearDown() {
  DCHECK_NULL(clients_head_);
}

void GlobalSafepoint::EnterGlobalSafepointScope(Isolate* initiator) {
  // Safepoints need to be initiated on some main thread.
  DCHECK_NULL(LocalHeap::Current());

  if (!clients_mutex_.TryLock()) {
    IgnoreLocalGCRequests ignore_gc_requests(initiator->heap());
    initiator->main_thread_local_heap()->ExecuteWhileParked(
        [this]() { clients_mutex_.Lock(); });
  }

  if (++active_safepoint_scopes_ > 1) return;

  TimedHistogramScope timer(
      initiator->counters()->gc_time_to_global_safepoint());
  TRACE_GC(initiator->heap()->tracer(),
           GCTracer::Scope::TIME_TO_GLOBAL_SAFEPOINT);

  std::vector<PerClientSafepointData> clients;

  // Try to initiate safepoint for all clients. Fail immediately when the
  // local_heaps_mutex_ can't be locked without blocking.
  IterateSharedSpaceAndClientIsolates([&clients, initiator](Isolate* client) {
    clients.emplace_back(client);
    client->heap()->safepoint()->TryInitiateGlobalSafepointScope(
        initiator, &clients.back());
  });

  // Iterate all clients again to initiate the safepoint for all of them - even
  // if that means blocking.
  for (PerClientSafepointData& client : clients) {
    if (client.is_locked()) continue;
    client.safepoint()->InitiateGlobalSafepointScope(initiator, &client);
  }

#if DEBUG
  for (const PerClientSafepointData& client : clients) {
    DCHECK_EQ(client.isolate()->shared_space_isolate(), shared_space_isolate_);
  }
#endif  // DEBUG

  // Now that safepoints were initiated for all clients, wait until all threads
  // of all clients reached a safepoint.
  for (const PerClientSafepointData& client : clients) {
    DCHECK(client.is_locked());
    client.safepoint()->WaitUntilRunningThreadsInSafepoint(&client);
  }
}

void GlobalSafepoint::LeaveGlobalSafepointScope(Isolate* initiator) {
  clients_mutex_.AssertHeld();
  DCHECK_GT(active_safepoint_scopes_, 0);

  if (--active_safepoint_scopes_ == 0) {
    IterateSharedSpaceAndClientIsolates([initiator](Isolate* client) {
      Heap* client_heap = client->heap();
      client_heap->safepoint()->LeaveGlobalSafepointScope(initiator);
    });
  }

  clients_mutex_.Unlock();
}

bool GlobalSafepoint::IsRequestedForTesting() {
  if (!clients_mutex_.TryLock()) return true;
  clients_mutex_.Unlock();
  return false;
}

GlobalSafepointScope::GlobalSafepointScope(Isolate* initiator)
    : initiator_(initiator),
      shared_space_isolate_(initiator->shared_space_isolate()) {
  shared_space_isolate_->global_safepoint()->EnterGlobalSafepointScope(
      initiator_);
}

GlobalSafepointScope::~GlobalSafepointScope() {
  shared_space_isolate_->global_safepoint()->LeaveGlobalSafepointScope(
      initiator_);
}

SafepointScope::SafepointScope(Isolate* initiator, SafepointKind kind) {
  if (kind == SafepointKind::kIsolate) {
    isolate_safepoint_.emplace(initiator->heap());
  } else {
    DCHECK_EQ(kind, SafepointKind::kGlobal);
    global_safepoint_.emplace(initiator);
  }
}

SafepointScope::SafepointScope(Isolate* initiator,
                               GlobalSafepointForSharedSpaceIsolateTag) {
  if (initiator->is_shared_space_isolate()) {
    global_safepoint_.emplace(initiator);
  } else {
    isolate_safepoint_.emplace(initiator->heap());
  }
}

}  // namespace internal
}  // namespace v8

"""

```