Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and Keyword Spotting:**

The first thing I do is quickly scan the file for recognizable keywords and structures. I see:

* `Copyright`, license information (BSD-style) -  Standard header stuff.
* `#ifndef`, `#define`, `#include` -  C++ preprocessor directives, indicating this is a header file.
* `<atomic>`, `<memory>`, etc. - Standard C++ library headers, hinting at the use of concurrency, memory management, etc.
* `namespace v8`, `namespace internal` -  This confirms it's V8 source code and in an internal namespace.
* `class Heap`, `class LocalHandles`, `class MarkingBarrier` - Declarations of other V8 classes, indicating dependencies and relationships.
* `thread_local`, `V8_TLS_MODEL` - Strong indication of thread-specific data.
* `class V8_EXPORT_PRIVATE LocalHeap` - The core of the file: a class named `LocalHeap`, marked as private to V8's internal implementation.
* Public methods like `Safepoint()`, `handles()`, `NewPersistentHandle()`, `IsParked()`, `AllocateRaw()`, `AddGCEpilogueCallback()`, `ExecuteWhileParked()`. These are the external interface of the class.
* Private members like `state_`, `allocation_failed_`, `handles_`, `persistent_handles_`, `heap_`. These are the internal data of the class.
* Nested classes like `ThreadState` and `AtomicThreadState`. This suggests internal state management.
* Macros like `V8_WARN_UNUSED_RESULT`, `V8_INLINE`, `DCHECK`. These are V8-specific helpers for annotations, inlining, and debugging.
* Comments explaining the purpose of `LocalHeap`, particularly "Parked" and "Running" states.

**2. Understanding the Core Purpose (Based on Comments and Names):**

The comments are crucial. The initial description clearly states:

> `LocalHeap is used by the GC to track all threads with heap access in order to stop them before performing a collection.`

This is the central function. The "Parked" and "Running" states are also explained, giving immediate insight into how the GC interacts with threads.

**3. Deconstructing Public Methods and Their Implications:**

I go through the public methods, trying to understand what each one does and how it relates to the core purpose:

* **`Safepoint()`:**  The comment "Frequently invoked by local thread to check whether safepoint was requested" is key. This is the mechanism for threads to voluntarily give up control to the GC.
* **`handles()` and `NewPersistentHandle()`:** These clearly relate to object management. "Persistent handles" suggest a way to keep objects alive even across garbage collections.
* **`IsParked()`/`IsRunning()`:**  Accessors for the core state.
* **`AllocateRaw()`:**  Fundamental for memory allocation within the heap.
* **`AddGCEpilogueCallback()`:** A way to execute code *after* a GC, likely for cleanup or other post-GC tasks.
* **`ExecuteWhileParked()`:** This reinforces the "Parked" state concept and allows executing code when heap access isn't needed.

**4. Examining Private Members and Nested Classes:**

These provide more detail about the implementation:

* **`state_` (AtomicThreadState):**  The use of `std::atomic` is important. It indicates thread-safe management of the "Parked" and "Running" states, crucial for concurrency. The nested `ThreadState` and `AtomicThreadState` structures provide fine-grained control over the state bits.
* **`allocation_failed_`:**  Likely a flag to handle allocation retries.
* **`handles_`, `persistent_handles_`:**  Internal storage for the handle mechanisms.
* **`heap_`:** A pointer to the main `Heap` object, establishing the relationship.
* **`marking_barrier_`:** This relates to the garbage collection marking phase.

**5. Connecting to JavaScript (If Applicable):**

The prompt asks about the relationship to JavaScript. The key connection is the garbage collector. JavaScript's automatic memory management relies heavily on the GC. Therefore:

* **Memory allocation:** `AllocateRaw()` directly supports JavaScript object creation.
* **Garbage collection pauses:** The "Parked" and "Running" states are directly related to how the V8 engine pauses JavaScript execution for garbage collection. When the GC needs to run, it needs to bring all JavaScript threads to a "Parked" state.
* **Handles:**  JavaScript values are represented by handles in the C++ layer. `LocalHandles` and `PersistentHandles` are fundamental to managing these references.

**6. Considering Torque (Based on File Extension):**

The prompt mentions the `.tq` extension. While this file is `.h`, the prompt forces consideration. Torque is V8's type system and code generation tool. If this *were* a `.tq` file, it would define types and possibly generate C++ code related to the `LocalHeap` functionality. Since it's not, this point is less relevant, but it's important to address the prompt's condition.

**7. Code Logic Inference and Examples:**

For code logic, focusing on the state transitions (`Park()`, `Unpark()`, `Safepoint()`) is logical. I'd consider scenarios like:

* A thread starts in the "Running" state.
* The GC wants to run, so it requests a safepoint.
* The thread calls `Safepoint()` and detects the request.
* The thread transitions to the "Parked" state (potentially via `Park()`).
* The GC runs.
* The thread is unparked (via `Unpark()`) and resumes execution.

For JavaScript examples, I'd focus on actions that trigger GC or demonstrate the need for handles (e.g., creating many objects, closures).

**8. Common Programming Errors:**

Thinking about how this code is *used* helps identify potential errors:

* **Forgetting `Safepoint()`:** If a thread stays in "Running" for too long without calling `Safepoint()`, it can delay GC.
* **Incorrect parking/unparking:**  Manually manipulating the state without using the provided scopes could lead to deadlocks or race conditions.
* **Accessing the heap while parked:** This is explicitly disallowed and would lead to crashes or undefined behavior.

**9. Structuring the Answer:**

Finally, I organize the information into clear sections as requested by the prompt:

* **Functionality:**  Summarize the main purpose and key responsibilities.
* **Torque:** Address the `.tq` condition, even if it's not applicable.
* **JavaScript Relation:** Provide concrete examples of how `LocalHeap` relates to JavaScript concepts.
* **Code Logic:**  Describe the state transitions and provide hypothetical input/output.
* **Common Errors:** Give practical examples of how developers might misuse the functionality (even if indirectly through higher-level V8 APIs).

This systematic approach, combining code analysis, comment understanding, and knowledge of the underlying system (V8's GC), allows for a comprehensive explanation of the header file's purpose.
This header file, `v8/src/heap/local-heap.h`, defines the `LocalHeap` class in the V8 JavaScript engine. Let's break down its functionality:

**Core Functionality of `LocalHeap`:**

The primary responsibility of `LocalHeap` is to manage the interaction of individual threads with the V8 heap, particularly concerning garbage collection (GC). It ensures that threads accessing the heap can be safely stopped and resumed during GC cycles.

Here's a breakdown of its key functions:

1. **Tracking Threads with Heap Access:**  `LocalHeap` represents a thread that currently has the potential to access the V8 heap. The GC uses this information to coordinate when to pause threads for garbage collection.

2. **Managing Thread State (Parked vs. Running):**  A `LocalHeap` can be in one of two states:
   * **Running:** The thread is actively executing and allowed to access the heap. While running, the thread is responsible for periodically calling `Safepoint()` to give the GC a chance to initiate a collection.
   * **Parked:** The thread is temporarily prevented from accessing the heap. This is crucial for the GC to perform its operations without data corruption from concurrent modifications. Threads enter the parked state using mechanisms like `ParkedScope`.

3. **Safepoint Mechanism (`Safepoint()`):** This method allows a running thread to check if the main thread (which initiates GC) has requested a safepoint. If a safepoint is requested, the thread will take necessary steps to pause its heap access.

4. **Local and Persistent Handles:**  `LocalHeap` manages handles associated with a thread. Handles are smart pointers used to access objects within the V8 heap.
   * **Local Handles (`LocalHandles`):**  These are typically short-lived and tied to the current scope of a function or operation.
   * **Persistent Handles (`PersistentHandles`):** These handles allow keeping references to objects alive even across garbage collections.

5. **Allocation (`AllocateRaw()`):**  `LocalHeap` provides methods for allocating raw memory within the V8 heap for objects.

6. **Garbage Collection Callbacks (`AddGCEpilogueCallback()`):** Allows registering callbacks that are executed after each garbage collection cycle. This is useful for tasks that need to happen once the heap is in a consistent state post-GC.

7. **Linear Allocation Buffers (LABs):**  `LocalHeap` manages thread-local allocation buffers to speed up object allocation. Methods like `FreeLinearAllocationAreas()`, `MarkLinearAllocationAreasBlack()`, etc., are related to managing these buffers during GC.

8. **Main Thread Management:**  It distinguishes between the main thread (where the GC typically runs) and other background threads.

9. **Executing Code While Parked (`ExecuteWhileParked()`):**  Provides a mechanism to execute code that doesn't require heap access while ensuring the thread remains in the parked state.

**Is `v8/src/heap/local-heap.h` a Torque file?**

No, `v8/src/heap/local-heap.h` ends with `.h`, which signifies a standard C++ header file. Torque files in V8 typically end with `.tq`.

**Relationship to JavaScript and Examples:**

The `LocalHeap` is fundamental to how JavaScript code interacts with V8's memory management. Here's how it relates and some illustrative JavaScript examples:

* **Object Creation and Allocation:** When you create objects in JavaScript, V8 uses the `LocalHeap` (through its associated `Heap` object) to allocate memory for those objects.

   ```javascript
   let myObject = {}; // This will trigger memory allocation on the heap.
   ```

* **Garbage Collection Pauses:** When the V8 garbage collector needs to run, it needs to pause JavaScript execution. The `LocalHeap` plays a crucial role in coordinating this. The GC will signal threads to reach a safepoint and transition to the "Parked" state. While the GC is running, your JavaScript code is paused.

   ```javascript
   // Example:  Creating a lot of objects can eventually trigger a garbage collection.
   for (let i = 0; i < 1000000; i++) {
     let temp = { value: i };
   }
   ```

* **Persistent References (Closures):** JavaScript closures can keep objects alive even if they are no longer directly referenced in the main part of the code. Persistent handles managed by `LocalHeap` are part of the underlying mechanism that makes this possible.

   ```javascript
   function createCounter() {
     let count = 0;
     return function() { // The inner function forms a closure.
       count++;
       console.log(count);
     };
   }

   const myCounter = createCounter();
   myCounter(); // 1
   myCounter(); // 2

   // The 'count' variable, even though outside the scope of the call to myCounter(),
   // is kept alive due to the closure, and V8 uses mechanisms involving handles
   // to manage its lifetime.
   ```

**Code Logic Inference (Hypothetical Example):**

Let's consider a simplified scenario with a single thread:

**Hypothetical Input:**

1. A JavaScript function is being executed on a thread managed by a `LocalHeap`.
2. The function allocates several objects.
3. The main GC thread decides it's time for a garbage collection.

**Steps and Internal Logic (simplified):**

1. **GC Request:** The main GC thread sets a flag indicating a safepoint is needed.
2. **`Safepoint()` Call:**  The thread executing the JavaScript function periodically calls `local_heap->Safepoint()`.
3. **Check for Safepoint:** Inside `Safepoint()`, the `LocalHeap` checks the safepoint flag.
4. **Enter Parked State:** If the safepoint flag is set, the thread prepares to stop accessing the heap and transitions to the "Parked" state (potentially through a `ParkedScope`).
5. **GC Execution:** The main GC thread performs its garbage collection tasks, knowing that all active threads are now parked and won't interfere.
6. **Resume Threads:** Once GC is complete, the main thread signals the parked threads to resume.
7. **Exit Parked State:** The threads transition back to the "Running" state.
8. **Continue Execution:** The JavaScript function continues executing.

**Hypothetical Output:**

* During the GC pause, JavaScript execution is temporarily suspended.
* Memory for unreachable objects is reclaimed.
* The JavaScript function eventually completes its execution.

**Common Programming Errors (Relating to Concepts in `LocalHeap`):**

While you don't directly interact with `LocalHeap` in typical JavaScript programming, understanding its concepts helps understand potential issues:

1. **Memory Leaks (JavaScript side):**  If you create objects in JavaScript and hold onto references to them unnecessarily (e.g., in global variables or long-lived closures), the GC might not be able to collect them, leading to increased memory usage. This indirectly relates to how `LocalHeap` manages object lifetimes through handles.

   ```javascript
   let leakedObjects = [];
   function createAndLeak() {
     for (let i = 0; i < 1000; i++) {
       leakedObjects.push({ data: new Array(1000).fill(i) });
     }
   }
   createAndLeak(); // These objects in leakedObjects might not be collectible if not managed properly.
   ```

2. **Performance Issues due to Excessive GC:**  If your JavaScript code constantly creates and discards a large number of objects, it can put pressure on the garbage collector, leading to frequent pauses and impacting performance. This is directly related to how often the GC needs to invoke the safepoint mechanism managed by `LocalHeap`.

   ```javascript
   function processData() {
     for (let i = 0; i < 10000; i++) {
       let tempResult = expensiveCalculation(); // Creates temporary objects.
       // ... do something with tempResult ...
     }
   }
   ```

3. **Unintended Object Retention (Closures):** As shown in the closure example above, understanding how closures can keep objects alive is crucial to avoid unintended memory retention. This connects to the concept of persistent handles.

**In summary, `v8/src/heap/local-heap.h` defines a critical component within the V8 engine responsible for managing thread interaction with the heap during garbage collection. It ensures the safety and correctness of memory management while allowing concurrent JavaScript execution.**

### 提示词
```
这是目录为v8/src/heap/local-heap.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/local-heap.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_LOCAL_HEAP_H_
#define V8_HEAP_LOCAL_HEAP_H_

#include <atomic>
#include <memory>

#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/platform/condition-variable.h"
#include "src/base/platform/mutex.h"
#include "src/common/assert-scope.h"
#include "src/common/ptr-compr.h"
#include "src/common/thread-local-storage.h"
#include "src/execution/isolate.h"
#include "src/handles/global-handles.h"
#include "src/handles/persistent-handles.h"
#include "src/heap/base/stack.h"
#include "src/heap/gc-callbacks.h"

namespace v8 {
namespace internal {

class Heap;
class LocalHandles;
class MarkingBarrier;
class MutablePageMetadata;
class Safepoint;

// Do not use this variable directly, use LocalHeap::Current() instead.
// Defined outside of LocalHeap because LocalHeap uses V8_EXPORT_PRIVATE.
__attribute__((tls_model(V8_TLS_MODEL))) extern thread_local LocalHeap*
    g_current_local_heap_ V8_CONSTINIT;

// LocalHeap is used by the GC to track all threads with heap access in order to
// stop them before performing a collection. LocalHeaps can be either Parked or
// Running and are in Parked mode when initialized.
//   Running: Thread is allowed to access the heap but needs to give the GC the
//            chance to run regularly by manually invoking Safepoint(). The
//            thread can be parked using ParkedScope.
//   Parked:  Heap access is not allowed, so the GC will not stop this thread
//            for a collection. Useful when threads do not need heap access for
//            some time or for blocking operations like locking a mutex.
class V8_EXPORT_PRIVATE LocalHeap {
 public:
  using GCEpilogueCallback = void(void*);

  explicit LocalHeap(
      Heap* heap, ThreadKind kind,
      std::unique_ptr<PersistentHandles> persistent_handles = nullptr);
  ~LocalHeap();

  // Frequently invoked by local thread to check whether safepoint was requested
  // from the main thread.
  void Safepoint() {
    DCHECK(AllowSafepoints::IsAllowed());
    ThreadState current = state_.load_relaxed();

    if (V8_UNLIKELY(current.IsRunningWithSlowPathFlag())) {
      SafepointSlowPath();
    }
  }

  LocalHandles* handles() { return handles_.get(); }

  template <typename T>
  IndirectHandle<T> NewPersistentHandle(Tagged<T> object) {
    if (!persistent_handles_) {
      EnsurePersistentHandles();
    }
    return persistent_handles_->NewHandle(object);
  }

  template <typename T, template <typename> typename HandleType,
            typename = std::enable_if_t<
                std::is_convertible_v<HandleType<T>, DirectHandle<T>>>>
  IndirectHandle<T> NewPersistentHandle(HandleType<T> object) {
    return NewPersistentHandle(*object);
  }

  template <typename T>
  IndirectHandle<T> NewPersistentHandle(T object) {
    static_assert(kTaggedCanConvertToRawObjects);
    return NewPersistentHandle(Tagged<T>(object));
  }

  template <typename T, template <typename> typename MaybeHandleType,
            typename = std::enable_if_t<std::is_convertible_v<
                MaybeHandleType<T>, MaybeDirectHandle<T>>>>
  MaybeIndirectHandle<T> NewPersistentMaybeHandle(
      MaybeHandleType<T> maybe_handle) {
    DirectHandle<T> handle;
    if (maybe_handle.ToHandle(&handle)) {
      return NewPersistentHandle(handle);
    }
    return kNullMaybeHandle;
  }

  void AttachPersistentHandles(
      std::unique_ptr<PersistentHandles> persistent_handles);
  std::unique_ptr<PersistentHandles> DetachPersistentHandles();
#ifdef DEBUG
  bool HasPersistentHandles() { return !!persistent_handles_; }
  bool ContainsPersistentHandle(Address* location);
  bool ContainsLocalHandle(Address* location);
  bool IsHandleDereferenceAllowed();
#endif

  bool IsParked() const;
  bool IsRunning() const;

  bool IsRetryOfFailedAllocation() const { return allocation_failed_; }

  void SetRetryOfFailedAllocation(bool value) { allocation_failed_ = value; }

  Heap* heap() const { return heap_; }
  Heap* AsHeap() const { return heap(); }

  // Heap root getters.
#define ROOT_ACCESSOR(type, name, CamelName) inline Tagged<type> name();
  MUTABLE_ROOT_LIST(ROOT_ACCESSOR)
#undef ROOT_ACCESSOR

  MarkingBarrier* marking_barrier() { return marking_barrier_.get(); }

  // Give up all LABs. Used for e.g. full GCs.
  void FreeLinearAllocationAreas();

#if DEBUG
  void VerifyLinearAllocationAreas() const;
#endif  // DEBUG

  // Make all LABs iterable.
  void MakeLinearAllocationAreasIterable();

  // Mark/Unmark all LABs except for new and shared space. Use for black
  // allocation.
  void MarkLinearAllocationAreasBlack();
  void UnmarkLinearAllocationsArea();

  // Mark/Unmark linear allocation areas in shared heap black. Used for black
  // allocation.
  void MarkSharedLinearAllocationAreasBlack();
  void UnmarkSharedLinearAllocationsArea();

  // Free all LABs and reset free-lists except for the new and shared space.
  // Used on black allocation.
  void FreeLinearAllocationAreasAndResetFreeLists();
  void FreeSharedLinearAllocationAreasAndResetFreeLists();

  // Fetches a pointer to the local heap from the thread local storage.
  // It is intended to be used in handle and write barrier code where it is
  // difficult to get a pointer to the current instance of local heap otherwise.
  // The result may be a nullptr if there is no local heap instance associated
  // with the current thread.
  V8_TLS_DECLARE_GETTER(Current, LocalHeap*, g_current_local_heap_)

  static void SetCurrent(LocalHeap* local_heap);

#ifdef DEBUG
  void VerifyCurrent() const;
#endif

  // Allocate an uninitialized object.
  V8_WARN_UNUSED_RESULT inline AllocationResult AllocateRaw(
      int size_in_bytes, AllocationType allocation,
      AllocationOrigin origin = AllocationOrigin::kRuntime,
      AllocationAlignment alignment = kTaggedAligned);

  // Allocate an uninitialized object.
  template <HeapAllocator::AllocationRetryMode mode>
  Tagged<HeapObject> AllocateRawWith(
      int size_in_bytes, AllocationType allocation,
      AllocationOrigin origin = AllocationOrigin::kRuntime,
      AllocationAlignment alignment = kTaggedAligned);

  // Allocates an uninitialized object and crashes when object
  // cannot be allocated.
  V8_WARN_UNUSED_RESULT inline Address AllocateRawOrFail(
      int size_in_bytes, AllocationType allocation,
      AllocationOrigin origin = AllocationOrigin::kRuntime,
      AllocationAlignment alignment = kTaggedAligned);

  void NotifyObjectSizeChange(Tagged<HeapObject> object, int old_size,
                              int new_size,
                              ClearRecordedSlots clear_recorded_slots);

  bool is_main_thread() const { return is_main_thread_; }
  bool is_main_thread_for(Heap* heap) const {
    return is_main_thread() && heap_ == heap;
  }
  V8_INLINE bool is_in_trampoline() const;

  bool deserialization_complete() const {
    return heap_->deserialization_complete();
  }
  ReadOnlySpace* read_only_space() { return heap_->read_only_space(); }

  // Adds a callback that is invoked with the given |data| after each GC.
  // The callback is invoked on the main thread before any background thread
  // resumes. The callback must not allocate or make any other calls that
  // can trigger GC.
  void AddGCEpilogueCallback(GCEpilogueCallback* callback, void* data,
                             GCCallbacksInSafepoint::GCType gc_type =
                                 GCCallbacksInSafepoint::GCType::kAll);
  void RemoveGCEpilogueCallback(GCEpilogueCallback* callback, void* data);

  // Weakens StrongDescriptorArray objects into regular DescriptorArray objects.
  void WeakenDescriptorArrays(
      GlobalHandleVector<DescriptorArray> strong_descriptor_arrays);

  // Used to make SetupMainThread() available to unit tests.
  void SetUpMainThreadForTesting();

  // Execute the callback while the local heap is parked. All threads must
  // always park via these methods, not directly with `ParkedScope`.
  // The callback must be a callable object, expecting either no parameters or a
  // const ParkedScope&, which serves as a witness for parking. The first
  // variant checks if we are on the main thread or not. Use the other two
  // variants if this already known.
  template <typename Callback>
  V8_INLINE void ExecuteWhileParked(Callback callback);
  template <typename Callback>
  V8_INLINE void ExecuteMainThreadWhileParked(Callback callback);
  template <typename Callback>
  V8_INLINE void ExecuteBackgroundThreadWhileParked(Callback callback);

 private:
  using ParkedBit = base::BitField8<bool, 0, 1>;
  using SafepointRequestedBit = ParkedBit::Next<bool, 1>;
  using CollectionRequestedBit = SafepointRequestedBit::Next<bool, 1>;

  class ThreadState final {
   public:
    static constexpr ThreadState Parked() {
      return ThreadState(ParkedBit::kMask);
    }
    static constexpr ThreadState Running() { return ThreadState(0); }

    constexpr bool IsRunning() const { return !ParkedBit::decode(raw_state_); }

    constexpr ThreadState SetRunning() const V8_WARN_UNUSED_RESULT {
      return ThreadState(raw_state_ & ~ParkedBit::kMask);
    }

    constexpr bool IsParked() const { return ParkedBit::decode(raw_state_); }

    constexpr ThreadState SetParked() const V8_WARN_UNUSED_RESULT {
      return ThreadState(ParkedBit::kMask | raw_state_);
    }

    constexpr bool IsSafepointRequested() const {
      return SafepointRequestedBit::decode(raw_state_);
    }

    constexpr bool IsCollectionRequested() const {
      return CollectionRequestedBit::decode(raw_state_);
    }

    constexpr bool IsRunningWithSlowPathFlag() const {
      return IsRunning() && (raw_state_ & (SafepointRequestedBit::kMask |
                                           CollectionRequestedBit::kMask));
    }

   private:
    constexpr explicit ThreadState(uint8_t value) : raw_state_(value) {}

    constexpr uint8_t raw() const { return raw_state_; }

    uint8_t raw_state_;

    friend class LocalHeap;
  };

  class AtomicThreadState final {
   public:
    constexpr explicit AtomicThreadState(ThreadState state)
        : raw_state_(state.raw()) {}

    bool CompareExchangeStrong(ThreadState& expected, ThreadState updated) {
      return raw_state_.compare_exchange_strong(expected.raw_state_,
                                                updated.raw());
    }

    bool CompareExchangeWeak(ThreadState& expected, ThreadState updated) {
      return raw_state_.compare_exchange_weak(expected.raw_state_,
                                              updated.raw());
    }

    ThreadState SetParked() {
      return ThreadState(raw_state_.fetch_or(ParkedBit::kMask));
    }

    ThreadState SetSafepointRequested() {
      return ThreadState(raw_state_.fetch_or(SafepointRequestedBit::kMask));
    }

    ThreadState ClearSafepointRequested() {
      return ThreadState(raw_state_.fetch_and(~SafepointRequestedBit::kMask));
    }

    ThreadState SetCollectionRequested() {
      return ThreadState(raw_state_.fetch_or(CollectionRequestedBit::kMask));
    }

    ThreadState ClearCollectionRequested() {
      return ThreadState(raw_state_.fetch_and(~CollectionRequestedBit::kMask));
    }

    ThreadState load_relaxed() const {
      return ThreadState(raw_state_.load(std::memory_order_relaxed));
    }

   private:
    std::atomic<uint8_t> raw_state_;
  };

#ifdef DEBUG
  bool IsSafeForConservativeStackScanning() const;
#endif

  template <typename Callback>
  V8_INLINE void ExecuteWithStackMarker(Callback callback);

  void Park() {
    DCHECK(AllowSafepoints::IsAllowed());
    DCHECK(IsSafeForConservativeStackScanning());
    ThreadState expected = ThreadState::Running();
    if (!state_.CompareExchangeWeak(expected, ThreadState::Parked())) {
      ParkSlowPath();
    }
  }

  void Unpark() {
    DCHECK(AllowSafepoints::IsAllowed());
    ThreadState expected = ThreadState::Parked();
    if (!state_.CompareExchangeWeak(expected, ThreadState::Running())) {
      UnparkSlowPath();
    }
  }

  void ParkSlowPath();
  void UnparkSlowPath();
  void EnsureParkedBeforeDestruction();
  void SafepointSlowPath();
  void SleepInSafepoint();
  void SleepInUnpark();

  template <typename Callback>
  V8_INLINE void ParkAndExecuteCallback(Callback callback);

  void EnsurePersistentHandles();

  void InvokeGCEpilogueCallbacksInSafepoint(
      GCCallbacksInSafepoint::GCType gc_type);

  // Set up this LocalHeap as main thread.
  void SetUpMainThread(LinearAllocationArea& new_allocation_info,
                       LinearAllocationArea& old_allocation_info);

  void SetUpMarkingBarrier();
  void SetUpSharedMarking();

  Heap* heap_;
  V8_NO_UNIQUE_ADDRESS PtrComprCageAccessScope ptr_compr_cage_access_scope_;
  bool is_main_thread_;

  AtomicThreadState state_;

  bool allocation_failed_;
  int nested_parked_scopes_;

  Isolate* saved_current_isolate_ = nullptr;

  LocalHeap* prev_;
  LocalHeap* next_;

  std::unique_ptr<LocalHandles> handles_;
  std::unique_ptr<PersistentHandles> persistent_handles_;
  std::unique_ptr<MarkingBarrier> marking_barrier_;

  GCCallbacksInSafepoint gc_epilogue_callbacks_;

  HeapAllocator heap_allocator_;

  MarkingBarrier* saved_marking_barrier_ = nullptr;

  // Stack information for the thread using this local heap.
  ::heap::base::Stack stack_;

  friend class CollectionBarrier;
  friend class GlobalSafepoint;
  friend class Heap;
  friend class Isolate;
  friend class IsolateSafepoint;
  friend class IsolateSafepointScope;
  friend class ParkedScope;
  friend class UnparkedScope;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_LOCAL_HEAP_H_
```