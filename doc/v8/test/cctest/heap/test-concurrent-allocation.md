Response:
Let's break down the thought process for analyzing the C++ code and answering the request.

1. **Initial Scan and Understanding the Purpose:**

   - The file name `test-concurrent-allocation.cc` immediately suggests its primary function: testing concurrent allocation within the V8 heap.
   - The `#include` directives confirm this, bringing in relevant headers like `heap/heap.h`, `heap/local-heap-inl.h`, `base/platform/thread.h`, etc. These are clearly related to memory management, threading, and testing.
   - The presence of `UNINITIALIZED_TEST` macros points to this being a unit test file within the V8 testing framework.

2. **Dissecting the Code - Key Components and Their Roles:**

   - **Helper Function `CreateFixedArray`:**  This function takes a memory address and size and initializes it as a `FixedArray`. This is a basic V8 data structure. The code clearly sets the map, length, and fills the array with `undefined`.

   - **Constants `kNumIterations`, `kSmallObjectSize`, `kMediumObjectSize`:** These define parameters for the allocation loops, indicating the test involves creating a number of small and medium-sized objects.

   - **Helper Function `AllocateSomeObjects`:** This is the core allocation logic. It repeatedly allocates small and medium objects using `LocalHeap`, initializes them as `FixedArray`s, and occasionally calls `local_heap->Safepoint()`. The `Safepoint()` suggests this is testing scenarios where garbage collection might occur.

   - **Class `ConcurrentAllocationThread`:** This class encapsulates the logic for performing allocations in a separate thread. It has a `LocalHeap`, allocates objects using `AllocateSomeObjects`, and handles synchronization using `std::atomic<int>`.

   - **Test Cases (`UNINITIALIZED_TEST`):** Each test case focuses on a specific scenario of concurrent allocation:
      - `ConcurrentAllocationInOldSpace`: Multiple threads allocating in old space.
      - `ConcurrentAllocationInOldSpaceFromMainThread`: Allocation solely on the main thread.
      - `ConcurrentAllocationWhileMainThreadIsParked`:  Background threads allocate while the main thread is parked (not actively executing JavaScript).
      - `ConcurrentAllocationWhileMainThreadParksAndUnparks`:  Background threads allocate while the main thread repeatedly parks and unparks.
      - `ConcurrentAllocationWhileMainThreadRunsWithSafepoints`: Background threads allocate while the main thread executes and explicitly calls `Safepoint()`.
      - `ConcurrentAllocationInLargeSpace`: Similar to `ConcurrentAllocationInOldSpace` but for large objects.
      - `ConcurrentBlackAllocation`: Tests allocation during incremental marking, specifically looking at black allocation.
      - `ConcurrentWriteBarrier`: Tests the write barrier mechanism during concurrent marking.
      - `ConcurrentRecordRelocSlot`: Tests updating relocation information in code objects concurrently with marking.

   - **Class `LargeObjectConcurrentAllocationThread`:**  Similar to `ConcurrentAllocationThread` but specifically for allocating large objects. It includes logic to trigger garbage collection if allocation fails.

   - **Class `ConcurrentBlackAllocationThread`:** Focuses on allocating objects while incremental marking is in progress. It uses semaphores for synchronization.

   - **Class `ConcurrentWriteBarrierThread`:**  Simulates a concurrent write to an object while marking is in progress to test the write barrier.

   - **Class `ConcurrentRecordRelocSlotThread`:** Simulates updating relocation information in code objects concurrently with marking.

3. **Identifying Core Functionality:**

   - The primary function is to test the robustness and correctness of V8's heap allocation mechanisms when multiple threads are allocating objects concurrently.
   - It specifically tests scenarios involving different object sizes, allocation spaces (old space, large object space), and interactions with garbage collection (safepoints, incremental marking, write barriers).

4. **Considering the `.tq` Extension:**

   - The prompt asks what if the extension were `.tq`. This immediately brings Torque into mind. Torque is V8's domain-specific language for writing built-in functions.
   - The key difference is that `.cc` is C++, which deals with lower-level memory management and core engine functionality, while `.tq` is for higher-level JavaScript built-in implementations.

5. **Relating to JavaScript:**

   -  The connection to JavaScript is that these tests directly validate the underlying memory management that makes JavaScript object creation and manipulation possible.
   -  Think about how JavaScript code creates objects: `const obj = {};`, `const arr = [];`, `function MyClass() {} new MyClass();`. These operations rely on the V8 heap allocation being tested here.

6. **Crafting the JavaScript Example:**

   - The JavaScript example needs to be simple yet illustrate the concept of concurrent object creation. Using `Promise.all` with a loop to simulate concurrent execution achieves this. The creation of plain objects `({})` maps directly to the allocation concepts in the C++ code.

7. **Code Logic Reasoning (Hypothetical):**

   -  The request asks for hypothetical input/output. Since it's a test file, the "input" is the configuration of the V8 engine (flags) and the "output" is whether the tests pass or fail.
   -  A good example would be the `ConcurrentBlackAllocation` test, where the expectation is that objects allocated *before* marking starts are white (unmarked), and those allocated *during* marking can be black (marked, or in a black-allocated chunk).

8. **Common Programming Errors:**

   -  The focus here is on *concurrent* allocation. The most common errors in concurrent programming are race conditions and deadlocks.
   -  A race condition example would be if two threads try to modify the same memory location without proper synchronization, leading to unpredictable results.
   -  A deadlock example could involve two threads waiting for each other to release a resource. While this specific test file doesn't directly *show* those errors, it's designed to *prevent* them in the V8 engine itself. The provided example of incorrect locking demonstrates a general concurrency issue.

9. **Structuring the Answer:**

   - Organize the answer logically, addressing each part of the request systematically.
   - Start with the core functionality, then address the `.tq` scenario, JavaScript relevance, code logic, and finally, common errors.
   - Use clear and concise language. Explain technical terms when necessary.

**Self-Correction/Refinement During the Process:**

- Initially, I might have focused too much on the low-level details of each test. The key is to abstract the purpose and relate it to the broader context of concurrent allocation testing.
- When considering the JavaScript example, I considered different concurrency mechanisms (workers, async/await), but `Promise.all` offered a simple and effective way to simulate concurrency for demonstration.
- For the "common errors," it's important to distinguish between errors the *test* is designed to catch in V8, and general concurrent programming errors.

By following these steps, the detailed and accurate answer provided in the initial example can be constructed.
The C++ source code file `v8/test/cctest/heap/test-concurrent-allocation.cc` is a **test file** within the V8 JavaScript engine's testing framework. Its primary function is to **verify the correctness and robustness of V8's heap allocation mechanisms when multiple threads are allocating objects concurrently.**

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Concurrent Object Allocation Testing:** The file contains several test cases that simulate scenarios where multiple threads are simultaneously allocating objects in the V8 heap. This helps ensure that V8's allocation logic is thread-safe and doesn't lead to crashes, corruption, or incorrect allocation behavior.

2. **Testing Different Allocation Spaces:** The tests cover allocation in different parts of the heap, including:
   - **Old Space:**  The primary area for long-lived objects. Tests like `ConcurrentAllocationInOldSpace` directly target this.
   - **Large Object Space:**  For objects exceeding a certain size threshold. The `ConcurrentAllocationInLargeSpace` test focuses on this.

3. **Testing with Main Thread Interaction:** Some tests examine how concurrent allocation interacts with the main JavaScript execution thread:
   - `ConcurrentAllocationWhileMainThreadIsParked`:  Tests allocation when the main thread is temporarily inactive.
   - `ConcurrentAllocationWhileMainThreadParksAndUnparks`: Simulates frequent parking and unparking of the main thread during concurrent allocation.
   - `ConcurrentAllocationWhileMainThreadRunsWithSafepoints`: Tests concurrent allocation while the main thread is running and reaching safepoints (points where garbage collection can occur).

4. **Testing During Garbage Collection:** Several tests are specifically designed to evaluate concurrent allocation during different phases of garbage collection:
   - `ConcurrentBlackAllocation`: Tests allocation during incremental marking, where objects allocated after marking starts might be colored "black."
   - `ConcurrentWriteBarrier`: Verifies the write barrier mechanism, which ensures that the garbage collector is notified when an object is modified concurrently.
   - `ConcurrentRecordRelocSlot`: Tests the concurrent modification of relocation information in compiled code objects during garbage collection.

5. **Using Local Heaps:** The tests utilize `LocalHeap` objects for each thread. This is a mechanism in V8 that allows threads other than the main thread to allocate objects within their own isolated allocation buffers, reducing contention and improving performance.

6. **Synchronization Primitives:** The tests employ synchronization primitives like `std::atomic`, `base::Semaphore`, and mutexes to coordinate the actions of multiple threads and ensure proper test execution.

**If `v8/test/cctest/heap/test-concurrent-allocation.cc` ended with `.tq`:**

If the file ended with `.tq`, it would be a **V8 Torque source code file**. Torque is V8's domain-specific language used for implementing JavaScript built-in functions and runtime libraries. In this hypothetical scenario, the file would likely contain Torque code related to:

- **Implementation of heap allocation primitives:**  Torque might be used to define the low-level logic for allocating objects in the heap.
- **Implementation of garbage collection mechanisms:**  Parts of the garbage collector, especially those dealing with concurrent operations, could be written in Torque.

**Relationship with JavaScript and Examples:**

This C++ test file directly relates to how JavaScript manages memory and creates objects. Every time you create an object, an array, a function, or any other data structure in JavaScript, V8's heap allocation mechanisms, which are being tested here, come into play.

**JavaScript Example:**

```javascript
// Simulate concurrent object creation in JavaScript (conceptually)

async function createObjects() {
  const objects = [];
  for (let i = 0; i < 1000; i++) {
    objects.push({}); // Creating a new object
  }
  return objects;
}

async function main() {
  const promises = [];
  for (let i = 0; i < 4; i++) {
    promises.push(createObjects()); // Multiple "threads" creating objects
  }
  await Promise.all(promises);
  console.log("Finished creating objects concurrently.");
}

main();
```

This JavaScript code simulates concurrent object creation using `async/await` and `Promise.all`. While JavaScript itself is single-threaded, V8's internal implementation handles the underlying memory allocation, and the C++ tests ensure this allocation is safe and correct even under concurrent pressure.

**Code Logic Reasoning (Hypothetical):**

Let's take the `ConcurrentBlackAllocation` test as an example:

**Hypothetical Input:**

1. V8 is configured with incremental marking enabled (`v8_flags.incremental_marking = true`).
2. A background thread starts allocating objects.
3. After a certain number of allocations (`kWhiteIterations`), the main thread triggers the start of incremental marking.
4. The background thread continues allocating objects.

**Hypothetical Output:**

- Objects allocated **before** incremental marking starts should be considered "white" (unmarked) by the garbage collector.
- Objects allocated **after** incremental marking starts, especially if V8's "black allocation" feature is enabled, might be allocated in memory chunks marked as "black," indicating they are considered live by the garbage collector from the moment of allocation.

**Code Snippet from `ConcurrentBlackAllocation` demonstrating the logic:**

```c++
    for (int i = 0; i < kNumIterations * kObjectsAllocatedPerIteration; i++) {
      Address address = objects[i];
      Tagged<HeapObject> object = HeapObject::FromAddress(address);
      if (v8_flags.black_allocated_pages) {
        CHECK(heap->marking_state()->IsUnmarked(object));
        if (i < kWhiteIterations * kObjectsAllocatedPerIteration) {
          CHECK(!PageMetadata::FromHeapObject(object)->Chunk()->IsFlagSet(
              MemoryChunk::BLACK_ALLOCATED));
        } else {
          CHECK(PageMetadata::FromHeapObject(object)->Chunk()->IsFlagSet(
              MemoryChunk::BLACK_ALLOCATED));
        }
      } else {
        if (i < kWhiteIterations * kObjectsAllocatedPerIteration) {
          CHECK(heap->marking_state()->IsUnmarked(object));
        } else {
          CHECK(heap->marking_state()->IsMarked(object));
        }
      }
    }
```

This code verifies that objects allocated before the marking phase are indeed unmarked, and objects allocated afterward might reside in black-allocated chunks or be marked, depending on the V8 configuration.

**User-Common Programming Errors:**

This test file is designed to prevent errors *within V8's implementation*. However, the concepts it tests are relevant to common programming errors users might encounter when dealing with concurrency in other contexts:

1. **Race Conditions:** When multiple threads access and modify shared resources (like the heap in V8's case) without proper synchronization, it can lead to unpredictable and incorrect behavior. V8's concurrent allocation mechanisms are designed to avoid these race conditions.

   **Example (Conceptual, not directly reproducible in safe JavaScript):** Imagine two threads trying to increment a shared counter without a lock. The final value might be incorrect.

   ```c++
   // Hypothetical error scenario (simplified)
   int counter = 0;

   void thread1_function() {
     // Potential race condition: read, increment, write
     int current_value = counter;
     // ... context switch ...
     counter = current_value + 1;
   }

   void thread2_function() {
     // Same potential race condition
     int current_value = counter;
     // ... context switch ...
     counter = current_value + 1;
   }
   ```

2. **Deadlocks:**  Occur when two or more threads are blocked indefinitely, waiting for each other to release resources. While V8 tries to avoid internal deadlocks, users working with threads in native modules could encounter this.

   **Example (Conceptual):**

   ```c++
   std::mutex mutex1, mutex2;

   void thread1_function() {
     mutex1.lock();
     // ... do something ...
     mutex2.lock(); // Waits for mutex2
     // ...
     mutex2.unlock();
     mutex1.unlock();
   }

   void thread2_function() {
     mutex2.lock();
     // ... do something ...
     mutex1.lock(); // Waits for mutex1
     // ...
     mutex1.unlock();
     mutex2.unlock();
   }
   ```
   If `thread1_function` holds `mutex1` and `thread2_function` holds `mutex2`, they will be stuck waiting for each other.

3. **Memory Corruption:**  If concurrent allocation or memory management isn't handled correctly, it can lead to memory corruption, where data is overwritten or accessed incorrectly, leading to crashes or unpredictable behavior. This is precisely what V8's concurrent allocation tests aim to prevent within the engine.

In summary, `v8/test/cctest/heap/test-concurrent-allocation.cc` is a critical test file that rigorously examines the thread-safety and correctness of V8's heap allocation mechanisms under concurrent conditions, ensuring the stability and reliability of the JavaScript engine.

### 提示词
```
这是目录为v8/test/cctest/heap/test-concurrent-allocation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-concurrent-allocation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "src/api/api.h"
#include "src/base/platform/condition-variable.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/semaphore.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/assembler.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/reloc-info-inl.h"
#include "src/common/globals.h"
#include "src/handles/global-handles-inl.h"
#include "src/handles/handles-inl.h"
#include "src/handles/handles.h"
#include "src/handles/local-handles-inl.h"
#include "src/handles/persistent-handles.h"
#include "src/heap/heap.h"
#include "src/heap/local-heap-inl.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/parked-scope.h"
#include "src/heap/safepoint.h"
#include "src/objects/heap-number.h"
#include "src/objects/heap-object.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"

namespace v8 {
namespace internal {

namespace {
void CreateFixedArray(Heap* heap, Address start, int size) {
  Tagged<HeapObject> object = HeapObject::FromAddress(start);
  object->set_map_after_allocation(heap->isolate(),
                                   ReadOnlyRoots(heap).fixed_array_map(),
                                   SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(object);
  int length = (size - OFFSET_OF_DATA_START(FixedArray)) / kTaggedSize;
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(),
               ReadOnlyRoots(heap).undefined_value(), length);
}

const int kNumIterations = 2000;
const int kSmallObjectSize = 10 * kTaggedSize;
const int kMediumObjectSize = 8 * KB;

void AllocateSomeObjects(LocalHeap* local_heap) {
  for (int i = 0; i < kNumIterations; i++) {
    AllocationResult result = local_heap->AllocateRaw(
        kSmallObjectSize, AllocationType::kOld, AllocationOrigin::kRuntime,
        AllocationAlignment::kTaggedAligned);
    if (!result.IsFailure()) {
      CreateFixedArray(local_heap->heap(), result.ToAddress(),
                       kSmallObjectSize);
    }
    result = local_heap->AllocateRaw(kMediumObjectSize, AllocationType::kOld,
                                     AllocationOrigin::kRuntime,
                                     AllocationAlignment::kTaggedAligned);
    if (!result.IsFailure()) {
      CreateFixedArray(local_heap->heap(), result.ToAddress(),
                       kMediumObjectSize);
    }
    if (i % 10 == 0) {
      local_heap->Safepoint();
    }
  }
}
}  // namespace

class ConcurrentAllocationThread final : public v8::base::Thread {
 public:
  explicit ConcurrentAllocationThread(Heap* heap,
                                      std::atomic<int>* pending = nullptr)
      : v8::base::Thread(base::Thread::Options("ThreadWithLocalHeap")),
        heap_(heap),
        pending_(pending) {}

  void Run() override {
    LocalHeap local_heap(heap_, ThreadKind::kBackground);
    UnparkedScope unparked_scope(&local_heap);
    AllocateSomeObjects(&local_heap);
    if (pending_) pending_->fetch_sub(1);
  }

  Heap* heap_;
  std::atomic<int>* pending_;
};

UNINITIALIZED_TEST(ConcurrentAllocationInOldSpace) {
  v8_flags.max_old_space_size = 32;
  v8_flags.stress_concurrent_allocation = false;

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);

  std::vector<std::unique_ptr<ConcurrentAllocationThread>> threads;

  const int kThreads = 4;

  std::atomic<int> pending(kThreads);

  for (int i = 0; i < kThreads; i++) {
    auto thread = std::make_unique<ConcurrentAllocationThread>(
        i_isolate->heap(), &pending);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  while (pending > 0) {
    v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(), isolate);
  }

  for (auto& thread : threads) {
    thread->Join();
  }

  isolate->Dispose();
}

UNINITIALIZED_TEST(ConcurrentAllocationInOldSpaceFromMainThread) {
  v8_flags.max_old_space_size = 4;
  v8_flags.stress_concurrent_allocation = false;

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);

  {
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    AllocateSomeObjects(i_isolate->main_thread_local_heap());
  }
  isolate->Dispose();
}

UNINITIALIZED_TEST(ConcurrentAllocationWhileMainThreadIsParked) {
#ifndef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
  v8_flags.max_old_space_size = 4;
#else
  // With CSS, it is expected that the GCs triggered by concurrent allocation
  // will reclaim less memory. If this test fails, this limit should probably
  // be further increased.
  v8_flags.max_old_space_size = 10;
#endif
  v8_flags.stress_concurrent_allocation = false;

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);

  std::vector<std::unique_ptr<ConcurrentAllocationThread>> threads;
  const int kThreads = 4;

  i_isolate->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      [i_isolate, &threads]() {
        for (int i = 0; i < kThreads; i++) {
          auto thread =
              std::make_unique<ConcurrentAllocationThread>(i_isolate->heap());
          CHECK(thread->Start());
          threads.push_back(std::move(thread));
        }

        for (auto& thread : threads) {
          thread->Join();
        }
      });

  isolate->Dispose();
}

UNINITIALIZED_TEST(ConcurrentAllocationWhileMainThreadParksAndUnparks) {
#ifndef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
  v8_flags.max_old_space_size = 4;
#else
  // With CSS, it is expected that the GCs triggered by concurrent allocation
  // will reclaim less memory. If this test fails, this limit should probably
  // be further increased.
  v8_flags.max_old_space_size = 10;
#endif
  v8_flags.stress_concurrent_allocation = false;
  v8_flags.incremental_marking = false;
  i::FlagList::EnforceFlagImplications();

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);

  std::vector<std::unique_ptr<ConcurrentAllocationThread>> threads;
  const int kThreads = 4;

  {
    for (int i = 0; i < kThreads; i++) {
      auto thread =
          std::make_unique<ConcurrentAllocationThread>(i_isolate->heap());
      CHECK(thread->Start());
      threads.push_back(std::move(thread));
    }

    for (int i = 0; i < 300'000; i++) {
      i_isolate->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
          []() { /* nothing */ });
    }

    i_isolate->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
        [&threads]() {
          for (auto& thread : threads) {
            thread->Join();
          }
        });
  }

  isolate->Dispose();
}

UNINITIALIZED_TEST(ConcurrentAllocationWhileMainThreadRunsWithSafepoints) {
#ifndef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
  v8_flags.max_old_space_size = 4;
#else
  // With CSS, it is expected that the GCs triggered by concurrent allocation
  // will reclaim less memory. If this test fails, this limit should probably
  // be further increased.
  v8_flags.max_old_space_size = 10;
#endif
  v8_flags.stress_concurrent_allocation = false;
  v8_flags.incremental_marking = false;
  i::FlagList::EnforceFlagImplications();

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);

  std::vector<std::unique_ptr<ConcurrentAllocationThread>> threads;
  const int kThreads = 4;

  {
    for (int i = 0; i < kThreads; i++) {
      auto thread =
          std::make_unique<ConcurrentAllocationThread>(i_isolate->heap());
      CHECK(thread->Start());
      threads.push_back(std::move(thread));
    }

    // Some of the following Safepoint() invocations are supposed to perform a
    // GC.
    for (int i = 0; i < 1'000'000; i++) {
      i_isolate->main_thread_local_heap()->Safepoint();
    }

    i_isolate->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
        [&threads]() {
          for (auto& thread : threads) {
            thread->Join();
          }
        });
  }

  i_isolate->main_thread_local_heap()->Safepoint();
  isolate->Dispose();
}

class LargeObjectConcurrentAllocationThread final : public v8::base::Thread {
 public:
  explicit LargeObjectConcurrentAllocationThread(Heap* heap,
                                                 std::atomic<int>* pending)
      : v8::base::Thread(base::Thread::Options("ThreadWithLocalHeap")),
        heap_(heap),
        pending_(pending) {}

  void Run() override {
    LocalHeap local_heap(heap_, ThreadKind::kBackground);
    UnparkedScope unparked_scope(&local_heap);
    const size_t kLargeObjectSize = kMaxRegularHeapObjectSize * 2;

    for (int i = 0; i < kNumIterations; i++) {
      AllocationResult result = local_heap.AllocateRaw(
          kLargeObjectSize, AllocationType::kOld, AllocationOrigin::kRuntime,
          AllocationAlignment::kTaggedAligned);
      if (result.IsFailure()) {
        heap_->CollectGarbageFromAnyThread(&local_heap);
      } else {
        Address address = result.ToAddress();
        CreateFixedArray(heap_, address, kLargeObjectSize);
      }
      local_heap.Safepoint();
    }

    pending_->fetch_sub(1);
  }

  Heap* heap_;
  std::atomic<int>* pending_;
};

UNINITIALIZED_TEST(ConcurrentAllocationInLargeSpace) {
  v8_flags.max_old_space_size = 32;
  v8_flags.stress_concurrent_allocation = false;

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);

  std::vector<std::unique_ptr<LargeObjectConcurrentAllocationThread>> threads;

  const int kThreads = 4;

  std::atomic<int> pending(kThreads);

  for (int i = 0; i < kThreads; i++) {
    auto thread = std::make_unique<LargeObjectConcurrentAllocationThread>(
        i_isolate->heap(), &pending);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  while (pending > 0) {
    v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(), isolate);
  }

  for (auto& thread : threads) {
    thread->Join();
  }

  isolate->Dispose();
}

const int kWhiteIterations = 1000;

class ConcurrentBlackAllocationThread final : public v8::base::Thread {
 public:
  explicit ConcurrentBlackAllocationThread(
      Heap* heap, std::vector<Address>* objects, base::Semaphore* sema_white,
      base::Semaphore* sema_marking_started)
      : v8::base::Thread(base::Thread::Options("ThreadWithLocalHeap")),
        heap_(heap),
        objects_(objects),
        sema_white_(sema_white),
        sema_marking_started_(sema_marking_started) {}

  void Run() override {
    LocalHeap local_heap(heap_, ThreadKind::kBackground);
    UnparkedScope unparked_scope(&local_heap);

    for (int i = 0; i < kNumIterations; i++) {
      if (i == kWhiteIterations) {
        local_heap.ExecuteWhileParked([this]() {
          sema_white_->Signal();
          sema_marking_started_->Wait();
        });
      }
      Address address = local_heap.AllocateRawOrFail(
          kSmallObjectSize, AllocationType::kOld, AllocationOrigin::kRuntime,
          AllocationAlignment::kTaggedAligned);
      objects_->push_back(address);
      CreateFixedArray(heap_, address, kSmallObjectSize);
      address = local_heap.AllocateRawOrFail(
          kMediumObjectSize, AllocationType::kOld, AllocationOrigin::kRuntime,
          AllocationAlignment::kTaggedAligned);
      objects_->push_back(address);
      CreateFixedArray(heap_, address, kMediumObjectSize);
    }
  }

  Heap* heap_;
  std::vector<Address>* objects_;
  base::Semaphore* sema_white_;
  base::Semaphore* sema_marking_started_;
};

UNINITIALIZED_TEST(ConcurrentBlackAllocation) {
  if (!v8_flags.incremental_marking) return;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  {
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);

    std::vector<Address> objects;

    base::Semaphore sema_white(0);
    base::Semaphore sema_marking_started(0);

    auto thread = std::make_unique<ConcurrentBlackAllocationThread>(
        heap, &objects, &sema_white, &sema_marking_started);
    CHECK(thread->Start());

    sema_white.Wait();
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
    sema_marking_started.Signal();

    thread->Join();

    const int kObjectsAllocatedPerIteration = 2;

    for (int i = 0; i < kNumIterations * kObjectsAllocatedPerIteration; i++) {
      Address address = objects[i];
      Tagged<HeapObject> object = HeapObject::FromAddress(address);
      if (v8_flags.black_allocated_pages) {
        CHECK(heap->marking_state()->IsUnmarked(object));
        if (i < kWhiteIterations * kObjectsAllocatedPerIteration) {
          CHECK(!PageMetadata::FromHeapObject(object)->Chunk()->IsFlagSet(
              MemoryChunk::BLACK_ALLOCATED));
        } else {
          CHECK(PageMetadata::FromHeapObject(object)->Chunk()->IsFlagSet(
              MemoryChunk::BLACK_ALLOCATED));
        }
      } else {
        if (i < kWhiteIterations * kObjectsAllocatedPerIteration) {
          CHECK(heap->marking_state()->IsUnmarked(object));
        } else {
          CHECK(heap->marking_state()->IsMarked(object));
        }
      }
    }
  }
  isolate->Dispose();
}

class ConcurrentWriteBarrierThread final : public v8::base::Thread {
 public:
  ConcurrentWriteBarrierThread(Heap* heap, Tagged<FixedArray> fixed_array,
                               Tagged<HeapObject> value)
      : v8::base::Thread(base::Thread::Options("ThreadWithLocalHeap")),
        heap_(heap),
        fixed_array_(fixed_array),
        value_(value) {}

  void Run() override {
    LocalHeap local_heap(heap_, ThreadKind::kBackground);
    UnparkedScope unparked_scope(&local_heap);
    fixed_array_->set(0, value_);
  }

  Heap* heap_;
  Tagged<FixedArray> fixed_array_;
  Tagged<HeapObject> value_;
};

UNINITIALIZED_TEST(ConcurrentWriteBarrier) {
  if (!v8_flags.incremental_marking) return;
  if (!v8_flags.concurrent_marking) {
    // The test requires concurrent marking barrier.
    return;
  }
  ManualGCScope manual_gc_scope;

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    Tagged<FixedArray> fixed_array;
    Tagged<HeapObject> value;
    {
      HandleScope handle_scope(i_isolate);
      DirectHandle<FixedArray> fixed_array_handle(
          i_isolate->factory()->NewFixedArray(1));
      DirectHandle<HeapNumber> value_handle(
          i_isolate->factory()->NewHeapNumber<AllocationType::kOld>(1.1));
      fixed_array = *fixed_array_handle;
      value = *value_handle;
    }
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
    CHECK(heap->marking_state()->IsUnmarked(value));

    // Mark host |fixed_array| to trigger the barrier.
    heap->marking_state()->TryMarkAndAccountLiveBytes(fixed_array);

    auto thread = std::make_unique<ConcurrentWriteBarrierThread>(
        heap, fixed_array, value);
    CHECK(thread->Start());

    thread->Join();

    CHECK(heap->marking_state()->IsMarked(value));
    heap::InvokeMajorGC(heap);
  }
  isolate->Dispose();
}

class ConcurrentRecordRelocSlotThread final : public v8::base::Thread {
 public:
  ConcurrentRecordRelocSlotThread(Heap* heap, Tagged<Code> code,
                                  Tagged<HeapObject> value)
      : v8::base::Thread(base::Thread::Options("ThreadWithLocalHeap")),
        heap_(heap),
        code_(code),
        value_(value) {}

  void Run() override {
    LocalHeap local_heap(heap_, ThreadKind::kBackground);
    UnparkedScope unparked_scope(&local_heap);
    DisallowGarbageCollection no_gc;
    Tagged<InstructionStream> istream = code_->instruction_stream();
    int mode_mask = RelocInfo::EmbeddedObjectModeMask();
    WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
        istream->address(), istream->Size(),
        ThreadIsolation::JitAllocationType::kInstructionStream, true);
    for (WritableRelocIterator it(jit_allocation, istream,
                                  code_->constant_pool(), mode_mask);
         !it.done(); it.next()) {
      DCHECK(RelocInfo::IsEmbeddedObjectMode(it.rinfo()->rmode()));
      it.rinfo()->set_target_object(istream, value_);
    }
  }

  Heap* heap_;
  Tagged<Code> code_;
  Tagged<HeapObject> value_;
};

UNINITIALIZED_TEST(ConcurrentRecordRelocSlot) {
  if (!v8_flags.incremental_marking) return;
  if (!v8_flags.concurrent_marking) {
    // The test requires concurrent marking barrier.
    return;
  }
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    Tagged<Code> code;
    Tagged<HeapObject> value;
    {
      HandleScope handle_scope(i_isolate);
      uint8_t buffer[i::Assembler::kDefaultBufferSize];
      MacroAssembler masm(i_isolate, v8::internal::CodeObjectRequired::kYes,
                          ExternalAssemblerBuffer(buffer, sizeof(buffer)));
#if V8_TARGET_ARCH_ARM64
      // Arm64 requires stack alignment.
      UseScratchRegisterScope temps(&masm);
      Register tmp = temps.AcquireX();
      masm.Mov(tmp, Operand(ReadOnlyRoots(heap).undefined_value_handle()));
      masm.Push(tmp, padreg);
#else
      masm.Push(ReadOnlyRoots(heap).undefined_value_handle());
#endif
      CodeDesc desc;
      masm.GetCode(i_isolate, &desc);
      Handle<Code> code_handle =
          Factory::CodeBuilder(i_isolate, desc, CodeKind::FOR_TESTING).Build();
      // Globalize the handle for |code| for the incremental marker to mark it.
      i_isolate->global_handles()->Create(*code_handle);
      heap::AbandonCurrentlyFreeMemory(heap->old_space());
      DirectHandle<HeapNumber> value_handle(
          i_isolate->factory()->NewHeapNumber<AllocationType::kOld>(1.1));
      heap::ForceEvacuationCandidate(
          PageMetadata::FromHeapObject(*value_handle));
      code = *code_handle;
      value = *value_handle;
    }
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
    CHECK(heap->marking_state()->IsUnmarked(value));

    // Advance marking to make sure |code| is marked.
    heap->incremental_marking()->AdvanceForTesting(v8::base::TimeDelta::Max());

    CHECK(heap->marking_state()->IsMarked(code));
    CHECK(heap->marking_state()->IsUnmarked(value));

    {
      auto thread =
          std::make_unique<ConcurrentRecordRelocSlotThread>(heap, code, value);
      CHECK(thread->Start());

      thread->Join();
    }

    CHECK(heap->marking_state()->IsMarked(value));
    heap::InvokeMajorGC(heap);
  }
  isolate->Dispose();
}

}  // namespace internal
}  // namespace v8
```