Response: Let's break down the thought process to analyze the C++ code and then relate it to JavaScript.

1. **Understand the Goal:** The file name `test-concurrent-allocation.cc` and the `#include` directives immediately suggest this code is about testing concurrent memory allocation within the V8 engine. Specifically, it seems to focus on how multiple threads can allocate memory simultaneously without causing issues.

2. **Identify Key V8 Components:**  Scan the `#include` list for familiar V8 terms:
    * `src/api/api.h`:  Deals with the V8 API exposed to embedders (like Node.js or browsers).
    * `src/heap/heap.h`, `src/heap/local-heap-inl.h`: These are core to V8's memory management, especially the heap. The "local heap" likely relates to per-thread allocation contexts.
    * `src/objects/heap-object.h`, `src/objects/heap-number.h`: These are the fundamental building blocks of V8's object model.
    * `src/codegen/...`:  Indicates involvement with code generation, which might relate to how JavaScript is compiled and executed.
    * `test/cctest/cctest.h`, `test/cctest/heap/heap-utils.h`:  Confirms this is a testing file using V8's internal testing framework.

3. **Analyze the Core Logic (Without Going Too Deep Initially):**
    * **`CreateFixedArray` function:**  This looks like a helper function to create a basic V8 array object in memory. It takes a memory address and size as input. The `set_map_after_allocation` and `set_length` calls are setting up the object's metadata.
    * **`AllocateSomeObjects` function:**  This function repeatedly allocates small and medium-sized objects using a `LocalHeap`. The `Safepoint()` call suggests a point where the thread might yield or synchronization might occur.
    * **`ConcurrentAllocationThread` class:** This class inherits from `v8::base::Thread`, confirming the concurrent allocation aspect. The `Run()` method allocates objects using a `LocalHeap`.
    * **`UNINITIALIZED_TEST` macros:** These define the actual test cases. Look for patterns in how they set up the isolate, create threads, and manage their execution.

4. **Focus on the Test Cases:**  The test names provide clues about the scenarios being tested:
    * `ConcurrentAllocationInOldSpace`:  Tests concurrent allocation in the "old generation" of the heap (where long-lived objects reside).
    * `ConcurrentAllocationInOldSpaceFromMainThread`: Tests allocation from the main JavaScript thread.
    * `ConcurrentAllocationWhileMainThreadIsParked`: Tests concurrent allocation while the main thread is idle or waiting.
    * `ConcurrentAllocationWhileMainThreadParksAndUnparks`: Tests allocation while the main thread repeatedly enters and exits a parked state.
    * `ConcurrentAllocationWhileMainThreadRunsWithSafepoints`: Tests allocation while the main thread is running and periodically hitting safepoints.
    * `ConcurrentAllocationInLargeSpace`: Tests allocation of very large objects.
    * `ConcurrentBlackAllocation`: Seems related to garbage collection marking (the "black" in the name).
    * `ConcurrentWriteBarrier`: Tests how concurrent threads writing to objects interact with garbage collection.
    * `ConcurrentRecordRelocSlot`:  Tests concurrent modification of relocation information in generated code.

5. **Synthesize the Functionality:** Based on the analysis, the primary function of this file is to test the robustness and correctness of V8's concurrent memory allocation mechanisms. It simulates scenarios where multiple threads (including potentially the main JavaScript thread) are allocating memory simultaneously, particularly in the old generation and for large objects. It also tests interactions with the garbage collector (safepoints, incremental marking, write barriers).

6. **Connect to JavaScript (Conceptual Level First):**
    * **Memory Allocation:**  In JavaScript, when you create objects, arrays, functions, etc., the V8 engine allocates memory on the heap. This C++ code is testing the underlying implementation of that allocation.
    * **Concurrency:** While JavaScript itself is single-threaded in terms of its main execution loop, V8 uses multiple threads internally for tasks like garbage collection and compilation. This C++ code is specifically testing scenarios where these internal threads allocate memory concurrently.
    * **Garbage Collection:** JavaScript's automatic garbage collection reclaims memory that is no longer in use. This C++ code tests how concurrent allocation interacts with the garbage collector, ensuring that memory is managed correctly even under concurrent load.

7. **Develop JavaScript Examples (Relating to the Concepts):**

    * **Basic Allocation:**  Simple object creation in JavaScript maps to the underlying allocation being tested.
    * **Concurrency (Indirectly):** While you can't directly create native threads in standard JavaScript within a browser, Web Workers provide a way to execute JavaScript code in separate threads. These workers will trigger concurrent memory allocation within V8. *Initially, I might think of `setTimeout` or `setInterval`, but those are asynchronous within the same thread, not truly concurrent in the way V8's internal threads are.*
    * **Large Objects:** Creating large arrays or strings in JavaScript will trigger allocation of large chunks of memory, similar to the `ConcurrentAllocationInLargeSpace` test.

8. **Refine the JavaScript Examples and Explanations:**  Make sure the JavaScript examples clearly illustrate the *effects* of the underlying concurrent allocation being tested, even if the JavaScript code doesn't directly interact with V8's threading primitives. Emphasize that the C++ code is testing the *implementation* that makes the JavaScript code work correctly in concurrent scenarios.

9. **Structure the Output:** Organize the findings into clear sections (functionality, relationship to JavaScript, JavaScript examples) for readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  The `Safepoint()` call in `AllocateSomeObjects` might just be about yielding.
* **Correction:** Realize that `Safepoint()` is a more significant point where V8 can perform actions like garbage collection. This refines the understanding of how the tests are stressing the system.
* **Initial JavaScript Example for Concurrency:**  Thinking of `setTimeout`.
* **Correction:** Realize that `setTimeout` is asynchronous but still runs on the main thread. Switch to Web Workers as a more accurate example of triggering concurrent activity within V8.
* **Focus on the "Why":**  Constantly ask "Why is this test doing this?". This helps in understanding the underlying V8 mechanisms being tested and how they relate to JavaScript.

By following this kind of thought process, moving from the general to the specific, and continually connecting the C++ code to its implications for JavaScript, we can arrive at a comprehensive and accurate understanding of the file's functionality.
这个C++源代码文件 `v8/test/cctest/heap/test-concurrent-allocation.cc` 的主要功能是**测试 V8 JavaScript 引擎在多线程并发执行时的内存分配机制的正确性和健壮性**。

具体来说，它做了以下几件事情：

1. **模拟并发分配场景:**  它创建多个线程（`ConcurrentAllocationThread` 和 `LargeObjectConcurrentAllocationThread`），每个线程都在独立的 `LocalHeap` 上执行内存分配操作。这模拟了 V8 内部或外部（例如，通过 Web Workers）并发执行 JavaScript 代码时可能发生的内存分配情况。

2. **测试不同大小对象的分配:**  测试了小对象（`kSmallObjectSize`）和中等大小对象（`kMediumObjectSize`）的并发分配，以及大对象（大于普通堆对象大小）的并发分配（`ConcurrentAllocationInLargeSpace` 测试）。

3. **测试不同阶段的并发分配:**
   - 在主线程正常运行时并发分配。
   - 在主线程进入“停顿”（parked）状态时并发分配（`ConcurrentAllocationWhileMainThreadIsParked` 和 `ConcurrentAllocationWhileMainThreadParksAndUnparks` 测试），模拟垃圾回收或其他需要暂停 JavaScript 执行的场景。
   - 在主线程运行并触发安全点（safepoint）时并发分配（`ConcurrentAllocationWhileMainThreadRunsWithSafepoints` 测试），安全点是 V8 进行垃圾回收等操作的同步点。

4. **测试并发的黑对象分配（Concurrent Black Allocation）:**  当增量标记（incremental marking）启用时，测试在后台标记线程正在运行时，新的对象如何在并发分配时被正确标记为黑色（已标记）。这涉及到垃圾回收的机制。

5. **测试并发写屏障（Concurrent Write Barrier）:**  当增量标记和并发标记都启用时，测试后台线程在写入对象引用时，写屏障机制是否能正确地记录这些更新，确保垃圾回收器能够追踪到这些引用关系。

6. **测试并发记录重定位槽（Concurrent Record Reloc Slot）:** 测试并发修改已编译代码中的对象引用，确保在并发标记阶段，这些修改能够被正确处理。

7. **使用 `LocalHeap`:**  每个测试线程都使用 `LocalHeap`，这是一个线程本地的堆分配器，用于提高并发分配的性能和减少锁竞争。

8. **使用同步机制:**  使用了 `std::atomic<int>` 和 `v8::base::Semaphore` 等同步机制来协调多个线程的执行，例如等待所有线程完成分配。

**与 JavaScript 的关系 (并用 JavaScript 举例说明):**

这个 C++ 文件测试的是 V8 引擎的底层实现，而 JavaScript 代码最终是在 V8 引擎上执行的。  因此，这个测试文件直接关系到 JavaScript 的内存管理和并发执行能力。

**JavaScript 例子：**

考虑以下 JavaScript 代码，它使用了 Web Workers 来模拟并发执行：

```javascript
// main.js
const worker1 = new Worker('worker.js');
const worker2 = new Worker('worker.js');

worker1.postMessage('allocate');
worker2.postMessage('allocate');

// worker.js
onmessage = function(e) {
  if (e.data === 'allocate') {
    // 在 Worker 线程中分配大量对象
    const largeArray = new Array(1000000).fill({ data: 'some data' });
    const anotherObject = { key: 'value' };
    // ... 其他分配操作
  }
}
```

**说明:**

- 在 `main.js` 中，我们创建了两个 Web Workers，它们会在独立的线程中执行 `worker.js` 的代码。
- 在 `worker.js` 中，当收到 'allocate' 消息时，会创建大量的对象（`largeArray` 和 `anotherObject`）。

当这段 JavaScript 代码在 V8 引擎上运行时，`worker.js` 中的分配操作会在独立的线程中进行。  `test-concurrent-allocation.cc` 中的测试就是在模拟这种场景，确保 V8 的堆管理机制能够安全高效地处理来自不同线程的并发内存分配请求。

**更具体的对应关系：**

- `ConcurrentAllocationInOldSpace` 模拟了 `worker.js` 中创建 `largeArray` 和 `anotherObject` 这样的操作，因为这些对象通常会被分配到老生代堆空间。
- `ConcurrentAllocationWhileMainThreadIsParked` 模拟了主线程在执行某些操作（例如垃圾回收）时，Web Worker 线程仍然在进行内存分配的情况。
- `ConcurrentAllocationInLargeSpace` 模拟了在 `worker.js` 中创建非常大的对象，导致 V8 需要在 Large Object Heap 中分配内存的情况。

**总结:**

`test-concurrent-allocation.cc` 是 V8 引擎为了保证其在多线程环境下的内存分配正确性和性能而编写的关键测试文件。它通过模拟各种并发分配场景来验证 V8 底层内存管理机制的健壮性，这直接影响到 JavaScript 代码在浏览器或 Node.js 等环境中的稳定运行和性能表现。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-concurrent-allocation.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```