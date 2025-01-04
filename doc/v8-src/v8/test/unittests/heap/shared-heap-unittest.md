Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality in relation to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of the C++ file `shared-heap-unittest.cc` and its connection to JavaScript, with a JavaScript example. This means we need to identify the core purpose of the C++ code and how it relates to V8's (the JavaScript engine) memory management.

2. **Identify Key Components:**  Start by scanning the `#include` directives and the overall structure. Keywords like "heap," "shared," "isolate," "FixedArray," "BytecodeArray," "GC," and "test" are strong indicators. The presence of `TEST_F` suggests this is a unit testing file.

3. **Focus on the "Shared Heap":** The filename itself, `shared-heap-unittest.cc`, is the biggest clue. The code frequently uses terms like "SharedOldSpace," "SharedTrustedSpace," and `AllocationType::kShared*`. This points to the core functionality being tested: the shared heap.

4. **What is a Shared Heap?**  At this point, internal knowledge of V8 is helpful. The shared heap is a region of memory that can be accessed by multiple isolates (independent instances of the V8 engine). This allows for sharing data between different JavaScript contexts, improving efficiency in certain scenarios. If you didn't know this, the code's structure—creating separate "client" isolates and interacting with a "shared space isolate"—would suggest the concept of shared memory.

5. **Analyze the Test Cases:**  Go through the `TEST_F` macros. Each test name usually hints at what's being tested. Examples:
    * `ConcurrentAllocationInSharedOldSpace`:  Testing if multiple threads can allocate in the shared old space without issues.
    * `ConcurrentAllocationInSharedTrustedSpace`: Similar to the above, but for the "trusted" shared space.
    * `TrustedToSharedTrustedPointer`: Testing the validity of pointers from trusted (non-shared) memory to the shared trusted space.
    * `SharedCollectionWithOneClient`, `SharedCollectionWithMultipleClients`: Testing garbage collection in the shared heap when one or more isolates are using it.

6. **Identify Core Operations:**  The code performs actions like:
    * Creating isolates (`IsolateWrapper`).
    * Allocating objects in different spaces (`NewFixedArray`, `NewTrustedByteArray`, `NewBytecodeArray`, `NewContextlessMap` with `AllocationType::kShared*`).
    * Triggering garbage collection (`InvokeMajorGC`, `InvokeMinorGC`).
    * Using threads to simulate concurrent access.
    * Using semaphores for synchronization.
    * Assertions (`CHECK`, `EXPECT_FALSE`) to verify expected behavior.

7. **Connect to JavaScript:**  The key connection lies in the types of objects being allocated. `FixedArray`, `ByteArray`, `BytecodeArray`, and `Map` are fundamental data structures within V8 that represent JavaScript objects and their metadata. The tests are ensuring that these core JavaScript building blocks can be allocated and managed correctly in the shared heap.

8. **Formulate the Summary:**  Based on the above analysis, the core functionality is testing the shared heap in V8. Specifically, it checks for:
    * Concurrent allocation in different shared memory spaces.
    * Correctness of pointers between shared and non-shared spaces.
    * Functionality of garbage collection in the shared heap with multiple isolates.

9. **Create the JavaScript Example:** The C++ code manipulates internal V8 data structures. To illustrate the *concept* in JavaScript, you need a scenario where data sharing between different JavaScript contexts is desired. `SharedArrayBuffer` and `Atomics` are the direct JavaScript APIs for interacting with shared memory. This makes them the natural fit for the example. The example should show how changes in one context using shared memory are visible in another.

10. **Refine and Review:** Read through the summary and the JavaScript example to ensure clarity, accuracy, and a logical flow. Check if the JavaScript example directly reflects the core concepts being tested in the C++ code (concurrent access and data sharing). For instance, initially, one might think of just showing the creation of a SharedArrayBuffer. But the C++ code heavily involves concurrency and GC, so the example should ideally touch on those implicitly through multiple workers modifying the shared buffer.

By following these steps, you can effectively analyze the C++ code and explain its functionality and relevance to JavaScript. The key is to focus on the core purpose, understand the internal V8 concepts being tested, and find a relevant and illustrative example in JavaScript.
这个C++源代码文件 `v8/test/unittests/heap/shared-heap-unittest.cc` 的主要功能是**测试 V8 JavaScript 引擎中共享堆 (Shared Heap) 的各种特性和功能**。

更具体地说，它测试了以下方面：

**1. 并发分配 (Concurrent Allocation) 在共享堆的不同空间：**

*   测试多个线程能否同时在共享的老生代空间 (Shared Old Space)、共享的受信任空间 (Shared Trusted Space) 和共享的大对象空间 (Shared Large Object Space) 中分配内存，而不会出现问题。
*   这确保了 V8 的共享堆机制在多线程环境下的稳定性和安全性。

**2. 共享堆中对象指针的正确性：**

*   测试从受信任空间 (Trusted Space) 到共享的受信任空间 (Shared Trusted Space) 的指针是否有效。这涉及到跨内存区域的对象引用。
*   例如，测试在受信任空间中创建的 `BytecodeArray` 对象是否能够正确引用共享的受信任空间中的 `TrustedByteArray` 对象 (如 `handler_table`)。

**3. 共享堆的垃圾回收 (Garbage Collection)：**

*   测试在有或没有客户端 Isolate (独立的 JavaScript 执行环境) 的情况下，共享堆的垃圾回收是否能正常工作。
*   模拟多个客户端 Isolate 同时在共享堆中分配对象，并触发垃圾回收，验证共享堆的垃圾回收机制能否正确回收不再使用的对象。

**4. 使用不同类型的句柄 (Handles) 和原始指针 (Raw Pointers) 与共享堆交互：**

*   测试使用普通句柄 (`Handle`) 和在启用保守栈扫描 (Conservative Stack Scanning) 的情况下使用原始指针与共享堆中分配的对象进行交互，验证 V8 的内存管理机制能否正确跟踪和管理这些引用。

**5. 共享堆的基本分配和垃圾回收：**

*   测试在单个或多个客户端 Isolate 的情况下，共享堆的基本分配功能和垃圾回收功能是否正常。

**与 JavaScript 的关系及 JavaScript 示例：**

这个 C++ 文件测试的是 V8 引擎的底层实现，而 V8 引擎是 JavaScript 的执行环境。共享堆是 V8 引擎为了提高性能和支持跨 Isolate 数据共享而引入的一种机制。

在 JavaScript 中，我们可以通过以下方式间接地使用到共享堆的概念：

*   **`SharedArrayBuffer`:**  这是 JavaScript 中创建共享内存区域的关键 API。多个 JavaScript Worker 可以访问和修改同一个 `SharedArrayBuffer` 的内容。在 V8 引擎的底层实现中，`SharedArrayBuffer` 的数据很可能就存储在共享堆中。
*   **`Atomics`:**  这是一个提供原子操作的 JavaScript 对象，用于在多个 Worker 访问共享内存时进行同步，避免数据竞争。`Atomics` API 通常与 `SharedArrayBuffer` 一起使用。

**JavaScript 示例：**

```javascript
// 创建一个 SharedArrayBuffer，大小为 1024 字节
const sab = new SharedArrayBuffer(1024);

// 创建一个 Int32Array 视图，用于操作 SharedArrayBuffer
const sharedArray = new Int32Array(sab);

// 第一个 Worker
const worker1 = new Worker('./worker1.js');
worker1.postMessage({ sharedArray });

// 第二个 Worker
const worker2 = new Worker('./worker2.js');
worker2.postMessage({ sharedArray });

// worker1.js 的内容：
// self.onmessage = function(event) {
//   const sharedArray = event.data.sharedArray;
//   sharedArray[0] = 10;
//   console.log('Worker 1 设置 sharedArray[0] 为 10');
// };

// worker2.js 的内容：
// self.onmessage = function(event) {
//   const sharedArray = event.data.sharedArray;
//   console.log('Worker 2 读取 sharedArray[0]:', sharedArray[0]);
// };
```

**解释:**

1. 我们创建了一个 `SharedArrayBuffer`，它在 V8 的底层可能会分配在共享堆中。
2. 我们创建了两个 JavaScript Worker (可以理解为独立的 JavaScript 执行环境，类似于 C++ 中的 Isolate)。
3. 我们将同一个 `SharedArrayBuffer` 传递给这两个 Worker。
4. `worker1` 修改了 `sharedArray[0]` 的值。
5. `worker2` 可以读取到 `worker1` 修改后的值。

这个例子展示了 JavaScript 中如何通过 `SharedArrayBuffer` 和 Worker 来实现跨执行环境的数据共享，而这在 V8 的底层实现中就依赖于共享堆这样的机制。`shared-heap-unittest.cc` 这个 C++ 文件就是用来确保 V8 的共享堆机制能够正确地支持这样的 JavaScript 功能。

总而言之，`shared-heap-unittest.cc` 是一个 V8 引擎的单元测试文件，专注于验证共享堆的正确性和稳定性，这直接关系到 JavaScript 中 `SharedArrayBuffer` 等共享内存特性的可靠运行。

Prompt: 
```
这是目录为v8/test/unittests/heap/shared-heap-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/platform/platform.h"
#include "src/base/platform/semaphore.h"
#include "src/heap/heap.h"
#include "src/heap/parked-scope-inl.h"
#include "src/objects/bytecode-array.h"
#include "src/objects/fixed-array.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

// In multi-cage mode we create one cage per isolate
// and we don't share objects between cages.
#if V8_CAN_CREATE_SHARED_HEAP_BOOL && !COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL

namespace v8 {
namespace internal {

using SharedHeapTest = TestJSSharedMemoryWithIsolate;

class SharedHeapNoClientsTest : public TestJSSharedMemoryWithPlatform {
 public:
  SharedHeapNoClientsTest() {
    shared_space_isolate_wrapper.emplace(kNoCounters);
    shared_space_isolate_ = shared_space_isolate_wrapper->i_isolate();
  }

  ~SharedHeapNoClientsTest() override { shared_space_isolate_ = nullptr; }

  v8::Isolate* shared_space_isolate() {
    return reinterpret_cast<v8::Isolate*>(i_shared_space_isolate());
  }

  Isolate* i_shared_space_isolate() { return shared_space_isolate_; }

 private:
  Isolate* shared_space_isolate_;
  std::optional<IsolateWrapper> shared_space_isolate_wrapper;
};

namespace {
const int kNumIterations = 2000;

template <typename Callback>
void SetupClientIsolateAndRunCallback(Callback callback) {
  IsolateWrapper isolate_wrapper(kNoCounters);
  v8::Isolate* client_isolate = isolate_wrapper.isolate();
  Isolate* i_client_isolate = reinterpret_cast<Isolate*>(client_isolate);
  v8::Isolate::Scope isolate_scope(client_isolate);

  callback(client_isolate, i_client_isolate);
}

class SharedOldSpaceAllocationThread final : public ParkingThread {
 public:
  SharedOldSpaceAllocationThread()
      : ParkingThread(base::Thread::Options("SharedOldSpaceAllocationThread")) {
  }

  void Run() override {
    SetupClientIsolateAndRunCallback(
        [](v8::Isolate* client_isolate, Isolate* i_client_isolate) {
          HandleScope scope(i_client_isolate);

          for (int i = 0; i < kNumIterations; i++) {
            i_client_isolate->factory()->NewFixedArray(
                10, AllocationType::kSharedOld);
          }

          InvokeMajorGC(i_client_isolate);

          v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(),
                                        client_isolate);
        });
  }
};
}  // namespace

TEST_F(SharedHeapTest, ConcurrentAllocationInSharedOldSpace) {
  i_isolate()->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      [](const ParkedScope& parked) {
        std::vector<std::unique_ptr<SharedOldSpaceAllocationThread>> threads;
        const int kThreads = 4;

        for (int i = 0; i < kThreads; i++) {
          auto thread = std::make_unique<SharedOldSpaceAllocationThread>();
          CHECK(thread->Start());
          threads.push_back(std::move(thread));
        }

        ParkingThread::ParkedJoinAll(parked, threads);
      });
}

namespace {
class SharedTrustedSpaceAllocationThread final : public ParkingThread {
 public:
  SharedTrustedSpaceAllocationThread()
      : ParkingThread(
            base::Thread::Options("SharedTrustedSpaceAllocationThread")) {}

  void Run() override {
    constexpr int kNumIterations = 2000;

    SetupClientIsolateAndRunCallback(
        [](v8::Isolate* client_isolate, Isolate* i_client_isolate) {
          HandleScope scope(i_client_isolate);

          for (int i = 0; i < kNumIterations; i++) {
            i_client_isolate->factory()->NewTrustedByteArray(
                10, AllocationType::kSharedTrusted);
          }

          InvokeMajorGC(i_client_isolate);

          v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(),
                                        client_isolate);
        });
  }
};
}  // namespace

TEST_F(SharedHeapTest, ConcurrentAllocationInSharedTrustedSpace) {
  i_isolate()->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      [](const ParkedScope& parked) {
        std::vector<std::unique_ptr<SharedTrustedSpaceAllocationThread>>
            threads;
        const int kThreads = 4;

        for (int i = 0; i < kThreads; i++) {
          auto thread = std::make_unique<SharedTrustedSpaceAllocationThread>();
          CHECK(thread->Start());
          threads.push_back(std::move(thread));
        }

        ParkingThread::ParkedJoinAll(parked, threads);
      });
}

namespace {
class SharedLargeOldSpaceAllocationThread final : public ParkingThread {
 public:
  SharedLargeOldSpaceAllocationThread()
      : ParkingThread(base::Thread::Options("SharedOldSpaceAllocationThread")) {
  }

  void Run() override {
    SetupClientIsolateAndRunCallback(
        [](v8::Isolate* client_isolate, Isolate* i_client_isolate) {
          HandleScope scope(i_client_isolate);
          const int kNumIterations = 50;

          for (int i = 0; i < kNumIterations; i++) {
            HandleScope scope(i_client_isolate);
            DirectHandle<FixedArray> fixed_array =
                i_client_isolate->factory()->NewFixedArray(
                    kMaxRegularHeapObjectSize / kTaggedSize,
                    AllocationType::kSharedOld);
            CHECK(MemoryChunk::FromHeapObject(*fixed_array)->IsLargePage());
          }

          InvokeMajorGC(i_client_isolate);

          v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(),
                                        client_isolate);
        });
  }
};
}  // namespace

TEST_F(SharedHeapTest, ConcurrentAllocationInSharedLargeOldSpace) {
  i_isolate()->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      [](const ParkedScope& parked) {
        std::vector<std::unique_ptr<SharedLargeOldSpaceAllocationThread>>
            threads;
        const int kThreads = 4;

        for (int i = 0; i < kThreads; i++) {
          auto thread = std::make_unique<SharedLargeOldSpaceAllocationThread>();
          CHECK(thread->Start());
          threads.push_back(std::move(thread));
        }

        ParkingThread::ParkedJoinAll(parked, threads);
      });
}

namespace {
class SharedTrustedLargeObjectSpaceAllocationThread final
    : public ParkingThread {
 public:
  SharedTrustedLargeObjectSpaceAllocationThread()
      : ParkingThread(base::Thread::Options(
            "SharedTrustedLargeObjectSpaceAllocationThread")) {}

  void Run() override {
    SetupClientIsolateAndRunCallback(
        [](v8::Isolate* client_isolate, Isolate* i_client_isolate) {
          HandleScope scope(i_client_isolate);
          constexpr int kNumIterations = 50;

          for (int i = 0; i < kNumIterations; i++) {
            HandleScope scope(i_client_isolate);
            DirectHandle<TrustedByteArray> fixed_array =
                i_client_isolate->factory()->NewTrustedByteArray(
                    kMaxRegularHeapObjectSize, AllocationType::kSharedTrusted);
            CHECK(MemoryChunk::FromHeapObject(*fixed_array)->IsLargePage());
          }

          InvokeMajorGC(i_client_isolate);

          v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(),
                                        client_isolate);
        });
  }
};
}  // namespace

TEST_F(SharedHeapTest, ConcurrentAllocationInSharedTrustedLargeObjectSpace) {
  i_isolate()->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      [](const ParkedScope& parked) {
        std::vector<
            std::unique_ptr<SharedTrustedLargeObjectSpaceAllocationThread>>
            threads;
        constexpr int kThreads = 4;

        for (int i = 0; i < kThreads; i++) {
          auto thread =
              std::make_unique<SharedTrustedLargeObjectSpaceAllocationThread>();
          CHECK(thread->Start());
          threads.push_back(std::move(thread));
        }

        ParkingThread::ParkedJoinAll(parked, threads);
      });
}

TEST_F(SharedHeapTest, TrustedToSharedTrustedPointer) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();

  DirectHandle<TrustedFixedArray> constant_pool =
      factory->NewTrustedFixedArray(0);
  DirectHandle<TrustedByteArray> handler_table =
      factory->NewTrustedByteArray(3, AllocationType::kSharedTrusted);
  CHECK_EQ(MemoryChunk::FromHeapObject(*handler_table)
               ->Metadata()
               ->owner()
               ->identity(),
           SHARED_TRUSTED_SPACE);

  // Use random bytes here since we don't ever run the bytecode.
  constexpr uint8_t kRawBytes[] = {0x1, 0x2, 0x3, 0x4};
  constexpr int kRawBytesSize = sizeof(kRawBytes);
  constexpr int32_t kFrameSize = 32;
  constexpr uint16_t kParameterCount = 2;
  constexpr uint16_t kMaxArguments = 0;

  Handle<BytecodeArray> bc = factory->NewBytecodeArray(
      kRawBytesSize, kRawBytes, kFrameSize, kParameterCount, kMaxArguments,
      constant_pool, handler_table);
  CHECK_EQ(MemoryChunk::FromHeapObject(*bc)->Metadata()->owner()->identity(),
           TRUSTED_SPACE);

  InvokeMajorGC(isolate);

  USE(bc);
}

namespace {
class TrustedToSharedTrustedPointerOnClient final : public ParkingThread {
 public:
  explicit TrustedToSharedTrustedPointerOnClient(ParkingSemaphore* sem_ready,
                                                 ParkingSemaphore* sema_done)
      : ParkingThread(
            base::Thread::Options("TrustedToSharedTrustedPointerOnClient")),
        sema_ready_(sem_ready),
        sema_done_(sema_done) {}

  void Run() override {
    SetupClientIsolateAndRunCallback([this](v8::Isolate* client_isolate,
                                            Isolate* i_client_isolate) {
      Factory* factory = i_client_isolate->factory();
      HandleScope scope(i_client_isolate);
      DirectHandle<BytecodeArray> keep_alive_bc;

      {
        HandleScope nested_scope(i_client_isolate);
        DirectHandle<TrustedFixedArray> constant_pool =
            factory->NewTrustedFixedArray(0);
        DirectHandle<TrustedByteArray> handler_table =
            factory->NewTrustedByteArray(3, AllocationType::kSharedTrusted);
        CHECK_EQ(MemoryChunk::FromHeapObject(*handler_table)
                     ->Metadata()
                     ->owner()
                     ->identity(),
                 SHARED_TRUSTED_SPACE);

        // Use random bytes here since we don't ever run the bytecode.
        constexpr uint8_t kRawBytes[] = {0x1, 0x2, 0x3, 0x4};
        constexpr int kRawBytesSize = sizeof(kRawBytes);
        constexpr int32_t kFrameSize = 32;
        constexpr uint16_t kParameterCount = 2;
        constexpr uint16_t kMaxArguments = 0;

        Handle<BytecodeArray> bc = factory->NewBytecodeArray(
            kRawBytesSize, kRawBytes, kFrameSize, kParameterCount,
            kMaxArguments, constant_pool, handler_table);
        keep_alive_bc = nested_scope.CloseAndEscape(bc);
      }

      sema_ready_->Signal();
      sema_done_->ParkedWait(i_client_isolate->main_thread_local_isolate());

      Tagged<TrustedByteArray> handler_table = keep_alive_bc->handler_table();
      CHECK(IsTrustedByteArray(handler_table));
      CHECK_EQ(handler_table->length(), 3);

      v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(),
                                    client_isolate);
    });
  }

 private:
  ParkingSemaphore* sema_ready_;
  ParkingSemaphore* sema_done_;
};
}  // namespace

TEST_F(SharedHeapTest, TrustedToSharedTrustedPointerOnClient) {
  std::vector<std::unique_ptr<TrustedToSharedTrustedPointerOnClient>> threads;
  const int kThreads = 4;

  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_done(0);

  for (int i = 0; i < kThreads; i++) {
    auto thread = std::make_unique<TrustedToSharedTrustedPointerOnClient>(
        &sema_ready, &sema_done);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  LocalIsolate* local_isolate = i_isolate()->main_thread_local_isolate();
  for (int i = 0; i < kThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }

  InvokeMajorGC(i_isolate());

  for (int i = 0; i < kThreads; i++) {
    sema_done.Signal();
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);
}

namespace {
class SharedMapSpaceAllocationThread final : public ParkingThread {
 public:
  SharedMapSpaceAllocationThread()
      : ParkingThread(base::Thread::Options("SharedMapSpaceAllocationThread")) {
  }

  void Run() override {
    SetupClientIsolateAndRunCallback(
        [](v8::Isolate* client_isolate, Isolate* i_client_isolate) {
          HandleScope scope(i_client_isolate);

          for (int i = 0; i < kNumIterations; i++) {
            i_client_isolate->factory()->NewContextlessMap(
                NATIVE_CONTEXT_TYPE, kVariableSizeSentinel,
                TERMINAL_FAST_ELEMENTS_KIND, 0, AllocationType::kSharedMap);
          }

          InvokeMajorGC(i_client_isolate);

          v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(),
                                        client_isolate);
        });
  }
};
}  // namespace

TEST_F(SharedHeapTest, ConcurrentAllocationInSharedMapSpace) {
  i_isolate()->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      [](const ParkedScope& parked) {
        std::vector<std::unique_ptr<SharedMapSpaceAllocationThread>> threads;
        const int kThreads = 4;

        for (int i = 0; i < kThreads; i++) {
          auto thread = std::make_unique<SharedMapSpaceAllocationThread>();
          CHECK(thread->Start());
          threads.push_back(std::move(thread));
        }

        ParkingThread::ParkedJoinAll(parked, threads);
      });
}

TEST_F(SharedHeapNoClientsTest, SharedCollectionWithoutClients) {
  ::v8::internal::InvokeMajorGC(i_shared_space_isolate());
}

void AllocateInSharedHeap(int iterations = 100) {
  SetupClientIsolateAndRunCallback([iterations](v8::Isolate* client_isolate,
                                                Isolate* i_client_isolate) {
    HandleScope outer_scope(i_client_isolate);
    std::vector<Handle<FixedArray>> arrays_in_handles;
    const int kKeptAliveInHandle = 1000;
    const int kKeptAliveInHeap = 100;
    DirectHandle<FixedArray> arrays_in_heap =
        i_client_isolate->factory()->NewFixedArray(kKeptAliveInHeap,
                                                   AllocationType::kYoung);

    for (int i = 0; i < kNumIterations * iterations; i++) {
      HandleScope scope(i_client_isolate);
      Handle<FixedArray> array = i_client_isolate->factory()->NewFixedArray(
          100, AllocationType::kSharedOld);
      if (i < kKeptAliveInHandle) {
        // Keep some of those arrays alive across GCs through handles.
        arrays_in_handles.push_back(scope.CloseAndEscape(array));
      }

      if (i < kKeptAliveInHeap) {
        // Keep some of those arrays alive across GCs through client heap
        // references.
        arrays_in_heap->set(i, *array);
      }

      i_client_isolate->factory()->NewFixedArray(100, AllocationType::kYoung);
    }

    for (DirectHandle<FixedArray> array : arrays_in_handles) {
      CHECK_EQ(array->length(), 100);
    }

    for (int i = 0; i < kKeptAliveInHeap; i++) {
      Tagged<FixedArray> array = Cast<FixedArray>(arrays_in_heap->get(i));
      CHECK_EQ(array->length(), 100);
    }
  });
}

TEST_F(SharedHeapTest, SharedCollectionWithOneClient) {
  v8_flags.max_old_space_size = 8;
  i_isolate()->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      []() { AllocateInSharedHeap(); });
}

namespace {
class SharedFixedArrayAllocationThread final : public ParkingThread {
 public:
  SharedFixedArrayAllocationThread()
      : ParkingThread(
            base::Thread::Options("SharedFixedArrayAllocationThread")) {}

  void Run() override { AllocateInSharedHeap(5); }
};
}  // namespace

TEST_F(SharedHeapTest, SharedCollectionWithMultipleClients) {
  v8_flags.max_old_space_size = 8;

  i_isolate()->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      [](const ParkedScope& parked) {
        std::vector<std::unique_ptr<SharedFixedArrayAllocationThread>> threads;
        const int kThreads = 4;

        for (int i = 0; i < kThreads; i++) {
          auto thread = std::make_unique<SharedFixedArrayAllocationThread>();
          CHECK(thread->Start());
          threads.push_back(std::move(thread));
        }

        ParkingThread::ParkedJoinAll(parked, threads);
      });
}

namespace {

/**
 * The following two classes implement a recurring pattern for testing the
 * shared heap: two isolates (main and client), used respectively by the main
 * thread and a concurrent thread, that execute arbitrary fragments of code
 * (shown below in angular brackets) and synchronize in the following way
 * using parked semaphores:
 *
 *      main thread                    concurrent thread
 * ---------------------------------------------------------------
 *        <SETUP>
 *           |
 *      start thread ----------\
 *           |                  \---------> <SETUP>
 *           |                                 |
 *           |                  /-------- signal ready
 *     wait for ready <--------/               |
 *       <EXECUTE>                             |
 *     signal execute ---------\               |
 *           |                  \-----> wait for execute
 *           |                             <EXECUTE>
 *           |                  /------ signal complete
 *    wait for complete <------/               |
 *           |                                 |
 *      <COMPLETE>                        <COMPLETE>
 *           |                  /----------- exit
 *      join thread <----------/
 *      <TEARDOWN>
 *
 * Both threads allocate an arbitrary state object on their stack, which
 * may contain information that is shared between the executed fragments
 * of code.
 */

template <typename State>
class ConcurrentThread final : public ParkingThread {
 public:
  using ThreadType = ConcurrentThread<State>;
  using Callback = void(ThreadType*);

  explicit ConcurrentThread(
      bool wait_while_parked, v8::base::Semaphore* sema_ready = nullptr,
      v8::base::Semaphore* sema_execute_start = nullptr,
      v8::base::Semaphore* sema_execute_complete = nullptr)
      : ParkingThread(Options("ConcurrentThread")),
        sema_ready_(sema_ready),
        sema_execute_start_(sema_execute_start),
        sema_execute_complete_(sema_execute_complete),
        wait_while_parked_(wait_while_parked) {}

  void Run() override {
    IsolateWrapper isolate_wrapper(kNoCounters);
    i_client_isolate_ = isolate_wrapper.i_isolate();

    v8::Isolate::Scope isolate_scope(isolate_wrapper.isolate());

    // Allocate the state on the stack, so that handles, direct handles or raw
    // pointers are stack-allocated.
    State state;
    state_ = &state;

    if (setup_callback_) setup_callback_(this);

    if (sema_ready_) sema_ready_->Signal();
    if (sema_execute_start_) {
      if (wait_while_parked_) {
        // Park and wait.
        i_client_isolate_->main_thread_local_isolate()
            ->ExecuteMainThreadWhileParked(
                [this]() { sema_execute_start_->Wait(); });
      } else {
        // Do not park, but enter a safepoint every now and then.
        const auto timeout = base::TimeDelta::FromMilliseconds(100);
        do {
          i_client_isolate_->main_thread_local_isolate()->heap()->Safepoint();
        } while (!sema_execute_start_->WaitFor(timeout));
      }
    }

    if (execute_callback_) execute_callback_(this);

    if (sema_execute_complete_) sema_execute_complete_->Signal();

    if (complete_callback_) complete_callback_(this);

    i_client_isolate_ = nullptr;
    state_ = nullptr;
  }

  Isolate* i_client_isolate() const {
    DCHECK_NOT_NULL(i_client_isolate_);
    return i_client_isolate_;
  }

  v8::Isolate* client_isolate() const {
    return reinterpret_cast<v8::Isolate*>(i_client_isolate_);
  }

  State* state() {
    DCHECK_NOT_NULL(state_);
    return state_;
  }

  void with_setup(Callback* callback) { setup_callback_ = callback; }
  void with_execute(Callback* callback) { execute_callback_ = callback; }
  void with_complete(Callback* callback) { complete_callback_ = callback; }

 private:
  Isolate* i_client_isolate_ = nullptr;
  State* state_ = nullptr;
  v8::base::Semaphore* sema_ready_ = nullptr;
  v8::base::Semaphore* sema_execute_start_ = nullptr;
  v8::base::Semaphore* sema_execute_complete_ = nullptr;
  Callback* setup_callback_ = nullptr;
  Callback* execute_callback_ = nullptr;
  Callback* complete_callback_ = nullptr;
  bool wait_while_parked_;
};

template <typename State, typename ThreadState, bool wait_while_parked>
class SharedHeapTestBase : public TestJSSharedMemoryWithNativeContext {
 public:
  using TestType = SharedHeapTestBase<State, ThreadState, wait_while_parked>;
  using Callback = void(TestType*);
  using ThreadType = ConcurrentThread<ThreadState>;
  using ThreadCallback = typename ThreadType::Callback;

  SharedHeapTestBase()
      : thread_(std::make_unique<ThreadType>(wait_while_parked, &sema_ready_,
                                             &sema_execute_start_,
                                             &sema_execute_complete_)) {}

  void Interact() {
    // Allocate the state on the stack, so that handles, direct handles or raw
    // pointers are stack-allocated.
    State state;
    state_ = &state;

    if (setup_callback_) setup_callback_(this);
    CHECK(thread()->Start());
    sema_ready_.Wait();
    if (execute_callback_) execute_callback_(this);
    sema_execute_start_.Signal();
    sema_execute_complete_.Wait();
    if (complete_callback_) complete_callback_(this);
    thread()->ParkedJoin(i_isolate()->main_thread_local_isolate());
    if (teardown_callback_) teardown_callback_(this);
  }

  ConcurrentThread<State>* thread() const {
    DCHECK(thread_);
    return thread_.get();
  }

  State* state() {
    DCHECK_NOT_NULL(state_);
    return state_;
  }

  void with_setup(Callback* callback) { setup_callback_ = callback; }
  void with_execute(Callback* callback) { execute_callback_ = callback; }
  void with_complete(Callback* callback) { complete_callback_ = callback; }
  void with_teardown(Callback* callback) { teardown_callback_ = callback; }

 private:
  State* state_ = nullptr;
  std::unique_ptr<ConcurrentThread<State>> thread_;
  v8::base::Semaphore sema_ready_{0};
  v8::base::Semaphore sema_execute_start_{0};
  v8::base::Semaphore sema_execute_complete_{0};
  Callback* setup_callback_ = nullptr;
  Callback* execute_callback_ = nullptr;
  Callback* complete_callback_ = nullptr;
  Callback* teardown_callback_ = nullptr;
};

}  // namespace

#define TEST_SCENARIO(test_class, test_method, test_name, allocation, space) \
  TEST_F(test_class, test_name) {                                            \
    test_method<test_class, allocation, space>(this);                        \
  }

#define TEST_ALL_SCENARIA(test_class, test_prefix, test_method)    \
  TEST_SCENARIO(test_class, test_method, test_prefix##YoungYoung,  \
                AllocationType::kYoung, NEW_SPACE)                 \
  TEST_SCENARIO(test_class, test_method, test_prefix##YoungOld,    \
                AllocationType::kYoung, OLD_SPACE)                 \
  TEST_SCENARIO(test_class, test_method, test_prefix##OldYoung,    \
                AllocationType::kOld, NEW_SPACE)                   \
  TEST_SCENARIO(test_class, test_method, test_prefix##OldOld,      \
                AllocationType::kOld, OLD_SPACE)                   \
  TEST_SCENARIO(test_class, test_method, test_prefix##SharedYoung, \
                AllocationType::kSharedOld, NEW_SPACE)             \
  TEST_SCENARIO(test_class, test_method, test_prefix##SharedOld,   \
                AllocationType::kSharedOld, OLD_SPACE)

namespace {

// Testing the shared heap using ordinary (indirect) handles.

struct StateWithHandle {
  std::optional<HandleScope> scope;
  Handle<FixedArray> handle;
  Global<v8::FixedArray> weak;
};

template <AllocationType allocation, AllocationSpace space, int size>
void AllocateWithHandle(Isolate* isolate, StateWithHandle* state) {
  // Install a handle scope.
  state->scope.emplace(isolate);
  // Allocate a fixed array, keep a handle and a weak reference.
  state->handle = isolate->factory()->NewFixedArray(size, allocation);
  Local<v8::FixedArray> l = Utils::FixedArrayToLocal(state->handle);
  state->weak.Reset(reinterpret_cast<v8::Isolate*>(isolate), l);
  state->weak.SetWeak();
}

using SharedHeapTestStateWithHandleParked =
    SharedHeapTestBase<StateWithHandle, StateWithHandle, true>;
using SharedHeapTestStateWithHandleUnparked =
    SharedHeapTestBase<StateWithHandle, StateWithHandle, false>;

void InvokeGC(AllocationSpace space, Isolate* isolate) {
  space == NEW_SPACE ? InvokeMinorGC(isolate) : InvokeMajorGC(isolate);
}

template <typename TestType, AllocationType allocation, AllocationSpace space>
void ToEachTheirOwnWithHandle(TestType* test) {
  using ThreadType = typename TestType::ThreadType;
  ThreadType* thread = test->thread();

  // Install all the callbacks.
  test->with_setup([](TestType* test) {
    AllocateWithHandle<allocation, space, 10>(test->i_isolate(), test->state());
  });

  thread->with_setup([](ThreadType* thread) {
    AllocateWithHandle<allocation, space, 20>(thread->i_client_isolate(),
                                              thread->state());
  });

  test->with_execute(
      [](TestType* test) { InvokeGC(space, test->i_isolate()); });

  thread->with_execute(
      [](ThreadType* thread) { InvokeGC(space, thread->i_client_isolate()); });

  test->with_complete([](TestType* test) {
    // The handle should keep the fixed array from being reclaimed.
    EXPECT_FALSE(test->state()->weak.IsEmpty());
  });

  thread->with_complete([](ThreadType* thread) {
    // The handle should keep the fixed array from being reclaimed.
    EXPECT_FALSE(thread->state()->weak.IsEmpty());
    thread->state()->scope.reset();  // Deallocate the handle scope.
    InvokeGC(space, thread->i_client_isolate());
  });

  test->with_teardown([](TestType* test) {
    test->state()->scope.reset();  // Deallocate the handle scope.
    InvokeGC(space, test->i_isolate());
  });

  // Perform the test.
  test->Interact();
}

}  // namespace

TEST_ALL_SCENARIA(SharedHeapTestStateWithHandleParked, ToEachTheirOwn,
                  ToEachTheirOwnWithHandle)
TEST_ALL_SCENARIA(SharedHeapTestStateWithHandleUnparked, ToEachTheirOwn,
                  ToEachTheirOwnWithHandle)

#ifdef V8_ENABLE_CONSERVATIVE_STACK_SCANNING

namespace {

// Testing the shared heap using raw pointers.
// This works only with conservative stack scanning.

struct StateWithRawPointer {
  Address ptr;
  Global<v8::FixedArray> weak;
};

template <AllocationType allocation, AllocationSpace space, int size>
void AllocateWithRawPointer(Isolate* isolate, StateWithRawPointer* state) {
  // Allocate a fixed array, keep a raw pointer and a weak reference.
  HandleScope scope(isolate);
  DirectHandle<FixedArray> h =
      isolate->factory()->NewFixedArray(size, allocation);
  state->ptr = (*h).ptr();
  Local<v8::FixedArray> l = Utils::FixedArrayToLocal(h);
  state->weak.Reset(reinterpret_cast<v8::Isolate*>(isolate), l);
  state->weak.SetWeak();
}

using SharedHeapTestStateWithRawPointerParked =
    SharedHeapTestBase<StateWithRawPointer, StateWithRawPointer, true>;
using SharedHeapTestStateWithRawPointerUnparked =
    SharedHeapTestBase<StateWithRawPointer, StateWithRawPointer, false>;

template <typename TestType, AllocationType allocation, AllocationSpace space>
void ToEachTheirOwnWithRawPointer(TestType* test) {
  using ThreadType = typename TestType::ThreadType;
  ThreadType* thread = test->thread();

  // Install all the callbacks.
  test->with_setup([](TestType* test) {
    AllocateWithRawPointer<allocation, space, 10>(test->i_isolate(),
                                                  test->state());
  });

  thread->with_setup([](ThreadType* thread) {
    AllocateWithRawPointer<allocation, space, 20>(thread->i_client_isolate(),
                                                  thread->state());
  });

  test->with_execute(
      [](TestType* test) { InvokeGC(space, test->i_isolate()); });

  thread->with_execute(
      [](ThreadType* thread) { InvokeGC(space, thread->i_client_isolate()); });

  test->with_complete([](TestType* test) {
    // With conservative stack scanning, the raw pointer should keep the fixed
    // array from being reclaimed.
    EXPECT_FALSE(test->state()->weak.IsEmpty());
  });

  thread->with_complete([](ThreadType* thread) {
    // With conservative stack scanning, the raw pointer should keep the fixed
    // array from being reclaimed.
    EXPECT_FALSE(thread->state()->weak.IsEmpty());
    InvokeGC(space, thread->i_client_isolate());
  });

  test->with_teardown(
      [](TestType* test) { InvokeGC(space, test->i_isolate()); });

  // Perform the test.
  test->Interact();
}

}  // namespace

TEST_ALL_SCENARIA(SharedHeapTestStateWithRawPointerParked, ToEachTheirOwn,
                  ToEachTheirOwnWithRawPointer)
TEST_ALL_SCENARIA(SharedHeapTestStateWithRawPointerUnparked, ToEachTheirOwn,
                  ToEachTheirOwnWithRawPointer)

#endif  // V8_ENABLE_CONSERVATIVE_STACK_SCANNING

#undef TEST_SCENARIO
#undef TEST_ALL_SCENARIA

// TODO(358918874): Re-enable this test once allocation paths are using the
// right tag for trusted pointers in shared objects.
#if false
TEST_F(SharedHeapTest, SharedUntrustedToSharedTrustedPointer) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();
  ManualGCScope manual_gc_scope(isolate);

  // Allocate an object in the shared trusted space.
  // Use random bytes here since we don't ever run the bytecode.
  constexpr uint8_t kRawBytes[] = {0x1, 0x2, 0x3, 0x4};
  constexpr int kRawBytesSize = sizeof(kRawBytes);
  constexpr int32_t kFrameSize = 32;
  constexpr uint16_t kParameterCount = 2;
  constexpr uint16_t kMaxArguments = 0;
  Handle<TrustedFixedArray> constant_pool =
      factory->NewTrustedFixedArray(0, AllocationType::kSharedTrusted);
  Handle<TrustedByteArray> handler_table =
      factory->NewTrustedByteArray(3, AllocationType::kSharedTrusted);
  Handle<BytecodeArray> bytecode_array = factory->NewBytecodeArray(
      kRawBytesSize, kRawBytes, kFrameSize, kParameterCount, kMaxArguments,
      constant_pool, handler_table, AllocationType::kSharedTrusted);
  CHECK_EQ(MemoryChunk::FromHeapObject(*bytecode_array)
               ->Metadata()
               ->owner()
               ->identity(),
           SHARED_TRUSTED_SPACE);

  // Start incremental marking
  isolate->heap()->StartIncrementalMarking(GCFlag::kNoFlags,
                                           GarbageCollectionReason::kTesting);

  // Allocate an object in the shared untrusted space.
  Handle<BytecodeWrapper> bytecode_wrapper =
      factory->NewBytecodeWrapper(AllocationType::kSharedOld);
  CHECK_EQ(MemoryChunk::FromHeapObject(*bytecode_wrapper)
               ->Metadata()
               ->owner()
               ->identity(),
           SHARED_SPACE);

  // Create a shared untrusted to shared trusted reference (with a write
  // barrier)
  bytecode_wrapper->set_bytecode(*bytecode_array);
  bytecode_array->wrapper()->clear_bytecode();
  bytecode_array->set_wrapper(*bytecode_wrapper);
}
#endif  // false

}  // namespace internal
}  // namespace v8

#endif  // V8_CAN_CREATE_SHARED_HEAP_BOOL

"""

```