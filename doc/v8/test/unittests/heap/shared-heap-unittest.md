Response:
Let's break down the thought process for analyzing this C++ V8 test file.

1. **Understand the Goal:** The primary goal is to analyze the given C++ code and describe its functionality, considering its context within the V8 project. The prompt specifically asks about shared heaps, Torque, JavaScript relationships, logic, and common errors.

2. **Identify the Core Topic:** The filename `shared-heap-unittest.cc` immediately points to the central theme: testing the shared heap functionality in V8. The `#if V8_CAN_CREATE_SHARED_HEAP_BOOL && !COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL` confirms that this code is relevant only when shared heaps are enabled and a specific configuration is active. This immediately suggests that the tests will focus on scenarios involving multiple isolates sharing memory.

3. **Examine Includes:** The included header files provide clues about the functionalities being tested:
    * `"src/base/platform/platform.h"` and `"src/base/platform/semaphore.h"`:  Indicate the use of platform-specific threading and synchronization primitives. This aligns with the concept of shared heaps needing concurrency control.
    * `"src/heap/heap.h"` and `"src/heap/parked-scope-inl.h"`:  Directly relate to heap management and the `ParkedScope` mechanism for executing code on the main thread.
    * `"src/objects/bytecode-array.h"` and `"src/objects/fixed-array.h"`: Reveal that the tests involve manipulating specific V8 object types.
    * `"test/unittests/heap/heap-utils.h"` and `"test/unittests/test-utils.h"`: Standard V8 testing utilities.
    * `"testing/gtest/include/gtest/gtest.h"`:  The Google Test framework used for writing the tests.

4. **Analyze Namespaces and Classes:**
    * `namespace v8 { namespace internal {`:  Confirms this is internal V8 code.
    * `using SharedHeapTest = TestJSSharedMemoryWithIsolate;`: Establishes a base test fixture for tests involving shared memory and isolates.
    * `class SharedHeapNoClientsTest`:  Focuses on scenarios without client isolates, likely testing the basic setup and cleanup of the shared heap.
    * The various `Shared...AllocationThread` classes: Clearly indicate tests involving concurrent allocation in different shared heap spaces (old, trusted, large object). The `ParkingThread` base class suggests synchronization.

5. **Deconstruct Individual Tests:** Go through each `TEST_F` function and understand its purpose:
    * `ConcurrentAllocationInSharedOldSpace`, `ConcurrentAllocationInSharedTrustedSpace`, etc.: These tests create multiple threads to concurrently allocate objects in the specified shared heap spaces. This verifies thread safety and proper allocation mechanisms.
    * `TrustedToSharedTrustedPointer`:  Examines the behavior of pointers between different memory spaces, specifically from the trusted space to the shared trusted space. This is important for security and data integrity.
    * `TrustedToSharedTrustedPointerOnClient`: Similar to the previous test but involves a separate client isolate and synchronization, making it more complex.
    * `ConcurrentAllocationInSharedMapSpace`: Tests concurrent allocation of `Map` objects in the shared map space.
    * `SharedCollectionWithoutClients`: A basic test to trigger garbage collection in the shared heap without any client isolates.
    * `SharedCollectionWithOneClient` and `SharedCollectionWithMultipleClients`: Tests the garbage collection process when shared objects are being referenced by client isolates.
    * The template-based tests (`SharedHeapTestStateWithHandleParked`, `SharedHeapTestStateWithRawPointerParked`, etc.): These are more involved and systematically test object lifecycle and garbage collection with different types of references (handles and raw pointers) in concurrent scenarios. The `wait_while_parked` template parameter hints at testing different synchronization strategies.

6. **Identify Key Concepts:** Based on the code, the following key concepts emerge:
    * **Shared Heap:** A memory region shared between multiple V8 isolates.
    * **Isolates:** Independent V8 instances.
    * **Allocation Spaces:** Different regions within the heap (old, young, trusted, map, large object).
    * **Concurrency:** Multiple threads accessing the shared heap simultaneously.
    * **Garbage Collection (GC):** The process of reclaiming unused memory.
    * **Handles and Raw Pointers:** Different ways to reference objects, with implications for GC.
    * **Synchronization:** Mechanisms like semaphores (`ParkingSemaphore`) to coordinate threads.
    * **Trusted and Untrusted Spaces:**  Memory spaces with different security implications.

7. **Address Specific Prompt Questions:**
    * **Functionality:** Summarize the purpose of each test case as described above.
    * **Torque:** The filename doesn't end in `.tq`, so it's not a Torque source file.
    * **JavaScript Relationship:** Explain that shared heaps enable sharing of certain data structures between isolates, which can improve performance in multi-isolate scenarios (e.g., web workers). Provide a conceptual JavaScript example of sharing data via `SharedArrayBuffer` (though the C++ code operates at a lower level).
    * **Code Logic Inference:**  Choose a relatively simple test like `ConcurrentAllocationInSharedOldSpace` and explain the setup (multiple threads allocating), the expected outcome (allocation without crashes), and potential errors (race conditions).
    * **Common Programming Errors:** Focus on concurrency-related issues like race conditions, deadlocks, and improper synchronization when dealing with shared resources. Provide a simplified C++ example to illustrate a race condition.

8. **Refine and Organize:**  Structure the analysis logically with clear headings and explanations. Use precise terminology and provide concrete examples where applicable. Ensure the answer directly addresses all parts of the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on individual function details.
* **Correction:**  Shift to understanding the broader *purpose* of each test and how it contributes to verifying the shared heap's functionality.
* **Initial thought:**  Assume deep knowledge of V8 internals.
* **Correction:** Explain concepts at a slightly higher level, focusing on the *what* and *why* rather than the low-level *how*, unless absolutely necessary for understanding.
* **Initial thought:**  Overlook the synchronization aspects.
* **Correction:**  Emphasize the role of semaphores and `ParkingThread` in managing concurrency and preventing race conditions.
* **Initial thought:**  Struggle with the JavaScript example.
* **Correction:**  Focus on the *concept* of sharing data between execution contexts in JavaScript (like `SharedArrayBuffer`) as an analogy, rather than trying to directly map the C++ code to a JavaScript equivalent.

By following this structured approach, iteratively refining understanding, and directly addressing the prompt's questions, we arrive at a comprehensive and accurate analysis of the given V8 test file.
`v8/test/unittests/heap/shared-heap-unittest.cc` is a C++ source file containing unit tests for the shared heap functionality in the V8 JavaScript engine. These tests aim to verify the correctness and robustness of the shared heap, which allows multiple V8 isolates to share certain memory regions and objects.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Testing Concurrent Allocation:**  The majority of the tests focus on verifying that multiple isolates (represented by different threads) can concurrently allocate objects in various spaces within the shared heap (old space, trusted space, large object space, map space) without causing crashes or data corruption. This is crucial for the stability of applications using shared memory.
* **Testing Pointer Integrity:** Some tests, like `TrustedToSharedTrustedPointer` and `TrustedToSharedTrustedPointerOnClient`, specifically check the validity of pointers between different memory spaces (trusted and shared trusted). This ensures that references to shared objects are correctly maintained even across garbage collection cycles.
* **Testing Garbage Collection (GC) in Shared Heap:** Several tests implicitly and explicitly trigger garbage collection (major and minor GCs) to ensure that the shared heap's garbage collector correctly handles shared objects and their references from different isolates. Tests like `SharedCollectionWithOneClient` and `SharedCollectionWithMultipleClients` are particularly focused on this.
* **Testing Scenarios with and without Clients:** The tests differentiate between scenarios with client isolates actively allocating and accessing shared memory and scenarios where only the shared heap isolate exists. This helps isolate potential issues.
* **Testing Different Allocation Types:** The tests use various `AllocationType` values (e.g., `kSharedOld`, `kSharedTrusted`, `kYoung`) to target specific allocation strategies within the shared heap.
* **Testing Different Reference Types:**  The template-based tests (`SharedHeapTestStateWithHandleParked`, `SharedHeapTestStateWithRawPointerParked`) explore how different types of references (handles and raw pointers) from different isolates affect the lifetime and garbage collection of shared objects.

**Is it a Torque source file?**

No, `v8/test/unittests/heap/shared-heap-unittest.cc` ends with `.cc`, which is the standard extension for C++ source files. If it were a Torque source file, it would end with `.tq`.

**Relationship with JavaScript and Examples:**

While this file is C++ code, it directly tests the underlying infrastructure that enables certain JavaScript features, particularly those related to shared memory and cross-origin isolation.

* **SharedArrayBuffer:** The shared heap is a crucial component for implementing `SharedArrayBuffer` in JavaScript. `SharedArrayBuffer` allows multiple JavaScript contexts (like web workers or different origins with proper headers) to access the same raw binary data in memory.

   ```javascript
   // JavaScript example demonstrating SharedArrayBuffer
   const sab = new SharedArrayBuffer(1024);
   const view1 = new Int32Array(sab);

   // In one JavaScript context (e.g., a web worker):
   view1[0] = 42;

   // In another JavaScript context:
   console.log(view1[0]); // Output: 42
   ```

* **Cross-Origin Isolated Environments:**  The shared heap plays a role in supporting cross-origin isolated environments. When a website is cross-origin isolated, it can leverage more powerful features like `SharedArrayBuffer` because it has stronger security guarantees.

**Code Logic Inference with Assumptions:**

Let's take the `ConcurrentAllocationInSharedOldSpace` test as an example:

**Assumptions:**

1. **Multiple Isolates:** The test sets up a main isolate and then spawns multiple client isolates (threads).
2. **Shared Heap Enabled:** The test is only run when the `V8_CAN_CREATE_SHARED_HEAP_BOOL` flag is true.
3. **Allocation in Shared Old Space:**  Each client thread attempts to allocate `FixedArray` objects specifically in the `kSharedOld` space.
4. **Synchronization:** The `ParkingThread` and `ParkedJoinAll` mechanisms ensure that the main thread waits for all allocation threads to complete before the test finishes.
5. **No Data Races:** The shared heap implementation is expected to handle concurrent allocations without introducing data races or memory corruption.

**Logic:**

1. The main test sets up the shared heap environment.
2. It creates `kThreads` (4 in this case) of `SharedOldSpaceAllocationThread`.
3. Each allocation thread, when started:
   - Sets up its own client isolate.
   - Enters a loop that iterates `kNumIterations` (2000).
   - In each iteration, it allocates a `FixedArray` of size 10 in the `kSharedOld` space.
   - After allocation, it triggers a major garbage collection.
   - It pumps the message loop to allow for asynchronous operations.
4. The main thread waits for all allocation threads to finish using `ParkedJoinAll`.

**Expected Output/Outcome:**

The test is expected to complete without any crashes, memory errors, or assertions failing. This indicates that the shared heap can handle concurrent allocations in the old space from multiple isolates correctly.

**Potential Programming Errors (User-Side):**

While this C++ code tests the V8 engine itself, here are some common programming errors users might encounter when working with JavaScript features that rely on the shared heap:

1. **Race Conditions with SharedArrayBuffer:**  If multiple JavaScript contexts access and modify a `SharedArrayBuffer` without proper synchronization mechanisms (like `Atomics`), it can lead to race conditions and unpredictable behavior.

   ```javascript
   // Potential race condition example (JavaScript)
   const sab = new SharedArrayBuffer(4);
   const view = new Int32Array(sab);

   // Context 1:
   view[0]++;

   // Context 2:
   view[0]++;

   // The final value of view[0] might be 1, not the expected 2.
   ```

2. **Incorrectly Handling Cross-Origin Isolation:**  If a website intends to use `SharedArrayBuffer` but doesn't have the correct cross-origin isolation headers set up, it might encounter errors or unexpected behavior.

3. **Memory Management Issues (less common in typical JS):** While the garbage collector handles most memory management, in very low-level scenarios or when interacting with native code, incorrect memory management related to shared memory could lead to issues.

4. **Type Errors and Data Corruption:**  When different JavaScript contexts interpret the data in a `SharedArrayBuffer` with different types (e.g., one as `Int32Array`, another as `Float64Array`), it can lead to misinterpretations and data corruption.

**In summary,** `v8/test/unittests/heap/shared-heap-unittest.cc` is a crucial part of V8's testing infrastructure, ensuring the stability and correctness of the shared heap, a foundational component for features like `SharedArrayBuffer` and cross-origin isolation in JavaScript. It focuses heavily on testing concurrent access and proper memory management in shared memory scenarios.

Prompt: 
```
这是目录为v8/test/unittests/heap/shared-heap-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/shared-heap-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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