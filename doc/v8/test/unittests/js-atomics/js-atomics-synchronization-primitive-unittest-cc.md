Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

**1. Initial Scan and Keyword Recognition:**

* Immediately, I see the `#include` directives. These point to platform specifics (`platform.h`), time (`time.h`), heap management (`parked-scope-inl.h`), the core subject (`js-atomics-synchronization-inl.h`), and testing frameworks (`test-utils.h`, `gtest/gtest.h`). This tells me it's likely a unit test for the JS atomics synchronization primitives within the V8 engine.
* The `namespace v8 { namespace internal {` structure confirms it's internal V8 code.
* The `using JSAtomicsMutexTest = ...;` and `using JSAtomicsConditionTest = ...;` lines clearly define the testing groups.
* I notice the `#if V8_CAN_CREATE_SHARED_HEAP_BOOL && !COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL` preprocessor directive. This is crucial. It means the code is specifically testing scenarios involving shared heaps and a condition where multiple cages don't compress pointers. This signals that the tests are related to concurrency and shared memory.

**2. Deeper Dive into Test Fixtures:**

* `TestJSSharedMemoryWithNativeContext`:  This base class name suggests the tests involve shared memory and a native JavaScript context. This reinforces the concurrency/shared memory theme.

**3. Analyzing the `LockingThread` Class:**

* `ParkingThread`: This base class strongly suggests these threads are managed by V8's parking/unparking mechanism, implying synchronization.
* Constructor parameters: `Handle<JSAtomicsMutex>`, `std::optional<base::TimeDelta> timeout`, `ParkingSemaphore*`. These immediately hint at mutex locking with optional timeouts and semaphores for thread coordination.
* `Run()` method:  It creates an `IsolateWithContextWrapper` (essential for running JavaScript code), calls `LockJSMutexAndSignal`, sleeps briefly, and then unlocks the mutex if it was acquired.
* `LockJSMutexAndSignal()`:  This is the core logic. It signals a "ready" semaphore, waits on a "start execution" semaphore, attempts to lock the mutex (potentially with a timeout), asserts the lock state, and returns whether the lock was acquired.

**4. Analyzing the `BlockingLockingThread` Class:**

* It inherits from `LockingThread`. This means it shares the basic locking behavior.
* The key difference lies in the `Run()` method. After acquiring the lock, it enters a `while` loop controlled by `should_wait_`, using a `ParkingConditionVariable` to wait for a notification. This indicates a test case for blocking and waiting on a condition.
* `NotifyCV()`:  This method signals the condition variable, allowing the blocking thread to proceed.

**5. Analyzing the `WaitOnConditionThread` Class:**

* Constructor parameters: `Handle<JSAtomicsMutex>`, `Handle<JSAtomicsCondition>`, `uint32_t* waiting_threads_count`, `ParkingSemaphore*`. This confirms tests for condition variables.
* `Run()` method: It acquires a mutex, enters a `while(keep_waiting)` loop, increments a counter, waits on the condition variable, decrements the counter, and finally unlocks the mutex.

**6. Analyzing the Test Cases:**

* `TEST_F(JSAtomicsMutexTest, Contention)`: Creates multiple `LockingThread` instances. This strongly suggests testing the mutex's behavior under contention (multiple threads trying to acquire the lock). The semaphores are used for precise synchronization to ensure all threads attempt to lock around the same time.
* `TEST_F(JSAtomicsMutexTest, Timeout)`:  Uses one `BlockingLockingThread` to hold the lock and multiple `LockingThread` instances with timeouts. This is clearly testing the mutex's timeout functionality.
* `TEST_F(JSAtomicsConditionTest, NotifyAll)`: Creates multiple `WaitOnConditionThread` instances. This tests the condition variable's `NotifyAll` functionality, ensuring that all waiting threads are woken up.

**7. Connecting to JavaScript:**

* The core functionality being tested (mutexes and condition variables) directly relates to JavaScript's `SharedArrayBuffer` and the Atomics API. I know that JavaScript uses these primitives for synchronizing access to shared memory. Therefore, I can provide JavaScript examples using `Atomics.wait`, `Atomics.notify`, and the concept of shared memory.

**8. Considering Potential Programming Errors:**

* The code itself provides clues. The timeout test demonstrates the danger of indefinite blocking. The contention test implicitly highlights the need for careful lock management to avoid deadlocks or performance bottlenecks. Missing unlocks and incorrect wait/notify patterns are common pitfalls.

**9. Structuring the Explanation:**

* Start with a high-level summary of the file's purpose.
* List the key functionalities (mutex testing, timeout testing, condition variable testing).
* Emphasize the conditional compilation based on shared heap support.
* Explain each class and its role in the tests.
* Provide JavaScript examples to illustrate the connection to the JavaScript API.
* Construct example scenarios with inputs and outputs to demonstrate the logic.
* List common programming errors related to mutexes and condition variables.
* Conclude with the overall significance of the code.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the low-level details of the `ParkingThread` and semaphores. However, realizing the core purpose is testing the *JS Atomics* primitives, I shifted the emphasis to how these classes facilitate that testing.
* I made sure to explicitly mention the shared memory aspect, as the `#if` directive clearly indicates its importance.
* When generating JavaScript examples, I focused on clarity and direct correspondence to the C++ concepts. I avoided overly complex JavaScript code.
* For the input/output examples, I aimed for simple, illustrative scenarios rather than exhaustive test cases.

By following this thought process, combining code analysis with domain knowledge of V8 and concurrent programming, I can arrive at a comprehensive and accurate explanation of the provided C++ code.
这个C++源代码文件 `v8/test/unittests/js-atomics/js-atomics-synchronization-primitive-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 JavaScript Atomics API 中的同步原语，主要是 `JSAtomicsMutex`（互斥锁）和 `JSAtomicsCondition`（条件变量）。

**功能概述:**

该文件包含了一系列单元测试，用于验证 `JSAtomicsMutex` 和 `JSAtomicsCondition` 的各种行为和特性，特别是在多线程环境下的正确性。这些测试主要关注以下几个方面：

1. **互斥锁 (JSAtomicsMutex):**
   - **争用 (Contention):** 测试多个线程尝试获取同一个互斥锁时的行为，验证锁的排他性，确保只有一个线程能够成功获取锁。
   - **超时 (Timeout):** 测试在尝试获取锁时设置超时时间的效果，验证当超过超时时间后，线程能够放弃获取锁。

2. **条件变量 (JSAtomicsCondition):**
   - **通知所有等待者 (NotifyAll):** 测试当一个线程通知条件变量时，所有等待在该条件变量上的线程都被唤醒。

**代码结构分析:**

- **头文件包含:** 包含了必要的 V8 内部头文件，用于访问互斥锁、条件变量的实现，以及测试框架 (gtest) 和平台相关的工具。
- **条件编译:**  `#if V8_CAN_CREATE_SHARED_HEAP_BOOL && !COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL` 表明这些测试是针对支持共享堆且未启用多 Cage 指针压缩的场景。这暗示了这些测试与跨线程共享内存的同步有关。
- **命名空间:** 代码位于 `v8::internal` 命名空间下，表明这是 V8 引擎内部的测试。
- **测试 Fixture:** 定义了 `JSAtomicsMutexTest` 和 `JSAtomicsConditionTest` 两个测试 Fixture，它们继承自 `TestJSSharedMemoryWithNativeContext`，表明测试需要在具有本地上下文的共享内存环境中进行。
- **辅助线程类:** 定义了 `LockingThread` 和 `BlockingLockingThread` 用于模拟多线程环境下的锁竞争和超时场景。`WaitOnConditionThread` 用于模拟等待条件变量的线程。
- **测试用例:**  使用 `TEST_F` 宏定义了具体的测试用例，例如 `Contention` 和 `Timeout` 用于测试互斥锁，`NotifyAll` 用于测试条件变量。

**与 JavaScript 的关系 (如果适用):**

`JSAtomicsMutex` 和 `JSAtomicsCondition` 是 JavaScript Atomics API 的底层实现。在 JavaScript 中，开发者可以使用 `SharedArrayBuffer` 来创建共享内存，并使用 `Atomics.wait()` 和 `Atomics.notify()` (以及 `Atomics.notifyAll()`) 方法来进行线程间的同步。

**JavaScript 示例:**

```javascript
// 创建一个共享的 Int32Array
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const sharedArray = new Int32Array(sab);

// 索引 0 作为锁，初始值为 0 (未锁定)
const lockIndex = 0;
// 索引 1 作为共享数据
const dataIndex = 1;

// 线程 1
function thread1() {
  console.log("线程 1 尝试获取锁");
  while (Atomics.compareExchange(sharedArray, lockIndex, 0, 1) !== 0) {
    // 自旋等待，或者可以考虑使用 Atomics.wait() 进入休眠
    // console.log("线程 1 等待锁");
  }
  console.log("线程 1 获取到锁");
  // 访问共享数据
  sharedArray[dataIndex] += 1;
  console.log("线程 1 修改共享数据为:", sharedArray[dataIndex]);
  // 释放锁
  Atomics.store(sharedArray, lockIndex, 0);
  console.log("线程 1 释放锁");
}

// 线程 2
function thread2() {
  console.log("线程 2 尝试获取锁");
  while (Atomics.compareExchange(sharedArray, lockIndex, 0, 1) !== 0) {
    // 自旋等待，或者可以考虑使用 Atomics.wait() 进入休眠
    // console.log("线程 2 等待锁");
  }
  console.log("线程 2 获取到锁");
  // 访问共享数据
  sharedArray[dataIndex] += 1;
  console.log("线程 2 修改共享数据为:", sharedArray[dataIndex]);
  // 释放锁
  Atomics.store(sharedArray, lockIndex, 0);
  console.log("线程 2 释放锁");
}

// 启动两个 Worker 线程 (需要在支持 Worker 的环境下运行)
const worker1 = new Worker(URL.createObjectURL(new Blob([`(${thread1.toString()})()`])));
const worker2 = new Worker(URL.createObjectURL(new Blob([`(${thread2.toString()})()`])));
```

这个 JavaScript 示例展示了如何使用 `SharedArrayBuffer` 和 `Atomics.compareExchange` 模拟一个简单的互斥锁。`v8/test/unittests/js-atomics/js-atomics-synchronization-primitive-unittest.cc` 中的 C++ 代码正是测试 V8 引擎中实现这些原子操作的基础设施。

**代码逻辑推理 (假设输入与输出):**

**测试用例: `TEST_F(JSAtomicsMutexTest, Contention)`**

**假设输入:**

- 创建一个 `JSAtomicsMutex` 实例。
- 启动 32 个线程（`kThreads = 32`），每个线程尝试获取该互斥锁，如果获取到则短暂停顿后释放。

**预期输出:**

- 所有 32 个线程都会执行完成。
- 在任意时刻，只有一个线程持有该互斥锁。
- 最终，互斥锁处于未持有状态 (`EXPECT_FALSE(contended_mutex->IsHeld())`)。

**测试用例: `TEST_F(JSAtomicsMutexTest, Timeout)`**

**假设输入:**

- 创建一个 `JSAtomicsMutex` 实例。
- 启动一个 `BlockingLockingThread`，该线程会成功获取锁并一直持有，直到被主线程通知。
- 启动 31 个 `LockingThread`，每个线程尝试获取该互斥锁，并设置了一个较短的超时时间（1 毫秒）。

**预期输出:**

- `BlockingLockingThread` 成功获取锁。
- 其他 31 个线程尝试获取锁会因超时而失败。
- 在超时测试期间，互斥锁是被 `BlockingLockingThread` 持有的 (`EXPECT_TRUE(contended_mutex->IsHeld())`)。
- 当 `BlockingLockingThread` 释放锁后，互斥锁变为未持有状态 (`EXPECT_FALSE(contended_mutex->IsHeld())`)。

**测试用例: `TEST_F(JSAtomicsConditionTest, NotifyAll)`**

**假设输入:**

- 创建一个 `JSAtomicsMutex` 实例和一个 `JSAtomicsCondition` 实例。
- 启动 32 个 `WaitOnConditionThread`，每个线程获取互斥锁后，调用条件变量的等待方法。

**预期输出:**

- 所有 32 个线程都会进入条件变量的等待状态。
- 当主线程调用 `JSAtomicsCondition::Notify` 并指定唤醒所有等待者 (`JSAtomicsCondition::kAllWaiters`) 后，所有 32 个线程都会被唤醒。
- 所有线程最终都会执行完成，并且互斥锁处于未持有状态。

**用户常见的编程错误 (与互斥锁和条件变量相关):**

1. **死锁 (Deadlock):** 多个线程互相等待对方释放资源（通常是互斥锁），导致所有线程都无法继续执行。
   ```c++
   // 线程 1 持有 mutexA，尝试获取 mutexB
   mutexA.Lock();
   // ...
   mutexB.Lock(); // 如果线程 2 持有 mutexB 并尝试获取 mutexA，则会发生死锁

   // 线程 2 持有 mutexB，尝试获取 mutexA
   mutexB.Lock();
   // ...
   mutexA.Lock();
   ```

2. **忘记释放锁:** 线程获取锁后，在退出临界区之前忘记释放锁，导致其他线程永久阻塞。
   ```c++
   mutex.Lock();
   // ... 访问共享资源
   // 忘记调用 mutex.Unlock();
   ```

3. **条件变量的虚假唤醒 (Spurious Wakeup):** 线程从条件变量的等待状态被唤醒，但实际上条件并未满足。因此，在从 `WaitFor` 返回后，应该总是检查条件是否满足，并在不满足时继续等待。
   ```c++
   mutex.Lock();
   while (!condition_is_met) { // 使用 while 循环检查条件
     condition.WaitFor(mutex);
   }
   // ... 处理共享资源
   mutex.Unlock();
   ```

4. **在未持有锁的情况下操作条件变量:**  条件变量的 `WaitFor` 和 `Notify` 操作必须在持有与该条件变量关联的互斥锁的情况下进行。否则，可能导致未定义的行为，例如丢失通知或竞争条件。
   ```c++
   // 错误：在没有持有 mutex 的情况下调用 WaitFor
   condition.WaitFor(mutex);

   mutex.Lock();
   condition.NotifyOne();
   mutex.Unlock();
   ```

5. **使用错误的通知方式:**  根据需要，应该使用 `NotifyOne` (唤醒一个等待线程) 或 `NotifyAll` (唤醒所有等待线程)。错误的选择可能导致某些线程一直等待，或者唤醒不必要的线程导致性能下降。

总而言之，`v8/test/unittests/js-atomics/js-atomics-synchronization-primitive-unittest.cc` 是一个关键的测试文件，用于确保 V8 引擎中 JavaScript Atomics API 的同步原语在各种并发场景下的正确性和可靠性，这对于构建安全的、多线程的 JavaScript 应用至关重要。

### 提示词
```
这是目录为v8/test/unittests/js-atomics/js-atomics-synchronization-primitive-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/js-atomics/js-atomics-synchronization-primitive-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/heap/parked-scope-inl.h"
#include "src/objects/js-atomics-synchronization-inl.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

// In multi-cage mode we create one cage per isolate
// and we don't share objects between cages.
#if V8_CAN_CREATE_SHARED_HEAP_BOOL && !COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL

namespace v8 {
namespace internal {

using JSAtomicsMutexTest = TestJSSharedMemoryWithNativeContext;
using JSAtomicsConditionTest = TestJSSharedMemoryWithNativeContext;

namespace {

class LockingThread : public ParkingThread {
 public:
  LockingThread(Handle<JSAtomicsMutex> mutex,
                std::optional<base::TimeDelta> timeout,
                ParkingSemaphore* sema_ready,
                ParkingSemaphore* sema_execute_start,
                ParkingSemaphore* sema_execute_complete)
      : ParkingThread(Options("LockingThread")),
        mutex_(mutex),
        timeout_(timeout),
        sema_ready_(sema_ready),
        sema_execute_start_(sema_execute_start),
        sema_execute_complete_(sema_execute_complete) {}

  void Run() override {
    IsolateWithContextWrapper isolate_wrapper;
    Isolate* isolate = isolate_wrapper.isolate();
    bool locked = LockJSMutexAndSignal(isolate);
    base::OS::Sleep(base::TimeDelta::FromMilliseconds(1));
    if (locked) {
      mutex_->Unlock(isolate);
    } else {
      EXPECT_TRUE(timeout_.has_value());
    }
    sema_execute_complete_->Signal();
  }

 protected:
  bool LockJSMutexAndSignal(Isolate* isolate) {
    sema_ready_->Signal();
    sema_execute_start_->ParkedWait(isolate->main_thread_local_isolate());

    HandleScope scope(isolate);
    bool locked = JSAtomicsMutex::Lock(isolate, mutex_, timeout_);
    if (locked) {
      EXPECT_TRUE(mutex_->IsHeld());
      EXPECT_TRUE(mutex_->IsCurrentThreadOwner());
    } else {
      EXPECT_FALSE(mutex_->IsCurrentThreadOwner());
    }
    return locked;
  }

  Handle<JSAtomicsMutex> mutex_;
  std::optional<base::TimeDelta> timeout_;
  ParkingSemaphore* sema_ready_;
  ParkingSemaphore* sema_execute_start_;
  ParkingSemaphore* sema_execute_complete_;
};

class BlockingLockingThread final : public LockingThread {
 public:
  BlockingLockingThread(Handle<JSAtomicsMutex> mutex,
                        std::optional<base::TimeDelta> timeout,
                        ParkingSemaphore* sema_ready,
                        ParkingSemaphore* sema_execute_start,
                        ParkingSemaphore* sema_execute_complete)
      : LockingThread(mutex, timeout, sema_ready, sema_execute_start,
                      sema_execute_complete) {}

  void Run() override {
    IsolateWithContextWrapper isolate_wrapper;
    Isolate* isolate = isolate_wrapper.isolate();
    EXPECT_TRUE(LockJSMutexAndSignal(isolate));
    {
      // Hold the js lock until the main thread notifies us.
      base::MutexGuard guard(&mutex_for_cv_);
      sema_execute_complete_->Signal();
      should_wait_ = true;
      while (should_wait_) {
        cv_.ParkedWait(isolate->main_thread_local_isolate(), &mutex_for_cv_);
      }
    }
    mutex_->Unlock(isolate);
    sema_execute_complete_->Signal();
  }

  void NotifyCV() {
    base::MutexGuard guard(&mutex_for_cv_);
    should_wait_ = false;
    cv_.NotifyOne();
  }

 private:
  base::Mutex mutex_for_cv_;
  ParkingConditionVariable cv_;
  bool should_wait_;
};

}  // namespace

TEST_F(JSAtomicsMutexTest, Contention) {
  constexpr int kThreads = 32;

  Isolate* i_main_isolate = i_isolate();
  Handle<JSAtomicsMutex> contended_mutex =
      i_main_isolate->factory()->NewJSAtomicsMutex();
  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_execute_start(0);
  ParkingSemaphore sema_execute_complete(0);
  std::vector<std::unique_ptr<LockingThread>> threads;
  for (int i = 0; i < kThreads; i++) {
    auto thread = std::make_unique<LockingThread>(
        contended_mutex, std::nullopt, &sema_ready, &sema_execute_start,
        &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  LocalIsolate* local_isolate = i_main_isolate->main_thread_local_isolate();
  for (int i = 0; i < kThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }
  for (int i = 0; i < kThreads; i++) sema_execute_start.Signal();
  for (int i = 0; i < kThreads; i++) {
    sema_execute_complete.ParkedWait(local_isolate);
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);

  EXPECT_FALSE(contended_mutex->IsHeld());
}

TEST_F(JSAtomicsMutexTest, Timeout) {
  constexpr int kThreads = 32;

  Isolate* i_main_isolate = i_isolate();
  Handle<JSAtomicsMutex> contended_mutex =
      i_main_isolate->factory()->NewJSAtomicsMutex();
  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_execute_start(0);
  ParkingSemaphore sema_execute_complete(0);
  std::unique_ptr<BlockingLockingThread> blocking_thread =
      std::make_unique<BlockingLockingThread>(contended_mutex, std::nullopt,
                                              &sema_ready, &sema_execute_start,
                                              &sema_execute_complete);

  LocalIsolate* local_isolate = i_main_isolate->main_thread_local_isolate();
  CHECK(blocking_thread->Start());
  sema_ready.ParkedWait(local_isolate);
  sema_execute_start.Signal();
  sema_execute_complete.ParkedWait(local_isolate);

  std::vector<std::unique_ptr<LockingThread>> threads;
  for (int i = 1; i < kThreads; i++) {
    auto thread = std::make_unique<LockingThread>(
        contended_mutex, base::TimeDelta::FromMilliseconds(1), &sema_ready,
        &sema_execute_start, &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  for (int i = 1; i < kThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }
  for (int i = 1; i < kThreads; i++) sema_execute_start.Signal();
  for (int i = 1; i < kThreads; i++) {
    sema_execute_complete.ParkedWait(local_isolate);
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);
  EXPECT_TRUE(contended_mutex->IsHeld());
  blocking_thread->NotifyCV();
  sema_execute_complete.ParkedWait(local_isolate);
  EXPECT_FALSE(contended_mutex->IsHeld());
  blocking_thread->ParkedJoin(local_isolate);
}

namespace {
class WaitOnConditionThread final : public ParkingThread {
 public:
  WaitOnConditionThread(Handle<JSAtomicsMutex> mutex,
                        Handle<JSAtomicsCondition> condition,
                        uint32_t* waiting_threads_count,
                        ParkingSemaphore* sema_ready,
                        ParkingSemaphore* sema_execute_complete)
      : ParkingThread(Options("WaitOnConditionThread")),
        mutex_(mutex),
        condition_(condition),
        waiting_threads_count_(waiting_threads_count),
        sema_ready_(sema_ready),
        sema_execute_complete_(sema_execute_complete) {}

  void Run() override {
    IsolateWithContextWrapper isolate_wrapper;
    Isolate* isolate = isolate_wrapper.isolate();

    sema_ready_->Signal();

    HandleScope scope(isolate);
    JSAtomicsMutex::Lock(isolate, mutex_);
    while (keep_waiting) {
      (*waiting_threads_count_)++;
      EXPECT_TRUE(JSAtomicsCondition::WaitFor(isolate, condition_, mutex_,
                                              std::nullopt));
      (*waiting_threads_count_)--;
    }
    mutex_->Unlock(isolate);

    sema_execute_complete_->Signal();
  }

  bool keep_waiting = true;

 private:
  Handle<JSAtomicsMutex> mutex_;
  Handle<JSAtomicsCondition> condition_;
  uint32_t* waiting_threads_count_;
  ParkingSemaphore* sema_ready_;
  ParkingSemaphore* sema_execute_complete_;
};
}  // namespace

TEST_F(JSAtomicsConditionTest, NotifyAll) {
  constexpr uint32_t kThreads = 32;

  Isolate* i_main_isolate = i_isolate();
  Handle<JSAtomicsMutex> mutex = i_main_isolate->factory()->NewJSAtomicsMutex();
  Handle<JSAtomicsCondition> condition =
      i_main_isolate->factory()->NewJSAtomicsCondition();

  uint32_t waiting_threads_count = 0;
  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_execute_complete(0);
  std::vector<std::unique_ptr<WaitOnConditionThread>> threads;
  for (uint32_t i = 0; i < kThreads; i++) {
    auto thread = std::make_unique<WaitOnConditionThread>(
        mutex, condition, &waiting_threads_count, &sema_ready,
        &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  LocalIsolate* local_isolate = i_main_isolate->main_thread_local_isolate();
  for (uint32_t i = 0; i < kThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }

  // Wait until all threads are waiting on the condition.
  for (;;) {
    JSAtomicsMutex::LockGuard lock_guard(i_main_isolate, mutex);
    uint32_t count = waiting_threads_count;
    if (count == kThreads) break;
  }

  // Wake all the threads up.
  for (uint32_t i = 0; i < kThreads; i++) {
    threads[i]->keep_waiting = false;
  }
  EXPECT_EQ(kThreads,
            JSAtomicsCondition::Notify(i_main_isolate, condition,
                                       JSAtomicsCondition::kAllWaiters));

  for (uint32_t i = 0; i < kThreads; i++) {
    sema_execute_complete.ParkedWait(local_isolate);
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);

  EXPECT_EQ(0U, waiting_threads_count);
  EXPECT_FALSE(mutex->IsHeld());
}

}  // namespace internal
}  // namespace v8

#endif  // V8_CAN_CREATE_SHARED_HEAP
```