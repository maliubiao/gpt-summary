Response:
Let's break down the thought process for analyzing the C++ mutex unittest code.

1. **Understanding the Goal:** The request asks for an analysis of the provided C++ code, focusing on its functionality, potential relation to JavaScript (if any), logical reasoning, and common user errors. The file path `v8/test/unittests/base/platform/mutex-unittest.cc` immediately signals that this is a testing file for mutex functionality within the V8 JavaScript engine.

2. **Initial Code Scan and Identification of Key Elements:**
   - **Includes:** Identify the included headers (`mutex.h`, `<chrono>`, `<queue>`, `<thread>`, `condition-variable.h`, etc.). This gives a high-level understanding of the dependencies and concepts being tested (threading, time, queues, synchronization primitives).
   - **Namespaces:** Note the `v8::base` namespace. This confirms it's within the V8 codebase and related to base functionalities.
   - **`TEST` Macros:** The extensive use of `TEST(ClassName, TestName)` immediately flags this as a Google Test unit test file. Each `TEST` block represents a specific test case.
   - **Mutex Types:**  Look for the mutex types being tested: `Mutex`, `RecursiveMutex`, `LazyMutex`, `LazyRecursiveMutex`, and `SharedMutex`. This is the core subject of the file.
   - **Synchronization Primitives:** Notice the usage of `MutexGuard`, `LockGuard`, and `ConditionVariable`. These are standard tools for managing mutexes and thread synchronization.
   - **Threading Constructs:** The use of `std::thread` and the custom `SharedMutexTestWorker` class highlights that concurrency and thread safety are being tested.
   - **Assertions:** The presence of `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_EQ` indicates assertions used to verify the expected behavior of the mutex implementations.
   - **Fuzz Testing:** The `#ifdef V8_ENABLE_FUZZTEST` block and `V8_FUZZ_TEST` macro point to fuzz testing integration.

3. **Analyzing Individual Test Cases:**  Go through each `TEST` block and understand its purpose:
   - **`LockGuardMutex` and `LockGuardRecursiveMutex`:** Basic locking and unlocking with RAII (Resource Acquisition Is Initialization) using `MutexGuard` and `LockGuard`. The recursive version tests nested locking.
   - **`LockGuardLazyMutex` and `LockGuardLazyRecursiveMutex`:** Similar to the above, but for lazily initialized mutexes.
   - **`MultipleMutexes` and `MultipleRecursiveMutexes`:** Tests the ability to lock and unlock multiple independent mutexes and the behavior of `TryLock` with recursive mutexes.
   - **`SharedMutexSimple`:** Basic locking and unlocking of shared and exclusive locks.
   - **`SharedMutexThreads`:** A more complex test involving multiple threads interacting with a `SharedMutex`, using a custom worker class for managing actions. This is where concurrency testing becomes more apparent.
   - **`SharedMutexThreadsFuzz` and `SharedMutexThreadsP`:** Tests involving a larger number of threads and a parameterized approach, including a fuzz testing scenario.

4. **Considering JavaScript Relevance:**
   - **Event Loop and Single-Threaded Nature (Initially):** Recall that JavaScript is traditionally single-threaded. Mutexes are inherently about managing access in concurrent environments. Therefore, a direct, literal mapping of these C++ mutexes to JavaScript *within a single thread* isn't accurate.
   - **Web Workers and SharedArrayBuffer:** Realize that modern JavaScript *does* have concurrency through Web Workers and shared memory structures like `SharedArrayBuffer`. These are the contexts where concepts similar to mutexes become relevant in JavaScript.
   - **Atomics and Synchronization Primitives:** Connect the C++ mutexes to JavaScript's atomic operations (e.g., `Atomics.compareExchange`) and the need for higher-level synchronization patterns when dealing with shared memory in workers. This allows for a conceptual link, even if the direct implementation differs. *(Self-correction: Initially, I might have focused too much on the single-threaded aspect, but remembering Web Workers is crucial).*

5. **Logical Reasoning and Examples:**
   - For the simpler tests, the logic is straightforward (lock, unlock, try lock, etc.). Provide simple scenarios and expected outcomes.
   - For `SharedMutexThreads`,  trace the actions of the workers to understand the expected locking and unlocking order and the assertions being made.
   - When discussing shared mutexes, emphasize the core principles: multiple readers can hold the lock simultaneously, but only one writer can hold it exclusively.

6. **Common Programming Errors:**
   - **Deadlocks:** This is a classic mutex-related problem. Explain how it occurs (circular dependency in lock acquisition).
   - **Forgetting to Unlock:** The importance of always releasing a lock, potentially leading to deadlocks or resource starvation. Highlight how RAII (like `MutexGuard`) helps prevent this.
   - **Incorrect Use of Recursive Mutexes:** Emphasize that `Unlock` must be called as many times as `Lock` for a recursive mutex.
   - **Race Conditions (Implicit):** While not explicitly shown as errors *in the test*, the tests themselves aim to *prevent* race conditions in the *implementation* of the mutexes. Mention this connection.

7. **Fuzz Testing Analysis:**  Explain the purpose of fuzzing: automatically generating inputs to find edge cases and potential bugs. Highlight the parameterized nature of the fuzz test in the code.

8. **Structure and Language:** Organize the analysis clearly, using headings and bullet points. Explain technical terms (like RAII) concisely. Provide concrete JavaScript examples where applicable, focusing on the conceptual parallels rather than direct code equivalence.

9. **Review and Refinement:** Read through the entire analysis to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where the explanation could be improved. Ensure the language is accessible to someone who might not be deeply familiar with C++ threading. For example, initially, I might have assumed the reader knows what RAII is, but explicitly defining it makes the explanation better.

By following this structured approach, combining code analysis with an understanding of concurrency concepts and JavaScript's evolving capabilities, one can generate a comprehensive and accurate answer to the request.
## 功能列表：

`v8/test/unittests/base/platform/mutex-unittest.cc` 文件是一个 C++ 单元测试文件，用于测试 V8 JavaScript 引擎中 `base` 模块下 `platform` 子模块中的互斥锁（mutex）相关的功能。

具体来说，它测试了以下几种互斥锁及其相关操作：

1. **`Mutex` (普通互斥锁):**
   - 测试基本的加锁 (`Lock`) 和解锁 (`Unlock`) 操作。
   - 测试使用 `MutexGuard` 进行 RAII (Resource Acquisition Is Initialization) 风格的加锁和自动解锁。

2. **`RecursiveMutex` (递归互斥锁):**
   - 测试在同一线程中多次成功加锁和解锁同一个递归互斥锁。
   - 测试使用 `LockGuard<RecursiveMutex>` 进行 RAII 风格的加锁和自动解锁。
   - 测试 `TryLock` 方法在已持有锁的情况下返回 `true`。

3. **`LazyMutex` (延迟初始化互斥锁):**
   - 测试延迟初始化的互斥锁的加锁和解锁操作。
   - 测试使用 `MutexGuard` 搭配 `lazy_mutex.Pointer()` 进行加锁和自动解锁。

4. **`LazyRecursiveMutex` (延迟初始化递归互斥锁):**
   - 测试延迟初始化的递归互斥锁的加锁和解锁操作。
   - 测试使用 `LockGuard<RecursiveMutex>` 搭配 `lazy_recursive_mutex.Pointer()` 进行加锁和自动解锁。

5. **多互斥锁操作:**
   - 测试同时锁定和解锁多个独立的 `Mutex` 对象。
   - 测试同时锁定和解锁多个独立的 `RecursiveMutex` 对象，并验证 `TryLock` 的行为。

6. **`SharedMutex` (共享互斥锁 / 读写锁):**
   - 测试基本的共享锁 (`LockShared`, `UnlockShared`) 和独占锁 (`LockExclusive`, `UnlockExclusive`) 操作。
   - 测试在持有共享锁时，尝试获取独占锁会失败。
   - 测试在持有独占锁时，尝试获取共享锁或独占锁会失败。
   - 通过多线程场景测试 `SharedMutex` 的正确性，包括：
     - 创建多个工作线程，模拟并发访问共享资源。
     - 使用队列和条件变量控制线程的执行顺序和操作。
     - 验证在不同线程持有共享锁和独占锁时，其他线程的尝试加锁行为是否符合预期。
     - 使用原子变量 (`reader_count_`, `writer_count_`) 跟踪读写锁的状态。
   - 使用参数化测试和模糊测试 (`fuzztest`) 来更全面地测试 `SharedMutex` 在各种并发场景下的行为。

**关于文件扩展名 `.tq`：**

如果 `v8/test/unittests/base/platform/mutex-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 内部使用的类型化的汇编语言，用于生成高效的 JavaScript 内置函数。 然而，根据你提供的代码内容，这个文件是以 `.cc` 结尾的 C++ 文件，所以它**不是** Torque 源代码。

**与 JavaScript 的功能关系：**

互斥锁是并发编程中用于保护共享资源的关键机制。虽然 JavaScript 自身是单线程的（在主线程中），但它可以使用 **Web Workers** 来实现并行执行。当多个 Web Workers 需要访问和修改共享数据时，就需要类似的同步机制来避免数据竞争和保证数据一致性。

虽然 JavaScript 本身没有直接对应的 `Mutex` 类，但可以使用以下方式模拟或实现类似的功能：

1. **`Atomics` 对象和 `SharedArrayBuffer`：**  `SharedArrayBuffer` 允许在多个 Web Workers 之间共享内存。 `Atomics` 对象提供了一组原子操作，可以用来实现底层的同步原语，例如实现自旋锁或基于信号量的互斥。

   ```javascript
   // 在多个 Worker 之间共享的 ArrayBuffer
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const view = new Int32Array(sab);

   // 模拟一个简单的互斥锁（忙等待）
   function lock(index) {
     while (Atomics.compareExchange(view, index, 0, 1) !== 0) {
       // 自旋等待
     }
   }

   function unlock(index) {
     Atomics.store(view, index, 0);
   }

   // 在一个 Worker 中
   lock(0);
   // 访问和修改共享资源
   view[0]++;
   unlock(0);
   ```

2. **消息传递机制：** Web Workers 之间可以通过消息传递进行通信，可以设计基于消息传递的同步协议，但这通常比直接使用互斥锁更复杂。

**代码逻辑推理 (以 `SharedMutexThreads` 测试为例)：**

**假设输入：**

- 启动三个 `SharedMutexTestWorker` 线程，分别命名为 worker1、worker2 和 worker3。
- 初始状态：`reader_count = 0`, `writer_count = 0`，`SharedMutex` 处于未锁定状态。
- 执行以下操作序列：
    - worker1 执行 `LockShared`
    - worker2 执行 `LockShared`
    - worker3 执行 `LockExclusive`
    - worker3 执行 `Sleep`
    - worker1 执行 `UnlockShared`
    - worker1 执行 `LockExclusive`
    - worker2 执行 `UnlockShared`
    - worker2 执行 `LockShared`
    - worker2 执行 `Sleep`
    - worker1 执行 `UnlockExclusive`
    - worker3 执行 `UnlockExclusive`
    - worker2 执行 `UnlockShared`

**预期输出：**

- 在执行过程中，`reader_count` 和 `writer_count` 的值会根据线程持有的锁类型而变化。例如，当 worker1 和 worker2 持有共享锁时，`reader_count` 为 2，`writer_count` 为 0。当 worker1 持有独占锁时，`reader_count` 为 0，`writer_count` 为 1。
- 由于 `SharedMutex` 的特性，某些操作可能会被阻塞，直到满足加锁条件。例如，在 worker1 和 worker2 持有共享锁时，worker3 的 `LockExclusive` 操作会被阻塞。
- 最终，当所有线程都执行完毕并释放锁后，`reader_count` 和 `writer_count` 都将为 0。
- 最后，主线程可以成功获取共享锁和独占锁，证明 `SharedMutex` 已完全释放。

**代码逻辑推理 (更细致的执行流程):**

1. **worker1.Do(SharedMutexTestWorker::Action::kLockShared);**: worker1 尝试获取共享锁，成功。 `reader_count` 变为 1。
2. **worker2.Do(SharedMutexTestWorker::Action::kLockShared);**: worker2 尝试获取共享锁，成功（允许多个读者）。 `reader_count` 变为 2。
3. **worker3.Do(SharedMutexTestWorker::Action::kLockExclusive);**: worker3 尝试获取独占锁，失败（因为已经有共享锁被持有），worker3 会阻塞。
4. **worker3.Do(SharedMutexTestWorker::Action::kSleep);**:  worker3 虽然尝试执行 sleep，但由于 `LockExclusive` 被阻塞，实际上不会立即执行 sleep。
5. **worker1.Do(SharedMutexTestWorker::Action::kUnlockShared);**: worker1 释放共享锁。 `reader_count` 变为 1。
6. **worker1.Do(SharedMutexTestWorker::Action::kLockExclusive);**: worker1 尝试获取独占锁，成功（现在只有一个共享锁被 worker2 持有）。 `reader_count` 变为 0，`writer_count` 变为 1。
7. **worker2.Do(SharedMutexTestWorker::Action::kUnlockShared);**: worker2 释放共享锁。 `reader_count` 变为 0。
8. **worker2.Do(SharedMutexTestWorker::Action::kLockShared);**: worker2 尝试获取共享锁，失败（因为 worker1 持有独占锁），worker2 会阻塞。
9. **worker2.Do(SharedMutexTestWorker::Action::kSleep);**: worker2 虽然尝试执行 sleep，但由于 `LockShared` 被阻塞，实际上不会立即执行 sleep。
10. **worker1.Do(SharedMutexTestWorker::Action::kUnlockExclusive);**: worker1 释放独占锁。 `writer_count` 变为 0。 现在 worker3 和 worker2 的阻塞操作可以继续。
11. **worker3.Do(SharedMutexTestWorker::Action::kUnlockExclusive);**: worker3 的 `LockExclusive` 操作现在可以成功获取锁，然后立即释放。
12. **worker2.Do(SharedMutexTestWorker::Action::kUnlockShared);**: worker2 的 `LockShared` 操作现在可以成功获取锁，然后立即释放。

**用户常见的编程错误：**

1. **死锁 (Deadlock):**
   - **场景:** 两个或多个线程相互等待对方释放资源（通常是锁），导致所有线程都无法继续执行。
   - **示例:**
     ```c++
     Mutex mutex_a;
     Mutex mutex_b;

     void thread1_func() {
       mutex_a.Lock();
       // ... 一些操作 ...
       mutex_b.Lock(); // 线程 1 尝试获取 mutex_b
       // ...
       mutex_b.Unlock();
       mutex_a.Unlock();
     }

     void thread2_func() {
       mutex_b.Lock();
       // ... 一些操作 ...
       mutex_a.Lock(); // 线程 2 尝试获取 mutex_a
       // ...
       mutex_a.Unlock();
       mutex_b.Unlock();
     }
     ```
     如果线程 1 先获取了 `mutex_a`，线程 2 先获取了 `mutex_b`，那么线程 1 会阻塞等待线程 2 释放 `mutex_b`，而线程 2 会阻塞等待线程 1 释放 `mutex_a`，从而形成死锁。

2. **忘记解锁 (Forgetting to Unlock):**
   - **场景:** 线程获取了互斥锁，但在某些执行路径下忘记释放锁，导致其他线程永久阻塞。
   - **示例:**
     ```c++
     Mutex mutex;

     void critical_section() {
       mutex.Lock();
       // ... 一些操作 ...
       if (some_condition) {
         return; // 忘记解锁
       }
       mutex.Unlock();
     }
     ```
     如果 `some_condition` 为真，函数会提前返回，导致 `mutex` 没有被解锁。

3. **在不应该使用递归锁的地方使用递归锁：**
   - **场景:**  错误地认为递归锁可以解决所有多线程问题，而没有理解其适用场景。递归锁通常用于在同一个线程中可能多次请求同一个锁的情况。在跨线程的普通互斥场景下使用递归锁可能会掩盖潜在的错误。

4. **过度使用锁或使用不必要的锁：**
   - **场景:**  为了“安全”而对所有共享数据都加锁，导致性能下降，因为线程会花费大量时间等待锁。需要仔细分析哪些数据需要保护，并尽可能缩小锁的范围（细粒度锁）。

5. **不正确地使用共享锁和独占锁：**
   - **场景:** 在只需要共享访问的情况下使用了独占锁，或者在需要修改数据的情况下使用了共享锁，导致并发性能低下或数据不一致。

6. **在持有锁的情况下执行耗时操作：**
   - **场景:**  在持有互斥锁的情况下执行大量的计算或 I/O 操作，导致其他需要访问相同资源的线程长时间等待，降低并发性。应该尽量缩短持有锁的时间。

7. **条件竞争 (Race Condition):**
   - **场景:**  多个线程并发访问和修改共享数据，最终结果取决于线程执行的顺序，导致不可预测的结果。互斥锁的主要作用就是防止条件竞争。

理解和避免这些常见的编程错误对于编写健壮的多线程程序至关重要。单元测试（如 `mutex-unittest.cc`）的作用就是帮助开发者验证互斥锁的实现是否正确，并尽早发现潜在的并发问题。

### 提示词
```
这是目录为v8/test/unittests/base/platform/mutex-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/base/platform/mutex-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/platform/mutex.h"

#include <chrono>  // NOLINT(build/c++11)
#include <queue>
#include <thread>  // NOLINT(build/c++11)

#include "src/base/platform/condition-variable.h"
#include "src/base/platform/platform.h"
#include "src/base/utils/random-number-generator.h"
#include "test/unittests/fuzztest.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace base {

TEST(Mutex, LockGuardMutex) {
  Mutex mutex;
  { MutexGuard lock_guard(&mutex); }
  { MutexGuard lock_guard(&mutex); }
}


TEST(Mutex, LockGuardRecursiveMutex) {
  RecursiveMutex recursive_mutex;
  { LockGuard<RecursiveMutex> lock_guard(&recursive_mutex); }
  {
    LockGuard<RecursiveMutex> lock_guard1(&recursive_mutex);
    LockGuard<RecursiveMutex> lock_guard2(&recursive_mutex);
  }
}


TEST(Mutex, LockGuardLazyMutex) {
  LazyMutex lazy_mutex = LAZY_MUTEX_INITIALIZER;
  { MutexGuard lock_guard(lazy_mutex.Pointer()); }
  { MutexGuard lock_guard(lazy_mutex.Pointer()); }
}


TEST(Mutex, LockGuardLazyRecursiveMutex) {
  LazyRecursiveMutex lazy_recursive_mutex = LAZY_RECURSIVE_MUTEX_INITIALIZER;
  { LockGuard<RecursiveMutex> lock_guard(lazy_recursive_mutex.Pointer()); }
  {
    LockGuard<RecursiveMutex> lock_guard1(lazy_recursive_mutex.Pointer());
    LockGuard<RecursiveMutex> lock_guard2(lazy_recursive_mutex.Pointer());
  }
}


TEST(Mutex, MultipleMutexes) {
  Mutex mutex1;
  Mutex mutex2;
  Mutex mutex3;
  // Order 1
  mutex1.Lock();
  mutex2.Lock();
  mutex3.Lock();
  mutex1.Unlock();
  mutex2.Unlock();
  mutex3.Unlock();
  // Order 2
  mutex1.Lock();
  mutex2.Lock();
  mutex3.Lock();
  mutex3.Unlock();
  mutex2.Unlock();
  mutex1.Unlock();
}


TEST(Mutex, MultipleRecursiveMutexes) {
  RecursiveMutex recursive_mutex1;
  RecursiveMutex recursive_mutex2;
  // Order 1
  recursive_mutex1.Lock();
  recursive_mutex2.Lock();
  EXPECT_TRUE(recursive_mutex1.TryLock());
  EXPECT_TRUE(recursive_mutex2.TryLock());
  recursive_mutex1.Unlock();
  recursive_mutex1.Unlock();
  recursive_mutex2.Unlock();
  recursive_mutex2.Unlock();
  // Order 2
  recursive_mutex1.Lock();
  EXPECT_TRUE(recursive_mutex1.TryLock());
  recursive_mutex2.Lock();
  EXPECT_TRUE(recursive_mutex2.TryLock());
  recursive_mutex2.Unlock();
  recursive_mutex1.Unlock();
  recursive_mutex2.Unlock();
  recursive_mutex1.Unlock();
}

TEST(Mutex, SharedMutexSimple) {
  SharedMutex mutex;
  mutex.LockShared();
  mutex.UnlockShared();
  mutex.LockExclusive();
  mutex.UnlockExclusive();
  mutex.LockShared();
  mutex.UnlockShared();
}

namespace {

void CheckCannotLockShared(SharedMutex& mutex) {
  std::thread([&]() { EXPECT_FALSE(mutex.TryLockShared()); }).join();
}

void CheckCannotLockExclusive(SharedMutex& mutex) {
  std::thread([&]() { EXPECT_FALSE(mutex.TryLockExclusive()); }).join();
}

class SharedMutexTestWorker : public Thread {
  // This class starts a thread that can lock/unlock shared/exclusive a
  // SharedMutex. The thread has a queue of actions that it needs to execute
  // (FIFO). Tasks can be added to the queue through the method `Do`.
  // After each lock/unlock, this class does a few checks about the state of the
  // SharedMutex (e.g., if we hold a shared lock on a mutex, no one can hold an
  // exclusive lock on this mutex).
 public:
  explicit SharedMutexTestWorker(SharedMutex& shared_mutex,
                                 std::atomic<int>& reader_count,
                                 std::atomic<int>& writer_count)
      : Thread(Options("SharedMutexTestWorker")),
        shared_mutex_(shared_mutex),
        reader_count_(reader_count),
        writer_count_(writer_count) {
    EXPECT_TRUE(Start());
  }

  enum class Action {
    kLockShared,
    kUnlockShared,
    kLockExclusive,
    kUnlockExclusive,
    kSleep,
    kEnd
  };

  void Do(Action what) {
    MutexGuard guard(&queue_mutex_);
    actions_.push(what);
    cv_.NotifyOne();
  }

  void End() {
    Do(Action::kEnd);
    Join();
  }

  static constexpr int kSleepTimeMs = 5;

  void Run() override {
    while (true) {
      queue_mutex_.Lock();
      while (actions_.empty()) {
        cv_.Wait(&queue_mutex_);
      }
      Action action = actions_.front();
      actions_.pop();
      // Unblock the queue before processing the action, in order to not block
      // the queue if the action is blocked.
      queue_mutex_.Unlock();
      switch (action) {
        case Action::kLockShared:
          shared_mutex_.LockShared();
          EXPECT_EQ(writer_count_, 0);
          CheckCannotLockExclusive(shared_mutex_);
          reader_count_++;
          break;
        case Action::kUnlockShared:
          reader_count_--;
          EXPECT_EQ(writer_count_, 0);
          CheckCannotLockExclusive(shared_mutex_);
          shared_mutex_.UnlockShared();
          break;
        case Action::kLockExclusive:
          shared_mutex_.LockExclusive();
          EXPECT_EQ(reader_count_, 0);
          EXPECT_EQ(writer_count_, 0);
          CheckCannotLockShared(shared_mutex_);
          CheckCannotLockExclusive(shared_mutex_);
          writer_count_++;
          break;
        case Action::kUnlockExclusive:
          writer_count_--;
          EXPECT_EQ(reader_count_, 0);
          EXPECT_EQ(writer_count_, 0);
          CheckCannotLockShared(shared_mutex_);
          CheckCannotLockExclusive(shared_mutex_);
          shared_mutex_.UnlockExclusive();
          break;
        case Action::kSleep:
          std::this_thread::sleep_for(std::chrono::milliseconds(kSleepTimeMs));
          break;
        case Action::kEnd:
          return;
      }
    }
  }

 private:
  // {actions_}, the queue of actions to execute, is shared between the thread
  // and the object. Holding {queue_mutex_} is required to access it. When the
  // queue is empty, the thread will Wait on {cv_}. Once `Do` adds an item to
  // the queue, it should NotifyOne on {cv_} to wake up the thread.
  Mutex queue_mutex_;
  ConditionVariable cv_;
  std::queue<Action> actions_;

  SharedMutex& shared_mutex_;

  // {reader_count} and {writer_count_} are used to verify the integrity of
  // {shared_mutex_}. For instance, if a thread acquires a shared lock, we
  // expect {writer_count_} to be 0.
  std::atomic<int>& reader_count_;
  std::atomic<int>& writer_count_;
};

}  // namespace

TEST(Mutex, SharedMutexThreads) {
  // A simple hand-written scenario involving 3 threads using the SharedMutex.
  SharedMutex mutex;
  std::atomic<int> reader_count = 0;
  std::atomic<int> writer_count = 0;

  SharedMutexTestWorker worker1(mutex, reader_count, writer_count);
  SharedMutexTestWorker worker2(mutex, reader_count, writer_count);
  SharedMutexTestWorker worker3(mutex, reader_count, writer_count);

  worker1.Do(SharedMutexTestWorker::Action::kLockShared);
  worker2.Do(SharedMutexTestWorker::Action::kLockShared);
  worker3.Do(SharedMutexTestWorker::Action::kLockExclusive);
  worker3.Do(SharedMutexTestWorker::Action::kSleep);
  worker1.Do(SharedMutexTestWorker::Action::kUnlockShared);
  worker1.Do(SharedMutexTestWorker::Action::kLockExclusive);
  worker2.Do(SharedMutexTestWorker::Action::kUnlockShared);
  worker2.Do(SharedMutexTestWorker::Action::kLockShared);
  worker2.Do(SharedMutexTestWorker::Action::kSleep);
  worker1.Do(SharedMutexTestWorker::Action::kUnlockExclusive);
  worker3.Do(SharedMutexTestWorker::Action::kUnlockExclusive);
  worker2.Do(SharedMutexTestWorker::Action::kUnlockShared);

  worker1.End();
  worker2.End();
  worker3.End();

  EXPECT_EQ(reader_count, 0);
  EXPECT_EQ(writer_count, 0);

  // Since the all of the worker threads are done, we should be able to take
  // both the shared and exclusive lock.
  EXPECT_TRUE(mutex.TryLockShared());
  mutex.UnlockShared();
  EXPECT_TRUE(mutex.TryLockExclusive());
  mutex.UnlockExclusive();
}

void SharedMutexThreadsP(
    const std::pair<int, std::vector<std::vector<bool>>>& instructions) {
  // This is a parameterized test, shared between the actual test below, which
  // executes a single instance, and a fuzz test below that, which executes it
  // through the fuzz-test engine.
  SharedMutex mutex;
  std::atomic<int> reader_count = 0;
  std::atomic<int> writer_count = 0;

  int kThreadCount = instructions.first;

  std::vector<SharedMutexTestWorker*> workers;
  for (int i = 0; i < kThreadCount; i++) {
    workers.push_back(
        new SharedMutexTestWorker(mutex, reader_count, writer_count));
  }

  base::RandomNumberGenerator rand_gen(GTEST_FLAG_GET(random_seed));
  for (const auto& instructions_per_thread : instructions.second) {
    for (int j = 0; const bool instr : instructions_per_thread) {
      if (instr) {
        workers[j]->Do(SharedMutexTestWorker::Action::kLockExclusive);
        workers[j]->Do(SharedMutexTestWorker::Action::kSleep);
        workers[j]->Do(SharedMutexTestWorker::Action::kUnlockExclusive);
      } else {
        workers[j]->Do(SharedMutexTestWorker::Action::kLockShared);
        workers[j]->Do(SharedMutexTestWorker::Action::kSleep);
        workers[j]->Do(SharedMutexTestWorker::Action::kUnlockShared);
      }
      ++j;
    }
  }
  for (int i = 0; i < kThreadCount; i++) {
    workers[i]->End();
    delete workers[i];
  }

  EXPECT_EQ(reader_count, 0);
  EXPECT_EQ(writer_count, 0);

  // Since the all of the worker threads are done, we should be able to take
  // both the shared and exclusive lock.
  EXPECT_TRUE(mutex.TryLockShared());
  mutex.UnlockShared();
  EXPECT_TRUE(mutex.TryLockExclusive());
  mutex.UnlockExclusive();
}

TEST(Mutex, SharedMutexThreadsFuzz) {
  // This test creates a lot of threads, each of which tries to take shared or
  // exclusive lock on a single SharedMutex.
  static constexpr int kThreadCount = 50;
  static constexpr int kActionPerWorker = 10;
  static constexpr int kReadToWriteRatio = 5;

  std::vector<std::vector<bool>> instructions;

  base::RandomNumberGenerator rand_gen(GTEST_FLAG_GET(random_seed));
  for (int i = 0; i < kActionPerWorker; i++) {
    std::vector<bool> instructions_per_thread;
    for (int j = 0; j < kThreadCount; j++) {
      instructions_per_thread.emplace_back(
          rand_gen.NextInt() % kReadToWriteRatio == 0);
    }
    instructions.emplace_back(std::move(instructions_per_thread));
  }

  SharedMutexThreadsP(std::make_pair(kThreadCount, instructions));
}

#ifdef V8_ENABLE_FUZZTEST
auto SharedMutexTestInstructions() {
  // Returns a domain that fuzzes over a certain thread count and a number of
  // workers with the associated instructions per thread. The thread count
  // varies between [2, 70], the worker count between [2, 15].
  auto count_with_vector = [](const int& count) {
    return fuzztest::PairOf(
        fuzztest::Just(count),
        fuzztest::VectorOf(
            fuzztest::VectorOf(fuzztest::Arbitrary<bool>()).WithSize(count))
            .WithMinSize(2)
            .WithMaxSize(15));
  };
  return fuzztest::FlatMap(count_with_vector, fuzztest::InRange(2, 70));
}

V8_FUZZ_TEST(MutexFuzzTest, SharedMutexThreadsP)
    .WithDomains(SharedMutexTestInstructions());
#endif  // V8_ENABLE_FUZZTEST

}  // namespace base
}  // namespace v8
```