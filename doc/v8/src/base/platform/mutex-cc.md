Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Core Purpose:** The file name `mutex.cc` within the `v8/src/base/platform` directory immediately suggests this code deals with mutexes, which are fundamental synchronization primitives for managing concurrent access to shared resources. The `platform` part indicates platform-specific implementations.

2. **Initial Scan for File Type:** The prompt asks about `.tq` files. A quick scan of the file contents reveals no `.tq` extension. Thus, the initial conclusion is that it's standard C++ and not Torque.

3. **Identifying Key Classes:**  Reading through the code, the main classes that jump out are `Mutex`, `RecursiveMutex`, and `SharedMutex`. These names strongly suggest their respective functionalities: basic mutex, mutex allowing recursive locking, and a reader-writer lock (allowing multiple readers or a single writer).

4. **Platform-Specific Implementations:** The `#if V8_OS_POSIX`, `#elif V8_OS_WIN`, and `#elif V8_OS_STARBOARD` preprocessor directives are crucial. This signifies that the code provides different implementations of the mutex classes based on the operating system. This is a common pattern for platform abstraction.

5. **Analyzing Each Mutex Type:**  For each mutex type, examine the core methods:
    * **Constructor/Destructor:** How is the underlying OS mutex initialized and destroyed?
    * **`Lock()`:** How is exclusive access acquired?
    * **`Unlock()`:** How is exclusive access released?
    * **`TryLock()`:** How is a non-blocking attempt to acquire exclusive access handled?
    * **`LockShared()`/`UnlockShared()`/`TryLockShared()` (for `SharedMutex`):** How are shared (read) locks acquired and released?
    * **`LockExclusive()`/`UnlockExclusive()`/`TryLockExclusive()` (for `SharedMutex`):** How are exclusive (write) locks acquired and released?

6. **Digging into Platform-Specific Details:**
    * **POSIX (`V8_OS_POSIX`):**  The code uses `pthread_mutex_t`, `pthread_mutex_init`, `pthread_mutex_lock`, etc. This points to the standard POSIX threads library. The debug-mode initialization with `PTHREAD_MUTEX_ERRORCHECK` is also noteworthy.
    * **Windows (`V8_OS_WIN`):** The code utilizes `SRWLOCK` (Slim Reader/Writer Lock) for `Mutex` and `SharedMutex`, and `CRITICAL_SECTION` for `RecursiveMutex`. The `V8ToWindowsType` function (not shown in the provided snippet but implied) is likely a helper to cast to the correct Windows type.
    * **Starboard (`V8_OS_STARBOARD`):** This uses `SbMutexCreate`, `SbMutexAcquire`, etc., indicating a Starboard-specific mutex API. The `RecursiveMutex` seems to rely on an internal `Acquire`/`Release` mechanism. `SharedMutex` has basic acquire/release for read/write locks but `TryLockShared`/`TryLockExclusive` always return `false`.

7. **Debug Assertions (`#ifdef DEBUG`):** Notice the `level_` variable in `Mutex` and `RecursiveMutex` and the logic around `single_held_shared_mutex` and `held_shared_mutexes` in the `DEBUG` block. This is for runtime checks to catch errors like double-locking or unlocking by the wrong thread.

8. **Relation to JavaScript (and lack thereof):**  The prompt asks about the connection to JavaScript. While these mutexes are *used by* the V8 engine (which runs JavaScript), this particular file is a low-level system utility. It doesn't directly expose functionality to JavaScript. Therefore, examples would involve *hypothetical* scenarios where JavaScript code indirectly triggers the use of these mutexes within V8's implementation. Think about concurrent JavaScript tasks or accessing shared data within the engine.

9. **Code Logic Reasoning:**  Focus on the `TryHoldSharedMutex` and `TryReleaseSharedMutex` functions within the `DEBUG` block. Trace the logic for how they track held shared mutexes, especially the transition from `single_held_shared_mutex` to `held_shared_mutexes`. This involves understanding the conditions under which a single mutex is tracked versus a set.

10. **Common Programming Errors:**  Think about typical mutex usage mistakes:
    * **Deadlocks:**  Circular dependencies in lock acquisition.
    * **Race Conditions:** Unprotected access to shared data.
    * **Forgetting to Unlock:** Holding a lock indefinitely, blocking other threads.
    * **Double Locking (without a recursive mutex):** Attempting to acquire a lock already held by the same thread.
    * **Unlocking by a Different Thread:**  Trying to release a lock held by another thread (often caught by debug assertions).

11. **Structuring the Output:** Organize the findings logically:
    * Start with the basic function and file type.
    * Detail the functionalities of each mutex class.
    * Explain the platform-specific implementations.
    * Address the JavaScript connection (or lack thereof directly in this file).
    * Provide examples of code logic reasoning (even if simple).
    * Illustrate common programming errors with examples.

12. **Refinement and Clarity:** Review the generated explanation for accuracy, clarity, and completeness. Use precise terminology (e.g., "exclusive lock," "shared lock"). Ensure the examples are easy to understand.

By following these steps, one can systematically analyze the C++ code and provide a comprehensive explanation covering its purpose, implementation details, and potential pitfalls.
这个C++源代码文件 `v8/src/base/platform/mutex.cc` 实现了跨平台的互斥锁 (mutex) 和共享互斥锁 (shared mutex) 功能。它为 V8 引擎的其余部分提供了一种抽象，使其能够在不同的操作系统上使用不同的底层同步机制，而无需关心具体的平台细节。

**主要功能:**

1. **互斥锁 (Mutex):**
   - 提供独占访问共享资源的能力。当一个线程持有一个互斥锁时，其他线程必须等待该锁被释放才能获取。
   - 提供了 `Lock()` (阻塞地获取锁), `Unlock()` (释放锁), 和 `TryLock()` (非阻塞地尝试获取锁) 等方法。
   - 在Debug模式下，会进行额外的检查以确保不会在同一线程上重复锁定互斥锁。

2. **递归互斥锁 (RecursiveMutex):**
   - 允许同一个线程多次获取同一个锁，而不会发生死锁。
   - 同样提供了 `Lock()`, `Unlock()`, 和 `TryLock()` 方法。
   - 在Debug模式下，会记录锁的层级，以确保 `Lock()` 和 `Unlock()` 的调用次数匹配。

3. **共享互斥锁 (SharedMutex):**
   - 允许多个线程同时拥有共享模式的锁 (用于读取)，但只允许一个线程拥有独占模式的锁 (用于写入)。这在读多写少的场景下可以提高并发性能。
   - 提供了 `LockShared()` (阻塞地获取共享锁), `UnlockShared()` (释放共享锁), `TryLockShared()` (非阻塞地尝试获取共享锁), `LockExclusive()` (阻塞地获取独占锁), `UnlockExclusive()` (释放独占锁), 和 `TryLockExclusive()` (非阻塞地尝试获取独占锁) 等方法。
   - 在Debug模式下，也会进行检查以防止在同一个线程上重复锁定。

4. **平台抽象:**
   - 使用预处理器宏 (`#if V8_OS_POSIX`, `#elif V8_OS_WIN`, `#elif V8_OS_STARBOARD`) 来选择不同操作系统下的具体实现。
   - 在 POSIX 系统上，使用 `pthread_mutex_t` 和 `pthread_rwlock_t`。
   - 在 Windows 系统上，使用 `SRWLOCK` (Slim Reader/Writer Lock) 和 `CRITICAL_SECTION`。
   - 在 Starboard 系统上，使用 `SbMutex` 和内部的读写锁实现。

**关于 .tq 文件:**

`v8/src/base/platform/mutex.cc` 的确是以 `.cc` 结尾，这意味着它是标准的 C++ 源代码文件，而不是 Torque 源代码。如果它是用 Torque 编写的，文件名会以 `.tq` 结尾。Torque 是一种用于 V8 内部实现的领域特定语言。

**与 JavaScript 的关系:**

`v8/src/base/platform/mutex.cc` 中实现的互斥锁和共享互斥锁是 V8 引擎内部用于管理并发和同步的关键机制。虽然 JavaScript 本身是单线程的，但 V8 引擎的内部实现使用了多线程来执行诸如垃圾回收、编译优化、以及处理 Web Workers 等任务。

**JavaScript 例子 (间接关系):**

虽然你不能直接在 JavaScript 中操作这些 C++ 的互斥锁，但你可以通过 JavaScript 的并发特性间接地观察到它们的作用：

```javascript
// 假设我们有一个共享的资源
let counter = 0;

// 模拟并发修改共享资源
function incrementCounter() {
  for (let i = 0; i < 10000; i++) {
    // 这里 V8 内部可能会使用互斥锁来保护 counter 的原子性更新
    counter++;
  }
}

// 创建多个 Web Worker 来并发执行 incrementCounter
const worker1 = new Worker(URL.createObjectURL(new Blob([`(${incrementCounter.toString()})()`])));
const worker2 = new Worker(URL.createObjectURL(new Blob([`(${incrementCounter.toString()})()`])));

Promise.all([
  new Promise(resolve => worker1.onmessage = resolve),
  new Promise(resolve => worker2.onmessage = resolve)
]).then(() => {
  console.log(counter); // 预期结果接近 20000
});
```

在这个例子中，尽管 JavaScript 代码本身没有显式使用互斥锁，但当两个 Web Worker 同时尝试修改 `counter` 变量时，V8 引擎内部可能会使用互斥锁来确保 `counter++` 操作的原子性，避免出现竞争条件，从而得到预期的结果。  如果没有适当的同步机制，`counter` 的最终值可能会小于 20000。

**代码逻辑推理:**

**假设输入:**

1. 线程 A 调用 `Mutex::Lock()`。
2. 线程 B 尝试调用同一个 `Mutex` 对象的 `Lock()`。

**输出:**

1. 线程 A 成功获取锁，继续执行。
2. 线程 B 会被阻塞，直到线程 A 调用 `Mutex::Unlock()` 释放锁。

**假设输入 (SharedMutex):**

1. 线程 A 调用 `SharedMutex::LockShared()`。
2. 线程 B 调用 `SharedMutex::LockShared()`。
3. 线程 C 调用 `SharedMutex::LockExclusive()`。

**输出:**

1. 线程 A 成功获取共享锁，继续读取共享资源。
2. 线程 B 成功获取共享锁，与线程 A 同时读取共享资源。
3. 线程 C 会被阻塞，直到线程 A 和线程 B 都调用 `UnlockShared()` 释放共享锁。

**用户常见的编程错误:**

1. **忘记解锁 (Forgetting to unlock):**

   ```c++
   void critical_section() {
     mutex.Lock();
     // ... 执行一些操作 ...
     // 错误：忘记调用 mutex.Unlock();
   }
   ```

   如果忘记解锁，持有锁的线程崩溃或者因为其他原因没有执行到 `Unlock()`，那么其他尝试获取该锁的线程将会永远阻塞，导致程序死锁。

2. **死锁 (Deadlock):**

   ```c++
   Mutex mutex1;
   Mutex mutex2;

   void thread_a() {
     mutex1.Lock();
     // ... 一些操作 ...
     mutex2.Lock(); // 线程 A 尝试获取 mutex2
     // ...
     mutex2.Unlock();
     mutex1.Unlock();
   }

   void thread_b() {
     mutex2.Lock();
     // ... 一些操作 ...
     mutex1.Lock(); // 线程 B 尝试获取 mutex1
     // ...
     mutex1.Unlock();
     mutex2.Unlock();
   }
   ```

   如果线程 A 持有 `mutex1` 并等待 `mutex2`，而线程 B 持有 `mutex2` 并等待 `mutex1`，则会发生死锁，两个线程都无法继续执行。

3. **在错误的线程解锁 (Unlocking from the wrong thread):**

   在某些平台上的非递归互斥锁中，尝试从一个没有持有锁的线程解锁会导致未定义的行为或错误。Debug 模式下的断言 `AssertHeldAndUnmark()` 旨在捕获这种错误。

4. **重复锁定非递归互斥锁 (Double locking a non-recursive mutex):**

   ```c++
   Mutex mutex;
   void some_function() {
     mutex.Lock();
     // ...
     mutex.Lock(); // 错误：在同一个线程重复锁定
     // ...
     mutex.Unlock();
     mutex.Unlock();
   }
   ```

   对于非递归互斥锁，同一个线程不能在没有先解锁的情况下再次锁定。这通常会导致死锁。递归互斥锁允许这样做。

5. **共享锁和独占锁的误用 (Misuse of shared and exclusive locks):**

   - 在需要修改共享资源时使用共享锁，导致数据竞争。
   - 在只需要读取共享资源时使用独占锁，降低了并发性能。

理解和正确使用互斥锁和共享互斥锁对于编写健壮和高效的多线程程序至关重要。V8 引擎的这个 `mutex.cc` 文件提供了一个基础但关键的构建块，支撑着引擎内部的并发操作。

### 提示词
```
这是目录为v8/src/base/platform/mutex.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/platform/mutex.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/platform/mutex.h"

#include <errno.h>

#include <atomic>

#include "src/base/platform/condition-variable.h"

#if DEBUG
#include <unordered_set>
#endif  // DEBUG

#if V8_OS_WIN
#include <windows.h>
#endif

namespace v8 {
namespace base {

#if DEBUG
namespace {
// Used for asserts to guarantee we are not re-locking a mutex on the same
// thread. If this thread has only one held shared mutex (common case), we use
// {single_held_shared_mutex}. If it has more than one we allocate a set for it.
// Said set has to manually be constructed and destroyed.
thread_local base::SharedMutex* single_held_shared_mutex = nullptr;
using TSet = std::unordered_set<base::SharedMutex*>;
thread_local TSet* held_shared_mutexes = nullptr;

// Returns true iff {shared_mutex} is not a held mutex.
bool SharedMutexNotHeld(SharedMutex* shared_mutex) {
  DCHECK_NOT_NULL(shared_mutex);
  return single_held_shared_mutex != shared_mutex &&
         (!held_shared_mutexes ||
          held_shared_mutexes->count(shared_mutex) == 0);
}

// Tries to hold {shared_mutex}. Returns true iff it hadn't been held prior to
// this function call.
bool TryHoldSharedMutex(SharedMutex* shared_mutex) {
  DCHECK_NOT_NULL(shared_mutex);
  if (single_held_shared_mutex) {
    if (shared_mutex == single_held_shared_mutex) {
      return false;
    }
    DCHECK_NULL(held_shared_mutexes);
    held_shared_mutexes = new TSet({single_held_shared_mutex, shared_mutex});
    single_held_shared_mutex = nullptr;
    return true;
  } else if (held_shared_mutexes) {
    return held_shared_mutexes->insert(shared_mutex).second;
  } else {
    DCHECK_NULL(single_held_shared_mutex);
    single_held_shared_mutex = shared_mutex;
    return true;
  }
}

// Tries to release {shared_mutex}. Returns true iff it had been held prior to
// this function call.
bool TryReleaseSharedMutex(SharedMutex* shared_mutex) {
  DCHECK_NOT_NULL(shared_mutex);
  if (single_held_shared_mutex == shared_mutex) {
    single_held_shared_mutex = nullptr;
    return true;
  }
  if (held_shared_mutexes && held_shared_mutexes->erase(shared_mutex)) {
    if (held_shared_mutexes->empty()) {
      delete held_shared_mutexes;
      held_shared_mutexes = nullptr;
    }
    return true;
  }
  return false;
}
}  // namespace
#endif  // DEBUG

#if V8_OS_POSIX

static V8_INLINE void InitializeNativeHandle(pthread_mutex_t* mutex) {
  int result;
#if defined(DEBUG)
  // Use an error checking mutex in debug mode.
  pthread_mutexattr_t attr;
  result = pthread_mutexattr_init(&attr);
  DCHECK_EQ(0, result);
  result = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
  DCHECK_EQ(0, result);
  result = pthread_mutex_init(mutex, &attr);
  DCHECK_EQ(0, result);
  result = pthread_mutexattr_destroy(&attr);
#else
  // Use a fast mutex (default attributes).
  result = pthread_mutex_init(mutex, nullptr);
#endif  // defined(DEBUG)
  DCHECK_EQ(0, result);
  USE(result);
}


static V8_INLINE void InitializeRecursiveNativeHandle(pthread_mutex_t* mutex) {
  pthread_mutexattr_t attr;
  int result = pthread_mutexattr_init(&attr);
  DCHECK_EQ(0, result);
  result = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  DCHECK_EQ(0, result);
  result = pthread_mutex_init(mutex, &attr);
  DCHECK_EQ(0, result);
  result = pthread_mutexattr_destroy(&attr);
  DCHECK_EQ(0, result);
  USE(result);
}


static V8_INLINE void DestroyNativeHandle(pthread_mutex_t* mutex) {
  int result = pthread_mutex_destroy(mutex);
  DCHECK_EQ(0, result);
  USE(result);
}


static V8_INLINE void LockNativeHandle(pthread_mutex_t* mutex) {
  int result = pthread_mutex_lock(mutex);
  DCHECK_EQ(0, result);
  USE(result);
}


static V8_INLINE void UnlockNativeHandle(pthread_mutex_t* mutex) {
  int result = pthread_mutex_unlock(mutex);
  DCHECK_EQ(0, result);
  USE(result);
}


static V8_INLINE bool TryLockNativeHandle(pthread_mutex_t* mutex) {
  int result = pthread_mutex_trylock(mutex);
  if (result == EBUSY) {
    return false;
  }
  DCHECK_EQ(0, result);
  return true;
}


Mutex::Mutex() {
  InitializeNativeHandle(&native_handle_);
#ifdef DEBUG
  level_ = 0;
#endif
}


Mutex::~Mutex() {
  DestroyNativeHandle(&native_handle_);
  DCHECK_EQ(0, level_);
}


void Mutex::Lock() {
  LockNativeHandle(&native_handle_);
  AssertUnheldAndMark();
}


void Mutex::Unlock() {
  AssertHeldAndUnmark();
  UnlockNativeHandle(&native_handle_);
}


bool Mutex::TryLock() {
  if (!TryLockNativeHandle(&native_handle_)) {
    return false;
  }
  AssertUnheldAndMark();
  return true;
}


RecursiveMutex::RecursiveMutex() {
  InitializeRecursiveNativeHandle(&native_handle_);
#ifdef DEBUG
  level_ = 0;
#endif
}


RecursiveMutex::~RecursiveMutex() {
  DestroyNativeHandle(&native_handle_);
  DCHECK_EQ(0, level_);
}


void RecursiveMutex::Lock() {
  LockNativeHandle(&native_handle_);
#ifdef DEBUG
  DCHECK_LE(0, level_);
  level_++;
#endif
}


void RecursiveMutex::Unlock() {
#ifdef DEBUG
  DCHECK_LT(0, level_);
  level_--;
#endif
  UnlockNativeHandle(&native_handle_);
}


bool RecursiveMutex::TryLock() {
  if (!TryLockNativeHandle(&native_handle_)) {
    return false;
  }
#ifdef DEBUG
  DCHECK_LE(0, level_);
  level_++;
#endif
  return true;
}

#if V8_OS_DARWIN

SharedMutex::SharedMutex() = default;
SharedMutex::~SharedMutex() = default;

void SharedMutex::LockShared() {
  DCHECK(TryHoldSharedMutex(this));
  native_handle_.lock_shared();
}

void SharedMutex::LockExclusive() {
  DCHECK(TryHoldSharedMutex(this));
  native_handle_.lock();
}

void SharedMutex::UnlockShared() {
  DCHECK(TryReleaseSharedMutex(this));
  native_handle_.unlock_shared();
}

void SharedMutex::UnlockExclusive() {
  DCHECK(TryReleaseSharedMutex(this));
  native_handle_.unlock();
}

bool SharedMutex::TryLockShared() {
  DCHECK(SharedMutexNotHeld(this));
  bool result = native_handle_.try_lock_shared();
  if (result) DCHECK(TryHoldSharedMutex(this));
  return result;
}

bool SharedMutex::TryLockExclusive() {
  DCHECK(SharedMutexNotHeld(this));
  bool result = native_handle_.try_lock();
  if (result) DCHECK(TryHoldSharedMutex(this));
  return result;
}

#else  // !V8_OS_DARWIN

SharedMutex::SharedMutex() { pthread_rwlock_init(&native_handle_, nullptr); }

SharedMutex::~SharedMutex() {
  int result = pthread_rwlock_destroy(&native_handle_);
  DCHECK_EQ(0, result);
  USE(result);
}

void SharedMutex::LockShared() {
  DCHECK(TryHoldSharedMutex(this));
  int result = pthread_rwlock_rdlock(&native_handle_);
  DCHECK_EQ(0, result);
  USE(result);
}

void SharedMutex::LockExclusive() {
  DCHECK(TryHoldSharedMutex(this));
  int result = pthread_rwlock_wrlock(&native_handle_);
  DCHECK_EQ(0, result);
  USE(result);
}

void SharedMutex::UnlockShared() {
  DCHECK(TryReleaseSharedMutex(this));
  int result = pthread_rwlock_unlock(&native_handle_);
  DCHECK_EQ(0, result);
  USE(result);
}

void SharedMutex::UnlockExclusive() {
  // Same code as {UnlockShared} on POSIX.
  UnlockShared();
}

bool SharedMutex::TryLockShared() {
  DCHECK(SharedMutexNotHeld(this));
  bool result = pthread_rwlock_tryrdlock(&native_handle_) == 0;
  if (result) DCHECK(TryHoldSharedMutex(this));
  return result;
}

bool SharedMutex::TryLockExclusive() {
  DCHECK(SharedMutexNotHeld(this));
  bool result = pthread_rwlock_trywrlock(&native_handle_) == 0;
  if (result) DCHECK(TryHoldSharedMutex(this));
  return result;
}

#endif  // !V8_OS_DARWIN

#elif V8_OS_WIN

Mutex::Mutex() : native_handle_(SRWLOCK_INIT) {
#ifdef DEBUG
  level_ = 0;
#endif
}


Mutex::~Mutex() {
  DCHECK_EQ(0, level_);
}


void Mutex::Lock() {
  AcquireSRWLockExclusive(V8ToWindowsType(&native_handle_));
  AssertUnheldAndMark();
}


void Mutex::Unlock() {
  AssertHeldAndUnmark();
  ReleaseSRWLockExclusive(V8ToWindowsType(&native_handle_));
}


bool Mutex::TryLock() {
  if (!TryAcquireSRWLockExclusive(V8ToWindowsType(&native_handle_))) {
    return false;
  }
  AssertUnheldAndMark();
  return true;
}


RecursiveMutex::RecursiveMutex() {
  InitializeCriticalSection(V8ToWindowsType(&native_handle_));
#ifdef DEBUG
  level_ = 0;
#endif
}


RecursiveMutex::~RecursiveMutex() {
  DeleteCriticalSection(V8ToWindowsType(&native_handle_));
  DCHECK_EQ(0, level_);
}


void RecursiveMutex::Lock() {
  EnterCriticalSection(V8ToWindowsType(&native_handle_));
#ifdef DEBUG
  DCHECK_LE(0, level_);
  level_++;
#endif
}


void RecursiveMutex::Unlock() {
#ifdef DEBUG
  DCHECK_LT(0, level_);
  level_--;
#endif
  LeaveCriticalSection(V8ToWindowsType(&native_handle_));
}


bool RecursiveMutex::TryLock() {
  if (!TryEnterCriticalSection(V8ToWindowsType(&native_handle_))) {
    return false;
  }
#ifdef DEBUG
  DCHECK_LE(0, level_);
  level_++;
#endif
  return true;
}

SharedMutex::SharedMutex() : native_handle_(SRWLOCK_INIT) {}

SharedMutex::~SharedMutex() {}

void SharedMutex::LockShared() {
  DCHECK(TryHoldSharedMutex(this));
  AcquireSRWLockShared(V8ToWindowsType(&native_handle_));
}

void SharedMutex::LockExclusive() {
  DCHECK(TryHoldSharedMutex(this));
  AcquireSRWLockExclusive(V8ToWindowsType(&native_handle_));
}

void SharedMutex::UnlockShared() {
  DCHECK(TryReleaseSharedMutex(this));
  ReleaseSRWLockShared(V8ToWindowsType(&native_handle_));
}

void SharedMutex::UnlockExclusive() {
  DCHECK(TryReleaseSharedMutex(this));
  ReleaseSRWLockExclusive(V8ToWindowsType(&native_handle_));
}

bool SharedMutex::TryLockShared() {
  DCHECK(SharedMutexNotHeld(this));
  bool result = TryAcquireSRWLockShared(V8ToWindowsType(&native_handle_));
  if (result) DCHECK(TryHoldSharedMutex(this));
  return result;
}

bool SharedMutex::TryLockExclusive() {
  DCHECK(SharedMutexNotHeld(this));
  bool result = TryAcquireSRWLockExclusive(V8ToWindowsType(&native_handle_));
  if (result) DCHECK(TryHoldSharedMutex(this));
  return result;
}

#elif V8_OS_STARBOARD

Mutex::Mutex() { SbMutexCreate(&native_handle_); }

Mutex::~Mutex() { SbMutexDestroy(&native_handle_); }

void Mutex::Lock() { SbMutexAcquire(&native_handle_); }

void Mutex::Unlock() { SbMutexRelease(&native_handle_); }

RecursiveMutex::RecursiveMutex() {}

RecursiveMutex::~RecursiveMutex() {}

void RecursiveMutex::Lock() { native_handle_.Acquire(); }

void RecursiveMutex::Unlock() { native_handle_.Release(); }

bool RecursiveMutex::TryLock() { return native_handle_.AcquireTry(); }

SharedMutex::SharedMutex() = default;

SharedMutex::~SharedMutex() = default;

void SharedMutex::LockShared() {
  DCHECK(TryHoldSharedMutex(this));
  native_handle_.AcquireReadLock();
}

void SharedMutex::LockExclusive() {
  DCHECK(TryHoldSharedMutex(this));
  native_handle_.AcquireWriteLock();
}

void SharedMutex::UnlockShared() {
  DCHECK(TryReleaseSharedMutex(this));
  native_handle_.ReleaseReadLock();
}

void SharedMutex::UnlockExclusive() {
  DCHECK(TryReleaseSharedMutex(this));
  native_handle_.ReleaseWriteLock();
}

bool SharedMutex::TryLockShared() {
  DCHECK(SharedMutexNotHeld(this));
  return false;
}

bool SharedMutex::TryLockExclusive() {
  DCHECK(SharedMutexNotHeld(this));
  return false;
}
#endif  // V8_OS_STARBOARD

}  // namespace base
}  // namespace v8
```