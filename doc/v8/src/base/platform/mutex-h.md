Response:
Let's break down the thought process for analyzing this `mutex.h` file.

**1. Initial Scan and Identification of Key Components:**

The first step is to quickly read through the code, paying attention to keywords, class names, and comments. This helps identify the major building blocks. Immediately, we see:

* `#ifndef V8_BASE_PLATFORM_MUTEX_H_`, `#define V8_BASE_PLATFORM_MUTEX_H_`, `#endif`: This is standard header guard practice.
* Includes: `<optional>`, `v8config.h`, platform-specific headers (`shared_mutex`, `pthread.h`, `win32-headers.h`, `starboard/...`), `base-export.h`, `lazy-instance.h`, `logging.h`. This signals platform abstraction and the use of supporting V8 base libraries.
* Namespaces: `v8::base`. This indicates the context within the V8 project.
* Classes: `Mutex`, `RecursiveMutex`, `SharedMutex`, `LockGuard`, `SharedMutexGuard`, `SharedMutexGuardIf`. These are the core synchronization primitives being defined.
* `LazyMutex`, `LazyRecursiveMutex`:  These suggest a mechanism for delayed initialization of mutexes.
* Macros: `LAZY_MUTEX_INITIALIZER`, `LAZY_RECURSIVE_MUTEX_INITIALIZER`. These are likely related to the lazy initialization.
* Comments: The comments are very helpful, explaining the purpose and usage of each class.

**2. Detailed Analysis of Each Class:**

Next, we examine each class individually, focusing on its purpose, methods, and any specific implementation details:

* **`Mutex`:**  The comments clearly state it's a replacement for `std::mutex`, providing exclusive, non-recursive locking. We look at the methods: `Lock()`, `Unlock()`, `TryLock()`, `native_handle()`, `AssertHeld()`. The `AssertHeld()` and related debug code using `level_` are interesting for debugging purposes. The `NativeHandle` typedef highlights platform-specific implementations.
* **`RecursiveMutex`:** Similar to `Mutex` but allows the same thread to acquire the lock multiple times. The methods are similar (`Lock()`, `Unlock()`, `TryLock()`, `AssertHeld()`), but the semantics are different, as explained in the comments. Again, `NativeHandle` indicates platform dependence.
* **`SharedMutex`:** This is the read-write lock, allowing multiple shared readers or a single exclusive writer. The methods are `LockShared()`, `LockExclusive()`, `UnlockShared()`, `UnlockExclusive()`, `TryLockShared()`, `TryLockExclusive()`. The comments emphasize the undefined behavior if used incorrectly. The platform-specific `NativeHandle` is present. The comment about `pthread_rwlock_t` being broken on MacOS is a valuable implementation detail.
* **`LockGuard`:**  This is a RAII wrapper for `Mutex` and `RecursiveMutex`. The constructor acquires the lock, and the destructor releases it. The template design makes it reusable. The `NullBehavior` enum is interesting, offering flexibility in handling null mutex pointers.
* **`SharedMutexGuard`:**  Similar to `LockGuard` but specialized for `SharedMutex`, handling both shared and exclusive locks based on the template parameter.
* **`SharedMutexGuardIf`:** Provides conditional locking based on a boolean flag.

**3. Identifying Functionality and Purpose:**

After analyzing the individual components, we can summarize the overall functionality of the header file:

* **Platform-Agnostic Mutex Abstraction:**  The header provides a set of mutex classes (`Mutex`, `RecursiveMutex`, `SharedMutex`) that abstract away platform-specific locking mechanisms. This allows V8 code to be more portable.
* **Synchronization Primitives:** The core purpose is to provide tools for managing concurrent access to shared resources, preventing data races.
* **RAII-style Locking:**  `LockGuard` and `SharedMutexGuard` promote safe and convenient mutex usage by automatically releasing locks when they go out of scope.
* **Lazy Initialization:** `LazyMutex` and `LazyRecursiveMutex` optimize initialization by deferring it until the mutex is actually needed.
* **Debugging Aids:** The `AssertHeld()` methods and the `level_` member (in debug builds) help detect incorrect mutex usage.

**4. Checking for Torque and JavaScript Relevance:**

* **`.tq` Extension:** The question specifically asks about the `.tq` extension. A quick scan reveals that the filename is `.h`, not `.tq`. Therefore, it's not a Torque file.
* **JavaScript Relationship:**  Mutexes are fundamental for implementing concurrency in any system, including JavaScript engines. V8 uses mutexes internally to protect its data structures and ensure thread safety. We can illustrate this with a JavaScript example, even though the header itself isn't JavaScript code.

**5. Code Logic and Examples:**

* **Code Logic Inference:**  The core logic revolves around the locking and unlocking mechanisms. We can infer that `Lock()` will block if the mutex is held, `Unlock()` will release it, and `TryLock()` will attempt to acquire the lock without blocking. For `RecursiveMutex`, we understand the concept of nested locks. For `SharedMutex`, we grasp the distinction between shared and exclusive access.
* **JavaScript Examples:**  We create scenarios where shared resources need protection, demonstrating how mutexes could be conceptually used in a JavaScript environment (even though direct mutex usage is less common in typical JS code due to the event loop).

**6. Common Programming Errors:**

We consider the common pitfalls associated with mutex usage:

* **Deadlocks:**  Two or more threads waiting indefinitely for each other to release a lock.
* **Forgetting to Unlock:**  Holding a lock for too long, potentially blocking other threads unnecessarily.
* **Locking the Same Mutex Multiple Times (Non-Recursive):**  Leads to undefined behavior or deadlocks with regular mutexes.
* **Unlocking a Mutex Not Held:**  Causes errors and undefined behavior.
* **Data Races (without Mutexes):**  Multiple threads accessing and modifying shared data concurrently, leading to unpredictable results.

**7. Structuring the Answer:**

Finally, we organize the information into a clear and structured response, addressing each part of the original request:

* List of functionalities.
* Check for `.tq` extension.
* Explain JavaScript relevance with examples.
* Provide code logic inference with assumptions.
* Illustrate common programming errors with examples.

This systematic approach ensures a comprehensive and accurate analysis of the provided C++ header file.
This header file, `v8/src/base/platform/mutex.h`, defines platform-independent mutex and related synchronization primitives for the V8 JavaScript engine. Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Mutex (Exclusive Lock):**
   - Provides a basic mutual exclusion lock. Only one thread can hold the lock at a time.
   - `Lock()`: Acquires the lock, blocking the thread if it's already held.
   - `Unlock()`: Releases the lock.
   - `TryLock()`: Attempts to acquire the lock without blocking. Returns `true` if successful, `false` otherwise.
   - Prevents race conditions when multiple threads access shared resources.

2. **RecursiveMutex:**
   - Allows a single thread to acquire the same mutex multiple times.
   - The lock is released only when the thread calls `Unlock()` the same number of times it called `Lock()`.
   - Useful in situations where a function that holds a lock might call another function that also needs to acquire the same lock.

3. **SharedMutex (Read-Write Lock):**
   - Allows multiple threads to hold a "shared" lock simultaneously (for reading).
   - Only one thread can hold an "exclusive" lock (for writing) at a time. No other thread can hold any lock (shared or exclusive) while an exclusive lock is held.
   - `LockShared()`: Acquires a shared lock, blocking if an exclusive lock is held.
   - `LockExclusive()`: Acquires an exclusive lock, blocking if any lock (shared or exclusive) is held.
   - `UnlockShared()`: Releases a shared lock.
   - `UnlockExclusive()`: Releases an exclusive lock.
   - `TryLockShared()`: Attempts to acquire a shared lock without blocking.
   - `TryLockExclusive()`: Attempts to acquire an exclusive lock without blocking.
   - Improves performance in scenarios with many readers and few writers.

4. **LockGuard (RAII Wrapper):**
   - Provides a convenient RAII (Resource Acquisition Is Initialization) mechanism for automatically managing mutex locks.
   - When a `LockGuard` object is created, it attempts to acquire the associated mutex.
   - When the `LockGuard` object goes out of scope (e.g., at the end of a function or block), its destructor automatically releases the mutex.
   - Prevents common errors like forgetting to unlock a mutex.

5. **LazyMutex and LazyRecursiveMutex:**
   - Provide a way to initialize mutexes (and recursive mutexes) lazily, only when they are first needed.
   - This can improve startup performance if the mutex is not always required.

**Is it a Torque file?**

No, the file extension is `.h`, which indicates a C++ header file. If it were a Torque source file, it would typically have a `.tq` extension.

**Relationship with JavaScript and Examples:**

While this header file is C++ code within the V8 engine, its functionality is crucial for ensuring the thread-safety and correct execution of JavaScript code. JavaScript itself is single-threaded in its core execution model. However, V8 internally uses multiple threads for tasks like:

* **Garbage Collection:**  Separate threads perform garbage collection concurrently with JavaScript execution.
* **Compilation and Optimization:** Background threads compile and optimize JavaScript code.
* **WebAssembly:**  Execution of WebAssembly code might involve multiple threads.
* **Asynchronous Operations:** While JavaScript uses an event loop for concurrency, native bindings and internal V8 operations that handle asynchronous tasks might use threads.

**How Mutexes are conceptually related to JavaScript (though not directly used in typical JS code):**

Imagine a scenario where a JavaScript function interacts with a shared resource managed by V8's internal C++ code (e.g., a cache of compiled code). Without proper synchronization, multiple JavaScript calls happening concurrently (due to asynchronous operations or internal V8 threads) could lead to data corruption.

```javascript
// Conceptual JavaScript example illustrating the *need* for mutex-like behavior
// (This doesn't directly use the C++ mutex, but shows why it's necessary internally)

let sharedData = 0;

function incrementData() {
  // Imagine this is accessing a shared resource protected by a mutex in C++
  const oldValue = sharedData;
  // Simulate a small delay where another thread *could* interfere without a mutex
  for (let i = 0; i < 1000; i++) { /* waste time */ }
  sharedData = oldValue + 1;
}

// Simulate concurrent access (this would be handled by V8's internal threads)
Promise.all([
  new Promise(resolve => setTimeout(() => { incrementData(); resolve(); }, 0)),
  new Promise(resolve => setTimeout(() => { incrementData(); resolve(); }, 0)),
  new Promise(resolve => setTimeout(() => { incrementData(); resolve(); }, 0)),
]).then(() => {
  console.log("Final sharedData:", sharedData); // Expected: 3, but might be less without proper synchronization
});
```

In the above example, without proper synchronization (which the C++ `Mutex` class provides internally), the final value of `sharedData` might not be 3 due to race conditions. V8's internal mutexes ensure that operations like modifying shared data structures happen atomically, preventing such issues.

**Code Logic Inference (with assumptions):**

Let's focus on the `Mutex` class and its `Lock()` and `Unlock()` methods.

**Assumptions:**

1. We have two threads, `Thread A` and `Thread B`.
2. We have an instance of `Mutex` called `myMutex`.

**Scenario 1: No contention**

* **Input:** `Thread A` calls `myMutex.Lock()`.
* **Output:** `Thread A` successfully acquires the lock. The internal state of `myMutex` indicates it's held by `Thread A`.
* **Input:** `Thread A` calls `myMutex.Unlock()`.
* **Output:** The lock is released. The internal state of `myMutex` indicates it's no longer held.

**Scenario 2: Contention**

* **Input:** `Thread A` calls `myMutex.Lock()`.
* **Output:** `Thread A` successfully acquires the lock.
* **Input:** `Thread B` calls `myMutex.Lock()`.
* **Output:** `Thread B` is blocked. It will remain blocked until `Thread A` calls `myMutex.Unlock()`.
* **Input:** `Thread A` calls `myMutex.Unlock()`.
* **Output:** The lock is released. `Thread B` is now unblocked and acquires the lock. The internal state of `myMutex` indicates it's held by `Thread B`.

**Common Programming Errors Involving Mutexes:**

1. **Deadlock:**
   ```c++
   Mutex mutexA, mutexB;

   void threadA() {
     mutexA.Lock();
     // ... do some work ...
     mutexB.Lock(); // Potentially blocks if threadB holds mutexB
     // ... do more work ...
     mutexB.Unlock();
     mutexA.Unlock();
   }

   void threadB() {
     mutexB.Lock();
     // ... do some work ...
     mutexA.Lock(); // Potentially blocks if threadA holds mutexA
     // ... do more work ...
     mutexA.Unlock();
     mutexB.Unlock();
   }
   ```
   **Explanation:** If `threadA` acquires `mutexA` and `threadB` acquires `mutexB` at almost the same time, `threadA` will block trying to acquire `mutexB`, and `threadB` will block trying to acquire `mutexA`, leading to a deadlock.

2. **Forgetting to Unlock:**
   ```c++
   Mutex myMutex;

   void criticalSection() {
     myMutex.Lock();
     // ... do some work ...
     // Oops! Forgot to call myMutex.Unlock();
   }
   ```
   **Explanation:** If `myMutex.Unlock()` is not called, the mutex will remain locked indefinitely, preventing other threads from accessing the protected resource. This can lead to program hangs. This is precisely why `LockGuard` is beneficial, as it ensures unlocking even if exceptions occur.

3. **Locking the Same Mutex Multiple Times (without a RecursiveMutex):**
   ```c++
   Mutex myMutex;

   void myFunction() {
     myMutex.Lock();
     // ... do some work ...
     myMutex.Lock(); // Error! Trying to lock an already held non-recursive mutex
     // ...
     myMutex.Unlock();
     myMutex.Unlock();
   }
   ```
   **Explanation:**  With a regular `Mutex`, if a thread tries to lock it again while already holding it, the behavior is undefined and usually leads to a deadlock. This is where `RecursiveMutex` is useful if nested locking is required.

4. **Unlocking a Mutex Not Held by the Current Thread:**
   ```c++
   Mutex myMutex;

   void threadA() {
     myMutex.Lock();
     // ...
   }

   void threadB() {
     // ...
     myMutex.Unlock(); // Error! Thread B doesn't hold the lock
   }
   ```
   **Explanation:**  Only the thread that currently owns the mutex should unlock it. Trying to unlock a mutex that is not held by the calling thread leads to undefined behavior and potential crashes.

These examples illustrate how crucial the proper use of mutexes is for writing correct and reliable multithreaded code, and why the abstractions provided in `mutex.h` are essential for V8's internal workings.

### 提示词
```
这是目录为v8/src/base/platform/mutex.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/platform/mutex.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BASE_PLATFORM_MUTEX_H_
#define V8_BASE_PLATFORM_MUTEX_H_

#include <optional>

#include "include/v8config.h"

#if V8_OS_DARWIN
#include <shared_mutex>
#endif

#if V8_OS_POSIX
#include <pthread.h>
#endif

#include "src/base/base-export.h"
#include "src/base/lazy-instance.h"
#include "src/base/logging.h"

#if V8_OS_WIN
#include "src/base/win32-headers.h"
#endif

#if V8_OS_STARBOARD
#include "starboard/common/mutex.h"
#include "starboard/common/recursive_mutex.h"
#include "starboard/common/rwlock.h"
#endif

namespace v8 {
namespace base {

class ConditionVariable;

// ----------------------------------------------------------------------------
// Mutex - a replacement for std::mutex
//
// This class is a synchronization primitive that can be used to protect shared
// data from being simultaneously accessed by multiple threads. A mutex offers
// exclusive, non-recursive ownership semantics:
// - A calling thread owns a mutex from the time that it successfully calls
//   either |Lock()| or |TryLock()| until it calls |Unlock()|.
// - When a thread owns a mutex, all other threads will block (for calls to
//   |Lock()|) or receive a |false| return value (for |TryLock()|) if they
//   attempt to claim ownership of the mutex.
// A calling thread must not own the mutex prior to calling |Lock()| or
// |TryLock()|. The behavior of a program is undefined if a mutex is destroyed
// while still owned by some thread. The Mutex class is non-copyable.

class V8_BASE_EXPORT Mutex final {
 public:
  Mutex();
  Mutex(const Mutex&) = delete;
  Mutex& operator=(const Mutex&) = delete;
  ~Mutex();

  // Locks the given mutex. If the mutex is currently unlocked, it becomes
  // locked and owned by the calling thread, and immediately. If the mutex
  // is already locked by another thread, suspends the calling thread until
  // the mutex is unlocked.
  void Lock();

  // Unlocks the given mutex. The mutex is assumed to be locked and owned by
  // the calling thread on entrance.
  void Unlock();

  // Tries to lock the given mutex. Returns whether the mutex was
  // successfully locked.
  // Note: Instead of `DCHECK(!mutex.TryLock())` use `mutex.AssertHeld()`.
  bool TryLock() V8_WARN_UNUSED_RESULT;

  // The implementation-defined native handle type.
#if V8_OS_POSIX
  using NativeHandle = pthread_mutex_t;
#elif V8_OS_WIN
  using NativeHandle = V8_SRWLOCK;
#elif V8_OS_STARBOARD
  using NativeHandle = SbMutex;
#endif

  NativeHandle& native_handle() {
    return native_handle_;
  }
  const NativeHandle& native_handle() const {
    return native_handle_;
  }

  V8_INLINE void AssertHeld() const {
    // If this access results in a race condition being detected by TSan, this
    // means that you in fact did *not* hold the mutex.
    DCHECK_EQ(1, level_);
  }

 private:
  NativeHandle native_handle_;
#ifdef DEBUG
  // This is being used for Assert* methods. Accesses are only allowed if you
  // actually hold the mutex, otherwise you would get race conditions.
  int level_;
#endif

  V8_INLINE void AssertHeldAndUnmark() {
#ifdef DEBUG
    // If this access results in a race condition being detected by TSan, this
    // means that you in fact did *not* hold the mutex.
    DCHECK_EQ(1, level_);
    level_--;
#endif
  }

  V8_INLINE void AssertUnheldAndMark() {
#ifdef DEBUG
    // This is only invoked *after* actually getting the mutex, so should not
    // result in race conditions.
    DCHECK_EQ(0, level_);
    level_++;
#endif
  }

  friend class ConditionVariable;
};

// POD Mutex initialized lazily (i.e. the first time Pointer() is called).
// Usage:
//   static LazyMutex my_mutex = LAZY_MUTEX_INITIALIZER;
//
//   void my_function() {
//     MutexGuard guard(my_mutex.Pointer());
//     // Do something.
//   }
//
using LazyMutex = LazyStaticInstance<Mutex, DefaultConstructTrait<Mutex>,
                                     ThreadSafeInitOnceTrait>::type;

#define LAZY_MUTEX_INITIALIZER LAZY_STATIC_INSTANCE_INITIALIZER

// -----------------------------------------------------------------------------
// RecursiveMutex - a replacement for std::recursive_mutex
//
// This class is a synchronization primitive that can be used to protect shared
// data from being simultaneously accessed by multiple threads. A recursive
// mutex offers exclusive, recursive ownership semantics:
// - A calling thread owns a recursive mutex for a period of time that starts
//   when it successfully calls either |Lock()| or |TryLock()|. During this
//   period, the thread may make additional calls to |Lock()| or |TryLock()|.
//   The period of ownership ends when the thread makes a matching number of
//   calls to |Unlock()|.
// - When a thread owns a recursive mutex, all other threads will block (for
//   calls to |Lock()|) or receive a |false| return value (for |TryLock()|) if
//   they attempt to claim ownership of the recursive mutex.
// - The maximum number of times that a recursive mutex may be locked is
//   unspecified, but after that number is reached, calls to |Lock()| will
//   probably abort the process and calls to |TryLock()| return false.
// The behavior of a program is undefined if a recursive mutex is destroyed
// while still owned by some thread. The RecursiveMutex class is non-copyable.

class V8_BASE_EXPORT RecursiveMutex final {
 public:
  RecursiveMutex();
  RecursiveMutex(const RecursiveMutex&) = delete;
  RecursiveMutex& operator=(const RecursiveMutex&) = delete;
  ~RecursiveMutex();

  // Locks the mutex. If another thread has already locked the mutex, a call to
  // |Lock()| will block execution until the lock is acquired. A thread may call
  // |Lock()| on a recursive mutex repeatedly. Ownership will only be released
  // after the thread makes a matching number of calls to |Unlock()|.
  // The behavior is undefined if the mutex is not unlocked before being
  // destroyed, i.e. some thread still owns it.
  void Lock();

  // Unlocks the mutex if its level of ownership is 1 (there was exactly one
  // more call to |Lock()| than there were calls to unlock() made by this
  // thread), reduces the level of ownership by 1 otherwise. The mutex must be
  // locked by the current thread of execution, otherwise, the behavior is
  // undefined.
  void Unlock();

  // Tries to lock the given mutex. Returns whether the mutex was
  // successfully locked.
  // Note: Instead of `DCHECK(!mutex.TryLock())` use `mutex.AssertHeld()`.
  bool TryLock() V8_WARN_UNUSED_RESULT;

  V8_INLINE void AssertHeld() const {
    // If this access results in a race condition being detected by TSan, this
    // mean that you in fact did *not* hold the mutex.
    DCHECK_LT(0, level_);
  }

 private:
  // The implementation-defined native handle type.
#if V8_OS_POSIX
  using NativeHandle = pthread_mutex_t;
#elif V8_OS_WIN
  using NativeHandle = V8_CRITICAL_SECTION;
#elif V8_OS_STARBOARD
  using NativeHandle = starboard::RecursiveMutex;
#endif

  NativeHandle native_handle_;
#ifdef DEBUG
  // This is being used for Assert* methods. Accesses are only allowed if you
  // actually hold the mutex, otherwise you would get race conditions.
  int level_;
#endif
};


// POD RecursiveMutex initialized lazily (i.e. the first time Pointer() is
// called).
// Usage:
//   static LazyRecursiveMutex my_mutex = LAZY_RECURSIVE_MUTEX_INITIALIZER;
//
//   void my_function() {
//     LockGuard<RecursiveMutex> guard(my_mutex.Pointer());
//     // Do something.
//   }
//
using LazyRecursiveMutex =
    LazyStaticInstance<RecursiveMutex, DefaultConstructTrait<RecursiveMutex>,
                       ThreadSafeInitOnceTrait>::type;

#define LAZY_RECURSIVE_MUTEX_INITIALIZER LAZY_STATIC_INSTANCE_INITIALIZER

// ----------------------------------------------------------------------------
// SharedMutex - a replacement for std::shared_mutex
//
// This class is a synchronization primitive that can be used to protect shared
// data from being simultaneously accessed by multiple threads. In contrast to
// other mutex types which facilitate exclusive access, a shared_mutex has two
// levels of access:
// - shared: several threads can share ownership of the same mutex.
// - exclusive: only one thread can own the mutex.
// Shared mutexes are usually used in situations when multiple readers can
// access the same resource at the same time without causing data races, but
// only one writer can do so.
// The SharedMutex class is non-copyable.

class V8_BASE_EXPORT SharedMutex final {
 public:
  SharedMutex();
  SharedMutex(const SharedMutex&) = delete;
  SharedMutex& operator=(const SharedMutex&) = delete;
  ~SharedMutex();

  // Acquires shared ownership of the {SharedMutex}. If another thread is
  // holding the mutex in exclusive ownership, a call to {LockShared()} will
  // block execution until shared ownership can be acquired.
  // If {LockShared()} is called by a thread that already owns the mutex in any
  // mode (exclusive or shared), the behavior is undefined and outright fails
  // with dchecks on.
  void LockShared();

  // Locks the SharedMutex. If another thread has already locked the mutex, a
  // call to {LockExclusive()} will block execution until the lock is acquired.
  // If {LockExclusive()} is called by a thread that already owns the mutex in
  // any mode (shared or exclusive), the behavior is undefined and outright
  // fails with dchecks on.
  void LockExclusive();

  // Releases the {SharedMutex} from shared ownership by the calling thread.
  // The mutex must be locked by the current thread of execution in shared mode,
  // otherwise, the behavior is undefined and outright fails with dchecks on.
  void UnlockShared();

  // Unlocks the {SharedMutex}. It must be locked by the current thread of
  // execution, otherwise, the behavior is undefined and outright fails with
  // dchecks on.
  void UnlockExclusive();

  // Tries to lock the {SharedMutex} in shared mode. Returns immediately. On
  // successful lock acquisition returns true, otherwise returns false.
  // This function is allowed to fail spuriously and return false even if the
  // mutex is not currenly exclusively locked by any other thread.
  // If it is called by a thread that already owns the mutex in any mode
  // (shared or exclusive), the behavior is undefined, and outright fails with
  // dchecks on.
  bool TryLockShared() V8_WARN_UNUSED_RESULT;

  // Tries to lock the {SharedMutex}. Returns immediately. On successful lock
  // acquisition returns true, otherwise returns false.
  // This function is allowed to fail spuriously and return false even if the
  // mutex is not currently locked by any other thread.
  // If it is called by a thread that already owns the mutex in any mode
  // (shared or exclusive), the behavior is undefined, and outright fails with
  // dchecks on.
  bool TryLockExclusive() V8_WARN_UNUSED_RESULT;

 private:
  // The implementation-defined native handle type.
#if V8_OS_DARWIN
  // pthread_rwlock_t is broken on MacOS when signals are being sent to the
  // process (see https://crbug.com/v8/11399).
  // We thus use std::shared_mutex on MacOS, which does not have this problem.
  using NativeHandle = std::shared_mutex;
#elif V8_OS_POSIX
  using NativeHandle = pthread_rwlock_t;
#elif V8_OS_WIN
  using NativeHandle = V8_SRWLOCK;
#elif V8_OS_STARBOARD
  using NativeHandle = starboard::RWLock;
#endif

  NativeHandle native_handle_;
};

// -----------------------------------------------------------------------------
// LockGuard
//
// This class is a mutex wrapper that provides a convenient RAII-style mechanism
// for owning a mutex for the duration of a scoped block.
// When a LockGuard object is created, it attempts to take ownership of the
// mutex it is given. When control leaves the scope in which the LockGuard
// object was created, the LockGuard is destructed and the mutex is released.
// The LockGuard class is non-copyable.

// Controls whether a LockGuard always requires a valid Mutex or will just
// ignore it if it's nullptr.
enum class NullBehavior { kRequireNotNull, kIgnoreIfNull };

template <typename Mutex, NullBehavior Behavior = NullBehavior::kRequireNotNull>
class V8_NODISCARD LockGuard final {
 public:
  explicit LockGuard(Mutex* mutex) : mutex_(mutex) {
    DCHECK_IMPLIES(Behavior == NullBehavior::kRequireNotNull,
                   mutex_ != nullptr);
    if (has_mutex()) mutex_->Lock();
  }
  LockGuard(const LockGuard&) = delete;
  LockGuard& operator=(const LockGuard&) = delete;
  LockGuard(LockGuard&& other) V8_NOEXCEPT : mutex_(other.mutex_) {
    DCHECK_IMPLIES(Behavior == NullBehavior::kRequireNotNull,
                   mutex_ != nullptr);
    other.mutex_ = nullptr;
  }
  ~LockGuard() {
    if (has_mutex()) mutex_->Unlock();
  }

 private:
  Mutex* mutex_;

  bool V8_INLINE has_mutex() const { return mutex_ != nullptr; }
};

using MutexGuard = LockGuard<Mutex>;
using RecursiveMutexGuard = LockGuard<RecursiveMutex>;

enum MutexSharedType : bool { kShared = true, kExclusive = false };

template <MutexSharedType kIsShared,
          NullBehavior Behavior = NullBehavior::kRequireNotNull>
class V8_NODISCARD SharedMutexGuard final {
 public:
  explicit SharedMutexGuard(SharedMutex* mutex) : mutex_(mutex) {
    if (!has_mutex()) return;
    if (kIsShared) {
      mutex_->LockShared();
    } else {
      mutex_->LockExclusive();
    }
  }
  SharedMutexGuard(const SharedMutexGuard&) = delete;
  SharedMutexGuard& operator=(const SharedMutexGuard&) = delete;
  ~SharedMutexGuard() {
    if (!has_mutex()) return;
    if (kIsShared) {
      mutex_->UnlockShared();
    } else {
      mutex_->UnlockExclusive();
    }
  }

 private:
  SharedMutex* const mutex_;

  bool V8_INLINE has_mutex() const {
    DCHECK_IMPLIES(Behavior == NullBehavior::kRequireNotNull,
                   mutex_ != nullptr);
    return Behavior == NullBehavior::kRequireNotNull || mutex_ != nullptr;
  }
};

template <MutexSharedType kIsShared,
          NullBehavior Behavior = NullBehavior::kRequireNotNull>
class V8_NODISCARD SharedMutexGuardIf final {
 public:
  SharedMutexGuardIf(SharedMutex* mutex, bool enable_mutex) {
    if (enable_mutex) mutex_.emplace(mutex);
  }
  SharedMutexGuardIf(const SharedMutexGuardIf&) = delete;
  SharedMutexGuardIf& operator=(const SharedMutexGuardIf&) = delete;

 private:
  std::optional<SharedMutexGuard<kIsShared, Behavior>> mutex_;
};

}  // namespace base
}  // namespace v8

#endif  // V8_BASE_PLATFORM_MUTEX_H_
```