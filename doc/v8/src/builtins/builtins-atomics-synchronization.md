Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of the C++ file and how it relates to JavaScript. This means identifying the core purpose of the code and then finding corresponding JavaScript features.

2. **Initial Scan for Keywords:**  Quickly scan the code for obvious keywords. "AtomicsMutex", "AtomicsCondition", "lock", "tryLock", "wait", "notify", "async", "Promise", "timeout". These immediately suggest this code deals with synchronization primitives similar to those found in threading or concurrent programming. The "Atomics" prefix further points to the JavaScript `Atomics` object.

3. **Identify Core Data Structures:**  Notice `JSAtomicsMutex` and `JSAtomicsCondition`. These are clearly the fundamental building blocks the code operates on. The comments and function names confirm they represent mutexes (mutual exclusion locks) and condition variables.

4. **Analyze Individual Builtin Functions:**  Focus on the `BUILTIN` macros. These are the entry points from the JavaScript side. For each `BUILTIN`:
    * **Name:** The name (e.g., `AtomicsMutexConstructor`, `AtomicsMutexLock`) directly hints at its JavaScript counterpart (`Atomics.Mutex()`, `Atomics.Mutex.lock()`).
    * **Arguments:**  Examine the arguments passed (`args.atOrUndefined`). This tells you what parameters the JavaScript function expects. For example, `AtomicsMutexLock` takes the mutex object and a callable.
    * **Core Logic:** Understand the main action performed. `AtomicsMutexLock` acquires a lock and executes a callback. `AtomicsMutexTryLock` attempts to acquire a lock. `AtomicsMutexLockWithTimeout` adds a timeout. `AtomicsMutexLockAsync` returns a Promise.
    * **Error Handling:**  Note the `THROW_NEW_ERROR_RETURN_FAILURE` calls. These indicate the types of errors JavaScript can encounter (e.g., `TypeError` for incorrect argument types, `AtomicsOperationNotAllowed`).
    * **Return Values:**  See what's being returned. Some functions return simple values (like boolean or number), others return Promises.

5. **Trace Relationships:** Pay attention to how the mutex and condition variables interact. `AtomicsConditionWait` requires a mutex to be held. `AtomicsConditionNotify` wakes up waiting threads. The `Async` versions of these methods clearly involve Promises for managing asynchronous behavior.

6. **Connect to JavaScript `Atomics`:**  The naming convention (`Atomics.Mutex`, `Atomics.Condition`) strongly suggests a direct mapping to the JavaScript `Atomics` object and its sub-properties (which are actually constructor functions in this case).

7. **Formulate the Summary:** Based on the analysis, describe the file's purpose in clear, concise language. Emphasize the implementation of mutexes and condition variables for synchronization, and their role in managing concurrent access to shared resources.

8. **Create JavaScript Examples:** For each key functionality, craft JavaScript examples that demonstrate the corresponding `Atomics` API usage. Ensure the examples are simple and illustrate the core concepts. Highlight:
    * Creating mutexes and conditions.
    * Synchronous locking and execution of code.
    * Try-locking.
    * Locking with timeouts.
    * Asynchronous locking and Promises.
    * Waiting on a condition.
    * Notifying waiting threads.
    * The `runUnderLock` callback.

9. **Refine and Clarify:** Review the summary and examples for clarity and accuracy. Ensure the connection between the C++ code and the JavaScript API is explicitly stated. For instance, mention that the C++ code *implements* the features exposed by the JavaScript `Atomics` API.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks like thread synchronization stuff."  **Correction:** While related to thread synchronization *concepts*, it's specifically implementing the *JavaScript* `Atomics` API, which might use underlying threads but is accessed via JavaScript.
* **Focusing too much on low-level details:**  Realize the request is about *functionality* and its *JavaScript relation*, not a deep dive into the C++ implementation details (like the `LockGuard` class). Keep the explanation at a higher level.
* **Not making the JavaScript connection clear enough:** Initially, the explanation might just describe the C++ functionality. **Correction:**  Explicitly link each C++ `BUILTIN` to its JavaScript counterpart and provide clear examples.
* **Overcomplicating the JavaScript examples:** Start with simple examples and gradually introduce more complex scenarios if needed. Focus on illustrating one concept per example.

By following this structured approach, breaking down the code into manageable parts, and actively seeking the connection to JavaScript, it becomes possible to provide a comprehensive and accurate answer to the request.
这个C++源代码文件 `builtins-atomics-synchronization.cc` 是 V8 JavaScript 引擎的一部分，它的主要功能是**实现了 JavaScript 中 `Atomics` API 中关于互斥锁（Mutex）和条件变量（Condition）的同步机制**。

更具体地说，这个文件定义了以下与 `Atomics.Mutex` 和 `Atomics.Condition` 相关的内置函数（builtins）：

**关于 `Atomics.Mutex`:**

* **`AtomicsMutexConstructor`**:  实现了 `new Atomics.Mutex()` 构造函数，用于创建一个新的互斥锁对象。
* **`AtomicsMutexLock`**: 实现了 `Atomics.Mutex.lock(runUnderLock)` 方法，用于同步地获取互斥锁并执行提供的回调函数 `runUnderLock`。  如果锁已经被其他线程持有，当前线程会阻塞直到获取到锁。
* **`AtomicsMutexTryLock`**: 实现了 `Atomics.Mutex.tryLock(runUnderLock)` 方法，尝试获取互斥锁并执行回调。如果锁当前不可用，则不会阻塞，而是立即返回一个指示是否成功获取锁的对象。
* **`AtomicsMutexLockWithTimeout`**: 实现了 `Atomics.Mutex.lock(runUnderLock, timeout)` 方法，尝试在指定的时间内获取互斥锁。如果超时仍未获取到锁，则返回失败状态。
* **`AtomicsMutexLockAsync`**: 实现了 `Atomics.Mutex.lockAsync(runUnderLock, timeout)` 方法，异步地获取互斥锁。它返回一个 Promise，该 Promise 在获取到锁并执行完 `runUnderLock` 后 resolve，或者在超时后 reject。
* **`AtomicsMutexAsyncUnlockResolveHandler` 和 `AtomicsMutexAsyncUnlockRejectHandler`**:  这两个函数是 `AtomicsMutexLockAsync` 返回的 Promise 的 resolve 和 reject 处理程序，用于在异步锁释放后处理 Promise 的状态。

**关于 `Atomics.Condition`:**

* **`AtomicsConditionConstructor`**: 实现了 `new Atomics.Condition()` 构造函数，用于创建一个新的条件变量对象。
* **`AtomicsConditionWait`**: 实现了 `Atomics.Condition.wait(mutex, timeout)` 方法，用于使当前线程等待与此条件变量关联的某个条件成立。在等待期间，会释放指定的互斥锁 `mutex`，并在被唤醒时重新获取该锁。这是一个同步操作，会阻塞线程。
* **`AtomicsConditionNotify`**: 实现了 `Atomics.Condition.notify(count)` 方法，用于唤醒等待此条件变量的一个或多个线程。`count` 参数指定要唤醒的线程数量。
* **`AtomicsConditionWaitAsync`**: 实现了 `Atomics.Condition.waitAsync(mutex, timeout)` 方法，异步地等待条件变量。它返回一个 Promise，该 Promise 在条件被通知后 resolve，或者在超时后 reject。
* **`AtomicsConditionAcquireLock`**:  这是一个内部辅助函数，用于在异步等待条件变量时重新获取互斥锁。

**与 JavaScript 的关系和示例：**

这个 C++ 文件中的代码直接实现了 JavaScript 中 `Atomics` 对象下的 `Mutex` 和 `Condition` 构造函数和其原型方法。 这些方法允许 JavaScript 代码在共享内存的场景下进行线程同步，防止数据竞争。

**JavaScript 示例：**

```javascript
// 创建一个共享的 Int32Array 缓冲区
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const sharedArray = new Int32Array(sab);

// 创建一个互斥锁和一个条件变量
const mutex = new Atomics.Mutex();
const condition = new Atomics.Condition();

// 模拟两个不同的 "线程" (可以使用 Web Workers 或 Node.js 的 worker_threads 模块)

// "线程 1"
function thread1() {
  console.log("线程 1 尝试获取锁...");
  Atomics.Mutex.lock(mutex, () => {
    console.log("线程 1 获取到锁");
    sharedArray[0] = 1;
    console.log("线程 1 修改了共享数据:", sharedArray[0]);
    console.log("线程 1 通知其他等待的线程...");
    Atomics.Condition.notify(condition);
    console.log("线程 1 释放锁");
  });
}

// "线程 2"
function thread2() {
  console.log("线程 2 尝试获取锁...");
  Atomics.Mutex.lock(mutex, () => {
    console.log("线程 2 获取到锁");
    console.log("线程 2 读取共享数据:", sharedArray[0]);
    if (sharedArray[0] === 0) {
      console.log("线程 2 等待数据被修改...");
      Atomics.Condition.wait(condition, mutex); // 注意：wait 方法需要持有 mutex
      console.log("线程 2 被唤醒，重新获取锁");
      console.log("线程 2 读取共享数据:", sharedArray[0]);
    }
    console.log("线程 2 释放锁");
  });
}

// 启动 "线程" (这里只是简单的函数调用，实际使用中会涉及真正的多线程)
thread1();
thread2();
```

**异步示例：**

```javascript
async function asyncExample() {
  const mutex = new Atomics.Mutex();

  async function task() {
    console.log("任务尝试获取锁...");
    const result = await Atomics.Mutex.lockAsync(mutex, async () => {
      console.log("任务获取到锁");
      await new Promise(resolve => setTimeout(resolve, 1000)); // 模拟耗时操作
      console.log("任务完成操作，准备释放锁");
      return "任务完成";
    });
    console.log("锁已释放，异步锁结果:", result);
  }

  task();
}

asyncExample();
```

**总结：**

`builtins-atomics-synchronization.cc` 文件是 V8 引擎中实现 JavaScript `Atomics.Mutex` 和 `Atomics.Condition` 功能的关键部分。它提供了底层的 C++ 实现，使得 JavaScript 开发者可以使用这些同步原语来编写更健壮的并发代码，尤其是在使用共享内存的场景下。这些内置函数确保了在多线程环境中对共享资源的访问是安全和可控的。

### 提示词
```
这是目录为v8/src/builtins/builtins-atomics-synchronization.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-inl.h"
#include "src/objects/js-atomics-synchronization-inl.h"
#include "src/objects/promise-inl.h"

namespace v8 {
namespace internal {
namespace {

std::optional<base::TimeDelta> GetTimeoutDelta(
    DirectHandle<Object> timeout_obj) {
  double ms = Object::NumberValue(*timeout_obj);
  if (!std::isnan(ms)) {
    if (ms < 0) ms = 0;
    if (ms <= static_cast<double>(std::numeric_limits<int64_t>::max())) {
      return base::TimeDelta::FromMilliseconds(static_cast<int64_t>(ms));
    }
  }
  return std::nullopt;
}

Handle<JSPromise> UnlockAsyncLockedMutexFromPromiseHandler(Isolate* isolate) {
  DirectHandle<Context> context(isolate->context(), isolate);
  DirectHandle<Object> mutex(
      context->get(JSAtomicsMutex::kMutexAsyncContextSlot), isolate);
  Handle<Object> unlock_promise(
      context->get(JSAtomicsMutex::kUnlockedPromiseAsyncContextSlot), isolate);
  DirectHandle<Object> waiter_wrapper_obj(
      context->get(JSAtomicsMutex::kAsyncLockedWaiterAsyncContextSlot),
      isolate);

  auto js_mutex = Cast<JSAtomicsMutex>(mutex);
  auto js_unlock_promise = Cast<JSPromise>(unlock_promise);
  auto async_locked_waiter_wrapper = Cast<Foreign>(waiter_wrapper_obj);
  js_mutex->UnlockAsyncLockedMutex(isolate, async_locked_waiter_wrapper);
  return js_unlock_promise;
}

}  // namespace

BUILTIN(AtomicsMutexConstructor) {
  DCHECK(v8_flags.harmony_struct);
  HandleScope scope(isolate);
  return *isolate->factory()->NewJSAtomicsMutex();
}

BUILTIN(AtomicsMutexLock) {
  DCHECK(v8_flags.harmony_struct);
  constexpr char method_name[] = "Atomics.Mutex.lock";
  HandleScope scope(isolate);

  Handle<Object> js_mutex_obj = args.atOrUndefined(isolate, 1);
  if (!IsJSAtomicsMutex(*js_mutex_obj)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }
  Handle<JSAtomicsMutex> js_mutex = Cast<JSAtomicsMutex>(js_mutex_obj);
  Handle<Object> run_under_lock = args.atOrUndefined(isolate, 2);
  if (!IsCallable(*run_under_lock)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNotCallable, run_under_lock));
  }

  // Like Atomics.wait, synchronous locking may block, and so is disallowed on
  // the main thread.
  //
  // This is not a recursive lock, so also throw if recursively locking.
  if (!isolate->allow_atomics_wait() || js_mutex->IsCurrentThreadOwner()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kAtomicsOperationNotAllowed,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  Handle<Object> result;
  {
    JSAtomicsMutex::LockGuard lock_guard(isolate, js_mutex);
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result,
        Execution::Call(isolate, run_under_lock,
                        isolate->factory()->undefined_value(), 0, nullptr));
  }

  return *result;
}

BUILTIN(AtomicsMutexTryLock) {
  DCHECK(v8_flags.harmony_struct);
  constexpr char method_name[] = "Atomics.Mutex.tryLock";
  HandleScope scope(isolate);

  Handle<Object> js_mutex_obj = args.atOrUndefined(isolate, 1);
  if (!IsJSAtomicsMutex(*js_mutex_obj)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }
  Handle<JSAtomicsMutex> js_mutex = Cast<JSAtomicsMutex>(js_mutex_obj);
  Handle<Object> run_under_lock = args.atOrUndefined(isolate, 2);
  if (!IsCallable(*run_under_lock)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNotCallable, run_under_lock));
  }

  Handle<Object> callback_result;
  bool success;
  {
    JSAtomicsMutex::TryLockGuard try_lock_guard(isolate, js_mutex);
    if (try_lock_guard.locked()) {
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, callback_result,
          Execution::Call(isolate, run_under_lock,
                          isolate->factory()->undefined_value(), 0, nullptr));
      success = true;
    } else {
      callback_result = isolate->factory()->undefined_value();
      success = false;
    }
  }
  DirectHandle<JSObject> result =
      JSAtomicsMutex::CreateResultObject(isolate, callback_result, success);
  return *result;
}

BUILTIN(AtomicsMutexLockWithTimeout) {
  DCHECK(v8_flags.harmony_struct);
  constexpr char method_name[] = "Atomics.Mutex.lockWithTimeout";
  HandleScope scope(isolate);

  Handle<Object> js_mutex_obj = args.atOrUndefined(isolate, 1);
  if (!IsJSAtomicsMutex(*js_mutex_obj)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }
  Handle<JSAtomicsMutex> js_mutex = Cast<JSAtomicsMutex>(js_mutex_obj);
  Handle<Object> run_under_lock = args.atOrUndefined(isolate, 2);
  if (!IsCallable(*run_under_lock)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNotCallable, run_under_lock));
  }

  Handle<Object> timeout_obj = args.atOrUndefined(isolate, 3);
  std::optional<base::TimeDelta> timeout;
  if (!IsNumber(*timeout_obj)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kIsNotNumber, timeout_obj,
                              Object::TypeOf(isolate, timeout_obj)));
  }
  timeout = GetTimeoutDelta(timeout_obj);

  // Like Atomics.wait, synchronous locking may block, and so is disallowed on
  // the main thread.
  //
  // This is not a recursive lock, so also throw if recursively locking.
  if (!isolate->allow_atomics_wait() || js_mutex->IsCurrentThreadOwner()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kAtomicsOperationNotAllowed,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  Handle<Object> callback_result;
  bool success;
  {
    JSAtomicsMutex::LockGuard lock_guard(isolate, js_mutex, timeout);
    if (V8_LIKELY(lock_guard.locked())) {
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, callback_result,
          Execution::Call(isolate, run_under_lock,
                          isolate->factory()->undefined_value(), 0, nullptr));
      success = true;
    } else {
      callback_result = isolate->factory()->undefined_value();
      success = false;
    }
  }
  DirectHandle<JSObject> result =
      JSAtomicsMutex::CreateResultObject(isolate, callback_result, success);
  return *result;
}

BUILTIN(AtomicsMutexLockAsync) {
  DCHECK(v8_flags.harmony_struct);
  constexpr char method_name[] = "Atomics.Mutex.lockAsync";
  HandleScope scope(isolate);

  Handle<Object> js_mutex_obj = args.atOrUndefined(isolate, 1);
  if (!IsJSAtomicsMutex(*js_mutex_obj)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }
  Handle<JSAtomicsMutex> js_mutex = Cast<JSAtomicsMutex>(js_mutex_obj);
  Handle<Object> run_under_lock = args.atOrUndefined(isolate, 2);
  if (!IsCallable(*run_under_lock)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNotCallable, run_under_lock));
  }

  Handle<Object> timeout_obj = args.atOrUndefined(isolate, 3);
  std::optional<base::TimeDelta> timeout = std::nullopt;
  if (!IsUndefined(*timeout_obj, isolate)) {
    if (!IsNumber(*timeout_obj)) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewTypeError(MessageTemplate::kIsNotNumber, timeout_obj,
                                Object::TypeOf(isolate, timeout_obj)));
    }
    timeout = GetTimeoutDelta(timeout_obj);
  }

  Handle<JSPromise> result_promise;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result_promise,
      JSAtomicsMutex::LockOrEnqueuePromise(isolate, js_mutex, run_under_lock,
                                           timeout));

  return *result_promise;
}

BUILTIN(AtomicsMutexAsyncUnlockResolveHandler) {
  DCHECK(v8_flags.harmony_struct);
  HandleScope scope(isolate);

  DirectHandle<Object> previous_result = args.atOrUndefined(isolate, 1);
  Handle<JSPromise> js_unlock_promise =
      UnlockAsyncLockedMutexFromPromiseHandler(isolate);

  Handle<JSObject> result =
      JSAtomicsMutex::CreateResultObject(isolate, previous_result, true);
  auto resolve_result = JSPromise::Resolve(js_unlock_promise, result);
  USE(resolve_result);
  return *isolate->factory()->undefined_value();
}

BUILTIN(AtomicsMutexAsyncUnlockRejectHandler) {
  DCHECK(v8_flags.harmony_struct);
  HandleScope scope(isolate);

  Handle<Object> error = args.atOrUndefined(isolate, 1);
  Handle<JSPromise> js_unlock_promise =
      UnlockAsyncLockedMutexFromPromiseHandler(isolate);

  auto reject_result = JSPromise::Reject(js_unlock_promise, error);
  USE(reject_result);
  return *isolate->factory()->undefined_value();
}

BUILTIN(AtomicsConditionConstructor) {
  DCHECK(v8_flags.harmony_struct);
  HandleScope scope(isolate);
  return *isolate->factory()->NewJSAtomicsCondition();
}

BUILTIN(AtomicsConditionWait) {
  DCHECK(v8_flags.harmony_struct);
  constexpr char method_name[] = "Atomics.Condition.wait";
  HandleScope scope(isolate);

  Handle<Object> js_condition_obj = args.atOrUndefined(isolate, 1);
  Handle<Object> js_mutex_obj = args.atOrUndefined(isolate, 2);
  Handle<Object> timeout_obj = args.atOrUndefined(isolate, 3);
  if (!IsJSAtomicsCondition(*js_condition_obj) ||
      !IsJSAtomicsMutex(*js_mutex_obj)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  std::optional<base::TimeDelta> timeout = std::nullopt;
  if (!IsUndefined(*timeout_obj, isolate)) {
    if (!IsNumber(*timeout_obj)) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewTypeError(MessageTemplate::kIsNotNumber, timeout_obj,
                                Object::TypeOf(isolate, timeout_obj)));
    }
    timeout = GetTimeoutDelta(timeout_obj);
  }

  if (!isolate->allow_atomics_wait()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kAtomicsOperationNotAllowed,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  auto js_condition = Cast<JSAtomicsCondition>(js_condition_obj);
  auto js_mutex = Cast<JSAtomicsMutex>(js_mutex_obj);

  if (!js_mutex->IsCurrentThreadOwner()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kAtomicsMutexNotOwnedByCurrentThread));
  }

  return isolate->heap()->ToBoolean(
      JSAtomicsCondition::WaitFor(isolate, js_condition, js_mutex, timeout));
}

BUILTIN(AtomicsConditionNotify) {
  DCHECK(v8_flags.harmony_struct);
  constexpr char method_name[] = "Atomics.Condition.notify";
  HandleScope scope(isolate);

  Handle<Object> js_condition_obj = args.atOrUndefined(isolate, 1);
  Handle<Object> count_obj = args.atOrUndefined(isolate, 2);
  if (!IsJSAtomicsCondition(*js_condition_obj)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  uint32_t count;
  if (IsUndefined(*count_obj, isolate)) {
    count = JSAtomicsCondition::kAllWaiters;
  } else {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, count_obj,
                                       Object::ToInteger(isolate, count_obj));
    double count_double = Object::NumberValue(*count_obj);
    if (count_double <= 0) {
      return Smi::zero();
    } else if (count_double > JSAtomicsCondition::kAllWaiters) {
      count_double = JSAtomicsCondition::kAllWaiters;
    }
    count = static_cast<uint32_t>(count_double);
  }

  auto js_condition = Cast<JSAtomicsCondition>(js_condition_obj);
  return *isolate->factory()->NewNumberFromUint(
      JSAtomicsCondition::Notify(isolate, js_condition, count));
}

BUILTIN(AtomicsConditionWaitAsync) {
  DCHECK(v8_flags.harmony_struct);
  constexpr char method_name[] = "Atomics.Condition.waitAsync";
  HandleScope scope(isolate);

  Handle<Object> js_condition_obj = args.atOrUndefined(isolate, 1);
  Handle<Object> js_mutex_obj = args.atOrUndefined(isolate, 2);
  if (!IsJSAtomicsCondition(*js_condition_obj) ||
      !IsJSAtomicsMutex(*js_mutex_obj)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  Handle<Object> timeout_obj = args.atOrUndefined(isolate, 3);
  std::optional<base::TimeDelta> timeout = std::nullopt;
  if (!IsUndefined(*timeout_obj, isolate)) {
    if (!IsNumber(*timeout_obj)) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewTypeError(MessageTemplate::kIsNotNumber, timeout_obj,
                                Object::TypeOf(isolate, timeout_obj)));
    }
    timeout = GetTimeoutDelta(timeout_obj);
  }

  Handle<JSAtomicsCondition> js_condition =
      Cast<JSAtomicsCondition>(js_condition_obj);
  auto js_mutex = Cast<JSAtomicsMutex>(js_mutex_obj);

  if (!js_mutex->IsCurrentThreadOwner()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kAtomicsMutexNotOwnedByCurrentThread));
  }

  Handle<JSReceiver> result_promise;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result_promise,
      JSAtomicsCondition::WaitAsync(isolate, js_condition, js_mutex, timeout));
  return *result_promise;
}

BUILTIN(AtomicsConditionAcquireLock) {
  DCHECK(v8_flags.harmony_struct);
  HandleScope scope(isolate);

  DirectHandle<Context> context(isolate->context(), isolate);
  Handle<Object> js_mutex_obj = Handle<Object>(
      context->get(JSAtomicsCondition::kMutexAsyncContextSlot), isolate);
  Handle<JSAtomicsMutex> js_mutex = Cast<JSAtomicsMutex>(js_mutex_obj);
  DirectHandle<JSPromise> lock_promise =
      JSAtomicsMutex::LockAsyncWrapperForWait(isolate, js_mutex);
  return *lock_promise;
}

}  // namespace internal
}  // namespace v8
```