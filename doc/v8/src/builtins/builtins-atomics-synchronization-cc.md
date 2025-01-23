Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Understand the Context:** The file path `v8/src/builtins/builtins-atomics-synchronization.cc` immediately tells us this is related to built-in functions for atomic operations, specifically concerning synchronization primitives like mutexes and condition variables. The `.cc` extension confirms it's C++ code within the V8 engine.

2. **Initial Scan for Keywords and Structure:** Quickly scan the code for important keywords and structural elements:
    * `// Copyright`: Standard V8 copyright header.
    * `#include`:  Indicates dependencies on other V8 components (like `builtins-utils-inl.h`, `js-atomics-synchronization-inl.h`, `promise-inl.h`).
    * `namespace v8 { namespace internal { namespace { ... } } }`:  Standard C++ namespacing for V8 internal code. The anonymous namespace `namespace { ... }` suggests helper functions local to this file.
    * `BUILTIN(...)`: This is a crucial V8 macro. It signifies the definition of a built-in JavaScript function. The names inside the parentheses (`AtomicsMutexConstructor`, `AtomicsMutexLock`, etc.) directly correspond to methods in the `Atomics.Mutex` and `Atomics.Condition` JavaScript APIs.
    * Function names like `GetTimeoutDelta`, `UnlockAsyncLockedMutexFromPromiseHandler`. These suggest helper logic.
    * Error handling using `THROW_NEW_ERROR_RETURN_FAILURE`.
    * Use of `HandleScope`, `Handle`, `DirectHandle`. These are V8's smart pointers for managing garbage-collected objects.
    * Calls to `Execution::Call` for invoking JavaScript functions.
    * Use of `JSAtomicsMutex`, `JSAtomicsCondition`, `JSPromise`. These are V8's internal representations of the corresponding JavaScript objects.

3. **Analyze Helper Functions:** Examine the functions within the anonymous namespace:
    * `GetTimeoutDelta`: Takes a JavaScript object representing a timeout, converts it to milliseconds, and returns a `base::TimeDelta`. Handles edge cases like `NaN` and negative values. This is a common utility for handling timeouts in asynchronous operations.
    * `UnlockAsyncLockedMutexFromPromiseHandler`: This is more complex. It seems to be involved in the asynchronous unlocking process, likely when a promise associated with a lock resolves or rejects. It retrieves stored mutex and promise objects from the current context and calls a mutex method (`UnlockAsyncLockedMutex`). This hints at how V8 manages asynchronous locking states.

4. **Analyze `BUILTIN` Functions (Core Functionality):** This is where the main logic lies. Go through each `BUILTIN` definition:
    * **Constructors (`AtomicsMutexConstructor`, `AtomicsConditionConstructor`):** These are straightforward. They create new instances of `JSAtomicsMutex` and `JSAtomicsCondition`.
    * **`AtomicsMutexLock`:**  Performs synchronous locking. It checks if the argument is a `JSAtomicsMutex` and a callable function. It prevents locking on the main thread and recursive locking. Crucially, it uses a `JSAtomicsMutex::LockGuard` to manage the lock and executes the provided function under the lock.
    * **`AtomicsMutexTryLock`:** Attempts to acquire the lock without blocking. It uses a `TryLockGuard`. It returns an object indicating success or failure along with the result of the function if the lock was acquired.
    * **`AtomicsMutexLockWithTimeout`:**  Similar to `Lock`, but with a timeout. It uses a `LockGuard` that accepts a timeout.
    * **`AtomicsMutexLockAsync`:**  Performs asynchronous locking. It uses `JSAtomicsMutex::LockOrEnqueuePromise`, suggesting it returns a promise that resolves when the lock is acquired.
    * **`AtomicsMutexAsyncUnlockResolveHandler`, `AtomicsMutexAsyncUnlockRejectHandler`:** These look like handlers for the promise returned by `LockAsync`. They call `UnlockAsyncLockedMutexFromPromiseHandler` to actually release the lock.
    * **`AtomicsConditionWait`:** Implements the `wait` operation for condition variables. It verifies the types, extracts the timeout, and checks if the mutex is held by the current thread. It calls `JSAtomicsCondition::WaitFor`, which likely blocks the thread.
    * **`AtomicsConditionNotify`:** Implements the `notify` operation. It takes an optional count and calls `JSAtomicsCondition::Notify` to wake up waiting threads.
    * **`AtomicsConditionWaitAsync`:** The asynchronous version of `wait`, returning a promise.
    * **`AtomicsConditionAcquireLock`:**  This is interesting. It seems to be related to the asynchronous `wait` on a condition. It acquires a lock (asynchronously) which is necessary before waiting on a condition.

5. **Identify JavaScript Relationships:**  Connect the `BUILTIN` names to their JavaScript counterparts (`Atomics.Mutex.lock`, `Atomics.Condition.waitAsync`, etc.). This directly links the C++ implementation to the user-facing API.

6. **Consider Torque:** The prompt asks about `.tq` files. Since this file is `.cc`, it's C++, not Torque. Note this distinction. If it *were* Torque, the functionality would be similar, but the syntax and level of abstraction would differ.

7. **Illustrate with JavaScript Examples:**  Create simple JavaScript code snippets that demonstrate the usage of the corresponding `Atomics.Mutex` and `Atomics.Condition` methods. This helps solidify the understanding of what the C++ code is doing at a higher level.

8. **Infer Code Logic and Examples:**  For functions with more complex logic (like `TryLock` or `LockWithTimeout`), think about different scenarios and their expected outputs. Create examples showing successful lock acquisition, failed acquisition due to timeout, etc.

9. **Identify Common Errors:** Based on the checks performed in the C++ code (e.g., type checking, checking if the mutex is owned by the current thread, disallowing synchronous locking on the main thread), identify common programming errors users might make. Provide JavaScript examples of these errors.

10. **Review and Refine:**  Go back through the analysis, ensuring clarity, accuracy, and completeness. Check for any missed details or areas where the explanation could be improved. For example, explicitly mention the thread-blocking nature of synchronous operations and the non-recursive nature of the mutex.

This systematic approach, starting from high-level understanding and gradually drilling down into the details of each function, helps to thoroughly analyze and explain the functionality of the given V8 source code.
这个C++源代码文件 `v8/src/builtins/builtins-atomics-synchronization.cc` 是 V8 JavaScript 引擎的一部分，它实现了 **ECMAScript 标准中 `Atomics.Mutex` 和 `Atomics.Condition` 对象的相关功能**。  这些对象提供了在共享内存多线程环境中进行同步操作的基础设施。

**功能列举:**

这个文件主要实现了以下功能：

1. **`Atomics.Mutex` 的构造和操作:**
   - **`AtomicsMutexConstructor`**:  实现了 `new Atomics.Mutex()` 构造函数，用于创建一个新的互斥锁对象。
   - **`AtomicsMutexLock`**: 实现了 `Atomics.Mutex.lock(callback)` 方法，用于同步地获取互斥锁，并在持有锁的情况下执行提供的回调函数。如果锁已经被其他线程持有，当前线程将会被阻塞直到获取到锁。
   - **`AtomicsMutexTryLock`**: 实现了 `Atomics.Mutex.tryLock(callback)` 方法，尝试非阻塞地获取互斥锁。如果成功获取到锁，则执行回调函数并返回一个包含结果和成功状态的对象；如果锁已被持有，则不阻塞，直接返回包含未获取到锁的状态的对象。
   - **`AtomicsMutexLockWithTimeout`**: 实现了 `Atomics.Mutex.lockWithTimeout(callback, timeout)` 方法，尝试在指定超时时间内同步地获取互斥锁。行为类似于 `lock`，但如果在超时时间内未能获取到锁，则不会无限期阻塞。
   - **`AtomicsMutexLockAsync`**: 实现了 `Atomics.Mutex.lockAsync(callback, timeout?)` 方法，用于异步地获取互斥锁。返回一个 Promise，该 Promise 在获取到锁并执行完回调后 resolve。可以指定可选的超时时间。
   - **`AtomicsMutexAsyncUnlockResolveHandler` 和 `AtomicsMutexAsyncUnlockRejectHandler`**:  这两个是内部的回调处理函数，用于处理 `lockAsync` 返回的 Promise 的 resolve 和 reject 情况，负责在异步操作完成后释放锁。

2. **`Atomics.Condition` 的构造和操作:**
   - **`AtomicsConditionConstructor`**: 实现了 `new Atomics.Condition()` 构造函数，用于创建一个新的条件变量对象。
   - **`AtomicsConditionWait`**: 实现了 `Atomics.Condition.wait(mutex, timeout?)` 方法，允许线程原子地释放指定的互斥锁并等待条件变量被通知。可以指定可选的超时时间。这个操作必须在持有互斥锁的情况下调用。
   - **`AtomicsConditionNotify`**: 实现了 `Atomics.Condition.notify(count?)` 方法，用于唤醒等待在该条件变量上的一个或多个线程。可以指定唤醒的线程数量，默认为唤醒所有等待的线程。
   - **`AtomicsConditionWaitAsync`**: 实现了 `Atomics.Condition.waitAsync(mutex, timeout?)` 方法，用于异步地等待条件变量。返回一个 Promise，该 Promise 在条件变量被通知后 resolve。
   - **`AtomicsConditionAcquireLock`**:  这是一个内部方法，主要用于异步等待条件变量的实现中，在等待前重新获取互斥锁。

**关于 `.tq` 后缀:**

如果 `v8/src/builtins/builtins-atomics-synchronization.cc` 的文件名以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 开发的一种类型化的中间语言，用于更安全、更高效地定义内置函数。然而，根据你提供的文件名，这是一个 `.cc` 文件，因此是 **C++ 源代码**。

**与 JavaScript 功能的关系及举例:**

这个 C++ 文件直接实现了 JavaScript 中 `Atomics.Mutex` 和 `Atomics.Condition` API 的底层逻辑。这些 API 允许 JavaScript 开发者在共享内存的 Worker 线程之间进行同步，避免竞态条件等问题。

**JavaScript 示例:**

```javascript
// 创建一个共享的 ArrayBuffer
const sab = new SharedArrayBuffer(1024);
const mutex = new Atomics.Mutex();
const cond = new Atomics.Condition();

// 在一个 Worker 线程中
const worker1 = new Worker('worker.js');
worker1.postMessage({ type: 'lock', sab, mutex, cond });

// 在另一个 Worker 线程中
const worker2 = new Worker('worker.js');
worker2.postMessage({ type: 'lock', sab, mutex, cond });

// worker.js 的内容 (简化示例)
onmessage = function(event) {
  const { type, sab, mutexObj, condObj } = event.data;
  const mutex = mutexObj;
  const cond = condObj;

  if (type === 'lock') {
    console.log('Worker trying to acquire lock');
    Atomics.Mutex.lock(mutex, () => {
      console.log('Worker acquired lock, performing critical section');
      // 模拟一些需要同步的操作
      Atomics.Condition.notify(cond); // 通知其他等待的线程
    });
    console.log('Worker released lock');
  }
};
```

**代码逻辑推理及假设输入与输出:**

以 `AtomicsMutexLock` 为例进行推理：

**假设输入:**

- `js_mutex`: 一个已经创建的 `Atomics.Mutex` 对象的内部表示 (C++ 中的 `JSAtomicsMutex` 对象)。
- `run_under_lock`: 一个 JavaScript 函数。

**代码逻辑:**

1. 检查 `js_mutex` 是否是 `JSAtomicsMutex` 类型。如果不是，抛出 `TypeError`。
2. 检查 `run_under_lock` 是否是可调用的函数。如果不是，抛出 `TypeError`。
3. 检查当前线程是否允许原子操作，并且当前线程是否已经是该互斥锁的拥有者（防止递归锁定）。如果不允许或已拥有，抛出 `TypeError`。
4. 创建一个 `JSAtomicsMutex::LockGuard` 对象，这会自动尝试获取互斥锁。如果锁已经被其他线程持有，当前线程将会在这里阻塞。
5. 一旦获取到锁，调用 `Execution::Call` 执行 `run_under_lock` 函数。
6. 当 `run_under_lock` 执行完毕后，`LockGuard` 的析构函数会自动释放互斥锁。
7. 返回 `run_under_lock` 的执行结果。

**假设输入与输出示例 (模拟):**

假设 `mutex` 是一个未被锁定的 `Atomics.Mutex` 实例，`callback` 是一个简单的返回数字 `10` 的函数。

```javascript
const mutex = new Atomics.Mutex();
function callback() { return 10; }
const result = Atomics.Mutex.lock(mutex, callback);
console.log(result); // 输出: 10
```

在这个例子中，`AtomicsMutexLock` 会成功获取锁，执行 `callback` 函数，并返回其结果 `10`。

**涉及用户常见的编程错误:**

1. **在主线程上调用同步的 `lock` 或 `wait`:**  V8 不允许在主线程上执行可能导致阻塞的原子操作，因为这会冻结 UI。

   ```javascript
   const mutex = new Atomics.Mutex();
   // 在主线程上调用会导致错误
   Atomics.Mutex.lock(mutex, () => {}); // 错误: Atomics operation not allowed
   ```

2. **在没有持有锁的情况下调用 `Atomics.Condition.wait`:**  `wait` 操作必须在持有相应的互斥锁时调用，否则会导致错误或未定义的行为。

   ```javascript
   const mutex = new Atomics.Mutex();
   const cond = new Atomics.Condition();
   // 错误: AtomicsMutexNotOwnedByCurrentThread
   Atomics.Condition.wait(cond, mutex);
   ```

3. **忘记释放锁:** 如果使用 `Atomics.Mutex.lock`，V8 会在回调函数执行完毕后自动释放锁。但是，如果手动管理锁（例如，如果 API 提供了显式的 unlock 方法，尽管 `Atomics.Mutex` 没有），忘记释放锁会导致其他线程永久阻塞。

4. **类型错误:** 传递了错误的参数类型，例如将非函数传递给 `lock` 的回调参数。

   ```javascript
   const mutex = new Atomics.Mutex();
   // 错误: TypeError: Callback must be callable
   Atomics.Mutex.lock(mutex, 123);
   ```

5. **竞态条件和死锁 (逻辑错误):**  即使使用了 `Atomics.Mutex` 和 `Atomics.Condition`，不正确的同步逻辑仍然可能导致竞态条件或死锁。例如，两个线程互相等待对方释放锁。

这些功能是构建更复杂的并发模式的基础，例如生产者-消费者模式，或者在多线程环境中保护共享资源。理解这些底层的实现可以帮助开发者更好地利用这些 API 并避免常见的并发编程陷阱。

### 提示词
```
这是目录为v8/src/builtins/builtins-atomics-synchronization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-atomics-synchronization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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