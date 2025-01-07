Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-atomics-synchronization.cc`.

Here's a breakdown of the thinking process to arrive at the answer:

1. **Identify the Core Components:**  The code clearly revolves around `JSAtomicsMutex` and `JSAtomicsCondition`. These are the key classes.

2. **Analyze `JSAtomicsMutex` Functionality:**
    * **`Lock` and `Unlock`:** These are the fundamental operations of a mutex. The code shows both synchronous and asynchronous versions (`LockAsync`).
    * **Asynchronous Locking (`LockAsync`):** This is more complex and involves promises. Look for promise creation and resolution (`NewJSPromise`, `JSPromise::Resolve`). The use of callbacks and timeouts is also apparent. The `LockAsyncSlowPath` suggests handling contention.
    * **Waiter Queue:**  The code mentions `LockAsyncWaiterQueueNode` and interacting with a waiter queue. This is how the mutex manages multiple requests for the lock.
    * **Timeouts:** The presence of `std::optional<base::TimeDelta> timeout` and `AsyncLockTimeoutTask` clearly indicates support for timed locking attempts.
    * **Error Handling:** The code checks for situations like the mutex being unlocked twice in `UnlockAsyncLockedMutex`.
    * **Underlying Mechanism:** The code refers to `LockImpl` and uses atomic operations (`std::atomic<StateT>`). This points to a low-level implementation of the mutex.

3. **Analyze `JSAtomicsCondition` Functionality:**
    * **`Wait` and `Notify`:** These are the standard condition variable operations. Again, both synchronous (`WaitFor`) and asynchronous (`WaitAsync`) versions exist.
    * **Asynchronous Waiting (`WaitAsync`):** Similar to `LockAsync`, this uses promises. The `atomics_condition_acquire_lock_sfi` suggests that acquiring the lock after being notified is part of the asynchronous wait process.
    * **Waiter Queue:** The code interacts with a waiter queue (`QueueWaiter`) specifically for condition variables.
    * **Timeouts:** `AsyncWaitTimeoutTask` indicates support for timed waits.
    * **Cleanup:** `CleanupMatchingAsyncWaiters` suggests managing waiters when conditions change or objects are garbage collected.

4. **Identify Asynchronous Patterns:**  The prevalence of `Async` in function names, the use of Promises, and the presence of timeout mechanisms strongly indicate asynchronous operations are a key feature.

5. **Look for Connections to JavaScript:** While the code is C++, the prefix "JS" in the class names suggests an interface with JavaScript. The use of Promises reinforces this connection, as Promises are a core JavaScript concept for asynchronous operations.

6. **Infer JavaScript Usage (and provide examples):** Based on the identified functionalities, think about how these features would be used in JavaScript. `Atomics.Mutex` and `Atomics.Condition` are the obvious corresponding JavaScript APIs. Construct basic usage scenarios demonstrating locking, unlocking, waiting, and notifying. Include an example of potential errors like forgetting to unlock.

7. **Infer Code Logic (and provide input/output):** For the more complex asynchronous parts, construct simplified scenarios. For example, in `LockAsync`,  imagine a mutex is initially unlocked. The input is a request to lock it asynchronously. The expected output is a resolved promise once the lock is acquired. Consider the case where the mutex is already locked, and the output is a pending promise until the mutex is released.

8. **Identify Common Programming Errors:**  Based on the mutex and condition variable concepts, think about typical mistakes developers make: forgetting to unlock, deadlocks (though not explicitly shown in this snippet, it's a related concept), and race conditions (which these primitives are designed to prevent, but incorrect usage can still lead to issues). The snippet itself mentions a specific error scenario related to promise prototype tampering.

9. **Address the `.tq` Question:** State that the code is C++ and not Torque based on the `.cc` extension.

10. **Synthesize a Summary:** Combine all the observations into a concise summary covering the main functionalities of both `JSAtomicsMutex` and `JSAtomicsCondition`, emphasizing the synchronous and asynchronous aspects and their relationship to JavaScript.

11. **Structure the Answer:**  Organize the information logically with clear headings for each aspect (functionality, JavaScript relation, logic, errors, etc.).

12. **Review and Refine:** Read through the generated answer to ensure accuracy, clarity, and completeness, addressing all parts of the user's request. Ensure the language is precise and avoids jargon where possible, or explains it clearly. For instance, clearly distinguish between the C++ implementation and the JavaScript API it supports.
好的，我们来归纳一下 `v8/src/objects/js-atomics-synchronization.cc` 的功能。

**功能归纳：**

`v8/src/objects/js-atomics-synchronization.cc` 文件实现了 JavaScript 中 `Atomics.Mutex` 和 `Atomics.Condition` 相关的核心功能。它提供了用于实现同步原语（互斥锁和条件变量）的底层机制，允许 JavaScript 代码在多线程环境中进行安全的资源访问和线程协作。

**具体功能点包括：**

1. **`JSAtomicsMutex` (互斥锁) 的实现：**
   - **同步锁 (`Lock`) 和解锁 (`Unlock`)：** 提供了基本的互斥锁操作，确保同一时刻只有一个线程可以访问被保护的资源。
   - **异步锁 (`LockAsync`)：** 允许在不阻塞主线程的情况下尝试获取锁。如果锁不可用，会创建一个 Promise，并在锁被释放后 resolve 该 Promise。支持可选的超时时间。
   - **异步锁的内部机制：**  包括快速尝试获取锁 (`BackoffTryLock`)、慢速路径处理 (`LockAsyncSlowPath`)、以及在锁竞争激烈时将等待线程加入队列 (`MaybeEnqueueNode`)。
   - **异步解锁处理：**  `UnlockAsyncLockedMutex` 处理异步锁的释放，并处理一些边缘情况，例如在 `waitAsync` 没有被 `await` 或者 Promise 原型被篡改时可能发生的重复解锁。
   - **异步锁的超时处理：** `HandleAsyncTimeout`  处理异步锁请求超时的情况，将等待线程从队列中移除，并 resolve 相应的 Promise。
   - **异步锁的通知处理：** `HandleAsyncNotify` 处理异步锁被通知（例如，通过条件变量）的情况，尝试再次获取锁，如果成功则 resolve 相应的 Promise。

2. **`JSAtomicsCondition` (条件变量) 的实现：**
   - **同步等待 (`WaitFor`) 和通知 (`Notify`)：** 提供了基本的条件变量操作，允许线程在满足特定条件时休眠，并在条件满足时被唤醒。
   - **异步等待 (`WaitAsync`)：** 允许在不阻塞主线程的情况下等待特定条件的发生。会创建一个 Promise，并在条件被通知后 resolve 该 Promise。支持可选的超时时间。
   - **异步等待的内部机制：** 包括创建并管理等待 Promise，以及在条件满足时 acquire 锁的逻辑。
   - **管理等待队列：** `QueueWaiter` 将等待线程添加到条件变量的等待队列中。
   - **显式出队操作：** `DequeueExplicit` 提供了在持有锁的情况下从等待队列中移除线程的机制。
   - **异步等待的超时处理：** `HandleAsyncTimeout` 处理异步等待超时的情况，将等待线程从队列中移除，并 resolve 相应的 Promise。
   - **异步等待的通知处理：** `HandleAsyncNotify` 处理异步等待被通知的情况，resolve 相应的 Promise。
   - **清理异步等待者：** `CleanupMatchingAsyncWaiters` 用于清理不再需要的异步等待者。

**关于文件后缀和 Torque：**

你提供的代码片段是 `.cc` 文件，这意味着它是 C++ 源代码，而不是 Torque 源代码。如果文件以 `.tq` 结尾，那才是 V8 的 Torque 源代码。

**与 JavaScript 功能的关系及示例：**

`v8/src/objects/js-atomics-synchronization.cc` 中实现的功能直接对应于 JavaScript 中的 `Atomics.Mutex` 和 `Atomics.Condition` 对象。

**`Atomics.Mutex` 示例：**

```javascript
const mutex = new Atomics.Mutex();

// 同步锁
mutex.lock();
try {
  // 访问共享资源
  console.log("获得了锁");
} finally {
  mutex.unlock();
  console.log("释放了锁");
}

// 异步锁
async function asyncLockExample() {
  await mutex.lockAsync();
  try {
    console.log("异步获得了锁");
    // 访问共享资源
  } finally {
    mutex.unlock();
    console.log("异步释放了锁");
  }
}

asyncLockExample();
```

**`Atomics.Condition` 示例：**

```javascript
const mutex = new Atomics.Mutex();
const condition = new Atomics.Condition();
let dataReady = false;

// 生产者
async function producer() {
  // ... 生产数据
  await new Promise(resolve => setTimeout(resolve, 1000)); // 模拟生产耗时

  mutex.lock();
  dataReady = true;
  condition.notifyOne(); // 通知一个等待的消费者
  mutex.unlock();
}

// 消费者
async function consumer() {
  mutex.lock();
  while (!dataReady) {
    await condition.waitAsync(mutex); // 异步等待数据准备好
  }
  console.log("消费者：数据已准备好");
  mutex.unlock();
}

producer();
consumer();
```

**代码逻辑推理示例：**

假设有以下异步锁的调用：

```javascript
const mutex = new Atomics.Mutex();
let lockAcquired = false;

async function tryLock() {
  await mutex.lockAsync();
  lockAcquired = true;
  console.log("锁被获取");
  await new Promise(resolve => setTimeout(resolve, 500)); // 模拟持有锁一段时间
  mutex.unlock();
  console.log("锁被释放");
}

async function main() {
  console.log("尝试第一次获取锁");
  const promise1 = tryLock();
  console.log("尝试第二次获取锁");
  const promise2 = tryLock();

  await Promise.all([promise1, promise2]);
  console.log("所有操作完成");
}

main();
```

**假设输入：** 两个并发的 `tryLock` 调用。

**预期输出：**

```
尝试第一次获取锁
尝试第二次获取锁
锁被获取  // 第一次调用成功获取锁
锁被释放
锁被获取  // 第二次调用在第一次释放后获取锁
锁被释放
所有操作完成
```

**用户常见的编程错误示例：**

1. **忘记解锁：**

   ```javascript
   const mutex = new Atomics.Mutex();

   mutex.lock();
   // ... 访问共享资源
   // 忘记调用 mutex.unlock()，导致其他线程永远无法获取锁，造成死锁。
   ```

2. **在异步操作中忘记 `await`：**

   ```javascript
   const mutex = new Atomics.Mutex();

   function incorrectAsyncLock() {
     mutex.lockAsync(); // 忘记 await，锁可能还没获取就执行后续代码
     console.log("尝试获取锁，但不确定是否成功");
   }

   incorrectAsyncLock();
   ```

3. **条件变量的虚假唤醒处理不当：**

   ```javascript
   const mutex = new Atomics.Mutex();
   const condition = new Atomics.Condition();
   let conditionMet = false;

   async function waitForCondition() {
     mutex.lock();
     // 错误的做法：只判断一次条件
     if (!conditionMet) {
       await condition.waitAsync(mutex);
     }
     console.log("条件满足了");
     mutex.unlock();
   }
   ```
   正确的做法应该在 `waitAsync` 之后使用 `while` 循环再次检查条件，以处理虚假唤醒。

4. **在持有锁的情况下执行耗时操作：** 这会降低程序的并发性。应该尽快释放锁。

**总结：**

`v8/src/objects/js-atomics-synchronization.cc` 是 V8 引擎中实现 JavaScript 原子操作同步原语的核心 C++ 代码，负责管理互斥锁和条件变量的状态、等待队列、以及异步操作的 Promise 管理和超时处理。它为 JavaScript 提供了在多线程环境下进行安全并发编程的基础设施。

Prompt: 
```
这是目录为v8/src/objects/js-atomics-synchronization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-atomics-synchronization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
 mutex, Handle<Object> callback,
    std::optional<base::TimeDelta> timeout) {
  Handle<JSPromise> internal_locked_promise =
      requester->factory()->NewJSPromise();
  Handle<JSReceiver> waiting_for_callback_promise;
  ASSIGN_RETURN_ON_EXCEPTION(
      requester, waiting_for_callback_promise,
      PerformPromiseThen(requester, internal_locked_promise, callback));
  Handle<JSPromise> unlocked_promise = requester->factory()->NewJSPromise();
  // Set the async unlock handlers here so we can throw without any additional
  // cleanup if the inner `promise_then` call fails. Keep a reference to
  // the handlers' synthetic context so we can store the waiter node in it once
  // the node is created.
  Handle<Context> handlers_context;
  ASSIGN_RETURN_ON_EXCEPTION(
      requester, handlers_context,
      SetAsyncUnlockHandlers(requester, mutex, waiting_for_callback_promise,
                             unlocked_promise));
  LockAsyncWaiterQueueNode* waiter_node = nullptr;
  bool locked = LockAsync(requester, mutex, internal_locked_promise,
                          unlocked_promise, &waiter_node, timeout);
  if (locked) {
    // Create an LockAsyncWaiterQueueNode to be queued in the async locked
    // waiter queue.
    DCHECK(!waiter_node);
    waiter_node = LockAsyncWaiterQueueNode::NewLockedAsyncWaiterStoredInIsolate(
        requester, mutex);
  }
  // Don't use kWaiterQueueNodeTag here as that will cause the pointer to be
  // stored in the shared external pointer table, which is not necessary since
  // this object is only visible in this thread.
  DirectHandle<Foreign> wrapper =
      requester->factory()->NewForeign<kWaiterQueueForeignTag>(
          reinterpret_cast<Address>(waiter_node));
  handlers_context->set(JSAtomicsMutex::kAsyncLockedWaiterAsyncContextSlot,
                        *wrapper);
  return unlocked_promise;
}

// static
bool JSAtomicsMutex::LockAsync(Isolate* requester, Handle<JSAtomicsMutex> mutex,
                               Handle<JSPromise> internal_locked_promise,
                               MaybeHandle<JSPromise> unlocked_promise,
                               LockAsyncWaiterQueueNode** waiter_node,
                               std::optional<base::TimeDelta> timeout) {
  bool locked =
      LockImpl(requester, mutex, timeout, [=](std::atomic<StateT>* state) {
        return LockAsyncSlowPath(requester, mutex, state,
                                 internal_locked_promise, unlocked_promise,
                                 waiter_node, timeout);
      });
  if (locked) {
    // Resolve `internal_locked_promise` instead of synchronously running the
    // callback. This guarantees that the callback is run in a microtask
    // regardless of the current state of the mutex.
    MaybeHandle<Object> result = JSPromise::Resolve(
        internal_locked_promise, requester->factory()->undefined_value());
    USE(result);
  } else {
    // If the promise is not resolved, keep it alive in a set in the native
    // context. The promise will be resolved and remove from the set in
    // `JSAtomicsMutex::HandleAsyncNotify` or
    // `JSAtomicsMutex::HandleAsyncTimeout`.
    AddPromiseToNativeContext(requester, internal_locked_promise);
  }
  return locked;
}

// static
Handle<JSPromise> JSAtomicsMutex::LockAsyncWrapperForWait(
    Isolate* requester, Handle<JSAtomicsMutex> mutex) {
  Handle<JSPromise> internal_locked_promise =
      requester->factory()->NewJSPromise();
  AsyncWaiterNodeType* waiter_node = nullptr;
  LockAsync(requester, mutex, internal_locked_promise, MaybeHandle<JSPromise>(),
            &waiter_node);
  return internal_locked_promise;
}

// static
bool JSAtomicsMutex::LockAsyncSlowPath(
    Isolate* isolate, Handle<JSAtomicsMutex> mutex, std::atomic<StateT>* state,
    Handle<JSPromise> internal_locked_promise,
    MaybeHandle<JSPromise> unlocked_promise,
    LockAsyncWaiterQueueNode** waiter_node,
    std::optional<base::TimeDelta> timeout) {
  // Spin for a little bit to try to acquire the lock, so as to be fast under
  // microcontention.
  if (BackoffTryLock(isolate, mutex, state)) {
    return true;
  }

  // At this point the lock is considered contended, create a new async waiter
  // node in the C++ heap. It's lifetime is managed by the requester's
  // `async_waiter_queue_nodes` list.
  LockAsyncWaiterQueueNode* this_waiter =
      LockAsyncWaiterQueueNode::NewAsyncWaiterStoredInIsolate(
          isolate, mutex, internal_locked_promise, unlocked_promise);
  if (!MaybeEnqueueNode(isolate, mutex, state, this_waiter)) {
    return true;
  }

  if (timeout) {
    // Start a timer to run the `AsyncLockTimeoutTask` after the timeout.
    TaskRunner* taks_runner = this_waiter->task_runner();
    auto task = std::make_unique<AsyncLockTimeoutTask>(
        isolate->cancelable_task_manager(), this_waiter);
    this_waiter->timeout_task_id_ = task->id();
    taks_runner->PostNonNestableDelayedTask(std::move(task),
                                            timeout->InSecondsF());
  }
  *waiter_node = this_waiter;
  return false;
}

// static
bool JSAtomicsMutex::LockOrEnqueueAsyncNode(Isolate* isolate,
                                            DirectHandle<JSAtomicsMutex> mutex,
                                            LockAsyncWaiterQueueNode* waiter) {
  std::atomic<StateT>* state = mutex->AtomicStatePtr();
  // Spin for a little bit to try to acquire the lock, so as to be fast under
  // microcontention.
  if (BackoffTryLock(isolate, mutex, state)) {
    return true;
  }

  return !MaybeEnqueueNode(isolate, mutex, state, waiter);
}

void JSAtomicsMutex::UnlockAsyncLockedMutex(
    Isolate* requester, DirectHandle<Foreign> async_locked_waiter_wrapper) {
  LockAsyncWaiterQueueNode* waiter_node =
      reinterpret_cast<LockAsyncWaiterQueueNode*>(
          async_locked_waiter_wrapper->foreign_address<kWaiterQueueForeignTag>(
              IsolateForSandbox(requester)));
  LockAsyncWaiterQueueNode::RemoveFromAsyncWaiterQueueList(waiter_node);
  if (IsCurrentThreadOwner()) {
    Unlock(requester);
    return;
  }
  // If this is reached, the lock was already released by this thread.
  // This can happen if waitAsync is called without awaiting or due to
  // promise prototype tampering. Setting Promise.prototype.then to a
  // non callable will cause the `waiting_for_callback_promise` (defined in
  // LockOrEnqueuePromise) reactions to be called even if the async callback
  // is not resolved; as a consequence, the following code will try to unlock
  // the mutex twice:
  //
  // let mutex = new Atomics.Mutex();
  // let cv = new Atomics.Condition();
  // Promise.prototype.then = undefined;
  // Atomics.Mutex.lockAsync(mutex, async function() {
  //   await Atomics.Condition.waitAsync(cv, mutex);
  // }
}

bool JSAtomicsMutex::DequeueTimedOutAsyncWaiter(
    Isolate* requester, DirectHandle<JSAtomicsMutex> mutex,
    std::atomic<StateT>* state, WaiterQueueNode* timed_out_waiter) {
  // First acquire the queue lock, which is itself a spinlock.
  StateT current_state = state->load(std::memory_order_relaxed);
  // There are no waiters, but the js mutex lock may be held by another thread.
  if (!HasWaitersField::decode(current_state)) return false;

  // The details of updating the state in this function are too complicated
  // for the waiter queue lock guard to manage, so handle the state manually.
  while (!TryLockWaiterQueueExplicit(state, current_state)) {
    YIELD_PROCESSOR;
  }

  // Get the waiter queue head.
  WaiterQueueNode* waiter_head =
      mutex->DestructivelyGetWaiterQueueHead(requester);

  if (waiter_head == nullptr) {
    // The queue is empty but the js mutex lock may be held by another thread,
    // release the waiter queue bit without changing the "is locked" bit.
    DCHECK(!HasWaitersField::decode(current_state));
    SetWaiterQueueStateOnly(state, kUnlockedUncontended);
    return false;
  }

  WaiterQueueNode* dequeued_node = WaiterQueueNode::DequeueMatching(
      &waiter_head,
      [&](WaiterQueueNode* node) { return node == timed_out_waiter; });

  // Release the queue lock and install the new waiter queue head.
  DCHECK_EQ(state->load(),
            IsWaiterQueueLockedField::update(current_state, true));
  StateT new_state = kUnlockedUncontended;
  new_state = mutex->SetWaiterQueueHead(requester, waiter_head, new_state);

  SetWaiterQueueStateOnly(state, new_state);
  return dequeued_node != nullptr;
}

// static
void JSAtomicsMutex::HandleAsyncTimeout(LockAsyncWaiterQueueNode* waiter) {
  Isolate* requester = waiter->requester_;
  HandleScope scope(requester);

  if (V8_UNLIKELY(waiter->native_context_.IsEmpty())) {
    // The native context was destroyed so the lock_promise was already removed
    // from the native context. Remove the node from the async unlocked waiter
    // list.
    LockAsyncWaiterQueueNode::RemoveFromAsyncWaiterQueueList(waiter);
    return;
  }

  v8::Context::Scope contextScope(waiter->GetNativeContext());
  DirectHandle<JSAtomicsMutex> js_mutex = waiter->GetSynchronizationPrimitive();

  bool dequeued = JSAtomicsMutex::DequeueTimedOutAsyncWaiter(
      requester, js_mutex, js_mutex->AtomicStatePtr(), waiter);
  // If the waiter is no longer in the queue, then its corresponding notify
  // task is already in the event loop, this doesn't guarantee that the lock
  // will be taken by the time the notify task runs, so cancel the notify task.
  if (!dequeued) {
    TryAbortResult abort_result =
        requester->cancelable_task_manager()->TryAbort(waiter->notify_task_id_);
    DCHECK_EQ(abort_result, TryAbortResult::kTaskAborted);
    USE(abort_result);
  }

  DirectHandle<JSPromise> lock_promise = waiter->GetInternalWaitingPromise();
  Handle<JSPromise> lock_async_promise = waiter->GetUnlockedPromise();
  Handle<JSObject> result = CreateResultObject(
      requester, requester->factory()->undefined_value(), false);
  auto resolve_result = JSPromise::Resolve(lock_async_promise, result);
  USE(resolve_result);
  LockAsyncWaiterQueueNode::RemoveFromAsyncWaiterQueueList(waiter);
  RemovePromiseFromNativeContext(requester, lock_promise);
}

// static
void JSAtomicsMutex::HandleAsyncNotify(LockAsyncWaiterQueueNode* waiter) {
  Isolate* requester = waiter->requester_;
  HandleScope scope(requester);

  if (V8_UNLIKELY(waiter->native_context_.IsEmpty())) {
    // The native context was destroyed, so the promise was already removed. But
    // it is possible that other threads are holding references to the
    // synchronization primitive. Try to notify the next waiter.
    if (!waiter->synchronization_primitive_.IsEmpty()) {
      DirectHandle<JSAtomicsMutex> js_mutex =
          waiter->GetSynchronizationPrimitive();
      std::atomic<StateT>* state = js_mutex->AtomicStatePtr();
      StateT current_state = state->load(std::memory_order_acquire);
      if (HasWaitersField::decode(current_state)) {
        // Another thread might take the lock while we are notifying the next
        // waiter, so manually release the queue lock without changing the
        // IsLockedField bit.
        while (!TryLockWaiterQueueExplicit(state, current_state)) {
          YIELD_PROCESSOR;
        }
        WaiterQueueNode* waiter_head =
            js_mutex->DestructivelyGetWaiterQueueHead(requester);
        if (waiter_head) {
          WaiterQueueNode* old_head = WaiterQueueNode::Dequeue(&waiter_head);
          old_head->Notify();
        }
        StateT new_state =
            js_mutex->SetWaiterQueueHead(requester, waiter_head, kEmptyState);
        new_state = IsWaiterQueueLockedField::update(new_state, false);
        SetWaiterQueueStateOnly(state, new_state);
      }
    }
    LockAsyncWaiterQueueNode::RemoveFromAsyncWaiterQueueList(waiter);
    return;
  }

  v8::Context::Scope contextScope(waiter->GetNativeContext());
  DirectHandle<JSAtomicsMutex> js_mutex = waiter->GetSynchronizationPrimitive();
  Handle<JSPromise> promise = waiter->GetInternalWaitingPromise();
  bool locked = LockOrEnqueueAsyncNode(requester, js_mutex, waiter);
  if (locked) {
    if (waiter->timeout_task_id_ != CancelableTaskManager::kInvalidTaskId) {
      TryAbortResult abort_result =
          requester->cancelable_task_manager()->TryAbort(
              waiter->timeout_task_id_);
      DCHECK_EQ(abort_result, TryAbortResult::kTaskAborted);
      USE(abort_result);
    }
    if (waiter->unlocked_promise_.IsEmpty()) {
      // This node came from an async wait notify giving control back to an
      // async lock call, so we don't need to put the node in the locked waiter
      // list because the original LockAsycWaiterQueueNode is already in
      // the locked waiter list.
      LockAsyncWaiterQueueNode::RemoveFromAsyncWaiterQueueList(waiter);
    }
    js_mutex->SetCurrentThreadAsOwner();
    auto resolve_result =
        JSPromise::Resolve(promise, requester->factory()->undefined_value());
    USE(resolve_result);
    RemovePromiseFromNativeContext(requester, promise);
  }
}

// static
void JSAtomicsCondition::CleanupMatchingAsyncWaiters(Isolate* isolate,
                                                     WaiterQueueNode* node,
                                                     DequeueMatcher matcher) {
  auto* async_node = static_cast<WaitAsyncWaiterQueueNode*>(node);
  if (async_node->ready_for_async_cleanup_) {
    // The node is not in the waiter queue and there is no HandleNotify task
    // for it in the event loop. So it is safe to delete it.
    return;
  }
  if (async_node->IsEmpty()) {
    // The node's underlying synchronization primitive has been collected, so
    // delete it.
    async_node->SetNotInListForVerification();
    return;
  }
  DirectHandle<JSAtomicsCondition> cv =
      async_node->GetSynchronizationPrimitive();
  std::atomic<StateT>* state = cv->AtomicStatePtr();
  StateT current_state = state->load(std::memory_order_relaxed);

  WaiterQueueLockGuard waiter_queue_lock_guard(state, current_state);

  WaiterQueueNode* waiter_head = cv->DestructivelyGetWaiterQueueHead(isolate);
  if (waiter_head) {
    WaiterQueueNode::DequeueAllMatchingForAsyncCleanup(&waiter_head, matcher);
  }
  StateT new_state =
      cv->SetWaiterQueueHead(isolate, waiter_head, current_state);
  waiter_queue_lock_guard.set_new_state(new_state);
}

// static
void JSAtomicsCondition::QueueWaiter(Isolate* requester,
                                     DirectHandle<JSAtomicsCondition> cv,
                                     WaiterQueueNode* waiter) {
  // The state pointer should not be used outside of this block as a shared GC
  // may reallocate it after waiting.
  std::atomic<StateT>* state = cv->AtomicStatePtr();

  // Try to acquire the queue lock, which is itself a spinlock.
  StateT current_state = state->load(std::memory_order_relaxed);
  WaiterQueueLockGuard waiter_queue_lock_guard(state, current_state);

  // With the queue lock held, enqueue the requester onto the waiter queue.
  WaiterQueueNode* waiter_head = cv->DestructivelyGetWaiterQueueHead(requester);
  WaiterQueueNode::Enqueue(&waiter_head, waiter);

  // Release the queue lock and install the new waiter queue head.
  DCHECK_EQ(state->load(),
            IsWaiterQueueLockedField::update(current_state, true));
  StateT new_state =
      cv->SetWaiterQueueHead(requester, waiter_head, current_state);
  waiter_queue_lock_guard.set_new_state(new_state);
}

// static
bool JSAtomicsCondition::WaitFor(Isolate* requester,
                                 DirectHandle<JSAtomicsCondition> cv,
                                 Handle<JSAtomicsMutex> mutex,
                                 std::optional<base::TimeDelta> timeout) {
  DisallowGarbageCollection no_gc;

  bool rv;
  {
    // Allocate a waiter queue node on-stack, since this thread is going to
    // sleep and will be blocked anyway.
    SyncWaiterQueueNode this_waiter(requester);

    JSAtomicsCondition::QueueWaiter(requester, cv, &this_waiter);

    // Release the mutex and wait for another thread to wake us up, reacquiring
    // the mutex upon wakeup.
    mutex->Unlock(requester);
    if (timeout) {
      rv = this_waiter.WaitFor(*timeout);
      if (!rv) {
        // If timed out, remove ourself from the waiter list, which is usually
        // done by the thread performing the notifying.
        std::atomic<StateT>* state = cv->AtomicStatePtr();
        DequeueExplicit(
            requester, cv, state, [&](WaiterQueueNode** waiter_head) {
              WaiterQueueNode* dequeued = WaiterQueueNode::DequeueMatching(
                  waiter_head,
                  [&](WaiterQueueNode* node) { return node == &this_waiter; });
              return dequeued ? 1 : 0;
            });
      }
    } else {
      this_waiter.Wait();
      rv = true;
    }
  }
  JSAtomicsMutex::Lock(requester, mutex);
  return rv;
}

// static
uint32_t JSAtomicsCondition::DequeueExplicit(
    Isolate* requester, DirectHandle<JSAtomicsCondition> cv,
    std::atomic<StateT>* state, const DequeueAction& action_under_lock) {
  // First acquire the queue lock, which is itself a spinlock.
  StateT current_state = state->load(std::memory_order_relaxed);

  if (!HasWaitersField::decode(current_state)) return 0;
  WaiterQueueLockGuard waiter_queue_lock_guard(state, current_state);

  // Get the waiter queue head.
  WaiterQueueNode* waiter_head = cv->DestructivelyGetWaiterQueueHead(requester);

  // There's no waiter to wake up, release the queue lock by setting it to the
  // empty state.
  if (waiter_head == nullptr) {
    StateT new_state = kEmptyState;
    waiter_queue_lock_guard.set_new_state(new_state);
    return 0;
  }

  uint32_t num_dequeued_waiters = action_under_lock(&waiter_head);

  // Release the queue lock and install the new waiter queue head.
  DCHECK_EQ(state->load(),
            IsWaiterQueueLockedField::update(current_state, true));
  StateT new_state =
      cv->SetWaiterQueueHead(requester, waiter_head, current_state);
  waiter_queue_lock_guard.set_new_state(new_state);

  return num_dequeued_waiters;
}

// static
uint32_t JSAtomicsCondition::Notify(Isolate* requester,
                                    DirectHandle<JSAtomicsCondition> cv,
                                    uint32_t count) {
  std::atomic<StateT>* state = cv->AtomicStatePtr();

  // Dequeue count waiters.
  return DequeueExplicit(
      requester, cv, state, [=](WaiterQueueNode** waiter_head) -> uint32_t {
        WaiterQueueNode* old_head;
        if (count == 1) {
          old_head = WaiterQueueNode::Dequeue(waiter_head);
          if (!old_head) return 0;
          old_head->Notify();
          return 1;
        }
        if (count == kAllWaiters) {
          old_head = *waiter_head;
          *waiter_head = nullptr;
        } else {
          old_head = WaiterQueueNode::Split(waiter_head, count);
        }
        if (!old_head) return 0;
        // Notify while holding the queue lock to avoid notifying
        // waiters that have been deleted in other threads.
        return old_head->NotifyAllInList();
      });
}

// The lockAsync flow is controlled 2 chained promises, with lock_promise being
// the return value of the API.
// 1. `internal_waiting_promise`, which will be resolved either in the notify
// task or in the
//    timeout task.
// 2. `lock_promise`, which will be resolved when the lock is acquired after
//    waiting.
// static
MaybeHandle<JSReceiver> JSAtomicsCondition::WaitAsync(
    Isolate* requester, Handle<JSAtomicsCondition> cv,
    DirectHandle<JSAtomicsMutex> mutex,
    std::optional<base::TimeDelta> timeout) {
  Handle<JSPromise> internal_waiting_promise =
      requester->factory()->NewJSPromise();
  Handle<Context> handler_context = requester->factory()->NewBuiltinContext(
      requester->native_context(), kAsyncContextLength);
  handler_context->set(kMutexAsyncContextSlot, *mutex);
  handler_context->set(kConditionVariableAsyncContextSlot, *cv);

  Handle<SharedFunctionInfo> info(
      requester->heap()->atomics_condition_acquire_lock_sfi(), requester);
  Handle<JSFunction> lock_function =
      Factory::JSFunctionBuilder{requester, info, handler_context}
          .set_map(requester->strict_function_without_prototype_map())
          .Build();

  Handle<JSReceiver> lock_promise;

  ASSIGN_RETURN_ON_EXCEPTION(
      requester, lock_promise,
      PerformPromiseThen(requester, internal_waiting_promise, lock_function));

  // Create a new async waiter node in the C++ heap. Its lifetime is managed by
  // the requester's `async_waiter_queue_nodes` list.
  WaitAsyncWaiterQueueNode* this_waiter =
      WaitAsyncWaiterQueueNode::NewAsyncWaiterStoredInIsolate(
          requester, cv, internal_waiting_promise);
  QueueWaiter(requester, cv, this_waiter);

  if (timeout) {
    TaskRunner* taks_runner = this_waiter->task_runner();
    auto task = std::make_unique<AsyncWaitTimeoutTask>(
        requester->cancelable_task_manager(), this_waiter);
    this_waiter->timeout_task_id_ = task->id();
    taks_runner->PostNonNestableDelayedTask(std::move(task),
                                            timeout->InSecondsF());
  }
  mutex->Unlock(requester);
  // Keep the wait promise alive in the native context.
  AddPromiseToNativeContext(requester, internal_waiting_promise);
  return lock_promise;
}

// static
void JSAtomicsCondition::HandleAsyncTimeout(WaitAsyncWaiterQueueNode* waiter) {
  Isolate* requester = waiter->requester_;
  if (V8_UNLIKELY(waiter->native_context_.IsEmpty())) {
    // The native context was destroyed so the promise was already removed
    // from the native context. Remove the node from the async unlocked waiter
    // list.
    WaitAsyncWaiterQueueNode::RemoveFromAsyncWaiterQueueList(waiter);
    return;
  }
  HandleScope scope(requester);
  DirectHandle<JSAtomicsCondition> cv = waiter->GetSynchronizationPrimitive();
  std::atomic<StateT>* state = cv->AtomicStatePtr();
  uint32_t num_dequeued =
      DequeueExplicit(requester, cv, state, [&](WaiterQueueNode** waiter_head) {
        WaiterQueueNode* dequeued = WaiterQueueNode::DequeueMatching(
            waiter_head, [&](WaiterQueueNode* node) { return node == waiter; });
        return dequeued ? 1 : 0;
      });
  // If the waiter is not in the queue, the notify task is already in the event
  // loop, so cancel the notify task.
  if (num_dequeued == 0) {
    TryAbortResult abort_result =
        requester->cancelable_task_manager()->TryAbort(waiter->notify_task_id_);
    DCHECK_EQ(abort_result, TryAbortResult::kTaskAborted);
    USE(abort_result);
  }
  // Reset the timeout task id to kInvalidTaskId, otherwise the notify task will
  // try to cancel it.
  waiter->timeout_task_id_ = CancelableTaskManager::kInvalidTaskId;
  JSAtomicsCondition::HandleAsyncNotify(waiter);
}

// static
void JSAtomicsCondition::HandleAsyncNotify(WaitAsyncWaiterQueueNode* waiter) {
  Isolate* requester = waiter->requester_;
  if (V8_UNLIKELY(waiter->native_context_.IsEmpty())) {
    // The native context was destroyed so the promise was already removed
    // from the native context. Remove the node from the async unlocked waiter
    // list.
    WaitAsyncWaiterQueueNode::RemoveFromAsyncWaiterQueueList(waiter);
    return;
  }
  HandleScope scope(requester);
  if (waiter->timeout_task_id_ != CancelableTaskManager::kInvalidTaskId) {
    TryAbortResult abort_result =
        requester->cancelable_task_manager()->TryAbort(
            waiter->timeout_task_id_);
    DCHECK_EQ(abort_result, TryAbortResult::kTaskAborted);
    USE(abort_result);
  }
  v8::Context::Scope contextScope(waiter->GetNativeContext());
  Handle<JSPromise> promise = waiter->GetInternalWaitingPromise();
  MaybeHandle<Object> result =
      JSPromise::Resolve(promise, requester->factory()->undefined_value());
  USE(result);
  WaitAsyncWaiterQueueNode::RemoveFromAsyncWaiterQueueList(waiter);
  RemovePromiseFromNativeContext(requester, promise);
}

}  // namespace internal
}  // namespace v8

"""


```