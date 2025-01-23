Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for recognizable keywords and structures. I see:

* `// Copyright`, licensing information (not relevant to functionality).
* `#include`:  Headers indicating dependencies on other V8 components (`api-inl.h`, `base/...`, `execution/...`, `handles/...`, `objects/...`, `tasks/...`). This immediately suggests it's dealing with low-level operations within V8.
* `namespace v8::internal`: Confirms it's internal V8 code.
* `class FutexWaitList`:  The core data structure. The name "Futex" is a strong clue about its purpose.
* `AddNode`, `RemoveNode`, `DeleteAsyncWaiterNode`, `DeleteNodesForIsolate`: Methods for managing a linked list of waiting entities.
* `base::Mutex`:  Indicates thread safety and synchronization.
* `base::SmallMap`:  An optimized map data structure.
* `Tagged<JSArrayBuffer>`, `Tagged<Object>`, `Handle<...>`:  V8's managed object types.
* `FutexWaitListNode`:  Elements within the `FutexWaitList`.
* `CancelableTask`, `AsyncWaiterTimeoutTask`, `ResolveAsyncWaiterPromisesTask`:  Asynchronous operations and task management.
* `FutexEmulation`:  The main class containing the logic.
* `WaitJs32`, `WaitJs64`, `WaitWasm32`, `WaitWasm64`: Functions suggesting different wait scenarios (JavaScript and WebAssembly, 32-bit and 64-bit).
* `WaitSync`, `WaitAsync`:  Different modes of waiting.
* `Wake`:  The opposite of wait, signaling completion.
* `JSPromise`:  Involvement with JavaScript Promises.

**2. Inferring Core Functionality - "Futex":**

The name "Futex" is a strong indicator. It's a common abbreviation for "fast userspace mutex."  Even without knowing the V8 internals deeply, the presence of `FutexWaitList`, mutexes, and wait/wake methods strongly suggests this code is implementing a mechanism for threads (or in V8's case, potentially isolates or tasks) to wait for a specific condition to be met.

**3. Analyzing `FutexWaitList`:**

This class seems to be the central registry of waiting entities.

* **Purpose:**  Manages contexts waiting on memory locations (within shared buffers) and on promises.
* **Data Structures:**
    * `location_lists_`: A map from memory addresses within `JSArrayBuffer`s to linked lists of waiting nodes. This suggests the "wait" operation is tied to specific memory locations.
    * `isolate_promises_to_resolve_`: A map from `Isolate`s to linked lists of nodes waiting for promise resolution. This connects the futex mechanism to JavaScript Promises.
* **Synchronization:**  The `mutex_` protects the integrity of these data structures, ensuring thread-safe access.

**4. Analyzing `FutexWaitListNode`:**

This represents a single waiting entity.

* **Key Members:**
    * `wait_location_`: The memory address being waited on.
    * `waiting_`: A boolean indicating if the node is currently waiting.
    * `cond_`: A condition variable for synchronization within synchronous waits.
    * `interrupted_`: A flag for handling interruptions.
    * `async_state_`: Contains information specific to asynchronous waits (promise, timeout, etc.).

**5. Analyzing `FutexEmulation`:**

This class provides the public interface for interacting with the futex emulation.

* **`Wait...` functions:**  These are the entry points for initiating a wait. They handle different data types and contexts (JS, WASM, sync, async).
* **`WaitSync`:** Implements the synchronous waiting logic using condition variables. The code within the `do...while` loop handles checking the value, adding the node to the waitlist, waiting on the condition variable, and handling interruptions and timeouts.
* **`WaitAsync`:** Implements asynchronous waiting using Promises. It creates a Promise, adds the waiting node to the list, and sets up a timeout task if necessary.
* **`Wake`:**  Signals waiting entities. It iterates through the waitlist at the given memory location and notifies the waiting nodes.
* **Task classes (`ResolveAsyncWaiterPromisesTask`, `AsyncWaiterTimeoutTask`):** These handle the asynchronous resolution of Promises and timeout scenarios.

**6. Connecting to JavaScript:**

The presence of `WaitJs32`, `WaitJs64`, and the integration with `JSPromise` clearly links this code to JavaScript. The `Atomics` API in JavaScript comes to mind, as it deals with shared memory and waiting/waking.

**7. Considering `.tq` Extension:**

The prompt mentions `.tq`. Knowing that Torque is V8's internal language for generating optimized code, the fact that this file is `.cc` immediately tells us it's *not* a Torque file. Torque files generate C++ code.

**8. Code Logic Inference (Example with `WaitSync`):**

Let's take a small piece of `WaitSync` and infer logic:

* **Assumption:** A JavaScript thread calls `Atomics.wait(sharedArray, index, expectedValue, timeout)`. This translates to `FutexEmulation::WaitJs32` or `WaitJs64`.
* **Input:** `array_buffer`, `addr`, `value`, `rel_timeout_ms`.
* **Process in `WaitSync`:**
    1. Check if the value at the memory location matches `value`. If not, return "not-equal".
    2. Add the current thread's wait node to the `FutexWaitList` associated with the memory location.
    3. Wait on the node's condition variable (`cond_`).
    4. If `Wake` is called on this location, the condition variable is notified, and the thread wakes up.
    5. If the timeout expires, the thread wakes up.
    6. Return "ok" (if woken) or "timed-out".
* **Output:**  The JavaScript side receives "ok", "not-equal", or "timed-out".

**9. Common Programming Errors:**

Thinking about how this is used in JavaScript (`Atomics`), common errors come to mind:

* **Incorrect `expectedValue`:** Waiting for a value that will never be set.
* **Incorrect `address`:**  Waiting on the wrong memory location.
* **Forgetting to `Wake`:**  If no other thread calls `Atomics.wake`, the waiting thread might wait indefinitely.
* **Race conditions:**  Multiple threads might try to modify the shared memory location simultaneously without proper synchronization.

**10. Final Summarization (Part 1):**

Based on the analysis, the key functionalities can be summarized as:

* **Implementing a futex-like mechanism:**  Allows JavaScript and WebAssembly code to wait for specific conditions on shared memory.
* **Synchronous and Asynchronous waiting:** Supports both blocking waits (using condition variables) and non-blocking waits (using Promises).
* **Managing waiting contexts:**  The `FutexWaitList` tracks threads/tasks waiting on specific memory locations.
* **Integration with JavaScript `Atomics`:** Provides the underlying implementation for the `Atomics.wait` and `Atomics.wake` operations.
* **Handling timeouts:**  Supports optional timeouts for wait operations.

This detailed breakdown, combining code analysis, keyword recognition, and knowledge of related concepts (like futexes and the JavaScript `Atomics` API), allows for a comprehensive understanding of the code's purpose.
好的，让我们来分析一下 `v8/src/execution/futex-emulation.cc` 这个 V8 源代码文件的功能。

**功能归纳:**

`v8/src/execution/futex-emulation.cc` 实现了对 futex（快速用户空间互斥量）的模拟。它主要用于支持 JavaScript 和 WebAssembly 中的原子操作 (`Atomics.wait` 和 `Atomics.wake`)，以便在共享内存上进行同步。

**具体功能点:**

1. **FutexWaitList 管理:**
   - 维护一个全局的等待列表 (`FutexWaitList`)，用于跟踪所有等待在特定内存地址上的执行上下文（可能是 JavaScript 线程或 WebAssembly 实例）。
   - 使用 `base::SmallMap` 来高效地存储和查找等待在特定内存位置的节点。
   - 提供了添加 (`AddNode`) 和移除 (`RemoveNode`) 等待节点的功能。
   - 实现了针对特定 `Isolate` 清理等待节点的功能 (`DeleteNodesForIsolate`)，这在 `Isolate` 关闭时非常重要。

2. **FutexWaitListNode:**
   - 定义了等待列表中的节点 (`FutexWaitListNode`)，每个节点代表一个正在等待的执行上下文。
   - 包含等待的内存地址 (`wait_location_`)、等待状态 (`waiting_`) 以及用于同步的条件变量 (`cond_`) 和互斥锁 (`mutex_` 在 `FutexWaitList` 中)。
   - 对于异步等待，还包含 `async_state_`，其中存储了与 Promise 相关的状态信息，以及超时任务 ID。

3. **同步等待 (`WaitSync`):**
   - 实现了同步的等待操作。当 JavaScript 或 WebAssembly 调用 `Atomics.wait` 时，会进入此函数。
   - 它会检查共享内存地址上的值是否与期望值匹配。
   - 如果匹配，则将当前执行上下文添加到等待列表中，并阻塞当前线程，直到被唤醒或超时。
   - 使用条件变量 (`cond_`) 进行线程阻塞和唤醒。
   - 处理中断信号。

4. **异步等待 (`WaitAsync`):**
   - 实现了异步的等待操作，返回一个 Promise。
   - 当 JavaScript 调用 `Atomics.waitAsync` 时，会进入此函数。
   - 与同步等待类似，它也会检查共享内存地址上的值。
   - 如果匹配，则创建一个 `FutexWaitListNode` 并添加到等待列表中。
   - 如果指定了超时时间，则会创建一个延迟执行的任务 (`AsyncWaiterTimeoutTask`)，在超时后唤醒等待者。
   - 当被 `Wake` 调用唤醒时，或者超时发生时，会解析相应的 Promise。

5. **唤醒 (`Wake`):**
   - 实现了唤醒等待在特定内存地址上的执行上下文的功能。
   - 遍历等待列表，找到与指定内存地址匹配的等待节点。
   - 根据 `num_waiters_to_wake` 参数，唤醒指定数量的等待者。
   - 对于同步等待，调用条件变量的 `NotifyOne()`。
   - 对于异步等待，会调度一个任务 (`ResolveAsyncWaiterPromisesTask`) 来解析相应的 Promise。

6. **超时处理:**
   - 对于异步等待，使用 `CancelableTask` 实现超时机制。
   - `AsyncWaiterTimeoutTask` 在超时后被执行，负责通知等待者超时。

7. **Promise 管理 (异步等待):**
   - 使用弱引用 (`std::weak_ptr`) 来存储与异步等待相关的 `JSArrayBuffer` 的 `BackingStore`，以避免内存泄漏。
   - 使用 `v8::Global` 管理 Promise 对象，并在 Promise 被解决后释放。
   - 维护一个 `isolate_promises_to_resolve_` 列表，用于批量解析同一 `Isolate` 下的待解析 Promise，以提高效率。

8. **与 JavaScript 的交互:**
   - 提供了 `WaitJs32` 和 `WaitJs64` 函数，作为 JavaScript `Atomics.wait` 的底层实现。
   - 返回特定的字符串（"ok"、"not-equal"、"timed-out"）来表示等待的结果。

9. **与 WebAssembly 的交互:**
   - 提供了 `WaitWasm32` 和 `WaitWasm64` 函数，作为 WebAssembly 中原子操作的底层实现。

**关于 `.tq` 后缀:**

根据您的描述，如果 `v8/src/execution/futex-emulation.cc` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。由于该文件以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 文件。Torque 文件通常用于生成高效的 C++ 代码，但这个文件本身就是 C++ 代码。

**与 JavaScript 功能的关系及示例:**

`v8/src/execution/futex-emulation.cc` 直接为 JavaScript 的 `Atomics` API 提供底层支持。

**JavaScript 示例:**

```javascript
// 创建一个共享的 Int32Array
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const i32a = new Int32Array(sab);

// 期望的初始值
const expected = 0;
// 超时时间（毫秒）
const timeout = 1000;

// 模拟一个工作线程
const worker = new Worker('./worker.js');

// 主线程等待共享内存中的值变为 1
console.log('主线程：等待开始');
const result = Atomics.wait(i32a, 0, expected, timeout);
console.log('主线程：等待结束，结果:', result);

// worker.js 内容 (模拟另一个线程修改共享内存)
// self.onmessage = function(e) {
//   const i32a = new Int32Array(e.data);
//   console.log('工作线程：收到消息，修改共享内存');
//   Atomics.store(i32a, 0, 1);
//   Atomics.wake(i32a, 0, 1); // 唤醒等待的线程
// };
// postMessage(i32a);
```

在这个例子中：

- `Atomics.wait(i32a, 0, expected, timeout)` 会调用 `v8/src/execution/futex-emulation.cc` 中的 `WaitJs32` 函数。
- 主线程会等待 `i32a[0]` 的值变为非 `expected` (0) 的状态，或者直到超时。
- 工作线程（在 `worker.js` 中）会修改 `i32a[0]` 的值为 1，并调用 `Atomics.wake` 唤醒主线程。
- `Atomics.wake(i32a, 0, 1)` 会调用 `v8/src/execution/futex-emulation.cc` 中的 `Wake` 函数。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- `array_buffer`: 一个指向 `SharedArrayBuffer` 的 `Handle<JSArrayBuffer>`.
- `addr`:  共享内存中的偏移量 (例如: 0).
- `value`:  期望的初始值 (例如: 0).
- `rel_timeout_ms`: 等待的超时时间 (例如: 1000 毫秒).

**场景：主线程等待一个值改变**

1. **初始状态:**  共享内存地址 `addr` 上的值为 `value` (0)。
2. **主线程调用 `WaitJs32`:**  `WaitSync` 被调用。
3. **检查值:** `WaitSync` 检查 `array_buffer` 的 `addr` 位置的值，发现与 `value` 相等。
4. **添加到等待列表:** 主线程的执行上下文被添加到 `FutexWaitList` 中，与该 `array_buffer` 和 `addr` 关联。
5. **线程阻塞:** 主线程在 `cond_.Wait` 上阻塞。
6. **工作线程修改值并唤醒:** 另一个线程将 `array_buffer` 的 `addr` 位置的值修改为非 0 的值，并调用 `Wake`。
7. **查找等待者:** `Wake` 函数在 `FutexWaitList` 中找到等待在 `array_buffer` 和 `addr` 上的主线程。
8. **唤醒主线程:** `Wake` 调用 `cond_.NotifyOne()` 唤醒主线程。
9. **主线程恢复执行:**  `WaitSync` 返回 `WaitReturnValue::kOk` (0)。
10. **`WaitJs32` 返回:** JavaScript 层面收到 "ok"。

**输出:** JavaScript 的 `Atomics.wait` 调用返回字符串 "ok"。

**涉及用户常见的编程错误:**

1. **错误的期望值:** 用户在 `Atomics.wait` 中指定的 `expectedValue` 与共享内存中的实际值不符，导致 `Atomics.wait` 立即返回 "not-equal"，即使可能将来会变成期望的值。

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const i32a = new Int32Array(sab);
   i32a[0] = 5; // 实际初始值为 5
   const result = Atomics.wait(i32a, 0, 0, 1000); // 期望值为 0，但实际是 5
   console.log(result); // 输出 "not-equal"
   ```

2. **忘记唤醒等待的线程:**  一个线程调用了 `Atomics.wait`，但没有其他线程在适当的时候调用 `Atomics.wake`，导致等待的线程一直阻塞，可能导致程序无响应或死锁。

   ```javascript
   // 主线程等待
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const i32a = new Int32Array(sab);
   const result = Atomics.wait(i32a, 0, 0, 10000);
   console.log(result); // 如果没有其他线程唤醒，最终会超时，输出 "timed-out"
   ```

3. **错误的内存地址或类型:**  `Atomics.wait` 中指定的内存地址或操作的类型与共享内存的实际结构不匹配，可能导致未定义的行为或错误。

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const i32a = new Int32Array(sab);
   const result = Atomics.wait(i32a, 100, 0, 1000); // 索引 100 超出范围
   console.log(result); // 可能会抛出错误，取决于具体的 V8 实现
   ```

**总结一下它的功能 (第 1 部分):**

`v8/src/execution/futex-emulation.cc` 的主要功能是为 V8 引擎提供 futex 机制的模拟，这是实现 JavaScript 和 WebAssembly 中原子操作同步的基础。它管理着等待在共享内存上的执行上下文，并提供了同步和异步的等待/唤醒机制，以及超时处理。该文件是 V8 中实现并发和共享内存操作的关键组成部分。

### 提示词
```
这是目录为v8/src/execution/futex-emulation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/futex-emulation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/futex-emulation.h"

#include <limits>

#include "src/api/api-inl.h"
#include "src/base/lazy-instance.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/small-map.h"
#include "src/execution/isolate.h"
#include "src/execution/vm-state-inl.h"
#include "src/handles/handles-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/objects-inl.h"
#include "src/tasks/cancelable-task.h"

namespace v8::internal {

using AtomicsWaitEvent = v8::Isolate::AtomicsWaitEvent;

// A {FutexWaitList} manages all contexts waiting (synchronously or
// asynchronously) on any address.
class FutexWaitList {
 public:
  FutexWaitList() = default;
  FutexWaitList(const FutexWaitList&) = delete;
  FutexWaitList& operator=(const FutexWaitList&) = delete;

  void AddNode(FutexWaitListNode* node);
  void RemoveNode(FutexWaitListNode* node);

  static void* ToWaitLocation(Tagged<JSArrayBuffer> array_buffer, size_t addr) {
    DCHECK_LT(addr, array_buffer->GetByteLength());
    // Use the cheaper JSArrayBuffer::backing_store() accessor, but DCHECK that
    // it matches the start of the JSArrayBuffer::GetBackingStore().
    DCHECK_EQ(array_buffer->backing_store(),
              array_buffer->GetBackingStore()->buffer_start());
    return static_cast<uint8_t*>(array_buffer->backing_store()) + addr;
  }

  // Deletes "node" and returns the next node of its list.
  static FutexWaitListNode* DeleteAsyncWaiterNode(FutexWaitListNode* node) {
    DCHECK(node->IsAsync());
    DCHECK_NOT_NULL(node->async_state_->isolate_for_async_waiters);
    FutexWaitListNode* next = node->next_;
    if (node->prev_ != nullptr) {
      node->prev_->next_ = next;
    }
    if (next != nullptr) {
      next->prev_ = node->prev_;
    }
    delete node;
    return next;
  }

  static void DeleteNodesForIsolate(Isolate* isolate, FutexWaitListNode** head,
                                    FutexWaitListNode** tail) {
    // For updating head & tail once we've iterated all nodes.
    FutexWaitListNode* new_head = nullptr;
    FutexWaitListNode* new_tail = nullptr;
    for (FutexWaitListNode* node = *head; node;) {
      if (node->IsAsync() &&
          node->async_state_->isolate_for_async_waiters == isolate) {
        node->async_state_->timeout_task_id =
            CancelableTaskManager::kInvalidTaskId;
        node = DeleteAsyncWaiterNode(node);
      } else {
        if (new_head == nullptr) {
          new_head = node;
        }
        new_tail = node;
        node = node->next_;
      }
    }
    *head = new_head;
    *tail = new_tail;
  }

  // For checking the internal consistency of the FutexWaitList.
  void Verify() const;
  // Returns true if |node| is on the linked list starting with |head|.
  static bool NodeIsOnList(FutexWaitListNode* node, FutexWaitListNode* head);

  base::Mutex* mutex() { return &mutex_; }

 private:
  friend class FutexEmulation;

  struct HeadAndTail {
    FutexWaitListNode* head;
    FutexWaitListNode* tail;
  };

  // `mutex` protects the composition of the fields below (i.e. no elements may
  // be added or removed without holding this mutex), as well as the `waiting_`
  // and `interrupted_` fields for each individual list node that is currently
  // part of the list. It must be the mutex used together with the `cond_`
  // condition variable of such nodes.
  base::Mutex mutex_;

  // Location inside a shared buffer -> linked list of Nodes waiting on that
  // location.
  // As long as the map does not grow beyond 16 entries, there is no dynamic
  // allocation and deallocation happening in wait or wake, which reduces the
  // time spend in the critical section.
  base::SmallMap<std::map<void*, HeadAndTail>, 16> location_lists_;

  // Isolate* -> linked list of Nodes which are waiting for their Promises to
  // be resolved.
  base::SmallMap<std::map<Isolate*, HeadAndTail>> isolate_promises_to_resolve_;
};

namespace {

// {GetWaitList} returns the lazily initialized global wait list.
DEFINE_LAZY_LEAKY_OBJECT_GETTER(FutexWaitList, GetWaitList)

}  // namespace

bool FutexWaitListNode::CancelTimeoutTask() {
  DCHECK(IsAsync());
  if (async_state_->timeout_task_id == CancelableTaskManager::kInvalidTaskId) {
    return true;
  }
  auto* cancelable_task_manager =
      async_state_->isolate_for_async_waiters->cancelable_task_manager();
  TryAbortResult return_value =
      cancelable_task_manager->TryAbort(async_state_->timeout_task_id);
  async_state_->timeout_task_id = CancelableTaskManager::kInvalidTaskId;
  return return_value != TryAbortResult::kTaskRunning;
}

void FutexWaitListNode::NotifyWake() {
  DCHECK(!IsAsync());
  // Lock the FutexEmulation mutex before notifying. We know that the mutex
  // will have been unlocked if we are currently waiting on the condition
  // variable. The mutex will not be locked if FutexEmulation::Wait hasn't
  // locked it yet. In that case, we set the interrupted_
  // flag to true, which will be tested after the mutex locked by a future wait.
  FutexWaitList* wait_list = GetWaitList();
  NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

  // if not waiting, this will not have any effect.
  cond_.NotifyOne();
  interrupted_ = true;
}

class ResolveAsyncWaiterPromisesTask : public CancelableTask {
 public:
  ResolveAsyncWaiterPromisesTask(Isolate* isolate)
      : CancelableTask(isolate), isolate_(isolate) {}

  void RunInternal() override {
    FutexEmulation::ResolveAsyncWaiterPromises(isolate_);
  }

 private:
  Isolate* isolate_;
};

class AsyncWaiterTimeoutTask : public CancelableTask {
 public:
  AsyncWaiterTimeoutTask(CancelableTaskManager* cancelable_task_manager,
                         FutexWaitListNode* node)
      : CancelableTask(cancelable_task_manager), node_(node) {}

  void RunInternal() override {
    FutexEmulation::HandleAsyncWaiterTimeout(node_);
  }

 private:
  FutexWaitListNode* node_;
};

void FutexEmulation::NotifyAsyncWaiter(FutexWaitListNode* node) {
  DCHECK(node->IsAsync());
  // This function can run in any thread.

  FutexWaitList* wait_list = GetWaitList();
  wait_list->mutex()->AssertHeld();

  // Nullify the timeout time; this distinguishes timed out waiters from
  // woken up ones.
  node->async_state_->timeout_time = base::TimeTicks();

  wait_list->RemoveNode(node);

  // Schedule a task for resolving the Promise. It's still possible that the
  // timeout task runs before the promise resolving task. In that case, the
  // timeout task will just ignore the node.
  auto& isolate_map = wait_list->isolate_promises_to_resolve_;
  auto it = isolate_map.find(node->async_state_->isolate_for_async_waiters);
  if (it == isolate_map.end()) {
    // This Isolate doesn't have other Promises to resolve at the moment.
    isolate_map.insert(
        std::make_pair(node->async_state_->isolate_for_async_waiters,
                       FutexWaitList::HeadAndTail{node, node}));
    auto task = std::make_unique<ResolveAsyncWaiterPromisesTask>(
        node->async_state_->isolate_for_async_waiters);
    node->async_state_->task_runner->PostNonNestableTask(std::move(task));
  } else {
    // Add this Node into the existing list.
    node->prev_ = it->second.tail;
    it->second.tail->next_ = node;
    it->second.tail = node;
  }
}

void FutexWaitList::AddNode(FutexWaitListNode* node) {
  DCHECK_NULL(node->prev_);
  DCHECK_NULL(node->next_);
  auto [it, inserted] =
      location_lists_.insert({node->wait_location_, HeadAndTail{node, node}});
  if (!inserted) {
    it->second.tail->next_ = node;
    node->prev_ = it->second.tail;
    it->second.tail = node;
  }

  Verify();
}

void FutexWaitList::RemoveNode(FutexWaitListNode* node) {
  if (!node->prev_ && !node->next_) {
    // If the node was the last one on its list, delete the whole list.
    size_t erased = location_lists_.erase(node->wait_location_);
    DCHECK_EQ(1, erased);
    USE(erased);
  } else if (node->prev_ && node->next_) {
    // If we have both a successor and a predecessor, skip the lookup in the
    // list and just update those two nodes directly.
    node->prev_->next_ = node->next_;
    node->next_->prev_ = node->prev_;
    node->prev_ = node->next_ = nullptr;
  } else {
    // Otherwise we have to lookup in the list to find the head and tail
    // pointers.
    auto it = location_lists_.find(node->wait_location_);
    DCHECK_NE(location_lists_.end(), it);
    DCHECK(NodeIsOnList(node, it->second.head));

    if (node->prev_) {
      DCHECK(!node->next_);
      node->prev_->next_ = nullptr;
      DCHECK_EQ(node, it->second.tail);
      it->second.tail = node->prev_;
      node->prev_ = nullptr;
    } else {
      DCHECK_EQ(node, it->second.head);
      it->second.head = node->next_;
      DCHECK(node->next_);
      node->next_->prev_ = nullptr;
      node->next_ = nullptr;
    }
  }

  Verify();
}

void AtomicsWaitWakeHandle::Wake() {
  // Adding a separate `NotifyWake()` variant that doesn't acquire the lock
  // itself would likely just add unnecessary complexity..
  // The split lock by itself isn’t an issue, as long as the caller properly
  // synchronizes this with the closing `AtomicsWaitCallback`.
  FutexWaitList* wait_list = GetWaitList();
  {
    NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());
    stopped_ = true;
  }
  isolate_->futex_wait_list_node()->NotifyWake();
}

enum WaitReturnValue : int { kOk = 0, kNotEqualValue = 1, kTimedOut = 2 };

namespace {

Tagged<Object> WaitJsTranslateReturn(Isolate* isolate, Tagged<Object> res) {
  if (IsSmi(res)) {
    int val = Smi::ToInt(res);
    switch (val) {
      case WaitReturnValue::kOk:
        return ReadOnlyRoots(isolate).ok_string();
      case WaitReturnValue::kNotEqualValue:
        return ReadOnlyRoots(isolate).not_equal_string();
      case WaitReturnValue::kTimedOut:
        return ReadOnlyRoots(isolate).timed_out_string();
      default:
        UNREACHABLE();
    }
  }
  return res;
}

}  // namespace

Tagged<Object> FutexEmulation::WaitJs32(Isolate* isolate, WaitMode mode,
                                        Handle<JSArrayBuffer> array_buffer,
                                        size_t addr, int32_t value,
                                        double rel_timeout_ms) {
  Tagged<Object> res =
      Wait<int32_t>(isolate, mode, array_buffer, addr, value, rel_timeout_ms);
  return WaitJsTranslateReturn(isolate, res);
}

Tagged<Object> FutexEmulation::WaitJs64(Isolate* isolate, WaitMode mode,
                                        Handle<JSArrayBuffer> array_buffer,
                                        size_t addr, int64_t value,
                                        double rel_timeout_ms) {
  Tagged<Object> res =
      Wait<int64_t>(isolate, mode, array_buffer, addr, value, rel_timeout_ms);
  return WaitJsTranslateReturn(isolate, res);
}

Tagged<Object> FutexEmulation::WaitWasm32(Isolate* isolate,
                                          Handle<JSArrayBuffer> array_buffer,
                                          size_t addr, int32_t value,
                                          int64_t rel_timeout_ns) {
  return Wait<int32_t>(isolate, WaitMode::kSync, array_buffer, addr, value,
                       rel_timeout_ns >= 0, rel_timeout_ns, CallType::kIsWasm);
}

Tagged<Object> FutexEmulation::WaitWasm64(Isolate* isolate,
                                          Handle<JSArrayBuffer> array_buffer,
                                          size_t addr, int64_t value,
                                          int64_t rel_timeout_ns) {
  return Wait<int64_t>(isolate, WaitMode::kSync, array_buffer, addr, value,
                       rel_timeout_ns >= 0, rel_timeout_ns, CallType::kIsWasm);
}

template <typename T>
Tagged<Object> FutexEmulation::Wait(Isolate* isolate, WaitMode mode,
                                    Handle<JSArrayBuffer> array_buffer,
                                    size_t addr, T value,
                                    double rel_timeout_ms) {
  DCHECK_LT(addr, array_buffer->GetByteLength());

  bool use_timeout = rel_timeout_ms != V8_INFINITY;
  int64_t rel_timeout_ns = -1;

  if (use_timeout) {
    // Convert to nanoseconds.
    double timeout_ns = rel_timeout_ms *
                        base::Time::kNanosecondsPerMicrosecond *
                        base::Time::kMicrosecondsPerMillisecond;
    if (timeout_ns > static_cast<double>(std::numeric_limits<int64_t>::max())) {
      // 2**63 nanoseconds is 292 years. Let's just treat anything greater as
      // infinite.
      use_timeout = false;
    } else {
      rel_timeout_ns = static_cast<int64_t>(timeout_ns);
    }
  }
  return Wait(isolate, mode, array_buffer, addr, value, use_timeout,
              rel_timeout_ns);
}

namespace {
double WaitTimeoutInMs(double timeout_ns) {
  return timeout_ns < 0
             ? V8_INFINITY
             : timeout_ns / (base::Time::kNanosecondsPerMicrosecond *
                             base::Time::kMicrosecondsPerMillisecond);
}
}  // namespace

template <typename T>
Tagged<Object> FutexEmulation::Wait(Isolate* isolate, WaitMode mode,
                                    Handle<JSArrayBuffer> array_buffer,
                                    size_t addr, T value, bool use_timeout,
                                    int64_t rel_timeout_ns,
                                    CallType call_type) {
  if (mode == WaitMode::kSync) {
    return WaitSync(isolate, array_buffer, addr, value, use_timeout,
                    rel_timeout_ns, call_type);
  }
  DCHECK_EQ(mode, WaitMode::kAsync);
  return WaitAsync(isolate, array_buffer, addr, value, use_timeout,
                   rel_timeout_ns, call_type);
}

template <typename T>
Tagged<Object> FutexEmulation::WaitSync(Isolate* isolate,
                                        Handle<JSArrayBuffer> array_buffer,
                                        size_t addr, T value, bool use_timeout,
                                        int64_t rel_timeout_ns,
                                        CallType call_type) {
  VMState<ATOMICS_WAIT> state(isolate);
  base::TimeDelta rel_timeout =
      base::TimeDelta::FromNanoseconds(rel_timeout_ns);

  // We have to convert the timeout back to double for the AtomicsWaitCallback.
  double rel_timeout_ms = WaitTimeoutInMs(static_cast<double>(rel_timeout_ns));
  AtomicsWaitWakeHandle stop_handle(isolate);

  isolate->RunAtomicsWaitCallback(AtomicsWaitEvent::kStartWait, array_buffer,
                                  addr, value, rel_timeout_ms, &stop_handle);
  if (isolate->has_exception()) return ReadOnlyRoots(isolate).exception();

  DirectHandle<Object> result;
  AtomicsWaitEvent callback_result = AtomicsWaitEvent::kWokenUp;

  FutexWaitList* wait_list = GetWaitList();
  FutexWaitListNode* node = isolate->futex_wait_list_node();
  void* wait_location = FutexWaitList::ToWaitLocation(*array_buffer, addr);

  base::TimeTicks timeout_time;
  if (use_timeout) {
    base::TimeTicks current_time = base::TimeTicks::Now();
    timeout_time = current_time + rel_timeout;
  }

  // The following is not really a loop; the do-while construct makes it easier
  // to break out early.
  // Keep the code in the loop as minimal as possible, because this is all in
  // the critical section.
  do {
    NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

    std::atomic<T>* p = reinterpret_cast<std::atomic<T>*>(wait_location);
    T loaded_value = p->load();
#if defined(V8_TARGET_BIG_ENDIAN)
    // If loading a Wasm value, it needs to be reversed on Big Endian platforms.
    if (call_type == CallType::kIsWasm) {
      DCHECK(sizeof(T) == kInt32Size || sizeof(T) == kInt64Size);
      loaded_value = ByteReverse(loaded_value);
    }
#endif
    if (loaded_value != value) {
      result =
          direct_handle(Smi::FromInt(WaitReturnValue::kNotEqualValue), isolate);
      callback_result = AtomicsWaitEvent::kNotEqual;
      break;
    }

    node->wait_location_ = wait_location;
    node->waiting_ = true;
    wait_list->AddNode(node);

    while (true) {
      if (V8_UNLIKELY(node->interrupted_)) {
        // Reset the interrupted flag while still holding the mutex.
        node->interrupted_ = false;

        // Unlock the mutex here to prevent deadlock from lock ordering between
        // mutex and mutexes locked by HandleInterrupts.
        lock_guard.Unlock();

        // Because the mutex is unlocked, we have to be careful about not
        // dropping an interrupt. The notification can happen in three different
        // places:
        // 1) Before Wait is called: the notification will be dropped, but
        //    interrupted_ will be set to 1. This will be checked below.
        // 2) After interrupted has been checked here, but before mutex is
        //    acquired: interrupted is checked in a loop, with mutex locked.
        //    Because the wakeup signal also acquires mutex, we know it will not
        //    be able to notify until mutex is released below, when waiting on
        //    the condition variable.
        // 3) After the mutex is released in the call to WaitFor(): this
        //    notification will wake up the condition variable. node->waiting()
        //    will be false, so we'll loop and then check interrupts.
        Tagged<Object> interrupt_object =
            isolate->stack_guard()->HandleInterrupts();

        lock_guard.Lock();

        if (IsException(interrupt_object, isolate)) {
          result = direct_handle(interrupt_object, isolate);
          callback_result = AtomicsWaitEvent::kTerminatedExecution;
          break;
        }
      }

      if (V8_UNLIKELY(node->interrupted_)) {
        // An interrupt occurred while the mutex was unlocked. Don't wait yet.
        continue;
      }

      if (stop_handle.has_stopped()) {
        node->waiting_ = false;
        callback_result = AtomicsWaitEvent::kAPIStopped;
      }

      if (!node->waiting_) {
        // We were woken either via the stop_handle or via Wake.
        result = direct_handle(Smi::FromInt(WaitReturnValue::kOk), isolate);
        break;
      }

      // No interrupts, now wait.
      if (use_timeout) {
        base::TimeTicks current_time = base::TimeTicks::Now();
        if (current_time >= timeout_time) {
          result =
              direct_handle(Smi::FromInt(WaitReturnValue::kTimedOut), isolate);
          callback_result = AtomicsWaitEvent::kTimedOut;
          break;
        }

        base::TimeDelta time_until_timeout = timeout_time - current_time;
        DCHECK_GE(time_until_timeout.InMicroseconds(), 0);
        bool wait_for_result =
            node->cond_.WaitFor(wait_list->mutex(), time_until_timeout);
        USE(wait_for_result);
      } else {
        node->cond_.Wait(wait_list->mutex());
      }

      // Spurious wakeup, interrupt or timeout.
    }

    node->waiting_ = false;
    wait_list->RemoveNode(node);
  } while (false);
  DCHECK(!node->waiting_);

  isolate->RunAtomicsWaitCallback(callback_result, array_buffer, addr, value,
                                  rel_timeout_ms, nullptr);

  if (isolate->has_exception() &&
      callback_result != AtomicsWaitEvent::kTerminatedExecution) {
    return ReadOnlyRoots(isolate).exception();
  }

  return *result;
}

namespace {
template <typename T>
Global<T> GetWeakGlobal(Isolate* isolate, Local<T> object) {
  auto* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8::Global<T> global{v8_isolate, object};
  global.SetWeak();
  return global;
}
}  // namespace

FutexWaitListNode::FutexWaitListNode(std::weak_ptr<BackingStore> backing_store,
                                     void* wait_location,
                                     Handle<JSObject> promise, Isolate* isolate)
    : wait_location_(wait_location),
      waiting_(true),
      async_state_(std::make_unique<AsyncState>(
          isolate,
          V8::GetCurrentPlatform()->GetForegroundTaskRunner(
              reinterpret_cast<v8::Isolate*>(isolate)),
          std::move(backing_store),
          GetWeakGlobal(isolate, Utils::PromiseToLocal(promise)),
          GetWeakGlobal(isolate, Utils::ToLocal(isolate->native_context())))) {}

template <typename T>
Tagged<Object> FutexEmulation::WaitAsync(
    Isolate* isolate, DirectHandle<JSArrayBuffer> array_buffer, size_t addr,
    T value, bool use_timeout, int64_t rel_timeout_ns, CallType call_type) {
  base::TimeDelta rel_timeout =
      base::TimeDelta::FromNanoseconds(rel_timeout_ns);

  Factory* factory = isolate->factory();
  Handle<JSObject> result = factory->NewJSObject(isolate->object_function());
  Handle<JSObject> promise_capability = factory->NewJSPromise();

  enum class ResultKind { kNotEqual, kTimedOut, kAsync };
  ResultKind result_kind;
  void* wait_location = FutexWaitList::ToWaitLocation(*array_buffer, addr);
  // Get a weak pointer to the backing store, to be stored in the async state of
  // the node.
  std::weak_ptr<BackingStore> backing_store{array_buffer->GetBackingStore()};
  FutexWaitList* wait_list = GetWaitList();
  {
    // 16. Perform EnterCriticalSection(WL).
    NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

    // 17. Let w be ! AtomicLoad(typedArray, i).
    std::atomic<T>* p = static_cast<std::atomic<T>*>(wait_location);
    T loaded_value = p->load();
#if defined(V8_TARGET_BIG_ENDIAN)
    // If loading a Wasm value, it needs to be reversed on Big Endian platforms.
    if (call_type == CallType::kIsWasm) {
      DCHECK(sizeof(T) == kInt32Size || sizeof(T) == kInt64Size);
      loaded_value = ByteReverse(loaded_value);
    }
#endif
    if (loaded_value != value) {
      result_kind = ResultKind::kNotEqual;
    } else if (use_timeout && rel_timeout_ns == 0) {
      result_kind = ResultKind::kTimedOut;
    } else {
      result_kind = ResultKind::kAsync;

      FutexWaitListNode* node = new FutexWaitListNode(
          std::move(backing_store), wait_location, promise_capability, isolate);

      if (use_timeout) {
        node->async_state_->timeout_time = base::TimeTicks::Now() + rel_timeout;
        auto task = std::make_unique<AsyncWaiterTimeoutTask>(
            node->async_state_->isolate_for_async_waiters
                ->cancelable_task_manager(),
            node);
        node->async_state_->timeout_task_id = task->id();
        node->async_state_->task_runner->PostNonNestableDelayedTask(
            std::move(task), rel_timeout.InSecondsF());
      }

      wait_list->AddNode(node);
    }

    // Leaving the block collapses the following steps:
    // 18.a. Perform LeaveCriticalSection(WL).
    // 19.b. Perform LeaveCriticalSection(WL).
    // 24. Perform LeaveCriticalSection(WL).
  }

  switch (result_kind) {
    case ResultKind::kNotEqual:
      // 18. If v is not equal to w, then
      //   ...
      //   c. Perform ! CreateDataPropertyOrThrow(resultObject, "async", false).
      //   d. Perform ! CreateDataPropertyOrThrow(resultObject, "value",
      //     "not-equal").
      //   e. Return resultObject.
      CHECK(JSReceiver::CreateDataProperty(
                isolate, result, factory->async_string(),
                factory->false_value(), Just(kDontThrow))
                .FromJust());
      CHECK(JSReceiver::CreateDataProperty(
                isolate, result, factory->value_string(),
                factory->not_equal_string(), Just(kDontThrow))
                .FromJust());
      break;

    case ResultKind::kTimedOut:
      // 19. If t is 0 and mode is async, then
      //   ...
      //   c. Perform ! CreateDataPropertyOrThrow(resultObject, "async", false).
      //   d. Perform ! CreateDataPropertyOrThrow(resultObject, "value",
      //     "timed-out").
      //   e. Return resultObject.
      CHECK(JSReceiver::CreateDataProperty(
                isolate, result, factory->async_string(),
                factory->false_value(), Just(kDontThrow))
                .FromJust());
      CHECK(JSReceiver::CreateDataProperty(
                isolate, result, factory->value_string(),
                factory->timed_out_string(), Just(kDontThrow))
                .FromJust());
      break;

    case ResultKind::kAsync:
      // Add the Promise into the NativeContext's atomics_waitasync_promises
      // set, so that the list keeps it alive.
      DirectHandle<NativeContext> native_context(isolate->native_context());
      Handle<OrderedHashSet> promises(
          native_context->atomics_waitasync_promises(), isolate);
      promises = OrderedHashSet::Add(isolate, promises, promise_capability)
                     .ToHandleChecked();
      native_context->set_atomics_waitasync_promises(*promises);

      // 26. Perform ! CreateDataPropertyOrThrow(resultObject, "async", true).
      // 27. Perform ! CreateDataPropertyOrThrow(resultObject, "value",
      // promiseCapability.[[Promise]]).
      // 28. Return resultObject.
      CHECK(JSReceiver::CreateDataProperty(
                isolate, result, factory->async_string(), factory->true_value(),
                Just(kDontThrow))
                .FromJust());
      CHECK(JSReceiver::CreateDataProperty(isolate, result,
                                           factory->value_string(),
                                           promise_capability, Just(kDontThrow))
                .FromJust());
      break;
  }

  return *result;
}

int FutexEmulation::Wake(Tagged<JSArrayBuffer> array_buffer, size_t addr,
                         uint32_t num_waiters_to_wake) {
  void* wait_location = FutexWaitList::ToWaitLocation(array_buffer, addr);
  return Wake(wait_location, num_waiters_to_wake);
}

int FutexEmulation::Wake(void* wait_location, uint32_t num_waiters_to_wake) {
  int num_waiters_woken = 0;
  FutexWaitList* wait_list = GetWaitList();
  NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

  auto& location_lists = wait_list->location_lists_;
  auto it = location_lists.find(wait_location);
  if (it == location_lists.end()) return num_waiters_woken;

  FutexWaitListNode* node = it->second.head;
  while (node && num_waiters_to_wake > 0) {
    if (!node->waiting_) {
      node = node->next_;
      continue;
    }
    // Relying on wait_location_ here is not enough, since we need to guard
    // against the case where the BackingStore of the node has been deleted
    // during an async wait and a new BackingStore recreated in the same memory
    // area. Note that sync wait always keeps the backing store alive.
    // It is sufficient to check whether the node's backing store is expired
    // (and consider this a non-match). If it is not expired, it must be
    // identical to the backing store from which wait_location was computed by
    // the caller. In that case, the current context holds the arraybuffer and
    // backing store alive during this call, so it can not expire while we
    // execute this code.
    bool matching_backing_store =
        !node->IsAsync() || !node->async_state_->backing_store.expired();
    if (V8_LIKELY(matching_backing_store)) {
      node->waiting_ = false;

      // Retrieve the next node to iterate before calling NotifyAsyncWaiter,
      // since NotifyAsyncWaiter will take the node out of the linked list.
      FutexWaitListNode* next_node = node->next_;
      if (node->IsAsync()) {
        NotifyAsyncWaiter(node);
      } else {
        // WaitSync will remove the node from the list.
        node->cond_.NotifyOne();
      }
      node = next_node;
      if (num_waiters_to_wake != kWakeAll) {
        --num_waiters_to_wake;
      }
      num_waiters_woken++;
      continue;
    }

    // ---
    // Code below handles the unlikely case that this node's backing store was
    // deleted during an async wait and a new one was allocated in its place.
    // We delete the node if possible (no timeout, or context is gone).
    // ---
    bool delete_this_node = false;
    DCHECK(node->IsAsync());
    if (node->async_state_->timeout_time.IsNull()) {
      // Backing store has been deleted and the node is still waiting, and
      // there's no timeout. It's never going to be woken up, so we can clean it
      // up now. We don't need to cancel the timeout task, because there is
      // none.

      // This cleanup code is not very efficient, since it only kicks in when
      // a new BackingStore has been created in the same memory area where the
      // deleted BackingStore was.
      DCHECK(node->IsAsync());
      DCHECK_EQ(CancelableTaskManager::kInvalidTaskId,
                node->async_state_->timeout_task_id);
      delete_this_node = true;
    }
    if (node->async_state_->native_context.IsEmpty()) {
      // The NativeContext related to the async waiter has been deleted.
      // Ditto, clean up now.

      // Using the CancelableTaskManager here is OK since the Isolate is
      // guaranteed to be alive - FutexEmulation::IsolateDeinit removes all
      // FutexWaitListNodes owned by an Isolate which is going to die.
      if (node->CancelTimeoutTask()) {
        delete_this_node = true;
      }
      // If cancelling the timeout task failed, the timeout task is already
      // running and will clean up the node.
    }

    FutexWaitListNode* next_node = node->next_;
    if (delete_this_node) {
      wait_list->RemoveNode(node);
      delete node;
    }
    node = next_node;
  }

  return num_waiters_woken;
}

void FutexEmulation::CleanupAsyncWaiterPromise(FutexWaitListNode* node) {
  DCHECK(node->IsAsync());
  // This function must run in the main thread of node's Isolate. This function
  // may allocate memory. To avoid deadlocks, we shouldn't be holding the
  // FutexEmulationGlobalState::mutex.

  Isolate* isolate = node->async_state_->isolate_for_async_waiters;
  auto v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);

  if (!node->async_state_->promise.IsEmpty()) {
    auto promise = Cast<JSPromise>(
        Utils::OpenDirectHandle(*node->async_state_->promise.Get(v8_isolate)));
    // Promise keeps the NativeContext alive.
    DCHECK(!node->async_state_->native_context.IsEmpty());
    auto native_context = Cast<NativeContext>(Utils::OpenDirectHandle(
        *node->async_state_->native_context.Get(v8_isolate)));

    // Remove the Promise from the NativeContext's set.
    Handle<OrderedHashSet> promises(
        native_context->atomics_waitasync_promises(), isolate);
    bool was_deleted = OrderedHashSet::Delete(isolate, *promises, *promise);
    DCHECK(was_deleted);
    USE(was_deleted);
    promises = OrderedHashSet::Shrink(isolate, promises);
    native_context->set_atomics_waitasync_promises(*promises);
  } else {
    // NativeContext keeps the Promise alive; if the Promise is dead then
    // surely NativeContext is too.
    DCHECK(node->async_state_->native_context.IsEmpty());
  }
}

void FutexEmulation::ResolveAsyncWaiterPromise(FutexWaitListNode* node) {
  DCHECK(node->IsAsync());
  // This function must run in the main thread of node's Isolate.

  Isolate* isolate = node->async_state_->isolate_for_async_waiters;
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);

  // Try to cancel the timeout task (if one exists). If the timeout task exists,
  // cancelling it will always succeed. It's not possible for the timeout task
  // to be running, since it's scheduled to run in the same thread as this task.

  // Using the CancelableTaskManager here is OK since the Isolate is guaranteed
  // to be alive - FutexEmulation::IsolateDeinit removes all FutexWaitListNodes
  // owned by an Isolate which is going to die.
  bool success = node->CancelTimeoutTask();
  DCHECK(success);
  USE(success);

  if (!node->async_state_->promise.IsEmpty()) {
    DCHECK(!node->async_state_->native_context.IsEmpty());
    Local<v8::Context> native_context =
        node->async_state_->native_context.Get(v8_isolate);
    v8::Context::Scope contextScope(native_context);
    Handle<JSPromise> promise = Cast<JSPromise>(
        Utils::OpenHandle(*node->async_state_->promise.Get(v8_isolate)));
    Handle<String> result_string;
    // When waiters are notified, their timeout_time is reset. Having a
    // non-zero timeout_time here means the waiter timed out.
    if (node->async_state_->timeout_time != base::TimeTicks()) {
      DCHECK(node->waiting_);
      result_string = isolate->factory()->timed_out_string();
    } else {
      DCHECK(!node->waiting_);
      result_string = isolate->factory()->ok_string();
    }
    MaybeHandle<Object> resolve_result =
        JSPromise::Resolve(promise, result_string);
    DCHECK(!resolve_result.is_null());
    USE(resolve_result);
  }
}

void Futex
```