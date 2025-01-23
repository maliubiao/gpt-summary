Response:
The user wants a summary of the provided C++ code snippet for `v8/src/execution/futex-emulation.cc`. This is the second part of a two-part description. I should focus on summarizing the functionality described in this specific snippet.

The code deals with managing lists of "waiters" (threads or promises waiting on a futex). Key functions include:

*   **`ResolveAsyncWaiterPromises`**: Handles resolving promises that were waiting on a futex when their isolate is shutting down.
*   **`HandleAsyncWaiterTimeout`**:  Manages the timeout case for asynchronous futex waits.
*   **`IsolateDeinit`**: Cleans up futex waiter data when an isolate is being deinitialized.
*   **`NumWaitersForTesting`**:  A debugging/testing function to count the number of active waiters on a specific futex location.
*   **`NumUnresolvedAsyncPromisesForTesting`**: A debugging/testing function to count the number of unresolved promises waiting on a specific futex location.
*   **`FutexWaitList::Verify`**: A debug-only function to verify the integrity of the internal wait list data structures.
*   **`FutexWaitList::NodeIsOnList`**: A helper function to check if a node is present in a linked list.

Based on these functions, the main purpose of this code snippet is to manage the lifecycle of asynchronous futex waiters, especially handling scenarios like isolate shutdown and timeouts. The testing functions suggest this is a low-level component related to concurrency and synchronization.
这段代码主要负责管理异步futex等待操作的生命周期，特别是在Isolate（V8中的隔离执行上下文）关闭或等待超时的情况下。以下是其主要功能归纳：

**功能归纳:**

这段代码的主要职责是管理异步futex等待的生命周期，包括：

1. **处理异步等待Promise的解析:**  `ResolveAsyncWaiterPromises` 函数负责在Isolate即将关闭时，解析所有与该Isolate相关的、正在等待futex的Promise。它将这些Promise从等待列表中移除，并进行解析，确保这些异步操作能够完成。

2. **处理异步等待超时:** `HandleAsyncWaiterTimeout` 函数处理异步futex等待超时的情况。当一个异步等待操作超时时，该函数会将对应的等待节点从等待列表中移除，并解析相关的Promise。

3. **Isolate销毁时的清理:** `IsolateDeinit` 函数在Isolate被销毁时执行清理工作。它会遍历所有futex等待列表，找到并删除属于该Isolate的等待节点。为了防止内存泄漏，它会清理与这些等待节点相关的资源。

4. **提供测试辅助功能:**  `NumWaitersForTesting` 和 `NumUnresolvedAsyncPromisesForTesting` 是用于测试目的的函数。
    *   `NumWaitersForTesting` 统计指定ArrayBuffer和地址上当前正在等待（未被唤醒）的futex等待者数量。
    *   `NumUnresolvedAsyncPromisesForTesting` 统计指定ArrayBuffer和地址上，已经超时或准备被解析但尚未完成解析的异步Promise等待者的数量。

5. **维护等待列表的完整性:**  `FutexWaitList::Verify` 函数（仅在Debug模式下启用）用于验证内部等待列表数据结构的完整性，例如链表的连接是否正确，节点是否在列表中等。 `FutexWaitList::NodeIsOnList` 是一个辅助函数，用于检查一个节点是否在给定的链表中。

**关于代码的特性：**

*   **非Torque代码:** 文件名以 `.cc` 结尾，表明它是 C++ 源代码，而不是 Torque 源代码。

*   **与JavaScript的功能相关:**  这段代码直接支持 JavaScript 中使用 `SharedArrayBuffer` 和原子操作（如 `Atomics.waitAsync`）实现的异步等待功能。当 JavaScript 代码调用 `Atomics.waitAsync` 时，V8 引擎内部会使用这里的 futex 模拟机制来管理等待状态和通知。

**总结:**

这段代码是 V8 引擎中负责管理异步 futex 等待的核心部分。它确保了在各种情况下（包括正常唤醒、超时和 Isolate 关闭）异步等待操作能够正确地被处理和清理，避免资源泄漏并保证程序的正确性。它还提供了用于调试和测试的辅助功能。

由于这是第二部分，它主要关注异步 futex 等待的管理和清理，特别是涉及到 Isolate 的生命周期管理。第一部分可能更侧重于 futex 等待的注册和基本的唤醒机制。

### 提示词
```
这是目录为v8/src/execution/futex-emulation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/futex-emulation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
Emulation::ResolveAsyncWaiterPromises(Isolate* isolate) {
  // This function must run in the main thread of isolate.

  FutexWaitList* wait_list = GetWaitList();
  FutexWaitListNode* node;
  {
    NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

    auto& isolate_map = wait_list->isolate_promises_to_resolve_;
    auto it = isolate_map.find(isolate);
    DCHECK_NE(isolate_map.end(), it);

    node = it->second.head;
    isolate_map.erase(it);
  }

  // The list of nodes starting from "node" are no longer on any list, so it's
  // ok to iterate them without holding the mutex. We also need to not hold the
  // mutex while calling CleanupAsyncWaiterPromise, since it may allocate
  // memory.
  HandleScope handle_scope(isolate);
  while (node) {
    DCHECK(node->IsAsync());
    DCHECK_EQ(isolate, node->async_state_->isolate_for_async_waiters);
    DCHECK(!node->waiting_);
    ResolveAsyncWaiterPromise(node);
    CleanupAsyncWaiterPromise(node);
    // We've already tried to cancel the timeout task for the node; since we're
    // now in the same thread the timeout task is supposed to run, we know the
    // timeout task will never happen, and it's safe to delete the node here.
    DCHECK_EQ(CancelableTaskManager::kInvalidTaskId,
              node->async_state_->timeout_task_id);
    node = FutexWaitList::DeleteAsyncWaiterNode(node);
  }
}

void FutexEmulation::HandleAsyncWaiterTimeout(FutexWaitListNode* node) {
  // This function must run in the main thread of node's Isolate.
  DCHECK(node->IsAsync());

  FutexWaitList* wait_list = GetWaitList();

  {
    NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

    node->async_state_->timeout_task_id = CancelableTaskManager::kInvalidTaskId;
    if (!node->waiting_) {
      // If the Node is not waiting, it's already scheduled to have its Promise
      // resolved. Ignore the timeout.
      return;
    }
    wait_list->RemoveNode(node);
  }

  // "node" has been taken out of the lists, so it's ok to access it without
  // holding the mutex. We also need to not hold the mutex while calling
  // CleanupAsyncWaiterPromise, since it may allocate memory.
  HandleScope handle_scope(node->async_state_->isolate_for_async_waiters);
  ResolveAsyncWaiterPromise(node);
  CleanupAsyncWaiterPromise(node);
  delete node;
}

void FutexEmulation::IsolateDeinit(Isolate* isolate) {
  FutexWaitList* wait_list = GetWaitList();
  NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

  // Iterate all locations to find nodes belonging to "isolate" and delete them.
  // The Isolate is going away; don't bother cleaning up the Promises in the
  // NativeContext. Also we don't need to cancel the timeout tasks, since they
  // will be cancelled by Isolate::Deinit.
  {
    auto& location_lists = wait_list->location_lists_;
    auto it = location_lists.begin();
    while (it != location_lists.end()) {
      FutexWaitListNode*& head = it->second.head;
      FutexWaitListNode*& tail = it->second.tail;
      FutexWaitList::DeleteNodesForIsolate(isolate, &head, &tail);
      // head and tail are either both nullptr or both non-nullptr.
      DCHECK_EQ(head == nullptr, tail == nullptr);
      if (head == nullptr) {
        it = location_lists.erase(it);
      } else {
        ++it;
      }
    }
  }

  {
    auto& isolate_map = wait_list->isolate_promises_to_resolve_;
    auto it = isolate_map.find(isolate);
    if (it != isolate_map.end()) {
      for (FutexWaitListNode* node = it->second.head; node;) {
        DCHECK(node->IsAsync());
        DCHECK_EQ(isolate, node->async_state_->isolate_for_async_waiters);
        node->async_state_->timeout_task_id =
            CancelableTaskManager::kInvalidTaskId;
        node = FutexWaitList::DeleteAsyncWaiterNode(node);
      }
      isolate_map.erase(it);
    }
  }

  wait_list->Verify();
}

int FutexEmulation::NumWaitersForTesting(Tagged<JSArrayBuffer> array_buffer,
                                         size_t addr) {
  void* wait_location = FutexWaitList::ToWaitLocation(*array_buffer, addr);
  FutexWaitList* wait_list = GetWaitList();
  NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

  int num_waiters = 0;
  auto& location_lists = wait_list->location_lists_;
  auto it = location_lists.find(wait_location);
  if (it == location_lists.end()) return num_waiters;

  for (FutexWaitListNode* node = it->second.head; node; node = node->next_) {
    if (!node->waiting_) continue;
    if (node->IsAsync()) {
      if (node->async_state_->backing_store.expired()) continue;
      DCHECK_EQ(array_buffer->GetBackingStore(),
                node->async_state_->backing_store.lock());
    }
    num_waiters++;
  }

  return num_waiters;
}

int FutexEmulation::NumUnresolvedAsyncPromisesForTesting(
    Tagged<JSArrayBuffer> array_buffer, size_t addr) {
  void* wait_location = FutexWaitList::ToWaitLocation(array_buffer, addr);
  FutexWaitList* wait_list = GetWaitList();
  NoGarbageCollectionMutexGuard lock_guard(wait_list->mutex());

  int num_waiters = 0;
  auto& isolate_map = wait_list->isolate_promises_to_resolve_;
  for (const auto& it : isolate_map) {
    for (FutexWaitListNode* node = it.second.head; node; node = node->next_) {
      DCHECK(node->IsAsync());
      if (node->waiting_) continue;
      if (wait_location != node->wait_location_) continue;
      if (node->async_state_->backing_store.expired()) continue;
      DCHECK_EQ(array_buffer->GetBackingStore(),
                node->async_state_->backing_store.lock());
      num_waiters++;
    }
  }

  return num_waiters;
}

void FutexWaitList::Verify() const {
#ifdef DEBUG
  auto VerifyNode = [](FutexWaitListNode* node, FutexWaitListNode* head,
                       FutexWaitListNode* tail) {
    if (node->next_ != nullptr) {
      DCHECK_NE(node, tail);
      DCHECK_EQ(node, node->next_->prev_);
    } else {
      DCHECK_EQ(node, tail);
    }
    if (node->prev_ != nullptr) {
      DCHECK_NE(node, head);
      DCHECK_EQ(node, node->prev_->next_);
    } else {
      DCHECK_EQ(node, head);
    }

    DCHECK(NodeIsOnList(node, head));
  };

  for (const auto& [addr, head_and_tail] : location_lists_) {
    auto [head, tail] = head_and_tail;
    for (FutexWaitListNode* node = head; node; node = node->next_) {
      VerifyNode(node, head, tail);
    }
  }

  for (const auto& [isolate, head_and_tail] : isolate_promises_to_resolve_) {
    auto [head, tail] = head_and_tail;
    for (FutexWaitListNode* node = head; node; node = node->next_) {
      DCHECK(node->IsAsync());
      VerifyNode(node, head, tail);
      DCHECK_EQ(isolate, node->async_state_->isolate_for_async_waiters);
    }
  }
#endif  // DEBUG
}

bool FutexWaitList::NodeIsOnList(FutexWaitListNode* node,
                                 FutexWaitListNode* head) {
  for (FutexWaitListNode* n = head; n; n = n->next_) {
    if (n == node) return true;
  }
  return false;
}

}  // namespace v8::internal
```