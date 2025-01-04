Response: Let's break down the thought process to analyze this C++ code and explain its functionality in relation to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of `v8threads.cc` and its connection to JavaScript. This means I need to identify the core purpose of the code and how it facilitates JavaScript execution.

2. **Initial Scan for Keywords:**  I'll quickly scan the code for relevant terms:
    * `threads`, `Locker`, `Unlocker`, `mutex`, `Isolate`, `javascript`, `execution`, `stack`, `debug`, `regexp`. These give strong hints about the domain.

3. **Identify Core Classes/Concepts:**  The `Locker` and `Unlocker` classes stand out. Their names suggest managing some kind of locking mechanism. The `ThreadManager` class is also prominent, likely handling thread-related operations. `Isolate` is a key V8 concept representing an independent JavaScript execution environment.

4. **Analyze `Locker` and `Unlocker`:**
    * `Locker::Initialize`: Takes an `Isolate`. Calls `isolate_->thread_manager()->Lock()`. Sets a flag `has_lock_`.
    * `Locker::~Locker`: Checks `has_lock_` and calls `isolate_->thread_manager()->Unlock()`. Also handles `FreeThreadResources` or `ArchiveThread`.
    * `Unlocker::Initialize`: Takes an `Isolate`. Calls `isolate_->thread_manager()->Unlock()`.
    * `Unlocker::~Unlocker`: Calls `isolate_->thread_manager()->Lock()`.

    * **Inference:** These classes are clearly about managing a lock associated with an `Isolate`. The `Locker` acquires the lock, and the `Unlocker` releases it temporarily. The `top_level_` flag suggests nested locking scenarios.

5. **Analyze `ThreadManager`:**
    * `Lock()` and `Unlock()`: Directly manipulate a `mutex_`.
    * `InitThread()`: Initializes thread-local data for various components (`stack_guard`, `debug`).
    * `RestoreThread()`:  Complex logic involving `lazily_archived_thread_`, `ThreadState`, and restoring state for various V8 sub-systems.
    * `ArchiveThread()` and `EagerlyArchiveThread()`:  Save thread state.
    * `FreeThreadResources()`: Cleans up thread-specific resources.
    * `IsLockedByCurrentThread()`: Checks if the current thread holds the lock.
    * `ThreadState`: Seems to store the archived state of a thread.

    * **Inference:**  `ThreadManager` is responsible for managing threads within a V8 `Isolate`. This includes locking, initializing thread-local data, archiving and restoring thread states, and freeing resources. The archiving mechanism likely allows temporarily releasing a thread's resources without completely destroying the thread.

6. **Connect to JavaScript:** The filename `v8threads.cc` and the presence of `Locker` and `Unlocker` strongly suggest a connection to managing concurrent execution in a JavaScript environment. JavaScript itself is single-threaded in its core execution model, *but* V8 uses multiple threads internally for tasks like garbage collection, compilation, and handling asynchronous operations.

7. **Formulate the Core Functionality:** Based on the analysis, the file's main function is to provide mechanisms for managing threads within the V8 engine, particularly focusing on:
    * **Mutual Exclusion:** Ensuring that only one thread accesses critical `Isolate` resources at a time (using `Locker` and `Unlocker`).
    * **Thread Local Storage:** Managing data that is specific to each thread.
    * **Thread State Management:**  Saving and restoring the state of a thread, allowing it to be temporarily suspended and resumed.

8. **Explain the JavaScript Connection:**  Explain that while JavaScript is conceptually single-threaded, V8 uses threads internally. The `Locker` and `Unlocker` are crucial for coordinating access to shared V8 data structures by these internal threads. Explain how embedding applications might use `Locker` and `Unlocker` when interacting with V8 from multiple host OS threads.

9. **Provide a JavaScript Example (Crucial Step):** The challenge is to demonstrate the *effect* of this C++ code within a JavaScript context. Since `Locker` and `Unlocker` are mainly used internally by V8 or by embedding applications, a direct JavaScript example won't use these classes explicitly. Therefore, the example should illustrate a scenario where these mechanisms are *implicitly* at play:

    * **Asynchronous Operations:**  `setTimeout` or `fetch` are good examples because they involve V8's internal thread pool.
    * **Concurrency/Parallelism (Subtle):**  While not true parallelism in single-threaded JavaScript, the *effect* of concurrent operations managed by V8's threads can be shown.

    The example should highlight that even though the JavaScript code looks sequential, V8's internal thread management ensures consistency and prevents race conditions when these asynchronous operations interact with the JavaScript heap.

10. **Refine and Organize:** Structure the explanation clearly with headings, bullet points, and clear language. Explain the purpose of each class and function concisely. Emphasize the internal nature of these mechanisms within V8.

11. **Review and Iterate:** Read through the explanation to ensure accuracy and clarity. Check if the JavaScript example effectively illustrates the connection. For example, initially, I might think of a more complex example involving Workers, but that might overcomplicate the core point. `setTimeout` is a simple and direct way to show asynchronous behavior managed by V8's internal threads.

By following these steps, I can analyze the C++ code, understand its purpose, and effectively explain its relationship to JavaScript, even when the connection isn't a direct one-to-one mapping of code constructs.
这个 C++ 代码文件 `v8threads.cc` 的主要功能是**管理 V8 引擎中的线程，并提供线程安全的机制来访问和操作 V8 引擎的内部状态**。 它定义了 `Locker` 和 `Unlocker` 类，用于控制对 V8 `Isolate` 的访问，以及 `ThreadManager` 类，用于管理与线程相关的资源和状态。

以下是其主要功能点的归纳：

1. **线程锁定 (Locking):**
   - `Locker` 类用于获取对特定 `v8::Isolate` 的独占访问权。 当创建一个 `Locker` 对象时，它会尝试获取与该 `Isolate` 关联的锁。 只有拥有锁的线程才能安全地操作该 `Isolate` 的内部状态，例如创建对象、执行 JavaScript 代码等。
   - `Unlocker` 类用于临时释放由 `Locker` 获取的锁。 这允许其他线程在特定操作期间访问 `Isolate`，例如在执行某些不涉及 V8 内部状态的操作时。

2. **线程管理 (Thread Management):**
   - `ThreadManager` 类负责管理与 V8 引擎相关的线程资源。 这包括：
     - **线程本地存储 (Thread Local Storage):**  `InitThread` 方法用于初始化线程本地的数据，例如堆栈保护和调试器。
     - **线程状态存档和恢复 (Thread State Archiving and Restoration):** `ArchiveThread` 用于保存当前线程的状态，以便稍后可以恢复。 `RestoreThread` 用于恢复先前存档的线程状态。这对于在多线程环境中切换对 `Isolate` 的访问非常重要。
     - **线程资源释放 (Thread Resource Freeing):** `FreeThreadResources` 用于释放与线程关联的资源，例如句柄作用域和调试器状态。
     - **管理线程状态列表:**  维护一个已存档线程状态的列表 (`in_use_anchor_`) 和一个可用线程状态的列表 (`free_anchor_`)。

3. **线程安全 (Thread Safety):**
   - 通过 `Locker` 和 `Unlocker` 提供的锁机制，确保在多线程环境中对 V8 引擎内部状态的访问是互斥的，从而避免数据竞争和其他并发问题。
   - 使用 `std::mutex` 来实现底层的线程锁定。

**与 JavaScript 的关系以及 JavaScript 示例:**

虽然 JavaScript 本身是单线程的（在单个浏览器的 tab 页或 Node.js 进程中），但 V8 引擎内部使用了多线程来执行各种任务，例如：

- **编译 JavaScript 代码:**  将 JavaScript 代码编译为机器码。
- **垃圾回收 (Garbage Collection):**  回收不再使用的内存。
- **处理异步操作:**  例如 `setTimeout`, `setInterval`, `fetch` 等。

`v8threads.cc` 中定义的机制确保了当这些内部线程需要访问和修改 JavaScript 堆、执行 JavaScript 代码或与 V8 的其他内部组件交互时，操作是线程安全的。

**JavaScript 示例：**

虽然你不能直接在 JavaScript 代码中操作 `Locker` 和 `Unlocker` 类（因为它们是 C++ 的实现细节），但它们的存在和功能直接影响了 JavaScript 的并发模型和行为。

考虑以下 JavaScript 代码：

```javascript
let counter = 0;

function incrementCounter() {
  for (let i = 0; i < 100000; i++) {
    counter++;
  }
}

// 模拟并发执行
setTimeout(incrementCounter, 0);
setTimeout(incrementCounter, 0);

// 等待一段时间，期望两个 incrementCounter 完成
setTimeout(() => {
  console.log("Counter value:", counter);
}, 100);
```

在这个例子中，我们使用了 `setTimeout` 来模拟两个“并发”执行的 `incrementCounter` 函数。  虽然 JavaScript 引擎（V8）是单线程执行 JavaScript 代码的，但 `setTimeout` 的回调函数会被放入事件循环队列，并且可能会在不同的时间点被执行。

**`v8threads.cc` 的作用体现在以下方面：**

1. **内部线程安全:**  当 `setTimeout` 的回调函数被执行时，V8 引擎的内部线程（例如处理事件循环的线程）可能需要访问和修改 JavaScript 的堆内存来执行 `counter++` 操作。 `Locker` 和 `Unlocker` 确保了在多线程访问共享的 JavaScript 堆时不会发生数据竞争。 例如，当一个线程正在执行 `counter++` 时（涉及到读取 `counter` 的值，加 1，然后写回），V8 内部会使用锁机制来防止另一个线程同时修改 `counter`，从而保证最终 `counter` 的值是正确的（尽管在没有锁的情况下，可能会出现丢失更新的情况）。

2. **异步操作处理:**  `setTimeout` 本身就是一个异步操作，V8 内部会使用线程来管理这些异步任务。 `v8threads.cc` 中的机制确保了当这些异步操作的结果（例如网络请求的响应）需要返回到 JavaScript 环境并修改 JavaScript 对象时，操作是线程安全的。

**更贴近 C++ API 的例子（在 V8 嵌入场景中）：**

如果你是在一个 C++ 应用中嵌入 V8 引擎，并使用多个原生线程与 V8 交互，那么你会显式地使用 `Locker` 和 `Unlocker`：

```c++
#include <v8.h>
#include <iostream>
#include <thread>

void worker_thread(v8::Isolate* isolate) {
  v8::Locker locker(isolate); // 获取锁
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope context_scope(context);

  // 在这里安全地操作 V8 Isolate
  v8::Local<v8::String> source =
      v8::String::NewFromUtf8(isolate, "console.log('Hello from worker thread!');",
                             v8::NewStringType::kNormal)
          .ToLocalChecked();
  v8::Local<v8::Script> script =
      v8::Script::Compile(context, source).ToLocalChecked();
  script->Run(context);
}

int main() {
  v8::V8::InitializeICUDefaultLocation("");
  v8::V8::InitializeExternalStartupData("");
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  std::thread t1(worker_thread, isolate);
  std::thread t2(worker_thread, isolate);

  t1.join();
  t2.join();

  isolate->Dispose();
  delete create_params.array_buffer_allocator;
  v8::V8::Dispose();
  v8::V8::ShutdownPlatform();
  return 0;
}
```

在这个 C++ 示例中，我们创建了两个线程 `t1` 和 `t2`，它们都尝试在同一个 `v8::Isolate` 上执行 JavaScript 代码。  `v8::Locker locker(isolate);` 这行代码确保了在 `worker_thread` 函数中，只有当前线程拥有对 `isolate` 的访问权，避免了并发访问可能导致的问题。

总而言之，`v8threads.cc` 定义了 V8 引擎内部用于管理线程和提供线程安全的关键机制，这些机制对于保证 JavaScript 代码在多线程环境中的正确执行至关重要，尤其是在 V8 内部线程处理异步操作和垃圾回收时，以及在嵌入 V8 的 C++ 应用中进行多线程编程时。

Prompt: 
```
这是目录为v8/src/execution/v8threads.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/v8threads.h"

#include "include/v8-locker.h"
#include "src/api/api.h"
#include "src/debug/debug.h"
#include "src/execution/execution.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/stack-guard.h"
#include "src/init/bootstrapper.h"
#include "src/objects/visitors.h"
#include "src/regexp/regexp-stack.h"

namespace v8 {

namespace {

// Track whether this V8 instance has ever called v8::Locker. This allows the
// API code to verify that the lock is always held when V8 is being entered.
base::AtomicWord g_locker_was_ever_used_ = 0;

}  // namespace

// Once the Locker is initialized, the current thread will be guaranteed to have
// the lock for a given isolate.
void Locker::Initialize(v8::Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);
  has_lock_ = false;
  top_level_ = true;
  isolate_ = reinterpret_cast<i::Isolate*>(isolate);

  // Record that the Locker has been used at least once.
  base::Relaxed_Store(&g_locker_was_ever_used_, 1);
  isolate_->set_was_locker_ever_used();

  // Get the big lock if necessary.
  if (!isolate_->thread_manager()->IsLockedByCurrentThread()) {
    isolate_->thread_manager()->Lock();
    has_lock_ = true;

    // This may be a locker within an unlocker in which case we have to
    // get the saved state for this thread and restore it.
    if (isolate_->thread_manager()->RestoreThread()) {
      top_level_ = false;
    }
  }
  DCHECK(isolate_->thread_manager()->IsLockedByCurrentThread());
}

bool Locker::IsLocked(v8::Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  return i_isolate->thread_manager()->IsLockedByCurrentThread();
}

Locker::~Locker() {
  DCHECK(isolate_->thread_manager()->IsLockedByCurrentThread());
  if (has_lock_) {
    if (top_level_) {
      isolate_->thread_manager()->FreeThreadResources();
    } else {
      isolate_->thread_manager()->ArchiveThread();
    }
    isolate_->thread_manager()->Unlock();
  }
}

void Unlocker::Initialize(v8::Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);
  isolate_ = reinterpret_cast<i::Isolate*>(isolate);
  DCHECK(isolate_->thread_manager()->IsLockedByCurrentThread());
  isolate_->thread_manager()->ArchiveThread();
  isolate_->thread_manager()->Unlock();
}

Unlocker::~Unlocker() {
  DCHECK(!isolate_->thread_manager()->IsLockedByCurrentThread());
  isolate_->thread_manager()->Lock();
  isolate_->thread_manager()->RestoreThread();
}

namespace internal {

void ThreadManager::InitThread(const ExecutionAccess& lock) {
  isolate_->InitializeThreadLocal();
  isolate_->stack_guard()->InitThread(lock);
  isolate_->debug()->InitThread(lock);
}

bool ThreadManager::RestoreThread() {
  DCHECK(IsLockedByCurrentThread());
  // First check whether the current thread has been 'lazily archived', i.e.
  // not archived at all.  If that is the case we put the state storage we
  // had prepared back in the free list, since we didn't need it after all.
  if (lazily_archived_thread_ == ThreadId::Current()) {
    lazily_archived_thread_ = ThreadId::Invalid();
    Isolate::PerIsolateThreadData* per_thread =
        isolate_->FindPerThreadDataForThisThread();
    DCHECK_NOT_NULL(per_thread);
    DCHECK(per_thread->thread_state() == lazily_archived_thread_state_);
    lazily_archived_thread_state_->set_id(ThreadId::Invalid());
    lazily_archived_thread_state_->LinkInto(ThreadState::FREE_LIST);
    lazily_archived_thread_state_ = nullptr;
    per_thread->set_thread_state(nullptr);
    return true;
  }

  // Make sure that the preemption thread cannot modify the thread state while
  // it is being archived or restored.
  ExecutionAccess access(isolate_);

  // If there is another thread that was lazily archived then we have to really
  // archive it now.
  if (lazily_archived_thread_.IsValid()) {
    EagerlyArchiveThread();
  }
  Isolate::PerIsolateThreadData* per_thread =
      isolate_->FindPerThreadDataForThisThread();
  if (per_thread == nullptr || per_thread->thread_state() == nullptr) {
    // This is a new thread.
    InitThread(access);
    return false;
  }
  // In case multi-cage pointer compression mode is enabled ensure that
  // current thread's cage base values are properly initialized.
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate_);

  ThreadState* state = per_thread->thread_state();
  char* from = state->data();
  from = isolate_->handle_scope_implementer()->RestoreThread(from);
  from = isolate_->RestoreThread(from);
  from = Relocatable::RestoreState(isolate_, from);
  // Stack guard should be restored before Debug, etc. since Debug etc. might
  // depend on a correct stack guard.
  from = isolate_->stack_guard()->RestoreStackGuard(from);
  from = isolate_->debug()->RestoreDebug(from);
  from = isolate_->regexp_stack()->RestoreStack(from);
  from = isolate_->bootstrapper()->RestoreState(from);
  per_thread->set_thread_state(nullptr);
  state->set_id(ThreadId::Invalid());
  state->Unlink();
  state->LinkInto(ThreadState::FREE_LIST);
  return true;
}

void ThreadManager::Lock() {
  mutex_.Lock();
  mutex_owner_.store(ThreadId::Current(), std::memory_order_relaxed);
  DCHECK(IsLockedByCurrentThread());
}

void ThreadManager::Unlock() {
  mutex_owner_.store(ThreadId::Invalid(), std::memory_order_relaxed);
  mutex_.Unlock();
}

static int ArchiveSpacePerThread() {
  return HandleScopeImplementer::ArchiveSpacePerThread() +
         Isolate::ArchiveSpacePerThread() + Debug::ArchiveSpacePerThread() +
         StackGuard::ArchiveSpacePerThread() +
         RegExpStack::ArchiveSpacePerThread() +
         Bootstrapper::ArchiveSpacePerThread() +
         Relocatable::ArchiveSpacePerThread();
}

ThreadState::ThreadState(ThreadManager* thread_manager)
    : id_(ThreadId::Invalid()),
      data_(nullptr),
      next_(this),
      previous_(this),
      thread_manager_(thread_manager) {}

ThreadState::~ThreadState() { DeleteArray<char>(data_); }

void ThreadState::AllocateSpace() {
  data_ = NewArray<char>(ArchiveSpacePerThread());
}

void ThreadState::Unlink() {
  next_->previous_ = previous_;
  previous_->next_ = next_;
}

void ThreadState::LinkInto(List list) {
  ThreadState* flying_anchor = list == FREE_LIST
                                   ? thread_manager_->free_anchor_
                                   : thread_manager_->in_use_anchor_;
  next_ = flying_anchor->next_;
  previous_ = flying_anchor;
  flying_anchor->next_ = this;
  next_->previous_ = this;
}

ThreadState* ThreadManager::GetFreeThreadState() {
  ThreadState* gotten = free_anchor_->next_;
  if (gotten == free_anchor_) {
    ThreadState* new_thread_state = new ThreadState(this);
    new_thread_state->AllocateSpace();
    return new_thread_state;
  }
  return gotten;
}

// Gets the first in the list of archived threads.
ThreadState* ThreadManager::FirstThreadStateInUse() {
  return in_use_anchor_->Next();
}

ThreadState* ThreadState::Next() {
  if (next_ == thread_manager_->in_use_anchor_) return nullptr;
  return next_;
}

// Thread ids must start with 1, because in TLS having thread id 0 can't
// be distinguished from not having a thread id at all (since NULL is
// defined as 0.)
ThreadManager::ThreadManager(Isolate* isolate)
    : mutex_owner_(ThreadId::Invalid()),
      lazily_archived_thread_(ThreadId::Invalid()),
      lazily_archived_thread_state_(nullptr),
      free_anchor_(nullptr),
      in_use_anchor_(nullptr),
      isolate_(isolate) {
  free_anchor_ = new ThreadState(this);
  in_use_anchor_ = new ThreadState(this);
}

ThreadManager::~ThreadManager() {
  DeleteThreadStateList(free_anchor_);
  DeleteThreadStateList(in_use_anchor_);
}

void ThreadManager::DeleteThreadStateList(ThreadState* anchor) {
  // The list starts and ends with the anchor.
  for (ThreadState* current = anchor->next_; current != anchor;) {
    ThreadState* next = current->next_;
    delete current;
    current = next;
  }
  delete anchor;
}

void ThreadManager::ArchiveThread() {
  DCHECK_EQ(lazily_archived_thread_, ThreadId::Invalid());
  DCHECK(!IsArchived());
  DCHECK(IsLockedByCurrentThread());
  ThreadState* state = GetFreeThreadState();
  state->Unlink();
  Isolate::PerIsolateThreadData* per_thread =
      isolate_->FindOrAllocatePerThreadDataForThisThread();
  per_thread->set_thread_state(state);
  lazily_archived_thread_ = ThreadId::Current();
  lazily_archived_thread_state_ = state;
  DCHECK_EQ(state->id(), ThreadId::Invalid());
  state->set_id(CurrentId());
  DCHECK_NE(state->id(), ThreadId::Invalid());
}

void ThreadManager::EagerlyArchiveThread() {
  DCHECK(IsLockedByCurrentThread());
  ThreadState* state = lazily_archived_thread_state_;
  state->LinkInto(ThreadState::IN_USE_LIST);
  char* to = state->data();
  // Ensure that data containing GC roots are archived first, and handle them
  // in ThreadManager::Iterate(RootVisitor*).
  to = isolate_->handle_scope_implementer()->ArchiveThread(to);
  to = isolate_->ArchiveThread(to);
  to = Relocatable::ArchiveState(isolate_, to);
  to = isolate_->stack_guard()->ArchiveStackGuard(to);
  to = isolate_->debug()->ArchiveDebug(to);
  to = isolate_->regexp_stack()->ArchiveStack(to);
  to = isolate_->bootstrapper()->ArchiveState(to);
  lazily_archived_thread_ = ThreadId::Invalid();
  lazily_archived_thread_state_ = nullptr;
}

void ThreadManager::FreeThreadResources() {
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate_);
#endif  // DEBUG
  DCHECK(!isolate_->has_exception());
  DCHECK_NULL(isolate_->try_catch_handler());
  isolate_->handle_scope_implementer()->FreeThreadResources();
  isolate_->FreeThreadResources();
  isolate_->debug()->FreeThreadResources();
  isolate_->stack_guard()->FreeThreadResources();
  isolate_->regexp_stack()->FreeThreadResources();
  isolate_->bootstrapper()->FreeThreadResources();
}

bool ThreadManager::IsArchived() {
  Isolate::PerIsolateThreadData* data =
      isolate_->FindPerThreadDataForThisThread();
  return data != nullptr && data->thread_state() != nullptr;
}

void ThreadManager::Iterate(RootVisitor* v) {
  // Expecting no threads during serialization/deserialization
  for (ThreadState* state = FirstThreadStateInUse(); state != nullptr;
       state = state->Next()) {
    char* data = state->data();
    data = HandleScopeImplementer::Iterate(v, data);
    data = isolate_->Iterate(v, data);
    data = Relocatable::Iterate(v, data);
    data = StackGuard::Iterate(v, data);
    data = Debug::Iterate(v, data);
  }
}

void ThreadManager::IterateArchivedThreads(ThreadVisitor* v) {
  for (ThreadState* state = FirstThreadStateInUse(); state != nullptr;
       state = state->Next()) {
    char* data = state->data();
    data += HandleScopeImplementer::ArchiveSpacePerThread();
    isolate_->IterateThread(v, data);
  }
}

ThreadId ThreadManager::CurrentId() { return ThreadId::Current(); }

}  // namespace internal
}  // namespace v8

"""

```