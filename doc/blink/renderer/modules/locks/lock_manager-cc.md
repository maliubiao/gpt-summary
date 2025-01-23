Response:
Let's break down the thought process for analyzing the provided `lock_manager.cc` file.

**1. Initial Understanding - What is this file about?**

The file path `blink/renderer/modules/locks/lock_manager.cc` immediately tells us this is part of the Blink rendering engine, specifically the module responsible for implementing the Web Locks API. The name "lock_manager" strongly suggests its core function is managing lock requests and their lifecycle.

**2. Core Functionality - What does the code *do*?**

I'll read through the code, focusing on the key classes and methods.

*   **`LockManager` class:** This is the central class. It likely handles incoming lock requests from JavaScript. I see methods like `request()`, `query()`, `AddPendingRequest()`, `RemovePendingRequest()`, etc. These hint at the core management tasks.
*   **`LockRequestImpl` class:** This looks like an internal class representing a single lock request. It interacts with Mojo (inter-process communication in Chromium) through `mojom::blink::LockRequest`. It also manages the promise associated with the request and callbacks.
*   **Mojo Interfaces (`mojom::blink::LockManager`, `mojom::blink::LockRequest`, `mojom::blink::LockHandle`, `mojom::blink::ObservedFeature`):** These indicate communication with other parts of the browser process responsible for the actual lock acquisition and management.
*   **Promises and Callbacks:**  The use of `ScriptPromiseResolver` and `V8LockGrantedCallback` indicates the asynchronous nature of the Web Locks API and how results are returned to JavaScript.
*   **`Lock` class:** This represents an acquired lock. It seems to hold the Mojo handle and manage its release.
*   **`LockManagerSnapshot` class:**  This appears to be a data structure used for the `query()` method, providing a snapshot of the current lock state.
*   **AbortSignal Integration:** The code explicitly handles `AbortSignal`, allowing JavaScript to cancel lock requests.

**3. Relationship with JavaScript, HTML, and CSS:**

*   **JavaScript:** The `request()` and `query()` methods are clearly the entry points for JavaScript code to interact with the lock manager. The use of `ScriptState`, `ScriptPromise`, and callbacks confirms this. The parameters of `request()` (`name`, `options`, `callback`) map directly to the Web Locks API usage in JavaScript.
*   **HTML:** The Web Locks API is a JavaScript API, so its connection to HTML is through the `<script>` tag where the JavaScript is executed. Specific HTML elements don't directly trigger lock manager functionality.
*   **CSS:**  CSS has no direct relationship with the Web Locks API. Locking is about managing concurrent access to resources, which is independent of styling.

**4. Logical Reasoning - Hypothetical Scenarios:**

I'll think about simple use cases and trace the flow:

*   **Scenario 1: Basic Lock Request:**
    *   **Input (JavaScript):** `navigator.locks.request('my_resource', () => { /* do something */ });`
    *   **Output (Internal):** A `LockRequestImpl` is created, communicating with the browser process to request the lock. If granted, the callback is executed. If not, the promise might reject, or the callback might be called with `undefined` if `ifAvailable` is used.
*   **Scenario 2: Lock Request with AbortSignal:**
    *   **Input (JavaScript):** `const controller = new AbortController(); navigator.locks.request('my_resource', { signal: controller.signal }, () => { /* ... */ }); controller.abort();`
    *   **Output (Internal):**  The `LockRequestImpl` is associated with the `AbortSignal`. When `abort()` is called, the `Abort()` method in `LockRequestImpl` is triggered, rejecting the promise.
*   **Scenario 3: Querying Locks:**
    *   **Input (JavaScript):** `navigator.locks.query().then(snapshot => { console.log(snapshot); });`
    *   **Output (Internal):** The `query()` method triggers a request to the browser process to get the current lock state. This state is then formatted into a `LockManagerSnapshot` and returned to the JavaScript promise.

**5. Common User/Programming Errors:**

I'll consider how a developer might misuse the API:

*   **Requesting a lock with a hyphen as the first character:** The code explicitly checks for this and throws a `NotSupportedError`.
*   **Using `steal` and `ifAvailable` together:**  The code prevents this combination.
*   **Using `steal` with a shared lock:** The code enforces that `steal` can only be used with exclusive locks.
*   **Using `signal` with `steal` or `ifAvailable`:** These combinations are disallowed.
*   **Calling `request()` after the document is inactive:** The code checks the execution context and throws an error.

**6. Debugging Clues - How to Reach this Code:**

To debug code within `lock_manager.cc`, a developer would typically:

1. **Identify the JavaScript code:** Find the specific call to `navigator.locks.request()` or `navigator.locks.query()` that's causing the issue.
2. **Set breakpoints:** Use browser developer tools to set breakpoints in the JavaScript code.
3. **Step through the JavaScript:**  Observe the values of variables and the execution flow.
4. **"Step into" the browser internals:**  Chrome DevTools allows stepping into browser source code if source maps are available (or by manually navigating). The breakpoint in the JavaScript call to `navigator.locks.request()` would eventually lead into the Blink implementation, including `LockManager::request()`.
5. **Set breakpoints in C++:**  Use a debugger (like gdb or lldb) attached to the Chrome renderer process to set breakpoints within `lock_manager.cc`. This allows inspection of the internal state and the flow of execution within Blink.
6. **Examine Mojo messages:**  Tools like `chrome://tracing` can be used to examine the Mojo messages being passed between the renderer process and the browser process related to lock requests.

**Self-Correction/Refinement:**

During this process, I might realize some initial assumptions were slightly off. For example,  I initially might not have fully grasped the role of the `LockRequestImpl` and how it manages the lifetime of a request. By carefully reading the code and seeing its interaction with Mojo and promises, I'd refine my understanding. I'd also pay close attention to error handling and the specific DOMExceptions being thrown, as these are key to understanding the API's constraints. The comments in the code are also valuable for clarifying the purpose of specific sections.
好的，我们来分析一下 `blink/renderer/modules/locks/lock_manager.cc` 这个文件。

**文件功能概述:**

`lock_manager.cc` 文件是 Chromium Blink 引擎中实现 Web Locks API 的核心部分。它的主要功能是：

1. **接收和管理来自 JavaScript 的锁请求：**  当 JavaScript 代码调用 `navigator.locks.request()` 方法时，这个文件中的代码会被执行，处理锁的请求。
2. **与浏览器进程通信：** 它通过 Mojo IPC 与浏览器进程通信，实际的锁管理逻辑可能在浏览器进程中实现。
3. **维护待处理的锁请求队列：**  记录当前正在等待锁释放的请求。
4. **管理已授予的锁：**  跟踪当前已被授予的锁。
5. **处理锁的授予和拒绝：** 当锁可以被授予时，通知 JavaScript 代码；如果锁无法获取，也需要告知。
6. **处理锁的释放：** 当锁被持有者释放时，将锁标记为可用，并可能授予等待队列中的下一个请求。
7. **实现 `navigator.locks.query()` 方法：**  允许 JavaScript 查询当前锁的状态（哪些锁正在等待，哪些锁被持有）。
8. **与 `AbortSignal` 集成：** 允许 JavaScript 使用 `AbortSignal` 来取消未完成的锁请求。
9. **进行安全性检查：**  例如，检查当前上下文是否有权限访问 Locks API。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **与 JavaScript 的关系最为密切：**  `LockManager` 是 Web Locks API 在 Blink 渲染引擎中的实现核心，它直接响应 JavaScript 的 `navigator.locks` 对象上的 `request` 和 `query` 方法调用。

    *   **举例：**
        ```javascript
        // JavaScript 代码请求一个名为 'my-resource' 的独占锁
        navigator.locks.request('my-resource', async lock => {
          console.log('获得锁');
          // 在这里执行需要持有锁的操作
          await new Promise(resolve => setTimeout(resolve, 2000)); // 模拟持有锁一段时间
          console.log('释放锁');
        });
        ```
        当上述 JavaScript 代码执行时，Blink 引擎会调用 `LockManager::request` 方法，将锁的名称 `'my-resource'` 和回调函数传递给 C++ 代码进行处理。`LockManager` 会与浏览器进程通信，请求获取该锁。如果锁被成功获取，JavaScript 中传入的回调函数会被执行，并传入一个 `Lock` 对象作为参数。

*   **与 HTML 的关系：**  Web Locks API 是一个 JavaScript API，所以它通过在 HTML 文件中嵌入的 `<script>` 标签内的 JavaScript 代码来使用。HTML 结构本身并不直接参与锁的管理。

    *   **举例：**
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>Web Locks Example</title>
        </head>
        <body>
          <script>
            navigator.locks.request('data-update', () => {
              console.log('执行数据更新操作');
            });
          </script>
        </body>
        </html>
        ```
        在这个 HTML 文件加载时，嵌入的 JavaScript 代码会尝试获取一个名为 `'data-update'` 的锁。

*   **与 CSS 的关系：**  CSS 样式与 Web Locks API 没有直接关系。CSS 负责页面的视觉呈现，而 Web Locks API 负责管理并发访问资源。

**逻辑推理及假设输入与输出:**

假设我们有以下 JavaScript 代码：

```javascript
navigator.locks.request('counter', lock => {
  console.log('counter 锁被持有');
  return new Promise(resolve => setTimeout(resolve, 1000));
});

navigator.locks.request('counter', lock => {
  console.log('第二个 counter 锁被持有');
});
```

**假设输入：**

1. 两个连续的 JavaScript 代码片段，都尝试请求名为 `'counter'` 的独占锁。

**逻辑推理：**

1. 第一个 `request` 调用会创建一个 `LockRequestImpl` 对象，并发送锁请求给浏览器进程。
2. 由于是第一个请求，且假设锁当前未被持有，浏览器进程可能会立即授予该锁。
3. 第一个 `request` 的回调函数被执行，打印 "counter 锁被持有"。
4. 回调函数返回一个 Promise，该 Promise 在 1 秒后 resolve。这意味着第一个锁会持有至少 1 秒。
5. 在第一个锁仍然持有的情况下，第二个 `request` 调用会创建另一个 `LockRequestImpl` 对象，并发送锁请求。
6. 由于锁 `'counter'` 已经被持有，第二个请求会被放入等待队列中。
7. 1 秒后，第一个 `request` 的回调函数返回的 Promise resolve，隐式地释放了第一个锁。
8. 浏览器进程发现锁 `'counter'` 被释放，会检查等待队列，并将锁授予第二个请求。
9. 第二个 `request` 的回调函数被执行，打印 "第二个 counter 锁被持有"。

**假设输出（Console）：**

```
counter 锁被持有
(等待 1 秒)
第二个 counter 锁被持有
```

**用户或编程常见的使用错误及举例说明:**

1. **忘记释放锁：** 如果在 `navigator.locks.request` 的回调函数中没有正确地管理锁的生命周期（例如，返回一个永远不会 resolve 的 Promise，或者在同步代码中持有锁过长时间），会导致其他请求一直处于等待状态，造成死锁或性能问题。

    ```javascript
    // 错误示例：忘记释放锁
    navigator.locks.request('resource', () => {
      console.log('获得锁，但永远不释放');
      // 没有返回 Promise，或者 Promise 永远不 resolve
      while (true) {
        // 忙等待，阻塞其他锁请求
      }
    });
    ```

2. **请求名称以 `-` 开头的锁：**  代码中明确禁止锁的名称以 `-` 开头。

    ```javascript
    // 错误示例：锁名称以 '-' 开头
    navigator.locks.request('-invalid-name', () => {
      console.log('不会执行');
    });
    ```
    这会导致抛出一个 `NotSupportedError` 异常。

3. **同时使用 `steal` 和 `ifAvailable` 选项：**  这两个选项是互斥的。

    ```javascript
    // 错误示例：同时使用 steal 和 ifAvailable
    navigator.locks.request('resource', { steal: true, ifAvailable: true }, () => {});
    ```
    这会导致抛出一个 `NotSupportedError` 异常。

4. **在不合适的上下文中使用 Locks API：** 例如，在不支持 Locks API 的环境中或者在没有足够权限的上下文中使用。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户与网页交互：** 用户在浏览器中打开一个网页，该网页包含使用 Web Locks API 的 JavaScript 代码。
2. **JavaScript 代码执行：**  当网页加载或用户执行某些操作（例如点击按钮）时，JavaScript 代码被执行。
3. **调用 `navigator.locks.request()` 或 `navigator.locks.query()`：**  JavaScript 代码尝试获取或查询锁的状态。
4. **Blink 引擎接收请求：**  浏览器引擎（Blink）接收到来自 JavaScript 的锁请求。具体来说，会调用 `blink/renderer/modules/locks/lock_manager.cc` 文件中的 `LockManager::request()` 或 `LockManager::query()` 方法。
5. **Mojo 消息传递：** `LockManager` 类会使用 Mojo 将请求发送到浏览器进程中的锁服务。
6. **浏览器进程处理：** 浏览器进程中的锁服务根据当前锁的状态和请求的类型，决定是否授予锁。
7. **结果返回：** 浏览器进程通过 Mojo 将锁的授予或拒绝信息返回给渲染进程的 `LockManager`。
8. **回调执行或 Promise resolve/reject：** `LockManager` 根据浏览器进程的返回结果，执行 JavaScript 中 `navigator.locks.request()` 提供的回调函数，或者 resolve/reject `navigator.locks.query()` 返回的 Promise。

**调试线索：**

*   **在 JavaScript 代码中设置断点：**  在调用 `navigator.locks.request()` 或 `navigator.locks.query()` 的地方设置断点，查看参数和执行流程。
*   **在 `lock_manager.cc` 中设置断点：**  如果怀疑是 Blink 引擎内部逻辑问题，可以在 `LockManager::request()`、`LockManager::query()` 以及相关的处理函数中设置断点，例如 `LockRequestImpl::Granted()`、`LockRequestImpl::Failed()` 等。
*   **查看控制台输出：**  使用 `console.log()` 输出关键变量的值，例如锁的名称、请求的模式等。
*   **使用 Chrome 的 `chrome://webrtc-internals` 或 `chrome://tracing`：**  虽然这些工具主要用于 WebRTC 和通用性能跟踪，但有时候可以帮助理解跨进程的交互，尽管 Web Locks 的具体信息可能不会直接显示。更相关的可能是用于观察 Mojo 消息的工具（如果存在）。
*   **检查异常信息：**  查看 JavaScript 控制台是否有关于 Locks API 的异常抛出，例如 `NotSupportedError` 或 `SecurityError`。

总而言之，`blink/renderer/modules/locks/lock_manager.cc` 是 Blink 引擎中 Web Locks API 的核心实现，负责协调 JavaScript 的锁请求，与浏览器进程通信，并管理锁的生命周期。理解这个文件的工作原理对于调试和理解 Web Locks API 的行为至关重要。

### 提示词
```
这是目录为blink/renderer/modules/locks/lock_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/locks/lock_manager.h"

#include <algorithm>
#include <utility>

#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_lock_granted_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_lock_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_lock_manager_snapshot.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/modules/locks/lock.h"
#include "third_party/blink/renderer/modules/shared_storage/shared_storage_worklet_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/name_client.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_associated_receiver.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/scheduling_policy.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

constexpr char kSecurityErrorMessage[] = "The request was denied.";
constexpr char kInvalidStateErrorMessage[] = "The document is not active.";

LockInfo* ToLockInfo(const mojom::blink::LockInfoPtr& record) {
  LockInfo* info = LockInfo::Create();
  info->setMode(Lock::ModeToEnum(record->mode));
  info->setName(record->name);
  info->setClientId(record->client_id);
  return info;
}

HeapVector<Member<LockInfo>> ToLockInfos(
    const Vector<mojom::blink::LockInfoPtr>& records) {
  HeapVector<Member<LockInfo>> out;
  out.ReserveInitialCapacity(records.size());
  for (const auto& record : records)
    out.push_back(ToLockInfo(record));
  return out;
}

}  // namespace

class LockManager::LockRequestImpl final
    : public GarbageCollected<LockRequestImpl>,
      public NameClient,
      public mojom::blink::LockRequest {
 public:
  LockRequestImpl(
      V8LockGrantedCallback* callback,
      ScriptPromiseResolver<IDLAny>* resolver,
      const String& name,
      mojom::blink::LockMode mode,
      mojo::PendingAssociatedReceiver<mojom::blink::LockRequest> receiver,
      mojo::PendingRemote<mojom::blink::ObservedFeature> lock_lifetime,
      LockManager* manager)
      : callback_(callback),
        resolver_(resolver),
        name_(name),
        mode_(mode),
        receiver_(this, manager->GetExecutionContext()),
        lock_lifetime_(std::move(lock_lifetime)),
        manager_(manager) {
    receiver_.Bind(
        std::move(receiver),
        manager->GetExecutionContext()->GetTaskRunner(TaskType::kWebLocks));
  }

  LockRequestImpl(const LockRequestImpl&) = delete;
  LockRequestImpl& operator=(const LockRequestImpl&) = delete;

  ~LockRequestImpl() override = default;

  void Trace(Visitor* visitor) const {
    visitor->Trace(resolver_);
    visitor->Trace(manager_);
    visitor->Trace(callback_);
    visitor->Trace(receiver_);
    visitor->Trace(abort_handle_);
  }

  const char* NameInHeapSnapshot() const override {
    return "LockManager::LockRequestImpl";
  }

  // Called to immediately close the pipe which signals the back-end,
  // unblocking further requests, without waiting for GC finalize the object.
  void Cancel() { receiver_.reset(); }

  void InitializeAbortAlgorithm(AbortSignal::AlgorithmHandle& handle) {
    DCHECK(!abort_handle_);
    abort_handle_ = &handle;
  }

  void Abort(AbortSignal* signal) {
    // Abort signal after acquisition should be ignored.
    if (!manager_->IsPendingRequest(this)) {
      return;
    }

    manager_->RemovePendingRequest(this);
    receiver_.reset();
    abort_handle_.Clear();

    DCHECK(resolver_);

    ScriptState* const script_state = resolver_->GetScriptState();

    if (!IsInParallelAlgorithmRunnable(resolver_->GetExecutionContext(),
                                       script_state)) {
      return;
    }

    ScriptState::Scope script_state_scope(script_state);

    resolver_->Reject(signal->reason(script_state));
  }

  void Failed() override {
    auto* callback = callback_.Release();

    manager_->RemovePendingRequest(this);
    receiver_.reset();
    abort_handle_.Clear();

    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid())
      return;

    // Lock was not granted e.g. because ifAvailable was specified but
    // the lock was not available.
    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    v8::Maybe<ScriptValue> result = callback->Invoke(nullptr, nullptr);
    if (try_catch.HasCaught()) {
      resolver_->Reject(try_catch.Exception());
    } else if (!result.IsNothing()) {
      resolver_->Resolve(result.FromJust());
    }
  }

  void Granted(mojo::PendingAssociatedRemote<mojom::blink::LockHandle>
                   handle_remote) override {
    DCHECK(receiver_.is_bound());

    auto* callback = callback_.Release();

    manager_->RemovePendingRequest(this);
    receiver_.reset();
    abort_handle_.Clear();

    ScriptState* script_state = resolver_->GetScriptState();
    if (!script_state->ContextIsValid()) {
      // If a handle was returned, it will be automatically be released.
      return;
    }

    Lock* lock = MakeGarbageCollected<Lock>(
        script_state, name_, mode_, std::move(handle_remote),
        std::move(lock_lifetime_), manager_);
    manager_->held_locks_.insert(lock);

    // Note that either invoking `callback` or calling
    // ToResolvedPromise to convert the resulting value to a Promise
    // can or will execute javascript. This means that the ExecutionContext
    // could be synchronously destroyed, and the `lock` might be released before
    // HoldUntil is called. This is safe, as releasing a lock twice is harmless.
    ScriptState::Scope scope(script_state);
    v8::TryCatch try_catch(script_state->GetIsolate());
    v8::Maybe<ScriptValue> result = callback->Invoke(nullptr, lock);
    if (try_catch.HasCaught()) {
      lock->HoldUntil(
          ScriptPromise<IDLAny>::Reject(script_state, try_catch.Exception()),
          resolver_);
    } else if (!result.IsNothing()) {
      lock->HoldUntil(
          ToResolvedPromise<IDLAny>(script_state, result.FromJust()),
          resolver_);
    }
  }

 private:
  // Callback passed by script; invoked when the lock is granted.
  Member<V8LockGrantedCallback> callback_;

  // Rejects if the request was aborted, otherwise resolves/rejects with
  // |callback_|'s result.
  Member<ScriptPromiseResolver<IDLAny>> resolver_;

  // Held to stamp the Lock object's |name| property.
  String name_;

  // Held to stamp the Lock object's |mode| property.
  mojom::blink::LockMode mode_;

  HeapMojoAssociatedReceiver<mojom::blink::LockRequest, LockRequestImpl>
      receiver_;

  // Held to pass into the Lock if granted, to inform the browser that
  // WebLocks are being used by this frame.
  mojo::PendingRemote<mojom::blink::ObservedFeature> lock_lifetime_;

  // The |manager_| keeps |this| alive until a response comes in and this is
  // registered. If the context is destroyed then |manager_| will dispose of
  // |this| which terminates the request on the service side.
  Member<LockManager> manager_;

  // Handle that keeps the associated abort algorithm alive for the duration of
  // the request.
  Member<AbortSignal::AlgorithmHandle> abort_handle_;
};

const char LockManager::kSupplementName[] = "LockManager";

// static
LockManager* LockManager::locks(NavigatorBase& navigator) {
  auto* supplement = Supplement<NavigatorBase>::From<LockManager>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<LockManager>(navigator);
    Supplement<NavigatorBase>::ProvideTo(navigator, supplement);
  }
  return supplement;
}

LockManager::LockManager(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      ExecutionContextLifecycleObserver(navigator.GetExecutionContext()),
      service_(navigator.GetExecutionContext()),
      observer_(navigator.GetExecutionContext()) {}

void LockManager::SetManager(
    mojo::PendingRemote<mojom::blink::LockManager> manager,
    ExecutionContext* execution_context) {
  service_.Bind(std::move(manager),
                execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI));
}

ScriptPromise<IDLAny> LockManager::request(ScriptState* script_state,
                                           const String& name,
                                           V8LockGrantedCallback* callback,
                                           ExceptionState& exception_state) {
  return request(script_state, name, LockOptions::Create(), callback,
                 exception_state);
}

ScriptPromise<IDLAny> LockManager::request(ScriptState* script_state,
                                           const String& name,
                                           const LockOptions* options,
                                           V8LockGrantedCallback* callback,
                                           ExceptionState& exception_state) {
  // Observed context may be gone if frame is detached.
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInvalidStateErrorMessage);
    return EmptyPromise();
  }

  ExecutionContext* context = ExecutionContext::From(script_state);
  DCHECK(context->IsContextThread());

  context->GetScheduler()->RegisterStickyFeature(
      blink::SchedulingPolicy::Feature::kWebLocks,
      {blink::SchedulingPolicy::DisableBackForwardCache()});

  // 5. If origin is an opaque origin, then reject promise with a
  // "SecurityError" DOMException.
  //
  // TODO(crbug.com/373899208): It's safe to bypass the opaque origin check for
  // shared storage worklets. However, it'd be better to give shared storage
  // worklets the correct security origin to avoid bypassing this check.
  if (!context->GetSecurityOrigin()->CanAccessLocks() &&
      !context->IsSharedStorageWorkletGlobalScope()) {
    exception_state.ThrowSecurityError(
        "Access to the Locks API is denied in this context.");
    return EmptyPromise();
  }
  if (context->GetSecurityOrigin()->IsLocal()) {
    UseCounter::Count(context, WebFeature::kFileAccessedLocks);
  }

  mojom::blink::LockMode mode = Lock::EnumToMode(options->mode().AsEnum());

  // 6. Otherwise, if name starts with U+002D HYPHEN-MINUS (-), then reject
  // promise with a "NotSupportedError" DOMException.
  if (name.StartsWith("-")) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Names cannot start with '-'.");
    return EmptyPromise();
  }

  // 7. Otherwise, if both options’ steal dictionary member and option’s
  // ifAvailable dictionary member are true, then reject promise with a
  // "NotSupportedError" DOMException.
  if (options->steal() && options->ifAvailable()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The 'steal' and 'ifAvailable' options cannot be used together.");
    return EmptyPromise();
  }

  // 8. Otherwise, if options’ steal dictionary member is true and option’s mode
  // dictionary member is not "exclusive", then reject promise with a
  // "NotSupportedError" DOMException.
  if (options->steal() && mode != mojom::blink::LockMode::EXCLUSIVE) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The 'steal' option may only be used with 'exclusive' locks.");
    return EmptyPromise();
  }

  // 9. Otherwise, if option’s signal dictionary member is present, and either
  // of options’ steal dictionary member or options’ ifAvailable dictionary
  // member is true, then reject promise with a "NotSupportedError"
  // DOMException.
  if (options->hasSignal() && options->ifAvailable()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The 'signal' and 'ifAvailable' options cannot be used together.");
    return EmptyPromise();
  }
  if (options->hasSignal() && options->steal()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The 'signal' and 'steal' options cannot be used together.");
    return EmptyPromise();
  }

  // If options["signal"] exists and is aborted, then return a promise rejected
  // with options["signal"]'s abort reason.
  if (options->hasSignal() && options->signal()->aborted()) {
    return ScriptPromise<IDLAny>::Reject(
        script_state, options->signal()->reason(script_state));
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  CheckStorageAccessAllowed(
      context, resolver,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &LockManager::RequestImpl, WrapWeakPersistent(this),
          WrapPersistent(options), name, WrapPersistent(callback), mode)));

  // 12. Return promise.
  return promise;
}

void LockManager::RequestImpl(const LockOptions* options,
                              const String& name,
                              V8LockGrantedCallback* callback,
                              mojom::blink::LockMode mode,
                              ScriptPromiseResolver<IDLAny>* resolver) {
  ExecutionContext* context = resolver->GetExecutionContext();
  if (!service_.is_bound()) {
    context->GetBrowserInterfaceBroker().GetInterface(
        service_.BindNewPipeAndPassReceiver(
            context->GetTaskRunner(TaskType::kMiscPlatformAPI)));

    if (!service_.is_bound()) {
      resolver->RejectWithDOMException(DOMExceptionCode::kAbortError, "");
    }
  }
  if (!observer_.is_bound()) {
    context->GetBrowserInterfaceBroker().GetInterface(
        observer_.BindNewPipeAndPassReceiver(
            context->GetTaskRunner(TaskType::kMiscPlatformAPI)));

    if (!observer_.is_bound()) {
      resolver->RejectWithDOMException(DOMExceptionCode::kAbortError, "");
    }
  }

  mojom::blink::LockManager::WaitMode wait =
      options->steal()         ? mojom::blink::LockManager::WaitMode::PREEMPT
      : options->ifAvailable() ? mojom::blink::LockManager::WaitMode::NO_WAIT
                               : mojom::blink::LockManager::WaitMode::WAIT;

  mojo::PendingRemote<mojom::blink::ObservedFeature> lock_lifetime;
  observer_->Register(lock_lifetime.InitWithNewPipeAndPassReceiver(),
                      mojom::blink::ObservedFeatureType::kWebLock);

  mojo::PendingAssociatedRemote<mojom::blink::LockRequest> request_remote;

  // 11.1. Let request be the result of running the steps to request a lock with
  // promise, the current agent, environment’s id, origin, callback, name,
  // options’ mode dictionary member, options’ ifAvailable dictionary member,
  // and options’ steal dictionary member.
  LockRequestImpl* request = MakeGarbageCollected<LockRequestImpl>(
      callback, resolver, name, mode,
      request_remote.InitWithNewEndpointAndPassReceiver(),
      std::move(lock_lifetime), this);
  AddPendingRequest(request);

  // 11.2. If options’ signal dictionary member is present, then add the
  // following abort steps to options’ signal dictionary member:
  if (options->hasSignal()) {
    // In "Request a lock": If signal is present, then add the algorithm signal
    // to abort the request request with signal to signal.
    AbortSignal::AlgorithmHandle* handle = options->signal()->AddAlgorithm(
        WTF::BindOnce(&LockRequestImpl::Abort, WrapWeakPersistent(request),
                      WrapPersistent(options->signal())));
    request->InitializeAbortAlgorithm(*handle);
  }
  service_->RequestLock(name, mode, wait, std::move(request_remote));
}

ScriptPromise<LockManagerSnapshot> LockManager::query(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // Observed context may be gone if frame is detached.
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInvalidStateErrorMessage);
    return EmptyPromise();
  }
  ExecutionContext* context = ExecutionContext::From(script_state);
  DCHECK(context->IsContextThread());

  if (!context->GetSecurityOrigin()->CanAccessLocks()) {
    exception_state.ThrowSecurityError(
        "Access to the Locks API is denied in this context.");
    return EmptyPromise();
  }
  if (context->GetSecurityOrigin()->IsLocal()) {
    UseCounter::Count(context, WebFeature::kFileAccessedLocks);
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<LockManagerSnapshot>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  CheckStorageAccessAllowed(
      context, resolver,
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&LockManager::QueryImpl, WrapWeakPersistent(this))));
  return promise;
}

void LockManager::QueryImpl(
    ScriptPromiseResolver<LockManagerSnapshot>* resolver) {
  ExecutionContext* context = resolver->GetExecutionContext();
  if (!service_.is_bound()) {
    context->GetBrowserInterfaceBroker().GetInterface(
        service_.BindNewPipeAndPassReceiver(
            context->GetTaskRunner(TaskType::kMiscPlatformAPI)));

    if (!service_.is_bound()) {
      resolver->RejectWithDOMException(DOMExceptionCode::kAbortError, "");
    }
  }

  service_->QueryState(WTF::BindOnce(
      [](ScriptPromiseResolver<LockManagerSnapshot>* resolver,
         Vector<mojom::blink::LockInfoPtr> pending,
         Vector<mojom::blink::LockInfoPtr> held) {
        LockManagerSnapshot* snapshot = LockManagerSnapshot::Create();
        snapshot->setPending(ToLockInfos(pending));
        snapshot->setHeld(ToLockInfos(held));
        resolver->Resolve(snapshot);
      },
      WrapPersistent(resolver)));
}

void LockManager::AddPendingRequest(LockRequestImpl* request) {
  pending_requests_.insert(request);
}

void LockManager::RemovePendingRequest(LockRequestImpl* request) {
  pending_requests_.erase(request);
}

bool LockManager::IsPendingRequest(LockRequestImpl* request) {
  return pending_requests_.Contains(request);
}

void LockManager::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  visitor->Trace(pending_requests_);
  visitor->Trace(held_locks_);
  visitor->Trace(service_);
  visitor->Trace(observer_);
}

void LockManager::ContextDestroyed() {
  for (auto request : pending_requests_)
    request->Cancel();
  pending_requests_.clear();
  held_locks_.clear();
}

void LockManager::OnLockReleased(Lock* lock) {
  // Lock may be removed by an explicit call and/or when the context is
  // destroyed, so this must be idempotent.
  held_locks_.erase(lock);
}

void LockManager::CheckStorageAccessAllowed(
    ExecutionContext* context,
    ScriptPromiseResolverBase* resolver,
    base::OnceCallback<void()> callback) {
  DCHECK(context->IsWindow() || context->IsWorkerGlobalScope() ||
         context->IsSharedStorageWorkletGlobalScope());

  auto wrapped_callback = WTF::BindOnce(
      &LockManager::DidCheckStorageAccessAllowed, WrapWeakPersistent(this),
      WrapPersistent(resolver), std::move(callback));

  if (cached_allowed_.has_value()) {
    std::move(wrapped_callback).Run(cached_allowed_.value());
    return;
  }

  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    LocalFrame* frame = window->GetFrame();
    if (!frame) {
      std::move(wrapped_callback).Run(false);
      return;
    }
    frame->AllowStorageAccessAndNotify(
        WebContentSettingsClient::StorageType::kWebLocks,
        std::move(wrapped_callback));
  } else if (auto* worker_global_scope =
                 DynamicTo<WorkerGlobalScope>(context)) {
    WebContentSettingsClient* content_settings_client =
        worker_global_scope->ContentSettingsClient();
    if (!content_settings_client) {
      std::move(wrapped_callback).Run(true);
      return;
    }
    content_settings_client->AllowStorageAccess(
        WebContentSettingsClient::StorageType::kWebLocks,
        std::move(wrapped_callback));
  } else {
    // Shared storage always allows WebLocks as long as the
    // `SharedStorageWorkletGlobalScope` is allowed in the first place.
    //
    // TODO(crbug.com/373891801): A more generic way is to provide
    // `WebContentSettingsClient` to shared storage worklets.
    CHECK(context->IsSharedStorageWorkletGlobalScope());
    std::move(wrapped_callback).Run(true);
  }
}

void LockManager::DidCheckStorageAccessAllowed(
    ScriptPromiseResolverBase* resolver,
    base::OnceCallback<void()> callback,
    bool allow_access) {
  if (cached_allowed_.has_value()) {
    DCHECK_EQ(cached_allowed_.value(), allow_access);
  } else {
    cached_allowed_ = allow_access;
  }

  ScriptState* script_state = resolver->GetScriptState();

  if (!script_state->ContextIsValid()) {
    return;
  }

  if (cached_allowed_.value()) {
    std::move(callback).Run();
    return;
  }

  ScriptState::Scope scope(script_state);

  resolver->Reject(V8ThrowDOMException::CreateOrDie(
      script_state->GetIsolate(), DOMExceptionCode::kSecurityError,
      kSecurityErrorMessage));
}

}  // namespace blink
```