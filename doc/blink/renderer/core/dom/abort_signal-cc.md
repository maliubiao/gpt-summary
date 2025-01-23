Response:
Let's break down the thought process for analyzing the `abort_signal.cc` file. The goal is to understand its purpose, its relationships with other web technologies, and how it might be used or misused.

**1. Initial Skim and Keyword Recognition:**

First, I'd quickly scan the code for recognizable keywords and patterns. Things like:

* `#include`:  This tells us dependencies. Immediately, I see `AbortSignal.h` (its own header),  things related to time (`base/time/time.h`),  V8 integration (`bindings/core/v8`, `platform/bindings`), events (`core/dom/events/event.h`, `core/event_type_names.h`), and execution contexts. The `third_party/blink` namespace confirms this is Blink code.
* `class AbortSignal`: The core class we're investigating.
* `aborted()`, `abort_reason_`, `SignalAbort()`:  These strongly suggest the functionality is about signaling cancellation.
* `addEventListener`, `dispatchEvent`:  Indicates it's an `EventTarget` and participates in the event system.
* `timeout()`:  Clearly a time-based cancellation mechanism.
* `any()`:  Suggests combining multiple abort signals.
* `Algorithm`, `AlgorithmHandle`:  A pattern for executing code when the signal is aborted.
* `ExecutionContext`:  Ties it to the lifecycle of a JavaScript execution environment.
* `AbortSignalRegistry`, `AbortSignalCompositionManager`:  These hint at more complex internal management of abort signals.

**2. Understanding the Core Functionality - The "Why":**

Based on the keywords, the central function of `AbortSignal` is clear: to represent a signal that can be *aborted*, indicating that an ongoing operation should be cancelled. This is crucial for tasks like:

* **Network requests:**  Canceling a fetch.
* **Timers:**  Stopping a `setTimeout` or `setInterval`.
* **Animations:**  Interrupting an animation.
* **Long-running computations:**  Providing a way to stop them prematurely.

**3. Examining Key Methods and Their Implications:**

Now, I'd go through the main methods and try to understand their specific roles and how they relate to the overall purpose:

* **Constructors:** The different constructors reveal how `AbortSignal` instances are created:
    * Default: A composite signal (can be linked to others).
    * With `SignalType`:  A source signal (like one created by an `AbortController`).
    * With a list of other `AbortSignal`s (`any`):  A composite signal that aborts if *any* of its sources abort.
* **`abort()` (static):**  How to create an *already aborted* signal, either with a default reason or a provided one. This is useful for testing or immediate cancellation.
* **`timeout()` (static):**  Creates a signal that will automatically abort after a specified delay. The use of `PostDelayedTask` and different `TaskType` values highlights the integration with Blink's task scheduling.
* **`reason()`:**  Retrieves the reason for the abort, if any.
* **`throwIfAborted()`:**  A convenience method to immediately throw an exception if the signal is aborted. This is a common pattern for early cancellation.
* **`AddAlgorithm()`, `RemoveAlgorithm()`:**  The mechanism for registering functions to be called when the signal is aborted. This allows components to react to the abortion. The `OnceCallbackAlgorithm` is a specific implementation for one-time callbacks.
* **`SignalAbort()`:**  The *internal* method to trigger the abort process for a source signal. It manages propagating the abort to dependent signals and running the registered algorithms. The `SignalAbortPassKey` likely enforces that only the `AbortController` can call this directly.
* **`SetAbortReason()`:**  Sets the reason for the abort.
* **`RunAbortSteps()`:**  Executes the registered algorithms and dispatches the `abort` event.
* **Event Listener Methods (`AddedEventListener`, `RemovedEventListener`):**  Shows that `AbortSignal` is an `EventTarget` and dispatches `abort` events. The logic around `AbortSignalRegistry` for composite signals is important for managing the lifecycle of these signals based on event listeners.
* **`DetachFromController()`:**  Allows breaking the link between a signal and its controller, preventing further abortion.

**4. Connecting to JavaScript, HTML, and CSS:**

Now, I'd think about how these internal mechanisms manifest in web development:

* **JavaScript:** The primary interaction point. The `AbortController` API is directly tied to `AbortSignal`. Examples of `fetch`, `setTimeout`, `addEventListener` with `signal` options would be key.
* **HTML:** While not directly related, the actions initiated by JavaScript (like `fetch`) affect how HTML content is loaded and displayed. Canceling a fetch prevents resources from loading.
* **CSS:**  CSS animations and transitions can be tied to abort signals. For example, a JavaScript animation loop might stop if its associated `AbortSignal` is aborted.

**5. Identifying Potential User/Programming Errors:**

Based on the understanding of the API, I'd consider common mistakes:

* **Not checking `aborted`:**  Continuing operations even after the signal is aborted.
* **Not handling the `abort` event:**  Failing to clean up resources or update the UI when cancellation occurs.
* **Incorrectly using `throwIfAborted`:**  Using it in synchronous code where exceptions might not be handled properly.
* **Memory leaks with composite signals:**  If event listeners aren't properly removed or if the `AbortController` is not garbage collected.
* **Misunderstanding the `reason`:**  Not providing or handling the abort reason appropriately.

**6. Tracing User Actions to the Code:**

To understand how a user action leads to this code, I'd work backward:

* **User clicks "Cancel" on a file upload:** This triggers a JavaScript event handler.
* **The handler calls `abort()` on an `AbortController`:** This is the direct JavaScript API interaction.
* **Internally, the browser calls the `SignalAbort()` method in `abort_signal.cc`:** This is where the C++ implementation takes over.

**7. Logical Reasoning and Assumptions:**

When explaining the logic, I'd make assumptions explicit:

* **Assumption:** The `SignalAbortPassKey` mechanism ensures only trusted components (like the `AbortController`) can initiate the abort.
* **Assumption:** The `AbortSignalRegistry` is a central place to track composite signals and their listeners to manage their lifecycle.
* **Assumption:**  The `ExecutionContext` provides the necessary context for running tasks and accessing other browser features.

**8. Refinement and Organization:**

Finally, I'd organize the information logically, using clear headings and examples. The goal is to provide a comprehensive yet easy-to-understand explanation of the code's functionality and its role in the browser. The "功能 (Functions)," "与 Javascript, HTML, CSS 的关系 (Relationship with JS, HTML, CSS)," "逻辑推理 (Logical Reasoning)," "用户或编程常见的使用错误 (Common User/Programming Errors)," and "用户操作如何一步步的到达这里，作为调试线索 (How User Actions Lead Here)" structure provides a good framework for this.
好的，让我们来分析一下 `blink/renderer/core/dom/abort_signal.cc` 文件的功能。

**功能 (Functions):**

`abort_signal.cc` 文件实现了 `AbortSignal` 接口，该接口用于表示可以被中止的操作的信号。它提供了一种与异步操作（例如网络请求、定时器等）进行通信的机制，允许在操作进行过程中将其取消。

以下是 `AbortSignal` 的主要功能：

1. **表示中止状态:** `AbortSignal` 对象可以处于 "未中止" 或 "已中止" 状态。
2. **关联中止原因:**  当 `AbortSignal` 被中止时，可以关联一个原因，通常是一个 `DOMException` 对象，说明中止的原因。
3. **事件监听:** `AbortSignal` 继承自 `EventTarget`，可以监听 `abort` 事件。当信号被中止时，会触发该事件，通知相关的监听器。
4. **中止方法:**  静态方法 `abort()` 用于创建一个已经处于中止状态的 `AbortSignal` 对象。可以指定中止原因。
5. **超时中止:** 静态方法 `timeout()` 创建一个在指定毫秒数后自动中止的 `AbortSignal` 对象。
6. **组合中止信号:** 静态方法 `any()` 可以将多个 `AbortSignal` 对象组合成一个新的 `AbortSignal`。只要其中任何一个源信号中止，组合信号也会中止。
7. **添加中止算法:** 允许注册在 `AbortSignal` 被中止时执行的回调函数（通过 `AddAlgorithm`）。
8. **移除中止算法:**  允许移除之前注册的回调函数（通过 `RemoveAlgorithm`）。
9. **检查是否中止:**  `aborted()` 方法返回信号是否已被中止。
10. **抛出异常如果已中止:** `throwIfAborted()` 方法在信号已中止的情况下抛出一个异常。
11. **获取中止原因:** `reason()` 方法返回与中止信号关联的原因。

**与 Javascript, HTML, CSS 的关系 (Relationship with Javascript, HTML, CSS):**

`AbortSignal` 是 Web API 的一部分，主要在 Javascript 中使用，以控制异步操作。

* **Javascript:**
    * **`AbortController`:**  `AbortSignal` 通常与 `AbortController` 一起使用。`AbortController` 提供了一个 `signal` 属性，返回一个关联的 `AbortSignal` 对象，以及一个 `abort()` 方法来中止该信号。
    * **`fetch` API:** `fetch` 函数接受一个可选的 `signal` 属性，该属性可以设置为一个 `AbortSignal` 对象。当 `AbortSignal` 被中止时，`fetch` 请求将被取消。
    * **`setTimeout` 和 `setInterval`:**  虽然原生的 `setTimeout` 和 `setInterval` 不直接支持 `AbortSignal`，但可以结合使用来实现可取消的定时器。例如，在 `AbortSignal` 的 `abort` 事件触发时清除定时器。
    * **`addEventListener` 的 `options`:**  一些新的 API（例如 `EventTarget.addEventListener` 的 `options` 参数）可以接受 `signal` 属性，允许在 `AbortSignal` 中止时自动移除事件监听器。

* **HTML:**  `AbortSignal` 本身不直接与 HTML 交互，但它可以控制由 Javascript 发起的与 HTML 相关的操作，例如加载资源（通过 `fetch`）。

* **CSS:**  `AbortSignal` 也不直接与 CSS 交互，但它可以间接影响 CSS 相关的操作，例如通过 Javascript 控制的动画或过渡。如果一个动画或过渡由一个与 `AbortSignal` 关联的 Javascript 函数控制，那么中止信号可以停止该动画或过渡。

**举例说明:**

**Javascript 示例 (使用 `fetch`):**

```javascript
const controller = new AbortController();
const signal = controller.signal;

fetch('/data', { signal })
  .then(response => {
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  })
  .then(data => console.log(data))
  .catch(error => {
    if (error.name === 'AbortError') {
      console.log('Fetch aborted');
    } else {
      console.error('Fetch error:', error);
    }
  });

// 在某个时刻中止请求
setTimeout(() => {
  controller.abort('Request timed out'); // 可以传递中止原因
}, 5000);
```

在这个例子中，`AbortController` 创建了一个 `AbortSignal` 并将其传递给 `fetch` 函数。如果在 5 秒后 `controller.abort()` 被调用，`fetch` 请求将被中止，并且 `catch` 块中的错误名称将是 `AbortError`。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 创建一个 `AbortController`： `const controller = new AbortController();`
2. 获取其 `signal`： `const signal = controller.signal;`
3. 注册一个 `abort` 事件监听器：
   ```javascript
   signal.addEventListener('abort', () => {
     console.log('Abort signal was triggered with reason:', signal.reason);
   });
   ```
4. 在一段时间后中止信号，并提供一个原因： `controller.abort('Operation cancelled by user');`

**输出:**

在控制台中会输出： `Abort signal was triggered with reason: Operation cancelled by user`

**解释:**

当 `controller.abort()` 被调用时，`AbortSignal` 的内部状态被设置为 "已中止"，并且中止原因被设置为 "Operation cancelled by user"。这会触发 `abort` 事件，之前注册的监听器会被调用，并打印出中止原因。

**用户或者编程常见的使用错误 (Common User/Programming Errors):**

1. **忘记检查 `signal.aborted` 状态:**  在异步操作的回调函数中，应该检查 `signal.aborted` 状态，以避免在操作被中止后继续执行不必要的工作。

   ```javascript
   fetch('/some-resource', { signal })
     .then(response => {
       if (signal.aborted) { // 正确的做法
         console.log('Fetch completed but signal was already aborted.');
         return;
       }
       // ... 处理响应
     });
   ```

2. **没有正确处理 `AbortError`:**  当 `fetch` 或其他支持 `AbortSignal` 的 API 被中止时，会抛出一个 `AbortError` 类型的错误。开发者需要捕获并妥善处理这个错误。

3. **在不需要时创建 `AbortController`:**  如果不需要取消操作，则不必创建 `AbortController` 和 `AbortSignal`。

4. **在多个操作中复用同一个 `AbortSignal` 并过早中止:**  确保 `AbortSignal` 的生命周期与它所控制的操作相匹配。过早中止可能会影响其他不应被取消的操作。

5. **忘记移除事件监听器 (尽管 `AbortSignal` 可以自动移除):**  在某些情况下，手动管理事件监听器仍然很重要，特别是在不直接使用 `AbortSignal` 的场景中。

**用户操作是如何一步步的到达这里，作为调试线索 (How User Actions Lead Here as Debugging Clues):**

假设用户在一个 Web 应用程序中点击了一个 "取消上传" 按钮。以下是可能发生的步骤，最终涉及到 `abort_signal.cc`：

1. **用户操作:** 用户点击了 "取消上传" 按钮。
2. **前端 Javascript 事件处理:** 浏览器捕获到用户的点击事件，并执行与该按钮关联的 Javascript 事件处理函数。
3. **调用 `AbortController.abort()`:** 在事件处理函数中，代码会获取与上传操作关联的 `AbortController` 实例，并调用其 `abort()` 方法。例如：`uploadController.abort();`
4. **Blink 引擎处理中止:**  `AbortController.abort()` 的调用会触发 Blink 渲染引擎中 `AbortSignal` 相关的逻辑。具体来说，会调用 `blink/renderer/core/dom/abort_signal.cc` 中的 `SignalAbort()` 方法（或其他相关方法），该方法会将 `AbortSignal` 的内部状态设置为 "已中止"，并设置中止原因（如果提供了）。
5. **触发 `abort` 事件:**  `SignalAbort()` 方法会触发 `AbortSignal` 上的 `abort` 事件。
6. **通知监听器:**  任何已经注册到该 `AbortSignal` 上的 `abort` 事件监听器都会被调用。这可能包括 `fetch` API 的内部实现，它会因此取消相关的网络请求。
7. **异步操作取消:** 如果 `AbortSignal` 被传递给了 `fetch` API，Blink 引擎的网络模块会接收到中止信号，并尝试取消正在进行的网络请求。
8. **回调函数处理:** `fetch` Promise 的 `catch` 块会捕获到 `AbortError`，开发者可以在这里执行清理或通知用户的操作。

**调试线索:**

* **断点:**  在 `abort_signal.cc` 的 `SignalAbort()` 方法中设置断点，可以观察 `AbortSignal` 是如何被中止的，以及中止原因是什么。
* **查看调用堆栈:**  当断点命中时，查看调用堆栈可以追溯到哪个 Javascript 代码调用了 `AbortController.abort()`，从而理解用户操作是如何触发中止的。
* **检查 `AbortController` 的生命周期:**  确保 `AbortController` 的创建和 `abort()` 的调用发生在预期的时间和上下文中。
* **监控网络请求:**  使用浏览器的开发者工具的网络面板，观察在点击 "取消上传" 后，相关的网络请求是否被取消。

总而言之，`abort_signal.cc` 是 Blink 渲染引擎中实现 Web API `AbortSignal` 核心逻辑的关键文件，它负责管理中止信号的状态、事件处理以及与异步操作的协调，使得 Javascript 代码能够有效地取消正在进行的操作。

### 提示词
```
这是目录为blink/renderer/core/dom/abort_signal.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/abort_signal.h"

#include <optional>
#include <utility>

#include "base/check_deref.h"
#include "base/functional/callback.h"
#include "base/functional/function_ref.h"
#include "base/time/time.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/abort_signal_composition_manager.h"
#include "third_party/blink/renderer/core/dom/abort_signal_composition_type.h"
#include "third_party/blink/renderer/core/dom/abort_signal_registry.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_linked_hash_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

namespace {

class OnceCallbackAlgorithm final : public AbortSignal::Algorithm {
 public:
  explicit OnceCallbackAlgorithm(base::OnceClosure callback)
      : callback_(std::move(callback)) {}
  ~OnceCallbackAlgorithm() override = default;

  void Run() override { std::move(callback_).Run(); }

 private:
  base::OnceClosure callback_;
};

}  // namespace

AbortSignal::AbortSignal(ExecutionContext* execution_context)
    : execution_context_(execution_context),
      signal_type_(SignalType::kComposite) {
  InitializeCompositeSignal(HeapVector<Member<AbortSignal>>());
}

AbortSignal::AbortSignal(ExecutionContext* execution_context,
                         SignalType signal_type)
    : execution_context_(execution_context),
      signal_type_(signal_type),
      composition_manager_(MakeGarbageCollected<SourceSignalCompositionManager>(
          *this,
          AbortSignalCompositionType::kAbort)) {
  DCHECK_NE(signal_type, SignalType::kComposite);
}

AbortSignal::AbortSignal(ScriptState* script_state,
                         const HeapVector<Member<AbortSignal>>& source_signals)
    : execution_context_(ExecutionContext::From(script_state)),
      signal_type_(SignalType::kComposite) {
  // If any of the signals are aborted, skip the linking and just abort this
  // signal.
  for (auto& source : source_signals) {
    CHECK(source.Get());
    if (source->aborted()) {
      abort_reason_ = source->reason(script_state);
      break;
    }
  }
  InitializeCompositeSignal(aborted() ? HeapVector<Member<AbortSignal>>()
                                      : source_signals);
}

void AbortSignal::InitializeCompositeSignal(
    const HeapVector<Member<AbortSignal>>& source_signals) {
  CHECK_EQ(signal_type_, SignalType::kComposite);
  composition_manager_ =
      MakeGarbageCollected<DependentSignalCompositionManager>(
          *this, AbortSignalCompositionType::kAbort, source_signals);
  // Ensure the registry isn't created during GC, e.g. during an abort
  // controller's prefinalizer.
  AbortSignalRegistry::From(CHECK_DEREF(execution_context_.Get()));
}

AbortSignal::~AbortSignal() = default;

// static
AbortSignal* AbortSignal::abort(ScriptState* script_state) {
  v8::Local<v8::Value> dom_exception = V8ThrowDOMException::CreateOrEmpty(
      script_state->GetIsolate(), DOMExceptionCode::kAbortError,
      "signal is aborted without reason");
  CHECK(!dom_exception.IsEmpty());
  ScriptValue reason(script_state->GetIsolate(), dom_exception);
  return abort(script_state, reason);
}

// static
AbortSignal* AbortSignal::abort(ScriptState* script_state, ScriptValue reason) {
  DCHECK(!reason.IsEmpty());
  AbortSignal* signal = MakeGarbageCollected<AbortSignal>(
      ExecutionContext::From(script_state), SignalType::kAborted);
  signal->abort_reason_ = reason;
  signal->composition_manager_->Settle();
  return signal;
}

// static
AbortSignal* AbortSignal::any(ScriptState* script_state,
                              HeapVector<Member<AbortSignal>> signals) {
  return MakeGarbageCollected<AbortSignal>(script_state, signals);
}

// static
AbortSignal* AbortSignal::timeout(ScriptState* script_state,
                                  uint64_t milliseconds) {
  ExecutionContext* context = ExecutionContext::From(script_state);
  AbortSignal* signal =
      MakeGarbageCollected<AbortSignal>(context, SignalType::kTimeout);
  // The spec requires us to use the timer task source, but there are a few
  // timer task sources due to our throttling implementation. We match
  // setTimeout for immediate timeouts, but use the high-nesting task type for
  // all positive timeouts so they are eligible for throttling (i.e. no
  // nesting-level exception).
  TaskType task_type = milliseconds == 0
                           ? TaskType::kJavascriptTimerImmediate
                           : TaskType::kJavascriptTimerDelayedHighNesting;
  // `signal` needs to be held with a strong reference to keep it alive in case
  // there are or will be event handlers attached.
  context->GetTaskRunner(task_type)->PostDelayedTask(
      FROM_HERE,
      WTF::BindOnce(&AbortSignal::AbortTimeoutFired, WrapPersistent(signal),
                    WrapPersistent(script_state)),
      base::Milliseconds(milliseconds));
  return signal;
}

void AbortSignal::AbortTimeoutFired(ScriptState* script_state) {
  if (GetExecutionContext()->IsContextDestroyed() ||
      !script_state->ContextIsValid()) {
    return;
  }
  ScriptState::Scope scope(script_state);
  auto* isolate = script_state->GetIsolate();
  v8::Local<v8::Value> reason = V8ThrowDOMException::CreateOrEmpty(
      isolate, DOMExceptionCode::kTimeoutError, "signal timed out");
  SignalAbort(script_state, ScriptValue(isolate, reason), SignalAbortPassKey());
}

ScriptValue AbortSignal::reason(ScriptState* script_state) const {
  DCHECK(script_state->GetIsolate()->InContext());
  if (abort_reason_.IsEmpty()) {
    return ScriptValue(script_state->GetIsolate(),
                       v8::Undefined(script_state->GetIsolate()));
  }
  return abort_reason_;
}

void AbortSignal::throwIfAborted() const {
  if (!aborted())
    return;
  V8ThrowException::ThrowException(execution_context_->GetIsolate(),
                                   abort_reason_.V8Value());
}

const AtomicString& AbortSignal::InterfaceName() const {
  return event_target_names::kAbortSignal;
}

ExecutionContext* AbortSignal::GetExecutionContext() const {
  return execution_context_.Get();
}

AbortSignal::AlgorithmHandle* AbortSignal::AddAlgorithm(Algorithm* algorithm) {
  if (aborted() || composition_manager_->IsSettled()) {
    return nullptr;
  }
  auto* handle = MakeGarbageCollected<AlgorithmHandle>(algorithm, this);
  CHECK(!abort_algorithms_.Contains(handle));
  // This always appends since `handle` is not already in the collection.
  abort_algorithms_.insert(handle);
  return handle;
}

AbortSignal::AlgorithmHandle* AbortSignal::AddAlgorithm(
    base::OnceClosure algorithm) {
  if (aborted() || composition_manager_->IsSettled()) {
    return nullptr;
  }
  auto* callback_algorithm =
      MakeGarbageCollected<OnceCallbackAlgorithm>(std::move(algorithm));
  auto* handle =
      MakeGarbageCollected<AlgorithmHandle>(callback_algorithm, this);
  CHECK(!abort_algorithms_.Contains(handle));
  // This always appends since `handle` is not already in the collection.
  abort_algorithms_.insert(handle);
  return handle;
}

void AbortSignal::RemoveAlgorithm(AlgorithmHandle* handle) {
  if (aborted() || composition_manager_->IsSettled()) {
    return;
  }
  abort_algorithms_.erase(handle);
}

void AbortSignal::SignalAbort(ScriptState* script_state,
                              ScriptValue reason,
                              SignalAbortPassKey) {
  DCHECK(!reason.IsEmpty());
  if (aborted()) {
    return;
  }

  CHECK(composition_manager_);
  auto* source_signal_manager =
      DynamicTo<SourceSignalCompositionManager>(composition_manager_.Get());
  // `SignalAbort` can only be called on source signals.
  CHECK(source_signal_manager);
  HeapVector<Member<AbortSignal>> dependent_signals_to_abort;
  dependent_signals_to_abort.ReserveInitialCapacity(
      source_signal_manager->GetDependentSignals().size());

  // Set the abort reason for this signal and any unaborted dependent signals so
  // that all dependent signals are aborted before JS runs in abort algorithms
  // or event dispatch.
  SetAbortReason(script_state, reason);

  for (auto& signal : source_signal_manager->GetDependentSignals()) {
    CHECK(signal.Get());
    if (!signal->aborted()) {
      signal->SetAbortReason(script_state, abort_reason_);
      dependent_signals_to_abort.push_back(signal);
    }
  }

  RunAbortSteps();

  for (auto& signal : dependent_signals_to_abort) {
    signal->RunAbortSteps();
    signal->composition_manager_->Settle();
  }

  composition_manager_->Settle();
}

void AbortSignal::SetAbortReason(ScriptState* script_state,
                                 ScriptValue reason) {
  CHECK(!aborted());
  if (reason.IsUndefined()) {
    abort_reason_ = ScriptValue(
        script_state->GetIsolate(),
        V8ThrowDOMException::CreateOrEmpty(
            script_state->GetIsolate(), DOMExceptionCode::kAbortError,
            "signal is aborted with undefined reason"));
  } else {
    abort_reason_ = reason;
  }
}

void AbortSignal::RunAbortSteps() {
  for (AbortSignal::AlgorithmHandle* handle : abort_algorithms_) {
    CHECK(handle);
    CHECK(handle->GetAlgorithm());
    handle->GetAlgorithm()->Run();
  }

  DispatchEvent(*Event::Create(event_type_names::kAbort));
}

void AbortSignal::Trace(Visitor* visitor) const {
  visitor->Trace(abort_reason_);
  visitor->Trace(execution_context_);
  visitor->Trace(abort_algorithms_);
  visitor->Trace(composition_manager_);
  EventTarget::Trace(visitor);
}

AbortSignalCompositionManager* AbortSignal::GetCompositionManager(
    AbortSignalCompositionType type) {
  if (type == AbortSignalCompositionType::kAbort) {
    return composition_manager_.Get();
  }
  return nullptr;
}

void AbortSignal::DetachFromController() {
  if (aborted()) {
    return;
  }
  composition_manager_->Settle();
}

void AbortSignal::OnSignalSettled(AbortSignalCompositionType type) {
  if (type == AbortSignalCompositionType::kAbort) {
    abort_algorithms_.clear();
  }
  if (signal_type_ == SignalType::kComposite) {
    InvokeRegistryCallback([&](AbortSignalRegistry& registry) {
      registry.UnregisterSignal(*this, type);
    });
  }
}

bool AbortSignal::CanAbort() const {
  if (aborted()) {
    return false;
  }
  return !composition_manager_->IsSettled();
}

void AbortSignal::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  EventTarget::AddedEventListener(event_type, registered_listener);
  OnEventListenerAddedOrRemoved(event_type, AddRemoveType::kAdded);
}

void AbortSignal::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {
  EventTarget::RemovedEventListener(event_type, registered_listener);
  OnEventListenerAddedOrRemoved(event_type, AddRemoveType::kRemoved);
}

void AbortSignal::InvokeRegistryCallback(
    base::FunctionRef<void(AbortSignalRegistry&)> callback) {
  CHECK_EQ(signal_type_, SignalType::kComposite);
  callback(*AbortSignalRegistry::From(*GetExecutionContext()));
}

void AbortSignal::OnEventListenerAddedOrRemoved(const AtomicString& event_type,
                                                AddRemoveType add_or_remove) {
  if (signal_type_ != SignalType::kComposite) {
    return;
  }
  std::optional<AbortSignalCompositionType> composition_type;
  if (event_type == event_type_names::kAbort) {
    composition_type = AbortSignalCompositionType::kAbort;
  } else if (event_type == event_type_names::kPrioritychange) {
    composition_type = AbortSignalCompositionType::kPriority;
  } else {
    return;
  }
  if (IsSettledFor(*composition_type)) {
    // Signals are unregistered when they're settled for `composition_type`
    // since the event will no longer be propagated. In that case, the signal
    // doesn't need to be unregistered on removal, and it shouldn't be
    // registered on adding a listener, since that could leak it.
    return;
  }
  if (add_or_remove == AddRemoveType::kRemoved &&
      HasEventListeners(event_type)) {
    // Unsettled composite signals need to be kept alive while they have active
    // event listeners for `event_type`, so only unregister the signal if
    // removing the last one.
    return;
  }
  // `manager` will be null if this signal doesn't handle composition for
  // `composition_type`.
  if (GetCompositionManager(*composition_type)) {
    InvokeRegistryCallback([&](AbortSignalRegistry& registry) {
      switch (add_or_remove) {
        case AddRemoveType::kAdded:
          registry.RegisterSignal(*this, *composition_type);
          break;
        case AddRemoveType::kRemoved:
          registry.UnregisterSignal(*this, *composition_type);
          break;
      }
    });
  }
}

bool AbortSignal::IsSettledFor(
    AbortSignalCompositionType composition_type) const {
  return composition_type == AbortSignalCompositionType::kAbort &&
         composition_manager_->IsSettled();
}

AbortSignal::AlgorithmHandle::AlgorithmHandle(AbortSignal::Algorithm* algorithm,
                                              AbortSignal* signal)
    : algorithm_(algorithm), signal_(signal) {
  CHECK(algorithm_);
  CHECK(signal_);
}

AbortSignal::AlgorithmHandle::~AlgorithmHandle() = default;

void AbortSignal::AlgorithmHandle::Trace(Visitor* visitor) const {
  visitor->Trace(algorithm_);
  visitor->Trace(signal_);
}

}  // namespace blink
```