Response:
Let's break down the thought process for analyzing this C++ code file and generating the comprehensive response.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `rejected_promises.cc` within the Chromium Blink engine and how it relates to JavaScript promises, especially rejections. The request also specifically asks for connections to HTML/CSS, examples, logic, and user/programming errors. Finally, it wants a debugging walkthrough.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for important keywords and structures. I look for:

* **Headers:**  `rejected_promises.h`, `v8`, `PromiseRejectionEvent`, `ExecutionContext`, `ThreadDebugger`. These immediately signal the file's purpose: handling rejected promises within the V8 JavaScript engine in the context of a web page.
* **Namespaces:** `blink`. This confirms it's part of the Blink rendering engine.
* **Classes:** `RejectedPromises`, `Message`. The `Message` class seems to hold information about a rejected promise.
* **Methods:** `RejectedWithNoHandler`, `HandlerAdded`, `Report`, `Revoke`, `ProcessQueue`, `Dispose`. These suggest the lifecycle of a rejected promise being tracked.
* **Data Structures:** `queue_`, `reported_as_errors_`. These are likely used to store information about rejected promises at different stages.
* **Constants:** `kMaxReportedHandlersPendingResolution`. This hints at a mechanism to prevent excessive memory usage.
* **Callbacks/Weak Pointers:** The `DidCollectPromise` and `DidCollectException` static methods and the use of `ScopedPersistent` indicate a need to manage the lifetime of V8 objects.
* **Events:** `PromiseRejectionEvent`, `unhandledrejection`, `rejectionhandled`. These are standard JavaScript events related to promise rejections.
* **Logging/Debugging:**  References to `ThreadDebugger`.

**3. Deciphering the Core Logic:**

Based on the keywords, I start to form a mental model of the workflow:

* **Rejection Occurs:** When a JavaScript promise is rejected *without* an immediate `.catch()` handler, the `RejectedWithNoHandler` function is called. This creates a `Message` object to store information about the rejected promise (the promise itself, the reason for rejection, and location).
* **Tracking Pending Rejections:** These `Message` objects are stored in the `queue_`.
* **Handler Added:** If a `.catch()` or `.then(..., rejectionHandler)` is later added to the promise, the `HandlerAdded` function is called. This function checks if the rejected promise is in the `queue_`. If found, it's removed, as the rejection is now being handled.
* **Reporting Unhandled Rejections:** The `ProcessQueue` function is called periodically. It iterates through the `queue_`. For promises that *still* don't have a handler, the `Report` method is called. This triggers the `unhandledrejection` event, potentially logs to the console (via `ThreadDebugger`), and moves the `Message` to the `reported_as_errors_` list. The promise reference is made weak to avoid memory leaks.
* **Revoking Reports:** If a handler is added *after* the rejection has been reported (and the `Message` is in `reported_as_errors_`), the `HandlerAdded` function finds it there. The `Revoke` method is called, triggering the `rejectionhandled` event and potentially informing the debugger. The promise reference is made strong temporarily to perform the operations.
* **Garbage Collection:** The weak pointers in `Message` and the `IsCollected()` check ensure that if the JavaScript promise object is garbage collected, the corresponding `Message` is also cleaned up.
* **Resource Management:** The `kMaxReportedHandlersPendingResolution` constant limits the number of reported unhandled rejections to prevent excessive memory usage.

**4. Connecting to JavaScript/HTML/CSS:**

Now that I have a basic understanding, I explicitly think about the connections:

* **JavaScript:** The entire mechanism is triggered by JavaScript promise rejections. The `PromiseRejectMessage` object is a V8-specific representation of this. The `unhandledrejection` and `rejectionhandled` events are standard JavaScript events.
* **HTML:** While not directly involved in the *logic* of this C++ code, the JavaScript that creates and rejects promises runs within the context of a web page, which is defined by HTML. The errors might be displayed in the browser's console, which is part of the browser UI rendering the HTML.
* **CSS:** CSS has no direct interaction with promise rejection handling.

**5. Crafting Examples and Logic:**

This involves creating concrete scenarios to illustrate the functionality:

* **Unhandled Rejection:** Show a simple promise rejection without a `catch`. Explain how `RejectedWithNoHandler` and `ProcessQueue` would handle it.
* **Handler Added Before Reporting:** Demonstrate a rejection followed by a `catch`. Explain how `HandlerAdded` prevents reporting.
* **Handler Added After Reporting:** Show a rejection, the reporting, and then the addition of a handler. Explain how `HandlerAdded` and `Revoke` handle this case.

**6. Identifying User/Programming Errors:**

Consider common mistakes developers make with promises:

* **Forgetting to add a `.catch()`:**  This is the primary scenario this code addresses.
* **Incorrectly handling rejections:**  The `unhandledrejection` event allows developers to implement custom error handling, but they might not do it correctly.

**7. Developing the Debugging Scenario:**

Think about how a developer might end up looking at this C++ code:

* They see an "Unhandled Promise Rejection" in the console.
* They want to understand *why* it's happening and how the browser detects it.
* This leads them to search for the relevant Chromium source code.

Then, outline the steps to trace the code execution, starting from the JavaScript promise rejection and following the calls into the C++ code.

**8. Structuring the Response:**

Finally, organize the information clearly and logically, using headings and bullet points to make it easy to read and understand. Address all the specific points raised in the original request.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just logs errors."  **Correction:** It does more than just log; it manages the lifecycle of unhandled rejections and handles cases where handlers are added later.
* **Initial thought:** "The `Message` class is just a simple struct." **Correction:** It has logic for reporting, revoking, and managing weak pointers.
* **Ensuring clarity:**  Use precise language (e.g., "microtask queue," "event loop") and avoid jargon where possible.

By following this systematic approach, I can effectively analyze the C++ code and generate a comprehensive and informative response that addresses all aspects of the user's request.
好的，让我们来详细分析一下 `blink/renderer/bindings/core/v8/rejected_promises.cc` 这个文件。

**功能概述:**

这个 C++ 文件在 Chromium Blink 引擎中负责管理和追踪被拒绝 (rejected) 且没有处理程序 (handler) 的 JavaScript Promise。 它的主要功能包括：

1. **记录未处理的 Promise 拒绝:**  当一个 Promise 被拒绝，且在微任务队列清空后仍然没有被 `.catch()` 或 `.then()` 处理时，这个文件会记录下这个拒绝事件。
2. **报告未处理的 Promise 拒绝:**  将这些未处理的拒绝报告给开发者，通常是通过触发 `unhandledrejection` 事件，并在控制台中输出错误信息。
3. **处理后续添加的处理程序:**  如果之后为之前被拒绝的 Promise 添加了处理程序（例如，在稍后的代码中添加了 `.catch()`），这个文件会检测到这种情况，并撤销之前的报告（通过触发 `rejectionhandled` 事件，并可能从控制台中移除相关的错误信息）。
4. **资源管理:**  维护一个记录未处理拒绝的队列，并进行资源管理，例如限制报告的未处理拒绝的数量，避免内存占用过多。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接与 **JavaScript** 的 Promise 功能紧密相关。 Promise 是 JavaScript 中处理异步操作的重要机制。当 Promise 状态变为 "rejected" 且没有提供处理拒绝情况的回调函数时，这个文件就开始发挥作用。

* **JavaScript 示例:**

```javascript
// 一个会被拒绝的 Promise
const myPromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    reject("Something went wrong!");
  }, 100);
});

// 没有添加 .catch() 或 .then(null, ...) 来处理拒绝

// 稍后添加处理程序
setTimeout(() => {
  myPromise.catch(error => {
    console.error("Caught the error:", error);
  });
}, 500);
```

在这个例子中：

1. 当 `myPromise` 被拒绝时，`rejected_promises.cc` 会记录下这次拒绝，因为在第一次微任务队列清空后没有找到处理程序。
2. 大约在 100 毫秒后，`rejected_promises.cc` 可能会触发一个 `unhandledrejection` 事件，并可能在控制台中显示 "Unhandled Promise Rejection: Something went wrong!"。
3. 当 500 毫秒后的 `setTimeout` 执行，并添加了 `.catch()` 处理程序后，`rejected_promises.cc` 会检测到这个处理程序的添加，并触发一个 `rejectionhandled` 事件，并可能从控制台中移除之前的 "Unhandled Promise Rejection" 提示。

这个文件与 **HTML** 和 **CSS** 的关系是间接的。 JavaScript 代码运行在 HTML 文档的上下文中，Promise 的使用也是在 JavaScript 代码中。 当未处理的 Promise 拒绝被报告时，控制台的输出会显示在浏览器的开发者工具中，而开发者工具是浏览器 UI 的一部分，用于检查 HTML 结构、CSS 样式和 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

* JavaScript 代码创建了一个立即被拒绝的 Promise，且没有立即添加处理程序。

```javascript
Promise.reject("Initial rejection");
```

**预期输出 1:**

* `rejected_promises.cc` 中的 `RejectedWithNoHandler` 函数会被调用，记录下这次拒绝。
* 在微任务队列清空后，如果仍然没有添加处理程序，`ProcessQueue` 函数会处理这个记录，并调用 `Report` 函数。
* `Report` 函数会触发一个 `unhandledrejection` 事件，事件的 `promise` 属性是拒绝的 Promise 对象，`reason` 属性是 `"Initial rejection"`。
* 控制台可能会显示 "Unhandled Promise Rejection: Initial rejection"。

**假设输入 2:**

* JavaScript 代码创建了一个会被拒绝的 Promise，但在微任务队列清空前添加了处理程序。

```javascript
const p = Promise.reject("Early handled rejection");
p.catch(error => {
  console.log("Handled:", error);
});
```

**预期输出 2:**

* `rejected_promises.cc` 中的 `RejectedWithNoHandler` 函数会被调用。
* 在微任务队列清空前，Promise 的状态已经确定，并且有了处理程序。
* 当 `ProcessQueue` 函数运行时，会发现该 Promise 已经有处理程序（通过 `HasHandler()` 判断），因此不会调用 `Report` 函数，也不会触发 `unhandledrejection` 事件。
* 控制台会输出 "Handled: Early handled rejection"，但不会有 "Unhandled Promise Rejection" 的提示。

**假设输入 3:**

* JavaScript 代码创建了一个会被拒绝的 Promise，一段时间后才添加处理程序。

```javascript
const delayedP = new Promise((resolve, reject) => {
  setTimeout(() => {
    reject("Delayed rejection");
  }, 100);
});

setTimeout(() => {
  delayedP.catch(error => {
    console.log("Finally handled:", error);
  });
}, 500);
```

**预期输出 3:**

* 在 100 毫秒后，`rejected_promises.cc` 中的 `RejectedWithNoHandler` 函数会被调用。
* 在第一次 `ProcessQueue` 运行时（假设在 500 毫秒前），会触发 `unhandledrejection` 事件，并可能在控制台显示 "Unhandled Promise Rejection: Delayed rejection"。
* 在 500 毫秒后的 `setTimeout` 执行，添加了 `.catch()` 后，`HandlerAdded` 函数会被调用，检测到该 Promise 之前被报告过。
* `Revoke` 函数会被调用，触发 `rejectionhandled` 事件，并可能从控制台中移除之前的 "Unhandled Promise Rejection" 提示。
* 控制台会输出 "Finally handled: Delayed rejection"。

**用户或编程常见的使用错误:**

1. **忘记添加 `.catch()` 或 `.then(null, rejectionHandler)` 来处理 Promise 拒绝:** 这是最常见的情况，会导致 `rejected_promises.cc` 报告未处理的拒绝。

   ```javascript
   // 错误示例
   fetch('some-api')
     .then(response => response.json()); // 如果 fetch 失败，Promise 会被拒绝，但没有处理
   ```

2. **在异步操作中没有正确处理 Promise 链的拒绝:**  如果 Promise 链中的某个环节拒绝了，但后续的 `.then()` 没有正确处理拒绝，也会导致未处理的拒绝。

   ```javascript
   // 错误示例
   Promise.resolve()
     .then(() => { throw new Error("Oops!"); })
     .then(result => console.log(result)); // 这里的 .then 没有处理上一个 then 的拒绝
   ```

3. **误解 Promise 的错误处理机制:**  认为某些代码结构会自动捕获 Promise 的拒绝，但实际上并没有。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览网页时，网页的 JavaScript 代码中存在一个未处理的 Promise 拒绝。以下是可能发生的步骤，最终导致开发者查看 `rejected_promises.cc`：

1. **用户访问网页:**  浏览器加载 HTML、CSS 和 JavaScript 代码。
2. **JavaScript 代码执行:**  JavaScript 代码开始执行，其中包含创建和操作 Promise 的代码。
3. **Promise 被拒绝:**  某个 Promise 因为异步操作失败或代码逻辑错误而被拒绝。
4. **微任务队列清空:**  在当前的 JavaScript 执行上下文完成后，浏览器会处理微任务队列。如果被拒绝的 Promise 在此时仍然没有处理程序，浏览器会注意到。
5. **Blink 引擎处理未处理的拒绝:**  Blink 引擎的 Promise 实现（涉及到 V8 引擎）会检测到这个未处理的拒绝，并调用 `rejected_promises.cc` 中的相关函数 (`RejectedWithNoHandler`)。
6. **`unhandledrejection` 事件触发 (可能):**  `rejected_promises.cc` 可能会触发一个 `unhandledrejection` 全局事件，开发者可以在 JavaScript 中监听这个事件进行自定义处理。
7. **控制台输出错误信息:**  `rejected_promises.cc` 通常会将未处理的 Promise 拒绝信息输出到浏览器的开发者工具控制台，显示 "Unhandled Promise Rejection" 以及拒绝的原因。
8. **开发者查看控制台:**  用户或开发者可能会注意到控制台中的错误信息。
9. **开发者调试代码:**  开发者会查看 JavaScript 代码，试图找到导致 Promise 拒绝的原因以及为什么没有被处理。
10. **深入研究 Blink 源码 (高级):**  如果开发者对浏览器引擎的内部工作原理感兴趣，或者遇到一些复杂的 Promise 拒绝问题，他们可能会搜索 Chromium 的源代码，找到 `rejected_promises.cc` 这个文件，希望能更深入地理解浏览器是如何处理这些未处理的拒绝的。他们可能会查看这个文件的代码，了解 `RejectedWithNoHandler`、`ProcessQueue`、`Report` 和 `Revoke` 等函数的工作方式。

**总结:**

`rejected_promises.cc` 是 Chromium Blink 引擎中一个关键的组件，它确保了 JavaScript Promise 的拒绝状态不会被忽略，并提供了机制来通知开发者潜在的错误，并允许在后续添加处理程序时进行修正。理解这个文件的功能有助于开发者更好地理解 Promise 的工作原理以及浏览器如何处理异步操作中的错误。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/rejected_promises.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/rejected_promises.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_promise_rejection_event_init.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/core/events/promise_rejection_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/scoped_persistent.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/thread_debugger.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"

namespace blink {

static const unsigned kMaxReportedHandlersPendingResolution = 1000;

class RejectedPromises::Message final {
 public:
  Message(ScriptState* script_state,
          v8::Local<v8::Promise> promise,
          v8::Local<v8::Value> exception,
          const String& error_message,
          std::unique_ptr<SourceLocation> location,
          SanitizeScriptErrors sanitize_script_errors)
      : script_state_(script_state),
        promise_(script_state->GetIsolate(), promise),
        exception_(script_state->GetIsolate(), exception),
        error_message_(error_message),
        location_(std::move(location)),
        promise_rejection_id_(0),
        collected_(false),
        should_log_to_console_(true),
        sanitize_script_errors_(sanitize_script_errors) {}

  bool IsCollected() { return collected_ || !script_state_->ContextIsValid(); }

  bool HasPromise(v8::Local<v8::Value> promise) { return promise_ == promise; }

  void Report() {
    if (!script_state_->ContextIsValid())
      return;
    // If execution termination has been triggered, quietly bail out.
    if (script_state_->GetIsolate()->IsExecutionTerminating())
      return;
    ExecutionContext* execution_context = ExecutionContext::From(script_state_);
    if (!execution_context)
      return;

    ScriptState::Scope scope(script_state_);
    v8::Local<v8::Promise> promise =
        promise_.NewLocal(script_state_->GetIsolate());
    v8::Local<v8::Value> reason =
        exception_.NewLocal(script_state_->GetIsolate());
    if (promise.IsEmpty()) {
      return;
    }
    DCHECK(!HasHandler());

    EventTarget* target = execution_context->ErrorEventTarget();
    if (target &&
        sanitize_script_errors_ == SanitizeScriptErrors::kDoNotSanitize) {
      PromiseRejectionEventInit* init = PromiseRejectionEventInit::Create();
      init->setPromise(
          MemberScriptPromise<IDLAny>(script_state_->GetIsolate(), promise));
      init->setReason(ScriptValue(script_state_->GetIsolate(), reason));
      init->setCancelable(true);
      PromiseRejectionEvent* event = PromiseRejectionEvent::Create(
          script_state_, event_type_names::kUnhandledrejection, init);
      // Log to console if event was not canceled.
      should_log_to_console_ =
          target->DispatchEvent(*event) == DispatchEventResult::kNotCanceled;
    }

    if (should_log_to_console_) {
      ThreadDebugger* debugger =
          ThreadDebugger::From(script_state_->GetIsolate());
      if (debugger) {
        promise_rejection_id_ = debugger->PromiseRejected(
            script_state_->GetContext(), error_message_, reason,
            std::move(location_));
      }
    }

    location_.reset();
  }

  void Revoke() {
    if (!script_state_->ContextIsValid()) {
      // If the context is not valid, the frame is removed for example, then do
      // nothing.
      return;
    }
    ExecutionContext* execution_context = ExecutionContext::From(script_state_);
    if (!execution_context)
      return;

    ScriptState::Scope scope(script_state_);
    v8::Local<v8::Promise> promise =
        promise_.NewLocal(script_state_->GetIsolate());
    v8::Local<v8::Value> reason =
        exception_.NewLocal(script_state_->GetIsolate());
    if (promise.IsEmpty()) {
      return;
    }

    EventTarget* target = execution_context->ErrorEventTarget();
    if (target &&
        sanitize_script_errors_ == SanitizeScriptErrors::kDoNotSanitize) {
      PromiseRejectionEventInit* init = PromiseRejectionEventInit::Create();
      init->setPromise(
          MemberScriptPromise<IDLAny>(script_state_->GetIsolate(), promise));
      init->setReason(ScriptValue(script_state_->GetIsolate(), reason));
      PromiseRejectionEvent* event = PromiseRejectionEvent::Create(
          script_state_, event_type_names::kRejectionhandled, init);
      target->DispatchEvent(*event);
    }

    if (should_log_to_console_ && promise_rejection_id_) {
      ThreadDebugger* debugger =
          ThreadDebugger::From(script_state_->GetIsolate());
      if (debugger) {
        debugger->PromiseRejectionRevoked(script_state_->GetContext(),
                                          promise_rejection_id_);
      }
    }
  }

  void MakePromiseWeak() {
    CHECK(!promise_.IsEmpty());
    CHECK(!promise_.IsWeak());
    promise_.SetWeak(this, &Message::DidCollectPromise);
    exception_.SetWeak(this, &Message::DidCollectException);
  }

  void MakePromiseStrong() {
    CHECK(!promise_.IsEmpty());
    CHECK(promise_.IsWeak());
    promise_.ClearWeak();
    exception_.ClearWeak();
  }

  bool HasHandler() {
    DCHECK(!IsCollected());
    ScriptState::Scope scope(script_state_);
    v8::Local<v8::Value> value = promise_.NewLocal(script_state_->GetIsolate());
    return v8::Local<v8::Promise>::Cast(value)->HasHandler();
  }

  ExecutionContext* GetContext() {
    return ExecutionContext::From(script_state_);
  }

 private:
  static void DidCollectPromise(const v8::WeakCallbackInfo<Message>& data) {
    data.GetParameter()->collected_ = true;
    data.GetParameter()->promise_.Clear();
  }

  static void DidCollectException(const v8::WeakCallbackInfo<Message>& data) {
    data.GetParameter()->exception_.Clear();
  }

  Persistent<ScriptState> script_state_;
  ScopedPersistent<v8::Promise> promise_;
  ScopedPersistent<v8::Value> exception_;
  String error_message_;
  std::unique_ptr<SourceLocation> location_;
  unsigned promise_rejection_id_;
  bool collected_;
  bool should_log_to_console_;
  SanitizeScriptErrors sanitize_script_errors_;
};

RejectedPromises::RejectedPromises() = default;

RejectedPromises::~RejectedPromises() = default;

void RejectedPromises::RejectedWithNoHandler(
    ScriptState* script_state,
    v8::PromiseRejectMessage data,
    const String& error_message,
    std::unique_ptr<SourceLocation> location,
    SanitizeScriptErrors sanitize_script_errors) {
  queue_.push_back(std::make_unique<Message>(
      script_state, data.GetPromise(), data.GetValue(), error_message,
      std::move(location), sanitize_script_errors));
}

void RejectedPromises::HandlerAdded(v8::PromiseRejectMessage data) {
  // First look it up in the pending messages and fast return, it'll be covered
  // by processQueue().
  for (auto it = queue_.begin(); it != queue_.end(); ++it) {
    if (!(*it)->IsCollected() && (*it)->HasPromise(data.GetPromise())) {
      queue_.erase(it);
      return;
    }
  }

  // Then look it up in the reported errors.
  for (wtf_size_t i = 0; i < reported_as_errors_.size(); ++i) {
    std::unique_ptr<Message>& message = reported_as_errors_.at(i);
    if (!message->IsCollected() && message->HasPromise(data.GetPromise())) {
      message->MakePromiseStrong();
      // Since we move out of `message` below, we need to pull `context` out in
      // a separate statement.
      ExecutionContext* context = message->GetContext();
      context->GetTaskRunner(TaskType::kDOMManipulation)
          ->PostTask(FROM_HERE,
                     WTF::BindOnce(&RejectedPromises::RevokeNow,
                                   scoped_refptr<RejectedPromises>(this),
                                   std::move(message)));
      reported_as_errors_.EraseAt(i);
      return;
    }
  }
}

void RejectedPromises::Dispose() {
  if (queue_.empty())
    return;

  ProcessQueueNow(std::move(queue_));
  queue_.clear();
}

void RejectedPromises::ProcessQueue() {
  if (queue_.empty())
    return;

  HeapHashMap<Member<ExecutionContext>, MessageQueue> queues;
  for (auto& message : queue_) {
    auto result = queues.insert(message->GetContext(), MessageQueue());
    result.stored_value->value.push_back(std::move(message));
  }
  queue_.clear();

  for (auto& kv : queues) {
    kv.key->GetTaskRunner(blink::TaskType::kDOMManipulation)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&RejectedPromises::ProcessQueueNow,
                                 scoped_refptr<RejectedPromises>(this),
                                 std::move(kv.value)));
  }
}

void RejectedPromises::ProcessQueueNow(MessageQueue queue) {
  // Remove collected handlers.
  auto new_end = std::remove_if(
      reported_as_errors_.begin(), reported_as_errors_.end(),
      [](const auto& message) { return message->IsCollected(); });
  reported_as_errors_.Shrink(
      static_cast<wtf_size_t>(new_end - reported_as_errors_.begin()));

  for (auto& message : queue) {
    if (message->IsCollected())
      continue;
    if (!message->HasHandler()) {
      message->Report();
      message->MakePromiseWeak();
      reported_as_errors_.push_back(std::move(message));
      if (reported_as_errors_.size() > kMaxReportedHandlersPendingResolution) {
        reported_as_errors_.EraseAt(0,
                                    kMaxReportedHandlersPendingResolution / 10);
      }
    }
  }
}

void RejectedPromises::RevokeNow(std::unique_ptr<Message> message) {
  message->Revoke();
}

}  // namespace blink
```