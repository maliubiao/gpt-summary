Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/inspector/injected-script.cc`. They also have some specific conditions:

1. **List the functionalities:** I need to analyze the code and identify the core capabilities it provides.
2. **Torque check:** Determine if the file could be a Torque file based on its extension (which is `.cc`, so the answer is no).
3. **JavaScript relationship:** If the code interacts with JavaScript, I need to illustrate this with JavaScript examples.
4. **Code logic and reasoning:** If there's logical flow, I need to provide hypothetical inputs and outputs.
5. **Common programming errors:** Identify and illustrate common errors the code might help debug or related to its function.
6. **Overall summary:** Condense the identified functionalities into a concise summary.

Let's break down the code section by section to understand its purpose:

- **Includes:** The initial `#include` directives indicate the dependencies. The file interacts with V8 internals (`v8-*`), inspector protocol (`inspector_protocol`), and internal inspector components (`src/inspector/*`). This strongly suggests its role is within the V8 inspector framework.
- **`EvaluateCallback`:** This class handles the asynchronous results of evaluating JavaScript code. It has `sendSuccess` and `sendFailure` methods, indicating how results and errors are propagated back.
- **`InjectedScript::ProtocolPromiseHandler`:** This nested class seems to deal specifically with handling Promises in the context of the inspector. It has logic to attach callbacks to Promises and process their fulfillment or rejection. The `thenCallback` and `catchCallback` methods are central to this.
- **`InjectedScript` constructor and destructor:**  Basic object lifecycle management. The destructor calls `discardEvaluateCallbacks`, suggesting cleanup of ongoing evaluations.
- **`getProperties`:** This function retrieves properties of a JavaScript object, formatting them for the inspector protocol. It handles various property attributes like configurability, enumerability, and accessors.
- **`getInternalAndPrivateProperties`:**  Similar to `getProperties`, but specifically for internal and private properties of JavaScript objects.
- **`releaseObject`:** This function likely releases a reference to a remotely inspected object, indicated by its `objectId`.
- **`wrapObject`:**  A core function for converting V8 JavaScript values into the inspector's `RemoteObject` representation. It handles different wrapping modes and custom previews.
- **`wrapTable`:**  Specifically handles the formatting of table-like data for display in the inspector.
- **`addPromiseCallback`:** This function appears to initiate the process of observing a Promise, using the `ProtocolPromiseHandler`.

Based on this analysis, the core function of `injected-script.cc` seems to be managing the interaction between the V8 runtime and the inspector frontend, particularly when evaluating JavaScript code and inspecting its objects. The code handles asynchronous operations (Promises) and ensures proper formatting and serialization of JavaScript values for the inspector protocol.
```
列举一下它的功能:

1. **异步代码求值管理:**  `InjectedScript` 类负责管理在 JavaScript 虚拟机中异步执行代码的流程，特别是通过 Promise 进行的异步操作。它维护一个 `m_evaluateCallbacks` 集合，用于跟踪待处理的求值回调。

2. **Promise 结果处理:**  `ProtocolPromiseHandler` 类专门用于处理 JavaScript Promise 的结果（成功或失败）。它将 DevTools 的回调函数连接到 Promise 的 `then` 和 `catch` 方法，并在 Promise 状态改变时将结果或错误传递回 DevTools。

3. **对象属性获取:** `getProperties` 函数允许获取 JavaScript 对象的属性信息，包括自有属性和继承属性，并可以过滤访问器属性或非索引属性。它将 V8 的属性信息转换为 Inspector 协议定义的 `PropertyDescriptor` 对象。

4. **内部和私有属性获取:** `getInternalAndPrivateProperties` 函数用于获取 JavaScript 对象的内部属性（例如 `[[Prototype]]`）和私有属性（使用 `#` 前缀）。

5. **远程对象管理:** `releaseObject` 函数用于释放对远程对象的引用，这通常用于管理 DevTools 前端持有的 JavaScript 对象的生命周期。

6. **对象包装 (Wrapping):** `wrapObject` 函数是将 V8 的 JavaScript 值转换为 Inspector 协议定义的 `RemoteObject` 的核心功能。这个过程包括提取值的类型、内容，以及可能的对象预览信息。它还支持深度序列化，以便在需要时完整地传输对象结构。

7. **表格数据包装:** `wrapTable` 函数专门用于将类似表格的 JavaScript 对象转换为 Inspector 协议中可以展示的格式。它可以根据提供的列名选择性地展示表格数据。

8. **自定义预览生成:**  代码中提到了 `generateCustomPreview`，虽然具体实现未在此代码段中，但暗示了可以为特定类型的 JavaScript 对象生成自定义的预览信息，以便在 DevTools 中更友好地展示。

9. **异常详情创建:** 代码中多次调用 `createExceptionDetails`，表明它负责将 V8 中发生的 JavaScript 异常转换为 Inspector 协议定义的 `ExceptionDetails` 结构，以便 DevTools 可以显示详细的错误信息，包括堆栈跟踪。

如果 v8/src/inspector/injected-script.cc 以 .tq 结尾，那它是个 v8 torque 源代码。

否，当前提供的文件名是 `injected-script.cc`，以 `.cc` 结尾，这意味着它是 C++ 源代码文件，而不是 Torque (`.tq`) 文件。Torque 用于定义 V8 内部的内置函数和类型。

如果它与javascript的功能有关系，请用javascript举例说明:

`injected-script.cc` 的核心功能是作为 V8 Inspector 的一部分，与 JavaScript 代码进行交互。以下是一些 JavaScript 场景，说明了 `injected-script.cc` 中功能的用途：

1. **代码求值和 Promise 处理:**

   **JavaScript 示例:**
   ```javascript
   let result = await new Promise(resolve => setTimeout(() => resolve(10), 100));
   console.log(result);
   ```

   当你在 DevTools 的 Console 中输入这段代码并执行时，`injected-script.cc` 中的 `ProtocolPromiseHandler` 会捕获到 Promise 的创建，并监控其状态。当 Promise 完成 (resolve) 时，`thenCallback` 会被触发，并将结果 `10` 包装成 `RemoteObject` 发送回 DevTools。

2. **对象属性检查:**

   **JavaScript 示例:**
   ```javascript
   const myObject = { a: 1, b: 'hello' };
   ```

   当你使用 DevTools 的 "Scope" 面板或在 Console 中输入 `myObject` 时，`injected-script.cc` 中的 `getProperties` 函数会被调用，以获取 `myObject` 的属性 `a` 和 `b` 及其值，并将其显示在 DevTools 中。

3. **检查内部属性:**

   **JavaScript 示例:**
   ```javascript
   const arr = [1, 2, 3];
   ```

   在 DevTools 中检查 `arr` 时，展开对象可能会显示内部属性，例如 `[[Prototype]]`。`getInternalAndPrivateProperties` 函数负责提取这些信息。

4. **处理错误:**

   **JavaScript 示例:**
   ```javascript
   throw new Error("Something went wrong!");
   ```

   当这段代码执行并抛出错误时，`injected-script.cc` 中的代码会捕获这个错误，并使用 `createExceptionDetails` 创建一个包含错误消息和堆栈跟踪的结构，发送到 DevTools 的 "Console" 或 "Debugger" 面板。

如果有代码逻辑推理，请给出假设输入与输出:

**场景：Promise 求值成功**

**假设输入 (在 DevTools Console 中执行的 JavaScript 代码):**
```javascript
new Promise(resolve => resolve(42));
```

**`ProtocolPromiseHandler::thenCallback` 的假设输入：**

- `info.Data()`: 包含与 Promise 处理器关联的 ID 的 `v8::Number`。
- `info[0]`:  `v8::Local<v8::Value>`，其值为数字 `42`。

**假设输出 (通过 EvaluateCallback 发送回 DevTools):**

- `result`: 一个 `protocol::Runtime::RemoteObject`，其类型为 `"number"`，值为 `42`。
- `exceptionDetails`: `protocol::Maybe<protocol::Runtime::ExceptionDetails>`，为空，因为 Promise 成功完成，没有异常。

**场景：Promise 求值失败**

**假设输入 (在 DevTools Console 中执行的 JavaScript 代码):**
```javascript
Promise.reject(new Error("Failed!"));
```

**`ProtocolPromiseHandler::catchCallback` 的假设输入：**

- `info.Data()`: 包含与 Promise 处理器关联的 ID 的 `v8::Number`。
- `info[0]`: `v8::Local<v8::Value>`，其为一个 `Error` 对象。

**假设输出 (通过 EvaluateCallback 发送回 DevTools):**

- `result`: 一个 `protocol::Runtime::RemoteObject`，其类型为 `"object"`，子类型为 `"error"`，描述了 `Error` 对象。
- `exceptionDetails`: `protocol::Maybe<protocol::Runtime::ExceptionDetails>`，包含以下信息：
    - `text`:  "Uncaught (in promise) Error: Failed!"
    - `exceptionId`: 一个唯一的异常 ID。
    - `stackTrace`:  表示异常发生时的调用堆栈信息的 `protocol::Runtime::StackTrace` 对象。

如果涉及用户常见的编程错误，请举例说明:

`injected-script.cc` 本身不是用来直接防止用户编程错误的，但它在 DevTools 中展示错误信息的功能，有助于用户识别和调试错误。以下是一些常见的编程错误，当发生时，`injected-script.cc` 会参与到错误信息的呈现：

1. **未捕获的 Promise 拒绝:**

   **JavaScript 错误示例:**
   ```javascript
   new Promise((resolve, reject) => reject("Something bad happened!"));
   ```

   当这段代码执行时，Promise 被拒绝，但没有 `.catch()` 处理器。`injected-script.cc` 会捕获这个未处理的拒绝，并在 DevTools 的 Console 中显示一个 "Unhandled Rejection" 错误，包含拒绝的原因。

2. **类型错误:**

   **JavaScript 错误示例:**
   ```javascript
   const num = 10;
   num.toUpperCase(); // TypeError: num.toUpperCase is not a function
   ```

   当执行到 `num.toUpperCase()` 时，会抛出一个 `TypeError`。`injected-script.cc` 会捕获这个错误，并将其转换为包含错误消息和堆栈跟踪的 `ExceptionDetails`，显示在 DevTools 中。

3. **引用错误:**

   **JavaScript 错误示例:**
   ```javascript
   console.log(undeclaredVariable); // ReferenceError: undeclaredVariable is not defined
   ```

   尝试访问未声明的变量会抛出 `ReferenceError`。 `injected-script.cc` 同样会捕获并呈现这个错误信息。

4. **异步操作中的错误:**

   **JavaScript 错误示例:**
   ```javascript
   async function fetchData() {
       const response = await fetch('invalid-url');
       const data = await response.json(); // 如果 fetch 失败，response.json() 可能会出错
       return data;
   }

   fetchData().catch(error => console.error("Error fetching data:", error));
   ```

   在异步操作中发生的错误（例如网络请求失败）会被 `injected-script.cc` 捕获，并通过 Promise 的拒绝处理机制传递到 DevTools，帮助开发者诊断异步问题。

这是第1部分，共2部分，请归纳一下它的功能:

总的来说，`v8/src/inspector/injected-script.cc` 的主要功能是 **作为 V8 Inspector 后端的核心组件，负责在 JavaScript 虚拟机和 DevTools 前端之间建立桥梁，实现代码求值、对象属性检查、Promise 结果处理和错误信息传递等关键的调试功能。** 它处理 JavaScript 的异步特性，并将 V8 内部的 JavaScript 对象和错误信息转换为 DevTools 可以理解和展示的协议格式。
```
### 提示词
```
这是目录为v8/src/inspector/injected-script.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/injected-script.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "src/inspector/injected-script.h"

#include <cmath>
#include <memory>
#include <unordered_set>

#include "../../third_party/inspector_protocol/crdtp/json.h"
#include "include/v8-container.h"
#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-inspector.h"
#include "include/v8-microtask-queue.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/custom-preview.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Protocol.h"
#include "src/inspector/remote-object-id.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-console.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-serialization-duplicate-tracker.h"
#include "src/inspector/v8-stack-trace-impl.h"
#include "src/inspector/v8-value-utils.h"
#include "src/inspector/value-mirror.h"

namespace v8_inspector {

namespace {
const char kGlobalHandleLabel[] = "DevTools console";
bool isResolvableNumberLike(String16 query) {
  return query == "Infinity" || query == "-Infinity" || query == "NaN";
}
}  // namespace

using protocol::Array;
using protocol::Maybe;
using protocol::Runtime::InternalPropertyDescriptor;
using protocol::Runtime::PrivatePropertyDescriptor;
using protocol::Runtime::PropertyDescriptor;
using protocol::Runtime::RemoteObject;

// static
void EvaluateCallback::sendSuccess(
    std::weak_ptr<EvaluateCallback> callback, InjectedScript* injectedScript,
    std::unique_ptr<protocol::Runtime::RemoteObject> result,
    protocol::Maybe<protocol::Runtime::ExceptionDetails> exceptionDetails) {
  std::shared_ptr<EvaluateCallback> cb = callback.lock();
  if (!cb) return;
  injectedScript->deleteEvaluateCallback(cb);
  CHECK_EQ(cb.use_count(), 1);
  cb->sendSuccess(std::move(result), std::move(exceptionDetails));
}

// static
void EvaluateCallback::sendFailure(std::weak_ptr<EvaluateCallback> callback,
                                   InjectedScript* injectedScript,
                                   const protocol::DispatchResponse& response) {
  std::shared_ptr<EvaluateCallback> cb = callback.lock();
  if (!cb) return;
  injectedScript->deleteEvaluateCallback(cb);
  CHECK_EQ(cb.use_count(), 1);
  cb->sendFailure(response);
}

class InjectedScript::ProtocolPromiseHandler {
 public:
  static void add(V8InspectorSessionImpl* session,
                  v8::Local<v8::Context> context, v8::Local<v8::Value> value,
                  int executionContextId, const String16& objectGroup,
                  std::unique_ptr<WrapOptions> wrapOptions, bool replMode,
                  bool throwOnSideEffect,
                  std::weak_ptr<EvaluateCallback> callback) {
    InjectedScript::ContextScope scope(session, executionContextId);
    Response response = scope.initialize();
    if (!response.IsSuccess()) return;

    v8::Local<v8::Promise> promise;
    v8::Local<v8::Promise::Resolver> resolver;
    if (value->IsPromise()) {
      // If value is a promise, we can chain the handlers directly onto `value`.
      promise = value.As<v8::Promise>();
    } else {
      // Otherwise we do `Promise.resolve(value)`.
      CHECK(!replMode);
      if (!v8::Promise::Resolver::New(context).ToLocal(&resolver)) {
        EvaluateCallback::sendFailure(callback, scope.injectedScript(),
                                      Response::InternalError());
        return;
      }
      if (!resolver->Resolve(context, value).FromMaybe(false)) {
        EvaluateCallback::sendFailure(callback, scope.injectedScript(),
                                      Response::InternalError());
        return;
      }
      promise = resolver->GetPromise();
    }

    V8InspectorImpl* inspector = session->inspector();
    PromiseHandlerTracker::Id handlerId =
        inspector->promiseHandlerTracker().create(
            session, executionContextId, objectGroup, std::move(wrapOptions),
            replMode, throwOnSideEffect, callback, promise);
    v8::Local<v8::Number> data =
        v8::Number::New(inspector->isolate(), handlerId);
    v8::Local<v8::Function> thenCallbackFunction =
        v8::Function::New(context, thenCallback, data, 0,
                          v8::ConstructorBehavior::kThrow)
            .ToLocalChecked();
    v8::Local<v8::Function> catchCallbackFunction =
        v8::Function::New(context, catchCallback, data, 0,
                          v8::ConstructorBehavior::kThrow)
            .ToLocalChecked();

    if (promise->Then(context, thenCallbackFunction, catchCallbackFunction)
            .IsEmpty()) {
      // Re-initialize after returning from JS.
      Response response = scope.initialize();
      if (!response.IsSuccess()) return;
      EvaluateCallback::sendFailure(callback, scope.injectedScript(),
                                    Response::InternalError());
    }
  }

 private:
  friend class PromiseHandlerTracker;

  static v8::Local<v8::String> GetDotReplResultString(v8::Isolate* isolate) {
    // TODO(szuend): Cache the string in a v8::Persistent handle.
    return v8::String::NewFromOneByte(
               isolate, reinterpret_cast<const uint8_t*>(".repl_result"))
        .ToLocalChecked();
  }

  static void thenCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    PromiseHandlerTracker::Id handlerId =
        static_cast<PromiseHandlerTracker::Id>(
            info.Data().As<v8::Number>()->Value());
    PromiseHandlerTracker& handlerTracker =
        static_cast<V8InspectorImpl*>(
            v8::debug::GetInspector(info.GetIsolate()))
            ->promiseHandlerTracker();
    // We currently store the handlers with the inspector. In rare cases the
    // inspector dies (discarding the handler) with the micro task queue
    // running after. Don't do anything in that case.
    ProtocolPromiseHandler* handler = handlerTracker.get(handlerId);
    if (!handler) return;
    v8::Local<v8::Value> value =
        info.Length() > 0 ? info[0]
                          : v8::Undefined(info.GetIsolate()).As<v8::Value>();
    handler->thenCallback(value);
    handlerTracker.discard(handlerId,
                           PromiseHandlerTracker::DiscardReason::kFulfilled);
  }

  static void catchCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    PromiseHandlerTracker::Id handlerId =
        static_cast<PromiseHandlerTracker::Id>(
            info.Data().As<v8::Number>()->Value());
    PromiseHandlerTracker& handlerTracker =
        static_cast<V8InspectorImpl*>(
            v8::debug::GetInspector(info.GetIsolate()))
            ->promiseHandlerTracker();
    // We currently store the handlers with the inspector. In rare cases the
    // inspector dies (discarding the handler) with the micro task queue
    // running after. Don't do anything in that case.
    ProtocolPromiseHandler* handler = handlerTracker.get(handlerId);
    if (!handler) return;
    v8::Local<v8::Value> value =
        info.Length() > 0 ? info[0]
                          : v8::Undefined(info.GetIsolate()).As<v8::Value>();
    handler->catchCallback(value);
    handlerTracker.discard(handlerId,
                           PromiseHandlerTracker::DiscardReason::kFulfilled);
  }

  ProtocolPromiseHandler(PromiseHandlerTracker::Id id,
                         V8InspectorSessionImpl* session,
                         int executionContextId, const String16& objectGroup,
                         std::unique_ptr<WrapOptions> wrapOptions,
                         bool replMode, bool throwOnSideEffect,
                         std::weak_ptr<EvaluateCallback> callback,
                         v8::Local<v8::Promise> evaluationResult)
      : m_inspector(session->inspector()),
        m_sessionId(session->sessionId()),
        m_contextGroupId(session->contextGroupId()),
        m_executionContextId(executionContextId),
        m_objectGroup(objectGroup),
        m_wrapOptions(std::move(wrapOptions)),
        m_replMode(replMode),
        m_throwOnSideEffect(throwOnSideEffect),
        m_callback(std::move(callback)),
        m_evaluationResult(m_inspector->isolate(), evaluationResult) {
    m_evaluationResult.SetWeak(reinterpret_cast<PromiseHandlerTracker::Id*>(id),
                               cleanup, v8::WeakCallbackType::kParameter);
  }

  static void cleanup(
      const v8::WeakCallbackInfo<PromiseHandlerTracker::Id>& data) {
    auto id = reinterpret_cast<PromiseHandlerTracker::Id>(data.GetParameter());
    PromiseHandlerTracker& handlerTracker =
        static_cast<V8InspectorImpl*>(
            v8::debug::GetInspector(data.GetIsolate()))
            ->promiseHandlerTracker();
    // {discard} deletes the {ProtocolPromiseHandler} which resets the handle.
    handlerTracker.discard(
        id, PromiseHandlerTracker::DiscardReason::kPromiseCollected);
  }

  void thenCallback(v8::Local<v8::Value> value) {
    // We don't need the m_evaluationResult in the `thenCallback`, but we also
    // don't want `cleanup` running in case we re-enter JS.
    m_evaluationResult.Reset();
    V8InspectorSessionImpl* session =
        m_inspector->sessionById(m_contextGroupId, m_sessionId);
    if (!session) return;
    InjectedScript::ContextScope scope(session, m_executionContextId);
    Response response = scope.initialize();
    if (!response.IsSuccess()) return;

    // In REPL mode the result is additionally wrapped in an object.
    // The evaluation result can be found at ".repl_result".
    v8::Local<v8::Value> result = value;
    if (m_replMode) {
      v8::Local<v8::Object> object;
      if (!result->ToObject(scope.context()).ToLocal(&object)) {
        EvaluateCallback::sendFailure(m_callback, scope.injectedScript(),
                                      response);
        return;
      }

      v8::Local<v8::String> name =
          GetDotReplResultString(m_inspector->isolate());
      if (!object->Get(scope.context(), name).ToLocal(&result)) {
        EvaluateCallback::sendFailure(m_callback, scope.injectedScript(),
                                      response);
        return;
      }
    }

    if (m_objectGroup == "console") {
      scope.injectedScript()->setLastEvaluationResult(result);
    }

    std::unique_ptr<protocol::Runtime::RemoteObject> wrappedValue;
    response = scope.injectedScript()->wrapObject(
        result, m_objectGroup, *m_wrapOptions, &wrappedValue);
    if (!response.IsSuccess()) {
      EvaluateCallback::sendFailure(m_callback, scope.injectedScript(),
                                    response);
      return;
    }
    EvaluateCallback::sendSuccess(m_callback, scope.injectedScript(),
                                  std::move(wrappedValue),
                                  Maybe<protocol::Runtime::ExceptionDetails>());
  }

  void catchCallback(v8::Local<v8::Value> result) {
    // Hold strongly onto m_evaluationResult now to prevent `cleanup` from
    // running in case any code below triggers GC.
    m_evaluationResult.ClearWeak();
    V8InspectorSessionImpl* session =
        m_inspector->sessionById(m_contextGroupId, m_sessionId);
    if (!session) return;
    InjectedScript::ContextScope scope(session, m_executionContextId);
    Response response = scope.initialize();
    if (!response.IsSuccess()) return;
    std::unique_ptr<protocol::Runtime::RemoteObject> wrappedValue;
    response = scope.injectedScript()->wrapObject(
        result, m_objectGroup, *m_wrapOptions, &wrappedValue);
    if (!response.IsSuccess()) {
      EvaluateCallback::sendFailure(m_callback, scope.injectedScript(),
                                    response);
      return;
    }
    v8::Isolate* isolate = session->inspector()->isolate();

    v8::MaybeLocal<v8::Message> maybeMessage =
        m_evaluationResult.IsEmpty()
            ? v8::MaybeLocal<v8::Message>()
            : v8::debug::GetMessageFromPromise(m_evaluationResult.Get(isolate));
    v8::Local<v8::Message> message;
    // In case a MessageObject was attached to the rejected promise, we
    // construct the exception details from the message object. Otherwise
    // we try to capture a fresh stack trace.
    if (maybeMessage.ToLocal(&message)) {
      v8::Local<v8::Value> exception = result;
      if (!m_throwOnSideEffect) {
        session->inspector()->client()->dispatchError(scope.context(), message,
                                                      exception);
      }
      protocol::Maybe<protocol::Runtime::ExceptionDetails> exceptionDetails;
      response = scope.injectedScript()->createExceptionDetails(
          message, exception, m_objectGroup, &exceptionDetails);
      if (!response.IsSuccess()) {
        EvaluateCallback::sendFailure(m_callback, scope.injectedScript(),
                                      response);
        return;
      }

      EvaluateCallback::sendSuccess(m_callback, scope.injectedScript(),
                                    std::move(wrappedValue),
                                    std::move(exceptionDetails));
      return;
    }

    String16 messageString;
    std::unique_ptr<V8StackTraceImpl> stack;
    if (result->IsNativeError()) {
      messageString =
          " " +
          toProtocolString(isolate,
                           result->ToDetailString(isolate->GetCurrentContext())
                               .ToLocalChecked());
      v8::Local<v8::StackTrace> stackTrace =
          v8::Exception::GetStackTrace(result);
      if (!stackTrace.IsEmpty()) {
        stack = m_inspector->debugger()->createStackTrace(stackTrace);
      }
    }
    if (!stack) {
      stack = m_inspector->debugger()->captureStackTrace(true);
    }

    // REPL mode implicitly handles the script like an async function.
    // Do not prepend the '(in promise)' prefix for these exceptions since that
    // would be confusing for the user. The stringified error is part of the
    // exception and does not need to be added in REPL mode, otherwise it would
    // be printed twice.
    String16 exceptionDetailsText =
        m_replMode ? "Uncaught" : "Uncaught (in promise)" + messageString;
    std::unique_ptr<protocol::Runtime::ExceptionDetails> exceptionDetails =
        protocol::Runtime::ExceptionDetails::create()
            .setExceptionId(m_inspector->nextExceptionId())
            .setText(exceptionDetailsText)
            .setLineNumber(stack && !stack->isEmpty() ? stack->topLineNumber()
                                                      : 0)
            .setColumnNumber(
                stack && !stack->isEmpty() ? stack->topColumnNumber() : 0)
            .build();
    response = scope.injectedScript()->addExceptionToDetails(
        result, exceptionDetails.get(), m_objectGroup);
    if (!response.IsSuccess()) {
      EvaluateCallback::sendFailure(m_callback, scope.injectedScript(),
                                    response);
      return;
    }
    if (stack)
      exceptionDetails->setStackTrace(
          stack->buildInspectorObjectImpl(m_inspector->debugger()));
    if (stack && !stack->isEmpty())
      exceptionDetails->setScriptId(
          String16::fromInteger(stack->topScriptId()));
    EvaluateCallback::sendSuccess(m_callback, scope.injectedScript(),
                                  std::move(wrappedValue),
                                  std::move(exceptionDetails));
  }

  V8InspectorImpl* m_inspector;
  int m_sessionId;
  int m_contextGroupId;
  int m_executionContextId;
  String16 m_objectGroup;
  std::unique_ptr<WrapOptions> m_wrapOptions;
  bool m_replMode;
  bool m_throwOnSideEffect;
  std::weak_ptr<EvaluateCallback> m_callback;
  v8::Global<v8::Promise> m_evaluationResult;
};

InjectedScript::InjectedScript(InspectedContext* context, int sessionId)
    : m_context(context), m_sessionId(sessionId) {}

InjectedScript::~InjectedScript() { discardEvaluateCallbacks(); }

namespace {
class PropertyAccumulator : public ValueMirror::PropertyAccumulator {
 public:
  explicit PropertyAccumulator(std::vector<PropertyMirror>* mirrors)
      : m_mirrors(mirrors) {}
  bool Add(PropertyMirror mirror) override {
    m_mirrors->push_back(std::move(mirror));
    return true;
  }

 private:
  std::vector<PropertyMirror>* m_mirrors;
};
}  // anonymous namespace

Response InjectedScript::getProperties(
    v8::Local<v8::Object> object, const String16& groupName, bool ownProperties,
    bool accessorPropertiesOnly, bool nonIndexedPropertiesOnly,
    const WrapOptions& wrapOptions,
    std::unique_ptr<Array<PropertyDescriptor>>* properties,
    Maybe<protocol::Runtime::ExceptionDetails>* exceptionDetails) {
  v8::HandleScope handles(m_context->isolate());
  v8::Local<v8::Context> context = m_context->context();
  v8::Isolate* isolate = m_context->isolate();
  int sessionId = m_sessionId;
  v8::TryCatch tryCatch(isolate);

  *properties = std::make_unique<Array<PropertyDescriptor>>();
  std::vector<PropertyMirror> mirrors;
  PropertyAccumulator accumulator(&mirrors);
  if (!ValueMirror::getProperties(context, object, ownProperties,
                                  accessorPropertiesOnly,
                                  nonIndexedPropertiesOnly, &accumulator)) {
    return createExceptionDetails(tryCatch, groupName, exceptionDetails);
  }
  for (const PropertyMirror& mirror : mirrors) {
    std::unique_ptr<PropertyDescriptor> descriptor =
        PropertyDescriptor::create()
            .setName(mirror.name)
            .setConfigurable(mirror.configurable)
            .setEnumerable(mirror.enumerable)
            .setIsOwn(mirror.isOwn)
            .build();
    std::unique_ptr<RemoteObject> remoteObject;
    if (mirror.value) {
      Response response = wrapObjectMirror(
          *mirror.value, groupName, wrapOptions, v8::MaybeLocal<v8::Value>(),
          kMaxCustomPreviewDepth, &remoteObject);
      if (!response.IsSuccess()) return response;
      descriptor->setValue(std::move(remoteObject));
      descriptor->setWritable(mirror.writable);
    }
    if (mirror.getter) {
      Response response =
          mirror.getter->buildRemoteObject(context, wrapOptions, &remoteObject);
      if (!response.IsSuccess()) return response;
      response = bindRemoteObjectIfNeeded(sessionId, context,
                                          mirror.getter->v8Value(isolate),
                                          groupName, remoteObject.get());
      if (!response.IsSuccess()) return response;
      descriptor->setGet(std::move(remoteObject));
    }
    if (mirror.setter) {
      Response response =
          mirror.setter->buildRemoteObject(context, wrapOptions, &remoteObject);
      if (!response.IsSuccess()) return response;
      response = bindRemoteObjectIfNeeded(sessionId, context,
                                          mirror.setter->v8Value(isolate),
                                          groupName, remoteObject.get());
      if (!response.IsSuccess()) return response;
      descriptor->setSet(std::move(remoteObject));
    }
    if (mirror.symbol) {
      Response response =
          mirror.symbol->buildRemoteObject(context, wrapOptions, &remoteObject);
      if (!response.IsSuccess()) return response;
      response = bindRemoteObjectIfNeeded(sessionId, context,
                                          mirror.symbol->v8Value(isolate),
                                          groupName, remoteObject.get());
      if (!response.IsSuccess()) return response;
      descriptor->setSymbol(std::move(remoteObject));
    }
    if (mirror.exception) {
      Response response = mirror.exception->buildRemoteObject(
          context, wrapOptions, &remoteObject);
      if (!response.IsSuccess()) return response;
      response = bindRemoteObjectIfNeeded(sessionId, context,
                                          mirror.exception->v8Value(isolate),
                                          groupName, remoteObject.get());
      if (!response.IsSuccess()) return response;
      descriptor->setValue(std::move(remoteObject));
      descriptor->setWasThrown(true);
    }
    (*properties)->emplace_back(std::move(descriptor));
  }
  return Response::Success();
}

Response InjectedScript::getInternalAndPrivateProperties(
    v8::Local<v8::Value> value, const String16& groupName,
    bool accessorPropertiesOnly,
    std::unique_ptr<protocol::Array<InternalPropertyDescriptor>>*
        internalProperties,
    std::unique_ptr<protocol::Array<PrivatePropertyDescriptor>>*
        privateProperties) {
  *internalProperties = std::make_unique<Array<InternalPropertyDescriptor>>();
  *privateProperties = std::make_unique<Array<PrivatePropertyDescriptor>>();

  if (!value->IsObject()) return Response::Success();

  v8::Local<v8::Object> value_obj = value.As<v8::Object>();

  v8::Local<v8::Context> context = m_context->context();
  int sessionId = m_sessionId;

  if (!accessorPropertiesOnly) {
    std::vector<InternalPropertyMirror> internalPropertiesWrappers;
    ValueMirror::getInternalProperties(m_context->context(), value_obj,
                                       &internalPropertiesWrappers);
    for (const auto& internalProperty : internalPropertiesWrappers) {
      std::unique_ptr<RemoteObject> remoteObject;
      Response response = internalProperty.value->buildRemoteObject(
          m_context->context(), WrapOptions({WrapMode::kIdOnly}),
          &remoteObject);
      if (!response.IsSuccess()) return response;
      response = bindRemoteObjectIfNeeded(
          sessionId, context,
          internalProperty.value->v8Value(context->GetIsolate()), groupName,
          remoteObject.get());
      if (!response.IsSuccess()) return response;
      (*internalProperties)
          ->emplace_back(InternalPropertyDescriptor::create()
                             .setName(internalProperty.name)
                             .setValue(std::move(remoteObject))
                             .build());
    }
  }

  std::vector<PrivatePropertyMirror> privatePropertyWrappers =
      ValueMirror::getPrivateProperties(context, value_obj,
                                        accessorPropertiesOnly);
  for (const auto& privateProperty : privatePropertyWrappers) {
    std::unique_ptr<PrivatePropertyDescriptor> descriptor =
        PrivatePropertyDescriptor::create()
            .setName(privateProperty.name)
            .build();

    std::unique_ptr<RemoteObject> remoteObject;
    DCHECK((privateProperty.getter || privateProperty.setter) ^
           (!!privateProperty.value));
    if (privateProperty.value) {
      Response response = privateProperty.value->buildRemoteObject(
          context, WrapOptions({WrapMode::kIdOnly}), &remoteObject);
      if (!response.IsSuccess()) return response;
      response = bindRemoteObjectIfNeeded(
          sessionId, context,
          privateProperty.value->v8Value(context->GetIsolate()), groupName,
          remoteObject.get());
      if (!response.IsSuccess()) return response;
      descriptor->setValue(std::move(remoteObject));
    }

    if (privateProperty.getter) {
      Response response = privateProperty.getter->buildRemoteObject(
          context, WrapOptions({WrapMode::kIdOnly}), &remoteObject);
      if (!response.IsSuccess()) return response;
      response = bindRemoteObjectIfNeeded(
          sessionId, context,
          privateProperty.getter->v8Value(context->GetIsolate()), groupName,
          remoteObject.get());
      if (!response.IsSuccess()) return response;
      descriptor->setGet(std::move(remoteObject));
    }

    if (privateProperty.setter) {
      Response response = privateProperty.setter->buildRemoteObject(
          context, WrapOptions({WrapMode::kIdOnly}), &remoteObject);
      if (!response.IsSuccess()) return response;
      response = bindRemoteObjectIfNeeded(
          sessionId, context,
          privateProperty.setter->v8Value(context->GetIsolate()), groupName,
          remoteObject.get());
      if (!response.IsSuccess()) return response;
      descriptor->setSet(std::move(remoteObject));
    }

    (*privateProperties)->emplace_back(std::move(descriptor));
  }
  return Response::Success();
}

void InjectedScript::releaseObject(const String16& objectId) {
  std::unique_ptr<RemoteObjectId> remoteId;
  Response response = RemoteObjectId::parse(objectId, &remoteId);
  if (response.IsSuccess()) unbindObject(remoteId->id());
}

Response InjectedScript::wrapObject(
    v8::Local<v8::Value> value, const String16& groupName,
    const WrapOptions& wrapOptions,
    std::unique_ptr<protocol::Runtime::RemoteObject>* result) {
  return wrapObject(value, groupName, wrapOptions, v8::MaybeLocal<v8::Value>(),
                    kMaxCustomPreviewDepth, result);
}

Response InjectedScript::wrapObject(
    v8::Local<v8::Value> value, const String16& groupName,
    const WrapOptions& wrapOptions,
    v8::MaybeLocal<v8::Value> customPreviewConfig, int maxCustomPreviewDepth,
    std::unique_ptr<protocol::Runtime::RemoteObject>* result) {
  v8::Local<v8::Context> context = m_context->context();
  v8::Context::Scope contextScope(context);
  std::unique_ptr<ValueMirror> mirror = ValueMirror::create(context, value);
  if (!mirror) return Response::InternalError();
  return wrapObjectMirror(*mirror, groupName, wrapOptions, customPreviewConfig,
                          maxCustomPreviewDepth, result);
}

Response InjectedScript::wrapObjectMirror(
    const ValueMirror& mirror, const String16& groupName,
    const WrapOptions& wrapOptions,
    v8::MaybeLocal<v8::Value> customPreviewConfig, int maxCustomPreviewDepth,
    std::unique_ptr<protocol::Runtime::RemoteObject>* result) {
  int customPreviewEnabled = m_customPreviewEnabled;
  int sessionId = m_sessionId;
  v8::Local<v8::Context> context = m_context->context();
  v8::Context::Scope contextScope(context);
  Response response = mirror.buildRemoteObject(context, wrapOptions, result);
  if (!response.IsSuccess()) return response;
  v8::Local<v8::Value> value = mirror.v8Value(context->GetIsolate());
  response = bindRemoteObjectIfNeeded(sessionId, context, value, groupName,
                                      result->get());
  if (!response.IsSuccess()) return response;
  if (customPreviewEnabled && value->IsObject()) {
    std::unique_ptr<protocol::Runtime::CustomPreview> customPreview;
    generateCustomPreview(m_context->isolate(), sessionId, groupName,
                          value.As<v8::Object>(), customPreviewConfig,
                          maxCustomPreviewDepth, &customPreview);
    if (customPreview) (*result)->setCustomPreview(std::move(customPreview));
  }
  if (wrapOptions.mode == WrapMode::kDeep) {
    V8SerializationDuplicateTracker duplicateTracker{context};

    std::unique_ptr<protocol::DictionaryValue> deepSerializedValueDict;
    response = mirror.buildDeepSerializedValue(
        context, wrapOptions.serializationOptions.maxDepth,
        wrapOptions.serializationOptions.additionalParameters.Get(
            m_context->isolate()),
        duplicateTracker, &deepSerializedValueDict);
    if (!response.IsSuccess()) return response;

    String16 type;
    deepSerializedValueDict->getString("type", &type);

    std::unique_ptr<protocol::Runtime::DeepSerializedValue>
        deepSerializedValue = protocol::Runtime::DeepSerializedValue::create()
                                  .setType(type)
                                  .build();

    protocol::Value* maybeValue = deepSerializedValueDict->get("value");
    if (maybeValue != nullptr) {
      deepSerializedValue->setValue(maybeValue->clone());
    }

    int weakLocalObjectReference;
    if (deepSerializedValueDict->getInteger("weakLocalObjectReference",
                                            &weakLocalObjectReference)) {
      deepSerializedValue->setWeakLocalObjectReference(
          weakLocalObjectReference);
    }

    if (!response.IsSuccess()) return response;
    (*result)->setDeepSerializedValue(std::move(deepSerializedValue));
  }

  return Response::Success();
}

std::unique_ptr<protocol::Runtime::RemoteObject> InjectedScript::wrapTable(
    v8::Local<v8::Object> table, v8::MaybeLocal<v8::Array> maybeColumns) {
  using protocol::Array;
  using protocol::Runtime::ObjectPreview;
  using protocol::Runtime::PropertyPreview;
  using protocol::Runtime::RemoteObject;

  v8::Isolate* isolate = m_context->isolate();
  v8::HandleScope handles(isolate);
  v8::Local<v8::Context> context = m_context->context();

  std::unique_ptr<RemoteObject> remoteObject;
  Response response = wrapObject(
      table, "console", WrapOptions({WrapMode::kIdOnly}), &remoteObject);
  if (!remoteObject || !response.IsSuccess()) return nullptr;

  auto mirror = ValueMirror::create(context, table);
  std::unique_ptr<ObjectPreview> preview;
  int limit = 1000;
  mirror->buildObjectPreview(context, true /* generatePreviewForTable */,
                             &limit, &limit, &preview);
  if (!preview) return nullptr;

  std::vector<String16> selectedColumns;
  std::unordered_set<String16> columnSet;
  v8::Local<v8::Array> v8Columns;
  if (maybeColumns.ToLocal(&v8Columns)) {
    for (uint32_t i = 0; i < v8Columns->Length(); ++i) {
      v8::Local<v8::Value> column;
      if (v8Columns->Get(context, i).ToLocal(&column) && column->IsString()) {
        String16 name = toProtocolString(isolate, column.As<v8::String>());
        if (columnSet.find(name) == columnSet.end()) {
          columnSet.insert(name);
          selectedColumns.push_back(name);
        }
      }
    }
  }
  if (!selectedColumns.empty()) {
    for (const std::unique_ptr<PropertyPreview>& prop :
         *preview->getProperties()) {
      ObjectPreview* columnPreview = prop->getValuePreview(nullptr);
      if (!columnPreview) continue;
      // Use raw pointer here since the lifetime of each PropertyPreview is
      // ensured by columnPreview. This saves an additional clone.
      std::unordered_map<String16, PropertyPreview*> columnMap;
      for (const std::unique_ptr<PropertyPreview>& property :
           *columnPreview->getProperties()) {
        if (columnSet.find(property->getName()) == columnSet.end()) continue;
        columnMap[property->getName()] = property.get();
      }
      auto filtered = std::make_unique<Array<PropertyPreview>>();
      for (const String16& column : selectedColumns) {
        if (columnMap.find(column) == columnMap.end()) continue;
        filtered->push_back(columnMap[column]->Clone());
      }
      columnPreview->setProperties(std::move(filtered));
    }
  }
  remoteObject->setPreview(std::move(preview));
  return remoteObject;
}

void InjectedScript::addPromiseCallback(
    V8InspectorSessionImpl* session, v8::MaybeLocal<v8::Value> value,
    const String16& objectGroup, std::unique_ptr<WrapOptions> wrapOptions,
    bool replMode, bool throwOnSideEffect,
    std::shared_ptr<EvaluateCallback> callback) {
  m_evaluateCallbacks.insert(callback);
  // After stashing the shared_ptr in `m_evaluateCallback`, we reset `callback`.
  // `ProtocolPromiseHandler:add` can take longer than the life time of this
  // `InjectedScript` and we don't want `callback` to survive that.
  std::weak_ptr<EvaluateCallback> weak_callback = callback;
  callback.reset();
  CHECK_EQ(weak_callback.use_count(), 1);

  if (value.IsEmpty()) {
```