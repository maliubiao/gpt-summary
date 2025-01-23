Response: The user wants to understand the functionality of the `injected-script.cc` file in the V8 inspector. I need to:

1. **Summarize the core responsibilities** of this file based on its content. Keywords like "inspector", "script", "evaluate", "object", "properties", "remote object", and interactions with JavaScript values are important clues.
2. **Identify connections to JavaScript functionality.** This involves recognizing how the C++ code interacts with and reflects JavaScript concepts like objects, properties, promises, and evaluation.
3. **Provide concrete JavaScript examples** to illustrate these connections. These examples should show how the functionality implemented in `injected-script.cc` relates to observable behavior in JavaScript.

**Plan:**

1. **High-level overview:** Start with a general statement about the file's role in bridging the V8 engine and the inspector.
2. **Key functionalities:** Detail the major features implemented, such as:
    * Evaluating JavaScript code.
    * Inspecting JavaScript objects (properties, internal properties, private properties).
    * Wrapping JavaScript values into "remote objects" for the inspector.
    * Handling promises.
    * Managing object groups and lifetimes for the inspector.
3. **JavaScript interaction:** Explain how these functionalities relate to actions a developer might take in the browser's DevTools.
4. **Illustrative examples:**  Craft concise JavaScript examples that demonstrate specific functionalities, linking them back to the C++ code's role.
`v8/src/inspector/injected-script.cc` 文件是 V8 Inspector 中一个核心的 C++ 源代码文件，它的主要功能是 **提供在 JavaScript 执行环境中执行代码和检查 JavaScript 对象的能力，并将结果反馈给 Inspector 前端**。  它充当了 V8 JavaScript 引擎和 Inspector 协议之间的桥梁。

以下是该文件的一些关键职责和功能：

**核心功能归纳：**

1. **代码执行 (Evaluation):**
   - 允许 Inspector 前端向 JavaScript 执行环境发送代码字符串进行执行。
   - 处理执行结果，包括成功的结果和发生的异常。
   - 支持异步代码执行，特别是针对 Promise 的处理。
   - 维护最近一次执行的结果，用于控制台的 `$_` 变量等。

2. **对象检查 (Object Inspection):**
   - 允许 Inspector 前端请求获取 JavaScript 对象的属性（包括自有属性和继承属性）。
   - 支持获取访问器属性 (getter/setter)。
   - 可以获取对象的内部属性 (Internal Properties) 和私有属性 (Private Properties)。
   - 将 JavaScript 对象包装成 `RemoteObject`，以便在 Inspector 前端进行表示和操作。

3. **远程对象管理 (Remote Object Management):**
   - 创建和管理 `RemoteObject` 的生命周期，`RemoteObject` 是 Inspector 协议中用于表示 JavaScript 对象的抽象。
   - 为 `RemoteObject` 生成唯一的 ID，用于在 Inspector 前端和后端之间引用对象。
   - 支持对象分组，方便 Inspector 前端批量释放不再需要的对象。

4. **Promise 处理 (Promise Handling):**
   - 专门处理 JavaScript Promise 的执行结果。
   - 允许 Inspector 前端在 Promise resolve 或 reject 时接收通知。
   - 将 Promise 的结果包装成 `RemoteObject` 并返回。

5. **异常处理 (Exception Handling):**
   - 捕获 JavaScript 代码执行过程中抛出的异常。
   - 将异常信息格式化成 `ExceptionDetails` 对象，包含错误消息、堆栈信息等。
   - 将异常对象也包装成 `RemoteObject` 发送给 Inspector 前端。

6. **自定义预览 (Custom Preview):**
   - 支持为特定类型的 JavaScript 对象生成自定义的预览信息，以便在 Inspector 前端更友好地展示。

7. **命令行 API (Command Line API):**
   - 提供一些内置的命令行 API (例如 `$`、`$$`、`inspect`)，方便在 Inspector 控制台中进行交互。

**与 JavaScript 功能的关系及 JavaScript 示例：**

`injected-script.cc` 很大程度上是围绕着与 JavaScript 的交互展开的。它提供的功能直接对应了开发者在使用浏览器 DevTools 时能够进行的操作。

**示例 1：代码执行和结果返回**

- **C++ (`injected-script.cc` 的功能):**  接收来自 Inspector 前端的 JavaScript 代码字符串，使用 V8 引擎执行，并将执行结果（可以是值或异常）转换成 `RemoteObject` 返回。

- **JavaScript (DevTools 控制台):**

```javascript
// 在 DevTools 控制台中输入
2 + 2;
```

- **解释:**  `injected-script.cc` 中的代码会接收到字符串 `"2 + 2;"`，交给 V8 执行，得到结果 `4`。然后，`4` 会被包装成一个 `RemoteObject`，其类型是 "number"，值为 `4`，并发送回 DevTools 前端显示。

**示例 2：对象属性检查**

- **C++ (`injected-script.cc` 的功能):**  接收 Inspector 前端的请求，获取指定 JavaScript 对象的属性信息，并将属性名、属性值（包装成 `RemoteObject`）、属性特性（可写、可枚举、可配置等）组织成 `PropertyDescriptor` 数组返回。

- **JavaScript (DevTools "Elements" 或 "Console" 面板):**

```javascript
const myObject = { a: 1, b: 'hello' };
// 在 DevTools 中查看 myObject 的属性
```

- **解释:** 当你在 DevTools 中查看 `myObject` 的属性时，Inspector 前端会发送请求到 V8 后端。`injected-script.cc` 的代码会获取 `myObject` 的属性 `a` 和 `b`，并将它们的值 `1` 和 `'hello'` 分别包装成 `RemoteObject`，然后将属性名和 `RemoteObject` 等信息组合成 `PropertyDescriptor` 返回给前端展示。

**示例 3：Promise 的处理**

- **C++ (`injected-script.cc` 的功能):**  能够执行返回 Promise 的代码，并在 Promise resolve 或 reject 时通知 Inspector 前端，并将 Promise 的结果或拒绝原因包装成 `RemoteObject`。

- **JavaScript (DevTools 控制台):**

```javascript
const myPromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve('Promise resolved!');
  }, 1000);
});

myPromise.then(result => console.log(result));
```

- **解释:**  当执行这段代码时，`injected-script.cc` 会跟踪 `myPromise` 的状态。当 Promise 在 1 秒后 resolve 时，它会将结果 `"Promise resolved!"` 包装成 `RemoteObject`，并通知 DevTools 前端，以便控制台能够显示该结果。

**示例 4：异常的捕获和展示**

- **C++ (`injected-script.cc` 的功能):**  捕获 JavaScript 代码执行过程中发生的异常，提取异常信息（消息、堆栈），并将异常对象包装成 `RemoteObject`，生成 `ExceptionDetails` 对象返回给 Inspector 前端。

- **JavaScript (DevTools 控制台):**

```javascript
function causeError() {
  throw new Error('Something went wrong!');
}

causeError();
```

- **解释:**  当 `causeError()` 被执行时，`injected-script.cc` 会捕获 `Error` 异常。它会提取错误消息 `"Something went wrong!"`，生成堆栈信息，并将 `Error` 对象包装成 `RemoteObject`。这些信息会被组合成 `ExceptionDetails`，发送到 DevTools 前端，从而在控制台中显示错误信息和堆栈跟踪。

总而言之，`v8/src/inspector/injected-script.cc` 文件是 V8 Inspector 的一个关键组成部分，它实现了 Inspector 与 JavaScript 执行环境交互的核心机制，使得开发者可以通过 DevTools 对 JavaScript 代码进行执行、检查和调试。它的功能直接对应了我们在 DevTools 中所能观察和操作的 JavaScript 世界。

### 提示词
```
这是目录为v8/src/inspector/injected-script.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
    EvaluateCallback::sendFailure(weak_callback, this,
                                  Response::InternalError());
    return;
  }

  v8::MicrotasksScope microtasksScope(m_context->context(),
                                      v8::MicrotasksScope::kRunMicrotasks);
  ProtocolPromiseHandler::add(session, m_context->context(),
                              value.ToLocalChecked(), m_context->contextId(),
                              objectGroup, std::move(wrapOptions), replMode,
                              throwOnSideEffect, weak_callback);
  // Do not add any code here! `this` might be invalid.
  // `ProtocolPromiseHandler::add` calls into JS which could kill this
  // `InjectedScript`.
}

void InjectedScript::discardEvaluateCallbacks() {
  while (!m_evaluateCallbacks.empty()) {
    EvaluateCallback::sendFailure(
        *m_evaluateCallbacks.begin(), this,
        Response::ServerError("Execution context was destroyed."));
  }
  CHECK(m_evaluateCallbacks.empty());
}

void InjectedScript::deleteEvaluateCallback(
    std::shared_ptr<EvaluateCallback> callback) {
  auto it = m_evaluateCallbacks.find(callback);
  CHECK_NE(it, m_evaluateCallbacks.end());
  m_evaluateCallbacks.erase(it);
}

Response InjectedScript::findObject(const RemoteObjectId& objectId,
                                    v8::Local<v8::Value>* outObject) const {
  auto it = m_idToWrappedObject.find(objectId.id());
  if (it == m_idToWrappedObject.end())
    return Response::ServerError("Could not find object with given id");
  *outObject = it->second.Get(m_context->isolate());
  return Response::Success();
}

String16 InjectedScript::objectGroupName(const RemoteObjectId& objectId) const {
  if (objectId.id() <= 0) return String16();
  auto it = m_idToObjectGroupName.find(objectId.id());
  return it != m_idToObjectGroupName.end() ? it->second : String16();
}

void InjectedScript::releaseObjectGroup(const String16& objectGroup) {
  if (objectGroup == "console") m_lastEvaluationResult.Reset();
  if (objectGroup.isEmpty()) return;
  auto it = m_nameToObjectGroup.find(objectGroup);
  if (it == m_nameToObjectGroup.end()) return;
  for (int id : it->second) unbindObject(id);
  m_nameToObjectGroup.erase(it);
}

void InjectedScript::setCustomObjectFormatterEnabled(bool enabled) {
  m_customPreviewEnabled = enabled;
}

v8::Local<v8::Value> InjectedScript::lastEvaluationResult() const {
  if (m_lastEvaluationResult.IsEmpty())
    return v8::Undefined(m_context->isolate());
  return m_lastEvaluationResult.Get(m_context->isolate());
}

void InjectedScript::setLastEvaluationResult(v8::Local<v8::Value> result) {
  m_lastEvaluationResult.Reset(m_context->isolate(), result);
  m_lastEvaluationResult.AnnotateStrongRetainer(kGlobalHandleLabel);
}

Response InjectedScript::resolveCallArgument(
    protocol::Runtime::CallArgument* callArgument,
    v8::Local<v8::Value>* result) {
  if (callArgument->hasObjectId()) {
    std::unique_ptr<RemoteObjectId> remoteObjectId;
    Response response =
        RemoteObjectId::parse(callArgument->getObjectId(""), &remoteObjectId);
    if (!response.IsSuccess()) return response;
    if (remoteObjectId->contextId() != m_context->contextId() ||
        remoteObjectId->isolateId() != m_context->inspector()->isolateId()) {
      return Response::ServerError(
          "Argument should belong to the same JavaScript world as target "
          "object");
    }
    return findObject(*remoteObjectId, result);
  }
  if (callArgument->hasValue() || callArgument->hasUnserializableValue()) {
    String16 value;
    if (callArgument->hasValue()) {
      std::vector<uint8_t> json;
      v8_crdtp::json::ConvertCBORToJSON(
          v8_crdtp::SpanFrom(callArgument->getValue(nullptr)->Serialize()),
          &json);
      value =
          "(" +
          String16(reinterpret_cast<const char*>(json.data()), json.size()) +
          ")";
    } else {
      String16 unserializableValue = callArgument->getUnserializableValue("");
      // Protect against potential identifier resolution for NaN and Infinity.
      if (isResolvableNumberLike(unserializableValue))
        value = "Number(\"" + unserializableValue + "\")";
      else
        value = unserializableValue;
    }
    if (!m_context->inspector()
             ->compileAndRunInternalScript(
                 m_context->context(), toV8String(m_context->isolate(), value))
             .ToLocal(result)) {
      return Response::ServerError(
          "Couldn't parse value object in call argument");
    }
    return Response::Success();
  }
  *result = v8::Undefined(m_context->isolate());
  return Response::Success();
}

Response InjectedScript::addExceptionToDetails(
    v8::Local<v8::Value> exception,
    protocol::Runtime::ExceptionDetails* exceptionDetails,
    const String16& objectGroup) {
  if (exception.IsEmpty()) return Response::Success();
  std::unique_ptr<protocol::Runtime::RemoteObject> wrapped;
  Response response =
      wrapObject(exception, objectGroup,
                 exception->IsNativeError() ? WrapOptions({WrapMode::kIdOnly})
                                            : WrapOptions({WrapMode::kPreview}),
                 &wrapped);
  if (!response.IsSuccess()) return response;
  exceptionDetails->setException(std::move(wrapped));
  return Response::Success();
}

Response InjectedScript::createExceptionDetails(
    const v8::TryCatch& tryCatch, const String16& objectGroup,
    Maybe<protocol::Runtime::ExceptionDetails>* result) {
  if (!tryCatch.HasCaught()) return Response::InternalError();
  v8::Local<v8::Message> message = tryCatch.Message();
  v8::Local<v8::Value> exception = tryCatch.Exception();
  return createExceptionDetails(message, exception, objectGroup, result);
}

Response InjectedScript::createExceptionDetails(
    v8::Local<v8::Message> message, v8::Local<v8::Value> exception,
    const String16& objectGroup,
    Maybe<protocol::Runtime::ExceptionDetails>* result) {
  String16 messageText =
      message.IsEmpty()
          ? String16()
          : toProtocolString(m_context->isolate(), message->Get());
  std::unique_ptr<protocol::Runtime::ExceptionDetails> exceptionDetails =
      protocol::Runtime::ExceptionDetails::create()
          .setExceptionId(m_context->inspector()->nextExceptionId())
          .setText(exception.IsEmpty() ? messageText : String16("Uncaught"))
          .setLineNumber(
              message.IsEmpty()
                  ? 0
                  : message->GetLineNumber(m_context->context()).FromMaybe(1) -
                        1)
          .setColumnNumber(
              message.IsEmpty()
                  ? 0
                  : message->GetStartColumn(m_context->context()).FromMaybe(0))
          .build();
  if (!message.IsEmpty()) {
    exceptionDetails->setScriptId(
        String16::fromInteger(message->GetScriptOrigin().ScriptId()));
    v8::Local<v8::StackTrace> stackTrace = message->GetStackTrace();
    if (!stackTrace.IsEmpty() && stackTrace->GetFrameCount() > 0) {
      std::unique_ptr<V8StackTraceImpl> v8StackTrace =
          m_context->inspector()->debugger()->createStackTrace(stackTrace);
      if (v8StackTrace) {
        exceptionDetails->setStackTrace(v8StackTrace->buildInspectorObjectImpl(
            m_context->inspector()->debugger()));
      }
    }
  }
  Response response =
      addExceptionToDetails(exception, exceptionDetails.get(), objectGroup);
  if (!response.IsSuccess()) return response;
  *result = std::move(exceptionDetails);
  return Response::Success();
}

Response InjectedScript::wrapEvaluateResult(
    v8::MaybeLocal<v8::Value> maybeResultValue, const v8::TryCatch& tryCatch,
    const String16& objectGroup, const WrapOptions& wrapOptions,
    bool throwOnSideEffect,
    std::unique_ptr<protocol::Runtime::RemoteObject>* result,
    Maybe<protocol::Runtime::ExceptionDetails>* exceptionDetails) {
  v8::Local<v8::Value> resultValue;
  if (!tryCatch.HasCaught()) {
    if (!maybeResultValue.ToLocal(&resultValue)) {
      if (!tryCatch.CanContinue()) {
        return Response::ServerError("Execution was terminated");
      }
      return Response::InternalError();
    }
    Response response =
        wrapObject(resultValue, objectGroup, wrapOptions, result);
    if (!response.IsSuccess()) return response;
    if (objectGroup == "console") {
      m_lastEvaluationResult.Reset(m_context->isolate(), resultValue);
      m_lastEvaluationResult.AnnotateStrongRetainer(kGlobalHandleLabel);
    }
  } else {
    if (tryCatch.HasTerminated() || !tryCatch.CanContinue()) {
      return Response::ServerError("Execution was terminated");
    }
    v8::Local<v8::Value> exception = tryCatch.Exception();
    if (!throwOnSideEffect) {
      m_context->inspector()->client()->dispatchError(
          m_context->context(), tryCatch.Message(), exception);
    }
    Response response = wrapObject(exception, objectGroup,
                                   exception->IsNativeError()
                                       ? WrapOptions({WrapMode::kIdOnly})
                                       : WrapOptions({WrapMode::kPreview}),
                                   result);
    if (!response.IsSuccess()) return response;
    // We send exception in result for compatibility reasons, even though it's
    // accessible through exceptionDetails.exception.
    response = createExceptionDetails(tryCatch, objectGroup, exceptionDetails);
    if (!response.IsSuccess()) return response;
  }
  return Response::Success();
}

v8::Local<v8::Object> InjectedScript::commandLineAPI() {
  if (m_commandLineAPI.IsEmpty()) {
    v8::debug::DisableBreakScope disable_break(m_context->isolate());
    m_commandLineAPI.Reset(
        m_context->isolate(),
        m_context->inspector()->console()->createCommandLineAPI(
            m_context->context(), m_sessionId));
    m_commandLineAPI.AnnotateStrongRetainer(kGlobalHandleLabel);
  }
  return m_commandLineAPI.Get(m_context->isolate());
}

InjectedScript::Scope::Scope(V8InspectorSessionImpl* session)
    : m_inspector(session->inspector()),
      m_injectedScript(nullptr),
      m_handleScope(m_inspector->isolate()),
      m_tryCatch(m_inspector->isolate()),
      m_ignoreExceptionsAndMuteConsole(false),
      m_previousPauseOnExceptionsState(v8::debug::NoBreakOnException),
      m_userGesture(false),
      m_allowEval(false),
      m_contextGroupId(session->contextGroupId()),
      m_sessionId(session->sessionId()) {}

Response InjectedScript::Scope::initialize() {
  cleanup();
  V8InspectorSessionImpl* session =
      m_inspector->sessionById(m_contextGroupId, m_sessionId);
  if (!session) return Response::InternalError();
  Response response = findInjectedScript(session);
  if (!response.IsSuccess()) return response;
  m_context = m_injectedScript->context()->context();
  m_context->Enter();
  if (m_allowEval) m_context->AllowCodeGenerationFromStrings(true);
  return Response::Success();
}

void InjectedScript::Scope::installCommandLineAPI() {
  DCHECK(m_injectedScript && !m_context.IsEmpty() &&
         !m_commandLineAPIScope.get());
  V8InspectorSessionImpl* session =
      m_inspector->sessionById(m_contextGroupId, m_sessionId);
  if (session->clientTrustLevel() != V8Inspector::kFullyTrusted) {
    return;
  }
  m_commandLineAPIScope.reset(new V8Console::CommandLineAPIScope(
      m_context, m_injectedScript->commandLineAPI(), m_context->Global()));
}

void InjectedScript::Scope::ignoreExceptionsAndMuteConsole() {
  DCHECK(!m_ignoreExceptionsAndMuteConsole);
  m_ignoreExceptionsAndMuteConsole = true;
  m_inspector->client()->muteMetrics(m_contextGroupId);
  m_inspector->muteExceptions(m_contextGroupId);
  m_previousPauseOnExceptionsState =
      setPauseOnExceptionsState(v8::debug::NoBreakOnException);
}

v8::debug::ExceptionBreakState InjectedScript::Scope::setPauseOnExceptionsState(
    v8::debug::ExceptionBreakState newState) {
  if (!m_inspector->debugger()->enabled()) return newState;
  v8::debug::ExceptionBreakState presentState =
      m_inspector->debugger()->getPauseOnExceptionsState();
  if (presentState != newState)
    m_inspector->debugger()->setPauseOnExceptionsState(newState);
  return presentState;
}

void InjectedScript::Scope::pretendUserGesture() {
  DCHECK(!m_userGesture);
  m_userGesture = true;
  m_inspector->client()->beginUserGesture();
}

void InjectedScript::Scope::allowCodeGenerationFromStrings() {
  DCHECK(!m_allowEval);
  if (m_context->IsCodeGenerationFromStringsAllowed()) return;
  m_allowEval = true;
  m_context->AllowCodeGenerationFromStrings(true);
}

void InjectedScript::Scope::setTryCatchVerbose() {
  m_tryCatch.SetVerbose(true);
}

void InjectedScript::Scope::cleanup() {
  m_commandLineAPIScope.reset();
  if (!m_context.IsEmpty()) {
    if (m_allowEval) m_context->AllowCodeGenerationFromStrings(false);
    m_context->Exit();
    m_context.Clear();
  }
}

InjectedScript::Scope::~Scope() {
  if (m_ignoreExceptionsAndMuteConsole) {
    setPauseOnExceptionsState(m_previousPauseOnExceptionsState);
    m_inspector->client()->unmuteMetrics(m_contextGroupId);
    m_inspector->unmuteExceptions(m_contextGroupId);
  }
  if (m_userGesture) m_inspector->client()->endUserGesture();
  cleanup();
}

InjectedScript::ContextScope::ContextScope(V8InspectorSessionImpl* session,
                                           int executionContextId)
    : InjectedScript::Scope(session),
      m_executionContextId(executionContextId) {}

InjectedScript::ContextScope::~ContextScope() = default;

Response InjectedScript::ContextScope::findInjectedScript(
    V8InspectorSessionImpl* session) {
  return session->findInjectedScript(m_executionContextId, m_injectedScript);
}

InjectedScript::ObjectScope::ObjectScope(V8InspectorSessionImpl* session,
                                         const String16& remoteObjectId)
    : InjectedScript::Scope(session), m_remoteObjectId(remoteObjectId) {}

InjectedScript::ObjectScope::~ObjectScope() = default;

Response InjectedScript::ObjectScope::findInjectedScript(
    V8InspectorSessionImpl* session) {
  std::unique_ptr<RemoteObjectId> remoteId;
  Response response = RemoteObjectId::parse(m_remoteObjectId, &remoteId);
  if (!response.IsSuccess()) return response;
  InjectedScript* injectedScript = nullptr;
  response = session->findInjectedScript(remoteId.get(), injectedScript);
  if (!response.IsSuccess()) return response;
  m_objectGroupName = injectedScript->objectGroupName(*remoteId);
  response = injectedScript->findObject(*remoteId, &m_object);
  if (!response.IsSuccess()) return response;
  m_injectedScript = injectedScript;
  return Response::Success();
}

InjectedScript::CallFrameScope::CallFrameScope(V8InspectorSessionImpl* session,
                                               const String16& remoteObjectId)
    : InjectedScript::Scope(session), m_remoteCallFrameId(remoteObjectId) {}

InjectedScript::CallFrameScope::~CallFrameScope() = default;

Response InjectedScript::CallFrameScope::findInjectedScript(
    V8InspectorSessionImpl* session) {
  std::unique_ptr<RemoteCallFrameId> remoteId;
  Response response = RemoteCallFrameId::parse(m_remoteCallFrameId, &remoteId);
  if (!response.IsSuccess()) return response;
  m_frameOrdinal = static_cast<size_t>(remoteId->frameOrdinal());
  return session->findInjectedScript(remoteId.get(), m_injectedScript);
}

String16 InjectedScript::bindObject(v8::Local<v8::Value> value,
                                    const String16& groupName) {
  if (m_lastBoundObjectId <= 0) m_lastBoundObjectId = 1;
  int id = m_lastBoundObjectId++;
  m_idToWrappedObject[id].Reset(m_context->isolate(), value);
  m_idToWrappedObject[id].AnnotateStrongRetainer(kGlobalHandleLabel);
  if (!groupName.isEmpty() && id > 0) {
    m_idToObjectGroupName[id] = groupName;
    m_nameToObjectGroup[groupName].push_back(id);
  }
  return RemoteObjectId::serialize(m_context->inspector()->isolateId(),
                                   m_context->contextId(), id);
}

// static
Response InjectedScript::bindRemoteObjectIfNeeded(
    int sessionId, v8::Local<v8::Context> context, v8::Local<v8::Value> value,
    const String16& groupName, protocol::Runtime::RemoteObject* remoteObject) {
  if (!remoteObject) return Response::Success();
  if (remoteObject->hasValue()) return Response::Success();
  if (remoteObject->hasUnserializableValue()) return Response::Success();
  if (remoteObject->getType() != RemoteObject::TypeEnum::Undefined) {
    v8::Isolate* isolate = context->GetIsolate();
    V8InspectorImpl* inspector =
        static_cast<V8InspectorImpl*>(v8::debug::GetInspector(isolate));
    InspectedContext* inspectedContext =
        inspector->getContext(InspectedContext::contextId(context));
    InjectedScript* injectedScript =
        inspectedContext ? inspectedContext->getInjectedScript(sessionId)
                         : nullptr;
    if (!injectedScript) {
      return Response::ServerError("Cannot find context with specified id");
    }
    remoteObject->setObjectId(injectedScript->bindObject(value, groupName));
  }
  return Response::Success();
}

void InjectedScript::unbindObject(int id) {
  m_idToWrappedObject.erase(id);
  m_idToObjectGroupName.erase(id);
}

PromiseHandlerTracker::PromiseHandlerTracker() = default;

PromiseHandlerTracker::~PromiseHandlerTracker() { discardAll(); }

template <typename... Args>
PromiseHandlerTracker::Id PromiseHandlerTracker::create(Args&&... args) {
  Id id = m_lastUsedId++;
  InjectedScript::ProtocolPromiseHandler* handler =
      new InjectedScript::ProtocolPromiseHandler(id,
                                                 std::forward<Args>(args)...);
  m_promiseHandlers.emplace(id, handler);
  return id;
}

void PromiseHandlerTracker::discard(Id id, DiscardReason reason) {
  auto iter = m_promiseHandlers.find(id);
  CHECK_NE(iter, m_promiseHandlers.end());
  InjectedScript::ProtocolPromiseHandler* handler = iter->second.get();

  switch (reason) {
    case DiscardReason::kPromiseCollected:
      sendFailure(handler, Response::ServerError("Promise was collected"));
      break;
    case DiscardReason::kTearDown:
      sendFailure(handler, Response::ServerError(
                               "Tearing down inspector/session/context"));
      break;
    case DiscardReason::kFulfilled:
      // Do nothing.
      break;
  }

  m_promiseHandlers.erase(id);
}

InjectedScript::ProtocolPromiseHandler* PromiseHandlerTracker::get(
    Id id) const {
  auto iter = m_promiseHandlers.find(id);
  if (iter == m_promiseHandlers.end()) return nullptr;

  return iter->second.get();
}

void PromiseHandlerTracker::sendFailure(
    InjectedScript::ProtocolPromiseHandler* handler,
    const protocol::DispatchResponse& response) const {
  V8InspectorImpl* inspector = handler->m_inspector;
  V8InspectorSessionImpl* session =
      inspector->sessionById(handler->m_contextGroupId, handler->m_sessionId);
  if (!session) return;
  InjectedScript::ContextScope scope(session, handler->m_executionContextId);
  Response res = scope.initialize();
  if (!res.IsSuccess()) return;
  EvaluateCallback::sendFailure(handler->m_callback, scope.injectedScript(),
                                response);
}

void PromiseHandlerTracker::discardAll() {
  while (!m_promiseHandlers.empty()) {
    discard(m_promiseHandlers.begin()->first, DiscardReason::kTearDown);
  }
  CHECK(m_promiseHandlers.empty());
}

}  // namespace v8_inspector
```