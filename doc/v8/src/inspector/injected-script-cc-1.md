Response:
Let's break down the thought process for analyzing the provided `injected-script.cc` code and generating the summary.

1. **Understand the Goal:** The primary goal is to understand the functionalities of the `injected-script.cc` file within the V8 inspector context. The decomposed instructions guide the specific aspects to look for.

2. **Initial Scan for Keywords and Data Structures:**  A quick skim reveals key classes and data structures: `InjectedScript`, `EvaluateCallback`, `RemoteObjectId`, `ProtocolPromiseHandler`, `Scope`, `ContextScope`, `ObjectScope`, `CallFrameScope`, `PromiseHandlerTracker`, `v8::Context`, `v8::Value`, `v8::Object`, etc. These provide a high-level understanding of the components involved.

3. **Focus on Core Functionality - `InjectedScript` Class:**  This is clearly the central class. The methods within it will reveal its core responsibilities. I'd group related methods mentally:

    * **Evaluation:** `evaluate`, `addEvaluateCallback`, `discardEvaluateCallbacks`, `deleteEvaluateCallback`, `wrapEvaluateResult`. This suggests handling code execution and results.
    * **Object Management:** `findObject`, `objectGroupName`, `releaseObjectGroup`, `bindObject`, `unbindObject`, `bindRemoteObjectIfNeeded`. This points to managing references to JavaScript objects in the debugger.
    * **Exception Handling:** `addExceptionToDetails`, `createExceptionDetails`. Responsible for formatting and reporting exceptions.
    * **Call Arguments:** `resolveCallArgument`. Deals with processing arguments passed to function calls from the debugger.
    * **Command Line API:** `commandLineAPI`. Provides access to the console API within the debugger.
    * **Last Evaluation Result:** `lastEvaluationResult`, `setLastEvaluationResult`. Stores and retrieves the most recent evaluation result.
    * **Custom Formatting:** `setCustomObjectFormatterEnabled`. Controls custom object previews.

4. **Analyze Supporting Classes:**

    * **`EvaluateCallback`:** The name suggests handling callbacks after evaluations. The `sendFailure` function indicates how errors are reported.
    * **`RemoteObjectId`:**  Used to uniquely identify JavaScript objects in the debugger. The `parse` and `serialize` methods confirm this.
    * **`ProtocolPromiseHandler`:** Clearly related to handling Promises. The `add` method suggests managing promise lifecycles.
    * **`Scope` and its subclasses (`ContextScope`, `ObjectScope`, `CallFrameScope`):** These appear to manage the execution environment for debugger commands. They handle setting up and tearing down the V8 context and related settings. The differences in subclasses likely relate to the context in which an operation is performed (general context, specific object, specific call frame).
    * **`PromiseHandlerTracker`:**  Manages the lifecycle of `ProtocolPromiseHandler` instances, handling creation, discarding, and error reporting.

5. **Connect the Dots and Infer Functionality:**  Based on the methods and data structures, I start to piece together the flow:

    * The debugger wants to evaluate some JavaScript code.
    * `InjectedScript::evaluate` likely handles this, using a `Scope` to set up the execution environment.
    * Results are wrapped using `wrapEvaluateResult`, potentially creating `RemoteObjectId`s to refer to objects.
    * `EvaluateCallback` is used to asynchronously report the result back to the debugger.
    * `RemoteObjectId`s are used to maintain references to objects across debugger commands. `findObject` retrieves the actual `v8::Value` from an ID.
    * Promises are handled separately using `ProtocolPromiseHandler` to track their state and report results.
    * Exceptions are caught and formatted into `ExceptionDetails`.
    * The `Scope` classes ensure operations are performed in the correct V8 context and with appropriate settings.

6. **Address Specific Instructions:**

    * **Torque:** The file extension check is straightforward. It's `.cc`, so it's not Torque.
    * **JavaScript Relationship:**  The code heavily interacts with V8's JavaScript execution environment. Examples can be constructed based on common debugger actions (evaluating expressions, inspecting variables).
    * **Code Logic Inference:** Focus on specific methods like `resolveCallArgument` or `wrapEvaluateResult` to create hypothetical inputs and outputs demonstrating their behavior.
    * **Common Programming Errors:** Think about scenarios where the debugger interaction might go wrong (e.g., accessing objects from the wrong context, promises not resolving).

7. **Structure the Summary:** Organize the findings logically:

    * Start with the core purpose.
    * Detail the key functionalities and the classes responsible.
    * Address the specific instructions (Torque, JavaScript examples, logic inference, errors).
    * Provide a concluding summary.

8. **Refine and Elaborate:** Review the initial draft and add more details, examples, and explanations to make it clearer and more comprehensive. For instance,  elaborate on the role of `RemoteObjectId` and how object groups are used.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the `Scope` classes are just about managing V8 scopes.
* **Correction:**  Realize they also handle other aspects like user gestures, code generation, and the command-line API, making their role more central to the debugger's interaction with the JavaScript engine.
* **Initial thought:** Focus only on the main `InjectedScript` class.
* **Correction:** Recognize the importance of the supporting classes like `EvaluateCallback` and `ProtocolPromiseHandler` in the overall workflow. Understanding their interaction is crucial.
* **Initial thought:**  Provide very technical details about V8 internals.
* **Correction:**  Balance the technical details with a higher-level explanation that is easier to understand for someone familiar with debugging concepts. Use JavaScript examples to illustrate the concepts in a more accessible way.

By following this structured approach, combining code analysis with an understanding of debugging principles, and iteratively refining the analysis, I can arrive at a comprehensive and accurate summary of the `injected-script.cc` file's functionality.
好的，这是对 `v8/src/inspector/injected-script.cc` 代码的功能归纳：

**核心功能总结：**

`v8/src/inspector/injected-script.cc` 文件的核心职责是 **在 V8 引擎的调试器 (Inspector) 和 JavaScript 执行环境之间建立桥梁，允许调试器安全地执行 JavaScript 代码、检查和操作 JavaScript 对象，并处理异步操作 (Promise)。**  它管理着一个特定的 JavaScript 执行上下文，并提供了一系列方法来与该上下文进行交互。

**详细功能列举：**

1. **JavaScript 代码求值 (Evaluation)：**
   - `evaluate()`:  允许调试器发送 JavaScript 代码到目标上下文中执行。
   - `EvaluateCallback`:  用于处理 `evaluate()` 操作的回调，包括成功和失败的情况。
   - `wrapEvaluateResult()`:  将 JavaScript 代码执行的结果包装成调试器可以理解的 `RemoteObject` 格式。
   - `discardEvaluateCallbacks()` 和 `deleteEvaluateCallback()`: 管理和清理未完成的求值回调。

2. **JavaScript 对象管理和引用：**
   - `findObject()`: 根据 `RemoteObjectId` 查找并返回对应的 JavaScript 对象。
   - `bindObject()`: 将一个 V8 的 `v8::Value` 对象与一个调试器内部的 ID 关联起来，创建 `RemoteObjectId`。这允许调试器在后续操作中引用该对象。
   - `unbindObject()`: 解除对象和 ID 的关联。
   - `bindRemoteObjectIfNeeded()`:  根据需要将 JavaScript 对象绑定到 `RemoteObject`。
   - `objectGroupName()`: 获取与 `RemoteObjectId` 关联的对象组名称。
   - `releaseObjectGroup()`: 释放一个对象组，解除该组内所有对象的绑定。
   - `m_idToWrappedObject`:  内部数据结构，存储 ID 和对应的 V8 对象的弱引用。
   - `m_idToObjectGroupName`, `m_nameToObjectGroup`: 内部数据结构，用于管理对象和对象组之间的关系。

3. **异常处理：**
   - `createExceptionDetails()`:  将 V8 的异常信息（`v8::TryCatch`, `v8::Message`) 转换为调试器可以理解的 `ExceptionDetails` 格式。
   - `addExceptionToDetails()`:  将异常对象本身包装成 `RemoteObject` 并添加到 `ExceptionDetails` 中。

4. **函数调用参数处理：**
   - `resolveCallArgument()`:  解析调试器发送的函数调用参数，将其转换为 V8 的 `v8::Value`。参数可以是 `RemoteObjectId` 或者直接的值。

5. **Promise 处理：**
   - `ProtocolPromiseHandler`:  用于跟踪和管理 Promise 的状态和结果。
   - `PromiseHandlerTracker`:  管理 `ProtocolPromiseHandler` 的生命周期。
   -  代码中包含了创建、添加、丢弃 Promise 处理器的逻辑，并能在 Promise 收集或销毁时发送失败回调。

6. **执行上下文管理 (`Scope` 类及其子类)：**
   - `Scope`:  一个 RAII 风格的类，用于安全地进入和退出 JavaScript 执行上下文，并管理一些调试相关的设置（例如，是否允许 eval，是否模拟用户手势）。
   - `ContextScope`: `Scope` 的子类，针对特定的执行上下文 ID。
   - `ObjectScope`: `Scope` 的子类，针对特定的 `RemoteObjectId`。
   - `CallFrameScope`: `Scope` 的子类，针对特定的调用帧。

7. **命令行 API 支持：**
   - `commandLineAPI()`:  提供对 V8 调试器命令行 API 的访问（例如 `$`, `$$`, `inspect` 等）。

8. **其他功能：**
   - `setCustomObjectFormatterEnabled()`:  控制是否启用自定义对象格式化器。
   - `lastEvaluationResult()` 和 `setLastEvaluationResult()`:  存储和检索最后一次求值的结果（通常用于控制台）。

**关于文件类型：**

- 由于题目中明确指出这是 `v8/src/inspector/injected-script.cc`，因此它是一个 **C++ 源代码文件**，而不是 Torque (`.tq`) 文件。

**与 JavaScript 功能的关系及举例：**

`injected-script.cc` 的所有功能都直接或间接地与 JavaScript 功能相关，因为它负责在调试器和 JavaScript 运行时之间进行交互。

**JavaScript 示例：**

假设在调试器中我们执行以下操作：

1. **求值代码:** 在调试器的 Console 面板中输入 `1 + 2` 并回车。
   - `injected-script.cc` 中的 `evaluate()` 方法会被调用。
   - V8 引擎会执行 `1 + 2`，结果为 `3`。
   - `wrapEvaluateResult()` 会将结果 `3` 包装成 `protocol::Runtime::RemoteObject`，类型为 "number"，值为 3。

2. **检查对象:** 在调试器中查看一个变量 `myObject = { a: 1, b: 'hello' }`。
   - 如果 `myObject` 之前没有被绑定，`bindObject()` 会被调用，为 `myObject` 生成一个 `RemoteObjectId` (例如 `{"injectedScriptId": 1, "id": 10}`).
   - 调试器显示 `myObject` 的属性时，可能会调用 `findObject()` 来获取 `myObject` 对应的 V8 对象，然后进一步获取其属性。

3. **调用函数:** 在调试器中调用一个函数 `myFunction(arg1, arg2)`，其中 `arg1` 是一个已经存在的对象。
   - `resolveCallArgument()` 会被调用来解析 `arg1` (可能是一个 `RemoteObjectId`) 和 `arg2` (可能是一个字面量值)。
   - 对于 `arg1`，`findObject()` 会被调用根据 `RemoteObjectId` 找到对应的 JavaScript 对象。
   - 对于 `arg2`，如果是一个字面量，则会直接转换为 V8 的 `v8::Value`。

4. **Promise 的检查:** 当遇到一个 Promise 时，`ProtocolPromiseHandler` 负责跟踪其状态。当 Promise resolve 或 reject 时，会通知调试器。

**代码逻辑推理及假设输入输出：**

考虑 `resolveCallArgument()` 方法：

**假设输入 (protocol::Runtime::CallArgument):**

- **场景 1：**  `callArgument` 包含 `objectId`:  `{"objectId": "{\"injectedScriptId\":1,\"id\":123}"}`
- **场景 2：**  `callArgument` 包含 `value`: `{"value": "10"}` (CBOR 编码后的 "10")
- **场景 3：**  `callArgument` 包含 `unserializableValue`: `{"unserializableValue": "NaN"}`

**假设 `m_context` 指向一个有效的 JavaScript 上下文，且 `m_idToWrappedObject` 中存在 ID 为 123 的对象。**

**输出 (v8::Local<v8::Value>):**

- **场景 1：**  `findObject()` 成功找到 ID 为 123 的 V8 对象，输出该对象的 `v8::Local<v8::Value>`。
- **场景 2：**  V8 会将字符串 "10" 解析为数字 10，输出表示数字 10 的 `v8::Local<v8::Value>`。
- **场景 3：**  V8 会将 "NaN" 解析为 `NaN` (Not a Number)，输出表示 `NaN` 的 `v8::Local<v8::Value>`。

**涉及用户常见的编程错误及举例：**

1. **尝试访问已释放的对象:**  如果用户在调试器中持有一个 `RemoteObjectId`，但在 JavaScript 代码中该对象已经被垃圾回收，那么当调试器尝试使用这个 `RemoteObjectId` 时，`findObject()` 会返回错误 "Could not find object with given id"。

   ```javascript
   let myObject = { value: 1 };
   // ... 一段时间后，myObject 可能不再被引用，等待垃圾回收

   // 调试器尝试访问之前绑定的 myObject 的 RemoteObjectId
   ```

2. **在错误的上下文中操作对象:**  如果存在多个 JavaScript 执行上下文，尝试在一个上下文的调试会话中使用另一个上下文的 `RemoteObjectId`，会导致错误，因为 `RemoteObjectId` 包含了 `injectedScriptId` (对应上下文 ID)。`findObject()` 中会检查 `remoteObjectId->contextId()` 是否与当前 `m_context->contextId()` 匹配。

3. **Promise 的意外行为:**  如果用户不理解 Promise 的异步性，在调试器中观察 Promise 状态时可能会感到困惑。例如，在 Promise 真正 resolve 之前检查其值，可能看到的是 pending 状态。`ProtocolPromiseHandler` 的作用就是帮助调试器更好地呈现 Promise 的状态变化。

**总结 (针对第 2 部分的归纳)：**

这部分代码主要负责处理 **JavaScript 对象的绑定、查找和释放，以及处理函数调用的参数**。它维护着调试器内部的 `RemoteObjectId` 和实际 JavaScript 对象之间的映射，确保调试器可以安全地引用和操作这些对象。此外，`resolveCallArgument` 确保了从调试器传递到 JavaScript 函数的参数被正确解析和转换。`PromiseHandlerTracker` 和 `ProtocolPromiseHandler` 则专注于管理异步 Promise 的生命周期，使得调试器能够跟踪 Promise 的状态和结果。 简而言之，这部分代码是 `InjectedScript` 类中对象管理和函数调用支持的关键组成部分。

Prompt: 
```
这是目录为v8/src/inspector/injected-script.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/injected-script.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""

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

"""


```