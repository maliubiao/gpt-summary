Response:
The user wants to understand the functionality of the `v8-runtime-agent-impl.cc` file in the V8 source code. I need to analyze the code and identify its main responsibilities.

Here's a breakdown of how I'll approach this:

1. **Identify the file's purpose:** Based on the name `V8RuntimeAgentImpl`, it likely implements the "Runtime" domain of the Chrome DevTools Protocol (CDP) within V8. This domain handles interactions related to the execution environment of JavaScript code.

2. **Analyze the included headers:** The included files give hints about the functionalities. Keywords like "inspector", "runtime", "debug", "protocol", "v8" suggest interaction with the V8 engine for debugging and inspection purposes.

3. **Examine the class structure:** The core of the file is the `V8RuntimeAgentImpl` class. Its methods will define the available functionalities.

4. **Go through the methods:** I'll iterate through the methods like `evaluate`, `callFunctionOn`, `getProperties`, etc., and describe their apparent function based on their names and parameters.

5. **Connect to JavaScript:**  For methods that have a clear connection to JavaScript execution (like `evaluate`, `callFunctionOn`), I will provide JavaScript examples demonstrating their use conceptually (as the C++ code is an implementation detail).

6. **Look for logic and potential errors:** I'll try to identify any specific logic within the methods and potential programming errors that users might encounter when interacting with these functionalities through the DevTools.

7. **Address the Torque question:** I'll check the file extension and confirm it's not a Torque file.

8. **Summarize the functionalities:** Finally, I'll provide a concise summary of the identified functionalities based on the analysis.```javascript
/**
 * This is a conceptual representation of the functionalities provided by
 * v8/src/inspector/v8-runtime-agent-impl.cc. The actual implementation is in C++.
 */

// Simulating Runtime.evaluate
async function evaluateInV8(expression) {
  // In reality, this would be a communication with the V8 engine.
  // Here, we just use eval for demonstration.
  try {
    return { result: eval(expression) };
  } catch (error) {
    return { exceptionDetails: { text: error.toString() } };
  }
}

// Example usage of evaluate
async function testEvaluate() {
  const result1 = await evaluateInV8("1 + 2");
  console.log("Evaluate '1 + 2':", result1.result); // Output: 3

  const result2 = await evaluateInV8("nonExistentVariable");
  console.log("Evaluate 'nonExistentVariable' (error):", result2.exceptionDetails);
  // Output: Exception details indicating an error
}

testEvaluate();

// Simulating Runtime.callFunctionOn
async function callFunctionOnV8(objectId, functionDeclaration, args) {
  // In reality, objectId would identify an object in V8's memory.
  // We'll use a simple object for demonstration.
  const targetObject = {
    add(a, b) {
      return a + b;
    },
  };

  if (objectId !== "myObjectId") {
    return { error: "Object not found" };
  }

  try {
    const func = new Function(...args.map((_, i) => `arg${i}`), functionDeclaration);
    const argumentValues = args.map(arg => arg.value);
    const result = targetObject.add(...argumentValues); // Assuming the function is 'add'
    return { result };
  } catch (error) {
    return { exceptionDetails: { text: error.toString() } };
  }
}

// Example usage of callFunctionOn
async function testCallFunctionOn() {
  const result1 = await callFunctionOnV8(
    "myObjectId",
    "return arg0 + arg1;",
    [{ value: 5 }, { value: 3 }]
  );
  console.log("callFunctionOn 'add(5, 3)':", result1.result); // Output: 8

  const result2 = await callFunctionOnV8(
    "wrongObjectId",
    "return arg0 + arg1;",
    [{ value: 1 }, { value: 2 }]
  );
  console.log("callFunctionOn with wrong objectId:", result2.error);
  // Output: Error indicating object not found
}

testCallFunctionOn();

// Simulating Runtime.getProperties
async function getPropertiesInV8(objectId) {
  const targetObject = { a: 1, b: "hello" };
  if (objectId === "myObjectId") {
    return {
      result: Object.entries(targetObject).map(([name, value]) => ({
        name,
        value: { type: typeof value, value },
      })),
    };
  } else {
    return { error: "Object not found" };
  }
}

// Example usage of getProperties
async function testGetProperties() {
  const properties = await getPropertiesInV8("myObjectId");
  console.log("Properties of myObjectId:", properties.result);
  // Output: An array of property descriptors
}

testGetProperties();

// Simulating Runtime.releaseObjectGroup
function releaseObjectGroupInV8(objectGroup) {
  console.log(`Releasing object group: ${objectGroup}`);
  // In reality, this would involve freeing resources associated with the group.
}

// Example usage of releaseObjectGroup
releaseObjectGroupInV8("myGroup");
// Output: "Releasing object group: myGroup"

// User's common programming error example related to asynchronous operations
async function fetchData() {
  let data;
  setTimeout(() => {
    data = "Data fetched!";
    console.log("Data inside setTimeout:", data); // This will run later
  }, 1000);
  console.log("Data outside setTimeout:", data); // This will run immediately and be undefined
  return data; // This will likely return undefined before the data is fetched.
}

fetchData().then(result => console.log("Result from fetchData:", result));
```

### 功能列举:

`v8/src/inspector/v8-runtime-agent-impl.cc` 实现了 Chrome DevTools Protocol (CDP) 中 `Runtime` 域的功能。 这个域主要负责与 JavaScript 运行时的交互，允许开发者检查和控制 JavaScript 代码的执行。 以下是其主要功能的归纳：

1. **代码执行与求值 (`evaluate`)**: 允许在指定的 JavaScript 执行上下文中执行一段字符串形式的 JavaScript 代码，并返回执行结果。这包括处理异常、Promise 等。
2. **函数调用 (`callFunctionOn`)**: 允许在一个指定的对象上调用一个函数。可以传递参数，并控制是否静默执行、是否模拟用户手势等。
3. **属性获取 (`getProperties`)**: 允许获取指定对象的属性，包括自有属性、继承属性、内部属性和私有属性。可以控制是否只获取自有属性、访问器属性等。
4. **对象释放 (`releaseObject`, `releaseObjectGroup`)**:  为了避免内存泄漏，允许显式地释放之前通过检查器协议返回的远程对象或对象组。
5. **等待调试器 (`runIfWaitingForDebugger`)**:  在某些情况下，JavaScript 执行可能会暂停等待调试器连接。此功能允许继续执行。
6. **自定义对象格式化器 (`setCustomObjectFormatterEnabled`)**: 控制是否启用自定义的对象格式化器，这会影响在开发者工具中对象的显示方式。
7. **最大调用栈大小 (`setMaxCallStackSizeToCapture`)**: 设置可以捕获的最大调用栈大小，用于生成错误堆栈信息。
8. **清空控制台 (`discardConsoleEntries`)**: 清除特定执行上下文组的控制台消息。
9. **脚本编译与运行 (`compileScript`, `runScript`)**: 允许预编译 JavaScript 代码，并稍后在指定的上下文中运行。
10. **查询对象 (`queryObjects`)**:  查找指定原型链上的所有对象实例。
11. **全局词法作用域名称 (`globalLexicalScopeNames`)**: 获取全局作用域中的变量和函数名称。

### 关于文件类型:

`v8/src/inspector/v8-runtime-agent-impl.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque (`.tq`) 文件。 Torque 是 V8 用于定义运行时内置函数的一种领域特定语言。

### 与 JavaScript 的关系及示例:

`v8/src/inspector/v8-runtime-agent-impl.cc` 的功能直接对应于 Chrome DevTools Protocol (CDP) 中 `Runtime` 域的命令。开发者工具的前端 (通常是 JavaScript 编写的) 通过 CDP 与 V8 的 Inspector 后端进行通信。

以下是一些 JavaScript 代码示例，展示了如何通过 DevTools Protocol 与 `v8-runtime-agent-impl.cc` 实现的功能进行交互：

**1. `Runtime.evaluate` 对应示例:**

```javascript
// 假设我们已经建立了一个 DevTools Protocol 连接 (e.g., 通过 Chrome 扩展或 Node.js 的 chrome-remote-interface 库)
async function evaluateExpression(expression) {
  const result = await chrome.debugger.sendCommand({ tabId: /* 你的 Tab ID */ }, "Runtime.evaluate", {
    expression: expression,
  });
  if (result.exceptionDetails) {
    console.error("Evaluation failed:", result.exceptionDetails);
  } else {
    console.log("Evaluation result:", result.result.value);
  }
}

evaluateExpression("2 + 2");
evaluateExpression("nonExistentVariable");
```

**2. `Runtime.callFunctionOn` 对应示例:**

```javascript
async function callFunctionOnObject(objectId, functionDeclaration, args) {
  const result = await chrome.debugger.sendCommand({ tabId: /* 你的 Tab ID */ }, "Runtime.callFunctionOn", {
    objectId: objectId,
    functionDeclaration: functionDeclaration,
    arguments: args,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    console.error("Function call failed:", result.exceptionDetails);
  } else {
    console.log("Function call result:", result.result.value);
  }
}

// 假设我们已经有一个远程对象的 ID
const myObjectId = "/* 远程对象的 ID */";
callFunctionOnObject(myObjectId, "function() { return this.value * 2; }", []);
```

**3. `Runtime.getProperties` 对应示例:**

```javascript
async function getObjectProperties(objectId) {
  const result = await chrome.debugger.sendCommand({ tabId: /* 你的 Tab ID */ }, "Runtime.getProperties", {
    objectId: objectId,
    ownProperties: true,
  });
  console.log("Object properties:", result.result);
}

const myObjectId = "/* 远程对象的 ID */";
getObjectProperties(myObjectId);
```

### 代码逻辑推理和假设输入输出:

**示例：`evaluate` 函数**

**假设输入:**

*   `expression`: `"myVariable + 5"`
*   执行上下文中 `myVariable` 的值为 `10`。

**预期输出:**

*   `result`:  一个 `RemoteObject`，其 `value` 属性为 `15`，`type` 属性为 `"number"`。

**示例：`callFunctionOn` 函数**

**假设输入:**

*   `objectId`:  一个表示 JavaScript 对象的远程 ID，该对象具有一个名为 `add` 的方法。
*   `expression`: `"add"`
*   `optionalArguments`: `[{ "value": 2 }, { "value": 3 }]`

**预期输出:**

*   `result`: 一个 `RemoteObject`，其 `value` 属性为 `5`，`type` 属性为 `"number"`。

### 用户常见的编程错误:

1. **在 `evaluate` 中访问不存在的变量或函数:**

    ```javascript
    // 用户代码
    evaluateExpression("undefinedVariable"); // undefinedVariable 未定义
    ```

    **预期结果 (通过 `exceptionDetails` 返回):** 类似于 "ReferenceError: undefinedVariable is not defined"。

2. **在 `callFunctionOn` 中 `objectId` 不正确:**

    ```javascript
    // 用户代码，假设 'invalidObjectId' 是一个无效的 ID
    callFunctionOnObject('invalidObjectId', "function() { return 1; }", []);
    ```

    **预期结果 (根据代码逻辑):**  可能会收到一个错误，指示找不到具有给定 ID 的对象。

3. **在 `callFunctionOn` 中传递了错误类型的参数:**

    ```javascript
    // 假设目标函数期望接收数字
    callFunctionOnObject(myObjectId, "function(a) { return a * 2; }", [{ "value": "not a number" }]);
    ```

    **预期结果:**  JavaScript 代码执行时可能会抛出类型错误，并通过 `exceptionDetails` 返回。

4. **忘记 `releaseObjectGroup` 或 `releaseObject` 导致内存泄漏:**

    开发者在调试过程中可能会频繁地获取对象的属性或调用函数，如果不对不再需要的远程对象进行释放，可能会导致 V8 进程的内存占用增加。虽然 V8 有垃圾回收机制，但检查器创建的远程对象需要显式释放。

### 功能归纳:

`v8/src/inspector/v8-runtime-agent-impl.cc` 是 V8 引擎中负责实现 Chrome DevTools Protocol 的 `Runtime` 域的关键组件。它提供了允许开发者远程检查和控制 JavaScript 运行时环境的功能，包括代码执行、函数调用、对象属性获取和管理等。该文件的功能是连接 DevTools 前端和 V8 引擎的桥梁，使得开发者可以通过 DevTools 与正在运行的 JavaScript 代码进行交互和调试。

### 提示词
```
这是目录为v8/src/inspector/v8-runtime-agent-impl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-runtime-agent-impl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "src/inspector/v8-runtime-agent-impl.h"

#include <inttypes.h>

#include <memory>

#include "../../third_party/inspector_protocol/crdtp/json.h"
#include "include/v8-container.h"
#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-inspector.h"
#include "include/v8-microtask-queue.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/injected-script.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Protocol.h"
#include "src/inspector/protocol/Runtime.h"
#include "src/inspector/remote-object-id.h"
#include "src/inspector/v8-console-message.h"
#include "src/inspector/v8-debugger-agent-impl.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-stack-trace-impl.h"
#include "src/inspector/v8-value-utils.h"
#include "src/tracing/trace-event.h"

namespace v8_inspector {

namespace V8RuntimeAgentImplState {
static const char customObjectFormatterEnabled[] =
    "customObjectFormatterEnabled";
static const char maxCallStackSizeToCapture[] = "maxCallStackSizeToCapture";
static const char runtimeEnabled[] = "runtimeEnabled";
static const char bindings[] = "bindings";
static const char globalBindingsKey[] = "";
}  // namespace V8RuntimeAgentImplState

using protocol::Runtime::RemoteObject;

namespace {

template <typename ProtocolCallback>
class EvaluateCallbackWrapper : public EvaluateCallback {
 public:
  static std::shared_ptr<EvaluateCallback> wrap(
      std::unique_ptr<ProtocolCallback> callback) {
    return std::shared_ptr<EvaluateCallback>(
        new EvaluateCallbackWrapper(std::move(callback)));
  }
  void sendSuccess(std::unique_ptr<protocol::Runtime::RemoteObject> result,
                   protocol::Maybe<protocol::Runtime::ExceptionDetails>
                       exceptionDetails) override {
    return m_callback->sendSuccess(std::move(result),
                                   std::move(exceptionDetails));
  }
  void sendFailure(const protocol::DispatchResponse& response) override {
    return m_callback->sendFailure(response);
  }

 private:
  explicit EvaluateCallbackWrapper(std::unique_ptr<ProtocolCallback> callback)
      : m_callback(std::move(callback)) {}

  std::unique_ptr<ProtocolCallback> m_callback;
};

template <typename ProtocolCallback>
bool wrapEvaluateResultAsync(InjectedScript* injectedScript,
                             v8::MaybeLocal<v8::Value> maybeResultValue,
                             const v8::TryCatch& tryCatch,
                             const String16& objectGroup,
                             const WrapOptions& wrapOptions,
                             bool throwOnSideEffect,
                             ProtocolCallback* callback) {
  std::unique_ptr<RemoteObject> result;
  Maybe<protocol::Runtime::ExceptionDetails> exceptionDetails;

  Response response = injectedScript->wrapEvaluateResult(
      maybeResultValue, tryCatch, objectGroup, wrapOptions, throwOnSideEffect,
      &result, &exceptionDetails);
  if (response.IsSuccess()) {
    callback->sendSuccess(std::move(result), std::move(exceptionDetails));
    return true;
  }
  callback->sendFailure(response);
  return false;
}

void innerCallFunctionOn(
    V8InspectorSessionImpl* session, InjectedScript::Scope& scope,
    v8::Local<v8::Value> recv, const String16& expression,
    Maybe<protocol::Array<protocol::Runtime::CallArgument>> optionalArguments,
    bool silent, std::unique_ptr<WrapOptions> wrapOptions, bool userGesture,
    bool awaitPromise, const String16& objectGroup, bool throwOnSideEffect,
    std::unique_ptr<V8RuntimeAgentImpl::CallFunctionOnCallback> callback) {
  V8InspectorImpl* inspector = session->inspector();

  std::unique_ptr<v8::Global<v8::Value>[]> argv = nullptr;
  int argc = 0;
  if (optionalArguments) {
    protocol::Array<protocol::Runtime::CallArgument>& arguments =
        *optionalArguments;
    argc = static_cast<int>(arguments.size());
    argv.reset(new v8::Global<v8::Value>[argc]);
    for (int i = 0; i < argc; ++i) {
      v8::Local<v8::Value> argumentValue;
      Response response = scope.injectedScript()->resolveCallArgument(
          arguments[i].get(), &argumentValue);
      if (!response.IsSuccess()) {
        callback->sendFailure(response);
        return;
      }
      argv[i] = v8::Global<v8::Value>(inspector->isolate(), argumentValue);
    }
  }

  if (silent) scope.ignoreExceptionsAndMuteConsole();
  if (userGesture) scope.pretendUserGesture();

  // Temporarily enable allow evals for inspector.
  scope.allowCodeGenerationFromStrings();

  v8::MaybeLocal<v8::Value> maybeFunctionValue;
  v8::Local<v8::Script> functionScript;
  if (inspector
          ->compileScript(scope.context(), "(" + expression + ")", String16())
          .ToLocal(&functionScript)) {
    v8::MicrotasksScope microtasksScope(scope.context(),
                                        v8::MicrotasksScope::kRunMicrotasks);
    maybeFunctionValue = functionScript->Run(scope.context());
  }
  // Re-initialize after running client's code, as it could have destroyed
  // context or session.
  Response response = scope.initialize();
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  if (scope.tryCatch().HasCaught()) {
    wrapEvaluateResultAsync(scope.injectedScript(), maybeFunctionValue,
                            scope.tryCatch(), objectGroup,
                            WrapOptions({WrapMode::kIdOnly}), throwOnSideEffect,
                            callback.get());
    return;
  }

  v8::Local<v8::Value> functionValue;
  if (!maybeFunctionValue.ToLocal(&functionValue) ||
      !functionValue->IsFunction()) {
    callback->sendFailure(Response::ServerError(
        "Given expression does not evaluate to a function"));
    return;
  }

  v8::MaybeLocal<v8::Value> maybeResultValue;
  {
    v8::MicrotasksScope microtasksScope(scope.context(),
                                        v8::MicrotasksScope::kRunMicrotasks);
    maybeResultValue = v8::debug::CallFunctionOn(
        scope.context(), functionValue.As<v8::Function>(), recv, argc,
        argv.get(), throwOnSideEffect);
  }
  // Re-initialize after running client's code, as it could have destroyed
  // context or session.
  response = scope.initialize();
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  if (!awaitPromise || scope.tryCatch().HasCaught()) {
    wrapEvaluateResultAsync(scope.injectedScript(), maybeResultValue,
                            scope.tryCatch(), objectGroup, *wrapOptions,
                            throwOnSideEffect, callback.get());
    return;
  }

  scope.injectedScript()->addPromiseCallback(
      session, maybeResultValue, objectGroup, std::move(wrapOptions),
      false /* replMode */, throwOnSideEffect,
      EvaluateCallbackWrapper<V8RuntimeAgentImpl::CallFunctionOnCallback>::wrap(
          std::move(callback)));
}

Response ensureContext(V8InspectorImpl* inspector, int contextGroupId,
                       Maybe<int> executionContextId,
                       Maybe<String16> uniqueContextId, int* contextId) {
  if (executionContextId.has_value()) {
    if (uniqueContextId.has_value()) {
      return Response::InvalidParams(
          "contextId and uniqueContextId are mutually exclusive");
    }
    *contextId = executionContextId.value();
  } else if (uniqueContextId.has_value()) {
    internal::V8DebuggerId uniqueId(uniqueContextId.value());
    if (!uniqueId.isValid())
      return Response::InvalidParams("invalid uniqueContextId");
    int id = inspector->resolveUniqueContextId(uniqueId);
    if (!id) return Response::InvalidParams("uniqueContextId not found");
    *contextId = id;
  } else {
    v8::HandleScope handles(inspector->isolate());
    v8::Local<v8::Context> defaultContext =
        inspector->client()->ensureDefaultContextInGroup(contextGroupId);
    if (defaultContext.IsEmpty())
      return Response::ServerError("Cannot find default execution context");
    *contextId = InspectedContext::contextId(defaultContext);
  }

  return Response::Success();
}

Response parseAdditionalSerializationParameters(
    protocol::DictionaryValue* additionalParameters, v8::Isolate* isolate,
    v8::Local<v8::Object>* result) {
  v8::LocalVector<v8::Name> keys(isolate);
  v8::LocalVector<v8::Value> values(isolate);

  if (additionalParameters != nullptr) {
    for (size_t i = 0; i < additionalParameters->size(); ++i) {
      String16 key = (*additionalParameters).at(i).first;
      keys.push_back(toV8String(isolate, key));

      protocol::Value* value = (*additionalParameters).at(i).second;
      String16 stringValue;
      if (value->asString(&stringValue)) {
        values.push_back(toV8String(isolate, stringValue));
        continue;
      }
      int intValue;
      if (value->asInteger(&intValue)) {
        values.push_back(v8::Int32::New(isolate, intValue));
        continue;
      }
      return Response::InvalidParams(
          "Values of serializationOptions.additionalParameters can be only of "
          "type string or integer.");
    }
  }
  CHECK(keys.size() == values.size());
  *result = v8::Object::New(isolate, v8::Null(isolate), keys.data(),
                            values.data(), keys.size());

  return Response::Success();
}

Response getWrapOptions(
    Maybe<bool> returnByValue, Maybe<bool> generatePreview,
    Maybe<protocol::Runtime::SerializationOptions> maybeSerializationOptions,
    v8::Isolate* isolate, std::unique_ptr<WrapOptions>* result) {
  if (maybeSerializationOptions) {
    String16 serializationModeStr =
        maybeSerializationOptions->getSerialization();
    if (serializationModeStr ==
        protocol::Runtime::SerializationOptions::SerializationEnum::Deep) {
      v8::Local<v8::Object> additionalParameters;
      Response response = parseAdditionalSerializationParameters(
          maybeSerializationOptions->getAdditionalParameters(nullptr), isolate,
          &additionalParameters);
      if (!response.IsSuccess()) {
        return response;
      }
      *result = std::make_unique<WrapOptions>(WrapOptions{
          WrapMode::kDeep,
          {maybeSerializationOptions->getMaxDepth(v8::internal::kMaxInt),
           v8::Global<v8::Object>(isolate, additionalParameters)}});
      return Response::Success();
    }
    if (serializationModeStr ==
        protocol::Runtime::SerializationOptions::SerializationEnum::Json) {
      *result = std::make_unique<WrapOptions>(WrapOptions{WrapMode::kJson});
      return Response::Success();
    }
    if (serializationModeStr ==
        protocol::Runtime::SerializationOptions::SerializationEnum::IdOnly) {
      *result = std::make_unique<WrapOptions>(WrapOptions{WrapMode::kIdOnly});
      return Response::Success();
    }
    return Response::InvalidParams(
        "Unknown serializationOptions.serialization value " +
        serializationModeStr.utf8());
  }

  if (returnByValue.value_or(false)) {
    *result = std::make_unique<WrapOptions>(WrapOptions{WrapMode::kJson});
    return Response::Success();
  }
  if (generatePreview.value_or(false)) {
    *result = std::make_unique<WrapOptions>(WrapOptions{WrapMode::kPreview});
    return Response::Success();
  }
  *result = std::make_unique<WrapOptions>(WrapOptions{WrapMode::kIdOnly});
  return Response::Success();
}

Response getWrapOptions(Maybe<bool> returnByValue, Maybe<bool> generatePreview,
                        v8::Isolate* isolate,
                        std::unique_ptr<WrapOptions>* result) {
  return getWrapOptions(
      std::move(returnByValue), std::move(generatePreview),
      Maybe<protocol::Runtime::
                SerializationOptions>() /* empty serialization options */,
      isolate, result);
}

}  // namespace

V8RuntimeAgentImpl::V8RuntimeAgentImpl(
    V8InspectorSessionImpl* session, protocol::FrontendChannel* FrontendChannel,
    protocol::DictionaryValue* state,
    std::shared_ptr<V8DebuggerBarrier> debuggerBarrier)
    : m_session(session),
      m_state(state),
      m_frontend(FrontendChannel),
      m_inspector(session->inspector()),
      m_debuggerBarrier(debuggerBarrier),
      m_enabled(false) {}

V8RuntimeAgentImpl::~V8RuntimeAgentImpl() = default;

void V8RuntimeAgentImpl::evaluate(
    const String16& expression, Maybe<String16> objectGroup,
    Maybe<bool> includeCommandLineAPI, Maybe<bool> silent,
    Maybe<int> executionContextId, Maybe<bool> returnByValue,
    Maybe<bool> generatePreview, Maybe<bool> userGesture,
    Maybe<bool> maybeAwaitPromise, Maybe<bool> throwOnSideEffect,
    Maybe<double> timeout, Maybe<bool> disableBreaks, Maybe<bool> maybeReplMode,
    Maybe<bool> allowUnsafeEvalBlockedByCSP, Maybe<String16> uniqueContextId,
    Maybe<protocol::Runtime::SerializationOptions> serializationOptions,
    std::unique_ptr<EvaluateCallback> callback) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
               "EvaluateScript");
  int contextId = 0;
  Response response = ensureContext(m_inspector, m_session->contextGroupId(),
                                    std::move(executionContextId),
                                    std::move(uniqueContextId), &contextId);
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  InjectedScript::ContextScope scope(m_session, contextId);
  response = scope.initialize();
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  if (silent.value_or(false)) scope.ignoreExceptionsAndMuteConsole();
  if (userGesture.value_or(false)) scope.pretendUserGesture();

  if (includeCommandLineAPI.value_or(false)) scope.installCommandLineAPI();

  const bool replMode = maybeReplMode.value_or(false);

  if (allowUnsafeEvalBlockedByCSP.value_or(true)) {
    // Temporarily enable allow evals for inspector.
    scope.allowCodeGenerationFromStrings();
  }
  v8::MaybeLocal<v8::Value> maybeResultValue;
  {
    V8InspectorImpl::EvaluateScope evaluateScope(scope);
    if (timeout.has_value()) {
      response = evaluateScope.setTimeout(timeout.value() / 1000.0);
      if (!response.IsSuccess()) {
        callback->sendFailure(response);
        return;
      }
    }
    v8::MicrotasksScope microtasksScope(scope.context(),
                                        v8::MicrotasksScope::kRunMicrotasks);
    v8::debug::EvaluateGlobalMode mode =
        v8::debug::EvaluateGlobalMode::kDefault;
    if (throwOnSideEffect.value_or(false)) {
      mode = v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect;
    } else if (disableBreaks.value_or(false)) {
      mode = v8::debug::EvaluateGlobalMode::kDisableBreaks;
    }
    const v8::Local<v8::String> source =
        toV8String(m_inspector->isolate(), expression);
    maybeResultValue = v8::debug::EvaluateGlobal(m_inspector->isolate(), source,
                                                 mode, replMode);
  }  // Run microtasks before returning result.

  // Re-initialize after running client's code, as it could have destroyed
  // context or session.
  response = scope.initialize();
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  std::unique_ptr<WrapOptions> wrapOptions;
  response = getWrapOptions(
      std::move(returnByValue), std::move(generatePreview),
      std::move(serializationOptions), m_inspector->isolate(), &wrapOptions);
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  // REPL mode always returns a promise that must be awaited.
  const bool await = replMode || maybeAwaitPromise.value_or(false);
  if (!await || scope.tryCatch().HasCaught()) {
    wrapEvaluateResultAsync(scope.injectedScript(), maybeResultValue,
                            scope.tryCatch(), objectGroup.value_or(""),
                            *wrapOptions, throwOnSideEffect.value_or(false),
                            callback.get());
    return;
  }
  scope.injectedScript()->addPromiseCallback(
      m_session, maybeResultValue, objectGroup.value_or(""),
      std::move(wrapOptions), replMode, throwOnSideEffect.value_or(false),
      EvaluateCallbackWrapper<EvaluateCallback>::wrap(std::move(callback)));
}

void V8RuntimeAgentImpl::awaitPromise(
    const String16& promiseObjectId, Maybe<bool> returnByValue,
    Maybe<bool> generatePreview,
    std::unique_ptr<AwaitPromiseCallback> callback) {
  InjectedScript::ObjectScope scope(m_session, promiseObjectId);
  Response response = scope.initialize();
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }
  if (!scope.object()->IsPromise()) {
    callback->sendFailure(
        Response::ServerError("Could not find promise with given id"));
    return;
  }

  std::unique_ptr<WrapOptions> wrapOptions;
  response =
      getWrapOptions(std::move(returnByValue), std::move(generatePreview),
                     m_inspector->isolate(), &wrapOptions);
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  scope.injectedScript()->addPromiseCallback(
      m_session, scope.object(), scope.objectGroupName(),
      std::move(wrapOptions), false /* replMode */,
      false /* throwOnSideEffect */,
      EvaluateCallbackWrapper<AwaitPromiseCallback>::wrap(std::move(callback)));
}

void V8RuntimeAgentImpl::callFunctionOn(
    const String16& expression, Maybe<String16> objectId,
    Maybe<protocol::Array<protocol::Runtime::CallArgument>> optionalArguments,
    Maybe<bool> silent, Maybe<bool> returnByValue, Maybe<bool> generatePreview,
    Maybe<bool> userGesture, Maybe<bool> awaitPromise,
    Maybe<int> executionContextId, Maybe<String16> objectGroup,
    Maybe<bool> throwOnSideEffect, Maybe<String16> uniqueContextId,
    Maybe<protocol::Runtime::SerializationOptions> serializationOptions,
    std::unique_ptr<CallFunctionOnCallback> callback) {
  int justCount = (objectId.has_value() ? 1 : 0) +
                  (executionContextId.has_value() ? 1 : 0) +
                  (uniqueContextId.has_value() ? 1 : 0);
  if (justCount > 1) {
    callback->sendFailure(Response::InvalidParams(
        "ObjectId, executionContextId and uniqueContextId must mutually "
        "exclude each other"));
    return;
  }
  if (justCount < 1) {
    callback->sendFailure(
        Response::InvalidParams("Either objectId or executionContextId or "
                                "uniqueContextId must be specified"));
    return;
  }

  if (objectId.has_value()) {
    InjectedScript::ObjectScope scope(m_session, objectId.value());
    Response response = scope.initialize();
    if (!response.IsSuccess()) {
      callback->sendFailure(response);
      return;
    }

    std::unique_ptr<WrapOptions> wrapOptions;
    response = getWrapOptions(
        std::move(returnByValue), std::move(generatePreview),
        std::move(serializationOptions), m_inspector->isolate(), &wrapOptions);
    if (!response.IsSuccess()) {
      callback->sendFailure(response);
      return;
    }

    innerCallFunctionOn(m_session, scope, scope.object(), expression,
                        std::move(optionalArguments), silent.value_or(false),
                        std::move(wrapOptions), userGesture.value_or(false),
                        awaitPromise.value_or(false),
                        objectGroup.value_or(scope.objectGroupName()),
                        throwOnSideEffect.value_or(false), std::move(callback));
  } else {
    int contextId = 0;
    Response response = ensureContext(m_inspector, m_session->contextGroupId(),
                                      std::move(executionContextId),
                                      std::move(uniqueContextId), &contextId);
    if (!response.IsSuccess()) {
      callback->sendFailure(response);
      return;
    }
    InjectedScript::ContextScope scope(m_session, contextId);
    response = scope.initialize();
    if (!response.IsSuccess()) {
      callback->sendFailure(response);
      return;
    }

    std::unique_ptr<WrapOptions> wrapOptions;
    response = getWrapOptions(
        std::move(returnByValue), std::move(generatePreview),
        std::move(serializationOptions), m_inspector->isolate(), &wrapOptions);
    if (!response.IsSuccess()) {
      callback->sendFailure(response);
      return;
    }

    innerCallFunctionOn(m_session, scope, scope.context()->Global(), expression,
                        std::move(optionalArguments), silent.value_or(false),
                        std::move(wrapOptions), userGesture.value_or(false),
                        awaitPromise.value_or(false), objectGroup.value_or(""),
                        throwOnSideEffect.value_or(false), std::move(callback));
  }
}

Response V8RuntimeAgentImpl::getProperties(
    const String16& objectId, Maybe<bool> ownProperties,
    Maybe<bool> accessorPropertiesOnly, Maybe<bool> generatePreview,
    Maybe<bool> nonIndexedPropertiesOnly,
    std::unique_ptr<protocol::Array<protocol::Runtime::PropertyDescriptor>>*
        result,
    Maybe<protocol::Array<protocol::Runtime::InternalPropertyDescriptor>>*
        internalProperties,
    Maybe<protocol::Array<protocol::Runtime::PrivatePropertyDescriptor>>*
        privateProperties,
    Maybe<protocol::Runtime::ExceptionDetails>* exceptionDetails) {
  using protocol::Runtime::InternalPropertyDescriptor;
  using protocol::Runtime::PrivatePropertyDescriptor;

  InjectedScript::ObjectScope scope(m_session, objectId);
  Response response = scope.initialize();
  if (!response.IsSuccess()) return response;

  scope.ignoreExceptionsAndMuteConsole();
  v8::MicrotasksScope microtasks_scope(scope.context(),
                                       v8::MicrotasksScope::kRunMicrotasks);
  if (!scope.object()->IsObject())
    return Response::ServerError("Value with given id is not an object");

  v8::Local<v8::Object> object = scope.object().As<v8::Object>();

  std::unique_ptr<WrapOptions> wrapOptions;
  response =
      getWrapOptions(false /* returnByValue */, std::move(generatePreview),
                     m_inspector->isolate(), &wrapOptions);
  if (!response.IsSuccess()) return response;

  response = scope.injectedScript()->getProperties(
      object, scope.objectGroupName(), ownProperties.value_or(false),
      accessorPropertiesOnly.value_or(false),
      nonIndexedPropertiesOnly.value_or(false), *wrapOptions, result,
      exceptionDetails);
  if (!response.IsSuccess()) return response;
  if (*exceptionDetails) return Response::Success();
  std::unique_ptr<protocol::Array<InternalPropertyDescriptor>>
      internalPropertiesProtocolArray;
  std::unique_ptr<protocol::Array<PrivatePropertyDescriptor>>
      privatePropertiesProtocolArray;
  response = scope.injectedScript()->getInternalAndPrivateProperties(
      object, scope.objectGroupName(), accessorPropertiesOnly.value_or(false),
      &internalPropertiesProtocolArray, &privatePropertiesProtocolArray);
  if (!response.IsSuccess()) return response;
  if (!internalPropertiesProtocolArray->empty())
    *internalProperties = std::move(internalPropertiesProtocolArray);
  if (!privatePropertiesProtocolArray->empty())
    *privateProperties = std::move(privatePropertiesProtocolArray);
  return Response::Success();
}

Response V8RuntimeAgentImpl::releaseObject(const String16& objectId) {
  InjectedScript::ObjectScope scope(m_session, objectId);
  Response response = scope.initialize();
  if (!response.IsSuccess()) return response;
  scope.injectedScript()->releaseObject(objectId);
  return Response::Success();
}

Response V8RuntimeAgentImpl::releaseObjectGroup(const String16& objectGroup) {
  m_session->releaseObjectGroup(objectGroup);
  return Response::Success();
}

Response V8RuntimeAgentImpl::runIfWaitingForDebugger() {
  if (m_debuggerBarrier) {
    m_debuggerBarrier.reset();
    return Response::Success();
  }
  // TODO(chromium:1352175): the below is provisional until client-side changes
  // land. The call should come through the barrier only once client properly
  // communicates whether the session is waiting for debugger.
  m_inspector->client()->runIfWaitingForDebugger(m_session->contextGroupId());
  return Response::Success();
}

Response V8RuntimeAgentImpl::setCustomObjectFormatterEnabled(bool enabled) {
  m_state->setBoolean(V8RuntimeAgentImplState::customObjectFormatterEnabled,
                      enabled);
  if (!m_enabled) return Response::ServerError("Runtime agent is not enabled");
  m_session->setCustomObjectFormatterEnabled(enabled);
  return Response::Success();
}

Response V8RuntimeAgentImpl::setMaxCallStackSizeToCapture(int size) {
  if (size < 0) {
    return Response::ServerError(
        "maxCallStackSizeToCapture should be non-negative");
  }
  TRACE_EVENT_WITH_FLOW1(
      TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
      "V8RuntimeAgentImpl::setMaxCallStackSizeToCapture", this,
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT, "size", size);
  if (!m_enabled) return Response::ServerError("Runtime agent is not enabled");
  m_state->setInteger(V8RuntimeAgentImplState::maxCallStackSizeToCapture, size);
  m_inspector->debugger()->setMaxCallStackSizeToCapture(this, size);
  return Response::Success();
}

Response V8RuntimeAgentImpl::discardConsoleEntries() {
  V8ConsoleMessageStorage* storage =
      m_inspector->ensureConsoleMessageStorage(m_session->contextGroupId());
  storage->clear();
  return Response::Success();
}

Response V8RuntimeAgentImpl::compileScript(
    const String16& expression, const String16& sourceURL, bool persistScript,
    Maybe<int> executionContextId, Maybe<String16>* scriptId,
    Maybe<protocol::Runtime::ExceptionDetails>* exceptionDetails) {
  if (!m_enabled) return Response::ServerError("Runtime agent is not enabled");

  int contextId = 0;
  Response response = ensureContext(m_inspector, m_session->contextGroupId(),
                                    std::move(executionContextId),
                                    /*uniqueContextId*/ {}, &contextId);
  if (!response.IsSuccess()) return response;
  InjectedScript::ContextScope scope(m_session, contextId);
  response = scope.initialize();
  if (!response.IsSuccess()) return response;

  if (!persistScript) m_inspector->debugger()->muteScriptParsedEvents();
  v8::Local<v8::Script> script;
  bool isOk = m_inspector->compileScript(scope.context(), expression, sourceURL)
                  .ToLocal(&script);
  if (!persistScript) m_inspector->debugger()->unmuteScriptParsedEvents();
  if (!isOk) {
    if (scope.tryCatch().HasCaught()) {
      response = scope.injectedScript()->createExceptionDetails(
          scope.tryCatch(), String16(), exceptionDetails);
      if (!response.IsSuccess()) return response;
      return Response::Success();
    } else {
      return Response::ServerError("Script compilation failed");
    }
  }

  if (!persistScript) return Response::Success();

  String16 scriptValueId =
      String16::fromInteger(script->GetUnboundScript()->GetId());
  std::unique_ptr<v8::Global<v8::Script>> global(
      new v8::Global<v8::Script>(m_inspector->isolate(), script));
  m_compiledScripts[scriptValueId] = std::move(global);
  *scriptId = scriptValueId;
  return Response::Success();
}

void V8RuntimeAgentImpl::runScript(
    const String16& scriptId, Maybe<int> executionContextId,
    Maybe<String16> objectGroup, Maybe<bool> silent,
    Maybe<bool> includeCommandLineAPI, Maybe<bool> returnByValue,
    Maybe<bool> generatePreview, Maybe<bool> awaitPromise,
    std::unique_ptr<RunScriptCallback> callback) {
  if (!m_enabled) {
    callback->sendFailure(
        Response::ServerError("Runtime agent is not enabled"));
    return;
  }

  auto it = m_compiledScripts.find(scriptId);
  if (it == m_compiledScripts.end()) {
    callback->sendFailure(Response::ServerError("No script with given id"));
    return;
  }

  int contextId = 0;
  Response response = ensureContext(m_inspector, m_session->contextGroupId(),
                                    std::move(executionContextId),
                                    /*uniqueContextId*/ {}, &contextId);
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  InjectedScript::ContextScope scope(m_session, contextId);
  response = scope.initialize();
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  if (silent.value_or(false)) scope.ignoreExceptionsAndMuteConsole();

  std::unique_ptr<v8::Global<v8::Script>> scriptWrapper = std::move(it->second);
  m_compiledScripts.erase(it);
  v8::Local<v8::Script> script = scriptWrapper->Get(m_inspector->isolate());
  if (script.IsEmpty()) {
    callback->sendFailure(Response::ServerError("Script execution failed"));
    return;
  }

  if (includeCommandLineAPI.value_or(false)) scope.installCommandLineAPI();

  v8::MaybeLocal<v8::Value> maybeResultValue;
  {
    v8::MicrotasksScope microtasksScope(scope.context(),
                                        v8::MicrotasksScope::kRunMicrotasks);
    maybeResultValue = script->Run(scope.context());
  }

  // Re-initialize after running client's code, as it could have destroyed
  // context or session.
  response = scope.initialize();
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  std::unique_ptr<WrapOptions> wrapOptions;
  response =
      getWrapOptions(std::move(returnByValue), std::move(generatePreview),
                     m_inspector->isolate(), &wrapOptions);
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  if (!awaitPromise.value_or(false) || scope.tryCatch().HasCaught()) {
    wrapEvaluateResultAsync(scope.injectedScript(), maybeResultValue,
                            scope.tryCatch(), objectGroup.value_or(""),
                            *wrapOptions, false /* throwOnSideEffect */,
                            callback.get());
    return;
  }
  scope.injectedScript()->addPromiseCallback(
      m_session, maybeResultValue.ToLocalChecked(), objectGroup.value_or(""),
      std::move(wrapOptions), false /* replMode */,
      false /* throwOnSideEffect */,
      EvaluateCallbackWrapper<RunScriptCallback>::wrap(std::move(callback)));
}

Response V8RuntimeAgentImpl::queryObjects(
    const String16& prototypeObjectId, Maybe<String16> objectGroup,
    std::unique_ptr<protocol::Runtime::RemoteObject>* objects) {
  InjectedScript::ObjectScope scope(m_session, prototypeObjectId);
  Response response = scope.initialize();
  if (!response.IsSuccess()) return response;
  if (!scope.object()->IsObject()) {
    return Response::ServerError("Prototype should be instance of Object");
  }
  v8::Local<v8::Array> resultArray = m_inspector->debugger()->queryObjects(
      scope.context(), scope.object().As<v8::Object>());
  return scope.injectedScript()->wrapObject(
      resultArray, objectGroup.value_or(scope.objectGroupName()),
      WrapOptions({WrapMode::kIdOnly}), objects);
}

Response V8RuntimeAgentImpl::globalLexicalScopeNames(
    Maybe<int> executionContextId,
    std::unique_ptr<protocol::Array<String16>>* outNames) {
  int contextId = 0;
  Response response = ensureContext(m_inspector, m_session->contextGroupId(),
```