Response:
My thought process to analyze the `injected-script.h` file goes like this:

1. **Understand the Goal:** The request asks for a breakdown of the file's functionality, considering potential Torque usage, JavaScript relevance, logic with input/output, and common programming errors.

2. **Initial Scan and Keyword Recognition:** I first scanned the file for keywords and structural elements:
    * `#ifndef`, `#define`, `#include`: Standard C++ header file structure.
    * `namespace v8_inspector`: Indicates this is part of the V8 inspector.
    * `class`, `struct`: Defines classes and structures. The presence of many classes is a strong indicator of a complex component with various responsibilities.
    * `EvaluateCallback`, `InjectedScript`, `Scope`, `ContextScope`, `ObjectScope`, `CallFrameScope`, `PromiseHandlerTracker`: These class names immediately suggest core functionalities related to script evaluation, object inspection, and asynchronous operations.
    * `protocol::`:  Indicates interaction with the Chrome DevTools Protocol (CDP).
    * `v8::`: Indicates interaction with the V8 JavaScript engine's API.
    * `String16`: Likely a custom string class used within V8.
    * Comments:  The copyright notice and the comment block before `PromiseHandlerTracker` provide valuable context.

3. **High-Level Purpose Inference:** Based on the keywords and structure, I deduced that `injected-script.h` defines the `InjectedScript` class, which acts as a bridge between the V8 JavaScript engine and the Chrome DevTools. It seems responsible for:
    * Executing and managing JavaScript code within the inspected context.
    * Inspecting JavaScript objects and their properties.
    * Handling asynchronous operations (Promises).
    * Communicating with the DevTools frontend via the CDP.

4. **Detailed Class Analysis:** I went through each major class to understand its specific role:
    * **`EvaluateCallback`:**  Deals with the asynchronous nature of JavaScript evaluation. It has `sendSuccess` and `sendFailure` methods, crucial for reporting results back to the DevTools.
    * **`InjectedScript`:** The core class. Its methods (`getProperties`, `wrapObject`, `evaluate`, `releaseObject`, etc.) strongly suggest its role in interacting with the JavaScript environment and preparing data for the DevTools. The nested `Scope` classes further refine how interactions happen within different contexts (execution context, object context, call frame).
    * **`Scope` and its subclasses (`ContextScope`, `ObjectScope`, `CallFrameScope`):** These seem to manage the context in which operations are performed. They handle setting up the V8 environment (e.g., `TryCatch`, command-line API). The different subclasses represent different levels of context during debugging (general context, specific object, specific call frame).
    * **`PromiseHandlerTracker`:**  Clearly manages the lifecycle of promises during evaluation, especially for asynchronous operations and the communication of their results to the DevTools.

5. **Torque Consideration:** The request specifically asks about `.tq` files. Since the file ends in `.h`, it's a standard C++ header file, *not* a Torque file. I noted this clearly.

6. **JavaScript Relevance and Examples:**  Since the core purpose is interacting with the JavaScript engine for debugging, the entire file is inherently related to JavaScript. I looked for methods that directly translate to JavaScript concepts:
    * `getProperties`:  Relates to accessing object properties in JavaScript.
    * `wrapObject`:  Important for representing JavaScript objects in the DevTools.
    * `evaluate`: Directly executes JavaScript code.
    * The concept of scopes (global, function, block) maps to the `Scope` and its subclasses.
    * Promises are a fundamental JavaScript feature, making `PromiseHandlerTracker` and related methods relevant.

    I then formulated simple JavaScript examples to illustrate these connections. For example, showing how `getProperties` would relate to `Object.keys()` or accessing properties directly.

7. **Logic Inference and Input/Output:** I looked for methods where the input and output could be reasoned about:
    * `getProperties`: Input is a `v8::Local<v8::Object>`, and the output is a `protocol::Array<protocol::Runtime::PropertyDescriptor>`. This involves inspecting a JavaScript object and converting its properties into a DevTools-friendly format.
    * `wrapObject`:  Input is a `v8::Local<v8::Value>`, and the output is a `protocol::Runtime::RemoteObject`. This involves taking a V8 value and creating a representation that can be sent to the DevTools.
    * `evaluate`:  Input is a string of JavaScript code, and the output is a `protocol::Runtime::RemoteObject` representing the result (or an `ExceptionDetails`).

8. **Common Programming Errors:**  I considered common mistakes developers make that would be relevant in the context of debugging and using the DevTools:
    * **Incorrectly assuming object properties:** Demonstrating a case where `getProperties` with specific flags would return different results based on property attributes.
    * **Misunderstanding asynchronous behavior:** Illustrating how forgetting to handle promises would lead to unhandled rejections, which the DevTools helps to identify.

9. **Structure and Formatting:**  I organized the information clearly, using headings and bullet points for readability. I made sure to address each part of the original request.

10. **Review and Refinement:** Finally, I reviewed my analysis to ensure accuracy, clarity, and completeness. I checked for any ambiguities or areas where further explanation might be needed. For example, making sure the connection between the C++ code and the JavaScript examples was explicit.
好的，让我们来分析一下 `v8/src/inspector/injected-script.h` 这个 V8 源代码文件。

**文件功能概览**

`v8/src/inspector/injected-script.h` 定义了 `InjectedScript` 类及其相关的辅助类，它是 V8 Inspector (调试器) 的核心组件之一。 `InjectedScript` 的主要职责是：

1. **作为 JavaScript 代码和 Inspector 后端之间的桥梁：** 它允许 Inspector 后端（C++ 代码）在特定的 JavaScript 上下文（通常是正在调试的页面或 Node.js 应用）中执行代码、检查对象、获取属性等。
2. **管理 JavaScript 对象的生命周期和表示：**  当 Inspector 需要引用 JavaScript 对象时，`InjectedScript` 会创建并管理这些对象的代理 (RemoteObject)。这涉及到对象的序列化、唯一标识符的生成和释放。
3. **处理 JavaScript 代码的执行和求值：** 它提供了在目标上下文中执行 JavaScript 代码的方法，并能够捕获执行结果和异常信息。
4. **提供用于对象检查和属性获取的接口：**  它允许 Inspector 获取对象的属性（包括自有属性、继承属性、内部属性和私有属性）。
5. **支持 Promise 的异步操作：** 它能追踪 Promise 的状态，并在 Promise resolve 或 reject 时通知 Inspector。
6. **管理 Inspector 的上下文环境：**  它定义了 `Scope` 类及其子类，用于在不同的上下文中执行操作，例如在特定的执行上下文中、在特定的对象上下文中或在特定的调用帧上下文中。

**文件类型判断**

`v8/src/inspector/injected-script.h` 以 `.h` 结尾，这表明它是一个 **C++ 头文件**，而不是 V8 Torque 源代码。 Torque 文件的扩展名通常是 `.tq`。

**与 JavaScript 功能的关系及 JavaScript 示例**

`InjectedScript` 类与 JavaScript 的功能有着密切的联系，因为它主要负责与 JavaScript 运行时环境进行交互。以下是一些相关的 JavaScript 功能及其对应的 `InjectedScript` 方法示例：

1. **获取对象属性 (`getProperties`)：**

   在 JavaScript 中，我们可以使用多种方式获取对象的属性，例如使用点号 `.`、方括号 `[]` 或 `Object.keys()`。`InjectedScript::getProperties` 提供了 Inspector 后端获取这些属性的机制。

   ```javascript
   const myObject = { a: 1, b: 'hello', c: true };

   // 使用点号访问属性
   console.log(myObject.a); // 输出: 1

   // 使用方括号访问属性
   console.log(myObject['b']); // 输出: hello

   // 使用 Object.keys() 获取所有可枚举的自有属性
   console.log(Object.keys(myObject)); // 输出: ['a', 'b', 'c']
   ```

   `InjectedScript::getProperties` 可以根据不同的参数（例如 `ownProperties`）来模拟这些 JavaScript 的行为，返回不同类型的属性描述符。

2. **执行 JavaScript 代码 (`EvaluateCallback` 和相关的 `Scope` 类)：**

   Inspector 允许开发者在调试过程中执行 JavaScript 代码。 `InjectedScript` 使用 `EvaluateCallback` 来处理代码执行的结果，并使用 `Scope` 类来设置执行上下文。

   ```javascript
   let x = 10;
   let y = 20;
   let sum = x + y;
   console.log(sum); // 输出: 30
   ```

   当你在 Inspector 的控制台中输入类似 `x + y` 的表达式并执行时，Inspector 后端会调用 `InjectedScript` 的相关方法，在当前的 JavaScript 上下文中执行这段代码，并将结果返回到 Inspector 前端。

3. **包装 JavaScript 对象 (`wrapObject`)：**

   为了在 Inspector 前端表示 JavaScript 对象，需要将它们包装成 `protocol::Runtime::RemoteObject`。`InjectedScript::wrapObject` 负责完成这个过程。

   ```javascript
   const myArray = [1, 'two', { key: 'value' }];
   console.log(myArray); // 在控制台中显示数组
   ```

   当 Inspector 需要显示 `myArray` 的内容时，`wrapObject` 会创建一个 `RemoteObject`，其中包含了数组的类型、类名、以及可能包含其属性的描述。

4. **释放对象 (`releaseObject` 和 `releaseObjectGroup`)：**

   为了避免内存泄漏，当 Inspector 不再需要引用某个 JavaScript 对象时，需要将其释放。 `InjectedScript` 提供了 `releaseObject` 和 `releaseObjectGroup` 方法来管理这些 `RemoteObject` 的生命周期。

5. **处理 Promise (`addPromiseCallback`)：**

   当在 Inspector 中执行返回 Promise 的代码时，`InjectedScript` 使用 `addPromiseCallback` 来追踪 Promise 的状态，并在 Promise resolve 或 reject 时通知 Inspector。

   ```javascript
   const myPromise = new Promise((resolve, reject) => {
     setTimeout(() => {
       resolve('Promise resolved!');
     }, 1000);
   });

   myPromise.then(result => {
     console.log(result); // 一秒后输出: Promise resolved!
   });
   ```

   Inspector 可以利用 `addPromiseCallback` 来监视 `myPromise` 的状态，并在其变为 resolved 时，显示其结果。

**代码逻辑推理及假设输入与输出**

让我们以 `getProperties` 方法为例进行代码逻辑推理：

**假设输入：**

* `v8::Local<v8::Object>`: 一个表示 JavaScript 对象的 V8 局部句柄，例如表示 `{ a: 1, b: 'hello' }` 的对象。
* `groupName`: 一个字符串，表示对象所属的分组，例如 `"console"`.
* `ownProperties`: `true` (只获取自有属性)。
* `accessorPropertiesOnly`: `false` (不只获取访问器属性)。
* `nonIndexedPropertiesOnly`: `false` (不只获取非索引属性)。
* `wrapOptions`: 一些包装选项，例如是否生成预览。

**代码逻辑：**

1. `getProperties` 方法会使用 V8 API 来遍历输入 `v8::Local<v8::Object>` 的属性。
2. 根据 `ownProperties` 的值，它会决定是否只考虑对象的自有属性，还是包括继承的属性。
3. 根据 `accessorPropertiesOnly` 的值，它会决定是否只返回访问器属性 (getter/setter)。
4. 根据 `nonIndexedPropertiesOnly` 的值，它会决定是否排除数组索引类型的属性。
5. 对于符合条件的每个属性，它会创建一个 `protocol::Runtime::PropertyDescriptor` 对象，其中包含属性的名称、类型、值（可能会被包装成 `RemoteObject`）以及其他属性描述符。
6. 如果在获取属性的过程中发生异常，它会填充 `Maybe<protocol::Runtime::ExceptionDetails>*`。

**假设输出：**

假设输入的对象是 `{ a: 1, b: 'hello' }`，且其他参数如上所述，则输出的 `result` 可能包含一个 `protocol::Array<protocol::Runtime::PropertyDescriptor>`，其内容类似于：

```json
[
  {
    "name": "a",
    "value": {
      "type": "number",
      "value": 1
    },
    "writable": true,
    "configurable": true,
    "enumerable": true
  },
  {
    "name": "b",
    "value": {
      "type": "string",
      "value": "hello"
    },
    "writable": true,
    "configurable": true,
    "enumerable": true
  }
]
```

**涉及用户常见的编程错误**

`InjectedScript` 的功能与调试密切相关，因此它能帮助开发者发现和理解各种编程错误。以下是一些例子：

1. **访问未定义的属性导致错误：**

   ```javascript
   const myObject = { a: 1 };
   console.log(myObject.b.toUpperCase()); // TypeError: Cannot read properties of undefined (reading 'toUpperCase')
   ```

   当在 Inspector 中执行这段代码时，`InjectedScript` 可以捕获这个 `TypeError`，并通过 `createExceptionDetails` 方法将异常信息传递给 Inspector 前端，帮助开发者定位问题。

2. **Promise 未处理的 rejection：**

   ```javascript
   const myPromise = new Promise((resolve, reject) => {
     setTimeout(() => {
       reject('Something went wrong!');
     }, 500);
   });

   // 没有提供 .catch() 来处理 rejection
   ```

   `InjectedScript` 可以追踪 Promise 的状态，如果一个 Promise 被 rejected 且没有提供相应的 `.catch()` 处理，Inspector 可以发出警告，提醒开发者存在潜在的错误。

3. **作用域理解错误：**

   ```javascript
   function myFunction() {
     let localVar = 10;
   }
   myFunction();
   console.log(localVar); // ReferenceError: localVar is not defined
   ```

   在调试过程中，开发者可以使用 Inspector 的 Scope 功能来查看不同作用域中的变量。`InjectedScript` 的 `Scope` 类及其子类为 Inspector 提供了访问这些作用域的能力，帮助开发者理解变量的作用域和生命周期，从而发现这类错误。

4. **意外的类型转换：**

   ```javascript
   let count = "5";
   let result = count + 2;
   console.log(result); // 输出: "52" (字符串拼接，而非数字加法)
   ```

   通过 Inspector 检查变量的值和类型，开发者可以发现这种意外的类型转换，并使用 `InjectedScript` 执行代码来验证他们的假设，例如 `typeof count`。

总之，`v8/src/inspector/injected-script.h` 定义的 `InjectedScript` 类是 V8 Inspector 的核心组成部分，它负责在 JavaScript 运行时环境和 Inspector 后端之间建立通信桥梁，提供代码执行、对象检查、属性获取等关键功能，并能帮助开发者识别和理解各种 JavaScript 编程错误。

### 提示词
```
这是目录为v8/src/inspector/injected-script.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/injected-script.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
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

#ifndef V8_INSPECTOR_INJECTED_SCRIPT_H_
#define V8_INSPECTOR_INJECTED_SCRIPT_H_

#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "include/v8-exception.h"
#include "include/v8-local-handle.h"
#include "include/v8-persistent-handle.h"
#include "src/base/macros.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Forward.h"
#include "src/inspector/protocol/Runtime.h"
#include "src/inspector/v8-console.h"
#include "src/inspector/v8-debugger.h"

namespace v8_inspector {

class RemoteObjectId;
class V8InspectorImpl;
class V8InspectorSessionImpl;
class ValueMirror;

using protocol::Maybe;
using protocol::Response;

class EvaluateCallback {
 public:
  static void sendSuccess(
      std::weak_ptr<EvaluateCallback> callback, InjectedScript* injectedScript,
      std::unique_ptr<protocol::Runtime::RemoteObject> result,
      protocol::Maybe<protocol::Runtime::ExceptionDetails> exceptionDetails);
  static void sendFailure(std::weak_ptr<EvaluateCallback> callback,
                          InjectedScript* injectedScript,
                          const protocol::DispatchResponse& response);

  virtual ~EvaluateCallback() = default;

 private:
  virtual void sendSuccess(
      std::unique_ptr<protocol::Runtime::RemoteObject> result,
      protocol::Maybe<protocol::Runtime::ExceptionDetails>
          exceptionDetails) = 0;
  virtual void sendFailure(const protocol::DispatchResponse& response) = 0;
};

class InjectedScript final {
 public:
  InjectedScript(InspectedContext*, int sessionId);
  ~InjectedScript();
  InjectedScript(const InjectedScript&) = delete;
  InjectedScript& operator=(const InjectedScript&) = delete;

  InspectedContext* context() const { return m_context; }

  Response getProperties(
      v8::Local<v8::Object>, const String16& groupName, bool ownProperties,
      bool accessorPropertiesOnly, bool nonIndexedPropertiesOnly,
      const WrapOptions& wrapOptions,
      std::unique_ptr<protocol::Array<protocol::Runtime::PropertyDescriptor>>*
          result,
      Maybe<protocol::Runtime::ExceptionDetails>*);

  Response getInternalAndPrivateProperties(
      v8::Local<v8::Value>, const String16& groupName,
      bool accessorPropertiesOnly,
      std::unique_ptr<
          protocol::Array<protocol::Runtime::InternalPropertyDescriptor>>*
          internalProperties,
      std::unique_ptr<
          protocol::Array<protocol::Runtime::PrivatePropertyDescriptor>>*
          privateProperties);

  void releaseObject(const String16& objectId);

  Response wrapObject(v8::Local<v8::Value>, const String16& groupName,
                      const WrapOptions& wrapOptions,
                      std::unique_ptr<protocol::Runtime::RemoteObject>* result);
  Response wrapObject(v8::Local<v8::Value>, const String16& groupName,
                      const WrapOptions& wrapOptions,
                      v8::MaybeLocal<v8::Value> customPreviewConfig,
                      int maxCustomPreviewDepth,
                      std::unique_ptr<protocol::Runtime::RemoteObject>* result);
  Response wrapObjectMirror(
      const ValueMirror& mirror, const String16& groupName,
      const WrapOptions& wrapOptions,
      v8::MaybeLocal<v8::Value> customPreviewConfig, int maxCustomPreviewDepth,
      std::unique_ptr<protocol::Runtime::RemoteObject>* result);
  std::unique_ptr<protocol::Runtime::RemoteObject> wrapTable(
      v8::Local<v8::Object> table, v8::MaybeLocal<v8::Array> columns);

  void addPromiseCallback(V8InspectorSessionImpl* session,
                          v8::MaybeLocal<v8::Value> value,
                          const String16& objectGroup,
                          std::unique_ptr<WrapOptions> wrapOptions,
                          bool replMode, bool throwOnSideEffect,
                          std::shared_ptr<EvaluateCallback> callback);

  Response findObject(const RemoteObjectId&, v8::Local<v8::Value>*) const;
  String16 objectGroupName(const RemoteObjectId&) const;
  void releaseObjectGroup(const String16&);
  void setCustomObjectFormatterEnabled(bool);
  Response resolveCallArgument(protocol::Runtime::CallArgument*,
                               v8::Local<v8::Value>* result);

  Response createExceptionDetails(
      const v8::TryCatch&, const String16& groupName,
      Maybe<protocol::Runtime::ExceptionDetails>* result);
  Response createExceptionDetails(
      v8::Local<v8::Message> message, v8::Local<v8::Value> exception,
      const String16& groupName,
      Maybe<protocol::Runtime::ExceptionDetails>* result);

  Response wrapEvaluateResult(
      v8::MaybeLocal<v8::Value> maybeResultValue, const v8::TryCatch&,
      const String16& objectGroup, const WrapOptions& wrapOptions,
      bool throwOnSideEffect,
      std::unique_ptr<protocol::Runtime::RemoteObject>* result,
      Maybe<protocol::Runtime::ExceptionDetails>*);
  v8::Local<v8::Value> lastEvaluationResult() const;
  void setLastEvaluationResult(v8::Local<v8::Value> result);

  class Scope {
   public:
    Response initialize();
    void installCommandLineAPI();
    void ignoreExceptionsAndMuteConsole();
    void pretendUserGesture();
    void allowCodeGenerationFromStrings();
    void setTryCatchVerbose();
    v8::Local<v8::Context> context() const { return m_context; }
    InjectedScript* injectedScript() const { return m_injectedScript; }
    const v8::TryCatch& tryCatch() const { return m_tryCatch; }
    V8InspectorImpl* inspector() const { return m_inspector; }

   protected:
    explicit Scope(V8InspectorSessionImpl*);
    virtual ~Scope();
    virtual Response findInjectedScript(V8InspectorSessionImpl*) = 0;

    V8InspectorImpl* m_inspector;
    InjectedScript* m_injectedScript;

   private:
    void cleanup();
    v8::debug::ExceptionBreakState setPauseOnExceptionsState(
        v8::debug::ExceptionBreakState);

    v8::HandleScope m_handleScope;
    v8::TryCatch m_tryCatch;
    v8::Local<v8::Context> m_context;
    std::unique_ptr<V8Console::CommandLineAPIScope> m_commandLineAPIScope;
    bool m_ignoreExceptionsAndMuteConsole;
    v8::debug::ExceptionBreakState m_previousPauseOnExceptionsState;
    bool m_userGesture;
    bool m_allowEval;
    int m_contextGroupId;
    int m_sessionId;
  };

  class ContextScope : public Scope {
   public:
    ContextScope(V8InspectorSessionImpl*, int executionContextId);
    ~ContextScope() override;
    ContextScope(const ContextScope&) = delete;
    ContextScope& operator=(const ContextScope&) = delete;

   private:
    Response findInjectedScript(V8InspectorSessionImpl*) override;
    int m_executionContextId;
  };

  class ObjectScope : public Scope {
   public:
    ObjectScope(V8InspectorSessionImpl*, const String16& remoteObjectId);
    ~ObjectScope() override;
    ObjectScope(const ObjectScope&) = delete;
    ObjectScope& operator=(const ObjectScope&) = delete;
    const String16& objectGroupName() const { return m_objectGroupName; }
    v8::Local<v8::Value> object() const { return m_object; }

   private:
    Response findInjectedScript(V8InspectorSessionImpl*) override;
    String16 m_remoteObjectId;
    String16 m_objectGroupName;
    v8::Local<v8::Value> m_object;
  };

  class CallFrameScope : public Scope {
   public:
    CallFrameScope(V8InspectorSessionImpl*, const String16& remoteCallFrameId);
    ~CallFrameScope() override;
    CallFrameScope(const CallFrameScope&) = delete;
    CallFrameScope& operator=(const CallFrameScope&) = delete;
    size_t frameOrdinal() const { return m_frameOrdinal; }

   private:
    Response findInjectedScript(V8InspectorSessionImpl*) override;
    String16 m_remoteCallFrameId;
    size_t m_frameOrdinal;
  };
  String16 bindObject(v8::Local<v8::Value>, const String16& groupName);

 private:
  friend class EvaluateCallback;
  friend class PromiseHandlerTracker;

  v8::Local<v8::Object> commandLineAPI();
  void unbindObject(int id);

  static Response bindRemoteObjectIfNeeded(
      int sessionId, v8::Local<v8::Context> context, v8::Local<v8::Value>,
      const String16& groupName, protocol::Runtime::RemoteObject* remoteObject);

  class ProtocolPromiseHandler;
  void discardEvaluateCallbacks();
  void deleteEvaluateCallback(std::shared_ptr<EvaluateCallback> callback);
  Response addExceptionToDetails(
      v8::Local<v8::Value> exception,
      protocol::Runtime::ExceptionDetails* exceptionDetails,
      const String16& objectGroup);

  InspectedContext* m_context;
  int m_sessionId;
  v8::Global<v8::Value> m_lastEvaluationResult;
  v8::Global<v8::Object> m_commandLineAPI;
  int m_lastBoundObjectId = 1;
  std::unordered_map<int, v8::Global<v8::Value>> m_idToWrappedObject;
  std::unordered_map<int, String16> m_idToObjectGroupName;
  std::unordered_map<String16, std::vector<int>> m_nameToObjectGroup;
  std::unordered_set<std::shared_ptr<EvaluateCallback>> m_evaluateCallbacks;
  bool m_customPreviewEnabled = false;
};

// Owns and tracks the life-time of {ProtocolPromiseHandler} instances.
// Each Runtime#evaluate, Runtime#awaitPromise or Runtime#callFunctionOn
// can create a {ProtocolPromiseHandler} to send the CDP response once it's
// ready.
//
// A {ProtocolPromiseHandler} can be destroyed by various events:
//
//   1) The evaluation promise fulfills (and we send the CDP response).
//   2) The evaluation promise gets GC'ed
//   3) The {PromiseHandlerTracker} owning the {ProtocolPromiseHandler} dies.
//
// We keep the logic of {PromiseHandlerTracker} separate so it's
// easier to move it. E.g. we could keep it on the inspector, session or
// inspected context level.
class PromiseHandlerTracker {
 public:
  PromiseHandlerTracker();
  PromiseHandlerTracker(const PromiseHandlerTracker&) = delete;
  void operator=(const PromiseHandlerTracker&) = delete;
  ~PromiseHandlerTracker();

  // Any reason other then kFulfilled will send a CDP error response as to
  // not keep the request pending forever. Depending on when the
  // {PromiseHandlerTracker} is destructed, the {EvaluateCallback} might
  // already be dead and we can't send the error response (but that's fine).
  enum class DiscardReason {
    kFulfilled,
    kPromiseCollected,
    kTearDown,
  };
  using Id = int64_t;

  template <typename... Args>
  Id create(Args&&... args);
  void discard(Id id, DiscardReason reason);
  InjectedScript::ProtocolPromiseHandler* get(Id id) const;

 private:
  void sendFailure(InjectedScript::ProtocolPromiseHandler* handler,
                   const protocol::DispatchResponse& response) const;
  void discardAll();

  std::map<Id, std::unique_ptr<InjectedScript::ProtocolPromiseHandler>>
      m_promiseHandlers;
  Id m_lastUsedId = 1;
};

}  // namespace v8_inspector

#endif  // V8_INSPECTOR_INJECTED_SCRIPT_H_
```