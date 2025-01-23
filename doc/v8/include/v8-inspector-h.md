Response:
Let's break down the thought process for analyzing the `v8-inspector.h` header file.

1. **Understand the Goal:** The request is to understand the *functionality* of this header file within the V8 project. This means identifying the main purpose, key classes, and their roles.

2. **Initial Scan for Keywords:** Quickly scan the file for recognizable keywords and patterns:
    * `#ifndef`, `#define`, `#include`: Standard C++ header file guards. Note the included V8 headers (`v8-isolate.h`, `v8-local-handle.h`). This immediately tells us it's related to V8's core functionality.
    * `namespace v8`, `namespace v8_inspector`:  Clear namespace organization, indicating the code belongs to the "inspector" part of V8.
    * `class`, `struct`:  Definitions of classes and structures. These will be the primary building blocks of the inspector's functionality.
    * `V8_EXPORT`:  Likely a macro for exporting these classes/structures from a shared library. This implies the inspector is a modular component.
    * `StringView`, `StringBuffer`:  Classes for handling strings efficiently, likely to avoid unnecessary copying.
    * `Context`, `Isolate`, `Value`, `Object`, `StackTrace`: These are fundamental V8 types, further reinforcing the connection to V8 internals.
    * `protocol::Debugger`, `protocol::Runtime`, `protocol::Schema`:  These namespaces strongly suggest the file deals with a debugging protocol. The "Debugger", "Runtime", and "Schema" parts are common in debugging/development tools.
    *  Method names like `dispatchProtocolMessage`, `schedulePauseOnNextStatement`, `resume`, `stepOver`, `evaluate`: These directly point to debugging actions.
    *  Method names like `contextCreated`, `contextDestroyed`, `asyncTaskScheduled`, `exceptionThrown`: These suggest the inspector is involved in monitoring and tracking the execution of JavaScript code.
    *  `V8InspectorClient`, `V8InspectorSession`, `V8Inspector`: These are the core classes, hinting at a client-server architecture for the inspector.

3. **Identify Core Components and Their Responsibilities:** Based on the initial scan, start grouping related elements:

    * **String Handling:** `StringView`, `StringBuffer`. These are utilities for efficient string management. Note the distinction between a read-only view and a mutable buffer.
    * **Context Information:** `V8ContextInfo`. This holds metadata about a V8 context, essential for managing multiple JavaScript execution environments.
    * **Debugger Identity:** `V8DebuggerId`. Crucial for uniquely identifying debugging sessions, especially for asynchronous operations.
    * **Stack Traces:** `V8StackFrame`, `V8StackTrace`, `V8StackTraceId`. Fundamental for debugging, providing information about the call stack. The `V8StackTraceId` suggests a mechanism for serializing and transferring stack trace information.
    * **Inspector Session:** `V8InspectorSession`. Represents an active debugging session. It handles protocol messages, manages breakpoints, evaluates expressions, and interacts with the client.
    * **Inspector Client Interface:** `V8InspectorClient`. Defines the interface that an embedding application needs to implement to integrate with the inspector. This includes handling pauses, serializing values, and managing contexts.
    * **Main Inspector Class:** `V8Inspector`. The central point of contact for the inspector. It creates and manages sessions and handles global inspector events (context creation/destruction, async tasks, exceptions).
    * **Protocol Communication:**  The `protocol::*` namespaces and methods like `dispatchProtocolMessage`, `sendResponse`, `sendNotification` clearly indicate the use of a debugging protocol (likely Chrome DevTools Protocol or a similar one).
    * **Remote Objects:**  The `wrapObject` and `unwrapObject` methods suggest a mechanism for inspecting JavaScript objects from the debugger.
    * **Evaluation:** The `evaluate` method allows executing JavaScript code within a specific context.

4. **Infer Functionality from Class and Method Names:**  Go through the classes and their methods and deduce their purpose based on their names. For example:

    * `schedulePauseOnNextStatement`:  Sets a breakpoint at the next line of code executed.
    * `breakProgram`:  Immediately pauses execution.
    * `resume`:  Continues execution.
    * `stepOver`:  Executes the current line and moves to the next in the same scope.
    * `searchInTextByLines`:  Searches for text within a script.
    * `contextCreated`, `contextDestroyed`:  Notifies the inspector about the creation and destruction of V8 contexts.
    * `asyncTaskScheduled`, `asyncTaskStarted`, `asyncTaskFinished`:  Instrumentation for tracking asynchronous operations.
    * `exceptionThrown`:  Reports uncaught exceptions to the debugger.

5. **Address Specific Questions in the Prompt:**

    * **Functionality List:**  Summarize the inferred functionality into a concise list, as done in the example answer.
    * **Torque Source:** Check the file extension. Since it's `.h`, it's a C++ header, not Torque.
    * **JavaScript Relationship and Examples:**  Think about how the inspector features relate to what a JavaScript developer experiences when debugging. Provide concrete JavaScript examples for actions like setting breakpoints, inspecting variables, and stepping through code.
    * **Code Logic and Assumptions:** Look for methods that might involve some processing. The `StringView` and `StringBuffer` classes involve handling string data. The `evaluate` method would involve compiling and executing JavaScript. Provide hypothetical inputs and outputs for basic scenarios.
    * **Common Programming Errors:**  Consider how the debugging features help identify common JavaScript errors (e.g., `TypeError`, `ReferenceError`, incorrect logic). Illustrate with simple code examples that would trigger these errors and how the debugger can help.

6. **Organize and Refine:** Structure the analysis logically, grouping related functionalities. Use clear and concise language. Ensure the JavaScript examples are easy to understand. Review and refine the explanation to ensure accuracy and completeness.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on individual methods. It's important to step back and see the bigger picture of how the classes and methods work together to provide the overall debugging functionality.
* I might initially miss the significance of the `protocol::*` namespaces. Realizing this indicates a debugging protocol is crucial for understanding how the inspector communicates with external tools.
* When providing JavaScript examples, ensure they are relevant to the C++ code being described. Don't just provide random JavaScript code. Focus on demonstrating the *effect* of the inspector's actions.

By following these steps, including careful observation, deduction, and organization, one can effectively analyze the functionality of a complex header file like `v8-inspector.h`.
这是一个V8源代码头文件 `v8/include/v8-inspector.h`，它定义了 V8 Inspector 的 C++ 接口。V8 Inspector 是一个强大的工具，允许开发者连接到正在运行的 V8 引擎（例如，在 Chrome 或 Node.js 中）并进行调试、性能分析和检查。

**功能列表：**

`v8/include/v8-inspector.h` 文件定义了以下主要功能：

1. **与调试器前端的通信:**
   - 定义了 `Channel` 类，用于发送和接收调试协议消息。
   - `V8InspectorSession` 类负责处理单个调试会话，包括消息分发 (`dispatchProtocolMessage`)、状态管理 (`state()`) 和支持的域 (`supportedDomains()`).
   - 定义了可以调度的调试操作，如暂停 (`schedulePauseOnNextStatement`, `breakProgram`)、恢复 (`resume`) 和单步执行 (`stepOver`).

2. **管理和跟踪 JavaScript 执行上下文 (Contexts):**
   - `V8ContextInfo` 结构体存储关于 JavaScript 执行上下文的信息，如关联的 V8 上下文、上下文组 ID 和可读名称。
   - `V8Inspector` 类提供了创建和销毁上下文的通知机制 (`contextCreated`, `contextDestroyed`).
   - 允许通过 ID 获取上下文 (`contextById`) 和获取上下文的唯一调试器 ID (`uniqueDebuggerId`).

3. **堆栈跟踪 (Stack Traces):**
   - 定义了 `V8StackFrame` 结构体表示堆栈帧。
   - `V8StackTrace` 类表示 JavaScript 的堆栈跟踪，并提供了获取顶部帧信息、构建 Inspector 协议对象和将其转换为字符串的方法。
   - `V8StackTraceId` 结构体用于在不同的调试器之间传递堆栈跟踪信息，用于异步调试等场景。

4. **远程对象检查 (Remote Object Inspection):**
   - `V8InspectorSession` 提供了 `wrapObject` 方法，用于将 V8 对象包装成可用于调试协议的远程对象。
   - `unwrapObject` 方法用于将远程对象 ID 解析回 V8 对象。
   - `releaseObjectGroup` 用于释放一组远程对象。

5. **表达式求值 (Expression Evaluation):**
   - `V8InspectorSession` 的 `evaluate` 方法允许在指定的 JavaScript 上下文中执行代码。

6. **断点和代码执行控制 (Breakpoints and Execution Control):**
   - 允许设置“在下一语句暂停” (`schedulePauseOnNextStatement`).
   - 允许中断程序执行 (`breakProgram`).
   - 允许设置跳过所有暂停 (`setSkipAllPauses`).
   - 提供了单步执行的控制 (`stepOver`).

7. **文本搜索 (Text Search):**
   - `V8InspectorSession` 提供了 `searchInTextByLines` 方法，用于在脚本中搜索文本。

8. **异步操作跟踪 (Asynchronous Operation Tracking):**
   - `V8Inspector` 提供了 `asyncTaskScheduled`, `asyncTaskCanceled`, `asyncTaskStarted`, `asyncTaskFinished` 等方法来跟踪异步任务的生命周期。
   - `storeCurrentStackTrace`, `externalAsyncTaskStarted`, `externalAsyncTaskFinished` 用于关联异步操作和它们的堆栈跟踪。

9. **异常处理 (Exception Handling):**
   - `V8Inspector` 提供了 `exceptionThrown` 方法来通知 Inspector 发生了异常。
   - `exceptionRevoked` 用于通知异常已被撤销。
   - `associateExceptionData` 允许关联额外的异常数据。

10. **深度序列化 (Deep Serialization):**
    - `DeepSerializedValue` 和 `DeepSerializationResult` 结构体以及 `V8InspectorClient` 的 `deepSerialize` 方法用于将 V8 值深度序列化为可以跨进程或网络传输的格式。

11. **V8 Inspector 客户端接口 (`V8InspectorClient`):**
    - 定义了一个抽象类 `V8InspectorClient`，V8 的嵌入器（例如 Chrome 或 Node.js）需要实现这个接口，以便与 Inspector 集成。
    - 接口包含了处理暂停、运行消息循环、序列化值、获取内存信息、控制台 API 消息处理等方法。

12. **唯一标识符生成 (`V8DebuggerId`):**
    - `V8DebuggerId` 用于生成唯一的调试器 ID，这对于跨调试器操作非常重要。

**关于文件类型和 Torque：**

`v8/include/v8-inspector.h` 的文件扩展名是 `.h`，这表明它是一个 **C++ 头文件**。如果文件以 `.tq` 结尾，那才是 V8 Torque 源代码。Torque 是一种 V8 内部使用的类型化的中间语言。

**与 JavaScript 的关系和示例：**

V8 Inspector 的功能直接与 JavaScript 的调试和分析相关。以下是一些 JavaScript 功能如何与 `v8-inspector.h` 中定义的功能关联的示例：

**1. 设置断点和单步执行：**

在 Chrome 开发者工具或 Node.js 调试器中设置断点，会触发 Inspector 调用 V8 的相应接口，最终调用到 `V8InspectorSession` 的方法，例如：

```javascript
// JavaScript 代码
function myFunction(a, b) { // 在这里设置一个断点
  const sum = a + b;
  console.log(sum);
  return sum;
}

myFunction(5, 3);
```

当代码执行到断点时，V8 会暂停执行，并通知 Inspector。Inspector 前端会显示当前的堆栈信息（对应 `V8StackTrace` 和 `V8StackFrame`），允许开发者单步执行（对应 `stepOver` 等方法）。

**2. 查看变量和对象：**

在调试过程中，可以查看 JavaScript 变量和对象的值。这涉及到 Inspector 调用 `V8InspectorSession` 的 `wrapObject` 方法，将 V8 的 `v8::Value` 包装成远程对象，以便在调试器前端显示。

```javascript
// JavaScript 代码
const myObject = { name: "Example", value: 42 }; // 查看 myObject
```

调试器会通过 Inspector 获取 `myObject` 的属性和值。

**3. 执行表达式：**

在调试器的控制台中执行 JavaScript 表达式，会调用 `V8InspectorSession` 的 `evaluate` 方法。

```javascript
// 在调试器控制台中输入：
myObject.name.toUpperCase()
```

Inspector 会在当前的 JavaScript 上下文中执行这个表达式，并将结果返回到调试器前端。

**4. 异步调试：**

当涉及到 `setTimeout`, `Promise`, `async/await` 等异步操作时，`V8Inspector` 的异步跟踪功能可以帮助开发者理解异步调用的流程。`asyncTaskScheduled`, `asyncTaskStarted`, `asyncTaskFinished` 等方法会被调用来记录异步任务的生命周期，并在调试器中显示异步调用栈。

```javascript
// JavaScript 代码
setTimeout(() => {
  console.log("延迟执行");
}, 1000);
```

Inspector 可以跟踪这个 `setTimeout` 回调的执行。

**代码逻辑推理示例（假设）：**

假设 `V8InspectorSession::evaluate` 方法的简化逻辑如下：

```c++
// 简化的 V8InspectorSession::evaluate
V8InspectorSession::EvaluateResult V8InspectorSession::evaluate(
    v8::Local<v8::Context> context, StringView expression,
    bool includeCommandLineAPI) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::String> source =
      v8::String::NewFromUtf8(isolate, expression.characters8(),
                              v8::NewStringType::kNormal, expression.length())
          .ToLocalChecked();

  v8::Local<v8::Script> script;
  v8::MaybeLocal<v8::Script> maybe_script =
      v8::Script::Compile(context, source);
  if (maybe_script.ToLocal(&script)) {
    v8::Local<v8::Value> result;
    v8::MaybeLocal<v8::Value> maybe_result = script->Run(context);
    if (maybe_result.ToLocal(&result)) {
      return {EvaluateResult::kSuccess, result};
    } else {
      // 处理执行错误
      return {EvaluateResult::kException, v8::Local<v8::Value>()};
    }
  } else {
    // 处理编译错误
    return {EvaluateResult::kException, v8::Local<v8::Value>()};
  }
}
```

**假设输入：**

- `context`: 一个有效的 V8 JavaScript 上下文。
- `expression`: `"2 + 2"` (StringView).
- `includeCommandLineAPI`: `false`.

**预期输出：**

- `EvaluateResult::type`: `EvaluateResult::kSuccess`.
- `EvaluateResult::value`: 一个表示数字 `4` 的 `v8::Local<v8::Value>`.

**用户常见的编程错误示例：**

涉及到 V8 Inspector 的常见编程错误通常是在使用 Inspector 的客户端 API 时发生，或者是在与调试器交互时理解其行为方面出现误解。

1. **在没有活跃的 Inspector 连接时尝试发送调试命令：** 如果你的程序没有正确地初始化 Inspector 或连接到调试器，尝试调用 Inspector 的方法将不会有任何效果。

   ```javascript
   // Node.js 示例 (错误)
   const v8 = require('v8');
   // 假设没有启动 Inspector
   v8.getHeapStatistics(); // 这不会通过 Inspector 发送任何信息
   ```

2. **错误地处理异步操作中的断点：** 开发者可能不理解异步代码的执行流程，导致在设置断点时出现困惑。例如，在一个 Promise 的回调函数中设置断点，但代码执行没有如预期暂停。

   ```javascript
   // JavaScript 示例
   function fetchData() {
     return new Promise(resolve => {
       setTimeout(() => {
         const data = { value: 10 }; // 期望在这里断点暂停
         resolve(data);
       }, 1000);
     });
   }

   async function main() {
     const result = await fetchData(); // 在这里设置断点可能会更有效
     console.log(result);
   }

   main();
   ```

3. **不理解远程对象生命周期：** 当通过 Inspector 获取远程对象时，开发者可能会误认为它们是普通的 JavaScript 对象，并尝试直接操作它们，而实际上需要使用 Inspector 提供的机制。

   ```javascript
   // 假设在调试器中查看了一个远程对象 remoteObj
   // 尝试直接修改远程对象 (错误)
   // remoteObj.newValue = 20; // 这不会直接修改原始的 V8 对象
   ```

4. **忘记处理 Inspector 发送的事件或响应：** 如果客户端没有正确实现 `V8InspectorClient` 接口，可能会丢失重要的调试信息或无法正确响应调试器的请求。

总而言之，`v8/include/v8-inspector.h` 定义了 V8 Inspector 的核心接口，它使得开发者能够对运行中的 JavaScript 代码进行深入的检查和控制，是构建调试器和性能分析工具的基础。

### 提示词
```
这是目录为v8/include/v8-inspector.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-inspector.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_V8_INSPECTOR_H_
#define V8_V8_INSPECTOR_H_

#include <stdint.h>

#include <cctype>
#include <memory>

#include "v8-isolate.h"       // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)

namespace v8 {
class Context;
class Name;
class Object;
class StackTrace;
class Value;
}  // namespace v8

namespace v8_inspector {

namespace internal {
class V8DebuggerId;
}  // namespace internal

namespace protocol {
namespace Debugger {
namespace API {
class SearchMatch;
}
}  // namespace Debugger
namespace Runtime {
namespace API {
class RemoteObject;
class StackTrace;
class StackTraceId;
}  // namespace API
}  // namespace Runtime
namespace Schema {
namespace API {
class Domain;
}
}  // namespace Schema
}  // namespace protocol

class V8_EXPORT StringView {
 public:
  StringView() : m_is8Bit(true), m_length(0), m_characters8(nullptr) {}

  StringView(const uint8_t* characters, size_t length)
      : m_is8Bit(true), m_length(length), m_characters8(characters) {}

  StringView(const uint16_t* characters, size_t length)
      : m_is8Bit(false), m_length(length), m_characters16(characters) {}

  bool is8Bit() const { return m_is8Bit; }
  size_t length() const { return m_length; }

  // TODO(dgozman): add DCHECK(m_is8Bit) to accessors once platform can be used
  // here.
  const uint8_t* characters8() const { return m_characters8; }
  const uint16_t* characters16() const { return m_characters16; }

 private:
  bool m_is8Bit;
  size_t m_length;
  union {
    const uint8_t* m_characters8;
    const uint16_t* m_characters16;
  };
};

class V8_EXPORT StringBuffer {
 public:
  virtual ~StringBuffer() = default;
  virtual StringView string() const = 0;
  // This method copies contents.
  static std::unique_ptr<StringBuffer> create(StringView);
};

class V8_EXPORT V8ContextInfo {
 public:
  V8ContextInfo(v8::Local<v8::Context> context, int contextGroupId,
                StringView humanReadableName)
      : context(context),
        contextGroupId(contextGroupId),
        humanReadableName(humanReadableName),
        hasMemoryOnConsole(false) {}

  v8::Local<v8::Context> context;
  // Each v8::Context is a part of a group. The group id must be non-zero.
  int contextGroupId;
  StringView humanReadableName;
  StringView origin;
  StringView auxData;
  bool hasMemoryOnConsole;

  static int executionContextId(v8::Local<v8::Context> context);

  // Disallow copying and allocating this one.
  enum NotNullTagEnum { NotNullLiteral };
  void* operator new(size_t) = delete;
  void* operator new(size_t, NotNullTagEnum, void*) = delete;
  void* operator new(size_t, void*) = delete;
  V8ContextInfo(const V8ContextInfo&) = delete;
  V8ContextInfo& operator=(const V8ContextInfo&) = delete;
};

// This debugger id tries to be unique by generating two random
// numbers, which should most likely avoid collisions.
// Debugger id has a 1:1 mapping to context group. It is used to
// attribute stack traces to a particular debugging, when doing any
// cross-debugger operations (e.g. async step in).
// See also Runtime.UniqueDebuggerId in the protocol.
class V8_EXPORT V8DebuggerId {
 public:
  V8DebuggerId() = default;
  V8DebuggerId(const V8DebuggerId&) = default;
  V8DebuggerId& operator=(const V8DebuggerId&) = default;

  std::unique_ptr<StringBuffer> toString() const;
  bool isValid() const;
  std::pair<int64_t, int64_t> pair() const;

 private:
  friend class internal::V8DebuggerId;
  explicit V8DebuggerId(std::pair<int64_t, int64_t>);

  int64_t m_first = 0;
  int64_t m_second = 0;
};

struct V8_EXPORT V8StackFrame {
  StringView sourceURL;
  StringView functionName;
  int lineNumber;
  int columnNumber;
};

class V8_EXPORT V8StackTrace {
 public:
  virtual StringView firstNonEmptySourceURL() const = 0;
  virtual bool isEmpty() const = 0;
  virtual StringView topSourceURL() const = 0;
  virtual int topLineNumber() const = 0;
  virtual int topColumnNumber() const = 0;
  virtual int topScriptId() const = 0;
  virtual StringView topFunctionName() const = 0;

  virtual ~V8StackTrace() = default;
  virtual std::unique_ptr<protocol::Runtime::API::StackTrace>
  buildInspectorObject(int maxAsyncDepth) const = 0;
  virtual std::unique_ptr<StringBuffer> toString() const = 0;

  // Safe to pass between threads, drops async chain.
  virtual std::unique_ptr<V8StackTrace> clone() = 0;

  virtual std::vector<V8StackFrame> frames() const = 0;
};

class V8_EXPORT V8InspectorSession {
 public:
  virtual ~V8InspectorSession() = default;

  // Cross-context inspectable values (DOM nodes in different worlds, etc.).
  class V8_EXPORT Inspectable {
   public:
    virtual v8::Local<v8::Value> get(v8::Local<v8::Context>) = 0;
    virtual ~Inspectable() = default;
  };
  virtual void addInspectedObject(std::unique_ptr<Inspectable>) = 0;

  // Dispatching protocol messages.
  static bool canDispatchMethod(StringView method);
  virtual void dispatchProtocolMessage(StringView message) = 0;
  virtual std::vector<uint8_t> state() = 0;
  virtual std::vector<std::unique_ptr<protocol::Schema::API::Domain>>
  supportedDomains() = 0;

  // Debugger actions.
  virtual void schedulePauseOnNextStatement(StringView breakReason,
                                            StringView breakDetails) = 0;
  virtual void cancelPauseOnNextStatement() = 0;
  virtual void breakProgram(StringView breakReason,
                            StringView breakDetails) = 0;
  virtual void setSkipAllPauses(bool) = 0;
  virtual void resume(bool setTerminateOnResume = false) = 0;
  virtual void stepOver() = 0;
  virtual std::vector<std::unique_ptr<protocol::Debugger::API::SearchMatch>>
  searchInTextByLines(StringView text, StringView query, bool caseSensitive,
                      bool isRegex) = 0;

  // Remote objects.
  virtual std::unique_ptr<protocol::Runtime::API::RemoteObject> wrapObject(
      v8::Local<v8::Context>, v8::Local<v8::Value>, StringView groupName,
      bool generatePreview) = 0;

  virtual bool unwrapObject(std::unique_ptr<StringBuffer>* error,
                            StringView objectId, v8::Local<v8::Value>*,
                            v8::Local<v8::Context>*,
                            std::unique_ptr<StringBuffer>* objectGroup) = 0;
  virtual void releaseObjectGroup(StringView) = 0;
  virtual void triggerPreciseCoverageDeltaUpdate(StringView occasion) = 0;

  struct V8_EXPORT EvaluateResult {
    enum class ResultType {
      kNotRun,
      kSuccess,
      kException,
    };

    ResultType type;
    v8::Local<v8::Value> value;
  };
  // Evalaute 'expression' in the provided context. Does the same as
  // Runtime#evaluate under-the-hood but exposed on the C++ side.
  virtual EvaluateResult evaluate(v8::Local<v8::Context> context,
                                  StringView expression,
                                  bool includeCommandLineAPI = false) = 0;

  // Prepare for shutdown (disables debugger pausing, etc.).
  virtual void stop() = 0;
};

struct V8_EXPORT DeepSerializedValue {
  explicit DeepSerializedValue(std::unique_ptr<StringBuffer> type,
                               v8::MaybeLocal<v8::Value> value = {})
      : type(std::move(type)), value(value) {}
  std::unique_ptr<StringBuffer> type;
  v8::MaybeLocal<v8::Value> value;
};

struct V8_EXPORT DeepSerializationResult {
  explicit DeepSerializationResult(
      std::unique_ptr<DeepSerializedValue> serializedValue)
      : serializedValue(std::move(serializedValue)), isSuccess(true) {}
  explicit DeepSerializationResult(std::unique_ptr<StringBuffer> errorMessage)
      : errorMessage(std::move(errorMessage)), isSuccess(false) {}

  // Use std::variant when available.
  std::unique_ptr<DeepSerializedValue> serializedValue;
  std::unique_ptr<StringBuffer> errorMessage;
  bool isSuccess;
};

class V8_EXPORT V8InspectorClient {
 public:
  virtual ~V8InspectorClient() = default;

  virtual void runMessageLoopOnPause(int contextGroupId) {}
  virtual void runMessageLoopOnInstrumentationPause(int contextGroupId) {
    runMessageLoopOnPause(contextGroupId);
  }
  virtual void quitMessageLoopOnPause() {}
  virtual void runIfWaitingForDebugger(int contextGroupId) {}

  virtual void muteMetrics(int contextGroupId) {}
  virtual void unmuteMetrics(int contextGroupId) {}

  virtual void beginUserGesture() {}
  virtual void endUserGesture() {}

  virtual std::unique_ptr<DeepSerializationResult> deepSerialize(
      v8::Local<v8::Value> v8Value, int maxDepth,
      v8::Local<v8::Object> additionalParameters) {
    return nullptr;
  }
  virtual std::unique_ptr<StringBuffer> valueSubtype(v8::Local<v8::Value>) {
    return nullptr;
  }
  virtual std::unique_ptr<StringBuffer> descriptionForValueSubtype(
      v8::Local<v8::Context>, v8::Local<v8::Value>) {
    return nullptr;
  }
  virtual bool isInspectableHeapObject(v8::Local<v8::Object>) { return true; }

  virtual v8::Local<v8::Context> ensureDefaultContextInGroup(
      int contextGroupId) {
    return v8::Local<v8::Context>();
  }
  virtual void beginEnsureAllContextsInGroup(int contextGroupId) {}
  virtual void endEnsureAllContextsInGroup(int contextGroupId) {}

  virtual void installAdditionalCommandLineAPI(v8::Local<v8::Context>,
                                               v8::Local<v8::Object>) {}
  virtual void consoleAPIMessage(int contextGroupId,
                                 v8::Isolate::MessageErrorLevel level,
                                 const StringView& message,
                                 const StringView& url, unsigned lineNumber,
                                 unsigned columnNumber, V8StackTrace*) {}
  virtual v8::MaybeLocal<v8::Value> memoryInfo(v8::Isolate*,
                                               v8::Local<v8::Context>) {
    return v8::MaybeLocal<v8::Value>();
  }

  virtual void consoleTime(v8::Isolate* isolate, v8::Local<v8::String> label) {}
  virtual void consoleTimeEnd(v8::Isolate* isolate,
                              v8::Local<v8::String> label) {}
  virtual void consoleTimeStamp(v8::Isolate* isolate,
                                v8::Local<v8::String> label) {}

  virtual void consoleClear(int contextGroupId) {}
  virtual double currentTimeMS() { return 0; }
  typedef void (*TimerCallback)(void*);
  virtual void startRepeatingTimer(double, TimerCallback, void* data) {}
  virtual void cancelTimer(void* data) {}

  // TODO(dgozman): this was added to support service worker shadow page. We
  // should not connect at all.
  virtual bool canExecuteScripts(int contextGroupId) { return true; }

  virtual void maxAsyncCallStackDepthChanged(int depth) {}

  virtual std::unique_ptr<StringBuffer> resourceNameToUrl(
      const StringView& resourceName) {
    return nullptr;
  }

  // The caller would defer to generating a random 64 bit integer if
  // this method returns 0.
  virtual int64_t generateUniqueId() { return 0; }

  virtual void dispatchError(v8::Local<v8::Context>, v8::Local<v8::Message>,
                             v8::Local<v8::Value>) {}
};

// These stack trace ids are intended to be passed between debuggers and be
// resolved later. This allows to track cross-debugger calls and step between
// them if a single client connects to multiple debuggers.
struct V8_EXPORT V8StackTraceId {
  uintptr_t id;
  std::pair<int64_t, int64_t> debugger_id;
  bool should_pause = false;

  V8StackTraceId();
  V8StackTraceId(const V8StackTraceId&) = default;
  V8StackTraceId(uintptr_t id, const std::pair<int64_t, int64_t> debugger_id);
  V8StackTraceId(uintptr_t id, const std::pair<int64_t, int64_t> debugger_id,
                 bool should_pause);
  explicit V8StackTraceId(StringView);
  V8StackTraceId& operator=(const V8StackTraceId&) = default;
  V8StackTraceId& operator=(V8StackTraceId&&) noexcept = default;
  ~V8StackTraceId() = default;

  bool IsInvalid() const;
  std::unique_ptr<StringBuffer> ToString();
};

class V8_EXPORT V8Inspector {
 public:
  static std::unique_ptr<V8Inspector> create(v8::Isolate*, V8InspectorClient*);
  virtual ~V8Inspector() = default;

  // Contexts instrumentation.
  virtual void contextCreated(const V8ContextInfo&) = 0;
  virtual void contextDestroyed(v8::Local<v8::Context>) = 0;
  virtual void resetContextGroup(int contextGroupId) = 0;
  virtual v8::MaybeLocal<v8::Context> contextById(int contextId) = 0;
  virtual V8DebuggerId uniqueDebuggerId(int contextId) = 0;

  // Various instrumentation.
  virtual void idleStarted() = 0;
  virtual void idleFinished() = 0;

  // Async stack traces instrumentation.
  virtual void asyncTaskScheduled(StringView taskName, void* task,
                                  bool recurring) = 0;
  virtual void asyncTaskCanceled(void* task) = 0;
  virtual void asyncTaskStarted(void* task) = 0;
  virtual void asyncTaskFinished(void* task) = 0;
  virtual void allAsyncTasksCanceled() = 0;

  virtual V8StackTraceId storeCurrentStackTrace(StringView description) = 0;
  virtual void externalAsyncTaskStarted(const V8StackTraceId& parent) = 0;
  virtual void externalAsyncTaskFinished(const V8StackTraceId& parent) = 0;

  // Exceptions instrumentation.
  virtual unsigned exceptionThrown(v8::Local<v8::Context>, StringView message,
                                   v8::Local<v8::Value> exception,
                                   StringView detailedMessage, StringView url,
                                   unsigned lineNumber, unsigned columnNumber,
                                   std::unique_ptr<V8StackTrace>,
                                   int scriptId) = 0;
  virtual void exceptionRevoked(v8::Local<v8::Context>, unsigned exceptionId,
                                StringView message) = 0;
  virtual bool associateExceptionData(v8::Local<v8::Context>,
                                      v8::Local<v8::Value> exception,
                                      v8::Local<v8::Name> key,
                                      v8::Local<v8::Value> value) = 0;

  // Connection.
  class V8_EXPORT Channel {
   public:
    virtual ~Channel() = default;
    virtual void sendResponse(int callId,
                              std::unique_ptr<StringBuffer> message) = 0;
    virtual void sendNotification(std::unique_ptr<StringBuffer> message) = 0;
    virtual void flushProtocolNotifications() = 0;
  };
  enum ClientTrustLevel { kUntrusted, kFullyTrusted };
  enum SessionPauseState { kWaitingForDebugger, kNotWaitingForDebugger };
  // TODO(chromium:1352175): remove default value once downstream change lands.
  virtual std::unique_ptr<V8InspectorSession> connect(
      int contextGroupId, Channel*, StringView state,
      ClientTrustLevel client_trust_level,
      SessionPauseState = kNotWaitingForDebugger) {
    return nullptr;
  }

  // API methods.
  virtual std::unique_ptr<V8StackTrace> createStackTrace(
      v8::Local<v8::StackTrace>) = 0;
  virtual std::unique_ptr<V8StackTrace> captureStackTrace(bool fullStack) = 0;
};

}  // namespace v8_inspector

#endif  // V8_V8_INSPECTOR_H_
```