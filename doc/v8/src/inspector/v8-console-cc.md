Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/inspector/v8-console.cc`.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Purpose:** The file name "v8-console.cc" strongly suggests that this code handles console API calls within the V8 inspector. This is the primary function.

2. **Scan for Key Classes and Methods:** Look for classes and methods that directly relate to console functionality. The `V8Console` class and methods like `Debug`, `Error`, `Log`, `Warn`, `Group`, `Time`, etc., are strong indicators. The `ConsoleHelper` class also appears to be a central utility.

3. **Analyze the `ConsoleHelper` Class:** This class seems to encapsulate the logic for processing console calls. Note its constructor takes `ConsoleCallArguments` and `ConsoleContext`, suggesting it's used when a console method is invoked. Observe the methods like `reportCall`, `reportCallWithDefaultArgument`, `reportDeprecatedCall`, which are responsible for creating and sending console messages.

4. **Trace the Flow of a Console Call:**  Take a specific console method (e.g., `V8Console::Log`) and follow its execution. It creates a `ConsoleHelper` and calls `reportCall`. The `reportCall` method then creates a `V8ConsoleMessage`. This reveals the path from a JavaScript console call to its representation within the inspector.

5. **Understand Message Handling:**  Notice how `reportCall` interacts with `V8ConsoleMessageStorage`. This indicates the code is responsible for storing and managing console messages. The inclusion of stack trace capture logic within `reportCall` is also important.

6. **Identify Interaction with Other V8 Inspector Components:** Observe the `#include` directives and the usage of classes like `V8InspectorImpl`, `V8DebuggerAgentImpl`, `V8ProfilerAgentImpl`, `V8RuntimeAgentImpl`. This shows that `v8-console.cc` is not isolated and interacts with various parts of the V8 inspector for debugging, profiling, and runtime information.

7. **Check for Torque/JavaScript Relevance:** The prompt asks about Torque and JavaScript. The file extension is `.cc`, so it's C++, not Torque. The code directly relates to the JavaScript `console` object, as it implements the backend for its methods.

8. **Consider Examples and Error Scenarios:** Think about how the console API is used in JavaScript and potential errors. For instance, `console.time` and `console.timeEnd` need matching labels. `console.assert` triggers a breakpoint if the condition is false.

9. **Address Specific Instructions:**
    * **Functionality Listing:** Create a bulleted list of the identified functionalities.
    * **Torque:**  Explicitly state that the file is C++, not Torque.
    * **JavaScript Examples:** Provide concise JavaScript examples demonstrating the usage of the implemented console methods.
    * **Code Logic/Input-Output:**  Choose a simple scenario like `console.count` and illustrate its behavior with an example of input and expected output.
    * **Common Programming Errors:**  Provide examples of typical mistakes users make with the console API.
    * **Summary:**  Concisely summarize the overall purpose of the file.

10. **Structure the Output:** Organize the information clearly, following the order of the user's request. Use headings and bullet points for readability.

**Self-Correction/Refinement during thought process:**

* Initially, I might have focused too much on the individual console methods. Realizing the importance of `ConsoleHelper` and the message creation process is crucial for a more holistic understanding.
*  I need to ensure the JavaScript examples are simple and directly illustrate the corresponding C++ functionality.
* The input/output example should be straightforward and not involve complex internal V8 state. Focus on the user-observable behavior.
* When listing functionalities, group related items together logically (e.g., different log levels, grouping methods, timing methods).

By following these steps and continuously refining the understanding, a comprehensive and accurate answer can be generated.这是对V8源代码文件 `v8/src/inspector/v8-console.cc` 的分析。根据您提供的代码片段，以下是它的功能归纳：

**核心功能:**

该文件实现了 V8 Inspector 中与 JavaScript `console` 对象及其相关功能交互的 C++ 代码。它充当了 V8 引擎和开发者工具（例如 Chrome DevTools）之间关于控制台消息、断点、性能分析等操作的桥梁。

**具体功能列表:**

* **接收和处理 JavaScript 控制台 API 调用:**  该文件中的 `V8Console` 类定义了与 JavaScript `console` 对象上的方法相对应的方法（例如 `Debug`, `Error`, `Log`, `Warn`, `Dir`, `Table`, `Trace`, `Group`, `Time`, `Count` 等）。当 JavaScript 代码调用 `console.log()`, `console.error()` 等方法时，V8 引擎会调用 `V8Console` 中相应的方法。
* **格式化和报告控制台消息:** `ConsoleHelper` 类负责处理控制台调用的参数，并将它们格式化成可以在开发者工具中显示的消息。它还会记录消息的类型（例如 `kDebug`, `kError`, `kLog`），以及可能的堆栈跟踪信息。
* **管理控制台上下文:**  代码中使用了 `v8::debug::ConsoleContext` 来区分不同的 JavaScript 上下文，确保控制台消息与正确的上下文关联。
* **集成 V8 Inspector 的其他组件:**  `V8Console` 与 `V8InspectorImpl`, `V8DebuggerAgentImpl`, `V8ProfilerAgentImpl` 等类交互，以实现更高级的功能，例如：
    * **断点控制:** `debugFunctionCallback`, `undebugFunctionCallback`, `monitorFunctionCallback`, `unmonitorFunctionCallback` 用于设置和取消针对特定函数的断点。
    * **性能分析:** `Profile`, `ProfileEnd`, `Time`, `TimeLog`, `TimeEnd` 用于启动和停止性能分析，并记录时间信息。
    * **异步任务跟踪:** `createTask`, `runTask`, `cancelConsoleTask` 提供了创建、运行和取消与控制台相关的异步任务的功能，并将其信息同步到开发者工具。
    * **对象检查:** `inspectCallback`, `copyCallback`, `queryObjectsCallback` 允许开发者在控制台中检查对象，并将其复制到剪贴板或查询特定类型的对象。
* **管理控制台消息存储:** `V8ConsoleMessageStorage` 用于存储和管理控制台消息，例如用于 `console.count` 和 `console.time` 的计数和计时信息。
* **处理 `console.assert`:**  当 `console.assert` 的条件为 `false` 时，会记录错误消息并触发断点。
* **提供 `console.memory` 信息:**  `memoryGetterCallback` 提供了获取内存使用情况的功能。
* **支持 `console.clear`:** 清除控制台消息。

**关于 .tq 结尾和 JavaScript 关系:**

您是对的，如果 `v8/src/inspector/v8-console.cc` 以 `.tq` 结尾，那它将是 V8 Torque 源代码。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 JavaScript 运行时代码。

由于该文件以 `.cc` 结尾，它是一个 C++ 源代码文件。但是，它的功能与 JavaScript 的 `console` 对象紧密相关。

**JavaScript 举例说明:**

以下是一些 JavaScript 代码示例，展示了 `v8/src/inspector/v8-console.cc` 中实现的功能：

```javascript
console.log("Hello, world!");
console.error("An error occurred.");
console.warn("This is a warning.");
console.info("Some information.");
console.debug("Debugging information.");

const myObject = { a: 1, b: "test" };
console.dir(myObject);
console.table([{ a: 1, b: 2 }, { a: 3, b: 4 }]);

console.trace("Show stack trace");

console.group("My Group");
console.log("Message inside group");
console.groupEnd();

console.time("MyTimer");
for (let i = 0; i < 1000000; i++) {
  // Some code
}
console.timeEnd("MyTimer");

console.count("myCounter");
console.count("myCounter");
console.countReset("myCounter");

console.assert(1 === 1, "This should not fail");
console.assert(1 === 2, "This will trigger an assertion error");

function myFunction() {
  console.log("myFunction called");
}
// 在开发者工具的 Sources 面板中设置断点后，调用 debugFunction 将会在 myFunction 的入口处暂停
// debugFunction(myFunction);
// undebugFunction(myFunction); // 移除断点

// monitorFunction(myFunction); // 每次调用 myFunction 时都会在控制台输出信息
// unmonitorFunction(myFunction);

inspect(myObject); // 在控制台的 "Scope" 视图中显示对象
copy(myObject);    // 将对象的字符串表示复制到剪贴板

async function myTask() {
  console.log("Task started");
  await new Promise(resolve => setTimeout(resolve, 1000));
  console.log("Task finished");
}

const task = console.createTask("MyAsyncTask");
task.run(myTask);
```

**代码逻辑推理 (假设输入与输出):**

假设 JavaScript 代码调用了 `console.count('myLabel')` 两次，然后调用了 `console.countReset('myLabel')`，最后再次调用 `console.count('myLabel')`。

**假设输入:**

1. `console.count('myLabel')`  (第一次调用)
2. `console.count('myLabel')`  (第二次调用)
3. `console.countReset('myLabel')`
4. `console.count('myLabel')`  (第三次调用)

**推断的输出（控制台消息）：**

1. `myLabel: 1`
2. `myLabel: 2`
3. (无输出，但内部计数器被重置)
4. `myLabel: 1`

**解释:**

* 每次调用 `console.count('myLabel')` 时，`V8Console::Count` 方法会被调用。
* `ConsoleHelper` 会获取标签 'myLabel'。
* `consoleMessageStorage()->count()` 会递增与该标签关联的计数器。
* `reportCallWithArgument` 会生成包含当前计数值的控制台消息。
* 调用 `console.countReset('myLabel')` 时，`V8Console::CountReset` 方法会被调用，它会重置 `consoleMessageStorage` 中与 'myLabel' 关联的计数器。

**用户常见的编程错误:**

1. **`console.time` 和 `console.timeEnd` 标签不匹配:**

   ```javascript
   console.time("TimerA");
   // ... some code ...
   console.timeEnd("TimerB"); // 错误：标签不匹配
   ```
   这会导致 `console.timeEnd` 找不到对应的计时器，控制台会输出警告。

2. **在 `console.assert` 中混淆条件和错误消息:**

   ```javascript
   console.assert("Something went wrong", 1 === 2); // 错误：第一个参数应该是条件
   ```
   `console.assert` 的第一个参数应该是布尔类型的条件，如果为 `false`，则会输出第二个参数作为错误消息。

3. **忘记使用 `console.groupEnd()` 结束分组:**

   ```javascript
   console.group("My Group");
   console.log("Message inside group");
   // 忘记调用 console.groupEnd()
   ```
   这会导致控制台消息的格式不正确，后续的消息可能仍然被缩进。

4. **过度使用 `console.log` 进行调试，而没有使用更合适的 `console.debug` 或断点。**

**总结 (第 1 部分功能归纳):**

`v8/src/inspector/v8-console.cc` 是 V8 Inspector 中至关重要的组件，它负责实现 JavaScript `console` 对象的各种方法，并将这些调用转化为与开发者工具交互的底层操作，包括消息记录、断点管理、性能分析和对象检查。它充当了 JavaScript 代码和 V8 Inspector 后端之间的桥梁，是开发者进行调试和性能分析的关键工具。

### 提示词
```
这是目录为v8/src/inspector/v8-console.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-console.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/v8-console.h"

#include "include/v8-container.h"
#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-inspector.h"
#include "include/v8-microtask-queue.h"
#include "src/base/lazy-instance.h"
#include "src/base/macros.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/injected-script.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-console-message.h"
#include "src/inspector/v8-debugger-agent-impl.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-profiler-agent-impl.h"
#include "src/inspector/v8-runtime-agent-impl.h"
#include "src/inspector/v8-stack-trace-impl.h"
#include "src/inspector/v8-value-utils.h"
#include "src/tracing/trace-event.h"

namespace v8_inspector {

namespace {

String16 consoleContextToString(
    v8::Isolate* isolate, const v8::debug::ConsoleContext& consoleContext) {
  if (consoleContext.id() == 0) return String16();
  return toProtocolString(isolate, consoleContext.name()) + "#" +
         String16::fromInteger(consoleContext.id());
}

class ConsoleHelper {
 public:
  ConsoleHelper(const v8::debug::ConsoleCallArguments& info,
                const v8::debug::ConsoleContext& consoleContext,
                V8InspectorImpl* inspector)
      : m_info(info),
        m_consoleContext(consoleContext),
        m_inspector(inspector) {}

  ConsoleHelper(const ConsoleHelper&) = delete;
  ConsoleHelper& operator=(const ConsoleHelper&) = delete;

  v8::Isolate* isolate() const { return m_inspector->isolate(); }
  v8::Local<v8::Context> context() const {
    return isolate()->GetCurrentContext();
  }
  int contextId() const { return InspectedContext::contextId(context()); }
  int groupId() const { return m_inspector->contextGroupId(contextId()); }

  InjectedScript* injectedScript(int sessionId) {
    InspectedContext* context = m_inspector->getContext(groupId(), contextId());
    if (!context) return nullptr;
    return context->getInjectedScript(sessionId);
  }

  V8InspectorSessionImpl* session(int sessionId) {
    return m_inspector->sessionById(groupId(), sessionId);
  }

  V8ConsoleMessageStorage* consoleMessageStorage() {
    return m_inspector->ensureConsoleMessageStorage(groupId());
  }

  void reportCall(ConsoleAPIType type) {
    if (!m_info.Length()) return;
    v8::LocalVector<v8::Value> arguments(isolate());
    arguments.reserve(m_info.Length());
    for (int i = 0; i < m_info.Length(); ++i) arguments.push_back(m_info[i]);
    reportCall(type, {arguments.begin(), arguments.end()});
  }

  void reportCallWithDefaultArgument(ConsoleAPIType type,
                                     const String16& message) {
    v8::LocalVector<v8::Value> arguments(isolate());
    arguments.reserve(m_info.Length());
    for (int i = 0; i < m_info.Length(); ++i) arguments.push_back(m_info[i]);
    if (!m_info.Length()) arguments.push_back(toV8String(isolate(), message));
    reportCall(type, {arguments.begin(), arguments.end()});
  }

  void reportCallAndReplaceFirstArgument(ConsoleAPIType type,
                                         const String16& message) {
    v8::LocalVector<v8::Value> arguments(isolate());
    arguments.push_back(toV8String(isolate(), message));
    for (int i = 1; i < m_info.Length(); ++i) arguments.push_back(m_info[i]);
    reportCall(type, {arguments.begin(), arguments.end()});
  }

  void reportCallWithArgument(ConsoleAPIType type, const String16& message) {
    auto arguments =
        v8::to_array<v8::Local<v8::Value>>({toV8String(isolate(), message)});
    reportCall(type, arguments);
  }

  void reportCall(ConsoleAPIType type,
                  v8::MemorySpan<const v8::Local<v8::Value>> arguments) {
    if (!groupId()) return;
    // Depending on the type of the console message, we capture only parts of
    // the stack trace, or no stack trace at all.
    std::unique_ptr<V8StackTraceImpl> stackTrace;
    switch (type) {
      case ConsoleAPIType::kTrace:
        // The purpose of `console.trace()` is to output a stack trace to the
        // developer tools console, therefore we should always strive to
        // capture a full stack trace, even before any debugger is attached.
        stackTrace = m_inspector->debugger()->captureStackTrace(true);
        break;

      case ConsoleAPIType::kTimeEnd:
        // The `console.time()` and `console.timeEnd()` APIs are meant for
        // performance investigations, and therefore it's important to reduce
        // the total overhead of these calls, but also make sure these APIs
        // have consistent performance overhead. In order to guarantee that,
        // we always capture only the top frame, otherwise the performance
        // characteristics of `console.timeEnd()` would differ based on the
        // current call depth, which would skew the results.
        //
        // See https://crbug.com/41433391 for more information.
        stackTrace = V8StackTraceImpl::capture(m_inspector->debugger(), 1);
        break;

      default:
        // All other APIs get a full stack trace only when the debugger is
        // attached, otherwise record only the top frame.
        stackTrace = m_inspector->debugger()->captureStackTrace(false);
        break;
    }
    std::unique_ptr<V8ConsoleMessage> message =
        V8ConsoleMessage::createForConsoleAPI(
            context(), contextId(), groupId(), m_inspector,
            m_inspector->client()->currentTimeMS(), type, arguments,
            consoleContextToString(isolate(), m_consoleContext),
            std::move(stackTrace));
    consoleMessageStorage()->addMessage(std::move(message));
  }

  void reportDeprecatedCall(const char* id, const String16& message) {
    if (!consoleMessageStorage()->shouldReportDeprecationMessage(contextId(),
                                                                 id)) {
      return;
    }
    auto arguments =
        v8::to_array<v8::Local<v8::Value>>({toV8String(isolate(), message)});
    reportCall(ConsoleAPIType::kWarning, arguments);
  }

  bool firstArgToBoolean(bool defaultValue) {
    if (m_info.Length() < 1) return defaultValue;
    if (m_info[0]->IsBoolean()) return m_info[0].As<v8::Boolean>()->Value();
    return m_info[0]->BooleanValue(m_inspector->isolate());
  }

  v8::Local<v8::String> firstArgToString() {
    if (V8_LIKELY(m_info.Length() > 0)) {
      v8::Local<v8::Value> arg = m_info[0];
      if (V8_LIKELY(arg->IsString())) {
        return arg.As<v8::String>();
      }
      v8::Local<v8::String> label;
      if (!arg->IsUndefined() && arg->ToString(context()).ToLocal(&label)) {
        return label;
      }
    }
    return toV8StringInternalized(isolate(), "default");
  }

  v8::MaybeLocal<v8::Object> firstArgAsObject() {
    if (m_info.Length() < 1 || !m_info[0]->IsObject())
      return v8::MaybeLocal<v8::Object>();
    return m_info[0].As<v8::Object>();
  }

  v8::MaybeLocal<v8::Function> firstArgAsFunction() {
    if (m_info.Length() < 1 || !m_info[0]->IsFunction())
      return v8::MaybeLocal<v8::Function>();
    v8::Local<v8::Function> func = m_info[0].As<v8::Function>();
    while (func->GetBoundFunction()->IsFunction())
      func = func->GetBoundFunction().As<v8::Function>();
    return func;
  }

  void forEachSession(std::function<void(V8InspectorSessionImpl*)> callback) {
    m_inspector->forEachSession(groupId(), std::move(callback));
  }

 private:
  const v8::debug::ConsoleCallArguments& m_info;
  const v8::debug::ConsoleContext& m_consoleContext;
  V8InspectorImpl* m_inspector;
};

void createBoundFunctionProperty(
    v8::Local<v8::Context> context, v8::Local<v8::Object> console,
    v8::Local<v8::Value> data, const char* name, v8::FunctionCallback callback,
    v8::SideEffectType side_effect_type = v8::SideEffectType::kHasSideEffect) {
  v8::Local<v8::String> funcName =
      toV8StringInternalized(context->GetIsolate(), name);
  v8::Local<v8::Function> func;
  if (!v8::Function::New(context, callback, data, 0,
                         v8::ConstructorBehavior::kThrow, side_effect_type)
           .ToLocal(&func))
    return;
  func->SetName(funcName);
  createDataProperty(context, console, funcName, func);
}

enum InspectRequest { kRegular, kCopyToClipboard, kQueryObjects };

}  // namespace

V8Console::V8Console(V8InspectorImpl* inspector) : m_inspector(inspector) {}

void V8Console::Debug(const v8::debug::ConsoleCallArguments& info,
                      const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Debug");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCall(ConsoleAPIType::kDebug);
}

void V8Console::Error(const v8::debug::ConsoleCallArguments& info,
                      const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Error");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCall(ConsoleAPIType::kError);
}

void V8Console::Info(const v8::debug::ConsoleCallArguments& info,
                     const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Info");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCall(ConsoleAPIType::kInfo);
}

void V8Console::Log(const v8::debug::ConsoleCallArguments& info,
                    const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Log");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCall(ConsoleAPIType::kLog);
}

void V8Console::Warn(const v8::debug::ConsoleCallArguments& info,
                     const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Warn");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCall(ConsoleAPIType::kWarning);
}

void V8Console::Dir(const v8::debug::ConsoleCallArguments& info,
                    const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Dir");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCall(ConsoleAPIType::kDir);
}

void V8Console::DirXml(const v8::debug::ConsoleCallArguments& info,
                       const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::DirXml");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCall(ConsoleAPIType::kDirXML);
}

void V8Console::Table(const v8::debug::ConsoleCallArguments& info,
                      const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Table");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCall(ConsoleAPIType::kTable);
}

void V8Console::Trace(const v8::debug::ConsoleCallArguments& info,
                      const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Trace");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCallWithDefaultArgument(ConsoleAPIType::kTrace,
                                     String16("console.trace"));
}

void V8Console::Group(const v8::debug::ConsoleCallArguments& info,
                      const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Group");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCallWithDefaultArgument(ConsoleAPIType::kStartGroup,
                                     String16("console.group"));
}

void V8Console::GroupCollapsed(
    const v8::debug::ConsoleCallArguments& info,
    const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
               "V8Console::GroupCollapsed");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCallWithDefaultArgument(ConsoleAPIType::kStartGroupCollapsed,
                                     String16("console.groupCollapsed"));
}

void V8Console::GroupEnd(const v8::debug::ConsoleCallArguments& info,
                         const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
               "V8Console::GroupEnd");
  ConsoleHelper(info, consoleContext, m_inspector)
      .reportCallWithDefaultArgument(ConsoleAPIType::kEndGroup,
                                     String16("console.groupEnd"));
}

void V8Console::Clear(const v8::debug::ConsoleCallArguments& info,
                      const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Clear");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  if (!helper.groupId()) return;
  m_inspector->client()->consoleClear(helper.groupId());
  helper.reportCallWithDefaultArgument(ConsoleAPIType::kClear,
                                       String16("console.clear"));
}

void V8Console::Count(const v8::debug::ConsoleCallArguments& info,
                      const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT_BEGIN0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                     "V8Console::Count");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  String16 label =
      toProtocolString(m_inspector->isolate(), helper.firstArgToString());
  int count = helper.consoleMessageStorage()->count(helper.contextId(),
                                                    consoleContext.id(), label);
  helper.reportCallWithArgument(ConsoleAPIType::kCount,
                                label + ": " + String16::fromInteger(count));
  TRACE_EVENT_END2(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                   "V8Console::Count", "label",
                   TRACE_STR_COPY(label.utf8().c_str()), "count", count);
}

void V8Console::CountReset(const v8::debug::ConsoleCallArguments& info,
                           const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT_BEGIN0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                     "V8Console::CountReset");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  String16 label =
      toProtocolString(m_inspector->isolate(), helper.firstArgToString());
  if (!helper.consoleMessageStorage()->countReset(helper.contextId(),
                                                  consoleContext.id(), label)) {
    helper.reportCallWithArgument(ConsoleAPIType::kWarning,
                                  "Count for '" + label + "' does not exist");
  }
  TRACE_EVENT_END1(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                   "V8Console::CountReset", "label",
                   TRACE_STR_COPY(label.utf8().c_str()));
}

void V8Console::Assert(const v8::debug::ConsoleCallArguments& info,
                       const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Assert");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  DCHECK(!helper.firstArgToBoolean(false));

  v8::Isolate* isolate = m_inspector->isolate();
  v8::LocalVector<v8::Value> arguments(isolate);
  for (int i = 1; i < info.Length(); ++i) arguments.push_back(info[i]);
  if (info.Length() < 2)
    arguments.push_back(toV8String(isolate, String16("console.assert")));
  helper.reportCall(ConsoleAPIType::kAssert,
                    {arguments.begin(), arguments.end()});
  m_inspector->debugger()->breakProgramOnAssert(helper.groupId());
}

void V8Console::Profile(const v8::debug::ConsoleCallArguments& info,
                        const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT_BEGIN0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                     "V8Console::Profile");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  String16 title =
      toProtocolString(m_inspector->isolate(), helper.firstArgToString());
  helper.forEachSession([&title](V8InspectorSessionImpl* session) {
    session->profilerAgent()->consoleProfile(title);
  });
  TRACE_EVENT_END1(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                   "V8Console::Profile", "title",
                   TRACE_STR_COPY(title.utf8().c_str()));
}

void V8Console::ProfileEnd(const v8::debug::ConsoleCallArguments& info,
                           const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT_BEGIN0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                     "V8Console::ProfileEnd");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  String16 title =
      toProtocolString(m_inspector->isolate(), helper.firstArgToString());
  helper.forEachSession([&title](V8InspectorSessionImpl* session) {
    session->profilerAgent()->consoleProfileEnd(title);
  });
  TRACE_EVENT_END1(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                   "V8Console::ProfileEnd", "title",
                   TRACE_STR_COPY(title.utf8().c_str()));
}

void V8Console::Time(const v8::debug::ConsoleCallArguments& info,
                     const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::Time");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  v8::Local<v8::String> label = helper.firstArgToString();
  String16 protocolLabel = toProtocolString(m_inspector->isolate(), label);
  if (!helper.consoleMessageStorage()->time(
          helper.contextId(), consoleContext.id(), protocolLabel)) {
    helper.reportCallWithArgument(
        ConsoleAPIType::kWarning,
        "Timer '" + protocolLabel + "' already exists");
    return;
  }
  m_inspector->client()->consoleTime(m_inspector->isolate(), label);
}

void V8Console::TimeLog(const v8::debug::ConsoleCallArguments& info,
                        const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::TimeLog");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  v8::Local<v8::String> label = helper.firstArgToString();
  String16 protocolLabel = toProtocolString(m_inspector->isolate(), label);
  std::optional<double> elapsed = helper.consoleMessageStorage()->timeLog(
      helper.contextId(), consoleContext.id(), protocolLabel);
  if (!elapsed.has_value()) {
    helper.reportCallWithArgument(
        ConsoleAPIType::kWarning,
        "Timer '" + protocolLabel + "' does not exist");
    return;
  }
  String16 message =
      protocolLabel + ": " + String16::fromDouble(elapsed.value()) + " ms";
  helper.reportCallAndReplaceFirstArgument(ConsoleAPIType::kLog, message);
}

void V8Console::TimeEnd(const v8::debug::ConsoleCallArguments& info,
                        const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "V8Console::TimeEnd");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  v8::Local<v8::String> label = helper.firstArgToString();
  String16 protocolLabel = toProtocolString(m_inspector->isolate(), label);
  std::optional<double> elapsed = helper.consoleMessageStorage()->timeEnd(
      helper.contextId(), consoleContext.id(), protocolLabel);
  if (!elapsed.has_value()) {
    helper.reportCallWithArgument(
        ConsoleAPIType::kWarning,
        "Timer '" + protocolLabel + "' does not exist");
    return;
  }
  m_inspector->client()->consoleTimeEnd(m_inspector->isolate(), label);
  String16 message =
      protocolLabel + ": " + String16::fromDouble(elapsed.value()) + " ms";
  helper.reportCallWithArgument(ConsoleAPIType::kTimeEnd, message);
}

void V8Console::TimeStamp(const v8::debug::ConsoleCallArguments& info,
                          const v8::debug::ConsoleContext& consoleContext) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
               "V8Console::TimeStamp");
  ConsoleHelper helper(info, consoleContext, m_inspector);
  v8::Local<v8::String> label = helper.firstArgToString();
  m_inspector->client()->consoleTimeStamp(m_inspector->isolate(), label);
}

void V8Console::memoryGetterCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Value> memoryValue;
  if (!m_inspector->client()
           ->memoryInfo(info.GetIsolate(),
                        info.GetIsolate()->GetCurrentContext())
           .ToLocal(&memoryValue))
    return;
  info.GetReturnValue().Set(memoryValue);
}

void V8Console::memorySetterCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  // We can't make the attribute readonly as it breaks existing code that relies
  // on being able to assign to console.memory in strict mode. Instead, the
  // setter just ignores the passed value.  http://crbug.com/468611
}

void V8Console::createTask(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();

  v8::debug::RecordAsyncStackTaggingCreateTaskCall(isolate);

  if (info.Length() < 1 || !info[0]->IsString() ||
      !info[0].As<v8::String>()->Length()) {
    isolate->ThrowError("First argument must be a non-empty string.");
    return;
  }

  v8::Local<v8::Object> task = taskTemplate()
                                   ->NewInstance(isolate->GetCurrentContext())
                                   .ToLocalChecked();

  auto taskInfo = std::make_unique<TaskInfo>(isolate, this, task);
  void* taskId = taskInfo->Id();
  auto [iter, inserted] = m_tasks.emplace(taskId, std::move(taskInfo));
  CHECK(inserted);

  String16 nameArgument = toProtocolString(isolate, info[0].As<v8::String>());
  StringView taskName =
      StringView(nameArgument.characters16(), nameArgument.length());
  m_inspector->asyncTaskScheduled(taskName, taskId, /* recurring */ true);

  info.GetReturnValue().Set(task);
}

void V8Console::runTask(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  if (info.Length() < 1 || !info[0]->IsFunction()) {
    isolate->ThrowError("First argument must be a function.");
    return;
  }
  v8::Local<v8::Function> function = info[0].As<v8::Function>();

  v8::Local<v8::Object> task = info.This();
  v8::Local<v8::Value> maybeTaskExternal;
  if (!task->GetPrivate(isolate->GetCurrentContext(), taskInfoKey())
           .ToLocal(&maybeTaskExternal)) {
    // An exception is already thrown.
    return;
  }

  if (!maybeTaskExternal->IsExternal()) {
    isolate->ThrowError("'run' called with illegal receiver.");
    return;
  }

  v8::Local<v8::External> taskExternal = maybeTaskExternal.As<v8::External>();
  TaskInfo* taskInfo = reinterpret_cast<TaskInfo*>(taskExternal->Value());

  m_inspector->asyncTaskStarted(taskInfo->Id());
  v8::Local<v8::Value> result;
  if (function
          ->Call(isolate->GetCurrentContext(), v8::Undefined(isolate), 0, {})
          .ToLocal(&result)) {
    info.GetReturnValue().Set(result);
  }
  m_inspector->asyncTaskFinished(taskInfo->Id());
}

v8::Local<v8::Private> V8Console::taskInfoKey() {
  v8::Isolate* isolate = m_inspector->isolate();
  if (m_taskInfoKey.IsEmpty()) {
    m_taskInfoKey.Reset(isolate, v8::Private::New(isolate));
  }
  return m_taskInfoKey.Get(isolate);
}

v8::Local<v8::ObjectTemplate> V8Console::taskTemplate() {
  v8::Isolate* isolate = m_inspector->isolate();
  if (!m_taskTemplate.IsEmpty()) {
    return m_taskTemplate.Get(isolate);
  }

  v8::Local<v8::External> data = v8::External::New(isolate, this);
  v8::Local<v8::ObjectTemplate> taskTemplate = v8::ObjectTemplate::New(isolate);
  v8::Local<v8::FunctionTemplate> funcTemplate = v8::FunctionTemplate::New(
      isolate, &V8Console::call<&V8Console::runTask>, data);
  taskTemplate->Set(isolate, "run", funcTemplate);

  m_taskTemplate.Reset(isolate, taskTemplate);
  return taskTemplate;
}

void V8Console::cancelConsoleTask(TaskInfo* taskInfo) {
  m_inspector->asyncTaskCanceled(taskInfo->Id());
  m_tasks.erase(taskInfo->Id());
}

namespace {

void cleanupTaskInfo(const v8::WeakCallbackInfo<TaskInfo>& info) {
  TaskInfo* task = info.GetParameter();
  CHECK(task);
  task->Cancel();
}

}  // namespace

TaskInfo::TaskInfo(v8::Isolate* isolate, V8Console* console,
                   v8::Local<v8::Object> task)
    : m_task(isolate, task), m_console(console) {
  task->SetPrivate(isolate->GetCurrentContext(), console->taskInfoKey(),
                   v8::External::New(isolate, this))
      .Check();
  m_task.SetWeak(this, cleanupTaskInfo, v8::WeakCallbackType::kParameter);
}

void V8Console::keysCallback(const v8::FunctionCallbackInfo<v8::Value>& info,
                             int sessionId) {
  v8::Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::Array::New(isolate));

  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), m_inspector);
  v8::Local<v8::Object> obj;
  if (!helper.firstArgAsObject().ToLocal(&obj)) return;
  v8::Local<v8::Array> names;
  if (!obj->GetOwnPropertyNames(isolate->GetCurrentContext()).ToLocal(&names))
    return;
  info.GetReturnValue().Set(names);
}

void V8Console::valuesCallback(const v8::FunctionCallbackInfo<v8::Value>& info,
                               int sessionId) {
  v8::Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::Array::New(isolate));

  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), m_inspector);
  v8::Local<v8::Object> obj;
  if (!helper.firstArgAsObject().ToLocal(&obj)) return;
  v8::Local<v8::Array> names;
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  if (!obj->GetOwnPropertyNames(context).ToLocal(&names)) return;
  v8::Local<v8::Array> values = v8::Array::New(isolate, names->Length());
  for (uint32_t i = 0; i < names->Length(); ++i) {
    v8::Local<v8::Value> key;
    if (!names->Get(context, i).ToLocal(&key)) continue;
    v8::Local<v8::Value> value;
    if (!obj->Get(context, key).ToLocal(&value)) continue;
    createDataProperty(context, values, i, value);
  }
  info.GetReturnValue().Set(values);
}

static void setFunctionBreakpoint(ConsoleHelper& helper, int sessionId,
                                  v8::Local<v8::Function> function,
                                  V8DebuggerAgentImpl::BreakpointSource source,
                                  v8::Local<v8::String> condition,
                                  bool enable) {
  V8InspectorSessionImpl* session = helper.session(sessionId);
  if (session == nullptr) return;
  if (!session->debuggerAgent()->enabled()) return;
  if (enable) {
    session->debuggerAgent()->setBreakpointFor(function, condition, source);
  } else {
    session->debuggerAgent()->removeBreakpointFor(function, source);
  }
}

void V8Console::debugFunctionCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info, int sessionId) {
  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), m_inspector);
  v8::Local<v8::Function> function;
  v8::Local<v8::String> condition;
  if (!helper.firstArgAsFunction().ToLocal(&function)) return;
  if (args.Length() > 1 && args[1]->IsString()) {
    condition = args[1].As<v8::String>();
  }
  setFunctionBreakpoint(helper, sessionId, function,
                        V8DebuggerAgentImpl::DebugCommandBreakpointSource,
                        condition, true);
}

void V8Console::undebugFunctionCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info, int sessionId) {
  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), m_inspector);
  v8::Local<v8::Function> function;
  if (!helper.firstArgAsFunction().ToLocal(&function)) return;
  setFunctionBreakpoint(helper, sessionId, function,
                        V8DebuggerAgentImpl::DebugCommandBreakpointSource,
                        v8::Local<v8::String>(), false);
}

void V8Console::monitorFunctionCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info, int sessionId) {
  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), m_inspector);
  v8::Local<v8::Function> function;
  if (!helper.firstArgAsFunction().ToLocal(&function)) return;
  v8::Local<v8::Value> name = function->GetName();
  if (!name->IsString() || !name.As<v8::String>()->Length())
    name = function->GetInferredName();
  String16 functionName =
      toProtocolStringWithTypeCheck(info.GetIsolate(), name);
  String16Builder builder;
  builder.append("console.log(\"function ");
  if (functionName.isEmpty())
    builder.append("(anonymous function)");
  else
    builder.append(functionName);
  builder.append(
      " called\" + (typeof arguments !== \"undefined\" && arguments.length > 0 "
      "? \" with arguments: \" + Array.prototype.join.call(arguments, \", \") "
      ": \"\")) && false");
  setFunctionBreakpoint(helper, sessionId, function,
                        V8DebuggerAgentImpl::MonitorCommandBreakpointSource,
                        toV8String(info.GetIsolate(), builder.toString()),
                        true);
}

void V8Console::unmonitorFunctionCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info, int sessionId) {
  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), m_inspector);
  v8::Local<v8::Function> function;
  if (!helper.firstArgAsFunction().ToLocal(&function)) return;
  setFunctionBreakpoint(helper, sessionId, function,
                        V8DebuggerAgentImpl::MonitorCommandBreakpointSource,
                        v8::Local<v8::String>(), false);
}

void V8Console::lastEvaluationResultCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info, int sessionId) {
  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), m_inspector);
  InjectedScript* injectedScript = helper.injectedScript(sessionId);
  if (!injectedScript) return;
  info.GetReturnValue().Set(injectedScript->lastEvaluationResult());
}

static void inspectImpl(const v8::FunctionCallbackInfo<v8::Value>& info,
                        v8::Local<v8::Value> value, int sessionId,
                        InspectRequest request, V8InspectorImpl* inspector) {
  if (request == kRegular) info.GetReturnValue().Set(value);

  v8::debug::ConsoleCallArguments args(info);
  ConsoleHelper helper(args, v8::debug::ConsoleContext(), inspector);
  InjectedScript* injectedScript = helper.injectedScript(sessionId);
  if (!injectedScript) return;
  std::unique_ptr<protocol::Runtime::RemoteObject> wrappedObject;
  protocol::Response response = injectedScript->wrapObject(
      value, "", WrapOptions({WrapMode::kIdOnly}), &wrappedObject);
  if (!response.IsSuccess()) return;

  std::unique_ptr<protocol::DictionaryValue> hints =
      protocol::DictionaryValue::create();
  if (request == kCopyToClipboard) {
    hints->setBoolean("copyToClipboard", true);
  } else if (request == kQueryObjects) {
    hints->setBoolean("queryObjects", true);
  }
  if (V8InspectorSessionImpl* session = helper.session(sessionId)) {
    session->runtimeAgent()->inspect(std::move(wrappedObject), std::move(hints),
                                     helper.contextId());
  }
}

void V8Console::inspectCallback(const v8::FunctionCallbackInfo<v8::Value>& info,
                                int sessionId) {
  if (info.Length() < 1) return;
  inspectImpl(info, info[0], sessionId, kRegular, m_inspector);
}

void V8Console::copyCallback(const v8::FunctionCallbackInfo<v8::Value>& info,
                             int sessionId) {
  if (info.Length() < 1) return;
  inspectImpl(info, info[0], sessionId, kCopyToClipboard, m_inspector);
}

void V8Console::queryObjectsCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info, int sessionId) {
  if (info.Length() < 1) return;
  v8::Local<v8::Value> arg = info[0];
  if (arg->IsFunction()) {
    v8::Isolate* isolate = info.GetIsolate();
    v8::TryCatch tryCatch(isolate);
    v8::Local<v8::Value> prototype;
    if (arg.As<v8::Function>()
            ->Get(isolate->GetCurrentContext(),
                  toV8StringInternalized(isolate, "prototype"))
            .ToLocal(&prototype) &&
        prototype->IsObject()) {
      arg = prototype;
    }
    if (tryCatch.HasCaught()) {
      tryCatch.ReThrow();
      return;
    }
  }
  inspectImpl(info, arg, sessionId, kQueryObjects, m_inspector);
}

void V8Console::inspectedObject(const v8::FunctionCallbackInfo<v8::Value>& info,
                                int sessionId, unsigned num) {
  DCHECK_GT(V8InspectorSess
```